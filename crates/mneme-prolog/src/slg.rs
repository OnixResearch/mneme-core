//! Bounded pure-Rust SLG tabling engine and recursive SCC detector.
//!
//! Detects recursive strongly connected components (SCCs) in Prolog rule
//! manifests (for both automatic Scryer `:- table p/n.` emission and in-process
//! tabled resolution) and evaluates cyclic, left-recursive, right-recursive,
//! mutually recursive, and stratified guarded-negation queries deterministically
//! inside `TermProfile` and `mneme_kernel::budget::charge` bounds.
// Octet structural exception: domain-qualified names keep core types unambiguous

/// Default maximum SLG resolution steps before reporting budget exhaustion.
pub const DEFAULT_STEP_BUDGET: u64 = 250_000;

/// Maximum depth for variable dereference chains during unification.
const MAX_DEREF_STEPS: u32 = 256;

/// One predicate indicator `(name, arity)` using fixed-width `u32` arity.
pub type PredicateIndicator = (String, u32);

/// Configuration for one bounded tabled evaluation run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// Maximum metered resolution/unification steps charged through
    /// [`mneme_kernel::budget::charge`].
    pub step_budget: u64,
}

impl Config {
    /// Standard bounded configuration.
    pub const fn standard() -> Self {
        Self {
            step_budget: DEFAULT_STEP_BUDGET,
        }
    }
}

/// Detect every predicate `(name, arity)` that participates in a recursive
/// strongly connected component (direct self-recursion or mutual recursion).
pub fn recursive_predicates(
    rules: &[crate::Rule],
) -> std::collections::BTreeSet<PredicateIndicator> {
    let graph = build_dependency_graph(rules);
    let sccs = tarjan_sccs(&graph);
    let mut recursive = std::collections::BTreeSet::new();
    for scc in sccs {
        if scc.len() > 1 {
            recursive.extend(scc);
            continue;
        }
        if let Some(only) = scc.first()
            && graph
                .get(only)
                .is_some_and(|targets| targets.contains(only))
        {
            recursive.insert(only.clone());
        }
    }
    recursive
}

/// Emit Scryer Prolog `:- use_module(library(tabling)).` and `:- table p/n.`
/// directives for all recursive SCC predicates in `rules`.
pub fn tabling_directives(rules: &[crate::Rule]) -> Vec<String> {
    let recursive = recursive_predicates(rules);
    if recursive.is_empty() {
        return Vec::new();
    }
    let mut directives = Vec::with_capacity(recursive.len().saturating_add(1));
    directives.push(":- use_module(library(tabling)).".to_owned());
    for (name, arity) in recursive {
        directives.push(format!(":- table {name}/{arity}."));
    }
    directives
}

/// Stratified dependency graph node key.
pub(crate) type PredKey = PredicateIndicator;

/// Whether a dependency edge passes through a positive or negative literal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EdgePolarity {
    Positive,
    Negative,
}

/// Build the directed predicate dependency graph from a rule manifest.
fn build_dependency_graph(
    rules: &[crate::Rule],
) -> std::collections::BTreeMap<PredKey, std::collections::BTreeSet<PredKey>> {
    let mut graph: std::collections::BTreeMap<PredKey, std::collections::BTreeSet<PredKey>> =
        std::collections::BTreeMap::new();
    for rule in rules {
        let head_key = atom_key(&rule.head);
        graph.entry(head_key.clone()).or_default();
        for literal in &rule.body {
            let atom = literal_atom(literal);
            let body_key = atom_key(atom);
            graph
                .entry(head_key.clone())
                .or_default()
                .insert(body_key.clone());
            graph.entry(body_key).or_default();
        }
    }
    graph
}

/// Build the signed dependency graph to compute negation strata.
fn build_signed_graph(
    rules: &[crate::Rule],
) -> std::collections::BTreeMap<PredKey, Vec<(PredKey, EdgePolarity)>> {
    let mut graph: std::collections::BTreeMap<PredKey, Vec<(PredKey, EdgePolarity)>> =
        std::collections::BTreeMap::new();
    for rule in rules {
        let head_key = atom_key(&rule.head);
        graph.entry(head_key.clone()).or_default();
        for literal in &rule.body {
            let (atom, polarity) = literal_polarity(literal);
            let body_key = atom_key(atom);
            graph
                .entry(head_key.clone())
                .or_default()
                .push((body_key.clone(), polarity));
            graph.entry(body_key).or_default();
        }
    }
    graph
}

fn literal_polarity(literal: &crate::Literal) -> (&crate::Atom, EdgePolarity) {
    if let crate::Literal::Negative(atom) = literal {
        return (atom, EdgePolarity::Negative);
    }
    (literal_atom(literal), EdgePolarity::Positive)
}

pub(crate) fn atom_key(atom: &crate::Atom) -> PredKey {
    let arity = saturating_u32(atom.terms.len());
    (atom.predicate.clone(), arity)
}

pub(crate) fn saturating_u32(value: usize) -> u32 {
    if let Ok(narrow) = u32::try_from(value) {
        narrow
    } else {
        u32::MAX
    }
}

pub(crate) fn elapsed_millis_u64(duration: std::time::Duration) -> u64 {
    if let Ok(millis) = u64::try_from(duration.as_millis()) {
        millis
    } else {
        u64::MAX
    }
}

pub(crate) fn literal_atom(literal: &crate::Literal) -> &crate::Atom {
    if let crate::Literal::Positive(atom) = literal {
        return atom;
    }
    if let crate::Literal::Negative(atom) = literal {
        return atom;
    }
    // Exhaustive over current `Literal` variants; impossible branch kept panic-free.
    static EMPTY: std::sync::LazyLock<crate::Atom> = std::sync::LazyLock::new(|| crate::Atom {
        predicate: String::new(),
        terms: Vec::new(),
    });
    &EMPTY
}

/// Iterative Tarjan SCC decomposition returning components in reverse
/// topological order (callees before callers).
fn tarjan_sccs(
    graph: &std::collections::BTreeMap<PredKey, std::collections::BTreeSet<PredKey>>,
) -> Vec<Vec<PredKey>> {
    let nodes: Vec<PredKey> = graph.keys().cloned().collect();
    let index_of: std::collections::BTreeMap<PredKey, usize> = nodes
        .iter()
        .enumerate()
        .map(|(idx, key)| (key.clone(), idx))
        .collect();
    let adj: Vec<Vec<usize>> = nodes
        .iter()
        .map(|key| {
            graph
                .get(key)
                .map(|targets| {
                    targets
                        .iter()
                        .filter_map(|target| index_of.get(target).copied())
                        .collect()
                })
                .unwrap_or_default()
        })
        .collect();
    let count = nodes.len();
    let mut state = TarjanState::new(count);
    for start in 0..count {
        if state.indices[start].is_none() {
            tarjan_visit(start, &adj, &mut state);
        }
    }
    state
        .components
        .into_iter()
        .map(|comp| comp.into_iter().map(|id| nodes[id].clone()).collect())
        .collect()
}

struct TarjanState {
    next_index: usize,
    indices: Vec<Option<usize>>,
    lowlink: Vec<usize>,
    on_stack: Vec<bool>,
    stack: Vec<usize>,
    components: Vec<Vec<usize>>,
}

impl TarjanState {
    fn new(count: usize) -> Self {
        Self {
            next_index: 0,
            indices: vec![None; count],
            lowlink: vec![0; count],
            on_stack: vec![false; count],
            stack: Vec::with_capacity(count),
            components: Vec::with_capacity(count),
        }
    }
}

/// Iterative DFS frame for Tarjan's SCC algorithm (avoids Rust stack recursion).
struct TarjanFrame {
    node: usize,
    edge_cursor: usize,
}

fn tarjan_visit(start: usize, adj: &[Vec<usize>], state: &mut TarjanState) {
    let mut frames = Vec::with_capacity(adj.len());
    enter_tarjan_node(start, state, &mut frames);
    while let Some(frame) = frames.last_mut() {
        let node = frame.node;
        if frame.edge_cursor < adj[node].len() {
            let neighbor = adj[node][frame.edge_cursor];
            frame.edge_cursor = frame.edge_cursor.saturating_add(1);
            if state.indices[neighbor].is_none() {
                enter_tarjan_node(neighbor, state, &mut frames);
            } else if state.on_stack[neighbor]
                && let Some(neighbor_index) = state.indices[neighbor]
            {
                state.lowlink[node] = state.lowlink[node].min(neighbor_index);
            }
        } else {
            frames.pop();
            finish_tarjan_node(node, state, frames.last().map(|parent| parent.node));
        }
    }
}

fn enter_tarjan_node(node: usize, state: &mut TarjanState, frames: &mut Vec<TarjanFrame>) {
    let idx = state.next_index;
    state.next_index = state.next_index.saturating_add(1);
    state.indices[node] = Some(idx);
    state.lowlink[node] = idx;
    state.stack.push(node);
    state.on_stack[node] = true;
    frames.push(TarjanFrame {
        node,
        edge_cursor: 0,
    });
}

fn finish_tarjan_node(node: usize, state: &mut TarjanState, parent: Option<usize>) {
    if let Some(parent_node) = parent {
        state.lowlink[parent_node] = state.lowlink[parent_node].min(state.lowlink[node]);
    }
    if state.indices[node] == Some(state.lowlink[node]) {
        let mut comp = Vec::with_capacity(state.stack.len());
        while let Some(member) = state.stack.pop() {
            state.on_stack[member] = false;
            comp.push(member);
            if member == node {
                break;
            }
        }
        state.components.push(comp);
    }
}

/// Verify that no cycle contains a negative edge (negation stratification).
pub(crate) fn check_stratified(rules: &[crate::Rule]) -> Result<(), crate::CapabilityError> {
    let unsigned = build_dependency_graph(rules);
    let signed = build_signed_graph(rules);
    let sccs = tarjan_sccs(&unsigned);
    for scc in sccs {
        let members: std::collections::BTreeSet<&PredKey> = scc.iter().collect();
        for node in &scc {
            let Some(edges) = signed.get(node) else {
                continue;
            };
            for (target, polarity) in edges {
                if *polarity == EdgePolarity::Negative && members.contains(target) {
                    return Err(crate::CapabilityError::InvalidRequest(format!(
                        "unstratified negative cycle involving {}/{}",
                        node.0, node.1
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Metered work-step counter backed by [`mneme_kernel::budget::charge`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct StepBudget {
    used: u64,
    limit: u64,
}

/// Why an SLG step terminated early.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StopReason {
    BudgetExhausted,
    Cancelled,
}

impl StepBudget {
    pub(crate) const fn new(limit: u64) -> Self {
        Self { used: 0, limit }
    }

    pub(crate) const fn used(self) -> u64 {
        self.used
    }

    pub(crate) fn charge(
        &mut self,
        cost: u64,
        control: &crate::process::WorkerControl,
    ) -> Result<(), StopReason> {
        if control.is_cancelled() {
            return Err(StopReason::Cancelled);
        }
        let Some(next) = mneme_kernel::budget::charge(self.used, cost, self.limit) else {
            return Err(StopReason::BudgetExhausted);
        };
        self.used = next;
        Ok(())
    }
}

/// Variable substitution map.
pub(crate) type Subst = std::collections::BTreeMap<String, crate::Term>;

/// Canonicalized call key for variant-based SLG tabling.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CallKey {
    pub(crate) atom: crate::Atom,
}

/// Canonicalize an atom by renaming distinct variables in traversal order to
/// `_V0`, `_V1`, ... so variant subgoals share one SLG table entry.
pub(crate) fn canonicalize_atom(atom: &crate::Atom) -> CallKey {
    let mut map: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    let mut terms = Vec::with_capacity(atom.terms.len());
    for term in &atom.terms {
        terms.push(canonicalize_term(term, &mut map));
    }
    CallKey {
        atom: crate::Atom {
            predicate: atom.predicate.clone(),
            terms,
        },
    }
}

fn canonicalize_term(
    root: &crate::Term,
    map: &mut std::collections::BTreeMap<String, String>,
) -> crate::Term {
    enum Step<'a> {
        Visit(&'a crate::Term),
        BuildList(usize),
        BuildCompound(String, usize),
    }
    let mut stack = vec![Step::Visit(root)];
    let mut out: Vec<crate::Term> = Vec::with_capacity(8);
    while let Some(step) = stack.pop() {
        if let Step::Visit(term) = step {
            if let crate::Term::Variable(name) = term {
                let next_idx = map.len();
                let canonical = map
                    .entry(name.clone())
                    .or_insert_with(|| format!("_V{next_idx}"))
                    .clone();
                out.push(crate::Term::Variable(canonical));
            } else if let crate::Term::List(items) = term {
                stack.push(Step::BuildList(items.len()));
                for item in items.iter().rev() {
                    stack.push(Step::Visit(item));
                }
            } else if let crate::Term::Compound { functor, args } = term {
                stack.push(Step::BuildCompound(functor.clone(), args.len()));
                for arg in args.iter().rev() {
                    stack.push(Step::Visit(arg));
                }
            } else {
                out.push(term.clone());
            }
        } else if let Step::BuildList(len) = step {
            let start = out.len().saturating_sub(len);
            let items = out.split_off(start);
            out.push(crate::Term::List(items));
        } else if let Step::BuildCompound(functor, len) = step {
            let start = out.len().saturating_sub(len);
            let args = out.split_off(start);
            out.push(crate::Term::Compound { functor, args });
        }
    }
    out.pop().unwrap_or(crate::Term::Integer(0))
}

/// Whether a term contains no variables.
pub(crate) fn is_ground_term(root: &crate::Term) -> bool {
    let mut pending = vec![root];
    while let Some(term) = pending.pop() {
        if matches!(term, crate::Term::Variable(_)) {
            return false;
        }
        if let crate::Term::List(items) | crate::Term::Compound { args: items, .. } = term {
            for item in items {
                pending.push(item);
            }
        }
    }
    true
}

/// Whether an atom contains no variables.
pub(crate) fn is_ground_atom(atom: &crate::Atom) -> bool {
    atom.terms.iter().all(is_ground_term)
}

/// Whether a term obeys `TermProfile` depth and collection bounds.
pub(crate) fn term_within_profile(root: &crate::Term, profile: crate::TermProfile) -> bool {
    let mut pending = vec![(root, 1_usize)];
    while let Some((term, depth)) = pending.pop() {
        if depth > profile.max_depth {
            return false;
        }
        if let crate::Term::List(items) | crate::Term::Compound { args: items, .. } = term {
            if items.len() > profile.max_collection {
                return false;
            }
            for item in items {
                pending.push((item, depth.saturating_add(1)));
            }
        } else if matches!(term, crate::Term::Reference { .. }) && !profile.references_allowed {
            return false;
        }
    }
    true
}

/// Rename every variable in a rule with a unique numeric suffix so clause
/// instances cannot collide.
pub(crate) fn rename_rule(rule: &crate::Rule, instance_id: u64) -> crate::Rule {
    let suffix = format!("_R{instance_id}_");
    crate::Rule {
        id: rule.id.clone(),
        version: rule.version.clone(),
        head: rename_atom(&rule.head, &suffix),
        body: rule
            .body
            .iter()
            .map(|lit| rename_literal(lit, &suffix))
            .collect(),
    }
}

fn rename_literal(lit: &crate::Literal, suffix: &str) -> crate::Literal {
    if let crate::Literal::Negative(atom) = lit {
        crate::Literal::Negative(rename_atom(atom, suffix))
    } else {
        crate::Literal::Positive(rename_atom(literal_atom(lit), suffix))
    }
}

fn rename_atom(atom: &crate::Atom, prefix: &str) -> crate::Atom {
    crate::Atom {
        predicate: atom.predicate.clone(),
        terms: atom
            .terms
            .iter()
            .map(|term| rename_term(term, prefix))
            .collect(),
    }
}

fn rename_term(root: &crate::Term, prefix: &str) -> crate::Term {
    enum Step<'a> {
        Visit(&'a crate::Term),
        BuildList(usize),
        BuildCompound(String, usize),
    }
    let mut stack = vec![Step::Visit(root)];
    let mut out: Vec<crate::Term> = Vec::with_capacity(8);
    while let Some(step) = stack.pop() {
        if let Step::Visit(term) = step {
            if let crate::Term::Variable(name) = term {
                out.push(crate::Term::Variable(format!("{prefix}{name}")));
            } else if let crate::Term::List(items) = term {
                stack.push(Step::BuildList(items.len()));
                for item in items.iter().rev() {
                    stack.push(Step::Visit(item));
                }
            } else if let crate::Term::Compound { functor, args } = term {
                stack.push(Step::BuildCompound(functor.clone(), args.len()));
                for arg in args.iter().rev() {
                    stack.push(Step::Visit(arg));
                }
            } else {
                out.push(term.clone());
            }
        } else if let Step::BuildList(len) = step {
            let start = out.len().saturating_sub(len);
            let items = out.split_off(start);
            out.push(crate::Term::List(items));
        } else if let Step::BuildCompound(functor, len) = step {
            let start = out.len().saturating_sub(len);
            let args = out.split_off(start);
            out.push(crate::Term::Compound { functor, args });
        }
    }
    out.pop().unwrap_or(crate::Term::Integer(0))
}

/// Apply `subst` iteratively to `term`, respecting `max_depth`.
pub(crate) fn apply_subst_term(
    root: &crate::Term,
    subst: &Subst,
    max_depth: usize,
) -> Option<crate::Term> {
    enum Step {
        Visit(crate::Term, usize),
        BuildList(usize),
        BuildCompound(String, usize),
    }
    let mut stack = vec![Step::Visit(root.clone(), 1)];
    let mut out: Vec<crate::Term> = Vec::with_capacity(8);
    while let Some(step) = stack.pop() {
        if let Step::Visit(term, depth) = step {
            if depth > max_depth {
                return None;
            }
            let resolved = deref_term(&term, subst)?;
            if let crate::Term::List(items) = resolved {
                stack.push(Step::BuildList(items.len()));
                for item in items.into_iter().rev() {
                    stack.push(Step::Visit(item, depth.saturating_add(1)));
                }
            } else if let crate::Term::Compound { functor, args } = resolved {
                stack.push(Step::BuildCompound(functor, args.len()));
                for arg in args.into_iter().rev() {
                    stack.push(Step::Visit(arg, depth.saturating_add(1)));
                }
            } else {
                out.push(resolved);
            }
        } else if let Step::BuildList(len) = step {
            let start = out.len().saturating_sub(len);
            let items = out.split_off(start);
            out.push(crate::Term::List(items));
        } else if let Step::BuildCompound(functor, len) = step {
            let start = out.len().saturating_sub(len);
            let args = out.split_off(start);
            out.push(crate::Term::Compound { functor, args });
        }
    }
    out.pop()
}

pub(crate) fn apply_subst_atom(
    atom: &crate::Atom,
    subst: &Subst,
    max_depth: usize,
) -> Option<crate::Atom> {
    let mut terms = Vec::with_capacity(atom.terms.len());
    for term in &atom.terms {
        terms.push(apply_subst_term(term, subst, max_depth)?);
    }
    Some(crate::Atom {
        predicate: atom.predicate.clone(),
        terms,
    })
}

fn deref_term(term: &crate::Term, subst: &Subst) -> Option<crate::Term> {
    let mut current = term.clone();
    for _ in 0..MAX_DEREF_STEPS {
        if let crate::Term::Variable(name) = &current {
            let Some(next) = subst.get(name) else {
                return Some(current);
            };
            if next == &current {
                return Some(current);
            }
            current = next.clone();
        } else {
            return Some(current);
        }
    }
    None
}

fn occurs_in(var: &str, root: &crate::Term, subst: &Subst) -> bool {
    let mut pending = vec![root.clone()];
    while let Some(term) = pending.pop() {
        let Some(resolved) = deref_term(&term, subst) else {
            return true;
        };
        if let crate::Term::Variable(name) = resolved {
            if name == var {
                return true;
            }
        } else if let crate::Term::List(items) | crate::Term::Compound { args: items, .. } =
            resolved
        {
            pending.extend(items);
        }
    }
    false
}

/// Iterative Robinson unification with occurs check and metered step budget.
pub(crate) fn unify_atoms(
    left: &crate::Atom,
    right: &crate::Atom,
    subst: &Subst,
    budget: &mut StepBudget,
    control: &crate::process::WorkerControl,
) -> Result<Option<Subst>, StopReason> {
    budget.charge(1, control)?;
    if left.predicate != right.predicate || left.terms.len() != right.terms.len() {
        return Ok(None);
    }
    let mut next = subst.clone();
    let mut pairs: Vec<(crate::Term, crate::Term)> = left
        .terms
        .iter()
        .cloned()
        .zip(right.terms.iter().cloned())
        .collect();
    while let Some((lhs_raw, rhs_raw)) = pairs.pop() {
        budget.charge(1, control)?;
        let Some(lhs) = deref_term(&lhs_raw, &next) else {
            return Ok(None);
        };
        let Some(rhs) = deref_term(&rhs_raw, &next) else {
            return Ok(None);
        };
        if lhs == rhs {
            continue;
        }
        match (lhs, rhs) {
            (crate::Term::Variable(var), term) | (term, crate::Term::Variable(var)) => {
                if occurs_in(&var, &term, &next) {
                    return Ok(None);
                }
                next.insert(var, term);
            }
            (crate::Term::List(l_items), crate::Term::List(r_items)) => {
                if l_items.len() != r_items.len() {
                    return Ok(None);
                }
                pairs.extend(l_items.into_iter().zip(r_items));
            }
            (
                crate::Term::Compound {
                    functor: lf,
                    args: la,
                },
                crate::Term::Compound {
                    functor: rf,
                    args: ra,
                },
            ) => {
                if lf != rf || la.len() != ra.len() {
                    return Ok(None);
                }
                pairs.extend(la.into_iter().zip(ra));
            }
            _ => return Ok(None),
        }
    }
    Ok(Some(next))
}

/// Indexed in-memory fact and rule database for SLG and abductive evaluation.
pub(crate) struct ProgramDb {
    pub(crate) facts: std::collections::BTreeMap<PredKey, Vec<crate::Atom>>,
    first_arg_index: std::collections::BTreeMap<(PredKey, crate::Term), Vec<usize>>,
    relation_head_index: std::collections::BTreeMap<(String, crate::Term), Vec<usize>>,
    pub(crate) rules: std::collections::BTreeMap<PredKey, Vec<crate::Rule>>,
    pub(crate) coverage_complete: bool,
    pub(crate) source_pruned: bool,
}

impl ProgramDb {
    pub(crate) fn from_request(
        image: &crate::snapshot::InputImage,
        request: &crate::Request,
        extra_facts: &[crate::Atom],
    ) -> Result<Self, crate::CapabilityError> {
        let mut db = Self {
            facts: std::collections::BTreeMap::new(),
            first_arg_index: std::collections::BTreeMap::new(),
            relation_head_index: std::collections::BTreeMap::new(),
            rules: std::collections::BTreeMap::new(),
            coverage_complete: image.coverage.complete,
            source_pruned: image_has_pruned_source(image),
        };
        db.load_canonical(&image.canonical)?;
        db.load_relations(&image.relations)?;
        for assumption in &request.assumptions {
            db.insert_fact(assumption.atom.clone());
        }
        for extra in extra_facts {
            db.insert_fact(extra.clone());
        }
        for rule in &request.rules {
            if rule.body.is_empty() && is_ground_atom(&rule.head) {
                db.insert_fact(rule.head.clone());
            } else {
                db.rules
                    .entry(atom_key(&rule.head))
                    .or_default()
                    .push(rule.clone());
            }
        }
        Ok(db)
    }

    fn load_canonical(
        &mut self,
        canonical: &[crate::snapshot::CanonicalFact],
    ) -> Result<(), crate::CapabilityError> {
        let atoms = canonical
            .iter()
            .map(canonical_fact_atom)
            .collect::<Result<Vec<_>, _>>()?;
        for atom in atoms {
            self.insert_fact(atom);
        }
        Ok(())
    }

    fn load_relations(
        &mut self,
        relations: &[crate::snapshot::SelectedRelation],
    ) -> Result<(), crate::CapabilityError> {
        for relation in relations {
            if !relation.coverage.complete {
                self.coverage_complete = false;
            }
            for row in &relation.rows {
                self.insert_selected_row(&relation.predicate, row)?;
            }
        }
        Ok(())
    }

    fn insert_selected_row(
        &mut self,
        predicate: &str,
        row: &crate::snapshot::SelectedRow,
    ) -> Result<(), crate::CapabilityError> {
        let status_tag = match row.epistemic {
            mneme_datalog::EpistemicStatus::Rejected => return Ok(()),
            mneme_datalog::EpistemicStatus::Accepted => {
                mneme_datalog::EpistemicStatus::Accepted.name()
            }
            mneme_datalog::EpistemicStatus::Proposed => {
                mneme_datalog::EpistemicStatus::Proposed.name()
            }
        };
        let value_terms = row
            .values
            .iter()
            .map(crate::snapshot::value_term)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                crate::CapabilityError::InvalidRequest(
                    "input image contains a value that cannot be rendered".to_owned(),
                )
            })?;
        if row.epistemic == mneme_datalog::EpistemicStatus::Accepted {
            self.insert_fact(crate::Atom {
                predicate: crate::RELATION_RELATION.to_owned(),
                terms: vec![
                    crate::Term::String(predicate.to_owned()),
                    crate::Term::List(value_terms.clone()),
                ],
            });
        }
        self.insert_fact(crate::Atom {
            predicate: crate::snapshot::SelectedRow::EPISTEMIC_RELATION.to_owned(),
            terms: vec![
                crate::Term::String(predicate.to_owned()),
                crate::Term::List(value_terms),
                crate::Term::String(status_tag.to_owned()),
            ],
        });
        Ok(())
    }

    pub(crate) fn insert_fact(&mut self, atom: crate::Atom) {
        let key = atom_key(&atom);
        let list = self.facts.entry(key.clone()).or_default();
        let idx = list.len();
        if let Some(first) = atom.terms.first()
            && is_ground_term(first)
        {
            self.first_arg_index
                .entry((key.clone(), first.clone()))
                .or_default()
                .push(idx);
        }
        if let Some((rel_name, first_elem)) = relation_head_key(&atom) {
            self.relation_head_index
                .entry((rel_name, first_elem))
                .or_default()
                .push(idx);
        }
        list.push(atom);
    }

    /// Return candidate matching facts using secondary indexes when possible.
    pub(crate) fn matching_facts<'a>(&'a self, subgoal: &crate::Atom) -> Vec<&'a crate::Atom> {
        let key = atom_key(subgoal);
        let Some(all) = self.facts.get(&key) else {
            return Vec::new();
        };
        if let Some((rel_name, first_elem)) = relation_head_key(subgoal) {
            return self
                .relation_head_index
                .get(&(rel_name, first_elem))
                .map(|indices| indices.iter().filter_map(|&i| all.get(i)).collect())
                .unwrap_or_default();
        }
        if let Some(first) = subgoal.terms.first()
            && is_ground_term(first)
        {
            return self
                .first_arg_index
                .get(&(key, first.clone()))
                .map(|indices| indices.iter().filter_map(|&i| all.get(i)).collect())
                .unwrap_or_default();
        }
        all.iter().collect()
    }
}

fn canonical_fact_atom(
    fact: &crate::snapshot::CanonicalFact,
) -> Result<crate::Atom, crate::CapabilityError> {
    let value = crate::snapshot::value_term(&fact.value).map_err(|_| {
        crate::CapabilityError::InvalidRequest(
            "input image contains a value that cannot be rendered".to_owned(),
        )
    })?;
    Ok(crate::Atom {
        predicate: crate::ASSERTION_RELATION.to_owned(),
        terms: vec![
            crate::Term::String(fact.predicate.clone()),
            crate::Term::String(fact.subject.to_hex()),
            value,
        ],
    })
}

fn relation_head_key(atom: &crate::Atom) -> Option<(String, crate::Term)> {
    if atom.predicate != crate::RELATION_RELATION || atom.terms.len() != 2 {
        return None;
    }
    let crate::Term::String(name) = &atom.terms[0] else {
        return None;
    };
    let crate::Term::List(items) = &atom.terms[1] else {
        return None;
    };
    let first_elem = items.first()?;
    if !is_ground_term(first_elem) {
        return None;
    }
    Some((name.clone(), first_elem.clone()))
}

fn image_has_pruned_source(image: &crate::snapshot::InputImage) -> bool {
    image
        .relations
        .iter()
        .any(|rel| rel.rows.iter().any(|row| row.support_truncated))
}

/// Call-table worklist tracked during fixpoint completion.
struct CallWorklist {
    ordered: Vec<CallKey>,
    known: std::collections::BTreeSet<CallKey>,
}

/// Stratified SLG evaluator holding call tables across fixpoint completion.
pub(crate) struct Engine<'a> {
    pub(crate) db: &'a ProgramDb,
    pub(crate) profile: crate::TermProfile,
    pub(crate) budget: StepBudget,
    pub(crate) control: &'a crate::process::WorkerControl,
    tables: std::collections::BTreeMap<CallKey, std::collections::BTreeSet<crate::Atom>>,
    fresh_counter: u64,
}

impl<'a> Engine<'a> {
    pub(crate) fn new(
        db: &'a ProgramDb,
        profile: crate::TermProfile,
        step_budget: u64,
        control: &'a crate::process::WorkerControl,
    ) -> Self {
        Self {
            db,
            profile,
            budget: StepBudget::new(step_budget),
            control,
            tables: std::collections::BTreeMap::new(),
            fresh_counter: 0,
        }
    }

    /// Evaluate `goal` to fixpoint and return all derived ground answer atoms
    /// matching `goal` along with matching substitutions.
    pub(crate) fn evaluate_goal(
        &mut self,
        goal: &crate::Atom,
    ) -> Result<Vec<(crate::Atom, Subst)>, StopReason> {
        let root_key = canonicalize_atom(goal);
        self.complete_call(&root_key)?;
        let Some(answers) = self.tables.get(&root_key).cloned() else {
            return Ok(Vec::new());
        };
        let empty = Subst::new();
        let mut results = Vec::with_capacity(answers.len());
        for answer in answers {
            if let Some(subst) = unify_atoms(goal, &answer, &empty, &mut self.budget, self.control)?
            {
                results.push((answer, subst));
            }
        }
        Ok(results)
    }

    fn complete_call(&mut self, root_call: &CallKey) -> Result<(), StopReason> {
        let mut worklist = CallWorklist {
            ordered: vec![root_call.clone()],
            known: std::collections::BTreeSet::from([root_call.clone()]),
        };
        self.tables.entry(root_call.clone()).or_default();

        loop {
            self.budget.charge(1, self.control)?;
            let mut has_changed = false;
            let mut cursor = 0_usize;
            while cursor < worklist.ordered.len() {
                let call = worklist.ordered[cursor].clone();
                cursor = cursor.saturating_add(1);
                if self.expand_call(&call, &mut worklist)? {
                    has_changed = true;
                }
            }
            if !has_changed {
                return Ok(());
            }
        }
    }

    fn expand_call(
        &mut self,
        call: &CallKey,
        worklist: &mut CallWorklist,
    ) -> Result<bool, StopReason> {
        let mut has_changed = false;
        let empty = Subst::new();
        for fact in self.db.matching_facts(&call.atom) {
            self.budget.charge(1, self.control)?;
            if unify_atoms(&call.atom, fact, &empty, &mut self.budget, self.control)?.is_some()
                && self.insert_answer(call, fact.clone())
            {
                has_changed = true;
            }
        }
        let key = atom_key(&call.atom);
        let Some(rules) = self.db.rules.get(&key) else {
            return Ok(has_changed);
        };
        for rule in rules {
            self.budget.charge(1, self.control)?;
            self.fresh_counter = self.fresh_counter.saturating_add(1);
            let renamed = rename_rule(rule, self.fresh_counter);
            let Some(init_subst) = unify_atoms(
                &call.atom,
                &renamed.head,
                &empty,
                &mut self.budget,
                self.control,
            )?
            else {
                continue;
            };
            if self.eval_rule_body(call, &renamed.body, init_subst, worklist)? {
                has_changed = true;
            }
        }
        Ok(has_changed)
    }

    fn eval_rule_body(
        &mut self,
        call: &CallKey,
        body: &[crate::Literal],
        init_subst: Subst,
        worklist: &mut CallWorklist,
    ) -> Result<bool, StopReason> {
        let mut has_changed = false;
        let mut agenda: Vec<(usize, Subst)> = vec![(0, init_subst)];
        while let Some((idx, subst)) = agenda.pop() {
            self.budget.charge(1, self.control)?;
            if idx == body.len() {
                if self.record_ground_answer(call, &subst) {
                    has_changed = true;
                }
                continue;
            }
            if let crate::Literal::Negative(atom) = &body[idx] {
                if let Some(subgoal) = apply_subst_atom(atom, &subst, self.profile.max_depth)
                    && self.check_guarded_negative(&subgoal)?
                {
                    agenda.push((idx.saturating_add(1), subst));
                }
            } else if let Some(subgoal) =
                apply_subst_atom(literal_atom(&body[idx]), &subst, self.profile.max_depth)
                && self.step_positive_literal(&subgoal, &subst, idx, &mut agenda, worklist)?
            {
                has_changed = true;
            }
        }
        Ok(has_changed)
    }

    fn record_ground_answer(&mut self, call: &CallKey, subst: &Subst) -> bool {
        let Some(answer) = apply_subst_atom(&call.atom, subst, self.profile.max_depth) else {
            return false;
        };
        if !is_ground_atom(&answer) {
            return false;
        }
        let is_within = answer
            .terms
            .iter()
            .all(|t| term_within_profile(t, self.profile));
        if !is_within {
            return false;
        }
        self.insert_answer(call, answer)
    }

    fn step_positive_literal(
        &mut self,
        subgoal: &crate::Atom,
        subst: &Subst,
        idx: usize,
        agenda: &mut Vec<(usize, Subst)>,
        worklist: &mut CallWorklist,
    ) -> Result<bool, StopReason> {
        let key = atom_key(subgoal);
        if !self.db.rules.contains_key(&key) {
            for fact in self.db.matching_facts(subgoal) {
                if let Some(next_subst) =
                    unify_atoms(subgoal, fact, subst, &mut self.budget, self.control)?
                {
                    agenda.push((idx.saturating_add(1), next_subst));
                }
            }
            return Ok(false);
        }
        let sub_key = canonicalize_atom(subgoal);
        let mut is_new_call = false;
        if worklist.known.insert(sub_key.clone()) {
            worklist.ordered.push(sub_key.clone());
            self.tables.entry(sub_key.clone()).or_default();
            is_new_call = true;
        }
        let answers = self.tables.get(&sub_key).cloned().unwrap_or_default();
        for answer in &answers {
            if let Some(next_subst) =
                unify_atoms(subgoal, answer, subst, &mut self.budget, self.control)?
            {
                agenda.push((idx.saturating_add(1), next_subst));
            }
        }
        Ok(is_new_call)
    }

    /// Guarded negation check strictly gated by [`crate::evaluate_negative_guard`]
    /// (`mneme_kernel::completeness::absence_established`).
    fn check_guarded_negative(&mut self, subgoal: &crate::Atom) -> Result<bool, StopReason> {
        let is_ground = is_ground_atom(subgoal);
        let conditions = crate::NegativeConditions {
            relation_complete: self.db.coverage_complete,
            subgoal_completed: true,
            subgoal_ground: is_ground,
            source_pruned: self.db.source_pruned,
            within_limits: true,
        };
        if !matches!(
            crate::evaluate_negative_guard(conditions),
            crate::NegativeConclusion::Established
        ) {
            return Ok(false);
        }
        let sub_key = canonicalize_atom(subgoal);
        self.complete_call(&sub_key)?;
        if !matches!(
            crate::evaluate_negative_guard(conditions),
            crate::NegativeConclusion::Established
        ) {
            return Ok(false);
        }
        let is_derived = self
            .tables
            .get(&sub_key)
            .is_some_and(|set| set.contains(subgoal));
        Ok(!is_derived)
    }

    fn insert_answer(&mut self, call: &CallKey, answer: crate::Atom) -> bool {
        self.tables.entry(call.clone()).or_default().insert(answer)
    }
}

/// Protocol formatting context bundled to keep helper arity small.
struct ProtocolFormatContext<'a> {
    request: &'a crate::Request,
    metadata: &'a crate::CapabilityMetadata,
    identity: &'a crate::ProtocolIdentity,
    max_output_bytes: usize,
    elapsed_ms: u64,
}

/// Run one request through the bounded pure-Rust SLG tabling engine, producing
/// a standard [`crate::process::WorkerOutcome`] speaking the exact request-bound
/// response protocol.
#[allow(unknown_lints, ambient_clock)] // wall-clock measurement mirrors process::run_worker
pub fn run_worker(
    metadata: &crate::CapabilityMetadata,
    image: &crate::snapshot::InputImage,
    request: &crate::Request,
    runtime: &crate::process::WorkerRuntime<'_>,
    config: Config,
) -> Result<crate::process::WorkerOutcome, crate::CapabilityError> {
    metadata.ensure_request(request)?;
    image.verify_for_request(request).map_err(|_| {
        crate::CapabilityError::InvalidRequest("input image does not match the request".to_owned())
    })?;
    if runtime.limits.max_wall_ms == 0 || runtime.limits.max_output_bytes == 0 {
        return Err(crate::CapabilityError::LimitExceeded(
            "worker limits must be positive".to_owned(),
        ));
    }
    check_stratified(&request.rules)?;
    if runtime.control.is_cancelled() {
        return Ok(cancelled_worker_outcome());
    }
    let identity = request.protocol_identity(metadata, image)?;
    let started = std::time::Instant::now();
    let db = ProgramDb::from_request(image, request, &[])?;
    let mut engine = Engine::new(&db, metadata.terms, config.step_budget, runtime.control);
    let evaluated = engine.evaluate_goal(&request.goal);
    let elapsed_ms = elapsed_millis_u64(started.elapsed());
    match evaluated {
        Err(StopReason::Cancelled) => Ok(cancelled_worker_outcome()),
        Err(StopReason::BudgetExhausted) => Ok(crate::process::WorkerOutcome {
            status: crate::process::WorkerStatus::Timeout,
            output: String::new(),
            stderr: String::new(),
            captured_bytes: 0,
            output_utf8_valid: true,
            elapsed_ms,
            output_limit_exceeded: false,
            solution_limit_exceeded: false,
            reason: Some("SLG step budget exhausted".to_owned()),
        }),
        Ok(answers) => {
            let fmt_ctx = ProtocolFormatContext {
                request,
                metadata,
                identity: &identity,
                max_output_bytes: runtime.limits.max_output_bytes,
                elapsed_ms,
            };
            format_protocol_outcome(&fmt_ctx, &answers)
        }
    }
}

/// Run one request directly via the bounded pure-Rust SLG tabling engine and
/// return a fully validated [`crate::Outcome`].
pub fn run_query(
    metadata: &crate::CapabilityMetadata,
    image: &crate::snapshot::InputImage,
    request: &crate::Request,
    runtime: &crate::process::WorkerRuntime<'_>,
    config: Config,
) -> Result<crate::Outcome, crate::CapabilityError> {
    let identity = request.protocol_identity(metadata, image)?;
    let effective = crate::process::WorkerLimits {
        max_wall_ms: runtime.limits.max_wall_ms.min(request.limits.max_time_ms),
        max_output_bytes: runtime
            .limits
            .max_output_bytes
            .min(request.limits.max_output_bytes),
    };
    let clamped = crate::process::WorkerRuntime {
        control: runtime.control,
        limits: effective,
    };
    let worker = run_worker(metadata, image, request, &clamped, config)?;
    let outcome = crate::outcome_from_worker(&worker, image, request, &identity);
    outcome.validate_for_request(request)?;
    Ok(outcome)
}

fn cancelled_worker_outcome() -> crate::process::WorkerOutcome {
    crate::process::WorkerOutcome {
        status: crate::process::WorkerStatus::Cancelled,
        output: String::new(),
        stderr: String::new(),
        captured_bytes: 0,
        output_utf8_valid: true,
        elapsed_ms: 0,
        output_limit_exceeded: false,
        solution_limit_exceeded: false,
        reason: Some("cancelled before SLG start".to_owned()),
    }
}

fn format_protocol_outcome(
    ctx: &ProtocolFormatContext<'_>,
    answers: &[(crate::Atom, Subst)],
) -> Result<crate::process::WorkerOutcome, crate::CapabilityError> {
    let mut output = String::new();
    let header = crate::protocol_header(ctx.identity, &ctx.request.mode);
    if !push_bounded(&mut output, &header, ctx.max_output_bytes) {
        return Ok(output_limit_outcome(output, ctx.elapsed_ms));
    }
    let output_vars: Vec<&str> = ctx
        .request
        .variables
        .iter()
        .filter(|var| var.role == crate::VariableRole::Output)
        .map(|var| var.name.as_str())
        .collect();
    let rows = project_answer_rows(answers, &output_vars, ctx.metadata.terms);
    if ctx.request.mode == crate::QueryMode::GroundTest {
        let stop_name = if rows.is_empty() {
            "ground-failure"
        } else {
            "ground-success"
        };
        return finish_with_stop(ctx, output, stop_name);
    }
    if ctx.request.mode == crate::QueryMode::FindOne {
        if let Some(first) = rows.first() {
            let row_line = format_row_line(
                ctx.identity,
                first,
                ctx.metadata.terms,
                ctx.max_output_bytes,
            )?;
            if !push_bounded(&mut output, &row_line, ctx.max_output_bytes) {
                return Ok(output_limit_outcome(output, ctx.elapsed_ms));
            }
            return finish_with_stop(ctx, output, "found-one");
        }
        return finish_with_stop(ctx, output, "exhausted");
    }
    emit_multi_row_outcome(ctx, &rows, output)
}

fn finish_with_stop(
    ctx: &ProtocolFormatContext<'_>,
    mut output: String,
    stop_name: &str,
) -> Result<crate::process::WorkerOutcome, crate::CapabilityError> {
    let stop_line = format!(
        "{}\t{}\t{stop_name}",
        crate::RESPONSE_STOP_PREFIX,
        ctx.identity.request_digest
    );
    if !push_bounded(&mut output, &stop_line, ctx.max_output_bytes) {
        return Ok(output_limit_outcome(output, ctx.elapsed_ms));
    }
    Ok(complete_worker_outcome(output, ctx.elapsed_ms))
}

fn emit_multi_row_outcome(
    ctx: &ProtocolFormatContext<'_>,
    rows: &[std::collections::BTreeMap<String, crate::Term>],
    mut output: String,
) -> Result<crate::process::WorkerOutcome, crate::CapabilityError> {
    let limit = ctx.request.limits.max_solutions;
    let mut emitted = 0_usize;
    let mut is_solution_limit_hit = false;
    for bindings in rows {
        let row_line = format_row_line(
            ctx.identity,
            bindings,
            ctx.metadata.terms,
            ctx.max_output_bytes,
        )?;
        if !push_bounded(&mut output, &row_line, ctx.max_output_bytes) {
            return Ok(output_limit_outcome(output, ctx.elapsed_ms));
        }
        emitted = emitted.saturating_add(1);
        if emitted > limit {
            is_solution_limit_hit = true;
            break;
        }
    }
    if is_solution_limit_hit {
        let captured_bytes = output.len();
        return Ok(crate::process::WorkerOutcome {
            status: crate::process::WorkerStatus::Partial,
            output,
            stderr: String::new(),
            captured_bytes,
            output_utf8_valid: true,
            elapsed_ms: ctx.elapsed_ms,
            output_limit_exceeded: false,
            solution_limit_exceeded: true,
            reason: Some("solution limit reached".to_owned()),
        });
    }
    finish_with_stop(ctx, output, "exhausted")
}

fn project_answer_rows(
    answers: &[(crate::Atom, Subst)],
    output_vars: &[&str],
    profile: crate::TermProfile,
) -> Vec<std::collections::BTreeMap<String, crate::Term>> {
    let mut seen: std::collections::BTreeSet<std::collections::BTreeMap<String, crate::Term>> =
        std::collections::BTreeSet::new();
    let mut rows = Vec::with_capacity(answers.len());
    for (_, subst) in answers {
        if let Some(row) = project_one_row(subst, output_vars, profile)
            && seen.insert(row.clone())
        {
            rows.push(row);
        }
    }
    rows
}

fn project_one_row(
    subst: &Subst,
    output_vars: &[&str],
    profile: crate::TermProfile,
) -> Option<std::collections::BTreeMap<String, crate::Term>> {
    output_vars
        .iter()
        .map(|&name| {
            let raw = subst.get(name)?;
            let resolved = apply_subst_term(raw, subst, profile.max_depth)?;
            if !is_ground_term(&resolved) || !term_within_profile(&resolved, profile) {
                return None;
            }
            Some((name.to_owned(), resolved))
        })
        .collect()
}

fn format_row_line(
    identity: &crate::ProtocolIdentity,
    bindings: &std::collections::BTreeMap<String, crate::Term>,
    profile: crate::TermProfile,
    max_output_bytes: usize,
) -> Result<String, crate::CapabilityError> {
    let mut pairs = Vec::with_capacity(bindings.len());
    for (name, term) in bindings {
        let encoded = crate::encode_term(term, profile, max_output_bytes)?;
        pairs.push(format!("{name}={encoded}"));
    }
    Ok(format!(
        "{}\t{}\t{}",
        crate::RESPONSE_ROW_PREFIX,
        identity.request_digest,
        pairs.join(",")
    ))
}

fn push_bounded(output: &mut String, line: &str, max_bytes: usize) -> bool {
    let needed = output.len().saturating_add(line.len()).saturating_add(1);
    if needed > max_bytes {
        return false;
    }
    output.push_str(line);
    output.push('\n');
    true
}

fn complete_worker_outcome(output: String, elapsed_ms: u64) -> crate::process::WorkerOutcome {
    let captured_bytes = output.len();
    crate::process::WorkerOutcome {
        status: crate::process::WorkerStatus::Complete,
        output,
        stderr: String::new(),
        captured_bytes,
        output_utf8_valid: true,
        elapsed_ms,
        output_limit_exceeded: false,
        solution_limit_exceeded: false,
        reason: None,
    }
}

fn output_limit_outcome(output: String, elapsed_ms: u64) -> crate::process::WorkerOutcome {
    let captured_bytes = output.len();
    crate::process::WorkerOutcome {
        status: crate::process::WorkerStatus::Partial,
        output,
        stderr: String::new(),
        captured_bytes,
        output_utf8_valid: true,
        output_limit_exceeded: true,
        solution_limit_exceeded: false,
        elapsed_ms,
        reason: Some("output byte limit reached".to_owned()),
    }
}
