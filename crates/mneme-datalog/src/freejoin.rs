//! Worst-case optimal Free Join planning and sorted-trie evaluation.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct TrieNode {
    pub(crate) children: std::collections::BTreeMap<mneme_core::Value, TrieNode>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct FactTrie {
    pub(crate) root: TrieNode,
}

impl FactTrie {
    /// Insert one ground fact tuple according to the trie's column permutation.
    pub(crate) fn insert(&mut self, terms: &[mneme_core::Value], cols: &[usize]) {
        debug_assert!(!cols.is_empty());
        let mut node = &mut self.root;
        for &col in cols {
            let Some(value) = terms.get(col) else {
                return;
            };
            node = node.children.entry(value.clone()).or_default();
        }
    }

    /// Recanonicalize every key stored in this trie using `canonicalize`,
    /// merging subtrees whose keys collide in the same equivalence class.
    ///
    /// Traverses the trie iteratively (zero recursion), bounding work by
    /// `remaining_steps`, and returns `(rebuilt_trie, steps_spent, is_complete)`.
    pub(crate) fn into_recanonicalized<F>(
        self,
        remaining_steps: u64,
        canonicalize: &F,
    ) -> (Self, u64, bool)
    where
        F: Fn(&mneme_core::Value) -> mneme_core::Value,
    {
        if self.root.children.is_empty() {
            return (self, 0, true);
        }
        let mut rebuilt = FactTrie::default();
        let max_depth = 64_usize;
        let mut stack: Vec<std::collections::btree_map::IntoIter<mneme_core::Value, TrieNode>> =
            Vec::with_capacity(max_depth);
        stack.push(self.root.children.into_iter());
        let mut path: Vec<mneme_core::Value> = Vec::with_capacity(max_depth);
        let mut steps = 0_u64;
        let max_iterations = remaining_steps.saturating_mul(2).saturating_add(4);
        for _ in 0..max_iterations {
            let Some(top) = stack.last_mut() else {
                break;
            };
            let Some((value, child)) = top.next() else {
                stack.pop();
                path.pop();
                continue;
            };
            if steps >= remaining_steps {
                return (rebuilt, steps, false);
            }
            steps = steps.saturating_add(1);
            if path.len() < max_depth {
                path.push(canonicalize(&value));
            }
            if child.children.is_empty() {
                let mut node = &mut rebuilt.root;
                for item in &path {
                    node = node.children.entry(item.clone()).or_default();
                }
                path.pop();
            } else if stack.len() < max_depth {
                stack.push(child.children.into_iter());
            }
        }
        (rebuilt, steps, stack.is_empty())
    }
}

#[derive(Clone, Debug)]
struct ResolvedTerm {
    var_slot: Option<usize>,
    constant: Option<mneme_core::Value>,
}

impl ResolvedTerm {
    fn from_term(
        term: &crate::Term,
        var_slots: &std::collections::BTreeMap<String, usize>,
    ) -> Option<Self> {
        if let crate::Term::Constant(value) = term {
            return Some(Self {
                var_slot: None,
                constant: Some(value.clone()),
            });
        }
        if let crate::Term::Variable(name) = term {
            return var_slots.get(name).copied().map(|slot| Self {
                var_slot: Some(slot),
                constant: None,
            });
        }
        None
    }

    fn resolve<'a>(
        &'a self,
        bound_values: &[Option<&'a mneme_core::Value>],
    ) -> Option<&'a mneme_core::Value> {
        if let Some(slot) = self.var_slot {
            return bound_values.get(slot).copied().flatten();
        }
        self.constant.as_ref()
    }
}

struct ScheduledCompare {
    op: crate::CompareOp,
    left: ResolvedTerm,
    right: ResolvedTerm,
}

struct ScheduledNegative {
    predicate: String,
    terms: Vec<ResolvedTerm>,
}

#[derive(Clone, Copy, Debug)]
struct LevelParticipant {
    atom_idx: usize,
    repeat_count: usize,
}

struct LevelStep {
    participants: Vec<LevelParticipant>,
    compares: Vec<ScheduledCompare>,
    negatives: Vec<ScheduledNegative>,
}

struct AtomTrieSpec<'a> {
    atom_idx: usize,
    body_index: usize,
    atom: &'a crate::Atom,
    const_cols: Vec<(usize, mneme_core::Value)>,
    var_cols: std::collections::BTreeMap<String, Vec<usize>>,
    col_order: Vec<usize>,
    extent: usize,
}

struct FreeJoinPlan<'a> {
    var_names: Vec<String>,
    atoms: Vec<AtomTrieSpec<'a>>,
    levels: Vec<LevelStep>,
    trailing_compares: Vec<usize>,
    trailing_negatives: Vec<usize>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct VarScore {
    is_payload_only: bool,
    is_unconnected: bool,
    closes_atoms: std::cmp::Reverse<usize>,
    connected_atoms: std::cmp::Reverse<usize>,
    total_atoms: std::cmp::Reverse<usize>,
    min_extent: usize,
    first_pos: usize,
}

struct VarInfo {
    first_pos: usize,
    atom_indices: Vec<usize>,
    has_filter_use: bool,
}

struct DfsFrame<'a> {
    driver_atom: usize,
    driver_repeat: usize,
    iter: std::collections::btree_map::Iter<'a, mneme_core::Value, TrieNode>,
}

struct BodyParts<'a> {
    ground_positives: Vec<&'a crate::Atom>,
    trie_atoms: Vec<AtomTrieSpec<'a>>,
    zero_compares: Vec<(crate::CompareOp, &'a crate::Term, &'a crate::Term)>,
    zero_negatives: Vec<&'a crate::Atom>,
    var_compares: Vec<(
        usize,
        crate::CompareOp,
        &'a crate::Term,
        &'a crate::Term,
        std::collections::BTreeSet<String>,
    )>,
    var_negatives: Vec<(usize, &'a crate::Atom, std::collections::BTreeSet<String>)>,
}

/// Evaluate a multi-atom rule body using deterministic Free Join over sorted tries.
pub(super) fn evaluate_free_join_body(
    evaluation: &mut super::engine::Evaluation<'_>,
    rule: &crate::Rule,
) -> Result<super::engine::RuleBindings, super::engine::RuleOutcome> {
    evaluate_free_join_with_delta(evaluation, rule, None)
}

/// Evaluate a multi-atom rule body using semi-naive Free Join where positive body
/// atom at `delta_body_index` reads only from `delta_facts` (`ΔR ⋈ S`).
pub(super) fn evaluate_free_join_semi_naive(
    evaluation: &mut super::engine::Evaluation<'_>,
    rule: &crate::Rule,
    delta_facts: &std::collections::BTreeMap<String, super::engine::FactStore>,
    delta_body_index: usize,
) -> Result<super::engine::RuleBindings, super::engine::RuleOutcome> {
    evaluate_free_join_with_delta(evaluation, rule, Some((delta_facts, delta_body_index)))
}

fn evaluate_free_join_with_delta(
    evaluation: &mut super::engine::Evaluation<'_>,
    rule: &crate::Rule,
    delta_source: Option<(
        &std::collections::BTreeMap<String, super::engine::FactStore>,
        usize,
    )>,
) -> Result<super::engine::RuleBindings, super::engine::RuleOutcome> {
    debug_assert!(!rule.body.is_empty());
    let parts = partition_rule_body(rule, &evaluation.facts, delta_source);
    verify_negative_coverage(evaluation, rule)?;
    check_zero_var_filters(evaluation, &parts)?;
    check_ground_positives(evaluation, &parts.ground_positives)?;
    if parts.trie_atoms.is_empty() {
        return Ok(vec![super::engine::Binding::new()]);
    }
    if any_store_empty(&parts.trie_atoms, &evaluation.facts, delta_source) {
        return Err(super::engine::RuleOutcome::Stable);
    }

    let plan = build_free_join_plan(parts);
    debug_assert_eq!(plan.var_names.len(), plan.levels.len());
    if plan.levels.is_empty() {
        return Ok(vec![super::engine::Binding::new()]);
    }
    let delta_trie = build_and_verify_tries(evaluation, &plan.atoms, delta_source)?;
    let mut output = run_free_join_dfs(evaluation, &plan, delta_trie.as_ref())?;
    apply_trailing_filters(evaluation, rule, &plan, &mut output)?;
    if output.is_empty() {
        return Err(super::engine::RuleOutcome::Stable);
    }
    if output.len() > 1 {
        super::engine::sort_bindings_by_written_order(rule, &mut output);
    }
    Ok(output)
}

fn verify_negative_coverage(
    evaluation: &super::engine::Evaluation<'_>,
    rule: &crate::Rule,
) -> Result<(), super::engine::RuleOutcome> {
    for literal in &rule.body {
        if let crate::Literal::Negative(atom) = literal
            && evaluation.coverage_status(&atom.predicate) != crate::CoverageStatus::Complete
        {
            return Err(super::engine::RuleOutcome::Skipped);
        }
    }
    Ok(())
}

fn partition_rule_body<'a>(
    rule: &'a crate::Rule,
    facts: &std::collections::BTreeMap<String, super::engine::FactStore>,
    delta_source: Option<(
        &std::collections::BTreeMap<String, super::engine::FactStore>,
        usize,
    )>,
) -> BodyParts<'a> {
    let mut parts = BodyParts {
        ground_positives: Vec::with_capacity(rule.body.len()),
        trie_atoms: Vec::with_capacity(rule.body.len()),
        zero_compares: Vec::new(),
        zero_negatives: Vec::new(),
        var_compares: Vec::new(),
        var_negatives: Vec::new(),
    };
    for (body_index, literal) in rule.body.iter().enumerate() {
        classify_literal(body_index, literal, facts, delta_source, &mut parts);
    }
    parts
}

fn classify_literal<'a>(
    body_index: usize,
    literal: &'a crate::Literal,
    facts: &std::collections::BTreeMap<String, super::engine::FactStore>,
    delta_source: Option<(
        &std::collections::BTreeMap<String, super::engine::FactStore>,
        usize,
    )>,
    parts: &mut BodyParts<'a>,
) {
    match literal {
        crate::Literal::Positive(atom) => {
            let source_facts = match delta_source {
                Some((delta_facts, delta_idx)) if delta_idx == body_index => delta_facts,
                Some(_) | None => facts,
            };
            push_positive_atom(body_index, atom, source_facts, parts);
        }
        crate::Literal::Negative(atom) => {
            let vars = atom_vars(atom);
            if vars.is_empty() {
                parts.zero_negatives.push(atom);
            } else {
                parts.var_negatives.push((body_index, atom, vars));
            }
        }
        crate::Literal::Compare { op, left, right } => {
            let mut vars = std::collections::BTreeSet::new();
            collect_term_var(left, &mut vars);
            collect_term_var(right, &mut vars);
            if vars.is_empty() {
                parts.zero_compares.push((*op, left, right));
            } else {
                parts
                    .var_compares
                    .push((body_index, *op, left, right, vars));
            }
        }
        _ => {}
    }
}

fn push_positive_atom<'a>(
    body_index: usize,
    atom: &'a crate::Atom,
    facts: &std::collections::BTreeMap<String, super::engine::FactStore>,
    parts: &mut BodyParts<'a>,
) {
    debug_assert!(!atom.terms.is_empty());
    debug_assert!(!atom.predicate.is_empty());
    let mut const_cols = Vec::with_capacity(atom.terms.len());
    let mut var_cols: std::collections::BTreeMap<String, Vec<usize>> =
        std::collections::BTreeMap::new();
    for (col, term) in atom.terms.iter().enumerate() {
        if let crate::Term::Constant(value) = term {
            const_cols.push((col, value.clone()));
        } else if let crate::Term::Variable(name) = term {
            var_cols.entry(name.clone()).or_default().push(col);
        }
    }
    if var_cols.is_empty() {
        parts.ground_positives.push(atom);
        return;
    }
    let atom_idx = parts.trie_atoms.len();
    let extent = facts
        .get(&atom.predicate)
        .map_or(0, |store| store.rows.len());
    parts.trie_atoms.push(AtomTrieSpec {
        atom_idx,
        body_index,
        atom,
        const_cols,
        var_cols,
        col_order: Vec::new(),
        extent,
    });
}

fn atom_vars(atom: &crate::Atom) -> std::collections::BTreeSet<String> {
    let mut vars = std::collections::BTreeSet::new();
    for term in &atom.terms {
        collect_term_var(term, &mut vars);
    }
    vars
}

fn collect_term_var(term: &crate::Term, vars: &mut std::collections::BTreeSet<String>) {
    if let crate::Term::Variable(name) = term {
        vars.insert(name.clone());
    }
}

fn check_zero_var_filters(
    evaluation: &mut super::engine::Evaluation<'_>,
    parts: &BodyParts<'_>,
) -> Result<(), super::engine::RuleOutcome> {
    let empty = super::engine::Binding::new();
    debug_assert!(empty.is_empty());
    debug_assert!(!parts.trie_atoms.is_empty() || !parts.ground_positives.is_empty());
    for &(op, left, right) in &parts.zero_compares {
        if !evaluation.budget.charge(1) {
            return Err(super::engine::RuleOutcome::Skipped);
        }
        let is_kept = match (
            super::engine::term_value(left, &empty),
            super::engine::term_value(right, &empty),
        ) {
            (Some(lval), Some(rval)) => super::engine::compare_values(op, &lval, &rval),
            _ => false,
        };
        if !is_kept {
            return Err(super::engine::RuleOutcome::Stable);
        }
    }
    for &atom in &parts.zero_negatives {
        if !evaluation.budget.charge(1) {
            return Err(super::engine::RuleOutcome::Skipped);
        }
        if super::engine::matches_atom(evaluation, atom, &empty)? {
            return Err(super::engine::RuleOutcome::Stable);
        }
    }
    Ok(())
}

fn check_ground_positives(
    evaluation: &mut super::engine::Evaluation<'_>,
    ground_positives: &[&crate::Atom],
) -> Result<(), super::engine::RuleOutcome> {
    let empty = super::engine::Binding::new();
    debug_assert!(empty.is_empty());
    debug_assert!(ground_positives.iter().all(|atom| !atom.terms.is_empty()));
    for &atom in ground_positives {
        if !evaluation.budget.charge(1) {
            return Err(super::engine::RuleOutcome::Skipped);
        }
        let Some(key) = atom
            .terms
            .iter()
            .map(|term| super::engine::term_value(term, &empty))
            .collect::<Option<Vec<_>>>()
        else {
            return Err(super::engine::RuleOutcome::Stable);
        };
        let is_present = evaluation
            .facts
            .get(&atom.predicate)
            .and_then(|store| store.rows.get(&key))
            .is_some_and(crate::FactData::is_active);
        if !is_present {
            return Err(super::engine::RuleOutcome::Stable);
        }
    }
    Ok(())
}

fn any_store_empty(
    atoms: &[AtomTrieSpec<'_>],
    facts: &std::collections::BTreeMap<String, super::engine::FactStore>,
    delta_source: Option<(
        &std::collections::BTreeMap<String, super::engine::FactStore>,
        usize,
    )>,
) -> bool {
    atoms.iter().any(|spec| {
        let source = match delta_source {
            Some((delta_facts, delta_idx)) if spec.body_index == delta_idx => delta_facts,
            Some(_) | None => facts,
        };
        source
            .get(&spec.atom.predicate)
            .is_none_or(|store| store.rows.is_empty())
    })
}

fn build_free_join_plan(mut parts: BodyParts<'_>) -> FreeJoinPlan<'_> {
    debug_assert!(!parts.trie_atoms.is_empty());
    let var_info = collect_var_info(&parts);
    let var_order = select_variable_order(&parts.trie_atoms, &var_info);
    let var_slots = var_order
        .iter()
        .enumerate()
        .map(|(slot, name)| (name.clone(), slot))
        .collect::<std::collections::BTreeMap<_, _>>();

    for spec in &mut parts.trie_atoms {
        spec.col_order = compute_col_order(spec, &var_order);
        debug_assert_eq!(spec.col_order.len(), spec.atom.terms.len());
    }

    let levels = build_level_steps(&var_order, &var_slots, &mut parts);
    let trailing_compares = parts
        .var_compares
        .iter()
        .map(|(body_index, _, _, _, _)| *body_index)
        .collect();
    let trailing_negatives = parts
        .var_negatives
        .iter()
        .map(|(body_index, _, _)| *body_index)
        .collect();

    FreeJoinPlan {
        var_names: var_order,
        atoms: parts.trie_atoms,
        levels,
        trailing_compares,
        trailing_negatives,
    }
}

fn collect_var_info(parts: &BodyParts<'_>) -> std::collections::BTreeMap<String, VarInfo> {
    debug_assert!(!parts.trie_atoms.is_empty());
    let mut info: std::collections::BTreeMap<String, VarInfo> = std::collections::BTreeMap::new();
    for (atom_idx, spec) in parts.trie_atoms.iter().enumerate() {
        for (name, cols) in &spec.var_cols {
            let first_col = cols.first().copied().unwrap_or(0);
            let pos = atom_idx.saturating_mul(1024).saturating_add(first_col);
            let entry = info.entry(name.clone()).or_insert_with(|| VarInfo {
                first_pos: pos,
                atom_indices: Vec::new(),
                has_filter_use: false,
            });
            entry.first_pos = entry.first_pos.min(pos);
            entry.atom_indices.push(atom_idx);
        }
    }
    mark_filter_vars(&parts.var_compares, &parts.var_negatives, &mut info);
    info
}

fn mark_filter_vars(
    var_compares: &[(
        usize,
        crate::CompareOp,
        &crate::Term,
        &crate::Term,
        std::collections::BTreeSet<String>,
    )],
    var_negatives: &[(usize, &crate::Atom, std::collections::BTreeSet<String>)],
    info: &mut std::collections::BTreeMap<String, VarInfo>,
) {
    for (_, _, _, _, vars) in var_compares {
        for name in vars {
            if let Some(entry) = info.get_mut(name) {
                entry.has_filter_use = true;
            }
        }
    }
    for (_, _, vars) in var_negatives {
        for name in vars {
            if let Some(entry) = info.get_mut(name) {
                entry.has_filter_use = true;
            }
        }
    }
}

fn select_variable_order(
    atoms: &[AtomTrieSpec<'_>],
    var_info: &std::collections::BTreeMap<String, VarInfo>,
) -> Vec<String> {
    let mut unbound = var_info
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    debug_assert_eq!(unbound.len(), var_info.len());
    let mut bound = std::collections::BTreeSet::new();
    let mut order = Vec::with_capacity(unbound.len());

    while !unbound.is_empty() {
        let mut best: Option<(VarScore, String)> = None;
        for name in &unbound {
            let Some(info) = var_info.get(name) else {
                continue;
            };
            let score = score_variable(name, info, atoms, &bound);
            let is_better = best
                .as_ref()
                .is_none_or(|(best_score, _)| score < *best_score);
            if is_better {
                best = Some((score, name.clone()));
            }
        }
        let Some((_, chosen)) = best else {
            break;
        };
        unbound.remove(&chosen);
        bound.insert(chosen.clone());
        order.push(chosen);
    }
    debug_assert_eq!(order.len(), var_info.len());
    order
}

fn score_variable(
    var_name: &str,
    info: &VarInfo,
    atoms: &[AtomTrieSpec<'_>],
    bound: &std::collections::BTreeSet<String>,
) -> VarScore {
    debug_assert!(!info.atom_indices.is_empty());
    let mut connected_atoms = 0_usize;
    let mut closes_atoms = 0_usize;
    let mut min_extent = usize::MAX;
    for &atom_idx in &info.atom_indices {
        let spec = &atoms[atom_idx];
        min_extent = min_extent.min(spec.extent);
        let has_bound = spec.var_cols.keys().any(|other| bound.contains(other));
        if has_bound {
            connected_atoms = connected_atoms.saturating_add(1);
        }
        let is_all_others_bound = spec
            .var_cols
            .keys()
            .all(|other| other == var_name || bound.contains(other));
        if is_all_others_bound {
            closes_atoms = closes_atoms.saturating_add(1);
        }
    }
    let total_atoms = info.atom_indices.len();
    debug_assert!(connected_atoms <= total_atoms);
    debug_assert!(closes_atoms <= total_atoms);
    let is_payload_only = total_atoms <= 1 && !info.has_filter_use;
    let is_unconnected = !bound.is_empty() && connected_atoms == 0;
    VarScore {
        is_payload_only,
        is_unconnected,
        closes_atoms: std::cmp::Reverse(closes_atoms),
        connected_atoms: std::cmp::Reverse(connected_atoms),
        total_atoms: std::cmp::Reverse(total_atoms),
        min_extent,
        first_pos: info.first_pos,
    }
}

fn compute_col_order(spec: &AtomTrieSpec<'_>, var_order: &[String]) -> Vec<usize> {
    let mut col_order = Vec::with_capacity(spec.atom.terms.len());
    for &(col, _) in &spec.const_cols {
        col_order.push(col);
    }
    for var_name in var_order {
        if let Some(cols) = spec.var_cols.get(var_name) {
            col_order.extend_from_slice(cols);
        }
    }
    col_order
}

fn build_level_steps(
    var_order: &[String],
    var_slots: &std::collections::BTreeMap<String, usize>,
    parts: &mut BodyParts<'_>,
) -> Vec<LevelStep> {
    debug_assert!(!var_order.is_empty());
    let mut bound = std::collections::BTreeSet::new();
    let mut levels = Vec::with_capacity(var_order.len());
    for var_name in var_order {
        bound.insert(var_name.clone());
        let participants = parts
            .trie_atoms
            .iter()
            .filter_map(|spec| {
                spec.var_cols.get(var_name).map(|cols| LevelParticipant {
                    atom_idx: spec.atom_idx,
                    repeat_count: cols.len(),
                })
            })
            .collect::<Vec<_>>();
        debug_assert!(!participants.is_empty());
        let compares = drain_ready_compares(&mut parts.var_compares, &bound, var_slots);
        let negatives = drain_ready_negatives(&mut parts.var_negatives, &bound, var_slots);
        levels.push(LevelStep {
            participants,
            compares,
            negatives,
        });
    }
    levels
}

fn drain_ready_compares(
    var_compares: &mut Vec<(
        usize,
        crate::CompareOp,
        &crate::Term,
        &crate::Term,
        std::collections::BTreeSet<String>,
    )>,
    bound: &std::collections::BTreeSet<String>,
    var_slots: &std::collections::BTreeMap<String, usize>,
) -> Vec<ScheduledCompare> {
    debug_assert!(!bound.is_empty());
    let mut ready = Vec::with_capacity(var_compares.len());
    let mut idx = 0_usize;
    while idx < var_compares.len() {
        if var_compares[idx].4.is_subset(bound) {
            let (_, op, left, right, _) = var_compares.remove(idx);
            if let (Some(left), Some(right)) = (
                ResolvedTerm::from_term(left, var_slots),
                ResolvedTerm::from_term(right, var_slots),
            ) {
                ready.push(ScheduledCompare { op, left, right });
            }
        } else {
            idx = idx.saturating_add(1);
        }
    }
    debug_assert!(var_compares.iter().all(|item| !item.4.is_subset(bound)));
    ready
}

fn drain_ready_negatives(
    var_negatives: &mut Vec<(usize, &crate::Atom, std::collections::BTreeSet<String>)>,
    bound: &std::collections::BTreeSet<String>,
    var_slots: &std::collections::BTreeMap<String, usize>,
) -> Vec<ScheduledNegative> {
    debug_assert!(!bound.is_empty());
    let mut ready = Vec::with_capacity(var_negatives.len());
    let mut idx = 0_usize;
    while idx < var_negatives.len() {
        if var_negatives[idx].2.is_subset(bound) {
            let (_, atom, _) = var_negatives.remove(idx);
            if let Some(terms) = atom
                .terms
                .iter()
                .map(|term| ResolvedTerm::from_term(term, var_slots))
                .collect()
            {
                ready.push(ScheduledNegative {
                    predicate: atom.predicate.clone(),
                    terms,
                });
            }
        } else {
            idx = idx.saturating_add(1);
        }
    }
    debug_assert!(var_negatives.iter().all(|item| !item.2.is_subset(bound)));
    ready
}

struct DeltaTrieSlot {
    atom_idx: usize,
    trie: FactTrie,
}

fn build_and_verify_tries(
    evaluation: &mut super::engine::Evaluation<'_>,
    atoms: &[AtomTrieSpec<'_>],
    delta_source: Option<(
        &std::collections::BTreeMap<String, super::engine::FactStore>,
        usize,
    )>,
) -> Result<Option<DeltaTrieSlot>, super::engine::RuleOutcome> {
    let mut build_order = (0..atoms.len()).collect::<Vec<_>>();
    build_order.sort_by_key(|&idx| {
        let spec = &atoms[idx];
        (
            std::cmp::Reverse(spec.const_cols.len()),
            spec.extent,
            spec.atom_idx,
        )
    });
    debug_assert_eq!(build_order.len(), atoms.len());
    let mut delta_slot = None;
    for idx in build_order {
        let spec = &atoms[idx];
        let arity = spec.atom.terms.len();
        if let Some((delta_facts, delta_body_index)) = delta_source
            && spec.body_index == delta_body_index
        {
            let trie = build_delta_trie(
                &mut evaluation.budget,
                delta_facts,
                &spec.atom.predicate,
                arity,
                &spec.col_order,
            )?;
            verify_const_prefix_in_trie(&mut evaluation.budget, &trie, &spec.const_cols)?;
            delta_slot = Some(DeltaTrieSlot {
                atom_idx: spec.atom_idx,
                trie,
            });
            continue;
        }
        ensure_trie(evaluation, &spec.atom.predicate, arity, &spec.col_order)?;
        verify_const_prefix(evaluation, spec)?;
    }
    Ok(delta_slot)
}

fn build_delta_trie(
    budget: &mut super::engine::Budget<'_>,
    delta_facts: &std::collections::BTreeMap<String, super::engine::FactStore>,
    predicate: &str,
    arity: usize,
    col_order: &[usize],
) -> Result<FactTrie, super::engine::RuleOutcome> {
    let Some(store) = delta_facts.get(predicate) else {
        return Err(super::engine::RuleOutcome::Stable);
    };
    let mut trie = FactTrie::default();
    for (terms, data) in &store.rows {
        if !budget.charge(1) {
            return Err(super::engine::RuleOutcome::Skipped);
        }
        if terms.len() != arity || !data.is_active() {
            continue;
        }
        trie.insert(terms, col_order);
    }
    Ok(trie)
}

fn verify_const_prefix_in_trie(
    budget: &mut super::engine::Budget<'_>,
    trie: &FactTrie,
    const_cols: &[(usize, mneme_core::Value)],
) -> Result<(), super::engine::RuleOutcome> {
    let mut node = &trie.root;
    for (_, expected) in const_cols {
        if !budget.charge(1) {
            return Err(super::engine::RuleOutcome::Skipped);
        }
        let Some(child) = node.children.get(expected) else {
            return Err(super::engine::RuleOutcome::Stable);
        };
        node = child;
    }
    Ok(())
}

fn ensure_trie(
    evaluation: &mut super::engine::Evaluation<'_>,
    predicate: &str,
    arity: usize,
    col_order: &[usize],
) -> Result<(), super::engine::RuleOutcome> {
    debug_assert!(arity > 0);
    debug_assert_eq!(col_order.len(), arity);
    let Some(store) = evaluation.facts.get(predicate) else {
        return Err(super::engine::RuleOutcome::Stable);
    };
    let trie_key = (arity, col_order.to_vec());
    if store.tries.contains_key(&trie_key) {
        return Ok(());
    }
    let mut trie = FactTrie::default();
    for (terms, data) in &store.rows {
        if !evaluation.budget.charge(1) {
            return Err(super::engine::RuleOutcome::Skipped);
        }
        if terms.len() != arity || !data.is_active() {
            continue;
        }
        trie.insert(terms, col_order);
    }
    if let Some(store_mut) = evaluation.facts.get_mut(predicate) {
        store_mut.tries.insert(trie_key, trie);
    }
    Ok(())
}

fn verify_const_prefix(
    evaluation: &mut super::engine::Evaluation<'_>,
    spec: &AtomTrieSpec<'_>,
) -> Result<(), super::engine::RuleOutcome> {
    if spec.const_cols.is_empty() {
        return Ok(());
    }
    debug_assert!(!spec.col_order.is_empty());
    debug_assert_eq!(spec.col_order.len(), spec.atom.terms.len());
    let trie_key = (spec.atom.terms.len(), spec.col_order.clone());
    let Some(trie) = evaluation
        .facts
        .get(&spec.atom.predicate)
        .and_then(|store| store.tries.get(&trie_key))
    else {
        return Err(super::engine::RuleOutcome::Stable);
    };
    let mut node = &trie.root;
    for (_, expected) in &spec.const_cols {
        if !evaluation.budget.charge(1) {
            return Err(super::engine::RuleOutcome::Skipped);
        }
        let Some(child) = node.children.get(expected) else {
            return Err(super::engine::RuleOutcome::Stable);
        };
        node = child;
    }
    Ok(())
}

fn initial_cursors<'a>(
    facts: &'a std::collections::BTreeMap<String, super::engine::FactStore>,
    atoms: &[AtomTrieSpec<'_>],
    delta_slot: Option<&'a DeltaTrieSlot>,
) -> Option<Vec<&'a TrieNode>> {
    let mut cursors = Vec::with_capacity(atoms.len());
    for spec in atoms {
        let mut node = if let Some(slot) = delta_slot
            && slot.atom_idx == spec.atom_idx
        {
            &slot.trie.root
        } else {
            let trie_key = (spec.atom.terms.len(), spec.col_order.clone());
            &facts.get(&spec.atom.predicate)?.tries.get(&trie_key)?.root
        };
        for (_, expected) in &spec.const_cols {
            node = node.children.get(expected)?;
        }
        cursors.push(node);
    }
    debug_assert_eq!(cursors.len(), atoms.len());
    Some(cursors)
}

fn make_frame<'a>(
    level_idx: usize,
    cursors: &[&'a TrieNode],
    plan: &FreeJoinPlan<'_>,
) -> Option<DfsFrame<'a>> {
    debug_assert!(level_idx < plan.levels.len());
    debug_assert_eq!(cursors.len(), plan.atoms.len());
    let step = plan.levels.get(level_idx)?;
    let mut best: Option<(usize, LevelParticipant)> = None;
    for &participant in &step.participants {
        let len = cursors.get(participant.atom_idx)?.children.len();
        if len == 0 {
            return None;
        }
        if best.is_none_or(|(best_len, _)| len < best_len) {
            best = Some((len, participant));
        }
    }
    let (_, driver) = best?;
    let iter = cursors.get(driver.atom_idx)?.children.iter();
    Some(DfsFrame {
        driver_atom: driver.atom_idx,
        driver_repeat: driver.repeat_count,
        iter,
    })
}

struct DfsScratch<'a, 'b> {
    plan: &'b FreeJoinPlan<'b>,
    negative_facts: &'a std::collections::BTreeMap<String, super::engine::FactStore>,
    negation_semantics: crate::NegationSemantics,
    cursor_levels: Vec<Vec<&'a TrieNode>>,
    stack: Vec<DfsFrame<'a>>,
    bound_values: Vec<Option<&'a mneme_core::Value>>,
    ground_key_buf: Vec<mneme_core::Value>,
    output: super::engine::RuleBindings,
}

fn run_free_join_dfs(
    evaluation: &mut super::engine::Evaluation<'_>,
    plan: &FreeJoinPlan<'_>,
    delta_slot: Option<&DeltaTrieSlot>,
) -> Result<super::engine::RuleBindings, super::engine::RuleOutcome> {
    let depth = plan.levels.len();
    let atom_count = plan.atoms.len();
    debug_assert!(depth > 0);
    let Some(init_cursors) = initial_cursors(&evaluation.facts, &plan.atoms, delta_slot) else {
        return Err(super::engine::RuleOutcome::Stable);
    };
    let mut cursor_levels = Vec::with_capacity(depth.saturating_add(1));
    cursor_levels.push(init_cursors);
    cursor_levels.resize_with(depth.saturating_add(1), || Vec::with_capacity(atom_count));

    let mut stack = Vec::with_capacity(depth);
    let Some(frame0) = make_frame(0, &cursor_levels[0], plan) else {
        return Err(super::engine::RuleOutcome::Stable);
    };
    stack.push(frame0);

    let negative_facts = evaluation.negation_oracle.unwrap_or(&evaluation.facts);
    let negation_semantics = evaluation.negation_semantics;
    let mut scratch = DfsScratch {
        plan,
        negative_facts,
        negation_semantics,
        cursor_levels,
        stack,
        bound_values: vec![None; depth],
        ground_key_buf: Vec::new(),
        output: Vec::new(),
    };
    let budget = &mut evaluation.budget;
    let row_cap = budget.limits.max_result_rows;
    debug_assert_eq!(scratch.cursor_levels.len(), depth.saturating_add(1));

    while !scratch.stack.is_empty() {
        step_free_join_dfs(&mut scratch, budget, row_cap)?;
    }
    Ok(scratch.output)
}

fn step_free_join_dfs<'a>(
    scratch: &mut DfsScratch<'a, '_>,
    budget: &mut super::engine::Budget<'_>,
    row_cap: usize,
) -> Result<(), super::engine::RuleOutcome> {
    debug_assert!(!scratch.stack.is_empty());
    let level_idx = scratch.stack.len().saturating_sub(1);
    debug_assert!(level_idx < scratch.plan.levels.len());
    let next_entry = scratch.stack.last_mut().and_then(|frame| {
        frame
            .iter
            .next()
            .map(|(val, child)| (frame.driver_atom, frame.driver_repeat, val, child))
    });
    let Some((driver_atom, driver_repeat, val, driver_child)) = next_entry else {
        scratch.stack.pop();
        if let Some(slot) = scratch.bound_values.get_mut(level_idx) {
            *slot = None;
        }
        return Ok(());
    };
    if !budget.charge(1) {
        return Err(super::engine::RuleOutcome::Skipped);
    }
    let Some(driver_final) =
        advance_repeats(driver_child, val, driver_repeat.saturating_sub(1), budget)?
    else {
        return Ok(());
    };
    let next_level = level_idx.saturating_add(1);
    let (prev_slice, next_slice) = scratch.cursor_levels.split_at_mut(next_level);
    let current_cursors = &prev_slice[level_idx];
    let next_cursors = &mut next_slice[0];
    next_cursors.clear();
    next_cursors.extend_from_slice(current_cursors);
    next_cursors[driver_atom] = driver_final;

    let step = &scratch.plan.levels[level_idx];
    let mut probe = ProbeStep {
        step,
        driver_atom,
        val,
        current_cursors,
        next_cursors,
    };
    if !probe_other_participants(&mut probe, budget)? {
        return Ok(());
    }
    scratch.bound_values[level_idx] = Some(val);
    let neg_ctx = NegationCheckContext {
        facts: scratch.negative_facts,
        semantics: scratch.negation_semantics,
    };
    if !check_level_filters(
        step,
        &scratch.bound_values,
        neg_ctx,
        budget,
        &mut scratch.ground_key_buf,
    )? {
        return Ok(());
    }
    if next_level == scratch.plan.levels.len() {
        let extended = materialize_binding(&scratch.plan.var_names, &scratch.bound_values);
        super::engine::push_extended_binding(&mut scratch.output, extended, row_cap, budget)?;
    } else if let Some(child_frame) = make_frame(next_level, next_cursors, scratch.plan) {
        scratch.stack.push(child_frame);
    }
    Ok(())
}

struct ProbeStep<'a, 'b> {
    step: &'b LevelStep,
    driver_atom: usize,
    val: &'b mneme_core::Value,
    current_cursors: &'b [&'a TrieNode],
    next_cursors: &'b mut [&'a TrieNode],
}

fn advance_repeats<'a>(
    mut node: &'a TrieNode,
    val: &mneme_core::Value,
    extra_repeats: usize,
    budget: &mut super::engine::Budget<'_>,
) -> Result<Option<&'a TrieNode>, super::engine::RuleOutcome> {
    for _ in 0..extra_repeats {
        if !budget.charge(1) {
            return Err(super::engine::RuleOutcome::Skipped);
        }
        let Some(child) = node.children.get(val) else {
            return Ok(None);
        };
        node = child;
    }
    Ok(Some(node))
}

fn probe_other_participants<'a>(
    probe: &mut ProbeStep<'a, '_>,
    budget: &mut super::engine::Budget<'_>,
) -> Result<bool, super::engine::RuleOutcome> {
    for &participant in &probe.step.participants {
        if participant.atom_idx == probe.driver_atom {
            continue;
        }
        let Some(start_node) = probe.current_cursors.get(participant.atom_idx).copied() else {
            return Ok(false);
        };
        let Some(end_node) =
            advance_repeats(start_node, probe.val, participant.repeat_count, budget)?
        else {
            return Ok(false);
        };
        if let Some(slot) = probe.next_cursors.get_mut(participant.atom_idx) {
            *slot = end_node;
        }
    }
    Ok(true)
}

#[derive(Clone, Copy)]
struct NegationCheckContext<'a> {
    facts: &'a std::collections::BTreeMap<String, super::engine::FactStore>,
    semantics: crate::NegationSemantics,
}

fn check_level_filters(
    step: &LevelStep,
    bound_values: &[Option<&mneme_core::Value>],
    neg_ctx: NegationCheckContext<'_>,
    budget: &mut super::engine::Budget<'_>,
    ground_key_buf: &mut Vec<mneme_core::Value>,
) -> Result<bool, super::engine::RuleOutcome> {
    debug_assert!(!step.participants.is_empty());
    debug_assert!(!bound_values.is_empty());
    for compare in &step.compares {
        if !budget.charge(1) {
            return Err(super::engine::RuleOutcome::Skipped);
        }
        let is_kept = match (
            compare.left.resolve(bound_values),
            compare.right.resolve(bound_values),
        ) {
            (Some(left), Some(right)) => super::engine::compare_values(compare.op, left, right),
            _ => false,
        };
        if !is_kept {
            return Ok(false);
        }
    }
    for negative in &step.negatives {
        if !budget.charge(1) {
            return Err(super::engine::RuleOutcome::Skipped);
        }
        if matches_ground_negative(neg_ctx, negative, bound_values, budget, ground_key_buf)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn matches_ground_negative(
    neg_ctx: NegationCheckContext<'_>,
    negative: &ScheduledNegative,
    bound_values: &[Option<&mneme_core::Value>],
    budget: &mut super::engine::Budget<'_>,
    ground_key_buf: &mut Vec<mneme_core::Value>,
) -> Result<bool, super::engine::RuleOutcome> {
    debug_assert!(!negative.predicate.is_empty());
    let Some(store) = neg_ctx.facts.get(&negative.predicate) else {
        return Ok(false);
    };
    if store.rows.is_empty() {
        return Ok(false);
    }
    if !budget.charge(1) {
        return Err(super::engine::RuleOutcome::Skipped);
    }
    ground_key_buf.clear();
    for term in &negative.terms {
        let Some(value) = term.resolve(bound_values) else {
            return Ok(false);
        };
        ground_key_buf.push(value.clone());
    }
    debug_assert_eq!(ground_key_buf.len(), negative.terms.len());
    Ok(store
        .rows
        .get(ground_key_buf)
        .is_some_and(|data| super::engine::fact_blocks_negation(data, neg_ctx.semantics)))
}

fn materialize_binding(
    var_names: &[String],
    bound_values: &[Option<&mneme_core::Value>],
) -> super::engine::Binding {
    debug_assert_eq!(var_names.len(), bound_values.len());
    var_names
        .iter()
        .zip(bound_values)
        .filter_map(|(name, value)| value.map(|v| (name.clone(), (*v).clone())))
        .collect()
}

fn apply_trailing_filters(
    evaluation: &mut super::engine::Evaluation<'_>,
    rule: &crate::Rule,
    plan: &FreeJoinPlan<'_>,
    output: &mut super::engine::RuleBindings,
) -> Result<(), super::engine::RuleOutcome> {
    for &body_index in &plan.trailing_compares {
        if let crate::Literal::Compare { op, left, right } = &rule.body[body_index] {
            retain_compare_bindings(evaluation, *op, left, right, output)?;
        }
    }
    for &body_index in &plan.trailing_negatives {
        if let crate::Literal::Negative(atom) = &rule.body[body_index] {
            retain_negative_bindings(evaluation, atom, output)?;
        }
    }
    Ok(())
}

fn retain_compare_bindings(
    evaluation: &mut super::engine::Evaluation<'_>,
    op: crate::CompareOp,
    left: &crate::Term,
    right: &crate::Term,
    output: &mut super::engine::RuleBindings,
) -> Result<(), super::engine::RuleOutcome> {
    let initial_len = output.len();
    let mut kept = Vec::with_capacity(initial_len);
    for binding in output.drain(..) {
        if !evaluation.budget.charge(1) {
            return Err(super::engine::RuleOutcome::Skipped);
        }
        let is_kept = match (
            super::engine::term_value(left, &binding),
            super::engine::term_value(right, &binding),
        ) {
            (Some(lval), Some(rval)) => super::engine::compare_values(op, &lval, &rval),
            _ => false,
        };
        if is_kept {
            kept.push(binding);
        }
    }
    debug_assert!(output.is_empty());
    debug_assert!(kept.len() <= initial_len);
    *output = kept;
    Ok(())
}
fn retain_negative_bindings(
    evaluation: &mut super::engine::Evaluation<'_>,
    atom: &crate::Atom,
    output: &mut super::engine::RuleBindings,
) -> Result<(), super::engine::RuleOutcome> {
    let initial_len = output.len();
    let mut kept = Vec::with_capacity(initial_len);
    for binding in output.drain(..) {
        if !evaluation.budget.charge(1) {
            return Err(super::engine::RuleOutcome::Skipped);
        }
        if !super::engine::matches_atom(evaluation, atom, &binding)? {
            kept.push(binding);
        }
    }
    debug_assert!(output.is_empty());
    debug_assert!(kept.len() <= initial_len);
    *output = kept;
    Ok(())
}

// ---------------------------------------------------------------------------
// Incremental K-relation Free Join Delta Tries (DBSP multi-way telescoping)
// ---------------------------------------------------------------------------

/// One node in a weighted sorted trie carrying [`crate::zset::EpistemicWeight`] at leaves.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct WeightedTrieNode {
    pub(crate) children: std::collections::BTreeMap<mneme_core::Value, WeightedTrieNode>,
    pub(crate) weight: crate::zset::EpistemicWeight,
}

/// Incremental sorted trie storing a K-relation `EpistemicZSet<FactKey>` under a fixed column order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct WeightedFactTrie {
    pub(crate) root: WeightedTrieNode,
}

impl WeightedFactTrie {
    /// Whether the trie contains no non-zero leaves.
    pub(crate) fn is_empty(&self) -> bool {
        self.root.children.is_empty() && self.root.weight.is_zero()
    }

    /// Apply a signed [`crate::zset::EpistemicWeight`] delta for one ground tuple,
    /// pruning empty branches iteratively when a leaf weight cancels to zero.
    pub(crate) fn apply_delta(
        &mut self,
        terms: &[mneme_core::Value],
        cols: &[usize],
        delta: crate::zset::EpistemicWeight,
    ) -> Result<(), crate::Error> {
        if delta.is_zero() {
            return Ok(());
        }
        if cols.is_empty() {
            self.root.weight = self.root.weight.checked_add(delta)?;
            return Ok(());
        }
        let mut path = Vec::with_capacity(cols.len());
        for &col in cols {
            let Some(val) = terms.get(col) else {
                return Ok(());
            };
            path.push(val.clone());
        }
        let mut node = &mut self.root;
        for key in &path {
            node = node.children.entry(key.clone()).or_default();
        }
        node.weight = node.weight.checked_add(delta)?;
        if node.weight.is_zero() && node.children.is_empty() {
            self.prune_empty_path(&path);
        }
        Ok(())
    }

    fn prune_empty_path(&mut self, path: &[mneme_core::Value]) {
        for depth in (0..path.len()).rev() {
            let mut parent = &mut self.root;
            for key in &path[..depth] {
                let Some(next) = parent.children.get_mut(key) else {
                    return;
                };
                parent = next;
            }
            let key = &path[depth];
            let is_removable = parent
                .children
                .get(key)
                .is_some_and(|child| child.weight.is_zero() && child.children.is_empty());
            if is_removable {
                parent.children.remove(key);
            } else {
                break;
            }
        }
    }
}

/// Static Free Join column layout and variable schedule for one rule's positive body atoms.
#[derive(Clone, Debug)]
pub(crate) struct WeightedAtomLayout {
    pub(crate) predicate: String,
    pub(crate) arity: usize,
    pub(crate) const_cols: Vec<(usize, mneme_core::Value)>,
    pub(crate) col_order: Vec<usize>,
}

impl WeightedAtomLayout {
    pub(crate) fn matches_tuple(&self, terms: &[mneme_core::Value]) -> bool {
        terms.len() == self.arity
            && self
                .const_cols
                .iter()
                .all(|(col, expected)| terms.get(*col) == Some(expected))
    }
}

#[derive(Clone, Debug)]
struct WeightedLevel {
    participants: Vec<LevelParticipant>,
}

/// Precomputed WCOJ Free Join plan for incremental K-relation rule evaluation.
#[derive(Clone, Debug)]
pub(crate) struct WeightedJoinPlan {
    pub(crate) var_names: Vec<String>,
    pub(crate) atoms: Vec<WeightedAtomLayout>,
    levels: Vec<WeightedLevel>,
}

type AtomConstCols = Vec<(usize, mneme_core::Value)>;
type AtomVarCols = std::collections::BTreeMap<String, Vec<usize>>;

fn extract_weighted_atom_terms(
    atom_idx: usize,
    atom: &crate::Atom,
    var_atoms: &mut std::collections::BTreeMap<String, (usize, Vec<usize>)>,
) -> (AtomConstCols, AtomVarCols) {
    let mut const_cols = Vec::with_capacity(atom.terms.len());
    let mut var_cols: AtomVarCols = std::collections::BTreeMap::new();
    for (col, term) in atom.terms.iter().enumerate() {
        if let crate::Term::Constant(value) = term {
            const_cols.push((col, value.clone()));
        } else if let crate::Term::Variable(name) = term {
            var_cols.entry(name.clone()).or_default().push(col);
            let pos = atom_idx.saturating_mul(1024).saturating_add(col);
            let entry = var_atoms
                .entry(name.clone())
                .or_insert_with(|| (pos, Vec::new()));
            entry.0 = entry.0.min(pos);
            if !entry.1.contains(&atom_idx) {
                entry.1.push(atom_idx);
            }
        }
    }
    (const_cols, var_cols)
}

fn build_weighted_atom_layout(
    atom: &crate::Atom,
    const_cols: &[(usize, mneme_core::Value)],
    var_cols: &AtomVarCols,
    var_names: &[String],
) -> WeightedAtomLayout {
    let mut col_order = Vec::with_capacity(atom.terms.len());
    for &(col, _) in const_cols {
        col_order.push(col);
    }
    for var_name in var_names {
        if let Some(cols) = var_cols.get(var_name) {
            col_order.extend_from_slice(cols);
        }
    }
    WeightedAtomLayout {
        predicate: atom.predicate.clone(),
        arity: atom.terms.len(),
        const_cols: const_cols.to_vec(),
        col_order,
    }
}

impl WeightedJoinPlan {
    /// Compile a deterministic multi-way Free Join plan from a rule's positive atoms.
    pub(crate) fn compile(positive_atoms: &[crate::Atom]) -> Self {
        let mut var_atoms: std::collections::BTreeMap<String, (usize, Vec<usize>)> =
            std::collections::BTreeMap::new();
        let mut per_atom_vars: Vec<AtomVarCols> = Vec::with_capacity(positive_atoms.len());
        let mut per_atom_consts: Vec<AtomConstCols> = Vec::with_capacity(positive_atoms.len());

        for (atom_idx, atom) in positive_atoms.iter().enumerate() {
            let (const_cols, var_cols) =
                extract_weighted_atom_terms(atom_idx, atom, &mut var_atoms);
            per_atom_consts.push(const_cols);
            per_atom_vars.push(var_cols);
        }

        // Order variables by decreasing join degree, then first occurrence.
        let mut var_names: Vec<String> = var_atoms.keys().cloned().collect();
        var_names.sort_by_key(|name| {
            let (first_pos, indices) = &var_atoms[name];
            (std::cmp::Reverse(indices.len()), *first_pos, name.clone())
        });

        let atoms = positive_atoms
            .iter()
            .enumerate()
            .map(|(atom_idx, atom)| {
                build_weighted_atom_layout(
                    atom,
                    &per_atom_consts[atom_idx],
                    &per_atom_vars[atom_idx],
                    &var_names,
                )
            })
            .collect();

        let levels = var_names
            .iter()
            .map(|var_name| {
                let participants = per_atom_vars
                    .iter()
                    .enumerate()
                    .filter_map(|(atom_idx, var_cols)| {
                        var_cols.get(var_name).map(|cols| LevelParticipant {
                            atom_idx,
                            repeat_count: cols.len(),
                        })
                    })
                    .collect();
                WeightedLevel { participants }
            })
            .collect();

        Self {
            var_names,
            atoms,
            levels,
        }
    }
}

struct WeightedDfsFrame<'a> {
    driver_atom: usize,
    driver_repeat: usize,
    iter: std::collections::btree_map::Iter<'a, mneme_core::Value, WeightedTrieNode>,
}

struct WeightedDfsState<'a> {
    plan: &'a WeightedJoinPlan,
    cursor_levels: Vec<Vec<&'a WeightedTrieNode>>,
    stack: Vec<WeightedDfsFrame<'a>>,
    bound_values: Vec<Option<&'a mneme_core::Value>>,
    output: crate::zset::EpistemicZSet<super::engine::Binding>,
}

/// Evaluate one multi-way weighted Free Join term `T_0 ⋈ T_1 ⋈ ... ⋈ T_{k-1}`
/// over `WeightedFactTrie`s, returning an exact [`crate::zset::EpistemicZSet<Binding>`].
pub(crate) fn evaluate_weighted_free_join_term(
    plan: &WeightedJoinPlan,
    tries: &[&WeightedFactTrie],
    budget: &mut super::engine::Budget<'_>,
) -> Result<crate::zset::EpistemicZSet<super::engine::Binding>, crate::Error> {
    assert_eq!(plan.atoms.len(), tries.len());
    let mut output = crate::zset::EpistemicZSet::new();
    if tries.iter().any(|trie| trie.is_empty()) {
        return Ok(output);
    }
    let Some(init_cursors) = weighted_initial_cursors(&plan.atoms, tries, budget)? else {
        return Ok(output);
    };
    if plan.levels.is_empty() {
        let weight = multiply_cursor_weights(&init_cursors)?;
        if !weight.is_zero() {
            output.insert_weight(super::engine::Binding::new(), weight)?;
        }
        return Ok(output);
    }

    let depth = plan.levels.len();
    let mut cursor_levels = Vec::with_capacity(depth.saturating_add(1));
    cursor_levels.push(init_cursors);
    cursor_levels.resize_with(depth.saturating_add(1), || {
        Vec::with_capacity(plan.atoms.len())
    });

    let Some(frame0) = make_weighted_frame(0, &cursor_levels[0], plan) else {
        return Ok(output);
    };
    let mut stack = Vec::with_capacity(depth);
    stack.push(frame0);
    let mut state = WeightedDfsState {
        plan,
        cursor_levels,
        stack,
        bound_values: vec![None; depth],
        output,
    };
    while !state.stack.is_empty() {
        step_weighted_dfs(&mut state, budget)?;
    }
    Ok(state.output)
}

fn step_weighted_dfs<'a>(
    state: &mut WeightedDfsState<'a>,
    budget: &mut super::engine::Budget<'_>,
) -> Result<(), crate::Error> {
    let depth = state.plan.levels.len();
    let level_idx = state.stack.len().saturating_sub(1);
    let next_entry = state.stack.last_mut().and_then(|frame| {
        frame
            .iter
            .next()
            .map(|(val, child)| (frame.driver_atom, frame.driver_repeat, val, child))
    });
    let Some((driver_atom, driver_repeat, val, driver_child)) = next_entry else {
        state.stack.pop();
        if let Some(slot) = state.bound_values.get_mut(level_idx) {
            *slot = None;
        }
        return Ok(());
    };
    charge_weighted_budget(budget, 1)?;
    let Some(driver_final) =
        advance_weighted_repeats(driver_child, val, driver_repeat.saturating_sub(1), budget)?
    else {
        return Ok(());
    };
    let next_level = level_idx.saturating_add(1);
    let (prev_slice, next_slice) = state.cursor_levels.split_at_mut(next_level);
    let current_cursors = &prev_slice[level_idx];
    let next_cursors = &mut next_slice[0];
    next_cursors.clear();
    next_cursors.extend_from_slice(current_cursors);
    next_cursors[driver_atom] = driver_final;

    let mut probe = WeightedProbeStep {
        step: &state.plan.levels[level_idx],
        driver_atom,
        val,
        current_cursors,
        next_cursors,
    };
    if !probe_weighted_participants(&mut probe, budget)? {
        return Ok(());
    }
    state.bound_values[level_idx] = Some(val);
    if next_level == depth {
        let weight = multiply_cursor_weights(next_cursors)?;
        if !weight.is_zero() {
            let binding = materialize_binding(&state.plan.var_names, &state.bound_values);
            state.output.insert_weight(binding, weight)?;
        }
    } else if let Some(child_frame) = make_weighted_frame(next_level, next_cursors, state.plan) {
        state.stack.push(child_frame);
    }
    Ok(())
}

fn weighted_initial_cursors<'a>(
    atoms: &[WeightedAtomLayout],
    tries: &[&'a WeightedFactTrie],
    budget: &mut super::engine::Budget<'_>,
) -> Result<Option<Vec<&'a WeightedTrieNode>>, crate::Error> {
    let mut cursors = Vec::with_capacity(atoms.len());
    for (layout, trie) in atoms.iter().zip(tries) {
        let mut node = &trie.root;
        for (_, expected) in &layout.const_cols {
            charge_weighted_budget(budget, 1)?;
            let Some(child) = node.children.get(expected) else {
                return Ok(None);
            };
            node = child;
        }
        cursors.push(node);
    }
    Ok(Some(cursors))
}

fn make_weighted_frame<'a>(
    level_idx: usize,
    cursors: &[&'a WeightedTrieNode],
    plan: &WeightedJoinPlan,
) -> Option<WeightedDfsFrame<'a>> {
    let step = plan.levels.get(level_idx)?;
    let mut best: Option<(usize, LevelParticipant)> = None;
    for &participant in &step.participants {
        let len = cursors.get(participant.atom_idx)?.children.len();
        if len == 0 {
            return None;
        }
        if best.is_none_or(|(best_len, _)| len < best_len) {
            best = Some((len, participant));
        }
    }
    let (_, driver) = best?;
    let iter = cursors.get(driver.atom_idx)?.children.iter();
    Some(WeightedDfsFrame {
        driver_atom: driver.atom_idx,
        driver_repeat: driver.repeat_count,
        iter,
    })
}

fn advance_weighted_repeats<'a>(
    mut node: &'a WeightedTrieNode,
    val: &mneme_core::Value,
    extra_repeats: usize,
    budget: &mut super::engine::Budget<'_>,
) -> Result<Option<&'a WeightedTrieNode>, crate::Error> {
    for _ in 0..extra_repeats {
        charge_weighted_budget(budget, 1)?;
        let Some(child) = node.children.get(val) else {
            return Ok(None);
        };
        node = child;
    }
    Ok(Some(node))
}

struct WeightedProbeStep<'a, 'b> {
    step: &'b WeightedLevel,
    driver_atom: usize,
    val: &'b mneme_core::Value,
    current_cursors: &'b [&'a WeightedTrieNode],
    next_cursors: &'b mut [&'a WeightedTrieNode],
}

fn probe_weighted_participants<'a>(
    probe: &mut WeightedProbeStep<'a, '_>,
    budget: &mut super::engine::Budget<'_>,
) -> Result<bool, crate::Error> {
    for &participant in &probe.step.participants {
        if participant.atom_idx == probe.driver_atom {
            continue;
        }
        let Some(start_node) = probe.current_cursors.get(participant.atom_idx).copied() else {
            return Ok(false);
        };
        let Some(end_node) =
            advance_weighted_repeats(start_node, probe.val, participant.repeat_count, budget)?
        else {
            return Ok(false);
        };
        if let Some(slot) = probe.next_cursors.get_mut(participant.atom_idx) {
            *slot = end_node;
        }
    }
    Ok(true)
}

fn multiply_cursor_weights(
    cursors: &[&WeightedTrieNode],
) -> Result<crate::zset::EpistemicWeight, crate::Error> {
    let mut acc = crate::zset::EpistemicWeight::ONE;
    for node in cursors {
        acc = acc.join_mul(node.weight)?;
        if acc.is_zero() {
            return Ok(crate::zset::EpistemicWeight::ZERO);
        }
    }
    Ok(acc)
}

fn charge_weighted_budget(
    budget: &mut super::engine::Budget<'_>,
    amount: u64,
) -> Result<(), crate::Error> {
    if budget.charge(amount) {
        Ok(())
    } else {
        Err(crate::Error::LimitExceeded(
            "incremental Free Join work or time limit reached".to_owned(),
        ))
    }
}
