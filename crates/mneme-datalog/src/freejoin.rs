//! Worst-case optimal Free Join planning and sorted-trie evaluation.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

#[derive(Clone, Debug, Default)]
pub(crate) struct TrieNode {
    pub(crate) children: std::collections::BTreeMap<mneme_core::Value, TrieNode>,
}

#[derive(Clone, Debug, Default)]
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
    debug_assert!(!rule.body.is_empty());
    let parts = partition_rule_body(rule, &evaluation.facts);
    verify_negative_coverage(evaluation, rule)?;
    check_zero_var_filters(evaluation, &parts)?;
    check_ground_positives(evaluation, &parts.ground_positives)?;
    if parts.trie_atoms.is_empty() {
        return Ok(vec![super::engine::Binding::new()]);
    }
    if any_store_empty(&parts.trie_atoms, &evaluation.facts) {
        return Err(super::engine::RuleOutcome::Stable);
    }

    let plan = build_free_join_plan(parts);
    debug_assert_eq!(plan.var_names.len(), plan.levels.len());
    if plan.levels.is_empty() {
        return Ok(vec![super::engine::Binding::new()]);
    }
    build_and_verify_tries(evaluation, &plan.atoms)?;
    let mut output = run_free_join_dfs(evaluation, &plan)?;
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
        classify_literal(body_index, literal, facts, &mut parts);
    }
    parts
}

fn classify_literal<'a>(
    body_index: usize,
    literal: &'a crate::Literal,
    facts: &std::collections::BTreeMap<String, super::engine::FactStore>,
    parts: &mut BodyParts<'a>,
) {
    match literal {
        crate::Literal::Positive(atom) => push_positive_atom(atom, facts, parts),
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
) -> bool {
    atoms.iter().any(|spec| {
        facts
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

fn build_and_verify_tries(
    evaluation: &mut super::engine::Evaluation<'_>,
    atoms: &[AtomTrieSpec<'_>],
) -> Result<(), super::engine::RuleOutcome> {
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
    for idx in build_order {
        let spec = &atoms[idx];
        let arity = spec.atom.terms.len();
        ensure_trie(evaluation, &spec.atom.predicate, arity, &spec.col_order)?;
        verify_const_prefix(evaluation, spec)?;
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
) -> Option<Vec<&'a TrieNode>> {
    let mut cursors = Vec::with_capacity(atoms.len());
    for spec in atoms {
        let trie_key = (spec.atom.terms.len(), spec.col_order.clone());
        let mut node = &facts.get(&spec.atom.predicate)?.tries.get(&trie_key)?.root;
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
    facts: &'a std::collections::BTreeMap<String, super::engine::FactStore>,
    cursor_levels: Vec<Vec<&'a TrieNode>>,
    stack: Vec<DfsFrame<'a>>,
    bound_values: Vec<Option<&'a mneme_core::Value>>,
    ground_key_buf: Vec<mneme_core::Value>,
    output: super::engine::RuleBindings,
}

fn run_free_join_dfs(
    evaluation: &mut super::engine::Evaluation<'_>,
    plan: &FreeJoinPlan<'_>,
) -> Result<super::engine::RuleBindings, super::engine::RuleOutcome> {
    let depth = plan.levels.len();
    let atom_count = plan.atoms.len();
    debug_assert!(depth > 0);
    let Some(init_cursors) = initial_cursors(&evaluation.facts, &plan.atoms) else {
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

    let mut scratch = DfsScratch {
        plan,
        facts: &evaluation.facts,
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
    if !check_level_filters(
        step,
        &scratch.bound_values,
        scratch.facts,
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

fn check_level_filters(
    step: &LevelStep,
    bound_values: &[Option<&mneme_core::Value>],
    facts: &std::collections::BTreeMap<String, super::engine::FactStore>,
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
        if matches_ground_negative(facts, negative, bound_values, budget, ground_key_buf)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn matches_ground_negative(
    facts: &std::collections::BTreeMap<String, super::engine::FactStore>,
    negative: &ScheduledNegative,
    bound_values: &[Option<&mneme_core::Value>],
    budget: &mut super::engine::Budget<'_>,
    ground_key_buf: &mut Vec<mneme_core::Value>,
) -> Result<bool, super::engine::RuleOutcome> {
    debug_assert!(!negative.predicate.is_empty());
    let Some(store) = facts.get(&negative.predicate) else {
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
        .is_some_and(crate::FactData::is_active))
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
