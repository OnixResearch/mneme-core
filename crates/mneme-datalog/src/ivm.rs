//! Incremental Datalog view maintenance via DBSP Z-set delta propagation.
//!
//! Each stratum in a validated [`crate::RuleProgram`] is partitioned into
//! dependency-connected predicate components. Non-recursive components maintain
//! a single Z-set pipeline; recursive components maintain an inner-iteration
//! trace (`rounds`) so inserts, replacements, retractions, and cycles converge
//! deterministically to the exact least fixpoint.

type Binding = crate::engine::Binding;
type FactKey = crate::engine::FactKey;
type JoinKey = Vec<mneme_core::Value>;

#[derive(Clone, Debug)]
struct AggSpec {
    function: crate::AggregateFunction,
    input: crate::Term,
    output: String,
    group_vars: std::collections::BTreeSet<String>,
}

/// Per-rule incremental operator pipeline and cached intermediate Z-sets.
#[derive(Clone, Debug)]
pub(crate) struct RuleState {
    pub(crate) rule: crate::Rule,
    positive_atoms: Vec<crate::Atom>,
    compares: Vec<(crate::CompareOp, crate::Term, crate::Term)>,
    negatives: Vec<crate::Atom>,
    aggregate: Option<AggSpec>,
    atom_bindings: Vec<crate::zset::ZSet<Binding>>,
    join_steps: Vec<crate::zset::ZSet<Binding>>,
    shared_vars: Vec<Vec<String>>,
    join_left_indexes: Vec<crate::zset::IndexedZSet<JoinKey, Binding>>,
    join_right_indexes: Vec<crate::zset::IndexedZSet<JoinKey, Binding>>,
    after_compare: crate::zset::ZSet<Binding>,
    neg_steps: Vec<crate::zset::ZSet<Binding>>,
    neg_left_indexes: Vec<crate::zset::IndexedZSet<FactKey, Binding>>,
    neg_right_indexes: Vec<crate::zset::IndexedZSet<FactKey, ()>>,
    agg_groups: crate::zset::IndexedZSet<JoinKey, Binding>,
    agg_group_outputs: std::collections::BTreeMap<JoinKey, FactKey>,
    head_bindings: std::collections::BTreeMap<FactKey, std::collections::BTreeSet<Binding>>,
    is_unit_seeded: bool,
    pub(crate) output: crate::zset::ZSet<FactKey>,
}

impl RuleState {
    pub(crate) fn new(rule: crate::Rule) -> Self {
        assert!(!rule.head.predicate.is_empty());
        let cap = rule.body.len();
        let mut positive_atoms = Vec::with_capacity(cap);
        let mut compares = Vec::with_capacity(cap);
        let mut negatives = Vec::with_capacity(cap);
        let mut aggregate = None;
        for literal in &rule.body {
            match literal {
                crate::Literal::Positive(atom) => positive_atoms.push(atom.clone()),
                crate::Literal::Compare { op, left, right } => {
                    compares.push((*op, left.clone(), right.clone()));
                }
                crate::Literal::Negative(atom) => negatives.push(atom.clone()),
                crate::Literal::Aggregate {
                    function,
                    input,
                    output,
                } => {
                    aggregate = Some(AggSpec {
                        function: *function,
                        input: input.clone(),
                        output: output.clone(),
                        group_vars: crate::engine::aggregate_group_variables_crate(
                            &rule.head, output,
                        ),
                    });
                }
                _ => {}
            }
        }
        let shared_vars = compute_shared_vars(&positive_atoms);
        let join_count = positive_atoms.len().saturating_sub(1);
        let neg_count = negatives.len();
        debug_assert!(positive_atoms.len() <= rule.body.len());
        RuleState {
            rule,
            atom_bindings: vec![crate::zset::ZSet::new(); positive_atoms.len()],
            join_steps: vec![crate::zset::ZSet::new(); positive_atoms.len()],
            positive_atoms,
            compares,
            neg_steps: vec![crate::zset::ZSet::new(); neg_count],
            neg_left_indexes: vec![crate::zset::IndexedZSet::new(); neg_count],
            neg_right_indexes: vec![crate::zset::IndexedZSet::new(); neg_count],
            negatives,
            aggregate,
            shared_vars,
            join_left_indexes: vec![crate::zset::IndexedZSet::new(); join_count],
            join_right_indexes: vec![crate::zset::IndexedZSet::new(); join_count],
            after_compare: crate::zset::ZSet::new(),
            agg_groups: crate::zset::IndexedZSet::new(),
            agg_group_outputs: std::collections::BTreeMap::new(),
            head_bindings: std::collections::BTreeMap::new(),
            is_unit_seeded: false,
            output: crate::zset::ZSet::new(),
        }
    }

    fn references_any_delta(
        &self,
        input_deltas: &std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    ) -> bool {
        if self.positive_atoms.is_empty() && !self.is_unit_seeded {
            return true;
        }
        let is_pos_dirty = self.positive_atoms.iter().any(|atom| {
            input_deltas
                .get(&atom.predicate)
                .is_some_and(|delta| !delta.is_empty())
        });
        let is_neg_dirty = self.negatives.iter().any(|atom| {
            input_deltas
                .get(&atom.predicate)
                .is_some_and(|delta| !delta.is_empty())
        });
        is_pos_dirty || is_neg_dirty
    }

    /// Apply input deltas through the DBSP operator pipeline and return `Δoutput`.
    pub(crate) fn step_delta(
        &mut self,
        input_deltas: &std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
        coverage: &std::collections::BTreeMap<String, crate::CoverageStatus>,
        budget: &mut crate::engine::Budget<'_>,
        coverage_reasons: &mut std::collections::BTreeMap<String, String>,
    ) -> Result<crate::zset::ZSet<FactKey>, crate::Error> {
        let is_non_monotonic = !self.negatives.is_empty() || self.aggregate.is_some();
        if is_non_monotonic && !is_rule_body_complete(&self.rule, coverage) {
            return self.retract_output_for_incomplete();
        }
        if !self.references_any_delta(input_deltas) {
            return Ok(crate::zset::ZSet::new());
        }
        let mut delta_cur = self.step_positive_joins(input_deltas, budget)?;
        delta_cur = self.step_compares(&delta_cur, budget)?;
        delta_cur = self.step_negatives(input_deltas, coverage, delta_cur, budget)?;
        self.step_head(&delta_cur, coverage, budget, coverage_reasons)
    }

    fn retract_output_for_incomplete(
        &mut self,
    ) -> Result<crate::zset::ZSet<FactKey>, crate::Error> {
        debug_assert!(!self.negatives.is_empty() || self.aggregate.is_some());
        if self.output.is_empty() {
            return Ok(crate::zset::ZSet::new());
        }
        let retraction = crate::zset::ZSet::new().subtract(&self.output)?;
        self.output = crate::zset::ZSet::new();
        self.head_bindings.clear();
        self.agg_group_outputs.clear();
        self.agg_groups = crate::zset::IndexedZSet::new();
        Ok(retraction)
    }

    fn step_positive_joins(
        &mut self,
        input_deltas: &std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
        budget: &mut crate::engine::Budget<'_>,
    ) -> Result<crate::zset::ZSet<Binding>, crate::Error> {
        assert_eq!(self.atom_bindings.len(), self.positive_atoms.len());
        assert_eq!(self.join_steps.len(), self.positive_atoms.len());
        if self.positive_atoms.is_empty() {
            if !self.is_unit_seeded {
                self.is_unit_seeded = true;
                let mut unit = crate::zset::ZSet::new();
                unit.insert_weighted(Binding::new(), 1)?;
                return Ok(unit);
            }
            return Ok(crate::zset::ZSet::new());
        }
        let mut delta_join = crate::zset::ZSet::new();
        for index in 0..self.positive_atoms.len() {
            let atom = &self.positive_atoms[index];
            let delta_atom = bind_optional_delta(atom, input_deltas.get(&atom.predicate), budget)?;
            if index == 0 {
                delta_join = delta_atom.clone();
                self.atom_bindings[0].add_in_place(&delta_atom)?;
                self.join_steps[0].add_in_place(&delta_join)?;
                continue;
            }
            let join_idx = index.saturating_sub(1);
            if delta_join.is_empty() && delta_atom.is_empty() {
                continue;
            }
            let vars = &self.shared_vars[join_idx];
            let delta_left =
                crate::zset::IndexedZSet::from_zset(&delta_join, |b| project_vars(b, vars))?;
            let delta_right =
                crate::zset::IndexedZSet::from_zset(&delta_atom, |b| project_vars(b, vars))?;
            let next_delta = crate::zset::delta_join(
                crate::zset::BilinearJoin {
                    left_prev: &self.join_left_indexes[join_idx],
                    left_delta: &delta_left,
                    right_prev: &self.join_right_indexes[join_idx],
                    right_delta: &delta_right,
                },
                merge_bindings,
                |cost| charge_budget(budget, cost),
            )?;
            self.join_left_indexes[join_idx]
                .apply_delta_with(&delta_join, |b| project_vars(b, vars))?;
            self.join_right_indexes[join_idx]
                .apply_delta_with(&delta_atom, |b| project_vars(b, vars))?;
            self.atom_bindings[index].add_in_place(&delta_atom)?;
            self.join_steps[index].add_in_place(&next_delta)?;
            delta_join = next_delta;
        }
        Ok(delta_join)
    }

    fn step_compares(
        &mut self,
        delta_in: &crate::zset::ZSet<Binding>,
        budget: &mut crate::engine::Budget<'_>,
    ) -> Result<crate::zset::ZSet<Binding>, crate::Error> {
        if delta_in.is_empty() || self.compares.is_empty() {
            self.after_compare.add_in_place(delta_in)?;
            return Ok(delta_in.clone());
        }
        let mut out = crate::zset::ZSet::new();
        for (binding, weight) in delta_in.iter() {
            charge_budget(budget, 1)?;
            if compares_hold(&self.compares, binding) {
                out.insert_weighted(binding.clone(), weight)?;
            }
        }
        self.after_compare.add_in_place(&out)?;
        Ok(out)
    }

    fn step_negatives(
        &mut self,
        input_deltas: &std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
        coverage: &std::collections::BTreeMap<String, crate::CoverageStatus>,
        mut delta_cur: crate::zset::ZSet<Binding>,
        budget: &mut crate::engine::Budget<'_>,
    ) -> Result<crate::zset::ZSet<Binding>, crate::Error> {
        assert_eq!(self.neg_steps.len(), self.negatives.len());
        assert_eq!(self.neg_left_indexes.len(), self.negatives.len());
        if !self.negatives.is_empty() && !is_rule_body_complete(&self.rule, coverage) {
            return Ok(crate::zset::ZSet::new());
        }
        for index in 0..self.negatives.len() {
            let neg_atom = &self.negatives[index];
            if !mneme_kernel::admission::non_monotonic_rule_admissible(kernel_coverage(
                coverage_status_of(coverage, &neg_atom.predicate),
            )) {
                return Ok(crate::zset::ZSet::new());
            }
            let delta_neg_raw =
                filter_optional_neg(neg_atom, input_deltas.get(&neg_atom.predicate), budget)?;
            if delta_cur.is_empty() && delta_neg_raw.is_empty() {
                continue;
            }
            let delta_left =
                crate::zset::IndexedZSet::from_zset(&delta_cur, |b| neg_atom_key(neg_atom, b))?;
            let mut delta_right = crate::zset::IndexedZSet::new();
            for (key, weight) in delta_neg_raw.iter() {
                delta_right.insert_weighted(key.clone(), (), weight)?;
            }
            let matched_delta = crate::zset::delta_join(
                crate::zset::BilinearJoin {
                    left_prev: &self.neg_left_indexes[index],
                    left_delta: &delta_left,
                    right_prev: &self.neg_right_indexes[index],
                    right_delta: &delta_right,
                },
                |binding, _| Some(binding.clone()),
                |cost| charge_budget(budget, cost),
            )?;
            let next_delta = delta_cur.subtract(&matched_delta)?;
            self.neg_left_indexes[index]
                .apply_delta_with(&delta_cur, |b| neg_atom_key(neg_atom, b))?;
            for (key, weight) in delta_neg_raw.iter() {
                self.neg_right_indexes[index].insert_weighted(key.clone(), (), weight)?;
            }
            self.neg_steps[index].add_in_place(&next_delta)?;
            delta_cur = next_delta;
        }
        Ok(delta_cur)
    }

    fn step_head(
        &mut self,
        delta_bindings: &crate::zset::ZSet<Binding>,
        coverage: &std::collections::BTreeMap<String, crate::CoverageStatus>,
        budget: &mut crate::engine::Budget<'_>,
        coverage_reasons: &mut std::collections::BTreeMap<String, String>,
    ) -> Result<crate::zset::ZSet<FactKey>, crate::Error> {
        assert!(!self.rule.head.predicate.is_empty());
        if delta_bindings.is_empty() {
            return Ok(crate::zset::ZSet::new());
        }
        if let Some(agg) = self.aggregate.clone() {
            return self.step_aggregate_head(
                &agg,
                delta_bindings,
                coverage,
                budget,
                coverage_reasons,
            );
        }
        let mut delta_out = crate::zset::ZSet::new();
        for (binding, weight) in delta_bindings.iter() {
            charge_budget(budget, 1)?;
            let Some(terms) = crate::engine::head_terms_crate(&self.rule.head, binding) else {
                record_coverage_reason(
                    coverage_reasons,
                    PredicateReason {
                        predicate: &self.rule.head.predicate,
                        reason: "rule head has an unbound variable",
                    },
                );
                continue;
            };
            update_head_binding_index(&mut self.head_bindings, &terms, binding, weight);
            delta_out.insert_weighted(terms, weight)?;
        }
        self.output.add_in_place(&delta_out)?;
        debug_assert!(self.output.iter().all(|(_, weight)| weight > 0));
        Ok(delta_out)
    }

    fn step_aggregate_head(
        &mut self,
        agg: &AggSpec,
        delta_bindings: &crate::zset::ZSet<Binding>,
        coverage: &std::collections::BTreeMap<String, crate::CoverageStatus>,
        budget: &mut crate::engine::Budget<'_>,
        coverage_reasons: &mut std::collections::BTreeMap<String, String>,
    ) -> Result<crate::zset::ZSet<FactKey>, crate::Error> {
        assert!(self.aggregate.is_some());
        if !is_rule_body_complete(&self.rule, coverage) {
            return Ok(crate::zset::ZSet::new());
        }
        let affected_groups: std::collections::BTreeSet<JoinKey> = delta_bindings
            .iter()
            .filter_map(|(binding, _)| aggregate_group_key(&agg.group_vars, binding))
            .collect();
        self.agg_groups
            .apply_delta_with(delta_bindings, |binding| {
                aggregate_group_key(&agg.group_vars, binding).unwrap_or_default()
            })?;
        let mut delta_out = crate::zset::ZSet::new();
        for group_key in affected_groups {
            charge_budget(budget, 1)?;
            if let Some(old_terms) = self.agg_group_outputs.remove(&group_key) {
                delta_out.insert_weighted(old_terms, -1)?;
            }
            let Some(bucket) = self.agg_groups.get(&group_key) else {
                continue;
            };
            match compute_group_head_row(&self.rule.head, agg, bucket) {
                Ok(Some(new_terms)) => {
                    self.agg_group_outputs.insert(group_key, new_terms.clone());
                    delta_out.insert_weighted(new_terms, 1)?;
                }
                Ok(None) => {}
                Err(reason) => {
                    record_coverage_reason(
                        coverage_reasons,
                        PredicateReason {
                            predicate: &self.rule.head.predicate,
                            reason,
                        },
                    );
                }
            }
        }
        self.output.add_in_place(&delta_out)?;
        debug_assert!(self.output.iter().all(|(_, weight)| weight > 0));
        Ok(delta_out)
    }

    pub(crate) fn ordinary_bindings_for(&self, head_terms: &FactKey) -> Vec<Binding> {
        self.head_bindings
            .get(head_terms)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub(crate) fn aggregate_bindings_for(&self, head_terms: &FactKey) -> Vec<Binding> {
        if self.aggregate.is_none() {
            return Vec::new();
        }
        let mut matched = Vec::with_capacity(self.agg_group_outputs.len());
        for (group_key, output_row) in &self.agg_group_outputs {
            if output_row != head_terms {
                continue;
            }
            if let Some(bucket) = self.agg_groups.get(group_key) {
                for (binding, weight) in bucket.iter() {
                    if weight > 0 {
                        matched.push(binding.clone());
                    }
                }
            }
        }
        debug_assert!(matched.len() < usize::MAX);
        debug_assert!(self.aggregate.is_some());
        matched
    }

    fn collect_dirty_heads_for_inputs(
        &self,
        dirty_inputs: &std::collections::BTreeMap<String, std::collections::BTreeSet<FactKey>>,
        out: &mut std::collections::BTreeMap<String, std::collections::BTreeSet<FactKey>>,
    ) {
        assert!(!self.rule.head.predicate.is_empty());
        for atom in &self.positive_atoms {
            let Some(keys) = dirty_inputs.get(&atom.predicate) else {
                continue;
            };
            if keys.is_empty() {
                continue;
            }
            self.collect_dirty_ordinary_heads(atom, keys, out);
            self.collect_dirty_aggregate_heads(atom, keys, out);
        }
        debug_assert!(self.positive_atoms.len() <= self.rule.body.len());
    }

    fn collect_dirty_ordinary_heads(
        &self,
        atom: &crate::Atom,
        keys: &std::collections::BTreeSet<FactKey>,
        out: &mut std::collections::BTreeMap<String, std::collections::BTreeSet<FactKey>>,
    ) {
        for (head_key, bindings) in &self.head_bindings {
            if bindings.iter().any(|binding| {
                instantiate_atom(atom, binding).is_some_and(|inst| keys.contains(&inst))
            }) {
                out.entry(self.rule.head.predicate.clone())
                    .or_default()
                    .insert(head_key.clone());
            }
        }
    }

    fn collect_dirty_aggregate_heads(
        &self,
        atom: &crate::Atom,
        keys: &std::collections::BTreeSet<FactKey>,
        out: &mut std::collections::BTreeMap<String, std::collections::BTreeSet<FactKey>>,
    ) {
        if self.aggregate.is_none() {
            return;
        }
        for (group_key, output_row) in &self.agg_group_outputs {
            let Some(bucket) = self.agg_groups.get(group_key) else {
                continue;
            };
            if bucket.iter().any(|(binding, weight)| {
                weight > 0
                    && instantiate_atom(atom, binding).is_some_and(|inst| keys.contains(&inst))
            }) {
                out.entry(self.rule.head.predicate.clone())
                    .or_default()
                    .insert(output_row.clone());
            }
        }
    }
}

/// One inner-loop round of a component's evaluation.
#[derive(Clone, Debug, Default)]
pub(crate) struct ComponentRoundState {
    pub(crate) rule_states: std::collections::BTreeMap<String, RuleState>,
    pub(crate) derived_multisets: std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    pub(crate) derived_sets: std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
}

/// One dependency-connected predicate component within a single stratum.
#[derive(Clone, Debug)]
pub(crate) struct ComponentState {
    pub(crate) stratum: usize,
    pub(crate) id: String,
    pub(crate) predicates: std::collections::BTreeSet<String>,
    pub(crate) rule_ids: Vec<String>,
    pub(crate) is_recursive: bool,
    pub(crate) rounds: Vec<ComponentRoundState>,
}

/// Complete DBSP incremental view state across all strata of a [`crate::RuleProgram`].
#[derive(Clone, Debug, Default)]
pub(crate) struct ViewState {
    pub(crate) relations: std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    pub(crate) components: Vec<ComponentState>,
}

pub(crate) struct SyncRuleChangeRequest<'a> {
    pub(crate) program: &'a crate::RuleProgram,
    pub(crate) build_facts: &'a std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<FactKey, crate::FactData>,
    >,
    pub(crate) affected: &'a std::collections::BTreeSet<String>,
    pub(crate) base_coverage: &'a std::collections::BTreeMap<String, crate::CoverageStatus>,
    pub(crate) coverage_reasons: &'a std::collections::BTreeMap<String, String>,
    pub(crate) limits: &'a crate::Limits,
    pub(crate) initial_work: u64,
    pub(crate) start: std::time::Instant,
}

impl ViewState {
    /// Initialize DBSP state from loaded base facts with no derived rules.
    pub(crate) fn from_base_facts(
        facts: &std::collections::BTreeMap<String, crate::engine::FactStore>,
    ) -> Result<Self, crate::Error> {
        let pairs = facts
            .iter()
            .map(|(predicate, store)| {
                let entries: Vec<(FactKey, i64)> = store
                    .rows
                    .iter()
                    .filter(|(_, data)| data.is_active())
                    .map(|(key, _)| (key.clone(), 1))
                    .collect();
                Ok((predicate.clone(), crate::zset::ZSet::from_entries(entries)?))
            })
            .collect::<Result<Vec<_>, crate::Error>>()?;
        let relations: std::collections::BTreeMap<_, _> = pairs.into_iter().collect();
        debug_assert_eq!(relations.len(), facts.len());
        debug_assert!(relations.len() < usize::MAX);
        Ok(ViewState {
            relations,
            components: Vec::new(),
        })
    }

    /// Synchronize DBSP component states after `add_rule` or `retract_rule`,
    /// enforcing `request.limits` and reporting work spent via `work_charged`.
    pub(crate) fn sync_after_rule_change(
        &mut self,
        request: SyncRuleChangeRequest<'_>,
        work_charged: &mut u64,
    ) -> Result<(), crate::Error> {
        assert!(request.limits.max_work > 0);
        let next_relations = build_relations_map(request.build_facts)?;
        let specs = partition_program_components(request.program);
        let existing_by_key: std::collections::BTreeMap<(usize, String), &ComponentState> = self
            .components
            .iter()
            .map(|comp| ((comp.stratum, comp.id.clone()), comp))
            .collect();
        let mut budget = crate::engine::Budget {
            limits: request.limits,
            work: request.initial_work,
            stored_rows: 0,
            start: request.start,
            cancellation: None,
            status: crate::ExecutionStatus::Complete,
            limit_reached: false,
            support_truncated: false,
        };
        let rebuild_result = rebuild_components(
            &request,
            specs,
            &existing_by_key,
            &next_relations,
            &mut budget,
        );
        *work_charged = budget.work.saturating_sub(request.initial_work);
        debug_assert!(budget.work >= request.initial_work);
        let next_components = rebuild_result?;
        self.relations = next_relations;
        self.components = next_components;
        Ok(())
    }
}

fn build_relations_map(
    build_facts: &std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<FactKey, crate::FactData>,
    >,
) -> Result<std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>, crate::Error> {
    assert!(build_facts.len() < usize::MAX);
    let pairs = build_facts
        .iter()
        .map(|(predicate, rows)| {
            let entries: Vec<(FactKey, i64)> = rows
                .iter()
                .filter(|(_, data)| data.is_active())
                .map(|(key, _)| (key.clone(), 1))
                .collect();
            Ok((predicate.clone(), crate::zset::ZSet::from_entries(entries)?))
        })
        .collect::<Result<Vec<_>, crate::Error>>()?;
    let map: std::collections::BTreeMap<_, _> = pairs.into_iter().collect();
    debug_assert_eq!(map.len(), build_facts.len());
    Ok(map)
}

fn can_reuse_component(
    existing: Option<&&ComponentState>,
    spec: &ComponentSpec,
    has_affected: bool,
) -> bool {
    if has_affected {
        return false;
    }
    let Some(comp) = existing else {
        return false;
    };
    comp.rule_ids == spec.rule_ids && comp.predicates == spec.predicates
}

fn rebuild_components(
    request: &SyncRuleChangeRequest<'_>,
    specs: Vec<ComponentSpec>,
    existing_by_key: &std::collections::BTreeMap<(usize, String), &ComponentState>,
    next_relations: &std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    budget: &mut crate::engine::Budget<'_>,
) -> Result<Vec<ComponentState>, crate::Error> {
    assert!(specs.len() <= request.program.bundle.rules.len());
    let mut next_components = Vec::with_capacity(specs.len());
    let mut coverage_reasons = request.coverage_reasons.clone();
    let mut coverage_map = crate::engine::compute_derived_coverage(
        &request.program.bundle,
        request.base_coverage,
        &coverage_reasons,
        budget.status,
    );
    for spec in specs {
        let has_affected = spec
            .predicates
            .iter()
            .any(|predicate| request.affected.contains(predicate));
        let existing = existing_by_key.get(&(spec.stratum, spec.id.clone()));
        if can_reuse_component(existing, &spec, has_affected) {
            if let Some(comp) = existing {
                next_components.push((*comp).clone());
            }
            continue;
        }
        let mut comp = ComponentState {
            stratum: spec.stratum,
            id: spec.id,
            predicates: spec.predicates,
            rule_ids: spec.rule_ids,
            is_recursive: spec.is_recursive,
            rounds: Vec::new(),
        };
        let initial_deltas = external_inputs_for_component(request.program, &comp, next_relations);
        let prev_reasons_len = coverage_reasons.len();
        let _ = comp.step_component_delta(
            ComponentStepContext {
                program: request.program,
                external_deltas: &initial_deltas,
                coverage: &coverage_map,
                max_recursion_depth: request.limits.max_recursion_depth,
            },
            budget,
            &mut coverage_reasons,
        )?;
        if coverage_reasons.len() != prev_reasons_len {
            coverage_map = crate::engine::compute_derived_coverage(
                &request.program.bundle,
                request.base_coverage,
                &coverage_reasons,
                budget.status,
            );
        }
        next_components.push(comp);
    }
    debug_assert!(next_components.len() <= request.program.bundle.rules.len());
    Ok(next_components)
}

pub(crate) struct AdvanceViewRequest<'a> {
    pub(crate) program: &'a crate::RuleProgram,
    pub(crate) base_deltas: std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    pub(crate) dirty_provenance: std::collections::BTreeSet<(String, FactKey)>,
    pub(crate) next_base: &'a crate::engine::BaseSnapshot,
    pub(crate) next_context: &'a crate::BuildContext,
    pub(crate) limits: &'a crate::Limits,
    pub(crate) initial_work: u64,
    pub(crate) current_facts: &'a std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<FactKey, crate::FactData>,
    >,
    pub(crate) at: Option<mneme_core::Timestamp>,
    pub(crate) start: std::time::Instant,
}

pub(crate) struct AdvanceViewResult {
    pub(crate) next_view: ViewState,
    pub(crate) next_facts:
        std::collections::BTreeMap<String, std::collections::BTreeMap<FactKey, crate::FactData>>,
    pub(crate) coverage: Vec<crate::Coverage>,
    pub(crate) status: crate::ExecutionStatus,
    pub(crate) work: u64,
    pub(crate) support_truncated: bool,
    pub(crate) limit_reached: bool,
    pub(crate) affected_predicates: Vec<String>,
    pub(crate) reused_predicates: Vec<String>,
}

/// Propagate base Z-set deltas through all strata and refresh affected `FactData`.
pub(crate) fn advance_view(
    view: &ViewState,
    request: AdvanceViewRequest<'_>,
) -> Result<AdvanceViewResult, crate::Error> {
    assert!(request.limits.max_work > 0);
    let mut state = AdvanceAccumulator::new(view, &request)?;
    let mut budget = crate::engine::Budget {
        limits: request.limits,
        work: request.initial_work,
        stored_rows: 0,
        start: request.start,
        cancellation: None,
        status: crate::ExecutionStatus::Complete,
        limit_reached: false,
        support_truncated: request.next_base.support_truncated,
    };
    let mut coverage_reasons = request.next_base.coverage_reasons.clone();
    let mut coverage_map = crate::engine::compute_derived_coverage(
        &request.program.bundle,
        &request.next_base.base_coverage,
        &coverage_reasons,
        budget.status,
    );
    let is_ok = state.step_all_components(
        &request,
        &mut coverage_map,
        &mut budget,
        &mut coverage_reasons,
    )?;
    if !is_ok || budget.limit_reached || !budget.is_active() {
        return Ok(limit_reached_result(state.next_view, &budget));
    }
    debug_assert!(!budget.limit_reached);
    finish_advance_view(state, &request, &mut budget, &coverage_reasons)
}

struct ComponentStepRecord {
    comp_idx: usize,
    comp_deltas: std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    comp_multiset_deltas: std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    max_recursion_depth: usize,
}

struct AdvanceAccumulator {
    next_view: ViewState,
    all_deltas: std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    multiset_deltas: std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    dirty_by_pred: std::collections::BTreeMap<String, std::collections::BTreeSet<FactKey>>,
    affected_set: std::collections::BTreeSet<String>,
    reused_predicates: Vec<String>,
}

impl AdvanceAccumulator {
    fn new(view: &ViewState, request: &AdvanceViewRequest<'_>) -> Result<Self, crate::Error> {
        let mut next_view = view.clone();
        let all_deltas = request.base_deltas.clone();
        let mut dirty_by_pred: std::collections::BTreeMap<
            String,
            std::collections::BTreeSet<FactKey>,
        > = std::collections::BTreeMap::new();
        for (pred, key) in &request.dirty_provenance {
            dirty_by_pred
                .entry(pred.clone())
                .or_default()
                .insert(key.clone());
        }
        for (pred, delta) in &all_deltas {
            next_view
                .relations
                .entry(pred.clone())
                .or_default()
                .add_in_place(delta)?;
            if !delta.is_empty() {
                let dirty_entry = dirty_by_pred.entry(pred.clone()).or_default();
                for (key, weight) in delta.iter() {
                    if weight != 0 {
                        dirty_entry.insert(key.clone());
                    }
                }
            }
        }
        let affected_set = all_deltas
            .iter()
            .filter(|(_, delta)| !delta.is_empty())
            .map(|(pred, _)| pred.clone())
            .collect();
        let reused_cap = next_view
            .components
            .iter()
            .map(|comp| comp.predicates.len())
            .sum();
        debug_assert!(
            dirty_by_pred.len()
                <= request
                    .dirty_provenance
                    .len()
                    .saturating_add(all_deltas.len())
        );
        debug_assert!(all_deltas.len() < usize::MAX);
        Ok(Self {
            next_view,
            all_deltas,
            multiset_deltas: std::collections::BTreeMap::new(),
            dirty_by_pred,
            affected_set,
            reused_predicates: Vec::with_capacity(reused_cap),
        })
    }

    fn step_all_components(
        &mut self,
        request: &AdvanceViewRequest<'_>,
        coverage_map: &mut std::collections::BTreeMap<String, crate::CoverageStatus>,
        budget: &mut crate::engine::Budget<'_>,
        coverage_reasons: &mut std::collections::BTreeMap<String, String>,
    ) -> Result<bool, crate::Error> {
        let count = self.next_view.components.len();
        assert!(count <= request.program.bundle.rules.len());
        for idx in 0..count {
            if !budget.is_active() {
                break;
            }
            let prev_reasons_len = coverage_reasons.len();
            let step_result = self.next_view.components[idx].step_component_delta(
                ComponentStepContext {
                    program: request.program,
                    external_deltas: &self.all_deltas,
                    coverage: coverage_map,
                    max_recursion_depth: request.limits.max_recursion_depth,
                },
                budget,
                coverage_reasons,
            );
            let (comp_deltas, comp_multiset_deltas) = match step_result {
                Ok(res) => res,
                Err(crate::Error::LimitExceeded(_)) => return Ok(false),
                Err(err) => return Err(err),
            };
            if coverage_reasons.len() != prev_reasons_len {
                *coverage_map = crate::engine::compute_derived_coverage(
                    &request.program.bundle,
                    &request.next_base.base_coverage,
                    coverage_reasons,
                    budget.status,
                );
            }
            self.record_component_step(ComponentStepRecord {
                comp_idx: idx,
                comp_deltas,
                comp_multiset_deltas,
                max_recursion_depth: request.limits.max_recursion_depth,
            })?;
        }
        debug_assert!(self.reused_predicates.len() < usize::MAX);
        Ok(true)
    }

    fn record_component_step(&mut self, record: ComponentStepRecord) -> Result<(), crate::Error> {
        let ComponentStepRecord {
            comp_idx,
            comp_deltas,
            comp_multiset_deltas,
            max_recursion_depth,
        } = record;
        let component = &self.next_view.components[comp_idx];
        assert!(!component.predicates.is_empty());
        let mut is_component_affected = false;
        for (pred, delta) in comp_deltas {
            if !delta.is_empty() {
                is_component_affected = true;
                self.affected_set.insert(pred.clone());
                self.next_view
                    .relations
                    .entry(pred.clone())
                    .or_default()
                    .add_in_place(&delta)?;
            }
            self.all_deltas.insert(pred, delta);
        }
        for (pred, m_delta) in comp_multiset_deltas {
            if !m_delta.is_empty() {
                is_component_affected = true;
                self.affected_set.insert(pred.clone());
                let dirty_entry = self.dirty_by_pred.entry(pred.clone()).or_default();
                for (key, weight) in m_delta.iter() {
                    if weight != 0 {
                        dirty_entry.insert(key.clone());
                    }
                }
            }
            self.multiset_deltas.insert(pred, m_delta);
        }
        propagate_component_dirty_heads(component, &mut self.dirty_by_pred, max_recursion_depth);
        if !is_component_affected {
            for pred in &component.predicates {
                let is_clean = self
                    .dirty_by_pred
                    .get(pred)
                    .is_none_or(std::collections::BTreeSet::is_empty);
                if is_clean {
                    self.reused_predicates.push(pred.clone());
                } else {
                    self.affected_set.insert(pred.clone());
                }
            }
        }
        debug_assert!(
            !is_component_affected || self.all_deltas.len() >= component.predicates.len()
        );
        Ok(())
    }
}

fn propagate_component_dirty_heads(
    component: &ComponentState,
    dirty_by_pred: &mut std::collections::BTreeMap<String, std::collections::BTreeSet<FactKey>>,
    max_recursion_depth: usize,
) {
    assert!(!component.predicates.is_empty());
    let Some(last_round) = component.rounds.last() else {
        return;
    };
    let max_passes = component
        .rounds
        .len()
        .max(max_recursion_depth)
        .saturating_add(1);
    debug_assert!(max_passes > 0);
    for _ in 0..max_passes {
        let mut new_dirty = std::collections::BTreeMap::new();
        for rule_id in &component.rule_ids {
            if let Some(rule_state) = last_round.rule_states.get(rule_id) {
                rule_state.collect_dirty_heads_for_inputs(dirty_by_pred, &mut new_dirty);
            }
        }
        let mut is_any_added = false;
        for (pred, keys) in new_dirty {
            let entry = dirty_by_pred.entry(pred).or_default();
            for key in keys {
                if entry.insert(key) {
                    is_any_added = true;
                }
            }
        }
        if !is_any_added {
            break;
        }
    }
}

fn limit_reached_result(
    next_view: ViewState,
    budget: &crate::engine::Budget<'_>,
) -> AdvanceViewResult {
    AdvanceViewResult {
        next_view,
        next_facts: std::collections::BTreeMap::new(),
        coverage: Vec::new(),
        status: budget.status,
        work: budget.work,
        support_truncated: budget.support_truncated,
        limit_reached: true,
        affected_predicates: Vec::new(),
        reused_predicates: Vec::new(),
    }
}

fn finish_advance_view(
    mut state: AdvanceAccumulator,
    request: &AdvanceViewRequest<'_>,
    budget: &mut crate::engine::Budget<'_>,
    coverage_reasons: &std::collections::BTreeMap<String, String>,
) -> Result<AdvanceViewResult, crate::Error> {
    assert!(!budget.limit_reached);
    let mut next_facts = build_next_fact_stores(
        request.next_base,
        request.current_facts,
        request.next_context.served_revision,
    );
    let mut fact_predicates: std::collections::BTreeSet<String> =
        next_facts.keys().cloned().collect();
    fact_predicates.extend(state.next_view.relations.keys().cloned());
    let (coverage_map, coverage, coverage_status) =
        crate::engine::compute_coverage_for_facts(crate::engine::CoverageCheckRequest {
            base: request.next_base,
            bundle: &request.program.bundle,
            context: request.next_context,
            limits: request.limits,
            fact_predicates: &fact_predicates,
            coverage_reasons,
            at: request.at,
            start: request.start,
        });
    let is_truncated = refresh_derived_fact_data(
        RefreshFactDataRequest {
            view: &state.next_view,
            all_deltas: &state.all_deltas,
            multiset_deltas: &state.multiset_deltas,
            dirty_by_pred: &state.dirty_by_pred,
            next_context: request.next_context,
            limits: request.limits,
            coverage_map: &coverage_map,
        },
        budget,
        &mut next_facts,
    );
    if !budget.is_active() || budget.limit_reached {
        return Ok(limit_reached_result(state.next_view, budget));
    }
    let is_support_truncated = budget.support_truncated || is_truncated;
    let status = if budget.status != crate::ExecutionStatus::Complete {
        budget.status
    } else {
        coverage_status
    };
    state.reused_predicates.sort();
    debug_assert!(fact_predicates.len() >= next_facts.len());
    Ok(AdvanceViewResult {
        next_view: state.next_view,
        next_facts,
        coverage,
        status,
        work: budget.work,
        support_truncated: is_support_truncated,
        limit_reached: false,
        affected_predicates: state.affected_set.into_iter().collect(),
        reused_predicates: state.reused_predicates,
    })
}

fn build_next_fact_stores(
    next_base: &crate::engine::BaseSnapshot,
    current_facts: &std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<FactKey, crate::FactData>,
    >,
    target_revision: mneme_core::WorkspaceRevisionId,
) -> std::collections::BTreeMap<String, std::collections::BTreeMap<FactKey, crate::FactData>> {
    let mut next_facts: std::collections::BTreeMap<_, _> = current_facts
        .iter()
        .filter(|(pred, _)| !next_base.facts.contains_key(*pred))
        .map(|(pred, rows)| {
            let mut cloned = rows.clone();
            for data in cloned.values_mut() {
                for support in &mut data.supports {
                    support.revision = target_revision;
                }
            }
            (pred.clone(), cloned)
        })
        .collect();
    for (pred, store) in &next_base.facts {
        next_facts.insert(pred.clone(), store.rows.clone());
    }
    debug_assert!(next_facts.len() >= next_base.facts.len());
    debug_assert!(next_facts.len() < usize::MAX);
    next_facts
}

struct RefreshFactDataRequest<'a> {
    view: &'a ViewState,
    all_deltas: &'a std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    multiset_deltas: &'a std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    dirty_by_pred: &'a std::collections::BTreeMap<String, std::collections::BTreeSet<FactKey>>,
    next_context: &'a crate::BuildContext,
    limits: &'a crate::Limits,
    coverage_map: &'a std::collections::BTreeMap<String, crate::CoverageStatus>,
}

fn refresh_derived_fact_data(
    request: RefreshFactDataRequest<'_>,
    budget: &mut crate::engine::Budget<'_>,
    next_facts: &mut std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<FactKey, crate::FactData>,
    >,
) -> bool {
    let mut store_map: std::collections::BTreeMap<String, crate::engine::FactStore> = next_facts
        .iter()
        .map(|(pred, rows)| {
            (
                pred.clone(),
                crate::engine::FactStore::from_rows(rows.clone()),
            )
        })
        .collect();
    let mut is_any_truncated = false;
    for component in &request.view.components {
        if !budget.is_active() {
            break;
        }
        remove_retracted_rows(component, request.all_deltas, &mut store_map);
        let keys_to_refresh = collect_keys_to_refresh(component, &request, &mut store_map);
        if populate_refreshed_component_rows(
            component,
            &request,
            &keys_to_refresh,
            budget,
            &mut store_map,
        ) {
            is_any_truncated = true;
        }
    }
    if !budget.is_active() {
        return is_any_truncated;
    }
    *next_facts = store_map
        .into_iter()
        .map(|(pred, store)| (pred, store.rows))
        .collect();
    debug_assert!(next_facts.len() < usize::MAX);
    debug_assert!(request.limits.max_supports_per_fact > 0);
    is_any_truncated
}

fn remove_retracted_rows(
    component: &ComponentState,
    all_deltas: &std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    store_map: &mut std::collections::BTreeMap<String, crate::engine::FactStore>,
) {
    for pred in &component.predicates {
        if let Some(delta) = all_deltas.get(pred)
            && let Some(store) = store_map.get_mut(pred)
        {
            for (key, weight) in delta.iter() {
                if weight < 0 {
                    store.rows.remove(key);
                }
            }
        }
    }
}

fn collect_keys_to_refresh(
    component: &ComponentState,
    request: &RefreshFactDataRequest<'_>,
    store_map: &mut std::collections::BTreeMap<String, crate::engine::FactStore>,
) -> std::collections::BTreeMap<String, std::collections::BTreeSet<FactKey>> {
    assert!(!component.predicates.is_empty());
    let pairs: Vec<_> = component
        .predicates
        .iter()
        .map(|pred| {
            let mut set = std::collections::BTreeSet::new();
            if let Some(delta) = request.all_deltas.get(pred) {
                set.extend(delta.iter().filter(|(_, w)| *w > 0).map(|(k, _)| k.clone()));
            }
            let is_positive_rel = |key: &FactKey| {
                request
                    .view
                    .relations
                    .get(pred)
                    .is_some_and(|rel| rel.weight(key) > 0)
            };
            if let Some(m_delta) = request.multiset_deltas.get(pred) {
                set.extend(
                    m_delta
                        .iter()
                        .filter(|(k, w)| *w != 0 && is_positive_rel(k))
                        .map(|(k, _)| k.clone()),
                );
            }
            if let Some(dirty) = request.dirty_by_pred.get(pred) {
                set.extend(dirty.iter().filter(|k| is_positive_rel(k)).cloned());
            }
            if let Some(store) = store_map.get_mut(pred) {
                for key in &set {
                    store.rows.remove(key);
                }
            }
            (pred.clone(), set)
        })
        .collect();
    let keys_to_refresh: std::collections::BTreeMap<_, _> = pairs.into_iter().collect();
    debug_assert_eq!(keys_to_refresh.len(), component.predicates.len());
    keys_to_refresh
}

struct RoundRefreshTarget<'a> {
    component: &'a ComponentState,
    round: &'a ComponentRoundState,
    keys_to_refresh: &'a std::collections::BTreeMap<String, std::collections::BTreeSet<FactKey>>,
}

fn populate_refreshed_component_rows(
    component: &ComponentState,
    request: &RefreshFactDataRequest<'_>,
    keys_to_refresh: &std::collections::BTreeMap<String, std::collections::BTreeSet<FactKey>>,
    budget: &mut crate::engine::Budget<'_>,
    store_map: &mut std::collections::BTreeMap<String, crate::engine::FactStore>,
) -> bool {
    assert!(request.limits.max_supports_per_fact > 0);
    let mut is_any_truncated = false;
    for round in &component.rounds {
        if !budget.is_active() {
            return is_any_truncated;
        }
        let target = RoundRefreshTarget {
            component,
            round,
            keys_to_refresh,
        };
        let (is_round_truncated, _) = refresh_round_keys(&target, request, budget, store_map);
        is_any_truncated = is_any_truncated || is_round_truncated;
    }
    if component.is_recursive
        && budget.is_active()
        && let Some(last_round) = component.rounds.last()
    {
        for _ in 0..request.limits.max_recursion_depth {
            if !budget.is_active() {
                break;
            }
            let target = RoundRefreshTarget {
                component,
                round: last_round,
                keys_to_refresh,
            };
            let (is_round_truncated, is_any_upgraded) =
                refresh_round_keys(&target, request, budget, store_map);
            is_any_truncated = is_any_truncated || is_round_truncated;
            if !is_any_upgraded {
                break;
            }
        }
    }
    debug_assert!(component.rounds.len() < usize::MAX);
    is_any_truncated
}

fn refresh_round_keys(
    target: &RoundRefreshTarget<'_>,
    request: &RefreshFactDataRequest<'_>,
    budget: &mut crate::engine::Budget<'_>,
    store_map: &mut std::collections::BTreeMap<String, crate::engine::FactStore>,
) -> (bool, bool) {
    assert!(!target.component.predicates.is_empty());
    debug_assert!(request.limits.max_supports_per_fact > 0);
    let mut is_any_truncated = false;
    let mut is_any_upgraded = false;
    for pred in &target.component.predicates {
        if !budget.is_active() {
            break;
        }
        let Some(keys) = target.keys_to_refresh.get(pred) else {
            continue;
        };
        let Some(round_set) = target.round.derived_sets.get(pred) else {
            continue;
        };
        for key in keys {
            if !budget.is_active() {
                break;
            }
            if round_set.weight(key) <= 0 {
                continue;
            }
            let prev_epistemic = store_map
                .get(pred)
                .and_then(|s| s.rows.get(key))
                .map(|data| data.epistemic);
            let prev_supports = store_map
                .get(pred)
                .and_then(|s| s.rows.get(key))
                .map_or(0, |data| data.supports.len());
            if rebuild_fact_key_from_round(
                RoundKeyTarget {
                    component: target.component,
                    round: target.round,
                    pred,
                    key,
                },
                request,
                budget,
                store_map,
            ) {
                is_any_truncated = true;
            }
            let next_epistemic = store_map
                .get(pred)
                .and_then(|s| s.rows.get(key))
                .map(|data| data.epistemic);
            let next_supports = store_map
                .get(pred)
                .and_then(|s| s.rows.get(key))
                .map_or(0, |data| data.supports.len());
            if next_epistemic != prev_epistemic || next_supports != prev_supports {
                is_any_upgraded = true;
            }
        }
    }
    (is_any_truncated, is_any_upgraded)
}

struct RoundKeyTarget<'a> {
    component: &'a ComponentState,
    round: &'a ComponentRoundState,
    pred: &'a str,
    key: &'a FactKey,
}

fn rebuild_fact_key_from_round(
    target: RoundKeyTarget<'_>,
    request: &RefreshFactDataRequest<'_>,
    budget: &mut crate::engine::Budget<'_>,
    store_map: &mut std::collections::BTreeMap<String, crate::engine::FactStore>,
) -> bool {
    let RoundKeyTarget {
        component,
        round,
        pred,
        key,
    } = target;
    assert!(!pred.is_empty());
    if !budget.is_active() {
        return false;
    }
    let mut is_any_truncated = false;
    let mut target_store = store_map.get(pred).cloned().unwrap_or_default();
    for rule_id in &component.rule_ids {
        if !budget.is_active() {
            return is_any_truncated;
        }
        let Some(rule_state) = round.rule_states.get(rule_id) else {
            continue;
        };
        if rule_state.rule.head.predicate != pred {
            continue;
        }
        let bindings = if rule_state.aggregate.is_some() {
            rule_state.aggregate_bindings_for(key)
        } else {
            rule_state.ordinary_bindings_for(key)
        };
        if bindings.is_empty() {
            continue;
        }
        let build_req = crate::engine::FactDataBuildRequest {
            rule: &rule_state.rule,
            context: request.next_context,
            facts: store_map,
            coverage_map: request.coverage_map,
            bindings: &bindings,
            target_terms: key,
        };
        let is_truncated = if rule_state.aggregate.is_some() {
            crate::engine::build_aggregate_fact_data_from_bindings(
                build_req,
                budget,
                &mut target_store,
            )
        } else {
            crate::engine::build_ordinary_fact_data_from_bindings(
                build_req,
                budget,
                &mut target_store,
            )
        };
        if is_truncated {
            is_any_truncated = true;
        }
    }
    if !budget.is_active() {
        return is_any_truncated;
    }
    store_map.insert(pred.to_owned(), target_store);
    debug_assert!(store_map.contains_key(pred));
    is_any_truncated
}

type ComponentStepDelta = (
    std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
);

struct ComponentStepContext<'a> {
    program: &'a crate::RuleProgram,
    external_deltas: &'a std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    coverage: &'a std::collections::BTreeMap<String, crate::CoverageStatus>,
    max_recursion_depth: usize,
}

struct ComponentLoopState<'a> {
    program: &'a crate::RuleProgram,
    external_deltas: &'a std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    coverage: &'a std::collections::BTreeMap<String, crate::CoverageStatus>,
    prev_round_new_sets: std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    prev_round_delta_x: std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    next_rounds: Vec<ComponentRoundState>,
}

impl ComponentState {
    fn step_component_delta(
        &mut self,
        ctx: ComponentStepContext<'_>,
        budget: &mut crate::engine::Budget<'_>,
        coverage_reasons: &mut std::collections::BTreeMap<String, String>,
    ) -> Result<ComponentStepDelta, crate::Error> {
        let ComponentStepContext {
            program,
            external_deltas,
            coverage,
            max_recursion_depth,
        } = ctx;
        let prev_sets = last_derived_sets(&self.rounds);
        let prev_multisets = last_derived_multisets(&self.rounds);
        let has_ext_delta = component_has_external_delta(program, self, external_deltas);
        let has_incomplete_non_monotonic =
            component_has_incomplete_non_monotonic(program, self, coverage);
        if !self.rounds.is_empty() && !has_ext_delta && !has_incomplete_non_monotonic {
            return Ok((
                std::collections::BTreeMap::new(),
                std::collections::BTreeMap::new(),
            ));
        }

        let max_rounds = if self.is_recursive {
            max_recursion_depth.saturating_add(1)
        } else {
            1
        };
        let mut loop_state = ComponentLoopState {
            program,
            external_deltas,
            coverage,
            prev_round_new_sets: self
                .predicates
                .iter()
                .map(|p| (p.clone(), crate::zset::ZSet::new()))
                .collect(),
            prev_round_delta_x: std::collections::BTreeMap::new(),
            next_rounds: Vec::with_capacity(max_rounds.min(64)),
        };
        let is_initial_build = self.rounds.is_empty();
        let mut has_converged = false;
        for round_idx in 0..max_rounds {
            if self.advance_component_round(
                round_idx,
                is_initial_build,
                &mut loop_state,
                budget,
                coverage_reasons,
            )? {
                has_converged = true;
                break;
            }
        }
        if !has_converged && self.is_recursive {
            budget.stop(crate::ExecutionStatus::Partial);
            return Err(crate::Error::LimitExceeded(
                "incremental fixpoint exceeded max_recursion_depth".to_owned(),
            ));
        }
        self.rounds = loop_state.next_rounds;
        debug_assert!(!self.rounds.is_empty() || self.rule_ids.is_empty());
        debug_assert!(self.rounds.len() <= max_rounds);
        compute_outer_component_deltas(&self.predicates, &prev_sets, &prev_multisets, &self.rounds)
    }

    fn advance_component_round(
        &self,
        round_idx: usize,
        is_initial_build: bool,
        loop_state: &mut ComponentLoopState<'_>,
        budget: &mut crate::engine::Budget<'_>,
        coverage_reasons: &mut std::collections::BTreeMap<String, String>,
    ) -> Result<bool, crate::Error> {
        if !budget.is_active() {
            return Err(crate::Error::LimitExceeded(
                "budget exhausted during incremental fixpoint".to_owned(),
            ));
        }
        let (mut round, use_ext_deltas) =
            self.select_round_template(round_idx, is_initial_build, loop_state);
        let round_input_deltas = build_round_inputs(
            &self.predicates,
            use_ext_deltas,
            loop_state.external_deltas,
            &loop_state.prev_round_delta_x,
        );
        let round_m_deltas = step_round_rules(
            RoundStepInput {
                rule_ids: &self.rule_ids,
                input_deltas: &round_input_deltas,
                coverage: loop_state.coverage,
            },
            &mut round,
            budget,
            coverage_reasons,
        )?;
        let (round_x_deltas, round_new_sets) = apply_round_distinct_deltas(
            &self.predicates,
            &mut round,
            &round_m_deltas,
            is_initial_build,
            &loop_state.prev_round_new_sets,
        )?;
        let is_fixpoint = !self.is_recursive || round_new_sets == loop_state.prev_round_new_sets;
        assert!(!self.predicates.is_empty());
        loop_state.next_rounds.push(round);
        loop_state.prev_round_new_sets = round_new_sets;
        loop_state.prev_round_delta_x = round_x_deltas;
        debug_assert_eq!(loop_state.next_rounds.len(), round_idx.saturating_add(1));
        Ok(is_fixpoint)
    }

    fn select_round_template(
        &self,
        round_idx: usize,
        is_initial_build: bool,
        loop_state: &ComponentLoopState<'_>,
    ) -> (ComponentRoundState, bool) {
        if round_idx < self.rounds.len() {
            (self.rounds[round_idx].clone(), true)
        } else if is_initial_build {
            if let Some(last_new) = loop_state.next_rounds.last() {
                (last_new.clone(), false)
            } else {
                (empty_round_for_component(loop_state.program, self), true)
            }
        } else if let Some(last) = self.rounds.last() {
            (last.clone(), true)
        } else {
            (empty_round_for_component(loop_state.program, self), true)
        }
    }
}

fn last_derived_sets(
    rounds: &[ComponentRoundState],
) -> std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>> {
    rounds
        .last()
        .map(|r| r.derived_sets.clone())
        .unwrap_or_default()
}

fn last_derived_multisets(
    rounds: &[ComponentRoundState],
) -> std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>> {
    rounds
        .last()
        .map(|r| r.derived_multisets.clone())
        .unwrap_or_default()
}

fn build_round_inputs(
    predicates: &std::collections::BTreeSet<String>,
    use_ext_deltas: bool,
    external_deltas: &std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    prev_round_delta_x: &std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
) -> std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>> {
    let mut round_input_deltas = if use_ext_deltas {
        external_deltas.clone()
    } else {
        std::collections::BTreeMap::new()
    };
    for pred in predicates {
        if let Some(dx) = prev_round_delta_x.get(pred) {
            round_input_deltas.insert(pred.clone(), dx.clone());
        } else {
            round_input_deltas.remove(pred);
        }
    }
    debug_assert!(!predicates.is_empty());
    debug_assert!(round_input_deltas.len() < usize::MAX);
    round_input_deltas
}

struct RoundStepInput<'a> {
    rule_ids: &'a [String],
    input_deltas: &'a std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    coverage: &'a std::collections::BTreeMap<String, crate::CoverageStatus>,
}

fn step_round_rules(
    input: RoundStepInput<'_>,
    round: &mut ComponentRoundState,
    budget: &mut crate::engine::Budget<'_>,
    coverage_reasons: &mut std::collections::BTreeMap<String, String>,
) -> Result<std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>, crate::Error> {
    let RoundStepInput {
        rule_ids,
        input_deltas,
        coverage,
    } = input;
    assert!(!rule_ids.is_empty());
    let mut round_m_deltas: std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>> =
        std::collections::BTreeMap::new();
    for rule_id in rule_ids {
        let Some(rule_state) = round.rule_states.get_mut(rule_id) else {
            continue;
        };
        let delta_out = rule_state.step_delta(input_deltas, coverage, budget, coverage_reasons)?;
        if !delta_out.is_empty() {
            round_m_deltas
                .entry(rule_state.rule.head.predicate.clone())
                .or_default()
                .add_in_place(&delta_out)?;
        }
    }
    debug_assert!(round_m_deltas.len() <= rule_ids.len());
    Ok(round_m_deltas)
}

fn coverage_status_of(
    coverage: &std::collections::BTreeMap<String, crate::CoverageStatus>,
    predicate: &str,
) -> crate::CoverageStatus {
    coverage
        .get(predicate)
        .copied()
        .unwrap_or(crate::CoverageStatus::Unknown)
}

fn kernel_coverage(status: crate::CoverageStatus) -> mneme_kernel::completeness::Coverage {
    match status {
        crate::CoverageStatus::Complete => mneme_kernel::completeness::Coverage::Complete,
        crate::CoverageStatus::Incomplete => mneme_kernel::completeness::Coverage::Incomplete,
        crate::CoverageStatus::Unknown => mneme_kernel::completeness::Coverage::Unknown,
    }
}

fn is_rule_body_complete(
    rule: &crate::Rule,
    coverage: &std::collections::BTreeMap<String, crate::CoverageStatus>,
) -> bool {
    assert!(!rule.head.predicate.is_empty());
    let mut combined = mneme_kernel::completeness::Coverage::Complete;
    for literal in &rule.body {
        match literal {
            crate::Literal::Positive(atom) | crate::Literal::Negative(atom) => {
                combined = mneme_kernel::completeness::combine_coverage(
                    combined,
                    kernel_coverage(coverage_status_of(coverage, &atom.predicate)),
                );
            }
            crate::Literal::Forbidden(_) => return false,
            crate::Literal::Compare { .. } | crate::Literal::Aggregate { .. } => {}
        }
    }
    mneme_kernel::admission::non_monotonic_rule_admissible(combined)
}

fn component_has_incomplete_non_monotonic(
    program: &crate::RuleProgram,
    comp: &ComponentState,
    coverage: &std::collections::BTreeMap<String, crate::CoverageStatus>,
) -> bool {
    assert!(!comp.predicates.is_empty());
    program
        .bundle
        .rules
        .iter()
        .filter(|rule| comp.predicates.contains(&rule.head.predicate))
        .any(|rule| {
            let is_non_monotonic = rule.body.iter().any(|literal| {
                matches!(
                    literal,
                    crate::Literal::Negative(_) | crate::Literal::Aggregate { .. }
                )
            });
            is_non_monotonic && !is_rule_body_complete(rule, coverage)
        })
}

fn apply_round_distinct_deltas(
    predicates: &std::collections::BTreeSet<String>,
    round: &mut ComponentRoundState,
    round_m_deltas: &std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    is_initial_build: bool,
    prev_round_new_sets: &std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
) -> Result<ComponentStepDelta, crate::Error> {
    assert!(!predicates.is_empty());
    let mut x_delta_entries = Vec::with_capacity(predicates.len());
    let mut new_set_entries = Vec::with_capacity(predicates.len());
    for pred in predicates {
        let m_prev = round.derived_multisets.entry(pred.clone()).or_default();
        let x_prev = round.derived_sets.entry(pred.clone()).or_default();
        let x_delta = if let Some(m_delta) = round_m_deltas.get(pred) {
            let dx = m_prev.delta_distinct(m_delta)?;
            m_prev.add_in_place(m_delta)?;
            x_prev.add_in_place(&dx)?;
            dx
        } else {
            crate::zset::ZSet::new()
        };
        let effective_delta = if is_initial_build {
            let prev_s = prev_round_new_sets.get(pred).cloned().unwrap_or_default();
            x_prev.subtract(&prev_s)?
        } else {
            x_delta
        };
        x_delta_entries.push((pred.clone(), effective_delta));
        new_set_entries.push((pred.clone(), x_prev.clone()));
    }
    let round_x_deltas: std::collections::BTreeMap<_, _> = x_delta_entries.into_iter().collect();
    let round_new_sets: std::collections::BTreeMap<_, _> = new_set_entries.into_iter().collect();
    debug_assert_eq!(round_x_deltas.len(), predicates.len());
    Ok((round_x_deltas, round_new_sets))
}

fn compute_outer_component_deltas(
    predicates: &std::collections::BTreeSet<String>,
    prev_final_sets: &std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    prev_final_multisets: &std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    rounds: &[ComponentRoundState],
) -> Result<ComponentStepDelta, crate::Error> {
    assert!(!predicates.is_empty());
    let final_sets = last_derived_sets(rounds);
    let final_multisets = last_derived_multisets(rounds);
    let set_pairs = predicates
        .iter()
        .map(|pred| {
            let old_s = prev_final_sets.get(pred).cloned().unwrap_or_default();
            let new_s = final_sets.get(pred).cloned().unwrap_or_default();
            Ok((pred.clone(), new_s.subtract(&old_s)?))
        })
        .collect::<Result<Vec<_>, crate::Error>>()?;
    let multiset_pairs = predicates
        .iter()
        .map(|pred| {
            let old_m = prev_final_multisets.get(pred).cloned().unwrap_or_default();
            let new_m = final_multisets.get(pred).cloned().unwrap_or_default();
            Ok((pred.clone(), new_m.subtract(&old_m)?))
        })
        .collect::<Result<Vec<_>, crate::Error>>()?;
    debug_assert_eq!(set_pairs.len(), predicates.len());
    Ok((
        set_pairs.into_iter().collect(),
        multiset_pairs.into_iter().collect(),
    ))
}

struct ComponentSpec {
    stratum: usize,
    id: String,
    predicates: std::collections::BTreeSet<String>,
    rule_ids: Vec<String>,
    is_recursive: bool,
}

fn partition_program_components(program: &crate::RuleProgram) -> Vec<ComponentSpec> {
    let mut by_stratum: std::collections::BTreeMap<usize, Vec<&crate::Rule>> =
        std::collections::BTreeMap::new();
    for rule in &program.bundle.rules {
        let stratum = program
            .strata
            .get(&rule.head.predicate)
            .copied()
            .unwrap_or(0);
        by_stratum.entry(stratum).or_default().push(rule);
    }
    let mut specs = Vec::with_capacity(program.bundle.rules.len());
    for (stratum, rules) in by_stratum {
        partition_stratum_components(stratum, &rules, &mut specs);
    }
    debug_assert!(specs.len() <= program.bundle.rules.len());
    debug_assert!(by_stratum_count_ok(program));
    specs
}

fn by_stratum_count_ok(program: &crate::RuleProgram) -> bool {
    program.bundle.rules.len() < usize::MAX
}

fn partition_stratum_components(
    stratum: usize,
    rules: &[&crate::Rule],
    specs: &mut Vec<ComponentSpec>,
) {
    assert!(!rules.is_empty());
    let heads: std::collections::BTreeSet<String> = rules
        .iter()
        .map(|rule| rule.head.predicate.clone())
        .collect();
    let adj = build_stratum_adjacency(rules, &heads);
    let mut visited = std::collections::BTreeSet::new();
    for head in &heads {
        if visited.contains(head) {
            continue;
        }
        let comp_preds = collect_connected_predicates(head, &adj, &mut visited);
        specs.push(build_component_spec(stratum, rules, comp_preds));
    }
    debug_assert!(visited.len() == heads.len());
}

fn build_stratum_adjacency(
    rules: &[&crate::Rule],
    heads: &std::collections::BTreeSet<String>,
) -> std::collections::BTreeMap<String, std::collections::BTreeSet<String>> {
    assert!(!heads.is_empty());
    let mut adj: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> = heads
        .iter()
        .map(|head| (head.clone(), std::collections::BTreeSet::new()))
        .collect();
    for rule in rules {
        let head = &rule.head.predicate;
        for literal in &rule.body {
            if let crate::Literal::Positive(atom) = literal
                && heads.contains(&atom.predicate)
            {
                adj.entry(head.clone())
                    .or_default()
                    .insert(atom.predicate.clone());
                adj.entry(atom.predicate.clone())
                    .or_default()
                    .insert(head.clone());
            }
        }
    }
    debug_assert_eq!(adj.len(), heads.len());
    adj
}

fn collect_connected_predicates(
    start_head: &str,
    adj: &std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
    visited: &mut std::collections::BTreeSet<String>,
) -> std::collections::BTreeSet<String> {
    assert!(adj.contains_key(start_head));
    let mut comp_preds = std::collections::BTreeSet::new();
    let mut queue = std::collections::VecDeque::from([start_head.to_owned()]);
    while let Some(cur) = queue.pop_front() {
        if !visited.insert(cur.clone()) {
            continue;
        }
        comp_preds.insert(cur.clone());
        if let Some(neighbors) = adj.get(&cur) {
            for next in neighbors {
                if !visited.contains(next) {
                    queue.push_back(next.clone());
                }
            }
        }
    }
    debug_assert!(!comp_preds.is_empty());
    comp_preds
}

fn build_component_spec(
    stratum: usize,
    rules: &[&crate::Rule],
    comp_preds: std::collections::BTreeSet<String>,
) -> ComponentSpec {
    assert!(!comp_preds.is_empty());
    let comp_rules: Vec<&crate::Rule> = rules
        .iter()
        .copied()
        .filter(|rule| comp_preds.contains(&rule.head.predicate))
        .collect();
    let is_recursive = comp_rules.iter().any(|rule| {
        rule.body.iter().any(|literal| {
            matches!(literal, crate::Literal::Positive(atom) if comp_preds.contains(&atom.predicate))
        })
    });
    let id = comp_preds.iter().next().cloned().unwrap_or_default();
    let rule_ids = comp_rules.iter().map(|rule| rule.id.clone()).collect();
    debug_assert!(!id.is_empty());
    ComponentSpec {
        stratum,
        id,
        predicates: comp_preds,
        rule_ids,
        is_recursive,
    }
}

fn empty_round_for_component(
    program: &crate::RuleProgram,
    comp: &ComponentState,
) -> ComponentRoundState {
    let rule_states = program
        .bundle
        .rules
        .iter()
        .filter(|rule| comp.predicates.contains(&rule.head.predicate))
        .map(|rule| (rule.id.clone(), RuleState::new(rule.clone())))
        .collect();
    ComponentRoundState {
        rule_states,
        derived_multisets: std::collections::BTreeMap::new(),
        derived_sets: std::collections::BTreeMap::new(),
    }
}

fn external_inputs_for_component(
    program: &crate::RuleProgram,
    comp: &ComponentState,
    relations: &std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
) -> std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>> {
    assert!(!comp.predicates.is_empty());
    let inputs: std::collections::BTreeMap<_, _> = program
        .bundle
        .rules
        .iter()
        .filter(|rule| comp.predicates.contains(&rule.head.predicate))
        .flat_map(|rule| rule.body.iter())
        .filter_map(|literal| {
            if let crate::Literal::Positive(atom) | crate::Literal::Negative(atom) = literal
                && !comp.predicates.contains(&atom.predicate)
            {
                relations
                    .get(&atom.predicate)
                    .map(|rel| (atom.predicate.clone(), rel.clone()))
            } else {
                None
            }
        })
        .collect();
    debug_assert!(inputs.len() <= relations.len());
    inputs
}

fn component_has_external_delta(
    program: &crate::RuleProgram,
    comp: &ComponentState,
    external_deltas: &std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
) -> bool {
    assert!(!comp.predicates.is_empty());
    debug_assert!(comp.rule_ids.len() <= program.bundle.rules.len());
    program
        .bundle
        .rules
        .iter()
        .filter(|rule| comp.predicates.contains(&rule.head.predicate))
        .flat_map(|rule| rule.body.iter())
        .any(|literal| {
            if let crate::Literal::Positive(atom) | crate::Literal::Negative(atom) = literal {
                !comp.predicates.contains(&atom.predicate)
                    && external_deltas
                        .get(&atom.predicate)
                        .is_some_and(|delta| !delta.is_empty())
            } else {
                false
            }
        })
}

fn charge_budget(budget: &mut crate::engine::Budget<'_>, amount: u64) -> Result<(), crate::Error> {
    if budget.charge(amount) {
        Ok(())
    } else {
        Err(crate::Error::LimitExceeded(
            "incremental evaluation work or time limit reached".to_owned(),
        ))
    }
}

struct PredicateReason<'a> {
    predicate: &'a str,
    reason: &'a str,
}

fn record_coverage_reason(
    coverage_reasons: &mut std::collections::BTreeMap<String, String>,
    entry: PredicateReason<'_>,
) {
    coverage_reasons.insert(entry.predicate.to_owned(), entry.reason.to_owned());
}

fn bind_optional_delta(
    atom: &crate::Atom,
    maybe_delta: Option<&crate::zset::ZSet<FactKey>>,
    budget: &mut crate::engine::Budget<'_>,
) -> Result<crate::zset::ZSet<Binding>, crate::Error> {
    if let Some(delta) = maybe_delta
        && !delta.is_empty()
    {
        return bind_atom_zset(atom, delta, budget);
    }
    Ok(crate::zset::ZSet::new())
}

fn filter_optional_neg(
    atom: &crate::Atom,
    maybe_delta: Option<&crate::zset::ZSet<FactKey>>,
    budget: &mut crate::engine::Budget<'_>,
) -> Result<crate::zset::ZSet<FactKey>, crate::Error> {
    if let Some(delta) = maybe_delta
        && !delta.is_empty()
    {
        return filter_neg_atom(atom, delta, budget);
    }
    Ok(crate::zset::ZSet::new())
}

fn compute_shared_vars(atoms: &[crate::Atom]) -> Vec<Vec<String>> {
    let mut seen_vars = std::collections::BTreeSet::new();
    let mut shared = Vec::with_capacity(atoms.len().saturating_sub(1));
    for (idx, atom) in atoms.iter().enumerate() {
        let atom_vars: std::collections::BTreeSet<String> = atom
            .terms
            .iter()
            .filter_map(|term| {
                if let crate::Term::Variable(name) = term {
                    Some(name.clone())
                } else {
                    None
                }
            })
            .collect();
        if idx > 0 {
            let common: Vec<String> = seen_vars.intersection(&atom_vars).cloned().collect();
            shared.push(common);
        }
        seen_vars.extend(atom_vars);
    }
    debug_assert_eq!(shared.len(), atoms.len().saturating_sub(1));
    debug_assert!(seen_vars.len() < usize::MAX);
    shared
}

fn bind_atom_zset(
    atom: &crate::Atom,
    rel: &crate::zset::ZSet<FactKey>,
    budget: &mut crate::engine::Budget<'_>,
) -> Result<crate::zset::ZSet<Binding>, crate::Error> {
    let mut out = crate::zset::ZSet::new();
    for (terms, weight) in rel.iter() {
        charge_budget(budget, 1)?;
        if terms.len() != atom.terms.len() {
            continue;
        }
        if let Some(binding) = unify_atom_terms(atom, terms) {
            out.insert_weighted(binding, weight)?;
        }
    }
    Ok(out)
}

fn unify_atom_terms(atom: &crate::Atom, terms: &[mneme_core::Value]) -> Option<Binding> {
    assert!(!atom.predicate.is_empty());
    if atom.terms.len() != terms.len() {
        return None;
    }
    let binding =
        atom.terms
            .iter()
            .zip(terms)
            .try_fold(Binding::new(), |mut acc, (term, value)| {
                if let crate::Term::Constant(expected) = term {
                    if expected != value {
                        return None;
                    }
                } else if let crate::Term::Variable(name) = term {
                    if let Some(existing) = acc.get(name) {
                        if existing != value {
                            return None;
                        }
                    } else {
                        acc.insert(name.clone(), value.clone());
                    }
                }
                Some(acc)
            })?;
    debug_assert!(binding.len() <= atom.terms.len());
    Some(binding)
}

fn filter_neg_atom(
    atom: &crate::Atom,
    rel: &crate::zset::ZSet<FactKey>,
    budget: &mut crate::engine::Budget<'_>,
) -> Result<crate::zset::ZSet<FactKey>, crate::Error> {
    let mut out = crate::zset::ZSet::new();
    for (terms, weight) in rel.iter() {
        charge_budget(budget, 1)?;
        if unify_atom_terms(atom, terms).is_some() {
            out.insert_weighted(terms.clone(), weight)?;
        }
    }
    Ok(out)
}

fn project_vars(binding: &Binding, vars: &[String]) -> JoinKey {
    vars.iter()
        .filter_map(|name| binding.get(name).cloned())
        .collect()
}

fn merge_bindings(left: &Binding, right: &Binding) -> Option<Binding> {
    let mut merged = left.clone();
    for (name, value) in right {
        if let Some(existing) = merged.get(name) {
            if existing != value {
                return None;
            }
        } else {
            merged.insert(name.clone(), value.clone());
        }
    }
    Some(merged)
}

fn compares_hold(
    compares: &[(crate::CompareOp, crate::Term, crate::Term)],
    binding: &Binding,
) -> bool {
    compares.iter().all(|(op, left, right)| {
        match (
            crate::engine::term_value_crate(left, binding),
            crate::engine::term_value_crate(right, binding),
        ) {
            (Some(l), Some(r)) => crate::engine::compare_values_crate(*op, &l, &r),
            _ => false,
        }
    })
}

fn neg_atom_key(atom: &crate::Atom, binding: &Binding) -> FactKey {
    atom.terms
        .iter()
        .filter_map(|term| crate::engine::term_value_crate(term, binding))
        .collect()
}

fn instantiate_atom(atom: &crate::Atom, binding: &Binding) -> Option<FactKey> {
    atom.terms
        .iter()
        .map(|term| crate::engine::term_value_crate(term, binding))
        .collect()
}

fn update_head_binding_index(
    index: &mut std::collections::BTreeMap<FactKey, std::collections::BTreeSet<Binding>>,
    terms: &FactKey,
    binding: &Binding,
    weight: i64,
) {
    if weight > 0 {
        index
            .entry(terms.clone())
            .or_default()
            .insert(binding.clone());
    } else if weight < 0
        && let Some(set) = index.get_mut(terms)
    {
        set.remove(binding);
        if set.is_empty() {
            index.remove(terms);
        }
    }
}

fn aggregate_group_key(
    group_vars: &std::collections::BTreeSet<String>,
    binding: &Binding,
) -> Option<JoinKey> {
    group_vars
        .iter()
        .map(|name| binding.get(name).cloned())
        .collect()
}

fn compute_group_head_row(
    head: &crate::Atom,
    agg: &AggSpec,
    bucket: &crate::zset::ZSet<Binding>,
) -> Result<Option<FactKey>, &'static str> {
    assert!(!head.predicate.is_empty());
    let mut values = Vec::new();
    let mut first_binding: Option<&Binding> = None;
    for (binding, weight) in bucket.iter() {
        if weight <= 0 {
            continue;
        }
        if first_binding.is_none() {
            first_binding = Some(binding);
        }
        let val = crate::engine::term_value_crate(&agg.input, binding)
            .ok_or("aggregate input is unbound")?;
        let repeat = usize::try_from(weight).map_err(|_| "aggregate weight overflow")?;
        values.reserve(repeat);
        for _ in 0..repeat {
            values.push(val.clone());
        }
    }
    let Some(first) = first_binding else {
        return Ok(None);
    };
    let agg_val = crate::engine::aggregate_value_crate(agg.function, values)?;
    debug_assert!(!head.terms.is_empty());
    let head_terms = head
        .terms
        .iter()
        .map(|term| {
            if let crate::Term::Constant(value) = term {
                Some(value.clone())
            } else if let crate::Term::Variable(name) = term {
                if name == &agg.output {
                    Some(agg_val.clone())
                } else {
                    first.get(name).cloned()
                }
            } else {
                None
            }
        })
        .collect::<Option<Vec<_>>>()
        .ok_or("aggregate head variable is unbound")?;
    Ok(Some(head_terms))
}
