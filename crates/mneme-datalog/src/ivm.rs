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
    pub(crate) output: crate::zset::ZSet<FactKey>,
}

impl RuleState {
    pub(crate) fn new(rule: crate::Rule) -> Self {
        let mut positive_atoms = Vec::new();
        let mut compares = Vec::new();
        let mut negatives = Vec::new();
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
                    let group_vars =
                        crate::engine::aggregate_group_variables_crate(&rule.head, output);
                    aggregate = Some(AggSpec {
                        function: *function,
                        input: input.clone(),
                        output: output.clone(),
                        group_vars,
                    });
                }
                crate::Literal::Forbidden(_) => {}
            }
        }
        let shared_vars = compute_shared_vars(&positive_atoms);
        let join_count = positive_atoms.len().saturating_sub(1);
        let neg_count = negatives.len();
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
            output: crate::zset::ZSet::new(),
        }
    }

    fn references_any_delta(
        &self,
        input_deltas: &std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    ) -> bool {
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
        budget: &mut crate::engine::Budget<'_>,
        coverage_reasons: &mut std::collections::BTreeMap<String, String>,
    ) -> Result<crate::zset::ZSet<FactKey>, crate::Error> {
        if !self.references_any_delta(input_deltas) {
            return Ok(crate::zset::ZSet::new());
        }
        let mut delta_cur = self.step_positive_joins(input_deltas, budget)?;
        delta_cur = self.step_compares(&delta_cur, budget)?;
        delta_cur = self.step_negatives(input_deltas, delta_cur, budget)?;
        self.step_head(&delta_cur, budget, coverage_reasons)
    }

    fn step_positive_joins(
        &mut self,
        input_deltas: &std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
        budget: &mut crate::engine::Budget<'_>,
    ) -> Result<crate::zset::ZSet<Binding>, crate::Error> {
        if self.positive_atoms.is_empty() {
            return Ok(crate::zset::ZSet::new());
        }
        let mut delta_join = crate::zset::ZSet::new();
        for index in 0..self.positive_atoms.len() {
            let atom = &self.positive_atoms[index];
            let delta_atom = match input_deltas.get(&atom.predicate) {
                Some(delta) if !delta.is_empty() => bind_atom_zset(atom, delta, budget)?,
                _ => crate::zset::ZSet::new(),
            };
            if index == 0 {
                delta_join = delta_atom.clone();
                self.atom_bindings[0].add_in_place(&delta_atom)?;
                self.join_steps[0].add_in_place(&delta_join)?;
                continue;
            }
            let join_idx = index.saturating_sub(1);
            let vars = &self.shared_vars[join_idx];
            if delta_join.is_empty() && delta_atom.is_empty() {
                continue;
            }
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
        mut delta_cur: crate::zset::ZSet<Binding>,
        budget: &mut crate::engine::Budget<'_>,
    ) -> Result<crate::zset::ZSet<Binding>, crate::Error> {
        for index in 0..self.negatives.len() {
            let neg_atom = &self.negatives[index];
            let delta_neg_raw = match input_deltas.get(&neg_atom.predicate) {
                Some(delta) if !delta.is_empty() => filter_neg_atom(neg_atom, delta, budget)?,
                _ => crate::zset::ZSet::new(),
            };
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
        budget: &mut crate::engine::Budget<'_>,
        coverage_reasons: &mut std::collections::BTreeMap<String, String>,
    ) -> Result<crate::zset::ZSet<FactKey>, crate::Error> {
        if delta_bindings.is_empty() {
            return Ok(crate::zset::ZSet::new());
        }
        if let Some(agg) = self.aggregate.clone() {
            return self.step_aggregate_head(&agg, delta_bindings, budget, coverage_reasons);
        }
        let mut delta_out = crate::zset::ZSet::new();
        for (binding, weight) in delta_bindings.iter() {
            charge_budget(budget, 1)?;
            let Some(terms) = crate::engine::head_terms_crate(&self.rule.head, binding) else {
                coverage_reasons.insert(
                    self.rule.head.predicate.clone(),
                    "rule head has an unbound variable".to_owned(),
                );
                continue;
            };
            update_head_binding_index(&mut self.head_bindings, &terms, binding, weight);
            delta_out.insert_weighted(terms, weight)?;
        }
        self.output.add_in_place(&delta_out)?;
        Ok(delta_out)
    }

    fn step_aggregate_head(
        &mut self,
        agg: &AggSpec,
        delta_bindings: &crate::zset::ZSet<Binding>,
        budget: &mut crate::engine::Budget<'_>,
        coverage_reasons: &mut std::collections::BTreeMap<String, String>,
    ) -> Result<crate::zset::ZSet<FactKey>, crate::Error> {
        let mut affected_groups = std::collections::BTreeSet::new();
        for (binding, _) in delta_bindings.iter() {
            if let Some(group_key) = aggregate_group_key(&agg.group_vars, binding) {
                affected_groups.insert(group_key);
            }
        }
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
                    coverage_reasons.insert(self.rule.head.predicate.clone(), reason.to_owned());
                }
            }
        }
        self.output.add_in_place(&delta_out)?;
        Ok(delta_out)
    }

    pub(crate) fn ordinary_bindings_for(&self, head_terms: &FactKey) -> Vec<Binding> {
        self.head_bindings
            .get(head_terms)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub(crate) fn aggregate_bindings_for(&self, head_terms: &FactKey) -> Vec<Binding> {
        let Some(agg) = &self.aggregate else {
            return Vec::new();
        };
        let mut matched = Vec::new();
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
        let _ = agg;
        matched
    }

    fn collect_dirty_heads_for_inputs(
        &self,
        dirty_inputs: &std::collections::BTreeMap<String, std::collections::BTreeSet<FactKey>>,
        out: &mut std::collections::BTreeMap<String, std::collections::BTreeSet<FactKey>>,
    ) {
        let has_dirty_input = self.positive_atoms.iter().any(|atom| {
            dirty_inputs
                .get(&atom.predicate)
                .is_some_and(|s| !s.is_empty())
        });
        if !has_dirty_input {
            return;
        }
        let mut dirty_bindings: std::collections::BTreeSet<Binding> =
            std::collections::BTreeSet::new();
        for atom in &self.positive_atoms {
            let Some(keys) = dirty_inputs.get(&atom.predicate) else {
                continue;
            };
            if keys.is_empty() {
                continue;
            }
            for (head_key, bindings) in &self.head_bindings {
                for binding in bindings {
                    if let Some(inst) = instantiate_atom(atom, binding)
                        && keys.contains(&inst)
                    {
                        out.entry(self.rule.head.predicate.clone())
                            .or_default()
                            .insert(head_key.clone());
                        dirty_bindings.insert(binding.clone());
                    }
                }
            }
            if let Some(agg) = &self.aggregate {
                for (group_key, output_row) in &self.agg_group_outputs {
                    let Some(bucket) = self.agg_groups.get(group_key) else {
                        continue;
                    };
                    for (binding, weight) in bucket.iter() {
                        if weight > 0
                            && let Some(inst) = instantiate_atom(atom, binding)
                            && keys.contains(&inst)
                        {
                            out.entry(self.rule.head.predicate.clone())
                                .or_default()
                                .insert(output_row.clone());
                        }
                    }
                }
                let _ = agg;
            }
        }
        let _ = dirty_bindings;
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
pub(crate) struct IvmState {
    pub(crate) relations: std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    pub(crate) components: Vec<ComponentState>,
}

impl IvmState {
    /// Initialize DBSP state from loaded base facts with no derived rules.
    pub(crate) fn from_base_facts(
        facts: &std::collections::BTreeMap<String, crate::engine::FactStore>,
    ) -> Result<Self, crate::Error> {
        let mut relations = std::collections::BTreeMap::new();
        for (predicate, store) in facts {
            let mut zset = crate::zset::ZSet::new();
            for key in store.rows.keys() {
                zset.insert_weighted(key.clone(), 1)?;
            }
            relations.insert(predicate.clone(), zset);
        }
        Ok(IvmState {
            relations,
            components: Vec::new(),
        })
    }

    /// Synchronize DBSP component states after `add_rule` or `retract_rule`.
    pub(crate) fn sync_after_rule_change(
        &mut self,
        program: &crate::RuleProgram,
        base_facts: &std::collections::BTreeMap<String, crate::engine::FactStore>,
        build_facts: &std::collections::BTreeMap<
            String,
            std::collections::BTreeMap<FactKey, crate::FactData>,
        >,
        affected: &std::collections::BTreeSet<String>,
    ) -> Result<(), crate::Error> {
        let _ = base_facts;
        let mut next_relations = std::collections::BTreeMap::new();
        for (predicate, rows) in build_facts {
            let mut zset = crate::zset::ZSet::new();
            for key in rows.keys() {
                zset.insert_weighted(key.clone(), 1)?;
            }
            next_relations.insert(predicate.clone(), zset);
        }
        let specs = partition_program_components(program);
        let existing_by_key: std::collections::BTreeMap<(usize, String), ComponentState> = self
            .components
            .drain(..)
            .map(|comp| ((comp.stratum, comp.id.clone()), comp))
            .collect();
        let mut next_components = Vec::with_capacity(specs.len());
        let unlimited = crate::Limits {
            max_work: u64::MAX,
            max_time_ms: u128::from(u64::MAX),
            max_result_rows: usize::MAX,
            max_supports_per_fact: usize::MAX,
            max_recursion_depth: usize::MAX / 2,
        };
        let start = crate::engine::evaluation_start();
        let mut noop_budget = crate::engine::Budget {
            limits: &unlimited,
            work: 0,
            stored_rows: 0,
            start,
            cancellation: None,
            status: crate::ExecutionStatus::Complete,
            limit_reached: false,
            support_truncated: false,
        };
        let mut noop_reasons = std::collections::BTreeMap::new();
        for spec in specs {
            let touches_affected = spec
                .predicates
                .iter()
                .any(|predicate| affected.contains(predicate));
            if !touches_affected
                && let Some(existing) = existing_by_key.get(&(spec.stratum, spec.id.clone()))
                && existing.rule_ids == spec.rule_ids
                && existing.predicates == spec.predicates
            {
                next_components.push(existing.clone());
                continue;
            }
            let mut comp = ComponentState {
                stratum: spec.stratum,
                id: spec.id,
                predicates: spec.predicates,
                rule_ids: spec.rule_ids.clone(),
                is_recursive: spec.is_recursive,
                rounds: Vec::new(),
            };
            let initial_deltas = external_inputs_for_component(program, &comp, &next_relations);
            let _ = comp.step_component_delta(
                program,
                &initial_deltas,
                &mut noop_budget,
                &mut noop_reasons,
                usize::MAX / 4,
            )?;
            next_components.push(comp);
        }
        self.relations = next_relations;
        self.components = next_components;
        Ok(())
    }
}

pub(crate) struct AdvanceIvmRequest<'a> {
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

pub(crate) struct AdvanceIvmResult {
    pub(crate) next_ivm: IvmState,
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
pub(crate) fn advance_ivm(
    ivm: &IvmState,
    request: AdvanceIvmRequest<'_>,
) -> Result<AdvanceIvmResult, crate::Error> {
    let mut next_ivm = ivm.clone();
    let mut all_deltas = request.base_deltas;
    let mut multiset_deltas: std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>> =
        std::collections::BTreeMap::new();
    let mut dirty_by_pred: std::collections::BTreeMap<String, std::collections::BTreeSet<FactKey>> =
        std::collections::BTreeMap::new();
    for (pred, key) in request.dirty_provenance {
        dirty_by_pred.entry(pred).or_default().insert(key);
    }

    for (pred, delta) in &all_deltas {
        next_ivm
            .relations
            .entry(pred.clone())
            .or_default()
            .add_in_place(delta)?;
    }

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
    let mut affected_set: std::collections::BTreeSet<String> = all_deltas
        .iter()
        .filter(|(_, d)| !d.is_empty())
        .map(|(p, _)| p.clone())
        .collect();
    let mut reused_predicates = Vec::new();

    for component in &mut next_ivm.components {
        if !budget.is_active() {
            break;
        }
        let step_result = component.step_component_delta(
            request.program,
            &all_deltas,
            &mut budget,
            &mut coverage_reasons,
            request.limits.max_recursion_depth,
        );
        let (comp_deltas, comp_multiset_deltas) = match step_result {
            Ok(res) => res,
            Err(crate::Error::LimitExceeded(_)) => {
                return Ok(AdvanceIvmResult {
                    next_ivm,
                    next_facts: std::collections::BTreeMap::new(),
                    coverage: Vec::new(),
                    status: budget.status,
                    work: budget.work,
                    support_truncated: budget.support_truncated,
                    limit_reached: true,
                    affected_predicates: Vec::new(),
                    reused_predicates: Vec::new(),
                });
            }
            Err(err) => return Err(err),
        };

        let mut is_component_affected = false;
        for (pred, delta) in comp_deltas {
            if !delta.is_empty() {
                is_component_affected = true;
                affected_set.insert(pred.clone());
                next_ivm
                    .relations
                    .entry(pred.clone())
                    .or_default()
                    .add_in_place(&delta)?;
            }
            all_deltas.insert(pred, delta);
        }
        for (pred, m_delta) in comp_multiset_deltas {
            if !m_delta.is_empty() {
                is_component_affected = true;
                affected_set.insert(pred.clone());
                let dirty_entry = dirty_by_pred.entry(pred.clone()).or_default();
                for (key, weight) in m_delta.iter() {
                    if weight != 0 {
                        dirty_entry.insert(key.clone());
                    }
                }
            }
            multiset_deltas.insert(pred, m_delta);
        }
        if let Some(last_round) = component.rounds.last() {
            let max_passes = component.rounds.len().saturating_add(1);
            for _ in 0..max_passes {
                let mut new_dirty = std::collections::BTreeMap::new();
                for rule_id in &component.rule_ids {
                    if let Some(rule_state) = last_round.rule_states.get(rule_id) {
                        rule_state.collect_dirty_heads_for_inputs(&dirty_by_pred, &mut new_dirty);
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
        if !is_component_affected {
            for pred in &component.predicates {
                if dirty_by_pred
                    .get(pred)
                    .is_none_or(std::collections::BTreeSet::is_empty)
                {
                    reused_predicates.push(pred.clone());
                } else {
                    affected_set.insert(pred.clone());
                }
            }
        }
    }

    if budget.limit_reached {
        return Ok(AdvanceIvmResult {
            next_ivm,
            next_facts: std::collections::BTreeMap::new(),
            coverage: Vec::new(),
            status: budget.status,
            work: budget.work,
            support_truncated: budget.support_truncated,
            limit_reached: true,
            affected_predicates: Vec::new(),
            reused_predicates: Vec::new(),
        });
    }

    let mut next_facts = build_next_fact_stores(
        request.next_base,
        request.current_facts,
        request.next_context.served_revision,
    );
    let mut fact_predicates: std::collections::BTreeSet<String> =
        next_facts.keys().cloned().collect();
    for pred in next_ivm.relations.keys() {
        fact_predicates.insert(pred.clone());
    }
    let (coverage_map, coverage, coverage_status) =
        crate::engine::compute_coverage_for_facts(crate::engine::CoverageCheckRequest {
            base: request.next_base,
            bundle: &request.program.bundle,
            context: request.next_context,
            limits: request.limits,
            fact_predicates: &fact_predicates,
            coverage_reasons: &coverage_reasons,
            at: request.at,
            start: request.start,
        });

    let is_truncated = refresh_derived_fact_data(
        &next_ivm,
        &all_deltas,
        &multiset_deltas,
        &dirty_by_pred,
        request.next_base,
        request.next_context,
        request.limits,
        &coverage_map,
        request.at,
        request.start,
        &mut next_facts,
    );
    let support_truncated = budget.support_truncated || is_truncated;
    let status = if budget.status != crate::ExecutionStatus::Complete {
        budget.status
    } else {
        coverage_status
    };
    reused_predicates.sort();
    Ok(AdvanceIvmResult {
        next_ivm,
        next_facts,
        coverage,
        status,
        work: budget.work,
        support_truncated,
        limit_reached: false,
        affected_predicates: affected_set.into_iter().collect(),
        reused_predicates,
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
    let mut next_facts = std::collections::BTreeMap::new();
    for (pred, rows) in current_facts {
        if !next_base.facts.contains_key(pred) {
            let mut cloned = rows.clone();
            for data in cloned.values_mut() {
                for support in &mut data.supports {
                    support.revision = target_revision;
                }
            }
            next_facts.insert(pred.clone(), cloned);
        }
    }
    for (pred, store) in &next_base.facts {
        next_facts.insert(pred.clone(), store.rows.clone());
    }
    next_facts
}

#[allow(clippy::too_many_arguments)]
fn refresh_derived_fact_data(
    ivm: &IvmState,
    all_deltas: &std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    multiset_deltas: &std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    dirty_by_pred: &std::collections::BTreeMap<String, std::collections::BTreeSet<FactKey>>,
    next_base: &crate::engine::BaseSnapshot,
    next_context: &crate::BuildContext,
    limits: &crate::Limits,
    coverage_map: &std::collections::BTreeMap<String, crate::CoverageStatus>,
    at: Option<mneme_core::Timestamp>,
    start: std::time::Instant,
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
                crate::engine::FactStore {
                    rows: rows.clone(),
                    truncated: false,
                },
            )
        })
        .collect();
    let mut is_any_truncated = false;
    for component in &ivm.components {
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
        let mut keys_to_refresh: std::collections::BTreeMap<
            String,
            std::collections::BTreeSet<FactKey>,
        > = std::collections::BTreeMap::new();
        for pred in &component.predicates {
            let set = keys_to_refresh.entry(pred.clone()).or_default();
            if let Some(delta) = all_deltas.get(pred) {
                for (key, weight) in delta.iter() {
                    if weight > 0 {
                        set.insert(key.clone());
                    }
                }
            }
            if let Some(m_delta) = multiset_deltas.get(pred) {
                for (key, weight) in m_delta.iter() {
                    if weight != 0
                        && ivm
                            .relations
                            .get(pred)
                            .is_some_and(|rel| rel.weight(key) > 0)
                    {
                        set.insert(key.clone());
                    }
                }
            }
            if let Some(dirty) = dirty_by_pred.get(pred) {
                for key in dirty {
                    if ivm
                        .relations
                        .get(pred)
                        .is_some_and(|rel| rel.weight(key) > 0)
                    {
                        set.insert(key.clone());
                    }
                }
            }
            if let Some(store) = store_map.get_mut(pred) {
                for key in set.iter() {
                    store.rows.remove(key);
                }
            }
        }
        let mut populated: std::collections::BTreeSet<(String, FactKey)> =
            std::collections::BTreeSet::new();
        for round in &component.rounds {
            for pred in &component.predicates {
                let Some(keys) = keys_to_refresh.get(pred) else {
                    continue;
                };
                if keys.is_empty() {
                    continue;
                }
                let Some(round_set) = round.derived_sets.get(pred) else {
                    continue;
                };
                for key in keys {
                    if round_set.weight(key) <= 0
                        || populated.contains(&(pred.clone(), key.clone()))
                    {
                        continue;
                    }
                    let mut target_store = store_map.get(pred).cloned().unwrap_or_default();
                    for rule_id in &component.rule_ids {
                        let Some(rule_state) = round.rule_states.get(rule_id) else {
                            continue;
                        };
                        if &rule_state.rule.head.predicate != pred {
                            continue;
                        }
                        let truncated = if rule_state.aggregate.is_some() {
                            let bindings = rule_state.aggregate_bindings_for(key);
                            if bindings.is_empty() {
                                false
                            } else {
                                crate::engine::build_aggregate_fact_data_from_bindings(
                                    crate::engine::FactDataBuildRequest {
                                        rule: &rule_state.rule,
                                        context: next_context,
                                        limits,
                                        facts: &store_map,
                                        coverage_map,
                                        current_sources: &next_base.current_sources,
                                        at,
                                        start,
                                        bindings: &bindings,
                                        target_terms: key,
                                    },
                                    &mut target_store,
                                )
                            }
                        } else {
                            let bindings = rule_state.ordinary_bindings_for(key);
                            if bindings.is_empty() {
                                false
                            } else {
                                crate::engine::build_ordinary_fact_data_from_bindings(
                                    crate::engine::FactDataBuildRequest {
                                        rule: &rule_state.rule,
                                        context: next_context,
                                        limits,
                                        facts: &store_map,
                                        coverage_map,
                                        current_sources: &next_base.current_sources,
                                        at,
                                        start,
                                        bindings: &bindings,
                                        target_terms: key,
                                    },
                                    &mut target_store,
                                )
                            }
                        };
                        if truncated {
                            is_any_truncated = true;
                        }
                    }
                    store_map.insert(pred.clone(), target_store);
                    populated.insert((pred.clone(), key.clone()));
                }
            }
        }
    }
    *next_facts = store_map
        .into_iter()
        .map(|(pred, store)| (pred, store.rows))
        .collect();
    is_any_truncated
}

type ComponentStepDelta = (
    std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
);

impl ComponentState {
    fn step_component_delta(
        &mut self,
        program: &crate::RuleProgram,
        external_deltas: &std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
        budget: &mut crate::engine::Budget<'_>,
        coverage_reasons: &mut std::collections::BTreeMap<String, String>,
        max_recursion_depth: usize,
    ) -> Result<ComponentStepDelta, crate::Error> {
        let prev_final_sets = self
            .rounds
            .last()
            .map(|r| r.derived_sets.clone())
            .unwrap_or_default();
        let prev_final_multisets = self
            .rounds
            .last()
            .map(|r| r.derived_multisets.clone())
            .unwrap_or_default();

        let has_ext_delta = component_has_external_delta(program, self, external_deltas);
        if !self.rounds.is_empty() && !has_ext_delta {
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

        let mut next_rounds: Vec<ComponentRoundState> = Vec::new();
        let mut prev_round_new_sets: std::collections::BTreeMap<
            String,
            crate::zset::ZSet<FactKey>,
        > = self
            .predicates
            .iter()
            .map(|p| (p.clone(), crate::zset::ZSet::new()))
            .collect();
        let mut prev_round_delta_x: std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>> =
            std::collections::BTreeMap::new();

        let mut converged = false;
        let is_initial_build = self.rounds.is_empty();
        for round_idx in 0..max_rounds {
            if !budget.is_active() {
                return Err(crate::Error::LimitExceeded(
                    "budget exhausted during incremental fixpoint".to_owned(),
                ));
            }
            let (mut round, use_ext_deltas) = if round_idx < self.rounds.len() {
                (self.rounds[round_idx].clone(), true)
            } else if is_initial_build {
                if let Some(last_new) = next_rounds.last() {
                    (last_new.clone(), false)
                } else {
                    (empty_round_for_component(program, self), true)
                }
            } else if let Some(last) = self.rounds.last() {
                (last.clone(), true)
            } else {
                (empty_round_for_component(program, self), true)
            };

            let mut round_input_deltas = if use_ext_deltas {
                external_deltas.clone()
            } else {
                std::collections::BTreeMap::new()
            };
            for pred in &self.predicates {
                if let Some(dx) = prev_round_delta_x.get(pred) {
                    round_input_deltas.insert(pred.clone(), dx.clone());
                } else {
                    round_input_deltas.remove(pred);
                }
            }

            let mut round_m_deltas: std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>> =
                std::collections::BTreeMap::new();
            for rule_id in &self.rule_ids {
                let Some(rule_state) = round.rule_states.get_mut(rule_id) else {
                    continue;
                };
                let delta_out =
                    rule_state.step_delta(&round_input_deltas, budget, coverage_reasons)?;
                if !delta_out.is_empty() {
                    round_m_deltas
                        .entry(rule_state.rule.head.predicate.clone())
                        .or_default()
                        .add_in_place(&delta_out)?;
                }
            }

            let mut round_x_deltas: std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>> =
                std::collections::BTreeMap::new();
            let mut round_new_sets: std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>> =
                std::collections::BTreeMap::new();
            for pred in &self.predicates {
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
                if is_initial_build {
                    let prev_s = prev_round_new_sets.get(pred).cloned().unwrap_or_default();
                    round_x_deltas.insert(pred.clone(), x_prev.subtract(&prev_s)?);
                } else {
                    round_x_deltas.insert(pred.clone(), x_delta);
                }
                round_new_sets.insert(pred.clone(), x_prev.clone());
            }

            let is_fixpoint = !self.is_recursive || round_new_sets == prev_round_new_sets;
            next_rounds.push(round);
            prev_round_new_sets = round_new_sets;
            prev_round_delta_x = round_x_deltas;

            if is_fixpoint {
                converged = true;
                break;
            }
        }

        if !converged && self.is_recursive {
            budget.stop(crate::ExecutionStatus::Partial);
            return Err(crate::Error::LimitExceeded(
                "incremental fixpoint exceeded max_recursion_depth".to_owned(),
            ));
        }

        self.rounds = next_rounds;
        let final_sets = self
            .rounds
            .last()
            .map(|r| &r.derived_sets)
            .cloned()
            .unwrap_or_default();
        let final_multisets = self
            .rounds
            .last()
            .map(|r| &r.derived_multisets)
            .cloned()
            .unwrap_or_default();

        let mut outer_deltas = std::collections::BTreeMap::new();
        let mut outer_m_deltas = std::collections::BTreeMap::new();
        for pred in &self.predicates {
            let old_s = prev_final_sets.get(pred).cloned().unwrap_or_default();
            let new_s = final_sets.get(pred).cloned().unwrap_or_default();
            let diff_s = new_s.subtract(&old_s)?;
            outer_deltas.insert(pred.clone(), diff_s);

            let old_m = prev_final_multisets.get(pred).cloned().unwrap_or_default();
            let new_m = final_multisets.get(pred).cloned().unwrap_or_default();
            let diff_m = new_m.subtract(&old_m)?;
            outer_m_deltas.insert(pred.clone(), diff_m);
        }
        Ok((outer_deltas, outer_m_deltas))
    }
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
    let mut specs = Vec::new();
    for (stratum, rules) in by_stratum {
        let heads: std::collections::BTreeSet<String> = rules
            .iter()
            .map(|rule| rule.head.predicate.clone())
            .collect();
        let mut adj: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> = heads
            .iter()
            .map(|head| (head.clone(), std::collections::BTreeSet::new()))
            .collect();
        for rule in &rules {
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
        let mut visited = std::collections::BTreeSet::new();
        for head in &heads {
            if visited.contains(head) {
                continue;
            }
            let mut comp_preds = std::collections::BTreeSet::new();
            let mut queue = std::collections::VecDeque::from([head.clone()]);
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
            specs.push(ComponentSpec {
                stratum,
                id,
                predicates: comp_preds,
                rule_ids,
                is_recursive,
            });
        }
    }
    specs
}

fn empty_round_for_component(
    program: &crate::RuleProgram,
    comp: &ComponentState,
) -> ComponentRoundState {
    let mut rule_states = std::collections::BTreeMap::new();
    for rule in &program.bundle.rules {
        if comp.predicates.contains(&rule.head.predicate) {
            rule_states.insert(rule.id.clone(), RuleState::new(rule.clone()));
        }
    }
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
    let mut inputs = std::collections::BTreeMap::new();
    for rule in &program.bundle.rules {
        if !comp.predicates.contains(&rule.head.predicate) {
            continue;
        }
        for literal in &rule.body {
            if let crate::Literal::Positive(atom) | crate::Literal::Negative(atom) = literal
                && !comp.predicates.contains(&atom.predicate)
                && let Some(rel) = relations.get(&atom.predicate)
            {
                inputs.insert(atom.predicate.clone(), rel.clone());
            }
        }
    }
    inputs
}

fn component_has_external_delta(
    program: &crate::RuleProgram,
    comp: &ComponentState,
    external_deltas: &std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
) -> bool {
    for rule in &program.bundle.rules {
        if !comp.predicates.contains(&rule.head.predicate) {
            continue;
        }
        for literal in &rule.body {
            if let crate::Literal::Positive(atom) | crate::Literal::Negative(atom) = literal
                && !comp.predicates.contains(&atom.predicate)
                && external_deltas
                    .get(&atom.predicate)
                    .is_some_and(|delta| !delta.is_empty())
            {
                return true;
            }
        }
    }
    false
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

fn compute_shared_vars(atoms: &[crate::Atom]) -> Vec<Vec<String>> {
    let mut seen_vars = std::collections::BTreeSet::new();
    let mut shared = Vec::with_capacity(atoms.len().saturating_sub(1));
    for (idx, atom) in atoms.iter().enumerate() {
        let atom_vars: std::collections::BTreeSet<String> = atom
            .terms
            .iter()
            .filter_map(|term| match term {
                crate::Term::Variable(name) => Some(name.clone()),
                crate::Term::Constant(_) => None,
            })
            .collect();
        if idx > 0 {
            let common: Vec<String> = seen_vars.intersection(&atom_vars).cloned().collect();
            shared.push(common);
        }
        seen_vars.extend(atom_vars);
    }
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
    if atom.terms.len() != terms.len() {
        return None;
    }
    let mut binding = Binding::new();
    for (term, value) in atom.terms.iter().zip(terms) {
        match term {
            crate::Term::Constant(expected) => {
                if expected != value {
                    return None;
                }
            }
            crate::Term::Variable(name) => {
                if let Some(existing) = binding.get(name) {
                    if existing != value {
                        return None;
                    }
                } else {
                    binding.insert(name.clone(), value.clone());
                }
            }
        }
    }
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
        for _ in 0..weight {
            values.push(val.clone());
        }
    }
    let Some(first) = first_binding else {
        return Ok(None);
    };
    let agg_val = crate::engine::aggregate_value_crate(agg.function, values)?;
    let head_terms = head
        .terms
        .iter()
        .map(|term| match term {
            crate::Term::Constant(value) => Some(value.clone()),
            crate::Term::Variable(name) if name == &agg.output => Some(agg_val.clone()),
            crate::Term::Variable(name) => first.get(name).cloned(),
        })
        .collect::<Option<Vec<_>>>()
        .ok_or("aggregate head variable is unbound")?;
    Ok(Some(head_terms))
}
