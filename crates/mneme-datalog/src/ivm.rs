//! Incremental Datalog view maintenance via K-relation DBSP Z-sets,
//! Free Join delta tries, and content-addressed justification invalidation.
//!
//! Each stratum in a validated [`crate::RuleProgram`] is partitioned into
//! dependency-connected predicate components. Non-recursive components maintain
//! a single K-relation pipeline over [`crate::zset::EpistemicZSet`]; recursive
//! components maintain an inner-iteration trace (`rounds`) so inserts,
//! replacements, epistemic upgrades/downgrades, retractions, and cycles
//! converge deterministically to the exact least fixpoint.

type Binding = crate::engine::Binding;
type FactKey = crate::engine::FactKey;
type JoinKey = Vec<mneme_core::Value>;
type EpistemicFactDeltaMap =
    std::collections::BTreeMap<String, crate::zset::EpistemicZSet<FactKey>>;

#[derive(Clone, Debug)]
struct AggSpec {
    function: crate::AggregateFunction,
    input: crate::Term,
    output: String,
    group_vars: std::collections::BTreeSet<String>,
}

/// Per-rule incremental K-relation operator pipeline backed by Free Join delta tries.
#[derive(Clone, Debug)]
pub(crate) struct RuleState {
    pub(crate) rule: crate::Rule,
    positive_atoms: Vec<crate::Atom>,
    compares: Vec<(crate::CompareOp, crate::Term, crate::Term)>,
    negatives: Vec<crate::Atom>,
    aggregate: Option<AggSpec>,
    join_plan: Option<crate::freejoin::WeightedJoinPlan>,
    atom_tries: Vec<crate::freejoin::WeightedFactTrie>,
    after_compare: crate::zset::EpistemicZSet<Binding>,
    neg_steps: Vec<crate::zset::EpistemicZSet<Binding>>,
    neg_left_indexes: Vec<crate::zset::IndexedEpistemicZSet<FactKey, Binding>>,
    neg_right_indexes: Vec<crate::zset::IndexedEpistemicZSet<FactKey, ()>>,
    agg_groups: crate::zset::IndexedEpistemicZSet<JoinKey, Binding>,
    agg_group_outputs: std::collections::BTreeMap<JoinKey, (FactKey, crate::EpistemicStatus)>,
    head_binding_weights: std::collections::BTreeMap<FactKey, crate::zset::EpistemicZSet<Binding>>,
    is_unit_seeded: bool,
    pub(crate) output: crate::zset::EpistemicZSet<FactKey>,
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
        let join_plan = (positive_atoms.len() >= 2)
            .then(|| crate::freejoin::WeightedJoinPlan::compile(&positive_atoms));
        let atom_tries = if join_plan.is_some() {
            vec![crate::freejoin::WeightedFactTrie::default(); positive_atoms.len()]
        } else {
            Vec::new()
        };
        let neg_count = negatives.len();
        debug_assert!(positive_atoms.len() <= rule.body.len());
        RuleState {
            rule,
            positive_atoms,
            compares,
            neg_steps: vec![crate::zset::EpistemicZSet::new(); neg_count],
            neg_left_indexes: vec![crate::zset::IndexedEpistemicZSet::new(); neg_count],
            neg_right_indexes: vec![crate::zset::IndexedEpistemicZSet::new(); neg_count],
            negatives,
            aggregate,
            join_plan,
            atom_tries,
            after_compare: crate::zset::EpistemicZSet::new(),
            agg_groups: crate::zset::IndexedEpistemicZSet::new(),
            agg_group_outputs: std::collections::BTreeMap::new(),
            head_binding_weights: std::collections::BTreeMap::new(),
            is_unit_seeded: false,
            output: crate::zset::EpistemicZSet::new(),
        }
    }

    fn references_any_delta(&self, input_deltas: &EpistemicFactDeltaMap) -> bool {
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

    /// Apply input K-relation deltas through the Free Join / antijoin pipeline and return `Δoutput`.
    pub(crate) fn step_delta(
        &mut self,
        ctx: RuleStepContext<'_>,
        budget: &mut crate::engine::Budget<'_>,
        coverage_reasons: &mut std::collections::BTreeMap<String, String>,
    ) -> Result<crate::zset::EpistemicZSet<FactKey>, crate::Error> {
        let is_non_monotonic = !self.negatives.is_empty() || self.aggregate.is_some();
        if is_non_monotonic && !is_rule_body_complete(&self.rule, ctx.coverage) {
            return self.retract_output_for_incomplete();
        }
        if !self.references_any_delta(ctx.input_deltas) {
            return Ok(crate::zset::EpistemicZSet::new());
        }
        let mut delta_cur = self.step_positive_joins(ctx.input_deltas, budget)?;
        delta_cur = self.step_compares(&delta_cur, budget)?;
        delta_cur = self.step_negatives(&ctx, delta_cur, budget)?;
        self.step_head(&delta_cur, ctx.coverage, budget, coverage_reasons)
    }

    fn retract_output_for_incomplete(
        &mut self,
    ) -> Result<crate::zset::EpistemicZSet<FactKey>, crate::Error> {
        debug_assert!(!self.negatives.is_empty() || self.aggregate.is_some());
        if self.output.is_empty() {
            return Ok(crate::zset::EpistemicZSet::new());
        }
        let retraction = crate::zset::EpistemicZSet::new().subtract(&self.output)?;
        self.output = crate::zset::EpistemicZSet::new();
        self.head_binding_weights.clear();
        self.agg_group_outputs.clear();
        self.agg_groups = crate::zset::IndexedEpistemicZSet::new();
        Ok(retraction)
    }

    fn step_positive_joins(
        &mut self,
        input_deltas: &EpistemicFactDeltaMap,
        budget: &mut crate::engine::Budget<'_>,
    ) -> Result<crate::zset::EpistemicZSet<Binding>, crate::Error> {
        if self.positive_atoms.is_empty() {
            if !self.is_unit_seeded {
                self.is_unit_seeded = true;
                let mut unit = crate::zset::EpistemicZSet::new();
                unit.insert_weight(Binding::new(), crate::zset::EpistemicWeight::ONE)?;
                return Ok(unit);
            }
            return Ok(crate::zset::EpistemicZSet::new());
        }
        if self.positive_atoms.len() == 1 {
            let atom = &self.positive_atoms[0];
            return bind_optional_delta(atom, input_deltas.get(&atom.predicate), budget);
        }
        self.step_free_join_telescoping(input_deltas, budget)
    }

    /// Exact multi-way DBSP telescoping Free Join:
    /// `Δ(R_0 ⋈ ... ⋈ R_{k-1}) = Σ_{i=0}^{k-1} (R_0^next ⋈ ... ⋈ ΔR_i ⋈ ... ⋈ R_{k-1}^prev)`.
    fn step_free_join_telescoping(
        &mut self,
        input_deltas: &EpistemicFactDeltaMap,
        budget: &mut crate::engine::Budget<'_>,
    ) -> Result<crate::zset::EpistemicZSet<Binding>, crate::Error> {
        let Some(plan) = self.join_plan.as_ref() else {
            return Ok(crate::zset::EpistemicZSet::new());
        };
        assert_eq!(self.atom_tries.len(), plan.atoms.len());
        let mut total_delta = crate::zset::EpistemicZSet::new();
        for atom_idx in 0..plan.atoms.len() {
            let layout = &plan.atoms[atom_idx];
            let Some(delta_rel) = input_deltas.get(&layout.predicate) else {
                continue;
            };
            if delta_rel.is_empty() {
                continue;
            }
            let delta_trie = build_delta_weighted_trie(layout, delta_rel, budget)?;
            if delta_trie.is_empty() {
                continue;
            }
            let tries_refs: Vec<&crate::freejoin::WeightedFactTrie> = (0..plan.atoms.len())
                .map(|idx| {
                    if idx == atom_idx {
                        &delta_trie
                    } else {
                        &self.atom_tries[idx]
                    }
                })
                .collect();
            let term_delta =
                crate::freejoin::evaluate_weighted_free_join_term(plan, &tries_refs, budget)?;
            total_delta.add_in_place(&term_delta)?;
            apply_delta_to_weighted_trie(&mut self.atom_tries[atom_idx], layout, delta_rel)?;
        }
        Ok(total_delta)
    }

    fn step_compares(
        &mut self,
        delta_in: &crate::zset::EpistemicZSet<Binding>,
        budget: &mut crate::engine::Budget<'_>,
    ) -> Result<crate::zset::EpistemicZSet<Binding>, crate::Error> {
        if delta_in.is_empty() || self.compares.is_empty() {
            self.after_compare.add_in_place(delta_in)?;
            return Ok(delta_in.clone());
        }
        let mut out = crate::zset::EpistemicZSet::new();
        for (binding, weight) in delta_in.iter() {
            charge_budget(budget, 1)?;
            if compares_hold(&self.compares, binding) {
                out.insert_weight(binding.clone(), weight)?;
            }
        }
        self.after_compare.add_in_place(&out)?;
        Ok(out)
    }

    fn step_negatives(
        &mut self,
        ctx: &RuleStepContext<'_>,
        mut delta_cur: crate::zset::EpistemicZSet<Binding>,
        budget: &mut crate::engine::Budget<'_>,
    ) -> Result<crate::zset::EpistemicZSet<Binding>, crate::Error> {
        assert_eq!(self.neg_steps.len(), self.negatives.len());
        assert_eq!(self.neg_left_indexes.len(), self.negatives.len());
        if !self.negatives.is_empty() && !is_rule_body_complete(&self.rule, ctx.coverage) {
            return Ok(crate::zset::EpistemicZSet::new());
        }
        let combine_op = if ctx.negation_semantics == crate::NegationSemantics::Strict {
            crate::zset::EpistemicCombineOp::StrictAntijoinMask
        } else {
            crate::zset::EpistemicCombineOp::KleeneAntijoinMask
        };
        for index in 0..self.negatives.len() {
            let neg_atom = &self.negatives[index];
            if !mneme_kernel::admission::non_monotonic_rule_admissible(kernel_coverage(
                coverage_status_of(ctx.coverage, &neg_atom.predicate),
            )) {
                return Ok(crate::zset::EpistemicZSet::new());
            }
            let delta_neg_raw =
                filter_optional_neg(neg_atom, ctx.input_deltas.get(&neg_atom.predicate), budget)?;
            if delta_cur.is_empty() && delta_neg_raw.is_empty() {
                continue;
            }
            let delta_left = crate::zset::IndexedEpistemicZSet::from_zset(&delta_cur, |b| {
                neg_atom_key(neg_atom, b)
            })?;
            let mut delta_right = crate::zset::IndexedEpistemicZSet::new();
            for (key, weight) in delta_neg_raw.iter() {
                delta_right.insert_weight(key.clone(), (), weight)?;
            }
            let mask_delta = crate::zset::delta_epistemic_join(
                crate::zset::EpistemicBilinearJoin {
                    left_prev: &self.neg_left_indexes[index],
                    left_delta: &delta_left,
                    right_prev: &self.neg_right_indexes[index],
                    right_delta: &delta_right,
                },
                combine_op,
                |binding, _| Some(binding.clone()),
                |cost| charge_budget(budget, cost),
            )?;
            let next_delta = delta_cur.subtract(&mask_delta)?;
            self.neg_left_indexes[index]
                .apply_delta_with(&delta_cur, |b| neg_atom_key(neg_atom, b))?;
            for (key, weight) in delta_neg_raw.iter() {
                self.neg_right_indexes[index].insert_weight(key.clone(), (), weight)?;
            }
            self.neg_steps[index].add_in_place(&next_delta)?;
            delta_cur = next_delta;
        }
        Ok(delta_cur)
    }

    fn step_head(
        &mut self,
        delta_bindings: &crate::zset::EpistemicZSet<Binding>,
        coverage: &std::collections::BTreeMap<String, crate::CoverageStatus>,
        budget: &mut crate::engine::Budget<'_>,
        coverage_reasons: &mut std::collections::BTreeMap<String, String>,
    ) -> Result<crate::zset::EpistemicZSet<FactKey>, crate::Error> {
        assert!(!self.rule.head.predicate.is_empty());
        if delta_bindings.is_empty() {
            return Ok(crate::zset::EpistemicZSet::new());
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
        let mut delta_out = crate::zset::EpistemicZSet::new();
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
            update_head_binding_weights(&mut self.head_binding_weights, &terms, binding, weight)?;
            delta_out.insert_weight(terms, weight)?;
        }
        self.output.add_in_place(&delta_out)?;
        debug_assert!(self.output.iter().all(|(_, w)| w.is_active()));
        Ok(delta_out)
    }

    fn step_aggregate_head(
        &mut self,
        agg: &AggSpec,
        delta_bindings: &crate::zset::EpistemicZSet<Binding>,
        coverage: &std::collections::BTreeMap<String, crate::CoverageStatus>,
        budget: &mut crate::engine::Budget<'_>,
        coverage_reasons: &mut std::collections::BTreeMap<String, String>,
    ) -> Result<crate::zset::EpistemicZSet<FactKey>, crate::Error> {
        assert!(self.aggregate.is_some());
        if !is_rule_body_complete(&self.rule, coverage) {
            return Ok(crate::zset::EpistemicZSet::new());
        }
        let affected_groups: std::collections::BTreeSet<JoinKey> = delta_bindings
            .iter()
            .filter_map(|(binding, _)| aggregate_group_key(&agg.group_vars, binding))
            .collect();
        self.agg_groups
            .apply_delta_with(delta_bindings, |binding| {
                aggregate_group_key(&agg.group_vars, binding).unwrap_or_default()
            })?;
        let mut delta_out = crate::zset::EpistemicZSet::new();
        for group_key in affected_groups {
            charge_budget(budget, 1)?;
            if let Some((old_terms, old_status)) = self.agg_group_outputs.remove(&group_key) {
                delta_out.insert_status(old_terms, old_status, -1)?;
            }
            let Some(bucket) = self.agg_groups.get(&group_key) else {
                continue;
            };
            match compute_group_head_row(&self.rule.head, agg, bucket) {
                Ok(Some((new_terms, group_epistemic))) => {
                    self.agg_group_outputs
                        .insert(group_key, (new_terms.clone(), group_epistemic));
                    delta_out.insert_status(new_terms, group_epistemic, 1)?;
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
        debug_assert!(self.output.iter().all(|(_, w)| w.is_active()));
        Ok(delta_out)
    }

    pub(crate) fn ordinary_bindings_for(&self, head_terms: &FactKey) -> Vec<Binding> {
        self.head_binding_weights
            .get(head_terms)
            .map(|zset| {
                zset.iter()
                    .filter(|(_, w)| w.is_active())
                    .map(|(b, _)| b.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn aggregate_bindings_for(&self, head_terms: &FactKey) -> Vec<Binding> {
        if self.aggregate.is_none() {
            return Vec::new();
        }
        let mut matched = Vec::with_capacity(self.agg_group_outputs.len());
        for (group_key, (output_row, _)) in &self.agg_group_outputs {
            if output_row != head_terms {
                continue;
            }
            if let Some(bucket) = self.agg_groups.get(group_key) {
                for (binding, weight) in bucket.iter() {
                    if weight.is_active() {
                        matched.push(binding.clone());
                    }
                }
            }
        }
        debug_assert!(matched.len() < usize::MAX);
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
        for atom in &self.negatives {
            let Some(keys) = dirty_inputs.get(&atom.predicate) else {
                continue;
            };
            if keys.is_empty() {
                continue;
            }
            self.collect_dirty_ordinary_heads(atom, keys, out);
            self.collect_dirty_aggregate_heads(atom, keys, out);
        }
    }

    fn collect_dirty_ordinary_heads(
        &self,
        atom: &crate::Atom,
        keys: &std::collections::BTreeSet<FactKey>,
        out: &mut std::collections::BTreeMap<String, std::collections::BTreeSet<FactKey>>,
    ) {
        for (head_key, bindings) in &self.head_binding_weights {
            if bindings.iter().any(|(binding, weight)| {
                weight.is_active()
                    && instantiate_atom(atom, binding).is_some_and(|inst| keys.contains(&inst))
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
        for (group_key, (output_row, _)) in &self.agg_group_outputs {
            let Some(bucket) = self.agg_groups.get(group_key) else {
                continue;
            };
            if bucket.iter().any(|(binding, weight)| {
                weight.is_active()
                    && instantiate_atom(atom, binding).is_some_and(|inst| keys.contains(&inst))
            }) {
                out.entry(self.rule.head.predicate.clone())
                    .or_default()
                    .insert(output_row.clone());
            }
        }
    }
}

pub(crate) struct RuleStepContext<'a> {
    input_deltas: &'a EpistemicFactDeltaMap,
    coverage: &'a std::collections::BTreeMap<String, crate::CoverageStatus>,
    negation_semantics: crate::NegationSemantics,
}

/// One inner-loop round of a component's evaluation.
#[derive(Clone, Debug, Default)]
pub(crate) struct ComponentRoundState {
    pub(crate) rule_states: std::collections::BTreeMap<String, RuleState>,
    pub(crate) derived_multisets: EpistemicFactDeltaMap,
    pub(crate) derived_sets: EpistemicFactDeltaMap,
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

/// Complete K-relation DBSP incremental view state across all strata of a [`crate::RuleProgram`].
#[derive(Clone, Debug, Default)]
pub(crate) struct ViewState {
    pub(crate) relations: EpistemicFactDeltaMap,
    pub(crate) components: Vec<ComponentState>,
    pub(crate) justifications: crate::JustificationGraph,
    pub(crate) negation_semantics: crate::NegationSemantics,
}

pub(crate) struct SyncRuleChangeRequest<'a> {
    pub(crate) program: &'a crate::RuleProgram,
    pub(crate) build_facts: &'a std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<FactKey, crate::FactData>,
    >,
    pub(crate) justifications: &'a crate::JustificationGraph,
    pub(crate) affected: &'a std::collections::BTreeSet<String>,
    pub(crate) base_coverage: &'a std::collections::BTreeMap<String, crate::CoverageStatus>,
    pub(crate) coverage_reasons: &'a std::collections::BTreeMap<String, String>,
    pub(crate) limits: &'a crate::Limits,
    pub(crate) initial_work: u64,
    pub(crate) start: std::time::Instant,
}

pub(crate) struct ApplyRuleChangeRequest<'a> {
    pub(crate) program: &'a crate::RuleProgram,
    pub(crate) affected: &'a std::collections::BTreeSet<String>,
    pub(crate) base: &'a crate::engine::BaseSnapshot,
    pub(crate) context: &'a crate::BuildContext,
    pub(crate) current_facts: &'a std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<FactKey, crate::FactData>,
    >,
    pub(crate) limits: &'a crate::Limits,
    pub(crate) at: Option<mneme_core::Timestamp>,
    pub(crate) start: std::time::Instant,
}

impl ViewState {
    /// Initialize K-relation DBSP state and justification graph from loaded base facts.
    pub(crate) fn from_base_facts(
        facts: &std::collections::BTreeMap<String, crate::engine::FactStore>,
        negation_semantics: crate::NegationSemantics,
    ) -> Result<Self, crate::Error> {
        let mut justifications = crate::JustificationGraph::default();
        let relations = facts
            .iter()
            .map(|(predicate, store)| {
                let mut zset = crate::zset::EpistemicZSet::new();
                for (key, data) in &store.rows {
                    if data.is_active() {
                        zset.insert_status(key.clone(), data.epistemic, 1)?;
                        let fact_ref = (predicate.clone(), key.clone());
                        for support in &data.supports {
                            justifications.intern_derivation(fact_ref.clone(), support);
                        }
                    }
                }
                Ok((predicate.clone(), zset))
            })
            .collect::<Result<std::collections::BTreeMap<_, _>, crate::Error>>()?;
        debug_assert_eq!(relations.len(), facts.len());
        Ok(ViewState {
            relations,
            components: Vec::new(),
            justifications,
            negation_semantics,
        })
    }

    fn prune_removed_and_affected(
        &mut self,
        program: &crate::RuleProgram,
        affected: &std::collections::BTreeSet<String>,
    ) {
        let to_clear: Vec<String> = self
            .relations
            .keys()
            .filter(|pred| {
                let is_base = program.bundle.base_predicates.contains_key(*pred);
                !is_base && (affected.contains(*pred) || !program.arities.contains_key(*pred))
            })
            .cloned()
            .collect();
        for pred in to_clear {
            if let Some(rel) = self.relations.remove(&pred) {
                for (key, _) in rel.iter() {
                    self.justifications.clear_fact(&(pred.clone(), key.clone()));
                }
            }
        }
    }

    /// Synchronize K-relation component states after a fallback rule evaluation (e.g. temporal rules).
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
        let mut budget =
            new_step_budget(request.limits, request.initial_work, request.start, false);
        let rebuild_result = rebuild_components(
            RebuildComponentsContext {
                request: &request,
                existing_by_key: &existing_by_key,
                next_relations: &next_relations,
                negation_semantics: self.negation_semantics,
            },
            specs,
            &mut budget,
        );
        *work_charged = budget.work.saturating_sub(request.initial_work);
        let next_components = rebuild_result?;
        self.relations = next_relations;
        self.components = next_components;
        self.justifications = request.justifications.clone();
        Ok(())
    }
}

struct RuleChangeState {
    next_view: ViewState,
    store_map: std::collections::BTreeMap<String, crate::engine::FactStore>,
    coverage_reasons: std::collections::BTreeMap<String, String>,
    coverage_map: std::collections::BTreeMap<String, crate::CoverageStatus>,
    is_any_truncated: bool,
}

/// Apply a rule addition or retraction directly using the unified K-relation Free Join IVM engine.
pub(crate) fn apply_rule_change(
    view: &ViewState,
    request: ApplyRuleChangeRequest<'_>,
) -> Result<AdvanceViewResult, crate::Error> {
    assert!(request.limits.max_work > 0);
    let mut budget = new_step_budget(
        request.limits,
        0,
        request.start,
        request.base.support_truncated,
    );
    let mut next_view = view.clone();
    let store_map = init_kept_stores(
        request.program,
        request.affected,
        request.base,
        request.current_facts,
    );
    next_view.prune_removed_and_affected(request.program, request.affected);

    let specs = partition_program_components(request.program);
    let existing_by_key: std::collections::BTreeMap<(usize, String), ComponentState> = next_view
        .components
        .iter()
        .map(|comp| ((comp.stratum, comp.id.clone()), comp.clone()))
        .collect();
    let coverage_reasons = request.base.coverage_reasons.clone();
    let coverage_map = crate::engine::compute_derived_coverage(
        &request.program.bundle,
        &request.base.base_coverage,
        &coverage_reasons,
        budget.status,
    );
    let reused_cap: usize = specs.iter().map(|spec| spec.predicates.len()).sum();
    let mut next_components = Vec::with_capacity(specs.len());
    let mut reused_predicates = Vec::with_capacity(reused_cap);
    let mut state = RuleChangeState {
        next_view,
        store_map,
        coverage_reasons,
        coverage_map,
        is_any_truncated: false,
    };

    for spec in specs {
        if !budget.is_active() {
            return Ok(limit_reached_result(state.next_view, &budget));
        }
        let has_affected = spec
            .predicates
            .iter()
            .any(|pred| request.affected.contains(pred));
        let existing = existing_by_key.get(&(spec.stratum, spec.id.clone()));
        if can_reuse_owned_component(existing, &spec, has_affected) {
            if let Some(comp) = existing {
                reused_predicates.extend(comp.predicates.iter().cloned());
                next_components.push(comp.clone());
            }
            continue;
        }
        let Some(comp) = step_rule_change_component(&request, spec, &mut state, &mut budget)?
        else {
            return Ok(limit_reached_result(state.next_view, &budget));
        };
        next_components.push(comp);
    }

    state.next_view.components = next_components;
    Ok(finalize_rule_change(
        &request,
        state,
        &budget,
        reused_predicates,
    ))
}

fn can_reuse_owned_component(
    existing: Option<&ComponentState>,
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

fn step_rule_change_component(
    request: &ApplyRuleChangeRequest<'_>,
    spec: ComponentSpec,
    state: &mut RuleChangeState,
    budget: &mut crate::engine::Budget<'_>,
) -> Result<Option<ComponentState>, crate::Error> {
    let mut comp = ComponentState {
        stratum: spec.stratum,
        id: spec.id,
        predicates: spec.predicates,
        rule_ids: spec.rule_ids,
        is_recursive: spec.is_recursive,
        rounds: Vec::new(),
    };
    let initial_deltas =
        external_inputs_for_component(request.program, &comp, &state.next_view.relations);
    let prev_reasons_len = state.coverage_reasons.len();
    let step_res = comp.step_component_delta(
        ComponentStepContext {
            program: request.program,
            external_deltas: &initial_deltas,
            coverage: &state.coverage_map,
            negation_semantics: state.next_view.negation_semantics,
            max_recursion_depth: request.limits.max_recursion_depth,
        },
        budget,
        &mut state.coverage_reasons,
    );
    let (comp_deltas, _) = match step_res {
        Ok(res) => res,
        Err(crate::Error::LimitExceeded(_)) => return Ok(None),
        Err(err) => return Err(err),
    };
    if state.coverage_reasons.len() != prev_reasons_len {
        state.coverage_map = crate::engine::compute_derived_coverage(
            &request.program.bundle,
            &request.base.base_coverage,
            &state.coverage_reasons,
            budget.status,
        );
    }
    let keys_to_populate: std::collections::BTreeMap<String, std::collections::BTreeSet<FactKey>> =
        comp_deltas
            .into_iter()
            .map(|(pred, delta)| {
                let active_keys = delta
                    .iter()
                    .filter(|(_, weight)| weight.is_active())
                    .map(|(key, _)| key.clone())
                    .collect();
                state.next_view.relations.insert(pred.clone(), delta);
                (pred, active_keys)
            })
            .collect();
    let is_comp_truncated = rebuild_component_keys_once(
        RebuildComponentTarget {
            component: &comp,
            keys_to_refresh: &keys_to_populate,
            relations: &state.next_view.relations,
            key_ctx: RebuildKeyContext {
                context: request.context,
                coverage_map: &state.coverage_map,
                negation_semantics: state.next_view.negation_semantics,
            },
        },
        budget,
        &mut state.store_map,
        &mut state.next_view.justifications,
    );
    state.is_any_truncated |= is_comp_truncated;
    if !budget.is_active() || budget.limit_reached {
        return Ok(None);
    }
    Ok(Some(comp))
}

fn finalize_rule_change(
    request: &ApplyRuleChangeRequest<'_>,
    state: RuleChangeState,
    budget: &crate::engine::Budget<'_>,
    mut reused_predicates: Vec<String>,
) -> AdvanceViewResult {
    let next_facts: std::collections::BTreeMap<_, _> = state
        .store_map
        .into_iter()
        .map(|(pred, store)| (pred, store.rows))
        .collect();
    let mut fact_predicates: std::collections::BTreeSet<String> =
        next_facts.keys().cloned().collect();
    fact_predicates.extend(state.next_view.relations.keys().cloned());
    let (_, coverage, coverage_status) =
        crate::engine::compute_coverage_for_facts(crate::engine::CoverageCheckRequest {
            base: request.base,
            bundle: &request.program.bundle,
            context: request.context,
            limits: request.limits,
            fact_predicates: &fact_predicates,
            coverage_reasons: &state.coverage_reasons,
            at: request.at,
            start: request.start,
        });
    reused_predicates.sort();
    let status = if budget.status != crate::ExecutionStatus::Complete {
        budget.status
    } else {
        coverage_status
    };
    AdvanceViewResult {
        next_view: state.next_view,
        next_facts,
        coverage,
        status,
        work: budget.work,
        support_truncated: budget.support_truncated || state.is_any_truncated,
        limit_reached: false,
        affected_predicates: request.affected.iter().cloned().collect(),
        reused_predicates,
    }
}

fn init_kept_stores(
    program: &crate::RuleProgram,
    affected: &std::collections::BTreeSet<String>,
    base: &crate::engine::BaseSnapshot,
    current_facts: &std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<FactKey, crate::FactData>,
    >,
) -> std::collections::BTreeMap<String, crate::engine::FactStore> {
    let mut store_map: std::collections::BTreeMap<String, crate::engine::FactStore> = current_facts
        .iter()
        .filter(|(pred, _)| {
            let is_base = program.bundle.base_predicates.contains_key(*pred);
            let is_defined = program.arities.contains_key(*pred);
            is_base || (is_defined && !affected.contains(*pred))
        })
        .map(|(pred, rows)| {
            (
                pred.clone(),
                crate::engine::FactStore::from_rows(rows.clone()),
            )
        })
        .collect();
    for (pred, store) in &base.facts {
        store_map
            .entry(pred.clone())
            .or_insert_with(|| store.clone());
    }
    store_map
}

fn new_step_budget<'a>(
    limits: &'a crate::Limits,
    initial_work: u64,
    start: std::time::Instant,
    support_truncated: bool,
) -> crate::engine::Budget<'a> {
    crate::engine::Budget {
        limits,
        work: initial_work,
        stored_rows: 0,
        start,
        cancellation: None,
        status: crate::ExecutionStatus::Complete,
        limit_reached: false,
        support_truncated,
        max_intervals_per_fact: crate::DEFAULT_MAX_INTERVALS_PER_FACT,
    }
}

fn build_relations_map(
    build_facts: &std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<FactKey, crate::FactData>,
    >,
) -> Result<EpistemicFactDeltaMap, crate::Error> {
    assert!(build_facts.len() < usize::MAX);
    build_facts
        .iter()
        .map(|(predicate, rows)| {
            let mut zset = crate::zset::EpistemicZSet::new();
            for (key, data) in rows {
                if data.is_active() {
                    zset.insert_status(key.clone(), data.epistemic, 1)?;
                }
            }
            Ok((predicate.clone(), zset))
        })
        .collect()
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

struct RebuildComponentsContext<'a> {
    request: &'a SyncRuleChangeRequest<'a>,
    existing_by_key: &'a std::collections::BTreeMap<(usize, String), &'a ComponentState>,
    next_relations: &'a EpistemicFactDeltaMap,
    negation_semantics: crate::NegationSemantics,
}

fn rebuild_components(
    ctx: RebuildComponentsContext<'_>,
    specs: Vec<ComponentSpec>,
    budget: &mut crate::engine::Budget<'_>,
) -> Result<Vec<ComponentState>, crate::Error> {
    let request = ctx.request;
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
        let existing = ctx.existing_by_key.get(&(spec.stratum, spec.id.clone()));
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
        let initial_deltas =
            external_inputs_for_component(request.program, &comp, ctx.next_relations);
        let prev_reasons_len = coverage_reasons.len();
        let _ = comp.step_component_delta(
            ComponentStepContext {
                program: request.program,
                external_deltas: &initial_deltas,
                coverage: &coverage_map,
                negation_semantics: ctx.negation_semantics,
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
    Ok(next_components)
}

pub(crate) struct AdvanceViewRequest<'a> {
    pub(crate) program: &'a crate::RuleProgram,
    pub(crate) base_deltas: EpistemicFactDeltaMap,
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

/// Propagate K-relation base Z-set deltas through all strata and refresh affected `FactData`
/// using O(Delta) justification DAG invalidation.
pub(crate) fn advance_view(
    view: &ViewState,
    request: AdvanceViewRequest<'_>,
) -> Result<AdvanceViewResult, crate::Error> {
    assert!(request.limits.max_work > 0);
    let mut state = AdvanceAccumulator::new(view, &request)?;
    let mut budget = new_step_budget(
        request.limits,
        request.initial_work,
        request.start,
        request.next_base.support_truncated,
    );
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
    finish_advance_view(state, &request, &mut budget, &coverage_reasons)
}

struct ComponentStepRecord {
    comp_idx: usize,
    comp_deltas: EpistemicFactDeltaMap,
    comp_multiset_deltas: EpistemicFactDeltaMap,
    max_recursion_depth: usize,
}

struct AdvanceAccumulator {
    next_view: ViewState,
    all_deltas: EpistemicFactDeltaMap,
    multiset_deltas: EpistemicFactDeltaMap,
    dirty_by_pred: std::collections::BTreeMap<String, std::collections::BTreeSet<FactKey>>,
    affected_set: std::collections::BTreeSet<String>,
    reused_predicates: Vec<String>,
    is_fallback_dirty_scan: bool,
}

impl AdvanceAccumulator {
    fn new(view: &ViewState, request: &AdvanceViewRequest<'_>) -> Result<Self, crate::Error> {
        let mut next_view = view.clone();
        let all_deltas = request.base_deltas.clone();
        let delta_seed_cap: usize = all_deltas.values().map(|delta| delta.iter().count()).sum();
        let mut seed_refs = Vec::with_capacity(
            request
                .dirty_provenance
                .len()
                .saturating_add(delta_seed_cap),
        );
        let mut dirty_by_pred: std::collections::BTreeMap<
            String,
            std::collections::BTreeSet<FactKey>,
        > = std::collections::BTreeMap::new();
        for (pred, key) in &request.dirty_provenance {
            dirty_by_pred
                .entry(pred.clone())
                .or_default()
                .insert(key.clone());
            seed_refs.push((pred.clone(), key.clone()));
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
                    if !weight.is_zero() {
                        dirty_entry.insert(key.clone());
                        seed_refs.push((pred.clone(), key.clone()));
                    }
                }
            }
        }
        let is_fallback_dirty_scan = next_view.justifications.is_truncated();
        invalidate_and_reintern_seeds(
            &mut next_view.justifications,
            &seed_refs,
            request.next_base,
            &mut dirty_by_pred,
        );
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
        Ok(Self {
            next_view,
            all_deltas,
            multiset_deltas: std::collections::BTreeMap::new(),
            dirty_by_pred,
            affected_set,
            reused_predicates: Vec::with_capacity(reused_cap),
            is_fallback_dirty_scan,
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
        let negation_semantics = self.next_view.negation_semantics;
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
                    negation_semantics,
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
        Ok(true)
    }

    fn record_component_step(&mut self, record: ComponentStepRecord) -> Result<(), crate::Error> {
        let ComponentStepRecord {
            comp_idx,
            comp_deltas,
            comp_multiset_deltas,
            max_recursion_depth,
        } = record;
        assert!(!self.next_view.components[comp_idx].predicates.is_empty());
        let (is_component_affected, newly_dirty_seeds) =
            self.apply_component_deltas(comp_deltas, comp_multiset_deltas)?;
        if !newly_dirty_seeds.is_empty() {
            let invalidated = self
                .next_view
                .justifications
                .invalidate_facts(&newly_dirty_seeds);
            for (pred, terms) in invalidated {
                self.dirty_by_pred.entry(pred).or_default().insert(terms);
            }
        }
        if self.is_fallback_dirty_scan {
            propagate_component_dirty_heads(
                &self.next_view.components[comp_idx],
                &mut self.dirty_by_pred,
                max_recursion_depth,
            );
        }
        if !is_component_affected {
            for pred in &self.next_view.components[comp_idx].predicates {
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
        Ok(())
    }

    fn apply_component_deltas(
        &mut self,
        comp_deltas: EpistemicFactDeltaMap,
        comp_multiset_deltas: EpistemicFactDeltaMap,
    ) -> Result<(bool, Vec<crate::FactRef>), crate::Error> {
        let seed_cap: usize = comp_deltas
            .values()
            .chain(comp_multiset_deltas.values())
            .map(|delta| delta.iter().count())
            .sum();
        let mut is_component_affected = false;
        let mut newly_dirty_seeds = Vec::with_capacity(seed_cap);
        for (pred, delta) in comp_deltas {
            if !delta.is_empty() {
                is_component_affected = true;
                self.affected_set.insert(pred.clone());
                self.next_view
                    .relations
                    .entry(pred.clone())
                    .or_default()
                    .add_in_place(&delta)?;
                for (key, weight) in delta.iter() {
                    if !weight.is_zero() {
                        newly_dirty_seeds.push((pred.clone(), key.clone()));
                    }
                }
            }
            self.all_deltas.insert(pred, delta);
        }
        for (pred, m_delta) in comp_multiset_deltas {
            if !m_delta.is_empty() {
                is_component_affected = true;
                self.affected_set.insert(pred.clone());
                let dirty_entry = self.dirty_by_pred.entry(pred.clone()).or_default();
                for (key, weight) in m_delta.iter() {
                    if !weight.is_zero() {
                        dirty_entry.insert(key.clone());
                        newly_dirty_seeds.push((pred.clone(), key.clone()));
                    }
                }
            }
            self.multiset_deltas.insert(pred, m_delta);
        }
        Ok((is_component_affected, newly_dirty_seeds))
    }
}

fn invalidate_and_reintern_seeds(
    justifications: &mut crate::JustificationGraph,
    seed_refs: &[crate::FactRef],
    next_base: &crate::engine::BaseSnapshot,
    dirty_by_pred: &mut std::collections::BTreeMap<String, std::collections::BTreeSet<FactKey>>,
) {
    if seed_refs.is_empty() {
        return;
    }
    let invalidated = justifications.invalidate_facts(seed_refs);
    for (pred, terms) in invalidated {
        dirty_by_pred.entry(pred).or_default().insert(terms);
    }
    for seed in seed_refs {
        if let Some(data) = next_base
            .facts
            .get(&seed.0)
            .and_then(|s| s.rows.get(&seed.1))
            && data.is_active()
        {
            for support in &data.supports {
                justifications.intern_derivation(seed.clone(), support);
            }
        }
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
            components: &state.next_view.components,
            relations: &state.next_view.relations,
            all_deltas: &state.all_deltas,
            multiset_deltas: &state.multiset_deltas,
            dirty_by_pred: &state.dirty_by_pred,
            next_context: request.next_context,
            coverage_map: &coverage_map,
            negation_semantics: state.next_view.negation_semantics,
        },
        budget,
        &mut next_facts,
        &mut state.next_view.justifications,
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
    next_facts
}

struct RefreshFactDataRequest<'a> {
    components: &'a [ComponentState],
    relations: &'a EpistemicFactDeltaMap,
    all_deltas: &'a EpistemicFactDeltaMap,
    multiset_deltas: &'a EpistemicFactDeltaMap,
    dirty_by_pred: &'a std::collections::BTreeMap<String, std::collections::BTreeSet<FactKey>>,
    next_context: &'a crate::BuildContext,
    coverage_map: &'a std::collections::BTreeMap<String, crate::CoverageStatus>,
    negation_semantics: crate::NegationSemantics,
}

#[derive(Clone, Copy)]
struct RebuildKeyContext<'a> {
    context: &'a crate::BuildContext,
    coverage_map: &'a std::collections::BTreeMap<String, crate::CoverageStatus>,
    negation_semantics: crate::NegationSemantics,
}

/// Refresh `FactData` and `JustificationGraph` ONLY for the O(Delta) keys that
/// changed or were invalidated via reverse hyperedges — no full-component fixpoint recomputation.
fn refresh_derived_fact_data(
    request: RefreshFactDataRequest<'_>,
    budget: &mut crate::engine::Budget<'_>,
    next_facts: &mut std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<FactKey, crate::FactData>,
    >,
    justifications: &mut crate::JustificationGraph,
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
    let key_ctx = RebuildKeyContext {
        context: request.next_context,
        coverage_map: request.coverage_map,
        negation_semantics: request.negation_semantics,
    };
    for component in request.components {
        if !budget.is_active() {
            break;
        }
        remove_retracted_rows(
            component,
            request.relations,
            request.all_deltas,
            &mut store_map,
            justifications,
        );
        let keys_to_refresh =
            collect_keys_to_refresh(component, &request, &mut store_map, justifications);
        if keys_to_refresh
            .values()
            .all(std::collections::BTreeSet::is_empty)
        {
            continue;
        }
        if rebuild_component_keys_once(
            RebuildComponentTarget {
                component,
                keys_to_refresh: &keys_to_refresh,
                relations: request.relations,
                key_ctx,
            },
            budget,
            &mut store_map,
            justifications,
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
    is_any_truncated
}

fn remove_retracted_rows(
    component: &ComponentState,
    relations: &EpistemicFactDeltaMap,
    all_deltas: &EpistemicFactDeltaMap,
    store_map: &mut std::collections::BTreeMap<String, crate::engine::FactStore>,
    justifications: &mut crate::JustificationGraph,
) {
    for pred in &component.predicates {
        let Some(delta) = all_deltas.get(pred) else {
            continue;
        };
        let rel = relations.get(pred);
        for (key, _) in delta.iter() {
            let is_still_active = rel.is_some_and(|r| r.epistemic_status(key).is_active());
            if !is_still_active {
                if let Some(store) = store_map.get_mut(pred) {
                    store.rows.remove(key);
                }
                justifications.clear_fact(&(pred.clone(), key.clone()));
            }
        }
    }
}

fn collect_keys_to_refresh(
    component: &ComponentState,
    request: &RefreshFactDataRequest<'_>,
    store_map: &mut std::collections::BTreeMap<String, crate::engine::FactStore>,
    justifications: &mut crate::JustificationGraph,
) -> std::collections::BTreeMap<String, std::collections::BTreeSet<FactKey>> {
    assert!(!component.predicates.is_empty());
    component
        .predicates
        .iter()
        .map(|pred| {
            let mut set = std::collections::BTreeSet::new();
            let is_active_rel = |key: &FactKey| {
                request
                    .relations
                    .get(pred)
                    .is_some_and(|rel| rel.epistemic_status(key).is_active())
            };
            if let Some(delta) = request.all_deltas.get(pred) {
                set.extend(
                    delta
                        .iter()
                        .filter(|(k, w)| !w.is_zero() && is_active_rel(k))
                        .map(|(k, _)| k.clone()),
                );
            }
            if let Some(m_delta) = request.multiset_deltas.get(pred) {
                set.extend(
                    m_delta
                        .iter()
                        .filter(|(k, w)| !w.is_zero() && is_active_rel(k))
                        .map(|(k, _)| k.clone()),
                );
            }
            if let Some(dirty) = request.dirty_by_pred.get(pred) {
                set.extend(dirty.iter().filter(|k| is_active_rel(k)).cloned());
            }
            if let Some(store) = store_map.get_mut(pred) {
                for key in &set {
                    store.rows.remove(key);
                    justifications.clear_fact(&(pred.clone(), key.clone()));
                }
            }
            (pred.clone(), set)
        })
        .collect()
}

struct RebuildComponentTarget<'a> {
    component: &'a ComponentState,
    keys_to_refresh: &'a std::collections::BTreeMap<String, std::collections::BTreeSet<FactKey>>,
    relations: &'a EpistemicFactDeltaMap,
    key_ctx: RebuildKeyContext<'a>,
}

/// Rebuild `FactData` for the exact O(Delta) `keys_to_refresh` in a single pass
/// over `component.rounds`, reading converged `EpistemicStatus` in O(1) from
/// `relations` and interning every derived support into `justifications`.
fn rebuild_component_keys_once(
    target: RebuildComponentTarget<'_>,
    budget: &mut crate::engine::Budget<'_>,
    store_map: &mut std::collections::BTreeMap<String, crate::engine::FactStore>,
    justifications: &mut crate::JustificationGraph,
) -> bool {
    let RebuildComponentTarget {
        component,
        keys_to_refresh,
        relations,
        key_ctx,
    } = target;
    let mut is_any_truncated = false;
    for round in &component.rounds {
        if !budget.is_active() {
            return is_any_truncated;
        }
        for pred in &component.predicates {
            if !budget.is_active() {
                break;
            }
            let Some(keys) = keys_to_refresh.get(pred) else {
                continue;
            };
            let Some(round_set) = round.derived_sets.get(pred) else {
                continue;
            };
            for key in keys {
                if !budget.is_active() {
                    break;
                }
                if !round_set.epistemic_status(key).is_active() {
                    continue;
                }
                if rebuild_fact_key_from_round(
                    RoundKeyTarget {
                        component,
                        round,
                        pred,
                        key,
                    },
                    key_ctx,
                    budget,
                    store_map,
                ) {
                    is_any_truncated = true;
                }
            }
        }
    }
    // Synchronize exact O(1) K-relation epistemic status and intern derivations into the DAG.
    for pred in &component.predicates {
        let Some(keys) = keys_to_refresh.get(pred) else {
            continue;
        };
        let Some(rel) = relations.get(pred) else {
            continue;
        };
        let Some(store) = store_map.get_mut(pred) else {
            continue;
        };
        for key in keys {
            if let Some(data) = store.rows.get_mut(key) {
                let exact_epistemic = rel.epistemic_status(key);
                if exact_epistemic.is_active() {
                    data.epistemic = exact_epistemic;
                    let fact_ref = (pred.clone(), key.clone());
                    for support in &data.supports {
                        justifications.intern_derivation(fact_ref.clone(), support);
                    }
                }
            }
        }
    }
    is_any_truncated
}

struct RoundKeyTarget<'a> {
    component: &'a ComponentState,
    round: &'a ComponentRoundState,
    pred: &'a str,
    key: &'a FactKey,
}

fn rebuild_fact_key_from_round(
    target: RoundKeyTarget<'_>,
    key_ctx: RebuildKeyContext<'_>,
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
            context: key_ctx.context,
            facts: store_map,
            coverage_map: key_ctx.coverage_map,
            bindings: &bindings,
            target_terms: key,
            negation_semantics: key_ctx.negation_semantics,
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
    is_any_truncated
}

type ComponentStepDelta = (EpistemicFactDeltaMap, EpistemicFactDeltaMap);

struct ComponentStepContext<'a> {
    program: &'a crate::RuleProgram,
    external_deltas: &'a EpistemicFactDeltaMap,
    coverage: &'a std::collections::BTreeMap<String, crate::CoverageStatus>,
    negation_semantics: crate::NegationSemantics,
    max_recursion_depth: usize,
}

struct ComponentLoopState<'a> {
    program: &'a crate::RuleProgram,
    external_deltas: &'a EpistemicFactDeltaMap,
    coverage: &'a std::collections::BTreeMap<String, crate::CoverageStatus>,
    negation_semantics: crate::NegationSemantics,
    prev_round_new_sets: EpistemicFactDeltaMap,
    prev_round_delta_x: EpistemicFactDeltaMap,
    next_rounds: Vec<ComponentRoundState>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BuildPhase {
    Initial,
    Incremental,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExternalDeltaPolicy {
    Apply,
    Skip,
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
            negation_semantics,
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
            negation_semantics,
            prev_round_new_sets: self
                .predicates
                .iter()
                .map(|p| (p.clone(), crate::zset::EpistemicZSet::new()))
                .collect(),
            prev_round_delta_x: std::collections::BTreeMap::new(),
            next_rounds: Vec::with_capacity(max_rounds.min(64)),
        };
        let phase = if self.rounds.is_empty() {
            BuildPhase::Initial
        } else {
            BuildPhase::Incremental
        };
        let mut has_converged = false;
        for round_idx in 0..max_rounds {
            if self.advance_component_round(
                round_idx,
                phase,
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
        compute_outer_component_deltas(&self.predicates, &prev_sets, &prev_multisets, &self.rounds)
    }

    fn advance_component_round(
        &self,
        round_idx: usize,
        phase: BuildPhase,
        loop_state: &mut ComponentLoopState<'_>,
        budget: &mut crate::engine::Budget<'_>,
        coverage_reasons: &mut std::collections::BTreeMap<String, String>,
    ) -> Result<bool, crate::Error> {
        if !budget.is_active() {
            return Err(crate::Error::LimitExceeded(
                "budget exhausted during incremental fixpoint".to_owned(),
            ));
        }
        let (mut round, ext_policy) = self.select_round_template(round_idx, phase, loop_state);
        let round_input_deltas = build_round_inputs(
            &self.predicates,
            ext_policy,
            loop_state.external_deltas,
            &loop_state.prev_round_delta_x,
        );
        let round_m_deltas = step_round_rules(
            RoundStepInput {
                rule_ids: &self.rule_ids,
                input_deltas: &round_input_deltas,
                coverage: loop_state.coverage,
                negation_semantics: loop_state.negation_semantics,
            },
            &mut round,
            budget,
            coverage_reasons,
        )?;
        let (round_x_deltas, round_new_sets) = apply_round_distinct_deltas(
            &self.predicates,
            &mut round,
            &round_m_deltas,
            phase,
            &loop_state.prev_round_new_sets,
        )?;
        let is_fixpoint = !self.is_recursive || round_new_sets == loop_state.prev_round_new_sets;
        loop_state.next_rounds.push(round);
        loop_state.prev_round_new_sets = round_new_sets;
        loop_state.prev_round_delta_x = round_x_deltas;
        Ok(is_fixpoint)
    }

    fn select_round_template(
        &self,
        round_idx: usize,
        phase: BuildPhase,
        loop_state: &ComponentLoopState<'_>,
    ) -> (ComponentRoundState, ExternalDeltaPolicy) {
        if round_idx < self.rounds.len() {
            (self.rounds[round_idx].clone(), ExternalDeltaPolicy::Apply)
        } else if phase == BuildPhase::Initial {
            if let Some(last_new) = loop_state.next_rounds.last() {
                (last_new.clone(), ExternalDeltaPolicy::Skip)
            } else {
                (
                    empty_round_for_component(loop_state.program, self),
                    ExternalDeltaPolicy::Apply,
                )
            }
        } else if let Some(last) = self.rounds.last() {
            (last.clone(), ExternalDeltaPolicy::Apply)
        } else {
            (
                empty_round_for_component(loop_state.program, self),
                ExternalDeltaPolicy::Apply,
            )
        }
    }
}

fn last_derived_sets(rounds: &[ComponentRoundState]) -> EpistemicFactDeltaMap {
    rounds
        .last()
        .map(|r| r.derived_sets.clone())
        .unwrap_or_default()
}

fn last_derived_multisets(rounds: &[ComponentRoundState]) -> EpistemicFactDeltaMap {
    rounds
        .last()
        .map(|r| r.derived_multisets.clone())
        .unwrap_or_default()
}

fn build_round_inputs(
    predicates: &std::collections::BTreeSet<String>,
    ext_policy: ExternalDeltaPolicy,
    external_deltas: &EpistemicFactDeltaMap,
    prev_round_delta_x: &EpistemicFactDeltaMap,
) -> EpistemicFactDeltaMap {
    let mut round_input_deltas = if ext_policy == ExternalDeltaPolicy::Apply {
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
    round_input_deltas
}

struct RoundStepInput<'a> {
    rule_ids: &'a [String],
    input_deltas: &'a EpistemicFactDeltaMap,
    coverage: &'a std::collections::BTreeMap<String, crate::CoverageStatus>,
    negation_semantics: crate::NegationSemantics,
}

fn step_round_rules(
    input: RoundStepInput<'_>,
    round: &mut ComponentRoundState,
    budget: &mut crate::engine::Budget<'_>,
    coverage_reasons: &mut std::collections::BTreeMap<String, String>,
) -> Result<EpistemicFactDeltaMap, crate::Error> {
    assert!(!input.rule_ids.is_empty());
    let mut round_m_deltas: EpistemicFactDeltaMap = std::collections::BTreeMap::new();
    for rule_id in input.rule_ids {
        let Some(rule_state) = round.rule_states.get_mut(rule_id) else {
            continue;
        };
        let delta_out = rule_state.step_delta(
            RuleStepContext {
                input_deltas: input.input_deltas,
                coverage: input.coverage,
                negation_semantics: input.negation_semantics,
            },
            budget,
            coverage_reasons,
        )?;
        if !delta_out.is_empty() {
            round_m_deltas
                .entry(rule_state.rule.head.predicate.clone())
                .or_default()
                .add_in_place(&delta_out)?;
        }
    }
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
            crate::Literal::Positive(atom)
            | crate::Literal::Negative(atom)
            | crate::Literal::DiamondMinus { atom, .. }
            | crate::Literal::BoxMinus { atom, .. } => {
                combined = mneme_kernel::completeness::combine_coverage(
                    combined,
                    kernel_coverage(coverage_status_of(coverage, &atom.predicate)),
                );
            }
            crate::Literal::Since {
                maintained,
                trigger,
                ..
            } => {
                combined = mneme_kernel::completeness::combine_coverage(
                    combined,
                    kernel_coverage(coverage_status_of(coverage, &maintained.predicate)),
                );
                combined = mneme_kernel::completeness::combine_coverage(
                    combined,
                    kernel_coverage(coverage_status_of(coverage, &trigger.predicate)),
                );
            }
            crate::Literal::Allen { left, right, .. } => {
                combined = mneme_kernel::completeness::combine_coverage(
                    combined,
                    kernel_coverage(coverage_status_of(coverage, &left.predicate)),
                );
                combined = mneme_kernel::completeness::combine_coverage(
                    combined,
                    kernel_coverage(coverage_status_of(coverage, &right.predicate)),
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
    round_m_deltas: &EpistemicFactDeltaMap,
    phase: BuildPhase,
    prev_round_new_sets: &EpistemicFactDeltaMap,
) -> Result<ComponentStepDelta, crate::Error> {
    assert!(!predicates.is_empty());
    let pairs = predicates
        .iter()
        .map(|pred| {
            let m_prev = round.derived_multisets.entry(pred.clone()).or_default();
            let x_prev = round.derived_sets.entry(pred.clone()).or_default();
            let x_delta = if let Some(m_delta) = round_m_deltas.get(pred) {
                let dx = m_prev.delta_distinct(m_delta)?;
                m_prev.add_in_place(m_delta)?;
                x_prev.add_in_place(&dx)?;
                dx
            } else {
                crate::zset::EpistemicZSet::new()
            };
            let effective_delta = if phase == BuildPhase::Initial {
                let prev_s = prev_round_new_sets.get(pred).cloned().unwrap_or_default();
                x_prev.subtract(&prev_s)?
            } else {
                x_delta
            };
            Ok((
                (pred.clone(), effective_delta),
                (pred.clone(), x_prev.clone()),
            ))
        })
        .collect::<Result<Vec<_>, crate::Error>>()?;
    let (round_x_deltas, round_new_sets): (EpistemicFactDeltaMap, EpistemicFactDeltaMap) =
        pairs.into_iter().unzip();
    Ok((round_x_deltas, round_new_sets))
}

fn compute_outer_component_deltas(
    predicates: &std::collections::BTreeSet<String>,
    prev_final_sets: &EpistemicFactDeltaMap,
    prev_final_multisets: &EpistemicFactDeltaMap,
    rounds: &[ComponentRoundState],
) -> Result<ComponentStepDelta, crate::Error> {
    assert!(!predicates.is_empty());
    let final_sets = last_derived_sets(rounds);
    let final_multisets = last_derived_multisets(rounds);
    let pairs = predicates
        .iter()
        .map(|pred| {
            let old_s = prev_final_sets.get(pred).cloned().unwrap_or_default();
            let new_s = final_sets.get(pred).cloned().unwrap_or_default();
            let old_m = prev_final_multisets.get(pred).cloned().unwrap_or_default();
            let new_m = final_multisets.get(pred).cloned().unwrap_or_default();
            Ok((
                (pred.clone(), new_s.subtract(&old_s)?),
                (pred.clone(), new_m.subtract(&old_m)?),
            ))
        })
        .collect::<Result<Vec<_>, crate::Error>>()?;
    let (set_deltas, multiset_deltas): (EpistemicFactDeltaMap, EpistemicFactDeltaMap) =
        pairs.into_iter().unzip();
    Ok((set_deltas, multiset_deltas))
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
    specs
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
    relations: &EpistemicFactDeltaMap,
) -> EpistemicFactDeltaMap {
    assert!(!comp.predicates.is_empty());
    program
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
        .collect()
}

fn component_has_external_delta(
    program: &crate::RuleProgram,
    comp: &ComponentState,
    external_deltas: &EpistemicFactDeltaMap,
) -> bool {
    assert!(!comp.predicates.is_empty());
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

fn build_delta_weighted_trie(
    layout: &crate::freejoin::WeightedAtomLayout,
    delta_rel: &crate::zset::EpistemicZSet<FactKey>,
    budget: &mut crate::engine::Budget<'_>,
) -> Result<crate::freejoin::WeightedFactTrie, crate::Error> {
    let mut trie = crate::freejoin::WeightedFactTrie::default();
    for (terms, weight) in delta_rel.iter() {
        charge_budget(budget, 1)?;
        if layout.matches_tuple(terms) {
            trie.apply_delta(terms, &layout.col_order, weight)?;
        }
    }
    Ok(trie)
}

fn apply_delta_to_weighted_trie(
    trie: &mut crate::freejoin::WeightedFactTrie,
    layout: &crate::freejoin::WeightedAtomLayout,
    delta_rel: &crate::zset::EpistemicZSet<FactKey>,
) -> Result<(), crate::Error> {
    for (terms, weight) in delta_rel.iter() {
        if layout.matches_tuple(terms) {
            trie.apply_delta(terms, &layout.col_order, weight)?;
        }
    }
    Ok(())
}

fn bind_optional_delta(
    atom: &crate::Atom,
    maybe_delta: Option<&crate::zset::EpistemicZSet<FactKey>>,
    budget: &mut crate::engine::Budget<'_>,
) -> Result<crate::zset::EpistemicZSet<Binding>, crate::Error> {
    if let Some(delta) = maybe_delta
        && !delta.is_empty()
    {
        return bind_atom_zset(atom, delta, budget);
    }
    Ok(crate::zset::EpistemicZSet::new())
}

fn filter_optional_neg(
    atom: &crate::Atom,
    maybe_delta: Option<&crate::zset::EpistemicZSet<FactKey>>,
    budget: &mut crate::engine::Budget<'_>,
) -> Result<crate::zset::EpistemicZSet<FactKey>, crate::Error> {
    if let Some(delta) = maybe_delta
        && !delta.is_empty()
    {
        return filter_neg_atom(atom, delta, budget);
    }
    Ok(crate::zset::EpistemicZSet::new())
}

fn bind_atom_zset(
    atom: &crate::Atom,
    rel: &crate::zset::EpistemicZSet<FactKey>,
    budget: &mut crate::engine::Budget<'_>,
) -> Result<crate::zset::EpistemicZSet<Binding>, crate::Error> {
    let mut out = crate::zset::EpistemicZSet::new();
    for (terms, weight) in rel.iter() {
        charge_budget(budget, 1)?;
        if terms.len() != atom.terms.len() {
            continue;
        }
        if let Some(binding) = unify_atom_terms(atom, terms) {
            out.insert_weight(binding, weight)?;
        }
    }
    Ok(out)
}

fn unify_atom_terms(atom: &crate::Atom, terms: &[mneme_core::Value]) -> Option<Binding> {
    assert!(!atom.predicate.is_empty());
    if atom.terms.len() != terms.len() {
        return None;
    }
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
        })
}

fn filter_neg_atom(
    atom: &crate::Atom,
    rel: &crate::zset::EpistemicZSet<FactKey>,
    budget: &mut crate::engine::Budget<'_>,
) -> Result<crate::zset::EpistemicZSet<FactKey>, crate::Error> {
    let mut out = crate::zset::EpistemicZSet::new();
    for (terms, weight) in rel.iter() {
        charge_budget(budget, 1)?;
        if unify_atom_terms(atom, terms).is_some() {
            out.insert_weight(terms.clone(), weight)?;
        }
    }
    Ok(out)
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

fn update_head_binding_weights(
    index: &mut std::collections::BTreeMap<FactKey, crate::zset::EpistemicZSet<Binding>>,
    terms: &FactKey,
    binding: &Binding,
    weight: crate::zset::EpistemicWeight,
) -> Result<(), crate::Error> {
    let entry = index.entry(terms.clone()).or_default();
    entry.insert_weight(binding.clone(), weight)?;
    if entry.is_empty() {
        index.remove(terms);
    }
    Ok(())
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
    bucket: &crate::zset::EpistemicZSet<Binding>,
) -> Result<Option<(FactKey, crate::EpistemicStatus)>, &'static str> {
    assert!(!head.predicate.is_empty());
    let mut values = Vec::new();
    let mut first_binding: Option<&Binding> = None;
    let mut group_epistemic = crate::EpistemicStatus::Accepted;
    for (binding, weight) in bucket.iter() {
        let total = weight.accepted.saturating_add(weight.proposed);
        if total <= 0 {
            continue;
        }
        if first_binding.is_none() {
            first_binding = Some(binding);
        }
        group_epistemic = group_epistemic.join(weight.effective_status());
        let val = crate::engine::term_value_crate(&agg.input, binding)
            .ok_or("aggregate input is unbound")?;
        let repeat = usize::try_from(total).map_err(|_| "aggregate weight overflow")?;
        values.reserve(repeat);
        for _ in 0..repeat {
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
    Ok(Some((head_terms, group_epistemic)))
}
