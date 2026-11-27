//! Bounded alternating-fixpoint Well-Founded Semantics (Van Gelder) over
//! `{Rejected, Proposed, Accepted}` for [`crate::engine`].
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// Iterates `P_{k+1} = Γ_over(T_k)` and `T_{k+1} = Γ_under(P_{k+1})` until
/// fixpoint within `max_recursion_depth`. Facts active in `T*` keep their
/// `T*` epistemic status; facts active in `P* \ T*` are well-founded undefined
/// and materialized as `EpistemicStatus::Proposed`.
pub(super) fn evaluate_well_founded(evaluation: &mut super::Evaluation<'_>) {
    let base_facts = evaluation.facts.clone();
    let all_rules: Vec<&crate::Rule> = evaluation.bundle.rules.iter().collect();
    if all_rules.is_empty() {
        super::update_derived_coverage(evaluation);
        return;
    }
    let mut strata_all = std::collections::BTreeMap::new();
    strata_all.insert(0_usize, all_rules);
    let max_iters = evaluation.budget.limits.max_recursion_depth.max(1);

    let mut under_facts = base_facts.clone();
    let mut over_facts = base_facts.clone();
    let mut prev_under_sig = active_fact_signature(&under_facts);
    let mut prev_over_sig = std::collections::BTreeMap::new();
    let mut is_converged = false;

    for _ in 0..=max_iters {
        if !evaluation.budget.is_active() {
            break;
        }
        // Over-approximation P = Γ_Kleene(T): only definitely Accepted facts in T block.
        let Some(next_over) = run_positive_pass(
            evaluation,
            &base_facts,
            &under_facts,
            &strata_all,
            crate::NegationSemantics::Kleene,
        ) else {
            break;
        };
        // Under-approximation T = Γ_Strict(P): both Accepted and Proposed facts in P block.
        let Some(next_under) = run_positive_pass(
            evaluation,
            &base_facts,
            &next_over,
            &strata_all,
            crate::NegationSemantics::Strict,
        ) else {
            break;
        };
        let next_over_sig = active_fact_signature(&next_over);
        let next_under_sig = active_fact_signature(&next_under);
        over_facts = next_over;
        under_facts = next_under;
        if next_over_sig == prev_over_sig && next_under_sig == prev_under_sig {
            is_converged = true;
            break;
        }
        prev_over_sig = next_over_sig;
        prev_under_sig = next_under_sig;
    }
    if !is_converged && evaluation.budget.is_active() {
        evaluation.budget.stop(crate::ExecutionStatus::Partial);
    }
    assemble_result(evaluation, under_facts, over_facts);
    update_derived_coverage(evaluation, is_converged);
}

fn update_derived_coverage(evaluation: &mut super::Evaluation<'_>, is_converged: bool) {
    let heads: std::collections::BTreeSet<String> = evaluation
        .bundle
        .rules
        .iter()
        .map(|rule| rule.head.predicate.clone())
        .collect();
    let mut current = evaluation.base_coverage.clone();
    let initial_status =
        if is_converged && evaluation.budget.status == crate::ExecutionStatus::Complete {
            crate::CoverageStatus::Complete
        } else {
            crate::CoverageStatus::Incomplete
        };
    current.extend(heads.iter().map(|head| (head.clone(), initial_status)));
    current.extend(
        evaluation
            .coverage_reasons
            .keys()
            .map(|pred| (pred.clone(), crate::CoverageStatus::Incomplete)),
    );
    let passes = heads.len().saturating_add(2);
    for _ in 0..passes {
        let mut next = current.clone();
        let updates: Vec<(String, crate::CoverageStatus)> = heads
            .iter()
            .map(|head| {
                let status = if evaluation.coverage_reasons.contains_key(head) {
                    crate::CoverageStatus::Incomplete
                } else {
                    super::head_coverage_from(
                        evaluation.bundle,
                        &current,
                        evaluation.budget.status,
                        head,
                    )
                };
                (head.clone(), status)
            })
            .collect();
        next.extend(updates);
        if next == current {
            break;
        }
        current = next;
    }
    evaluation.coverage = current;
}

fn run_positive_pass(
    evaluation: &mut super::Evaluation<'_>,
    base_facts: &std::collections::BTreeMap<String, super::FactStore>,
    oracle: &std::collections::BTreeMap<String, super::FactStore>,
    strata_all: &std::collections::BTreeMap<usize, Vec<&crate::Rule>>,
    negation_semantics: crate::NegationSemantics,
) -> Option<std::collections::BTreeMap<String, super::FactStore>> {
    let mut pass_eval = super::Evaluation {
        bundle: evaluation.bundle,
        context: evaluation.context,
        budget: super::Budget {
            limits: evaluation.budget.limits,
            work: evaluation.budget.work,
            stored_rows: 0,
            start: evaluation.budget.start,
            cancellation: evaluation.budget.cancellation.clone(),
            status: evaluation.budget.status,
            limit_reached: evaluation.budget.limit_reached,
            support_truncated: evaluation.budget.support_truncated,
            max_intervals_per_fact: evaluation.budget.max_intervals_per_fact,
        },
        facts: base_facts.clone(),
        negation_oracle: Some(oracle),
        negation_semantics,
        justifications: crate::JustificationGraph::default(),
        eclasses: crate::egraph::EClassTable::new(),
        egraph_config: evaluation.egraph_config,
        round_deltas: None,
        coverage: evaluation.coverage.clone(),
        base_coverage: evaluation.base_coverage.clone(),
        coverage_reasons: evaluation.coverage_reasons.clone(),
        participating_vaults: evaluation.participating_vaults.clone(),
        at: evaluation.at,
        derivation_eligibility: evaluation.derivation_eligibility.clone(),
        record_contributions: std::collections::BTreeMap::new(),
    };
    for pred in evaluation.bundle.rules.iter().map(|r| &r.head.predicate) {
        pass_eval
            .coverage
            .entry(pred.clone())
            .or_insert(crate::CoverageStatus::Complete);
    }
    super::evaluate_strata(&mut pass_eval, strata_all);
    evaluation.budget.work = pass_eval.budget.work;
    evaluation.budget.status = pass_eval.budget.status;
    evaluation.budget.limit_reached = pass_eval.budget.limit_reached;
    evaluation.budget.support_truncated =
        evaluation.budget.support_truncated || pass_eval.budget.support_truncated;
    if !evaluation.budget.is_active() {
        return None;
    }
    Some(pass_eval.facts)
}

fn active_fact_signature(
    facts: &std::collections::BTreeMap<String, super::FactStore>,
) -> std::collections::BTreeMap<(String, super::FactKey), crate::EpistemicStatus> {
    facts
        .iter()
        .flat_map(|(pred, store)| {
            store
                .rows
                .iter()
                .filter(|&(_, data)| data.is_active())
                .map(move |(key, data)| ((pred.clone(), key.clone()), data.epistemic))
        })
        .collect()
}

fn assemble_result(
    evaluation: &mut super::Evaluation<'_>,
    mut under_facts: std::collections::BTreeMap<String, super::FactStore>,
    over_facts: std::collections::BTreeMap<String, super::FactStore>,
) {
    for (pred, over_store) in over_facts {
        let target_store = under_facts.entry(pred.clone()).or_default();
        for (key, mut over_data) in over_store.rows {
            if !over_data.is_active() {
                continue;
            }
            if target_store
                .rows
                .get(&key)
                .is_some_and(crate::FactData::is_active)
            {
                continue;
            }
            // In P* \ T*: well-founded undefined -> attenuate to Proposed.
            over_data.epistemic = over_data.epistemic.join(crate::EpistemicStatus::Proposed);
            for support in &mut over_data.supports {
                support.epistemic = support.epistemic.join(crate::EpistemicStatus::Proposed);
            }
            target_store.rows.insert(key, over_data);
        }
    }
    evaluation.justifications = crate::JustificationGraph::default();
    for (pred, store) in &under_facts {
        for (key, data) in &store.rows {
            if !data.is_active() {
                continue;
            }
            for support in &data.supports {
                let _ = evaluation
                    .justifications
                    .intern_derivation((pred.clone(), key.clone()), support);
            }
        }
    }
    evaluation.facts = under_facts;
}
