use super::*;

fn test_scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "datalog-unit").expect("valid scope")
}

pub(super) fn rid(tag: u16) -> mneme_core::RecordId {
    let mut bytes = [0_u8; 16];
    let [hi, lo] = tag.to_be_bytes();
    bytes[0] = 0x42;
    bytes[14] = hi;
    bytes[15] = lo;
    mneme_core::RecordId::from_bytes(bytes)
}

pub(super) fn test_context(bundle: &crate::RuleBundle) -> crate::BuildContext {
    crate::BuildContext {
        requested_revision: mneme_core::WorkspaceRevisionId::from_bytes([0x11; 16]),
        served_revision: mneme_core::WorkspaceRevisionId::from_bytes([0x11; 16]),
        scope: test_scope(),
        schema_version: bundle.schema_version,
        rule_bundle_id: bundle.id.clone(),
        rule_bundle_version: bundle.version.clone(),
        projection_build_id: "unit-build".to_owned(),
        eligibility_generation: 1,
        requested_was_head: true,
        vaults: Vec::new(),
    }
}

pub(super) fn base_fact_contents(
    predicate: &str,
    terms: FactKey,
    record_id: mneme_core::RecordId,
    context: &crate::BuildContext,
) -> FactContents {
    let support = crate::Derivation {
        rule_id: "canonical".to_owned(),
        rule_version: "1".to_owned(),
        premises: vec![crate::Premise {
            predicate: predicate.to_owned(),
            terms: Vec::new(),
            canonical: Some(record_id),
            canonical_roots: std::collections::BTreeSet::from([record_id]),
            sources: std::collections::BTreeSet::new(),
            source_availability: None,
            vault: Some(crate::PRIMARY_VAULT_ALIAS.to_owned()),
            vaults: std::collections::BTreeSet::from([crate::PRIMARY_VAULT_ALIAS.to_owned()]),
            absent: false,
            coverage: None,
            epistemic: crate::EpistemicStatus::Accepted,
        }],
        sources: std::collections::BTreeSet::new(),
        vaults: std::collections::BTreeSet::from([crate::PRIMARY_VAULT_ALIAS.to_owned()]),
        temporal_parameters: Vec::new(),
        revision: context.served_revision,
        scope: context.scope.clone(),
        truncated: false,
        epistemic: crate::EpistemicStatus::Accepted,
    };
    FactContents {
        terms,
        support,
        sources: std::collections::BTreeSet::new(),
        canonical: Some(record_id),
        canonical_roots: std::collections::BTreeSet::from([record_id]),
        vaults: std::collections::BTreeSet::from([crate::PRIMARY_VAULT_ALIAS.to_owned()]),
        validity: crate::FactValidity::always(),
        epistemic: crate::EpistemicStatus::Accepted,
    }
}

pub(super) struct EvaluationFixture<'a> {
    pub(super) bundle: &'a crate::RuleBundle,
    pub(super) context: &'a crate::BuildContext,
    pub(super) limits: &'a crate::Limits,
    pub(super) current_sources: &'a AvailabilityMap,
    pub(super) base_facts: &'a [(String, FactKey, mneme_core::RecordId)],
}

pub(super) fn make_evaluation<'a>(fixture: &'a EvaluationFixture<'a>) -> Evaluation<'a> {
    assert!(!fixture.bundle.id.is_empty());
    assert!(fixture.limits.max_supports_per_fact > 0);
    let _ = fixture.current_sources;
    let mut evaluation = Evaluation {
        bundle: fixture.bundle,
        context: fixture.context,
        budget: Budget {
            limits: fixture.limits,
            work: 0,
            stored_rows: 0,
            start: evaluation_start(),
            cancellation: None,
            status: crate::ExecutionStatus::Complete,
            limit_reached: false,
            support_truncated: false,
            max_intervals_per_fact: crate::DEFAULT_MAX_INTERVALS_PER_FACT,
        },
        facts: std::collections::BTreeMap::new(),
        negation_oracle: None,
        negation_semantics: crate::NegationSemantics::default(),
        justifications: crate::JustificationGraph::default(),
        round_deltas: None,
        coverage: std::collections::BTreeMap::new(),
        base_coverage: std::collections::BTreeMap::new(),
        coverage_reasons: std::collections::BTreeMap::new(),
        participating_vaults: std::collections::BTreeSet::from([
            crate::PRIMARY_VAULT_ALIAS.to_owned()
        ]),
        at: None,
        derivation_eligibility: std::collections::BTreeMap::new(),
        record_contributions: std::collections::BTreeMap::new(),
    };
    for predicate in fixture.bundle.base_predicates.keys() {
        evaluation
            .coverage
            .insert(predicate.clone(), crate::CoverageStatus::Complete);
        evaluation
            .base_coverage
            .insert(predicate.clone(), crate::CoverageStatus::Complete);
    }
    for (predicate, terms, record_id) in fixture.base_facts {
        add_fact(
            &mut evaluation,
            predicate,
            base_fact_contents(predicate, terms.clone(), *record_id, fixture.context),
        );
    }
    evaluation
}

// --- Reference binary indexed evaluator (#98 greedy + column indexes) ---

pub(super) fn evaluate_rules_binary(
    evaluation: &mut Evaluation<'_>,
    rule_strata: &std::collections::BTreeMap<String, usize>,
) {
    debug_assert!(!evaluation.bundle.rules.is_empty());
    let mut strata: std::collections::BTreeMap<usize, Vec<&crate::Rule>> =
        std::collections::BTreeMap::new();
    for rule in &evaluation.bundle.rules {
        let stratum = rule_strata.get(&rule.head.predicate).copied().unwrap_or(0);
        strata.entry(stratum).or_default().push(rule);
    }
    for rules in strata.values() {
        let mut rounds = 0_usize;
        loop {
            if !evaluation.budget.is_active() {
                break;
            }
            let mut is_changed = false;
            for rule in rules {
                if evaluate_rule_binary(evaluation, rule) == RuleOutcome::Changed {
                    is_changed = true;
                }
                if !evaluation.budget.is_active() {
                    break;
                }
            }
            rounds = rounds.saturating_add(1);
            if !is_changed || !evaluation.budget.is_active() {
                break;
            }
            if rounds > evaluation.budget.limits.max_recursion_depth {
                evaluation.budget.stop(crate::ExecutionStatus::Partial);
                break;
            }
        }
        update_derived_coverage(evaluation);
    }
    debug_assert!(!strata.is_empty());
}

fn evaluate_rule_binary(evaluation: &mut Evaluation<'_>, rule: &crate::Rule) -> RuleOutcome {
    debug_assert!(!rule.head.predicate.is_empty());
    let Some(body_coverage) = rule_body_coverage(evaluation, rule) else {
        return RuleOutcome::Skipped;
    };
    let aggregate = rule.body.iter().find_map(|literal| {
        if let crate::Literal::Aggregate {
            function,
            input,
            output,
        } = literal
        {
            Some(AggregateSpec {
                function: *function,
                input: input.clone(),
                output: output.clone(),
            })
        } else {
            None
        }
    });
    let has_negative = rule
        .body
        .iter()
        .any(|literal| matches!(literal, crate::Literal::Negative(_)));
    if (aggregate.is_some() || has_negative)
        && !mneme_kernel::admission::non_monotonic_rule_admissible(body_coverage)
    {
        return RuleOutcome::Skipped;
    }
    let bindings = match evaluate_planned_body(evaluation, rule) {
        Ok(bindings) => bindings,
        Err(outcome) => return outcome,
    };
    debug_assert!(!bindings.is_empty());
    if let Some(aggregate) = aggregate {
        return evaluate_aggregate_rule(evaluation, rule, &aggregate, &bindings);
    }
    evaluate_ordinary_rule(evaluation, rule, &bindings)
}

// --- Reference naive evaluator (pre-optimization written-order scan) ---

pub(super) fn evaluate_rules_naive(
    evaluation: &mut Evaluation<'_>,
    rule_strata: &std::collections::BTreeMap<String, usize>,
) {
    let mut strata: std::collections::BTreeMap<usize, Vec<&crate::Rule>> =
        std::collections::BTreeMap::new();
    for rule in &evaluation.bundle.rules {
        let stratum = rule_strata.get(&rule.head.predicate).copied().unwrap_or(0);
        strata.entry(stratum).or_default().push(rule);
    }
    for rules in strata.values() {
        let mut rounds = 0_usize;
        loop {
            if !evaluation.budget.is_active() {
                break;
            }
            let mut is_changed = false;
            for rule in rules {
                if evaluate_rule_naive(evaluation, rule) == RuleOutcome::Changed {
                    is_changed = true;
                }
                if !evaluation.budget.is_active() {
                    break;
                }
            }
            rounds = rounds.saturating_add(1);
            if !is_changed || !evaluation.budget.is_active() {
                break;
            }
            if rounds > evaluation.budget.limits.max_recursion_depth {
                evaluation.budget.stop(crate::ExecutionStatus::Partial);
                break;
            }
        }
        update_derived_coverage(evaluation);
    }
}

fn evaluate_rule_naive(evaluation: &mut Evaluation<'_>, rule: &crate::Rule) -> RuleOutcome {
    let Some(body_coverage) = rule_body_coverage(evaluation, rule) else {
        return RuleOutcome::Skipped;
    };
    let aggregate = rule.body.iter().find_map(|literal| {
        if let crate::Literal::Aggregate {
            function,
            input,
            output,
        } = literal
        {
            Some(AggregateSpec {
                function: *function,
                input: input.clone(),
                output: output.clone(),
            })
        } else {
            None
        }
    });
    let has_negative = rule
        .body
        .iter()
        .any(|literal| matches!(literal, crate::Literal::Negative(_)));
    if (aggregate.is_some() || has_negative)
        && !mneme_kernel::admission::non_monotonic_rule_admissible(body_coverage)
    {
        return RuleOutcome::Skipped;
    }
    let mut bindings = match positive_bindings_naive(evaluation, rule) {
        Ok(bindings) => bindings,
        Err(outcome) => return outcome,
    };
    if let Err(outcome) = filter_nonpositive_literals_naive(evaluation, rule, &mut bindings) {
        return outcome;
    }
    if let Some(aggregate) = aggregate {
        return evaluate_aggregate_rule(evaluation, rule, &aggregate, &bindings);
    }
    evaluate_ordinary_rule(evaluation, rule, &bindings)
}

fn positive_bindings_naive(
    evaluation: &mut Evaluation<'_>,
    rule: &crate::Rule,
) -> Result<RuleBindings, RuleOutcome> {
    let mut bindings = vec![Binding::new()];
    for literal in &rule.body {
        if let crate::Literal::Positive(atom) = literal {
            let Ok(cost) = u64::try_from(bindings.len()) else {
                return Err(RuleOutcome::Skipped);
            };
            if !evaluation.budget.charge(cost) {
                return Err(RuleOutcome::Skipped);
            }
            bindings = join_naive(evaluation, &bindings, atom)?;
            if bindings.is_empty() {
                return Err(RuleOutcome::Stable);
            }
        }
    }
    Ok(bindings)
}

fn filter_nonpositive_literals_naive(
    evaluation: &mut Evaluation<'_>,
    rule: &crate::Rule,
    bindings: &mut RuleBindings,
) -> Result<(), RuleOutcome> {
    for literal in &rule.body {
        if let crate::Literal::Negative(atom) = literal {
            if evaluation.coverage_status(&atom.predicate) != crate::CoverageStatus::Complete {
                return Err(RuleOutcome::Skipped);
            }
            let mut kept = Vec::with_capacity(bindings.len());
            for binding in bindings.drain(..) {
                if !evaluation.budget.charge(1) {
                    return Err(RuleOutcome::Skipped);
                }
                if !matches_atom_naive(evaluation, atom, &binding)? {
                    kept.push(binding);
                }
            }
            *bindings = kept;
            if bindings.is_empty() {
                return Err(RuleOutcome::Stable);
            }
        } else if let crate::Literal::Compare { op, left, right } = literal {
            let mut kept = Vec::with_capacity(bindings.len());
            for binding in bindings.drain(..) {
                if !evaluation.budget.charge(1) {
                    return Err(RuleOutcome::Skipped);
                }
                let is_kept = match (term_value(left, &binding), term_value(right, &binding)) {
                    (Some(left), Some(right)) => compare_values(*op, &left, &right),
                    _ => false,
                };
                if is_kept {
                    kept.push(binding);
                }
            }
            *bindings = kept;
        }
    }
    Ok(())
}

fn join_naive(
    evaluation: &mut Evaluation<'_>,
    bindings: &[Binding],
    atom: &crate::Atom,
) -> Result<RuleBindings, RuleOutcome> {
    let Some(store) = evaluation.facts.get(&atom.predicate) else {
        return Ok(Vec::new());
    };
    let binding_limit = evaluation.budget.limits.max_result_rows;
    let mut output = Vec::with_capacity(bindings.len().min(binding_limit));
    for binding in bindings {
        for (terms, data) in &store.rows {
            if terms.len() != atom.terms.len() {
                continue;
            }
            if !evaluation.budget.charge(1) {
                return Err(RuleOutcome::Skipped);
            }
            if let Some(extended) = unify(atom, terms, binding, data) {
                push_extended_binding(
                    &mut output,
                    extended,
                    binding_limit,
                    &mut evaluation.budget,
                )?;
            }
        }
    }
    Ok(output)
}

fn matches_atom_naive(
    evaluation: &mut Evaluation<'_>,
    atom: &crate::Atom,
    binding: &Binding,
) -> Result<bool, RuleOutcome> {
    let Some(store) = evaluation.facts.get(&atom.predicate) else {
        return Ok(false);
    };
    let mut is_matched = false;
    for (terms, data) in &store.rows {
        if !evaluation.budget.charge(1) {
            return Err(RuleOutcome::Skipped);
        }
        if fact_blocks_negation(data, evaluation.negation_semantics)
            && atom_matches_row(atom, terms, binding)
        {
            is_matched = true;
            break;
        }
    }
    Ok(is_matched)
}

pub(super) fn assert_equivalent_to_naive(
    bundle: &crate::RuleBundle,
    base_facts: &[(String, FactKey, mneme_core::RecordId)],
    limits: &crate::Limits,
) -> (u64, u64) {
    let program = bundle.validate().expect("valid bundle");
    let context = test_context(bundle);
    let current_sources = AvailabilityMap::new();
    let fixture = EvaluationFixture {
        bundle,
        context: &context,
        limits,
        current_sources: &current_sources,
        base_facts,
    };
    let mut naive = make_evaluation(&fixture);
    evaluate_rules_naive(&mut naive, &program.strata);

    let mut planned = make_evaluation(&fixture);
    evaluate_rules(&mut planned, &program.strata);

    assert_eq!(planned.budget.status, naive.budget.status);
    assert_eq!(planned.budget.limit_reached, naive.budget.limit_reached);
    assert_eq!(
        planned.budget.support_truncated,
        naive.budget.support_truncated
    );
    assert_eq!(final_coverage(&planned), final_coverage(&naive));
    assert_eq!(
        planned.facts.keys().collect::<Vec<_>>(),
        naive.facts.keys().collect::<Vec<_>>()
    );
    let recursive_predicates: std::collections::BTreeSet<String> = bundle
        .rules
        .iter()
        .filter(|rule| {
            rule.body.iter().any(|lit| {
                matches!(lit, crate::Literal::Positive(atom) if atom.predicate == rule.head.predicate)
            })
        })
        .map(|rule| rule.head.predicate.clone())
        .collect();
    for (predicate, naive_store) in &naive.facts {
        let planned_store = planned.facts.get(predicate).expect("matching predicate");
        assert_store_rows_equivalent(predicate, planned_store, naive_store, &recursive_predicates);
    }
    (naive.budget.work, planned.budget.work)
}

fn assert_store_rows_equivalent(
    predicate: &str,
    planned_store: &FactStore,
    naive_store: &FactStore,
    recursive_predicates: &std::collections::BTreeSet<String>,
) {
    assert_eq!(planned_store.truncated, naive_store.truncated);
    assert_eq!(
        planned_store.rows.keys().collect::<Vec<_>>(),
        naive_store.rows.keys().collect::<Vec<_>>()
    );
    let is_recursive = recursive_predicates.contains(predicate);
    for (key, naive_data) in &naive_store.rows {
        let planned_data = planned_store.rows.get(key).expect("matching row");
        if is_recursive {
            let normalize = |supports: &[crate::Derivation]| {
                let mut cloned = supports.to_vec();
                for deriv in &mut cloned {
                    for premise in &mut deriv.premises {
                        if recursive_predicates.contains(&premise.predicate) {
                            premise.canonical_roots.clear();
                        }
                    }
                }
                cloned
            };
            assert_eq!(
                normalize(&planned_data.supports),
                normalize(&naive_data.supports)
            );
            if !naive_data.canonical_roots.is_empty() {
                assert!(!planned_data.canonical_roots.is_empty());
            }
            assert!(
                planned_data
                    .canonical_roots
                    .is_subset(&naive_data.canonical_roots)
            );
        } else {
            assert_eq!(planned_data.supports, naive_data.supports);
            assert_eq!(planned_data.canonical_roots, naive_data.canonical_roots);
        }
        assert_eq!(planned_data.sources, naive_data.sources);
        assert_eq!(planned_data.truncated, naive_data.truncated);
        assert_eq!(planned_data.canonical, naive_data.canonical);
        assert_eq!(planned_data.validity, naive_data.validity);
        assert_eq!(planned_data.epistemic, naive_data.epistemic);
    }
}

pub(super) fn atom(predicate: &str, terms: Vec<crate::Term>) -> crate::Atom {
    crate::Atom::new(predicate, terms)
}

pub(super) fn var(name: &str) -> crate::Term {
    crate::Term::var(name)
}

pub(super) fn sym(name: &str) -> crate::Term {
    crate::Term::constant(mneme_core::Value::symbol(name))
}

pub(super) fn int_const(value: i64) -> crate::Term {
    crate::Term::constant(mneme_core::Value::integer(value))
}
