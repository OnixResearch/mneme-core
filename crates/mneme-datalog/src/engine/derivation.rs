//! Pure premise instantiation, sequenced valid-time intersection, and bounded
//! DatalogMTL / Allen interval support assembly for [`crate::engine`].

/// Read-only evaluation context needed to instantiate premises and derivations.
pub(super) struct SupportContext<'a> {
    pub context: &'a crate::BuildContext,
    pub facts: &'a std::collections::BTreeMap<String, super::FactStore>,
    pub coverage: &'a std::collections::BTreeMap<String, crate::CoverageStatus>,
    pub participating_vaults: &'a std::collections::BTreeSet<String>,
}

impl SupportContext<'_> {
    fn coverage_status(&self, predicate: &str) -> crate::CoverageStatus {
        self.coverage
            .get(predicate)
            .copied()
            .unwrap_or(crate::CoverageStatus::Unknown)
    }
}

struct LiteralEvalContext<'a> {
    support_ctx: &'a SupportContext<'a>,
    binding: &'a super::Binding,
    max_intervals: u64,
    remaining_steps: u64,
}

struct PremiseSupport {
    sources: std::collections::BTreeSet<crate::SourceKey>,
    roots: std::collections::BTreeSet<mneme_core::RecordId>,
    vaults: std::collections::BTreeSet<String>,
    validity: crate::FactValidity,
    is_interval_truncated: bool,
}

/// Output of evaluating one body literal into premises, validity, and budget steps.
struct LiteralSupportOutput {
    premises: Vec<crate::Premise>,
    sources: std::collections::BTreeSet<crate::SourceKey>,
    roots: std::collections::BTreeSet<mneme_core::RecordId>,
    vaults: std::collections::BTreeSet<String>,
    validity: Option<crate::FactValidity>,
    is_interval_truncated: bool,
    steps: u64,
}

type PremiseIdentity = (
    String,
    Vec<mneme_core::Value>,
    Option<String>,
    std::collections::BTreeSet<String>,
    bool,
);

pub(super) fn instantiated_support(
    rule: &crate::Rule,
    support_ctx: &SupportContext<'_>,
    budget: &mut super::Budget<'_>,
    binding: &super::Binding,
    terms: super::FactKey,
) -> Option<super::FactContents> {
    assert!(!rule.id.is_empty());
    debug_assert_eq!(terms.len(), rule.head.terms.len());
    if !budget.is_active() {
        return None;
    }
    let super::PremiseSet {
        premises,
        sources,
        roots,
        vaults,
        validity,
        is_interval_truncated,
    } = premises_for_binding(rule, support_ctx, budget, binding)?;
    if !budget.is_active() {
        return None;
    }
    if is_interval_truncated {
        budget.support_truncated = true;
    }
    let epistemic = premises
        .iter()
        .fold(crate::EpistemicStatus::ONE, |acc, premise| {
            acc.join(premise.epistemic)
        });
    let temporal_parameters = validity.to_temporal_parameters();
    let support = crate::Derivation {
        rule_id: rule.id.clone(),
        rule_version: support_ctx.context.rule_bundle_version.clone(),
        premises,
        sources: sources.clone(),
        vaults: vaults.clone(),
        temporal_parameters,
        revision: support_ctx.context.served_revision,
        scope: support_ctx.context.scope.clone(),
        truncated: is_interval_truncated,
        epistemic,
    };
    Some(super::FactContents {
        terms,
        support,
        sources,
        canonical: None,
        canonical_roots: roots,
        vaults,
        validity,
        epistemic,
    })
}

pub(super) fn aggregate_support(
    rule: &crate::Rule,
    support_ctx: &SupportContext<'_>,
    budget: &mut super::Budget<'_>,
    bindings: &[super::Binding],
    row: &super::AggregateRow,
) -> Option<super::FactContents> {
    assert!(!rule.id.is_empty());
    debug_assert_eq!(row.head_terms.len(), rule.head.terms.len());
    if !budget.is_active() {
        return None;
    }
    let mut sets = Vec::with_capacity(row.binding_indices.len());
    for index in &row.binding_indices {
        if !budget.is_active() {
            return None;
        }
        let Some(binding) = bindings.get(*index) else {
            continue;
        };
        sets.push(premises_for_binding(rule, support_ctx, budget, binding)?);
    }
    if !budget.is_active() {
        return None;
    }
    let Some(merged) = combine_aggregate_sets(
        sets,
        budget.max_intervals_per_fact,
        budget.remaining_steps(),
    ) else {
        budget.stop(crate::ExecutionStatus::Timeout);
        return None;
    };
    if merged.steps > 0 && !budget.charge(merged.steps) {
        return None;
    }
    if merged.is_interval_truncated {
        budget.support_truncated = true;
    }
    Some(finalize_aggregate_contents(rule, support_ctx, row, merged))
}

struct MergedAggregateSupport {
    premises: Vec<crate::Premise>,
    sources: std::collections::BTreeSet<crate::SourceKey>,
    roots: std::collections::BTreeSet<mneme_core::RecordId>,
    vaults: std::collections::BTreeSet<String>,
    validity: crate::FactValidity,
    epistemic: crate::EpistemicStatus,
    is_interval_truncated: bool,
    steps: u64,
}

fn combine_aggregate_sets(
    sets: Vec<super::PremiseSet>,
    max_intervals: u64,
    remaining_steps: u64,
) -> Option<MergedAggregateSupport> {
    let mut premises = Vec::with_capacity(sets.len());
    let mut seen: std::collections::BTreeSet<PremiseIdentity> = std::collections::BTreeSet::new();
    let mut sources = std::collections::BTreeSet::new();
    let mut roots = std::collections::BTreeSet::new();
    let mut vaults = std::collections::BTreeSet::new();
    let mut validity: Option<crate::FactValidity> = None;
    let mut is_interval_truncated = false;
    let mut epistemic = crate::EpistemicStatus::ONE;
    let mut steps = 0_u64;
    for premise_set in sets {
        sources.extend(premise_set.sources);
        roots.extend(premise_set.roots);
        vaults.extend(premise_set.vaults);
        is_interval_truncated = is_interval_truncated || premise_set.is_interval_truncated;
        validity = match validity {
            None => Some(premise_set.validity),
            Some(current) => {
                let left_steps = remaining_steps.saturating_sub(steps);
                let bounded =
                    current.union_bounded(&premise_set.validity, max_intervals, left_steps)?;
                steps = steps.checked_add(bounded.steps)?;
                is_interval_truncated = is_interval_truncated || bounded.is_truncated;
                Some(bounded.validity)
            }
        };
        let binding_epistemic = premise_set
            .premises
            .iter()
            .fold(crate::EpistemicStatus::ONE, |acc, premise| {
                acc.join(premise.epistemic)
            });
        epistemic = epistemic.join(binding_epistemic);
        for premise in premise_set.premises {
            let key = (
                premise.predicate.clone(),
                premise.terms.clone(),
                premise.vault.clone(),
                premise.vaults.clone(),
                premise.absent,
            );
            if seen.insert(key) {
                premises.push(premise);
            }
        }
    }
    Some(MergedAggregateSupport {
        premises,
        sources,
        roots,
        vaults,
        validity: validity.unwrap_or_else(crate::FactValidity::always),
        epistemic,
        is_interval_truncated,
        steps,
    })
}

fn finalize_aggregate_contents(
    rule: &crate::Rule,
    support_ctx: &SupportContext<'_>,
    row: &super::AggregateRow,
    mut merged: MergedAggregateSupport,
) -> super::FactContents {
    let is_truncated = merged.premises.len() > 64 || merged.is_interval_truncated;
    merged.premises.truncate(64);
    let temporal_parameters = merged.validity.to_temporal_parameters();
    let support = crate::Derivation {
        rule_id: rule.id.clone(),
        rule_version: support_ctx.context.rule_bundle_version.clone(),
        premises: merged.premises,
        sources: merged.sources.clone(),
        vaults: merged.vaults.clone(),
        temporal_parameters,
        revision: support_ctx.context.served_revision,
        scope: support_ctx.context.scope.clone(),
        truncated: is_truncated,
        epistemic: merged.epistemic,
    };
    super::FactContents {
        terms: row.head_terms.clone(),
        support,
        sources: merged.sources,
        canonical: None,
        canonical_roots: merged.roots,
        vaults: merged.vaults,
        validity: merged.validity,
        epistemic: merged.epistemic,
    }
}

fn apply_literal_output(
    mut support: PremiseSupport,
    output: LiteralSupportOutput,
    max_intervals: u64,
    remaining_steps: u64,
) -> Result<Option<(PremiseSupport, Vec<crate::Premise>, u64)>, ()> {
    support.sources.extend(output.sources);
    support.roots.extend(output.roots);
    support.vaults.extend(output.vaults);
    support.is_interval_truncated = support.is_interval_truncated || output.is_interval_truncated;
    let mut extra_steps = 0_u64;
    if let Some(incoming) = output.validity {
        let bounded = support
            .validity
            .intersect_bounded(&incoming, max_intervals, remaining_steps)
            .ok_or(())?;
        if bounded.set.is_empty() {
            return Ok(None);
        }
        extra_steps = bounded.steps;
        support.is_interval_truncated = support.is_interval_truncated || bounded.is_truncated;
        support.validity = crate::FactValidity::Known(bounded.set);
    }
    Ok(Some((support, output.premises, extra_steps)))
}

/// Instantiate every premise a binding relies on.
///
/// A negated literal never has a matching row, so it is recorded as an explicit
/// absence premise together with the relation coverage the rule required.
/// Returns `None` if budget expires, any required positive/temporal premise
/// cannot be resolved, or sequenced valid-time intersection becomes empty.
pub(super) fn premises_for_binding(
    rule: &crate::Rule,
    support_ctx: &SupportContext<'_>,
    budget: &mut super::Budget<'_>,
    binding: &super::Binding,
) -> Option<super::PremiseSet> {
    assert!(!rule.id.is_empty());
    let mut premises = Vec::with_capacity(rule.body.len());
    let mut support = PremiseSupport {
        sources: std::collections::BTreeSet::new(),
        roots: std::collections::BTreeSet::new(),
        vaults: std::collections::BTreeSet::new(),
        validity: crate::FactValidity::always(),
        is_interval_truncated: false,
    };
    let max_intervals = budget.max_intervals_per_fact;
    for literal in &rule.body {
        let base_steps = literal_base_steps(literal);
        if base_steps > 0 && !budget.charge(base_steps) {
            return None;
        }
        let eval_ctx = LiteralEvalContext {
            support_ctx,
            binding,
            max_intervals,
            remaining_steps: budget.remaining_steps(),
        };
        let output = match evaluate_literal_support(literal, &eval_ctx) {
            Ok(Some(output)) => output,
            Ok(None) => return None,
            Err(()) => {
                budget.stop(crate::ExecutionStatus::Timeout);
                return None;
            }
        };
        if output.steps > 0 && !budget.charge(output.steps) {
            return None;
        }
        let (next_support, lit_premises, extra_steps) =
            match apply_literal_output(support, output, max_intervals, budget.remaining_steps()) {
                Ok(Some(merged)) => merged,
                Ok(None) => return None,
                Err(()) => {
                    budget.stop(crate::ExecutionStatus::Timeout);
                    return None;
                }
            };
        if extra_steps > 0 && !budget.charge(extra_steps) {
            return None;
        }
        support = next_support;
        premises.extend(lit_premises);
    }
    if !budget.is_active() {
        return None;
    }
    debug_assert!(premises.len() <= rule.body.len().saturating_mul(2));
    Some(super::PremiseSet {
        premises,
        sources: support.sources,
        roots: support.roots,
        vaults: support.vaults,
        validity: support.validity,
        is_interval_truncated: support.is_interval_truncated,
    })
}

fn literal_base_steps(literal: &crate::Literal) -> u64 {
    if matches!(
        literal,
        crate::Literal::Positive(_)
            | crate::Literal::Negative(_)
            | crate::Literal::DiamondMinus { .. }
            | crate::Literal::BoxMinus { .. }
    ) {
        1
    } else if matches!(
        literal,
        crate::Literal::Since { .. } | crate::Literal::Allen { .. }
    ) {
        2
    } else {
        0
    }
}

fn evaluate_literal_support(
    literal: &crate::Literal,
    ctx: &LiteralEvalContext<'_>,
) -> Result<Option<LiteralSupportOutput>, ()> {
    match literal {
        crate::Literal::Positive(atom) => Ok(positive_literal_support(ctx, atom)),
        crate::Literal::Negative(atom) => Ok(negative_literal_support(ctx, atom)),
        crate::Literal::DiamondMinus {
            atom,
            lower_ns,
            upper_ns,
        } => diamond_minus_literal_support(
            ctx,
            atom,
            mneme_kernel::temporal::MetricWindow {
                lower: *lower_ns,
                upper: *upper_ns,
            },
        ),
        crate::Literal::BoxMinus {
            atom,
            lower_ns,
            upper_ns,
        } => box_minus_literal_support(
            ctx,
            atom,
            mneme_kernel::temporal::MetricWindow {
                lower: *lower_ns,
                upper: *upper_ns,
            },
        ),
        crate::Literal::Since {
            maintained,
            trigger,
            lower_ns,
            upper_ns,
        } => since_literal_support(
            ctx,
            maintained,
            trigger,
            mneme_kernel::temporal::MetricWindow {
                lower: *lower_ns,
                upper: *upper_ns,
            },
        ),
        crate::Literal::Allen {
            relation,
            left,
            right,
        } => allen_literal_support(ctx, *relation, left, right),
        _ => Ok(Some(empty_literal_support())),
    }
}

fn empty_literal_support() -> LiteralSupportOutput {
    LiteralSupportOutput {
        premises: Vec::new(),
        sources: std::collections::BTreeSet::new(),
        roots: std::collections::BTreeSet::new(),
        vaults: std::collections::BTreeSet::new(),
        validity: None,
        is_interval_truncated: false,
        steps: 0,
    }
}

fn resolve_active_fact<'a>(
    support_ctx: &'a SupportContext<'a>,
    atom: &crate::Atom,
    binding: &super::Binding,
) -> Option<(super::FactKey, &'a crate::FactData)> {
    assert!(!atom.predicate.is_empty());
    let terms = atom
        .terms
        .iter()
        .filter_map(|term| super::term_value(term, binding))
        .collect::<Vec<_>>();
    let data = support_ctx
        .facts
        .get(&atom.predicate)
        .and_then(|store| store.rows.get(&terms))
        .filter(|data| data.is_active())?;
    debug_assert!(data.epistemic != crate::EpistemicStatus::Rejected);
    Some((terms, data))
}

fn make_fact_premise(
    predicate: &str,
    terms: super::FactKey,
    data: &crate::FactData,
) -> crate::Premise {
    let vault = if data.vaults.len() == 1 {
        data.vaults.iter().next().cloned()
    } else {
        None
    };
    crate::Premise {
        predicate: predicate.to_owned(),
        terms,
        canonical: data.canonical,
        canonical_roots: data.canonical_roots.clone(),
        sources: data.sources.clone(),
        source_availability: data.supports.first().and_then(|proof| {
            proof
                .premises
                .iter()
                .find_map(|premise| premise.source_availability.clone())
        }),
        vault,
        vaults: data.vaults.clone(),
        absent: false,
        coverage: None,
        epistemic: data.epistemic,
    }
}

fn single_fact_output(
    premise: crate::Premise,
    data: &crate::FactData,
    bounded: crate::temporal::BoundedValidity,
) -> LiteralSupportOutput {
    LiteralSupportOutput {
        premises: vec![premise],
        sources: data.sources.clone(),
        roots: data.canonical_roots.clone(),
        vaults: data.vaults.clone(),
        validity: Some(bounded.validity),
        is_interval_truncated: bounded.is_truncated,
        steps: bounded.steps,
    }
}

fn positive_literal_support(
    ctx: &LiteralEvalContext<'_>,
    atom: &crate::Atom,
) -> Option<LiteralSupportOutput> {
    let (terms, data) = resolve_active_fact(ctx.support_ctx, atom, ctx.binding)?;
    let premise = make_fact_premise(&atom.predicate, terms, data);
    Some(single_fact_output(
        premise,
        data,
        crate::temporal::BoundedValidity {
            validity: data.validity.clone(),
            is_truncated: false,
            steps: 0,
        },
    ))
}

fn diamond_minus_literal_support(
    ctx: &LiteralEvalContext<'_>,
    atom: &crate::Atom,
    window: mneme_kernel::temporal::MetricWindow,
) -> Result<Option<LiteralSupportOutput>, ()> {
    let Some((terms, data)) = resolve_active_fact(ctx.support_ctx, atom, ctx.binding) else {
        return Ok(None);
    };
    let Some(set) = data.validity.as_interval_set() else {
        return Ok(None);
    };
    let bounded = set
        .diamond_minus_bounded(window, ctx.max_intervals, ctx.remaining_steps)
        .ok_or(())?;
    if bounded.set.is_empty() {
        return Ok(None);
    }
    let premise = make_fact_premise(&atom.predicate, terms, data);
    Ok(Some(single_fact_output(
        premise,
        data,
        crate::temporal::BoundedValidity {
            validity: crate::FactValidity::Known(bounded.set),
            is_truncated: bounded.is_truncated,
            steps: bounded.steps,
        },
    )))
}

fn box_minus_literal_support(
    ctx: &LiteralEvalContext<'_>,
    atom: &crate::Atom,
    window: mneme_kernel::temporal::MetricWindow,
) -> Result<Option<LiteralSupportOutput>, ()> {
    let Some((terms, data)) = resolve_active_fact(ctx.support_ctx, atom, ctx.binding) else {
        return Ok(None);
    };
    let Some(set) = data.validity.as_interval_set() else {
        return Ok(None);
    };
    let bounded = set
        .box_minus_bounded(window, ctx.max_intervals, ctx.remaining_steps)
        .ok_or(())?;
    if bounded.set.is_empty() {
        return Ok(None);
    }
    let premise = make_fact_premise(&atom.predicate, terms, data);
    Ok(Some(single_fact_output(
        premise,
        data,
        crate::temporal::BoundedValidity {
            validity: crate::FactValidity::Known(bounded.set),
            is_truncated: bounded.is_truncated,
            steps: bounded.steps,
        },
    )))
}

fn since_literal_support(
    ctx: &LiteralEvalContext<'_>,
    maintained: &crate::Atom,
    trigger: &crate::Atom,
    window: mneme_kernel::temporal::MetricWindow,
) -> Result<Option<LiteralSupportOutput>, ()> {
    let Some((t_terms, t_data)) = resolve_active_fact(ctx.support_ctx, trigger, ctx.binding) else {
        return Ok(None);
    };
    let Some(t_set) = t_data.validity.as_interval_set() else {
        return Ok(None);
    };
    let empty_maintained = crate::IntervalSet::empty();
    let maintained_match = resolve_active_fact(ctx.support_ctx, maintained, ctx.binding);
    let m_set = match &maintained_match {
        Some((_, m_data)) => {
            let Some(set) = m_data.validity.as_interval_set() else {
                return Ok(None);
            };
            set
        }
        None if window.lower == 0 => &empty_maintained,
        None => return Ok(None),
    };
    let bounded = m_set
        .since_bounded(t_set, window, ctx.max_intervals, ctx.remaining_steps)
        .ok_or(())?;
    if bounded.set.is_empty() {
        return Ok(None);
    }
    let mut sources = t_data.sources.clone();
    let mut roots = t_data.canonical_roots.clone();
    let mut vaults = t_data.vaults.clone();
    let mut premises = Vec::with_capacity(2);
    if let Some((m_terms, m_data)) = maintained_match {
        sources.extend(m_data.sources.iter().copied());
        roots.extend(m_data.canonical_roots.iter().copied());
        vaults.extend(m_data.vaults.iter().cloned());
        premises.push(make_fact_premise(&maintained.predicate, m_terms, m_data));
    }
    premises.push(make_fact_premise(&trigger.predicate, t_terms, t_data));
    Ok(Some(LiteralSupportOutput {
        premises,
        sources,
        roots,
        vaults,
        validity: Some(crate::FactValidity::Known(bounded.set)),
        is_interval_truncated: bounded.is_truncated,
        steps: bounded.steps,
    }))
}

fn allen_literal_support(
    ctx: &LiteralEvalContext<'_>,
    relation: mneme_kernel::temporal::AllenRelation,
    left: &crate::Atom,
    right: &crate::Atom,
) -> Result<Option<LiteralSupportOutput>, ()> {
    let Some((l_terms, l_data)) = resolve_active_fact(ctx.support_ctx, left, ctx.binding) else {
        return Ok(None);
    };
    let Some((r_terms, r_data)) = resolve_active_fact(ctx.support_ctx, right, ctx.binding) else {
        return Ok(None);
    };
    let (Some(l_set), Some(r_set)) = (
        l_data.validity.as_interval_set(),
        r_data.validity.as_interval_set(),
    ) else {
        return Ok(None);
    };
    let bounded = l_set
        .allen_bounded(r_set, relation, ctx.max_intervals, ctx.remaining_steps)
        .ok_or(())?;
    if bounded.set.is_empty() {
        return Ok(None);
    }
    let mut sources = l_data.sources.clone();
    sources.extend(r_data.sources.iter().copied());
    let mut roots = l_data.canonical_roots.clone();
    roots.extend(r_data.canonical_roots.iter().copied());
    let mut vaults = l_data.vaults.clone();
    vaults.extend(r_data.vaults.iter().cloned());
    Ok(Some(LiteralSupportOutput {
        premises: vec![
            make_fact_premise(&left.predicate, l_terms, l_data),
            make_fact_premise(&right.predicate, r_terms, r_data),
        ],
        sources,
        roots,
        vaults,
        validity: Some(crate::FactValidity::Known(bounded.set)),
        is_interval_truncated: bounded.is_truncated,
        steps: bounded.steps,
    }))
}

fn negative_literal_support(
    ctx: &LiteralEvalContext<'_>,
    atom: &crate::Atom,
) -> Option<LiteralSupportOutput> {
    let terms = atom
        .terms
        .iter()
        .filter_map(|term| super::term_value(term, ctx.binding))
        .collect::<Vec<_>>();
    let (vault, vaults) = if atom.predicate.starts_with("vault_")
        && let Some(alias) = terms.first().and_then(mneme_core::Value::as_string)
    {
        (
            Some(alias.to_owned()),
            std::collections::BTreeSet::from([alias.to_owned()]),
        )
    } else {
        let single = if ctx.support_ctx.participating_vaults.len() == 1 {
            ctx.support_ctx.participating_vaults.iter().next().cloned()
        } else {
            None
        };
        (single, ctx.support_ctx.participating_vaults.clone())
    };
    assert!(!atom.predicate.is_empty());
    assert!(!vaults.is_empty());
    let premise = crate::Premise {
        predicate: atom.predicate.clone(),
        terms,
        canonical: None,
        canonical_roots: std::collections::BTreeSet::new(),
        sources: std::collections::BTreeSet::new(),
        source_availability: None,
        vault,
        vaults: vaults.clone(),
        absent: true,
        coverage: Some(
            ctx.support_ctx
                .coverage_status(&atom.predicate)
                .name()
                .to_owned(),
        ),
        epistemic: crate::EpistemicStatus::Accepted,
    };
    Some(LiteralSupportOutput {
        premises: vec![premise],
        sources: std::collections::BTreeSet::new(),
        roots: std::collections::BTreeSet::new(),
        vaults,
        validity: None,
        is_interval_truncated: false,
        steps: 0,
    })
}
