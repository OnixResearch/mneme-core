//! Snapshot fact loading, bounded fixpoint evaluation, and coverage.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use mneme_core::{Lifecycle, RecordEnvelope, RecordId, RecordKind, Reference, ScopeId, Value};
use mneme_memory::{AssertionView, MemoryView};

use crate::{
    AggregateFunction, Atom, BuildRequest, CompareOp, Coverage, CoverageStatus, Derivation,
    ExecutionStatus, FactData, Limits, Literal, Premise, Rule, RuleBundle, RuleProgram, SourceKey,
    Term,
};

type FactKey = Vec<Value>;

#[derive(Clone, Debug, Default)]
pub(crate) struct FactStore {
    pub rows: BTreeMap<FactKey, FactData>,
    pub truncated: bool,
}

pub(crate) struct BuildFacts {
    pub facts: BTreeMap<String, FactStore>,
    pub coverage: Vec<Coverage>,
    pub status: ExecutionStatus,
    pub work: u64,
    pub support_truncated: bool,
}

struct Evaluation<'a> {
    bundle: &'a RuleBundle,
    context: &'a crate::BuildContext,
    limits: &'a Limits,
    facts: BTreeMap<String, FactStore>,
    coverage: BTreeMap<String, CoverageStatus>,
    base_coverage: BTreeMap<String, CoverageStatus>,
    work: u64,
    start: Instant,
    cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    status: ExecutionStatus,
    support_truncated: bool,
}

impl<'a> Evaluation<'a> {
    fn remaining(&self) -> bool {
        self.status == ExecutionStatus::Complete
    }

    fn cancelled(&self) -> bool {
        self.cancellation
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
    }

    fn charge(&mut self, amount: u64) -> bool {
        if self.cancelled() {
            self.status = ExecutionStatus::Cancelled;
            return false;
        }
        self.work = self.work.saturating_add(amount);
        if self.work > self.limits.max_work {
            self.status = ExecutionStatus::Timeout;
            return false;
        }
        if self.start.elapsed()
            > Duration::from_millis(u64::try_from(self.limits.max_time_ms).unwrap_or(u64::MAX))
        {
            self.status = ExecutionStatus::Timeout;
            return false;
        }
        true
    }

    fn relation(&self, predicate: &str) -> Option<&FactStore> {
        self.facts.get(predicate)
    }

    fn coverage_status(&self, predicate: &str) -> CoverageStatus {
        self.coverage
            .get(predicate)
            .copied()
            .unwrap_or(CoverageStatus::Unknown)
    }

    fn add_fact(&mut self, predicate: &str, terms: Vec<Value>, support: Derivation) -> bool {
        let store = self.facts.entry(predicate.to_owned()).or_default();
        if let Some(data) = store.rows.get_mut(&terms) {
            if !data.supports.iter().any(|existing| {
                existing.rule_id == support.rule_id && existing.premises == support.premises
            }) {
                if data.supports.len() >= self.limits.max_supports_per_fact {
                    data.truncated = true;
                    store.truncated = true;
                    self.support_truncated = true;
                } else {
                    data.supports.push(support);
                }
            }
            false
        } else {
            store.rows.insert(
                terms,
                FactData {
                    supports: vec![support],
                    sources: BTreeSet::new(),
                    truncated: false,
                },
            );
            true
        }
    }

    fn add_fact_with_sources(
        &mut self,
        predicate: &str,
        terms: Vec<Value>,
        support: Derivation,
        sources: &BTreeSet<SourceKey>,
    ) -> bool {
        let changed = self.add_fact(predicate, terms.clone(), support);
        if let Some(data) = self
            .facts
            .get_mut(predicate)
            .and_then(|store| store.rows.get_mut(&terms))
        {
            data.sources.extend(sources.iter().copied());
        }
        changed
    }
}

pub(crate) fn build(
    view: &MemoryView,
    request: &BuildRequest,
    context: &crate::BuildContext,
    program: &RuleProgram,
) -> Result<BuildFacts, crate::DatalogError> {
    let mut evaluation = Evaluation {
        bundle: &request.bundle,
        context,
        limits: &request.limits,
        facts: BTreeMap::new(),
        coverage: BTreeMap::new(),
        base_coverage: BTreeMap::new(),
        work: 0,
        start: Instant::now(),
        cancellation: request.cancellation.clone(),
        status: ExecutionStatus::Complete,
        support_truncated: false,
    };
    load_base_facts(
        view,
        &request.scope,
        &mut evaluation,
        &request.incomplete_extents,
    )?;
    evaluate_rules(&mut evaluation, &program.strata)?;
    let coverage = final_coverage(&evaluation);
    let status = if evaluation.status != ExecutionStatus::Complete {
        evaluation.status
    } else if coverage
        .iter()
        .any(|coverage| coverage.status != CoverageStatus::Complete)
    {
        ExecutionStatus::Partial
    } else {
        ExecutionStatus::Complete
    };
    Ok(BuildFacts {
        facts: evaluation.facts,
        coverage,
        status,
        work: evaluation.work,
        support_truncated: evaluation.support_truncated,
    })
}

fn load_base_facts(
    view: &MemoryView,
    scope: &ScopeId,
    evaluation: &mut Evaluation<'_>,
    incomplete_extents: &BTreeSet<String>,
) -> Result<(), crate::DatalogError> {
    let known = [
        "entity",
        "relation",
        "assertion",
        "evidence",
        "document",
        "derivation",
        "source",
    ];
    for predicate in known {
        let status = if incomplete_extents.contains(predicate) {
            CoverageStatus::Incomplete
        } else {
            CoverageStatus::Complete
        };
        evaluation.coverage.insert(predicate.to_owned(), status);
        evaluation
            .base_coverage
            .insert(predicate.to_owned(), status);
    }
    for (predicate, arity) in &evaluation.bundle.base_predicates {
        if !known.contains(&predicate.as_str()) {
            evaluation
                .coverage
                .insert(predicate.clone(), CoverageStatus::Unknown);
            evaluation
                .base_coverage
                .insert(predicate.clone(), CoverageStatus::Unknown);
        } else if incomplete_extents.contains(predicate) {
            evaluation
                .coverage
                .insert(predicate.clone(), CoverageStatus::Incomplete);
            evaluation
                .base_coverage
                .insert(predicate.clone(), CoverageStatus::Incomplete);
        } else {
            evaluation
                .coverage
                .insert(predicate.clone(), CoverageStatus::Complete);
            evaluation
                .base_coverage
                .insert(predicate.clone(), CoverageStatus::Complete);
        }
        let _ = arity;
    }
    for record in &view.snapshot().records {
        if record.scope != *scope {
            continue;
        }
        match record.kind {
            RecordKind::Entity => {
                let entity_type = record
                    .payload
                    .get("entity-type")
                    .and_then(Value::as_symbol)
                    .map(|symbol| Value::symbol(symbol.as_str().to_owned()))
                    .unwrap_or_else(|| Value::symbol("unknown"));
                let label = record
                    .payload
                    .get("label")
                    .and_then(Value::as_string)
                    .map(|label| Value::string(label.to_owned()))
                    .unwrap_or_else(|| Value::string(""));
                evaluation.add_fact_with_sources(
                    "entity",
                    vec![record.record_id.to_value(), entity_type, label],
                    canonical_support(record, evaluation.context, BTreeSet::new()),
                    &BTreeSet::new(),
                );
            }
            RecordKind::Relation => {
                let relation_type = record
                    .payload
                    .get("relation-type")
                    .and_then(Value::as_symbol)
                    .map(|symbol| Value::symbol(symbol.as_str().to_owned()))
                    .unwrap_or_else(|| Value::symbol("unknown"));
                if let (Some(from), Some(to)) = (
                    reference_target(record, "from"),
                    reference_target(record, "to"),
                ) {
                    evaluation.add_fact_with_sources(
                        "relation",
                        vec![relation_type, from.to_value(), to.to_value()],
                        canonical_support(record, evaluation.context, BTreeSet::new()),
                        &BTreeSet::new(),
                    );
                }
            }
            RecordKind::Assertion => {
                if let Ok(assertion) = AssertionView::parse(record.clone())
                    && assertion.lifecycle == Lifecycle::Accepted
                    && view.accepted_decision(&assertion).unwrap_or(false)
                    && view.assertion_has_current_basis(&assertion)
                {
                    let (sources, availability) = assertion_sources(view, &assertion);
                    evaluation.add_fact_with_sources(
                        "assertion",
                        vec![
                            assertion.subject.to_value(),
                            Value::symbol(assertion.predicate.clone()),
                            assertion.value.clone(),
                            assertion.record_id().to_value(),
                        ],
                        canonical_support_with_availability(
                            record,
                            evaluation.context,
                            sources.clone(),
                            availability.clone(),
                        ),
                        &sources,
                    );
                }
            }
            RecordKind::Evidence => {
                if let Ok(evidence) = mneme_memory::EvidenceView::parse(record.clone()) {
                    let sources = match evidence.source_reference {
                        Reference::Pinned {
                            target, revision, ..
                        } => BTreeSet::from([(target, revision)]),
                        _ => BTreeSet::new(),
                    };
                    let availability = sources.iter().next().and_then(|(source, revision)| {
                        view.source_at(*source, *revision)
                            .ok()
                            .map(|source| source.availability.name().to_owned())
                    });
                    evaluation.add_fact_with_sources(
                        "evidence",
                        vec![evidence.assertion.to_value(), evidence.source.to_value()],
                        canonical_support_with_availability(
                            record,
                            evaluation.context,
                            sources.clone(),
                            availability,
                        ),
                        &sources,
                    );
                }
            }
            RecordKind::Document => {
                let entity = reference_target(record, "entity")
                    .map(|entity| entity.to_value())
                    .unwrap_or_else(|| Value::symbol("unbound"));
                let path = record
                    .payload
                    .get("path")
                    .and_then(Value::as_string)
                    .map(|path| Value::string(path.to_owned()))
                    .unwrap_or_else(|| Value::symbol("unpathed"));
                evaluation.add_fact_with_sources(
                    "document",
                    vec![record.record_id.to_value(), entity, path],
                    canonical_support(record, evaluation.context, BTreeSet::new()),
                    &BTreeSet::new(),
                );
            }
            RecordKind::SourceRevision => {
                if let Ok(source) = mneme_memory::SourceView::parse(record.clone()) {
                    let availability = view.source_status(record.record_id).ok().map_or_else(
                        || "unknown".to_owned(),
                        |status| status.availability().name().to_owned(),
                    );
                    let sources = BTreeSet::from([(record.record_id, record.revision_id)]);
                    evaluation.add_fact_with_sources(
                        "source",
                        vec![
                            record.record_id.to_value(),
                            record.revision_id.to_value(),
                            Value::string(availability),
                        ],
                        canonical_support_with_availability(
                            record,
                            evaluation.context,
                            sources.clone(),
                            Some(source.availability.name().to_owned()),
                        ),
                        &sources,
                    );
                }
            }
            RecordKind::Derivation => {
                if let Some(conclusion) = reference_target(record, "conclusion")
                    && let Some(premises) = record.payload.get("premises").and_then(Value::as_set)
                {
                    for premise in premises {
                        if let Ok(reference) =
                            Reference::from_value(premise, &mneme_core::Path::root())
                            && let Some(target) = reference.target()
                        {
                            evaluation.add_fact_with_sources(
                                "derivation",
                                vec![conclusion.to_value(), target.to_value()],
                                canonical_support(record, evaluation.context, BTreeSet::new()),
                                &BTreeSet::new(),
                            );
                        }
                    }
                }
            }
            _ => {}
        }
        if evaluation.status != ExecutionStatus::Complete {
            return Ok(());
        }
        if !evaluation.charge(1) {
            return Ok(());
        }
    }
    Ok(())
}

fn evaluate_rules(
    evaluation: &mut Evaluation<'_>,
    rule_strata: &BTreeMap<String, usize>,
) -> Result<(), crate::DatalogError> {
    let mut strata: BTreeMap<usize, Vec<&Rule>> = BTreeMap::new();
    for rule in &evaluation.bundle.rules {
        let stratum = rule_strata.get(&rule.head.predicate).copied().unwrap_or(0);
        strata.entry(stratum).or_default().push(rule);
    }
    for rules in strata.values() {
        let mut rounds = 0_usize;
        loop {
            if !evaluation.remaining() {
                break;
            }
            let mut changed = false;
            for rule in rules {
                match evaluate_rule(evaluation, rule)? {
                    RuleOutcome::Changed => changed = true,
                    RuleOutcome::Stable => {}
                    RuleOutcome::Skipped => {}
                }
                if !evaluation.remaining() {
                    break;
                }
            }
            rounds += 1;
            let depth_exhausted = rounds > evaluation.limits.max_recursion_depth;
            if !changed || !evaluation.remaining() {
                break;
            }
            if depth_exhausted {
                if evaluation.status == ExecutionStatus::Complete {
                    evaluation.status = ExecutionStatus::Partial;
                }
                break;
            }
        }
        update_derived_coverage(evaluation);
    }
    Ok(())
}

enum RuleOutcome {
    Changed,
    Stable,
    Skipped,
}

fn evaluate_rule(
    evaluation: &mut Evaluation<'_>,
    rule: &Rule,
) -> Result<RuleOutcome, crate::DatalogError> {
    let mut body_complete = true;
    for literal in &rule.body {
        match literal {
            Literal::Positive(atom) | Literal::Negative(atom) => {
                if evaluation.coverage_status(&atom.predicate) != CoverageStatus::Complete {
                    body_complete = false;
                }
            }
            Literal::Aggregate { .. } => {}
            Literal::Forbidden(_) => return Ok(RuleOutcome::Skipped),
            Literal::Compare { .. } => {}
        }
    }
    let aggregate = rule.body.iter().find_map(|literal| match literal {
        Literal::Aggregate {
            function,
            input,
            output,
        } => Some((*function, input.clone(), output.clone())),
        _ => None,
    });
    let has_negative = rule
        .body
        .iter()
        .any(|literal| matches!(literal, Literal::Negative(_)));
    if (aggregate.is_some() || has_negative) && !body_complete {
        return Ok(RuleOutcome::Skipped);
    }
    let mut bindings = vec![BTreeMap::<String, Value>::new()];
    for literal in &rule.body {
        if let Literal::Positive(atom) = literal {
            if !evaluation.charge(u64::try_from(bindings.len()).unwrap_or(u64::MAX)) {
                return Ok(RuleOutcome::Skipped);
            }
            bindings = join(evaluation, &bindings, atom);
            if bindings.is_empty() {
                return Ok(RuleOutcome::Stable);
            }
        }
    }
    for literal in &rule.body {
        match literal {
            Literal::Negative(atom) => {
                if evaluation.coverage_status(&atom.predicate) != CoverageStatus::Complete {
                    return Ok(RuleOutcome::Skipped);
                }
                bindings.retain(|binding| !matches_atom(evaluation, atom, binding));
                if bindings.is_empty() {
                    return Ok(RuleOutcome::Stable);
                }
            }
            Literal::Compare { op, left, right } => {
                bindings.retain(|binding| {
                    let left = term_value(left, binding);
                    let right = term_value(right, binding);
                    match (left, right) {
                        (Some(left), Some(right)) => compare(*op, &left, &right),
                        _ => false,
                    }
                });
            }
            _ => {}
        }
    }
    if let Some((function, input, output)) = aggregate {
        if !body_complete {
            return Ok(RuleOutcome::Skipped);
        }
        let grouped = aggregate_rows(&rule.head, &output, function, &input, &bindings)?;
        let mut changed = false;
        for aggregate_row in grouped {
            let (support, sources) =
                aggregate_support(rule, evaluation, &bindings, &aggregate_row.binding_indices);
            if evaluation.add_fact_with_sources(
                &rule.head.predicate,
                aggregate_row.head_terms,
                support,
                &sources,
            ) {
                changed = true;
            }
        }
        return Ok(if changed {
            RuleOutcome::Changed
        } else {
            RuleOutcome::Stable
        });
    }
    let mut changed = false;
    for binding in &bindings {
        let terms = head_terms(&rule.head, binding)?;
        let (support, sources) = instantiated_support(rule, evaluation, binding);
        if evaluation.add_fact_with_sources(&rule.head.predicate, terms, support, &sources) {
            changed = true;
        }
    }
    Ok(if changed {
        RuleOutcome::Changed
    } else {
        RuleOutcome::Stable
    })
}

fn join(
    evaluation: &Evaluation<'_>,
    bindings: &[BTreeMap<String, Value>],
    atom: &Atom,
) -> Vec<BTreeMap<String, Value>> {
    let Some(store) = evaluation.relation(&atom.predicate) else {
        return Vec::new();
    };
    let mut output = Vec::new();
    for binding in bindings {
        for (terms, data) in &store.rows {
            if terms.len() != atom.terms.len() {
                continue;
            }
            if let Some(extended) = unify(atom, terms, binding, data) {
                output.push(extended);
            }
        }
    }
    output
}

fn matches_atom(
    evaluation: &Evaluation<'_>,
    atom: &Atom,
    binding: &BTreeMap<String, Value>,
) -> bool {
    let Some(store) = evaluation.relation(&atom.predicate) else {
        return false;
    };
    store.rows.keys().any(|terms| {
        terms.len() == atom.terms.len()
            && atom
                .terms
                .iter()
                .zip(terms)
                .all(|(term, value)| match term {
                    Term::Constant(expected) => expected == value,
                    Term::Variable(name) => binding.get(name).is_none_or(|bound| bound == value),
                })
    })
}

fn unify(
    atom: &Atom,
    terms: &[Value],
    binding: &BTreeMap<String, Value>,
    data: &FactData,
) -> Option<BTreeMap<String, Value>> {
    if data.supports.is_empty() {
        return None;
    }
    let mut extended = binding.clone();
    for (term, value) in atom.terms.iter().zip(terms) {
        match term {
            Term::Constant(expected) => {
                if expected != value {
                    return None;
                }
            }
            Term::Variable(name) => {
                if let Some(existing) = extended.get(name) {
                    if existing != value {
                        return None;
                    }
                } else {
                    extended.insert(name.clone(), value.clone());
                }
            }
        }
    }
    Some(extended)
}

fn term_value(term: &Term, binding: &BTreeMap<String, Value>) -> Option<Value> {
    match term {
        Term::Constant(value) => Some(value.clone()),
        Term::Variable(name) => binding.get(name).cloned(),
    }
}

fn compare(op: CompareOp, left: &Value, right: &Value) -> bool {
    match op {
        CompareOp::Eq => left == right,
        CompareOp::Ne => left != right,
        CompareOp::Lt => left < right,
        CompareOp::Le => left <= right,
        CompareOp::Gt => left > right,
        CompareOp::Ge => left >= right,
    }
}

fn head_terms(
    head: &Atom,
    binding: &BTreeMap<String, Value>,
) -> Result<Vec<Value>, crate::DatalogError> {
    head.terms
        .iter()
        .map(|term| {
            term_value(term, binding).ok_or_else(|| {
                crate::DatalogError::Failed("rule head has an unbound variable".to_owned())
            })
        })
        .collect()
}

#[derive(Clone, Debug)]
struct AggregateRow {
    head_terms: Vec<Value>,
    binding_indices: Vec<usize>,
}

fn aggregate_rows(
    head: &Atom,
    output: &str,
    function: AggregateFunction,
    input: &Term,
    bindings: &[BTreeMap<String, Value>],
) -> Result<Vec<AggregateRow>, crate::DatalogError> {
    let group_variables = head
        .terms
        .iter()
        .filter_map(|term| match term {
            Term::Variable(name) if name != output => Some(name.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let mut groups: BTreeMap<Vec<Value>, (Vec<usize>, Vec<Value>)> = BTreeMap::new();
    for (index, binding) in bindings.iter().enumerate() {
        let key = group_variables
            .iter()
            .map(|name| {
                binding.get(name).cloned().ok_or_else(|| {
                    crate::DatalogError::Failed("aggregate group variable is unbound".to_owned())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let value = term_value(input, binding)
            .ok_or_else(|| crate::DatalogError::Failed("aggregate input is unbound".to_owned()))?;
        let entry = groups.entry(key).or_default();
        entry.0.push(index);
        entry.1.push(value);
    }
    let mut output_rows = Vec::new();
    for (_, (indices, values)) in groups {
        let value = match function {
            AggregateFunction::Count => {
                Value::integer(i64::try_from(values.len()).unwrap_or(i64::MAX))
            }
            AggregateFunction::Sum => {
                let mut total = 0_u64;
                for value in &values {
                    let Some(integer) = value.as_integer().and_then(|integer| integer.to_i64())
                    else {
                        return Err(crate::DatalogError::Failed(
                            "sum aggregate requires integer values".to_owned(),
                        ));
                    };
                    let integer = u64::try_from(integer).map_err(|_| {
                        crate::DatalogError::Failed(
                            "sum aggregate requires non-negative values".to_owned(),
                        )
                    })?;
                    total = total.saturating_add(integer);
                }
                Value::integer(total)
            }
            AggregateFunction::Min => values
                .into_iter()
                .min()
                .unwrap_or_else(|| Value::integer(0)),
            AggregateFunction::Max => values
                .into_iter()
                .max()
                .unwrap_or_else(|| Value::integer(0)),
        };
        let Some(first) = indices.first().and_then(|index| bindings.get(*index)) else {
            continue;
        };
        let head_terms = head
            .terms
            .iter()
            .map(|term| match term {
                Term::Constant(value) => Some(value.clone()),
                Term::Variable(name) if name == output => Some(value.clone()),
                Term::Variable(name) => first.get(name).cloned(),
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                crate::DatalogError::Failed("aggregate head variable is unbound".to_owned())
            })?;
        output_rows.push(AggregateRow {
            head_terms,
            binding_indices: indices,
        });
    }
    Ok(output_rows)
}

fn instantiated_support(
    rule: &Rule,
    evaluation: &Evaluation<'_>,
    binding: &BTreeMap<String, Value>,
) -> (Derivation, BTreeSet<SourceKey>) {
    let (premises, sources) = premises_for_binding(rule, evaluation, binding);
    let support = Derivation {
        rule_id: rule.id.clone(),
        rule_version: evaluation.context.rule_bundle_version.clone(),
        premises: premises.clone(),
        sources: sources.clone(),
        temporal_parameters: Vec::new(),
        revision: evaluation.context.served_revision,
        scope: evaluation.context.scope.clone(),
        truncated: false,
    };
    (support, sources)
}

fn aggregate_support(
    rule: &Rule,
    evaluation: &Evaluation<'_>,
    bindings: &[BTreeMap<String, Value>],
    indices: &[usize],
) -> (Derivation, BTreeSet<SourceKey>) {
    let mut premises = Vec::new();
    let mut sources = BTreeSet::new();
    for index in indices {
        if let Some(binding) = bindings.get(*index) {
            let (binding_premises, binding_sources) =
                premises_for_binding(rule, evaluation, binding);
            sources.extend(binding_sources);
            for premise in binding_premises {
                if !premises.contains(&premise) {
                    premises.push(premise);
                }
            }
        }
    }
    let truncated = premises.len() > 64;
    premises.truncate(64);
    let support = Derivation {
        rule_id: rule.id.clone(),
        rule_version: evaluation.context.rule_bundle_version.clone(),
        premises,
        sources: sources.clone(),
        temporal_parameters: Vec::new(),
        revision: evaluation.context.served_revision,
        scope: evaluation.context.scope.clone(),
        truncated,
    };
    (support, sources)
}

fn premises_for_binding(
    rule: &Rule,
    evaluation: &Evaluation<'_>,
    binding: &BTreeMap<String, Value>,
) -> (Vec<Premise>, BTreeSet<SourceKey>) {
    let mut premises = Vec::new();
    let mut sources = BTreeSet::new();
    for literal in &rule.body {
        match literal {
            Literal::Positive(atom) | Literal::Negative(atom) => {
                if let Some(store) = evaluation.relation(&atom.predicate) {
                    let terms = atom
                        .terms
                        .iter()
                        .filter_map(|term| term_value(term, binding))
                        .collect::<Vec<_>>();
                    if let Some(data) = store.rows.get(&terms) {
                        sources.extend(data.sources.iter().copied());
                        premises.push(Premise {
                            predicate: atom.predicate.clone(),
                            terms,
                            canonical: data
                                .supports
                                .first()
                                .and_then(|support| support.premises.first())
                                .and_then(|premise| premise.canonical),
                            sources: data.sources.clone(),
                            source_availability: data.supports.first().and_then(|support| {
                                support
                                    .premises
                                    .iter()
                                    .find_map(|premise| premise.source_availability.clone())
                            }),
                        });
                    }
                }
            }
            _ => {}
        }
    }
    (premises, sources)
}

fn canonical_support(
    record: &RecordEnvelope,
    context: &crate::BuildContext,
    sources: BTreeSet<SourceKey>,
) -> Derivation {
    canonical_support_with_availability(record, context, sources, None)
}

fn canonical_support_with_availability(
    record: &RecordEnvelope,
    context: &crate::BuildContext,
    sources: BTreeSet<SourceKey>,
    availability: Option<String>,
) -> Derivation {
    Derivation {
        rule_id: "canonical".to_owned(),
        rule_version: "1".to_owned(),
        premises: vec![Premise {
            predicate: record.kind.symbol().to_owned(),
            terms: Vec::new(),
            canonical: Some(record.record_id),
            sources: sources.clone(),
            source_availability: availability,
        }],
        sources,
        temporal_parameters: Vec::new(),
        revision: context.served_revision,
        scope: context.scope.clone(),
        truncated: false,
    }
}

fn assertion_sources(
    view: &MemoryView,
    assertion: &AssertionView,
) -> (BTreeSet<SourceKey>, Option<String>) {
    let mut sources = BTreeSet::new();
    let mut availability = None;
    for evidence in &assertion.evidence {
        if let Ok(evidence) = view.evidence(*evidence) {
            if view
                .suppression_for(&evidence.record)
                .is_some_and(|suppression| {
                    suppression.mode == mneme_store::SuppressionMode::Withdrawn
                        || suppression.mode == mneme_store::SuppressionMode::Forgotten
                })
            {
                continue;
            }
            if let Ok(roots) = view.evidence_roots(evidence.record.record_id) {
                sources.extend(roots);
            }
            if let Ok(source) = view.evidence_source(&evidence)
                && source.availability != mneme_memory::SourceAvailability::Retained
            {
                availability.get_or_insert_with(|| source.availability.name().to_owned());
            }
        }
    }
    (sources, availability)
}

fn reference_target(record: &RecordEnvelope, name: &str) -> Option<RecordId> {
    record
        .payload
        .get(name)
        .and_then(|value| Reference::from_value(value, &mneme_core::Path::root()).ok())
        .and_then(|reference| reference.target())
}

fn update_derived_coverage(evaluation: &mut Evaluation<'_>) {
    let heads = evaluation
        .bundle
        .rules
        .iter()
        .map(|rule| rule.head.predicate.clone())
        .collect::<BTreeSet<_>>();
    loop {
        let mut changed = false;
        let mut next = evaluation.base_coverage.clone();
        for head in &heads {
            let rules = evaluation
                .bundle
                .rules
                .iter()
                .filter(|rule| &rule.head.predicate == head)
                .collect::<Vec<_>>();
            let mut all_complete = !rules.is_empty();
            let mut any_incomplete = false;
            let mut has_seed = false;
            for rule in rules {
                let has_self = rule.body.iter().any(
                    |literal| matches!(literal, Literal::Positive(atom) if &atom.predicate == head),
                );
                if !has_self {
                    has_seed = true;
                }
                let body_complete = evaluation.status == ExecutionStatus::Complete
                    && rule.body.iter().all(|literal| match literal {
                        Literal::Positive(atom) | Literal::Negative(atom) => {
                            if matches!(literal, Literal::Positive(_)) && &atom.predicate == head {
                                return true;
                            }
                            evaluation.coverage_status(&atom.predicate) == CoverageStatus::Complete
                        }
                        Literal::Forbidden(_) => false,
                        Literal::Aggregate { .. } | Literal::Compare { .. } => true,
                    });
                if body_complete {
                    continue;
                }
                all_complete = false;
                any_incomplete = true;
            }
            let status = if all_complete && has_seed {
                CoverageStatus::Complete
            } else if any_incomplete {
                CoverageStatus::Incomplete
            } else {
                CoverageStatus::Unknown
            };
            next.insert(head.clone(), status);
        }
        if next != evaluation.coverage {
            evaluation.coverage = next;
            changed = true;
        }
        if !changed {
            break;
        }
    }
}

fn final_coverage(evaluation: &Evaluation<'_>) -> Vec<Coverage> {
    let mut predicates = BTreeSet::new();
    predicates.extend(evaluation.facts.keys().cloned());
    predicates.extend(evaluation.coverage.keys().cloned());
    predicates
        .into_iter()
        .map(|predicate| {
            let status = evaluation.coverage_status(&predicate);
            Coverage {
                predicate,
                status,
                reason: match status {
                    CoverageStatus::Complete => None,
                    CoverageStatus::Incomplete => {
                        Some("declared extent or dependency is incomplete".to_owned())
                    }
                    CoverageStatus::Unknown => Some("predicate coverage is unknown".to_owned()),
                },
            }
        })
        .collect()
}
