//! Snapshot fact loading, bounded fixpoint evaluation, and coverage.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

type FactKey = Vec<mneme_core::Value>;

#[derive(Clone, Debug, Default)]
pub(crate) struct FactStore {
    pub rows: std::collections::BTreeMap<FactKey, crate::FactData>,
    pub truncated: bool,
}

pub(crate) struct BuildFacts {
    pub facts: std::collections::BTreeMap<String, FactStore>,
    pub coverage: Vec<crate::Coverage>,
    pub status: crate::ExecutionStatus,
    pub work: u64,
    pub support_truncated: bool,
}

struct Evaluation<'a> {
    bundle: &'a crate::RuleBundle,
    context: &'a crate::BuildContext,
    limits: &'a crate::Limits,
    facts: std::collections::BTreeMap<String, FactStore>,
    coverage: std::collections::BTreeMap<String, crate::CoverageStatus>,
    base_coverage: std::collections::BTreeMap<String, crate::CoverageStatus>,
    work: u64,
    start: std::time::Instant,
    cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    status: crate::ExecutionStatus,
    support_truncated: bool,
}

impl<'a> Evaluation<'a> {
    fn remaining(&self) -> bool {
        self.status == crate::ExecutionStatus::Complete
    }

    fn cancelled(&self) -> bool {
        self.cancellation
            .as_ref()
            .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed))
    }

    #[allow(unknown_lints, ambient_clock)] // wall-clock budget is the evaluation shell
    fn charge(&mut self, amount: u64) -> bool {
        if self.cancelled() {
            self.status = crate::ExecutionStatus::Cancelled;
            return false;
        }
        self.work = self.work.saturating_add(amount);
        if self.work > self.limits.max_work {
            self.status = crate::ExecutionStatus::Timeout;
            return false;
        }
        let Ok(max_time_ms) = u64::try_from(self.limits.max_time_ms) else {
            self.status = crate::ExecutionStatus::Timeout;
            return false;
        };
        if self.start.elapsed() > std::time::Duration::from_millis(max_time_ms) {
            self.status = crate::ExecutionStatus::Timeout;
            return false;
        }
        true
    }

    fn relation(&self, predicate: &str) -> Option<&FactStore> {
        self.facts.get(predicate)
    }

    fn coverage_status(&self, predicate: &str) -> crate::CoverageStatus {
        self.coverage
            .get(predicate)
            .copied()
            .unwrap_or(crate::CoverageStatus::Unknown)
    }

    fn add_fact(
        &mut self,
        predicate: &str,
        terms: Vec<mneme_core::Value>,
        support: crate::Derivation,
    ) -> bool {
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
                crate::FactData {
                    supports: vec![support],
                    sources: std::collections::BTreeSet::new(),
                    truncated: false,
                },
            );
            true
        }
    }

    fn add_fact_with_sources(
        &mut self,
        predicate: &str,
        terms: Vec<mneme_core::Value>,
        support: crate::Derivation,
        sources: &std::collections::BTreeSet<crate::SourceKey>,
    ) -> bool {
        let is_changed = self.add_fact(predicate, terms.clone(), support);
        if let Some(data) = self
            .facts
            .get_mut(predicate)
            .and_then(|store| store.rows.get_mut(&terms))
        {
            data.sources.extend(sources.iter().copied());
        }
        is_changed
    }
}

#[allow(unknown_lints, ambient_clock)] // one evaluation start time for the bounded build
pub(crate) fn build(
    view: &mneme_memory::View,
    request: &crate::BuildRequest,
    context: &crate::BuildContext,
    program: &crate::RuleProgram,
) -> Result<BuildFacts, crate::Error> {
    let mut evaluation = Evaluation {
        bundle: &request.bundle,
        context,
        limits: &request.limits,
        facts: std::collections::BTreeMap::new(),
        coverage: std::collections::BTreeMap::new(),
        base_coverage: std::collections::BTreeMap::new(),
        work: 0,
        start: std::time::Instant::now(),
        cancellation: request.cancellation.clone(),
        status: crate::ExecutionStatus::Complete,
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
    let status = if evaluation.status != crate::ExecutionStatus::Complete {
        evaluation.status
    } else if coverage
        .iter()
        .any(|coverage| coverage.status != crate::CoverageStatus::Complete)
    {
        crate::ExecutionStatus::Partial
    } else {
        crate::ExecutionStatus::Complete
    };
    Ok(BuildFacts {
        facts: evaluation.facts,
        coverage,
        status,
        work: evaluation.work,
        support_truncated: evaluation.support_truncated,
    })
}

#[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
fn load_base_facts(
    view: &mneme_memory::View,
    scope: &mneme_core::ScopeId,
    evaluation: &mut Evaluation<'_>,
    incomplete_extents: &std::collections::BTreeSet<String>,
) -> Result<(), crate::Error> {
    initialize_base_coverage(evaluation, incomplete_extents);
    for record in &view.snapshot().records {
        if record.scope != *scope {
            continue;
        }
        load_record_facts(view, record, evaluation);
        if evaluation.status != crate::ExecutionStatus::Complete {
            return Ok(());
        }
        if !evaluation.charge(1) {
            return Ok(());
        }
    }
    Ok(())
}

fn initialize_base_coverage(
    evaluation: &mut Evaluation<'_>,
    incomplete_extents: &std::collections::BTreeSet<String>,
) {
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
            crate::CoverageStatus::Incomplete
        } else {
            crate::CoverageStatus::Complete
        };
        evaluation.coverage.insert(predicate.to_owned(), status);
        evaluation
            .base_coverage
            .insert(predicate.to_owned(), status);
    }
    for (predicate, arity) in &evaluation.bundle.base_predicates {
        let status = if !known.contains(&predicate.as_str()) {
            crate::CoverageStatus::Unknown
        } else if incomplete_extents.contains(predicate) {
            crate::CoverageStatus::Incomplete
        } else {
            crate::CoverageStatus::Complete
        };
        evaluation.coverage.insert(predicate.clone(), status);
        evaluation.base_coverage.insert(predicate.clone(), status);
        let _ = arity;
    }
}

fn load_record_facts(
    view: &mneme_memory::View,
    record: &mneme_core::RecordEnvelope,
    evaluation: &mut Evaluation<'_>,
) {
    match record.kind {
        mneme_core::RecordKind::Entity => load_entity_fact(record, evaluation),
        mneme_core::RecordKind::Relation => load_relation_fact(record, evaluation),
        mneme_core::RecordKind::Assertion => load_assertion_fact(view, record, evaluation),
        mneme_core::RecordKind::Evidence => load_evidence_fact(view, record, evaluation),
        mneme_core::RecordKind::Document => load_document_fact(record, evaluation),
        mneme_core::RecordKind::SourceRevision => load_source_fact(view, record, evaluation),
        mneme_core::RecordKind::Derivation => load_derivation_facts(record, evaluation),
        _ => {}
    }
}

fn load_entity_fact(record: &mneme_core::RecordEnvelope, evaluation: &mut Evaluation<'_>) {
    let entity_type = record
        .payload
        .get("entity-type")
        .and_then(mneme_core::Value::as_symbol)
        .map(|symbol| mneme_core::Value::symbol(symbol.as_str().to_owned()))
        .unwrap_or_else(|| mneme_core::Value::symbol("unknown"));
    let label = record
        .payload
        .get("label")
        .and_then(mneme_core::Value::as_string)
        .map(|label| mneme_core::Value::string(label.to_owned()))
        .unwrap_or_else(|| mneme_core::Value::string(""));
    evaluation.add_fact_with_sources(
        "entity",
        vec![record.record_id.to_value(), entity_type, label],
        canonical_support(
            record,
            evaluation.context,
            std::collections::BTreeSet::new(),
        ),
        &std::collections::BTreeSet::new(),
    );
}

fn load_relation_fact(record: &mneme_core::RecordEnvelope, evaluation: &mut Evaluation<'_>) {
    let relation_type = record
        .payload
        .get("relation-type")
        .and_then(mneme_core::Value::as_symbol)
        .map(|symbol| mneme_core::Value::symbol(symbol.as_str().to_owned()))
        .unwrap_or_else(|| mneme_core::Value::symbol("unknown"));
    if let (Some(from), Some(to)) = (
        reference_target(record, "from"),
        reference_target(record, "to"),
    ) {
        evaluation.add_fact_with_sources(
            "relation",
            vec![relation_type, from.to_value(), to.to_value()],
            canonical_support(
                record,
                evaluation.context,
                std::collections::BTreeSet::new(),
            ),
            &std::collections::BTreeSet::new(),
        );
    }
}

fn load_assertion_fact(
    view: &mneme_memory::View,
    record: &mneme_core::RecordEnvelope,
    evaluation: &mut Evaluation<'_>,
) {
    if let Ok(assertion) = mneme_memory::AssertionView::parse(record.clone())
        && assertion.lifecycle == mneme_core::Lifecycle::Accepted
        && view.accepted_decision(&assertion).unwrap_or(false)
        && view.assertion_has_current_basis(&assertion)
    {
        let (sources, availability) = assertion_sources(view, &assertion);
        evaluation.add_fact_with_sources(
            "assertion",
            vec![
                assertion.subject.to_value(),
                mneme_core::Value::symbol(assertion.predicate.clone()),
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

fn load_evidence_fact(
    view: &mneme_memory::View,
    record: &mneme_core::RecordEnvelope,
    evaluation: &mut Evaluation<'_>,
) {
    if let Ok(evidence) = mneme_memory::EvidenceView::parse(record.clone()) {
        let sources = match evidence.source_reference {
            mneme_core::Reference::Pinned {
                target, revision, ..
            } => std::collections::BTreeSet::from([(target, revision)]),
            _ => std::collections::BTreeSet::new(),
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

fn load_document_fact(record: &mneme_core::RecordEnvelope, evaluation: &mut Evaluation<'_>) {
    let entity = reference_target(record, "entity")
        .map(|entity| entity.to_value())
        .unwrap_or_else(|| mneme_core::Value::symbol("unbound"));
    let path = record
        .payload
        .get("path")
        .and_then(mneme_core::Value::as_string)
        .map(|path| mneme_core::Value::string(path.to_owned()))
        .unwrap_or_else(|| mneme_core::Value::symbol("unpathed"));
    evaluation.add_fact_with_sources(
        "document",
        vec![record.record_id.to_value(), entity, path],
        canonical_support(
            record,
            evaluation.context,
            std::collections::BTreeSet::new(),
        ),
        &std::collections::BTreeSet::new(),
    );
}

fn load_source_fact(
    view: &mneme_memory::View,
    record: &mneme_core::RecordEnvelope,
    evaluation: &mut Evaluation<'_>,
) {
    if let Ok(source) = mneme_memory::SourceView::parse(record.clone()) {
        let availability = view.source_status(record.record_id).ok().map_or_else(
            || "unknown".to_owned(),
            |status| status.availability().name().to_owned(),
        );
        let sources = std::collections::BTreeSet::from([(record.record_id, record.revision_id)]);
        evaluation.add_fact_with_sources(
            "source",
            vec![
                record.record_id.to_value(),
                record.revision_id.to_value(),
                mneme_core::Value::string(availability),
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

fn load_derivation_facts(record: &mneme_core::RecordEnvelope, evaluation: &mut Evaluation<'_>) {
    if let Some(conclusion) = reference_target(record, "conclusion")
        && let Some(premises) = record
            .payload
            .get("premises")
            .and_then(mneme_core::Value::as_set)
    {
        for premise in premises {
            if let Ok(reference) =
                mneme_core::Reference::from_value(premise, &mneme_core::Path::root())
                && let Some(target) = reference.target()
            {
                evaluation.add_fact_with_sources(
                    "derivation",
                    vec![conclusion.to_value(), target.to_value()],
                    canonical_support(
                        record,
                        evaluation.context,
                        std::collections::BTreeSet::new(),
                    ),
                    &std::collections::BTreeSet::new(),
                );
            }
        }
    }
}

fn evaluate_rules(
    evaluation: &mut Evaluation<'_>,
    rule_strata: &std::collections::BTreeMap<String, usize>,
) -> Result<(), crate::Error> {
    let mut strata: std::collections::BTreeMap<usize, Vec<&crate::Rule>> =
        std::collections::BTreeMap::new();
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
            let mut is_changed = false;
            for rule in rules {
                match evaluate_rule(evaluation, rule)? {
                    RuleOutcome::Changed => is_changed = true,
                    RuleOutcome::Stable => {}
                    RuleOutcome::Skipped => {}
                }
                if !evaluation.remaining() {
                    break;
                }
            }
            rounds += 1;
            let is_depth_exhausted = rounds > evaluation.limits.max_recursion_depth;
            if !is_changed || !evaluation.remaining() {
                break;
            }
            if is_depth_exhausted {
                if evaluation.status == crate::ExecutionStatus::Complete {
                    evaluation.status = crate::ExecutionStatus::Partial;
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

struct AggregateSpec {
    function: crate::AggregateFunction,
    input: crate::Term,
    output: String,
}

#[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
fn evaluate_rule(
    evaluation: &mut Evaluation<'_>,
    rule: &crate::Rule,
) -> Result<RuleOutcome, crate::Error> {
    let Some(is_body_complete) = body_is_complete(evaluation, rule) else {
        return Ok(RuleOutcome::Skipped);
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
    if (aggregate.is_some() || has_negative) && !is_body_complete {
        return Ok(RuleOutcome::Skipped);
    }
    let mut bindings = match positive_bindings(evaluation, rule) {
        Ok(bindings) => bindings,
        Err(outcome) => return Ok(outcome),
    };
    if let Err(outcome) = filter_nonpositive_literals(evaluation, rule, &mut bindings) {
        return Ok(outcome);
    }
    if let Some(aggregate) = aggregate {
        return evaluate_aggregate_rule(evaluation, rule, aggregate, &bindings);
    }
    evaluate_ordinary_rule(evaluation, rule, &bindings)
}

type RuleBindings = Vec<std::collections::BTreeMap<String, mneme_core::Value>>;

fn body_is_complete(evaluation: &Evaluation<'_>, rule: &crate::Rule) -> Option<bool> {
    let mut is_body_complete = true;
    for literal in &rule.body {
        match literal {
            crate::Literal::Positive(atom) | crate::Literal::Negative(atom) => {
                if evaluation.coverage_status(&atom.predicate) != crate::CoverageStatus::Complete {
                    is_body_complete = false;
                }
            }
            crate::Literal::Aggregate { .. } => {}
            crate::Literal::Forbidden(_) => return None,
            crate::Literal::Compare { .. } => {}
        }
    }
    Some(is_body_complete)
}

fn positive_bindings(
    evaluation: &mut Evaluation<'_>,
    rule: &crate::Rule,
) -> Result<RuleBindings, RuleOutcome> {
    let mut bindings = vec![std::collections::BTreeMap::<String, mneme_core::Value>::new()];
    for literal in &rule.body {
        if let crate::Literal::Positive(atom) = literal {
            if !evaluation.charge(bindings.len() as u64) {
                return Err(RuleOutcome::Skipped);
            }
            bindings = join(evaluation, &bindings, atom);
            if bindings.is_empty() {
                return Err(RuleOutcome::Stable);
            }
        }
    }
    Ok(bindings)
}

fn filter_nonpositive_literals(
    evaluation: &Evaluation<'_>,
    rule: &crate::Rule,
    bindings: &mut RuleBindings,
) -> Result<(), RuleOutcome> {
    for literal in &rule.body {
        match literal {
            crate::Literal::Negative(atom) => {
                if evaluation.coverage_status(&atom.predicate) != crate::CoverageStatus::Complete {
                    return Err(RuleOutcome::Skipped);
                }
                bindings.retain(|binding| !matches_atom(evaluation, atom, binding));
                if bindings.is_empty() {
                    return Err(RuleOutcome::Stable);
                }
            }
            crate::Literal::Compare { op, left, right } => {
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
    Ok(())
}

fn evaluate_aggregate_rule(
    evaluation: &mut Evaluation<'_>,
    rule: &crate::Rule,
    aggregate: AggregateSpec,
    bindings: &RuleBindings,
) -> Result<RuleOutcome, crate::Error> {
    let grouped = aggregate_rows(
        &rule.head,
        &aggregate.output,
        aggregate.function,
        &aggregate.input,
        bindings,
    )?;
    let mut is_changed = false;
    for aggregate_row in grouped {
        let (support, sources) =
            aggregate_support(rule, evaluation, bindings, &aggregate_row.binding_indices);
        if evaluation.add_fact_with_sources(
            &rule.head.predicate,
            aggregate_row.head_terms,
            support,
            &sources,
        ) {
            is_changed = true;
        }
    }
    Ok(if is_changed {
        RuleOutcome::Changed
    } else {
        RuleOutcome::Stable
    })
}

fn evaluate_ordinary_rule(
    evaluation: &mut Evaluation<'_>,
    rule: &crate::Rule,
    bindings: &RuleBindings,
) -> Result<RuleOutcome, crate::Error> {
    let mut is_changed = false;
    for binding in bindings {
        let terms = head_terms(&rule.head, binding)?;
        let (support, sources) = instantiated_support(rule, evaluation, binding);
        if evaluation.add_fact_with_sources(&rule.head.predicate, terms, support, &sources) {
            is_changed = true;
        }
    }
    Ok(if is_changed {
        RuleOutcome::Changed
    } else {
        RuleOutcome::Stable
    })
}

fn join(
    evaluation: &Evaluation<'_>,
    bindings: &[std::collections::BTreeMap<String, mneme_core::Value>],
    atom: &crate::Atom,
) -> Vec<std::collections::BTreeMap<String, mneme_core::Value>> {
    let Some(store) = evaluation.relation(&atom.predicate) else {
        return Vec::new();
    };
    let mut output = Vec::with_capacity(store.rows.len());
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
    atom: &crate::Atom,
    binding: &std::collections::BTreeMap<String, mneme_core::Value>,
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
                    crate::Term::Constant(expected) => expected == value,
                    crate::Term::Variable(name) => {
                        binding.get(name).is_none_or(|bound| bound == value)
                    }
                })
    })
}

fn unify(
    atom: &crate::Atom,
    terms: &[mneme_core::Value],
    binding: &std::collections::BTreeMap<String, mneme_core::Value>,
    data: &crate::FactData,
) -> Option<std::collections::BTreeMap<String, mneme_core::Value>> {
    if data.supports.is_empty() {
        return None;
    }
    let mut extended = binding.clone();
    for (term, value) in atom.terms.iter().zip(terms) {
        match term {
            crate::Term::Constant(expected) => {
                if expected != value {
                    return None;
                }
            }
            crate::Term::Variable(name) => {
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

fn term_value(
    term: &crate::Term,
    binding: &std::collections::BTreeMap<String, mneme_core::Value>,
) -> Option<mneme_core::Value> {
    match term {
        crate::Term::Constant(value) => Some(value.clone()),
        crate::Term::Variable(name) => binding.get(name).cloned(),
    }
}

fn compare(op: crate::CompareOp, left: &mneme_core::Value, right: &mneme_core::Value) -> bool {
    match op {
        crate::CompareOp::Eq => left == right,
        crate::CompareOp::Ne => left != right,
        crate::CompareOp::Lt => left < right,
        crate::CompareOp::Le => left <= right,
        crate::CompareOp::Gt => left > right,
        crate::CompareOp::Ge => left >= right,
    }
}

fn head_terms(
    head: &crate::Atom,
    binding: &std::collections::BTreeMap<String, mneme_core::Value>,
) -> Result<Vec<mneme_core::Value>, crate::Error> {
    head.terms
        .iter()
        .map(|term| {
            term_value(term, binding)
                .ok_or_else(|| crate::Error::Failed("rule head has an unbound variable".to_owned()))
        })
        .collect()
}

#[derive(Clone, Debug)]
struct AggregateRow {
    head_terms: Vec<mneme_core::Value>,
    binding_indices: Vec<usize>,
}

#[allow(unknown_lints)] // row count is bounded by the result-row limit
fn aggregate_rows(
    head: &crate::Atom,
    output: &str,
    function: crate::AggregateFunction,
    input: &crate::Term,
    bindings: &[std::collections::BTreeMap<String, mneme_core::Value>],
) -> Result<Vec<AggregateRow>, crate::Error> {
    let group_variables = aggregate_group_variables(head, output);
    let groups = collect_aggregate_groups(&group_variables, input, bindings)?;
    let mut output_rows = Vec::with_capacity(groups.len());
    for (_, (indices, values)) in groups {
        let value = aggregate_value(function, values)?;
        let Some(first) = indices.first().and_then(|index| bindings.get(*index)) else {
            continue;
        };
        output_rows.push(aggregate_head_row(head, output, first, value, indices)?);
    }
    Ok(output_rows)
}

fn aggregate_group_variables(
    head: &crate::Atom,
    output: &str,
) -> std::collections::BTreeSet<String> {
    head.terms
        .iter()
        .filter_map(|term| {
            if let crate::Term::Variable(name) = term {
                if name != output {
                    Some(name.clone())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect()
}

type AggregateGroups =
    std::collections::BTreeMap<Vec<mneme_core::Value>, (Vec<usize>, Vec<mneme_core::Value>)>;

fn collect_aggregate_groups(
    group_variables: &std::collections::BTreeSet<String>,
    input: &crate::Term,
    bindings: &[std::collections::BTreeMap<String, mneme_core::Value>],
) -> Result<AggregateGroups, crate::Error> {
    let mut groups: AggregateGroups = std::collections::BTreeMap::new();
    for (index, binding) in bindings.iter().enumerate() {
        let key = group_variables
            .iter()
            .map(|name| {
                binding.get(name).cloned().ok_or_else(|| {
                    crate::Error::Failed("aggregate group variable is unbound".to_owned())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let value = term_value(input, binding)
            .ok_or_else(|| crate::Error::Failed("aggregate input is unbound".to_owned()))?;
        let entry = groups.entry(key).or_default();
        entry.0.push(index);
        entry.1.push(value);
    }
    Ok(groups)
}

fn aggregate_value(
    function: crate::AggregateFunction,
    values: Vec<mneme_core::Value>,
) -> Result<mneme_core::Value, crate::Error> {
    match function {
        crate::AggregateFunction::Count => Ok(mneme_core::Value::integer(
            i64::try_from(values.len())
                .map_err(|_| crate::Error::Failed("aggregate count exceeds i64".to_owned()))?,
        )),
        crate::AggregateFunction::Sum => aggregate_sum(&values),
        crate::AggregateFunction::Min => Ok(values
            .into_iter()
            .min()
            .unwrap_or_else(|| mneme_core::Value::integer(0))),
        crate::AggregateFunction::Max => Ok(values
            .into_iter()
            .max()
            .unwrap_or_else(|| mneme_core::Value::integer(0))),
    }
}

fn aggregate_sum(values: &[mneme_core::Value]) -> Result<mneme_core::Value, crate::Error> {
    let mut total = 0_u64;
    for value in values {
        let Some(integer) = value.as_integer().and_then(|integer| integer.to_i64()) else {
            return Err(crate::Error::Failed(
                "sum aggregate requires integer values".to_owned(),
            ));
        };
        let integer = u64::try_from(integer).map_err(|_| {
            crate::Error::Failed("sum aggregate requires non-negative values".to_owned())
        })?;
        total = total.saturating_add(integer);
    }
    Ok(mneme_core::Value::integer(total))
}

fn aggregate_head_row(
    head: &crate::Atom,
    output: &str,
    first: &std::collections::BTreeMap<String, mneme_core::Value>,
    value: mneme_core::Value,
    indices: Vec<usize>,
) -> Result<AggregateRow, crate::Error> {
    let head_terms = head
        .terms
        .iter()
        .map(|term| match term {
            crate::Term::Constant(value) => Some(value.clone()),
            crate::Term::Variable(name) if name == output => Some(value.clone()),
            crate::Term::Variable(name) => first.get(name).cloned(),
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| crate::Error::Failed("aggregate head variable is unbound".to_owned()))?;
    Ok(AggregateRow {
        head_terms,
        binding_indices: indices,
    })
}

fn instantiated_support(
    rule: &crate::Rule,
    evaluation: &Evaluation<'_>,
    binding: &std::collections::BTreeMap<String, mneme_core::Value>,
) -> (
    crate::Derivation,
    std::collections::BTreeSet<crate::SourceKey>,
) {
    let (premises, sources) = premises_for_binding(rule, evaluation, binding);
    let support = crate::Derivation {
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
    rule: &crate::Rule,
    evaluation: &Evaluation<'_>,
    bindings: &[std::collections::BTreeMap<String, mneme_core::Value>],
    indices: &[usize],
) -> (
    crate::Derivation,
    std::collections::BTreeSet<crate::SourceKey>,
) {
    let mut premises = Vec::with_capacity(indices.len());
    let mut sources = std::collections::BTreeSet::new();
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
    let is_truncated = premises.len() > 64;
    premises.truncate(64);
    let support = crate::Derivation {
        rule_id: rule.id.clone(),
        rule_version: evaluation.context.rule_bundle_version.clone(),
        premises,
        sources: sources.clone(),
        temporal_parameters: Vec::new(),
        revision: evaluation.context.served_revision,
        scope: evaluation.context.scope.clone(),
        truncated: is_truncated,
    };
    (support, sources)
}

fn premises_for_binding(
    rule: &crate::Rule,
    evaluation: &Evaluation<'_>,
    binding: &std::collections::BTreeMap<String, mneme_core::Value>,
) -> (
    Vec<crate::Premise>,
    std::collections::BTreeSet<crate::SourceKey>,
) {
    let mut premises = Vec::with_capacity(rule.body.len());
    let mut sources = std::collections::BTreeSet::new();
    for literal in &rule.body {
        match literal {
            crate::Literal::Positive(atom) | crate::Literal::Negative(atom) => {
                if let Some(store) = evaluation.relation(&atom.predicate) {
                    let terms = atom
                        .terms
                        .iter()
                        .filter_map(|term| term_value(term, binding))
                        .collect::<Vec<_>>();
                    if let Some(data) = store.rows.get(&terms) {
                        sources.extend(data.sources.iter().copied());
                        premises.push(crate::Premise {
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
    record: &mneme_core::RecordEnvelope,
    context: &crate::BuildContext,
    sources: std::collections::BTreeSet<crate::SourceKey>,
) -> crate::Derivation {
    canonical_support_with_availability(record, context, sources, None)
}

fn canonical_support_with_availability(
    record: &mneme_core::RecordEnvelope,
    context: &crate::BuildContext,
    sources: std::collections::BTreeSet<crate::SourceKey>,
    availability: Option<String>,
) -> crate::Derivation {
    crate::Derivation {
        rule_id: "canonical".to_owned(),
        rule_version: "1".to_owned(),
        premises: vec![crate::Premise {
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
    view: &mneme_memory::View,
    assertion: &mneme_memory::AssertionView,
) -> (std::collections::BTreeSet<crate::SourceKey>, Option<String>) {
    let mut sources = std::collections::BTreeSet::new();
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

fn reference_target(
    record: &mneme_core::RecordEnvelope,
    name: &str,
) -> Option<mneme_core::RecordId> {
    record
        .payload
        .get(name)
        .and_then(|value| mneme_core::Reference::from_value(value, &mneme_core::Path::root()).ok())
        .and_then(|reference| reference.target())
}

fn update_derived_coverage(evaluation: &mut Evaluation<'_>) {
    let heads = evaluation
        .bundle
        .rules
        .iter()
        .map(|rule| rule.head.predicate.clone())
        .collect::<std::collections::BTreeSet<_>>();
    loop {
        let mut is_changed = false;
        let mut next = evaluation.base_coverage.clone();
        for head in &heads {
            let rules = evaluation
                .bundle
                .rules
                .iter()
                .filter(|rule| &rule.head.predicate == head)
                .collect::<Vec<_>>();
            let mut is_all_complete = !rules.is_empty();
            let mut is_any_incomplete = false;
            let mut has_seed = false;
            for rule in rules {
                let has_self = rule.body.iter().any(
                    |literal| matches!(literal, crate::Literal::Positive(atom) if &atom.predicate == head),
                );
                if !has_self {
                    has_seed = true;
                }
                let is_body_complete = evaluation.status == crate::ExecutionStatus::Complete
                    && rule.body.iter().all(|literal| match literal {
                        crate::Literal::Positive(atom) | crate::Literal::Negative(atom) => {
                            if matches!(literal, crate::Literal::Positive(_))
                                && &atom.predicate == head
                            {
                                return true;
                            }
                            evaluation.coverage_status(&atom.predicate)
                                == crate::CoverageStatus::Complete
                        }
                        crate::Literal::Forbidden(_) => false,
                        crate::Literal::Aggregate { .. } | crate::Literal::Compare { .. } => true,
                    });
                if is_body_complete {
                    continue;
                }
                is_all_complete = false;
                is_any_incomplete = true;
            }
            let status = if is_all_complete && has_seed {
                crate::CoverageStatus::Complete
            } else if is_any_incomplete {
                crate::CoverageStatus::Incomplete
            } else {
                crate::CoverageStatus::Unknown
            };
            next.insert(head.clone(), status);
        }
        if next != evaluation.coverage {
            evaluation.coverage = next;
            is_changed = true;
        }
        if !is_changed {
            break;
        }
    }
}

fn final_coverage(evaluation: &Evaluation<'_>) -> Vec<crate::Coverage> {
    let mut predicates = std::collections::BTreeSet::new();
    predicates.extend(evaluation.facts.keys().cloned());
    predicates.extend(evaluation.coverage.keys().cloned());
    predicates
        .into_iter()
        .map(|predicate| {
            let status = evaluation.coverage_status(&predicate);
            crate::Coverage {
                predicate,
                status,
                reason: match status {
                    crate::CoverageStatus::Complete => None,
                    crate::CoverageStatus::Incomplete => {
                        Some("declared extent or dependency is incomplete".to_owned())
                    }
                    crate::CoverageStatus::Unknown => {
                        Some("predicate coverage is unknown".to_owned())
                    }
                },
            }
        })
        .collect()
}
