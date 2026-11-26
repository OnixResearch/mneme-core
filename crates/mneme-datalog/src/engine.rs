//! Snapshot fact loading, bounded fixpoint evaluation, and coverage.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

pub(crate) type FactKey = Vec<mneme_core::Value>;
pub(crate) type Binding = std::collections::BTreeMap<String, mneme_core::Value>;
pub(crate) type AvailabilityMap =
    std::collections::BTreeMap<mneme_core::RecordId, mneme_memory::SourceAvailability>;

/// The instant one bounded build started, taken before any snapshot is read.
#[allow(unknown_lints, ambient_clock)] // one evaluation start time for the bounded build
pub(crate) fn evaluation_start() -> std::time::Instant {
    std::time::Instant::now()
}

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
    pub limit_reached: bool,
    pub declaration_valid: bool,
}

/// One materialized row before it is inserted or merged.
struct FactContents {
    terms: FactKey,
    support: crate::Derivation,
    sources: std::collections::BTreeSet<crate::SourceKey>,
    canonical: Option<mneme_core::RecordId>,
    canonical_roots: std::collections::BTreeSet<mneme_core::RecordId>,
    temporal: Vec<String>,
}

/// The premises one binding instantiates.
struct PremiseSet {
    premises: Vec<crate::Premise>,
    sources: std::collections::BTreeSet<crate::SourceKey>,
    roots: std::collections::BTreeSet<mneme_core::RecordId>,
    temporal: std::collections::BTreeSet<String>,
}

/// Support accumulated over one instantiated rule body.
struct PremiseSupport {
    sources: std::collections::BTreeSet<crate::SourceKey>,
    roots: std::collections::BTreeSet<mneme_core::RecordId>,
    temporal: std::collections::BTreeSet<String>,
}

/// Work, row, time, and cancellation accounting for one evaluation.
///
/// Kept apart from the fact store so a join can charge while it holds a shared
/// borrow of the store: the two are disjoint fields of [`Evaluation`].
pub(crate) struct Budget<'a> {
    pub limits: &'a crate::Limits,
    pub work: u64,
    pub stored_rows: u64,
    pub start: std::time::Instant,
    pub cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    pub status: crate::ExecutionStatus,
    pub limit_reached: bool,
    pub support_truncated: bool,
}

impl<'a> Budget<'a> {
    pub(crate) fn is_active(&self) -> bool {
        self.status == crate::ExecutionStatus::Complete
    }

    fn cancelled(&self) -> bool {
        self.cancellation
            .as_ref()
            .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed))
    }

    pub(crate) fn stop(&mut self, status: crate::ExecutionStatus) {
        self.limit_reached = true;
        if self.status == crate::ExecutionStatus::Complete {
            self.status = status;
        }
    }

    /// Charge work before it is spent, and notice cancellation and the clock.
    #[allow(unknown_lints, ambient_clock)] // wall-clock budget is the evaluation shell
    pub(crate) fn charge(&mut self, amount: u64) -> bool {
        if self.cancelled() {
            self.stop(crate::ExecutionStatus::Cancelled);
            return false;
        }
        match mneme_kernel::budget::charge(self.work, amount, self.limits.max_work) {
            Some(work) => self.work = work,
            None => {
                self.stop(crate::ExecutionStatus::Timeout);
                return false;
            }
        }
        let Ok(max_time_ms) = u64::try_from(self.limits.max_time_ms) else {
            self.stop(crate::ExecutionStatus::Timeout);
            return false;
        };
        if self.start.elapsed() > std::time::Duration::from_millis(max_time_ms) {
            self.stop(crate::ExecutionStatus::Timeout);
            return false;
        }
        true
    }

    /// Charge one materialized row against the stored-row bound.
    pub(crate) fn charge_row(&mut self) -> bool {
        let Ok(limit) = u64::try_from(self.limits.max_result_rows) else {
            self.stop(crate::ExecutionStatus::Partial);
            return false;
        };
        match mneme_kernel::budget::charge(self.stored_rows, 1, limit) {
            Some(rows) => {
                self.stored_rows = rows;
                true
            }
            None => {
                self.stop(crate::ExecutionStatus::Partial);
                false
            }
        }
    }
}

struct Evaluation<'a> {
    bundle: &'a crate::RuleBundle,
    context: &'a crate::BuildContext,
    budget: Budget<'a>,
    facts: std::collections::BTreeMap<String, FactStore>,
    coverage: std::collections::BTreeMap<String, crate::CoverageStatus>,
    base_coverage: std::collections::BTreeMap<String, crate::CoverageStatus>,
    coverage_reasons: std::collections::BTreeMap<String, String>,
    current_sources: &'a AvailabilityMap,
    at: Option<mneme_core::Timestamp>,
    derivation_eligibility: std::collections::BTreeMap<
        mneme_core::RecordId,
        std::collections::BTreeSet<mneme_core::RecordId>,
    >,
    record_contributions: std::collections::BTreeMap<mneme_core::RecordId, Vec<(String, FactKey)>>,
}

impl Evaluation<'_> {
    fn coverage_status(&self, predicate: &str) -> crate::CoverageStatus {
        self.coverage
            .get(predicate)
            .copied()
            .unwrap_or(crate::CoverageStatus::Unknown)
    }

    /// Record that one relation cannot be materialized completely.
    fn mark_incomplete(&mut self, predicate: &str, reason: &str) {
        self.coverage
            .insert(predicate.to_owned(), crate::CoverageStatus::Incomplete);
        self.coverage_reasons
            .insert(predicate.to_owned(), reason.to_owned());
        if self.budget.status == crate::ExecutionStatus::Complete {
            self.budget.status = crate::ExecutionStatus::Partial;
        }
    }
}

/// The canonical base extents every build may load.
pub(crate) fn canonical_extents() -> &'static [&'static str] {
    &[
        "entity",
        "relation",
        "assertion",
        "denial",
        "hypothesis",
        "evidence",
        "document",
        "derivation",
        "source",
    ]
}

/// The wall-clock start and current byte availability a bounded build runs under.
pub(crate) struct BuildEnvironment<'a> {
    pub start: std::time::Instant,
    pub current_sources: &'a AvailabilityMap,
}

pub(crate) fn build(
    view: &mneme_memory::View,
    request: &crate::BuildRequest,
    context: &crate::BuildContext,
    program: &crate::RuleProgram,
    environment: BuildEnvironment<'_>,
) -> BuildFacts {
    let mut evaluation = Evaluation {
        bundle: &request.bundle,
        context,
        budget: Budget {
            limits: &request.limits,
            work: 0,
            stored_rows: 0,
            start: environment.start,
            cancellation: request.cancellation.clone(),
            status: crate::ExecutionStatus::Complete,
            limit_reached: false,
            support_truncated: false,
        },
        facts: std::collections::BTreeMap::new(),
        coverage: std::collections::BTreeMap::new(),
        base_coverage: std::collections::BTreeMap::new(),
        coverage_reasons: std::collections::BTreeMap::new(),
        current_sources: environment.current_sources,
        at: request.at,
        derivation_eligibility: std::collections::BTreeMap::new(),
        record_contributions: std::collections::BTreeMap::new(),
    };
    initialize_base_coverage(&mut evaluation, &request.incomplete_extents);
    load_base_facts(view, &mut evaluation);
    evaluate_rules(&mut evaluation, &program.strata);
    let coverage = final_coverage(&evaluation);
    let status = overall_status(evaluation.budget.status, &coverage);
    BuildFacts {
        facts: evaluation.facts,
        coverage,
        status,
        work: evaluation.budget.work,
        support_truncated: evaluation.budget.support_truncated,
        limit_reached: evaluation.budget.limit_reached,
        declaration_valid: declarations_match(evaluation.bundle),
    }
}

/// Cached canonical base extents and availability for one pinned REPL session.
#[derive(Clone)]
pub(crate) struct BaseSnapshot {
    pub revision: mneme_core::WorkspaceRevisionId,
    pub sequence: u64,
    pub scope: mneme_core::ScopeId,
    pub access: mneme_memory::Access,
    pub records: std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RecordEnvelope>,
    pub history: std::collections::BTreeMap<
        (mneme_core::RecordId, mneme_core::RevisionId),
        mneme_core::RecordEnvelope,
    >,
    pub revision_sequences: std::collections::BTreeMap<mneme_core::WorkspaceRevisionId, u64>,
    pub suppressions: Vec<mneme_store::RetentionSuppression>,
    pub facts: std::collections::BTreeMap<String, FactStore>,
    pub record_contributions:
        std::collections::BTreeMap<mneme_core::RecordId, Vec<(String, FactKey)>>,
    pub key_contributors: std::collections::BTreeMap<
        (String, FactKey),
        std::collections::BTreeSet<mneme_core::RecordId>,
    >,
    pub reverse_deps: std::collections::BTreeMap<
        mneme_core::RecordId,
        std::collections::BTreeSet<mneme_core::RecordId>,
    >,
    pub derivation_ids: std::collections::BTreeSet<mneme_core::RecordId>,
    pub base_coverage: std::collections::BTreeMap<String, crate::CoverageStatus>,
    pub coverage_reasons: std::collections::BTreeMap<String, String>,
    pub current_sources: AvailabilityMap,
    pub derivation_eligibility: std::collections::BTreeMap<
        mneme_core::RecordId,
        std::collections::BTreeSet<mneme_core::RecordId>,
    >,
    pub coverage: Vec<crate::Coverage>,
    pub status: crate::ExecutionStatus,
    pub work: u64,
    pub support_truncated: bool,
    pub limit_reached: bool,
}

/// Parameters for loading canonical base extents once for a REPL session.
pub(crate) struct BaseLoadRequest<'a> {
    pub bundle: &'a crate::RuleBundle,
    pub context: &'a crate::BuildContext,
    pub limits: &'a crate::Limits,
    pub incomplete_extents: &'a std::collections::BTreeSet<String>,
    pub current_sources: AvailabilityMap,
    pub history: std::collections::BTreeMap<
        (mneme_core::RecordId, mneme_core::RevisionId),
        mneme_core::RecordEnvelope,
    >,
    pub revision_sequences: std::collections::BTreeMap<mneme_core::WorkspaceRevisionId, u64>,
    pub suppressions: Vec<mneme_store::RetentionSuppression>,
    pub at: Option<mneme_core::Timestamp>,
    pub start: std::time::Instant,
}

/// Load canonical base extents once for a session pinned to one revision.
pub(crate) fn load_base_snapshot(
    view: &mneme_memory::View,
    request: BaseLoadRequest<'_>,
) -> BaseSnapshot {
    assert!(request.limits.max_work > 0);
    assert!(request.history.len() <= 1_000_000);
    let mut evaluation = Evaluation {
        bundle: request.bundle,
        context: request.context,
        budget: new_budget(request.limits, request.start, false),
        facts: std::collections::BTreeMap::new(),
        coverage: std::collections::BTreeMap::new(),
        base_coverage: std::collections::BTreeMap::new(),
        coverage_reasons: std::collections::BTreeMap::new(),
        current_sources: &request.current_sources,
        at: request.at,
        derivation_eligibility: std::collections::BTreeMap::new(),
        record_contributions: std::collections::BTreeMap::new(),
    };
    initialize_base_coverage(&mut evaluation, request.incomplete_extents);
    load_base_facts(view, &mut evaluation);
    let coverage = final_coverage(&evaluation);
    let status = overall_status(evaluation.budget.status, &coverage);
    let parts = LoadedBaseParts {
        facts: evaluation.facts,
        record_contributions: evaluation.record_contributions,
        base_coverage: evaluation.base_coverage,
        coverage_reasons: evaluation.coverage_reasons,
        derivation_eligibility: evaluation.derivation_eligibility,
        coverage,
        status,
        work: evaluation.budget.work,
        support_truncated: evaluation.budget.support_truncated,
        limit_reached: evaluation.budget.limit_reached,
    };
    finish_base_snapshot(view, request, parts)
}

struct LoadedBaseParts {
    facts: std::collections::BTreeMap<String, FactStore>,
    record_contributions: std::collections::BTreeMap<mneme_core::RecordId, Vec<(String, FactKey)>>,
    base_coverage: std::collections::BTreeMap<String, crate::CoverageStatus>,
    coverage_reasons: std::collections::BTreeMap<String, String>,
    derivation_eligibility: std::collections::BTreeMap<
        mneme_core::RecordId,
        std::collections::BTreeSet<mneme_core::RecordId>,
    >,
    coverage: Vec<crate::Coverage>,
    status: crate::ExecutionStatus,
    work: u64,
    support_truncated: bool,
    limit_reached: bool,
}

fn new_budget<'a>(
    limits: &'a crate::Limits,
    start: std::time::Instant,
    support_truncated: bool,
) -> Budget<'a> {
    Budget {
        limits,
        work: 0,
        stored_rows: 0,
        start,
        cancellation: None,
        status: crate::ExecutionStatus::Complete,
        limit_reached: false,
        support_truncated,
    }
}

fn finish_base_snapshot(
    view: &mneme_memory::View,
    request: BaseLoadRequest<'_>,
    parts: LoadedBaseParts,
) -> BaseSnapshot {
    assert!(request.limits.max_work > 0);
    assert!(request.history.len() <= 1_000_000);
    let snapshot = view.snapshot();
    let (records, key_contributors, reverse_deps, derivation_ids) =
        index_snapshot_records(&snapshot.records, &parts.record_contributions);
    BaseSnapshot {
        revision: snapshot.revision,
        sequence: snapshot.sequence,
        scope: request.context.scope.clone(),
        access: view.access().clone(),
        records,
        history: request.history,
        revision_sequences: request.revision_sequences,
        suppressions: request.suppressions,
        facts: parts.facts,
        record_contributions: parts.record_contributions,
        key_contributors,
        reverse_deps,
        derivation_ids,
        base_coverage: parts.base_coverage,
        coverage_reasons: parts.coverage_reasons,
        current_sources: request.current_sources,
        derivation_eligibility: parts.derivation_eligibility,
        coverage: parts.coverage,
        status: parts.status,
        work: parts.work,
        support_truncated: parts.support_truncated,
        limit_reached: parts.limit_reached,
    }
}

/// Parameters for incremental re-evaluation of affected predicates.
pub(crate) struct IncrementalRequest<'a> {
    pub bundle: &'a crate::RuleBundle,
    pub program: &'a crate::RuleProgram,
    pub context: &'a crate::BuildContext,
    pub limits: &'a crate::Limits,
    pub kept_facts: std::collections::BTreeMap<String, FactStore>,
    pub affected_predicates: &'a std::collections::BTreeSet<String>,
    pub at: Option<mneme_core::Timestamp>,
    pub start: std::time::Instant,
}

/// Re-evaluate only `affected_predicates` while preserving unaffected cached relations.
pub(crate) fn evaluate_incremental(
    base: &BaseSnapshot,
    request: IncrementalRequest<'_>,
) -> BuildFacts {
    let IncrementalRequest {
        bundle,
        program,
        context,
        limits,
        kept_facts,
        affected_predicates,
        at,
        start,
    } = request;
    let mut evaluation = Evaluation {
        bundle,
        context,
        budget: Budget {
            limits,
            work: 0,
            stored_rows: 0,
            start,
            cancellation: None,
            status: crate::ExecutionStatus::Complete,
            limit_reached: false,
            support_truncated: false,
        },
        facts: kept_facts,
        coverage: base.base_coverage.clone(),
        base_coverage: base.base_coverage.clone(),
        coverage_reasons: base.coverage_reasons.clone(),
        current_sources: &base.current_sources,
        at,
        derivation_eligibility: base.derivation_eligibility.clone(),
        record_contributions: std::collections::BTreeMap::new(),
    };
    let mut strata: std::collections::BTreeMap<usize, Vec<&crate::Rule>> =
        std::collections::BTreeMap::new();
    for rule in &bundle.rules {
        if affected_predicates.contains(&rule.head.predicate) {
            let stratum = program
                .strata
                .get(&rule.head.predicate)
                .copied()
                .unwrap_or(0);
            strata.entry(stratum).or_default().push(rule);
        }
    }
    update_derived_coverage(&mut evaluation);
    evaluate_strata(&mut evaluation, &strata);
    update_derived_coverage(&mut evaluation);
    let coverage = final_coverage(&evaluation);
    let status = overall_status(evaluation.budget.status, &coverage);
    BuildFacts {
        facts: evaluation.facts,
        coverage,
        status,
        work: evaluation.budget.work,
        support_truncated: evaluation.budget.support_truncated,
        limit_reached: evaluation.budget.limit_reached,
        declaration_valid: declarations_match(evaluation.bundle),
    }
}

fn overall_status(
    budget_status: crate::ExecutionStatus,
    coverage: &[crate::Coverage],
) -> crate::ExecutionStatus {
    if budget_status != crate::ExecutionStatus::Complete {
        budget_status
    } else if coverage
        .iter()
        .any(|coverage| coverage.status != crate::CoverageStatus::Complete)
    {
        crate::ExecutionStatus::Partial
    } else {
        crate::ExecutionStatus::Complete
    }
}

/// Whether every declared base predicate matches its canonical extent shape.
///
/// Registration already refuses a mismatch; re-deriving it here keeps the
/// completeness answer of a build truthful even if a program were built by
/// another path.
fn declarations_match(bundle: &crate::RuleBundle) -> bool {
    bundle.base_predicates.iter().all(|(predicate, arity)| {
        super::rules::canonical_arity(predicate).is_none_or(|expected| expected == *arity)
    })
}

fn initialize_base_coverage(
    evaluation: &mut Evaluation<'_>,
    incomplete_extents: &std::collections::BTreeSet<String>,
) {
    for predicate in canonical_extents() {
        let status = if incomplete_extents.contains(*predicate) {
            crate::CoverageStatus::Incomplete
        } else {
            crate::CoverageStatus::Complete
        };
        evaluation.coverage.insert((*predicate).to_owned(), status);
        evaluation
            .base_coverage
            .insert((*predicate).to_owned(), status);
    }
    for predicate in evaluation.bundle.base_predicates.keys() {
        let status = if !canonical_extents().contains(&predicate.as_str()) {
            crate::CoverageStatus::Unknown
        } else if incomplete_extents.contains(predicate) {
            crate::CoverageStatus::Incomplete
        } else {
            crate::CoverageStatus::Complete
        };
        evaluation.coverage.insert(predicate.clone(), status);
        evaluation.base_coverage.insert(predicate.clone(), status);
    }
}

/// Every base extent becomes incomplete when loading stops before its end.
fn stop_loading(evaluation: &mut Evaluation<'_>) {
    for status in evaluation.coverage.values_mut() {
        if *status != crate::CoverageStatus::Unknown {
            *status = crate::CoverageStatus::Incomplete;
        }
    }
    for status in evaluation.base_coverage.values_mut() {
        if *status != crate::CoverageStatus::Unknown {
            *status = crate::CoverageStatus::Incomplete;
        }
    }
}

fn load_base_facts(view: &mneme_memory::View, evaluation: &mut Evaluation<'_>) {
    for record in &view.snapshot().records {
        // The snapshot is already filtered to records this build may see; the
        // scope test is kept as a second fence so a wider snapshot can never
        // ground an in-scope fact.
        if record.scope != evaluation.context.scope {
            continue;
        }
        if !evaluation.budget.charge(1) {
            stop_loading(evaluation);
            return;
        }
        load_record_facts(view, record, evaluation);
        if !evaluation.budget.is_active() {
            stop_loading(evaluation);
            return;
        }
    }
}

fn load_record_facts(
    view: &mneme_memory::View,
    record: &mneme_core::RecordEnvelope,
    evaluation: &mut Evaluation<'_>,
) {
    match record.kind {
        mneme_core::RecordKind::Entity => load_entity_fact(record, evaluation),
        mneme_core::RecordKind::Relation => load_relation_fact(view, record, evaluation),
        mneme_core::RecordKind::Assertion => load_assertion_fact(view, record, evaluation),
        mneme_core::RecordKind::Evidence => load_evidence_fact(view, record, evaluation),
        mneme_core::RecordKind::Document => load_document_fact(view, record, evaluation),
        mneme_core::RecordKind::SourceRevision => load_source_fact(record, evaluation),
        mneme_core::RecordKind::Derivation => load_derivation_facts(view, record, evaluation),
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
    add_canonical_fact(
        evaluation,
        "entity",
        vec![record.record_id.to_value(), entity_type, label],
        plain_row(record),
    );
}

fn load_relation_fact(
    view: &mneme_memory::View,
    record: &mneme_core::RecordEnvelope,
    evaluation: &mut Evaluation<'_>,
) {
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
        // An endpoint outside the view is a foreign record identity, so the
        // edge cannot ground an in-scope fact.
        if view.record(from).is_err() || view.record(to).is_err() {
            return;
        }
        add_canonical_fact(
            evaluation,
            "relation",
            vec![relation_type, from.to_value(), to.to_value()],
            plain_row(record),
        );
    }
}

/// The extent an accepted assertion is loaded into, if it may be a fact.
///
/// A denial states the opposite of a claim, so it is never an affirmative
/// `assertion` row. A hypothesis is not operational knowledge, so it is loaded
/// only inside a hypothesis scope.
fn stance_extent(
    assertion: &mneme_memory::AssertionView,
    scope: &mneme_core::ScopeId,
) -> Option<&'static str> {
    match assertion.stance {
        mneme_memory::Stance::Affirm => Some("assertion"),
        mneme_memory::Stance::Deny => Some("denial"),
        mneme_memory::Stance::Hypothesis => {
            if scope.class() == mneme_core::ScopeClass::Hypothesis {
                Some("hypothesis")
            } else {
                None
            }
        }
    }
}

fn load_assertion_fact(
    view: &mneme_memory::View,
    record: &mneme_core::RecordEnvelope,
    evaluation: &mut Evaluation<'_>,
) {
    let Ok(assertion) = mneme_memory::AssertionView::parse(record.clone()) else {
        return;
    };
    if assertion.lifecycle != mneme_core::Lifecycle::Accepted
        || !view.accepted_decision(&assertion).unwrap_or(false)
        || !view.assertion_has_current_basis(&assertion)
    {
        return;
    }
    let Some(extent) = stance_extent(&assertion, &evaluation.context.scope) else {
        return;
    };
    // An out-of-scope subject would leak a record identity the caller cannot
    // see, so the whole assertion stays out of the projection.
    if view.record(assertion.subject).is_err() {
        return;
    }
    if let Some(at) = evaluation.at
        && !valid_at(assertion.valid_time, at)
    {
        return;
    }
    let (sources, availability) = assertion_sources(view, &assertion, evaluation.current_sources);
    add_canonical_fact(
        evaluation,
        extent,
        vec![
            assertion.subject.to_value(),
            mneme_core::Value::symbol(assertion.predicate.clone()),
            assertion.value.clone(),
            assertion.record_id().to_value(),
        ],
        CanonicalRow {
            record,
            sources,
            availability,
            temporal: temporal_parameters(assertion.valid_time),
        },
    );
}

fn load_evidence_fact(
    view: &mneme_memory::View,
    record: &mneme_core::RecordEnvelope,
    evaluation: &mut Evaluation<'_>,
) {
    let Ok(evidence) = mneme_memory::EvidenceView::parse(record.clone()) else {
        return;
    };
    // Challenging evidence argues against a claim; counting it as support would
    // make a contradicting source look like corroboration.
    if evidence.relation != mneme_memory::SupportRelation::Supports {
        return;
    }
    if is_suppressed(view, record)
        || view.record(evidence.assertion).is_err()
        || view.record(evidence.source).is_err()
    {
        return;
    }
    let sources = match evidence.source_reference {
        mneme_core::Reference::Pinned {
            target, revision, ..
        } => std::collections::BTreeSet::from([(target, revision)]),
        _ => std::collections::BTreeSet::new(),
    };
    // Availability is a property of the source record, not of the revision the
    // evidence pins: at head the record already carries the pruned/erased
    // outcome, and a build of an earlier revision gets it from the overlay.
    let current = view
        .record(evidence.source)
        .ok()
        .and_then(|record| mneme_memory::SourceView::parse(record.clone()).ok())
        .filter(|source| source.availability != mneme_memory::SourceAvailability::Retained)
        .map(|source| source.availability.name().to_owned());
    let availability = source_availability(evaluation.current_sources, evidence.source, current);
    add_canonical_fact(
        evaluation,
        "evidence",
        vec![evidence.assertion.to_value(), evidence.source.to_value()],
        CanonicalRow {
            record,
            sources,
            availability,
            temporal: Vec::new(),
        },
    );
}

fn load_document_fact(
    view: &mneme_memory::View,
    record: &mneme_core::RecordEnvelope,
    evaluation: &mut Evaluation<'_>,
) {
    let entity = match reference_target(record, "entity") {
        // An entity outside the view is a foreign record identity, so the
        // document cannot contribute an in-scope fact.
        Some(entity) if view.record(entity).is_err() => return,
        Some(entity) => entity.to_value(),
        None => mneme_core::Value::symbol("unbound"),
    };
    let path = record
        .payload
        .get("path")
        .and_then(mneme_core::Value::as_string)
        .map(|path| mneme_core::Value::string(path.to_owned()))
        .unwrap_or_else(|| mneme_core::Value::symbol("unpathed"));
    add_canonical_fact(
        evaluation,
        "document",
        vec![record.record_id.to_value(), entity, path],
        plain_row(record),
    );
}

fn load_source_fact(record: &mneme_core::RecordEnvelope, evaluation: &mut Evaluation<'_>) {
    let Ok(source) = mneme_memory::SourceView::parse(record.clone()) else {
        return;
    };
    // Availability comes from the retained source record and the current
    // workspace overlay, never from reading the bytes: a pruned source is not
    // corrupt, and reading every blob just to label it is unbounded work.
    let availability = source_availability(
        evaluation.current_sources,
        record.record_id,
        Some(source.availability.name().to_owned()),
    );
    let sources = std::collections::BTreeSet::from([(record.record_id, record.revision_id)]);
    let availability_name = match availability {
        Some(name) => name,
        None => "retained".to_owned(),
    };
    add_canonical_fact(
        evaluation,
        "source",
        vec![
            record.record_id.to_value(),
            record.revision_id.to_value(),
            mneme_core::Value::string(availability_name),
        ],
        CanonicalRow {
            record,
            sources,
            availability: None,
            temporal: Vec::new(),
        },
    );
}

fn load_derivation_facts(
    view: &mneme_memory::View,
    record: &mneme_core::RecordEnvelope,
    evaluation: &mut Evaluation<'_>,
) {
    let Ok(derivation) = mneme_memory::DerivationView::parse(record.clone()) else {
        return;
    };
    if is_suppressed(view, record)
        || !is_derivation_eligible(evaluation, view, derivation.conclusion, record.record_id)
    {
        return;
    }
    for premise in &derivation.premises {
        add_canonical_fact(
            evaluation,
            "derivation",
            vec![derivation.conclusion.to_value(), premise.to_value()],
            plain_row(record),
        );
    }
}

/// Whether memory's eligibility rules accept one derivation for its conclusion.
fn is_derivation_eligible(
    evaluation: &mut Evaluation<'_>,
    view: &mneme_memory::View,
    conclusion: mneme_core::RecordId,
    derivation: mneme_core::RecordId,
) -> bool {
    let eligible = evaluation
        .derivation_eligibility
        .entry(conclusion)
        .or_insert_with(|| eligible_derivations(view, conclusion));
    eligible.contains(&derivation)
}

/// The derivation records memory currently admits for one conclusion.
fn eligible_derivations(
    view: &mneme_memory::View,
    conclusion: mneme_core::RecordId,
) -> std::collections::BTreeSet<mneme_core::RecordId> {
    match view.derivation_alternatives(conclusion) {
        Ok(alternatives) => alternatives
            .into_iter()
            .filter(|alternative| alternative.eligible)
            .map(|alternative| alternative.derivation)
            .collect(),
        // A conclusion whose derivations cannot be evaluated grounds nothing.
        Err(_) => std::collections::BTreeSet::new(),
    }
}

/// The availability of one source, overlaying the current workspace state.
///
/// A build of an earlier revision sees the revision's records but must still
/// observe current byte availability: pruning that happened after the pinned
/// revision marks the source unavailable, and never as corruption.
fn source_availability(
    current_sources: &AvailabilityMap,
    source: mneme_core::RecordId,
    pinned: Option<String>,
) -> Option<String> {
    match current_sources.get(&source) {
        Some(availability)
            if !matches!(availability, mneme_memory::SourceAvailability::Retained) =>
        {
            Some(availability.name().to_owned())
        }
        _ => pinned,
    }
}

fn is_suppressed(view: &mneme_memory::View, record: &mneme_core::RecordEnvelope) -> bool {
    view.suppression_for(record).is_some_and(|suppression| {
        matches!(
            suppression.mode,
            mneme_store::SuppressionMode::Withdrawn | mneme_store::SuppressionMode::Forgotten
        )
    })
}

/// Whether a claim's valid time contains the evaluation instant.
///
/// Unknown validity is not the epoch, so it never matches an explicit instant.
fn valid_at(valid_time: mneme_core::ValidTime, at: mneme_core::Timestamp) -> bool {
    match valid_time {
        mneme_core::ValidTime::Unknown => false,
        mneme_core::ValidTime::Bounded { start, end } => {
            start.is_none_or(|start| start <= at) && end.is_none_or(|at_bound| at <= at_bound)
        }
    }
}

/// The temporal parameters a claim contributes to a derivation.
fn temporal_parameters(valid_time: mneme_core::ValidTime) -> Vec<String> {
    match valid_time {
        mneme_core::ValidTime::Unknown => vec!["valid-time:unknown".to_owned()],
        mneme_core::ValidTime::Bounded { start, end } => {
            let mut parameters = Vec::new();
            if let Some(start) = start {
                parameters.push(format!("valid-time-start:{}", start.nanos()));
            }
            if let Some(end) = end {
                parameters.push(format!("valid-time-end:{}", end.nanos()));
            }
            parameters
        }
    }
}

/// Root sources and availability for one assertion's supporting evidence.
fn assertion_sources(
    view: &mneme_memory::View,
    assertion: &mneme_memory::AssertionView,
    current_sources: &AvailabilityMap,
) -> (std::collections::BTreeSet<crate::SourceKey>, Option<String>) {
    let mut sources = std::collections::BTreeSet::new();
    let mut availability = None;
    for evidence_id in &assertion.evidence {
        let Ok(evidence) = view.evidence(*evidence_id) else {
            continue;
        };
        if evidence.relation != mneme_memory::SupportRelation::Supports
            || is_suppressed(view, &evidence.record)
        {
            continue;
        }
        if let Ok(roots) = view.evidence_roots(evidence.record.record_id) {
            sources.extend(roots);
        }
        let pinned = view
            .evidence_source(&evidence)
            .ok()
            .map(|source| source.availability.name().to_owned());
        if let Some(name) = source_availability(current_sources, evidence.source, pinned)
            && name != "retained"
        {
            availability.get_or_insert(name);
        }
    }
    (sources, availability)
}

/// Where one canonical base row comes from and how it is grounded.
struct CanonicalRow<'a> {
    record: &'a mneme_core::RecordEnvelope,
    sources: std::collections::BTreeSet<crate::SourceKey>,
    availability: Option<String>,
    temporal: Vec<String>,
}

/// A canonical row with no supporting sources and no temporal parameters.
fn plain_row(record: &mneme_core::RecordEnvelope) -> CanonicalRow<'_> {
    CanonicalRow {
        record,
        sources: std::collections::BTreeSet::new(),
        availability: None,
        temporal: Vec::new(),
    }
}

fn add_canonical_fact(
    evaluation: &mut Evaluation<'_>,
    predicate: &str,
    terms: FactKey,
    row: CanonicalRow<'_>,
) {
    let CanonicalRow {
        record,
        sources,
        availability,
        temporal,
    } = row;
    let support = canonical_support(
        record,
        evaluation.context,
        sources.clone(),
        availability,
        temporal.clone(),
    );
    evaluation
        .record_contributions
        .entry(record.record_id)
        .or_default()
        .push((predicate.to_owned(), terms.clone()));
    add_fact(
        evaluation,
        predicate,
        FactContents {
            terms,
            support,
            sources,
            canonical: Some(record.record_id),
            canonical_roots: std::collections::BTreeSet::from([record.record_id]),
            temporal,
        },
    );
}

fn canonical_support(
    record: &mneme_core::RecordEnvelope,
    context: &crate::BuildContext,
    sources: std::collections::BTreeSet<crate::SourceKey>,
    availability: Option<String>,
    temporal: Vec<String>,
) -> crate::Derivation {
    crate::Derivation {
        rule_id: "canonical".to_owned(),
        rule_version: "1".to_owned(),
        premises: vec![crate::Premise {
            predicate: record.kind.symbol().to_owned(),
            terms: Vec::new(),
            canonical: Some(record.record_id),
            canonical_roots: std::collections::BTreeSet::from([record.record_id]),
            sources: sources.clone(),
            source_availability: availability,
            absent: false,
            coverage: None,
        }],
        sources,
        temporal_parameters: temporal,
        revision: context.served_revision,
        scope: context.scope.clone(),
        truncated: false,
    }
}

/// Insert one row or merge the support of an existing one.
///
/// Work is charged before the fact is materialized. A proof is identified by its
/// rule and instantiated premises only: a premise that gains sources in a later
/// round must update the recorded support instead of appending a duplicate.
fn add_fact(evaluation: &mut Evaluation<'_>, predicate: &str, contents: FactContents) -> bool {
    if !evaluation.budget.charge(1) {
        return false;
    }
    let is_new = evaluation
        .facts
        .get(predicate)
        .is_none_or(|store| !store.rows.contains_key(&contents.terms));
    if is_new && !evaluation.budget.charge_row() {
        return false;
    }
    let max_supports = evaluation.budget.limits.max_supports_per_fact;
    let FactContents {
        terms,
        support,
        sources,
        canonical,
        canonical_roots,
        temporal,
    } = contents;
    let store = evaluation.facts.entry(predicate.to_owned()).or_default();
    if let Some(data) = store.rows.get_mut(&terms) {
        if let Some(existing) = data
            .supports
            .iter_mut()
            .find(|existing| same_proof(existing, &support))
        {
            merge_premises(existing, &support);
            data.sources.extend(sources);
            data.canonical_roots.extend(canonical_roots);
            merge_strings(&mut data.temporal, temporal);
            return false;
        }
        if data.supports.len() >= max_supports {
            data.truncated = true;
            store.truncated = true;
            evaluation.budget.support_truncated = true;
            return false;
        }
        data.supports.push(support);
        data.sources.extend(sources);
        data.canonical_roots.extend(canonical_roots);
        merge_strings(&mut data.temporal, temporal);
        return false;
    }
    store.rows.insert(
        terms,
        crate::FactData {
            supports: vec![support],
            sources,
            truncated: false,
            canonical,
            canonical_roots,
            temporal,
        },
    );
    true
}

/// Whether two supports record the same proof.
fn same_proof(left: &crate::Derivation, right: &crate::Derivation) -> bool {
    left.rule_id == right.rule_id
        && left.premises.len() == right.premises.len()
        && left
            .premises
            .iter()
            .zip(&right.premises)
            .all(|(left, right)| {
                left.predicate == right.predicate
                    && left.terms == right.terms
                    && left.canonical == right.canonical
                    && left.absent == right.absent
            })
}

fn merge_premises(existing: &mut crate::Derivation, new: &crate::Derivation) {
    for premise in &new.premises {
        match existing.premises.iter_mut().find(|candidate| {
            candidate.predicate == premise.predicate
                && candidate.terms == premise.terms
                && candidate.canonical == premise.canonical
                && candidate.absent == premise.absent
        }) {
            Some(candidate) => {
                candidate.sources.extend(premise.sources.iter().copied());
                candidate
                    .canonical_roots
                    .extend(premise.canonical_roots.iter().copied());
                if candidate.source_availability.is_none() {
                    candidate.source_availability = premise.source_availability.clone();
                }
            }
            None => existing.premises.push(premise.clone()),
        }
    }
    existing.sources.extend(new.sources.iter().copied());
    merge_strings(
        &mut existing.temporal_parameters,
        new.temporal_parameters.clone(),
    );
    existing.truncated = existing.truncated || new.truncated;
}

fn merge_strings(target: &mut Vec<String>, extra: Vec<String>) {
    if extra.is_empty() {
        return;
    }
    let mut merged = target
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    merged.extend(extra);
    target.clear();
    target.extend(merged);
}

fn evaluate_rules(
    evaluation: &mut Evaluation<'_>,
    rule_strata: &std::collections::BTreeMap<String, usize>,
) {
    let mut strata: std::collections::BTreeMap<usize, Vec<&crate::Rule>> =
        std::collections::BTreeMap::new();
    for rule in &evaluation.bundle.rules {
        let stratum = rule_strata.get(&rule.head.predicate).copied().unwrap_or(0);
        strata.entry(stratum).or_default().push(rule);
    }
    evaluate_strata(evaluation, &strata);
}

fn evaluate_strata(
    evaluation: &mut Evaluation<'_>,
    strata: &std::collections::BTreeMap<usize, Vec<&crate::Rule>>,
) {
    for rules in strata.values() {
        let mut rounds = 0_usize;
        loop {
            if !evaluation.budget.is_active() {
                break;
            }
            let mut is_changed = false;
            for rule in rules {
                if evaluate_rule(evaluation, rule) == RuleOutcome::Changed {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

fn evaluate_rule(evaluation: &mut Evaluation<'_>, rule: &crate::Rule) -> RuleOutcome {
    let Some(is_body_complete) = body_is_complete(evaluation, rule) else {
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
    if (aggregate.is_some() || has_negative) && !is_body_complete {
        return RuleOutcome::Skipped;
    }
    let mut bindings = match positive_bindings(evaluation, rule) {
        Ok(bindings) => bindings,
        Err(outcome) => return outcome,
    };
    if let Err(outcome) = filter_nonpositive_literals(evaluation, rule, &mut bindings) {
        return outcome;
    }
    if let Some(aggregate) = aggregate {
        return evaluate_aggregate_rule(evaluation, rule, &aggregate, &bindings);
    }
    evaluate_ordinary_rule(evaluation, rule, &bindings)
}

type RuleBindings = Vec<Binding>;

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
    let mut bindings = vec![Binding::new()];
    for literal in &rule.body {
        if let crate::Literal::Positive(atom) = literal {
            // A binding count past the budget's counter cannot be charged at
            // all, so the rule is skipped exactly as an exhausted budget is.
            let Ok(cost) = u64::try_from(bindings.len()) else {
                return Err(RuleOutcome::Skipped);
            };
            if !evaluation.budget.charge(cost) {
                return Err(RuleOutcome::Skipped);
            }
            bindings = join(evaluation, &bindings, atom)?;
            if bindings.is_empty() {
                return Err(RuleOutcome::Stable);
            }
        }
    }
    Ok(bindings)
}

fn filter_nonpositive_literals(
    evaluation: &mut Evaluation<'_>,
    rule: &crate::Rule,
    bindings: &mut RuleBindings,
) -> Result<(), RuleOutcome> {
    for literal in &rule.body {
        match literal {
            crate::Literal::Negative(atom) => {
                if evaluation.coverage_status(&atom.predicate) != crate::CoverageStatus::Complete {
                    return Err(RuleOutcome::Skipped);
                }
                let mut kept = Vec::with_capacity(bindings.len());
                for binding in bindings.drain(..) {
                    if !evaluation.budget.charge(1) {
                        return Err(RuleOutcome::Skipped);
                    }
                    if !matches_atom(evaluation, atom, &binding)? {
                        kept.push(binding);
                    }
                }
                *bindings = kept;
                if bindings.is_empty() {
                    return Err(RuleOutcome::Stable);
                }
            }
            crate::Literal::Compare { op, left, right } => {
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
            _ => {}
        }
    }
    Ok(())
}

fn evaluate_aggregate_rule(
    evaluation: &mut Evaluation<'_>,
    rule: &crate::Rule,
    aggregate: &AggregateSpec,
    bindings: &RuleBindings,
) -> RuleOutcome {
    let grouped = match aggregate_rows(&rule.head, aggregate, bindings) {
        Ok(grouped) => grouped,
        Err(reason) => return fail_relation(evaluation, &rule.head.predicate, reason),
    };
    let mut is_changed = false;
    for aggregate_row in grouped {
        if !evaluation.budget.is_active() {
            break;
        }
        let contents = aggregate_support(rule, evaluation, bindings, &aggregate_row);
        if add_fact(evaluation, &rule.head.predicate, contents) {
            is_changed = true;
        }
    }
    if is_changed {
        RuleOutcome::Changed
    } else {
        RuleOutcome::Stable
    }
}

fn evaluate_ordinary_rule(
    evaluation: &mut Evaluation<'_>,
    rule: &crate::Rule,
    bindings: &RuleBindings,
) -> RuleOutcome {
    let mut is_changed = false;
    for binding in bindings {
        if !evaluation.budget.is_active() {
            break;
        }
        let Some(terms) = head_terms(&rule.head, binding) else {
            // One malformed binding leaves this relation incomplete; it must not
            // discard every other relation of the build.
            return fail_relation(
                evaluation,
                &rule.head.predicate,
                "rule head has an unbound variable",
            );
        };
        let contents = instantiated_support(rule, evaluation, binding, terms);
        if add_fact(evaluation, &rule.head.predicate, contents) {
            is_changed = true;
        }
    }
    if is_changed {
        RuleOutcome::Changed
    } else {
        RuleOutcome::Stable
    }
}

fn fail_relation(
    evaluation: &mut Evaluation<'_>,
    predicate: &str,
    reason: &'static str,
) -> RuleOutcome {
    evaluation.mark_incomplete(predicate, reason);
    RuleOutcome::Skipped
}

fn join(
    evaluation: &mut Evaluation<'_>,
    bindings: &[Binding],
    atom: &crate::Atom,
) -> Result<RuleBindings, RuleOutcome> {
    let Some(store) = evaluation.facts.get(&atom.predicate) else {
        return Ok(Vec::new());
    };
    let binding_limit = evaluation.budget.limits.max_result_rows;
    // A join can never emit more rows than the intermediate-binding limit, and
    // the input bindings are already materialized, so reserve the smaller.
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
                if output.len() >= binding_limit {
                    // Intermediate bindings are bounded like result rows so a
                    // cross product cannot exhaust memory inside one join.
                    evaluation.budget.stop(crate::ExecutionStatus::Partial);
                    return Err(RuleOutcome::Skipped);
                }
                output.push(extended);
            }
        }
    }
    Ok(output)
}

fn matches_atom(
    evaluation: &mut Evaluation<'_>,
    atom: &crate::Atom,
    binding: &Binding,
) -> Result<bool, RuleOutcome> {
    let Some(store) = evaluation.facts.get(&atom.predicate) else {
        return Ok(false);
    };
    let mut is_matched = false;
    for terms in store.rows.keys() {
        if !evaluation.budget.charge(1) {
            return Err(RuleOutcome::Skipped);
        }
        if terms.len() == atom.terms.len()
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
        {
            is_matched = true;
            break;
        }
    }
    Ok(is_matched)
}

fn unify(
    atom: &crate::Atom,
    terms: &[mneme_core::Value],
    binding: &Binding,
    data: &crate::FactData,
) -> Option<Binding> {
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

fn term_value(term: &crate::Term, binding: &Binding) -> Option<mneme_core::Value> {
    match term {
        crate::Term::Constant(value) => Some(value.clone()),
        crate::Term::Variable(name) => binding.get(name).cloned(),
    }
}

fn compare_values(
    op: crate::CompareOp,
    left: &mneme_core::Value,
    right: &mneme_core::Value,
) -> bool {
    match op {
        crate::CompareOp::Eq => left == right,
        crate::CompareOp::Ne => left != right,
        crate::CompareOp::Lt => order_values(left, right) == std::cmp::Ordering::Less,
        crate::CompareOp::Le => order_values(left, right) != std::cmp::Ordering::Greater,
        crate::CompareOp::Gt => order_values(left, right) == std::cmp::Ordering::Greater,
        crate::CompareOp::Ge => order_values(left, right) != std::cmp::Ordering::Less,
    }
}

/// Order two values, numerically when both are numbers.
///
/// Preserves' total order ranks kinds before values, so `SignedInteger(1)` sorts
/// after `Double(1.5)` and `1 < 1.5` would be false. Comparisons and min/max in
/// this profile are numeric, so integers and doubles compare by value; every
/// other pair keeps the total order that makes the result deterministic.
fn order_values(left: &mneme_core::Value, right: &mneme_core::Value) -> std::cmp::Ordering {
    match compare_numeric(left, right) {
        Some(ordering) => ordering,
        None => left.cmp(right),
    }
}

/// Compare two numbers by value, including the integer/double pair.
///
/// A double is `significand × 2^exponent`, so an exact comparison against an
/// arbitrary-precision integer scales both sides to integers instead of
/// rounding either one. The integer type stays inferred from
/// [`mneme_core::Value::as_integer`], which keeps this crate free of a direct
/// `num-bigint` dependency.
fn compare_numeric(
    left: &mneme_core::Value,
    right: &mneme_core::Value,
) -> Option<std::cmp::Ordering> {
    if let (mneme_core::Value::SignedInteger(left), mneme_core::Value::SignedInteger(right)) =
        (left, right)
    {
        return Some(left.as_bigint().cmp(right.as_bigint()));
    }
    if let (mneme_core::Value::Double(left), mneme_core::Value::Double(right)) = (left, right) {
        return Some(left.value().total_cmp(&right.value()));
    }
    let (integer, double, is_reversed) = match (left, right) {
        (mneme_core::Value::SignedInteger(integer), mneme_core::Value::Double(double)) => {
            (integer.as_bigint(), double.value(), false)
        }
        (mneme_core::Value::Double(double), mneme_core::Value::SignedInteger(integer)) => {
            (integer.as_bigint(), double.value(), true)
        }
        _ => return None,
    };
    if double.is_nan() {
        return None;
    }
    let ordering = if double.is_infinite() {
        if double.is_sign_positive() {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    } else {
        let bits = double.to_bits();
        let is_negative = (bits >> 63) != 0;
        let exponent_bits = (bits >> 52) & 0x7ff;
        let fraction = bits & 0x000f_ffff_ffff_ffff;
        let (significand_bits, exponent) = if exponent_bits == 0 {
            (fraction, -1074_i64)
        } else {
            let Ok(exponent_bits) = i64::try_from(exponent_bits) else {
                return None;
            };
            (fraction | 0x0010_0000_0000_0000, exponent_bits - 1075)
        };
        let significand_value = mneme_core::Value::integer(significand_bits);
        let significand_integer = significand_value.as_integer()?;
        compare_scaled(
            integer,
            significand_integer.as_bigint(),
            is_negative,
            exponent,
        )?
    };
    Some(if is_reversed {
        ordering.reverse()
    } else {
        ordering
    })
}

/// Exactly compare an arbitrary-precision integer with `significand × 2^exponent`.
///
/// Generic over the integer type so this crate needs no direct dependency on the
/// big-integer crate: both operands come from
/// [`mneme_core::Value::as_integer`], and every operation used here is one that
/// arbitrary-precision integer implements.
fn compare_scaled<T>(
    integer: &T,
    significand: &T,
    is_negative: bool,
    exponent: i64,
) -> Option<std::cmp::Ordering>
where
    T: Clone + Ord + std::ops::Neg<Output = T>,
    for<'a> &'a T: std::ops::Shl<u64, Output = T>,
{
    let mut scaled = significand.clone();
    if is_negative {
        scaled = -scaled;
    }
    if exponent >= 0 {
        let Ok(shift) = u64::try_from(exponent) else {
            return None;
        };
        Some(integer.cmp(&((&scaled) << shift)))
    } else {
        let Ok(shift) = u64::try_from(-exponent) else {
            return None;
        };
        Some((integer << shift).cmp(&scaled))
    }
}

fn head_terms(head: &crate::Atom, binding: &Binding) -> Option<Vec<mneme_core::Value>> {
    head.terms
        .iter()
        .map(|term| term_value(term, binding))
        .collect()
}

#[derive(Clone, Debug)]
struct AggregateRow {
    head_terms: Vec<mneme_core::Value>,
    binding_indices: Vec<usize>,
}

fn aggregate_rows(
    head: &crate::Atom,
    aggregate: &AggregateSpec,
    bindings: &[Binding],
) -> Result<Vec<AggregateRow>, &'static str> {
    let group_variables = aggregate_group_variables(head, &aggregate.output);
    let groups = collect_aggregate_groups(&group_variables, &aggregate.input, bindings)?;
    let mut output_rows = Vec::with_capacity(groups.len());
    for (indices, values) in groups.into_values() {
        let value = aggregate_value(aggregate.function, values)?;
        let Some(first) = indices.first().and_then(|index| bindings.get(*index)) else {
            continue;
        };
        output_rows.push(aggregate_head_row(
            head,
            &aggregate.output,
            first,
            value,
            indices,
        )?);
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
    bindings: &[Binding],
) -> Result<AggregateGroups, &'static str> {
    let mut groups: AggregateGroups = std::collections::BTreeMap::new();
    for (index, binding) in bindings.iter().enumerate() {
        let key = group_variables
            .iter()
            .map(|name| {
                binding
                    .get(name)
                    .cloned()
                    .ok_or("aggregate group variable is unbound")
            })
            .collect::<Result<Vec<_>, _>>()?;
        let value = term_value(input, binding).ok_or("aggregate input is unbound")?;
        let entry = groups.entry(key).or_default();
        entry.0.push(index);
        entry.1.push(value);
    }
    Ok(groups)
}

fn aggregate_value(
    function: crate::AggregateFunction,
    values: Vec<mneme_core::Value>,
) -> Result<mneme_core::Value, &'static str> {
    match function {
        crate::AggregateFunction::Count => {
            let count = i64::try_from(values.len()).map_err(|_| "aggregate count exceeds i64")?;
            Ok(mneme_core::Value::integer(count))
        }
        crate::AggregateFunction::Sum => aggregate_sum(&values),
        crate::AggregateFunction::Min => values
            .into_iter()
            .min_by(order_values)
            .ok_or("aggregate group is empty"),
        crate::AggregateFunction::Max => values
            .into_iter()
            .max_by(order_values)
            .ok_or("aggregate group is empty"),
    }
}

/// Add values in an arbitrary-precision integer.
///
/// Summing in a `u64` with saturation silently replaced a correct total with
/// `u64::MAX`; a value of another kind is a type error for this group only.
fn aggregate_sum(values: &[mneme_core::Value]) -> Result<mneme_core::Value, &'static str> {
    let mut iterator = values.iter();
    let Some(first) = iterator.next() else {
        return Ok(mneme_core::Value::integer(0_i64));
    };
    let first_integer = first
        .as_integer()
        .ok_or("sum aggregate requires integer values")?;
    let mut total = first_integer.as_bigint().clone();
    for value in iterator {
        let integer = value
            .as_integer()
            .ok_or("sum aggregate requires integer values")?;
        total += integer.as_bigint();
    }
    Ok(mneme_core::Value::integer(total))
}

fn aggregate_head_row(
    head: &crate::Atom,
    output: &str,
    first: &Binding,
    value: mneme_core::Value,
    indices: Vec<usize>,
) -> Result<AggregateRow, &'static str> {
    let head_terms = head
        .terms
        .iter()
        .map(|term| match term {
            crate::Term::Constant(value) => Some(value.clone()),
            crate::Term::Variable(name) if name == output => Some(value.clone()),
            crate::Term::Variable(name) => first.get(name).cloned(),
        })
        .collect::<Option<Vec<_>>>()
        .ok_or("aggregate head variable is unbound")?;
    Ok(AggregateRow {
        head_terms,
        binding_indices: indices,
    })
}

fn instantiated_support(
    rule: &crate::Rule,
    evaluation: &mut Evaluation<'_>,
    binding: &Binding,
    terms: FactKey,
) -> FactContents {
    let PremiseSet {
        premises,
        sources,
        roots,
        temporal,
    } = premises_for_binding(rule, evaluation, binding);
    let temporal = temporal.into_iter().collect::<Vec<_>>();
    let support = crate::Derivation {
        rule_id: rule.id.clone(),
        rule_version: evaluation.context.rule_bundle_version.clone(),
        premises,
        sources: sources.clone(),
        temporal_parameters: temporal.clone(),
        revision: evaluation.context.served_revision,
        scope: evaluation.context.scope.clone(),
        truncated: false,
    };
    FactContents {
        terms,
        support,
        sources,
        canonical: None,
        canonical_roots: roots,
        temporal,
    }
}

fn aggregate_support(
    rule: &crate::Rule,
    evaluation: &mut Evaluation<'_>,
    bindings: &[Binding],
    row: &AggregateRow,
) -> FactContents {
    let mut premises = Vec::with_capacity(row.binding_indices.len());
    let mut seen = std::collections::BTreeSet::new();
    let mut sources = std::collections::BTreeSet::new();
    let mut roots = std::collections::BTreeSet::new();
    let mut temporal = std::collections::BTreeSet::new();
    for index in &row.binding_indices {
        let Some(binding) = bindings.get(*index) else {
            continue;
        };
        let premise_set = premises_for_binding(rule, evaluation, binding);
        sources.extend(premise_set.sources);
        roots.extend(premise_set.roots);
        temporal.extend(premise_set.temporal);
        // De-duplicate by identity instead of a linear scan over every premise
        // already collected: a group can hold thousands of bindings.
        for premise in premise_set.premises {
            let key = (
                premise.predicate.clone(),
                premise.terms.clone(),
                premise.absent,
            );
            if seen.insert(key) {
                premises.push(premise);
            }
        }
    }
    let is_truncated = premises.len() > 64;
    premises.truncate(64);
    let temporal = temporal.into_iter().collect::<Vec<_>>();
    let support = crate::Derivation {
        rule_id: rule.id.clone(),
        rule_version: evaluation.context.rule_bundle_version.clone(),
        premises,
        sources: sources.clone(),
        temporal_parameters: temporal.clone(),
        revision: evaluation.context.served_revision,
        scope: evaluation.context.scope.clone(),
        truncated: is_truncated,
    };
    FactContents {
        terms: row.head_terms.clone(),
        support,
        sources,
        canonical: None,
        canonical_roots: roots,
        temporal,
    }
}

/// Instantiate every premise a binding relies on.
///
/// A negated literal never has a matching row, so it is recorded as an explicit
/// absence premise together with the relation coverage the rule required;
/// otherwise a derivation that rests on negation would look like it rested on
/// the positive body alone.
fn premises_for_binding(
    rule: &crate::Rule,
    evaluation: &mut Evaluation<'_>,
    binding: &Binding,
) -> PremiseSet {
    let mut premises = Vec::with_capacity(rule.body.len());
    let mut support = PremiseSupport {
        sources: std::collections::BTreeSet::new(),
        roots: std::collections::BTreeSet::new(),
        temporal: std::collections::BTreeSet::new(),
    };
    for literal in &rule.body {
        match literal {
            crate::Literal::Positive(atom) => {
                if let Some(premise) = positive_premise(evaluation, atom, binding, &mut support) {
                    premises.push(premise);
                }
            }
            crate::Literal::Negative(atom) => {
                if let Some(premise) = negative_premise(evaluation, atom, binding) {
                    premises.push(premise);
                }
            }
            _ => {}
        }
    }
    PremiseSet {
        premises,
        sources: support.sources,
        roots: support.roots,
        temporal: support.temporal,
    }
}

/// Instantiate one positive literal against the fact it matches.
///
/// Charges the budget first; `None` means the charge failed or no row matched,
/// so the literal contributes no premise.
fn positive_premise(
    evaluation: &mut Evaluation<'_>,
    atom: &crate::Atom,
    binding: &Binding,
    support: &mut PremiseSupport,
) -> Option<crate::Premise> {
    if !evaluation.budget.charge(1) {
        return None;
    }
    let terms = atom
        .terms
        .iter()
        .filter_map(|term| term_value(term, binding))
        .collect::<Vec<_>>();
    let data = evaluation
        .facts
        .get(&atom.predicate)
        .and_then(|store| store.rows.get(&terms))?;
    support.sources.extend(data.sources.iter().copied());
    support.roots.extend(data.canonical_roots.iter().copied());
    support.temporal.extend(data.temporal.iter().cloned());
    Some(crate::Premise {
        predicate: atom.predicate.clone(),
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
        absent: false,
        coverage: None,
    })
}

/// Record one negated literal as an explicit absence premise.
fn negative_premise(
    evaluation: &mut Evaluation<'_>,
    atom: &crate::Atom,
    binding: &Binding,
) -> Option<crate::Premise> {
    if !evaluation.budget.charge(1) {
        return None;
    }
    let terms = atom
        .terms
        .iter()
        .filter_map(|term| term_value(term, binding))
        .collect::<Vec<_>>();
    Some(crate::Premise {
        predicate: atom.predicate.clone(),
        terms,
        canonical: None,
        canonical_roots: std::collections::BTreeSet::new(),
        sources: std::collections::BTreeSet::new(),
        source_availability: None,
        absent: true,
        coverage: Some(
            evaluation
                .coverage_status(&atom.predicate)
                .name()
                .to_owned(),
        ),
    })
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
    let passes = heads.len().saturating_add(2);
    for _ in 0..passes {
        let mut next = evaluation.base_coverage.clone();
        for head in &heads {
            next.insert(head.clone(), head_coverage(evaluation, head));
        }
        // A relation that failed with a type or binding error stays incomplete
        // even when its inputs happen to be complete.
        for predicate in evaluation.coverage_reasons.keys() {
            next.insert(predicate.clone(), crate::CoverageStatus::Incomplete);
        }
        if next == evaluation.coverage {
            return;
        }
        evaluation.coverage = next;
    }
}

/// The coverage a derived head may claim from its rules and their inputs.
fn head_coverage(evaluation: &Evaluation<'_>, head: &str) -> crate::CoverageStatus {
    let mut is_all_complete = true;
    let mut is_any_incomplete = false;
    let mut has_seed = false;
    for rule in &evaluation.bundle.rules {
        if rule.head.predicate != head {
            continue;
        }
        let has_self = rule.body.iter().any(
            |literal| matches!(literal, crate::Literal::Positive(atom) if atom.predicate == head),
        );
        has_seed = has_seed || !has_self;
        let is_body_complete = evaluation.budget.status == crate::ExecutionStatus::Complete
            && rule.body.iter().all(|literal| match literal {
                crate::Literal::Positive(atom) | crate::Literal::Negative(atom) => {
                    if matches!(literal, crate::Literal::Positive(_)) && atom.predicate == head {
                        true
                    } else {
                        evaluation.coverage_status(&atom.predicate)
                            == crate::CoverageStatus::Complete
                    }
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
    if is_all_complete && has_seed {
        crate::CoverageStatus::Complete
    } else if is_any_incomplete {
        crate::CoverageStatus::Incomplete
    } else {
        crate::CoverageStatus::Unknown
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
            let reason = match status {
                crate::CoverageStatus::Complete => None,
                crate::CoverageStatus::Incomplete => {
                    let reason = match evaluation.coverage_reasons.get(&predicate) {
                        Some(reason) => reason.clone(),
                        None => "declared extent or dependency is incomplete".to_owned(),
                    };
                    Some(reason)
                }
                crate::CoverageStatus::Unknown => Some("predicate coverage is unknown".to_owned()),
            };
            crate::Coverage {
                predicate,
                status,
                reason,
            }
        })
        .collect()
}

pub(crate) fn compare_values_crate(
    op: crate::CompareOp,
    left: &mneme_core::Value,
    right: &mneme_core::Value,
) -> bool {
    compare_values(op, left, right)
}

pub(crate) fn aggregate_value_crate(
    function: crate::AggregateFunction,
    values: Vec<mneme_core::Value>,
) -> Result<mneme_core::Value, &'static str> {
    aggregate_value(function, values)
}

pub(crate) fn aggregate_group_variables_crate(
    head: &crate::Atom,
    output: &str,
) -> std::collections::BTreeSet<String> {
    aggregate_group_variables(head, output)
}

pub(crate) fn term_value_crate(term: &crate::Term, binding: &Binding) -> Option<mneme_core::Value> {
    term_value(term, binding)
}

pub(crate) fn head_terms_crate(
    head: &crate::Atom,
    binding: &Binding,
) -> Option<Vec<mneme_core::Value>> {
    head_terms(head, binding)
}

pub(crate) fn record_dependencies(
    record: &mneme_core::RecordEnvelope,
) -> Vec<mneme_core::RecordId> {
    let mut deps = Vec::new();
    match record.kind {
        mneme_core::RecordKind::Relation => collect_relation_deps(record, &mut deps),
        mneme_core::RecordKind::Document => {
            if let Some(entity) = reference_target(record, "entity") {
                deps.push(entity);
            }
        }
        mneme_core::RecordKind::Evidence => collect_evidence_deps(record, &mut deps),
        mneme_core::RecordKind::Assertion => collect_assertion_deps(record, &mut deps),
        mneme_core::RecordKind::Derivation => collect_derivation_deps(record, &mut deps),
        mneme_core::RecordKind::Entity
        | mneme_core::RecordKind::SourceRevision
        | mneme_core::RecordKind::Episode
        | mneme_core::RecordKind::Checkpoint
        | mneme_core::RecordKind::Proposal
        | mneme_core::RecordKind::Decision
        | mneme_core::RecordKind::RetentionDirective
        | mneme_core::RecordKind::DocumentBinding
        | mneme_core::RecordKind::DocumentAnchor
        | mneme_core::RecordKind::Comment
        | mneme_core::RecordKind::RecognitionRun
        | mneme_core::RecordKind::RecognitionSegment => {}
    }
    debug_assert!(deps.len() < usize::MAX);
    debug_assert!(record.schema_version > 0);
    deps
}

fn collect_relation_deps(
    record: &mneme_core::RecordEnvelope,
    deps: &mut Vec<mneme_core::RecordId>,
) {
    if let Some(from) = reference_target(record, "from") {
        deps.push(from);
    }
    if let Some(to) = reference_target(record, "to") {
        deps.push(to);
    }
}

fn collect_evidence_deps(
    record: &mneme_core::RecordEnvelope,
    deps: &mut Vec<mneme_core::RecordId>,
) {
    if let Ok(evidence) = mneme_memory::EvidenceView::parse(record.clone()) {
        deps.push(evidence.assertion);
        deps.push(evidence.source);
    }
}

fn collect_assertion_deps(
    record: &mneme_core::RecordEnvelope,
    deps: &mut Vec<mneme_core::RecordId>,
) {
    if let Ok(assertion) = mneme_memory::AssertionView::parse(record.clone()) {
        deps.push(assertion.subject);
        if let Some(decision) = assertion.decision {
            deps.push(decision);
        }
        deps.extend(assertion.evidence);
    }
}

fn collect_derivation_deps(
    record: &mneme_core::RecordEnvelope,
    deps: &mut Vec<mneme_core::RecordId>,
) {
    if let Ok(derivation) = mneme_memory::DerivationView::parse(record.clone()) {
        deps.push(derivation.conclusion);
        deps.extend(derivation.premises);
    }
}

type SnapshotIndexTuple = (
    std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RecordEnvelope>,
    std::collections::BTreeMap<(String, FactKey), std::collections::BTreeSet<mneme_core::RecordId>>,
    std::collections::BTreeMap<
        mneme_core::RecordId,
        std::collections::BTreeSet<mneme_core::RecordId>,
    >,
    std::collections::BTreeSet<mneme_core::RecordId>,
);

fn index_snapshot_records(
    snapshot_records: &[mneme_core::RecordEnvelope],
    record_contributions: &std::collections::BTreeMap<mneme_core::RecordId, Vec<(String, FactKey)>>,
) -> SnapshotIndexTuple {
    let records: std::collections::BTreeMap<_, _> = snapshot_records
        .iter()
        .map(|record| (record.record_id, record.clone()))
        .collect();
    let derivation_ids: std::collections::BTreeSet<_> = snapshot_records
        .iter()
        .filter(|record| record.kind == mneme_core::RecordKind::Derivation)
        .map(|record| record.record_id)
        .collect();
    let mut reverse_deps: std::collections::BTreeMap<
        mneme_core::RecordId,
        std::collections::BTreeSet<mneme_core::RecordId>,
    > = std::collections::BTreeMap::new();
    for record in snapshot_records {
        add_reverse_dep_edges(record, &mut reverse_deps);
    }
    let key_contributors = build_key_contributors(record_contributions);
    debug_assert!(records.len() <= snapshot_records.len());
    debug_assert!(derivation_ids.len() <= records.len());
    (records, key_contributors, reverse_deps, derivation_ids)
}

fn build_key_contributors(
    record_contributions: &std::collections::BTreeMap<mneme_core::RecordId, Vec<(String, FactKey)>>,
) -> std::collections::BTreeMap<(String, FactKey), std::collections::BTreeSet<mneme_core::RecordId>>
{
    let mut key_contributors: std::collections::BTreeMap<
        (String, FactKey),
        std::collections::BTreeSet<mneme_core::RecordId>,
    > = std::collections::BTreeMap::new();
    for (record_id, entries) in record_contributions {
        for key in entries {
            key_contributors
                .entry(key.clone())
                .or_default()
                .insert(*record_id);
        }
    }
    key_contributors
}

fn add_reverse_dep_edges(
    record: &mneme_core::RecordEnvelope,
    reverse_deps: &mut std::collections::BTreeMap<
        mneme_core::RecordId,
        std::collections::BTreeSet<mneme_core::RecordId>,
    >,
) {
    for dep in record_dependencies(record) {
        reverse_deps
            .entry(dep)
            .or_default()
            .insert(record.record_id);
    }
    if record.kind == mneme_core::RecordKind::Derivation
        && let Ok(derivation) = mneme_memory::DerivationView::parse(record.clone())
    {
        reverse_deps
            .entry(record.record_id)
            .or_default()
            .insert(derivation.conclusion);
    }
}

fn remove_reverse_dep_edges(
    record: &mneme_core::RecordEnvelope,
    reverse_deps: &mut std::collections::BTreeMap<
        mneme_core::RecordId,
        std::collections::BTreeSet<mneme_core::RecordId>,
    >,
) {
    for dep in record_dependencies(record) {
        if let Some(set) = reverse_deps.get_mut(&dep) {
            set.remove(&record.record_id);
            if set.is_empty() {
                reverse_deps.remove(&dep);
            }
        }
    }
    if record.kind == mneme_core::RecordKind::Derivation
        && let Ok(derivation) = mneme_memory::DerivationView::parse(record.clone())
        && let Some(set) = reverse_deps.get_mut(&record.record_id)
    {
        set.remove(&derivation.conclusion);
        if set.is_empty() {
            reverse_deps.remove(&record.record_id);
        }
    }
}

pub(crate) struct BaseAdvanceRequest<'a> {
    pub workspace: &'a mneme_store::Workspace,
    pub target_revision: mneme_core::WorkspaceRevisionId,
    pub next_context: &'a crate::BuildContext,
    pub bundle: &'a crate::RuleBundle,
    pub limits: &'a crate::Limits,
    pub incomplete_extents: &'a std::collections::BTreeSet<String>,
    pub at: Option<mneme_core::Timestamp>,
    pub start: std::time::Instant,
}

pub(crate) struct BaseAdvanceResult {
    pub next_base: BaseSnapshot,
    pub eligibility_generation: u64,
    pub base_deltas: std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    pub dirty_provenance: std::collections::BTreeSet<(String, FactKey)>,
    pub work: u64,
    pub limit_reached: bool,
    pub status: crate::ExecutionStatus,
}

struct SnapshotDeltaState {
    records: std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RecordEnvelope>,
    history: std::collections::BTreeMap<
        (mneme_core::RecordId, mneme_core::RevisionId),
        mneme_core::RecordEnvelope,
    >,
    revision_sequences: std::collections::BTreeMap<mneme_core::WorkspaceRevisionId, u64>,
    reverse_deps: std::collections::BTreeMap<
        mneme_core::RecordId,
        std::collections::BTreeSet<mneme_core::RecordId>,
    >,
    derivation_ids: std::collections::BTreeSet<mneme_core::RecordId>,
    seed_changed: std::collections::BTreeSet<mneme_core::RecordId>,
}

impl SnapshotDeltaState {
    fn from_base(base: &BaseSnapshot) -> Self {
        Self {
            records: base.records.clone(),
            history: base.history.clone(),
            revision_sequences: base.revision_sequences.clone(),
            reverse_deps: base.reverse_deps.clone(),
            derivation_ids: base.derivation_ids.clone(),
            seed_changed: std::collections::BTreeSet::new(),
        }
    }
}

pub(crate) fn advance_base_snapshot(
    base: &BaseSnapshot,
    request: BaseAdvanceRequest<'_>,
) -> Result<BaseAdvanceResult, crate::Error> {
    assert!(request.limits.max_work > 0);
    let delta = request
        .workspace
        .revision_delta(base.revision, request.target_revision, None)?;
    let suppressions = request.workspace.active_suppressions()?;
    let current_sources =
        crate::source_availability_overlay(request.workspace, request.target_revision)?;
    let mut state = SnapshotDeltaState::from_base(base);

    collect_removed_seeds(base, &delta, &mut state);
    let added_visible = filter_visible_records(&delta.added, &base.scope, &base.access);
    apply_added_records(request.workspace, &delta, &added_visible, &mut state)?;
    collect_overlay_changed_seeds(
        base,
        &suppressions,
        &current_sources,
        delta.to_sequence,
        &mut state,
    );

    let impacted =
        bfs_impacted_records(&state.seed_changed, &base.reverse_deps, &state.reverse_deps);
    let (old_rows, eval_ids, next_facts, next_contribs, next_key_contribs) =
        detach_impacted_contributions(base, &impacted, &state.records);
    let view = build_delta_view(base, request.workspace, &delta, &state, &suppressions);
    let mut reconciled = ReconciledFacts {
        next_facts,
        next_contribs,
        next_key_contribs,
    };
    let eval_parts = evaluate_delta_parts(
        DeltaEvalInput {
            base,
            request: &request,
            view: &view,
            records: &state.records,
            eval_ids: &eval_ids,
            current_sources: &current_sources,
            old_rows: &old_rows,
        },
        &mut reconciled,
    )?;
    debug_assert_eq!(delta.to_revision, request.target_revision);
    Ok(finish_base_advance(FinishBaseAdvance {
        base,
        delta: &delta,
        state,
        suppressions,
        current_sources,
        reconciled,
        eval_parts,
        max_work: request.limits.max_work,
    }))
}

struct DeltaEvalInput<'a> {
    base: &'a BaseSnapshot,
    request: &'a BaseAdvanceRequest<'a>,
    view: &'a mneme_memory::View,
    records: &'a std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RecordEnvelope>,
    eval_ids: &'a std::collections::BTreeSet<mneme_core::RecordId>,
    current_sources: &'a AvailabilityMap,
    old_rows: &'a std::collections::BTreeMap<(String, FactKey), crate::FactData>,
}

fn evaluate_delta_parts(
    input: DeltaEvalInput<'_>,
    reconciled: &mut ReconciledFacts,
) -> Result<DeltaEvalParts, crate::Error> {
    let DeltaEvalInput {
        base,
        request,
        view,
        records,
        eval_ids,
        current_sources,
        old_rows,
    } = input;
    assert!(request.limits.max_work > 0);
    let mut evaluation = Evaluation {
        bundle: request.bundle,
        context: request.next_context,
        budget: new_budget(request.limits, request.start, base.support_truncated),
        facts: std::collections::BTreeMap::new(),
        coverage: std::collections::BTreeMap::new(),
        base_coverage: std::collections::BTreeMap::new(),
        coverage_reasons: std::collections::BTreeMap::new(),
        current_sources,
        at: request.at,
        derivation_eligibility: std::collections::BTreeMap::new(),
        record_contributions: std::collections::BTreeMap::new(),
    };
    initialize_base_coverage(&mut evaluation, request.incomplete_extents);
    evaluate_impacted_records(view, records, eval_ids, &mut evaluation);
    let (base_deltas, dirty_provenance) = reconcile_delta_facts(
        ReconcileDeltaInput {
            old_rows,
            temp_facts: &evaluation.facts,
            temp_contribs: &evaluation.record_contributions,
            target_revision: request.target_revision,
        },
        reconciled,
    )?;
    let coverage = final_coverage(&evaluation);
    let status = overall_status(evaluation.budget.status, &coverage);
    debug_assert!(
        evaluation.budget.work <= request.limits.max_work || evaluation.budget.limit_reached
    );
    Ok(DeltaEvalParts {
        coverage,
        status,
        work: evaluation.budget.work,
        is_support_truncated: evaluation.budget.support_truncated,
        is_limit_reached: evaluation.budget.limit_reached,
        base_coverage: evaluation.base_coverage,
        coverage_reasons: evaluation.coverage_reasons,
        derivation_eligibility: evaluation.derivation_eligibility,
        base_deltas,
        dirty_provenance,
    })
}

struct ReconciledFacts {
    next_facts: std::collections::BTreeMap<String, FactStore>,
    next_contribs: std::collections::BTreeMap<mneme_core::RecordId, Vec<(String, FactKey)>>,
    next_key_contribs: std::collections::BTreeMap<
        (String, FactKey),
        std::collections::BTreeSet<mneme_core::RecordId>,
    >,
}

struct DeltaEvalParts {
    coverage: Vec<crate::Coverage>,
    status: crate::ExecutionStatus,
    work: u64,
    is_support_truncated: bool,
    is_limit_reached: bool,
    base_coverage: std::collections::BTreeMap<String, crate::CoverageStatus>,
    coverage_reasons: std::collections::BTreeMap<String, String>,
    derivation_eligibility: std::collections::BTreeMap<
        mneme_core::RecordId,
        std::collections::BTreeSet<mneme_core::RecordId>,
    >,
    base_deltas: std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    dirty_provenance: std::collections::BTreeSet<(String, FactKey)>,
}

struct FinishBaseAdvance<'a> {
    base: &'a BaseSnapshot,
    delta: &'a mneme_store::RevisionDelta,
    state: SnapshotDeltaState,
    suppressions: Vec<mneme_store::RetentionSuppression>,
    current_sources: AvailabilityMap,
    reconciled: ReconciledFacts,
    eval_parts: DeltaEvalParts,
    max_work: u64,
}

fn finish_base_advance(args: FinishBaseAdvance<'_>) -> BaseAdvanceResult {
    let FinishBaseAdvance {
        base,
        delta,
        state,
        suppressions,
        current_sources,
        reconciled,
        eval_parts,
        max_work,
    } = args;
    assert!(max_work > 0);
    debug_assert!(eval_parts.work <= max_work || eval_parts.is_limit_reached);
    let next_base = BaseSnapshot {
        revision: delta.to_revision,
        sequence: delta.to_sequence,
        scope: base.scope.clone(),
        access: base.access.clone(),
        records: state.records,
        history: state.history,
        revision_sequences: state.revision_sequences,
        suppressions,
        facts: reconciled.next_facts,
        record_contributions: reconciled.next_contribs,
        key_contributors: reconciled.next_key_contribs,
        reverse_deps: state.reverse_deps,
        derivation_ids: state.derivation_ids,
        base_coverage: eval_parts.base_coverage,
        coverage_reasons: eval_parts.coverage_reasons,
        current_sources,
        derivation_eligibility: eval_parts.derivation_eligibility,
        coverage: eval_parts.coverage,
        status: eval_parts.status,
        work: eval_parts.work,
        support_truncated: eval_parts.is_support_truncated,
        limit_reached: eval_parts.is_limit_reached,
    };
    BaseAdvanceResult {
        next_base,
        eligibility_generation: delta.eligibility_generation,
        base_deltas: eval_parts.base_deltas,
        dirty_provenance: eval_parts.dirty_provenance,
        work: eval_parts.work,
        limit_reached: eval_parts.is_limit_reached,
        status: eval_parts.status,
    }
}

fn collect_removed_seeds(
    base: &BaseSnapshot,
    delta: &mneme_store::RevisionDelta,
    state: &mut SnapshotDeltaState,
) {
    assert_eq!(delta.from_revision, base.revision);
    let mut to_remove = std::collections::BTreeSet::new();
    for removed in &delta.removed {
        if state.records.contains_key(&removed.record_id) {
            to_remove.insert(removed.record_id);
        }
    }
    for (record_id, envelope) in &base.records {
        if delta.forgotten_identities.contains(record_id)
            || delta
                .forgotten_revisions
                .contains(&(*record_id, envelope.revision_id))
        {
            to_remove.insert(*record_id);
        }
    }
    debug_assert!(to_remove.len() <= base.records.len());
    for record_id in to_remove {
        state.seed_changed.insert(record_id);
        if let Some(old_record) = state.records.remove(&record_id) {
            remove_reverse_dep_edges(&old_record, &mut state.reverse_deps);
        }
        state.derivation_ids.remove(&record_id);
        state.history.retain(|(id, _), _| *id != record_id);
    }
}

fn filter_visible_records(
    added: &[mneme_core::RecordEnvelope],
    scope: &mneme_core::ScopeId,
    access: &mneme_memory::Access,
) -> Vec<mneme_core::RecordEnvelope> {
    added
        .iter()
        .filter(|record| {
            mneme_kernel::isolation::record_visible(&mneme_kernel::isolation::VisibilityFacts {
                same_scope: record.scope == *scope,
                record_class: record.scope.class().to_kernel(),
                include_hypothetical: false,
                record_scope_authorized: access.allows(&record.scope),
            })
        })
        .cloned()
        .collect()
}

fn apply_added_records(
    workspace: &mneme_store::Workspace,
    delta: &mneme_store::RevisionDelta,
    added_visible: &[mneme_core::RecordEnvelope],
    state: &mut SnapshotDeltaState,
) -> Result<(), crate::Error> {
    assert!(added_visible.len() <= delta.added.len());
    let mut added_ids = std::collections::BTreeSet::new();
    for record in added_visible {
        state.seed_changed.insert(record.record_id);
        added_ids.insert(record.record_id);
        if let Some(previous) = state.records.insert(record.record_id, record.clone()) {
            remove_reverse_dep_edges(&previous, &mut state.reverse_deps);
        }
        add_reverse_dep_edges(record, &mut state.reverse_deps);
        if record.kind == mneme_core::RecordKind::Derivation {
            state.derivation_ids.insert(record.record_id);
        }
    }
    let mut wanted_revisions = std::collections::BTreeSet::from([delta.to_revision]);
    fetch_added_histories(
        workspace,
        delta,
        AddedHistoryInputs {
            visible: added_visible,
            ids: &added_ids,
        },
        state,
        &mut wanted_revisions,
    )?;
    for record in added_visible {
        collect_wanted_revisions(record, &mut wanted_revisions)?;
    }
    wanted_revisions.retain(|rev| !state.revision_sequences.contains_key(rev));
    if !wanted_revisions.is_empty() {
        let seqs = workspace.revision_sequences_for(&wanted_revisions)?;
        state.revision_sequences.extend(seqs);
    }
    debug_assert!(state.revision_sequences.contains_key(&delta.to_revision));
    Ok(())
}

struct AddedHistoryInputs<'a> {
    visible: &'a [mneme_core::RecordEnvelope],
    ids: &'a std::collections::BTreeSet<mneme_core::RecordId>,
}

fn fetch_added_histories(
    workspace: &mneme_store::Workspace,
    delta: &mneme_store::RevisionDelta,
    inputs: AddedHistoryInputs<'_>,
    state: &mut SnapshotDeltaState,
    wanted_revisions: &mut std::collections::BTreeSet<mneme_core::WorkspaceRevisionId>,
) -> Result<(), crate::Error> {
    if inputs.ids.is_empty() {
        return Ok(());
    }
    assert!(!inputs.visible.is_empty());
    let temp_snapshot = mneme_store::Snapshot {
        revision: delta.to_revision,
        sequence: delta.to_sequence,
        parent: delta.to_parent,
        manifest_digest: delta.to_manifest_digest,
        eligibility_generation: delta.eligibility_generation,
        records: inputs.visible.to_vec(),
        index: mneme_core::SnapshotIndex::new(),
    };
    let fetched = workspace.record_histories_of(&temp_snapshot, inputs.ids)?;
    for envelopes in fetched.into_values() {
        for envelope in envelopes {
            collect_wanted_revisions(&envelope, wanted_revisions)?;
            state
                .history
                .insert((envelope.record_id, envelope.revision_id), envelope);
        }
    }
    debug_assert!(state.history.len() >= inputs.ids.len());
    Ok(())
}

fn collect_wanted_revisions(
    record: &mneme_core::RecordEnvelope,
    wanted: &mut std::collections::BTreeSet<mneme_core::WorkspaceRevisionId>,
) -> Result<(), crate::Error> {
    if record.kind == mneme_core::RecordKind::Decision {
        let decision =
            mneme_memory::DecisionView::parse(record.clone()).map_err(crate::Error::Engine)?;
        wanted.insert(decision.input_revision);
    } else if record.kind == mneme_core::RecordKind::Derivation {
        let derivation =
            mneme_memory::DerivationView::parse(record.clone()).map_err(crate::Error::Engine)?;
        wanted.insert(derivation.evaluation_revision);
    }
    Ok(())
}

fn collect_overlay_changed_seeds(
    base: &BaseSnapshot,
    new_suppressions: &[mneme_store::RetentionSuppression],
    new_sources: &AvailabilityMap,
    new_sequence: u64,
    state: &mut SnapshotDeltaState,
) {
    assert!(new_sequence < u64::MAX);
    let old_sup = suppression_key_set(&base.suppressions);
    let new_sup = suppression_key_set(new_suppressions);
    for (target, _, _) in old_sup.symmetric_difference(&new_sup) {
        state.seed_changed.insert(*target);
    }
    for (source_id, avail) in &base.current_sources {
        if new_sources.get(source_id) != Some(avail) {
            state.seed_changed.insert(*source_id);
        }
    }
    for (source_id, avail) in new_sources {
        if base.current_sources.get(source_id) != Some(avail) {
            state.seed_changed.insert(*source_id);
        }
    }
    if new_sequence < base.sequence {
        state
            .seed_changed
            .extend(state.derivation_ids.iter().copied());
    }
    debug_assert!(new_sources.len() < usize::MAX);
}

fn suppression_key_set(
    suppressions: &[mneme_store::RetentionSuppression],
) -> std::collections::BTreeSet<(
    mneme_core::RecordId,
    Option<mneme_core::RevisionId>,
    &'static str,
)> {
    suppressions
        .iter()
        .map(|s| (s.target, s.revision, s.mode.as_str()))
        .collect()
}

fn bfs_impacted_records(
    seeds: &std::collections::BTreeSet<mneme_core::RecordId>,
    old_reverse: &std::collections::BTreeMap<
        mneme_core::RecordId,
        std::collections::BTreeSet<mneme_core::RecordId>,
    >,
    new_reverse: &std::collections::BTreeMap<
        mneme_core::RecordId,
        std::collections::BTreeSet<mneme_core::RecordId>,
    >,
) -> std::collections::BTreeSet<mneme_core::RecordId> {
    let mut visited = std::collections::BTreeSet::new();
    let mut queue = std::collections::VecDeque::new();
    for id in seeds {
        if visited.insert(*id) {
            queue.push_back(*id);
        }
    }
    while let Some(current) = queue.pop_front() {
        for map in [old_reverse, new_reverse] {
            if let Some(dependents) = map.get(&current) {
                for dependent in dependents {
                    if visited.insert(*dependent) {
                        queue.push_back(*dependent);
                    }
                }
            }
        }
    }
    debug_assert!(visited.len() >= seeds.len());
    debug_assert!(queue.is_empty());
    visited
}

type DetachedState = (
    std::collections::BTreeMap<(String, FactKey), crate::FactData>,
    std::collections::BTreeSet<mneme_core::RecordId>,
    std::collections::BTreeMap<String, FactStore>,
    std::collections::BTreeMap<mneme_core::RecordId, Vec<(String, FactKey)>>,
    std::collections::BTreeMap<(String, FactKey), std::collections::BTreeSet<mneme_core::RecordId>>,
);

fn detach_impacted_contributions(
    base: &BaseSnapshot,
    impacted: &std::collections::BTreeSet<mneme_core::RecordId>,
    new_records: &std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RecordEnvelope>,
) -> DetachedState {
    assert!(impacted.len() < usize::MAX);
    let mut next_facts = base.facts.clone();
    let mut next_contribs = base.record_contributions.clone();
    let mut next_key_contribs = base.key_contributors.clone();
    let mut eval_ids = impacted.clone();
    let mut touched_keys = std::collections::BTreeSet::new();

    let old_rows = collect_detached_old_rows(
        impacted,
        &next_facts,
        &mut next_contribs,
        &mut next_key_contribs,
        &mut touched_keys,
    );
    for (pred, key) in &touched_keys {
        if let Some(remaining) = next_key_contribs.get(&(pred.clone(), key.clone())) {
            for other_id in remaining {
                if new_records.contains_key(other_id) {
                    eval_ids.insert(*other_id);
                }
            }
        }
        if let Some(store) = next_facts.get_mut(pred) {
            store.rows.remove(key);
        }
    }
    for id in &eval_ids {
        if !impacted.contains(id)
            && let Some(entries) = next_contribs.remove(id)
        {
            for (pred, key) in entries {
                if let Some(set) = next_key_contribs.get_mut(&(pred, key)) {
                    set.remove(id);
                }
            }
        }
    }
    next_key_contribs.retain(|_, set| !set.is_empty());
    debug_assert!(eval_ids.len() >= impacted.len());
    (
        old_rows,
        eval_ids,
        next_facts,
        next_contribs,
        next_key_contribs,
    )
}

fn collect_detached_old_rows(
    impacted: &std::collections::BTreeSet<mneme_core::RecordId>,
    next_facts: &std::collections::BTreeMap<String, FactStore>,
    next_contribs: &mut std::collections::BTreeMap<mneme_core::RecordId, Vec<(String, FactKey)>>,
    next_key_contribs: &mut std::collections::BTreeMap<
        (String, FactKey),
        std::collections::BTreeSet<mneme_core::RecordId>,
    >,
    touched_keys: &mut std::collections::BTreeSet<(String, FactKey)>,
) -> std::collections::BTreeMap<(String, FactKey), crate::FactData> {
    assert!(impacted.len() < usize::MAX);
    let mut old_row_entries = Vec::with_capacity(impacted.len());
    for id in impacted {
        if let Some(entries) = next_contribs.remove(id) {
            for (pred, key) in entries {
                if let Some(data) = next_facts.get(&pred).and_then(|s| s.rows.get(&key)) {
                    old_row_entries.push(((pred.clone(), key.clone()), data.clone()));
                }
                if let Some(set) = next_key_contribs.get_mut(&(pred.clone(), key.clone())) {
                    set.remove(id);
                }
                touched_keys.insert((pred, key));
            }
        }
    }
    let old_rows: std::collections::BTreeMap<_, _> = old_row_entries.into_iter().collect();
    debug_assert!(old_rows.len() <= touched_keys.len());
    old_rows
}

fn build_delta_view(
    base: &BaseSnapshot,
    workspace: &mneme_store::Workspace,
    delta: &mneme_store::RevisionDelta,
    state: &SnapshotDeltaState,
    suppressions: &[mneme_store::RetentionSuppression],
) -> mneme_memory::View {
    let snapshot = mneme_store::Snapshot {
        revision: delta.to_revision,
        sequence: delta.to_sequence,
        parent: delta.to_parent,
        manifest_digest: delta.to_manifest_digest,
        eligibility_generation: delta.eligibility_generation,
        records: state.records.values().cloned().collect(),
        index: mneme_core::SnapshotIndex::new(),
    };
    mneme_memory::View::with_retention(
        snapshot,
        workspace.root(),
        state.history.clone(),
        state.revision_sequences.clone(),
        suppressions.to_vec(),
    )
    .with_access(base.access.clone())
}

fn evaluate_impacted_records(
    view: &mneme_memory::View,
    records: &std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RecordEnvelope>,
    eval_ids: &std::collections::BTreeSet<mneme_core::RecordId>,
    evaluation: &mut Evaluation<'_>,
) {
    assert!(evaluation.budget.limits.max_work > 0);
    for id in eval_ids {
        let Some(record) = records.get(id) else {
            continue;
        };
        if record.scope != evaluation.context.scope {
            continue;
        }
        if !evaluation.budget.charge(1) {
            stop_loading(evaluation);
            return;
        }
        load_record_facts(view, record, evaluation);
        if !evaluation.budget.is_active() {
            stop_loading(evaluation);
            return;
        }
    }
    debug_assert!(evaluation.budget.is_active());
}

type ReconciledDeltaOutput = (
    std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    std::collections::BTreeSet<(String, FactKey)>,
);

struct ReconcileDeltaInput<'a> {
    old_rows: &'a std::collections::BTreeMap<(String, FactKey), crate::FactData>,
    temp_facts: &'a std::collections::BTreeMap<String, FactStore>,
    temp_contribs: &'a std::collections::BTreeMap<mneme_core::RecordId, Vec<(String, FactKey)>>,
    target_revision: mneme_core::WorkspaceRevisionId,
}

fn reconcile_delta_facts(
    input: ReconcileDeltaInput<'_>,
    reconciled: &mut ReconciledFacts,
) -> Result<ReconciledDeltaOutput, crate::Error> {
    assert!(input.old_rows.len() < usize::MAX);
    let mut base_deltas: std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>> =
        std::collections::BTreeMap::new();
    let mut dirty_provenance = std::collections::BTreeSet::new();

    for store in reconciled.next_facts.values_mut() {
        for data in store.rows.values_mut() {
            for support in &mut data.supports {
                support.revision = input.target_revision;
            }
        }
    }
    for ((pred, key), old_data) in input.old_rows {
        if let Some(new_data) = input.temp_facts.get(pred).and_then(|s| s.rows.get(key)) {
            if !same_semantic_fact_data(old_data, new_data) {
                dirty_provenance.insert((pred.clone(), key.clone()));
            }
            reconciled
                .next_facts
                .entry(pred.clone())
                .or_default()
                .rows
                .insert(key.clone(), new_data.clone());
        } else {
            base_deltas
                .entry(pred.clone())
                .or_default()
                .insert_weighted(key.clone(), -1)?;
        }
    }
    for (pred, store) in input.temp_facts {
        for (key, new_data) in &store.rows {
            if !input.old_rows.contains_key(&(pred.clone(), key.clone())) {
                reconciled
                    .next_facts
                    .entry(pred.clone())
                    .or_default()
                    .rows
                    .insert(key.clone(), new_data.clone());
                base_deltas
                    .entry(pred.clone())
                    .or_default()
                    .insert_weighted(key.clone(), 1)?;
            }
        }
    }
    for (record_id, entries) in input.temp_contribs {
        for (pred, key) in entries {
            reconciled
                .next_key_contribs
                .entry((pred.clone(), key.clone()))
                .or_default()
                .insert(*record_id);
        }
        reconciled.next_contribs.insert(*record_id, entries.clone());
    }
    debug_assert!(dirty_provenance.len() <= input.old_rows.len());
    Ok((base_deltas, dirty_provenance))
}

fn same_semantic_fact_data(left: &crate::FactData, right: &crate::FactData) -> bool {
    left.sources == right.sources
        && left.canonical == right.canonical
        && left.canonical_roots == right.canonical_roots
        && left.temporal == right.temporal
        && left.truncated == right.truncated
        && left.supports.len() == right.supports.len()
        && left.supports.iter().zip(&right.supports).all(|(a, b)| {
            a.rule_id == b.rule_id
                && a.rule_version == b.rule_version
                && a.premises == b.premises
                && a.sources == b.sources
                && a.temporal_parameters == b.temporal_parameters
                && a.scope == b.scope
                && a.truncated == b.truncated
        })
}

pub(crate) struct FactDataBuildRequest<'a> {
    pub rule: &'a crate::Rule,
    pub context: &'a crate::BuildContext,
    pub limits: &'a crate::Limits,
    pub facts: &'a std::collections::BTreeMap<String, FactStore>,
    pub coverage_map: &'a std::collections::BTreeMap<String, crate::CoverageStatus>,
    pub current_sources: &'a AvailabilityMap,
    pub at: Option<mneme_core::Timestamp>,
    pub start: std::time::Instant,
    pub bindings: &'a [Binding],
    pub target_terms: &'a FactKey,
}

pub(crate) fn build_ordinary_fact_data_from_bindings(
    request: FactDataBuildRequest<'_>,
    target_store: &mut FactStore,
) -> bool {
    build_fact_data_with(
        &request,
        target_store,
        |rule, evaluation, target_terms, temp| {
            for binding in request.bindings {
                let contents =
                    instantiated_support(rule, evaluation, binding, target_terms.clone());
                merge_fact_contents(
                    temp,
                    &rule.head.predicate,
                    contents,
                    request.limits.max_supports_per_fact,
                );
            }
        },
    )
}

pub(crate) fn build_aggregate_fact_data_from_bindings(
    request: FactDataBuildRequest<'_>,
    target_store: &mut FactStore,
) -> bool {
    build_fact_data_with(
        &request,
        target_store,
        |rule, evaluation, target_terms, temp| {
            let binding_indices: Vec<usize> = (0..request.bindings.len()).collect();
            let row = AggregateRow {
                head_terms: target_terms.clone(),
                binding_indices,
            };
            let contents = aggregate_support(rule, evaluation, request.bindings, &row);
            merge_fact_contents(
                temp,
                &rule.head.predicate,
                contents,
                request.limits.max_supports_per_fact,
            );
        },
    )
}

fn build_fact_data_with<F>(
    request: &FactDataBuildRequest<'_>,
    target_store: &mut FactStore,
    build: F,
) -> bool
where
    F: FnOnce(
        &crate::Rule,
        &mut Evaluation<'_>,
        &FactKey,
        &mut std::collections::BTreeMap<String, FactStore>,
    ),
{
    assert!(!request.rule.head.predicate.is_empty());
    let empty_bundle = crate::RuleBundle::new(crate::RuleBundleOptions {
        id: request.context.rule_bundle_id.clone(),
        version: request.context.rule_bundle_version.clone(),
        schema_version: request.context.schema_version,
        base_predicates: std::collections::BTreeMap::new(),
        complete_predicates: std::collections::BTreeSet::new(),
        rules: Vec::new(),
    });
    let mut evaluation = Evaluation {
        bundle: &empty_bundle,
        context: request.context,
        budget: new_budget(request.limits, request.start, false),
        facts: request.facts.clone(),
        coverage: request.coverage_map.clone(),
        base_coverage: request.coverage_map.clone(),
        coverage_reasons: std::collections::BTreeMap::new(),
        current_sources: request.current_sources,
        at: request.at,
        derivation_eligibility: std::collections::BTreeMap::new(),
        record_contributions: std::collections::BTreeMap::new(),
    };
    let mut temp = std::collections::BTreeMap::new();
    if let Some(existing) = target_store.rows.get(request.target_terms) {
        let mut s = FactStore::default();
        s.rows
            .insert(request.target_terms.clone(), existing.clone());
        temp.insert(request.rule.head.predicate.clone(), s);
    }
    build(
        request.rule,
        &mut evaluation,
        request.target_terms,
        &mut temp,
    );
    debug_assert!(request.limits.max_supports_per_fact > 0);
    if let Some(updated) = temp
        .get(&request.rule.head.predicate)
        .and_then(|s| s.rows.get(request.target_terms))
    {
        let is_truncated = updated.truncated;
        target_store
            .rows
            .insert(request.target_terms.clone(), updated.clone());
        if is_truncated {
            target_store.truncated = true;
        }
        return is_truncated;
    }
    false
}

fn merge_fact_contents(
    temp_facts: &mut std::collections::BTreeMap<String, FactStore>,
    predicate: &str,
    contents: FactContents,
    max_supports: usize,
) {
    assert!(!predicate.is_empty());
    assert!(max_supports > 0);
    let FactContents {
        terms,
        support,
        sources,
        canonical,
        canonical_roots,
        temporal,
    } = contents;
    let store = temp_facts.entry(predicate.to_owned()).or_default();
    if let Some(data) = store.rows.get_mut(&terms) {
        if let Some(existing) = data
            .supports
            .iter_mut()
            .find(|existing| same_proof(existing, &support))
        {
            merge_premises(existing, &support);
            data.sources.extend(sources);
            data.canonical_roots.extend(canonical_roots);
            merge_strings(&mut data.temporal, temporal);
            return;
        }
        if data.supports.len() >= max_supports {
            data.truncated = true;
            store.truncated = true;
            return;
        }
        data.supports.push(support);
        data.sources.extend(sources);
        data.canonical_roots.extend(canonical_roots);
        merge_strings(&mut data.temporal, temporal);
        return;
    }
    store.rows.insert(
        terms,
        crate::FactData {
            supports: vec![support],
            sources,
            truncated: false,
            canonical,
            canonical_roots,
            temporal,
        },
    );
}

pub(crate) struct CoverageCheckRequest<'a> {
    pub base: &'a BaseSnapshot,
    pub bundle: &'a crate::RuleBundle,
    pub context: &'a crate::BuildContext,
    pub limits: &'a crate::Limits,
    pub fact_predicates: &'a std::collections::BTreeSet<String>,
    pub coverage_reasons: &'a std::collections::BTreeMap<String, String>,
    pub at: Option<mneme_core::Timestamp>,
    pub start: std::time::Instant,
}

pub(crate) fn compute_coverage_for_facts(
    request: CoverageCheckRequest<'_>,
) -> (
    std::collections::BTreeMap<String, crate::CoverageStatus>,
    Vec<crate::Coverage>,
    crate::ExecutionStatus,
) {
    assert!(request.limits.max_work > 0);
    let stub_facts: std::collections::BTreeMap<_, _> = request
        .fact_predicates
        .iter()
        .map(|predicate| (predicate.clone(), FactStore::default()))
        .collect();
    debug_assert_eq!(stub_facts.len(), request.fact_predicates.len());
    let mut evaluation = Evaluation {
        bundle: request.bundle,
        context: request.context,
        budget: new_budget(request.limits, request.start, false),
        facts: stub_facts,
        coverage: request.base.base_coverage.clone(),
        base_coverage: request.base.base_coverage.clone(),
        coverage_reasons: request.coverage_reasons.clone(),
        current_sources: &request.base.current_sources,
        at: request.at,
        derivation_eligibility: request.base.derivation_eligibility.clone(),
        record_contributions: std::collections::BTreeMap::new(),
    };
    update_derived_coverage(&mut evaluation);
    let coverage = final_coverage(&evaluation);
    let status = overall_status(evaluation.budget.status, &coverage);
    (evaluation.coverage, coverage, status)
}
