//! Snapshot fact loading, bounded fixpoint evaluation, and coverage.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

type FactKey = Vec<mneme_core::Value>;
pub(super) type Binding = std::collections::BTreeMap<String, mneme_core::Value>;
pub(crate) type AvailabilityMap =
    std::collections::BTreeMap<mneme_core::RecordId, mneme_memory::SourceAvailability>;

/// The instant one bounded build started, taken before any snapshot is read.
#[allow(unknown_lints, ambient_clock)] // one evaluation start time for the bounded build
pub(crate) fn evaluation_start() -> std::time::Instant {
    std::time::Instant::now()
}

#[derive(Clone, Debug, Default)]
struct FactColumnIndex {
    buckets: std::collections::BTreeMap<Vec<mneme_core::Value>, Vec<FactKey>>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct FactStore {
    pub rows: std::collections::BTreeMap<FactKey, crate::FactData>,
    pub truncated: bool,
    indexes: std::collections::BTreeMap<(usize, Vec<usize>), FactColumnIndex>,
    pub(super) tries: std::collections::BTreeMap<(usize, Vec<usize>), crate::freejoin::FactTrie>,
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
pub(super) struct Budget<'a> {
    pub(super) limits: &'a crate::Limits,
    work: u64,
    stored_rows: u64,
    start: std::time::Instant,
    cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    status: crate::ExecutionStatus,
    limit_reached: bool,
    support_truncated: bool,
}

impl<'a> Budget<'a> {
    fn is_active(&self) -> bool {
        self.status == crate::ExecutionStatus::Complete
    }

    fn cancelled(&self) -> bool {
        self.cancellation
            .as_ref()
            .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed))
    }

    fn stop(&mut self, status: crate::ExecutionStatus) {
        self.limit_reached = true;
        if self.status == crate::ExecutionStatus::Complete {
            self.status = status;
        }
    }

    /// Charge work before it is spent, and notice cancellation and the clock.
    #[allow(unknown_lints, ambient_clock)] // wall-clock budget is the evaluation shell
    pub(super) fn charge(&mut self, amount: u64) -> bool {
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
    fn charge_row(&mut self) -> bool {
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

pub(super) struct Evaluation<'a> {
    bundle: &'a crate::RuleBundle,
    context: &'a crate::BuildContext,
    pub(super) budget: Budget<'a>,
    pub(super) facts: std::collections::BTreeMap<String, FactStore>,
    coverage: std::collections::BTreeMap<String, crate::CoverageStatus>,
    base_coverage: std::collections::BTreeMap<String, crate::CoverageStatus>,
    coverage_reasons: std::collections::BTreeMap<String, String>,
    current_sources: &'a AvailabilityMap,
    at: Option<mneme_core::Timestamp>,
    derivation_eligibility: std::collections::BTreeMap<
        mneme_core::RecordId,
        std::collections::BTreeSet<mneme_core::RecordId>,
    >,
}

impl Evaluation<'_> {
    pub(super) fn coverage_status(&self, predicate: &str) -> crate::CoverageStatus {
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
fn canonical_extents() -> &'static [&'static str] {
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
    };
    initialize_base_coverage(&mut evaluation, &request.incomplete_extents);
    load_base_facts(view, &mut evaluation);
    evaluate_rules(&mut evaluation, &program.strata);
    let coverage = final_coverage(&evaluation);
    let status = if evaluation.budget.status != crate::ExecutionStatus::Complete {
        evaluation.budget.status
    } else if coverage
        .iter()
        .any(|coverage| coverage.status != crate::CoverageStatus::Complete)
    {
        crate::ExecutionStatus::Partial
    } else {
        crate::ExecutionStatus::Complete
    };
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
    if !store.indexes.is_empty() {
        for ((arity, cols), index) in &mut store.indexes {
            if terms.len() == *arity {
                let key = project_key(&terms, cols);
                let bucket = index.buckets.entry(key).or_default();
                if let Err(pos) = bucket.binary_search(&terms) {
                    bucket.insert(pos, terms.clone());
                }
            }
        }
    }
    if !store.tries.is_empty() {
        for ((arity, cols), trie) in &mut store.tries {
            if terms.len() == *arity {
                trie.insert(&terms, cols);
            }
        }
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
pub(super) enum RuleOutcome {
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
    let positive_count = rule
        .body
        .iter()
        .filter(|literal| matches!(literal, crate::Literal::Positive(_)))
        .count();
    let bindings = match if positive_count >= 2 {
        crate::freejoin::evaluate_free_join_body(evaluation, rule)
    } else {
        evaluate_planned_body(evaluation, rule)
    } {
        Ok(bindings) => bindings,
        Err(outcome) => return outcome,
    };
    if let Some(aggregate) = aggregate {
        return evaluate_aggregate_rule(evaluation, rule, &aggregate, &bindings);
    }
    evaluate_ordinary_rule(evaluation, rule, &bindings)
}

fn evaluate_planned_body(
    evaluation: &mut Evaluation<'_>,
    rule: &crate::Rule,
) -> Result<RuleBindings, RuleOutcome> {
    let plan = plan_rule_body(rule, &evaluation.facts);
    let mut bindings = execute_plan(evaluation, rule, &plan)?;
    if plan.positive_reordered && bindings.len() > 1 {
        sort_bindings_by_written_order(rule, &mut bindings);
    }
    Ok(bindings)
}

pub(super) type RuleBindings = Vec<Binding>;

#[derive(Clone, Debug)]
enum PlanStep {
    Positive {
        body_index: usize,
        bound_cols: Vec<usize>,
    },
    Negative {
        body_index: usize,
    },
    Compare {
        body_index: usize,
    },
}

struct RulePlan {
    steps: Vec<PlanStep>,
    positive_reordered: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IndexState {
    Ready,
    Empty,
}

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

/// Plan body execution greedily: run ready comparisons/negations as soon as
/// their variables are bound, and pick the most-bound, smallest-extent positive
/// atom next with written order as the stable tie-breaker.
fn plan_rule_body(
    rule: &crate::Rule,
    facts: &std::collections::BTreeMap<String, FactStore>,
) -> RulePlan {
    let written_positives = rule
        .body
        .iter()
        .enumerate()
        .filter_map(|(index, literal)| match literal {
            crate::Literal::Positive(_) => Some(index),
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut remaining = rule
        .body
        .iter()
        .enumerate()
        .filter_map(|(index, literal)| match literal {
            crate::Literal::Aggregate { .. } | crate::Literal::Forbidden(_) => None,
            _ => Some(index),
        })
        .collect::<Vec<_>>();
    let mut bound_vars = std::collections::BTreeSet::new();
    let mut steps = Vec::with_capacity(remaining.len());
    let mut planned_positives = Vec::with_capacity(written_positives.len());

    while !remaining.is_empty() {
        if let Some(pos) = remaining.iter().position(|&idx| {
            matches!(rule.body[idx], crate::Literal::Compare { .. })
                && literal_all_vars_bound(&rule.body[idx], &bound_vars)
        }) {
            let body_index = remaining.remove(pos);
            steps.push(PlanStep::Compare { body_index });
            continue;
        }
        if let Some(pos) = remaining.iter().position(|&idx| {
            matches!(rule.body[idx], crate::Literal::Negative(_))
                && literal_all_vars_bound(&rule.body[idx], &bound_vars)
        }) {
            let body_index = remaining.remove(pos);
            steps.push(PlanStep::Negative { body_index });
            continue;
        }
        if let Some((pos, body_index, bound_cols)) =
            select_next_positive(&rule.body, &remaining, &bound_vars, facts)
        {
            remaining.remove(pos);
            if let crate::Literal::Positive(atom) = &rule.body[body_index] {
                for term in &atom.terms {
                    if let crate::Term::Variable(name) = term {
                        bound_vars.insert(name.clone());
                    }
                }
            }
            planned_positives.push(body_index);
            steps.push(PlanStep::Positive {
                body_index,
                bound_cols,
            });
            continue;
        }
        // Defensive tail: only reached if an unvalidated body has non-positive
        // literals whose variables were never positively bound.
        for body_index in remaining.drain(..) {
            match rule.body[body_index] {
                crate::Literal::Negative(_) => steps.push(PlanStep::Negative { body_index }),
                crate::Literal::Compare { .. } => steps.push(PlanStep::Compare { body_index }),
                _ => {}
            }
        }
    }

    RulePlan {
        steps,
        positive_reordered: planned_positives != written_positives,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PositiveScore {
    is_non_empty: bool,
    has_unbound_vars: bool,
    is_unconnected: bool,
    bound_positions: std::cmp::Reverse<usize>,
    unbound_distinct: usize,
    extent: usize,
    body_index: usize,
}

struct PositiveCandidate {
    score: PositiveScore,
    pos: usize,
    body_index: usize,
    bound_cols: Vec<usize>,
}

fn select_next_positive(
    body: &[crate::Literal],
    remaining: &[usize],
    bound_vars: &std::collections::BTreeSet<String>,
    facts: &std::collections::BTreeMap<String, FactStore>,
) -> Option<(usize, usize, Vec<usize>)> {
    let mut best: Option<PositiveCandidate> = None;
    for (pos, &body_index) in remaining.iter().enumerate() {
        let crate::Literal::Positive(atom) = &body[body_index] else {
            continue;
        };
        let extent = facts
            .get(&atom.predicate)
            .map_or(0, |store| store.rows.len());
        let bound_cols = bound_columns(atom, bound_vars);
        let bound_positions = bound_cols.len();
        let mut unbound_vars = std::collections::BTreeSet::new();
        let mut has_bound_var = false;
        for term in &atom.terms {
            if let crate::Term::Variable(name) = term {
                if bound_vars.contains(name) {
                    has_bound_var = true;
                } else {
                    unbound_vars.insert(name.as_str());
                }
            }
        }
        let unbound_distinct = unbound_vars.len();
        let score = PositiveScore {
            is_non_empty: extent > 0,
            has_unbound_vars: unbound_distinct > 0,
            is_unconnected: !bound_vars.is_empty() && !has_bound_var,
            bound_positions: std::cmp::Reverse(bound_positions),
            unbound_distinct,
            extent,
            body_index,
        };
        if best
            .as_ref()
            .is_none_or(|candidate| score < candidate.score)
        {
            best = Some(PositiveCandidate {
                score,
                pos,
                body_index,
                bound_cols,
            });
        }
    }
    best.map(|candidate| (candidate.pos, candidate.body_index, candidate.bound_cols))
}

fn bound_columns(
    atom: &crate::Atom,
    bound_vars: &std::collections::BTreeSet<String>,
) -> Vec<usize> {
    atom.terms
        .iter()
        .enumerate()
        .filter_map(|(index, term)| match term {
            crate::Term::Constant(_) => Some(index),
            crate::Term::Variable(name) if bound_vars.contains(name) => Some(index),
            crate::Term::Variable(_) => None,
        })
        .collect()
}

fn literal_all_vars_bound(
    literal: &crate::Literal,
    bound_vars: &std::collections::BTreeSet<String>,
) -> bool {
    match literal {
        crate::Literal::Positive(atom) | crate::Literal::Negative(atom) => atom
            .terms
            .iter()
            .all(|term| term_is_bound(term, bound_vars)),
        crate::Literal::Compare { left, right, .. } => {
            term_is_bound(left, bound_vars) && term_is_bound(right, bound_vars)
        }
        crate::Literal::Aggregate { .. } | crate::Literal::Forbidden(_) => false,
    }
}

fn term_is_bound(term: &crate::Term, bound_vars: &std::collections::BTreeSet<String>) -> bool {
    match term {
        crate::Term::Constant(_) => true,
        crate::Term::Variable(name) => bound_vars.contains(name),
    }
}

fn execute_plan(
    evaluation: &mut Evaluation<'_>,
    rule: &crate::Rule,
    plan: &RulePlan,
) -> Result<RuleBindings, RuleOutcome> {
    let mut bindings = vec![Binding::new()];
    for step in &plan.steps {
        match step {
            PlanStep::Positive {
                body_index,
                bound_cols,
            } => {
                let crate::Literal::Positive(atom) = &rule.body[*body_index] else {
                    continue;
                };
                // A binding count past the budget's counter cannot be charged at
                // all, so the rule is skipped exactly as an exhausted budget is.
                let Ok(cost) = u64::try_from(bindings.len()) else {
                    return Err(RuleOutcome::Skipped);
                };
                if !evaluation.budget.charge(cost) {
                    return Err(RuleOutcome::Skipped);
                }
                bindings = join_indexed(evaluation, &bindings, atom, bound_cols)?;
            }
            PlanStep::Negative { body_index } => {
                let crate::Literal::Negative(atom) = &rule.body[*body_index] else {
                    continue;
                };
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
                bindings = kept;
            }
            PlanStep::Compare { body_index } => {
                let crate::Literal::Compare { op, left, right } = &rule.body[*body_index] else {
                    continue;
                };
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
                bindings = kept;
            }
        }
        if bindings.is_empty() {
            return Err(RuleOutcome::Stable);
        }
    }
    Ok(bindings)
}

pub(super) fn sort_bindings_by_written_order(rule: &crate::Rule, bindings: &mut [Binding]) {
    let written_positives = rule
        .body
        .iter()
        .filter_map(|literal| match literal {
            crate::Literal::Positive(atom) => Some(atom),
            _ => None,
        })
        .collect::<Vec<_>>();
    bindings.sort_by(|left, right| compare_bindings_by_atoms(&written_positives, left, right));
}

fn compare_bindings_by_atoms(
    atoms: &[&crate::Atom],
    left: &Binding,
    right: &Binding,
) -> std::cmp::Ordering {
    for atom in atoms {
        for term in &atom.terms {
            let left_val = term_value_ref(term, left);
            let right_val = term_value_ref(term, right);
            let ord = left_val.cmp(&right_val);
            if ord != std::cmp::Ordering::Equal {
                return ord;
            }
        }
    }
    std::cmp::Ordering::Equal
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

fn project_key(terms: &[mneme_core::Value], cols: &[usize]) -> Vec<mneme_core::Value> {
    let mut key = Vec::with_capacity(cols.len());
    for &col in cols {
        if let Some(value) = terms.get(col) {
            key.push(value.clone());
        }
    }
    key
}

fn fill_probe_key(
    atom: &crate::Atom,
    cols: &[usize],
    binding: &Binding,
    probe_key: &mut Vec<mneme_core::Value>,
) -> bool {
    probe_key.clear();
    for &col in cols {
        let Some(value) = atom
            .terms
            .get(col)
            .and_then(|term| term_value(term, binding))
        else {
            return false;
        };
        probe_key.push(value);
    }
    true
}

fn ensure_column_index(
    evaluation: &mut Evaluation<'_>,
    predicate: &str,
    arity: usize,
    bound_cols: &[usize],
) -> Result<IndexState, RuleOutcome> {
    let Some(store) = evaluation.facts.get(predicate) else {
        return Ok(IndexState::Empty);
    };
    if store.rows.is_empty() {
        return Ok(IndexState::Empty);
    }
    let index_key = (arity, bound_cols.to_vec());
    if store.indexes.contains_key(&index_key) {
        return Ok(IndexState::Ready);
    }
    let mut index = FactColumnIndex::default();
    for terms in store.rows.keys() {
        if !evaluation.budget.charge(1) {
            return Err(RuleOutcome::Skipped);
        }
        if terms.len() != arity {
            continue;
        }
        let key = project_key(terms, bound_cols);
        index.buckets.entry(key).or_default().push(terms.clone());
    }
    if let Some(store_mut) = evaluation.facts.get_mut(predicate) {
        store_mut.indexes.insert(index_key, index);
    }
    Ok(IndexState::Ready)
}

pub(super) fn push_extended_binding(
    output: &mut RuleBindings,
    extended: Binding,
    max_bindings: usize,
    budget: &mut Budget<'_>,
) -> Result<(), RuleOutcome> {
    if output.len() >= max_bindings {
        // Intermediate bindings are bounded like result rows so a
        // cross product cannot exhaust memory inside one join.
        budget.stop(crate::ExecutionStatus::Partial);
        return Err(RuleOutcome::Skipped);
    }
    output.push(extended);
    Ok(())
}

fn join_indexed(
    evaluation: &mut Evaluation<'_>,
    bindings: &[Binding],
    atom: &crate::Atom,
    bound_cols: &[usize],
) -> Result<RuleBindings, RuleOutcome> {
    let arity = atom.terms.len();
    let has_rows = evaluation
        .facts
        .get(&atom.predicate)
        .is_some_and(|store| !store.rows.is_empty());
    if !has_rows {
        return Ok(Vec::new());
    }
    if bound_cols.is_empty() {
        return join_full_scan(evaluation, bindings, atom);
    }
    if bound_cols.len() == arity {
        return join_all_bound(evaluation, bindings, atom);
    }
    join_by_column_index(evaluation, bindings, atom, bound_cols)
}

fn join_full_scan(
    evaluation: &mut Evaluation<'_>,
    bindings: &[Binding],
    atom: &crate::Atom,
) -> Result<RuleBindings, RuleOutcome> {
    let arity = atom.terms.len();
    let binding_limit = evaluation.budget.limits.max_result_rows;
    let mut output = Vec::with_capacity(bindings.len().min(binding_limit));
    let Some(store) = evaluation.facts.get(&atom.predicate) else {
        return Ok(Vec::new());
    };
    for binding in bindings {
        for (terms, data) in &store.rows {
            if terms.len() != arity {
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

fn join_all_bound(
    evaluation: &mut Evaluation<'_>,
    bindings: &[Binding],
    atom: &crate::Atom,
) -> Result<RuleBindings, RuleOutcome> {
    let arity = atom.terms.len();
    let binding_limit = evaluation.budget.limits.max_result_rows;
    let mut output = Vec::with_capacity(bindings.len().min(binding_limit));
    let Some(store) = evaluation.facts.get(&atom.predicate) else {
        return Ok(Vec::new());
    };
    let mut probe_key = Vec::with_capacity(arity);
    for binding in bindings {
        if !evaluation.budget.charge(1) {
            return Err(RuleOutcome::Skipped);
        }
        probe_key.clear();
        let mut is_complete_key = true;
        for term in &atom.terms {
            match term_value(term, binding) {
                Some(value) => probe_key.push(value),
                None => {
                    is_complete_key = false;
                    break;
                }
            }
        }
        if !is_complete_key {
            continue;
        }
        if let Some(data) = store.rows.get(&probe_key)
            && !data.supports.is_empty()
        {
            push_extended_binding(
                &mut output,
                binding.clone(),
                binding_limit,
                &mut evaluation.budget,
            )?;
        }
    }
    Ok(output)
}

fn join_by_column_index(
    evaluation: &mut Evaluation<'_>,
    bindings: &[Binding],
    atom: &crate::Atom,
    bound_cols: &[usize],
) -> Result<RuleBindings, RuleOutcome> {
    let arity = atom.terms.len();
    let binding_limit = evaluation.budget.limits.max_result_rows;
    let mut output = Vec::with_capacity(bindings.len().min(binding_limit));
    if ensure_column_index(evaluation, &atom.predicate, arity, bound_cols)? == IndexState::Empty {
        return Ok(Vec::new());
    }
    let index_key = (arity, bound_cols.to_vec());
    let Some(store) = evaluation.facts.get(&atom.predicate) else {
        return Ok(Vec::new());
    };
    let Some(index) = store.indexes.get(&index_key) else {
        return Ok(Vec::new());
    };
    let mut probe_key = Vec::with_capacity(bound_cols.len());
    for binding in bindings {
        if !evaluation.budget.charge(1) {
            return Err(RuleOutcome::Skipped);
        }
        if !fill_probe_key(atom, bound_cols, binding, &mut probe_key) {
            continue;
        }
        let Some(matching_keys) = index.buckets.get(&probe_key) else {
            continue;
        };
        for terms in matching_keys {
            if !evaluation.budget.charge(1) {
                return Err(RuleOutcome::Skipped);
            }
            let Some(data) = store.rows.get(terms) else {
                continue;
            };
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

pub(super) fn matches_atom(
    evaluation: &mut Evaluation<'_>,
    atom: &crate::Atom,
    binding: &Binding,
) -> Result<bool, RuleOutcome> {
    let arity = atom.terms.len();
    let has_rows = evaluation
        .facts
        .get(&atom.predicate)
        .is_some_and(|store| !store.rows.is_empty());
    if !has_rows {
        return Ok(false);
    }
    let mut ground_key = Vec::with_capacity(arity);
    let mut is_all_ground = true;
    for term in &atom.terms {
        match term_value(term, binding) {
            Some(value) => ground_key.push(value),
            None => {
                is_all_ground = false;
                break;
            }
        }
    }
    if is_all_ground {
        if !evaluation.budget.charge(1) {
            return Err(RuleOutcome::Skipped);
        }
        let is_matched = evaluation
            .facts
            .get(&atom.predicate)
            .and_then(|store| store.rows.get(&ground_key))
            .is_some_and(|data| !data.supports.is_empty());
        return Ok(is_matched);
    }

    let bound_cols = atom
        .terms
        .iter()
        .enumerate()
        .filter_map(|(index, term)| term_value_ref(term, binding).map(|_| index))
        .collect::<Vec<_>>();
    if !bound_cols.is_empty() {
        return matches_atom_indexed(evaluation, atom, binding, &bound_cols);
    }

    let Some(store) = evaluation.facts.get(&atom.predicate) else {
        return Ok(false);
    };
    for terms in store.rows.keys() {
        if !evaluation.budget.charge(1) {
            return Err(RuleOutcome::Skipped);
        }
        if terms.len() == arity && atom_matches_row(atom, terms, binding) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn matches_atom_indexed(
    evaluation: &mut Evaluation<'_>,
    atom: &crate::Atom,
    binding: &Binding,
    bound_cols: &[usize],
) -> Result<bool, RuleOutcome> {
    let arity = atom.terms.len();
    if ensure_column_index(evaluation, &atom.predicate, arity, bound_cols)? == IndexState::Empty {
        return Ok(false);
    }
    let index_key = (arity, bound_cols.to_vec());
    let Some(store) = evaluation.facts.get(&atom.predicate) else {
        return Ok(false);
    };
    let Some(index) = store.indexes.get(&index_key) else {
        return Ok(false);
    };
    if !evaluation.budget.charge(1) {
        return Err(RuleOutcome::Skipped);
    }
    let mut probe_key = Vec::with_capacity(bound_cols.len());
    if !fill_probe_key(atom, bound_cols, binding, &mut probe_key) {
        return Ok(false);
    }
    let Some(matching_keys) = index.buckets.get(&probe_key) else {
        return Ok(false);
    };
    for terms in matching_keys {
        if !evaluation.budget.charge(1) {
            return Err(RuleOutcome::Skipped);
        }
        if atom_matches_row(atom, terms, binding) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn atom_matches_row(atom: &crate::Atom, terms: &[mneme_core::Value], binding: &Binding) -> bool {
    terms.len() == atom.terms.len()
        && atom
            .terms
            .iter()
            .zip(terms)
            .all(|(term, value)| match term {
                crate::Term::Constant(expected) => expected == value,
                crate::Term::Variable(name) => binding.get(name).is_none_or(|bound| bound == value),
            })
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

pub(super) fn term_value(term: &crate::Term, binding: &Binding) -> Option<mneme_core::Value> {
    match term {
        crate::Term::Constant(value) => Some(value.clone()),
        crate::Term::Variable(name) => binding.get(name).cloned(),
    }
}

fn term_value_ref<'a>(
    term: &'a crate::Term,
    binding: &'a Binding,
) -> Option<&'a mneme_core::Value> {
    match term {
        crate::Term::Constant(value) => Some(value),
        crate::Term::Variable(name) => binding.get(name),
    }
}

pub(super) fn compare_values(
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_scope() -> mneme_core::ScopeId {
        mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "datalog-unit")
            .expect("valid scope")
    }

    fn rid(tag: u16) -> mneme_core::RecordId {
        let mut bytes = [0_u8; 16];
        let [hi, lo] = tag.to_be_bytes();
        bytes[0] = 0x42;
        bytes[14] = hi;
        bytes[15] = lo;
        mneme_core::RecordId::from_bytes(bytes)
    }

    fn test_context(bundle: &crate::RuleBundle) -> crate::BuildContext {
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
        }
    }

    fn base_fact_contents(
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
                absent: false,
                coverage: None,
            }],
            sources: std::collections::BTreeSet::new(),
            temporal_parameters: Vec::new(),
            revision: context.served_revision,
            scope: context.scope.clone(),
            truncated: false,
        };
        FactContents {
            terms,
            support,
            sources: std::collections::BTreeSet::new(),
            canonical: Some(record_id),
            canonical_roots: std::collections::BTreeSet::from([record_id]),
            temporal: Vec::new(),
        }
    }

    struct EvaluationFixture<'a> {
        bundle: &'a crate::RuleBundle,
        context: &'a crate::BuildContext,
        limits: &'a crate::Limits,
        current_sources: &'a AvailabilityMap,
        base_facts: &'a [(String, FactKey, mneme_core::RecordId)],
    }

    fn make_evaluation<'a>(fixture: &'a EvaluationFixture<'a>) -> Evaluation<'a> {
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
            },
            facts: std::collections::BTreeMap::new(),
            coverage: std::collections::BTreeMap::new(),
            base_coverage: std::collections::BTreeMap::new(),
            coverage_reasons: std::collections::BTreeMap::new(),
            current_sources: fixture.current_sources,
            at: None,
            derivation_eligibility: std::collections::BTreeMap::new(),
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

    fn evaluate_rules_binary(
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

    fn evaluate_rules_naive(
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
            match literal {
                crate::Literal::Negative(atom) => {
                    if evaluation.coverage_status(&atom.predicate)
                        != crate::CoverageStatus::Complete
                    {
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
                }
                crate::Literal::Compare { op, left, right } => {
                    let mut kept = Vec::with_capacity(bindings.len());
                    for binding in bindings.drain(..) {
                        if !evaluation.budget.charge(1) {
                            return Err(RuleOutcome::Skipped);
                        }
                        let is_kept =
                            match (term_value(left, &binding), term_value(right, &binding)) {
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
        for terms in store.rows.keys() {
            if !evaluation.budget.charge(1) {
                return Err(RuleOutcome::Skipped);
            }
            if atom_matches_row(atom, terms, binding) {
                is_matched = true;
                break;
            }
        }
        Ok(is_matched)
    }

    fn assert_equivalent_to_naive(
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
        for (predicate, naive_store) in &naive.facts {
            let planned_store = planned.facts.get(predicate).expect("matching predicate");
            assert_eq!(planned_store.truncated, naive_store.truncated);
            assert_eq!(
                planned_store.rows.keys().collect::<Vec<_>>(),
                naive_store.rows.keys().collect::<Vec<_>>()
            );
            for (key, naive_data) in &naive_store.rows {
                let planned_data = planned_store.rows.get(key).expect("matching row");
                assert_eq!(planned_data.supports, naive_data.supports);
                assert_eq!(planned_data.sources, naive_data.sources);
                assert_eq!(planned_data.truncated, naive_data.truncated);
                assert_eq!(planned_data.canonical, naive_data.canonical);
                assert_eq!(planned_data.canonical_roots, naive_data.canonical_roots);
                assert_eq!(planned_data.temporal, naive_data.temporal);
            }
        }
        (naive.budget.work, planned.budget.work)
    }

    fn atom(predicate: &str, terms: Vec<crate::Term>) -> crate::Atom {
        crate::Atom::new(predicate, terms)
    }

    fn var(name: &str) -> crate::Term {
        crate::Term::var(name)
    }

    fn sym(name: &str) -> crate::Term {
        crate::Term::constant(mneme_core::Value::symbol(name))
    }

    fn int_const(value: i64) -> crate::Term {
        crate::Term::constant(mneme_core::Value::integer(value))
    }

    fn push_entities(
        facts: &mut Vec<(String, FactKey, mneme_core::RecordId)>,
        next_id: &mut u16,
        entity_type: &str,
        prefix: &str,
        count: usize,
    ) -> Vec<mneme_core::RecordId> {
        let mut ids = Vec::with_capacity(count);
        for idx in 0..count {
            let id = rid(*next_id);
            *next_id = next_id.saturating_add(1);
            ids.push(id);
            facts.push((
                "entity".to_owned(),
                vec![
                    id.to_value(),
                    mneme_core::Value::symbol(entity_type),
                    mneme_core::Value::string(format!("{prefix} {idx}")),
                ],
                id,
            ));
        }
        ids
    }

    fn five_atom_fixture_facts() -> Vec<(String, FactKey, mneme_core::RecordId)> {
        let mut facts = Vec::with_capacity(194);
        let mut next_id = 1_u16;
        let papers = push_entities(&mut facts, &mut next_id, "paper", "Paper", 25);
        let principles = push_entities(&mut facts, &mut next_id, "principle", "Principle", 25);
        let classes = push_entities(&mut facts, &mut next_id, "problem_class", "Class", 10);
        let _notes = push_entities(&mut facts, &mut next_id, "note", "Note", 20);
        // 50 in_class edges for papers, 50 for principles, 14 bridged edges (114 relations; 194 total)
        for (idx, paper) in papers.iter().enumerate() {
            for offset in 0..2_usize {
                let class = classes[(idx + offset) % 10];
                let id = rid(next_id);
                next_id = next_id.saturating_add(1);
                facts.push((
                    "relation".to_owned(),
                    vec![
                        mneme_core::Value::symbol("in_class"),
                        paper.to_value(),
                        class.to_value(),
                    ],
                    id,
                ));
            }
        }
        for (idx, principle) in principles.iter().enumerate() {
            for offset in 0..2_usize {
                let class = classes[(idx + offset) % 10];
                let id = rid(next_id);
                next_id = next_id.saturating_add(1);
                facts.push((
                    "relation".to_owned(),
                    vec![
                        mneme_core::Value::symbol("in_class"),
                        principle.to_value(),
                        class.to_value(),
                    ],
                    id,
                ));
            }
        }
        for idx in 0..14_usize {
            let id = rid(next_id);
            next_id = next_id.saturating_add(1);
            facts.push((
                "relation".to_owned(),
                vec![
                    mneme_core::Value::symbol("bridged"),
                    papers[idx].to_value(),
                    principles[idx].to_value(),
                ],
                id,
            ));
        }
        facts
    }

    #[test]
    fn five_atom_bridge_query_and_permutations_match_naive_with_low_work() {
        let base_facts = five_atom_fixture_facts();
        assert_eq!(base_facts.len(), 194);

        let atoms = [
            crate::Literal::Positive(atom(
                "entity",
                vec![var("paper"), sym("paper"), var("p_label")],
            )),
            crate::Literal::Positive(atom(
                "entity",
                vec![var("principle"), sym("principle"), var("pr_label")],
            )),
            crate::Literal::Positive(atom(
                "entity",
                vec![var("class"), sym("problem_class"), var("c_label")],
            )),
            crate::Literal::Positive(atom(
                "relation",
                vec![sym("in_class"), var("paper"), var("class")],
            )),
            crate::Literal::Positive(atom(
                "relation",
                vec![sym("in_class"), var("principle"), var("class")],
            )),
        ];
        let negation = crate::Literal::Negative(atom(
            "relation",
            vec![sym("bridged"), var("paper"), var("principle")],
        ));

        let unfactored = crate::RuleBundle::new(crate::RuleBundleOptions {
            id: "bridge-unfactored".to_owned(),
            version: "1".to_owned(),
            schema_version: 3,
            base_predicates: std::collections::BTreeMap::from([
                ("entity".to_owned(), 3),
                ("relation".to_owned(), 3),
            ]),
            complete_predicates: std::collections::BTreeSet::from(["relation".to_owned()]),
            rules: vec![crate::Rule::new(
                "unbridged_candidate",
                atom(
                    "unbridged_candidate",
                    vec![var("paper"), var("principle"), var("class")],
                ),
                // Natural 5-atom chained order (avoids intermediate Cartesian row limit,
                // yet still exceeds 100,000 work under naive full-table scans).
                vec![
                    atoms[0].clone(),
                    atoms[3].clone(),
                    atoms[2].clone(),
                    atoms[4].clone(),
                    atoms[1].clone(),
                    negation.clone(),
                ],
            )],
        });

        let default_limits = crate::Limits::default();
        let program = unfactored.validate().expect("valid");
        let context = test_context(&unfactored);
        let sources = AvailabilityMap::new();
        let default_fixture = EvaluationFixture {
            bundle: &unfactored,
            context: &context,
            limits: &default_limits,
            current_sources: &sources,
            base_facts: &base_facts,
        };

        let mut naive_default = make_evaluation(&default_fixture);
        evaluate_rules_naive(&mut naive_default, &program.strata);
        assert_eq!(naive_default.budget.status, crate::ExecutionStatus::Timeout);
        assert!(naive_default.budget.limit_reached);

        let mut planned_default = make_evaluation(&default_fixture);
        evaluate_rules(&mut planned_default, &program.strata);
        assert_eq!(
            planned_default.budget.status,
            crate::ExecutionStatus::Complete
        );
        assert!(!planned_default.budget.limit_reached);
        assert!(
            planned_default.budget.work < 15_000,
            "planned work {} should be well under 100k",
            planned_default.budget.work
        );

        let generous_limits = crate::Limits {
            max_work: 50_000_000,
            max_time_ms: 60_000,
            max_result_rows: 10_000,
            ..default_limits
        };
        let (naive_work, planned_work) =
            assert_equivalent_to_naive(&unfactored, &base_facts, &generous_limits);
        eprintln!("5-atom chained bridge: naive_work={naive_work}, planned_work={planned_work}");
        assert!(naive_work > 100_000);
        assert!(planned_work < 15_000);

        // Permutations of positive atoms + early placement of negation all match
        // the unfactored canonical rows and complete well under default limits.
        let permutations: [[usize; 5]; 6] = [
            [0, 1, 2, 3, 4],
            [4, 3, 2, 1, 0],
            [2, 3, 4, 0, 1],
            [3, 0, 2, 4, 1],
            [1, 4, 2, 3, 0],
            [3, 4, 0, 1, 2],
        ];
        for perm in permutations {
            let body = vec![
                atoms[perm[0]].clone(),
                atoms[perm[1]].clone(),
                negation.clone(),
                atoms[perm[2]].clone(),
                atoms[perm[3]].clone(),
                atoms[perm[4]].clone(),
            ];
            let permuted = crate::RuleBundle::new(crate::RuleBundleOptions {
                id: "bridge-perm".to_owned(),
                version: "1".to_owned(),
                schema_version: 3,
                base_predicates: unfactored.base_predicates.clone(),
                complete_predicates: unfactored.complete_predicates.clone(),
                rules: vec![crate::Rule::new(
                    "unbridged_candidate",
                    atom(
                        "unbridged_candidate",
                        vec![var("paper"), var("principle"), var("class")],
                    ),
                    body,
                )],
            });
            let (perm_naive, perm_planned) =
                assert_equivalent_to_naive(&permuted, &base_facts, &generous_limits);
            assert!(
                perm_planned < 15_000,
                "perm {:?} planned_work={}",
                perm,
                perm_planned
            );
            assert!(perm_planned < perm_naive);
        }
    }

    #[test]
    fn equivalence_against_naive_across_cyclic_compare_aggregates_and_truncation() {
        let mut base_facts = Vec::new();
        for idx in 1..=12_u16 {
            let id = rid(idx);
            base_facts.push((
                "node".to_owned(),
                vec![
                    mneme_core::Value::integer(i64::from(idx)),
                    mneme_core::Value::symbol(if idx % 2 == 0 { "even" } else { "odd" }),
                ],
                id,
            ));
        }
        let mut edge_id = 100_u16;
        for src in 1..=12_i64 {
            for dst in [src % 12 + 1, (src + 1) % 12 + 1, (src + 3) % 12 + 1] {
                edge_id = edge_id.saturating_add(1);
                base_facts.push((
                    "edge".to_owned(),
                    vec![
                        mneme_core::Value::integer(src),
                        mneme_core::Value::integer(dst),
                    ],
                    rid(edge_id),
                ));
            }
        }
        // Self-loop edge + blocked pair + multi-proof witness table
        edge_id = edge_id.saturating_add(1);
        base_facts.push((
            "edge".to_owned(),
            vec![mneme_core::Value::integer(1), mneme_core::Value::integer(1)],
            rid(edge_id),
        ));
        base_facts.push((
            "blocked".to_owned(),
            vec![mneme_core::Value::integer(2), mneme_core::Value::integer(3)],
            rid(400),
        ));
        for a in 1..=4_i64 {
            for b in 1..=4_i64 {
                base_facts.push((
                    "witness".to_owned(),
                    vec![
                        mneme_core::Value::integer(1),
                        mneme_core::Value::integer(a),
                        mneme_core::Value::integer(b),
                    ],
                    rid(500 + u16::try_from(a * 10 + b).expect("small")),
                ));
            }
        }
        for b in 1..=4_i64 {
            for a in 1..=4_i64 {
                if (a + b) % 2 == 0 {
                    base_facts.push((
                        "pair_filter".to_owned(),
                        vec![mneme_core::Value::integer(b), mneme_core::Value::integer(a)],
                        rid(700 + u16::try_from(b * 10 + a).expect("small")),
                    ));
                }
            }
        }

        let bundle = crate::RuleBundle::new(crate::RuleBundleOptions {
            id: "equivalence-suite".to_owned(),
            version: "1".to_owned(),
            schema_version: 3,
            base_predicates: std::collections::BTreeMap::from([
                ("node".to_owned(), 2),
                ("edge".to_owned(), 2),
                ("blocked".to_owned(), 2),
                ("witness".to_owned(), 3),
                ("pair_filter".to_owned(), 2),
            ]),
            complete_predicates: std::collections::BTreeSet::from([
                "node".to_owned(),
                "edge".to_owned(),
                "blocked".to_owned(),
                "witness".to_owned(),
                "pair_filter".to_owned(),
            ]),
            rules: vec![
                // Cyclic triangle with stratified negation + Compare pushdown
                crate::Rule::new(
                    "triangle",
                    atom("triangle", vec![var("a"), var("b"), var("c")]),
                    vec![
                        crate::Literal::Positive(atom("edge", vec![var("a"), var("b")])),
                        crate::Literal::Positive(atom("node", vec![var("c"), sym("even")])),
                        crate::Literal::Positive(atom("edge", vec![var("b"), var("c")])),
                        crate::Literal::Positive(atom("edge", vec![var("c"), var("a")])),
                        crate::Literal::Negative(atom("blocked", vec![var("a"), var("b")])),
                        crate::Literal::Compare {
                            op: crate::CompareOp::Lt,
                            left: var("a"),
                            right: var("c"),
                        },
                    ],
                ),
                // Self-join with repeated variable in an atom
                crate::Rule::new(
                    "self_loop",
                    atom("self_loop", vec![var("x")]),
                    vec![crate::Literal::Positive(atom(
                        "edge",
                        vec![var("x"), var("x")],
                    ))],
                ),
                // Projected-out variables (y, z) where pair_filter has smaller extent than witness
                crate::Rule::new(
                    "projected",
                    atom("projected", vec![var("x")]),
                    vec![
                        crate::Literal::Positive(atom(
                            "witness",
                            vec![var("x"), var("y"), var("z")],
                        )),
                        crate::Literal::Positive(atom("pair_filter", vec![var("z"), var("y")])),
                    ],
                ),
                // Recursive reachability
                crate::Rule::new(
                    "reach_base",
                    atom("reach", vec![var("x"), var("y")]),
                    vec![crate::Literal::Positive(atom(
                        "edge",
                        vec![var("x"), var("y")],
                    ))],
                ),
                crate::Rule::new(
                    "reach_step",
                    atom("reach", vec![var("x"), var("z")]),
                    vec![
                        crate::Literal::Positive(atom("reach", vec![var("x"), var("y")])),
                        crate::Literal::Positive(atom("edge", vec![var("y"), var("z")])),
                        crate::Literal::Compare {
                            op: crate::CompareOp::Ne,
                            left: var("x"),
                            right: var("z"),
                        },
                    ],
                ),
                // Aggregate over reordered body
                crate::Rule::new(
                    "out_sum",
                    atom("out_sum", vec![var("a"), var("total")]),
                    vec![
                        crate::Literal::Positive(atom("edge", vec![var("a"), var("b")])),
                        crate::Literal::Positive(atom("node", vec![var("b"), sym("odd")])),
                        crate::Literal::Aggregate {
                            function: crate::AggregateFunction::Sum,
                            input: var("b"),
                            output: "total".to_owned(),
                        },
                    ],
                ),
                // Ground false comparison short-circuit
                crate::Rule::new(
                    "impossible",
                    atom("impossible", vec![var("x")]),
                    vec![
                        crate::Literal::Positive(atom("node", vec![var("x"), var("k")])),
                        crate::Literal::Compare {
                            op: crate::CompareOp::Gt,
                            left: int_const(1),
                            right: int_const(2),
                        },
                    ],
                ),
            ],
        });

        let limits = crate::Limits {
            max_work: 5_000_000,
            max_time_ms: 60_000,
            max_result_rows: 1_000,
            max_supports_per_fact: 2,
            max_recursion_depth: 16,
        };
        let (naive_work, planned_work) = assert_equivalent_to_naive(&bundle, &base_facts, &limits);
        assert!(planned_work < naive_work);
    }

    #[test]
    fn property_equivalence_against_naive_across_seeded_programs() {
        let mut seed = 0x9E37_79B9_7F4A_7C15_u64;
        let mut next_u64 = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        let preds = ["p0", "p1", "p2", "p3"];
        let vars = ["a", "b", "c", "d"];

        for case_idx in 0..30_usize {
            let mut base_facts = Vec::with_capacity(60);
            let mut next_rid = 1_u16;
            for (pred_idx, pred) in preds.iter().enumerate() {
                // Deliberately skew extent sizes (some empty, some small, some medium).
                let row_count = match (case_idx + pred_idx) % 4 {
                    0 => 0,
                    1 => 3,
                    2 => 8,
                    _ => 18,
                };
                for _ in 0..row_count {
                    let v0 = i64::try_from(next_u64() % 5).expect("mod 5");
                    let v1 = i64::try_from(next_u64() % 5).expect("mod 5");
                    let v2 = i64::try_from(next_u64() % 4).expect("mod 4");
                    let id = rid(next_rid);
                    next_rid = next_rid.saturating_add(1);
                    let row = if pred_idx < 2 {
                        vec![
                            mneme_core::Value::integer(v0),
                            mneme_core::Value::integer(v1),
                        ]
                    } else {
                        vec![
                            mneme_core::Value::integer(v0),
                            mneme_core::Value::integer(v1),
                            mneme_core::Value::integer(v2),
                        ]
                    };
                    base_facts.push(((*pred).to_owned(), row, id));
                }
            }

            let num_pos = 2 + usize::try_from(next_u64() % 3).expect("mod 3");
            let mut body = Vec::new();
            let mut used_vars = Vec::new();
            for pos_idx in 0..num_pos {
                let pred_idx = usize::try_from(next_u64() % 4).expect("mod 4");
                let arity = if pred_idx < 2 { 2 } else { 3 };
                let mut terms = Vec::with_capacity(arity);
                for col in 0..arity {
                    let choice = next_u64() % 5;
                    if choice == 0 && (pos_idx > 0 || col > 0) {
                        terms.push(int_const(i64::try_from(next_u64() % 4).expect("mod 4")));
                    } else {
                        let var_name = if !used_vars.is_empty() && next_u64() % 2 == 0 {
                            let idx = usize::try_from(next_u64())
                                .expect("u64")
                                .checked_rem(used_vars.len())
                                .expect("non-empty used_vars");
                            used_vars[idx]
                        } else {
                            let name = vars[usize::try_from(next_u64() % 4).expect("mod 4")];
                            if !used_vars.contains(&name) {
                                used_vars.push(name);
                            }
                            name
                        };
                        terms.push(var(var_name));
                    }
                }
                body.push(crate::Literal::Positive(atom(preds[pred_idx], terms)));
            }
            if let Some(&v0) = used_vars.first() {
                let v1 = *used_vars.get(1).unwrap_or(&v0);
                if next_u64() % 2 == 0 {
                    body.push(crate::Literal::Negative(atom("p0", vec![var(v0), var(v1)])));
                }
                if next_u64() % 2 == 0 {
                    body.push(crate::Literal::Compare {
                        op: crate::CompareOp::Le,
                        left: var(v0),
                        right: var(v1),
                    });
                }
            }
            let head_terms = if used_vars.len() >= 2 {
                vec![var(used_vars[0]), var(used_vars[1])]
            } else if let Some(&v0) = used_vars.first() {
                vec![var(v0)]
            } else {
                vec![int_const(1)]
            };

            let bundle = crate::RuleBundle::new(crate::RuleBundleOptions {
                id: format!("prop-{case_idx}"),
                version: "1".to_owned(),
                schema_version: 3,
                base_predicates: std::collections::BTreeMap::from([
                    ("p0".to_owned(), 2),
                    ("p1".to_owned(), 2),
                    ("p2".to_owned(), 3),
                    ("p3".to_owned(), 3),
                ]),
                complete_predicates: std::collections::BTreeSet::from([
                    "p0".to_owned(),
                    "p1".to_owned(),
                    "p2".to_owned(),
                    "p3".to_owned(),
                ]),
                rules: vec![crate::Rule::new("out", atom("out", head_terms), body)],
            });

            let limits = crate::Limits {
                max_work: 5_000_000,
                max_time_ms: 60_000,
                max_result_rows: 1_000,
                max_supports_per_fact: 3,
                max_recursion_depth: 16,
            };
            assert_equivalent_to_naive(&bundle, &base_facts, &limits);
        }
    }

    #[test]
    fn greedy_planner_orders_most_bound_and_smallest_extent_with_written_tie_break() {
        let mut facts = std::collections::BTreeMap::new();
        let mut big = FactStore::default();
        for idx in 0..20_i64 {
            big.rows.insert(
                vec![
                    mneme_core::Value::integer(idx),
                    mneme_core::Value::integer(idx + 1),
                ],
                crate::FactData {
                    supports: Vec::new(),
                    sources: std::collections::BTreeSet::new(),
                    truncated: false,
                    canonical: None,
                    canonical_roots: std::collections::BTreeSet::new(),
                    temporal: Vec::new(),
                },
            );
        }
        let mut small = FactStore::default();
        for idx in 0..3_i64 {
            small.rows.insert(
                vec![
                    mneme_core::Value::integer(idx),
                    mneme_core::Value::integer(idx + 1),
                ],
                crate::FactData {
                    supports: Vec::new(),
                    sources: std::collections::BTreeSet::new(),
                    truncated: false,
                    canonical: None,
                    canonical_roots: std::collections::BTreeSet::new(),
                    temporal: Vec::new(),
                },
            );
        }
        let mut tie_a = small.clone();
        let mut tie_b = small.clone();
        let _ = (&mut tie_a, &mut tie_b);
        facts.insert("big".to_owned(), big);
        facts.insert("small".to_owned(), small.clone());
        facts.insert("tie_a".to_owned(), small.clone());
        facts.insert("tie_b".to_owned(), small);

        // Smaller extent beats larger extent; ready negative/compare runs before next join.
        let rule = crate::Rule::new(
            "ordered",
            atom("out", vec![var("x"), var("z")]),
            vec![
                crate::Literal::Positive(atom("big", vec![var("y"), var("z")])),
                crate::Literal::Negative(atom("small", vec![var("x"), var("y")])),
                crate::Literal::Compare {
                    op: crate::CompareOp::Lt,
                    left: var("x"),
                    right: var("y"),
                },
                crate::Literal::Positive(atom("small", vec![var("x"), var("y")])),
            ],
        );
        let plan = plan_rule_body(&rule, &facts);
        assert!(plan.positive_reordered);
        let order = plan
            .steps
            .iter()
            .map(|step| match step {
                PlanStep::Positive { body_index, .. }
                | PlanStep::Negative { body_index }
                | PlanStep::Compare { body_index } => *body_index,
            })
            .collect::<Vec<_>>();
        // 3: small(x, y) first -> 2: Compare(x < y) -> 1: Negative(small(x, y)) -> 0: big(y, z)
        assert_eq!(order, vec![3, 2, 1, 0]);

        // Equal extent & equal bound positions tie-break by written order.
        let tie_rule = crate::Rule::new(
            "tie",
            atom("out", vec![var("x"), var("z")]),
            vec![
                crate::Literal::Positive(atom("tie_a", vec![var("x"), var("y")])),
                crate::Literal::Positive(atom("tie_b", vec![var("y"), var("z")])),
            ],
        );
        let tie_plan = plan_rule_body(&tie_rule, &facts);
        assert!(!tie_plan.positive_reordered);
    }

    #[test]
    fn join_only_visits_matching_rows_for_bound_positions() {
        let mut base_facts = Vec::new();
        for idx in 0..100_i64 {
            let id = rid(u16::try_from(idx + 1).expect("small"));
            base_facts.push((
                "left".to_owned(),
                vec![
                    mneme_core::Value::integer(idx),
                    mneme_core::Value::integer(idx % 5),
                ],
                id,
            ));
            base_facts.push((
                "right".to_owned(),
                vec![
                    mneme_core::Value::integer(idx),
                    mneme_core::Value::string(format!("v-{idx}")),
                ],
                rid(u16::try_from(idx + 201).expect("small")),
            ));
        }
        let bundle = crate::RuleBundle::new(crate::RuleBundleOptions {
            id: "indexed-probe".to_owned(),
            version: "1".to_owned(),
            schema_version: 3,
            base_predicates: std::collections::BTreeMap::from([
                ("left".to_owned(), 2),
                ("right".to_owned(), 2),
            ]),
            complete_predicates: std::collections::BTreeSet::from([
                "left".to_owned(),
                "right".to_owned(),
            ]),
            rules: vec![crate::Rule::new(
                "joined",
                atom("joined", vec![var("k"), var("s")]),
                vec![
                    crate::Literal::Positive(atom("left", vec![var("k"), int_const(0)])),
                    crate::Literal::Positive(atom("right", vec![var("k"), var("s")])),
                ],
            )],
        });
        let limits = crate::Limits::default();
        let (naive_work, planned_work) = assert_equivalent_to_naive(&bundle, &base_facts, &limits);
        // Naive scans 100 rows on left + 20 * 100 = 2000 rows on right per round (~4,500 total).
        // Indexed builds indexes once (~200) + probes (~20 * 2 per round) (~700 total including base load).
        eprintln!("indexed-probe: naive_work={naive_work}, planned_work={planned_work}");
        assert!(naive_work > 4_000);
        assert!(planned_work < 800);
    }

    fn assert_evaluations_match(expected: &Evaluation<'_>, actual: &Evaluation<'_>) {
        assert_eq!(actual.budget.status, expected.budget.status);
        assert_eq!(actual.budget.limit_reached, expected.budget.limit_reached);
        assert_eq!(
            actual.budget.support_truncated,
            expected.budget.support_truncated
        );
        assert_eq!(final_coverage(actual), final_coverage(expected));
        assert_eq!(
            actual.facts.keys().collect::<Vec<_>>(),
            expected.facts.keys().collect::<Vec<_>>()
        );
        for (predicate, expected_store) in &expected.facts {
            let actual_store = actual.facts.get(predicate).expect("matching predicate");
            assert_eq!(actual_store.truncated, expected_store.truncated);
            assert_eq!(
                actual_store.rows.keys().collect::<Vec<_>>(),
                expected_store.rows.keys().collect::<Vec<_>>()
            );
            for (key, expected_data) in &expected_store.rows {
                let actual_data = actual_store.rows.get(key).expect("matching row");
                assert_eq!(actual_data.supports, expected_data.supports);
                assert_eq!(actual_data.sources, expected_data.sources);
                assert_eq!(actual_data.truncated, expected_data.truncated);
                assert_eq!(actual_data.canonical, expected_data.canonical);
                assert_eq!(actual_data.canonical_roots, expected_data.canonical_roots);
                assert_eq!(actual_data.temporal, expected_data.temporal);
            }
        }
    }

    fn assert_equivalent_to_binary(
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
        let mut binary = make_evaluation(&fixture);
        evaluate_rules_binary(&mut binary, &program.strata);

        let mut free_join = make_evaluation(&fixture);
        evaluate_rules(&mut free_join, &program.strata);

        assert_evaluations_match(&binary, &free_join);
        (binary.budget.work, free_join.budget.work)
    }

    fn assert_equivalent_to_binary_and_naive(
        bundle: &crate::RuleBundle,
        base_facts: &[(String, FactKey, mneme_core::RecordId)],
        limits: &crate::Limits,
    ) -> (u64, u64, u64) {
        assert!(!bundle.rules.is_empty());
        let program = bundle.validate().expect("valid bundle");
        assert!(!program.strata.is_empty());
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

        let mut binary = make_evaluation(&fixture);
        evaluate_rules_binary(&mut binary, &program.strata);

        let mut free_join = make_evaluation(&fixture);
        evaluate_rules(&mut free_join, &program.strata);

        assert_evaluations_match(&naive, &binary);
        assert_evaluations_match(&naive, &free_join);
        (naive.budget.work, binary.budget.work, free_join.budget.work)
    }

    #[test]
    fn cyclic_triangle_hub_query_completes_under_default_limits_vs_binary_blowup() {
        // Hub node 0 has 120 incoming edges (1..=120 -> 0) and 120 outgoing edges
        // (0 -> 121..=240). Nodes 1..=120 also each have 1 incoming edge from
        // 301..=420 so `edge(c, a)` cannot reject them before `a` is inspected.
        // Plus 5 disjoint triangles on 501..=515 (15 edges) -> 375 edges total.
        let mut base_facts = Vec::new();
        let mut next_id = 1_u16;
        let mut push_edge = |src: i64, dst: i64| {
            let id = rid(next_id);
            next_id = next_id.saturating_add(1);
            base_facts.push((
                "edge".to_owned(),
                vec![
                    mneme_core::Value::integer(src),
                    mneme_core::Value::integer(dst),
                ],
                id,
            ));
        };
        for idx in 1..=120_i64 {
            push_edge(idx, 0);
            push_edge(0, 120 + idx);
            push_edge(300 + idx, idx);
        }
        for tri in 0..5_i64 {
            let base = 500 + tri * 3;
            push_edge(base, base + 1);
            push_edge(base + 1, base + 2);
            push_edge(base + 2, base);
        }

        assert_eq!(base_facts.len(), 375);

        assert_eq!(base_facts.len(), 375);

        let bundle = crate::RuleBundle::new(crate::RuleBundleOptions {
            id: "cyclic-triangle-hub".to_owned(),
            version: "1".to_owned(),
            schema_version: 3,
            base_predicates: std::collections::BTreeMap::from([("edge".to_owned(), 2)]),
            complete_predicates: std::collections::BTreeSet::from(["edge".to_owned()]),
            rules: vec![crate::Rule::new(
                "triangle",
                atom("triangle", vec![var("a"), var("b"), var("c")]),
                vec![
                    crate::Literal::Positive(atom("edge", vec![var("a"), var("b")])),
                    crate::Literal::Positive(atom("edge", vec![var("b"), var("c")])),
                    crate::Literal::Positive(atom("edge", vec![var("c"), var("a")])),
                ],
            )],
        });

        let default_limits = crate::Limits::default();
        let program = bundle.validate().expect("valid");
        let context = test_context(&bundle);
        let sources = AvailabilityMap::new();
        let fixture = EvaluationFixture {
            bundle: &bundle,
            context: &context,
            limits: &default_limits,
            current_sources: &sources,
            base_facts: &base_facts,
        };

        // Under default limits (`max_result_rows: 1_000`), binary join blows past
        // the intermediate binding limit on `edge(a, b) ⋈ edge(b, c)` (14,400 tuples).
        let mut binary_default = make_evaluation(&fixture);
        evaluate_rules_binary(&mut binary_default, &program.strata);
        assert_eq!(
            binary_default.budget.status,
            crate::ExecutionStatus::Partial
        );
        assert!(binary_default.budget.limit_reached);

        // Free Join completes exhaustively well within default limits.
        let mut free_default = make_evaluation(&fixture);
        evaluate_rules(&mut free_default, &program.strata);
        assert_eq!(free_default.budget.status, crate::ExecutionStatus::Complete);
        assert!(!free_default.budget.limit_reached);
        assert!(!free_default.facts["triangle"].truncated);
        assert_eq!(
            free_default.coverage_status("triangle"),
            crate::CoverageStatus::Complete
        );
        assert_eq!(free_default.facts["triangle"].rows.len(), 15);
        assert!(
            free_default.budget.work < 5_000,
            "free join work {} should be well under 5,000",
            free_default.budget.work
        );

        // Compare full exact work under raised row/work caps.
        let generous_limits = crate::Limits {
            max_work: 5_000_000,
            max_time_ms: 60_000,
            max_result_rows: 50_000,
            ..default_limits
        };
        let (binary_work, free_work) =
            assert_equivalent_to_binary(&bundle, &base_facts, &generous_limits);
        eprintln!(
            "cyclic-triangle-hub (375 edges, 15 triangles): binary={binary_work}, free_join={free_work}"
        );
        assert!(binary_work > 50_000);
        assert!(free_work < 5_000);
    }

    #[test]
    fn cyclic_four_clique_completes_under_default_limits_vs_binary_blowup() {
        // Hub node 0 has 160 outgoing edges (0 -> 1..=160), plus two disjoint
        // directed 4-cliques on 201..=204 and 205..=208 (24 edges) -> 184 edges total.
        // Binary join `edge(a, b) ⋈ edge(a, c)` produces 160*160 = 25,600 intermediate
        // bindings before checking `edge(b, c)`, failing default `max_result_rows` (1,000)
        // and exceeding default `max_work` (100,000) even with raised row caps.
        let mut base_facts = Vec::new();
        let mut next_id = 1_u16;
        let mut push_edge = |src: i64, dst: i64| {
            let id = rid(next_id);
            next_id = next_id.saturating_add(1);
            base_facts.push((
                "edge".to_owned(),
                vec![
                    mneme_core::Value::integer(src),
                    mneme_core::Value::integer(dst),
                ],
                id,
            ));
        };
        for idx in 1..=160_i64 {
            push_edge(0, idx);
        }
        for base in [201_i64, 205_i64] {
            for i in 0..4_i64 {
                for j in 0..4_i64 {
                    if i != j {
                        push_edge(base + i, base + j);
                    }
                }
            }
        }

        let bundle = crate::RuleBundle::new(crate::RuleBundleOptions {
            id: "cyclic-k4-hub".to_owned(),
            version: "1".to_owned(),
            schema_version: 3,
            base_predicates: std::collections::BTreeMap::from([("edge".to_owned(), 2)]),
            complete_predicates: std::collections::BTreeSet::from(["edge".to_owned()]),
            rules: vec![crate::Rule::new(
                "k4",
                atom("k4", vec![var("a"), var("b"), var("c"), var("d")]),
                vec![
                    crate::Literal::Positive(atom("edge", vec![var("a"), var("b")])),
                    crate::Literal::Positive(atom("edge", vec![var("a"), var("c")])),
                    crate::Literal::Positive(atom("edge", vec![var("a"), var("d")])),
                    crate::Literal::Positive(atom("edge", vec![var("b"), var("c")])),
                    crate::Literal::Positive(atom("edge", vec![var("b"), var("d")])),
                    crate::Literal::Positive(atom("edge", vec![var("c"), var("d")])),
                ],
            )],
        });

        let default_limits = crate::Limits::default();
        let program = bundle.validate().expect("valid");
        let context = test_context(&bundle);
        let sources = AvailabilityMap::new();
        let fixture = EvaluationFixture {
            bundle: &bundle,
            context: &context,
            limits: &default_limits,
            current_sources: &sources,
            base_facts: &base_facts,
        };

        // Binary join fails under default limits (`Partial` at 1,000 intermediate bindings).
        let mut binary_default = make_evaluation(&fixture);
        evaluate_rules_binary(&mut binary_default, &program.strata);
        assert_eq!(
            binary_default.budget.status,
            crate::ExecutionStatus::Partial
        );
        assert!(binary_default.budget.limit_reached);

        // Even with raised `max_result_rows`, binary join hits `Timeout` at 100k work.
        let raised_rows = crate::Limits {
            max_result_rows: 100_000,
            ..default_limits
        };
        let raised_fixture = EvaluationFixture {
            limits: &raised_rows,
            ..fixture
        };
        let mut binary_raised = make_evaluation(&raised_fixture);
        evaluate_rules_binary(&mut binary_raised, &program.strata);
        assert_eq!(binary_raised.budget.status, crate::ExecutionStatus::Timeout);
        assert!(binary_raised.budget.limit_reached);

        // Free Join completes exhaustively under default limits in ~2k work.
        let mut free_default = make_evaluation(&fixture);
        evaluate_rules(&mut free_default, &program.strata);
        assert_eq!(free_default.budget.status, crate::ExecutionStatus::Complete);
        assert!(!free_default.budget.limit_reached);
        assert_eq!(free_default.facts["k4"].rows.len(), 48);
        assert!(
            free_default.budget.work < 5_000,
            "free join k4 work {} should be well under 5,000",
            free_default.budget.work
        );

        let generous_limits = crate::Limits {
            max_work: 5_000_000,
            max_time_ms: 60_000,
            max_result_rows: 100_000,
            ..default_limits
        };
        let (binary_work, free_work) =
            assert_equivalent_to_binary(&bundle, &base_facts, &generous_limits);
        eprintln!(
            "cyclic-4-clique-hub (184 edges, 48 k4 tuples): binary={binary_work}, free_join={free_work}"
        );
        assert!(binary_work > 100_000);
        assert!(free_work < 5_000);
    }

    #[test]
    fn property_equivalence_against_binary_and_naive_across_cyclic_seeded_programs() {
        let mut seed = 0x517C_C1B7_2722_0A95_u64;
        let mut next_u64 = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        let preds = ["e0", "e1", "t0"];
        let vars = ["a", "b", "c", "d"];

        for case_idx in 0..40_usize {
            let mut base_facts = Vec::with_capacity(60);
            let mut next_rid = 1_u16;
            for (pred_idx, pred) in preds.iter().enumerate() {
                let row_count = 4 + usize::try_from(next_u64() % 14).expect("mod 14");
                for _ in 0..row_count {
                    let v0 = i64::try_from(next_u64() % 5).expect("mod 5");
                    let v1 = i64::try_from(next_u64() % 5).expect("mod 5");
                    let v2 = i64::try_from(next_u64() % 4).expect("mod 4");
                    let id = rid(next_rid);
                    next_rid = next_rid.saturating_add(1);
                    let row = if pred_idx < 2 {
                        vec![
                            mneme_core::Value::integer(v0),
                            mneme_core::Value::integer(v1),
                        ]
                    } else {
                        vec![
                            mneme_core::Value::integer(v0),
                            mneme_core::Value::integer(v1),
                            mneme_core::Value::integer(v2),
                        ]
                    };
                    base_facts.push(((*pred).to_owned(), row, id));
                }
            }

            // Build cyclic and self-join shapes with constants, negation, and compares.
            let body = vec![
                crate::Literal::Positive(atom("e0", vec![var("a"), var("b")])),
                crate::Literal::Positive(atom("e1", vec![var("b"), var("c")])),
                crate::Literal::Positive(atom(
                    if case_idx % 2 == 0 { "e0" } else { "e1" },
                    vec![var("c"), var("a")],
                )),
                crate::Literal::Positive(atom(
                    "t0",
                    vec![
                        var(vars[case_idx % 3]),
                        var(vars[(case_idx + 1) % 3]),
                        if case_idx % 3 == 0 {
                            int_const(i64::try_from(next_u64() % 4).expect("mod 4"))
                        } else {
                            var("d")
                        },
                    ],
                )),
                crate::Literal::Negative(atom("e1", vec![var("a"), var("c")])),
                crate::Literal::Compare {
                    op: crate::CompareOp::Ne,
                    left: var("a"),
                    right: var("b"),
                },
            ];
            let head_terms = if case_idx % 4 == 0 {
                vec![var("a"), var("c")]
            } else {
                vec![var("a"), var("b"), var("c")]
            };
            let bundle = crate::RuleBundle::new(crate::RuleBundleOptions {
                id: format!("cyclic-prop-{case_idx}"),
                version: "1".to_owned(),
                schema_version: 3,
                base_predicates: std::collections::BTreeMap::from([
                    ("e0".to_owned(), 2),
                    ("e1".to_owned(), 2),
                    ("t0".to_owned(), 3),
                ]),
                complete_predicates: std::collections::BTreeSet::from([
                    "e0".to_owned(),
                    "e1".to_owned(),
                    "t0".to_owned(),
                ]),
                rules: vec![crate::Rule::new("cyc", atom("cyc", head_terms), body)],
            });

            let limits = crate::Limits {
                max_work: 5_000_000,
                max_time_ms: 60_000,
                max_result_rows: 1_000,
                max_supports_per_fact: 2,
                max_recursion_depth: 16,
            };
            assert_equivalent_to_binary_and_naive(&bundle, &base_facts, &limits);
        }
    }
}
