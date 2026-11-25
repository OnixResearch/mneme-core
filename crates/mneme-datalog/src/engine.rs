//! Snapshot fact loading, bounded fixpoint evaluation, and coverage.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

type FactKey = Vec<mneme_core::Value>;
type Binding = std::collections::BTreeMap<String, mneme_core::Value>;
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
    vaults: std::collections::BTreeSet<String>,
    temporal: Vec<String>,
}

/// The premises one binding instantiates.
struct PremiseSet {
    premises: Vec<crate::Premise>,
    sources: std::collections::BTreeSet<crate::SourceKey>,
    roots: std::collections::BTreeSet<mneme_core::RecordId>,
    vaults: std::collections::BTreeSet<String>,
    temporal: std::collections::BTreeSet<String>,
}

/// Support accumulated over one instantiated rule body.
struct PremiseSupport {
    sources: std::collections::BTreeSet<crate::SourceKey>,
    roots: std::collections::BTreeSet<mneme_core::RecordId>,
    vaults: std::collections::BTreeSet<String>,
    temporal: std::collections::BTreeSet<String>,
}

/// Work, row, time, and cancellation accounting for one evaluation.
///
/// Kept apart from the fact store so a join can charge while it holds a shared
/// borrow of the store: the two are disjoint fields of [`Evaluation`].
struct Budget<'a> {
    limits: &'a crate::Limits,
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
    fn charge(&mut self, amount: u64) -> bool {
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

struct Evaluation<'a> {
    bundle: &'a crate::RuleBundle,
    context: &'a crate::BuildContext,
    budget: Budget<'a>,
    facts: std::collections::BTreeMap<String, FactStore>,
    coverage: std::collections::BTreeMap<String, crate::CoverageStatus>,
    base_coverage: std::collections::BTreeMap<String, crate::CoverageStatus>,
    coverage_reasons: std::collections::BTreeMap<String, String>,
    participating_vaults: std::collections::BTreeSet<String>,
    at: Option<mneme_core::Timestamp>,
    derivation_eligibility: std::collections::BTreeMap<
        mneme_core::RecordId,
        std::collections::BTreeSet<mneme_core::RecordId>,
    >,
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

/// One participating vault's pinned view and byte availability.
pub(crate) struct VaultSource<'a> {
    pub alias: &'a str,
    pub served_revision: mneme_core::WorkspaceRevisionId,
    pub view: &'a mneme_memory::View,
    pub current_sources: &'a AvailabilityMap,
}

pub(crate) fn build(
    view: &mneme_memory::View,
    request: &crate::BuildRequest,
    context: &crate::BuildContext,
    program: &crate::RuleProgram,
    environment: BuildEnvironment<'_>,
) -> BuildFacts {
    let sources = [VaultSource {
        alias: crate::PRIMARY_VAULT_ALIAS,
        served_revision: context.served_revision,
        view,
        current_sources: environment.current_sources,
    }];
    build_federated(&sources, request, context, program, environment.start)
}

pub(crate) fn build_federated(
    sources: &[VaultSource<'_>],
    request: &crate::BuildRequest,
    context: &crate::BuildContext,
    program: &crate::RuleProgram,
    start: std::time::Instant,
) -> BuildFacts {
    assert!(!sources.is_empty());
    let participating_vaults = sources
        .iter()
        .map(|source| source.alias.to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(!participating_vaults.is_empty());
    let mut evaluation = Evaluation {
        bundle: &request.bundle,
        context,
        budget: Budget {
            limits: &request.limits,
            work: 0,
            stored_rows: 0,
            start,
            cancellation: request.cancellation.clone(),
            status: crate::ExecutionStatus::Complete,
            limit_reached: false,
            support_truncated: false,
        },
        facts: std::collections::BTreeMap::new(),
        coverage: std::collections::BTreeMap::new(),
        base_coverage: std::collections::BTreeMap::new(),
        coverage_reasons: std::collections::BTreeMap::new(),
        participating_vaults,
        at: request.at,
        derivation_eligibility: std::collections::BTreeMap::new(),
    };
    initialize_base_coverage(&mut evaluation, &request.incomplete_extents);
    load_base_facts(sources, &mut evaluation);
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
        let status = if super::rules::canonical_schema(predicate).is_none() {
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

struct LoadVaultContext<'a> {
    alias: &'a str,
    served_revision: mneme_core::WorkspaceRevisionId,
    view: &'a mneme_memory::View,
    current_sources: &'a AvailabilityMap,
    all_views: &'a [&'a mneme_memory::View],
}

impl LoadVaultContext<'_> {
    fn has_record(&self, id: mneme_core::RecordId) -> bool {
        self.all_views.iter().any(|view| view.record(id).is_ok())
    }

    fn wants_vault_predicate(&self, evaluation: &Evaluation<'_>, predicate: &str) -> bool {
        evaluation.bundle.base_predicates.contains_key(predicate)
    }
}

fn load_base_facts(sources: &[VaultSource<'_>], evaluation: &mut Evaluation<'_>) {
    assert!(!sources.is_empty());
    let all_views = sources.iter().map(|source| source.view).collect::<Vec<_>>();
    assert_eq!(all_views.len(), sources.len());
    for source in sources {
        evaluation.derivation_eligibility.clear();
        let vault_ctx = LoadVaultContext {
            alias: source.alias,
            served_revision: source.served_revision,
            view: source.view,
            current_sources: source.current_sources,
            all_views: &all_views,
        };
        for record in &source.view.snapshot().records {
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
            load_record_facts(&vault_ctx, record, evaluation);
            if !evaluation.budget.is_active() {
                stop_loading(evaluation);
                return;
            }
        }
    }
}

fn load_record_facts(
    ctx: &LoadVaultContext<'_>,
    record: &mneme_core::RecordEnvelope,
    evaluation: &mut Evaluation<'_>,
) {
    assert!(!ctx.alias.is_empty());
    assert_eq!(record.scope, evaluation.context.scope);
    if ctx.wants_vault_predicate(evaluation, "vault_record") {
        add_canonical_fact(
            evaluation,
            "vault_record",
            vec![
                mneme_core::Value::string(ctx.alias.to_owned()),
                record.record_id.to_value(),
            ],
            plain_row(ctx, record),
        );
    }
    match record.kind {
        mneme_core::RecordKind::Entity => load_entity_fact(ctx, record, evaluation),
        mneme_core::RecordKind::Relation => load_relation_fact(ctx, record, evaluation),
        mneme_core::RecordKind::Assertion => load_assertion_fact(ctx, record, evaluation),
        mneme_core::RecordKind::Evidence => load_evidence_fact(ctx, record, evaluation),
        mneme_core::RecordKind::Document => load_document_fact(ctx, record, evaluation),
        mneme_core::RecordKind::SourceRevision => load_source_fact(ctx, record, evaluation),
        mneme_core::RecordKind::Derivation => load_derivation_facts(ctx, record, evaluation),
        mneme_core::RecordKind::Episode
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
}

#[derive(Clone, Copy)]
struct PredicatePair {
    base: &'static str,
    vault: &'static str,
}

fn add_canonical_pair(
    ctx: &LoadVaultContext<'_>,
    evaluation: &mut Evaluation<'_>,
    predicates: PredicatePair,
    terms: Vec<mneme_core::Value>,
    row: CanonicalRow<'_>,
) {
    assert!(!ctx.alias.is_empty());
    assert!(predicates.vault.starts_with("vault_"));
    if ctx.wants_vault_predicate(evaluation, predicates.vault) {
        let mut vault_terms = Vec::with_capacity(terms.len().saturating_add(1));
        vault_terms.push(mneme_core::Value::string(ctx.alias.to_owned()));
        vault_terms.extend(terms.iter().cloned());
        add_canonical_fact(evaluation, predicates.vault, vault_terms, row.clone());
    }
    add_canonical_fact(evaluation, predicates.base, terms, row);
}

fn load_entity_fact(
    ctx: &LoadVaultContext<'_>,
    record: &mneme_core::RecordEnvelope,
    evaluation: &mut Evaluation<'_>,
) {
    assert_eq!(record.kind, mneme_core::RecordKind::Entity);
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
    let terms = vec![record.record_id.to_value(), entity_type, label];
    assert_eq!(terms.len(), 3);
    add_canonical_pair(
        ctx,
        evaluation,
        PredicatePair {
            base: "entity",
            vault: "vault_entity",
        },
        terms,
        plain_row(ctx, record),
    );
}

fn load_relation_fact(
    ctx: &LoadVaultContext<'_>,
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
        // An endpoint outside every participating view is a foreign record
        // identity, so the edge cannot ground an in-scope fact.
        if !ctx.has_record(from) || !ctx.has_record(to) {
            return;
        }
        assert!(ctx.has_record(from));
        assert!(ctx.has_record(to));
        let terms = vec![relation_type, from.to_value(), to.to_value()];
        add_canonical_pair(
            ctx,
            evaluation,
            PredicatePair {
                base: "relation",
                vault: "vault_relation",
            },
            terms,
            plain_row(ctx, record),
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
    ctx: &LoadVaultContext<'_>,
    record: &mneme_core::RecordEnvelope,
    evaluation: &mut Evaluation<'_>,
) {
    let Ok(assertion) = mneme_memory::AssertionView::parse(record.clone()) else {
        return;
    };
    if assertion.lifecycle != mneme_core::Lifecycle::Accepted
        || !ctx.view.accepted_decision(&assertion).unwrap_or(false)
        || !ctx.view.assertion_has_current_basis(&assertion)
    {
        return;
    }
    let Some(extent) = stance_extent(&assertion, &evaluation.context.scope) else {
        return;
    };
    // An out-of-scope subject would leak a record identity the caller cannot
    // see, so the whole assertion stays out of the projection.
    if !ctx.has_record(assertion.subject) {
        return;
    }
    if let Some(at) = evaluation.at
        && !valid_at(assertion.valid_time, at)
    {
        return;
    }
    let (sources, availability) = assertion_sources(ctx.view, &assertion, ctx.current_sources);
    let terms = vec![
        assertion.subject.to_value(),
        mneme_core::Value::symbol(assertion.predicate.clone()),
        assertion.value.clone(),
        assertion.record_id().to_value(),
    ];
    let temporal = temporal_parameters(assertion.valid_time);
    let predicates = match extent {
        "assertion" => PredicatePair {
            base: "assertion",
            vault: "vault_assertion",
        },
        "denial" => PredicatePair {
            base: "denial",
            vault: "vault_denial",
        },
        "hypothesis" => PredicatePair {
            base: "hypothesis",
            vault: "vault_hypothesis",
        },
        _ => return,
    };
    add_canonical_pair(
        ctx,
        evaluation,
        predicates,
        terms,
        CanonicalRow {
            record,
            sources,
            availability,
            temporal,
            vault_alias: ctx.alias,
            vault_revision: ctx.served_revision,
        },
    );
}

fn load_evidence_fact(
    ctx: &LoadVaultContext<'_>,
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
    if is_suppressed(ctx.view, record)
        || !ctx.has_record(evidence.assertion)
        || !ctx.has_record(evidence.source)
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
    let current = ctx
        .view
        .record(evidence.source)
        .ok()
        .and_then(|record| mneme_memory::SourceView::parse(record.clone()).ok())
        .filter(|source| source.availability != mneme_memory::SourceAvailability::Retained)
        .map(|source| source.availability.name().to_owned());
    let availability = source_availability(ctx.current_sources, evidence.source, current);
    let terms = vec![evidence.assertion.to_value(), evidence.source.to_value()];
    assert!(ctx.has_record(evidence.assertion));
    assert!(ctx.has_record(evidence.source));
    add_canonical_pair(
        ctx,
        evaluation,
        PredicatePair {
            base: "evidence",
            vault: "vault_evidence",
        },
        terms,
        CanonicalRow {
            record,
            sources,
            availability,
            temporal: Vec::new(),
            vault_alias: ctx.alias,
            vault_revision: ctx.served_revision,
        },
    );
}

fn load_document_fact(
    ctx: &LoadVaultContext<'_>,
    record: &mneme_core::RecordEnvelope,
    evaluation: &mut Evaluation<'_>,
) {
    assert_eq!(record.kind, mneme_core::RecordKind::Document);
    let entity = match reference_target(record, "entity") {
        // An entity outside every participating view is a foreign record identity,
        // so the document cannot contribute an in-scope fact.
        Some(entity) if !ctx.has_record(entity) => return,
        Some(entity) => entity.to_value(),
        None => mneme_core::Value::symbol("unbound"),
    };
    let path = record
        .payload
        .get("path")
        .and_then(mneme_core::Value::as_string)
        .map(|path| mneme_core::Value::string(path.to_owned()))
        .unwrap_or_else(|| mneme_core::Value::symbol("unpathed"));
    let terms = vec![record.record_id.to_value(), entity, path];
    assert_eq!(terms.len(), 3);
    add_canonical_pair(
        ctx,
        evaluation,
        PredicatePair {
            base: "document",
            vault: "vault_document",
        },
        terms,
        plain_row(ctx, record),
    );
}

fn load_source_fact(
    ctx: &LoadVaultContext<'_>,
    record: &mneme_core::RecordEnvelope,
    evaluation: &mut Evaluation<'_>,
) {
    assert_eq!(record.kind, mneme_core::RecordKind::SourceRevision);
    let Ok(source) = mneme_memory::SourceView::parse(record.clone()) else {
        return;
    };
    // Availability comes from the retained source record and the current
    // workspace overlay, never from reading the bytes: a pruned source is not
    // corrupt, and reading every blob just to label it is unbounded work.
    let availability = source_availability(
        ctx.current_sources,
        record.record_id,
        Some(source.availability.name().to_owned()),
    );
    let sources = std::collections::BTreeSet::from([(record.record_id, record.revision_id)]);
    let availability_name = match availability {
        Some(name) => name,
        None => "retained".to_owned(),
    };
    let terms = vec![
        record.record_id.to_value(),
        record.revision_id.to_value(),
        mneme_core::Value::string(availability_name),
    ];
    assert_eq!(sources.len(), 1);
    add_canonical_pair(
        ctx,
        evaluation,
        PredicatePair {
            base: "source",
            vault: "vault_source",
        },
        terms,
        CanonicalRow {
            record,
            sources,
            availability: None,
            temporal: Vec::new(),
            vault_alias: ctx.alias,
            vault_revision: ctx.served_revision,
        },
    );
}

fn load_derivation_facts(
    ctx: &LoadVaultContext<'_>,
    record: &mneme_core::RecordEnvelope,
    evaluation: &mut Evaluation<'_>,
) {
    let Ok(derivation) = mneme_memory::DerivationView::parse(record.clone()) else {
        return;
    };
    if is_suppressed(ctx.view, record)
        || !is_derivation_eligible(
            evaluation,
            ctx.view,
            derivation.conclusion,
            record.record_id,
        )
    {
        return;
    }
    for premise in &derivation.premises {
        let terms = vec![derivation.conclusion.to_value(), premise.to_value()];
        add_canonical_pair(
            ctx,
            evaluation,
            PredicatePair {
                base: "derivation",
                vault: "vault_derivation",
            },
            terms,
            plain_row(ctx, record),
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
#[derive(Clone)]
struct CanonicalRow<'a> {
    record: &'a mneme_core::RecordEnvelope,
    sources: std::collections::BTreeSet<crate::SourceKey>,
    availability: Option<String>,
    temporal: Vec<String>,
    vault_alias: &'a str,
    vault_revision: mneme_core::WorkspaceRevisionId,
}

/// A canonical row with no supporting sources and no temporal parameters.
fn plain_row<'a>(
    ctx: &LoadVaultContext<'a>,
    record: &'a mneme_core::RecordEnvelope,
) -> CanonicalRow<'a> {
    CanonicalRow {
        record,
        sources: std::collections::BTreeSet::new(),
        availability: None,
        temporal: Vec::new(),
        vault_alias: ctx.alias,
        vault_revision: ctx.served_revision,
    }
}

fn add_canonical_fact(
    evaluation: &mut Evaluation<'_>,
    predicate: &str,
    terms: FactKey,
    row: CanonicalRow<'_>,
) {
    let support = canonical_support(&row, evaluation.context);
    let record_id = row.record.record_id;
    let vaults = std::collections::BTreeSet::from([row.vault_alias.to_owned()]);
    add_fact(
        evaluation,
        predicate,
        FactContents {
            terms,
            support,
            sources: row.sources,
            canonical: Some(record_id),
            canonical_roots: std::collections::BTreeSet::from([record_id]),
            vaults,
            temporal: row.temporal,
        },
    );
}

fn canonical_support(row: &CanonicalRow<'_>, context: &crate::BuildContext) -> crate::Derivation {
    assert!(!row.vault_alias.is_empty());
    let vaults = std::collections::BTreeSet::from([row.vault_alias.to_owned()]);
    assert_eq!(vaults.len(), 1);
    crate::Derivation {
        rule_id: "canonical".to_owned(),
        rule_version: "1".to_owned(),
        premises: vec![crate::Premise {
            predicate: row.record.kind.symbol().to_owned(),
            terms: Vec::new(),
            canonical: Some(row.record.record_id),
            canonical_roots: std::collections::BTreeSet::from([row.record.record_id]),
            sources: row.sources.clone(),
            source_availability: row.availability.clone(),
            vault: Some(row.vault_alias.to_owned()),
            vaults: vaults.clone(),
            absent: false,
            coverage: None,
        }],
        sources: row.sources.clone(),
        vaults,
        temporal_parameters: row.temporal.clone(),
        revision: row.vault_revision,
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
        vaults,
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
            data.vaults.extend(vaults);
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
        data.vaults.extend(vaults);
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
            vaults,
            temporal,
        },
    );
    true
}

/// Whether two supports record the same proof.
fn same_proof(left: &crate::Derivation, right: &crate::Derivation) -> bool {
    left.rule_id == right.rule_id
        && left.vaults == right.vaults
        && left.premises.len() == right.premises.len()
        && left
            .premises
            .iter()
            .zip(&right.premises)
            .all(|(left, right)| {
                left.predicate == right.predicate
                    && left.terms == right.terms
                    && left.canonical == right.canonical
                    && left.vault == right.vault
                    && left.vaults == right.vaults
                    && left.absent == right.absent
            })
}

fn merge_premises(existing: &mut crate::Derivation, new: &crate::Derivation) {
    for premise in &new.premises {
        match existing.premises.iter_mut().find(|candidate| {
            candidate.predicate == premise.predicate
                && candidate.terms == premise.terms
                && candidate.canonical == premise.canonical
                && candidate.vault == premise.vault
                && candidate.vaults == premise.vaults
                && candidate.absent == premise.absent
        }) {
            Some(candidate) => {
                candidate.sources.extend(premise.sources.iter().copied());
                candidate
                    .canonical_roots
                    .extend(premise.canonical_roots.iter().copied());
                candidate.vaults.extend(premise.vaults.iter().cloned());
                if candidate.source_availability.is_none() {
                    candidate.source_availability = premise.source_availability.clone();
                }
            }
            None => existing.premises.push(premise.clone()),
        }
    }
    existing.sources.extend(new.sources.iter().copied());
    existing.vaults.extend(new.vaults.iter().cloned());
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
        vaults,
        temporal,
    } = premises_for_binding(rule, evaluation, binding);
    let temporal = temporal.into_iter().collect::<Vec<_>>();
    let support = crate::Derivation {
        rule_id: rule.id.clone(),
        rule_version: evaluation.context.rule_bundle_version.clone(),
        premises,
        sources: sources.clone(),
        vaults: vaults.clone(),
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
        vaults,
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
    let mut vaults = std::collections::BTreeSet::new();
    let mut temporal = std::collections::BTreeSet::new();
    for index in &row.binding_indices {
        let Some(binding) = bindings.get(*index) else {
            continue;
        };
        let premise_set = premises_for_binding(rule, evaluation, binding);
        sources.extend(premise_set.sources);
        roots.extend(premise_set.roots);
        vaults.extend(premise_set.vaults);
        temporal.extend(premise_set.temporal);
        // De-duplicate by identity instead of a linear scan over every premise
        // already collected: a group can hold thousands of bindings.
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
    let is_truncated = premises.len() > 64;
    premises.truncate(64);
    let temporal = temporal.into_iter().collect::<Vec<_>>();
    let support = crate::Derivation {
        rule_id: rule.id.clone(),
        rule_version: evaluation.context.rule_bundle_version.clone(),
        premises,
        sources: sources.clone(),
        vaults: vaults.clone(),
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
        vaults,
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
        vaults: std::collections::BTreeSet::new(),
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
                if let Some(premise) = negative_premise(evaluation, atom, binding, &mut support) {
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
        vaults: support.vaults,
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
    support.vaults.extend(data.vaults.iter().cloned());
    support.temporal.extend(data.temporal.iter().cloned());
    let vault = if data.vaults.len() == 1 {
        data.vaults.iter().next().cloned()
    } else {
        None
    };
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
        vault,
        vaults: data.vaults.clone(),
        absent: false,
        coverage: None,
    })
}

/// Record one negated literal as an explicit absence premise.
fn negative_premise(
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
    let (vault, vaults) = if atom.predicate.starts_with("vault_")
        && let Some(alias) = terms.first().and_then(mneme_core::Value::as_string)
    {
        (
            Some(alias.to_owned()),
            std::collections::BTreeSet::from([alias.to_owned()]),
        )
    } else {
        let single = if evaluation.participating_vaults.len() == 1 {
            evaluation.participating_vaults.iter().next().cloned()
        } else {
            None
        };
        (single, evaluation.participating_vaults.clone())
    };
    assert!(!atom.predicate.is_empty());
    support.vaults.extend(vaults.iter().cloned());
    assert!(!support.vaults.is_empty());
    Some(crate::Premise {
        predicate: atom.predicate.clone(),
        terms,
        canonical: None,
        canonical_roots: std::collections::BTreeSet::new(),
        sources: std::collections::BTreeSet::new(),
        source_availability: None,
        vault,
        vaults,
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
