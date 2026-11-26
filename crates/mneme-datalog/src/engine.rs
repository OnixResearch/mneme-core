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

impl FactStore {
    pub(crate) fn from_rows(rows: std::collections::BTreeMap<FactKey, crate::FactData>) -> Self {
        Self {
            rows,
            ..Self::default()
        }
    }
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
    validity: crate::FactValidity,
    epistemic: crate::EpistemicStatus,
}

/// The premises one binding instantiates.
struct PremiseSet {
    premises: Vec<crate::Premise>,
    sources: std::collections::BTreeSet<crate::SourceKey>,
    roots: std::collections::BTreeSet<mneme_core::RecordId>,
    vaults: std::collections::BTreeSet<String>,
    validity: crate::FactValidity,
    is_interval_truncated: bool,
}

/// Support accumulated over one instantiated rule body.
struct PremiseSupport {
    sources: std::collections::BTreeSet<crate::SourceKey>,
    roots: std::collections::BTreeSet<mneme_core::RecordId>,
    vaults: std::collections::BTreeSet<String>,
    validity: crate::FactValidity,
    is_interval_truncated: bool,
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
    pub max_intervals_per_fact: u64,
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

pub(super) struct Evaluation<'a> {
    bundle: &'a crate::RuleBundle,
    context: &'a crate::BuildContext,
    pub(super) budget: Budget<'a>,
    pub(super) facts: std::collections::BTreeMap<String, FactStore>,
    coverage: std::collections::BTreeMap<String, crate::CoverageStatus>,
    base_coverage: std::collections::BTreeMap<String, crate::CoverageStatus>,
    coverage_reasons: std::collections::BTreeMap<String, String>,
    participating_vaults: std::collections::BTreeSet<String>,
    at: Option<mneme_core::Timestamp>,
    derivation_eligibility: std::collections::BTreeMap<
        mneme_core::RecordId,
        std::collections::BTreeSet<mneme_core::RecordId>,
    >,
    record_contributions: std::collections::BTreeMap<mneme_core::RecordId, Vec<(String, FactKey)>>,
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
    pub temporal_config: crate::TemporalConfig,
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
    build_federated_with_config(
        &sources,
        request,
        context,
        program,
        environment.start,
        environment.temporal_config,
    )
}

pub(crate) fn build_federated(
    sources: &[VaultSource<'_>],
    request: &crate::BuildRequest,
    context: &crate::BuildContext,
    program: &crate::RuleProgram,
    start: std::time::Instant,
) -> BuildFacts {
    build_federated_with_config(
        sources,
        request,
        context,
        program,
        start,
        crate::TemporalConfig::default(),
    )
}

fn build_federated_with_config(
    sources: &[VaultSource<'_>],
    request: &crate::BuildRequest,
    context: &crate::BuildContext,
    program: &crate::RuleProgram,
    start: std::time::Instant,
    temporal_config: crate::TemporalConfig,
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
            max_intervals_per_fact: temporal_config.max_intervals_per_fact,
        },
        facts: std::collections::BTreeMap::new(),
        coverage: std::collections::BTreeMap::new(),
        base_coverage: std::collections::BTreeMap::new(),
        coverage_reasons: std::collections::BTreeMap::new(),
        participating_vaults,
        at: request.at,
        derivation_eligibility: std::collections::BTreeMap::new(),
        record_contributions: std::collections::BTreeMap::new(),
    };
    initialize_base_coverage(&mut evaluation, &request.incomplete_extents);
    load_base_facts(sources, &mut evaluation);
    evaluate_rules(&mut evaluation, &program.strata);
    if let Some(at) = evaluation.at
        && bundle_has_temporal_literals(evaluation.bundle)
    {
        filter_facts_at_timestamp(&mut evaluation.facts, at);
    }
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

fn bundle_has_temporal_literals(bundle: &crate::RuleBundle) -> bool {
    bundle.rules.iter().any(rule_has_temporal_literals)
}

fn rule_has_temporal_literals(rule: &crate::Rule) -> bool {
    rule.body.iter().any(|literal| {
        matches!(
            literal,
            crate::Literal::DiamondMinus { .. }
                | crate::Literal::BoxMinus { .. }
                | crate::Literal::Since { .. }
                | crate::Literal::Allen { .. }
        )
    })
}

fn filter_facts_at_timestamp(
    facts: &mut std::collections::BTreeMap<String, FactStore>,
    at: mneme_core::Timestamp,
) {
    for store in facts.values_mut() {
        store
            .rows
            .retain(|_, data| data.validity.contains_timestamp(at));
        store.indexes.clear();
        store.tries.clear();
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
        participating_vaults: std::collections::BTreeSet::from([
            crate::PRIMARY_VAULT_ALIAS.to_owned()
        ]),
        at: request.at,
        derivation_eligibility: std::collections::BTreeMap::new(),
        record_contributions: std::collections::BTreeMap::new(),
    };
    initialize_base_coverage(&mut evaluation, request.incomplete_extents);
    let sources = [VaultSource {
        alias: crate::PRIMARY_VAULT_ALIAS,
        served_revision: request.context.served_revision,
        view,
        current_sources: &request.current_sources,
    }];
    load_base_facts(&sources, &mut evaluation);
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
        max_intervals_per_fact: crate::DEFAULT_MAX_INTERVALS_PER_FACT,
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
            max_intervals_per_fact: crate::DEFAULT_MAX_INTERVALS_PER_FACT,
        },
        facts: kept_facts,
        coverage: base.base_coverage.clone(),
        base_coverage: base.base_coverage.clone(),
        coverage_reasons: base.coverage_reasons.clone(),
        participating_vaults: std::collections::BTreeSet::from([
            crate::PRIMARY_VAULT_ALIAS.to_owned()
        ]),
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
    assert_eq!(record.kind, mneme_core::RecordKind::Assertion);
    let Ok(assertion) = mneme_memory::AssertionView::parse(record.clone()) else {
        return;
    };
    let admission = mneme_kernel::admission::AssertionAdmissionInput {
        has_accepted_decision: assertion.lifecycle == mneme_core::Lifecycle::Accepted
            && ctx.view.accepted_decision(&assertion).unwrap_or(false),
        has_current_basis: ctx.view.assertion_has_current_basis(&assertion),
        suppressed: is_suppressed(ctx.view, record),
        subject_live: ctx.has_record(assertion.subject),
    };
    if !mneme_kernel::admission::assertion_admissible(&admission) {
        return;
    }
    let Some(extent) = stance_extent(&assertion, &evaluation.context.scope) else {
        return;
    };
    if let Some(at) = evaluation.at
        && !bundle_has_temporal_literals(evaluation.bundle)
        && !valid_at(assertion.valid_time, at)
    {
        return;
    }
    let (sources, availability) = assertion_sources(ctx.view, &assertion, ctx.current_sources);
    let record_epistemic = crate::provenance::record_epistemic_status(record);
    let epistemic = if assertion.stance == mneme_memory::Stance::Hypothesis {
        record_epistemic.join(crate::EpistemicStatus::Proposed)
    } else {
        record_epistemic
    };
    let terms = vec![
        assertion.subject.to_value(),
        mneme_core::Value::symbol(assertion.predicate.clone()),
        assertion.value.clone(),
        assertion.record_id().to_value(),
    ];
    debug_assert_eq!(terms.len(), 4);
    let validity = crate::FactValidity::from_valid_time(assertion.valid_time);
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
            validity,
            epistemic,
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
            validity: crate::FactValidity::always(),
            epistemic: crate::provenance::record_epistemic_status(record),
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
            validity: crate::FactValidity::always(),
            epistemic: crate::provenance::record_epistemic_status(record),
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

/// Whether a claim's valid time contains the evaluation instant under half-open
/// `[start, end)` semantics (with legacy `Instant(t) -> [t, t + 1ns)` compatibility).
///
/// Unknown validity is fail-closed bottom (`⊥`) and never matches any instant.
fn valid_at(valid_time: mneme_core::ValidTime, at: mneme_core::Timestamp) -> bool {
    mneme_kernel::temporal::validity_contains(
        mneme_memory::valid_time_to_kernel(valid_time),
        i128::from(at.nanos()),
    )
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
    validity: crate::FactValidity,
    epistemic: crate::EpistemicStatus,
    vault_alias: &'a str,
    vault_revision: mneme_core::WorkspaceRevisionId,
}

/// A canonical row with no supporting sources and always-valid temporal scope.
fn plain_row<'a>(
    ctx: &LoadVaultContext<'a>,
    record: &'a mneme_core::RecordEnvelope,
) -> CanonicalRow<'a> {
    CanonicalRow {
        record,
        sources: std::collections::BTreeSet::new(),
        availability: None,
        validity: crate::FactValidity::always(),
        epistemic: crate::provenance::record_epistemic_status(record),
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
    evaluation
        .record_contributions
        .entry(record_id)
        .or_default()
        .push((predicate.to_owned(), terms.clone()));
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
            validity: row.validity,
            epistemic: row.epistemic,
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
            epistemic: row.epistemic,
        }],
        sources: row.sources.clone(),
        vaults,
        temporal_parameters: row.validity.to_temporal_parameters(),
        revision: row.vault_revision,
        scope: context.scope.clone(),
        truncated: false,
        epistemic: row.epistemic,
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
    let store = evaluation.facts.entry(predicate.to_owned()).or_default();
    if store.rows.contains_key(&contents.terms) {
        return merge_existing_fact(store, contents, max_supports, &mut evaluation.budget);
    }
    insert_new_fact(store, contents);
    true
}

fn merge_existing_fact(
    store: &mut FactStore,
    contents: FactContents,
    max_supports: usize,
    budget: &mut Budget<'_>,
) -> bool {
    let FactContents {
        terms,
        support,
        sources,
        canonical_roots,
        vaults,
        validity,
        epistemic,
        ..
    } = contents;
    assert!(!support.rule_id.is_empty());
    assert_eq!(support.epistemic, epistemic);
    let Some(data) = store.rows.get_mut(&terms) else {
        return false;
    };
    let prev_epistemic = data.epistemic;
    let was_active = data.is_active();
    data.epistemic = data.epistemic.union(epistemic);
    let is_now_active = data.is_active();
    let is_upgraded = data.epistemic > prev_epistemic;
    let max_intervals = budget.max_intervals_per_fact;
    let Some((merged_validity, is_interval_truncated)) =
        data.validity
            .union_bounded(&validity, max_intervals, budget)
    else {
        return false;
    };
    let is_validity_changed = merged_validity != data.validity;
    data.validity = merged_validity;
    if is_interval_truncated {
        data.truncated = true;
        store.truncated = true;
        budget.support_truncated = true;
    }
    if let Some(existing) = data
        .supports
        .iter_mut()
        .find(|existing| same_proof(existing, &support))
    {
        merge_premises(existing, &support);
        data.sources.extend(sources);
        data.canonical_roots.extend(canonical_roots);
        data.vaults.extend(vaults);
        if !was_active && is_now_active {
            index_active_terms(store, &terms);
        }
        return is_upgraded || is_validity_changed;
    }
    if data.supports.len() >= max_supports {
        data.truncated = true;
        store.truncated = true;
        budget.support_truncated = true;
        if !was_active && is_now_active {
            index_active_terms(store, &terms);
        }
        return is_upgraded || is_validity_changed;
    }
    data.supports.push(support);
    data.sources.extend(sources);
    data.canonical_roots.extend(canonical_roots);
    data.vaults.extend(vaults);
    if !was_active && is_now_active {
        index_active_terms(store, &terms);
    }
    is_upgraded || is_validity_changed
}

fn index_active_terms(store: &mut FactStore, terms: &FactKey) {
    debug_assert!(store.rows.len() < usize::MAX);
    debug_assert!(store.indexes.len() < usize::MAX);
    if !store.indexes.is_empty() {
        for ((arity, cols), index) in &mut store.indexes {
            if terms.len() == *arity {
                let key = project_key(terms, cols);
                let bucket = index.buckets.entry(key).or_default();
                if let Err(pos) = bucket.binary_search(terms) {
                    bucket.insert(pos, terms.clone());
                }
            }
        }
    }
    if !store.tries.is_empty() {
        for ((arity, cols), trie) in &mut store.tries {
            if terms.len() == *arity {
                trie.insert(terms, cols);
            }
        }
    }
}

fn insert_new_fact(store: &mut FactStore, contents: FactContents) {
    let FactContents {
        terms,
        support,
        sources,
        canonical,
        canonical_roots,
        vaults,
        validity,
        epistemic,
    } = contents;
    assert!(!support.rule_id.is_empty());
    assert_eq!(support.epistemic, epistemic);
    if epistemic.is_active() {
        index_active_terms(store, &terms);
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
            validity,
            epistemic,
        },
    );
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
                candidate.epistemic = candidate.epistemic.union(premise.epistemic);
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
    existing.epistemic = existing
        .premises
        .iter()
        .fold(crate::EpistemicStatus::ONE, |acc, premise| {
            acc.join(premise.epistemic)
        });
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

fn kernel_coverage(status: crate::CoverageStatus) -> mneme_kernel::completeness::Coverage {
    match status {
        crate::CoverageStatus::Complete => mneme_kernel::completeness::Coverage::Complete,
        crate::CoverageStatus::Incomplete => mneme_kernel::completeness::Coverage::Incomplete,
        crate::CoverageStatus::Unknown => mneme_kernel::completeness::Coverage::Unknown,
    }
}

fn evaluate_rule(evaluation: &mut Evaluation<'_>, rule: &crate::Rule) -> RuleOutcome {
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
    let positive_count = rule
        .body
        .iter()
        .filter(|literal| matches!(literal, crate::Literal::Positive(_)))
        .count();
    let has_temporal = rule_has_temporal_literals(rule);
    let bindings = match if positive_count >= 2 && !has_temporal {
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
    Temporal {
        body_index: usize,
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

fn rule_body_coverage(
    evaluation: &Evaluation<'_>,
    rule: &crate::Rule,
) -> Option<mneme_kernel::completeness::Coverage> {
    let mut combined = mneme_kernel::completeness::Coverage::Complete;
    for literal in &rule.body {
        match literal {
            crate::Literal::Positive(atom)
            | crate::Literal::Negative(atom)
            | crate::Literal::DiamondMinus { atom, .. }
            | crate::Literal::BoxMinus { atom, .. } => {
                combined = mneme_kernel::completeness::combine_coverage(
                    combined,
                    kernel_coverage(evaluation.coverage_status(&atom.predicate)),
                );
            }
            crate::Literal::Since {
                maintained,
                trigger,
                ..
            } => {
                combined = mneme_kernel::completeness::combine_coverage(
                    combined,
                    kernel_coverage(evaluation.coverage_status(&maintained.predicate)),
                );
                combined = mneme_kernel::completeness::combine_coverage(
                    combined,
                    kernel_coverage(evaluation.coverage_status(&trigger.predicate)),
                );
            }
            crate::Literal::Allen { left, right, .. } => {
                combined = mneme_kernel::completeness::combine_coverage(
                    combined,
                    kernel_coverage(evaluation.coverage_status(&left.predicate)),
                );
                combined = mneme_kernel::completeness::combine_coverage(
                    combined,
                    kernel_coverage(evaluation.coverage_status(&right.predicate)),
                );
            }
            crate::Literal::Aggregate { .. } | crate::Literal::Compare { .. } => {}
            crate::Literal::Forbidden(_) => return None,
        }
    }
    Some(combined)
}

fn extend_atom_vars(atom: &crate::Atom, bound_vars: &mut std::collections::BTreeSet<String>) {
    for term in &atom.terms {
        if let crate::Term::Variable(name) = term {
            bound_vars.insert(name.clone());
        }
    }
}

fn is_temporal_literal(literal: &crate::Literal) -> bool {
    matches!(
        literal,
        crate::Literal::DiamondMinus { .. }
            | crate::Literal::BoxMinus { .. }
            | crate::Literal::Since { .. }
            | crate::Literal::Allen { .. }
    )
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
                extend_atom_vars(atom, &mut bound_vars);
            }
            planned_positives.push(body_index);
            steps.push(PlanStep::Positive {
                body_index,
                bound_cols,
            });
            continue;
        }
        if let Some(pos) = remaining
            .iter()
            .position(|&idx| is_temporal_literal(&rule.body[idx]))
        {
            let body_index = remaining.remove(pos);
            match &rule.body[body_index] {
                crate::Literal::DiamondMinus { atom, .. }
                | crate::Literal::BoxMinus { atom, .. } => {
                    extend_atom_vars(atom, &mut bound_vars);
                }
                crate::Literal::Since {
                    maintained,
                    trigger,
                    ..
                } => {
                    extend_atom_vars(trigger, &mut bound_vars);
                    extend_atom_vars(maintained, &mut bound_vars);
                }
                crate::Literal::Allen { left, right, .. } => {
                    extend_atom_vars(left, &mut bound_vars);
                    extend_atom_vars(right, &mut bound_vars);
                }
                _ => {}
            }
            steps.push(PlanStep::Temporal { body_index });
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
        crate::Literal::Positive(atom)
        | crate::Literal::Negative(atom)
        | crate::Literal::DiamondMinus { atom, .. }
        | crate::Literal::BoxMinus { atom, .. } => atom
            .terms
            .iter()
            .all(|term| term_is_bound(term, bound_vars)),
        crate::Literal::Since {
            maintained,
            trigger,
            ..
        } => {
            maintained
                .terms
                .iter()
                .all(|term| term_is_bound(term, bound_vars))
                && trigger
                    .terms
                    .iter()
                    .all(|term| term_is_bound(term, bound_vars))
        }
        crate::Literal::Allen { left, right, .. } => {
            left.terms
                .iter()
                .all(|term| term_is_bound(term, bound_vars))
                && right
                    .terms
                    .iter()
                    .all(|term| term_is_bound(term, bound_vars))
        }
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
            PlanStep::Temporal { body_index } => {
                let Ok(cost) = u64::try_from(bindings.len()) else {
                    return Err(RuleOutcome::Skipped);
                };
                if !evaluation.budget.charge(cost) {
                    return Err(RuleOutcome::Skipped);
                }
                bindings = execute_temporal_step(evaluation, &bindings, &rule.body[*body_index])?;
            }
            PlanStep::Negative { body_index } => {
                let crate::Literal::Negative(atom) = &rule.body[*body_index] else {
                    continue;
                };
                if !mneme_kernel::admission::non_monotonic_rule_admissible(kernel_coverage(
                    evaluation.coverage_status(&atom.predicate),
                )) {
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

fn bound_columns_from_bindings(atom: &crate::Atom, bindings: &[Binding]) -> Vec<usize> {
    let Some(sample) = bindings.first() else {
        return Vec::new();
    };
    atom.terms
        .iter()
        .enumerate()
        .filter_map(|(index, term)| match term {
            crate::Term::Constant(_) => Some(index),
            crate::Term::Variable(name) if sample.contains_key(name) => Some(index),
            crate::Term::Variable(_) => None,
        })
        .collect()
}

fn execute_temporal_step(
    evaluation: &mut Evaluation<'_>,
    bindings: &[Binding],
    literal: &crate::Literal,
) -> Result<RuleBindings, RuleOutcome> {
    match literal {
        crate::Literal::DiamondMinus { atom, .. } | crate::Literal::BoxMinus { atom, .. } => {
            let bound_cols = bound_columns_from_bindings(atom, bindings);
            join_indexed(evaluation, bindings, atom, &bound_cols)
        }
        crate::Literal::Since {
            maintained,
            trigger,
            lower_ns,
            ..
        } => {
            let trigger_cols = bound_columns_from_bindings(trigger, bindings);
            let after_trigger = join_indexed(evaluation, bindings, trigger, &trigger_cols)?;
            if after_trigger.is_empty() {
                return Ok(Vec::new());
            }
            let maintained_all_bound = after_trigger.first().is_some_and(|sample| {
                maintained.terms.iter().all(|term| match term {
                    crate::Term::Constant(_) => true,
                    crate::Term::Variable(name) => sample.contains_key(name),
                })
            });
            if *lower_ns == 0 && maintained_all_bound {
                // When lower_ns == 0 and all variables of `maintained` are already
                // bound by `trigger`, `Empty S_[0, u] trigger = trigger` still holds.
                Ok(after_trigger)
            } else {
                let maintained_cols = bound_columns_from_bindings(maintained, &after_trigger);
                join_indexed(evaluation, &after_trigger, maintained, &maintained_cols)
            }
        }
        crate::Literal::Allen { left, right, .. } => {
            let left_cols = bound_columns_from_bindings(left, bindings);
            let after_left = join_indexed(evaluation, bindings, left, &left_cols)?;
            if after_left.is_empty() {
                return Ok(Vec::new());
            }
            let right_cols = bound_columns_from_bindings(right, &after_left);
            join_indexed(evaluation, &after_left, right, &right_cols)
        }
        _ => Ok(bindings.to_vec()),
    }
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
    assert!(!rule.head.predicate.is_empty());
    debug_assert!(bindings.len() < usize::MAX);
    // Filter out bindings whose premises have an empty sequenced temporal
    // intersection before grouping, so disjoint intervals never enter COUNT/SUM.
    let mut valid_bindings = Vec::with_capacity(bindings.len());
    for binding in bindings {
        if !evaluation.budget.is_active() {
            return RuleOutcome::Skipped;
        }
        let support_ctx = SupportContext {
            context: evaluation.context,
            facts: &evaluation.facts,
            coverage: &evaluation.coverage,
            participating_vaults: &evaluation.participating_vaults,
        };
        if premises_for_binding(rule, &support_ctx, &mut evaluation.budget, binding).is_some() {
            valid_bindings.push(binding.clone());
        }
    }
    if valid_bindings.is_empty() {
        return RuleOutcome::Stable;
    }
    let grouped = match aggregate_rows(&rule.head, aggregate, &valid_bindings) {
        Ok(grouped) => grouped,
        Err(reason) => return fail_relation(evaluation, &rule.head.predicate, reason),
    };
    let mut is_changed = false;
    for aggregate_row in grouped {
        if !evaluation.budget.is_active() {
            break;
        }
        let support_ctx = SupportContext {
            context: evaluation.context,
            facts: &evaluation.facts,
            coverage: &evaluation.coverage,
            participating_vaults: &evaluation.participating_vaults,
        };
        let Some(contents) = aggregate_support(
            rule,
            &support_ctx,
            &mut evaluation.budget,
            &valid_bindings,
            &aggregate_row,
        ) else {
            if !evaluation.budget.is_active() {
                break;
            }
            continue;
        };
        if !contents.epistemic.is_active() {
            continue;
        }
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
    assert!(!rule.head.predicate.is_empty());
    debug_assert!(bindings.len() < usize::MAX);
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
        let support_ctx = SupportContext {
            context: evaluation.context,
            facts: &evaluation.facts,
            coverage: &evaluation.coverage,
            participating_vaults: &evaluation.participating_vaults,
        };
        let Some(contents) =
            instantiated_support(rule, &support_ctx, &mut evaluation.budget, binding, terms)
        else {
            if !evaluation.budget.is_active() {
                break;
            }
            continue;
        };
        if !contents.epistemic.is_active() {
            continue;
        }
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
    assert!(!predicate.is_empty());
    assert!(!bound_cols.is_empty());
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
    for (terms, data) in &store.rows {
        if !evaluation.budget.charge(1) {
            return Err(RuleOutcome::Skipped);
        }
        if terms.len() != arity || !data.is_active() {
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
    assert!(!atom.predicate.is_empty());
    debug_assert!(bindings.len() < usize::MAX);
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
            && data.is_active()
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
    assert!(!atom.predicate.is_empty());
    debug_assert!(binding.len() < usize::MAX);
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
            .is_some_and(crate::FactData::is_active);
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
    for (terms, data) in &store.rows {
        if !evaluation.budget.charge(1) {
            return Err(RuleOutcome::Skipped);
        }
        if data.is_active()
            && data.epistemic.negation_blocks()
            && terms.len() == arity
            && atom_matches_row(atom, terms, binding)
        {
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
    assert!(!atom.predicate.is_empty());
    assert!(!bound_cols.is_empty());
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
        if store
            .rows
            .get(terms)
            .is_some_and(crate::FactData::is_active)
            && atom_matches_row(atom, terms, binding)
        {
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
    assert!(!atom.predicate.is_empty());
    debug_assert_eq!(atom.terms.len(), terms.len());
    if !data.is_active() {
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

pub(crate) fn compare_fact_values(
    op: crate::CompareOp,
    left: &mneme_core::Value,
    right: &mneme_core::Value,
) -> bool {
    compare_values(op, left, right)
}

pub(crate) fn compute_aggregate_value(
    function: crate::AggregateFunction,
    values: Vec<mneme_core::Value>,
) -> Result<mneme_core::Value, &'static str> {
    aggregate_value(function, values)
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

/// Read-only evaluation context needed to instantiate premises and derivations.
struct SupportContext<'a> {
    context: &'a crate::BuildContext,
    facts: &'a std::collections::BTreeMap<String, FactStore>,
    coverage: &'a std::collections::BTreeMap<String, crate::CoverageStatus>,
    participating_vaults: &'a std::collections::BTreeSet<String>,
}

impl SupportContext<'_> {
    fn coverage_status(&self, predicate: &str) -> crate::CoverageStatus {
        self.coverage
            .get(predicate)
            .copied()
            .unwrap_or(crate::CoverageStatus::Unknown)
    }
}

fn instantiated_support(
    rule: &crate::Rule,
    support_ctx: &SupportContext<'_>,
    budget: &mut Budget<'_>,
    binding: &Binding,
    terms: FactKey,
) -> Option<FactContents> {
    assert!(!rule.id.is_empty());
    debug_assert_eq!(terms.len(), rule.head.terms.len());
    if !budget.is_active() {
        return None;
    }
    let PremiseSet {
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
    Some(FactContents {
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

type PremiseIdentity = (
    String,
    Vec<mneme_core::Value>,
    Option<String>,
    std::collections::BTreeSet<String>,
    bool,
);

fn extend_unique_premises(
    incoming: Vec<crate::Premise>,
    seen: &mut std::collections::BTreeSet<PremiseIdentity>,
    premises: &mut Vec<crate::Premise>,
) {
    for premise in incoming {
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

fn aggregate_support(
    rule: &crate::Rule,
    support_ctx: &SupportContext<'_>,
    budget: &mut Budget<'_>,
    bindings: &[Binding],
    row: &AggregateRow,
) -> Option<FactContents> {
    assert!(!rule.id.is_empty());
    debug_assert_eq!(row.head_terms.len(), rule.head.terms.len());
    if !budget.is_active() {
        return None;
    }
    let mut premises = Vec::with_capacity(row.binding_indices.len());
    let mut seen = std::collections::BTreeSet::new();
    let mut sources = std::collections::BTreeSet::new();
    let mut roots = std::collections::BTreeSet::new();
    let mut vaults = std::collections::BTreeSet::new();
    let mut validity: Option<crate::FactValidity> = None;
    let mut is_interval_truncated = false;
    let mut epistemic = crate::EpistemicStatus::ONE;
    for index in &row.binding_indices {
        if !budget.is_active() {
            return None;
        }
        let Some(binding) = bindings.get(*index) else {
            continue;
        };
        let premise_set = premises_for_binding(rule, support_ctx, budget, binding)?;
        sources.extend(premise_set.sources);
        roots.extend(premise_set.roots);
        vaults.extend(premise_set.vaults);
        is_interval_truncated = is_interval_truncated || premise_set.is_interval_truncated;
        validity = match validity {
            None => Some(premise_set.validity),
            Some(current) => {
                let max_intervals = budget.max_intervals_per_fact;
                let (merged, truncated) =
                    current.union_bounded(&premise_set.validity, max_intervals, budget)?;
                is_interval_truncated = is_interval_truncated || truncated;
                Some(merged)
            }
        };
        let binding_epistemic = premise_set
            .premises
            .iter()
            .fold(crate::EpistemicStatus::ONE, |acc, premise| {
                acc.join(premise.epistemic)
            });
        epistemic = epistemic.join(binding_epistemic);
        extend_unique_premises(premise_set.premises, &mut seen, &mut premises);
    }
    if !budget.is_active() {
        return None;
    }
    let validity = validity.unwrap_or_else(crate::FactValidity::always);
    let is_truncated = premises.len() > 64 || is_interval_truncated;
    if is_interval_truncated {
        budget.support_truncated = true;
    }
    premises.truncate(64);
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
        truncated: is_truncated,
        epistemic,
    };
    Some(FactContents {
        terms: row.head_terms.clone(),
        support,
        sources,
        canonical: None,
        canonical_roots: roots,
        vaults,
        validity,
        epistemic,
    })
}

/// Instantiate every premise a binding relies on.
///
/// A negated literal never has a matching row, so it is recorded as an explicit
/// absence premise together with the relation coverage the rule required;
/// otherwise a derivation that rests on negation would look like it rested on
/// the positive body alone. Returns `None` if budget expires or any required
/// positive premise cannot be resolved to an active row, preventing silent
/// promotion of a truncated premise set to `EpistemicStatus::Accepted`.
fn premises_for_binding(
    rule: &crate::Rule,
    support_ctx: &SupportContext<'_>,
    budget: &mut Budget<'_>,
    binding: &Binding,
) -> Option<PremiseSet> {
    assert!(!rule.id.is_empty());
    let mut premises = Vec::with_capacity(rule.body.len());
    let mut support = PremiseSupport {
        sources: std::collections::BTreeSet::new(),
        roots: std::collections::BTreeSet::new(),
        vaults: std::collections::BTreeSet::new(),
        validity: crate::FactValidity::always(),
        is_interval_truncated: false,
    };
    for literal in &rule.body {
        match literal {
            crate::Literal::Positive(atom) => {
                let premise = positive_premise(support_ctx, budget, atom, binding, &mut support)?;
                premises.push(premise);
            }
            crate::Literal::Negative(atom) => {
                let premise = negative_premise(support_ctx, budget, atom, binding, &mut support)?;
                premises.push(premise);
            }
            crate::Literal::DiamondMinus {
                atom,
                lower_ns,
                upper_ns,
            } => {
                let window = mneme_kernel::temporal::MetricWindow {
                    lower: *lower_ns,
                    upper: *upper_ns,
                };
                let premise = unary_metric_premise(
                    support_ctx,
                    budget,
                    atom,
                    binding,
                    &mut support,
                    UnaryMetricOp::DiamondMinus(window),
                )?;
                premises.push(premise);
            }
            crate::Literal::BoxMinus {
                atom,
                lower_ns,
                upper_ns,
            } => {
                let window = mneme_kernel::temporal::MetricWindow {
                    lower: *lower_ns,
                    upper: *upper_ns,
                };
                let premise = unary_metric_premise(
                    support_ctx,
                    budget,
                    atom,
                    binding,
                    &mut support,
                    UnaryMetricOp::BoxMinus(window),
                )?;
                premises.push(premise);
            }
            crate::Literal::Since {
                maintained,
                trigger,
                lower_ns,
                upper_ns,
            } => {
                let window = mneme_kernel::temporal::MetricWindow {
                    lower: *lower_ns,
                    upper: *upper_ns,
                };
                since_premises(
                    support_ctx,
                    budget,
                    maintained,
                    trigger,
                    window,
                    binding,
                    &mut support,
                    &mut premises,
                )?;
            }
            crate::Literal::Allen {
                relation,
                left,
                right,
            } => {
                allen_premises(
                    support_ctx,
                    budget,
                    *relation,
                    left,
                    right,
                    binding,
                    &mut support,
                    &mut premises,
                )?;
            }
            _ => {}
        }
    }
    if !budget.is_active() {
        return None;
    }
    debug_assert!(premises.len() <= rule.body.len().saturating_mul(2));
    Some(PremiseSet {
        premises,
        sources: support.sources,
        roots: support.roots,
        vaults: support.vaults,
        validity: support.validity,
        is_interval_truncated: support.is_interval_truncated,
    })
}

enum UnaryMetricOp {
    DiamondMinus(mneme_kernel::temporal::MetricWindow),
    BoxMinus(mneme_kernel::temporal::MetricWindow),
}

fn apply_sequenced_validity(
    support: &mut PremiseSupport,
    incoming: &crate::FactValidity,
    budget: &mut Budget<'_>,
) -> bool {
    let max_intervals = budget.max_intervals_per_fact;
    let Some(bounded) = support
        .validity
        .intersect_bounded(incoming, max_intervals, budget)
    else {
        return false;
    };
    if bounded.set.is_empty() {
        return false;
    }
    support.is_interval_truncated = support.is_interval_truncated || bounded.is_truncated;
    support.validity = crate::FactValidity::Known(bounded.set);
    true
}

fn resolve_active_fact<'a>(
    support_ctx: &'a SupportContext<'a>,
    budget: &mut Budget<'_>,
    atom: &crate::Atom,
    binding: &Binding,
) -> Option<(FactKey, &'a crate::FactData)> {
    assert!(!atom.predicate.is_empty());
    if !budget.charge(1) {
        return None;
    }
    let terms = atom
        .terms
        .iter()
        .filter_map(|term| term_value(term, binding))
        .collect::<Vec<_>>();
    let data = support_ctx
        .facts
        .get(&atom.predicate)
        .and_then(|store| store.rows.get(&terms))
        .filter(|data| data.is_active())?;
    debug_assert!(data.epistemic != crate::EpistemicStatus::Rejected);
    Some((terms, data))
}

fn record_fact_premise(
    predicate: &str,
    terms: FactKey,
    data: &crate::FactData,
    support: &mut PremiseSupport,
) -> crate::Premise {
    support.sources.extend(data.sources.iter().copied());
    support.roots.extend(data.canonical_roots.iter().copied());
    support.vaults.extend(data.vaults.iter().cloned());
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

/// Instantiate one positive literal against the active fact it matches.
///
/// Charges the budget first; `None` means the charge failed, no active row matched,
/// or sequenced valid-time intersection with prior premises is empty.
fn positive_premise(
    support_ctx: &SupportContext<'_>,
    budget: &mut Budget<'_>,
    atom: &crate::Atom,
    binding: &Binding,
    support: &mut PremiseSupport,
) -> Option<crate::Premise> {
    let (terms, data) = resolve_active_fact(support_ctx, budget, atom, binding)?;
    if !apply_sequenced_validity(support, &data.validity, budget) {
        return None;
    }
    Some(record_fact_premise(&atom.predicate, terms, data, support))
}

fn unary_metric_premise(
    support_ctx: &SupportContext<'_>,
    budget: &mut Budget<'_>,
    atom: &crate::Atom,
    binding: &Binding,
    support: &mut PremiseSupport,
    op: UnaryMetricOp,
) -> Option<crate::Premise> {
    let (terms, data) = resolve_active_fact(support_ctx, budget, atom, binding)?;
    let set = data.validity.as_interval_set()?;
    let max_intervals = budget.max_intervals_per_fact;
    let bounded = match op {
        UnaryMetricOp::DiamondMinus(window) => {
            set.diamond_minus_bounded(window, max_intervals, budget)?
        }
        UnaryMetricOp::BoxMinus(window) => set.box_minus_bounded(window, max_intervals, budget)?,
    };
    if bounded.set.is_empty() {
        return None;
    }
    support.is_interval_truncated = support.is_interval_truncated || bounded.is_truncated;
    if !apply_sequenced_validity(support, &crate::FactValidity::Known(bounded.set), budget) {
        return None;
    }
    Some(record_fact_premise(&atom.predicate, terms, data, support))
}

#[allow(clippy::too_many_arguments)]
fn since_premises(
    support_ctx: &SupportContext<'_>,
    budget: &mut Budget<'_>,
    maintained: &crate::Atom,
    trigger: &crate::Atom,
    window: mneme_kernel::temporal::MetricWindow,
    binding: &Binding,
    support: &mut PremiseSupport,
    premises: &mut Vec<crate::Premise>,
) -> Option<()> {
    let (t_terms, t_data) = resolve_active_fact(support_ctx, budget, trigger, binding)?;
    let t_set = t_data.validity.as_interval_set()?;
    let empty_maintained = crate::IntervalSet::empty();
    let maintained_match = resolve_active_fact(support_ctx, budget, maintained, binding);
    let m_set = match &maintained_match {
        Some((_, m_data)) => m_data.validity.as_interval_set()?,
        None if window.lower == 0 => &empty_maintained,
        None => return None,
    };
    let max_intervals = budget.max_intervals_per_fact;
    let bounded = m_set.since_bounded(t_set, window, max_intervals, budget)?;
    if bounded.set.is_empty() {
        return None;
    }
    support.is_interval_truncated = support.is_interval_truncated || bounded.is_truncated;
    if !apply_sequenced_validity(support, &crate::FactValidity::Known(bounded.set), budget) {
        return None;
    }
    if let Some((m_terms, m_data)) = maintained_match {
        premises.push(record_fact_premise(
            &maintained.predicate,
            m_terms,
            m_data,
            support,
        ));
    }
    premises.push(record_fact_premise(
        &trigger.predicate,
        t_terms,
        t_data,
        support,
    ));
    Some(())
}

#[allow(clippy::too_many_arguments)]
fn allen_premises(
    support_ctx: &SupportContext<'_>,
    budget: &mut Budget<'_>,
    relation: mneme_kernel::temporal::AllenRelation,
    left: &crate::Atom,
    right: &crate::Atom,
    binding: &Binding,
    support: &mut PremiseSupport,
    premises: &mut Vec<crate::Premise>,
) -> Option<()> {
    let (l_terms, l_data) = resolve_active_fact(support_ctx, budget, left, binding)?;
    let (r_terms, r_data) = resolve_active_fact(support_ctx, budget, right, binding)?;
    let l_set = l_data.validity.as_interval_set()?;
    let r_set = r_data.validity.as_interval_set()?;
    let max_intervals = budget.max_intervals_per_fact;
    let bounded = l_set.allen_bounded(r_set, relation, max_intervals, budget)?;
    if bounded.set.is_empty() {
        return None;
    }
    support.is_interval_truncated = support.is_interval_truncated || bounded.is_truncated;
    if !apply_sequenced_validity(support, &crate::FactValidity::Known(bounded.set), budget) {
        return None;
    }
    premises.push(record_fact_premise(
        &left.predicate,
        l_terms,
        l_data,
        support,
    ));
    premises.push(record_fact_premise(
        &right.predicate,
        r_terms,
        r_data,
        support,
    ));
    Some(())
}

/// Record one negated literal as an explicit absence premise.
fn negative_premise(
    support_ctx: &SupportContext<'_>,
    budget: &mut Budget<'_>,
    atom: &crate::Atom,
    binding: &Binding,
    support: &mut PremiseSupport,
) -> Option<crate::Premise> {
    if !budget.charge(1) {
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
        let single = if support_ctx.participating_vaults.len() == 1 {
            support_ctx.participating_vaults.iter().next().cloned()
        } else {
            None
        };
        (single, support_ctx.participating_vaults.clone())
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
            support_ctx
                .coverage_status(&atom.predicate)
                .name()
                .to_owned(),
        ),
        epistemic: crate::EpistemicStatus::Accepted,
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

pub(crate) fn compute_derived_coverage(
    bundle: &crate::RuleBundle,
    base_coverage: &std::collections::BTreeMap<String, crate::CoverageStatus>,
    coverage_reasons: &std::collections::BTreeMap<String, String>,
    budget_status: crate::ExecutionStatus,
) -> std::collections::BTreeMap<String, crate::CoverageStatus> {
    let heads = bundle
        .rules
        .iter()
        .map(|rule| rule.head.predicate.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let mut current = base_coverage.clone();
    let passes = heads.len().saturating_add(2);
    debug_assert!(passes >= 2);
    debug_assert!(current.len() >= base_coverage.len());
    for _ in 0..passes {
        let mut next = base_coverage.clone();
        for head in &heads {
            next.insert(
                head.clone(),
                head_coverage_from(bundle, &current, budget_status, head),
            );
        }
        // A relation that failed with a type or binding error stays incomplete
        // even when its inputs happen to be complete.
        for predicate in coverage_reasons.keys() {
            next.insert(predicate.clone(), crate::CoverageStatus::Incomplete);
        }
        if next == current {
            return current;
        }
        current = next;
    }
    current
}

fn update_derived_coverage(evaluation: &mut Evaluation<'_>) {
    evaluation.coverage = compute_derived_coverage(
        evaluation.bundle,
        &evaluation.base_coverage,
        &evaluation.coverage_reasons,
        evaluation.budget.status,
    );
}

/// The coverage a derived head may claim from its rules and their inputs.
fn head_coverage_from(
    bundle: &crate::RuleBundle,
    coverage: &std::collections::BTreeMap<String, crate::CoverageStatus>,
    budget_status: crate::ExecutionStatus,
    head: &str,
) -> crate::CoverageStatus {
    assert!(!head.is_empty());
    debug_assert!(bundle.rules.len() < usize::MAX);
    let mut is_all_complete = true;
    let mut is_any_incomplete = false;
    let mut has_seed = false;
    for rule in &bundle.rules {
        if rule.head.predicate != head {
            continue;
        }
        let has_self = rule.body.iter().any(
            |literal| matches!(literal, crate::Literal::Positive(atom) if atom.predicate == head),
        );
        has_seed = has_seed || !has_self;
        let is_body_complete = budget_status == crate::ExecutionStatus::Complete
            && rule.body.iter().all(|literal| match literal {
                crate::Literal::Positive(atom) => {
                    atom.predicate == head
                        || coverage
                            .get(&atom.predicate)
                            .copied()
                            .unwrap_or(crate::CoverageStatus::Unknown)
                            == crate::CoverageStatus::Complete
                }
                crate::Literal::Negative(atom)
                | crate::Literal::DiamondMinus { atom, .. }
                | crate::Literal::BoxMinus { atom, .. } => {
                    coverage
                        .get(&atom.predicate)
                        .copied()
                        .unwrap_or(crate::CoverageStatus::Unknown)
                        == crate::CoverageStatus::Complete
                }
                crate::Literal::Since {
                    maintained,
                    trigger,
                    ..
                } => {
                    coverage
                        .get(&maintained.predicate)
                        .copied()
                        .unwrap_or(crate::CoverageStatus::Unknown)
                        == crate::CoverageStatus::Complete
                        && coverage
                            .get(&trigger.predicate)
                            .copied()
                            .unwrap_or(crate::CoverageStatus::Unknown)
                            == crate::CoverageStatus::Complete
                }
                crate::Literal::Allen { left, right, .. } => {
                    coverage
                        .get(&left.predicate)
                        .copied()
                        .unwrap_or(crate::CoverageStatus::Unknown)
                        == crate::CoverageStatus::Complete
                        && coverage
                            .get(&right.predicate)
                            .copied()
                            .unwrap_or(crate::CoverageStatus::Unknown)
                            == crate::CoverageStatus::Complete
                }
                crate::Literal::Compare { .. } | crate::Literal::Aggregate { .. } => true,
                crate::Literal::Forbidden(_) => false,
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
        participating_vaults: std::collections::BTreeSet::from([
            crate::PRIMARY_VAULT_ALIAS.to_owned()
        ]),
        at: request.at,
        derivation_eligibility: std::collections::BTreeMap::new(),
        record_contributions: std::collections::BTreeMap::new(),
    };
    initialize_base_coverage(&mut evaluation, request.incomplete_extents);
    evaluate_impacted_records(view, records, current_sources, eval_ids, &mut evaluation);
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
    current_sources: &AvailabilityMap,
    eval_ids: &std::collections::BTreeSet<mneme_core::RecordId>,
    evaluation: &mut Evaluation<'_>,
) {
    assert!(evaluation.budget.limits.max_work > 0);
    let all_views = [view];
    let vault_ctx = LoadVaultContext {
        alias: crate::PRIMARY_VAULT_ALIAS,
        served_revision: evaluation.context.served_revision,
        view,
        current_sources,
        all_views: &all_views,
    };
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
        load_record_facts(&vault_ctx, record, evaluation);
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

struct ExistingRowTransition<'a> {
    pred: &'a str,
    key: &'a FactKey,
    old_data: &'a crate::FactData,
    new_data: Option<&'a crate::FactData>,
}

struct ReconcileAccum {
    base_deltas: std::collections::BTreeMap<String, crate::zset::ZSet<FactKey>>,
    dirty_provenance: std::collections::BTreeSet<(String, FactKey)>,
}

fn reconcile_existing_row(
    row: ExistingRowTransition<'_>,
    reconciled: &mut ReconciledFacts,
    accum: &mut ReconcileAccum,
) -> Result<(), crate::Error> {
    assert!(!row.pred.is_empty());
    let was_active = row.old_data.is_active();
    if let Some(new_data) = row.new_data {
        let is_now_active = new_data.is_active();
        if was_active != is_now_active {
            let weight = if is_now_active { 1 } else { -1 };
            accum
                .base_deltas
                .entry(row.pred.to_owned())
                .or_default()
                .insert_weighted(row.key.clone(), weight)?;
        } else if was_active && !same_semantic_fact_data(row.old_data, new_data) {
            accum
                .dirty_provenance
                .insert((row.pred.to_owned(), row.key.clone()));
        }
        reconciled
            .next_facts
            .entry(row.pred.to_owned())
            .or_default()
            .rows
            .insert(row.key.clone(), new_data.clone());
    } else if was_active {
        accum
            .base_deltas
            .entry(row.pred.to_owned())
            .or_default()
            .insert_weighted(row.key.clone(), -1)?;
    }
    debug_assert!(accum.dirty_provenance.len() < usize::MAX);
    Ok(())
}

fn reconcile_delta_facts(
    input: ReconcileDeltaInput<'_>,
    reconciled: &mut ReconciledFacts,
) -> Result<ReconciledDeltaOutput, crate::Error> {
    assert!(input.old_rows.len() < usize::MAX);
    let mut accum = ReconcileAccum {
        base_deltas: std::collections::BTreeMap::new(),
        dirty_provenance: std::collections::BTreeSet::new(),
    };

    for store in reconciled.next_facts.values_mut() {
        for data in store.rows.values_mut() {
            for support in &mut data.supports {
                support.revision = input.target_revision;
            }
        }
    }
    for ((pred, key), old_data) in input.old_rows {
        let new_data = input.temp_facts.get(pred).and_then(|s| s.rows.get(key));
        reconcile_existing_row(
            ExistingRowTransition {
                pred,
                key,
                old_data,
                new_data,
            },
            reconciled,
            &mut accum,
        )?;
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
                if new_data.is_active() {
                    accum
                        .base_deltas
                        .entry(pred.clone())
                        .or_default()
                        .insert_weighted(key.clone(), 1)?;
                }
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
    debug_assert!(accum.dirty_provenance.len() <= input.old_rows.len());
    Ok((accum.base_deltas, accum.dirty_provenance))
}

fn same_semantic_fact_data(left: &crate::FactData, right: &crate::FactData) -> bool {
    left.sources == right.sources
        && left.canonical == right.canonical
        && left.canonical_roots == right.canonical_roots
        && left.vaults == right.vaults
        && left.validity == right.validity
        && left.epistemic == right.epistemic
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
    pub facts: &'a std::collections::BTreeMap<String, FactStore>,
    pub coverage_map: &'a std::collections::BTreeMap<String, crate::CoverageStatus>,
    pub bindings: &'a [Binding],
    pub target_terms: &'a FactKey,
}

pub(crate) fn build_ordinary_fact_data_from_bindings(
    request: FactDataBuildRequest<'_>,
    budget: &mut Budget<'_>,
    target_store: &mut FactStore,
) -> bool {
    build_fact_data_with(
        &request,
        budget,
        target_store,
        |rule, support_ctx, budget, target_terms, temp| {
            for binding in request.bindings {
                if !budget.is_active() {
                    return;
                }
                let Some(contents) =
                    instantiated_support(rule, support_ctx, budget, binding, target_terms.clone())
                else {
                    return;
                };
                merge_fact_contents(temp, &rule.head.predicate, contents, budget);
            }
        },
    )
}

pub(crate) fn build_aggregate_fact_data_from_bindings(
    request: FactDataBuildRequest<'_>,
    budget: &mut Budget<'_>,
    target_store: &mut FactStore,
) -> bool {
    build_fact_data_with(
        &request,
        budget,
        target_store,
        |rule, support_ctx, budget, target_terms, temp| {
            if !budget.is_active() {
                return;
            }
            let binding_indices: Vec<usize> = (0..request.bindings.len()).collect();
            let row = AggregateRow {
                head_terms: target_terms.clone(),
                binding_indices,
            };
            let Some(contents) =
                aggregate_support(rule, support_ctx, budget, request.bindings, &row)
            else {
                return;
            };
            merge_fact_contents(temp, &rule.head.predicate, contents, budget);
        },
    )
}

fn build_fact_data_with<F>(
    request: &FactDataBuildRequest<'_>,
    budget: &mut Budget<'_>,
    target_store: &mut FactStore,
    build: F,
) -> bool
where
    F: FnOnce(
        &crate::Rule,
        &SupportContext<'_>,
        &mut Budget<'_>,
        &FactKey,
        &mut std::collections::BTreeMap<String, FactStore>,
    ),
{
    assert!(!request.rule.head.predicate.is_empty());
    if !budget.is_active() {
        return false;
    }
    let participating_vaults = if request.context.vaults.is_empty() {
        std::collections::BTreeSet::from([crate::PRIMARY_VAULT_ALIAS.to_owned()])
    } else {
        request
            .context
            .vaults
            .iter()
            .map(|vault| vault.alias.clone())
            .collect()
    };
    let support_ctx = SupportContext {
        context: request.context,
        facts: request.facts,
        coverage: request.coverage_map,
        participating_vaults: &participating_vaults,
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
        &support_ctx,
        budget,
        request.target_terms,
        &mut temp,
    );
    if !budget.is_active() {
        return false;
    }
    debug_assert!(budget.limits.max_supports_per_fact > 0);
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
            budget.support_truncated = true;
        }
        return is_truncated;
    }
    false
}

fn merge_fact_contents(
    temp_facts: &mut std::collections::BTreeMap<String, FactStore>,
    predicate: &str,
    contents: FactContents,
    budget: &mut Budget<'_>,
) {
    assert!(!predicate.is_empty());
    let max_supports = budget.limits.max_supports_per_fact;
    assert!(max_supports > 0);
    if !budget.is_active() || !contents.epistemic.is_active() {
        return;
    }
    if !budget.charge(1) {
        return;
    }
    let FactContents {
        terms,
        support,
        sources,
        canonical,
        canonical_roots,
        vaults,
        validity,
        epistemic,
    } = contents;
    let store = temp_facts.entry(predicate.to_owned()).or_default();
    if let Some(data) = store.rows.get_mut(&terms) {
        data.epistemic = data.epistemic.union(epistemic);
        let max_intervals = budget.max_intervals_per_fact;
        let Some((merged_validity, is_interval_truncated)) =
            data.validity
                .union_bounded(&validity, max_intervals, budget)
        else {
            return;
        };
        data.validity = merged_validity;
        if is_interval_truncated {
            data.truncated = true;
            store.truncated = true;
            budget.support_truncated = true;
        }
        if let Some(existing) = data
            .supports
            .iter_mut()
            .find(|existing| same_proof(existing, &support))
        {
            merge_premises(existing, &support);
            data.sources.extend(sources);
            data.canonical_roots.extend(canonical_roots);
            data.vaults.extend(vaults);
            return;
        }
        if data.supports.len() >= max_supports {
            data.truncated = true;
            store.truncated = true;
            budget.support_truncated = true;
            return;
        }
        data.supports.push(support);
        data.sources.extend(sources);
        data.canonical_roots.extend(canonical_roots);
        data.vaults.extend(vaults);
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
            vaults,
            validity,
            epistemic,
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
        participating_vaults: std::collections::BTreeSet::from([
            crate::PRIMARY_VAULT_ALIAS.to_owned()
        ]),
        at: request.at,
        derivation_eligibility: request.base.derivation_eligibility.clone(),
        record_contributions: std::collections::BTreeMap::new(),
    };
    let _ = request.base.current_sources;
    update_derived_coverage(&mut evaluation);
    let coverage = final_coverage(&evaluation);
    let status = overall_status(evaluation.budget.status, &coverage);
    (evaluation.coverage, coverage, status)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_scope() -> mneme_core::ScopeId {
        mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "datalog-unit")
            .expect("valid scope")
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
        for (terms, data) in &store.rows {
            if !evaluation.budget.charge(1) {
                return Err(RuleOutcome::Skipped);
            }
            if data.is_active() && atom_matches_row(atom, terms, binding) {
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
                assert_eq!(planned_data.validity, naive_data.validity);
                assert_eq!(planned_data.epistemic, naive_data.epistemic);
            }
        }
        (naive.budget.work, planned.budget.work)
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
}

#[cfg(test)]
#[path = "engine/tests.rs"]
mod extra_tests;
