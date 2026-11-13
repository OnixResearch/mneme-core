//! Bounded recall service over one mutable workspace handle.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// Ranking/fusion policy version.
pub const FUSION_POLICY_VERSION: &str = "rrf-k60-v1";
const RRF_K: f64 = 60.0;
/// Smallest item text that can carry its attribution inside the context budget.
const MIN_ITEM_BYTES: usize = 32;
/// Longest accepted query text.
const MAX_QUERY_BYTES: usize = 4096;
/// Deterministic work bound for one recall, in charged units.
const WORK_LIMIT: u64 = 20_000_000;
/// Units of work charged between two clock and cancellation observations.
const BUDGET_CHECK_INTERVAL: u64 = 256;
/// Attempts made when an eligibility barrier advances under a recall.
const RECALL_ATTEMPTS: u32 = 2;
/// Retained revision bound for the history one recall loads.
const MAX_HISTORY_REVISIONS: usize = 1_000_000;
/// Bounded support walk one ranked claim may pay for.
const EXPLANATION_NODES: usize = 4096;
/// Disclosure that a claim's support set is incomplete.
const SUPPORT_LIMITED: &str =
    "a claim citation is unresolved or ineligible, so its support is incomplete";
/// Disclosure that a claim's support walk could not finish.
const SUPPORT_UNRESOLVED: &str =
    "a claim's support ancestry could not be resolved, so its independence is not claimed";

/// A caller's explicit scope authorization; `None` is the operator.
type Authorization = Option<std::collections::BTreeSet<mneme_core::ScopeId>>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct IndexKey {
    revision: mneme_core::WorkspaceRevisionId,
    scope: mneme_core::ScopeId,
    /// The caller's authorization, because it decides which scopes are indexed.
    /// `None` is the operator.
    authorized: Authorization,
    generation: u64,
    temporal: crate::model::TemporalMode,
    at: mneme_core::Timestamp,
    include_disputed: bool,
    include_hypothetical: bool,
}

/// The authorization part of a cache key.
fn access_key(request: &crate::model::Request) -> Authorization {
    match &request.access {
        mneme_memory::Access::Operator => None,
        mneme_memory::Access::Scopes(scopes) => Some(scopes.clone()),
    }
}

/// Why bounded work stopped before it finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    /// The request's cancellation flag was observed.
    Cancelled,
    /// The request's time budget elapsed.
    Timeout,
    /// The request's work budget was exhausted.
    WorkLimit,
}

impl Stop {
    /// The execution outcome this stop reports.
    fn outcome(self) -> crate::model::Execution {
        match self {
            Stop::Cancelled => crate::model::Execution::Cancelled,
            Stop::Timeout | Stop::WorkLimit => crate::model::Execution::Timeout,
        }
    }

    /// The response-level reason text.
    fn reason(self) -> &'static str {
        match self {
            Stop::Cancelled => "recall cancelled",
            Stop::Timeout => "recall exceeded its time budget",
            Stop::WorkLimit => "recall exceeded its work budget",
        }
    }

    /// The omission reason for the candidate that could not be finished.
    fn omission(self) -> &'static str {
        match self {
            Stop::Cancelled => "cancelled",
            Stop::Timeout => "time-budget",
            Stop::WorkLimit => "work-budget",
        }
    }
}

/// A recall attempt either fails or stops on its own budget.
pub(crate) enum AttemptFailure {
    /// Constructing a qualified response is impossible.
    Error(crate::failure::QueryError),
    /// Bounded work stopped; the caller reports the stop in the response.
    Stop(Stop),
}

impl From<crate::failure::QueryError> for AttemptFailure {
    fn from(error: crate::failure::QueryError) -> Self {
        AttemptFailure::Error(error)
    }
}

impl From<mneme_memory::EvidenceError> for AttemptFailure {
    fn from(error: mneme_memory::EvidenceError) -> Self {
        AttemptFailure::Error(error.into())
    }
}

impl From<mneme_datalog::Error> for AttemptFailure {
    fn from(error: mneme_datalog::Error) -> Self {
        AttemptFailure::Error(error.into())
    }
}

impl From<mneme_store::Failure> for AttemptFailure {
    fn from(error: mneme_store::Failure) -> Self {
        AttemptFailure::Error(error.into())
    }
}

impl From<Stop> for AttemptFailure {
    fn from(stop: Stop) -> Self {
        AttemptFailure::Stop(stop)
    }
}

/// One recall attempt's result.
pub(crate) type AttemptResult<T> = std::result::Result<T, AttemptFailure>;

/// The time and work budget one recall attempt runs under.
///
/// Every charged unit of work pays for itself before it happens, so a request
/// that is already out of budget stops at the first unit instead of after the
/// work has been done.
pub(crate) struct WorkBudget {
    started: std::time::Instant,
    max_time: std::time::Duration,
    cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    used: u64,
    limit: u64,
    next_check: u64,
    /// Whole milliseconds elapsed as the last budget check observed them.
    observed_ms: u64,
}

impl WorkBudget {
    /// A budget for one attempt.
    fn new(started: std::time::Instant, request: &crate::model::Request) -> Self {
        // A budget wider than u64 milliseconds is reported as the maximum
        // instead of rejected: the caller asked for effectively-unbounded time.
        let millis = reported_amount(request.max_time_ms);
        WorkBudget {
            started,
            max_time: std::time::Duration::from_millis(millis),
            cancellation: request.cancellation.clone(),
            used: 0,
            limit: WORK_LIMIT,
            next_check: 0,
            observed_ms: 0,
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancellation
            .as_ref()
            .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Charge `cost` units of work, observing the clock at bounded intervals.
    pub(crate) fn charge(&mut self, cost: u64) -> std::result::Result<(), Stop> {
        let used =
            mneme_kernel::budget::charge(self.used, cost, self.limit).ok_or(Stop::WorkLimit)?;
        self.used = used;
        if used >= self.next_check {
            self.next_check = used.saturating_add(BUDGET_CHECK_INTERVAL);
            self.check()
        } else {
            Ok(())
        }
    }

    /// Observe cancellation and the wall clock now.
    #[allow(unknown_lints, ambient_clock)] // the budget's only clock read, taken from the start instant `recall_once` captured
    pub(crate) fn check(&mut self) -> std::result::Result<(), Stop> {
        let elapsed = self.started.elapsed();
        self.observed_ms = reported_amount(elapsed.as_millis());
        if self.is_cancelled() {
            return Err(Stop::Cancelled);
        }
        // A zero budget is spent before any work: it must never look complete.
        if self.max_time.is_zero() || elapsed > self.max_time {
            return Err(Stop::Timeout);
        }
        Ok(())
    }

    /// Whole milliseconds this attempt has run, as the last check observed.
    fn elapsed_ms(&self) -> u64 {
        self.observed_ms
    }

    /// Work units charged so far.
    fn work_used(&self) -> u64 {
        self.used
    }
}

/// A request limit or a spent total as a reported `u64` amount.
///
/// The range comparison is explicit: a value that a `u64` cannot hold is
/// reported as `u64::MAX`, never wrapped or silently reduced to a smaller
/// number that would misstate the limit or the amount used.
#[allow(unknown_lints, unchecked_narrowing)] // the range comparison below proves the cast fits
fn reported_amount(value: u128) -> u64 {
    if value > u128::from(u64::MAX) {
        return u64::MAX;
    }
    value as u64
}

/// The amounts one response actually returned or spent.
///
/// The request supplies every allowed amount; these are the matching used
/// amounts, which a caller can verify against the response itself.
struct SpentAmounts<'a> {
    request: &'a crate::model::Request,
    returned: &'a [crate::model::Candidate],
    elapsed_ms: u64,
    work_used: u64,
}

/// Report the budget use of one response against the limits its request carries.
fn budget_use(spent: SpentAmounts<'_>) -> crate::model::BudgetUse {
    let mut text_bytes: u128 = 0;
    let mut excerpt_bytes: u128 = 0;
    for candidate in spent.returned {
        let bytes = candidate.text.len() as u128;
        text_bytes = text_bytes.saturating_add(bytes);
        if candidate.quote {
            excerpt_bytes = excerpt_bytes.max(bytes);
        }
    }
    crate::model::BudgetUse {
        items_used: reported_amount(spent.returned.len() as u128),
        items_allowed: reported_amount(spent.request.max_items as u128),
        text_bytes_used: reported_amount(text_bytes),
        text_bytes_allowed: reported_amount(spent.request.max_context_bytes as u128),
        excerpt_bytes_used: reported_amount(excerpt_bytes),
        excerpt_bytes_allowed: reported_amount(spent.request.max_quote_bytes as u128),
        elapsed_ms_used: spent.elapsed_ms,
        elapsed_ms_allowed: reported_amount(spent.request.max_time_ms),
        work_used: spent.work_used,
        work_allowed: WORK_LIMIT,
    }
}

fn failure_execution(allow_partial: bool) -> crate::model::Execution {
    if allow_partial {
        crate::model::Execution::Partial
    } else {
        crate::model::Execution::Failed
    }
}

/// How strongly an execution outcome limits an answer.
fn severity(execution: crate::model::Execution) -> u8 {
    match execution {
        crate::model::Execution::Complete => 0,
        crate::model::Execution::Partial => 1,
        crate::model::Execution::Timeout => 2,
        crate::model::Execution::Failed => 3,
        crate::model::Execution::Cancelled => 4,
    }
}

/// Record a limiting outcome without weakening one already recorded: a failure
/// is never downgraded to a timeout, and a cancellation always wins.
fn note(
    execution: &mut crate::model::Execution,
    reasons: &mut Vec<String>,
    outcome: crate::model::Execution,
    reason: &str,
) {
    if severity(outcome) > severity(*execution) {
        *execution = outcome;
    }
    push_reason(reasons, reason);
}

/// Record one reason once.
fn push_reason(reasons: &mut Vec<String>, reason: &str) {
    if !reasons.iter().any(|existing| existing == reason) {
        reasons.push(reason.to_owned());
    }
}

/// Whether another attempt may follow a failed one.
///
/// Only an eligibility barrier that advanced under the attempt is retried, and
/// only within the attempt bound; every other failure is reported at once.
fn decide_retry(attempt: u32, error: &crate::failure::QueryError) -> bool {
    matches!(error, crate::failure::QueryError::BarrierAdvanced { .. })
        && attempt.saturating_add(1) < RECALL_ATTEMPTS
}

/// Recall service over a committed workspace revision.
pub struct Service<'w> {
    workspace: &'w mut mneme_store::Workspace,
    indexes: std::collections::BTreeMap<IndexKey, crate::model::CachedIndex>,
    cached_generation: Option<u64>,
}

/// One pinned view and the retention state that governs it.
struct PinnedView {
    view: mneme_memory::View,
    sources: crate::lookup::SourceStates,
}

/// Everything one attempt resolved before any candidate mode ran.
struct AttemptSetup {
    pinned: PinnedView,
    index: Option<crate::model::CachedIndex>,
    key: IndexKey,
    modes: Modes,
    is_structured_requested: bool,
}

/// Retained revisions a memory view resolves pinned citations against.
type RecordHistory = std::collections::BTreeMap<
    (mneme_core::RecordId, mneme_core::RevisionId),
    mneme_core::RecordEnvelope,
>;

/// The newest retained revision's availability for each source record.
///
/// Revisions are keyed rather than ordered, so the newest one is chosen by its
/// assigned revision order instead of by position.
fn newest_source_states(history: &RecordHistory) -> crate::lookup::SourceStates {
    let mut newest: std::collections::BTreeMap<
        mneme_core::RecordId,
        (u64, mneme_memory::SourceAvailability),
    > = std::collections::BTreeMap::new();
    for revision in history.values() {
        if revision.kind != mneme_core::RecordKind::SourceRevision {
            continue;
        }
        if let Ok(source) = mneme_memory::SourceView::parse(revision.clone()) {
            let order = revision.recorded.revision_order();
            let slot = newest
                .entry(revision.record_id)
                .or_insert_with(|| (order, source.availability.clone()));
            if order >= slot.0 {
                *slot = (order, source.availability);
            }
        }
    }
    newest
        .into_iter()
        .map(|(record, (_, availability))| (record, availability))
        .collect()
}

impl<'w> Service<'w> {
    /// Wrap one mutable workspace.
    pub fn new(workspace: &'w mut mneme_store::Workspace) -> Self {
        Service {
            workspace,
            indexes: std::collections::BTreeMap::new(),
            cached_generation: None,
        }
    }

    /// Execute one recall request, retrying once if an erasure/authorization
    /// barrier advances during candidate generation or packing.
    pub fn recall(
        &mut self,
        request: crate::model::Request,
    ) -> crate::failure::Result<crate::model::Response> {
        validate(&request)?;
        let mut last = None;
        for attempt in 0..RECALL_ATTEMPTS {
            match self.recall_once(&request) {
                Ok(response) => return Ok(response),
                Err(error) => {
                    if !decide_retry(attempt, &error) {
                        return Err(error);
                    }
                    last = Some(error);
                    self.indexes.clear();
                    self.cached_generation = None;
                }
            }
        }
        Err(last.unwrap_or_else(|| {
            crate::failure::QueryError::InvalidRequest("recall made no attempt".to_owned())
        }))
    }

    #[allow(unknown_lints, ambient_clock)] // recall wall-clock budget is the request shell
    fn recall_once(
        &mut self,
        request: &crate::model::Request,
    ) -> crate::failure::Result<crate::model::Response> {
        let started = std::time::Instant::now();
        let mut budget = WorkBudget::new(started, request);
        let generation = self.workspace.eligibility_generation()?;
        if self.cached_generation != Some(generation) {
            self.indexes.clear();
            self.cached_generation = Some(generation);
        }
        let current_revision = self.workspace.current_revision()?;
        match self.bounded_once(request, &mut budget, generation, current_revision) {
            Ok(response) => Ok(response),
            Err(AttemptFailure::Stop(stop)) => Ok(stopped_response(
                StoppedContext {
                    request,
                    budget: &budget,
                    generation,
                    current_revision,
                    served_revision: request.revision,
                },
                stop,
            )),
            Err(AttemptFailure::Error(error)) => Err(error),
        }
    }

    fn bounded_once(
        &mut self,
        request: &crate::model::Request,
        budget: &mut WorkBudget,
        generation: u64,
        current_revision: mneme_core::WorkspaceRevisionId,
    ) -> AttemptResult<crate::model::Response> {
        let AttemptSetup {
            pinned,
            mut index,
            key,
            modes,
            is_structured_requested,
        } = self.prepare_attempt(request, budget, generation, current_revision)?;
        let served_revision = pinned.view.revision();
        budget.check()?;
        self.require_generation(generation)?;
        let mut progress = Progress::default();
        if modes.use_lexical {
            progress.add_lexical(index.as_ref(), request, modes.fallback_lexical, budget)?;
        }
        if modes.use_vector {
            progress.add_vector(index.as_ref(), request, budget)?;
        }
        if is_structured_requested {
            self.add_structured_mode(request, served_revision, &mut progress);
        }
        self.require_generation(generation)?;
        let mut fused = fuse(progress.candidates.clone(), &progress.ranking);
        enrich_claims(&mut fused, &pinned.view, budget, &mut progress.reasons)?;
        self.require_generation(generation)?;
        let mut packed = pack(PackInputs {
            candidates: fused,
            index: index.as_ref(),
            request,
            budget: &mut *budget,
            execution: &mut progress.execution,
            reasons: &mut progress.reasons,
        });
        if let Some(index) = index.take() {
            self.indexes.insert(key, index);
        }
        if !request.allow_partial && progress.execution != crate::model::Execution::Complete {
            packed.returned.clear();
            packed.omissions.clear();
            push_reason(
                &mut progress.reasons,
                "partial results were withheld by the request",
            );
        }
        self.require_generation(generation)?;
        Ok(finish_response(
            CompletionContext {
                request,
                budget,
                served_revision,
                current_revision,
                generation,
            },
            progress,
            packed,
        ))
    }

    /// Resolve the attempt's preconditions, pinned view, key and index.
    fn prepare_attempt(
        &mut self,
        request: &crate::model::Request,
        budget: &mut WorkBudget,
        generation: u64,
        current_revision: mneme_core::WorkspaceRevisionId,
    ) -> AttemptResult<AttemptSetup> {
        budget.check()?;
        let is_structured_requested = request.modes.contains(&crate::model::Mode::Structured);
        if request.revision != current_revision && !request.allow_stale {
            let stale = crate::failure::QueryError::StaleRevision {
                requested: request.revision,
                current: current_revision,
            };
            return Err(stale.into());
        }
        if is_structured_requested && request.structured.is_none() && !request.allow_fallback {
            let unavailable = crate::failure::QueryError::ModeUnavailable {
                mode: crate::model::Mode::Structured.name().to_owned(),
                reason: "no structured request was supplied".to_owned(),
            };
            return Err(unavailable.into());
        }
        let modes = modes(request, is_structured_requested)?;
        let pinned = self.pinned_view(request, generation, budget)?;
        let key = IndexKey {
            revision: request.revision,
            scope: request.scope.clone(),
            authorized: access_key(request),
            generation,
            temporal: request.temporal,
            at: request.at,
            include_disputed: request.include_disputed,
            include_hypothetical: request.include_hypothetical,
        };
        let index = if modes.use_lexical || modes.use_vector {
            Some(self.take_index(&key, &pinned, request, budget)?)
        } else {
            None
        };
        Ok(AttemptSetup {
            pinned,
            index,
            key,
            modes,
            is_structured_requested,
        })
    }

    /// Take the cached index for this request, or build one.
    fn take_index(
        &mut self,
        key: &IndexKey,
        pinned: &PinnedView,
        request: &crate::model::Request,
        budget: &mut WorkBudget,
    ) -> AttemptResult<crate::model::CachedIndex> {
        if let Some(index) = self.indexes.remove(key) {
            return Ok(index);
        }
        crate::lookup::build_index(&pinned.view, request, &pinned.sources, budget)
    }

    fn pinned_view(
        &self,
        request: &crate::model::Request,
        generation: u64,
        budget: &mut WorkBudget,
    ) -> AttemptResult<PinnedView> {
        let result = self
            .workspace
            .snapshot_at(request.revision, Some(generation));
        let snapshot = self.barrier_map(result, generation)?;
        let (context, sources) = self.load_context(&snapshot, generation, budget)?;
        let result = self.workspace.active_suppressions();
        let suppressions = self.barrier_map(result, generation)?;
        let view = mneme_memory::View::with_retention(
            snapshot,
            self.workspace.root(),
            context.history,
            context.revision_sequences,
            suppressions,
        )
        .with_access(request.view_access());
        Ok(PinnedView { view, sources })
    }

    /// Load the history, sequences and source states a view over `snapshot` needs.
    ///
    /// The history and the sequences arrive together from two set-based reads,
    /// so one charge pays for every retained revision the view receives. The
    /// newest source revision's availability is what governs every older
    /// revision of the same source, so it is derived from the loaded history.
    fn load_context(
        &self,
        snapshot: &mneme_store::Snapshot,
        generation: u64,
        budget: &mut WorkBudget,
    ) -> AttemptResult<(mneme_memory::ViewContext, crate::lookup::SourceStates)> {
        let context = match mneme_memory::view_context(self.workspace, snapshot) {
            Ok(context) => context,
            Err(error) => return Err(self.view_failure(error, generation)),
        };
        let retained_revisions = reported_amount(context.history.len() as u128);
        if retained_revisions > 0 {
            budget.charge(retained_revisions)?;
        }
        if context.history.len() > MAX_HISTORY_REVISIONS {
            return Err(crate::failure::QueryError::InvalidRequest(
                "workspace history exceeds the retained revision bound".to_owned(),
            )
            .into());
        }
        let sources = newest_source_states(&context.history);
        Ok((context, sources))
    }

    /// Translate a view-context refusal so a barrier advance is retried.
    ///
    /// A store refusal keeps the barrier mapping every other store read uses;
    /// any other refusal is a memory-layer failure with no retryable barrier.
    fn view_failure(&self, error: mneme_memory::EvidenceError, generation: u64) -> AttemptFailure {
        match error {
            mneme_memory::EvidenceError::Store(error) => {
                AttemptFailure::Error(self.barrier_or_store(error, generation))
            }
            error @ mneme_memory::EvidenceError::InvalidRecord { .. }
            | error @ mneme_memory::EvidenceError::Missing { .. }
            | error @ mneme_memory::EvidenceError::Policy(_)
            | error @ mneme_memory::EvidenceError::Validation(_)
            | error @ mneme_memory::EvidenceError::Invalid(_)
            | error @ mneme_memory::EvidenceError::Truncated => {
                AttemptFailure::Error(crate::failure::QueryError::Engine(error))
            }
        }
    }

    fn add_structured_mode(
        &mut self,
        request: &crate::model::Request,
        served_revision: mneme_core::WorkspaceRevisionId,
        progress: &mut Progress,
    ) {
        match request.structured.as_ref() {
            None => {
                progress.mode_reports.push(crate::model::ModeReport {
                    mode: crate::model::Mode::Structured,
                    status: crate::model::ModeStatus::Unavailable,
                    index_version: None,
                    revision: Some(served_revision),
                    coverage: crate::model::IndexCoverage::incomplete(
                        0,
                        0,
                        "no structured Datalog request was supplied",
                    ),
                    candidates: 0,
                    relation_exhaustive: None,
                    reason: Some("structured mode was not configured".to_owned()),
                });
                progress.limit(
                    crate::model::Execution::Partial,
                    "structured mode unavailable",
                );
            }
            Some(structured) => {
                let build = mneme_datalog::Service::new(self.workspace).build(
                    mneme_datalog::BuildRequest {
                        actor: request.actor.clone(),
                        scope: request.scope.clone(),
                        revision: request.revision,
                        bundle: structured.bundle.clone(),
                        limits: structured.limits.clone(),
                        publish: false,
                        incomplete_extents: structured.incomplete_extents.clone(),
                        cancellation: request.cancellation.clone(),
                        access: request.view_access(),
                        // Only current-mode recall is an instant-bounded view;
                        // historical and inspection recall keeps every retained
                        // claim and records its validity instead.
                        at: match request.temporal {
                            crate::model::TemporalMode::Current => Some(request.at),
                            crate::model::TemporalMode::Historical
                            | crate::model::TemporalMode::Inspection => None,
                        },
                    },
                );
                match build {
                    Err(error) => progress.structured_build_failed(
                        request,
                        served_revision,
                        structured,
                        error,
                    ),
                    Ok(build) => self.add_structured_query(
                        request,
                        served_revision,
                        structured,
                        &build,
                        progress,
                    ),
                }
            }
        }
    }

    fn add_structured_query(
        &mut self,
        request: &crate::model::Request,
        served_revision: mneme_core::WorkspaceRevisionId,
        structured: &crate::model::StructuredRequest,
        build: &mneme_datalog::Build,
        progress: &mut Progress,
    ) {
        let mut query = structured.query.clone();
        query.cancellation = request.cancellation.clone();
        let rows = mneme_datalog::Service::new(self.workspace).query_build(build, query);
        match rows {
            Err(error) => progress.structured_query_failed(request, served_revision, build, error),
            Ok(rows) => progress.add_structured_rows(request, served_revision, build, rows),
        }
    }

    fn require_generation(&self, generation: u64) -> crate::failure::Result<()> {
        let current = self.workspace.eligibility_generation()?;
        if current != generation {
            return Err(crate::failure::QueryError::BarrierAdvanced {
                pinned: generation,
                current,
            });
        }
        Ok(())
    }

    /// Translate a store read so a barrier refusal joins the retried path.
    fn barrier_map<T>(&self, result: mneme_store::Result<T>, generation: u64) -> AttemptResult<T> {
        result.map_err(|error| AttemptFailure::Error(self.barrier_or_store(error, generation)))
    }

    /// Translate a store refusal that an eligibility barrier explains.
    ///
    /// A suppression that appears between the snapshot and the history load is
    /// a barrier change, not a missing record, so it is retried once like any
    /// other barrier advance.
    fn barrier_or_store(
        &self,
        error: mneme_store::Failure,
        pinned: u64,
    ) -> crate::failure::QueryError {
        match error {
            mneme_store::Failure::BarrierAdvanced {
                pinned: observed,
                current,
            } => crate::failure::QueryError::BarrierAdvanced {
                pinned: observed,
                current,
            },
            error @ mneme_store::Failure::RetentionSuppressed { .. } => {
                match self.workspace.eligibility_generation() {
                    Ok(current) if current != pinned => {
                        crate::failure::QueryError::BarrierAdvanced { pinned, current }
                    }
                    _ => crate::failure::QueryError::Store(error),
                }
            }
            other => crate::failure::QueryError::Store(other),
        }
    }
}

struct Modes {
    fallback_lexical: bool,
    use_lexical: bool,
    use_vector: bool,
}

fn modes(
    request: &crate::model::Request,
    is_requested_structured: bool,
) -> crate::failure::Result<Modes> {
    let is_fallback_lexical = is_requested_structured
        && request.structured.is_none()
        && request.allow_fallback
        && !request.modes.contains(&crate::model::Mode::Lexical);
    let is_lexical_used =
        request.modes.contains(&crate::model::Mode::Lexical) || is_fallback_lexical;
    let is_vector_used = request.modes.contains(&crate::model::Mode::Vector);
    if !is_lexical_used && !is_vector_used && request.structured.is_none() {
        return Err(crate::failure::QueryError::ModeUnavailable {
            mode: "all requested modes".to_owned(),
            reason: "no candidate mode can execute".to_owned(),
        });
    }
    Ok(Modes {
        fallback_lexical: is_fallback_lexical,
        use_lexical: is_lexical_used,
        use_vector: is_vector_used,
    })
}

struct Progress {
    mode_reports: Vec<crate::model::ModeReport>,
    ranking: Vec<(crate::model::Mode, Vec<(String, f64)>)>,
    candidates: std::collections::BTreeMap<String, crate::model::Candidate>,
    execution: crate::model::Execution,
    reasons: Vec<String>,
}

impl Default for Progress {
    fn default() -> Self {
        Self {
            mode_reports: Vec::new(),
            ranking: Vec::new(),
            candidates: std::collections::BTreeMap::new(),
            execution: crate::model::Execution::Complete,
            reasons: Vec::new(),
        }
    }
}

impl Progress {
    /// Record a limiting outcome and its reason.
    fn limit(&mut self, outcome: crate::model::Execution, reason: &str) {
        note(&mut self.execution, &mut self.reasons, outcome, reason);
    }

    fn add_lexical(
        &mut self,
        index: Option<&crate::model::CachedIndex>,
        request: &crate::model::Request,
        is_fallback: bool,
        budget: &mut WorkBudget,
    ) -> AttemptResult<()> {
        let index = index.ok_or_else(|| {
            crate::failure::QueryError::InvalidRequest("lexical index was not built".to_owned())
        })?;
        let entries = lexical_rank(index, request, budget)?;
        for (id, score) in &entries {
            budget.charge(1)?;
            let Some(document) = index.document(id) else {
                continue;
            };
            add_candidate(
                &mut self.candidates,
                candidate_from_document(document),
                crate::model::Mode::Lexical,
                *score,
                id,
            );
        }
        self.ranking.push((
            crate::model::Mode::Lexical,
            entries
                .iter()
                .map(|(id, score)| (id.clone(), *score))
                .collect(),
        ));
        self.mode_reports.push(crate::model::ModeReport {
            mode: crate::model::Mode::Lexical,
            status: crate::model::ModeStatus::Used,
            index_version: Some(crate::lookup::LEXICAL_INDEX_VERSION.to_owned()),
            revision: Some(index.revision),
            coverage: index.coverage.clone(),
            candidates: entries.len(),
            relation_exhaustive: None,
            reason: if is_fallback {
                Some("lexical fallback for an unavailable requested mode".to_owned())
            } else {
                None
            },
        });
        Ok(())
    }

    fn add_vector(
        &mut self,
        index: Option<&crate::model::CachedIndex>,
        request: &crate::model::Request,
        budget: &mut WorkBudget,
    ) -> AttemptResult<()> {
        let index = index.ok_or_else(|| {
            crate::failure::QueryError::InvalidRequest("vector index was not built".to_owned())
        })?;
        let entries = vector_rank(index, request, budget)?;
        for (id, score) in &entries {
            budget.charge(1)?;
            let Some(document) = index.document(id) else {
                continue;
            };
            add_candidate(
                &mut self.candidates,
                candidate_from_document(document),
                crate::model::Mode::Vector,
                *score,
                id,
            );
        }
        self.ranking.push((
            crate::model::Mode::Vector,
            entries
                .iter()
                .map(|(id, score)| (id.clone(), *score))
                .collect(),
        ));
        self.mode_reports.push(crate::model::ModeReport {
            mode: crate::model::Mode::Vector,
            status: crate::model::ModeStatus::Used,
            index_version: Some(crate::lookup::VECTOR_INDEX_VERSION.to_owned()),
            revision: Some(index.revision),
            coverage: index.coverage.clone(),
            candidates: entries.len(),
            relation_exhaustive: None,
            reason: Some(
                "local character-trigram vector projection; not a learned semantic model"
                    .to_owned(),
            ),
        });
        Ok(())
    }

    fn structured_build_failed(
        &mut self,
        request: &crate::model::Request,
        served_revision: mneme_core::WorkspaceRevisionId,
        structured: &crate::model::StructuredRequest,
        error: mneme_datalog::Error,
    ) {
        let reason = error.to_string();
        self.mode_reports.push(crate::model::ModeReport {
            mode: crate::model::Mode::Structured,
            status: crate::model::ModeStatus::Failed,
            index_version: Some(bundle_version(&structured.bundle)),
            revision: Some(served_revision),
            coverage: crate::model::IndexCoverage::incomplete(0, 0, reason.clone()),
            candidates: 0,
            relation_exhaustive: None,
            reason: Some(reason),
        });
        self.limit(
            failure_execution(request.allow_partial),
            &format!("structured mode failed: {error}"),
        );
    }

    fn structured_query_failed(
        &mut self,
        request: &crate::model::Request,
        served_revision: mneme_core::WorkspaceRevisionId,
        build: &mneme_datalog::Build,
        error: mneme_datalog::Error,
    ) {
        let reason = error.to_string();
        self.mode_reports.push(crate::model::ModeReport {
            mode: crate::model::Mode::Structured,
            status: crate::model::ModeStatus::Failed,
            index_version: Some(datalog_version(build)),
            revision: Some(served_revision),
            coverage: crate::model::IndexCoverage::incomplete(0, 0, reason.clone()),
            candidates: 0,
            relation_exhaustive: None,
            reason: Some(reason),
        });
        self.limit(
            failure_execution(request.allow_partial),
            &format!("structured query failed: {error}"),
        );
    }

    fn add_structured_rows(
        &mut self,
        request: &crate::model::Request,
        served_revision: mneme_core::WorkspaceRevisionId,
        build: &mneme_datalog::Build,
        rows: mneme_datalog::QueryResult,
    ) {
        let coverage = structured_coverage(build, &rows);
        let mut structured_ranking = Vec::with_capacity(rows.rows.len());
        for row in &rows.rows {
            let id = structured_id(&rows.relation, &row.values);
            let candidate = structured_candidate(&rows.relation, row, id.clone());
            add_candidate(
                &mut self.candidates,
                candidate,
                crate::model::Mode::Structured,
                1.0,
                &id,
            );
            structured_ranking.push((id, 1.0));
        }
        self.ranking
            .push((crate::model::Mode::Structured, structured_ranking));
        let status = structured_mode_status(rows.status);
        match status {
            crate::model::ModeStatus::Used => {}
            crate::model::ModeStatus::Partial => self.limit(
                crate::model::Execution::Partial,
                "structured mode reported incomplete declared coverage",
            ),
            crate::model::ModeStatus::TimedOut => self.limit(
                crate::model::Execution::Timeout,
                "structured mode timed out",
            ),
            crate::model::ModeStatus::Omitted => self.limit(
                crate::model::Execution::Cancelled,
                "structured mode was cancelled",
            ),
            crate::model::ModeStatus::Unavailable => self.limit(
                failure_execution(request.allow_partial),
                "structured mode was unavailable",
            ),
            crate::model::ModeStatus::Failed => self.limit(
                failure_execution(request.allow_partial),
                "structured mode failed",
            ),
        }
        self.mode_reports.push(crate::model::ModeReport {
            mode: crate::model::Mode::Structured,
            status,
            index_version: Some(datalog_version(build)),
            revision: Some(served_revision),
            coverage,
            candidates: rows.rows.len(),
            relation_exhaustive: Some(rows.exhaustive),
            reason: rows.reason.clone(),
        });
    }
}

fn structured_candidate(
    predicate: &str,
    row: &mneme_datalog::QueryRow,
    id: String,
) -> crate::model::Candidate {
    let body = format!(
        "{} {}",
        predicate,
        row.values
            .iter()
            .map(mneme_core::text::render)
            .collect::<Vec<_>>()
            .join(" ")
    );
    let roots = row
        .supports
        .iter()
        .flat_map(|support| support.sources.iter().copied())
        .collect::<std::collections::BTreeSet<_>>();
    crate::model::Candidate {
        id,
        content_kind: crate::model::ContentKind::StructuredRow,
        text: body,
        text_truncated: false,
        source: None,
        source_revision: None,
        span: None,
        field_path: format!("structured.{predicate}"),
        assertion: None,
        episode: None,
        entity: None,
        claim_status: None,
        quote: false,
        evidence: Vec::new(),
        derivations: row.supports.clone(),
        ancestry_roots: roots,
        // A row whose support set was cut by the support bound rests on
        // unrecorded roots, so it never counts as independent support.
        independent_support: !row.support_truncated,
        support_limited: row.support_truncated,
        origins: std::collections::BTreeSet::new(),
        score: 0.0,
        score_components: std::collections::BTreeMap::new(),
    }
}

fn structured_mode_status(status: mneme_datalog::ExecutionStatus) -> crate::model::ModeStatus {
    match status {
        mneme_datalog::ExecutionStatus::Complete => crate::model::ModeStatus::Used,
        mneme_datalog::ExecutionStatus::Partial => crate::model::ModeStatus::Partial,
        mneme_datalog::ExecutionStatus::Timeout => crate::model::ModeStatus::TimedOut,
        mneme_datalog::ExecutionStatus::Cancelled => crate::model::ModeStatus::Omitted,
        mneme_datalog::ExecutionStatus::Failed => crate::model::ModeStatus::Failed,
    }
}

struct Packed {
    returned: Vec<crate::model::Candidate>,
    omissions: Vec<crate::model::Omission>,
    truncated: bool,
}

struct CompletionContext<'a> {
    request: &'a crate::model::Request,
    budget: &'a mut WorkBudget,
    served_revision: mneme_core::WorkspaceRevisionId,
    current_revision: mneme_core::WorkspaceRevisionId,
    generation: u64,
}

fn finish_response(
    context: CompletionContext<'_>,
    progress: Progress,
    mut packed: Packed,
) -> crate::model::Response {
    let CompletionContext {
        request,
        budget,
        served_revision,
        current_revision,
        generation,
    } = context;
    let mut execution = progress.execution;
    let Progress {
        mode_reports,
        mut reasons,
        ..
    } = progress;
    if let Err(stop) = budget.check() {
        note(&mut execution, &mut reasons, stop.outcome(), stop.reason());
        if stop.outcome() == crate::model::Execution::Cancelled {
            packed.returned.clear();
            packed.omissions.clear();
        }
    }
    let facts = answer_facts(&mode_reports, &packed, execution);
    let is_exhaustive = mneme_kernel::completeness::answer_complete(&facts);
    let is_absence_established = mneme_kernel::completeness::absence_established(&facts);
    let budget_report = budget_use(SpentAmounts {
        request,
        returned: &packed.returned,
        elapsed_ms: budget.elapsed_ms(),
        work_used: budget.work_used(),
    });
    let index_versions = mode_reports
        .iter()
        .filter_map(|report| match (&report.index_version, report.status) {
            (Some(version), crate::model::ModeStatus::Used | crate::model::ModeStatus::Partial) => {
                Some((report.mode.name().to_owned(), version.clone()))
            }
            _ => None,
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    crate::model::Response {
        context: crate::model::Context {
            schema_version: crate::INDEX_SCHEMA_VERSION,
            scope: request.scope.clone(),
            requested_revision: request.revision,
            served_revision,
            current_revision,
            stale: served_revision != current_revision,
            eligibility_generation: generation,
            temporal: request.temporal,
            at: request.at,
            index_versions,
            fusion_policy: FUSION_POLICY_VERSION.to_owned(),
        },
        status: execution,
        modes: mode_reports,
        candidates: packed.returned,
        exhaustive: is_exhaustive,
        absence_established: is_absence_established,
        truncated: packed.truncated || !packed.omissions.is_empty(),
        budget: budget_report,
        omissions: packed.omissions,
        reason: if reasons.is_empty() {
            Some("ranked recall is non-exhaustive; omissions are not absence".to_owned())
        } else {
            Some(reasons.join("; "))
        },
        boundary: crate::model::DataBoundary::default(),
    }
}

/// The completeness facts of this answer, as the kernel sees them.
fn answer_facts(
    mode_reports: &[crate::model::ModeReport],
    packed: &Packed,
    execution: crate::model::Execution,
) -> mneme_kernel::completeness::AnswerFacts {
    let mut coverage: Option<mneme_kernel::completeness::Coverage> = None;
    let mut is_ranked = false;
    let mut is_structured_exhaustive = false;
    for report in mode_reports {
        let level = if report.coverage.complete {
            mneme_kernel::completeness::Coverage::Complete
        } else {
            mneme_kernel::completeness::Coverage::Incomplete
        };
        coverage = Some(match coverage {
            None => level,
            Some(existing) => mneme_kernel::completeness::combine_coverage(existing, level),
        });
        let is_contributing = report.candidates > 0
            && matches!(
                report.status,
                crate::model::ModeStatus::Used | crate::model::ModeStatus::Partial
            );
        let is_ranked_mode = matches!(
            report.mode,
            crate::model::Mode::Lexical | crate::model::Mode::Vector
        );
        if is_contributing && is_ranked_mode {
            is_ranked = true;
        }
        if is_contributing
            && report.mode == crate::model::Mode::Structured
            && report.relation_exhaustive == Some(true)
        {
            is_structured_exhaustive = true;
        }
    }
    // A candidate vector cannot be longer than `usize::MAX`, which fits `u64` on
    // every supported target; the clamp only keeps the conversion total, and a
    // saturated count still reports the answer as non-empty.
    let (rows, is_row_count_exact) = match u64::try_from(packed.returned.len()) {
        Ok(rows) => (rows, true),
        Err(_) => (u64::MAX, false),
    };
    mneme_kernel::completeness::AnswerFacts {
        rows,
        // A ranked top-k answer scans a relevance ordering, never a whole
        // extent; only an exhaustive structured relation can be complete.
        exhaustive: is_structured_exhaustive && !is_ranked && is_row_count_exact,
        coverage: coverage.unwrap_or(mneme_kernel::completeness::Coverage::Unknown),
        limit_reached: packed.truncated
            || !packed.omissions.is_empty()
            || execution != crate::model::Execution::Complete,
        // An invalid declaration already makes the structured coverage
        // incomplete, so completeness has no second route to `true`.
        declaration_valid: true,
        // The barrier was rechecked immediately before this response.
        generation_current: true,
    }
}

fn validate(request: &crate::model::Request) -> crate::failure::Result<()> {
    if request.actor.trim().is_empty() {
        return Err(crate::failure::QueryError::InvalidRequest(
            "actor must not be empty".to_owned(),
        ));
    }
    if request.modes.is_empty() {
        return Err(crate::failure::QueryError::InvalidRequest(
            "at least one recall mode is required".to_owned(),
        ));
    }
    if request.structured.is_some() && !request.modes.contains(&crate::model::Mode::Structured) {
        return Err(crate::failure::QueryError::InvalidRequest(
            "a structured request requires the structured mode".to_owned(),
        ));
    }
    if request.max_items == 0 {
        return Err(crate::failure::QueryError::InvalidRequest(
            "max_items must be greater than zero".to_owned(),
        ));
    }
    if request.max_context_bytes < MIN_ITEM_BYTES {
        return Err(crate::failure::QueryError::InvalidRequest(
            "max_context_bytes is too small for attribution".to_owned(),
        ));
    }
    if request.max_quote_bytes < MIN_ITEM_BYTES {
        return Err(crate::failure::QueryError::InvalidRequest(
            "max_quote_bytes is too small for an attributed excerpt".to_owned(),
        ));
    }
    if request.query.len() > MAX_QUERY_BYTES {
        return Err(crate::failure::QueryError::InvalidRequest(format!(
            "query is longer than {MAX_QUERY_BYTES} bytes"
        )));
    }
    Ok(())
}

/// Everything a stopped attempt reports about the request it served.
struct StoppedContext<'a> {
    request: &'a crate::model::Request,
    budget: &'a WorkBudget,
    generation: u64,
    current_revision: mneme_core::WorkspaceRevisionId,
    served_revision: mneme_core::WorkspaceRevisionId,
}

fn stopped_response(context: StoppedContext<'_>, stop: Stop) -> crate::model::Response {
    let StoppedContext {
        request,
        budget,
        generation,
        current_revision,
        served_revision,
    } = context;
    crate::model::Response {
        context: crate::model::Context {
            schema_version: crate::INDEX_SCHEMA_VERSION,
            scope: request.scope.clone(),
            requested_revision: request.revision,
            served_revision,
            current_revision,
            stale: served_revision != current_revision,
            eligibility_generation: generation,
            temporal: request.temporal,
            at: request.at,
            index_versions: std::collections::BTreeMap::new(),
            fusion_policy: FUSION_POLICY_VERSION.to_owned(),
        },
        status: stop.outcome(),
        modes: Vec::new(),
        candidates: Vec::new(),
        exhaustive: false,
        absence_established: false,
        truncated: false,
        budget: budget_use(SpentAmounts {
            request,
            returned: &[],
            elapsed_ms: budget.elapsed_ms(),
            work_used: budget.work_used(),
        }),
        omissions: Vec::new(),
        reason: Some(stop.reason().to_owned()),
        boundary: crate::model::DataBoundary::default(),
    }
}

fn lexical_rank(
    index: &crate::model::CachedIndex,
    request: &crate::model::Request,
    budget: &mut WorkBudget,
) -> AttemptResult<Vec<(String, f64)>> {
    let query_terms = crate::lookup::tokenize(&request.query.to_lowercase());
    if query_terms.is_empty() {
        return Ok(Vec::new());
    }
    let query_lower = request.query.to_lowercase();
    let mut entries = Vec::with_capacity(index.documents.len());
    for document in &index.documents {
        budget.charge(1)?;
        let matched = query_terms
            .iter()
            .filter(|term| document.terms.contains(*term))
            .count();
        if matched == 0 {
            continue;
        }
        let is_phrase = !query_lower.is_empty() && document.normalized.contains(&query_lower);
        let score = matched as f64 / query_terms.len() as f64 + if is_phrase { 0.5 } else { 0.0 };
        entries.push((document.id.clone(), score));
    }
    sort_rank(&mut entries);
    Ok(entries)
}

fn vector_rank(
    index: &crate::model::CachedIndex,
    request: &crate::model::Request,
    budget: &mut WorkBudget,
) -> AttemptResult<Vec<(String, f64)>> {
    let query_vector = crate::lookup::trigram_counts(&request.query.to_lowercase());
    if query_vector.is_empty() {
        return Ok(Vec::new());
    }
    let query_norm = query_vector
        .values()
        .map(|count| f64::from(*count) * f64::from(*count))
        .sum::<f64>()
        .sqrt();
    if query_norm == 0.0 {
        return Ok(Vec::new());
    }
    let mut entries = Vec::with_capacity(index.documents.len());
    for document in &index.documents {
        budget.charge(1)?;
        if document.trigram_norm == 0.0 {
            continue;
        }
        let dot = query_vector
            .iter()
            .filter_map(|(hash, count)| {
                document
                    .trigrams
                    .get(hash)
                    .map(|document_count| f64::from(*count) * f64::from(*document_count))
            })
            .sum::<f64>();
        if dot == 0.0 {
            continue;
        }
        let score = dot / (query_norm * document.trigram_norm);
        entries.push((document.id.clone(), score));
    }
    sort_rank(&mut entries);
    Ok(entries)
}

fn sort_rank(entries: &mut [(String, f64)]) {
    entries.sort_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.cmp(&right.0))
    });
}

/// One candidate before packing. A quote's text is extracted only when the
/// candidate is actually packed, so a ranked document that is dropped by an
/// earlier limit never pays for an excerpt search.
fn candidate_from_document(document: &crate::model::IndexedDocument) -> crate::model::Candidate {
    let is_quote = document.kind == crate::model::ContentKind::SourceExcerpt;
    crate::model::Candidate {
        id: document.id.clone(),
        content_kind: document.kind,
        text: if is_quote {
            String::new()
        } else {
            document.text.clone()
        },
        text_truncated: false,
        source: document.source,
        source_revision: document.source_revision,
        span: if is_quote { None } else { document.span },
        field_path: document.field_path.clone(),
        assertion: document.assertion,
        episode: document.episode,
        entity: document.entity,
        claim_status: document.claim_status.clone(),
        quote: is_quote,
        evidence: document.evidence.clone(),
        derivations: Vec::new(),
        ancestry_roots: document.ancestry_roots.clone(),
        independent_support: true,
        // Only the claim support walk raises this; an entity, episode, source
        // or path document rests on the record it came from.
        support_limited: false,
        origins: std::collections::BTreeSet::new(),
        score: 0.0,
        score_components: std::collections::BTreeMap::new(),
    }
}

fn add_candidate(
    candidates: &mut std::collections::BTreeMap<String, crate::model::Candidate>,
    candidate: crate::model::Candidate,
    mode: crate::model::Mode,
    score: f64,
    id: &str,
) {
    let entry = candidates
        .entry(id.to_owned())
        .or_insert_with(|| candidate.clone());
    entry.origins.insert(mode);
    entry.score_components.insert(mode.name().to_owned(), score);
    if entry.evidence.is_empty() {
        entry.evidence = candidate.evidence;
    }
    if entry.derivations.is_empty() {
        entry.derivations = candidate.derivations;
    }
    if entry.ancestry_roots.is_empty() {
        entry.ancestry_roots = candidate.ancestry_roots;
    }
}

fn fuse(
    candidates: std::collections::BTreeMap<String, crate::model::Candidate>,
    rankings: &[(crate::model::Mode, Vec<(String, f64)>)],
) -> Vec<crate::model::Candidate> {
    let mut fused = candidates;
    for (mode, ranking) in rankings {
        for (rank, (id, _raw)) in ranking.iter().enumerate() {
            if let Some(candidate) = fused.get_mut(id) {
                let contribution = 1.0 / (RRF_K + rank as f64 + 1.0);
                candidate.score += contribution;
                candidate
                    .score_components
                    .insert(format!("rrf-{}", mode.name()), contribution);
            }
        }
    }
    let mut values = fused.into_values().collect::<Vec<_>>();
    values.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| left.id.cmp(&right.id))
    });
    values
}

/// Fill in the support ancestry and limitation of every ranked claim.
///
/// One bounded, memoized walk per claim replaces a traversal of the whole
/// index, and it only runs for claims the query actually matched. The walk is
/// the memory engine's, so a citation whose declared ancestry could not be
/// resolved is reported as ineligible and incomplete here; it is never read as
/// an independent observation and never falls back to the source it restates.
fn enrich_claims(
    candidates: &mut [crate::model::Candidate],
    view: &mneme_memory::View,
    budget: &mut WorkBudget,
    reasons: &mut Vec<String>,
) -> AttemptResult<()> {
    for candidate in candidates.iter_mut() {
        if candidate.content_kind != crate::model::ContentKind::Claim {
            continue;
        }
        let Some(assertion) = candidate.assertion else {
            continue;
        };
        budget.charge(1)?;
        let explained = view.explain(
            assertion,
            mneme_memory::Policy {
                max_explanation_nodes: EXPLANATION_NODES,
                max_excerpt_bytes: 0,
            },
        );
        let Ok(explanation) = explained else {
            candidate.ancestry_roots.clear();
            mark_support_limited(candidate, reasons, SUPPORT_UNRESOLVED);
            continue;
        };
        fill_evidence(candidate, &explanation.evidence);
        let is_limited = explanation.truncated || has_ineligible_support(candidate);
        candidate.ancestry_roots = explanation.corroboration.roots;
        if is_limited {
            mark_support_limited(candidate, reasons, SUPPORT_LIMITED);
        }
    }
    Ok(())
}

/// Copy the memory engine's per-citation facts onto the candidate.
///
/// An explanation entry that is inaccessible carries withheld identities, so it
/// matches nothing and its citation keeps the fail-closed index defaults.
fn fill_evidence(
    candidate: &mut crate::model::Candidate,
    explained: &[mneme_memory::EvidenceExplanation],
) {
    for item in explained {
        if item.inaccessible {
            continue;
        }
        let Some(entry) = candidate
            .evidence
            .iter_mut()
            .find(|entry| entry.evidence == item.evidence)
        else {
            continue;
        };
        entry.eligible = item.eligible;
        entry.withdrawn = item.withdrawn;
        entry.ancestry_roots = item.ancestry_roots.clone();
    }
}

/// Whether any supporting citation is ineligible for current support.
fn has_ineligible_support(candidate: &crate::model::Candidate) -> bool {
    candidate.evidence.iter().any(|entry| {
        matches!(entry.relation, mneme_memory::SupportRelation::Supports) && !entry.eligible
    })
}

/// Mark a candidate's support as incomplete, which forbids any independence
/// claim and discloses the limitation once in the response.
fn mark_support_limited(
    candidate: &mut crate::model::Candidate,
    reasons: &mut Vec<String>,
    reason: &str,
) {
    candidate.support_limited = true;
    candidate.independent_support = false;
    push_reason(reasons, reason);
}

/// The candidates one packing pass walks, and the state it charges and records.
struct PackInputs<'a> {
    candidates: Vec<crate::model::Candidate>,
    index: Option<&'a crate::model::CachedIndex>,
    request: &'a crate::model::Request,
    budget: &'a mut WorkBudget,
    execution: &'a mut crate::model::Execution,
    reasons: &'a mut Vec<String>,
}

fn pack(inputs: PackInputs<'_>) -> Packed {
    let PackInputs {
        candidates,
        index,
        request,
        budget,
        execution,
        reasons,
    } = inputs;
    let ordered = order_by_independence(candidates);
    let mut packed = PackedCandidates {
        returned: Vec::with_capacity(ordered.len().min(request.max_items)),
        omissions: Vec::with_capacity(ordered.len()),
        is_truncated: false,
        remaining: request.max_context_bytes,
    };
    {
        let mut context = CandidatePackingContext {
            request,
            index,
            budget,
            packed: &mut packed,
            execution,
            reasons,
        };
        for candidate in ordered {
            pack_candidate(candidate, &mut context);
        }
    }
    Packed {
        returned: packed.returned,
        omissions: packed.omissions,
        truncated: packed.is_truncated,
    }
}

struct PackedCandidates {
    returned: Vec<crate::model::Candidate>,
    omissions: Vec<crate::model::Omission>,
    is_truncated: bool,
    remaining: usize,
}

fn order_by_independence(values: Vec<crate::model::Candidate>) -> Vec<crate::model::Candidate> {
    let mut ordered = Vec::with_capacity(values.len());
    let mut duplicates = Vec::with_capacity(values.len());
    let mut seen_roots = std::collections::BTreeSet::new();
    for candidate in values {
        if candidate.ancestry_roots.is_empty() {
            // An empty root set is only an independent observation when the
            // support set is known to be complete: a citation whose declared
            // ancestry could not be resolved contributes no root, and reading
            // that absence as independence would count it as support.
            let mut candidate = candidate;
            if candidate.support_limited {
                candidate.independent_support = false;
            }
            ordered.push(candidate);
        } else if candidate
            .ancestry_roots
            .iter()
            .any(|root| seen_roots.contains(root))
        {
            let mut candidate = candidate;
            candidate.independent_support = false;
            duplicates.push(candidate);
        } else {
            seen_roots.extend(candidate.ancestry_roots.iter().copied());
            ordered.push(candidate);
        }
    }
    ordered.extend(duplicates);
    ordered
}

struct CandidatePackingContext<'a> {
    request: &'a crate::model::Request,
    index: Option<&'a crate::model::CachedIndex>,
    budget: &'a mut WorkBudget,
    packed: &'a mut PackedCandidates,
    execution: &'a mut crate::model::Execution,
    reasons: &'a mut Vec<String>,
}

fn pack_candidate(candidate: crate::model::Candidate, context: &mut CandidatePackingContext<'_>) {
    if let Err(stop) = context.budget.check() {
        note(
            context.execution,
            context.reasons,
            stop.outcome(),
            stop.reason(),
        );
        omit_candidate(candidate, stop.omission(), context.packed);
        return;
    }
    if context.packed.returned.len() >= context.request.max_items {
        omit_candidate(candidate, "item-limit", context.packed);
        return;
    }
    let cap = if candidate.quote {
        context
            .packed
            .remaining
            .min(context.request.max_quote_bytes)
    } else {
        context.packed.remaining
    };
    if cap < MIN_ITEM_BYTES {
        omit_candidate(candidate, "context-budget", context.packed);
        return;
    }
    let candidate = if candidate.quote {
        let Some(filled) = fill_quote(candidate, context, cap) else {
            return;
        };
        filled
    } else {
        candidate
    };
    let Some(candidate) = truncate_candidate(candidate, cap, context.packed) else {
        return;
    };
    if candidate.text.is_empty() {
        omit_candidate(candidate, "empty-item", context.packed);
        return;
    }
    context.packed.remaining = context
        .packed
        .remaining
        .saturating_sub(candidate.text.len());
    context.packed.returned.push(candidate);
}

/// Replace a quote's text with its excerpt, or omit the candidate.
fn fill_quote(
    candidate: crate::model::Candidate,
    context: &mut CandidatePackingContext<'_>,
    cap: usize,
) -> Option<crate::model::Candidate> {
    let Some(document) = context
        .index
        .and_then(|index| index.document(&candidate.id))
    else {
        omit_candidate(candidate, "quote-unavailable", context.packed);
        return None;
    };
    // The excerpt search is the one unbounded step on attacker-sized text,
    // so its length is charged before the search starts.
    let cost = match u64::try_from(document.text.len() / 4096) {
        Ok(value) => value.saturating_add(1),
        Err(_) => 1,
    };
    if let Err(stop) = context.budget.charge(cost) {
        note(
            context.execution,
            context.reasons,
            stop.outcome(),
            stop.reason(),
        );
        omit_candidate(candidate, stop.omission(), context.packed);
        return None;
    }
    let Some(excerpt) = crate::lookup::source_excerpt(&document.text, &context.request.query, cap)
    else {
        omit_candidate(candidate, "quote-unavailable", context.packed);
        return None;
    };
    let mut filled = candidate;
    filled.text = excerpt.text;
    filled.span = Some(excerpt.span);
    filled.text_truncated = excerpt.truncated;
    if excerpt.truncated {
        context.packed.is_truncated = true;
    }
    Some(filled)
}

fn truncate_candidate(
    mut candidate: crate::model::Candidate,
    cap: usize,
    packed: &mut PackedCandidates,
) -> Option<crate::model::Candidate> {
    if candidate.text.len() > cap {
        let end = mneme_kernel::extent::floor_boundary(candidate.text.as_bytes(), cap);
        if end == 0 {
            omit_candidate(candidate, "context-budget", packed);
            return None;
        }
        candidate.text.truncate(end);
        candidate.text_truncated = true;
        packed.is_truncated = true;
    }
    Some(candidate)
}

fn omit_candidate(candidate: crate::model::Candidate, reason: &str, packed: &mut PackedCandidates) {
    packed.omissions.push(crate::model::Omission {
        candidate: candidate.id,
        reason: reason.to_owned(),
    });
}

fn datalog_version(build: &mneme_datalog::Build) -> String {
    let context = build.context();
    format!(
        "datalog:{}:{}:{}",
        context.rule_bundle_id, context.rule_bundle_version, context.projection_build_id
    )
}

/// The index version of a bundle that could not be built or queried.
fn bundle_version(bundle: &mneme_datalog::RuleBundle) -> String {
    format!("datalog:{}:{}", bundle.id, bundle.version)
}

fn structured_coverage(
    build: &mneme_datalog::Build,
    result: &mneme_datalog::QueryResult,
) -> crate::model::IndexCoverage {
    if !build.declaration_valid() {
        return crate::model::IndexCoverage::incomplete(
            result.rows.len(),
            0,
            "declared relation shapes do not match their canonical extents",
        );
    }
    if result.truncated {
        return crate::model::IndexCoverage::incomplete(
            result.rows.len(),
            0,
            "structured result hit its row cap",
        );
    }
    let coverage = build
        .coverage()
        .iter()
        .find(|coverage| coverage.predicate == result.relation)
        .map(|coverage| coverage.status)
        .unwrap_or(mneme_datalog::CoverageStatus::Unknown);
    if coverage == mneme_datalog::CoverageStatus::Complete && result.exhaustive {
        return crate::model::IndexCoverage::complete(result.rows.len());
    }
    let reason = if build.status() == mneme_datalog::ExecutionStatus::Complete {
        format!("declared relation coverage is {:?}", coverage)
    } else {
        format!("Datalog execution finished with {:?}", build.status())
    };
    crate::model::IndexCoverage::incomplete(result.rows.len(), 0, reason)
}

fn structured_id(predicate: &str, values: &[mneme_core::Value]) -> String {
    let payload = mneme_core::Value::sequence(values.to_vec());
    format!(
        "structured:{predicate}:{}",
        mneme_core::ContentDigest::of_payload(&payload).to_hex()
    )
}

#[cfg(test)]
mod tests {
    fn barrier() -> crate::failure::QueryError {
        crate::failure::QueryError::BarrierAdvanced {
            pinned: 1,
            current: 2,
        }
    }

    #[test]
    fn a_timeout_never_downgrades_a_failure() {
        let mut execution = crate::model::Execution::Failed;
        let mut reasons = Vec::new();
        super::note(
            &mut execution,
            &mut reasons,
            crate::model::Execution::Timeout,
            "recall exceeded its time budget",
        );
        assert_eq!(execution, crate::model::Execution::Failed);
        assert_eq!(reasons.len(), 1);
    }

    #[test]
    fn a_cancellation_outranks_every_other_outcome() {
        let mut execution = crate::model::Execution::Failed;
        let mut reasons = Vec::new();
        super::note(
            &mut execution,
            &mut reasons,
            crate::model::Execution::Cancelled,
            "recall cancelled",
        );
        assert_eq!(execution, crate::model::Execution::Cancelled);
    }

    #[test]
    fn a_failure_still_escalates_a_partial_answer() {
        let mut execution = crate::model::Execution::Partial;
        let mut reasons = Vec::new();
        super::note(
            &mut execution,
            &mut reasons,
            crate::model::Execution::Failed,
            "structured mode failed",
        );
        assert_eq!(execution, crate::model::Execution::Failed);
    }

    #[test]
    fn a_reason_is_recorded_once() {
        let mut reasons = Vec::new();
        super::push_reason(&mut reasons, "recall exceeded its time budget");
        super::push_reason(&mut reasons, "recall exceeded its time budget");
        assert_eq!(reasons.len(), 1);
    }

    #[test]
    fn the_barrier_retry_is_bounded() {
        assert!(super::decide_retry(0, &barrier()));
        // The second attempt is the last: an unchanged barrier is reported.
        assert!(!super::decide_retry(1, &barrier()));
        let other = crate::failure::QueryError::InvalidRequest("query is empty".to_owned());
        assert!(!super::decide_retry(0, &other));
    }
}
