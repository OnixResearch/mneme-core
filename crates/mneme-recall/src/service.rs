//! Bounded recall service over one mutable workspace handle.
#![allow(path_segment_repetition)] // Octet structural exception: domain-qualified names and macro-only imports are intentional

/// Ranking/fusion policy version.
pub const FUSION_POLICY_VERSION: &str = "rrf-k60-v1";
const RRF_K: f64 = 60.0;
const MIN_ITEM_BYTES: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct IndexKey {
    revision: mneme_core::WorkspaceRevisionId,
    scope: mneme_core::ScopeId,
    generation: u64,
    temporal: crate::model::TemporalMode,
    at: mneme_core::Timestamp,
    include_disputed: bool,
    include_hypothetical: bool,
}

/// A recall service with a generation-fenced in-memory index cache.
fn failure_execution(allow_partial: bool) -> crate::model::RecallExecution {
    if allow_partial {
        crate::model::RecallExecution::Partial
    } else {
        crate::model::RecallExecution::Failed
    }
}

/// Recall service over a committed workspace revision.
pub struct RecallService<'w> {
    workspace: &'w mut mneme_store::Workspace,
    indexes: std::collections::BTreeMap<IndexKey, crate::model::CachedIndex>,
    cached_generation: Option<u64>,
}

impl<'w> RecallService<'w> {
    /// Wrap one mutable workspace.
    pub fn new(workspace: &'w mut mneme_store::Workspace) -> Self {
        RecallService {
            workspace,
            indexes: std::collections::BTreeMap::new(),
            cached_generation: None,
        }
    }

    /// Execute one recall request, retrying once if an erasure/authorization
    /// barrier advances during candidate generation or packing.
    pub fn recall(
        &mut self,
        request: crate::model::RecallRequest,
    ) -> crate::error::Result<crate::model::RecallResponse> {
        validate(&request)?;
        let mut last_barrier = None;
        for attempt in 0..2 {
            match self.recall_once(&request) {
                Err(crate::error::RecallError::BarrierAdvanced { pinned, current })
                    if attempt == 0 =>
                {
                    last_barrier = Some((pinned, current));
                    self.indexes.clear();
                    self.cached_generation = None;
                }
                other => return other,
            }
        }
        Err(last_barrier
            .map(|(pinned, current)| crate::error::RecallError::BarrierAdvanced { pinned, current })
            .unwrap_or_else(|| {
                crate::error::RecallError::InvalidRequest("recall retry exhausted".to_owned())
            }))
    }

    #[allow(unknown_lints, ambient_clock, nested_conditionals)] // recall wall-clock budget is the request shell; structured fallback nests match arms
    fn recall_once(
        &mut self,
        request: &crate::model::RecallRequest,
    ) -> crate::error::Result<crate::model::RecallResponse> {
        let (started, generation) = (
            std::time::Instant::now(),
            self.workspace.eligibility_generation()?,
        );
        if self.cached_generation != Some(generation) {
            self.indexes.clear();
            self.cached_generation = Some(generation);
        }
        if cancelled(request) {
            return Ok(cancelled_response(request, generation));
        }
        let view = self.pinned_view(request, generation)?;
        let served_revision = view.revision();
        let is_requested_structured = request
            .modes
            .contains(&crate::model::RecallMode::Structured);
        if is_requested_structured && request.structured.is_none() && !request.allow_fallback {
            return Err(crate::error::RecallError::ModeUnavailable {
                mode: crate::model::RecallMode::Structured.name().to_owned(),
                reason: "no structured request was supplied".to_owned(),
            });
        }
        let modes = recall_modes(request, is_requested_structured)?;
        if cancelled(request) {
            return Ok(cancelled_response(request, generation));
        }
        let index = if modes.use_lexical || modes.use_vector {
            Some(self.cached_index(&view, request, generation)?)
        } else {
            None
        };
        self.require_generation(generation)?;
        let mut progress = RecallProgress::default();
        if modes.use_lexical {
            progress.add_lexical(index.as_ref(), request, modes.fallback_lexical)?;
        }
        if modes.use_vector {
            progress.add_vector(index.as_ref(), request)?;
        }
        if is_requested_structured {
            self.add_structured_mode(request, served_revision, modes.use_lexical, &mut progress)?;
        }
        self.require_generation(generation)?;
        let mut fused = fuse(progress.candidates.clone(), &progress.ranking);
        let (mut returned, mut omissions, truncated) = pack(
            &mut fused,
            request,
            started,
            &mut progress.execution,
            &mut progress.reasons,
        );
        if progress.execution == crate::model::RecallExecution::Failed && !request.allow_partial {
            returned.clear();
            omissions.clear();
        }
        self.require_generation(generation)?;
        finish_recall_response(
            request,
            started,
            served_revision,
            generation,
            progress,
            RecallPacked {
                returned,
                omissions,
                truncated,
            },
        )
    }

    fn pinned_view(
        &self,
        request: &crate::model::RecallRequest,
        generation: u64,
    ) -> crate::error::Result<mneme_memory::MemoryView> {
        let current_revision = self.workspace.current_revision()?;
        if current_revision != request.revision && !request.allow_stale {
            return Err(crate::error::RecallError::StaleRevision {
                requested: request.revision,
                current: current_revision,
            });
        }
        self.view(request.revision, generation)
    }

    fn cached_index(
        &mut self,
        view: &mneme_memory::MemoryView,
        request: &crate::model::RecallRequest,
        generation: u64,
    ) -> crate::error::Result<crate::model::CachedIndex> {
        let key = IndexKey {
            revision: request.revision,
            scope: request.scope.clone(),
            generation,
            temporal: request.temporal,
            at: request.at,
            include_disputed: request.include_disputed,
            include_hypothetical: request.include_hypothetical,
        };
        let index = if let Some(cached) = self.indexes.get(&key) {
            cached.clone()
        } else {
            let built = crate::index::build_index(view, request)?;
            self.indexes.insert(key, built.clone());
            built
        };
        Ok(index)
    }

    fn add_structured_mode(
        &mut self,
        request: &crate::model::RecallRequest,
        served_revision: mneme_core::WorkspaceRevisionId,
        is_use_lexical: bool,
        progress: &mut RecallProgress,
    ) -> crate::error::Result<()> {
        match request.structured.as_ref() {
            None => {
                progress.mode_reports.push(crate::model::ModeReport {
                    mode: crate::model::RecallMode::Structured,
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
                if !request.allow_fallback && !is_use_lexical {
                    return Err(crate::error::RecallError::ModeUnavailable {
                        mode: crate::model::RecallMode::Structured.name().to_owned(),
                        reason: "structured mode has no request and fallback is disabled"
                            .to_owned(),
                    });
                }
                progress.execution = crate::model::RecallExecution::Partial;
                progress
                    .reasons
                    .push("structured mode unavailable".to_owned());
            }
            Some(structured) => {
                let build = mneme_datalog::DatalogService::new(self.workspace).build(
                    mneme_datalog::BuildRequest {
                        actor: request.actor.clone(),
                        scope: request.scope.clone(),
                        revision: request.revision,
                        bundle: structured.bundle.clone(),
                        limits: structured.limits.clone(),
                        publish: false,
                        incomplete_extents: structured.incomplete_extents.clone(),
                        cancellation: request.cancellation.clone(),
                    },
                );
                match build {
                    Err(error) => progress.structured_build_failed(
                        request,
                        served_revision,
                        structured,
                        error,
                    ),
                    Ok(build) => {
                        self.add_structured_query(
                            request,
                            served_revision,
                            structured,
                            &build,
                            progress,
                        );
                    }
                }
            }
        }
        Ok(())
    }

    fn add_structured_query(
        &mut self,
        request: &crate::model::RecallRequest,
        served_revision: mneme_core::WorkspaceRevisionId,
        structured: &crate::model::StructuredRequest,
        build: &mneme_datalog::DatalogBuild,
        progress: &mut RecallProgress,
    ) {
        let rows = mneme_datalog::DatalogService::new(self.workspace)
            .query_build(build, structured.query.clone());
        match rows {
            Err(error) => progress.structured_query_failed(request, served_revision, build, error),
            Ok(rows) => {
                progress.add_structured_rows(request, served_revision, structured, build, rows)
            }
        }
    }

    fn view(
        &self,
        revision: mneme_core::WorkspaceRevisionId,
        generation: u64,
    ) -> crate::error::Result<mneme_memory::MemoryView> {
        let snapshot = self.workspace.snapshot_at(revision, Some(generation))?;
        let history = history(self.workspace, &snapshot)?;
        let sequences = self.workspace.revision_sequences()?;
        let suppressions = self.workspace.active_suppressions()?;
        Ok(mneme_memory::MemoryView::with_retention(
            snapshot,
            self.workspace.root(),
            history,
            sequences,
            suppressions,
        ))
    }

    fn require_generation(&self, generation: u64) -> crate::error::Result<()> {
        let current = self.workspace.eligibility_generation()?;
        if current != generation {
            return Err(crate::error::RecallError::BarrierAdvanced {
                pinned: generation,
                current,
            });
        }
        Ok(())
    }
}

struct RecallModes {
    fallback_lexical: bool,
    use_lexical: bool,
    use_vector: bool,
}

fn recall_modes(
    request: &crate::model::RecallRequest,
    is_requested_structured: bool,
) -> crate::error::Result<RecallModes> {
    let is_fallback_lexical = is_requested_structured
        && request.structured.is_none()
        && request.allow_fallback
        && !request.modes.contains(&crate::model::RecallMode::Lexical);
    let is_lexical_used =
        request.modes.contains(&crate::model::RecallMode::Lexical) || is_fallback_lexical;
    let is_vector_used = request.modes.contains(&crate::model::RecallMode::Vector);
    if !is_lexical_used && !is_vector_used && request.structured.is_none() {
        return Err(crate::error::RecallError::ModeUnavailable {
            mode: "all requested modes".to_owned(),
            reason: "no candidate mode can execute".to_owned(),
        });
    }
    Ok(RecallModes {
        fallback_lexical: is_fallback_lexical,
        use_lexical: is_lexical_used,
        use_vector: is_vector_used,
    })
}

struct RecallProgress {
    mode_reports: Vec<crate::model::ModeReport>,
    ranking: Vec<(crate::model::RecallMode, Vec<(String, f64)>)>,
    candidates: std::collections::BTreeMap<String, crate::model::RecallCandidate>,
    execution: crate::model::RecallExecution,
    reasons: Vec<String>,
}

impl Default for RecallProgress {
    fn default() -> Self {
        Self {
            mode_reports: Vec::new(),
            ranking: Vec::new(),
            candidates: std::collections::BTreeMap::new(),
            execution: crate::model::RecallExecution::Complete,
            reasons: Vec::new(),
        }
    }
}

impl RecallProgress {
    fn add_lexical(
        &mut self,
        index: Option<&crate::model::CachedIndex>,
        request: &crate::model::RecallRequest,
        is_fallback: bool,
    ) -> crate::error::Result<()> {
        let index = index.ok_or_else(|| {
            crate::error::RecallError::InvalidRequest("lexical index was not built".to_owned())
        })?;
        let entries = lexical_rank(index, request);
        for (id, document, score) in &entries {
            let Some(candidate) = candidate_from_document(document, request, 0.0) else {
                continue;
            };
            add_candidate(
                &mut self.candidates,
                candidate,
                crate::model::RecallMode::Lexical,
                *score,
                id,
            );
        }
        self.ranking.push((
            crate::model::RecallMode::Lexical,
            entries
                .iter()
                .map(|(id, _, score)| (id.clone(), *score))
                .collect(),
        ));
        self.mode_reports.push(crate::model::ModeReport {
            mode: crate::model::RecallMode::Lexical,
            status: crate::model::ModeStatus::Used,
            index_version: Some(crate::index::LEXICAL_INDEX_VERSION.to_owned()),
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
        request: &crate::model::RecallRequest,
    ) -> crate::error::Result<()> {
        let index = index.ok_or_else(|| {
            crate::error::RecallError::InvalidRequest("vector index was not built".to_owned())
        })?;
        let entries = vector_rank(index, request);
        for (id, document, score) in &entries {
            let Some(candidate) = candidate_from_document(document, request, *score) else {
                continue;
            };
            add_candidate(
                &mut self.candidates,
                candidate,
                crate::model::RecallMode::Vector,
                *score,
                id,
            );
        }
        self.ranking.push((
            crate::model::RecallMode::Vector,
            entries
                .iter()
                .map(|(id, _, score)| (id.clone(), *score))
                .collect(),
        ));
        self.mode_reports.push(crate::model::ModeReport {
            mode: crate::model::RecallMode::Vector,
            status: crate::model::ModeStatus::Used,
            index_version: Some(crate::index::VECTOR_INDEX_VERSION.to_owned()),
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
        request: &crate::model::RecallRequest,
        served_revision: mneme_core::WorkspaceRevisionId,
        structured: &crate::model::StructuredRequest,
        error: mneme_datalog::DatalogError,
    ) {
        let reason = error.to_string();
        self.mode_reports.push(crate::model::ModeReport {
            mode: crate::model::RecallMode::Structured,
            status: crate::model::ModeStatus::Failed,
            index_version: Some(format!(
                "datalog:{}:{}",
                structured.bundle.id, structured.bundle.version
            )),
            revision: Some(served_revision),
            coverage: crate::model::IndexCoverage::incomplete(0, 0, reason.clone()),
            candidates: 0,
            relation_exhaustive: None,
            reason: Some(reason),
        });
        self.execution = failure_execution(request.allow_partial);
        self.reasons
            .push(format!("structured mode failed: {error}"));
    }

    fn structured_query_failed(
        &mut self,
        request: &crate::model::RecallRequest,
        served_revision: mneme_core::WorkspaceRevisionId,
        build: &mneme_datalog::DatalogBuild,
        error: mneme_datalog::DatalogError,
    ) {
        let reason = error.to_string();
        self.mode_reports.push(crate::model::ModeReport {
            mode: crate::model::RecallMode::Structured,
            status: crate::model::ModeStatus::Failed,
            index_version: Some(datalog_version(build)),
            revision: Some(served_revision),
            coverage: crate::model::IndexCoverage::incomplete(0, 0, reason.clone()),
            candidates: 0,
            relation_exhaustive: None,
            reason: Some(reason),
        });
        self.execution = failure_execution(request.allow_partial);
        self.reasons
            .push(format!("structured query failed: {error}"));
    }

    fn add_structured_rows(
        &mut self,
        request: &crate::model::RecallRequest,
        served_revision: mneme_core::WorkspaceRevisionId,
        structured: &crate::model::StructuredRequest,
        build: &mneme_datalog::DatalogBuild,
        rows: mneme_datalog::QueryResult,
    ) {
        let coverage = structured_coverage(build, &rows, &structured.query.predicate);
        let mut structured_ranking = Vec::with_capacity(rows.rows.len());
        for row in &rows.rows {
            let id = structured_id(&structured.query.predicate, &row.values);
            let candidate = structured_candidate(&structured.query.predicate, row, id.clone());
            add_candidate(
                &mut self.candidates,
                candidate,
                crate::model::RecallMode::Structured,
                1.0,
                &id,
            );
            structured_ranking.push((id, 1.0));
        }
        self.ranking
            .push((crate::model::RecallMode::Structured, structured_ranking));
        let status = structured_mode_status(rows.status);
        if !matches!(status, crate::model::ModeStatus::Used) {
            self.execution = failure_execution(request.allow_partial);
            self.reasons
                .push(format!("structured mode finished with {:?}", rows.status));
        }
        self.mode_reports.push(crate::model::ModeReport {
            mode: crate::model::RecallMode::Structured,
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
) -> crate::model::RecallCandidate {
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
    crate::model::RecallCandidate {
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
        independent_support: true,
        origins: std::collections::BTreeSet::new(),
        score: 0.0,
        score_components: std::collections::BTreeMap::new(),
    }
}

fn structured_mode_status(status: mneme_datalog::ExecutionStatus) -> crate::model::ModeStatus {
    match status {
        mneme_datalog::ExecutionStatus::Complete => crate::model::ModeStatus::Used,
        mneme_datalog::ExecutionStatus::Timeout => crate::model::ModeStatus::TimedOut,
        mneme_datalog::ExecutionStatus::Cancelled => crate::model::ModeStatus::Omitted,
        mneme_datalog::ExecutionStatus::Failed | mneme_datalog::ExecutionStatus::Partial => {
            crate::model::ModeStatus::Failed
        }
    }
}

struct RecallPacked {
    returned: Vec<crate::model::RecallCandidate>,
    omissions: Vec<crate::model::Omission>,
    truncated: bool,
}

#[allow(
    unknown_lints,
    ambient_clock,
    clippy::too_many_arguments,
    too_many_parameters
)]
fn finish_recall_response(
    request: &crate::model::RecallRequest,
    started: std::time::Instant,
    served_revision: mneme_core::WorkspaceRevisionId,
    generation: u64,
    mut progress: RecallProgress,
    mut packed: RecallPacked,
) -> crate::error::Result<crate::model::RecallResponse> {
    if cancelled(request) {
        progress.execution = crate::model::RecallExecution::Cancelled;
        packed.returned.clear();
        progress.reasons.push("recall cancelled".to_owned());
    }
    let max_time_ms = u64::try_from(request.max_time_ms).map_err(|_| {
        crate::error::RecallError::InvalidRequest(
            "recall time budget exceeds u64 milliseconds".to_owned(),
        )
    })?;
    if started.elapsed() > std::time::Duration::from_millis(max_time_ms)
        && progress.execution == crate::model::RecallExecution::Complete
    {
        progress.execution = crate::model::RecallExecution::Timeout;
        progress
            .reasons
            .push("recall exceeded its time budget".to_owned());
    }
    let index_versions = progress
        .mode_reports
        .iter()
        .filter_map(|report| match (&report.index_version, report.status) {
            (Some(version), crate::model::ModeStatus::Used) => {
                Some((report.mode.name().to_owned(), version.clone()))
            }
            _ => None,
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    Ok(crate::model::RecallResponse {
        context: crate::model::RecallContext {
            schema_version: crate::INDEX_SCHEMA_VERSION,
            scope: request.scope.clone(),
            requested_revision: request.revision,
            served_revision,
            eligibility_generation: generation,
            temporal: request.temporal,
            index_versions,
            fusion_policy: FUSION_POLICY_VERSION.to_owned(),
        },
        status: progress.execution,
        modes: progress.mode_reports,
        candidates: packed.returned,
        exhaustive: false,
        absence_established: false,
        truncated: packed.truncated || !packed.omissions.is_empty(),
        omissions: packed.omissions,
        reason: if progress.reasons.is_empty() {
            Some("ranked recall is non-exhaustive; omissions are not absence".to_owned())
        } else {
            Some(progress.reasons.join("; "))
        },
        boundary: crate::model::DataBoundary::default(),
    })
}

fn validate(request: &crate::model::RecallRequest) -> crate::error::Result<()> {
    if request.actor.trim().is_empty() {
        return Err(crate::error::RecallError::InvalidRequest(
            "actor must not be empty".to_owned(),
        ));
    }
    if request.modes.is_empty() {
        return Err(crate::error::RecallError::InvalidRequest(
            "at least one recall mode is required".to_owned(),
        ));
    }
    if request.structured.is_some()
        && !request
            .modes
            .contains(&crate::model::RecallMode::Structured)
    {
        return Err(crate::error::RecallError::InvalidRequest(
            "a structured request requires the structured mode".to_owned(),
        ));
    }
    if request.max_items == 0 {
        return Err(crate::error::RecallError::InvalidRequest(
            "max_items must be greater than zero".to_owned(),
        ));
    }
    if request.max_context_bytes < MIN_ITEM_BYTES {
        return Err(crate::error::RecallError::InvalidRequest(
            "max_context_bytes is too small for attribution".to_owned(),
        ));
    }
    if request.max_quote_bytes == 0 {
        return Err(crate::error::RecallError::InvalidRequest(
            "max_quote_bytes must be greater than zero".to_owned(),
        ));
    }
    Ok(())
}

#[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
fn history(
    workspace: &mneme_store::Workspace,
    snapshot: &mneme_store::Snapshot,
) -> crate::error::Result<
    std::collections::BTreeMap<
        (mneme_core::RecordId, mneme_core::RevisionId),
        mneme_core::RecordEnvelope,
    >,
> {
    let mut history = std::collections::BTreeMap::new();
    let max_history_revisions = 1_000_000;
    for record in &snapshot.records {
        for revision in workspace.record_revisions(record.record_id)? {
            if history.len() >= max_history_revisions {
                return Err(crate::error::RecallError::InvalidRequest(
                    "workspace history exceeds the 1M revision bound".to_owned(),
                ));
            }
            history.insert((revision.record_id, revision.revision_id), revision);
        }
    }
    Ok(history)
}

fn cancelled(request: &crate::model::RecallRequest) -> bool {
    request
        .cancellation
        .as_ref()
        .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed))
}

fn cancelled_response(
    request: &crate::model::RecallRequest,
    generation: u64,
) -> crate::model::RecallResponse {
    crate::model::RecallResponse {
        context: crate::model::RecallContext {
            schema_version: crate::INDEX_SCHEMA_VERSION,
            scope: request.scope.clone(),
            requested_revision: request.revision,
            served_revision: request.revision,
            eligibility_generation: generation,
            temporal: request.temporal,
            index_versions: std::collections::BTreeMap::new(),
            fusion_policy: FUSION_POLICY_VERSION.to_owned(),
        },
        status: crate::model::RecallExecution::Cancelled,
        modes: Vec::new(),
        candidates: Vec::new(),
        exhaustive: false,
        absence_established: false,
        truncated: false,
        omissions: Vec::new(),
        reason: Some("recall cancelled before candidate generation".to_owned()),
        boundary: crate::model::DataBoundary::default(),
    }
}

fn lexical_rank(
    index: &crate::model::CachedIndex,
    request: &crate::model::RecallRequest,
) -> Vec<(String, crate::model::IndexedDocument, f64)> {
    let query_terms = crate::index::tokenize(&request.query.to_lowercase());
    if query_terms.is_empty() {
        return Vec::new();
    }
    let query_lower = request.query.to_lowercase();
    let mut entries = Vec::with_capacity(index.documents.len());
    for document in &index.documents {
        let matched = query_terms
            .iter()
            .filter(|term| document.terms.contains(*term))
            .count();
        if matched == 0 {
            continue;
        }
        let is_phrase = !query_lower.is_empty() && document.normalized.contains(&query_lower);
        let score = matched as f64 / query_terms.len() as f64 + if is_phrase { 0.5 } else { 0.0 };
        entries.push((document.id.clone(), document.clone(), score));
    }
    sort_rank(&mut entries);
    entries
}

fn vector_rank(
    index: &crate::model::CachedIndex,
    request: &crate::model::RecallRequest,
) -> Vec<(String, crate::model::IndexedDocument, f64)> {
    let query_vector = crate::index::trigram_counts(&request.query.to_lowercase());
    if query_vector.is_empty() {
        return Vec::new();
    }
    let query_norm = query_vector
        .values()
        .map(|count| f64::from(*count) * f64::from(*count))
        .sum::<f64>()
        .sqrt();
    if query_norm == 0.0 {
        return Vec::new();
    }
    let mut entries = Vec::with_capacity(index.documents.len());
    for document in &index.documents {
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
        entries.push((document.id.clone(), document.clone(), score));
    }
    sort_rank(&mut entries);
    entries
}

fn sort_rank(entries: &mut [(String, crate::model::IndexedDocument, f64)]) {
    entries.sort_by(|left, right| {
        right
            .2
            .total_cmp(&left.2)
            .then_with(|| left.0.cmp(&right.0))
    });
}

fn candidate_from_document(
    document: &crate::model::IndexedDocument,
    request: &crate::model::RecallRequest,
    _vector_score: f64,
) -> Option<crate::model::RecallCandidate> {
    let (body, span) = if document.kind == crate::model::ContentKind::SourceExcerpt {
        let (body, span) =
            crate::index::source_excerpt(&document.text, &request.query, request.max_quote_bytes)?;
        (body, Some(span))
    } else {
        (document.text.clone(), document.span)
    };
    Some(crate::model::RecallCandidate {
        id: document.id.clone(),
        content_kind: document.kind,
        text: body,
        text_truncated: false,
        source: document.source,
        source_revision: document.source_revision,
        span,
        field_path: document.field_path.clone(),
        assertion: document.assertion,
        episode: document.episode,
        entity: document.entity,
        claim_status: document.claim_status.clone(),
        quote: document.kind == crate::model::ContentKind::SourceExcerpt,
        evidence: document.evidence.clone(),
        derivations: Vec::new(),
        ancestry_roots: document.ancestry_roots.clone(),
        independent_support: true,
        origins: std::collections::BTreeSet::new(),
        score: 0.0,
        score_components: std::collections::BTreeMap::new(),
    })
}

fn add_candidate(
    candidates: &mut std::collections::BTreeMap<String, crate::model::RecallCandidate>,
    candidate: crate::model::RecallCandidate,
    mode: crate::model::RecallMode,
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
    candidates: std::collections::BTreeMap<String, crate::model::RecallCandidate>,
    rankings: &[(crate::model::RecallMode, Vec<(String, f64)>)],
) -> Vec<crate::model::RecallCandidate> {
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

#[allow(unknown_lints, ambient_clock)] // packing deadline is the request shell
fn pack(
    candidates: &mut Vec<crate::model::RecallCandidate>,
    request: &crate::model::RecallRequest,
    started: std::time::Instant,
    execution: &mut crate::model::RecallExecution,
    reasons: &mut Vec<String>,
) -> (
    Vec<crate::model::RecallCandidate>,
    Vec<crate::model::Omission>,
    bool,
) {
    let ordered = order_by_independence(std::mem::take(candidates));
    let mut packed = PackedCandidates {
        returned: Vec::with_capacity(ordered.len().min(request.max_items)),
        omissions: Vec::with_capacity(ordered.len()),
        is_truncated: false,
        remaining: request.max_context_bytes,
    };
    let max_time_ms = match u64::try_from(request.max_time_ms) {
        Ok(value) => value,
        Err(_) => {
            *execution = crate::model::RecallExecution::Timeout;
            reasons.push("recall time budget exceeds u64 milliseconds".to_owned());
            return packed.into_parts();
        }
    };
    let deadline = std::time::Duration::from_millis(max_time_ms);
    for candidate in ordered {
        pack_candidate(
            candidate,
            request,
            started,
            deadline,
            &mut packed,
            execution,
            reasons,
        );
    }
    packed.into_parts()
}

struct PackedCandidates {
    returned: Vec<crate::model::RecallCandidate>,
    omissions: Vec<crate::model::Omission>,
    is_truncated: bool,
    remaining: usize,
}

impl PackedCandidates {
    fn into_parts(
        self,
    ) -> (
        Vec<crate::model::RecallCandidate>,
        Vec<crate::model::Omission>,
        bool,
    ) {
        (self.returned, self.omissions, self.is_truncated)
    }
}

fn order_by_independence(
    values: Vec<crate::model::RecallCandidate>,
) -> Vec<crate::model::RecallCandidate> {
    let mut ordered = Vec::with_capacity(values.len());
    let mut duplicates = Vec::with_capacity(values.len());
    let mut seen_roots = std::collections::BTreeSet::new();
    for candidate in values {
        if candidate.ancestry_roots.is_empty() {
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

#[allow(
    unknown_lints,
    ambient_clock,
    clippy::too_many_arguments,
    too_many_parameters
)]
fn pack_candidate(
    candidate: crate::model::RecallCandidate,
    request: &crate::model::RecallRequest,
    started: std::time::Instant,
    deadline: std::time::Duration,
    packed: &mut PackedCandidates,
    execution: &mut crate::model::RecallExecution,
    reasons: &mut Vec<String>,
) {
    if cancelled(request) {
        *execution = crate::model::RecallExecution::Cancelled;
        reasons.push("recall cancelled during packing".to_owned());
        omit_candidate(candidate, "cancelled", packed);
        return;
    }
    if started.elapsed() > deadline {
        *execution = crate::model::RecallExecution::Timeout;
        reasons.push("recall timed out during packing".to_owned());
        omit_candidate(candidate, "time-budget", packed);
        return;
    }
    if packed.returned.len() >= request.max_items {
        omit_candidate(candidate, "item-limit", packed);
        return;
    }
    let cap = if candidate.quote {
        packed.remaining.min(request.max_quote_bytes)
    } else {
        packed.remaining
    };
    if cap < MIN_ITEM_BYTES {
        omit_candidate(candidate, "context-budget", packed);
        return;
    }
    let Some(candidate) = truncate_candidate(candidate, cap, packed) else {
        return;
    };
    if candidate.text.is_empty() {
        omit_candidate(candidate, "empty-item", packed);
        return;
    }
    packed.remaining = packed.remaining.saturating_sub(candidate.text.len());
    packed.returned.push(candidate);
}

fn truncate_candidate(
    mut candidate: crate::model::RecallCandidate,
    cap: usize,
    packed: &mut PackedCandidates,
) -> Option<crate::model::RecallCandidate> {
    if candidate.text.len() > cap {
        let end = floor_boundary(&candidate.text, cap);
        if end == 0 {
            omit_candidate(candidate, "context-budget", packed);
            return None;
        }
        candidate.text.truncate(end);
        candidate.text_truncated = true;
        packed.is_truncated = true;
        if candidate.quote
            && let Some(span) = candidate.span
        {
            let start = span.start();
            candidate.span = mneme_core::SourceSpan::new(start, start + end as u64 - 1).ok();
        }
    }
    Some(candidate)
}

fn omit_candidate(
    candidate: crate::model::RecallCandidate,
    reason: &str,
    packed: &mut PackedCandidates,
) {
    packed.omissions.push(crate::model::Omission {
        candidate: candidate.id,
        reason: reason.to_owned(),
    });
}

fn floor_boundary(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn datalog_version(build: &mneme_datalog::DatalogBuild) -> String {
    format!(
        "datalog:{}:{}:{}",
        build.context.rule_bundle_id,
        build.context.rule_bundle_version,
        build.context.projection_build_id
    )
}

fn structured_coverage(
    build: &mneme_datalog::DatalogBuild,
    result: &mneme_datalog::QueryResult,
    predicate: &str,
) -> crate::model::IndexCoverage {
    let coverage = build
        .coverage
        .iter()
        .find(|coverage| coverage.predicate == predicate)
        .map(|coverage| coverage.status)
        .unwrap_or(mneme_datalog::CoverageStatus::Unknown);
    if result.truncated {
        return crate::model::IndexCoverage::incomplete(
            result.rows.len(),
            0,
            "structured result hit its row cap",
        );
    }
    if coverage == mneme_datalog::CoverageStatus::Complete && result.exhaustive {
        return crate::model::IndexCoverage::complete(result.rows.len());
    }
    let reason = if build.status == mneme_datalog::ExecutionStatus::Complete {
        format!("declared relation coverage is {:?}", coverage)
    } else {
        format!("Datalog execution finished with {:?}", build.status)
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
