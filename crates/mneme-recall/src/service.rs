//! Bounded recall service over one mutable workspace handle.

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
        let started = std::time::Instant::now();
        let generation = self.workspace.eligibility_generation()?;
        if self.cached_generation != Some(generation) {
            self.indexes.clear();
            self.cached_generation = Some(generation);
        }
        if cancelled(request) {
            return Ok(cancelled_response(request, generation));
        }
        let current_revision = self.workspace.current_revision()?;
        if current_revision != request.revision && !request.allow_stale {
            return Err(crate::error::RecallError::StaleRevision {
                requested: request.revision,
                current: current_revision,
            });
        }
        let view = self.view(request.revision, generation)?;
        let served_revision = view.revision();
        let mut mode_reports = Vec::new();
        let is_requested_structured = request
            .modes
            .contains(&crate::model::RecallMode::Structured);
        if is_requested_structured && request.structured.is_none() && !request.allow_fallback {
            return Err(crate::error::RecallError::ModeUnavailable {
                mode: crate::model::RecallMode::Structured.name().to_owned(),
                reason: "no structured request was supplied".to_owned(),
            });
        }
        let is_fallback_lexical = is_requested_structured
            && request.structured.is_none()
            && request.allow_fallback
            && !request.modes.contains(&crate::model::RecallMode::Lexical);
        let is_use_lexical =
            request.modes.contains(&crate::model::RecallMode::Lexical) || is_fallback_lexical;
        let is_use_vector = request.modes.contains(&crate::model::RecallMode::Vector);
        if !is_use_lexical && !is_use_vector && request.structured.is_none() {
            return Err(crate::error::RecallError::ModeUnavailable {
                mode: "all requested modes".to_owned(),
                reason: "no candidate mode can execute".to_owned(),
            });
        }
        if cancelled(request) {
            return Ok(cancelled_response(request, generation));
        }

        let mut index = None;
        if is_use_lexical || is_use_vector {
            let key = IndexKey {
                revision: request.revision,
                scope: request.scope.clone(),
                generation,
                temporal: request.temporal,
                at: request.at,
                include_disputed: request.include_disputed,
                include_hypothetical: request.include_hypothetical,
            };
            let built = if let Some(cached) = self.indexes.get(&key) {
                cached.clone()
            } else {
                let built = crate::index::build_index(&view, request)?;
                self.indexes.insert(key, built.clone());
                built
            };
            index = Some(built);
        }
        self.require_generation(generation)?;

        let mut ranking = Vec::new();
        let mut candidates: std::collections::BTreeMap<String, crate::model::RecallCandidate> =
            std::collections::BTreeMap::new();
        if is_use_lexical {
            let index = index.as_ref().ok_or_else(|| {
                crate::error::RecallError::InvalidRequest("lexical index was not built".to_owned())
            })?;
            let entries = lexical_rank(index, request);
            for (id, document, score) in &entries {
                let Some(candidate) = candidate_from_document(document, request, 0.0) else {
                    continue;
                };
                add_candidate(
                    &mut candidates,
                    candidate,
                    crate::model::RecallMode::Lexical,
                    *score,
                    id,
                );
            }
            ranking.push((
                crate::model::RecallMode::Lexical,
                entries
                    .iter()
                    .map(|(id, _, score)| (id.clone(), *score))
                    .collect::<Vec<_>>(),
            ));
            mode_reports.push(crate::model::ModeReport {
                mode: crate::model::RecallMode::Lexical,
                status: crate::model::ModeStatus::Used,
                index_version: Some(crate::index::LEXICAL_INDEX_VERSION.to_owned()),
                revision: Some(index.revision),
                coverage: index.coverage.clone(),
                candidates: entries.len(),
                relation_exhaustive: None,
                reason: if is_fallback_lexical {
                    Some("lexical fallback for an unavailable requested mode".to_owned())
                } else {
                    None
                },
            });
        }
        if is_use_vector {
            let index = index.as_ref().ok_or_else(|| {
                crate::error::RecallError::InvalidRequest("vector index was not built".to_owned())
            })?;
            let entries = vector_rank(index, request);
            for (id, document, score) in &entries {
                let Some(candidate) = candidate_from_document(document, request, *score) else {
                    continue;
                };
                add_candidate(
                    &mut candidates,
                    candidate,
                    crate::model::RecallMode::Vector,
                    *score,
                    id,
                );
            }
            ranking.push((
                crate::model::RecallMode::Vector,
                entries
                    .iter()
                    .map(|(id, _, score)| (id.clone(), *score))
                    .collect::<Vec<_>>(),
            ));
            mode_reports.push(crate::model::ModeReport {
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
        }

        let mut execution = crate::model::RecallExecution::Complete;
        let mut reasons = Vec::new();
        if is_requested_structured {
            match request.structured.as_ref() {
                None => {
                    mode_reports.push(crate::model::ModeReport {
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
                    execution = crate::model::RecallExecution::Partial;
                    reasons.push("structured mode unavailable".to_owned());
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
                        Err(error) => {
                            mode_reports.push(crate::model::ModeReport {
                                mode: crate::model::RecallMode::Structured,
                                status: crate::model::ModeStatus::Failed,
                                index_version: Some(format!(
                                    "datalog:{}:{}",
                                    structured.bundle.id, structured.bundle.version
                                )),
                                revision: Some(served_revision),
                                coverage: crate::model::IndexCoverage::incomplete(
                                    0,
                                    0,
                                    error.to_string(),
                                ),
                                candidates: 0,
                                relation_exhaustive: None,
                                reason: Some(error.to_string()),
                            });
                            execution = failure_execution(request.allow_partial);
                            reasons.push(format!("structured mode failed: {error}"));
                        }
                        Ok(build) => {
                            let rows = mneme_datalog::DatalogService::new(self.workspace)
                                .query_build(&build, structured.query.clone());
                            match rows {
                                Err(error) => {
                                    mode_reports.push(crate::model::ModeReport {
                                        mode: crate::model::RecallMode::Structured,
                                        status: crate::model::ModeStatus::Failed,
                                        index_version: Some(datalog_version(&build)),
                                        revision: Some(served_revision),
                                        coverage: crate::model::IndexCoverage::incomplete(
                                            0,
                                            0,
                                            error.to_string(),
                                        ),
                                        candidates: 0,
                                        relation_exhaustive: None,
                                        reason: Some(error.to_string()),
                                    });
                                    execution = failure_execution(request.allow_partial);
                                    reasons.push(format!("structured query failed: {error}"));
                                }
                                Ok(rows) => {
                                    let coverage = structured_coverage(
                                        &build,
                                        &rows,
                                        &structured.query.predicate,
                                    );
                                    let mut structured_ranking = Vec::new();
                                    for row in &rows.rows {
                                        let id =
                                            structured_id(&structured.query.predicate, &row.values);
                                        let body = format!(
                                            "{} {}",
                                            structured.query.predicate,
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
                                        let candidate = crate::model::RecallCandidate {
                                            id: id.clone(),
                                            content_kind: crate::model::ContentKind::StructuredRow,
                                            text: body,
                                            text_truncated: false,
                                            source: None,
                                            source_revision: None,
                                            span: None,
                                            field_path: format!(
                                                "structured.{}",
                                                structured.query.predicate
                                            ),
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
                                        };
                                        add_candidate(
                                            &mut candidates,
                                            candidate,
                                            crate::model::RecallMode::Structured,
                                            1.0,
                                            &id,
                                        );
                                        structured_ranking.push((id, 1.0));
                                    }
                                    ranking.push((
                                        crate::model::RecallMode::Structured,
                                        structured_ranking,
                                    ));
                                    let status = match rows.status {
                                        mneme_datalog::ExecutionStatus::Complete => {
                                            crate::model::ModeStatus::Used
                                        }
                                        mneme_datalog::ExecutionStatus::Timeout => {
                                            crate::model::ModeStatus::TimedOut
                                        }
                                        mneme_datalog::ExecutionStatus::Cancelled => {
                                            crate::model::ModeStatus::Omitted
                                        }
                                        mneme_datalog::ExecutionStatus::Failed
                                        | mneme_datalog::ExecutionStatus::Partial => {
                                            crate::model::ModeStatus::Failed
                                        }
                                    };
                                    if !matches!(status, crate::model::ModeStatus::Used) {
                                        execution = failure_execution(request.allow_partial);
                                        reasons.push(format!(
                                            "structured mode finished with {:?}",
                                            rows.status
                                        ));
                                    }
                                    mode_reports.push(crate::model::ModeReport {
                                        mode: crate::model::RecallMode::Structured,
                                        status,
                                        index_version: Some(datalog_version(&build)),
                                        revision: Some(served_revision),
                                        coverage,
                                        candidates: rows.rows.len(),
                                        relation_exhaustive: Some(rows.exhaustive),
                                        reason: rows.reason.clone(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        self.require_generation(generation)?;

        let mut fused = fuse(candidates, &ranking);
        let (mut returned, mut omissions, truncated) =
            pack(&mut fused, request, started, &mut execution, &mut reasons);
        if execution == crate::model::RecallExecution::Failed && !request.allow_partial {
            returned.clear();
            omissions.clear();
        }
        self.require_generation(generation)?;
        if cancelled(request) {
            execution = crate::model::RecallExecution::Cancelled;
            returned.clear();
            reasons.push("recall cancelled".to_owned());
        }
        let max_time_ms = u64::try_from(request.max_time_ms).map_err(|_| {
            crate::error::RecallError::InvalidRequest(
                "recall time budget exceeds u64 milliseconds".to_owned(),
            )
        })?;
        if started.elapsed() > std::time::Duration::from_millis(max_time_ms)
            && execution == crate::model::RecallExecution::Complete
        {
            execution = crate::model::RecallExecution::Timeout;
            reasons.push("recall exceeded its time budget".to_owned());
        }
        let mut index_versions = std::collections::BTreeMap::new();
        for report in &mode_reports {
            if let (Some(version), crate::model::ModeStatus::Used) =
                (&report.index_version, report.status)
            {
                index_versions.insert(report.mode.name().to_owned(), version.clone());
            }
        }
        let _ = current_revision;
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
            status: execution,
            modes: mode_reports,
            candidates: returned,
            exhaustive: false,
            absence_established: false,
            truncated: truncated || !omissions.is_empty(),
            omissions,
            reason: if reasons.is_empty() {
                Some("ranked recall is non-exhaustive; omissions are not absence".to_owned())
            } else {
                Some(reasons.join("; "))
            },
            boundary: crate::model::DataBoundary::default(),
        })
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
    for record in &snapshot.records {
        for revision in workspace.record_revisions(record.record_id)? {
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
    let values = std::mem::take(candidates);
    let mut ordered = Vec::new();
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
    let mut returned = Vec::new();
    let mut omissions = Vec::with_capacity(ordered.len());
    let mut is_truncated = false;
    let mut remaining = request.max_context_bytes;
    let max_time_ms = match u64::try_from(request.max_time_ms) {
        Ok(value) => value,
        Err(_) => {
            *execution = crate::model::RecallExecution::Timeout;
            reasons.push("recall time budget exceeds u64 milliseconds".to_owned());
            return (returned, omissions, is_truncated);
        }
    };
    let deadline = std::time::Duration::from_millis(max_time_ms);
    for candidate in ordered {
        if cancelled(request) {
            *execution = crate::model::RecallExecution::Cancelled;
            reasons.push("recall cancelled during packing".to_owned());
            omissions.push(crate::model::Omission {
                candidate: candidate.id,
                reason: "cancelled".to_owned(),
            });
            continue;
        }
        if started.elapsed() > deadline {
            *execution = crate::model::RecallExecution::Timeout;
            reasons.push("recall timed out during packing".to_owned());
            omissions.push(crate::model::Omission {
                candidate: candidate.id,
                reason: "time-budget".to_owned(),
            });
            continue;
        }
        if returned.len() >= request.max_items {
            omissions.push(crate::model::Omission {
                candidate: candidate.id,
                reason: "item-limit".to_owned(),
            });
            continue;
        }
        let cap = if candidate.quote {
            remaining.min(request.max_quote_bytes)
        } else {
            remaining
        };
        if cap < MIN_ITEM_BYTES {
            omissions.push(crate::model::Omission {
                candidate: candidate.id,
                reason: "context-budget".to_owned(),
            });
            continue;
        }
        let mut candidate = candidate;
        if candidate.text.len() > cap {
            let end = floor_boundary(&candidate.text, cap);
            if end == 0 {
                omissions.push(crate::model::Omission {
                    candidate: candidate.id,
                    reason: "context-budget".to_owned(),
                });
                continue;
            }
            candidate.text.truncate(end);
            candidate.text_truncated = true;
            is_truncated = true;
            if candidate.quote
                && let Some(span) = candidate.span
            {
                let start = span.start();
                candidate.span = mneme_core::SourceSpan::new(start, start + end as u64 - 1).ok();
            }
        }
        if candidate.text.is_empty() {
            omissions.push(crate::model::Omission {
                candidate: candidate.id,
                reason: "empty-item".to_owned(),
            });
            continue;
        }
        remaining = remaining.saturating_sub(candidate.text.len());
        returned.push(candidate);
    }
    (returned, omissions, is_truncated)
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
