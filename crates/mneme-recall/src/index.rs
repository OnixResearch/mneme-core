//! In-memory lexical and local token-vector index over one scoped snapshot.
#![allow(path_segment_repetition)] // Octet structural exception: domain-qualified names and macro-only imports are intentional

/// Index schema and tokenizer version.
pub const LEXICAL_INDEX_VERSION: &str = "mneme-lexical-token-v1";
/// Sparse character-trigram vector projection. This is not a learned model.
pub const VECTOR_INDEX_VERSION: &str = "mneme-trigram-hash-v1";

/// Build a fresh index for the request's temporal selection.
#[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
pub(crate) fn build_index(
    view: &mneme_memory::MemoryView,
    request: &crate::model::RecallRequest,
) -> crate::error::Result<crate::model::CachedIndex> {
    let snapshot = view.snapshot().clone();
    let mut index = IndexBuild::default();
    let max_documents = snapshot.records.len().saturating_mul(2);
    index.documents.reserve(max_documents);
    let entities = entity_labels(view, &request.scope);
    for record in snapshot
        .records
        .iter()
        .filter(|record| record.scope == request.scope)
    {
        index.add_record(view, record, &entities)?;
    }
    let assertions = selected_assertions(view, request)?;
    for assertion in assertions {
        index.add_assertion(view, &entities, &assertion);
    }
    Ok(index.finish(view.revision()))
}

#[derive(Default)]
struct IndexBuild {
    documents: Vec<crate::model::IndexedDocument>,
    skipped: usize,
    skip_reasons: std::collections::BTreeSet<String>,
}

impl IndexBuild {
    fn add_record(
        &mut self,
        view: &mneme_memory::MemoryView,
        record: &mneme_core::RecordEnvelope,
        entities: &std::collections::BTreeMap<mneme_core::RecordId, String>,
    ) -> crate::error::Result<()> {
        match record.kind {
            mneme_core::RecordKind::Entity => self.add_entity(record, entities),
            mneme_core::RecordKind::Episode => self.add_episode(view, record)?,
            mneme_core::RecordKind::SourceRevision => self.add_source(view, record)?,
            _ => {}
        }
        Ok(())
    }

    fn add_entity(
        &mut self,
        record: &mneme_core::RecordEnvelope,
        entities: &std::collections::BTreeMap<mneme_core::RecordId, String>,
    ) {
        let label = entities
            .get(&record.record_id)
            .cloned()
            .unwrap_or_else(|| record.record_id.to_hex());
        let entity_type = record
            .payload
            .get("entity-type")
            .map(mneme_core::text::render)
            .unwrap_or_default();
        let properties = record
            .payload
            .get("properties")
            .map(mneme_core::text::render)
            .unwrap_or_default();
        let body = format!("{label} {entity_type} {properties}");
        self.documents.push(document(
            format!("entity:{}", record.record_id),
            crate::model::ContentKind::TypedField,
            body,
            "entity.label".to_owned(),
            None,
            None,
            None,
            Some(record.record_id),
            None,
            None,
            None,
            Vec::new(),
            std::collections::BTreeSet::new(),
        ));
    }

    fn add_episode(
        &mut self,
        view: &mneme_memory::MemoryView,
        record: &mneme_core::RecordEnvelope,
    ) -> crate::error::Result<()> {
        let episode = mneme_memory::EpisodeView::parse(record.clone())?;
        let body = format!(
            "{} {} {}",
            episode.summary,
            episode.actor,
            episode.episode_type.name()
        );
        let (source, source_revision) = match episode.source {
            Some(source) => {
                let revision = view
                    .source(source)
                    .ok()
                    .map(|source| source.record.revision_id);
                (Some(source), revision)
            }
            None => (None, None),
        };
        self.documents.push(document(
            format!("episode:{}", record.record_id),
            crate::model::ContentKind::EpisodeSummary,
            body,
            "episode.summary".to_owned(),
            source,
            source_revision,
            None,
            None,
            Some(record.record_id),
            None,
            None,
            Vec::new(),
            std::collections::BTreeSet::new(),
        ));
        Ok(())
    }

    fn add_source(
        &mut self,
        view: &mneme_memory::MemoryView,
        record: &mneme_core::RecordEnvelope,
    ) -> crate::error::Result<()> {
        let source = view.source(record.record_id)?;
        if let Some(path) = &source.path_hint {
            self.documents.push(document(
                format!("source-path:{}:{}", record.record_id, record.revision_id),
                crate::model::ContentKind::TypedField,
                path.clone(),
                "source.path-hint".to_owned(),
                Some(record.record_id),
                Some(record.revision_id),
                None,
                None,
                None,
                None,
                None,
                Vec::new(),
                std::collections::BTreeSet::from([(record.record_id, record.revision_id)]),
            ));
        }
        self.add_source_content(view, record, &source)?;
        Ok(())
    }

    fn add_source_content(
        &mut self,
        view: &mneme_memory::MemoryView,
        record: &mneme_core::RecordEnvelope,
        source: &mneme_memory::SourceView,
    ) -> crate::error::Result<()> {
        match view.source_status_for(source)? {
            mneme_memory::SourceStatus::Retained(bytes) => match String::from_utf8(bytes) {
                Ok(body) => self.documents.push(document(
                    format!("source:{}:{}", record.record_id, record.revision_id),
                    crate::model::ContentKind::SourceExcerpt,
                    body,
                    "source.content".to_owned(),
                    Some(record.record_id),
                    Some(record.revision_id),
                    None,
                    None,
                    None,
                    None,
                    None,
                    Vec::new(),
                    std::collections::BTreeSet::from([(record.record_id, record.revision_id)]),
                )),
                Err(_) => {
                    self.skipped += 1;
                    self.skip_reasons
                        .insert("source bytes are not UTF-8 text".to_owned());
                }
            },
            status => {
                self.skipped += 1;
                self.skip_reasons.insert(format!(
                    "source is {} and has no searchable bytes",
                    status.availability().name()
                ));
            }
        }
        Ok(())
    }

    fn add_assertion(
        &mut self,
        view: &mneme_memory::MemoryView,
        entities: &std::collections::BTreeMap<mneme_core::RecordId, String>,
        assertion: &mneme_memory::AssertionView,
    ) {
        let status = crate::model::ClaimStatus::from_assertion(assertion);
        let (evidence, roots) = evidence_refs(view, assertion);
        let subject = entities
            .get(&assertion.subject)
            .cloned()
            .unwrap_or_else(|| assertion.subject.to_hex());
        let body = format!(
            "{} {} {} {}",
            assertion.predicate,
            mneme_core::text::render(&assertion.value),
            subject,
            assertion.asserted_by
        );
        self.documents.push(document(
            format!("assertion:{}", assertion.record.record_id),
            crate::model::ContentKind::Claim,
            body,
            format!("assertion.{}", assertion.predicate),
            None,
            None,
            None,
            Some(assertion.record.record_id),
            None,
            None,
            Some(status),
            evidence,
            roots,
        ));
    }

    fn finish(self, revision: mneme_core::WorkspaceRevisionId) -> crate::model::CachedIndex {
        let indexed = self.documents.len();
        let coverage = if self.skipped == 0 {
            crate::model::IndexCoverage::complete(indexed)
        } else {
            crate::model::IndexCoverage::incomplete(
                indexed,
                self.skipped,
                self.skip_reasons.into_iter().collect::<Vec<_>>().join("; "),
            )
        };
        crate::model::CachedIndex {
            revision,
            coverage,
            documents: self.documents,
        }
    }
}

fn selected_assertions(
    view: &mneme_memory::MemoryView,
    request: &crate::model::RecallRequest,
) -> crate::error::Result<Vec<mneme_memory::AssertionView>> {
    match request.temporal {
        crate::model::TemporalMode::Current => {
            Ok(view.current_beliefs(&mneme_memory::BeliefView {
                scope: request.scope.clone(),
                at: request.at,
                include_hypothetical: request.include_hypothetical,
                include_disputed: request.include_disputed,
            })?)
        }
        crate::model::TemporalMode::Historical => Ok(view
            .assertions()?
            .into_iter()
            .filter(|assertion| {
                assertion.record.scope == request.scope
                    && assertion.lifecycle != mneme_core::Lifecycle::Proposed
            })
            .collect()),
        crate::model::TemporalMode::Inspection => Ok(view
            .assertions()?
            .into_iter()
            .filter(|assertion| assertion.record.scope == request.scope)
            .collect()),
    }
}

fn entity_labels(
    view: &mneme_memory::MemoryView,
    scope: &mneme_core::ScopeId,
) -> std::collections::BTreeMap<mneme_core::RecordId, String> {
    view.snapshot()
        .records
        .iter()
        .filter(|record| record.kind == mneme_core::RecordKind::Entity && &record.scope == scope)
        .filter_map(|record| {
            record
                .payload
                .get("label")
                .and_then(mneme_core::Value::as_string)
                .map(|label| (record.record_id, label.to_owned()))
        })
        .collect()
}

fn evidence_refs(
    view: &mneme_memory::MemoryView,
    assertion: &mneme_memory::AssertionView,
) -> (
    Vec<crate::model::RecallEvidence>,
    std::collections::BTreeSet<(mneme_core::RecordId, mneme_core::RevisionId)>,
) {
    let mut roots = std::collections::BTreeSet::new();
    let mut refs = Vec::with_capacity(assertion.evidence.len());
    for evidence_id in &assertion.evidence {
        let Ok(evidence) = view.evidence(*evidence_id) else {
            continue;
        };
        let Ok(source) = view.evidence_source(&evidence) else {
            continue;
        };
        let availability = view
            .source_status_for(&source)
            .map(|status| status.availability())
            .unwrap_or_else(|_| mneme_memory::SourceAvailability::Unavailable {
                reason: "source could not be read".to_owned(),
            });
        let source_revision = match evidence.source_reference {
            mneme_core::Reference::Pinned { revision, .. } => Some(revision),
            _ => Some(source.record.revision_id),
        };
        let evidence_roots = view.evidence_roots(*evidence_id).unwrap_or_default();
        roots.extend(evidence_roots.iter().copied());
        refs.push(crate::model::RecallEvidence {
            evidence: *evidence_id,
            source: evidence.source,
            source_revision,
            span: evidence.span,
            availability,
            ancestry_roots: evidence_roots,
        });
    }
    (refs, roots)
}

#[allow(unknown_lints, clippy::too_many_arguments, too_many_parameters)]
fn document(
    id: String,
    kind: crate::model::ContentKind,
    text: String,
    field_path: String,
    source: Option<mneme_core::RecordId>,
    source_revision: Option<mneme_core::RevisionId>,
    span: Option<mneme_core::SourceSpan>,
    assertion: Option<mneme_core::RecordId>,
    episode: Option<mneme_core::RecordId>,
    entity: Option<mneme_core::RecordId>,
    claim_status: Option<crate::model::ClaimStatus>,
    evidence: Vec<crate::model::RecallEvidence>,
    ancestry_roots: std::collections::BTreeSet<(mneme_core::RecordId, mneme_core::RevisionId)>,
) -> crate::model::IndexedDocument {
    let normalized = text.to_lowercase();
    let terms = tokenize(&normalized);
    let trigrams = trigram_counts(&normalized);
    let trigram_norm = trigrams
        .values()
        .map(|count| f64::from(*count) * f64::from(*count))
        .sum::<f64>()
        .sqrt();
    crate::model::IndexedDocument {
        id,
        kind,
        text,
        normalized,
        terms,
        trigrams,
        trigram_norm,
        field_path,
        source,
        source_revision,
        span,
        assertion,
        episode,
        entity,
        claim_status,
        evidence,
        ancestry_roots,
    }
}

/// Tokenize lower-case alphanumeric runs for lexical candidate generation.
pub(crate) fn tokenize(text: &str) -> std::collections::BTreeSet<String> {
    text.split(|character: char| !character.is_alphanumeric())
        .filter(|term| !term.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// Hash character trigrams into a sparse vector.
pub(crate) fn trigram_counts(text: &str) -> std::collections::BTreeMap<u64, u32> {
    let characters = text.chars().collect::<Vec<_>>();
    let mut counts = std::collections::BTreeMap::new();
    if characters.is_empty() {
        return counts;
    }
    if characters.len() < 3 {
        *counts.entry(fnv(&characters)).or_insert(0) += 1;
        return counts;
    }
    for window in characters.windows(3) {
        *counts.entry(fnv(window)).or_insert(0) += 1;
    }
    counts
}

fn fnv(characters: &[char]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for character in characters {
        for byte in character.to_string().as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    hash
}

/// Find an exact source excerpt around the query and return its inclusive span.
pub(crate) fn source_excerpt(
    text: &str,
    query: &str,
    max_quote_bytes: usize,
) -> Option<(String, mneme_core::SourceSpan)> {
    if text.is_empty() || max_quote_bytes == 0 {
        return None;
    }
    let start = if !query.is_empty() {
        find_ascii_case_insensitive(text, query)
    } else {
        None
    }
    .or_else(|| {
        tokenize(&query.to_lowercase())
            .into_iter()
            .find_map(|term| find_ascii_case_insensitive(text, &term))
    })
    .unwrap_or(0);
    let start = floor_boundary(text, start.min(text.len()));
    let mut end = (start + max_quote_bytes).min(text.len());
    end = floor_boundary(text, end);
    if end <= start {
        return None;
    }
    let quote = text[start..end].to_owned();
    let inclusive_end = end.saturating_sub(1);
    let span = mneme_core::SourceSpan::new(start as u64, inclusive_end as u64).ok()?;
    Some((quote, span))
}

fn floor_boundary(text: &str, mut index: usize) -> usize {
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn find_ascii_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    let needle = needle.as_bytes();
    haystack
        .as_bytes()
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
}
