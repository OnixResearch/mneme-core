//! In-memory lexical and local token-vector index over one scoped snapshot.

use std::collections::{BTreeMap, BTreeSet};

use mneme_core::{Lifecycle, RecordId, RecordKind, Reference, ScopeId, SourceSpan, Value, text};
use mneme_memory::{
    AssertionView, BeliefView, EpisodeView, MemoryView, SourceAvailability, SourceStatus,
};

use crate::error::Result;
use crate::model::{
    CachedIndex, ClaimStatus, ContentKind, IndexCoverage, IndexedDocument, RecallEvidence,
    RecallRequest, TemporalMode,
};

/// Index schema and tokenizer version.
pub const LEXICAL_INDEX_VERSION: &str = "mneme-lexical-token-v1";
/// Sparse character-trigram vector projection. This is not a learned model.
pub const VECTOR_INDEX_VERSION: &str = "mneme-trigram-hash-v1";

/// Build a fresh index for the request's temporal selection.
pub(crate) fn build_index(view: &MemoryView, request: &RecallRequest) -> Result<CachedIndex> {
    let snapshot = view.snapshot().clone();
    let mut documents = Vec::new();
    let mut skipped = 0_usize;
    let mut skip_reasons = BTreeSet::new();

    let entities = entity_labels(view, &request.scope);
    for record in snapshot
        .records
        .iter()
        .filter(|record| record.scope == request.scope)
    {
        match record.kind {
            RecordKind::Entity => {
                let label = entities
                    .get(&record.record_id)
                    .cloned()
                    .unwrap_or_else(|| record.record_id.to_hex());
                let entity_type = record
                    .payload
                    .get("entity-type")
                    .map(text::render)
                    .unwrap_or_default();
                let properties = record
                    .payload
                    .get("properties")
                    .map(text::render)
                    .unwrap_or_default();
                let body = format!("{label} {entity_type} {properties}");
                documents.push(document(
                    format!("entity:{}", record.record_id),
                    ContentKind::TypedField,
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
                    BTreeSet::new(),
                ));
            }
            RecordKind::Episode => {
                let episode = EpisodeView::parse(record.clone())?;
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
                documents.push(document(
                    format!("episode:{}", record.record_id),
                    ContentKind::EpisodeSummary,
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
                    BTreeSet::new(),
                ));
            }
            RecordKind::SourceRevision => {
                let source = view.source(record.record_id)?;
                if let Some(path) = &source.path_hint {
                    documents.push(document(
                        format!("source-path:{}:{}", record.record_id, record.revision_id),
                        ContentKind::TypedField,
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
                        BTreeSet::from([(record.record_id, record.revision_id)]),
                    ));
                }
                match view.source_status_for(&source)? {
                    SourceStatus::Retained(bytes) => match String::from_utf8(bytes) {
                        Ok(body) => {
                            documents.push(document(
                                format!("source:{}:{}", record.record_id, record.revision_id),
                                ContentKind::SourceExcerpt,
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
                                BTreeSet::from([(record.record_id, record.revision_id)]),
                            ));
                        }
                        Err(_) => {
                            skipped += 1;
                            skip_reasons.insert("source bytes are not UTF-8 text".to_owned());
                        }
                    },
                    status => {
                        skipped += 1;
                        skip_reasons.insert(format!(
                            "source is {} and has no searchable bytes",
                            status.availability().name()
                        ));
                    }
                }
            }
            _ => {}
        }
    }

    let assertions = selected_assertions(view, request)?;
    for assertion in assertions {
        let status = ClaimStatus::from_assertion(&assertion);
        let (evidence, roots) = evidence_refs(view, &assertion);
        let subject = entities
            .get(&assertion.subject)
            .cloned()
            .unwrap_or_else(|| assertion.subject.to_hex());
        let body = format!(
            "{} {} {} {}",
            assertion.predicate,
            text::render(&assertion.value),
            subject,
            assertion.asserted_by
        );
        documents.push(document(
            format!("assertion:{}", assertion.record.record_id),
            ContentKind::Claim,
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

    let indexed = documents.len();
    let coverage = if skipped == 0 {
        IndexCoverage::complete(indexed)
    } else {
        IndexCoverage::incomplete(
            indexed,
            skipped,
            skip_reasons.into_iter().collect::<Vec<_>>().join("; "),
        )
    };
    Ok(CachedIndex {
        revision: view.revision(),
        coverage,
        documents,
    })
}

fn selected_assertions(view: &MemoryView, request: &RecallRequest) -> Result<Vec<AssertionView>> {
    match request.temporal {
        TemporalMode::Current => Ok(view.current_beliefs(&BeliefView {
            scope: request.scope.clone(),
            at: request.at,
            include_hypothetical: request.include_hypothetical,
            include_disputed: request.include_disputed,
        })?),
        TemporalMode::Historical => Ok(view
            .assertions()?
            .into_iter()
            .filter(|assertion| {
                assertion.record.scope == request.scope
                    && assertion.lifecycle != Lifecycle::Proposed
            })
            .collect()),
        TemporalMode::Inspection => Ok(view
            .assertions()?
            .into_iter()
            .filter(|assertion| assertion.record.scope == request.scope)
            .collect()),
    }
}

fn entity_labels(view: &MemoryView, scope: &ScopeId) -> BTreeMap<RecordId, String> {
    view.snapshot()
        .records
        .iter()
        .filter(|record| record.kind == RecordKind::Entity && &record.scope == scope)
        .filter_map(|record| {
            record
                .payload
                .get("label")
                .and_then(Value::as_string)
                .map(|label| (record.record_id, label.to_owned()))
        })
        .collect()
}

fn evidence_refs(
    view: &MemoryView,
    assertion: &AssertionView,
) -> (
    Vec<RecallEvidence>,
    BTreeSet<(RecordId, mneme_core::RevisionId)>,
) {
    let mut roots = BTreeSet::new();
    let mut refs = Vec::new();
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
            .unwrap_or_else(|_| SourceAvailability::Unavailable {
                reason: "source could not be read".to_owned(),
            });
        let source_revision = match evidence.source_reference {
            Reference::Pinned { revision, .. } => Some(revision),
            _ => Some(source.record.revision_id),
        };
        let evidence_roots = view.evidence_roots(*evidence_id).unwrap_or_default();
        roots.extend(evidence_roots.iter().copied());
        refs.push(RecallEvidence {
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

#[allow(clippy::too_many_arguments)]
fn document(
    id: String,
    kind: ContentKind,
    text: String,
    field_path: String,
    source: Option<RecordId>,
    source_revision: Option<mneme_core::RevisionId>,
    span: Option<SourceSpan>,
    assertion: Option<RecordId>,
    episode: Option<RecordId>,
    entity: Option<RecordId>,
    claim_status: Option<ClaimStatus>,
    evidence: Vec<RecallEvidence>,
    ancestry_roots: BTreeSet<(RecordId, mneme_core::RevisionId)>,
) -> IndexedDocument {
    let normalized = text.to_lowercase();
    let terms = tokenize(&normalized);
    let trigrams = trigram_counts(&normalized);
    let trigram_norm = trigrams
        .values()
        .map(|count| f64::from(*count) * f64::from(*count))
        .sum::<f64>()
        .sqrt();
    IndexedDocument {
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
pub(crate) fn tokenize(text: &str) -> BTreeSet<String> {
    text.split(|character: char| !character.is_alphanumeric())
        .filter(|term| !term.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// Hash character trigrams into a sparse vector.
pub(crate) fn trigram_counts(text: &str) -> BTreeMap<u64, u32> {
    let characters = text.chars().collect::<Vec<_>>();
    let mut counts = BTreeMap::new();
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
) -> Option<(String, SourceSpan)> {
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
    let span = SourceSpan::new(start as u64, inclusive_end as u64).ok()?;
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
