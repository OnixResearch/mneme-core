//! In-memory lexical and local token-vector index over one scoped snapshot.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// Index schema and tokenizer version.
pub const LEXICAL_INDEX_VERSION: &str = "mneme-lexical-token-v1";
/// Sparse character-trigram vector projection. This is not a learned model.
pub const VECTOR_INDEX_VERSION: &str = "mneme-trigram-hash-v1";

/// Current availability of every source record in the pinned snapshot.
///
/// A retrieval pinned to an older revision still obeys the retention state in
/// force now, so the newest revision's availability governs every older one.
pub(crate) type SourceStates =
    std::collections::BTreeMap<mneme_core::RecordId, mneme_memory::SourceAvailability>;

/// One index build's result.
type BuildResult<T> = std::result::Result<T, crate::engine::AttemptFailure>;

/// Read-only material one index build uses for every record.
struct BuildScope<'a> {
    view: &'a mneme_memory::View,
    request: &'a crate::model::Request,
    sources: &'a SourceStates,
    entities: &'a std::collections::BTreeMap<mneme_core::RecordId, String>,
}

/// Build a fresh index for the request's temporal selection.
#[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
pub(crate) fn build_index(
    view: &mneme_memory::View,
    request: &crate::model::Request,
    sources: &SourceStates,
    budget: &mut crate::engine::WorkBudget,
) -> BuildResult<crate::model::CachedIndex> {
    budget.check()?;
    let entities = entity_labels(view, request, budget)?;
    let scope = BuildScope {
        view,
        request,
        sources,
        entities: &entities,
    };
    let mut index = IndexBuild::default();
    for record in &view.snapshot().records {
        if !record_visible(request, &record.scope) {
            continue;
        }
        budget.charge(1)?;
        index.add_record(&scope, record, budget)?;
    }
    for assertion in selected_assertions(view, request, budget)? {
        budget.charge(1)?;
        index.add_assertion(&scope, &assertion, budget)?;
    }
    Ok(index.finish(view.revision()))
}

/// Whether the caller's authorization and flags make records in `scope`
/// readable. The kernel owns the rule.
fn record_visible(request: &crate::model::Request, scope: &mneme_core::ScopeId) -> bool {
    mneme_kernel::isolation::record_visible(&mneme_kernel::isolation::VisibilityFacts {
        same_scope: scope == &request.scope,
        record_class: scope.class().to_kernel(),
        include_hypothetical: request.include_hypothetical,
        record_scope_authorized: request.access.allows(scope),
    })
}

/// A record identity naming a record this request may read, or nothing.
fn readable_record(
    scope: &BuildScope<'_>,
    record: mneme_core::RecordId,
) -> Option<mneme_core::RecordId> {
    let envelope = scope.view.record(record).ok()?;
    if record_visible(scope.request, &envelope.scope) {
        Some(record)
    } else {
        None
    }
}

#[derive(Default)]
struct IndexBuild {
    documents: Vec<crate::model::IndexedDocument>,
    skipped: usize,
    skip_reasons: std::collections::BTreeSet<String>,
}

/// A source record's bytes and availability as recall may use them.
struct SourceFacts {
    view: mneme_memory::SourceView,
    availability: mneme_memory::SourceAvailability,
    bytes: Option<Vec<u8>>,
}

impl IndexBuild {
    fn add_record(
        &mut self,
        scope: &BuildScope<'_>,
        record: &mneme_core::RecordEnvelope,
        budget: &mut crate::engine::WorkBudget,
    ) -> BuildResult<()> {
        match record.kind {
            mneme_core::RecordKind::Entity => self.add_entity(scope, record),
            mneme_core::RecordKind::Episode => self.add_episode(scope, record)?,
            mneme_core::RecordKind::SourceRevision => self.add_source(scope, record, budget)?,
            _ => {}
        }
        Ok(())
    }

    fn add_entity(&mut self, scope: &BuildScope<'_>, record: &mneme_core::RecordEnvelope) {
        let label = scope
            .entities
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
        self.documents.push(document(IndexedDocumentInput {
            id: format!("entity:{}", record.record_id),
            kind: crate::model::ContentKind::TypedField,
            text: body,
            field_path: "entity.label".to_owned(),
            source: None,
            source_revision: None,
            span: None,
            assertion: None,
            episode: None,
            entity: Some(record.record_id),
            claim_status: None,
            evidence: Vec::new(),
            ancestry_roots: std::collections::BTreeSet::new(),
        }));
    }

    fn add_episode(
        &mut self,
        scope: &BuildScope<'_>,
        record: &mneme_core::RecordEnvelope,
    ) -> BuildResult<()> {
        let episode = mneme_memory::EpisodeView::parse(record.clone())?;
        let body = format!(
            "{} {} {}",
            episode.summary,
            episode.actor,
            episode.episode_type.name()
        );
        // The memory engine treats an episode's source revision as its root, so
        // an episode and its own source never count as independent evidence.
        let resolved = episode
            .source
            .and_then(|source| readable_source(scope, source));
        let root = resolved.unwrap_or((record.record_id, record.revision_id));
        self.documents.push(document(IndexedDocumentInput {
            id: format!("episode:{}", record.record_id),
            kind: crate::model::ContentKind::EpisodeSummary,
            text: body,
            field_path: "episode.summary".to_owned(),
            source: resolved.map(|key| key.0),
            source_revision: resolved.map(|key| key.1),
            span: None,
            assertion: None,
            episode: Some(record.record_id),
            entity: None,
            claim_status: None,
            evidence: Vec::new(),
            ancestry_roots: std::collections::BTreeSet::from([root]),
        }));
        Ok(())
    }

    fn add_source(
        &mut self,
        scope: &BuildScope<'_>,
        record: &mneme_core::RecordEnvelope,
        budget: &mut crate::engine::WorkBudget,
    ) -> BuildResult<()> {
        let facts = source_facts(scope.view, record, scope.sources, budget)?;
        let key = (record.record_id, record.revision_id);
        if let Some(path) = &facts.view.path_hint {
            self.documents.push(document(IndexedDocumentInput {
                id: format!("source-path:{}:{}", record.record_id, record.revision_id),
                kind: crate::model::ContentKind::TypedField,
                text: path.clone(),
                field_path: "source.path-hint".to_owned(),
                source: Some(record.record_id),
                source_revision: Some(record.revision_id),
                span: None,
                assertion: None,
                episode: None,
                entity: facts.view.entity,
                claim_status: None,
                evidence: Vec::new(),
                ancestry_roots: std::collections::BTreeSet::from([key]),
            }));
        }
        match facts.bytes {
            Some(bytes) => match String::from_utf8(bytes) {
                Ok(body) => {
                    let content = IndexedDocumentInput {
                        id: format!("source:{}:{}", record.record_id, record.revision_id),
                        kind: crate::model::ContentKind::SourceExcerpt,
                        text: body,
                        field_path: "source.content".to_owned(),
                        source: Some(record.record_id),
                        source_revision: Some(record.revision_id),
                        span: None,
                        assertion: None,
                        episode: None,
                        entity: facts.view.entity,
                        claim_status: None,
                        evidence: Vec::new(),
                        ancestry_roots: std::collections::BTreeSet::from([key]),
                    };
                    self.documents.push(document(content));
                }
                Err(_) => {
                    self.skipped += 1;
                    self.skip_reasons
                        .insert("source bytes are not UTF-8 text".to_owned());
                }
            },
            None => {
                self.skipped += 1;
                self.skip_reasons.insert(format!(
                    "source is {} and has no searchable bytes",
                    facts.availability.name()
                ));
            }
        }
        Ok(())
    }

    fn add_assertion(
        &mut self,
        scope: &BuildScope<'_>,
        assertion: &mneme_memory::AssertionView,
        budget: &mut crate::engine::WorkBudget,
    ) -> BuildResult<()> {
        let status = crate::model::ClaimStatus::from_assertion(assertion);
        let evidence = evidence_refs(scope, assertion, budget)?;
        let subject = scope
            .entities
            .get(&assertion.subject)
            .cloned()
            .or_else(|| readable_record(scope, assertion.subject).map(mneme_core::RecordId::to_hex))
            // A subject outside the readable scopes is named by nothing: the
            // claim stays retrievable without leaking a foreign identifier.
            .unwrap_or_else(|| "unlabeled-subject".to_owned());
        let body = format!(
            "{} {} {} {}",
            assertion.predicate,
            mneme_core::text::render(&assertion.value),
            subject,
            assertion.asserted_by
        );
        self.documents.push(document(IndexedDocumentInput {
            id: format!("assertion:{}", assertion.record.record_id),
            kind: crate::model::ContentKind::Claim,
            text: body,
            field_path: format!("assertion.{}", assertion.predicate),
            source: None,
            source_revision: None,
            span: None,
            assertion: Some(assertion.record.record_id),
            episode: None,
            entity: readable_record(scope, assertion.subject),
            claim_status: Some(status),
            evidence,
            // A claim's deduplicated roots come from one bounded support walk
            // over the ranked candidates, never from the whole index.
            ancestry_roots: std::collections::BTreeSet::new(),
        }));
        Ok(())
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
        crate::model::CachedIndex::new(revision, coverage, self.documents)
    }
}

/// The pinned revision of one source record, when the caller may read it.
fn readable_source(
    scope: &BuildScope<'_>,
    source: mneme_core::RecordId,
) -> Option<(mneme_core::RecordId, mneme_core::RevisionId)> {
    let record = scope.view.record(source).ok()?;
    if record_visible(scope.request, &record.scope) {
        Some((source, record.revision_id))
    } else {
        None
    }
}

/// The availability in force now for a pinned source revision.
///
/// A later pruning or erasure of the same source governs every older revision:
/// blob presence is never eligibility.
fn effective_availability(
    view: &mneme_memory::View,
    source: &mneme_memory::SourceView,
    states: &SourceStates,
) -> mneme_memory::SourceAvailability {
    if let Some(current) = states.get(&source.record.record_id)
        && *current != mneme_memory::SourceAvailability::Retained
    {
        return current.clone();
    }
    if view.suppression_for(&source.record).is_some() {
        return if source.availability == mneme_memory::SourceAvailability::Retained {
            mneme_memory::SourceAvailability::Pruned
        } else {
            source.availability.clone()
        };
    }
    source.availability.clone()
}

/// Read one source record's bytes if, and only if, they are still eligible.
fn source_facts(
    view: &mneme_memory::View,
    record: &mneme_core::RecordEnvelope,
    states: &SourceStates,
    budget: &mut crate::engine::WorkBudget,
) -> BuildResult<SourceFacts> {
    budget.charge(1)?;
    let source = view.source(record.record_id)?;
    let declared = effective_availability(view, &source, states);
    let (availability, bytes) = if declared == mneme_memory::SourceAvailability::Retained {
        match view.source_status_for(&source) {
            Ok(mneme_memory::SourceStatus::Retained(bytes)) => {
                (mneme_memory::SourceAvailability::Retained, Some(bytes))
            }
            Ok(other) => (other.availability(), None),
            Err(_) => (
                mneme_memory::SourceAvailability::Unavailable {
                    reason: "source could not be read".to_owned(),
                },
                None,
            ),
        }
    } else {
        (declared, None)
    };
    Ok(SourceFacts {
        view: source,
        availability,
        bytes,
    })
}

fn selected_assertions(
    view: &mneme_memory::View,
    request: &crate::model::Request,
    budget: &mut crate::engine::WorkBudget,
) -> BuildResult<Vec<mneme_memory::AssertionView>> {
    budget.check()?;
    match request.temporal {
        crate::model::TemporalMode::Current => {
            let beliefs = view.current_beliefs(&mneme_memory::BeliefView {
                scope: request.scope.clone(),
                at: request.at,
                include_hypothetical: request.include_hypothetical,
                include_disputed: request.include_disputed,
            })?;
            let mut selected = Vec::with_capacity(beliefs.len());
            for assertion in beliefs {
                budget.charge(1)?;
                if record_visible(request, &assertion.record.scope) {
                    selected.push(assertion);
                }
            }
            Ok(selected)
        }
        crate::model::TemporalMode::Historical => {
            let retained = visible_assertions(view, request, budget)?;
            Ok(retained
                .into_iter()
                .filter(|assertion| assertion.lifecycle != mneme_core::Lifecycle::Proposed)
                .collect())
        }
        crate::model::TemporalMode::Inspection => visible_assertions(view, request, budget),
    }
}

fn visible_assertions(
    view: &mneme_memory::View,
    request: &crate::model::Request,
    budget: &mut crate::engine::WorkBudget,
) -> BuildResult<Vec<mneme_memory::AssertionView>> {
    let assertions = view.assertions()?;
    let mut visible = Vec::with_capacity(assertions.len());
    for assertion in assertions {
        budget.charge(1)?;
        if record_visible(request, &assertion.record.scope) {
            visible.push(assertion);
        }
    }
    Ok(visible)
}

fn entity_labels(
    view: &mneme_memory::View,
    request: &crate::model::Request,
    budget: &mut crate::engine::WorkBudget,
) -> BuildResult<std::collections::BTreeMap<mneme_core::RecordId, String>> {
    let records = &view.snapshot().records;
    // One label per record, so the snapshot's own length bounds the map.
    let max_labels = records.len();
    let mut labels = std::collections::BTreeMap::new();
    for record in records {
        if labels.len() >= max_labels {
            break;
        }
        if record.kind != mneme_core::RecordKind::Entity {
            continue;
        }
        if !record_visible(request, &record.scope) {
            continue;
        }
        budget.charge(1)?;
        if let Some(label) = record
            .payload
            .get("label")
            .and_then(mneme_core::Value::as_string)
        {
            labels.insert(record.record_id, label.to_owned());
        }
    }
    Ok(labels)
}

/// Evidence attribution for one claim.
///
/// A challenge or a withdrawn record stays visible as attribution but grounds
/// nothing: only readable `Supports` records reach the candidate's ancestry.
fn evidence_refs(
    scope: &BuildScope<'_>,
    assertion: &mneme_memory::AssertionView,
    budget: &mut crate::engine::WorkBudget,
) -> BuildResult<Vec<crate::model::Evidence>> {
    let mut refs = Vec::with_capacity(assertion.evidence.len());
    for evidence_id in &assertion.evidence {
        budget.charge(1)?;
        let Ok(evidence) = scope.view.evidence(*evidence_id) else {
            continue;
        };
        if evidence.assertion != assertion.record.record_id {
            continue;
        }
        if !record_visible(scope.request, &evidence.record.scope) {
            continue;
        }
        let Ok(source_record) = scope.view.record(evidence.source) else {
            continue;
        };
        if !record_visible(scope.request, &source_record.scope) {
            continue;
        }
        let source_revision = match evidence.source_reference {
            mneme_core::Reference::Pinned { revision, .. } => revision,
            _ => source_record.revision_id,
        };
        refs.push(crate::model::Evidence {
            evidence: *evidence_id,
            source: evidence.source,
            source_revision: Some(source_revision),
            span: evidence.span,
            availability: evidence_availability(
                scope.view,
                evidence.source,
                source_revision,
                scope.sources,
            ),
            relation: evidence.relation,
            withdrawn: is_withdrawn(scope.view, &evidence.record),
            // The support walk over a ranked claim raises this flag; an index
            // that has not walked the citation claims nothing about it. In
            // particular a citation that declares ancestry does not root at the
            // source it restates.
            eligible: false,
            ancestry_roots: std::collections::BTreeSet::new(),
        });
    }
    Ok(refs)
}

/// Whether a withdrawal suppression covers this record.
fn is_withdrawn(view: &mneme_memory::View, record: &mneme_core::RecordEnvelope) -> bool {
    view.suppression_for(record)
        .map(|suppression| suppression.mode == mneme_store::SuppressionMode::Withdrawn)
        .unwrap_or(false)
}

/// The availability a pinned evidence citation is judged by now.
fn evidence_availability(
    view: &mneme_memory::View,
    source: mneme_core::RecordId,
    revision: mneme_core::RevisionId,
    states: &SourceStates,
) -> mneme_memory::SourceAvailability {
    if let Some(current) = states.get(&source)
        && *current != mneme_memory::SourceAvailability::Retained
    {
        return current.clone();
    }
    match view.source_at(source, revision) {
        Ok(source_view) => effective_availability(view, &source_view, states),
        Err(_) => mneme_memory::SourceAvailability::Unavailable {
            reason: "source revision is unavailable".to_owned(),
        },
    }
}

struct IndexedDocumentInput {
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
    evidence: Vec<crate::model::Evidence>,
    ancestry_roots: std::collections::BTreeSet<(mneme_core::RecordId, mneme_core::RevisionId)>,
}

fn document(input: IndexedDocumentInput) -> crate::model::IndexedDocument {
    let IndexedDocumentInput {
        id,
        kind,
        text,
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
    } = input;
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
///
/// The window is a fixed three-character ring, so profiling one document never
/// allocates per character.
pub(crate) fn trigram_counts(text: &str) -> std::collections::BTreeMap<u64, u32> {
    let mut counts = std::collections::BTreeMap::new();
    let mut window = ['\0'; 3];
    let mut filled = 0_usize;
    let mut total = 0_usize;
    for character in text.chars() {
        total = total.saturating_add(1);
        if filled == 3 {
            window.rotate_left(1);
            window[2] = character;
        } else {
            window[filled] = character;
            filled = filled.saturating_add(1);
        }
        if filled == 3 {
            bump(&mut counts, fnv(&window));
        }
    }
    if total > 0 && total < 3 {
        bump(&mut counts, fnv(&window[..filled]));
    }
    counts
}

fn bump(counts: &mut std::collections::BTreeMap<u64, u32>, hash: u64) {
    let entry = counts.entry(hash).or_insert(0);
    *entry = entry.saturating_add(1);
}

fn fnv(characters: &[char]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    let mut buffer = [0_u8; 4];
    for character in characters {
        for byte in character.encode_utf8(&mut buffer).as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    hash
}

/// One exact source excerpt.
pub(crate) struct Excerpt {
    pub(crate) text: String,
    pub(crate) span: mneme_core::SourceSpan,
    pub(crate) truncated: bool,
}

/// Find an exact source excerpt around the query and return its inclusive span.
///
/// The window is taken from the kernel, so it always lies inside the text, a
/// huge limit cannot overflow, and the caller learns that the text was cut.
pub(crate) fn source_excerpt(text: &str, query: &str, max_quote_bytes: usize) -> Option<Excerpt> {
    if text.is_empty() || max_quote_bytes == 0 {
        return None;
    }
    let text_len = u64::try_from(text.len()).ok()?;
    // A ranked document whose exact query text is not a byte substring (a
    // non-ASCII case fold, for example) still quotes from its first character
    // rather than disappearing from the answer.
    let matched = match_position(text, query).unwrap_or(0);
    let start = mneme_kernel::extent::floor_boundary(text.as_bytes(), matched);
    let start = u64::try_from(start).ok()?;
    let max_bytes = u64::try_from(max_quote_bytes).ok()?;
    let window = mneme_kernel::extent::excerpt_window(&mneme_kernel::extent::ExcerptRequest {
        start,
        stop: text_len,
        text_len,
        max_bytes,
    })?;
    let stop =
        mneme_kernel::extent::floor_boundary(text.as_bytes(), usize::try_from(window.stop).ok()?);
    let stop = u64::try_from(stop).ok()?;
    if mneme_kernel::extent::span_length(start, stop)? == 0 {
        return None;
    }
    let quote = text
        .get(usize::try_from(start).ok()?..usize::try_from(stop).ok()?)?
        .to_owned();
    Some(Excerpt {
        text: quote,
        span: mneme_core::SourceSpan::new(start, stop.checked_sub(1)?).ok()?,
        truncated: window.truncated,
    })
}

/// Where the query, or failing that its first term, appears in the text.
fn match_position(text: &str, query: &str) -> Option<usize> {
    if !query.is_empty()
        && let Some(position) = find_ascii_case_insensitive(text, query)
    {
        return Some(position);
    }
    tokenize(&query.to_lowercase())
        .into_iter()
        .find_map(|term| find_ascii_case_insensitive(text, &term))
}

/// Find a case-insensitive byte match in one pass.
///
/// A naive window comparison is `O(text × query)`; the failure table makes this
/// search linear in the text length, so an attacker-sized document cannot pin a
/// worker per query term.
fn find_ascii_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    let needle = needle.as_bytes();
    if needle.is_empty() {
        return None;
    }
    let lowered = needle
        .iter()
        .map(u8::to_ascii_lowercase)
        .collect::<Vec<u8>>();
    let mut fallback = vec![0_usize; lowered.len()];
    let mut matched = 0_usize;
    for index in 1..lowered.len() {
        while matched > 0 && lowered[index] != lowered[matched] {
            matched = fallback[matched - 1];
        }
        if lowered[index] == lowered[matched] {
            matched = matched.saturating_add(1);
        }
        fallback[index] = matched;
    }
    let mut matched = 0_usize;
    for (index, byte) in haystack.as_bytes().iter().enumerate() {
        let byte = byte.to_ascii_lowercase();
        while matched > 0 && byte != lowered[matched] {
            matched = fallback[matched - 1];
        }
        if byte == lowered[matched] {
            matched = matched.saturating_add(1);
            if matched == lowered.len() {
                return Some(index.saturating_add(1).saturating_sub(lowered.len()));
            }
        }
    }
    None
}
