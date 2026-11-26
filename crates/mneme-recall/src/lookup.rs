//! In-memory lexical and local token-vector index over one scoped snapshot.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// Index schema, term and weighting version: English Snowball stems with
/// camelCase/snake_case symbol sub-tokenization across four typed fields,
/// weighted by pre-saturation BM25F over the request's own index.
pub const LEXICAL_INDEX_VERSION: &str = "mneme-lexical-bm25f-v3";
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
    media_locations:
        &'a std::collections::BTreeMap<mneme_core::SourcePin, Vec<crate::model::MediaCitation>>,
    /// Recognized texts not selected for their part of a capture: kept in
    /// history and in inspection recall, never searched as primary text.
    unselected_texts: &'a std::collections::BTreeSet<mneme_core::RecordId>,
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
    let (media_locations, skipped_locations) =
        recognition_media_locations(view, request, sources, budget)?;
    let unselected_texts = match request.temporal {
        crate::model::TemporalMode::Current | crate::model::TemporalMode::Historical => {
            // Selection reads each recognition run once; charge for it first.
            for record in &view.snapshot().records {
                if record.kind == mneme_core::RecordKind::RecognitionRun {
                    budget.charge(1)?;
                }
            }
            view.unselected_recognized_texts()
        }
        crate::model::TemporalMode::Inspection => std::collections::BTreeSet::new(),
    };
    let scope = BuildScope {
        view,
        request,
        sources,
        entities: &entities,
        media_locations: &media_locations,
        unselected_texts: &unselected_texts,
    };
    let mut index = IndexBuild {
        skipped: skipped_locations,
        skip_reasons: if skipped_locations == 0 {
            std::collections::BTreeSet::new()
        } else {
            std::collections::BTreeSet::from(["some recognition media locations were unavailable or exceeded the per-source bound".to_owned()])
        },
        ..IndexBuild::default()
    };
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

const MAX_MEDIA_LOCATIONS_PER_SOURCE: usize = 4096;

fn recognition_media_locations(
    view: &mneme_memory::View,
    request: &crate::model::Request,
    sources: &SourceStates,
    budget: &mut crate::engine::WorkBudget,
) -> BuildResult<(
    std::collections::BTreeMap<mneme_core::SourcePin, Vec<crate::model::MediaCitation>>,
    usize,
)> {
    let mut locations = std::collections::BTreeMap::new();
    let mut skipped = 0_usize;
    let mut resolvable = std::collections::BTreeMap::new();
    for record in &view.snapshot().records {
        if record.kind != mneme_core::RecordKind::RecognitionSegment {
            continue;
        }
        budget.charge(1)?;
        if !record_visible(request, &record.scope) || view.suppression_for(record).is_some() {
            continue;
        }
        let Ok(segment) = mneme_memory::RecognitionSegmentView::parse(record.clone()) else {
            skipped = skipped.saturating_add(1);
            continue;
        };
        let Ok(media_record) = view.record(segment.media_source.source()) else {
            skipped = skipped.saturating_add(1);
            continue;
        };
        if !record_visible(request, &media_record.scope) {
            continue;
        }
        let Ok(media) = view.source_at(
            segment.media_source.source(),
            segment.media_source.revision(),
        ) else {
            skipped = skipped.saturating_add(1);
            continue;
        };
        if media.digest().or(media.prior_digest) != Some(segment.media_digest)
            || !has_ancestry(view, segment.text_source, &mut resolvable, budget)?
            || !has_ancestry(view, segment.media_source, &mut resolvable, budget)?
        {
            skipped = skipped.saturating_add(1);
            continue;
        }
        let items = locations
            .entry(segment.text_source)
            .or_insert_with(Vec::new);
        if items.len() >= MAX_MEDIA_LOCATIONS_PER_SOURCE {
            skipped = skipped.saturating_add(1);
            continue;
        }
        items.push(crate::model::MediaCitation {
            segment: record.record_id,
            segment_revision: record.revision_id,
            text_span: segment.text_span,
            media_source: segment.media_source,
            media_digest: segment.media_digest,
            availability: effective_availability(view, &media, sources),
            location: segment.location,
        });
    }
    Ok((locations, skipped))
}

/// Whether `pin`'s ancestry resolves, walking each pin once and charging the
/// walk to the build budget.
fn has_ancestry(
    view: &mneme_memory::View,
    pin: mneme_core::SourcePin,
    resolvable: &mut std::collections::BTreeMap<mneme_core::SourcePin, bool>,
    budget: &mut crate::engine::WorkBudget,
) -> BuildResult<bool> {
    if let Some(known) = resolvable.get(&pin) {
        return Ok(*known);
    }
    budget.charge(1)?;
    let is_resolvable = view.source_roots(pin).is_ok();
    resolvable.insert(pin, is_resolvable);
    Ok(is_resolvable)
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
    content_omission: Option<&'static str>,
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
        let fields = DocumentFields {
            title_or_label: vec![label],
            heading_or_symbol: Vec::new(),
            body_or_value: Vec::new(),
            metadata: vec![entity_type, properties],
        };
        self.documents.push(document(IndexedDocumentInput {
            id: format!("entity:{}", record.record_id),
            kind: crate::model::ContentKind::TypedField,
            text: body,
            normalized: None,
            fields,
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
            media_locations: Vec::new(),
        }));
    }

    fn add_episode(
        &mut self,
        scope: &BuildScope<'_>,
        record: &mneme_core::RecordEnvelope,
    ) -> BuildResult<()> {
        let episode = mneme_memory::EpisodeView::parse(record.clone())?;
        let episode_kind = episode.episode_type.name().to_owned();
        let body = format!("{} {} {}", episode.summary, episode.actor, episode_kind);
        // The memory engine treats an episode's source revision as its root, so
        // an episode and its own source never count as independent evidence.
        // A source the caller cannot read leaves the episode as its own root.
        let readable = episode
            .source
            .and_then(|source| readable_source(scope, source));
        let resolved = readable.and_then(|key| {
            let roots = scope
                .view
                .source_roots(mneme_core::SourcePin::new(key.0, key.1))
                .ok()?;
            let root = roots.iter().next().copied()?;
            Some((key, root))
        });
        if readable.is_some() && resolved.is_none() {
            self.skipped = self.skipped.saturating_add(1);
            self.skip_reasons
                .insert("episode source ancestry is unavailable".to_owned());
            return Ok(());
        }
        let root = resolved.map_or((record.record_id, record.revision_id), |(_, root)| root);
        let source = resolved.map(|(key, _)| key);
        let fields = DocumentFields {
            title_or_label: Vec::new(),
            heading_or_symbol: Vec::new(),
            body_or_value: vec![episode.summary],
            metadata: vec![episode.actor, episode_kind],
        };
        self.documents.push(document(IndexedDocumentInput {
            id: format!("episode:{}", record.record_id),
            kind: crate::model::ContentKind::EpisodeSummary,
            text: body,
            normalized: None,
            fields,
            field_path: "episode.summary".to_owned(),
            source: source.map(|key| key.0),
            source_revision: source.map(|key| key.1),
            span: None,
            assertion: None,
            episode: Some(record.record_id),
            entity: None,
            claim_status: None,
            evidence: Vec::new(),
            ancestry_roots: std::collections::BTreeSet::from([root]),
            media_locations: Vec::new(),
        }));
        Ok(())
    }

    fn add_source(
        &mut self,
        scope: &BuildScope<'_>,
        record: &mneme_core::RecordEnvelope,
        budget: &mut crate::engine::WorkBudget,
    ) -> BuildResult<()> {
        if scope.unselected_texts.contains(&record.record_id) {
            return Ok(());
        }
        let facts = source_facts(scope.view, record, scope.sources, budget)?;
        let key = (record.record_id, record.revision_id);
        let roots = match scope
            .view
            .source_roots(mneme_core::SourcePin::new(key.0, key.1))
        {
            Ok(roots) => roots,
            Err(_) => {
                self.skipped = self.skipped.saturating_add(1);
                self.skip_reasons
                    .insert("source transformation ancestry is unavailable".to_owned());
                return Ok(());
            }
        };
        let is_retained = facts.availability == mneme_memory::SourceAvailability::Retained;
        if let Some(reason) = facts.content_omission {
            if is_retained && let Some(path) = &facts.view.path_hint {
                self.push_source_path_document(record, path, facts.view.entity, &roots);
            }
            self.skipped += 1;
            self.skip_reasons.insert(reason.to_owned());
            return Ok(());
        }
        match facts.bytes {
            Some(bytes) => match String::from_utf8(bytes) {
                Ok(body) => {
                    if body.is_empty()
                        && let Some(path) = &facts.view.path_hint
                    {
                        self.push_source_path_document(record, path, facts.view.entity, &roots);
                        return Ok(());
                    }
                    let fields = extract_source_fields(
                        facts.view.path_hint.as_deref(),
                        facts
                            .view
                            .media_type
                            .as_ref()
                            .map(mneme_core::Symbol::as_str),
                        &body,
                    );
                    let normalized =
                        facts.view.path_hint.as_deref().map(|path| {
                            format!("{}\n{}", path.to_lowercase(), body.to_lowercase())
                        });
                    let content = IndexedDocumentInput {
                        id: format!("source:{}:{}", record.record_id, record.revision_id),
                        kind: crate::model::ContentKind::SourceExcerpt,
                        text: body,
                        normalized,
                        fields,
                        field_path: "source.content".to_owned(),
                        source: Some(record.record_id),
                        source_revision: Some(record.revision_id),
                        span: None,
                        assertion: None,
                        episode: None,
                        entity: facts.view.entity,
                        claim_status: None,
                        evidence: Vec::new(),
                        ancestry_roots: roots,
                        media_locations: scope
                            .media_locations
                            .get(&mneme_core::SourcePin::new(key.0, key.1))
                            .cloned()
                            .unwrap_or_default(),
                    };
                    self.documents.push(document(content));
                }
                Err(_) => {
                    if is_retained && let Some(path) = &facts.view.path_hint {
                        self.push_source_path_document(record, path, facts.view.entity, &roots);
                    }
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

    fn push_source_path_document(
        &mut self,
        record: &mneme_core::RecordEnvelope,
        path: &str,
        entity: Option<mneme_core::RecordId>,
        roots: &std::collections::BTreeSet<(mneme_core::RecordId, mneme_core::RevisionId)>,
    ) {
        let fields = DocumentFields {
            title_or_label: vec![path.to_owned()],
            heading_or_symbol: Vec::new(),
            body_or_value: Vec::new(),
            metadata: Vec::new(),
        };
        self.documents.push(document(IndexedDocumentInput {
            id: format!("source-path:{}:{}", record.record_id, record.revision_id),
            kind: crate::model::ContentKind::TypedField,
            text: path.to_owned(),
            normalized: None,
            fields,
            field_path: "source.path-hint".to_owned(),
            source: Some(record.record_id),
            source_revision: Some(record.revision_id),
            span: None,
            assertion: None,
            episode: None,
            entity,
            claim_status: None,
            evidence: Vec::new(),
            ancestry_roots: roots.clone(),
            media_locations: Vec::new(),
        }));
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
        let value_text = mneme_core::text::render(&assertion.value);
        let body = format!(
            "{} {} {} {}",
            assertion.predicate, value_text, subject, assertion.asserted_by
        );
        let fields = DocumentFields {
            title_or_label: vec![subject],
            heading_or_symbol: vec![assertion.predicate.clone()],
            body_or_value: vec![value_text],
            metadata: vec![assertion.asserted_by.clone()],
        };
        self.documents.push(document(IndexedDocumentInput {
            id: format!("assertion:{}", assertion.record.record_id),
            kind: crate::model::ContentKind::Claim,
            text: body,
            normalized: None,
            fields,
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
            media_locations: Vec::new(),
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

/// Read bytes only for an eligible source whose content enters the index.
fn source_facts(
    view: &mneme_memory::View,
    record: &mneme_core::RecordEnvelope,
    states: &SourceStates,
    budget: &mut crate::engine::WorkBudget,
) -> BuildResult<SourceFacts> {
    budget.charge(1)?;
    let source = view.source(record.record_id)?;
    let content_omission = content_omission(&source);
    let declared = effective_availability(view, &source, states);
    let (availability, bytes) =
        if declared == mneme_memory::SourceAvailability::Retained && content_omission.is_none() {
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
        content_omission,
        bytes,
    })
}

/// MIME, not UTF-8 decodability, distinguishes PDF containers from prose.
fn content_omission(source: &mneme_memory::SourceView) -> Option<&'static str> {
    let media_type = source.media_type.as_ref()?.as_str();
    let base = media_type
        .split_once(';')
        .map_or(media_type, |(base, _)| base)
        .trim();
    if base.eq_ignore_ascii_case("application/pdf") {
        return Some("PDF original bytes are not searched; recognized text remains searchable");
    }
    base.split_once('/')
        .filter(|(kind, _)| kind.eq_ignore_ascii_case("image"))
        .map(|_| "image pixels are not searched; authored captions remain searchable text")
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

/// Maximum Markdown/AsciiDoc heading depth recognized for fielded indexing.
const MAX_HEADING_LEVEL: usize = 6;
/// Minimum run of `-` characters opening/closing an AsciiDoc listing block.
const ASCIIDOC_LISTING_DASHES: usize = 4;
/// Code declaration keywords whose immediately following identifier is indexed
/// in `HeadingOrSymbol`.
const CODE_DECLARATION_KEYWORDS: [&str; 13] = [
    "fn",
    "struct",
    "enum",
    "trait",
    "type",
    "const",
    "static",
    "mod",
    "def",
    "class",
    "function",
    "interface",
    "func",
];
/// File extensions where `# ` starts a comment rather than a Markdown heading.
const HASH_COMMENT_EXTENSIONS: [&str; 10] = [
    ".py", ".sh", ".bash", ".zsh", ".rb", ".yml", ".yaml", ".toml", ".nix", ".r",
];
/// File extensions recognized as source code for `HeadingOrSymbol` extraction.
const CODE_SOURCE_EXTENSIONS: [&str; 22] = [
    ".rs", ".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".java", ".c", ".h", ".cpp", ".cc", ".hpp",
    ".rb", ".swift", ".kt", ".cs", ".zig", ".lean", ".nix", ".sql", ".sh",
];
/// Minimum leading lowercase prefix length for a `lowerCamelCase` identifier
/// in plain prose to be treated as a code symbol (avoids brand names like
/// `iOS` / `eBay` while matching `parseHttpRequest`, `getUserId`, etc.).
const PROSE_LOWER_CAMEL_PREFIX: usize = 2;

#[derive(Default)]
struct DocumentFields {
    title_or_label: Vec<String>,
    heading_or_symbol: Vec<String>,
    body_or_value: Vec<String>,
    metadata: Vec<String>,
}

impl DocumentFields {
    fn into_field_terms(self) -> [crate::model::FieldTerms; crate::model::LEXICAL_FIELD_COUNT] {
        let stemmer = rust_stemmers::Stemmer::create(rust_stemmers::Algorithm::English);
        [
            field_terms_from_segments(&stemmer, &self.title_or_label),
            field_terms_from_segments(&stemmer, &self.heading_or_symbol),
            field_terms_from_segments(&stemmer, &self.body_or_value),
            field_terms_from_segments(&stemmer, &self.metadata),
        ]
    }
}

fn field_terms_from_segments(
    stemmer: &rust_stemmers::Stemmer,
    segments: &[String],
) -> crate::model::FieldTerms {
    let mut counts: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    let mut total = 0_usize;
    let mut terms = Vec::new();
    for segment in segments {
        terms.clear();
        collect_terms_with(stemmer, segment, &mut terms);
        for term in terms.drain(..) {
            let entry = counts.entry(term).or_insert(0);
            *entry = entry.saturating_add(1);
            total = total.saturating_add(1);
        }
    }
    crate::model::FieldTerms { counts, total }
}

/// Extract typed BM25F fields from a retained UTF-8 source document.
///
/// Merges `path_hint` into `TitleOrLabel` alongside Markdown H1 / AsciiDoc
/// document titles, routes subheadings and code symbols into
/// `HeadingOrSymbol`, and places remaining content in `BodyOrValue`.
fn extract_source_fields(
    path_hint: Option<&str>,
    media_type: Option<&str>,
    body: &str,
) -> DocumentFields {
    let mut fields = DocumentFields::default();
    if let Some(path) = path_hint {
        fields.title_or_label.push(path.to_owned());
    }
    let allow_hash_headings = !is_hash_comment_source(media_type, path_hint);
    let is_code_file = is_code_source(media_type, path_hint);
    let mut fence = CodeBlockState::Outside;
    for line in body.lines() {
        let trimmed = line.trim_start();
        if let Some(next_fence) = next_code_block_state(fence, trimmed) {
            fence = next_fence;
            continue;
        }
        if fence == CodeBlockState::Outside {
            if allow_hash_headings && let Some((level, heading)) = parse_heading_line(trimmed, '#')
            {
                if level == 1 {
                    fields.title_or_label.push(heading.to_owned());
                } else {
                    fields.heading_or_symbol.push(heading.to_owned());
                }
                continue;
            }
            if let Some((level, heading)) = parse_heading_line(trimmed, '=') {
                if level == 1 {
                    fields.title_or_label.push(heading.to_owned());
                } else {
                    fields.heading_or_symbol.push(heading.to_owned());
                }
                continue;
            }
        }
        fields.body_or_value.push(line.to_owned());
        let context = if is_code_file || fence != CodeBlockState::Outside {
            SymbolContext::Code
        } else {
            SymbolContext::Prose
        };
        extract_code_symbols(line, context, &mut fields.heading_or_symbol);
    }
    fields
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SymbolContext {
    Code,
    Prose,
}

fn is_code_source(media_type: Option<&str>, path_hint: Option<&str>) -> bool {
    if let Some(media) = media_type {
        let base = media
            .split_once(';')
            .map_or(media, |(prefix, _)| prefix)
            .trim()
            .to_ascii_lowercase();
        if base.starts_with("text/x-")
            || base.contains("rust")
            || base.contains("python")
            || base.contains("javascript")
            || base.contains("typescript")
            || base.contains("shell")
        {
            return true;
        }
    }
    if let Some(path) = path_hint {
        let lower = path.to_ascii_lowercase();
        if CODE_SOURCE_EXTENSIONS
            .iter()
            .any(|ext| lower.ends_with(ext))
        {
            return true;
        }
    }
    false
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CodeBlockState {
    Outside,
    BacktickFence,
    TildeFence,
    AsciiDocListing,
}

fn next_code_block_state(current: CodeBlockState, trimmed: &str) -> Option<CodeBlockState> {
    if trimmed.starts_with("```") {
        return match current {
            CodeBlockState::Outside => Some(CodeBlockState::BacktickFence),
            CodeBlockState::BacktickFence => Some(CodeBlockState::Outside),
            CodeBlockState::TildeFence | CodeBlockState::AsciiDocListing => None,
        };
    }
    if trimmed.starts_with("~~~") {
        return match current {
            CodeBlockState::Outside => Some(CodeBlockState::TildeFence),
            CodeBlockState::TildeFence => Some(CodeBlockState::Outside),
            CodeBlockState::BacktickFence | CodeBlockState::AsciiDocListing => None,
        };
    }
    let clean = trimmed.trim_end();
    if clean.len() >= ASCIIDOC_LISTING_DASHES && clean.bytes().all(|byte| byte == b'-') {
        return match current {
            CodeBlockState::Outside => Some(CodeBlockState::AsciiDocListing),
            CodeBlockState::AsciiDocListing => Some(CodeBlockState::Outside),
            CodeBlockState::BacktickFence | CodeBlockState::TildeFence => None,
        };
    }
    None
}

fn is_hash_comment_source(media_type: Option<&str>, path_hint: Option<&str>) -> bool {
    if let Some(media) = media_type {
        let base = media
            .split_once(';')
            .map_or(media, |(prefix, _)| prefix)
            .trim()
            .to_ascii_lowercase();
        if base.contains("python")
            || base.contains("shell")
            || base.contains("yaml")
            || base.contains("toml")
            || base.contains("ruby")
        {
            return true;
        }
    }
    if let Some(path) = path_hint {
        let lower = path.to_ascii_lowercase();
        if HASH_COMMENT_EXTENSIONS
            .iter()
            .any(|ext| lower.ends_with(ext))
        {
            return true;
        }
    }
    false
}

fn parse_heading_line(trimmed: &str, marker: char) -> Option<(usize, &str)> {
    let level = trimmed.chars().take_while(|ch| *ch == marker).count();
    if level == 0 || level > MAX_HEADING_LEVEL {
        return None;
    }
    let after = trimmed.get(level * marker.len_utf8()..)?;
    if !after.starts_with(' ') && !after.starts_with('\t') {
        return None;
    }
    let heading = after.trim().trim_end_matches(marker).trim();
    if heading.is_empty() {
        return None;
    }
    Some((level, heading))
}

/// Extract code symbol identifiers into `HeadingOrSymbol`.
///
/// Inside code files, fenced code blocks, or inline backticks, every compound
/// camelCase/PascalCase/snake_case identifier (and every identifier after a
/// declaration keyword) is indexed as a symbol. In plain prose, `snake_case`,
/// `lowerCamelCase`, and declared identifiers are indexed without inflating
/// proper nouns such as `SQLite` or `GitHub`.
fn extract_code_symbols(line: &str, context: SymbolContext, out: &mut Vec<String>) {
    if context == SymbolContext::Code {
        extract_symbols_from_segment(line, SymbolContext::Code, out);
        return;
    }
    // Split on inline backticks so `` `PascalCaseSymbol` `` in prose gets full
    // code-symbol treatment while surrounding prose stays prose.
    let mut is_inline_code = false;
    for segment in line.split('`') {
        let seg_ctx = if is_inline_code {
            SymbolContext::Code
        } else {
            SymbolContext::Prose
        };
        extract_symbols_from_segment(segment, seg_ctx, out);
        is_inline_code = !is_inline_code;
    }
}

fn extract_symbols_from_segment(segment: &str, context: SymbolContext, out: &mut Vec<String>) {
    let mut after_decl = false;
    for raw in raw_identifier_tokens(segment) {
        let starts_ident = raw
            .chars()
            .next()
            .is_some_and(|ch| ch.is_alphabetic() || ch == '_');
        let has_alpha = raw.chars().any(char::is_alphabetic);
        if starts_ident && has_alpha {
            let subparts = split_identifier_subparts(raw);
            let is_symbol = if after_decl {
                true
            } else if subparts.len() > 1 {
                match context {
                    SymbolContext::Code => true,
                    SymbolContext::Prose => is_prose_code_symbol(raw, &subparts),
                }
            } else {
                false
            };
            if is_symbol {
                out.push(raw.to_owned());
            }
            after_decl = CODE_DECLARATION_KEYWORDS.contains(&raw);
        } else {
            after_decl = false;
        }
    }
}

fn is_prose_code_symbol(raw: &str, subparts: &[&str]) -> bool {
    if raw.contains('_') {
        return true;
    }
    subparts.first().is_some_and(|first| {
        first.chars().count() >= PROSE_LOWER_CAMEL_PREFIX
            && first
                .chars()
                .all(|ch| ch.is_lowercase() || ch.is_ascii_digit())
    })
}

struct IndexedDocumentInput {
    id: String,
    kind: crate::model::ContentKind,
    text: String,
    normalized: Option<String>,
    fields: DocumentFields,
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
    media_locations: Vec<crate::model::MediaCitation>,
}

fn document(input: IndexedDocumentInput) -> crate::model::IndexedDocument {
    let IndexedDocumentInput {
        id,
        kind,
        text,
        normalized,
        fields,
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
        media_locations,
    } = input;
    let normalized = normalized.unwrap_or_else(|| text.to_lowercase());
    let fields = fields.into_field_terms();
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
        fields,
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
        media_locations,
    }
}

/// The lexical terms of a text, in order and with repeats: each run of
/// alphanumeric characters (and underscores), with deterministic camelCase and
/// snake_case sub-tokenization, lowercased and reduced to English Snowball
/// stems. Documents and queries are both read this way, so "joined" and "join"
/// meet at "join", and `parseHttpRequest` / `parse_http_request` match both
/// their full symbol form and their component words.
pub fn lexical_terms(text: &str) -> Vec<String> {
    let stemmer = rust_stemmers::Stemmer::create(rust_stemmers::Algorithm::English);
    let mut terms = Vec::new();
    collect_terms_with(&stemmer, text, &mut terms);
    terms
}

fn collect_terms_with(stemmer: &rust_stemmers::Stemmer, text: &str, out: &mut Vec<String>) {
    for raw in raw_identifier_tokens(text) {
        let subparts = split_identifier_subparts(raw);
        if subparts.is_empty() {
            continue;
        }
        if subparts.len() == 1 {
            let lowered = subparts[0].to_lowercase();
            out.push(stemmer.stem(&lowered).into_owned());
            continue;
        }
        for part in subparts {
            let lowered = part.to_lowercase();
            out.push(stemmer.stem(&lowered).into_owned());
        }
        let whole = raw.trim_matches('_').to_lowercase();
        if !whole.is_empty() {
            if whole.contains('_') {
                out.push(whole);
            } else {
                out.push(stemmer.stem(&whole).into_owned());
            }
        }
    }
}

fn raw_identifier_tokens(text: &str) -> impl Iterator<Item = &str> {
    text.split(|character: char| !character.is_alphanumeric() && character != '_')
        .filter(|segment| !segment.is_empty())
}

fn split_identifier_subparts(raw: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    for segment in raw.split('_').filter(|part| !part.is_empty()) {
        split_camel_case_into(segment, &mut parts);
    }
    parts
}

fn split_camel_case_into<'a>(segment: &'a str, out: &mut Vec<&'a str>) {
    let chars: Vec<(usize, char)> = segment.char_indices().collect();
    if chars.is_empty() {
        return;
    }
    let mut start = 0_usize;
    for idx in 1..chars.len() {
        let prev = chars[idx - 1].1;
        let curr = chars[idx].1;
        let next = chars.get(idx + 1).map(|(_, ch)| *ch);
        let is_lower_or_digit_to_upper =
            (prev.is_lowercase() || prev.is_ascii_digit()) && curr.is_uppercase();
        let is_acronym_to_word =
            prev.is_uppercase() && curr.is_uppercase() && next.is_some_and(char::is_lowercase);
        if is_lower_or_digit_to_upper || is_acronym_to_word {
            let split_at = chars[idx].0;
            if split_at > start {
                out.push(&segment[start..split_at]);
                start = split_at;
            }
        }
    }
    if start < segment.len() {
        out.push(&segment[start..]);
    }
}

/// The distinct lowercase alphanumeric words of a text, unstemmed. Excerpt
/// placement searches the source for these surface forms.
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

#[cfg(test)]
mod lexical_term_tests {
    #[test]
    fn terms_are_lowercase_stems_in_order_with_repeats() {
        assert_eq!(
            super::lexical_terms("Joined the CHOIRS; joined again, 2023-05"),
            vec!["join", "the", "choir", "join", "again", "2023", "05"]
        );
        let stemmer = rust_stemmers::Stemmer::create(rust_stemmers::Algorithm::English);
        let terms =
            super::field_terms_from_segments(&stemmer, &["joined the choir joined".to_owned()]);
        assert_eq!(terms.counts.get("join"), Some(&2));
        assert_eq!(terms.total, 4);
    }

    #[test]
    fn camel_case_and_snake_case_symbols_sub_tokenize_deterministically() {
        assert_eq!(
            super::lexical_terms("parseHttpRequest"),
            vec!["pars", "http", "request", "parsehttprequest"]
        );
        assert_eq!(
            super::lexical_terms("HTTPServerConfig"),
            vec!["http", "server", "config", "httpserverconfig"]
        );
        assert_eq!(
            super::lexical_terms("parse_http_request"),
            vec!["pars", "http", "request", "parse_http_request"]
        );
        assert_eq!(
            super::lexical_terms("MAX_LEIDEN_ITERS"),
            vec!["max", "leiden", "iter", "max_leiden_iters"]
        );
    }

    #[test]
    fn source_field_extraction_separates_title_headings_symbols_and_body() {
        let doc = "# Sparse Routing\n\n## Kernel Notes\n\nfn parseHttpRequest(x: u32) {}\nPlain body text.\n";
        let fields =
            super::extract_source_fields(Some("docs/routing.md"), Some("text/markdown"), doc);
        assert_eq!(
            fields.title_or_label,
            vec!["docs/routing.md".to_owned(), "Sparse Routing".to_owned()]
        );
        assert!(fields.heading_or_symbol.iter().any(|s| s == "Kernel Notes"));
        assert!(
            fields
                .heading_or_symbol
                .iter()
                .any(|s| s == "parseHttpRequest")
        );
        assert!(
            fields
                .body_or_value
                .iter()
                .any(|line| line.contains("Plain body text."))
        );
    }
}
