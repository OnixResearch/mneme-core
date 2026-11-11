//! Recording and explanation services over the workspace coordinator.
//!
//! Builders construct typed drafts; [`Memory::commit`] validates evidence spans,
//! lifecycle decisions, ancestry, and action outcomes before submitting the
//! normal workspace command. No draft can promote a claim without an explicit
//! decision record in the same batch.
#![allow(path_segment_repetition)] // Octet structural exception: domain-qualified names and macro-only imports are intentional

/// A memory batch submitted through the workspace coordinator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryBatch {
    pub actor: String,
    pub scope: mneme_core::ScopeId,
    pub idempotency_key: String,
    pub records: Vec<mneme_store::RecordDraft>,
    pub source_blobs: Vec<mneme_store::SourceBlobDraft>,
    pub publications: Vec<mneme_store::PublicationDraft>,
}

/// The memory service over one mutable workspace handle.
pub struct Memory<'w> {
    workspace: &'w mut mneme_store::Workspace,
}

impl<'w> Memory<'w> {
    /// Wrap a workspace.
    pub fn new(workspace: &'w mut mneme_store::Workspace) -> Self {
        Memory { workspace }
    }

    /// The current pinned view.
    pub fn view(&self) -> crate::error::Result<crate::policy::MemoryView> {
        self.view_at(None)
    }

    /// A view fenced by an expected eligibility generation.
    pub fn view_at(
        &self,
        pinned_generation: Option<u64>,
    ) -> crate::error::Result<crate::policy::MemoryView> {
        let revision = self.workspace.current_revision()?;
        let snapshot = self.workspace.snapshot_at(revision, pinned_generation)?;
        let history = load_history(self.workspace, &snapshot)?;
        let sequences = self.workspace.revision_sequences()?;
        let suppressions = self.workspace.active_suppressions()?;
        Ok(crate::policy::MemoryView::with_retention(
            snapshot,
            self.workspace.root(),
            history,
            sequences,
            suppressions,
        ))
    }

    /// All retained revisions of one record.
    pub fn revisions(
        &self,
        record: mneme_core::RecordId,
    ) -> crate::error::Result<Vec<mneme_core::RecordEnvelope>> {
        Ok(self.workspace.record_revisions(record)?)
    }

    /// Explain one current assertion.
    pub fn explain(
        &self,
        assertion: mneme_core::RecordId,
        policy: crate::policy::Policy,
    ) -> crate::error::Result<crate::policy::Explanation> {
        self.explain_at(assertion, None, policy)
    }

    /// Explain one assertion under a pinned eligibility generation.
    pub fn explain_at(
        &self,
        assertion: mneme_core::RecordId,
        pinned_generation: Option<u64>,
        policy: crate::policy::Policy,
    ) -> crate::error::Result<crate::policy::Explanation> {
        self.view_at(pinned_generation)?.explain(assertion, policy)
    }

    /// Current beliefs under an explicit scope and effective-time policy.
    pub fn beliefs(
        &self,
        view: &crate::policy::BeliefView,
    ) -> crate::error::Result<Vec<crate::model::AssertionView>> {
        self.view()?.current_beliefs(view)
    }

    /// Conflicts among currently eligible claims.
    pub fn conflicts(
        &self,
        view: &crate::policy::BeliefView,
    ) -> crate::error::Result<Vec<crate::policy::ConflictGroup>> {
        self.view()?.conflicts(view)
    }

    /// Validate and commit a memory batch.
    pub fn commit(
        &mut self,
        batch: MemoryBatch,
    ) -> crate::error::Result<mneme_store::CommitOutcome> {
        let base = self.workspace.current_revision()?;
        self.commit_at_base(batch, base)
    }

    /// Validate and commit a memory batch against a caller-supplied base
    /// revision. The coordinator still applies its compare-and-swap and
    /// idempotency rules.
    pub fn commit_at_base(
        &mut self,
        batch: MemoryBatch,
        base: mneme_core::WorkspaceRevisionId,
    ) -> crate::error::Result<mneme_store::CommitOutcome> {
        let snapshot = self.workspace.snapshot()?;
        let history = load_history(self.workspace, &snapshot)?;
        let sequences = self.workspace.revision_sequences()?;
        let suppressions = self.workspace.active_suppressions()?;
        validate_batch(
            &snapshot,
            self.workspace.root(),
            &batch,
            &history,
            &sequences,
            &suppressions,
        )?;
        let outcome = self.workspace.commit(mneme_store::CommitCommand {
            base,
            actor: batch.actor,
            scope: batch.scope,
            idempotency_key: batch.idempotency_key,
            records: batch.records,
            source_blobs: batch.source_blobs,
            publications: batch.publications,
            import_candidates: Vec::new(),
            retention: None,
        })?;
        Ok(outcome)
    }
}

#[allow(unknown_lints, unbounded_collection_growth)] // Octet structural exception: cohesive state-machine code; split tracked separately
fn load_history(
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

#[allow(
    unknown_lints,
    function_length,
    too_many_parameters,
    unbounded_collection_growth
)] // Octet structural exception: cohesive state-machine code; split tracked separately
fn validate_batch(
    snapshot: &mneme_store::Snapshot,
    root: &std::path::Path,
    batch: &MemoryBatch,
    history: &std::collections::BTreeMap<
        (mneme_core::RecordId, mneme_core::RevisionId),
        mneme_core::RecordEnvelope,
    >,
    revision_sequences: &std::collections::BTreeMap<mneme_core::WorkspaceRevisionId, u64>,
    suppressions: &[mneme_store::RetentionSuppression],
) -> crate::error::Result<()> {
    let mut combined: std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RecordEnvelope> =
        snapshot
            .records
            .iter()
            .map(|record| (record.record_id, record.clone()))
            .collect();
    let mut supplied_sources: std::collections::BTreeMap<mneme_core::ContentDigest, Vec<u8>> =
        std::collections::BTreeMap::new();
    for source in &batch.source_blobs {
        supplied_sources.insert(source.digest(), source.bytes.clone());
    }
    for draft in &batch.records {
        let envelope = draft.clone().into_envelope(mneme_core::RecordedTime::new(
            mneme_core::Timestamp::from_nanos(0),
            0,
        ));
        if envelope.scope != batch.scope {
            return Err(crate::error::MemoryError::policy(format!(
                "record {} scope {} differs from batch scope {}",
                envelope.record_id, envelope.scope, batch.scope
            )));
        }
        combined.insert(envelope.record_id, envelope);
    }
    let mut index = mneme_core::SnapshotIndex::new();
    for record in combined.values() {
        index.insert(record.record_id, record.kind, record.revision_id);
    }
    let virtual_snapshot = mneme_store::Snapshot {
        revision: snapshot.revision,
        sequence: snapshot.sequence,
        parent: snapshot.parent,
        manifest_digest: snapshot.manifest_digest,
        eligibility_generation: snapshot.eligibility_generation,
        records: combined.values().cloned().collect(),
        index,
    };
    let view = crate::policy::MemoryView::with_retention(
        virtual_snapshot,
        root,
        history.clone(),
        revision_sequences.clone(),
        suppressions.to_vec(),
    );

    for draft in &batch.records {
        let envelope = draft.clone().into_envelope(mneme_core::RecordedTime::new(
            mneme_core::Timestamp::from_nanos(0),
            0,
        ));
        match envelope.kind {
            mneme_core::RecordKind::Evidence => {
                let evidence = crate::model::EvidenceView::parse(envelope.clone())?;
                if view.suppression_for(&envelope).is_some_and(|suppression| {
                    suppression.mode == mneme_store::SuppressionMode::Withdrawn
                }) {
                    return Err(crate::error::MemoryError::policy(format!(
                        "evidence {} is withdrawn and cannot be newly cited",
                        evidence.record.record_id
                    )));
                }
                let source = view.evidence_source(&evidence).map_err(|_| {
                    crate::error::MemoryError::policy(format!(
                        "evidence {} references missing source {}",
                        evidence.record.record_id, evidence.source
                    ))
                })?;
                if let mneme_core::Reference::Pinned { revision, .. } = evidence.source_reference
                    && revision != source.record.revision_id
                {
                    return Err(crate::error::MemoryError::policy(format!(
                        "evidence {} pins source revision {revision}, but the source record is {}",
                        evidence.record.record_id, source.record.revision_id
                    )));
                }
                let bytes = source_bytes(&source, &supplied_sources, root)?;
                if evidence.span.is_none() && evidence.anchor.is_none() {
                    return Err(crate::error::MemoryError::policy(
                        "evidence requires an exact span or a stable anchor",
                    ));
                }
                if let Some(span) = evidence.span
                    && span.end() >= bytes.len() as u64
                {
                    return Err(crate::error::MemoryError::policy(format!(
                        "evidence {} span ends at byte {} beyond {} retained bytes",
                        evidence.record.record_id,
                        span.end(),
                        bytes.len()
                    )));
                }
                if let Some(anchor) = &evidence.anchor
                    && anchor.trim().is_empty()
                {
                    return Err(crate::error::MemoryError::policy(
                        "evidence anchor must not be empty",
                    ));
                }
                for ancestor in &evidence.ancestry {
                    if !combined.contains_key(ancestor) {
                        return Err(crate::error::MemoryError::policy(format!(
                            "evidence {} ancestry names missing record {ancestor}",
                            evidence.record.record_id
                        )));
                    }
                }
                // Cycle detection over the combined evidence ancestry graph.
                view.evidence_roots(evidence.record.record_id)?;
            }
            mneme_core::RecordKind::Assertion => {
                let assertion = crate::model::AssertionView::parse(envelope.clone())?;
                for evidence_id in &assertion.evidence {
                    if let Ok(evidence_record) = view.envelope(*evidence_id)
                        && view
                            .suppression_for(evidence_record)
                            .is_some_and(|suppression| {
                                suppression.mode == mneme_store::SuppressionMode::Withdrawn
                            })
                    {
                        return Err(crate::error::MemoryError::policy(format!(
                            "assertion {} cites withdrawn evidence {evidence_id}",
                            assertion.record.record_id
                        )));
                    }
                }
                if !view.lifecycle_decision_valid(&assertion)? {
                    return Err(crate::error::MemoryError::policy(format!(
                        "assertion {} lifecycle {} lacks a matching decision",
                        assertion.record.record_id,
                        assertion.lifecycle.symbol()
                    )));
                }
                if assertion.origin == mneme_core::Origin::ModelExtraction
                    && assertion.extraction.is_none()
                {
                    return Err(crate::error::MemoryError::policy(format!(
                        "model-extracted assertion {} must retain extraction lineage",
                        assertion.record.record_id
                    )));
                }
                if assertion.predicate == crate::policy::ACTION_COMPLETED_PREDICATE
                    && !view.has_observed_outcome(&assertion)?
                {
                    return Err(crate::error::MemoryError::policy(format!(
                        "completed-action assertion {} has no observed outcome episode",
                        assertion.record.record_id
                    )));
                }
                if assertion.lifecycle == mneme_core::Lifecycle::Accepted
                    && assertion.stance == crate::model::Stance::Deny
                {
                    let is_complete = assertion
                        .record
                        .payload
                        .get("completeness")
                        .and_then(mneme_core::Value::as_symbol)
                        .map(|symbol| symbol.as_str() == "declared-complete")
                        .unwrap_or(false);
                    if !is_complete {
                        return Err(crate::error::MemoryError::policy(format!(
                            "accepted negative assertion {} lacks a declared-complete basis",
                            assertion.record.record_id
                        )));
                    }
                }
                for evidence in &assertion.evidence {
                    if !combined.contains_key(evidence) {
                        return Err(crate::error::MemoryError::policy(format!(
                            "assertion {} evidence reference {evidence} is missing",
                            assertion.record.record_id
                        )));
                    }
                }
            }
            mneme_core::RecordKind::Decision => {
                let decision = crate::model::DecisionView::parse(envelope.clone())?;
                if decision.actor.trim().is_empty() || decision.policy.trim().is_empty() {
                    return Err(crate::error::MemoryError::policy(
                        "decision actor and policy must be non-empty",
                    ));
                }
                if decision.input_revision != snapshot.revision {
                    return Err(crate::error::MemoryError::policy(format!(
                        "decision {} evaluates revision {}, not the current base {}",
                        decision.record.record_id, decision.input_revision, snapshot.revision
                    )));
                }
                let target = crate::model::AssertionView::parse(
                    combined
                        .get(&decision.target)
                        .ok_or(crate::error::MemoryError::policy(format!(
                            "decision {} targets missing assertion {}",
                            decision.record.record_id, decision.target
                        )))?
                        .clone(),
                )?;
                if target.decision != Some(decision.record.record_id) {
                    return Err(crate::error::MemoryError::policy(format!(
                        "decision {} is not linked from its target assertion",
                        decision.record.record_id
                    )));
                }
                let expected = match decision.decision_kind {
                    crate::model::DecisionKind::Acceptance => {
                        (mneme_core::Lifecycle::Accepted, "accepted")
                    }
                    crate::model::DecisionKind::Retraction => {
                        (mneme_core::Lifecycle::Retracted, "retracted")
                    }
                    crate::model::DecisionKind::Supersession => {
                        (mneme_core::Lifecycle::Superseded, "superseded")
                    }
                    crate::model::DecisionKind::ConflictResolution => {
                        (mneme_core::Lifecycle::Disputed, "disputed")
                    }
                    crate::model::DecisionKind::Other(_) => {
                        return Err(crate::error::MemoryError::policy(
                            "unknown decision kind cannot be committed",
                        ));
                    }
                };
                if target.lifecycle != expected.0 || decision.outcome != expected.1 {
                    return Err(crate::error::MemoryError::policy(format!(
                        "decision {} outcome {} does not match target lifecycle {}",
                        decision.record.record_id,
                        decision.outcome,
                        target.lifecycle.symbol()
                    )));
                }
                for evidence in &decision.evidence {
                    if !combined.contains_key(evidence) {
                        return Err(crate::error::MemoryError::policy(format!(
                            "decision {} evidence {evidence} is missing",
                            decision.record.record_id
                        )));
                    }
                }
            }
            mneme_core::RecordKind::Derivation => {
                let derivation = crate::model::DerivationView::parse(envelope.clone())?;
                if derivation.evaluation_revision != snapshot.revision {
                    return Err(crate::error::MemoryError::policy(format!(
                        "derivation {} evaluates revision {}, not the current base {}",
                        derivation.record.record_id,
                        derivation.evaluation_revision,
                        snapshot.revision
                    )));
                }
                if !combined.contains_key(&derivation.conclusion) {
                    return Err(crate::error::MemoryError::policy(format!(
                        "derivation {} conclusion {} is missing",
                        derivation.record.record_id, derivation.conclusion
                    )));
                }
                for premise in &derivation.premises {
                    if !combined.contains_key(premise) {
                        return Err(crate::error::MemoryError::policy(format!(
                            "derivation {} premise {premise} is missing",
                            derivation.record.record_id
                        )));
                    }
                }
            }
            mneme_core::RecordKind::Episode => {
                let episode = crate::model::EpisodeView::parse(envelope.clone())?;
                for related in &episode.related {
                    if !combined.contains_key(related) {
                        return Err(crate::error::MemoryError::policy(format!(
                            "episode {} related record {related} is missing",
                            episode.record.record_id
                        )));
                    }
                }
            }
            mneme_core::RecordKind::Checkpoint => {
                let (revision, episodes, verified) =
                    view.checkpoint_revision(envelope.record_id)?;
                if revision != snapshot.revision {
                    return Err(crate::error::MemoryError::policy(format!(
                        "checkpoint {} references revision {revision}, not the current base {}",
                        envelope.record_id, snapshot.revision
                    )));
                }
                for linked in episodes.iter().chain(verified.iter()) {
                    if !combined.contains_key(linked) {
                        return Err(crate::error::MemoryError::policy(format!(
                            "checkpoint {} references missing record {linked}",
                            envelope.record_id
                        )));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn source_bytes(
    source: &crate::model::SourceView,
    supplied: &std::collections::BTreeMap<mneme_core::ContentDigest, Vec<u8>>,
    root: &std::path::Path,
) -> crate::error::Result<Vec<u8>> {
    let Some(digest) = source.digest() else {
        return Err(crate::error::MemoryError::policy(
            "new evidence requires retained source bytes",
        ));
    };
    if let Some(bytes) = supplied.get(&digest) {
        return Ok(bytes.clone());
    }
    match mneme_store::blob::read(root, digest) {
        Ok(bytes) => Ok(bytes),
        Err(mneme_store::StoreError::MissingBlob { .. }) => Err(crate::error::MemoryError::policy(
            "new evidence cites a source whose committed bytes are missing",
        )),
        Err(mneme_store::StoreError::CorruptBlob { reason, .. }) => {
            Err(crate::error::MemoryError::policy(format!(
                "new evidence cites corrupt source bytes: {reason}"
            )))
        }
        Err(error) => Err(error.into()),
    }
}

fn reference(target: mneme_core::RecordId, kind: mneme_core::RecordKind) -> mneme_core::Reference {
    mneme_core::Reference::local(target, kind)
}

fn pinned(
    target: mneme_core::RecordId,
    revision: mneme_core::RevisionId,
    kind: mneme_core::RecordKind,
) -> mneme_core::Reference {
    mneme_core::Reference::pinned(target, revision, kind)
}

fn ref_set(references: &[mneme_core::Reference]) -> mneme_core::Value {
    mneme_core::Value::set(references.iter().map(mneme_core::Reference::to_value))
}

fn valid_time_value(valid_time: mneme_core::ValidTime) -> mneme_core::Value {
    valid_time.to_value()
}

/// Build a retained source revision and its exact source blob.
#[allow(unknown_lints, clippy::too_many_arguments, too_many_parameters)]
pub fn build_source(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    bytes: &[u8],
    media_type: &str,
    entity: Option<mneme_core::RecordId>,
    path_hint: Option<&str>,
) -> crate::error::Result<(mneme_store::RecordDraft, mneme_store::SourceBlobDraft)> {
    let retained = mneme_core::RetainedSource::new(
        mneme_core::ContentDigest::of_source_bytes(bytes),
        bytes.len() as u64,
        media_type,
    )
    .map_err(|message| crate::error::MemoryError::policy(message.to_owned()))?;
    let mut entries = vec![
        (
            mneme_core::Symbol::from("content"),
            mneme_core::SourceContent::Retained(retained).to_value(),
        ),
        (
            mneme_core::Symbol::from("acquisition"),
            mneme_core::Value::symbol("authored"),
        ),
    ];
    if let Some(entity) = entity {
        entries.push((
            mneme_core::Symbol::from("entity"),
            reference(entity, mneme_core::RecordKind::Entity).to_value(),
        ));
    }
    if let Some(path) = path_hint {
        entries.push((
            mneme_core::Symbol::from("path-hint"),
            mneme_core::Value::string(path),
        ));
    }
    Ok((
        mneme_store::RecordDraft {
            schema_version: 2,
            kind: mneme_core::RecordKind::SourceRevision,
            record_id,
            revision_id,
            predecessor: None,
            scope: scope.clone(),
            payload: mneme_core::Payload::new(entries),
        },
        mneme_store::SourceBlobDraft {
            bytes: bytes.to_vec(),
            media_type: mneme_core::Symbol::from(media_type),
        },
    ))
}

/// Build an unavailable or pruned source revision.
#[allow(unknown_lints, clippy::too_many_arguments, too_many_parameters)]
pub fn build_unavailable_source(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    reason: &str,
    availability: &str,
    entity: Option<mneme_core::RecordId>,
    path_hint: Option<&str>,
) -> mneme_store::RecordDraft {
    build_unavailable_source_with_digest(
        record_id,
        revision_id,
        scope,
        reason,
        availability,
        None,
        entity,
        path_hint,
    )
}

/// Build an unavailable source revision that preserves the identity of the
/// bytes it no longer stores.
#[allow(unknown_lints, clippy::too_many_arguments, too_many_parameters)]
pub fn build_unavailable_source_with_digest(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    reason: &str,
    availability: &str,
    prior_digest: Option<mneme_core::ContentDigest>,
    entity: Option<mneme_core::RecordId>,
    path_hint: Option<&str>,
) -> mneme_store::RecordDraft {
    let mut entries = vec![
        (
            mneme_core::Symbol::from("content"),
            mneme_core::SourceContent::Unavailable {
                reason: reason.to_owned(),
            }
            .to_value(),
        ),
        (
            mneme_core::Symbol::from("acquisition"),
            mneme_core::Value::symbol("authored"),
        ),
        (
            mneme_core::Symbol::from("availability"),
            mneme_core::Value::symbol(availability),
        ),
    ];
    if let Some(entity) = entity {
        entries.push((
            mneme_core::Symbol::from("entity"),
            reference(entity, mneme_core::RecordKind::Entity).to_value(),
        ));
    }
    if let Some(path) = path_hint {
        entries.push((
            mneme_core::Symbol::from("path-hint"),
            mneme_core::Value::string(path),
        ));
    }
    if let Some(digest) = prior_digest {
        entries.push((
            mneme_core::Symbol::from("content-digest"),
            digest.to_value(),
        ));
    }
    mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::SourceRevision,
        record_id,
        revision_id,
        predecessor: None,
        scope: scope.clone(),
        payload: mneme_core::Payload::new(entries),
    }
}

/// Build an episode, including optional related-record links.
#[allow(unknown_lints, clippy::too_many_arguments, too_many_parameters)]
pub fn build_episode(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    actor: &str,
    episode_type: &str,
    occurred: mneme_core::ValidTime,
    summary: &str,
    source: Option<mneme_core::Reference>,
    related: &[mneme_core::Reference],
) -> mneme_store::RecordDraft {
    let mut entries = vec![
        (
            mneme_core::Symbol::from("actor"),
            mneme_core::Value::string(actor),
        ),
        (
            mneme_core::Symbol::from("episode-type"),
            mneme_core::Value::symbol(episode_type),
        ),
        (
            mneme_core::Symbol::from("occurred"),
            valid_time_value(occurred),
        ),
        (
            mneme_core::Symbol::from("summary"),
            mneme_core::Value::string(summary),
        ),
    ];
    if let Some(source) = source {
        entries.push((mneme_core::Symbol::from("source"), source.to_value()));
    }
    if !related.is_empty() {
        entries.push((mneme_core::Symbol::from("related"), ref_set(related)));
    }
    mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::Episode,
        record_id,
        revision_id,
        predecessor: None,
        scope: scope.clone(),
        payload: mneme_core::Payload::new(entries),
    }
}

/// Build evidence over an exact source revision.
#[allow(unknown_lints, clippy::too_many_arguments, too_many_parameters)]
pub fn build_evidence(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    assertion: mneme_core::RecordId,
    source: mneme_core::RecordId,
    source_revision: mneme_core::RevisionId,
    span: Option<mneme_core::SourceSpan>,
    anchor: Option<&str>,
    relation: crate::model::SupportRelation,
    origin: mneme_core::Origin,
    ancestry: &[mneme_core::Reference],
) -> mneme_store::RecordDraft {
    let mut entries = vec![
        (
            mneme_core::Symbol::from("assertion"),
            reference(assertion, mneme_core::RecordKind::Assertion).to_value(),
        ),
        (
            mneme_core::Symbol::from("source"),
            pinned(
                source,
                source_revision,
                mneme_core::RecordKind::SourceRevision,
            )
            .to_value(),
        ),
        (
            mneme_core::Symbol::from("relation"),
            mneme_core::Value::symbol(match relation {
                crate::model::SupportRelation::Supports => "supports",
                crate::model::SupportRelation::Challenges => "challenges",
            }),
        ),
        (
            mneme_core::Symbol::from("origin"),
            mneme_core::Value::symbol(origin.symbol()),
        ),
        (mneme_core::Symbol::from("ancestry"), ref_set(ancestry)),
    ];
    if let Some(span) = span {
        entries.push((mneme_core::Symbol::from("span"), span.to_value()));
    }
    if let Some(anchor) = anchor {
        entries.push((
            mneme_core::Symbol::from("anchor"),
            mneme_core::Value::string(anchor),
        ));
    }
    mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::Evidence,
        record_id,
        revision_id,
        predecessor: None,
        scope: scope.clone(),
        payload: mneme_core::Payload::new(entries),
    }
}

/// Build a proposed assertion. There is deliberately no parameter that sets an
/// accepted lifecycle.
#[allow(unknown_lints, clippy::too_many_arguments, too_many_parameters)]
pub fn build_proposed_assertion(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    subject: mneme_core::RecordId,
    predicate: &str,
    value: mneme_core::Value,
    stance: crate::model::Stance,
    origin: mneme_core::Origin,
    asserted_by: &str,
    valid_time: mneme_core::ValidTime,
    evidence: &[mneme_core::Reference],
    extraction: Option<(&str, &str)>,
    superseded_by: Option<mneme_core::Reference>,
) -> mneme_store::RecordDraft {
    let mut entries = vec![
        (
            mneme_core::Symbol::from("subject"),
            reference(subject, mneme_core::RecordKind::Entity).to_value(),
        ),
        (
            mneme_core::Symbol::from("predicate"),
            mneme_core::Value::symbol(predicate),
        ),
        (mneme_core::Symbol::from("value"), value),
        (
            mneme_core::Symbol::from("stance"),
            mneme_core::Value::symbol(match stance {
                crate::model::Stance::Affirm => "affirm",
                crate::model::Stance::Deny => "deny",
                crate::model::Stance::Hypothesis => "hypothesis",
            }),
        ),
        (
            mneme_core::Symbol::from("lifecycle"),
            mneme_core::Value::symbol("proposed"),
        ),
        (
            mneme_core::Symbol::from("origin"),
            mneme_core::Value::symbol(origin.symbol()),
        ),
        (
            mneme_core::Symbol::from("asserted-by"),
            mneme_core::Value::string(asserted_by),
        ),
        (
            mneme_core::Symbol::from("valid-time"),
            valid_time_value(valid_time),
        ),
        (mneme_core::Symbol::from("evidence"), ref_set(evidence)),
    ];
    if let Some((model, prompt)) = extraction {
        entries.push((
            mneme_core::Symbol::from("extraction"),
            mneme_core::Value::record_named(
                "extraction",
                vec![
                    mneme_core::Value::string(model),
                    mneme_core::Value::string(prompt),
                ],
            ),
        ));
    }
    if let Some(superseded_by) = superseded_by {
        entries.push((
            mneme_core::Symbol::from("superseded-by"),
            superseded_by.to_value(),
        ));
    }
    mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::Assertion,
        record_id,
        revision_id,
        predecessor: None,
        scope: scope.clone(),
        payload: mneme_core::Payload::new(entries),
    }
}

/// Build an attributed decision.
#[allow(unknown_lints, clippy::too_many_arguments, too_many_parameters)]
pub fn build_decision(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    kind: crate::model::DecisionKind,
    target: mneme_core::RecordId,
    actor: &str,
    policy: &str,
    input_revision: mneme_core::WorkspaceRevisionId,
    outcome: &str,
    rationale: &str,
    evidence: &[mneme_core::Reference],
    related: &[mneme_core::Reference],
) -> mneme_store::RecordDraft {
    let mut entries = vec![
        (
            mneme_core::Symbol::from("decision-kind"),
            mneme_core::Value::symbol(kind.name()),
        ),
        (
            mneme_core::Symbol::from("target"),
            reference(target, mneme_core::RecordKind::Assertion).to_value(),
        ),
        (
            mneme_core::Symbol::from("actor"),
            mneme_core::Value::string(actor),
        ),
        (
            mneme_core::Symbol::from("policy"),
            mneme_core::Value::string(policy),
        ),
        (
            mneme_core::Symbol::from("input-revision"),
            input_revision.to_value(),
        ),
        (
            mneme_core::Symbol::from("outcome"),
            mneme_core::Value::symbol(outcome),
        ),
        (
            mneme_core::Symbol::from("rationale"),
            mneme_core::Value::string(rationale),
        ),
        (mneme_core::Symbol::from("evidence"), ref_set(evidence)),
    ];
    if !related.is_empty() {
        entries.push((mneme_core::Symbol::from("related"), ref_set(related)));
    }
    mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::Decision,
        record_id,
        revision_id,
        predecessor: None,
        scope: scope.clone(),
        payload: mneme_core::Payload::new(entries),
    }
}

/// Build the next assertion revision with an explicit lifecycle and decision.
pub fn build_assertion_revision(
    assertion: &mneme_core::RecordEnvelope,
    revision_id: mneme_core::RevisionId,
    lifecycle: mneme_core::Lifecycle,
    decision: mneme_core::Reference,
    superseded_by: Option<mneme_core::Reference>,
) -> mneme_store::RecordDraft {
    let mut payload = assertion.payload.clone();
    payload.insert(
        mneme_core::Symbol::from("lifecycle"),
        mneme_core::Value::symbol(lifecycle.symbol()),
    );
    payload.insert(mneme_core::Symbol::from("decision"), decision.to_value());
    if let Some(superseded_by) = superseded_by {
        payload.insert(
            mneme_core::Symbol::from("superseded-by"),
            superseded_by.to_value(),
        );
    }
    mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::Assertion,
        record_id: assertion.record_id,
        revision_id,
        predecessor: Some(assertion.revision_id),
        scope: assertion.scope.clone(),
        payload,
    }
}

/// Build a derivation with a complete premise set.
#[allow(unknown_lints, clippy::too_many_arguments, too_many_parameters)]
pub fn build_derivation(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    conclusion: mneme_core::RecordId,
    premises: &[mneme_core::Reference],
    rule_id: &str,
    rule_version: i64,
    evaluation_revision: mneme_core::WorkspaceRevisionId,
    completeness: &str,
) -> mneme_store::RecordDraft {
    mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::Derivation,
        record_id,
        revision_id,
        predecessor: None,
        scope: scope.clone(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("conclusion"),
                reference(conclusion, mneme_core::RecordKind::Assertion).to_value(),
            ),
            (mneme_core::Symbol::from("premises"), ref_set(premises)),
            (
                mneme_core::Symbol::from("rule-id"),
                mneme_core::Value::string(rule_id),
            ),
            (
                mneme_core::Symbol::from("rule-version"),
                mneme_core::Value::integer(rule_version),
            ),
            (
                mneme_core::Symbol::from("evaluation-revision"),
                evaluation_revision.to_value(),
            ),
            (
                mneme_core::Symbol::from("completeness"),
                mneme_core::Value::symbol(completeness),
            ),
        ]),
    }
}

/// Build a checkpoint pinned to the current episode/revision state.
#[allow(unknown_lints, clippy::too_many_arguments, too_many_parameters)]
pub fn build_checkpoint(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    goal: &str,
    state: &str,
    episodes: &[mneme_core::Reference],
    verified_outcomes: &[mneme_core::Reference],
    revision: mneme_core::WorkspaceRevisionId,
    note: Option<&str>,
) -> mneme_store::RecordDraft {
    let mut entries = vec![
        (
            mneme_core::Symbol::from("goal"),
            mneme_core::Value::string(goal),
        ),
        (
            mneme_core::Symbol::from("state"),
            mneme_core::Value::symbol(state),
        ),
        (mneme_core::Symbol::from("episodes"), ref_set(episodes)),
        (
            mneme_core::Symbol::from("verified-outcomes"),
            ref_set(verified_outcomes),
        ),
        (mneme_core::Symbol::from("revision"), revision.to_value()),
    ];
    if let Some(note) = note {
        entries.push((
            mneme_core::Symbol::from("note"),
            mneme_core::Value::string(note),
        ));
    }
    mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::Checkpoint,
        record_id,
        revision_id,
        predecessor: None,
        scope: scope.clone(),
        payload: mneme_core::Payload::new(entries),
    }
}
