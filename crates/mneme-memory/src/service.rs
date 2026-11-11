//! Recording and explanation services over the workspace coordinator.
//!
//! Builders construct typed drafts; [`Memory::commit`] validates evidence spans,
//! lifecycle decisions, ancestry, and action outcomes before submitting the
//! normal workspace command. No draft can promote a claim without an explicit
//! decision record in the same batch.

use std::collections::BTreeMap;
use std::path::Path;

use mneme_core::{
    ContentDigest, Lifecycle, Origin, Payload, RecordEnvelope, RecordId, RecordedTime, Reference,
    RevisionId, ScopeId, SnapshotIndex, SourceContent, SourceSpan, Symbol, Timestamp, ValidTime,
    Value, WorkspaceRevisionId,
};
use mneme_store::{
    CommitCommand, CommitOutcome, PublicationDraft, RecordDraft, Snapshot, SourceBlobDraft,
    StoreError, Workspace,
};

use crate::error::{MemoryError, Result};
use crate::model::{
    AssertionView, DecisionKind, DecisionView, DerivationView, EpisodeView, EvidenceView,
    SourceView, Stance, SupportRelation,
};
use crate::policy::{
    ACTION_COMPLETED_PREDICATE, BeliefView, ConflictGroup, Explanation, MemoryView, Policy,
};

/// A memory batch submitted through the workspace coordinator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryBatch {
    pub actor: String,
    pub scope: ScopeId,
    pub idempotency_key: String,
    pub records: Vec<RecordDraft>,
    pub source_blobs: Vec<SourceBlobDraft>,
    pub publications: Vec<PublicationDraft>,
}

/// The memory service over one mutable workspace handle.
pub struct Memory<'w> {
    workspace: &'w mut Workspace,
}

impl<'w> Memory<'w> {
    /// Wrap a workspace.
    pub fn new(workspace: &'w mut Workspace) -> Self {
        Memory { workspace }
    }

    /// The current pinned view.
    pub fn view(&self) -> Result<MemoryView> {
        self.view_at(None)
    }

    /// A view fenced by an expected eligibility generation.
    pub fn view_at(&self, pinned_generation: Option<u64>) -> Result<MemoryView> {
        let revision = self.workspace.current_revision()?;
        let snapshot = self.workspace.snapshot_at(revision, pinned_generation)?;
        let history = load_history(self.workspace, &snapshot)?;
        let sequences = self.workspace.revision_sequences()?;
        let suppressions = self.workspace.active_suppressions()?;
        Ok(MemoryView::with_retention(
            snapshot,
            self.workspace.root(),
            history,
            sequences,
            suppressions,
        ))
    }

    /// All retained revisions of one record.
    pub fn revisions(&self, record: RecordId) -> Result<Vec<RecordEnvelope>> {
        Ok(self.workspace.record_revisions(record)?)
    }

    /// Explain one current assertion.
    pub fn explain(&self, assertion: RecordId, policy: Policy) -> Result<Explanation> {
        self.explain_at(assertion, None, policy)
    }

    /// Explain one assertion under a pinned eligibility generation.
    pub fn explain_at(
        &self,
        assertion: RecordId,
        pinned_generation: Option<u64>,
        policy: Policy,
    ) -> Result<Explanation> {
        self.view_at(pinned_generation)?.explain(assertion, policy)
    }

    /// Current beliefs under an explicit scope and effective-time policy.
    pub fn beliefs(&self, view: &BeliefView) -> Result<Vec<AssertionView>> {
        self.view()?.current_beliefs(view)
    }

    /// Conflicts among currently eligible claims.
    pub fn conflicts(&self, view: &BeliefView) -> Result<Vec<ConflictGroup>> {
        self.view()?.conflicts(view)
    }

    /// Validate and commit a memory batch.
    pub fn commit(&mut self, batch: MemoryBatch) -> Result<CommitOutcome> {
        let base = self.workspace.current_revision()?;
        self.commit_at_base(batch, base)
    }

    /// Validate and commit a memory batch against a caller-supplied base
    /// revision. The coordinator still applies its compare-and-swap and
    /// idempotency rules.
    pub fn commit_at_base(
        &mut self,
        batch: MemoryBatch,
        base: WorkspaceRevisionId,
    ) -> Result<CommitOutcome> {
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
        let outcome = self.workspace.commit(CommitCommand {
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

fn load_history(
    workspace: &Workspace,
    snapshot: &Snapshot,
) -> Result<BTreeMap<(RecordId, RevisionId), RecordEnvelope>> {
    let mut history = BTreeMap::new();
    for record in &snapshot.records {
        for revision in workspace.record_revisions(record.record_id)? {
            history.insert((revision.record_id, revision.revision_id), revision);
        }
    }
    Ok(history)
}

fn validate_batch(
    snapshot: &Snapshot,
    root: &Path,
    batch: &MemoryBatch,
    history: &BTreeMap<(RecordId, RevisionId), RecordEnvelope>,
    revision_sequences: &BTreeMap<WorkspaceRevisionId, u64>,
    suppressions: &[mneme_store::RetentionSuppression],
) -> Result<()> {
    let mut combined: BTreeMap<RecordId, RecordEnvelope> = snapshot
        .records
        .iter()
        .map(|record| (record.record_id, record.clone()))
        .collect();
    let mut supplied_sources: BTreeMap<ContentDigest, Vec<u8>> = BTreeMap::new();
    for source in &batch.source_blobs {
        supplied_sources.insert(source.digest(), source.bytes.clone());
    }
    for draft in &batch.records {
        let envelope = draft
            .clone()
            .into_envelope(RecordedTime::new(Timestamp::from_nanos(0), 0));
        if envelope.scope != batch.scope {
            return Err(MemoryError::policy(format!(
                "record {} scope {} differs from batch scope {}",
                envelope.record_id, envelope.scope, batch.scope
            )));
        }
        combined.insert(envelope.record_id, envelope);
    }
    let mut index = SnapshotIndex::new();
    for record in combined.values() {
        index.insert(record.record_id, record.kind, record.revision_id);
    }
    let virtual_snapshot = Snapshot {
        revision: snapshot.revision,
        sequence: snapshot.sequence,
        parent: snapshot.parent,
        manifest_digest: snapshot.manifest_digest,
        eligibility_generation: snapshot.eligibility_generation,
        records: combined.values().cloned().collect(),
        index,
    };
    let view = MemoryView::with_retention(
        virtual_snapshot,
        root,
        history.clone(),
        revision_sequences.clone(),
        suppressions.to_vec(),
    );

    for draft in &batch.records {
        let envelope = draft
            .clone()
            .into_envelope(RecordedTime::new(Timestamp::from_nanos(0), 0));
        match envelope.kind {
            mneme_core::RecordKind::Evidence => {
                let evidence = EvidenceView::parse(envelope.clone())?;
                if view.suppression_for(&envelope).is_some_and(|suppression| {
                    suppression.mode == mneme_store::SuppressionMode::Withdrawn
                }) {
                    return Err(MemoryError::policy(format!(
                        "evidence {} is withdrawn and cannot be newly cited",
                        evidence.record.record_id
                    )));
                }
                let source = view.evidence_source(&evidence).map_err(|_| {
                    MemoryError::policy(format!(
                        "evidence {} references missing source {}",
                        evidence.record.record_id, evidence.source
                    ))
                })?;
                if let Reference::Pinned { revision, .. } = evidence.source_reference
                    && revision != source.record.revision_id
                {
                    return Err(MemoryError::policy(format!(
                        "evidence {} pins source revision {revision}, but the source record is {}",
                        evidence.record.record_id, source.record.revision_id
                    )));
                }
                let bytes = source_bytes(&source, &supplied_sources, root)?;
                if evidence.span.is_none() && evidence.anchor.is_none() {
                    return Err(MemoryError::policy(
                        "evidence requires an exact span or a stable anchor",
                    ));
                }
                if let Some(span) = evidence.span
                    && span.end() >= bytes.len() as u64
                {
                    return Err(MemoryError::policy(format!(
                        "evidence {} span ends at byte {} beyond {} retained bytes",
                        evidence.record.record_id,
                        span.end(),
                        bytes.len()
                    )));
                }
                if let Some(anchor) = &evidence.anchor
                    && anchor.trim().is_empty()
                {
                    return Err(MemoryError::policy("evidence anchor must not be empty"));
                }
                for ancestor in &evidence.ancestry {
                    if !combined.contains_key(ancestor) {
                        return Err(MemoryError::policy(format!(
                            "evidence {} ancestry names missing record {ancestor}",
                            evidence.record.record_id
                        )));
                    }
                }
                // Cycle detection over the combined evidence ancestry graph.
                view.evidence_roots(evidence.record.record_id)?;
            }
            mneme_core::RecordKind::Assertion => {
                let assertion = AssertionView::parse(envelope.clone())?;
                for evidence_id in &assertion.evidence {
                    if let Ok(evidence_record) = view.envelope(*evidence_id)
                        && view
                            .suppression_for(evidence_record)
                            .is_some_and(|suppression| {
                                suppression.mode == mneme_store::SuppressionMode::Withdrawn
                            })
                    {
                        return Err(MemoryError::policy(format!(
                            "assertion {} cites withdrawn evidence {evidence_id}",
                            assertion.record.record_id
                        )));
                    }
                }
                if !view.lifecycle_decision_valid(&assertion)? {
                    return Err(MemoryError::policy(format!(
                        "assertion {} lifecycle {} lacks a matching decision",
                        assertion.record.record_id,
                        assertion.lifecycle.symbol()
                    )));
                }
                if assertion.origin == Origin::ModelExtraction && assertion.extraction.is_none() {
                    return Err(MemoryError::policy(format!(
                        "model-extracted assertion {} must retain extraction lineage",
                        assertion.record.record_id
                    )));
                }
                if assertion.predicate == ACTION_COMPLETED_PREDICATE
                    && !view.has_observed_outcome(&assertion)?
                {
                    return Err(MemoryError::policy(format!(
                        "completed-action assertion {} has no observed outcome episode",
                        assertion.record.record_id
                    )));
                }
                if assertion.lifecycle == Lifecycle::Accepted && assertion.stance == Stance::Deny {
                    let is_complete = assertion
                        .record
                        .payload
                        .get("completeness")
                        .and_then(Value::as_symbol)
                        .map(|symbol| symbol.as_str() == "declared-complete")
                        .unwrap_or(false);
                    if !is_complete {
                        return Err(MemoryError::policy(format!(
                            "accepted negative assertion {} lacks a declared-complete basis",
                            assertion.record.record_id
                        )));
                    }
                }
                for evidence in &assertion.evidence {
                    if !combined.contains_key(evidence) {
                        return Err(MemoryError::policy(format!(
                            "assertion {} evidence reference {evidence} is missing",
                            assertion.record.record_id
                        )));
                    }
                }
            }
            mneme_core::RecordKind::Decision => {
                let decision = DecisionView::parse(envelope.clone())?;
                if decision.actor.trim().is_empty() || decision.policy.trim().is_empty() {
                    return Err(MemoryError::policy(
                        "decision actor and policy must be non-empty",
                    ));
                }
                if decision.input_revision != snapshot.revision {
                    return Err(MemoryError::policy(format!(
                        "decision {} evaluates revision {}, not the current base {}",
                        decision.record.record_id, decision.input_revision, snapshot.revision
                    )));
                }
                let target = AssertionView::parse(
                    combined
                        .get(&decision.target)
                        .ok_or(MemoryError::policy(format!(
                            "decision {} targets missing assertion {}",
                            decision.record.record_id, decision.target
                        )))?
                        .clone(),
                )?;
                if target.decision != Some(decision.record.record_id) {
                    return Err(MemoryError::policy(format!(
                        "decision {} is not linked from its target assertion",
                        decision.record.record_id
                    )));
                }
                let expected = match decision.decision_kind {
                    DecisionKind::Acceptance => (Lifecycle::Accepted, "accepted"),
                    DecisionKind::Retraction => (Lifecycle::Retracted, "retracted"),
                    DecisionKind::Supersession => (Lifecycle::Superseded, "superseded"),
                    DecisionKind::ConflictResolution => (Lifecycle::Disputed, "disputed"),
                    DecisionKind::Other(_) => {
                        return Err(MemoryError::policy(
                            "unknown decision kind cannot be committed",
                        ));
                    }
                };
                if target.lifecycle != expected.0 || decision.outcome != expected.1 {
                    return Err(MemoryError::policy(format!(
                        "decision {} outcome {} does not match target lifecycle {}",
                        decision.record.record_id,
                        decision.outcome,
                        target.lifecycle.symbol()
                    )));
                }
                for evidence in &decision.evidence {
                    if !combined.contains_key(evidence) {
                        return Err(MemoryError::policy(format!(
                            "decision {} evidence {evidence} is missing",
                            decision.record.record_id
                        )));
                    }
                }
            }
            mneme_core::RecordKind::Derivation => {
                let derivation = DerivationView::parse(envelope.clone())?;
                if derivation.evaluation_revision != snapshot.revision {
                    return Err(MemoryError::policy(format!(
                        "derivation {} evaluates revision {}, not the current base {}",
                        derivation.record.record_id,
                        derivation.evaluation_revision,
                        snapshot.revision
                    )));
                }
                if !combined.contains_key(&derivation.conclusion) {
                    return Err(MemoryError::policy(format!(
                        "derivation {} conclusion {} is missing",
                        derivation.record.record_id, derivation.conclusion
                    )));
                }
                for premise in &derivation.premises {
                    if !combined.contains_key(premise) {
                        return Err(MemoryError::policy(format!(
                            "derivation {} premise {premise} is missing",
                            derivation.record.record_id
                        )));
                    }
                }
            }
            mneme_core::RecordKind::Episode => {
                let episode = EpisodeView::parse(envelope.clone())?;
                for related in &episode.related {
                    if !combined.contains_key(related) {
                        return Err(MemoryError::policy(format!(
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
                    return Err(MemoryError::policy(format!(
                        "checkpoint {} references revision {revision}, not the current base {}",
                        envelope.record_id, snapshot.revision
                    )));
                }
                for linked in episodes.iter().chain(verified.iter()) {
                    if !combined.contains_key(linked) {
                        return Err(MemoryError::policy(format!(
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
    source: &SourceView,
    supplied: &BTreeMap<ContentDigest, Vec<u8>>,
    root: &Path,
) -> Result<Vec<u8>> {
    let Some(digest) = source.digest() else {
        return Err(MemoryError::policy(
            "new evidence requires retained source bytes",
        ));
    };
    if let Some(bytes) = supplied.get(&digest) {
        return Ok(bytes.clone());
    }
    match mneme_store::blob::read(root, digest) {
        Ok(bytes) => Ok(bytes),
        Err(StoreError::MissingBlob { .. }) => Err(MemoryError::policy(
            "new evidence cites a source whose committed bytes are missing",
        )),
        Err(StoreError::CorruptBlob { reason, .. }) => Err(MemoryError::policy(format!(
            "new evidence cites corrupt source bytes: {reason}"
        ))),
        Err(error) => Err(error.into()),
    }
}

fn reference(target: RecordId, kind: mneme_core::RecordKind) -> Reference {
    Reference::local(target, kind)
}

fn pinned(target: RecordId, revision: RevisionId, kind: mneme_core::RecordKind) -> Reference {
    Reference::pinned(target, revision, kind)
}

fn ref_set(references: &[Reference]) -> Value {
    Value::set(references.iter().map(Reference::to_value))
}

fn valid_time_value(valid_time: ValidTime) -> Value {
    valid_time.to_value()
}

/// Build a retained source revision and its exact source blob.
#[allow(clippy::too_many_arguments)]
pub fn build_source(
    record_id: RecordId,
    revision_id: RevisionId,
    scope: &ScopeId,
    bytes: &[u8],
    media_type: &str,
    entity: Option<RecordId>,
    path_hint: Option<&str>,
) -> Result<(RecordDraft, SourceBlobDraft)> {
    let retained = mneme_core::RetainedSource::new(
        ContentDigest::of_source_bytes(bytes),
        bytes.len() as u64,
        media_type,
    )
    .map_err(|message| MemoryError::policy(message.to_owned()))?;
    let mut entries = vec![
        (
            Symbol::from("content"),
            SourceContent::Retained(retained).to_value(),
        ),
        (Symbol::from("acquisition"), Value::symbol("authored")),
    ];
    if let Some(entity) = entity {
        entries.push((
            Symbol::from("entity"),
            reference(entity, mneme_core::RecordKind::Entity).to_value(),
        ));
    }
    if let Some(path) = path_hint {
        entries.push((Symbol::from("path-hint"), Value::string(path)));
    }
    Ok((
        RecordDraft {
            schema_version: 2,
            kind: mneme_core::RecordKind::SourceRevision,
            record_id,
            revision_id,
            predecessor: None,
            scope: scope.clone(),
            payload: Payload::new(entries),
        },
        SourceBlobDraft {
            bytes: bytes.to_vec(),
            media_type: Symbol::from(media_type),
        },
    ))
}

/// Build an unavailable or pruned source revision.
#[allow(clippy::too_many_arguments)]
pub fn build_unavailable_source(
    record_id: RecordId,
    revision_id: RevisionId,
    scope: &ScopeId,
    reason: &str,
    availability: &str,
    entity: Option<RecordId>,
    path_hint: Option<&str>,
) -> RecordDraft {
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
#[allow(clippy::too_many_arguments)]
pub fn build_unavailable_source_with_digest(
    record_id: RecordId,
    revision_id: RevisionId,
    scope: &ScopeId,
    reason: &str,
    availability: &str,
    prior_digest: Option<ContentDigest>,
    entity: Option<RecordId>,
    path_hint: Option<&str>,
) -> RecordDraft {
    let mut entries = vec![
        (
            Symbol::from("content"),
            SourceContent::Unavailable {
                reason: reason.to_owned(),
            }
            .to_value(),
        ),
        (Symbol::from("acquisition"), Value::symbol("authored")),
        (Symbol::from("availability"), Value::symbol(availability)),
    ];
    if let Some(entity) = entity {
        entries.push((
            Symbol::from("entity"),
            reference(entity, mneme_core::RecordKind::Entity).to_value(),
        ));
    }
    if let Some(path) = path_hint {
        entries.push((Symbol::from("path-hint"), Value::string(path)));
    }
    if let Some(digest) = prior_digest {
        entries.push((Symbol::from("content-digest"), digest.to_value()));
    }
    RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::SourceRevision,
        record_id,
        revision_id,
        predecessor: None,
        scope: scope.clone(),
        payload: Payload::new(entries),
    }
}

/// Build an episode, including optional related-record links.
#[allow(clippy::too_many_arguments)]
pub fn build_episode(
    record_id: RecordId,
    revision_id: RevisionId,
    scope: &ScopeId,
    actor: &str,
    episode_type: &str,
    occurred: ValidTime,
    summary: &str,
    source: Option<Reference>,
    related: &[Reference],
) -> RecordDraft {
    let mut entries = vec![
        (Symbol::from("actor"), Value::string(actor)),
        (Symbol::from("episode-type"), Value::symbol(episode_type)),
        (Symbol::from("occurred"), valid_time_value(occurred)),
        (Symbol::from("summary"), Value::string(summary)),
    ];
    if let Some(source) = source {
        entries.push((Symbol::from("source"), source.to_value()));
    }
    if !related.is_empty() {
        entries.push((Symbol::from("related"), ref_set(related)));
    }
    RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::Episode,
        record_id,
        revision_id,
        predecessor: None,
        scope: scope.clone(),
        payload: Payload::new(entries),
    }
}

/// Build evidence over an exact source revision.
#[allow(clippy::too_many_arguments)]
pub fn build_evidence(
    record_id: RecordId,
    revision_id: RevisionId,
    scope: &ScopeId,
    assertion: RecordId,
    source: RecordId,
    source_revision: RevisionId,
    span: Option<SourceSpan>,
    anchor: Option<&str>,
    relation: SupportRelation,
    origin: Origin,
    ancestry: &[Reference],
) -> RecordDraft {
    let mut entries = vec![
        (
            Symbol::from("assertion"),
            reference(assertion, mneme_core::RecordKind::Assertion).to_value(),
        ),
        (
            Symbol::from("source"),
            pinned(
                source,
                source_revision,
                mneme_core::RecordKind::SourceRevision,
            )
            .to_value(),
        ),
        (
            Symbol::from("relation"),
            Value::symbol(match relation {
                SupportRelation::Supports => "supports",
                SupportRelation::Challenges => "challenges",
            }),
        ),
        (Symbol::from("origin"), Value::symbol(origin.symbol())),
        (Symbol::from("ancestry"), ref_set(ancestry)),
    ];
    if let Some(span) = span {
        entries.push((Symbol::from("span"), span.to_value()));
    }
    if let Some(anchor) = anchor {
        entries.push((Symbol::from("anchor"), Value::string(anchor)));
    }
    RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::Evidence,
        record_id,
        revision_id,
        predecessor: None,
        scope: scope.clone(),
        payload: Payload::new(entries),
    }
}

/// Build a proposed assertion. There is deliberately no parameter that sets an
/// accepted lifecycle.
#[allow(clippy::too_many_arguments)]
pub fn build_proposed_assertion(
    record_id: RecordId,
    revision_id: RevisionId,
    scope: &ScopeId,
    subject: RecordId,
    predicate: &str,
    value: Value,
    stance: Stance,
    origin: Origin,
    asserted_by: &str,
    valid_time: ValidTime,
    evidence: &[Reference],
    extraction: Option<(&str, &str)>,
    superseded_by: Option<Reference>,
) -> RecordDraft {
    let mut entries = vec![
        (
            Symbol::from("subject"),
            reference(subject, mneme_core::RecordKind::Entity).to_value(),
        ),
        (Symbol::from("predicate"), Value::symbol(predicate)),
        (Symbol::from("value"), value),
        (
            Symbol::from("stance"),
            Value::symbol(match stance {
                Stance::Affirm => "affirm",
                Stance::Deny => "deny",
                Stance::Hypothesis => "hypothesis",
            }),
        ),
        (Symbol::from("lifecycle"), Value::symbol("proposed")),
        (Symbol::from("origin"), Value::symbol(origin.symbol())),
        (Symbol::from("asserted-by"), Value::string(asserted_by)),
        (Symbol::from("valid-time"), valid_time_value(valid_time)),
        (Symbol::from("evidence"), ref_set(evidence)),
    ];
    if let Some((model, prompt)) = extraction {
        entries.push((
            Symbol::from("extraction"),
            Value::record_named(
                "extraction",
                vec![Value::string(model), Value::string(prompt)],
            ),
        ));
    }
    if let Some(superseded_by) = superseded_by {
        entries.push((Symbol::from("superseded-by"), superseded_by.to_value()));
    }
    RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::Assertion,
        record_id,
        revision_id,
        predecessor: None,
        scope: scope.clone(),
        payload: Payload::new(entries),
    }
}

/// Build an attributed decision.
#[allow(clippy::too_many_arguments)]
pub fn build_decision(
    record_id: RecordId,
    revision_id: RevisionId,
    scope: &ScopeId,
    kind: DecisionKind,
    target: RecordId,
    actor: &str,
    policy: &str,
    input_revision: WorkspaceRevisionId,
    outcome: &str,
    rationale: &str,
    evidence: &[Reference],
    related: &[Reference],
) -> RecordDraft {
    let mut entries = vec![
        (Symbol::from("decision-kind"), Value::symbol(kind.name())),
        (
            Symbol::from("target"),
            reference(target, mneme_core::RecordKind::Assertion).to_value(),
        ),
        (Symbol::from("actor"), Value::string(actor)),
        (Symbol::from("policy"), Value::string(policy)),
        (Symbol::from("input-revision"), input_revision.to_value()),
        (Symbol::from("outcome"), Value::symbol(outcome)),
        (Symbol::from("rationale"), Value::string(rationale)),
        (Symbol::from("evidence"), ref_set(evidence)),
    ];
    if !related.is_empty() {
        entries.push((Symbol::from("related"), ref_set(related)));
    }
    RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::Decision,
        record_id,
        revision_id,
        predecessor: None,
        scope: scope.clone(),
        payload: Payload::new(entries),
    }
}

/// Build the next assertion revision with an explicit lifecycle and decision.
pub fn build_assertion_revision(
    assertion: &RecordEnvelope,
    revision_id: RevisionId,
    lifecycle: Lifecycle,
    decision: Reference,
    superseded_by: Option<Reference>,
) -> RecordDraft {
    let mut payload = assertion.payload.clone();
    payload.insert(Symbol::from("lifecycle"), Value::symbol(lifecycle.symbol()));
    payload.insert(Symbol::from("decision"), decision.to_value());
    if let Some(superseded_by) = superseded_by {
        payload.insert(Symbol::from("superseded-by"), superseded_by.to_value());
    }
    RecordDraft {
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
#[allow(clippy::too_many_arguments)]
pub fn build_derivation(
    record_id: RecordId,
    revision_id: RevisionId,
    scope: &ScopeId,
    conclusion: RecordId,
    premises: &[Reference],
    rule_id: &str,
    rule_version: i64,
    evaluation_revision: WorkspaceRevisionId,
    completeness: &str,
) -> RecordDraft {
    RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::Derivation,
        record_id,
        revision_id,
        predecessor: None,
        scope: scope.clone(),
        payload: Payload::new([
            (
                Symbol::from("conclusion"),
                reference(conclusion, mneme_core::RecordKind::Assertion).to_value(),
            ),
            (Symbol::from("premises"), ref_set(premises)),
            (Symbol::from("rule-id"), Value::string(rule_id)),
            (Symbol::from("rule-version"), Value::integer(rule_version)),
            (
                Symbol::from("evaluation-revision"),
                evaluation_revision.to_value(),
            ),
            (Symbol::from("completeness"), Value::symbol(completeness)),
        ]),
    }
}

/// Build a checkpoint pinned to the current episode/revision state.
#[allow(clippy::too_many_arguments)]
pub fn build_checkpoint(
    record_id: RecordId,
    revision_id: RevisionId,
    scope: &ScopeId,
    goal: &str,
    state: &str,
    episodes: &[Reference],
    verified_outcomes: &[Reference],
    revision: WorkspaceRevisionId,
    note: Option<&str>,
) -> RecordDraft {
    let mut entries = vec![
        (Symbol::from("goal"), Value::string(goal)),
        (Symbol::from("state"), Value::symbol(state)),
        (Symbol::from("episodes"), ref_set(episodes)),
        (
            Symbol::from("verified-outcomes"),
            ref_set(verified_outcomes),
        ),
        (Symbol::from("revision"), revision.to_value()),
    ];
    if let Some(note) = note {
        entries.push((Symbol::from("note"), Value::string(note)));
    }
    RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::Checkpoint,
        record_id,
        revision_id,
        predecessor: None,
        scope: scope.clone(),
        payload: Payload::new(entries),
    }
}
