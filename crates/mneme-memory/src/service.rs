//! Recording and explanation services over the workspace coordinator.
//!
//! Builders construct typed drafts; [`Engine::commit`] validates evidence spans,
//! lifecycle decisions, ancestry, and action outcomes before submitting the
//! normal workspace command. No draft can promote a claim without an explicit
//! decision record in the same batch.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// A memory batch submitted through the workspace coordinator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    pub actor: String,
    pub scope: mneme_core::ScopeId,
    pub idempotency_key: String,
    pub records: Vec<mneme_store::RecordDraft>,
    pub source_blobs: Vec<mneme_store::SourceBlobDraft>,
    pub publications: Vec<mneme_store::PublicationDraft>,
}

/// The memory service over one mutable workspace handle.
pub struct Engine<'w> {
    workspace: &'w mut mneme_store::Workspace,
    access: crate::authorization::Access,
}

impl<'w> Engine<'w> {
    /// Wrap a workspace for a caller authorized over `access`.
    pub fn new(
        workspace: &'w mut mneme_store::Workspace,
        access: crate::authorization::Access,
    ) -> Self {
        Engine { workspace, access }
    }

    /// The current pinned view.
    pub fn view(&self) -> crate::failure::Result<crate::beliefs::View> {
        self.view_at(None)
    }

    /// A view fenced by an expected eligibility generation.
    pub fn view_at(
        &self,
        pinned_generation: Option<u64>,
    ) -> crate::failure::Result<crate::beliefs::View> {
        let revision = self.workspace.current_revision()?;
        let snapshot = self.workspace.snapshot_at(revision, pinned_generation)?;
        let context = view_context(self.workspace, &snapshot)?;
        let suppressions = self.workspace.active_suppressions()?;
        Ok(crate::beliefs::View::with_retention(
            snapshot,
            self.workspace.root(),
            context.history,
            context.revision_sequences,
            suppressions,
        )
        .with_access(self.access.clone()))
    }

    /// All retained revisions of one record.
    pub fn revisions(
        &self,
        record: mneme_core::RecordId,
    ) -> crate::failure::Result<Vec<mneme_core::RecordEnvelope>> {
        Ok(self.workspace.record_revisions(record)?)
    }

    /// Explain one current assertion.
    pub fn explain(
        &self,
        assertion: mneme_core::RecordId,
        policy: crate::beliefs::Policy,
    ) -> crate::failure::Result<crate::beliefs::Explanation> {
        self.explain_at(assertion, None, policy)
    }

    /// Explain one assertion under a pinned eligibility generation.
    pub fn explain_at(
        &self,
        assertion: mneme_core::RecordId,
        pinned_generation: Option<u64>,
        policy: crate::beliefs::Policy,
    ) -> crate::failure::Result<crate::beliefs::Explanation> {
        self.view_at(pinned_generation)?.explain(assertion, policy)
    }

    /// Current beliefs under an explicit scope and effective-time policy.
    pub fn beliefs(
        &self,
        view: &crate::beliefs::BeliefView,
    ) -> crate::failure::Result<Vec<crate::model::AssertionView>> {
        self.view()?.current_beliefs(view)
    }

    /// Conflicts among currently eligible claims that apply at the view
    /// instant.
    pub fn conflicts(
        &self,
        view: &crate::beliefs::BeliefView,
    ) -> crate::failure::Result<Vec<crate::beliefs::ConflictGroup>> {
        self.view()?.conflicts(view)
    }

    /// Validate and commit a memory batch.
    pub fn commit(&mut self, batch: Batch) -> crate::failure::Result<mneme_store::CommitOutcome> {
        self.commit_inner(batch, None)
    }

    /// Validate and commit a memory batch against a caller-supplied base
    /// revision. The coordinator still applies its compare-and-swap and
    /// idempotency rules.
    pub fn commit_at_base(
        &mut self,
        batch: Batch,
        base: mneme_core::WorkspaceRevisionId,
    ) -> crate::failure::Result<mneme_store::CommitOutcome> {
        self.commit_inner(batch, Some(base))
    }

    /// Commit one batch, replaying a recorded outcome before any validation.
    ///
    /// A lost-response retry must return the original outcome even when its
    /// base is no longer current, and a genuinely stale base must be reported
    /// as stale rather than as invalid input, so the stored outcome and the
    /// base are both decided before memory validation runs. The request
    /// fingerprint covers every input that changes the outcome; only a
    /// caller-supplied base is included, because [`Engine::commit`] derives
    /// its base from the workspace and a retry must still replay.
    /// Validation then runs against exactly the snapshot at that base.
    fn commit_inner(
        &mut self,
        batch: Batch,
        supplied_base: Option<mneme_core::WorkspaceRevisionId>,
    ) -> crate::failure::Result<mneme_store::CommitOutcome> {
        let fingerprint = request_fingerprint(&batch, supplied_base);
        if let Some(outcome) = self.workspace.replay_outcome(
            &batch.actor,
            &batch.scope,
            &batch.idempotency_key,
            &fingerprint,
        )? {
            return Ok(outcome);
        }
        let snapshot = self.workspace.snapshot()?;
        let base = match supplied_base {
            Some(base) => {
                if base != snapshot.revision {
                    return Err(mneme_store::Failure::StaleBase {
                        base,
                        current: snapshot.revision,
                    }
                    .into());
                }
                base
            }
            None => snapshot.revision,
        };
        let context = view_context(self.workspace, &snapshot)?;
        let suppressions = self.workspace.active_suppressions()?;
        validate_batch(BatchValidationInputs {
            snapshot: &snapshot,
            root: self.workspace.root(),
            batch: &batch,
            history: &context.history,
            revision_sequences: &context.revision_sequences,
            suppressions: &suppressions,
            access: &self.access,
        })?;
        let outcome = self.workspace.commit_bound(
            mneme_store::CommitCommand {
                base,
                actor: batch.actor,
                scope: batch.scope,
                idempotency_key: batch.idempotency_key,
                records: batch.records,
                source_blobs: batch.source_blobs,
                publications: batch.publications,
                import_candidates: Vec::new(),
                retention: None,
            },
            fingerprint,
        )?;
        Ok(outcome)
    }
}

/// The request identity bound to a batch's idempotency key.
///
/// It covers every input that changes the committed outcome: the operation,
/// the actor, scope and idempotency key, each record draft, the supplied source
/// digests and the publication intents. Only a caller-supplied base is
/// included, because [`Engine::commit`] derives its base from the workspace and
/// a retry after an unrelated commit must still replay.
fn request_fingerprint(
    batch: &Batch,
    supplied_base: Option<mneme_core::WorkspaceRevisionId>,
) -> mneme_core::ContentDigest {
    let base = match supplied_base {
        Some(revision) => revision.to_value(),
        None => mneme_core::Value::symbol("none"),
    };
    mneme_core::request_fingerprint(&mneme_core::Value::record_named(
        "memory-commit-request",
        vec![
            mneme_core::Value::symbol("memory-commit"),
            mneme_core::Value::string(batch.actor.clone()),
            batch.scope.to_value(),
            mneme_core::Value::string(batch.idempotency_key.clone()),
            base,
            mneme_core::Value::set(batch.records.iter().map(record_draft_value)),
            mneme_core::Value::set(
                batch
                    .source_blobs
                    .iter()
                    .map(|blob| blob.digest().to_value()),
            ),
            mneme_core::Value::set(batch.publications.iter().map(publication_value)),
        ],
    ))
}

/// One record draft as the coordinator will record its identity and content.
fn record_draft_value(draft: &mneme_store::RecordDraft) -> mneme_core::Value {
    mneme_core::Value::record_named(
        "draft-record",
        vec![
            mneme_core::Value::integer(i64::from(draft.schema_version)),
            draft.kind.to_value(),
            draft.record_id.to_value(),
            draft.revision_id.to_value(),
            match draft.predecessor {
                Some(revision) => revision.to_value(),
                None => mneme_core::Value::symbol("none"),
            },
            draft.scope.to_value(),
            draft.payload.to_value(),
        ],
    )
}

/// One publication intent as an identity-bearing value.
fn publication_value(draft: &mneme_store::PublicationDraft) -> mneme_core::Value {
    mneme_core::Value::record_named(
        "publication",
        vec![
            mneme_core::Value::string(draft.path.clone()),
            match draft.expected_previous {
                Some(digest) => digest.to_value(),
                None => mneme_core::Value::symbol("none"),
            },
            draft.desired_digest().to_value(),
        ],
    )
}

/// The retained history and committed sequences one view over a snapshot reads.
#[derive(Clone, Debug)]
pub struct ViewContext {
    /// Every retained revision of every record the snapshot contains, keyed by
    /// record identity and revision identity.
    pub history: std::collections::BTreeMap<
        (mneme_core::RecordId, mneme_core::RevisionId),
        mneme_core::RecordEnvelope,
    >,
    /// The sequence of the snapshot revision and of every revision a decision
    /// or derivation in the snapshot or its history names.
    pub revision_sequences: std::collections::BTreeMap<mneme_core::WorkspaceRevisionId, u64>,
}

/// The history and revision sequences a view over `snapshot` needs.
///
/// Both are read set-based: the history of every record the snapshot contains,
/// and only the sequences of the revisions a view actually looks up. A revision
/// that is not committed in this workspace stays absent from the sequences,
/// which every lookup already treats as "not established".
pub fn view_context(
    workspace: &mneme_store::Workspace,
    snapshot: &mneme_store::Snapshot,
) -> crate::failure::Result<ViewContext> {
    let history = flatten_history(workspace.record_histories(snapshot)?);
    let wanted = wanted_revisions(snapshot, &history)?;
    let revision_sequences = workspace.revision_sequences_for(&wanted)?;
    Ok(ViewContext {
        history,
        revision_sequences,
    })
}

/// Flatten a complete history already admitted by the store's streaming bound.
fn flatten_history(
    histories: std::collections::BTreeMap<mneme_core::RecordId, Vec<mneme_core::RecordEnvelope>>,
) -> std::collections::BTreeMap<
    (mneme_core::RecordId, mneme_core::RevisionId),
    mneme_core::RecordEnvelope,
> {
    histories
        .into_values()
        .flatten()
        .map(|record| ((record.record_id, record.revision_id), record))
        .collect()
}

/// The workspace revisions a view over `snapshot` looks up.
///
/// A view resolves a decision's input revision and a derivation's evaluation
/// revision, so those revisions' sequences are the ones it consults, together
/// with the pinned revision itself. Records are read from the snapshot and from
/// its retained history: a decision retained only in history still has its
/// input revision looked up.
fn wanted_revisions(
    snapshot: &mneme_store::Snapshot,
    history: &std::collections::BTreeMap<
        (mneme_core::RecordId, mneme_core::RevisionId),
        mneme_core::RecordEnvelope,
    >,
) -> crate::failure::Result<std::collections::BTreeSet<mneme_core::WorkspaceRevisionId>> {
    let mut wanted = std::collections::BTreeSet::new();
    wanted.insert(snapshot.revision);
    for record in snapshot.records.iter().chain(history.values()) {
        match record.kind {
            mneme_core::RecordKind::Decision => {
                let decision = crate::model::DecisionView::parse(record.clone())?;
                wanted.insert(decision.input_revision);
            }
            mneme_core::RecordKind::Derivation => {
                let derivation = crate::model::DerivationView::parse(record.clone())?;
                wanted.insert(derivation.evaluation_revision);
            }
            mneme_core::RecordKind::Entity
            | mneme_core::RecordKind::Relation
            | mneme_core::RecordKind::Document
            | mneme_core::RecordKind::SourceRevision
            | mneme_core::RecordKind::Episode
            | mneme_core::RecordKind::Assertion
            | mneme_core::RecordKind::Evidence
            | mneme_core::RecordKind::Checkpoint
            | mneme_core::RecordKind::Proposal
            | mneme_core::RecordKind::RetentionDirective
            | mneme_core::RecordKind::DocumentBinding
            | mneme_core::RecordKind::DocumentAnchor
            | mneme_core::RecordKind::RecognitionRun
            | mneme_core::RecordKind::RecognitionSegment
            | mneme_core::RecordKind::Comment => {}
        }
    }
    Ok(wanted)
}

fn validate_batch(inputs: BatchValidationInputs<'_>) -> crate::failure::Result<()> {
    let BatchValidationInputs {
        snapshot,
        root,
        batch,
        history,
        revision_sequences,
        suppressions,
        access,
    } = inputs;
    let max_batch_records = 1_000_000;
    if snapshot.records.len().saturating_add(batch.records.len()) > max_batch_records
        || batch.source_blobs.len() > max_batch_records
    {
        return Err(crate::failure::EvidenceError::policy(
            "memory batch exceeds the 1M record or source bound",
        ));
    }
    let mut combined: std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RecordEnvelope> =
        snapshot
            .records
            .iter()
            .map(|record| (record.record_id, record.clone()))
            .collect();
    let supplied_sources = supplied_source_map(&batch.source_blobs)?;
    extend_batch_records(&mut combined, batch, access)?;
    let view = batch_view(BatchViewInputs {
        snapshot,
        root,
        combined: &combined,
        history,
        revision_sequences,
        suppressions,
        access,
    });
    let context = BatchValidation {
        access,
        batch_scope: &batch.scope,
        actor: &batch.actor,
        base: snapshot.revision,
        batch_records: batch.records.iter().map(|draft| draft.record_id).collect(),
        snapshot,
        root,
        combined,
        supplied_sources,
        view,
        validated_texts: std::cell::RefCell::new(std::collections::BTreeMap::new()),
    };
    for draft in &batch.records {
        let envelope = draft.clone().into_envelope(mneme_core::RecordedTime::new(
            mneme_core::Timestamp::from_nanos(0),
            0,
        ));
        validate_record(&envelope, &context)?;
    }
    Ok(())
}

/// The batch's supplied source bytes, bounded by its own input length.
fn supplied_source_map(
    blobs: &[mneme_store::SourceBlobDraft],
) -> crate::failure::Result<std::collections::BTreeMap<mneme_core::ContentDigest, Vec<u8>>> {
    let mut supplied_sources: std::collections::BTreeMap<mneme_core::ContentDigest, Vec<u8>> =
        std::collections::BTreeMap::new();
    let max_supplied_sources = blobs.len();
    for source in blobs {
        if !supplied_sources.contains_key(&source.digest())
            && supplied_sources.len() >= max_supplied_sources
        {
            return Err(crate::failure::EvidenceError::policy(
                "supplied source map exceeds its batch input bound",
            ));
        }
        if supplied_sources.len() >= max_supplied_sources {
            return Err(crate::failure::EvidenceError::policy(
                "supplied source map exceeds its batch input bound",
            ));
        }
        supplied_sources.insert(source.digest(), source.bytes.clone());
    }
    Ok(supplied_sources)
}

struct BatchValidationInputs<'a> {
    snapshot: &'a mneme_store::Snapshot,
    root: &'a std::path::Path,
    batch: &'a Batch,
    history: &'a std::collections::BTreeMap<
        (mneme_core::RecordId, mneme_core::RevisionId),
        mneme_core::RecordEnvelope,
    >,
    revision_sequences: &'a std::collections::BTreeMap<mneme_core::WorkspaceRevisionId, u64>,
    suppressions: &'a [mneme_store::RetentionSuppression],
    access: &'a crate::authorization::Access,
}

fn extend_batch_records(
    combined: &mut std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RecordEnvelope>,
    batch: &Batch,
    access: &crate::authorization::Access,
) -> crate::failure::Result<()> {
    for draft in &batch.records {
        let envelope = draft.clone().into_envelope(mneme_core::RecordedTime::new(
            mneme_core::Timestamp::from_nanos(0),
            0,
        ));
        if envelope.scope != batch.scope {
            return Err(crate::failure::EvidenceError::policy(format!(
                "record {} scope {} differs from batch scope {}",
                envelope.record_id, envelope.scope, batch.scope
            )));
        }
        if let Some(prior) = combined.get(&envelope.record_id)
            && prior.scope != envelope.scope
        {
            // A record may move only by an authorized hypothesis promotion:
            // the same batch must commit a cited acceptance decision and the
            // caller must be authorized for the scope it came from.
            let facts = mneme_kernel::isolation::RevisionFacts {
                same_scope: false,
                prior_class: prior.scope.class().to_kernel(),
                next_class: envelope.scope.class().to_kernel(),
                carries_acceptance: carries_acceptance_decision(batch, &envelope),
                both_authorized: access.allows(&prior.scope),
            };
            if !mneme_kernel::isolation::revision_scope_allowed(&facts) {
                return Err(crate::failure::EvidenceError::policy(
                    "a new revision may not move a record out of its scope",
                ));
            }
        }
        combined.insert(envelope.record_id, envelope);
    }
    Ok(())
}

/// Whether the batch commits an acceptance decision that this revision cites.
fn carries_acceptance_decision(batch: &Batch, envelope: &mneme_core::RecordEnvelope) -> bool {
    let Some(cited) = crate::model::optional_reference_target(envelope, "decision")
        .ok()
        .flatten()
    else {
        return false;
    };
    batch.records.iter().any(|draft| {
        draft.kind == mneme_core::RecordKind::Decision
            && draft.record_id == cited
            && crate::model::DecisionView::parse(draft.clone().into_envelope(
                mneme_core::RecordedTime::new(mneme_core::Timestamp::from_nanos(0), 0),
            ))
            .is_ok_and(|decision| {
                decision.decision_kind == crate::model::DecisionKind::Acceptance
                    && decision.outcome == "accepted"
                    && decision.target == envelope.record_id
            })
    })
}

#[allow(unknown_lints)] // Octet structural exception: parameter group mirrors one cohesive context
fn batch_view(inputs: BatchViewInputs<'_>) -> crate::beliefs::View {
    let BatchViewInputs {
        snapshot,
        root,
        combined,
        history,
        revision_sequences,
        suppressions,
        access,
    } = inputs;
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
    crate::beliefs::View::with_retention(
        virtual_snapshot,
        root,
        history.clone(),
        revision_sequences.clone(),
        suppressions.to_vec(),
    )
    .with_access(access.clone())
}

struct BatchViewInputs<'a> {
    snapshot: &'a mneme_store::Snapshot,
    root: &'a std::path::Path,
    combined: &'a std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RecordEnvelope>,
    history: &'a std::collections::BTreeMap<
        (mneme_core::RecordId, mneme_core::RevisionId),
        mneme_core::RecordEnvelope,
    >,
    revision_sequences: &'a std::collections::BTreeMap<mneme_core::WorkspaceRevisionId, u64>,
    suppressions: &'a [mneme_store::RetentionSuppression],
    access: &'a crate::authorization::Access,
}

struct BatchValidation<'a> {
    access: &'a crate::authorization::Access,
    batch_scope: &'a mneme_core::ScopeId,
    actor: &'a str,
    base: mneme_core::WorkspaceRevisionId,
    batch_records: std::collections::BTreeSet<mneme_core::RecordId>,
    snapshot: &'a mneme_store::Snapshot,
    root: &'a std::path::Path,
    combined: std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RecordEnvelope>,
    supplied_sources: std::collections::BTreeMap<mneme_core::ContentDigest, Vec<u8>>,
    view: crate::beliefs::View,
    /// Text already read and checked as UTF-8 in this batch, by digest, so
    /// many segments over one text read it once.
    validated_texts:
        std::cell::RefCell<std::collections::BTreeMap<mneme_core::ContentDigest, std::rc::Rc<str>>>,
}

/// Refusal text for a reference that is missing or outside the caller's
/// access. Both cases are reported identically, so a response cannot confirm
/// that another scope holds a record.
const UNAVAILABLE_REFERENCE: &str = "a referenced record is missing or unavailable";

/// Refusal text for a reference the caller may resolve but the isolation rules
/// forbid. It names scope classes, never a record identifier.
const INADMISSIBLE_REFERENCE: &str = "a record may not reference a record of that scope";

impl BatchValidation<'_> {
    /// The envelopes of this batch's own records.
    fn batch_envelopes(&self) -> impl Iterator<Item = &mneme_core::RecordEnvelope> {
        self.batch_records
            .iter()
            .filter_map(|record_id| self.combined.get(record_id))
    }
}

impl BatchValidation<'_> {
    /// Whether the caller is authorized for a scope. The batch's own scope is
    /// always authorized: authorization for it precedes the engine.
    fn allows(&self, scope: &mneme_core::ScopeId) -> bool {
        self.access.allows(scope) || scope == self.batch_scope
    }

    /// The committed revision of a record, if the workspace already holds one.
    fn committed(&self, record: mneme_core::RecordId) -> Option<&mneme_core::RecordEnvelope> {
        self.snapshot
            .records
            .iter()
            .find(|candidate| candidate.record_id == record)
    }

    /// Resolve one reference from `owner` under the isolation rules.
    fn reference(
        &self,
        owner: &mneme_core::RecordEnvelope,
        target: mneme_core::RecordId,
    ) -> crate::failure::Result<&mneme_core::RecordEnvelope> {
        let Some(record) = self.combined.get(&target) else {
            return Err(crate::failure::EvidenceError::policy(UNAVAILABLE_REFERENCE));
        };
        if !self.allows(&record.scope) {
            return Err(crate::failure::EvidenceError::policy(UNAVAILABLE_REFERENCE));
        }
        let facts = mneme_kernel::isolation::ReferenceFacts {
            same_scope: record.scope == owner.scope,
            source_class: owner.scope.class().to_kernel(),
            target_class: record.scope.class().to_kernel(),
            target_authorized: self.allows(&record.scope),
        };
        if !mneme_kernel::isolation::reference_allowed(&facts) {
            return Err(crate::failure::EvidenceError::policy(
                INADMISSIBLE_REFERENCE,
            ));
        }
        Ok(record)
    }

    /// Whether a record is an intent or attempt episode.
    fn is_action_episode(&self, record: mneme_core::RecordId) -> bool {
        self.combined
            .get(&record)
            .and_then(|record| crate::model::EpisodeView::parse(record.clone()).ok())
            .is_some_and(|episode| {
                matches!(
                    episode.episode_type,
                    crate::model::EpisodeType::Intent | crate::model::EpisodeType::Attempt
                )
            })
    }
}

fn validate_record(
    envelope: &mneme_core::RecordEnvelope,
    context: &BatchValidation<'_>,
) -> crate::failure::Result<()> {
    match envelope.kind {
        mneme_core::RecordKind::Evidence => validate_evidence(envelope, context),
        mneme_core::RecordKind::Assertion => validate_assertion(envelope, context),
        mneme_core::RecordKind::Decision => validate_decision(envelope, context),
        mneme_core::RecordKind::Derivation => validate_derivation(envelope, context),
        mneme_core::RecordKind::Episode => validate_episode(envelope, context),
        mneme_core::RecordKind::Checkpoint => validate_checkpoint(envelope, context),
        mneme_core::RecordKind::SourceRevision => validate_source_revision(envelope, context),
        mneme_core::RecordKind::RecognitionRun => validate_recognition_run(envelope, context),
        mneme_core::RecordKind::RecognitionSegment => {
            validate_recognition_segment(envelope, context)
        }
        _ => Ok(()),
    }
}

fn validate_evidence(
    envelope: &mneme_core::RecordEnvelope,
    context: &BatchValidation<'_>,
) -> crate::failure::Result<()> {
    let evidence = crate::model::EvidenceView::parse(envelope.clone())?;
    if context
        .view
        .suppression_for(envelope)
        .is_some_and(|suppression| suppression.mode == mneme_store::SuppressionMode::Withdrawn)
    {
        return Err(crate::failure::EvidenceError::policy(
            "a withdrawn evidence record cannot be newly cited",
        ));
    }
    // Evidence pins the exact source revision it cites: an unpinned reference
    // would resolve to whatever revision is current, silently changing the
    // quotation under the recorded span.
    if !matches!(
        &evidence.source_reference,
        mneme_core::Reference::Pinned { .. }
    ) {
        return Err(crate::failure::EvidenceError::policy(
            "evidence must pin the exact source revision it cites",
        ));
    }
    let assertion = context.reference(&evidence.record, evidence.assertion)?;
    if assertion.kind != mneme_core::RecordKind::Assertion {
        return Err(crate::failure::EvidenceError::policy(
            "evidence must reference an assertion record",
        ));
    }
    context.reference(&evidence.record, evidence.source)?;
    for ancestor in &evidence.ancestry {
        context.reference(&evidence.record, *ancestor)?;
    }
    let source = context.view.evidence_source(&evidence).map_err(|_| {
        crate::failure::EvidenceError::policy("evidence references a missing source revision")
    })?;
    if let mneme_core::Reference::Pinned { revision, .. } = evidence.source_reference
        && revision != source.record.revision_id
    {
        return Err(crate::failure::EvidenceError::policy(
            "evidence references a missing source revision",
        ));
    }
    let bytes = source_bytes(&source, &context.supplied_sources, context.root)?;
    validate_evidence_extent(&evidence, &bytes)?;
    context.view.evidence_roots(evidence.record.record_id)?;
    Ok(())
}

fn validate_evidence_extent(
    evidence: &crate::model::EvidenceView,
    bytes: &[u8],
) -> crate::failure::Result<()> {
    if evidence.span.is_none() && evidence.anchor.is_none() {
        return Err(crate::failure::EvidenceError::policy(
            "evidence requires an exact span or a stable anchor",
        ));
    }
    if let Some(span) = evidence.span {
        // The citation's end offset is inclusive; the kernel span is half-open,
        // so a citation ending at the last source byte has `stop == len`.
        let is_within = span.end().checked_add(1).is_some_and(|stop| {
            mneme_kernel::extent::span_in_text(span.start(), stop, bytes.len() as u64)
        });
        if !is_within {
            return Err(crate::failure::EvidenceError::policy(
                "evidence span ends beyond the retained source",
            ));
        }
    }
    if let Some(anchor) = &evidence.anchor
        && anchor.trim().is_empty()
    {
        return Err(crate::failure::EvidenceError::policy(
            "evidence anchor must not be empty",
        ));
    }
    Ok(())
}

fn validate_assertion(
    envelope: &mneme_core::RecordEnvelope,
    context: &BatchValidation<'_>,
) -> crate::failure::Result<()> {
    let assertion = crate::model::AssertionView::parse(envelope.clone())?;
    validate_assertion_lifecycle(&assertion, context)?;
    validate_assertion_origin(&assertion)?;
    if assertion.claim_type == crate::model::ClaimType::ActionCompleted
        && !observed_outcome_linked(&assertion, context)?
    {
        return Err(crate::failure::EvidenceError::policy(
            "a completed-action assertion requires an observed outcome episode",
        ));
    }
    validate_negative_assertion(&assertion)?;
    context.reference(&assertion.record, assertion.subject)?;
    if let Some(superseded_by) = assertion.superseded_by {
        context.reference(&assertion.record, superseded_by)?;
    }
    for evidence in &assertion.evidence {
        let record = context.reference(&assertion.record, *evidence)?;
        if record.kind != mneme_core::RecordKind::Evidence {
            return Err(crate::failure::EvidenceError::policy(
                "assertion evidence must reference evidence records",
            ));
        }
    }
    validate_assertion_evidence(&assertion, context)?;
    Ok(())
}

/// Whether the cited evidence establishes an observed outcome of the action.
///
/// Only an outcome episode counts: an observation, attempt or intent cannot
/// stand in for a result, and the outcome must name the intent or attempt it
/// concludes, so an unrelated observation or result cannot supply provenance.
fn observed_outcome_linked(
    assertion: &crate::model::AssertionView,
    context: &BatchValidation<'_>,
) -> crate::failure::Result<bool> {
    for evidence_id in &assertion.evidence {
        let Some(record) = context.combined.get(evidence_id) else {
            continue;
        };
        let Ok(evidence) = crate::model::EvidenceView::parse(record.clone()) else {
            continue;
        };
        for ancestor in &evidence.ancestry {
            let Some(record) = context.combined.get(ancestor) else {
                continue;
            };
            let Ok(episode) = crate::model::EpisodeView::parse(record.clone()) else {
                continue;
            };
            if episode.episode_type == crate::model::EpisodeType::Outcome
                && episode
                    .related
                    .iter()
                    .any(|related| context.is_action_episode(*related))
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Decide one assertion revision's lifecycle with the kernel.
///
/// The prior lifecycle comes from the record's committed revision (or nothing
/// for a new record), and every cited decision must be made by the committing
/// actor against exactly the revision this batch replaces. A decision
/// committed earlier therefore cannot promote later content, a lost
/// acceptance cannot be forged, and a retracted assertion stays retracted.
fn validate_assertion_lifecycle(
    assertion: &crate::model::AssertionView,
    context: &BatchValidation<'_>,
) -> crate::failure::Result<()> {
    let prior = context
        .committed(assertion.record.record_id)
        .and_then(mneme_core::RecordEnvelope::assertion_lifecycle);
    let cited = match assertion.decision {
        Some(decision_id) => Some(cited_decision(assertion, decision_id, context)?),
        None => None,
    };
    let commit = mneme_kernel::claim::CommitTimeFacts {
        decision_in_batch: assertion
            .decision
            .is_some_and(|decision| context.batch_records.contains(&decision)),
        actor_is_committer: assertion
            .decision
            .is_some_and(|decision| decision_actor_is(decision, context)),
    };
    let is_admissible = mneme_kernel::claim::revision_admissible(
        prior.map(mneme_core::Lifecycle::to_kernel),
        assertion.lifecycle.to_kernel(),
        &cited,
        &commit,
    );
    if !is_admissible {
        return Err(crate::failure::EvidenceError::policy(
            "assertion revision is not an admissible lifecycle transition",
        ));
    }
    Ok(())
}

/// The facts the lifecycle kernel needs about the decision an assertion cites.
fn cited_decision(
    assertion: &crate::model::AssertionView,
    decision_id: mneme_core::RecordId,
    context: &BatchValidation<'_>,
) -> crate::failure::Result<mneme_kernel::claim::CitedDecision> {
    let record = context.reference(&assertion.record, decision_id)?;
    let decision = crate::model::DecisionView::parse(record.clone())?;
    let kind = kernel_decision_kind(&decision.decision_kind).ok_or_else(|| {
        crate::failure::EvidenceError::policy("unknown decision kind cannot be committed")
    })?;
    Ok(mneme_kernel::claim::CitedDecision {
        kind,
        outcome_matches: Some(decision.outcome.as_str()) == lifecycle_outcome(assertion.lifecycle),
        targets_assertion: decision.target == assertion.record.record_id,
        binds_replaced_revision: decision.input_revision == context.base,
    })
}

/// The outcome word a revision in this lifecycle must record.
fn lifecycle_outcome(lifecycle: mneme_core::Lifecycle) -> Option<&'static str> {
    match lifecycle {
        mneme_core::Lifecycle::Proposed => None,
        mneme_core::Lifecycle::Accepted => Some("accepted"),
        mneme_core::Lifecycle::Disputed => Some("disputed"),
        mneme_core::Lifecycle::Superseded => Some("superseded"),
        mneme_core::Lifecycle::Retracted => Some("retracted"),
    }
}

/// The kernel decision kind for a parsed decision, or nothing when unknown.
fn kernel_decision_kind(
    kind: &crate::model::DecisionKind,
) -> Option<mneme_kernel::claim::DecisionKind> {
    match kind {
        crate::model::DecisionKind::Acceptance => {
            Some(mneme_kernel::claim::DecisionKind::Acceptance)
        }
        crate::model::DecisionKind::ConflictResolution => {
            Some(mneme_kernel::claim::DecisionKind::ConflictResolution)
        }
        crate::model::DecisionKind::Retraction => {
            Some(mneme_kernel::claim::DecisionKind::Retraction)
        }
        crate::model::DecisionKind::Supersession => {
            Some(mneme_kernel::claim::DecisionKind::Supersession)
        }
        crate::model::DecisionKind::Other(_) => None,
    }
}

/// Whether the cited decision record was made by the committing actor.
fn decision_actor_is(decision: mneme_core::RecordId, context: &BatchValidation<'_>) -> bool {
    context
        .combined
        .get(&decision)
        .and_then(|record| crate::model::DecisionView::parse(record.clone()).ok())
        .is_some_and(|decision| decision.actor == context.actor)
}

/// Additional evidence every claim needs beyond an ordinary authored claim.
fn validate_assertion_origin(
    assertion: &crate::model::AssertionView,
) -> crate::failure::Result<()> {
    if assertion.origin != mneme_core::Origin::ModelExtraction {
        return Ok(());
    }
    if assertion.extraction.is_none() {
        return Err(crate::failure::EvidenceError::policy(
            "a model-extracted assertion must retain extraction lineage",
        ));
    }
    if assertion.evidence.is_empty() {
        return Err(crate::failure::EvidenceError::policy(
            "a model-extracted assertion requires input evidence",
        ));
    }
    Ok(())
}

fn validate_assertion_evidence(
    assertion: &crate::model::AssertionView,
    context: &BatchValidation<'_>,
) -> crate::failure::Result<()> {
    for evidence_id in &assertion.evidence {
        if let Ok(evidence_record) = context.view.envelope(*evidence_id)
            && context
                .view
                .suppression_for(evidence_record)
                .is_some_and(|suppression| {
                    suppression.mode == mneme_store::SuppressionMode::Withdrawn
                })
        {
            return Err(crate::failure::EvidenceError::policy(format!(
                "assertion {} cites withdrawn evidence {evidence_id}",
                assertion.record.record_id
            )));
        }
    }
    Ok(())
}

fn validate_negative_assertion(
    assertion: &crate::model::AssertionView,
) -> crate::failure::Result<()> {
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
            return Err(crate::failure::EvidenceError::policy(format!(
                "accepted negative assertion {} lacks a declared-complete basis",
                assertion.record.record_id
            )));
        }
    }
    Ok(())
}

fn validate_decision(
    envelope: &mneme_core::RecordEnvelope,
    context: &BatchValidation<'_>,
) -> crate::failure::Result<()> {
    let decision = crate::model::DecisionView::parse(envelope.clone())?;
    if decision.actor.trim().is_empty() || decision.policy.trim().is_empty() {
        return Err(crate::failure::EvidenceError::policy(
            "decision actor and policy must be non-empty",
        ));
    }
    // Attribution is a property of the committing principal, not of free text
    // a client supplies: a decision made in another actor's name is refused.
    if decision.actor != context.actor {
        return Err(crate::failure::EvidenceError::policy(
            "a decision must be made by the actor committing the batch",
        ));
    }
    if kernel_decision_kind(&decision.decision_kind).is_none() {
        return Err(crate::failure::EvidenceError::policy(
            "unknown decision kind cannot be committed",
        ));
    }
    if decision.input_revision != context.base {
        return Err(crate::failure::EvidenceError::policy(format!(
            "decision {} evaluates revision {}, not the current base {}",
            decision.record.record_id, decision.input_revision, context.base
        )));
    }
    let target = decision_target(&decision, context)?;
    if target.decision != Some(decision.record.record_id) {
        return Err(crate::failure::EvidenceError::policy(
            "decision is not linked from its target assertion",
        ));
    }
    validate_decision_outcome(&decision, &target)?;
    for evidence in &decision.evidence {
        context.reference(&decision.record, *evidence)?;
    }
    for related in &decision.related {
        context.reference(&decision.record, *related)?;
    }
    Ok(())
}

fn decision_target(
    decision: &crate::model::DecisionView,
    context: &BatchValidation<'_>,
) -> crate::failure::Result<crate::model::AssertionView> {
    let envelope = context.reference(&decision.record, decision.target)?;
    if envelope.kind != mneme_core::RecordKind::Assertion {
        return Err(crate::failure::EvidenceError::policy(
            "a decision must target an assertion record",
        ));
    }
    crate::model::AssertionView::parse(envelope.clone())
}

fn validate_decision_outcome(
    decision: &crate::model::DecisionView,
    target: &crate::model::AssertionView,
) -> crate::failure::Result<()> {
    let expected = match decision.decision_kind {
        crate::model::DecisionKind::Acceptance => (mneme_core::Lifecycle::Accepted, "accepted"),
        crate::model::DecisionKind::Retraction => (mneme_core::Lifecycle::Retracted, "retracted"),
        crate::model::DecisionKind::Supersession => {
            (mneme_core::Lifecycle::Superseded, "superseded")
        }
        crate::model::DecisionKind::ConflictResolution => {
            (mneme_core::Lifecycle::Disputed, "disputed")
        }
        crate::model::DecisionKind::Other(_) => {
            return Err(crate::failure::EvidenceError::policy(
                "unknown decision kind cannot be committed",
            ));
        }
    };
    if target.lifecycle != expected.0 || decision.outcome != expected.1 {
        return Err(crate::failure::EvidenceError::policy(format!(
            "decision {} outcome {} does not match target lifecycle {}",
            decision.record.record_id,
            decision.outcome,
            target.lifecycle.symbol()
        )));
    }
    Ok(())
}

fn validate_derivation(
    envelope: &mneme_core::RecordEnvelope,
    context: &BatchValidation<'_>,
) -> crate::failure::Result<()> {
    let derivation = crate::model::DerivationView::parse(envelope.clone())?;
    if derivation.evaluation_revision != context.base {
        return Err(crate::failure::EvidenceError::policy(format!(
            "derivation {} evaluates revision {}, not the current base {}",
            derivation.record.record_id, derivation.evaluation_revision, context.base
        )));
    }
    let conclusion = context.reference(&derivation.record, derivation.conclusion)?;
    if conclusion.kind != mneme_core::RecordKind::Assertion {
        return Err(crate::failure::EvidenceError::policy(
            "a derivation must conclude an assertion record",
        ));
    }
    // A justification its author declared incomplete cannot be the basis of an
    // accepted conclusion; it may only accompany a proposed one.
    let conclusion = crate::model::AssertionView::parse(conclusion.clone())?;
    if !derivation.is_complete() && conclusion.lifecycle == mneme_core::Lifecycle::Accepted {
        return Err(crate::failure::EvidenceError::policy(
            "an incomplete derivation cannot support an accepted conclusion",
        ));
    }
    for premise in &derivation.premises {
        context.reference(&derivation.record, *premise)?;
    }
    Ok(())
}

fn validate_episode(
    envelope: &mneme_core::RecordEnvelope,
    context: &BatchValidation<'_>,
) -> crate::failure::Result<()> {
    let episode = crate::model::EpisodeView::parse(envelope.clone())?;
    if let Some(source) = episode.source {
        context.reference(&episode.record, source)?;
    }
    for related in &episode.related {
        context.reference(&episode.record, *related)?;
    }
    Ok(())
}

fn validate_checkpoint(
    envelope: &mneme_core::RecordEnvelope,
    context: &BatchValidation<'_>,
) -> crate::failure::Result<()> {
    let (revision, episodes, verified) = context.view.checkpoint_revision(envelope.record_id)?;
    if revision != context.base {
        return Err(crate::failure::EvidenceError::policy(format!(
            "checkpoint {} references revision {revision}, not the current base {}",
            envelope.record_id, context.base
        )));
    }
    for linked in &episodes {
        context.reference(envelope, *linked)?;
    }
    for linked in &verified {
        let record = context.reference(envelope, *linked)?;
        let episode = crate::model::EpisodeView::parse(record.clone())?;
        if episode.episode_type != crate::model::EpisodeType::Outcome {
            return Err(crate::failure::EvidenceError::policy(
                "a checkpoint verified outcome must be an outcome episode",
            ));
        }
    }
    Ok(())
}

fn validate_source_revision(
    envelope: &mneme_core::RecordEnvelope,
    context: &BatchValidation<'_>,
) -> crate::failure::Result<()> {
    let source = crate::model::SourceView::parse(envelope.clone())?;
    let pin = mneme_core::SourcePin::new(envelope.record_id, envelope.revision_id);
    validate_source_acquisition(&source, pin, envelope, context)?;
    validate_source_parent(&source, pin, envelope, context)
}

fn validate_source_acquisition(
    source: &crate::model::SourceView,
    pin: mneme_core::SourcePin,
    envelope: &mneme_core::RecordEnvelope,
    context: &BatchValidation<'_>,
) -> crate::failure::Result<()> {
    match source.acquisition {
        mneme_core::Acquisition::MachineRecognized => {
            validate_machine_recognized_source(source, pin, envelope, context)?;
        }
        mneme_core::Acquisition::Corrected => {
            validate_corrected_source(source, pin, envelope, context)?
        }
        mneme_core::Acquisition::Derived => {
            if source.correction.is_some() {
                return Err(crate::failure::EvidenceError::policy(
                    "correction provenance requires corrected acquisition",
                ));
            }
            validate_derived_source(source, envelope)?;
        }
        _ => {
            if source.correction.is_some() {
                return Err(crate::failure::EvidenceError::policy(
                    "correction provenance requires corrected acquisition",
                ));
            }
        }
    }
    if source.acquisition == mneme_core::Acquisition::MachineRecognized
        && source
            .derived_from
            .is_some_and(|parent| parent.source() == envelope.record_id)
    {
        return Err(crate::failure::EvidenceError::policy(
            "reprocessing must create a separate recognition output and never overwrite text",
        ));
    }
    Ok(())
}

/// A derived source names an upstream source revision that is not itself and
/// matches its `derived-from` pin. Existence, scope and availability of that
/// revision are checked with the other source parents.
fn validate_derived_source(
    source: &crate::model::SourceView,
    envelope: &mneme_core::RecordEnvelope,
) -> crate::failure::Result<()> {
    let Some(derivation) = &source.derivation else {
        return Err(crate::failure::EvidenceError::policy(
            "derived acquisition requires source, backend and backend-version",
        ));
    };
    if source.derived_from != Some(derivation.source()) {
        return Err(crate::failure::EvidenceError::policy(
            "derived acquisition source must equal the derived-from pin",
        ));
    }
    if derivation.source().source() == envelope.record_id {
        return Err(crate::failure::EvidenceError::policy(
            "a derived source cannot be a revision of its own upstream source",
        ));
    }
    Ok(())
}

fn validate_machine_recognized_source(
    source: &crate::model::SourceView,
    pin: mneme_core::SourcePin,
    envelope: &mneme_core::RecordEnvelope,
    context: &BatchValidation<'_>,
) -> crate::failure::Result<()> {
    if source.derived_from.is_none() || envelope.predecessor.is_some() {
        return Err(crate::failure::EvidenceError::policy(
            "machine recognition must create a new text record pinned to its exact input",
        ));
    }
    validate_utf8_text_source(source, context)?;
    let has_run = context.batch_envelopes().any(|record| {
        record.kind == mneme_core::RecordKind::RecognitionRun
            && crate::model::RecognitionRunView::parse(record.clone())
                .is_ok_and(|run| run.output == pin && Some(run.input) == source.derived_from)
    });
    if has_run {
        Ok(())
    } else {
        Err(crate::failure::EvidenceError::policy(
            "machine-recognized text must be bound to a recognition run in the same batch",
        ))
    }
}

fn validate_corrected_source(
    source: &crate::model::SourceView,
    pin: mneme_core::SourcePin,
    envelope: &mneme_core::RecordEnvelope,
    context: &BatchValidation<'_>,
) -> crate::failure::Result<()> {
    let Some(parent) = source.derived_from else {
        return Err(crate::failure::EvidenceError::policy(
            "a correction must pin its exact predecessor source revision",
        ));
    };
    if parent.source() != envelope.record_id || envelope.predecessor != Some(parent.revision()) {
        return Err(crate::failure::EvidenceError::policy(
            "a correction must be a new revision of the same source record",
        ));
    }
    let correction = source.correction.as_ref().ok_or_else(|| {
        crate::failure::EvidenceError::policy("correction provenance is required")
    })?;
    validate_utf8_text_source(source, context)?;
    validate_correction_alignment(pin, correction, context)
}

fn validate_source_parent(
    source: &crate::model::SourceView,
    pin: mneme_core::SourcePin,
    envelope: &mneme_core::RecordEnvelope,
    context: &BatchValidation<'_>,
) -> crate::failure::Result<()> {
    let Some(parent) = source.derived_from else {
        return Ok(());
    };
    if parent == pin {
        return Err(crate::failure::EvidenceError::policy(
            "a source transformation cannot depend on itself",
        ));
    }
    let parent_record = context.reference(envelope, parent.source())?;
    if parent_record.kind != mneme_core::RecordKind::SourceRevision
        || parent_record.scope != envelope.scope
    {
        return Err(crate::failure::EvidenceError::policy(
            "source transformation parent must be an exact source revision in the same scope",
        ));
    }
    let parent_view = context
        .view
        .source_at(parent.source(), parent.revision())
        .map_err(|_| {
            crate::failure::EvidenceError::policy(
                "source transformation parent revision is unavailable",
            )
        })?;
    if parent_view.record.scope != envelope.scope {
        return Err(crate::failure::EvidenceError::policy(
            "source transformation parent must be in the same scope",
        ));
    }
    context.view.source_roots(parent)?;
    if source.media_transform.is_some() && source.media_extent.is_none() {
        return Err(crate::failure::EvidenceError::policy(
            "a transformed media source must declare its coordinate extent",
        ));
    }
    // A transform maps the derivative's own frame onto its parent's, page for
    // page: it carries no page offset, so the page extents must agree.
    if let Some(transform) = source.media_transform
        && (source.media_frame != Some(transform.from_frame())
            || parent_view.media_frame != Some(transform.to_frame()))
    {
        return Err(crate::failure::EvidenceError::policy(
            "a media transform must map the derivative's declared frame onto its parent's",
        ));
    }
    if source.media_transform.is_some() && source.media_extent != parent_view.media_extent {
        return Err(crate::failure::EvidenceError::policy(
            "a transformed media source must keep its parent's pages",
        ));
    }
    Ok(())
}

fn validate_utf8_text_source(
    source: &crate::model::SourceView,
    context: &BatchValidation<'_>,
) -> crate::failure::Result<std::rc::Rc<str>> {
    if !source
        .media_type
        .as_ref()
        .is_some_and(|media_type| media_type.as_str().starts_with("text/"))
    {
        return Err(crate::failure::EvidenceError::policy(
            "recognized and corrected source revisions must have a text media type",
        ));
    }
    if let Some(digest) = source.digest()
        && let Some(text) = context.validated_texts.borrow().get(&digest)
    {
        return Ok(std::rc::Rc::clone(text));
    }
    let bytes = source_bytes(source, &context.supplied_sources, context.root)?;
    let text: std::rc::Rc<str> = String::from_utf8(bytes)
        .map_err(|_| {
            crate::failure::EvidenceError::policy(
                "recognized and corrected text must be valid UTF-8",
            )
        })?
        .into();
    if let Some(digest) = source.digest() {
        context
            .validated_texts
            .borrow_mut()
            .insert(digest, std::rc::Rc::clone(&text));
    }
    Ok(text)
}

fn validate_correction_alignment(
    pin: mneme_core::SourcePin,
    correction: &mneme_core::CorrectionProvenance,
    context: &BatchValidation<'_>,
) -> crate::failure::Result<()> {
    let has_aligned_segment = context.batch_envelopes().any(|record| {
        record.kind == mneme_core::RecordKind::RecognitionSegment
            && crate::model::RecognitionSegmentView::parse(record.clone())
                .is_ok_and(|segment| segment.text_source == pin && segment.run.is_none())
    });
    if has_aligned_segment != correction.alignment_updated() {
        return Err(crate::failure::EvidenceError::policy(
            if correction.alignment_updated() {
                "a corrected source declaring updated alignment must commit new aligned segments"
            } else {
                "a corrected source declaring invalidated alignment must not commit replacement segments"
            },
        ));
    }
    Ok(())
}

/// A raw run draft is held to the builders' segment bound, since a longer run
/// could never be read back, and commits the text it produced: a later run
/// cannot claim text another run produced.
fn validate_run_bounds(
    run: &crate::model::RecognitionRunView,
    context: &BatchValidation<'_>,
) -> crate::failure::Result<()> {
    if run.segments.len() > mneme_core::MAX_RECOGNITION_SEGMENTS {
        return Err(crate::failure::EvidenceError::policy(
            "a recognition run names more segments than its bound",
        ));
    }
    if !context.batch_records.contains(&run.output.source()) {
        return Err(crate::failure::EvidenceError::policy(
            "a recognition run's text must be committed in the run's own batch",
        ));
    }
    Ok(())
}

fn validate_recognition_run(
    envelope: &mneme_core::RecordEnvelope,
    context: &BatchValidation<'_>,
) -> crate::failure::Result<()> {
    let run = crate::model::RecognitionRunView::parse(envelope.clone())?;
    validate_run_bounds(&run, context)?;
    let input_record = context.reference(envelope, run.input.source())?;
    let output_record = context.reference(envelope, run.output.source())?;
    if input_record.kind != mneme_core::RecordKind::SourceRevision
        || output_record.kind != mneme_core::RecordKind::SourceRevision
        || input_record.scope != envelope.scope
        || output_record.scope != envelope.scope
    {
        return Err(crate::failure::EvidenceError::policy(
            "recognition input and output sources must be in the run scope",
        ));
    }
    let input = context
        .view
        .source_at(run.input.source(), run.input.revision())
        .map_err(|_| {
            crate::failure::EvidenceError::policy(
                "recognition input source revision is unavailable",
            )
        })?;
    let output = context
        .view
        .source_at(run.output.source(), run.output.revision())
        .map_err(|_| {
            crate::failure::EvidenceError::policy(
                "recognition output source revision is unavailable",
            )
        })?;
    if source_digest(&input) != Some(run.input_digest)
        || source_digest(&output) != Some(run.output_digest)
        || output.acquisition != mneme_core::Acquisition::MachineRecognized
        || output.derived_from != Some(run.input)
    {
        return Err(crate::failure::EvidenceError::policy(
            "recognition run pins must match the exact media input and machine-produced text output",
        ));
    }
    let extent = input.media_extent.ok_or_else(|| {
        crate::failure::EvidenceError::policy("recognition input must declare a typed media extent")
    })?;
    run.covers
        .validate_extent(extent)
        .and_then(|()| {
            run.page.as_ref().map_or(Ok(()), |page| {
                page.validate_source(extent, input.media_frame, run.covers)
            })
        })
        .map_err(|message| crate::failure::EvidenceError::policy(message.to_owned()))?;
    let output_text = validate_utf8_text_source(&output, context)?;
    if mneme_core::ContentDigest::of_source_bytes(output_text.as_bytes()) != run.output_digest {
        return Err(crate::failure::EvidenceError::policy(
            "recognition output digest does not match its exact text bytes",
        ));
    }
    if context.view.source_roots(run.input)? != context.view.source_roots(run.output)? {
        return Err(crate::failure::EvidenceError::policy(
            "recognition output must retain the input source's evidence root",
        ));
    }
    validate_run_segments(envelope, &run, context)
}

/// Every segment a run names maps the run's exact output and lies within the
/// part of the input it covers.
fn validate_run_segments(
    envelope: &mneme_core::RecordEnvelope,
    run: &crate::model::RecognitionRunView,
    context: &BatchValidation<'_>,
) -> crate::failure::Result<()> {
    for segment_id in &run.segments {
        let segment = context.view.recognition_segment(*segment_id).map_err(|_| {
            crate::failure::EvidenceError::policy("recognition run segment is missing")
        })?;
        if segment.run != Some(envelope.record_id) || segment.text_source != run.output {
            return Err(crate::failure::EvidenceError::policy(
                "recognition run segment must map the run's exact output text revision",
            ));
        }
        // A segment on a processed derivative uses the derivative's own
        // frame; only one on the input itself is checked against the part.
        if segment.media_source == run.input && !run.covers.holds(&segment.location) {
            return Err(crate::failure::EvidenceError::policy(
                "recognition run segment lies outside the part of the input the run covers",
            ));
        }
    }
    Ok(())
}

fn validate_recognition_segment(
    envelope: &mneme_core::RecordEnvelope,
    context: &BatchValidation<'_>,
) -> crate::failure::Result<()> {
    let segment = crate::model::RecognitionSegmentView::parse(envelope.clone())?;
    validate_segment_source_records(envelope, &segment, context)?;
    let text = context
        .view
        .source_at(segment.text_source.source(), segment.text_source.revision())
        .map_err(|_| {
            crate::failure::EvidenceError::policy(
                "recognition segment text source revision is unavailable",
            )
        })?;
    let media = context
        .view
        .source_at(
            segment.media_source.source(),
            segment.media_source.revision(),
        )
        .map_err(|_| {
            crate::failure::EvidenceError::policy(
                "recognition segment media source revision is unavailable",
            )
        })?;
    validate_segment_media_location(&segment, &media)?;
    let content = validate_utf8_text_source(&text, context)?;
    validate_utf8_span(segment.text_span, &content)?;
    validate_segment_lineage(envelope, &segment, &text, context)
}

fn validate_segment_source_records(
    envelope: &mneme_core::RecordEnvelope,
    segment: &crate::model::RecognitionSegmentView,
    context: &BatchValidation<'_>,
) -> crate::failure::Result<()> {
    let text_record = context.reference(envelope, segment.text_source.source())?;
    let media_record = context.reference(envelope, segment.media_source.source())?;
    if text_record.kind != mneme_core::RecordKind::SourceRevision
        || media_record.kind != mneme_core::RecordKind::SourceRevision
        || text_record.scope != envelope.scope
        || media_record.scope != envelope.scope
    {
        return Err(crate::failure::EvidenceError::policy(
            "recognition segment sources must be source revisions in the segment scope",
        ));
    }
    Ok(())
}

fn validate_segment_media_location(
    segment: &crate::model::RecognitionSegmentView,
    media: &crate::model::SourceView,
) -> crate::failure::Result<()> {
    if source_digest(media) != Some(segment.media_digest) {
        return Err(crate::failure::EvidenceError::policy(
            "recognition segment media digest does not match its pinned source",
        ));
    }
    let extent = media.media_extent.ok_or_else(|| {
        crate::failure::EvidenceError::policy(
            "recognition segment source lacks a typed media extent",
        )
    })?;
    segment
        .location
        .validate_source(extent, media.media_frame, media.ink_inventory.as_ref())
        .map_err(|message| crate::failure::EvidenceError::policy(message.to_owned()))
}

fn validate_segment_lineage(
    envelope: &mneme_core::RecordEnvelope,
    segment: &crate::model::RecognitionSegmentView,
    text: &crate::model::SourceView,
    context: &BatchValidation<'_>,
) -> crate::failure::Result<()> {
    match segment.run {
        Some(run_id) => {
            let run_record = context.reference(envelope, run_id)?;
            if run_record.kind != mneme_core::RecordKind::RecognitionRun {
                return Err(crate::failure::EvidenceError::policy(
                    "segment run reference has the wrong kind",
                ));
            }
            let run = context.view.recognition_run(run_id).map_err(|_| {
                crate::failure::EvidenceError::policy("recognition segment run is unavailable")
            })?;
            if run.output != segment.text_source || !run.segments.contains(&envelope.record_id) {
                return Err(crate::failure::EvidenceError::policy(
                    "machine segment must be declared by the run for its exact output revision",
                ));
            }
            if !source_descends_from(&context.view, segment.media_source, run.input)? {
                return Err(crate::failure::EvidenceError::policy(
                    "segment media location must pin the exact run input or its processed derivative",
                ));
            }
        }
        None => {
            if text.acquisition != mneme_core::Acquisition::Corrected
                || !text
                    .correction
                    .as_ref()
                    .is_some_and(mneme_core::CorrectionProvenance::alignment_updated)
            {
                return Err(crate::failure::EvidenceError::policy(
                    "a segment without a recognition run must align an explicitly corrected text revision",
                ));
            }
            if context.view.source_roots(segment.text_source)?
                != context.view.source_roots(segment.media_source)?
            {
                return Err(crate::failure::EvidenceError::policy(
                    "corrected alignment must preserve the media evidence root",
                ));
            }
        }
    }
    Ok(())
}

fn source_digest(source: &crate::model::SourceView) -> Option<mneme_core::ContentDigest> {
    source.digest().or(source.prior_digest)
}

/// Whether `span` lies on character boundaries of `text`, which was checked
/// as UTF-8 once when it was read.
fn validate_utf8_span(span: mneme_core::SourceSpan, text: &str) -> crate::failure::Result<()> {
    let start = usize::try_from(span.start()).ok();
    let stop = span
        .end()
        .checked_add(1)
        .and_then(|value| usize::try_from(value).ok());
    let is_valid = start
        .zip(stop)
        .is_some_and(|(start, stop)| text.get(start..stop).is_some());
    if is_valid {
        Ok(())
    } else {
        Err(crate::failure::EvidenceError::policy(
            "recognition segment byte span must lie within UTF-8 boundaries of its exact text revision",
        ))
    }
}

fn source_descends_from(
    view: &crate::beliefs::View,
    descendant: mneme_core::SourcePin,
    ancestor: mneme_core::SourcePin,
) -> crate::failure::Result<bool> {
    let mut current = descendant;
    let mut visited = std::collections::BTreeSet::new();
    for _ in 0..crate::beliefs::MAX_ANCESTRY_NODES {
        if current == ancestor {
            return Ok(true);
        }
        if !visited.insert(current) {
            return Err(crate::failure::EvidenceError::policy(
                "source transformation ancestry contains a cycle",
            ));
        }
        let source = view.source_at(current.source(), current.revision())?;
        let Some(parent) = source.derived_from else {
            return Ok(false);
        };
        current = parent;
    }
    Err(crate::failure::EvidenceError::policy(
        "source transformation ancestry exceeds its bound",
    ))
}

fn source_bytes(
    source: &crate::model::SourceView,
    supplied: &std::collections::BTreeMap<mneme_core::ContentDigest, Vec<u8>>,
    root: &std::path::Path,
) -> crate::failure::Result<Vec<u8>> {
    let Some(digest) = source.digest() else {
        return Err(crate::failure::EvidenceError::policy(
            "new evidence requires retained source bytes",
        ));
    };
    if let Some(bytes) = supplied.get(&digest) {
        return Ok(bytes.clone());
    }
    match mneme_store::payload::read(root, digest) {
        Ok(bytes) => Ok(bytes),
        Err(mneme_store::Failure::MissingBlob { .. }) => {
            Err(crate::failure::EvidenceError::policy(
                "new evidence cites a source whose committed bytes are missing",
            ))
        }
        Err(mneme_store::Failure::CorruptBlob { reason, .. }) => {
            Err(crate::failure::EvidenceError::policy(format!(
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

/// Optional source metadata used when building a retained source revision.
#[derive(Clone, Copy)]
pub struct SourceOptions<'a> {
    pub bytes: &'a [u8],
    pub media_type: &'a str,
    pub entity: Option<mneme_core::RecordId>,
    pub path_hint: Option<&'a str>,
}

/// Exact acquisition and media ancestry metadata for a retained source.
#[derive(Clone, Copy)]
pub struct SourceProvenance<'a> {
    pub acquisition: mneme_core::Acquisition,
    /// Required exactly when `acquisition` is [`mneme_core::Acquisition::Derived`].
    pub derivation: Option<&'a mneme_core::DerivedAcquisition>,
    pub derived_from: Option<mneme_core::SourcePin>,
    pub media_extent: Option<mneme_core::MediaExtent>,
    pub media_transform: Option<mneme_core::MediaTransform>,
    /// The coordinate frame a page or ink source's pages use.
    pub media_frame: Option<mneme_core::CoordinateFrame>,
    /// The stroke ids an ink source declares.
    pub ink_inventory: Option<&'a mneme_core::InkInventory>,
    pub correction: Option<&'a mneme_core::CorrectionProvenance>,
}

#[derive(Clone, Copy)]
struct SourceRevisionIdentity {
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    predecessor: Option<mneme_core::RevisionId>,
}

/// Typed recognition execution inputs and immutable output references.
pub struct RecognitionRunOptions<'a> {
    pub input: mneme_core::SourcePin,
    pub input_digest: mneme_core::ContentDigest,
    pub output: mneme_core::SourcePin,
    pub output_digest: mneme_core::ContentDigest,
    pub model: &'a str,
    pub runtime: &'a str,
    pub adapter: &'a str,
    pub preprocessing: &'a str,
    pub configuration: &'a str,
    pub segments: &'a [mneme_core::RecordId],
    pub coverage: mneme_core::RecognitionCoverage,
    pub status: mneme_core::RecognitionStatus,
    pub scores: &'a [mneme_core::RecognitionScore],
    pub alternatives: &'a [mneme_core::RecognitionAlternative],
    /// The part of the input the run covers.
    pub covers: mneme_core::CapturePart,
    /// Optional strict raster processing map, including unread regions.
    pub page: Option<&'a mneme_core::RecognitionPage>,
}

/// Typed mapping from a text byte span to one pinned media source location.
pub struct RecognitionSegmentOptions<'a> {
    /// Present for machine-produced segments; absent for a human-updated
    /// alignment belonging to a corrected source revision.
    pub run: Option<mneme_core::RecordId>,
    pub text_source: mneme_core::SourcePin,
    pub span: mneme_core::SourceSpan,
    pub media_source: mneme_core::SourcePin,
    pub media_digest: mneme_core::ContentDigest,
    pub location: &'a mneme_core::MediaLocation,
    /// Optional backend layout provenance; legacy/audio segments omit it.
    pub block: Option<&'a mneme_core::RecognitionBlock>,
}

/// Metadata for an unavailable or pruned source revision.
#[derive(Clone, Copy)]
pub struct UnavailableSourceOptions<'a> {
    pub reason: &'a str,
    pub availability: &'a str,
    pub entity: Option<mneme_core::RecordId>,
    pub path_hint: Option<&'a str>,
}

/// Metadata for an unavailable source revision, including its prior digest.
#[derive(Clone, Copy)]
pub struct UnavailableSourceWithDigestOptions<'a> {
    pub reason: &'a str,
    pub availability: &'a str,
    pub prior_digest: Option<mneme_core::ContentDigest>,
    pub entity: Option<mneme_core::RecordId>,
    pub path_hint: Option<&'a str>,
}

/// Build a retained source revision and its exact source blob.
pub fn build_source(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    options: SourceOptions<'_>,
) -> crate::failure::Result<(mneme_store::RecordDraft, mneme_store::SourceBlobDraft)> {
    let SourceOptions {
        bytes,
        media_type,
        entity,
        path_hint,
    } = options;
    let retained = mneme_core::RetainedSource::new(
        mneme_core::ContentDigest::of_source_bytes(bytes),
        bytes.len() as u64,
        media_type,
    )
    .map_err(|message| crate::failure::EvidenceError::policy(message.to_owned()))?;
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

/// Build a retained source under schema v5 with explicit acquisition and
/// transformation lineage.
pub fn build_source_with_provenance(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    options: SourceOptions<'_>,
    provenance: SourceProvenance<'_>,
) -> crate::failure::Result<(mneme_store::RecordDraft, mneme_store::SourceBlobDraft)> {
    build_source_with_provenance_and_predecessor(
        SourceRevisionIdentity {
            record_id,
            revision_id,
            predecessor: None,
        },
        scope,
        options,
        provenance,
    )
}

fn build_source_with_provenance_and_predecessor(
    identity: SourceRevisionIdentity,
    scope: &mneme_core::ScopeId,
    options: SourceOptions<'_>,
    provenance: SourceProvenance<'_>,
) -> crate::failure::Result<(mneme_store::RecordDraft, mneme_store::SourceBlobDraft)> {
    let payload = source_payload(options, provenance)?;
    debug_assert!(!options.media_type.is_empty());
    let schema_version = if provenance.acquisition == mneme_core::Acquisition::Derived {
        debug_assert!(provenance.derivation.is_some());
        mneme_core::DERIVED_ACQUISITION_SCHEMA_VERSION
    } else {
        5
    };
    Ok((
        mneme_store::RecordDraft {
            schema_version,
            kind: mneme_core::RecordKind::SourceRevision,
            record_id: identity.record_id,
            revision_id: identity.revision_id,
            predecessor: identity.predecessor,
            scope: scope.clone(),
            payload,
        },
        mneme_store::SourceBlobDraft {
            bytes: options.bytes.to_vec(),
            media_type: mneme_core::Symbol::from(options.media_type),
        },
    ))
}

fn source_payload(
    options: SourceOptions<'_>,
    provenance: SourceProvenance<'_>,
) -> crate::failure::Result<mneme_core::Payload> {
    if let Some(extent) = provenance.media_extent {
        extent
            .validate()
            .map_err(|message| crate::failure::EvidenceError::policy(message.to_owned()))?;
    }
    if let Some(transform) = provenance.media_transform {
        transform
            .validate()
            .map_err(|message| crate::failure::EvidenceError::policy(message.to_owned()))?;
    }
    if let Some(correction) = provenance.correction {
        correction
            .validate()
            .map_err(|message| crate::failure::EvidenceError::policy(message.to_owned()))?;
    }
    let retained = mneme_core::RetainedSource::new(
        mneme_core::ContentDigest::of_source_bytes(options.bytes),
        options.bytes.len() as u64,
        options.media_type,
    )
    .map_err(|message| crate::failure::EvidenceError::policy(message.to_owned()))?;
    let mut entries = Vec::with_capacity(8);
    entries.push((
        mneme_core::Symbol::from("content"),
        mneme_core::SourceContent::Retained(retained).to_value(),
    ));
    entries.push((
        mneme_core::Symbol::from("acquisition"),
        source_acquisition_value(provenance)?,
    ));
    if let Some(entity) = options.entity {
        entries.push((
            mneme_core::Symbol::from("entity"),
            reference(entity, mneme_core::RecordKind::Entity).to_value(),
        ));
    }
    if let Some(path) = options.path_hint {
        entries.push((
            mneme_core::Symbol::from("path-hint"),
            mneme_core::Value::string(path),
        ));
    }
    if let Some(parent) = provenance.derived_from {
        entries.push((mneme_core::Symbol::from("derived-from"), parent.to_value()));
    }
    if let Some(extent) = provenance.media_extent {
        entries.push((mneme_core::Symbol::from("media-extent"), extent.to_value()));
    }
    if let Some(transform) = provenance.media_transform {
        entries.push((
            mneme_core::Symbol::from("media-transform"),
            transform.to_value(),
        ));
    }
    if let Some(frame) = provenance.media_frame {
        entries.push((mneme_core::Symbol::from("media-frame"), frame.to_value()));
    }
    if let Some(inventory) = provenance.ink_inventory {
        entries.push((
            mneme_core::Symbol::from("ink-strokes"),
            inventory.to_value(),
        ));
    }
    if let Some(correction) = provenance.correction {
        entries.push((
            mneme_core::Symbol::from("correction"),
            correction.to_value(),
        ));
    }
    Ok(mneme_core::Payload::new(entries))
}

fn source_acquisition_value(
    provenance: SourceProvenance<'_>,
) -> crate::failure::Result<mneme_core::Value> {
    match (provenance.acquisition, provenance.derivation) {
        (mneme_core::Acquisition::Derived, Some(derivation)) => {
            derivation
                .validate()
                .map_err(|message| crate::failure::EvidenceError::policy(message.to_owned()))?;
            if provenance.derived_from != Some(derivation.source()) {
                return Err(crate::failure::EvidenceError::policy(
                    "derived acquisition source must equal the derived-from pin",
                ));
            }
            Ok(derivation.to_value())
        }
        (mneme_core::Acquisition::Derived, None) => Err(crate::failure::EvidenceError::policy(
            "derived acquisition requires source, backend and backend-version",
        )),
        (acquisition, None) => Ok(acquisition.to_value()),
        (_, Some(_)) => Err(crate::failure::EvidenceError::policy(
            "only a derived acquisition carries a derivation",
        )),
    }
}

/// Build a derived source: reproducible output of `backend` run over the exact
/// upstream source revision `source`. The upstream is also recorded as the
/// `derived-from` pin so lineage walks reach it.
pub fn build_derived_source(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    options: SourceOptions<'_>,
    derivation: &mneme_core::DerivedAcquisition,
) -> crate::failure::Result<(mneme_store::RecordDraft, mneme_store::SourceBlobDraft)> {
    build_source_with_provenance(
        record_id,
        revision_id,
        scope,
        options,
        SourceProvenance {
            acquisition: mneme_core::Acquisition::Derived,
            derivation: Some(derivation),
            derived_from: Some(derivation.source()),
            media_extent: None,
            media_transform: None,
            media_frame: None,
            ink_inventory: None,
            correction: None,
        },
    )
}

/// Build an explicitly captured media source with a declared typed extent.
pub fn build_captured_source(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    options: SourceOptions<'_>,
    extent: mneme_core::MediaExtent,
) -> crate::failure::Result<(mneme_store::RecordDraft, mneme_store::SourceBlobDraft)> {
    build_source_with_provenance(
        record_id,
        revision_id,
        scope,
        options,
        SourceProvenance {
            derivation: None,
            acquisition: mneme_core::Acquisition::Captured,
            derived_from: None,
            media_extent: Some(extent),
            media_transform: None,
            media_frame: None,
            ink_inventory: None,
            correction: None,
        },
    )
}

/// Build machine-recognized UTF-8 text as a new derivative of a pinned source.
pub fn build_recognized_source(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    options: SourceOptions<'_>,
    input: mneme_core::SourcePin,
) -> crate::failure::Result<(mneme_store::RecordDraft, mneme_store::SourceBlobDraft)> {
    if std::str::from_utf8(options.bytes).is_err() {
        return Err(crate::failure::EvidenceError::policy(
            "recognized text must be valid UTF-8",
        ));
    }
    let SourceOptions {
        bytes,
        entity,
        path_hint,
        ..
    } = options;
    build_source_with_provenance(
        record_id,
        revision_id,
        scope,
        SourceOptions {
            bytes,
            media_type: "text/plain; charset=utf-8",
            entity,
            path_hint,
        },
        SourceProvenance {
            derivation: None,
            acquisition: mneme_core::Acquisition::MachineRecognized,
            derived_from: Some(input),
            media_extent: None,
            media_transform: None,
            media_frame: None,
            ink_inventory: None,
            correction: None,
        },
    )
}

/// Build a human correction as an immutable new revision of the source record.
pub fn build_corrected_source(
    predecessor: mneme_core::SourcePin,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    options: SourceOptions<'_>,
    correction: &mneme_core::CorrectionProvenance,
) -> crate::failure::Result<(mneme_store::RecordDraft, mneme_store::SourceBlobDraft)> {
    if std::str::from_utf8(options.bytes).is_err() {
        return Err(crate::failure::EvidenceError::policy(
            "corrected text must be valid UTF-8",
        ));
    }
    build_source_with_provenance_and_predecessor(
        SourceRevisionIdentity {
            record_id: predecessor.source(),
            revision_id,
            predecessor: Some(predecessor.revision()),
        },
        scope,
        options,
        SourceProvenance {
            derivation: None,
            acquisition: mneme_core::Acquisition::Corrected,
            derived_from: Some(predecessor),
            media_extent: None,
            media_transform: None,
            media_frame: None,
            ink_inventory: None,
            correction: Some(correction),
        },
    )
}

/// Build a run that binds exact media/text pins, provider execution identity,
/// output coverage and declared machine-output segment ids.
pub fn build_recognition_run(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    options: RecognitionRunOptions<'_>,
) -> crate::failure::Result<mneme_store::RecordDraft> {
    validate_recognition_run_options(&options)?;
    Ok(mneme_store::RecordDraft {
        schema_version: 5,
        kind: mneme_core::RecordKind::RecognitionRun,
        record_id,
        revision_id,
        predecessor: None,
        scope: scope.clone(),
        payload: recognition_run_payload(&options),
    })
}

fn validate_recognition_run_options(
    options: &RecognitionRunOptions<'_>,
) -> crate::failure::Result<()> {
    let unique_segments = options
        .segments
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    if options.segments.len() > mneme_core::MAX_RECOGNITION_SEGMENTS
        || unique_segments != options.segments.len()
    {
        return Err(crate::failure::EvidenceError::policy(
            "recognition run segment ids must be unique and bounded",
        ));
    }
    for score in options.scores {
        score
            .validate()
            .map_err(|message| crate::failure::EvidenceError::policy(message.to_owned()))?;
    }
    for alternative in options.alternatives {
        alternative
            .validate()
            .map_err(|message| crate::failure::EvidenceError::policy(message.to_owned()))?;
    }
    if let Some(page) = options.page {
        let segment_count = u64::try_from(options.segments.len()).map_err(|_| {
            crate::failure::EvidenceError::policy(
                "recognition run segment ids must be unique and bounded",
            )
        })?;
        page.validate_result(
            (options.coverage, options.status),
            options.covers,
            segment_count,
        )
        .map_err(|message| crate::failure::EvidenceError::policy(message.to_owned()))?;
    }
    options
        .covers
        .validate()
        .map_err(|message| crate::failure::EvidenceError::policy(message.to_owned()))
}

fn recognition_run_payload(options: &RecognitionRunOptions<'_>) -> mneme_core::Payload {
    let mut fields = Vec::with_capacity(16);
    append_recognition_pins(&mut fields, options);
    append_recognition_identity(&mut fields, options);
    append_recognition_results(&mut fields, options);
    mneme_core::Payload::new(fields)
}

fn append_recognition_pins(
    fields: &mut Vec<(mneme_core::Symbol, mneme_core::Value)>,
    options: &RecognitionRunOptions<'_>,
) {
    fields.push((mneme_core::Symbol::from("input"), options.input.to_value()));
    fields.push((
        mneme_core::Symbol::from("input-digest"),
        options.input_digest.to_value(),
    ));
    fields.push((
        mneme_core::Symbol::from("output"),
        options.output.to_value(),
    ));
    fields.push((
        mneme_core::Symbol::from("output-digest"),
        options.output_digest.to_value(),
    ));
}

fn append_recognition_identity(
    fields: &mut Vec<(mneme_core::Symbol, mneme_core::Value)>,
    options: &RecognitionRunOptions<'_>,
) {
    for (name, identity) in [
        ("model", options.model),
        ("runtime", options.runtime),
        ("adapter", options.adapter),
        ("preprocessing", options.preprocessing),
        ("configuration", options.configuration),
    ] {
        fields.push((
            mneme_core::Symbol::from(name),
            mneme_core::Value::string(identity),
        ));
    }
}

fn append_recognition_results(
    fields: &mut Vec<(mneme_core::Symbol, mneme_core::Value)>,
    options: &RecognitionRunOptions<'_>,
) {
    fields.push((
        mneme_core::Symbol::from("segments"),
        mneme_core::Value::set(options.segments.iter().map(|segment| {
            reference(*segment, mneme_core::RecordKind::RecognitionSegment).to_value()
        })),
    ));
    fields.push((
        mneme_core::Symbol::from("coverage"),
        options.coverage.to_value(),
    ));
    fields.push((
        mneme_core::Symbol::from("status"),
        mneme_core::Value::symbol(options.status.symbol()),
    ));
    fields.push((
        mneme_core::Symbol::from("scores"),
        mneme_core::Value::sequence(
            options
                .scores
                .iter()
                .map(mneme_core::RecognitionScore::to_value)
                .collect(),
        ),
    ));
    fields.push((
        mneme_core::Symbol::from("alternatives"),
        mneme_core::Value::sequence(
            options
                .alternatives
                .iter()
                .map(mneme_core::RecognitionAlternative::to_value)
                .collect(),
        ),
    ));
    fields.push((
        mneme_core::Symbol::from("covers"),
        options.covers.to_value(),
    ));
    if let Some(page) = options.page {
        fields.push((mneme_core::Symbol::from("page"), page.to_value()));
    }
}

/// Build a segment mapping. A corrected alignment omits `run` and pins its
/// corrected text revision directly.
pub fn build_recognition_segment(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    options: RecognitionSegmentOptions<'_>,
) -> crate::failure::Result<mneme_store::RecordDraft> {
    options
        .location
        .validate()
        .map_err(|message| crate::failure::EvidenceError::policy(message.to_owned()))?;
    let mut fields = vec![
        (
            mneme_core::Symbol::from("text-source"),
            options.text_source.to_value(),
        ),
        (mneme_core::Symbol::from("span"), options.span.to_value()),
        (
            mneme_core::Symbol::from("media-source"),
            options.media_source.to_value(),
        ),
        (
            mneme_core::Symbol::from("media-digest"),
            options.media_digest.to_value(),
        ),
        (
            mneme_core::Symbol::from("location"),
            options.location.to_value(),
        ),
    ];
    if let Some(run) = options.run {
        fields.push((
            mneme_core::Symbol::from("run"),
            reference(run, mneme_core::RecordKind::RecognitionRun).to_value(),
        ));
    }
    if let Some(block) = options.block {
        block
            .validate()
            .map_err(|message| crate::failure::EvidenceError::policy(message.to_owned()))?;
        fields.push((mneme_core::Symbol::from("block"), block.to_value()));
    }
    Ok(mneme_store::RecordDraft {
        schema_version: 5,
        kind: mneme_core::RecordKind::RecognitionSegment,
        record_id,
        revision_id,
        predecessor: None,
        scope: scope.clone(),
        payload: mneme_core::Payload::new(fields),
    })
}

/// Build an unavailable or pruned source revision.
pub fn build_unavailable_source(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    options: UnavailableSourceOptions<'_>,
) -> mneme_store::RecordDraft {
    let UnavailableSourceOptions {
        reason,
        availability,
        entity,
        path_hint,
    } = options;
    build_unavailable_source_with_digest(
        record_id,
        revision_id,
        scope,
        UnavailableSourceWithDigestOptions {
            reason,
            availability,
            prior_digest: None,
            entity,
            path_hint,
        },
    )
}

/// Build an unavailable source revision that preserves the identity of the
/// bytes it no longer stores.
pub fn build_unavailable_source_with_digest(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    options: UnavailableSourceWithDigestOptions<'_>,
) -> mneme_store::RecordDraft {
    let UnavailableSourceWithDigestOptions {
        reason,
        availability,
        prior_digest,
        entity,
        path_hint,
    } = options;
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

/// Build a pruned revision while preserving acquisition, media extent,
/// transformation parent, correction lineage, and the exact prior digest.
/// Keep a source's media extent, transform, frame and ink inventory on a
/// rewritten revision.
fn preserve_media_fields(
    source: &crate::model::SourceView,
    fields: &mut Vec<(mneme_core::Symbol, mneme_core::Value)>,
) {
    if let Some(extent) = source.media_extent {
        fields.push((mneme_core::Symbol::from("media-extent"), extent.to_value()));
    }
    if let Some(transform) = source.media_transform {
        fields.push((
            mneme_core::Symbol::from("media-transform"),
            transform.to_value(),
        ));
    }
    if let Some(frame) = source.media_frame {
        fields.push((mneme_core::Symbol::from("media-frame"), frame.to_value()));
    }
    if let Some(inventory) = &source.ink_inventory {
        fields.push((
            mneme_core::Symbol::from("ink-strokes"),
            inventory.to_value(),
        ));
    }
}

pub fn build_unavailable_source_preserving(
    source: &crate::model::SourceView,
    revision_id: mneme_core::RevisionId,
    reason: &str,
    availability: &str,
) -> mneme_store::RecordDraft {
    let mut fields = vec![
        (
            mneme_core::Symbol::from("content"),
            mneme_core::SourceContent::Unavailable {
                reason: reason.to_owned(),
            }
            .to_value(),
        ),
        (
            mneme_core::Symbol::from("acquisition"),
            source.acquisition_value.clone(),
        ),
        (
            mneme_core::Symbol::from("availability"),
            mneme_core::Value::symbol(availability),
        ),
    ];
    if let Some(entity) = source.entity {
        fields.push((
            mneme_core::Symbol::from("entity"),
            reference(entity, mneme_core::RecordKind::Entity).to_value(),
        ));
    }
    if let Some(path) = &source.path_hint {
        fields.push((
            mneme_core::Symbol::from("path-hint"),
            mneme_core::Value::string(path.clone()),
        ));
    }
    if let Some(digest) = source.digest().or(source.prior_digest) {
        fields.push((
            mneme_core::Symbol::from("content-digest"),
            digest.to_value(),
        ));
    }
    if let Some(parent) = source.derived_from {
        fields.push((mneme_core::Symbol::from("derived-from"), parent.to_value()));
    }
    preserve_media_fields(source, &mut fields);
    if let Some(correction) = &source.correction {
        fields.push((
            mneme_core::Symbol::from("correction"),
            correction.to_value(),
        ));
    }
    mneme_store::RecordDraft {
        schema_version: if source.derivation.is_some() {
            mneme_core::DERIVED_ACQUISITION_SCHEMA_VERSION
        } else {
            5
        },
        kind: mneme_core::RecordKind::SourceRevision,
        record_id: source.record.record_id,
        revision_id,
        predecessor: Some(source.record.revision_id),
        scope: source.record.scope.clone(),
        payload: mneme_core::Payload::new(fields),
    }
}

/// Optional episode content, including related-record links.
#[derive(Clone)]
pub struct EpisodeOptions<'a> {
    pub actor: &'a str,
    pub episode_type: &'a str,
    pub occurred: mneme_core::ValidTime,
    pub summary: &'a str,
    pub source: Option<mneme_core::Reference>,
    pub related: &'a [mneme_core::Reference],
}

/// Build an episode, including optional related-record links.
pub fn build_episode(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    options: EpisodeOptions<'_>,
) -> mneme_store::RecordDraft {
    let EpisodeOptions {
        actor,
        episode_type,
        occurred,
        summary,
        source,
        related,
    } = options;
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

/// Evidence content over an exact source revision.
#[derive(Clone, Copy)]
pub struct EvidenceOptions<'a> {
    pub assertion: mneme_core::RecordId,
    pub source: mneme_core::RecordId,
    pub source_revision: mneme_core::RevisionId,
    pub span: Option<mneme_core::SourceSpan>,
    pub anchor: Option<&'a str>,
    pub relation: crate::model::SupportRelation,
    pub origin: mneme_core::Origin,
    pub ancestry: &'a [mneme_core::Reference],
}

/// Build evidence over an exact source revision.
pub fn build_evidence(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    options: EvidenceOptions<'_>,
) -> mneme_store::RecordDraft {
    let EvidenceOptions {
        assertion,
        source,
        source_revision,
        span,
        anchor,
        relation,
        origin,
        ancestry,
    } = options;
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

/// Proposed assertion content; this never sets an accepted lifecycle.
#[derive(Clone)]
pub struct ProposedAssertionOptions<'a> {
    pub subject: mneme_core::RecordId,
    pub predicate: &'a str,
    pub value: mneme_core::Value,
    pub stance: crate::model::Stance,
    pub origin: mneme_core::Origin,
    pub asserted_by: &'a str,
    pub valid_time: mneme_core::ValidTime,
    pub evidence: &'a [mneme_core::Reference],
    pub extraction: Option<(&'a str, &'a str)>,
    pub superseded_by: Option<mneme_core::Reference>,
}

/// Build a proposed assertion. There is deliberately no option that sets an
/// accepted lifecycle.
fn assertion_entries(
    options: ProposedAssertionOptions<'_>,
) -> Vec<(mneme_core::Symbol, mneme_core::Value)> {
    let ProposedAssertionOptions {
        subject,
        predicate,
        value,
        stance,
        origin,
        asserted_by,
        valid_time,
        evidence,
        extraction,
        superseded_by,
    } = options;
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
    entries
}

pub fn build_proposed_assertion(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    options: ProposedAssertionOptions<'_>,
) -> mneme_store::RecordDraft {
    let entries = assertion_entries(options);
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

/// Content for a comment record. A comment is about a note; it never edits it.
#[derive(Clone)]
pub struct CommentOptions<'a> {
    pub actor: &'a str,
    pub document: mneme_core::RecordId,
    pub source_revision: mneme_core::RecordId,
    /// The revision of the source the comment is about, so a later edit of
    /// the note shows the comment as about an older text.
    pub source_pin: mneme_core::RevisionId,
    pub span: Option<mneme_core::SourceSpan>,
    pub block: Option<&'a str>,
    pub text: &'a str,
    pub reply_to: Option<mneme_core::RecordId>,
    pub mentions: &'a [&'a str],
    pub status: &'a str,
    pub resolves: Option<mneme_core::RecordId>,
}

/// Build a comment record.
pub fn build_comment(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    options: CommentOptions<'_>,
) -> mneme_store::RecordDraft {
    let CommentOptions {
        actor,
        document,
        source_revision,
        source_pin,
        span,
        block,
        text,
        reply_to,
        mentions,
        status,
        resolves,
    } = options;
    let mut entries = vec![
        (
            mneme_core::Symbol::from("actor"),
            mneme_core::Value::string(actor),
        ),
        (
            mneme_core::Symbol::from("document"),
            reference(document, mneme_core::RecordKind::Document).to_value(),
        ),
        (
            mneme_core::Symbol::from("source-revision"),
            mneme_core::Reference::pinned(
                source_revision,
                source_pin,
                mneme_core::RecordKind::SourceRevision,
            )
            .to_value(),
        ),
        (
            mneme_core::Symbol::from("text"),
            mneme_core::Value::string(text),
        ),
        (
            mneme_core::Symbol::from("status"),
            mneme_core::Value::symbol(status),
        ),
    ];
    entries.extend(optional_comment_entries(
        span, block, reply_to, mentions, resolves,
    ));
    mneme_store::RecordDraft {
        schema_version: 4,
        kind: mneme_core::RecordKind::Comment,
        record_id,
        revision_id,
        predecessor: None,
        scope: scope.clone(),
        payload: mneme_core::Payload::new(entries),
    }
}

/// The payload entries of a comment's optional fields that are present.
fn optional_comment_entries(
    span: Option<mneme_core::SourceSpan>,
    block: Option<&str>,
    reply_to: Option<mneme_core::RecordId>,
    mentions: &[&str],
    resolves: Option<mneme_core::RecordId>,
) -> Vec<(mneme_core::Symbol, mneme_core::Value)> {
    let mut entries = Vec::with_capacity(5);
    if let Some(span) = span {
        entries.push((mneme_core::Symbol::from("span"), span.to_value()));
    }
    if let Some(block) = block {
        entries.push((
            mneme_core::Symbol::from("block"),
            mneme_core::Value::string(block),
        ));
    }
    if let Some(reply_to) = reply_to {
        entries.push((
            mneme_core::Symbol::from("reply-to"),
            reference(reply_to, mneme_core::RecordKind::Comment).to_value(),
        ));
    }
    if !mentions.is_empty() {
        entries.push((
            mneme_core::Symbol::from("mentions"),
            mneme_core::Value::set(mentions.iter().map(|name| mneme_core::Value::string(*name))),
        ));
    }
    if let Some(resolves) = resolves {
        entries.push((
            mneme_core::Symbol::from("resolves"),
            reference(resolves, mneme_core::RecordKind::Comment).to_value(),
        ));
    }
    entries
}

/// Content for an attributed decision.
#[derive(Clone)]
pub struct DecisionOptions<'a> {
    pub kind: crate::model::DecisionKind,
    pub target: mneme_core::RecordId,
    pub actor: &'a str,
    pub policy: &'a str,
    pub input_revision: mneme_core::WorkspaceRevisionId,
    pub outcome: &'a str,
    pub rationale: &'a str,
    pub evidence: &'a [mneme_core::Reference],
    pub related: &'a [mneme_core::Reference],
}

/// Build an attributed decision.
pub fn build_decision(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    options: DecisionOptions<'_>,
) -> mneme_store::RecordDraft {
    let DecisionOptions {
        kind,
        target,
        actor,
        policy,
        input_revision,
        outcome,
        rationale,
        evidence,
        related,
    } = options;
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

/// Content for a derivation with a complete premise set.
#[derive(Clone, Copy)]
pub struct DerivationOptions<'a> {
    pub conclusion: mneme_core::RecordId,
    pub premises: &'a [mneme_core::Reference],
    pub rule_id: &'a str,
    pub rule_version: i64,
    pub evaluation_revision: mneme_core::WorkspaceRevisionId,
    pub completeness: &'a str,
}

/// Build a derivation with a complete premise set.
pub fn build_derivation(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    options: DerivationOptions<'_>,
) -> mneme_store::RecordDraft {
    let DerivationOptions {
        conclusion,
        premises,
        rule_id,
        rule_version,
        evaluation_revision,
        completeness,
    } = options;
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

/// Content for a checkpoint pinned to the current episode/revision state.
#[derive(Clone, Copy)]
pub struct CheckpointOptions<'a> {
    pub goal: &'a str,
    pub state: &'a str,
    pub episodes: &'a [mneme_core::Reference],
    pub verified_outcomes: &'a [mneme_core::Reference],
    pub revision: mneme_core::WorkspaceRevisionId,
    pub note: Option<&'a str>,
}

/// Build a checkpoint pinned to the current episode/revision state.
pub fn build_checkpoint(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    options: CheckpointOptions<'_>,
) -> mneme_store::RecordDraft {
    let CheckpointOptions {
        goal,
        state,
        episodes,
        verified_outcomes,
        revision,
        note,
    } = options;
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
