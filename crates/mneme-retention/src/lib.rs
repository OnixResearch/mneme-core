//! Scoped retention: expiry, retraction, source pruning, forget, accountable
//! cleanup, and replay suppression.
//!
//! Plans are computed from one committed snapshot and a caller scope. The
//! barrier commit atomically advances the eligibility generation, records the
//! minimal suppression ledger, and writes the lifecycle records. Physical
//! cleanup runs afterwards and is independently resumable.
#![allow(unknown_lints, path_segment_repetition)] // Octet structural exception: domain-qualified names and macro-only imports are intentional
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

/// The policy version implemented by this build.
pub const POLICY_VERSION: &str = "retention-policy/v1";

/// A retention operation's semantic intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationKind {
    ValidTimeExpiry,
    AssertionRetraction,
    SourcePruning,
    Forget,
}

impl OperationKind {
    /// Stable operation name used by the ledger and interfaces.
    pub const fn name(self) -> &'static str {
        match self {
            OperationKind::ValidTimeExpiry => "valid-time-expiry",
            OperationKind::AssertionRetraction => "assertion-retraction",
            OperationKind::SourcePruning => "source-pruning",
            OperationKind::Forget => "forget",
        }
    }
}

/// The exact target selected by an authorized request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selector {
    /// One source record identity.
    Source(mneme_core::RecordId),
    /// A source pinned to one revision.
    SourceRevision(mneme_core::RecordId, mneme_core::RevisionId),
    /// Withdraw support derived from a source without retracting every claim.
    SourceSupport(mneme_core::RecordId),
    /// One assertion identity.
    Assertion(mneme_core::RecordId),
    /// Every authorized source with exact content identity.
    Content(mneme_core::ContentDigest),
}

impl Selector {
    fn kind(&self) -> &'static str {
        match self {
            Selector::Source(_) => "source",
            Selector::SourceRevision(_, _) => "source-revision",
            Selector::SourceSupport(_) => "source-support",
            Selector::Assertion(_) => "assertion",
            Selector::Content(_) => "content",
        }
    }
}

/// Caller-selected retention policy. These are policy inputs, not assumptions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub version: String,
    /// Keep a policy-permitted assertion when only its source bytes are pruned.
    pub retain_assertion_after_prune: bool,
    /// Block future content-equal imports under this forget operation.
    pub block_content_replay: bool,
    /// Retain withdrawn evidence metadata for authorized inspection.
    pub retain_withdrawn_evidence_metadata: bool,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        RetentionPolicy {
            version: POLICY_VERSION.to_owned(),
            retain_assertion_after_prune: true,
            block_content_replay: true,
            retain_withdrawn_evidence_metadata: true,
        }
    }
}

/// One authorized retention request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionRequest {
    pub actor: String,
    pub scope: mneme_core::ScopeId,
    pub base_revision: mneme_core::WorkspaceRevisionId,
    pub idempotency_key: String,
    pub operation: OperationKind,
    pub selector: Selector,
    /// Required by valid-time expiry.
    pub effective: Option<mneme_core::Timestamp>,
    pub policy: RetentionPolicy,
}

/// A suppression selected by the plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedSuppression {
    pub target: mneme_core::RecordId,
    pub revision: Option<mneme_core::RevisionId>,
    pub kind: mneme_core::RecordKind,
    pub mode: mneme_store::SuppressionMode,
    pub content_digest: Option<mneme_core::ContentDigest>,
}

/// The inspectable impact plan for one retention request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionPlan {
    pub operation_id: String,
    pub request: RetentionRequest,
    pub generation: u64,
    pub source_targets: Vec<mneme_core::RecordId>,
    pub retracted_assertions: Vec<mneme_core::RecordId>,
    pub expired_assertions: Vec<(mneme_core::RecordId, mneme_core::Timestamp)>,
    pub revised_assertions: Vec<mneme_core::RecordId>,
    pub surviving_assertions: Vec<mneme_core::RecordId>,
    pub withdrawn_evidence: Vec<mneme_core::RecordId>,
    pub suppressed: Vec<PlannedSuppression>,
    pub invalidated_derivations: Vec<mneme_core::RecordId>,
    pub locations: Vec<mneme_store::RetentionLocationPlan>,
    pub retained_metadata: Vec<String>,
    pub limitations: Vec<String>,
    pub warnings: Vec<String>,
    /// Lifecycle drafts committed with the barrier.
    pub records: Vec<mneme_store::RecordDraft>,
    /// The barrier, suppression entries, and cleanup inventory.
    pub commit: mneme_store::RetentionCommit,
}

/// Counts of terminal managed-location outcomes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CleanupSummary {
    pub purged: usize,
    pub absent: usize,
    pub retained_shared: usize,
    pub unavailable: usize,
    pub failed: usize,
    pub pending: usize,
}

/// The safe result of an executed or resumed retention operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionResult {
    pub operation_id: String,
    pub operation_kind: String,
    pub state: mneme_store::RetentionJobState,
    pub generation: u64,
    /// Logical withdrawal is in force as soon as the barrier commits.
    pub logical_withdrawal: bool,
    /// Every registered managed payload was purged or verified absent.
    pub physical_cleanup_complete: bool,
    pub cleanup: CleanupSummary,
    pub locations: Vec<mneme_store::RetentionLocationStateRecord>,
    pub limitations: Vec<String>,
    pub retained_metadata: Vec<String>,
}

/// A safe audit record; it contains no source text or raw adapter errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionAudit {
    pub operation_id: String,
    pub operation_kind: String,
    pub policy_version: String,
    pub generation: u64,
    pub state: mneme_store::RetentionJobState,
    pub selector_kinds: Vec<String>,
    pub suppressed_records: usize,
    pub retained_metadata: Vec<String>,
}

/// Retention failures. Authorization failures never name another scope's data.
#[derive(Debug, thiserror::Error)]
pub enum RetentionError {
    #[error(transparent)]
    Store(#[from] mneme_store::StoreError),
    #[error(transparent)]
    Memory(#[from] mneme_memory::MemoryError),
    #[error("retention selector is not authorized in the requested scope")]
    Unauthorized,
    #[error("retention target is not available in the requested scope")]
    NotFound,
    #[error("retention operation conflicts with current state: {0}")]
    Conflict(&'static str),
    #[error("retention policy refused the operation: {0}")]
    Policy(&'static str),
    #[error("invalid retention request: {0}")]
    Invalid(&'static str),
    #[error("retention cleanup is incomplete: {0}")]
    Cleanup(&'static str),
}

/// A result alias.
pub type Result<T, E = RetentionError> = std::result::Result<T, E>;

/// Retention operations over one mutable workspace handle.
pub struct Retention<'w> {
    workspace: &'w mut mneme_store::Workspace,
}

impl<'w> Retention<'w> {
    /// Wrap a workspace.
    pub fn new(workspace: &'w mut mneme_store::Workspace) -> Self {
        Retention { workspace }
    }

    /// Review the impact plan without mutating workspace state.
    pub fn plan(&mut self, request: RetentionRequest) -> Result<RetentionPlan> {
        let view = self.view()?;
        build_plan(self.workspace, &view, &request)
    }

    /// Execute or resume a retention request. The operation identity is bound
    /// to `(actor, scope, idempotency key)`.
    pub fn execute(&mut self, request: RetentionRequest) -> Result<RetentionResult> {
        validate_request(&request)?;
        if let Some(existing) = self.workspace.retention_operation_by_key(
            &request.actor,
            &request.scope,
            &request.idempotency_key,
        )? {
            let selectors = self.workspace.retention_selectors(&existing.operation_id)?;
            if existing.operation_kind != request.operation.name()
                || existing.policy_version != request.policy.version
                || selectors.len() != 1
                || selectors[0] != selector_row(&request)
            {
                return Err(mneme_store::StoreError::IdempotencyConflict {
                    key: request.idempotency_key,
                }
                .into());
            }
            return self.cleanup(existing);
        }
        let plan = self.plan(request)?;
        let base = self.workspace.current_revision()?;
        if plan.request.base_revision != base {
            return Err(RetentionError::Store(mneme_store::StoreError::StaleBase {
                base: plan.request.base_revision,
                current: base,
            }));
        }
        let generation = self.workspace.eligibility_generation()?;
        if plan.generation != generation.saturating_add(1) {
            return Err(mneme_store::StoreError::BarrierAdvanced {
                pinned: plan.generation,
                current: generation.saturating_add(1),
            }
            .into());
        }
        let outcome = self.workspace.commit(mneme_store::CommitCommand {
            base,
            actor: plan.request.actor.clone(),
            scope: plan.request.scope.clone(),
            idempotency_key: plan.request.idempotency_key.clone(),
            records: plan.records.clone(),
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: Some(plan.commit.clone()),
        })?;
        let operation = self
            .workspace
            .retention_operation(&plan.operation_id)?
            .ok_or_else(|| {
                RetentionError::Store(mneme_store::StoreError::InvalidCommand(
                    "retention operation was not committed".to_owned(),
                ))
            })?;
        if operation.outcome_revision != outcome.revision {
            return Err(RetentionError::Store(mneme_store::StoreError::Integrity {
                revision: outcome.revision,
                reason: "retention operation names a different revision".to_owned(),
            }));
        }
        self.cleanup(operation)
    }

    /// Resume cleanup for an existing operation.
    pub fn resume(&mut self, operation_id: &str) -> Result<RetentionResult> {
        let operation = self
            .workspace
            .retention_operation(operation_id)?
            .ok_or(RetentionError::NotFound)?;
        self.cleanup(operation)
    }

    /// Cancel outstanding cleanup without lifting the committed barrier.
    /// Pending locations remain resumable.
    pub fn cancel(&mut self, operation_id: &str) -> Result<RetentionResult> {
        let operation = self
            .workspace
            .retention_operation(operation_id)?
            .ok_or(RetentionError::NotFound)?;
        if operation.state != mneme_store::RetentionJobState::Complete {
            self.workspace
                .set_retention_state(operation_id, mneme_store::RetentionJobState::Partial)?;
        }
        let operation = self
            .workspace
            .retention_operation(operation_id)?
            .ok_or(RetentionError::NotFound)?;
        self.result(operation)
    }

    /// Read the safe audit metadata for an operation.
    pub fn audit(&self, operation_id: &str) -> Result<RetentionAudit> {
        let operation = self
            .workspace
            .retention_operation(operation_id)?
            .ok_or(RetentionError::NotFound)?;
        let selectors = self.workspace.retention_selectors(operation_id)?;
        let suppressions = self.workspace.retention_suppressions(operation_id)?;
        Ok(RetentionAudit {
            operation_id: operation.operation_id,
            operation_kind: operation.operation_kind,
            policy_version: operation.policy_version,
            generation: operation.generation,
            state: operation.state,
            selector_kinds: selectors
                .into_iter()
                .map(|selector| selector.kind)
                .collect(),
            suppressed_records: suppressions.len(),
            retained_metadata: operation.retained_metadata,
        })
    }

    fn view(&self) -> Result<mneme_memory::MemoryView> {
        let revision = self.workspace.current_revision()?;
        let snapshot = self.workspace.snapshot_at(revision, None)?;
        let history = self.history(&snapshot)?;
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

    #[allow(unknown_lints, unbounded_collection_growth)] // Octet structural exception: cohesive state-machine code; split tracked separately
    fn history(
        &self,
        snapshot: &mneme_store::Snapshot,
    ) -> Result<
        std::collections::BTreeMap<
            (mneme_core::RecordId, mneme_core::RevisionId),
            mneme_core::RecordEnvelope,
        >,
    > {
        let mut history = std::collections::BTreeMap::new();
        for record in &snapshot.records {
            for revision in self.workspace.record_revisions(record.record_id)? {
                history.insert((revision.record_id, revision.revision_id), revision);
            }
        }
        Ok(history)
    }

    #[allow(unknown_lints, function_length)] // Octet structural exception: cohesive state-machine code; split tracked separately
    fn cleanup(&mut self, operation: mneme_store::RetentionOperation) -> Result<RetentionResult> {
        if operation.state == mneme_store::RetentionJobState::Complete {
            return self.result(operation);
        }
        self.workspace.set_retention_state(
            &operation.operation_id,
            mneme_store::RetentionJobState::CleanupPending,
        )?;
        let locations = self
            .workspace
            .retention_locations(&operation.operation_id)?;
        for location in &locations {
            if location.state.is_terminal() {
                continue;
            }
            match location.location_kind.as_str() {
                "source-blob" | "record-blob" => {
                    match self.workspace.purge_retention_blob(
                        &operation.operation_id,
                        &location.location_id,
                        &location.location_kind,
                        &location.locator,
                    ) {
                        Ok(_) => {}
                        Err(mneme_store::StoreError::InjectedFault(point)) => {
                            return Err(mneme_store::StoreError::InjectedFault(point).into());
                        }
                        Err(mneme_store::StoreError::Io { .. })
                        | Err(mneme_store::StoreError::CorruptBlob { .. }) => {
                            self.workspace.verify_retention_location(
                                &operation.operation_id,
                                &location.location_id,
                                mneme_store::RetentionLocationState::Failed,
                                Some("payload-removal-failed"),
                            )?;
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                "publication-intent" => {
                    let is_suppressed = self.workspace.publication_intent_has_state(
                        &location.locator,
                        mneme_store::PublicationState::Suppressed,
                    )?;
                    self.workspace.verify_retention_location(
                        &operation.operation_id,
                        &location.location_id,
                        if is_suppressed {
                            mneme_store::RetentionLocationState::Verified
                        } else {
                            mneme_store::RetentionLocationState::Failed
                        },
                        if is_suppressed {
                            None
                        } else {
                            Some("publication-not-suppressed")
                        },
                    )?;
                }
                "staging" | "temporary-exports" | "sqlite-payloads" => {
                    self.workspace.verify_retention_location(
                        &operation.operation_id,
                        &location.location_id,
                        mneme_store::RetentionLocationState::Absent,
                        None,
                    )?;
                }
                "working-file" => {
                    match self.workspace.purge_retention_working_file(
                        &operation.operation_id,
                        &location.location_id,
                        &location.locator,
                    ) {
                        Ok(_) => {}
                        Err(mneme_store::StoreError::InjectedFault(point)) => {
                            return Err(mneme_store::StoreError::InjectedFault(point).into());
                        }
                        Err(mneme_store::StoreError::Io { .. }) => {
                            self.workspace.verify_retention_location(
                                &operation.operation_id,
                                &location.location_id,
                                mneme_store::RetentionLocationState::Failed,
                                Some("working-file-removal-failed"),
                            )?;
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                _ => {
                    self.workspace.verify_retention_location(
                        &operation.operation_id,
                        &location.location_id,
                        mneme_store::RetentionLocationState::Failed,
                        Some("unregistered-location-kind"),
                    )?;
                }
            }
        }
        let locations = self
            .workspace
            .retention_locations(&operation.operation_id)?;
        let summary = summarize(&locations);
        let state = if summary.pending > 0
            || summary.failed > 0
            || summary.retained_shared > 0
            || summary.unavailable > 0
        {
            mneme_store::RetentionJobState::Partial
        } else {
            mneme_store::RetentionJobState::Complete
        };
        self.workspace
            .set_retention_state(&operation.operation_id, state)?;
        let operation = self
            .workspace
            .retention_operation(&operation.operation_id)?
            .ok_or(RetentionError::NotFound)?;
        self.result(operation)
    }

    fn result(&self, operation: mneme_store::RetentionOperation) -> Result<RetentionResult> {
        let locations = self
            .workspace
            .retention_locations(&operation.operation_id)?;
        let summary = summarize(&locations);
        let mut limitations = Vec::new();
        if summary.retained_shared > 0 {
            limitations.push("shared-content-addressed-bytes-retained".to_owned());
        }
        if summary.unavailable > 0 {
            limitations.push("external-or-editable-copy-not-removed".to_owned());
        }
        if summary.failed > 0 {
            limitations.push("managed-cleanup-failed".to_owned());
        }
        let is_physical_cleanup_complete = summary.pending == 0
            && summary.failed == 0
            && summary.retained_shared == 0
            && summary.unavailable == 0;
        Ok(RetentionResult {
            operation_id: operation.operation_id,
            operation_kind: operation.operation_kind,
            state: operation.state,
            generation: operation.generation,
            logical_withdrawal: true,
            physical_cleanup_complete: is_physical_cleanup_complete,
            cleanup: summary,
            locations,
            limitations,
            retained_metadata: operation.retained_metadata,
        })
    }
}

fn summarize(locations: &[mneme_store::RetentionLocationStateRecord]) -> CleanupSummary {
    let mut summary = CleanupSummary::default();
    for location in locations {
        match location.state {
            mneme_store::RetentionLocationState::Pending => summary.pending += 1,
            mneme_store::RetentionLocationState::Purged => summary.purged += 1,
            mneme_store::RetentionLocationState::Absent
            | mneme_store::RetentionLocationState::Verified => {
                summary.absent += 1;
            }
            mneme_store::RetentionLocationState::RetainedShared => summary.retained_shared += 1,
            mneme_store::RetentionLocationState::Unavailable => summary.unavailable += 1,
            mneme_store::RetentionLocationState::Failed => summary.failed += 1,
        }
    }
    summary
}

fn validate_request(request: &RetentionRequest) -> Result<()> {
    if request.actor.trim().is_empty() || request.actor.len() > 128 {
        return Err(RetentionError::Invalid("actor is empty or too long"));
    }
    if request.idempotency_key.trim().is_empty() || request.idempotency_key.len() > 256 {
        return Err(RetentionError::Invalid(
            "idempotency key is empty or too long",
        ));
    }
    if request.policy.version.trim().is_empty() {
        return Err(RetentionError::Invalid("policy version is empty"));
    }
    match request.operation {
        OperationKind::ValidTimeExpiry => {
            if !matches!(request.selector, Selector::Assertion(_)) {
                return Err(RetentionError::Invalid(
                    "valid-time expiry requires an assertion selector",
                ));
            }
            if request.effective.is_none() {
                return Err(RetentionError::Invalid(
                    "valid-time expiry requires an effective instant",
                ));
            }
        }
        OperationKind::AssertionRetraction => {
            if !matches!(
                request.selector,
                Selector::Assertion(_) | Selector::SourceSupport(_)
            ) {
                return Err(RetentionError::Invalid(
                    "retraction requires an assertion or source-support selector",
                ));
            }
        }
        OperationKind::SourcePruning | OperationKind::Forget => {
            if matches!(request.selector, Selector::Assertion(_)) {
                return Err(RetentionError::Invalid(
                    "source operations require a source or content selector",
                ));
            }
            if matches!(request.selector, Selector::SourceSupport(_))
                && request.operation == OperationKind::Forget
            {
                return Err(RetentionError::Invalid(
                    "forget requires a source or content selector",
                ));
            }
        }
    }
    Ok(())
}

fn build_plan(
    workspace: &mneme_store::Workspace,
    view: &mneme_memory::MemoryView,
    request: &RetentionRequest,
) -> Result<RetentionPlan> {
    validate_request(request)?;
    let operation_id = format!("retention-{}", mneme_store::blob::random_hex(16)?);
    let generation = workspace.eligibility_generation()?.saturating_add(1);
    let mut plan = RetentionPlan {
        operation_id: operation_id.clone(),
        request: request.clone(),
        generation,
        source_targets: Vec::new(),
        retracted_assertions: Vec::new(),
        expired_assertions: Vec::new(),
        revised_assertions: Vec::new(),
        surviving_assertions: Vec::new(),
        withdrawn_evidence: Vec::new(),
        suppressed: Vec::new(),
        invalidated_derivations: Vec::new(),
        locations: Vec::new(),
        retained_metadata: vec!["operation-generation".to_owned()],
        limitations: Vec::new(),
        warnings: Vec::new(),
        records: Vec::new(),
        commit: mneme_store::RetentionCommit {
            operation_id,
            operation_kind: request.operation.name().to_owned(),
            policy_version: request.policy.version.clone(),
            selectors: vec![selector_row(request)],
            suppressions: Vec::new(),
            locations: Vec::new(),
            retained_metadata: Vec::new(),
        },
    };
    match request.operation {
        OperationKind::ValidTimeExpiry => plan_expiry(view, request, &mut plan)?,
        OperationKind::AssertionRetraction => plan_retraction(view, request, &mut plan)?,
        OperationKind::SourcePruning => plan_pruning(view, request, &mut plan)?,
        OperationKind::Forget => plan_forget(workspace, view, request, &mut plan)?,
    }
    plan.retained_metadata.sort();
    plan.retained_metadata.dedup();
    plan.commit.retained_metadata = plan.retained_metadata.clone();
    plan.commit.suppressions = plan
        .suppressed
        .iter()
        .map(|suppression| mneme_store::RetentionSuppression {
            operation_id: plan.operation_id.clone(),
            target: suppression.target,
            revision: suppression.revision,
            target_kind: suppression.kind.symbol().to_owned(),
            mode: suppression.mode,
            content_digest: suppression.content_digest,
            generation: plan.generation,
        })
        .collect();
    plan.commit.locations = plan.locations.clone();
    Ok(plan)
}

fn selector_row(request: &RetentionRequest) -> mneme_store::RetentionSelector {
    let (target, revision, digest) = match request.selector {
        Selector::Source(source) => (Some(source), None, None),
        Selector::SourceRevision(source, revision) => (Some(source), Some(revision), None),
        Selector::SourceSupport(source) => (Some(source), None, None),
        Selector::Assertion(assertion) => (Some(assertion), None, None),
        Selector::Content(digest) => (None, None, Some(digest)),
    };
    mneme_store::RetentionSelector {
        ordinal: 0,
        kind: request.selector.kind().to_owned(),
        target,
        revision,
        digest,
    }
}

fn plan_expiry(
    view: &mneme_memory::MemoryView,
    request: &RetentionRequest,
    plan: &mut RetentionPlan,
) -> Result<()> {
    let Selector::Assertion(assertion_id) = request.selector else {
        return Err(RetentionError::Invalid(
            "valid-time expiry requires an assertion",
        ));
    };
    let assertion = view.assertion(assertion_id).map_err(map_missing)?;
    authorize(&assertion.record, &request.scope)?;
    let effective = request
        .effective
        .ok_or(RetentionError::Invalid("expiry effective time is required"))?;
    let valid_time = expired_time(assertion.valid_time, effective)?;
    let mut payload = assertion.record.payload.clone();
    payload.insert(
        mneme_core::Symbol::from("valid-time"),
        valid_time.to_value(),
    );
    plan.records.push(mneme_store::RecordDraft {
        schema_version: assertion.record.schema_version,
        kind: mneme_core::RecordKind::Assertion,
        record_id: assertion.record.record_id,
        revision_id: fresh_revision()?,
        predecessor: Some(assertion.record.revision_id),
        scope: assertion.record.scope.clone(),
        payload,
    });
    plan.expired_assertions.push((assertion_id, effective));
    plan.retained_metadata
        .push("lifecycle-and-valid-time-history".to_owned());
    plan.limitations
        .push("expiry-changes-applicability-not-truth-or-bytes".to_owned());
    Ok(())
}

fn expired_time(
    valid_time: mneme_core::ValidTime,
    effective: mneme_core::Timestamp,
) -> Result<mneme_core::ValidTime> {
    match valid_time {
        mneme_core::ValidTime::Unknown => Ok(mneme_core::ValidTime::Bounded {
            start: None,
            end: Some(effective),
        }),
        mneme_core::ValidTime::Bounded { start, end } => {
            if start.is_some_and(|start| effective < start) {
                return Err(RetentionError::Conflict(
                    "requested expiry precedes the valid-time start",
                ));
            }
            if end.is_some_and(|end| end <= effective) {
                return Err(RetentionError::Conflict(
                    "valid time already ends at or before the requested expiry",
                ));
            }
            Ok(mneme_core::ValidTime::Bounded {
                start,
                end: Some(effective),
            })
        }
    }
}

fn plan_retraction(
    view: &mneme_memory::MemoryView,
    request: &RetentionRequest,
    plan: &mut RetentionPlan,
) -> Result<()> {
    let Selector::Assertion(assertion_id) = request.selector else {
        if let Selector::SourceSupport(source) = request.selector {
            return plan_support_retraction(view, request, source, plan);
        }
        return Err(RetentionError::Invalid(
            "assertion retraction requires an assertion or source support",
        ));
    };
    let assertion = view.assertion(assertion_id).map_err(map_missing)?;
    authorize(&assertion.record, &request.scope)?;
    if assertion.lifecycle == mneme_core::Lifecycle::Retracted {
        return Err(RetentionError::Conflict("assertion is already retracted"));
    }
    let decision_id = fresh_id()?;
    let decision_revision = fresh_revision()?;
    let assertion_revision = fresh_revision()?;
    let decision = mneme_memory::build_decision(
        decision_id,
        decision_revision,
        &assertion.record.scope,
        mneme_memory::DecisionKind::Retraction,
        assertion_id,
        &request.actor,
        &request.policy.version,
        plan.request.base_revision,
        "retracted",
        "retention request; no opposite proposition asserted",
        &[],
        &[],
    );
    let retracted = mneme_memory::build_assertion_revision(
        &assertion.record,
        assertion_revision,
        mneme_core::Lifecycle::Retracted,
        mneme_core::Reference::local(decision_id, mneme_core::RecordKind::Decision),
        None,
    );
    plan.records.push(decision);
    plan.records.push(retracted);
    plan.retracted_assertions.push(assertion_id);
    plan.invalidated_derivations = dependent_derivations(view, assertion_id, &request.scope)?;
    plan.retained_metadata
        .push("withdrawn-assertion-history".to_owned());
    plan.limitations
        .push("retraction-does-not-assert-the-opposite".to_owned());
    Ok(())
}

fn plan_support_retraction(
    view: &mneme_memory::MemoryView,
    request: &RetentionRequest,
    source: mneme_core::RecordId,
    plan: &mut RetentionPlan,
) -> Result<()> {
    let source_view = view.source(source).map_err(map_missing)?;
    authorize(&source_view.record, &request.scope)?;
    let deps = dependencies_for_sources(view, &[source])?;
    authorize_dependencies(view, &deps, &request.scope)?;
    let withdrawn: std::collections::BTreeSet<mneme_core::RecordId> = deps.evidence.clone();
    let mode = if request.policy.retain_withdrawn_evidence_metadata {
        mneme_store::SuppressionMode::Withdrawn
    } else {
        mneme_store::SuppressionMode::Forgotten
    };
    for evidence in &deps.evidence {
        let record = view.record(*evidence)?;
        plan.suppressed.push(PlannedSuppression {
            target: *evidence,
            revision: None,
            kind: mneme_core::RecordKind::Evidence,
            mode,
            content_digest: None,
        });
        if mode == mneme_store::SuppressionMode::Forgotten {
            add_record_blob_locations(view, record, plan)?;
        }
    }
    plan.withdrawn_evidence = deps.evidence.iter().copied().collect();
    for assertion_id in &deps.assertions {
        if independent_evidence_exists(view, *assertion_id, &withdrawn, Some(source))? {
            plan.surviving_assertions.push(*assertion_id);
        } else {
            plan.invalidated_derivations.extend(dependent_derivations(
                view,
                *assertion_id,
                &request.scope,
            )?);
        }
    }
    plan.invalidated_derivations.sort_unstable();
    plan.invalidated_derivations.dedup();
    plan.retained_metadata
        .push("withdrawn-evidence-metadata".to_owned());
    Ok(())
}

fn plan_pruning(
    view: &mneme_memory::MemoryView,
    request: &RetentionRequest,
    plan: &mut RetentionPlan,
) -> Result<()> {
    let (sources, _digest) = resolve_sources(view, request)?;
    let mut source_digests = std::collections::BTreeSet::new();
    let deps = dependencies_for_sources(view, &sources)?;
    authorize_dependencies(view, &deps, &request.scope)?;
    if !deps.assertions.is_empty() && !request.policy.retain_assertion_after_prune {
        return Err(RetentionError::Policy(
            "policy does not permit retaining assertions after source pruning",
        ));
    }
    for source in &sources {
        let source_view = view.source(*source).map_err(map_missing)?;
        let Some(digest) = source_view.digest() else {
            return Err(RetentionError::Conflict(
                "source bytes are already unavailable",
            ));
        };
        source_digests.insert(digest);
        let mut revision = mneme_memory::build_unavailable_source_with_digest(
            *source,
            fresh_revision()?,
            &source_view.record.scope,
            "source bytes pruned under retention policy",
            "pruned",
            Some(digest),
            source_view.entity,
            source_view.path_hint.as_deref(),
        );
        revision.predecessor = Some(source_view.record.revision_id);
        plan.records.push(revision);
        plan.source_targets.push(*source);
        add_blob_location(
            digest,
            "source-blob",
            format!("source-blob:{}", digest.to_hex()),
            plan,
        );
        if let Some(path) = &source_view.path_hint {
            plan.locations.push(mneme_store::RetentionLocationPlan {
                location_id: format!("working-file:{}", path),
                location_kind: "working-file".to_owned(),
                locator: format!("{path}#{}", digest.to_hex()),
            });
        }
    }
    add_inventory_locations(plan);
    plan.surviving_assertions = deps.assertions.iter().copied().collect();
    plan.retained_metadata
        .push("source-byte-absence".to_owned());
    plan.limitations
        .push("pruning-is-not-a-truth-or-retraction-operation".to_owned());
    Ok(())
}

#[allow(unknown_lints, function_length, unbounded_collection_growth)] // Octet structural exception: cohesive state-machine code; split tracked separately
fn plan_forget(
    workspace: &mneme_store::Workspace,
    view: &mneme_memory::MemoryView,
    request: &RetentionRequest,
    plan: &mut RetentionPlan,
) -> Result<()> {
    let (sources, _) = resolve_sources(view, request)?;
    let deps = dependencies_for_sources(view, &sources)?;
    authorize_dependencies(view, &deps, &request.scope)?;
    let mut forgotten_records: std::collections::BTreeSet<mneme_core::RecordId> =
        std::collections::BTreeSet::new();
    let mut forgotten_revisions: std::collections::BTreeSet<(
        mneme_core::RecordId,
        mneme_core::RevisionId,
    )> = std::collections::BTreeSet::new();
    let mut suppressed_assertions: std::collections::BTreeSet<mneme_core::RecordId> =
        std::collections::BTreeSet::new();
    let mut suppressed_derivations: std::collections::BTreeSet<mneme_core::RecordId> =
        std::collections::BTreeSet::new();
    let mut revised_assertions: std::collections::BTreeSet<mneme_core::RecordId> =
        std::collections::BTreeSet::new();
    let mut source_digests: std::collections::BTreeMap<
        mneme_core::RecordId,
        mneme_core::ContentDigest,
    > = std::collections::BTreeMap::new();

    for source in &sources {
        let source_view = view.source(*source).map_err(map_missing)?;
        if let Some(digest) = source_view.digest() {
            source_digests.insert(*source, digest);
            add_blob_location(
                digest,
                "source-blob",
                format!("source-blob:{}", digest.to_hex()),
                plan,
            );
        }
        forgotten_records.insert(*source);
        if let Some(path) = &source_view.path_hint
            && let Some(digest) = source_digests.get(source)
        {
            plan.locations.push(mneme_store::RetentionLocationPlan {
                location_id: format!("working-file:{}", path),
                location_kind: "working-file".to_owned(),
                locator: format!("{path}#{}", digest.to_hex()),
            });
        }
        plan.source_targets.push(*source);
    }
    for episode in &deps.episodes {
        forgotten_records.insert(*episode);
    }
    for evidence in &deps.evidence {
        forgotten_records.insert(*evidence);
    }
    let withdrawn: std::collections::BTreeSet<mneme_core::RecordId> = deps.evidence.clone();
    for assertion_id in &deps.assertions {
        if independent_evidence_exists(view, *assertion_id, &withdrawn, None)? {
            revised_assertions.insert(*assertion_id);
        } else {
            suppressed_assertions.insert(*assertion_id);
        }
    }

    // A derivation is a dependent semantic copy. It is suppressed when any
    // required premise is suppressed, when its conclusion is suppressed, or
    // when it depends on another suppressed derivation.
    loop {
        let mut is_changed = false;
        for record in visible_records(view)? {
            if record.kind != mneme_core::RecordKind::Derivation {
                continue;
            }
            let derivation = view.derivation(record.record_id)?;
            let is_invalid = suppressed_assertions.contains(&derivation.conclusion)
                || derivation.premises.iter().any(|premise| {
                    suppressed_assertions.contains(premise)
                        || suppressed_derivations.contains(premise)
                });
            if is_invalid && derivation.record.scope != request.scope {
                return Err(RetentionError::Unauthorized);
            }
            if is_invalid && suppressed_derivations.insert(record.record_id) {
                is_changed = true;
            }
        }
        // An assertion with no evidence of its own survives only through a
        // derivation. Once every derivation is suppressed, the assertion is a
        // semantic copy with no remaining proof.
        for record in visible_records(view)? {
            if record.kind != mneme_core::RecordKind::Assertion {
                continue;
            }
            let assertion = view.assertion(record.record_id)?;
            if assertion.evidence.is_empty() && !suppressed_assertions.contains(&record.record_id) {
                let derivations = view.derivations_for(record.record_id)?;
                if !derivations.is_empty()
                    && derivations.iter().all(|derivation| {
                        suppressed_derivations.contains(&derivation.record.record_id)
                    })
                {
                    suppressed_assertions.insert(record.record_id);
                    is_changed = true;
                }
            }
        }
        if !is_changed {
            break;
        }
    }
    for assertion_id in &revised_assertions {
        let assertion = view.assertion(*assertion_id)?;
        let remaining: Vec<mneme_core::Reference> = assertion
            .evidence
            .iter()
            .filter(|evidence| !withdrawn.contains(evidence))
            .map(|evidence| {
                mneme_core::Reference::local(*evidence, mneme_core::RecordKind::Evidence)
            })
            .collect();
        let mut payload = assertion.record.payload.clone();
        payload.insert(
            mneme_core::Symbol::from("evidence"),
            mneme_core::Value::set(remaining.iter().map(mneme_core::Reference::to_value)),
        );
        plan.records.push(mneme_store::RecordDraft {
            schema_version: assertion.record.schema_version,
            kind: mneme_core::RecordKind::Assertion,
            record_id: assertion.record.record_id,
            revision_id: fresh_revision()?,
            predecessor: Some(assertion.record.revision_id),
            scope: assertion.record.scope.clone(),
            payload,
        });
        for revision in workspace.record_revisions(*assertion_id)? {
            forgotten_revisions.insert((*assertion_id, revision.revision_id));
            add_record_blob_locations(view, &revision, plan)?;
        }
        plan.revised_assertions.push(*assertion_id);
        plan.surviving_assertions.push(*assertion_id);
    }
    for assertion_id in &suppressed_assertions {
        forgotten_records.insert(*assertion_id);
    }
    for derivation_id in &suppressed_derivations {
        forgotten_records.insert(*derivation_id);
    }
    // Checkpoints and proposals are dependent copies when they reference any
    // suppressed record. Records without registered ancestry are an explicit
    // policy limitation rather than guessed at by text matching.
    for record in visible_records(view)? {
        if !matches!(
            record.kind,
            mneme_core::RecordKind::Checkpoint | mneme_core::RecordKind::Proposal
        ) {
            continue;
        }
        let targets = forgotten_records
            .iter()
            .chain(deps.evidence.iter())
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        if references_any(&record.payload.to_value(), &targets) {
            if record.scope != request.scope {
                return Err(RetentionError::Unauthorized);
            }
            forgotten_records.insert(record.record_id);
        }
    }
    for record_id in &forgotten_records {
        let record = view.record(*record_id)?;
        plan.suppressed.push(PlannedSuppression {
            target: *record_id,
            revision: None,
            kind: record.kind,
            mode: mneme_store::SuppressionMode::Forgotten,
            content_digest: source_digests
                .get(record_id)
                .copied()
                .filter(|_| request.policy.block_content_replay),
        });
        for revision in workspace.record_revisions(*record_id)? {
            add_record_blob_locations(view, &revision, plan)?;
        }
    }
    for (assertion_id, revision) in &forgotten_revisions {
        let record = workspace
            .record_revisions(*assertion_id)?
            .into_iter()
            .find(|record| record.revision_id == *revision)
            .ok_or_else(|| RetentionError::NotFound)?;
        plan.suppressed.push(PlannedSuppression {
            target: *assertion_id,
            revision: Some(*revision),
            kind: record.kind,
            mode: mneme_store::SuppressionMode::Forgotten,
            content_digest: None,
        });
    }
    plan.suppressed.sort_by_key(|suppression| {
        (
            suppression.target,
            suppression
                .revision
                .unwrap_or(mneme_core::RevisionId::from_bytes([0; 16])),
        )
    });
    plan.invalidated_derivations = suppressed_derivations.iter().copied().collect();
    add_inventory_locations(plan);
    plan.retained_metadata.extend([
        "suppression-identity".to_owned(),
        "operation-generation".to_owned(),
    ]);
    if request.policy.block_content_replay && !source_digests.is_empty() {
        plan.retained_metadata
            .push("content-replay-block".to_owned());
    }
    plan.limitations
        .push("no-forensic-media-erasure-claim".to_owned());
    plan.limitations
        .push("unregistered-semantic-copies-not-inferred".to_owned());
    Ok(())
}

#[allow(unknown_lints, unbounded_collection_growth)] // Octet structural exception: cohesive state-machine code; split tracked separately
fn resolve_sources(
    view: &mneme_memory::MemoryView,
    request: &RetentionRequest,
) -> Result<(Vec<mneme_core::RecordId>, Option<mneme_core::ContentDigest>)> {
    match request.selector {
        Selector::Source(source) => {
            let record = view.source(source).map_err(map_missing)?;
            authorize(&record.record, &request.scope)?;
            Ok((vec![source], record.digest()))
        }
        Selector::SourceRevision(source, revision) => {
            let record = view.source(source).map_err(map_missing)?;
            authorize(&record.record, &request.scope)?;
            if record.record.revision_id != revision {
                return Err(RetentionError::NotFound);
            }
            Ok((vec![source], record.digest()))
        }
        Selector::Content(digest) => {
            let mut sources = Vec::new();
            for record in visible_records(view)? {
                if record.kind != mneme_core::RecordKind::SourceRevision {
                    continue;
                }
                let source = view.source(record.record_id)?;
                if source.digest() != Some(digest) {
                    continue;
                }
                if source.record.scope != request.scope {
                    return Err(RetentionError::Unauthorized);
                }
                sources.push(source.record.record_id);
            }
            if sources.is_empty() {
                return Err(RetentionError::NotFound);
            }
            Ok((sources, Some(digest)))
        }
        Selector::SourceSupport(_) | Selector::Assertion(_) => Err(RetentionError::Invalid(
            "operation requires a source or content selector",
        )),
    }
}

fn visible_records(view: &mneme_memory::MemoryView) -> Result<Vec<mneme_core::RecordEnvelope>> {
    Ok(view.snapshot().records.clone())
}

fn authorize(record: &mneme_core::RecordEnvelope, scope: &mneme_core::ScopeId) -> Result<()> {
    if &record.scope == scope {
        Ok(())
    } else {
        Err(RetentionError::Unauthorized)
    }
}

fn authorize_dependencies(
    view: &mneme_memory::MemoryView,
    deps: &Dependencies,
    scope: &mneme_core::ScopeId,
) -> Result<()> {
    for record in deps
        .episodes
        .iter()
        .chain(deps.evidence.iter())
        .chain(deps.assertions.iter())
    {
        let envelope = view.record(*record)?;
        if &envelope.scope != scope {
            return Err(RetentionError::Unauthorized);
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Default)]
struct Dependencies {
    episodes: std::collections::BTreeSet<mneme_core::RecordId>,
    evidence: std::collections::BTreeSet<mneme_core::RecordId>,
    assertions: std::collections::BTreeSet<mneme_core::RecordId>,
}

#[allow(unknown_lints, function_length)] // Octet structural exception: cohesive state-machine code; split tracked separately
fn dependencies_for_sources(
    view: &mneme_memory::MemoryView,
    sources: &[mneme_core::RecordId],
) -> Result<Dependencies> {
    let targets: std::collections::BTreeSet<mneme_core::RecordId> =
        sources.iter().copied().collect();
    let mut deps = Dependencies::default();
    loop {
        let mut is_changed = false;
        let closure: std::collections::BTreeSet<mneme_core::RecordId> = targets
            .iter()
            .chain(deps.episodes.iter())
            .chain(deps.evidence.iter())
            .copied()
            .collect();
        for record in visible_records(view)? {
            match record.kind {
                mneme_core::RecordKind::Episode => {
                    if deps.episodes.contains(&record.record_id) {
                        continue;
                    }
                    let episode = view.episode(record.record_id)?;
                    let is_linked_source = episode
                        .source
                        .is_some_and(|source| closure.contains(&source));
                    let is_linked_related = episode
                        .related
                        .iter()
                        .any(|related| closure.contains(related));
                    if is_linked_source || is_linked_related {
                        deps.episodes.insert(record.record_id);
                        is_changed = true;
                    }
                }
                mneme_core::RecordKind::Evidence => {
                    if deps.evidence.contains(&record.record_id) {
                        continue;
                    }
                    let evidence = view.evidence(record.record_id)?;
                    if closure.contains(&evidence.source)
                        || evidence
                            .ancestry
                            .iter()
                            .any(|ancestor| closure.contains(ancestor))
                    {
                        deps.evidence.insert(record.record_id);
                        is_changed = true;
                    }
                }
                mneme_core::RecordKind::Assertion => {
                    if deps.assertions.contains(&record.record_id) {
                        continue;
                    }
                    let assertion = view.assertion(record.record_id)?;
                    if assertion
                        .evidence
                        .iter()
                        .any(|evidence| deps.evidence.contains(evidence))
                    {
                        deps.assertions.insert(record.record_id);
                        is_changed = true;
                    }
                }
                mneme_core::RecordKind::Derivation => {
                    let derivation = view.derivation(record.record_id)?;
                    if derivation
                        .premises
                        .iter()
                        .any(|premise| deps.assertions.contains(premise))
                        && deps.assertions.insert(derivation.conclusion)
                    {
                        is_changed = true;
                    }
                }
                _ => {}
            }
        }
        if !is_changed {
            return Ok(deps);
        }
    }
}

fn independent_evidence_exists(
    view: &mneme_memory::MemoryView,
    assertion_id: mneme_core::RecordId,
    withdrawn: &std::collections::BTreeSet<mneme_core::RecordId>,
    target_source: Option<mneme_core::RecordId>,
) -> Result<bool> {
    let assertion = view.assertion(assertion_id)?;
    for evidence_id in &assertion.evidence {
        if withdrawn.contains(evidence_id) {
            continue;
        }
        let evidence = match view.evidence(*evidence_id) {
            Ok(evidence) => evidence,
            Err(_) => continue,
        };
        if evidence.relation != mneme_memory::SupportRelation::Supports {
            continue;
        }
        if view.suppression_for(&evidence.record).is_some() {
            continue;
        }
        if let Some(target) = target_source {
            let roots = view.evidence_roots(*evidence_id).unwrap_or_default();
            if roots.iter().any(|(source, _)| *source == target) {
                continue;
            }
        }
        if view.source(evidence.source).is_ok() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn dependent_derivations(
    view: &mneme_memory::MemoryView,
    assertion: mneme_core::RecordId,
    scope: &mneme_core::ScopeId,
) -> Result<Vec<mneme_core::RecordId>> {
    let mut affected_assertions = std::collections::BTreeSet::from([assertion]);
    let mut derivations = std::collections::BTreeSet::new();
    loop {
        let mut is_changed = false;
        for record in visible_records(view)? {
            if record.kind != mneme_core::RecordKind::Derivation {
                continue;
            }
            let derivation = view.derivation(record.record_id)?;
            if derivations.contains(&record.record_id) {
                continue;
            }
            if derivation
                .premises
                .iter()
                .any(|premise| affected_assertions.contains(premise))
            {
                if &derivation.record.scope != scope {
                    return Err(RetentionError::Unauthorized);
                }
                derivations.insert(record.record_id);
                if affected_assertions.insert(derivation.conclusion) {
                    is_changed = true;
                }
            }
        }
        if !is_changed {
            return Ok(derivations.into_iter().collect());
        }
    }
}

fn fresh_id() -> Result<mneme_core::RecordId> {
    Ok(mneme_core::RecordId::from_bytes(
        mneme_store::blob::random_bytes()?,
    ))
}

fn fresh_revision() -> Result<mneme_core::RevisionId> {
    Ok(mneme_core::RevisionId::from_bytes(
        mneme_store::blob::random_bytes()?,
    ))
}

fn map_missing(error: mneme_memory::MemoryError) -> RetentionError {
    match error {
        mneme_memory::MemoryError::Missing { .. } => RetentionError::NotFound,
        other => RetentionError::Memory(other),
    }
}

fn add_blob_location(
    digest: mneme_core::ContentDigest,
    kind: &str,
    location_id: String,
    plan: &mut RetentionPlan,
) {
    if plan
        .locations
        .iter()
        .any(|location| location.location_id == location_id)
    {
        return;
    }
    plan.locations.push(mneme_store::RetentionLocationPlan {
        location_id,
        location_kind: kind.to_owned(),
        locator: digest.to_hex(),
    });
}

fn add_record_blob_locations(
    _view: &mneme_memory::MemoryView,
    record: &mneme_core::RecordEnvelope,
    plan: &mut RetentionPlan,
) -> Result<()> {
    let digest = record.full_digest();
    add_blob_location(
        digest,
        "record-blob",
        format!("record-blob:{}", digest.to_hex()),
        plan,
    );
    Ok(())
}

fn add_inventory_locations(plan: &mut RetentionPlan) {
    for (kind, label) in [
        ("staging", "workspace-staging"),
        ("temporary-exports", "workspace-temporary-exports"),
        ("sqlite-payloads", "workspace-sqlite-payloads"),
    ] {
        let location_id = format!("inventory:{kind}");
        if !plan
            .locations
            .iter()
            .any(|location| location.location_id == location_id)
        {
            plan.locations.push(mneme_store::RetentionLocationPlan {
                location_id,
                location_kind: kind.to_owned(),
                locator: label.to_owned(),
            });
        }
    }
}

#[allow(unknown_lints, no_recursion)] // Octet structural exception: cohesive state-machine code; split tracked separately
fn references_any(
    value: &mneme_core::Value,
    targets: &std::collections::BTreeSet<mneme_core::RecordId>,
) -> bool {
    if let Ok(reference) = mneme_core::Reference::from_value(value, &mneme_core::Path::root()) {
        return reference
            .target()
            .is_some_and(|target| targets.contains(&target));
    }
    match value {
        mneme_core::Value::Record(record) => {
            record.label();
            record
                .fields()
                .iter()
                .any(|field| references_any(field, targets))
        }
        mneme_core::Value::Sequence(items) => {
            items.iter().any(|item| references_any(item, targets))
        }
        mneme_core::Value::Set(items) => items.iter().any(|item| references_any(item, targets)),
        mneme_core::Value::Dictionary(entries) => entries
            .iter()
            .any(|(key, value)| references_any(key, targets) || references_any(value, targets)),
        mneme_core::Value::Embedded(inner) => references_any(inner, targets),
        mneme_core::Value::Boolean(_)
        | mneme_core::Value::Double(_)
        | mneme_core::Value::SignedInteger(_)
        | mneme_core::Value::Symbol(_)
        | mneme_core::Value::String(_)
        | mneme_core::Value::ByteString(_) => false,
    }
}
