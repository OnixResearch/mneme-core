//! Scoped retention: expiry, retraction, source pruning, forget, accountable
//! cleanup, and replay suppression.
//!
//! Plans are computed from one committed snapshot and a caller scope. The
//! barrier commit atomically advances the eligibility generation, records the
//! minimal suppression ledger, and writes the lifecycle records. Physical
//! cleanup runs afterwards and is independently resumable.
#![allow(unknown_lints)] // Octet structural exception: domain-qualified names and macro-only imports are intentional
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

/// The policy version implemented by this build.
pub const POLICY_VERSION: &str = "retention-policy/v1";

/// The maximum number of managed locations one cleanup run attempts.
///
/// A plan may inventory more locations than one run can inspect; the run stops
/// at this bound, leaves the rest pending, and reports that it did so so the
/// caller can resume instead of holding one process open indefinitely.
pub const MAX_CLEANUP_ATTEMPTS_PER_RUN: u32 = 256;

/// The maximum number of records one impact plan may consider.
const MAX_PLAN_RECORDS: usize = 1_000_000;

/// The maximum number of retained source revisions one plan may inventory.
const MAX_SOURCE_REVISIONS: usize = 1_000_000;

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

    fn parts(
        &self,
    ) -> (
        Option<mneme_core::RecordId>,
        Option<mneme_core::RevisionId>,
        Option<mneme_core::ContentDigest>,
    ) {
        match self {
            Selector::Source(source) => (Some(*source), None, None),
            Selector::SourceRevision(source, revision) => (Some(*source), Some(*revision), None),
            Selector::SourceSupport(source) => (Some(*source), None, None),
            Selector::Assertion(assertion) => (Some(*assertion), None, None),
            Selector::Content(digest) => (None, None, Some(*digest)),
        }
    }
}

/// Caller-selected retention policy. These are policy inputs, not assumptions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub version: String,
    /// Keep a policy-permitted assertion when only its source bytes are pruned.
    pub retain_assertion_after_prune: bool,
    /// Block future content-equal imports under this forget operation.
    pub block_content_replay: bool,
    /// Retain withdrawn evidence metadata for authorized inspection.
    pub retain_withdrawn_evidence_metadata: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            version: POLICY_VERSION.to_owned(),
            retain_assertion_after_prune: true,
            block_content_replay: true,
            retain_withdrawn_evidence_metadata: true,
        }
    }
}

/// One authorized retention request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub actor: String,
    pub scope: mneme_core::ScopeId,
    pub base_revision: mneme_core::WorkspaceRevisionId,
    pub idempotency_key: String,
    pub operation: OperationKind,
    pub selector: Selector,
    /// Required by valid-time expiry.
    pub effective: Option<mneme_core::Timestamp>,
    pub policy: Policy,
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
pub struct Plan {
    pub operation_id: String,
    pub request: Request,
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
pub struct Outcome {
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
pub struct Audit {
    pub operation_id: String,
    pub operation_kind: String,
    pub policy_version: String,
    pub generation: u64,
    pub state: mneme_store::RetentionJobState,
    pub selector_kinds: Vec<String>,
    pub suppressed_records: usize,
    pub retained_metadata: Vec<String>,
}

/// Engine failures. Authorization failures never name another scope's data.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error(transparent)]
    Store(#[from] mneme_store::Failure),
    #[error(transparent)]
    Engine(#[from] mneme_memory::EvidenceError),
    /// Reserved for callers that map an explicit authorization denial; the
    /// retention engine itself reports an out-of-scope target as unavailable so
    /// a request cannot probe another scope's content.
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
pub type Result<T, E = PolicyError> = std::result::Result<T, E>;

/// Whether one cleanup run finished its inventory or stopped at the bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CleanupRun {
    Completed,
    AttemptBound,
}

/// Engine operations over one mutable workspace handle.
pub struct Engine<'w> {
    workspace: &'w mut mneme_store::Workspace,
}

impl<'w> Engine<'w> {
    /// Wrap a workspace.
    pub fn new(workspace: &'w mut mneme_store::Workspace) -> Self {
        Engine { workspace }
    }

    /// Review the impact plan without mutating workspace state.
    ///
    /// A dry run consults the idempotency state: a key already bound to an
    /// identical request reports the existing operation, and a key bound to a
    /// different request is an idempotency conflict.
    pub fn plan(&mut self, request: Request) -> Result<Plan> {
        validate_request(&request)?;
        let fingerprint = request_fingerprint(&request);
        if self
            .workspace
            .replay_outcome(
                &request.actor,
                &request.scope,
                &request.idempotency_key,
                &fingerprint,
            )?
            .is_some()
        {
            return Err(PolicyError::Conflict(
                "idempotency key already names a committed retention request",
            ));
        }
        let view = self.view()?;
        build_plan(self.workspace, &view, &request)
    }

    /// Execute or resume a retention request. The operation identity is bound
    /// to `(actor, scope, idempotency key)` and to the complete request content.
    pub fn execute(&mut self, request: Request) -> Result<Outcome> {
        validate_request(&request)?;
        let fingerprint = request_fingerprint(&request);
        if self
            .workspace
            .replay_outcome(
                &request.actor,
                &request.scope,
                &request.idempotency_key,
                &fingerprint,
            )?
            .is_some()
        {
            let existing = self.existing_operation(&request)?;
            return self.cleanup(existing);
        }
        let plan = self.plan(request)?;
        let base = self.workspace.current_revision()?;
        if plan.request.base_revision != base {
            return Err(PolicyError::Store(mneme_store::Failure::StaleBase {
                base: plan.request.base_revision,
                current: base,
            }));
        }
        let generation = self.workspace.eligibility_generation()?;
        if plan.generation != generation.saturating_add(1) {
            return Err(mneme_store::Failure::BarrierAdvanced {
                pinned: plan.generation,
                current: generation.saturating_add(1),
            }
            .into());
        }
        let outcome = self.workspace.commit_bound(
            mneme_store::CommitCommand {
                base,
                actor: plan.request.actor.clone(),
                scope: plan.request.scope.clone(),
                idempotency_key: plan.request.idempotency_key.clone(),
                records: plan.records.clone(),
                source_blobs: Vec::new(),
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: Some(plan.commit.clone()),
            },
            fingerprint,
        )?;
        let operation = match self.workspace.retention_operation(&plan.operation_id)? {
            Some(operation) => operation,
            // A concurrent identical request committed first; the coordinator
            // replayed its outcome under the same request fingerprint.
            None => self.existing_operation(&plan.request)?,
        };
        if operation.outcome_revision != outcome.revision {
            return Err(PolicyError::Store(mneme_store::Failure::Integrity {
                revision: outcome.revision,
                reason: "retention operation names a different revision".to_owned(),
            }));
        }
        self.cleanup(operation)
    }

    /// Resume cleanup for an existing operation.
    pub fn resume(&mut self, operation_id: &str) -> Result<Outcome> {
        let operation = self
            .workspace
            .retention_operation(operation_id)?
            .ok_or(PolicyError::NotFound)?;
        self.cleanup(operation)
    }

    /// Cancel outstanding cleanup without lifting the committed barrier.
    /// Pending locations remain resumable.
    pub fn cancel(&mut self, operation_id: &str) -> Result<Outcome> {
        let operation = self
            .workspace
            .retention_operation(operation_id)?
            .ok_or(PolicyError::NotFound)?;
        if operation.state != mneme_store::RetentionJobState::Complete {
            self.workspace
                .set_retention_state(operation_id, mneme_store::RetentionJobState::Partial)?;
        }
        let operation = self
            .workspace
            .retention_operation(operation_id)?
            .ok_or(PolicyError::NotFound)?;
        self.result(operation, CleanupRun::Completed)
    }

    /// Read the safe audit metadata for an operation.
    pub fn audit(&self, operation_id: &str) -> Result<Audit> {
        let operation = self
            .workspace
            .retention_operation(operation_id)?
            .ok_or(PolicyError::NotFound)?;
        let selectors = self.workspace.retention_selectors(operation_id)?;
        let suppressions = self.workspace.retention_suppressions(operation_id)?;
        Ok(Audit {
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

    fn existing_operation(&self, request: &Request) -> Result<mneme_store::RetentionOperation> {
        self.workspace
            .retention_operation_by_key(&request.actor, &request.scope, &request.idempotency_key)?
            .ok_or(PolicyError::Conflict(
                "idempotency key names no retention operation",
            ))
    }

    fn view(&self) -> Result<mneme_memory::View> {
        let revision = self.workspace.current_revision()?;
        let snapshot = self.workspace.snapshot_at(revision, None)?;
        self.rebuild_view(snapshot)
    }

    /// Rebuild a readable view from a pinned snapshot.
    ///
    /// This is the production rebuild path for retention planning and later
    /// re-checks: a snapshot that still names a forgotten identity or blocked
    /// content is refused before any dependent state is derived from it.
    pub fn rebuild_view(&self, snapshot: mneme_store::Snapshot) -> Result<mneme_memory::View> {
        self.workspace.require_replay_eligible(&snapshot)?;
        let context =
            mneme_memory::view_context(self.workspace, &snapshot).map_err(view_context_error)?;
        if context.history.len() > MAX_PLAN_RECORDS {
            return Err(PolicyError::Invalid(
                "workspace history exceeds the 1M revision bound",
            ));
        }
        let suppressions = self.workspace.active_suppressions()?;
        Ok(mneme_memory::View::with_retention(
            snapshot,
            self.workspace.root(),
            context.history,
            context.revision_sequences,
            suppressions,
        )
        .with_access(mneme_memory::Access::Operator))
    }

    fn cleanup(&mut self, operation: mneme_store::RetentionOperation) -> Result<Outcome> {
        if operation.state == mneme_store::RetentionJobState::Complete {
            return self.result(operation, CleanupRun::Completed);
        }
        self.workspace.set_retention_state(
            &operation.operation_id,
            mneme_store::RetentionJobState::CleanupPending,
        )?;
        let locations = self
            .workspace
            .retention_locations(&operation.operation_id)?;
        let mut attempts = 0_u32;
        let mut run = CleanupRun::Completed;
        for location in &locations {
            if !location.state.needs_attempt() {
                continue;
            }
            if attempts >= MAX_CLEANUP_ATTEMPTS_PER_RUN {
                run = CleanupRun::AttemptBound;
                break;
            }
            self.cleanup_location(&operation.operation_id, location)?;
            attempts = attempts.saturating_add(1);
        }
        let locations = self
            .workspace
            .retention_locations(&operation.operation_id)?;
        let states = location_states(&locations);
        let state = job_state(&states);
        self.workspace
            .set_retention_state(&operation.operation_id, state)?;
        let operation = self
            .workspace
            .retention_operation(&operation.operation_id)?
            .ok_or(PolicyError::NotFound)?;
        self.result(operation, run)
    }

    fn cleanup_location(
        &mut self,
        operation_id: &str,
        location: &mneme_store::RetentionLocationStateRecord,
    ) -> Result<()> {
        match location.location_kind.as_str() {
            "source-blob" | "record-blob" => self.cleanup_blob(operation_id, location),
            "participant-file" => self.cleanup_participant_file(operation_id, location),
            // The store owns inspection for these kinds; the caller's claimed
            // state is not trusted, so a location is verified only after it was
            // actually searched.
            "staging" | "temporary-exports" | "sqlite-payloads" | "publication-intent" => {
                self.workspace.verify_retention_location(
                    operation_id,
                    &location.location_id,
                    mneme_store::RetentionLocationState::Pending,
                    None,
                )?;
                Ok(())
            }
            // These kinds have no purge adapter in this build; they are
            // reported as unavailable instead of being claimed as cleaned.
            "participant-store" => {
                self.workspace.verify_retention_location(
                    operation_id,
                    &location.location_id,
                    mneme_store::RetentionLocationState::Unavailable,
                    Some("participant-store-not-purgeable"),
                )?;
                Ok(())
            }
            "unregistered-store" => {
                self.workspace.verify_retention_location(
                    operation_id,
                    &location.location_id,
                    mneme_store::RetentionLocationState::Unavailable,
                    Some("unregistered-payload-store"),
                )?;
                Ok(())
            }
            "working-file" => self.cleanup_working_file(operation_id, location),
            _ => {
                self.workspace.verify_retention_location(
                    operation_id,
                    &location.location_id,
                    mneme_store::RetentionLocationState::Failed,
                    Some("unregistered-location-kind"),
                )?;
                Ok(())
            }
        }
    }

    fn cleanup_blob(
        &mut self,
        operation_id: &str,
        location: &mneme_store::RetentionLocationStateRecord,
    ) -> Result<()> {
        match self.workspace.purge_retention_blob(
            operation_id,
            &location.location_id,
            &location.location_kind,
            &location.locator,
        ) {
            Ok(_) => Ok(()),
            Err(mneme_store::Failure::InjectedFault(point)) => {
                Err(mneme_store::Failure::InjectedFault(point).into())
            }
            Err(mneme_store::Failure::Io { .. })
            | Err(mneme_store::Failure::CorruptBlob { .. }) => {
                self.workspace.verify_retention_location(
                    operation_id,
                    &location.location_id,
                    mneme_store::RetentionLocationState::Failed,
                    Some("payload-removal-failed"),
                )?;
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    fn cleanup_participant_file(
        &mut self,
        operation_id: &str,
        location: &mneme_store::RetentionLocationStateRecord,
    ) -> Result<()> {
        match self.workspace.purge_retention_participant_file(
            operation_id,
            &location.location_id,
            &location.locator,
        ) {
            Ok(_) => Ok(()),
            Err(mneme_store::Failure::InjectedFault(point)) => {
                Err(mneme_store::Failure::InjectedFault(point).into())
            }
            Err(mneme_store::Failure::Io { .. })
            | Err(mneme_store::Failure::CorruptBlob { .. }) => {
                self.workspace.verify_retention_location(
                    operation_id,
                    &location.location_id,
                    mneme_store::RetentionLocationState::Failed,
                    Some("participant-file-removal-failed"),
                )?;
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    fn cleanup_working_file(
        &mut self,
        operation_id: &str,
        location: &mneme_store::RetentionLocationStateRecord,
    ) -> Result<()> {
        match self.workspace.purge_retention_working_file(
            operation_id,
            &location.location_id,
            &location.locator,
        ) {
            Ok(_) => Ok(()),
            Err(mneme_store::Failure::InjectedFault(point)) => {
                Err(mneme_store::Failure::InjectedFault(point).into())
            }
            Err(mneme_store::Failure::Io { .. }) => {
                self.workspace.verify_retention_location(
                    operation_id,
                    &location.location_id,
                    mneme_store::RetentionLocationState::Failed,
                    Some("working-file-removal-failed"),
                )?;
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    fn result(
        &self,
        operation: mneme_store::RetentionOperation,
        run: CleanupRun,
    ) -> Result<Outcome> {
        let locations = self
            .workspace
            .retention_locations(&operation.operation_id)?;
        let states = location_states(&locations);
        let is_physical_cleanup_complete = mneme_kernel::cleanup::physically_complete(&states);
        let summary = summarize(&locations);
        let mut limitations = Vec::new();
        if summary.pending > 0 {
            push_limitation(&mut limitations, "cleanup-pending");
        }
        if summary.retained_shared > 0 {
            push_limitation(&mut limitations, "shared-content-addressed-bytes-retained");
        }
        if summary.unavailable > 0 {
            push_limitation(&mut limitations, "external-or-editable-copy-not-removed");
        }
        if summary.failed > 0 {
            push_limitation(&mut limitations, "managed-cleanup-failed");
        }
        if run == CleanupRun::AttemptBound {
            push_limitation(&mut limitations, "cleanup-attempt-bound-reached");
        }
        if !is_physical_cleanup_complete {
            push_limitation(&mut limitations, "cleanup-incomplete");
        }
        Ok(Outcome {
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

fn push_limitation(limitations: &mut Vec<String>, code: &str) {
    if !limitations.iter().any(|entry| entry == code) {
        limitations.push(code.to_owned());
    }
}

fn location_states(
    locations: &[mneme_store::RetentionLocationStateRecord],
) -> Vec<mneme_kernel::cleanup::LocationState> {
    locations
        .iter()
        .map(|location| location.state.to_kernel())
        .collect()
}

fn job_state(states: &[mneme_kernel::cleanup::LocationState]) -> mneme_store::RetentionJobState {
    match mneme_kernel::cleanup::summarize(states) {
        mneme_kernel::cleanup::JobSummary::Complete => mneme_store::RetentionJobState::Complete,
        mneme_kernel::cleanup::JobSummary::Pending => {
            mneme_store::RetentionJobState::CleanupPending
        }
        mneme_kernel::cleanup::JobSummary::Failed => mneme_store::RetentionJobState::Failed,
        mneme_kernel::cleanup::JobSummary::Partial => mneme_store::RetentionJobState::Partial,
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

fn validate_request(request: &Request) -> Result<()> {
    if request.actor.trim().is_empty() || request.actor.len() > 128 {
        return Err(PolicyError::Invalid("actor is empty or too long"));
    }
    if request.idempotency_key.trim().is_empty() || request.idempotency_key.len() > 256 {
        return Err(PolicyError::Invalid("idempotency key is empty or too long"));
    }
    if request.policy.version.trim().is_empty() {
        return Err(PolicyError::Invalid("policy version is empty"));
    }
    match request.operation {
        OperationKind::ValidTimeExpiry => {
            if !matches!(request.selector, Selector::Assertion(_)) {
                return Err(PolicyError::Invalid(
                    "valid-time expiry requires an assertion selector",
                ));
            }
            if request.effective.is_none() {
                return Err(PolicyError::Invalid(
                    "valid-time expiry requires an effective instant",
                ));
            }
        }
        OperationKind::AssertionRetraction => {
            if !matches!(
                request.selector,
                Selector::Assertion(_) | Selector::SourceSupport(_)
            ) {
                return Err(PolicyError::Invalid(
                    "retraction requires an assertion or source-support selector",
                ));
            }
        }
        OperationKind::SourcePruning | OperationKind::Forget => {
            if matches!(request.selector, Selector::Assertion(_)) {
                return Err(PolicyError::Invalid(
                    "source operations require a source or content selector",
                ));
            }
            if matches!(request.selector, Selector::SourceSupport(_))
                && request.operation == OperationKind::Forget
            {
                return Err(PolicyError::Invalid(
                    "forget requires a source or content selector",
                ));
            }
        }
    }
    Ok(())
}

/// The request identity an idempotency key is bound to.
///
/// Every input that changes the outcome is covered: the operation, the
/// selector, the effective instant, and every policy flag. A retry with a
/// different effective time or policy is therefore a different request instead
/// of silently returning the first operation.
fn request_fingerprint(request: &Request) -> mneme_core::ContentDigest {
    let (target, revision, digest) = request.selector.parts();
    let fields = vec![
        mneme_core::Value::symbol(request.operation.name()),
        mneme_core::Value::symbol(request.selector.kind()),
        target.map_or_else(
            || mneme_core::Value::symbol("none"),
            mneme_core::RecordId::to_value,
        ),
        revision.map_or_else(
            || mneme_core::Value::symbol("none"),
            mneme_core::RevisionId::to_value,
        ),
        digest.map_or_else(
            || mneme_core::Value::symbol("none"),
            mneme_core::ContentDigest::to_value,
        ),
        request.effective.map_or_else(
            || mneme_core::Value::symbol("none"),
            |effective| mneme_core::Value::integer(effective.nanos()),
        ),
        mneme_core::Value::string(request.policy.version.clone()),
        mneme_core::Value::integer(i64::from(u8::from(
            request.policy.retain_assertion_after_prune,
        ))),
        mneme_core::Value::integer(i64::from(u8::from(request.policy.block_content_replay))),
        mneme_core::Value::integer(i64::from(u8::from(
            request.policy.retain_withdrawn_evidence_metadata,
        ))),
    ];
    mneme_core::request_fingerprint(&mneme_core::Value::record_named(
        "retention-request",
        fields,
    ))
}

/// Whether one plan keeps content-replay entries for the erased bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ContentReplay {
    Block,
    Allow,
}

impl ContentReplay {
    fn enabled(self) -> bool {
        self == ContentReplay::Block
    }
}

/// The pinned snapshot and indexes one plan derives its decisions from.
struct PlanContext<'a> {
    view: &'a mneme_memory::View,
    records: &'a [mneme_core::RecordEnvelope],
    by_id: std::collections::BTreeMap<mneme_core::RecordId, &'a mneme_core::RecordEnvelope>,
    derivations: std::collections::BTreeMap<mneme_core::RecordId, Vec<mneme_core::RecordId>>,
}

impl<'a> PlanContext<'a> {
    fn new(view: &'a mneme_memory::View) -> Result<Self> {
        let records = view.snapshot().records.as_slice();
        if records.len() > MAX_PLAN_RECORDS {
            return Err(PolicyError::Policy(
                "retention plan exceeds the 1M record bound",
            ));
        }
        let by_id = records
            .iter()
            .map(|record| (record.record_id, record))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut derivations: std::collections::BTreeMap<
            mneme_core::RecordId,
            Vec<mneme_core::RecordId>,
        > = std::collections::BTreeMap::new();
        for record in records {
            if record.kind != mneme_core::RecordKind::Derivation {
                continue;
            }
            let derivation = view.derivation(record.record_id)?;
            derivations
                .entry(derivation.conclusion)
                .or_default()
                .push(record.record_id);
        }
        Ok(PlanContext {
            view,
            records,
            by_id,
            derivations,
        })
    }
}

fn build_plan(
    workspace: &mneme_store::Workspace,
    view: &mneme_memory::View,
    request: &Request,
) -> Result<Plan> {
    validate_request(request)?;
    let context = PlanContext::new(view)?;
    let operation_id = format!("retention-{}", mneme_store::payload::random_hex(16)?);
    let generation = workspace.eligibility_generation()?.saturating_add(1);
    let mut plan = Plan {
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
        OperationKind::ValidTimeExpiry => plan_expiry(&context, request, &mut plan)?,
        OperationKind::AssertionRetraction => plan_retraction(&context, request, &mut plan)?,
        OperationKind::SourcePruning => plan_pruning(workspace, &context, request, &mut plan)?,
        OperationKind::Forget => plan_forget(workspace, &context, request, &mut plan)?,
    }
    // Every operation records the managed inventory, even one that removes no
    // payload: a receipt may claim complete cleanup only after inspecting it.
    add_inventory_locations(workspace, &std::collections::BTreeSet::new(), &mut plan)?;
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

fn selector_row(request: &Request) -> mneme_store::RetentionSelector {
    let (target, revision, digest) = request.selector.parts();
    mneme_store::RetentionSelector {
        ordinal: 0,
        kind: request.selector.kind().to_owned(),
        target,
        revision,
        digest,
    }
}

fn plan_expiry(context: &PlanContext<'_>, request: &Request, plan: &mut Plan) -> Result<()> {
    let Selector::Assertion(assertion_id) = request.selector else {
        return Err(PolicyError::Invalid(
            "valid-time expiry requires an assertion",
        ));
    };
    let assertion = context.view.assertion(assertion_id).map_err(map_missing)?;
    require_in_scope(&assertion.record, &request.scope)?;
    let effective = request
        .effective
        .ok_or(PolicyError::Invalid("expiry effective time is required"))?;
    let valid_time = expired_time(assertion.valid_time, effective)?;
    let mut payload = assertion.record.payload.clone();
    payload.insert(
        mneme_core::Symbol::from("valid-time"),
        valid_time.to_value(),
    );
    if let Some((kind, outcome)) = expiry_decision(assertion.lifecycle)? {
        // A non-proposed revision must cite a decision committed in the same
        // batch, by the batch actor, against the base this revision replaces.
        let decision_id = fresh_id()?;
        let decision = mneme_memory::build_decision(
            decision_id,
            fresh_revision()?,
            &assertion.record.scope,
            mneme_memory::DecisionOptions {
                kind,
                target: assertion_id,
                actor: &request.actor,
                policy: &request.policy.version,
                input_revision: request.base_revision,
                outcome,
                rationale: "retention valid-time expiry re-enacts the current lifecycle",
                evidence: &[],
                related: &[],
            },
        );
        payload.insert(
            mneme_core::Symbol::from("decision"),
            mneme_core::Reference::local(decision_id, mneme_core::RecordKind::Decision).to_value(),
        );
        plan.records.push(decision);
    }
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

/// The decision an expiry revision of a settled lifecycle must cite.
fn expiry_decision(
    lifecycle: mneme_core::Lifecycle,
) -> Result<Option<(mneme_memory::DecisionKind, &'static str)>> {
    match lifecycle {
        mneme_core::Lifecycle::Proposed => Ok(None),
        mneme_core::Lifecycle::Accepted => {
            Ok(Some((mneme_memory::DecisionKind::Acceptance, "accepted")))
        }
        mneme_core::Lifecycle::Disputed => Ok(Some((
            mneme_memory::DecisionKind::ConflictResolution,
            "disputed",
        ))),
        mneme_core::Lifecycle::Superseded => Err(PolicyError::Conflict(
            "a superseded assertion has no applicable validity to expire",
        )),
        mneme_core::Lifecycle::Retracted => Err(PolicyError::Conflict(
            "a retracted assertion has no applicable validity to expire",
        )),
    }
}

fn expired_time(
    valid_time: mneme_core::ValidTime,
    effective: mneme_core::Timestamp,
) -> Result<mneme_core::ValidTime> {
    match valid_time {
        // An unknown validity is not an open start bound: writing an end bound
        // over it would assert that the claim was valid at every earlier
        // instant, which was never recorded.
        mneme_core::ValidTime::Unknown => Err(PolicyError::Conflict(
            "valid-time expiry requires a known validity interval",
        )),
        mneme_core::ValidTime::Bounded { start, end } => {
            if start.is_some_and(|start| effective < start) {
                return Err(PolicyError::Conflict(
                    "requested expiry precedes the valid-time start",
                ));
            }
            if end.is_some_and(|end| end <= effective) {
                return Err(PolicyError::Conflict(
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

fn plan_retraction(context: &PlanContext<'_>, request: &Request, plan: &mut Plan) -> Result<()> {
    let Selector::Assertion(assertion_id) = request.selector else {
        if let Selector::SourceSupport(source) = request.selector {
            return plan_support_retraction(context, request, source, plan);
        }
        return Err(PolicyError::Invalid(
            "assertion retraction requires an assertion or source support",
        ));
    };
    let assertion = context.view.assertion(assertion_id).map_err(map_missing)?;
    require_in_scope(&assertion.record, &request.scope)?;
    if assertion.lifecycle == mneme_core::Lifecycle::Retracted {
        return Err(PolicyError::Conflict("assertion is already retracted"));
    }
    let decision_id = fresh_id()?;
    let decision_revision = fresh_revision()?;
    let assertion_revision = fresh_revision()?;
    let decision = mneme_memory::build_decision(
        decision_id,
        decision_revision,
        &assertion.record.scope,
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Retraction,
            target: assertion_id,
            actor: &request.actor,
            policy: &request.policy.version,
            input_revision: request.base_revision,
            outcome: "retracted",
            rationale: "retention request; no opposite proposition asserted",
            evidence: &[],
            related: &[],
        },
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
    plan.invalidated_derivations = dependent_derivations(context, assertion_id, &request.scope)?;
    plan.retained_metadata
        .push("withdrawn-assertion-history".to_owned());
    plan.limitations
        .push("retraction-does-not-assert-the-opposite".to_owned());
    Ok(())
}

fn plan_support_retraction(
    context: &PlanContext<'_>,
    request: &Request,
    source: mneme_core::RecordId,
    plan: &mut Plan,
) -> Result<()> {
    let source_view = context.view.source(source).map_err(map_missing)?;
    require_in_scope(&source_view.record, &request.scope)?;
    let deps = dependencies_for_sources(context, &[source], &request.scope)?;
    let withdrawn = compute_withdrawal(context, &[source], &deps, &request.scope)?;
    let withdrawn_evidence: std::collections::BTreeSet<mneme_core::RecordId> = deps
        .evidence
        .iter()
        .filter(|evidence| withdrawn.contains(*evidence))
        .copied()
        .collect();
    let mode = if request.policy.retain_withdrawn_evidence_metadata {
        mneme_store::SuppressionMode::Withdrawn
    } else {
        mneme_store::SuppressionMode::Forgotten
    };
    for evidence in &withdrawn_evidence {
        let record = context.view.record(*evidence)?;
        plan.suppressed.push(PlannedSuppression {
            target: *evidence,
            revision: None,
            kind: mneme_core::RecordKind::Evidence,
            mode,
            content_digest: None,
        });
        if mode == mneme_store::SuppressionMode::Forgotten {
            add_record_blob_locations(record, plan);
        }
    }
    plan.withdrawn_evidence = withdrawn_evidence.iter().copied().collect();
    plan.surviving_assertions = deps
        .assertions
        .iter()
        .filter(|assertion| !withdrawn.contains(*assertion))
        .copied()
        .collect();
    plan.invalidated_derivations = deps
        .derivations
        .iter()
        .filter(|derivation| withdrawn.contains(*derivation))
        .copied()
        .collect();
    plan.retained_metadata
        .push("withdrawn-evidence-metadata".to_owned());
    Ok(())
}

fn plan_pruning(
    workspace: &mneme_store::Workspace,
    context: &PlanContext<'_>,
    request: &Request,
    plan: &mut Plan,
) -> Result<()> {
    let sources = resolve_sources(workspace, context.view, request)?;
    let deps = dependencies_for_sources(context, &sources, &request.scope)?;
    if !deps.assertions.is_empty() && !request.policy.retain_assertion_after_prune {
        return Err(PolicyError::Policy(
            "policy does not permit retaining assertions after source pruning",
        ));
    }
    let history = source_history(workspace, context.view, &sources)?;
    let mut forgotten = std::collections::BTreeSet::new();
    let mut documents = std::collections::BTreeSet::new();
    for source in &sources {
        plan_pruned_source(context, *source, &history, plan)?;
        forgotten.insert(*source);
    }
    // Document, anchor and binding records pin source bytes by reference, so a
    // pruned source still has readable copies in them.
    let mut targets = forgotten.clone();
    collect_copies(context, &request.scope, &mut targets, &mut documents)?;
    for record_id in targets.iter().filter(|target| !forgotten.contains(*target)) {
        let record = context.view.record(*record_id)?;
        plan.suppressed.push(PlannedSuppression {
            target: *record_id,
            revision: None,
            kind: record.kind,
            mode: mneme_store::SuppressionMode::Forgotten,
            content_digest: None,
        });
        for revision in workspace.record_revisions(*record_id)? {
            add_record_blob_locations(&revision, plan);
        }
    }
    add_inventory_locations(workspace, &documents, plan)?;
    plan.surviving_assertions = deps.assertions.iter().copied().collect();
    plan.retained_metadata
        .push("source-byte-absence".to_owned());
    declare_managed_paths(plan);
    plan.limitations
        .push("pruning-is-not-a-truth-or-retraction-operation".to_owned());
    Ok(())
}

/// Plan the removal and replacement records for one pruned source.
fn plan_pruned_source(
    context: &PlanContext<'_>,
    source: mneme_core::RecordId,
    history: &std::collections::BTreeMap<mneme_core::RecordId, Vec<SourceRevisionDigest>>,
    plan: &mut Plan,
) -> Result<()> {
    let source_view = context.view.source(source).map_err(map_missing)?;
    let Some(current_digest) = source_view.digest() else {
        return Err(PolicyError::Conflict(
            "source bytes are already unavailable",
        ));
    };
    let revisions = history.get(&source).ok_or(PolicyError::Invalid(
        "source revision history is unavailable",
    ))?;
    for revision in revisions {
        if let Some(digest) = revision.digest {
            // The raw bytes are inventoried for removal, but the revision
            // itself stays readable: pruning preserves the record envelope
            // and a pinned citation resolves to content-pruned metadata.
            // Pruning is not content-wide erasure, so it neither hides the
            // revision nor blocks a later import of the same bytes.
            add_blob_location(
                digest,
                "source-blob",
                format!("source-blob:{}", digest.to_hex()),
                plan,
            );
        }
    }
    let mut replacement = mneme_memory::build_unavailable_source_with_digest(
        source,
        fresh_revision()?,
        &source_view.record.scope,
        mneme_memory::UnavailableSourceWithDigestOptions {
            reason: "source bytes pruned under retention policy",
            availability: "pruned",
            prior_digest: Some(current_digest),
            entity: source_view.entity,
            path_hint: source_view.path_hint.as_deref(),
        },
    );
    replacement.predecessor = Some(source_view.record.revision_id);
    plan.records.push(replacement);
    plan.source_targets.push(source);
    if let Some(path) = &source_view.path_hint {
        add_working_file_location(path, current_digest, plan);
    }
    Ok(())
}

/// The records a forget plan must cover beyond the selected sources.
#[derive(Default)]
struct ForgetState {
    forgotten_records: std::collections::BTreeSet<mneme_core::RecordId>,
    forgotten_documents: std::collections::BTreeSet<mneme_core::RecordId>,
    forgotten_revisions: std::collections::BTreeMap<
        (mneme_core::RecordId, mneme_core::RevisionId),
        Option<mneme_core::ContentDigest>,
    >,
    suppressed_assertions: std::collections::BTreeSet<mneme_core::RecordId>,
    suppressed_derivations: std::collections::BTreeSet<mneme_core::RecordId>,
    revised_assertions: std::collections::BTreeSet<mneme_core::RecordId>,
    withdrawn: std::collections::BTreeSet<mneme_core::RecordId>,
    identity_digests:
        std::collections::BTreeMap<mneme_core::RecordId, Option<mneme_core::ContentDigest>>,
    content_digests: std::collections::BTreeSet<mneme_core::ContentDigest>,
}

fn plan_forget(
    workspace: &mneme_store::Workspace,
    context: &PlanContext<'_>,
    request: &Request,
    plan: &mut Plan,
) -> Result<()> {
    let sources = resolve_sources(workspace, context.view, request)?;
    let deps = dependencies_for_sources(context, &sources, &request.scope)?;
    let withdrawn = compute_withdrawal(context, &sources, &deps, &request.scope)?;
    let history = source_history(workspace, context.view, &sources)?;
    let mut state = ForgetState {
        withdrawn: deps
            .evidence
            .iter()
            .filter(|evidence| withdrawn.contains(*evidence))
            .copied()
            .collect(),
        ..ForgetState::default()
    };
    let replay = if request.policy.block_content_replay {
        ContentReplay::Block
    } else {
        ContentReplay::Allow
    };
    let mut collection = ForgetCollection {
        replay,
        state: &mut state,
        plan: &mut *plan,
    };
    collect_source_targets(context, &sources, &history, &mut collection)?;
    mark_withdrawn_dependents(context, &deps, &withdrawn, &request.scope, &mut state)?;
    state
        .forgotten_records
        .extend(state.suppressed_assertions.iter().copied());
    state
        .forgotten_records
        .extend(state.suppressed_derivations.iter().copied());
    collect_copies(
        context,
        &request.scope,
        &mut state.forgotten_records,
        &mut state.forgotten_documents,
    )?;
    revise_forget_assertions(context.view, &mut state, plan)?;
    record_forgotten_targets(workspace, context.view, &state, plan)?;
    record_forgotten_revisions(context.view, &state, plan)?;
    collect_publication_locations(workspace, &state.content_digests, plan)?;
    add_inventory_locations(workspace, &state.forgotten_documents, plan)?;
    finish_forget_plan(request, &state, plan);
    Ok(())
}

/// The forget state and plan one collection pass writes into.
struct ForgetCollection<'a> {
    /// Whether content-replay entries are kept for the erased bytes.
    replay: ContentReplay,
    state: &'a mut ForgetState,
    plan: &'a mut Plan,
}

/// Mark the withdrawn dependents so the plan covers them.
fn mark_withdrawn_dependents(
    context: &PlanContext<'_>,
    deps: &Dependencies,
    withdrawn: &std::collections::BTreeSet<mneme_core::RecordId>,
    scope: &mneme_core::ScopeId,
    state: &mut ForgetState,
) -> Result<()> {
    for record_id in &deps.episodes {
        if withdrawn.contains(record_id) {
            state.forgotten_records.insert(*record_id);
        }
    }
    for record_id in &deps.evidence {
        if withdrawn.contains(record_id) {
            state.forgotten_records.insert(*record_id);
        }
    }
    for record_id in &deps.derivations {
        if withdrawn.contains(record_id) {
            state.suppressed_derivations.insert(*record_id);
        }
    }
    for record_id in &deps.assertions {
        let Some(record) = context.by_id.get(record_id) else {
            continue;
        };
        if record.kind != mneme_core::RecordKind::Assertion || &record.scope != scope {
            continue;
        }
        if withdrawn.contains(record_id) {
            state.suppressed_assertions.insert(*record_id);
            continue;
        }
        let assertion = context.view.assertion(*record_id)?;
        if assertion
            .evidence
            .iter()
            .any(|evidence| state.withdrawn.contains(evidence))
        {
            state.revised_assertions.insert(*record_id);
        }
    }
    Ok(())
}

fn collect_source_targets(
    context: &PlanContext<'_>,
    sources: &[mneme_core::RecordId],
    history: &std::collections::BTreeMap<mneme_core::RecordId, Vec<SourceRevisionDigest>>,
    collection: &mut ForgetCollection<'_>,
) -> Result<()> {
    let is_block_content = collection.replay.enabled();
    let state = &mut *collection.state;
    let plan = &mut *collection.plan;
    for source in sources {
        let source_view = context.view.source(*source).map_err(map_missing)?;
        let revisions = history.get(source).ok_or(PolicyError::Invalid(
            "source revision history is unavailable",
        ))?;
        state.forgotten_records.insert(*source);
        let current_digest = source_view.digest().or(source_view.prior_digest);
        state
            .identity_digests
            .insert(*source, current_digest.filter(|_| is_block_content));
        for revision in revisions {
            if let Some(digest) = revision.digest {
                state.content_digests.insert(digest);
                add_blob_location(
                    digest,
                    "source-blob",
                    format!("source-blob:{}", digest.to_hex()),
                    plan,
                );
                if is_block_content && !revision.is_current {
                    state
                        .forgotten_revisions
                        .insert((*source, revision.revision), Some(digest));
                }
            }
            add_blob_location(
                revision.full_digest,
                "record-blob",
                format!("record-blob:{}", revision.full_digest.to_hex()),
                plan,
            );
        }
        if let Some(path) = &source_view.path_hint
            && let Some(digest) = current_digest
        {
            add_working_file_location(path, digest, plan);
        }
        plan.source_targets.push(*source);
    }
    Ok(())
}

/// One retained revision of a source record and the bytes it accounts for.
struct SourceRevisionDigest {
    revision: mneme_core::RevisionId,
    digest: Option<mneme_core::ContentDigest>,
    full_digest: mneme_core::ContentDigest,
    is_current: bool,
}

fn source_history(
    workspace: &mneme_store::Workspace,
    view: &mneme_memory::View,
    sources: &[mneme_core::RecordId],
) -> Result<std::collections::BTreeMap<mneme_core::RecordId, Vec<SourceRevisionDigest>>> {
    let mut total = 0_usize;
    sources
        .iter()
        .map(
            |source| -> Result<(mneme_core::RecordId, Vec<SourceRevisionDigest>)> {
                let revisions = revisions_for_source(workspace, view, *source, &mut total)?;
                Ok((*source, revisions))
            },
        )
        .collect()
}

/// The retained revisions of one source, charged against the plan's bound.
fn revisions_for_source(
    workspace: &mneme_store::Workspace,
    view: &mneme_memory::View,
    source: mneme_core::RecordId,
    total: &mut usize,
) -> Result<Vec<SourceRevisionDigest>> {
    let source_view = view.source(source).map_err(map_missing)?;
    let current = source_view.record.revision_id;
    let envelopes = workspace.record_revisions(source)?;
    let observed = total.saturating_add(envelopes.len());
    if observed > MAX_SOURCE_REVISIONS {
        return Err(PolicyError::Policy(
            "retention plan exceeds the revision bound",
        ));
    }
    *total = observed;
    if envelopes.is_empty() {
        return Err(PolicyError::Conflict("source has no retained revision"));
    }
    envelopes
        .into_iter()
        .map(|envelope| -> Result<SourceRevisionDigest> {
            let parsed = mneme_memory::SourceView::parse(envelope.clone())?;
            Ok(SourceRevisionDigest {
                revision: envelope.revision_id,
                digest: parsed.digest().or(parsed.prior_digest),
                full_digest: envelope.full_digest(),
                is_current: envelope.revision_id == current,
            })
        })
        .collect()
}

fn revise_forget_assertions(
    view: &mneme_memory::View,
    state: &mut ForgetState,
    plan: &mut Plan,
) -> Result<()> {
    for assertion_id in &state.revised_assertions {
        let assertion = view.assertion(*assertion_id)?;
        let remaining: Vec<mneme_core::Reference> = assertion
            .evidence
            .iter()
            .filter(|evidence| !state.withdrawn.contains(*evidence))
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
        // The prior revisions stay retained. The rewrite is backed by the
        // decision that accepted the predecessor, and the belief calculation
        // proves that by walking the predecessor chain; suppressing it would
        // make the surviving assertion unbacked. The prior payloads carry only
        // the forgotten evidence identifiers, never its text.
        plan.revised_assertions.push(*assertion_id);
        plan.surviving_assertions.push(*assertion_id);
    }
    Ok(())
}

fn record_forgotten_targets(
    workspace: &mneme_store::Workspace,
    view: &mneme_memory::View,
    state: &ForgetState,
    plan: &mut Plan,
) -> Result<()> {
    for record_id in &state.forgotten_records {
        let record = view.record(*record_id)?;
        plan.suppressed.push(PlannedSuppression {
            target: *record_id,
            revision: None,
            kind: record.kind,
            mode: mneme_store::SuppressionMode::Forgotten,
            content_digest: state.identity_digests.get(record_id).copied().flatten(),
        });
        for revision in workspace.record_revisions(*record_id)? {
            add_record_blob_locations(&revision, plan);
        }
    }
    Ok(())
}

fn record_forgotten_revisions(
    view: &mneme_memory::View,
    state: &ForgetState,
    plan: &mut Plan,
) -> Result<()> {
    for ((record_id, revision), digest) in &state.forgotten_revisions {
        // Every revision of a record has the record's kind, so the current
        // envelope names it without re-reading the revision history.
        let kind = view.record(*record_id)?.kind;
        // An identity suppression already hides every revision; a digest-free
        // revision entry would only repeat it. A digest-bearing entry stays so
        // the content-replay block covers the bytes that revision held.
        if digest.is_none() && state.forgotten_records.contains(record_id) {
            continue;
        }
        plan.suppressed.push(PlannedSuppression {
            target: *record_id,
            revision: Some(*revision),
            kind,
            mode: mneme_store::SuppressionMode::Forgotten,
            content_digest: *digest,
        });
    }
    Ok(())
}

fn collect_copies(
    context: &PlanContext<'_>,
    scope: &mneme_core::ScopeId,
    forgotten: &mut std::collections::BTreeSet<mneme_core::RecordId>,
    documents: &mut std::collections::BTreeSet<mneme_core::RecordId>,
) -> Result<()> {
    loop {
        let mut is_changed = false;
        for record in context.records {
            if &record.scope != scope
                || forgotten.contains(&record.record_id)
                || !copy_kind(record.kind)
            {
                continue;
            }
            if references_any(&record.payload.to_value(), forgotten) {
                is_changed |= forgotten.insert(record.record_id);
                if record.kind == mneme_core::RecordKind::Document {
                    documents.insert(record.record_id);
                }
            }
        }
        if !is_changed {
            return Ok(());
        }
    }
}

fn copy_kind(kind: mneme_core::RecordKind) -> bool {
    matches!(
        kind,
        mneme_core::RecordKind::Checkpoint
            | mneme_core::RecordKind::Proposal
            | mneme_core::RecordKind::Decision
            | mneme_core::RecordKind::Document
            | mneme_core::RecordKind::DocumentAnchor
            | mneme_core::RecordKind::DocumentBinding
    )
}

fn collect_publication_locations(
    workspace: &mneme_store::Workspace,
    digests: &std::collections::BTreeSet<mneme_core::ContentDigest>,
    plan: &mut Plan,
) -> Result<()> {
    if digests.is_empty() {
        return Ok(());
    }
    for intent in workspace.publication_intents()? {
        let Some(observed) = intent.observed else {
            continue;
        };
        if !digests.contains(&observed) {
            continue;
        }
        // The source's own managed working copy is already a planned
        // working-file location. Once that exact file is purged the published
        // copy is gone; reporting the intent separately would fail forever
        // even though no copy remains.
        let is_covered_by_working_file = plan.locations.iter().any(|location| {
            location.location_kind == "working-file"
                && location.locator == format!("{}#{}", intent.path, observed.to_hex())
        });
        if is_covered_by_working_file {
            continue;
        }
        push_location(
            plan,
            format!("publication-intent:{}", intent.intent_id),
            "publication-intent",
            intent.intent_id.clone(),
        );
        add_working_file_location(&intent.path, observed, plan);
    }
    Ok(())
}

fn add_inventory_locations(
    workspace: &mneme_store::Workspace,
    documents: &std::collections::BTreeSet<mneme_core::RecordId>,
    plan: &mut Plan,
) -> Result<()> {
    for (kind, label) in [
        ("staging", "workspace-staging"),
        ("temporary-exports", "workspace-temporary-exports"),
        ("sqlite-payloads", "workspace-sqlite-payloads"),
    ] {
        push_location(plan, format!("inventory:{kind}"), kind, label.to_owned());
    }
    for participant in workspace.retention_participants()? {
        if participant.storage_role == "document-keyed-files" {
            let base = participant.inventory_locator.trim_end_matches('/');
            let mut is_planned = false;
            for document in documents {
                let locator = format!("{base}/{}.json", document.to_hex());
                if mneme_kernel::text::is_canonical_relative_path(locator.as_bytes()) {
                    push_location(
                        plan,
                        format!(
                            "participant-file:{}:{}",
                            participant.name,
                            document.to_hex()
                        ),
                        "participant-file",
                        locator,
                    );
                    is_planned = true;
                }
            }
            // A document-keyed store with no affected document has nothing to
            // purge; a store whose directory cannot address its draft files is
            // reported instead of assumed clean.
            if is_planned || documents.is_empty() {
                continue;
            }
        }
        push_location(
            plan,
            format!("participant:{}", participant.name),
            "participant-store",
            participant.inventory_locator.clone(),
        );
    }
    for entry in workspace.unregistered_payload_entries()? {
        push_location(
            plan,
            format!("unregistered-store:{entry}"),
            "unregistered-store",
            entry,
        );
    }
    Ok(())
}

fn finish_forget_plan(request: &Request, state: &ForgetState, plan: &mut Plan) {
    plan.suppressed.sort_by_key(|suppression| {
        (
            suppression.target,
            suppression
                .revision
                .unwrap_or(mneme_core::RevisionId::from_bytes([0; 16])),
        )
    });
    plan.invalidated_derivations = state.suppressed_derivations.iter().copied().collect();
    plan.retained_metadata.extend([
        "suppression-identity".to_owned(),
        "operation-generation".to_owned(),
    ]);
    if request.policy.block_content_replay && !state.content_digests.is_empty() {
        plan.retained_metadata
            .push("content-replay-block".to_owned());
    }
    declare_managed_paths(plan);
    plan.limitations
        .push("no-forensic-media-erasure-claim".to_owned());
    plan.limitations
        .push("unregistered-semantic-copies-not-inferred".to_owned());
}

fn declare_managed_paths(plan: &mut Plan) {
    if plan
        .locations
        .iter()
        .any(|location| location.location_kind == "working-file")
    {
        plan.retained_metadata
            .push(mneme_store::lifecycle::MANAGED_WORKING_PATH_DECLARATION.to_owned());
    }
}

/// A view-context refusal, with a store refusal kept on its own variant.
fn view_context_error(error: mneme_memory::EvidenceError) -> PolicyError {
    match error {
        mneme_memory::EvidenceError::Store(error) => PolicyError::Store(error),
        error @ mneme_memory::EvidenceError::InvalidRecord { .. }
        | error @ mneme_memory::EvidenceError::Missing { .. }
        | error @ mneme_memory::EvidenceError::Policy(_)
        | error @ mneme_memory::EvidenceError::Validation(_)
        | error @ mneme_memory::EvidenceError::Invalid(_)
        | error @ mneme_memory::EvidenceError::Truncated => PolicyError::Engine(error),
    }
}

fn resolve_sources(
    workspace: &mneme_store::Workspace,
    view: &mneme_memory::View,
    request: &Request,
) -> Result<Vec<mneme_core::RecordId>> {
    match request.selector {
        Selector::Source(source) => {
            let record = view.source(source).map_err(map_missing)?;
            require_in_scope(&record.record, &request.scope)?;
            Ok(vec![source])
        }
        Selector::SourceRevision(source, revision) => {
            let record = view.source(source).map_err(map_missing)?;
            require_in_scope(&record.record, &request.scope)?;
            let revisions = workspace.record_revisions(source)?;
            if !revisions
                .iter()
                .any(|retained| retained.revision_id == revision)
            {
                return Err(PolicyError::NotFound);
            }
            Ok(vec![source])
        }
        Selector::Content(digest) => {
            let mut sources = Vec::new();
            for record in &view.snapshot().records {
                // A source in another scope is invisible here: matching it
                // would let the caller learn whether someone else holds these
                // bytes.
                if record.kind != mneme_core::RecordKind::SourceRevision
                    || record.scope != request.scope
                {
                    continue;
                }
                if sources.len() >= MAX_PLAN_RECORDS {
                    return Err(PolicyError::Policy(
                        "content selector exceeds the source bound",
                    ));
                }
                let is_matched = workspace
                    .record_revisions(record.record_id)?
                    .into_iter()
                    .any(|envelope| {
                        mneme_memory::SourceView::parse(envelope)
                            .map(|source| source.digest().or(source.prior_digest) == Some(digest))
                            .unwrap_or(false)
                    });
                if is_matched {
                    sources.push(record.record_id);
                }
            }
            if sources.is_empty() {
                return Err(PolicyError::NotFound);
            }
            Ok(sources)
        }
        Selector::SourceSupport(_) | Selector::Assertion(_) => Err(PolicyError::Invalid(
            "operation requires a source or content selector",
        )),
    }
}

fn require_in_scope(
    record: &mneme_core::RecordEnvelope,
    scope: &mneme_core::ScopeId,
) -> Result<()> {
    if &record.scope == scope {
        Ok(())
    } else {
        // An out-of-scope target is reported exactly like an unknown one.
        Err(PolicyError::NotFound)
    }
}

/// The records one source selection depends on, transitively.
#[derive(Clone, Debug, Default)]
struct Dependencies {
    episodes: std::collections::BTreeSet<mneme_core::RecordId>,
    evidence: std::collections::BTreeSet<mneme_core::RecordId>,
    assertions: std::collections::BTreeSet<mneme_core::RecordId>,
    derivations: std::collections::BTreeSet<mneme_core::RecordId>,
}

fn dependencies_for_sources(
    context: &PlanContext<'_>,
    sources: &[mneme_core::RecordId],
    scope: &mneme_core::ScopeId,
) -> Result<Dependencies> {
    let mut deps = Dependencies::default();
    loop {
        let closure = dependency_closure(sources, &deps);
        let mut is_changed = false;
        for record in context.records {
            if dependency_is_known(record, &deps, scope) {
                continue;
            }
            match record.kind {
                mneme_core::RecordKind::Episode => {
                    let episode = context.view.episode(record.record_id)?;
                    let is_linked = episode
                        .source
                        .is_some_and(|source| closure.contains(&source))
                        || episode
                            .related
                            .iter()
                            .any(|related| closure.contains(related));
                    if is_linked {
                        deps.episodes.insert(record.record_id);
                        is_changed = true;
                    }
                }
                mneme_core::RecordKind::Evidence => {
                    let evidence = context.view.evidence(record.record_id)?;
                    // Ancestry may pass through assertions and derivations, so
                    // the whole dependency closure participates, not only the
                    // source and episode identifiers.
                    let is_linked = closure.contains(&evidence.source)
                        || evidence
                            .ancestry
                            .iter()
                            .any(|ancestor| closure.contains(ancestor));
                    if is_linked {
                        deps.evidence.insert(record.record_id);
                        is_changed = true;
                    }
                }
                mneme_core::RecordKind::Assertion => {
                    let assertion = context.view.assertion(record.record_id)?;
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
                    let derivation = context.view.derivation(record.record_id)?;
                    if derivation
                        .premises
                        .iter()
                        .any(|premise| closure.contains(premise))
                    {
                        deps.derivations.insert(record.record_id);
                        deps.assertions.insert(derivation.conclusion);
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

/// The records already attributed to the selection.
fn dependency_closure(
    sources: &[mneme_core::RecordId],
    deps: &Dependencies,
) -> std::collections::BTreeSet<mneme_core::RecordId> {
    let mut closure: std::collections::BTreeSet<mneme_core::RecordId> =
        sources.iter().copied().collect();
    closure.extend(deps.episodes.iter().copied());
    closure.extend(deps.evidence.iter().copied());
    closure.extend(deps.assertions.iter().copied());
    closure.extend(deps.derivations.iter().copied());
    closure
}

/// Whether a record is already attributed, or lies outside the scope.
///
/// A dependent record in another scope is left untouched: this operation
/// never broadens into that scope or reveals it.
fn dependency_is_known(
    record: &mneme_core::RecordEnvelope,
    deps: &Dependencies,
    scope: &mneme_core::ScopeId,
) -> bool {
    &record.scope != scope
        || deps.episodes.contains(&record.record_id)
        || deps.evidence.contains(&record.record_id)
        || deps.assertions.contains(&record.record_id)
        || deps.derivations.contains(&record.record_id)
}

/// The records whose support no longer survives the selection.
///
/// The fixpoint is monotone: withdrawing a record can only withdraw more, so
/// a conclusion with an independent surviving derivation stays, and a
/// derivation with any withdrawn premise goes.
fn compute_withdrawal(
    context: &PlanContext<'_>,
    sources: &[mneme_core::RecordId],
    deps: &Dependencies,
    scope: &mneme_core::ScopeId,
) -> Result<std::collections::BTreeSet<mneme_core::RecordId>> {
    let mut withdrawn: std::collections::BTreeSet<mneme_core::RecordId> =
        sources.iter().copied().collect();
    loop {
        let mut is_changed = withdraw_episodes(context, deps, &mut withdrawn)?;
        is_changed |= withdraw_evidence(context, deps, &mut withdrawn)?;
        is_changed |= withdraw_derivations(context, deps, &mut withdrawn)?;
        is_changed |= withdraw_assertions(context, deps, &mut withdrawn, scope)?;
        if !is_changed {
            return Ok(withdrawn);
        }
    }
}

/// Withdraw the episodes whose source or relation is already withdrawn.
fn withdraw_episodes(
    context: &PlanContext<'_>,
    deps: &Dependencies,
    withdrawn: &mut std::collections::BTreeSet<mneme_core::RecordId>,
) -> Result<bool> {
    let mut is_changed = false;
    for record_id in &deps.episodes {
        if withdrawn.contains(record_id) {
            continue;
        }
        let episode = context.view.episode(*record_id)?;
        let is_linked = episode
            .source
            .is_some_and(|source| withdrawn.contains(&source))
            || episode
                .related
                .iter()
                .any(|related| withdrawn.contains(related));
        if is_linked {
            withdrawn.insert(*record_id);
            is_changed = true;
        }
    }
    Ok(is_changed)
}

/// Withdraw the evidence whose source or ancestry is already withdrawn.
fn withdraw_evidence(
    context: &PlanContext<'_>,
    deps: &Dependencies,
    withdrawn: &mut std::collections::BTreeSet<mneme_core::RecordId>,
) -> Result<bool> {
    let mut is_changed = false;
    for record_id in &deps.evidence {
        if withdrawn.contains(record_id) {
            continue;
        }
        let evidence = context.view.evidence(*record_id)?;
        let is_linked = withdrawn.contains(&evidence.source)
            || evidence
                .ancestry
                .iter()
                .any(|ancestor| withdrawn.contains(ancestor));
        if is_linked {
            withdrawn.insert(*record_id);
            is_changed = true;
        }
    }
    Ok(is_changed)
}

/// Withdraw the derivations with at least one withdrawn premise.
fn withdraw_derivations(
    context: &PlanContext<'_>,
    deps: &Dependencies,
    withdrawn: &mut std::collections::BTreeSet<mneme_core::RecordId>,
) -> Result<bool> {
    let mut is_changed = false;
    for record_id in &deps.derivations {
        if withdrawn.contains(record_id) {
            continue;
        }
        let derivation = context.view.derivation(*record_id)?;
        let is_linked = derivation
            .premises
            .iter()
            .any(|premise| withdrawn.contains(premise));
        if is_linked {
            withdrawn.insert(*record_id);
            is_changed = true;
        }
    }
    Ok(is_changed)
}

/// Withdraw the in-scope assertions with neither surviving support nor a
/// surviving derivation.
fn withdraw_assertions(
    context: &PlanContext<'_>,
    deps: &Dependencies,
    withdrawn: &mut std::collections::BTreeSet<mneme_core::RecordId>,
    scope: &mneme_core::ScopeId,
) -> Result<bool> {
    let mut is_changed = false;
    for record_id in &deps.assertions {
        if withdrawn.contains(record_id) {
            continue;
        }
        let Some(record) = context.by_id.get(record_id) else {
            continue;
        };
        if record.kind != mneme_core::RecordKind::Assertion || &record.scope != scope {
            continue;
        }
        let assertion = context.view.assertion(*record_id)?;
        let has_evidence = assertion.evidence.iter().any(|evidence| {
            if withdrawn.contains(evidence) {
                return false;
            }
            context.view.evidence(*evidence).is_ok_and(|view| {
                view.relation == mneme_memory::SupportRelation::Supports
                    && view.assertion == *record_id
            })
        });
        let has_derivation = context
            .derivations
            .get(record_id)
            .is_some_and(|derivations| {
                derivations
                    .iter()
                    .any(|derivation| !withdrawn.contains(derivation))
            });
        if !has_evidence && !has_derivation {
            withdrawn.insert(*record_id);
            is_changed = true;
        }
    }
    Ok(is_changed)
}

fn dependent_derivations(
    context: &PlanContext<'_>,
    assertion: mneme_core::RecordId,
    scope: &mneme_core::ScopeId,
) -> Result<Vec<mneme_core::RecordId>> {
    let mut affected_assertions = std::collections::BTreeSet::from([assertion]);
    let mut derivations = std::collections::BTreeSet::new();
    loop {
        let mut is_changed = false;
        for record in context.records {
            if record.kind != mneme_core::RecordKind::Derivation
                || &record.scope != scope
                || derivations.contains(&record.record_id)
            {
                continue;
            }
            let derivation = context.view.derivation(record.record_id)?;
            if derivation
                .premises
                .iter()
                .any(|premise| affected_assertions.contains(premise))
            {
                let is_inserted = derivations.insert(record.record_id);
                let is_conclusion_added = affected_assertions.insert(derivation.conclusion);
                is_changed |= is_inserted || is_conclusion_added;
            }
        }
        if !is_changed {
            return Ok(derivations.into_iter().collect());
        }
    }
}

fn fresh_id() -> Result<mneme_core::RecordId> {
    Ok(mneme_core::RecordId::from_bytes(
        mneme_store::payload::random_bytes()?,
    ))
}

fn fresh_revision() -> Result<mneme_core::RevisionId> {
    Ok(mneme_core::RevisionId::from_bytes(
        mneme_store::payload::random_bytes()?,
    ))
}

fn map_missing(error: mneme_memory::EvidenceError) -> PolicyError {
    match error {
        mneme_memory::EvidenceError::Missing { .. } => PolicyError::NotFound,
        other => PolicyError::Engine(other),
    }
}

fn push_location(plan: &mut Plan, location_id: String, location_kind: &str, locator: String) {
    if plan
        .locations
        .iter()
        .any(|location| location.location_id == location_id)
    {
        return;
    }
    plan.locations.push(mneme_store::RetentionLocationPlan {
        location_id,
        location_kind: location_kind.to_owned(),
        locator,
    });
}

fn add_blob_location(
    digest: mneme_core::ContentDigest,
    kind: &str,
    location_id: String,
    plan: &mut Plan,
) {
    push_location(plan, location_id, kind, digest.to_hex());
}

fn add_record_blob_locations(record: &mneme_core::RecordEnvelope, plan: &mut Plan) {
    let digest = record.full_digest();
    add_blob_location(
        digest,
        "record-blob",
        format!("record-blob:{}", digest.to_hex()),
        plan,
    );
}

fn add_working_file_location(path: &str, digest: mneme_core::ContentDigest, plan: &mut Plan) {
    let locator = format!("{path}#{}", digest.to_hex());
    push_location(
        plan,
        format!("working-file:{locator}"),
        "working-file",
        locator,
    );
}

fn references_any(
    value: &mneme_core::Value,
    targets: &std::collections::BTreeSet<mneme_core::RecordId>,
) -> bool {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        if let Ok(reference) = mneme_core::Reference::from_value(value, &mneme_core::Path::root()) {
            if reference
                .target()
                .is_some_and(|target| targets.contains(&target))
            {
                return true;
            }
            continue;
        }
        match value {
            mneme_core::Value::Record(record) => {
                record.label();
                for field in record.fields().iter().rev() {
                    pending.push(field);
                }
            }
            mneme_core::Value::Sequence(items) => {
                for item in items.iter().rev() {
                    pending.push(item);
                }
            }
            mneme_core::Value::Set(items) => {
                for item in items.iter().rev() {
                    pending.push(item);
                }
            }
            mneme_core::Value::Dictionary(entries) => {
                for (key, value) in entries.iter().rev() {
                    pending.push(value);
                    pending.push(key);
                }
            }
            mneme_core::Value::Embedded(inner) => pending.push(inner),
            mneme_core::Value::Boolean(_)
            | mneme_core::Value::Double(_)
            | mneme_core::Value::SignedInteger(_)
            | mneme_core::Value::Symbol(_)
            | mneme_core::Value::String(_)
            | mneme_core::Value::ByteString(_) => {}
        }
    }
    false
}
