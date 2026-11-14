//! The workspace entry point for consolidation.
//!
//! [`consolidate_workspace`] runs one consolidation job against a committed
//! workspace: it pins a view, selects the reviewed extent with authorized
//! recall, generates proposals under the job's limits, and commits each
//! generated proposal as a *proposed* assertion with pinned evidence through
//! the memory engine. Nothing on this path accepts a proposal or rewrites an
//! accepted assertion; acceptance stays with the separate acceptance command.
//!
//! The job is idempotent per request: a retry of the same request replays the
//! recorded commit and reports it as replayed, and a run whose record identities
//! already exist never commits a second copy. A retry under a different policy,
//! limit, extractor or input revision is a different run with different record
//! identities, never a silent reuse of the earlier one.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// Declared work cost of processing one deterministic input unit, in milliseconds.
///
/// This layer reads no clock, so the job's time budget is charged in declared
/// units: one millisecond per reviewed input. A caller that needs a tighter or
/// looser budget bounds the work with `max_inputs`, `max_proposals` and
/// `max_model_calls`.
const DECLARED_UNIT_WORK_MS: u64 = 1;

/// Bounds for the recall that selects the reviewed extent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecallBounds {
    pub max_items: usize,
    pub max_context_bytes: usize,
    pub max_quote_bytes: usize,
    pub max_time_ms: u128,
}

impl RecallBounds {
    /// Conservative budgets for one consolidation job.
    pub fn conservative() -> Self {
        RecallBounds {
            max_items: 32,
            max_context_bytes: 32_768,
            max_quote_bytes: 4_096,
            max_time_ms: 500,
        }
    }
}

/// One workspace-backed consolidation request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceJob {
    /// The principal committing the proposals.
    pub actor: String,
    /// The one scope this job consolidates.
    pub scope: mneme_core::ScopeId,
    /// The caller's scope authorization.
    pub access: mneme_memory::Access,
    pub job_id: String,
    /// The request identity; a retry under the same key and content replays.
    pub idempotency_key: String,
    pub policy_version: String,
    /// The extractor configuration this run is attributed to, when any.
    pub extractor: Option<crate::ExtractorDescriptor>,
    /// The recall query that selects the reviewed extent.
    pub query: String,
    /// The valid-time instant current-mode recall selects claims at.
    pub at: mneme_core::Timestamp,
    /// The recorded time carried by the job envelope.
    pub recorded_at: mneme_core::Timestamp,
    pub limits: crate::JobLimits,
    pub recall: RecallBounds,
}

/// Who is asking for one consolidation run, and when.
///
/// These are the caller-supplied facts about the request itself rather than
/// about the work: every one of them is part of the run identity, so a retry
/// differs from a new run exactly when one of them differs.
#[derive(Clone, Copy, Debug)]
pub struct JobRequest<'a> {
    /// The principal committing the proposals.
    pub actor: &'a str,
    /// The job identity carried by the run and its proposals.
    pub job_id: &'a str,
    /// The request identity; a retry under the same key and content replays.
    pub idempotency_key: &'a str,
    /// The recall query that selects the reviewed extent.
    pub query: &'a str,
    /// The valid-time instant current-mode recall selects claims at.
    pub at: mneme_core::Timestamp,
    /// The recorded time carried by the job envelope.
    pub recorded_at: mneme_core::Timestamp,
}

impl WorkspaceJob {
    /// A conservative request over one scope.
    pub fn new(
        scope: mneme_core::ScopeId,
        access: mneme_memory::Access,
        request: JobRequest<'_>,
    ) -> Self {
        WorkspaceJob {
            actor: request.actor.to_owned(),
            scope,
            access,
            job_id: request.job_id.to_owned(),
            idempotency_key: request.idempotency_key.to_owned(),
            policy_version: "consolidation-policy/v1".to_owned(),
            extractor: None,
            query: request.query.to_owned(),
            at: request.at,
            recorded_at: request.recorded_at,
            limits: crate::JobLimits {
                max_inputs: 8,
                max_proposals: 8,
                max_time_ms: 1_000,
                max_model_calls: 0,
            },
            recall: RecallBounds::conservative(),
        }
    }

    /// Validate the request envelope before any work is done.
    pub fn validate(&self) -> Result<(), Failure> {
        for (name, value) in [
            ("actor", self.actor.as_str()),
            ("job", self.job_id.as_str()),
            ("idempotency key", self.idempotency_key.as_str()),
            ("policy version", self.policy_version.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(Failure::Invalid(format!("{name} is required")));
            }
        }
        self.limits.validate().map_err(Failure::Invalid)?;
        if !self.access.allows(&self.scope) {
            return Err(Failure::Invalid(
                "the caller is not authorized for the requested scope".to_owned(),
            ));
        }
        if self.recall.max_items == 0
            || self.recall.max_context_bytes == 0
            || self.recall.max_quote_bytes == 0
            || self.recall.max_time_ms == 0
        {
            return Err(Failure::Invalid(
                "recall bounds must be positive".to_owned(),
            ));
        }
        Ok(())
    }
}

/// One proposal committed as a proposed assertion with pinned evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedProposal {
    pub proposal_id: String,
    pub assertion: mneme_core::RecordId,
    pub assertion_revision: mneme_core::RevisionId,
    pub evidence: mneme_core::RecordId,
    pub evidence_revision: mneme_core::RevisionId,
}

/// A reviewed input the job did not commit a proposal for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedUnit {
    pub key: crate::InputKey,
    pub reason: String,
}

/// The outcome of one workspace-backed consolidation job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceReceipt {
    pub job_id: String,
    pub status: crate::JobStatus,
    pub base_revision: mneme_core::WorkspaceRevisionId,
    /// The workspace revision when the job finished.
    pub revision: mneme_core::WorkspaceRevisionId,
    pub committed: Vec<CommittedProposal>,
    pub skipped: Vec<SkippedUnit>,
    /// The configured generation mode and any content-free model attempt receipts.
    pub generation: GenerationMode,
    /// Declared deterministic work, distinct from host-measured model elapsed time.
    pub declared_work_ms: u64,
    /// Host-measured model time accumulated in monotonic nanoseconds.
    pub observed_elapsed_ns: u64,
    /// The commit was already recorded and was not written twice.
    pub replayed: bool,
}

/// Provenance for one bounded model attempt; source bytes and model output are absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvocationReceipt {
    pub input: crate::InputKey,
    pub input_digest: String,
    pub configuration_digest: String,
    pub status: Option<mneme_recall::inference::InvocationStatus>,
    /// Pinned runtime/model/tokenizer/prompt/schema/decoding identities.
    pub model: mneme_recall::inference::ModelDescriptor,
    pub reported_model: Option<String>,
    pub input_bytes: u64,
    pub elapsed_ns: u64,
    pub usage: mneme_recall::inference::UsageTelemetry,
    pub output_bytes: Option<usize>,
    pub observed_output_digest: Option<String>,
    pub reserved_output_bytes: usize,
    pub reserved_wall_ms: u64,
}

/// Whether the receipt used the deterministic default or an actual model run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GenerationMode {
    Deterministic,
    ModelUnavailable { reason: String },
    Model { attempts: Vec<InvocationReceipt> },
}

/// Why a workspace-backed consolidation job did not complete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The request envelope or the generated proposal is invalid.
    Invalid(String),
    /// Recall over the pinned view failed.
    Recall(String),
    /// The pinned base revision is no longer current.
    StaleBase,
    /// The memory layer refused the commit.
    Memory(String),
    /// A workspace read failed.
    Store(String),
}

impl Failure {
    /// The failure detail, without foreign identifiers.
    pub fn detail(&self) -> &str {
        match self {
            Failure::Invalid(detail)
            | Failure::Recall(detail)
            | Failure::Memory(detail)
            | Failure::Store(detail) => detail,
            Failure::StaleBase => "the pinned base revision is no longer current",
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.detail())
    }
}

impl std::error::Error for Failure {}

/// Consolidate one scope of a committed workspace into proposed assertions.
///
/// The reviewed extent comes from authorized recall at the pinned revision, so
/// ranked recall never certifies absence or cleanup. Only the deterministic
/// generator runs on this path: without a configured extractor the job declares
/// no model, and the job envelope records that. Each generated proposal becomes
/// one evidence record pinning the exact cited revision and bytes plus one
/// proposed assertion citing it. Nothing is accepted, and a proposal whose
/// premise is no longer retained is skipped with the reason rather than quoted.
pub fn consolidate_workspace(
    workspace: &mut mneme_store::Workspace,
    request: &WorkspaceJob,
) -> Result<WorkspaceReceipt, Failure> {
    let mut prepared = prepare_workspace_job(workspace, request)?;
    let mut executor = crate::runner::Executor::start(prepared.job).map_err(Failure::Invalid)?;
    let (proposals, generation) = if request.extractor.is_some() {
        prepared
            .skipped
            .extend(prepared.inputs.iter().map(|input| SkippedUnit {
                key: input.key,
                reason:
                    "model extractor unavailable: no supervised runtime was configured".to_owned(),
            }));
        (
            Vec::new(),
            GenerationMode::ModelUnavailable {
                reason: "no supervised model runtime was configured".to_owned(),
            },
        )
    } else {
        (
            run_job(
                &mut executor,
                &prepared.batch,
                &prepared.inputs,
                &mut prepared.skipped,
            ),
            GenerationMode::Deterministic,
        )
    };
    let drafts = commit_drafts(&prepared.view, request, &proposals, &mut prepared.skipped);
    let committed = commit(workspace, request, prepared.base, drafts)?;
    Ok(WorkspaceReceipt {
        job_id: request.job_id.clone(),
        status: finished_status(executor.progress().status),
        base_revision: prepared.base,
        revision: committed.revision,
        committed: committed.proposals,
        skipped: dedupe_skips(prepared.skipped),
        generation,
        declared_work_ms: executor.progress().declared_work_ms,
        observed_elapsed_ns: executor.progress().observed_elapsed_ns,
        replayed: committed.replayed,
    })
}

struct WorkspacePreparation {
    view: mneme_memory::View,
    base: mneme_core::WorkspaceRevisionId,
    batch: crate::InputBatch,
    skipped: Vec<SkippedUnit>,
    inputs: Vec<crate::proposals::GeneratorInput>,
    job: crate::Job,
}

struct ModelReplayContext<'a> {
    workspace: &'a mneme_store::Workspace,
    request: &'a WorkspaceJob,
    extractor: &'a crate::model_extractor::ModelExtractor,
    progress_store: &'a crate::runner::ProgressStore,
}

impl ModelReplayContext<'_> {
    fn existing_receipt(
        &self,
        prepared: &WorkspacePreparation,
        progress: &crate::runner::JobProgress,
    ) -> Result<Option<WorkspaceReceipt>, Failure> {
        if progress
            .validate_model_identity_replay(&prepared.job)
            .is_err()
        {
            return Ok(None);
        }
        let is_terminal_without_recovery = progress.status == crate::JobStatus::Failed
            || (matches!(
                progress.status,
                crate::JobStatus::Timeout | crate::JobStatus::Cancelled
            ) && !progress.model_attempts.is_empty());
        if is_terminal_without_recovery {
            return self
                .receipt(ModelReceiptState {
                    base: progress.identity.input_revision,
                    skipped: prepared.skipped.clone(),
                    progress,
                    replayed: false,
                })
                .map(Some);
        }
        if verify_model_attempt_inputs(prepared, self.extractor, progress).is_err() {
            return Ok(None);
        }
        if progress.validate_model_replay(&prepared.job).is_ok() {
            return self
                .receipt(ModelReceiptState {
                    base: progress.identity.input_revision,
                    skipped: prepared.skipped.clone(),
                    progress,
                    replayed: true,
                })
                .map(Some);
        }
        if progress.status == crate::JobStatus::Failed {
            return self
                .receipt(ModelReceiptState {
                    base: progress.identity.input_revision,
                    skipped: prepared.skipped.clone(),
                    progress,
                    replayed: false,
                })
                .map(Some);
        }
        self.reconcile_interrupted_progress(prepared, progress)
    }

    fn reconcile_interrupted_progress(
        &self,
        prepared: &WorkspacePreparation,
        progress: &crate::runner::JobProgress,
    ) -> Result<Option<WorkspaceReceipt>, Failure> {
        let mut recovery =
            crate::runner::Executor::resume_model_replay(prepared.job.clone(), progress.clone())
                .map_err(Failure::Invalid)?;
        let has_recovered_prepared =
            recover_prepared_model_attempts(self.workspace, self.request, &mut recovery)?;
        let has_interrupted_attempts = recovery.fail_interrupted_model_attempts();
        if !has_recovered_prepared && !has_interrupted_attempts {
            return self
                .receipt(ModelReceiptState {
                    base: progress.identity.input_revision,
                    skipped: prepared.skipped.clone(),
                    progress,
                    replayed: false,
                })
                .map(Some);
        }
        self.progress_store
            .save(recovery.progress())
            .map_err(Failure::Store)?;
        if recovery
            .progress()
            .validate_model_replay(&prepared.job)
            .is_ok()
        {
            return self
                .receipt(ModelReceiptState {
                    base: recovery.progress().identity.input_revision,
                    skipped: prepared.skipped.clone(),
                    progress: recovery.progress(),
                    replayed: true,
                })
                .map(Some);
        }
        self.unfinished(
            recovery.progress().identity.input_revision,
            prepared.skipped.clone(),
            &recovery,
        )
        .map(Some)
    }

    fn recover_fresh_progress(
        &self,
        prepared: &WorkspacePreparation,
        executor: &mut crate::runner::Executor,
    ) -> Result<Option<WorkspaceReceipt>, Failure> {
        let has_recovered_prepared =
            recover_prepared_model_attempts(self.workspace, self.request, executor)?;
        let has_interrupted_attempts = executor.fail_interrupted_model_attempts();
        if has_recovered_prepared || has_interrupted_attempts {
            self.progress_store
                .save(executor.progress())
                .map_err(Failure::Store)?;
            if executor.progress().status == crate::JobStatus::Failed {
                return self
                    .unfinished(prepared.base, prepared.skipped.clone(), executor)
                    .map(Some);
            }
        }
        let has_unfinished_invocation = executor.progress().model_attempts.iter().any(|attempt| {
            attempt.phase == crate::runner::ModelAttemptPhase::Invoked
                && attempt.status != Some(mneme_recall::inference::InvocationStatus::Complete)
        });
        if has_unfinished_invocation {
            return self
                .unfinished(prepared.base, prepared.skipped.clone(), executor)
                .map(Some);
        }
        Ok(None)
    }

    fn receipt(&self, state: ModelReceiptState<'_>) -> Result<WorkspaceReceipt, Failure> {
        model_progress_receipt(
            ModelReceiptContext {
                workspace: self.workspace,
                request: self.request,
                extractor: self.extractor,
            },
            state,
        )
    }

    fn unfinished(
        &self,
        base: mneme_core::WorkspaceRevisionId,
        skipped: Vec<SkippedUnit>,
        executor: &crate::runner::Executor,
    ) -> Result<WorkspaceReceipt, Failure> {
        unfinished_model_receipt(
            ModelReceiptContext {
                workspace: self.workspace,
                request: self.request,
                extractor: self.extractor,
            },
            base,
            skipped,
            executor,
        )
    }
}

struct ModelInputContext<'a> {
    inputs: &'a [crate::proposals::GeneratorInput],
    view: &'a mneme_memory::View,
    job: &'a crate::Job,
    batch: &'a crate::InputBatch,
    scope: &'a mneme_core::ScopeId,
    request: &'a WorkspaceJob,
    extractor: &'a crate::model_extractor::ModelExtractor,
    progress_store: &'a crate::runner::ProgressStore,
    control: &'a mneme_recall::inference::InvocationControl,
}

struct PreparedModelCall<'a> {
    input: &'a crate::proposals::GeneratorInput,
    entities: Vec<crate::proposals::EntityHandle>,
    request: crate::model_extractor::PreparedModelRequest<'a>,
}

enum ModelInputOutcome {
    Stop,
    Drafts(Vec<ProposalDrafts>),
}

struct ModelWorkspaceExecution<'a> {
    workspace: &'a mut mneme_store::Workspace,
    request: &'a WorkspaceJob,
    extractor: &'a crate::model_extractor::ModelExtractor,
    progress_store: &'a crate::runner::ProgressStore,
    control: &'a mneme_recall::inference::InvocationControl,
    prepared: WorkspacePreparation,
    executor: crate::runner::Executor,
}

impl<'a> ModelWorkspaceExecution<'a> {
    fn execute(self) -> Result<WorkspaceReceipt, Failure> {
        let mut execution = self;
        let mut drafts = Vec::with_capacity(
            execution
                .prepared
                .inputs
                .len()
                .min(execution.request.limits.max_proposals),
        );
        let mut committed_inputs = Vec::with_capacity(execution.prepared.inputs.len());
        let should_stop = {
            let context = ModelInputContext {
                inputs: &execution.prepared.inputs,
                view: &execution.prepared.view,
                job: &execution.prepared.job,
                batch: &execution.prepared.batch,
                scope: &execution.request.scope,
                request: execution.request,
                extractor: execution.extractor,
                progress_store: execution.progress_store,
                control: execution.control,
            };
            let mut should_stop = false;
            for index in 0..context.inputs.len() {
                let key = context.inputs[index].key;
                if execution.executor.progress().completed.contains(&key) {
                    continue;
                }
                match process_model_input(
                    &context,
                    &mut execution.executor,
                    &mut execution.prepared.skipped,
                    index,
                )? {
                    ModelInputOutcome::Stop => {
                        should_stop = true;
                        break;
                    }
                    ModelInputOutcome::Drafts(input_drafts) => {
                        drafts.extend(input_drafts);
                        committed_inputs.push(key);
                    }
                }
            }
            should_stop
        };
        if should_stop {
            return execution.unfinished();
        }
        execution.commit_model_run(drafts, committed_inputs)
    }

    fn unfinished(&mut self) -> Result<WorkspaceReceipt, Failure> {
        unfinished_model_receipt(
            ModelReceiptContext {
                workspace: self.workspace,
                request: self.request,
                extractor: self.extractor,
            },
            self.prepared.base,
            std::mem::take(&mut self.prepared.skipped),
            &self.executor,
        )
    }

    fn commit_model_run(
        mut self,
        drafts: Vec<ProposalDrafts>,
        committed_inputs: Vec<crate::InputKey>,
    ) -> Result<WorkspaceReceipt, Failure> {
        if let Some(receipt) = self.precommit_refusal(&committed_inputs)? {
            return Ok(receipt);
        }
        let current_revision = self
            .workspace
            .current_revision()
            .map_err(|error| Failure::Store(error.to_string()))?;
        let current_generation = self
            .workspace
            .eligibility_generation()
            .map_err(|error| Failure::Store(error.to_string()))?;
        if let Some(receipt) =
            self.stale_head_receipt(current_revision, current_generation, &committed_inputs)?
        {
            return Ok(receipt);
        }
        let committed = match commit(
            &mut *self.workspace,
            self.request,
            self.prepared.base,
            drafts,
        ) {
            Ok(committed) => committed,
            Err(error) => {
                self.executor.fail_model_work();
                self.persist_progress()?;
                return Err(error);
            }
        };
        for input in committed_inputs {
            self.executor
                .mark_model_committed(input)
                .map_err(Failure::Invalid)?;
        }
        self.executor.finish_model_work();
        self.persist_progress()?;
        Ok(WorkspaceReceipt {
            job_id: self.request.job_id.clone(),
            status: finished_status(self.executor.progress().status),
            base_revision: self.prepared.base,
            revision: committed.revision,
            committed: committed.proposals,
            skipped: dedupe_skips(self.prepared.skipped),
            generation: model_generation(self.extractor, self.executor.progress())?,
            declared_work_ms: self.executor.progress().declared_work_ms,
            observed_elapsed_ns: self.executor.progress().observed_elapsed_ns,
            replayed: committed.replayed,
        })
    }

    fn precommit_refusal(
        &mut self,
        committed_inputs: &[crate::InputKey],
    ) -> Result<Option<WorkspaceReceipt>, Failure> {
        if !self.control.is_cancelled() {
            return Ok(None);
        }
        self.executor.cancel_model_work();
        self.persist_progress()?;
        if let Some(key) = committed_inputs.first().copied() {
            self.prepared.skipped.push(SkippedUnit {
                key,
                reason: "model extraction cancelled before commit".to_owned(),
            });
        }
        self.unfinished().map(Some)
    }

    fn stale_head_receipt(
        &mut self,
        current_revision: mneme_core::WorkspaceRevisionId,
        current_generation: u64,
        committed_inputs: &[crate::InputKey],
    ) -> Result<Option<WorkspaceReceipt>, Failure> {
        if current_revision == self.prepared.base
            && current_generation == self.prepared.batch.eligibility_generation
        {
            return Ok(None);
        }
        self.executor.fail_model_work();
        self.persist_progress()?;
        if let Some(key) = committed_inputs.first().copied() {
            self.prepared.skipped.push(SkippedUnit {
                key,
                reason: "workspace base or eligibility generation changed during inference"
                    .to_owned(),
            });
        }
        self.unfinished().map(Some)
    }

    fn persist_progress(&self) -> Result<(), Failure> {
        self.progress_store
            .save(self.executor.progress())
            .map_err(Failure::Store)
    }
}

fn process_model_input(
    context: &ModelInputContext<'_>,
    executor: &mut crate::runner::Executor,
    skipped: &mut Vec<SkippedUnit>,
    index: usize,
) -> Result<ModelInputOutcome, Failure> {
    let input = &context.inputs[index];
    if context.control.is_cancelled() {
        cancel_model_input(
            executor,
            context.progress_store,
            skipped,
            input.key,
            "model extraction cancelled before dispatch".to_owned(),
        )?;
        return Ok(ModelInputOutcome::Stop);
    }
    let Some(call) = prepare_model_call(context, executor, skipped, index)? else {
        return Ok(ModelInputOutcome::Stop);
    };
    dispatch_model_call(context, executor, skipped, call)
}

fn prepare_model_call<'a>(
    context: &'a ModelInputContext<'a>,
    executor: &mut crate::runner::Executor,
    skipped: &mut Vec<SkippedUnit>,
    index: usize,
) -> Result<Option<PreparedModelCall<'a>>, Failure> {
    let input = &context.inputs[index];
    let entities = match source_entity_handle(context.view, context.scope, input) {
        Ok(entities) => entities,
        Err(reason) => {
            fail_model_input(executor, context.progress_store, skipped, input.key, reason)?;
            return Ok(None);
        }
    };
    let prepared_request = match context.extractor.prepare_request(input, &entities) {
        Ok(prepared_request) => prepared_request,
        Err(reason) => {
            fail_model_input(
                executor,
                context.progress_store,
                skipped,
                input.key,
                format!("model request refused: {reason}"),
            )?;
            return Ok(None);
        }
    };
    let remaining = executor.remaining_model_time().map_err(Failure::Invalid)?;
    let prepared_request = match prepared_request.cap_wall_time(remaining) {
        Ok(prepared_request) => prepared_request,
        Err(reason) => {
            fail_model_input(executor, context.progress_store, skipped, input.key, reason)?;
            return Ok(None);
        }
    };
    Ok(Some(PreparedModelCall {
        input,
        entities,
        request: prepared_request,
    }))
}

fn dispatch_model_call(
    context: &ModelInputContext<'_>,
    executor: &mut crate::runner::Executor,
    skipped: &mut Vec<SkippedUnit>,
    call: PreparedModelCall<'_>,
) -> Result<ModelInputOutcome, Failure> {
    if !reserve_model_call(context, executor, skipped, &call)? {
        return Ok(ModelInputOutcome::Stop);
    }
    let attempt = context.extractor.invoke_prepared(
        call.request,
        call.input,
        &call.entities,
        context.control,
    );
    if let Err(reason) = executor.record_model_invocation(call.input.key, &attempt) {
        context
            .progress_store
            .save(executor.progress())
            .map_err(Failure::Store)?;
        skipped.push(SkippedUnit {
            key: call.input.key,
            reason,
        });
        return Ok(ModelInputOutcome::Stop);
    }
    context
        .progress_store
        .save(executor.progress())
        .map_err(Failure::Store)?;
    if attempt.status != mneme_recall::inference::InvocationStatus::Complete
        || !attempt.supervised_model
    {
        skipped.push(SkippedUnit {
            key: call.input.key,
            reason: attempt.detail.clone().unwrap_or_else(|| {
                "model invocation did not produce supervised structured output".to_owned()
            }),
        });
        return Ok(ModelInputOutcome::Stop);
    }
    let proposals = match crate::proposals::generate_extracted_attempt(
        context.job,
        context.batch,
        call.input,
        &attempt,
    ) {
        Ok(proposals) => proposals,
        Err(reason) => {
            fail_model_input(
                executor,
                context.progress_store,
                skipped,
                call.input.key,
                reason,
            )?;
            return Ok(ModelInputOutcome::Stop);
        }
    };
    let input_drafts = commit_drafts(context.view, context.request, &proposals, skipped);
    let proposal_ids = input_drafts
        .iter()
        .map(|draft| draft.committed.proposal_id.clone())
        .collect::<Vec<_>>();
    executor
        .prepare_model_proposals(call.input.key, &proposal_ids)
        .map_err(Failure::Invalid)?;
    context
        .progress_store
        .save(executor.progress())
        .map_err(Failure::Store)?;
    Ok(ModelInputOutcome::Drafts(input_drafts))
}

fn reserve_model_call(
    context: &ModelInputContext<'_>,
    executor: &mut crate::runner::Executor,
    skipped: &mut Vec<SkippedUnit>,
    call: &PreparedModelCall<'_>,
) -> Result<bool, Failure> {
    executor
        .reserve_model_call(crate::runner::ModelCallReservation {
            input: call.input.key,
            input_digest: call.request.input_digest(),
            configuration_digest: call.request.configuration_digest(),
            input_bytes: call.request.input_bytes(),
            output_bytes: call.request.reserved_output_bytes(),
            wall_time: call.request.wall_time(),
        })
        .map_err(Failure::Invalid)?;
    context
        .progress_store
        .save(executor.progress())
        .map_err(Failure::Store)?;
    if !context.control.is_cancelled() {
        return Ok(true);
    }
    executor
        .cancel_reserved_model_call(call.input.key)
        .map_err(Failure::Invalid)?;
    skipped.push(SkippedUnit {
        key: call.input.key,
        reason: "model extraction cancelled before worker start".to_owned(),
    });
    context
        .progress_store
        .save(executor.progress())
        .map_err(Failure::Store)?;
    Ok(false)
}

fn fail_model_input(
    executor: &mut crate::runner::Executor,
    progress_store: &crate::runner::ProgressStore,
    skipped: &mut Vec<SkippedUnit>,
    input: crate::InputKey,
    reason: String,
) -> Result<(), Failure> {
    executor.fail_model_work();
    skipped.push(SkippedUnit { key: input, reason });
    progress_store
        .save(executor.progress())
        .map_err(Failure::Store)
}

fn cancel_model_input(
    executor: &mut crate::runner::Executor,
    progress_store: &crate::runner::ProgressStore,
    skipped: &mut Vec<SkippedUnit>,
    input: crate::InputKey,
    reason: String,
) -> Result<(), Failure> {
    executor.cancel_model_work();
    skipped.push(SkippedUnit { key: input, reason });
    progress_store
        .save(executor.progress())
        .map_err(Failure::Store)
}

fn prepare_workspace_job(
    workspace: &mut mneme_store::Workspace,
    request: &WorkspaceJob,
) -> Result<WorkspacePreparation, Failure> {
    request.validate()?;
    let view = mneme_memory::Engine::new(workspace, request.access.clone())
        .view()
        .map_err(|error| Failure::Memory(describe_memory_error(&error)))?;
    let base = view.revision();
    let response = recall(workspace, request, base)?;
    let batch = crate::InputBatch::from_recall(request.scope.clone(), base, &response, &view)
        .map_err(Failure::Invalid)?;
    let (batch, dropped) = batch.limit_inputs(request.limits.max_inputs);
    let mut skipped = dropped
        .into_iter()
        .map(|key| SkippedUnit {
            key,
            reason: "the job's input limit was reached".to_owned(),
        })
        .collect::<Vec<_>>();
    skipped.extend(unavailable_sources(&view, &request.scope));
    let inputs = reviewed_inputs(&view, &response, &batch, &mut skipped);
    let job = job_envelope(request, base, &batch, &inputs);
    Ok(WorkspacePreparation {
        view,
        base,
        batch,
        skipped,
        inputs,
        job,
    })
}

fn validate_model_extractor(
    request: &WorkspaceJob,
    extractor: &crate::model_extractor::ModelExtractor,
) -> Result<(), Failure> {
    request.validate()?;
    if request.extractor.as_ref() != Some(extractor.extractor_descriptor()) {
        return Err(Failure::Invalid(
            "model runtime identity differs from the job declaration".to_owned(),
        ));
    }
    Ok(())
}

fn validate_model_input_extent(
    request: &WorkspaceJob,
    prepared: &WorkspacePreparation,
) -> Result<(), Failure> {
    let max_model_calls = request
        .limits
        .max_model_calls
        .min(crate::runner::MAX_MODEL_CALLS_PER_JOB);
    let max_model_calls = usize::try_from(max_model_calls).map_err(|_| {
        Failure::Invalid("model-call budget exceeds this platform's addressable size".to_owned())
    })?;
    if prepared.inputs.len() > max_model_calls {
        return Err(Failure::Invalid(
            "model-call budget is smaller than the reviewed input extent".to_owned(),
        ));
    }
    Ok(())
}

fn resume_model_executor(
    prepared: &WorkspacePreparation,
    stored: Option<crate::runner::JobProgress>,
) -> Result<crate::runner::Executor, Failure> {
    match stored {
        Some(progress)
            if progress.identity == prepared.job.identity()
                && progress.model_attempts.is_empty() =>
        {
            crate::runner::Executor::resume(prepared.job.clone(), progress)
                .map_err(Failure::Invalid)
        }
        Some(_) => Err(Failure::Invalid(
            "stored model progress belongs to a different run; use a new idempotency key"
                .to_owned(),
        )),
        None => crate::runner::Executor::start(prepared.job.clone()).map_err(Failure::Invalid),
    }
}

/// Run the explicitly configured model extractor through the same evidence and
/// proposal path as deterministic consolidation. `progress_store` contains
/// only content-free digests, counters, and proposal identities.
pub fn consolidate_workspace_with_model(
    workspace: &mut mneme_store::Workspace,
    request: &WorkspaceJob,
    extractor: &crate::model_extractor::ModelExtractor,
    progress_store: &crate::runner::ProgressStore,
    control: &mneme_recall::inference::InvocationControl,
) -> Result<WorkspaceReceipt, Failure> {
    validate_model_extractor(request, extractor)?;
    let prepared = prepare_workspace_job(workspace, request)?;
    validate_model_input_extent(request, &prepared)?;

    let stored = progress_store.load().map_err(Failure::Store)?;
    if let Some(progress) = stored.as_ref() {
        let replay = ModelReplayContext {
            workspace,
            request,
            extractor,
            progress_store,
        };
        if let Some(receipt) = replay.existing_receipt(&prepared, progress)? {
            return Ok(receipt);
        }
    }

    let mut executor = resume_model_executor(&prepared, stored)?;
    let recovery = ModelReplayContext {
        workspace,
        request,
        extractor,
        progress_store,
    };
    if let Some(receipt) = recovery.recover_fresh_progress(&prepared, &mut executor)? {
        return Ok(receipt);
    }

    ModelWorkspaceExecution {
        workspace,
        request,
        extractor,
        progress_store,
        control,
        prepared,
        executor,
    }
    .execute()
}

fn source_entity_handle(
    view: &mneme_memory::View,
    scope: &mneme_core::ScopeId,
    input: &crate::proposals::GeneratorInput,
) -> Result<Vec<crate::proposals::EntityHandle>, String> {
    let source = view
        .source_at(input.key.record_id, input.key.revision_id)
        .map_err(|_| "the source revision is no longer available".to_owned())?;
    if source.availability != mneme_memory::SourceAvailability::Retained {
        return Err(format!("model source is {}", source.availability.name()));
    }
    let entity = source
        .entity
        .ok_or_else(|| "model input has no source-declared entity identity".to_owned())?;
    let record = view
        .record(entity)
        .map_err(|_| "the source-declared entity is not in the pinned view".to_owned())?;
    if record.kind != mneme_core::RecordKind::Entity || &record.scope != scope {
        return Err("the source-declared entity is outside the pinned scope".to_owned());
    }
    // The model sees an opaque per-entity handle and the role label only. It
    // does not receive entity record IDs, names, or unrelated scope records.
    let identity = mneme_recall::inference::input_digest(record.record_id.to_hex().as_bytes());
    let handle = identity
        .strip_prefix("sha256:")
        .ok_or_else(|| "entity handle digest is not canonical".to_owned())?;
    Ok(vec![crate::proposals::EntityHandle {
        handle: format!("entity-{handle}"),
        label: "source entity".to_owned(),
        record_id: entity,
    }])
}

fn verify_model_attempt_inputs(
    prepared: &WorkspacePreparation,
    extractor: &crate::model_extractor::ModelExtractor,
    progress: &crate::runner::JobProgress,
) -> Result<(), String> {
    progress.validate_model_identity_replay(&prepared.job)?;
    if progress.model_attempts.len() > prepared.inputs.len()
        || (progress.model_attempts.is_empty() && !prepared.inputs.is_empty())
    {
        return Err("stored attempt set differs from the current reviewed input extent".to_owned());
    }
    // An interrupted run may have reserved only part of its reviewed extent.
    // Verify every durable attempt, then let the caller classify it as
    // interrupted; missing inputs are never invoked during recovery.
    for attempt in &progress.model_attempts {
        let input = prepared
            .inputs
            .iter()
            .find(|input| input.key == attempt.input)
            .ok_or_else(|| {
                "stored model attempt is outside the current reviewed inputs".to_owned()
            })?;
        let entities = source_entity_handle(&prepared.view, &prepared.job.scope, input)?;
        let reserved_wall_time = std::time::Duration::from_millis(attempt.reserved_wall_ms);
        let current = extractor
            .prepare_request(input, &entities)?
            .cap_wall_time(reserved_wall_time)?;
        if current.wall_time() != reserved_wall_time
            || current.input_digest() != attempt.input_digest
            || current.configuration_digest() != attempt.configuration_digest
            || u64::try_from(current.input_bytes()).ok() != Some(attempt.input_bytes)
            || u64::try_from(current.reserved_output_bytes()).ok()
                != Some(attempt.reserved_output_bytes)
        {
            return Err(
                "stored model attempt differs from the exact current input or configuration"
                    .to_owned(),
            );
        }
    }
    Ok(())
}

fn model_generation(
    extractor: &crate::model_extractor::ModelExtractor,
    progress: &crate::runner::JobProgress,
) -> Result<GenerationMode, Failure> {
    let attempts = progress
        .model_attempts
        .iter()
        .map(|attempt| {
            let output_bytes = attempt
                .output_bytes
                .map(usize::try_from)
                .transpose()
                .map_err(|_| {
                    Failure::Invalid(
                        "observed model output size exceeds addressable memory".to_owned(),
                    )
                })?;
            let reserved_output_bytes =
                usize::try_from(attempt.reserved_output_bytes).map_err(|_| {
                    Failure::Invalid(
                        "reserved model output size exceeds addressable memory".to_owned(),
                    )
                })?;
            Ok(InvocationReceipt {
                input: attempt.input,
                input_digest: attempt.input_digest.clone(),
                configuration_digest: attempt.configuration_digest.clone(),
                status: attempt.status,
                model: extractor.model_descriptor().clone(),
                reported_model: attempt.reported_model.clone(),
                input_bytes: attempt.input_bytes,
                elapsed_ns: attempt.elapsed_ns,
                usage: attempt.usage.clone(),
                output_bytes,
                observed_output_digest: attempt.observed_output_digest.clone(),
                reserved_output_bytes,
                reserved_wall_ms: attempt.reserved_wall_ms,
            })
        })
        .collect::<Result<Vec<_>, Failure>>()?;
    Ok(GenerationMode::Model { attempts })
}

struct ModelReceiptContext<'a> {
    workspace: &'a mneme_store::Workspace,
    request: &'a WorkspaceJob,
    extractor: &'a crate::model_extractor::ModelExtractor,
}

struct ModelReceiptState<'a> {
    base: mneme_core::WorkspaceRevisionId,
    skipped: Vec<SkippedUnit>,
    progress: &'a crate::runner::JobProgress,
    replayed: bool,
}

fn unfinished_model_receipt(
    context: ModelReceiptContext<'_>,
    base: mneme_core::WorkspaceRevisionId,
    skipped: Vec<SkippedUnit>,
    executor: &crate::runner::Executor,
) -> Result<WorkspaceReceipt, Failure> {
    model_progress_receipt(
        context,
        ModelReceiptState {
            base,
            skipped,
            progress: executor.progress(),
            replayed: false,
        },
    )
}

fn model_progress_receipt(
    context: ModelReceiptContext<'_>,
    state: ModelReceiptState<'_>,
) -> Result<WorkspaceReceipt, Failure> {
    Ok(WorkspaceReceipt {
        job_id: context.request.job_id.clone(),
        status: finished_status(state.progress.status),
        base_revision: state.base,
        revision: context
            .workspace
            .current_revision()
            .map_err(|error| Failure::Store(error.to_string()))?,
        committed: recover_committed_proposals(context.workspace, context.request, state.progress)?,
        skipped: dedupe_skips(state.skipped),
        generation: model_generation(context.extractor, state.progress)?,
        declared_work_ms: state.progress.declared_work_ms,
        observed_elapsed_ns: state.progress.observed_elapsed_ns,
        replayed: state.replayed,
    })
}

fn recover_prepared_model_attempts(
    workspace: &mneme_store::Workspace,
    request: &WorkspaceJob,
    executor: &mut crate::runner::Executor,
) -> Result<bool, Failure> {
    let pending = executor
        .progress()
        .model_attempts
        .iter()
        .filter(|attempt| attempt.phase == crate::runner::ModelAttemptPhase::Prepared)
        .map(|attempt| (attempt.input, attempt.proposal_ids.clone()))
        .collect::<Vec<_>>();
    for (input, proposal_ids) in &pending {
        if !prepared_proposals_exist(workspace, request, proposal_ids)? {
            executor.fail_model_work();
            return Ok(true);
        }
        executor
            .mark_model_committed(*input)
            .map_err(Failure::Invalid)?;
    }
    Ok(!pending.is_empty())
}

fn prepared_proposals_exist(
    workspace: &mneme_store::Workspace,
    request: &WorkspaceJob,
    proposal_ids: &[String],
) -> Result<bool, Failure> {
    for proposal_id in proposal_ids {
        let (assertion, assertion_revision) = record_identity(request, proposal_id, "assertion");
        let (evidence, evidence_revision) = record_identity(request, proposal_id, "evidence");
        if !record_revision_exists(workspace, assertion, assertion_revision)?
            || !record_revision_exists(workspace, evidence, evidence_revision)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn recover_committed_proposals(
    workspace: &mneme_store::Workspace,
    request: &WorkspaceJob,
    progress: &crate::runner::JobProgress,
) -> Result<Vec<CommittedProposal>, Failure> {
    let mut committed = Vec::with_capacity(progress.proposal_ids.len());
    for attempt in &progress.model_attempts {
        if attempt.phase != crate::runner::ModelAttemptPhase::Committed {
            continue;
        }
        for proposal_id in &attempt.proposal_ids {
            let (assertion, assertion_revision) =
                record_identity(request, proposal_id, "assertion");
            let (evidence, evidence_revision) = record_identity(request, proposal_id, "evidence");
            if !record_revision_exists(workspace, assertion, assertion_revision)?
                || !record_revision_exists(workspace, evidence, evidence_revision)?
            {
                return Err(Failure::Store(
                    "stored model receipt no longer has its committed assertion and evidence"
                        .to_owned(),
                ));
            }
            committed.push(CommittedProposal {
                proposal_id: proposal_id.clone(),
                assertion,
                assertion_revision,
                evidence,
                evidence_revision,
            });
        }
    }
    Ok(committed)
}

fn record_revision_exists(
    workspace: &mneme_store::Workspace,
    record: mneme_core::RecordId,
    revision: mneme_core::RevisionId,
) -> Result<bool, Failure> {
    workspace
        .record_revisions(record)
        .map(|history| history.iter().any(|entry| entry.revision_id == revision))
        .map_err(|error| Failure::Store(error.to_string()))
}

/// Every source of the scope whose exact bytes the pinned view cannot quote.
///
/// A source the view no longer holds at all (a forgotten identity) is never
/// listed: naming it would disclose an identity the suppression hides. A source
/// that is still in the view but pruned, erased, inaccessible or corrupt is
/// listed with its availability, so the receipt never claims to have reviewed
/// bytes the job could not read.
fn unavailable_sources(view: &mneme_memory::View, scope: &mneme_core::ScopeId) -> Vec<SkippedUnit> {
    let records = &view.snapshot().records;
    let mut skipped = Vec::with_capacity(records.len());
    for record in records {
        if &record.scope != scope || record.kind != mneme_core::RecordKind::SourceRevision {
            continue;
        }
        let availability = crate::source_availability(view, record.record_id, record.revision_id);
        if availability.is_retained() {
            continue;
        }
        skipped.push(SkippedUnit {
            key: crate::InputKey {
                record_id: record.record_id,
                revision_id: record.revision_id,
            },
            reason: format!("source is {}", availability.name()),
        });
    }
    skipped
}

/// Keep one entry per unit, preferring the first (most specific) reason.
fn dedupe_skips(skipped: Vec<SkippedUnit>) -> Vec<SkippedUnit> {
    let mut seen = std::collections::BTreeSet::new();
    skipped
        .into_iter()
        .filter(|unit| seen.insert(unit.key))
        .collect()
}

/// The status a finished call reports.
///
/// A run that reviewed no unit, or that stopped before processing one, reports
/// a partial extent: it never claims a terminal completion it did not reach.
fn finished_status(status: crate::JobStatus) -> crate::JobStatus {
    if matches!(status, crate::JobStatus::Running) {
        crate::JobStatus::Partial
    } else {
        status
    }
}

/// Recall the reviewed extent from the pinned view.
fn recall(
    workspace: &mut mneme_store::Workspace,
    request: &WorkspaceJob,
    revision: mneme_core::WorkspaceRevisionId,
) -> Result<mneme_recall::Response, Failure> {
    let recall = mneme_recall::Request {
        actor: request.actor.clone(),
        scope: request.scope.clone(),
        access: request.access.clone(),
        revision,
        query: request.query.clone(),
        at: request.at,
        temporal: mneme_recall::TemporalMode::Current,
        modes: std::collections::BTreeSet::from([mneme_recall::Mode::Lexical]),
        structured: None,
        semantic: None,
        allow_stale: false,
        allow_fallback: true,
        allow_partial: true,
        include_disputed: false,
        include_hypothetical: false,
        max_items: request.recall.max_items,
        max_context_bytes: request.recall.max_context_bytes,
        max_quote_bytes: request.recall.max_quote_bytes,
        max_time_ms: request.recall.max_time_ms,
        cancellation: None,
    };
    mneme_recall::Service::new(workspace)
        .recall(recall)
        .map_err(|error| Failure::Recall(error.to_string()))
}

/// The reviewed text of every batch unit that can still be quoted.
fn reviewed_inputs(
    view: &mneme_memory::View,
    response: &mneme_recall::Response,
    batch: &crate::InputBatch,
    skipped: &mut Vec<SkippedUnit>,
) -> Vec<crate::proposals::GeneratorInput> {
    let mut inputs = Vec::with_capacity(batch.units.len());
    for unit in &batch.units {
        if !unit.availability.is_retained() {
            skipped.push(SkippedUnit {
                key: unit.key,
                reason: format!("source is {}", unit.availability.name()),
            });
            continue;
        }
        match reviewed_input(view, response, unit) {
            Ok(input) => inputs.push(input),
            Err(reason) => skipped.push(SkippedUnit {
                key: unit.key,
                reason,
            }),
        }
    }
    inputs
}

/// The exact reviewed text of one unit, bound to the retained source bytes.
fn reviewed_input(
    view: &mneme_memory::View,
    response: &mneme_recall::Response,
    unit: &crate::InputUnit,
) -> Result<crate::proposals::GeneratorInput, String> {
    let candidate = response
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.source == Some(unit.key.record_id)
                && candidate.source_revision == Some(unit.key.revision_id)
        })
        .min_by_key(|candidate| match candidate.content_kind {
            mneme_recall::ContentKind::SourceExcerpt => 0,
            _ => 1,
        })
        .ok_or_else(|| "no recalled item names this input".to_owned())?;
    if candidate.text_truncated {
        return Err("the recalled item was truncated".to_owned());
    }
    let pinned = view
        .source_at(unit.key.record_id, unit.key.revision_id)
        .map_err(|_| "the source revision is not retained".to_owned())?;
    let bytes = match view.source_status_for(&pinned) {
        Ok(mneme_memory::SourceStatus::Retained(bytes)) => bytes,
        Ok(status) => {
            return Err(format!("source is {}", status.availability().name()));
        }
        Err(_) => return Err("the source bytes could not be read".to_owned()),
    };
    let span = match candidate.span {
        Some(span) => {
            if !cited_exactly(&bytes, span, &candidate.text) {
                return Err("the recalled text does not match the cited bytes".to_owned());
            }
            Some(span)
        }
        None => {
            if bytes != candidate.text.as_bytes() {
                return Err("the recalled text is not the whole source extent".to_owned());
            }
            None
        }
    };
    Ok(crate::proposals::GeneratorInput::from_unit(
        unit,
        candidate.text.clone(),
        span,
    ))
}

/// Whether `span` of `bytes` is exactly the offered text.
fn cited_exactly(bytes: &[u8], span: mneme_core::SourceSpan, text: &str) -> bool {
    let Ok(start) = usize::try_from(span.start()) else {
        return false;
    };
    let Some(end) = usize::try_from(span.end())
        .ok()
        .and_then(|end| end.checked_add(1))
    else {
        return false;
    };
    bytes.get(start..end) == Some(text.as_bytes())
}

/// The job envelope the executor runs under.
fn job_envelope(
    request: &WorkspaceJob,
    base: mneme_core::WorkspaceRevisionId,
    batch: &crate::InputBatch,
    inputs: &[crate::proposals::GeneratorInput],
) -> crate::Job {
    let mut batch = batch.clone();
    // Only reviewed units belong to this job; a unit that produced no text was
    // never reviewed, so the cursor must not claim it.
    let reviewed = inputs
        .iter()
        .map(|input| input.key)
        .collect::<std::collections::BTreeSet<_>>();
    batch.units.retain(|unit| reviewed.contains(&unit.key));
    batch.reviewed = reviewed;
    if batch.declared_extent.is_some() {
        batch.declared_extent = Some(batch.reviewed.clone());
    }
    crate::Job {
        job_id: request.job_id.clone(),
        recorded_at: request.recorded_at,
        idempotency_key: request.idempotency_key.clone(),
        scope: request.scope.clone(),
        base_revision: base,
        policy_version: request.policy_version.clone(),
        extractor: request.extractor.clone(),
        batch,
        limits: request.limits,
        status: crate::JobStatus::Running,
    }
}

/// Run the job over its reviewed inputs.
fn run_job(
    executor: &mut crate::runner::Executor,
    batch: &crate::InputBatch,
    inputs: &[crate::proposals::GeneratorInput],
    skipped: &mut Vec<SkippedUnit>,
) -> Vec<crate::Proposal> {
    let control = crate::runner::JobControl::new();
    let mut proposals = Vec::with_capacity(inputs.len());
    for input in inputs {
        let is_unavailable = batch
            .units
            .iter()
            .find(|unit| unit.key == input.key)
            .is_some_and(|unit| !unit.availability.is_retained());
        if is_unavailable {
            skipped.push(SkippedUnit {
                key: input.key,
                reason: "the source is no longer retained".to_owned(),
            });
            continue;
        }
        match executor.process_summary(input, &control, DECLARED_UNIT_WORK_MS) {
            Ok(generated) => proposals.extend(generated),
            Err(reason) => {
                skipped.push(SkippedUnit {
                    key: input.key,
                    reason,
                });
                break;
            }
        }
    }
    proposals
}

/// One proposal's evidence and assertion drafts.
struct ProposalDrafts {
    evidence: mneme_store::RecordDraft,
    assertion: mneme_store::RecordDraft,
    committed: CommittedProposal,
}

/// Build the drafts that record one proposal as a proposed assertion.
fn commit_drafts(
    view: &mneme_memory::View,
    request: &WorkspaceJob,
    proposals: &[crate::Proposal],
    skipped: &mut Vec<SkippedUnit>,
) -> Vec<ProposalDrafts> {
    let mut drafts = Vec::with_capacity(proposals.len());
    let mut identities = std::collections::BTreeSet::new();
    for proposal in proposals {
        let key = proposal.premises.first().map(|premise| crate::InputKey {
            record_id: premise.record_id,
            revision_id: premise.revision_id,
        });
        match proposal_drafts(view, request, proposal) {
            Ok(draft) => {
                let is_unique = identities.insert(draft.committed.assertion)
                    && identities.insert(draft.committed.evidence);
                if !is_unique {
                    if let Some(key) = key {
                        skipped.push(SkippedUnit {
                            key,
                            reason: "two proposals share one record identity".to_owned(),
                        });
                    }
                    continue;
                }
                drafts.push(draft);
            }
            Err(reason) => {
                if let Some(key) = key {
                    skipped.push(SkippedUnit { key, reason });
                }
            }
        }
    }
    drafts
}

/// Build the evidence and assertion drafts for one proposal.
fn proposal_drafts(
    view: &mneme_memory::View,
    request: &WorkspaceJob,
    proposal: &crate::Proposal,
) -> Result<ProposalDrafts, String> {
    proposal.validate()?;
    let premise = proposal
        .premises
        .first()
        .ok_or_else(|| "the proposal has no premise".to_owned())?;
    let span = premise
        .span
        .ok_or_else(|| "the proposal cites no exact bytes".to_owned())?;
    let claim = proposed_claim(view, proposal)?;
    let identities = DraftIdentities::for_proposal(request, &proposal.proposal_id);
    let evidence = evidence_draft(request, &identities, premise, span);
    let assertion = assertion_draft(request, &identities, claim);
    Ok(ProposalDrafts {
        evidence,
        assertion,
        committed: CommittedProposal {
            proposal_id: proposal.proposal_id.clone(),
            assertion: identities.assertion.record_id,
            assertion_revision: identities.assertion.revision_id,
            evidence: identities.evidence.record_id,
            evidence_revision: identities.evidence.revision_id,
        },
    })
}

/// The record identities one proposal's drafts are recorded under.
struct DraftIdentities {
    evidence: crate::InputKey,
    assertion: crate::InputKey,
}

impl DraftIdentities {
    /// Derive the evidence and assertion identities for one proposal.
    fn for_proposal(request: &WorkspaceJob, proposal_id: &str) -> Self {
        let (evidence, evidence_revision) = record_identity(request, proposal_id, "evidence");
        let (assertion, assertion_revision) = record_identity(request, proposal_id, "assertion");
        DraftIdentities {
            evidence: crate::InputKey {
                record_id: evidence,
                revision_id: evidence_revision,
            },
            assertion: crate::InputKey {
                record_id: assertion,
                revision_id: assertion_revision,
            },
        }
    }
}

/// The evidence draft that supports one proposal's cited premise.
fn evidence_draft(
    request: &WorkspaceJob,
    identities: &DraftIdentities,
    premise: &crate::ProposalPremise,
    span: mneme_core::SourceSpan,
) -> mneme_store::RecordDraft {
    let ancestry = premise
        .derivation
        .map(|derivation| {
            vec![mneme_core::Reference::local(
                derivation,
                mneme_core::RecordKind::Derivation,
            )]
        })
        .unwrap_or_default();
    mneme_memory::build_evidence(
        identities.evidence.record_id,
        identities.evidence.revision_id,
        &request.scope,
        mneme_memory::EvidenceOptions {
            assertion: identities.assertion.record_id,
            source: premise.record_id,
            source_revision: premise.revision_id,
            span: Some(span),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::Inference,
            ancestry: &ancestry,
        },
    )
}

/// The proposed-assertion draft for one proposal's claim.
fn assertion_draft(
    request: &WorkspaceJob,
    identities: &DraftIdentities,
    claim: ProposedClaim,
) -> mneme_store::RecordDraft {
    let ProposedClaim {
        subject,
        predicate,
        value,
        stance,
        valid_time,
        uncertainty,
        model_provenance,
    } = claim;
    let extraction = request.extractor.as_ref().map(|extractor| {
        (
            extractor.identity.as_str(),
            extractor.prompt_digest.as_str(),
        )
    });
    let mut draft = mneme_memory::build_proposed_assertion(
        identities.assertion.record_id,
        identities.assertion.revision_id,
        &request.scope,
        mneme_memory::ProposedAssertionOptions {
            subject,
            predicate: &predicate,
            value,
            stance,
            origin: if extraction.is_some() {
                mneme_core::Origin::ModelExtraction
            } else {
                mneme_core::Origin::Inference
            },
            asserted_by: &request.actor,
            valid_time,
            evidence: &[mneme_core::Reference::local(
                identities.evidence.record_id,
                mneme_core::RecordKind::Evidence,
            )],
            extraction,
            superseded_by: None,
        },
    );
    if let Some(uncertainty) = uncertainty {
        draft.payload.insert(
            mneme_core::Symbol::from("uncertainty"),
            mneme_core::Value::string(uncertainty),
        );
    }
    if let (Some(extractor), Some(provenance)) = (request.extractor.as_ref(), model_provenance) {
        draft.payload.insert(
            mneme_core::Symbol::from("x-model-provenance"),
            model_provenance_value(extractor, provenance),
        );
    }
    draft
}

fn model_provenance_value(
    extractor: &crate::ExtractorDescriptor,
    provenance: crate::ExtractionProvenance,
) -> mneme_core::Value {
    let usage_value = match provenance.usage {
        mneme_recall::inference::UsageTelemetry::Measured(usage) => {
            mneme_core::Value::record_named(
                "token-usage",
                vec![
                    token_usage_value(usage.prompt_tokens),
                    token_usage_value(usage.completion_tokens),
                    token_usage_value(usage.total_tokens),
                ],
            )
        }
        mneme_recall::inference::UsageTelemetry::Unavailable => {
            mneme_core::Value::symbol("unavailable")
        }
    };
    mneme_core::Value::record_named(
        "model-provenance",
        vec![
            mneme_core::Value::string(extractor.identity.clone()),
            mneme_core::Value::string(extractor.revision.clone()),
            mneme_core::Value::string(extractor.prompt_digest.clone()),
            mneme_core::Value::string(provenance.input_digest),
            mneme_core::Value::string(provenance.configuration_digest),
            provenance.reported_model.map_or_else(
                || mneme_core::Value::symbol("unavailable"),
                mneme_core::Value::string,
            ),
            mneme_core::Value::integer(provenance.elapsed_ns),
            usage_value,
        ],
    )
}

fn token_usage_value(tokens: Option<u64>) -> mneme_core::Value {
    tokens.map_or_else(
        || mneme_core::Value::symbol("unavailable"),
        mneme_core::Value::integer,
    )
}

/// The claim one proposal asks to record as a proposed assertion.
struct ProposedClaim {
    subject: mneme_core::RecordId,
    predicate: String,
    value: mneme_core::Value,
    stance: mneme_memory::Stance,
    valid_time: mneme_core::ValidTime,
    uncertainty: Option<String>,
    model_provenance: Option<crate::ExtractionProvenance>,
}

/// The claim one proposal asks to record.
fn proposed_claim(
    view: &mneme_memory::View,
    proposal: &crate::Proposal,
) -> Result<ProposedClaim, String> {
    match &proposal.operation {
        crate::ProposalOperation::Summary(summary) => {
            let premise = proposal
                .premises
                .first()
                .ok_or_else(|| "the summary has no premise".to_owned())?;
            Ok(ProposedClaim {
                subject: summary_subject(view, premise.record_id)?,
                predicate: SUMMARY_PREDICATE.to_owned(),
                value: mneme_core::Value::string(summary.text.clone()),
                stance: mneme_memory::Stance::Hypothesis,
                valid_time: mneme_core::ValidTime::Unknown,
                uncertainty: None,
                model_provenance: None,
            })
        }
        crate::ProposalOperation::Assertion(assertion) => {
            entity_subject(view, assertion.subject)?;
            Ok(ProposedClaim {
                subject: assertion.subject,
                predicate: assertion.predicate.clone(),
                value: assertion.value.clone(),
                stance: match assertion.stance {
                    crate::ProposalStance::Affirm => mneme_memory::Stance::Affirm,
                    crate::ProposalStance::Deny => mneme_memory::Stance::Deny,
                    crate::ProposalStance::Hypothesis => mneme_memory::Stance::Hypothesis,
                },
                valid_time: assertion.valid_time,
                uncertainty: assertion.uncertainty.clone(),
                model_provenance: assertion.extraction.clone(),
            })
        }
        crate::ProposalOperation::Dispute(_)
        | crate::ProposalOperation::Supersession(_)
        | crate::ProposalOperation::Absence(_)
        | crate::ProposalOperation::Cleanup(_)
        | crate::ProposalOperation::Procedure(_) => {
            Err("this proposal kind is not recorded as a proposed assertion".to_owned())
        }
    }
}

/// The entity a summary proposal is an interpretation of.
///
/// A summary says something about the subject its source names; a source that
/// names no entity cannot carry one, so no assertion is recorded for it.
fn summary_subject(
    view: &mneme_memory::View,
    source: mneme_core::RecordId,
) -> Result<mneme_core::RecordId, String> {
    let source = view
        .source(source)
        .map_err(|_| "the summary source is not readable".to_owned())?;
    let entity = source
        .entity
        .ok_or_else(|| "the summary source names no entity".to_owned())?;
    entity_subject(view, entity)?;
    Ok(entity)
}

/// Check that one proposed subject is a readable entity record.
fn entity_subject(view: &mneme_memory::View, subject: mneme_core::RecordId) -> Result<(), String> {
    let record = view
        .record(subject)
        .map_err(|_| "the proposal subject is not readable".to_owned())?;
    if record.kind != mneme_core::RecordKind::Entity {
        return Err("the proposal subject is not an entity record".to_owned());
    }
    Ok(())
}

/// The predicate a deterministic summary proposal records.
///
/// A summary is an interpretation of the bytes it cites, so it is recorded as a
/// hypothesis about its source rather than as a claim about the world.
const SUMMARY_PREDICATE: &str = "summary";

/// The record and revision identity derived for one run's proposal record.
///
/// Identities are bound to the run (job, request key, policy and extractor) and
/// to the proposal, whose own identity already names the exact input revisions it
/// was generated from. A retry of the same request therefore derives the same
/// records and is detected as a replay even though the job's own commit advanced
/// the head, while a different run can never overwrite or silently reuse another
/// run's records. Reusing a key for different inputs yields different identities,
/// and the store's idempotency rule refuses that key reuse.
fn record_identity(
    request: &WorkspaceJob,
    proposal_id: &str,
    label: &str,
) -> (mneme_core::RecordId, mneme_core::RevisionId) {
    let identity = mneme_core::Value::record_named(
        "consolidation-record",
        vec![
            mneme_core::Value::symbol(label),
            mneme_core::Value::string(request.job_id.clone()),
            mneme_core::Value::string(request.idempotency_key.clone()),
            mneme_core::Value::string(request.policy_version.clone()),
            request.extractor.as_ref().map_or_else(
                || mneme_core::Value::symbol("none"),
                |extractor| {
                    mneme_core::Value::record_named(
                        "extractor",
                        vec![
                            mneme_core::Value::string(extractor.identity.clone()),
                            mneme_core::Value::string(extractor.revision.clone()),
                            mneme_core::Value::string(extractor.prompt_digest.clone()),
                        ],
                    )
                },
            ),
            mneme_core::Value::string(proposal_id),
        ],
    );
    let record = mneme_core::ContentDigest::of_payload(&identity);
    let revision = mneme_core::ContentDigest::of_payload(&mneme_core::Value::record_named(
        "consolidation-revision",
        vec![identity, record.to_value()],
    ));
    (
        mneme_core::RecordId::from_bytes(leading_bytes(record)),
        mneme_core::RevisionId::from_bytes(leading_bytes(revision)),
    )
}

/// The first sixteen digest bytes, as an identity-sized key.
fn leading_bytes(digest: mneme_core::ContentDigest) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    for (target, source) in bytes.iter_mut().zip(digest.as_bytes()) {
        *target = *source;
    }
    bytes
}

/// The committed state a job reports.
struct CommitReport {
    revision: mneme_core::WorkspaceRevisionId,
    proposals: Vec<CommittedProposal>,
    replayed: bool,
}

/// Commit the drafts, replaying a commit this run already recorded.
fn commit(
    workspace: &mut mneme_store::Workspace,
    request: &WorkspaceJob,
    base: mneme_core::WorkspaceRevisionId,
    drafts: Vec<ProposalDrafts>,
) -> Result<CommitReport, Failure> {
    let mut proposals = Vec::with_capacity(drafts.len());
    let mut records = Vec::with_capacity(drafts.len().saturating_mul(2));
    let mut already = 0_usize;
    for draft in drafts {
        let existing = workspace
            .record_revisions(draft.committed.assertion)
            .map_err(|error| Failure::Store(error.to_string()))?;
        if existing.is_empty() {
            records.push(draft.evidence);
            records.push(draft.assertion);
        } else {
            already = already.saturating_add(1);
        }
        proposals.push(draft.committed);
    }
    if proposals.is_empty() {
        return Ok(CommitReport {
            revision: workspace
                .current_revision()
                .map_err(|error| Failure::Store(error.to_string()))?,
            proposals,
            replayed: false,
        });
    }
    if already == proposals.len() {
        return Ok(CommitReport {
            revision: workspace
                .current_revision()
                .map_err(|error| Failure::Store(error.to_string()))?,
            proposals,
            replayed: true,
        });
    }
    if already != 0 {
        return Err(Failure::Store(
            "the consolidation run is partially committed".to_owned(),
        ));
    }
    let batch = mneme_memory::Batch {
        actor: request.actor.clone(),
        scope: request.scope.clone(),
        idempotency_key: request.idempotency_key.clone(),
        records,
        source_blobs: Vec::new(),
        publications: Vec::new(),
    };
    let outcome = mneme_memory::Engine::new(workspace, request.access.clone())
        .commit_at_base(batch, base)
        .map_err(|error| match error {
            mneme_memory::EvidenceError::Store(mneme_store::Failure::StaleBase { .. }) => {
                Failure::StaleBase
            }
            other => Failure::Memory(describe_memory_error(&other)),
        })?;
    Ok(CommitReport {
        revision: outcome.revision,
        proposals,
        replayed: false,
    })
}

/// A memory failure message that names no foreign record.
fn describe_memory_error(error: &mneme_memory::EvidenceError) -> String {
    match error {
        mneme_memory::EvidenceError::Validation(diagnostics) => format!(
            "evidence validation failed: {}",
            diagnostics
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        ),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at() -> mneme_core::Timestamp {
        mneme_core::Timestamp::parse("2026-11-10T00:00:00Z").expect("time")
    }

    fn record_draft(envelope: &mneme_core::RecordEnvelope) -> mneme_store::RecordDraft {
        mneme_store::RecordDraft {
            schema_version: envelope.schema_version,
            kind: envelope.kind,
            record_id: envelope.record_id,
            revision_id: envelope.revision_id,
            predecessor: envelope.predecessor,
            scope: envelope.scope.clone(),
            payload: envelope.payload.clone(),
        }
    }

    fn commit(
        workspace: &mut mneme_store::Workspace,
        scope: &mneme_core::ScopeId,
        key: &str,
        records: Vec<mneme_store::RecordDraft>,
        source_blobs: Vec<mneme_store::SourceBlobDraft>,
    ) {
        let batch = mneme_memory::Batch {
            actor: "model-recovery-test".to_owned(),
            scope: scope.clone(),
            idempotency_key: key.to_owned(),
            records,
            source_blobs,
            publications: Vec::new(),
        };
        mneme_memory::Engine::new(workspace, mneme_memory::Access::Operator)
            .commit(batch)
            .expect("commit fixture records");
    }

    fn workspace_with_two_sources() -> (
        tempfile::TempDir,
        mneme_store::Workspace,
        mneme_core::ScopeId,
    ) {
        let temp = tempfile::tempdir().expect("temporary workspace");
        let mut workspace = mneme_store::Workspace::create(
            temp.path(),
            mneme_store::WorkspaceConfig {
                clock: Box::new(mneme_store::FixedClock::new(at())),
                faults: Box::new(mneme_store::NoFaults),
            },
        )
        .expect("create workspace");
        let entity = mneme_core::fixtures::entity();
        let scope = entity.scope.clone();
        commit(
            &mut workspace,
            &scope,
            "entity",
            vec![record_draft(&entity)],
            Vec::new(),
        );
        for (ordinal, text, path) in [
            (
                0_u8,
                b"Cedar service uses SQLite.".as_slice(),
                "cedar-a.txt",
            ),
            (
                1_u8,
                b"Cedar deployment also uses SQLite.".as_slice(),
                "cedar-b.txt",
            ),
        ] {
            let (source, blob) = mneme_memory::build_source(
                mneme_core::RecordId::from_bytes([0x20 + ordinal; 16]),
                mneme_core::RevisionId::from_bytes([0x40 + ordinal; 16]),
                &scope,
                mneme_memory::SourceOptions {
                    bytes: text,
                    media_type: "text/plain",
                    entity: Some(entity.record_id),
                    path_hint: Some(path),
                },
            )
            .expect("build source fixture");
            commit(
                &mut workspace,
                &scope,
                &format!("source-{ordinal}"),
                vec![source],
                vec![blob],
            );
        }
        (temp, workspace, scope)
    }

    fn model_extractor() -> (
        crate::model_extractor::ModelExtractor,
        mneme_recall::inference::InvocationConfig,
        mneme_recall::inference::InvocationLimits,
    ) {
        let config = mneme_recall::inference::InvocationConfig {
            descriptor: mneme_recall::inference::ModelDescriptor {
                adapter_id: "fixture-json-worker".to_owned(),
                adapter_version: "fixture-v1".to_owned(),
                model_id: "fixture-model".to_owned(),
                model_revision: "fixture-revision".to_owned(),
                artifact_digest: mneme_recall::inference::input_digest(b"fixture-artifact"),
                tokenizer_id: "fixture-tokenizer".to_owned(),
                tokenizer_digest: mneme_recall::inference::input_digest(b"fixture-tokenizer"),
                prompt_template_digest:
                    crate::model_extractor::ModelExtractor::prompt_template_digest(),
                output_schema_digest: crate::model_extractor::ModelExtractor::output_schema_digest(
                ),
                settings_digest: crate::model_extractor::ModelExtractor::settings_digest(),
            },
            worker: mneme_recall::inference::WorkerCommand {
                executable: std::path::PathBuf::from("/bin/cat"),
                args: Vec::new(),
            },
        };
        let limits = mneme_recall::inference::InvocationLimits {
            max_input_bytes: 64 * 1_024,
            max_output_bytes: 64 * 1_024,
            max_wall_time: std::time::Duration::from_secs(2),
        };
        let extractor = crate::model_extractor::ModelExtractor::new(config.clone(), limits)
            .expect("fixture model configuration");
        (extractor, config, limits)
    }

    fn workspace_job(
        scope: mneme_core::ScopeId,
        extractor: &crate::model_extractor::ModelExtractor,
        job_id: &str,
        idempotency_key: &str,
    ) -> WorkspaceJob {
        let mut request = WorkspaceJob::new(
            scope,
            mneme_memory::Access::Operator,
            JobRequest {
                actor: "model-recovery-test",
                job_id,
                idempotency_key,
                query: "Cedar",
                at: at(),
                recorded_at: at(),
            },
        );
        request.extractor = Some(extractor.extractor_descriptor().clone());
        request.limits.max_model_calls = 2;
        request.limits.max_time_ms = 1_000;
        request
    }

    #[test]
    fn resumed_model_attempt_verification_binds_reserved_deadline() {
        let (_temp, mut workspace, scope) = workspace_with_two_sources();
        let (extractor, config, limits) = model_extractor();
        let request = workspace_job(scope, &extractor, "deadline-job", "deadline-key");
        let prepared = prepare_workspace_job(&mut workspace, &request).expect("prepare inputs");
        assert_eq!(prepared.inputs.len(), 2, "fixture has two reviewed sources");

        let reserved_wall_time = std::time::Duration::from_millis(500);
        let reserved_limits = mneme_recall::inference::InvocationLimits {
            max_wall_time: reserved_wall_time,
            ..limits
        };
        let configuration_digest = config.invocation_digest(reserved_limits);
        let mut executor =
            crate::runner::Executor::start(prepared.job.clone()).expect("start model job");
        for input in &prepared.inputs {
            let entities = source_entity_handle(&prepared.view, &request.scope, input)
                .expect("source entity handle");
            let model_request = extractor
                .prepare_request(input, &entities)
                .expect("prepare model request");
            executor
                .reserve_model_call(crate::runner::ModelCallReservation {
                    input: input.key,
                    input_digest: model_request.input_digest(),
                    configuration_digest: &configuration_digest,
                    input_bytes: model_request.input_bytes(),
                    output_bytes: model_request.reserved_output_bytes(),
                    wall_time: reserved_wall_time,
                })
                .expect("reserve exact deadline");
        }

        assert!(verify_model_attempt_inputs(&prepared, &extractor, executor.progress()).is_ok());
    }

    #[test]
    fn same_identity_partial_model_progress_fails_reserved_attempt_without_replay() {
        let (temp, mut workspace, scope) = workspace_with_two_sources();
        let (extractor, _config, _limits) = model_extractor();
        let request = workspace_job(scope, &extractor, "partial-job", "partial-key");
        let prepared = prepare_workspace_job(&mut workspace, &request).expect("prepare inputs");
        assert_eq!(prepared.inputs.len(), 2, "fixture has two reviewed sources");

        let mut executor =
            crate::runner::Executor::start(prepared.job.clone()).expect("start model job");
        let input = &prepared.inputs[0];
        let entities = source_entity_handle(&prepared.view, &request.scope, input)
            .expect("source entity handle");
        let model_request = extractor
            .prepare_request(input, &entities)
            .expect("prepare model request")
            .cap_wall_time(
                executor
                    .remaining_model_time()
                    .expect("remaining job budget"),
            )
            .expect("cap model deadline");
        executor
            .reserve_model_call(crate::runner::ModelCallReservation {
                input: input.key,
                input_digest: model_request.input_digest(),
                configuration_digest: model_request.configuration_digest(),
                input_bytes: model_request.input_bytes(),
                output_bytes: model_request.reserved_output_bytes(),
                wall_time: model_request.wall_time(),
            })
            .expect("persist one reserved call");

        let progress_store = crate::runner::ProgressStore::new(temp.path().join("progress.json"));
        progress_store
            .save(executor.progress())
            .expect("persist interrupted model run");
        let receipt = consolidate_workspace_with_model(
            &mut workspace,
            &request,
            &extractor,
            &progress_store,
            &mneme_recall::inference::InvocationControl::default(),
        )
        .expect("recover same-identity interrupted progress");
        let recovered = progress_store
            .load()
            .expect("load recovered progress")
            .expect("recovered progress exists");

        assert_eq!(receipt.status, crate::JobStatus::Failed);
        assert_eq!(recovered.status, crate::JobStatus::Failed);
        assert_eq!(recovered.model_calls_reserved, 1);
        assert_eq!(recovered.model_attempts.len(), 1);
        assert_eq!(
            recovered.model_attempts[0].phase,
            crate::runner::ModelAttemptPhase::Invoked
        );
        assert_eq!(
            recovered.model_attempts[0].status,
            Some(mneme_recall::inference::InvocationStatus::Failed)
        );
    }
}
