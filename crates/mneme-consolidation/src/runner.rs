//! Durable progress, cancellation, and retry identity for consolidation jobs.
//!
//! Progress advances one reviewed input at a time. A retry resumes the same
//! identity without replaying completed inputs or duplicating proposal IDs, and
//! a policy, limit, extractor or input change starts an identifiable new run
//! instead of reusing another run's progress.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// Maximum inference calls allowed in one model-backed job.
pub const MAX_MODEL_CALLS_PER_JOB: u32 = 16;
/// Maximum serialized model-input bytes reserved by one job.
pub const MAX_MODEL_INPUT_BYTES_PER_JOB: u64 = 16 * 1_048_576;
/// Maximum model-output bytes reserved by one job.
pub const MAX_MODEL_OUTPUT_BYTES_PER_JOB: u64 = 64 * 1_048_576;

/// A cooperative cancellation flag.
#[derive(Clone, Default)]
pub struct JobControl {
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl JobControl {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Durable progress for one job identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobProgress {
    pub job_id: String,
    /// The run identity every stored unit of progress belongs to.
    pub identity: JobIdentity,
    pub completed: std::collections::BTreeSet<crate::InputKey>,
    /// Proposal identities whose source content was forgotten.
    pub suppressed: std::collections::BTreeSet<String>,
    pub proposal_ids: std::collections::BTreeSet<String>,
    /// Declared deterministic work, not measured elapsed wall time.
    pub declared_work_ms: u64,
    /// Host-measured wall time for supervised inference attempts.
    pub observed_elapsed_ns: u64,
    /// Monotonic reservation count; failed and interrupted attempts remain charged.
    pub model_calls_reserved: u32,
    /// Reserved input bytes; only sizes and digests are retained, never bytes.
    pub model_input_bytes_reserved: u64,
    /// Reserved output bytes; only sizes and digests are retained, never output.
    pub model_output_bytes_reserved: u64,
    /// One content-free durable reservation/attempt per input, with no automatic retry.
    pub model_attempts: Vec<ModelAttempt>,
    pub status: crate::JobStatus,
}

/// Durable phase of one model call and its proposal commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelAttemptPhase {
    Reserved,
    Invoked,
    Prepared,
    Committed,
}

/// Content-free durable model attempt and finite resource reservation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelAttempt {
    pub input: crate::InputKey,
    pub input_digest: String,
    pub configuration_digest: String,
    pub input_bytes: u64,
    pub reserved_output_bytes: u64,
    pub reserved_wall_ms: u64,
    pub phase: ModelAttemptPhase,
    pub status: Option<mneme_recall::inference::InvocationStatus>,
    pub elapsed_ns: u64,
    pub usage: mneme_recall::inference::UsageTelemetry,
    pub reported_model: Option<String>,
    pub output_bytes: Option<u64>,
    pub observed_output_digest: Option<String>,
    pub proposal_ids: Vec<String>,
}

impl JobProgress {
    /// Validate that progress belongs to the job and has no out-of-batch work.
    pub fn validate(&self, job: &crate::Job) -> Result<(), String> {
        if self.job_id != job.job_id {
            return Err("progress belongs to another job".to_owned());
        }
        if self.identity != job.identity() {
            return Err("progress belongs to another run identity".to_owned());
        }
        if !self.completed.is_subset(&job.batch.reviewed) {
            return Err("progress contains unreviewed input units".to_owned());
        }
        if self.proposal_ids.len() > job.limits.max_proposals {
            return Err("progress exceeds the proposal limit".to_owned());
        }
        self.validate_model_work(job)?;
        if self.status == crate::JobStatus::Complete && self.completed != job.batch.reviewed {
            return Err("complete progress has unreviewed units".to_owned());
        }
        Ok(())
    }

    /// Validate a completed model run for replay against the same authorized
    /// inputs after its own commit advanced the workspace revision.
    pub fn validate_model_replay(&self, job: &crate::Job) -> Result<(), String> {
        self.validate_model_identity_replay(job)?;
        if !matches!(
            self.status,
            crate::JobStatus::Complete | crate::JobStatus::Partial
        ) || self.completed != job.batch.reviewed
            || self.model_attempts.len() != job.batch.reviewed.len()
            || self.model_attempts.iter().any(|attempt| {
                attempt.phase != ModelAttemptPhase::Committed
                    || attempt.status != Some(mneme_recall::inference::InvocationStatus::Complete)
            })
        {
            return Err("stored model work is not a complete committed run".to_owned());
        }
        Ok(())
    }

    /// Validate static request identity and exact current work extent while
    /// allowing the workspace head to have advanced after the pinned run.
    pub fn validate_model_identity_replay(&self, job: &crate::Job) -> Result<(), String> {
        if self.job_id != job.job_id
            || self.identity.idempotency_key != job.idempotency_key
            || self.identity.policy_version != job.policy_version
            || self.identity.extractor != job.extractor
            || self.identity.limits != job.limits
            || self.identity.eligibility_generation != job.batch.eligibility_generation
        {
            return Err("stored model progress belongs to a different request identity".to_owned());
        }
        if job.extractor.is_none() {
            return Err("model replay requires a declared extractor".to_owned());
        }
        self.validate_model_work(job)?;
        Ok(())
    }

    fn validate_model_work(&self, job: &crate::Job) -> Result<(), String> {
        if !self.completed.is_subset(&job.batch.reviewed)
            || self.proposal_ids.len() > job.limits.max_proposals
            || u32::try_from(self.model_attempts.len()).ok() != Some(self.model_calls_reserved)
            || self.model_calls_reserved > job.limits.max_model_calls.min(MAX_MODEL_CALLS_PER_JOB)
            || job.batch.reviewed.len() > job.limits.max_inputs
        {
            return Err("stored model work exceeds the current job bounds".to_owned());
        }
        validate_model_attempts(self, job)
    }
}

/// A job run that can be reconstructed from durable progress.
#[derive(Clone, Debug)]
pub struct Executor {
    job: crate::Job,
    progress: JobProgress,
}

/// Finite request facts reserved before a model worker is dispatched.
#[allow(unknown_lints, usize_in_public_api)] // byte counts size the actual request and output buffer
#[derive(Clone, Copy, Debug)]
pub struct ModelCallReservation<'a> {
    /// Reviewed source revision addressed by this invocation.
    pub input: crate::InputKey,
    /// Digest of the exact serialized worker request.
    pub input_digest: &'a str,
    /// Digest of the pinned invocation configuration and deadline.
    pub configuration_digest: &'a str,
    /// Exact serialized request size in bytes.
    pub input_bytes: usize,
    /// Maximum output buffer reserved for the worker.
    pub output_bytes: usize,
    /// Exact whole-millisecond worker deadline.
    pub wall_time: std::time::Duration,
}

struct ModelCallAccounting {
    input_bytes: u64,
    output_bytes: u64,
    wall_ms: u64,
    next_input_bytes: u64,
    next_output_bytes: u64,
}

impl Executor {
    /// Start a fresh run.
    pub fn start(job: crate::Job) -> Result<Self, String> {
        job.validate()?;
        let progress = JobProgress {
            job_id: job.job_id.clone(),
            identity: job.identity(),
            completed: std::collections::BTreeSet::new(),
            suppressed: std::collections::BTreeSet::new(),
            proposal_ids: std::collections::BTreeSet::new(),
            declared_work_ms: 0,
            observed_elapsed_ns: 0,
            model_calls_reserved: 0,
            model_input_bytes_reserved: 0,
            model_output_bytes_reserved: 0,
            model_attempts: Vec::new(),
            status: crate::JobStatus::Running,
        };
        Ok(Executor { job, progress })
    }

    /// Resume from durable progress, refusing a different run identity.
    ///
    /// An interrupted run (timeout or cancellation) resumes with a fresh budget
    /// and keeps its completed units, so its durable progress is never thrown
    /// away. A completed run is returned as recorded; a failed run is refused,
    /// because the same identity would fail again.
    pub fn resume(job: crate::Job, progress: JobProgress) -> Result<Self, String> {
        job.validate()?;
        progress.validate(&job)?;
        let mut progress = progress;
        match progress.status {
            crate::JobStatus::Complete => {}
            crate::JobStatus::Failed => {
                return Err("failed progress cannot be resumed under the same identity".to_owned());
            }
            crate::JobStatus::Timeout | crate::JobStatus::Cancelled => {
                if job.extractor.is_none() {
                    progress.declared_work_ms = 0;
                }
                progress.status = crate::JobStatus::Running;
            }
            crate::JobStatus::Running | crate::JobStatus::Partial => {}
        }
        Ok(Executor { job, progress })
    }

    /// Reopen a model run only to reconcile its already-prepared records after
    /// the atomic workspace commit may have succeeded before progress was saved.
    pub fn resume_model_replay(job: crate::Job, progress: JobProgress) -> Result<Self, String> {
        job.validate()?;
        progress.validate_model_identity_replay(&job)?;
        if progress.status == crate::JobStatus::Failed {
            return Err("failed progress cannot be resumed under the same identity".to_owned());
        }
        Ok(Executor { job, progress })
    }

    pub fn progress(&self) -> &JobProgress {
        &self.progress
    }

    pub fn job(&self) -> &crate::Job {
        &self.job
    }

    /// Suppress every unit and proposal derived from forgotten content.
    ///
    /// A forget reaches the units whose own record or ancestry it covers: their
    /// availability becomes forgotten, so no generator can use them again, and
    /// the proposal identities already produced from them are dropped so a
    /// replay cannot restore forbidden content. Returns the number of units
    /// suppressed.
    pub fn suppress(
        &mut self,
        forgotten: &std::collections::BTreeSet<mneme_core::RecordId>,
    ) -> u64 {
        let mut suppressed_units: u64 = 0;
        for unit in &mut self.job.batch.units {
            let is_derived = forgotten.contains(&unit.key.record_id)
                || unit
                    .ancestry_roots
                    .iter()
                    .any(|root| forgotten.contains(&root.record_id));
            if !is_derived {
                continue;
            }
            if unit.availability.is_retained() {
                unit.availability = crate::InputAvailability::Forgotten {
                    reason: "source content was explicitly forgotten".to_owned(),
                };
                suppressed_units = suppressed_units.saturating_add(1);
            }
        }
        let forgotten_proposals = self
            .progress
            .proposal_ids
            .iter()
            .filter(|proposal_id| proposal_is_forgotten(proposal_id, forgotten))
            .cloned()
            .collect::<Vec<_>>();
        for proposal_id in forgotten_proposals {
            self.progress.proposal_ids.remove(&proposal_id);
            self.progress.suppressed.insert(proposal_id);
        }
        for attempt in &mut self.progress.model_attempts {
            attempt
                .proposal_ids
                .retain(|proposal_id| !proposal_is_forgotten(proposal_id, forgotten));
        }
        // The run's input extent changed, so its identity must follow; a stored
        // snapshot taken before the forget stays a different identity.
        self.progress.identity = self.job.identity();
        suppressed_units
    }

    /// Process one reviewed input and persist proposals/progress in memory.
    ///
    /// Repeating an already completed input is idempotent and returns no new
    /// proposals. A terminal run refuses further work before cancellation is
    /// consulted, so a late cancel can never rewrite a recorded status, and
    /// cancellation or a time limit prevents the current unit from being marked
    /// complete.
    pub fn process_summary(
        &mut self,
        input: &crate::proposals::GeneratorInput,
        control: &JobControl,
        elapsed_ms: u64,
    ) -> Result<Vec<crate::Proposal>, String> {
        if is_terminal(self.progress.status) {
            return Err("job is not running".to_owned());
        }
        if self.job.extractor.is_some() {
            self.progress.status = crate::JobStatus::Failed;
            return Err(
                "declared model extraction requires the supervised model invocation path"
                    .to_owned(),
            );
        }
        if control.is_cancelled() {
            self.progress.status = crate::JobStatus::Cancelled;
            return Err("job cancelled".to_owned());
        }
        if !self.job.batch.reviewed.contains(&input.key) {
            return Err("input is not in the reviewed batch".to_owned());
        }
        if self.progress.completed.contains(&input.key) {
            return Ok(Vec::new());
        }
        match mneme_kernel::budget::charge(
            self.progress.declared_work_ms,
            elapsed_ms,
            self.job.limits.max_time_ms,
        ) {
            Some(total) => self.progress.declared_work_ms = total,
            None => {
                self.progress.status = crate::JobStatus::Timeout;
                return Err("job time limit exceeded".to_owned());
            }
        }
        let proposals = crate::proposals::DeterministicGenerator.generate(
            &self.job,
            &self.job.batch,
            std::slice::from_ref(input),
        )?;
        let new_proposals = self.register_deterministic_proposals(proposals)?;
        self.progress.completed.insert(input.key);
        self.progress.status = if self.progress.completed == self.job.batch.reviewed {
            if matches!(self.job.batch.coverage, crate::BatchCoverage::Complete) {
                crate::JobStatus::Complete
            } else {
                crate::JobStatus::Partial
            }
        } else {
            crate::JobStatus::Partial
        };
        Ok(new_proposals)
    }

    fn register_deterministic_proposals(
        &mut self,
        proposals: Vec<crate::Proposal>,
    ) -> Result<Vec<crate::Proposal>, String> {
        let mut new_proposals = Vec::with_capacity(proposals.len());
        for proposal in proposals {
            if self.progress.suppressed.contains(&proposal.proposal_id)
                || self.progress.proposal_ids.contains(&proposal.proposal_id)
            {
                self.progress.status = crate::JobStatus::Failed;
                return Err("generated proposals share a proposal identity".to_owned());
            }
            let limit = u64::try_from(self.job.limits.max_proposals)
                .map_err(|_| "job proposal limit is too large".to_owned())?;
            let used = u64::try_from(self.progress.proposal_ids.len())
                .map_err(|_| "progress exceeds the proposal limit".to_owned())?;
            if mneme_kernel::budget::charge(used, 1, limit).is_none() {
                self.progress.status = crate::JobStatus::Failed;
                return Err("job proposal limit exceeded".to_owned());
            }
            if proposal.disposition != crate::ProposalDisposition::Pending {
                self.progress.status = crate::JobStatus::Failed;
                return Err("generated proposal must be pending".to_owned());
            }
            self.progress
                .proposal_ids
                .insert(proposal.proposal_id.clone());
            new_proposals.push(proposal);
        }
        Ok(new_proposals)
    }

    /// Durably reserve one bounded inference attempt before the worker starts.
    pub fn reserve_model_call(
        &mut self,
        reservation: ModelCallReservation<'_>,
    ) -> Result<(), String> {
        self.validate_model_call_reservation(&reservation)?;
        let accounting = self.model_call_accounting(&reservation)?;
        self.progress.model_attempts.push(ModelAttempt {
            input: reservation.input,
            input_digest: reservation.input_digest.to_owned(),
            configuration_digest: reservation.configuration_digest.to_owned(),
            input_bytes: accounting.input_bytes,
            reserved_output_bytes: accounting.output_bytes,
            reserved_wall_ms: accounting.wall_ms,
            phase: ModelAttemptPhase::Reserved,
            status: None,
            elapsed_ns: 0,
            usage: mneme_recall::inference::UsageTelemetry::Unavailable,
            reported_model: None,
            output_bytes: None,
            observed_output_digest: None,
            proposal_ids: Vec::new(),
        });
        self.progress.model_calls_reserved = self.progress.model_calls_reserved.saturating_add(1);
        self.progress.model_input_bytes_reserved = accounting.next_input_bytes;
        self.progress.model_output_bytes_reserved = accounting.next_output_bytes;
        Ok(())
    }

    fn validate_model_call_reservation(
        &self,
        reservation: &ModelCallReservation<'_>,
    ) -> Result<(), String> {
        if is_terminal(self.progress.status) {
            return Err("job is not running".to_owned());
        }
        if self.job.extractor.is_none() {
            return Err("model calls require a declared extractor".to_owned());
        }
        if !self.job.batch.reviewed.contains(&reservation.input) {
            return Err("model input is not in the reviewed batch".to_owned());
        }
        if self.progress.completed.contains(&reservation.input)
            || self
                .progress
                .model_attempts
                .iter()
                .any(|attempt| attempt.input == reservation.input)
        {
            return Err(
                "model input already has a durable attempt; automatic retry is refused".to_owned(),
            );
        }
        if self.progress.model_calls_reserved
            >= self.job.limits.max_model_calls.min(MAX_MODEL_CALLS_PER_JOB)
        {
            return Err("job model-call reservation limit exceeded".to_owned());
        }
        if !is_sha256_digest(reservation.input_digest)
            || !is_sha256_digest(reservation.configuration_digest)
        {
            return Err("model reservation requires input and configuration digests".to_owned());
        }
        Ok(())
    }

    fn model_call_accounting(
        &self,
        reservation: &ModelCallReservation<'_>,
    ) -> Result<ModelCallAccounting, String> {
        if reservation.input_bytes == 0
            || reservation.input_bytes > mneme_recall::inference::MAX_INVOCATION_INPUT_BYTES
            || reservation.output_bytes == 0
            || reservation.output_bytes > mneme_recall::inference::MAX_INVOCATION_OUTPUT_BYTES
            || reservation.wall_time.is_zero()
            || reservation.wall_time > mneme_recall::inference::MAX_INVOCATION_WALL_TIME
        {
            return Err("model reservation exceeds the finite invocation bounds".to_owned());
        }
        let input_bytes = u64::try_from(reservation.input_bytes)
            .map_err(|_| "model input size exceeds u64".to_owned())?;
        let output_bytes = u64::try_from(reservation.output_bytes)
            .map_err(|_| "model output reservation exceeds u64".to_owned())?;
        let next_input = self
            .progress
            .model_input_bytes_reserved
            .checked_add(input_bytes)
            .filter(|total| *total <= MAX_MODEL_INPUT_BYTES_PER_JOB)
            .ok_or_else(|| "job cumulative model input-byte budget exceeded".to_owned())?;
        let next_output = self
            .progress
            .model_output_bytes_reserved
            .checked_add(output_bytes)
            .filter(|total| *total <= MAX_MODEL_OUTPUT_BYTES_PER_JOB)
            .ok_or_else(|| "job cumulative model output-byte reservation exceeded".to_owned())?;
        if !reservation.wall_time.as_nanos().is_multiple_of(1_000_000) {
            return Err("model wall-time reservation must use whole milliseconds".to_owned());
        }
        let wall_ms = u64::try_from(reservation.wall_time.as_millis())
            .map_err(|_| "model wall-time reservation exceeds u64 milliseconds".to_owned())?;
        let elapsed_ms = elapsed_ms_ceil(self.progress.observed_elapsed_ns)?;
        let pending_ms = self
            .progress
            .model_attempts
            .iter()
            .filter(|attempt| attempt.phase == ModelAttemptPhase::Reserved)
            .try_fold(0_u64, |total, attempt| {
                total.checked_add(attempt.reserved_wall_ms)
            })
            .ok_or_else(|| "reserved model wall time overflows".to_owned())?;
        let remaining_ms = self
            .job
            .limits
            .max_time_ms
            .saturating_sub(elapsed_ms)
            .saturating_sub(pending_ms);
        if wall_ms > remaining_ms {
            return Err("job has insufficient remaining observed-time budget".to_owned());
        }
        Ok(ModelCallAccounting {
            input_bytes,
            output_bytes,
            wall_ms,
            next_input_bytes: next_input,
            next_output_bytes: next_output,
        })
    }

    /// Record the result of the single reserved inference call.
    pub fn record_model_invocation(
        &mut self,
        input: crate::InputKey,
        attempt: &crate::proposals::ExtractorAttempt,
    ) -> Result<(), String> {
        let observed_elapsed_ns = self.progress.observed_elapsed_ns;
        let job_limit_ns = u128::from(self.job.limits.max_time_ms).saturating_mul(1_000_000);
        let reservation = self.matching_model_reservation(input, attempt)?;
        let elapsed_ns = crate::elapsed_ns_telemetry(attempt.elapsed);
        let attempt_elapsed_ns = elapsed_ns;
        let elapsed_ns = observed_elapsed_ns
            .checked_add(elapsed_ns)
            .ok_or_else(|| "cumulative model elapsed time overflows".to_owned())?;
        if u128::from(elapsed_ns) > job_limit_ns {
            record_attempt_receipt(
                reservation,
                attempt,
                mneme_recall::inference::InvocationStatus::Timeout,
                attempt_elapsed_ns,
            );
            self.progress.observed_elapsed_ns = elapsed_ns;
            self.progress.status = crate::JobStatus::Timeout;
            return Err("job observed-time budget exceeded".to_owned());
        }
        let reserved_ns = u128::from(reservation.reserved_wall_ms).saturating_mul(1_000_000);
        if attempt.elapsed.as_nanos() > reserved_ns {
            record_attempt_receipt(
                reservation,
                attempt,
                mneme_recall::inference::InvocationStatus::Timeout,
                attempt_elapsed_ns,
            );
            self.progress.observed_elapsed_ns = elapsed_ns;
            self.progress.status = crate::JobStatus::Timeout;
            return Err("inference exceeded its durable wall-time reservation".to_owned());
        }
        record_attempt_receipt(reservation, attempt, attempt.status, attempt_elapsed_ns);
        self.progress.observed_elapsed_ns = elapsed_ns;
        self.progress.status = match attempt.status {
            mneme_recall::inference::InvocationStatus::Complete => crate::JobStatus::Partial,
            mneme_recall::inference::InvocationStatus::Timeout => crate::JobStatus::Timeout,
            mneme_recall::inference::InvocationStatus::Cancelled => crate::JobStatus::Cancelled,
            mneme_recall::inference::InvocationStatus::Unavailable
            | mneme_recall::inference::InvocationStatus::Failed
            | mneme_recall::inference::InvocationStatus::Oversized
            | mneme_recall::inference::InvocationStatus::Malformed => crate::JobStatus::Failed,
        };
        Ok(())
    }

    fn matching_model_reservation(
        &mut self,
        input: crate::InputKey,
        attempt: &crate::proposals::ExtractorAttempt,
    ) -> Result<&mut ModelAttempt, String> {
        let Some(reservation) = self.progress.model_attempts.iter_mut().find(|reservation| {
            reservation.input == input && reservation.input_digest == attempt.input_digest
        }) else {
            return Err("model invocation has no matching durable reservation".to_owned());
        };
        if reservation.phase != ModelAttemptPhase::Reserved {
            return Err("model invocation reservation is not awaiting a result".to_owned());
        }
        if attempt
            .input_bytes
            .and_then(|bytes| u64::try_from(bytes).ok())
            != Some(reservation.input_bytes)
        {
            self.progress.status = crate::JobStatus::Failed;
            return Err("model invocation input size differs from its reservation".to_owned());
        }
        if reservation.configuration_digest != attempt.configuration_digest {
            self.progress.status = crate::JobStatus::Failed;
            return Err("model invocation configuration differs from its reservation".to_owned());
        }
        Ok(reservation)
    }

    /// Persist proposal identities before the workspace commit so a crash can
    /// recover committed output without retaining source-bearing model text.
    pub fn prepare_model_proposals(
        &mut self,
        input: crate::InputKey,
        proposal_ids: &[String],
    ) -> Result<(), String> {
        let Some(attempt) = self
            .progress
            .model_attempts
            .iter_mut()
            .find(|attempt| attempt.input == input)
        else {
            return Err("model proposals have no durable attempt".to_owned());
        };
        if attempt.phase != ModelAttemptPhase::Invoked
            || attempt.status != Some(mneme_recall::inference::InvocationStatus::Complete)
        {
            return Err("model proposals require a completed invocation".to_owned());
        }
        let count = self
            .progress
            .proposal_ids
            .len()
            .checked_add(proposal_ids.len())
            .ok_or_else(|| "proposal count overflows".to_owned())?;
        if count > self.job.limits.max_proposals {
            self.progress.status = crate::JobStatus::Failed;
            return Err("job proposal limit exceeded".to_owned());
        }
        let mut new_ids = std::collections::BTreeSet::new();
        for proposal_id in proposal_ids {
            if proposal_id.trim().is_empty()
                || self.progress.proposal_ids.contains(proposal_id)
                || !new_ids.insert(proposal_id.as_str())
            {
                self.progress.status = crate::JobStatus::Failed;
                return Err("model proposals contain a duplicate identity".to_owned());
            }
        }
        attempt.proposal_ids = proposal_ids.to_vec();
        attempt.phase = ModelAttemptPhase::Prepared;
        self.progress
            .proposal_ids
            .extend(proposal_ids.iter().cloned());
        self.progress.status = crate::JobStatus::Partial;
        Ok(())
    }

    /// Mark a prepared proposal batch committed only after the workspace CAS succeeds.
    pub fn mark_model_committed(&mut self, input: crate::InputKey) -> Result<(), String> {
        let Some(attempt) = self
            .progress
            .model_attempts
            .iter_mut()
            .find(|attempt| attempt.input == input)
        else {
            return Err("committed model input has no durable attempt".to_owned());
        };
        if attempt.phase != ModelAttemptPhase::Prepared {
            return Err("model input is not prepared for commit".to_owned());
        }
        attempt.phase = ModelAttemptPhase::Committed;
        self.progress.completed.insert(input);
        self.progress.status = if self.progress.completed == self.job.batch.reviewed {
            if matches!(self.job.batch.coverage, crate::BatchCoverage::Complete) {
                crate::JobStatus::Complete
            } else {
                crate::JobStatus::Partial
            }
        } else {
            crate::JobStatus::Partial
        };
        Ok(())
    }

    /// Remaining model wall time after completed work and outstanding reserves.
    pub fn remaining_model_time(&self) -> Result<std::time::Duration, String> {
        let observed_ms = elapsed_ms_ceil(self.progress.observed_elapsed_ns)?;
        let pending_ms = self
            .progress
            .model_attempts
            .iter()
            .filter(|attempt| attempt.phase == ModelAttemptPhase::Reserved)
            .try_fold(0_u64, |total, attempt| {
                total.checked_add(attempt.reserved_wall_ms)
            })
            .ok_or_else(|| "reserved model wall time overflows".to_owned())?;
        let remaining_ms = self
            .job
            .limits
            .max_time_ms
            .saturating_sub(observed_ms)
            .saturating_sub(pending_ms);
        Ok(std::time::Duration::from_millis(remaining_ms))
    }

    /// Classify calls left unresolved by a process interruption as failed.
    /// The same reviewed input is never invoked twice under this identity.
    pub fn fail_interrupted_model_attempts(&mut self) -> bool {
        let mut has_interrupted_attempts = false;
        for attempt in &mut self.progress.model_attempts {
            if attempt.phase == ModelAttemptPhase::Reserved {
                attempt.phase = ModelAttemptPhase::Invoked;
                attempt.status = Some(mneme_recall::inference::InvocationStatus::Failed);
                has_interrupted_attempts = true;
            } else if attempt.phase == ModelAttemptPhase::Invoked
                && attempt.status == Some(mneme_recall::inference::InvocationStatus::Complete)
            {
                // The output was intentionally memory-only and is unavailable
                // after interruption, so it cannot be validated or replayed.
                has_interrupted_attempts = true;
            }
        }
        if has_interrupted_attempts {
            self.progress.status = crate::JobStatus::Failed;
        }
        has_interrupted_attempts
    }

    /// Stop a model run after request preparation, proposal validation, or
    /// stale-base refusal without recording any successful input.
    pub fn fail_model_work(&mut self) {
        if !is_terminal(self.progress.status) {
            self.progress.status = crate::JobStatus::Failed;
        }
    }

    /// Record cancellation before commit; prepared output remains noncommittable.
    pub fn cancel_model_work(&mut self) {
        if !is_terminal(self.progress.status) {
            self.progress.status = crate::JobStatus::Cancelled;
        }
    }

    /// Mark a reserved call cancelled when the host stops it before dispatch.
    pub fn cancel_reserved_model_call(&mut self, input: crate::InputKey) -> Result<(), String> {
        let Some(attempt) = self
            .progress
            .model_attempts
            .iter_mut()
            .find(|attempt| attempt.input == input)
        else {
            return Err("cancelled model call has no durable reservation".to_owned());
        };
        if attempt.phase != ModelAttemptPhase::Reserved || attempt.status.is_some() {
            return Err("model call is not awaiting dispatch".to_owned());
        }
        attempt.phase = ModelAttemptPhase::Invoked;
        attempt.status = Some(mneme_recall::inference::InvocationStatus::Cancelled);
        self.progress.status = crate::JobStatus::Cancelled;
        Ok(())
    }

    /// Finalize a run whose reviewed inputs all reached a committed outcome.
    pub fn finish_model_work(&mut self) {
        if is_terminal(self.progress.status) {
            return;
        }
        self.progress.status = if self.progress.completed == self.job.batch.reviewed {
            if matches!(self.job.batch.coverage, crate::BatchCoverage::Complete) {
                crate::JobStatus::Complete
            } else {
                crate::JobStatus::Partial
            }
        } else {
            crate::JobStatus::Partial
        };
    }
}

fn record_attempt_receipt(
    reservation: &mut ModelAttempt,
    attempt: &crate::proposals::ExtractorAttempt,
    status: mneme_recall::inference::InvocationStatus,
    elapsed_ns: u64,
) {
    reservation.status = Some(status);
    reservation.phase = ModelAttemptPhase::Invoked;
    reservation.elapsed_ns = elapsed_ns;
    reservation.usage = attempt.usage.clone();
    reservation.reported_model = attempt.reported_model.clone();
    reservation.output_bytes = attempt
        .output_bytes
        .and_then(|bytes| u64::try_from(bytes).ok());
    reservation.observed_output_digest = attempt.observed_output_digest.clone();
}

/// Validate that every persisted model reserve is in the pinned reviewed extent.
fn validate_model_attempts(progress: &JobProgress, job: &crate::Job) -> Result<(), String> {
    if !progress.model_attempts.is_empty() && job.extractor.is_none() {
        return Err("model reservations exist for a deterministic job".to_owned());
    }
    let mut inputs = std::collections::BTreeSet::new();
    let mut input_bytes = 0_u64;
    let mut output_bytes = 0_u64;
    let mut observed_ns = 0_u64;
    let mut proposal_ids = std::collections::BTreeSet::new();
    for attempt in &progress.model_attempts {
        if !job.batch.reviewed.contains(&attempt.input) || !inputs.insert(attempt.input) {
            return Err("model reservation input is unreviewed or duplicated".to_owned());
        }
        if has_invalid_model_attempt_bounds(attempt) {
            return Err("model reservation fields exceed their hard bounds".to_owned());
        }
        validate_model_attempt_phase(attempt)?;
        if attempt.phase == ModelAttemptPhase::Committed
            && !progress.completed.contains(&attempt.input)
        {
            return Err("committed model attempt is not marked complete".to_owned());
        }
        if attempt.phase == ModelAttemptPhase::Prepared
            && progress.completed.contains(&attempt.input)
        {
            return Err("prepared model attempt is marked committed".to_owned());
        }
        for proposal_id in &attempt.proposal_ids {
            if proposal_id.trim().is_empty() || !proposal_ids.insert(proposal_id.clone()) {
                return Err("model attempts contain duplicate proposal identities".to_owned());
            }
        }
        input_bytes = input_bytes
            .checked_add(attempt.input_bytes)
            .ok_or_else(|| "model input reservation total overflows".to_owned())?;
        output_bytes = output_bytes
            .checked_add(attempt.reserved_output_bytes)
            .ok_or_else(|| "model output reservation total overflows".to_owned())?;
        observed_ns = observed_ns
            .checked_add(attempt.elapsed_ns)
            .ok_or_else(|| "model elapsed-time total overflows".to_owned())?;
    }
    if input_bytes != progress.model_input_bytes_reserved
        || output_bytes != progress.model_output_bytes_reserved
        || input_bytes > MAX_MODEL_INPUT_BYTES_PER_JOB
        || output_bytes > MAX_MODEL_OUTPUT_BYTES_PER_JOB
        || observed_ns != progress.observed_elapsed_ns
        || !proposal_ids.is_subset(&progress.proposal_ids)
    {
        return Err("model progress counters differ from durable attempt receipts".to_owned());
    }
    let calls = u32::try_from(progress.model_attempts.len())
        .map_err(|_| "model attempt count exceeds u32".to_owned())?;
    if calls != progress.model_calls_reserved {
        return Err("model-call reservation count differs from attempts".to_owned());
    }
    Ok(())
}

fn has_invalid_model_attempt_bounds(attempt: &ModelAttempt) -> bool {
    !is_sha256_digest(&attempt.input_digest)
        || !is_sha256_digest(&attempt.configuration_digest)
        || attempt.input_bytes == 0
        || u64::try_from(mneme_recall::inference::MAX_INVOCATION_INPUT_BYTES)
            .is_ok_and(|maximum| attempt.input_bytes > maximum)
        || attempt.reserved_output_bytes == 0
        || u64::try_from(mneme_recall::inference::MAX_INVOCATION_OUTPUT_BYTES)
            .is_ok_and(|maximum| attempt.reserved_output_bytes > maximum)
        || attempt.reserved_wall_ms == 0
        || u64::try_from(mneme_recall::inference::MAX_INVOCATION_WALL_TIME.as_millis())
            .is_ok_and(|maximum| attempt.reserved_wall_ms > maximum)
        || attempt
            .output_bytes
            .is_some_and(|actual| actual > attempt.reserved_output_bytes)
        || attempt
            .observed_output_digest
            .as_deref()
            .is_some_and(|digest| !is_sha256_digest(digest))
        || (attempt.observed_output_digest.is_some() && attempt.output_bytes.is_none())
}

fn validate_model_attempt_phase(attempt: &ModelAttempt) -> Result<(), String> {
    match (attempt.phase, attempt.status) {
        (ModelAttemptPhase::Reserved, None) => {
            if attempt.elapsed_ns != 0
                || attempt.output_bytes.is_some()
                || attempt.observed_output_digest.is_some()
                || !attempt.proposal_ids.is_empty()
            {
                return Err("unresolved model reserve contains an outcome".to_owned());
            }
        }
        (ModelAttemptPhase::Invoked, Some(_)) => {}
        (
            ModelAttemptPhase::Prepared | ModelAttemptPhase::Committed,
            Some(mneme_recall::inference::InvocationStatus::Complete),
        ) => {}
        _ => return Err("model attempt phase and invocation outcome disagree".to_owned()),
    }
    Ok(())
}

fn elapsed_ms_ceil(elapsed_ns: u64) -> Result<u64, String> {
    elapsed_ns
        .checked_add(999_999)
        .map(|rounded| rounded / 1_000_000)
        .ok_or_else(|| "elapsed nanoseconds overflow milliseconds".to_owned())
}

fn is_sha256_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Whether one recorded status admits no further work.
fn is_terminal(status: crate::JobStatus) -> bool {
    matches!(
        status,
        crate::JobStatus::Complete
            | crate::JobStatus::Timeout
            | crate::JobStatus::Cancelled
            | crate::JobStatus::Failed
    )
}

/// Whether a proposal identity was derived from one of the forgotten records.
///
/// Proposal identities embed the input record identity, so a suppressed
/// identity is recognised from its own name without keeping the content.
fn proposal_is_forgotten(
    proposal_id: &str,
    forgotten: &std::collections::BTreeSet<mneme_core::RecordId>,
) -> bool {
    forgotten
        .iter()
        .any(|record| proposal_id.contains(&record.to_hex()))
}

/// Retry identity parameters that must match before resuming stored work.
///
/// Every input that changes a generated proposal is covered: the request key and
/// policy, the extractor configuration, the limits, the pinned input revision
/// and the batch digest. Reusing an idempotency key after any of them changed is
/// a new run, never a resume of the old one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobIdentity {
    pub idempotency_key: String,
    pub policy_version: String,
    pub extractor: Option<crate::ExtractorDescriptor>,
    pub limits: crate::JobLimits,
    pub input_revision: mneme_core::WorkspaceRevisionId,
    pub batch_digest: String,
    pub eligibility_generation: u64,
}

impl crate::Job {
    /// Identity used to classify retries.
    pub fn identity(&self) -> JobIdentity {
        JobIdentity {
            idempotency_key: self.idempotency_key.clone(),
            policy_version: self.policy_version.clone(),
            extractor: self.extractor.clone(),
            limits: self.limits,
            input_revision: self.base_revision,
            batch_digest: format!("sha256:{}", self.batch.digest().to_hex()),
            eligibility_generation: self.batch.eligibility_generation,
        }
    }
}

/// Whether a retry reuses a run or starts an identifiable new one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryClassification {
    Resume,
    NewRun,
}

/// Classify a retry. Changing policy, limits, extractor or inputs creates a new
/// run even when the caller reuses the same idempotency key.
pub fn classify_retry(previous: &JobIdentity, next: &JobIdentity) -> RetryClassification {
    if previous == next {
        RetryClassification::Resume
    } else {
        RetryClassification::NewRun
    }
}

/// A versioned durable progress snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgressStore {
    path: std::path::PathBuf,
}

/// Process-local counter that keeps concurrent writers' temporary files apart.
static TEMPORARY_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
const PROGRESS_SNAPSHOT_VERSION: u32 = 4;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProgressSnapshot {
    #[serde(default = "legacy_progress_version")]
    version: u32,
    job_id: String,
    identity: IdentitySnapshot,
    completed: Vec<ProgressKey>,
    suppressed: Vec<String>,
    proposal_ids: Vec<String>,
    #[serde(default, alias = "elapsedMs")]
    declared_work_ms: u64,
    #[serde(default)]
    observed_elapsed_ns: u64,
    #[serde(default)]
    model_calls_reserved: u32,
    #[serde(default)]
    model_input_bytes_reserved: u64,
    #[serde(default)]
    model_output_bytes_reserved: u64,
    #[serde(default = "Vec::new")]
    model_attempts: Vec<ModelAttemptSnapshot>,
    status: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ModelAttemptSnapshot {
    input: ProgressKey,
    input_digest: String,
    configuration_digest: String,
    input_bytes: u64,
    reserved_output_bytes: u64,
    reserved_wall_ms: u64,
    phase: String,
    status: Option<String>,
    elapsed_ns: u64,
    usage_available: bool,
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
    total_tokens: Option<u64>,
    reported_model: Option<String>,
    output_bytes: Option<u64>,
    observed_output_digest: Option<String>,
    proposal_ids: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentitySnapshot {
    idempotency_key: String,
    policy_version: String,
    extractor: Option<ExtractorSnapshot>,
    max_inputs: u64,
    max_proposals: u64,
    max_time_ms: u64,
    max_model_calls: u32,
    input_revision: String,
    batch_digest: String,
    #[serde(default)]
    eligibility_generation: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExtractorSnapshot {
    identity: String,
    revision: String,
    prompt_digest: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProgressKey {
    record_id: String,
    revision_id: String,
}

fn legacy_progress_version() -> u32 {
    1
}

impl crate::JobStatus {
    fn name(self) -> &'static str {
        match self {
            crate::JobStatus::Running => "running",
            crate::JobStatus::Complete => "complete",
            crate::JobStatus::Partial => "partial",
            crate::JobStatus::Timeout => "timeout",
            crate::JobStatus::Cancelled => "cancelled",
            crate::JobStatus::Failed => "failed",
        }
    }

    fn parse(text: &str) -> Result<crate::JobStatus, String> {
        match text {
            "running" => Ok(crate::JobStatus::Running),
            "complete" => Ok(crate::JobStatus::Complete),
            "partial" => Ok(crate::JobStatus::Partial),
            "timeout" => Ok(crate::JobStatus::Timeout),
            "cancelled" => Ok(crate::JobStatus::Cancelled),
            "failed" => Ok(crate::JobStatus::Failed),
            _ => Err(format!("unknown job status {text:?}")),
        }
    }
}

impl JobIdentity {
    fn to_snapshot(&self) -> Result<IdentitySnapshot, String> {
        Ok(IdentitySnapshot {
            idempotency_key: self.idempotency_key.clone(),
            policy_version: self.policy_version.clone(),
            extractor: self.extractor.as_ref().map(|extractor| ExtractorSnapshot {
                identity: extractor.identity.clone(),
                revision: extractor.revision.clone(),
                prompt_digest: extractor.prompt_digest.clone(),
            }),
            max_inputs: u64::try_from(self.limits.max_inputs)
                .map_err(|_| "input limit is too large".to_owned())?,
            max_proposals: u64::try_from(self.limits.max_proposals)
                .map_err(|_| "proposal limit is too large".to_owned())?,
            max_time_ms: self.limits.max_time_ms,
            max_model_calls: self.limits.max_model_calls,
            input_revision: self.input_revision.to_hex(),
            batch_digest: self.batch_digest.clone(),
            eligibility_generation: self.eligibility_generation,
        })
    }

    fn from_snapshot(snapshot: IdentitySnapshot) -> Result<Self, String> {
        Ok(JobIdentity {
            idempotency_key: snapshot.idempotency_key,
            policy_version: snapshot.policy_version,
            extractor: snapshot
                .extractor
                .map(|extractor| crate::ExtractorDescriptor {
                    identity: extractor.identity,
                    revision: extractor.revision,
                    prompt_digest: extractor.prompt_digest,
                }),
            limits: crate::JobLimits {
                max_inputs: usize::try_from(snapshot.max_inputs)
                    .map_err(|_| "stored input limit is out of range".to_owned())?,
                max_proposals: usize::try_from(snapshot.max_proposals)
                    .map_err(|_| "stored proposal limit is out of range".to_owned())?,
                max_time_ms: snapshot.max_time_ms,
                max_model_calls: snapshot.max_model_calls,
            },
            input_revision: mneme_core::WorkspaceRevisionId::from_hex(&snapshot.input_revision)
                .map_err(|error| error.to_owned())?,
            batch_digest: snapshot.batch_digest,
            eligibility_generation: snapshot.eligibility_generation,
        })
    }
}

impl JobProgress {
    /// Encode progress as a deterministic JSON snapshot.
    pub fn to_json(&self) -> Result<String, String> {
        let snapshot = ProgressSnapshot {
            version: PROGRESS_SNAPSHOT_VERSION,
            job_id: self.job_id.clone(),
            identity: self.identity.to_snapshot()?,
            completed: self
                .completed
                .iter()
                .map(|key| ProgressKey {
                    record_id: key.record_id.to_hex(),
                    revision_id: key.revision_id.to_hex(),
                })
                .collect(),
            suppressed: self.suppressed.iter().cloned().collect(),
            proposal_ids: self.proposal_ids.iter().cloned().collect(),
            declared_work_ms: self.declared_work_ms,
            observed_elapsed_ns: self.observed_elapsed_ns,
            model_calls_reserved: self.model_calls_reserved,
            model_input_bytes_reserved: self.model_input_bytes_reserved,
            model_output_bytes_reserved: self.model_output_bytes_reserved,
            model_attempts: self
                .model_attempts
                .iter()
                .map(ModelAttempt::to_snapshot)
                .collect(),
            status: self.status.name().to_owned(),
        };
        serde_json::to_string_pretty(&snapshot).map_err(|error| error.to_string())
    }

    /// Decode progress from a JSON snapshot.
    pub fn from_json(text: &str) -> Result<Self, String> {
        let snapshot: ProgressSnapshot =
            serde_json::from_str(text).map_err(|error| error.to_string())?;
        if !matches!(snapshot.version, 1 | 2 | 3 | PROGRESS_SNAPSHOT_VERSION) {
            return Err(format!(
                "unsupported progress snapshot version {}",
                snapshot.version
            ));
        }
        let completed = snapshot
            .completed
            .into_iter()
            .map(|key| {
                Ok(crate::InputKey {
                    record_id: mneme_core::RecordId::from_hex(&key.record_id)
                        .map_err(|error| error.to_owned())?,
                    revision_id: mneme_core::RevisionId::from_hex(&key.revision_id)
                        .map_err(|error| error.to_owned())?,
                })
            })
            .collect::<Result<std::collections::BTreeSet<_>, String>>()?;
        let progress = JobProgress {
            job_id: snapshot.job_id,
            identity: JobIdentity::from_snapshot(snapshot.identity)?,
            completed,
            suppressed: snapshot.suppressed.into_iter().collect(),
            proposal_ids: snapshot.proposal_ids.into_iter().collect(),
            declared_work_ms: snapshot.declared_work_ms,
            observed_elapsed_ns: snapshot.observed_elapsed_ns,
            model_calls_reserved: snapshot.model_calls_reserved,
            model_input_bytes_reserved: snapshot.model_input_bytes_reserved,
            model_output_bytes_reserved: snapshot.model_output_bytes_reserved,
            model_attempts: snapshot
                .model_attempts
                .into_iter()
                .map(ModelAttempt::from_snapshot)
                .collect::<Result<Vec<_>, String>>()?,
            status: crate::JobStatus::parse(&snapshot.status)?,
        };
        validate_progress_snapshot(&progress)?;
        Ok(progress)
    }
}

impl ModelAttempt {
    fn to_snapshot(&self) -> ModelAttemptSnapshot {
        let (usage_available, prompt_tokens, completion_tokens, total_tokens) = match &self.usage {
            mneme_recall::inference::UsageTelemetry::Measured(usage) => (
                true,
                usage.prompt_tokens,
                usage.completion_tokens,
                usage.total_tokens,
            ),
            mneme_recall::inference::UsageTelemetry::Unavailable => (false, None, None, None),
        };
        ModelAttemptSnapshot {
            input: ProgressKey {
                record_id: self.input.record_id.to_hex(),
                revision_id: self.input.revision_id.to_hex(),
            },
            input_digest: self.input_digest.clone(),
            configuration_digest: self.configuration_digest.clone(),
            input_bytes: self.input_bytes,
            reserved_output_bytes: self.reserved_output_bytes,
            reserved_wall_ms: self.reserved_wall_ms,
            phase: self.phase.name().to_owned(),
            status: self.status.map(invocation_status_name).map(str::to_owned),
            elapsed_ns: self.elapsed_ns,
            usage_available,
            prompt_tokens,
            completion_tokens,
            total_tokens,
            reported_model: self.reported_model.clone(),
            output_bytes: self.output_bytes,
            observed_output_digest: self.observed_output_digest.clone(),
            proposal_ids: self.proposal_ids.clone(),
        }
    }

    fn from_snapshot(snapshot: ModelAttemptSnapshot) -> Result<Self, String> {
        let usage = if snapshot.usage_available {
            if snapshot.prompt_tokens.is_none()
                && snapshot.completion_tokens.is_none()
                && snapshot.total_tokens.is_none()
            {
                return Err("stored measured usage has no token counts".to_owned());
            }
            mneme_recall::inference::UsageTelemetry::Measured(mneme_recall::inference::TokenUsage {
                prompt_tokens: snapshot.prompt_tokens,
                completion_tokens: snapshot.completion_tokens,
                total_tokens: snapshot.total_tokens,
            })
        } else {
            if snapshot.prompt_tokens.is_some()
                || snapshot.completion_tokens.is_some()
                || snapshot.total_tokens.is_some()
            {
                return Err("stored unavailable usage carries token counts".to_owned());
            }
            mneme_recall::inference::UsageTelemetry::Unavailable
        };
        Ok(ModelAttempt {
            input: crate::InputKey {
                record_id: mneme_core::RecordId::from_hex(&snapshot.input.record_id)
                    .map_err(|error| error.to_owned())?,
                revision_id: mneme_core::RevisionId::from_hex(&snapshot.input.revision_id)
                    .map_err(|error| error.to_owned())?,
            },
            input_digest: snapshot.input_digest,
            configuration_digest: snapshot.configuration_digest,
            input_bytes: snapshot.input_bytes,
            reserved_output_bytes: snapshot.reserved_output_bytes,
            reserved_wall_ms: snapshot.reserved_wall_ms,
            phase: ModelAttemptPhase::parse(&snapshot.phase)?,
            status: snapshot
                .status
                .as_deref()
                .map(parse_invocation_status)
                .transpose()?,
            elapsed_ns: snapshot.elapsed_ns,
            usage,
            reported_model: snapshot.reported_model,
            output_bytes: snapshot.output_bytes,
            observed_output_digest: snapshot.observed_output_digest,
            proposal_ids: snapshot.proposal_ids,
        })
    }
}

impl ModelAttemptPhase {
    fn name(self) -> &'static str {
        match self {
            ModelAttemptPhase::Reserved => "reserved",
            ModelAttemptPhase::Invoked => "invoked",
            ModelAttemptPhase::Prepared => "prepared",
            ModelAttemptPhase::Committed => "committed",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "reserved" => Ok(ModelAttemptPhase::Reserved),
            "invoked" => Ok(ModelAttemptPhase::Invoked),
            "prepared" => Ok(ModelAttemptPhase::Prepared),
            "committed" => Ok(ModelAttemptPhase::Committed),
            _ => Err("stored model attempt has an unknown phase".to_owned()),
        }
    }
}

fn invocation_status_name(status: mneme_recall::inference::InvocationStatus) -> &'static str {
    match status {
        mneme_recall::inference::InvocationStatus::Complete => "complete",
        mneme_recall::inference::InvocationStatus::Timeout => "timeout",
        mneme_recall::inference::InvocationStatus::Cancelled => "cancelled",
        mneme_recall::inference::InvocationStatus::Unavailable => "unavailable",
        mneme_recall::inference::InvocationStatus::Failed => "failed",
        mneme_recall::inference::InvocationStatus::Oversized => "oversized",
        mneme_recall::inference::InvocationStatus::Malformed => "malformed",
    }
}

fn parse_invocation_status(
    value: &str,
) -> Result<mneme_recall::inference::InvocationStatus, String> {
    match value {
        "complete" => Ok(mneme_recall::inference::InvocationStatus::Complete),
        "timeout" => Ok(mneme_recall::inference::InvocationStatus::Timeout),
        "cancelled" => Ok(mneme_recall::inference::InvocationStatus::Cancelled),
        "unavailable" => Ok(mneme_recall::inference::InvocationStatus::Unavailable),
        "failed" => Ok(mneme_recall::inference::InvocationStatus::Failed),
        "oversized" => Ok(mneme_recall::inference::InvocationStatus::Oversized),
        "malformed" => Ok(mneme_recall::inference::InvocationStatus::Malformed),
        _ => Err("stored model attempt has an unknown invocation status".to_owned()),
    }
}

fn validate_progress_snapshot(progress: &JobProgress) -> Result<(), String> {
    if u32::try_from(progress.model_attempts.len()).ok() != Some(progress.model_calls_reserved)
        || progress.model_calls_reserved > MAX_MODEL_CALLS_PER_JOB
    {
        return Err("stored model-call reservation count differs from attempts".to_owned());
    }
    let mut input_bytes = 0_u64;
    let mut output_bytes = 0_u64;
    let mut elapsed_ns = 0_u64;
    let mut inputs = std::collections::BTreeSet::new();
    let mut proposals = std::collections::BTreeSet::new();
    for attempt in &progress.model_attempts {
        if !inputs.insert(attempt.input) {
            return Err("stored progress repeats a model input attempt".to_owned());
        }
        if has_invalid_model_attempt_bounds(attempt) {
            return Err("stored model reservation is incomplete".to_owned());
        }
        if has_invalid_snapshot_attempt_phase(attempt) {
            return Err("stored model attempt phase and status disagree".to_owned());
        }
        for proposal_id in &attempt.proposal_ids {
            if proposal_id.trim().is_empty() || !proposals.insert(proposal_id.clone()) {
                return Err("stored model proposal identities repeat".to_owned());
            }
        }
        input_bytes = input_bytes
            .checked_add(attempt.input_bytes)
            .ok_or_else(|| "stored input reservation total overflows".to_owned())?;
        output_bytes = output_bytes
            .checked_add(attempt.reserved_output_bytes)
            .ok_or_else(|| "stored output reservation total overflows".to_owned())?;
        elapsed_ns = elapsed_ns
            .checked_add(attempt.elapsed_ns)
            .ok_or_else(|| "stored elapsed-time total overflows".to_owned())?;
    }
    if input_bytes != progress.model_input_bytes_reserved
        || output_bytes != progress.model_output_bytes_reserved
        || input_bytes > MAX_MODEL_INPUT_BYTES_PER_JOB
        || output_bytes > MAX_MODEL_OUTPUT_BYTES_PER_JOB
        || elapsed_ns != progress.observed_elapsed_ns
        || !proposals.is_subset(&progress.proposal_ids)
    {
        return Err("stored progress counters disagree with model attempts".to_owned());
    }
    Ok(())
}

fn has_invalid_snapshot_attempt_phase(attempt: &ModelAttempt) -> bool {
    match (attempt.phase, attempt.status) {
        (ModelAttemptPhase::Reserved, None) => {
            attempt.elapsed_ns != 0
                || attempt.output_bytes.is_some()
                || attempt.observed_output_digest.is_some()
        }
        (ModelAttemptPhase::Invoked, Some(_)) => false,
        (
            ModelAttemptPhase::Prepared | ModelAttemptPhase::Committed,
            Some(mneme_recall::inference::InvocationStatus::Complete),
        ) => false,
        _ => true,
    }
}

impl ProgressStore {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        ProgressStore { path: path.into() }
    }

    /// Persist progress durably at the configured path.
    ///
    /// The snapshot is written to a uniquely named temporary file in the target
    /// directory, flushed to stable storage, renamed over the target, and the
    /// directory entry is flushed too. Flushing only the file would leave a
    /// crash able to expose the rename without the bytes.
    pub fn save(&self, progress: &JobProgress) -> Result<(), String> {
        let parent = self.path.parent().map_or_else(
            || std::path::PathBuf::from("."),
            std::path::Path::to_path_buf,
        );
        std::fs::create_dir_all(&parent).map_err(|error| error.to_string())?;
        let rendered = progress.to_json()?;
        let name = self
            .path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or("progress");
        let unique = TEMPORARY_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let temporary = parent.join(format!(".{name}.{}.{unique}.tmp", std::process::id()));
        write_synced(&temporary, rendered.as_bytes())?;
        if let Err(error) = std::fs::rename(&temporary, &self.path) {
            discard_temporary(&temporary);
            return Err(error.to_string());
        }
        sync_directory(&parent)
    }

    /// Load progress, returning `None` when the store has not been written.
    pub fn load(&self) -> Result<Option<JobProgress>, String> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => JobProgress::from_json(&text).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }
}

/// Remove a temporary file abandoned by a failed rename.
///
/// Best effort only: the rename error is the failure the caller must see, so a
/// leftover temporary file neither replaces nor masks it.
#[allow(unknown_lints, ignored_result)] // best-effort cleanup after the primary failure is decided
fn discard_temporary(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
}

/// Write bytes to a new file and flush them to stable storage.
fn write_synced(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

/// Flush one directory entry to stable storage.
fn sync_directory(path: &std::path::Path) -> Result<(), String> {
    std::fs::File::open(path)
        .map_err(|error| error.to_string())?
        .sync_all()
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> Vec<crate::proposals::GeneratorInput> {
        let fixture = crate::fixture().expect("fixture");
        let mut result = Vec::with_capacity(fixture.job.batch.units.len());
        for unit in fixture.job.batch.units.clone() {
            result.push(crate::proposals::GeneratorInput::from_unit(
                &unit,
                format!("source {}", unit.key.record_id.to_hex()),
                None,
            ));
        }
        result
    }

    fn run() -> Executor {
        Executor::start(crate::fixture().expect("fixture").job).expect("start")
    }

    fn model_run() -> Executor {
        let mut job = crate::fixture().expect("fixture").job;
        job.extractor = Some(crate::ExtractorDescriptor {
            identity: "fixture-model".to_owned(),
            revision: "sha256:fixture-artifact".to_owned(),
            prompt_digest: "sha256:fixture-prompt".to_owned(),
        });
        job.limits.max_model_calls = 2;
        job.limits.max_time_ms = 20_000;
        Executor::start(job).expect("model job")
    }

    fn reservation_digests() -> (String, String) {
        (
            mneme_recall::inference::input_digest(b"exact serialized model request"),
            mneme_recall::inference::input_digest(b"pinned model configuration"),
        )
    }

    fn reserve_first_input(
        run: &mut Executor,
        input: &crate::proposals::GeneratorInput,
    ) -> (String, String) {
        let (input_digest, configuration_digest) = reservation_digests();
        run.reserve_model_call(ModelCallReservation {
            input: input.key,
            input_digest: &input_digest,
            configuration_digest: &configuration_digest,
            input_bytes: 128,
            output_bytes: 256,
            wall_time: std::time::Duration::from_millis(500),
        })
        .expect("durable model reserve");
        (input_digest, configuration_digest)
    }

    fn completed_attempt(
        input_digest: String,
        configuration_digest: String,
    ) -> crate::proposals::ExtractorAttempt {
        crate::proposals::ExtractorAttempt {
            status: mneme_recall::inference::InvocationStatus::Complete,
            claims: Vec::new(),
            input_bytes: Some(128),
            elapsed: std::time::Duration::from_millis(1),
            usage: mneme_recall::inference::UsageTelemetry::Unavailable,
            input_digest,
            configuration_digest,
            reported_model: Some("fixture-model".to_owned()),
            output_bytes: Some(12),
            observed_output_digest: Some(mneme_recall::inference::input_digest(
                b"fixture response",
            )),
            detail: None,
            supervised_model: true,
        }
    }

    #[test]
    fn model_progress_is_content_free_and_forget_suppresses_attempt_output_ids() {
        let inputs = inputs();
        let mut run = model_run();
        let (input_digest, configuration_digest) = reserve_first_input(&mut run, &inputs[0]);
        let attempt = completed_attempt(input_digest, configuration_digest);
        run.record_model_invocation(inputs[0].key, &attempt)
            .expect("record attempt");
        let proposal_id = format!("model-proposal-{}", inputs[0].key.record_id.to_hex());
        run.prepare_model_proposals(inputs[0].key, std::slice::from_ref(&proposal_id))
            .expect("prepare candidate");
        run.mark_model_committed(inputs[0].key)
            .expect("mark committed");

        let rendered = run.progress().to_json().expect("content-free progress");
        assert!(!rendered.contains(inputs[0].text.as_str()));
        let loaded = JobProgress::from_json(&rendered).expect("progress roundtrip");
        assert_eq!(loaded.model_attempts.len(), 1);
        assert_eq!(loaded.model_attempts[0].input_bytes, 128);
        assert_eq!(loaded.model_attempts[0].elapsed_ns, 1_000_000);
        assert_eq!(
            loaded.model_attempts[0].observed_output_digest,
            Some(mneme_recall::inference::input_digest(b"fixture response"))
        );
        assert_eq!(
            loaded.model_attempts[0].usage,
            mneme_recall::inference::UsageTelemetry::Unavailable
        );

        let forgotten = std::collections::BTreeSet::from([inputs[0].key.record_id]);
        run.suppress(&forgotten);
        assert!(run.progress().proposal_ids.is_empty());
        assert!(run.progress().model_attempts[0].proposal_ids.is_empty());
        assert!(run.progress().suppressed.contains(&proposal_id));
        run.progress()
            .validate(run.job())
            .expect("suppressed progress remains valid");
    }

    #[test]
    fn interrupted_model_reservation_is_durable_and_not_automatically_replayed() {
        let inputs = inputs();
        let mut run = model_run();
        reserve_first_input(&mut run, &inputs[0]);
        let rendered = run.progress().to_json().expect("reserved snapshot");
        assert!(!rendered.contains(inputs[0].text.as_str()));
        let loaded = JobProgress::from_json(&rendered).expect("reserved snapshot valid");
        let mut resumed = Executor::resume_model_replay(run.job().clone(), loaded)
            .expect("same identity can reconcile interrupted work");
        assert!(resumed.fail_interrupted_model_attempts());
        assert_eq!(resumed.progress().status, crate::JobStatus::Failed);
        assert_eq!(resumed.progress().model_calls_reserved, 1);
        assert_eq!(resumed.progress().model_input_bytes_reserved, 128);
        assert_eq!(resumed.progress().model_attempts.len(), 1);
        assert!(resumed.progress().model_attempts[0].status.is_some());
        assert!(
            Executor::resume_model_replay(resumed.job().clone(), resumed.progress().clone())
                .is_err()
        );
    }

    #[test]
    fn model_call_reservation_requires_a_millisecond_exact_deadline() {
        let inputs = inputs();
        let mut run = model_run();
        let (input_digest, configuration_digest) = reservation_digests();
        let error = run
            .reserve_model_call(ModelCallReservation {
                input: inputs[0].key,
                input_digest: &input_digest,
                configuration_digest: &configuration_digest,
                input_bytes: 128,
                output_bytes: 256,
                wall_time: std::time::Duration::from_nanos(500_000_001),
            })
            .expect_err("a rounded reservation cannot identify the actual deadline");
        assert!(error.contains("whole milliseconds"));
        assert!(run.progress().model_attempts.is_empty());
        assert_eq!(run.progress().model_calls_reserved, 0);
    }

    #[test]
    fn pre_dispatch_cancellation_records_the_reserved_attempt() {
        let inputs = inputs();
        let mut run = model_run();
        reserve_first_input(&mut run, &inputs[0]);
        run.cancel_reserved_model_call(inputs[0].key)
            .expect("record cancellation");
        let attempt = &run.progress().model_attempts[0];
        assert_eq!(attempt.phase, ModelAttemptPhase::Invoked);
        assert_eq!(
            attempt.status,
            Some(mneme_recall::inference::InvocationStatus::Cancelled)
        );
        assert_eq!(run.progress().status, crate::JobStatus::Cancelled);
        let restored =
            JobProgress::from_json(&run.progress().to_json().expect("cancelled snapshot"))
                .expect("cancelled attempt remains durable");
        assert_eq!(restored.model_calls_reserved, 1);
        assert_eq!(restored.model_attempts[0].input_bytes, 128);
    }

    #[test]
    fn deterministic_job_refuses_declared_model_instead_of_attributing_fallback() {
        let inputs = inputs();
        let control = JobControl::new();
        let mut run = model_run();
        let error = run
            .process_summary(&inputs[0], &control, 10)
            .expect_err("declared model job must not emit deterministic proposals");
        assert!(error.contains("supervised model invocation path"));
        assert_eq!(run.progress().status, crate::JobStatus::Failed);
        assert!(run.progress().completed.is_empty());
        assert!(run.progress().proposal_ids.is_empty());
    }

    #[test]
    fn retry_resumes_without_duplicate_proposals() {
        let inputs = inputs();
        let control = JobControl::new();
        let mut run = run();
        let first = run
            .process_summary(&inputs[0], &control, 10)
            .expect("first");
        assert_eq!(first.len(), 1);
        let progress = run.progress().clone();
        let mut resumed = Executor::resume(run.job().clone(), progress).expect("resume");
        let duplicate = resumed
            .process_summary(&inputs[0], &control, 10)
            .expect("idempotent retry");
        assert!(duplicate.is_empty());
        let second = resumed
            .process_summary(&inputs[1], &control, 10)
            .expect("second");
        assert_eq!(second.len(), 1);
        assert_eq!(resumed.progress().completed.len(), 2);
        assert_eq!(resumed.progress().proposal_ids.len(), 2);
        assert_eq!(resumed.progress().status, crate::JobStatus::Complete);
    }

    #[test]
    fn cancellation_keeps_completed_units_and_does_not_advance() {
        let inputs = inputs();
        let mut run = run();
        let control = JobControl::new();
        run.process_summary(&inputs[0], &control, 10)
            .expect("first");
        control.cancel();
        let error = run
            .process_summary(&inputs[1], &control, 10)
            .expect_err("cancelled");
        assert_eq!(error, "job cancelled");
        assert_eq!(run.progress().status, crate::JobStatus::Cancelled);
        assert_eq!(run.progress().completed.len(), 1);
    }

    #[test]
    fn cancelled_and_timed_out_runs_resume_with_a_fresh_budget() {
        let inputs = inputs();
        let mut job = crate::fixture().expect("fixture").job;
        job.limits.max_time_ms = 15;
        let control = JobControl::new();
        let mut run = Executor::start(job).expect("start");
        run.process_summary(&inputs[0], &control, 10)
            .expect("first");
        let error = run
            .process_summary(&inputs[1], &control, 10)
            .expect_err("timeout");
        assert_eq!(error, "job time limit exceeded");
        assert_eq!(run.progress().status, crate::JobStatus::Timeout);
        let progress = run.progress().clone();
        let mut resumed = Executor::resume(run.job().clone(), progress).expect("resume timeout");
        assert_eq!(resumed.progress().status, crate::JobStatus::Running);
        assert_eq!(resumed.progress().declared_work_ms, 0);
        resumed
            .process_summary(&inputs[1], &control, 10)
            .expect("resumed unit");
        assert_eq!(resumed.progress().completed.len(), 2);
        assert!(resumed.progress().completed.contains(&inputs[1].key));

        let mut cancelled = Executor::start(resumed.job().clone()).expect("start again");
        let control = JobControl::new();
        cancelled
            .process_summary(&inputs[0], &control, 1)
            .expect("first");
        control.cancel();
        assert!(cancelled.process_summary(&inputs[1], &control, 1).is_err());
        let progress = cancelled.progress().clone();
        assert_eq!(progress.status, crate::JobStatus::Cancelled);
        let resumed = Executor::resume(cancelled.job().clone(), progress).expect("resume cancel");
        assert_eq!(resumed.progress().status, crate::JobStatus::Running);
    }

    #[test]
    fn a_late_cancel_never_rewrites_a_terminal_status() {
        let inputs = inputs();
        let mut run = run();
        let control = JobControl::new();
        run.process_summary(&inputs[0], &control, 1).expect("first");
        run.process_summary(&inputs[1], &control, 1)
            .expect("second");
        assert_eq!(run.progress().status, crate::JobStatus::Complete);
        control.cancel();
        assert!(run.process_summary(&inputs[1], &control, 1).is_err());
        assert_eq!(run.progress().status, crate::JobStatus::Complete);
    }

    #[test]
    fn time_limit_blocks_completion() {
        let inputs = inputs();
        let run = run();
        let control = JobControl::new();
        let mut job = run.job().clone();
        job.limits.max_time_ms = 5;
        let mut limited = Executor::start(job).expect("limited");
        let error = limited
            .process_summary(&inputs[0], &control, 6)
            .expect_err("timeout");
        assert_eq!(error, "job time limit exceeded");
        assert_eq!(limited.progress().status, crate::JobStatus::Timeout);
        assert!(limited.progress().completed.is_empty());
    }

    #[test]
    fn resume_refuses_a_changed_run_identity() {
        let inputs = inputs();
        let mut run = run();
        let control = JobControl::new();
        run.process_summary(&inputs[0], &control, 10)
            .expect("first");
        let progress = run.progress().clone();

        let mut policy = run.job().clone();
        policy.policy_version = "consolidation-policy/v2".to_owned();
        assert!(Executor::resume(policy.clone(), progress.clone()).is_err());
        assert_eq!(
            classify_retry(&run.job().identity(), &policy.identity()),
            RetryClassification::NewRun
        );

        let mut limits = run.job().clone();
        limits.limits.max_proposals = 4;
        assert!(Executor::resume(limits, progress.clone()).is_err());

        let mut extractor = run.job().clone();
        extractor.extractor = Some(crate::ExtractorDescriptor {
            identity: "extractor".to_owned(),
            revision: "r1".to_owned(),
            prompt_digest: "sha256:prompt".to_owned(),
        });
        assert!(Executor::resume(extractor, progress.clone()).is_err());

        let mut input = run.job().clone();
        input.base_revision = mneme_core::WorkspaceRevisionId::from_bytes([0x99; 16]);
        input.batch.requested_revision = input.base_revision;
        assert!(Executor::resume(input, progress.clone()).is_err());

        let mut batch = run.job().clone();
        batch.batch.units[1].availability = crate::InputAvailability::Pruned {
            reason: "pruned after review".to_owned(),
        };
        assert!(Executor::resume(batch, progress).is_err());
    }

    #[test]
    fn duplicate_proposal_identities_fail_instead_of_dropping() {
        let inputs = inputs();
        let mut run = run();
        let control = JobControl::new();
        run.process_summary(&inputs[0], &control, 1).expect("first");
        // A recorded identity that the next unit would emit must be an error,
        // not a silently dropped proposal and a Complete status.
        run.progress.proposal_ids.insert(format!(
            "{}-summary-{}:{}",
            run.progress.job_id,
            inputs[1].key.record_id.to_hex(),
            inputs[1].key.revision_id.to_hex()
        ));
        let error = run
            .process_summary(&inputs[1], &control, 1)
            .expect_err("duplicate identity");
        assert!(error.contains("proposal identity"));
        assert_eq!(run.progress().status, crate::JobStatus::Failed);
        assert!(!run.progress().completed.contains(&inputs[1].key));
    }

    #[test]
    fn suppression_marks_units_forgotten_and_drops_their_proposals() {
        let inputs = inputs();
        let mut run = run();
        let control = JobControl::new();
        let first = run.process_summary(&inputs[0], &control, 1).expect("first");
        assert_eq!(first.len(), 1);
        let forgotten = std::collections::BTreeSet::from([inputs[0].key.record_id]);
        assert_eq!(run.suppress(&forgotten), 1);
        assert_eq!(run.progress().proposal_ids.len(), 0);
        assert_eq!(run.progress().suppressed.len(), 1);
        assert!(matches!(
            run.job().batch.units[0].availability,
            crate::InputAvailability::Forgotten { .. }
        ));
        assert!(
            run.process_summary(&inputs[0], &control, 1).is_ok(),
            "a completed unit is not reprocessed"
        );
        let mut fresh = Executor::start(run.job().clone()).expect("fresh");
        assert!(
            fresh.process_summary(&inputs[0], &control, 1).is_err(),
            "forgotten bytes are never re-generated"
        );
    }

    #[test]
    fn policy_change_is_a_new_run_identity() {
        let job = crate::fixture().expect("fixture").job;
        let mut changed = job.identity();
        changed.policy_version = "next-policy".to_owned();
        assert_eq!(
            classify_retry(&job.identity(), &changed),
            RetryClassification::NewRun
        );
        assert_eq!(
            classify_retry(&job.identity(), &job.identity()),
            RetryClassification::Resume
        );
    }

    #[test]
    fn progress_store_roundtrips_and_resumes() {
        let inputs = inputs();
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ProgressStore::new(dir.path().join("progress.json"));
        let control = JobControl::new();
        let mut run = run();
        run.process_summary(&inputs[0], &control, 10)
            .expect("first");
        store.save(run.progress()).expect("save");
        let loaded = store.load().expect("load").expect("progress");
        let job = run.job().clone();
        let mut resumed = Executor::resume(job, loaded).expect("resume");
        resumed
            .process_summary(&inputs[1], &control, 10)
            .expect("second");
        assert_eq!(resumed.progress().status, crate::JobStatus::Complete);
        store.save(resumed.progress()).expect("save complete");
        let complete = store.load().expect("load").expect("complete progress");
        assert_eq!(complete.status, crate::JobStatus::Complete);
        assert_eq!(complete.completed.len(), 2);
        assert_eq!(complete.identity, resumed.job().identity());
    }

    #[test]
    fn progress_store_leaves_no_temporary_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ProgressStore::new(dir.path().join("progress.tmp"));
        let mut run = run();
        run.process_summary(&inputs()[0], &JobControl::new(), 1)
            .expect("first");
        store.save(run.progress()).expect("save");
        let entries = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(entries, vec!["progress.tmp".to_owned()]);
    }
}
