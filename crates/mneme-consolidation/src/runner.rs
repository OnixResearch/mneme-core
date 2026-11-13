//! Durable progress, cancellation, and retry identity for consolidation jobs.
//!
//! Progress advances one reviewed input at a time. A retry resumes the same
//! identity without replaying completed inputs or duplicating proposal IDs, and
//! a policy, limit, extractor or input change starts an identifiable new run
//! instead of reusing another run's progress.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

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
    pub elapsed_ms: u64,
    pub status: crate::JobStatus,
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
        if job.batch.reviewed.len() > job.limits.max_inputs {
            return Err("batch exceeds the input limit".to_owned());
        }
        if self.status == crate::JobStatus::Complete && self.completed != job.batch.reviewed {
            return Err("complete progress has unreviewed units".to_owned());
        }
        Ok(())
    }
}

/// A job run that can be reconstructed from durable progress.
#[derive(Clone, Debug)]
pub struct Executor {
    job: crate::Job,
    progress: JobProgress,
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
            elapsed_ms: 0,
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
                progress.elapsed_ms = 0;
                progress.status = crate::JobStatus::Running;
            }
            crate::JobStatus::Running | crate::JobStatus::Partial => {}
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
            self.progress.elapsed_ms,
            elapsed_ms,
            self.job.limits.max_time_ms,
        ) {
            Some(total) => self.progress.elapsed_ms = total,
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

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProgressSnapshot {
    job_id: String,
    identity: IdentitySnapshot,
    completed: Vec<ProgressKey>,
    suppressed: Vec<String>,
    proposal_ids: Vec<String>,
    elapsed_ms: u64,
    status: String,
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
        })
    }
}

impl JobProgress {
    /// Encode progress as a deterministic JSON snapshot.
    pub fn to_json(&self) -> Result<String, String> {
        let snapshot = ProgressSnapshot {
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
            elapsed_ms: self.elapsed_ms,
            status: self.status.name().to_owned(),
        };
        serde_json::to_string_pretty(&snapshot).map_err(|error| error.to_string())
    }

    /// Decode progress from a JSON snapshot.
    pub fn from_json(text: &str) -> Result<Self, String> {
        let snapshot: ProgressSnapshot =
            serde_json::from_str(text).map_err(|error| error.to_string())?;
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
        Ok(JobProgress {
            job_id: snapshot.job_id,
            identity: JobIdentity::from_snapshot(snapshot.identity)?,
            completed,
            suppressed: snapshot.suppressed.into_iter().collect(),
            proposal_ids: snapshot.proposal_ids.into_iter().collect(),
            elapsed_ms: snapshot.elapsed_ms,
            status: crate::JobStatus::parse(&snapshot.status)?,
        })
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
        assert_eq!(resumed.progress().elapsed_ms, 0);
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
