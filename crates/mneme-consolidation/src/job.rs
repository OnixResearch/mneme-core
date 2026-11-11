//! Durable progress, cancellation, and retry identity for consolidation jobs.
//!
//! Progress advances one reviewed input at a time. A retry resumes the same
//! identity without replaying completed inputs or duplicating proposal IDs.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::generator::{DeterministicGenerator, GeneratorInput};
use crate::{
    BatchCoverage, ConsolidationJob, ConsolidationProposal, InputKey, JobStatus,
    ProposalDisposition,
};

/// A cooperative cancellation flag.
#[derive(Clone, Default)]
pub struct JobControl {
    cancelled: Arc<AtomicBool>,
}

impl JobControl {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
}

/// Durable progress for one job identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobProgress {
    pub job_id: String,
    pub completed: BTreeSet<InputKey>,
    pub proposal_ids: BTreeSet<String>,
    pub elapsed_ms: u64,
    pub status: JobStatus,
}

impl JobProgress {
    /// Validate that progress belongs to the job and has no out-of-batch work.
    pub fn validate(&self, job: &ConsolidationJob) -> Result<(), String> {
        if self.job_id != job.job_id {
            return Err("progress belongs to another job".to_owned());
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
        if self.status == JobStatus::Complete && self.completed != job.batch.reviewed {
            return Err("complete progress has unreviewed units".to_owned());
        }
        Ok(())
    }
}

/// A job runner that can be reconstructed from durable progress.
#[derive(Clone, Debug)]
pub struct JobRunner {
    job: ConsolidationJob,
    progress: JobProgress,
}

impl JobRunner {
    /// Start a fresh run.
    pub fn start(job: ConsolidationJob) -> Result<Self, String> {
        if job.batch.reviewed.len() > job.limits.max_inputs {
            return Err("batch exceeds the input limit".to_owned());
        }
        let progress = JobProgress {
            job_id: job.job_id.clone(),
            completed: BTreeSet::new(),
            proposal_ids: BTreeSet::new(),
            elapsed_ms: 0,
            status: JobStatus::Running,
        };
        Ok(JobRunner { job, progress })
    }

    /// Resume from durable progress, refusing a different job identity.
    pub fn resume(job: ConsolidationJob, progress: JobProgress) -> Result<Self, String> {
        progress.validate(&job)?;
        if matches!(
            progress.status,
            JobStatus::Complete | JobStatus::Failed | JobStatus::Cancelled | JobStatus::Timeout
        ) && progress.completed != job.batch.reviewed
        {
            return Err("terminal progress is inconsistent with the batch".to_owned());
        }
        Ok(JobRunner { job, progress })
    }

    pub fn progress(&self) -> &JobProgress {
        &self.progress
    }

    pub fn job(&self) -> &ConsolidationJob {
        &self.job
    }

    /// Process one reviewed input and persist proposals/progress in memory.
    ///
    /// Repeating an already completed input is idempotent and returns no new
    /// proposals. Cancellation or a time limit prevents the current unit from
    /// being marked complete.
    pub fn process_summary(
        &mut self,
        input: &GeneratorInput,
        control: &JobControl,
        elapsed_ms: u64,
    ) -> Result<Vec<ConsolidationProposal>, String> {
        if control.is_cancelled() {
            self.progress.status = JobStatus::Cancelled;
            return Err("job cancelled".to_owned());
        }
        if !matches!(
            self.progress.status,
            JobStatus::Running | JobStatus::Partial
        ) {
            return Err("job is not running".to_owned());
        }
        if !self.job.batch.reviewed.contains(&input.key) {
            return Err("input is not in the reviewed batch".to_owned());
        }
        if self.progress.completed.contains(&input.key) {
            return Ok(Vec::new());
        }
        if self.progress.elapsed_ms.saturating_add(elapsed_ms) > self.job.limits.max_time_ms {
            self.progress.status = JobStatus::Timeout;
            return Err("job time limit exceeded".to_owned());
        }
        let proposals = DeterministicGenerator.generate(
            &self.job,
            &self.job.batch,
            std::slice::from_ref(input),
        )?;
        let mut new_proposals = Vec::new();
        for proposal in proposals {
            if self.progress.proposal_ids.contains(&proposal.proposal_id) {
                continue;
            }
            if self.progress.proposal_ids.len() >= self.job.limits.max_proposals {
                self.progress.status = JobStatus::Failed;
                return Err("job proposal limit exceeded".to_owned());
            }
            if proposal.disposition != ProposalDisposition::Pending {
                return Err("generated proposal must be pending".to_owned());
            }
            self.progress
                .proposal_ids
                .insert(proposal.proposal_id.clone());
            new_proposals.push(proposal);
        }
        self.progress.completed.insert(input.key);
        self.progress.elapsed_ms = self.progress.elapsed_ms.saturating_add(elapsed_ms);
        self.progress.status = if self.progress.completed == self.job.batch.reviewed {
            if matches!(self.job.batch.coverage, BatchCoverage::Complete) {
                JobStatus::Complete
            } else {
                JobStatus::Partial
            }
        } else {
            JobStatus::Partial
        };
        Ok(new_proposals)
    }
}

/// Retry identity parameters that must match before resuming stored work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobIdentity {
    pub idempotency_key: String,
    pub policy_version: String,
    pub extractor_revision: Option<String>,
}

impl ConsolidationJob {
    /// Identity used to classify retries.
    pub fn identity(&self) -> JobIdentity {
        JobIdentity {
            idempotency_key: self.idempotency_key.clone(),
            policy_version: self.policy_version.clone(),
            extractor_revision: self
                .extractor
                .as_ref()
                .map(|extractor| extractor.revision.clone()),
        }
    }
}

/// Whether a retry reuses a run or starts an identifiable new one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryClassification {
    Resume,
    NewRun,
}

/// Classify a retry. Changing policy or extractor revision creates a new run
/// even when the caller reuses the same idempotency key.
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

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProgressSnapshot {
    job_id: String,
    completed: Vec<ProgressKey>,
    proposal_ids: Vec<String>,
    elapsed_ms: u64,
    status: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProgressKey {
    record_id: String,
    revision_id: String,
}

impl JobStatus {
    fn name(self) -> &'static str {
        match self {
            JobStatus::Running => "running",
            JobStatus::Complete => "complete",
            JobStatus::Partial => "partial",
            JobStatus::Timeout => "timeout",
            JobStatus::Cancelled => "cancelled",
            JobStatus::Failed => "failed",
        }
    }

    fn parse(text: &str) -> Result<Self, String> {
        match text {
            "running" => Ok(JobStatus::Running),
            "complete" => Ok(JobStatus::Complete),
            "partial" => Ok(JobStatus::Partial),
            "timeout" => Ok(JobStatus::Timeout),
            "cancelled" => Ok(JobStatus::Cancelled),
            "failed" => Ok(JobStatus::Failed),
            _ => Err(format!("unknown job status {text:?}")),
        }
    }
}

impl JobProgress {
    /// Encode progress as a deterministic JSON snapshot.
    pub fn to_json(&self) -> Result<String, String> {
        let snapshot = ProgressSnapshot {
            job_id: self.job_id.clone(),
            completed: self
                .completed
                .iter()
                .map(|key| ProgressKey {
                    record_id: key.record_id.to_hex(),
                    revision_id: key.revision_id.to_hex(),
                })
                .collect(),
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
                Ok(InputKey {
                    record_id: mneme_core::RecordId::from_hex(&key.record_id)
                        .map_err(|error| error.to_owned())?,
                    revision_id: mneme_core::RevisionId::from_hex(&key.revision_id)
                        .map_err(|error| error.to_owned())?,
                })
            })
            .collect::<Result<BTreeSet<_>, String>>()?;
        Ok(JobProgress {
            job_id: snapshot.job_id,
            completed,
            proposal_ids: snapshot.proposal_ids.into_iter().collect(),
            elapsed_ms: snapshot.elapsed_ms,
            status: JobStatus::parse(&snapshot.status)?,
        })
    }
}

impl ProgressStore {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        ProgressStore { path: path.into() }
    }

    /// Persist progress atomically at the configured path.
    pub fn save(&self, progress: &JobProgress) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let rendered = progress.to_json()?;
        let temporary = self.path.with_extension("tmp");
        std::fs::write(&temporary, rendered).map_err(|error| error.to_string())?;
        std::fs::rename(&temporary, &self.path).map_err(|error| error.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture;
    use crate::generator::GeneratorInput;
    use mneme_core::SourceSpan;

    fn inputs() -> Vec<GeneratorInput> {
        let fixture = fixture().expect("fixture");
        let mut result = Vec::new();
        for unit in fixture.job.batch.units.clone() {
            result.push(GeneratorInput {
                key: unit.key,
                text: format!("source {}", unit.key.record_id.to_hex()),
                span: SourceSpan::new(0, 7).ok(),
            });
        }
        result
    }

    fn runner() -> JobRunner {
        JobRunner::start(fixture().expect("fixture").job).expect("start")
    }

    #[test]
    fn retry_resumes_without_duplicate_proposals() {
        let inputs = inputs();
        let control = JobControl::new();
        let mut runner = runner();
        let first = runner
            .process_summary(&inputs[0], &control, 10)
            .expect("first");
        assert_eq!(first.len(), 1);
        let progress = runner.progress().clone();
        let mut resumed = JobRunner::resume(runner.job().clone(), progress).expect("resume");
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
        assert_eq!(resumed.progress().status, JobStatus::Complete);
    }

    #[test]
    fn cancellation_keeps_completed_units_and_does_not_advance() {
        let inputs = inputs();
        let mut runner = runner();
        let control = JobControl::new();
        runner
            .process_summary(&inputs[0], &control, 10)
            .expect("first");
        control.cancel();
        let error = runner
            .process_summary(&inputs[1], &control, 10)
            .expect_err("cancelled");
        assert_eq!(error, "job cancelled");
        assert_eq!(runner.progress().status, JobStatus::Cancelled);
        assert_eq!(runner.progress().completed.len(), 1);
    }

    #[test]
    fn time_limit_blocks_completion() {
        let inputs = inputs();
        let runner = runner();
        let control = JobControl::new();
        let mut job = runner.job().clone();
        job.limits.max_time_ms = 5;
        let mut limited = JobRunner::start(job).expect("limited");
        let error = limited
            .process_summary(&inputs[0], &control, 6)
            .expect_err("timeout");
        assert_eq!(error, "job time limit exceeded");
        assert_eq!(limited.progress().status, JobStatus::Timeout);
        assert!(limited.progress().completed.is_empty());
    }

    #[test]
    fn policy_change_is_a_new_run_identity() {
        let job = fixture().expect("fixture").job;
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
        let mut runner = runner();
        runner
            .process_summary(&inputs[0], &control, 10)
            .expect("first");
        store.save(runner.progress()).expect("save");
        let loaded = store.load().expect("load").expect("progress");
        let job = runner.job().clone();
        let mut resumed = JobRunner::resume(job, loaded).expect("resume");
        resumed
            .process_summary(&inputs[1], &control, 10)
            .expect("second");
        assert_eq!(resumed.progress().status, JobStatus::Complete);
        store.save(resumed.progress()).expect("save complete");
        let complete = store.load().expect("load").expect("complete progress");
        assert_eq!(complete.status, JobStatus::Complete);
        assert_eq!(complete.completed.len(), 2);
    }
}
