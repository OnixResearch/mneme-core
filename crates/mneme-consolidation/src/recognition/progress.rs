//! A job's durable, content-free progress and the reports derived from it.

/// The progress layout this code reads and writes.
const PROGRESS_VERSION: u32 = 1;

/// Where one unit stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnitState {
    /// Not yet dispatched in this attempt.
    Pending,
    /// Reserved and handed to a worker; its outcome is not yet recorded.
    Dispatched,
    /// Its answer was published as a recognition run.
    Published,
    /// A runner stopped after dispatching it and before recording an outcome.
    /// It is never dispatched again automatically.
    Uncertain,
    /// The worker exceeded the unit's wall time and was reaped.
    Timeout,
    /// The run was cancelled while the unit's worker ran.
    Cancelled,
    /// The recognizer cannot recognize this unit, or the capture exceeds the
    /// unit's media bound: a capability outcome, not an error.
    Unsupported,
    /// The answer was malformed or oversized, or its alignment did not validate.
    Rejected,
    /// The worker failed or could not be started.
    Failed,
    /// The capture was forgotten, pruned, revised or put out of reach before
    /// the unit could be published.
    Suppressed,
}

impl UnitState {
    /// Whether an explicit retry may dispatch the unit again.
    pub(super) const fn is_retryable(self) -> bool {
        match self {
            UnitState::Uncertain
            | UnitState::Timeout
            | UnitState::Cancelled
            | UnitState::Rejected
            | UnitState::Failed => true,
            UnitState::Pending
            | UnitState::Dispatched
            | UnitState::Published
            | UnitState::Unsupported
            | UnitState::Suppressed => false,
        }
    }
}

/// Resources a job has been charged, failed and interrupted work included.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Charges {
    pub invocations: u64,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub elapsed_ms: u64,
}

/// One unit's durable record: no recognized text, only where it stands.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(super) struct UnitProgress {
    pub selector: super::UnitSelector,
    pub state: UnitState,
    pub attempts: u32,
    /// The published run, as lowercase hex.
    pub run: Option<String>,
    /// A content-free reason for a state other than published.
    pub detail: Option<String>,
}

/// A job's durable progress.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(super) struct Progress {
    pub version: u32,
    /// The job definition this progress belongs to.
    pub definition: String,
    /// The capture's content digest when the job was planned.
    pub media_digest: String,
    pub units: Vec<UnitProgress>,
    pub charged: Charges,
}

impl Progress {
    pub(super) fn new(
        definition: String,
        media_digest: mneme_core::ContentDigest,
        selectors: Vec<super::UnitSelector>,
    ) -> Self {
        Progress {
            version: PROGRESS_VERSION,
            definition,
            media_digest: media_digest.to_hex(),
            units: selectors
                .into_iter()
                .map(|selector| UnitProgress {
                    selector,
                    state: UnitState::Pending,
                    attempts: 0,
                    run: None,
                    detail: None,
                })
                .collect(),
            charged: Charges::default(),
        }
    }

    /// Parse saved progress, refusing another layout or an unbounded unit list.
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, super::Failure> {
        let progress: Progress = serde_json::from_slice(bytes)
            .map_err(|_| super::Failure::Invalid("saved job progress is malformed".to_owned()))?;
        let is_bounded = u32::try_from(progress.units.len())
            .is_ok_and(|count| (1..=super::MAX_RECOGNITION_UNITS).contains(&count));
        if progress.version != PROGRESS_VERSION || !is_bounded {
            return Err(super::Failure::Invalid(
                "saved job progress has an unsupported layout".to_owned(),
            ));
        }
        Ok(progress)
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, super::Failure> {
        serde_json::to_vec(self).map_err(|error| super::Failure::Store(error.to_string()))
    }

    /// Settle every still-pending unit with `state` and a reason.
    pub(super) fn settle_pending(&mut self, state: UnitState, detail: &str) {
        for unit in &mut self.units {
            if unit.state == UnitState::Pending {
                unit.state = state;
                unit.detail = Some(detail.to_owned());
            }
        }
    }

    pub(super) fn report(&self) -> RecognitionReport {
        let units: Vec<UnitReport> = self.units.iter().map(UnitReport::of).collect();
        let published = units
            .iter()
            .filter(|unit| unit.state == UnitState::Published)
            .count();
        let total = units.len();
        let has = |state: UnitState| units.iter().any(|unit| unit.state == state);
        let state = if has(UnitState::Cancelled) {
            JobState::Cancelled
        } else if has(UnitState::Pending) || has(UnitState::Dispatched) {
            JobState::Queued
        } else if published == total {
            JobState::Complete
        } else if published > 0 {
            JobState::Partial
        } else {
            JobState::Failed
        };
        RecognitionReport {
            state,
            published,
            total,
            units,
            charged: self.charged,
        }
    }
}

/// Where a whole job stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobState {
    /// Units remain to dispatch, now or in a later run.
    Queued,
    /// Every unit was published.
    Complete,
    /// Some units were published and the rest ended otherwise; recognition
    /// is not complete.
    Partial,
    /// No unit was published.
    Failed,
    /// A run was cancelled; retrying the cancelled units resumes the job.
    Cancelled,
}

/// One unit as a report shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitReport {
    pub selector: super::UnitSelector,
    pub state: UnitState,
    pub attempts: u32,
    pub run: Option<mneme_core::RecordId>,
    pub detail: Option<String>,
}

impl UnitReport {
    fn of(unit: &UnitProgress) -> Self {
        UnitReport {
            selector: unit.selector,
            state: unit.state,
            attempts: unit.attempts,
            run: unit
                .run
                .as_deref()
                .and_then(|run| mneme_core::RecordId::from_hex(run).ok()),
            detail: unit.detail.clone(),
        }
    }
}

/// A job's typed progress: its state, its coverage, each unit, and what it
/// has been charged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecognitionReport {
    pub state: JobState,
    /// Units published, out of `total`.
    pub published: usize,
    pub total: usize,
    pub units: Vec<UnitReport>,
    pub charged: Charges,
}
