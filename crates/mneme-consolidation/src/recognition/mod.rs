//! Durable recognition jobs over committed captures.
//!
//! A job recognizes one committed capture (a recording, scan, PDF or ink
//! document) unit by unit: pages, audio intervals or the whole capture. The
//! capture is committed before any recognizer exists, and a job can be queued
//! and run later. Each unit is reserved durably before its worker starts. The
//! worker receives a typed header and the capture's bytes on stdin, never a
//! path, and each unit whose answer validates is published as its own
//! recognition run once the capture is checked to be current, retained and
//! visible.
//!
//! Progress records only unit states, attempts, run identities and charged
//! resources. Recognized text exists only in published records, so forgetting
//! the capture reaches it through the normal retention rules, and no source
//! bytes are staged anywhere.

mod durable;
mod plan;
mod protocol;
mod publication;
mod session;

pub use durable::{Charges, JobState, Report, UnitReport, UnitState};
pub use plan::UnitSelector;
pub use session::{queue, retry, run, status};

/// The most units one job admits.
pub const MAX_RECOGNITION_UNITS: u32 = 10_000;
/// The most attempts one unit admits, retries included.
pub const MAX_UNIT_ATTEMPTS: u32 = 16;
/// The longest a single run may spend dispatching units.
pub const MAX_RUN_TIME: std::time::Duration = std::time::Duration::from_secs(86_400);

/// The recognizer a job runs and the identities each published run records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recognizer {
    pub worker: mneme_recall::inference::WorkerCommand,
    pub model: String,
    pub runtime: String,
    pub adapter: String,
    pub preprocessing: String,
    pub configuration: String,
}

/// How a capture is divided into units.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnitPlan {
    /// One unit per page of a page or ink capture.
    Pages,
    /// Consecutive intervals of an audio capture, each at most `ticks` long.
    AudioChunks { ticks: u64 },
    /// Consecutive intervals of an audio capture ending at `ends`: strictly
    /// increasing tick offsets, the last of them the capture's duration. A
    /// caller places them where the audio allows, such as in pauses, so no
    /// unit cuts a word another unit also hears.
    AudioSpans { ends: Vec<u64> },
    /// The whole capture as one unit.
    Whole,
}

/// Finite bounds for one job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_units: u32,
    pub max_attempts_per_unit: u32,
    /// Bounds on each unit's media, answer and wall time.
    pub unit: mneme_recall::inference::MediaInvocationLimits,
    /// Wall time one run may spend dispatching units; units still pending
    /// when it runs out wait for a later run.
    pub max_run_time: std::time::Duration,
}

/// One durable recognition job over a committed capture.
#[derive(Clone, Debug)]
pub struct Job {
    pub job_id: String,
    pub actor: String,
    pub scope: mneme_core::ScopeId,
    pub access: mneme_memory::Access,
    /// The committed capture, at the exact revision to recognize.
    pub media: mneme_core::SourcePin,
    pub recognizer: Recognizer,
    pub plan: UnitPlan,
    pub limits: Limits,
}

impl Job {
    /// Refuse a job outside its finite bounds before any effects.
    fn validate(&self) -> Result<(), Failure> {
        let limits = self.limits;
        let is_bounded = (1..=MAX_RECOGNITION_UNITS).contains(&limits.max_units)
            && (1..=MAX_UNIT_ATTEMPTS).contains(&limits.max_attempts_per_unit)
            && !limits.max_run_time.is_zero()
            && limits.max_run_time <= MAX_RUN_TIME;
        if !is_bounded {
            return Err(Failure::Invalid(
                "recognition job limits are outside their finite bounds".to_owned(),
            ));
        }
        limits.unit.validate().map_err(Failure::Invalid)?;
        if !self.access.allows(&self.scope) {
            return Err(Failure::Invalid(
                "the job's access does not include its scope".to_owned(),
            ));
        }
        let recognizer = &self.recognizer;
        let has_identities = [
            self.job_id.as_str(),
            self.actor.as_str(),
            recognizer.model.as_str(),
            recognizer.runtime.as_str(),
            recognizer.adapter.as_str(),
            recognizer.preprocessing.as_str(),
            recognizer.configuration.as_str(),
        ]
        .iter()
        .all(|identity| !identity.trim().is_empty());
        if !has_identities {
            return Err(Failure::Invalid(
                "a recognition job needs its identities".to_owned(),
            ));
        }
        recognizer.worker.validate().map_err(Failure::Invalid)
    }
}

/// Why a job call did nothing or stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The job definition, its capture or its saved progress is not admissible.
    Invalid(String),
    /// Another runner owns the job.
    Busy(String),
    /// A workspace read or write failed.
    Store(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::Invalid(detail) | Failure::Busy(detail) | Failure::Store(detail) => {
                formatter.write_str(detail)
            }
        }
    }
}

impl std::error::Error for Failure {}
