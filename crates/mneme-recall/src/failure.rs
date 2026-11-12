//! Recall failures that prevent constructing a qualified response.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// A recall infrastructure or request failure.
#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("invalid recall request: {0}")]
    InvalidRequest(String),
    #[error("requested revision {requested} is not the current revision {current}")]
    StaleRevision {
        requested: mneme_core::WorkspaceRevisionId,
        current: mneme_core::WorkspaceRevisionId,
    },
    #[error("retrieval eligibility barrier advanced from {pinned} to {current}")]
    BarrierAdvanced { pinned: u64, current: u64 },
    #[error("requested mode {mode} is unavailable and fallback is disabled: {reason}")]
    ModeUnavailable { mode: String, reason: String },
    #[error("workspace: {0}")]
    Store(#[from] mneme_store::Failure),
    #[error("memory: {0}")]
    Engine(#[from] mneme_memory::EvidenceError),
    #[error("datalog: {0}")]
    Datalog(#[from] mneme_datalog::Error),
}

/// Recall result type.
pub type Result<T> = std::result::Result<T, QueryError>;
