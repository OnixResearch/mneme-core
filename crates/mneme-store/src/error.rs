//! Store-level failures.
//!
//! Integrity failures are distinct from policy unavailability: a missing or
//! hash-invalid committed payload is an error, never an empty document. Stale
//! bases, idempotency conflicts, validation refusals, publication divergence,
//! and injected faults are separate variants so callers can react truthfully.

use std::path::PathBuf;

use mneme_core::{Diagnostic, WorkspaceRevisionId};

use crate::faults::FaultPoint;

/// A workspace operation failure.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("unsupported workspace layout: {0}")]
    UnsupportedLayout(String),

    #[error("invalid command: {0}")]
    InvalidCommand(String),

    #[error("stale base revision: requested {base}, current {current}")]
    StaleBase {
        base: WorkspaceRevisionId,
        current: WorkspaceRevisionId,
    },

    #[error("idempotency key {key:?} was reused with different command content")]
    IdempotencyConflict { key: String },

    #[error("record validation failed")]
    Validation(Vec<Diagnostic>),

    #[error("integrity failure for revision {revision}: {reason}")]
    Integrity {
        revision: WorkspaceRevisionId,
        reason: String,
    },

    #[error("missing committed blob {digest}")]
    MissingBlob { digest: String },

    #[error("corrupt committed blob {digest}: {reason}")]
    CorruptBlob { digest: String, reason: String },

    #[error("record scope {record_scope} does not match command scope {command_scope}")]
    ScopeMismatch {
        record_scope: String,
        command_scope: String,
    },

    #[error("retained source bytes for {digest} were not supplied")]
    MissingSource { digest: String },

    #[error("source byte length mismatch for {digest}: declared {declared}, supplied {supplied}")]
    SourceLengthMismatch {
        digest: String,
        declared: u64,
        supplied: u64,
    },

    #[error("source binding conflict: {0}")]
    BindingConflict(String),

    #[error("working-file path {0:?} escapes the workspace working directory")]
    PathEscapes(String),

    #[error("import candidate {path:?} does not match its committed record or current bytes")]
    InvalidCandidate { path: String },

    #[error("fault injected at {0:?}")]
    InjectedFault(FaultPoint),

    #[error("eligibility generation advanced from {pinned} to {current}")]
    BarrierAdvanced { pinned: u64, current: u64 },

    #[error("system randomness unavailable: {0}")]
    Random(String),
}

impl StoreError {
    /// Wrap an I/O error with its path.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        StoreError::Io {
            path: path.into(),
            source,
        }
    }
}

/// A store result.
pub type Result<T, E = StoreError> = std::result::Result<T, E>;
