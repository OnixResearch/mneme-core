//! Structured API failures. Transport adapters add framing only.

use mneme_core::Diagnostic;
use mneme_memory::MemoryError;
use mneme_recall::RecallError;
use mneme_retention::RetentionError;
use mneme_store::StoreError;
use thiserror::Error;

/// Stable API error classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiErrorCode {
    InvalidInput,
    UnsupportedVersion,
    Denied,
    Conflict,
    Unavailable,
    Limit,
    Cancelled,
    Failed,
}

impl ApiErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            ApiErrorCode::InvalidInput => "invalid-input",
            ApiErrorCode::UnsupportedVersion => "unsupported-version",
            ApiErrorCode::Denied => "denied",
            ApiErrorCode::Conflict => "conflict",
            ApiErrorCode::Unavailable => "unavailable",
            ApiErrorCode::Limit => "limit",
            ApiErrorCode::Cancelled => "cancelled",
            ApiErrorCode::Failed => "failed",
        }
    }
}

/// One API error with a safe public detail and optional field diagnostics.
#[derive(Debug, Error)]
#[error("{code:?}: {message}")]
pub struct ApiError {
    pub code: ApiErrorCode,
    pub message: String,
    pub diagnostics: Vec<Diagnostic>,
}

impl ApiError {
    pub fn new(code: ApiErrorCode, message: impl Into<String>) -> Self {
        ApiError {
            code,
            message: message.into(),
            diagnostics: Vec::new(),
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ApiErrorCode::InvalidInput, message)
    }

    pub fn denied() -> Self {
        Self::new(
            ApiErrorCode::Denied,
            "session is not authorized for the requested scope",
        )
    }

    pub fn diagnostics(diagnostics: Vec<Diagnostic>) -> Self {
        ApiError {
            code: ApiErrorCode::InvalidInput,
            message: "field-addressed validation failed".to_owned(),
            diagnostics,
        }
    }

    pub fn from_diagnostic(diagnostic: Diagnostic) -> Self {
        Self::diagnostics(vec![diagnostic])
    }

    pub fn from_store(error: StoreError) -> Self {
        if let StoreError::Validation(diagnostics) = &error {
            return Self::diagnostics(diagnostics.clone());
        }
        let code = match &error {
            StoreError::StaleBase { .. }
            | StoreError::IdempotencyConflict { .. }
            | StoreError::BindingConflict(_) => ApiErrorCode::Conflict,
            StoreError::Validation(_)
            | StoreError::InvalidCommand(_)
            | StoreError::UnsupportedLayout(_)
            | StoreError::ScopeMismatch { .. }
            | StoreError::MissingSource { .. }
            | StoreError::SourceLengthMismatch { .. }
            | StoreError::PathEscapes(_)
            | StoreError::InvalidCandidate { .. }
            | StoreError::ValueOutOfRange(_) => ApiErrorCode::InvalidInput,
            StoreError::RetentionSuppressed { .. }
            | StoreError::MissingRetentionState { .. }
            | StoreError::MissingRetentionParticipant { .. } => ApiErrorCode::Denied,
            StoreError::BarrierAdvanced { .. } => ApiErrorCode::Conflict,
            StoreError::Io { .. }
            | StoreError::Sqlite(_)
            | StoreError::Integrity { .. }
            | StoreError::MissingBlob { .. }
            | StoreError::CorruptBlob { .. }
            | StoreError::InjectedFault(_)
            | StoreError::Random(_) => ApiErrorCode::Failed,
        };
        Self::new(code, error.to_string())
    }

    pub fn from_memory(error: MemoryError) -> Self {
        match error {
            MemoryError::Store(error) => Self::from_store(error),
            MemoryError::Validation(diagnostics) => Self::diagnostics(diagnostics),
            MemoryError::Missing { .. } => {
                Self::new(ApiErrorCode::Unavailable, "requested record is unavailable")
            }
            MemoryError::Policy(message) | MemoryError::Invalid(message) => {
                Self::new(ApiErrorCode::InvalidInput, message)
            }
            MemoryError::InvalidRecord { .. } => {
                Self::new(ApiErrorCode::InvalidInput, error.to_string())
            }
            MemoryError::Truncated => Self::new(ApiErrorCode::Limit, "explanation is truncated"),
        }
    }

    pub fn from_recall(error: RecallError) -> Self {
        match error {
            RecallError::InvalidRequest(message) => Self::new(ApiErrorCode::InvalidInput, message),
            RecallError::StaleRevision { requested, current } => Self::new(
                ApiErrorCode::Conflict,
                format!("requested revision {requested} is not current {current}"),
            ),
            RecallError::BarrierAdvanced { pinned, current } => Self::new(
                ApiErrorCode::Conflict,
                format!("eligibility generation advanced from {pinned} to {current}"),
            ),
            RecallError::ModeUnavailable { mode, reason } => Self::new(
                ApiErrorCode::Unavailable,
                format!("requested mode {mode} is unavailable: {reason}"),
            ),
            RecallError::Store(error) => Self::from_store(error),
            RecallError::Memory(error) => Self::from_memory(error),
            RecallError::Datalog(error) => Self::new(ApiErrorCode::Failed, error.to_string()),
        }
    }

    pub fn from_retention(error: RetentionError) -> Self {
        match error {
            RetentionError::Unauthorized => Self::denied(),
            RetentionError::Conflict(message) => Self::new(ApiErrorCode::Conflict, message),
            RetentionError::Invalid(message) | RetentionError::Policy(message) => {
                Self::new(ApiErrorCode::InvalidInput, message)
            }
            RetentionError::NotFound => {
                Self::new(ApiErrorCode::Unavailable, "retention target is unavailable")
            }
            RetentionError::Cleanup(message) => Self::new(ApiErrorCode::Limit, message),
            RetentionError::Store(error) => Self::from_store(error),
            RetentionError::Memory(error) => Self::from_memory(error),
        }
    }
}

pub type ApiResult<T> = std::result::Result<T, ApiError>;
