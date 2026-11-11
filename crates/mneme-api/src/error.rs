//! Structured API failures. Transport adapters add framing only.
#![allow(path_segment_repetition)] // Octet structural exception: domain-qualified names and macro-only imports are intentional

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
#[derive(Debug, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct ApiError {
    pub code: ApiErrorCode,
    pub message: String,
    pub diagnostics: Vec<mneme_core::Diagnostic>,
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

    pub fn diagnostics(diagnostics: Vec<mneme_core::Diagnostic>) -> Self {
        ApiError {
            code: ApiErrorCode::InvalidInput,
            message: "field-addressed validation failed".to_owned(),
            diagnostics,
        }
    }

    pub fn from_diagnostic(diagnostic: mneme_core::Diagnostic) -> Self {
        Self::diagnostics(vec![diagnostic])
    }

    pub fn from_store(error: mneme_store::StoreError) -> Self {
        if let mneme_store::StoreError::Validation(diagnostics) = &error {
            return Self::diagnostics(diagnostics.clone());
        }
        let code = match &error {
            mneme_store::StoreError::StaleBase { .. }
            | mneme_store::StoreError::IdempotencyConflict { .. }
            | mneme_store::StoreError::BindingConflict(_) => ApiErrorCode::Conflict,
            mneme_store::StoreError::Validation(_)
            | mneme_store::StoreError::InvalidCommand(_)
            | mneme_store::StoreError::UnsupportedLayout(_)
            | mneme_store::StoreError::ScopeMismatch { .. }
            | mneme_store::StoreError::MissingSource { .. }
            | mneme_store::StoreError::SourceLengthMismatch { .. }
            | mneme_store::StoreError::PathEscapes(_)
            | mneme_store::StoreError::InvalidCandidate { .. }
            | mneme_store::StoreError::ValueOutOfRange(_) => ApiErrorCode::InvalidInput,
            mneme_store::StoreError::RetentionSuppressed { .. }
            | mneme_store::StoreError::MissingRetentionState { .. }
            | mneme_store::StoreError::MissingRetentionParticipant { .. } => ApiErrorCode::Denied,
            mneme_store::StoreError::BarrierAdvanced { .. } => ApiErrorCode::Conflict,
            mneme_store::StoreError::Io { .. }
            | mneme_store::StoreError::Sqlite(_)
            | mneme_store::StoreError::Integrity { .. }
            | mneme_store::StoreError::MissingBlob { .. }
            | mneme_store::StoreError::CorruptBlob { .. }
            | mneme_store::StoreError::InjectedFault(_)
            | mneme_store::StoreError::Random(_) => ApiErrorCode::Failed,
        };
        Self::new(code, error.to_string())
    }

    pub fn from_memory(error: mneme_memory::MemoryError) -> Self {
        match error {
            mneme_memory::MemoryError::Store(error) => Self::from_store(error),
            mneme_memory::MemoryError::Validation(diagnostics) => Self::diagnostics(diagnostics),
            mneme_memory::MemoryError::Missing { .. } => {
                Self::new(ApiErrorCode::Unavailable, "requested record is unavailable")
            }
            mneme_memory::MemoryError::Policy(message)
            | mneme_memory::MemoryError::Invalid(message) => {
                Self::new(ApiErrorCode::InvalidInput, message)
            }
            mneme_memory::MemoryError::InvalidRecord { .. } => {
                Self::new(ApiErrorCode::InvalidInput, error.to_string())
            }
            mneme_memory::MemoryError::Truncated => {
                Self::new(ApiErrorCode::Limit, "explanation is truncated")
            }
        }
    }

    pub fn from_recall(error: mneme_recall::RecallError) -> Self {
        match error {
            mneme_recall::RecallError::InvalidRequest(message) => {
                Self::new(ApiErrorCode::InvalidInput, message)
            }
            mneme_recall::RecallError::StaleRevision { requested, current } => Self::new(
                ApiErrorCode::Conflict,
                format!("requested revision {requested} is not current {current}"),
            ),
            mneme_recall::RecallError::BarrierAdvanced { pinned, current } => Self::new(
                ApiErrorCode::Conflict,
                format!("eligibility generation advanced from {pinned} to {current}"),
            ),
            mneme_recall::RecallError::ModeUnavailable { mode, reason } => Self::new(
                ApiErrorCode::Unavailable,
                format!("requested mode {mode} is unavailable: {reason}"),
            ),
            mneme_recall::RecallError::Store(error) => Self::from_store(error),
            mneme_recall::RecallError::Memory(error) => Self::from_memory(error),
            mneme_recall::RecallError::Datalog(error) => {
                Self::new(ApiErrorCode::Failed, error.to_string())
            }
        }
    }

    pub fn from_retention(error: mneme_retention::RetentionError) -> Self {
        match error {
            mneme_retention::RetentionError::Unauthorized => Self::denied(),
            mneme_retention::RetentionError::Conflict(message) => {
                Self::new(ApiErrorCode::Conflict, message)
            }
            mneme_retention::RetentionError::Invalid(message)
            | mneme_retention::RetentionError::Policy(message) => {
                Self::new(ApiErrorCode::InvalidInput, message)
            }
            mneme_retention::RetentionError::NotFound => {
                Self::new(ApiErrorCode::Unavailable, "retention target is unavailable")
            }
            mneme_retention::RetentionError::Cleanup(message) => {
                Self::new(ApiErrorCode::Limit, message)
            }
            mneme_retention::RetentionError::Store(error) => Self::from_store(error),
            mneme_retention::RetentionError::Memory(error) => Self::from_memory(error),
        }
    }
}

pub type ApiResult<T> = std::result::Result<T, ApiError>;
