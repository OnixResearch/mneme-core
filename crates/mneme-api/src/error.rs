//! Structured API failures. Transport adapters add framing only.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

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

    pub fn from_store(error: mneme_store::Failure) -> Self {
        if let mneme_store::Failure::Validation(diagnostics) = &error {
            return Self::diagnostics(diagnostics.clone());
        }
        let code = match &error {
            mneme_store::Failure::StaleBase { .. }
            | mneme_store::Failure::IdempotencyConflict { .. }
            | mneme_store::Failure::BindingConflict(_) => ApiErrorCode::Conflict,
            mneme_store::Failure::Validation(_)
            | mneme_store::Failure::InvalidCommand(_)
            | mneme_store::Failure::UnsupportedLayout(_)
            | mneme_store::Failure::ScopeMismatch { .. }
            | mneme_store::Failure::MissingSource { .. }
            | mneme_store::Failure::SourceLengthMismatch { .. }
            | mneme_store::Failure::PathEscapes(_)
            | mneme_store::Failure::InvalidCandidate { .. }
            | mneme_store::Failure::ValueOutOfRange(_) => ApiErrorCode::InvalidInput,
            mneme_store::Failure::RetentionSuppressed { .. }
            | mneme_store::Failure::MissingRetentionState { .. }
            | mneme_store::Failure::MissingRetentionParticipant { .. } => ApiErrorCode::Denied,
            mneme_store::Failure::BarrierAdvanced { .. } => ApiErrorCode::Conflict,
            mneme_store::Failure::Io { .. }
            | mneme_store::Failure::Sqlite(_)
            | mneme_store::Failure::Integrity { .. }
            | mneme_store::Failure::MissingBlob { .. }
            | mneme_store::Failure::CorruptBlob { .. }
            | mneme_store::Failure::InjectedFault(_)
            | mneme_store::Failure::Random(_) => ApiErrorCode::Failed,
        };
        Self::new(code, error.to_string())
    }

    pub fn from_memory(error: mneme_memory::EvidenceError) -> Self {
        match error {
            mneme_memory::EvidenceError::Store(error) => Self::from_store(error),
            mneme_memory::EvidenceError::Validation(diagnostics) => Self::diagnostics(diagnostics),
            mneme_memory::EvidenceError::Missing { .. } => {
                Self::new(ApiErrorCode::Unavailable, "requested record is unavailable")
            }
            mneme_memory::EvidenceError::Policy(message)
            | mneme_memory::EvidenceError::Invalid(message) => {
                Self::new(ApiErrorCode::InvalidInput, message)
            }
            mneme_memory::EvidenceError::InvalidRecord { .. } => {
                Self::new(ApiErrorCode::InvalidInput, error.to_string())
            }
            mneme_memory::EvidenceError::Truncated => {
                Self::new(ApiErrorCode::Limit, "explanation is truncated")
            }
        }
    }

    pub fn from_recall(error: mneme_recall::QueryError) -> Self {
        match error {
            mneme_recall::QueryError::InvalidRequest(message) => {
                Self::new(ApiErrorCode::InvalidInput, message)
            }
            mneme_recall::QueryError::StaleRevision { requested, current } => Self::new(
                ApiErrorCode::Conflict,
                format!("requested revision {requested} is not current {current}"),
            ),
            mneme_recall::QueryError::BarrierAdvanced { pinned, current } => Self::new(
                ApiErrorCode::Conflict,
                format!("eligibility generation advanced from {pinned} to {current}"),
            ),
            mneme_recall::QueryError::ModeUnavailable { mode, reason } => Self::new(
                ApiErrorCode::Unavailable,
                format!("requested mode {mode} is unavailable: {reason}"),
            ),
            mneme_recall::QueryError::Store(error) => Self::from_store(error),
            mneme_recall::QueryError::Engine(error) => Self::from_memory(error),
            mneme_recall::QueryError::Datalog(error) => {
                Self::new(ApiErrorCode::Failed, error.to_string())
            }
        }
    }

    pub fn from_retention(error: mneme_retention::PolicyError) -> Self {
        match error {
            mneme_retention::PolicyError::Unauthorized => Self::denied(),
            mneme_retention::PolicyError::Conflict(message) => {
                Self::new(ApiErrorCode::Conflict, message)
            }
            mneme_retention::PolicyError::Invalid(message)
            | mneme_retention::PolicyError::Policy(message) => {
                Self::new(ApiErrorCode::InvalidInput, message)
            }
            mneme_retention::PolicyError::NotFound => {
                Self::new(ApiErrorCode::Unavailable, "retention target is unavailable")
            }
            mneme_retention::PolicyError::Cleanup(message) => {
                Self::new(ApiErrorCode::Limit, message)
            }
            mneme_retention::PolicyError::Store(error) => Self::from_store(error),
            mneme_retention::PolicyError::Engine(error) => Self::from_memory(error),
        }
    }
}

pub type CallResult<T> = std::result::Result<T, ApiError>;
