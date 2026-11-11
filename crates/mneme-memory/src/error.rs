//! Evidence-policy failures.

/// A memory-layer failure.
#[derive(Debug, thiserror::Error)]
pub enum MemoryError {
    #[error(transparent)]
    Store(#[from] mneme_store::StoreError),

    #[error("record {record} has an invalid {kind} payload: {message}")]
    InvalidRecord {
        record: mneme_core::RecordId,
        kind: &'static str,
        message: String,
    },

    #[error("record {record} is missing")]
    Missing { record: mneme_core::RecordId },

    #[error("policy refusal: {0}")]
    Policy(String),

    #[error("evidence validation failed")]
    Validation(Vec<mneme_core::Diagnostic>),

    #[error("field-addressed validation failed: {0}")]
    Invalid(String),

    #[error("explanation is truncated at the configured bound")]
    Truncated,
}

impl MemoryError {
    /// A typed payload failure.
    pub fn invalid(
        record: mneme_core::RecordId,
        kind: &'static str,
        message: impl Into<String>,
    ) -> Self {
        MemoryError::InvalidRecord {
            record,
            kind,
            message: message.into(),
        }
    }

    /// A policy refusal.
    pub fn policy(message: impl Into<String>) -> Self {
        MemoryError::Policy(message.into())
    }
}

/// A memory result.
pub type Result<T, E = MemoryError> = std::result::Result<T, E>;
