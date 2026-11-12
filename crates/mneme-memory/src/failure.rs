//! Evidence-policy failures.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// A memory-layer failure.
#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error(transparent)]
    Store(#[from] mneme_store::Failure),

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

impl EvidenceError {
    /// A typed payload failure.
    pub fn invalid(
        record: mneme_core::RecordId,
        kind: &'static str,
        message: impl Into<String>,
    ) -> Self {
        EvidenceError::InvalidRecord {
            record,
            kind,
            message: message.into(),
        }
    }

    /// A policy refusal.
    pub fn policy(message: impl Into<String>) -> Self {
        EvidenceError::Policy(message.into())
    }
}

/// A memory result.
pub type Result<T, E = EvidenceError> = std::result::Result<T, E>;
