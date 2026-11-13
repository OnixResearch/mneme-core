//! Structured API failures. Transport adapters add framing only.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// The public message for a record id that does not resolve for this caller.
///
/// A record held in a scope the caller is not authorized for produces exactly
/// this answer, so a status code or message never confirms that a foreign
/// record exists.
pub const UNAVAILABLE_RECORD: &str = "requested record is unavailable";

/// The public message for a target covered by an authorized forget.
pub const FORGOTTEN_TARGET: &str = "target was explicitly forgotten by retention policy";

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
    /// Stable lower-case name used in transport documents.
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
///
/// Messages are fixed per failure class. A raw library message can name a
/// record, a revision, a scope or a host path from a scope the caller is not
/// authorized for, so those stay inside the library and only the diagnostics of
/// a caller-supplied document are echoed.
#[derive(Debug, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct ApiError {
    pub code: ApiErrorCode,
    pub message: String,
    pub diagnostics: Vec<mneme_core::Diagnostic>,
}

impl ApiError {
    /// Construct one error with a fixed public message.
    pub fn new(code: ApiErrorCode, message: impl Into<String>) -> Self {
        ApiError {
            code,
            message: message.into(),
            diagnostics: Vec::new(),
        }
    }

    /// A malformed or unsupported request.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ApiErrorCode::InvalidInput, message)
    }

    /// The session is not authorized for the requested scope.
    pub fn denied() -> Self {
        Self::new(
            ApiErrorCode::Denied,
            "session is not authorized for the requested scope",
        )
    }

    /// A record id that does not resolve for this caller.
    pub fn missing() -> Self {
        Self::new(ApiErrorCode::Unavailable, UNAVAILABLE_RECORD)
    }

    /// A target covered by an authorized forget.
    pub fn forgotten() -> Self {
        Self::new(ApiErrorCode::Unavailable, FORGOTTEN_TARGET)
    }

    /// Field-addressed diagnostics for a caller-supplied document.
    ///
    /// An unsupported schema version, value kind or tag is a compatibility
    /// failure, not a malformed request: it receives its own error class so a
    /// client can tell an incompatible encoder from a wrong document.
    pub fn diagnostics(diagnostics: Vec<mneme_core::Diagnostic>) -> Self {
        if diagnostics.iter().any(unsupported) {
            return Self::new(
                ApiErrorCode::UnsupportedVersion,
                "request uses an unsupported schema version, value kind or tag",
            )
            .with_diagnostics(diagnostics);
        }
        ApiError::new(
            ApiErrorCode::InvalidInput,
            "field-addressed validation failed",
        )
        .with_diagnostics(diagnostics)
    }

    /// Attach the diagnostics one refusal carries.
    pub(crate) fn with_diagnostic(mut self, diagnostic: mneme_core::Diagnostic) -> Self {
        self.diagnostics = vec![diagnostic];
        self
    }

    pub(crate) fn with_diagnostics(mut self, diagnostics: Vec<mneme_core::Diagnostic>) -> Self {
        self.diagnostics = diagnostics;
        self
    }

    /// A library refusal reported as text only.
    ///
    /// The adapter cannot see which record or member the library validator
    /// rejected, so the diagnostic names the command payload root and the
    /// refusal class; a finer address would be invented.
    fn refused(code: ApiErrorCode, message: impl Into<String>) -> Self {
        let message = message.into();
        ApiError::new(code, message.clone()).with_diagnostic(mneme_core::Diagnostic::new(
            mneme_core::Stage::Domain,
            mneme_core::ErrorCode::TypeMismatch,
            payload_path(),
            message,
        ))
    }

    /// One advisory diagnostic.
    pub fn from_diagnostic(diagnostic: mneme_core::Diagnostic) -> Self {
        Self::diagnostics(vec![diagnostic])
    }

    /// A workspace failure.
    pub fn from_store(error: mneme_store::Failure) -> Self {
        match error {
            mneme_store::Failure::Validation(diagnostics) => Self::diagnostics(diagnostics),
            mneme_store::Failure::StaleBase { .. } => {
                Self::new(ApiErrorCode::Conflict, "base revision is not current")
            }
            mneme_store::Failure::BarrierAdvanced { .. } => Self::new(
                ApiErrorCode::Conflict,
                "workspace eligibility barrier advanced during the request",
            ),
            mneme_store::Failure::IdempotencyConflict { .. } => Self::new(
                ApiErrorCode::Conflict,
                "idempotency key was reused with different command content",
            ),
            mneme_store::Failure::BindingConflict(_) => {
                Self::new(ApiErrorCode::Conflict, "source binding conflict")
            }
            mneme_store::Failure::RetentionSuppressed { .. }
            | mneme_store::Failure::MissingRetentionState { .. }
            | mneme_store::Failure::MissingRetentionParticipant { .. } => Self::new(
                ApiErrorCode::Denied,
                "request is blocked by current retention state",
            ),
            mneme_store::Failure::InvalidCommand(_)
            | mneme_store::Failure::ScopeMismatch { .. }
            | mneme_store::Failure::MissingSource { .. }
            | mneme_store::Failure::SourceLengthMismatch { .. }
            | mneme_store::Failure::PathEscapes(_)
            | mneme_store::Failure::InvalidCandidate { .. }
            | mneme_store::Failure::ValueOutOfRange(_) => Self::refused(
                ApiErrorCode::InvalidInput,
                "command is not admissible in this workspace",
            ),
            mneme_store::Failure::UnsupportedLayout(_) => {
                Self::new(ApiErrorCode::Failed, "workspace layout is not supported")
            }
            mneme_store::Failure::Io { .. } => {
                Self::new(ApiErrorCode::Failed, "workspace I/O failure")
            }
            mneme_store::Failure::Sqlite(_) => {
                Self::new(ApiErrorCode::Failed, "workspace storage failure")
            }
            mneme_store::Failure::Integrity { .. } => {
                Self::new(ApiErrorCode::Failed, "workspace integrity failure")
            }
            mneme_store::Failure::MissingBlob { .. } | mneme_store::Failure::CorruptBlob { .. } => {
                Self::new(ApiErrorCode::Failed, "workspace payload is unavailable")
            }
            mneme_store::Failure::InjectedFault(_) | mneme_store::Failure::Random(_) => {
                Self::new(ApiErrorCode::Failed, "workspace operation failed")
            }
        }
    }

    /// A memory-layer failure.
    pub fn from_memory(error: mneme_memory::EvidenceError) -> Self {
        match error {
            mneme_memory::EvidenceError::Store(error) => Self::from_store(error),
            mneme_memory::EvidenceError::Validation(diagnostics) => Self::diagnostics(diagnostics),
            mneme_memory::EvidenceError::Missing { .. } => Self::missing(),
            mneme_memory::EvidenceError::Policy(message)
            | mneme_memory::EvidenceError::Invalid(message) => {
                Self::refused(ApiErrorCode::InvalidInput, message)
            }
            mneme_memory::EvidenceError::InvalidRecord { kind, message, .. } => Self::refused(
                ApiErrorCode::InvalidInput,
                format!("{kind} payload is not valid: {message}"),
            ),
            mneme_memory::EvidenceError::Truncated => Self::new(
                ApiErrorCode::Limit,
                "the requested result exceeds its configured bound",
            ),
        }
    }

    /// A recall failure.
    pub fn from_recall(error: mneme_recall::QueryError) -> Self {
        match error {
            mneme_recall::QueryError::InvalidRequest(message) => {
                Self::refused(ApiErrorCode::InvalidInput, message)
            }
            mneme_recall::QueryError::StaleRevision { .. } => {
                Self::new(ApiErrorCode::Conflict, "requested revision is not current")
            }
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
            mneme_recall::QueryError::Datalog(error) => Self::from_datalog(error),
        }
    }

    /// A structured evaluation failure.
    pub fn from_datalog(error: mneme_datalog::Error) -> Self {
        match error {
            mneme_datalog::Error::InvalidBundle(diagnostics) => {
                let reasons = diagnostics
                    .iter()
                    .map(|diagnostic| diagnostic.message.clone())
                    .collect::<Vec<_>>()
                    .join("; ");
                let message = format!("rule bundle is invalid: {reasons}");
                if diagnostics.is_empty() {
                    Self::refused(ApiErrorCode::InvalidInput, message)
                } else {
                    Self::new(ApiErrorCode::InvalidInput, message).with_diagnostics(
                        diagnostics
                            .iter()
                            .map(|diagnostic| {
                                mneme_core::Diagnostic::new(
                                    mneme_core::Stage::Domain,
                                    mneme_core::ErrorCode::TypeMismatch,
                                    payload_path().field("structured"),
                                    format!("{}: {}", diagnostic.code, diagnostic.message),
                                )
                            })
                            .collect(),
                    )
                }
            }
            mneme_datalog::Error::UnknownPredicate(predicate) => Self::refused(
                ApiErrorCode::InvalidInput,
                format!("unknown relation {predicate}"),
            ),
            mneme_datalog::Error::InvalidQuery(reason) => Self::refused(
                ApiErrorCode::InvalidInput,
                format!("query is invalid: {reason}"),
            ),
            mneme_datalog::Error::Stale { .. } => {
                Self::new(ApiErrorCode::Conflict, "projection is stale")
            }
            mneme_datalog::Error::Cancelled => Self::new(
                ApiErrorCode::Cancelled,
                "structured evaluation was cancelled",
            ),
            mneme_datalog::Error::Store(error) => Self::from_store(error),
            mneme_datalog::Error::Engine(error) => Self::from_memory(error),
            mneme_datalog::Error::MissingBuild(_) | mneme_datalog::Error::Failed(_) => {
                Self::new(ApiErrorCode::Failed, "structured evaluation failed")
            }
        }
    }

    /// A retention failure.
    pub fn from_retention(error: mneme_retention::PolicyError) -> Self {
        match error {
            mneme_retention::PolicyError::Unauthorized => Self::denied(),
            mneme_retention::PolicyError::Conflict(message)
            | mneme_retention::PolicyError::Policy(message) => {
                Self::new(ApiErrorCode::Conflict, message)
            }
            mneme_retention::PolicyError::Invalid(message) => {
                Self::refused(ApiErrorCode::InvalidInput, message)
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

/// The command payload root: the finest address a library refusal exposes.
fn payload_path() -> mneme_core::Path {
    mneme_core::Path::root().field("payload")
}

/// Whether one diagnostic reports a compatibility failure rather than a
/// malformed request.
fn unsupported(diagnostic: &mneme_core::Diagnostic) -> bool {
    diagnostic.is(mneme_core::ErrorCode::UnsupportedSchemaVersion)
        || diagnostic.is(mneme_core::ErrorCode::UnsupportedValueKind)
        || diagnostic.is(mneme_core::ErrorCode::UnsupportedTag)
        || diagnostic.is(mneme_core::ErrorCode::UnsupportedExtension)
}

/// A result carrying an API failure.
pub type CallResult<T> = std::result::Result<T, ApiError>;
