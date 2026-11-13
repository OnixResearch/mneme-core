//! Versioned tagged-JSON command envelopes and local session authorization.
//!
//! Every member of an envelope and of an operation payload is declared here.
//! A member the operation does not define, or an optional member of the wrong
//! type, is refused with a field-addressed diagnostic instead of being ignored:
//! a request must never execute with semantics its author did not ask for.

use serde::Deserialize;

/// Command format and version.
pub const COMMAND_FORMAT: &str = "mneme.agent-command";
pub const COMMAND_VERSION: u64 = 1;
/// Result format and version.
pub const RESULT_FORMAT: &str = "mneme.agent-result";
pub const RESULT_VERSION: u64 = 1;
/// Rule bundle schema version accepted in a structured recall request.
pub const RULE_BUNDLE_SCHEMA_VERSION: u32 = 3;

/// A local principal and its explicit scope allowlist.
#[derive(Clone, Debug, Deserialize)]
pub struct SessionConfig {
    pub principal: String,
    pub workspace_root: std::path::PathBuf,
    pub scopes: Vec<String>,
}

/// A loaded session. Scope labels are matched against this allowlist.
#[derive(Clone, Debug)]
pub struct LocalSession {
    pub principal: String,
    pub workspace_root: std::path::PathBuf,
    scopes: std::collections::BTreeSet<mneme_core::ScopeId>,
}

impl LocalSession {
    /// Load and validate one session document.
    pub fn load(path: &std::path::Path) -> crate::error::CallResult<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|_| crate::error::ApiError::invalid("cannot read the session file"))?;
        let config: SessionConfig = serde_json::from_str(&text)
            .map_err(|_| crate::error::ApiError::invalid("session file is not a valid document"))?;
        if config.principal.trim().is_empty() {
            return Err(crate::error::ApiError::invalid(
                "session principal must not be empty",
            ));
        }
        let mut scopes = std::collections::BTreeSet::new();
        for scope in config.scopes {
            scopes.insert(parse_scope_text(&scope)?);
        }
        Ok(LocalSession {
            principal: config.principal,
            workspace_root: config.workspace_root,
            scopes,
        })
    }

    /// Require authorization for one command scope.
    pub fn authorize(&self, scope: &mneme_core::ScopeId) -> crate::error::CallResult<()> {
        if self.scopes.contains(scope) {
            Ok(())
        } else {
            Err(crate::error::ApiError::denied())
        }
    }

    /// The authorized scopes.
    pub fn scopes(&self) -> impl Iterator<Item = &mneme_core::ScopeId> {
        self.scopes.iter()
    }
}

/// A structured evaluation request carried by a recall command.
#[derive(Clone, Debug)]
pub struct StructuredQuery {
    /// An inline versioned rule bundle.
    pub bundle: Option<mneme_datalog::RuleBundle>,
    /// A workspace-relative tagged-JSON document holding the rule bundle.
    pub bundle_path: Option<String>,
    /// The declared relation the query names.
    pub relation: String,
    /// One term per relation position; a free position is a variable term.
    pub constants: Vec<Option<mneme_core::Value>>,
    /// Row limit for this query.
    pub limit: usize,
    /// Evaluation bounds.
    pub limits: mneme_datalog::Limits,
    /// Explicitly incomplete source extents.
    pub incomplete_extents: std::collections::BTreeSet<String>,
}

/// One validated API command.
#[derive(Clone, Debug)]
pub enum ApiCommand {
    Record {
        request_id: String,
        scope: mneme_core::ScopeId,
        base: mneme_core::WorkspaceRevisionId,
        key: String,
        records: Vec<mneme_core::RecordEnvelope>,
        sources: Vec<mneme_store::SourceBlobDraft>,
    },
    Accept {
        request_id: String,
        scope: mneme_core::ScopeId,
        base: mneme_core::WorkspaceRevisionId,
        key: String,
        assertion: mneme_core::RecordId,
        decision: mneme_core::RecordId,
        decision_revision: mneme_core::RevisionId,
        accepted_revision: mneme_core::RevisionId,
        policy: String,
        rationale: String,
    },
    Recall {
        request_id: String,
        scope: mneme_core::ScopeId,
        revision: Option<mneme_core::WorkspaceRevisionId>,
        query: String,
        at: mneme_core::Timestamp,
        temporal: mneme_recall::TemporalMode,
        modes: std::collections::BTreeSet<mneme_recall::Mode>,
        /// Boxed so a recall request stays close to the size of the other
        /// commands instead of making every command carry its full option set.
        structured: Option<Box<StructuredQuery>>,
        allow_stale: bool,
        allow_fallback: bool,
        allow_partial: bool,
        include_disputed: bool,
        include_hypothetical: bool,
        max_items: usize,
        max_context_bytes: usize,
        max_quote_bytes: usize,
        max_time_ms: u128,
    },
    Explain {
        request_id: String,
        scope: mneme_core::ScopeId,
        assertion: mneme_core::RecordId,
        max_nodes: usize,
        max_excerpt_bytes: usize,
    },
    Revise {
        request_id: String,
        scope: mneme_core::ScopeId,
        base: mneme_core::WorkspaceRevisionId,
        key: String,
        assertion: mneme_core::RecordId,
        action: ReviseAction,
        rationale: String,
        decision: mneme_core::RecordId,
        decision_revision: mneme_core::RevisionId,
        revised_revision: mneme_core::RevisionId,
        superseded_by: Option<mneme_core::RecordId>,
    },
    Resume {
        request_id: String,
        scope: mneme_core::ScopeId,
        checkpoint: mneme_core::RecordId,
    },
    Forget {
        request_id: String,
        scope: mneme_core::ScopeId,
        base: mneme_core::WorkspaceRevisionId,
        key: String,
        selector: mneme_retention::Selector,
        effective: Option<mneme_core::Timestamp>,
    },
    ProposalInspect {
        request_id: String,
        scope: mneme_core::ScopeId,
        assertion: mneme_core::RecordId,
    },
    Capabilities {
        request_id: String,
    },
}

/// Explicit revision action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviseAction {
    Supersede,
    Dispute,
    Retract,
}

impl ApiCommand {
    /// The caller-supplied request identity.
    pub fn request_id(&self) -> &str {
        match self {
            ApiCommand::Record { request_id, .. }
            | ApiCommand::Accept { request_id, .. }
            | ApiCommand::Recall { request_id, .. }
            | ApiCommand::Explain { request_id, .. }
            | ApiCommand::Revise { request_id, .. }
            | ApiCommand::Resume { request_id, .. }
            | ApiCommand::Forget { request_id, .. }
            | ApiCommand::ProposalInspect { request_id, .. }
            | ApiCommand::Capabilities { request_id } => request_id,
        }
    }

    /// The stable operation name.
    pub fn operation(&self) -> &'static str {
        match self {
            ApiCommand::Record { .. } => "record",
            ApiCommand::Accept { .. } => "accept",
            ApiCommand::Recall { .. } => "recall",
            ApiCommand::Explain { .. } => "explain",
            ApiCommand::Revise { .. } => "revise",
            ApiCommand::Resume { .. } => "resume",
            ApiCommand::Forget { .. } => "forget",
            ApiCommand::ProposalInspect { .. } => "proposal.inspect",
            ApiCommand::Capabilities { .. } => "capabilities",
        }
    }

    /// The scope a command authorizes before any other work.
    pub fn scope(&self) -> Option<&mneme_core::ScopeId> {
        match self {
            ApiCommand::Record { scope, .. }
            | ApiCommand::Accept { scope, .. }
            | ApiCommand::Recall { scope, .. }
            | ApiCommand::Explain { scope, .. }
            | ApiCommand::Revise { scope, .. }
            | ApiCommand::Resume { scope, .. }
            | ApiCommand::Forget { scope, .. }
            | ApiCommand::ProposalInspect { scope, .. } => Some(scope),
            ApiCommand::Capabilities { .. } => None,
        }
    }

    /// Parse one command envelope.
    pub fn from_value(value: &mneme_core::Value) -> crate::error::CallResult<Self> {
        let envelope = Fields::checked(
            value,
            &["format", "version", "request-id", "operation", "payload"],
            &mneme_core::Path::root(),
        )?;
        if envelope.text("format")? != COMMAND_FORMAT {
            return Err(unsupported(
                "unsupported command format",
                mneme_core::ErrorCode::UnsupportedSchemaVersion,
                envelope_path("format"),
            ));
        }
        if envelope.integer("version")? != COMMAND_VERSION as i64 {
            return Err(unsupported(
                "unsupported command version",
                mneme_core::ErrorCode::UnsupportedSchemaVersion,
                envelope_path("version"),
            ));
        }
        let request_id = envelope.text("request-id")?.to_owned();
        let operation = envelope.symbol("operation")?;
        let payload = envelope.field("payload")?;
        match operation {
            "record" => record(request_id, payload),
            "accept" => accept(request_id, payload),
            "recall" => recall(request_id, payload),
            "explain" => explain(request_id, payload),
            "revise" => revise(request_id, payload),
            "resume" => resume(request_id, payload),
            "forget" => forget(request_id, payload),
            "proposal.inspect" => proposal_inspect(request_id, payload),
            "capabilities" => {
                Fields::checked(payload, &[], &payload_path())?;
                Ok(ApiCommand::Capabilities { request_id })
            }
            _ => Err(unsupported(
                "unsupported operation",
                mneme_core::ErrorCode::UnsupportedValueKind,
                envelope_path("operation"),
            )),
        }
    }
}

/// One compatibility refusal addressed at the member that carried it.
fn unsupported(
    message: &str,
    code: mneme_core::ErrorCode,
    path: mneme_core::Path,
) -> crate::error::ApiError {
    crate::error::ApiError::new(crate::error::ApiErrorCode::UnsupportedVersion, message)
        .with_diagnostic(mneme_core::Diagnostic::new(
            mneme_core::Stage::Envelope,
            code,
            path,
            message,
        ))
}

fn envelope_path(name: &'static str) -> mneme_core::Path {
    mneme_core::Path::root().field(name)
}

fn payload_path() -> mneme_core::Path {
    mneme_core::Path::root().field("payload")
}

fn record(request_id: String, payload: &mneme_core::Value) -> Result<ApiCommand, crate::ApiError> {
    let fields = Fields::checked(
        payload,
        &[
            "scope",
            "base-revision",
            "idempotency-key",
            "records",
            "sources",
        ],
        &payload_path(),
    )?;
    let scope = fields.scope("scope")?;
    let base = fields.revision("base-revision")?;
    let key = fields.text("idempotency-key")?.to_owned();
    let records = fields
        .field("records")?
        .as_sequence()
        .ok_or_else(|| fields.refuse("records", "records must be a sequence"))?
        .iter()
        .enumerate()
        .map(|(index, value)| parse_record(index, value))
        .collect::<crate::error::CallResult<Vec<_>>>()?;
    let sources = match fields.optional("sources") {
        Some(value) => parse_sources(value, &payload_path().field("sources"))?,
        None => Vec::new(),
    };
    Ok(ApiCommand::Record {
        request_id,
        scope,
        base,
        key,
        records,
        sources,
    })
}

fn accept(request_id: String, payload: &mneme_core::Value) -> Result<ApiCommand, crate::ApiError> {
    let fields = Fields::checked(
        payload,
        &[
            "scope",
            "base-revision",
            "idempotency-key",
            "assertion",
            "decision",
            "decision-revision",
            "accepted-revision",
            "policy",
            "rationale",
        ],
        &payload_path(),
    )?;
    Ok(ApiCommand::Accept {
        request_id,
        scope: fields.scope("scope")?,
        base: fields.revision("base-revision")?,
        key: fields.text("idempotency-key")?.to_owned(),
        assertion: fields.record("assertion")?,
        decision: fields.record("decision")?,
        decision_revision: fields.revision_id("decision-revision")?,
        accepted_revision: fields.revision_id("accepted-revision")?,
        policy: fields.text("policy")?.to_owned(),
        rationale: fields.text("rationale")?.to_owned(),
    })
}

fn recall(request_id: String, payload: &mneme_core::Value) -> Result<ApiCommand, crate::ApiError> {
    let fields = Fields::checked(
        payload,
        &[
            "scope",
            "revision",
            "query",
            "at",
            "temporal",
            "modes",
            "structured",
            "allow-stale",
            "allow-fallback",
            "allow-partial",
            "include-disputed",
            "include-hypothetical",
            "max-items",
            "max-context-bytes",
            "max-quote-bytes",
            "max-time-ms",
        ],
        &payload_path(),
    )?;
    let modes = match fields.optional("modes") {
        Some(value) => parse_modes(value, &payload_path().field("modes"))?,
        None => std::collections::BTreeSet::from([mneme_recall::Mode::Lexical]),
    };
    let mut modes = modes;
    let structured = match fields.optional("structured") {
        Some(value) => {
            // A structured query is itself an explicit request for the
            // structured mode; the response still reports that mode's own
            // status and coverage.
            modes.insert(mneme_recall::Mode::Structured);
            Some(Box::new(parse_structured(value)?))
        }
        None => None,
    };
    Ok(ApiCommand::Recall {
        request_id,
        scope: fields.scope("scope")?,
        revision: fields.optional_revision("revision")?,
        query: fields.text("query")?.to_owned(),
        at: fields.timestamp("at")?,
        temporal: match fields.optional("temporal") {
            Some(_) => parse_temporal(&fields, "temporal")?,
            None => mneme_recall::TemporalMode::Current,
        },
        modes,
        structured,
        allow_stale: fields.boolean_or("allow-stale", false)?,
        allow_fallback: fields.boolean_or("allow-fallback", true)?,
        allow_partial: fields.boolean_or("allow-partial", true)?,
        include_disputed: fields.boolean_or("include-disputed", false)?,
        include_hypothetical: fields.boolean_or("include-hypothetical", false)?,
        max_items: fields.usize_or("max-items", 8)?,
        max_context_bytes: fields.usize_or("max-context-bytes", 4096)?,
        max_quote_bytes: fields.usize_or("max-quote-bytes", 1024)?,
        max_time_ms: fields.u128_or("max-time-ms", 500)?,
    })
}

fn explain(request_id: String, payload: &mneme_core::Value) -> Result<ApiCommand, crate::ApiError> {
    let fields = Fields::checked(
        payload,
        &["scope", "assertion", "max-nodes", "max-excerpt-bytes"],
        &payload_path(),
    )?;
    Ok(ApiCommand::Explain {
        request_id,
        scope: fields.scope("scope")?,
        assertion: fields.record("assertion")?,
        max_nodes: fields.usize_or("max-nodes", 64)?,
        max_excerpt_bytes: fields.usize_or("max-excerpt-bytes", 4096)?,
    })
}

fn revise(request_id: String, payload: &mneme_core::Value) -> Result<ApiCommand, crate::ApiError> {
    let fields = Fields::checked(
        payload,
        &[
            "scope",
            "base-revision",
            "idempotency-key",
            "assertion",
            "action",
            "rationale",
            "decision",
            "decision-revision",
            "revised-revision",
            "superseded-by",
        ],
        &payload_path(),
    )?;
    Ok(ApiCommand::Revise {
        request_id,
        scope: fields.scope("scope")?,
        base: fields.revision("base-revision")?,
        key: fields.text("idempotency-key")?.to_owned(),
        assertion: fields.record("assertion")?,
        action: parse_action(&fields, "action")?,
        rationale: fields.text("rationale")?.to_owned(),
        decision: fields.record("decision")?,
        decision_revision: fields.revision_id("decision-revision")?,
        revised_revision: fields.revision_id("revised-revision")?,
        superseded_by: fields.optional_record("superseded-by")?,
    })
}

fn resume(request_id: String, payload: &mneme_core::Value) -> Result<ApiCommand, crate::ApiError> {
    let fields = Fields::checked(payload, &["scope", "checkpoint"], &payload_path())?;
    Ok(ApiCommand::Resume {
        request_id,
        scope: fields.scope("scope")?,
        checkpoint: fields.record("checkpoint")?,
    })
}

fn forget(request_id: String, payload: &mneme_core::Value) -> Result<ApiCommand, crate::ApiError> {
    let fields = Fields::checked(
        payload,
        &[
            "scope",
            "base-revision",
            "idempotency-key",
            "selector",
            "effective",
        ],
        &payload_path(),
    )?;
    Ok(ApiCommand::Forget {
        request_id,
        scope: fields.scope("scope")?,
        base: fields.revision("base-revision")?,
        key: fields.text("idempotency-key")?.to_owned(),
        selector: parse_selector(fields.field("selector")?)?,
        effective: fields.optional_timestamp("effective")?,
    })
}

fn proposal_inspect(
    request_id: String,
    payload: &mneme_core::Value,
) -> Result<ApiCommand, crate::ApiError> {
    let fields = Fields::checked(payload, &["scope", "assertion"], &payload_path())?;
    Ok(ApiCommand::ProposalInspect {
        request_id,
        scope: fields.scope("scope")?,
        assertion: fields.record("assertion")?,
    })
}

fn parse_record(
    index: usize,
    value: &mneme_core::Value,
) -> crate::error::CallResult<mneme_core::RecordEnvelope> {
    mneme_core::validate_record_value(value, &mneme_core::SchemaRegistry::production(), None)
        .map_err(|diagnostics| {
            crate::error::ApiError::diagnostics(
                diagnostics
                    .into_iter()
                    .map(|diagnostic| {
                        at_record(&payload_path().field("records").index(index), diagnostic)
                    })
                    .collect(),
            )
        })
}

fn parse_sources(
    value: &mneme_core::Value,
    path: &mneme_core::Path,
) -> crate::error::CallResult<Vec<mneme_store::SourceBlobDraft>> {
    let sequence = value.as_sequence().ok_or_else(|| {
        member_error(
            path.clone(),
            mneme_core::ErrorCode::TypeMismatch,
            "sources must be a sequence",
        )
    })?;
    sequence
        .iter()
        .enumerate()
        .map(|(index, source)| {
            let fields = Fields::checked(source, &["bytes", "media-type"], &path.index(index))?;
            let bytes = fields
                .field("bytes")?
                .as_bytes()
                .ok_or_else(|| fields.refuse("bytes", "source bytes must be a byte string"))?
                .to_vec();
            let media_type = fields.text("media-type")?.to_owned();
            Ok(mneme_store::SourceBlobDraft {
                bytes,
                media_type: media_type.as_str().into(),
            })
        })
        .collect()
}

fn parse_modes(
    value: &mneme_core::Value,
    path: &mneme_core::Path,
) -> crate::error::CallResult<std::collections::BTreeSet<mneme_recall::Mode>> {
    let sequence = value.as_sequence().ok_or_else(|| {
        member_error(
            path.clone(),
            mneme_core::ErrorCode::TypeMismatch,
            "modes must be a sequence",
        )
    })?;
    sequence
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let mode = |message: &str| {
                member_error(
                    path.index(index),
                    mneme_core::ErrorCode::TypeMismatch,
                    message,
                )
            };
            match value.as_symbol().map(|symbol| symbol.as_str()) {
                Some("lexical") => Ok(mneme_recall::Mode::Lexical),
                Some("structured") => Ok(mneme_recall::Mode::Structured),
                Some("vector") => Ok(mneme_recall::Mode::Vector),
                Some(other) => Err(mode(&format!("unknown recall mode {other}"))),
                None => Err(mode("recall modes must be symbols")),
            }
        })
        .collect()
}

fn parse_temporal(
    fields: &Fields<'_>,
    name: &str,
) -> crate::error::CallResult<mneme_recall::TemporalMode> {
    let value = fields.symbol(name)?;
    match value {
        "current" => Ok(mneme_recall::TemporalMode::Current),
        "historical" => Ok(mneme_recall::TemporalMode::Historical),
        "inspection" => Ok(mneme_recall::TemporalMode::Inspection),
        other => Err(fields.refuse(name, format!("unknown temporal mode {other}"))),
    }
}

fn parse_action(fields: &Fields<'_>, name: &str) -> crate::error::CallResult<ReviseAction> {
    let value = fields.symbol(name)?;
    match value {
        "supersede" | "correct" => Ok(ReviseAction::Supersede),
        "dispute" => Ok(ReviseAction::Dispute),
        "retract" => Ok(ReviseAction::Retract),
        other => Err(fields.refuse(name, format!("unknown revision action {other}"))),
    }
}

fn parse_selector(
    value: &mneme_core::Value,
) -> crate::error::CallResult<mneme_retention::Selector> {
    let fields = Fields::checked(
        value,
        &["kind", "target", "revision"],
        &payload_path().field("selector"),
    )?;
    match fields.symbol("kind")? {
        "source" => Ok(mneme_retention::Selector::Source(fields.record("target")?)),
        "source-revision" => Ok(mneme_retention::Selector::SourceRevision(
            fields.record("target")?,
            fields.revision_id("revision")?,
        )),
        "assertion" => Ok(mneme_retention::Selector::Assertion(
            fields.record("target")?,
        )),
        "source-support" => Ok(mneme_retention::Selector::SourceSupport(
            fields.record("target")?,
        )),
        "digest" => {
            let digest = mneme_core::ContentDigest::from_value(
                fields.field("target")?,
                &fields.member_path("target"),
            )
            .map_err(crate::error::ApiError::from_diagnostic)?;
            Ok(mneme_retention::Selector::Content(digest))
        }
        other => Err(fields.refuse("kind", format!("unknown forget selector {other}"))),
    }
}

fn parse_scope_text(text: &str) -> crate::error::CallResult<mneme_core::ScopeId> {
    parse_scope_text_at(text, &mneme_core::Path::root())
}

fn parse_scope_text_at(
    text: &str,
    path: &mneme_core::Path,
) -> crate::error::CallResult<mneme_core::ScopeId> {
    let (class, local) = text.split_once(':').ok_or_else(|| {
        member_error(
            path.clone(),
            mneme_core::ErrorCode::InvalidScope,
            "scope must be class:local",
        )
    })?;
    let class = mneme_core::ScopeClass::parse(class).ok_or_else(|| {
        member_error(
            path.clone(),
            mneme_core::ErrorCode::InvalidScope,
            "unknown scope class",
        )
    })?;
    mneme_core::ScopeId::new(class, local)
        .map_err(|message| member_error(path.clone(), mneme_core::ErrorCode::InvalidScope, message))
}

fn structured_path() -> mneme_core::Path {
    payload_path().field("structured")
}

/// Parse one structured evaluation request.
fn parse_structured(value: &mneme_core::Value) -> crate::error::CallResult<StructuredQuery> {
    let fields = Fields::checked(
        value,
        &[
            "bundle",
            "bundle-path",
            "relation",
            "constants",
            "limit",
            "limits",
            "incomplete-extents",
        ],
        &structured_path(),
    )?;
    let bundle = fields
        .optional("bundle")
        .map(|value| parse_bundle(value, &structured_path().field("bundle")))
        .transpose()?;
    let bundle_path = fields
        .optional("bundle-path")
        .map(parse_bundle_path)
        .transpose()?;
    if bundle.is_some() == bundle_path.is_some() {
        return Err(member_error(
            structured_path(),
            mneme_core::ErrorCode::TypeMismatch,
            "structured request needs exactly one of bundle or bundle-path",
        ));
    }
    let constants = match fields.optional("constants") {
        Some(value) => value
            .as_sequence()
            .ok_or_else(|| fields.refuse("constants", "constants must be a sequence"))?
            .iter()
            .map(parse_constant)
            .collect::<crate::error::CallResult<Vec<_>>>()?,
        None => Vec::new(),
    };
    Ok(StructuredQuery {
        bundle,
        bundle_path,
        relation: fields.text("relation")?.to_owned(),
        constants,
        limit: fields.usize_or("limit", 100)?,
        limits: match fields.optional("limits") {
            Some(value) => parse_limits(value)?,
            None => default_limits(),
        },
        incomplete_extents: match fields.optional("incomplete-extents") {
            Some(value) => parse_text_set(value, &structured_path().field("incomplete-extents"))?,
            None => std::collections::BTreeSet::new(),
        },
    })
}

/// A free position is a variable term; a bound position holds an exact value.
fn parse_constant(
    value: &mneme_core::Value,
) -> crate::error::CallResult<Option<mneme_core::Value>> {
    let term = parse_term(value, &structured_path().field("constants"))?;
    match term {
        mneme_datalog::Term::Variable(_) => Ok(None),
        mneme_datalog::Term::Constant(value) => Ok(Some(value)),
    }
}

/// Read one workspace-relative reference to a rule bundle document.
///
/// The reference is canonical before any file is opened, so a command cannot
/// name a path outside the workspace.
fn parse_bundle_path(value: &mneme_core::Value) -> crate::error::CallResult<String> {
    let address = structured_path().field("bundle-path");
    let path = value.as_string().ok_or_else(|| {
        member_error(
            address.clone(),
            mneme_core::ErrorCode::TypeMismatch,
            "bundle-path must be text",
        )
    })?;
    if !mneme_kernel::text::is_canonical_relative_path(path.as_bytes()) {
        return Err(member_error(
            address,
            mneme_core::ErrorCode::TypeMismatch,
            "bundle-path must be a canonical workspace-relative path",
        ));
    }
    Ok(path.to_owned())
}

fn parse_limits(value: &mneme_core::Value) -> crate::error::CallResult<mneme_datalog::Limits> {
    let fields = Fields::checked(
        value,
        &[
            "max-work",
            "max-time-ms",
            "max-result-rows",
            "max-supports-per-fact",
            "max-recursion-depth",
        ],
        &structured_path().field("limits"),
    )?;
    let default = default_limits();
    Ok(mneme_datalog::Limits {
        max_work: fields.u64_or("max-work", default.max_work)?,
        max_time_ms: fields.u128_or("max-time-ms", default.max_time_ms)?,
        max_result_rows: fields.usize_or("max-result-rows", default.max_result_rows)?,
        max_supports_per_fact: fields
            .usize_or("max-supports-per-fact", default.max_supports_per_fact)?,
        max_recursion_depth: fields.usize_or("max-recursion-depth", default.max_recursion_depth)?,
    })
}

/// The evaluation bounds a structured request runs under when it names none.
///
/// These are the values `mneme_datalog::Limits::default()` declares, restated
/// here: a silent default on another crate's type would let its definition
/// change the bounds this API puts on a caller's query.
const fn default_limits() -> mneme_datalog::Limits {
    mneme_datalog::Limits {
        max_work: 100_000,
        max_time_ms: 2_000,
        max_result_rows: 1_000,
        max_supports_per_fact: 8,
        max_recursion_depth: 32,
    }
}

fn parse_text_set(
    value: &mneme_core::Value,
    path: &mneme_core::Path,
) -> crate::error::CallResult<std::collections::BTreeSet<String>> {
    let sequence = value.as_sequence().ok_or_else(|| {
        member_error(
            path.clone(),
            mneme_core::ErrorCode::TypeMismatch,
            format!("{path} must be a sequence"),
        )
    })?;
    sequence
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            entry.as_string().map(str::to_owned).ok_or_else(|| {
                member_error(
                    path.index(index),
                    mneme_core::ErrorCode::TypeMismatch,
                    format!("{path} must hold text"),
                )
            })
        })
        .collect()
}

/// Parse one versioned rule bundle document.
pub fn parse_bundle(
    value: &mneme_core::Value,
    path: &mneme_core::Path,
) -> crate::error::CallResult<mneme_datalog::RuleBundle> {
    let fields = Fields::checked(
        value,
        &[
            "id",
            "version",
            "schema-version",
            "base-predicates",
            "complete-predicates",
            "rules",
        ],
        path,
    )?;
    let schema_version = fields.integer("schema-version")?;
    if schema_version != i64::from(RULE_BUNDLE_SCHEMA_VERSION) {
        return Err(unsupported(
            "unsupported rule bundle schema version",
            mneme_core::ErrorCode::UnsupportedSchemaVersion,
            fields.member_path("schema-version"),
        ));
    }
    let base_predicates = fields
        .field("base-predicates")?
        .as_dictionary()
        .ok_or_else(|| fields.refuse("base-predicates", "base-predicates must be an object"))?
        .iter()
        .map(|(predicate, arity)| parse_base_predicate(predicate, arity, &fields))
        .collect::<crate::error::CallResult<std::collections::BTreeMap<String, usize>>>()?;
    let rules = fields
        .field("rules")?
        .as_sequence()
        .ok_or_else(|| fields.refuse("rules", "rules must be a sequence"))?
        .iter()
        .enumerate()
        .map(|(index, rule)| parse_rule(rule, &path.field("rules").index(index)))
        .collect::<crate::error::CallResult<Vec<_>>>()?;
    Ok(mneme_datalog::RuleBundle::new(
        mneme_datalog::RuleBundleOptions {
            id: fields.text("id")?.to_owned(),
            version: fields.text("version")?.to_owned(),
            schema_version: RULE_BUNDLE_SCHEMA_VERSION,
            base_predicates,
            complete_predicates: parse_text_set(
                fields.field("complete-predicates")?,
                &path.field("complete-predicates"),
            )?,
            rules,
        },
    ))
}

/// Read one base predicate declaration: a symbol name and a non-negative arity.
fn parse_base_predicate(
    predicate: &mneme_core::Value,
    arity: &mneme_core::Value,
    fields: &Fields<'_>,
) -> crate::error::CallResult<(String, usize)> {
    let predicate_path = fields
        .member_path("base-predicates")
        .named(predicate.to_text());
    let name = predicate
        .as_symbol()
        .map(|symbol| symbol.as_str())
        .ok_or_else(|| {
            member_error(
                predicate_path.clone(),
                mneme_core::ErrorCode::TypeMismatch,
                "base predicate names must be symbols",
            )
        })?;
    let arity = arity
        .as_integer()
        .and_then(|integer| integer.to_i64())
        .and_then(|integer| usize::try_from(integer).ok())
        .ok_or_else(|| {
            member_error(
                predicate_path,
                mneme_core::ErrorCode::TypeMismatch,
                "base predicate arities must be non-negative",
            )
        })?;
    Ok((name.to_owned(), arity))
}

fn parse_rule(
    value: &mneme_core::Value,
    path: &mneme_core::Path,
) -> crate::error::CallResult<mneme_datalog::Rule> {
    let fields = Fields::checked(value, &["id", "head", "body"], path)?;
    let head = parse_atom(fields.field("head")?, &path.field("head"))?;
    let body = fields
        .field("body")?
        .as_sequence()
        .ok_or_else(|| fields.refuse("body", "rule body must be a sequence"))?
        .iter()
        .enumerate()
        .map(|(index, literal)| parse_literal(literal, &path.field("body").index(index)))
        .collect::<crate::error::CallResult<Vec<_>>>()?;
    Ok(mneme_datalog::Rule::new(
        fields.text("id")?.to_owned(),
        head,
        body,
    ))
}

fn parse_atom(
    value: &mneme_core::Value,
    path: &mneme_core::Path,
) -> crate::error::CallResult<mneme_datalog::Atom> {
    let fields = Fields::checked(value, &["predicate", "terms"], path)?;
    let terms = fields
        .field("terms")?
        .as_sequence()
        .ok_or_else(|| fields.refuse("terms", "atom terms must be a sequence"))?
        .iter()
        .enumerate()
        .map(|(index, term)| parse_term(term, &path.field("terms").index(index)))
        .collect::<crate::error::CallResult<Vec<_>>>()?;
    Ok(mneme_datalog::Atom::new(
        fields.text("predicate")?.to_owned(),
        terms,
    ))
}

fn parse_term(
    value: &mneme_core::Value,
    path: &mneme_core::Path,
) -> crate::error::CallResult<mneme_datalog::Term> {
    let fields = Fields::checked(value, &["kind", "name", "value"], path)?;
    match fields.symbol("kind")? {
        "variable" => Ok(mneme_datalog::Term::var(fields.text("name")?.to_owned())),
        "constant" => Ok(mneme_datalog::Term::constant(
            fields.field("value")?.clone(),
        )),
        other => Err(fields.refuse("kind", format!("unknown term kind {other}"))),
    }
}

fn parse_literal(
    value: &mneme_core::Value,
    path: &mneme_core::Path,
) -> crate::error::CallResult<mneme_datalog::Literal> {
    let fields = Fields::checked(
        value,
        &[
            "kind", "atom", "op", "left", "right", "function", "input", "output",
        ],
        path,
    )?;
    match fields.symbol("kind")? {
        "positive" => Ok(mneme_datalog::Literal::Positive(parse_atom(
            fields.field("atom")?,
            &path.field("atom"),
        )?)),
        "negative" => Ok(mneme_datalog::Literal::Negative(parse_atom(
            fields.field("atom")?,
            &path.field("atom"),
        )?)),
        "compare" => Ok(mneme_datalog::Literal::Compare {
            op: parse_compare_op(&fields, "op")?,
            left: parse_term(fields.field("left")?, &path.field("left"))?,
            right: parse_term(fields.field("right")?, &path.field("right"))?,
        }),
        "aggregate" => Ok(mneme_datalog::Literal::Aggregate {
            function: parse_aggregate(&fields, "function")?,
            input: parse_term(fields.field("input")?, &path.field("input"))?,
            output: fields.text("output")?.to_owned(),
        }),
        other => Err(fields.refuse("kind", format!("unsupported rule literal {other}"))),
    }
}

fn parse_compare_op(
    fields: &Fields<'_>,
    name: &str,
) -> crate::error::CallResult<mneme_datalog::CompareOp> {
    let value = fields.symbol(name)?;
    match value {
        "eq" => Ok(mneme_datalog::CompareOp::Eq),
        "ne" => Ok(mneme_datalog::CompareOp::Ne),
        "lt" => Ok(mneme_datalog::CompareOp::Lt),
        "le" => Ok(mneme_datalog::CompareOp::Le),
        "gt" => Ok(mneme_datalog::CompareOp::Gt),
        "ge" => Ok(mneme_datalog::CompareOp::Ge),
        other => Err(fields.refuse(name, format!("unknown comparison operator {other}"))),
    }
}

fn parse_aggregate(
    fields: &Fields<'_>,
    name: &str,
) -> crate::error::CallResult<mneme_datalog::AggregateFunction> {
    let value = fields.symbol(name)?;
    match value {
        "count" => Ok(mneme_datalog::AggregateFunction::Count),
        "sum" => Ok(mneme_datalog::AggregateFunction::Sum),
        "min" => Ok(mneme_datalog::AggregateFunction::Min),
        "max" => Ok(mneme_datalog::AggregateFunction::Max),
        other => Err(fields.refuse(name, format!("unknown aggregate function {other}"))),
    }
}

/// Typed member access over one decoded object at a known address.
struct Fields<'a> {
    values: &'a std::collections::BTreeMap<mneme_core::Value, mneme_core::Value>,
    path: mneme_core::Path,
}

impl<'a> Fields<'a> {
    /// Construct typed access, refusing every member outside `allowed`.
    fn checked(
        value: &'a mneme_core::Value,
        allowed: &[&str],
        path: &mneme_core::Path,
    ) -> crate::error::CallResult<Self> {
        let values = value.as_dictionary().ok_or_else(|| {
            member_error(
                path.clone(),
                mneme_core::ErrorCode::TypeMismatch,
                "expected an object",
            )
        })?;
        let fields = Fields {
            values,
            path: path.clone(),
        };
        let diagnostics = fields
            .values
            .keys()
            .filter_map(|key| match key.as_symbol().map(|symbol| symbol.as_str()) {
                Some(name) if allowed.contains(&name) => None,
                Some(name) => Some(mneme_core::Diagnostic::new(
                    mneme_core::Stage::Envelope,
                    mneme_core::ErrorCode::UnexpectedFieldKind,
                    path.named(name),
                    format!("unknown request member {name}"),
                )),
                None => Some(mneme_core::Diagnostic::new(
                    mneme_core::Stage::Envelope,
                    mneme_core::ErrorCode::UnexpectedFieldKind,
                    path.named(key.to_text()),
                    "request member names must be symbols",
                )),
            })
            .collect::<Vec<_>>();
        if diagnostics.is_empty() {
            Ok(fields)
        } else {
            Err(crate::error::ApiError::diagnostics(diagnostics))
        }
    }

    /// The address of one member of this object.
    fn member_path(&self, name: &str) -> mneme_core::Path {
        self.path.named(name)
    }

    /// A refusal addressed at one member of this object.
    fn refuse(&self, name: &str, message: impl Into<String>) -> crate::error::ApiError {
        member_error(
            self.member_path(name),
            mneme_core::ErrorCode::TypeMismatch,
            message,
        )
    }

    fn field(&self, name: &str) -> crate::error::CallResult<&'a mneme_core::Value> {
        self.values
            .get(&mneme_core::Value::symbol(name))
            .ok_or_else(|| {
                member_error(
                    self.member_path(name),
                    mneme_core::ErrorCode::MissingField,
                    format!("missing field {name}"),
                )
            })
    }

    fn optional(&self, name: &str) -> Option<&'a mneme_core::Value> {
        self.values.get(&mneme_core::Value::symbol(name))
    }

    fn text(&self, name: &str) -> crate::error::CallResult<&'a str> {
        self.field(name)?
            .as_string()
            .ok_or_else(|| self.refuse(name, format!("{name} must be text")))
    }

    fn symbol(&self, name: &str) -> crate::error::CallResult<&'a str> {
        self.field(name)?
            .as_symbol()
            .map(|symbol| symbol.as_str())
            .ok_or_else(|| self.refuse(name, format!("{name} must be a symbol")))
    }

    fn integer(&self, name: &str) -> crate::error::CallResult<i64> {
        self.field(name)?
            .as_integer()
            .and_then(|integer| integer.to_i64())
            .ok_or_else(|| self.refuse(name, format!("{name} must be an integer")))
    }

    fn boolean_or(&self, name: &str, default: bool) -> crate::error::CallResult<bool> {
        match self.optional(name) {
            Some(value) => value
                .as_boolean()
                .ok_or_else(|| self.refuse(name, format!("{name} must be a boolean"))),
            None => Ok(default),
        }
    }

    fn usize_or(&self, name: &str, default: usize) -> crate::error::CallResult<usize> {
        match self.optional(name) {
            Some(value) => value
                .as_integer()
                .and_then(|integer| integer.to_i64())
                .and_then(|integer| usize::try_from(integer).ok())
                .ok_or_else(|| self.refuse(name, format!("{name} must be a non-negative integer"))),
            None => Ok(default),
        }
    }

    fn u64_or(&self, name: &str, default: u64) -> crate::error::CallResult<u64> {
        match self.optional(name) {
            Some(value) => value
                .as_integer()
                .and_then(|integer| integer.to_i64())
                .and_then(|integer| u64::try_from(integer).ok())
                .ok_or_else(|| self.refuse(name, format!("{name} must be a non-negative integer"))),
            None => Ok(default),
        }
    }

    fn u128_or(&self, name: &str, default: u128) -> crate::error::CallResult<u128> {
        match self.optional(name) {
            Some(value) => value
                .as_integer()
                .and_then(|integer| integer.to_i64())
                .and_then(|integer| u128::try_from(integer).ok())
                .ok_or_else(|| self.refuse(name, format!("{name} must be a non-negative integer"))),
            None => Ok(default),
        }
    }

    fn record(&self, name: &str) -> crate::error::CallResult<mneme_core::RecordId> {
        mneme_core::RecordId::from_value(self.field(name)?, &self.member_path(name))
            .map_err(crate::error::ApiError::from_diagnostic)
    }

    fn optional_record(
        &self,
        name: &str,
    ) -> crate::error::CallResult<Option<mneme_core::RecordId>> {
        self.optional(name)
            .map(|value| {
                mneme_core::RecordId::from_value(value, &self.member_path(name))
                    .map_err(crate::error::ApiError::from_diagnostic)
            })
            .transpose()
    }

    fn revision(&self, name: &str) -> crate::error::CallResult<mneme_core::WorkspaceRevisionId> {
        mneme_core::WorkspaceRevisionId::from_value(self.field(name)?, &self.member_path(name))
            .map_err(crate::error::ApiError::from_diagnostic)
    }

    fn optional_revision(
        &self,
        name: &str,
    ) -> crate::error::CallResult<Option<mneme_core::WorkspaceRevisionId>> {
        self.optional(name)
            .map(|value| {
                mneme_core::WorkspaceRevisionId::from_value(value, &self.member_path(name))
                    .map_err(crate::error::ApiError::from_diagnostic)
            })
            .transpose()
    }

    fn revision_id(&self, name: &str) -> crate::error::CallResult<mneme_core::RevisionId> {
        mneme_core::RevisionId::from_value(self.field(name)?, &self.member_path(name))
            .map_err(crate::error::ApiError::from_diagnostic)
    }

    fn scope(&self, name: &str) -> crate::error::CallResult<mneme_core::ScopeId> {
        let value = self.field(name)?;
        if let Some(text) = value.as_string() {
            return parse_scope_text_at(text, &self.member_path(name));
        }
        mneme_core::ScopeId::from_value(value, &self.member_path(name))
            .map_err(crate::error::ApiError::from_diagnostic)
    }

    fn timestamp(&self, name: &str) -> crate::error::CallResult<mneme_core::Timestamp> {
        let text = self.text(name)?;
        mneme_core::Timestamp::parse(text).map_err(|message| {
            member_error(
                self.member_path(name),
                mneme_core::ErrorCode::InvalidTimestamp,
                format!("{name}: {message}"),
            )
        })
    }

    fn optional_timestamp(
        &self,
        name: &str,
    ) -> crate::error::CallResult<Option<mneme_core::Timestamp>> {
        self.optional(name)
            .map(|value| {
                let text = value
                    .as_string()
                    .ok_or_else(|| self.refuse(name, format!("{name} must be text")))?;
                mneme_core::Timestamp::parse(text).map_err(|message| {
                    member_error(
                        self.member_path(name),
                        mneme_core::ErrorCode::InvalidTimestamp,
                        format!("{name}: {message}"),
                    )
                })
            })
            .transpose()
    }
}

/// One refusal addressed at a known location.
fn member_error(
    path: mneme_core::Path,
    code: mneme_core::ErrorCode,
    message: impl Into<String>,
) -> crate::error::ApiError {
    let message = message.into();
    crate::error::ApiError::new(crate::error::ApiErrorCode::InvalidInput, message.clone())
        .with_diagnostic(mneme_core::Diagnostic::new(
            mneme_core::Stage::Envelope,
            code,
            path,
            message,
        ))
}

/// Re-address a diagnostic decoded for one record inside the command payload.
///
/// The record codec reports paths relative to the record value; the adapter
/// knows the record's position, so the member address stays exact.
fn at_record(
    prefix: &mneme_core::Path,
    diagnostic: mneme_core::Diagnostic,
) -> mneme_core::Diagnostic {
    let mut segments = prefix.segments().to_vec();
    segments.extend_from_slice(diagnostic.path.segments());
    mneme_core::Diagnostic::new(
        diagnostic.stage,
        diagnostic.code,
        mneme_core::Path::from_segments(segments),
        diagnostic.message,
    )
}

/// Convert a validated envelope to a coordinator draft.
pub fn record_draft(record: mneme_core::RecordEnvelope) -> mneme_store::RecordDraft {
    mneme_store::RecordDraft {
        schema_version: record.schema_version,
        kind: record.kind,
        record_id: record.record_id,
        revision_id: record.revision_id,
        predecessor: record.predecessor,
        scope: record.scope,
        payload: record.payload,
    }
}

/// Decode a tagged JSON command document.
pub fn decode(text: &str) -> crate::error::CallResult<ApiCommand> {
    let value =
        mneme_core::decode_document(text).map_err(crate::error::ApiError::from_diagnostic)?;
    ApiCommand::from_value(&value)
}

/// Field diagnostic helper for adapters.
pub fn diagnostic_fields(diagnostics: Vec<mneme_core::Diagnostic>) -> mneme_core::Value {
    mneme_core::Value::sequence(
        diagnostics
            .into_iter()
            .map(|diagnostic| mneme_core::Value::string(diagnostic.to_string()))
            .collect(),
    )
}
