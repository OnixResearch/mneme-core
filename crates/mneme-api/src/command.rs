//! Versioned tagged-JSON command envelopes and local session authorization.

use serde::Deserialize;

/// Command format and version.
pub const COMMAND_FORMAT: &str = "mneme.agent-command";
pub const COMMAND_VERSION: u64 = 1;
/// Result format and version.
pub const RESULT_FORMAT: &str = "mneme.agent-result";
pub const RESULT_VERSION: u64 = 1;

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
    pub fn load(path: &std::path::Path) -> crate::error::CallResult<Self> {
        let text = std::fs::read_to_string(path).map_err(|error| {
            crate::error::ApiError::invalid(format!("cannot read session file: {error}"))
        })?;
        let config: SessionConfig = serde_json::from_str(&text).map_err(|error| {
            crate::error::ApiError::invalid(format!("invalid session file: {error}"))
        })?;
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

    pub fn authorize(&self, scope: &mneme_core::ScopeId) -> crate::error::CallResult<()> {
        if self.scopes.contains(scope) {
            Ok(())
        } else {
            Err(crate::error::ApiError::denied())
        }
    }

    pub fn scopes(&self) -> impl Iterator<Item = &mneme_core::ScopeId> {
        self.scopes.iter()
    }
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

    pub fn from_value(value: &mneme_core::Value) -> crate::error::CallResult<Self> {
        let envelope = Fields::new(value)?;
        if envelope.text("format")? != COMMAND_FORMAT {
            return Err(crate::error::ApiError::new(
                crate::error::ApiErrorCode::UnsupportedVersion,
                "unsupported command format",
            ));
        }
        if envelope.integer("version")? != COMMAND_VERSION as i64 {
            return Err(crate::error::ApiError::new(
                crate::error::ApiErrorCode::UnsupportedVersion,
                "unsupported command version",
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
            "capabilities" => Ok(ApiCommand::Capabilities { request_id }),
            _ => Err(crate::error::ApiError::new(
                crate::error::ApiErrorCode::UnsupportedVersion,
                "unsupported operation",
            )),
        }
    }
}

fn record(request_id: String, payload: &mneme_core::Value) -> Result<ApiCommand, crate::ApiError> {
    let fields = Fields::new(payload)?;
    let scope = fields.scope("scope")?;
    let base = fields.revision("base-revision")?;
    let key = fields.text("idempotency-key")?.to_owned();
    let records = fields
        .field("records")?
        .as_sequence()
        .ok_or_else(|| crate::error::ApiError::invalid("records must be a sequence"))?
        .iter()
        .map(parse_record)
        .collect::<crate::error::CallResult<Vec<_>>>()?;
    let sources = match fields.optional("sources") {
        Some(value) => parse_sources(value)?,
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
    let fields = Fields::new(payload)?;
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
    let fields = Fields::new(payload)?;
    let modes = match fields.optional("modes") {
        Some(value) => parse_modes(value)?,
        None => std::collections::BTreeSet::from([mneme_recall::Mode::Lexical]),
    };
    Ok(ApiCommand::Recall {
        request_id,
        scope: fields.scope("scope")?,
        revision: fields.optional_revision("revision")?,
        query: fields.text("query")?.to_owned(),
        at: fields.timestamp("at")?,
        temporal: parse_temporal(fields.text("temporal").unwrap_or("current"))?,
        modes,
        allow_stale: fields.boolean_or("allow-stale", false),
        allow_fallback: fields.boolean_or("allow-fallback", true),
        allow_partial: fields.boolean_or("allow-partial", true),
        include_disputed: fields.boolean_or("include-disputed", false),
        include_hypothetical: fields.boolean_or("include-hypothetical", false),
        max_items: fields.usize_or("max-items", 8)?,
        max_context_bytes: fields.usize_or("max-context-bytes", 4096)?,
        max_quote_bytes: fields.usize_or("max-quote-bytes", 1024)?,
        max_time_ms: fields.u128_or("max-time-ms", 500)?,
    })
}

fn explain(request_id: String, payload: &mneme_core::Value) -> Result<ApiCommand, crate::ApiError> {
    let fields = Fields::new(payload)?;
    Ok(ApiCommand::Explain {
        request_id,
        scope: fields.scope("scope")?,
        assertion: fields.record("assertion")?,
        max_nodes: fields.usize_or("max-nodes", 64)?,
        max_excerpt_bytes: fields.usize_or("max-excerpt-bytes", 4096)?,
    })
}

fn revise(request_id: String, payload: &mneme_core::Value) -> Result<ApiCommand, crate::ApiError> {
    let fields = Fields::new(payload)?;
    Ok(ApiCommand::Revise {
        request_id,
        scope: fields.scope("scope")?,
        base: fields.revision("base-revision")?,
        key: fields.text("idempotency-key")?.to_owned(),
        assertion: fields.record("assertion")?,
        action: parse_action(fields.symbol("action")?)?,
        rationale: fields.text("rationale")?.to_owned(),
        decision: fields.record("decision")?,
        decision_revision: fields.revision_id("decision-revision")?,
        revised_revision: fields.revision_id("revised-revision")?,
        superseded_by: fields.optional_record("superseded-by")?,
    })
}

fn resume(request_id: String, payload: &mneme_core::Value) -> Result<ApiCommand, crate::ApiError> {
    let fields = Fields::new(payload)?;
    Ok(ApiCommand::Resume {
        request_id,
        scope: fields.scope("scope")?,
        checkpoint: fields.record("checkpoint")?,
    })
}

fn forget(request_id: String, payload: &mneme_core::Value) -> Result<ApiCommand, crate::ApiError> {
    let fields = Fields::new(payload)?;
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
    let fields = Fields::new(payload)?;
    Ok(ApiCommand::ProposalInspect {
        request_id,
        scope: fields.scope("scope")?,
        assertion: fields.record("assertion")?,
    })
}

fn parse_record(value: &mneme_core::Value) -> crate::error::CallResult<mneme_core::RecordEnvelope> {
    mneme_core::validate_record_value(value, &mneme_core::SchemaRegistry::production(), None)
        .map_err(crate::error::ApiError::diagnostics)
}

fn parse_sources(
    value: &mneme_core::Value,
) -> crate::error::CallResult<Vec<mneme_store::SourceBlobDraft>> {
    let sequence = value
        .as_sequence()
        .ok_or_else(|| crate::error::ApiError::invalid("sources must be a sequence"))?;
    sequence
        .iter()
        .map(|source| {
            let fields = Fields::new(source)?;
            let bytes = fields
                .field("bytes")?
                .as_bytes()
                .ok_or_else(|| {
                    crate::error::ApiError::invalid("source bytes must be a byte string")
                })?
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
) -> crate::error::CallResult<std::collections::BTreeSet<mneme_recall::Mode>> {
    let sequence = value
        .as_sequence()
        .ok_or_else(|| crate::error::ApiError::invalid("modes must be a sequence"))?;
    sequence
        .iter()
        .map(
            |value| match value.as_symbol().map(|symbol| symbol.as_str()) {
                Some("lexical") => Ok(mneme_recall::Mode::Lexical),
                Some("structured") => Ok(mneme_recall::Mode::Structured),
                Some("vector") => Ok(mneme_recall::Mode::Vector),
                _ => Err(crate::error::ApiError::invalid("unknown recall mode")),
            },
        )
        .collect()
}

fn parse_temporal(value: &str) -> crate::error::CallResult<mneme_recall::TemporalMode> {
    match value {
        "current" => Ok(mneme_recall::TemporalMode::Current),
        "historical" => Ok(mneme_recall::TemporalMode::Historical),
        "inspection" => Ok(mneme_recall::TemporalMode::Inspection),
        _ => Err(crate::error::ApiError::invalid("unknown temporal mode")),
    }
}

fn parse_action(value: &str) -> crate::error::CallResult<ReviseAction> {
    match value {
        "supersede" | "correct" => Ok(ReviseAction::Supersede),
        "dispute" => Ok(ReviseAction::Dispute),
        "retract" => Ok(ReviseAction::Retract),
        _ => Err(crate::error::ApiError::invalid("unknown revision action")),
    }
}

fn parse_selector(
    value: &mneme_core::Value,
) -> crate::error::CallResult<mneme_retention::Selector> {
    let fields = Fields::new(value)?;
    match fields.symbol("kind")? {
        "source" => Ok(mneme_retention::Selector::Source(fields.record("target")?)),
        "assertion" => Ok(mneme_retention::Selector::Assertion(
            fields.record("target")?,
        )),
        "source-support" => Ok(mneme_retention::Selector::SourceSupport(
            fields.record("target")?,
        )),
        "digest" => {
            let digest = mneme_core::ContentDigest::from_value(
                fields.field("target")?,
                &mneme_core::Path::root().field("target"),
            )
            .map_err(crate::error::ApiError::from_diagnostic)?;
            Ok(mneme_retention::Selector::Content(digest))
        }
        _ => Err(crate::error::ApiError::invalid("unknown forget selector")),
    }
}

fn parse_scope_text(text: &str) -> crate::error::CallResult<mneme_core::ScopeId> {
    let (class, local) = text
        .split_once(':')
        .ok_or_else(|| crate::error::ApiError::invalid("scope must be class:local"))?;
    let class = mneme_core::ScopeClass::parse(class)
        .ok_or_else(|| crate::error::ApiError::invalid("unknown scope class"))?;
    mneme_core::ScopeId::new(class, local).map_err(crate::error::ApiError::invalid)
}

struct Fields<'a> {
    values: &'a std::collections::BTreeMap<mneme_core::Value, mneme_core::Value>,
}

impl<'a> Fields<'a> {
    fn new(value: &'a mneme_core::Value) -> crate::error::CallResult<Self> {
        let values = value
            .as_dictionary()
            .ok_or_else(|| crate::error::ApiError::invalid("expected an object"))?;
        Ok(Fields { values })
    }

    fn field(&self, name: &str) -> crate::error::CallResult<&'a mneme_core::Value> {
        self.values
            .get(&mneme_core::Value::symbol(name))
            .ok_or_else(|| crate::error::ApiError::invalid(format!("missing field {name}")))
    }

    fn optional(&self, name: &str) -> Option<&'a mneme_core::Value> {
        self.values.get(&mneme_core::Value::symbol(name))
    }

    fn text(&self, name: &str) -> crate::error::CallResult<&'a str> {
        self.field(name)?
            .as_string()
            .ok_or_else(|| crate::error::ApiError::invalid(format!("{name} must be text")))
    }

    fn symbol(&self, name: &str) -> crate::error::CallResult<&'a str> {
        self.field(name)?
            .as_symbol()
            .map(|symbol| symbol.as_str())
            .ok_or_else(|| crate::error::ApiError::invalid(format!("{name} must be a symbol")))
    }

    fn integer(&self, name: &str) -> crate::error::CallResult<i64> {
        self.field(name)?
            .as_integer()
            .and_then(|integer| integer.to_i64())
            .ok_or_else(|| crate::error::ApiError::invalid(format!("{name} must be an integer")))
    }

    fn boolean_or(&self, name: &str, default: bool) -> bool {
        self.optional(name)
            .and_then(mneme_core::Value::as_boolean)
            .unwrap_or(default)
    }

    fn usize_or(&self, name: &str, default: usize) -> crate::error::CallResult<usize> {
        match self.optional(name) {
            Some(value) => value
                .as_integer()
                .and_then(|integer| integer.to_i64())
                .and_then(|integer| usize::try_from(integer).ok())
                .ok_or_else(|| {
                    crate::error::ApiError::invalid(format!(
                        "{name} must be a non-negative integer"
                    ))
                }),
            None => Ok(default),
        }
    }

    fn u128_or(&self, name: &str, default: u128) -> crate::error::CallResult<u128> {
        match self.optional(name) {
            Some(value) => value
                .as_integer()
                .and_then(|integer| integer.to_i64())
                .and_then(|integer| u128::try_from(integer).ok())
                .ok_or_else(|| {
                    crate::error::ApiError::invalid(format!(
                        "{name} must be a non-negative integer"
                    ))
                }),
            None => Ok(default),
        }
    }

    fn record(&self, name: &str) -> crate::error::CallResult<mneme_core::RecordId> {
        mneme_core::RecordId::from_value(self.field(name)?, &mneme_core::Path::root())
            .map_err(crate::error::ApiError::from_diagnostic)
    }

    fn optional_record(
        &self,
        name: &str,
    ) -> crate::error::CallResult<Option<mneme_core::RecordId>> {
        self.optional(name)
            .map(|value| {
                mneme_core::RecordId::from_value(value, &mneme_core::Path::root())
                    .map_err(crate::error::ApiError::from_diagnostic)
            })
            .transpose()
    }

    fn revision(&self, name: &str) -> crate::error::CallResult<mneme_core::WorkspaceRevisionId> {
        mneme_core::WorkspaceRevisionId::from_value(self.field(name)?, &mneme_core::Path::root())
            .map_err(crate::error::ApiError::from_diagnostic)
    }

    fn optional_revision(
        &self,
        name: &str,
    ) -> crate::error::CallResult<Option<mneme_core::WorkspaceRevisionId>> {
        self.optional(name)
            .map(|value| {
                mneme_core::WorkspaceRevisionId::from_value(value, &mneme_core::Path::root())
                    .map_err(crate::error::ApiError::from_diagnostic)
            })
            .transpose()
    }

    fn revision_id(&self, name: &str) -> crate::error::CallResult<mneme_core::RevisionId> {
        mneme_core::RevisionId::from_value(self.field(name)?, &mneme_core::Path::root())
            .map_err(crate::error::ApiError::from_diagnostic)
    }

    fn scope(&self, name: &str) -> crate::error::CallResult<mneme_core::ScopeId> {
        let value = self.field(name)?;
        if let Some(text) = value.as_string() {
            return parse_scope_text(text);
        }
        mneme_core::ScopeId::from_value(value, &mneme_core::Path::root())
            .map_err(crate::error::ApiError::from_diagnostic)
    }

    fn timestamp(&self, name: &str) -> crate::error::CallResult<mneme_core::Timestamp> {
        let text = self.text(name)?;
        mneme_core::Timestamp::parse(text)
            .map_err(|message| crate::error::ApiError::invalid(format!("{name}: {message}")))
    }

    fn optional_timestamp(
        &self,
        name: &str,
    ) -> crate::error::CallResult<Option<mneme_core::Timestamp>> {
        self.optional(name)
            .map(|value| {
                value
                    .as_string()
                    .ok_or_else(|| crate::error::ApiError::invalid(format!("{name} must be text")))
                    .and_then(|text| {
                        mneme_core::Timestamp::parse(text).map_err(|message| {
                            crate::error::ApiError::invalid(format!("{name}: {message}"))
                        })
                    })
            })
            .transpose()
    }
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
