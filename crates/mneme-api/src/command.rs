//! Versioned tagged-JSON command envelopes and local session authorization.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use mneme_core::{
    ContentDigest, Diagnostic, RecordEnvelope, RecordId, RevisionId, SchemaRegistry, ScopeClass,
    ScopeId, Timestamp, Value, WorkspaceRevisionId, validate_record_value,
};
use mneme_recall::{RecallMode, TemporalMode};
use mneme_retention::Selector;
use mneme_store::SourceBlobDraft;
use serde::Deserialize;

use crate::error::{ApiError, ApiResult};

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
    pub workspace_root: PathBuf,
    pub scopes: Vec<String>,
}

/// A loaded session. Scope labels are matched against this allowlist.
#[derive(Clone, Debug)]
pub struct LocalSession {
    pub principal: String,
    pub workspace_root: PathBuf,
    scopes: BTreeSet<ScopeId>,
}

impl LocalSession {
    pub fn load(path: &Path) -> ApiResult<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| ApiError::invalid(format!("cannot read session file: {error}")))?;
        let config: SessionConfig = serde_json::from_str(&text)
            .map_err(|error| ApiError::invalid(format!("invalid session file: {error}")))?;
        if config.principal.trim().is_empty() {
            return Err(ApiError::invalid("session principal must not be empty"));
        }
        let mut scopes = BTreeSet::new();
        for scope in config.scopes {
            scopes.insert(parse_scope_text(&scope)?);
        }
        Ok(LocalSession {
            principal: config.principal,
            workspace_root: config.workspace_root,
            scopes,
        })
    }

    pub fn authorize(&self, scope: &ScopeId) -> ApiResult<()> {
        if self.scopes.contains(scope) {
            Ok(())
        } else {
            Err(ApiError::denied())
        }
    }

    pub fn scopes(&self) -> impl Iterator<Item = &ScopeId> {
        self.scopes.iter()
    }
}

/// One validated API command.
#[derive(Clone, Debug)]
pub enum ApiCommand {
    Record {
        request_id: String,
        scope: ScopeId,
        base: WorkspaceRevisionId,
        key: String,
        records: Vec<RecordEnvelope>,
        sources: Vec<SourceBlobDraft>,
    },
    Accept {
        request_id: String,
        scope: ScopeId,
        base: WorkspaceRevisionId,
        key: String,
        assertion: RecordId,
        decision: RecordId,
        decision_revision: RevisionId,
        accepted_revision: RevisionId,
        policy: String,
        rationale: String,
    },
    Recall {
        request_id: String,
        scope: ScopeId,
        revision: Option<WorkspaceRevisionId>,
        query: String,
        at: Timestamp,
        temporal: TemporalMode,
        modes: BTreeSet<RecallMode>,
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
        scope: ScopeId,
        assertion: RecordId,
        max_nodes: usize,
        max_excerpt_bytes: usize,
    },
    Revise {
        request_id: String,
        scope: ScopeId,
        base: WorkspaceRevisionId,
        key: String,
        assertion: RecordId,
        action: ReviseAction,
        rationale: String,
        decision: RecordId,
        decision_revision: RevisionId,
        revised_revision: RevisionId,
        superseded_by: Option<RecordId>,
    },
    Resume {
        request_id: String,
        scope: ScopeId,
        checkpoint: RecordId,
    },
    Forget {
        request_id: String,
        scope: ScopeId,
        base: WorkspaceRevisionId,
        key: String,
        selector: Selector,
        effective: Option<Timestamp>,
    },
    ProposalInspect {
        request_id: String,
        scope: ScopeId,
        assertion: RecordId,
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

    pub fn scope(&self) -> Option<&ScopeId> {
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

    pub fn from_value(value: &Value) -> ApiResult<Self> {
        let envelope = Fields::new(value)?;
        if envelope.text("format")? != COMMAND_FORMAT {
            return Err(ApiError::new(
                crate::error::ApiErrorCode::UnsupportedVersion,
                "unsupported command format",
            ));
        }
        if envelope.integer("version")? != COMMAND_VERSION as i64 {
            return Err(ApiError::new(
                crate::error::ApiErrorCode::UnsupportedVersion,
                "unsupported command version",
            ));
        }
        let request_id = envelope.text("request-id")?.to_owned();
        let operation = envelope.symbol("operation")?;
        let payload = envelope.field("payload")?;
        match operation {
            "record" => {
                let fields = Fields::new(payload)?;
                let scope = fields.scope("scope")?;
                let base = fields.revision("base-revision")?;
                let key = fields.text("idempotency-key")?.to_owned();
                let records = fields
                    .field("records")?
                    .as_sequence()
                    .ok_or_else(|| ApiError::invalid("records must be a sequence"))?
                    .iter()
                    .map(parse_record)
                    .collect::<ApiResult<Vec<_>>>()?;
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
            "accept" => {
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
            "recall" => {
                let fields = Fields::new(payload)?;
                let modes = match fields.optional("modes") {
                    Some(value) => parse_modes(value)?,
                    None => BTreeSet::from([RecallMode::Lexical]),
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
            "explain" => {
                let fields = Fields::new(payload)?;
                Ok(ApiCommand::Explain {
                    request_id,
                    scope: fields.scope("scope")?,
                    assertion: fields.record("assertion")?,
                    max_nodes: fields.usize_or("max-nodes", 64)?,
                    max_excerpt_bytes: fields.usize_or("max-excerpt-bytes", 4096)?,
                })
            }
            "revise" => {
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
            "resume" => {
                let fields = Fields::new(payload)?;
                Ok(ApiCommand::Resume {
                    request_id,
                    scope: fields.scope("scope")?,
                    checkpoint: fields.record("checkpoint")?,
                })
            }
            "forget" => {
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
            "proposal.inspect" => {
                let fields = Fields::new(payload)?;
                Ok(ApiCommand::ProposalInspect {
                    request_id,
                    scope: fields.scope("scope")?,
                    assertion: fields.record("assertion")?,
                })
            }
            "capabilities" => Ok(ApiCommand::Capabilities { request_id }),
            _ => Err(ApiError::new(
                crate::error::ApiErrorCode::UnsupportedVersion,
                "unsupported operation",
            )),
        }
    }
}

fn parse_record(value: &Value) -> ApiResult<RecordEnvelope> {
    validate_record_value(value, &SchemaRegistry::production(), None).map_err(ApiError::diagnostics)
}

fn parse_sources(value: &Value) -> ApiResult<Vec<SourceBlobDraft>> {
    let sequence = value
        .as_sequence()
        .ok_or_else(|| ApiError::invalid("sources must be a sequence"))?;
    sequence
        .iter()
        .map(|source| {
            let fields = Fields::new(source)?;
            let bytes = fields
                .field("bytes")?
                .as_bytes()
                .ok_or_else(|| ApiError::invalid("source bytes must be a byte string"))?
                .to_vec();
            let media_type = fields.text("media-type")?.to_owned();
            Ok(SourceBlobDraft {
                bytes,
                media_type: media_type.as_str().into(),
            })
        })
        .collect()
}

fn parse_modes(value: &Value) -> ApiResult<BTreeSet<RecallMode>> {
    let sequence = value
        .as_sequence()
        .ok_or_else(|| ApiError::invalid("modes must be a sequence"))?;
    sequence
        .iter()
        .map(
            |value| match value.as_symbol().map(|symbol| symbol.as_str()) {
                Some("lexical") => Ok(RecallMode::Lexical),
                Some("structured") => Ok(RecallMode::Structured),
                Some("vector") => Ok(RecallMode::Vector),
                _ => Err(ApiError::invalid("unknown recall mode")),
            },
        )
        .collect()
}

fn parse_temporal(value: &str) -> ApiResult<TemporalMode> {
    match value {
        "current" => Ok(TemporalMode::Current),
        "historical" => Ok(TemporalMode::Historical),
        "inspection" => Ok(TemporalMode::Inspection),
        _ => Err(ApiError::invalid("unknown temporal mode")),
    }
}

fn parse_action(value: &str) -> ApiResult<ReviseAction> {
    match value {
        "supersede" | "correct" => Ok(ReviseAction::Supersede),
        "dispute" => Ok(ReviseAction::Dispute),
        "retract" => Ok(ReviseAction::Retract),
        _ => Err(ApiError::invalid("unknown revision action")),
    }
}

fn parse_selector(value: &Value) -> ApiResult<Selector> {
    let fields = Fields::new(value)?;
    match fields.symbol("kind")? {
        "source" => Ok(Selector::Source(fields.record("target")?)),
        "assertion" => Ok(Selector::Assertion(fields.record("target")?)),
        "source-support" => Ok(Selector::SourceSupport(fields.record("target")?)),
        "digest" => {
            let digest = ContentDigest::from_value(
                fields.field("target")?,
                &mneme_core::Path::root().field("target"),
            )
            .map_err(ApiError::from_diagnostic)?;
            Ok(Selector::Content(digest))
        }
        _ => Err(ApiError::invalid("unknown forget selector")),
    }
}

fn parse_scope_text(text: &str) -> ApiResult<ScopeId> {
    let (class, local) = text
        .split_once(':')
        .ok_or_else(|| ApiError::invalid("scope must be class:local"))?;
    let class = ScopeClass::parse(class).ok_or_else(|| ApiError::invalid("unknown scope class"))?;
    ScopeId::new(class, local).map_err(ApiError::invalid)
}

struct Fields<'a> {
    values: &'a std::collections::BTreeMap<Value, Value>,
}

impl<'a> Fields<'a> {
    fn new(value: &'a Value) -> ApiResult<Self> {
        let values = value
            .as_dictionary()
            .ok_or_else(|| ApiError::invalid("expected an object"))?;
        Ok(Fields { values })
    }

    fn field(&self, name: &str) -> ApiResult<&'a Value> {
        self.values
            .get(&Value::symbol(name))
            .ok_or_else(|| ApiError::invalid(format!("missing field {name}")))
    }

    fn optional(&self, name: &str) -> Option<&'a Value> {
        self.values.get(&Value::symbol(name))
    }

    fn text(&self, name: &str) -> ApiResult<&'a str> {
        self.field(name)?
            .as_string()
            .ok_or_else(|| ApiError::invalid(format!("{name} must be text")))
    }

    fn symbol(&self, name: &str) -> ApiResult<&'a str> {
        self.field(name)?
            .as_symbol()
            .map(|symbol| symbol.as_str())
            .ok_or_else(|| ApiError::invalid(format!("{name} must be a symbol")))
    }

    fn integer(&self, name: &str) -> ApiResult<i64> {
        self.field(name)?
            .as_integer()
            .and_then(|integer| integer.to_i64())
            .ok_or_else(|| ApiError::invalid(format!("{name} must be an integer")))
    }

    fn boolean_or(&self, name: &str, default: bool) -> bool {
        self.optional(name)
            .and_then(Value::as_boolean)
            .unwrap_or(default)
    }

    fn usize_or(&self, name: &str, default: usize) -> ApiResult<usize> {
        match self.optional(name) {
            Some(value) => value
                .as_integer()
                .and_then(|integer| integer.to_i64())
                .and_then(|integer| usize::try_from(integer).ok())
                .ok_or_else(|| ApiError::invalid(format!("{name} must be a non-negative integer"))),
            None => Ok(default),
        }
    }

    fn u128_or(&self, name: &str, default: u128) -> ApiResult<u128> {
        match self.optional(name) {
            Some(value) => value
                .as_integer()
                .and_then(|integer| integer.to_i64())
                .and_then(|integer| u128::try_from(integer).ok())
                .ok_or_else(|| ApiError::invalid(format!("{name} must be a non-negative integer"))),
            None => Ok(default),
        }
    }

    fn record(&self, name: &str) -> ApiResult<RecordId> {
        RecordId::from_value(self.field(name)?, &mneme_core::Path::root())
            .map_err(ApiError::from_diagnostic)
    }

    fn optional_record(&self, name: &str) -> ApiResult<Option<RecordId>> {
        self.optional(name)
            .map(|value| {
                RecordId::from_value(value, &mneme_core::Path::root())
                    .map_err(ApiError::from_diagnostic)
            })
            .transpose()
    }

    fn revision(&self, name: &str) -> ApiResult<WorkspaceRevisionId> {
        WorkspaceRevisionId::from_value(self.field(name)?, &mneme_core::Path::root())
            .map_err(ApiError::from_diagnostic)
    }

    fn optional_revision(&self, name: &str) -> ApiResult<Option<WorkspaceRevisionId>> {
        self.optional(name)
            .map(|value| {
                WorkspaceRevisionId::from_value(value, &mneme_core::Path::root())
                    .map_err(ApiError::from_diagnostic)
            })
            .transpose()
    }

    fn revision_id(&self, name: &str) -> ApiResult<RevisionId> {
        RevisionId::from_value(self.field(name)?, &mneme_core::Path::root())
            .map_err(ApiError::from_diagnostic)
    }

    fn scope(&self, name: &str) -> ApiResult<ScopeId> {
        let value = self.field(name)?;
        if let Some(text) = value.as_string() {
            return parse_scope_text(text);
        }
        ScopeId::from_value(value, &mneme_core::Path::root()).map_err(ApiError::from_diagnostic)
    }

    fn timestamp(&self, name: &str) -> ApiResult<Timestamp> {
        let text = self.text(name)?;
        Timestamp::parse(text).map_err(|message| ApiError::invalid(format!("{name}: {message}")))
    }

    fn optional_timestamp(&self, name: &str) -> ApiResult<Option<Timestamp>> {
        self.optional(name)
            .map(|value| {
                value
                    .as_string()
                    .ok_or_else(|| ApiError::invalid(format!("{name} must be text")))
                    .and_then(|text| {
                        Timestamp::parse(text)
                            .map_err(|message| ApiError::invalid(format!("{name}: {message}")))
                    })
            })
            .transpose()
    }
}

/// Convert a validated envelope to a coordinator draft.
pub fn record_draft(record: RecordEnvelope) -> mneme_store::RecordDraft {
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
pub fn decode_command(text: &str) -> ApiResult<ApiCommand> {
    let value = mneme_core::decode_document(text).map_err(ApiError::from_diagnostic)?;
    ApiCommand::from_value(&value)
}

/// Field diagnostic helper for adapters.
pub fn diagnostic_fields(diagnostics: Vec<Diagnostic>) -> Value {
    Value::sequence(
        diagnostics
            .into_iter()
            .map(|diagnostic| Value::string(diagnostic.to_string()))
            .collect(),
    )
}
