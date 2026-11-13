//! Source-first AsciiDoc documents over the committed workspace.
//!
//! Exact source bytes are authoritative. Documents have stable identities,
//! optional literal entity bindings, pinned include closures, explicit anchors,
//! a restricted sanitized preview, and revision-bound extraction candidates.
#![allow(unknown_lints)] // Octet structural exception: domain-qualified names and macro-only imports are intentional
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod asciidoc;
pub mod images;

pub use asciidoc::{AnchorSpec, Diagnostic, Header, IncludeDirective};

/// The document schema version emitted by this build.
pub const DOCUMENT_SCHEMA_VERSION: u32 = 3;
/// The preview processor version.
pub const PROCESSOR_VERSION: &str = "mneme-asciidoc/0.2";
/// The preview configuration version.
pub const RENDER_CONFIG_VERSION: &str = "mneme-preview/v1";
const MAX_INCLUDE_ENTRIES: usize = 1_000_000;

/// Bounded include and import policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentPolicy {
    /// Authorized logical path prefixes. An empty list denies every include.
    pub allowed_roots: Vec<String>,
    pub max_depth: usize,
    pub max_inputs: usize,
    pub max_total_source_bytes: usize,
    pub max_expanded_bytes: usize,
    pub max_time_ms: u128,
}

impl Default for DocumentPolicy {
    fn default() -> Self {
        DocumentPolicy {
            allowed_roots: vec![String::new()],
            max_depth: 8,
            max_inputs: 64,
            max_total_source_bytes: 4 * 1024 * 1024,
            max_expanded_bytes: 8 * 1024 * 1024,
            max_time_ms: 1_000,
        }
    }
}

/// Versioned preview rendering configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderConfig {
    pub version: String,
    pub include_entity_metadata: bool,
    pub max_output_bytes: usize,
    pub max_time_ms: u128,
}

impl Default for RenderConfig {
    fn default() -> Self {
        RenderConfig {
            version: RENDER_CONFIG_VERSION.to_owned(),
            include_entity_metadata: true,
            max_output_bytes: 8 * 1024 * 1024,
            max_time_ms: 1_000,
        }
    }
}

/// A pinned source record and exact revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourcePin {
    pub source: mneme_core::RecordId,
    pub revision: mneme_core::RevisionId,
}

/// A parsed current or historical Document record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentView {
    pub record: mneme_core::RecordEnvelope,
    pub title: String,
    pub entity: Option<mneme_core::RecordId>,
    pub source: SourcePin,
    /// Version-one documents may use a snapshot-local source reference.
    pub source_is_pinned: bool,
    pub path: Option<String>,
    pub binding: Option<mneme_core::RecordId>,
    pub includes: std::collections::BTreeMap<String, SourcePin>,
    pub render_config: String,
}

/// A bounded inventory entry for one current document.
///
/// The summary is a read-only query value. It carries the canonical document
/// identity and revision so a client can open the document without resolving a
/// title or path again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentSummary {
    pub document_id: mneme_core::RecordId,
    pub revision: mneme_core::RevisionId,
    pub scope: mneme_core::ScopeId,
    pub title: String,
    pub path: Option<String>,
    pub entity: Option<mneme_core::RecordId>,
}

/// The retained current source of one document.
///
/// `source` is `None` when retention currently suppresses the source. A caller
/// that scans notes must treat that as a skipped note, not as empty content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentSource {
    pub document_id: mneme_core::RecordId,
    pub scope: mneme_core::ScopeId,
    pub title: String,
    pub path: Option<String>,
    pub source: Option<Vec<u8>>,
}

/// One include occurrence observed while scanning a document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncludeOccurrence {
    pub including_path: String,
    pub target_path: String,
    pub directive_span: mneme_core::SourceSpan,
    pub source: SourcePin,
}

/// One included source in a preview closure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncludedSource {
    pub path: String,
    pub pin: SourcePin,
    pub digest: Option<mneme_core::ContentDigest>,
}

/// A bounded preview artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewArtifact {
    pub document: mneme_core::RecordId,
    pub document_revision: mneme_core::RevisionId,
    pub workspace_revision: mneme_core::WorkspaceRevisionId,
    pub generation: u64,
    pub path: String,
    pub title: String,
    pub entity: Option<mneme_core::RecordId>,
    pub source: SourcePin,
    pub source_digest: Option<mneme_core::ContentDigest>,
    pub config_version: String,
    pub config_fingerprint: String,
    pub processor_version: String,
    pub html: String,
    pub included: Vec<IncludedSource>,
    pub occurrences: Vec<IncludeOccurrence>,
    pub diagnostics: Vec<Diagnostic>,
    pub source_available: bool,
    /// Whether a limit stopped the render, so the result is explicitly partial.
    pub truncated: bool,
}

/// The identity of a preview in a bounded cache.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PreviewKey {
    pub document: mneme_core::RecordId,
    pub document_revision: mneme_core::RevisionId,
    pub generation: u64,
    pub config_version: String,
    pub config_fingerprint: String,
    pub processor_version: String,
    pub includes: Vec<(String, mneme_core::RecordId, mneme_core::RevisionId)>,
}

impl PreviewArtifact {
    /// The cache identity derived from this artifact.
    pub fn key(&self) -> PreviewKey {
        let mut includes = self
            .included
            .iter()
            .map(|included| {
                (
                    included.path.clone(),
                    included.pin.source,
                    included.pin.revision,
                )
            })
            .collect::<Vec<_>>();
        includes.sort();
        PreviewKey {
            document: self.document,
            document_revision: self.document_revision,
            generation: self.generation,
            config_version: self.config_version.clone(),
            config_fingerprint: self.config_fingerprint.clone(),
            processor_version: self.processor_version.clone(),
            includes,
        }
    }
}

/// A bounded preview cache. Entries are reusable only under an exact key.
#[derive(Clone, Debug, Default)]
pub struct PreviewCache {
    entries: std::collections::BTreeMap<PreviewKey, PreviewArtifact>,
}

impl PreviewCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        PreviewCache::default()
    }

    /// Read a matching artifact.
    pub fn get(&self, key: &PreviewKey) -> Option<&PreviewArtifact> {
        self.entries.get(key)
    }

    /// Store an artifact under its exact key.
    pub fn insert(&mut self, artifact: PreviewArtifact) -> PreviewKey {
        let key = artifact.key();
        self.entries.insert(key.clone(), artifact);
        key
    }

    /// Drop every cached artifact for one document.
    pub fn invalidate_document(&mut self, document: mneme_core::RecordId) {
        self.entries.retain(|key, _| key.document != document);
    }
}

/// A validated but uncommitted document candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedDocument {
    pub candidate_id: String,
    pub base_revision: mneme_core::WorkspaceRevisionId,
    pub document_id: Option<mneme_core::RecordId>,
    pub path: String,
    pub title: String,
    pub entity: Option<mneme_core::RecordId>,
    pub source_digest: mneme_core::ContentDigest,
    pub anchors: Vec<AnchorSpec>,
    pub includes: Vec<IncludedSource>,
    pub diagnostics: Vec<Diagnostic>,
    pub preview_diagnostics: Vec<Diagnostic>,
    pub valid: bool,
    pub preview_html: String,
}

/// A committed document revision and its separately observed publication result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentRevision {
    pub document_id: mneme_core::RecordId,
    pub document_revision: mneme_core::RevisionId,
    pub source: SourcePin,
    pub source_digest: mneme_core::ContentDigest,
    pub workspace_revision: mneme_core::WorkspaceRevisionId,
    pub sequence: u64,
    pub path: String,
    pub entity: Option<mneme_core::RecordId>,
    pub anchors: Vec<mneme_core::RecordId>,
    pub includes: Vec<IncludedSource>,
    pub publications: Vec<mneme_store::PublicationOutcome>,
    /// The outcome of retiring the managed working copy a move left behind.
    ///
    /// `None` for every operation that does not change the logical path. The
    /// destination write is reported through `publications`; this field reports
    /// only what became of the file at the old path.
    pub retired_working_copy: Option<WorkingCopyRetirement>,
}

/// What became of the managed working copy at a move's old path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkingCopyRetirement {
    /// The old path held exactly the committed bytes and was removed.
    Removed,
    /// Nothing was at the old path.
    Absent,
    /// The old path no longer held the committed bytes, so it was kept.
    Diverged,
    /// The old path was not a regular file, so it was kept.
    Unsupported,
    /// The retirement step failed; the copy may still be at the old path.
    Failed,
}

/// A revision-bound extraction candidate. It is not an accepted assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtractionCandidate {
    pub document: mneme_core::RecordId,
    pub origin_path: String,
    pub source: SourcePin,
    pub span: mneme_core::SourceSpan,
    pub text: String,
    pub occurrences: Vec<IncludeOccurrence>,
}

/// A request to import or save a document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportRequest {
    pub actor: String,
    pub scope: mneme_core::ScopeId,
    pub base_revision: mneme_core::WorkspaceRevisionId,
    pub idempotency_key: String,
    /// Existing identity for an update; omitted for a new document.
    pub document_id: Option<mneme_core::RecordId>,
    pub path: String,
    pub title: Option<String>,
    pub policy: DocumentPolicy,
    pub render_config: RenderConfig,
}

/// A binding patch request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingRequest {
    pub import: ImportRequest,
    pub entity: Option<mneme_core::RecordId>,
    pub publish: bool,
}

/// A document move request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MoveRequest {
    pub actor: String,
    pub scope: mneme_core::ScopeId,
    pub base_revision: mneme_core::WorkspaceRevisionId,
    pub idempotency_key: String,
    pub document_id: mneme_core::RecordId,
    pub path: String,
    /// Optional new title committed in the same revision as the path.
    pub title: Option<String>,
}

/// A structured entity-property edit request.
pub struct EntityPropertyEditRequest<'a> {
    pub actor: &'a str,
    pub scope: &'a mneme_core::ScopeId,
    pub base_revision: mneme_core::WorkspaceRevisionId,
    pub idempotency_key: &'a str,
    pub entity_id: mneme_core::RecordId,
    pub property: &'a str,
    pub value: Option<mneme_core::Value>,
}

/// Failure of a document operation.
#[derive(Debug, thiserror::Error)]
pub enum DocumentError {
    #[error(transparent)]
    Store(#[from] mneme_store::Failure),
    #[error(transparent)]
    Engine(#[from] mneme_memory::EvidenceError),
    #[error("document validation failed")]
    Diagnostics(Vec<Diagnostic>),
    #[error("invalid document request: {0}")]
    Invalid(&'static str),
    #[error("document {0} is missing")]
    Missing(mneme_core::RecordId),
    #[error("operation conflicts with committed document state: {0}")]
    Conflict(&'static str),
    #[error("document I/O failed: {0}")]
    Io(String),
}

/// A document result.
pub type Result<T, E = DocumentError> = std::result::Result<T, E>;

/// One mutating document request as the adapter binds it to its idempotency key.
///
/// The store records this fingerprint with the command row, so a retry replays
/// only when it repeats the same operation, target, path, bytes and options. A
/// reused key with any other content is an idempotency conflict instead of a
/// silent reuse of an unrelated outcome.
///
/// The caller's base revision is deliberately absent. Every document caller
/// derives it from the workspace immediately before the call, so a retry after
/// a lost response presents a newer base while the request it repeats is
/// unchanged; the base still governs the commit's compare-and-swap whenever the
/// request is fresh.
struct BoundDocumentRequest<'a> {
    operation: &'a str,
    scope: &'a mneme_core::ScopeId,
    target: Option<mneme_core::RecordId>,
    path: Option<&'a str>,
    source_digest: Option<mneme_core::ContentDigest>,
    options: Vec<mneme_core::Value>,
}

fn document_request_fingerprint(request: &BoundDocumentRequest<'_>) -> mneme_core::ContentDigest {
    let mut fields = Vec::with_capacity(request.options.len().saturating_add(5));
    fields.push(mneme_core::Value::symbol(request.operation));
    fields.push(request.scope.to_value());
    fields.push(match request.target {
        Some(target) => target.to_value(),
        None => mneme_core::Value::symbol("none"),
    });
    fields.push(match request.path {
        Some(path) => mneme_core::Value::string(path),
        None => mneme_core::Value::symbol("none"),
    });
    fields.push(match request.source_digest {
        Some(digest) => digest.to_value(),
        None => mneme_core::Value::symbol("none"),
    });
    fields.extend(request.options.iter().cloned());
    mneme_core::request_fingerprint(&mneme_core::Value::record_named(
        format!("{}-request", request.operation),
        fields,
    ))
}

/// The options of an import or save request, as a fingerprint field.
fn import_request_options(request: &ImportRequest) -> Result<Vec<mneme_core::Value>> {
    Ok(vec![
        match &request.title {
            Some(title) => mneme_core::Value::string(title.clone()),
            None => mneme_core::Value::symbol("none"),
        },
        document_policy_value(&request.policy)?,
        render_config_value(&request.render_config)?,
    ])
}

fn document_policy_value(policy: &DocumentPolicy) -> Result<mneme_core::Value> {
    Ok(mneme_core::Value::record_named(
        "document-policy",
        vec![
            mneme_core::Value::set(
                policy
                    .allowed_roots
                    .iter()
                    .cloned()
                    .map(mneme_core::Value::string),
            ),
            mneme_core::Value::integer(u64_field(policy.max_depth)?),
            mneme_core::Value::integer(u64_field(policy.max_inputs)?),
            mneme_core::Value::integer(u64_field(policy.max_total_source_bytes)?),
            mneme_core::Value::integer(u64_field(policy.max_expanded_bytes)?),
            mneme_core::Value::integer(u64_field(policy.max_time_ms)?),
        ],
    ))
}

fn render_config_value(config: &RenderConfig) -> Result<mneme_core::Value> {
    let metadata = if config.include_entity_metadata {
        "true"
    } else {
        "false"
    };
    Ok(mneme_core::Value::record_named(
        "render-config",
        vec![
            mneme_core::Value::string(config.version.clone()),
            mneme_core::Value::symbol(metadata),
            mneme_core::Value::integer(u64_field(config.max_output_bytes)?),
            mneme_core::Value::integer(u64_field(config.max_time_ms)?),
        ],
    ))
}

/// A bounded platform count as a fingerprint integer.
///
/// A limit this platform cannot represent as a fingerprint integer is refused
/// instead of being replaced by an extreme value, which would make two distinct
/// policies share one request fingerprint.
fn u64_field(value: impl TryInto<u64>) -> Result<u64> {
    value
        .try_into()
        .map_err(|_| DocumentError::Invalid("document limit exceeds the fingerprint integer width"))
}

/// The fingerprint of one move request.
///
/// It names only what the caller supplied. The document's current path is
/// workspace state that the first move changes, so including it would make
/// every retry of a committed move a conflict.
fn move_request_fingerprint(request: &MoveRequest) -> mneme_core::ContentDigest {
    document_request_fingerprint(&BoundDocumentRequest {
        operation: "document-move",
        scope: &request.scope,
        target: Some(request.document_id),
        path: Some(&request.path),
        source_digest: None,
        options: vec![match &request.title {
            Some(title) => mneme_core::Value::string(title.clone()),
            None => mneme_core::Value::symbol("none"),
        }],
    })
}

/// The committed side of a move: what the commit retires or publishes besides
/// the record itself.
struct MovePreparation {
    old_path: String,
    source_digest: mneme_core::ContentDigest,
    publications: Vec<mneme_store::PublicationDraft>,
    draft: mneme_store::RecordDraft,
}

/// Build the moved document record and the publication that follows it.
///
/// The working file follows the record through a publication intent in the
/// same commit, so a crash after the commit is resumed by `Workspace::recover`
/// / `publish_pending` instead of leaving no file at the new path.
fn prepare_move(
    workspace_root: &std::path::Path,
    context: &DocumentContext,
    document: &DocumentView,
    request: &MoveRequest,
    title: Option<String>,
) -> Result<MovePreparation> {
    let old_path = document
        .path
        .clone()
        .ok_or(DocumentError::Conflict("document has no logical path"))?;
    let (_, source_bytes) = context.require_retained_source(document.source)?;
    let source_digest = mneme_core::ContentDigest::of_source_bytes(&source_bytes);
    let expected_previous = destination_expectation(workspace_root, &request.path, source_digest)?;
    let publications = vec![mneme_store::PublicationDraft {
        path: request.path.clone(),
        expected_previous,
        bytes: source_bytes,
    }];
    let mut payload = document.record.payload.clone();
    payload.insert(
        mneme_core::Symbol::from("path"),
        mneme_core::Value::string(request.path.clone()),
    );
    if let Some(title) = title {
        payload.insert(
            mneme_core::Symbol::from("title"),
            mneme_core::Value::string(title),
        );
    }
    let draft = mneme_store::RecordDraft {
        schema_version: DOCUMENT_SCHEMA_VERSION,
        kind: mneme_core::RecordKind::Document,
        record_id: document.record.record_id,
        revision_id: fresh_revision()?,
        predecessor: Some(document.record.revision_id),
        scope: document.record.scope.clone(),
        payload,
    };
    Ok(MovePreparation {
        old_path,
        source_digest,
        publications,
        draft,
    })
}

struct DocumentContext {
    view: mneme_memory::View,
    documents: std::collections::BTreeMap<mneme_core::RecordId, DocumentView>,
    paths: std::collections::BTreeMap<String, mneme_core::RecordId>,
    entities: std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RecordEnvelope>,
    generation: u64,
}

impl DocumentContext {
    #[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
    fn load(
        workspace: &mneme_store::Workspace,
        revision: Option<mneme_core::WorkspaceRevisionId>,
    ) -> Result<Self> {
        let revision = revision.unwrap_or(workspace.current_revision()?);
        let snapshot = workspace.snapshot_at(revision, None)?;
        let max_context_records = 1_000_000;
        if snapshot.records.len() > max_context_records {
            return Err(DocumentError::Invalid(
                "document context exceeds the 1M record bound",
            ));
        }
        let context =
            mneme_memory::view_context(workspace, &snapshot).map_err(view_context_error)?;
        if context.history.len() > max_context_records {
            return Err(DocumentError::Invalid(
                "document history exceeds the 1M revision bound",
            ));
        }
        let suppressions = workspace.active_suppressions()?;
        let view = mneme_memory::View::with_retention(
            snapshot.clone(),
            workspace.root(),
            context.history,
            context.revision_sequences,
            suppressions,
        )
        // Document commands are local operator work: every mutating call names
        // its scope and each operation re-checks it, while preview, anchor and
        // extraction reads address one already-authorized document identity.
        .with_access(mneme_memory::Access::Operator);
        let (documents, paths, entities) = index_documents(&snapshot, max_context_records)?;
        Ok(DocumentContext {
            generation: snapshot.eligibility_generation,
            view,
            documents,
            paths,
            entities,
        })
    }

    fn source(&self, pin: SourcePin) -> Result<mneme_memory::SourceView> {
        Ok(self.view.source_at(pin.source, pin.revision)?)
    }

    fn source_bytes(&self, pin: SourcePin) -> Result<Option<Vec<u8>>> {
        let source = self.source(pin)?;
        match self.view.source_status_for(&source)? {
            mneme_memory::SourceStatus::Retained(bytes) => Ok(Some(bytes)),
            _ => Ok(None),
        }
    }

    fn require_retained_source(
        &self,
        pin: SourcePin,
    ) -> Result<(mneme_memory::SourceView, Vec<u8>)> {
        let source = self.source(pin)?;
        match self.view.source_status_for(&source)? {
            mneme_memory::SourceStatus::Retained(bytes) => Ok((source, bytes)),
            status => Err(DocumentError::Diagnostics(vec![Diagnostic {
                code: "source-unavailable",
                message: format!("document source is {}", status.availability().name()),
                line: 1,
                column: 1,
                span: None,
                fatal: true,
            }])),
        }
    }
}

impl DocumentView {
    /// Parse a Document record.
    pub fn parse(record: mneme_core::RecordEnvelope) -> Result<Self> {
        if record.kind != mneme_core::RecordKind::Document {
            return Err(DocumentError::Invalid("record is not a document"));
        }
        let title = required_text(&record, "title")?;
        let source_reference = mneme_core::Reference::from_value(
            required(&record, "source-revision")?,
            &mneme_core::Path::root().field("source-revision"),
        )
        .map_err(|diagnostic| DocumentError::Io(diagnostic.to_string()))?;
        let (source, revision, source_is_pinned) = match source_reference {
            mneme_core::Reference::Pinned {
                target, revision, ..
            } => (target, revision, true),
            mneme_core::Reference::Local { target, .. } => {
                (target, mneme_core::RevisionId::from_bytes([0; 16]), false)
            }
            _ => {
                return Err(DocumentError::Invalid(
                    "document source-revision must be local or pinned",
                ));
            }
        };
        let entity = optional_reference_target(&record, "entity");
        let binding = optional_reference_target(&record, "binding");
        let path = record
            .payload
            .get("path")
            .and_then(mneme_core::Value::as_string)
            .map(str::to_owned);
        let render_config = record
            .payload
            .get("render-config")
            .and_then(mneme_core::Value::as_string)
            .unwrap_or(RENDER_CONFIG_VERSION)
            .to_owned();
        let includes = parse_include_map(&record)?;
        Ok(DocumentView {
            record,
            title,
            entity,
            source: SourcePin { source, revision },
            source_is_pinned,
            path,
            binding,
            includes,
            render_config,
        })
    }
}

#[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
fn parse_include_map(
    record: &mneme_core::RecordEnvelope,
) -> Result<std::collections::BTreeMap<String, SourcePin>> {
    let Some(value) = record.payload.get("includes") else {
        return Ok(std::collections::BTreeMap::new());
    };
    let dictionary = value
        .as_dictionary()
        .ok_or(DocumentError::Invalid("includes must be a dictionary"))?;
    let mut includes = std::collections::BTreeMap::new();
    for (path, reference_value) in dictionary {
        let Some(path) = path.as_string() else {
            return Err(DocumentError::Invalid("include path must be text"));
        };
        let reference = mneme_core::Reference::from_value(
            reference_value,
            &mneme_core::Path::root().field("includes"),
        )
        .map_err(|diagnostic| DocumentError::Io(diagnostic.to_string()))?;
        let mneme_core::Reference::Pinned {
            target, revision, ..
        } = reference
        else {
            return Err(DocumentError::Invalid(
                "include closure entries must be pinned",
            ));
        };
        if includes.len() >= MAX_INCLUDE_ENTRIES {
            return Err(DocumentError::Invalid(
                "document include closure exceeds the 1M entry bound",
            ));
        }
        includes.insert(
            path.to_owned(),
            SourcePin {
                source: target,
                revision,
            },
        );
    }
    Ok(includes)
}

fn required<'a>(
    record: &'a mneme_core::RecordEnvelope,
    name: &str,
) -> Result<&'a mneme_core::Value> {
    record.payload.get(name).ok_or(DocumentError::Invalid(
        "document record is missing a required field",
    ))
}

fn required_text(record: &mneme_core::RecordEnvelope, name: &str) -> Result<String> {
    required(record, name)?
        .as_string()
        .map(str::to_owned)
        .ok_or(DocumentError::Invalid(
            "document record text field is malformed",
        ))
}

fn optional_reference_target(
    record: &mneme_core::RecordEnvelope,
    name: &str,
) -> Option<mneme_core::RecordId> {
    record
        .payload
        .get(name)
        .and_then(|value| mneme_core::Reference::from_value(value, &mneme_core::Path::root()).ok())
        .and_then(|reference| reference.target())
}

fn normalized_listing_key(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn reference_is_pinned_to(record: &mneme_core::RecordEnvelope, name: &str, pin: SourcePin) -> bool {
    record
        .payload
        .get(name)
        .and_then(|value| mneme_core::Reference::from_value(value, &mneme_core::Path::root()).ok())
        .is_some_and(|reference| {
            matches!(
                reference,
                mneme_core::Reference::Pinned {
                    target,
                    revision,
                    ..
                } if target == pin.source && revision == pin.revision
            )
        })
}

fn fresh_id() -> Result<mneme_core::RecordId> {
    Ok(mneme_core::RecordId::from_bytes(
        mneme_store::payload::random_bytes()?,
    ))
}

fn fresh_revision() -> Result<mneme_core::RevisionId> {
    Ok(mneme_core::RevisionId::from_bytes(
        mneme_store::payload::random_bytes()?,
    ))
}

fn source_pin(source: mneme_core::RecordId, revision: mneme_core::RevisionId) -> SourcePin {
    SourcePin { source, revision }
}

mod preview;

struct ResolvedIncludes {
    closure: std::collections::BTreeMap<String, SourcePin>,
    sources: std::collections::BTreeMap<String, preview::RenderSource>,
    diagnostics: Vec<Diagnostic>,
    /// Source bytes resolved so far, charged before each read.
    used_bytes: u64,
}

struct IncludeResolutionRequest<'a> {
    context: &'a DocumentContext,
    scope: &'a mneme_core::ScopeId,
    root_path: &'a str,
    root_bytes: &'a [u8],
    policy: &'a DocumentPolicy,
    deadline: std::time::Instant,
}

#[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
fn resolve_import_includes(request: IncludeResolutionRequest<'_>) -> Result<ResolvedIncludes> {
    let limit = budget_count(request.policy.max_total_source_bytes);
    let root_bytes = budget_count(request.root_bytes.len());
    let Some(used_bytes) = mneme_kernel::budget::charge(0, root_bytes, limit) else {
        // The root document is part of the same byte budget as everything it
        // includes, and is charged before any include is resolved.
        return Err(DocumentError::Diagnostics(vec![Diagnostic::new(
            "source-byte-limit",
            "document source exceeds the configured byte limit",
            1,
            1,
            None,
        )]));
    };
    let mut resolved = ResolvedIncludes {
        closure: std::collections::BTreeMap::new(),
        sources: std::collections::BTreeMap::new(),
        diagnostics: Vec::new(),
        used_bytes,
    };
    let mut stack = std::collections::BTreeSet::new();
    stack.insert(request.root_path.to_owned());
    {
        let mut resolver = IncludeResolver {
            context: request.context,
            scope: request.scope,
            policy: request.policy,
            deadline: request.deadline,
            stack: &mut stack,
            resolved: &mut resolved,
        };
        resolve_include_bytes(&mut resolver, request.root_path, request.root_bytes, 0)?;
    }
    Ok(resolved)
}

/// A size or limit as the byte budget's counter type.
///
/// `usize` is at most 64 bits on every supported target, so widening a length
/// to the counter type is exact.
fn budget_count(value: usize) -> u64 {
    value as u64
}

#[allow(unknown_lints)] // include deadline is the import shell
fn resolve_include_bytes(
    resolver: &mut IncludeResolver<'_>,
    origin_path: &str,
    bytes: &[u8],
    depth: usize,
) -> Result<()> {
    resolver.resolve_bytes(origin_path, bytes, depth)
}

struct IncludeResolver<'a> {
    context: &'a DocumentContext,
    scope: &'a mneme_core::ScopeId,
    policy: &'a DocumentPolicy,
    deadline: std::time::Instant,
    stack: &'a mut std::collections::BTreeSet<String>,
    resolved: &'a mut ResolvedIncludes,
}

impl IncludeResolver<'_> {
    fn resolve_bytes(&mut self, origin_path: &str, bytes: &[u8], depth: usize) -> Result<()> {
        self.check_limits(depth)?;
        let text = std::str::from_utf8(bytes).map_err(|error| {
            DocumentError::Diagnostics(vec![Diagnostic::new(
                "invalid-utf8",
                "included source is not valid UTF-8",
                1,
                error.valid_up_to(),
                None,
            )])
        })?;
        // An include attribute the supported subset cannot honour is a fatal
        // source-local diagnostic: rendering or extracting the whole file
        // instead would include content the directive excluded.
        let (directives, diagnostic_errors) = asciidoc::scan_includes_checked(text);
        if !diagnostic_errors.is_empty() {
            return Err(DocumentError::Diagnostics(diagnostic_errors));
        }
        for directive in &directives {
            self.resolve_directive(origin_path, directive, depth)?;
        }
        Ok(())
    }

    fn check_limits(&self, depth: usize) -> Result<()> {
        if depth > self.policy.max_depth {
            return Err(DocumentError::Diagnostics(vec![Diagnostic::new(
                "include-depth-limit",
                "include depth exceeds the configured policy",
                1,
                1,
                None,
            )]));
        }
        if self.resolved.closure.len() > self.policy.max_inputs {
            return Err(DocumentError::Diagnostics(vec![Diagnostic::new(
                "include-input-limit",
                "include input count exceeds the configured policy",
                1,
                1,
                None,
            )]));
        }
        Ok(())
    }

    /// Charge the elapsed limit before resolving one directive.
    ///
    /// The deadline is checked at every directive, not once per source, so a
    /// file full of directives cannot run past the policy between two checks.
    #[allow(unknown_lints, ambient_clock)] // include deadline is the import shell
    fn check_deadline(&self, directive: &asciidoc::IncludeDirective) -> Result<()> {
        if std::time::Instant::now() <= self.deadline {
            return Ok(());
        }
        Err(include_error(
            "include-time-limit",
            "include resolution exceeded the configured time limit",
            directive,
        ))
    }

    fn resolve_directive(
        &mut self,
        origin_path: &str,
        directive: &asciidoc::IncludeDirective,
        depth: usize,
    ) -> Result<()> {
        self.check_deadline(directive)?;
        let Some((path, source_pin)) = self.resolve_target(origin_path, directive)? else {
            return Ok(());
        };
        let included = self.load_source(source_pin, directive)?;
        let included_bytes = budget_count(included.len());
        let charged = mneme_kernel::budget::charge(
            self.resolved.used_bytes,
            included_bytes,
            budget_count(self.policy.max_total_source_bytes),
        );
        let Some(used_bytes) = charged else {
            return Err(include_error(
                "include-byte-limit",
                "include closure exceeds the configured byte limit",
                directive,
            ));
        };
        self.resolved.used_bytes = used_bytes;
        if self
            .resolved
            .closure
            .insert(path.clone(), source_pin)
            .is_none()
        {
            self.recurse_include(path, source_pin, included, directive, depth)?;
        }
        Ok(())
    }

    fn resolve_target(
        &mut self,
        origin_path: &str,
        directive: &asciidoc::IncludeDirective,
    ) -> Result<Option<(String, SourcePin)>> {
        let path = match asciidoc::normalize_include_path(origin_path, &directive.target) {
            Ok(path) => path,
            Err(mut diagnostic) => {
                diagnostic.line = directive.line;
                diagnostic.column = directive.column;
                diagnostic.span = Some(directive.span);
                return Err(DocumentError::Diagnostics(vec![diagnostic]));
            }
        };
        if !asciidoc::allowed_path(&path, &self.policy.allowed_roots) {
            let mut diagnostic = include_diagnostic(
                "include-not-allowed",
                "include target is outside the authorized document roots",
                directive,
            );
            diagnostic.fatal = true;
            return Err(DocumentError::Diagnostics(vec![diagnostic]));
        }
        if self.stack.contains(&path) {
            let mut diagnostic =
                include_diagnostic("include-cycle", "include graph contains a cycle", directive);
            diagnostic.fatal = true;
            return Err(DocumentError::Diagnostics(vec![diagnostic]));
        }
        let Some(document_id) = self.context.paths.get(&path).copied() else {
            let diagnostic = if directive.optional {
                Diagnostic::warning(
                    "include-optional-missing",
                    format!("optional include {path:?} is absent"),
                    directive.line,
                    directive.column,
                    Some(directive.span),
                )
            } else {
                Diagnostic::new(
                    "include-missing",
                    format!("required include {path:?} is absent"),
                    directive.line,
                    directive.column,
                    Some(directive.span),
                )
            };
            if diagnostic.fatal {
                return Err(DocumentError::Diagnostics(vec![diagnostic]));
            }
            self.resolved.diagnostics.push(diagnostic);
            return Ok(None);
        };
        let document = self
            .context
            .documents
            .get(&document_id)
            .ok_or(DocumentError::Missing(document_id))?;
        if document.record.scope != *self.scope {
            return Err(DocumentError::Diagnostics(vec![include_diagnostic(
                "include-unauthorized",
                "include target is outside the caller's scope",
                directive,
            )]));
        }
        Ok(Some((path, document.source)))
    }

    fn load_source(
        &self,
        source: SourcePin,
        directive: &asciidoc::IncludeDirective,
    ) -> Result<Vec<u8>> {
        self.context
            .require_retained_source(source)
            .map(|(_, bytes)| bytes)
            .map_err(|error| match error {
                DocumentError::Diagnostics(mut diagnostics) => {
                    for diagnostic in &mut diagnostics {
                        diagnostic.line = directive.line;
                        diagnostic.column = directive.column;
                        diagnostic.span = Some(directive.span);
                    }
                    DocumentError::Diagnostics(diagnostics)
                }
                other => other,
            })
    }

    fn recurse_include(
        &mut self,
        path: String,
        source_pin: SourcePin,
        included: Vec<u8>,
        directive: &asciidoc::IncludeDirective,
        depth: usize,
    ) -> Result<()> {
        if self.resolved.closure.len() > self.policy.max_inputs {
            return Err(include_error(
                "include-input-limit",
                "include input count exceeds the configured policy",
                directive,
            ));
        }
        self.resolved.sources.insert(
            path.clone(),
            preview::RenderSource {
                path: path.clone(),
                pin: source_pin,
                scope: self.scope.clone(),
                bytes: included.clone(),
            },
        );
        self.stack.insert(path.clone());
        self.resolve_bytes(&path, &included, depth + 1)?;
        self.stack.remove(&path);
        Ok(())
    }
}

fn include_error(
    code: &'static str,
    message: &'static str,
    directive: &asciidoc::IncludeDirective,
) -> DocumentError {
    DocumentError::Diagnostics(vec![include_diagnostic(code, message, directive)])
}

fn include_diagnostic(
    code: &'static str,
    message: &'static str,
    directive: &asciidoc::IncludeDirective,
) -> Diagnostic {
    Diagnostic::new(
        code,
        message,
        directive.line,
        directive.column,
        Some(directive.span),
    )
}

struct PreparedDocument {
    validated: ValidatedDocument,
    records: Vec<mneme_store::RecordDraft>,
    source_blob: mneme_store::SourceBlobDraft,
    document_id: mneme_core::RecordId,
    /// The committed source the candidate replaces, if it is an update.
    ///
    /// A publication must find the working file still holding these exact
    /// committed bytes, never whatever happens to be on disk when the command
    /// runs; `None` means a new document, whose file is expected only when one
    /// is already present.
    existing_source: Option<SourcePin>,
}

struct SourcePreparation<'a> {
    request: &'a ImportRequest,
    bytes: &'a [u8],
    text: &'a str,
    context: DocumentContext,
    existing: Option<DocumentView>,
    document_id: mneme_core::RecordId,
    /// The identity a candidate reports; `None` for a new document.
    reported_document_id: Option<mneme_core::RecordId>,
    source_id: mneme_core::RecordId,
    source_revision: mneme_core::RevisionId,
    document_revision: mneme_core::RevisionId,
    source: SourcePin,
    digest: mneme_core::ContentDigest,
    candidate_id: String,
}

struct SourceAnalysis {
    title: String,
    entity: Option<mneme_core::RecordId>,
    diagnostics: Vec<Diagnostic>,
    deadline: std::time::Instant,
    resolved: ResolvedIncludes,
    anchors: Vec<asciidoc::AnchorSpec>,
}

struct SourceRender {
    html: String,
    diagnostics: Vec<Diagnostic>,
    includes: Vec<IncludedSource>,
}

/// A source-first document service over one mutable workspace.
pub struct Documents<'w> {
    workspace: &'w mut mneme_store::Workspace,
}

#[derive(Clone, Copy)]
struct PreparationOptions {
    publish: bool,
    external_import: bool,
}

impl<'w> Documents<'w> {
    /// Wrap a workspace.
    pub fn new(workspace: &'w mut mneme_store::Workspace) -> Self {
        Documents { workspace }
    }

    /// Validate the current managed working file as an import candidate.
    pub fn validate_working_file(&self, request: ImportRequest) -> Result<ValidatedDocument> {
        validate_import_request(&request)?;
        let bytes = mneme_store::payload::read_working_file(self.workspace.root(), &request.path)?
            .ok_or_else(|| DocumentError::Io("working file does not exist".to_owned()))?;
        self.prepare_source(&request, &bytes)
            .map(|prepared| prepared.validated)
    }

    /// Validate supplied bytes as a draft candidate without committing.
    pub fn validate_source(
        &self,
        request: ImportRequest,
        bytes: &[u8],
    ) -> Result<ValidatedDocument> {
        validate_import_request(&request)?;
        self.prepare_source(&request, bytes)
            .map(|prepared| prepared.validated)
    }

    /// Import the exact current bytes of a managed working file.
    pub fn import_working_file(&mut self, request: ImportRequest) -> Result<DocumentRevision> {
        validate_import_request(&request)?;
        let bytes = mneme_store::payload::read_working_file(self.workspace.root(), &request.path)?
            .ok_or_else(|| DocumentError::Io("working file does not exist".to_owned()))?;
        let fingerprint = document_request_fingerprint(&BoundDocumentRequest {
            operation: "document-import",
            scope: &request.scope,
            target: request.document_id,
            path: Some(&request.path),
            source_digest: Some(mneme_core::ContentDigest::of_source_bytes(&bytes)),
            options: import_request_options(&request)?,
        });
        if let Some(outcome) = self.workspace.replay_outcome(
            &request.actor,
            &request.scope,
            &request.idempotency_key,
            &fingerprint,
        )? {
            return self.revision_from_outcome(
                &request.scope,
                request.document_id,
                &request.path,
                outcome,
            );
        }
        let prepared = self.prepare_source(&request, &bytes)?;
        self.require_valid(&prepared)?;
        self.commit_prepared(
            request,
            prepared,
            PreparationOptions {
                publish: false,
                external_import: true,
            },
            fingerprint,
        )
    }

    /// Save supplied source bytes and publish them to the managed working file.
    pub fn save_source(
        &mut self,
        request: ImportRequest,
        bytes: &[u8],
    ) -> Result<DocumentRevision> {
        validate_import_request(&request)?;
        let fingerprint = document_request_fingerprint(&BoundDocumentRequest {
            operation: "document-save",
            scope: &request.scope,
            target: request.document_id,
            path: Some(&request.path),
            source_digest: Some(mneme_core::ContentDigest::of_source_bytes(bytes)),
            options: import_request_options(&request)?,
        });
        if let Some(outcome) = self.workspace.replay_outcome(
            &request.actor,
            &request.scope,
            &request.idempotency_key,
            &fingerprint,
        )? {
            return self.revision_from_outcome(
                &request.scope,
                request.document_id,
                &request.path,
                outcome,
            );
        }
        let prepared = self.prepare_source(&request, bytes)?;
        self.require_valid(&prepared)?;
        self.commit_prepared(
            request,
            prepared,
            PreparationOptions {
                publish: true,
                external_import: false,
            },
            fingerprint,
        )
    }

    /// Move a document to a new logical path without changing identity or source.
    pub fn move_document(&mut self, request: MoveRequest) -> Result<DocumentRevision> {
        validate_move_request(&request)?;
        let fingerprint = move_request_fingerprint(&request);
        if let Some(outcome) = self.workspace.replay_outcome(
            &request.actor,
            &request.scope,
            &request.idempotency_key,
            &fingerprint,
        )? {
            return self.revision_from_outcome(
                &request.scope,
                Some(request.document_id),
                &request.path,
                outcome,
            );
        }
        let context = DocumentContext::load(self.workspace, Some(request.base_revision))?;
        let document = context
            .documents
            .get(&request.document_id)
            .cloned()
            .ok_or(DocumentError::Missing(request.document_id))?;
        if document.record.scope != request.scope {
            return Err(DocumentError::Invalid("document scope is not authorized"));
        }
        let title = Self::move_destination_title(&context, &request)?;
        let prepared = prepare_move(self.workspace.root(), &context, &document, &request, title)?;
        let scope = request.scope.clone();
        let outcome = self.workspace.commit_bound(
            mneme_store::CommitCommand {
                base: request.base_revision,
                actor: request.actor,
                scope: scope.clone(),
                idempotency_key: request.idempotency_key,
                records: vec![prepared.draft],
                source_blobs: Vec::new(),
                publications: prepared.publications,
                import_candidates: Vec::new(),
                retention: None,
            },
            fingerprint,
        )?;
        let mut receipt =
            self.revision_from_outcome(&scope, Some(request.document_id), &request.path, outcome)?;
        if prepared.old_path != request.path {
            // The old copy is retired only after the record and the destination
            // file are committed, and only while it still holds exactly the
            // committed bytes: an edit made outside Mneme is kept and reported.
            receipt.retired_working_copy =
                Some(self.retire_old_working_copy(&prepared.old_path, prepared.source_digest));
        }
        Ok(receipt)
    }

    /// Retire the old managed copy of a moved document, reporting the outcome.
    ///
    /// The move itself already committed, so a filesystem failure here is
    /// reported in the receipt instead of turning a committed move into an
    /// error.
    fn retire_old_working_copy(
        &self,
        path: &str,
        digest: mneme_core::ContentDigest,
    ) -> WorkingCopyRetirement {
        match retire_managed_working_copy(self.workspace.root(), path, digest) {
            Ok(retirement) => retirement,
            Err(_) => WorkingCopyRetirement::Failed,
        }
    }

    fn move_destination_title(
        context: &DocumentContext,
        request: &MoveRequest,
    ) -> Result<Option<String>> {
        if let Some(existing) = context.paths.get(&request.path)
            && *existing != request.document_id
        {
            return Err(DocumentError::Conflict(
                "destination path is already in use",
            ));
        }
        match request.title.as_deref() {
            Some(title) => {
                let title = title.trim();
                if title.is_empty() {
                    return Err(DocumentError::Invalid("document title is required"));
                }
                Ok(Some(title.to_owned()))
            }
            None => Ok(None),
        }
    }

    /// Apply a localized entity-id header patch and import the result.
    pub fn patch_binding(&mut self, request: BindingRequest) -> Result<DocumentRevision> {
        let document_id = request.import.document_id.ok_or(DocumentError::Invalid(
            "binding changes require an existing document",
        ))?;
        validate_import_request(&request.import)?;
        // The fingerprint names only what the caller supplied. The source the
        // patch is computed from is workspace state: a retry after the first
        // patch already committed would otherwise present different bytes.
        let fingerprint = document_request_fingerprint(&BoundDocumentRequest {
            operation: "document-bind",
            scope: &request.import.scope,
            target: Some(document_id),
            path: Some(&request.import.path),
            source_digest: None,
            options: vec![
                match request.entity {
                    Some(entity) => entity.to_value(),
                    None => mneme_core::Value::symbol("none"),
                },
                mneme_core::Value::symbol(if request.publish {
                    "publish"
                } else {
                    "commit-only"
                }),
            ],
        });
        if let Some(outcome) = self.workspace.replay_outcome(
            &request.import.actor,
            &request.import.scope,
            &request.import.idempotency_key,
            &fingerprint,
        )? {
            return self.revision_from_outcome(
                &request.import.scope,
                Some(document_id),
                &request.import.path,
                outcome,
            );
        }
        let (_, bytes) = self.document_source_at(
            document_id,
            &request.import.scope,
            Some(request.import.base_revision),
        )?;
        let patched = patch_entity_header(&bytes, request.entity)?;
        let is_publish = request.publish;
        let import = request.import;
        let prepared = self.prepare_source(&import, &patched)?;
        self.require_valid(&prepared)?;
        self.commit_prepared(
            import,
            prepared,
            PreparationOptions {
                publish: is_publish,
                external_import: false,
            },
            fingerprint,
        )
    }

    /// Change one structured entity property without touching document bytes.
    pub fn edit_entity_property(
        &mut self,
        request: EntityPropertyEditRequest<'_>,
    ) -> Result<mneme_core::WorkspaceRevisionId> {
        let fingerprint = document_request_fingerprint(&BoundDocumentRequest {
            operation: "entity-property-edit",
            scope: request.scope,
            target: Some(request.entity_id),
            path: None,
            source_digest: None,
            options: vec![
                mneme_core::Value::string(request.property),
                match &request.value {
                    Some(value) => value.clone(),
                    None => mneme_core::Value::symbol("none"),
                },
            ],
        });
        if let Some(outcome) = self.workspace.replay_outcome(
            request.actor,
            request.scope,
            request.idempotency_key,
            &fingerprint,
        )? {
            return Ok(outcome.revision);
        }
        let context = DocumentContext::load(self.workspace, Some(request.base_revision))?;
        let entity = context
            .entities
            .get(&request.entity_id)
            .cloned()
            .ok_or(DocumentError::Missing(request.entity_id))?;
        if entity.scope != *request.scope {
            return Err(DocumentError::Invalid("entity scope is not authorized"));
        }
        let payload = edited_entity_payload(&entity, request.property, request.value)?;
        let draft = mneme_store::RecordDraft {
            schema_version: entity.schema_version,
            kind: mneme_core::RecordKind::Entity,
            record_id: entity.record_id,
            revision_id: fresh_revision()?,
            predecessor: Some(entity.revision_id),
            scope: entity.scope.clone(),
            payload,
        };
        let outcome = self.workspace.commit_bound(
            mneme_store::CommitCommand {
                base: request.base_revision,
                actor: request.actor.to_owned(),
                scope: request.scope.clone(),
                idempotency_key: request.idempotency_key.to_owned(),
                records: vec![draft],
                source_blobs: Vec::new(),
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            },
            fingerprint,
        )?;
        Ok(outcome.revision)
    }

    #[allow(unknown_lints)] // include deadline is the import shell
    fn prepare_source(&self, request: &ImportRequest, bytes: &[u8]) -> Result<PreparedDocument> {
        validate_import_request(request)?;
        let context = DocumentContext::load(self.workspace, Some(request.base_revision))?;
        let existing = load_existing_document(request, &context)?;
        // A dry run must name the identity a real run would use, and for a new
        // document that identity does not exist until the commit assigns it.
        let reported_document_id = existing
            .as_ref()
            .map(|document| document.record.record_id)
            .or(request.document_id);
        let document_id = existing
            .as_ref()
            .map(|document| document.record.record_id)
            .or(request.document_id)
            .unwrap_or(fresh_id()?);
        let source_id = existing
            .as_ref()
            .map(|document| document.source.source)
            .unwrap_or(fresh_id()?);
        let source_revision = fresh_revision()?;
        let document_revision = fresh_revision()?;
        let source = source_pin(source_id, source_revision);
        let digest = mneme_core::ContentDigest::of_source_bytes(bytes);
        let candidate_id = digest.to_hex();
        let existing_source = existing.as_ref().map(|document| document.source);
        let text = match std::str::from_utf8(bytes) {
            Ok(text) => text,
            Err(error) => {
                return Ok(invalid_utf8_document(InvalidUtf8DocumentInput {
                    request,
                    bytes,
                    document_id,
                    reported_document_id,
                    digest,
                    candidate_id,
                    existing_source,
                    valid_up_to: error.valid_up_to(),
                }));
            }
        };
        self.prepare_valid_source(SourcePreparation {
            request,
            bytes,
            text,
            context,
            existing,
            document_id,
            reported_document_id,
            source_id,
            source_revision,
            document_revision,
            source,
            digest,
            candidate_id,
        })
    }

    fn prepare_valid_source(&self, preparation: SourcePreparation<'_>) -> Result<PreparedDocument> {
        let (title, entity, diagnostics) = source_header(&preparation);
        let (deadline, resolved, anchors, diagnostics) =
            source_dependencies(&preparation, diagnostics)?;
        let analysis = SourceAnalysis {
            title,
            entity,
            diagnostics,
            deadline,
            resolved,
            anchors,
        };
        let rendered = render_prepared_source(&preparation, &analysis)?;
        let is_valid = !analysis
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.fatal);
        let records = if is_valid {
            build_source_records(&preparation, &analysis)?
        } else {
            Vec::new()
        };
        let validated = ValidatedDocument {
            candidate_id: preparation.candidate_id,
            base_revision: preparation.request.base_revision,
            document_id: preparation.reported_document_id,
            path: preparation.request.path.clone(),
            title: analysis.title,
            entity: analysis.entity,
            source_digest: preparation.digest,
            anchors: analysis.anchors,
            includes: rendered.includes,
            diagnostics: analysis.diagnostics,
            preview_diagnostics: rendered.diagnostics,
            valid: is_valid,
            preview_html: rendered.html,
        };
        Ok(PreparedDocument {
            validated,
            records,
            source_blob: mneme_memory::build_source(
                preparation.source_id,
                preparation.source_revision,
                &preparation.request.scope,
                mneme_memory::SourceOptions {
                    bytes: preparation.bytes,
                    media_type: "text/asciidoc",
                    entity: analysis.entity,
                    path_hint: Some(&preparation.request.path),
                },
            )?
            .1,
            document_id: preparation.document_id,
            existing_source: preparation
                .existing
                .as_ref()
                .map(|document| document.source),
        })
    }
}

/// The exact digest of the source bytes a document revision commits.
fn committed_source_digest(
    context: &DocumentContext,
    pin: SourcePin,
) -> Result<mneme_core::ContentDigest> {
    let source = context.source(pin)?;
    if let Some(digest) = source.digest().or(source.prior_digest) {
        return Ok(digest);
    }
    Err(DocumentError::Conflict(
        "committed document source digest is unavailable",
    ))
}

/// The working bytes a move's destination publication expects to replace.
///
/// Nothing at the destination expects nothing, so the file is created. An
/// entry that is already there may only be replaced when it holds the
/// document's committed bytes; any other content diverges and is kept.
fn destination_expectation(
    root: &std::path::Path,
    path: &str,
    committed: mneme_core::ContentDigest,
) -> Result<Option<mneme_core::ContentDigest>> {
    match mneme_store::payload::inspect_working_file(root, path)? {
        mneme_store::payload::WorkingEntry::Absent => Ok(None),
        mneme_store::payload::WorkingEntry::Regular(_)
        | mneme_store::payload::WorkingEntry::NotRegular => Ok(Some(committed)),
    }
}

/// Remove the managed working copy at `path` when it still holds `digest`.
///
/// The entry is displaced first and the kernel decides over the displaced
/// bytes, so an edit made between the check and the removal is kept rather
/// than deleted, and a symbolic link or other non-regular entry is never
/// followed or removed.
fn retire_managed_working_copy(
    root: &std::path::Path,
    path: &str,
    digest: mneme_core::ContentDigest,
) -> Result<WorkingCopyRetirement> {
    let mut guard = mneme_store::payload::quarantine_working_file(root, path)?;
    let mut kind = mneme_kernel::purge::EntryKind::Absent;
    let mut observed = None;
    if let Some(file) = guard.entry() {
        match file.read()? {
            mneme_store::payload::WorkingEntry::Absent => {}
            mneme_store::payload::WorkingEntry::NotRegular => {
                kind = mneme_kernel::purge::EntryKind::Other;
            }
            mneme_store::payload::WorkingEntry::Regular(bytes) => {
                kind = mneme_kernel::purge::EntryKind::Regular;
                observed = Some(mneme_core::ContentDigest::of_source_bytes(&bytes));
            }
        }
    }
    let facts = mneme_kernel::purge::WorkingFacts {
        kind,
        observed: observed.map(|observed| observed.to_kernel()),
        planned: digest.to_kernel(),
    };
    match mneme_kernel::purge::decide_working(&facts) {
        mneme_kernel::purge::WorkingDecision::Purge => {
            guard.discard()?;
            Ok(WorkingCopyRetirement::Removed)
        }
        mneme_kernel::purge::WorkingDecision::AlreadyAbsent => {
            guard.restore()?;
            Ok(WorkingCopyRetirement::Absent)
        }
        mneme_kernel::purge::WorkingDecision::ExternalEdit => {
            guard.restore()?;
            Ok(WorkingCopyRetirement::Diverged)
        }
        mneme_kernel::purge::WorkingDecision::Unsupported => {
            guard.restore()?;
            Ok(WorkingCopyRetirement::Unsupported)
        }
    }
}

fn validate_import_request(request: &ImportRequest) -> Result<()> {
    if request.actor.trim().is_empty() || request.idempotency_key.trim().is_empty() {
        return Err(DocumentError::Invalid(
            "actor and idempotency key are required",
        ));
    }
    validate_logical_path(&request.path)
}

fn validate_move_request(request: &MoveRequest) -> Result<()> {
    if request.actor.trim().is_empty() || request.idempotency_key.trim().is_empty() {
        return Err(DocumentError::Invalid(
            "actor and idempotency key are required",
        ));
    }
    validate_logical_path(&request.path)
}

/// Reject a logical path that is not in canonical relative form.
///
/// One working file has one document identity, so no two spellings may reach a
/// command: `a//b`, `a/./b`, a leading or trailing separator, a `..` segment, a
/// backslash or a NUL byte is refused before anything is stored or read.
fn validate_logical_path(path: &str) -> Result<()> {
    if !mneme_kernel::text::is_canonical_relative_path(path.as_bytes()) {
        return Err(DocumentError::Invalid(
            "logical path is not a canonical relative path",
        ));
    }
    Ok(())
}

fn load_existing_document(
    request: &ImportRequest,
    context: &DocumentContext,
) -> Result<Option<DocumentView>> {
    let existing = match request.document_id {
        Some(id) => Some(
            context
                .documents
                .get(&id)
                .cloned()
                .ok_or(DocumentError::Missing(id))?,
        ),
        None => context
            .paths
            .get(&request.path)
            .and_then(|id| context.documents.get(id))
            .cloned(),
    };
    if let Some(existing) = &existing {
        if existing.record.scope != request.scope {
            return Err(DocumentError::Invalid("document scope is not authorized"));
        }
        if existing
            .path
            .as_deref()
            .is_some_and(|path| path != request.path)
        {
            return Err(DocumentError::Conflict(
                "use move_document for a path change",
            ));
        }
    }
    if let Some(existing_id) = context.paths.get(&request.path)
        && request
            .document_id
            .is_some_and(|document_id| document_id != *existing_id)
    {
        return Err(DocumentError::Conflict("document path is already in use"));
    }
    Ok(existing)
}

struct InvalidUtf8DocumentInput<'a> {
    request: &'a ImportRequest,
    bytes: &'a [u8],
    document_id: mneme_core::RecordId,
    reported_document_id: Option<mneme_core::RecordId>,
    digest: mneme_core::ContentDigest,
    candidate_id: String,
    existing_source: Option<SourcePin>,
    valid_up_to: usize,
}

fn invalid_utf8_document(input: InvalidUtf8DocumentInput<'_>) -> PreparedDocument {
    PreparedDocument {
        validated: ValidatedDocument {
            candidate_id: input.candidate_id,
            base_revision: input.request.base_revision,
            document_id: input.reported_document_id,
            path: input.request.path.clone(),
            title: input.request.title.clone().unwrap_or_default(),
            entity: None,
            source_digest: input.digest,
            anchors: Vec::new(),
            includes: Vec::new(),
            diagnostics: vec![Diagnostic::new(
                "invalid-utf8",
                "document source is not valid UTF-8",
                1,
                input.valid_up_to,
                None,
            )],
            preview_diagnostics: Vec::new(),
            valid: false,
            preview_html: String::new(),
        },
        records: Vec::new(),
        source_blob: mneme_store::SourceBlobDraft {
            bytes: input.bytes.to_vec(),
            media_type: mneme_core::Symbol::from("text/asciidoc"),
        },
        document_id: input.document_id,
        existing_source: input.existing_source,
    }
}

fn source_header(
    preparation: &SourcePreparation<'_>,
) -> (String, Option<mneme_core::RecordId>, Vec<Diagnostic>) {
    let mut diagnostics = Vec::new();
    let header = match asciidoc::parse_header(preparation.text) {
        Ok(header) => header,
        Err(errors) => {
            diagnostics.extend(errors);
            Header::default()
        }
    };
    let title = preparation
        .request
        .title
        .clone()
        .or(header.title.clone())
        .unwrap_or_else(|| {
            std::path::Path::new(&preparation.request.path)
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("Untitled")
                .to_owned()
        });
    let mut entity = header.entity_id;
    if let Some(entity_id) = entity {
        match preparation.context.entities.get(&entity_id) {
            None => {
                diagnostics.push(Diagnostic::new(
                    "binding-missing",
                    "entity-id does not name a committed entity",
                    1,
                    1,
                    None,
                ));
                entity = None;
            }
            Some(record) if record.scope != preparation.request.scope => {
                diagnostics.push(Diagnostic::new(
                    "binding-unauthorized",
                    "entity-id is outside the caller's scope",
                    1,
                    1,
                    None,
                ));
                entity = None;
            }
            Some(_) => {}
        }
    }
    (title, entity, diagnostics)
}

#[allow(unknown_lints, ambient_clock)] // include deadline is the import shell
fn source_dependencies(
    preparation: &SourcePreparation<'_>,
    mut diagnostics: Vec<Diagnostic>,
) -> Result<(
    std::time::Instant,
    ResolvedIncludes,
    Vec<asciidoc::AnchorSpec>,
    Vec<Diagnostic>,
)> {
    let include_start = std::time::Instant::now();
    let max_time_ms = u64::try_from(preparation.request.policy.max_time_ms)
        .map_err(|_| DocumentError::Invalid("include time budget exceeds u64 milliseconds"))?;
    let deadline = include_start + std::time::Duration::from_millis(max_time_ms);
    let resolved = match resolve_import_includes(IncludeResolutionRequest {
        context: &preparation.context,
        scope: &preparation.request.scope,
        root_path: &preparation.request.path,
        root_bytes: preparation.bytes,
        policy: &preparation.request.policy,
        deadline,
    }) {
        Ok(resolved) => resolved,
        Err(DocumentError::Diagnostics(errors)) => {
            diagnostics.extend(errors);
            ResolvedIncludes {
                closure: std::collections::BTreeMap::new(),
                sources: std::collections::BTreeMap::new(),
                diagnostics: Vec::new(),
                used_bytes: 0,
            }
        }
        Err(error) => return Err(error),
    };
    diagnostics.extend(resolved.diagnostics.clone());
    let mut anchors = asciidoc::scan_anchors(preparation.text);
    let mut seen_anchors = std::collections::BTreeSet::new();
    anchors.retain(|anchor| {
        if seen_anchors.insert(anchor.anchor.clone()) {
            true
        } else {
            diagnostics.push(Diagnostic::new(
                "anchor-conflict",
                format!("duplicate anchor {}", anchor.anchor),
                anchor.line,
                anchor.column,
                Some(anchor.span),
            ));
            false
        }
    });
    Ok((deadline, resolved, anchors, diagnostics))
}

fn render_prepared_source(
    preparation: &SourcePreparation<'_>,
    analysis: &SourceAnalysis,
) -> Result<SourceRender> {
    let mut render_sources = analysis.resolved.sources.clone();
    render_sources.insert(
        preparation.request.path.clone(),
        preview::RenderSource {
            path: preparation.request.path.clone(),
            pin: preparation.source,
            scope: preparation.request.scope.clone(),
            bytes: preparation.bytes.to_vec(),
        },
    );
    let metadata = analysis
        .entity
        .and_then(|id| preparation.context.entities.get(&id));
    let root_render = render_sources
        .get(&preparation.request.path)
        .cloned()
        .ok_or(DocumentError::Invalid("root preview source is missing"))?;
    // The import validation render is bounded by both the render configuration
    // and the document policy's expanded-byte budget; the lower limit governs.
    let render_config = RenderConfig {
        max_output_bytes: preparation
            .request
            .render_config
            .max_output_bytes
            .min(preparation.request.policy.max_expanded_bytes),
        ..preparation.request.render_config.clone()
    };
    // Candidate bytes are not yet committed. Do not expose pinned image data
    // in this dry-run rendering; committed previews resolve through the shared
    // authorized image service below.
    let mut unavailable_image_loader = |_: &mneme_core::ScopeId, _: SourcePin| None;
    let rendered = preview::Renderer::new_with_images(
        &render_sources,
        &render_config,
        Some(analysis.deadline),
        &mut unavailable_image_loader,
    )
    .render(&root_render, metadata);
    let includes = analysis
        .resolved
        .closure
        .iter()
        .filter_map(|(path, pin)| {
            analysis
                .resolved
                .sources
                .get(path)
                .map(|source| IncludedSource {
                    path: path.clone(),
                    pin: *pin,
                    digest: Some(mneme_core::ContentDigest::of_source_bytes(&source.bytes)),
                })
        })
        .collect();
    Ok(SourceRender {
        html: rendered.html,
        diagnostics: rendered.diagnostics,
        includes,
    })
}

fn build_source_records(
    preparation: &SourcePreparation<'_>,
    analysis: &SourceAnalysis,
) -> Result<Vec<mneme_store::RecordDraft>> {
    let request = preparation.request;
    let mut source_draft = mneme_memory::build_source(
        preparation.source_id,
        preparation.source_revision,
        &request.scope,
        mneme_memory::SourceOptions {
            bytes: preparation.bytes,
            media_type: "text/asciidoc",
            entity: analysis.entity,
            path_hint: Some(&request.path),
        },
    )?
    .0;
    if let Some(existing) = &preparation.existing {
        source_draft.predecessor = Some(existing.source.revision);
    }
    let mut records = vec![source_draft];
    let binding = append_binding_record(&mut records, preparation, analysis)?;
    let payload = document_payload(preparation, analysis, binding)?;
    records.push(mneme_store::RecordDraft {
        schema_version: DOCUMENT_SCHEMA_VERSION,
        kind: mneme_core::RecordKind::Document,
        record_id: preparation.document_id,
        revision_id: preparation.document_revision,
        predecessor: preparation
            .existing
            .as_ref()
            .map(|document| document.record.revision_id),
        scope: request.scope.clone(),
        payload,
    });
    append_anchor_records(&mut records, preparation, analysis)?;
    Ok(records)
}

/// Append the document's current binding record and return its identity.
///
/// One document has one current binding and one current record per anchor
/// name. A re-import supersedes those records so a document that is saved
/// repeatedly does not accumulate a live record per save.
fn append_binding_record(
    records: &mut Vec<mneme_store::RecordDraft>,
    preparation: &SourcePreparation<'_>,
    analysis: &SourceAnalysis,
) -> Result<Option<mneme_core::RecordId>> {
    let request = preparation.request;
    let current_binding =
        current_binding_record(preparation.context.view.snapshot(), preparation.document_id);
    if let Some(entity_id) = analysis.entity {
        let (binding_id, predecessor) = match &current_binding {
            Some(record) => (record.record_id, Some(record.revision_id)),
            None => (fresh_id()?, None),
        };
        records.push(mneme_store::RecordDraft {
            schema_version: DOCUMENT_SCHEMA_VERSION,
            kind: mneme_core::RecordKind::DocumentBinding,
            record_id: binding_id,
            revision_id: fresh_revision()?,
            predecessor,
            scope: request.scope.clone(),
            payload: document_binding_payload(
                preparation.document_id,
                entity_id,
                preparation.source,
                "bound",
            )?,
        });
        return Ok(Some(binding_id));
    }
    let Some(record) = &current_binding else {
        return Ok(None);
    };
    if record
        .payload
        .get("status")
        .and_then(mneme_core::Value::as_symbol)
        .is_some_and(|status| status.as_str() == "unbound")
    {
        return Ok(None);
    }
    // The source no longer declares a binding. Record that state so the last
    // committed binding does not stay current after the document dropped it;
    // the record keeps the entity it was bound to as metadata.
    if let Some(previous) = optional_reference_target(record, "entity") {
        records.push(mneme_store::RecordDraft {
            schema_version: DOCUMENT_SCHEMA_VERSION,
            kind: mneme_core::RecordKind::DocumentBinding,
            record_id: record.record_id,
            revision_id: fresh_revision()?,
            predecessor: Some(record.revision_id),
            scope: request.scope.clone(),
            payload: document_binding_payload(
                preparation.document_id,
                previous,
                preparation.source,
                "unbound",
            )?,
        });
    }
    Ok(None)
}

fn document_payload(
    preparation: &SourcePreparation<'_>,
    analysis: &SourceAnalysis,
    binding: Option<mneme_core::RecordId>,
) -> Result<mneme_core::Payload> {
    let request = preparation.request;
    let mut includes_dictionary = std::collections::BTreeMap::new();
    for (path, pin) in &analysis.resolved.closure {
        let key = mneme_core::Value::string(path.clone());
        if includes_dictionary.len() >= MAX_INCLUDE_ENTRIES {
            return Err(DocumentError::Invalid(
                "document include closure exceeds the 1M entry bound",
            ));
        }
        includes_dictionary.insert(
            key,
            mneme_core::Reference::pinned(
                pin.source,
                pin.revision,
                mneme_core::RecordKind::SourceRevision,
            )
            .to_value(),
        );
    }
    let mut payload = vec![
        (
            mneme_core::Symbol::from("title"),
            mneme_core::Value::string(analysis.title.clone()),
        ),
        (
            mneme_core::Symbol::from("source-revision"),
            mneme_core::Reference::pinned(
                preparation.source_id,
                preparation.source_revision,
                mneme_core::RecordKind::SourceRevision,
            )
            .to_value(),
        ),
        (
            mneme_core::Symbol::from("path"),
            mneme_core::Value::string(request.path.clone()),
        ),
        (
            mneme_core::Symbol::from("render-config"),
            mneme_core::Value::string(request.render_config.version.clone()),
        ),
    ];
    if let Some(entity_id) = analysis.entity {
        payload.push((
            mneme_core::Symbol::from("entity"),
            mneme_core::Reference::local(entity_id, mneme_core::RecordKind::Entity).to_value(),
        ));
    }
    if let Some(binding_id) = binding {
        payload.push((
            mneme_core::Symbol::from("binding"),
            mneme_core::Reference::local(binding_id, mneme_core::RecordKind::DocumentBinding)
                .to_value(),
        ));
    }
    if !includes_dictionary.is_empty() {
        payload.push((
            mneme_core::Symbol::from("includes"),
            mneme_core::Value::Dictionary(includes_dictionary),
        ));
    }
    let replacement = mneme_core::Payload::new(payload);
    // An existing revision may carry extension fields this editor does not
    // declare. They must survive the edit or the edit must be refused; a
    // production editor never discards what it cannot interpret.
    let Some(existing) = &preparation.existing else {
        return Ok(replacement);
    };
    kind_editor(mneme_core::RecordKind::Document)?
        .edit(&existing.record, replacement)
        .map_err(editor_refusal)
}

/// The editor view over one declared record kind.
fn kind_editor(kind: mneme_core::RecordKind) -> Result<mneme_core::editing::EditorView> {
    let schema = mneme_core::fields::RecordSchema::documents_v3();
    let kind_schema = match schema.kind(kind) {
        Some(kind_schema) => kind_schema,
        None => return Err(DocumentError::Invalid("schema lacks the record kind")),
    };
    Ok(mneme_core::editing::EditorView::declared(kind_schema))
}

fn editor_refusal(diagnostics: Vec<mneme_core::problem::Diagnostic>) -> DocumentError {
    let mut reported = Vec::with_capacity(diagnostics.len());
    for diagnostic in diagnostics {
        reported.push(refusal_diagnostic(diagnostic));
    }
    DocumentError::Diagnostics(reported)
}

fn refusal_diagnostic(diagnostic: mneme_core::problem::Diagnostic) -> Diagnostic {
    Diagnostic::new("editor-refused", diagnostic.to_string(), 1, 1, None)
}

/// Build the replacement payload of one entity property edit.
///
/// Every field this editor does not understand is carried from the current
/// revision verbatim; the edit is refused if it would change or drop one.
fn edited_entity_payload(
    entity: &mneme_core::RecordEnvelope,
    property: &str,
    value: Option<mneme_core::Value>,
) -> Result<mneme_core::Payload> {
    let mut properties = entity
        .payload
        .get("properties")
        .and_then(mneme_core::Value::as_dictionary)
        .cloned()
        .unwrap_or_default();
    let key = mneme_core::Value::symbol(property);
    match value {
        Some(value) => {
            properties.insert(key, value);
        }
        None => {
            properties.remove(&key);
        }
    }
    let mut payload = entity.payload.clone();
    payload.insert(
        mneme_core::Symbol::from("properties"),
        mneme_core::Value::Dictionary(properties),
    );
    kind_editor(mneme_core::RecordKind::Entity)?
        .replace_payload(entity, payload)
        .map_err(editor_refusal)
}

fn append_anchor_records(
    records: &mut Vec<mneme_store::RecordDraft>,
    preparation: &SourcePreparation<'_>,
    analysis: &SourceAnalysis,
) -> Result<()> {
    for anchor in &analysis.anchors {
        let existing = current_anchor_record(
            preparation.context.view.snapshot(),
            preparation.document_id,
            &anchor.anchor,
        );
        let (anchor_id, predecessor) = match existing {
            Some(record) => (record.record_id, Some(record.revision_id)),
            None => (fresh_id()?, None),
        };
        records.push(mneme_store::RecordDraft {
            schema_version: DOCUMENT_SCHEMA_VERSION,
            kind: mneme_core::RecordKind::DocumentAnchor,
            record_id: anchor_id,
            revision_id: fresh_revision()?,
            predecessor,
            scope: preparation.request.scope.clone(),
            payload: document_anchor_payload(preparation.document_id, preparation.source, anchor),
        });
    }
    Ok(())
}

/// The current binding record of one document, if it has one.
fn current_binding_record(
    snapshot: &mneme_store::Snapshot,
    document: mneme_core::RecordId,
) -> Option<&mneme_core::RecordEnvelope> {
    snapshot.records.iter().find(|record| {
        record.kind == mneme_core::RecordKind::DocumentBinding
            && optional_reference_target(record, "document") == Some(document)
    })
}

/// The current record of one named anchor of one document, if it has one.
fn current_anchor_record<'a>(
    snapshot: &'a mneme_store::Snapshot,
    document: mneme_core::RecordId,
    anchor: &str,
) -> Option<&'a mneme_core::RecordEnvelope> {
    snapshot.records.iter().find(|record| {
        record.kind == mneme_core::RecordKind::DocumentAnchor
            && optional_reference_target(record, "document") == Some(document)
            && record
                .payload
                .get("anchor")
                .and_then(mneme_core::Value::as_string)
                == Some(anchor)
    })
}

fn document_binding_payload(
    document: mneme_core::RecordId,
    entity: mneme_core::RecordId,
    source: SourcePin,
    status: &str,
) -> Result<mneme_core::Payload> {
    Ok(mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("document"),
            mneme_core::Reference::local(document, mneme_core::RecordKind::Document).to_value(),
        ),
        (
            mneme_core::Symbol::from("entity"),
            mneme_core::Reference::local(entity, mneme_core::RecordKind::Entity).to_value(),
        ),
        (
            mneme_core::Symbol::from("status"),
            mneme_core::Value::symbol(status),
        ),
        (
            mneme_core::Symbol::from("basis"),
            mneme_core::Value::string("source-header"),
        ),
        (
            mneme_core::Symbol::from("source-revision"),
            mneme_core::Reference::pinned(
                source.source,
                source.revision,
                mneme_core::RecordKind::SourceRevision,
            )
            .to_value(),
        ),
    ]))
}

#[allow(unknown_lints, fallible_int_fallback, sentinel_fallback)] // positions are bounded by source length
fn document_anchor_payload(
    document: mneme_core::RecordId,
    source: SourcePin,
    anchor: &AnchorSpec,
) -> mneme_core::Payload {
    let mut entries = vec![
        (
            mneme_core::Symbol::from("document"),
            mneme_core::Reference::local(document, mneme_core::RecordKind::Document).to_value(),
        ),
        (
            mneme_core::Symbol::from("source-revision"),
            mneme_core::Reference::pinned(
                source.source,
                source.revision,
                mneme_core::RecordKind::SourceRevision,
            )
            .to_value(),
        ),
        (mneme_core::Symbol::from("span"), anchor.span.to_value()),
        (
            mneme_core::Symbol::from("anchor"),
            mneme_core::Value::string(anchor.anchor.clone()),
        ),
    ];
    if let Some(label) = &anchor.label {
        entries.push((
            mneme_core::Symbol::from("label"),
            mneme_core::Value::string(label.clone()),
        ));
    }
    entries.push((
        mneme_core::Symbol::from("line"),
        mneme_core::Value::integer(i64::try_from(anchor.line).unwrap_or(i64::MAX)),
    ));
    entries.push((
        mneme_core::Symbol::from("column"),
        mneme_core::Value::integer(i64::try_from(anchor.column).unwrap_or(i64::MAX)),
    ));
    mneme_core::Payload::new(entries)
}

impl Documents<'_> {
    fn require_valid(&self, prepared: &PreparedDocument) -> Result<()> {
        if prepared.validated.valid {
            Ok(())
        } else {
            Err(DocumentError::Diagnostics(
                prepared.validated.diagnostics.clone(),
            ))
        }
    }

    /// Read one document's committed source bytes at a pinned revision.
    fn document_source_at(
        &self,
        document_id: mneme_core::RecordId,
        scope: &mneme_core::ScopeId,
        revision: Option<mneme_core::WorkspaceRevisionId>,
    ) -> Result<(DocumentContext, Vec<u8>)> {
        let context = DocumentContext::load(self.workspace, revision)?;
        let document = context
            .documents
            .get(&document_id)
            .ok_or(DocumentError::Missing(document_id))?;
        if document.record.scope != *scope {
            return Err(DocumentError::Invalid("document scope is not authorized"));
        }
        let (_, bytes) = context.require_retained_source(document.source)?;
        Ok((context, bytes))
    }

    fn commit_prepared(
        &mut self,
        request: ImportRequest,
        prepared: PreparedDocument,
        options: PreparationOptions,
        fingerprint: mneme_core::ContentDigest,
    ) -> Result<DocumentRevision> {
        if !prepared.validated.valid {
            return Err(DocumentError::Diagnostics(prepared.validated.diagnostics));
        }
        let publications = if options.publish {
            // An update may only replace the bytes the committed revision holds,
            // so an edit made outside Mneme since that revision diverges instead
            // of being overwritten. The expected bytes are always the committed
            // source the candidate was prepared from, never the file as it is
            // now; a new document has no committed source, so it expects the
            // file already at its path, if any.
            let working =
                mneme_store::payload::read_working_file(self.workspace.root(), &request.path)?;
            let expected_previous = match prepared.existing_source {
                Some(pin) => match working {
                    Some(_) => {
                        let context =
                            DocumentContext::load(self.workspace, Some(request.base_revision))?;
                        Some(committed_source_digest(&context, pin)?)
                    }
                    None => None,
                },
                None => working.map(|bytes| mneme_core::ContentDigest::of_source_bytes(&bytes)),
            };
            vec![mneme_store::PublicationDraft {
                path: request.path.clone(),
                expected_previous,
                bytes: prepared.source_blob.bytes.clone(),
            }]
        } else {
            Vec::new()
        };
        let import_candidates = if options.external_import {
            vec![mneme_store::ImportCandidateDraft {
                path: request.path.clone(),
                bytes: prepared.source_blob.bytes.clone(),
            }]
        } else {
            Vec::new()
        };
        let outcome = self.workspace.commit_bound(
            mneme_store::CommitCommand {
                base: request.base_revision,
                actor: request.actor,
                scope: request.scope.clone(),
                idempotency_key: request.idempotency_key,
                records: prepared.records,
                source_blobs: vec![prepared.source_blob],
                publications,
                import_candidates,
                retention: None,
            },
            fingerprint,
        )?;
        self.revision_from_outcome(
            &request.scope,
            Some(prepared.document_id),
            &request.path,
            outcome,
        )
    }

    fn revision_from_outcome(
        &self,
        scope: &mneme_core::ScopeId,
        document_id: Option<mneme_core::RecordId>,
        path: &str,
        outcome: mneme_store::CommitOutcome,
    ) -> Result<DocumentRevision> {
        // A receipt must describe the one revision it names. Reading the
        // document from the current revision would pair an old workspace
        // revision and sequence with a newer document revision, digest and
        // anchor set.
        let context = DocumentContext::load(self.workspace, Some(outcome.revision))?;
        let document = if let Some(document_id) = document_id {
            context
                .documents
                .get(&document_id)
                .cloned()
                .ok_or(DocumentError::Missing(document_id))?
        } else {
            let document_id = context.paths.get(path).copied().ok_or(DocumentError::Io(
                "committed document path is missing".to_owned(),
            ))?;
            context
                .documents
                .get(&document_id)
                .cloned()
                .ok_or(DocumentError::Missing(document_id))?
        };
        if document.record.scope != *scope {
            return Err(DocumentError::Invalid("document scope is not authorized"));
        }
        let source_view = context.source(document.source)?;
        let source_digest =
            source_view
                .digest()
                .or(source_view.prior_digest)
                .ok_or(DocumentError::Conflict(
                    "document source digest is unavailable",
                ))?;
        let mut included = Vec::with_capacity(document.includes.len());
        for (path, pin) in &document.includes {
            let digest = context
                .source(*pin)
                .ok()
                .and_then(|source| source.digest().or(source.prior_digest));
            included.push(IncludedSource {
                path: path.clone(),
                pin: *pin,
                digest,
            });
        }
        let snapshot = context.view.snapshot();
        let mut anchors = Vec::with_capacity(snapshot.records.len());
        for record in &snapshot.records {
            if record.kind == mneme_core::RecordKind::DocumentAnchor
                && optional_reference_target(record, "document") == Some(document.record.record_id)
                && reference_is_pinned_to(record, "source-revision", document.source)
            {
                anchors.push(record.record_id);
            }
        }
        Ok(DocumentRevision {
            document_id: document.record.record_id,
            document_revision: document.record.revision_id,
            source: document.source,
            source_digest,
            workspace_revision: outcome.revision,
            sequence: outcome.sequence,
            path: document.path.unwrap_or_else(|| path.to_owned()),
            entity: document.entity,
            anchors,
            includes: included,
            publications: outcome.publications,
            retired_working_copy: None,
        })
    }

    /// Read the exact latest source bytes for a document.
    pub fn source_bytes(&self, document_id: mneme_core::RecordId) -> Result<Vec<u8>> {
        let context = DocumentContext::load(self.workspace, None)?;
        let document = context
            .documents
            .get(&document_id)
            .ok_or(DocumentError::Missing(document_id))?;
        Ok(context.require_retained_source(document.source)?.1)
    }

    /// Resolve the current document at one logical path.
    pub fn document_by_path(&self, path: &str) -> Result<Option<DocumentView>> {
        let context = DocumentContext::load(self.workspace, None)?;
        Ok(context
            .paths
            .get(path)
            .and_then(|document| context.documents.get(document))
            .cloned())
    }

    /// Read the current document with one stable identity.
    pub fn document(&self, document_id: mneme_core::RecordId) -> Result<DocumentView> {
        let context = DocumentContext::load(self.workspace, None)?;
        context
            .documents
            .get(&document_id)
            .cloned()
            .ok_or(DocumentError::Missing(document_id))
    }

    /// List current documents in deterministic title, path, and identity order.
    ///
    /// The result is a bounded inventory of one committed snapshot, not a
    /// search index. Callers that need authorization filter on `scope`.
    pub fn list_documents(&self) -> Result<Vec<DocumentSummary>> {
        let context = DocumentContext::load(self.workspace, None)?;
        let mut summaries: Vec<DocumentSummary> = context
            .documents
            .values()
            .map(|view| DocumentSummary {
                document_id: view.record.record_id,
                revision: view.record.revision_id,
                scope: view.record.scope.clone(),
                title: view.title.clone(),
                path: view.path.clone(),
                entity: view.entity,
            })
            .collect();
        summaries.sort_by(|left, right| {
            normalized_listing_key(&left.title)
                .cmp(&normalized_listing_key(&right.title))
                .then_with(|| {
                    left.path
                        .as_deref()
                        .unwrap_or_default()
                        .cmp(right.path.as_deref().unwrap_or_default())
                })
                .then_with(|| left.document_id.to_hex().cmp(&right.document_id.to_hex()))
        });
        Ok(summaries)
    }

    /// List current documents with their retained sources in one snapshot.
    ///
    /// Suppressed or unavailable sources are returned as `None` rather than as
    /// empty bytes or an error for the whole listing.
    pub fn list_sources(&self) -> Result<Vec<DocumentSource>> {
        let context = DocumentContext::load(self.workspace, None)?;
        let mut sources: Vec<DocumentSource> = context
            .documents
            .values()
            .map(|view| DocumentSource {
                document_id: view.record.record_id,
                scope: view.record.scope.clone(),
                title: view.title.clone(),
                path: view.path.clone(),
                source: context.source_bytes(view.source).ok().flatten(),
            })
            .collect();
        sources.sort_by(|left, right| {
            normalized_listing_key(&left.title)
                .cmp(&normalized_listing_key(&right.title))
                .then_with(|| {
                    left.path
                        .as_deref()
                        .unwrap_or_default()
                        .cmp(right.path.as_deref().unwrap_or_default())
                })
                .then_with(|| left.document_id.to_hex().cmp(&right.document_id.to_hex()))
        });
        Ok(sources)
    }

    /// List explicit anchors for the current document revision.
    #[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
    pub fn anchors(&self, document_id: mneme_core::RecordId) -> Result<Vec<AnchorRecord>> {
        let context = DocumentContext::load(self.workspace, None)?;
        let document = context
            .documents
            .get(&document_id)
            .ok_or(DocumentError::Missing(document_id))?;
        let records = &context.view.snapshot().records;
        let max_anchors = records
            .iter()
            .filter(|record| record.kind == mneme_core::RecordKind::DocumentAnchor)
            .count();
        let mut anchors = Vec::with_capacity(max_anchors);
        for record in records {
            if record.kind != mneme_core::RecordKind::DocumentAnchor
                || optional_reference_target(record, "document") != Some(document_id)
                || !reference_is_pinned_to(record, "source-revision", document.source)
            {
                continue;
            }
            let span = record.payload.get("span").and_then(|value| {
                mneme_core::SourceSpan::from_value(value, &mneme_core::Path::root()).ok()
            });
            let anchor = record
                .payload
                .get("anchor")
                .and_then(mneme_core::Value::as_string)
                .unwrap_or_default()
                .to_owned();
            let label = record
                .payload
                .get("label")
                .and_then(mneme_core::Value::as_string)
                .map(str::to_owned);
            anchors.push(AnchorRecord {
                record_id: record.record_id,
                source: document.source,
                span,
                anchor,
                label,
            });
        }
        Ok(anchors)
    }

    /// Render a current or historical document preview.
    #[allow(unknown_lints)] // preview deadline is the render shell
    pub fn preview(
        &mut self,
        document_id: mneme_core::RecordId,
        revision: Option<mneme_core::WorkspaceRevisionId>,
        config: RenderConfig,
    ) -> Result<PreviewArtifact> {
        let context = DocumentContext::load(self.workspace, revision)?;
        let document = context
            .documents
            .get(&document_id)
            .cloned()
            .ok_or(DocumentError::Missing(document_id))?;
        let sources = load_preview_sources(&context, &document)?;
        render_preview_artifact(self.workspace, &context, &document, &config, sources)
    }

    /// Extract revision-bound authored paragraphs without accepting assertions.
    #[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
    pub fn extract_proposals(
        &mut self,
        document_id: mneme_core::RecordId,
    ) -> Result<Vec<ExtractionCandidate>> {
        let context = DocumentContext::load(self.workspace, None)?;
        let document = context
            .documents
            .get(&document_id)
            .cloned()
            .ok_or(DocumentError::Missing(document_id))?;
        let sources = load_extraction_sources(&context, &document)?;
        let occurrences = extraction_include_occurrences(&sources)?;
        let candidates = extraction_candidates(document_id, &sources, &occurrences)?;
        let mut proposals = Vec::with_capacity(candidates.len());
        proposals.extend(candidates.into_values());
        Ok(proposals)
    }
}

struct PreviewSources {
    root: Option<preview::RenderSource>,
    sources: std::collections::BTreeMap<String, preview::RenderSource>,
    included: Vec<IncludedSource>,
    diagnostics: Vec<Diagnostic>,
}

fn load_preview_sources(
    context: &DocumentContext,
    document: &DocumentView,
) -> Result<PreviewSources> {
    if document.includes.len() > MAX_INCLUDE_ENTRIES {
        return Err(DocumentError::Invalid(
            "document include closure exceeds the 1M entry bound",
        ));
    }
    let mut diagnostics = Vec::with_capacity(document.includes.len().saturating_add(1));
    // The root's directives are interpreted against the path its pinned source
    // was committed under. A later move changes the document's logical path but
    // not the relative targets already written into the source, so resolving
    // against the new path would substitute a different document or drop the
    // include entirely.
    let root = load_root_preview(context, document, &mut diagnostics);
    let mut sources = std::collections::BTreeMap::new();
    let mut included = Vec::with_capacity(document.includes.len());
    for (path, pin) in &document.includes {
        let source = context.source(*pin).ok();
        let digest = source
            .as_ref()
            .and_then(|source| source.digest().or(source.prior_digest));
        included.push(IncludedSource {
            path: path.clone(),
            pin: *pin,
            digest,
        });
        match context.source_bytes(*pin) {
            Ok(Some(bytes)) => {
                if sources.len() >= MAX_INCLUDE_ENTRIES {
                    return Err(DocumentError::Invalid(
                        "document preview source index exceeds the 1M entry bound",
                    ));
                }
                sources.insert(
                    path.clone(),
                    preview::RenderSource {
                        path: path.clone(),
                        pin: *pin,
                        scope: source
                            .as_ref()
                            .map(|source| source.record.scope.clone())
                            .unwrap_or_else(|| document.record.scope.clone()),
                        bytes,
                    },
                );
            }
            Ok(None) | Err(_) => diagnostics.push(Diagnostic::warning(
                "include-unavailable",
                format!("include source {path:?} is unavailable"),
                1,
                1,
                None,
            )),
        }
    }
    Ok(PreviewSources {
        root,
        sources,
        included,
        diagnostics,
    })
}

fn load_root_preview(
    context: &DocumentContext,
    document: &DocumentView,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<preview::RenderSource> {
    let origin = source_origin_path(context, document.source, document.path.as_deref());
    match context.source_bytes(document.source) {
        Ok(Some(bytes)) => Some(preview::RenderSource {
            path: origin,
            pin: document.source,
            scope: context
                .source(document.source)
                .map(|source| source.record.scope)
                .unwrap_or_else(|_| document.record.scope.clone()),
            bytes,
        }),
        Ok(None) | Err(_) => {
            diagnostics.push(Diagnostic::warning(
                "source-unavailable",
                "document source bytes are unavailable",
                1,
                1,
                None,
            ));
            None
        }
    }
}

/// The logical path one pinned source was committed under.
///
/// Relative include targets are resolved against the path recorded on the
/// source revision that contains them, so a document's pinned closure stays
/// resolvable after the document itself moves.
fn source_origin_path(context: &DocumentContext, pin: SourcePin, fallback: Option<&str>) -> String {
    context
        .source(pin)
        .ok()
        .and_then(|source| source.path_hint)
        .or_else(|| fallback.map(str::to_owned))
        .unwrap_or_else(|| "<document>".to_owned())
}

#[allow(unknown_lints, ambient_clock)] // preview deadline is the render shell
fn render_preview_artifact(
    workspace: &mut mneme_store::Workspace,
    context: &DocumentContext,
    document: &DocumentView,
    config: &RenderConfig,
    mut sources: PreviewSources,
) -> Result<PreviewArtifact> {
    let source_digest = context
        .source(document.source)
        .ok()
        .and_then(|source| source.digest().or(source.prior_digest));
    let metadata = document
        .entity
        .and_then(|entity| context.entities.get(&entity));
    let max_time_ms = u64::try_from(config.max_time_ms)
        .map_err(|_| DocumentError::Invalid("preview time budget exceeds u64 milliseconds"))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(max_time_ms);
    let generation = context.generation;
    let revision = context.view.revision();
    let mut image_loader = |scope: &mneme_core::ScopeId,
                            pin: SourcePin|
     -> Option<(images::Loaded, images::Decoded)> {
        let (loaded, decoded) = images::load_decoded(workspace, scope, pin, Some(revision)).ok()?;
        (loaded.generation == generation).then_some((loaded, decoded))
    };
    let rendered = sources.root.as_ref().map(|root| {
        preview::Renderer::new_with_images(
            &sources.sources,
            config,
            Some(deadline),
            &mut image_loader,
        )
        .render(root, metadata)
    });
    workspace.recheck(context.view.snapshot())?;
    if let Some(rendered) = &rendered {
        sources.diagnostics.extend(rendered.diagnostics.clone());
    }
    let is_truncated = match &rendered {
        Some(rendered) => rendered.truncated,
        None => false,
    };
    let config_fingerprint = render_config_fingerprint(config);
    Ok(PreviewArtifact {
        document: document.record.record_id,
        document_revision: document.record.revision_id,
        workspace_revision: context.view.revision(),
        generation: context.generation,
        path: document.path.clone().unwrap_or_default(),
        title: document.title.clone(),
        entity: document.entity,
        source: document.source,
        source_digest,
        config_version: config.version.clone(),
        config_fingerprint,
        processor_version: PROCESSOR_VERSION.to_owned(),
        html: rendered
            .as_ref()
            .map(|rendered| rendered.html.clone())
            .unwrap_or_default(),
        included: sources.included,
        occurrences: rendered
            .map(|rendered| rendered.occurrences)
            .unwrap_or_default(),
        diagnostics: sources.diagnostics,
        source_available: sources.root.is_some(),
        truncated: is_truncated,
    })
}

fn load_extraction_sources(
    context: &DocumentContext,
    document: &DocumentView,
) -> Result<std::collections::BTreeMap<String, preview::RenderSource>> {
    if document.includes.len() > MAX_INCLUDE_ENTRIES {
        return Err(DocumentError::Invalid(
            "document include closure exceeds the 1M entry bound",
        ));
    }
    let root_bytes = context.require_retained_source(document.source)?.1;
    let mut sources = std::collections::BTreeMap::new();
    // Extraction attributes included text through the same pinned paths the
    // preview uses, so a moved document keeps reading its own closure.
    let root_path = source_origin_path(context, document.source, document.path.as_deref());
    sources.insert(
        root_path.clone(),
        preview::RenderSource {
            path: root_path.clone(),
            pin: document.source,
            scope: context
                .source(document.source)
                .map(|source| source.record.scope)
                .unwrap_or_else(|_| document.record.scope.clone()),
            bytes: root_bytes,
        },
    );
    let max_sources = MAX_INCLUDE_ENTRIES.saturating_add(1);
    for (path, pin) in &document.includes {
        let (_, bytes) = context.require_retained_source(*pin)?;
        if sources.len() >= max_sources {
            return Err(DocumentError::Invalid(
                "document extraction source index exceeds the 1M entry bound",
            ));
        }
        sources.insert(
            path.clone(),
            preview::RenderSource {
                path: path.clone(),
                pin: *pin,
                scope: context
                    .source(*pin)
                    .map(|source| source.record.scope)
                    .unwrap_or_else(|_| document.record.scope.clone()),
                bytes,
            },
        );
    }
    Ok(sources)
}

fn extraction_include_occurrences(
    sources: &std::collections::BTreeMap<String, preview::RenderSource>,
) -> Result<std::collections::BTreeMap<String, Vec<IncludeOccurrence>>> {
    let mut occurrences_by_path: std::collections::BTreeMap<String, Vec<IncludeOccurrence>> =
        std::collections::BTreeMap::new();
    for source in sources.values() {
        let text = std::str::from_utf8(&source.bytes)
            .map_err(|_| DocumentError::Invalid("document source is not UTF-8"))?;
        for directive in asciidoc::scan_includes(text) {
            let path = asciidoc::normalize_include_path(&source.path, &directive.target)
                .map_err(|diagnostic| DocumentError::Diagnostics(vec![diagnostic]))?;
            let Some(target) = sources.get(&path) else {
                continue;
            };
            occurrences_by_path
                .entry(path.clone())
                .or_default()
                .push(IncludeOccurrence {
                    including_path: source.path.clone(),
                    target_path: path,
                    directive_span: directive.span,
                    source: target.pin,
                });
        }
    }
    Ok(occurrences_by_path)
}

fn extraction_candidates(
    document_id: mneme_core::RecordId,
    sources: &std::collections::BTreeMap<String, preview::RenderSource>,
    occurrences_by_path: &std::collections::BTreeMap<String, Vec<IncludeOccurrence>>,
) -> Result<
    std::collections::BTreeMap<
        (mneme_core::RecordId, mneme_core::RevisionId, u64, u64),
        ExtractionCandidate,
    >,
> {
    let mut candidates = std::collections::BTreeMap::new();
    for source in sources.values() {
        let text = std::str::from_utf8(&source.bytes)
            .map_err(|_| DocumentError::Invalid("document source is not UTF-8"))?;
        for paragraph in asciidoc::scan_paragraphs(text) {
            insert_extraction_candidate(
                &mut candidates,
                document_id,
                source,
                paragraph,
                occurrences_by_path,
            )?;
        }
    }
    Ok(candidates)
}

fn insert_extraction_candidate(
    candidates: &mut std::collections::BTreeMap<
        (mneme_core::RecordId, mneme_core::RevisionId, u64, u64),
        ExtractionCandidate,
    >,
    document_id: mneme_core::RecordId,
    source: &preview::RenderSource,
    paragraph: asciidoc::Paragraph,
    occurrences_by_path: &std::collections::BTreeMap<String, Vec<IncludeOccurrence>>,
) -> Result<()> {
    let start = usize::try_from(paragraph.span.start())
        .map_err(|_| DocumentError::Invalid("span position exceeds the platform limit"))?;
    let end = usize::try_from(paragraph.span.end())
        .map_err(|_| DocumentError::Invalid("span position exceeds the platform limit"))?;
    if start > end || end >= source.bytes.len() {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&source.bytes[start..=end]).into_owned();
    let key = (
        source.pin.source,
        source.pin.revision,
        paragraph.span.start(),
        paragraph.span.end(),
    );
    let occurrences = occurrences_by_path
        .get(&source.path)
        .cloned()
        .unwrap_or_default();
    candidates.entry(key).or_insert(ExtractionCandidate {
        document: document_id,
        origin_path: source.path.clone(),
        source: source.pin,
        span: paragraph.span,
        text,
        occurrences,
    });
    Ok(())
}

/// One committed explicit anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorRecord {
    pub record_id: mneme_core::RecordId,
    pub source: SourcePin,
    pub span: Option<mneme_core::SourceSpan>,
    pub anchor: String,
    pub label: Option<String>,
}

/// One source line with the byte range it occupies, terminator included.
struct HeaderLine<'a> {
    text: &'a str,
    start: usize,
    line_end: usize,
}

impl HeaderLine<'_> {
    /// The terminator exactly as written: `\r\n`, `\n`, or nothing at EOF.
    fn terminator<'a>(&self, source: &'a str) -> &'a str {
        &source[self.start + self.text.len()..self.line_end]
    }
}

/// Split source text into lines with byte ranges, treating only `\n` as a
/// terminator and a preceding `\r` as part of it.
fn header_lines(text: &str) -> Vec<HeaderLine<'_>> {
    let mut lines = Vec::with_capacity(text.split_inclusive('\n').count());
    let mut offset = 0;
    for chunk in text.split_inclusive('\n') {
        let start = offset;
        offset += chunk.len();
        let content = chunk.strip_suffix('\n').unwrap_or(chunk);
        let content = content.strip_suffix('\r').unwrap_or(content);
        lines.push(HeaderLine {
            text: content,
            start,
            line_end: offset,
        });
    }
    lines
}

/// Rewrite only the literal `:entity-id:` header entry.
///
/// The header ends at the first blank line, exactly as the header parser reads
/// it, so prose or a listing that happens to start with `:entity-id:` is never
/// touched. The patched bytes are re-parsed and must bind exactly the requested
/// entity (or nothing, when clearing); otherwise the patch is refused instead
/// of reporting a binding the document does not carry.
fn patch_entity_header(bytes: &[u8], entity: Option<mneme_core::RecordId>) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| DocumentError::Invalid("document source is not UTF-8"))?;
    let lines = header_lines(text);
    let mut entity_line: Option<&HeaderLine<'_>> = None;
    let mut insert_at = 0;
    for line in &lines {
        if line.text.trim().is_empty() {
            break;
        }
        if line.start == 0 && line.text.starts_with("= ") {
            insert_at = line.line_end;
            continue;
        }
        if line.text.trim_start().starts_with(":entity-id:") {
            entity_line = Some(line);
            break;
        }
    }
    let patched = match (entity, entity_line) {
        (Some(entity), Some(line)) => replace_entity_line(text, line, &entity.to_hex()),
        (Some(entity), None) => insert_entity_line(text, insert_at, &entity.to_hex()),
        (None, Some(line)) => remove_entity_line(text, line),
        (None, None) => return Ok(bytes.to_vec()),
    };
    let patched_text = std::str::from_utf8(&patched)
        .map_err(|_| DocumentError::Invalid("document source is not UTF-8"))?;
    let header = asciidoc::parse_header(patched_text).map_err(DocumentError::Diagnostics)?;
    if header.entity_id != entity {
        return Err(DocumentError::Diagnostics(vec![Diagnostic::new(
            "binding-patch",
            "the binding patch did not bind the requested entity",
            1,
            1,
            None,
        )]));
    }
    Ok(patched)
}

fn replace_entity_line(text: &str, line: &HeaderLine<'_>, value: &str) -> Vec<u8> {
    let indent = line.text.len() - line.text.trim_start().len();
    let terminator = line.terminator(text);
    let replacement = format!("{}:entity-id: {value}{terminator}", &line.text[..indent]);
    let mut patched = String::with_capacity(text.len().saturating_add(replacement.len()));
    patched.push_str(&text[..line.start]);
    patched.push_str(&replacement);
    patched.push_str(&text[line.line_end..]);
    patched.into_bytes()
}

fn remove_entity_line(text: &str, line: &HeaderLine<'_>) -> Vec<u8> {
    let mut patched = String::with_capacity(text.len());
    patched.push_str(&text[..line.start]);
    patched.push_str(&text[line.line_end..]);
    patched.into_bytes()
}

/// Insert the binding entry after the title line, or at the top when there is
/// no title. A title without a terminator gains one so the entry starts on its
/// own line.
fn insert_entity_line(text: &str, insert_at: usize, value: &str) -> Vec<u8> {
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut insertion = String::new();
    if insert_at > 0 && !text[..insert_at].ends_with('\n') {
        insertion.push_str(newline);
    }
    insertion.push_str(&format!(":entity-id: {value}{newline}"));
    let mut patched = String::with_capacity(text.len().saturating_add(insertion.len()));
    patched.push_str(&text[..insert_at]);
    patched.push_str(&insertion);
    patched.push_str(&text[insert_at..]);
    patched.into_bytes()
}

fn render_config_fingerprint(config: &RenderConfig) -> String {
    format!(
        "{}|entity-metadata={}|output={}|time={}",
        config.version, config.include_entity_metadata, config.max_output_bytes, config.max_time_ms
    )
}

/// A view-context refusal, with a store refusal kept on its own variant.
fn view_context_error(error: mneme_memory::EvidenceError) -> DocumentError {
    match error {
        mneme_memory::EvidenceError::Store(error) => DocumentError::Store(error),
        error @ mneme_memory::EvidenceError::InvalidRecord { .. }
        | error @ mneme_memory::EvidenceError::Missing { .. }
        | error @ mneme_memory::EvidenceError::Policy(_)
        | error @ mneme_memory::EvidenceError::Validation(_)
        | error @ mneme_memory::EvidenceError::Invalid(_)
        | error @ mneme_memory::EvidenceError::Truncated => DocumentError::Engine(error),
    }
}

type DocumentIndexes = (
    std::collections::BTreeMap<mneme_core::RecordId, DocumentView>,
    std::collections::BTreeMap<String, mneme_core::RecordId>,
    std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RecordEnvelope>,
);

fn index_documents(
    snapshot: &mneme_store::Snapshot,
    max_context_records: usize,
) -> Result<DocumentIndexes> {
    let mut documents = std::collections::BTreeMap::new();
    let mut paths = std::collections::BTreeMap::new();
    let mut entities = std::collections::BTreeMap::new();
    for record in &snapshot.records {
        match record.kind {
            mneme_core::RecordKind::Document => {
                let mut document = DocumentView::parse(record.clone())?;
                if !document.source_is_pinned {
                    let source = snapshot
                        .records
                        .iter()
                        .find(|candidate| {
                            candidate.record_id == document.source.source
                                && candidate.kind == mneme_core::RecordKind::SourceRevision
                        })
                        .ok_or(DocumentError::Missing(document.source.source))?;
                    document.source.revision = source.revision_id;
                    document.source_is_pinned = true;
                }
                if let Some(path) = &document.path
                    && !paths.contains_key(path)
                    && paths.len() >= max_context_records
                {
                    return Err(DocumentError::Invalid(
                        "document path index exceeds the 1M record bound",
                    ));
                }
                if let Some(path) = &document.path
                    && let Some(existing) = paths.insert(path.clone(), record.record_id)
                    && existing != record.record_id
                {
                    return Err(DocumentError::Conflict(
                        "two committed documents share one logical path",
                    ));
                }
                if documents.len() >= max_context_records {
                    return Err(DocumentError::Invalid(
                        "document index exceeds the 1M record bound",
                    ));
                }
                documents.insert(record.record_id, document);
            }
            mneme_core::RecordKind::Entity => {
                if entities.len() >= max_context_records {
                    return Err(DocumentError::Invalid(
                        "entity index exceeds the 1M record bound",
                    ));
                }
                entities.insert(record.record_id, record.clone());
            }
            _ => {}
        }
    }
    Ok((documents, paths, entities))
}
