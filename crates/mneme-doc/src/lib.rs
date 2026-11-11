//! Source-first AsciiDoc documents over the committed workspace.
//!
//! Exact source bytes are authoritative. Documents have stable identities,
//! optional literal entity bindings, pinned include closures, explicit anchors,
//! a restricted sanitized preview, and revision-bound extraction candidates.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod asciidoc;

pub use asciidoc::{AnchorSpec, Diagnostic, Header, IncludeDirective};

/// The document schema version emitted by this build.
pub const DOCUMENT_SCHEMA_VERSION: u32 = 3;
/// The preview processor version.
pub const PROCESSOR_VERSION: &str = "mneme-asciidoc/0.1";
/// The preview configuration version.
pub const RENDER_CONFIG_VERSION: &str = "mneme-preview/v1";

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

/// Failure of a document operation.
#[derive(Debug, thiserror::Error)]
pub enum DocumentError {
    #[error(transparent)]
    Store(#[from] mneme_store::StoreError),
    #[error(transparent)]
    Memory(#[from] mneme_memory::MemoryError),
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

struct DocumentContext {
    view: mneme_memory::MemoryView,
    documents: std::collections::BTreeMap<mneme_core::RecordId, DocumentView>,
    paths: std::collections::BTreeMap<String, mneme_core::RecordId>,
    entities: std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RecordEnvelope>,
    generation: u64,
}

impl DocumentContext {
    fn load(
        workspace: &mneme_store::Workspace,
        revision: Option<mneme_core::WorkspaceRevisionId>,
    ) -> Result<Self> {
        let revision = revision.unwrap_or(workspace.current_revision()?);
        let snapshot = workspace.snapshot_at(revision, None)?;
        let mut history = std::collections::BTreeMap::new();
        for record in &snapshot.records {
            for retained in workspace.record_revisions(record.record_id)? {
                history.insert((retained.record_id, retained.revision_id), retained);
            }
        }
        let sequences = workspace.revision_sequences()?;
        let suppressions = workspace.active_suppressions()?;
        let view = mneme_memory::MemoryView::with_retention(
            snapshot.clone(),
            workspace.root(),
            history,
            sequences,
            suppressions,
        );
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
                        && let Some(existing) = paths.insert(path.clone(), record.record_id)
                        && existing != record.record_id
                    {
                        return Err(DocumentError::Conflict(
                            "two committed documents share one logical path",
                        ));
                    }
                    documents.insert(record.record_id, document);
                }
                mneme_core::RecordKind::Entity => {
                    entities.insert(record.record_id, record.clone());
                }
                _ => {}
            }
        }
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
        mneme_store::blob::random_bytes()?,
    ))
}

fn fresh_revision() -> Result<mneme_core::RevisionId> {
    Ok(mneme_core::RevisionId::from_bytes(
        mneme_store::blob::random_bytes()?,
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
    total_bytes: usize,
}

fn resolve_import_includes(
    context: &DocumentContext,
    scope: &mneme_core::ScopeId,
    root_path: &str,
    root_bytes: &[u8],
    policy: &DocumentPolicy,
    deadline: std::time::Instant,
) -> Result<ResolvedIncludes> {
    let mut resolved = ResolvedIncludes {
        closure: std::collections::BTreeMap::new(),
        sources: std::collections::BTreeMap::new(),
        diagnostics: Vec::new(),
        total_bytes: root_bytes.len(),
    };
    let mut stack = std::collections::BTreeSet::new();
    stack.insert(root_path.to_owned());
    resolve_include_bytes(
        context,
        scope,
        root_path,
        root_bytes,
        policy,
        deadline,
        0,
        &mut stack,
        &mut resolved,
    )?;
    Ok(resolved)
}

#[allow(clippy::too_many_arguments)]
#[allow(unknown_lints, ambient_clock)] // include deadline is the import shell
fn resolve_include_bytes(
    context: &DocumentContext,
    scope: &mneme_core::ScopeId,
    origin_path: &str,
    bytes: &[u8],
    policy: &DocumentPolicy,
    deadline: std::time::Instant,
    depth: usize,
    stack: &mut std::collections::BTreeSet<String>,
    resolved: &mut ResolvedIncludes,
) -> Result<()> {
    if depth > policy.max_depth {
        return Err(DocumentError::Diagnostics(vec![Diagnostic::new(
            "include-depth-limit",
            "include depth exceeds the configured policy",
            1,
            1,
            None,
        )]));
    }
    if std::time::Instant::now() > deadline {
        return Err(DocumentError::Diagnostics(vec![Diagnostic::new(
            "include-time-limit",
            "include resolution exceeded the configured time limit",
            1,
            1,
            None,
        )]));
    }
    if resolved.closure.len() > policy.max_inputs {
        return Err(DocumentError::Diagnostics(vec![Diagnostic::new(
            "include-input-limit",
            "include input count exceeds the configured policy",
            1,
            1,
            None,
        )]));
    }
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) => {
            return Err(DocumentError::Diagnostics(vec![Diagnostic::new(
                "invalid-utf8",
                "included source is not valid UTF-8",
                1,
                error.valid_up_to(),
                None,
            )]));
        }
    };
    for directive in asciidoc::scan_includes(text) {
        let path = match asciidoc::normalize_include_path(origin_path, &directive.target) {
            Ok(path) => path,
            Err(mut diagnostic) => {
                diagnostic.line = directive.line;
                diagnostic.column = directive.column;
                diagnostic.span = Some(directive.span);
                return Err(DocumentError::Diagnostics(vec![diagnostic]));
            }
        };
        if !asciidoc::allowed_path(&path, &policy.allowed_roots) {
            let mut diagnostic = Diagnostic::new(
                "include-not-allowed",
                "include target is outside the authorized document roots",
                directive.line,
                directive.column,
                Some(directive.span),
            );
            diagnostic.fatal = true;
            return Err(DocumentError::Diagnostics(vec![diagnostic]));
        }
        if stack.contains(&path) {
            let mut diagnostic = Diagnostic::new(
                "include-cycle",
                "include graph contains a cycle",
                directive.line,
                directive.column,
                Some(directive.span),
            );
            diagnostic.fatal = true;
            return Err(DocumentError::Diagnostics(vec![diagnostic]));
        }
        let Some(document_id) = context.paths.get(&path).copied() else {
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
            resolved.diagnostics.push(diagnostic);
            continue;
        };
        let document = context
            .documents
            .get(&document_id)
            .ok_or(DocumentError::Missing(document_id))?;
        if document.record.scope != *scope {
            return Err(DocumentError::Diagnostics(vec![Diagnostic::new(
                "include-unauthorized",
                "include target is outside the caller's scope",
                directive.line,
                directive.column,
                Some(directive.span),
            )]));
        }
        let (source, included) =
            context
                .require_retained_source(document.source)
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
                })?;
        let _ = source;
        resolved.total_bytes = resolved.total_bytes.saturating_add(included.len());
        if resolved.total_bytes > policy.max_total_source_bytes {
            return Err(DocumentError::Diagnostics(vec![Diagnostic::new(
                "include-byte-limit",
                "include closure exceeds the configured byte limit",
                directive.line,
                directive.column,
                Some(directive.span),
            )]));
        }
        if resolved
            .closure
            .insert(path.clone(), document.source)
            .is_none()
        {
            if resolved.closure.len() > policy.max_inputs {
                return Err(DocumentError::Diagnostics(vec![Diagnostic::new(
                    "include-input-limit",
                    "include input count exceeds the configured policy",
                    directive.line,
                    directive.column,
                    Some(directive.span),
                )]));
            }
            resolved.sources.insert(
                path.clone(),
                preview::RenderSource {
                    path: path.clone(),
                    pin: document.source,
                    bytes: included.clone(),
                },
            );
            stack.insert(path.clone());
            resolve_include_bytes(
                context,
                scope,
                &path,
                &included,
                policy,
                deadline,
                depth + 1,
                stack,
                resolved,
            )?;
            stack.remove(&path);
        }
    }
    Ok(())
}

struct PreparedDocument {
    validated: ValidatedDocument,
    records: Vec<mneme_store::RecordDraft>,
    source_blob: mneme_store::SourceBlobDraft,
    document_id: mneme_core::RecordId,
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
        let bytes = mneme_store::blob::read_working_file(self.workspace.root(), &request.path)?
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
        self.prepare_source(&request, bytes)
            .map(|prepared| prepared.validated)
    }

    /// Import the exact current bytes of a managed working file.
    pub fn import_working_file(&mut self, request: ImportRequest) -> Result<DocumentRevision> {
        if let Some(outcome) = self.workspace.command_outcome_by_key(
            &request.actor,
            &request.scope,
            &request.idempotency_key,
        )? {
            return self.revision_from_outcome(&request.scope, None, &request.path, outcome);
        }
        let bytes = mneme_store::blob::read_working_file(self.workspace.root(), &request.path)?
            .ok_or_else(|| DocumentError::Io("working file does not exist".to_owned()))?;
        let prepared = self.prepare_source(&request, &bytes)?;
        self.require_valid(&prepared)?;
        self.commit_prepared(
            request,
            prepared,
            PreparationOptions {
                publish: false,
                external_import: true,
            },
        )
    }

    /// Save supplied source bytes and publish them to the managed working file.
    pub fn save_source(
        &mut self,
        request: ImportRequest,
        bytes: &[u8],
    ) -> Result<DocumentRevision> {
        if let Some(outcome) = self.workspace.command_outcome_by_key(
            &request.actor,
            &request.scope,
            &request.idempotency_key,
        )? {
            return self.revision_from_outcome(&request.scope, None, &request.path, outcome);
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
        )
    }

    /// Move a document to a new logical path without changing identity or source.
    pub fn move_document(&mut self, request: MoveRequest) -> Result<DocumentRevision> {
        if let Some(outcome) = self.workspace.command_outcome_by_key(
            &request.actor,
            &request.scope,
            &request.idempotency_key,
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
        mneme_store::blob::validate_relative_path(&request.path)
            .map_err(|error| DocumentError::Io(error.to_string()))?;
        if request.path.contains('\\') {
            return Err(DocumentError::Invalid(
                "document path must use forward slashes",
            ));
        }
        if let Some(existing) = context.paths.get(&request.path)
            && *existing != request.document_id
        {
            return Err(DocumentError::Conflict(
                "destination path is already in use",
            ));
        }
        let title = match request.title.as_deref() {
            Some(title) => {
                let title = title.trim();
                if title.is_empty() {
                    return Err(DocumentError::Invalid("document title is required"));
                }
                Some(title.to_owned())
            }
            None => None,
        };
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
        let scope = request.scope.clone();
        let outcome = self.workspace.commit(mneme_store::CommitCommand {
            base: request.base_revision,
            actor: request.actor,
            scope: scope.clone(),
            idempotency_key: request.idempotency_key,
            records: vec![draft],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })?;
        self.revision_from_outcome(&scope, Some(request.document_id), &request.path, outcome)
    }

    /// Apply a localized entity-id header patch and import the result.
    pub fn patch_binding(&mut self, request: BindingRequest) -> Result<DocumentRevision> {
        let document_id = request.import.document_id.ok_or(DocumentError::Invalid(
            "binding changes require an existing document",
        ))?;
        if let Some(outcome) = self.workspace.command_outcome_by_key(
            &request.import.actor,
            &request.import.scope,
            &request.import.idempotency_key,
        )? {
            return self.revision_from_outcome(
                &request.import.scope,
                Some(document_id),
                &request.import.path,
                outcome,
            );
        }
        let (_, bytes) = self.current_document_source(document_id, &request.import.scope)?;
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
        )
    }

    /// Change one structured entity property without touching document bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn edit_entity_property(
        &mut self,
        actor: &str,
        scope: &mneme_core::ScopeId,
        base: mneme_core::WorkspaceRevisionId,
        idempotency_key: &str,
        entity_id: mneme_core::RecordId,
        property: &str,
        value: Option<mneme_core::Value>,
    ) -> Result<mneme_core::WorkspaceRevisionId> {
        let context = DocumentContext::load(self.workspace, Some(base))?;
        let entity = context
            .entities
            .get(&entity_id)
            .cloned()
            .ok_or(DocumentError::Missing(entity_id))?;
        if entity.scope != *scope {
            return Err(DocumentError::Invalid("entity scope is not authorized"));
        }
        let mut properties = entity
            .payload
            .get("properties")
            .and_then(mneme_core::Value::as_dictionary)
            .cloned()
            .unwrap_or_default();
        let key = mneme_core::Value::symbol(property.to_owned());
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
        let draft = mneme_store::RecordDraft {
            schema_version: entity.schema_version,
            kind: mneme_core::RecordKind::Entity,
            record_id: entity.record_id,
            revision_id: fresh_revision()?,
            predecessor: Some(entity.revision_id),
            scope: entity.scope.clone(),
            payload,
        };
        let outcome = self.workspace.commit(mneme_store::CommitCommand {
            base,
            actor: actor.to_owned(),
            scope: scope.clone(),
            idempotency_key: idempotency_key.to_owned(),
            records: vec![draft],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })?;
        Ok(outcome.revision)
    }

    #[allow(unknown_lints, ambient_clock)] // include deadline is the import shell
    fn prepare_source(&self, request: &ImportRequest, bytes: &[u8]) -> Result<PreparedDocument> {
        if request.actor.trim().is_empty() || request.idempotency_key.trim().is_empty() {
            return Err(DocumentError::Invalid(
                "actor and idempotency key are required",
            ));
        }
        mneme_store::blob::validate_relative_path(&request.path)
            .map_err(|error| DocumentError::Io(error.to_string()))?;
        if request.path.contains('\\') {
            return Err(DocumentError::Invalid(
                "document path must use forward slashes",
            ));
        }
        let context = DocumentContext::load(self.workspace, Some(request.base_revision))?;
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
        let text = match std::str::from_utf8(bytes) {
            Ok(text) => text,
            Err(error) => {
                return Ok(PreparedDocument {
                    validated: ValidatedDocument {
                        candidate_id,
                        base_revision: request.base_revision,
                        document_id: Some(document_id),
                        path: request.path.clone(),
                        title: request.title.clone().unwrap_or_default(),
                        entity: None,
                        source_digest: digest,
                        anchors: Vec::new(),
                        includes: Vec::new(),
                        diagnostics: vec![Diagnostic::new(
                            "invalid-utf8",
                            "document source is not valid UTF-8",
                            1,
                            error.valid_up_to(),
                            None,
                        )],
                        preview_diagnostics: Vec::new(),
                        valid: false,
                        preview_html: String::new(),
                    },
                    records: Vec::new(),
                    source_blob: mneme_store::SourceBlobDraft {
                        bytes: bytes.to_vec(),
                        media_type: mneme_core::Symbol::from("text/asciidoc"),
                    },
                    document_id,
                });
            }
        };
        let mut diagnostics = Vec::new();
        let header = match asciidoc::parse_header(text) {
            Ok(header) => header,
            Err(errors) => {
                diagnostics.extend(errors);
                Header::default()
            }
        };
        let title = request
            .title
            .clone()
            .or(header.title.clone())
            .unwrap_or_else(|| {
                std::path::Path::new(&request.path)
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or("Untitled")
                    .to_owned()
            });
        let mut entity = header.entity_id;
        if let Some(entity_id) = entity {
            match context.entities.get(&entity_id) {
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
                Some(record) if record.scope != request.scope => {
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
        let include_start = std::time::Instant::now();
        let max_time_ms = u64::try_from(request.policy.max_time_ms)
            .map_err(|_| DocumentError::Invalid("include time budget exceeds u64 milliseconds"))?;
        let deadline = include_start + std::time::Duration::from_millis(max_time_ms);
        let resolved = match resolve_import_includes(
            &context,
            &request.scope,
            &request.path,
            bytes,
            &request.policy,
            deadline,
        ) {
            Ok(resolved) => resolved,
            Err(DocumentError::Diagnostics(errors)) => {
                diagnostics.extend(errors);
                ResolvedIncludes {
                    closure: std::collections::BTreeMap::new(),
                    sources: std::collections::BTreeMap::new(),
                    diagnostics: Vec::new(),
                    total_bytes: bytes.len(),
                }
            }
            Err(error) => return Err(error),
        };
        diagnostics.extend(resolved.diagnostics.clone());
        let mut anchors = asciidoc::scan_anchors(text);
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
        let mut render_sources = resolved.sources.clone();
        render_sources.insert(
            request.path.clone(),
            preview::RenderSource {
                path: request.path.clone(),
                pin: source,
                bytes: bytes.to_vec(),
            },
        );
        let metadata = entity.and_then(|id| context.entities.get(&id));
        let root_render = render_sources
            .get(&request.path)
            .cloned()
            .ok_or(DocumentError::Invalid("root preview source is missing"))?;
        let rendered = preview::render(
            &root_render,
            &render_sources,
            metadata,
            &request.render_config,
            Some(deadline),
        );
        let is_valid = !diagnostics.iter().any(|diagnostic| diagnostic.fatal);
        let included = resolved
            .closure
            .iter()
            .filter_map(|(path, pin)| {
                resolved.sources.get(path).map(|source| IncludedSource {
                    path: path.clone(),
                    pin: *pin,
                    digest: Some(mneme_core::ContentDigest::of_source_bytes(&source.bytes)),
                })
            })
            .collect::<Vec<_>>();
        let validated = ValidatedDocument {
            candidate_id,
            base_revision: request.base_revision,
            document_id: Some(document_id),
            path: request.path.clone(),
            title: title.clone(),
            entity,
            source_digest: digest,
            anchors: anchors.clone(),
            includes: included.clone(),
            diagnostics,
            preview_diagnostics: rendered.diagnostics,
            valid: is_valid,
            preview_html: rendered.html,
        };
        let mut records = Vec::new();
        let mut binding = None;
        if is_valid {
            let mut source_draft = mneme_memory::build_source(
                source_id,
                source_revision,
                &request.scope,
                bytes,
                "text/asciidoc",
                entity,
                Some(&request.path),
            )?
            .0;
            if let Some(existing) = &existing {
                source_draft.predecessor = Some(existing.source.revision);
            }
            records.push(source_draft);
            if let Some(entity_id) = entity {
                let binding_id = fresh_id()?;
                let binding_revision = fresh_revision()?;
                records.push(mneme_store::RecordDraft {
                    schema_version: DOCUMENT_SCHEMA_VERSION,
                    kind: mneme_core::RecordKind::DocumentBinding,
                    record_id: binding_id,
                    revision_id: binding_revision,
                    predecessor: None,
                    scope: request.scope.clone(),
                    payload: document_binding_payload(document_id, entity_id, source)?,
                });
                binding = Some(binding_id);
            }
            let mut includes_dictionary = std::collections::BTreeMap::new();
            for (path, pin) in &resolved.closure {
                includes_dictionary.insert(
                    mneme_core::Value::string(path.clone()),
                    mneme_core::Reference::pinned(
                        pin.source,
                        pin.revision,
                        mneme_core::RecordKind::SourceRevision,
                    )
                    .to_value(),
                );
            }
            let mut document_payload = vec![
                (
                    mneme_core::Symbol::from("title"),
                    mneme_core::Value::string(title),
                ),
                (
                    mneme_core::Symbol::from("source-revision"),
                    mneme_core::Reference::pinned(
                        source_id,
                        source_revision,
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
            if let Some(entity_id) = entity {
                document_payload.push((
                    mneme_core::Symbol::from("entity"),
                    mneme_core::Reference::local(entity_id, mneme_core::RecordKind::Entity)
                        .to_value(),
                ));
            }
            if let Some(binding_id) = binding {
                document_payload.push((
                    mneme_core::Symbol::from("binding"),
                    mneme_core::Reference::local(
                        binding_id,
                        mneme_core::RecordKind::DocumentBinding,
                    )
                    .to_value(),
                ));
            }
            if !includes_dictionary.is_empty() {
                document_payload.push((
                    mneme_core::Symbol::from("includes"),
                    mneme_core::Value::Dictionary(includes_dictionary),
                ));
            }
            records.push(mneme_store::RecordDraft {
                schema_version: DOCUMENT_SCHEMA_VERSION,
                kind: mneme_core::RecordKind::Document,
                record_id: document_id,
                revision_id: document_revision,
                predecessor: existing
                    .as_ref()
                    .map(|document| document.record.revision_id),
                scope: request.scope.clone(),
                payload: mneme_core::Payload::new(document_payload),
            });
            for anchor in &anchors {
                let anchor_id = fresh_id()?;
                let anchor_revision = fresh_revision()?;
                records.push(mneme_store::RecordDraft {
                    schema_version: DOCUMENT_SCHEMA_VERSION,
                    kind: mneme_core::RecordKind::DocumentAnchor,
                    record_id: anchor_id,
                    revision_id: anchor_revision,
                    predecessor: None,
                    scope: request.scope.clone(),
                    payload: document_anchor_payload(document_id, source, anchor),
                });
            }
        }
        Ok(PreparedDocument {
            validated,
            records,
            source_blob: mneme_memory::build_source(
                source_id,
                source_revision,
                &request.scope,
                bytes,
                "text/asciidoc",
                entity,
                Some(&request.path),
            )?
            .1,
            document_id,
        })
    }
}

fn document_binding_payload(
    document: mneme_core::RecordId,
    entity: mneme_core::RecordId,
    source: SourcePin,
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
            mneme_core::Value::symbol("bound"),
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

    fn current_document_source(
        &self,
        document_id: mneme_core::RecordId,
        scope: &mneme_core::ScopeId,
    ) -> Result<(DocumentContext, Vec<u8>)> {
        let context = DocumentContext::load(self.workspace, None)?;
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
    ) -> Result<DocumentRevision> {
        if !prepared.validated.valid {
            return Err(DocumentError::Diagnostics(prepared.validated.diagnostics));
        }
        if let Some(outcome) = self.workspace.command_outcome_by_key(
            &request.actor,
            &request.scope,
            &request.idempotency_key,
        )? {
            return self.revision_from_outcome(
                &request.scope,
                Some(prepared.document_id),
                &request.path,
                outcome,
            );
        }
        let publications = if options.publish {
            let expected_previous =
                mneme_store::blob::read_working_file(self.workspace.root(), &request.path)?
                    .map(|bytes| mneme_core::ContentDigest::of_source_bytes(&bytes));
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
        let outcome = self.workspace.commit(mneme_store::CommitCommand {
            base: request.base_revision,
            actor: request.actor,
            scope: request.scope.clone(),
            idempotency_key: request.idempotency_key,
            records: prepared.records,
            source_blobs: vec![prepared.source_blob],
            publications,
            import_candidates,
            retention: None,
        })?;
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
        let context = DocumentContext::load(self.workspace, None)?;
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
        let mut anchors = Vec::new();
        for record in &context.view.snapshot().records {
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
    pub fn anchors(&self, document_id: mneme_core::RecordId) -> Result<Vec<AnchorRecord>> {
        let context = DocumentContext::load(self.workspace, None)?;
        let document = context
            .documents
            .get(&document_id)
            .ok_or(DocumentError::Missing(document_id))?;
        let mut anchors = Vec::new();
        for record in &context.view.snapshot().records {
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
    #[allow(unknown_lints, ambient_clock)] // preview deadline is the render shell
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
        let source_view = context.source(document.source).ok();
        let source_digest = source_view
            .as_ref()
            .and_then(|source| source.digest().or(source.prior_digest));
        let mut diagnostics = Vec::new();
        let mut root_source = None;
        match context.source_bytes(document.source) {
            Ok(Some(bytes)) => {
                root_source = Some(preview::RenderSource {
                    path: document
                        .path
                        .clone()
                        .unwrap_or_else(|| "<document>".to_owned()),
                    pin: document.source,
                    bytes,
                });
            }
            Ok(None) | Err(_) => {
                diagnostics.push(Diagnostic::warning(
                    "source-unavailable",
                    "document source bytes are unavailable",
                    1,
                    1,
                    None,
                ));
            }
        }
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
                    sources.insert(
                        path.clone(),
                        preview::RenderSource {
                            path: path.clone(),
                            pin: *pin,
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
        let metadata = document
            .entity
            .and_then(|entity| context.entities.get(&entity));
        let max_time_ms = u64::try_from(config.max_time_ms)
            .map_err(|_| DocumentError::Invalid("preview time budget exceeds u64 milliseconds"))?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(max_time_ms);
        let rendered = root_source
            .as_ref()
            .map(|root| preview::render(root, &sources, metadata, &config, Some(deadline)));
        if let Some(rendered) = &rendered {
            diagnostics.extend(rendered.diagnostics.clone());
        }
        let config_fingerprint = render_config_fingerprint(&config);
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
            included,
            occurrences: rendered
                .map(|rendered| rendered.occurrences)
                .unwrap_or_default(),
            diagnostics,
            source_available: root_source.is_some(),
        })
    }

    /// Extract revision-bound authored paragraphs without accepting assertions.
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
        let root_bytes = context.require_retained_source(document.source)?.1;
        let mut sources = std::collections::BTreeMap::new();
        let root_path = document
            .path
            .clone()
            .unwrap_or_else(|| "<document>".to_owned());
        sources.insert(
            root_path.clone(),
            preview::RenderSource {
                path: root_path.clone(),
                pin: document.source,
                bytes: root_bytes,
            },
        );
        for (path, pin) in &document.includes {
            let (_, bytes) = context.require_retained_source(*pin)?;
            sources.insert(
                path.clone(),
                preview::RenderSource {
                    path: path.clone(),
                    pin: *pin,
                    bytes,
                },
            );
        }
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
        let mut candidates: std::collections::BTreeMap<
            (mneme_core::RecordId, mneme_core::RevisionId, u64, u64),
            ExtractionCandidate,
        > = std::collections::BTreeMap::new();
        for source in sources.values() {
            let text = std::str::from_utf8(&source.bytes)
                .map_err(|_| DocumentError::Invalid("document source is not UTF-8"))?;
            for paragraph in asciidoc::scan_paragraphs(text) {
                let start = usize::try_from(paragraph.span.start()).map_err(|_| {
                    DocumentError::Invalid("span position exceeds the platform limit")
                })?;
                let end = usize::try_from(paragraph.span.end()).map_err(|_| {
                    DocumentError::Invalid("span position exceeds the platform limit")
                })?;
                if start > end || end >= source.bytes.len() {
                    continue;
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
            }
        }
        Ok(candidates.into_values().collect())
    }
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

fn patch_entity_header(bytes: &[u8], entity: Option<mneme_core::RecordId>) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| DocumentError::Invalid("document source is not UTF-8"))?;
    let header_end = text.find("\n\n").unwrap_or(text.len());
    let header = &text[..header_end];
    let mut target = None;
    let mut offset = 0;
    for line in header.split_inclusive('\n') {
        if line.trim_start().starts_with(":entity-id:") {
            target = Some((offset, line.len()));
            break;
        }
        offset += line.len();
    }
    match entity {
        Some(entity) => {
            let value = entity.to_hex();
            if let Some((start, length)) = target {
                let line = &text[start..start + length];
                let newline = if line.ends_with("\r\n") {
                    "\r\n"
                } else if line.ends_with('\n') {
                    "\n"
                } else {
                    ""
                };
                let indent = line.len() - line.trim_start().len();
                let replacement = format!("{}:entity-id: {value}{newline}", &line[..indent]);
                let mut patched = String::with_capacity(text.len() + replacement.len());
                patched.push_str(&text[..start]);
                patched.push_str(&replacement);
                patched.push_str(&text[start + length..]);
                Ok(patched.into_bytes())
            } else {
                let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
                let insertion = if let Some(title) =
                    text.lines().next().filter(|line| line.starts_with("= "))
                {
                    let title_end = text.find('\n').map(|end| end + 1).unwrap_or(text.len());
                    let _ = title;
                    title_end
                } else {
                    0
                };
                let mut patched = String::with_capacity(text.len() + 64);
                patched.push_str(&text[..insertion]);
                patched.push_str(&format!(":entity-id: {value}{newline}"));
                patched.push_str(&text[insertion..]);
                Ok(patched.into_bytes())
            }
        }
        None => {
            let Some((start, length)) = target else {
                return Ok(bytes.to_vec());
            };
            let mut patched = String::with_capacity(text.len());
            patched.push_str(&text[..start]);
            patched.push_str(&text[start + length..]);
            Ok(patched.into_bytes())
        }
    }
}

fn render_config_fingerprint(config: &RenderConfig) -> String {
    format!(
        "{}|entity-metadata={}|output={}|time={}",
        config.version, config.include_entity_metadata, config.max_output_bytes, config.max_time_ms
    )
}
