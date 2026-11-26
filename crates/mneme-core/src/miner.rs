//! Versioned external miner contract (`mneme.miner-request` and `mneme.miner-proposal` v1).
//!
//! External miners run out-of-process with zero FFI coupling. Mneme sends a
//! read-only [`Request`] on stdin and receives a [`ProposalDocument`]
//! on stdout. Validation is deterministic and fail-closed:
//!
//! - Every proposed record must belong to the requested scope.
//! - Every proposed record must be a non-destructive addition (no predecessor).
//! - No record may promote beliefs (`accepted` / `disputed` assertions,
//!   `decision` records, or non-`proposed` proposals are refused) or delete data
//!   (`retention-directive` records are refused).
//! - Record counts, blob counts, and byte sizes must stay within [`Limits`].
#![allow(unknown_lints, type_accumulation)] // miner protocol contract and containment helpers live in one cohesive module

use serde::{Deserialize, Serialize};

/// Stdin request format identifier.
pub const REQUEST_FORMAT: &str = "mneme.miner-request";
/// Stdin request format version.
pub const REQUEST_VERSION: u32 = 1;

/// Stdout proposal format identifier.
pub const PROPOSAL_FORMAT: &str = "mneme.miner-proposal";
/// Stdout proposal format version.
pub const PROPOSAL_VERSION: u32 = 1;

/// Default maximum number of records or source blobs per miner run.
pub const DEFAULT_MAX_RECORDS: usize = 10_000;
/// Default maximum byte budget for miner stdout and inline blobs (16 MiB).
pub const DEFAULT_MAX_BYTES: u64 = 16 * 1024 * 1024;
/// Default maximum wall-clock duration for one miner execution (30 seconds).
pub const DEFAULT_MAX_WALL_CLOCK_MS: u64 = 30_000;

/// Hard upper bound on `max_records`.
pub const HARD_MAX_RECORDS: usize = 100_000;
/// Hard upper bound on `max_bytes` (256 MiB).
pub const HARD_MAX_BYTES: u64 = 256 * 1024 * 1024;
/// Hard upper bound on `max_wall_clock_ms` (1 hour).
pub const HARD_MAX_WALL_CLOCK_MS: u64 = 3_600_000;

/// Maximum length of `minerId` or `minerVersion` in bytes.
pub const MAX_ID_BYTES: usize = 128;
/// Maximum length of an opaque cursor in bytes.
pub const MAX_CURSOR_BYTES: usize = 4096;

/// Bounded resource limits communicated to and enforced on an external miner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Limits {
    pub max_records: usize,
    pub max_bytes: u64,
    pub max_wall_clock_ms: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_records: DEFAULT_MAX_RECORDS,
            max_bytes: DEFAULT_MAX_BYTES,
            max_wall_clock_ms: DEFAULT_MAX_WALL_CLOCK_MS,
        }
    }
}

impl Limits {
    /// Validate that every limit is positive and within hard upper bounds.
    pub fn validate(&self) -> Result<(), crate::problem::Diagnostic> {
        check_bound(BoundSpec {
            value: self.max_records as u64,
            hard_max: HARD_MAX_RECORDS as u64,
            field: "maxRecords",
        })?;
        check_bound(BoundSpec {
            value: self.max_bytes,
            hard_max: HARD_MAX_BYTES,
            field: "maxBytes",
        })?;
        check_bound(BoundSpec {
            value: self.max_wall_clock_ms,
            hard_max: HARD_MAX_WALL_CLOCK_MS,
            field: "maxWallClockMs",
        })
    }
}

struct BoundSpec {
    value: u64,
    hard_max: u64,
    field: &'static str,
}

fn check_bound(spec: BoundSpec) -> Result<(), crate::problem::Diagnostic> {
    if spec.value == 0 || spec.value > spec.hard_max {
        return Err(domain_diag(
            crate::problem::ErrorCode::LimitExceeded,
            crate::problem::Path::root().field(spec.field),
            format!("{} must be in 1..={}", spec.field, spec.hard_max),
        ));
    }
    Ok(())
}

/// Optional read-only attached vault reference passed to a miner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Attachment {
    pub label: String,
    pub root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Read-only request envelope sent to an external miner on stdin (`mneme.miner-request` v1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub format: String,
    pub version: u32,
    pub scope: String,
    pub base_revision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since_cursor: Option<String>,
    pub limits: Limits,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_path: Option<String>,
    #[serde(default = "Vec::new", skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
}

impl Request {
    /// Construct a version-1 miner request for `scope` and `base_revision`.
    pub fn new(
        scope: &crate::tenancy::ScopeId,
        base_revision: crate::ids::WorkspaceRevisionId,
        since_cursor: Option<String>,
        limits: Limits,
    ) -> Self {
        Self {
            format: REQUEST_FORMAT.to_owned(),
            version: REQUEST_VERSION,
            scope: scope.to_string(),
            base_revision: base_revision.to_hex(),
            since_cursor,
            limits,
            snapshot_path: None,
            attachments: Vec::new(),
        }
    }

    /// Validate a decoded [`Request`].
    pub fn validate(&self) -> Result<(), crate::problem::Diagnostic> {
        let root = crate::problem::Path::root();
        check_envelope_header(
            &self.format,
            self.version,
            &EnvelopeSpec {
                format: REQUEST_FORMAT,
                version: REQUEST_VERSION,
            },
            &root,
        )?;
        parse_scope_str(&self.scope, &root.field("scope"))?;
        parse_revision_hex(&self.base_revision, &root.field("baseRevision"))?;
        if let Some(cursor) = &self.since_cursor {
            validate_cursor(cursor, &root.field("sinceCursor"))?;
        }
        self.limits.validate()
    }
}

/// Source blob entry in a miner proposal: either inline base64 or a streaming file path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceBlob {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    pub media_type: String,
}

/// Severity of a non-fatal diagnostic emitted by a miner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticLevel {
    Info,
    Warning,
    Error,
}

/// Structured non-fatal warning or work-unit report emitted by a miner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Diagnostic {
    pub level: DiagnosticLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub work_units: Option<u64>,
}

/// Proposal envelope emitted by an external miner on stdout (`mneme.miner-proposal` v1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProposalDocument {
    pub format: String,
    pub version: u32,
    pub miner_id: String,
    pub miner_version: String,
    pub base_revision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_cursor: Option<String>,
    #[serde(default = "Vec::new")]
    pub records: Vec<serde_json::Value>,
    #[serde(default = "Vec::new")]
    pub source_blobs: Vec<SourceBlob>,
    #[serde(default = "Vec::new")]
    pub diagnostics: Vec<Diagnostic>,
}

/// A validated source blob ready for staging into the workspace store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidatedBlob {
    Inline {
        bytes: Vec<u8>,
        media_type: crate::typed::Symbol,
    },
    FilePath {
        path: String,
        media_type: crate::typed::Symbol,
    },
}

/// Validated miner proposal ready for verbatim-span verification and atomic commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedProposal {
    pub miner_id: String,
    pub miner_version: String,
    pub base_revision: crate::ids::WorkspaceRevisionId,
    pub new_cursor: Option<String>,
    pub records: Vec<crate::wire::RecordEnvelope>,
    pub source_blobs: Vec<ValidatedBlob>,
    pub diagnostics: Vec<Diagnostic>,
}

/// Parse and validate raw JSON text as a `mneme.miner-proposal` v1 envelope.
pub fn parse_and_validate_proposal(
    text: &str,
    expected_scope: &crate::tenancy::ScopeId,
    expected_base: crate::ids::WorkspaceRevisionId,
    limits: &Limits,
) -> Result<ValidatedProposal, Vec<crate::problem::Diagnostic>> {
    limits.validate().map_err(|diag| vec![diag])?;
    debug_assert!(limits.max_bytes > 0);
    if (text.len() as u64) > limits.max_bytes {
        return Err(vec![domain_diag(
            crate::problem::ErrorCode::LimitExceeded,
            crate::problem::Path::root(),
            format!(
                "miner proposal exceeds maxBytes ({} > {})",
                text.len(),
                limits.max_bytes
            ),
        )]);
    }
    let document: ProposalDocument = serde_json::from_str(text).map_err(|error| {
        vec![domain_diag(
            crate::problem::ErrorCode::InvalidTaggedJson,
            crate::problem::Path::root(),
            format!("malformed miner proposal JSON: {error}"),
        )]
    })?;
    let validated = validate_proposal(&document, expected_scope, expected_base, limits)?;
    debug_assert_eq!(validated.base_revision, expected_base);
    Ok(validated)
}

/// Validate a decoded [`ProposalDocument`] against Mneme's invariants.
pub fn validate_proposal(
    document: &ProposalDocument,
    expected_scope: &crate::tenancy::ScopeId,
    expected_base: crate::ids::WorkspaceRevisionId,
    limits: &Limits,
) -> Result<ValidatedProposal, Vec<crate::problem::Diagnostic>> {
    limits.validate().map_err(|diag| vec![diag])?;
    validate_proposal_header(document, expected_base, limits)?;

    let records = validate_proposal_records(&document.records, expected_scope)?;
    let source_blobs = validate_proposal_blobs(&document.source_blobs, limits.max_bytes)?;

    debug_assert_eq!(records.len(), document.records.len());
    debug_assert_eq!(source_blobs.len(), document.source_blobs.len());
    Ok(ValidatedProposal {
        miner_id: document.miner_id.clone(),
        miner_version: document.miner_version.clone(),
        base_revision: expected_base,
        new_cursor: document.new_cursor.clone(),
        records,
        source_blobs,
        diagnostics: document.diagnostics.clone(),
    })
}

fn validate_proposal_header(
    document: &ProposalDocument,
    expected_base: crate::ids::WorkspaceRevisionId,
    limits: &Limits,
) -> Result<(), Vec<crate::problem::Diagnostic>> {
    let root = crate::problem::Path::root();
    debug_assert!(limits.max_records > 0);
    let mut errors = Vec::with_capacity(6);
    if let Err(diag) = check_envelope_header(
        &document.format,
        document.version,
        &EnvelopeSpec {
            format: PROPOSAL_FORMAT,
            version: PROPOSAL_VERSION,
        },
        &root,
    ) {
        errors.push(diag);
    }
    if let Err(diag) = validate_token(&document.miner_id, &root.field("minerId")) {
        errors.push(diag);
    }
    if let Err(diag) = validate_token(&document.miner_version, &root.field("minerVersion")) {
        errors.push(diag);
    }
    if let Err(diag) = check_base_revision(&document.base_revision, expected_base, &root) {
        errors.push(diag);
    }
    if let Some(cursor) = &document.new_cursor
        && let Err(diag) = validate_cursor(cursor, &root.field("newCursor"))
    {
        errors.push(diag);
    }
    check_collection_limit(limits, document.records.len(), "records", &mut errors);
    check_collection_limit(
        limits,
        document.source_blobs.len(),
        "sourceBlobs",
        &mut errors,
    );
    debug_assert!(errors.len() <= 7);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn validate_proposal_records(
    raw_records: &[serde_json::Value],
    expected_scope: &crate::tenancy::ScopeId,
) -> Result<Vec<crate::wire::RecordEnvelope>, Vec<crate::problem::Diagnostic>> {
    let root = crate::problem::Path::root();
    let registry = crate::fields::SchemaRegistry::production();
    let mut records = Vec::with_capacity(raw_records.len());
    for (index, raw_record) in raw_records.iter().enumerate() {
        let record_path = root.field("records").index(index);
        records.push(validate_proposed_record(
            raw_record,
            expected_scope,
            &registry,
            &record_path,
        )?);
    }
    Ok(records)
}

fn validate_proposal_blobs(
    raw_blobs: &[SourceBlob],
    max_bytes: u64,
) -> Result<Vec<ValidatedBlob>, Vec<crate::problem::Diagnostic>> {
    let root = crate::problem::Path::root();
    let mut total_inline_bytes: u64 = 0;
    let mut source_blobs = Vec::with_capacity(raw_blobs.len());
    for (index, blob) in raw_blobs.iter().enumerate() {
        let blob_path = root.field("sourceBlobs").index(index);
        let validated = validate_source_blob(blob, &blob_path, &mut total_inline_bytes, max_bytes)
            .map_err(|diag| vec![diag])?;
        source_blobs.push(validated);
    }
    Ok(source_blobs)
}

/// Deterministic idempotency key for `(miner_id, base_revision, new_cursor)`.
pub fn idempotency_key(
    miner_id: &str,
    base_revision: crate::ids::WorkspaceRevisionId,
    new_cursor: Option<&str>,
) -> String {
    let cursor_value = match new_cursor {
        Some(cursor) => crate::typed::Value::string(cursor.to_owned()),
        None => crate::typed::Value::symbol("none"),
    };
    let payload = crate::typed::Value::record_named(
        "miner-idempotency",
        vec![
            crate::typed::Value::string(miner_id.to_owned()),
            base_revision.to_value(),
            cursor_value,
        ],
    );
    let digest = crate::hashing::ContentDigest::of_payload(&payload);
    format!("miner-v1-{}", digest.to_hex())
}

/// Whether `kind` is permitted in a miner proposal.
pub const fn is_allowed_kind(kind: crate::fields::RecordKind) -> bool {
    matches!(
        kind,
        crate::fields::RecordKind::Entity
            | crate::fields::RecordKind::Relation
            | crate::fields::RecordKind::Document
            | crate::fields::RecordKind::SourceRevision
            | crate::fields::RecordKind::Assertion
            | crate::fields::RecordKind::Evidence
            | crate::fields::RecordKind::Derivation
            | crate::fields::RecordKind::Proposal
            | crate::fields::RecordKind::DocumentBinding
            | crate::fields::RecordKind::DocumentAnchor
    )
}

fn validate_proposed_record(
    raw_record: &serde_json::Value,
    expected_scope: &crate::tenancy::ScopeId,
    registry: &crate::fields::SchemaRegistry,
    path: &crate::problem::Path,
) -> Result<crate::wire::RecordEnvelope, Vec<crate::problem::Diagnostic>> {
    let value = crate::transport::decode_value(raw_record, path).map_err(|diag| vec![diag])?;
    let envelope = crate::wire::RecordEnvelope::from_value(&value)?;
    let mut diagnostics = Vec::with_capacity(4);

    if envelope.scope != *expected_scope {
        diagnostics.push(domain_diag(
            crate::problem::ErrorCode::InvalidScope,
            path.field("scope"),
            format!(
                "record scope {} does not match requested scope {}",
                envelope.scope, expected_scope
            ),
        ));
    }
    if envelope.predecessor.is_some() {
        diagnostics.push(domain_diag(
            crate::problem::ErrorCode::InvalidPredecessor,
            path.field("predecessor"),
            "mined proposals must be non-destructive additions without a predecessor",
        ));
    }
    if !is_allowed_kind(envelope.kind) {
        diagnostics.push(domain_diag(
            crate::problem::ErrorCode::UnknownRecordKind,
            path.field("kind"),
            format!(
                "record kind {:?} is not permitted in miner proposals",
                envelope.kind.symbol()
            ),
        ));
    }
    check_non_promoted_lifecycle(&envelope, path, &mut diagnostics);

    let context = crate::wire::RecordContext {
        registry,
        resolution: None,
        prior: None,
    };
    diagnostics.extend(crate::wire::validate_record(&envelope, &context, path));
    debug_assert!(!diagnostics.is_empty() || envelope.predecessor.is_none());
    debug_assert!(!diagnostics.is_empty() || envelope.scope == *expected_scope);

    if diagnostics.is_empty() {
        Ok(envelope)
    } else {
        Err(diagnostics)
    }
}

fn check_non_promoted_lifecycle(
    envelope: &crate::wire::RecordEnvelope,
    path: &crate::problem::Path,
    diagnostics: &mut Vec<crate::problem::Diagnostic>,
) {
    debug_assert!(envelope.kind.symbol().is_ascii());
    if envelope.kind == crate::fields::RecordKind::Assertion
        && envelope.assertion_lifecycle() != Some(crate::fields::Lifecycle::Proposed)
    {
        diagnostics.push(domain_diag(
            crate::problem::ErrorCode::UnexpectedFieldKind,
            path.field("payload").field("lifecycle"),
            "mined assertions must remain strictly `proposed`",
        ));
    }
    if envelope.kind == crate::fields::RecordKind::Proposal {
        let status = envelope
            .payload
            .get("status")
            .and_then(crate::typed::Value::as_symbol)
            .map(crate::typed::Symbol::as_str);
        if status != Some("proposed") {
            diagnostics.push(domain_diag(
                crate::problem::ErrorCode::UnexpectedFieldKind,
                path.field("payload").field("status"),
                "mined proposal records must have status `proposed`",
            ));
        }
    }
    debug_assert!(
        envelope.kind != crate::fields::RecordKind::Assertion
            || envelope.assertion_lifecycle() == Some(crate::fields::Lifecycle::Proposed)
            || !diagnostics.is_empty()
    );
}

fn validate_source_blob(
    blob: &SourceBlob,
    path: &crate::problem::Path,
    total_inline_bytes: &mut u64,
    max_bytes: u64,
) -> Result<ValidatedBlob, crate::problem::Diagnostic> {
    debug_assert!(max_bytes > 0);
    if blob.media_type.trim().is_empty() || blob.media_type.chars().any(char::is_control) {
        return Err(domain_diag(
            crate::problem::ErrorCode::UnexpectedFieldKind,
            path.field("mediaType"),
            "mediaType must be a non-empty string without control characters",
        ));
    }
    let media_type = crate::typed::Symbol::from(blob.media_type.as_str());
    debug_assert!(!media_type.as_str().is_empty());
    match (&blob.bytes, &blob.file_path) {
        (Some(encoded), None) => {
            decode_inline_blob(encoded, media_type, path, total_inline_bytes, max_bytes)
        }
        (None, Some(file_path)) => validate_file_blob(file_path, media_type, path),
        (Some(_), Some(_)) => Err(domain_diag(
            crate::problem::ErrorCode::UnexpectedFieldKind,
            path.clone(),
            "sourceBlob `bytes` and `filePath` are mutually exclusive",
        )),
        (None, None) => Err(domain_diag(
            crate::problem::ErrorCode::MissingField,
            path.clone(),
            "sourceBlob requires exactly one of `bytes` or `filePath`",
        )),
    }
}

fn decode_inline_blob(
    encoded: &str,
    media_type: crate::typed::Symbol,
    path: &crate::problem::Path,
    total_inline_bytes: &mut u64,
    max_bytes: u64,
) -> Result<ValidatedBlob, crate::problem::Diagnostic> {
    let bytes = crate::base64::decode(encoded).map_err(|message| {
        domain_diag(
            crate::problem::ErrorCode::InvalidBase64,
            path.field("bytes"),
            message,
        )
    })?;
    *total_inline_bytes = total_inline_bytes.saturating_add(bytes.len() as u64);
    if *total_inline_bytes > max_bytes {
        return Err(domain_diag(
            crate::problem::ErrorCode::LimitExceeded,
            path.field("bytes"),
            format!("inline sourceBlobs exceed maxBytes ({max_bytes})"),
        ));
    }
    Ok(ValidatedBlob::Inline { bytes, media_type })
}

fn validate_file_blob(
    file_path: &str,
    media_type: crate::typed::Symbol,
    path: &crate::problem::Path,
) -> Result<ValidatedBlob, crate::problem::Diagnostic> {
    debug_assert!(!media_type.as_str().is_empty());
    if file_path.trim().is_empty()
        || file_path.contains('\0')
        || file_path.chars().any(char::is_control)
    {
        return Err(domain_diag(
            crate::problem::ErrorCode::UnexpectedFieldKind,
            path.field("filePath"),
            "filePath must be non-empty and contain no NUL or control characters",
        ));
    }
    let has_parent_dir = std::path::Path::new(file_path)
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir));
    if has_parent_dir {
        return Err(domain_diag(
            crate::problem::ErrorCode::UnexpectedFieldKind,
            path.field("filePath"),
            "filePath must not contain parent-directory (`..`) traversal components",
        ));
    }
    debug_assert!(!file_path.contains('\0'));
    Ok(ValidatedBlob::FilePath {
        path: file_path.to_owned(),
        media_type,
    })
}

/// Verify that a canonicalized candidate file path stays strictly within at least
/// one canonicalized allowed root directory.
pub fn check_canonical_path_in_roots(
    canonical_candidate: &std::path::Path,
    canonical_roots: &[std::path::PathBuf],
    path: &crate::problem::Path,
) -> Result<(), crate::problem::Diagnostic> {
    debug_assert!(!canonical_candidate.as_os_str().is_empty());
    if canonical_roots.is_empty() {
        return Err(domain_diag(
            crate::problem::ErrorCode::UnexpectedFieldKind,
            path.field("filePath"),
            "filePath blob refused because no allowed file roots are configured",
        ));
    }
    let is_contained = canonical_roots
        .iter()
        .any(|root| canonical_candidate.starts_with(root));
    if is_contained {
        debug_assert!(!canonical_roots.is_empty());
        Ok(())
    } else {
        Err(domain_diag(
            crate::problem::ErrorCode::UnexpectedFieldKind,
            path.field("filePath"),
            format!(
                "filePath {} escapes allowed file roots",
                canonical_candidate.display()
            ),
        ))
    }
}

/// Byte charge applied against a miner proposal's total `max_bytes` budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobByteCharge {
    pub added_bytes: u64,
    pub max_bytes: u64,
}

/// Charge `charge.added_bytes` (inline or streamed file) against `charge.max_bytes`, failing closed on overflow.
pub fn check_total_blob_bytes(
    accumulated_bytes: &mut u64,
    charge: BlobByteCharge,
    path: &crate::problem::Path,
) -> Result<(), crate::problem::Diagnostic> {
    debug_assert!(charge.max_bytes > 0);
    let next = accumulated_bytes.saturating_add(charge.added_bytes);
    if next > charge.max_bytes {
        return Err(domain_diag(
            crate::problem::ErrorCode::LimitExceeded,
            path.clone(),
            format!(
                "total sourceBlobs ({next} bytes) exceed maxBytes ({})",
                charge.max_bytes
            ),
        ));
    }
    *accumulated_bytes = next;
    debug_assert!(*accumulated_bytes <= charge.max_bytes);
    Ok(())
}

struct EnvelopeSpec {
    format: &'static str,
    version: u32,
}

fn check_envelope_header(
    format: &str,
    version: u32,
    expected: &EnvelopeSpec,
    root: &crate::problem::Path,
) -> Result<(), crate::problem::Diagnostic> {
    debug_assert!(!expected.format.is_empty());
    if format != expected.format {
        return Err(domain_diag(
            crate::problem::ErrorCode::InvalidTaggedJson,
            root.field("format"),
            format!("expected format {:?}", expected.format),
        ));
    }
    if version != expected.version {
        return Err(domain_diag(
            crate::problem::ErrorCode::UnsupportedSchemaVersion,
            root.field("version"),
            format!("expected version {}", expected.version),
        ));
    }
    debug_assert_eq!(format, expected.format);
    Ok(())
}

fn check_base_revision(
    hex: &str,
    expected_base: crate::ids::WorkspaceRevisionId,
    root: &crate::problem::Path,
) -> Result<(), crate::problem::Diagnostic> {
    let parsed = parse_revision_hex(hex, &root.field("baseRevision"))?;
    if parsed != expected_base {
        return Err(domain_diag(
            crate::problem::ErrorCode::InvalidIdentifier,
            root.field("baseRevision"),
            format!(
                "proposal baseRevision {hex} does not match expected {}",
                expected_base.to_hex()
            ),
        ));
    }
    Ok(())
}

fn parse_revision_hex(
    hex: &str,
    path: &crate::problem::Path,
) -> Result<crate::ids::WorkspaceRevisionId, crate::problem::Diagnostic> {
    crate::ids::WorkspaceRevisionId::from_hex(hex).map_err(|message| {
        domain_diag(
            crate::problem::ErrorCode::InvalidIdentifier,
            path.clone(),
            message,
        )
    })
}

fn check_collection_limit(
    limits: &Limits,
    len: usize,
    field: &'static str,
    errors: &mut Vec<crate::problem::Diagnostic>,
) {
    if len > limits.max_records {
        errors.push(domain_diag(
            crate::problem::ErrorCode::LimitExceeded,
            crate::problem::Path::root().field(field),
            format!(
                "{field} count {len} exceeds maxRecords {}",
                limits.max_records
            ),
        ));
    }
}

fn validate_token(
    value: &str,
    path: &crate::problem::Path,
) -> Result<(), crate::problem::Diagnostic> {
    if value.trim().is_empty() || value.len() > MAX_ID_BYTES || value.chars().any(char::is_control)
    {
        return Err(domain_diag(
            crate::problem::ErrorCode::InvalidIdentifier,
            path.clone(),
            format!(
                "must be non-empty, at most {MAX_ID_BYTES} bytes, and contain no control characters"
            ),
        ));
    }
    Ok(())
}

fn validate_cursor(
    cursor: &str,
    path: &crate::problem::Path,
) -> Result<(), crate::problem::Diagnostic> {
    if cursor.len() > MAX_CURSOR_BYTES || cursor.chars().any(char::is_control) {
        return Err(domain_diag(
            crate::problem::ErrorCode::LimitExceeded,
            path.clone(),
            format!(
                "cursor must be at most {MAX_CURSOR_BYTES} bytes and contain no control characters"
            ),
        ));
    }
    Ok(())
}

fn parse_scope_str(
    text: &str,
    path: &crate::problem::Path,
) -> Result<crate::tenancy::ScopeId, crate::problem::Diagnostic> {
    debug_assert!(text.is_ascii() || !text.is_empty());
    let Some((class_text, local)) = text.split_once(':') else {
        return Err(domain_diag(
            crate::problem::ErrorCode::InvalidScope,
            path.clone(),
            "scope must be `<class>:<local>`",
        ));
    };
    let Some(class) = crate::tenancy::ScopeClass::parse(class_text) else {
        return Err(domain_diag(
            crate::problem::ErrorCode::InvalidScope,
            path.clone(),
            format!("unknown scope class {class_text:?}"),
        ));
    };
    let scope = crate::tenancy::ScopeId::new(class, local).map_err(|message| {
        domain_diag(
            crate::problem::ErrorCode::InvalidScope,
            path.clone(),
            message,
        )
    })?;
    debug_assert_eq!(scope.local(), local);
    Ok(scope)
}

fn domain_diag(
    code: crate::problem::ErrorCode,
    path: crate::problem::Path,
    message: impl Into<String>,
) -> crate::problem::Diagnostic {
    crate::problem::Diagnostic::new(crate::problem::Stage::Domain, code, path, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_scope() -> crate::tenancy::ScopeId {
        crate::tenancy::ScopeId::new(crate::tenancy::ScopeClass::Project, "miner-test")
            .expect("valid scope")
    }

    fn base_revision() -> crate::ids::WorkspaceRevisionId {
        crate::ids::WorkspaceRevisionId::from_bytes([1_u8; 16])
    }

    fn fixture_scope() -> crate::tenancy::ScopeId {
        crate::fixtures::proposed_assertion().scope
    }

    fn proposed_assertion_json() -> serde_json::Value {
        crate::transport::encode_value(&crate::fixtures::proposed_assertion().to_value())
    }

    fn accepted_assertion_json() -> serde_json::Value {
        crate::transport::encode_value(&crate::fixtures::accepted_assertion().to_value())
    }

    #[test]
    fn request_roundtrips_and_validates() {
        let req = Request::new(
            &test_scope(),
            base_revision(),
            Some("cursor-1".to_owned()),
            Limits::default(),
        );
        req.validate().expect("valid request");
        let json = serde_json::to_string(&req).expect("serialize");
        let decoded: Request = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, req);
        decoded.validate().expect("valid decoded");
    }

    #[test]
    fn valid_proposed_assertion_proposal_passes() {
        let scope = fixture_scope();
        let doc = ProposalDocument {
            format: PROPOSAL_FORMAT.to_owned(),
            version: PROPOSAL_VERSION,
            miner_id: "vein".to_owned(),
            miner_version: "0.1.0".to_owned(),
            base_revision: base_revision().to_hex(),
            new_cursor: Some("rev-2".to_owned()),
            records: vec![proposed_assertion_json()],
            source_blobs: vec![],
            diagnostics: vec![Diagnostic {
                level: DiagnosticLevel::Info,
                code: None,
                message: "scanned 1 crate".to_owned(),
                work_units: Some(42),
            }],
        };
        let validated = validate_proposal(&doc, &scope, base_revision(), &Limits::default())
            .expect("valid proposal");
        assert_eq!(validated.records.len(), 1);
        assert_eq!(
            validated.records[0].assertion_lifecycle(),
            Some(crate::fields::Lifecycle::Proposed)
        );
    }

    #[test]
    fn accepted_assertion_is_refused() {
        let scope = fixture_scope();
        let doc = ProposalDocument {
            format: PROPOSAL_FORMAT.to_owned(),
            version: PROPOSAL_VERSION,
            miner_id: "vein".to_owned(),
            miner_version: "0.1.0".to_owned(),
            base_revision: base_revision().to_hex(),
            new_cursor: None,
            records: vec![accepted_assertion_json()],
            source_blobs: vec![],
            diagnostics: vec![],
        };
        let errors = validate_proposal(&doc, &scope, base_revision(), &Limits::default())
            .expect_err("accepted assertion must be refused");
        assert!(errors.iter().any(|diag| diag.message.contains("proposed")));
    }

    #[test]
    fn unknown_fields_and_wrong_format_are_refused() {
        let scope = fixture_scope();
        let bad_json = serde_json::json!({
            "format": "wrong.format",
            "version": 1,
            "minerId": "x",
            "minerVersion": "1",
            "baseRevision": base_revision().to_hex(),
            "extra": true
        })
        .to_string();
        assert!(
            parse_and_validate_proposal(&bad_json, &scope, base_revision(), &Limits::default())
                .is_err()
        );
    }

    #[test]
    fn idempotency_key_is_deterministic() {
        let k1 = idempotency_key("vein", base_revision(), Some("c1"));
        let k2 = idempotency_key("vein", base_revision(), Some("c1"));
        let k3 = idempotency_key("vein", base_revision(), Some("c2"));
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
        assert!(k1.len() <= 256);
    }

    #[test]
    fn predecessor_and_scope_mismatch_are_refused() {
        let mut record = crate::fixtures::proposed_assertion();
        record.predecessor = Some(crate::ids::RevisionId::from_bytes([9_u8; 16]));
        let wrong_scope = test_scope();
        let doc = ProposalDocument {
            format: PROPOSAL_FORMAT.to_owned(),
            version: PROPOSAL_VERSION,
            miner_id: "vein".to_owned(),
            miner_version: "0.1.0".to_owned(),
            base_revision: base_revision().to_hex(),
            new_cursor: None,
            records: vec![crate::transport::encode_value(&record.to_value())],
            source_blobs: vec![],
            diagnostics: vec![],
        };
        let errors = validate_proposal(&doc, &wrong_scope, base_revision(), &Limits::default())
            .expect_err("predecessor and scope mismatch must be refused");
        assert!(
            errors
                .iter()
                .any(|d| d.code == crate::problem::ErrorCode::InvalidPredecessor)
        );
        assert!(
            errors
                .iter()
                .any(|d| d.code == crate::problem::ErrorCode::InvalidScope)
        );
    }

    #[test]
    fn streaming_file_path_blob_validates_and_rejects_ambiguous_blob() {
        let scope = fixture_scope();
        let valid_doc = ProposalDocument {
            format: PROPOSAL_FORMAT.to_owned(),
            version: PROPOSAL_VERSION,
            miner_id: "pdf-miner".to_owned(),
            miner_version: "0.1.0".to_owned(),
            base_revision: base_revision().to_hex(),
            new_cursor: None,
            records: vec![],
            source_blobs: vec![SourceBlob {
                bytes: None,
                file_path: Some("/tmp/sample.adoc".to_owned()),
                media_type: "text/asciidoc".to_owned(),
            }],
            diagnostics: vec![],
        };
        let validated = validate_proposal(&valid_doc, &scope, base_revision(), &Limits::default())
            .expect("streaming filePath blob should validate");
        assert_eq!(validated.source_blobs.len(), 1);

        let ambiguous_doc = ProposalDocument {
            source_blobs: vec![SourceBlob {
                bytes: Some("aGVsbG8=".to_owned()),
                file_path: Some("/tmp/sample.adoc".to_owned()),
                media_type: "text/plain".to_owned(),
            }],
            ..valid_doc
        };
        assert!(
            validate_proposal(&ambiguous_doc, &scope, base_revision(), &Limits::default()).is_err()
        );
    }

    #[test]
    fn file_path_traversal_and_containment_helpers_fail_closed() {
        let scope = fixture_scope();
        let traversal_doc = ProposalDocument {
            format: PROPOSAL_FORMAT.to_owned(),
            version: PROPOSAL_VERSION,
            miner_id: "pdf-miner".to_owned(),
            miner_version: "0.1.0".to_owned(),
            base_revision: base_revision().to_hex(),
            new_cursor: None,
            records: vec![],
            source_blobs: vec![SourceBlob {
                bytes: None,
                file_path: Some("/workspace/working/../../etc/passwd".to_owned()),
                media_type: "text/plain".to_owned(),
            }],
            diagnostics: vec![],
        };
        assert!(
            validate_proposal(&traversal_doc, &scope, base_revision(), &Limits::default()).is_err()
        );

        let root = std::path::PathBuf::from("/workspace/working");
        let inside = std::path::PathBuf::from("/workspace/working/note.adoc");
        let outside = std::path::PathBuf::from("/workspace/sync/identity.key");
        let path = crate::problem::Path::root();
        assert!(check_canonical_path_in_roots(&inside, std::slice::from_ref(&root), &path).is_ok());
        assert!(
            check_canonical_path_in_roots(&outside, std::slice::from_ref(&root), &path).is_err()
        );
        assert!(check_canonical_path_in_roots(&inside, &[], &path).is_err());

        let mut acc: u64 = 0;
        assert!(
            check_total_blob_bytes(
                &mut acc,
                BlobByteCharge {
                    added_bytes: 60,
                    max_bytes: 100,
                },
                &path,
            )
            .is_ok()
        );
        assert_eq!(acc, 60);
        assert!(
            check_total_blob_bytes(
                &mut acc,
                BlobByteCharge {
                    added_bytes: 41,
                    max_bytes: 100,
                },
                &path,
            )
            .is_err()
        );
        assert_eq!(acc, 60);
    }
}
