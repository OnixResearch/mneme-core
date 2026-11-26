//! Strictly read-only, revision-pinned `irpc` protocol for vault federation.
//!
//! No mutation, publication, or key-rotation messages exist in this protocol.
//! Every query binds an explicit scope, pins an explicit workspace revision (or
//! head at query start), and carries explicit work, row, time, and byte limits.
#![allow(unknown_lints)] // Octet structural exception: irpc macro generates internal paths

const DEFAULT_MAX_WORK: u64 = 100_000;
const DEFAULT_MAX_ROWS: u64 = 10_000;
const DEFAULT_MAX_TIME_MS: u64 = 2_000;
const DEFAULT_MAX_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_MAX_SUPPORTS_PER_FACT: u64 = 8;
const DEFAULT_MAX_RECURSION_DEPTH: u64 = 32;
const DEFAULT_EXPLAIN_MAX_WORK: u64 = 10_000;
const DEFAULT_EXPLAIN_MAX_DEPTH: u32 = 16;
const DEFAULT_EXPLAIN_MAX_REASONS: u32 = 64;

/// Protocol wire version.
pub const PROTOCOL_VERSION: u32 = 1;
/// ALPN identifier negotiated by Iroh and Quinn federation endpoints.
pub const FEDERATION_ALPN: &[u8] = b"mneme/federation-irpc/1";

/// Explicit resource bounds enforced on remote read-only federation RPCs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FederationLimits {
    pub max_work: u64,
    pub max_rows: u64,
    pub max_time_ms: u64,
    pub max_bytes: u64,
    pub max_supports_per_fact: u64,
    pub max_recursion_depth: u64,
}

impl Default for FederationLimits {
    fn default() -> Self {
        Self::standard()
    }
}

impl FederationLimits {
    /// Standard bounded federation limits.
    pub const fn standard() -> Self {
        Self {
            max_work: DEFAULT_MAX_WORK,
            max_rows: DEFAULT_MAX_ROWS,
            max_time_ms: DEFAULT_MAX_TIME_MS,
            max_bytes: DEFAULT_MAX_BYTES,
            max_supports_per_fact: DEFAULT_MAX_SUPPORTS_PER_FACT,
            max_recursion_depth: DEFAULT_MAX_RECURSION_DEPTH,
        }
    }

    fn as_array(&self) -> [u64; 6] {
        [
            self.max_work,
            self.max_rows,
            self.max_time_ms,
            self.max_bytes,
            self.max_supports_per_fact,
            self.max_recursion_depth,
        ]
    }

    /// Validate that every bound is strictly positive.
    pub fn validate(&self) -> Result<(), RpcError> {
        if self.as_array().contains(&0) {
            return Err(RpcError::new(
                RpcErrorCode::InvalidInput,
                "federation limits must all be non-zero",
            ));
        }
        Ok(())
    }

    /// Fail closed if any requested limit exceeds `ceiling`.
    pub fn check_within(&self, ceiling: &Self) -> Result<(), RpcError> {
        self.validate()?;
        let is_exceeded = self
            .as_array()
            .into_iter()
            .zip(ceiling.as_array())
            .any(|(requested, allowed)| requested > allowed);
        if is_exceeded {
            return Err(RpcError::new(
                RpcErrorCode::BudgetExceeded,
                "requested limits exceed server federation ceiling",
            ));
        }
        Ok(())
    }

    /// Convert to bounded `mneme_datalog::Limits`, refusing overflow on narrow targets.
    pub fn to_datalog_limits(&self) -> Result<mneme_datalog::Limits, RpcError> {
        self.validate()?;
        let max_result_rows = usize::try_from(self.max_rows).map_err(|_| {
            RpcError::new(
                RpcErrorCode::BudgetExceeded,
                "max_rows exceeds platform row capacity",
            )
        })?;
        let max_supports_per_fact = usize::try_from(self.max_supports_per_fact).map_err(|_| {
            RpcError::new(
                RpcErrorCode::BudgetExceeded,
                "max_supports_per_fact exceeds platform capacity",
            )
        })?;
        let max_recursion_depth = usize::try_from(self.max_recursion_depth).map_err(|_| {
            RpcError::new(
                RpcErrorCode::BudgetExceeded,
                "max_recursion_depth exceeds platform capacity",
            )
        })?;
        assert!(self.max_work > 0);
        assert!(self.max_time_ms > 0);
        Ok(mneme_datalog::Limits {
            max_work: self.max_work,
            max_time_ms: u128::from(self.max_time_ms),
            max_result_rows,
            max_supports_per_fact,
            max_recursion_depth,
        })
    }
}

/// Whether an evaluation accepts a served revision older than the requested revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StalePolicy {
    Refuse,
    Allow,
}

/// Machine-readable refusal codes for read-only federation RPCs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RpcErrorCode {
    Unauthorized,
    InvalidInput,
    NotFound,
    Conflict,
    BudgetExceeded,
    Stale,
    Unavailable,
    ProtocolError,
}

/// Typed RPC failure returned by the remote federation service.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RpcError {
    pub code: RpcErrorCode,
    pub message: String,
}

impl RpcError {
    /// Construct a structured RPC error.
    pub fn new(code: RpcErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for RpcError {}

/// Request the remote vault's current head revision and eligibility generation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct QueryHeadRequest {
    pub scope: String,
    pub capability_document: Option<String>,
}

/// Head revision state returned by [`QueryHeadRequest`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HeadState {
    pub protocol_version: u32,
    pub head_revision: [u8; 16],
    pub head_sequence: u64,
    pub eligibility_generation: u64,
}

/// Request scoped metadata for a pinned or head revision.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct QueryMetadataRequest {
    pub scope: String,
    pub revision: Option<[u8; 16]>,
    pub capability_document: Option<String>,
}

/// Scoped read-only vault metadata returned by [`QueryMetadataRequest`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VaultMetadata {
    pub protocol_version: u32,
    pub requested_revision: [u8; 16],
    pub served_revision: [u8; 16],
    pub sequence: u64,
    pub eligibility_generation: u64,
    pub scoped_record_count: u64,
    pub max_limits: FederationLimits,
}

/// Request a strictly read-only, scope-filtered pinned snapshot view.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FetchPinnedSnapshotRequest {
    pub scope: String,
    pub revision: Option<[u8; 16]>,
    pub limits: FederationLimits,
    pub capability_document: Option<String>,
}

/// Wire representation of one retention suppression entry.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EncodedSuppression {
    pub operation_id: String,
    pub target: [u8; 16],
    pub revision: Option<[u8; 16]>,
    pub target_kind: String,
    pub mode: String,
    pub content_digest_document: Option<String>,
    pub generation: u64,
}

/// Wire representation of `mneme_memory::SourceAvailability`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EncodedSourceAvailability {
    Retained,
    Pruned,
    Erased,
    Inaccessible,
    Corrupt(String),
    Unavailable(String),
}

/// Scoped, revision-pinned snapshot payload returned by [`FetchPinnedSnapshotRequest`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PinnedSnapshotPayload {
    pub protocol_version: u32,
    pub requested_revision: [u8; 16],
    pub served_revision: [u8; 16],
    pub sequence: u64,
    pub parent: Option<[u8; 16]>,
    pub manifest_digest_document: String,
    pub eligibility_generation: u64,
    pub record_documents: Vec<String>,
    pub history_documents: Vec<String>,
    pub revision_sequences: Vec<([u8; 16], u64)>,
    pub suppressions: Vec<EncodedSuppression>,
    pub current_sources: Vec<([u8; 16], EncodedSourceAvailability)>,
}

/// Request a bounded remote Datalog evaluation over one pinned vault revision.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EvaluateDatalogRequest {
    pub scope: String,
    pub revision: Option<[u8; 16]>,
    pub bundle_document: String,
    pub predicate: String,
    pub constant_documents: Vec<Option<String>>,
    pub max_rows: u64,
    pub at: Option<i64>,
    pub incomplete_extents: Vec<String>,
    pub stale_policy: StalePolicy,
    pub limits: FederationLimits,
    pub capability_document: Option<String>,
}

/// Wire representation of one `(record_id, revision_id)` source provenance key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RemoteSourceKey {
    pub record_id: [u8; 16],
    pub revision_id: [u8; 16],
}

/// Remote predicate coverage status.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RemoteCoverage {
    pub predicate: String,
    pub status: String,
    pub reason: Option<String>,
}

/// Remote premise provenance.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RemotePremise {
    pub predicate: String,
    pub term_documents: Vec<String>,
    pub canonical: Option<[u8; 16]>,
    pub canonical_roots: Vec<[u8; 16]>,
    pub sources: Vec<RemoteSourceKey>,
    pub vault: Option<String>,
    pub vaults: Vec<String>,
    pub absent: bool,
    pub coverage: Option<String>,
    pub source_availability: Option<String>,
    pub epistemic: String,
}

/// Remote derivation support for one answer row.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RemoteDerivation {
    pub rule_id: String,
    pub rule_version: String,
    pub premises: Vec<RemotePremise>,
    pub sources: Vec<RemoteSourceKey>,
    pub vaults: Vec<String>,
    pub temporal_parameters: Vec<String>,
    pub truncated: bool,
    pub epistemic: String,
}

/// One row returned by [`EvaluateDatalogRequest`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RemoteQueryRow {
    pub value_documents: Vec<String>,
    pub supports: Vec<RemoteDerivation>,
    pub support_truncated: bool,
    pub epistemic: String,
}

/// Bounded Datalog evaluation result returned by [`EvaluateDatalogRequest`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RemoteDatalogResult {
    pub protocol_version: u32,
    pub relation: String,
    pub status: String,
    pub requested_revision: [u8; 16],
    pub served_revision: [u8; 16],
    pub eligibility_generation: u64,
    pub at: Option<i64>,
    pub incomplete_extents: Vec<String>,
    pub coverage: Vec<RemoteCoverage>,
    pub rows: Vec<RemoteQueryRow>,
    pub exhaustive: bool,
    pub truncated: bool,
    pub absence_established: bool,
    pub stale: bool,
    pub reason: Option<String>,
    pub work: u64,
}

/// Explicit traversal bounds for a remote Why-Not [`ExplainMissingRpcRequest`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RemoteExplainLimits {
    pub max_work: u64,
    pub max_depth: u32,
    pub max_reasons: u32,
}

impl Default for RemoteExplainLimits {
    fn default() -> Self {
        Self::standard()
    }
}

impl RemoteExplainLimits {
    /// Standard bounded Why-Not traversal limits.
    pub const fn standard() -> Self {
        Self {
            max_work: DEFAULT_EXPLAIN_MAX_WORK,
            max_depth: DEFAULT_EXPLAIN_MAX_DEPTH,
            max_reasons: DEFAULT_EXPLAIN_MAX_REASONS,
        }
    }

    /// Validate that every explain bound is strictly positive.
    pub fn validate(&self) -> Result<(), RpcError> {
        if self.max_work == 0 || self.max_depth == 0 || self.max_reasons == 0 {
            return Err(RpcError::new(
                RpcErrorCode::InvalidInput,
                "explain-missing limits must all be non-zero",
            ));
        }
        Ok(())
    }

    /// Fail closed if any explain bound exceeds `ceiling`.
    pub fn check_within(&self, ceiling: &FederationLimits) -> Result<(), RpcError> {
        self.validate()?;
        if self.max_work > ceiling.max_work
            || u64::from(self.max_depth) > ceiling.max_recursion_depth
            || u64::from(self.max_reasons) > ceiling.max_rows
        {
            return Err(RpcError::new(
                RpcErrorCode::BudgetExceeded,
                "requested explain-missing limits exceed server federation ceiling",
            ));
        }
        Ok(())
    }

    /// Convert into `mneme_datalog::ExplainLimits`.
    pub const fn to_datalog_limits(&self) -> mneme_datalog::ExplainLimits {
        mneme_datalog::ExplainLimits {
            max_work: self.max_work,
            max_depth: self.max_depth,
            max_reasons: self.max_reasons,
        }
    }
}

/// Request a bounded remote Why-Not explanation over one pinned vault revision.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExplainMissingRpcRequest {
    pub scope: String,
    pub revision: Option<[u8; 16]>,
    pub bundle_document: String,
    pub predicate: String,
    pub term_documents: Vec<String>,
    pub at: Option<i64>,
    pub incomplete_extents: Vec<String>,
    pub stale_policy: StalePolicy,
    pub limits: FederationLimits,
    pub explain_limits: RemoteExplainLimits,
    pub capability_document: Option<String>,
}

/// Wire representation of one term inside a [`RemoteMissingReason`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RemoteMissingTerm {
    Variable(String),
    Constant(String),
}

/// Wire representation of one structured Why-Not cause.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RemoteMissingReason {
    pub kind: String,
    pub rule_id: Option<String>,
    pub predicate: Option<String>,
    pub terms: Vec<RemoteMissingTerm>,
    pub detail: String,
    pub blocker_epistemic: Option<String>,
    pub blocker_supports: Vec<RemoteDerivation>,
    pub causes: Vec<RemoteMissingReason>,
}

/// Bounded remote Why-Not explanation returned by [`ExplainMissingRpcRequest`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RemoteMissingExplanation {
    pub protocol_version: u32,
    pub predicate: String,
    pub term_documents: Vec<String>,
    pub status: String,
    pub build_status: String,
    pub requested_revision: [u8; 16],
    pub served_revision: [u8; 16],
    pub eligibility_generation: u64,
    pub at: Option<i64>,
    pub incomplete_extents: Vec<String>,
    pub coverage: Vec<RemoteCoverage>,
    pub present_epistemic: Option<String>,
    pub present_supports: Vec<RemoteDerivation>,
    pub reasons: Vec<RemoteMissingReason>,
    pub truncated: bool,
    pub exhaustive: bool,
    pub stale: bool,
    pub work: u64,
}

/// Strictly read-only, revision-pinned `irpc` protocol for remote vault federation.
#[irpc::rpc_requests(message = VaultFederationMessage, no_spans)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum VaultFederationProtocol {
    #[rpc(tx = irpc::channel::oneshot::Sender<Result<HeadState, RpcError>>)]
    QueryHead(QueryHeadRequest),
    #[rpc(tx = irpc::channel::oneshot::Sender<Result<VaultMetadata, RpcError>>)]
    QueryMetadata(QueryMetadataRequest),
    #[rpc(tx = irpc::channel::oneshot::Sender<Result<PinnedSnapshotPayload, RpcError>>)]
    FetchPinnedSnapshot(FetchPinnedSnapshotRequest),
    #[rpc(tx = irpc::channel::oneshot::Sender<Result<RemoteDatalogResult, RpcError>>)]
    EvaluateDatalog(EvaluateDatalogRequest),
    #[rpc(tx = irpc::channel::oneshot::Sender<Result<RemoteMissingExplanation, RpcError>>)]
    ExplainMissing(ExplainMissingRpcRequest),
}

/// Compute the deterministic scoped manifest digest binding `revision`, `parent`,
/// every returned current record (including its full canonical payload), and every
/// returned history record. Both server and client compute this exact digest to
/// detect tampering, drops, or injection of remote snapshot records.
pub fn scoped_manifest_digest<'a>(
    revision: mneme_core::WorkspaceRevisionId,
    parent: Option<mneme_core::WorkspaceRevisionId>,
    records: impl IntoIterator<Item = &'a mneme_core::RecordEnvelope>,
    history: impl IntoIterator<Item = &'a mneme_core::RecordEnvelope>,
    algorithm: mneme_core::HashAlgorithm,
) -> mneme_core::ContentDigest {
    let parent_value = match parent {
        Some(rev) => rev.to_value(),
        None => mneme_core::Value::symbol("none"),
    };
    let record_entries = mneme_core::Value::set(
        records
            .into_iter()
            .map(|envelope| scoped_manifest_record_value(envelope, algorithm)),
    );
    let history_entries = mneme_core::Value::set(
        history
            .into_iter()
            .map(|envelope| scoped_manifest_record_value(envelope, algorithm)),
    );
    let manifest_value = mneme_core::Value::record_named(
        "scoped-federation-manifest",
        vec![
            revision.to_value(),
            parent_value,
            record_entries,
            history_entries,
        ],
    );
    debug_assert!(manifest_value.as_record().is_some());
    let digest = mneme_core::ContentDigest::of_payload_with(&manifest_value, algorithm);
    debug_assert_eq!(digest.algorithm(), algorithm);
    digest
}

fn scoped_manifest_record_value(
    envelope: &mneme_core::RecordEnvelope,
    algorithm: mneme_core::HashAlgorithm,
) -> mneme_core::Value {
    let payload_digest =
        mneme_core::ContentDigest::of_payload_with(&envelope.to_value(), algorithm);
    mneme_core::Value::record_named(
        "scoped-manifest-record",
        vec![
            envelope.record_id.to_value(),
            envelope.revision_id.to_value(),
            envelope.kind.to_value(),
            envelope.scope.to_value(),
            payload_digest.to_value(),
        ],
    )
}
