//! Client-side typed federation RPC and `iroh://` attachment parsing.

use std::str::FromStr;

/// Client-side failure from remote federation transport, verification, or policy.
#[derive(Debug, thiserror::Error)]
pub enum FederationError {
    #[error("unauthorized peer: {0}")]
    Unauthorized(String),
    #[error("invalid federation input: {0}")]
    InvalidInput(String),
    #[error("remote resource not found: {0}")]
    NotFound(String),
    #[error("remote eligibility conflict: {0}")]
    Conflict(String),
    #[error("federation budget exceeded: {0}")]
    BudgetExceeded(String),
    #[error("stale remote revision: {0}")]
    Stale(String),
    #[error("remote vault unavailable: {0}")]
    Unavailable(String),
    #[error("remote protocol violation: {0}")]
    ProtocolError(String),
    #[error("clock skew exceeded: {0}")]
    ClockSkewExceeded(String),
    #[error("federation transport error: {0}")]
    Transport(String),
}

impl From<super::protocol::RpcError> for FederationError {
    fn from(error: super::protocol::RpcError) -> Self {
        match error.code {
            super::protocol::RpcErrorCode::Unauthorized => {
                FederationError::Unauthorized(error.message)
            }
            super::protocol::RpcErrorCode::InvalidInput => {
                FederationError::InvalidInput(error.message)
            }
            super::protocol::RpcErrorCode::NotFound => FederationError::NotFound(error.message),
            super::protocol::RpcErrorCode::Conflict => FederationError::Conflict(error.message),
            super::protocol::RpcErrorCode::BudgetExceeded => {
                FederationError::BudgetExceeded(error.message)
            }
            super::protocol::RpcErrorCode::Stale => FederationError::Stale(error.message),
            super::protocol::RpcErrorCode::Unavailable => {
                FederationError::Unavailable(error.message)
            }
            super::protocol::RpcErrorCode::ProtocolError => {
                FederationError::ProtocolError(error.message)
            }
            super::protocol::RpcErrorCode::ClockSkewExceeded => {
                FederationError::ClockSkewExceeded(error.message)
            }
        }
    }
}

/// Target of one `--attach` specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttachmentTarget {
    Local(std::path::PathBuf),
    Iroh {
        node_id: iroh::EndpointId,
        canonical_uri: String,
    },
}

/// Parsed `--attach <ALIAS>=<TARGET>[@<REVISION>]` entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedAttachment {
    pub alias: String,
    pub target: AttachmentTarget,
    pub revision: Option<mneme_core::WorkspaceRevisionId>,
}

/// Parse `<ALIAS>=<ROOT_OR_IROH_URI>[@<REVISION>]`.
pub fn parse_attachment_spec(spec: &str) -> Result<ParsedAttachment, FederationError> {
    let (alias, rest) = spec.split_once('=').ok_or_else(|| {
        FederationError::InvalidInput(format!(
            "invalid --attach {spec:?}: expected <ALIAS>=<TARGET>[@<REVISION>]"
        ))
    })?;
    mneme_datalog::validate_vault_alias(alias)
        .map_err(|error| FederationError::InvalidInput(error.to_string()))?;
    assert!(!alias.is_empty());
    let parsed = if let Some(iroh_rest) = rest.strip_prefix("iroh://") {
        parse_iroh_attachment(spec, alias, iroh_rest)?
    } else {
        parse_local_attachment(spec, alias, rest)?
    };
    assert_eq!(parsed.alias, alias);
    Ok(parsed)
}

fn parse_iroh_attachment(
    spec: &str,
    alias: &str,
    iroh_rest: &str,
) -> Result<ParsedAttachment, FederationError> {
    let (node_part, revision) = match iroh_rest.split_once('@') {
        Some((node, rev)) => {
            if node.is_empty() || rev.is_empty() {
                return Err(FederationError::InvalidInput(format!(
                    "invalid --attach {spec:?}: expected <ALIAS>=iroh://<NODE_ID>[@<REVISION>]"
                )));
            }
            let parsed = mneme_core::WorkspaceRevisionId::from_hex(rev)
                .map_err(|message| FederationError::InvalidInput(message.to_owned()))?;
            (node, Some(parsed))
        }
        None => (iroh_rest, None),
    };
    if node_part.trim().is_empty() {
        return Err(FederationError::InvalidInput(format!(
            "invalid --attach {spec:?}: iroh node id must not be empty"
        )));
    }
    let node_id = iroh::EndpointId::from_str(node_part).map_err(|error| {
        FederationError::InvalidInput(format!(
            "invalid --attach {spec:?}: invalid Ed25519 node id {node_part:?}: {error}"
        ))
    })?;
    Ok(ParsedAttachment {
        alias: alias.to_owned(),
        target: AttachmentTarget::Iroh {
            node_id,
            canonical_uri: format!("iroh://{node_id}"),
        },
        revision,
    })
}

fn parse_local_attachment(
    spec: &str,
    alias: &str,
    rest: &str,
) -> Result<ParsedAttachment, FederationError> {
    let last_sep = rest.rfind(['/', std::path::MAIN_SEPARATOR]);
    let (root_part, revision) = match rest.rfind('@') {
        Some(at_pos) if last_sep.is_none_or(|sep| at_pos > sep) => {
            let root_text = &rest[..at_pos];
            let rev_start = at_pos.checked_add(1).ok_or_else(|| {
                FederationError::InvalidInput("attachment revision offset overflow".to_owned())
            })?;
            let rev_text = &rest[rev_start..];
            if root_text.is_empty() || rev_text.is_empty() {
                return Err(FederationError::InvalidInput(format!(
                    "invalid --attach {spec:?}: expected <ALIAS>=<VAULT_ROOT>[@<REVISION>]"
                )));
            }
            let parsed = mneme_core::WorkspaceRevisionId::from_hex(rev_text)
                .map_err(|message| FederationError::InvalidInput(message.to_owned()))?;
            (root_text, Some(parsed))
        }
        _ => (rest, None),
    };
    if root_part.trim().is_empty() {
        return Err(FederationError::InvalidInput(format!(
            "invalid --attach {spec:?}: vault root must not be empty"
        )));
    }
    Ok(ParsedAttachment {
        alias: alias.to_owned(),
        target: AttachmentTarget::Local(std::path::PathBuf::from(root_part)),
        revision,
    })
}

/// Parameters for [`VaultFederationClient::evaluate_datalog`].
#[derive(Clone, Debug)]
pub struct RemoteDatalogRequest {
    pub scope: mneme_core::ScopeId,
    pub revision: Option<mneme_core::WorkspaceRevisionId>,
    pub read_hlc: Option<mneme_kernel::hlc::HybridTimestamp>,
    pub calm_seal: Option<super::protocol::CalmSeal>,
    pub bundle: mneme_datalog::RuleBundle,
    pub predicate: String,
    pub constants: Vec<Option<mneme_core::Value>>,
    pub limit: u64,
    pub at: Option<mneme_core::Timestamp>,
    pub incomplete_extents: std::collections::BTreeSet<String>,
    pub stale_policy: super::protocol::StalePolicy,
    pub limits: super::protocol::FederationLimits,
}

/// Parameters for [`VaultFederationClient::explain_missing`].
#[derive(Clone, Debug)]
pub struct RemoteExplainMissingRequest {
    pub scope: mneme_core::ScopeId,
    pub revision: Option<mneme_core::WorkspaceRevisionId>,
    pub read_hlc: Option<mneme_kernel::hlc::HybridTimestamp>,
    pub bundle: mneme_datalog::RuleBundle,
    pub predicate: String,
    pub terms: Vec<mneme_core::Value>,
    pub at: Option<mneme_core::Timestamp>,
    pub incomplete_extents: std::collections::BTreeSet<String>,
    pub stale_policy: super::protocol::StalePolicy,
    pub limits: super::protocol::FederationLimits,
    pub explain_limits: super::protocol::RemoteExplainLimits,
}

/// Options for fetching and validating a remote vault view into memory.
#[derive(Clone, Debug)]
pub struct RemoteViewFetchOptions<'a> {
    pub alias: &'a str,
    pub locator: &'a str,
    pub scope: &'a mneme_core::ScopeId,
    pub revision: Option<mneme_core::WorkspaceRevisionId>,
    pub read_hlc: Option<mneme_kernel::hlc::HybridTimestamp>,
    pub limits: super::protocol::FederationLimits,
    pub access: &'a mneme_memory::Access,
}

/// Transport-uniform client for [`super::protocol::VaultFederationProtocol`].
#[derive(Clone)]
#[allow(unknown_lints, path_segment_repetition)] // public API compatibility type name
pub struct VaultFederationClient {
    inner: irpc::Client<super::protocol::VaultFederationProtocol>,
    capability_document: Option<String>,
    clock: std::sync::Arc<dyn mneme_store::Clock>,
    hlc: std::sync::Arc<std::sync::Mutex<mneme_kernel::hlc::HybridTimestamp>>,
    max_skew_ns: i64,
}

impl std::fmt::Debug for VaultFederationClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VaultFederationClient")
            .field("has_capability", &self.capability_document.is_some())
            .field("max_skew_ns", &self.max_skew_ns)
            .finish()
    }
}

impl VaultFederationClient {
    fn with_inner(inner: irpc::Client<super::protocol::VaultFederationProtocol>) -> Self {
        let clock: std::sync::Arc<dyn mneme_store::Clock> =
            std::sync::Arc::new(mneme_store::SystemClock);
        let init_ns = clock.now().nanos();
        Self {
            inner,
            capability_document: None,
            clock,
            hlc: std::sync::Arc::new(std::sync::Mutex::new(mneme_kernel::hlc::HybridTimestamp {
                physical_ns: init_ns,
                logical: 0,
            })),
            max_skew_ns: mneme_kernel::hlc::DEFAULT_MAX_SKEW_NS,
        }
    }

    /// Wrap an existing `irpc::Client` (for in-memory or custom transports).
    pub fn from_irpc(client: irpc::Client<super::protocol::VaultFederationProtocol>) -> Self {
        Self::with_inner(client)
    }

    /// Connect over Quinn (`noq`) to `addr`.
    pub fn connect_noq(endpoint: noq::Endpoint, addr: std::net::SocketAddr) -> Self {
        Self::with_inner(irpc::Client::noq(endpoint, addr))
    }

    /// Connect over Iroh to `addr` using [`super::protocol::FEDERATION_ALPN`].
    pub fn connect_iroh(endpoint: iroh::Endpoint, addr: impl Into<iroh::EndpointAddr>) -> Self {
        Self::with_inner(irpc_iroh::client(
            endpoint,
            addr,
            super::protocol::FEDERATION_ALPN,
        ))
    }

    /// Attach a serialized `concap` capability token JSON document to subsequent RPCs.
    pub fn with_capability(mut self, capability_document: impl Into<String>) -> Self {
        self.capability_document = Some(capability_document.into());
        self
    }

    /// Configure an explicit physical clock source for this client's HLC.
    pub fn with_clock(mut self, clock: std::sync::Arc<dyn mneme_store::Clock>) -> Self {
        let init_ns = clock.now().nanos();
        self.clock = clock;
        self.hlc = std::sync::Arc::new(std::sync::Mutex::new(mneme_kernel::hlc::HybridTimestamp {
            physical_ns: init_ns,
            logical: 0,
        }));
        self
    }

    /// Configure the maximum permitted HLC physical clock skew in nanoseconds.
    pub fn with_max_skew_ns(mut self, max_skew_ns: i64) -> Self {
        self.max_skew_ns = max_skew_ns;
        self
    }

    /// Return this client's current HLC watermark.
    pub fn current_hlc(&self) -> mneme_kernel::hlc::HybridTimestamp {
        self.hlc
            .lock()
            .map(|guard| *guard)
            .unwrap_or(mneme_kernel::hlc::HybridTimestamp {
                physical_ns: 0,
                logical: 0,
            })
    }

    /// Advance this client's HLC for an outbound request or multi-vault causal cut.
    pub fn tick_hlc(&self) -> Result<mneme_kernel::hlc::HybridTimestamp, FederationError> {
        let mut guard = self
            .hlc
            .lock()
            .map_err(|_| FederationError::ProtocolError("client HLC mutex poisoned".to_owned()))?;
        let pt_ns = self.clock.now().nanos();
        let next = mneme_kernel::hlc::tick_local(*guard, pt_ns, self.max_skew_ns)
            .map_err(map_client_hlc_error)?;
        *guard = next;
        Ok(next)
    }

    /// Observe a remote HLC timestamp, advancing this client's HLC causally
    /// and failing closed on excessive clock skew.
    pub fn observe_hlc(
        &self,
        remote: mneme_kernel::hlc::HybridTimestamp,
    ) -> Result<mneme_kernel::hlc::HybridTimestamp, FederationError> {
        let mut guard = self
            .hlc
            .lock()
            .map_err(|_| FederationError::ProtocolError("client HLC mutex poisoned".to_owned()))?;
        let pt_ns = self.clock.now().nanos();
        let next = mneme_kernel::hlc::receive(*guard, pt_ns, remote, self.max_skew_ns)
            .map_err(map_client_hlc_error)?;
        *guard = next;
        Ok(next)
    }

    fn observe_reply_hlc(
        &self,
        remote: Option<super::protocol::WireHybridTimestamp>,
    ) -> Result<(), FederationError> {
        if let Some(ts) = remote {
            let _ = self.observe_hlc(ts.to_kernel())?;
        }
        Ok(())
    }

    /// Query the remote vault's current head revision and eligibility generation.
    pub async fn query_head(
        &self,
        scope: &mneme_core::ScopeId,
    ) -> Result<super::protocol::HeadState, FederationError> {
        let sender_hlc = Some(super::protocol::WireHybridTimestamp::from_kernel(
            self.tick_hlc()?,
        ));
        let reply = self
            .inner
            .rpc(super::protocol::QueryHeadRequest {
                scope: scope.to_string(),
                sender_hlc,
                capability_document: self.capability_document.clone(),
            })
            .await
            .map_err(transport_error)?
            .map_err(FederationError::from)?;
        check_protocol_version(reply.protocol_version)?;
        self.observe_reply_hlc(reply.sender_hlc)?;
        Ok(reply)
    }

    /// Query read-only scoped vault metadata at head or a pinned revision.
    pub async fn query_metadata(
        &self,
        scope: &mneme_core::ScopeId,
        revision: Option<mneme_core::WorkspaceRevisionId>,
    ) -> Result<super::protocol::VaultMetadata, FederationError> {
        let sender_hlc = Some(super::protocol::WireHybridTimestamp::from_kernel(
            self.tick_hlc()?,
        ));
        let reply = self
            .inner
            .rpc(super::protocol::QueryMetadataRequest {
                scope: scope.to_string(),
                revision: revision.map(|rev| *rev.as_bytes()),
                read_hlc: None,
                sender_hlc,
                capability_document: self.capability_document.clone(),
            })
            .await
            .map_err(transport_error)?
            .map_err(FederationError::from)?;
        check_protocol_version(reply.protocol_version)?;
        self.observe_reply_hlc(reply.sender_hlc)?;
        if let Some(expected) = revision
            && reply.served_revision != *expected.as_bytes()
        {
            return Err(FederationError::ProtocolError(
                "remote metadata served revision does not match requested pin".to_owned(),
            ));
        }
        assert_eq!(reply.protocol_version, super::protocol::PROTOCOL_VERSION);
        assert!(revision.is_none_or(|rev| reply.served_revision == *rev.as_bytes()));
        Ok(reply)
    }

    /// Fetch a strictly read-only, scope-filtered, revision-pinned snapshot payload.
    pub async fn fetch_pinned_snapshot(
        &self,
        scope: &mneme_core::ScopeId,
        revision: Option<mneme_core::WorkspaceRevisionId>,
        limits: super::protocol::FederationLimits,
    ) -> Result<super::protocol::PinnedSnapshotPayload, FederationError> {
        self.fetch_pinned_snapshot_at_hlc(scope, revision, None, limits)
            .await
    }

    /// Fetch a strictly read-only, scope-filtered snapshot payload pinned by
    /// explicit `revision` or causal `read_hlc` cut.
    pub async fn fetch_pinned_snapshot_at_hlc(
        &self,
        scope: &mneme_core::ScopeId,
        revision: Option<mneme_core::WorkspaceRevisionId>,
        read_hlc: Option<mneme_kernel::hlc::HybridTimestamp>,
        limits: super::protocol::FederationLimits,
    ) -> Result<super::protocol::PinnedSnapshotPayload, FederationError> {
        limits.validate().map_err(FederationError::from)?;
        let sender_hlc = Some(super::protocol::WireHybridTimestamp::from_kernel(
            self.tick_hlc()?,
        ));
        let reply = self
            .inner
            .rpc(super::protocol::FetchPinnedSnapshotRequest {
                scope: scope.to_string(),
                revision: revision.map(|rev| *rev.as_bytes()),
                read_hlc: read_hlc.map(super::protocol::WireHybridTimestamp::from_kernel),
                sender_hlc,
                limits,
                capability_document: self.capability_document.clone(),
            })
            .await
            .map_err(transport_error)?
            .map_err(FederationError::from)?;
        check_protocol_version(reply.protocol_version)?;
        self.observe_reply_hlc(reply.sender_hlc)?;
        if let Some(expected) = revision
            && reply.served_revision != *expected.as_bytes()
        {
            return Err(FederationError::ProtocolError(
                "remote snapshot served revision does not match requested pin".to_owned(),
            ));
        }
        assert_eq!(reply.protocol_version, super::protocol::PROTOCOL_VERSION);
        assert!(revision.is_none_or(|rev| reply.served_revision == *rev.as_bytes()));
        Ok(reply)
    }

    /// Evaluate a bounded read-only Datalog query directly on the remote peer.
    pub async fn evaluate_datalog(
        &self,
        request: RemoteDatalogRequest,
    ) -> Result<super::protocol::RemoteDatalogResult, FederationError> {
        request.limits.validate().map_err(FederationError::from)?;
        let sender_hlc = Some(super::protocol::WireHybridTimestamp::from_kernel(
            self.tick_hlc()?,
        ));
        let bundle_value = bundle_to_value(&request.bundle);
        let constant_documents = request
            .constants
            .iter()
            .map(|item| item.as_ref().map(mneme_core::encode_document_string))
            .collect();
        let reply = self
            .inner
            .rpc(super::protocol::EvaluateDatalogRequest {
                scope: request.scope.to_string(),
                revision: request.revision.map(|rev| *rev.as_bytes()),
                read_hlc: request
                    .read_hlc
                    .map(super::protocol::WireHybridTimestamp::from_kernel),
                sender_hlc,
                calm_seal: request.calm_seal,
                bundle_document: mneme_core::encode_document_string(&bundle_value),
                predicate: request.predicate,
                constant_documents,
                max_rows: request.limit,
                at: request.at.map(mneme_core::Timestamp::nanos),
                incomplete_extents: request.incomplete_extents.into_iter().collect(),
                stale_policy: request.stale_policy,
                limits: request.limits,
                capability_document: self.capability_document.clone(),
            })
            .await
            .map_err(transport_error)?
            .map_err(FederationError::from)?;
        check_protocol_version(reply.protocol_version)?;
        self.observe_reply_hlc(reply.sender_hlc)?;
        if let Some(expected) = request.revision
            && reply.served_revision != *expected.as_bytes()
        {
            return Err(FederationError::ProtocolError(
                "remote Datalog evaluation served revision does not match requested pin".to_owned(),
            ));
        }
        assert_eq!(reply.protocol_version, super::protocol::PROTOCOL_VERSION);
        assert!(
            request
                .revision
                .is_none_or(|rev| reply.served_revision == *rev.as_bytes())
        );
        Ok(reply)
    }

    /// Explain why a ground atom was or was not derived on the remote peer.
    pub async fn explain_missing(
        &self,
        request: RemoteExplainMissingRequest,
    ) -> Result<super::protocol::RemoteMissingExplanation, FederationError> {
        request.limits.validate().map_err(FederationError::from)?;
        request
            .explain_limits
            .validate()
            .map_err(FederationError::from)?;
        let sender_hlc = Some(super::protocol::WireHybridTimestamp::from_kernel(
            self.tick_hlc()?,
        ));
        let bundle_value = bundle_to_value(&request.bundle);
        let term_documents = request
            .terms
            .iter()
            .map(mneme_core::encode_document_string)
            .collect();
        let reply = self
            .inner
            .rpc(super::protocol::ExplainMissingRpcRequest {
                scope: request.scope.to_string(),
                revision: request.revision.map(|rev| *rev.as_bytes()),
                read_hlc: request
                    .read_hlc
                    .map(super::protocol::WireHybridTimestamp::from_kernel),
                sender_hlc,
                bundle_document: mneme_core::encode_document_string(&bundle_value),
                predicate: request.predicate,
                term_documents,
                at: request.at.map(mneme_core::Timestamp::nanos),
                incomplete_extents: request.incomplete_extents.into_iter().collect(),
                stale_policy: request.stale_policy,
                limits: request.limits,
                explain_limits: request.explain_limits,
                capability_document: self.capability_document.clone(),
            })
            .await
            .map_err(transport_error)?
            .map_err(FederationError::from)?;
        check_protocol_version(reply.protocol_version)?;
        self.observe_reply_hlc(reply.sender_hlc)?;
        if let Some(expected) = request.revision
            && reply.served_revision != *expected.as_bytes()
        {
            return Err(FederationError::ProtocolError(
                "remote explain-missing served revision does not match requested pin".to_owned(),
            ));
        }
        assert_eq!(reply.protocol_version, super::protocol::PROTOCOL_VERSION);
        assert!(
            request
                .revision
                .is_none_or(|rev| reply.served_revision == *rev.as_bytes())
        );
        Ok(reply)
    }

    /// Fetch and validate a remote vault view for local federated Datalog or
    /// Prolog joins without copying records to disk.
    pub async fn fetch_external_vault_view(
        &self,
        options: RemoteViewFetchOptions<'_>,
    ) -> Result<mneme_datalog::ExternalVaultView, FederationError> {
        mneme_datalog::validate_vault_alias(options.alias)
            .map_err(|error| FederationError::InvalidInput(error.to_string()))?;
        let payload = self
            .fetch_pinned_snapshot_at_hlc(
                options.scope,
                options.revision,
                options.read_hlc,
                options.limits,
            )
            .await?;
        decode_external_vault_view(&options, payload)
    }
}

fn map_client_hlc_error(error: mneme_kernel::hlc::HlcError) -> FederationError {
    match error {
        mneme_kernel::hlc::HlcError::ClockSkewExceeded => FederationError::ClockSkewExceeded(
            "remote federation HLC exceeded maximum permitted physical clock skew".to_owned(),
        ),
        mneme_kernel::hlc::HlcError::LogicalOverflow => FederationError::ClockSkewExceeded(
            "client federation HLC logical counter overflowed".to_owned(),
        ),
        mneme_kernel::hlc::HlcError::InvalidMaxSkew => {
            FederationError::InvalidInput("client HLC max_skew_ns must be non-negative".to_owned())
        }
    }
}

fn check_protocol_version(version: u32) -> Result<(), FederationError> {
    if version != super::protocol::PROTOCOL_VERSION {
        return Err(FederationError::ProtocolError(format!(
            "unsupported federation protocol version {version}; expected {}",
            super::protocol::PROTOCOL_VERSION
        )));
    }
    Ok(())
}

fn transport_error(error: irpc::Error) -> FederationError {
    FederationError::Transport(error.to_string())
}

fn decode_external_vault_view(
    options: &RemoteViewFetchOptions<'_>,
    payload: super::protocol::PinnedSnapshotPayload,
) -> Result<mneme_datalog::ExternalVaultView, FederationError> {
    let requested_revision =
        mneme_core::WorkspaceRevisionId::from_bytes(payload.requested_revision);
    let served_revision = mneme_core::WorkspaceRevisionId::from_bytes(payload.served_revision);
    let manifest_digest = decode_digest(&payload.manifest_digest_document)?;
    let registry = mneme_core::SchemaRegistry::production();
    let record_context = mneme_core::RecordContext::isolated(&registry);
    let mut index = mneme_core::SnapshotIndex::new();
    let parent = payload
        .parent
        .map(mneme_core::WorkspaceRevisionId::from_bytes);
    let records = decode_scoped_records(
        &payload.record_documents,
        options.scope,
        options.access,
        &record_context,
        &mut index,
    )?;
    let history = decode_history_records(
        &payload.history_documents,
        options.scope,
        &record_context,
        &mut index,
    )?;
    verify_scoped_manifest(served_revision, parent, &records, &history, manifest_digest)?;
    let (revision_sequences, suppressions, current_sources) = decode_snapshot_overlays(
        payload.revision_sequences,
        payload.suppressions,
        payload.current_sources,
    )?;
    let snapshot = mneme_store::Snapshot {
        revision: served_revision,
        sequence: payload.sequence,
        parent,
        manifest_digest,
        eligibility_generation: payload.eligibility_generation,
        records,
        index,
    };
    let view = mneme_memory::View::with_retention(
        snapshot,
        options.locator,
        history,
        revision_sequences,
        suppressions,
    )
    .with_access(options.access.clone());
    assert_eq!(view.revision(), served_revision);
    assert!(!options.alias.is_empty());
    Ok(mneme_datalog::ExternalVaultView {
        metadata: mneme_datalog::VaultRevision {
            alias: options.alias.to_owned(),
            root: std::path::PathBuf::from(options.locator),
            requested_revision,
            served_revision,
        },
        eligibility_generation: payload.eligibility_generation,
        view,
        current_sources,
    })
}

type DecodedSnapshotOverlays = (
    std::collections::BTreeMap<mneme_core::WorkspaceRevisionId, u64>,
    Vec<mneme_store::RetentionSuppression>,
    std::collections::BTreeMap<mneme_core::RecordId, mneme_memory::SourceAvailability>,
);

fn decode_snapshot_overlays(
    raw_sequences: Vec<([u8; 16], u64)>,
    raw_suppressions: Vec<super::protocol::EncodedSuppression>,
    raw_sources: Vec<([u8; 16], super::protocol::EncodedSourceAvailability)>,
) -> Result<DecodedSnapshotOverlays, FederationError> {
    let expected_suppressions = raw_suppressions.len();
    let revision_sequences = raw_sequences
        .into_iter()
        .map(|(bytes, seq)| (mneme_core::WorkspaceRevisionId::from_bytes(bytes), seq))
        .collect();
    let suppressions = raw_suppressions
        .into_iter()
        .map(decode_suppression)
        .collect::<Result<Vec<_>, _>>()?;
    let current_sources = raw_sources
        .into_iter()
        .map(|(bytes, avail)| {
            (
                mneme_core::RecordId::from_bytes(bytes),
                decode_source_availability(avail),
            )
        })
        .collect();
    debug_assert_eq!(suppressions.len(), expected_suppressions);
    debug_assert!(suppressions.capacity() >= expected_suppressions);
    Ok((revision_sequences, suppressions, current_sources))
}

fn verify_scoped_manifest(
    served_revision: mneme_core::WorkspaceRevisionId,
    parent: Option<mneme_core::WorkspaceRevisionId>,
    records: &[mneme_core::RecordEnvelope],
    history: &std::collections::BTreeMap<
        (mneme_core::RecordId, mneme_core::RevisionId),
        mneme_core::RecordEnvelope,
    >,
    manifest_digest: mneme_core::ContentDigest,
) -> Result<(), FederationError> {
    let expected = super::protocol::scoped_manifest_digest(
        served_revision,
        parent,
        records.iter(),
        history.values(),
        manifest_digest.algorithm(),
    );
    if manifest_digest != expected {
        return Err(FederationError::ProtocolError(
            "remote snapshot manifest_digest does not match returned scoped records".to_owned(),
        ));
    }
    Ok(())
}

fn decode_scoped_records(
    record_documents: &[String],
    scope: &mneme_core::ScopeId,
    access: &mneme_memory::Access,
    record_context: &mneme_core::RecordContext<'_>,
    index: &mut mneme_core::SnapshotIndex,
) -> Result<Vec<mneme_core::RecordEnvelope>, FederationError> {
    let max_records = record_documents.len();
    let mut records = Vec::with_capacity(max_records);
    for doc in record_documents {
        let envelope = decode_validated_record(doc, record_context)?;
        if envelope.scope != *scope {
            return Err(FederationError::ProtocolError(format!(
                "remote peer returned record in scope {} outside requested scope {scope}",
                envelope.scope
            )));
        }
        let is_visible =
            mneme_kernel::isolation::record_visible(&mneme_kernel::isolation::VisibilityFacts {
                same_scope: true,
                record_class: envelope.scope.class().to_kernel(),
                include_hypothetical: false,
                record_scope_authorized: access.allows(&envelope.scope),
            });
        if !is_visible {
            return Err(FederationError::ProtocolError(
                "remote peer returned out-of-scope record".to_owned(),
            ));
        }
        if !index.insert(envelope.record_id, envelope.kind, envelope.revision_id) {
            return Err(FederationError::ProtocolError(
                "remote snapshot contains duplicate record identity".to_owned(),
            ));
        }
        records.push(envelope);
    }
    assert_eq!(records.len(), max_records);
    debug_assert!(records.iter().all(|r| r.scope == *scope));
    Ok(records)
}

fn decode_history_records(
    history_documents: &[String],
    scope: &mneme_core::ScopeId,
    record_context: &mneme_core::RecordContext<'_>,
    index: &mut mneme_core::SnapshotIndex,
) -> Result<
    std::collections::BTreeMap<
        (mneme_core::RecordId, mneme_core::RevisionId),
        mneme_core::RecordEnvelope,
    >,
    FederationError,
> {
    let max_history_entries = history_documents.len();
    let mut history = std::collections::BTreeMap::new();
    for doc in history_documents {
        let envelope = decode_validated_record(doc, record_context)?;
        if envelope.scope != *scope {
            return Err(FederationError::ProtocolError(format!(
                "remote peer returned history record in scope {} outside requested scope {scope}",
                envelope.scope
            )));
        }
        if history.len() >= max_history_entries {
            break;
        }
        index.record_revision(envelope.record_id, envelope.revision_id);
        history.insert((envelope.record_id, envelope.revision_id), envelope);
    }
    debug_assert!(history.len() <= max_history_entries);
    debug_assert!(history.values().all(|r| r.scope == *scope));
    Ok(history)
}

fn decode_validated_record(
    document: &str,
    context: &mneme_core::RecordContext<'_>,
) -> Result<mneme_core::RecordEnvelope, FederationError> {
    let value = mneme_core::decode_document(document)
        .map_err(|diag| FederationError::ProtocolError(diag.to_string()))?;
    let envelope = mneme_core::RecordEnvelope::from_value(&value).map_err(|diags| {
        let msg = diags
            .into_iter()
            .map(|diag| diag.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        FederationError::ProtocolError(msg)
    })?;
    let diagnostics = mneme_core::validate_record(&envelope, context, &mneme_core::Path::root());
    if !diagnostics.is_empty() {
        let msg = diagnostics
            .into_iter()
            .map(|diag| diag.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(FederationError::ProtocolError(msg));
    }
    assert_eq!(envelope.schema_version, value_schema_version(&envelope));
    Ok(envelope)
}

fn value_schema_version(envelope: &mneme_core::RecordEnvelope) -> u32 {
    envelope.schema_version
}

fn decode_digest(document: &str) -> Result<mneme_core::ContentDigest, FederationError> {
    let value = mneme_core::decode_document(document)
        .map_err(|diag| FederationError::ProtocolError(diag.to_string()))?;
    mneme_core::ContentDigest::from_value(&value, &mneme_core::Path::root())
        .map_err(|diag| FederationError::ProtocolError(diag.to_string()))
}

fn decode_suppression(
    encoded: super::protocol::EncodedSuppression,
) -> Result<mneme_store::RetentionSuppression, FederationError> {
    let mode = mneme_store::SuppressionMode::parse(&encoded.mode).ok_or_else(|| {
        FederationError::ProtocolError(format!("unknown suppression mode {:?}", encoded.mode))
    })?;
    let content_digest = match encoded.content_digest_document {
        Some(doc) => Some(decode_digest(&doc)?),
        None => None,
    };
    Ok(mneme_store::RetentionSuppression {
        operation_id: encoded.operation_id,
        target: mneme_core::RecordId::from_bytes(encoded.target),
        revision: encoded.revision.map(mneme_core::RevisionId::from_bytes),
        target_kind: encoded.target_kind,
        mode,
        content_digest,
        generation: encoded.generation,
    })
}

fn decode_source_availability(
    encoded: super::protocol::EncodedSourceAvailability,
) -> mneme_memory::SourceAvailability {
    match encoded {
        super::protocol::EncodedSourceAvailability::Retained => {
            mneme_memory::SourceAvailability::Retained
        }
        super::protocol::EncodedSourceAvailability::Pruned => {
            mneme_memory::SourceAvailability::Pruned
        }
        super::protocol::EncodedSourceAvailability::Erased => {
            mneme_memory::SourceAvailability::Erased
        }
        super::protocol::EncodedSourceAvailability::Inaccessible => {
            mneme_memory::SourceAvailability::Inaccessible
        }
        super::protocol::EncodedSourceAvailability::Corrupt(reason) => {
            mneme_memory::SourceAvailability::Corrupt { reason }
        }
        super::protocol::EncodedSourceAvailability::Unavailable(reason) => {
            mneme_memory::SourceAvailability::Unavailable { reason }
        }
    }
}

fn bundle_to_value(bundle: &mneme_datalog::RuleBundle) -> mneme_core::Value {
    let base_predicates = mneme_core::Value::symbol_dictionary(bundle.base_predicates.iter().map(
        |(predicate, arity)| {
            (
                mneme_core::Symbol::from(predicate.as_str()),
                mneme_core::Value::integer(*arity as i64),
            )
        },
    ));
    let complete_predicates = mneme_core::Value::sequence(
        bundle
            .complete_predicates
            .iter()
            .cloned()
            .map(mneme_core::Value::string)
            .collect(),
    );
    let rules = mneme_core::Value::sequence(bundle.rules.iter().map(rule_to_value).collect());
    assert!(!bundle.id.is_empty());
    assert!(!bundle.version.is_empty());
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("id"),
            mneme_core::Value::string(bundle.id.clone()),
        ),
        (
            mneme_core::Symbol::from("version"),
            mneme_core::Value::string(bundle.version.clone()),
        ),
        (
            mneme_core::Symbol::from("schema-version"),
            mneme_core::Value::integer(i64::from(bundle.schema_version)),
        ),
        (mneme_core::Symbol::from("base-predicates"), base_predicates),
        (
            mneme_core::Symbol::from("complete-predicates"),
            complete_predicates,
        ),
        (mneme_core::Symbol::from("rules"), rules),
    ])
}

fn rule_to_value(rule: &mneme_datalog::Rule) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("id"),
            mneme_core::Value::string(rule.id.clone()),
        ),
        (mneme_core::Symbol::from("head"), atom_to_value(&rule.head)),
        (
            mneme_core::Symbol::from("body"),
            mneme_core::Value::sequence(rule.body.iter().map(literal_to_value).collect()),
        ),
    ])
}

fn atom_to_value(atom: &mneme_datalog::Atom) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("predicate"),
            mneme_core::Value::string(atom.predicate.clone()),
        ),
        (
            mneme_core::Symbol::from("terms"),
            mneme_core::Value::sequence(atom.terms.iter().map(term_to_value).collect()),
        ),
    ])
}

fn term_to_value(term: &mneme_datalog::Term) -> mneme_core::Value {
    match term {
        mneme_datalog::Term::Variable(name) => mneme_core::Value::symbol_dictionary([
            (
                mneme_core::Symbol::from("kind"),
                mneme_core::Value::symbol("variable"),
            ),
            (
                mneme_core::Symbol::from("name"),
                mneme_core::Value::string(name.clone()),
            ),
        ]),
        mneme_datalog::Term::Constant(value) => mneme_core::Value::symbol_dictionary([
            (
                mneme_core::Symbol::from("kind"),
                mneme_core::Value::symbol("constant"),
            ),
            (mneme_core::Symbol::from("value"), value.clone()),
        ]),
    }
}

fn literal_to_value(literal: &mneme_datalog::Literal) -> mneme_core::Value {
    match literal {
        mneme_datalog::Literal::Positive(atom) => tagged_atom_literal("positive", atom),
        mneme_datalog::Literal::Negative(atom) => tagged_atom_literal("negative", atom),
        mneme_datalog::Literal::Compare { op, left, right } => {
            compare_literal_value(*op, left, right)
        }
        mneme_datalog::Literal::Aggregate {
            function,
            input,
            output,
        } => aggregate_literal_value(*function, input, output),
        mneme_datalog::Literal::Forbidden(name) => mneme_core::Value::symbol_dictionary([
            (
                mneme_core::Symbol::from("kind"),
                mneme_core::Value::symbol("forbidden"),
            ),
            (
                mneme_core::Symbol::from("name"),
                mneme_core::Value::string(name.clone()),
            ),
        ]),
    }
}

fn tagged_atom_literal(kind: &str, atom: &mneme_datalog::Atom) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("kind"),
            mneme_core::Value::symbol(kind),
        ),
        (mneme_core::Symbol::from("atom"), atom_to_value(atom)),
    ])
}

fn compare_literal_value(
    op: mneme_datalog::CompareOp,
    left: &mneme_datalog::Term,
    right: &mneme_datalog::Term,
) -> mneme_core::Value {
    let op_name = match op {
        mneme_datalog::CompareOp::Eq => "eq",
        mneme_datalog::CompareOp::Ne => "ne",
        mneme_datalog::CompareOp::Lt => "lt",
        mneme_datalog::CompareOp::Le => "le",
        mneme_datalog::CompareOp::Gt => "gt",
        mneme_datalog::CompareOp::Ge => "ge",
    };
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("kind"),
            mneme_core::Value::symbol("compare"),
        ),
        (
            mneme_core::Symbol::from("op"),
            mneme_core::Value::symbol(op_name),
        ),
        (mneme_core::Symbol::from("left"), term_to_value(left)),
        (mneme_core::Symbol::from("right"), term_to_value(right)),
    ])
}

fn aggregate_literal_value(
    function: mneme_datalog::AggregateFunction,
    input: &mneme_datalog::Term,
    output: &str,
) -> mneme_core::Value {
    let fn_name = match function {
        mneme_datalog::AggregateFunction::Count => "count",
        mneme_datalog::AggregateFunction::Sum => "sum",
        mneme_datalog::AggregateFunction::Min => "min",
        mneme_datalog::AggregateFunction::Max => "max",
    };
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("kind"),
            mneme_core::Value::symbol("aggregate"),
        ),
        (
            mneme_core::Symbol::from("function"),
            mneme_core::Value::symbol(fn_name),
        ),
        (mneme_core::Symbol::from("input"), term_to_value(input)),
        (
            mneme_core::Symbol::from("output"),
            mneme_core::Value::string(output.to_owned()),
        ),
    ])
}
