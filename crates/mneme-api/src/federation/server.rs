//! Strictly read-only `irpc` federation server across in-memory, Quinn (`noq`), and Iroh.
#![allow(unknown_lints)] // Octet structural exception: irpc macro handler closures and async channels

use irpc::rpc::RemoteService;

const PERMISSION_DENIED_CODE: u32 = 1;
const DEFAULT_CHANNEL_CAPACITY: u32 = 64;
const FALLBACK_CHANNEL_CAPACITY_SLOTS: usize = 64;

/// Explicit Ed25519 peer allowlist. Empty by default (deny-all).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerAllowlist {
    peers: std::collections::BTreeSet<iroh::EndpointId>,
}

impl PeerAllowlist {
    /// An empty allowlist that refuses every remote peer.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Construct an allowlist from explicit Ed25519 peer identities.
    pub fn from_peers(peers: impl IntoIterator<Item = iroh::EndpointId>) -> Self {
        Self {
            peers: peers.into_iter().collect(),
        }
    }

    /// Add one authorized Ed25519 peer identity.
    pub fn allow(&mut self, peer: iroh::EndpointId) {
        self.peers.insert(peer);
    }

    /// Whether `peer` is explicitly authorized.
    pub fn allows(&self, peer: &iroh::EndpointId) -> bool {
        self.peers.contains(peer)
    }

    /// Number of allowlisted peers.
    #[must_use]
    #[allow(unknown_lints, usize_in_public_api)] // std-shaped collection length
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether no peers are allowlisted.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

/// Configuration for a read-only [`VaultFederationServer`].
#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub vault_root: std::path::PathBuf,
    pub allowlist: PeerAllowlist,
    pub max_limits: super::protocol::FederationLimits,
    pub channel_capacity: u32,
}

impl ServerConfig {
    /// Create a deny-all configuration for `vault_root` with default bounds.
    pub fn new(vault_root: impl Into<std::path::PathBuf>, allowlist: PeerAllowlist) -> Self {
        Self {
            vault_root: vault_root.into(),
            allowlist,
            max_limits: super::protocol::FederationLimits::standard(),
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
        }
    }
}

/// Read-only `irpc` federation server serving one vault over memory, Quinn, and Iroh.
#[derive(Clone)]
pub struct VaultFederationServer {
    config: ServerConfig,
    sender: tokio::sync::mpsc::Sender<super::protocol::VaultFederationMessage>,
}

impl VaultFederationServer {
    /// Spawn the bounded read-only RPC actor for `config`.
    pub fn spawn(config: ServerConfig) -> Result<Self, super::client::FederationError> {
        config
            .max_limits
            .validate()
            .map_err(|error| super::client::FederationError::InvalidInput(error.message))?;
        let capacity = usize::try_from(config.channel_capacity.max(1)).map_err(|_| {
            super::client::FederationError::InvalidInput("invalid channel capacity".to_owned())
        })?;
        let (sender, receiver) = tokio::sync::mpsc::channel(capacity);
        let actor_config = config.clone();
        let actor_handle = tokio::task::spawn(async move {
            run_actor(actor_config, receiver).await;
        });
        drop(actor_handle);
        Ok(Self { config, sender })
    }

    /// The configured Ed25519 peer allowlist.
    pub fn allowlist(&self) -> &PeerAllowlist {
        &self.config.allowlist
    }

    /// Create an in-memory client bound to `caller`, enforcing the server's
    /// explicit [`PeerAllowlist`] before dispatching any RPC.
    pub fn local_client_for(
        &self,
        caller: iroh::EndpointId,
    ) -> super::client::VaultFederationClient {
        let capacity = usize::try_from(self.config.channel_capacity.max(1))
            .unwrap_or(FALLBACK_CHANNEL_CAPACITY_SLOTS);
        let (gate_tx, mut gate_rx) = tokio::sync::mpsc::channel(capacity);
        let allowlist = self.config.allowlist.clone();
        let backend = self.sender.clone();
        let gate_handle = tokio::task::spawn(async move {
            while let Some(message) = gate_rx.recv().await {
                if !allowlist.allows(&caller) {
                    reject_unauthorized(message).await;
                    continue;
                }
                if backend.send(message).await.is_err() {
                    break;
                }
            }
        });
        drop(gate_handle);
        super::client::VaultFederationClient::from_irpc(irpc::Client::local(gate_tx))
    }

    /// Create an `iroh::protocol::ProtocolHandler` enforcing the server's
    /// explicit [`PeerAllowlist`] on every incoming Iroh connection.
    pub fn iroh_protocol_handler(&self) -> IrohFederationHandler {
        IrohFederationHandler {
            allowlist: self.config.allowlist.clone(),
            handler: super::protocol::VaultFederationProtocol::remote_handler(
                self.sender.clone().into(),
            ),
        }
    }

    /// Mount the federation protocol handler on an `iroh::Endpoint` router.
    pub fn serve_iroh(&self, endpoint: iroh::Endpoint) -> iroh::protocol::Router {
        iroh::protocol::Router::builder(endpoint)
            .accept(
                super::protocol::FEDERATION_ALPN,
                self.iroh_protocol_handler(),
            )
            .spawn()
    }

    /// Accept authenticated `noq` (Quinn) connections on `endpoint`, enforcing
    /// the server's explicit [`PeerAllowlist`] before handling RPC streams.
    pub fn serve_noq(&self, endpoint: noq::Endpoint) -> tokio::task::JoinHandle<()> {
        let allowlist = self.config.allowlist.clone();
        let handler =
            super::protocol::VaultFederationProtocol::remote_handler(self.sender.clone().into());
        assert!(endpoint.local_addr().is_ok());
        let handle = tokio::task::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
                    incoming = endpoint.accept() => {
                        let Some(incoming) = incoming else {
                            break;
                        };
                        let allowlist = allowlist.clone();
                        let handler = handler.clone();
                        let task = tasks.spawn(async move {
                            accept_noq_connection(incoming, allowlist, handler).await;
                        });
                        drop(task);
                    }
                }
            }
        });
        assert!(!handle.is_finished());
        handle
    }
}

async fn accept_noq_connection(
    incoming: noq::Incoming,
    allowlist: PeerAllowlist,
    handler: irpc::rpc::Handler<super::protocol::VaultFederationProtocol>,
) {
    let Ok(connection) = incoming.await else {
        return;
    };
    match super::quinn::authenticated_peer_id(&connection) {
        Ok(peer_id) if allowlist.allows(&peer_id) => {
            if irpc::rpc::handle_connection(connection, handler)
                .await
                .is_err()
            {}
        }
        _ => {
            connection.close(PERMISSION_DENIED_CODE.into(), b"peer not allowlisted");
        }
    }
}

/// `iroh::protocol::ProtocolHandler` that rejects unallowlisted `EndpointId`s
/// before reading any RPC message.
#[derive(Clone)]
pub struct IrohFederationHandler {
    allowlist: PeerAllowlist,
    handler: irpc::rpc::Handler<super::protocol::VaultFederationProtocol>,
}

impl std::fmt::Debug for IrohFederationHandler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IrohFederationHandler")
            .field("allowlisted_peers", &self.allowlist.len())
            .finish()
    }
}

impl iroh::protocol::ProtocolHandler for IrohFederationHandler {
    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        let remote_id = connection.remote_id();
        if !self.allowlist.allows(&remote_id) {
            connection.close(PERMISSION_DENIED_CODE.into(), b"peer not allowlisted");
            return Err(iroh::protocol::AcceptError::from_err(
                super::protocol::RpcError::new(
                    super::protocol::RpcErrorCode::Unauthorized,
                    "peer is not in federation allowlist",
                ),
            ));
        }
        irpc_iroh::handle_connection::<super::protocol::VaultFederationProtocol>(
            &connection,
            self.handler.clone(),
        )
        .await
        .map_err(iroh::protocol::AcceptError::from_err)
    }
}

async fn reject_unauthorized(message: super::protocol::VaultFederationMessage) {
    let error = super::protocol::RpcError::new(
        super::protocol::RpcErrorCode::Unauthorized,
        "peer is not in federation allowlist",
    );
    match message {
        super::protocol::VaultFederationMessage::QueryHead(msg) => {
            if msg.tx.send(Err(error)).await.is_err() {}
        }
        super::protocol::VaultFederationMessage::QueryMetadata(msg) => {
            if msg.tx.send(Err(error)).await.is_err() {}
        }
        super::protocol::VaultFederationMessage::FetchPinnedSnapshot(msg) => {
            if msg.tx.send(Err(error)).await.is_err() {}
        }
        super::protocol::VaultFederationMessage::EvaluateDatalog(msg) => {
            if msg.tx.send(Err(error)).await.is_err() {}
        }
    }
}

async fn run_actor(
    config: ServerConfig,
    mut receiver: tokio::sync::mpsc::Receiver<super::protocol::VaultFederationMessage>,
) {
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            message = receiver.recv() => {
                let Some(message) = message else {
                    break;
                };
                let cfg = config.clone();
                let task = tasks.spawn(async move {
                    dispatch_message(cfg, message).await;
                });
                drop(task);
            }
        }
    }
}

async fn dispatch_message(config: ServerConfig, message: super::protocol::VaultFederationMessage) {
    match message {
        super::protocol::VaultFederationMessage::QueryHead(msg) => {
            let timeout_ms = config.max_limits.max_time_ms;
            let result =
                run_bounded_blocking(timeout_ms, move || handle_query_head(&config, &msg.inner))
                    .await;
            if msg.tx.send(result).await.is_err() {}
        }
        super::protocol::VaultFederationMessage::QueryMetadata(msg) => {
            let timeout_ms = config.max_limits.max_time_ms;
            let result = run_bounded_blocking(timeout_ms, move || {
                handle_query_metadata(&config, &msg.inner)
            })
            .await;
            if msg.tx.send(result).await.is_err() {}
        }
        super::protocol::VaultFederationMessage::FetchPinnedSnapshot(msg) => {
            let timeout_ms = msg
                .inner
                .limits
                .max_time_ms
                .min(config.max_limits.max_time_ms)
                .max(1);
            let result = run_bounded_blocking(timeout_ms, move || {
                handle_fetch_pinned_snapshot(&config, &msg.inner)
            })
            .await;
            if msg.tx.send(result).await.is_err() {}
        }
        super::protocol::VaultFederationMessage::EvaluateDatalog(msg) => {
            let timeout_ms = msg
                .inner
                .limits
                .max_time_ms
                .min(config.max_limits.max_time_ms)
                .max(1);
            let result = run_bounded_blocking(timeout_ms, move || {
                handle_evaluate_datalog(&config, &msg.inner)
            })
            .await;
            if msg.tx.send(result).await.is_err() {}
        }
    }
}

async fn run_bounded_blocking<T, F>(
    timeout_ms: u64,
    task: F,
) -> Result<T, super::protocol::RpcError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, super::protocol::RpcError> + Send + 'static,
{
    let handle = tokio::task::spawn_blocking(task);
    match tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), handle).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(super::protocol::RpcError::new(
            super::protocol::RpcErrorCode::Unavailable,
            "federation worker task failed",
        )),
        Err(_) => Err(super::protocol::RpcError::new(
            super::protocol::RpcErrorCode::BudgetExceeded,
            "federation request exceeded wall-clock time limit",
        )),
    }
}

fn open_read_only_vault(
    root: &std::path::Path,
) -> Result<mneme_store::Workspace, super::protocol::RpcError> {
    mneme_store::Workspace::open_read_only(
        root,
        mneme_store::WorkspaceConfig::new(
            Box::new(mneme_store::SystemClock),
            Box::new(mneme_store::NoFaults),
        ),
    )
    .map_err(store_rpc_error)
}

fn parse_scope(scope: &str) -> Result<mneme_core::ScopeId, super::protocol::RpcError> {
    let (class_text, local) = scope.split_once(':').ok_or_else(|| {
        super::protocol::RpcError::new(
            super::protocol::RpcErrorCode::InvalidInput,
            format!("scope {scope:?} must be <class>:<local>"),
        )
    })?;
    let class = mneme_core::ScopeClass::parse(class_text).ok_or_else(|| {
        super::protocol::RpcError::new(
            super::protocol::RpcErrorCode::InvalidInput,
            format!("unknown scope class {class_text:?}"),
        )
    })?;
    mneme_core::ScopeId::new(class, local).map_err(|error| {
        super::protocol::RpcError::new(super::protocol::RpcErrorCode::InvalidInput, error)
    })
}

fn handle_query_head(
    config: &ServerConfig,
    request: &super::protocol::QueryHeadRequest,
) -> Result<super::protocol::HeadState, super::protocol::RpcError> {
    let _scope = parse_scope(&request.scope)?;
    let workspace = open_read_only_vault(&config.vault_root)?;
    let generation = workspace
        .eligibility_generation()
        .map_err(store_rpc_error)?;
    let head = workspace.current_revision().map_err(store_rpc_error)?;
    let snapshot = workspace
        .snapshot_at(head, Some(generation))
        .map_err(store_rpc_error)?;
    Ok(super::protocol::HeadState {
        protocol_version: super::protocol::PROTOCOL_VERSION,
        head_revision: *head.as_bytes(),
        head_sequence: snapshot.sequence,
        eligibility_generation: generation,
    })
}

fn handle_query_metadata(
    config: &ServerConfig,
    request: &super::protocol::QueryMetadataRequest,
) -> Result<super::protocol::VaultMetadata, super::protocol::RpcError> {
    let scope = parse_scope(&request.scope)?;
    let access = mneme_memory::Access::scopes([scope.clone()]);
    let workspace = open_read_only_vault(&config.vault_root)?;
    let generation = workspace
        .eligibility_generation()
        .map_err(store_rpc_error)?;
    let head = workspace.current_revision().map_err(store_rpc_error)?;
    let requested = request
        .revision
        .map_or(head, mneme_core::WorkspaceRevisionId::from_bytes);
    let snapshot = workspace
        .snapshot_at(requested, Some(generation))
        .map_err(store_rpc_error)?;
    let filtered = mneme_datalog::filter_visible_snapshot(snapshot, &scope, &access);
    verify_generation_unchanged(&workspace, generation, "metadata query")?;
    let scoped_record_count = u64::try_from(filtered.records.len()).map_err(|_| {
        super::protocol::RpcError::new(
            super::protocol::RpcErrorCode::BudgetExceeded,
            "scoped record count exceeds u64 range",
        )
    })?;
    assert_eq!(filtered.revision, requested);
    assert_eq!(filtered.eligibility_generation, generation);
    Ok(super::protocol::VaultMetadata {
        protocol_version: super::protocol::PROTOCOL_VERSION,
        requested_revision: *requested.as_bytes(),
        served_revision: *filtered.revision.as_bytes(),
        sequence: filtered.sequence,
        eligibility_generation: generation,
        scoped_record_count,
        max_limits: config.max_limits,
    })
}

fn verify_generation_unchanged(
    workspace: &mneme_store::Workspace,
    pinned_generation: u64,
    operation: &str,
) -> Result<(), super::protocol::RpcError> {
    let current_gen = workspace
        .eligibility_generation()
        .map_err(store_rpc_error)?;
    if current_gen != pinned_generation {
        return Err(super::protocol::RpcError::new(
            super::protocol::RpcErrorCode::Conflict,
            format!("eligibility barrier advanced during {operation}"),
        ));
    }
    Ok(())
}

fn handle_fetch_pinned_snapshot(
    config: &ServerConfig,
    request: &super::protocol::FetchPinnedSnapshotRequest,
) -> Result<super::protocol::PinnedSnapshotPayload, super::protocol::RpcError> {
    request.limits.check_within(&config.max_limits)?;
    let scope = parse_scope(&request.scope)?;
    let access = mneme_memory::Access::scopes([scope.clone()]);
    let workspace = open_read_only_vault(&config.vault_root)?;
    let generation = workspace
        .eligibility_generation()
        .map_err(store_rpc_error)?;
    let head = workspace.current_revision().map_err(store_rpc_error)?;
    let requested = request
        .revision
        .map_or(head, mneme_core::WorkspaceRevisionId::from_bytes);
    let snapshot = workspace
        .snapshot_at(requested, Some(generation))
        .map_err(store_rpc_error)?;
    let filtered = mneme_datalog::filter_visible_snapshot(snapshot, &scope, &access);
    let view_context = mneme_memory::view_context(&workspace, &filtered).map_err(|error| {
        super::protocol::RpcError::new(
            super::protocol::RpcErrorCode::Unavailable,
            format!("cannot load view context: {error}"),
        )
    })?;
    check_snapshot_row_budget(&filtered, &view_context, request.limits.max_rows)?;
    let suppressions = encode_suppressions(&workspace)?;
    let current_sources = scoped_source_overlay(&workspace, filtered.revision, &scope, &access)?;
    verify_generation_unchanged(&workspace, generation, "pinned snapshot fetch")?;
    let payload = build_snapshot_payload(SnapshotPayloadInput {
        requested,
        generation,
        filtered,
        view_context,
        suppressions,
        current_sources,
    });
    check_payload_byte_budget(&payload, request.limits.max_bytes, "pinned snapshot")?;
    Ok(payload)
}

fn check_snapshot_row_budget(
    filtered: &mneme_store::Snapshot,
    view_context: &mneme_memory::ViewContext,
    max_rows: u64,
) -> Result<(), super::protocol::RpcError> {
    let total_rows = filtered
        .records
        .len()
        .saturating_add(view_context.history.len());
    let total_rows_u64 = u64::try_from(total_rows).map_err(|_| {
        super::protocol::RpcError::new(
            super::protocol::RpcErrorCode::BudgetExceeded,
            "pinned snapshot row count exceeds u64 range",
        )
    })?;
    if total_rows_u64 > max_rows {
        return Err(super::protocol::RpcError::new(
            super::protocol::RpcErrorCode::BudgetExceeded,
            format!("pinned snapshot row count ({total_rows_u64}) exceeds max_rows ({max_rows})"),
        ));
    }
    Ok(())
}

fn encode_suppressions(
    workspace: &mneme_store::Workspace,
) -> Result<Vec<super::protocol::EncodedSuppression>, super::protocol::RpcError> {
    Ok(workspace
        .active_suppressions()
        .map_err(store_rpc_error)?
        .into_iter()
        .map(|entry| super::protocol::EncodedSuppression {
            operation_id: entry.operation_id,
            target: *entry.target.as_bytes(),
            revision: entry.revision.map(|rev| *rev.as_bytes()),
            target_kind: entry.target_kind,
            mode: entry.mode.as_str().to_owned(),
            content_digest_document: entry
                .content_digest
                .map(|digest| mneme_core::encode_document_string(&digest.to_value())),
            generation: entry.generation,
        })
        .collect())
}

struct SnapshotPayloadInput {
    requested: mneme_core::WorkspaceRevisionId,
    generation: u64,
    filtered: mneme_store::Snapshot,
    view_context: mneme_memory::ViewContext,
    suppressions: Vec<super::protocol::EncodedSuppression>,
    current_sources: Vec<([u8; 16], super::protocol::EncodedSourceAvailability)>,
}

fn build_snapshot_payload(input: SnapshotPayloadInput) -> super::protocol::PinnedSnapshotPayload {
    let SnapshotPayloadInput {
        requested,
        generation,
        filtered,
        view_context,
        suppressions,
        current_sources,
    } = input;
    assert_eq!(filtered.revision, requested);
    assert_eq!(filtered.eligibility_generation, generation);
    super::protocol::PinnedSnapshotPayload {
        protocol_version: super::protocol::PROTOCOL_VERSION,
        requested_revision: *requested.as_bytes(),
        served_revision: *filtered.revision.as_bytes(),
        sequence: filtered.sequence,
        parent: filtered.parent.map(|rev| *rev.as_bytes()),
        manifest_digest_document: mneme_core::encode_document_string(
            &filtered.manifest_digest.to_value(),
        ),
        eligibility_generation: generation,
        record_documents: filtered
            .records
            .iter()
            .map(|record| mneme_core::encode_document_string(&record.to_value()))
            .collect(),
        history_documents: view_context
            .history
            .values()
            .map(|record| mneme_core::encode_document_string(&record.to_value()))
            .collect(),
        revision_sequences: view_context
            .revision_sequences
            .into_iter()
            .map(|(rev, seq)| (*rev.as_bytes(), seq))
            .collect(),
        suppressions,
        current_sources,
    }
}

fn check_payload_byte_budget<T: serde::Serialize>(
    payload: &T,
    max_bytes: u64,
    label: &str,
) -> Result<(), super::protocol::RpcError> {
    let encoded_size = postcard::to_allocvec(payload)
        .map_err(|error| {
            super::protocol::RpcError::new(
                super::protocol::RpcErrorCode::ProtocolError,
                error.to_string(),
            )
        })?
        .len();
    let encoded_bytes = u64::try_from(encoded_size).map_err(|_| {
        super::protocol::RpcError::new(
            super::protocol::RpcErrorCode::BudgetExceeded,
            format!("{label} byte length exceeds u64 range"),
        )
    })?;
    if encoded_bytes > max_bytes {
        return Err(super::protocol::RpcError::new(
            super::protocol::RpcErrorCode::BudgetExceeded,
            format!("{label} ({encoded_bytes} bytes) exceeds max_bytes ({max_bytes})"),
        ));
    }
    assert!(encoded_bytes <= max_bytes);
    Ok(())
}

fn scoped_source_overlay(
    workspace: &mneme_store::Workspace,
    pinned: mneme_core::WorkspaceRevisionId,
    scope: &mneme_core::ScopeId,
    access: &mneme_memory::Access,
) -> Result<Vec<([u8; 16], super::protocol::EncodedSourceAvailability)>, super::protocol::RpcError>
{
    if workspace.current_revision().map_err(store_rpc_error)? == pinned {
        return Ok(Vec::new());
    }
    let current = workspace.snapshot().map_err(store_rpc_error)?;
    let visible = mneme_datalog::filter_visible_snapshot(current, scope, access);
    let max_entries = visible.records.len();
    let mut overlay = Vec::with_capacity(max_entries);
    for record in visible.records {
        let Ok(source) = mneme_memory::SourceView::parse(record.clone()) else {
            continue;
        };
        let encoded = encode_source_availability(source.availability);
        overlay.push((*record.record_id.as_bytes(), encoded));
    }
    assert!(overlay.len() <= max_entries);
    Ok(overlay)
}

fn encode_source_availability(
    availability: mneme_memory::SourceAvailability,
) -> super::protocol::EncodedSourceAvailability {
    match availability {
        mneme_memory::SourceAvailability::Retained => {
            super::protocol::EncodedSourceAvailability::Retained
        }
        mneme_memory::SourceAvailability::Pruned => {
            super::protocol::EncodedSourceAvailability::Pruned
        }
        mneme_memory::SourceAvailability::Erased => {
            super::protocol::EncodedSourceAvailability::Erased
        }
        mneme_memory::SourceAvailability::Inaccessible => {
            super::protocol::EncodedSourceAvailability::Inaccessible
        }
        mneme_memory::SourceAvailability::Corrupt { reason } => {
            super::protocol::EncodedSourceAvailability::Corrupt(reason)
        }
        mneme_memory::SourceAvailability::Unavailable { reason } => {
            super::protocol::EncodedSourceAvailability::Unavailable(reason)
        }
    }
}

fn decode_datalog_constants(
    constant_documents: &[Option<String>],
) -> Result<Vec<Option<mneme_core::Value>>, super::protocol::RpcError> {
    let mut constants = Vec::with_capacity(constant_documents.len());
    for entry in constant_documents {
        let parsed = match entry {
            Some(text) => Some(mneme_core::decode_document(text).map_err(|diag| {
                super::protocol::RpcError::new(
                    super::protocol::RpcErrorCode::InvalidInput,
                    diag.to_string(),
                )
            })?),
            None => None,
        };
        constants.push(parsed);
    }
    assert_eq!(constants.len(), constant_documents.len());
    Ok(constants)
}

fn handle_evaluate_datalog(
    config: &ServerConfig,
    request: &super::protocol::EvaluateDatalogRequest,
) -> Result<super::protocol::RemoteDatalogResult, super::protocol::RpcError> {
    request.limits.check_within(&config.max_limits)?;
    let scope = parse_scope(&request.scope)?;
    let bundle_value = mneme_core::decode_document(&request.bundle_document).map_err(|diag| {
        super::protocol::RpcError::new(
            super::protocol::RpcErrorCode::InvalidInput,
            diag.to_string(),
        )
    })?;
    let bundle =
        crate::parse_bundle(&bundle_value, &mneme_core::Path::root()).map_err(|error| {
            super::protocol::RpcError::new(
                super::protocol::RpcErrorCode::InvalidInput,
                error.message,
            )
        })?;
    let constants = decode_datalog_constants(&request.constant_documents)?;
    let datalog_limits = request.limits.to_datalog_limits()?;
    let query_limit = usize::try_from(request.limit).map_err(|_| {
        super::protocol::RpcError::new(
            super::protocol::RpcErrorCode::BudgetExceeded,
            "query row limit exceeds platform capacity",
        )
    })?;
    let mut workspace = open_read_only_vault(&config.vault_root)?;
    let generation = workspace
        .eligibility_generation()
        .map_err(store_rpc_error)?;
    let head = workspace.current_revision().map_err(store_rpc_error)?;
    let revision = request
        .revision
        .map_or(head, mneme_core::WorkspaceRevisionId::from_bytes);
    let result = run_read_only_datalog(
        &mut workspace,
        DatalogEvalParams {
            scope,
            revision,
            bundle,
            datalog_limits,
            predicate: &request.predicate,
            constants,
            query_limit,
            stale_policy: request.stale_policy,
        },
    )?;
    verify_generation_unchanged(&workspace, generation, "remote Datalog evaluation")?;
    let encoded = encode_datalog_result(&result);
    check_payload_byte_budget(&encoded, request.limits.max_bytes, "Datalog result")?;
    assert_eq!(encoded.served_revision, *result.served_revision.as_bytes());
    Ok(encoded)
}

struct DatalogEvalParams<'a> {
    scope: mneme_core::ScopeId,
    revision: mneme_core::WorkspaceRevisionId,
    bundle: mneme_datalog::RuleBundle,
    datalog_limits: mneme_datalog::Limits,
    predicate: &'a str,
    constants: Vec<Option<mneme_core::Value>>,
    query_limit: usize,
    stale_policy: super::protocol::StalePolicy,
}

fn run_read_only_datalog(
    workspace: &mut mneme_store::Workspace,
    params: DatalogEvalParams<'_>,
) -> Result<mneme_datalog::QueryResult, super::protocol::RpcError> {
    let access = mneme_memory::Access::scopes([params.scope.clone()]);
    let mut service = mneme_datalog::Service::new(workspace);
    let build = service
        .build(mneme_datalog::BuildRequest {
            actor: "remote-federation-peer".to_owned(),
            scope: params.scope,
            revision: params.revision,
            bundle: params.bundle,
            limits: params.datalog_limits,
            publish: false,
            incomplete_extents: std::collections::BTreeSet::new(),
            cancellation: None,
            access,
            at: None,
        })
        .map_err(datalog_rpc_error)?;
    let mut query = mneme_datalog::Query::all(params.predicate, params.query_limit);
    query.constants = params.constants;
    query.allow_stale = matches!(params.stale_policy, super::protocol::StalePolicy::Allow);
    service
        .query_build(&build, query)
        .map_err(datalog_rpc_error)
}

fn encode_datalog_result(
    result: &mneme_datalog::QueryResult,
) -> super::protocol::RemoteDatalogResult {
    super::protocol::RemoteDatalogResult {
        protocol_version: super::protocol::PROTOCOL_VERSION,
        relation: result.relation.clone(),
        status: result.status.name().to_owned(),
        requested_revision: *result.requested_revision.as_bytes(),
        served_revision: *result.served_revision.as_bytes(),
        eligibility_generation: result.context.eligibility_generation,
        coverage: result
            .coverage
            .iter()
            .map(|entry| super::protocol::RemoteCoverage {
                predicate: entry.predicate.clone(),
                status: entry.status.name().to_owned(),
                reason: entry.reason.clone(),
            })
            .collect(),
        rows: result
            .rows
            .iter()
            .map(|row| super::protocol::RemoteQueryRow {
                value_documents: row
                    .values
                    .iter()
                    .map(mneme_core::encode_document_string)
                    .collect(),
                supports: row
                    .supports
                    .iter()
                    .map(|support| super::protocol::RemoteDerivation {
                        rule_id: support.rule_id.clone(),
                        rule_version: support.rule_version.clone(),
                        premises: support
                            .premises
                            .iter()
                            .map(|premise| super::protocol::RemotePremise {
                                predicate: premise.predicate.clone(),
                                term_documents: premise
                                    .terms
                                    .iter()
                                    .map(mneme_core::encode_document_string)
                                    .collect(),
                                vault: premise.vault.clone(),
                                vaults: premise.vaults.iter().cloned().collect(),
                                absent: premise.absent,
                                source_availability: premise.source_availability.clone(),
                            })
                            .collect(),
                        vaults: support.vaults.iter().cloned().collect(),
                        truncated: support.truncated,
                    })
                    .collect(),
                support_truncated: row.support_truncated,
            })
            .collect(),
        exhaustive: result.exhaustive,
        truncated: result.truncated,
        absence_established: result.absence_established,
        stale: result.stale,
        reason: result.reason.clone(),
        work: result.work,
    }
}

fn store_rpc_error(error: mneme_store::Failure) -> super::protocol::RpcError {
    let code = match error {
        mneme_store::Failure::Integrity { .. } => super::protocol::RpcErrorCode::NotFound,
        mneme_store::Failure::BarrierAdvanced { .. }
        | mneme_store::Failure::StaleBase { .. }
        | mneme_store::Failure::IdempotencyConflict { .. } => {
            super::protocol::RpcErrorCode::Conflict
        }
        mneme_store::Failure::InvalidCommand(_)
        | mneme_store::Failure::ScopeMismatch { .. }
        | mneme_store::Failure::HistoryLimitExceeded => super::protocol::RpcErrorCode::InvalidInput,
        _ => super::protocol::RpcErrorCode::Unavailable,
    };
    super::protocol::RpcError::new(code, error.to_string())
}

fn datalog_rpc_error(error: mneme_datalog::Error) -> super::protocol::RpcError {
    match error {
        mneme_datalog::Error::Store(store) => store_rpc_error(store),
        mneme_datalog::Error::Stale { .. } => {
            super::protocol::RpcError::new(super::protocol::RpcErrorCode::Stale, error.to_string())
        }
        mneme_datalog::Error::InvalidBundle(_)
        | mneme_datalog::Error::UnknownPredicate(_)
        | mneme_datalog::Error::InvalidQuery(_) => super::protocol::RpcError::new(
            super::protocol::RpcErrorCode::InvalidInput,
            error.to_string(),
        ),
        other => super::protocol::RpcError::new(
            super::protocol::RpcErrorCode::Unavailable,
            other.to_string(),
        ),
    }
}
