//! Strictly read-only `irpc` federation server across in-memory, Quinn (`noq`), and Iroh.
#![allow(unknown_lints)] // Octet structural exception: irpc macro handler closures and async channels

use irpc::rpc::RemoteService;

const PERMISSION_DENIED_CODE: u32 = 1;
const RATE_LIMITED_CODE: u32 = 2;
const DEFAULT_CHANNEL_CAPACITY: u32 = 64;
const FALLBACK_CHANNEL_CAPACITY_SLOTS: usize = 64;
const MAX_CONCURRENT_CONNECTIONS: usize = 64;
const MAX_CONCURRENT_RPCS: usize = 64;
const MAX_CONCURRENT_BLOCKING_TASKS: usize = 16;
const MAX_HEAD_READ_RETRIES: u32 = 4;
const POSTCARD_LEN_OVERHEAD_BYTES: u64 = 10;

/// Re-export of [`super::auth::PeerAllowlist`] for backward compatibility.
pub use super::auth::PeerAllowlist;

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

struct AuthenticatedMessage {
    caller: iroh::EndpointId,
    message: super::protocol::VaultFederationMessage,
}

#[derive(Clone)]
struct ActorContext {
    config: ServerConfig,
    authorizer: super::auth::SharedFederationAuthorizer,
    clock: std::sync::Arc<dyn mneme_store::Clock>,
    blocking_semaphore: std::sync::Arc<tokio::sync::Semaphore>,
}

/// Read-only `irpc` federation server serving one vault over memory, Quinn, and Iroh.
#[derive(Clone)]
#[allow(unknown_lints, path_segment_repetition)] // public API compatibility type name
pub struct VaultFederationServer {
    config: ServerConfig,
    authorizer: super::auth::SharedFederationAuthorizer,
    connection_semaphore: std::sync::Arc<tokio::sync::Semaphore>,
    sender: tokio::sync::mpsc::Sender<AuthenticatedMessage>,
}

impl VaultFederationServer {
    /// Spawn the bounded read-only RPC actor for `config`.
    pub fn spawn(config: ServerConfig) -> Result<Self, super::client::FederationError> {
        let authorizer =
            super::auth::SharedFederationAuthorizer::from_allowlist(config.allowlist.clone());
        Self::spawn_with_authorizer_and_clock(
            config,
            authorizer,
            std::sync::Arc::new(mneme_store::SystemClock),
        )
    }

    /// Spawn the bounded read-only RPC actor with an explicit live-reloadable authorizer and clock.
    pub fn spawn_with_authorizer_and_clock(
        config: ServerConfig,
        authorizer: super::auth::SharedFederationAuthorizer,
        clock: std::sync::Arc<dyn mneme_store::Clock>,
    ) -> Result<Self, super::client::FederationError> {
        config
            .max_limits
            .validate()
            .map_err(|error| super::client::FederationError::InvalidInput(error.message))?;
        let channel_depth = usize::try_from(config.channel_capacity.max(1)).map_err(|_| {
            super::client::FederationError::InvalidInput("invalid channel capacity".to_owned())
        })?;
        debug_assert!(channel_depth >= 1);
        let (sender, receiver) = tokio::sync::mpsc::channel(channel_depth);
        let context = ActorContext {
            config: config.clone(),
            authorizer: authorizer.clone(),
            clock,
            blocking_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_BLOCKING_TASKS,
            )),
        };
        let actor_handle = tokio::task::spawn(async move {
            run_actor(context, receiver).await;
        });
        drop(actor_handle);
        let connection_semaphore =
            std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
        debug_assert_eq!(
            connection_semaphore.available_permits(),
            MAX_CONCURRENT_CONNECTIONS
        );
        Ok(Self {
            config,
            authorizer,
            connection_semaphore,
            sender,
        })
    }

    /// The initial configured Ed25519 peer allowlist.
    pub fn allowlist(&self) -> &PeerAllowlist {
        &self.config.allowlist
    }

    /// Live-reloadable (`RwLock`) per-scope allowlist and `concap` authorizer.
    pub fn authorizer(&self) -> &super::auth::SharedFederationAuthorizer {
        &self.authorizer
    }

    /// Create an in-memory client bound to `caller`, enforcing the server's live
    /// per-scope allowlist and `concap` authorizer on every RPC.
    pub fn local_client_for(
        &self,
        caller: iroh::EndpointId,
    ) -> super::client::VaultFederationClient {
        let channel_depth = match usize::try_from(self.config.channel_capacity.max(1)) {
            Ok(depth) => depth,
            Err(_) => FALLBACK_CHANNEL_CAPACITY_SLOTS,
        };
        debug_assert!(channel_depth >= 1);
        let (gate_tx, mut gate_rx) = tokio::sync::mpsc::channel(channel_depth);
        let backend = self.sender.clone();
        let gate_handle = tokio::task::spawn(async move {
            while let Some(message) = gate_rx.recv().await {
                if backend
                    .send(AuthenticatedMessage { caller, message })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        drop(gate_handle);
        debug_assert!(!caller.as_bytes().is_empty());
        super::client::VaultFederationClient::from_irpc(irpc::Client::local(gate_tx))
    }

    /// Create an `iroh::protocol::ProtocolHandler` enforcing the live authorizer
    /// and connection concurrency bounds on every incoming Iroh connection.
    pub fn iroh_protocol_handler(&self) -> IrohFederationHandler {
        IrohFederationHandler {
            authorizer: self.authorizer.clone(),
            connection_semaphore: std::sync::Arc::clone(&self.connection_semaphore),
            channel_depth: self.config.channel_capacity,
            backend: self.sender.clone(),
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
    /// the live authorizer and connection concurrency semaphore before handling RPC streams.
    pub fn serve_noq(&self, endpoint: noq::Endpoint) -> tokio::task::JoinHandle<()> {
        let authorizer = self.authorizer.clone();
        let connection_semaphore = std::sync::Arc::clone(&self.connection_semaphore);
        let channel_depth = self.config.channel_capacity;
        let backend = self.sender.clone();
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
                        let Ok(permit) = std::sync::Arc::clone(&connection_semaphore).try_acquire_owned() else {
                            incoming.refuse();
                            continue;
                        };
                        let authorizer = authorizer.clone();
                        let backend = backend.clone();
                        let task = tasks.spawn(async move {
                            let _permit = permit;
                            accept_noq_connection(incoming, authorizer, channel_depth, backend).await;
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

fn per_connection_handler(
    caller: iroh::EndpointId,
    channel_depth: u32,
    backend: tokio::sync::mpsc::Sender<AuthenticatedMessage>,
) -> (
    irpc::rpc::Handler<super::protocol::VaultFederationProtocol>,
    tokio::task::JoinHandle<()>,
) {
    let depth = match usize::try_from(channel_depth.max(1)) {
        Ok(value) => value,
        Err(_) => FALLBACK_CHANNEL_CAPACITY_SLOTS,
    };
    debug_assert!(depth >= 1);
    let (conn_tx, mut conn_rx) = tokio::sync::mpsc::channel(depth);
    let forwarder = tokio::task::spawn(async move {
        while let Some(message) = conn_rx.recv().await {
            if backend
                .send(AuthenticatedMessage { caller, message })
                .await
                .is_err()
            {
                break;
            }
        }
    });
    debug_assert!(!caller.as_bytes().is_empty());
    let handler = super::protocol::VaultFederationProtocol::remote_handler(conn_tx.into());
    (handler, forwarder)
}

async fn accept_noq_connection(
    incoming: noq::Incoming,
    authorizer: super::auth::SharedFederationAuthorizer,
    channel_depth: u32,
    backend: tokio::sync::mpsc::Sender<AuthenticatedMessage>,
) {
    let Ok(connection) = incoming.await else {
        return;
    };
    match super::quinn::authenticated_peer_id(&connection) {
        Ok(peer_id) if authorizer.can_connect(&peer_id) => {
            let (handler, forwarder) = per_connection_handler(peer_id, channel_depth, backend);
            let _closed = irpc::rpc::handle_connection(connection, handler)
                .await
                .is_err();
            forwarder.abort();
        }
        Ok(_) | Err(_) => {
            connection.close(PERMISSION_DENIED_CODE.into(), b"peer not authorized");
        }
    }
}

/// `iroh::protocol::ProtocolHandler` that rejects unauthorized `EndpointId`s
/// and enforces connection concurrency limits before reading any RPC message.
#[derive(Clone)]
#[allow(unknown_lints, path_segment_repetition)] // public API compatibility type name
pub struct IrohFederationHandler {
    authorizer: super::auth::SharedFederationAuthorizer,
    connection_semaphore: std::sync::Arc<tokio::sync::Semaphore>,
    channel_depth: u32,
    backend: tokio::sync::mpsc::Sender<AuthenticatedMessage>,
}

impl std::fmt::Debug for IrohFederationHandler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IrohFederationHandler")
            .field(
                "allowlisted_peers",
                &self.authorizer.allowlist_snapshot().len(),
            )
            .finish()
    }
}

impl iroh::protocol::ProtocolHandler for IrohFederationHandler {
    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        let remote_id = connection.remote_id();
        debug_assert!(!remote_id.as_bytes().is_empty());
        if !self.authorizer.can_connect(&remote_id) {
            connection.close(PERMISSION_DENIED_CODE.into(), b"peer not authorized");
            return Err(iroh::protocol::AcceptError::from_err(
                super::protocol::RpcError::new(
                    super::protocol::RpcErrorCode::Unauthorized,
                    "peer is not authorized for federation",
                ),
            ));
        }
        let Ok(_permit) = std::sync::Arc::clone(&self.connection_semaphore).try_acquire_owned()
        else {
            connection.close(
                RATE_LIMITED_CODE.into(),
                b"federation connection limit exceeded",
            );
            return Err(iroh::protocol::AcceptError::from_err(
                super::protocol::RpcError::new(
                    super::protocol::RpcErrorCode::BudgetExceeded,
                    "federation connection concurrency limit exceeded",
                ),
            ));
        };
        debug_assert!(self.channel_depth > 0);
        let (handler, forwarder) =
            per_connection_handler(remote_id, self.channel_depth, self.backend.clone());
        let result = irpc_iroh::handle_connection::<super::protocol::VaultFederationProtocol>(
            &connection,
            handler,
        )
        .await
        .map_err(iroh::protocol::AcceptError::from_err);
        forwarder.abort();
        result
    }
}

async fn run_actor(
    context: ActorContext,
    mut receiver: tokio::sync::mpsc::Receiver<AuthenticatedMessage>,
) {
    let rpc_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_RPCS));
    debug_assert_eq!(rpc_semaphore.available_permits(), MAX_CONCURRENT_RPCS);
    let mut tasks = tokio::task::JoinSet::new();
    debug_assert!(tasks.is_empty());
    loop {
        tokio::select! {
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            envelope = receiver.recv() => {
                let Some(envelope) = envelope else {
                    break;
                };
                let Ok(permit) = std::sync::Arc::clone(&rpc_semaphore).acquire_owned().await else {
                    break;
                };
                let ctx = context.clone();
                let task = tasks.spawn(async move {
                    let _permit = permit;
                    dispatch_message(ctx, envelope.caller, envelope.message).await;
                });
                drop(task);
            }
        }
    }
}

fn authorize_request(
    ctx: &ActorContext,
    caller: iroh::EndpointId,
    scope_text: &str,
    capability_document: Option<&str>,
) -> Result<mneme_core::ScopeId, super::protocol::RpcError> {
    let scope = parse_scope(scope_text)?;
    let now_secs = super::auth::timestamp_to_epoch_secs(ctx.clock.now()).map_err(|reason| {
        super::protocol::RpcError::new(super::protocol::RpcErrorCode::Unauthorized, reason)
    })?;
    ctx.authorizer
        .authorize_scope(caller, &scope, capability_document, now_secs)?;
    Ok(scope)
}

#[allow(unknown_lints, fragile_exhaustive_enum_match)] // irpc protocol dispatch must handle every VaultFederationMessage variant
async fn dispatch_message(
    ctx: ActorContext,
    caller: iroh::EndpointId,
    message: super::protocol::VaultFederationMessage,
) {
    match message {
        super::protocol::VaultFederationMessage::QueryHead(msg) => {
            dispatch_query_head(ctx, caller, msg).await;
        }
        super::protocol::VaultFederationMessage::QueryMetadata(msg) => {
            dispatch_query_metadata(ctx, caller, msg).await;
        }
        super::protocol::VaultFederationMessage::FetchPinnedSnapshot(msg) => {
            dispatch_fetch_pinned_snapshot(ctx, caller, msg).await;
        }
        super::protocol::VaultFederationMessage::EvaluateDatalog(msg) => {
            dispatch_evaluate_datalog(ctx, caller, msg).await;
        }
    }
}

async fn run_authorized_blocking<T, F>(
    ctx: &ActorContext,
    auth: Result<mneme_core::ScopeId, super::protocol::RpcError>,
    timeout_ms: u64,
    task: F,
) -> Result<T, super::protocol::RpcError>
where
    T: Send + 'static,
    F: FnOnce(ServerConfig) -> Result<T, super::protocol::RpcError> + Send + 'static,
{
    let _scope = auth?;
    let cfg = ctx.config.clone();
    run_bounded_blocking(
        std::sync::Arc::clone(&ctx.blocking_semaphore),
        timeout_ms,
        move || task(cfg),
    )
    .await
}

async fn dispatch_query_head(
    ctx: ActorContext,
    caller: iroh::EndpointId,
    msg: irpc::WithChannels<
        super::protocol::QueryHeadRequest,
        super::protocol::VaultFederationProtocol,
    >,
) {
    let auth = authorize_request(
        &ctx,
        caller,
        &msg.inner.scope,
        msg.inner.capability_document.as_deref(),
    );
    let timeout_ms = ctx.config.max_limits.max_time_ms;
    let result = run_authorized_blocking(&ctx, auth, timeout_ms, move |cfg| {
        handle_query_head(&cfg, &msg.inner)
    })
    .await;
    let _sent = msg.tx.send(result).await.is_ok();
}

async fn dispatch_query_metadata(
    ctx: ActorContext,
    caller: iroh::EndpointId,
    msg: irpc::WithChannels<
        super::protocol::QueryMetadataRequest,
        super::protocol::VaultFederationProtocol,
    >,
) {
    let auth = authorize_request(
        &ctx,
        caller,
        &msg.inner.scope,
        msg.inner.capability_document.as_deref(),
    );
    let timeout_ms = ctx.config.max_limits.max_time_ms;
    let result = run_authorized_blocking(&ctx, auth, timeout_ms, move |cfg| {
        handle_query_metadata(&cfg, &msg.inner)
    })
    .await;
    let _sent = msg.tx.send(result).await.is_ok();
}

async fn dispatch_fetch_pinned_snapshot(
    ctx: ActorContext,
    caller: iroh::EndpointId,
    msg: irpc::WithChannels<
        super::protocol::FetchPinnedSnapshotRequest,
        super::protocol::VaultFederationProtocol,
    >,
) {
    let auth = authorize_request(
        &ctx,
        caller,
        &msg.inner.scope,
        msg.inner.capability_document.as_deref(),
    );
    let timeout_ms = msg
        .inner
        .limits
        .max_time_ms
        .min(ctx.config.max_limits.max_time_ms)
        .max(1);
    let result = run_authorized_blocking(&ctx, auth, timeout_ms, move |cfg| {
        handle_fetch_pinned_snapshot(&cfg, &msg.inner)
    })
    .await;
    let _sent = msg.tx.send(result).await.is_ok();
}

async fn dispatch_evaluate_datalog(
    ctx: ActorContext,
    caller: iroh::EndpointId,
    msg: irpc::WithChannels<
        super::protocol::EvaluateDatalogRequest,
        super::protocol::VaultFederationProtocol,
    >,
) {
    let auth = authorize_request(
        &ctx,
        caller,
        &msg.inner.scope,
        msg.inner.capability_document.as_deref(),
    );
    let timeout_ms = msg
        .inner
        .limits
        .max_time_ms
        .min(ctx.config.max_limits.max_time_ms)
        .max(1);
    let result = run_authorized_blocking(&ctx, auth, timeout_ms, move |cfg| {
        handle_evaluate_datalog(&cfg, &msg.inner)
    })
    .await;
    let _sent = msg.tx.send(result).await.is_ok();
}

async fn run_bounded_blocking<T, F>(
    blocking_semaphore: std::sync::Arc<tokio::sync::Semaphore>,
    timeout_ms: u64,
    task: F,
) -> Result<T, super::protocol::RpcError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, super::protocol::RpcError> + Send + 'static,
{
    debug_assert!(timeout_ms > 0);
    let budget = std::time::Duration::from_millis(timeout_ms);
    let permit = match tokio::time::timeout(budget, blocking_semaphore.acquire_owned()).await {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) => {
            return Err(super::protocol::RpcError::new(
                super::protocol::RpcErrorCode::Unavailable,
                "federation worker pool closed",
            ));
        }
        Err(_) => {
            return Err(super::protocol::RpcError::new(
                super::protocol::RpcErrorCode::BudgetExceeded,
                "federation blocking pool saturated within wall-clock limit",
            ));
        }
    };
    debug_assert!(!budget.is_zero());
    let handle = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        task()
    });
    match tokio::time::timeout(budget, handle).await {
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
    for _ in 0..MAX_HEAD_READ_RETRIES {
        let generation_before = workspace
            .eligibility_generation()
            .map_err(store_rpc_error)?;
        let head_before = workspace.current_revision().map_err(store_rpc_error)?;
        let sequence = workspace.current_sequence().map_err(store_rpc_error)?;
        let head_after = workspace.current_revision().map_err(store_rpc_error)?;
        let generation_after = workspace
            .eligibility_generation()
            .map_err(store_rpc_error)?;
        if head_before == head_after && generation_before == generation_after {
            debug_assert_eq!(head_before, head_after);
            debug_assert_eq!(generation_before, generation_after);
            return Ok(super::protocol::HeadState {
                protocol_version: super::protocol::PROTOCOL_VERSION,
                head_revision: *head_before.as_bytes(),
                head_sequence: sequence,
                eligibility_generation: generation_before,
            });
        }
    }
    Err(super::protocol::RpcError::new(
        super::protocol::RpcErrorCode::Conflict,
        "workspace head advanced concurrently during O(1) QueryHead",
    ))
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
    let served = filtered.revision;
    let payload = build_snapshot_payload_bounded(
        SnapshotPayloadInput {
            requested,
            generation,
            filtered,
            view_context,
            suppressions,
            current_sources,
        },
        request.limits.max_bytes,
    )?;
    check_payload_byte_budget(&payload, request.limits.max_bytes, "pinned snapshot")?;
    assert_eq!(payload.served_revision, *served.as_bytes());
    assert_eq!(payload.eligibility_generation, generation);
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

fn encode_bounded_record_docs<'a>(
    records: impl ExactSizeIterator<Item = &'a mneme_core::RecordEnvelope>,
    running_bytes: &mut u64,
    max_bytes: u64,
) -> Result<Vec<String>, super::protocol::RpcError> {
    let mut docs = Vec::with_capacity(records.len());
    for record in records {
        let doc = mneme_core::encode_document_string(&record.to_value());
        *running_bytes = running_bytes.saturating_add(doc.len() as u64);
        ensure_running_budget(RunningByteBudget {
            running_bytes: *running_bytes,
            max_bytes,
            label: "pinned snapshot",
        })?;
        docs.push(doc);
    }
    Ok(docs)
}

fn build_snapshot_payload_bounded(
    input: SnapshotPayloadInput,
    max_bytes: u64,
) -> Result<super::protocol::PinnedSnapshotPayload, super::protocol::RpcError> {
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

    let scoped_digest = super::protocol::scoped_manifest_digest(
        filtered.revision,
        filtered.parent,
        filtered.records.iter(),
        view_context.history.values(),
        filtered.manifest_digest.algorithm(),
    );
    let manifest_digest_document = mneme_core::encode_document_string(&scoped_digest.to_value());
    let mut running_bytes: u64 = manifest_digest_document.len() as u64;
    ensure_running_budget(RunningByteBudget {
        running_bytes,
        max_bytes,
        label: "pinned snapshot",
    })?;

    let record_documents =
        encode_bounded_record_docs(filtered.records.iter(), &mut running_bytes, max_bytes)?;
    let history_documents =
        encode_bounded_record_docs(view_context.history.values(), &mut running_bytes, max_bytes)?;

    let revision_sequences: Vec<([u8; 16], u64)> = view_context
        .revision_sequences
        .into_iter()
        .map(|(rev, seq)| (*rev.as_bytes(), seq))
        .collect();
    running_bytes = running_bytes
        .saturating_add((revision_sequences.len() as u64).saturating_mul(17))
        .saturating_add(POSTCARD_LEN_OVERHEAD_BYTES);
    ensure_running_budget(RunningByteBudget {
        running_bytes,
        max_bytes,
        label: "pinned snapshot",
    })?;

    Ok(super::protocol::PinnedSnapshotPayload {
        protocol_version: super::protocol::PROTOCOL_VERSION,
        requested_revision: *requested.as_bytes(),
        served_revision: *filtered.revision.as_bytes(),
        sequence: filtered.sequence,
        parent: filtered.parent.map(|rev| *rev.as_bytes()),
        manifest_digest_document,
        eligibility_generation: generation,
        record_documents,
        history_documents,
        revision_sequences,
        suppressions,
        current_sources,
    })
}

struct RunningByteBudget<'a> {
    running_bytes: u64,
    max_bytes: u64,
    label: &'a str,
}

fn ensure_running_budget(budget: RunningByteBudget<'_>) -> Result<(), super::protocol::RpcError> {
    if budget.running_bytes > budget.max_bytes {
        return Err(super::protocol::RpcError::new(
            super::protocol::RpcErrorCode::BudgetExceeded,
            format!(
                "{} ({} bytes) exceeds max_bytes ({})",
                budget.label, budget.running_bytes, budget.max_bytes
            ),
        ));
    }
    Ok(())
}

struct BoundedByteCounter {
    count: u64,
    max_bytes: u64,
}

impl postcard::ser_flavors::Flavor for BoundedByteCounter {
    type Output = u64;

    fn try_push(&mut self, _data: u8) -> postcard::Result<()> {
        self.count = self.count.saturating_add(1);
        if self.count > self.max_bytes {
            return Err(postcard::Error::SerializeBufferFull);
        }
        Ok(())
    }

    fn try_extend(&mut self, data: &[u8]) -> postcard::Result<()> {
        let len = u64::try_from(data.len()).map_err(|_| postcard::Error::SerializeBufferFull)?;
        self.count = self.count.saturating_add(len);
        if self.count > self.max_bytes {
            return Err(postcard::Error::SerializeBufferFull);
        }
        Ok(())
    }

    fn finalize(self) -> postcard::Result<Self::Output> {
        Ok(self.count)
    }
}

fn check_payload_byte_budget<T: serde::Serialize>(
    payload: &T,
    max_bytes: u64,
    label: &str,
) -> Result<(), super::protocol::RpcError> {
    debug_assert!(max_bytes > 0);
    let counter = BoundedByteCounter {
        count: 0,
        max_bytes,
    };
    let encoded_bytes = postcard::serialize_with_flavor(payload, counter).map_err(|error| {
        if error == postcard::Error::SerializeBufferFull {
            super::protocol::RpcError::new(
                super::protocol::RpcErrorCode::BudgetExceeded,
                format!("{label} exceeds max_bytes ({max_bytes})"),
            )
        } else {
            super::protocol::RpcError::new(
                super::protocol::RpcErrorCode::ProtocolError,
                error.to_string(),
            )
        }
    })?;
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
    let max_result_rows = usize::try_from(request.max_rows).map_err(|_| {
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
            query_limit: max_result_rows,
            stale_policy: request.stale_policy,
        },
    )?;
    verify_generation_unchanged(&workspace, generation, "remote Datalog evaluation")?;
    let encoded = encode_datalog_result(&result);
    check_payload_byte_budget(&encoded, request.limits.max_bytes, "Datalog result")?;
    assert_eq!(encoded.served_revision, *result.served_revision.as_bytes());
    assert_eq!(encoded.protocol_version, super::protocol::PROTOCOL_VERSION);
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
