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
    pub max_hlc_skew_ns: i64,
}

impl ServerConfig {
    /// Create a deny-all configuration for `vault_root` with default bounds.
    pub fn new(vault_root: impl Into<std::path::PathBuf>, allowlist: PeerAllowlist) -> Self {
        Self {
            vault_root: vault_root.into(),
            allowlist,
            max_limits: super::protocol::FederationLimits::standard(),
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
            max_hlc_skew_ns: mneme_kernel::hlc::DEFAULT_MAX_SKEW_NS,
        }
    }
}

struct AuthenticatedMessage {
    caller: iroh::EndpointId,
    message: super::protocol::VaultFederationMessage,
}

struct ArcClock(std::sync::Arc<dyn mneme_store::Clock>);

impl mneme_store::Clock for ArcClock {
    fn now(&self) -> mneme_core::Timestamp {
        self.0.now()
    }
}

#[derive(Clone)]
struct ActorContext {
    config: ServerConfig,
    authorizer: super::auth::SharedFederationAuthorizer,
    clock: std::sync::Arc<dyn mneme_store::Clock>,
    hlc: std::sync::Arc<std::sync::Mutex<mneme_kernel::hlc::HybridTimestamp>>,
    blocking_semaphore: std::sync::Arc<tokio::sync::Semaphore>,
}

/// Read-only `irpc` federation server serving one vault over memory, Quinn, and Iroh.
#[derive(Clone)]
#[allow(unknown_lints, path_segment_repetition)] // public API compatibility type name
pub struct VaultFederationServer {
    config: ServerConfig,
    authorizer: super::auth::SharedFederationAuthorizer,
    clock: std::sync::Arc<dyn mneme_store::Clock>,
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
        let init_hlc = mneme_kernel::hlc::HybridTimestamp {
            physical_ns: clock.now().nanos(),
            logical: 0,
        };
        let context = ActorContext {
            config: config.clone(),
            authorizer: authorizer.clone(),
            clock: std::sync::Arc::clone(&clock),
            hlc: std::sync::Arc::new(std::sync::Mutex::new(init_hlc)),
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
            clock,
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
            .with_clock(std::sync::Arc::clone(&self.clock))
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
        super::protocol::VaultFederationMessage::ExplainMissing(msg) => {
            dispatch_explain_missing(ctx, caller, msg).await;
        }
    }
}

fn observe_incoming_hlc(
    ctx: &ActorContext,
    sender_hlc: Option<super::protocol::WireHybridTimestamp>,
    read_hlc: Option<super::protocol::WireHybridTimestamp>,
) -> Result<(), super::protocol::RpcError> {
    let pt_ns = ctx.clock.now().nanos();
    let max_skew_ns = ctx.config.max_hlc_skew_ns;
    let mut guard = ctx.hlc.lock().map_err(|_| {
        super::protocol::RpcError::new(
            super::protocol::RpcErrorCode::Unavailable,
            "server HLC mutex poisoned",
        )
    })?;
    for incoming in [sender_hlc, read_hlc].into_iter().flatten() {
        let next = mneme_kernel::hlc::receive(*guard, pt_ns, incoming.to_kernel(), max_skew_ns)
            .map_err(map_server_hlc_error)?;
        *guard = next;
    }
    Ok(())
}

fn tick_server_hlc(
    ctx: &ActorContext,
) -> Result<super::protocol::WireHybridTimestamp, super::protocol::RpcError> {
    let pt_ns = ctx.clock.now().nanos();
    let max_skew_ns = ctx.config.max_hlc_skew_ns;
    let mut guard = ctx.hlc.lock().map_err(|_| {
        super::protocol::RpcError::new(
            super::protocol::RpcErrorCode::Unavailable,
            "server HLC mutex poisoned",
        )
    })?;
    let next =
        mneme_kernel::hlc::tick_local(*guard, pt_ns, max_skew_ns).map_err(map_server_hlc_error)?;
    *guard = next;
    Ok(super::protocol::WireHybridTimestamp::from_kernel(next))
}

fn map_server_hlc_error(error: mneme_kernel::hlc::HlcError) -> super::protocol::RpcError {
    match error {
        mneme_kernel::hlc::HlcError::ClockSkewExceeded => super::protocol::RpcError::new(
            super::protocol::RpcErrorCode::ClockSkewExceeded,
            "incoming federation HLC exceeded maximum permitted physical clock skew",
        ),
        mneme_kernel::hlc::HlcError::LogicalOverflow => super::protocol::RpcError::new(
            super::protocol::RpcErrorCode::ClockSkewExceeded,
            "server federation HLC logical counter overflowed",
        ),
        mneme_kernel::hlc::HlcError::InvalidMaxSkew => super::protocol::RpcError::new(
            super::protocol::RpcErrorCode::InvalidInput,
            "server max_hlc_skew_ns must be non-negative",
        ),
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
    F: FnOnce(ActorContext) -> Result<T, super::protocol::RpcError> + Send + 'static,
{
    let _scope = auth?;
    let task_ctx = ctx.clone();
    run_bounded_blocking(
        std::sync::Arc::clone(&ctx.blocking_semaphore),
        timeout_ms,
        move || task(task_ctx),
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
    )
    .and_then(|scope| {
        observe_incoming_hlc(&ctx, msg.inner.sender_hlc, None)?;
        Ok(scope)
    });
    let timeout_ms = ctx.config.max_limits.max_time_ms;
    let result = run_authorized_blocking(&ctx, auth, timeout_ms, move |task_ctx| {
        handle_query_head(&task_ctx, &msg.inner)
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
    )
    .and_then(|scope| {
        observe_incoming_hlc(&ctx, msg.inner.sender_hlc, msg.inner.read_hlc)?;
        Ok(scope)
    });
    let timeout_ms = ctx.config.max_limits.max_time_ms;
    let result = run_authorized_blocking(&ctx, auth, timeout_ms, move |task_ctx| {
        handle_query_metadata(&task_ctx, &msg.inner)
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
    )
    .and_then(|scope| {
        observe_incoming_hlc(&ctx, msg.inner.sender_hlc, msg.inner.read_hlc)?;
        Ok(scope)
    });
    let timeout_ms = msg
        .inner
        .limits
        .max_time_ms
        .min(ctx.config.max_limits.max_time_ms)
        .max(1);
    let result = run_authorized_blocking(&ctx, auth, timeout_ms, move |task_ctx| {
        handle_fetch_pinned_snapshot(&task_ctx, &msg.inner)
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
    )
    .and_then(|scope| {
        observe_incoming_hlc(&ctx, msg.inner.sender_hlc, msg.inner.read_hlc)?;
        Ok(scope)
    });
    let timeout_ms = msg
        .inner
        .limits
        .max_time_ms
        .min(ctx.config.max_limits.max_time_ms)
        .max(1);
    let result = run_authorized_blocking(&ctx, auth, timeout_ms, move |task_ctx| {
        handle_evaluate_datalog(&task_ctx, &msg.inner)
    })
    .await;
    let _sent = msg.tx.send(result).await.is_ok();
}

async fn dispatch_explain_missing(
    ctx: ActorContext,
    caller: iroh::EndpointId,
    msg: irpc::WithChannels<
        super::protocol::ExplainMissingRpcRequest,
        super::protocol::VaultFederationProtocol,
    >,
) {
    let auth = authorize_request(
        &ctx,
        caller,
        &msg.inner.scope,
        msg.inner.capability_document.as_deref(),
    )
    .and_then(|scope| {
        observe_incoming_hlc(&ctx, msg.inner.sender_hlc, msg.inner.read_hlc)?;
        Ok(scope)
    });
    let timeout_ms = msg
        .inner
        .limits
        .max_time_ms
        .min(ctx.config.max_limits.max_time_ms)
        .max(1);
    let result = run_authorized_blocking(&ctx, auth, timeout_ms, move |task_ctx| {
        handle_explain_missing(&task_ctx, &msg.inner)
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
    clock: &std::sync::Arc<dyn mneme_store::Clock>,
    max_hlc_skew_ns: i64,
) -> Result<mneme_store::Workspace, super::protocol::RpcError> {
    let mut workspace = mneme_store::Workspace::open_read_only(
        root,
        mneme_store::WorkspaceConfig::new(
            Box::new(ArcClock(std::sync::Arc::clone(clock))),
            Box::new(mneme_store::NoFaults),
        ),
    )
    .map_err(store_rpc_error)?;
    workspace.set_hlc_max_skew_ns(max_hlc_skew_ns);
    Ok(workspace)
}

fn resolve_requested_revision(
    workspace: &mneme_store::Workspace,
    explicit_revision: Option<[u8; 16]>,
    read_hlc: Option<super::protocol::WireHybridTimestamp>,
) -> Result<mneme_core::WorkspaceRevisionId, super::protocol::RpcError> {
    if let Some(bytes) = explicit_revision {
        return Ok(mneme_core::WorkspaceRevisionId::from_bytes(bytes));
    }
    if let Some(hlc_cut) = read_hlc {
        return workspace
            .resolve_revision_at_hlc(hlc_cut.to_kernel())
            .map_err(store_rpc_error);
    }
    workspace.current_revision().map_err(store_rpc_error)
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
    ctx: &ActorContext,
    request: &super::protocol::QueryHeadRequest,
) -> Result<super::protocol::HeadState, super::protocol::RpcError> {
    let _scope = parse_scope(&request.scope)?;
    let workspace = open_read_only_vault(
        &ctx.config.vault_root,
        &ctx.clock,
        ctx.config.max_hlc_skew_ns,
    )?;
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
            let sender_hlc = Some(tick_server_hlc(ctx)?);
            return Ok(super::protocol::HeadState {
                protocol_version: super::protocol::PROTOCOL_VERSION,
                head_revision: *head_before.as_bytes(),
                head_sequence: sequence,
                eligibility_generation: generation_before,
                sender_hlc,
            });
        }
    }
    Err(super::protocol::RpcError::new(
        super::protocol::RpcErrorCode::Conflict,
        "workspace head advanced concurrently during O(1) QueryHead",
    ))
}

fn handle_query_metadata(
    ctx: &ActorContext,
    request: &super::protocol::QueryMetadataRequest,
) -> Result<super::protocol::VaultMetadata, super::protocol::RpcError> {
    let scope = parse_scope(&request.scope)?;
    let access = mneme_memory::Access::scopes([scope.clone()]);
    let workspace = open_read_only_vault(
        &ctx.config.vault_root,
        &ctx.clock,
        ctx.config.max_hlc_skew_ns,
    )?;
    let generation = workspace
        .eligibility_generation()
        .map_err(store_rpc_error)?;
    let requested = resolve_requested_revision(&workspace, request.revision, request.read_hlc)?;
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
    let sender_hlc = Some(tick_server_hlc(ctx)?);
    Ok(super::protocol::VaultMetadata {
        protocol_version: super::protocol::PROTOCOL_VERSION,
        requested_revision: *requested.as_bytes(),
        served_revision: *filtered.revision.as_bytes(),
        sequence: filtered.sequence,
        eligibility_generation: generation,
        scoped_record_count,
        max_limits: ctx.config.max_limits,
        sender_hlc,
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
    ctx: &ActorContext,
    request: &super::protocol::FetchPinnedSnapshotRequest,
) -> Result<super::protocol::PinnedSnapshotPayload, super::protocol::RpcError> {
    request.limits.check_within(&ctx.config.max_limits)?;
    let scope = parse_scope(&request.scope)?;
    let access = mneme_memory::Access::scopes([scope.clone()]);
    let workspace = open_read_only_vault(
        &ctx.config.vault_root,
        &ctx.clock,
        ctx.config.max_hlc_skew_ns,
    )?;
    let generation = workspace
        .eligibility_generation()
        .map_err(store_rpc_error)?;
    let requested = resolve_requested_revision(&workspace, request.revision, request.read_hlc)?;
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
    let sender_hlc = Some(tick_server_hlc(ctx)?);
    let payload = build_snapshot_payload_bounded(
        SnapshotPayloadInput {
            requested,
            generation,
            filtered,
            view_context,
            suppressions,
            current_sources,
            sender_hlc,
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
    sender_hlc: Option<super::protocol::WireHybridTimestamp>,
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
        sender_hlc,
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
        sender_hlc,
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

fn decode_ground_terms(
    term_documents: &[String],
) -> Result<Vec<mneme_core::Value>, super::protocol::RpcError> {
    let mut terms = Vec::with_capacity(term_documents.len());
    for entry in term_documents {
        let parsed = mneme_core::decode_document(entry).map_err(|diag| {
            super::protocol::RpcError::new(
                super::protocol::RpcErrorCode::InvalidInput,
                diag.to_string(),
            )
        })?;
        terms.push(parsed);
    }
    assert_eq!(terms.len(), term_documents.len());
    Ok(terms)
}

fn parse_bundle_document(
    bundle_document: &str,
) -> Result<mneme_datalog::RuleBundle, super::protocol::RpcError> {
    let bundle_value = mneme_core::decode_document(bundle_document).map_err(|diag| {
        super::protocol::RpcError::new(
            super::protocol::RpcErrorCode::InvalidInput,
            diag.to_string(),
        )
    })?;
    crate::parse_bundle(&bundle_value, &mneme_core::Path::root()).map_err(|error| {
        super::protocol::RpcError::new(super::protocol::RpcErrorCode::InvalidInput, error.message)
    })
}

fn bundle_calm_stratum(bundle: &mneme_datalog::RuleBundle) -> mneme_kernel::calm::CalmStratum {
    let has_non_monotonic = bundle.rules.iter().any(|rule| {
        rule.body.iter().any(|literal| {
            matches!(
                literal,
                mneme_datalog::Literal::Negative(_) | mneme_datalog::Literal::Aggregate { .. }
            )
        })
    });
    let op = if has_non_monotonic {
        mneme_kernel::calm::DistributedOp::NegatedFederatedDatalog
    } else {
        mneme_kernel::calm::DistributedOp::PositiveFederatedDatalog
    };
    mneme_kernel::calm::classify_op(op)
}

fn evaluate_calm_seal_facts(
    ctx: &ActorContext,
    scope: &str,
    generation: u64,
    served_revision: [u8; 16],
    seal: Option<&super::protocol::CalmSeal>,
) -> mneme_kernel::calm::CalmSealFacts {
    match seal {
        Some(calm_seal) => {
            let authorized_signers = ctx.authorizer.authorized_seal_signers();
            calm_seal.verify_facts(scope, generation, served_revision, &authorized_signers)
        }
        None => mneme_kernel::calm::CalmSealFacts {
            sealed: false,
            quorum_satisfied: false,
            epoch_matches: false,
        },
    }
}

fn handle_evaluate_datalog(
    ctx: &ActorContext,
    request: &super::protocol::EvaluateDatalogRequest,
) -> Result<super::protocol::RemoteDatalogResult, super::protocol::RpcError> {
    request.limits.check_within(&ctx.config.max_limits)?;
    let scope = parse_scope(&request.scope)?;
    let bundle = parse_bundle_document(&request.bundle_document)?;
    let stratum = bundle_calm_stratum(&bundle);
    let constants = decode_datalog_constants(&request.constant_documents)?;
    let datalog_limits = request.limits.to_datalog_limits()?;
    let max_result_rows = usize::try_from(request.max_rows).map_err(|_| {
        super::protocol::RpcError::new(
            super::protocol::RpcErrorCode::BudgetExceeded,
            "query row limit exceeds platform capacity",
        )
    })?;
    let incomplete_extents: std::collections::BTreeSet<String> =
        request.incomplete_extents.iter().cloned().collect();
    let mut workspace = open_read_only_vault(
        &ctx.config.vault_root,
        &ctx.clock,
        ctx.config.max_hlc_skew_ns,
    )?;
    let generation = workspace
        .eligibility_generation()
        .map_err(store_rpc_error)?;
    let revision = resolve_requested_revision(&workspace, request.revision, request.read_hlc)?;
    let allow_hlc_cut = request.read_hlc.is_some();
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
            at: request.at.map(mneme_core::Timestamp::from_nanos),
            incomplete_extents: incomplete_extents.clone(),
            stale_policy: request.stale_policy,
            allow_hlc_cut,
        },
    )?;
    verify_generation_unchanged(&workspace, generation, "remote Datalog evaluation")?;
    let barrier_seal = evaluate_calm_seal_facts(
        ctx,
        &request.scope,
        generation,
        *result.served_revision.as_bytes(),
        request.calm_seal.as_ref(),
    );
    let absence_established = mneme_kernel::calm::federated_absence_established(
        &mneme_kernel::calm::FederatedNegationFacts {
            local_absence_established: result.absence_established,
            stratum,
            is_federated: true,
            barrier_seal,
        },
    );
    let reason = if result.absence_established && !absence_established {
        result.reason.clone().or_else(|| {
            Some(
                "CALM barrier required: unsealed federated Stratum B negation cannot establish closed-world absence"
                    .to_owned(),
            )
        })
    } else {
        result.reason.clone()
    };
    let sender_hlc = Some(tick_server_hlc(ctx)?);
    let encoded = encode_datalog_result(
        &result,
        EncodedDatalogMetadata {
            at: request.at,
            incomplete_extents: incomplete_extents.into_iter().collect(),
            absence_established,
            reason,
            sender_hlc,
        },
    );
    check_payload_byte_budget(&encoded, request.limits.max_bytes, "Datalog result")?;
    assert_eq!(encoded.served_revision, *result.served_revision.as_bytes());
    assert_eq!(encoded.protocol_version, super::protocol::PROTOCOL_VERSION);
    Ok(encoded)
}

fn handle_explain_missing(
    ctx: &ActorContext,
    request: &super::protocol::ExplainMissingRpcRequest,
) -> Result<super::protocol::RemoteMissingExplanation, super::protocol::RpcError> {
    request.limits.check_within(&ctx.config.max_limits)?;
    request
        .explain_limits
        .check_within(&ctx.config.max_limits)?;
    let scope = parse_scope(&request.scope)?;
    let bundle = parse_bundle_document(&request.bundle_document)?;
    let terms = decode_ground_terms(&request.term_documents)?;
    let datalog_limits = request.limits.to_datalog_limits()?;
    let incomplete_extents: std::collections::BTreeSet<String> =
        request.incomplete_extents.iter().cloned().collect();
    let mut workspace = open_read_only_vault(
        &ctx.config.vault_root,
        &ctx.clock,
        ctx.config.max_hlc_skew_ns,
    )?;
    let generation = workspace
        .eligibility_generation()
        .map_err(store_rpc_error)?;
    let revision = resolve_requested_revision(&workspace, request.revision, request.read_hlc)?;
    let allow_stale = matches!(request.stale_policy, super::protocol::StalePolicy::Allow)
        || request.read_hlc.is_some();
    let access = mneme_memory::Access::scopes([scope.clone()]);
    let mut service = mneme_datalog::Service::new(&mut workspace);
    let build = service
        .build(mneme_datalog::BuildRequest {
            actor: "remote-federation-peer".to_owned(),
            scope,
            revision,
            bundle,
            limits: datalog_limits,
            publish: false,
            incomplete_extents: incomplete_extents.clone(),
            cancellation: None,
            access,
            at: request.at.map(mneme_core::Timestamp::from_nanos),
        })
        .map_err(datalog_rpc_error)?;
    let explanation = service
        .explain_missing_build(
            &build,
            mneme_datalog::ExplainMissingRequest {
                predicate: request.predicate.clone(),
                terms,
                limits: request.explain_limits.to_datalog_limits(),
                allow_stale,
                cancellation: None,
            },
        )
        .map_err(datalog_rpc_error)?;
    verify_generation_unchanged(&workspace, generation, "remote explain-missing")?;
    let sender_hlc = Some(tick_server_hlc(ctx)?);
    let encoded = encode_missing_explanation(
        &explanation,
        request.at,
        incomplete_extents.into_iter().collect(),
        sender_hlc,
    );
    check_payload_byte_budget(&encoded, request.limits.max_bytes, "explain-missing result")?;
    assert_eq!(
        encoded.served_revision,
        *explanation.served_revision.as_bytes()
    );
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
    at: Option<mneme_core::Timestamp>,
    incomplete_extents: std::collections::BTreeSet<String>,
    stale_policy: super::protocol::StalePolicy,
    allow_hlc_cut: bool,
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
            incomplete_extents: params.incomplete_extents,
            cancellation: None,
            access,
            at: params.at,
        })
        .map_err(datalog_rpc_error)?;
    let mut query = mneme_datalog::Query::all(params.predicate, params.query_limit);
    query.constants = params.constants;
    query.allow_stale =
        matches!(params.stale_policy, super::protocol::StalePolicy::Allow) || params.allow_hlc_cut;
    service
        .query_build(&build, query)
        .map_err(datalog_rpc_error)
}

fn encode_source_keys(
    sources: &std::collections::BTreeSet<mneme_datalog::SourceKey>,
) -> Vec<super::protocol::RemoteSourceKey> {
    sources
        .iter()
        .map(
            |(record_id, revision_id)| super::protocol::RemoteSourceKey {
                record_id: *record_id.as_bytes(),
                revision_id: *revision_id.as_bytes(),
            },
        )
        .collect()
}

fn encode_coverage(coverage: &[mneme_datalog::Coverage]) -> Vec<super::protocol::RemoteCoverage> {
    coverage
        .iter()
        .map(|entry| super::protocol::RemoteCoverage {
            predicate: entry.predicate.clone(),
            status: entry.status.name().to_owned(),
            reason: entry.reason.clone(),
        })
        .collect()
}

fn encode_premise(premise: &mneme_datalog::Premise) -> super::protocol::RemotePremise {
    super::protocol::RemotePremise {
        predicate: premise.predicate.clone(),
        term_documents: premise
            .terms
            .iter()
            .map(mneme_core::encode_document_string)
            .collect(),
        canonical: premise.canonical.map(|id| *id.as_bytes()),
        canonical_roots: premise
            .canonical_roots
            .iter()
            .map(|id| *id.as_bytes())
            .collect(),
        sources: encode_source_keys(&premise.sources),
        vault: premise.vault.clone(),
        vaults: premise.vaults.iter().cloned().collect(),
        absent: premise.absent,
        coverage: premise.coverage.clone(),
        source_availability: premise.source_availability.clone(),
        epistemic: premise.epistemic.name().to_owned(),
    }
}

fn encode_derivation(support: &mneme_datalog::Derivation) -> super::protocol::RemoteDerivation {
    super::protocol::RemoteDerivation {
        rule_id: support.rule_id.clone(),
        rule_version: support.rule_version.clone(),
        premises: support.premises.iter().map(encode_premise).collect(),
        sources: encode_source_keys(&support.sources),
        vaults: support.vaults.iter().cloned().collect(),
        temporal_parameters: support.temporal_parameters.clone(),
        truncated: support.truncated,
        epistemic: support.epistemic.name().to_owned(),
    }
}

struct EncodedDatalogMetadata {
    at: Option<i64>,
    incomplete_extents: Vec<String>,
    absence_established: bool,
    reason: Option<String>,
    sender_hlc: Option<super::protocol::WireHybridTimestamp>,
}

fn encode_datalog_result(
    result: &mneme_datalog::QueryResult,
    meta: EncodedDatalogMetadata,
) -> super::protocol::RemoteDatalogResult {
    super::protocol::RemoteDatalogResult {
        protocol_version: super::protocol::PROTOCOL_VERSION,
        relation: result.relation.clone(),
        status: result.status.name().to_owned(),
        requested_revision: *result.requested_revision.as_bytes(),
        served_revision: *result.served_revision.as_bytes(),
        eligibility_generation: result.context.eligibility_generation,
        at: meta.at,
        incomplete_extents: meta.incomplete_extents,
        coverage: encode_coverage(&result.coverage),
        rows: result
            .rows
            .iter()
            .map(|row| super::protocol::RemoteQueryRow {
                value_documents: row
                    .values
                    .iter()
                    .map(mneme_core::encode_document_string)
                    .collect(),
                supports: row.supports.iter().map(encode_derivation).collect(),
                support_truncated: row.support_truncated,
                epistemic: row.epistemic.name().to_owned(),
            })
            .collect(),
        exhaustive: result.exhaustive,
        truncated: result.truncated,
        absence_established: meta.absence_established,
        stale: result.stale,
        reason: meta.reason,
        work: result.work,
        sender_hlc: meta.sender_hlc,
    }
}

fn encode_missing_term(term: &mneme_datalog::Term) -> super::protocol::RemoteMissingTerm {
    match term {
        mneme_datalog::Term::Variable(name) => {
            super::protocol::RemoteMissingTerm::Variable(name.clone())
        }
        mneme_datalog::Term::Constant(value) => {
            super::protocol::RemoteMissingTerm::Constant(mneme_core::encode_document_string(value))
        }
    }
}

fn encode_missing_reason(
    reason: &mneme_datalog::MissingReason,
) -> super::protocol::RemoteMissingReason {
    super::protocol::RemoteMissingReason {
        kind: reason.kind.name().to_owned(),
        rule_id: reason.rule_id.clone(),
        predicate: reason.predicate.clone(),
        terms: reason.terms.iter().map(encode_missing_term).collect(),
        detail: reason.detail.clone(),
        blocker_epistemic: reason
            .blocker_epistemic
            .map(|status| status.name().to_owned()),
        blocker_supports: reason
            .blocker_supports
            .iter()
            .map(encode_derivation)
            .collect(),
        causes: reason.causes.iter().map(encode_missing_reason).collect(),
    }
}

fn encode_missing_explanation(
    explanation: &mneme_datalog::MissingExplanation,
    at: Option<i64>,
    incomplete_extents: Vec<String>,
    sender_hlc: Option<super::protocol::WireHybridTimestamp>,
) -> super::protocol::RemoteMissingExplanation {
    super::protocol::RemoteMissingExplanation {
        protocol_version: super::protocol::PROTOCOL_VERSION,
        predicate: explanation.predicate.clone(),
        term_documents: explanation
            .terms
            .iter()
            .map(mneme_core::encode_document_string)
            .collect(),
        status: explanation.status.name().to_owned(),
        build_status: explanation.build_status.name().to_owned(),
        requested_revision: *explanation.requested_revision.as_bytes(),
        served_revision: *explanation.served_revision.as_bytes(),
        eligibility_generation: explanation.context.eligibility_generation,
        at,
        incomplete_extents,
        coverage: encode_coverage(&explanation.coverage),
        present_epistemic: explanation
            .present_epistemic
            .map(|status| status.name().to_owned()),
        present_supports: explanation
            .present_supports
            .iter()
            .map(encode_derivation)
            .collect(),
        reasons: explanation
            .reasons
            .iter()
            .map(encode_missing_reason)
            .collect(),
        truncated: explanation.truncated,
        exhaustive: explanation.exhaustive,
        stale: explanation.stale,
        work: explanation.work,
        sender_hlc,
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
        mneme_store::Failure::ClockSkewExceeded(_) => {
            super::protocol::RpcErrorCode::ClockSkewExceeded
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
