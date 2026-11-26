//! Async Iroh sync node combining allowlisted blobs, control, discovery, and gossip.

#![allow(
    unknown_lints,
    assertion_density,
    path_segment_repetition,
    fragile_exhaustive_enum_match,
    unbounded_collection_growth,
    compound_condition
)] // returns typed Result failures instead of panicking; SyncNode* matches module domain; exhaustive match on closed control enum; max_pulls bounds pull_on_gossip output; compound checks verify receipt equivalence

use std::str::FromStr;

use n0_future::StreamExt;

/// Configuration for binding a [`SyncNode`].
#[derive(Clone, Debug)]
pub struct SyncNodeConfig {
    pub secret_key: iroh::SecretKey,
    pub allowlist: crate::trust::SharedAllowlist,
    pub discovery: crate::protocol::DiscoveryMode,
    pub relay: crate::protocol::RelayPreference,
    pub bind_addrs: Vec<std::net::SocketAddr>,
}

/// Factory constructing a fresh [`mneme_store::WorkspaceConfig`] per store open/restore.
pub type WorkspaceConfigFactory =
    std::sync::Arc<dyn Fn() -> mneme_store::WorkspaceConfig + Send + Sync>;

/// Request parameters for pulling a scope from an allowlisted peer.
pub struct PullRequest {
    pub peer: iroh::EndpointId,
    pub scope: mneme_core::ScopeId,
    pub destination: std::path::PathBuf,
    pub state_dir: Option<std::path::PathBuf>,
    pub workspace_config: WorkspaceConfigFactory,
}

/// Result of one verified pull from an allowlisted peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PullOutcome {
    pub disposition: crate::bundle::PullDisposition,
    pub snapshot: crate::protocol::VaultSnapshotInfo,
    pub local_revision: mneme_core::WorkspaceRevisionId,
    pub local_sequence: u64,
    pub verify_report: mneme_store::VerifyReport,
}

/// Active `iroh-gossip` subscription scoped to one vault's private topic.
pub struct VaultGossipTopic {
    vault_id: String,
    allowlist: crate::trust::SharedAllowlist,
    topic: iroh_gossip::GossipTopic,
}

impl VaultGossipTopic {
    /// Wait until at least one allowlisted neighbor is connected on the topic.
    pub async fn joined(&mut self) -> crate::error::Result<()> {
        self.topic
            .joined()
            .await
            .map_err(|error| crate::error::Failure::Protocol(format!("gossip join: {error}")))
    }

    /// Broadcast a lightweight `(vault_id, head_revision_digest, seq)` announcement.
    pub async fn broadcast_head(
        &mut self,
        info: &crate::protocol::VaultSnapshotInfo,
    ) -> crate::error::Result<()> {
        let announcement = info.to_announcement();
        let bytes = announcement.encode()?;
        self.topic
            .broadcast(bytes)
            .await
            .map_err(|error| crate::error::Failure::Protocol(format!("gossip broadcast: {error}")))
    }

    /// Receive the next authorized, well-formed [`crate::protocol::HeadAnnouncement`].
    ///
    /// Unauthorized senders and mismatched `vault_id` payloads are ignored
    /// without mutating local state.
    pub async fn next_announcement(
        &mut self,
    ) -> crate::error::Result<Option<(iroh::EndpointId, crate::protocol::HeadAnnouncement)>> {
        while let Some(item) = self.topic.next().await {
            let event = item.map_err(|error| {
                crate::error::Failure::Protocol(format!("gossip stream: {error}"))
            })?;
            let iroh_gossip::Event::Received(message) = event else {
                continue;
            };
            let Ok(announcement) = crate::protocol::HeadAnnouncement::decode(&message.content)
            else {
                continue;
            };
            if announcement.vault_id != self.vault_id {
                continue;
            }
            let Ok(scope) = crate::protocol::parse_scope_id(&announcement.scope) else {
                continue;
            };
            if !self.allowlist.allows_scope(message.delivered_from, &scope) {
                continue;
            }
            return Ok(Some((message.delivered_from, announcement)));
        }
        Ok(None)
    }
}

/// Peer-to-peer Mneme sync node running over Iroh QUIC.
#[derive(Clone, Debug)]
pub struct SyncNode {
    endpoint: iroh::Endpoint,
    router: iroh::protocol::Router,
    blobs: iroh_blobs::store::mem::MemStore,
    gossip: iroh_gossip::Gossip,
    memory_lookup: iroh::address_lookup::memory::MemoryLookup,
    allowlist: crate::trust::SharedAllowlist,
    published: crate::protocol::PublishedScopes,
}

impl SyncNode {
    /// Bind an Iroh endpoint and start the allowlisted blobs, gossip, and control protocols.
    pub async fn bind(config: SyncNodeConfig) -> crate::error::Result<Self> {
        let memory_lookup = iroh::address_lookup::memory::MemoryLookup::new();
        let mut builder = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(config.secret_key)
            .relay_mode(config.relay.into_iroh())
            .address_lookup(memory_lookup.clone());

        if matches!(
            config.discovery,
            crate::protocol::DiscoveryMode::MdnsOnly | crate::protocol::DiscoveryMode::MdnsAndDht
        ) {
            builder =
                builder.address_lookup(iroh_mdns_address_lookup::MdnsAddressLookup::builder());
        }
        if config.discovery == crate::protocol::DiscoveryMode::MdnsAndDht {
            builder =
                builder.address_lookup(iroh_mainline_address_lookup::DhtAddressLookup::builder());
        }
        for addr in config.bind_addrs {
            builder = builder.bind_addr(addr).map_err(|error| {
                crate::error::Failure::InvalidConfig(format!("invalid bind addr: {error}"))
            })?;
        }

        let endpoint = builder
            .bind()
            .await
            .map_err(|error| crate::error::Failure::Transport(format!("endpoint bind: {error}")))?;

        let blobs = iroh_blobs::store::mem::MemStore::new();
        let gossip = iroh_gossip::Gossip::builder().spawn(endpoint.clone());
        let published: crate::protocol::PublishedScopes =
            std::sync::Arc::new(std::sync::RwLock::new(std::collections::BTreeMap::new()));

        let blobs_handler = crate::protocol::AllowlistedProtocol::new(
            config.allowlist.clone(),
            iroh_blobs::BlobsProtocol::new(&blobs, None),
        );
        let gossip_handler =
            crate::protocol::AllowlistedProtocol::new(config.allowlist.clone(), gossip.clone());
        let control_handler = crate::protocol::AllowlistedProtocol::new(
            config.allowlist.clone(),
            crate::protocol::SyncControlHandler::new(config.allowlist.clone(), published.clone()),
        );

        let router = iroh::protocol::Router::builder(endpoint.clone())
            .accept(iroh_blobs::ALPN, blobs_handler)
            .accept(iroh_gossip::ALPN, gossip_handler)
            .accept(crate::protocol::SYNC_CONTROL_ALPN, control_handler)
            .spawn();

        Ok(Self {
            endpoint,
            router,
            blobs,
            gossip,
            memory_lookup,
            allowlist: config.allowlist,
            published,
        })
    }

    /// Return this node's Ed25519 identity.
    pub fn node_id(&self) -> iroh::EndpointId {
        self.endpoint.id()
    }

    /// Return this node's current socket/relay address information.
    pub fn addr(&self) -> iroh::EndpointAddr {
        self.endpoint.addr()
    }

    /// Register a peer's explicit address in local memory lookup without granting trust.
    pub fn add_peer_addr(&self, addr: iroh::EndpointAddr) {
        self.memory_lookup.add_endpoint_info(addr);
    }

    /// Access the live peer allowlist.
    pub const fn allowlist(&self) -> &crate::trust::SharedAllowlist {
        &self.allowlist
    }

    /// Access the underlying Iroh endpoint (for address lookup or diagnostics).
    pub const fn endpoint(&self) -> &iroh::Endpoint {
        &self.endpoint
    }

    /// Export `scope` from `workspace` and publish its bundle and blobs for allowlisted peers.
    pub async fn publish_workspace(
        &self,
        workspace: &mneme_store::Workspace,
        vault_id: &str,
        scope: &mneme_core::ScopeId,
    ) -> crate::error::Result<crate::protocol::VaultSnapshotInfo> {
        let exported =
            crate::bundle::export_scope_to_store(workspace, vault_id, scope, &self.blobs).await?;
        let mut guard = self.published.write().map_err(|_| {
            crate::error::Failure::InvalidConfig("published scopes lock poisoned".to_owned())
        })?;
        guard.insert(scope.clone(), exported.info.clone());
        Ok(exported.info)
    }

    /// Subscribe to the private `iroh-gossip` topic derived from `vault_id`.
    ///
    /// Every bootstrap peer MUST already be in [`PeerAllowlist`].
    pub async fn subscribe_gossip(
        &self,
        vault_id: &str,
        bootstrap: Vec<iroh::EndpointId>,
    ) -> crate::error::Result<VaultGossipTopic> {
        for peer in &bootstrap {
            if !self.allowlist.is_allowed(*peer) {
                return Err(crate::error::Failure::UnauthorizedPeer(peer.to_string()));
            }
        }
        let topic_id = crate::state::topic_id_for_vault(vault_id);
        let topic = self
            .gossip
            .subscribe(topic_id, bootstrap)
            .await
            .map_err(|error| {
                crate::error::Failure::Protocol(format!("gossip subscribe: {error}"))
            })?;
        Ok(VaultGossipTopic {
            vault_id: vault_id.to_owned(),
            allowlist: self.allowlist.clone(),
            topic,
        })
    }

    /// Query `peer` over [`crate::protocol::SYNC_CONTROL_ALPN`] for `scope`'s current head.
    pub async fn fetch_vault_head(
        &self,
        peer: iroh::EndpointId,
        scope: &mneme_core::ScopeId,
    ) -> crate::error::Result<crate::protocol::VaultSnapshotInfo> {
        self.require_peer_scope(peer, scope)?;
        let conn = self
            .endpoint
            .connect(peer, crate::protocol::SYNC_CONTROL_ALPN)
            .await
            .map_err(|error| {
                crate::error::Failure::Transport(format!("connect control to {peer}: {error}"))
            })?;
        let (mut send, mut recv) = conn.open_bi().await.map_err(|error| {
            crate::error::Failure::Transport(format!("open control stream: {error}"))
        })?;
        let req = crate::protocol::SyncControlRequest::GetVaultHead {
            scope: scope.to_string(),
        };
        let encoded = serde_json::to_vec(&req).map_err(|error| {
            crate::error::Failure::Protocol(format!("encode control request: {error}"))
        })?;
        send.write_all(&encoded)
            .await
            .map_err(|error| crate::error::Failure::Transport(format!("write control: {error}")))?;
        send.finish().map_err(|error| {
            crate::error::Failure::Transport(format!("finish control write: {error}"))
        })?;
        let response_bytes = recv
            .read_to_end(crate::protocol::MAX_CONTROL_MESSAGE_BYTES)
            .await
            .map_err(|error| crate::error::Failure::Transport(format!("read control: {error}")))?;
        let response: crate::protocol::SyncControlResponse =
            serde_json::from_slice(&response_bytes).map_err(|error| {
                crate::error::Failure::Protocol(format!("decode control response: {error}"))
            })?;
        match response {
            crate::protocol::SyncControlResponse::VaultHead(info) => Ok(*info),
            crate::protocol::SyncControlResponse::Refused { reason } => {
                Err(crate::error::Failure::Protocol(format!(
                    "peer {peer} refused sync head request: {reason}"
                )))
            }
        }
    }

    /// Pull `request.scope` from `request.peer`, verify over `iroh-blobs`, and ingest/verify locally.
    pub async fn pull_scope(&self, request: PullRequest) -> crate::error::Result<PullOutcome> {
        self.require_peer_scope(request.peer, &request.scope)?;
        let snapshot = self.fetch_vault_head(request.peer, &request.scope).await?;
        validate_snapshot_info(&snapshot, &request.scope)?;

        if let Some(outcome) = self.try_idempotent_fast_path(&request, &snapshot)? {
            return Ok(outcome);
        }

        let bundle_hash = snapshot.parsed_bundle_hash()?;
        self.download_verified_blobs(request.peer, bundle_hash, &snapshot.blobs)
            .await?;

        let temp_dir = tempfile::tempdir()
            .map_err(|error| crate::error::Failure::Io(format!("pull tempdir: {error}")))?;
        let archive_path = temp_dir.path().join("pulled.mneme");
        self.blobs
            .blobs()
            .export(bundle_hash, &archive_path)
            .await
            .map_err(|error| {
                crate::error::Failure::Transport(format!("export fetched bundle: {error}"))
            })?;

        let destination = request.destination.clone();
        let workspace_config = (request.workspace_config)();
        let ingested = tokio::task::spawn_blocking(move || {
            crate::bundle::ingest_downloaded_archive(&archive_path, &destination, workspace_config)
        })
        .await
        .map_err(|error| crate::error::Failure::Io(format!("ingest task join: {error}")))??;

        if let Some(state_dir) = &request.state_dir {
            record_pull_receipt(state_dir, &request, &snapshot, ingested.local_sequence)?;
        }

        Ok(PullOutcome {
            disposition: ingested.disposition,
            snapshot,
            local_revision: ingested.local_revision,
            local_sequence: ingested.local_sequence,
            verify_report: ingested.verify_report,
        })
    }

    /// Listen on `topic` for newer head announcements and pull + verify from the announcing peer.
    ///
    /// Stops after `max_pulls` successful pulls when `max_pulls` is `Some`.
    pub async fn pull_on_gossip(
        &self,
        topic: &mut VaultGossipTopic,
        destination: &std::path::Path,
        state_dir: Option<&std::path::Path>,
        workspace_config: WorkspaceConfigFactory,
        max_pulls: Option<u64>,
    ) -> crate::error::Result<Vec<PullOutcome>> {
        let mut outcomes = Vec::new();
        while let Some((sender, announcement)) = topic.next_announcement().await? {
            let scope = crate::protocol::parse_scope_id(&announcement.scope)?;
            let outcome = self
                .pull_scope(PullRequest {
                    peer: sender,
                    scope,
                    destination: destination.to_path_buf(),
                    state_dir: state_dir.map(std::path::Path::to_path_buf),
                    workspace_config: std::sync::Arc::clone(&workspace_config),
                })
                .await?;
            outcomes.push(outcome);
            if let Some(limit) = max_pulls
                && (outcomes.len() as u64) >= limit
            {
                break;
            }
        }
        Ok(outcomes)
    }

    /// Gracefully shut down the router, gossip actor, blob store, and endpoint.
    pub async fn shutdown(self) -> crate::error::Result<()> {
        self.router
            .shutdown()
            .await
            .map_err(|error| crate::error::Failure::Transport(format!("router shutdown: {error}")))
    }

    fn require_peer_scope(
        &self,
        peer: iroh::EndpointId,
        scope: &mneme_core::ScopeId,
    ) -> crate::error::Result<()> {
        if !self.allowlist.is_allowed(peer) {
            return Err(crate::error::Failure::UnauthorizedPeer(peer.to_string()));
        }
        if !self.allowlist.allows_scope(peer, scope) {
            return Err(crate::error::Failure::ScopeDenied {
                peer: peer.to_string(),
                scope: scope.to_string(),
            });
        }
        Ok(())
    }

    fn try_idempotent_fast_path(
        &self,
        request: &PullRequest,
        snapshot: &crate::protocol::VaultSnapshotInfo,
    ) -> crate::error::Result<Option<PullOutcome>> {
        let Some(state_dir) = &request.state_dir else {
            return Ok(None);
        };
        if !request.destination.is_dir() {
            return Ok(None);
        }
        let paths = crate::state::SyncPaths::new(state_dir);
        let state = crate::state::SyncState::load(&paths.state_path())?;
        let Some(receipt) = state.receipt_for(&snapshot.vault_id, &request.scope, request.peer)
        else {
            return Ok(None);
        };
        if receipt.remote_revision != snapshot.head_revision
            || receipt.remote_revision_digest != snapshot.head_revision_digest.hex
            || receipt.remote_sequence != snapshot.sequence
            || receipt.bundle_hash != snapshot.bundle_hash
        {
            return Ok(None);
        }
        let verify_report =
            mneme_store::verify_workspace(&request.destination, mneme_store::VerifyMode::Full)?;
        if !verify_report.is_healthy() {
            return Err(crate::error::Failure::VerificationFailed(format!(
                "{} integrity issues reported by verify_workspace",
                verify_report.issues.len()
            )));
        }
        let workspace =
            mneme_store::Workspace::open(&request.destination, (request.workspace_config)())?;
        Ok(Some(PullOutcome {
            disposition: crate::bundle::PullDisposition::AlreadyUpToDate,
            snapshot: snapshot.clone(),
            local_revision: workspace.current_revision()?,
            local_sequence: workspace.current_sequence()?,
            verify_report,
        }))
    }

    async fn download_verified_blobs(
        &self,
        peer: iroh::EndpointId,
        bundle_hash: iroh_blobs::Hash,
        blobs: &[crate::protocol::BlobDigestRef],
    ) -> crate::error::Result<()> {
        let conn = self
            .endpoint
            .connect(peer, iroh_blobs::ALPN)
            .await
            .map_err(|error| {
                crate::error::Failure::Transport(format!("connect blobs to {peer}: {error}"))
            })?;
        let _stats = self
            .blobs
            .remote()
            .fetch(conn.clone(), bundle_hash)
            .await
            .map_err(|error| {
                crate::error::Failure::Transport(format!("fetch bundle {bundle_hash}: {error}"))
            })?;

        for blob_ref in blobs {
            let expected_digest = blob_ref.content_digest.to_digest()?;
            let transport_hash =
                iroh_blobs::Hash::from_str(&blob_ref.transport_hash).map_err(|error| {
                    crate::error::Failure::Protocol(format!("invalid blob hash: {error}"))
                })?;
            let _blob_stats = self
                .blobs
                .remote()
                .fetch(conn.clone(), transport_hash)
                .await
                .map_err(|error| {
                    crate::error::Failure::Transport(format!(
                        "fetch blob {transport_hash}: {error}"
                    ))
                })?;
            let bytes = self
                .blobs
                .blobs()
                .get_bytes(transport_hash)
                .await
                .map_err(|error| {
                    crate::error::Failure::Transport(format!("read fetched blob: {error}"))
                })?;
            if bytes.len() as u64 != blob_ref.byte_length
                || mneme_core::ContentDigest::of_source_bytes_with(
                    &bytes,
                    expected_digest.algorithm(),
                ) != expected_digest
            {
                return Err(crate::error::Failure::VerificationFailed(format!(
                    "downloaded blob {} failed Mneme digest verification",
                    expected_digest.to_hex()
                )));
            }
        }
        Ok(())
    }
}

fn validate_snapshot_info(
    snapshot: &crate::protocol::VaultSnapshotInfo,
    expected_scope: &mneme_core::ScopeId,
) -> crate::error::Result<()> {
    if snapshot.parsed_scope()? != *expected_scope {
        return Err(crate::error::Failure::Protocol(format!(
            "peer served scope {} instead of {}",
            snapshot.scope, expected_scope
        )));
    }
    if snapshot.bundle_bytes > crate::protocol::MAX_SYNC_BUNDLE_BYTES {
        return Err(crate::error::Failure::SizeLimitExceeded {
            actual_bytes: snapshot.bundle_bytes,
            limit_bytes: crate::protocol::MAX_SYNC_BUNDLE_BYTES,
        });
    }
    let _ =
        mneme_core::WorkspaceRevisionId::from_hex(&snapshot.head_revision).map_err(|reason| {
            crate::error::Failure::Protocol(format!("invalid peer head revision: {reason}"))
        })?;
    let _ = snapshot.head_revision_digest.to_digest()?;
    let _ = snapshot.parsed_bundle_hash()?;
    Ok(())
}

fn record_pull_receipt(
    state_dir: &std::path::Path,
    request: &PullRequest,
    snapshot: &crate::protocol::VaultSnapshotInfo,
    local_sequence: u64,
) -> crate::error::Result<()> {
    let paths = crate::state::SyncPaths::new(state_dir);
    let mut state = crate::state::SyncState::load(&paths.state_path())?;
    state.record_receipt(crate::state::SyncReceipt {
        vault_id: snapshot.vault_id.clone(),
        scope: request.scope.to_string(),
        peer: request.peer.to_string(),
        remote_revision: snapshot.head_revision.clone(),
        remote_revision_digest: snapshot.head_revision_digest.hex.clone(),
        remote_sequence: snapshot.sequence,
        bundle_hash: snapshot.bundle_hash.clone(),
        local_sequence,
    });
    state.save(&paths.state_path())
}
