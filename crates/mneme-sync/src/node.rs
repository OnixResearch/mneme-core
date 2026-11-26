//! Async Iroh sync node combining allowlisted blobs, control, discovery, RBSR, and gossip.

#![allow(
    unknown_lints,
    assertion_density,
    path_segment_repetition,
    fragile_exhaustive_enum_match,
    unbounded_collection_growth,
    compound_condition,
    allocation_in_loop
)] // returns typed Result failures instead of panicking; SyncNode* matches module domain; exhaustive match on closed control enum; max_pulls and chunking bound allocations; compound checks verify receipt equivalence

use std::str::FromStr;

use n0_future::StreamExt;

/// Configuration for binding a [`SyncNode`].
#[derive(Clone)]
pub struct SyncNodeConfig {
    pub secret_key: iroh::SecretKey,
    pub allowlist: crate::trust::SharedAllowlist,
    pub revocations: crate::capability::SharedRevocationSet,
    pub trusted_roots: std::collections::BTreeSet<iroh::EndpointId>,
    pub clock: std::sync::Arc<dyn mneme_store::Clock>,
    pub discovery: crate::protocol::DiscoveryMode,
    pub relay: crate::protocol::RelayPreference,
    pub bind_addrs: Vec<std::net::SocketAddr>,
}

impl std::fmt::Debug for SyncNodeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncNodeConfig")
            .field("node_id", &self.secret_key.public())
            .field("trusted_roots_count", &self.trusted_roots.len())
            .field("discovery", &self.discovery)
            .field("relay", &self.relay)
            .field("bind_addrs", &self.bind_addrs)
            .finish()
    }
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

/// Telemetry describing RBSR control exchange and `iroh-blobs` transfers during one pull.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncTransferStats {
    pub rbsr_rounds: u64,
    pub control_bytes_sent: u64,
    pub control_bytes_received: u64,
    pub rbsr_remote_only_items: u64,
    pub rbsr_local_only_items: u64,
    pub blobs_fetched: u64,
    pub blob_bytes_fetched: u64,
}

/// Result of one verified pull from an allowlisted peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PullOutcome {
    pub disposition: crate::bundle::PullDisposition,
    pub snapshot: crate::protocol::VaultSnapshotInfo,
    pub local_revision: mneme_core::WorkspaceRevisionId,
    pub local_sequence: u64,
    pub verify_report: mneme_store::VerifyReport,
    pub stats: SyncTransferStats,
}

/// Active `iroh-gossip` subscription scoped to one vault's private topic.
pub struct VaultGossipTopic {
    vault_id: String,
    allowlist: crate::trust::SharedAllowlist,
    revocations: crate::capability::SharedRevocationSet,
    trusted_roots: std::collections::BTreeSet<iroh::EndpointId>,
    leases: crate::capability::SharedCapabilityLeases,
    clock: std::sync::Arc<dyn mneme_store::Clock>,
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

    /// Broadcast a signed [`crate::capability::RevocationTombstone`] over the vault topic.
    pub async fn broadcast_revocation(
        &mut self,
        tombstone: &crate::capability::RevocationTombstone,
    ) -> crate::error::Result<()> {
        tombstone.verify_signature()?;
        let encoded = serde_json::to_vec(tombstone).map_err(|error| {
            crate::error::Failure::Protocol(format!("encode revocation gossip: {error}"))
        })?;
        if encoded.len() > crate::protocol::MAX_GOSSIP_MESSAGE_BYTES {
            return Err(crate::error::Failure::SizeLimitExceeded {
                actual_bytes: encoded.len() as u64,
                limit_bytes: crate::protocol::MAX_GOSSIP_MESSAGE_BYTES as u64,
            });
        }
        self.topic
            .broadcast(bytes::Bytes::from(encoded))
            .await
            .map_err(|error| {
                crate::error::Failure::Protocol(format!("gossip revocation broadcast: {error}"))
            })
    }

    /// Receive the next authorized, well-formed [`crate::protocol::HeadAnnouncement`].
    ///
    /// Signed revocation tombstones received on the topic are verified and
    /// merged into the node's [`crate::capability::SharedRevocationSet`].
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
            if message.content.len() <= crate::protocol::MAX_GOSSIP_MESSAGE_BYTES
                && let Ok(tombstone) = serde_json::from_slice::<
                    crate::capability::RevocationTombstone,
                >(&message.content)
                && tombstone.vault_id == self.vault_id
                && tombstone.verify_signature().is_ok()
            {
                if let Err(error) = self.revocations.insert(tombstone) {
                    tracing::debug!(%error, "ignoring conflicting gossip revocation");
                }
                continue;
            }
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
            if !self.is_sender_authorized(message.delivered_from, &scope) {
                continue;
            }
            return Ok(Some((message.delivered_from, announcement)));
        }
        Ok(None)
    }

    fn is_sender_authorized(&self, sender: iroh::EndpointId, scope: &mneme_core::ScopeId) -> bool {
        if self.allowlist.allows_scope(sender, scope) {
            return true;
        }
        let Ok(now_secs) = crate::capability::timestamp_to_epoch_secs(self.clock.now()) else {
            return false;
        };
        self.leases
            .permits_scope(&crate::capability::LeaseScopeQuery {
                peer: sender,
                scope,
                required: crate::capability::CapabilityAuthority::SyncPull,
                now_secs,
                trusted_roots: &self.trusted_roots,
                revocations: &self.revocations,
            })
    }
}

/// Peer-to-peer Mneme sync node running over Iroh QUIC.
#[derive(Clone)]
pub struct SyncNode {
    endpoint: iroh::Endpoint,
    router: iroh::protocol::Router,
    blobs: iroh_blobs::store::mem::MemStore,
    gossip: iroh_gossip::Gossip,
    memory_lookup: iroh::address_lookup::memory::MemoryLookup,
    allowlist: crate::trust::SharedAllowlist,
    revocations: crate::capability::SharedRevocationSet,
    trusted_roots: std::collections::BTreeSet<iroh::EndpointId>,
    leases: crate::capability::SharedCapabilityLeases,
    clock: std::sync::Arc<dyn mneme_store::Clock>,
    scopes: crate::protocol::SharedScopeTable,
}

impl std::fmt::Debug for SyncNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncNode")
            .field("node_id", &self.endpoint.id())
            .finish()
    }
}

impl SyncNode {
    /// Bind an Iroh endpoint and start capability-enforced blobs, gossip, and control protocols.
    pub async fn bind(config: SyncNodeConfig) -> crate::error::Result<Self> {
        let memory_lookup = iroh::address_lookup::memory::MemoryLookup::new();
        let mut trusted_roots = config.trusted_roots.clone();
        trusted_roots.insert(config.secret_key.public());
        let endpoint = bind_iroh_endpoint(&config, &memory_lookup).await?;

        let blobs = iroh_blobs::store::mem::MemStore::new();
        let gossip = iroh_gossip::Gossip::builder().spawn(endpoint.clone());
        let scopes: crate::protocol::SharedScopeTable = std::sync::Arc::new(
            std::sync::RwLock::new(crate::protocol::SyncScopeTable::new()),
        );
        let leases = crate::capability::SharedCapabilityLeases::new();
        let auth = crate::protocol::CapabilityAuthorizer {
            allowlist: config.allowlist.clone(),
            leases: leases.clone(),
            trusted_roots: trusted_roots.clone(),
            revocations: config.revocations.clone(),
            clock: std::sync::Arc::clone(&config.clock),
        };

        let blobs_handler = crate::protocol::CapabilityProtocol::new(
            auth.clone(),
            crate::capability::CapabilityAuthority::SyncPull,
            iroh_blobs::BlobsProtocol::new(&blobs, None),
        );
        let gossip_handler = crate::protocol::CapabilityProtocol::new(
            auth.clone(),
            crate::capability::CapabilityAuthority::SyncPull,
            gossip.clone(),
        );
        let control_handler = crate::protocol::SyncControlHandler::new(auth, scopes.clone());

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
            revocations: config.revocations,
            trusted_roots,
            leases,
            clock: config.clock,
            scopes,
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

    /// Access the live convergent revocation set.
    pub const fn revocations(&self) -> &crate::capability::SharedRevocationSet {
        &self.revocations
    }

    /// Access the configured trusted root capability issuers.
    pub const fn trusted_roots(&self) -> &std::collections::BTreeSet<iroh::EndpointId> {
        &self.trusted_roots
    }

    /// Access the underlying Iroh endpoint (for address lookup or diagnostics).
    pub const fn endpoint(&self) -> &iroh::Endpoint {
        &self.endpoint
    }

    /// Return the most recent authorized `PushHead` announcement received for `scope`.
    pub fn last_pushed_head(
        &self,
        scope: &mneme_core::ScopeId,
    ) -> Option<crate::protocol::HeadAnnouncement> {
        self.scopes
            .read()
            .ok()
            .and_then(|guard| guard.received_pushes.get(scope).cloned())
    }

    /// Export `scope` from `workspace` and publish its bundle, blobs, and RBSR index.
    pub async fn publish_workspace(
        &self,
        workspace: &mneme_store::Workspace,
        vault_id: &str,
        scope: &mneme_core::ScopeId,
    ) -> crate::error::Result<crate::protocol::VaultSnapshotInfo> {
        let exported =
            crate::bundle::export_scope_to_store(workspace, vault_id, scope, &self.blobs).await?;
        let entry = std::sync::Arc::new(crate::protocol::PublishedScopeEntry {
            info: exported.info.clone(),
            rbsr_set: exported.rbsr_set,
            revisions: exported.revisions,
            blobs_by_digest: exported.blobs_by_digest,
        });
        let mut guard = self.scopes.write().map_err(|_| {
            crate::error::Failure::InvalidConfig("published scopes lock poisoned".to_owned())
        })?;
        guard.published.insert(scope.clone(), entry);
        Ok(exported.info)
    }

    /// Subscribe to the private `iroh-gossip` topic derived from `vault_id`.
    ///
    /// Every bootstrap peer MUST already be in [`crate::trust::PeerAllowlist`].
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
            revocations: self.revocations.clone(),
            trusted_roots: self.trusted_roots.clone(),
            leases: self.leases.clone(),
            clock: std::sync::Arc::clone(&self.clock),
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
        let conn = self.connect_control(peer).await?;
        let (info, _sent, _recv) = fetch_vault_head_on_conn(&conn, peer, scope, None).await?;
        conn.close(0_u32.into(), b"done");
        Ok(info)
    }

    /// Run bounded RBSR set reconciliation against `peer` over [`crate::protocol::SYNC_CONTROL_ALPN`].
    pub async fn reconcile_scope(
        &self,
        peer: iroh::EndpointId,
        scope: &mneme_core::ScopeId,
        snapshot_revision: &str,
        local_set: &crate::rbsr::RbsrSet,
    ) -> crate::error::Result<crate::rbsr::RbsrOutcome> {
        self.require_peer_scope(peer, scope)?;
        let conn = self.connect_control(peer).await?;
        let (outcome, _sent, _recv) =
            reconcile_on_conn(&conn, peer, scope, snapshot_revision, local_set, None).await?;
        conn.close(0_u32.into(), b"done");
        Ok(outcome)
    }

    /// Query `peer` for `scope`'s head using a signed, attenuated [`crate::capability::CapabilityToken`].
    pub async fn fetch_vault_head_with_capability(
        &self,
        peer: iroh::EndpointId,
        scope: &mneme_core::ScopeId,
        vault_id: &str,
        capability: &crate::capability::CapabilityToken,
    ) -> crate::error::Result<crate::protocol::VaultSnapshotInfo> {
        self.precheck_local_capability(
            capability,
            vault_id,
            scope,
            crate::capability::CapabilityAuthority::ReadOnly,
        )?;
        let response = self
            .send_control_request(
                peer,
                &crate::protocol::SyncControlRequest::GetVaultHead {
                    scope: scope.to_string(),
                    capability: Some(capability.clone()),
                },
            )
            .await?;
        match response {
            crate::protocol::SyncControlResponse::VaultHead(info) => {
                if info.vault_id != vault_id {
                    return Err(crate::error::Failure::Protocol(format!(
                        "peer served vault '{}' instead of '{}'",
                        info.vault_id, vault_id
                    )));
                }
                Ok(*info)
            }
            other => Err(unexpected_control_response(peer, other)),
        }
    }

    /// Pull `request.scope` from `request.peer`, isolate delta via RBSR, and ingest/verify locally.
    pub async fn pull_scope(&self, request: PullRequest) -> crate::error::Result<PullOutcome> {
        self.require_peer_scope(request.peer, &request.scope)?;
        let conn = self.connect_control(request.peer).await?;
        let (snapshot, head_sent, head_recv) =
            fetch_vault_head_on_conn(&conn, request.peer, &request.scope, None).await?;
        self.finish_pull_with_snapshot(
            conn,
            request,
            snapshot,
            SyncTransferStats {
                control_bytes_sent: head_sent,
                control_bytes_received: head_recv,
                ..SyncTransferStats::default()
            },
            None,
        )
        .await
    }

    /// Pull `request.scope` from `request.peer` using an offline-verifiable [`crate::capability::CapabilityToken`].
    pub async fn pull_scope_with_capability(
        &self,
        request: PullRequest,
        vault_id: &str,
        capability: &crate::capability::CapabilityToken,
    ) -> crate::error::Result<PullOutcome> {
        self.precheck_local_capability(
            capability,
            vault_id,
            &request.scope,
            crate::capability::CapabilityAuthority::SyncPull,
        )?;
        let conn = self.connect_control(request.peer).await?;
        let (snapshot, head_sent, head_recv) =
            fetch_vault_head_on_conn(&conn, request.peer, &request.scope, Some(capability)).await?;
        if snapshot.vault_id != vault_id {
            conn.close(0_u32.into(), b"wrong-vault");
            return Err(crate::error::Failure::Protocol(format!(
                "peer served vault '{}' instead of '{}'",
                snapshot.vault_id, vault_id
            )));
        }
        self.finish_pull_with_snapshot(
            conn,
            request,
            snapshot,
            SyncTransferStats {
                control_bytes_sent: head_sent,
                control_bytes_received: head_recv,
                ..SyncTransferStats::default()
            },
            Some(capability),
        )
        .await
    }

    /// Push a signed head announcement to `peer` using a `SyncPush` capability token.
    pub async fn push_head_with_capability(
        &self,
        peer: iroh::EndpointId,
        announcement: &crate::protocol::HeadAnnouncement,
        capability: &crate::capability::CapabilityToken,
    ) -> crate::error::Result<()> {
        let scope = crate::protocol::parse_scope_id(&announcement.scope)?;
        self.precheck_local_capability(
            capability,
            &announcement.vault_id,
            &scope,
            crate::capability::CapabilityAuthority::SyncPush,
        )?;
        let response = self
            .send_control_request(
                peer,
                &crate::protocol::SyncControlRequest::PushHead {
                    announcement: announcement.clone(),
                    capability: Some(capability.clone()),
                },
            )
            .await?;
        match response {
            crate::protocol::SyncControlResponse::HeadAccepted { .. } => Ok(()),
            other => Err(unexpected_control_response(peer, other)),
        }
    }

    /// Exchange and deterministically merge CRDT revocation tombstones with `peer`.
    pub async fn sync_revocations(
        &self,
        peer: iroh::EndpointId,
        capability: Option<&crate::capability::CapabilityToken>,
    ) -> crate::error::Result<u64> {
        if !self.allowlist.is_allowed(peer) && capability.is_none() {
            return Err(crate::error::Failure::UnauthorizedPeer(peer.to_string()));
        }
        let local = self.revocations.snapshot()?;
        let response = self
            .send_control_request(
                peer,
                &crate::protocol::SyncControlRequest::SyncRevocations {
                    revocations: local.tombstones().cloned().collect(),
                    capability: capability.cloned(),
                },
            )
            .await?;
        match response {
            crate::protocol::SyncControlResponse::Revocations { revocations } => {
                self.revocations.merge_tombstones(&revocations)
            }
            other => Err(unexpected_control_response(peer, other)),
        }
    }

    async fn finish_pull_with_snapshot(
        &self,
        conn: iroh::endpoint::Connection,
        request: PullRequest,
        snapshot: crate::protocol::VaultSnapshotInfo,
        stats: SyncTransferStats,
        capability: Option<&crate::capability::CapabilityToken>,
    ) -> crate::error::Result<PullOutcome> {
        validate_snapshot_info(&snapshot, &request.scope)?;

        if let Some(outcome) = self.try_idempotent_fast_path(&request, &snapshot, stats)? {
            conn.close(0_u32.into(), b"done");
            return Ok(outcome);
        }

        let local_sequence = local_workspace_sequence(&request)?;
        let Some(local_seq) = local_sequence.filter(|seq| *seq > 0) else {
            conn.close(0_u32.into(), b"done");
            return self.pull_full_restore(request, snapshot, stats).await;
        };
        let _ = local_seq;

        self.pull_delta_over_rbsr(conn, request, snapshot, stats, capability)
            .await
    }

    async fn pull_delta_over_rbsr(
        &self,
        conn: iroh::endpoint::Connection,
        request: PullRequest,
        snapshot: crate::protocol::VaultSnapshotInfo,
        mut stats: SyncTransferStats,
        capability: Option<&crate::capability::CapabilityToken>,
    ) -> crate::error::Result<PullOutcome> {
        let local_set = collect_local_rbsr_blocking(&request).await?;
        let (rbsr_outcome, rbsr_sent, rbsr_recv) = reconcile_on_conn(
            &conn,
            request.peer,
            &request.scope,
            &snapshot.head_revision,
            &local_set,
            capability,
        )
        .await?;

        stats.rbsr_rounds = rbsr_outcome.rounds;
        stats.control_bytes_sent = stats.control_bytes_sent.saturating_add(rbsr_sent);
        stats.control_bytes_received = stats.control_bytes_received.saturating_add(rbsr_recv);
        stats.rbsr_remote_only_items = rbsr_outcome.remote_only.len() as u64;
        stats.rbsr_local_only_items = rbsr_outcome.local_only.len() as u64;

        let extra_local = partition_keys(&rbsr_outcome.local_only)?;
        if !extra_local.revisions.is_empty() {
            conn.close(0_u32.into(), b"conflict");
            return Err(crate::error::Failure::Store(
                mneme_store::Failure::PortableArchive(
                    "destination workspace history conflicts with remote peer".to_owned(),
                ),
            ));
        }

        let missing = partition_keys(&rbsr_outcome.remote_only)?;
        if missing.revisions.is_empty() && missing.blobs.is_empty() {
            conn.close(0_u32.into(), b"done");
            return self.complete_empty_diff(request, snapshot, stats);
        }

        let query = DeltaMetadataQuery {
            peer: request.peer,
            scope: &request.scope,
            snapshot_revision: &snapshot.head_revision,
            missing_revs: &missing.revisions,
            missing_blobs: &missing.blobs,
            capability,
        };
        let (delta_revisions, delta_blob_refs, meta_sent, meta_recv) =
            fetch_delta_metadata_on_conn(&conn, &query).await?;
        conn.close(0_u32.into(), b"done");

        stats.control_bytes_sent = stats.control_bytes_sent.saturating_add(meta_sent);
        stats.control_bytes_received = stats.control_bytes_received.saturating_add(meta_recv);

        let (fetched_blobs, blob_bytes_fetched) = self
            .download_delta_blobs(request.peer, &delta_blob_refs)
            .await?;
        stats.blobs_fetched = fetched_blobs.len() as u64;
        stats.blob_bytes_fetched = blob_bytes_fetched;

        let delta =
            build_portable_delta(&request.scope, &snapshot, delta_revisions, fetched_blobs)?;
        let destination = request.destination.clone();
        let workspace_config = (request.workspace_config)();
        let ingested = tokio::task::spawn_blocking(move || {
            crate::bundle::ingest_delta_to_workspace(&delta, &destination, workspace_config)
        })
        .await
        .map_err(|error| crate::error::Failure::Io(format!("delta ingest task join: {error}")))??;

        if let Some(state_dir) = &request.state_dir {
            record_pull_receipt(state_dir, &request, &snapshot, ingested.local_sequence)?;
        }

        Ok(PullOutcome {
            disposition: ingested.disposition,
            snapshot,
            local_revision: ingested.local_revision,
            local_sequence: ingested.local_sequence,
            verify_report: ingested.verify_report,
            stats,
        })
    }

    async fn send_control_request(
        &self,
        peer: iroh::EndpointId,
        request: &crate::protocol::SyncControlRequest,
    ) -> crate::error::Result<crate::protocol::SyncControlResponse> {
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
        let encoded = serde_json::to_vec(request).map_err(|error| {
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
        serde_json::from_slice(&response_bytes).map_err(|error| {
            crate::error::Failure::Protocol(format!("decode control response: {error}"))
        })
    }

    fn precheck_local_capability(
        &self,
        capability: &crate::capability::CapabilityToken,
        vault_id: &str,
        scope: &mneme_core::ScopeId,
        required_authority: crate::capability::CapabilityAuthority,
    ) -> crate::error::Result<()> {
        let now_secs = crate::capability::timestamp_to_epoch_secs(self.clock.now())?;
        let revocations = self.revocations.snapshot()?;
        let _verified = crate::capability::verify_capability_with_policy(
            &crate::capability::VerificationRequest {
                token: capability,
                presenter: self.node_id(),
                vault_id,
                scope,
                required_authority,
                now_secs,
                trusted_roots: &self.trusted_roots,
                revocations: &revocations,
            },
            crate::capability::RootTrustPolicy::AllowAnySignedRoot,
        )?;
        Ok(())
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

    async fn connect_control(
        &self,
        peer: iroh::EndpointId,
    ) -> crate::error::Result<iroh::endpoint::Connection> {
        self.endpoint
            .connect(peer, crate::protocol::SYNC_CONTROL_ALPN)
            .await
            .map_err(|error| {
                crate::error::Failure::Transport(format!("connect control to {peer}: {error}"))
            })
    }

    async fn pull_full_restore(
        &self,
        request: PullRequest,
        snapshot: crate::protocol::VaultSnapshotInfo,
        mut stats: SyncTransferStats,
    ) -> crate::error::Result<PullOutcome> {
        let bundle_hash = snapshot.parsed_bundle_hash()?;
        self.download_bundle_only(request.peer, bundle_hash).await?;
        stats.blobs_fetched = 1;
        stats.blob_bytes_fetched = snapshot.bundle_bytes;

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
            stats,
        })
    }

    fn complete_empty_diff(
        &self,
        request: PullRequest,
        snapshot: crate::protocol::VaultSnapshotInfo,
        stats: SyncTransferStats,
    ) -> crate::error::Result<PullOutcome> {
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
        let local_revision = workspace.current_revision()?;
        let local_sequence = workspace.current_sequence()?;
        if let Some(state_dir) = &request.state_dir {
            record_pull_receipt(state_dir, &request, &snapshot, local_sequence)?;
        }
        Ok(PullOutcome {
            disposition: crate::bundle::PullDisposition::AlreadyUpToDate,
            snapshot,
            local_revision,
            local_sequence,
            verify_report,
            stats,
        })
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
        stats: SyncTransferStats,
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
            stats,
        }))
    }

    async fn download_bundle_only(
        &self,
        peer: iroh::EndpointId,
        bundle_hash: iroh_blobs::Hash,
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
            .fetch(conn, bundle_hash)
            .await
            .map_err(|error| {
                crate::error::Failure::Transport(format!("fetch bundle {bundle_hash}: {error}"))
            })?;
        Ok(())
    }

    async fn download_delta_blobs(
        &self,
        peer: iroh::EndpointId,
        blobs: &[crate::protocol::BlobDigestRef],
    ) -> crate::error::Result<(Vec<mneme_store::portability::PortableDeltaBlob>, u64)> {
        if blobs.is_empty() {
            return Ok((Vec::new(), 0));
        }
        let conn = self
            .endpoint
            .connect(peer, iroh_blobs::ALPN)
            .await
            .map_err(|error| {
                crate::error::Failure::Transport(format!("connect blobs to {peer}: {error}"))
            })?;
        let mut out = Vec::with_capacity(blobs.len());
        let mut bytes_fetched = 0_u64;
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
            bytes_fetched = bytes_fetched.saturating_add(bytes.len() as u64);
            out.push(mneme_store::portability::PortableDeltaBlob {
                digest: expected_digest,
                bytes: bytes.to_vec(),
            });
        }
        Ok((out, bytes_fetched))
    }
}

async fn send_control_on_conn(
    conn: &iroh::endpoint::Connection,
    request: &crate::protocol::SyncControlRequest,
) -> crate::error::Result<(crate::protocol::SyncControlResponse, u64, u64)> {
    let encoded = serde_json::to_vec(request).map_err(|error| {
        crate::error::Failure::Protocol(format!("encode control request: {error}"))
    })?;
    let bytes_sent = encoded.len() as u64;
    if encoded.len() > crate::protocol::MAX_CONTROL_MESSAGE_BYTES {
        return Err(crate::error::Failure::SizeLimitExceeded {
            actual_bytes: bytes_sent,
            limit_bytes: crate::protocol::MAX_CONTROL_MESSAGE_BYTES as u64,
        });
    }
    let (mut send, mut recv) = conn.open_bi().await.map_err(|error| {
        crate::error::Failure::Transport(format!("open control stream: {error}"))
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
    let bytes_received = response_bytes.len() as u64;
    let response: crate::protocol::SyncControlResponse = serde_json::from_slice(&response_bytes)
        .map_err(|error| {
            crate::error::Failure::Protocol(format!("decode control response: {error}"))
        })?;
    Ok((response, bytes_sent, bytes_received))
}

async fn fetch_vault_head_on_conn(
    conn: &iroh::endpoint::Connection,
    peer: iroh::EndpointId,
    scope: &mneme_core::ScopeId,
    capability: Option<&crate::capability::CapabilityToken>,
) -> crate::error::Result<(crate::protocol::VaultSnapshotInfo, u64, u64)> {
    let req = crate::protocol::SyncControlRequest::GetVaultHead {
        scope: scope.to_string(),
        capability: capability.cloned(),
    };
    let (response, sent, recv) = send_control_on_conn(conn, &req).await?;
    match response {
        crate::protocol::SyncControlResponse::VaultHead(info) => Ok((*info, sent, recv)),
        other => Err(unexpected_control_response(peer, other)),
    }
}

async fn reconcile_on_conn(
    conn: &iroh::endpoint::Connection,
    peer: iroh::EndpointId,
    scope: &mneme_core::ScopeId,
    snapshot_revision: &str,
    local_set: &crate::rbsr::RbsrSet,
    capability: Option<&crate::capability::CapabilityToken>,
) -> crate::error::Result<(crate::rbsr::RbsrOutcome, u64, u64)> {
    let mut session = crate::rbsr::RbsrSession::new(local_set.clone());
    let mut total_sent = 0_u64;
    let mut total_recv = 0_u64;
    let scope_text = scope.to_string();

    while let Some((request, in_flight)) = session.next_request()? {
        let control_req = crate::protocol::SyncControlRequest::RbsrReconcile {
            scope: scope_text.clone(),
            snapshot_revision: snapshot_revision.to_owned(),
            request,
            capability: capability.cloned(),
        };
        let (response, sent, recv) = send_control_on_conn(conn, &control_req).await?;
        total_sent = total_sent.saturating_add(sent);
        total_recv = total_recv.saturating_add(recv);
        match response {
            crate::protocol::SyncControlResponse::RbsrReply(reply) => {
                session.apply_response(&in_flight, reply)?;
            }
            other => return Err(unexpected_control_response(peer, other)),
        }
    }

    let outcome = session.finish()?;
    Ok((outcome, total_sent, total_recv))
}

struct DeltaMetadataQuery<'a> {
    peer: iroh::EndpointId,
    scope: &'a mneme_core::ScopeId,
    snapshot_revision: &'a str,
    missing_revs: &'a [(mneme_core::RecordId, mneme_core::RevisionId)],
    missing_blobs: &'a [[u8; 32]],
    capability: Option<&'a crate::capability::CapabilityToken>,
}

fn build_portable_delta(
    scope: &mneme_core::ScopeId,
    snapshot: &crate::protocol::VaultSnapshotInfo,
    revisions: Vec<mneme_store::portability::PortableRevision>,
    blobs: Vec<mneme_store::portability::PortableDeltaBlob>,
) -> crate::error::Result<mneme_store::portability::PortableDelta> {
    let remote_revision = mneme_core::WorkspaceRevisionId::from_hex(&snapshot.head_revision)
        .map_err(|reason| {
            crate::error::Failure::Protocol(format!("invalid remote head revision: {reason}"))
        })?;
    Ok(mneme_store::portability::PortableDelta {
        scope: scope.clone(),
        remote_revision,
        remote_sequence: snapshot.sequence,
        revisions,
        blobs,
    })
}

async fn fetch_delta_metadata_on_conn(
    conn: &iroh::endpoint::Connection,
    query: &DeltaMetadataQuery<'_>,
) -> crate::error::Result<(
    Vec<mneme_store::portability::PortableRevision>,
    Vec<crate::protocol::BlobDigestRef>,
    u64,
    u64,
)> {
    let items_per_chunk = usize::try_from(crate::protocol::MAX_DELTA_ITEMS_PER_REQUEST)
        .map_err(|_| crate::error::Failure::Protocol("delta chunk limit overflow".to_owned()))?;
    let rev_chunks: Vec<&[(mneme_core::RecordId, mneme_core::RevisionId)]> =
        if query.missing_revs.is_empty() {
            Vec::new()
        } else {
            query.missing_revs.chunks(items_per_chunk).collect()
        };
    let blob_chunks: Vec<&[[u8; 32]]> = if query.missing_blobs.is_empty() {
        Vec::new()
    } else {
        query.missing_blobs.chunks(items_per_chunk).collect()
    };
    let steps = rev_chunks.len().max(blob_chunks.len());
    let mut out_revs = Vec::with_capacity(query.missing_revs.len());
    let mut out_blobs = Vec::with_capacity(query.missing_blobs.len());
    let mut total_sent = 0_u64;
    let mut total_recv = 0_u64;
    let scope_text = query.scope.to_string();

    for idx in 0..steps {
        let rev_slice = rev_chunks.get(idx).copied().unwrap_or(&[]);
        let blob_slice = blob_chunks.get(idx).copied().unwrap_or(&[]);
        let (chunk_revs, chunk_blobs, sent, recv) =
            fetch_delta_chunk(conn, query, &scope_text, rev_slice, blob_slice).await?;
        total_sent = total_sent.saturating_add(sent);
        total_recv = total_recv.saturating_add(recv);
        out_revs.extend(chunk_revs);
        out_blobs.extend(chunk_blobs);
    }

    Ok((out_revs, out_blobs, total_sent, total_recv))
}

async fn fetch_delta_chunk(
    conn: &iroh::endpoint::Connection,
    query: &DeltaMetadataQuery<'_>,
    scope_text: &str,
    rev_slice: &[(mneme_core::RecordId, mneme_core::RevisionId)],
    blob_slice: &[[u8; 32]],
) -> crate::error::Result<(
    Vec<mneme_store::portability::PortableRevision>,
    Vec<crate::protocol::BlobDigestRef>,
    u64,
    u64,
)> {
    let expected_revs: std::collections::BTreeSet<(mneme_core::RecordId, mneme_core::RevisionId)> =
        rev_slice.iter().copied().collect();
    let expected_blobs: std::collections::BTreeSet<[u8; 32]> = blob_slice.iter().copied().collect();

    let req = crate::protocol::SyncControlRequest::FetchDeltaMetadata {
        scope: scope_text.to_owned(),
        snapshot_revision: query.snapshot_revision.to_owned(),
        revisions: rev_slice
            .iter()
            .map(|(rec, rev)| crate::protocol::WireRevisionKey::from_pair(*rec, *rev))
            .collect(),
        blobs: blob_slice.iter().map(encode_hex_32).collect(),
        capability: query.capability.cloned(),
    };
    let (response, sent, recv) = send_control_on_conn(conn, &req).await?;
    match response {
        crate::protocol::SyncControlResponse::DeltaMetadata { revisions, blobs } => {
            let parsed_revs = parse_delta_revisions(query.scope, &expected_revs, revisions)?;
            let parsed_blobs = parse_delta_blobs(&expected_blobs, blobs)?;
            Ok((parsed_revs, parsed_blobs, sent, recv))
        }
        other => Err(unexpected_control_response(query.peer, other)),
    }
}

fn parse_delta_revisions(
    scope: &mneme_core::ScopeId,
    expected_revs: &std::collections::BTreeSet<(mneme_core::RecordId, mneme_core::RevisionId)>,
    revisions: Vec<crate::protocol::WireDeltaRevision>,
) -> crate::error::Result<Vec<mneme_store::portability::PortableRevision>> {
    if revisions.len() != expected_revs.len() {
        return Err(crate::error::Failure::Protocol(
            "delta revision count did not match request".to_owned(),
        ));
    }
    let mut out = Vec::with_capacity(revisions.len());
    let mut seen = std::collections::BTreeSet::new();
    for wire_rev in revisions {
        let portable = wire_rev.to_portable(scope)?;
        let pair = (portable.envelope.record_id, portable.envelope.revision_id);
        if !expected_revs.contains(&pair) || !seen.insert(pair) {
            return Err(crate::error::Failure::Protocol(
                "peer returned unrequested or duplicate delta revision".to_owned(),
            ));
        }
        out.push(portable);
    }
    Ok(out)
}

fn parse_delta_blobs(
    expected_blobs: &std::collections::BTreeSet<[u8; 32]>,
    blobs: Vec<crate::protocol::BlobDigestRef>,
) -> crate::error::Result<Vec<crate::protocol::BlobDigestRef>> {
    if blobs.len() != expected_blobs.len() {
        return Err(crate::error::Failure::Protocol(
            "delta blob count did not match request".to_owned(),
        ));
    }
    let mut out = Vec::with_capacity(blobs.len());
    let mut seen = std::collections::BTreeSet::new();
    for blob_ref in blobs {
        let digest = blob_ref.content_digest.to_digest()?;
        let key = *digest.as_bytes();
        if !expected_blobs.contains(&key) || !seen.insert(key) {
            return Err(crate::error::Failure::Protocol(
                "peer returned unrequested or duplicate delta blob".to_owned(),
            ));
        }
        out.push(blob_ref);
    }
    Ok(out)
}

struct PartitionedKeys {
    revisions: Vec<(mneme_core::RecordId, mneme_core::RevisionId)>,
    blobs: Vec<[u8; 32]>,
}

fn partition_keys(keys: &[crate::rbsr::RbsrKey]) -> crate::error::Result<PartitionedKeys> {
    let mut revisions = Vec::new();
    let mut blobs = Vec::new();
    for &key in keys {
        match key.kind() {
            crate::rbsr::RbsrItemKind::Revision => {
                let pair = key.as_revision().ok_or_else(|| {
                    crate::error::Failure::Protocol("malformed RBSR revision key".to_owned())
                })?;
                revisions.push(pair);
            }
            crate::rbsr::RbsrItemKind::Blob => {
                let digest = key.as_blob_bytes().ok_or_else(|| {
                    crate::error::Failure::Protocol("malformed RBSR blob key".to_owned())
                })?;
                blobs.push(digest);
            }
        }
    }
    Ok(PartitionedKeys { revisions, blobs })
}

fn local_workspace_sequence(request: &PullRequest) -> crate::error::Result<Option<u64>> {
    if !request.destination.is_dir() || !request.destination.join(mneme_store::LEDGER_FILE).exists()
    {
        return Ok(None);
    }
    let workspace =
        mneme_store::Workspace::open(&request.destination, (request.workspace_config)())?;
    Ok(Some(workspace.current_sequence()?))
}

async fn collect_local_rbsr_blocking(
    request: &PullRequest,
) -> crate::error::Result<crate::rbsr::RbsrSet> {
    let destination = request.destination.clone();
    let scope = request.scope.clone();
    let config = (request.workspace_config)();
    tokio::task::spawn_blocking(move || {
        let workspace = mneme_store::Workspace::open(&destination, config)?;
        crate::bundle::collect_local_rbsr_set(&workspace, &scope)
    })
    .await
    .map_err(|error| crate::error::Failure::Io(format!("collect RBSR set join: {error}")))?
}

fn encode_hex_32(bytes: &[u8; 32]) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    out
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

fn unexpected_control_response(
    peer: iroh::EndpointId,
    response: crate::protocol::SyncControlResponse,
) -> crate::error::Failure {
    match response {
        crate::protocol::SyncControlResponse::CapabilityDenied { reason } => {
            crate::error::Failure::CapabilityDenied(reason)
        }
        crate::protocol::SyncControlResponse::CapabilityRevoked { token_id, reason } => {
            crate::error::Failure::CapabilityRevoked { token_id, reason }
        }
        crate::protocol::SyncControlResponse::Refused { reason } => {
            crate::error::Failure::Protocol(format!("peer {peer} refused sync request: {reason}"))
        }
        crate::protocol::SyncControlResponse::VaultHead(_)
        | crate::protocol::SyncControlResponse::RbsrReply(_)
        | crate::protocol::SyncControlResponse::DeltaMetadata { .. }
        | crate::protocol::SyncControlResponse::HeadAccepted { .. }
        | crate::protocol::SyncControlResponse::Revocations { .. } => {
            crate::error::Failure::Protocol(format!("unexpected sync control response from {peer}"))
        }
    }
}

async fn bind_iroh_endpoint(
    config: &SyncNodeConfig,
    memory_lookup: &iroh::address_lookup::memory::MemoryLookup,
) -> crate::error::Result<iroh::Endpoint> {
    let mut builder = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(config.secret_key.clone())
        .relay_mode(config.relay.clone().into_iroh())
        .address_lookup(memory_lookup.clone());
    if matches!(
        config.discovery,
        crate::protocol::DiscoveryMode::MdnsOnly | crate::protocol::DiscoveryMode::MdnsAndDht
    ) {
        builder = builder.address_lookup(iroh_mdns_address_lookup::MdnsAddressLookup::builder());
    }
    if config.discovery == crate::protocol::DiscoveryMode::MdnsAndDht {
        builder = builder.address_lookup(iroh_mainline_address_lookup::DhtAddressLookup::builder());
    }
    for addr in &config.bind_addrs {
        builder = builder.bind_addr(*addr).map_err(|error| {
            crate::error::Failure::InvalidConfig(format!("invalid bind addr: {error}"))
        })?;
    }
    builder
        .bind()
        .await
        .map_err(|error| crate::error::Failure::Transport(format!("endpoint bind: {error}")))
}
