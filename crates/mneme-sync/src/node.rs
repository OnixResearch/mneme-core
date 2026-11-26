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
    secret_key: iroh::SecretKey,
    allowlist: crate::trust::SharedAllowlist,
    revocations: crate::capability::SharedRevocationSet,
    trusted_roots: std::collections::BTreeSet<iroh::EndpointId>,
    authorized_issuers: crate::capability::SharedAuthorizedIssuers,
    leases: crate::capability::SharedCapabilityLeases,
    clock: std::sync::Arc<dyn mneme_store::Clock>,
    hlc: crate::protocol::SharedSyncHlc,
    high_water: std::collections::BTreeMap<(mneme_core::ScopeId, iroh::EndpointId), u64>,
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

    /// Broadcast a signed lightweight `(vault_id, head_revision_digest, seq)` announcement.
    pub async fn broadcast_head(
        &mut self,
        info: &crate::protocol::VaultSnapshotInfo,
    ) -> crate::error::Result<()> {
        let mut announcement = info.to_announcement();
        announcement.hlc = Some(self.hlc.tick()?);
        let announcement = announcement.signed(&self.secret_key)?;
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

    /// Receive the next authorized, Ed25519-signed, monotonic [`crate::protocol::HeadAnnouncement`].
    ///
    /// Signed revocation tombstones from authorized revokers received on the
    /// topic are verified and merged into [`crate::capability::SharedRevocationSet`].
    /// Unsigned announcements, untrusted revokers, unauthorized origins,
    /// mismatched `vault_id` payloads, and rollback sequences are ignored
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
            {
                let revokers = self
                    .authorized_issuers
                    .effective_revokers(&self.trusted_roots, &self.allowlist);
                if let Err(error) = self.revocations.insert_authorized(tombstone, &revokers) {
                    tracing::debug!(%error, "ignoring untrusted or conflicting gossip revocation");
                }
                continue;
            }
            let Ok(announcement) = crate::protocol::HeadAnnouncement::decode(&message.content)
            else {
                continue;
            };
            let Ok(origin) = announcement.verify_signature() else {
                continue;
            };
            if announcement.vault_id != self.vault_id {
                continue;
            }
            let Ok(scope) = crate::protocol::parse_scope_id(&announcement.scope) else {
                continue;
            };
            if !self.is_sender_authorized(origin, &scope) {
                continue;
            }
            if let Some(remote_hlc) = announcement.hlc
                && self.hlc.observe(remote_hlc).is_err()
            {
                continue;
            }
            let key = (scope, origin);
            if let Some(&prev_seq) = self.high_water.get(&key)
                && announcement.seq <= prev_seq
            {
                continue;
            }
            self.high_water.insert(key, announcement.seq);
            return Ok(Some((origin, announcement)));
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
            .permits_vault_scope(&crate::capability::LeaseVaultScopeQuery {
                peer: sender,
                vault_id: &self.vault_id,
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
    secret_key: iroh::SecretKey,
    transport: crate::transport::IrohTransport,
    router: iroh::protocol::Router,
    memory_lookup: iroh::address_lookup::memory::MemoryLookup,
    allowlist: crate::trust::SharedAllowlist,
    revocations: crate::capability::SharedRevocationSet,
    trusted_roots: std::collections::BTreeSet<iroh::EndpointId>,
    authorized_issuers: crate::capability::SharedAuthorizedIssuers,
    leases: crate::capability::SharedCapabilityLeases,
    clock: std::sync::Arc<dyn mneme_store::Clock>,
    hlc: crate::protocol::SharedSyncHlc,
    scopes: crate::protocol::SharedScopeTable,
}

impl std::fmt::Debug for SyncNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncNode")
            .field("node_id", &self.transport.node_id())
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

        let blobs = crate::blobstore::DiskBlobStore::new()?;
        let gossip = iroh_gossip::Gossip::builder().spawn(endpoint.clone());
        let scopes: crate::protocol::SharedScopeTable = std::sync::Arc::new(
            std::sync::RwLock::new(crate::protocol::SyncScopeTable::new()),
        );
        let leases = crate::capability::SharedCapabilityLeases::new();
        let authorized_issuers = crate::capability::SharedAuthorizedIssuers::new();
        let auth = crate::protocol::CapabilityAuthorizer {
            allowlist: config.allowlist.clone(),
            leases: leases.clone(),
            trusted_roots: trusted_roots.clone(),
            revocations: config.revocations.clone(),
            authorized_issuers: authorized_issuers.clone(),
            scopes: scopes.clone(),
            clock: std::sync::Arc::clone(&config.clock),
        };

        let blobs_events = crate::protocol::spawn_scoped_blobs_events(auth.clone());
        let blobs_handler = crate::protocol::CapabilityProtocol::new(
            auth.clone(),
            crate::capability::CapabilityAuthority::SyncPull,
            crate::blobstore::DiskBlobsProtocol::new(blobs.clone(), blobs_events),
        );
        let gossip_handler = crate::protocol::CapabilityProtocol::new(
            auth.clone(),
            crate::capability::CapabilityAuthority::SyncPull,
            gossip.clone(),
        );
        let hlc = crate::protocol::SharedSyncHlc::new(std::sync::Arc::clone(&config.clock));
        let control_handler =
            crate::protocol::SyncControlHandler::new(auth, scopes.clone(), hlc.clone());

        let router = iroh::protocol::Router::builder(endpoint.clone())
            .accept(iroh_blobs::ALPN, blobs_handler)
            .accept(iroh_gossip::ALPN, gossip_handler)
            .accept(crate::protocol::SYNC_CONTROL_ALPN, control_handler)
            .spawn();

        let transport = crate::transport::IrohTransport::new(endpoint, blobs, gossip);

        Ok(Self {
            secret_key: config.secret_key,
            transport,
            router,
            memory_lookup,
            allowlist: config.allowlist,
            revocations: config.revocations,
            trusted_roots,
            authorized_issuers,
            leases,
            clock: config.clock,
            hlc,
            scopes,
        })
    }

    /// Return this node's current Hybrid Logical Clock watermark.
    pub fn current_hlc(&self) -> mneme_kernel::hlc::HybridTimestamp {
        self.hlc.current()
    }

    /// Configure the maximum permitted HLC physical clock skew in nanoseconds.
    pub fn set_hlc_max_skew_ns(&self, max_skew_ns: i64) {
        self.hlc.set_max_skew_ns(max_skew_ns);
    }

    /// Return this node's Ed25519 identity.
    pub fn node_id(&self) -> iroh::EndpointId {
        self.transport.node_id()
    }

    /// Return this node's current socket/relay address information.
    pub fn addr(&self) -> iroh::EndpointAddr {
        self.transport.addr()
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

    /// Access the underlying production [`crate::transport::IrohTransport`].
    pub const fn transport(&self) -> &crate::transport::IrohTransport {
        &self.transport
    }

    /// Access the underlying Iroh endpoint (for address lookup or diagnostics).
    pub const fn endpoint(&self) -> &iroh::Endpoint {
        self.transport.endpoint()
    }

    /// Access the disk-backed blob store backing `iroh-blobs` transfers.
    pub const fn blob_store(&self) -> &crate::blobstore::DiskBlobStore {
        self.transport.blob_store()
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

    /// Register a local `vault_id` that this node accepts capability leases and pushes for.
    pub fn register_vault_id(&self, vault_id: &str) -> crate::error::Result<()> {
        if vault_id.trim().is_empty() {
            return Err(crate::error::Failure::InvalidConfig(
                "vault_id must not be empty".to_owned(),
            ));
        }
        let mut guard = self.scopes.write().map_err(|_| {
            crate::error::Failure::InvalidConfig("published scopes lock poisoned".to_owned())
        })?;
        guard.configured_vaults.insert(vault_id.to_owned());
        Ok(())
    }

    /// Access the live capability lease table (for inspection or tests).
    pub const fn leases(&self) -> &crate::capability::SharedCapabilityLeases {
        &self.leases
    }

    /// Export `scope` from `workspace` and publish its bundle, blobs, and RBSR index.
    pub async fn publish_workspace(
        &self,
        workspace: &mneme_store::Workspace,
        vault_id: &str,
        scope: &mneme_core::ScopeId,
    ) -> crate::error::Result<crate::protocol::VaultSnapshotInfo> {
        let exported = crate::bundle::export_scope_to_store(
            workspace,
            vault_id,
            scope,
            self.transport.blob_store(),
        )
        .await?;
        let mut authorized_hashes = std::collections::BTreeSet::new();
        authorized_hashes.insert(exported.archive_hash);
        for blob_ref in &exported.info.blobs {
            let hash = iroh_blobs::Hash::from_str(&blob_ref.transport_hash).map_err(|error| {
                crate::error::Failure::Protocol(format!("invalid exported blob hash: {error}"))
            })?;
            authorized_hashes.insert(hash);
        }
        let entry = std::sync::Arc::new(crate::protocol::PublishedScopeEntry {
            info: exported.info.clone(),
            rbsr_set: exported.rbsr_set,
            revisions: exported.revisions,
            blobs_by_digest: exported.blobs_by_digest,
            retention: exported.retention,
            authorized_hashes,
        });
        let mut guard = self.scopes.write().map_err(|_| {
            crate::error::Failure::InvalidConfig("published scopes lock poisoned".to_owned())
        })?;
        guard.configured_vaults.insert(vault_id.to_owned());
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
        self.register_vault_id(vault_id)?;
        let topic_id = crate::state::topic_id_for_vault(vault_id);
        let topic = self
            .transport
            .gossip()
            .subscribe(topic_id, bootstrap)
            .await
            .map_err(|error| {
                crate::error::Failure::Protocol(format!("gossip subscribe: {error}"))
            })?;
        Ok(VaultGossipTopic {
            vault_id: vault_id.to_owned(),
            secret_key: self.secret_key.clone(),
            allowlist: self.allowlist.clone(),
            revocations: self.revocations.clone(),
            trusted_roots: self.trusted_roots.clone(),
            authorized_issuers: self.authorized_issuers.clone(),
            leases: self.leases.clone(),
            clock: std::sync::Arc::clone(&self.clock),
            hlc: self.hlc.clone(),
            high_water: std::collections::BTreeMap::new(),
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
        let (info, _sent, _recv) =
            fetch_vault_head_on_conn(&conn, peer, scope, None, &self.hlc).await?;
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
        let (outcome, _sent, _recv) = reconcile_on_conn(
            &conn,
            ReconcileConnQuery {
                peer,
                scope,
                snapshot_revision,
                local_set,
                capability: None,
                hlc: &self.hlc,
            },
        )
        .await?;
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
                    hlc: Some(self.hlc.tick()?),
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
            fetch_vault_head_on_conn(&conn, request.peer, &request.scope, None, &self.hlc).await?;
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
        let (snapshot, head_sent, head_recv) = fetch_vault_head_on_conn(
            &conn,
            request.peer,
            &request.scope,
            Some(capability),
            &self.hlc,
        )
        .await?;
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
        let signed = if announcement.signature.is_some() {
            announcement.clone()
        } else {
            let mut with_hlc = announcement.clone();
            if with_hlc.hlc.is_none() {
                with_hlc.hlc = Some(self.hlc.tick()?);
            }
            with_hlc.signed(&self.secret_key)?
        };
        let response = self
            .send_control_request(
                peer,
                &crate::protocol::SyncControlRequest::PushHead {
                    announcement: Box::new(signed),
                    hlc: Some(self.hlc.tick()?),
                    capability: Some(capability.clone()),
                },
            )
            .await?;
        match response {
            crate::protocol::SyncControlResponse::HeadAccepted { .. } => Ok(()),
            other => Err(unexpected_control_response(peer, other)),
        }
    }

    /// Exchange and deterministically merge CRDT revocation tombstones with `peer` using bounded pagination.
    pub async fn sync_revocations(
        &self,
        peer: iroh::EndpointId,
        capability: Option<&crate::capability::CapabilityToken>,
    ) -> crate::error::Result<u64> {
        if !self.allowlist.is_allowed(peer) && capability.is_none() {
            return Err(crate::error::Failure::UnauthorizedPeer(peer.to_string()));
        }
        let local = self.revocations.snapshot()?;
        let all_local: Vec<crate::capability::RevocationTombstone> =
            local.tombstones().cloned().collect();
        let authorized_revokers = self.revokers_for_sync(capability);
        let (mut merged_total, mut pull_cursor, mut has_more_pages) = self
            .push_revocation_chunks(peer, &all_local, capability, &authorized_revokers)
            .await?;

        let max_pages = (crate::capability::MAX_REVOCATION_TOMBSTONES
            / crate::capability::MAX_REVOCATIONS_PER_PAGE)
            .saturating_add(2);
        let mut pages_pulled: u64 = 0;
        while has_more_pages && pages_pulled < max_pages {
            pages_pulled = pages_pulled.saturating_add(1);
            let (page, has_more, next_cursor) = self
                .exchange_revocation_page(peer, Vec::new(), pull_cursor, capability)
                .await?;
            let merged = self
                .revocations
                .merge_tombstones_authorized(&page, &authorized_revokers)?;
            merged_total = merged_total.saturating_add(merged);
            if page.is_empty() {
                break;
            }
            has_more_pages = has_more;
            pull_cursor = next_cursor.or_else(|| page.last().map(|t| t.tombstone_id));
        }
        Ok(merged_total)
    }

    fn revokers_for_sync(
        &self,
        capability: Option<&crate::capability::CapabilityToken>,
    ) -> std::collections::BTreeSet<iroh::EndpointId> {
        let mut revokers = self
            .authorized_issuers
            .effective_revokers(&self.trusted_roots, &self.allowlist);
        if let Some(token) = capability {
            for link in &token.links {
                revokers.insert(link.issuer);
            }
        }
        revokers
    }

    async fn push_revocation_chunks(
        &self,
        peer: iroh::EndpointId,
        all_local: &[crate::capability::RevocationTombstone],
        capability: Option<&crate::capability::CapabilityToken>,
        authorized_revokers: &std::collections::BTreeSet<iroh::EndpointId>,
    ) -> crate::error::Result<(u64, Option<crate::capability::TombstoneId>, bool)> {
        let chunk_items = usize::try_from(crate::capability::MAX_REVOCATIONS_PER_PAGE)
            .map_err(|_| crate::error::Failure::Protocol("revocation page overflow".to_owned()))?;
        let push_chunks: Vec<&[crate::capability::RevocationTombstone]> = if all_local.is_empty() {
            vec![&[]]
        } else {
            all_local.chunks(chunk_items).collect()
        };
        let mut merged_total: u64 = 0;
        let mut pull_cursor: Option<crate::capability::TombstoneId> = None;
        let mut has_more_pages = false;
        for chunk in push_chunks {
            let (page, has_more, next_cursor) = self
                .exchange_revocation_page(peer, chunk.to_vec(), pull_cursor, capability)
                .await?;
            let merged = self
                .revocations
                .merge_tombstones_authorized(&page, authorized_revokers)?;
            merged_total = merged_total.saturating_add(merged);
            has_more_pages = has_more;
            pull_cursor = next_cursor.or_else(|| page.last().map(|t| t.tombstone_id));
        }
        Ok((merged_total, pull_cursor, has_more_pages))
    }

    async fn exchange_revocation_page(
        &self,
        peer: iroh::EndpointId,
        revocations: Vec<crate::capability::RevocationTombstone>,
        after_id: Option<crate::capability::TombstoneId>,
        capability: Option<&crate::capability::CapabilityToken>,
    ) -> crate::error::Result<(
        Vec<crate::capability::RevocationTombstone>,
        bool,
        Option<crate::capability::TombstoneId>,
    )> {
        let response = self
            .send_control_request(
                peer,
                &crate::protocol::SyncControlRequest::SyncRevocations {
                    revocations,
                    after_id,
                    limit: Some(crate::capability::MAX_REVOCATIONS_PER_PAGE),
                    hlc: Some(self.hlc.tick()?),
                    capability: capability.cloned(),
                },
            )
            .await?;
        match response {
            crate::protocol::SyncControlResponse::Revocations {
                revocations,
                has_more,
                next_cursor,
                ..
            } => Ok((revocations, has_more, next_cursor)),
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
        let (local_set, local_generation) = collect_local_rbsr_blocking(&request).await?;
        let (rbsr_outcome, rbsr_sent, rbsr_recv) = reconcile_on_conn(
            &conn,
            ReconcileConnQuery {
                peer: request.peer,
                scope: &request.scope,
                snapshot_revision: &snapshot.head_revision,
                local_set: &local_set,
                capability,
                hlc: &self.hlc,
            },
        )
        .await?;

        stats.rbsr_rounds = rbsr_outcome.rounds;
        stats.control_bytes_sent = stats.control_bytes_sent.saturating_add(rbsr_sent);
        stats.control_bytes_received = stats.control_bytes_received.saturating_add(rbsr_recv);
        stats.rbsr_remote_only_items = rbsr_outcome.remote_only.len() as u64;
        stats.rbsr_local_only_items = rbsr_outcome.local_only.len() as u64;

        let extra_local = partition_keys(&rbsr_outcome.local_only)?;
        let missing = partition_keys(&rbsr_outcome.remote_only)?;
        let has_retention_update = snapshot.eligibility_generation > local_generation;
        if !extra_local.revisions.is_empty() && !has_retention_update {
            conn.close(0_u32.into(), b"conflict");
            return Err(crate::error::Failure::Store(
                mneme_store::Failure::PortableArchive(
                    "destination workspace history conflicts with remote peer".to_owned(),
                ),
            ));
        }

        if missing.revisions.is_empty() && missing.blobs.is_empty() && !has_retention_update {
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
            hlc: &self.hlc,
        };
        let (delta_revisions, delta_blob_refs, delta_retention, meta_sent, meta_recv) =
            fetch_delta_metadata_on_conn(&conn, &query).await?;
        conn.close(0_u32.into(), b"done");

        stats.control_bytes_sent = stats.control_bytes_sent.saturating_add(meta_sent);
        stats.control_bytes_received = stats.control_bytes_received.saturating_add(meta_recv);

        if !extra_local.revisions.is_empty() {
            let retention_barrier_present = delta_retention.as_ref().is_some_and(|retention| {
                retention.generation > local_generation
                    || extra_local.revisions.iter().any(|(rec_id, rev_id)| {
                        retention.suppressions.iter().any(|sup| {
                            sup.mode == mneme_store::SuppressionMode::Forgotten
                                && sup.target == *rec_id
                                && (sup.revision.is_none() || sup.revision == Some(*rev_id))
                        })
                    })
            });
            if !retention_barrier_present {
                return Err(crate::error::Failure::Store(
                    mneme_store::Failure::PortableArchive(
                        "destination workspace history conflicts with remote peer".to_owned(),
                    ),
                ));
            }
        }

        let (fetched_blobs, blob_bytes_fetched) = self
            .download_delta_blobs(request.peer, &request.destination, &delta_blob_refs)
            .await?;
        stats.blobs_fetched = fetched_blobs.len() as u64;
        stats.blob_bytes_fetched = blob_bytes_fetched;

        let delta = build_portable_delta(
            &request.scope,
            &snapshot,
            delta_revisions,
            fetched_blobs,
            delta_retention,
        )?;
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
        let encoded = serde_json::to_vec(request).map_err(|error| {
            crate::error::Failure::Protocol(format!("encode control request: {error}"))
        })?;
        let response_bytes =
            crate::transport::SyncTransport::control_roundtrip(&self.transport, peer, &encoded)
                .await?;
        let response: crate::protocol::SyncControlResponse =
            serde_json::from_slice(&response_bytes).map_err(|error| {
                crate::error::Failure::Protocol(format!("decode control response: {error}"))
            })?;
        if let Some(remote_hlc) = response.sender_hlc() {
            let _ = self.hlc.observe(remote_hlc)?;
        }
        Ok(response)
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
        self.transport.connect_control(peer).await
    }

    async fn pull_full_restore(
        &self,
        request: PullRequest,
        snapshot: crate::protocol::VaultSnapshotInfo,
        mut stats: SyncTransferStats,
    ) -> crate::error::Result<PullOutcome> {
        let bundle_hash = snapshot.parsed_bundle_hash()?;
        let max_bundle_bytes = snapshot
            .bundle_bytes
            .min(crate::protocol::MAX_SYNC_BUNDLE_BYTES);
        let staging_dir =
            create_pull_staging_dir(request.state_dir.as_deref(), &request.destination)?;
        let archive_path = staging_dir.path().join("pulled.mneme");
        let downloaded = self
            .download_bundle_to_path(request.peer, bundle_hash, max_bundle_bytes, &archive_path)
            .await?;
        if downloaded.byte_length != snapshot.bundle_bytes {
            return Err(crate::error::Failure::VerificationFailed(format!(
                "downloaded bundle length {} differs from snapshot metadata {}",
                downloaded.byte_length, snapshot.bundle_bytes
            )));
        }
        stats.blobs_fetched = 1;
        stats.blob_bytes_fetched = downloaded.byte_length;

        let destination = request.destination.clone();
        let workspace_config = (request.workspace_config)();
        let archive_for_ingest = archive_path.clone();
        let ingested = tokio::task::spawn_blocking(move || {
            crate::bundle::ingest_downloaded_archive(
                &archive_for_ingest,
                &destination,
                workspace_config,
            )
        })
        .await
        .map_err(|error| crate::error::Failure::Io(format!("ingest task join: {error}")))??;
        drop(staging_dir);

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

    async fn download_bundle_to_path(
        &self,
        peer: iroh::EndpointId,
        bundle_hash: iroh_blobs::Hash,
        max_bytes: u64,
        target_path: &std::path::Path,
    ) -> crate::error::Result<crate::blobstore::DownloadedBlob> {
        let fetch = crate::transport::BlobFetchRequest {
            peer,
            hash: bundle_hash,
            max_bytes,
            target_path,
            extra_algorithm: None,
        };
        crate::transport::SyncTransport::fetch_blob(&self.transport, &fetch).await
    }

    async fn download_delta_blobs(
        &self,
        peer: iroh::EndpointId,
        destination: &std::path::Path,
        blobs: &[crate::protocol::BlobDigestRef],
    ) -> crate::error::Result<(Vec<mneme_store::portability::PortableDeltaBlob>, u64)> {
        if blobs.is_empty() {
            return Ok((Vec::new(), 0));
        }
        let staging_dir = create_pull_staging_dir(None, destination)?;
        let conn = self.transport.connect_blobs(peer).await?;
        let mut out = Vec::with_capacity(blobs.len());
        let mut bytes_fetched = 0_u64;
        for (idx, blob_ref) in blobs.iter().enumerate() {
            let expected_digest = blob_ref.content_digest.to_digest()?;
            let transport_hash =
                iroh_blobs::Hash::from_str(&blob_ref.transport_hash).map_err(|error| {
                    crate::error::Failure::Protocol(format!("invalid blob hash: {error}"))
                })?;
            if expected_digest.algorithm() == mneme_core::HashAlgorithm::Blake3
                && transport_hash.as_bytes() != expected_digest.as_bytes()
            {
                return Err(crate::error::Failure::VerificationFailed(format!(
                    "peer transport hash for BLAKE3 blob {} disagrees with content digest",
                    expected_digest.to_hex()
                )));
            }
            let remaining = crate::protocol::MAX_SYNC_BUNDLE_BYTES.saturating_sub(bytes_fetched);
            if blob_ref.byte_length > remaining {
                return Err(crate::error::Failure::SizeLimitExceeded {
                    actual_bytes: bytes_fetched.saturating_add(blob_ref.byte_length),
                    limit_bytes: crate::protocol::MAX_SYNC_BUNDLE_BYTES,
                });
            }
            let blob_cap = blob_ref.byte_length.min(remaining);
            let extra_alg = if expected_digest.algorithm() == mneme_core::HashAlgorithm::Blake3 {
                None
            } else {
                Some(expected_digest.algorithm())
            };
            let staged_path = staging_dir.path().join(format!("delta-blob-{idx}.part"));
            let downloaded = crate::blobstore::download_blob_to_file(
                &conn,
                transport_hash,
                blob_cap,
                &staged_path,
                extra_alg,
            )
            .await?;
            let extra_matches = match downloaded.extra_digest {
                Some(actual) => actual == *expected_digest.as_bytes(),
                None => expected_digest.algorithm() == mneme_core::HashAlgorithm::Blake3,
            };
            if downloaded.byte_length != blob_ref.byte_length || !extra_matches {
                return Err(crate::error::Failure::VerificationFailed(format!(
                    "downloaded blob {} failed Mneme digest verification",
                    expected_digest.to_hex()
                )));
            }
            let bytes = std::fs::read(&staged_path).map_err(|error| {
                crate::error::Failure::Io(format!("read verified staged delta blob: {error}"))
            })?;
            let _removed = std::fs::remove_file(&staged_path).is_ok();
            bytes_fetched = bytes_fetched.saturating_add(downloaded.byte_length);
            out.push(mneme_store::portability::PortableDeltaBlob {
                digest: expected_digest,
                bytes,
            });
        }
        Ok((out, bytes_fetched))
    }
}

fn create_pull_staging_dir(
    state_dir: Option<&std::path::Path>,
    destination: &std::path::Path,
) -> crate::error::Result<tempfile::TempDir> {
    let base = if destination.is_dir() {
        Some(destination.join(mneme_store::payload::STAGING_DIRECTORY))
    } else {
        state_dir.map(|dir| dir.join(mneme_store::payload::STAGING_DIRECTORY))
    };
    if let Some(staging_root) = base {
        std::fs::create_dir_all(&staging_root).map_err(|error| {
            crate::error::Failure::Io(format!(
                "create sync staging directory {}: {error}",
                staging_root.display()
            ))
        })?;
        return tempfile::tempdir_in(&staging_root).map_err(|error| {
            crate::error::Failure::Io(format!(
                "create staged sync tempdir in {}: {error}",
                staging_root.display()
            ))
        });
    }
    tempfile::tempdir()
        .map_err(|error| crate::error::Failure::Io(format!("create sync staging tempdir: {error}")))
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
    hlc: &crate::protocol::SharedSyncHlc,
) -> crate::error::Result<(crate::protocol::VaultSnapshotInfo, u64, u64)> {
    let req = crate::protocol::SyncControlRequest::GetVaultHead {
        scope: scope.to_string(),
        hlc: Some(hlc.tick()?),
        capability: capability.cloned(),
    };
    let (response, sent, recv) = send_control_on_conn(conn, &req).await?;
    if let Some(remote_hlc) = response.sender_hlc() {
        let _ = hlc.observe(remote_hlc)?;
    }
    match response {
        crate::protocol::SyncControlResponse::VaultHead(info) => Ok((*info, sent, recv)),
        other => Err(unexpected_control_response(peer, other)),
    }
}

struct ReconcileConnQuery<'a> {
    peer: iroh::EndpointId,
    scope: &'a mneme_core::ScopeId,
    snapshot_revision: &'a str,
    local_set: &'a crate::rbsr::RbsrSet,
    capability: Option<&'a crate::capability::CapabilityToken>,
    hlc: &'a crate::protocol::SharedSyncHlc,
}

async fn reconcile_on_conn(
    conn: &iroh::endpoint::Connection,
    query: ReconcileConnQuery<'_>,
) -> crate::error::Result<(crate::rbsr::RbsrOutcome, u64, u64)> {
    let mut session = crate::rbsr::RbsrSession::new(query.local_set.clone());
    let mut total_sent = 0_u64;
    let mut total_recv = 0_u64;
    let scope_text = query.scope.to_string();

    while let Some((request, in_flight)) = session.next_request()? {
        let control_req = crate::protocol::SyncControlRequest::RbsrReconcile {
            scope: scope_text.clone(),
            snapshot_revision: query.snapshot_revision.to_owned(),
            request,
            hlc: Some(query.hlc.tick()?),
            capability: query.capability.cloned(),
        };
        let (response, sent, recv) = send_control_on_conn(conn, &control_req).await?;
        if let Some(remote_hlc) = response.sender_hlc() {
            let _ = query.hlc.observe(remote_hlc)?;
        }
        total_sent = total_sent.saturating_add(sent);
        total_recv = total_recv.saturating_add(recv);
        match response {
            crate::protocol::SyncControlResponse::RbsrReply(reply) => {
                session.apply_response(&in_flight, reply)?;
            }
            other => return Err(unexpected_control_response(query.peer, other)),
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
    hlc: &'a crate::protocol::SharedSyncHlc,
}

fn build_portable_delta(
    scope: &mneme_core::ScopeId,
    snapshot: &crate::protocol::VaultSnapshotInfo,
    revisions: Vec<mneme_store::portability::PortableRevision>,
    blobs: Vec<mneme_store::portability::PortableDeltaBlob>,
    retention: Option<mneme_store::portability::PortableRetentionState>,
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
        retention,
    })
}

async fn fetch_delta_metadata_on_conn(
    conn: &iroh::endpoint::Connection,
    query: &DeltaMetadataQuery<'_>,
) -> crate::error::Result<(
    Vec<mneme_store::portability::PortableRevision>,
    Vec<crate::protocol::BlobDigestRef>,
    Option<mneme_store::portability::PortableRetentionState>,
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
    let steps = rev_chunks.len().max(blob_chunks.len()).max(1);
    let mut out_revs = Vec::with_capacity(query.missing_revs.len());
    let mut out_blobs = Vec::with_capacity(query.missing_blobs.len());
    let mut out_retention = None;
    let mut total_sent = 0_u64;
    let mut total_recv = 0_u64;
    let scope_text = query.scope.to_string();

    for idx in 0..steps {
        let rev_slice = rev_chunks.get(idx).copied().unwrap_or(&[]);
        let blob_slice = blob_chunks.get(idx).copied().unwrap_or(&[]);
        let (chunk_revs, chunk_blobs, chunk_retention, sent, recv) =
            fetch_delta_chunk(conn, query, &scope_text, rev_slice, blob_slice).await?;
        total_sent = total_sent.saturating_add(sent);
        total_recv = total_recv.saturating_add(recv);
        out_revs.extend(chunk_revs);
        out_blobs.extend(chunk_blobs);
        if out_retention.is_none() {
            out_retention = chunk_retention;
        }
    }

    Ok((out_revs, out_blobs, out_retention, total_sent, total_recv))
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
    Option<mneme_store::portability::PortableRetentionState>,
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
        hlc: Some(query.hlc.tick()?),
        capability: query.capability.cloned(),
    };
    let (response, sent, recv) = send_control_on_conn(conn, &req).await?;
    if let Some(remote_hlc) = response.sender_hlc() {
        let _ = query.hlc.observe(remote_hlc)?;
    }
    match response {
        crate::protocol::SyncControlResponse::DeltaMetadata {
            revisions,
            blobs,
            retention,
            ..
        } => {
            let parsed_revs = parse_delta_revisions(query.scope, &expected_revs, revisions)?;
            let parsed_blobs = parse_delta_blobs(&expected_blobs, blobs)?;
            let parsed_retention = retention
                .as_deref()
                .map(crate::protocol::WirePortableRetentionState::to_portable)
                .transpose()?;
            Ok((parsed_revs, parsed_blobs, parsed_retention, sent, recv))
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
) -> crate::error::Result<(crate::rbsr::RbsrSet, u64)> {
    let destination = request.destination.clone();
    let scope = request.scope.clone();
    let config = (request.workspace_config)();
    tokio::task::spawn_blocking(move || {
        let workspace = mneme_store::Workspace::open(&destination, config)?;
        let generation = workspace.eligibility_generation()?;
        let rbsr = crate::bundle::collect_local_rbsr_set(&workspace, &scope)?;
        Ok((rbsr, generation))
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
