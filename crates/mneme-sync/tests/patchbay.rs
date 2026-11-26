//! Deterministic Linux-namespace network fault-injection tests for `mneme-sync` using `patchbay`.
#![allow(unknown_lints, no_unwrap, assertion_density)] // test/fixture code fails by panic, not a production path
#![allow(clippy::unwrap_used, clippy::expect_used)] // test/fixture code fails by panic, not a production path

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("patchbay tests skipped: requires Linux network namespaces");
}

#[cfg(target_os = "linux")]
mod linux_tests {
    use std::net::{IpAddr, SocketAddr};
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::{Context, Result};
    use mneme_core::{
        ContentDigest, Payload, RecordId, RecordKind, RetainedSource, RevisionId, ScopeClass,
        ScopeId, SourceContent, Symbol, Timestamp, Value,
    };
    use mneme_store::{
        CommitCommand, FixedClock, NoFaults, RecordDraft, SourceBlobDraft, VerifyMode, Workspace,
        WorkspaceConfig, verify_workspace,
    };
    use mneme_sync::{
        AllowedPeer, DiscoveryMode, PeerAllowlist, PullDisposition, PullRequest, RelayPreference,
        ScopeAllowance, SharedAllowlist, SyncNode, SyncNodeConfig, WorkspaceConfigFactory,
    };
    use patchbay::{Device, Lab, LinkCondition, LinkDirection, RegionLink, RouterPreset};

    fn scope() -> ScopeId {
        ScopeId::new(ScopeClass::Project, "cedar").expect("scope")
    }

    fn fixed_config() -> WorkspaceConfig {
        WorkspaceConfig::new(
            Box::new(FixedClock::new(Timestamp::from_nanos(
                1_700_000_000_000_000_000,
            ))),
            Box::new(NoFaults),
        )
    }

    fn config_factory() -> WorkspaceConfigFactory {
        Arc::new(fixed_config)
    }

    fn deterministic_secret_key(seed: u8) -> iroh::SecretKey {
        iroh::SecretKey::from_bytes(&[seed; 32])
    }

    fn create_fixture_workspace(
        root: &Path,
        extra_blob_bytes: Option<&[u8]>,
    ) -> (Workspace, String) {
        let mut workspace = Workspace::create(root, fixed_config()).expect("create workspace");
        let genesis = workspace.current_revision().expect("genesis");
        let mut records: Vec<RecordDraft> = mneme_core::fixtures::fixture_batch()
            .iter()
            .map(|record| RecordDraft {
                schema_version: record.schema_version,
                kind: record.kind,
                record_id: record.record_id,
                revision_id: record.revision_id,
                predecessor: record.predecessor,
                scope: record.scope.clone(),
                payload: record.payload.clone(),
            })
            .collect();
        let mut source_blobs = vec![SourceBlobDraft {
            bytes: mneme_core::fixtures::SOURCE_TEXT.as_bytes().to_vec(),
            media_type: Symbol::from("text/asciidoc"),
        }];

        if let Some(extra) = extra_blob_bytes {
            let retained = RetainedSource::new(
                ContentDigest::of_source_bytes(extra),
                extra.len() as u64,
                "application/octet-stream",
            )
            .expect("retained extra");
            records.push(RecordDraft {
                schema_version: 2,
                kind: RecordKind::SourceRevision,
                record_id: RecordId::from_bytes([0x11; 16]),
                revision_id: RevisionId::from_bytes([0x22; 16]),
                predecessor: None,
                scope: scope(),
                payload: Payload::new([
                    (
                        Symbol::from("content"),
                        SourceContent::Retained(retained).to_value(),
                    ),
                    (Symbol::from("acquisition"), Value::symbol("authored")),
                    (
                        Symbol::from("path-hint"),
                        Value::string("assets/payload.bin"),
                    ),
                ]),
            });
            source_blobs.push(SourceBlobDraft {
                bytes: extra.to_vec(),
                media_type: Symbol::from("application/octet-stream"),
            });
        }

        let _outcome = workspace
            .commit(CommitCommand {
                base: genesis,
                actor: "fixture-author".to_owned(),
                scope: scope(),
                idempotency_key: "fixture-1".to_owned(),
                records,
                source_blobs,
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("commit fixture");
        let vault_id = workspace.genesis_revision().expect("genesis").to_hex();
        (workspace, vault_id)
    }

    fn commit_follow_up_source(workspace: &mut Workspace) {
        let base = workspace.current_revision().expect("base");
        let updated_bytes = b"= Cedar Notes\n\nFollow-up revision after partition heal.\n";
        let retained = RetainedSource::new(
            ContentDigest::of_source_bytes(updated_bytes),
            updated_bytes.len() as u64,
            "text/asciidoc",
        )
        .expect("retained");
        let draft = RecordDraft {
            schema_version: 2,
            kind: RecordKind::SourceRevision,
            record_id: RecordId::from_bytes([0xaa; 16]),
            revision_id: RevisionId::from_bytes([0xbb; 16]),
            predecessor: None,
            scope: scope(),
            payload: Payload::new([
                (
                    Symbol::from("content"),
                    SourceContent::Retained(retained).to_value(),
                ),
                (Symbol::from("acquisition"), Value::symbol("authored")),
                (
                    Symbol::from("path-hint"),
                    Value::string("notes/follow-up.adoc"),
                ),
            ]),
        };
        let _outcome = workspace
            .commit(CommitCommand {
                base,
                actor: "fixture-author".to_owned(),
                scope: scope(),
                idempotency_key: "fixture-2".to_owned(),
                records: vec![draft],
                source_blobs: vec![SourceBlobDraft {
                    bytes: updated_bytes.to_vec(),
                    media_type: Symbol::from("text/asciidoc"),
                }],
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("commit follow-up");
    }

    fn assert_peers_verified_equal(
        source_root: &Path,
        dest_root: &Path,
        outcome: &mneme_sync::PullOutcome,
    ) {
        let src = verify_workspace(source_root, VerifyMode::Full).expect("verify source");
        let dst = verify_workspace(dest_root, VerifyMode::Full).expect("verify dest");
        assert!(src.is_healthy(), "source verify issues: {:?}", src.issues);
        assert!(dst.is_healthy(), "dest verify issues: {:?}", dst.issues);
        assert_eq!(
            src.head_revision.as_deref(),
            Some(outcome.snapshot.head_revision.as_str()),
            "synced snapshot head_revision must match source head_revision"
        );
        assert_eq!(
            dst.head_revision.as_deref(),
            Some(outcome.local_revision.to_hex().as_str()),
            "dest verified head_revision must match local_revision"
        );
        assert_eq!(
            src.records_checked, dst.records_checked,
            "peer record counts differ (possible duplicate or missing records)"
        );
        assert_eq!(
            src.blobs_checked, dst.blobs_checked,
            "peer blob counts differ"
        );

        let src_ws = Workspace::open(source_root, fixed_config()).expect("open source");
        let dst_ws = Workspace::open(dest_root, fixed_config()).expect("open dest");
        let mut src_records = src_ws.snapshot().expect("source snapshot").records;
        let mut dst_records = dst_ws.snapshot().expect("dest snapshot").records;
        src_records.sort_by_key(|r| (r.record_id, r.revision_id));
        dst_records.sort_by_key(|r| (r.record_id, r.revision_id));
        assert_eq!(
            src_records.len(),
            dst_records.len(),
            "snapshot record counts differ"
        );
        for (a, b) in src_records.iter().zip(dst_records.iter()) {
            assert_eq!(a.record_id, b.record_id);
            assert_eq!(a.revision_id, b.revision_id);
            assert_eq!(a.kind, b.kind);
            assert_eq!(a.scope, b.scope);
            assert_eq!(a.payload, b.payload);
        }
    }

    async fn bind_node_on_device(
        dev: &Device,
        seed: u8,
        allowlist: SharedAllowlist,
        discovery: DiscoveryMode,
        relay: RelayPreference,
    ) -> Result<SyncNode> {
        let ip = dev.ip().context("device missing IPv4 address")?;
        let bind_addr = SocketAddr::new(IpAddr::V4(ip), 0);
        dev.spawn(move |_| async move {
            SyncNode::bind(SyncNodeConfig {
                secret_key: deterministic_secret_key(seed),
                allowlist,
                discovery,
                relay,
                bind_addrs: vec![bind_addr],
            })
            .await
            .map_err(|e| anyhow::anyhow!("bind SyncNode: {e}"))
        })?
        .await?
    }

    fn mutual_allow(node_a: &SyncNode, node_b: &SyncNode) {
        node_a
            .allowlist()
            .allow(AllowedPeer {
                node_id: node_b.node_id(),
                label: Some("peer-b".to_owned()),
                allowance: ScopeAllowance::from_scopes([scope()]),
            })
            .expect("allow b");
        node_b
            .allowlist()
            .allow(AllowedPeer {
                node_id: node_a.node_id(),
                label: Some("peer-a".to_owned()),
                allowance: ScopeAllowance::from_scopes([scope()]),
            })
            .expect("allow a");
    }

    async fn shutdown_nodes(
        dev_a: &Device,
        node_a: SyncNode,
        dev_b: &Device,
        node_b: SyncNode,
    ) -> Result<()> {
        dev_a
            .spawn(move |_| async move {
                node_a
                    .shutdown()
                    .await
                    .map_err(|e| anyhow::anyhow!("shutdown a: {e}"))
            })?
            .await??;
        dev_b
            .spawn(move |_| async move {
                node_b
                    .shutdown()
                    .await
                    .map_err(|e| anyhow::anyhow!("shutdown b: {e}"))
            })?
            .await??;
        Ok(())
    }

    fn deterministic_payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| ((i * 31 + 17) & 0xff) as u8).collect()
    }

    /// Scenario 1: Direct LAN sync on a shared router with relay disabled.
    async fn scenario_direct_lan_sync() -> Result<()> {
        let lab = Lab::new().await?;
        let lan = lab
            .add_router("lan")
            .preset(RouterPreset::Public)
            .build()
            .await?;
        let dev_a = lab
            .add_device("peer-a")
            .iface("eth0", lan.id())
            .build()
            .await?;
        let dev_b = lab
            .add_device("peer-b")
            .iface("eth0", lan.id())
            .build()
            .await?;

        let temp = tempfile::tempdir()?;
        let source_root = temp.path().join("peer-a");
        let dest_root = temp.path().join("peer-b");
        let dest_state = temp.path().join("peer-b-state");
        let (source_ws, vault_id) = create_fixture_workspace(&source_root, None);

        let allow_a = SharedAllowlist::new(PeerAllowlist::new());
        let allow_b = SharedAllowlist::new(PeerAllowlist::new());
        let node_a = bind_node_on_device(
            &dev_a,
            11,
            allow_a,
            DiscoveryMode::MdnsOnly,
            RelayPreference::Disabled,
        )
        .await?;
        let node_b = bind_node_on_device(
            &dev_b,
            12,
            allow_b,
            DiscoveryMode::MdnsOnly,
            RelayPreference::Disabled,
        )
        .await?;
        mutual_allow(&node_a, &node_b);

        node_a.add_peer_addr(node_b.addr());
        node_b.add_peer_addr(node_a.addr());

        node_a
            .publish_workspace(&source_ws, &vault_id, &scope())
            .await
            .map_err(|e| anyhow::anyhow!("publish: {e}"))?;

        let node_b_pull = node_b.clone();
        let peer_a_id = node_a.node_id();
        let dest_root_c = dest_root.clone();
        let dest_state_c = dest_state.clone();
        let outcome = dev_b
            .spawn(move |_| async move {
                node_b_pull
                    .pull_scope(PullRequest {
                        peer: peer_a_id,
                        scope: scope(),
                        destination: dest_root_c,
                        state_dir: Some(dest_state_c),
                        workspace_config: config_factory(),
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("pull: {e}"))
            })?
            .await??;
        assert_eq!(outcome.disposition, PullDisposition::Restored);
        assert_peers_verified_equal(&source_root, &dest_root, &outcome);

        shutdown_nodes(&dev_a, node_a, &dev_b, node_b).await?;
        Ok(())
    }

    /// Scenario 2: NAT/router traversal (peer-b behind Home NAT + firewall pulls from peer-a on Public DC).
    async fn scenario_nat_traversal() -> Result<()> {
        let lab = Lab::new().await?;
        let dc = lab
            .add_router("dc")
            .preset(RouterPreset::Public)
            .build()
            .await?;
        let home = lab
            .add_router("home")
            .preset(RouterPreset::Home)
            .build()
            .await?;
        let dev_a = lab
            .add_device("peer-a")
            .iface("eth0", dc.id())
            .build()
            .await?;
        let dev_b = lab
            .add_device("peer-b")
            .iface("eth0", home.id())
            .build()
            .await?;

        let temp = tempfile::tempdir()?;
        let source_root = temp.path().join("peer-a");
        let dest_root = temp.path().join("peer-b");
        let (source_ws, vault_id) = create_fixture_workspace(&source_root, None);

        let allow_a = SharedAllowlist::new(PeerAllowlist::new());
        let allow_b = SharedAllowlist::new(PeerAllowlist::new());
        let node_a = bind_node_on_device(
            &dev_a,
            21,
            allow_a,
            DiscoveryMode::OfflineLoopback,
            RelayPreference::Disabled,
        )
        .await?;
        let node_b = bind_node_on_device(
            &dev_b,
            22,
            allow_b,
            DiscoveryMode::OfflineLoopback,
            RelayPreference::Disabled,
        )
        .await?;
        mutual_allow(&node_a, &node_b);
        node_b.add_peer_addr(node_a.addr());

        node_a
            .publish_workspace(&source_ws, &vault_id, &scope())
            .await
            .map_err(|e| anyhow::anyhow!("publish: {e}"))?;

        let node_b_pull = node_b.clone();
        let peer_a_id = node_a.node_id();
        let dest_root_c = dest_root.clone();
        let outcome = dev_b
            .spawn(move |_| async move {
                node_b_pull
                    .pull_scope(PullRequest {
                        peer: peer_a_id,
                        scope: scope(),
                        destination: dest_root_c,
                        state_dir: None,
                        workspace_config: config_factory(),
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("pull over NAT: {e}"))
            })?
            .await??;
        assert_eq!(outcome.disposition, PullDisposition::Restored);
        assert_peers_verified_equal(&source_root, &dest_root, &outcome);

        shutdown_nodes(&dev_a, node_a, &dev_b, node_b).await?;
        Ok(())
    }

    /// Scenario 3: Packet loss and added latency via tc netem.
    async fn scenario_packet_loss_and_latency() -> Result<()> {
        let lab = Lab::new().await?;
        let dc_a = lab
            .add_router("dc-a")
            .preset(RouterPreset::Public)
            .build()
            .await?;
        let dc_b = lab
            .add_router("dc-b")
            .preset(RouterPreset::Public)
            .build()
            .await?;
        let dev_a = lab
            .add_device("peer-a")
            .iface("eth0", dc_a.id())
            .build()
            .await?;
        let dev_b = lab
            .add_device("peer-b")
            .iface("eth0", dc_b.id())
            .build()
            .await?;

        dev_b
            .iface("eth0")
            .context("eth0")?
            .set_condition(
                LinkCondition::new()
                    .latency_ms(60)
                    .jitter_ms(15)
                    .loss_pct(5.0),
                LinkDirection::Both,
            )
            .await?;

        let temp = tempfile::tempdir()?;
        let source_root = temp.path().join("peer-a");
        let dest_root = temp.path().join("peer-b");
        let payload = deterministic_payload(256 * 1024);
        let (source_ws, vault_id) = create_fixture_workspace(&source_root, Some(&payload));

        let allow_a = SharedAllowlist::new(PeerAllowlist::new());
        let allow_b = SharedAllowlist::new(PeerAllowlist::new());
        let node_a = bind_node_on_device(
            &dev_a,
            31,
            allow_a,
            DiscoveryMode::OfflineLoopback,
            RelayPreference::Disabled,
        )
        .await?;
        let node_b = bind_node_on_device(
            &dev_b,
            32,
            allow_b,
            DiscoveryMode::OfflineLoopback,
            RelayPreference::Disabled,
        )
        .await?;
        mutual_allow(&node_a, &node_b);
        node_b.add_peer_addr(node_a.addr());

        node_a
            .publish_workspace(&source_ws, &vault_id, &scope())
            .await
            .map_err(|e| anyhow::anyhow!("publish: {e}"))?;

        let node_b_pull = node_b.clone();
        let peer_a_id = node_a.node_id();
        let dest_root_c = dest_root.clone();
        let outcome = dev_b
            .spawn(move |_| async move {
                node_b_pull
                    .pull_scope(PullRequest {
                        peer: peer_a_id,
                        scope: scope(),
                        destination: dest_root_c,
                        state_dir: None,
                        workspace_config: config_factory(),
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("pull under loss/latency: {e}"))
            })?
            .await??;
        assert_eq!(outcome.disposition, PullDisposition::Restored);
        assert_peers_verified_equal(&source_root, &dest_root, &outcome);

        shutdown_nodes(&dev_a, node_a, &dev_b, node_b).await?;
        Ok(())
    }

    /// Scenario 4: Mid-transfer disconnect followed by idempotent resume.
    async fn scenario_mid_transfer_disconnect_and_resume() -> Result<()> {
        let lab = Lab::new().await?;
        let dc_a = lab
            .add_router("dc-a")
            .preset(RouterPreset::Public)
            .build()
            .await?;
        let dc_b = lab
            .add_router("dc-b")
            .preset(RouterPreset::Public)
            .build()
            .await?;
        let dev_a = lab
            .add_device("peer-a")
            .iface("eth0", dc_a.id())
            .build()
            .await?;
        let dev_b = lab
            .add_device("peer-b")
            .iface("eth0", dc_b.id())
            .build()
            .await?;

        // Throttle link so a 2 MiB transfer stays in-flight long enough to cut mid-stream.
        let iface_b = dev_b.iface("eth0").context("eth0")?;
        iface_b
            .set_condition(
                LinkCondition::new().rate_kbit(500).latency_ms(20),
                LinkDirection::Both,
            )
            .await?;

        let temp = tempfile::tempdir()?;
        let source_root = temp.path().join("peer-a");
        let dest_root = temp.path().join("peer-b");
        let dest_state = temp.path().join("peer-b-state");
        let payload = deterministic_payload(2 * 1024 * 1024);
        let (source_ws, vault_id) = create_fixture_workspace(&source_root, Some(&payload));

        let allow_a = SharedAllowlist::new(PeerAllowlist::new());
        let allow_b = SharedAllowlist::new(PeerAllowlist::new());
        let node_a = bind_node_on_device(
            &dev_a,
            41,
            allow_a,
            DiscoveryMode::OfflineLoopback,
            RelayPreference::Disabled,
        )
        .await?;
        let node_b = bind_node_on_device(
            &dev_b,
            42,
            allow_b,
            DiscoveryMode::OfflineLoopback,
            RelayPreference::Disabled,
        )
        .await?;
        mutual_allow(&node_a, &node_b);
        node_b.add_peer_addr(node_a.addr());

        node_a
            .publish_workspace(&source_ws, &vault_id, &scope())
            .await
            .map_err(|e| anyhow::anyhow!("publish: {e}"))?;

        let node_b_pull = node_b.clone();
        let peer_a_id = node_a.node_id();
        let dest_root_c = dest_root.clone();
        let dest_state_c = dest_state.clone();
        let pull_task = dev_b.spawn(move |_| async move {
            tokio::time::timeout(
                Duration::from_secs(4),
                node_b_pull.pull_scope(PullRequest {
                    peer: peer_a_id,
                    scope: scope(),
                    destination: dest_root_c,
                    state_dir: Some(dest_state_c),
                    workspace_config: config_factory(),
                }),
            )
            .await
        })?;

        tokio::time::sleep(Duration::from_millis(250)).await;
        iface_b.link_down().await?;

        let interrupted = pull_task.await?;
        match interrupted {
            Err(_elapsed) => {}
            Ok(Err(_sync_err)) => {}
            Ok(Ok(outcome)) => {
                anyhow::bail!("expected mid-transfer disconnect, but pull completed: {outcome:?}");
            }
        }
        assert!(
            !dest_root.exists(),
            "failed pull must not leave partial destination workspace"
        );

        // Restore link, remove throttle, and resume cleanly.
        iface_b.link_up().await?;
        iface_b
            .set_condition(LinkCondition::default(), LinkDirection::Both)
            .await?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let node_b_resume = node_b.clone();
        let dest_root_r = dest_root.clone();
        let dest_state_r = dest_state.clone();
        let resumed = dev_b
            .spawn(move |_| async move {
                node_b_resume
                    .pull_scope(PullRequest {
                        peer: peer_a_id,
                        scope: scope(),
                        destination: dest_root_r,
                        state_dir: Some(dest_state_r),
                        workspace_config: config_factory(),
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("resumed pull: {e}"))
            })?
            .await??;
        assert_eq!(resumed.disposition, PullDisposition::Restored);

        // Idempotent re-pull after resume.
        let node_b_idem = node_b.clone();
        let dest_root_i = dest_root.clone();
        let dest_state_i = dest_state.clone();
        let repull = dev_b
            .spawn(move |_| async move {
                node_b_idem
                    .pull_scope(PullRequest {
                        peer: peer_a_id,
                        scope: scope(),
                        destination: dest_root_i,
                        state_dir: Some(dest_state_i),
                        workspace_config: config_factory(),
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("idempotent repull: {e}"))
            })?
            .await??;
        assert_eq!(repull.disposition, PullDisposition::AlreadyUpToDate);
        assert_peers_verified_equal(&source_root, &dest_root, &repull);

        shutdown_nodes(&dev_a, node_a, &dev_b, node_b).await?;
        Ok(())
    }

    /// Scenario 5: Region-level network partition and heal.
    async fn scenario_network_partition_and_heal() -> Result<()> {
        let lab = Lab::new().await?;
        let eu = lab.add_region("eu").await?;
        let us = lab.add_region("us").await?;
        lab.link_regions(&eu, &us, RegionLink::good(20)).await?;

        let dc_eu = lab
            .add_router("dc-eu")
            .region(&eu)
            .preset(RouterPreset::Public)
            .build()
            .await?;
        let dc_us = lab
            .add_router("dc-us")
            .region(&us)
            .preset(RouterPreset::Public)
            .build()
            .await?;

        let dev_a = lab
            .add_device("peer-a")
            .iface("eth0", dc_eu.id())
            .build()
            .await?;
        let dev_b = lab
            .add_device("peer-b")
            .iface("eth0", dc_us.id())
            .build()
            .await?;

        let temp = tempfile::tempdir()?;
        let source_root = temp.path().join("peer-a");
        let dest_root = temp.path().join("peer-b");
        let dest_state = temp.path().join("peer-b-state");
        let (mut source_ws, vault_id) = create_fixture_workspace(&source_root, None);

        let allow_a = SharedAllowlist::new(PeerAllowlist::new());
        let allow_b = SharedAllowlist::new(PeerAllowlist::new());
        let node_a = bind_node_on_device(
            &dev_a,
            51,
            allow_a,
            DiscoveryMode::OfflineLoopback,
            RelayPreference::Disabled,
        )
        .await?;
        let node_b = bind_node_on_device(
            &dev_b,
            52,
            allow_b,
            DiscoveryMode::OfflineLoopback,
            RelayPreference::Disabled,
        )
        .await?;
        mutual_allow(&node_a, &node_b);
        node_b.add_peer_addr(node_a.addr());

        // 1. Initial sync before partition.
        node_a
            .publish_workspace(&source_ws, &vault_id, &scope())
            .await
            .map_err(|e| anyhow::anyhow!("publish 1: {e}"))?;

        let node_b_pull1 = node_b.clone();
        let peer_a_id = node_a.node_id();
        let dest_root_1 = dest_root.clone();
        let dest_state_1 = dest_state.clone();
        let initial = dev_b
            .spawn(move |_| async move {
                node_b_pull1
                    .pull_scope(PullRequest {
                        peer: peer_a_id,
                        scope: scope(),
                        destination: dest_root_1,
                        state_dir: Some(dest_state_1),
                        workspace_config: config_factory(),
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("initial pull: {e}"))
            })?
            .await??;
        assert_eq!(initial.disposition, PullDisposition::Restored);
        assert_peers_verified_equal(&source_root, &dest_root, &initial);

        // 2. Partition EU <-> US (100% packet drop while both endpoints stay up) and commit on peer-a.
        let iface_b = dev_b.iface("eth0").context("eth0")?;
        iface_b
            .set_condition(LinkCondition::new().loss_pct(100.0), LinkDirection::Both)
            .await?;
        commit_follow_up_source(&mut source_ws);

        node_a
            .publish_workspace(&source_ws, &vault_id, &scope())
            .await
            .map_err(|e| anyhow::anyhow!("publish 2: {e}"))?;

        // 3. Pull during partition must fail/timeout without corrupting peer-b.
        let node_b_part = node_b.clone();
        let dest_root_p = dest_root.clone();
        let dest_state_p = dest_state.clone();
        let partitioned_pull = dev_b
            .spawn(move |_| async move {
                tokio::time::timeout(
                    Duration::from_secs(2),
                    node_b_part.pull_scope(PullRequest {
                        peer: peer_a_id,
                        scope: scope(),
                        destination: dest_root_p,
                        state_dir: Some(dest_state_p),
                        workspace_config: config_factory(),
                    }),
                )
                .await
            })?
            .await?;
        match partitioned_pull {
            Err(_elapsed) => {}
            Ok(Err(_sync_err)) => {}
            Ok(Ok(outcome)) => {
                anyhow::bail!("expected partitioned pull to fail, got: {outcome:?}");
            }
        }
        let mid_verify = verify_workspace(&dest_root, VerifyMode::Full)?;
        assert!(mid_verify.is_healthy());
        assert_eq!(
            mid_verify.head_revision.as_deref(),
            Some(initial.local_revision.to_hex().as_str())
        );

        // 4. Heal partition and verify peer-b converges cleanly.
        iface_b
            .set_condition(LinkCondition::default(), LinkDirection::Both)
            .await?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let node_b_heal = node_b.clone();
        let dest_root_h = dest_root.clone();
        let dest_state_h = dest_state.clone();
        let healed = dev_b
            .spawn(move |_| async move {
                node_b_heal
                    .pull_scope(PullRequest {
                        peer: peer_a_id,
                        scope: scope(),
                        destination: dest_root_h,
                        state_dir: Some(dest_state_h),
                        workspace_config: config_factory(),
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("healed pull: {e}"))
            })?
            .await??;
        assert_eq!(healed.disposition, PullDisposition::Updated);
        assert_peers_verified_equal(&source_root, &dest_root, &healed);

        shutdown_nodes(&dev_a, node_a, &dev_b, node_b).await?;
        Ok(())
    }

    fn tool_available(cmd: &str, arg: &str) -> bool {
        std::process::Command::new(cmd)
            .arg(arg)
            .output()
            .is_ok_and(|out| out.status.success())
    }

    pub fn run() {
        if let Err(err) = patchbay::init_userns() {
            eprintln!("patchbay tests skipped: user namespaces unavailable ({err})");
            return;
        }
        if let Err(err) = patchbay::check_caps() {
            eprintln!("patchbay tests skipped: missing namespace capabilities ({err})");
            return;
        }
        if !tool_available("nft", "--version") || !tool_available("tc", "-V") {
            eprintln!("patchbay tests skipped: nft or tc not available in PATH");
            return;
        }

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");

        rt.block_on(async {
            scenario_direct_lan_sync()
                .await
                .expect("scenario_direct_lan_sync");
            eprintln!("patchbay scenario_direct_lan_sync ... ok");

            scenario_nat_traversal()
                .await
                .expect("scenario_nat_traversal");
            eprintln!("patchbay scenario_nat_traversal ... ok");

            scenario_packet_loss_and_latency()
                .await
                .expect("scenario_packet_loss_and_latency");
            eprintln!("patchbay scenario_packet_loss_and_latency ... ok");

            scenario_mid_transfer_disconnect_and_resume()
                .await
                .expect("scenario_mid_transfer_disconnect_and_resume");
            eprintln!("patchbay scenario_mid_transfer_disconnect_and_resume ... ok");

            scenario_network_partition_and_heal()
                .await
                .expect("scenario_network_partition_and_heal");
            eprintln!("patchbay scenario_network_partition_and_heal ... ok");
        });
    }
}

#[cfg(target_os = "linux")]
fn main() {
    linux_tests::run();
}
