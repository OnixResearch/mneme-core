//! Deterministic Linux-namespace network fault-injection tests for `mneme-sync` using `patchbay`.
#![allow(unknown_lints, no_unwrap, assertion_density)] // test/fixture code fails by panic, not a production path
#![allow(clippy::unwrap_used, clippy::expect_used)] // test/fixture code fails by panic, not a production path

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("patchbay tests skipped: requires Linux network namespaces");
}

#[cfg(target_os = "linux")]
mod linux_tests {
    use anyhow::Context as _;

    struct ToolProbe {
        cmd: &'static str,
        arg: &'static str,
    }

    impl ToolProbe {
        fn is_available(&self) -> bool {
            std::process::Command::new(self.cmd)
                .arg(self.arg)
                .output()
                .is_ok_and(|out| out.status.success())
        }
    }

    struct PeerPair {
        dev_a: patchbay::Device,
        dev_b: patchbay::Device,
        node_a: mneme_sync::SyncNode,
        node_b: mneme_sync::SyncNode,
    }

    fn scope() -> mneme_core::ScopeId {
        mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
    }

    fn fixed_config() -> mneme_store::WorkspaceConfig {
        mneme_store::WorkspaceConfig::new(
            Box::new(mneme_store::FixedClock::new(
                mneme_core::Timestamp::from_nanos(1_700_000_000_000_000_000),
            )),
            Box::new(mneme_store::NoFaults),
        )
    }

    fn config_factory() -> mneme_sync::WorkspaceConfigFactory {
        std::sync::Arc::new(fixed_config)
    }

    fn deterministic_secret_key(seed: u8) -> iroh::SecretKey {
        iroh::SecretKey::from_bytes(&[seed; 32])
    }

    fn deterministic_payload(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| u8::try_from(i % 251).expect("mod 251 fits in u8"))
            .collect()
    }

    fn create_fixture_workspace(
        root: &std::path::Path,
        extra_blob_bytes: Option<&[u8]>,
    ) -> (mneme_store::Workspace, String) {
        let mut workspace =
            mneme_store::Workspace::create(root, fixed_config()).expect("create workspace");
        let genesis = workspace.current_revision().expect("genesis");
        let mut records: Vec<mneme_store::RecordDraft> = mneme_core::fixtures::fixture_batch()
            .iter()
            .map(|record| mneme_store::RecordDraft {
                schema_version: record.schema_version,
                kind: record.kind,
                record_id: record.record_id,
                revision_id: record.revision_id,
                predecessor: record.predecessor,
                scope: record.scope.clone(),
                payload: record.payload.clone(),
            })
            .collect();
        let mut source_blobs = vec![mneme_store::SourceBlobDraft::inline(
            mneme_core::fixtures::SOURCE_TEXT.as_bytes().to_vec(),
            mneme_core::Symbol::from("text/asciidoc"),
        )];

        if let Some(extra) = extra_blob_bytes {
            let retained = mneme_core::RetainedSource::new(
                mneme_core::ContentDigest::of_source_bytes(extra),
                extra.len() as u64,
                "application/octet-stream",
            )
            .expect("retained extra");
            records.push(mneme_store::RecordDraft {
                schema_version: 2,
                kind: mneme_core::RecordKind::SourceRevision,
                record_id: mneme_core::RecordId::from_bytes([0x11; 16]),
                revision_id: mneme_core::RevisionId::from_bytes([0x22; 16]),
                predecessor: None,
                scope: scope(),
                payload: mneme_core::Payload::new([
                    (
                        mneme_core::Symbol::from("content"),
                        mneme_core::SourceContent::Retained(retained).to_value(),
                    ),
                    (
                        mneme_core::Symbol::from("acquisition"),
                        mneme_core::Value::symbol("authored"),
                    ),
                    (
                        mneme_core::Symbol::from("path-hint"),
                        mneme_core::Value::string("assets/payload.bin"),
                    ),
                ]),
            });
            source_blobs.push(mneme_store::SourceBlobDraft::inline(
                extra.to_vec(),
                mneme_core::Symbol::from("application/octet-stream"),
            ));
        }

        let _outcome = workspace
            .commit(mneme_store::CommitCommand {
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

    fn commit_follow_up_source(workspace: &mut mneme_store::Workspace) {
        let base = workspace.current_revision().expect("base");
        let updated_bytes = b"= Cedar Notes\n\nFollow-up revision after partition heal.\n";
        let retained = mneme_core::RetainedSource::new(
            mneme_core::ContentDigest::of_source_bytes(updated_bytes),
            updated_bytes.len() as u64,
            "text/asciidoc",
        )
        .expect("retained");
        let draft = mneme_store::RecordDraft {
            schema_version: 2,
            kind: mneme_core::RecordKind::SourceRevision,
            record_id: mneme_core::RecordId::from_bytes([0xaa; 16]),
            revision_id: mneme_core::RevisionId::from_bytes([0xbb; 16]),
            predecessor: None,
            scope: scope(),
            payload: mneme_core::Payload::new([
                (
                    mneme_core::Symbol::from("content"),
                    mneme_core::SourceContent::Retained(retained).to_value(),
                ),
                (
                    mneme_core::Symbol::from("acquisition"),
                    mneme_core::Value::symbol("authored"),
                ),
                (
                    mneme_core::Symbol::from("path-hint"),
                    mneme_core::Value::string("notes/follow-up.adoc"),
                ),
            ]),
        };
        let _outcome = workspace
            .commit(mneme_store::CommitCommand {
                base,
                actor: "fixture-author".to_owned(),
                scope: scope(),
                idempotency_key: "fixture-2".to_owned(),
                records: vec![draft],
                source_blobs: vec![mneme_store::SourceBlobDraft::inline(
                    updated_bytes.to_vec(),
                    mneme_core::Symbol::from("text/asciidoc"),
                )],
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("commit follow-up");
    }

    fn assert_peers_verified_equal(
        source_root: &std::path::Path,
        dest_root: &std::path::Path,
        outcome: &mneme_sync::PullOutcome,
    ) {
        let src = mneme_store::verify_workspace(source_root, mneme_store::VerifyMode::Full)
            .expect("verify source");
        let dst = mneme_store::verify_workspace(dest_root, mneme_store::VerifyMode::Full)
            .expect("verify dest");
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

        let src_ws = mneme_store::Workspace::open(source_root, fixed_config()).expect("open src");
        let dst_ws = mneme_store::Workspace::open(dest_root, fixed_config()).expect("open dst");
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
        dev: &patchbay::Device,
        seed: u8,
        discovery: mneme_sync::DiscoveryMode,
        relay: mneme_sync::RelayPreference,
    ) -> anyhow::Result<mneme_sync::SyncNode> {
        let ip = dev.ip().context("device missing IPv4 address")?;
        let bind_addr = std::net::SocketAddr::new(std::net::IpAddr::V4(ip), 0);
        let allowlist = mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new());
        let clock: std::sync::Arc<dyn mneme_store::Clock> =
            std::sync::Arc::new(mneme_store::FixedClock::new(
                mneme_core::Timestamp::from_nanos(1_700_000_000_000_000_000),
            ));
        dev.spawn(move |_| async move {
            mneme_sync::SyncNode::bind(mneme_sync::SyncNodeConfig {
                secret_key: deterministic_secret_key(seed),
                allowlist,
                revocations: mneme_sync::SharedRevocationSet::new(mneme_sync::RevocationSet::new()),
                trusted_roots: std::collections::BTreeSet::new(),
                clock,
                discovery,
                relay,
                bind_addrs: vec![bind_addr],
            })
            .await
            .map_err(|e| anyhow::anyhow!("bind SyncNode: {e}"))
        })?
        .await?
    }

    async fn bind_pair(
        dev_a: patchbay::Device,
        dev_b: patchbay::Device,
        seed_base: u8,
        discovery: mneme_sync::DiscoveryMode,
    ) -> anyhow::Result<PeerPair> {
        let node_a = bind_node_on_device(
            &dev_a,
            seed_base,
            discovery,
            mneme_sync::RelayPreference::Disabled,
        )
        .await?;
        let node_b = bind_node_on_device(
            &dev_b,
            seed_base.saturating_add(1),
            discovery,
            mneme_sync::RelayPreference::Disabled,
        )
        .await?;
        node_a
            .allowlist()
            .allow(mneme_sync::AllowedPeer {
                node_id: node_b.node_id(),
                label: Some("peer-b".to_owned()),
                allowance: mneme_sync::ScopeAllowance::from_scopes([scope()]),
            })
            .expect("allow b");
        node_b
            .allowlist()
            .allow(mneme_sync::AllowedPeer {
                node_id: node_a.node_id(),
                label: Some("peer-a".to_owned()),
                allowance: mneme_sync::ScopeAllowance::from_scopes([scope()]),
            })
            .expect("allow a");
        node_b.add_peer_addr(node_a.addr());
        Ok(PeerPair {
            dev_a,
            dev_b,
            node_a,
            node_b,
        })
    }

    async fn pull_on_device(
        pair: &PeerPair,
        dest_root: &std::path::Path,
        state_dir: Option<&std::path::Path>,
    ) -> anyhow::Result<mneme_sync::PullOutcome> {
        let node_b = pair.node_b.clone();
        let peer_a_id = pair.node_a.node_id();
        let dest = dest_root.to_path_buf();
        let state = state_dir.map(std::path::Path::to_path_buf);
        pair.dev_b
            .spawn(move |_| async move {
                node_b
                    .pull_scope(mneme_sync::PullRequest {
                        peer: peer_a_id,
                        scope: scope(),
                        destination: dest,
                        state_dir: state,
                        workspace_config: config_factory(),
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("pull: {e}"))
            })?
            .await?
    }

    fn pull_expect_interrupted(
        pair: &PeerPair,
        dest_root: &std::path::Path,
        state_dir: Option<&std::path::Path>,
        timeout: std::time::Duration,
    ) -> anyhow::Result<tokio::task::JoinHandle<anyhow::Result<()>>> {
        let node_b = pair.node_b.clone();
        let peer_a_id = pair.node_a.node_id();
        let dest = dest_root.to_path_buf();
        let state = state_dir.map(std::path::Path::to_path_buf);
        pair.dev_b.spawn(move |_| async move {
            let res = tokio::time::timeout(
                timeout,
                node_b.pull_scope(mneme_sync::PullRequest {
                    peer: peer_a_id,
                    scope: scope(),
                    destination: dest,
                    state_dir: state,
                    workspace_config: config_factory(),
                }),
            )
            .await;
            if let Ok(Ok(outcome)) = res {
                anyhow::bail!("expected interrupted pull to fail, got: {outcome:?}");
            }
            Ok(())
        })
    }

    async fn shutdown_pair(pair: PeerPair) -> anyhow::Result<()> {
        let node_a = pair.node_a;
        let node_b = pair.node_b;
        pair.dev_a
            .spawn(move |_| async move {
                node_a
                    .shutdown()
                    .await
                    .map_err(|e| anyhow::anyhow!("shutdown a: {e}"))
            })?
            .await??;
        pair.dev_b
            .spawn(move |_| async move {
                node_b
                    .shutdown()
                    .await
                    .map_err(|e| anyhow::anyhow!("shutdown b: {e}"))
            })?
            .await??;
        Ok(())
    }

    /// Scenario 1: Direct LAN sync on a shared router with relay disabled.
    async fn scenario_direct_lan_sync() -> anyhow::Result<()> {
        let lab = patchbay::Lab::new().await?;
        let lan = lab
            .add_router("lan")
            .preset(patchbay::RouterPreset::Public)
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

        let pair = bind_pair(dev_a, dev_b, 11, mneme_sync::DiscoveryMode::MdnsOnly).await?;
        pair.node_a.add_peer_addr(pair.node_b.addr());
        pair.node_a
            .publish_workspace(&source_ws, &vault_id, &scope())
            .await
            .map_err(|e| anyhow::anyhow!("publish: {e}"))?;

        let outcome = pull_on_device(&pair, &dest_root, Some(&dest_state)).await?;
        assert_eq!(outcome.disposition, mneme_sync::PullDisposition::Restored);
        assert_peers_verified_equal(&source_root, &dest_root, &outcome);

        shutdown_pair(pair).await
    }

    /// Scenario 2: NAT/router traversal (peer-b behind Home NAT + firewall pulls from peer-a on Public DC).
    async fn scenario_nat_traversal() -> anyhow::Result<()> {
        let lab = patchbay::Lab::new().await?;
        let dc = lab
            .add_router("dc")
            .preset(patchbay::RouterPreset::Public)
            .build()
            .await?;
        let home = lab
            .add_router("home")
            .preset(patchbay::RouterPreset::Home)
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

        let pair = bind_pair(dev_a, dev_b, 21, mneme_sync::DiscoveryMode::OfflineLoopback).await?;
        pair.node_a
            .publish_workspace(&source_ws, &vault_id, &scope())
            .await
            .map_err(|e| anyhow::anyhow!("publish: {e}"))?;

        let outcome = pull_on_device(&pair, &dest_root, None).await?;
        assert_eq!(outcome.disposition, mneme_sync::PullDisposition::Restored);
        assert_peers_verified_equal(&source_root, &dest_root, &outcome);

        shutdown_pair(pair).await
    }

    /// Scenario 3: Packet loss and added latency via tc netem.
    async fn scenario_packet_loss_and_latency() -> anyhow::Result<()> {
        let lab = patchbay::Lab::new().await?;
        let dc_a = lab
            .add_router("dc-a")
            .preset(patchbay::RouterPreset::Public)
            .build()
            .await?;
        let dc_b = lab
            .add_router("dc-b")
            .preset(patchbay::RouterPreset::Public)
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
                patchbay::LinkCondition::new()
                    .latency_ms(60)
                    .jitter_ms(15)
                    .loss_pct(5.0),
                patchbay::LinkDirection::Both,
            )
            .await?;

        let temp = tempfile::tempdir()?;
        let source_root = temp.path().join("peer-a");
        let dest_root = temp.path().join("peer-b");
        let payload = deterministic_payload(256 * 1024);
        let (source_ws, vault_id) = create_fixture_workspace(&source_root, Some(&payload));

        let pair = bind_pair(dev_a, dev_b, 31, mneme_sync::DiscoveryMode::OfflineLoopback).await?;
        pair.node_a
            .publish_workspace(&source_ws, &vault_id, &scope())
            .await
            .map_err(|e| anyhow::anyhow!("publish: {e}"))?;

        let outcome = pull_on_device(&pair, &dest_root, None).await?;
        assert_eq!(outcome.disposition, mneme_sync::PullDisposition::Restored);
        assert_peers_verified_equal(&source_root, &dest_root, &outcome);

        shutdown_pair(pair).await
    }

    async fn run_disconnect_and_resume(
        pair: &PeerPair,
        iface_b: &patchbay::Iface,
        source_root: &std::path::Path,
        dest_root: &std::path::Path,
        dest_state: &std::path::Path,
    ) -> anyhow::Result<()> {
        let pull_task = pull_expect_interrupted(
            pair,
            dest_root,
            Some(dest_state),
            std::time::Duration::from_secs(4),
        )?;
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        iface_b.link_down().await?;

        pull_task.await??;
        assert!(
            !dest_root.exists(),
            "failed pull must not leave partial destination workspace"
        );

        iface_b.link_up().await?;
        iface_b
            .set_condition(
                patchbay::LinkCondition::new(),
                patchbay::LinkDirection::Both,
            )
            .await?;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let resumed = pull_on_device(pair, dest_root, Some(dest_state)).await?;
        assert_eq!(resumed.disposition, mneme_sync::PullDisposition::Restored);

        let repull = pull_on_device(pair, dest_root, Some(dest_state)).await?;
        assert_eq!(
            repull.disposition,
            mneme_sync::PullDisposition::AlreadyUpToDate
        );
        assert_peers_verified_equal(source_root, dest_root, &repull);
        Ok(())
    }

    /// Scenario 4: Mid-transfer disconnect followed by idempotent resume.
    async fn scenario_mid_transfer_disconnect_and_resume() -> anyhow::Result<()> {
        let lab = patchbay::Lab::new().await?;
        let dc_a = lab
            .add_router("dc-a")
            .preset(patchbay::RouterPreset::Public)
            .build()
            .await?;
        let dc_b = lab
            .add_router("dc-b")
            .preset(patchbay::RouterPreset::Public)
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

        let iface_b = dev_b.iface("eth0").context("eth0")?;
        iface_b
            .set_condition(
                patchbay::LinkCondition::new().rate_kbit(500).latency_ms(20),
                patchbay::LinkDirection::Both,
            )
            .await?;

        let temp = tempfile::tempdir()?;
        let source_root = temp.path().join("peer-a");
        let dest_root = temp.path().join("peer-b");
        let dest_state = temp.path().join("peer-b-state");
        let payload = deterministic_payload(2 * 1024 * 1024);
        let (source_ws, vault_id) = create_fixture_workspace(&source_root, Some(&payload));

        let pair = bind_pair(dev_a, dev_b, 41, mneme_sync::DiscoveryMode::OfflineLoopback).await?;
        pair.node_a
            .publish_workspace(&source_ws, &vault_id, &scope())
            .await
            .map_err(|e| anyhow::anyhow!("publish: {e}"))?;

        run_disconnect_and_resume(&pair, &iface_b, &source_root, &dest_root, &dest_state).await?;
        shutdown_pair(pair).await
    }

    struct SyncDirs {
        source_root: std::path::PathBuf,
        dest_root: std::path::PathBuf,
        dest_state: std::path::PathBuf,
    }

    async fn run_partition_and_heal(
        pair: &PeerPair,
        source_ws: &mut mneme_store::Workspace,
        vault_id: &str,
        dirs: &SyncDirs,
    ) -> anyhow::Result<()> {
        let initial = pull_on_device(pair, &dirs.dest_root, Some(&dirs.dest_state)).await?;
        assert_eq!(initial.disposition, mneme_sync::PullDisposition::Restored);
        assert_peers_verified_equal(&dirs.source_root, &dirs.dest_root, &initial);

        let iface_b = pair.dev_b.iface("eth0").context("eth0")?;
        iface_b
            .set_condition(
                patchbay::LinkCondition::new().loss_pct(100.0),
                patchbay::LinkDirection::Both,
            )
            .await?;
        commit_follow_up_source(source_ws);
        pair.node_a
            .publish_workspace(source_ws, vault_id, &scope())
            .await
            .map_err(|e| anyhow::anyhow!("publish 2: {e}"))?;

        let part_task = pull_expect_interrupted(
            pair,
            &dirs.dest_root,
            Some(&dirs.dest_state),
            std::time::Duration::from_secs(2),
        )?;
        part_task.await??;
        let mid_verify =
            mneme_store::verify_workspace(&dirs.dest_root, mneme_store::VerifyMode::Full)?;
        assert!(mid_verify.is_healthy());
        assert_eq!(
            mid_verify.head_revision.as_deref(),
            Some(initial.local_revision.to_hex().as_str())
        );

        iface_b
            .set_condition(
                patchbay::LinkCondition::new(),
                patchbay::LinkDirection::Both,
            )
            .await?;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let healed = pull_on_device(pair, &dirs.dest_root, Some(&dirs.dest_state)).await?;
        assert_eq!(healed.disposition, mneme_sync::PullDisposition::Updated);
        assert_peers_verified_equal(&dirs.source_root, &dirs.dest_root, &healed);
        Ok(())
    }

    /// Scenario 5: Region-level network partition and heal.
    async fn scenario_network_partition_and_heal() -> anyhow::Result<()> {
        let lab = patchbay::Lab::new().await?;
        let eu = lab.add_region("eu").await?;
        let us = lab.add_region("us").await?;
        lab.link_regions(&eu, &us, patchbay::RegionLink::good(20))
            .await?;

        let dc_eu = lab
            .add_router("dc-eu")
            .region(&eu)
            .preset(patchbay::RouterPreset::Public)
            .build()
            .await?;
        let dc_us = lab
            .add_router("dc-us")
            .region(&us)
            .preset(patchbay::RouterPreset::Public)
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

        let pair = bind_pair(dev_a, dev_b, 51, mneme_sync::DiscoveryMode::OfflineLoopback).await?;
        pair.node_a
            .publish_workspace(&source_ws, &vault_id, &scope())
            .await
            .map_err(|e| anyhow::anyhow!("publish 1: {e}"))?;

        let dirs = SyncDirs {
            source_root,
            dest_root,
            dest_state,
        };
        run_partition_and_heal(&pair, &mut source_ws, &vault_id, &dirs).await?;
        shutdown_pair(pair).await
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
        let nft = ToolProbe {
            cmd: "nft",
            arg: "--version",
        };
        let tc = ToolProbe {
            cmd: "tc",
            arg: "-V",
        };
        if !nft.is_available() || !tc.is_available() {
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
