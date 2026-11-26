//! Deterministic offline/loopback two-peer integration tests for `mneme-sync`.
#![allow(unknown_lints, no_unwrap, assertion_density)] // test/fixture code fails by panic, not a production path
#![allow(clippy::unwrap_used, clippy::expect_used)] // test/fixture code fails by panic, not a production path

fn scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
}

fn other_scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "other").expect("other scope")
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

fn create_fixture_workspace(root: &std::path::Path) -> (mneme_store::Workspace, String) {
    let mut workspace =
        mneme_store::Workspace::create(root, fixed_config()).expect("create workspace");
    let genesis = workspace.current_revision().expect("genesis");
    let records: Vec<mneme_store::RecordDraft> = mneme_core::fixtures::fixture_batch()
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
    let _outcome = workspace
        .commit(mneme_store::CommitCommand {
            base: genesis,
            actor: "fixture-author".to_owned(),
            scope: scope(),
            idempotency_key: "fixture-1".to_owned(),
            records,
            source_blobs: vec![mneme_store::SourceBlobDraft {
                bytes: mneme_core::fixtures::SOURCE_TEXT.as_bytes().to_vec(),
                media_type: mneme_core::Symbol::from("text/asciidoc"),
            }],
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
    let updated_bytes = b"= Cedar Notes\n\nSecond synced revision over Iroh.\n";
    let retained = mneme_core::RetainedSource::new(
        mneme_core::ContentDigest::of_source_bytes(updated_bytes),
        updated_bytes.len() as u64,
        "text/asciidoc",
    )
    .expect("retained");
    let record_id = mneme_core::RecordId::from_bytes([0xaa; 16]);
    let revision_id = mneme_core::RevisionId::from_bytes([0xbb; 16]);
    let draft = mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::SourceRevision,
        record_id,
        revision_id,
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
            source_blobs: vec![mneme_store::SourceBlobDraft {
                bytes: updated_bytes.to_vec(),
                media_type: mneme_core::Symbol::from("text/asciidoc"),
            }],
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit follow-up");
}

async fn bind_loopback_node(
    seed: u8,
    allowlist: mneme_sync::SharedAllowlist,
) -> mneme_sync::SyncNode {
    mneme_sync::SyncNode::bind(mneme_sync::SyncNodeConfig {
        secret_key: deterministic_secret_key(seed),
        allowlist,
        discovery: mneme_sync::DiscoveryMode::OfflineLoopback,
        relay: mneme_sync::RelayPreference::Disabled,
        bind_addrs: vec![std::net::SocketAddr::from(([127, 0, 0, 1], 0))],
    })
    .await
    .expect("bind loopback node")
}

#[tokio::test]
async fn two_peer_loopback_sync_restores_updates_and_repulls_idempotently() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source_root = temp.path().join("peer-a");
    let dest_root = temp.path().join("peer-b");
    let dest_state = temp.path().join("peer-b-sync");

    let (mut source_ws, vault_id) = create_fixture_workspace(&source_root);

    let allow_a = mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new());
    let allow_b = mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new());
    let node_a = bind_loopback_node(1, allow_a.clone()).await;
    let node_b = bind_loopback_node(2, allow_b.clone()).await;

    allow_a
        .allow(mneme_sync::AllowedPeer {
            node_id: node_b.node_id(),
            label: Some("peer-b".to_owned()),
            allowance: mneme_sync::ScopeAllowance::from_scopes([scope()]),
        })
        .expect("allow b");
    allow_b
        .allow(mneme_sync::AllowedPeer {
            node_id: node_a.node_id(),
            label: Some("peer-a".to_owned()),
            allowance: mneme_sync::ScopeAllowance::from_scopes([scope()]),
        })
        .expect("allow a");

    node_a.add_peer_addr(node_b.addr());
    node_b.add_peer_addr(node_a.addr());

    let published = node_a
        .publish_workspace(&source_ws, &vault_id, &scope())
        .await
        .expect("publish initial");
    assert_eq!(published.sequence, 1);

    // 1. Initial pull restores into non-existent destination and verifies cleanly.
    let first_pull = node_b
        .pull_scope(mneme_sync::PullRequest {
            peer: node_a.node_id(),
            scope: scope(),
            destination: dest_root.clone(),
            state_dir: Some(dest_state.clone()),
            workspace_config: config_factory(),
        })
        .await
        .expect("initial pull");
    assert_eq!(
        first_pull.disposition,
        mneme_sync::PullDisposition::Restored
    );
    assert!(first_pull.verify_report.is_healthy());
    assert!(first_pull.verify_report.blobs_checked > 0);

    // 2. Idempotent re-pull (with state_dir fast path).
    let second_pull = node_b
        .pull_scope(mneme_sync::PullRequest {
            peer: node_a.node_id(),
            scope: scope(),
            destination: dest_root.clone(),
            state_dir: Some(dest_state.clone()),
            workspace_config: config_factory(),
        })
        .await
        .expect("idempotent pull with state");
    assert_eq!(
        second_pull.disposition,
        mneme_sync::PullDisposition::AlreadyUpToDate
    );
    assert!(second_pull.verify_report.is_healthy());

    // 3. Idempotent re-pull WITHOUT state_dir (exercises store-level ingest_into deduplication).
    let third_pull = node_b
        .pull_scope(mneme_sync::PullRequest {
            peer: node_a.node_id(),
            scope: scope(),
            destination: dest_root.clone(),
            state_dir: None,
            workspace_config: config_factory(),
        })
        .await
        .expect("idempotent pull without state");
    assert_eq!(
        third_pull.disposition,
        mneme_sync::PullDisposition::AlreadyUpToDate
    );
    assert_eq!(third_pull.local_sequence, first_pull.local_sequence);

    // 4. Incremental commit on Peer A updates Peer B cleanly and passes verify_workspace.
    commit_follow_up_source(&mut source_ws);
    let published_2 = node_a
        .publish_workspace(&source_ws, &vault_id, &scope())
        .await
        .expect("publish second");
    assert_eq!(published_2.sequence, 2);

    let fourth_pull = node_b
        .pull_scope(mneme_sync::PullRequest {
            peer: node_a.node_id(),
            scope: scope(),
            destination: dest_root.clone(),
            state_dir: Some(dest_state.clone()),
            workspace_config: config_factory(),
        })
        .await
        .expect("incremental pull");
    assert_eq!(
        fourth_pull.disposition,
        mneme_sync::PullDisposition::Updated
    );
    assert!(fourth_pull.verify_report.is_healthy());
    assert!(fourth_pull.local_sequence > first_pull.local_sequence);

    let verify = mneme_store::verify_workspace(&dest_root, mneme_store::VerifyMode::Full)
        .expect("final verify");
    assert!(verify.is_healthy());

    node_a.shutdown().await.expect("shutdown a");
    node_b.shutdown().await.expect("shutdown b");
}

#[tokio::test]
async fn allowlist_is_deny_by_default_and_address_lookup_never_grants_trust() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source_root = temp.path().join("peer-a");
    let dest_root = temp.path().join("peer-b");

    let (source_ws, vault_id) = create_fixture_workspace(&source_root);

    let allow_a = mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new());
    let allow_b = mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new());
    let node_a = bind_loopback_node(11, allow_a.clone()).await;
    let node_b = bind_loopback_node(12, allow_b.clone()).await;

    // Register address only (simulates mDNS discovering an address without trusting the peer).
    node_a.add_peer_addr(node_b.addr());
    node_b.add_peer_addr(node_a.addr());

    let _published = node_a
        .publish_workspace(&source_ws, &vault_id, &scope())
        .await
        .expect("publish");

    // 1. Peer B's own allowlist is empty -> refuses pull locally.
    let err_local = node_b
        .pull_scope(mneme_sync::PullRequest {
            peer: node_a.node_id(),
            scope: scope(),
            destination: dest_root.clone(),
            state_dir: None,
            workspace_config: config_factory(),
        })
        .await
        .expect_err("empty allowlist must refuse");
    assert!(matches!(
        err_local,
        mneme_sync::Failure::UnauthorizedPeer(_)
    ));
    assert!(!dest_root.exists());

    // 2. Peer B allows Peer A, but Peer A does NOT allow Peer B -> Peer A closes connection.
    allow_b
        .allow(mneme_sync::AllowedPeer {
            node_id: node_a.node_id(),
            label: None,
            allowance: mneme_sync::ScopeAllowance::Any,
        })
        .expect("allow a on b");
    let err_remote = node_b
        .pull_scope(mneme_sync::PullRequest {
            peer: node_a.node_id(),
            scope: scope(),
            destination: dest_root.clone(),
            state_dir: None,
            workspace_config: config_factory(),
        })
        .await
        .expect_err("remote must refuse non-allowlisted peer");
    assert!(matches!(err_remote, mneme_sync::Failure::Transport(_)));
    assert!(!dest_root.exists());

    // 3. Peer A allows Peer B only for `other_scope()`, not `scope()` -> scope denied.
    allow_a
        .allow(mneme_sync::AllowedPeer {
            node_id: node_b.node_id(),
            label: None,
            allowance: mneme_sync::ScopeAllowance::from_scopes([other_scope()]),
        })
        .expect("allow other scope");
    let err_scope = node_b
        .pull_scope(mneme_sync::PullRequest {
            peer: node_a.node_id(),
            scope: scope(),
            destination: dest_root.clone(),
            state_dir: None,
            workspace_config: config_factory(),
        })
        .await
        .expect_err("scope mismatch must refuse");
    assert!(matches!(err_scope, mneme_sync::Failure::Protocol(_)));
    assert!(!dest_root.exists());

    node_a.shutdown().await.expect("shutdown a");
    node_b.shutdown().await.expect("shutdown b");
}

#[tokio::test]
async fn gossip_head_announcement_triggers_verified_pull() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source_root = temp.path().join("peer-a");
    let dest_root = temp.path().join("peer-b");
    let dest_state = temp.path().join("peer-b-sync");

    let (source_ws, vault_id) = create_fixture_workspace(&source_root);

    let allow_a = mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new());
    let allow_b = mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new());
    let node_a = bind_loopback_node(21, allow_a.clone()).await;
    let node_b = bind_loopback_node(22, allow_b.clone()).await;

    allow_a
        .allow(mneme_sync::AllowedPeer {
            node_id: node_b.node_id(),
            label: None,
            allowance: mneme_sync::ScopeAllowance::Any,
        })
        .expect("allow b");
    allow_b
        .allow(mneme_sync::AllowedPeer {
            node_id: node_a.node_id(),
            label: None,
            allowance: mneme_sync::ScopeAllowance::Any,
        })
        .expect("allow a");

    node_a.add_peer_addr(node_b.addr());
    node_b.add_peer_addr(node_a.addr());

    let snapshot = node_a
        .publish_workspace(&source_ws, &vault_id, &scope())
        .await
        .expect("publish");

    let mut topic_a = node_a
        .subscribe_gossip(&vault_id, vec![])
        .await
        .expect("subscribe a");
    let mut topic_b = node_b
        .subscribe_gossip(&vault_id, vec![node_a.node_id()])
        .await
        .expect("subscribe b");

    tokio::time::timeout(std::time::Duration::from_secs(10), topic_b.joined())
        .await
        .expect("join timeout")
        .expect("topic b joined");
    tokio::time::timeout(std::time::Duration::from_secs(10), topic_a.joined())
        .await
        .expect("join timeout a")
        .expect("topic a joined");

    topic_a
        .broadcast_head(&snapshot)
        .await
        .expect("broadcast head");

    let outcomes = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        node_b.pull_on_gossip(
            &mut topic_b,
            &dest_root,
            Some(&dest_state),
            config_factory(),
            Some(1),
        ),
    )
    .await
    .expect("gossip pull timeout")
    .expect("gossip pull ok");

    assert_eq!(outcomes.len(), 1);
    assert_eq!(
        outcomes[0].disposition,
        mneme_sync::PullDisposition::Restored
    );
    assert!(outcomes[0].verify_report.is_healthy());
    assert_eq!(outcomes[0].snapshot.head_revision, snapshot.head_revision);

    node_a.shutdown().await.expect("shutdown a");
    node_b.shutdown().await.expect("shutdown b");
}

#[test]
fn ingest_fails_closed_on_corrupted_bundle_or_conflicting_history() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source_root = temp.path().join("source");
    let dest_root = temp.path().join("dest");
    let archive_path = temp.path().join("bundle.mneme");

    let (source_ws, _vault_id) = create_fixture_workspace(&source_root);
    source_ws
        .export_portable(&archive_path, &scope())
        .expect("export portable");

    // 1. Corrupting one byte in the archive refuses restore without creating dest_root.
    let bad_archive = temp.path().join("corrupt.mneme");
    let mut bytes = std::fs::read(&archive_path).expect("read archive");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&bad_archive, &bytes).expect("write corrupt");

    let err = mneme_sync::ingest_downloaded_archive(&bad_archive, &dest_root, fixed_config())
        .expect_err("corrupt archive must fail closed");
    assert!(matches!(err, mneme_sync::Failure::Store(_)));
    assert!(!dest_root.exists());

    // 2. Conflicting local commit at destination refuses incremental ingest.
    let (mut conflicting_ws, _) = create_fixture_workspace(&dest_root);
    let base = conflicting_ws.current_revision().expect("base");
    let first_record = mneme_core::fixtures::fixture_batch()[0].clone();
    let _ = conflicting_ws
        .commit(mneme_store::CommitCommand {
            base,
            actor: "local-conflict".to_owned(),
            scope: scope(),
            idempotency_key: "conflict-1".to_owned(),
            records: vec![mneme_store::RecordDraft {
                schema_version: first_record.schema_version,
                kind: first_record.kind,
                record_id: first_record.record_id,
                revision_id: mneme_core::RevisionId::from_bytes([0xee; 16]),
                predecessor: Some(first_record.revision_id),
                scope: first_record.scope,
                payload: first_record.payload,
            }],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit local conflict");
    drop(conflicting_ws);

    let err_conflict =
        mneme_sync::ingest_downloaded_archive(&archive_path, &dest_root, fixed_config())
            .expect_err("conflicting history must fail closed");
    assert!(matches!(err_conflict, mneme_sync::Failure::Store(_)));
}

#[test]
fn allowlist_persistence_and_gossip_announcement_bounds() {
    let temp = tempfile::tempdir().expect("tempdir");
    let allowlist_path = temp.path().join("peers.json");
    let key_path = temp.path().join("identity.key");

    let key = mneme_sync::load_or_create_secret_key(&key_path).expect("create key");
    let key_again = mneme_sync::load_or_create_secret_key(&key_path).expect("reload key");
    assert_eq!(key.to_bytes(), key_again.to_bytes());

    let mut list = mneme_sync::PeerAllowlist::load(&allowlist_path).expect("empty load");
    assert_eq!(list.len_u64(), 0);
    assert!(!list.is_allowed(key.public()));

    list.allow(mneme_sync::AllowedPeer {
        node_id: key.public(),
        label: Some("aspen3".to_owned()),
        allowance: mneme_sync::ScopeAllowance::from_scopes([scope()]),
    });
    list.save(&allowlist_path).expect("save allowlist");

    let reloaded = mneme_sync::PeerAllowlist::load(&allowlist_path).expect("reload allowlist");
    assert!(reloaded.is_allowed(key.public()));
    assert!(reloaded.allows_scope(key.public(), &scope()));
    assert!(!reloaded.allows_scope(key.public(), &other_scope()));

    let digest = mneme_core::ContentDigest::of_payload(&mneme_core::Value::symbol("ok"));
    let announcement = mneme_sync::HeadAnnouncement {
        vault_id: "vault-1".to_owned(),
        scope: scope().to_string(),
        head_revision: mneme_core::WorkspaceRevisionId::from_bytes([7; 16]).to_hex(),
        head_revision_digest: mneme_sync::WireDigest::from_digest(digest),
        seq: 3,
        bundle_hash: iroh_blobs::Hash::EMPTY.to_string(),
        bundle_bytes: 128,
    };
    let encoded = announcement.encode().expect("encode announcement");
    let decoded = mneme_sync::HeadAnnouncement::decode(&encoded).expect("decode announcement");
    assert_eq!(decoded, announcement);

    let oversized = vec![b' '; mneme_sync::MAX_GOSSIP_MESSAGE_BYTES + 1];
    assert!(mneme_sync::HeadAnnouncement::decode(&oversized).is_err());

    assert_eq!(
        mneme_sync::topic_id_for_vault("vault-1"),
        mneme_sync::topic_id_for_vault("vault-1")
    );
    assert_ne!(
        mneme_sync::topic_id_for_vault("vault-1"),
        mneme_sync::topic_id_for_vault("vault-2")
    );
}

#[tokio::test]
async fn mdns_discovery_mode_binds_offline_without_relay() {
    let allowlist = mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new());
    let node = mneme_sync::SyncNode::bind(mneme_sync::SyncNodeConfig {
        secret_key: deterministic_secret_key(99),
        allowlist,
        discovery: mneme_sync::DiscoveryMode::MdnsOnly,
        relay: mneme_sync::RelayPreference::Disabled,
        bind_addrs: vec![std::net::SocketAddr::from(([127, 0, 0, 1], 0))],
    })
    .await
    .expect("bind mdns node");
    assert!(node.addr().relay_urls().next().is_none());
    node.shutdown().await.expect("shutdown mdns node");
}
