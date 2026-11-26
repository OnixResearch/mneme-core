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

fn fixed_sync_clock() -> std::sync::Arc<dyn mneme_store::Clock> {
    std::sync::Arc::new(mneme_store::FixedClock::new(
        mneme_core::Timestamp::from_nanos(1_700_000_000_000_000_000),
    ))
}

async fn bind_loopback_node(
    seed: u8,
    allowlist: mneme_sync::SharedAllowlist,
) -> mneme_sync::SyncNode {
    mneme_sync::SyncNode::bind(mneme_sync::SyncNodeConfig {
        secret_key: deterministic_secret_key(seed),
        allowlist,
        revocations: mneme_sync::SharedRevocationSet::new(mneme_sync::RevocationSet::new()),
        trusted_roots: std::collections::BTreeSet::new(),
        clock: fixed_sync_clock(),
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
        revocations: mneme_sync::SharedRevocationSet::new(mneme_sync::RevocationSet::new()),
        trusted_roots: std::collections::BTreeSet::new(),
        clock: fixed_sync_clock(),
        discovery: mneme_sync::DiscoveryMode::MdnsOnly,
        relay: mneme_sync::RelayPreference::Disabled,
        bind_addrs: vec![std::net::SocketAddr::from(([127, 0, 0, 1], 0))],
    })
    .await
    .expect("bind mdns node");
    assert!(node.addr().relay_urls().next().is_none());
    node.shutdown().await.expect("shutdown mdns node");
}

struct MutableTestClock {
    nanos: std::sync::Arc<std::sync::atomic::AtomicI64>,
}

impl MutableTestClock {
    fn new(secs: u64) -> (Self, std::sync::Arc<std::sync::atomic::AtomicI64>) {
        let nanos = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(
            i64::try_from(secs).expect("secs") * 1_000_000_000,
        ));
        (
            Self {
                nanos: std::sync::Arc::clone(&nanos),
            },
            nanos,
        )
    }
}

impl mneme_store::Clock for MutableTestClock {
    fn now(&self) -> mneme_core::Timestamp {
        mneme_core::Timestamp::from_nanos(self.nanos.load(std::sync::atomic::Ordering::SeqCst))
    }
}

async fn bind_capability_node(
    seed: u8,
    trusted_roots: std::collections::BTreeSet<iroh::EndpointId>,
    revocations: mneme_sync::SharedRevocationSet,
    clock: std::sync::Arc<dyn mneme_store::Clock>,
) -> mneme_sync::SyncNode {
    mneme_sync::SyncNode::bind(mneme_sync::SyncNodeConfig {
        secret_key: deterministic_secret_key(seed),
        allowlist: mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new()),
        revocations,
        trusted_roots,
        clock,
        discovery: mneme_sync::DiscoveryMode::OfflineLoopback,
        relay: mneme_sync::RelayPreference::Disabled,
        bind_addrs: vec![std::net::SocketAddr::from(([127, 0, 0, 1], 0))],
    })
    .await
    .expect("bind capability node")
}

#[tokio::test]
async fn delegated_capabilities_enforce_attenuation_readonly_pull_push_and_expiry() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source_root = temp.path().join("source");
    let dest_c = temp.path().join("dest-c");
    let dest_d = temp.path().join("dest-d");

    let (source_ws, vault_id) = create_fixture_workspace(&source_root);
    let base_secs: u64 = 1_700_000_000;
    let (clock, clock_nanos) = MutableTestClock::new(base_secs);
    let clock: std::sync::Arc<dyn mneme_store::Clock> = std::sync::Arc::new(clock);

    let key_a = deterministic_secret_key(31);
    let key_b = deterministic_secret_key(32);
    let key_c = deterministic_secret_key(33);
    let key_d = deterministic_secret_key(34);

    let mut roots = std::collections::BTreeSet::new();
    roots.insert(key_a.public());

    let rev_a = mneme_sync::SharedRevocationSet::new(mneme_sync::RevocationSet::new());
    let node_a = bind_capability_node(31, roots.clone(), rev_a.clone(), clock.clone()).await;
    let node_b = bind_capability_node(
        32,
        roots.clone(),
        mneme_sync::SharedRevocationSet::new(mneme_sync::RevocationSet::new()),
        clock.clone(),
    )
    .await;
    let node_c = bind_capability_node(
        33,
        roots.clone(),
        mneme_sync::SharedRevocationSet::new(mneme_sync::RevocationSet::new()),
        clock.clone(),
    )
    .await;
    let node_d = bind_capability_node(
        34,
        roots.clone(),
        mneme_sync::SharedRevocationSet::new(mneme_sync::RevocationSet::new()),
        clock.clone(),
    )
    .await;

    node_b.add_peer_addr(node_a.addr());
    node_c.add_peer_addr(node_a.addr());
    node_d.add_peer_addr(node_a.addr());

    let snapshot = node_a
        .publish_workspace(&source_ws, &vault_id, &scope())
        .await
        .expect("publish");

    // Root A grants SyncPush on scope:* to B (depth 3, expires at +600s).
    let cap_ab = mneme_sync::CapabilityToken::grant(
        &key_a,
        mneme_sync::GrantRequest {
            vault_id: vault_id.clone(),
            subject: key_b.public(),
            scope: mneme_sync::CapabilityScope::Wildcard,
            authority: mneme_sync::CapabilityAuthority::SyncPush,
            issued_at_secs: base_secs,
            expires_at_secs: base_secs + 600,
            max_delegation_depth: 3,
        },
    )
    .expect("grant A->B");

    // B delegates SyncPull on project:cedar to C (depth 1, expires at +400s).
    let cap_bc = cap_ab
        .delegate(
            &key_b,
            mneme_sync::DelegateRequest {
                subject: key_c.public(),
                scope: mneme_sync::CapabilityScope::from_scopes([scope()]).expect("scope"),
                authority: mneme_sync::CapabilityAuthority::SyncPull,
                issued_at_secs: base_secs,
                expires_at_secs: base_secs + 400,
                remaining_depth: Some(1),
            },
        )
        .expect("delegate B->C");

    // C delegates ReadOnly on project:cedar to D (depth 0, expires at +300s).
    let cap_cd = cap_bc
        .delegate(
            &key_c,
            mneme_sync::DelegateRequest {
                subject: key_d.public(),
                scope: mneme_sync::CapabilityScope::from_scopes([scope()]).expect("scope"),
                authority: mneme_sync::CapabilityAuthority::ReadOnly,
                issued_at_secs: base_secs,
                expires_at_secs: base_secs + 300,
                remaining_depth: Some(0),
            },
        )
        .expect("delegate C->D");

    // 1. D (delegated ReadOnly, not in PeerAllowlist) can inspect head metadata.
    let fetched_d = node_d
        .fetch_vault_head_with_capability(node_a.node_id(), &scope(), &vault_id, &cap_cd)
        .await
        .expect("ReadOnly head query succeeds");
    assert_eq!(fetched_d.head_revision, snapshot.head_revision);

    // 2. D (ReadOnly) CANNOT pull blobs/bundles (fails closed locally and on iroh-blobs ALPN).
    let pull_err_d = node_d
        .pull_scope_with_capability(
            mneme_sync::PullRequest {
                peer: node_a.node_id(),
                scope: scope(),
                destination: dest_d.clone(),
                state_dir: None,
                workspace_config: config_factory(),
            },
            &vault_id,
            &cap_cd,
        )
        .await
        .expect_err("ReadOnly must not pull");
    assert!(matches!(
        pull_err_d,
        mneme_sync::Failure::CapabilityDenied(_)
    ));
    assert!(!dest_d.exists());

    // Even direct iroh-blobs connection from D after ReadOnly auth must fail closed.
    let blob_conn_d = node_d
        .endpoint()
        .connect(node_a.node_id(), iroh_blobs::ALPN)
        .await;
    if let Ok(conn) = blob_conn_d {
        let closed = conn.closed().await;
        assert!(matches!(
            closed,
            iroh::endpoint::ConnectionError::ApplicationClosed(_)
                | iroh::endpoint::ConnectionError::ConnectionClosed(_)
                | iroh::endpoint::ConnectionError::LocallyClosed
        ));
    }

    // 3. C (delegated SyncPull) pulls & verifies workspace cleanly without being in PeerAllowlist.
    let pull_c = node_c
        .pull_scope_with_capability(
            mneme_sync::PullRequest {
                peer: node_a.node_id(),
                scope: scope(),
                destination: dest_c.clone(),
                state_dir: None,
                workspace_config: config_factory(),
            },
            &vault_id,
            &cap_bc,
        )
        .await
        .expect("delegated SyncPull succeeds");
    assert_eq!(pull_c.disposition, mneme_sync::PullDisposition::Restored);
    assert!(pull_c.verify_report.is_healthy());

    // 4. C (SyncPull) CANNOT push heads (SyncPush required), whereas B (SyncPush) CAN.
    let announcement = snapshot.to_announcement();
    let push_err_c = node_c
        .push_head_with_capability(node_a.node_id(), &announcement, &cap_bc)
        .await
        .expect_err("SyncPull must not push");
    assert!(matches!(
        push_err_c,
        mneme_sync::Failure::CapabilityDenied(_)
    ));

    node_b
        .push_head_with_capability(node_a.node_id(), &announcement, &cap_ab)
        .await
        .expect("SyncPush succeeds");
    assert_eq!(node_a.last_pushed_head(&scope()), Some(announcement));

    // 5. Wrong presenter (D presenting C's token) fails closed.
    let wrong_presenter = node_d
        .fetch_vault_head_with_capability(node_a.node_id(), &scope(), &vault_id, &cap_bc)
        .await
        .expect_err("wrong presenter must fail closed");
    assert!(matches!(
        wrong_presenter,
        mneme_sync::Failure::CapabilityDenied(_)
    ));

    // 6. Wrong scope (`other_scope()`) fails closed for C's `project:cedar` token.
    let wrong_scope = node_c
        .fetch_vault_head_with_capability(node_a.node_id(), &other_scope(), &vault_id, &cap_bc)
        .await
        .expect_err("wrong scope must fail closed");
    assert!(matches!(
        wrong_scope,
        mneme_sync::Failure::ScopeDenied { .. }
    ));

    // 7. Advance clock past C->D expiry (+300s) -> D fails closed.
    clock_nanos.store(
        i64::try_from(base_secs + 301).expect("secs") * 1_000_000_000,
        std::sync::atomic::Ordering::SeqCst,
    );
    let expired_err = node_d
        .fetch_vault_head_with_capability(node_a.node_id(), &scope(), &vault_id, &cap_cd)
        .await
        .expect_err("expired token must fail closed");
    assert!(matches!(
        expired_err,
        mneme_sync::Failure::CapabilityDenied(_)
    ));

    node_a.shutdown().await.expect("shutdown a");
    node_b.shutdown().await.expect("shutdown b");
    node_c.shutdown().await.expect("shutdown c");
    node_d.shutdown().await.expect("shutdown d");
}

#[test]
fn capability_escalation_tampering_and_depth_limits_fail_closed() {
    let key_a = deterministic_secret_key(41);
    let key_b = deterministic_secret_key(42);
    let key_c = deterministic_secret_key(43);
    let key_untrusted = deterministic_secret_key(44);
    let vault_id = "vault-test-1";
    let now_secs = 1_700_000_000;

    let mut roots = std::collections::BTreeSet::new();
    roots.insert(key_a.public());
    let empty_revocations = mneme_sync::RevocationSet::new();

    let cap_ab = mneme_sync::CapabilityToken::grant(
        &key_a,
        mneme_sync::GrantRequest {
            vault_id: vault_id.to_owned(),
            subject: key_b.public(),
            scope: mneme_sync::CapabilityScope::from_scopes([scope()]).expect("scope"),
            authority: mneme_sync::CapabilityAuthority::SyncPull,
            issued_at_secs: now_secs,
            expires_at_secs: now_secs + 500,
            max_delegation_depth: 1,
        },
    )
    .expect("grant A->B");

    // 1. Escalated authority (`SyncPull` -> `SyncPush`) fails closed.
    assert!(
        cap_ab
            .delegate(
                &key_b,
                mneme_sync::DelegateRequest {
                    subject: key_c.public(),
                    scope: mneme_sync::CapabilityScope::from_scopes([scope()]).expect("scope"),
                    authority: mneme_sync::CapabilityAuthority::SyncPush,
                    issued_at_secs: now_secs,
                    expires_at_secs: now_secs + 400,
                    remaining_depth: Some(0),
                },
            )
            .is_err()
    );

    // 2. Escalated scope (`project:cedar` -> `scope:*` or `project:other`) fails closed.
    assert!(
        cap_ab
            .delegate(
                &key_b,
                mneme_sync::DelegateRequest {
                    subject: key_c.public(),
                    scope: mneme_sync::CapabilityScope::Wildcard,
                    authority: mneme_sync::CapabilityAuthority::ReadOnly,
                    issued_at_secs: now_secs,
                    expires_at_secs: now_secs + 400,
                    remaining_depth: Some(0),
                },
            )
            .is_err()
    );
    assert!(
        cap_ab
            .delegate(
                &key_b,
                mneme_sync::DelegateRequest {
                    subject: key_c.public(),
                    scope: mneme_sync::CapabilityScope::from_scopes([other_scope()])
                        .expect("other"),
                    authority: mneme_sync::CapabilityAuthority::ReadOnly,
                    issued_at_secs: now_secs,
                    expires_at_secs: now_secs + 400,
                    remaining_depth: Some(0),
                },
            )
            .is_err()
    );

    // 3. Extended expiration fails closed.
    assert!(
        cap_ab
            .delegate(
                &key_b,
                mneme_sync::DelegateRequest {
                    subject: key_c.public(),
                    scope: mneme_sync::CapabilityScope::from_scopes([scope()]).expect("scope"),
                    authority: mneme_sync::CapabilityAuthority::ReadOnly,
                    issued_at_secs: now_secs,
                    expires_at_secs: now_secs + 501,
                    remaining_depth: Some(0),
                },
            )
            .is_err()
    );

    // 4. Depth limit enforced: B->C consumes depth 0, C->D fails closed.
    let cap_bc = cap_ab
        .delegate(
            &key_b,
            mneme_sync::DelegateRequest {
                subject: key_c.public(),
                scope: mneme_sync::CapabilityScope::from_scopes([scope()]).expect("scope"),
                authority: mneme_sync::CapabilityAuthority::ReadOnly,
                issued_at_secs: now_secs,
                expires_at_secs: now_secs + 400,
                remaining_depth: Some(0),
            },
        )
        .expect("delegate B->C");
    assert!(
        cap_bc
            .delegate(
                &key_c,
                mneme_sync::DelegateRequest {
                    subject: key_untrusted.public(),
                    scope: mneme_sync::CapabilityScope::from_scopes([scope()]).expect("scope"),
                    authority: mneme_sync::CapabilityAuthority::ReadOnly,
                    issued_at_secs: now_secs,
                    expires_at_secs: now_secs + 300,
                    remaining_depth: None,
                },
            )
            .is_err()
    );

    // 5. Tampered signature / tampered field fails closed.
    let mut tampered_field = cap_bc.clone();
    tampered_field.links[1].authority = mneme_sync::CapabilityAuthority::SyncPush;
    assert!(
        mneme_sync::verify_capability(&mneme_sync::VerificationRequest {
            token: &tampered_field,
            presenter: key_c.public(),
            vault_id,
            scope: &scope(),
            required_authority: mneme_sync::CapabilityAuthority::ReadOnly,
            now_secs,
            trusted_roots: &roots,
            revocations: &empty_revocations,
        })
        .is_err()
    );

    let mut tampered_sig = cap_bc.clone();
    let mut sig_bytes = tampered_sig.links[0].signature.as_iroh().to_bytes();
    sig_bytes[0] ^= 0x01;
    tampered_sig.links[0].signature =
        mneme_sync::CapabilitySignature::from_iroh(iroh::Signature::from_bytes(&sig_bytes));
    assert!(
        mneme_sync::verify_capability(&mneme_sync::VerificationRequest {
            token: &tampered_sig,
            presenter: key_c.public(),
            vault_id,
            scope: &scope(),
            required_authority: mneme_sync::CapabilityAuthority::ReadOnly,
            now_secs,
            trusted_roots: &roots,
            revocations: &empty_revocations,
        })
        .is_err()
    );

    // 6. Untrusted root issuer fails closed.
    let untrusted_cap = mneme_sync::CapabilityToken::grant(
        &key_untrusted,
        mneme_sync::GrantRequest {
            vault_id: vault_id.to_owned(),
            subject: key_b.public(),
            scope: mneme_sync::CapabilityScope::Wildcard,
            authority: mneme_sync::CapabilityAuthority::SyncPush,
            issued_at_secs: now_secs,
            expires_at_secs: now_secs + 500,
            max_delegation_depth: 1,
        },
    )
    .expect("grant untrusted");
    assert!(
        mneme_sync::verify_capability(&mneme_sync::VerificationRequest {
            token: &untrusted_cap,
            presenter: key_b.public(),
            vault_id,
            scope: &scope(),
            required_authority: mneme_sync::CapabilityAuthority::ReadOnly,
            now_secs,
            trusted_roots: &roots,
            revocations: &empty_revocations,
        })
        .is_err()
    );
}

#[tokio::test]
async fn offline_crdt_revocation_converges_deterministically_and_blocks_sync() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source_root = temp.path().join("source");
    let dest_c = temp.path().join("dest-c");
    let rev_path = temp.path().join("revocations.json");

    let (source_ws, vault_id) = create_fixture_workspace(&source_root);
    let now_secs: u64 = 1_700_000_000;

    let key_a = deterministic_secret_key(51);
    let key_b = deterministic_secret_key(52);
    let key_c = deterministic_secret_key(53);
    let key_attacker = deterministic_secret_key(54);

    let mut roots = std::collections::BTreeSet::new();
    roots.insert(key_a.public());

    let rev_a = mneme_sync::SharedRevocationSet::new(mneme_sync::RevocationSet::new());
    let rev_b = mneme_sync::SharedRevocationSet::new(mneme_sync::RevocationSet::new());
    let rev_c = mneme_sync::SharedRevocationSet::new(mneme_sync::RevocationSet::new());

    let node_a = bind_capability_node(51, roots.clone(), rev_a.clone(), fixed_sync_clock()).await;
    let node_b = bind_capability_node(52, roots.clone(), rev_b.clone(), fixed_sync_clock()).await;
    let node_c = bind_capability_node(53, roots.clone(), rev_c.clone(), fixed_sync_clock()).await;

    node_c.add_peer_addr(node_a.addr());
    node_b.add_peer_addr(node_a.addr());

    node_a
        .publish_workspace(&source_ws, &vault_id, &scope())
        .await
        .expect("publish");

    let cap_ab = mneme_sync::CapabilityToken::grant(
        &key_a,
        mneme_sync::GrantRequest {
            vault_id: vault_id.clone(),
            subject: key_b.public(),
            scope: mneme_sync::CapabilityScope::Wildcard,
            authority: mneme_sync::CapabilityAuthority::SyncPush,
            issued_at_secs: now_secs,
            expires_at_secs: now_secs + 1000,
            max_delegation_depth: 2,
        },
    )
    .expect("grant A->B");

    let cap_bc = cap_ab
        .delegate(
            &key_b,
            mneme_sync::DelegateRequest {
                subject: key_c.public(),
                scope: mneme_sync::CapabilityScope::from_scopes([scope()]).expect("scope"),
                authority: mneme_sync::CapabilityAuthority::SyncPull,
                issued_at_secs: now_secs,
                expires_at_secs: now_secs + 800,
                remaining_depth: Some(1),
            },
        )
        .expect("delegate B->C");

    // 1. Initial pull by C succeeds and records a SyncPull lease on node_a.
    let initial = node_c
        .pull_scope_with_capability(
            mneme_sync::PullRequest {
                peer: node_a.node_id(),
                scope: scope(),
                destination: dest_c.clone(),
                state_dir: None,
                workspace_config: config_factory(),
            },
            &vault_id,
            &cap_bc,
        )
        .await
        .expect("initial pull succeeds");
    assert_eq!(initial.disposition, mneme_sync::PullDisposition::Restored);

    // 2. Unauthorized third-party tombstone cannot revoke A->B.
    let forged_revoker_tombstone = mneme_sync::RevocationTombstone::issue(
        &key_attacker,
        &vault_id,
        cap_ab.links[0].token_id,
        now_secs + 10,
        Some("unauthorized"),
    )
    .expect("sign attacker tombstone");
    let mut attacker_set = mneme_sync::RevocationSet::new();
    attacker_set
        .insert(forged_revoker_tombstone)
        .expect("valid sig from attacker");
    let still_valid = mneme_sync::verify_capability(&mneme_sync::VerificationRequest {
        token: &cap_bc,
        presenter: key_c.public(),
        vault_id: &vault_id,
        scope: &scope(),
        required_authority: mneme_sync::CapabilityAuthority::SyncPull,
        now_secs: now_secs + 10,
        trusted_roots: &roots,
        revocations: &attacker_set,
    });
    assert!(still_valid.is_ok());

    // 3. Tampered tombstone signature fails closed on RevocationSet::insert/merge.
    let valid_tombstone = mneme_sync::RevocationTombstone::issue(
        &key_a,
        &vault_id,
        cap_ab.links[0].token_id,
        now_secs + 20,
        Some("compromised device"),
    )
    .expect("issue tombstone");
    let mut bad_tombstone = valid_tombstone.clone();
    bad_tombstone.reason = Some("tampered".to_owned());
    assert!(attacker_set.insert(bad_tombstone).is_err());

    // 4. Deterministic CRDT convergence across different merge orders + persistence.
    let extra_tombstone = mneme_sync::RevocationTombstone::issue(
        &key_b,
        &vault_id,
        cap_bc.links[1].token_id,
        now_secs + 25,
        Some("rotated"),
    )
    .expect("issue second tombstone");

    let mut set_1 = mneme_sync::RevocationSet::new();
    set_1.insert(valid_tombstone.clone()).expect("insert 1");
    let mut set_2 = mneme_sync::RevocationSet::new();
    set_2.insert(extra_tombstone.clone()).expect("insert 2");

    let mut order_12 = set_1.clone();
    order_12.merge(&set_2).expect("merge 1<-2");
    order_12.merge(&set_2).expect("idempotent merge");
    let mut order_21 = set_2.clone();
    order_21.merge(&set_1).expect("merge 2<-1");
    assert_eq!(order_12, order_21);

    order_12.save(&rev_path).expect("save revocations");
    let reloaded = mneme_sync::RevocationSet::load(&rev_path).expect("reload revocations");
    assert_eq!(reloaded, order_12);

    // 5. Offline causal revocation: node_b revokes A->B via synced tombstone from A,
    //    causally revoking delegated child B->C on node_a!
    valid_tombstone.verify_signature().expect("sig ok");
    rev_b
        .insert(valid_tombstone.clone())
        .expect("insert into b");
    // B syncs revocations to A using B's still-non-revoked-on-A capability before A learns it.
    let merged_on_b = node_b
        .sync_revocations(node_a.node_id(), Some(&cap_ab))
        .await
        .expect("sync revocations B->A");
    assert_eq!(merged_on_b, 0);
    assert_eq!(rev_a.len_u64(), 1);

    // Subsequent head query & pull by C fail closed with CapabilityRevoked!
    let query_after_revoke = node_c
        .fetch_vault_head_with_capability(node_a.node_id(), &scope(), &vault_id, &cap_bc)
        .await
        .expect_err("causal revocation must block query");
    assert!(matches!(
        query_after_revoke,
        mneme_sync::Failure::CapabilityRevoked { .. }
    ));

    let pull_after_revoke = node_c
        .pull_scope_with_capability(
            mneme_sync::PullRequest {
                peer: node_a.node_id(),
                scope: scope(),
                destination: dest_c,
                state_dir: None,
                workspace_config: config_factory(),
            },
            &vault_id,
            &cap_bc,
        )
        .await
        .expect_err("causal revocation must block pull");
    assert!(matches!(
        pull_after_revoke,
        mneme_sync::Failure::CapabilityRevoked { .. }
    ));

    // Also verify existing iroh-blobs lease is invalidated immediately upon revocation.
    let blob_conn_c = node_c
        .endpoint()
        .connect(node_a.node_id(), iroh_blobs::ALPN)
        .await;
    if let Ok(conn) = blob_conn_c {
        let closed = conn.closed().await;
        assert!(matches!(
            closed,
            iroh::endpoint::ConnectionError::ApplicationClosed(_)
                | iroh::endpoint::ConnectionError::ConnectionClosed(_)
                | iroh::endpoint::ConnectionError::LocallyClosed
        ));
    }

    node_a.shutdown().await.expect("shutdown a");
    node_b.shutdown().await.expect("shutdown b");
    node_c.shutdown().await.expect("shutdown c");
}
