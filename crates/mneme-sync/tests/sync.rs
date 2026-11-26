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
            source_blobs: vec![mneme_store::SourceBlobDraft::inline(
                mneme_core::fixtures::SOURCE_TEXT.as_bytes().to_vec(),
                mneme_core::Symbol::from("text/asciidoc"),
            )],
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
    assert_eq!(fourth_pull.stats.blobs_fetched, 1);
    assert!(fourth_pull.stats.rbsr_rounds >= 1);

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
        origin: None,
        signature: None,
    }
    .signed(&key)
    .expect("sign announcement");
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

fn deterministic_id_16(tag: u8, index: u64) -> [u8; 16] {
    let mut input = [0_u8; 9];
    input[0] = tag;
    input[1..9].copy_from_slice(&index.to_le_bytes());
    let hash = blake3::hash(&input);
    let mut out = [0_u8; 16];
    out.copy_from_slice(&hash.as_bytes()[0..16]);
    out
}

fn synthetic_blob_bytes(salt: u8, index: u64) -> Vec<u8> {
    let header = format!("= Note {salt}:{index}\n\n");
    let mut bytes = vec![b'x'; 1024];
    let prefix = header.as_bytes();
    let copy_len = prefix.len().min(bytes.len());
    bytes[..copy_len].copy_from_slice(&prefix[..copy_len]);
    bytes
}

struct SyntheticBatchSpec {
    salt: u8,
    start_index: u64,
    item_count: u64,
    batch_items: u64,
}

#[derive(Clone, Copy)]
enum PathHintMode {
    Omit,
    Include,
}

fn build_synthetic_item(
    salt: u8,
    idx: u64,
    path_hint: PathHintMode,
) -> (mneme_store::RecordDraft, mneme_store::SourceBlobDraft) {
    let bytes = synthetic_blob_bytes(salt, idx);
    let retained = mneme_core::RetainedSource::new(
        mneme_core::ContentDigest::of_source_bytes(&bytes),
        bytes.len() as u64,
        "text/asciidoc",
    )
    .expect("retained");
    let record_id = mneme_core::RecordId::from_bytes(deterministic_id_16(salt, idx));
    let revision_id =
        mneme_core::RevisionId::from_bytes(deterministic_id_16(salt.wrapping_add(100), idx));
    let mut payload_entries = vec![
        (
            mneme_core::Symbol::from("content"),
            mneme_core::SourceContent::Retained(retained).to_value(),
        ),
        (
            mneme_core::Symbol::from("acquisition"),
            mneme_core::Value::symbol("authored"),
        ),
    ];
    if matches!(path_hint, PathHintMode::Include) {
        payload_entries.push((
            mneme_core::Symbol::from("path-hint"),
            mneme_core::Value::string(format!("notes/{salt}/{idx}.adoc")),
        ));
    }
    let draft = mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::SourceRevision,
        record_id,
        revision_id,
        predecessor: None,
        scope: scope(),
        payload: mneme_core::Payload::new(payload_entries),
    };
    let blob =
        mneme_store::SourceBlobDraft::inline(bytes, mneme_core::Symbol::from("text/asciidoc"));
    (draft, blob)
}

#[allow(unknown_lints, allocation_in_loop)] // test fixture builder allocates bounded batches
fn commit_synthetic_items(workspace: &mut mneme_store::Workspace, spec: SyntheticBatchSpec) {
    let mut committed_items = 0_u64;
    let actor_name = "rbsr-fixture".to_owned();
    let path_hint = if spec.start_index >= 1000 {
        PathHintMode::Include
    } else {
        PathHintMode::Omit
    };
    while committed_items < spec.item_count {
        let take = spec
            .item_count
            .saturating_sub(committed_items)
            .min(spec.batch_items);
        let take_usize = usize::try_from(take).expect("batch size fits usize");
        let base = workspace.current_revision().expect("base");
        let mut records = Vec::with_capacity(take_usize);
        let mut source_blobs = Vec::with_capacity(take_usize);
        for item_offset in 0..take {
            let idx = spec
                .start_index
                .saturating_add(committed_items)
                .saturating_add(item_offset);
            let (draft, blob) = build_synthetic_item(spec.salt, idx, path_hint);
            records.push(draft);
            source_blobs.push(blob);
        }
        let _outcome = workspace
            .commit(mneme_store::CommitCommand {
                base,
                actor: actor_name.clone(),
                scope: scope(),
                idempotency_key: format!(
                    "rbsr-{}-{}-{committed_items}",
                    spec.salt, spec.start_index
                ),
                records,
                source_blobs,
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("commit synthetic batch");
        committed_items = committed_items.saturating_add(take);
    }
}

fn build_large_vault(
    root: &std::path::Path,
    salt: u8,
    item_count: u64,
) -> (mneme_store::Workspace, String) {
    let mut workspace =
        mneme_store::Workspace::create(root, fixed_config()).expect("create large workspace");
    commit_synthetic_items(
        &mut workspace,
        SyntheticBatchSpec {
            salt,
            start_index: 0,
            item_count,
            batch_items: 100,
        },
    );
    let vault_id = workspace.genesis_revision().expect("genesis").to_hex();
    (workspace, vault_id)
}

#[tokio::test]
async fn thousand_item_vaults_reconcile_delta_five_logarithmically_and_empty_diff_in_one_round() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source_root = temp.path().join("peer-a");
    let dest_root = temp.path().join("peer-b");

    let (mut source_ws, vault_id) = build_large_vault(&source_root, 1, 1000);

    let allow_a = mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new());
    let allow_b = mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new());
    let node_a = bind_loopback_node(31, allow_a.clone()).await;
    let node_b = bind_loopback_node(32, allow_b.clone()).await;

    allow_a
        .allow(mneme_sync::AllowedPeer {
            node_id: node_b.node_id(),
            label: None,
            allowance: mneme_sync::ScopeAllowance::from_scopes([scope()]),
        })
        .expect("allow b");
    allow_b
        .allow(mneme_sync::AllowedPeer {
            node_id: node_a.node_id(),
            label: None,
            allowance: mneme_sync::ScopeAllowance::from_scopes([scope()]),
        })
        .expect("allow a");

    node_a.add_peer_addr(node_b.addr());
    node_b.add_peer_addr(node_a.addr());

    // Initial full restore so Peer B has all 1,000 items.
    let _initial_pub = node_a
        .publish_workspace(&source_ws, &vault_id, &scope())
        .await
        .expect("publish 1000");
    let initial_pull = node_b
        .pull_scope(mneme_sync::PullRequest {
            peer: node_a.node_id(),
            scope: scope(),
            destination: dest_root.clone(),
            state_dir: None,
            workspace_config: config_factory(),
        })
        .await
        .expect("initial 1000-item pull");
    assert_eq!(
        initial_pull.disposition,
        mneme_sync::PullDisposition::Restored
    );
    assert_eq!(initial_pull.verify_report.blobs_checked, 2000);

    // Empty-diff re-pull WITHOUT state_dir exercises 1-round RBSR with 0 blobs fetched.
    let empty_pull = node_b
        .pull_scope(mneme_sync::PullRequest {
            peer: node_a.node_id(),
            scope: scope(),
            destination: dest_root.clone(),
            state_dir: None,
            workspace_config: config_factory(),
        })
        .await
        .expect("empty diff pull");
    assert_eq!(
        empty_pull.disposition,
        mneme_sync::PullDisposition::AlreadyUpToDate
    );
    assert_eq!(empty_pull.stats.rbsr_rounds, 1);
    assert_eq!(empty_pull.stats.blobs_fetched, 0);
    assert_eq!(empty_pull.stats.blob_bytes_fetched, 0);
    assert!(empty_pull.verify_report.is_healthy());

    // Commit 5 new items on Peer A (total 1005 items vs 1000 on Peer B).
    commit_synthetic_items(
        &mut source_ws,
        SyntheticBatchSpec {
            salt: 1,
            start_index: 1000,
            item_count: 5,
            batch_items: 5,
        },
    );
    let published_delta = node_a
        .publish_workspace(&source_ws, &vault_id, &scope())
        .await
        .expect("publish 1005");
    let full_blob_list_bytes = serde_json::to_vec(&published_delta.blobs)
        .expect("full blob list json")
        .len() as u64;

    let delta_pull = node_b
        .pull_scope(mneme_sync::PullRequest {
            peer: node_a.node_id(),
            scope: scope(),
            destination: dest_root.clone(),
            state_dir: None,
            workspace_config: config_factory(),
        })
        .await
        .expect("delta 5-item pull");

    assert_eq!(delta_pull.disposition, mneme_sync::PullDisposition::Updated);
    assert!(delta_pull.verify_report.is_healthy());
    assert_eq!(delta_pull.verify_report.blobs_checked, 2010);
    assert_eq!(delta_pull.stats.blobs_fetched, 5);
    assert_eq!(delta_pull.stats.blob_bytes_fetched, 5 * 1024);
    assert!(delta_pull.stats.rbsr_rounds >= 2);
    assert!(delta_pull.stats.rbsr_rounds <= 12);

    let total_control_bytes =
        delta_pull.stats.control_bytes_sent + delta_pull.stats.control_bytes_received;
    assert!(
        total_control_bytes < full_blob_list_bytes / 4,
        "control bytes {total_control_bytes} must be much smaller than full list {full_blob_list_bytes}"
    );

    node_a.shutdown().await.expect("shutdown a");
    node_b.shutdown().await.expect("shutdown b");
}

#[tokio::test]
async fn disjoint_thousand_item_vaults_reconcile_over_control_and_fail_closed_on_conflict() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root_a = temp.path().join("peer-a");
    let root_b = temp.path().join("peer-b");

    let (ws_a, vault_id_a) = build_large_vault(&root_a, 1, 1000);
    let (ws_b, _vault_id_b) = build_large_vault(&root_b, 2, 1000);

    let allow_a = mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new());
    let allow_b = mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new());
    let node_a = bind_loopback_node(41, allow_a.clone()).await;
    let node_b = bind_loopback_node(42, allow_b.clone()).await;

    allow_a
        .allow(mneme_sync::AllowedPeer {
            node_id: node_b.node_id(),
            label: None,
            allowance: mneme_sync::ScopeAllowance::from_scopes([scope()]),
        })
        .expect("allow b");
    allow_b
        .allow(mneme_sync::AllowedPeer {
            node_id: node_a.node_id(),
            label: None,
            allowance: mneme_sync::ScopeAllowance::from_scopes([scope()]),
        })
        .expect("allow a");

    node_a.add_peer_addr(node_b.addr());
    node_b.add_peer_addr(node_a.addr());

    let snapshot_a = node_a
        .publish_workspace(&ws_a, &vault_id_a, &scope())
        .await
        .expect("publish a");
    let local_set_b =
        mneme_sync::collect_local_rbsr_set(&ws_b, &scope()).expect("local rbsr set b");
    assert_eq!(local_set_b.len_u64(), 2000);

    let reconciled = node_b
        .reconcile_scope(
            node_a.node_id(),
            &scope(),
            &snapshot_a.head_revision,
            &local_set_b,
        )
        .await
        .expect("disjoint reconcile over /mneme/sync/1");
    assert_eq!(reconciled.remote_only.len(), 2000);
    assert_eq!(reconciled.local_only.len(), 2000);

    // Attempting pull_scope into conflicting Peer B fails closed without corrupting Peer B.
    let err = node_b
        .pull_scope(mneme_sync::PullRequest {
            peer: node_a.node_id(),
            scope: scope(),
            destination: root_b.clone(),
            state_dir: None,
            workspace_config: config_factory(),
        })
        .await
        .expect_err("conflicting disjoint vaults must fail closed");
    assert!(matches!(err, mneme_sync::Failure::Store(_)));

    let verify_b = mneme_store::verify_workspace(&root_b, mneme_store::VerifyMode::Full)
        .expect("verify b untouched");
    assert!(verify_b.is_healthy());
    assert_eq!(verify_b.blobs_checked, 2000);

    node_a.shutdown().await.expect("shutdown a");
    node_b.shutdown().await.expect("shutdown b");
}

#[tokio::test]
async fn rbsr_control_handler_refuses_malformed_requests_fail_closed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source_root = temp.path().join("peer-a");
    let (source_ws, vault_id) = create_fixture_workspace(&source_root);

    let allow_a = mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new());
    let allow_b = mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new());
    let node_a = bind_loopback_node(51, allow_a.clone()).await;
    let node_b = bind_loopback_node(52, allow_b.clone()).await;

    allow_a
        .allow(mneme_sync::AllowedPeer {
            node_id: node_b.node_id(),
            label: None,
            allowance: mneme_sync::ScopeAllowance::from_scopes([scope()]),
        })
        .expect("allow b");
    allow_b
        .allow(mneme_sync::AllowedPeer {
            node_id: node_a.node_id(),
            label: None,
            allowance: mneme_sync::ScopeAllowance::from_scopes([scope()]),
        })
        .expect("allow a");

    node_a.add_peer_addr(node_b.addr());
    node_b.add_peer_addr(node_a.addr());

    let snapshot = node_a
        .publish_workspace(&source_ws, &vault_id, &scope())
        .await
        .expect("publish");

    let conn = node_b
        .endpoint()
        .connect(node_a.node_id(), mneme_sync::SYNC_CONTROL_ALPN)
        .await
        .expect("connect control");

    let malformed_payloads = [
        serde_json::json!({
            "op": "rbsr-reconcile",
            "scope": "project:cedar",
            "snapshot_revision": snapshot.head_revision,
            "request": {
                "r": [{
                    "l": "+",
                    "u": "-",
                    "d": 0,
                    "p": { "k": "f", "c": 0, "d": mneme_core::base64::encode(&[0_u8; 32]) }
                }]
            }
        }),
        serde_json::json!({
            "op": "rbsr-reconcile",
            "scope": "project:cedar",
            "snapshot_revision": snapshot.head_revision,
            "request": {
                "r": [{
                    "l": "-",
                    "u": "+",
                    "d": mneme_sync::MAX_RBSR_DEPTH + 1,
                    "p": { "k": "f", "c": 0, "d": mneme_core::base64::encode(&[0_u8; 32]) }
                }]
            }
        }),
        serde_json::json!({
            "op": "rbsr-reconcile",
            "scope": "project:cedar",
            "snapshot_revision": "00000000000000000000000000000000",
            "request": {
                "r": [{
                    "l": "-",
                    "u": "+",
                    "d": 0,
                    "p": { "k": "f", "c": 0, "d": mneme_core::base64::encode(&[0_u8; 32]) }
                }]
            }
        }),
        serde_json::json!({
            "op": "fetch-delta-metadata",
            "scope": "project:cedar",
            "snapshot_revision": snapshot.head_revision,
            "revisions": [],
            "blobs": [ "0000000000000000000000000000000000000000000000000000000000000000" ]
        }),
    ];

    for payload in malformed_payloads {
        let (mut send, mut recv) = conn.open_bi().await.expect("open bi");
        let bytes = serde_json::to_vec(&payload).expect("encode");
        send.write_all(&bytes).await.expect("write");
        send.finish().expect("finish");
        let resp_bytes = recv
            .read_to_end(mneme_sync::MAX_CONTROL_MESSAGE_BYTES)
            .await
            .expect("read");
        let resp: serde_json::Value = serde_json::from_slice(&resp_bytes).expect("decode resp");
        assert_eq!(resp["status"], "refused");
    }

    conn.close(0_u32.into(), b"done");
    node_a.shutdown().await.expect("shutdown a");
    node_b.shutdown().await.expect("shutdown b");
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
    let announcement = snapshot
        .to_signed_announcement(&key_b)
        .expect("sign announcement");
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

fn commit_scoped_source(
    workspace: &mut mneme_store::Workspace,
    target_scope: &mneme_core::ScopeId,
    idempotency_key: &str,
    seed: u8,
    bytes: &[u8],
) {
    let base = workspace.current_revision().expect("base");
    let retained = mneme_core::RetainedSource::new(
        mneme_core::ContentDigest::of_source_bytes(bytes),
        bytes.len() as u64,
        "text/plain",
    )
    .expect("retained");
    let draft = mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::SourceRevision,
        record_id: mneme_core::RecordId::from_bytes([seed; 16]),
        revision_id: mneme_core::RevisionId::from_bytes([seed.wrapping_add(100); 16]),
        predecessor: None,
        scope: target_scope.clone(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("content"),
                mneme_core::SourceContent::Retained(retained).to_value(),
            ),
            (
                mneme_core::Symbol::from("acquisition"),
                mneme_core::Value::symbol("authored"),
            ),
        ]),
    };
    let _ = workspace
        .commit(mneme_store::CommitCommand {
            base,
            actor: "sec-test".to_owned(),
            scope: target_scope.clone(),
            idempotency_key: idempotency_key.to_owned(),
            records: vec![draft],
            source_blobs: vec![mneme_store::SourceBlobDraft::inline(
                bytes.to_vec(),
                mneme_core::Symbol::from("text/plain"),
            )],
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit scoped source");
}

#[tokio::test]
async fn cross_scope_blob_exfiltration_and_hashseq_traversal_fail_closed() {
    let dir_a = tempfile::tempdir().expect("tempdir a");
    let dest_b = tempfile::tempdir().expect("tempdir b");
    let key_a = deterministic_secret_key(61);
    let key_b = deterministic_secret_key(62);

    let mut ws_a = mneme_store::Workspace::create(dir_a.path(), config_factory()())
        .expect("create workspace a");
    let scope_a = scope();
    let scope_b = other_scope();
    commit_scoped_source(&mut ws_a, &scope_a, "c-scope-a", 11, b"public-a-payload");
    commit_scoped_source(
        &mut ws_a,
        &scope_b,
        "c-scope-b",
        12,
        b"top-secret-b-payload",
    );

    let vault_id = ws_a.genesis_revision().expect("genesis").to_hex();
    let now_secs = 1_700_000_000_u64;
    let clock: std::sync::Arc<dyn mneme_store::Clock> =
        std::sync::Arc::new(mneme_store::FixedClock::new(
            mneme_core::Timestamp::from_nanos((now_secs as i64) * 1_000_000_000),
        ));

    let node_a = mneme_sync::SyncNode::bind(mneme_sync::SyncNodeConfig {
        secret_key: key_a.clone(),
        allowlist: mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new()),
        revocations: mneme_sync::SharedRevocationSet::new(mneme_sync::RevocationSet::new()),
        trusted_roots: std::collections::BTreeSet::from([key_a.public()]),
        clock: std::sync::Arc::clone(&clock),
        discovery: mneme_sync::DiscoveryMode::OfflineLoopback,
        relay: mneme_sync::RelayPreference::Disabled,
        bind_addrs: vec![std::net::SocketAddr::from(([127, 0, 0, 1], 0))],
    })
    .await
    .expect("bind a");

    let node_b = mneme_sync::SyncNode::bind(mneme_sync::SyncNodeConfig {
        secret_key: key_b.clone(),
        allowlist: mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new()),
        revocations: mneme_sync::SharedRevocationSet::new(mneme_sync::RevocationSet::new()),
        trusted_roots: std::collections::BTreeSet::from([key_a.public()]),
        clock: std::sync::Arc::clone(&clock),
        discovery: mneme_sync::DiscoveryMode::OfflineLoopback,
        relay: mneme_sync::RelayPreference::Disabled,
        bind_addrs: vec![std::net::SocketAddr::from(([127, 0, 0, 1], 0))],
    })
    .await
    .expect("bind b");
    node_b.add_peer_addr(node_a.addr());

    let snap_a = node_a
        .publish_workspace(&ws_a, &vault_id, &scope_a)
        .await
        .expect("publish scope a");
    let snap_b = node_a
        .publish_workspace(&ws_a, &vault_id, &scope_b)
        .await
        .expect("publish scope b");

    // Grant B a SyncPull token attenuated STRICTLY to scope_a.
    let cap_a = mneme_sync::CapabilityToken::grant(
        &key_a,
        mneme_sync::GrantRequest {
            vault_id: vault_id.clone(),
            subject: key_b.public(),
            scope: mneme_sync::CapabilityScope::from_scopes([scope_a.clone()])
                .expect("scope a cap"),
            authority: mneme_sync::CapabilityAuthority::SyncPull,
            issued_at_secs: now_secs,
            expires_at_secs: now_secs + 600,
            max_delegation_depth: 2,
        },
    )
    .expect("grant cap a");

    // B pulls scope_a successfully (establishing its SyncPull lease on scope_a).
    let pulled_a = node_b
        .pull_scope_with_capability(
            mneme_sync::PullRequest {
                peer: node_a.node_id(),
                scope: scope_a.clone(),
                destination: dest_b.path().join("ws"),
                state_dir: None,
                workspace_config: config_factory(),
            },
            &vault_id,
            &cap_a,
        )
        .await
        .expect("pull scope a succeeds");
    assert_eq!(pulled_a.disposition, mneme_sync::PullDisposition::Restored);

    // Now B connects directly to node_a over iroh-blobs and tries to exfiltrate
    // scope_b's bundle hash AND scope_b's source blob hash — BOTH must fail closed!
    let client_store = iroh_blobs::store::mem::MemStore::new();
    let conn = node_b
        .endpoint()
        .connect(node_a.node_id(), iroh_blobs::ALPN)
        .await
        .expect("blobs conn for scope_a lease");

    let bundle_b_hash = snap_b.parsed_bundle_hash().expect("bundle b hash");
    let exfil_bundle = client_store
        .remote()
        .fetch(conn.clone(), bundle_b_hash)
        .await;
    assert!(
        exfil_bundle.is_err(),
        "peer with scope_a lease must NOT fetch scope_b bundle hash"
    );

    let secret_blob_hash: iroh_blobs::Hash = snap_b.blobs[0]
        .transport_hash
        .parse()
        .expect("secret blob hash");
    let exfil_blob = client_store
        .remote()
        .fetch(conn.clone(), secret_blob_hash)
        .await;
    assert!(
        exfil_blob.is_err(),
        "peer with scope_a lease must NOT fetch scope_b source blob hash"
    );

    // Fetching a HashSeq (offset > 0) against scope_a's bundle must also fail closed.
    let bundle_a_hash = snap_a.parsed_bundle_hash().expect("bundle a hash");
    let hashseq_attempt = client_store
        .remote()
        .fetch(
            conn.clone(),
            iroh_blobs::HashAndFormat::hash_seq(bundle_a_hash),
        )
        .await;
    assert!(
        hashseq_attempt.is_err(),
        "HashSeq requests must be refused on iroh-blobs handler"
    );

    // Fetching scope_a's raw bundle hash itself still succeeds.
    let legit_a = client_store.remote().fetch(conn, bundle_a_hash).await;
    assert!(
        legit_a.is_ok(),
        "authorized scope_a raw blob fetch succeeds"
    );

    node_a.shutdown().await.expect("shutdown a");
    node_b.shutdown().await.expect("shutdown b");
}

#[tokio::test]
async fn cross_vault_lease_poisoning_untrusted_tombstone_flood_rollback_and_clock_skew_fail_closed()
{
    let dir_a = tempfile::tempdir().expect("tempdir a");
    let key_a = deterministic_secret_key(71);
    let key_b = deterministic_secret_key(72);
    let key_attacker = deterministic_secret_key(73);

    let mut ws_a = mneme_store::Workspace::create(dir_a.path(), config_factory()())
        .expect("create workspace a");
    commit_scoped_source(&mut ws_a, &scope(), "c-sec-1", 21, b"sec-payload");
    let vault_id = ws_a.genesis_revision().expect("genesis").to_hex();

    let now_secs = 1_700_000_000_u64;
    let clock: std::sync::Arc<dyn mneme_store::Clock> =
        std::sync::Arc::new(mneme_store::FixedClock::new(
            mneme_core::Timestamp::from_nanos((now_secs as i64) * 1_000_000_000),
        ));
    let rev_a = mneme_sync::SharedRevocationSet::new(mneme_sync::RevocationSet::new());
    let rev_b = mneme_sync::SharedRevocationSet::new(mneme_sync::RevocationSet::new());

    let node_a = mneme_sync::SyncNode::bind(mneme_sync::SyncNodeConfig {
        secret_key: key_a.clone(),
        allowlist: mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new()),
        revocations: rev_a.clone(),
        trusted_roots: std::collections::BTreeSet::from([key_a.public()]),
        clock: std::sync::Arc::clone(&clock),
        discovery: mneme_sync::DiscoveryMode::OfflineLoopback,
        relay: mneme_sync::RelayPreference::Disabled,
        bind_addrs: vec![std::net::SocketAddr::from(([127, 0, 0, 1], 0))],
    })
    .await
    .expect("bind a");
    let node_b = mneme_sync::SyncNode::bind(mneme_sync::SyncNodeConfig {
        secret_key: key_b.clone(),
        allowlist: mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new()),
        revocations: rev_b.clone(),
        trusted_roots: std::collections::BTreeSet::from([key_a.public()]),
        clock: std::sync::Arc::clone(&clock),
        discovery: mneme_sync::DiscoveryMode::OfflineLoopback,
        relay: mneme_sync::RelayPreference::Disabled,
        bind_addrs: vec![std::net::SocketAddr::from(([127, 0, 0, 1], 0))],
    })
    .await
    .expect("bind b");
    node_b.add_peer_addr(node_a.addr());

    let snapshot = node_a
        .publish_workspace(&ws_a, &vault_id, &scope())
        .await
        .expect("publish");

    // 1. Future-dated issued_at_secs beyond MAX_CLOCK_SKEW_SECS fails closed.
    let future_cap = mneme_sync::CapabilityToken::grant(
        &key_a,
        mneme_sync::GrantRequest {
            vault_id: vault_id.clone(),
            subject: key_b.public(),
            scope: mneme_sync::CapabilityScope::from_scopes([scope()]).expect("scope"),
            authority: mneme_sync::CapabilityAuthority::ReadOnly,
            issued_at_secs: now_secs + mneme_sync::MAX_CLOCK_SKEW_SECS + 10,
            expires_at_secs: now_secs + mneme_sync::MAX_CLOCK_SKEW_SECS + 600,
            max_delegation_depth: 1,
        },
    )
    .expect("grant future");
    let future_err = mneme_sync::verify_capability(&mneme_sync::VerificationRequest {
        token: &future_cap,
        presenter: key_b.public(),
        vault_id: &vault_id,
        scope: &scope(),
        required_authority: mneme_sync::CapabilityAuthority::ReadOnly,
        now_secs,
        trusted_roots: &std::collections::BTreeSet::from([key_a.public()]),
        revocations: &mneme_sync::RevocationSet::new(),
    });
    assert!(
        future_err.is_err(),
        "future issued_at_secs must fail closed"
    );

    // 2. Cross-vault lease poisoning via PushHead and SyncRevocations fails closed.
    let foreign_vault = "vault-foreign-unconfigured";
    let cap_foreign = mneme_sync::CapabilityToken::grant(
        &key_a,
        mneme_sync::GrantRequest {
            vault_id: foreign_vault.to_owned(),
            subject: key_b.public(),
            scope: mneme_sync::CapabilityScope::from_scopes([scope()]).expect("scope"),
            authority: mneme_sync::CapabilityAuthority::SyncPush,
            issued_at_secs: now_secs,
            expires_at_secs: now_secs + 600,
            max_delegation_depth: 1,
        },
    )
    .expect("grant foreign");
    let mut foreign_ann = snapshot.to_announcement();
    foreign_ann.vault_id = foreign_vault.to_owned();
    let foreign_ann = foreign_ann.signed(&key_b).expect("sign foreign");
    let push_foreign = node_b
        .push_head_with_capability(node_a.node_id(), &foreign_ann, &cap_foreign)
        .await;
    assert!(
        push_foreign.is_err(),
        "unconfigured vault PushHead must fail"
    );
    let sync_foreign = node_b
        .sync_revocations(node_a.node_id(), Some(&cap_foreign))
        .await;
    assert!(
        sync_foreign.is_err(),
        "unconfigured vault SyncRevocations must fail"
    );
    assert_eq!(
        node_a.leases().lease_count_for_peer(key_b.public()),
        0,
        "foreign vault probes must not insert any leases"
    );

    // 3. Untrusted Ed25519 tombstone flood via SyncRevocations is rejected without growing rev_a.
    let cap_legit = mneme_sync::CapabilityToken::grant(
        &key_a,
        mneme_sync::GrantRequest {
            vault_id: vault_id.clone(),
            subject: key_b.public(),
            scope: mneme_sync::CapabilityScope::from_scopes([scope()]).expect("scope"),
            authority: mneme_sync::CapabilityAuthority::SyncPush,
            issued_at_secs: now_secs,
            expires_at_secs: now_secs + 600,
            max_delegation_depth: 1,
        },
    )
    .expect("grant legit");
    let untrusted_tombstone = mneme_sync::RevocationTombstone::issue(
        &key_attacker,
        &vault_id,
        cap_legit.root_id().expect("root"),
        now_secs,
        Some("untrusted flood"),
    )
    .expect("issue untrusted");
    rev_b
        .insert(untrusted_tombstone)
        .expect("insert into b local");
    let flood_res = node_b
        .sync_revocations(node_a.node_id(), Some(&cap_legit))
        .await;
    assert!(flood_res.is_err(), "untrusted tombstone must be rejected");
    assert_eq!(
        rev_a.len_u64(),
        0,
        "untrusted tombstones must not grow server RevocationSet"
    );

    // 4. Signed HeadAnnouncement + monotonic seq rollback protection.
    let mut ann_seq_5 = snapshot.to_announcement();
    ann_seq_5.seq = 5;
    let ann_seq_5 = ann_seq_5.signed(&key_b).expect("sign seq 5");
    node_b
        .push_head_with_capability(node_a.node_id(), &ann_seq_5, &cap_legit)
        .await
        .expect("seq 5 push accepted");

    // Rollback to seq 4 must fail closed!
    let mut ann_seq_4 = snapshot.to_announcement();
    ann_seq_4.seq = 4;
    let ann_seq_4 = ann_seq_4.signed(&key_b).expect("sign seq 4");
    let rollback_err = node_b
        .push_head_with_capability(node_a.node_id(), &ann_seq_4, &cap_legit)
        .await;
    assert!(
        rollback_err.is_err(),
        "rollback push seq=4 must fail closed"
    );
    assert_eq!(node_a.last_pushed_head(&scope()).map(|a| a.seq), Some(5));

    // Replay seq 5 must also fail closed, while seq 6 succeeds!
    let replay_err = node_b
        .push_head_with_capability(node_a.node_id(), &ann_seq_5, &cap_legit)
        .await;
    assert!(replay_err.is_err(), "replayed push seq=5 must fail closed");

    let mut ann_seq_6 = snapshot.to_announcement();
    ann_seq_6.seq = 6;
    let ann_seq_6 = ann_seq_6.signed(&key_b).expect("sign seq 6");
    node_b
        .push_head_with_capability(node_a.node_id(), &ann_seq_6, &cap_legit)
        .await
        .expect("monotonic seq 6 push succeeds");
    assert_eq!(node_a.last_pushed_head(&scope()).map(|a| a.seq), Some(6));

    // 5. Tampered HeadAnnouncement signature fails closed on decode & verify.
    let mut tampered = ann_seq_6.clone();
    tampered.seq = 999;
    assert!(tampered.verify_signature().is_err());

    // 6. Paginated revocation sync across > MAX_REVOCATIONS_PER_PAGE trusted tombstones.
    let rev_server = mneme_sync::SharedRevocationSet::new(mneme_sync::RevocationSet::new());
    let rev_client = mneme_sync::SharedRevocationSet::new(mneme_sync::RevocationSet::new());
    let total_tombstones = mneme_sync::MAX_REVOCATIONS_PER_PAGE + 40;
    for idx in 0..total_tombstones {
        let mut id_bytes = [0_u8; 16];
        id_bytes[..8].copy_from_slice(&idx.to_le_bytes());
        let tomb = mneme_sync::RevocationTombstone::issue(
            &key_a,
            &vault_id,
            mneme_sync::TokenId::from_bytes(id_bytes),
            now_secs + idx,
            Some("paginated"),
        )
        .expect("issue tombstone");
        rev_server.insert(tomb).expect("insert server");
    }
    let allow_srv = mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new());
    allow_srv
        .allow(mneme_sync::AllowedPeer {
            node_id: key_b.public(),
            label: Some("b".to_owned()),
            allowance: mneme_sync::ScopeAllowance::Any,
        })
        .expect("allow b");
    let allow_cli = mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new());
    allow_cli
        .allow(mneme_sync::AllowedPeer {
            node_id: key_a.public(),
            label: Some("a".to_owned()),
            allowance: mneme_sync::ScopeAllowance::Any,
        })
        .expect("allow a");

    let key_s = deterministic_secret_key(74);
    let key_c = deterministic_secret_key(75);
    allow_srv
        .allow(mneme_sync::AllowedPeer {
            node_id: key_c.public(),
            label: None,
            allowance: mneme_sync::ScopeAllowance::Any,
        })
        .expect("allow c");
    allow_cli
        .allow(mneme_sync::AllowedPeer {
            node_id: key_s.public(),
            label: None,
            allowance: mneme_sync::ScopeAllowance::Any,
        })
        .expect("allow s");

    let page_srv = mneme_sync::SyncNode::bind(mneme_sync::SyncNodeConfig {
        secret_key: key_s.clone(),
        allowlist: allow_srv,
        revocations: rev_server.clone(),
        trusted_roots: std::collections::BTreeSet::from([key_a.public()]),
        clock: std::sync::Arc::clone(&clock),
        discovery: mneme_sync::DiscoveryMode::OfflineLoopback,
        relay: mneme_sync::RelayPreference::Disabled,
        bind_addrs: vec![std::net::SocketAddr::from(([127, 0, 0, 1], 0))],
    })
    .await
    .expect("bind page srv");
    let page_cli = mneme_sync::SyncNode::bind(mneme_sync::SyncNodeConfig {
        secret_key: key_c.clone(),
        allowlist: allow_cli,
        revocations: rev_client.clone(),
        trusted_roots: std::collections::BTreeSet::from([key_a.public()]),
        clock: std::sync::Arc::clone(&clock),
        discovery: mneme_sync::DiscoveryMode::OfflineLoopback,
        relay: mneme_sync::RelayPreference::Disabled,
        bind_addrs: vec![std::net::SocketAddr::from(([127, 0, 0, 1], 0))],
    })
    .await
    .expect("bind page cli");
    page_cli.add_peer_addr(page_srv.addr());

    let synced = page_cli
        .sync_revocations(page_srv.node_id(), None)
        .await
        .expect("paginated sync succeeds");
    assert_eq!(synced, total_tombstones);
    assert_eq!(rev_client.len_u64(), total_tombstones);

    // 7. Per-peer lease cap and TTL eviction.
    let lease_table = mneme_sync::SharedCapabilityLeases::new();
    let empty_revs = mneme_sync::SharedRevocationSet::new(mneme_sync::RevocationSet::new());
    let roots = std::collections::BTreeSet::from([key_a.public()]);
    for i in 0..(mneme_sync::MAX_LEASES_PER_PEER + 10) {
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(&i.to_le_bytes());
        let verified = mneme_sync::VerifiedCapability {
            root_id: mneme_sync::TokenId::from_bytes(bytes),
            leaf_id: mneme_sync::TokenId::from_bytes(bytes),
            link_ids: vec![mneme_sync::TokenId::from_bytes(bytes)],
            issuer_chain: vec![key_a.public()],
            subject: key_b.public(),
            scope: mneme_sync::CapabilityScope::Wildcard,
            authority: mneme_sync::CapabilityAuthority::ReadOnly,
            expires_at_secs: now_secs + 10 + i,
            chain_depth: 1,
        };
        lease_table
            .record_lease_with_eviction(
                key_b.public(),
                &vault_id,
                &verified,
                &mneme_sync::LeaseEvictionContext {
                    now_secs,
                    trusted_roots: &roots,
                    revocations: &empty_revs,
                },
            )
            .expect("record bounded lease");
    }
    assert!(lease_table.lease_count_for_peer(key_b.public()) <= mneme_sync::MAX_LEASES_PER_PEER);
    let evicted = lease_table
        .evict_inactive(&mneme_sync::LeaseEvictionContext {
            now_secs: now_secs + 10_000,
            trusted_roots: &roots,
            revocations: &empty_revs,
        })
        .expect("evict expired");
    assert_eq!(evicted, mneme_sync::MAX_LEASES_PER_PEER);
    assert_eq!(lease_table.lease_count_for_peer(key_b.public()), 0);

    page_srv.shutdown().await.expect("shutdown page srv");
    page_cli.shutdown().await.expect("shutdown page cli");
    node_a.shutdown().await.expect("shutdown a");
    node_b.shutdown().await.expect("shutdown b");
}

#[test]
fn capability_kernel_attenuation_and_gset_revocation_dominance() {
    let root_key = iroh::SecretKey::from_bytes(&[0x31; 32]);
    let mid_key = iroh::SecretKey::from_bytes(&[0x32; 32]);
    let leaf_key = iroh::SecretKey::from_bytes(&[0x33; 32]);
    let scope_alpha =
        mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "alpha").expect("alpha");
    let scope_beta =
        mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "beta").expect("beta");
    let now_secs = 1_700_000_000_u64;

    let root = mneme_sync::CapabilityToken::grant(
        &root_key,
        mneme_sync::GrantRequest {
            vault_id: "vault-kernel".to_owned(),
            subject: mid_key.public(),
            scope: mneme_sync::CapabilityScope::from_scopes([
                scope_alpha.clone(),
                scope_beta.clone(),
            ])
            .expect("root scope"),
            authority: mneme_sync::CapabilityAuthority::SyncPush,
            issued_at_secs: now_secs,
            expires_at_secs: now_secs + 3_600,
            max_delegation_depth: 3,
        },
    )
    .expect("root grant");

    // Scope escalation (Wildcard beneath Explicit) must fail.
    let scope_escalation = root.delegate(
        &mid_key,
        mneme_sync::DelegateRequest {
            subject: leaf_key.public(),
            scope: mneme_sync::CapabilityScope::wildcard(),
            authority: mneme_sync::CapabilityAuthority::ReadOnly,
            issued_at_secs: now_secs + 10,
            expires_at_secs: now_secs + 1_800,
            remaining_depth: Some(1),
        },
    );
    assert!(scope_escalation.is_err());

    // Valid attenuated chain: SyncPush/{alpha,beta} -> ReadOnly/{alpha}.
    let leaf = root
        .delegate(
            &mid_key,
            mneme_sync::DelegateRequest {
                subject: leaf_key.public(),
                scope: mneme_sync::CapabilityScope::from_scopes([scope_alpha.clone()])
                    .expect("leaf scope"),
                authority: mneme_sync::CapabilityAuthority::ReadOnly,
                issued_at_secs: now_secs + 10,
                expires_at_secs: now_secs + 1_800,
                remaining_depth: Some(1),
            },
        )
        .expect("leaf delegate");

    let trusted_roots = std::collections::BTreeSet::from([root_key.public()]);
    let empty_revs = mneme_sync::RevocationSet::new();
    let verified = mneme_sync::verify_capability(&mneme_sync::VerificationRequest {
        token: &leaf,
        presenter: leaf_key.public(),
        vault_id: "vault-kernel",
        scope: &scope_alpha,
        required_authority: mneme_sync::CapabilityAuthority::ReadOnly,
        now_secs: now_secs + 20,
        trusted_roots: &trusted_roots,
        revocations: &empty_revs,
    })
    .expect("valid attenuated leaf");
    assert_eq!(verified.chain_depth, 2);

    // G-Set revocation dominance: revoking the root link dominates under any merge order.
    let tomb_root = mneme_sync::RevocationTombstone::issue(
        &root_key,
        "vault-kernel",
        root.root_id().expect("root id"),
        now_secs + 30,
        Some("compromised root"),
    )
    .expect("issue tombstone");
    let tomb_other = mneme_sync::RevocationTombstone::issue(
        &mid_key,
        "vault-kernel",
        mneme_sync::TokenId::from_bytes([0xee; 16]),
        now_secs + 31,
        Some("unrelated"),
    )
    .expect("issue unrelated tombstone");

    let mut replica_ab = mneme_sync::RevocationSet::new();
    replica_ab.insert(tomb_root.clone()).expect("insert root");
    replica_ab.insert(tomb_other.clone()).expect("insert other");

    let mut replica_ba = mneme_sync::RevocationSet::new();
    replica_ba.insert(tomb_other).expect("insert other");
    replica_ba.insert(tomb_root).expect("insert root");
    assert_eq!(replica_ab, replica_ba);

    // Idempotent re-merge keeps the revocation dominant.
    let added = replica_ab.merge(&replica_ba).expect("idempotent merge");
    assert_eq!(added, 0);

    let revoked_res = mneme_sync::verify_capability(&mneme_sync::VerificationRequest {
        token: &leaf,
        presenter: leaf_key.public(),
        vault_id: "vault-kernel",
        scope: &scope_alpha,
        required_authority: mneme_sync::CapabilityAuthority::ReadOnly,
        now_secs: now_secs + 40,
        trusted_roots: &trusted_roots,
        revocations: &replica_ab,
    });
    assert!(matches!(
        revoked_res,
        Err(mneme_sync::Failure::CapabilityRevoked { .. })
    ));
}

#[tokio::test]
async fn multi_mib_blake3_blob_transfers_zero_rehash_via_sidecar_and_enforces_limits() {
    let dir_a = tempfile::tempdir().expect("tempdir a");
    let dir_b = tempfile::tempdir().expect("tempdir b");
    let (mut ws_a, vault_id) = create_fixture_workspace(dir_a.path());

    let key_a = deterministic_secret_key(81);
    let key_b = deterministic_secret_key(82);

    let mut allow_a = mneme_sync::PeerAllowlist::new();
    allow_a.allow(mneme_sync::AllowedPeer {
        node_id: key_b.public(),
        label: Some("peer-b".to_owned()),
        allowance: mneme_sync::ScopeAllowance::Any,
    });
    let mut allow_b = mneme_sync::PeerAllowlist::new();
    allow_b.allow(mneme_sync::AllowedPeer {
        node_id: key_a.public(),
        label: Some("peer-a".to_owned()),
        allowance: mneme_sync::ScopeAllowance::Any,
    });

    let clock: std::sync::Arc<dyn mneme_store::Clock> = std::sync::Arc::new(
        mneme_store::FixedClock::new(mneme_core::Timestamp::from_nanos(1_700_000_000_000_000_000)),
    );
    let node_a = mneme_sync::SyncNode::bind(mneme_sync::SyncNodeConfig {
        secret_key: key_a.clone(),
        allowlist: mneme_sync::SharedAllowlist::new(allow_a),
        revocations: mneme_sync::SharedRevocationSet::new(mneme_sync::RevocationSet::new()),
        trusted_roots: std::collections::BTreeSet::new(),
        clock: std::sync::Arc::clone(&clock),
        discovery: mneme_sync::DiscoveryMode::OfflineLoopback,
        relay: mneme_sync::RelayPreference::Disabled,
        bind_addrs: vec![std::net::SocketAddr::from(([127, 0, 0, 1], 0))],
    })
    .await
    .expect("bind node_a");
    let node_b = mneme_sync::SyncNode::bind(mneme_sync::SyncNodeConfig {
        secret_key: key_b.clone(),
        allowlist: mneme_sync::SharedAllowlist::new(allow_b),
        revocations: mneme_sync::SharedRevocationSet::new(mneme_sync::RevocationSet::new()),
        trusted_roots: std::collections::BTreeSet::new(),
        clock,
        discovery: mneme_sync::DiscoveryMode::OfflineLoopback,
        relay: mneme_sync::RelayPreference::Disabled,
        bind_addrs: vec![std::net::SocketAddr::from(([127, 0, 0, 1], 0))],
    })
    .await
    .expect("bind node_b");
    node_b.add_peer_addr(node_a.addr());

    // 1. Initial sync to B so subsequent 3 MiB commit exercises RBSR delta blob transfer!
    let _initial = node_a
        .publish_workspace(&ws_a, &vault_id, &scope())
        .await
        .expect("publish initial");
    let dest_ws = dir_b.path().join("replica");
    let first_pull = node_b
        .pull_scope(mneme_sync::PullRequest {
            peer: node_a.node_id(),
            scope: scope(),
            destination: dest_ws.clone(),
            state_dir: None,
            workspace_config: config_factory(),
        })
        .await
        .expect("initial restore");
    assert_eq!(
        first_pull.disposition,
        mneme_sync::PullDisposition::Restored
    );

    // 2. Commit a 3 MiB BLAKE3 source blob on A; mneme-store creates its .obao4 sidecar.
    let large_len: usize = 3 * 1024 * 1024 + 517;
    let large_bytes: Vec<u8> = (0..large_len)
        .map(|idx| ((idx.wrapping_mul(29).wrapping_add(idx >> 6)) & 0xff) as u8)
        .collect();
    let large_digest = mneme_core::ContentDigest::of_source_bytes(&large_bytes);
    let retained =
        mneme_core::RetainedSource::new(large_digest, large_len as u64, "application/octet-stream")
            .expect("retained");
    let base = ws_a.current_revision().expect("base");
    ws_a.commit(mneme_store::CommitCommand {
        base,
        actor: "large-blob-author".to_owned(),
        scope: scope(),
        idempotency_key: "large-blob-3mib".to_owned(),
        records: vec![mneme_store::RecordDraft {
            schema_version: 2,
            kind: mneme_core::RecordKind::SourceRevision,
            record_id: mneme_core::RecordId::from_bytes([0xd1; 16]),
            revision_id: mneme_core::RevisionId::from_bytes([0xd2; 16]),
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
            ]),
        }],
        source_blobs: vec![mneme_store::SourceBlobDraft::inline(
            large_bytes.clone(),
            mneme_core::Symbol::from("application/octet-stream"),
        )],
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: None,
    })
    .expect("commit large blob");

    let sidecar_path = mneme_store::outboard::path(ws_a.root(), large_digest);
    assert!(
        sidecar_path.is_file(),
        "mneme-store must have generated .obao4 sidecar for 3 MiB blob"
    );

    // 3. Publish on A and prove the disk store reused the workspace .obao4 sidecar directly!
    let _snap = node_a
        .publish_workspace(&ws_a, &vault_id, &scope())
        .await
        .expect("publish large");
    let transport_hash = iroh_blobs::Hash::from_bytes(*large_digest.as_bytes());
    assert!(
        node_a
            .blob_store()
            .entry_reuses_workspace_sidecar(transport_hash),
        "3 MiB BLAKE3 blob must be served directly from workspace blobs/blake3 + .obao4 sidecar"
    );

    // 4. Streaming download budget enforcement refuses before reading payload when max_bytes < size.
    let conn = node_b
        .endpoint()
        .connect(node_a.node_id(), iroh_blobs::ALPN)
        .await
        .expect("connect blobs");
    let oversized_target = dir_b.path().join("oversized.part");
    let budget_err = mneme_sync::blobstore::download_blob_to_file(
        &conn,
        transport_hash,
        1024 * 1024,
        &oversized_target,
        None,
    )
    .await;
    assert!(
        matches!(
            budget_err,
            Err(mneme_sync::Failure::SizeLimitExceeded { .. })
        ),
        "download exceeding max_bytes must fail closed with SizeLimitExceeded, got: {budget_err:?}"
    );
    assert!(
        !oversized_target.exists(),
        "aborted oversized download must clean up staged file"
    );

    // 5. Incremental RBSR delta pull transfers the 3 MiB blob over DiskBlobsProtocol and verifies!
    let delta_pull = node_b
        .pull_scope(mneme_sync::PullRequest {
            peer: node_a.node_id(),
            scope: scope(),
            destination: dest_ws.clone(),
            state_dir: None,
            workspace_config: config_factory(),
        })
        .await
        .expect("delta pull 3 MiB blob");
    assert_eq!(delta_pull.disposition, mneme_sync::PullDisposition::Updated);
    assert_eq!(delta_pull.stats.blobs_fetched, 1);
    assert_eq!(delta_pull.stats.blob_bytes_fetched, large_len as u64);
    assert!(delta_pull.verify_report.is_healthy());
    let restored_bytes = mneme_store::payload::read(&dest_ws, large_digest).expect("read restored");
    assert_eq!(restored_bytes, large_bytes);

    // 6. Corrupting the workspace .obao4 sidecar on disk fails closed during transfer!
    let mut corrupt_sidecar = std::fs::read(&sidecar_path).expect("read sidecar");
    corrupt_sidecar[0] ^= 0xff;
    std::fs::write(&sidecar_path, &corrupt_sidecar).expect("corrupt sidecar");
    let conn_corrupt = node_b
        .endpoint()
        .connect(node_a.node_id(), iroh_blobs::ALPN)
        .await
        .expect("connect blobs corrupt");
    let corrupt_target = dir_b.path().join("corrupt.part");
    let corrupt_res = mneme_sync::blobstore::download_blob_to_file(
        &conn_corrupt,
        transport_hash,
        (large_len as u64) + 1024,
        &corrupt_target,
        None,
    )
    .await;
    assert!(
        corrupt_res.is_err(),
        "corrupted on-disk .obao4 sidecar must fail closed on transfer"
    );

    node_a.shutdown().await.expect("shutdown a");
    node_b.shutdown().await.expect("shutdown b");
}
