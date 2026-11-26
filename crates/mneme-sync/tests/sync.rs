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
    let blob = mneme_store::SourceBlobDraft {
        bytes,
        media_type: mneme_core::Symbol::from("text/asciidoc"),
    };
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
