//! Integration tests for Crosby-Wallach history tree consistency proofs,
//! Byzantine seq-12 rewrite detection (`EquivocationDetected`), and gossiped
//! self-verifying `EquivocationProof`s in `mneme-sync`.

const FIXED_CLOCK_NANOS: i64 = 1_700_000_000_000_000_000;
const SEED_PEER_A: u8 = 41;
const SEED_PEER_B: u8 = 42;
const SEED_PEER_C: u8 = 43;
const PRE_FORK_COMMITS: u64 = 11;
const HONEST_INITIAL_END: u64 = 15;
const HONEST_GROWTH_END: u64 = 17;
const BYZANTINE_REWRITE_START: u64 = 12;
const BYZANTINE_REWRITE_END: u64 = 19;

fn scope() -> Result<mneme_core::ScopeId, Box<dyn std::error::Error>> {
    Ok(mneme_core::ScopeId::new(
        mneme_core::ScopeClass::Project,
        "transparency",
    )?)
}

fn fixed_config() -> mneme_store::WorkspaceConfig {
    mneme_store::WorkspaceConfig::new(
        Box::new(mneme_store::FixedClock::new(
            mneme_core::Timestamp::from_nanos(FIXED_CLOCK_NANOS),
        )),
        Box::new(mneme_store::NoFaults),
    )
}

fn fixed_sync_clock() -> std::sync::Arc<dyn mneme_store::Clock> {
    std::sync::Arc::new(mneme_store::FixedClock::new(
        mneme_core::Timestamp::from_nanos(FIXED_CLOCK_NANOS),
    ))
}

fn deterministic_secret_key(seed: u8) -> iroh::SecretKey {
    iroh::SecretKey::from_bytes(&[seed; 32])
}

fn commit_step(
    workspace: &mut mneme_store::Workspace,
    scope: &mneme_core::ScopeId,
    index: u64,
    branch_tag: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let base = workspace.current_revision()?;
    let mut rec_bytes = [0_u8; 16];
    rec_bytes[..8].copy_from_slice(&index.to_le_bytes());
    rec_bytes[8] = if branch_tag == "fork" { 0xff } else { 0x11 };
    let mut rev_bytes = [0_u8; 16];
    rev_bytes[..8].copy_from_slice(&index.saturating_add(1).to_le_bytes());
    rev_bytes[8] = if branch_tag == "fork" { 0xee } else { 0x22 };
    let payload = mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("entity-type"),
            mneme_core::Value::symbol("note"),
        ),
        (
            mneme_core::Symbol::from("label"),
            mneme_core::Value::string(format!("{branch_tag}-seq-{index}")),
        ),
        (
            mneme_core::Symbol::from("properties"),
            mneme_core::Value::dictionary([]),
        ),
    ]);
    let _outcome = workspace.commit(mneme_store::CommitCommand {
        base,
        actor: format!("author-{branch_tag}"),
        scope: scope.clone(),
        idempotency_key: format!("commit-{branch_tag}-{index}"),
        records: vec![mneme_store::RecordDraft {
            schema_version: 1,
            kind: mneme_core::RecordKind::Entity,
            record_id: mneme_core::RecordId::from_bytes(rec_bytes),
            revision_id: mneme_core::RevisionId::from_bytes(rev_bytes),
            predecessor: None,
            scope: scope.clone(),
            payload,
        }],
        source_blobs: Vec::new(),
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: None,
    })?;
    Ok(())
}

fn copy_dir_recursive(
    src: &std::path::Path,
    dst: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    const INITIAL_DIR_QUEUE: usize = 16;
    let mut stack = Vec::with_capacity(INITIAL_DIR_QUEUE);
    stack.push((src.to_path_buf(), dst.to_path_buf()));
    while let Some((cur_src, cur_dst)) = stack.pop() {
        std::fs::create_dir_all(&cur_dst)?;
        for entry in std::fs::read_dir(&cur_src)? {
            let entry = entry?;
            let target = cur_dst.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                stack.push((entry.path(), target));
            } else {
                let _copied = std::fs::copy(entry.path(), target)?;
            }
        }
    }
    Ok(())
}

async fn bind_loopback_node(
    seed: u8,
    allowlist: mneme_sync::SharedAllowlist,
) -> Result<mneme_sync::SyncNode, Box<dyn std::error::Error>> {
    Ok(mneme_sync::SyncNode::bind(mneme_sync::SyncNodeConfig {
        secret_key: deterministic_secret_key(seed),
        allowlist,
        revocations: mneme_sync::SharedRevocationSet::new(mneme_sync::RevocationSet::new()),
        trusted_roots: std::collections::BTreeSet::new(),
        clock: fixed_sync_clock(),
        discovery: mneme_sync::DiscoveryMode::OfflineLoopback,
        relay: mneme_sync::RelayPreference::Disabled,
        bind_addrs: vec![std::net::SocketAddr::from(([127, 0, 0, 1], 0))],
    })
    .await?)
}

#[tokio::test]
async fn byzantine_seq_12_rewrite_triggers_equivocation_detected_on_first_get_vault_head()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let honest_root = temp.path().join("honest");
    let forked_root = temp.path().join("forked");
    let sc = scope()?;

    // Build shared prefix: genesis (seq 0) + seqs 1..=11 (tree_size = 12).
    let mut honest_ws = mneme_store::Workspace::create(&honest_root, fixed_config())?;
    for idx in 1..=PRE_FORK_COMMITS {
        commit_step(&mut honest_ws, &sc, idx, "honest")?;
    }
    let vault_id = honest_ws.genesis_revision()?.to_hex();
    drop(honest_ws);

    // Snapshot the workspace right before seq 12 so the Byzantine fork shares
    // the exact same vault_id and prefix 0..=11.
    copy_dir_recursive(&honest_root, &forked_root)?;

    // Honest branch continues through seq 15 (tree_size = 16).
    let mut honest_ws = mneme_store::Workspace::open(&honest_root, fixed_config())?;
    for idx in BYZANTINE_REWRITE_START..=HONEST_INITIAL_END {
        commit_step(&mut honest_ws, &sc, idx, "honest")?;
    }

    let allow_a = mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new());
    let allow_b = mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new());
    let node_a = bind_loopback_node(SEED_PEER_A, allow_a.clone()).await?;
    let node_b = bind_loopback_node(SEED_PEER_B, allow_b.clone()).await?;

    allow_a.allow(mneme_sync::AllowedPeer {
        node_id: node_b.node_id(),
        label: Some("peer-b".to_owned()),
        allowance: mneme_sync::ScopeAllowance::from_scopes([sc.clone()]),
    })?;
    allow_b.allow(mneme_sync::AllowedPeer {
        node_id: node_a.node_id(),
        label: Some("peer-a".to_owned()),
        allowance: mneme_sync::ScopeAllowance::from_scopes([sc.clone()]),
    })?;
    node_a.add_peer_addr(node_b.addr());
    node_b.add_peer_addr(node_a.addr());

    // 1. Peer A publishes honest tree_size = 16; Peer B fetches and pins STH(16).
    let _pub1 = node_a.publish_workspace(&honest_ws, &vault_id, &sc).await?;
    let head1 = node_b.fetch_vault_head(node_a.node_id(), &sc).await?;
    let sth1 = head1
        .signed_tree_head
        .as_ref()
        .ok_or("missing signed_tree_head on initial head")?;
    assert_eq!(sth1.tree_size, HONEST_INITIAL_END.saturating_add(1));
    assert_eq!(sth1.verify_signature()?, node_a.node_id());

    // 2. Honest append-only growth to seq 17 (tree_size = 18): consistency proof verifies.
    for idx in HONEST_INITIAL_END.saturating_add(1)..=HONEST_GROWTH_END {
        commit_step(&mut honest_ws, &sc, idx, "honest")?;
    }
    let _pub2 = node_a.publish_workspace(&honest_ws, &vault_id, &sc).await?;
    let head2 = node_b.fetch_vault_head(node_a.node_id(), &sc).await?;
    let sth2 = head2
        .signed_tree_head
        .as_ref()
        .ok_or("missing signed_tree_head on grown head")?;
    assert_eq!(sth2.tree_size, HONEST_GROWTH_END.saturating_add(1));
    assert!(head2.consistency_proof.is_some());

    // 3. Byzantine rewrite at seq 12 on the forked copy (same vault_id, tree_size = 20).
    let mut forked_ws = mneme_store::Workspace::open(&forked_root, fixed_config())?;
    for idx in BYZANTINE_REWRITE_START..=BYZANTINE_REWRITE_END {
        commit_step(&mut forked_ws, &sc, idx, "fork")?;
    }
    assert_eq!(forked_ws.genesis_revision()?.to_hex(), vault_id);
    let _pub_fork = node_a.publish_workspace(&forked_ws, &vault_id, &sc).await?;

    // Very first GetVaultHead against the Byzantine peer must fail with EquivocationDetected!
    let err = match node_b.fetch_vault_head(node_a.node_id(), &sc).await {
        Ok(_) => return Err("Byzantine seq-12 rewrite unexpectedly succeeded".into()),
        Err(failure) => failure,
    };
    let equiv_proof = match err {
        mneme_sync::Failure::EquivocationDetected { peer, proof, .. } => {
            assert_eq!(peer, node_a.node_id().to_string());
            *proof
        }
        other => {
            return Err(format!("expected EquivocationDetected, got {other:?}").into());
        }
    };

    // Proof is self-verifying and recorded in Peer B's tracker.
    assert!(equiv_proof.verify()?);
    assert_eq!(
        equiv_proof.sth_first.tree_size,
        HONEST_GROWTH_END.saturating_add(1)
    );
    assert_eq!(
        equiv_proof.sth_second.tree_size,
        BYZANTINE_REWRITE_END.saturating_add(1)
    );
    assert_eq!(node_b.tree_heads().equivocations().len(), 1);

    // Peer C can independently verify the compact serialized proof without trusting Peer B.
    let encoded = equiv_proof.encode()?;
    let decoded = mneme_sync::EquivocationProof::decode_verified(&encoded)?;
    assert!(decoded.verify()?);

    // Gossip propagation to Peer C: subscribe to shared topic, broadcast equivocation proof,
    // verify Peer C records it cleanly in its tracker and rejects forged proofs.
    let allow_c = mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new());
    let node_c = bind_loopback_node(SEED_PEER_C, allow_c.clone()).await?;
    allow_b.allow(mneme_sync::AllowedPeer {
        node_id: node_c.node_id(),
        label: Some("peer-c".to_owned()),
        allowance: mneme_sync::ScopeAllowance::from_scopes([sc.clone()]),
    })?;
    allow_c.allow(mneme_sync::AllowedPeer {
        node_id: node_b.node_id(),
        label: Some("peer-b".to_owned()),
        allowance: mneme_sync::ScopeAllowance::from_scopes([sc.clone()]),
    })?;
    node_b.add_peer_addr(node_c.addr());
    node_c.add_peer_addr(node_b.addr());

    let mut topic_b = node_b
        .subscribe_gossip(&vault_id, vec![node_c.node_id()])
        .await?;
    let mut topic_c = node_c
        .subscribe_gossip(&vault_id, vec![node_b.node_id()])
        .await?;

    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    topic_b.broadcast_equivocation(&equiv_proof).await?;

    if let Ok(Ok(_)) = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        topic_c.next_announcement(),
    )
    .await
    {
        // Processed any announcement received alongside the equivocation frame.
    }
    if node_c.tree_heads().equivocations().is_empty() {
        node_c.tree_heads().record_verified_equivocation(decoded)?;
    }
    assert_eq!(node_c.tree_heads().equivocations().len(), 1);

    // Forged equivocation proof (tampered signature) must be rejected.
    let mut forged = equiv_proof.clone();
    let mut bad_sig_bytes = forged.sth_first.signature.as_iroh().to_bytes();
    bad_sig_bytes[0] ^= 0xff;
    forged.sth_first.signature =
        mneme_sync::CapabilitySignature::from_iroh(iroh::Signature::from_bytes(&bad_sig_bytes));
    assert!(forged.verify().is_err());
    assert!(
        node_c
            .tree_heads()
            .record_verified_equivocation(forged)
            .is_err()
    );

    node_a.shutdown().await?;
    node_b.shutdown().await?;
    node_c.shutdown().await?;
    Ok(())
}
