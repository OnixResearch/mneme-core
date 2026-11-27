//! Integration tests for Signed Tree Heads, append-only consistency proofs,
//! inclusion proofs, and equivocation detection in `mneme-api::federation`.

const SERVER_KEY_SEED: u8 = 71;
const CLIENT_KEY_SEED: u8 = 72;
const INITIAL_COMMITS: u64 = 5;
const FOLLOWUP_COMMITS: u64 = 3;
const FORK_COMMITS: u64 = 6;
const FIXED_CLOCK_NANOS: i64 = 1_700_000_000_000_000_000;

fn scope() -> Result<mneme_core::ScopeId, Box<dyn std::error::Error>> {
    Ok(mneme_core::ScopeId::new(
        mneme_core::ScopeClass::Project,
        "fed-history",
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

fn commit_entity(
    workspace: &mut mneme_store::Workspace,
    scope: &mneme_core::ScopeId,
    index: u64,
    tag: &str,
) -> Result<mneme_core::WorkspaceRevisionId, Box<dyn std::error::Error>> {
    let base = workspace.current_revision()?;
    let mut id_bytes = [0_u8; 16];
    id_bytes[..8].copy_from_slice(&index.to_le_bytes());
    id_bytes[15] = if tag == "fork" { 0xaa } else { 0x01 };
    let mut rev_bytes = [0_u8; 16];
    rev_bytes[..8].copy_from_slice(&index.saturating_add(1).to_le_bytes());
    rev_bytes[15] = if tag == "fork" { 0xbb } else { 0x02 };
    let payload = mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("entity-type"),
            mneme_core::Value::symbol("note"),
        ),
        (
            mneme_core::Symbol::from("label"),
            mneme_core::Value::string(format!("{tag}-{index}")),
        ),
        (
            mneme_core::Symbol::from("properties"),
            mneme_core::Value::dictionary([]),
        ),
    ]);
    let outcome = workspace.commit(mneme_store::CommitCommand {
        base,
        actor: "fed-history-test".to_owned(),
        scope: scope.clone(),
        idempotency_key: format!("fed-{tag}-{index}"),
        records: vec![mneme_store::RecordDraft {
            schema_version: 1,
            kind: mneme_core::RecordKind::Entity,
            record_id: mneme_core::RecordId::from_bytes(id_bytes),
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
    Ok(outcome.revision)
}

#[tokio::test]
async fn federation_signs_sth_verifies_consistency_and_inclusion_and_detects_equivocation()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let honest_dir = temp.path().join("honest");
    let forked_dir = temp.path().join("forked");
    let sc = scope()?;

    let mut ws = mneme_store::Workspace::create(&honest_dir, fixed_config())?;
    let mut pinned_rev = ws.current_revision()?;
    for idx in 1..=INITIAL_COMMITS {
        let rev = commit_entity(&mut ws, &sc, idx, "honest")?;
        if idx == 3 {
            pinned_rev = rev;
        }
    }

    let server_key = iroh::SecretKey::from_bytes(&[SERVER_KEY_SEED; 32]);
    let client_key = iroh::SecretKey::from_bytes(&[CLIENT_KEY_SEED; 32]);
    let mut allowlist = mneme_api::federation::PeerAllowlist::empty();
    allowlist.allow(client_key.public());

    let server = mneme_api::federation::VaultFederationServer::spawn(
        mneme_api::federation::ServerConfig::new(&honest_dir, allowlist.clone())
            .with_signing_key(server_key.clone()),
    )?;
    let client = server.local_client_for(client_key.public());

    // 1. Initial query_head pins SignedTreeHead(tree_size = 6).
    let head1 = client.query_head(&sc).await?;
    let sth1 = head1
        .signed_tree_head
        .as_ref()
        .ok_or("expected signed_tree_head from signed federation server")?;
    assert_eq!(sth1.tree_size, INITIAL_COMMITS.saturating_add(1));
    assert_eq!(sth1.verify_signature()?, server_key.public());

    // 2. Append 3 more commits; query_head receives and verifies ConsistencyProof(6 -> 9).
    for idx in INITIAL_COMMITS.saturating_add(1)..=INITIAL_COMMITS.saturating_add(FOLLOWUP_COMMITS)
    {
        let _rev = commit_entity(&mut ws, &sc, idx, "honest")?;
    }
    let head2 = client.query_head(&sc).await?;
    let sth2 = head2
        .signed_tree_head
        .as_ref()
        .ok_or("expected signed_tree_head on grown head")?;
    assert_eq!(
        sth2.tree_size,
        INITIAL_COMMITS
            .saturating_add(FOLLOWUP_COMMITS)
            .saturating_add(1)
    );
    assert!(head2.consistency_proof.is_some());

    // 3. Pinned snapshot fetch attaches and verifies an InclusionProof against STH.
    let snapshot = client
        .fetch_pinned_snapshot(
            &sc,
            Some(pinned_rev),
            mneme_api::federation::FederationLimits::default(),
        )
        .await?;
    let inc = snapshot
        .inclusion_proof
        .as_ref()
        .ok_or("expected inclusion_proof on pinned snapshot")?;
    assert_eq!(inc.leaf_index, 3);
    assert!(snapshot.signed_tree_head.is_some());

    // 4. Spawn a Byzantine server using the SAME signing key over a divergent workspace
    //    with a larger tree_size, and verify the client pins detect equivocation!
    let mut forked_ws = mneme_store::Workspace::create(&forked_dir, fixed_config())?;
    for idx in 1..=INITIAL_COMMITS
        .saturating_add(FOLLOWUP_COMMITS)
        .saturating_add(FORK_COMMITS)
    {
        let _rev = commit_entity(&mut forked_ws, &sc, idx, "fork")?;
    }
    let byzantine_server = mneme_api::federation::VaultFederationServer::spawn(
        mneme_api::federation::ServerConfig::new(&forked_dir, allowlist)
            .with_signing_key(server_key),
    )?;
    let byzantine_client = byzantine_server.local_client_for(client_key.public());
    // Seed the Byzantine client's pins by querying the honest server's STH first,
    // or verify directly via ClientTreeHeadPins::verify_head.
    let pins = mneme_api::federation::ClientTreeHeadPins::new();
    let scope_str = sc.to_string();
    pins.observe(&scope_str, sth1, None)?;
    pins.observe(&scope_str, sth2, head2.consistency_proof.as_ref())?;
    let forked_head = byzantine_client.query_head(&sc).await?;
    let forked_sth = forked_head
        .signed_tree_head
        .as_ref()
        .ok_or("expected signed_tree_head from forked server")?;
    let equiv = pins.observe(
        &scope_str,
        forked_sth,
        forked_head.consistency_proof.as_ref(),
    );
    assert!(matches!(
        equiv,
        Err(mneme_api::federation::FederationError::EquivocationDetected(_))
    ));

    Ok(())
}
