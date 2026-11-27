//! Integration and scale tests for the persistent Crosby-Wallach Merkle history tree.

const COMMIT_COUNT: u64 = 16;
const COMMIT_COUNT_PLUS_GENESIS: usize = 17;
const LARGE_TREE_SIZE: u64 = 100_000;
const LARGE_TREE_CAPACITY: usize = 100_000;
const MID_TREE_SIZE: u64 = 50_000;
const EARLY_TREE_SIZE: u64 = 12;
const DIGEST_LEN: usize = 32;
const MAX_PROOF_BYTES: usize = 1_536;
const FIXED_CLOCK_NANOS: i64 = 1_700_000_000_000_000_000;
const MAX_GEN_PLUS_VERIFY_MICROS: u128 = 50_000;

fn test_config() -> mneme_store::WorkspaceConfig {
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
) -> Result<mneme_core::WorkspaceRevisionId, Box<dyn std::error::Error>> {
    let base = workspace.current_revision()?;
    let mut id_bytes = [0_u8; 16];
    id_bytes[..8].copy_from_slice(&index.to_le_bytes());
    let mut rev_bytes = [0_u8; 16];
    rev_bytes[..8].copy_from_slice(&index.saturating_add(1).to_le_bytes());
    rev_bytes[15] = 0x55;
    let payload = mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("entity-type"),
            mneme_core::Value::symbol("note"),
        ),
        (
            mneme_core::Symbol::from("label"),
            mneme_core::Value::string(format!("item-{index}")),
        ),
        (
            mneme_core::Symbol::from("properties"),
            mneme_core::Value::dictionary([]),
        ),
    ]);
    let outcome = workspace.commit(mneme_store::CommitCommand {
        base,
        actor: "history-tree-test".to_owned(),
        scope: scope.clone(),
        idempotency_key: format!("ht-commit-{index}"),
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

#[test]
fn workspace_commit_persists_history_tree_and_verifies_proofs()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let scope = mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "history")?;
    let mut workspace = mneme_store::Workspace::create(dir.path(), test_config())?;

    let mut roots: Vec<(u64, [u8; DIGEST_LEN])> = Vec::with_capacity(COMMIT_COUNT_PLUS_GENESIS);
    let genesis_head = workspace.history_tree_head()?;
    assert_eq!(genesis_head.tree_size, 1);
    roots.push((genesis_head.tree_size, genesis_head.root));

    for idx in 1..=COMMIT_COUNT {
        let rev = commit_entity(&mut workspace, &scope, idx)?;
        let head = workspace.history_tree_head()?;
        assert_eq!(head.tree_size, idx.saturating_add(1));
        assert_eq!(head.head_revision, rev);
        roots.push((head.tree_size, head.root));
    }

    let final_head = workspace.history_tree_head()?;
    let final_size = final_head.tree_size;
    assert_eq!(final_size, COMMIT_COUNT.saturating_add(1));

    // Verify inclusion of every committed revision inside the final tree.
    for seq in 0..final_size {
        let proof = workspace.history_inclusion_proof(seq, final_size)?;
        assert!(proof.verify(final_head.root));
        let mut wrong_root = final_head.root;
        wrong_root[0] ^= 0x01;
        assert!(!proof.verify(wrong_root));
    }

    // Verify append-only consistency from every historical tree size to final_size.
    for (old_size, old_root) in &roots {
        let proof = workspace.history_consistency_proof(*old_size, final_size)?;
        assert!(proof.verify(*old_root, final_head.root));
        let mut forged_old_root = *old_root;
        forged_old_root[0] ^= 0x80;
        assert!(!proof.verify(forged_old_root, final_head.root));
    }

    // Reopen workspace from disk and confirm root & proofs persist cleanly.
    drop(workspace);
    let reopened = mneme_store::Workspace::open(dir.path(), test_config())?;
    let reopened_head = reopened.history_tree_head()?;
    assert_eq!(reopened_head, final_head);
    let consistency = reopened.history_consistency_proof(EARLY_TREE_SIZE, final_size)?;
    let early_root = reopened.history_tree_root_at(EARLY_TREE_SIZE)?;
    assert!(consistency.verify(early_root, reopened_head.root));
    Ok(())
}

#[test]
fn consistency_proof_at_100k_revisions_meets_size_and_speed_budget()
-> Result<(), Box<dyn std::error::Error>> {
    let mut db = mneme_store::HistoryTreeDb::open_in_memory()?;
    let mut leaves: Vec<(u64, [u8; DIGEST_LEN])> = Vec::with_capacity(LARGE_TREE_CAPACITY);
    for seq in 0..LARGE_TREE_SIZE {
        let digest = *blake3::hash(&seq.to_le_bytes()).as_bytes();
        leaves.push((seq, digest));
    }
    db.append_batch(&leaves)?;

    let root_12 = db.root_at(EARLY_TREE_SIZE)?;
    let root_50k = db.root_at(MID_TREE_SIZE)?;
    let root_100k = db.root_at(LARGE_TREE_SIZE)?;

    // Measure proof generation + verification at 50k -> 100k and 12 -> 100k.
    let start_mid = std::time::Instant::now();
    let proof_mid = db.consistency_proof(MID_TREE_SIZE, LARGE_TREE_SIZE)?;
    let is_mid_valid = proof_mid.verify(root_50k, root_100k);
    let elapsed_mid = start_mid.elapsed();

    let start_early = std::time::Instant::now();
    let proof_early = db.consistency_proof(EARLY_TREE_SIZE, LARGE_TREE_SIZE)?;
    let is_early_valid = proof_early.verify(root_12, root_100k);
    let elapsed_early = start_early.elapsed();

    let mid_bytes = proof_mid.nodes.len().saturating_mul(DIGEST_LEN);
    let early_bytes = proof_early.nodes.len().saturating_mul(DIGEST_LEN);

    assert!(is_mid_valid);
    assert!(is_early_valid);
    assert!(mid_bytes < MAX_PROOF_BYTES);
    assert!(early_bytes < MAX_PROOF_BYTES);
    assert!(elapsed_mid.as_micros() < MAX_GEN_PLUS_VERIFY_MICROS);
    assert!(elapsed_early.as_micros() < MAX_GEN_PLUS_VERIFY_MICROS);

    // Inclusion proof for leaf 12 in 100k tree.
    let inc = db.inclusion_proof(EARLY_TREE_SIZE, LARGE_TREE_SIZE)?;
    assert!(inc.verify(root_100k));
    assert!(inc.audit_path.len().saturating_mul(DIGEST_LEN) < MAX_PROOF_BYTES);

    // Tampering with old_root or proof node must fail closed.
    let mut bad_old = root_50k;
    bad_old[0] ^= 0x01;
    assert!(!proof_mid.verify(bad_old, root_100k));

    let mut tampered_proof = proof_early.clone();
    if let Some(first) = tampered_proof.nodes.first_mut() {
        first[0] ^= 0x01;
    }
    assert!(!tampered_proof.verify(root_12, root_100k));

    eprintln!(
        "100K-HISTORY-TREE: 50k->100k {} nodes ({} B) in {} us; 12->100k {} nodes ({} B) in {} us",
        proof_mid.nodes.len(),
        mid_bytes,
        elapsed_mid.as_micros(),
        proof_early.nodes.len(),
        early_bytes,
        elapsed_early.as_micros(),
    );
    Ok(())
}
