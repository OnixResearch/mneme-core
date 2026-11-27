//! CALM barrier-first retention ingestion and HLC persistence / causal-cut tests.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

enum EntityStatus {
    Accepted,
    Proposed,
}

fn entity_draft(
    scope: &mneme_core::ScopeId,
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    label: &str,
    status: EntityStatus,
) -> mneme_store::RecordDraft {
    let properties = match status {
        EntityStatus::Proposed => mneme_core::Value::symbol_dictionary([(
            mneme_core::Symbol::from("status"),
            mneme_core::Value::symbol("proposed"),
        )]),
        EntityStatus::Accepted => mneme_core::Value::dictionary([]),
    };
    mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::Entity,
        record_id,
        revision_id,
        predecessor: None,
        scope: scope.clone(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("entity-type"),
                mneme_core::Value::symbol("topic"),
            ),
            (
                mneme_core::Symbol::from("label"),
                mneme_core::Value::string(label),
            ),
            (mneme_core::Symbol::from("properties"), properties),
        ]),
    }
}

fn forget_entity_barrier(
    target: mneme_core::RecordId,
    generation: u64,
    operation_id: &str,
) -> mneme_store::RetentionCommit {
    mneme_store::RetentionCommit {
        operation_id: operation_id.to_owned(),
        operation_kind: "forget".to_owned(),
        policy_version: "1".to_owned(),
        selectors: Vec::new(),
        suppressions: vec![mneme_store::RetentionSuppression {
            operation_id: operation_id.to_owned(),
            target,
            revision: None,
            target_kind: "entity".to_owned(),
            mode: mneme_store::SuppressionMode::Forgotten,
            content_digest: None,
            generation,
        }],
        locations: Vec::new(),
        retained_metadata: Vec::new(),
    }
}

#[test]
fn concurrent_forget_and_append_converge_without_resurrecting_forgotten_records() {
    let dir = tempfile::tempdir().expect("tempdir");
    let peer_a_dir = dir.path().join("peer-a");
    let peer_b_dir = dir.path().join("peer-b");
    let archive_a_path = dir.path().join("peer-a.mneme");
    let archive_b_path = dir.path().join("peer-b.mneme");
    let scope = common::scope();

    let forgotten_id = mneme_core::RecordId::from_bytes([0x11; 16]);
    let forgotten_rev = mneme_core::RevisionId::from_bytes([0x21; 16]);
    let appended_id = mneme_core::RecordId::from_bytes([0x33; 16]);
    let appended_rev = mneme_core::RevisionId::from_bytes([0x43; 16]);

    // Both peers start with identical committed entity `r` at sequence 1.
    let mut peer_a =
        mneme_store::Workspace::create(&peer_a_dir, common::config(1_700_000_000_000_000_000))
            .expect("create peer A");
    let base_a = peer_a.current_revision().expect("base A");
    peer_a
        .commit(mneme_store::CommitCommand {
            base: base_a,
            actor: "seed".to_owned(),
            scope: scope.clone(),
            idempotency_key: "seed-r".to_owned(),
            records: vec![entity_draft(
                &scope,
                forgotten_id,
                forgotten_rev,
                "sensitive-record",
                EntityStatus::Accepted,
            )],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit r on A");

    let seed_archive = dir.path().join("seed.mneme");
    peer_a
        .export_portable(&seed_archive, &scope)
        .expect("export seed");

    let mut peer_b =
        mneme_store::Workspace::create(&peer_b_dir, common::config(1_700_000_000_000_000_000))
            .expect("create peer B");
    mneme_store::portability::ingest_into(&seed_archive, &mut peer_b)
        .expect("bootstrap peer B from seed");
    assert_eq!(peer_b.snapshot().expect("snap B").records.len(), 1);

    // Peer A executes a Stratum B forget barrier on `r` (advancing generation to 2).
    let base_a2 = peer_a.current_revision().expect("head A");
    let next_gen = peer_a.eligibility_generation().expect("gen A") + 1;
    peer_a
        .commit(common::audit_barrier_command(
            base_a2,
            "forget-r",
            forget_entity_barrier(forgotten_id, next_gen, "op-forget-r"),
        ))
        .expect("forget r on A");
    assert_eq!(peer_a.eligibility_generation().expect("gen A after"), 2);
    assert!(
        peer_a
            .snapshot()
            .expect("snap A after forget")
            .records
            .is_empty()
    );

    // Concurrently, Peer B appends disjoint Proposed record `q` while still at gen=1.
    let base_b2 = peer_b.current_revision().expect("head B");
    peer_b
        .commit(mneme_store::CommitCommand {
            base: base_b2,
            actor: "peer-b".to_owned(),
            scope: scope.clone(),
            idempotency_key: "append-q".to_owned(),
            records: vec![entity_draft(
                &scope,
                appended_id,
                appended_rev,
                "disjoint-proposed",
                EntityStatus::Proposed,
            )],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit q on B");
    assert_eq!(peer_b.eligibility_generation().expect("gen B"), 1);

    // Export both peers' portable archives (which carry both commits and retention barriers).
    peer_a
        .export_portable(&archive_a_path, &scope)
        .expect("export peer A");
    peer_b
        .export_portable(&archive_b_path, &scope)
        .expect("export peer B");

    // 1. Peer A (sequence > 0, has forget barrier) ingests Peer B's archive (which contains `r` + `q`):
    //    `r` MUST NOT resurrect, `q` MUST be present, and verify_workspace(Full) MUST be clean.
    mneme_store::portability::ingest_into(&archive_b_path, &mut peer_a)
        .expect("peer A ingests peer B at sequence > 0");
    let snap_a = peer_a.snapshot().expect("snap A converged");
    let ids_a: std::collections::BTreeSet<mneme_core::RecordId> =
        snap_a.records.iter().map(|rec| rec.record_id).collect();
    assert_eq!(ids_a, std::collections::BTreeSet::from([appended_id]));
    assert!(!ids_a.contains(&forgotten_id));
    assert_eq!(peer_a.eligibility_generation().expect("gen A"), 2);
    let verify_a = mneme_store::verify_workspace(&peer_a_dir, mneme_store::VerifyMode::Full)
        .expect("verify peer A");
    assert!(
        verify_a.issues.is_empty(),
        "peer A issues: {:?}",
        verify_a.issues
    );

    // 2. Peer B (sequence > 0, has `r` and `q`) ingests Peer A's retention barrier via `ingest_delta`:
    //    barrier-first merge MUST suppress `r` (including SQLite metadata projection), retain `q`,
    //    advance eligibility_generation to 2, and pass verify_workspace(Full) with 0 ProjectionMismatch.
    let manifest_a =
        mneme_store::portability::read_archive_manifest(&archive_a_path).expect("read manifest A");
    let retention_a = mneme_store::portability::PortableRetentionState {
        generation: manifest_a.generation,
        suppressions: manifest_a.suppressions,
        prunings: manifest_a.prunings,
        key_punctures: Vec::new(),
    };
    let delta_a = mneme_store::portability::PortableDelta {
        scope: scope.clone(),
        remote_revision: peer_a.current_revision().expect("head A"),
        remote_sequence: peer_a.current_sequence().expect("seq A"),
        revisions: Vec::new(),
        blobs: Vec::new(),
        retention: Some(retention_a),
    };
    mneme_store::portability::ingest_delta(&delta_a, &mut peer_b)
        .expect("peer B ingests peer A barrier delta");

    let snap_b = peer_b.snapshot().expect("snap B converged");
    let ids_b: std::collections::BTreeSet<mneme_core::RecordId> =
        snap_b.records.iter().map(|rec| rec.record_id).collect();
    assert_eq!(ids_b, ids_a);
    assert_eq!(peer_b.eligibility_generation().expect("gen B converged"), 2);
    let verify_b = mneme_store::verify_workspace(&peer_b_dir, mneme_store::VerifyMode::Full)
        .expect("verify peer B");
    assert!(
        verify_b.issues.is_empty(),
        "peer B issues: {:?}",
        verify_b.issues
    );
}

#[test]
fn hlc_persistence_legacy_migration_and_barrier_fenced_revision_resolution() {
    let dir = tempfile::tempdir().expect("tempdir");
    let scope = common::scope();
    let t1_ns = 1_700_000_001_000_000_000_i64;
    let t2_ns = 1_700_000_002_000_000_000_i64;
    let t3_ns = 1_700_000_003_000_000_000_i64;

    let clock = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(t1_ns));
    struct AtomicClock(std::sync::Arc<std::sync::atomic::AtomicI64>);
    impl mneme_store::Clock for AtomicClock {
        fn now(&self) -> mneme_core::Timestamp {
            mneme_core::Timestamp::from_nanos(self.0.load(std::sync::atomic::Ordering::SeqCst))
        }
    }

    let mut ws = mneme_store::Workspace::create(
        dir.path(),
        mneme_store::WorkspaceConfig::new(
            Box::new(AtomicClock(std::sync::Arc::clone(&clock))),
            Box::new(mneme_store::NoFaults),
        ),
    )
    .expect("create workspace");
    let genesis = ws.current_revision().expect("genesis");

    let rec1 = mneme_core::RecordId::from_bytes([0x51; 16]);
    let rev1 = ws
        .commit(mneme_store::CommitCommand {
            base: genesis,
            actor: "hlc-test".to_owned(),
            scope: scope.clone(),
            idempotency_key: "c1".to_owned(),
            records: vec![entity_draft(
                &scope,
                rec1,
                mneme_core::RevisionId::from_bytes([0x61; 16]),
                "first",
                EntityStatus::Accepted,
            )],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit 1")
        .revision;
    let hlc1 = ws
        .revision_hlc(rev1)
        .expect("hlc1 query")
        .expect("hlc1 present");
    assert_eq!(hlc1.physical_ns, t1_ns);

    clock.store(t2_ns, std::sync::atomic::Ordering::SeqCst);
    let rec2 = mneme_core::RecordId::from_bytes([0x52; 16]);
    let rev2 = ws
        .commit(mneme_store::CommitCommand {
            base: rev1,
            actor: "hlc-test".to_owned(),
            scope: scope.clone(),
            idempotency_key: "c2".to_owned(),
            records: vec![entity_draft(
                &scope,
                rec2,
                mneme_core::RevisionId::from_bytes([0x62; 16]),
                "second",
                EntityStatus::Accepted,
            )],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit 2")
        .revision;
    let hlc2 = ws
        .revision_hlc(rev2)
        .expect("hlc2 query")
        .expect("hlc2 present");
    assert!(mneme_kernel::hlc::is_before(hlc1, hlc2));

    // Resolve causal cuts before rev1 (genesis), at hlc1 (rev1), between hlc1 and hlc2 (rev1), and at hlc2 (rev2).
    let before_all = mneme_kernel::hlc::HybridTimestamp {
        physical_ns: t1_ns - 1_000,
        logical: 0,
    };
    assert_eq!(
        ws.resolve_revision_at_hlc(before_all).expect("before all"),
        genesis
    );
    assert_eq!(ws.resolve_revision_at_hlc(hlc1).expect("at hlc1"), rev1);
    let between = mneme_kernel::hlc::HybridTimestamp {
        physical_ns: t1_ns + 500_000_000,
        logical: 0,
    };
    assert_eq!(ws.resolve_revision_at_hlc(between).expect("between"), rev1);
    assert_eq!(ws.resolve_revision_at_hlc(hlc2).expect("at hlc2"), rev2);

    // Advance eligibility_generation via a forget barrier at t3:
    // resolving an older `read_hlc` (hlc1) across the barrier MUST fail closed with BarrierAdvanced.
    clock.store(t3_ns, std::sync::atomic::Ordering::SeqCst);
    let next_gen = ws.eligibility_generation().expect("gen") + 1;
    let rev3 = ws
        .commit(common::audit_barrier_command(
            rev2,
            "forget-rec1",
            forget_entity_barrier(rec1, next_gen, "op-forget-rec1"),
        ))
        .expect("commit forget")
        .revision;
    let hlc3 = ws
        .revision_hlc(rev3)
        .expect("hlc3 query")
        .expect("hlc3 present");

    let crossed = ws.resolve_revision_at_hlc(hlc1);
    assert!(matches!(
        crossed,
        Err(mneme_store::Failure::BarrierAdvanced { .. })
    ));
    // Resolving at/after the barrier HLC succeeds and pins rev3.
    assert_eq!(ws.resolve_revision_at_hlc(hlc3).expect("at hlc3"), rev3);

    // Byzantine remote HLC beyond max_skew_ns fails closed.
    let byzantine = mneme_kernel::hlc::HybridTimestamp {
        physical_ns: t3_ns + 60_000_000_000,
        logical: 0,
    };
    assert!(matches!(
        ws.observe_remote_hlc(byzantine),
        Err(mneme_store::Failure::ClockSkewExceeded(_))
    ));
}
