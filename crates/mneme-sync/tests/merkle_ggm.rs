//! End-to-end verification of Wave 3 Stage 5:
//! - Multi-parent Merkle-CRDT DAG convergence across K-device sync permutations (`proptest`);
//! - Live loopback two-peer Iroh bidirectional Merkle-CRDT sync and explicit merge resolution;
//! - Immutable read-only `.mneme` backup cryptographic erasure via 32-depth BLAKE3 GGM
//!   puncturable key trees (`MNENC01\0` XChaCha20-Poly1305) and live Iroh
//!   `KeyPunctureBarrier` exchange;
//! - FastCDC per-forget-domain chunk encryption isolation.
#![allow(unknown_lints, no_unwrap, assertion_density)] // test/fixture code fails by panic, not a production path
#![allow(clippy::unwrap_used, clippy::expect_used)] // test/fixture code fails by panic, not a production path

use std::os::unix::fs::PermissionsExt;

use proptest::prelude::*;

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

fn fixed_sync_clock() -> std::sync::Arc<dyn mneme_store::Clock> {
    std::sync::Arc::new(mneme_store::FixedClock::new(
        mneme_core::Timestamp::from_nanos(1_700_000_000_000_000_000),
    ))
}

fn deterministic_secret_key(seed: u8) -> iroh::SecretKey {
    iroh::SecretKey::from_bytes(&[seed; 32])
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
    .expect("bind loopback sync node")
}

fn merkle_scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "merkle-dag").expect("scope")
}

fn confidential_scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::User, "confidential-vault").expect("scope")
}

fn make_revision_id(tag: u8, seq: u8) -> mneme_core::RevisionId {
    let mut bytes = [0_u8; 16];
    bytes[0] = 0x55;
    bytes[1] = tag;
    bytes[2] = seq;
    mneme_core::RevisionId::from_bytes(bytes)
}

fn entity_record_id() -> mneme_core::RecordId {
    mneme_core::RecordId::from_bytes([0x01; 16])
}

fn make_entity_draft(scope: &mneme_core::ScopeId) -> mneme_store::RecordDraft {
    mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::Entity,
        record_id: entity_record_id(),
        revision_id: make_revision_id(0xfe, 0x01),
        predecessor: None,
        scope: scope.clone(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("entity-type"),
                mneme_core::Value::symbol("project"),
            ),
            (
                mneme_core::Symbol::from("label"),
                mneme_core::Value::string("Merkle Test Subject"),
            ),
            (
                mneme_core::Symbol::from("properties"),
                mneme_core::Value::symbol_dictionary([]),
            ),
        ]),
    }
}

struct AssertionSpec<'a> {
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    parents: std::collections::BTreeSet<mneme_core::RevisionId>,
    scope: &'a mneme_core::ScopeId,
    statement: &'a str,
    lifecycle: &'a str,
}

fn make_assertion_draft(spec: AssertionSpec<'_>) -> mneme_store::RecordDraft {
    let payload = mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("subject"),
            mneme_core::Reference::local(entity_record_id(), mneme_core::RecordKind::Entity)
                .to_value(),
        ),
        (
            mneme_core::Symbol::from("predicate"),
            mneme_core::Value::symbol("statement"),
        ),
        (
            mneme_core::Symbol::from("value"),
            mneme_core::Value::string(spec.statement),
        ),
        (
            mneme_core::Symbol::from("stance"),
            mneme_core::Value::symbol("affirm"),
        ),
        (
            mneme_core::Symbol::from("lifecycle"),
            mneme_core::Value::symbol(spec.lifecycle),
        ),
        (
            mneme_core::Symbol::from("origin"),
            mneme_core::Value::symbol("authored-statement"),
        ),
        (
            mneme_core::Symbol::from("asserted-by"),
            mneme_core::Value::string("merkle-test-author"),
        ),
        (
            mneme_core::Symbol::from("valid-time"),
            mneme_core::ValidTime::Unknown.to_value(),
        ),
        (
            mneme_core::Symbol::from("evidence"),
            mneme_core::Value::set([]),
        ),
    ]);
    let predecessor = spec.parents.iter().next().copied();
    let draft = mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::Assertion,
        record_id: spec.record_id,
        revision_id: spec.revision_id,
        predecessor,
        scope: spec.scope.clone(),
        payload,
    };
    draft.with_parents(spec.parents)
}

fn make_source_draft(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    bytes: &[u8],
    path_hint: &str,
) -> mneme_store::RecordDraft {
    let retained = mneme_core::RetainedSource::new(
        mneme_core::ContentDigest::of_source_bytes(bytes),
        bytes.len() as u64,
        "text/plain",
    )
    .expect("retained source");
    mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::SourceRevision,
        record_id,
        revision_id,
        predecessor: None,
        scope: scope.clone(),
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
                mneme_core::Value::string(path_hint),
            ),
        ]),
    }
}

fn collect_record_revisions(
    ws: &mneme_store::Workspace,
    record_id: mneme_core::RecordId,
) -> mneme_store::Result<Vec<mneme_store::RecordRevisionCommit>> {
    let mut all = Vec::with_capacity(32);
    let mut cursor = None;
    for _page_idx in 0_u32..32 {
        let page = match ws.record_revision_commits(record_id, cursor) {
            Ok(page) => page,
            Err(mneme_store::Failure::RetentionSuppressed { .. }) => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        all.reserve(page.entries.len());
        all.extend(page.entries);
        if !page.has_more {
            break;
        }
        cursor = page.next_before_sequence;
    }
    Ok(all)
}

fn all_record_revisions(
    ws: &mneme_store::Workspace,
    record_id: mneme_core::RecordId,
) -> Vec<mneme_store::RecordRevisionCommit> {
    collect_record_revisions(ws, record_id).expect("read record revisions")
}

/// Export all committed revisions of `record_id` in `src` that `dst` does not yet hold,
/// together with `src`'s retention state, and ingest into `dst` via topological Merkle-CRDT delta sync.
fn sync_pair_delta(
    src: &mneme_store::Workspace,
    dst: &mut mneme_store::Workspace,
    scope: &mneme_core::ScopeId,
    record_id: mneme_core::RecordId,
) {
    let src_revs = all_record_revisions(src, record_id);
    let dst_existing: std::collections::BTreeSet<mneme_core::RevisionId> =
        all_record_revisions(dst, record_id)
            .into_iter()
            .map(|entry| entry.record.revision_id)
            .collect();

    let mut missing: Vec<mneme_store::portability::PortableRevision> = src_revs
        .into_iter()
        .filter(|entry| !dst_existing.contains(&entry.record.revision_id))
        .map(|entry| mneme_store::portability::PortableRevision {
            envelope: entry.record,
            commit: entry.commit,
        })
        .collect();
    missing.reverse();

    let retention = src
        .export_retention_state(scope)
        .expect("export portable retention state");
    let delta = mneme_store::portability::PortableDelta {
        scope: scope.clone(),
        remote_revision: src.current_revision().expect("src rev"),
        remote_sequence: src.current_sequence().expect("src seq"),
        revisions: missing,
        blobs: Vec::new(),
        retention: Some(retention),
    };
    let _report = mneme_store::portability::ingest_delta(&delta, dst).expect("merkle delta ingest");
}

fn frontier_ids(
    ws: &mneme_store::Workspace,
    record_id: mneme_core::RecordId,
) -> std::collections::BTreeSet<mneme_core::RevisionId> {
    let snapshot = ws.snapshot().expect("snapshot");
    ws.record_frontier(&snapshot, record_id)
        .into_iter()
        .map(|env| env.revision_id)
        .collect()
}

/// Copy all files from `src_dir` into `dst_dir` (used to seed identical initial device keytrees).
fn copy_dir_files(src_dir: &std::path::Path, dst_dir: &std::path::Path) {
    std::fs::create_dir_all(dst_dir).expect("create dst dir");
    for entry in std::fs::read_dir(src_dir).expect("read src dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_file() {
            let name = entry.file_name();
            std::fs::copy(&path, dst_dir.join(name)).expect("copy file");
        }
    }
}

fn seed_common_ancestor(
    root: &std::path::Path,
    scope: &mneme_core::ScopeId,
    record_id: mneme_core::RecordId,
    root_rev: mneme_core::RevisionId,
) -> mneme_store::Workspace {
    let mut ws = mneme_store::Workspace::create(root, fixed_config()).expect("create workspace");
    let genesis = ws.current_revision().expect("genesis");
    let entity_draft = make_entity_draft(scope);
    let root_draft = make_assertion_draft(AssertionSpec {
        record_id,
        revision_id: root_rev,
        parents: std::collections::BTreeSet::new(),
        scope,
        statement: "Common ancestor statement",
        lifecycle: "accepted",
    });
    ws.commit(mneme_store::CommitCommand {
        base: genesis,
        actor: "genesis-author".to_owned(),
        scope: scope.clone(),
        idempotency_key: "seed-root".to_owned(),
        records: vec![entity_draft, root_draft],
        source_blobs: Vec::new(),
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: None,
    })
    .expect("commit root");
    ws
}

type ParentEdgeMap = std::collections::BTreeMap<
    mneme_core::RevisionId,
    std::collections::BTreeSet<mneme_core::RevisionId>,
>;

type ScheduleOutcome = (
    Vec<std::collections::BTreeSet<mneme_core::RevisionId>>,
    Vec<mneme_kernel::lattice::ProjectedView>,
    ParentEdgeMap,
);

fn build_shuffled_pairs(k: usize, seed: u64) -> Vec<(usize, usize)> {
    let mut pairs = Vec::with_capacity(k.saturating_mul(k));
    for i in 0..k {
        for j in 0..k {
            if i != j {
                pairs.push((i, j));
            }
        }
    }
    let mut state = seed;
    for idx in (1..pairs.len()).rev() {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let modulus = u64::try_from(idx.saturating_add(1)).expect("modulus fits u64");
        let swap_idx = usize::try_from(state.checked_rem(modulus).unwrap_or(0))
            .expect("swap index fits usize");
        pairs.swap(idx, swap_idx);
    }
    pairs
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 24,
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    /// K-device (K in 2..=6) Merkle-CRDT permutation convergence property test:
    /// Arbitrary offline concurrent edits (and optional Forget suppression) synchronized
    /// in two independent random pairwise sync schedules converge to the EXACT same
    /// maximal DAG frontier, project concurrent frontiers to `Disputed` (never LWW
    /// silent overwrite or auto-Accepted), enforce suppression dominance, and collapse
    /// cleanly on explicit multi-parent merge.
    #[test]
    fn k_device_merkle_crdt_permutation_convergence_proptest(
        k in 2_usize..=6,
        edit_counts in proptest::collection::vec(1_u8..=2, 6),
        forget_device in proptest::option::of(0_usize..6),
        order_seed_a in 1_u64..10_000,
        order_seed_b in 10_001_u64..20_000,
    ) {
        let scope = merkle_scope();
        let record_id = mneme_core::RecordId::from_bytes([0x11; 16]);
        let root_rev = make_revision_id(0, 0);
        let forget_idx = forget_device.and_then(|idx| idx.checked_rem(k));

        // Run the exact same offline edit schedule under two different sync orders
        // and verify identical converged frontiers & projections across all K devices.
        let run_schedule = |seed: u64| -> ScheduleOutcome {
            let temp = tempfile::tempdir().expect("tempdir");
            let mut devices: Vec<mneme_store::Workspace> = (0..k)
                .map(|idx| {
                    seed_common_ancestor(
                        &temp.path().join(format!("dev-{idx}")),
                        &scope,
                        record_id,
                        root_rev,
                    )
                })
                .collect();

            // Each device performs 1..=2 offline chained edits starting from root_rev.
            let mut expected_parents = ParentEdgeMap::new();
            expected_parents.insert(root_rev, std::collections::BTreeSet::new());

            for (dev_idx, ws) in devices.iter_mut().enumerate() {
                let mut parent = root_rev;
                let count = edit_counts[dev_idx];
                let dev_tag = u8::try_from(dev_idx.saturating_add(1)).expect("dev tag fits u8");
                for step in 1..=count {
                    let rev = make_revision_id(dev_tag, step);
                    let parents = std::collections::BTreeSet::from([parent]);
                    if expected_parents.len() < 64 {
                        expected_parents.insert(rev, parents.clone());
                    }
                    let draft = make_assertion_draft(AssertionSpec {
                        record_id,
                        revision_id: rev,
                        parents,
                        scope: &scope,
                        statement: &format!("device-{dev_idx}-edit-{step}"),
                        lifecycle: "accepted",
                    });
                    let base = ws.current_revision().expect("base");
                    ws.commit(mneme_store::CommitCommand {
                        base,
                        actor: format!("device-{dev_idx}"),
                        scope: scope.clone(),
                        idempotency_key: format!("offline-{dev_idx}-{step}"),
                        records: vec![draft],
                        source_blobs: Vec::new(),
                        publications: Vec::new(),
                        import_candidates: Vec::new(),
                        retention: None,
                    })
                    .expect("offline commit");
                    parent = rev;
                }
            }

            // Optionally commit a Forget suppression barrier on one device before syncing.
            if let Some(f_idx) = forget_idx {
                let base = devices[f_idx].current_revision().expect("forget base");
                let next_gen = devices[f_idx]
                    .eligibility_generation()
                    .expect("gen")
                    .saturating_add(1);
                let op_id = format!("forget-op-{f_idx}");
                devices[f_idx]
                    .commit(mneme_store::CommitCommand {
                        base,
                        actor: format!("device-{f_idx}"),
                        scope: scope.clone(),
                        idempotency_key: format!("forget-{f_idx}"),
                        records: Vec::new(),
                        source_blobs: Vec::new(),
                        publications: Vec::new(),
                        import_candidates: Vec::new(),
                        retention: Some(mneme_store::RetentionCommit {
                            operation_id: op_id.clone(),
                            operation_kind: "forget".to_owned(),
                            policy_version: mneme_retention::POLICY_VERSION.to_owned(),
                            selectors: vec![mneme_store::RetentionSelector {
                                ordinal: 0,
                                kind: "assertion".to_owned(),
                                target: Some(record_id),
                                revision: None,
                                digest: None,
                            }],
                            suppressions: vec![mneme_store::RetentionSuppression {
                                operation_id: op_id,
                                target: record_id,
                                revision: None,
                                target_kind: "assertion".to_owned(),
                                mode: mneme_store::SuppressionMode::Forgotten,
                                content_digest: None,
                                generation: next_gen,
                            }],
                            locations: Vec::new(),
                            retained_metadata: Vec::new(),
                        }),
                    })
                    .expect("commit forget suppression");
            }

            let pairs = build_shuffled_pairs(k, seed);

            // Two full shuffled passes guarantee transitive convergence across all K devices.
            for _round in 0..2 {
                for &(src_i, dst_i) in &pairs {
                    let (src_ws, dst_ws) = if src_i < dst_i {
                        let (left, right) = devices.split_at_mut(dst_i);
                        (&left[src_i], &mut right[0])
                    } else {
                        let (left, right) = devices.split_at_mut(src_i);
                        (&right[0], &mut left[dst_i])
                    };
                    sync_pair_delta(src_ws, dst_ws, &scope, record_id);
                }
            }

            let mut frontiers = Vec::with_capacity(k);
            let mut views = Vec::with_capacity(k);
            let mut observed_parents = ParentEdgeMap::new();

            for ws in &devices {
                let snap = ws.snapshot().expect("snapshot");
                let frontier: std::collections::BTreeSet<mneme_core::RevisionId> = ws
                    .record_frontier(&snap, record_id)
                    .into_iter()
                    .map(|env| env.revision_id)
                    .collect();
                let view = ws.project_record_frontier(&snap, record_id).expect("project");
                frontiers.push(frontier);
                views.push(view);
                if forget_idx.is_none() {
                    for entry in all_record_revisions(ws, record_id) {
                        if observed_parents.len() < 64 {
                            observed_parents.insert(entry.record.revision_id, entry.record.parents());
                        }
                    }
                }
                let report =
                    mneme_store::verify_workspace(ws.root(), mneme_store::VerifyMode::Full)
                        .expect("verify");
                assert!(report.is_healthy(), "workspace unhealthy: {report:?}");
            }

            if forget_idx.is_none() {
                // Verify zero parent rewriting across all synced revisions.
                assert_eq!(observed_parents, expected_parents);

                // Resolve the concurrent frontier explicitly on device 0.
                let frontier = frontiers[0].clone();
                assert_eq!(frontier.len(), k);
                let snap0 = devices[0].snapshot().expect("snap 0");
                assert_eq!(
                    devices[0]
                        .decide_record_frontier_merge(
                            &snap0,
                            record_id,
                            &frontier,
                            mneme_store::MergeDecisionPresence::Present,
                        )
                        .expect("merge decision"),
                    mneme_kernel::lattice::MergeResolutionVerdict::Allowed
                );
                let merge_rev = make_revision_id(0xee, 1);
                let merge_draft = make_assertion_draft(AssertionSpec {
                    record_id,
                    revision_id: merge_rev,
                    parents: frontier,
                    scope: &scope,
                    statement: "Explicit merged resolution",
                    lifecycle: "accepted",
                });
                let base = devices[0].current_revision().expect("merge base");
                devices[0]
                    .commit_merkle_dag(mneme_store::CommitCommand {
                        base,
                        actor: "resolver".to_owned(),
                        scope: scope.clone(),
                        idempotency_key: "explicit-merge".to_owned(),
                        records: vec![merge_draft],
                        source_blobs: Vec::new(),
                        publications: Vec::new(),
                        import_candidates: Vec::new(),
                        retention: None,
                    })
                    .expect("commit explicit merge");
                let snap0_after = devices[0].snapshot().expect("snap 0 after");
                assert_eq!(
                    frontier_ids(&devices[0], record_id),
                    std::collections::BTreeSet::from([merge_rev])
                );
                assert_eq!(
                    devices[0]
                        .project_record_frontier(&snap0_after, record_id)
                        .expect("merged view"),
                    mneme_kernel::lattice::ProjectedView::Active(
                        mneme_kernel::claim::Lifecycle::Accepted
                    )
                );
            }

            (frontiers, views, observed_parents)
        };

        let (frontiers_a, views_a, parents_a) = run_schedule(order_seed_a);
        let (frontiers_b, views_b, parents_b) = run_schedule(order_seed_b);

        // Every device in both sync schedules converges to the exact same frontier & view.
        for idx in 1..k {
            prop_assert_eq!(&frontiers_a[idx], &frontiers_a[0]);
            prop_assert_eq!(&views_a[idx], &views_a[0]);
        }
        prop_assert_eq!(&frontiers_a[0], &frontiers_b[0]);
        prop_assert_eq!(&views_a[0], &views_b[0]);
        prop_assert_eq!(parents_a, parents_b);

        if forget_idx.is_some() {
            // Suppression dominates all concurrent DAG branches regardless of arrival order.
            prop_assert_eq!(views_a[0], mneme_kernel::lattice::ProjectedView::Forgotten);
        } else {
            // Concurrent K-way offline edits always surface as DisputedConcurrent (never silent Accepted).
            let k_u32 = u32::try_from(k).expect("k fits u32");
            prop_assert_eq!(frontiers_a[0].len(), k);
            prop_assert_eq!(
                views_a[0],
                mneme_kernel::lattice::ProjectedView::DisputedConcurrent {
                    frontier_count: k_u32,
                }
            );
        }
    }
}

#[tokio::test]
async fn two_peer_iroh_bidirectional_merkle_crdt_concurrent_edit_and_explicit_merge() {
    let temp = tempfile::tempdir().expect("tempdir");
    let peer_a_root = temp.path().join("peer-a");
    let peer_b_root = temp.path().join("peer-b");
    let scope = merkle_scope();
    let record_id = mneme_core::RecordId::from_bytes([0x22; 16]);
    let rev_0 = make_revision_id(10, 0);
    let rev_a = make_revision_id(10, 1);
    let rev_b = make_revision_id(10, 2);
    let rev_merge = make_revision_id(10, 3);

    // 1. Seed Peer A with common ancestor rev_0 and sync initial state to Peer B over Iroh.
    let mut ws_a = seed_common_ancestor(&peer_a_root, &scope, record_id, rev_0);
    let vault_id = ws_a.genesis_revision().expect("genesis").to_hex();

    let allow_a = mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new());
    let allow_b = mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new());
    let node_a = bind_loopback_node(11, allow_a.clone()).await;
    let node_b = bind_loopback_node(12, allow_b.clone()).await;
    allow_a
        .allow(mneme_sync::AllowedPeer {
            node_id: node_b.node_id(),
            label: Some("peer-b".to_owned()),
            allowance: mneme_sync::ScopeAllowance::from_scopes([scope.clone()]),
        })
        .expect("allow b");
    allow_b
        .allow(mneme_sync::AllowedPeer {
            node_id: node_a.node_id(),
            label: Some("peer-a".to_owned()),
            allowance: mneme_sync::ScopeAllowance::from_scopes([scope.clone()]),
        })
        .expect("allow a");
    node_a.add_peer_addr(node_b.addr());
    node_b.add_peer_addr(node_a.addr());

    node_a
        .publish_workspace(&ws_a, &vault_id, &scope)
        .await
        .expect("publish initial");
    let initial_pull = node_b
        .pull_scope(mneme_sync::PullRequest {
            peer: node_a.node_id(),
            scope: scope.clone(),
            destination: peer_b_root.clone(),
            state_dir: None,
            workspace_config: config_factory(),
        })
        .await
        .expect("initial pull");
    assert_eq!(
        initial_pull.disposition,
        mneme_sync::PullDisposition::Restored
    );

    // 2. Both peers go offline and commit concurrent revisions citing rev_0.
    let mut ws_b = mneme_store::Workspace::open(&peer_b_root, fixed_config()).expect("open peer b");
    let base_a = ws_a.current_revision().expect("base a");
    ws_a.commit(mneme_store::CommitCommand {
        base: base_a,
        actor: "peer-a".to_owned(),
        scope: scope.clone(),
        idempotency_key: "offline-a".to_owned(),
        records: vec![make_assertion_draft(AssertionSpec {
            record_id,
            revision_id: rev_a,
            parents: std::collections::BTreeSet::from([rev_0]),
            scope: &scope,
            statement: "Peer A offline claim",
            lifecycle: "accepted",
        })],
        source_blobs: Vec::new(),
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: None,
    })
    .expect("commit offline a");

    let base_b = ws_b.current_revision().expect("base b");
    ws_b.commit(mneme_store::CommitCommand {
        base: base_b,
        actor: "peer-b".to_owned(),
        scope: scope.clone(),
        idempotency_key: "offline-b".to_owned(),
        records: vec![make_assertion_draft(AssertionSpec {
            record_id,
            revision_id: rev_b,
            parents: std::collections::BTreeSet::from([rev_0]),
            scope: &scope,
            statement: "Peer B offline claim",
            lifecycle: "accepted",
        })],
        source_blobs: Vec::new(),
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: None,
    })
    .expect("commit offline b");

    // 3. Reconnect and sync bidirectionally over live Iroh `/mneme/sync/1`!
    node_a
        .publish_workspace(&ws_a, &vault_id, &scope)
        .await
        .expect("publish a");
    node_b
        .publish_workspace(&ws_b, &vault_id, &scope)
        .await
        .expect("publish b");

    let pull_b_from_a = node_b
        .pull_scope(mneme_sync::PullRequest {
            peer: node_a.node_id(),
            scope: scope.clone(),
            destination: peer_b_root.clone(),
            state_dir: None,
            workspace_config: config_factory(),
        })
        .await
        .expect("peer b pulls from peer a");
    assert_eq!(
        pull_b_from_a.disposition,
        mneme_sync::PullDisposition::Updated
    );

    let pull_a_from_b = node_a
        .pull_scope(mneme_sync::PullRequest {
            peer: node_b.node_id(),
            scope: scope.clone(),
            destination: peer_a_root.clone(),
            state_dir: None,
            workspace_config: config_factory(),
        })
        .await
        .expect("peer a pulls from peer b");
    assert_eq!(
        pull_a_from_b.disposition,
        mneme_sync::PullDisposition::Updated
    );

    // 4. Both peers converge to the identical 2-head concurrent frontier {rev_a, rev_b}
    //    and deterministically project to DisputedConcurrent (never silent Accepted).
    let expected_frontier = std::collections::BTreeSet::from([rev_a, rev_b]);
    let snap_a = ws_a.snapshot().expect("snap a");
    let snap_b = ws_b.snapshot().expect("snap b");
    assert_eq!(frontier_ids(&ws_a, record_id), expected_frontier);
    assert_eq!(frontier_ids(&ws_b, record_id), expected_frontier);
    assert_eq!(
        ws_a.project_record_frontier(&snap_a, record_id)
            .expect("view a"),
        mneme_kernel::lattice::ProjectedView::DisputedConcurrent { frontier_count: 2 }
    );
    assert_eq!(
        ws_b.project_record_frontier(&snap_b, record_id)
            .expect("view b"),
        mneme_kernel::lattice::ProjectedView::DisputedConcurrent { frontier_count: 2 }
    );

    // Incomplete parents or missing decision are refused; explicit merge is allowed.
    assert_eq!(
        ws_a.decide_record_frontier_merge(
            &snap_a,
            record_id,
            &std::collections::BTreeSet::from([rev_a]),
            mneme_store::MergeDecisionPresence::Present,
        )
        .expect("incomplete merge"),
        mneme_kernel::lattice::MergeResolutionVerdict::RefusedIncompleteParents
    );
    assert_eq!(
        ws_a.decide_record_frontier_merge(
            &snap_a,
            record_id,
            &expected_frontier,
            mneme_store::MergeDecisionPresence::Absent,
        )
        .expect("missing decision"),
        mneme_kernel::lattice::MergeResolutionVerdict::RefusedMissingDecision
    );
    assert_eq!(
        ws_a.decide_record_frontier_merge(
            &snap_a,
            record_id,
            &expected_frontier,
            mneme_store::MergeDecisionPresence::Present,
        )
        .expect("allowed merge"),
        mneme_kernel::lattice::MergeResolutionVerdict::Allowed
    );

    // 5. Commit explicit multi-parent merge on Peer A and sync to Peer B over Iroh.
    let base_merge = ws_a.current_revision().expect("base merge");
    ws_a.commit_merkle_dag(mneme_store::CommitCommand {
        base: base_merge,
        actor: "peer-a".to_owned(),
        scope: scope.clone(),
        idempotency_key: "explicit-merge-ab".to_owned(),
        records: vec![make_assertion_draft(AssertionSpec {
            record_id,
            revision_id: rev_merge,
            parents: expected_frontier,
            scope: &scope,
            statement: "Merged resolution of Peer A + Peer B",
            lifecycle: "accepted",
        })],
        source_blobs: Vec::new(),
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: None,
    })
    .expect("commit merge");

    node_a
        .publish_workspace(&ws_a, &vault_id, &scope)
        .await
        .expect("publish merge");
    let pull_merge = node_b
        .pull_scope(mneme_sync::PullRequest {
            peer: node_a.node_id(),
            scope: scope.clone(),
            destination: peer_b_root.clone(),
            state_dir: None,
            workspace_config: config_factory(),
        })
        .await
        .expect("peer b pulls merge");
    assert_eq!(pull_merge.disposition, mneme_sync::PullDisposition::Updated);

    let single_frontier = std::collections::BTreeSet::from([rev_merge]);
    let snap_b_after = ws_b.snapshot().expect("snap b after");
    assert_eq!(frontier_ids(&ws_a, record_id), single_frontier);
    assert_eq!(frontier_ids(&ws_b, record_id), single_frontier);
    assert_eq!(
        ws_b.project_record_frontier(&snap_b_after, record_id)
            .expect("merged view b"),
        mneme_kernel::lattice::ProjectedView::Active(mneme_kernel::claim::Lifecycle::Accepted)
    );
    assert!(
        mneme_store::verify_workspace(ws_a.root(), mneme_store::VerifyMode::Full)
            .expect("verify a")
            .is_healthy()
    );
    assert!(
        mneme_store::verify_workspace(ws_b.root(), mneme_store::VerifyMode::Full)
            .expect("verify b")
            .is_healthy()
    );

    node_a.shutdown().await.expect("shutdown node a");
    node_b.shutdown().await.expect("shutdown node b");
}

#[tokio::test]
async fn immutable_readonly_backup_ggm_cryptographic_erasure_over_iroh_barrier_sync() {
    let temp = tempfile::tempdir().expect("tempdir");
    let peer_a_root = temp.path().join("peer-a");
    let peer_b_root = temp.path().join("peer-b");
    let backup_path = temp.path().join("immutable-backup.mneme");
    let restored_root = temp.path().join("restored-from-immutable-backup");
    let scope = confidential_scope();

    let plaintext_1 = b"CONFIDENTIAL_TOP_SECRET_ALPHA_001: medical record to be forgotten";
    let plaintext_2 = b"CONFIDENTIAL_SURVIVING_BETA_002: surviving financial ledger entry";
    let plaintext_3 = b"CONFIDENTIAL_SURVIVING_GAMMA_003: surviving personal note entry";
    let digest_1 = mneme_core::ContentDigest::of_source_bytes(plaintext_1);
    let digest_2 = mneme_core::ContentDigest::of_source_bytes(plaintext_2);
    let digest_3 = mneme_core::ContentDigest::of_source_bytes(plaintext_3);

    let rec_1 = mneme_core::RecordId::from_bytes([0x31; 16]);
    let rec_2 = mneme_core::RecordId::from_bytes([0x32; 16]);
    let rec_3 = mneme_core::RecordId::from_bytes([0x33; 16]);

    // 1. Create Peer A workspace and commit 3 records into `confidential-vault`
    //    (GGM MNENC01\0 encryption is default-on for confidential scopes).
    let mut ws_a =
        mneme_store::Workspace::create(&peer_a_root, fixed_config()).expect("create peer a");
    let mut base = ws_a.current_revision().expect("genesis");
    for (seq_num, (rec_id, bytes, path_hint)) in [
        (1_u8, (rec_1, plaintext_1.as_slice(), "secret-1.txt")),
        (2_u8, (rec_2, plaintext_2.as_slice(), "secret-2.txt")),
        (3_u8, (rec_3, plaintext_3.as_slice(), "secret-3.txt")),
    ] {
        let draft = make_source_draft(
            rec_id,
            make_revision_id(30, seq_num),
            &scope,
            bytes,
            path_hint,
        );
        let outcome = ws_a
            .commit(mneme_store::CommitCommand {
                base,
                actor: "owner".to_owned(),
                scope: scope.clone(),
                idempotency_key: format!("commit-secret-{seq_num}"),
                records: vec![draft],
                source_blobs: vec![mneme_store::SourceBlobDraft::inline(
                    bytes.to_vec(),
                    mneme_core::Symbol::from("text/plain"),
                )],
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("commit confidential record");
        base = outcome.revision;
    }

    // 2. Verify all 3 blobs on disk are `MNENC01\0` ciphertext frames containing ZERO plaintext,
    //    and `DiskBlobStore` registers raw ciphertext (zero plaintext exposed to relays).
    for (digest, needle) in [
        (digest_1, b"CONFIDENTIAL_TOP_SECRET_ALPHA_001".as_slice()),
        (digest_2, b"CONFIDENTIAL_SURVIVING_BETA_002".as_slice()),
        (digest_3, b"CONFIDENTIAL_SURVIVING_GAMMA_003".as_slice()),
    ] {
        let raw = mneme_store::payload::read_raw_frame(&peer_a_root, digest).expect("raw frame");
        assert!(
            mneme_store::payload::is_encrypted_frame(&raw),
            "confidential blob must be stored as MNENC01\\0 ciphertext"
        );
        assert!(
            !raw.windows(needle.len()).any(|w| w == needle),
            "on-disk ciphertext must not contain plaintext"
        );
    }
    let store_blobs = mneme_sync::DiskBlobStore::new().expect("disk blob store");
    let raw_1 = mneme_store::payload::read_raw_frame(&peer_a_root, digest_1).expect("raw 1");
    let registered_hash = store_blobs
        .register_workspace_blob(&peer_a_root, digest_1, raw_1.len() as u64)
        .expect("register encrypted workspace blob");
    assert_eq!(registered_hash, iroh_blobs::Hash::new(&raw_1));

    // 3. Export immutable `.mneme` backup and lock it read-only (`chmod 0o444`).
    let export = ws_a
        .export_portable(&backup_path, &scope)
        .expect("export immutable backup");
    assert_eq!(export.blob_count, 3);
    assert_eq!(export.record_count, 3);
    std::fs::set_permissions(&backup_path, std::fs::Permissions::from_mode(0o444))
        .expect("chmod 0o444");

    // Verify backup contains ZERO plaintext and ZERO keytree bytes.
    let backup_bytes_before = std::fs::read(&backup_path).expect("read backup");
    for needle in [
        b"CONFIDENTIAL_TOP_SECRET_ALPHA_001".as_slice(),
        b"CONFIDENTIAL_SURVIVING_BETA_002".as_slice(),
        b"CONFIDENTIAL_SURVIVING_GAMMA_003".as_slice(),
        b"SQLite format 3".as_slice(),
    ] {
        assert!(
            !backup_bytes_before
                .windows(needle.len())
                .any(|w| w == needle),
            "immutable .mneme backup must never contain plaintext or keytree SQLite bytes"
        );
    }

    // 4. Seed Peer B with a copy of Peer A's scope keytree prior to erasure
    //    (modeling a second authorized device holding the same scope keytree).
    let ws_b = mneme_store::Workspace::create(&peer_b_root, fixed_config()).expect("create peer b");
    copy_dir_files(
        &peer_a_root.join(mneme_store::keytree::KEYTREE_DIRECTORY),
        &peer_b_root.join(mneme_store::keytree::KEYTREE_DIRECTORY),
    );
    drop(ws_b);

    // Before Forget, Peer B can decrypt ALL 3 records from the read-only `.mneme` backup.
    assert_eq!(
        mneme_store::portability::decrypt_portable_blob(&backup_path, &peer_b_root, digest_1)
            .expect("decrypt 1 before forget"),
        plaintext_1
    );
    assert_eq!(
        mneme_store::portability::decrypt_portable_blob(&backup_path, &peer_b_root, digest_2)
            .expect("decrypt 2 before forget"),
        plaintext_2
    );
    assert_eq!(
        mneme_store::portability::decrypt_portable_blob(&backup_path, &peer_b_root, digest_3)
            .expect("decrypt 3 before forget"),
        plaintext_3
    );

    // 5. Execute `mneme-retention` `Forget` for `rec_1` on Peer A!
    let forget_base = ws_a.current_revision().expect("forget base");
    let forget_outcome = {
        let mut engine = mneme_retention::Engine::new(&mut ws_a);
        engine
            .execute(mneme_retention::Request {
                actor: "owner".to_owned(),
                scope: scope.clone(),
                base_revision: forget_base,
                idempotency_key: "forget-secret-1".to_owned(),
                operation: mneme_retention::OperationKind::Forget,
                selector: mneme_retention::Selector::Source(rec_1),
                effective: None,
                policy: mneme_retention::Policy::default(),
            })
            .expect("execute forget")
    };
    assert!(forget_outcome.logical_withdrawal);

    let barriers_a = ws_a
        .key_puncture_barriers(&scope)
        .expect("peer a key puncture barriers");
    assert!(!barriers_a.is_empty());
    assert!(barriers_a.iter().all(|b| b.scope == scope));
    let source_barrier = barriers_a
        .iter()
        .find(|b| b.digest == Some(digest_1))
        .expect("source blob digest_1 must have a key puncture barrier");

    // 6. Sync ONLY the signed `KeyPunctureBarrier` from Peer A to Peer B over live Iroh `/mneme/sync/1`.
    let allow_a = mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new());
    let allow_b = mneme_sync::SharedAllowlist::new(mneme_sync::PeerAllowlist::new());
    let node_a = bind_loopback_node(21, allow_a.clone()).await;
    let node_b = bind_loopback_node(22, allow_b.clone()).await;
    allow_a
        .allow(mneme_sync::AllowedPeer {
            node_id: node_b.node_id(),
            label: Some("peer-b".to_owned()),
            allowance: mneme_sync::ScopeAllowance::from_scopes([scope.clone()]),
        })
        .expect("allow b");
    allow_b
        .allow(mneme_sync::AllowedPeer {
            node_id: node_a.node_id(),
            label: Some("peer-a".to_owned()),
            allowance: mneme_sync::ScopeAllowance::from_scopes([scope.clone()]),
        })
        .expect("allow a");
    node_a.add_peer_addr(node_b.addr());
    node_b.add_peer_addr(node_a.addr());

    let vault_id = ws_a.genesis_revision().expect("genesis").to_hex();
    node_a
        .publish_workspace(&ws_a, &vault_id, &scope)
        .await
        .expect("publish peer a");

    let synced_barriers = node_b
        .sync_key_punctures(node_a.node_id(), &scope, &peer_b_root, None)
        .await
        .expect("sync key punctures over iroh");
    assert_eq!(synced_barriers.len(), barriers_a.len());
    assert!(
        synced_barriers
            .iter()
            .any(|b| b.key_slot == source_barrier.key_slot && b.digest == Some(digest_1))
    );

    // 7. Verify the immutable `0o444` backup was NEVER modified or re-encrypted.
    let backup_bytes_after = std::fs::read(&backup_path).expect("read backup after");
    assert_eq!(backup_bytes_before, backup_bytes_after);

    // 8. On BOTH Peer A and Peer B, the forgotten record fails closed with
    //    `Failure::CryptographicallyErased`, while 100% of surviving records decrypt cleanly!
    for keytree_root in [&peer_a_root, &peer_b_root] {
        let erased =
            mneme_store::portability::decrypt_portable_blob(&backup_path, keytree_root, digest_1);
        assert!(
            matches!(
                erased,
                Err(mneme_store::Failure::CryptographicallyErased { .. })
            ),
            "forgotten record must fail closed with CryptographicallyErased, got: {erased:?}"
        );
        assert_eq!(
            mneme_store::portability::decrypt_portable_blob(&backup_path, keytree_root, digest_2)
                .expect("surviving record 2 must still decrypt"),
            plaintext_2
        );
        assert_eq!(
            mneme_store::portability::decrypt_portable_blob(&backup_path, keytree_root, digest_3)
                .expect("surviving record 3 must still decrypt"),
            plaintext_3
        );
    }

    // 9. Restore from the untouched read-only `.mneme` backup using Peer B's punctured keytree:
    //    surviving records restore & verify cleanly, forgotten record is omitted cleanly.
    let restore_report = mneme_store::portability::restore_portable_encrypted(
        &backup_path,
        &peer_b_root,
        &restored_root,
        fixed_config(),
    )
    .expect("restore surviving records from immutable backup");
    assert_eq!(restore_report.record_count, 2);
    assert_eq!(restore_report.blob_count, 2);
    assert!(
        restore_report
            .omissions
            .iter()
            .any(|o| o.reason == "cryptographically-erased" && o.count == 1)
    );

    let restored_ws =
        mneme_store::Workspace::open(&restored_root, fixed_config()).expect("open restored");
    assert!(
        mneme_store::verify_workspace(restored_ws.root(), mneme_store::VerifyMode::Full)
            .expect("verify restored")
            .is_healthy()
    );
    assert_eq!(
        mneme_store::payload::read(restored_ws.root(), digest_2).expect("read restored 2"),
        plaintext_2
    );
    assert_eq!(
        mneme_store::payload::read(restored_ws.root(), digest_3).expect("read restored 3"),
        plaintext_3
    );

    // Restore write permission so tempfile cleanup succeeds cleanly on all filesystems.
    std::fs::set_permissions(&backup_path, std::fs::Permissions::from_mode(0o644))
        .expect("restore backup permissions");
    node_a.shutdown().await.expect("shutdown node a");
    node_b.shutdown().await.expect("shutdown node b");
}

#[test]
fn fastcdc_chunk_ggm_encryption_isolates_forget_domains() {
    let temp = tempfile::tempdir().expect("tempdir");
    let scope = confidential_scope();
    let mut tree = mneme_store::keytree::PuncturableTree::open_or_init(temp.path(), &scope)
        .expect("init keytree");
    let chunk_data = b"shared FastCDC content chunk across two forget domains".repeat(8);
    let chunk_digest = mneme_core::ContentDigest::of_source_bytes(&chunk_data);
    let digest_a = mneme_core::ContentDigest::of_source_bytes(b"domain-a-blob");
    let digest_b = mneme_core::ContentDigest::of_source_bytes(b"domain-b-blob");
    let domain_a_slot = tree.allocate_slot(digest_a, None, None).expect("slot a");
    let domain_b_slot = tree.allocate_slot(digest_b, None, None).expect("slot b");

    let enc_a =
        mneme_store::payload::encrypt_cdc_chunk(&tree, domain_a_slot, 0, chunk_digest, &chunk_data)
            .expect("encrypt chunk for domain a");
    let enc_b =
        mneme_store::payload::encrypt_cdc_chunk(&tree, domain_b_slot, 0, chunk_digest, &chunk_data)
            .expect("encrypt chunk for domain b");
    assert_ne!(
        enc_a, enc_b,
        "distinct forget domains must produce distinct ciphertexts"
    );

    // Puncture domain A's key slot.
    let report = tree
        .puncture_slot(domain_a_slot, 2)
        .expect("puncture domain a");
    assert!(report.sibling_keys_written <= mneme_store::keytree::GGM_DEPTH);

    // Domain A fails closed with CryptographicallyErased; domain B still decrypts cleanly.
    let res_a = mneme_store::payload::decrypt_cdc_chunk(&tree, 0, chunk_digest, &enc_a);
    assert!(matches!(
        res_a,
        Err(mneme_store::Failure::CryptographicallyErased { .. })
    ));

    let dec_b = mneme_store::payload::decrypt_cdc_chunk(&tree, 0, chunk_digest, &enc_b)
        .expect("domain b chunk still decrypts");
    assert_eq!(dec_b, chunk_data);
}
