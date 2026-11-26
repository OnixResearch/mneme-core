//! FoundationDB-style Deterministic Simulation Testing (DST) suite for `mneme-sync`.
//!
//! Runs >= 500 seeded multi-node histories over `N in 2..=5` nodes with deterministic
//! packet drop/reorder/duplicate/asymmetric-partition, per-peer clock skew, storage
//! `FaultPoint` crashes/restarts, retention barriers, and `#[cfg(feature = "trace-spec")]`
//! NDJSON trace validation. Replay any single seed bit-exactly via `MNEME_DST_SEED=<u64>`.

#![allow(
    unknown_lints,
    no_unwrap,
    no_panic,
    assertion_density,
    ambient_env,
    unbounded_collection_growth
)] // DST test reads MNEME_DST_SEED/MNEME_EXPORT_TRACE_NDJSON and collects fixed WORKER_SHARDS handles
#![allow(clippy::unwrap_used, clippy::expect_used)] // DST integration test fails directly on invariant violation

const SEED_COUNT: u64 = 512;
const WORKER_SHARDS: u64 = 8;
const WORKSPACE_DST_SEEDS: u64 = 12;
const BASE_SEED: u64 = 0x51a7_2026_0000_0000;
const REPLAY_CHECK_SEEDS: [u64; 4] = [
    BASE_SEED,
    BASE_SEED.wrapping_add(17),
    BASE_SEED.wrapping_add(129),
    BASE_SEED.wrapping_add(511),
];

fn env_override_seed() -> Option<u64> {
    std::env::var("MNEME_DST_SEED")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
}

fn config_for_seed(seed: u64) -> mneme_sync::sim::Config {
    let offset = seed % 4;
    let nodes = match offset {
        0 => 2,
        1 => 3,
        2 => 4,
        _ => 5,
    };
    mneme_sync::sim::Config::for_nodes(nodes)
}

#[test]
fn dst_500_seeded_multi_node_histories_converge_and_replay_bit_exact() {
    if let Some(single_seed) = env_override_seed() {
        let cfg = config_for_seed(single_seed);
        let first = mneme_sync::sim::run_protocol_dst(single_seed, &cfg)
            .expect("MNEME_DST_SEED replay passed");
        let second = mneme_sync::sim::run_protocol_dst(single_seed, &cfg)
            .expect("MNEME_DST_SEED second replay passed");
        assert_eq!(first, second);
        assert!(first.quiescence_checks >= 2);
        return;
    }

    let shard_size = SEED_COUNT / WORKER_SHARDS;
    let totals = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for shard in 0..WORKER_SHARDS {
            let start = shard.saturating_mul(shard_size);
            let end = start.saturating_add(shard_size);
            handles.push(scope.spawn(move || run_seed_shard(start, end)));
        }
        let mut agg = (0_u64, 0_u64, 0_u64, 0_u64);
        for handle in handles {
            let (ev, dr, du, fl) = handle.join().expect("DST shard panicked");
            agg.0 = agg.0.saturating_add(ev);
            agg.1 = agg.1.saturating_add(dr);
            agg.2 = agg.2.saturating_add(du);
            agg.3 = agg.3.saturating_add(fl);
        }
        agg
    });
    assert!(totals.0 > 5_000);
    assert!(totals.1 > 0);
    assert!(totals.2 > 0);
    assert!(totals.3 > 0);

    for seed in REPLAY_CHECK_SEEDS {
        let cfg = config_for_seed(seed);
        let first = mneme_sync::sim::run_protocol_dst(seed, &cfg).expect("replay run 1");
        let second = mneme_sync::sim::run_protocol_dst(seed, &cfg).expect("replay run 2");
        assert_eq!(first, second);
    }
}

fn run_seed_shard(start: u64, end: u64) -> (u64, u64, u64, u64) {
    let mut events = 0_u64;
    let mut drops = 0_u64;
    let mut dups = 0_u64;
    let mut faults = 0_u64;
    for offset in start..end {
        let seed = BASE_SEED.wrapping_add(offset);
        let cfg = config_for_seed(seed);
        let report = mneme_sync::sim::run_protocol_dst(seed, &cfg)
            .expect("DST protocol history must satisfy all invariants");
        assert!(report.quiescence_checks >= 2);
        assert!(report.events_processed > 0);
        events = events.saturating_add(report.events_processed);
        drops = drops.saturating_add(report.packets_dropped);
        dups = dups.saturating_add(report.packets_duplicated);
        faults = faults.saturating_add(report.faults_injected);
    }
    (events, drops, dups, faults)
}

#[test]
fn dst_fault_seeded_regressions_caught_deterministically() {
    let seed = BASE_SEED.wrapping_add(42);
    assert_fault_seed_caught(
        seed,
        mneme_sync::sim::FaultSeed::LeakFastCdcChunksS1,
        "S1_no_leaked_fastcdc_chunks",
    );
    assert_fault_seed_caught(
        seed,
        mneme_sync::sim::FaultSeed::DropRevocationSetMerge,
        "revocation_set_convergence",
    );
    assert_fault_seed_caught(
        seed,
        mneme_sync::sim::FaultSeed::DropEligibilityGenerationPin,
        "eligibility_generation_pinning",
    );
    // Guarantee at least one duplicate/reordered PushHead hits stale-seq detection.
    let mut push_cfg = mneme_sync::sim::Config::for_nodes(3);
    push_cfg.drop_bps = 0;
    push_cfg.duplicate_bps = 10_000;
    push_cfg.fault_seed = mneme_sync::sim::FaultSeed::AllowStalePushSeqRollback;
    let first = mneme_sync::sim::run_protocol_dst(seed, &push_cfg)
        .expect_err("stale PushHead rollback must be caught");
    let second = mneme_sync::sim::run_protocol_dst(seed, &push_cfg)
        .expect_err("stale PushHead replay must be deterministic");
    assert_eq!(first.invariant, "push_head_monotonic");
    assert_eq!(first, second);
}

fn assert_fault_seed_caught(
    seed: u64,
    fault_seed: mneme_sync::sim::FaultSeed,
    expected_invariant: &str,
) {
    let mut cfg = mneme_sync::sim::Config::for_nodes(3);
    cfg.fault_seed = fault_seed;
    let first = mneme_sync::sim::run_protocol_dst(seed, &cfg)
        .expect_err("fault-seeded bug must fail invariant");
    let second = mneme_sync::sim::run_protocol_dst(seed, &cfg)
        .expect_err("fault-seeded replay must be bit-exact");
    assert_eq!(first.invariant, expected_invariant);
    assert_eq!(first, second);
}

#[tokio::test]
async fn dst_disk_backed_workspace_crash_recovery_and_transport_sync() {
    for offset in 0..WORKSPACE_DST_SEEDS {
        let seed = BASE_SEED.wrapping_add(1_000).wrapping_add(offset);
        let report = mneme_sync::sim::run_workspace_dst(seed)
            .await
            .expect("DST workspace history must satisfy all invariants");
        assert_eq!(report.node_count, 2);
        assert_eq!(report.quiescence_checks, 1);
    }
}

#[cfg(feature = "trace-spec")]
#[test]
fn dst_emits_valid_tla_trace_spec_ndjson_and_catches_faults() {
    let session = mneme_store::trace::Session::start();
    let seed = BASE_SEED.wrapping_add(7);
    let cfg = mneme_sync::sim::Config::for_nodes(2);
    let _report = mneme_sync::sim::run_protocol_dst(seed, &cfg).expect("protocol DST trace seed");
    exercise_workspace_and_restore_trace();

    let events = session.events();
    assert!(!events.is_empty());
    let checked = session
        .validate()
        .expect("live trace must satisfy TraceSpec");
    assert!(checked >= 5);

    let ndjson = session.to_ndjson();
    assert!(ndjson.contains("\"domain\":\"workspace\""));
    assert!(ndjson.contains("\"domain\":\"restore\""));
    assert!(ndjson.contains("\"domain\":\"sync\""));
    if let Ok(export_path) = std::env::var("MNEME_EXPORT_TRACE_NDJSON") {
        std::fs::write(&export_path, &ndjson).expect("write exported NDJSON trace");
    }
}

#[cfg(feature = "trace-spec")]
fn exercise_workspace_and_restore_trace() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("ws");
    let clock = || {
        mneme_store::WorkspaceConfig::new(
            Box::new(mneme_store::FixedClock::new(
                mneme_core::Timestamp::from_nanos(1_700_000_000_000_000_000),
            )),
            Box::new(mneme_store::NoFaults),
        )
    };
    let ws = mneme_store::Workspace::create(&root, clock()).expect("create ws");
    let ledger = ws.export_suppression_ledger().expect("export ledger");
    drop(ws);

    let mut restored =
        mneme_store::Workspace::open_restored(&root, clock()).expect("open restored");
    assert!(restored.snapshot().is_err());
    restored
        .apply_restore_suppression_ledger(&ledger)
        .expect("apply ledger");
}
