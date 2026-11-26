//! Criterion micro-benchmarks for `mneme-sync` RBSR set reconciliation
//! over 10,000-key vaults with Δ = 0, Δ = 5, and Δ = 50.

#![allow(
    unknown_lints,
    no_unwrap,
    function_length,
    allocation_in_loop,
    unbounded_collection_growth,
    platform_dependent_cast,
    raw_arithmetic_overflow,
    magic_number,
    explicit_defaults,
    non_trait_imports
)] // benchmark harness generates deterministic keysets, uses criterion macros, and asserts via expect
#![allow(clippy::expect_used, clippy::unwrap_used)] // benchmark harness asserts via expect

use criterion::{Criterion, black_box, criterion_group, criterion_main};

const VAULT_KEYS: u32 = 10_000;

fn key_for(id: u32) -> mneme_sync::RbsrKey {
    let mut raw = [0_u8; 32];
    let mixed = u64::from(id)
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    raw[0..8].copy_from_slice(&mixed.to_be_bytes());
    raw[8..12].copy_from_slice(&id.to_be_bytes());
    mneme_sync::RbsrKey::from_blob_bytes(raw)
}

fn build_rbsr_pair(total_keys: u32, delta_keys: u32) -> (mneme_sync::RbsrSet, mneme_sync::RbsrSet) {
    let local_keys: Vec<mneme_sync::RbsrKey> = (0..total_keys).map(key_for).collect();
    let mut remote_keys = local_keys.clone();
    for offset in 0..delta_keys {
        remote_keys.push(key_for(total_keys + 100_000 + offset));
    }
    (
        mneme_sync::RbsrSet::from_keys(local_keys),
        mneme_sync::RbsrSet::from_keys(remote_keys),
    )
}

fn bench_rbsr_reconcile(c: &mut Criterion) {
    let mut group = c.benchmark_group("rbsr_10k_keys");
    for delta in [0_u32, 5_u32, 50_u32] {
        let (local, remote) = build_rbsr_pair(VAULT_KEYS, delta);
        group.bench_function(format!("delta_{delta}"), |b| {
            b.iter(|| {
                let outcome =
                    mneme_sync::reconcile_in_memory(black_box(&local), black_box(&remote))
                        .expect("rbsr reconcile");
                assert_eq!(outcome.remote_only.len(), delta as usize);
                black_box((outcome.rounds, outcome.bytes_sent, outcome.bytes_received))
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_rbsr_reconcile);
criterion_main!(benches);
