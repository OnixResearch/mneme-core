//! Criterion micro-benchmarks for `mneme-store` FastCDC chunking,
//! Zstd & Zstd-dictionary compression, and verified blob read/span verification.

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
)] // benchmark harness constructs synthetic payloads, uses criterion macros, and asserts via expect
#![allow(clippy::expect_used, clippy::unwrap_used)] // benchmark harness asserts via expect

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

const DOC_LINES: usize = 2_000;

fn synthetic_asciidoc(lines: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(lines * 96);
    for idx in 0..lines {
        let mixed = (idx as u64)
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let line = format!(
            "== Section {idx:05} ({mixed:016x})\nThis paragraph benchmarks FastCDC chunking and Zstd dictionary compression {:08x}.\n",
            (mixed >> 32) & 0xffff_ffff
        );
        out.extend_from_slice(line.as_bytes());
    }
    out
}

fn train_dict() -> Vec<u8> {
    let samples: Vec<Vec<u8>> = (0..64_usize).map(|_| synthetic_asciidoc(8)).collect();
    let refs: Vec<&[u8]> = samples.iter().map(Vec::as_slice).collect();
    mneme_store::dedup::train_zstd_dictionary(&refs, 16 * 1024).expect("train zstd dict")
}

fn bench_fastcdc_and_zstd(c: &mut Criterion) {
    let payload = synthetic_asciidoc(DOC_LINES);
    let digest = mneme_core::ContentDigest::of_source_bytes(&payload);
    let dict = train_dict();
    let cdc_cfg = mneme_store::FastCdcConfig::default();

    let mut group = c.benchmark_group("dedup_zstd");
    group.throughput(Throughput::Bytes(payload.len() as u64));

    group.bench_function("fastcdc_chunk_spans", |b| {
        b.iter(|| {
            let spans = mneme_store::dedup::fastcdc_chunk_spans(black_box(&payload), cdc_cfg)
                .expect("chunk spans");
            black_box(spans.len())
        });
    });

    // Pre-stage a Zstd-dict blob and benchmark verified full read & span verification.
    let dir = tempfile::tempdir().expect("tempdir");
    let dict_digest = mneme_store::dedup::stage_dictionary(dir.path(), &dict).expect("stage dict");
    mneme_store::payload::stage_with_compression(
        dir.path(),
        digest,
        &payload,
        mneme_store::BlobCompression::ZstdDictionary {
            dictionary: dict_digest,
        },
        "text/asciidoc",
    )
    .expect("stage zstd-dict");

    group.bench_function("zstd_dict_verified_read", |b| {
        b.iter(|| {
            let bytes =
                mneme_store::payload::read(black_box(dir.path()), black_box(digest)).expect("read");
            black_box(bytes.len())
        });
    });

    // Pre-stage a raw BLAKE3 blob with `.obao4` outboard and benchmark 16 KiB span verification.
    let raw_dir = tempfile::tempdir().expect("raw tempdir");
    mneme_store::payload::stage(raw_dir.path(), digest, &payload).expect("stage raw");
    let mid = (payload.len() / 2) as u64;
    let span_end = (mid + 16 * 1024).min(payload.len() as u64);

    group.bench_function("bao_tree_verify_16k_span", |b| {
        b.iter(|| {
            let span = mneme_store::verify_span_range(
                black_box(raw_dir.path()),
                black_box(digest),
                mid..span_end,
            )
            .expect("verify span");
            black_box(span.len())
        });
    });

    group.finish();
}

criterion_group!(benches, bench_fastcdc_and_zstd);
criterion_main!(benches);
