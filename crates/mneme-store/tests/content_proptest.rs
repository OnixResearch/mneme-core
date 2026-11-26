//! Property-based (`proptest`) round-trip and 1-byte bitflip rejection suite
//! for `mneme-store` content objects: raw BLAKE3, `bao-tree` `.obao4`
//! outboards, Zstd, Zstd-dictionary, and FastCDC chunked blobs.

#![allow(
    unknown_lints,
    no_unwrap,
    function_length,
    allocation_in_loop,
    too_many_parameters,
    unbounded_collection_growth,
    platform_dependent_cast,
    raw_arithmetic_overflow,
    magic_number,
    explicit_defaults,
    compound_condition,
    fragile_exhaustive_enum_match,
    unchecked_narrowing,
    unchecked_division
)] // property test harness exercises randomized storage payloads and asserts via expect
#![allow(clippy::expect_used, clippy::unwrap_used)] // property test harness asserts via expect

use proptest::prelude::*;

const BOUNDARY_SIZES: &[usize] = &[
    0,
    1,
    16 * 1024 - 1,
    16 * 1024,
    16 * 1024 + 1,
    64 * 1024 - 1,
    64 * 1024,
    64 * 1024 + 1,
    256 * 1024,
];

fn test_scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "proptest").expect("scope")
}

fn test_config() -> mneme_store::WorkspaceConfig {
    mneme_store::WorkspaceConfig {
        clock: Box::new(mneme_store::FixedClock::new(
            mneme_core::Timestamp::from_nanos(10_000),
        )),
        faults: Box::new(mneme_store::NoFaults),
    }
}

#[derive(Clone, Copy)]
enum PayloadStyle {
    Random,
    Compressible,
}

fn make_payload(len: usize, seed: u64, style: PayloadStyle) -> Vec<u8> {
    if len == 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(len);
    let mut state = seed ^ 0x9e37_79b9_7f4a_7c15;
    match style {
        PayloadStyle::Compressible => {
            let mut line_idx: u64 = 0;
            while out.len() < len {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let chunk = format!(
                    "== Section {line_idx:05} seed={:04x}\nRepeated AsciiDoc body line for zstd/dict compression {:04x}.\n",
                    (state >> 48) & 0x00ff,
                    (state >> 32) & 0x00ff
                );
                let remaining = len - out.len();
                let take = remaining.min(chunk.len());
                out.extend_from_slice(&chunk.as_bytes()[..take]);
                line_idx += 1;
            }
        }
        PayloadStyle::Random => {
            for _ in 0..len {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                out.push((state >> 56) as u8);
            }
        }
    }
    out
}

fn train_asciidoc_dict() -> Vec<u8> {
    let owned: Vec<Vec<u8>> = (0..64_u64)
        .map(|i| make_payload(512, i + 1, PayloadStyle::Compressible))
        .collect();
    let refs: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
    mneme_store::dedup::train_zstd_dictionary(&refs, 16 * 1024).expect("train zstd dictionary")
}

fn flip_one_bit(path: &std::path::Path, byte_selector: usize, bit: u8) -> (usize, u8) {
    let mut bytes = std::fs::read(path).expect("read target file for bitflip");
    assert!(!bytes.is_empty(), "cannot bitflip empty file {:?}", path);
    let idx = byte_selector % bytes.len();
    let mask = 1_u8 << (bit % 8);
    bytes[idx] ^= mask;
    std::fs::write(path, &bytes).expect("write bitflipped file");
    (idx, mask)
}

fn restore_bit(path: &std::path::Path, idx: usize, mask: u8) {
    let mut bytes = std::fs::read(path).expect("read target file for restore");
    bytes[idx] ^= mask;
    std::fs::write(path, &bytes).expect("write restored file");
}

fn commit_blob_with_policy(
    dir: &std::path::Path,
    bytes: &[u8],
    compression: mneme_store::BlobCompression,
    chunking: mneme_store::BlobChunking,
    dict_bytes: Option<&[u8]>,
) -> mneme_core::ContentDigest {
    let mut ws = mneme_store::Workspace::create(dir, test_config()).expect("create workspace");
    let effective_compression = match (compression, dict_bytes) {
        (mneme_store::BlobCompression::ZstdDictionary { .. }, Some(dict)) => {
            let dict_digest = ws.stage_zstd_dictionary(dict).expect("stage dict");
            mneme_store::BlobCompression::ZstdDictionary {
                dictionary: dict_digest,
            }
        }
        (other, _) => other,
    };
    ws.set_blob_compression(effective_compression);
    ws.set_blob_chunking(chunking);

    let digest = mneme_core::ContentDigest::of_source_bytes(bytes);
    let retained = mneme_core::RetainedSource::new(digest, bytes.len() as u64, "text/asciidoc")
        .expect("retained source");
    let draft = mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::SourceRevision,
        record_id: mneme_core::RecordId::from_bytes([0x42; 16]),
        revision_id: mneme_core::RevisionId::from_bytes([0x43; 16]),
        predecessor: None,
        scope: test_scope(),
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
                mneme_core::Value::string("notes/proptest.adoc"),
            ),
        ]),
    };
    let genesis = ws.current_revision().expect("genesis");
    ws.commit(mneme_store::CommitCommand {
        base: genesis,
        actor: "proptest".to_owned(),
        scope: test_scope(),
        idempotency_key: "commit-blob".to_owned(),
        records: vec![draft],
        source_blobs: vec![mneme_store::SourceBlobDraft::inline(
            bytes.to_vec(),
            mneme_core::Symbol::from("text/asciidoc"),
        )],
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: None,
    })
    .expect("commit blob");
    digest
}

#[test]
fn boundary_sizes_raw_blake3_and_outboard_roundtrip_and_bitflip_rejection() {
    for (idx, &size) in BOUNDARY_SIZES.iter().enumerate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = make_payload(size, (idx as u64) + 100, PayloadStyle::Random);
        let digest = mneme_core::ContentDigest::of_source_bytes(&payload);
        mneme_store::payload::stage(dir.path(), digest, &payload).expect("stage raw");

        // Exact full round-trip + verification
        let read_back = mneme_store::payload::read(dir.path(), digest).expect("read raw");
        assert_eq!(read_back, payload);
        mneme_store::payload::verify(dir.path(), digest, size as u64).expect("verify raw");

        // Full-range and mid-range verified spans
        let full_span =
            mneme_store::verify_span_range(dir.path(), digest, 0..size as u64).expect("full span");
        assert_eq!(full_span, payload);

        let ob_path = mneme_store::outboard::path(dir.path(), digest);
        if (size as u64) >= mneme_store::outboard::THRESHOLD_BYTES {
            assert!(ob_path.exists(), "expected .obao4 for size={size}");
            // Flip a byte in the outboard sidecar and verify full-range proof rejects it.
            let (ob_idx, ob_mask) = flip_one_bit(&ob_path, idx * 17 + 3, (idx % 8) as u8);
            assert!(
                mneme_store::verify_span_range(dir.path(), digest, 0..size as u64).is_err(),
                "corrupted .obao4 must fail verify_span_range for size={size}"
            );
            restore_bit(&ob_path, ob_idx, ob_mask);
        } else {
            assert!(!ob_path.exists(), "unexpected .obao4 for size={size}");
        }

        // Flip a byte in the canonical blob (for non-empty payloads) and verify 100% rejection.
        if size > 0 {
            let blob_path = mneme_store::payload::blob_path(dir.path(), digest);
            let (b_idx, b_mask) = flip_one_bit(&blob_path, size / 2, 0);
            assert!(mneme_store::payload::read(dir.path(), digest).is_err());
            assert!(mneme_store::payload::verify(dir.path(), digest, size as u64).is_err());
            assert!(mneme_store::verify_span_range(dir.path(), digest, 0..size as u64).is_err());
            restore_bit(&blob_path, b_idx, b_mask);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, failure_persistence: None, .. ProptestConfig::default() })]

    #[test]
    fn proptest_raw_blake3_and_outboard_roundtrip_and_bitflip(
        size in prop_oneof![
            prop::sample::select(BOUNDARY_SIZES),
            1_usize..=(160 * 1024),
        ],
        seed in any::<u64>(),
        span_a in 0_u64..1000,
        span_b in 0_u64..1000,
        flip_pos in any::<usize>(),
        flip_bit in 0_u8..8,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = make_payload(size, seed, PayloadStyle::Random);
        let digest = mneme_core::ContentDigest::of_source_bytes(&payload);
        mneme_store::payload::stage(dir.path(), digest, &payload).expect("stage");

        prop_assert_eq!(mneme_store::payload::read(dir.path(), digest).expect("read"), payload.clone());
        prop_assert!(mneme_store::payload::verify(dir.path(), digest, size as u64).is_ok());

        let len_u64 = size as u64;
        let (start, end) = if len_u64 == 0 {
            (0, 0)
        } else {
            let p1 = span_a % (len_u64 + 1);
            let p2 = span_b % (len_u64 + 1);
            (p1.min(p2), p1.max(p2))
        };
        let span = mneme_store::verify_span_range(dir.path(), digest, start..end)
            .expect("verify_span_range");
        prop_assert_eq!(span.as_slice(), &payload[start as usize..end as usize]);

        if size > 0 {
            let blob_path = mneme_store::payload::blob_path(dir.path(), digest);
            let (b_idx, b_mask) = flip_one_bit(&blob_path, flip_pos, flip_bit);
            prop_assert!(mneme_store::payload::read(dir.path(), digest).is_err());
            prop_assert!(mneme_store::payload::verify(dir.path(), digest, len_u64).is_err());
            prop_assert!(mneme_store::verify_span_range(dir.path(), digest, 0..len_u64).is_err());
            restore_bit(&blob_path, b_idx, b_mask);
        }

        let ob_path = mneme_store::outboard::path(dir.path(), digest);
        if ob_path.exists() {
            let (ob_idx, ob_mask) = flip_one_bit(&ob_path, flip_pos, flip_bit);
            prop_assert!(mneme_store::verify_span_range(dir.path(), digest, 0..len_u64).is_err());
            restore_bit(&ob_path, ob_idx, ob_mask);
        }
    }

    #[test]
    fn proptest_zstd_and_zstd_dict_roundtrip_and_bitflip(
        size in 256_usize..=(96 * 1024),
        seed in any::<u64>(),
        use_dict in any::<bool>(),
        flip_pos in any::<usize>(),
        flip_bit in 0_u8..8,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let payload = make_payload(size, seed, PayloadStyle::Compressible);
        let digest = mneme_core::ContentDigest::of_source_bytes(&payload);

        let (compression, maybe_dict_digest) = if use_dict {
            let dict = train_asciidoc_dict();
            let dict_digest = mneme_store::dedup::stage_dictionary(dir.path(), &dict)
                .expect("stage dictionary");
            (
                mneme_store::BlobCompression::ZstdDictionary { dictionary: dict_digest },
                Some(dict_digest),
            )
        } else {
            (mneme_store::BlobCompression::Zstd, None)
        };

        mneme_store::payload::stage_with_compression(
            dir.path(),
            digest,
            &payload,
            compression,
            "text/asciidoc",
        )
        .expect("stage compressed");

        prop_assert_eq!(mneme_store::payload::read(dir.path(), digest).expect("read"), payload.clone());
        prop_assert!(mneme_store::payload::verify(dir.path(), digest, size as u64).is_ok());

        let half = (size / 2) as u64;
        let span = mneme_store::verify_span_range(dir.path(), digest, half..size as u64)
            .expect("verify compressed span");
        prop_assert_eq!(span.as_slice(), &payload[half as usize..]);

        // 1-byte bitflip in stored blob file must fail closed.
        let blob_path = mneme_store::payload::blob_path(dir.path(), digest);
        let (b_idx, b_mask) = flip_one_bit(&blob_path, flip_pos, flip_bit);
        prop_assert!(mneme_store::payload::read(dir.path(), digest).is_err());
        prop_assert!(mneme_store::payload::verify(dir.path(), digest, size as u64).is_err());
        prop_assert!(mneme_store::verify_span_range(dir.path(), digest, 0..size as u64).is_err());
        restore_bit(&blob_path, b_idx, b_mask);

        // If using a dictionary, 1-byte bitflip in the dictionary file must also fail closed.
        if let Some(dict_digest) = maybe_dict_digest {
            let dict_path = mneme_store::dedup::dictionary_path(dir.path(), dict_digest);
            let (d_idx, d_mask) = flip_one_bit(&dict_path, flip_pos, flip_bit);
            prop_assert!(mneme_store::dedup::read_dictionary(dir.path(), dict_digest).is_err());
            prop_assert!(mneme_store::payload::read(dir.path(), digest).is_err());
            restore_bit(&dict_path, d_idx, d_mask);
        }
    }

    #[test]
    fn proptest_fastcdc_partition_invariants_and_chunked_bitflip(
        size in (64 * 1024_usize)..=(192 * 1024_usize),
        seed in any::<u64>(),
        use_dict in any::<bool>(),
        flip_pos in any::<usize>(),
        flip_bit in 0_u8..8,
    ) {
        let payload = make_payload(size, seed, PayloadStyle::Compressible);
        let config = mneme_store::dedup::FastCdcConfig::from_bounds(
            mneme_store::dedup::FastCdcBounds {
                min_chunk_bytes: 4 * 1024,
                normal_chunk_bytes: 16 * 1024,
                max_chunk_bytes: 64 * 1024,
            },
            32 * 1024,
        )
        .expect("valid fastcdc config");

        let spans = mneme_store::dedup::fastcdc_chunk_spans(&payload, config).expect("spans");
        let spans_repeat = mneme_store::dedup::fastcdc_chunk_spans(&payload, config).expect("repeat");
        prop_assert_eq!(&spans, &spans_repeat);
        prop_assert!(!spans.is_empty());

        let mut cursor = 0_u64;
        for (i, span) in spans.iter().enumerate() {
            prop_assert_eq!(span.offset_bytes, cursor);
            prop_assert!(span.length_bytes > 0);
            prop_assert!(span.length_bytes <= 64 * 1024);
            if i + 1 < spans.len() {
                prop_assert!(span.length_bytes >= 4 * 1024);
            }
            cursor += span.length_bytes;
        }
        prop_assert_eq!(cursor, size as u64);

        // Commit through Workspace with FastCDC (+ optional Zstd dictionary) and verify round-trip + bitflips.
        let dir = tempfile::tempdir().expect("tempdir");
        let dict = if use_dict { Some(train_asciidoc_dict()) } else { None };
        let compression = if use_dict {
            mneme_store::BlobCompression::ZstdDictionary {
                dictionary: mneme_core::ContentDigest::of_source_bytes(b"placeholder"),
            }
        } else {
            mneme_store::BlobCompression::Zstd
        };
        let digest = commit_blob_with_policy(
            dir.path(),
            &payload,
            compression,
            mneme_store::BlobChunking::FastCdc(config),
            dict.as_deref(),
        );

        prop_assert_eq!(mneme_store::payload::read(dir.path(), digest).expect("read cdc"), payload.clone());
        prop_assert!(mneme_store::payload::verify(dir.path(), digest, size as u64).is_ok());

        let mid_start = (size / 3) as u64;
        let mid_end = ((size * 2) / 3) as u64;
        let span = mneme_store::verify_span_range(dir.path(), digest, mid_start..mid_end)
            .expect("verify cdc span");
        prop_assert_eq!(span.as_slice(), &payload[mid_start as usize..mid_end as usize]);

        // 1-byte bitflip in the CDC manifest blob must fail closed.
        let manifest_path = mneme_store::payload::blob_path(dir.path(), digest);
        let (m_idx, m_mask) = flip_one_bit(&manifest_path, flip_pos, flip_bit);
        prop_assert!(mneme_store::payload::read(dir.path(), digest).is_err());
        prop_assert!(mneme_store::payload::verify(dir.path(), digest, size as u64).is_err());
        prop_assert!(mneme_store::verify_span_range(dir.path(), digest, 0..size as u64).is_err());
        restore_bit(&manifest_path, m_idx, m_mask);

        // 1-byte bitflip in one of the underlying chunk files must fail closed.
        let chosen_span = spans[flip_pos % spans.len()];
        let chunk_slice = &payload[chosen_span.offset_bytes as usize
            ..(chosen_span.offset_bytes + chosen_span.length_bytes) as usize];
        let chunk_digest = mneme_core::ContentDigest::of_source_bytes(chunk_slice);
        let chunk_file = mneme_store::dedup::chunk_path(dir.path(), chunk_digest);
        prop_assert!(chunk_file.exists());
        let (c_idx, c_mask) = flip_one_bit(&chunk_file, flip_pos, flip_bit);
        prop_assert!(mneme_store::payload::read(dir.path(), digest).is_err());
        prop_assert!(mneme_store::payload::verify(dir.path(), digest, size as u64).is_err());
        prop_assert!(mneme_store::verify_span_range(dir.path(), digest, 0..size as u64).is_err());
        restore_bit(&chunk_file, c_idx, c_mask);
    }
}
