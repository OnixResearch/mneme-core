//! Integration tests for `bao-tree` outboard storage, `O(log N)` verified
//! range reads, workspace verify outboard auditing, and `iroh-blobs` compat.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::expect_used)] // test assertions

fn test_scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
}

fn test_config() -> mneme_store::WorkspaceConfig {
    mneme_store::WorkspaceConfig {
        clock: Box::new(mneme_store::FixedClock::new(
            mneme_core::Timestamp::from_nanos(1_000),
        )),
        faults: Box::new(mneme_store::NoFaults),
    }
}

fn deterministic_blob(len_bytes: usize) -> Vec<u8> {
    (0..len_bytes)
        .map(|index| {
            u8::try_from((index.wrapping_mul(31).wrapping_add(index >> 8)) & 0xff)
                .expect("masked byte")
        })
        .collect()
}

fn source_commit(
    base: mneme_core::WorkspaceRevisionId,
    key: &str,
    id_byte: u8,
    bytes: &[u8],
) -> (mneme_store::CommitCommand, mneme_core::RecordId) {
    assert!(!bytes.is_empty());
    let digest = mneme_core::ContentDigest::of_source_bytes(bytes);
    let retained =
        mneme_core::RetainedSource::new(digest, bytes.len() as u64, "application/octet-stream")
            .expect("retained source");
    assert_eq!(retained.byte_length(), bytes.len() as u64);
    assert!(!key.is_empty());
    let record_id = mneme_core::RecordId::from_bytes([id_byte; 16]);
    let revision_id = mneme_core::RevisionId::from_bytes([id_byte.wrapping_add(1); 16]);
    let draft = mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::SourceRevision,
        record_id,
        revision_id,
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
                mneme_core::Value::string("assets/large.bin"),
            ),
        ]),
    };
    let command = mneme_store::CommitCommand {
        base,
        actor: "test-author".to_owned(),
        scope: test_scope(),
        idempotency_key: key.to_owned(),
        records: vec![draft],
        source_blobs: vec![mneme_store::SourceBlobDraft {
            bytes: bytes.to_vec(),
            media_type: mneme_core::Symbol::from("application/octet-stream"),
        }],
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: None,
    };
    (command, record_id)
}

#[test]
fn large_blake3_blob_stores_outboard_without_mutating_canonical_bytes_or_digest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let small = deterministic_blob(12 * 1024);
    let small_digest = mneme_core::ContentDigest::of_source_bytes(&small);
    mneme_store::payload::stage(dir.path(), small_digest, &small).expect("stage small");
    assert!(!mneme_store::outboard::path(dir.path(), small_digest).exists());
    assert_eq!(
        mneme_store::payload::read(dir.path(), small_digest).expect("read small"),
        small
    );

    let large = deterministic_blob(256 * 1024 + 321);
    let large_digest = mneme_core::ContentDigest::of_source_bytes(&large);
    mneme_store::payload::stage(dir.path(), large_digest, &large).expect("stage large");

    let blob_path = mneme_store::payload::blob_path(dir.path(), large_digest);
    let ob_path = mneme_store::outboard::path(dir.path(), large_digest);
    assert!(blob_path.exists());
    assert!(ob_path.exists());
    assert_eq!(std::fs::read(&blob_path).expect("canonical bytes"), large);
    assert_eq!(
        mneme_core::ContentDigest::of_source_bytes(&large),
        large_digest
    );
    let expected_ob_len =
        bao_tree::BaoTree::new(large.len() as u64, mneme_store::outboard::BLOCK_SIZE)
            .outboard_size();
    assert_eq!(
        std::fs::metadata(&ob_path).expect("ob meta").len(),
        expected_ob_len
    );
}

#[test]
fn multi_mib_verify_span_range_succeeds_without_reading_unrelated_corrupt_chunks() {
    let dir = tempfile::tempdir().expect("tempdir");
    // ~3.2 MiB non-aligned blob
    let bytes = deterministic_blob(3 * 1024 * 1024 + 777);
    let digest = mneme_core::ContentDigest::of_source_bytes(&bytes);
    mneme_store::payload::stage(dir.path(), digest, &bytes).expect("stage multi-mib");

    // Arbitrary spans: beginning, chunk-group-straddling middle, and EOF tail.
    let spans = [
        0_u64..128,
        (16 * 1024 - 17)..(16 * 1024 + 55),
        1_800_000..1_820_500,
        (bytes.len() as u64 - 200)..(bytes.len() as u64),
        1234..1234,
    ];
    for range in &spans {
        let got = mneme_store::verify_span_range(dir.path(), digest, range.clone())
            .expect("verified range");
        let start = usize::try_from(range.start).expect("start");
        let end = usize::try_from(range.end).expect("end");
        assert_eq!(got, bytes[start..end]);
    }

    // Corrupt byte 0 (chunk group 0), then verify a middle span around ~1.8 MiB.
    // Because `verify_span_range` seeks and verifies only covering chunk groups,
    // it MUST succeed without reading chunk group 0, while full-blob read fails.
    let blob_path = mneme_store::payload::blob_path(dir.path(), digest);
    let mut tampered = bytes.clone();
    tampered[0] ^= 0x5a;
    std::fs::write(&blob_path, &tampered).expect("corrupt byte 0");

    assert!(matches!(
        mneme_store::payload::read(dir.path(), digest),
        Err(mneme_store::Failure::CorruptBlob { .. })
    ));
    let mid_range = 1_800_000_u64..1_820_500;
    let verified = mneme_store::verify_span_range(dir.path(), digest, mid_range.clone())
        .expect("mid-file span verifies without reading corrupt byte 0");
    let mid_start = usize::try_from(mid_range.start).expect("mid start");
    let mid_end = usize::try_from(mid_range.end).expect("mid end");
    assert_eq!(verified, bytes[mid_start..mid_end]);
}

#[test]
fn single_byte_corruption_in_range_or_outboard_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bytes = deterministic_blob(512 * 1024 + 19);
    let digest = mneme_core::ContentDigest::of_source_bytes(&bytes);
    mneme_store::payload::stage(dir.path(), digest, &bytes).expect("stage");

    let blob_path = mneme_store::payload::blob_path(dir.path(), digest);
    let ob_path = mneme_store::outboard::path(dir.path(), digest);
    let orig_ob = std::fs::read(&ob_path).expect("read ob");

    // 1. Corrupt 1 byte inside the queried range -> fails closed.
    let range = 200_000_u64..201_024;
    let mut bad_blob = bytes.clone();
    bad_blob[200_500] ^= 0x01;
    std::fs::write(&blob_path, &bad_blob).expect("corrupt in range");
    assert!(matches!(
        mneme_store::verify_span_range(dir.path(), digest, range.clone()),
        Err(mneme_store::Failure::CorruptBlob { .. })
    ));
    std::fs::write(&blob_path, &bytes).expect("restore blob");

    // 2. Corrupt 1 byte in the outboard root hash pair (offset 0) -> fails closed
    // (must NOT fall back to full-file read).
    let mut bad_ob = orig_ob.clone();
    bad_ob[0] ^= 0x80;
    std::fs::write(&ob_path, &bad_ob).expect("corrupt outboard");
    assert!(matches!(
        mneme_store::verify_span_range(dir.path(), digest, range.clone()),
        Err(mneme_store::Failure::CorruptBlob { .. })
    ));

    // 3. Truncate outboard by 1 byte -> fails closed.
    std::fs::write(&ob_path, &orig_ob[..orig_ob.len() - 1]).expect("truncate outboard");
    assert!(matches!(
        mneme_store::verify_span_range(dir.path(), digest, range),
        Err(mneme_store::Failure::CorruptBlob { .. })
    ));
}

#[test]
fn small_blake3_and_legacy_sha256_fallback_and_corruption_checks() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Small BLAKE3 blob (< 64 KiB, no outboard).
    let small = deterministic_blob(8 * 1024 + 77);
    let small_digest = mneme_core::ContentDigest::of_source_bytes(&small);
    mneme_store::payload::stage(dir.path(), small_digest, &small).expect("stage small");
    assert_eq!(
        mneme_store::verify_span_range(dir.path(), small_digest, 100..500).expect("small span"),
        small[100..500]
    );

    // Legacy SHA-256 blob (> 64 KiB, never writes outboard).
    let legacy = deterministic_blob(128 * 1024 + 5);
    let sha_digest =
        mneme_core::ContentDigest::of_source_bytes_with(&legacy, mneme_core::HashAlgorithm::Sha256);
    mneme_store::payload::stage(dir.path(), sha_digest, &legacy).expect("stage sha256");
    assert!(!mneme_store::outboard::path(dir.path(), sha_digest).exists());
    assert_eq!(
        mneme_store::verify_span_range(dir.path(), sha_digest, 65_000..66_000)
            .expect("sha256 span"),
        legacy[65_000..66_000]
    );

    // 1-byte corruption in SHA-256 blob fails closed.
    let sha_path = mneme_store::payload::blob_path(dir.path(), sha_digest);
    let mut bad_sha = legacy.clone();
    bad_sha[10] ^= 0xff;
    std::fs::write(&sha_path, &bad_sha).expect("corrupt sha");
    assert!(matches!(
        mneme_store::verify_span_range(dir.path(), sha_digest, 65_000..66_000),
        Err(mneme_store::Failure::CorruptBlob { .. })
    ));
}

#[test]
fn workspace_verify_checks_present_outboards_and_rebuilds_deterministically() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut workspace = mneme_store::Workspace::create(dir.path(), test_config()).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    let bytes = deterministic_blob(300 * 1024 + 111);
    let digest = mneme_core::ContentDigest::of_source_bytes(&bytes);
    let (cmd, _env) = source_commit(genesis, "large-1", 41, &bytes);
    workspace.commit(cmd).expect("commit large");
    drop(workspace);

    let ob_path = mneme_store::outboard::path(dir.path(), digest);
    assert!(ob_path.exists());
    let canonical_ob = std::fs::read(&ob_path).expect("canonical ob");

    // Healthy workspace passes full and quick with outboards_checked >= 1 and 0 orphans.
    let full = mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Full)
        .expect("full verify");
    assert!(full.is_healthy(), "issues: {:?}", full.issues);
    assert!(full.orphans.is_empty(), "orphans: {:?}", full.orphans);
    assert!(full.outboards_checked >= 1);

    let quick = mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Quick)
        .expect("quick verify");
    assert!(quick.is_healthy(), "issues: {:?}", quick.issues);
    assert!(quick.outboards_checked >= 1);

    // Flip 1 byte near the end of the outboard -> full fails closed with CorruptOutboard.
    let mut bad_ob = canonical_ob.clone();
    let last = bad_ob.len() - 1;
    bad_ob[last] ^= 0x01;
    std::fs::write(&ob_path, &bad_ob).expect("corrupt ob byte");

    let bad_full = mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Full)
        .expect("verify corrupt ob");
    assert!(!bad_full.is_healthy());
    let issue = bad_full
        .issues
        .iter()
        .find(|issue| issue.kind == mneme_store::IssueKind::CorruptOutboard)
        .expect("corrupt-outboard issue");
    assert_eq!(issue.digest.as_deref(), Some(digest.to_hex().as_str()));
    assert!(
        issue
            .path
            .as_deref()
            .expect("issue path")
            .ends_with(".obao4")
    );

    // Truncate outboard by 1 byte -> both quick and full fail with CorruptOutboard.
    std::fs::write(&ob_path, &canonical_ob[..canonical_ob.len() - 1]).expect("truncate ob");
    for mode in [
        mneme_store::VerifyMode::Quick,
        mneme_store::VerifyMode::Full,
    ] {
        let report = mneme_store::verify_workspace(dir.path(), mode).expect("verify trunc ob");
        assert!(!report.is_healthy());
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.kind == mneme_store::IssueKind::CorruptOutboard)
        );
    }

    // Delete outboard -> optional/lazy outboard absence still passes verify, and
    // verify_span_range falls back cleanly; rebuild_outboard reproduces exact bytes.
    std::fs::remove_file(&ob_path).expect("remove ob");
    let no_ob = mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Full)
        .expect("verify without ob");
    assert!(no_ob.is_healthy(), "issues: {:?}", no_ob.issues);
    assert_eq!(no_ob.outboards_checked, 0);
    assert_eq!(
        mneme_store::verify_span_range(dir.path(), digest, 10_000..12_000).expect("fallback"),
        bytes[10_000..12_000]
    );

    assert!(mneme_store::rebuild_outboard(dir.path(), digest).expect("rebuild"));
    assert_eq!(
        std::fs::read(&ob_path).expect("rebuilt ob"),
        canonical_ob,
        "rebuilt outboard must be byte-for-byte deterministic"
    );
}

#[test]
fn outboard_is_iroh_blobs_verified_streaming_compatible() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bytes = deterministic_blob(512 * 1024 + 999);
    let digest = mneme_core::ContentDigest::of_source_bytes(&bytes);
    mneme_store::payload::stage(dir.path(), digest, &bytes).expect("stage");

    let blob_file =
        std::fs::File::open(mneme_store::payload::blob_path(dir.path(), digest)).expect("blob");
    let ob_file =
        std::fs::File::open(mneme_store::outboard::path(dir.path(), digest)).expect("outboard");

    // Construct standard bao-tree PreOrderOutboard with iroh-blobs 16 KiB chunk groups.
    let tree = bao_tree::BaoTree::new(bytes.len() as u64, bao_tree::BlockSize::from_chunk_log(4));
    let root = bao_tree::blake3::Hash::from(*digest.as_bytes());
    let outboard = bao_tree::io::outboard::PreOrderOutboard {
        root,
        tree,
        data: ob_file,
    };

    let chunk_ranges =
        bao_tree::io::round_up_to_chunks(&bao_tree::ByteRanges::from(120_000_u64..150_000_u64));
    let mut encoded = Vec::new();
    bao_tree::io::sync::encode_ranges_validated(&blob_file, &outboard, &chunk_ranges, &mut encoded)
        .expect("encode verified iroh-blobs stream");

    let mut leaf_count = 0_u64;
    for item in bao_tree::io::sync::DecodeResponseIter::new(
        root,
        tree,
        std::io::Cursor::new(&encoded),
        &chunk_ranges,
    ) {
        if let bao_tree::io::BaoContentItem::Leaf(leaf) = item.expect("decode item") {
            let start = usize::try_from(leaf.offset).expect("leaf offset");
            let end = start.saturating_add(leaf.data.len());
            assert_eq!(leaf.data.as_ref(), &bytes[start..end]);
            leaf_count = leaf_count.saturating_add(1);
        }
    }
    assert!(leaf_count > 0);
}

#[test]
fn retention_purge_removes_outboard_alongside_canonical_blob() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut workspace = mneme_store::Workspace::create(dir.path(), test_config()).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    let bytes = deterministic_blob(128 * 1024);
    let digest = mneme_core::ContentDigest::of_source_bytes(&bytes);
    let (cmd, record_id) = source_commit(genesis, "purge-ob", 51, &bytes);
    let committed = workspace.commit(cmd).expect("commit");

    let blob_path = mneme_store::payload::blob_path(dir.path(), digest);
    let ob_path = mneme_store::outboard::path(dir.path(), digest);
    assert!(blob_path.exists());
    assert!(ob_path.exists());

    let operation_id = "op-forget-outboard";
    let location_id = "loc-source".to_owned();
    let generation = workspace.snapshot().expect("snap").eligibility_generation;
    workspace
        .commit(mneme_store::CommitCommand {
            base: committed.revision,
            actor: "test-author".to_owned(),
            scope: test_scope(),
            idempotency_key: "forget-ob".to_owned(),
            records: Vec::new(),
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: Some(mneme_store::RetentionCommit {
                operation_id: operation_id.to_owned(),
                operation_kind: "forget".to_owned(),
                policy_version: "1".to_owned(),
                selectors: Vec::new(),
                suppressions: vec![mneme_store::RetentionSuppression {
                    operation_id: operation_id.to_owned(),
                    target: record_id,
                    revision: None,
                    target_kind: "source-revision".to_owned(),
                    mode: mneme_store::SuppressionMode::Forgotten,
                    content_digest: Some(digest),
                    generation: generation.saturating_add(1),
                }],
                locations: vec![mneme_store::RetentionLocationPlan {
                    location_id: location_id.clone(),
                    location_kind: "source-blob".to_owned(),
                    locator: digest.to_hex(),
                }],
                retained_metadata: Vec::new(),
            }),
        })
        .expect("forget commit");

    let outcome = workspace
        .purge_retention_blob(operation_id, &location_id, "source-blob", &digest.to_hex())
        .expect("purge");
    assert_eq!(outcome, mneme_store::BlobPurgeOutcome::Purged);
    assert!(!blob_path.exists());
    assert!(
        !ob_path.exists(),
        "outboard sidecar must be removed when canonical blob is purged"
    );
}
