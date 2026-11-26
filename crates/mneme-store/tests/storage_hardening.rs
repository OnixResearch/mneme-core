//! End-to-end tests for FastCDC erasure GC, framing-aware outboards,
//! legacy SHA-256 dispatch, workspace hygiene, StoragePolicy, and verify parity.
#![allow(
    unknown_lints,
    no_unwrap,
    assertion_density,
    function_length,
    allocation_in_loop,
    too_many_parameters,
    numeric_units,
    unbounded_collection_growth,
    platform_dependent_cast,
    raw_arithmetic_overflow,
    magic_number
)] // integration test harness exercises multi-step storage scenarios and asserts via expect
#![allow(clippy::expect_used, clippy::unwrap_used)] // integration tests assert via expect

fn test_scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
}

fn test_config(at: i64) -> mneme_store::WorkspaceConfig {
    mneme_store::WorkspaceConfig {
        clock: Box::new(mneme_store::FixedClock::new(
            mneme_core::Timestamp::from_nanos(at),
        )),
        faults: Box::new(mneme_store::NoFaults),
    }
}

fn open_ws(root: &std::path::Path, at: i64) -> mneme_store::Workspace {
    mneme_store::Workspace::open(root, test_config(at)).expect("open workspace")
}

fn retained_source_record(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    bytes: &[u8],
    path: Option<&str>,
) -> mneme_store::RecordDraft {
    let retained = mneme_core::RetainedSource::new(
        mneme_core::ContentDigest::of_source_bytes(bytes),
        bytes.len() as u64,
        "text/asciidoc",
    )
    .expect("retained source");
    let mut entries = vec![
        (
            mneme_core::Symbol::from("content"),
            mneme_core::SourceContent::Retained(retained).to_value(),
        ),
        (
            mneme_core::Symbol::from("acquisition"),
            mneme_core::Value::symbol("authored"),
        ),
    ];
    if let Some(path) = path {
        entries.push((
            mneme_core::Symbol::from("path-hint"),
            mneme_core::Value::string(path),
        ));
    }
    mneme_store::RecordDraft {
        schema_version: 1,
        kind: mneme_core::RecordKind::SourceRevision,
        record_id,
        revision_id,
        predecessor: None,
        scope: scope.clone(),
        payload: mneme_core::Payload::new(entries),
    }
}

fn record_command(
    base: mneme_core::WorkspaceRevisionId,
    scope: &mneme_core::ScopeId,
    key: &str,
    records: Vec<mneme_store::RecordDraft>,
    blobs: Vec<mneme_store::SourceBlobDraft>,
    candidates: Vec<mneme_store::ImportCandidateDraft>,
) -> mneme_store::CommitCommand {
    mneme_store::CommitCommand {
        base,
        actor: "test-author".to_owned(),
        scope: scope.clone(),
        idempotency_key: key.to_owned(),
        records,
        source_blobs: blobs,
        publications: Vec::new(),
        import_candidates: candidates,
        retention: None,
    }
}

fn source_blob(bytes: &[u8]) -> mneme_store::SourceBlobDraft {
    mneme_store::SourceBlobDraft::inline(bytes.to_vec(), mneme_core::Symbol::from("text/asciidoc"))
}

fn deterministic_asciidoc(lines: usize, tag: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(lines.saturating_mul(80));
    for index in 0..lines {
        let mixed = (index as u64)
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let line = format!(
            "== Section {index:05} ({mixed:016x})\nBody paragraph {index} tag={tag} token={:08x}.\n",
            (mixed >> 32) & 0xffff_ffff
        );
        out.extend_from_slice(line.as_bytes());
    }
    out
}

fn train_test_dict() -> Vec<u8> {
    let samples: Vec<Vec<u8>> = (0..64)
        .map(|i| {
            format!(
                "== Section {i:05} (0123456789abcdef)\nBody paragraph {i} tag=shared token=deadbeef.\n"
            )
            .into_bytes()
        })
        .collect();
    let slices: Vec<&[u8]> = samples.iter().map(Vec::as_slice).collect();
    mneme_store::dedup::train_zstd_dictionary(&slices, 8 * 1024).expect("train dict")
}

fn all_files_under(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    if !dir.is_dir() {
        return files;
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in std::fs::read_dir(&current).expect("read dir") {
            let entry = entry.expect("entry");
            let file_type = entry.file_type().expect("type");
            if file_type.is_dir() {
                stack.push(entry.path());
            } else if file_type.is_file() {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    files
}

fn entity_draft(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    label: &str,
) -> mneme_store::RecordDraft {
    mneme_store::RecordDraft {
        schema_version: 1,
        kind: mneme_core::RecordKind::Entity,
        record_id,
        revision_id,
        predecessor: None,
        scope: scope.clone(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("entity-type"),
                mneme_core::Value::symbol("note"),
            ),
            (
                mneme_core::Symbol::from("label"),
                mneme_core::Value::string(label),
            ),
            (
                mneme_core::Symbol::from("properties"),
                mneme_core::Value::dictionary(std::collections::BTreeMap::new()),
            ),
        ]),
    }
}

fn copy_dir_tree(src: &std::path::Path, dst: &std::path::Path) {
    let mut pending = vec![(src.to_path_buf(), dst.to_path_buf())];
    while let Some((from_dir, to_dir)) = pending.pop() {
        std::fs::create_dir_all(&to_dir).expect("mkdir dst");
        for entry in std::fs::read_dir(&from_dir).expect("read src") {
            let entry = entry.expect("entry");
            let target = to_dir.join(entry.file_name());
            if entry.file_type().expect("type").is_dir() {
                pending.push((entry.path(), target));
            } else {
                std::fs::copy(entry.path(), target).expect("copy file");
            }
        }
    }
}

#[test]
fn fastcdc_secret_erasure_removes_unique_chunks_and_preserves_shared_chunks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let scope = test_scope();
    let dict_bytes = train_test_dict();

    let mut ws = mneme_store::Workspace::create(dir.path(), test_config(1_000)).expect("create");
    let dict_digest = ws.stage_zstd_dictionary(&dict_bytes).expect("stage dict");
    ws.set_blob_compression(mneme_store::BlobCompression::ZstdDictionary {
        dictionary: dict_digest,
    });
    ws.set_blob_chunking(mneme_store::BlobChunking::FastCdc(
        mneme_store::FastCdcConfig::default(),
    ));

    // Build two large documents (>250 KiB) that share almost all chunks, except
    // doc_secret has a unique secret block in the middle.
    let base_doc = deterministic_asciidoc(4_000, "shared");
    let secret_marker = b"TOP_SECRET_ERASE_ME_9f8a7b6c5d4e3f2a1b0c";
    let split = base_doc.len() / 2;
    let mut doc_secret = Vec::with_capacity(base_doc.len() + 1024);
    doc_secret.extend_from_slice(&base_doc[..split]);
    doc_secret.extend_from_slice(b"\n== Secret Section\n");
    for _ in 0..8 {
        doc_secret.extend_from_slice(secret_marker);
        doc_secret.push(b'\n');
    }
    doc_secret.extend_from_slice(&base_doc[split..]);

    let secret_digest = mneme_core::ContentDigest::of_source_bytes(&doc_secret);
    let public_digest = mneme_core::ContentDigest::of_source_bytes(&base_doc);

    let secret_id = mneme_core::RecordId::from_bytes([11; 16]);
    let secret_rev = mneme_core::RevisionId::from_bytes([12; 16]);
    let public_id = mneme_core::RecordId::from_bytes([13; 16]);
    let public_rev = mneme_core::RevisionId::from_bytes([14; 16]);

    let genesis = ws.current_revision().expect("genesis");
    let committed = ws
        .commit(record_command(
            genesis,
            &scope,
            "commit-both",
            vec![
                retained_source_record(
                    secret_id,
                    secret_rev,
                    &scope,
                    &doc_secret,
                    Some("notes/secret.adoc"),
                ),
                retained_source_record(
                    public_id,
                    public_rev,
                    &scope,
                    &base_doc,
                    Some("notes/public.adoc"),
                ),
            ],
            vec![source_blob(&doc_secret), source_blob(&base_doc)],
            Vec::new(),
        ))
        .expect("commit both");

    let chunks_dir = dir
        .path()
        .join(mneme_store::payload::BLOB_DIRECTORY)
        .join(mneme_store::dedup::CHUNK_DIRECTORY);
    let dicts_dir = dir
        .path()
        .join(mneme_store::payload::BLOB_DIRECTORY)
        .join(mneme_store::dedup::DICTIONARY_DIRECTORY);
    let chunks_before = all_files_under(&chunks_dir);
    assert!(chunks_before.len() >= 4, "expected FastCDC chunks");
    assert!(
        mneme_store::dedup::dictionary_path(dir.path(), dict_digest).exists(),
        "dictionary must live at algorithm-namespaced path"
    );

    // Forget and purge doc_secret while doc_public stays live.
    let op_secret = "op-forget-secret";
    let loc_secret = "loc-secret".to_owned();
    let gen1 = ws.snapshot().expect("snap1").eligibility_generation;
    ws.commit(mneme_store::CommitCommand {
        base: committed.revision,
        actor: "test-author".to_owned(),
        scope: scope.clone(),
        idempotency_key: "forget-secret".to_owned(),
        records: Vec::new(),
        source_blobs: Vec::new(),
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: Some(mneme_store::RetentionCommit {
            operation_id: op_secret.to_owned(),
            operation_kind: "forget".to_owned(),
            policy_version: "1".to_owned(),
            selectors: Vec::new(),
            suppressions: vec![mneme_store::RetentionSuppression {
                operation_id: op_secret.to_owned(),
                target: secret_id,
                revision: None,
                target_kind: "source-revision".to_owned(),
                mode: mneme_store::SuppressionMode::Forgotten,
                content_digest: Some(secret_digest),
                generation: gen1.saturating_add(1),
            }],
            locations: vec![mneme_store::RetentionLocationPlan {
                location_id: loc_secret.clone(),
                location_kind: "source-blob".to_owned(),
                locator: secret_digest.to_hex(),
            }],
            retained_metadata: Vec::new(),
        }),
    })
    .expect("forget secret commit");

    let purge_outcome = ws
        .purge_retention_blob(
            op_secret,
            &loc_secret,
            "source-blob",
            &secret_digest.to_hex(),
        )
        .expect("purge secret");
    assert_eq!(purge_outcome, mneme_store::BlobPurgeOutcome::Purged);

    let chunks_after_secret = all_files_under(&chunks_dir);
    assert!(
        chunks_after_secret.len() < chunks_before.len(),
        "unique secret chunks must be physically removed"
    );
    // Surviving public blob and dictionary must remain intact and readable.
    assert_eq!(
        mneme_store::payload::read(dir.path(), public_digest).expect("read public"),
        base_doc
    );
    assert!(mneme_store::dedup::dictionary_path(dir.path(), dict_digest).exists());
    // No surviving file under blobs/chunks/ may contain the secret bytes.
    for chunk_file in &chunks_after_secret {
        let raw = std::fs::read(chunk_file).expect("read chunk file");
        assert!(
            !raw.windows(secret_marker.len()).any(|w| w == secret_marker),
            "secret marker survived in {}",
            chunk_file.display()
        );
    }
    let verify_mid =
        mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Full).expect("verify");
    assert!(verify_mid.is_healthy(), "issues: {:?}", verify_mid.issues);
    assert!(
        verify_mid.orphans.is_empty(),
        "orphans: {:?}",
        verify_mid.orphans
    );

    // Now forget and purge doc_public as well -> ALL chunks AND the dict must be GC'd.
    let head2 = ws.current_revision().expect("head2");
    let gen2 = ws.snapshot().expect("snap2").eligibility_generation;
    let op_public = "op-forget-public";
    let loc_public = "loc-public".to_owned();
    ws.commit(mneme_store::CommitCommand {
        base: head2,
        actor: "test-author".to_owned(),
        scope: scope.clone(),
        idempotency_key: "forget-public".to_owned(),
        records: Vec::new(),
        source_blobs: Vec::new(),
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: Some(mneme_store::RetentionCommit {
            operation_id: op_public.to_owned(),
            operation_kind: "forget".to_owned(),
            policy_version: "1".to_owned(),
            selectors: Vec::new(),
            suppressions: vec![mneme_store::RetentionSuppression {
                operation_id: op_public.to_owned(),
                target: public_id,
                revision: None,
                target_kind: "source-revision".to_owned(),
                mode: mneme_store::SuppressionMode::Forgotten,
                content_digest: Some(public_digest),
                generation: gen2.saturating_add(1),
            }],
            locations: vec![mneme_store::RetentionLocationPlan {
                location_id: loc_public.clone(),
                location_kind: "source-blob".to_owned(),
                locator: public_digest.to_hex(),
            }],
            retained_metadata: Vec::new(),
        }),
    })
    .expect("forget public commit");

    let purge_public = ws
        .purge_retention_blob(
            op_public,
            &loc_public,
            "source-blob",
            &public_digest.to_hex(),
        )
        .expect("purge public");
    assert_eq!(purge_public, mneme_store::BlobPurgeOutcome::Purged);

    assert!(
        all_files_under(&chunks_dir).is_empty(),
        "all FastCDC chunks must be erased when last referencing blob is purged"
    );
    assert!(
        all_files_under(&dicts_dir).is_empty(),
        "unreferenced Zstd dictionary must be erased when last referencing blob is purged"
    );
    let verify_end =
        mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Full).expect("verify");
    assert!(verify_end.is_healthy(), "issues: {:?}", verify_end.issues);
    assert!(
        verify_end.orphans.is_empty(),
        "orphans: {:?}",
        verify_end.orphans
    );
}

#[test]
fn fastcdc_restore_ledger_gc_legacy_fallback_and_orphan_cleanup() {
    let dir = tempfile::tempdir().expect("tempdir");
    let restore_dir = tempfile::tempdir().expect("restore dir");
    let scope = test_scope();
    let dict_bytes = train_test_dict();

    let mut ws = mneme_store::Workspace::create(dir.path(), test_config(1_000)).expect("create");
    let dict_digest = ws.stage_zstd_dictionary(&dict_bytes).expect("stage dict");
    ws.set_blob_compression(mneme_store::BlobCompression::ZstdDictionary {
        dictionary: dict_digest,
    });
    ws.set_blob_chunking(mneme_store::BlobChunking::FastCdc(
        mneme_store::FastCdcConfig::default(),
    ));

    let doc = deterministic_asciidoc(4_000, "restore-erasure");
    let digest = mneme_core::ContentDigest::of_source_bytes(&doc);
    let rec_id = mneme_core::RecordId::from_bytes([21; 16]);
    let rev_id = mneme_core::RevisionId::from_bytes([22; 16]);
    let genesis = ws.current_revision().expect("genesis");
    let c1 = ws
        .commit(record_command(
            genesis,
            &scope,
            "c1",
            vec![retained_source_record(
                rec_id,
                rev_id,
                &scope,
                &doc,
                Some("notes/restore.adoc"),
            )],
            vec![source_blob(&doc)],
            Vec::new(),
        ))
        .expect("commit c1");

    // Test backward-compatible legacy un-namespaced chunk & dict read/verify:
    // move the dictionary and one chunk to their legacy un-namespaced paths.
    let namespaced_dict = mneme_store::dedup::dictionary_path(dir.path(), dict_digest);
    let dict_hex = dict_digest.to_hex();
    let legacy_dict = dir
        .path()
        .join(mneme_store::payload::BLOB_DIRECTORY)
        .join(mneme_store::dedup::DICTIONARY_DIRECTORY)
        .join(&dict_hex[0..2])
        .join(&dict_hex);
    std::fs::create_dir_all(legacy_dict.parent().expect("parent")).expect("mkdir");
    std::fs::rename(&namespaced_dict, &legacy_dict).expect("move dict to legacy");

    let namespaced_chunks = all_files_under(
        &dir.path()
            .join(mneme_store::payload::BLOB_DIRECTORY)
            .join(mneme_store::dedup::CHUNK_DIRECTORY)
            .join("blake3"),
    );
    let first_chunk = &namespaced_chunks[0];
    let first_chunk_name = first_chunk.file_name().expect("name").to_string_lossy();
    let legacy_chunk = dir
        .path()
        .join(mneme_store::payload::BLOB_DIRECTORY)
        .join(mneme_store::dedup::CHUNK_DIRECTORY)
        .join(&first_chunk_name[0..2])
        .join(first_chunk_name.as_ref());
    std::fs::create_dir_all(legacy_chunk.parent().expect("parent")).expect("mkdir");
    std::fs::rename(first_chunk, &legacy_chunk).expect("move chunk to legacy");

    assert_eq!(
        mneme_store::payload::read(dir.path(), digest).expect("read with legacy paths"),
        doc
    );
    assert_eq!(
        mneme_store::verify_span_range(dir.path(), digest, 10_000..12_000)
            .expect("verify_span_range with legacy paths"),
        doc[10_000..12_000]
    );
    let legacy_verify =
        mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Full).expect("verify");
    assert!(
        legacy_verify.is_healthy(),
        "issues: {:?}",
        legacy_verify.issues
    );
    assert!(
        legacy_verify.orphans.is_empty(),
        "orphans: {:?}",
        legacy_verify.orphans
    );

    // Plant an orphan chunk and orphan dict and verify `verify_workspace` reports them
    // and `recover()` sweeps them cleanly.
    let orphan_chunk_digest = mneme_core::ContentDigest::of_source_bytes(b"orphan-chunk-bytes");
    let orphan_chunk_path = mneme_store::dedup::chunk_path(dir.path(), orphan_chunk_digest);
    std::fs::create_dir_all(orphan_chunk_path.parent().expect("parent")).expect("mkdir");
    std::fs::write(&orphan_chunk_path, b"orphan-chunk-bytes").expect("write orphan chunk");

    let orphan_dict_digest = mneme_core::ContentDigest::of_source_bytes(b"orphan-dict-bytes");
    let orphan_dict_path = mneme_store::dedup::dictionary_path(dir.path(), orphan_dict_digest);
    std::fs::create_dir_all(orphan_dict_path.parent().expect("parent")).expect("mkdir");
    std::fs::write(&orphan_dict_path, b"orphan-dict-bytes").expect("write orphan dict");

    let with_orphans =
        mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Full).expect("verify");
    assert!(with_orphans.is_healthy());
    assert_eq!(
        with_orphans.orphans.len(),
        2,
        "orphans: {:?}",
        with_orphans.orphans
    );

    let recovered = ws.recover().expect("recover");
    assert_eq!(recovered.orphan_blobs_removed, 2);
    assert!(!orphan_chunk_path.exists());
    assert!(!orphan_dict_path.exists());
    assert_eq!(
        mneme_store::payload::read(dir.path(), digest).expect("read after recover"),
        doc
    );

    // Snapshot a pre-forget copy for restore-suppression testing.
    copy_dir_tree(dir.path(), restore_dir.path());
    // Forget on primary workspace and export suppression ledger.
    let gen1 = ws.snapshot().expect("snap").eligibility_generation;
    ws.commit(mneme_store::CommitCommand {
        base: c1.revision,
        actor: "test-author".to_owned(),
        scope: scope.clone(),
        idempotency_key: "forget-for-restore".to_owned(),
        records: Vec::new(),
        source_blobs: Vec::new(),
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: Some(mneme_store::RetentionCommit {
            operation_id: "op-restore-cdc".to_owned(),
            operation_kind: "forget".to_owned(),
            policy_version: "1".to_owned(),
            selectors: Vec::new(),
            suppressions: vec![mneme_store::RetentionSuppression {
                operation_id: "op-restore-cdc".to_owned(),
                target: rec_id,
                revision: None,
                target_kind: "source-revision".to_owned(),
                mode: mneme_store::SuppressionMode::Forgotten,
                content_digest: Some(digest),
                generation: gen1.saturating_add(1),
            }],
            locations: vec![mneme_store::RetentionLocationPlan {
                location_id: "loc-1".to_owned(),
                location_kind: "source-blob".to_owned(),
                locator: digest.to_hex(),
            }],
            retained_metadata: Vec::new(),
        }),
    })
    .expect("forget");
    let ledger = ws
        .export_suppression_ledger()
        .expect("export suppression ledger");

    // Mark restore copy as restored and apply suppression ledger -> purges legacy + namespaced chunks & dict.
    let mut restored =
        mneme_store::Workspace::open_restored(restore_dir.path(), test_config(2_000))
            .expect("open restored");
    restored
        .apply_restore_suppression_ledger(&ledger)
        .expect("apply ledger");
    assert!(
        all_files_under(
            &restore_dir
                .path()
                .join(mneme_store::payload::BLOB_DIRECTORY)
                .join(mneme_store::dedup::CHUNK_DIRECTORY)
        )
        .is_empty(),
        "restore purge must physically erase both namespaced and legacy FastCDC chunks"
    );
    assert!(
        all_files_under(
            &restore_dir
                .path()
                .join(mneme_store::payload::BLOB_DIRECTORY)
                .join(mneme_store::dedup::DICTIONARY_DIRECTORY)
        )
        .is_empty(),
        "restore purge must physically erase unreferenced Zstd dictionaries"
    );
}

#[test]
fn framed_blobs_support_verify_span_range_skip_outboards_and_stage_file_dedup() {
    let dir = tempfile::tempdir().expect("tempdir");
    let scope = test_scope();
    let dict_bytes = train_test_dict();

    let mut ws = mneme_store::Workspace::create(dir.path(), test_config(1_000)).expect("create");
    let dict_digest = ws.stage_zstd_dictionary(&dict_bytes).expect("stage dict");

    // 1. Zstd (MNZSTD01) blob >= 64 KiB
    let zstd_payload = deterministic_asciidoc(1_500, "zstd-plain");
    assert!(zstd_payload.len() as u64 >= mneme_store::outboard::THRESHOLD_BYTES);
    let zstd_digest = mneme_core::ContentDigest::of_source_bytes(&zstd_payload);
    ws.set_blob_compression(mneme_store::BlobCompression::Zstd);
    ws.set_blob_chunking(mneme_store::BlobChunking::None);
    let head = ws.current_revision().expect("head");
    let c1 = ws
        .commit(record_command(
            head,
            &scope,
            "zstd-plain",
            vec![retained_source_record(
                mneme_core::RecordId::from_bytes([31; 16]),
                mneme_core::RevisionId::from_bytes([32; 16]),
                &scope,
                &zstd_payload,
                Some("notes/zstd.adoc"),
            )],
            vec![source_blob(&zstd_payload)],
            Vec::new(),
        ))
        .expect("commit zstd");

    // 2. Zstd-dict (MNZSTD02) blob >= 64 KiB
    let dict_payload = deterministic_asciidoc(1_500, "zstd-dict");
    let dict_blob_digest = mneme_core::ContentDigest::of_source_bytes(&dict_payload);
    ws.set_blob_compression(mneme_store::BlobCompression::ZstdDictionary {
        dictionary: dict_digest,
    });
    let c2 = ws
        .commit(record_command(
            c1.revision,
            &scope,
            "zstd-dict",
            vec![retained_source_record(
                mneme_core::RecordId::from_bytes([33; 16]),
                mneme_core::RevisionId::from_bytes([34; 16]),
                &scope,
                &dict_payload,
                Some("notes/zstd-dict.adoc"),
            )],
            vec![source_blob(&dict_payload)],
            Vec::new(),
        ))
        .expect("commit zstd dict");

    // 3. FastCDC (MNCDC01\0) blob >= 200 KiB
    let cdc_payload = deterministic_asciidoc(4_000, "fastcdc-span");
    let cdc_digest = mneme_core::ContentDigest::of_source_bytes(&cdc_payload);
    ws.set_blob_chunking(mneme_store::BlobChunking::FastCdc(
        mneme_store::FastCdcConfig::default(),
    ));
    let c3 = ws
        .commit(record_command(
            c2.revision,
            &scope,
            "fastcdc",
            vec![retained_source_record(
                mneme_core::RecordId::from_bytes([35; 16]),
                mneme_core::RevisionId::from_bytes([36; 16]),
                &scope,
                &cdc_payload,
                Some("notes/cdc.adoc"),
            )],
            vec![source_blob(&cdc_payload)],
            Vec::new(),
        ))
        .expect("commit fastcdc");

    // None of the framed blobs may have an `.obao4` sidecar, and ensure/rebuild must return false.
    for digest in [zstd_digest, dict_blob_digest, cdc_digest] {
        assert!(!mneme_store::outboard::path(dir.path(), digest).exists());
        assert!(!mneme_store::outboard::ensure(dir.path(), digest).expect("ensure framed"));
        assert!(!mneme_store::outboard::rebuild(dir.path(), digest).expect("rebuild framed"));
        assert!(!mneme_store::outboard::path(dir.path(), digest).exists());
    }

    // verify_span_range succeeds across arbitrary spans on all three framings.
    for (digest, payload) in [
        (zstd_digest, &zstd_payload),
        (dict_blob_digest, &dict_payload),
        (cdc_digest, &cdc_payload),
    ] {
        let len = payload.len() as u64;
        for range in [0..64, 5_000..5_512, (len - 128)..len, 100..100] {
            let slice = mneme_store::verify_span_range(dir.path(), digest, range.clone())
                .expect("verify framed span");
            assert_eq!(slice, payload[range.start as usize..range.end as usize]);
        }
    }

    // stage_file dedup hit against already-staged Zstd & FastCDC blobs succeeds without creating `.obao4`.
    let tmp_files = tempfile::tempdir().expect("tmp files");
    let zstd_file = tmp_files.path().join("zstd.adoc");
    let cdc_file = tmp_files.path().join("cdc.adoc");
    std::fs::write(&zstd_file, &zstd_payload).expect("write zstd file");
    std::fs::write(&cdc_file, &cdc_payload).expect("write cdc file");
    let c4 = ws
        .commit(record_command(
            c3.revision,
            &scope,
            "dedup-streamed-hits",
            vec![
                retained_source_record(
                    mneme_core::RecordId::from_bytes([37; 16]),
                    mneme_core::RevisionId::from_bytes([38; 16]),
                    &scope,
                    &zstd_payload,
                    Some("notes/zstd-dedup.adoc"),
                ),
                retained_source_record(
                    mneme_core::RecordId::from_bytes([39; 16]),
                    mneme_core::RevisionId::from_bytes([40; 16]),
                    &scope,
                    &cdc_payload,
                    Some("notes/cdc-dedup.adoc"),
                ),
            ],
            vec![
                mneme_store::SourceBlobDraft::from_file(
                    &zstd_file,
                    mneme_core::Symbol::from("text/asciidoc"),
                )
                .expect("zstd from_file"),
                mneme_store::SourceBlobDraft::from_file(
                    &cdc_file,
                    mneme_core::Symbol::from("text/asciidoc"),
                )
                .expect("cdc from_file"),
            ],
            Vec::new(),
        ))
        .expect("commit streamed dedup hits");
    assert!(c4.sequence > c3.sequence);
    assert!(!mneme_store::outboard::path(dir.path(), zstd_digest).exists());
    assert!(!mneme_store::outboard::path(dir.path(), cdc_digest).exists());

    // FastCDC verify_span_range reads only covering chunks: corrupt chunk 0,
    // verify a tail span still succeeds, while reading chunk 0 fails closed!
    let spans = mneme_store::dedup::fastcdc_chunk_spans(
        &cdc_payload,
        mneme_store::FastCdcConfig::default(),
    )
    .expect("spans");
    assert!(spans.len() >= 3);
    let chunk0_bytes = &cdc_payload[0..spans[0].length_bytes as usize];
    let chunk0_digest = mneme_core::ContentDigest::of_source_bytes(chunk0_bytes);
    let chunk0_path = mneme_store::dedup::chunk_path(dir.path(), chunk0_digest);
    let orig_chunk0 = std::fs::read(&chunk0_path).expect("read chunk0");
    let mut bad_chunk0 = orig_chunk0.clone();
    let last_idx = bad_chunk0.len() - 1;
    bad_chunk0[last_idx] ^= 0xff;
    std::fs::write(&chunk0_path, &bad_chunk0).expect("corrupt chunk0");

    let tail_start = cdc_payload.len() as u64 - 256;
    let tail_end = cdc_payload.len() as u64;
    let tail = mneme_store::verify_span_range(dir.path(), cdc_digest, tail_start..tail_end)
        .expect("tail span succeeds without touching corrupt chunk 0");
    assert_eq!(tail, cdc_payload[tail_start as usize..tail_end as usize]);
    assert!(matches!(
        mneme_store::verify_span_range(dir.path(), cdc_digest, 0..128),
        Err(mneme_store::Failure::CorruptBlob { .. })
    ));
    std::fs::write(&chunk0_path, &orig_chunk0).expect("restore chunk0");
}

#[test]
fn storage_policy_applies_to_streamed_files_imports_publications_and_restaged_blobs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let scope = test_scope();
    let mut ws = mneme_store::Workspace::create(dir.path(), test_config(1_000))
        .expect("create")
        .with_blob_compression(mneme_store::BlobCompression::Zstd)
        .with_blob_chunking(mneme_store::BlobChunking::FastCdc(
            mneme_store::FastCdcConfig::default(),
        ));

    // 1. Streamed new file under Zstd policy
    let tmp = tempfile::tempdir().expect("tmp");
    let streamed_text =
        b"= Streamed Zstd Document\n\nRepeated content for compression.\n".repeat(120);
    let streamed_digest = mneme_core::ContentDigest::of_source_bytes(&streamed_text);
    let streamed_file = tmp.path().join("streamed.adoc");
    std::fs::write(&streamed_file, &streamed_text).expect("write streamed");

    // 2. Import candidate under Zstd policy
    let imported_text = b"= Imported Candidate\n\nRepeated candidate text for zstd.\n".repeat(120);
    let imported_digest = mneme_core::ContentDigest::of_source_bytes(&imported_text);
    mneme_store::payload::publish_working_file(dir.path(), "notes/imported.adoc", &imported_text)
        .expect("write working import");

    // 3. Publication under Zstd policy
    let published_text = b"= Published Text\n\nRepeated publication text for zstd.\n".repeat(120);
    let published_digest = mneme_core::ContentDigest::of_source_bytes(&published_text);

    let genesis = ws.current_revision().expect("genesis");
    let mut cmd = record_command(
        genesis,
        &scope,
        "policy-all-paths",
        vec![
            retained_source_record(
                mneme_core::RecordId::from_bytes([41; 16]),
                mneme_core::RevisionId::from_bytes([42; 16]),
                &scope,
                &streamed_text,
                Some("notes/streamed.adoc"),
            ),
            retained_source_record(
                mneme_core::RecordId::from_bytes([43; 16]),
                mneme_core::RevisionId::from_bytes([44; 16]),
                &scope,
                &imported_text,
                Some("notes/imported.adoc"),
            ),
        ],
        vec![
            mneme_store::SourceBlobDraft::from_file(
                &streamed_file,
                mneme_core::Symbol::from("text/asciidoc"),
            )
            .expect("from_file"),
        ],
        vec![mneme_store::ImportCandidateDraft {
            path: "notes/imported.adoc".to_owned(),
            bytes: imported_text.clone(),
        }],
    );
    cmd.publications.push(mneme_store::PublicationDraft {
        path: "notes/published.adoc".to_owned(),
        expected_previous: None,
        bytes: published_text.clone(),
    });
    ws.commit(cmd).expect("commit all policy paths");

    for (label, digest, expected) in [
        ("streamed", streamed_digest, &streamed_text),
        ("imported", imported_digest, &imported_text),
        ("published", published_digest, &published_text),
    ] {
        let disk = std::fs::read(mneme_store::payload::blob_path(dir.path(), digest))
            .expect("read disk blob");
        assert!(
            disk.starts_with(b"MNZSTD01"),
            "{label} blob must be zstd-framed under StoragePolicy"
        );
        assert_eq!(
            mneme_store::payload::read(dir.path(), digest).expect("read back"),
            *expected
        );
    }

    // 4. Verify restore_staged_blobs re-streams file.path under StoragePolicy when
    // an out-of-band sweep removes the staged blob between staging and transaction commit.
    let restage_text = b"= Restaged Streamed File\n\nRestaged content repeated.\n".repeat(120);
    let restage_digest = mneme_core::ContentDigest::of_source_bytes(&restage_text);
    let restage_file = tmp.path().join("restage.adoc");
    std::fs::write(&restage_file, &restage_text).expect("write restage");

    struct SweepOnStage {
        root: std::path::PathBuf,
        target: mneme_core::ContentDigest,
    }
    impl mneme_store::FaultInjector for SweepOnStage {
        fn inject(&self, point: mneme_store::FaultPoint) -> bool {
            if point == mneme_store::FaultPoint::AfterBlobStaging {
                let path = mneme_store::payload::blob_path(&self.root, self.target);
                if std::fs::remove_file(path).is_err() {}
            }
            false
        }
    }
    let mut ws_sweep = mneme_store::Workspace::open(
        dir.path(),
        mneme_store::WorkspaceConfig {
            clock: Box::new(mneme_store::FixedClock::new(
                mneme_core::Timestamp::from_nanos(2_000),
            )),
            faults: Box::new(SweepOnStage {
                root: dir.path().to_path_buf(),
                target: restage_digest,
            }),
        },
    )
    .expect("open with sweep fault")
    .with_blob_compression(mneme_store::BlobCompression::Zstd);

    let head = ws_sweep.current_revision().expect("head");
    ws_sweep
        .commit(record_command(
            head,
            &scope,
            "restage-streamed",
            vec![retained_source_record(
                mneme_core::RecordId::from_bytes([45; 16]),
                mneme_core::RevisionId::from_bytes([46; 16]),
                &scope,
                &restage_text,
                Some("notes/restage.adoc"),
            )],
            vec![
                mneme_store::SourceBlobDraft::from_file(
                    &restage_file,
                    mneme_core::Symbol::from("text/asciidoc"),
                )
                .expect("restage from_file"),
            ],
            Vec::new(),
        ))
        .expect("commit with restaged streamed blob must succeed");

    let restaged_disk = std::fs::read(mneme_store::payload::blob_path(dir.path(), restage_digest))
        .expect("read restaged");
    assert!(
        restaged_disk.starts_with(b"MNZSTD01"),
        "restore_staged_blobs must respect StoragePolicy"
    );
    assert_eq!(
        mneme_store::payload::read(dir.path(), restage_digest).expect("read restaged"),
        restage_text
    );
}

/// Convert a single-commit workspace to legacy SHA-256 blobs, record rows, and manifests.
fn rewrite_single_source_workspace_to_sha256(
    root: &std::path::Path,
    mut record: mneme_core::RecordEnvelope,
    source_bytes: &[u8],
) -> (mneme_core::ContentDigest, mneme_core::ContentDigest) {
    let connection =
        rusqlite::Connection::open(root.join(mneme_store::LEDGER_FILE)).expect("open sqlite");

    // Rewrite genesis manifest digest to SHA-256.
    let gen_bytes: Vec<u8> = connection
        .query_row(
            "SELECT revision_id FROM revisions WHERE sequence = 0",
            [],
            |row| row.get(0),
        )
        .expect("genesis");
    let gen_rev = mneme_core::WorkspaceRevisionId::from_bytes(
        gen_bytes.as_slice().try_into().expect("16 bytes"),
    );
    let gen_sha =
        mneme_store::Manifest::genesis(gen_rev).digest_with(mneme_core::HashAlgorithm::Sha256);
    connection
        .execute(
            "UPDATE revisions SET manifest_digest = ?1, manifest_algorithm = 'sha256' WHERE sequence = 0",
            rusqlite::params![gen_sha.as_bytes().as_slice()],
        )
        .expect("update genesis");

    // Rewrite source record to use SHA-256 retained source digest.
    let sha_source = mneme_core::ContentDigest::of_source_bytes_with(
        source_bytes,
        mneme_core::HashAlgorithm::Sha256,
    );
    let retained =
        mneme_core::RetainedSource::new(sha_source, source_bytes.len() as u64, "text/asciidoc")
            .expect("retained");
    record.payload = mneme_core::Payload::new([
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
            mneme_core::Value::string("notes/legacy.adoc"),
        ),
    ]);
    let value = record.to_value();
    let encoded_record = mneme_core::binary::encode(&value);
    let sha_full = record.full_digest_with(mneme_core::HashAlgorithm::Sha256);
    let sha_payload = record.payload_digest_with(mneme_core::HashAlgorithm::Sha256);

    // Stage SHA-256 blobs and delete BLAKE3 directory.
    let blake3_dir = root
        .join(mneme_store::payload::BLOB_DIRECTORY)
        .join("blake3");
    if blake3_dir.exists() {
        std::fs::remove_dir_all(&blake3_dir).expect("remove blake3");
    }
    mneme_store::payload::stage(root, sha_source, source_bytes).expect("stage sha source");
    mneme_store::payload::stage(root, sha_full, &encoded_record).expect("stage sha record");

    let rev1_bytes: Vec<u8> = connection
        .query_row(
            "SELECT revision_id FROM revisions WHERE sequence = 1",
            [],
            |row| row.get(0),
        )
        .expect("rev1");
    let rev1 = mneme_core::WorkspaceRevisionId::from_bytes(
        rev1_bytes.as_slice().try_into().expect("16 bytes"),
    );
    let manifest1 = mneme_store::Manifest {
        revision: rev1,
        parent: Some(gen_rev),
        records: std::collections::BTreeSet::from([mneme_store::ManifestRecord {
            record_id: record.record_id,
            revision_id: record.revision_id,
            kind: record.kind,
        }]),
        blobs: std::collections::BTreeSet::from([sha_full, sha_source]),
    };
    let manifest1_sha = manifest1.digest_with(mneme_core::HashAlgorithm::Sha256);

    connection
        .execute("DELETE FROM blobs", [])
        .expect("clear blobs");
    connection
        .execute(
            "INSERT INTO blobs (digest, algorithm, profile, boundary, byte_length)
             VALUES (?1, 'sha256', 'raw-bytes-v1', 'source-bytes', ?2),
                    (?3, 'sha256', 'preserves-canonical-binary-v1', 'full-record', ?4)",
            rusqlite::params![
                sha_source.as_bytes().as_slice(),
                source_bytes.len() as i64,
                sha_full.as_bytes().as_slice(),
                encoded_record.len() as i64,
            ],
        )
        .expect("insert sha blobs");
    connection
        .execute(
            "UPDATE records SET envelope_digest = ?1, payload_digest = ?2, full_digest = ?1
             WHERE record_id = ?3 AND revision_id = ?4",
            rusqlite::params![
                sha_full.as_bytes().as_slice(),
                sha_payload.as_bytes().as_slice(),
                record.record_id.as_bytes().as_slice(),
                record.revision_id.as_bytes().as_slice(),
            ],
        )
        .expect("update record");
    connection
        .execute("DELETE FROM revision_blob_changes", [])
        .expect("clear journal");
    connection
        .execute(
            "INSERT INTO revision_blob_changes (revision_sequence, digest, change)
             VALUES (1, ?1, 'add'), (1, ?2, 'add')",
            rusqlite::params![
                sha_source.as_bytes().as_slice(),
                sha_full.as_bytes().as_slice(),
            ],
        )
        .expect("insert sha journal");
    connection
        .execute(
            "UPDATE revisions SET manifest_digest = ?1, manifest_algorithm = 'sha256' WHERE sequence = 1",
            rusqlite::params![manifest1_sha.as_bytes().as_slice()],
        )
        .expect("update rev1");

    (sha_full, sha_source)
}

#[test]
fn legacy_sha256_retention_suppression_and_portable_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let scope = test_scope();
    let legacy_bytes = b"= Legacy SHA-256 Note\n\nStored before BLAKE3 migration.\n";
    let rec_id = mneme_core::RecordId::from_bytes([61; 16]);
    let rev_id = mneme_core::RevisionId::from_bytes([62; 16]);

    let mut ws = mneme_store::Workspace::create(dir.path(), test_config(1_000)).expect("create");
    let genesis = ws.current_revision().expect("genesis");
    ws.commit(record_command(
        genesis,
        &scope,
        "legacy-1",
        vec![retained_source_record(
            rec_id,
            rev_id,
            &scope,
            legacy_bytes,
            Some("notes/legacy.adoc"),
        )],
        vec![source_blob(legacy_bytes)],
        Vec::new(),
    ))
    .expect("commit");
    let record = ws.snapshot().expect("snap").records[0].clone();
    drop(ws);

    let (sha_full, sha_source) =
        rewrite_single_source_workspace_to_sha256(dir.path(), record, legacy_bytes);
    mneme_store::payload::publish_working_file(dir.path(), "notes/legacy.adoc", legacy_bytes)
        .expect("write working file");

    let verify_initial =
        mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Full).expect("verify");
    assert!(
        verify_initial.is_healthy(),
        "issues: {:?}",
        verify_initial.issues
    );

    // 1. Portable archive export & restore on legacy SHA-256 workspace.
    let export_dir = tempfile::tempdir().expect("export dir");
    let archive_path = export_dir.path().join("legacy.mneme");
    let mut ws = open_ws(dir.path(), 2_000);
    let export_report = ws
        .export_portable(&archive_path, &scope)
        .expect("export legacy sha256 portable archive");
    assert_eq!(export_report.blob_count, 1);

    let restored_dest = export_dir.path().join("restored-vault");
    let restore_report =
        mneme_store::portability::restore(&archive_path, &restored_dest, test_config(3_000))
            .expect("restore legacy sha256 archive");
    assert_eq!(restore_report.blob_count, 1);
    assert_eq!(
        mneme_store::payload::read(&restored_dest, sha_source).expect("read restored sha256 blob"),
        legacy_bytes
    );
    let verify_restored =
        mneme_store::verify_workspace(&restored_dest, mneme_store::VerifyMode::Full)
            .expect("verify restored");
    assert!(
        verify_restored.is_healthy(),
        "issues: {:?}",
        verify_restored.issues
    );

    // 2. Portable ingest_into existing empty workspace (and symlink refusal at ingest.rs:714).
    let ingest_dir = tempfile::tempdir().expect("ingest dir");
    let mut ingest_ws =
        mneme_store::Workspace::create(ingest_dir.path(), test_config(3_500)).expect("create");
    let ingested = mneme_store::portability::ingest_into(&archive_path, &mut ingest_ws)
        .expect("ingest legacy sha256 archive");
    assert_eq!(
        ingested.status,
        mneme_store::portability::IngestOutcomeStatus::Updated
    );
    assert_eq!(
        mneme_store::payload::read(ingest_dir.path(), sha_source).expect("read ingested sha256"),
        legacy_bytes
    );

    // Symlink at working target must be refused safely by inspect_working_file in ingest_into.
    #[cfg(unix)]
    {
        let symlink_ingest_dir = tempfile::tempdir().expect("symlink ingest dir");
        let mut sym_ws =
            mneme_store::Workspace::create(symlink_ingest_dir.path(), test_config(3_600))
                .expect("create");
        let outside_secret = export_dir.path().join("outside-secret.txt");
        std::fs::write(&outside_secret, b"outside secret").expect("write outside");
        let working_notes = symlink_ingest_dir.path().join("working").join("notes");
        std::fs::create_dir_all(&working_notes).expect("mkdir notes");
        std::os::unix::fs::symlink(&outside_secret, working_notes.join("legacy.adoc"))
            .expect("symlink");
        let err = mneme_store::portability::ingest_into(&archive_path, &mut sym_ws)
            .expect_err("symlink at working target must be refused");
        assert!(matches!(err, mneme_store::Failure::InvalidCommand(_)));
        assert_eq!(
            std::fs::read(&outside_secret).expect("outside untouched"),
            b"outside secret"
        );
    }

    // 3. Copy pre-forget SHA-256 workspace for suppression-ledger restore test.
    let restore_copy = tempfile::tempdir().expect("restore copy");
    copy_dir_tree(dir.path(), restore_copy.path());

    // 4. Retention forget + purge source blob + purge working file on legacy SHA-256 workspace.
    let head = ws.current_revision().expect("head");
    let generation = ws.snapshot().expect("snap").eligibility_generation;
    let op_id = "op-forget-sha256";
    ws.commit(mneme_store::CommitCommand {
        base: head,
        actor: "test-author".to_owned(),
        scope: scope.clone(),
        idempotency_key: "forget-sha256".to_owned(),
        records: Vec::new(),
        source_blobs: Vec::new(),
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: Some(mneme_store::RetentionCommit {
            operation_id: op_id.to_owned(),
            operation_kind: "forget".to_owned(),
            policy_version: "1".to_owned(),
            selectors: Vec::new(),
            suppressions: vec![mneme_store::RetentionSuppression {
                operation_id: op_id.to_owned(),
                target: rec_id,
                revision: None,
                target_kind: "source-revision".to_owned(),
                mode: mneme_store::SuppressionMode::Forgotten,
                content_digest: Some(sha_source),
                generation: generation.saturating_add(1),
            }],
            locations: vec![
                mneme_store::RetentionLocationPlan {
                    location_id: "loc-src".to_owned(),
                    location_kind: "source-blob".to_owned(),
                    locator: sha_source.to_hex(),
                },
                mneme_store::RetentionLocationPlan {
                    location_id: "loc-work".to_owned(),
                    location_kind: "working-file".to_owned(),
                    locator: format!("notes/legacy.adoc#{}", sha_source.to_hex()),
                },
            ],
            retained_metadata: vec![
                mneme_store::lifecycle::MANAGED_WORKING_PATH_DECLARATION.to_owned(),
            ],
        }),
    })
    .expect("forget sha256");

    assert_eq!(
        ws.purge_retention_blob(op_id, "loc-src", "source-blob", &sha_source.to_hex())
            .expect("purge sha256 source blob"),
        mneme_store::BlobPurgeOutcome::Purged
    );
    assert_eq!(
        ws.purge_retention_working_file(
            op_id,
            "loc-work",
            &format!("notes/legacy.adoc#{}", sha_source.to_hex()),
        )
        .expect("purge sha256 working copy"),
        mneme_store::BlobPurgeOutcome::Purged
    );
    assert!(
        !dir.path().join("working/notes/legacy.adoc").exists(),
        "SHA-256 working copy must be purged rather than flagged external-edit"
    );

    // 5. Suppression ledger export & apply on restored SHA-256 workspace (exercises recovery.rs:380).
    let ledger = ws.export_suppression_ledger().expect("export ledger");
    let mut restored_sha =
        mneme_store::Workspace::open_restored(restore_copy.path(), test_config(4_000))
            .expect("open restored sha");
    restored_sha
        .apply_restore_suppression_ledger(&ledger)
        .expect("apply suppression ledger to legacy sha256 workspace");
    assert!(
        !mneme_store::payload::blob_path(restore_copy.path(), sha_full).exists(),
        "restored SHA-256 record blob must be purged"
    );
    assert!(
        !mneme_store::payload::blob_path(restore_copy.path(), sha_source).exists(),
        "restored SHA-256 source blob must be purged"
    );
    assert!(
        !restore_copy
            .path()
            .join("working/notes/legacy.adoc")
            .exists(),
        "restored SHA-256 working file must be purged"
    );
}

#[test]
fn transfers_and_sync_directories_are_whitelisted_for_retention() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ws = mneme_store::Workspace::create(dir.path(), test_config(1_000)).expect("create");

    let transfers = dir.path().join(mneme_store::payload::TRANSFER_DIRECTORY);
    let sync_dir = dir.path().join(mneme_store::payload::SYNC_DIRECTORY);
    std::fs::create_dir_all(&transfers).expect("mkdir transfers");
    std::fs::create_dir_all(&sync_dir).expect("mkdir sync");
    std::fs::write(sync_dir.join("identity.key"), b"key").expect("write sync key");

    assert!(
        ws.unregistered_payload_entries()
            .expect("unregistered entries")
            .is_empty(),
        "transfers/ and sync/ must be recognized as workspace-owned directories"
    );

    let rogue = dir.path().join("rogue-exports");
    std::fs::create_dir_all(&rogue).expect("mkdir rogue");
    assert_eq!(
        ws.unregistered_payload_entries()
            .expect("unregistered entries"),
        vec!["rogue-exports".to_owned()]
    );
}

#[test]
fn verify_workspace_catches_chunk_dict_corruption_stray_outboards_and_projection_drift() {
    let dir = tempfile::tempdir().expect("tempdir");
    let scope = test_scope();
    let dict_bytes = train_test_dict();

    let mut ws = mneme_store::Workspace::create(dir.path(), test_config(1_000)).expect("create");
    let dict_digest = ws.stage_zstd_dictionary(&dict_bytes).expect("stage dict");
    ws.set_blob_compression(mneme_store::BlobCompression::ZstdDictionary {
        dictionary: dict_digest,
    });
    ws.set_blob_chunking(mneme_store::BlobChunking::FastCdc(
        mneme_store::FastCdcConfig::default(),
    ));

    let ent_id = mneme_core::RecordId::from_bytes([71; 16]);
    let ent_rev = mneme_core::RevisionId::from_bytes([72; 16]);
    let src_id = mneme_core::RecordId::from_bytes([73; 16]);
    let src_rev = mneme_core::RevisionId::from_bytes([74; 16]);
    let doc_id = mneme_core::RecordId::from_bytes([75; 16]);
    let doc_rev = mneme_core::RevisionId::from_bytes([76; 16]);

    let doc_payload = deterministic_asciidoc(4_000, "verify-cdc");
    let doc_digest = mneme_core::ContentDigest::of_source_bytes(&doc_payload);
    let doc_record = mneme_store::RecordDraft {
        schema_version: 1,
        kind: mneme_core::RecordKind::Document,
        record_id: doc_id,
        revision_id: doc_rev,
        predecessor: None,
        scope: scope.clone(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("entity"),
                mneme_core::Reference::local(ent_id, mneme_core::RecordKind::Entity).to_value(),
            ),
            (
                mneme_core::Symbol::from("title"),
                mneme_core::Value::string("Verify Parity Doc"),
            ),
            (
                mneme_core::Symbol::from("path"),
                mneme_core::Value::string("notes/parity.adoc"),
            ),
            (
                mneme_core::Symbol::from("source-revision"),
                mneme_core::Reference::local(src_id, mneme_core::RecordKind::SourceRevision)
                    .to_value(),
            ),
        ]),
    };

    let genesis = ws.current_revision().expect("genesis");
    ws.commit(record_command(
        genesis,
        &scope,
        "verify-setup",
        vec![
            entity_draft(ent_id, ent_rev, &scope, "Parity Entity"),
            retained_source_record(
                src_id,
                src_rev,
                &scope,
                &doc_payload,
                Some("notes/parity.adoc"),
            ),
            doc_record,
        ],
        vec![source_blob(&doc_payload)],
        Vec::new(),
    ))
    .expect("commit setup");

    // Baseline healthy in both Quick and Full modes.
    for mode in [
        mneme_store::VerifyMode::Quick,
        mneme_store::VerifyMode::Full,
    ] {
        let ok = mneme_store::verify_workspace(dir.path(), mode).expect("verify ok");
        assert!(ok.is_healthy(), "mode={mode:?} issues={:?}", ok.issues);
        assert!(ok.orphans.is_empty(), "orphans={:?}", ok.orphans);
    }

    // 1. Stray `.obao4` placed beside a framed blob is flagged in Quick and Full modes.
    let stray_ob = mneme_store::outboard::path(dir.path(), doc_digest);
    std::fs::write(&stray_ob, b"stray-outboard").expect("write stray ob");
    for mode in [
        mneme_store::VerifyMode::Quick,
        mneme_store::VerifyMode::Full,
    ] {
        let rep = mneme_store::verify_workspace(dir.path(), mode).expect("verify stray ob");
        assert!(!rep.is_healthy());
        assert!(
            rep.issues
                .iter()
                .any(|i| i.kind == mneme_store::IssueKind::CorruptOutboard),
            "mode={mode:?} issues={:?}",
            rep.issues
        );
    }
    std::fs::remove_file(&stray_ob).expect("remove stray ob");

    // 2. 1-byte corruption in a FastCDC chunk -> Full detects DigestMismatch.
    let chunks_dir = dir
        .path()
        .join(mneme_store::payload::BLOB_DIRECTORY)
        .join(mneme_store::dedup::CHUNK_DIRECTORY);
    let chunk_path = all_files_under(&chunks_dir)[0].clone();
    let orig_chunk = std::fs::read(&chunk_path).expect("read chunk");
    let mut bad_chunk = orig_chunk.clone();
    let last = bad_chunk.len() - 1;
    bad_chunk[last] ^= 0xff;
    std::fs::write(&chunk_path, &bad_chunk).expect("corrupt chunk");
    let bad_chunk_full =
        mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Full).expect("verify");
    assert!(!bad_chunk_full.is_healthy());
    assert!(
        bad_chunk_full
            .issues
            .iter()
            .any(|i| i.kind == mneme_store::IssueKind::DigestMismatch)
    );
    // Delete chunk -> Quick ALSO catches MissingBlob!
    std::fs::remove_file(&chunk_path).expect("delete chunk");
    let missing_chunk_quick =
        mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Quick).expect("verify");
    assert!(!missing_chunk_quick.is_healthy());
    assert!(
        missing_chunk_quick
            .issues
            .iter()
            .any(|i| i.kind == mneme_store::IssueKind::MissingBlob)
    );
    std::fs::write(&chunk_path, &orig_chunk).expect("restore chunk");

    // 3. Missing / corrupt Zstd dictionary -> Quick catches missing, Full catches 1-byte corruption.
    let dict_path = mneme_store::dedup::dictionary_path(dir.path(), dict_digest);
    let orig_dict = std::fs::read(&dict_path).expect("read dict");
    let mut bad_dict = orig_dict.clone();
    bad_dict[0] ^= 0xff;
    std::fs::write(&dict_path, &bad_dict).expect("corrupt dict");
    let bad_dict_full =
        mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Full).expect("verify");
    assert!(!bad_dict_full.is_healthy());
    assert!(
        bad_dict_full
            .issues
            .iter()
            .any(|i| i.kind == mneme_store::IssueKind::DigestMismatch)
    );
    std::fs::remove_file(&dict_path).expect("delete dict");
    let missing_dict_quick =
        mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Quick).expect("verify");
    assert!(!missing_dict_quick.is_healthy());
    assert!(
        missing_dict_quick
            .issues
            .iter()
            .any(|i| i.kind == mneme_store::IssueKind::MissingBlob)
    );
    std::fs::write(&dict_path, &orig_dict).expect("restore dict");

    // 4. SQLite #89 metadata projection parity: tamper entity label & delete document row.
    let conn =
        rusqlite::Connection::open(dir.path().join(mneme_store::LEDGER_FILE)).expect("sqlite");
    conn.execute("UPDATE entities SET label = 'TAMPERED'", [])
        .expect("tamper entity");
    conn.execute("DELETE FROM documents", [])
        .expect("delete document projection");
    drop(conn);

    let quick_drift =
        mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Quick).expect("verify");
    assert!(
        quick_drift
            .issues
            .iter()
            .any(|i| i.kind == mneme_store::IssueKind::ProjectionMismatch),
        "Quick mode must catch missing projection rows: {:?}",
        quick_drift.issues
    );

    let full_drift =
        mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Full).expect("verify");
    let proj_issues: Vec<_> = full_drift
        .issues
        .iter()
        .filter(|i| i.kind == mneme_store::IssueKind::ProjectionMismatch)
        .collect();
    assert_eq!(
        proj_issues.len(),
        2,
        "Full mode must catch both tampered entity column and missing document row: {:?}",
        full_drift.issues
    );

    // Recover rebuilds metadata projection -> verify returns healthy.
    ws.recover().expect("recover projection");
    let repaired =
        mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Full).expect("verify");
    assert!(repaired.is_healthy(), "issues: {:?}", repaired.issues);
}
