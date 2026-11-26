//! Integration tests for read-only workspace integrity verification.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::unwrap_used, clippy::expect_used)] // test/fixture code fails by panic, not a production path

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

fn fixture_command(base: mneme_core::WorkspaceRevisionId, key: &str) -> mneme_store::CommitCommand {
    let records: Vec<mneme_store::RecordDraft> = mneme_core::fixtures::fixture_batch()
        .iter()
        .map(|envelope| mneme_store::RecordDraft {
            schema_version: envelope.schema_version,
            kind: envelope.kind,
            record_id: envelope.record_id,
            revision_id: envelope.revision_id,
            predecessor: envelope.predecessor,
            scope: envelope.scope.clone(),
            payload: envelope.payload.clone(),
        })
        .collect();
    assert!(!records.is_empty());
    assert!(!key.is_empty());
    mneme_store::CommitCommand {
        base,
        actor: "test-author".to_owned(),
        scope: test_scope(),
        idempotency_key: key.to_owned(),
        records,
        source_blobs: vec![mneme_store::SourceBlobDraft::inline(
            mneme_core::fixtures::SOURCE_TEXT.as_bytes().to_vec(),
            mneme_core::Symbol::from("text/asciidoc"),
        )],
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: None,
    }
}

fn retained_source_record(bytes: &[u8]) -> mneme_store::RecordDraft {
    assert!(!bytes.is_empty());
    let retained = mneme_core::RetainedSource::new(
        mneme_core::ContentDigest::of_source_bytes(bytes),
        bytes.len() as u64,
        "text/asciidoc",
    )
    .expect("retained source");
    assert_eq!(retained.byte_length(), bytes.len() as u64);
    let entries = vec![
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
            mneme_core::Value::string("notes/retained.adoc"),
        ),
    ];
    mneme_store::RecordDraft {
        schema_version: 1,
        kind: mneme_core::RecordKind::SourceRevision,
        record_id: mneme_core::RecordId::from_bytes([9; 16]),
        revision_id: mneme_core::RevisionId::from_bytes([10; 16]),
        predecessor: None,
        scope: test_scope(),
        payload: mneme_core::Payload::new(entries),
    }
}

fn populated_workspace(root: &std::path::Path) -> mneme_store::Workspace {
    let mut workspace =
        mneme_store::Workspace::create(root, test_config()).expect("create workspace");
    let genesis = workspace.current_revision().expect("genesis");
    let outcome = workspace
        .commit(fixture_command(genesis, "first"))
        .expect("commit fixture");
    assert_eq!(outcome.sequence, 1);
    let mut command = fixture_command(outcome.revision, "second");
    let source_bytes = b"retained source payload bytes for scrub test";
    command.records = vec![retained_source_record(source_bytes)];
    command.source_blobs = vec![mneme_store::SourceBlobDraft::inline(
        source_bytes.to_vec(),
        mneme_core::Symbol::from("text/asciidoc"),
    )];
    let second = workspace.commit(command).expect("commit retained source");
    assert_eq!(second.sequence, 2);
    workspace
}

#[test]
fn healthy_workspace_passes_full_and_quick() {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = populated_workspace(dir.path());
    let head = workspace.current_revision().expect("head");

    let full = mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Full)
        .expect("full verify");
    assert!(full.is_healthy(), "issues: {:?}", full.issues);
    assert!(full.orphans.is_empty(), "orphans: {:?}", full.orphans);
    assert!(full.blobs_checked > 0);
    assert!(full.bytes_verified > 0);
    assert_eq!(full.bytes_verified, full.bytes_sized);
    assert!(full.records_checked > 0);
    assert_eq!(full.revisions_verified, 3); // genesis + 2 commits
    assert_eq!(full.head_revision.as_deref(), Some(head.to_hex().as_str()));

    let quick = mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Quick)
        .expect("quick verify");
    assert!(quick.is_healthy(), "issues: {:?}", quick.issues);
    assert_eq!(quick.blobs_checked, full.blobs_checked);
    assert_eq!(quick.bytes_verified, 0);
    assert_eq!(quick.bytes_sized, full.bytes_sized);
    assert_eq!(quick.revisions_verified, 3);
}

#[test]
fn corrupted_single_byte_fails_with_exact_digest_and_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = populated_workspace(dir.path());
    let snapshot = workspace.snapshot().expect("snapshot");
    let target = snapshot.records.first().expect("record");
    let digest = target.full_digest();
    let blob_path = mneme_store::payload::blob_path(dir.path(), digest);
    drop(workspace);

    let mut bytes = std::fs::read(&blob_path).expect("read blob");
    bytes[0] ^= 0xff;
    std::fs::write(&blob_path, &bytes).expect("corrupt blob");

    // Quick mode checks size only, so a same-length flip passes quick.
    let quick = mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Quick)
        .expect("quick verify");
    assert!(quick.is_healthy());

    let full = mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Full)
        .expect("full verify");
    assert!(!full.is_healthy());
    assert_eq!(full.issues.len(), 1, "issues: {:?}", full.issues);
    let issue = &full.issues[0];
    assert_eq!(issue.kind, mneme_store::IssueKind::DigestMismatch);
    assert_eq!(issue.digest.as_deref(), Some(digest.to_hex().as_str()));
    assert!(issue.path.as_deref().unwrap().contains(&digest.to_hex()));
    let expected_record = format!(
        "{}@{}",
        target.record_id.to_hex(),
        target.revision_id.to_hex()
    );
    assert!(
        issue.records.contains(&expected_record),
        "expected {expected_record} in {:?}",
        issue.records
    );
}

#[test]
fn deleted_blob_fails_in_full_and_quick() {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = populated_workspace(dir.path());
    let snapshot = workspace.snapshot().expect("snapshot");
    let target = snapshot.records.first().expect("record");
    let digest = target.full_digest();
    let blob_path = mneme_store::payload::blob_path(dir.path(), digest);
    drop(workspace);

    std::fs::remove_file(&blob_path).expect("delete blob");

    for mode in [
        mneme_store::VerifyMode::Quick,
        mneme_store::VerifyMode::Full,
    ] {
        let report = mneme_store::verify_workspace(dir.path(), mode).expect("verify");
        assert!(!report.is_healthy());
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.kind == mneme_store::IssueKind::MissingBlob)
            .expect("missing blob issue");
        assert_eq!(issue.digest.as_deref(), Some(digest.to_hex().as_str()));
        assert!(issue.path.as_deref().unwrap().contains(&digest.to_hex()));
    }
}

#[test]
fn truncated_blob_fails_with_size_mismatch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = populated_workspace(dir.path());
    let snapshot = workspace.snapshot().expect("snapshot");
    let target = snapshot.records.first().expect("record");
    let digest = target.full_digest();
    let blob_path = mneme_store::payload::blob_path(dir.path(), digest);
    drop(workspace);

    let bytes = std::fs::read(&blob_path).expect("read blob");
    std::fs::write(&blob_path, &bytes[..bytes.len() - 1]).expect("truncate blob");

    for mode in [
        mneme_store::VerifyMode::Quick,
        mneme_store::VerifyMode::Full,
    ] {
        let report = mneme_store::verify_workspace(dir.path(), mode).expect("verify");
        assert!(!report.is_healthy());
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.kind == mneme_store::IssueKind::SizeMismatch)
            .expect("size mismatch issue");
        assert_eq!(issue.digest.as_deref(), Some(digest.to_hex().as_str()));
    }
}

#[test]
fn orphan_blob_is_reported_without_failing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let _workspace = populated_workspace(dir.path());

    let orphan_digest = mneme_core::ContentDigest::of_source_bytes(b"unreferenced orphan");
    let orphan_path = mneme_store::payload::blob_path(dir.path(), orphan_digest);
    std::fs::create_dir_all(orphan_path.parent().unwrap()).expect("mkdir");
    std::fs::write(&orphan_path, b"unreferenced orphan").expect("write orphan");

    let report =
        mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Full).expect("verify");
    assert!(report.is_healthy());
    assert_eq!(report.orphans.len(), 1);
    assert_eq!(
        report.orphans[0].reason,
        mneme_store::OrphanReason::FileWithoutRow
    );
    assert_eq!(report.orphans[0].digest, orphan_digest.to_hex());
}

#[test]
fn tampered_manifest_digest_fails_chain_verification() {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = populated_workspace(dir.path());
    drop(workspace);

    let ledger = dir.path().join(mneme_store::LEDGER_FILE);
    let conn = rusqlite::Connection::open(&ledger).expect("open sqlite");
    conn.execute(
        "UPDATE revisions SET manifest_digest = zeroblob(32) WHERE sequence = 1",
        [],
    )
    .expect("tamper manifest_digest");
    drop(conn);

    let report =
        mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Full).expect("verify");
    assert!(!report.is_healthy());
    assert!(
        report.issues.iter().any(
            |issue| issue.kind == mneme_store::IssueKind::ManifestMismatch
                && issue.sequence == Some(1)
        ),
        "issues: {:?}",
        report.issues
    );
}

#[test]
fn dangling_source_blob_is_detected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = populated_workspace(dir.path());
    drop(workspace);

    let source_digest =
        mneme_core::ContentDigest::of_source_bytes(b"retained source payload bytes for scrub test");
    let ledger = dir.path().join(mneme_store::LEDGER_FILE);
    let conn = rusqlite::Connection::open(&ledger).expect("open sqlite");
    conn.execute(
        "DELETE FROM blobs WHERE digest = ?1",
        rusqlite::params![source_digest.as_bytes().as_slice()],
    )
    .expect("delete source blob row");
    drop(conn);

    let report =
        mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Full).expect("verify");
    assert!(!report.is_healthy());
    let issue = report
        .issues
        .iter()
        .find(|issue| issue.kind == mneme_store::IssueKind::DanglingSourceBlob)
        .expect("dangling source blob issue");
    assert_eq!(
        issue.digest.as_deref(),
        Some(source_digest.to_hex().as_str())
    );
    assert!(!issue.records.is_empty());
}

struct LegacySha256Blobs<'a> {
    record: &'a mneme_core::RecordEnvelope,
    source_digest: mneme_core::ContentDigest,
    full_digest: mneme_core::ContentDigest,
    payload_digest: mneme_core::ContentDigest,
    source_len: i64,
    record_len: i64,
}

fn rewrite_genesis_to_sha256(connection: &rusqlite::Connection) -> mneme_core::WorkspaceRevisionId {
    let (gen_rev_bytes,): (Vec<u8>,) = connection
        .query_row(
            "SELECT revision_id FROM revisions WHERE sequence = 0",
            [],
            |row| Ok((row.get(0)?,)),
        )
        .expect("genesis row");
    assert_eq!(gen_rev_bytes.len(), 16);
    let gen_rev = mneme_core::WorkspaceRevisionId::from_bytes(
        gen_rev_bytes.as_slice().try_into().expect("16 bytes"),
    );
    let gen_manifest = mneme_store::Manifest::genesis(gen_rev);
    let gen_sha = gen_manifest.digest_with(mneme_core::HashAlgorithm::Sha256);
    assert_eq!(gen_sha.algorithm(), mneme_core::HashAlgorithm::Sha256);
    let updated = connection
        .execute(
            "UPDATE revisions SET manifest_digest = ?1, manifest_algorithm = NULL WHERE sequence = 0",
            rusqlite::params![gen_sha.as_bytes().as_slice()],
        )
        .expect("update genesis");
    assert_eq!(updated, 1);
    gen_rev
}

/// Rewrite a newly created workspace's single commit (and genesis) to use
/// legacy SHA-256 digests and `blobs/sha256/...` paths, simulating a vault
/// created before BLAKE3 became the default.
fn convert_workspace_to_legacy_sha256(
    root: &std::path::Path,
    mut record: mneme_core::RecordEnvelope,
) -> mneme_core::ContentDigest {
    let connection =
        rusqlite::Connection::open(root.join(mneme_store::LEDGER_FILE)).expect("open sqlite");
    let gen_rev = rewrite_genesis_to_sha256(&connection);

    let source_bytes = b"legacy sha256 source bytes";
    let sha_source = mneme_core::ContentDigest::of_source_bytes_with(
        source_bytes,
        mneme_core::HashAlgorithm::Sha256,
    );
    assert_eq!(sha_source.algorithm(), mneme_core::HashAlgorithm::Sha256);
    mneme_store::payload::stage(root, sha_source, source_bytes).expect("stage sha source");

    let retained =
        mneme_core::RetainedSource::new(sha_source, source_bytes.len() as u64, "text/asciidoc")
            .expect("retained");
    record.payload.insert(
        "content",
        mneme_core::SourceContent::Retained(retained).to_value(),
    );
    let sha_full = record.full_digest_with(mneme_core::HashAlgorithm::Sha256);
    let sha_payload = record.payload_digest_with(mneme_core::HashAlgorithm::Sha256);
    let encoded_record = mneme_core::binary::encode(&record.to_value());
    mneme_store::payload::stage(root, sha_full, &encoded_record).expect("stage sha record");
    assert_eq!(sha_full.algorithm(), mneme_core::HashAlgorithm::Sha256);

    let blobs = LegacySha256Blobs {
        record: &record,
        source_digest: sha_source,
        full_digest: sha_full,
        payload_digest: sha_payload,
        source_len: source_bytes.len() as i64,
        record_len: encoded_record.len() as i64,
    };
    replace_rev1_with_sha256(&connection, gen_rev, &blobs);

    let blake3_dir = root.join("blobs").join("blake3");
    if blake3_dir.exists() {
        std::fs::remove_dir_all(&blake3_dir).expect("remove blake3 dir");
    }
    assert!(!blake3_dir.exists());

    sha_full
}

fn insert_sha256_ledger_rows(connection: &rusqlite::Connection, blobs: &LegacySha256Blobs<'_>) {
    connection
        .execute("DELETE FROM blobs", [])
        .expect("del blobs");
    connection
        .execute("DELETE FROM revision_blob_changes", [])
        .expect("del changes");
    connection
        .execute("DELETE FROM records", [])
        .expect("del records");
    connection
        .execute("DELETE FROM record_membership", [])
        .expect("del membership");

    let inserted_blobs = connection
        .execute(
            "INSERT INTO blobs (digest, algorithm, profile, boundary, byte_length)
             VALUES (?1, 'sha256', 'raw-bytes-v1', 'source-bytes', ?2),
                    (?3, 'sha256', 'preserves-canonical-binary-v1', 'full-record', ?4)",
            rusqlite::params![
                blobs.source_digest.as_bytes().as_slice(),
                blobs.source_len,
                blobs.full_digest.as_bytes().as_slice(),
                blobs.record_len,
            ],
        )
        .expect("insert sha blobs");
    assert_eq!(inserted_blobs, 2);
    connection
        .execute(
            "INSERT INTO revision_blob_changes (revision_sequence, digest, change)
             VALUES (1, ?1, 'add'), (1, ?2, 'add')",
            rusqlite::params![
                blobs.source_digest.as_bytes().as_slice(),
                blobs.full_digest.as_bytes().as_slice(),
            ],
        )
        .expect("insert sha changes");
    connection
        .execute(
            "INSERT INTO records (record_id, revision_id, kind, schema_version, scope,
                 recorded_at_ns, recorded_order, envelope_digest, payload_digest, full_digest)
             VALUES (?1, ?2, 'source-revision', 2, ?3, ?4, 0, ?5, ?6, ?5)",
            rusqlite::params![
                blobs.record.record_id.as_bytes().as_slice(),
                blobs.record.revision_id.as_bytes().as_slice(),
                blobs.record.scope.to_string(),
                blobs.record.recorded.at().nanos(),
                blobs.full_digest.as_bytes().as_slice(),
                blobs.payload_digest.as_bytes().as_slice(),
            ],
        )
        .expect("insert sha record");
    let inserted_membership = connection
        .execute(
            "INSERT INTO record_membership (record_id, revision_id, first_sequence, last_sequence)
             VALUES (?1, ?2, 1, NULL)",
            rusqlite::params![
                blobs.record.record_id.as_bytes().as_slice(),
                blobs.record.revision_id.as_bytes().as_slice(),
            ],
        )
        .expect("insert sha membership");
    assert_eq!(inserted_membership, 1);
}

fn replace_rev1_with_sha256(
    connection: &rusqlite::Connection,
    gen_rev: mneme_core::WorkspaceRevisionId,
    blobs: &LegacySha256Blobs<'_>,
) {
    let (rev1_bytes,): (Vec<u8>,) = connection
        .query_row(
            "SELECT revision_id FROM revisions WHERE sequence = 1",
            [],
            |row| Ok((row.get(0)?,)),
        )
        .expect("rev1 row");
    assert_eq!(rev1_bytes.len(), 16);
    let rev1 = mneme_core::WorkspaceRevisionId::from_bytes(
        rev1_bytes.as_slice().try_into().expect("16 bytes"),
    );

    insert_sha256_ledger_rows(connection, blobs);

    let mut manifest_records = std::collections::BTreeSet::new();
    manifest_records.insert(mneme_store::ManifestRecord {
        record_id: blobs.record.record_id,
        revision_id: blobs.record.revision_id,
        kind: blobs.record.kind,
    });
    let mut manifest_blobs = std::collections::BTreeSet::new();
    manifest_blobs.insert(blobs.source_digest);
    manifest_blobs.insert(blobs.full_digest);
    let rev1_manifest = mneme_store::Manifest {
        revision: rev1,
        parent: Some(gen_rev),
        records: manifest_records,
        blobs: manifest_blobs,
    };
    let rev1_sha = rev1_manifest.digest_with(mneme_core::HashAlgorithm::Sha256);
    let updated = connection
        .execute(
            "UPDATE revisions SET manifest_digest = ?1, manifest_algorithm = NULL WHERE sequence = 1",
            rusqlite::params![rev1_sha.as_bytes().as_slice()],
        )
        .expect("update rev1");
    assert_eq!(updated, 1);
}

#[test]
fn new_workspace_writes_blake3_digests_and_paths() {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = populated_workspace(dir.path());
    drop(workspace);

    assert!(dir.path().join("blobs").join("blake3").exists());
    assert!(!dir.path().join("blobs").join("sha256").exists());

    let connection =
        rusqlite::Connection::open(dir.path().join(mneme_store::LEDGER_FILE)).expect("open sqlite");
    let mut stmt = connection
        .prepare("SELECT DISTINCT algorithm FROM blobs")
        .expect("stmt");
    let algorithms: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("rows");
    assert_eq!(algorithms, vec!["blake3".to_owned()]);

    let mut stmt = connection
        .prepare("SELECT DISTINCT manifest_algorithm FROM revisions")
        .expect("stmt");
    let manifest_algorithms: Vec<Option<String>> = stmt
        .query_map([], |row| row.get(0))
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("rows");
    assert_eq!(manifest_algorithms, vec![Some("blake3".to_owned())]);

    let full = mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Full)
        .expect("full verify");
    assert!(full.is_healthy(), "issues: {:?}", full.issues);
}

fn source_commit(
    base: mneme_core::WorkspaceRevisionId,
    key: &str,
    id_byte: u8,
    bytes: &[u8],
) -> mneme_store::CommitCommand {
    let mut record = retained_source_record(bytes);
    record.record_id = mneme_core::RecordId::from_bytes([id_byte; 16]);
    record.revision_id = mneme_core::RevisionId::from_bytes([id_byte.wrapping_add(1); 16]);
    assert!(!key.is_empty());
    assert!(!bytes.is_empty());
    mneme_store::CommitCommand {
        base,
        actor: "test-author".to_owned(),
        scope: test_scope(),
        idempotency_key: key.to_owned(),
        records: vec![record],
        source_blobs: vec![mneme_store::SourceBlobDraft::inline(
            bytes.to_vec(),
            mneme_core::Symbol::from("text/asciidoc"),
        )],
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: None,
    }
}

#[test]
fn legacy_sha256_workspace_opens_reads_verifies_and_accepts_blake3_commits() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut workspace = mneme_store::Workspace::create(dir.path(), test_config()).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    let first = source_commit(genesis, "first", 21, b"legacy sha256 source bytes");
    workspace.commit(first).expect("commit");
    let record = workspace.snapshot().expect("snap").records[0].clone();
    drop(workspace);

    let sha_full = convert_workspace_to_legacy_sha256(dir.path(), record);
    assert_eq!(sha_full.algorithm(), mneme_core::HashAlgorithm::Sha256);

    let legacy_verify = mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Full)
        .expect("verify legacy");
    assert!(
        legacy_verify.is_healthy(),
        "issues: {:?}",
        legacy_verify.issues
    );

    let mut reopened =
        mneme_store::Workspace::open(dir.path(), test_config()).expect("reopen legacy");
    let snap = reopened.snapshot().expect("snapshot");
    assert_eq!(snap.records.len(), 1);
    let head = reopened.current_revision().expect("head");
    let blake3_bytes = b"new blake3 source bytes";
    let cmd = source_commit(head, "second", 31, blake3_bytes);
    let outcome = reopened.commit(cmd).expect("commit blake3 onto sha256");
    assert_eq!(
        outcome.manifest_digest.algorithm(),
        mneme_core::HashAlgorithm::Blake3
    );
    drop(reopened);

    let mixed_verify = mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Full)
        .expect("verify mixed");
    assert!(
        mixed_verify.is_healthy(),
        "issues: {:?}",
        mixed_verify.issues
    );
    assert_eq!(mixed_verify.revisions_verified, 3);

    let reopened = mneme_store::Workspace::open(dir.path(), test_config()).expect("reopen mixed");
    let snap = reopened.snapshot().expect("mixed snapshot");
    assert_eq!(snap.records.len(), 2);
}

#[test]
fn mixed_sha256_and_blake3_workspace_catches_corruption_in_both_algorithms() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut workspace = mneme_store::Workspace::create(dir.path(), test_config()).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    let first = source_commit(genesis, "first", 21, b"legacy sha256 source bytes");
    workspace.commit(first).expect("commit");
    let record = workspace.snapshot().expect("snap").records[0].clone();
    drop(workspace);

    let sha_full = convert_workspace_to_legacy_sha256(dir.path(), record);

    let mut reopened = mneme_store::Workspace::open(dir.path(), test_config()).expect("reopen");
    let head = reopened.current_revision().expect("head");
    let blake3_bytes = b"new blake3 source bytes";
    let blake3_source = mneme_core::ContentDigest::of_source_bytes(blake3_bytes);
    assert_eq!(blake3_source.algorithm(), mneme_core::HashAlgorithm::Blake3);
    let cmd = source_commit(head, "second", 31, blake3_bytes);
    reopened.commit(cmd).expect("commit blake3");
    drop(reopened);

    let sha_path = mneme_store::payload::blob_path(dir.path(), sha_full);
    let original_sha = std::fs::read(&sha_path).expect("read sha");
    let mut corrupted_sha = original_sha.clone();
    corrupted_sha[0] ^= 0xff;
    std::fs::write(&sha_path, &corrupted_sha).expect("write corrupt sha");
    let report = mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Full)
        .expect("verify corrupt sha");
    assert!(!report.is_healthy());
    assert!(report.issues.iter().any(|issue| {
        issue.kind == mneme_store::IssueKind::DigestMismatch
            && issue.digest.as_deref() == Some(sha_full.to_hex().as_str())
    }));
    std::fs::write(&sha_path, &original_sha).expect("restore sha");

    let blake3_path = mneme_store::payload::blob_path(dir.path(), blake3_source);
    let mut corrupted_b3 = std::fs::read(&blake3_path).expect("read b3");
    corrupted_b3[0] ^= 0xff;
    std::fs::write(&blake3_path, &corrupted_b3).expect("write corrupt b3");
    let report = mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Full)
        .expect("verify corrupt b3");
    assert!(!report.is_healthy());
    assert!(report.issues.iter().any(|issue| {
        issue.kind == mneme_store::IssueKind::DigestMismatch
            && issue.digest.as_deref() == Some(blake3_source.to_hex().as_str())
    }));
}

#[test]
fn legacy_sha256_workspace_retention_purge_deletes_sha256_blob() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut workspace = mneme_store::Workspace::create(dir.path(), test_config()).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    let first = source_commit(genesis, "first", 21, b"legacy sha256 source bytes");
    workspace.commit(first).expect("commit");
    let record = workspace.snapshot().expect("snap").records[0].clone();
    drop(workspace);

    let sha_full = convert_workspace_to_legacy_sha256(dir.path(), record.clone());
    let sha_path = mneme_store::payload::blob_path(dir.path(), sha_full);
    assert!(sha_path.exists());

    let mut reopened = mneme_store::Workspace::open(dir.path(), test_config()).expect("reopen");
    let head = reopened.current_revision().expect("head");
    let sha_source = mneme_core::ContentDigest::of_source_bytes_with(
        b"legacy sha256 source bytes",
        mneme_core::HashAlgorithm::Sha256,
    );
    let operation_id = "op-forget-legacy";
    let location_id = "loc-forget-legacy".to_owned();
    let generation = reopened
        .snapshot()
        .expect("reopened snap")
        .eligibility_generation;
    reopened
        .commit(mneme_store::CommitCommand {
            base: head,
            actor: "test-author".to_owned(),
            scope: test_scope(),
            idempotency_key: "forget-legacy".to_owned(),
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
                    target: record.record_id,
                    revision: None,
                    target_kind: "source-revision".to_owned(),
                    mode: mneme_store::SuppressionMode::Forgotten,
                    content_digest: Some(sha_source),
                    generation: generation.saturating_add(1),
                }],
                locations: vec![mneme_store::RetentionLocationPlan {
                    location_id: location_id.clone(),
                    location_kind: "record-blob".to_owned(),
                    locator: sha_full.to_hex(),
                }],
                retained_metadata: Vec::new(),
            }),
        })
        .expect("forget legacy");

    let outcome = reopened
        .purge_retention_blob(
            operation_id,
            &location_id,
            "record-blob",
            &sha_full.to_hex(),
        )
        .expect("purge legacy");
    assert_eq!(outcome, mneme_store::BlobPurgeOutcome::Purged);
    assert!(!sha_path.exists(), "legacy sha256 blob must be deleted");
}

#[test]
fn legacy_sha256_working_file_publishes_and_updates_to_blake3() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut workspace = mneme_store::Workspace::create(dir.path(), test_config()).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    let first = source_commit(genesis, "first", 21, b"legacy sha256 source bytes");
    workspace.commit(first).expect("commit");
    let record = workspace.snapshot().expect("snap").records[0].clone();
    drop(workspace);

    let _sha_full = convert_workspace_to_legacy_sha256(dir.path(), record);
    let legacy_bytes = b"legacy sha256 source bytes";
    let sha_source = mneme_core::ContentDigest::of_source_bytes_with(
        legacy_bytes,
        mneme_core::HashAlgorithm::Sha256,
    );
    let working_path = dir.path().join("working").join("notes").join("legacy.adoc");
    std::fs::create_dir_all(working_path.parent().expect("parent")).expect("mkdir");
    std::fs::write(&working_path, legacy_bytes).expect("write legacy working file");

    let mut reopened = mneme_store::Workspace::open(dir.path(), test_config()).expect("reopen");
    let head = reopened.current_revision().expect("head");
    let updated_bytes = b"updated blake3 content";
    let cmd = mneme_store::CommitCommand {
        base: head,
        actor: "test-author".to_owned(),
        scope: test_scope(),
        idempotency_key: "publish-over-legacy".to_owned(),
        records: Vec::new(),
        source_blobs: Vec::new(),
        publications: vec![mneme_store::PublicationDraft {
            path: "notes/legacy.adoc".to_owned(),
            expected_previous: Some(sha_source),
            bytes: updated_bytes.to_vec(),
        }],
        import_candidates: Vec::new(),
        retention: None,
    };
    let outcome = reopened.commit(cmd).expect("publish over legacy");
    assert_eq!(outcome.publications.len(), 1);
    assert_eq!(
        outcome.publications[0].state,
        mneme_store::PublicationState::Published
    );
    assert_eq!(std::fs::read(&working_path).expect("read"), updated_bytes);
}
