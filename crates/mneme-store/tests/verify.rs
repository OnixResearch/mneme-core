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
        source_blobs: vec![mneme_store::SourceBlobDraft {
            bytes: mneme_core::fixtures::SOURCE_TEXT.as_bytes().to_vec(),
            media_type: mneme_core::Symbol::from("text/asciidoc"),
        }],
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
    command.source_blobs = vec![mneme_store::SourceBlobDraft {
        bytes: source_bytes.to_vec(),
        media_type: mneme_core::Symbol::from("text/asciidoc"),
    }];
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
        mneme_store::verify_workspace(dir.path(), mneme_store::VerifyMode::Quick).expect("verify");
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
