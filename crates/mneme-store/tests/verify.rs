//! Integration tests for read-only workspace integrity verification.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

fn populated_workspace(root: &std::path::Path) -> mneme_store::Workspace {
    let mut workspace =
        mneme_store::Workspace::create(root, common::config(1_000)).expect("create workspace");
    let genesis = workspace.current_revision().expect("genesis");
    let outcome = workspace
        .commit(common::fixture_command(genesis, "first"))
        .expect("commit fixture");
    let mut command = common::fixture_command(outcome.revision, "second");
    command.records = vec![common::retained_source_record(
        mneme_core::RecordId::from_bytes([9; 16]),
        mneme_core::RevisionId::from_bytes([10; 16]),
        &common::scope(),
        b"retained source payload bytes for scrub test",
        Some("notes/retained.adoc"),
    )];
    command.source_blobs = vec![mneme_store::SourceBlobDraft {
        bytes: b"retained source payload bytes for scrub test".to_vec(),
        media_type: mneme_core::Symbol::from("text/asciidoc"),
    }];
    workspace.commit(command).expect("commit retained source");
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
