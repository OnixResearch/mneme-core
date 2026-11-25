//! Portable vault backup and restore tests.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

const V2_SOURCE: &[u8] = b"= Cedar Notes\n\nSecond committed revision.\n";
const IMAGE: &[u8] = b"\x89PNG\r\n\x1a\nportable-image-bytes";
const PRUNED_ALPHA: &[u8] = b"= Alpha source\n\nAlpha body.\n";
const PRUNED_BETA: &[u8] = b"= Beta source\n\nBeta body.\n";

fn scope() -> mneme_core::ScopeId {
    common::scope()
}

fn other_scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "other").expect("scope")
}

fn record_id(byte: u8) -> mneme_core::RecordId {
    mneme_core::RecordId::from_bytes([byte; 16])
}

fn revision_id(byte: u8) -> mneme_core::RevisionId {
    mneme_core::RevisionId::from_bytes([byte; 16])
}

fn config(at: i64) -> mneme_store::WorkspaceConfig {
    common::config(at)
}

fn image_draft(
    id: mneme_core::RecordId,
    revision: mneme_core::RevisionId,
    bytes: &[u8],
    path: &str,
) -> mneme_store::RecordDraft {
    let retained = mneme_core::RetainedSource::new(
        mneme_core::ContentDigest::of_source_bytes(bytes),
        bytes.len() as u64,
        "image/png",
    )
    .expect("retained image");
    mneme_store::RecordDraft {
        schema_version: 1,
        kind: mneme_core::RecordKind::SourceRevision,
        record_id: id,
        revision_id: revision,
        predecessor: None,
        scope: scope(),
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
                mneme_core::Value::string(path),
            ),
        ]),
    }
}

fn pruned_source_draft(
    id: mneme_core::RecordId,
    revision: mneme_core::RevisionId,
    predecessor: mneme_core::RevisionId,
    prior: mneme_core::ContentDigest,
) -> mneme_store::RecordDraft {
    mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::SourceRevision,
        record_id: id,
        revision_id: revision,
        predecessor: Some(predecessor),
        scope: scope(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("content"),
                mneme_core::SourceContent::Unavailable {
                    reason: "pruned by retention".to_owned(),
                }
                .to_value(),
            ),
            (
                mneme_core::Symbol::from("acquisition"),
                mneme_core::Value::symbol("authored"),
            ),
            (
                mneme_core::Symbol::from("availability"),
                mneme_core::Value::symbol("pruned"),
            ),
            (mneme_core::Symbol::from("content-digest"), prior.to_value()),
        ]),
    }
}

fn retained_bytes(root: &std::path::Path, record: &mneme_core::RecordEnvelope) -> Vec<u8> {
    let value = record.payload.get("content").expect("source content");
    let content = mneme_core::SourceContent::from_value(value, &mneme_core::Path::root())
        .expect("decoded content");
    let retained = match content {
        mneme_core::SourceContent::Retained(retained) => Some(retained),
        mneme_core::SourceContent::Unavailable { .. } => None,
    }
    .expect("retained source");
    mneme_store::payload::read(root, retained.digest()).expect("verified source")
}

fn omission(report: &mneme_store::portability::PortableExportReport, reason: &str) -> u64 {
    report
        .omissions
        .iter()
        .filter(|omission| omission.reason == reason)
        .map(|omission| omission.count)
        .sum()
}

fn restore_omission(report: &mneme_store::portability::PortableRestoreReport, reason: &str) -> u64 {
    report
        .omissions
        .iter()
        .filter(|omission| omission.reason == reason)
        .map(|omission| omission.count)
        .sum()
}

fn omission_entry(
    report: &mneme_store::portability::PortableExportReport,
    reason: &str,
) -> mneme_store::portability::PortableOmission {
    report
        .omissions
        .iter()
        .find(|omission| omission.reason == reason)
        .cloned()
        .expect("omission reason")
}

#[test]
fn portable_backup_preserves_history_attachment_and_memory_records() {
    let temp = tempfile::tempdir().expect("temp");
    let root = temp.path().join("source");
    let archive = temp.path().join("vault.mneme-backup");
    let restored = temp.path().join("restored");
    let source_id = mneme_core::fixtures::source_revision_id();
    let first_revision = mneme_core::fixtures::source_revision().revision_id;
    let second_revision = revision_id(0x44);
    let image_id = record_id(0x45);
    let image_revision = revision_id(0x46);
    let foreign_id = record_id(0x51);
    let mut workspace = mneme_store::Workspace::create(&root, config(1_000)).expect("create");
    workspace
        .commit(common::fixture_command(
            workspace.current_revision().expect("base"),
            "seed",
        ))
        .expect("seed");
    let mut revised = common::retained_source_record(
        source_id,
        second_revision,
        &scope(),
        V2_SOURCE,
        Some("project.adoc"),
    );
    revised.predecessor = Some(first_revision);
    workspace
        .commit(common::record_command(
            workspace.current_revision().expect("base"),
            &scope(),
            "revise",
            vec![revised],
            vec![common::source_blob(V2_SOURCE)],
            Vec::new(),
        ))
        .expect("revise");
    workspace
        .commit(common::record_command(
            workspace.current_revision().expect("base"),
            &scope(),
            "image",
            vec![image_draft(
                image_id,
                image_revision,
                IMAGE,
                "images/diagram.png",
            )],
            vec![mneme_store::SourceBlobDraft {
                file: None,
                bytes: IMAGE.to_vec(),
                media_type: mneme_core::Symbol::from("image/png"),
            }],
            Vec::new(),
        ))
        .expect("image");
    let mut foreign = mneme_core::fixtures::entity();
    foreign.record_id = foreign_id;
    foreign.revision_id = revision_id(0x52);
    foreign.scope = other_scope();
    foreign.payload.insert(
        mneme_core::Symbol::from("label"),
        mneme_core::Value::string("Foreign"),
    );
    workspace
        .commit(common::record_command(
            workspace.current_revision().expect("base"),
            &other_scope(),
            "foreign",
            vec![common::draft(&foreign)],
            Vec::new(),
            Vec::new(),
        ))
        .expect("foreign");

    let report = workspace
        .export_portable(&archive, &scope())
        .expect("export");
    assert_eq!(report.scope, scope());
    assert_eq!(report.record_count, 6);
    assert_eq!(report.revision_count, 7);
    assert_eq!(report.blob_count, 3);
    assert_eq!(omission(&report, "foreign-scope-record"), 1);
    assert!(!report.checksum.is_empty());
    assert!(archive.is_file());

    let restored_report =
        mneme_store::portability::restore(&archive, &restored, config(2_000)).expect("restore");
    assert_eq!(restored_report.destination, restored);
    assert_eq!(restored_report.scope, scope());
    assert_eq!(restored_report.record_count, 6);
    assert_eq!(restored_report.revision_count, 7);
    assert_eq!(restored_report.blob_count, 3);
    assert_eq!(restored_report.rewritten_predecessors, 0);
    assert_eq!(restored_report.ambiguous_publication_paths, 0);
    assert_eq!(
        restored_report
            .publications
            .iter()
            .filter(|publication| { publication.state == mneme_store::PublicationState::Published })
            .count(),
        2
    );

    let restored_workspace = common::open(&restored, 3_000);
    let snapshot = restored_workspace.snapshot().expect("snapshot");
    assert_eq!(snapshot.records.len(), 6);
    assert!(
        snapshot
            .records
            .iter()
            .all(|record| record.record_id != foreign_id),
        "foreign-scope record must not travel"
    );
    let source = snapshot
        .records
        .iter()
        .find(|record| record.record_id == source_id)
        .expect("source record");
    assert_eq!(source.revision_id, second_revision);
    let histories = restored_workspace
        .record_histories_of(
            &snapshot,
            &std::collections::BTreeSet::from([source_id, image_id]),
        )
        .expect("histories");
    let source_history = histories.get(&source_id).expect("source history");
    assert_eq!(
        source_history
            .iter()
            .map(|record| record.revision_id)
            .collect::<Vec<_>>(),
        vec![first_revision, second_revision]
    );
    assert_eq!(
        retained_bytes(&restored, &source_history[0]),
        mneme_core::fixtures::SOURCE_TEXT.as_bytes()
    );
    assert_eq!(retained_bytes(&restored, &source_history[1]), V2_SOURCE);
    let image_history = histories.get(&image_id).expect("image history");
    assert_eq!(image_history.len(), 1);
    assert_eq!(retained_bytes(&restored, &image_history[0]), IMAGE);
    let assertion = snapshot
        .records
        .iter()
        .find(|record| record.record_id == mneme_core::fixtures::assertion_id())
        .expect("memory record");
    assert_eq!(assertion.kind, mneme_core::RecordKind::Assertion);
    assert_eq!(
        std::fs::read(restored.join("working/project.adoc")).expect("published note"),
        V2_SOURCE
    );
    assert_eq!(
        std::fs::read(restored.join("working/images/diagram.png")).expect("published image"),
        IMAGE
    );
}

#[test]
fn portable_restore_keeps_forgotten_identity_and_content_unreplayable() {
    let temp = tempfile::tempdir().expect("temp");
    let root = temp.path().join("source");
    let archive = temp.path().join("vault.mneme-backup");
    let restored = temp.path().join("restored");
    let source_id = record_id(0x61);
    let source_revision = revision_id(0x62);
    let mut workspace = mneme_store::Workspace::create(&root, config(1_000)).expect("create");
    let mut seed = common::retained_source_record(
        source_id,
        source_revision,
        &scope(),
        mneme_core::fixtures::SOURCE_TEXT.as_bytes(),
        Some("source.adoc"),
    );
    seed.predecessor = None;
    workspace
        .commit(common::record_command(
            workspace.current_revision().expect("base"),
            &scope(),
            "seed",
            vec![seed],
            vec![common::source_blob(
                mneme_core::fixtures::SOURCE_TEXT.as_bytes(),
            )],
            Vec::new(),
        ))
        .expect("seed");
    let generation = workspace
        .eligibility_generation()
        .expect("generation")
        .saturating_add(1);
    let retention = common::forget_content_barrier(
        source_id,
        mneme_core::fixtures::SOURCE_TEXT.as_bytes(),
        generation,
        "forget-source",
    );
    workspace
        .commit(common::audit_barrier_command(
            workspace.current_revision().expect("base"),
            "forget-source",
            retention,
        ))
        .expect("forget");

    let report = workspace
        .export_portable(&archive, &scope())
        .expect("export");
    assert_eq!(omission(&report, "forgotten-record"), 1);
    assert_eq!(report.record_count, 0);
    assert_eq!(report.revision_count, 0);
    assert_eq!(report.blob_count, 0);
    assert!(
        report
            .omissions
            .iter()
            .any(|omission| omission.reason == "forgotten-record")
    );
    let restore =
        mneme_store::portability::restore(&archive, &restored, config(2_000)).expect("restore");
    assert_eq!(restore_omission(&restore, "forgotten-record"), 1);

    let mut restored_workspace = common::open(&restored, 3_000);
    let snapshot = restored_workspace.snapshot().expect("snapshot");
    assert!(
        snapshot
            .records
            .iter()
            .all(|record| record.record_id != source_id),
        "a forgotten identity must not travel as a record"
    );
    assert!(matches!(
        restored_workspace.record_revisions(source_id),
        Err(mneme_store::Failure::RetentionSuppressed { .. })
    ));
    let replay = common::retained_source_record(
        record_id(0x71),
        revision_id(0x72),
        &scope(),
        mneme_core::fixtures::SOURCE_TEXT.as_bytes(),
        Some("revived.adoc"),
    );
    let error = restored_workspace
        .commit(common::record_command(
            restored_workspace.current_revision().expect("base"),
            &scope(),
            "revive",
            vec![replay],
            vec![common::source_blob(
                mneme_core::fixtures::SOURCE_TEXT.as_bytes(),
            )],
            Vec::new(),
        ))
        .expect_err("forgotten content must stay unreplayable");
    assert!(matches!(
        error,
        mneme_store::Failure::RetentionSuppressed { .. }
    ));
}

#[test]
fn portable_export_refuses_a_scope_whose_remaining_records_dangle() {
    let temp = tempfile::tempdir().expect("temp");
    let root = temp.path().join("source");
    let archive = temp.path().join("vault.mneme-backup");
    let source_id = mneme_core::fixtures::source_revision_id();
    let mut workspace = mneme_store::Workspace::create(&root, config(1_000)).expect("create");
    workspace
        .commit(common::fixture_command(
            workspace.current_revision().expect("base"),
            "seed",
        ))
        .expect("seed");
    let generation = workspace
        .eligibility_generation()
        .expect("generation")
        .saturating_add(1);
    let retention = common::forget_content_barrier(
        source_id,
        mneme_core::fixtures::SOURCE_TEXT.as_bytes(),
        generation,
        "forget-source",
    );
    workspace
        .commit(common::audit_barrier_command(
            workspace.current_revision().expect("base"),
            "forget-source",
            retention,
        ))
        .expect("forget");
    let error = workspace
        .export_portable(&archive, &scope())
        .expect_err("a batch that references a forgotten record cannot be restored");
    assert!(
        error
            .to_string()
            .contains("cannot be restored as a set of complete batches"),
        "{error}"
    );
    assert!(
        !archive.exists(),
        "a refused export leaves no partial archive"
    );
}

#[test]
fn portable_restore_refuses_corruption_and_an_existing_destination() {
    let temp = tempfile::tempdir().expect("temp");
    let root = temp.path().join("source");
    let archive = temp.path().join("vault.mneme-backup");
    let mut workspace = mneme_store::Workspace::create(&root, config(1_000)).expect("create");
    workspace
        .commit(common::fixture_command(
            workspace.current_revision().expect("base"),
            "seed",
        ))
        .expect("seed");
    workspace
        .export_portable(&archive, &scope())
        .expect("export");
    let bytes = std::fs::read(&archive).expect("archive");

    let flipped = temp.path().join("flipped.mneme-backup");
    let mut damaged = bytes.clone();
    let index = damaged.len() / 2;
    damaged[index] ^= 0x01;
    std::fs::write(&flipped, &damaged).expect("write flipped");
    let destination = temp.path().join("flipped-restore");
    assert!(
        mneme_store::portability::restore(&flipped, &destination, config(2_000)).is_err(),
        "a changed byte must be refused"
    );
    assert!(!destination.exists());

    let truncated = temp.path().join("truncated.mneme-backup");
    std::fs::write(&truncated, &bytes[..bytes.len() - 5]).expect("write truncated");
    let destination = temp.path().join("truncated-restore");
    assert!(
        mneme_store::portability::restore(&truncated, &destination, config(3_000)).is_err(),
        "a truncated body must be refused"
    );
    assert!(!destination.exists());

    let occupied = temp.path().join("occupied");
    std::fs::create_dir_all(&occupied).expect("occupied");
    std::fs::write(occupied.join("keep.txt"), b"user data").expect("keep");
    assert!(
        mneme_store::portability::restore(&archive, &occupied, config(4_000)).is_err(),
        "an existing destination must be refused"
    );
    assert_eq!(
        std::fs::read(occupied.join("keep.txt")).expect("kept file"),
        b"user data"
    );

    let destination = temp.path().join("valid-restore");
    mneme_store::portability::restore(&archive, &destination, config(5_000))
        .expect("valid restore");
    assert!(destination.join(mneme_store::LEDGER_FILE).is_file());
}

#[test]
fn portable_restore_keeps_pre_prune_history_and_blocks_pruned_bytes() {
    let temp = tempfile::tempdir().expect("temp");
    let root = temp.path().join("source");
    let archive = temp.path().join("vault.mneme-backup");
    let restored = temp.path().join("restored");
    let source_id = record_id(0xB1);
    let first = revision_id(0xB2);
    let second = revision_id(0xB3);
    let pruned = revision_id(0xB4);
    let mut workspace = mneme_store::Workspace::create(&root, config(1_000)).expect("create");
    let mut first_draft = common::retained_source_record(
        source_id,
        first,
        &scope(),
        PRUNED_ALPHA,
        Some("alpha.adoc"),
    );
    first_draft.predecessor = None;
    workspace
        .commit(common::record_command(
            workspace.current_revision().expect("base"),
            &scope(),
            "seed",
            vec![first_draft],
            vec![common::source_blob(PRUNED_ALPHA)],
            Vec::new(),
        ))
        .expect("seed");
    let mut second_draft = common::retained_source_record(
        source_id,
        second,
        &scope(),
        PRUNED_BETA,
        Some("alpha.adoc"),
    );
    second_draft.predecessor = Some(first);
    workspace
        .commit(common::record_command(
            workspace.current_revision().expect("base"),
            &scope(),
            "revise",
            vec![second_draft],
            vec![common::source_blob(PRUNED_BETA)],
            Vec::new(),
        ))
        .expect("revise");
    workspace
        .commit(common::record_command(
            workspace.current_revision().expect("base"),
            &scope(),
            "prune",
            vec![pruned_source_draft(
                source_id,
                pruned,
                second,
                mneme_core::ContentDigest::of_source_bytes(PRUNED_BETA),
            )],
            Vec::new(),
            Vec::new(),
        ))
        .expect("prune");

    let report = workspace
        .export_portable(&archive, &scope())
        .expect("export");
    assert_eq!(omission(&report, "pruned-revision"), 1);
    assert_eq!(
        omission_entry(&report, "pruned-revision").count,
        1,
        "the pruned revision is named, not silently dropped"
    );
    assert_eq!(report.record_count, 1);
    assert_eq!(report.revision_count, 2);
    assert_eq!(report.blob_count, 1);

    let restore =
        mneme_store::portability::restore(&archive, &restored, config(2_000)).expect("restore");
    assert_eq!(restore.rewritten_predecessors, 1);
    let mut restored_workspace = common::open(&restored, 3_000);
    let snapshot = restored_workspace.snapshot().expect("snapshot");
    let source = snapshot
        .records
        .iter()
        .find(|record| record.record_id == source_id)
        .expect("source");
    assert_eq!(source.revision_id, pruned);
    let histories = restored_workspace
        .record_histories_of(&snapshot, &std::collections::BTreeSet::from([source_id]))
        .expect("histories");
    let history = histories.get(&source_id).expect("history");
    assert_eq!(
        history
            .iter()
            .map(|record| record.revision_id)
            .collect::<Vec<_>>(),
        vec![first, pruned],
        "pre-prune history is retained while the pruned revision is omitted"
    );
    assert_eq!(retained_bytes(&restored, &history[0]), PRUNED_ALPHA);

    let replay = common::retained_source_record(
        record_id(0xB5),
        revision_id(0xB6),
        &scope(),
        PRUNED_BETA,
        Some("beta.adoc"),
    );
    let error = restored_workspace
        .commit(common::record_command(
            restored_workspace.current_revision().expect("base"),
            &scope(),
            "replay-beta",
            vec![replay],
            vec![common::source_blob(PRUNED_BETA)],
            Vec::new(),
        ))
        .expect_err("pruned bytes must stay unreplayable");
    assert!(matches!(
        error,
        mneme_store::Failure::RetentionSuppressed { .. }
    ));
}
