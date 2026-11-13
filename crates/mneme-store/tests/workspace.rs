//! End-to-end workspace coordinator tests.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::unwrap_used, clippy::expect_used)]

use mneme_store::FaultInjector;

mod common;

// `common` holds the single definition of every shared fixture. These adapters
// let the tests below keep calling a fixture by name: the lint gate rejects
// importing a non-trait item, so the name is bound here instead.
fn scope() -> mneme_core::ScopeId {
    common::scope()
}

fn config(at: i64) -> mneme_store::WorkspaceConfig {
    common::config(at)
}

fn draft(envelope: &mneme_core::RecordEnvelope) -> mneme_store::RecordDraft {
    common::draft(envelope)
}

fn fixture_command(base: mneme_core::WorkspaceRevisionId, key: &str) -> mneme_store::CommitCommand {
    common::fixture_command(base, key)
}

fn open(root: &std::path::Path, at: i64) -> mneme_store::Workspace {
    common::open(root, at)
}

fn retained_source_record(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    bytes: &[u8],
    path: Option<&str>,
) -> mneme_store::RecordDraft {
    common::retained_source_record(record_id, revision_id, scope, bytes, path)
}

fn publication_command(
    base: mneme_core::WorkspaceRevisionId,
    scope: &mneme_core::ScopeId,
    key: &str,
    path: &str,
    bytes: &[u8],
) -> mneme_store::CommitCommand {
    common::publication_command(base, scope, key, path, bytes)
}

#[allow(unknown_lints, too_many_parameters)] // every membership fixture passes the three target fields positionally
fn record_command(
    base: mneme_core::WorkspaceRevisionId,
    scope: &mneme_core::ScopeId,
    key: &str,
    records: Vec<mneme_store::RecordDraft>,
    blobs: Vec<mneme_store::SourceBlobDraft>,
    candidates: Vec<mneme_store::ImportCandidateDraft>,
) -> mneme_store::CommitCommand {
    common::record_command(base, scope, key, records, blobs, candidates)
}

fn source_blob(bytes: &[u8]) -> mneme_store::SourceBlobDraft {
    common::source_blob(bytes)
}

fn forget_content_barrier(
    target: mneme_core::RecordId,
    bytes: &[u8],
    generation: u64,
    operation_id: &str,
) -> mneme_store::RetentionCommit {
    common::forget_content_barrier(target, bytes, generation, operation_id)
}

fn audit_barrier_command(
    base: mneme_core::WorkspaceRevisionId,
    key: &str,
    retention: mneme_store::RetentionCommit,
) -> mneme_store::CommitCommand {
    common::audit_barrier_command(base, key, retention)
}

fn audit_blob_location(
    location_kind: &str,
    digest: mneme_core::ContentDigest,
) -> mneme_store::RetentionLocationPlan {
    common::audit_blob_location(location_kind, digest)
}

fn config_with_faults(at: i64, faults: Box<dyn FaultInjector>) -> mneme_store::WorkspaceConfig {
    mneme_store::WorkspaceConfig {
        clock: Box::new(mneme_store::FixedClock::new(
            mneme_core::Timestamp::from_nanos(at),
        )),
        faults,
    }
}

struct SourceDraftInput<'a> {
    bytes: &'a [u8],
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    predecessor: Option<mneme_core::RevisionId>,
    entity: mneme_core::RecordId,
    path: &'a str,
}

fn source_draft(input: SourceDraftInput<'_>) -> mneme_store::RecordDraft {
    let retained = mneme_core::RetainedSource::new(
        mneme_core::ContentDigest::of_source_bytes(input.bytes),
        input.bytes.len() as u64,
        "text/asciidoc",
    )
    .expect("retained source");
    mneme_store::RecordDraft {
        schema_version: 1,
        kind: mneme_core::RecordKind::SourceRevision,
        record_id: input.record_id,
        revision_id: input.revision_id,
        predecessor: input.predecessor,
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
                mneme_core::Symbol::from("entity"),
                mneme_core::Reference::local(input.entity, mneme_core::RecordKind::Entity)
                    .to_value(),
            ),
            (
                mneme_core::Symbol::from("path-hint"),
                mneme_core::Value::string(input.path),
            ),
        ]),
    }
}

#[test]
fn commit_advances_one_revision_and_reads_a_complete_snapshot() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    assert_eq!(workspace.status().expect("status").record_count, 0);

    let outcome = workspace
        .commit(fixture_command(genesis, "first"))
        .expect("commit");
    assert_eq!(outcome.sequence, 1);
    assert_eq!(outcome.eligibility_generation, 1);
    assert_eq!(
        outcome.revision,
        workspace.current_revision().expect("current")
    );
    assert!(outcome.publications.is_empty());

    let snapshot = workspace.snapshot().expect("snapshot");
    assert_eq!(snapshot.sequence, 1);
    assert_eq!(
        snapshot.records.len(),
        mneme_core::fixtures::fixture_batch().len()
    );
    assert_eq!(snapshot.parent, Some(genesis));
    let assertion = snapshot
        .records
        .iter()
        .find(|record| record.record_id == mneme_core::fixtures::assertion_id())
        .expect("assertion");
    assert_eq!(
        assertion.assertion_lifecycle(),
        Some(mneme_core::Lifecycle::Proposed)
    );
    for record in &snapshot.records {
        assert_eq!(record.recorded.at().nanos(), 1_000);
        assert_eq!(record.recorded.revision_order(), 1);
    }
    let index: &mneme_core::SnapshotIndex = &snapshot.index;
    assert_eq!(index.len(), snapshot.records.len());

    // Reopening retains the same pinned revision and manifest.
    let reopened = open(temp.path(), 2_000);
    let again = reopened.snapshot().expect("reopened snapshot");
    assert_eq!(again.revision, snapshot.revision);
    assert_eq!(again.manifest_digest, snapshot.manifest_digest);
    assert_eq!(again.records, snapshot.records);
    assert_eq!(reopened.status().expect("status").record_count, 5);
}

#[test]
fn stale_base_cannot_replace_the_winner() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    workspace
        .commit(fixture_command(genesis, "winner"))
        .expect("commit");
    let winner = workspace.snapshot().expect("snapshot");

    let mut loser = fixture_command(genesis, "loser");
    loser.publications = vec![mneme_store::PublicationDraft {
        path: "project.adoc".to_owned(),
        expected_previous: None,
        bytes: b"loser bytes".to_vec(),
    }];
    let error = workspace.commit(loser).expect_err("stale");
    assert!(matches!(error, mneme_store::Failure::StaleBase { .. }));
    let after = workspace.snapshot().expect("still valid");
    assert_eq!(after.revision, winner.revision);
    assert_eq!(after.records, winner.records);
    assert!(
        mneme_store::payload::read_working_file(temp.path(), "project.adoc")
            .expect("working")
            .is_none(),
        "a stale command must not publish files"
    );
}

#[test]
fn idempotent_retry_returns_the_original_revision_and_conflicts_on_changed_content() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    let command = fixture_command(genesis, "same-key");
    let first = workspace.commit(command.clone()).expect("first");

    let retry = workspace.commit(command.clone()).expect("idempotent retry");
    assert_eq!(retry.revision, first.revision);
    assert_eq!(retry.sequence, first.sequence);
    assert_eq!(workspace.status().expect("status").sequence, 1);

    let mut reopened = {
        let mut reopened = open(temp.path(), 2_000);
        let retry = reopened.commit(command).expect("retry survives restart");
        assert_eq!(retry.revision, first.revision);
        reopened
    };
    let mut changed = fixture_command(genesis, "same-key");
    changed.actor = "test-author".to_owned();
    changed.records.pop();
    let error = reopened.commit(changed).expect_err("conflicting content");
    assert!(matches!(
        error,
        mneme_store::Failure::IdempotencyConflict { .. }
    ));
    let status = reopened.status().expect("status");
    assert_eq!(status.sequence, 1);
    let _ = temp; // keep the directory until the reopened handle is dropped
}

#[test]
fn external_import_candidate_must_match_existing_bytes_and_bindings() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    let initial = mneme_store::CommitCommand {
        base: genesis,
        actor: "author".to_owned(),
        scope: scope(),
        idempotency_key: "source".to_owned(),
        records: vec![
            draft(&mneme_core::fixtures::entity()),
            draft(&mneme_core::fixtures::source_revision()),
        ],
        source_blobs: vec![mneme_store::SourceBlobDraft {
            bytes: mneme_core::fixtures::SOURCE_TEXT.as_bytes().to_vec(),
            media_type: mneme_core::Symbol::from("text/asciidoc"),
        }],
        publications: vec![mneme_store::PublicationDraft {
            path: "project.adoc".to_owned(),
            expected_previous: None,
            bytes: mneme_core::fixtures::SOURCE_TEXT.as_bytes().to_vec(),
        }],
        import_candidates: Vec::new(),
        retention: None,
    };
    workspace.commit(initial).expect("initial commit");
    let base = workspace.current_revision().expect("current");

    let edited = format!("{}\n// external edit\n", mneme_core::fixtures::SOURCE_TEXT);
    mneme_store::payload::publish_working_file(temp.path(), "project.adoc", edited.as_bytes())
        .expect("edit file");
    let revision = mneme_core::RevisionId::from_bytes([0x21; 16]);
    let replacement = source_draft(SourceDraftInput {
        bytes: edited.as_bytes(),
        record_id: mneme_core::fixtures::source_revision_id(),
        revision_id: revision,
        predecessor: Some(mneme_core::fixtures::source_revision().revision_id),
        entity: mneme_core::fixtures::entity_id(),
        path: "project.adoc",
    });
    let import = mneme_store::CommitCommand {
        base,
        actor: "author".to_owned(),
        scope: scope(),
        idempotency_key: "import".to_owned(),
        records: vec![replacement.clone()],
        source_blobs: Vec::new(),
        publications: Vec::new(),
        import_candidates: vec![mneme_store::ImportCandidateDraft {
            path: "project.adoc".to_owned(),
            bytes: edited.as_bytes().to_vec(),
        }],
        retention: None,
    };
    workspace.commit(import).expect("candidate import");
    let snapshot = workspace.snapshot().expect("snapshot");
    let source = snapshot
        .records
        .iter()
        .find(|record| record.record_id == mneme_core::fixtures::source_revision_id())
        .expect("source");
    assert_eq!(source.revision_id, revision);

    // A candidate whose bytes no longer match the working file is refused and
    // leaves the committed snapshot untouched.
    mneme_store::payload::publish_working_file(
        temp.path(),
        "project.adoc",
        b"newer external bytes",
    )
    .expect("second edit");
    let second_revision = mneme_core::RevisionId::from_bytes([0x22; 16]);
    let stale = mneme_store::CommitCommand {
        base: workspace.current_revision().expect("current"),
        actor: "author".to_owned(),
        scope: scope(),
        idempotency_key: "stale-import".to_owned(),
        records: vec![source_draft(SourceDraftInput {
            bytes: edited.as_bytes(),
            record_id: mneme_core::fixtures::source_revision_id(),
            revision_id: second_revision,
            predecessor: Some(revision),
            entity: mneme_core::fixtures::entity_id(),
            path: "project.adoc",
        })],
        source_blobs: Vec::new(),
        publications: Vec::new(),
        import_candidates: vec![mneme_store::ImportCandidateDraft {
            path: "project.adoc".to_owned(),
            bytes: edited.as_bytes().to_vec(),
        }],
        retention: None,
    };
    let error = workspace.commit(stale).expect_err("stale candidate");
    assert!(matches!(
        error,
        mneme_store::Failure::InvalidCandidate { .. }
    ));
    assert_eq!(
        workspace.snapshot().expect("snapshot").revision,
        snapshot.revision
    );
    assert_eq!(
        mneme_store::payload::read_working_file(temp.path(), "project.adoc").expect("read"),
        Some(b"newer external bytes".to_vec())
    );
}

#[test]
fn conflicting_source_binding_is_rejected_before_commit() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    workspace
        .commit(mneme_store::CommitCommand {
            base: genesis,
            actor: "author".to_owned(),
            scope: scope(),
            idempotency_key: "base".to_owned(),
            records: vec![
                draft(&mneme_core::fixtures::entity()),
                draft(&mneme_core::fixtures::source_revision()),
            ],
            source_blobs: vec![mneme_store::SourceBlobDraft {
                bytes: mneme_core::fixtures::SOURCE_TEXT.as_bytes().to_vec(),
                media_type: mneme_core::Symbol::from("text/asciidoc"),
            }],
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("base commit");

    let mut entity_payload = mneme_core::fixtures::entity().payload;
    entity_payload.insert(
        mneme_core::Symbol::from("label"),
        mneme_core::Value::string("Other entity"),
    );
    let other_entity = mneme_store::RecordDraft {
        schema_version: 1,
        kind: mneme_core::RecordKind::Entity,
        record_id: mneme_core::RecordId::from_bytes([0x31; 16]),
        revision_id: mneme_core::RevisionId::from_bytes([0x32; 16]),
        predecessor: None,
        scope: scope(),
        payload: entity_payload,
    };
    let rebind = source_draft(SourceDraftInput {
        bytes: mneme_core::fixtures::SOURCE_TEXT.as_bytes(),
        record_id: mneme_core::RecordId::from_bytes([0x33; 16]),
        revision_id: mneme_core::RevisionId::from_bytes([0x34; 16]),
        predecessor: None,
        entity: other_entity.record_id,
        path: "project.adoc",
    });
    let error = workspace
        .commit(mneme_store::CommitCommand {
            base: workspace.current_revision().expect("current"),
            actor: "author".to_owned(),
            scope: scope(),
            idempotency_key: "rebind".to_owned(),
            records: vec![other_entity, rebind],
            source_blobs: vec![mneme_store::SourceBlobDraft {
                bytes: mneme_core::fixtures::SOURCE_TEXT.as_bytes().to_vec(),
                media_type: mneme_core::Symbol::from("text/asciidoc"),
            }],
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect_err("binding conflict");
    assert!(matches!(error, mneme_store::Failure::BindingConflict(_)));
}

#[test]
fn missing_or_corrupt_record_blob_is_an_explicit_integrity_failure() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    workspace
        .commit(fixture_command(genesis, "commit"))
        .expect("commit");
    let snapshot = workspace.snapshot().expect("snapshot");
    let assertion = snapshot
        .records
        .iter()
        .find(|record| record.record_id == mneme_core::fixtures::assertion_id())
        .expect("assertion");
    let digest = assertion.full_digest();
    let path = mneme_store::payload::blob_path(temp.path(), digest);
    std::fs::remove_file(&path).expect("remove blob");
    // Even a handle that verified the envelope before must report the missing
    // committed bytes: a cache hit is only valid while the blob is still there.
    let error = workspace.snapshot().expect_err("integrity");
    assert!(matches!(error, mneme_store::Failure::Integrity { .. }));
    let mut reopened = open(temp.path(), 2_000);
    assert!(matches!(
        reopened.snapshot().expect_err("integrity"),
        mneme_store::Failure::Integrity { .. }
    ));
    assert!(
        reopened.recover().is_err(),
        "recovery reports integrity failure"
    );
}

#[test]
fn fault_before_commit_leaves_the_previous_revision_and_recovery_cleans_orphans() {
    for point in [
        mneme_store::FaultPoint::AfterBlobStaging,
        mneme_store::FaultPoint::BeforeCommitTransaction,
    ] {
        let temp = tempfile::tempdir().expect("temp");
        let mut workspace = mneme_store::Workspace::create(
            temp.path(),
            config_with_faults(1_000, Box::new(mneme_store::FaultAt(point))),
        )
        .expect("create");
        let genesis = workspace.current_revision().expect("genesis");
        let error = workspace
            .commit(fixture_command(genesis, "fault"))
            .expect_err("injected");
        assert!(matches!(error, mneme_store::Failure::InjectedFault(p) if p == point));
        assert_eq!(workspace.current_revision().expect("current"), genesis);
        assert_eq!(workspace.status().expect("status").record_count, 0);
        drop(workspace);

        let mut reopened = open(temp.path(), 2_000);
        let report = reopened.recover().expect("recovery");
        assert!(
            report.staged_files_removed + report.orphan_blobs_removed > 0,
            "orphans should be cleaned: {report:?}"
        );
        let genesis = reopened.current_revision().expect("genesis");
        reopened
            .commit(fixture_command(genesis, "after-recovery"))
            .expect("commit after recovery");
    }
}

#[test]
fn fault_after_commit_leaves_a_pending_publication_for_recovery() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(
        temp.path(),
        config_with_faults(
            1_000,
            Box::new(mneme_store::FaultAt(mneme_store::FaultPoint::AfterCommit)),
        ),
    )
    .expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    let command = mneme_store::CommitCommand {
        base: genesis,
        actor: "author".to_owned(),
        scope: scope(),
        idempotency_key: "publish".to_owned(),
        records: vec![
            draft(&mneme_core::fixtures::entity()),
            draft(&mneme_core::fixtures::source_revision()),
        ],
        source_blobs: vec![mneme_store::SourceBlobDraft {
            bytes: mneme_core::fixtures::SOURCE_TEXT.as_bytes().to_vec(),
            media_type: mneme_core::Symbol::from("text/asciidoc"),
        }],
        publications: vec![mneme_store::PublicationDraft {
            path: "project.adoc".to_owned(),
            expected_previous: None,
            bytes: mneme_core::fixtures::SOURCE_TEXT.as_bytes().to_vec(),
        }],
        import_candidates: Vec::new(),
        retention: None,
    };
    let error = workspace.commit(command).expect_err("crash after commit");
    assert!(matches!(
        error,
        mneme_store::Failure::InjectedFault(mneme_store::FaultPoint::AfterCommit)
    ));
    let status = workspace.status().expect("status");
    assert_eq!(status.sequence, 1, "commit is visible before publication");
    assert_eq!(status.pending_publications, 1);
    assert!(
        mneme_store::payload::read_working_file(temp.path(), "project.adoc")
            .expect("working")
            .is_none()
    );
    drop(workspace);

    let mut reopened = open(temp.path(), 2_000);
    let report = reopened.recover().expect("recovery");
    assert_eq!(report.publications.len(), 1);
    assert_eq!(
        report.publications[0].state,
        mneme_store::PublicationState::Published
    );
    assert_eq!(
        mneme_store::payload::read_working_file(temp.path(), "project.adoc").expect("read"),
        Some(mneme_core::fixtures::SOURCE_TEXT.as_bytes().to_vec())
    );
    assert_eq!(reopened.status().expect("status").pending_publications, 0);
}

#[test]
fn external_edit_during_pending_publication_is_preserved_and_reported() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    let first = mneme_store::CommitCommand {
        base: genesis,
        actor: "author".to_owned(),
        scope: scope(),
        idempotency_key: "publish-one".to_owned(),
        records: vec![draft(&mneme_core::fixtures::entity())],
        source_blobs: Vec::new(),
        publications: vec![mneme_store::PublicationDraft {
            path: "notes.adoc".to_owned(),
            expected_previous: None,
            bytes: b"version one".to_vec(),
        }],
        import_candidates: Vec::new(),
        retention: None,
    };
    let outcome = workspace.commit(first).expect("first publication");
    assert_eq!(
        outcome.publications[0].state,
        mneme_store::PublicationState::Published
    );
    assert_eq!(
        mneme_store::payload::read_working_file(temp.path(), "notes.adoc").expect("read"),
        Some(b"version one".to_vec())
    );

    mneme_store::payload::publish_working_file(temp.path(), "notes.adoc", b"external edit")
        .expect("external edit");
    let second = mneme_store::CommitCommand {
        base: workspace.current_revision().expect("current"),
        actor: "author".to_owned(),
        scope: scope(),
        idempotency_key: "publish-two".to_owned(),
        records: Vec::new(),
        source_blobs: Vec::new(),
        publications: vec![mneme_store::PublicationDraft {
            path: "notes.adoc".to_owned(),
            expected_previous: Some(mneme_core::ContentDigest::of_source_bytes(b"version one")),
            bytes: b"version two".to_vec(),
        }],
        import_candidates: Vec::new(),
        retention: None,
    };
    let outcome = workspace.commit(second).expect("second publication");
    assert_eq!(
        outcome.publications[0].state,
        mneme_store::PublicationState::Diverged
    );
    assert_eq!(
        mneme_store::payload::read_working_file(temp.path(), "notes.adoc").expect("read"),
        Some(b"external edit".to_vec()),
        "the external edit is preserved"
    );
    // The committed desired payload remains available separately.
    let desired = mneme_core::ContentDigest::of_source_bytes(b"version two");
    assert_eq!(
        mneme_store::payload::read(temp.path(), desired).expect("committed payload"),
        b"version two"
    );
}

#[test]
fn metadata_only_update_preserves_exact_source_bytes() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    let source_bytes =
        b"= Synthetic\n\n// a comment\ninclude::other.adoc[]\n\n  noncanonical   spacing\n";
    let source = source_draft(SourceDraftInput {
        bytes: source_bytes,
        record_id: mneme_core::fixtures::source_revision_id(),
        revision_id: mneme_core::RevisionId::from_bytes([0x41; 16]),
        predecessor: None,
        entity: mneme_core::fixtures::entity_id(),
        path: "project.adoc",
    });
    workspace
        .commit(mneme_store::CommitCommand {
            base: genesis,
            actor: "author".to_owned(),
            scope: scope(),
            idempotency_key: "source".to_owned(),
            records: vec![draft(&mneme_core::fixtures::entity()), source],
            source_blobs: vec![mneme_store::SourceBlobDraft {
                bytes: source_bytes.to_vec(),
                media_type: mneme_core::Symbol::from("text/asciidoc"),
            }],
            publications: vec![mneme_store::PublicationDraft {
                path: "project.adoc".to_owned(),
                expected_previous: None,
                bytes: source_bytes.to_vec(),
            }],
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("source commit");
    let before = workspace.snapshot().expect("snapshot");
    let source_before = before
        .records
        .iter()
        .find(|record| record.record_id == mneme_core::fixtures::source_revision_id())
        .expect("source");
    mneme_store::payload::publish_working_file(
        temp.path(),
        "project.adoc",
        b"external edit after commit",
    )
    .expect("external edit");

    let mut payload = mneme_core::fixtures::entity().payload;
    payload.insert(
        mneme_core::Symbol::from("label"),
        mneme_core::Value::string("Renamed only"),
    );
    let update = mneme_store::RecordDraft {
        schema_version: 1,
        kind: mneme_core::RecordKind::Entity,
        record_id: mneme_core::fixtures::entity_id(),
        revision_id: mneme_core::RevisionId::from_bytes([0x42; 16]),
        predecessor: Some(mneme_core::fixtures::entity().revision_id),
        scope: scope(),
        payload,
    };
    workspace
        .commit(mneme_store::CommitCommand {
            base: workspace.current_revision().expect("current"),
            actor: "author".to_owned(),
            scope: scope(),
            idempotency_key: "metadata-only".to_owned(),
            records: vec![update],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("metadata update");
    let after = workspace.snapshot().expect("snapshot");
    let source_after = after
        .records
        .iter()
        .find(|record| record.record_id == mneme_core::fixtures::source_revision_id())
        .expect("source");
    assert_eq!(source_after.revision_id, source_before.revision_id);
    assert_eq!(source_after.full_digest(), source_before.full_digest());
    assert_eq!(
        mneme_store::payload::read_working_file(temp.path(), "project.adoc").expect("read"),
        Some(b"external edit after commit".to_vec()),
        "a metadata-only update neither rewrites prose nor overwrites an external edit"
    );
    assert_eq!(
        mneme_store::payload::read(
            temp.path(),
            mneme_core::ContentDigest::of_source_bytes(source_bytes)
        )
        .expect("blob"),
        source_bytes,
        "the committed source blob remains byte-identical"
    );
}

#[test]
fn barrier_advance_suppresses_publication_and_pinned_reads() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(
        temp.path(),
        config_with_faults(
            1_000,
            Box::new(mneme_store::FaultAt(mneme_store::FaultPoint::AfterCommit)),
        ),
    )
    .expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    let pending = mneme_store::CommitCommand {
        base: genesis,
        actor: "author".to_owned(),
        scope: scope(),
        idempotency_key: "pending".to_owned(),
        records: vec![draft(&mneme_core::fixtures::entity())],
        source_blobs: Vec::new(),
        publications: vec![mneme_store::PublicationDraft {
            path: "suppressed.adoc".to_owned(),
            expected_previous: None,
            bytes: b"should not appear".to_vec(),
        }],
        import_candidates: Vec::new(),
        retention: None,
    };
    workspace.commit(pending).expect_err("crash after commit");
    let pinned = workspace.snapshot().expect("pinned snapshot");
    let advanced = workspace.advance_eligibility_barrier().expect("barrier");
    assert_eq!(advanced, pinned.eligibility_generation + 1);
    assert!(matches!(
        workspace
            .snapshot_at(pinned.revision, Some(pinned.eligibility_generation))
            .expect_err("barrier"),
        mneme_store::Failure::BarrierAdvanced { .. }
    ));
    assert!(matches!(
        workspace.recheck(&pinned).expect_err("barrier"),
        mneme_store::Failure::BarrierAdvanced { .. }
    ));
    let outcomes = workspace.publish_pending().expect("publish");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].state, mneme_store::PublicationState::Suppressed);
    assert!(
        mneme_store::payload::read_working_file(temp.path(), "suppressed.adoc")
            .expect("working")
            .is_none()
    );
}

struct RaiseBarrier {
    root: std::path::PathBuf,
}

impl FaultInjector for RaiseBarrier {
    fn inject(&self, point: mneme_store::FaultPoint) -> bool {
        if point == mneme_store::FaultPoint::BeforeCommitTransaction {
            let mut other = mneme_store::Workspace::open(
                &self.root,
                mneme_store::WorkspaceConfig {
                    clock: Box::new(mneme_store::SystemClock),
                    faults: Box::new(mneme_store::NoFaults),
                },
            )
            .expect("second handle");
            other.advance_eligibility_barrier().expect("barrier");
        }
        false
    }
}

#[test]
fn commit_rechecks_the_generation_before_committing() {
    let temp = tempfile::tempdir().expect("temp");
    let root = temp.path().to_path_buf();
    let mut workspace = mneme_store::Workspace::create(
        &root,
        config_with_faults(1_000, Box::new(RaiseBarrier { root: root.clone() })),
    )
    .expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    let error = workspace
        .commit(fixture_command(genesis, "background-commit"))
        .expect_err("barrier wins");
    assert!(matches!(
        error,
        mneme_store::Failure::BarrierAdvanced { .. }
    ));
    assert_eq!(workspace.current_revision().expect("current"), genesis);
    drop(workspace);
    let mut reopened = open(&root, 2_000);
    let report = reopened.recover().expect("recovery");
    assert!(report.staged_files_removed + report.orphan_blobs_removed > 0);
}

#[test]
fn invalid_commands_are_refused_without_mutation() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");

    let mut wrong_scope = fixture_command(genesis, "scope");
    wrong_scope.records[0].scope =
        mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "other").expect("scope");
    assert!(matches!(
        workspace.commit(wrong_scope).expect_err("scope"),
        mneme_store::Failure::ScopeMismatch { .. }
    ));

    let mut duplicate_publications = fixture_command(genesis, "paths");
    duplicate_publications.publications = vec![
        mneme_store::PublicationDraft {
            path: "same.adoc".to_owned(),
            expected_previous: None,
            bytes: b"a".to_vec(),
        },
        mneme_store::PublicationDraft {
            path: "same.adoc".to_owned(),
            expected_previous: None,
            bytes: b"b".to_vec(),
        },
    ];
    assert!(matches!(
        workspace.commit(duplicate_publications).expect_err("paths"),
        mneme_store::Failure::InvalidCommand(_)
    ));

    let mut unreferenced_source = fixture_command(genesis, "source");
    unreferenced_source
        .source_blobs
        .push(mneme_store::SourceBlobDraft {
            bytes: b"unused".to_vec(),
            media_type: mneme_core::Symbol::from("text/plain"),
        });
    assert!(matches!(
        workspace
            .commit(unreferenced_source)
            .expect_err("unused source"),
        mneme_store::Failure::InvalidCommand(_)
    ));
    assert_eq!(workspace.current_revision().expect("current"), genesis);
}

#[test]
fn lost_commit_response_retries_to_the_same_revision_after_restart() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(
        temp.path(),
        config_with_faults(
            1_000,
            Box::new(mneme_store::FaultAt(mneme_store::FaultPoint::AfterCommit)),
        ),
    )
    .expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    let command = mneme_store::CommitCommand {
        base: genesis,
        actor: "author".to_owned(),
        scope: scope(),
        idempotency_key: "lost-response".to_owned(),
        records: vec![draft(&mneme_core::fixtures::entity())],
        source_blobs: Vec::new(),
        publications: vec![mneme_store::PublicationDraft {
            path: "recovered.adoc".to_owned(),
            expected_previous: None,
            bytes: b"published after retry".to_vec(),
        }],
        import_candidates: Vec::new(),
        retention: None,
    };
    workspace.commit(command.clone()).expect_err("crash");
    let committed = workspace.current_revision().expect("committed");
    drop(workspace);

    let mut reopened = open(temp.path(), 2_000);
    let retry = reopened.commit(command).expect("retry");
    assert_eq!(retry.revision, committed);
    assert_eq!(retry.sequence, 1);
    assert_eq!(reopened.status().expect("status").sequence, 1);
    assert_eq!(retry.publications.len(), 1);
    assert_eq!(
        retry.publications[0].state,
        mneme_store::PublicationState::Pending
    );
    let report = reopened.recover().expect("recovery");
    assert_eq!(
        report.publications[0].state,
        mneme_store::PublicationState::Published
    );
    assert_eq!(
        mneme_store::payload::read_working_file(temp.path(), "recovered.adoc").expect("read"),
        Some(b"published after retry".to_vec())
    );
}

#[test]
fn historical_snapshot_is_pinned_while_a_new_revision_commits() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    workspace
        .commit(fixture_command(genesis, "first"))
        .expect("first");
    let pinned = workspace.snapshot().expect("pinned");

    let mut payload = mneme_core::fixtures::entity().payload;
    payload.insert(
        mneme_core::Symbol::from("label"),
        mneme_core::Value::string("Second"),
    );
    workspace
        .commit(mneme_store::CommitCommand {
            base: workspace.current_revision().expect("current"),
            actor: "author".to_owned(),
            scope: scope(),
            idempotency_key: "second".to_owned(),
            records: vec![mneme_store::RecordDraft {
                schema_version: 1,
                kind: mneme_core::RecordKind::Entity,
                record_id: mneme_core::fixtures::entity_id(),
                revision_id: mneme_core::RevisionId::from_bytes([0x51; 16]),
                predecessor: Some(mneme_core::fixtures::entity().revision_id),
                scope: scope(),
                payload,
            }],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("second");
    let current = workspace.snapshot().expect("current");
    assert_ne!(current.revision, pinned.revision);
    let reread = workspace
        .snapshot_at(pinned.revision, Some(pinned.eligibility_generation))
        .expect("historical read");
    assert_eq!(reread.records, pinned.records);
    assert_eq!(reread.manifest_digest, pinned.manifest_digest);
    assert_eq!(
        reread.sequence, pinned.sequence,
        "a historical read cannot mix in the newer revision"
    );
}

#[test]
fn fault_after_file_replace_recovers_without_rewriting() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(
        temp.path(),
        config_with_faults(
            1_000,
            Box::new(mneme_store::FaultAt(
                mneme_store::FaultPoint::AfterFileReplace,
            )),
        ),
    )
    .expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    let error = workspace
        .commit(mneme_store::CommitCommand {
            base: genesis,
            actor: "author".to_owned(),
            scope: scope(),
            idempotency_key: "replace-fault".to_owned(),
            records: vec![draft(&mneme_core::fixtures::entity())],
            source_blobs: Vec::new(),
            publications: vec![mneme_store::PublicationDraft {
                path: "after-replace.adoc".to_owned(),
                expected_previous: None,
                bytes: b"already there".to_vec(),
            }],
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect_err("crash after replacement");
    assert!(matches!(
        error,
        mneme_store::Failure::InjectedFault(mneme_store::FaultPoint::AfterFileReplace)
    ));
    assert_eq!(
        mneme_store::payload::read_working_file(temp.path(), "after-replace.adoc").expect("read"),
        Some(b"already there".to_vec())
    );
    assert_eq!(workspace.status().expect("status").pending_publications, 1);
    drop(workspace);

    let mut reopened = open(temp.path(), 2_000);
    let report = reopened.recover().expect("recovery");
    assert_eq!(
        report.publications[0].state,
        mneme_store::PublicationState::Published
    );
    assert_eq!(
        mneme_store::payload::read_working_file(temp.path(), "after-replace.adoc").expect("read"),
        Some(b"already there".to_vec())
    );
}

#[test]
fn corrupt_blob_content_is_an_explicit_integrity_failure() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    workspace
        .commit(fixture_command(genesis, "commit"))
        .expect("commit");
    let snapshot = workspace.snapshot().expect("snapshot");
    let assertion = snapshot
        .records
        .iter()
        .find(|record| record.record_id == mneme_core::fixtures::assertion_id())
        .expect("assertion");
    let path = mneme_store::payload::blob_path(temp.path(), assertion.full_digest());
    let length =
        usize::try_from(std::fs::metadata(&path).expect("metadata").len()).expect("file length");
    std::fs::write(&path, vec![0x5a_u8; length]).expect("tamper");
    // The cache validates a hit by length, modification time, device and inode,
    // so make the rewrite observable without relying on the clock: the tampered
    // file must not masquerade as the one this handle verified.
    let tampered = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("tampered blob");
    tampered
        .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(60))
        .expect("modification time");
    drop(tampered);
    // The rewrite has a different identity, so the handle reads it again and the
    // committed digest check fails closed.
    assert!(matches!(
        workspace.snapshot().expect_err("corrupt"),
        mneme_store::Failure::Integrity { .. }
    ));
    assert!(matches!(
        open(temp.path(), 2_500).snapshot().expect_err("corrupt"),
        mneme_store::Failure::Integrity { .. }
    ));
}

#[test]
fn declared_source_length_mismatch_is_rejected() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    let bytes = b"abc";
    let retained = mneme_core::RetainedSource::new(
        mneme_core::ContentDigest::of_source_bytes(bytes),
        4,
        "text/plain",
    )
    .expect("retained");
    let source = mneme_store::RecordDraft {
        schema_version: 1,
        kind: mneme_core::RecordKind::SourceRevision,
        record_id: mneme_core::fixtures::source_revision_id(),
        revision_id: mneme_core::RevisionId::from_bytes([0x61; 16]),
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
                mneme_core::Symbol::from("entity"),
                mneme_core::Reference::local(
                    mneme_core::fixtures::entity_id(),
                    mneme_core::RecordKind::Entity,
                )
                .to_value(),
            ),
        ]),
    };
    let error = workspace
        .commit(mneme_store::CommitCommand {
            base: genesis,
            actor: "author".to_owned(),
            scope: scope(),
            idempotency_key: "length".to_owned(),
            records: vec![draft(&mneme_core::fixtures::entity()), source],
            source_blobs: vec![mneme_store::SourceBlobDraft {
                bytes: bytes.to_vec(),
                media_type: mneme_core::Symbol::from("text/plain"),
            }],
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect_err("length mismatch");
    assert!(matches!(
        error,
        mneme_store::Failure::SourceLengthMismatch { .. }
    ));
    assert_eq!(workspace.current_revision().expect("current"), genesis);
}

#[test]
fn publication_path_escape_is_rejected() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    let error = workspace
        .commit(mneme_store::CommitCommand {
            base: genesis,
            actor: "author".to_owned(),
            scope: scope(),
            idempotency_key: "escape".to_owned(),
            records: Vec::new(),
            source_blobs: Vec::new(),
            publications: vec![mneme_store::PublicationDraft {
                path: "../escape.adoc".to_owned(),
                expected_previous: None,
                bytes: b"nope".to_vec(),
            }],
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect_err("escape");
    assert!(matches!(error, mneme_store::Failure::PathEscapes(_)));
    assert!(
        mneme_store::payload::read_working_file(temp.path(), "escape.adoc")
            .expect("working")
            .is_none()
    );
}

#[test]
fn create_and_open_refuse_an_unsupported_layout() {
    let temp = tempfile::tempdir().expect("temp");
    std::fs::write(temp.path().join("existing"), b"x").expect("nonempty");
    assert!(matches!(
        mneme_store::Workspace::create(temp.path(), config(1_000)).expect_err("nonempty"),
        mneme_store::Failure::UnsupportedLayout(_)
    ));
    let empty = tempfile::tempdir().expect("empty");
    assert!(matches!(
        mneme_store::Workspace::open(empty.path(), config(1_000)).expect_err("no ledger"),
        mneme_store::Failure::UnsupportedLayout(_)
    ));
}

#[test]
fn projections_are_revision_scope_and_generation_fenced() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    workspace
        .commit(fixture_command(genesis, "first"))
        .expect("first");
    let first = workspace.snapshot().expect("snapshot");
    workspace
        .register_retention_participant(mneme_store::RetentionParticipant {
            name: "lexical".to_owned(),
            storage_role: "lexical-index".to_owned(),
            supports_invalidation: true,
            supports_purge: true,
            checks_generation: true,
            inventory_locator: "index/lexical".to_owned(),
        })
        .expect("participant");
    let projection = workspace
        .register_projection(mneme_store::ProjectionRegistration {
            name: "lexical".to_owned(),
            revision: first.revision,
            eligibility_generation: first.eligibility_generation,
            schema_version: 1,
            rule_version: "none".to_owned(),
            index_version: "v1".to_owned(),
            scope: scope().to_string(),
        })
        .expect("register");
    assert_eq!(projection.revision, first.revision);
    assert!(matches!(
        workspace
            .resolve_projection("lexical", first.revision, &scope())
            .expect("resolve"),
        mneme_store::ProjectionResolution::Compatible(_)
    ));
    assert!(matches!(
        workspace
            .resolve_projection("missing", first.revision, &scope())
            .expect("resolve"),
        mneme_store::ProjectionResolution::Missing
    ));
    let other_scope =
        mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "other").expect("scope");
    assert!(matches!(
        workspace
            .resolve_projection("lexical", first.revision, &other_scope)
            .expect("resolve"),
        mneme_store::ProjectionResolution::ScopeMismatch { .. }
    ));

    let mut payload = mneme_core::fixtures::entity().payload;
    payload.insert(
        mneme_core::Symbol::from("label"),
        mneme_core::Value::string("Second"),
    );
    workspace
        .commit(mneme_store::CommitCommand {
            base: workspace.current_revision().expect("current"),
            actor: "author".to_owned(),
            scope: scope(),
            idempotency_key: "second".to_owned(),
            records: vec![mneme_store::RecordDraft {
                schema_version: 1,
                kind: mneme_core::RecordKind::Entity,
                record_id: mneme_core::fixtures::entity_id(),
                revision_id: mneme_core::RevisionId::from_bytes([0x71; 16]),
                predecessor: Some(mneme_core::fixtures::entity().revision_id),
                scope: scope(),
                payload,
            }],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("second");
    let second = workspace.snapshot().expect("second snapshot");
    assert!(matches!(
        workspace
            .resolve_projection("lexical", second.revision, &scope())
            .expect("resolve"),
        mneme_store::ProjectionResolution::Behind { .. }
    ));
    assert!(matches!(
        workspace
            .resolve_projection("lexical", first.revision, &scope())
            .expect("resolve"),
        mneme_store::ProjectionResolution::Compatible(_)
    ));

    workspace.advance_eligibility_barrier().expect("barrier");
    assert!(matches!(
        workspace
            .resolve_projection("lexical", first.revision, &scope())
            .expect("resolve"),
        mneme_store::ProjectionResolution::BarrierAdvanced { .. }
    ));
    // Record reads do not depend on any projection existing.
    assert_eq!(workspace.snapshot().expect("snapshot").records.len(), 5);
    workspace
        .register_retention_participant(mneme_store::RetentionParticipant {
            name: "orphan".to_owned(),
            storage_role: "test-index".to_owned(),
            supports_invalidation: true,
            supports_purge: true,
            checks_generation: true,
            inventory_locator: "index/orphan".to_owned(),
        })
        .expect("orphan participant");
    let generation = workspace.eligibility_generation().expect("generation");
    assert!(
        workspace
            .register_projection(mneme_store::ProjectionRegistration {
                name: "orphan".to_owned(),
                revision: mneme_core::WorkspaceRevisionId::from_bytes([0x7f; 16]),
                eligibility_generation: generation,
                schema_version: 1,
                rule_version: "none".to_owned(),
                index_version: "v1".to_owned(),
                scope: scope().to_string(),
            })
            .is_err()
    );
}

#[test]
fn fault_before_file_replace_leaves_the_intent_pending_and_no_file() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(
        temp.path(),
        config_with_faults(
            1_000,
            Box::new(mneme_store::FaultAt(
                mneme_store::FaultPoint::BeforeFileReplace,
            )),
        ),
    )
    .expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    let error = workspace
        .commit(mneme_store::CommitCommand {
            base: genesis,
            actor: "author".to_owned(),
            scope: scope(),
            idempotency_key: "before-replace".to_owned(),
            records: vec![draft(&mneme_core::fixtures::entity())],
            source_blobs: Vec::new(),
            publications: vec![mneme_store::PublicationDraft {
                path: "not-written.adoc".to_owned(),
                expected_previous: None,
                bytes: b"pending".to_vec(),
            }],
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect_err("crash before replacement");
    assert!(matches!(
        error,
        mneme_store::Failure::InjectedFault(mneme_store::FaultPoint::BeforeFileReplace)
    ));
    assert!(
        mneme_store::payload::read_working_file(temp.path(), "not-written.adoc")
            .expect("working")
            .is_none()
    );
    assert_eq!(workspace.status().expect("status").pending_publications, 1);
    drop(workspace);
    let mut reopened = open(temp.path(), 2_000);
    let report = reopened.recover().expect("recovery");
    assert_eq!(
        report.publications[0].state,
        mneme_store::PublicationState::Published
    );
    assert_eq!(
        mneme_store::payload::read_working_file(temp.path(), "not-written.adoc").expect("read"),
        Some(b"pending".to_vec())
    );
}

#[test]
fn malformed_import_candidate_is_refused_and_keeps_the_prior_snapshot() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    workspace
        .commit(mneme_store::CommitCommand {
            base: genesis,
            actor: "author".to_owned(),
            scope: scope(),
            idempotency_key: "base".to_owned(),
            records: vec![draft(&mneme_core::fixtures::entity())],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("base commit");
    let before = workspace.snapshot().expect("snapshot");
    let candidate_bytes = b"candidate bytes";
    mneme_store::payload::publish_working_file(temp.path(), "project.adoc", candidate_bytes)
        .expect("file");
    // The record claims a retained source whose bytes do not match the file.
    let wrong = source_draft(SourceDraftInput {
        bytes: b"different bytes",
        record_id: mneme_core::fixtures::source_revision_id(),
        revision_id: mneme_core::RevisionId::from_bytes([0x81; 16]),
        predecessor: None,
        entity: mneme_core::fixtures::entity_id(),
        path: "project.adoc",
    });
    let error = workspace
        .commit(mneme_store::CommitCommand {
            base: workspace.current_revision().expect("current"),
            actor: "author".to_owned(),
            scope: scope(),
            idempotency_key: "malformed".to_owned(),
            records: vec![wrong],
            // The record supplies its own bytes so the candidate, not the
            // digest-claim rule, is what the command is refused for.
            source_blobs: vec![mneme_store::SourceBlobDraft {
                bytes: b"different bytes".to_vec(),
                media_type: mneme_core::Symbol::from("text/asciidoc"),
            }],
            publications: Vec::new(),
            import_candidates: vec![mneme_store::ImportCandidateDraft {
                path: "project.adoc".to_owned(),
                bytes: candidate_bytes.to_vec(),
            }],
            retention: None,
        })
        .expect_err("malformed candidate");
    assert!(matches!(
        error,
        mneme_store::Failure::InvalidCandidate { .. }
    ));
    assert_eq!(
        workspace.snapshot().expect("snapshot").revision,
        before.revision
    );
    assert_eq!(
        mneme_store::payload::read_working_file(temp.path(), "project.adoc").expect("read"),
        Some(candidate_bytes.to_vec())
    );
}

fn project_scope(local: &str) -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, local).expect("scope")
}

#[test]
fn forgotten_content_is_refused_in_the_forgetting_scope_only() {
    const SECRET: &[u8] = b"= Secret plan\n\nThe launch code is 4242.\n";
    let secret_digest = mneme_core::ContentDigest::of_source_bytes(SECRET);
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let cedar = scope();
    let birch = project_scope("birch");
    let secret = mneme_core::RecordId::from_bytes([0x81; 16]);
    workspace
        .commit(record_command(
            workspace.current_revision().expect("genesis"),
            &cedar,
            "seed",
            vec![retained_source_record(
                secret,
                mneme_core::RevisionId::from_bytes([0x82; 16]),
                &cedar,
                SECRET,
                Some("secret.adoc"),
            )],
            vec![source_blob(SECRET)],
            Vec::new(),
        ))
        .expect("seed source");
    let generation = workspace.eligibility_generation().expect("generation");
    workspace
        .commit(mneme_store::CommitCommand {
            base: workspace.current_revision().expect("base"),
            actor: "test-author".to_owned(),
            scope: cedar.clone(),
            idempotency_key: "forget".to_owned(),
            records: Vec::new(),
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: Some(forget_content_barrier(
                secret,
                SECRET,
                generation.saturating_add(1),
                "forget-secret",
            )),
        })
        .expect("forget barrier");
    assert!(
        workspace.snapshot().expect("snapshot").records.is_empty(),
        "the forgotten record leaves every view"
    );

    let denied = |error: mneme_store::Failure| {
        assert!(
            matches!(&error, mneme_store::Failure::RetentionSuppressed { .. }),
            "expected a suppression refusal, got {error:?}"
        );
        assert!(
            !error.to_string().contains(&secret_digest.to_hex()),
            "a refusal must not repeat the forgotten digest"
        );
    };

    // The forgotten bytes arrive as a publication.
    let error = workspace
        .commit(publication_command(
            workspace.current_revision().expect("base"),
            &cedar,
            "leak",
            "leak.adoc",
            SECRET,
        ))
        .expect_err("publication replays forgotten bytes");
    denied(error);
    assert!(
        mneme_store::payload::read_working_file(temp.path(), "leak.adoc")
            .expect("read")
            .is_none(),
        "a refused publication writes no file"
    );

    // The forgotten bytes arrive as an import candidate.
    let error = workspace
        .commit(record_command(
            workspace.current_revision().expect("base"),
            &cedar,
            "candidate",
            vec![retained_source_record(
                mneme_core::RecordId::from_bytes([0x83; 16]),
                mneme_core::RevisionId::from_bytes([0x84; 16]),
                &cedar,
                SECRET,
                Some("again.adoc"),
            )],
            Vec::new(),
            vec![mneme_store::ImportCandidateDraft {
                path: "again.adoc".to_owned(),
                bytes: SECRET.to_vec(),
            }],
        ))
        .expect_err("import candidate replays forgotten bytes");
    denied(error);

    // The forgotten digest is named with no bytes at all.
    let error = workspace
        .commit(record_command(
            workspace.current_revision().expect("base"),
            &cedar,
            "digest",
            vec![retained_source_record(
                mneme_core::RecordId::from_bytes([0x85; 16]),
                mneme_core::RevisionId::from_bytes([0x86; 16]),
                &cedar,
                SECRET,
                None,
            )],
            Vec::new(),
            Vec::new(),
        ))
        .expect_err("digest reference replays forgotten content");
    denied(error);

    // Another scope holding the same bytes is neither refused nor told that
    // the content was forgotten elsewhere.
    let outcome = workspace
        .commit(publication_command(
            workspace.current_revision().expect("base"),
            &birch,
            "birch-publish",
            "birch/secret.adoc",
            SECRET,
        ))
        .expect("another scope keeps the same bytes");
    assert_eq!(
        outcome.publications[0].state,
        mneme_store::PublicationState::Published
    );
    assert_eq!(
        mneme_store::payload::read_working_file(temp.path(), "birch/secret.adoc").expect("read"),
        Some(SECRET.to_vec())
    );
    workspace
        .commit(record_command(
            workspace.current_revision().expect("base"),
            &birch,
            "birch-retain",
            vec![retained_source_record(
                mneme_core::RecordId::from_bytes([0x87; 16]),
                mneme_core::RevisionId::from_bytes([0x88; 16]),
                &birch,
                SECRET,
                Some("birch/secret.adoc"),
            )],
            vec![source_blob(SECRET)],
            Vec::new(),
        ))
        .expect("another scope retains the same bytes");
    workspace
        .commit(record_command(
            workspace.current_revision().expect("base"),
            &birch,
            "birch-adopt",
            vec![retained_source_record(
                mneme_core::RecordId::from_bytes([0x89; 16]),
                mneme_core::RevisionId::from_bytes([0x8a; 16]),
                &birch,
                SECRET,
                None,
            )],
            Vec::new(),
            Vec::new(),
        ))
        .expect("a scope may adopt a digest its own records already bind");
}

#[test]
fn aliased_working_paths_are_refused() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    let aliases = [
        "notes//doc.adoc",
        "notes/./doc.adoc",
        "/notes/doc.adoc",
        "notes/doc.adoc/",
        "notes\\doc.adoc",
    ];
    for (index, path) in aliases.iter().copied().enumerate() {
        let key = format!("alias-{index}");
        assert!(
            matches!(
                workspace
                    .commit(publication_command(genesis, &scope(), &key, path, b"bytes"))
                    .expect_err("aliased publication path"),
                mneme_store::Failure::PathEscapes(_)
            ),
            "publication path {path:?} must be refused"
        );
        assert!(
            matches!(
                workspace
                    .commit(record_command(
                        genesis,
                        &scope(),
                        &key,
                        Vec::new(),
                        Vec::new(),
                        vec![mneme_store::ImportCandidateDraft {
                            path: path.to_owned(),
                            bytes: b"bytes".to_vec(),
                        }],
                    ))
                    .expect_err("aliased candidate path"),
                mneme_store::Failure::PathEscapes(_)
            ),
            "import candidate path {path:?} must be refused"
        );
        assert!(
            matches!(
                workspace
                    .commit(record_command(
                        genesis,
                        &scope(),
                        &key,
                        vec![retained_source_record(
                            mneme_core::RecordId::from_bytes([0x91; 16]),
                            mneme_core::RevisionId::from_bytes([0x92; 16]),
                            &scope(),
                            b"bytes",
                            Some(path),
                        )],
                        vec![source_blob(b"bytes")],
                        Vec::new(),
                    ))
                    .expect_err("aliased binding path"),
                mneme_store::Failure::PathEscapes(_)
            ),
            "source binding path {path:?} must be refused"
        );
    }
    assert_eq!(
        workspace.current_revision().expect("current"),
        genesis,
        "no aliased path reached commit staging"
    );
    assert!(
        std::fs::read_dir(temp.path().join("working"))
            .expect("working")
            .next()
            .is_none(),
        "no aliased path created a working file"
    );
}

#[test]
fn a_symlinked_working_directory_is_refused_before_creating_directories() {
    let temp = tempfile::tempdir().expect("temp");
    let root = temp.path().to_path_buf();
    let mut workspace = mneme_store::Workspace::create(&root, config(1_000)).expect("create");
    let outside = root.join("outside");
    std::fs::create_dir(&outside).expect("outside");
    std::os::unix::fs::symlink(&outside, root.join("working/link")).expect("symlink");

    let outcome = workspace
        .commit(publication_command(
            workspace.current_revision().expect("base"),
            &scope(),
            "symlink",
            "link/deep/er/file.adoc",
            b"x",
        ))
        .expect("commit");
    assert_eq!(
        outcome.publications[0].state,
        mneme_store::PublicationState::Failed
    );
    assert_eq!(
        std::fs::read_dir(&outside).expect("outside").count(),
        0,
        "a publication may not create directories outside the workspace"
    );
    assert!(matches!(
        mneme_store::payload::publish_working_file(&root, "link/other/file.adoc", b"x")
            .expect_err("symlinked parent"),
        mneme_store::Failure::PathEscapes(_)
    ));
    assert_eq!(
        std::fs::read_dir(&outside).expect("outside").count(),
        0,
        "a refused publication creates nothing below the link"
    );
}

#[test]
fn a_revision_cannot_move_a_record_into_another_scope() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    workspace
        .commit(fixture_command(genesis, "first"))
        .expect("first");
    let pinned = workspace.snapshot().expect("snapshot");
    let entity = mneme_core::fixtures::entity();
    let birch = project_scope("birch");

    let mut payload = entity.payload.clone();
    payload.insert(
        mneme_core::Symbol::from("label"),
        mneme_core::Value::string("Rehomed"),
    );
    let error = workspace
        .commit(record_command(
            workspace.current_revision().expect("base"),
            &birch,
            "rehome",
            vec![mneme_store::RecordDraft {
                schema_version: 1,
                kind: mneme_core::RecordKind::Entity,
                record_id: entity.record_id,
                revision_id: mneme_core::RevisionId::from_bytes([0x51; 16]),
                predecessor: Some(entity.revision_id),
                scope: birch.clone(),
                payload: payload.clone(),
            }],
            Vec::new(),
            Vec::new(),
        ))
        .expect_err("cross-scope revision");
    assert!(matches!(&error, mneme_store::Failure::InvalidCommand(_)));
    let rendered = error.to_string();
    assert!(!rendered.contains(&entity.record_id.to_string()));
    assert!(!rendered.contains(&entity.revision_id.to_string()));
    assert!(!rendered.contains("cedar"));
    assert!(!rendered.contains("birch"));
    assert_eq!(
        workspace.current_revision().expect("current"),
        pinned.revision
    );

    // The same revision in the record's own scope is accepted.
    workspace
        .commit(record_command(
            workspace.current_revision().expect("base"),
            &scope(),
            "same-scope",
            vec![mneme_store::RecordDraft {
                schema_version: 1,
                kind: mneme_core::RecordKind::Entity,
                record_id: entity.record_id,
                revision_id: mneme_core::RevisionId::from_bytes([0x52; 16]),
                predecessor: Some(entity.revision_id),
                scope: scope(),
                payload,
            }],
            Vec::new(),
            Vec::new(),
        ))
        .expect("a revision inside the record's scope");
}

#[test]
fn a_source_revision_cannot_adopt_another_scopes_blob_by_digest() {
    const PRIVATE: &[u8] = b"birch-only bytes\n";
    let digest = mneme_core::ContentDigest::of_source_bytes(PRIVATE);
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let birch = project_scope("birch");
    let oak = project_scope("oak");
    workspace
        .commit(record_command(
            workspace.current_revision().expect("genesis"),
            &birch,
            "birch-source",
            vec![retained_source_record(
                mneme_core::RecordId::from_bytes([0xa1; 16]),
                mneme_core::RevisionId::from_bytes([0xa2; 16]),
                &birch,
                PRIVATE,
                None,
            )],
            vec![source_blob(PRIVATE)],
            Vec::new(),
        ))
        .expect("birch source");

    let error = workspace
        .commit(record_command(
            workspace.current_revision().expect("base"),
            &oak,
            "oak-claim",
            vec![retained_source_record(
                mneme_core::RecordId::from_bytes([0xa3; 16]),
                mneme_core::RevisionId::from_bytes([0xa4; 16]),
                &oak,
                PRIVATE,
                None,
            )],
            Vec::new(),
            Vec::new(),
        ))
        .expect_err("digest adoption");
    assert!(matches!(&error, mneme_store::Failure::InvalidCommand(_)));
    assert!(
        !error.to_string().contains(&digest.to_hex()),
        "the refusal must not confirm another scope's digest"
    );
    assert!(
        workspace
            .snapshot()
            .expect("snapshot")
            .records
            .iter()
            .all(|record| record.record_id != mneme_core::RecordId::from_bytes([0xa3; 16])),
        "the refused claim committed nothing"
    );
}

#[test]
fn a_projection_built_before_a_barrier_is_never_compatible() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    workspace
        .commit(fixture_command(
            workspace.current_revision().expect("genesis"),
            "first",
        ))
        .expect("first");
    let built_from = workspace.snapshot().expect("builder pinned its read");
    workspace
        .register_retention_participant(mneme_store::RetentionParticipant {
            name: "lexical".to_owned(),
            storage_role: "lexical-index".to_owned(),
            supports_invalidation: true,
            supports_purge: true,
            checks_generation: true,
            inventory_locator: "index/lexical".to_owned(),
        })
        .expect("participant");
    workspace
        .advance_eligibility_barrier()
        .expect("the barrier lands while the projection is being built");
    let error = workspace
        .register_projection(mneme_store::ProjectionRegistration {
            name: "lexical".to_owned(),
            revision: built_from.revision,
            eligibility_generation: built_from.eligibility_generation,
            schema_version: 1,
            rule_version: "none".to_owned(),
            index_version: "v1".to_owned(),
            scope: scope().to_string(),
        })
        .expect_err("stale build");
    assert!(matches!(
        error,
        mneme_store::Failure::BarrierAdvanced { .. }
    ));
    assert!(
        workspace.projection("lexical").expect("read").is_none(),
        "a stale projection is not recorded"
    );

    let pinned = workspace.eligibility_generation().expect("generation");
    let state = workspace
        .register_projection(mneme_store::ProjectionRegistration {
            name: "lexical".to_owned(),
            revision: built_from.revision,
            eligibility_generation: pinned,
            schema_version: 1,
            rule_version: "none".to_owned(),
            index_version: "v1".to_owned(),
            scope: scope().to_string(),
        })
        .expect("a projection of the current generation");
    assert_eq!(state.eligibility_generation, pinned);
    assert!(matches!(
        workspace
            .resolve_projection("lexical", built_from.revision, &scope())
            .expect("resolve"),
        mneme_store::ProjectionResolution::Compatible(_)
    ));
    assert!(matches!(
        workspace
            .resolve_projection_versions("lexical", built_from.revision, &scope(), 1, "none", "v2")
            .expect("resolve"),
        mneme_store::ProjectionResolution::VersionMismatch { .. }
    ));
    workspace
        .advance_eligibility_barrier()
        .expect("a second barrier");
    assert!(matches!(
        workspace
            .resolve_projection("lexical", built_from.revision, &scope())
            .expect("resolve"),
        mneme_store::ProjectionResolution::BarrierAdvanced { .. }
    ));
}

#[test]
fn a_historical_snapshot_index_excludes_later_revisions() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    workspace
        .commit(fixture_command(
            workspace.current_revision().expect("genesis"),
            "first",
        ))
        .expect("first");
    let pinned = workspace.snapshot().expect("pinned");
    let later = mneme_core::RevisionId::from_bytes([0x51; 16]);
    let entity = mneme_core::fixtures::entity();
    let mut payload = entity.payload.clone();
    payload.insert(
        mneme_core::Symbol::from("label"),
        mneme_core::Value::string("Later"),
    );
    workspace
        .commit(record_command(
            workspace.current_revision().expect("base"),
            &scope(),
            "later",
            vec![mneme_store::RecordDraft {
                schema_version: 1,
                kind: mneme_core::RecordKind::Entity,
                record_id: entity.record_id,
                revision_id: later,
                predecessor: Some(entity.revision_id),
                scope: scope(),
                payload,
            }],
            Vec::new(),
            Vec::new(),
        ))
        .expect("later revision");
    let reread = workspace
        .snapshot_at(pinned.revision, Some(pinned.eligibility_generation))
        .expect("historical read");
    assert_eq!(reread.index, pinned.index);
    assert!(
        !reread.index.knows_revision(&entity.record_id, &later),
        "a historical snapshot cannot know a revision committed after it"
    );
    assert!(
        workspace
            .snapshot()
            .expect("current")
            .index
            .knows_revision(&entity.record_id, &later)
    );
}

struct SweepStagedBlobs {
    root: std::path::PathBuf,
    point: mneme_store::FaultPoint,
}

impl FaultInjector for SweepStagedBlobs {
    fn inject(&self, point: mneme_store::FaultPoint) -> bool {
        if point == self.point {
            assert!(
                remove_blob_files(&self.root) > 0,
                "the commit must have staged blobs when this point is reached"
            );
        }
        false
    }
}

/// Delete every blob file, the way an uncoordinated cleanup would.
fn remove_blob_files(root: &std::path::Path) -> usize {
    let shards = root
        .join(mneme_store::payload::BLOB_DIRECTORY)
        .join("sha256");
    if !shards.is_dir() {
        return 0;
    }
    let mut removed = 0_usize;
    for shard in std::fs::read_dir(&shards).expect("shard directories") {
        let shard = shard.expect("shard directory");
        if !shard.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
            continue;
        }
        for file in std::fs::read_dir(shard.path()).expect("shard files") {
            let file = file.expect("shard file");
            if file.file_type().map(|kind| kind.is_file()).unwrap_or(false) {
                std::fs::remove_file(file.path()).expect("remove blob");
                removed += 1;
            }
        }
    }
    removed
}

fn commit_with_out_of_band_sweep(point: mneme_store::FaultPoint) {
    let temp = tempfile::tempdir().expect("temp");
    let root = temp.path().join("workspace");
    let mut workspace = mneme_store::Workspace::create(
        &root,
        config_with_faults(
            1_000,
            Box::new(SweepStagedBlobs {
                root: root.clone(),
                point,
            }),
        ),
    )
    .expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    let outcome = workspace
        .commit(fixture_command(genesis, "in-flight"))
        .expect("a sweep outside the lock cannot fail or strand the commit");
    assert_eq!(outcome.sequence, 1);
    let fresh = open(&root, 3_000);
    let snapshot = fresh
        .snapshot()
        .expect("a committed revision stays readable after an out-of-band sweep");
    assert_eq!(snapshot.revision, outcome.revision);
    assert!(!snapshot.records.is_empty());
    assert_eq!(snapshot.sequence, 1);
}

#[test]
fn an_out_of_band_sweep_cannot_strand_a_committed_revision() {
    commit_with_out_of_band_sweep(mneme_store::FaultPoint::BeforeCommitTransaction);
}

#[test]
fn an_out_of_band_sweep_during_blob_staging_cannot_strand_a_commit() {
    commit_with_out_of_band_sweep(mneme_store::FaultPoint::AfterBlobStaging);
}

struct DuplicateElsewhere {
    root: std::path::PathBuf,
    command: mneme_store::CommitCommand,
}

impl FaultInjector for DuplicateElsewhere {
    fn inject(&self, point: mneme_store::FaultPoint) -> bool {
        if point == mneme_store::FaultPoint::BeforeCommitTransaction {
            let mut other =
                mneme_store::Workspace::open(&self.root, config(2_000)).expect("second handle");
            let outcome = other
                .commit(self.command.clone())
                .expect("identical commit elsewhere");
            assert_eq!(outcome.sequence, 1);
        }
        false
    }
}

#[test]
fn identical_retry_after_a_concurrent_commit_replays_instead_of_conflicting() {
    let temp = tempfile::tempdir().expect("temp");
    let root = temp.path().join("workspace");
    let probe = mneme_store::Workspace::create(&root, config(1_000)).expect("create");
    let genesis = probe.current_revision().expect("genesis");
    drop(probe);
    let command = fixture_command(genesis, "same-key");
    let mut workspace = mneme_store::Workspace::open(
        &root,
        config_with_faults(
            1_100,
            Box::new(DuplicateElsewhere {
                root: root.clone(),
                command: command.clone(),
            }),
        ),
    )
    .expect("open");
    let outcome = workspace
        .commit(command)
        .expect("a retry of the committed command returns its outcome, not StaleBase");
    assert_eq!(outcome.sequence, 1);
    assert_eq!(workspace.status().expect("status").sequence, 1);
}

#[test]
fn retry_of_a_committed_command_replays_after_the_workspace_advanced() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    let command = fixture_command(genesis, "plain");
    let first = workspace.commit(command.clone()).expect("first commit");
    let later = advance_with_entity_update(&mut workspace, "later", 0x42);
    assert_eq!(later.sequence, 2);
    let replayed = workspace
        .commit(command)
        .expect("the original command replays instead of reporting a stale base");
    assert_eq!(replayed.revision, first.revision);
    assert_eq!(replayed.sequence, 1);
    assert_eq!(workspace.status().expect("status").sequence, 2);
}

/// Advance the workspace with a new revision of the fixture entity.
fn advance_with_entity_update(
    workspace: &mut mneme_store::Workspace,
    key: &str,
    revision: u8,
) -> mneme_store::CommitOutcome {
    let base = workspace.current_revision().expect("base");
    let mut payload = mneme_core::fixtures::entity().payload;
    payload.insert(
        mneme_core::Symbol::from("label"),
        mneme_core::Value::string(format!("revision {revision}")),
    );
    let update = mneme_store::RecordDraft {
        schema_version: 1,
        kind: mneme_core::RecordKind::Entity,
        record_id: mneme_core::fixtures::entity_id(),
        revision_id: mneme_core::RevisionId::from_bytes([revision; 16]),
        predecessor: Some(mneme_core::fixtures::entity().revision_id),
        scope: scope(),
        payload,
    };
    workspace
        .commit(mneme_store::CommitCommand {
            base,
            actor: "test-author".to_owned(),
            scope: scope(),
            idempotency_key: key.to_owned(),
            records: vec![update],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("advance")
}

fn fingerprint(label: &str) -> mneme_core::ContentDigest {
    mneme_core::request_fingerprint(&mneme_core::Value::record_named(
        "fixture-request",
        vec![mneme_core::Value::string(label.to_owned())],
    ))
}

#[test]
fn a_bound_fingerprint_replays_a_rebuilt_command_without_another_commit() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let bound = fingerprint("plan.adoc");
    let genesis = workspace.current_revision().expect("genesis");
    let first = workspace
        .commit_bound(fixture_command(genesis, "bound"), bound)
        .expect("first commit");
    assert_eq!(first.sequence, 1);
    let advanced = advance_with_entity_update(&mut workspace, "other", 0x43);
    assert_eq!(advanced.sequence, 2);
    // The adapter rebuilt the same request on the new base, so the command
    // digest differs while the request fingerprint does not.
    let rebuilt = fixture_command(workspace.current_revision().expect("base"), "bound");
    let replayed = workspace
        .commit_bound(rebuilt, bound)
        .expect("the same request replays even though the base is stale");
    assert_eq!(replayed.revision, first.revision);
    assert_eq!(replayed.sequence, 1);
    assert_eq!(workspace.status().expect("status").sequence, 2);
    let changed = fingerprint("changed.adoc");
    let error = workspace
        .commit_bound(
            fixture_command(workspace.current_revision().expect("base"), "bound"),
            changed,
        )
        .expect_err("a different request under the same key conflicts");
    assert!(matches!(
        error,
        mneme_store::Failure::IdempotencyConflict { .. }
    ));
    assert_eq!(workspace.status().expect("status").sequence, 2);
}

#[test]
fn replay_outcome_reports_absence_replay_and_conflict() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let bound = fingerprint("first-request");
    assert!(
        workspace
            .replay_outcome("test-author", &scope(), "bound", &bound)
            .expect("absent key")
            .is_none()
    );
    let genesis = workspace.current_revision().expect("genesis");
    let committed = workspace
        .commit_bound(fixture_command(genesis, "bound"), bound)
        .expect("commit");
    let replayed = workspace
        .replay_outcome("test-author", &scope(), "bound", &bound)
        .expect("matching fingerprint")
        .expect("recorded outcome");
    assert_eq!(replayed.revision, committed.revision);
    assert_eq!(replayed.sequence, committed.sequence);
    let error = workspace
        .replay_outcome("test-author", &scope(), "bound", &fingerprint("other"))
        .expect_err("a different fingerprint conflicts");
    assert!(matches!(
        error,
        mneme_store::Failure::IdempotencyConflict { .. }
    ));
    advance_with_entity_update(&mut workspace, "unbound", 0x44);
    let error = workspace
        .replay_outcome("test-author", &scope(), "unbound", &bound)
        .expect_err("a command stored without a fingerprint cannot be replayed by one");
    assert!(matches!(
        error,
        mneme_store::Failure::IdempotencyConflict { .. }
    ));
}

struct RemoveCommittedBlob {
    root: std::path::PathBuf,
    digest: mneme_core::ContentDigest,
}

impl FaultInjector for RemoveCommittedBlob {
    fn inject(&self, point: mneme_store::FaultPoint) -> bool {
        if point == mneme_store::FaultPoint::AfterCommit {
            std::fs::remove_file(mneme_store::payload::blob_path(&self.root, self.digest))
                .expect("remove the committed publication blob");
        }
        false
    }
}

#[test]
fn a_publication_failure_is_reported_without_failing_the_commit() {
    let temp = tempfile::tempdir().expect("temp");
    let publication = b"published bytes".to_vec();
    let mut workspace = mneme_store::Workspace::create(
        temp.path(),
        config_with_faults(
            1_000,
            Box::new(RemoveCommittedBlob {
                root: temp.path().to_path_buf(),
                digest: mneme_core::ContentDigest::of_source_bytes(&publication),
            }),
        ),
    )
    .expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    let outcome = workspace
        .commit(mneme_store::CommitCommand {
            base: genesis,
            actor: "author".to_owned(),
            scope: scope(),
            idempotency_key: "publication-failure".to_owned(),
            records: vec![draft(&mneme_core::fixtures::entity())],
            source_blobs: Vec::new(),
            publications: vec![mneme_store::PublicationDraft {
                path: "notes.adoc".to_owned(),
                expected_previous: None,
                bytes: publication,
            }],
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("a publication failure is recorded, not returned as a failed commit");
    assert_eq!(outcome.sequence, 1);
    assert_eq!(outcome.publications.len(), 1);
    assert_eq!(
        outcome.publications[0].state,
        mneme_store::PublicationState::Failed
    );
    assert_eq!(
        workspace.current_revision().expect("current"),
        outcome.revision
    );
    assert_eq!(workspace.status().expect("status").pending_publications, 0);
}

#[test]
fn status_reads_one_consistent_revision_while_commits_run() {
    let temp = tempfile::tempdir().expect("temp");
    let root = temp.path().join("workspace");
    let mut workspace = mneme_store::Workspace::create(&root, config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    workspace
        .commit(mneme_store::CommitCommand {
            base: genesis,
            actor: "author".to_owned(),
            scope: scope(),
            idempotency_key: "status-entity".to_owned(),
            records: vec![draft(&mneme_core::fixtures::entity())],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("seed entity");
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader_stop = stop.clone();
    let ready = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader_ready = ready.clone();
    let reader_root = root.clone();
    let reader = std::thread::spawn(move || {
        let reader = mneme_store::Workspace::open(&reader_root, config(9_000)).expect("reader");
        let mut reads = 0_usize;
        let mut sequences = std::collections::BTreeSet::new();
        reader_ready.store(true, std::sync::atomic::Ordering::Relaxed);
        while !reader_stop.load(std::sync::atomic::Ordering::Relaxed) || reads < 200 {
            let status = reader.status().expect("status");
            let mapping = reader.revision_sequences().expect("sequences");
            assert_eq!(
                mapping.get(&status.revision).copied(),
                Some(status.sequence),
                "status reported one revision with another revision's sequence"
            );
            sequences.insert(status.sequence);
            if reads.is_multiple_of(64) {
                let pinned = reader
                    .snapshot_at(status.revision, Some(status.eligibility_generation))
                    .expect("status revision is readable");
                assert_eq!(pinned.sequence, status.sequence);
                assert_eq!(
                    pinned.records.len(),
                    status.record_count,
                    "status reported one revision with another revision's record count"
                );
            }
            reads += 1;
        }
        sequences.len()
    });
    while !ready.load(std::sync::atomic::Ordering::Relaxed) {
        std::thread::yield_now();
    }
    for index in 0..30_usize {
        let base = workspace.current_revision().expect("base");
        let bytes = format!("= Synthetic {index}\n\nbody {index}\n").into_bytes();
        workspace
            .commit(mneme_store::CommitCommand {
                base,
                actor: "author".to_owned(),
                scope: scope(),
                idempotency_key: format!("status-{index}"),
                records: vec![source_draft(SourceDraftInput {
                    bytes: &bytes,
                    record_id: distinct_id(0x90, index),
                    revision_id: mneme_core::RevisionId::from_bytes(distinct_bytes(0x91, index)),
                    predecessor: None,
                    entity: mneme_core::fixtures::entity_id(),
                    path: &format!("notes/{index}.adoc"),
                })],
                source_blobs: vec![mneme_store::SourceBlobDraft {
                    bytes,
                    media_type: mneme_core::Symbol::from("text/asciidoc"),
                }],
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("commit during status reads");
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let observed = reader.join().expect("reader thread");
    assert!(
        observed > 1,
        "the reader must have observed several revisions"
    );
    let status = workspace.status().expect("status");
    assert_eq!(
        status.revision,
        workspace.current_revision().expect("current")
    );
    assert_eq!(
        status.sequence,
        workspace.current_sequence().expect("sequence")
    );
    assert_eq!(status.record_count, 31);
}

fn distinct_bytes(prefix: u8, index: usize) -> [u8; 16] {
    let mut bytes = [prefix; 16];
    bytes[1] = u8::try_from(index % 256).expect("low index byte");
    bytes[2] = u8::try_from((index / 256) % 256).expect("high index byte");
    bytes
}

fn distinct_id(prefix: u8, index: usize) -> mneme_core::RecordId {
    mneme_core::RecordId::from_bytes(distinct_bytes(prefix, index))
}

#[test]
fn concurrent_barrier_advances_are_never_lost() {
    let temp = tempfile::tempdir().expect("temp");
    let root = temp.path().join("workspace");
    let mut first = mneme_store::Workspace::create(&root, config(1_000)).expect("create");
    let pinned = first.snapshot().expect("snapshot");
    assert_eq!(first.advance_eligibility_barrier().expect("advance"), 2);
    assert!(matches!(
        first.recheck(&pinned),
        Err(mneme_store::Failure::BarrierAdvanced { .. })
    ));
    let rounds = 25_usize;
    let second_root = root.clone();
    let other = std::thread::spawn(move || {
        let mut second = mneme_store::Workspace::open(&second_root, config(2_000)).expect("open");
        for _ in 0..rounds {
            second.advance_eligibility_barrier().expect("advance");
        }
    });
    for _ in 0..rounds {
        first.advance_eligibility_barrier().expect("advance");
    }
    other.join().expect("barrier thread");
    assert_eq!(
        first.eligibility_generation().expect("generation"),
        2 + 2 * rounds as u64,
        "an advance interleaved with another advance is never lost"
    );
}

#[test]
fn create_publishes_a_complete_workspace_or_nothing() {
    let temp = tempfile::tempdir().expect("temp");
    let root = temp.path().join("nested").join("workspace");
    let workspace = mneme_store::Workspace::create(&root, config(1_000)).expect("create");
    assert_eq!(workspace.status().expect("status").sequence, 0);
    drop(workspace);
    let siblings: Vec<String> = std::fs::read_dir(temp.path().join("nested"))
        .expect("siblings")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(
        siblings,
        vec!["workspace".to_owned()],
        "create leaves no partial sibling directory behind"
    );
    // An existing empty directory is completed in place, so a relative `.` root
    // and a mount point keep the directory the caller is standing in.
    let empty = temp.path().join("empty");
    std::fs::create_dir(&empty).expect("empty directory");
    use std::os::unix::fs::MetadataExt;
    let before = std::fs::metadata(&empty).expect("metadata");
    assert!(mneme_store::Workspace::create(&empty, config(2_000)).is_ok());
    let after = std::fs::metadata(&empty).expect("metadata");
    assert_eq!(
        before.ino(),
        after.ino(),
        "create completes an existing directory instead of replacing it"
    );
    assert!(empty.join("ledger.sqlite3").is_file());
    assert!(
        empty.join("workspace.lock").is_file(),
        "create writes the store-owned advisory lock file"
    );
    // A non-empty root is refused without modifying anything in it.
    let occupied = temp.path().join("occupied");
    std::fs::create_dir(&occupied).expect("occupied directory");
    std::fs::write(occupied.join("keep.txt"), b"user bytes").expect("keep");
    assert!(mneme_store::Workspace::create(&occupied, config(3_000)).is_err());
    assert_eq!(
        std::fs::read(occupied.join("keep.txt")).expect("kept"),
        b"user bytes"
    );
    assert_eq!(
        std::fs::read_dir(&occupied)
            .expect("occupied entries")
            .count(),
        1
    );
    // A file that only claims the ledger name is refused, never deleted.
    let garbage = temp.path().join("garbage");
    std::fs::create_dir(&garbage).expect("garbage directory");
    std::fs::write(garbage.join("ledger.sqlite3"), b"not a database").expect("garbage ledger");
    assert!(mneme_store::Workspace::create(&garbage, config(4_000)).is_err());
    assert_eq!(
        std::fs::read(garbage.join("ledger.sqlite3")).expect("garbage kept"),
        b"not a database"
    );
}

#[test]
fn a_restaged_blob_stays_readable_and_is_reported_present() {
    let temp = tempfile::tempdir().expect("temp");
    let bytes = b"durable staged bytes";
    let digest = mneme_core::ContentDigest::of_source_bytes(bytes);
    let length = bytes.len() as u64;
    let first = mneme_store::payload::stage(temp.path(), digest, bytes).expect("stage");
    assert!(mneme_store::payload::blob_is_present(temp.path(), digest, length).expect("present"));
    let again = mneme_store::payload::stage(temp.path(), digest, bytes).expect("restage");
    assert_eq!(again, first);
    assert_eq!(
        mneme_store::payload::read(temp.path(), digest).expect("read"),
        bytes
    );
    std::fs::write(
        mneme_store::payload::blob_path(temp.path(), digest),
        b"truncated",
    )
    .expect("truncate");
    assert!(
        !mneme_store::payload::blob_is_present(temp.path(), digest, length).expect("present"),
        "a truncated blob is not reported as present"
    );
    assert!(matches!(
        mneme_store::payload::verify(temp.path(), digest, length),
        Err(mneme_store::Failure::CorruptBlob { .. })
    ));
}

#[test]
fn a_purged_record_payload_reports_the_barrier_once_the_generation_moves() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    workspace
        .commit(fixture_command(genesis, "first"))
        .expect("first");
    let pinned = workspace.snapshot().expect("pinned");
    let assertion = pinned
        .records
        .iter()
        .find(|record| record.record_id == mneme_core::fixtures::assertion_id())
        .expect("assertion");
    // A forget purges committed payloads only after its barrier is committed.
    std::fs::remove_file(mneme_store::payload::blob_path(
        temp.path(),
        assertion.full_digest(),
    ))
    .expect("purge the committed record blob");

    // With an unchanged generation the purge is still an integrity failure, even
    // for a handle that verified the envelope before it was removed.
    assert!(matches!(
        workspace
            .snapshot_at(pinned.revision, Some(pinned.eligibility_generation))
            .expect_err("purged record payload"),
        mneme_store::Failure::Integrity { .. }
    ));

    // A barrier that moved after the read pinned its generation explains the
    // purge, so the read reports the barrier instead of corruption.
    let moved = workspace.advance_eligibility_barrier().expect("barrier");
    assert!(matches!(
        workspace
            .snapshot_at(pinned.revision, Some(pinned.eligibility_generation))
            .expect_err("the pinned generation is stale"),
        mneme_store::Failure::BarrierAdvanced { pinned: stale, current }
            if stale == pinned.eligibility_generation && current == moved
    ));

    // A read pinned to the moved generation sees no movement of its own, so a
    // payload that was already purged stays the integrity failure.
    assert!(matches!(
        workspace
            .snapshot_at(pinned.revision, Some(moved))
            .expect_err("purged record payload"),
        mneme_store::Failure::Integrity { .. }
    ));
}

#[test]
fn a_purged_source_payload_reports_the_barrier_once_the_generation_moves() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    workspace
        .commit(fixture_command(genesis, "first"))
        .expect("first");
    let pinned = workspace.snapshot().expect("pinned");
    std::fs::remove_file(mneme_store::payload::blob_path(
        temp.path(),
        mneme_core::ContentDigest::of_source_bytes(mneme_core::fixtures::SOURCE_TEXT.as_bytes()),
    ))
    .expect("purge the committed source blob");

    assert!(matches!(
        workspace
            .snapshot_at(pinned.revision, Some(pinned.eligibility_generation))
            .expect_err("purged source payload"),
        mneme_store::Failure::Integrity { .. }
    ));

    let moved = workspace.advance_eligibility_barrier().expect("barrier");
    assert!(matches!(
        workspace
            .snapshot_at(pinned.revision, Some(pinned.eligibility_generation))
            .expect_err("the pinned generation is stale"),
        mneme_store::Failure::BarrierAdvanced { pinned: stale, current }
            if stale == pinned.eligibility_generation && current == moved
    ));
}

#[test]
fn concurrent_recovery_never_fails_a_commit() {
    let temp = tempfile::tempdir().expect("temp");
    let root = temp.path().join("workspace");
    let mut workspace = mneme_store::Workspace::create(&root, config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    workspace
        .commit(mneme_store::CommitCommand {
            base: genesis,
            actor: "author".to_owned(),
            scope: scope(),
            idempotency_key: "sweep-seed".to_owned(),
            records: vec![draft(&mneme_core::fixtures::entity())],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("seed entity");
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ready = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sweeper_stop = stop.clone();
    let sweeper_ready = ready.clone();
    let sweeper_root = root.clone();
    let sweeper = std::thread::spawn(move || {
        let mut handle =
            mneme_store::Workspace::open(&sweeper_root, config(2_000)).expect("sweeper handle");
        handle.recover().expect("initial recovery");
        let mut sweeps = 0_usize;
        sweeper_ready.store(true, std::sync::atomic::Ordering::Relaxed);
        while !sweeper_stop.load(std::sync::atomic::Ordering::Relaxed) {
            handle.recover().expect("recovery beside a running commit");
            sweeps += 1;
        }
        sweeps
    });
    while !ready.load(std::sync::atomic::Ordering::Relaxed) {
        std::thread::yield_now();
    }
    let commit_count = 200_usize;
    let mut revisions = Vec::with_capacity(commit_count);
    for index in 0..commit_count {
        let base = workspace.current_revision().expect("base");
        let bytes = format!("= Sweep {index}\n\nbody {index}\n").into_bytes();
        let outcome = workspace
            .commit(mneme_store::CommitCommand {
                base,
                actor: "author".to_owned(),
                scope: scope(),
                idempotency_key: format!("sweep-{index}"),
                records: vec![source_draft(SourceDraftInput {
                    bytes: &bytes,
                    record_id: distinct_id(0xA0, index),
                    revision_id: mneme_core::RevisionId::from_bytes(distinct_bytes(0xA1, index)),
                    predecessor: None,
                    entity: mneme_core::fixtures::entity_id(),
                    path: &format!("notes/sweep-{index}.adoc"),
                })],
                source_blobs: vec![mneme_store::SourceBlobDraft {
                    bytes,
                    media_type: mneme_core::Symbol::from("text/asciidoc"),
                }],
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("a concurrent recovery must not fail a valid commit");
        assert_eq!(outcome.sequence, index as u64 + 2);
        revisions.push(outcome.revision);
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let sweeps = sweeper.join().expect("sweeper thread");
    assert!(sweeps > 0, "the sweeper must have run at least once");
    assert!(
        root.join("workspace.lock").is_file(),
        "the store-owned lock file is never swept as an orphan"
    );
    for revision in &revisions {
        let snapshot = workspace
            .snapshot_at(*revision, None)
            .expect("every committed revision stays readable");
        assert_eq!(snapshot.revision, *revision);
    }
    let fresh = open(&root, 9_000);
    let snapshot = fresh.snapshot().expect("final snapshot");
    assert_eq!(snapshot.sequence, 201);
    assert_eq!(snapshot.records.len(), 201);
}

// Audit remediation regressions: quarantine replacement, bounded working reads,
// retried publications, the durable restore gate, inspecting cleanup, and
// participant/unregistered payload accounting.

/// The cleanup locations and retained-metadata rows one audited forget plans.
struct ForgetCleanup {
    locations: Vec<mneme_store::RetentionLocationPlan>,
    retained_metadata: Vec<String>,
}

fn audit_forget_barrier(
    key: &str,
    target: mneme_core::RecordId,
    bytes: &[u8],
    generation: u64,
    cleanup: ForgetCleanup,
) -> mneme_store::RetentionCommit {
    let mut retention =
        forget_content_barrier(target, bytes, generation, &format!("retention-{key}"));
    retention.locations = cleanup.locations;
    retention.retained_metadata = cleanup.retained_metadata;
    retention
}

fn audit_inventory_location(kind: &str) -> mneme_store::RetentionLocationPlan {
    mneme_store::RetentionLocationPlan {
        location_id: format!("inventory:{kind}"),
        location_kind: kind.to_owned(),
        locator: format!("workspace-{kind}"),
    }
}

fn audit_working_file_location(
    path: &str,
    digest: mneme_core::ContentDigest,
) -> mneme_store::RetentionLocationPlan {
    mneme_store::RetentionLocationPlan {
        location_id: format!("working-file:{path}"),
        location_kind: "working-file".to_owned(),
        locator: format!("{path}#{}", digest.to_hex()),
    }
}

fn audit_managed_working_metadata() -> Vec<String> {
    vec![mneme_store::lifecycle::MANAGED_WORKING_PATH_DECLARATION.to_owned()]
}

/// Deepest directory chain one audited copy walks.
const COPY_TREE_DIRECTORY_BOUND: usize = 64;

fn audit_copy_tree(source: &std::path::Path, destination: &std::path::Path) {
    let mut pending = vec![(source.to_path_buf(), destination.to_path_buf())];
    while let Some((from, to)) = pending.pop() {
        std::fs::create_dir_all(&to).expect("destination directory");
        for entry in std::fs::read_dir(&from).expect("source entries") {
            let entry = entry.expect("entry");
            let target = to.join(entry.file_name());
            let file_type = entry.file_type().expect("entry kind");
            if file_type.is_dir() {
                assert!(
                    pending.len() < COPY_TREE_DIRECTORY_BOUND,
                    "copied tree stays within its directory bound"
                );
                pending.push((entry.path(), target));
            } else if file_type.is_file() {
                std::fs::copy(entry.path(), &target).expect("copy file");
            }
        }
    }
}

fn audit_location(
    workspace: &mneme_store::Workspace,
    operation_id: &str,
    location_id: &str,
) -> mneme_store::RetentionLocationStateRecord {
    workspace
        .retention_locations(operation_id)
        .expect("locations")
        .into_iter()
        .find(|location| location.location_id == location_id)
        .expect("location")
}

struct AuditEditBeforeReplace {
    root: std::path::PathBuf,
}

impl FaultInjector for AuditEditBeforeReplace {
    fn inject(&self, point: mneme_store::FaultPoint) -> bool {
        if point == mneme_store::FaultPoint::BeforeFileReplace {
            std::fs::write(self.root.join("working/notes.adoc"), b"external edit")
                .expect("external edit");
        }
        false
    }
}

#[test]
fn an_edit_that_lands_during_replacement_is_preserved_and_reported_diverged() {
    let temp = tempfile::tempdir().expect("temp");
    let root = temp.path().join("workspace");
    let mut workspace = mneme_store::Workspace::create(&root, config(1_000)).expect("create");
    workspace
        .commit(publication_command(
            workspace.current_revision().expect("base"),
            &scope(),
            "one",
            "notes.adoc",
            b"version one",
        ))
        .expect("first publication");
    drop(workspace);

    let mut workspace = mneme_store::Workspace::open(
        &root,
        config_with_faults(
            2_000,
            Box::new(AuditEditBeforeReplace { root: root.clone() }),
        ),
    )
    .expect("reopen");
    let mut command = publication_command(
        workspace.current_revision().expect("base"),
        &scope(),
        "two",
        "notes.adoc",
        b"version two",
    );
    command.publications[0].expected_previous =
        Some(mneme_core::ContentDigest::of_source_bytes(b"version one"));
    let outcome = workspace.commit(command).expect("second publication");
    assert_eq!(
        outcome.publications[0].state,
        mneme_store::PublicationState::Diverged,
        "an edit that appears during the replacement is reported, not overwritten"
    );
    assert_eq!(
        mneme_store::payload::read_working_file(&root, "notes.adoc").expect("working"),
        Some(b"external edit".to_vec()),
        "the newer external bytes win"
    );
    let quarantined = std::fs::read_dir(root.join("working"))
        .expect("working")
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".mneme-quarantine-")
        })
        .count();
    assert_eq!(
        quarantined, 0,
        "a reported divergence settles the displaced entry"
    );
}

#[test]
fn a_fifo_at_a_working_path_is_refused_without_blocking_a_commit() {
    let temp = tempfile::tempdir().expect("temp");
    let root = temp.path().join("workspace");
    let mut workspace = mneme_store::Workspace::create(&root, config(1_000)).expect("create");
    let fifo = root.join("working/notes.adoc");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo");
    assert!(status.success(), "mkfifo creates the special file");

    let outcome = workspace
        .commit(publication_command(
            workspace.current_revision().expect("base"),
            &scope(),
            "fifo",
            "notes.adoc",
            b"publication bytes",
        ))
        .expect("a special working target is reported, not read");
    assert_eq!(
        outcome.publications[0].state,
        mneme_store::PublicationState::Failed
    );
    assert_eq!(
        outcome.publications[0].detail.as_deref(),
        Some("working target is not a regular file")
    );
    assert!(
        mneme_store::payload::read_working_file(&root, "notes.adoc").is_err(),
        "a working read refuses a FIFO without opening it"
    );
    let retried = workspace.publish_pending().expect("publish");
    assert_eq!(retried.len(), 1);
    assert_eq!(
        retried[0].state,
        mneme_store::PublicationState::Failed,
        "recovery reports the same obstacle instead of hanging"
    );
    assert!(
        !std::fs::symlink_metadata(&fifo)
            .expect("special file survives")
            .is_file()
    );
}

#[test]
fn a_failed_publication_is_retried_by_publish_pending() {
    let temp = tempfile::tempdir().expect("temp");
    let root = temp.path().join("workspace");
    let mut workspace = mneme_store::Workspace::create(&root, config(1_000)).expect("create");
    // A directory at the target makes the first attempt fail deterministically.
    std::fs::create_dir(root.join("working/docs")).expect("obstacle");
    let outcome = workspace
        .commit(publication_command(
            workspace.current_revision().expect("base"),
            &scope(),
            "obstacle",
            "docs",
            b"published bytes",
        ))
        .expect("commit");
    assert_eq!(
        outcome.publications[0].state,
        mneme_store::PublicationState::Failed
    );
    std::fs::remove_dir(root.join("working/docs")).expect("remove obstacle");
    let retried = workspace.publish_pending().expect("retry");
    assert_eq!(retried.len(), 1);
    assert_eq!(
        retried[0].state,
        mneme_store::PublicationState::Published,
        "a failed attempt is retried instead of staying terminal"
    );
    assert_eq!(
        mneme_store::payload::read_working_file(&root, "docs").expect("working"),
        Some(b"published bytes".to_vec())
    );
    // A later publication of the same path is not misreported as diverged,
    // because the retried attempt really wrote the content it committed.
    let mut follow_up = publication_command(
        workspace.current_revision().expect("base"),
        &scope(),
        "follow-up",
        "docs",
        b"second version",
    );
    follow_up.publications[0].expected_previous = Some(mneme_core::ContentDigest::of_source_bytes(
        b"published bytes",
    ));
    let follow_up = workspace.commit(follow_up).expect("follow-up publication");
    assert_eq!(
        follow_up.publications[0].state,
        mneme_store::PublicationState::Published,
        "the retried content is the expected previous content"
    );
    assert_eq!(
        mneme_store::payload::read_working_file(&root, "docs").expect("working"),
        Some(b"second version".to_vec())
    );
}

#[test]
fn the_restore_marker_survives_restart_and_the_ledger_names_its_workspace() {
    let temp = tempfile::tempdir().expect("temp");
    let backup = tempfile::tempdir().expect("backup");
    let root = temp.path().join("workspace");
    {
        let mut workspace = mneme_store::Workspace::create(&root, config(1_000)).expect("create");
        workspace
            .commit(fixture_command(
                workspace.current_revision().expect("base"),
                "seed",
            ))
            .expect("seed");
    }
    audit_copy_tree(&root, backup.path());
    let mut current = open(&root, 2_000);
    current.advance_eligibility_barrier().expect("barrier");
    let ledger = current.export_suppression_ledger().expect("ledger");
    drop(current);

    let other_root = temp.path().join("other");
    let other = mneme_store::Workspace::create(&other_root, config(3_000)).expect("other");
    let foreign = other.export_suppression_ledger().expect("foreign ledger");
    drop(other);

    let mut restored =
        mneme_store::Workspace::open_restored(backup.path(), config(4_000)).expect("restore");
    assert!(matches!(
        restored.snapshot(),
        Err(mneme_store::Failure::MissingRetentionState { .. })
    ));
    assert!(matches!(
        restored.export_suppression_ledger(),
        Err(mneme_store::Failure::MissingRetentionState { .. })
    ));
    assert!(
        restored.apply_restore_suppression_ledger(&foreign).is_err(),
        "a ledger from another workspace is never applied"
    );
    assert!(
        restored.snapshot().is_err(),
        "a refused ledger keeps the gate closed"
    );

    let backup_genesis = restored.genesis_revision().expect("genesis");
    let stale = mneme_core::binary::encode(&mneme_core::Value::record_named(
        "retention-state",
        vec![
            mneme_core::Value::integer(2_i64),
            mneme_core::Value::integer(0_i64),
            backup_genesis.to_value(),
            mneme_core::Value::set(Vec::<mneme_core::Value>::new()),
            mneme_core::Value::set(Vec::<mneme_core::Value>::new()),
        ],
    ));
    assert!(
        restored.apply_restore_suppression_ledger(&stale).is_err(),
        "a ledger older than the restored copy is refused"
    );
    drop(restored);

    let mut reopened = open(backup.path(), 5_000);
    assert!(
        matches!(
            reopened.snapshot(),
            Err(mneme_store::Failure::MissingRetentionState { .. })
        ),
        "a plain open honours the persisted restore marker"
    );
    assert!(reopened.export_suppression_ledger().is_err());
    reopened
        .apply_restore_suppression_ledger(&ledger)
        .expect("apply the current ledger");
    assert!(reopened.snapshot().is_ok());
    drop(reopened);
    let fresh = open(backup.path(), 6_000);
    assert!(fresh.snapshot().is_ok());
}

const AUDIT_SOURCE: &[u8] = b"= Audit source\n\nThe audit secret body.\n";

#[test]
fn applying_a_ledger_purges_the_restored_copy_and_tracks_the_cleanup() {
    let temp = tempfile::tempdir().expect("temp");
    let backup = tempfile::tempdir().expect("backup");
    let root = temp.path().join("workspace");
    let source_id = mneme_core::RecordId::from_bytes([0x31; 16]);
    {
        let mut workspace = mneme_store::Workspace::create(&root, config(1_000)).expect("create");
        workspace
            .commit(mneme_store::CommitCommand {
                base: workspace.current_revision().expect("base"),
                actor: "test-author".to_owned(),
                scope: scope(),
                idempotency_key: "seed".to_owned(),
                records: vec![retained_source_record(
                    source_id,
                    mneme_core::RevisionId::from_bytes([0x32; 16]),
                    &scope(),
                    AUDIT_SOURCE,
                    Some("project.adoc"),
                )],
                source_blobs: vec![source_blob(AUDIT_SOURCE)],
                publications: vec![mneme_store::PublicationDraft {
                    path: "project.adoc".to_owned(),
                    expected_previous: None,
                    bytes: AUDIT_SOURCE.to_vec(),
                }],
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("seed");
    }
    audit_copy_tree(&root, backup.path());
    let digest = mneme_core::ContentDigest::of_source_bytes(AUDIT_SOURCE);
    let mut current = open(&root, 2_000);
    let generation = current.eligibility_generation().expect("generation");
    current
        .commit(audit_barrier_command(
            current.current_revision().expect("base"),
            "forget-source",
            audit_forget_barrier(
                "forget-source",
                source_id,
                AUDIT_SOURCE,
                generation.saturating_add(1),
                ForgetCleanup {
                    locations: Vec::new(),
                    retained_metadata: Vec::new(),
                },
            ),
        ))
        .expect("forget barrier");
    let ledger_generation = current.eligibility_generation().expect("generation");
    let ledger = current.export_suppression_ledger().expect("ledger");
    drop(current);

    let mut restored =
        mneme_store::Workspace::open_restored(backup.path(), config(3_000)).expect("restore");
    restored
        .apply_restore_suppression_ledger(&ledger)
        .expect("apply");
    let snapshot = restored.snapshot().expect("visible");
    assert!(
        snapshot
            .records
            .iter()
            .all(|record| record.record_id != source_id),
        "the restored copy hides the forgotten identity"
    );
    assert!(matches!(
        mneme_store::payload::read(backup.path(), digest),
        Err(mneme_store::Failure::MissingBlob { .. })
    ));
    assert_eq!(
        mneme_store::payload::read_working_file(backup.path(), "project.adoc").expect("working"),
        None,
        "the restored copy's working copy of the forgotten bytes is removed"
    );
    let operation_id = format!(
        "restore-{}-{ledger_generation}",
        restored.genesis_revision().expect("genesis").to_hex()
    );
    let operation = restored
        .retention_operation(&operation_id)
        .expect("operation")
        .expect("restore operation");
    assert_eq!(
        operation.state,
        mneme_store::RetentionJobState::Complete,
        "the restored cleanup is tracked and finished"
    );
    let locations = restored
        .retention_locations(&operation_id)
        .expect("locations");
    assert!(locations.len() >= 3, "{locations:?}");
    assert!(locations.iter().all(|location| {
        location.state == mneme_store::RetentionLocationState::Purged
            || location.state == mneme_store::RetentionLocationState::Absent
    }));
    assert!(
        locations
            .iter()
            .any(|location| location.location_kind == "working-file")
    );
}

#[test]
fn a_failed_purge_location_is_not_terminal_and_is_retried() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    workspace
        .commit(fixture_command(
            workspace.current_revision().expect("base"),
            "seed",
        ))
        .expect("seed");
    let digest =
        mneme_core::ContentDigest::of_source_bytes(mneme_core::fixtures::SOURCE_TEXT.as_bytes());
    let location = audit_blob_location("source-blob", digest);
    let generation = workspace.eligibility_generation().expect("generation");
    let operation_id = "retention-retry".to_owned();
    workspace
        .commit(audit_barrier_command(
            workspace.current_revision().expect("base"),
            "retry",
            audit_forget_barrier(
                "retry",
                mneme_core::fixtures::source_revision_id(),
                mneme_core::fixtures::SOURCE_TEXT.as_bytes(),
                generation.saturating_add(1),
                ForgetCleanup {
                    locations: vec![location.clone()],
                    retained_metadata: Vec::new(),
                },
            ),
        ))
        .expect("barrier");
    workspace
        .verify_retention_location(
            &operation_id,
            &location.location_id,
            mneme_store::RetentionLocationState::Failed,
            Some("payload-removal-failed"),
        )
        .expect("record failure");
    let failed = audit_location(&workspace, &operation_id, &location.location_id);
    assert_eq!(failed.state, mneme_store::RetentionLocationState::Failed);
    assert!(
        !failed.verified,
        "a failed attempt is not a verified outcome"
    );
    assert_eq!(failed.attempts, 1);
    assert!(
        !failed.state.is_terminal(),
        "a failed purge is not a terminal location state"
    );
    assert!(
        failed.state.needs_attempt(),
        "a resume must attempt a failed purge again"
    );

    workspace
        .purge_retention_blob(
            &operation_id,
            &location.location_id,
            "source-blob",
            &digest.to_hex(),
        )
        .expect("retry the purge");
    let purged = audit_location(&workspace, &operation_id, &location.location_id);
    assert_eq!(purged.state, mneme_store::RetentionLocationState::Purged);
    assert!(purged.verified);
    assert_eq!(purged.attempts, 2);
    assert!(!mneme_store::payload::blob_path(temp.path(), digest).exists());
}

#[test]
fn a_blob_purge_keeps_bytes_a_live_retained_record_requires() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    workspace
        .commit(fixture_command(
            workspace.current_revision().expect("base"),
            "seed",
        ))
        .expect("seed");
    let digest =
        mneme_core::ContentDigest::of_source_bytes(mneme_core::fixtures::SOURCE_TEXT.as_bytes());
    let location = audit_blob_location("source-blob", digest);
    let operation_id = "retention-shared".to_owned();
    let operation = mneme_store::RetentionCommit {
        operation_id: operation_id.clone(),
        operation_kind: "keep".to_owned(),
        policy_version: "1".to_owned(),
        selectors: Vec::new(),
        suppressions: Vec::new(),
        locations: vec![location.clone()],
        retained_metadata: Vec::new(),
    };
    workspace
        .commit(audit_barrier_command(
            workspace.current_revision().expect("base"),
            "shared",
            operation,
        ))
        .expect("barrier");
    let outcome = workspace
        .purge_retention_blob(
            &operation_id,
            &location.location_id,
            "source-blob",
            &digest.to_hex(),
        )
        .expect("purge");
    assert_eq!(outcome, mneme_store::BlobPurgeOutcome::RetainedShared);
    assert!(mneme_store::payload::blob_path(temp.path(), digest).exists());
    let state = audit_location(&workspace, &operation_id, &location.location_id);
    assert_eq!(
        state.state,
        mneme_store::RetentionLocationState::RetainedShared
    );
    assert!(!state.verified);
}

#[test]
fn a_purge_removal_and_its_recorded_state_share_one_transaction() {
    let temp = tempfile::tempdir().expect("temp");
    let root = temp.path().join("workspace");
    let mut workspace = mneme_store::Workspace::create(&root, config(1_000)).expect("create");
    workspace
        .commit(fixture_command(
            workspace.current_revision().expect("base"),
            "seed",
        ))
        .expect("seed");
    let digest =
        mneme_core::ContentDigest::of_source_bytes(mneme_core::fixtures::SOURCE_TEXT.as_bytes());
    let location = audit_blob_location("source-blob", digest);
    let generation = workspace.eligibility_generation().expect("generation");
    workspace
        .commit(audit_barrier_command(
            workspace.current_revision().expect("base"),
            "atomic",
            audit_forget_barrier(
                "atomic",
                mneme_core::fixtures::source_revision_id(),
                mneme_core::fixtures::SOURCE_TEXT.as_bytes(),
                generation.saturating_add(1),
                ForgetCleanup {
                    locations: vec![location.clone()],
                    retained_metadata: Vec::new(),
                },
            ),
        ))
        .expect("barrier");
    drop(workspace);

    let mut workspace = mneme_store::Workspace::open(
        &root,
        config_with_faults(
            2_000,
            Box::new(mneme_store::FaultAt(
                mneme_store::FaultPoint::AfterRetentionPurge,
            )),
        ),
    )
    .expect("open");
    let error = workspace
        .purge_retention_blob(
            "retention-atomic",
            &location.location_id,
            "source-blob",
            &digest.to_hex(),
        )
        .expect_err("crash after the removal");
    assert!(matches!(
        error,
        mneme_store::Failure::InjectedFault(mneme_store::FaultPoint::AfterRetentionPurge)
    ));
    let pending = audit_location(&workspace, "retention-atomic", &location.location_id);
    assert_eq!(
        pending.state,
        mneme_store::RetentionLocationState::Pending,
        "the outcome is not recorded before the removal is durable"
    );
    assert_eq!(pending.attempts, 0);
    assert!(!mneme_store::payload::blob_path(&root, digest).exists());
    drop(workspace);

    let mut workspace = open(&root, 3_000);
    let outcome = workspace
        .purge_retention_blob(
            "retention-atomic",
            &location.location_id,
            "source-blob",
            &digest.to_hex(),
        )
        .expect("resume the purge");
    assert_eq!(outcome, mneme_store::BlobPurgeOutcome::Absent);
    let absent = audit_location(&workspace, "retention-atomic", &location.location_id);
    assert_eq!(absent.state, mneme_store::RetentionLocationState::Absent);
    assert!(absent.verified);
}

#[test]
fn a_symlink_at_a_planned_working_path_is_unavailable_and_unlinked_nowhere() {
    let temp = tempfile::tempdir().expect("temp");
    let root = temp.path().join("workspace");
    let mut workspace = mneme_store::Workspace::create(&root, config(1_000)).expect("create");
    let source_id = mneme_core::RecordId::from_bytes([0x41; 16]);
    workspace
        .commit(mneme_store::CommitCommand {
            base: workspace.current_revision().expect("base"),
            actor: "test-author".to_owned(),
            scope: scope(),
            idempotency_key: "seed".to_owned(),
            records: vec![retained_source_record(
                source_id,
                mneme_core::RevisionId::from_bytes([0x42; 16]),
                &scope(),
                AUDIT_SOURCE,
                Some("secret.adoc"),
            )],
            source_blobs: vec![source_blob(AUDIT_SOURCE)],
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("seed");
    let digest = mneme_core::ContentDigest::of_source_bytes(AUDIT_SOURCE);
    mneme_store::payload::publish_working_file(&root, "real.adoc", AUDIT_SOURCE)
        .expect("real copy");
    std::os::unix::fs::symlink("real.adoc", root.join("working/secret.adoc")).expect("symlink");
    let location = audit_working_file_location("secret.adoc", digest);
    let generation = workspace.eligibility_generation().expect("generation");
    workspace
        .commit(audit_barrier_command(
            workspace.current_revision().expect("base"),
            "symlink",
            audit_forget_barrier(
                "symlink",
                source_id,
                AUDIT_SOURCE,
                generation.saturating_add(1),
                ForgetCleanup {
                    locations: vec![location.clone()],
                    retained_metadata: audit_managed_working_metadata(),
                },
            ),
        ))
        .expect("barrier");
    let outcome = workspace
        .purge_retention_working_file(
            "retention-symlink",
            &location.location_id,
            &location.locator,
        )
        .expect("purge");
    assert_eq!(outcome, mneme_store::BlobPurgeOutcome::RetainedShared);
    let state = audit_location(&workspace, "retention-symlink", &location.location_id);
    assert_eq!(
        state.state,
        mneme_store::RetentionLocationState::Unavailable
    );
    assert_eq!(state.detail_code.as_deref(), Some("not-a-regular-file"));
    assert!(
        std::fs::symlink_metadata(root.join("working/secret.adoc"))
            .expect("symlink still present")
            .file_type()
            .is_symlink(),
        "a symbolic link is reported, never unlinked"
    );
    assert_eq!(
        mneme_store::payload::read_working_file(&root, "real.adoc").expect("real"),
        Some(AUDIT_SOURCE.to_vec()),
        "the link target is never hashed or deleted"
    );
}

struct AuditEditBeforePurge {
    root: std::path::PathBuf,
}

impl FaultInjector for AuditEditBeforePurge {
    fn inject(&self, point: mneme_store::FaultPoint) -> bool {
        if point == mneme_store::FaultPoint::BeforeRetentionPurge {
            std::fs::write(self.root.join("working/secret.adoc"), b"external edit")
                .expect("external edit");
        }
        false
    }
}

#[test]
fn an_edit_that_lands_during_a_purge_is_preserved_and_reported_unavailable() {
    let temp = tempfile::tempdir().expect("temp");
    let root = temp.path().join("workspace");
    let mut workspace = mneme_store::Workspace::create(&root, config(1_000)).expect("create");
    let source_id = mneme_core::RecordId::from_bytes([0x51; 16]);
    workspace
        .commit(mneme_store::CommitCommand {
            base: workspace.current_revision().expect("base"),
            actor: "test-author".to_owned(),
            scope: scope(),
            idempotency_key: "seed".to_owned(),
            records: vec![retained_source_record(
                source_id,
                mneme_core::RevisionId::from_bytes([0x52; 16]),
                &scope(),
                AUDIT_SOURCE,
                Some("secret.adoc"),
            )],
            source_blobs: vec![source_blob(AUDIT_SOURCE)],
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("seed");
    let digest = mneme_core::ContentDigest::of_source_bytes(AUDIT_SOURCE);
    mneme_store::payload::publish_working_file(&root, "secret.adoc", AUDIT_SOURCE)
        .expect("working copy");
    let location = audit_working_file_location("secret.adoc", digest);
    let generation = workspace.eligibility_generation().expect("generation");
    workspace
        .commit(audit_barrier_command(
            workspace.current_revision().expect("base"),
            "purge-race",
            audit_forget_barrier(
                "purge-race",
                source_id,
                AUDIT_SOURCE,
                generation.saturating_add(1),
                ForgetCleanup {
                    locations: vec![location.clone()],
                    retained_metadata: audit_managed_working_metadata(),
                },
            ),
        ))
        .expect("barrier");
    drop(workspace);

    let mut workspace = mneme_store::Workspace::open(
        &root,
        config_with_faults(2_000, Box::new(AuditEditBeforePurge { root: root.clone() })),
    )
    .expect("open");
    workspace
        .purge_retention_working_file(
            "retention-purge-race",
            &location.location_id,
            &location.locator,
        )
        .expect("purge");
    let state = audit_location(&workspace, "retention-purge-race", &location.location_id);
    assert_eq!(
        state.state,
        mneme_store::RetentionLocationState::Unavailable
    );
    assert_eq!(state.detail_code.as_deref(), Some("external-edit-present"));
    assert_eq!(
        mneme_store::payload::read_working_file(&root, "secret.adoc").expect("working"),
        Some(b"external edit".to_vec()),
        "the external bytes are kept"
    );
}

#[test]
fn a_plan_that_retains_a_working_path_must_declare_it() {
    let temp = tempfile::tempdir().expect("temp");
    let root = temp.path().join("workspace");
    let mut workspace = mneme_store::Workspace::create(&root, config(1_000)).expect("create");
    let source_id = mneme_core::RecordId::from_bytes([0x61; 16]);
    workspace
        .commit(mneme_store::CommitCommand {
            base: workspace.current_revision().expect("base"),
            actor: "test-author".to_owned(),
            scope: scope(),
            idempotency_key: "seed".to_owned(),
            records: vec![retained_source_record(
                source_id,
                mneme_core::RevisionId::from_bytes([0x62; 16]),
                &scope(),
                AUDIT_SOURCE,
                Some("secret.adoc"),
            )],
            source_blobs: vec![source_blob(AUDIT_SOURCE)],
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("seed");
    let digest = mneme_core::ContentDigest::of_source_bytes(AUDIT_SOURCE);
    let location = audit_working_file_location("secret.adoc", digest);
    let generation = workspace.eligibility_generation().expect("generation");
    let undeclared = audit_forget_barrier(
        "undeclared",
        source_id,
        AUDIT_SOURCE,
        generation.saturating_add(1),
        ForgetCleanup {
            locations: vec![location.clone()],
            retained_metadata: Vec::new(),
        },
    );
    let error = workspace
        .commit(audit_barrier_command(
            workspace.current_revision().expect("base"),
            "undeclared",
            undeclared,
        ))
        .expect_err("an undeclared working path is refused");
    assert!(matches!(error, mneme_store::Failure::InvalidCommand(_)));
    assert_eq!(
        workspace.eligibility_generation().expect("generation"),
        generation,
        "a refused plan commits no barrier"
    );
    let declared = audit_forget_barrier(
        "declared",
        source_id,
        AUDIT_SOURCE,
        generation.saturating_add(1),
        ForgetCleanup {
            locations: vec![location],
            retained_metadata: audit_managed_working_metadata(),
        },
    );
    workspace
        .commit(audit_barrier_command(
            workspace.current_revision().expect("base"),
            "declared",
            declared,
        ))
        .expect("a declared working path is accepted");
}

#[test]
fn leftover_staging_and_working_temporaries_holding_targeted_bytes_are_purged() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    workspace
        .commit(fixture_command(
            workspace.current_revision().expect("base"),
            "seed",
        ))
        .expect("seed");
    let digest =
        mneme_core::ContentDigest::of_source_bytes(mneme_core::fixtures::SOURCE_TEXT.as_bytes());
    let staging = audit_inventory_location("staging");
    let ledger = audit_inventory_location("sqlite-payloads");
    let generation = workspace.eligibility_generation().expect("generation");
    workspace
        .commit(audit_barrier_command(
            workspace.current_revision().expect("base"),
            "inventory",
            audit_forget_barrier(
                "inventory",
                mneme_core::fixtures::source_revision_id(),
                mneme_core::fixtures::SOURCE_TEXT.as_bytes(),
                generation.saturating_add(1),
                ForgetCleanup {
                    locations: vec![
                        audit_blob_location("source-blob", digest),
                        staging.clone(),
                        ledger.clone(),
                    ],
                    retained_metadata: Vec::new(),
                },
            ),
        ))
        .expect("barrier");
    let leftover = temp.path().join("staging/.mneme-tmp-crashed");
    std::fs::write(&leftover, mneme_core::fixtures::SOURCE_TEXT.as_bytes())
        .expect("crashed staging file");
    let unrelated = temp.path().join("working/.mneme-tmp-unrelated");
    std::fs::write(&unrelated, b"unrelated bytes").expect("unrelated temporary");

    workspace
        .verify_retention_location(
            "retention-inventory",
            &staging.location_id,
            mneme_store::RetentionLocationState::Absent,
            None,
        )
        .expect("inspect staging");
    assert!(
        !leftover.exists(),
        "a leftover holding targeted bytes is removed"
    );
    assert!(unrelated.exists(), "an unrelated temporary is left alone");
    let inspected = audit_location(&workspace, "retention-inventory", &staging.location_id);
    assert_eq!(inspected.state, mneme_store::RetentionLocationState::Purged);
    assert!(inspected.verified);

    workspace
        .verify_retention_location(
            "retention-inventory",
            &staging.location_id,
            mneme_store::RetentionLocationState::Absent,
            None,
        )
        .expect("inspect staging again");
    let absent = audit_location(&workspace, "retention-inventory", &staging.location_id);
    assert_eq!(
        absent.state,
        mneme_store::RetentionLocationState::Absent,
        "absence is recorded only after an inspection"
    );
    assert_eq!(absent.attempts, 2);

    workspace
        .verify_retention_location(
            "retention-inventory",
            &ledger.location_id,
            mneme_store::RetentionLocationState::Absent,
            None,
        )
        .expect("inspect the ledger");
    let sqlite = audit_location(&workspace, "retention-inventory", &ledger.location_id);
    assert_eq!(sqlite.state, mneme_store::RetentionLocationState::Absent);
    assert!(sqlite.verified);
}

#[test]
fn participant_files_are_purged_and_unregistered_payload_stores_are_reported() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    workspace
        .register_retention_participant(mneme_store::RetentionParticipant {
            name: "mneme-desktop-drafts".to_owned(),
            storage_role: "document-keyed-files".to_owned(),
            supports_invalidation: true,
            supports_purge: true,
            checks_generation: true,
            inventory_locator: ".mneme-ui/drafts".to_owned(),
        })
        .expect("participant");
    assert_eq!(
        workspace
            .retention_participants()
            .expect("participants")
            .len(),
        1
    );
    std::fs::create_dir_all(temp.path().join(".mneme-ui/drafts")).expect("draft directory");
    std::fs::create_dir(temp.path().join("cache")).expect("unregistered store");
    let document = "0123456789abcdef0123456789abcdef";
    let draft = temp
        .path()
        .join(format!(".mneme-ui/drafts/{document}.json"));
    std::fs::write(&draft, b"{\"draft\":\"forgotten text\"}").expect("draft");
    let location = mneme_store::RetentionLocationPlan {
        location_id: format!("participant-file:{document}"),
        location_kind: "participant-file".to_owned(),
        locator: format!(".mneme-ui/drafts/{document}.json"),
    };
    let generation = workspace.eligibility_generation().expect("generation");
    workspace
        .commit(audit_barrier_command(
            workspace.current_revision().expect("base"),
            "participant",
            audit_forget_barrier(
                "participant",
                mneme_core::fixtures::source_revision_id(),
                b"participant bytes",
                generation.saturating_add(1),
                ForgetCleanup {
                    locations: vec![location.clone()],
                    retained_metadata: Vec::new(),
                },
            ),
        ))
        .expect("barrier");
    let outcome = workspace
        .purge_retention_participant_file(
            "retention-participant",
            &location.location_id,
            &location.locator,
        )
        .expect("purge participant file");
    assert_eq!(outcome, mneme_store::BlobPurgeOutcome::Purged);
    assert!(!draft.exists(), "the participant copy is removed");
    assert!(
        temp.path().join(".mneme-ui/drafts").is_dir(),
        "the participant directory itself is kept"
    );
    let state = audit_location(&workspace, "retention-participant", &location.location_id);
    assert_eq!(state.state, mneme_store::RetentionLocationState::Purged);
    assert_eq!(
        workspace.unregistered_payload_entries().expect("entries"),
        vec!["cache".to_owned()],
        "a registered participant directory is not unregistered"
    );
}
