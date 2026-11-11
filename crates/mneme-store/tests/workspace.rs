//! End-to-end workspace coordinator tests.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::unwrap_used, clippy::expect_used)]

use mneme_store::FaultInjector;

fn scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
}

fn config(at: i64) -> mneme_store::WorkspaceConfig {
    mneme_store::WorkspaceConfig {
        clock: Box::new(mneme_store::FixedClock::new(
            mneme_core::Timestamp::from_nanos(at),
        )),
        faults: Box::new(mneme_store::NoFaults),
    }
}

fn config_with_faults(at: i64, faults: Box<dyn FaultInjector>) -> mneme_store::WorkspaceConfig {
    mneme_store::WorkspaceConfig {
        clock: Box::new(mneme_store::FixedClock::new(
            mneme_core::Timestamp::from_nanos(at),
        )),
        faults,
    }
}

fn draft(envelope: &mneme_core::RecordEnvelope) -> mneme_store::RecordDraft {
    mneme_store::RecordDraft {
        schema_version: envelope.schema_version,
        kind: envelope.kind,
        record_id: envelope.record_id,
        revision_id: envelope.revision_id,
        predecessor: envelope.predecessor,
        scope: envelope.scope.clone(),
        payload: envelope.payload.clone(),
    }
}

fn fixture_command(base: mneme_core::WorkspaceRevisionId, key: &str) -> mneme_store::CommitCommand {
    mneme_store::CommitCommand {
        base,
        actor: "test-author".to_owned(),
        scope: scope(),
        idempotency_key: key.to_owned(),
        records: mneme_core::fixtures::fixture_batch()
            .iter()
            .map(draft)
            .collect(),
        source_blobs: vec![mneme_store::SourceBlobDraft {
            bytes: mneme_core::fixtures::SOURCE_TEXT.as_bytes().to_vec(),
            media_type: mneme_core::Symbol::from("text/asciidoc"),
        }],
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: None,
    }
}

#[allow(unknown_lints, too_many_parameters)] // Octet structural exception: cohesive state-machine code; split tracked separately
fn source_draft(
    bytes: &[u8],
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    predecessor: Option<mneme_core::RevisionId>,
    entity: mneme_core::RecordId,
    path: &str,
) -> mneme_store::RecordDraft {
    let retained = mneme_core::RetainedSource::new(
        mneme_core::ContentDigest::of_source_bytes(bytes),
        bytes.len() as u64,
        "text/asciidoc",
    )
    .expect("retained source");
    mneme_store::RecordDraft {
        schema_version: 1,
        kind: mneme_core::RecordKind::SourceRevision,
        record_id,
        revision_id,
        predecessor,
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
                mneme_core::Reference::local(entity, mneme_core::RecordKind::Entity).to_value(),
            ),
            (
                mneme_core::Symbol::from("path-hint"),
                mneme_core::Value::string(path),
            ),
        ]),
    }
}

fn open(root: &std::path::Path, at: i64) -> mneme_store::Workspace {
    mneme_store::Workspace::open(root, config(at)).expect("open workspace")
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
    assert!(matches!(error, mneme_store::StoreError::StaleBase { .. }));
    let after = workspace.snapshot().expect("still valid");
    assert_eq!(after.revision, winner.revision);
    assert_eq!(after.records, winner.records);
    assert!(
        mneme_store::blob::read_working_file(temp.path(), "project.adoc")
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
        mneme_store::StoreError::IdempotencyConflict { .. }
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
    mneme_store::blob::publish_working_file(temp.path(), "project.adoc", edited.as_bytes())
        .expect("edit file");
    let revision = mneme_core::RevisionId::from_bytes([0x21; 16]);
    let replacement = source_draft(
        edited.as_bytes(),
        mneme_core::fixtures::source_revision_id(),
        revision,
        Some(mneme_core::fixtures::source_revision().revision_id),
        mneme_core::fixtures::entity_id(),
        "project.adoc",
    );
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
    mneme_store::blob::publish_working_file(temp.path(), "project.adoc", b"newer external bytes")
        .expect("second edit");
    let second_revision = mneme_core::RevisionId::from_bytes([0x22; 16]);
    let stale = mneme_store::CommitCommand {
        base: workspace.current_revision().expect("current"),
        actor: "author".to_owned(),
        scope: scope(),
        idempotency_key: "stale-import".to_owned(),
        records: vec![source_draft(
            edited.as_bytes(),
            mneme_core::fixtures::source_revision_id(),
            second_revision,
            Some(revision),
            mneme_core::fixtures::entity_id(),
            "project.adoc",
        )],
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
        mneme_store::StoreError::InvalidCandidate { .. }
    ));
    assert_eq!(
        workspace.snapshot().expect("snapshot").revision,
        snapshot.revision
    );
    assert_eq!(
        mneme_store::blob::read_working_file(temp.path(), "project.adoc").expect("read"),
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
    let rebind = source_draft(
        mneme_core::fixtures::SOURCE_TEXT.as_bytes(),
        mneme_core::RecordId::from_bytes([0x33; 16]),
        mneme_core::RevisionId::from_bytes([0x34; 16]),
        None,
        other_entity.record_id,
        "project.adoc",
    );
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
    assert!(matches!(error, mneme_store::StoreError::BindingConflict(_)));
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
    let path = mneme_store::blob::blob_path(temp.path(), digest);
    std::fs::remove_file(&path).expect("remove blob");
    let error = workspace.snapshot().expect_err("integrity");
    assert!(matches!(error, mneme_store::StoreError::Integrity { .. }));
    let mut reopened = open(temp.path(), 2_000);
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
        assert!(matches!(error, mneme_store::StoreError::InjectedFault(p) if p == point));
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
        mneme_store::StoreError::InjectedFault(mneme_store::FaultPoint::AfterCommit)
    ));
    let status = workspace.status().expect("status");
    assert_eq!(status.sequence, 1, "commit is visible before publication");
    assert_eq!(status.pending_publications, 1);
    assert!(
        mneme_store::blob::read_working_file(temp.path(), "project.adoc")
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
        mneme_store::blob::read_working_file(temp.path(), "project.adoc").expect("read"),
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
        mneme_store::blob::read_working_file(temp.path(), "notes.adoc").expect("read"),
        Some(b"version one".to_vec())
    );

    mneme_store::blob::publish_working_file(temp.path(), "notes.adoc", b"external edit")
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
        mneme_store::blob::read_working_file(temp.path(), "notes.adoc").expect("read"),
        Some(b"external edit".to_vec()),
        "the external edit is preserved"
    );
    // The committed desired payload remains available separately.
    let desired = mneme_core::ContentDigest::of_source_bytes(b"version two");
    assert_eq!(
        mneme_store::blob::read(temp.path(), desired).expect("committed payload"),
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
    let source = source_draft(
        source_bytes,
        mneme_core::fixtures::source_revision_id(),
        mneme_core::RevisionId::from_bytes([0x41; 16]),
        None,
        mneme_core::fixtures::entity_id(),
        "project.adoc",
    );
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
    mneme_store::blob::publish_working_file(
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
        mneme_store::blob::read_working_file(temp.path(), "project.adoc").expect("read"),
        Some(b"external edit after commit".to_vec()),
        "a metadata-only update neither rewrites prose nor overwrites an external edit"
    );
    assert_eq!(
        mneme_store::blob::read(
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
        mneme_store::StoreError::BarrierAdvanced { .. }
    ));
    assert!(matches!(
        workspace.recheck(&pinned).expect_err("barrier"),
        mneme_store::StoreError::BarrierAdvanced { .. }
    ));
    let outcomes = workspace.publish_pending().expect("publish");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].state, mneme_store::PublicationState::Suppressed);
    assert!(
        mneme_store::blob::read_working_file(temp.path(), "suppressed.adoc")
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
        mneme_store::StoreError::BarrierAdvanced { .. }
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
        mneme_store::StoreError::ScopeMismatch { .. }
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
        mneme_store::StoreError::InvalidCommand(_)
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
        mneme_store::StoreError::InvalidCommand(_)
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
        mneme_store::blob::read_working_file(temp.path(), "recovered.adoc").expect("read"),
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
        mneme_store::StoreError::InjectedFault(mneme_store::FaultPoint::AfterFileReplace)
    ));
    assert_eq!(
        mneme_store::blob::read_working_file(temp.path(), "after-replace.adoc").expect("read"),
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
        mneme_store::blob::read_working_file(temp.path(), "after-replace.adoc").expect("read"),
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
    let path = mneme_store::blob::blob_path(temp.path(), assertion.full_digest());
    let length =
        usize::try_from(std::fs::metadata(&path).expect("metadata").len()).expect("file length");
    std::fs::write(&path, vec![0x5a_u8; length]).expect("tamper");
    assert!(matches!(
        workspace.snapshot().expect_err("corrupt"),
        mneme_store::StoreError::Integrity { .. }
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
        mneme_store::StoreError::SourceLengthMismatch { .. }
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
    assert!(matches!(error, mneme_store::StoreError::PathEscapes(_)));
    assert!(
        mneme_store::blob::read_working_file(temp.path(), "escape.adoc")
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
        mneme_store::StoreError::UnsupportedLayout(_)
    ));
    let empty = tempfile::tempdir().expect("empty");
    assert!(matches!(
        mneme_store::Workspace::open(empty.path(), config(1_000)).expect_err("no ledger"),
        mneme_store::StoreError::UnsupportedLayout(_)
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
    assert!(
        workspace
            .register_projection(mneme_store::ProjectionRegistration {
                name: "orphan".to_owned(),
                revision: mneme_core::WorkspaceRevisionId::from_bytes([0x7f; 16]),
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
        mneme_store::StoreError::InjectedFault(mneme_store::FaultPoint::BeforeFileReplace)
    ));
    assert!(
        mneme_store::blob::read_working_file(temp.path(), "not-written.adoc")
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
        mneme_store::blob::read_working_file(temp.path(), "not-written.adoc").expect("read"),
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
    mneme_store::blob::publish_working_file(temp.path(), "project.adoc", candidate_bytes)
        .expect("file");
    // The record claims a retained source whose bytes do not match the file.
    let wrong = source_draft(
        b"different bytes",
        mneme_core::fixtures::source_revision_id(),
        mneme_core::RevisionId::from_bytes([0x81; 16]),
        None,
        mneme_core::fixtures::entity_id(),
        "project.adoc",
    );
    let error = workspace
        .commit(mneme_store::CommitCommand {
            base: workspace.current_revision().expect("current"),
            actor: "author".to_owned(),
            scope: scope(),
            idempotency_key: "malformed".to_owned(),
            records: vec![wrong],
            source_blobs: Vec::new(),
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
        mneme_store::StoreError::InvalidCandidate { .. }
    ));
    assert_eq!(
        workspace.snapshot().expect("snapshot").revision,
        before.revision
    );
    assert_eq!(
        mneme_store::blob::read_working_file(temp.path(), "project.adoc").expect("read"),
        Some(candidate_bytes.to_vec())
    );
}
