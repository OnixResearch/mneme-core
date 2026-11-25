//! Integration tests for the SQLite metadata projection index and single-record lookup.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

fn scope(local: &str) -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, local).expect("scope")
}

fn rid(byte: u8) -> mneme_core::RecordId {
    mneme_core::RecordId::from_bytes([byte; 16])
}

fn rev(byte: u8) -> mneme_core::RevisionId {
    mneme_core::RevisionId::from_bytes([byte; 16])
}

fn entity_draft(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    predecessor: Option<mneme_core::RevisionId>,
    scope: &mneme_core::ScopeId,
    entity_type: &str,
    label: &str,
    external_id: Option<&str>,
) -> mneme_store::RecordDraft {
    let mut props = Vec::new();
    if let Some(ext) = external_id {
        props.push((
            mneme_core::Symbol::from("external-id"),
            mneme_core::Value::string(ext),
        ));
    }
    mneme_store::RecordDraft {
        schema_version: 3,
        kind: mneme_core::RecordKind::Entity,
        record_id,
        revision_id,
        predecessor,
        scope: scope.clone(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("entity-type"),
                mneme_core::Value::symbol(entity_type),
            ),
            (
                mneme_core::Symbol::from("label"),
                mneme_core::Value::string(label),
            ),
            (
                mneme_core::Symbol::from("properties"),
                mneme_core::Value::symbol_dictionary(props),
            ),
        ]),
    }
}

fn relation_draft(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    predecessor: Option<mneme_core::RevisionId>,
    scope: &mneme_core::ScopeId,
    relation_type: &str,
    from: mneme_core::Reference,
    to: mneme_core::Reference,
) -> mneme_store::RecordDraft {
    mneme_store::RecordDraft {
        schema_version: 3,
        kind: mneme_core::RecordKind::Relation,
        record_id,
        revision_id,
        predecessor,
        scope: scope.clone(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("relation-type"),
                mneme_core::Value::symbol(relation_type),
            ),
            (mneme_core::Symbol::from("from"), from.to_value()),
            (mneme_core::Symbol::from("to"), to.to_value()),
            (
                mneme_core::Symbol::from("properties"),
                mneme_core::Value::symbol_dictionary([]),
            ),
        ]),
    }
}

fn document_draft(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    predecessor: Option<mneme_core::RevisionId>,
    scope: &mneme_core::ScopeId,
    title: &str,
    path: Option<&str>,
    source: mneme_core::Reference,
) -> mneme_store::RecordDraft {
    let mut fields = vec![
        (
            mneme_core::Symbol::from("title"),
            mneme_core::Value::string(title),
        ),
        (
            mneme_core::Symbol::from("source-revision"),
            source.to_value(),
        ),
    ];
    if let Some(path) = path {
        fields.push((
            mneme_core::Symbol::from("path"),
            mneme_core::Value::string(path),
        ));
    }
    mneme_store::RecordDraft {
        schema_version: 3,
        kind: mneme_core::RecordKind::Document,
        record_id,
        revision_id,
        predecessor,
        scope: scope.clone(),
        payload: mneme_core::Payload::new(fields),
    }
}

fn expected_from_snapshot(
    snapshot: &mneme_store::Snapshot,
) -> (
    Vec<mneme_store::EntityMetadata>,
    Vec<mneme_store::RelationMetadata>,
    Vec<mneme_store::DocumentMetadata>,
) {
    let mut entities = Vec::new();
    let mut relations = Vec::new();
    let mut documents = Vec::new();
    for record in &snapshot.records {
        match record.kind {
            mneme_core::RecordKind::Entity => {
                let entity_type = record
                    .payload
                    .get("entity-type")
                    .and_then(mneme_core::Value::as_symbol)
                    .map(|sym| sym.as_str().to_owned())
                    .unwrap_or_default();
                let label = record
                    .payload
                    .get("label")
                    .and_then(mneme_core::Value::as_string)
                    .unwrap_or("")
                    .to_owned();
                let external_id = record
                    .payload
                    .get("properties")
                    .and_then(mneme_core::Value::as_dictionary)
                    .and_then(|dict| dict.get(&mneme_core::Value::symbol("external-id")))
                    .and_then(mneme_core::Value::as_string)
                    .map(str::to_owned);
                entities.push(mneme_store::EntityMetadata {
                    record_id: record.record_id,
                    revision_id: record.revision_id,
                    scope: record.scope.clone(),
                    entity_type,
                    label,
                    external_id,
                });
            }
            mneme_core::RecordKind::Relation => {
                let relation_type = record
                    .payload
                    .get("relation-type")
                    .and_then(mneme_core::Value::as_symbol)
                    .map(|sym| sym.as_str().to_owned())
                    .unwrap_or_default();
                let from_id = record
                    .payload
                    .get("from")
                    .and_then(|v| {
                        mneme_core::Reference::from_value(v, &mneme_core::Path::root()).ok()
                    })
                    .and_then(|r| r.target());
                let to_id = record
                    .payload
                    .get("to")
                    .and_then(|v| {
                        mneme_core::Reference::from_value(v, &mneme_core::Path::root()).ok()
                    })
                    .and_then(|r| r.target());
                relations.push(mneme_store::RelationMetadata {
                    record_id: record.record_id,
                    revision_id: record.revision_id,
                    scope: record.scope.clone(),
                    relation_type,
                    from_id,
                    to_id,
                });
            }
            mneme_core::RecordKind::Document => {
                let title = record
                    .payload
                    .get("title")
                    .and_then(mneme_core::Value::as_string)
                    .unwrap_or("")
                    .to_owned();
                let path = record
                    .payload
                    .get("path")
                    .and_then(mneme_core::Value::as_string)
                    .map(str::to_owned);
                let source_revision_id = record
                    .payload
                    .get("source-revision")
                    .and_then(|v| {
                        mneme_core::Reference::from_value(v, &mneme_core::Path::root()).ok()
                    })
                    .and_then(|r| r.target());
                documents.push(mneme_store::DocumentMetadata {
                    record_id: record.record_id,
                    revision_id: record.revision_id,
                    scope: record.scope.clone(),
                    path,
                    title,
                    source_revision_id,
                });
            }
            _ => {}
        }
    }
    entities.sort_by_key(|e| *e.record_id.as_bytes());
    relations.sort_by_key(|r| *r.record_id.as_bytes());
    documents.sort_by_key(|d| *d.record_id.as_bytes());
    (entities, relations, documents)
}

fn assert_projection_matches_snapshot(workspace: &mneme_store::Workspace) {
    let snapshot = workspace.snapshot().expect("snapshot");
    let (exp_entities, exp_relations, exp_documents) = expected_from_snapshot(&snapshot);
    let entities = workspace
        .query_entities(&mneme_store::EntityQuery::default())
        .expect("query entities");
    assert!(!entities.has_more);
    assert_eq!(entities.items, exp_entities);

    let relations = workspace
        .query_relations(&mneme_store::RelationQuery::default())
        .expect("query relations");
    assert!(!relations.has_more);
    assert_eq!(relations.items, exp_relations);

    let documents = workspace
        .query_documents(&mneme_store::DocumentQuery::default())
        .expect("query documents");
    assert!(!documents.has_more);
    assert_eq!(documents.items, exp_documents);
}

#[test]
fn projection_matches_full_ledger_scan_across_commits_replacements_forget_and_recovery() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace =
        mneme_store::Workspace::create(temp.path(), common::config(1_000)).expect("create");
    let cedar = scope("cedar");
    let maple = scope("maple");

    let e1 = rid(0x10);
    let e2 = rid(0x11);
    let e3 = rid(0x12);
    let r1 = rid(0x20);
    let r2 = rid(0x21);
    let s1 = rid(0x30);
    let s2 = rid(0x31);
    let d1 = rid(0x40);
    let d2 = rid(0x41);

    let bytes_a = b"= Doc A\n\nAlpha.\n";
    let bytes_b = b"= Doc B\n\nBeta.\n";

    let base = workspace.current_revision().expect("base");
    let outcome = workspace
        .commit(mneme_store::CommitCommand {
            base,
            actor: "tester".to_owned(),
            scope: cedar.clone(),
            idempotency_key: "c1".to_owned(),
            records: vec![
                entity_draft(
                    e1,
                    rev(0x01),
                    None,
                    &cedar,
                    "bookmark",
                    "First",
                    Some("bm:1"),
                ),
                entity_draft(e2, rev(0x02), None, &cedar, "topic", "Second", None),
                relation_draft(
                    r1,
                    rev(0x03),
                    None,
                    &cedar,
                    "mentions",
                    mneme_core::Reference::local(e1, mneme_core::RecordKind::Entity),
                    mneme_core::Reference::local(e2, mneme_core::RecordKind::Entity),
                ),
                common::retained_source_record(s1, rev(0x04), &cedar, bytes_a, Some("a.adoc")),
                document_draft(
                    d1,
                    rev(0x05),
                    None,
                    &cedar,
                    "Doc A",
                    Some("notes/a.adoc"),
                    mneme_core::Reference::pinned(
                        s1,
                        rev(0x04),
                        mneme_core::RecordKind::SourceRevision,
                    ),
                ),
            ],
            source_blobs: vec![common::source_blob(bytes_a)],
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit c1");
    assert_projection_matches_snapshot(&workspace);

    // Commit in a second scope + replacement in the first scope.
    let c2 = workspace
        .commit(mneme_store::CommitCommand {
            base: outcome.revision,
            actor: "tester".to_owned(),
            scope: maple.clone(),
            idempotency_key: "c2".to_owned(),
            records: vec![
                entity_draft(
                    e3,
                    rev(0x06),
                    None,
                    &maple,
                    "bookmark",
                    "Third",
                    Some("bm:2"),
                ),
                relation_draft(
                    r2,
                    rev(0x07),
                    None,
                    &maple,
                    "references",
                    mneme_core::Reference::local(e3, mneme_core::RecordKind::Entity),
                    mneme_core::Reference::pinned(e1, rev(0x01), mneme_core::RecordKind::Entity),
                ),
                common::retained_source_record(s2, rev(0x08), &maple, bytes_b, None),
                document_draft(
                    d2,
                    rev(0x09),
                    None,
                    &maple,
                    "Doc B",
                    None,
                    mneme_core::Reference::local(s2, mneme_core::RecordKind::SourceRevision),
                ),
            ],
            source_blobs: vec![common::source_blob(bytes_b)],
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit c2");
    assert_projection_matches_snapshot(&workspace);

    // Replace e1, r1, and d1.
    let c3 = workspace
        .commit(mneme_store::CommitCommand {
            base: c2.revision,
            actor: "tester".to_owned(),
            scope: cedar.clone(),
            idempotency_key: "c3".to_owned(),
            records: vec![
                entity_draft(
                    e1,
                    rev(0x11),
                    Some(rev(0x01)),
                    &cedar,
                    "bookmark",
                    "First Updated",
                    Some("bm:1b"),
                ),
                relation_draft(
                    r1,
                    rev(0x13),
                    Some(rev(0x03)),
                    &cedar,
                    "cites",
                    mneme_core::Reference::local(e2, mneme_core::RecordKind::Entity),
                    mneme_core::Reference::local(e1, mneme_core::RecordKind::Entity),
                ),
                document_draft(
                    d1,
                    rev(0x15),
                    Some(rev(0x05)),
                    &cedar,
                    "Doc A v2",
                    Some("notes/a-v2.adoc"),
                    mneme_core::Reference::pinned(
                        s1,
                        rev(0x04),
                        mneme_core::RecordKind::SourceRevision,
                    ),
                ),
            ],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit c3");
    assert_projection_matches_snapshot(&workspace);

    // Old external_id is gone after replacement; new one resolves.
    assert!(
        workspace
            .query_entities(&mneme_store::EntityQuery {
                external_id: Some("bm:1".to_owned()),
                ..mneme_store::EntityQuery::default()
            })
            .expect("old ext")
            .items
            .is_empty()
    );
    let updated_e1 = workspace
        .query_entities(&mneme_store::EntityQuery {
            external_id: Some("bm:1b".to_owned()),
            ..mneme_store::EntityQuery::default()
        })
        .expect("new ext");
    assert_eq!(updated_e1.items.len(), 1);
    assert_eq!(updated_e1.items[0].label, "First Updated");

    // Forget e3 via a retention barrier commit.
    let next_gen = c3.eligibility_generation + 1;
    let retention = mneme_store::RetentionCommit {
        operation_id: "forget-e3".to_owned(),
        operation_kind: "forget".to_owned(),
        policy_version: "v1".to_owned(),
        retained_metadata: vec!["forget e3".to_owned()],
        selectors: vec![mneme_store::RetentionSelector {
            ordinal: 0,
            kind: "assertion".to_owned(),
            target: Some(e3),
            revision: None,
            digest: None,
        }],
        suppressions: vec![mneme_store::RetentionSuppression {
            operation_id: "forget-e3".to_owned(),
            target: e3,
            revision: None,
            target_kind: "entity".to_owned(),
            mode: mneme_store::SuppressionMode::Forgotten,
            content_digest: None,
            generation: next_gen,
        }],
        locations: Vec::new(),
    };
    workspace
        .commit(mneme_store::CommitCommand {
            base: c3.revision,
            actor: "tester".to_owned(),
            scope: maple.clone(),
            idempotency_key: "c4-forget".to_owned(),
            records: Vec::new(),
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: Some(retention),
        })
        .expect("commit forget");
    assert_projection_matches_snapshot(&workspace);
    assert!(
        workspace
            .query_entities(&mneme_store::EntityQuery {
                external_id: Some("bm:2".to_owned()),
                ..mneme_store::EntityQuery::default()
            })
            .expect("forgotten ext")
            .items
            .is_empty()
    );

    // Recover rebuilds deterministically and continues to match snapshot.
    workspace.recover().expect("recover");
    assert_projection_matches_snapshot(&workspace);
}

#[test]
fn bounded_paging_and_filters_return_exact_subsets() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace =
        mneme_store::Workspace::create(temp.path(), common::config(1_000)).expect("create");
    let cedar = scope("cedar");
    let base = workspace.current_revision().expect("base");
    let drafts = (1_u8..=5)
        .map(|i| {
            entity_draft(
                rid(i),
                rev(i + 0x20),
                None,
                &cedar,
                if i % 2 == 0 { "person" } else { "bookmark" },
                &format!("Entity {i}"),
                Some(&format!("ext:{i}")),
            )
        })
        .collect();
    workspace
        .commit(mneme_store::CommitCommand {
            base,
            actor: "tester".to_owned(),
            scope: cedar.clone(),
            idempotency_key: "batch-5".to_owned(),
            records: drafts,
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit");

    let mut collected = Vec::new();
    let mut after = None;
    loop {
        let page = workspace
            .query_entities(&mneme_store::EntityQuery {
                scope: Some(cedar.clone()),
                after,
                limit: Some(2),
                ..mneme_store::EntityQuery::default()
            })
            .expect("page");
        collected.extend(page.items);
        if !page.has_more {
            assert!(page.next_after.is_none());
            break;
        }
        assert!(page.next_after.is_some());
        after = page.next_after;
    }
    assert_eq!(collected.len(), 5);
    assert_eq!(
        collected.iter().map(|e| e.record_id).collect::<Vec<_>>(),
        vec![rid(1), rid(2), rid(3), rid(4), rid(5)]
    );

    let people = workspace
        .query_entities(&mneme_store::EntityQuery {
            entity_type: Some("person".to_owned()),
            ..mneme_store::EntityQuery::default()
        })
        .expect("filter type");
    assert_eq!(people.items.len(), 2);

    assert!(matches!(
        workspace.query_entities(&mneme_store::EntityQuery {
            limit: Some(0),
            ..mneme_store::EntityQuery::default()
        }),
        Err(mneme_store::Failure::InvalidCommand(_))
    ));
    assert!(matches!(
        workspace.query_entities(&mneme_store::EntityQuery {
            limit: Some(mneme_store::MAX_METADATA_PAGE_SIZE + 1),
            ..mneme_store::EntityQuery::default()
        }),
        Err(mneme_store::Failure::InvalidCommand(_))
    ));
}

#[test]
fn current_record_reads_only_requested_blob_and_respects_suppression() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace =
        mneme_store::Workspace::create(temp.path(), common::config(1_000)).expect("create");
    let cedar = scope("cedar");
    let e1 = rid(0x51);
    let e2 = rid(0x52);
    let base = workspace.current_revision().expect("base");
    let draft1 = entity_draft(e1, rev(0x61), None, &cedar, "topic", "Keep", Some("keep:1"));
    let draft2 = entity_draft(
        e2,
        rev(0x62),
        None,
        &cedar,
        "topic",
        "RemoveBlob",
        Some("drop:2"),
    );
    let outcome = workspace
        .commit(mneme_store::CommitCommand {
            base,
            actor: "tester".to_owned(),
            scope: cedar.clone(),
            idempotency_key: "two-entities".to_owned(),
            records: vec![draft1, draft2],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit");

    // Delete e2's envelope blob file on disk to prove current_record(e1) does not
    // scan unrelated blobs (whereas a full snapshot load fails).
    let e2_envelope = workspace
        .current_record(e2)
        .expect("read e2")
        .expect("e2 exists");
    let e2_blob_path = mneme_store::payload::blob_path(temp.path(), e2_envelope.full_digest());
    let e2_blob_bytes = std::fs::read(&e2_blob_path).expect("read e2 blob bytes");
    std::fs::remove_file(&e2_blob_path).expect("remove e2 blob");

    assert!(workspace.snapshot().is_err());

    let e1_loaded = workspace
        .current_record(e1)
        .expect("read e1 without scanning e2")
        .expect("e1 exists");
    assert_eq!(e1_loaded.record_id, e1);
    assert_eq!(
        e1_loaded
            .payload
            .get("label")
            .and_then(mneme_core::Value::as_string),
        Some("Keep")
    );
    assert!(
        workspace
            .current_record(rid(0x99))
            .expect("missing")
            .is_none()
    );

    // Restore e2's blob, then forget e1 and confirm current_record refuses it.
    std::fs::write(&e2_blob_path, &e2_blob_bytes).expect("restore e2 blob");
    let next_gen = outcome.eligibility_generation + 1;
    workspace
        .commit(mneme_store::CommitCommand {
            base: outcome.revision,
            actor: "tester".to_owned(),
            scope: cedar,
            idempotency_key: "forget-e1".to_owned(),
            records: Vec::new(),
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: Some(mneme_store::RetentionCommit {
                operation_id: "forget-e1".to_owned(),
                operation_kind: "forget".to_owned(),
                policy_version: "v1".to_owned(),
                retained_metadata: vec!["forget e1".to_owned()],
                selectors: vec![mneme_store::RetentionSelector {
                    ordinal: 0,
                    kind: "assertion".to_owned(),
                    target: Some(e1),
                    revision: None,
                    digest: None,
                }],
                suppressions: vec![mneme_store::RetentionSuppression {
                    operation_id: "forget-e1".to_owned(),
                    target: e1,
                    revision: None,
                    target_kind: "entity".to_owned(),
                    mode: mneme_store::SuppressionMode::Forgotten,
                    content_digest: None,
                    generation: next_gen,
                }],
                locations: Vec::new(),
            }),
        })
        .expect("forget");

    assert!(matches!(
        workspace.current_record(e1),
        Err(mneme_store::Failure::RetentionSuppressed { .. })
    ));
}

#[test]
fn restore_suppression_ledger_gates_reads_and_purges_projection() {
    let temp_orig = tempfile::tempdir().expect("orig");
    let temp_copy = tempfile::tempdir().expect("copy");
    let mut orig =
        mneme_store::Workspace::create(temp_orig.path(), common::config(1_000)).expect("create");
    let cedar = scope("cedar");
    let e1 = rid(0x71);
    let base = orig.current_revision().expect("base");
    let committed = orig
        .commit(mneme_store::CommitCommand {
            base,
            actor: "tester".to_owned(),
            scope: cedar.clone(),
            idempotency_key: "seed-restore".to_owned(),
            records: vec![entity_draft(
                e1,
                rev(0x81),
                None,
                &cedar,
                "bookmark",
                "Secret",
                Some("sec:1"),
            )],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit");

    // Copy pre-forget workspace to temp_copy before forgetting e1 on orig.
    fn copy_dir(src: &std::path::Path, dst: &std::path::Path) {
        std::fs::create_dir_all(dst).expect("mkdir");
        for entry in std::fs::read_dir(src).expect("readdir") {
            let entry = entry.expect("entry");
            let ty = entry.file_type().expect("type");
            let from = entry.path();
            let to = dst.join(entry.file_name());
            if ty.is_dir() {
                copy_dir(&from, &to);
            } else {
                std::fs::copy(&from, &to).expect("copy");
            }
        }
    }
    copy_dir(temp_orig.path(), temp_copy.path());

    let next_gen = committed.eligibility_generation + 1;
    orig.commit(mneme_store::CommitCommand {
        base: committed.revision,
        actor: "tester".to_owned(),
        scope: cedar,
        idempotency_key: "forget-secret".to_owned(),
        records: Vec::new(),
        source_blobs: Vec::new(),
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: Some(mneme_store::RetentionCommit {
            operation_id: "forget-sec".to_owned(),
            operation_kind: "forget".to_owned(),
            policy_version: "v1".to_owned(),
            retained_metadata: vec!["forget sec".to_owned()],
            selectors: vec![mneme_store::RetentionSelector {
                ordinal: 0,
                kind: "assertion".to_owned(),
                target: Some(e1),
                revision: None,
                digest: None,
            }],
            suppressions: vec![mneme_store::RetentionSuppression {
                operation_id: "forget-sec".to_owned(),
                target: e1,
                revision: None,
                target_kind: "entity".to_owned(),
                mode: mneme_store::SuppressionMode::Forgotten,
                content_digest: None,
                generation: next_gen,
            }],
            locations: Vec::new(),
        }),
    })
    .expect("forget");
    let ledger = orig.export_suppression_ledger().expect("export ledger");

    let mut restored =
        mneme_store::Workspace::open_restored(temp_copy.path(), common::config(2_000))
            .expect("open_restored");
    assert!(matches!(
        restored.query_entities(&mneme_store::EntityQuery::default()),
        Err(mneme_store::Failure::MissingRetentionState { .. })
    ));
    assert!(matches!(
        restored.current_record(e1),
        Err(mneme_store::Failure::MissingRetentionState { .. })
    ));

    restored
        .apply_restore_suppression_ledger(&ledger)
        .expect("apply ledger");
    let entities = restored
        .query_entities(&mneme_store::EntityQuery::default())
        .expect("query after restore");
    assert!(entities.items.is_empty());
}
