//! Integration tests for the SQLite metadata projection index and single-record lookup.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::unwrap_used, clippy::expect_used)] // test fixtures fail fast on unexpected setup errors

fn scope(local: &str) -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, local).expect("scope")
}

fn config(at_ns: i64) -> mneme_store::WorkspaceConfig {
    mneme_store::WorkspaceConfig {
        clock: Box::new(mneme_store::FixedClock::new(
            mneme_core::Timestamp::from_nanos(at_ns),
        )),
        faults: Box::new(mneme_store::NoFaults),
    }
}

fn rid(byte: u8) -> mneme_core::RecordId {
    mneme_core::RecordId::from_bytes([byte; 16])
}

fn rev(byte: u8) -> mneme_core::RevisionId {
    mneme_core::RevisionId::from_bytes([byte; 16])
}

struct EntityDraft<'a> {
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    predecessor: Option<mneme_core::RevisionId>,
    scope: &'a mneme_core::ScopeId,
    entity_type: &'a str,
    label: &'a str,
    external_id: Option<&'a str>,
}

fn entity_draft(input: EntityDraft<'_>) -> mneme_store::RecordDraft {
    assert!(!input.entity_type.is_empty());
    assert!(!input.label.is_empty());
    let mut props = Vec::new();
    if let Some(ext) = input.external_id {
        props.push((
            mneme_core::Symbol::from("external-id"),
            mneme_core::Value::string(ext),
        ));
    }
    mneme_store::RecordDraft {
        schema_version: 3,
        kind: mneme_core::RecordKind::Entity,
        record_id: input.record_id,
        revision_id: input.revision_id,
        predecessor: input.predecessor,
        scope: input.scope.clone(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("entity-type"),
                mneme_core::Value::symbol(input.entity_type),
            ),
            (
                mneme_core::Symbol::from("label"),
                mneme_core::Value::string(input.label),
            ),
            (
                mneme_core::Symbol::from("properties"),
                mneme_core::Value::symbol_dictionary(props),
            ),
        ]),
    }
}

struct RelationDraft<'a> {
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    predecessor: Option<mneme_core::RevisionId>,
    scope: &'a mneme_core::ScopeId,
    relation_type: &'a str,
    from: mneme_core::Reference,
    to: mneme_core::Reference,
}

fn relation_draft(input: RelationDraft<'_>) -> mneme_store::RecordDraft {
    mneme_store::RecordDraft {
        schema_version: 3,
        kind: mneme_core::RecordKind::Relation,
        record_id: input.record_id,
        revision_id: input.revision_id,
        predecessor: input.predecessor,
        scope: input.scope.clone(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("relation-type"),
                mneme_core::Value::symbol(input.relation_type),
            ),
            (mneme_core::Symbol::from("from"), input.from.to_value()),
            (mneme_core::Symbol::from("to"), input.to.to_value()),
            (
                mneme_core::Symbol::from("properties"),
                mneme_core::Value::symbol_dictionary([]),
            ),
        ]),
    }
}

struct DocumentDraft<'a> {
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    predecessor: Option<mneme_core::RevisionId>,
    scope: &'a mneme_core::ScopeId,
    title: &'a str,
    path: Option<&'a str>,
    source: mneme_core::Reference,
}

fn document_draft(input: DocumentDraft<'_>) -> mneme_store::RecordDraft {
    assert!(!input.title.is_empty());
    assert!(input.source.target().is_some());
    let mut fields = vec![
        (
            mneme_core::Symbol::from("title"),
            mneme_core::Value::string(input.title),
        ),
        (
            mneme_core::Symbol::from("source-revision"),
            input.source.to_value(),
        ),
    ];
    if let Some(path) = input.path {
        fields.push((
            mneme_core::Symbol::from("path"),
            mneme_core::Value::string(path),
        ));
    }
    mneme_store::RecordDraft {
        schema_version: 3,
        kind: mneme_core::RecordKind::Document,
        record_id: input.record_id,
        revision_id: input.revision_id,
        predecessor: input.predecessor,
        scope: input.scope.clone(),
        payload: mneme_core::Payload::new(fields),
    }
}

fn retained_source_record(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    bytes: &[u8],
    path: Option<&str>,
) -> mneme_store::RecordDraft {
    assert!(!bytes.is_empty());
    assert!(!scope.local().is_empty());
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

fn source_blob(bytes: &[u8]) -> mneme_store::SourceBlobDraft {
    mneme_store::SourceBlobDraft {
        bytes: bytes.to_vec(),
        media_type: mneme_core::Symbol::from("text/asciidoc"),
    }
}

fn entity_from_envelope(record: &mneme_core::RecordEnvelope) -> mneme_store::EntityMetadata {
    assert_eq!(record.kind, mneme_core::RecordKind::Entity);
    let entity_type = record
        .payload
        .get("entity-type")
        .and_then(mneme_core::Value::as_symbol)
        .map(|sym| sym.as_str().to_owned())
        .unwrap_or_default();
    assert!(!entity_type.is_empty());
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
    mneme_store::EntityMetadata {
        record_id: record.record_id,
        revision_id: record.revision_id,
        scope: record.scope.clone(),
        entity_type,
        label,
        external_id,
    }
}

fn relation_from_envelope(record: &mneme_core::RecordEnvelope) -> mneme_store::RelationMetadata {
    assert_eq!(record.kind, mneme_core::RecordKind::Relation);
    let relation_type = record
        .payload
        .get("relation-type")
        .and_then(mneme_core::Value::as_symbol)
        .map(|sym| sym.as_str().to_owned())
        .unwrap_or_default();
    assert!(!relation_type.is_empty());
    let from_id = record
        .payload
        .get("from")
        .and_then(|v| mneme_core::Reference::from_value(v, &mneme_core::Path::root()).ok())
        .and_then(|r| r.target());
    let to_id = record
        .payload
        .get("to")
        .and_then(|v| mneme_core::Reference::from_value(v, &mneme_core::Path::root()).ok())
        .and_then(|r| r.target());
    mneme_store::RelationMetadata {
        record_id: record.record_id,
        revision_id: record.revision_id,
        scope: record.scope.clone(),
        relation_type,
        from_id,
        to_id,
    }
}

fn document_from_envelope(record: &mneme_core::RecordEnvelope) -> mneme_store::DocumentMetadata {
    assert_eq!(record.kind, mneme_core::RecordKind::Document);
    let title = record
        .payload
        .get("title")
        .and_then(mneme_core::Value::as_string)
        .unwrap_or("")
        .to_owned();
    assert!(!title.is_empty());
    let path = record
        .payload
        .get("path")
        .and_then(mneme_core::Value::as_string)
        .map(str::to_owned);
    let source_revision_id = record
        .payload
        .get("source-revision")
        .and_then(|v| mneme_core::Reference::from_value(v, &mneme_core::Path::root()).ok())
        .and_then(|r| r.target());
    mneme_store::DocumentMetadata {
        record_id: record.record_id,
        revision_id: record.revision_id,
        scope: record.scope.clone(),
        path,
        title,
        source_revision_id,
    }
}

fn expected_from_snapshot(
    snapshot: &mneme_store::Snapshot,
) -> (
    Vec<mneme_store::EntityMetadata>,
    Vec<mneme_store::RelationMetadata>,
    Vec<mneme_store::DocumentMetadata>,
) {
    assert!(!snapshot.records.is_empty());
    let mut entities: Vec<_> = snapshot
        .records
        .iter()
        .filter(|r| r.kind == mneme_core::RecordKind::Entity)
        .map(entity_from_envelope)
        .collect();
    let mut relations: Vec<_> = snapshot
        .records
        .iter()
        .filter(|r| r.kind == mneme_core::RecordKind::Relation)
        .map(relation_from_envelope)
        .collect();
    let mut documents: Vec<_> = snapshot
        .records
        .iter()
        .filter(|r| r.kind == mneme_core::RecordKind::Document)
        .map(document_from_envelope)
        .collect();
    entities.sort_by_key(|e| *e.record_id.as_bytes());
    relations.sort_by_key(|r| *r.record_id.as_bytes());
    documents.sort_by_key(|d| *d.record_id.as_bytes());
    assert!(
        entities
            .len()
            .saturating_add(relations.len())
            .saturating_add(documents.len())
            <= snapshot.records.len()
    );
    (entities, relations, documents)
}

fn all_entity_query() -> mneme_store::EntityQuery {
    mneme_store::EntityQuery {
        scope: None,
        entity_type: None,
        external_id: None,
        after: None,
        limit: None,
    }
}

fn assert_projection_matches_snapshot(workspace: &mneme_store::Workspace) {
    let snapshot = workspace.snapshot().expect("snapshot");
    let (exp_entities, exp_relations, exp_documents) = expected_from_snapshot(&snapshot);
    let entities = workspace
        .query_entities(&all_entity_query())
        .expect("query entities");
    assert!(!entities.has_more);
    assert_eq!(entities.items, exp_entities);

    let relations = workspace
        .query_relations(&mneme_store::RelationQuery {
            scope: None,
            relation_type: None,
            from_id: None,
            to_id: None,
            after: None,
            limit: None,
        })
        .expect("query relations");
    assert!(!relations.has_more);
    assert_eq!(relations.items, exp_relations);

    let documents = workspace
        .query_documents(&mneme_store::DocumentQuery {
            scope: None,
            path: None,
            after: None,
            limit: None,
        })
        .expect("query documents");
    assert!(!documents.has_more);
    assert_eq!(documents.items, exp_documents);
}

#[test]
fn projection_matches_full_ledger_scan_across_commits_replacements_forget_and_recovery() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
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
                entity_draft(EntityDraft {
                    record_id: e1,
                    revision_id: rev(0x01),
                    predecessor: None,
                    scope: &cedar,
                    entity_type: "bookmark",
                    label: "First",
                    external_id: Some("bm:1"),
                }),
                entity_draft(EntityDraft {
                    record_id: e2,
                    revision_id: rev(0x02),
                    predecessor: None,
                    scope: &cedar,
                    entity_type: "topic",
                    label: "Second",
                    external_id: None,
                }),
                relation_draft(RelationDraft {
                    record_id: r1,
                    revision_id: rev(0x03),
                    predecessor: None,
                    scope: &cedar,
                    relation_type: "mentions",
                    from: mneme_core::Reference::local(e1, mneme_core::RecordKind::Entity),
                    to: mneme_core::Reference::local(e2, mneme_core::RecordKind::Entity),
                }),
                retained_source_record(s1, rev(0x04), &cedar, bytes_a, Some("a.adoc")),
                document_draft(DocumentDraft {
                    record_id: d1,
                    revision_id: rev(0x05),
                    predecessor: None,
                    scope: &cedar,
                    title: "Doc A",
                    path: Some("notes/a.adoc"),
                    source: mneme_core::Reference::pinned(
                        s1,
                        rev(0x04),
                        mneme_core::RecordKind::SourceRevision,
                    ),
                }),
            ],
            source_blobs: vec![source_blob(bytes_a)],
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit c1");
    assert_projection_matches_snapshot(&workspace);

    let c2 = workspace
        .commit(mneme_store::CommitCommand {
            base: outcome.revision,
            actor: "tester".to_owned(),
            scope: maple.clone(),
            idempotency_key: "c2".to_owned(),
            records: vec![
                entity_draft(EntityDraft {
                    record_id: e3,
                    revision_id: rev(0x06),
                    predecessor: None,
                    scope: &maple,
                    entity_type: "bookmark",
                    label: "Third",
                    external_id: Some("bm:2"),
                }),
                relation_draft(RelationDraft {
                    record_id: r2,
                    revision_id: rev(0x07),
                    predecessor: None,
                    scope: &maple,
                    relation_type: "references",
                    from: mneme_core::Reference::local(e3, mneme_core::RecordKind::Entity),
                    to: mneme_core::Reference::pinned(
                        e1,
                        rev(0x01),
                        mneme_core::RecordKind::Entity,
                    ),
                }),
                retained_source_record(s2, rev(0x08), &maple, bytes_b, None),
                document_draft(DocumentDraft {
                    record_id: d2,
                    revision_id: rev(0x09),
                    predecessor: None,
                    scope: &maple,
                    title: "Doc B",
                    path: None,
                    source: mneme_core::Reference::local(
                        s2,
                        mneme_core::RecordKind::SourceRevision,
                    ),
                }),
            ],
            source_blobs: vec![source_blob(bytes_b)],
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit c2");
    assert_projection_matches_snapshot(&workspace);

    let c3 = workspace
        .commit(mneme_store::CommitCommand {
            base: c2.revision,
            actor: "tester".to_owned(),
            scope: cedar.clone(),
            idempotency_key: "c3".to_owned(),
            records: vec![
                entity_draft(EntityDraft {
                    record_id: e1,
                    revision_id: rev(0x11),
                    predecessor: Some(rev(0x01)),
                    scope: &cedar,
                    entity_type: "bookmark",
                    label: "First Updated",
                    external_id: Some("bm:1b"),
                }),
                relation_draft(RelationDraft {
                    record_id: r1,
                    revision_id: rev(0x13),
                    predecessor: Some(rev(0x03)),
                    scope: &cedar,
                    relation_type: "cites",
                    from: mneme_core::Reference::local(e2, mneme_core::RecordKind::Entity),
                    to: mneme_core::Reference::local(e1, mneme_core::RecordKind::Entity),
                }),
                document_draft(DocumentDraft {
                    record_id: d1,
                    revision_id: rev(0x15),
                    predecessor: Some(rev(0x05)),
                    scope: &cedar,
                    title: "Doc A v2",
                    path: Some("notes/a-v2.adoc"),
                    source: mneme_core::Reference::pinned(
                        s1,
                        rev(0x04),
                        mneme_core::RecordKind::SourceRevision,
                    ),
                }),
            ],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit c3");
    assert_projection_matches_snapshot(&workspace);

    assert!(
        workspace
            .query_entities(&mneme_store::EntityQuery {
                scope: None,
                entity_type: None,
                external_id: Some("bm:1".to_owned()),
                after: None,
                limit: None,
            })
            .expect("old ext")
            .items
            .is_empty()
    );
    let updated_e1 = workspace
        .query_entities(&mneme_store::EntityQuery {
            scope: None,
            entity_type: None,
            external_id: Some("bm:1b".to_owned()),
            after: None,
            limit: None,
        })
        .expect("new ext");
    assert_eq!(updated_e1.items.len(), 1);
    assert_eq!(updated_e1.items[0].label, "First Updated");

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
                scope: None,
                entity_type: None,
                external_id: Some("bm:2".to_owned()),
                after: None,
                limit: None,
            })
            .expect("forgotten ext")
            .items
            .is_empty()
    );

    workspace.recover().expect("recover");
    assert_projection_matches_snapshot(&workspace);
}

#[test]
fn bounded_paging_and_filters_return_exact_subsets() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let cedar = scope("cedar");
    let base = workspace.current_revision().expect("base");
    let drafts = (1_u8..=5)
        .map(|i| {
            entity_draft(EntityDraft {
                record_id: rid(i),
                revision_id: rev(i + 0x20),
                predecessor: None,
                scope: &cedar,
                entity_type: if i % 2 == 0 { "person" } else { "bookmark" },
                label: &format!("Entity {i}"),
                external_id: Some(&format!("ext:{i}")),
            })
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

    let mut collected = Vec::with_capacity(5);
    let mut after = None;
    for _ in 0..10 {
        let page = workspace
            .query_entities(&mneme_store::EntityQuery {
                scope: Some(cedar.clone()),
                entity_type: None,
                external_id: None,
                after,
                limit: Some(2),
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
            scope: None,
            entity_type: Some("person".to_owned()),
            external_id: None,
            after: None,
            limit: None,
        })
        .expect("filter type");
    assert_eq!(people.items.len(), 2);

    assert!(matches!(
        workspace.query_entities(&mneme_store::EntityQuery {
            scope: None,
            entity_type: None,
            external_id: None,
            after: None,
            limit: Some(0),
        }),
        Err(mneme_store::Failure::InvalidCommand(_))
    ));
    assert!(matches!(
        workspace.query_entities(&mneme_store::EntityQuery {
            scope: None,
            entity_type: None,
            external_id: None,
            after: None,
            limit: Some(mneme_store::MAX_METADATA_PAGE_SIZE + 1),
        }),
        Err(mneme_store::Failure::InvalidCommand(_))
    ));
}

#[test]
fn current_record_reads_only_requested_blob_and_respects_suppression() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let cedar = scope("cedar");
    let e1 = rid(0x51);
    let e2 = rid(0x52);
    let base = workspace.current_revision().expect("base");
    let draft1 = entity_draft(EntityDraft {
        record_id: e1,
        revision_id: rev(0x61),
        predecessor: None,
        scope: &cedar,
        entity_type: "topic",
        label: "Keep",
        external_id: Some("keep:1"),
    });
    let draft2 = entity_draft(EntityDraft {
        record_id: e2,
        revision_id: rev(0x62),
        predecessor: None,
        scope: &cedar,
        entity_type: "topic",
        label: "RemoveBlob",
        external_id: Some("drop:2"),
    });
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

fn copy_workspace_tree(src: &std::path::Path, dst: &std::path::Path) {
    let mut pending = vec![(src.to_path_buf(), dst.to_path_buf())];
    while let Some((from_dir, to_dir)) = pending.pop() {
        std::fs::create_dir_all(&to_dir).expect("mkdir");
        for entry in std::fs::read_dir(&from_dir).expect("readdir") {
            let entry = entry.expect("entry");
            let ty = entry.file_type().expect("type");
            let from = entry.path();
            let to = to_dir.join(entry.file_name());
            if ty.is_dir() {
                pending.push((from, to));
            } else {
                std::fs::copy(&from, &to).expect("copy");
            }
        }
    }
}

#[test]
fn restore_suppression_ledger_gates_reads_and_purges_projection() {
    let temp_orig = tempfile::tempdir().expect("orig");
    let temp_copy = tempfile::tempdir().expect("copy");
    let mut orig = mneme_store::Workspace::create(temp_orig.path(), config(1_000)).expect("create");
    let cedar = scope("cedar");
    let e1 = rid(0x71);
    let base = orig.current_revision().expect("base");
    let committed = orig
        .commit(mneme_store::CommitCommand {
            base,
            actor: "tester".to_owned(),
            scope: cedar.clone(),
            idempotency_key: "seed-restore".to_owned(),
            records: vec![entity_draft(EntityDraft {
                record_id: e1,
                revision_id: rev(0x81),
                predecessor: None,
                scope: &cedar,
                entity_type: "bookmark",
                label: "Secret",
                external_id: Some("sec:1"),
            })],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit");

    copy_workspace_tree(temp_orig.path(), temp_copy.path());

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
        mneme_store::Workspace::open_restored(temp_copy.path(), config(2_000)).expect("restored");
    assert!(matches!(
        restored.query_entities(&all_entity_query()),
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
        .query_entities(&all_entity_query())
        .expect("query after restore");
    assert!(entities.items.is_empty());
}
