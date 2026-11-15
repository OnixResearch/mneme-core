//! Cross-device forget barriers survive delayed and replayed signed bundles.
#![allow(unknown_lints, no_unwrap)] // test inputs are deterministic fixtures
#![allow(clippy::unwrap_used, clippy::expect_used)]

fn config() -> mneme_store::WorkspaceConfig {
    mneme_store::WorkspaceConfig {
        clock: Box::new(mneme_store::FixedClock::new(
            mneme_core::Timestamp::from_nanos(1_000),
        )),
        faults: Box::new(mneme_store::NoFaults),
    }
}

fn workspace(root: &std::path::Path) -> mneme_store::Workspace {
    mneme_store::Workspace::create(root, config()).expect("workspace")
}

fn draft(record: &mneme_core::RecordEnvelope) -> mneme_store::RecordDraft {
    mneme_store::RecordDraft {
        schema_version: record.schema_version,
        kind: record.kind,
        record_id: record.record_id,
        revision_id: record.revision_id,
        predecessor: record.predecessor,
        scope: record.scope.clone(),
        payload: record.payload.clone(),
    }
}

fn scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
}

fn rid(byte: u8) -> mneme_core::RecordId {
    mneme_core::RecordId::from_bytes([byte; 16])
}

fn rev(byte: u8) -> mneme_core::RevisionId {
    mneme_core::RevisionId::from_bytes([byte; 16])
}

fn commit_entity(workspace: &mut mneme_store::Workspace, scope: &mneme_core::ScopeId) {
    mneme_memory::Engine::new(workspace, mneme_memory::Access::Operator)
        .commit(mneme_memory::Batch {
            actor: "device-owner".to_owned(),
            scope: scope.clone(),
            idempotency_key: "seed-exchange-entity".to_owned(),
            records: vec![draft(&mneme_core::fixtures::entity())],
            source_blobs: Vec::new(),
            publications: Vec::new(),
        })
        .expect("valid fixture entity");
}

fn commit_source(workspace: &mut mneme_store::Workspace, scope: &mneme_core::ScopeId) {
    let (source, blob) = mneme_memory::build_source(
        rid(0x02),
        rev(0x52),
        scope,
        mneme_memory::SourceOptions {
            bytes: mneme_core::fixtures::SOURCE_TEXT.as_bytes(),
            media_type: "text/asciidoc",
            entity: Some(mneme_core::fixtures::entity_id()),
            path_hint: Some("project.adoc"),
        },
    )
    .expect("source record");
    mneme_memory::Engine::new(workspace, mneme_memory::Access::Operator)
        .commit(mneme_memory::Batch {
            actor: "device-owner".to_owned(),
            scope: scope.clone(),
            idempotency_key: "seed-exchange-source".to_owned(),
            records: vec![source],
            source_blobs: vec![blob],
            publications: Vec::new(),
        })
        .expect("valid source");
}

fn commit_claim(workspace: &mut mneme_store::Workspace, scope: &mneme_core::ScopeId) {
    let evidence_id = rid(0x80);
    let assertion_id = rid(0x82);
    let evidence = mneme_memory::build_evidence(
        evidence_id,
        rev(0x81),
        scope,
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: rid(0x02),
            source_revision: rev(0x52),
            span: None,
            anchor: Some("storage-decision"),
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let assertion = mneme_memory::build_proposed_assertion(
        assertion_id,
        rev(0x83),
        scope,
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "exchange-forget-test",
            value: mneme_core::Value::string("shared claim"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "device-owner",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                evidence_id,
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    mneme_memory::Engine::new(workspace, mneme_memory::Access::Operator)
        .commit(mneme_memory::Batch {
            actor: "device-owner".to_owned(),
            scope: scope.clone(),
            idempotency_key: "seed-exchange-claim".to_owned(),
            records: vec![evidence, assertion],
            source_blobs: Vec::new(),
            publications: Vec::new(),
        })
        .expect("valid authored claim");
}

fn seed_origin(workspace: &mut mneme_store::Workspace) {
    let scope = scope();
    commit_entity(workspace, &scope);
    commit_source(workspace, &scope);
    commit_claim(workspace, &scope);
}

fn forget_source(workspace: &mut mneme_store::Workspace) {
    let request = mneme_retention::Request {
        actor: "device-owner".to_owned(),
        scope: scope(),
        base_revision: workspace.current_revision().expect("base"),
        idempotency_key: "forget-exchange-source".to_owned(),
        operation: mneme_retention::OperationKind::Forget,
        selector: mneme_retention::Selector::Source(rid(0x02)),
        effective: None,
        policy: mneme_retention::Policy {
            version: mneme_retention::POLICY_VERSION.to_owned(),
            retain_assertion_after_prune: true,
            block_content_replay: true,
            retain_withdrawn_evidence_metadata: true,
        },
    };
    mneme_retention::Engine::new(workspace)
        .execute(request)
        .expect("forget source");
}

fn policy(secret: &[u8; 32]) -> mneme_memory::exchange::Policy {
    mneme_memory::exchange::Policy::new([mneme_memory::exchange::Peer {
        issuer: "device-a".to_owned(),
        public_key: mneme_memory::exchange::public_key(secret),
    }])
    .expect("peer trust")
}

fn authenticate(
    document: &str,
    policy: &mneme_memory::exchange::Policy,
) -> mneme_memory::exchange::AuthenticatedBundle {
    mneme_memory::exchange::authenticate_json(document.as_bytes(), policy)
        .expect("authenticated exchange bundle")
}

fn assert_records_absent(workspace: &mut mneme_store::Workspace) {
    let view = mneme_memory::Engine::new(workspace, mneme_memory::Access::Operator)
        .view()
        .expect("workspace view");
    assert!(matches!(
        view.source_status(rid(0x02)),
        Err(mneme_memory::EvidenceError::Missing { .. })
    ));
    assert!(matches!(
        view.assertion(rid(0x82)),
        Err(mneme_memory::EvidenceError::Missing { .. })
    ));
}

#[test]
fn forgotten_barrier_blocks_a_delayed_bundle_when_target_is_absent() {
    let origin_temp = tempfile::tempdir().expect("origin directory");
    let mut origin = workspace(origin_temp.path());
    seed_origin(&mut origin);
    let secret = [0xb3; 32];
    let old_document = mneme_memory::exchange::export_workspace(&origin, "device-a", &secret)
        .expect("pre-forget bundle");
    forget_source(&mut origin);
    let current_document = mneme_memory::exchange::export_workspace(&origin, "device-a", &secret)
        .expect("bundle with forget barrier");

    let current_policy = policy(&secret);
    let current = authenticate(&current_document, &current_policy);
    let forgotten_digest = mneme_core::hashing::ContentDigest::of_source_bytes(
        mneme_core::fixtures::SOURCE_TEXT.as_bytes(),
    );
    assert!(
        current
            .barriers()
            .iter()
            .any(|barrier| barrier.content_digest == Some(forgotten_digest))
    );
    let receiver_temp = tempfile::tempdir().expect("receiver directory");
    let mut receiver = workspace(receiver_temp.path());
    for barrier in current.barriers() {
        mneme_retention::Engine::new(&mut receiver)
            .apply_exchange_barrier("device-a", barrier)
            .expect("commit content-bound tombstone");
    }

    let delayed = authenticate(&old_document, &current_policy);
    mneme_memory::exchange::import_records(&mut receiver, delayed, "local-reviewer")
        .expect("old signed bundle is safely blocked");
    assert_records_absent(&mut receiver);

    let replay = authenticate(&old_document, &current_policy);
    mneme_memory::exchange::import_records(&mut receiver, replay, "local-reviewer")
        .expect("replayed bundle remains blocked");
    assert_records_absent(&mut receiver);
}
