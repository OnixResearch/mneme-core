//! Half-open valid-time expiry handoff tests for `mneme-retention`.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::unwrap_used, clippy::expect_used)] // test/fixture code fails by panic, not a production path

fn scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "bitemporal-ret").expect("scope")
}

fn rid(byte: u8) -> mneme_core::RecordId {
    mneme_core::RecordId::from_bytes([byte; 16])
}

fn rev(byte: u8) -> mneme_core::RevisionId {
    mneme_core::RevisionId::from_bytes([byte; 16])
}

const SOURCE_BYTES: &[u8] = b"= Cedar\n\nPrimary engine changed cleanly at handoff.\n";

fn setup_workspace() -> (tempfile::TempDir, mneme_store::Workspace) {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(
        temp.path(),
        mneme_store::WorkspaceConfig {
            clock: Box::new(mneme_store::FixedClock::new(
                mneme_core::Timestamp::from_nanos(1_000),
            )),
            faults: Box::new(mneme_store::NoFaults),
        },
    )
    .expect("create");
    let entity_payload = std::collections::BTreeMap::from([
        (
            mneme_core::Symbol::from("entity-type"),
            mneme_core::Value::symbol("service"),
        ),
        (
            mneme_core::Symbol::from("label"),
            mneme_core::Value::string("Cedar"),
        ),
        (
            mneme_core::Symbol::from("properties"),
            mneme_core::Value::dictionary([]),
        ),
    ]);
    let base = workspace.current_revision().expect("base");
    let (source_record, source_blob) = mneme_memory::build_source(
        rid(0x20),
        rev(0x21),
        &scope(),
        mneme_memory::SourceOptions {
            media_type: "text/asciidoc",
            bytes: SOURCE_BYTES,
            entity: Some(rid(0x10)),
            path_hint: Some("cedar.adoc"),
        },
    )
    .expect("source");
    workspace
        .commit(mneme_store::CommitCommand {
            base,
            actor: "test".to_owned(),
            scope: scope(),
            idempotency_key: "init".to_owned(),
            records: vec![
                mneme_store::RecordDraft {
                    schema_version: 1,
                    kind: mneme_core::RecordKind::Entity,
                    record_id: rid(0x10),
                    revision_id: rev(0x11),
                    predecessor: None,
                    scope: scope(),
                    payload: mneme_core::Payload::new(entity_payload),
                },
                source_record,
            ],
            source_blobs: vec![source_blob],
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("init commit");
    (temp, workspace)
}

struct ClaimSpec<'a> {
    key: &'a str,
    evidence_id: mneme_core::RecordId,
    evidence_rev: mneme_core::RevisionId,
    assertion_id: mneme_core::RecordId,
    prop_rev: mneme_core::RevisionId,
    accept_rev: mneme_core::RevisionId,
    decision_id: mneme_core::RecordId,
    decision_rev: mneme_core::RevisionId,
    value: &'a str,
    valid_time: mneme_core::ValidTime,
}

fn propose_claim(workspace: &mut mneme_store::Workspace, spec: &ClaimSpec<'_>) {
    let evidence = mneme_memory::build_evidence(
        spec.evidence_id,
        spec.evidence_rev,
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: spec.assertion_id,
            source: rid(0x20),
            source_revision: rev(0x21),
            span: None,
            anchor: Some("cedar-anchor"),
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let proposed = mneme_memory::build_proposed_assertion(
        spec.assertion_id,
        spec.prop_rev,
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: rid(0x10),
            predicate: "storage-engine",
            value: mneme_core::Value::string(spec.value),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "test",
            evidence: &[mneme_core::Reference::local(
                spec.evidence_id,
                mneme_core::RecordKind::Evidence,
            )],
            valid_time: spec.valid_time,
            extraction: None,
            superseded_by: None,
        },
    );
    let mut memory = mneme_memory::Engine::new(workspace, mneme_memory::Access::Operator);
    memory
        .commit(mneme_memory::Batch {
            actor: "test".to_owned(),
            scope: scope(),
            idempotency_key: format!("{}-prop", spec.key),
            records: vec![evidence, proposed],
            source_blobs: Vec::new(),
            publications: Vec::new(),
        })
        .expect("propose");
}

fn add_accepted_claim(workspace: &mut mneme_store::Workspace, spec: ClaimSpec<'_>) {
    propose_claim(workspace, &spec);
    let current = workspace
        .snapshot()
        .expect("snap")
        .records
        .into_iter()
        .find(|record| record.record_id == spec.assertion_id)
        .expect("assertion");
    let base = workspace.current_revision().expect("base");
    let decision = mneme_memory::build_decision(
        spec.decision_id,
        spec.decision_rev,
        &scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: spec.assertion_id,
            actor: "test",
            policy: "test/v1",
            input_revision: base,
            outcome: "accepted",
            rationale: "accepted",
            evidence: &[],
            related: &[],
        },
    );
    let accepted = mneme_memory::build_assertion_revision(
        &current,
        spec.accept_rev,
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(spec.decision_id, mneme_core::RecordKind::Decision),
        None,
    );
    let mut memory = mneme_memory::Engine::new(workspace, mneme_memory::Access::Operator);
    memory
        .commit(mneme_memory::Batch {
            actor: "test".to_owned(),
            scope: scope(),
            idempotency_key: format!("{}-acc", spec.key),
            records: vec![decision, accepted],
            source_blobs: Vec::new(),
            publications: Vec::new(),
        })
        .expect("accept");
}

#[test]
fn expiry_handoff_at_t_yields_zero_conflicts_and_strict_half_open_switchover() {
    let (_temp, mut workspace) = setup_workspace();
    let start_a1 = mneme_core::Timestamp::from_nanos(1_000);
    let handoff = mneme_core::Timestamp::from_nanos(5_000);
    let before_handoff = mneme_core::Timestamp::from_nanos(4_999);

    add_accepted_claim(
        &mut workspace,
        ClaimSpec {
            key: "a1",
            evidence_id: rid(0x30),
            evidence_rev: rev(0x31),
            assertion_id: rid(0x40),
            prop_rev: rev(0x41),
            accept_rev: rev(0x42),
            decision_id: rid(0x50),
            decision_rev: rev(0x51),
            value: "SQLite",
            valid_time: mneme_core::ValidTime::since(start_a1),
        },
    );

    // Expiring A1 at effective == start_a1 must fail under half-open semantics
    // (cannot create empty [T, T) or collide with legacy Instant(T)).
    let base = workspace.current_revision().expect("base");
    let invalid_req = mneme_retention::Request {
        operation: mneme_retention::OperationKind::ValidTimeExpiry,
        selector: mneme_retention::Selector::Assertion(rid(0x40)),
        scope: scope(),
        base_revision: base,
        actor: "retention-test".to_owned(),
        idempotency_key: "expire-at-start".to_owned(),
        policy: mneme_retention::Policy::default(),
        effective: Some(start_a1),
    };
    {
        let mut retention = mneme_retention::Engine::new(&mut workspace);
        let err = retention.plan(invalid_req).expect_err("effective == start");
        assert!(matches!(err, mneme_retention::PolicyError::Conflict(_)));
    }

    // Expire A1 at effective == handoff -> A1 becomes [1_000, 5_000).
    let expire_req = mneme_retention::Request {
        operation: mneme_retention::OperationKind::ValidTimeExpiry,
        selector: mneme_retention::Selector::Assertion(rid(0x40)),
        scope: scope(),
        base_revision: base,
        actor: "retention-test".to_owned(),
        idempotency_key: "expire-a1-handoff".to_owned(),
        policy: mneme_retention::Policy::default(),
        effective: Some(handoff),
    };
    {
        let mut retention = mneme_retention::Engine::new(&mut workspace);
        retention.execute(expire_req).expect("expire a1");
    }

    // Add replacement A2 with ValidTime::since(handoff) -> [5_000, +inf).
    add_accepted_claim(
        &mut workspace,
        ClaimSpec {
            key: "a2",
            evidence_id: rid(0x32),
            evidence_rev: rev(0x33),
            assertion_id: rid(0x44),
            prop_rev: rev(0x45),
            accept_rev: rev(0x46),
            decision_id: rid(0x52),
            decision_rev: rev(0x53),
            value: "LMDB",
            valid_time: mneme_core::ValidTime::since(handoff),
        },
    );

    let memory = mneme_memory::Engine::new(&mut workspace, mneme_memory::Access::Operator);
    let view = memory.view().expect("view");

    // At T - 1ns: only A1 is active, 0 conflicts.
    let at_before = mneme_memory::BeliefView {
        scope: scope(),
        at: before_handoff,
        include_hypothetical: false,
        include_disputed: false,
    };
    assert!(
        view.conflicts(&at_before)
            .expect("conflicts T-1")
            .is_empty()
    );
    let beliefs_before = view.current_beliefs(&at_before).expect("beliefs T-1");
    assert_eq!(beliefs_before.len(), 1);
    assert_eq!(beliefs_before[0].record.record_id, rid(0x40));

    // At T: only A2 is active, 0 conflicts!
    let at_handoff = mneme_memory::BeliefView {
        scope: scope(),
        at: handoff,
        include_hypothetical: false,
        include_disputed: false,
    };
    assert!(view.conflicts(&at_handoff).expect("conflicts T").is_empty());
    let beliefs_handoff = view.current_beliefs(&at_handoff).expect("beliefs T");
    assert_eq!(beliefs_handoff.len(), 1);
    assert_eq!(beliefs_handoff[0].record.record_id, rid(0x44));
}
