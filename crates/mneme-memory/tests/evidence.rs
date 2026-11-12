//! End-to-end evidence-memory tests over the durable workspace.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::unwrap_used, clippy::expect_used)]

fn scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
}

fn rid(byte: u8) -> mneme_core::RecordId {
    mneme_core::RecordId::from_bytes([byte; 16])
}

fn rev(byte: u8) -> mneme_core::RevisionId {
    mneme_core::RevisionId::from_bytes([byte; 16])
}

fn config() -> mneme_store::WorkspaceConfig {
    mneme_store::WorkspaceConfig {
        clock: Box::new(mneme_store::FixedClock::new(
            mneme_core::Timestamp::from_nanos(1_000),
        )),
        faults: Box::new(mneme_store::NoFaults),
    }
}

fn batch(
    key: &str,
    records: Vec<mneme_store::RecordDraft>,
    sources: Vec<mneme_store::SourceBlobDraft>,
) -> mneme_memory::MemoryBatch {
    batch_in(&scope(), key, records, sources)
}

fn batch_in(
    scope: &mneme_core::ScopeId,
    key: &str,
    records: Vec<mneme_store::RecordDraft>,
    sources: Vec<mneme_store::SourceBlobDraft>,
) -> mneme_memory::MemoryBatch {
    mneme_memory::MemoryBatch {
        actor: "test-author".to_owned(),
        scope: scope.clone(),
        idempotency_key: key.to_owned(),
        records,
        source_blobs: sources,
        publications: Vec::new(),
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

const SOURCE_ID: mneme_core::RecordId = mneme_core::RecordId::from_bytes([0x02; 16]);
const SOURCE_REV: mneme_core::RevisionId = mneme_core::RevisionId::from_bytes([0x52; 16]);

fn setup() -> (tempfile::TempDir, mneme_store::Workspace) {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config()).expect("create");
    {
        let mut memory = mneme_memory::Memory::new(&mut workspace);
        memory
            .commit(batch(
                "entity",
                vec![draft(&mneme_core::fixtures::entity())],
                Vec::new(),
            ))
            .expect("entity");
        let (source, blob) = mneme_memory::build_source(
            SOURCE_ID,
            SOURCE_REV,
            &scope(),
            mneme_memory::SourceOptions {
                bytes: mneme_core::fixtures::SOURCE_TEXT.as_bytes(),
                media_type: "text/asciidoc",
                entity: Some(mneme_core::fixtures::entity_id()),
                path_hint: Some("project.adoc"),
            },
        )
        .expect("source");
        memory
            .commit(batch("source", vec![source], vec![blob]))
            .expect("source commit");
    }
    (temp, workspace)
}

fn latest(
    workspace: &mneme_store::Workspace,
    record: mneme_core::RecordId,
) -> mneme_core::RecordEnvelope {
    workspace
        .record_revisions(record)
        .expect("history")
        .last()
        .cloned()
        .expect("revision")
}

struct ProposalInput<'a> {
    evidence_id: mneme_core::RecordId,
    evidence_revision: mneme_core::RevisionId,
    assertion_id: mneme_core::RecordId,
    assertion_revision: mneme_core::RevisionId,
    predicate: &'a str,
    value: mneme_core::Value,
    stance: mneme_memory::Stance,
    valid_time: mneme_core::ValidTime,
    span: Option<mneme_core::SourceSpan>,
    ancestry: &'a [mneme_core::Reference],
    extraction: Option<(&'a str, &'a str)>,
}

fn propose(
    workspace: &mut mneme_store::Workspace,
    key: &str,
    scope: &mneme_core::ScopeId,
    input: ProposalInput<'_>,
) -> mneme_core::RecordId {
    let ProposalInput {
        evidence_id,
        evidence_revision,
        assertion_id,
        assertion_revision,
        predicate,
        value,
        stance,
        valid_time,
        span,
        ancestry,
        extraction,
    } = input;
    let evidence = mneme_memory::build_evidence(
        evidence_id,
        evidence_revision,
        scope,
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: SOURCE_ID,
            source_revision: SOURCE_REV,
            span,
            anchor: Some("storage-decision"),
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry,
        },
    );
    let assertion = mneme_memory::build_proposed_assertion(
        assertion_id,
        assertion_revision,
        scope,
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate,
            value,
            stance,
            origin: if extraction.is_some() {
                mneme_core::Origin::ModelExtraction
            } else {
                mneme_core::Origin::AuthoredStatement
            },
            asserted_by: "synthetic author",
            valid_time,
            evidence: &[mneme_core::Reference::local(
                evidence_id,
                mneme_core::RecordKind::Evidence,
            )],
            extraction,
            superseded_by: None,
        },
    );
    {
        let mut memory = mneme_memory::Memory::new(workspace);
        memory
            .commit(batch_in(scope, key, vec![evidence, assertion], Vec::new()))
            .expect("proposal commit");
    }
    assertion_id
}

struct DecisionInput<'a> {
    assertion: mneme_core::RecordId,
    lifecycle: mneme_core::Lifecycle,
    decision_id: mneme_core::RecordId,
    decision_revision: mneme_core::RevisionId,
    assertion_revision: mneme_core::RevisionId,
    kind: mneme_memory::DecisionKind,
    outcome: &'a str,
    related: &'a [mneme_core::Reference],
}

fn decide(workspace: &mut mneme_store::Workspace, key: &str, input: DecisionInput<'_>) {
    let DecisionInput {
        assertion,
        lifecycle,
        decision_id,
        decision_revision,
        assertion_revision,
        kind,
        outcome,
        related,
    } = input;
    let base = workspace.current_revision().expect("base");
    let current = latest(workspace, assertion);
    let decision = mneme_memory::build_decision(
        decision_id,
        decision_revision,
        &scope(),
        mneme_memory::DecisionOptions {
            kind,
            target: assertion,
            actor: "policy actor",
            policy: "test-policy/v1",
            input_revision: base,
            outcome,
            rationale: "explicit test decision",
            evidence: &[],
            related,
        },
    );
    let revision = mneme_memory::build_assertion_revision(
        &current,
        assertion_revision,
        lifecycle,
        mneme_core::Reference::local(decision_id, mneme_core::RecordKind::Decision),
        None,
    );
    let mut memory = mneme_memory::Memory::new(workspace);
    memory
        .commit(batch(key, vec![decision, revision], Vec::new()))
        .expect("decision commit");
}

#[test]
fn proposed_assertion_is_not_promoted_by_retrieval_or_explanation() {
    let (_temp, mut workspace) = setup();
    let assertion_id = propose(
        &mut workspace,
        "proposal",
        &scope(),
        ProposalInput {
            evidence_id: rid(0x10),
            evidence_revision: rev(0x11),
            assertion_id: rid(0x20),
            assertion_revision: rev(0x21),
            predicate: "storage-engine",
            value: mneme_core::Value::string("SQLite"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    let at = mneme_core::Timestamp::parse("2026-11-10T00:00:00Z").expect("time");
    let view = mneme_memory::BeliefView {
        scope: scope(),
        at,
        include_hypothetical: false,
        include_disputed: false,
    };
    {
        let memory = mneme_memory::Memory::new(&mut workspace);
        assert!(memory.beliefs(&view).expect("beliefs").is_empty());
        let explanation = memory
            .explain(
                assertion_id,
                mneme_memory::Policy {
                    max_explanation_nodes: 64,
                    max_excerpt_bytes: 4096,
                },
            )
            .expect("explain");
        assert_eq!(
            explanation.assertion.lifecycle,
            mneme_core::Lifecycle::Proposed
        );
        let again = memory
            .explain(
                assertion_id,
                mneme_memory::Policy {
                    max_explanation_nodes: 64,
                    max_excerpt_bytes: 4096,
                },
            )
            .expect("explain");
        assert_eq!(again.assertion.lifecycle, mneme_core::Lifecycle::Proposed);
    }
    assert_eq!(
        latest(&workspace, assertion_id).assertion_lifecycle(),
        Some(mneme_core::Lifecycle::Proposed)
    );
}

#[test]
fn invalid_span_rejects_the_whole_batch() {
    let (_temp, mut workspace) = setup();
    let before = workspace.snapshot().expect("snapshot");
    let evidence = mneme_memory::build_evidence(
        rid(0x10),
        rev(0x11),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: rid(0x20),
            source: SOURCE_ID,
            source_revision: SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(0, 10_000).expect("ordered")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let assertion = mneme_memory::build_proposed_assertion(
        rid(0x20),
        rev(0x21),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "storage-engine",
            value: mneme_core::Value::string("SQLite"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                rid(0x10),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    let error = {
        let mut memory = mneme_memory::Memory::new(&mut workspace);
        memory
            .commit(batch("bad-span", vec![evidence, assertion], Vec::new()))
            .expect_err("span beyond source")
    };
    assert!(error.to_string().contains("beyond"));
    let after = workspace.snapshot().expect("snapshot");
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.records.len(), before.records.len());
}

#[test]
fn acceptance_requires_a_matching_decision() {
    let (_temp, mut workspace) = setup();
    let assertion_id = propose(
        &mut workspace,
        "proposal",
        &scope(),
        ProposalInput {
            evidence_id: rid(0x10),
            evidence_revision: rev(0x11),
            assertion_id: rid(0x20),
            assertion_revision: rev(0x21),
            predicate: "storage-engine",
            value: mneme_core::Value::string("SQLite"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    let current = latest(&workspace, assertion_id);
    let accepted_without_decision = mneme_memory::build_assertion_revision(
        &current,
        rev(0x22),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(rid(0x30), mneme_core::RecordKind::Decision),
        None,
    );
    let error = {
        let mut memory = mneme_memory::Memory::new(&mut workspace);
        memory
            .commit(batch(
                "missing-decision",
                vec![accepted_without_decision],
                Vec::new(),
            ))
            .expect_err("decision missing")
    };
    assert!(error.to_string().contains("missing"));

    decide(
        &mut workspace,
        "accept",
        DecisionInput {
            assertion: assertion_id,
            lifecycle: mneme_core::Lifecycle::Accepted,
            decision_id: rid(0x30),
            decision_revision: rev(0x31),
            assertion_revision: rev(0x22),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let at = mneme_core::Timestamp::parse("2026-11-10T00:00:00Z").expect("time");
    let memory = mneme_memory::Memory::new(&mut workspace);
    let beliefs = memory
        .beliefs(&mneme_memory::BeliefView {
            scope: scope(),
            at,
            include_hypothetical: false,
            include_disputed: false,
        })
        .expect("beliefs");
    assert_eq!(beliefs.len(), 1);
    assert_eq!(beliefs[0].lifecycle, mneme_core::Lifecycle::Accepted);
}

#[test]
fn source_change_after_extraction_keeps_the_pinned_citation() {
    let (_temp, mut workspace) = setup();
    let assertion_id = propose(
        &mut workspace,
        "proposal",
        &scope(),
        ProposalInput {
            evidence_id: rid(0x10),
            evidence_revision: rev(0x11),
            assertion_id: rid(0x20),
            assertion_revision: rev(0x21),
            predicate: "storage-engine",
            value: mneme_core::Value::string("SQLite"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: Some(
                mneme_core::SourceSpan::new(
                    mneme_core::fixtures::SOURCE_TEXT
                        .find("SQLite")
                        .expect("present") as u64,
                    mneme_core::fixtures::SOURCE_TEXT
                        .find("SQLite")
                        .expect("present") as u64
                        + 5,
                )
                .expect("span"),
            ),
            ancestry: &[],
            extraction: None,
        },
    );
    decide(
        &mut workspace,
        "accept",
        DecisionInput {
            assertion: assertion_id,
            lifecycle: mneme_core::Lifecycle::Accepted,
            decision_id: rid(0x30),
            decision_revision: rev(0x31),
            assertion_revision: rev(0x22),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );

    let changed = mneme_core::fixtures::SOURCE_TEXT.replace("SQLite", "LMDB");
    let (mut source, blob) = mneme_memory::build_source(
        SOURCE_ID,
        rev(0x0c),
        &scope(),
        mneme_memory::SourceOptions {
            bytes: changed.as_bytes(),
            media_type: "text/asciidoc",
            entity: Some(mneme_core::fixtures::entity_id()),
            path_hint: Some("project.adoc"),
        },
    )
    .expect("source");
    source.predecessor = Some(SOURCE_REV);
    {
        let mut memory = mneme_memory::Memory::new(&mut workspace);
        memory
            .commit(batch("source-v2", vec![source], vec![blob]))
            .expect("source change");
        let explanation = memory
            .explain(
                assertion_id,
                mneme_memory::Policy {
                    max_explanation_nodes: 64,
                    max_excerpt_bytes: 4096,
                },
            )
            .expect("explain");
        let evidence = &explanation.evidence[0];
        assert_eq!(evidence.source_revision, SOURCE_REV);
        let excerpt = evidence.excerpt.as_ref().expect("pinned excerpt");
        assert_eq!(String::from_utf8_lossy(&excerpt.bytes), "SQLite");
        assert!(!String::from_utf8_lossy(&excerpt.bytes).contains("LMDB"));
    }
}

struct BareProposalInput<'a> {
    assertion_id: mneme_core::RecordId,
    assertion_revision: mneme_core::RevisionId,
    predicate: &'a str,
    value: mneme_core::Value,
}

fn propose_bare(
    workspace: &mut mneme_store::Workspace,
    key: &str,
    scope: &mneme_core::ScopeId,
    input: BareProposalInput<'_>,
) -> mneme_core::RecordId {
    let BareProposalInput {
        assertion_id,
        assertion_revision,
        predicate,
        value,
    } = input;
    let assertion = mneme_memory::build_proposed_assertion(
        assertion_id,
        assertion_revision,
        scope,
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate,
            value,
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[],
            extraction: None,
            superseded_by: None,
        },
    );
    let mut memory = mneme_memory::Memory::new(workspace);
    memory
        .commit(batch_in(scope, key, vec![assertion], Vec::new()))
        .expect("bare proposal");
    assertion_id
}

#[test]
fn future_and_unknown_validity_do_not_answer_the_current_view() {
    let (_temp, mut workspace) = setup();
    let future = mneme_core::Timestamp::parse("2030-01-01T00:00:00Z").expect("future");
    let future_claim = propose(
        &mut workspace,
        "future",
        &scope(),
        ProposalInput {
            evidence_id: rid(0x10),
            evidence_revision: rev(0x11),
            assertion_id: rid(0x20),
            assertion_revision: rev(0x21),
            predicate: "future-change",
            value: mneme_core::Value::string("scheduled"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::since(future),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    decide(
        &mut workspace,
        "future-accept",
        DecisionInput {
            assertion: future_claim,
            lifecycle: mneme_core::Lifecycle::Accepted,
            decision_id: rid(0x30),
            decision_revision: rev(0x31),
            assertion_revision: rev(0x22),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let unknown_claim = propose(
        &mut workspace,
        "unknown",
        &scope(),
        ProposalInput {
            evidence_id: rid(0x12),
            evidence_revision: rev(0x13),
            assertion_id: rid(0x24),
            assertion_revision: rev(0x25),
            predicate: "unknown-time",
            value: mneme_core::Value::string("unknown"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::Unknown,
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    decide(
        &mut workspace,
        "unknown-accept",
        DecisionInput {
            assertion: unknown_claim,
            lifecycle: mneme_core::Lifecycle::Accepted,
            decision_id: rid(0x32),
            decision_revision: rev(0x33),
            assertion_revision: rev(0x26),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );

    let memory = mneme_memory::Memory::new(&mut workspace);
    let today = mneme_memory::BeliefView {
        scope: scope(),
        at: mneme_core::Timestamp::parse("2026-11-10T00:00:00Z").expect("today"),
        include_hypothetical: false,
        include_disputed: false,
    };
    assert!(memory.beliefs(&today).expect("today").is_empty());
    let later = mneme_memory::BeliefView {
        at: future,
        ..today.clone()
    };
    let beliefs = memory.beliefs(&later).expect("future");
    assert_eq!(beliefs.len(), 1);
    assert_eq!(beliefs[0].predicate, "future-change");
}

#[test]
fn hypothesis_scope_is_isolated_and_promotion_is_explicit() {
    let (_temp, mut workspace) = setup();
    let hypothesis_scope = mneme_core::ScopeId::new(mneme_core::ScopeClass::Hypothesis, "plan-1")
        .expect("hypothesis scope");
    let assertion_id = propose(
        &mut workspace,
        "hypothesis",
        &hypothesis_scope,
        ProposalInput {
            evidence_id: rid(0x10),
            evidence_revision: rev(0x11),
            assertion_id: rid(0x20),
            assertion_revision: rev(0x21),
            predicate: "device-state",
            value: mneme_core::Value::string("maybe-offline"),
            stance: mneme_memory::Stance::Hypothesis,
            valid_time: mneme_core::ValidTime::always(),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    let today = mneme_memory::BeliefView {
        scope: scope(),
        at: mneme_core::Timestamp::parse("2026-11-10T00:00:00Z").expect("today"),
        include_hypothetical: false,
        include_disputed: false,
    };
    let memory = mneme_memory::Memory::new(&mut workspace);
    assert!(memory.beliefs(&today).expect("project view").is_empty());
    assert!(
        memory
            .view()
            .expect("view")
            .assertions()
            .expect("assertions")
            .iter()
            .any(|assertion| assertion.record.record_id == assertion_id)
    );
    let _ = memory;

    // Promotion requires an accepted revision in the operational scope with a
    // decision that targets the promoted record.
    let current = latest(&workspace, assertion_id);
    let mut accepted = mneme_memory::build_assertion_revision(
        &current,
        rev(0x22),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(rid(0x30), mneme_core::RecordKind::Decision),
        None,
    );
    accepted.scope = scope();
    let base = workspace.current_revision().expect("base");
    let decision = mneme_memory::build_decision(
        rid(0x30),
        rev(0x31),
        &scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: assertion_id,
            actor: "policy actor",
            policy: "promotion-policy/v1",
            input_revision: base,
            outcome: "accepted",
            rationale: "explicit hypothesis promotion",
            evidence: &[],
            related: &[],
        },
    );
    {
        let mut memory = mneme_memory::Memory::new(&mut workspace);
        memory
            .commit(batch("promote", vec![decision, accepted], Vec::new()))
            .expect("promotion");
        let beliefs = memory.beliefs(&today).expect("project view");
        assert_eq!(beliefs.len(), 1);
        assert_eq!(beliefs[0].record.scope, scope());
    }
}

#[test]
fn conflicts_remain_visible_and_resolution_is_recorded() {
    let (_temp, mut workspace) = setup();
    let first = propose(
        &mut workspace,
        "first-claim",
        &scope(),
        ProposalInput {
            evidence_id: rid(0x10),
            evidence_revision: rev(0x11),
            assertion_id: rid(0x20),
            assertion_revision: rev(0x21),
            predicate: "storage-engine",
            value: mneme_core::Value::string("SQLite"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    let second = propose(
        &mut workspace,
        "second-claim",
        &scope(),
        ProposalInput {
            evidence_id: rid(0x12),
            evidence_revision: rev(0x13),
            assertion_id: rid(0x24),
            assertion_revision: rev(0x25),
            predicate: "storage-engine",
            value: mneme_core::Value::string("LMDB"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    decide(
        &mut workspace,
        "first-accept",
        DecisionInput {
            assertion: first,
            lifecycle: mneme_core::Lifecycle::Accepted,
            decision_id: rid(0x30),
            decision_revision: rev(0x31),
            assertion_revision: rev(0x22),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    decide(
        &mut workspace,
        "second-accept",
        DecisionInput {
            assertion: second,
            lifecycle: mneme_core::Lifecycle::Accepted,
            decision_id: rid(0x32),
            decision_revision: rev(0x33),
            assertion_revision: rev(0x26),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let view = mneme_memory::BeliefView {
        scope: scope(),
        at: mneme_core::Timestamp::parse("2026-11-10T00:00:00Z").expect("today"),
        include_hypothetical: false,
        include_disputed: true,
    };
    let memory = mneme_memory::Memory::new(&mut workspace);
    let conflicts = memory.conflicts(&view).expect("conflicts");
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].assertions.len(), 2);
    let _ = memory;

    // Explicitly mark both claims disputed with related links.
    let first_envelope = latest(&workspace, first);
    let second_envelope = latest(&workspace, second);
    let first_disputed = mneme_memory::build_assertion_revision(
        &first_envelope,
        rev(0x23),
        mneme_core::Lifecycle::Disputed,
        mneme_core::Reference::local(rid(0x34), mneme_core::RecordKind::Decision),
        None,
    );
    let second_disputed = mneme_memory::build_assertion_revision(
        &second_envelope,
        rev(0x27),
        mneme_core::Lifecycle::Disputed,
        mneme_core::Reference::local(rid(0x36), mneme_core::RecordKind::Decision),
        None,
    );
    let base = workspace.current_revision().expect("base");
    let decision_first = mneme_memory::build_decision(
        rid(0x34),
        rev(0x35),
        &scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::ConflictResolution,
            target: first,
            actor: "policy actor",
            policy: "conflict-policy/v1",
            input_revision: base,
            outcome: "disputed",
            rationale: "contradictory functional claims",
            evidence: &[],
            related: &[mneme_core::Reference::local(
                second,
                mneme_core::RecordKind::Assertion,
            )],
        },
    );
    let decision_second = mneme_memory::build_decision(
        rid(0x36),
        rev(0x37),
        &scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::ConflictResolution,
            target: second,
            actor: "policy actor",
            policy: "conflict-policy/v1",
            input_revision: base,
            outcome: "disputed",
            rationale: "contradictory functional claims",
            evidence: &[],
            related: &[mneme_core::Reference::local(
                first,
                mneme_core::RecordKind::Assertion,
            )],
        },
    );
    {
        let mut memory = mneme_memory::Memory::new(&mut workspace);
        memory
            .commit(batch(
                "resolve-conflict",
                vec![
                    first_disputed,
                    second_disputed,
                    decision_first,
                    decision_second,
                ],
                Vec::new(),
            ))
            .expect("resolution");
        let disputed = memory.beliefs(&view).expect("disputed view");
        assert_eq!(disputed.len(), 2);
        let accepted_only = mneme_memory::BeliefView {
            include_disputed: false,
            ..view
        };
        assert!(memory.beliefs(&accepted_only).expect("accepted").is_empty());
    }
}

#[test]
fn disjoint_validity_does_not_create_a_conflict() {
    let (_temp, mut workspace) = setup();
    let past = propose(
        &mut workspace,
        "past",
        &scope(),
        ProposalInput {
            evidence_id: rid(0x10),
            evidence_revision: rev(0x11),
            assertion_id: rid(0x20),
            assertion_revision: rev(0x21),
            predicate: "storage-engine",
            value: mneme_core::Value::string("SQLite"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::between(
                mneme_core::Timestamp::parse("2020-01-01T00:00:00Z").expect("start"),
                mneme_core::Timestamp::parse("2021-01-01T00:00:00Z").expect("end"),
            )
            .expect("interval"),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    let future = propose(
        &mut workspace,
        "future",
        &scope(),
        ProposalInput {
            evidence_id: rid(0x12),
            evidence_revision: rev(0x13),
            assertion_id: rid(0x24),
            assertion_revision: rev(0x25),
            predicate: "storage-engine",
            value: mneme_core::Value::string("LMDB"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::between(
                mneme_core::Timestamp::parse("2022-01-01T00:00:00Z").expect("start"),
                mneme_core::Timestamp::parse("2023-01-01T00:00:00Z").expect("end"),
            )
            .expect("interval"),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    decide(
        &mut workspace,
        "past-accept",
        DecisionInput {
            assertion: past,
            lifecycle: mneme_core::Lifecycle::Accepted,
            decision_id: rid(0x30),
            decision_revision: rev(0x31),
            assertion_revision: rev(0x22),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    decide(
        &mut workspace,
        "future-accept",
        DecisionInput {
            assertion: future,
            lifecycle: mneme_core::Lifecycle::Accepted,
            decision_id: rid(0x32),
            decision_revision: rev(0x33),
            assertion_revision: rev(0x26),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let view = mneme_memory::BeliefView {
        scope: scope(),
        at: mneme_core::Timestamp::parse("2024-06-01T00:00:00Z").expect("at"),
        include_hypothetical: false,
        include_disputed: false,
    };
    let memory = mneme_memory::Memory::new(&mut workspace);
    assert!(memory.conflicts(&view).expect("conflicts").is_empty());
}

#[test]
fn derivations_offer_independent_alternatives_and_survive_one_withdrawal() {
    let (_temp, mut workspace) = setup();
    let premise_one = propose(
        &mut workspace,
        "p1",
        &scope(),
        ProposalInput {
            evidence_id: rid(0x10),
            evidence_revision: rev(0x11),
            assertion_id: rid(0x20),
            assertion_revision: rev(0x21),
            predicate: "premise-one",
            value: mneme_core::Value::string("yes"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    let premise_two = propose(
        &mut workspace,
        "p2",
        &scope(),
        ProposalInput {
            evidence_id: rid(0x12),
            evidence_revision: rev(0x13),
            assertion_id: rid(0x24),
            assertion_revision: rev(0x25),
            predicate: "premise-two",
            value: mneme_core::Value::string("yes"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    let premise_three = propose(
        &mut workspace,
        "p3",
        &scope(),
        ProposalInput {
            evidence_id: rid(0x14),
            evidence_revision: rev(0x15),
            assertion_id: rid(0x28),
            assertion_revision: rev(0x29),
            predicate: "premise-three",
            value: mneme_core::Value::string("yes"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    decide(
        &mut workspace,
        "p1a",
        DecisionInput {
            assertion: premise_one,
            lifecycle: mneme_core::Lifecycle::Accepted,
            decision_id: rid(0x40),
            decision_revision: rev(0x41),
            assertion_revision: rev(0x22),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    decide(
        &mut workspace,
        "p2a",
        DecisionInput {
            assertion: premise_two,
            lifecycle: mneme_core::Lifecycle::Accepted,
            decision_id: rid(0x42),
            decision_revision: rev(0x43),
            assertion_revision: rev(0x26),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    decide(
        &mut workspace,
        "p3a",
        DecisionInput {
            assertion: premise_three,
            lifecycle: mneme_core::Lifecycle::Accepted,
            decision_id: rid(0x44),
            decision_revision: rev(0x45),
            assertion_revision: rev(0x2a),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let conclusion = propose_bare(
        &mut workspace,
        "conclusion",
        &scope(),
        BareProposalInput {
            assertion_id: rid(0x30),
            assertion_revision: rev(0x31),
            predicate: "conclusion",
            value: mneme_core::Value::string("derived"),
        },
    );
    decide(
        &mut workspace,
        "conclusion-a",
        DecisionInput {
            assertion: conclusion,
            lifecycle: mneme_core::Lifecycle::Accepted,
            decision_id: rid(0x46),
            decision_revision: rev(0x47),
            assertion_revision: rev(0x32),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let base = workspace.current_revision().expect("base");
    let derivation_one = mneme_memory::build_derivation(
        rid(0x50),
        rev(0x51),
        &scope(),
        mneme_memory::DerivationOptions {
            conclusion,
            premises: &[
                mneme_core::Reference::local(premise_one, mneme_core::RecordKind::Assertion),
                mneme_core::Reference::local(premise_two, mneme_core::RecordKind::Assertion),
            ],
            rule_id: "rule-a",
            rule_version: 1,
            evaluation_revision: base,
            completeness: "complete",
        },
    );
    let derivation_two = mneme_memory::build_derivation(
        rid(0x52),
        rev(0x53),
        &scope(),
        mneme_memory::DerivationOptions {
            conclusion,
            premises: &[mneme_core::Reference::local(
                premise_three,
                mneme_core::RecordKind::Assertion,
            )],
            rule_id: "rule-b",
            rule_version: 1,
            evaluation_revision: base,
            completeness: "complete",
        },
    );
    {
        let mut memory = mneme_memory::Memory::new(&mut workspace);
        memory
            .commit(batch(
                "derivations",
                vec![derivation_one, derivation_two],
                Vec::new(),
            ))
            .expect("derivations");
        let view = memory.view().expect("view");
        assert!(view.assertion_eligible(conclusion));
        let alternatives = view
            .derivation_alternatives(conclusion)
            .expect("alternatives");
        assert_eq!(alternatives.len(), 2);
        assert!(alternatives.iter().all(|alternative| alternative.eligible));
    }
    decide(
        &mut workspace,
        "retract-p1",
        DecisionInput {
            assertion: premise_one,
            lifecycle: mneme_core::Lifecycle::Retracted,
            decision_id: rid(0x48),
            decision_revision: rev(0x49),
            assertion_revision: rev(0x23),
            kind: mneme_memory::DecisionKind::Retraction,
            outcome: "retracted",
            related: &[],
        },
    );
    let memory = mneme_memory::Memory::new(&mut workspace);
    let view = memory.view().expect("view");
    assert!(view.assertion_eligible(conclusion));
    let alternatives = view
        .derivation_alternatives(conclusion)
        .expect("alternatives");
    assert_eq!(
        alternatives
            .iter()
            .filter(|alternative| alternative.eligible)
            .count(),
        1
    );
}

#[test]
fn cyclic_derivations_are_never_eligible() {
    let (_temp, mut workspace) = setup();
    let first = propose_bare(
        &mut workspace,
        "cycle-a",
        &scope(),
        BareProposalInput {
            assertion_id: rid(0x20),
            assertion_revision: rev(0x21),
            predicate: "cycle-a",
            value: mneme_core::Value::string("a"),
        },
    );
    let second = propose_bare(
        &mut workspace,
        "cycle-b",
        &scope(),
        BareProposalInput {
            assertion_id: rid(0x24),
            assertion_revision: rev(0x25),
            predicate: "cycle-b",
            value: mneme_core::Value::string("b"),
        },
    );
    decide(
        &mut workspace,
        "cycle-a-accept",
        DecisionInput {
            assertion: first,
            lifecycle: mneme_core::Lifecycle::Accepted,
            decision_id: rid(0x30),
            decision_revision: rev(0x31),
            assertion_revision: rev(0x22),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    decide(
        &mut workspace,
        "cycle-b-accept",
        DecisionInput {
            assertion: second,
            lifecycle: mneme_core::Lifecycle::Accepted,
            decision_id: rid(0x32),
            decision_revision: rev(0x33),
            assertion_revision: rev(0x26),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let base = workspace.current_revision().expect("base");
    let derivation_a = mneme_memory::build_derivation(
        rid(0x40),
        rev(0x41),
        &scope(),
        mneme_memory::DerivationOptions {
            conclusion: first,
            premises: &[mneme_core::Reference::local(
                second,
                mneme_core::RecordKind::Assertion,
            )],
            rule_id: "cycle-rule",
            rule_version: 1,
            evaluation_revision: base,
            completeness: "complete",
        },
    );
    let derivation_b = mneme_memory::build_derivation(
        rid(0x42),
        rev(0x43),
        &scope(),
        mneme_memory::DerivationOptions {
            conclusion: second,
            premises: &[mneme_core::Reference::local(
                first,
                mneme_core::RecordKind::Assertion,
            )],
            rule_id: "cycle-rule",
            rule_version: 1,
            evaluation_revision: base,
            completeness: "complete",
        },
    );
    let mut memory = mneme_memory::Memory::new(&mut workspace);
    memory
        .commit(batch(
            "cycle-derivations",
            vec![derivation_a, derivation_b],
            Vec::new(),
        ))
        .expect("cycles are retained but not accepted");
    let view = memory.view().expect("view");
    assert!(!view.assertion_eligible(first));
    assert!(!view.assertion_eligible(second));
    assert!(
        view.derivation_alternatives(first)
            .expect("alternatives")
            .iter()
            .all(|alternative| !alternative.eligible)
    );
}

#[test]
fn corroboration_counts_distinct_sources_not_record_copies() {
    let (_temp, mut workspace) = setup();
    let assertion_id = rid(0x20);
    let evidence_one = mneme_memory::build_evidence(
        rid(0x10),
        rev(0x11),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: SOURCE_ID,
            source_revision: SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let evidence_two = mneme_memory::build_evidence(
        rid(0x12),
        rev(0x13),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: SOURCE_ID,
            source_revision: SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(4, 7).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[mneme_core::Reference::local(
                rid(0x10),
                mneme_core::RecordKind::Evidence,
            )],
        },
    );
    let evidence_three = mneme_memory::build_evidence(
        rid(0x14),
        rev(0x15),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: SOURCE_ID,
            source_revision: SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(8, 12).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[mneme_core::Reference::local(
                rid(0x10),
                mneme_core::RecordKind::Evidence,
            )],
        },
    );
    let assertion = mneme_memory::build_proposed_assertion(
        assertion_id,
        rev(0x21),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "corroborated",
            value: mneme_core::Value::string("yes"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[
                mneme_core::Reference::local(rid(0x10), mneme_core::RecordKind::Evidence),
                mneme_core::Reference::local(rid(0x12), mneme_core::RecordKind::Evidence),
                mneme_core::Reference::local(rid(0x14), mneme_core::RecordKind::Evidence),
            ],
            extraction: None,
            superseded_by: None,
        },
    );
    {
        let mut memory = mneme_memory::Memory::new(&mut workspace);
        memory
            .commit(batch(
                "corroboration",
                vec![evidence_one, evidence_two, evidence_three, assertion],
                Vec::new(),
            ))
            .expect("corroboration batch");
    }
    decide(
        &mut workspace,
        "corroborated-accept",
        DecisionInput {
            assertion: assertion_id,
            lifecycle: mneme_core::Lifecycle::Accepted,
            decision_id: rid(0x30),
            decision_revision: rev(0x31),
            assertion_revision: rev(0x22),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let memory = mneme_memory::Memory::new(&mut workspace);
    let corroboration = memory
        .view()
        .expect("view")
        .corroboration(assertion_id)
        .expect("corroboration");
    assert_eq!(corroboration.independent_supports, 1);
    assert!(corroboration.shared_ancestry);
}

#[test]
fn cyclic_evidence_ancestry_is_rejected() {
    let (_temp, mut workspace) = setup();
    let assertion_id = rid(0x20);
    let evidence_one = mneme_memory::build_evidence(
        rid(0x10),
        rev(0x11),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: SOURCE_ID,
            source_revision: SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[mneme_core::Reference::local(
                rid(0x12),
                mneme_core::RecordKind::Evidence,
            )],
        },
    );
    let evidence_two = mneme_memory::build_evidence(
        rid(0x12),
        rev(0x13),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: SOURCE_ID,
            source_revision: SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(4, 7).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[mneme_core::Reference::local(
                rid(0x10),
                mneme_core::RecordKind::Evidence,
            )],
        },
    );
    let assertion = mneme_memory::build_proposed_assertion(
        assertion_id,
        rev(0x21),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "cyclic",
            value: mneme_core::Value::string("no"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[
                mneme_core::Reference::local(rid(0x10), mneme_core::RecordKind::Evidence),
                mneme_core::Reference::local(rid(0x12), mneme_core::RecordKind::Evidence),
            ],
            extraction: None,
            superseded_by: None,
        },
    );
    let error = {
        let mut memory = mneme_memory::Memory::new(&mut workspace);
        memory
            .commit(batch(
                "cyclic-ancestry",
                vec![evidence_one, evidence_two, assertion],
                Vec::new(),
            ))
            .expect_err("cycle")
    };
    assert!(error.to_string().contains("cycle"));
}

#[test]
fn pruned_source_is_reported_without_inventing_an_excerpt() {
    let (_temp, mut workspace) = setup();
    let assertion_id = propose(
        &mut workspace,
        "proposal",
        &scope(),
        ProposalInput {
            evidence_id: rid(0x10),
            evidence_revision: rev(0x11),
            assertion_id: rid(0x20),
            assertion_revision: rev(0x21),
            predicate: "storage-engine",
            value: mneme_core::Value::string("SQLite"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: Some(
                mneme_core::SourceSpan::new(
                    mneme_core::fixtures::SOURCE_TEXT
                        .find("SQLite")
                        .expect("present") as u64,
                    mneme_core::fixtures::SOURCE_TEXT
                        .find("SQLite")
                        .expect("present") as u64
                        + 5,
                )
                .expect("span"),
            ),
            ancestry: &[],
            extraction: None,
        },
    );
    decide(
        &mut workspace,
        "accept",
        DecisionInput {
            assertion: assertion_id,
            lifecycle: mneme_core::Lifecycle::Accepted,
            decision_id: rid(0x30),
            decision_revision: rev(0x31),
            assertion_revision: rev(0x22),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let (mut pruned, _) = (
        mneme_memory::build_unavailable_source(
            SOURCE_ID,
            rev(0x53),
            &scope(),
            mneme_memory::UnavailableSourceOptions {
                reason: "raw bytes pruned under retention policy",
                availability: "pruned",
                entity: Some(mneme_core::fixtures::entity_id()),
                path_hint: Some("project.adoc"),
            },
        ),
        (),
    );
    pruned.predecessor = Some(SOURCE_REV);
    {
        let mut memory = mneme_memory::Memory::new(&mut workspace);
        memory
            .commit(batch("prune", vec![pruned], Vec::new()))
            .expect("prune");
        let explanation = memory
            .explain(
                assertion_id,
                mneme_memory::Policy {
                    max_explanation_nodes: 64,
                    max_excerpt_bytes: 4096,
                },
            )
            .expect("explain");
        assert_eq!(
            explanation.evidence[0].availability,
            mneme_memory::SourceAvailability::Pruned
        );
        assert!(explanation.evidence[0].excerpt.is_none());
        assert_eq!(
            explanation.assertion.lifecycle,
            mneme_core::Lifecycle::Accepted
        );
    }
}

#[test]
fn correction_retraction_and_history_do_not_assert_the_opposite() {
    let (_temp, mut workspace) = setup();
    let assertion_id = propose(
        &mut workspace,
        "proposal",
        &scope(),
        ProposalInput {
            evidence_id: rid(0x10),
            evidence_revision: rev(0x11),
            assertion_id: rid(0x20),
            assertion_revision: rev(0x21),
            predicate: "storage-engine",
            value: mneme_core::Value::string("SQLite"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    decide(
        &mut workspace,
        "accept",
        DecisionInput {
            assertion: assertion_id,
            lifecycle: mneme_core::Lifecycle::Accepted,
            decision_id: rid(0x30),
            decision_revision: rev(0x31),
            assertion_revision: rev(0x22),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let accepted = latest(&workspace, assertion_id);
    let mut corrected = mneme_memory::build_assertion_revision(
        &accepted,
        rev(0x23),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(rid(0x32), mneme_core::RecordKind::Decision),
        None,
    );
    corrected.payload.insert(
        mneme_core::Symbol::from("value"),
        mneme_core::Value::string("LMDB"),
    );
    corrected.payload.insert(
        mneme_core::Symbol::from("valid-time"),
        mneme_core::ValidTime::between(
            mneme_core::Timestamp::parse("2020-01-01T00:00:00Z").expect("start"),
            mneme_core::Timestamp::parse("2021-01-01T00:00:00Z").expect("end"),
        )
        .expect("interval")
        .to_value(),
    );
    let base = workspace.current_revision().expect("base");
    let correction_decision = mneme_memory::build_decision(
        rid(0x32),
        rev(0x33),
        &scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: assertion_id,
            actor: "policy actor",
            policy: "correction-policy/v1",
            input_revision: base,
            outcome: "accepted",
            rationale: "corrected after review",
            evidence: &[],
            related: &[],
        },
    );
    {
        let mut memory = mneme_memory::Memory::new(&mut workspace);
        memory
            .commit(batch(
                "correct",
                vec![correction_decision, corrected],
                Vec::new(),
            ))
            .expect("correction");
        let beliefs = memory
            .beliefs(&mneme_memory::BeliefView {
                scope: scope(),
                at: mneme_core::Timestamp::parse("2020-06-01T00:00:00Z").expect("historical"),
                include_hypothetical: false,
                include_disputed: false,
            })
            .expect("beliefs");
        assert_eq!(beliefs.len(), 1);
        assert_eq!(beliefs[0].value, mneme_core::Value::string("LMDB"));
        assert_eq!(memory.revisions(assertion_id).expect("history").len(), 3);
        let explanation = memory
            .explain(
                assertion_id,
                mneme_memory::Policy {
                    max_explanation_nodes: 64,
                    max_excerpt_bytes: 4096,
                },
            )
            .expect("corrected explanation");
        assert_eq!(
            explanation.assertion.lifecycle,
            mneme_core::Lifecycle::Accepted
        );
        assert!(explanation.decisions.len() >= 2);
        assert_eq!(
            explanation.evidence[0].availability,
            mneme_memory::SourceAvailability::Retained
        );
    }
    decide(
        &mut workspace,
        "retract",
        DecisionInput {
            assertion: assertion_id,
            lifecycle: mneme_core::Lifecycle::Retracted,
            decision_id: rid(0x34),
            decision_revision: rev(0x35),
            assertion_revision: rev(0x24),
            kind: mneme_memory::DecisionKind::Retraction,
            outcome: "retracted",
            related: &[],
        },
    );
    let memory = mneme_memory::Memory::new(&mut workspace);
    assert!(
        memory
            .beliefs(&mneme_memory::BeliefView {
                scope: scope(),
                at: mneme_core::Timestamp::parse("2026-11-10T00:00:00Z").expect("today"),
                include_hypothetical: false,
                include_disputed: false,
            })
            .expect("beliefs")
            .is_empty()
    );
    assert_eq!(memory.revisions(assertion_id).expect("history").len(), 4);
    assert!(
        memory
            .view()
            .expect("view")
            .assertions()
            .expect("assertions")
            .iter()
            .all(|assertion| !matches!(assertion.stance, mneme_memory::Stance::Deny))
    );
}

#[test]
fn action_intent_without_an_observed_outcome_cannot_be_completed() {
    let (_temp, mut workspace) = setup();
    let intent = mneme_memory::build_episode(
        rid(0x10),
        rev(0x11),
        &scope(),
        mneme_memory::EpisodeOptions {
            actor: "agent",
            episode_type: "intent",
            occurred: mneme_core::ValidTime::Unknown,
            summary: "plan to test the device",
            source: None,
            related: &[],
        },
    );
    let attempt = mneme_memory::build_episode(
        rid(0x12),
        rev(0x13),
        &scope(),
        mneme_memory::EpisodeOptions {
            actor: "agent",
            episode_type: "attempt",
            occurred: mneme_core::ValidTime::Unknown,
            summary: "attempted the test with unknown result",
            source: None,
            related: &[mneme_core::Reference::local(
                rid(0x10),
                mneme_core::RecordKind::Episode,
            )],
        },
    );
    {
        let mut memory = mneme_memory::Memory::new(&mut workspace);
        memory
            .commit(batch("episodes", vec![intent, attempt], Vec::new()))
            .expect("episodes");
    }
    let assertion_id = rid(0x20);
    let evidence = mneme_memory::build_evidence(
        rid(0x14),
        rev(0x15),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: SOURCE_ID,
            source_revision: SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(0, 4).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::Observation,
            ancestry: &[mneme_core::Reference::local(
                rid(0x12),
                mneme_core::RecordKind::Episode,
            )],
        },
    );
    let completed = mneme_memory::build_proposed_assertion(
        assertion_id,
        rev(0x21),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "action-completed",
            value: mneme_core::Value::string("device tested"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::Observation,
            asserted_by: "agent",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                rid(0x14),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    {
        let mut memory = mneme_memory::Memory::new(&mut workspace);
        let error = memory
            .commit(batch(
                "false-completion",
                vec![evidence, completed],
                Vec::new(),
            ))
            .expect_err("no observed outcome");
        assert!(error.to_string().contains("observed outcome"));
    }

    let outcome = mneme_memory::build_episode(
        rid(0x16),
        rev(0x17),
        &scope(),
        mneme_memory::EpisodeOptions {
            actor: "agent",
            episode_type: "outcome",
            occurred: mneme_core::ValidTime::Unknown,
            summary: "device responded",
            source: None,
            related: &[mneme_core::Reference::local(
                rid(0x12),
                mneme_core::RecordKind::Episode,
            )],
        },
    );
    {
        let mut memory = mneme_memory::Memory::new(&mut workspace);
        memory
            .commit(batch("outcome", vec![outcome], Vec::new()))
            .expect("outcome");
    }
    let evidence = mneme_memory::build_evidence(
        rid(0x14),
        rev(0x15),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: SOURCE_ID,
            source_revision: SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(0, 4).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::Observation,
            ancestry: &[mneme_core::Reference::local(
                rid(0x16),
                mneme_core::RecordKind::Episode,
            )],
        },
    );
    let completed = mneme_memory::build_proposed_assertion(
        assertion_id,
        rev(0x21),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "action-completed",
            value: mneme_core::Value::string("device tested"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::Observation,
            asserted_by: "agent",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                rid(0x14),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    let checkpoint = mneme_memory::build_checkpoint(
        rid(0x18),
        rev(0x19),
        &scope(),
        mneme_memory::CheckpointOptions {
            goal: "verify device",
            state: "awaiting-verification",
            episodes: &[mneme_core::Reference::local(
                rid(0x10),
                mneme_core::RecordKind::Episode,
            )],
            verified_outcomes: &[mneme_core::Reference::local(
                rid(0x16),
                mneme_core::RecordKind::Episode,
            )],
            revision: workspace.current_revision().expect("revision"),
            note: None,
        },
    );
    {
        let mut memory = mneme_memory::Memory::new(&mut workspace);
        memory
            .commit(batch(
                "observed-completion",
                vec![evidence, completed, checkpoint],
                Vec::new(),
            ))
            .expect("completed action with observed outcome");
    }
}

#[test]
fn accepted_absence_requires_an_explicit_completeness_basis() {
    let (_temp, mut workspace) = setup();
    let assertion_id = rid(0x20);
    let mut assertion = mneme_memory::build_proposed_assertion(
        assertion_id,
        rev(0x21),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "blocker",
            value: mneme_core::Value::string("none"),
            stance: mneme_memory::Stance::Deny,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[],
            extraction: None,
            superseded_by: None,
        },
    );
    {
        let mut memory = mneme_memory::Memory::new(&mut workspace);
        memory
            .commit(batch("absence", vec![assertion.clone()], Vec::new()))
            .expect("proposed absence");
    }
    let current = latest(&workspace, assertion_id);
    let accepted = mneme_memory::build_assertion_revision(
        &current,
        rev(0x22),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(rid(0x30), mneme_core::RecordKind::Decision),
        None,
    );
    let base = workspace.current_revision().expect("base");
    let decision = mneme_memory::build_decision(
        rid(0x30),
        rev(0x31),
        &scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: assertion_id,
            actor: "policy actor",
            policy: "absence-policy/v1",
            input_revision: base,
            outcome: "accepted",
            rationale: "attempted acceptance",
            evidence: &[],
            related: &[],
        },
    );
    {
        let mut memory = mneme_memory::Memory::new(&mut workspace);
        let error = memory
            .commit(batch(
                "accept-absence",
                vec![decision, accepted],
                Vec::new(),
            ))
            .expect_err("partial evidence cannot establish absence");
        assert!(error.to_string().contains("declared-complete"));
    }
    // A declared-complete basis is an explicit policy input, not a retrieval
    // side effect.
    assertion.payload.insert(
        mneme_core::Symbol::from("completeness"),
        mneme_core::Value::symbol("declared-complete"),
    );
    assertion.revision_id = rev(0x23);
    assertion.predecessor = Some(rev(0x21));
    {
        let mut memory = mneme_memory::Memory::new(&mut workspace);
        memory
            .commit(batch("declared-absence", vec![assertion], Vec::new()))
            .expect("declared complete basis");
    }
    let current = latest(&workspace, assertion_id);
    let accepted = mneme_memory::build_assertion_revision(
        &current,
        rev(0x24),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(rid(0x32), mneme_core::RecordKind::Decision),
        None,
    );
    let base = workspace.current_revision().expect("base");
    let decision = mneme_memory::build_decision(
        rid(0x32),
        rev(0x33),
        &scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: assertion_id,
            actor: "policy actor",
            policy: "absence-policy/v1",
            input_revision: base,
            outcome: "accepted",
            rationale: "declared-complete absence",
            evidence: &[],
            related: &[],
        },
    );
    let mut memory = mneme_memory::Memory::new(&mut workspace);
    memory
        .commit(batch(
            "accept-declared-absence",
            vec![decision, accepted],
            Vec::new(),
        ))
        .expect("accepted declared absence");
}

#[test]
fn supersession_is_explicit_and_preserves_the_prior_revision() {
    let (_temp, mut workspace) = setup();
    let old = propose(
        &mut workspace,
        "old",
        &scope(),
        ProposalInput {
            evidence_id: rid(0x10),
            evidence_revision: rev(0x11),
            assertion_id: rid(0x20),
            assertion_revision: rev(0x21),
            predicate: "storage-engine",
            value: mneme_core::Value::string("SQLite"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    decide(
        &mut workspace,
        "old-accept",
        DecisionInput {
            assertion: old,
            lifecycle: mneme_core::Lifecycle::Accepted,
            decision_id: rid(0x30),
            decision_revision: rev(0x31),
            assertion_revision: rev(0x22),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let replacement = propose(
        &mut workspace,
        "new",
        &scope(),
        ProposalInput {
            evidence_id: rid(0x12),
            evidence_revision: rev(0x13),
            assertion_id: rid(0x24),
            assertion_revision: rev(0x25),
            predicate: "storage-engine",
            value: mneme_core::Value::string("LMDB"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    decide(
        &mut workspace,
        "new-accept",
        DecisionInput {
            assertion: replacement,
            lifecycle: mneme_core::Lifecycle::Accepted,
            decision_id: rid(0x32),
            decision_revision: rev(0x33),
            assertion_revision: rev(0x26),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let current_old = latest(&workspace, old);
    let mut superseded = mneme_memory::build_assertion_revision(
        &current_old,
        rev(0x23),
        mneme_core::Lifecycle::Superseded,
        mneme_core::Reference::local(rid(0x34), mneme_core::RecordKind::Decision),
        Some(mneme_core::Reference::local(
            replacement,
            mneme_core::RecordKind::Assertion,
        )),
    );
    superseded.predecessor = Some(current_old.revision_id);
    let base = workspace.current_revision().expect("base");
    let decision = mneme_memory::build_decision(
        rid(0x34),
        rev(0x35),
        &scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Supersession,
            target: old,
            actor: "policy actor",
            policy: "supersession-policy/v1",
            input_revision: base,
            outcome: "superseded",
            rationale: "replaced by LMDB",
            evidence: &[],
            related: &[mneme_core::Reference::local(
                replacement,
                mneme_core::RecordKind::Assertion,
            )],
        },
    );
    {
        let mut memory = mneme_memory::Memory::new(&mut workspace);
        memory
            .commit(batch("supersede", vec![decision, superseded], Vec::new()))
            .expect("supersession");
        let beliefs = memory
            .beliefs(&mneme_memory::BeliefView {
                scope: scope(),
                at: mneme_core::Timestamp::parse("2026-11-10T00:00:00Z").expect("today"),
                include_hypothetical: false,
                include_disputed: false,
            })
            .expect("beliefs");
        assert_eq!(beliefs.len(), 1);
        assert_eq!(beliefs[0].record.record_id, replacement);
        assert_eq!(memory.revisions(old).expect("history").len(), 3);
    }
}

#[test]
fn mismatched_source_revision_and_stale_decision_are_refused() {
    let (_temp, mut workspace) = setup();
    let assertion_id = rid(0x20);
    let evidence = mneme_memory::build_evidence(
        rid(0x10),
        rev(0x11),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: SOURCE_ID,
            source_revision: rev(0x54),
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let assertion = mneme_memory::build_proposed_assertion(
        assertion_id,
        rev(0x21),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "storage-engine",
            value: mneme_core::Value::string("SQLite"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                rid(0x10),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    {
        let mut memory = mneme_memory::Memory::new(&mut workspace);
        let error = memory
            .commit(batch(
                "pinned-mismatch",
                vec![evidence, assertion],
                Vec::new(),
            ))
            .expect_err("mismatched pinned revision");
        assert!(error.to_string().contains("missing source"));
    }

    let assertion_id = propose(
        &mut workspace,
        "proposal",
        &scope(),
        ProposalInput {
            evidence_id: rid(0x12),
            evidence_revision: rev(0x13),
            assertion_id: rid(0x24),
            assertion_revision: rev(0x25),
            predicate: "stale-decision",
            value: mneme_core::Value::string("value"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    // Advance the workspace so the decision's input revision is stale.
    let mut workspace = workspace;
    {
        let mut memory = mneme_memory::Memory::new(&mut workspace);
        memory
            .commit(batch(
                "advance",
                vec![mneme_memory::build_proposed_assertion(
                    rid(0x30),
                    rev(0x31),
                    &scope(),
                    mneme_memory::ProposedAssertionOptions {
                        subject: mneme_core::fixtures::entity_id(),
                        predicate: "unrelated",
                        value: mneme_core::Value::string("x"),
                        stance: mneme_memory::Stance::Affirm,
                        origin: mneme_core::Origin::AuthoredStatement,
                        asserted_by: "author",
                        valid_time: mneme_core::ValidTime::always(),
                        evidence: &[],
                        extraction: None,
                        superseded_by: None,
                    },
                )],
                Vec::new(),
            ))
            .expect("advance");
    }
    let current = latest(&workspace, assertion_id);
    let accepted = mneme_memory::build_assertion_revision(
        &current,
        rev(0x26),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(rid(0x40), mneme_core::RecordKind::Decision),
        None,
    );
    let decision = mneme_memory::build_decision(
        rid(0x40),
        rev(0x41),
        &scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: assertion_id,
            actor: "policy actor",
            policy: "stale-policy/v1",
            input_revision: mneme_core::WorkspaceRevisionId::from_bytes([0x7f; 16]),
            outcome: "accepted",
            rationale: "stale decision",
            evidence: &[],
            related: &[],
        },
    );
    let mut memory = mneme_memory::Memory::new(&mut workspace);
    let error = memory
        .commit(batch(
            "stale-decision",
            vec![decision, accepted],
            Vec::new(),
        ))
        .expect_err("stale decision revision");
    assert!(error.to_string().contains("current base"));
}

#[test]
fn erased_and_inaccessible_sources_are_labelled_without_text() {
    for (availability, reason) in [
        ("erased", "explicitly forgotten"),
        ("inaccessible", "access policy"),
    ] {
        let (_temp, mut workspace) = setup();
        let assertion = propose(
            &mut workspace,
            "proposal",
            &scope(),
            ProposalInput {
                evidence_id: rid(0x10),
                evidence_revision: rev(0x11),
                assertion_id: rid(0x20),
                assertion_revision: rev(0x21),
                predicate: "storage-engine",
                value: mneme_core::Value::string("SQLite"),
                stance: mneme_memory::Stance::Affirm,
                valid_time: mneme_core::ValidTime::always(),
                span: Some(mneme_core::SourceSpan::new(0, 5).expect("span")),
                ancestry: &[],
                extraction: None,
            },
        );
        decide(
            &mut workspace,
            "accept",
            DecisionInput {
                assertion,
                lifecycle: mneme_core::Lifecycle::Accepted,
                decision_id: rid(0x30),
                decision_revision: rev(0x31),
                assertion_revision: rev(0x22),
                kind: mneme_memory::DecisionKind::Acceptance,
                outcome: "accepted",
                related: &[],
            },
        );
        let mut replacement = mneme_memory::build_unavailable_source(
            SOURCE_ID,
            rev(0x55),
            &scope(),
            mneme_memory::UnavailableSourceOptions {
                reason,
                availability,
                entity: Some(mneme_core::fixtures::entity_id()),
                path_hint: Some("project.adoc"),
            },
        );
        replacement.predecessor = Some(SOURCE_REV);
        {
            let mut memory = mneme_memory::Memory::new(&mut workspace);
            memory
                .commit(batch("unavailable", vec![replacement], Vec::new()))
                .expect("source state");
            let explanation = memory
                .explain(
                    assertion,
                    mneme_memory::Policy {
                        max_explanation_nodes: 64,
                        max_excerpt_bytes: 4096,
                    },
                )
                .expect("explain");
            assert!(explanation.evidence[0].excerpt.is_none());
            assert_eq!(
                explanation.evidence[0].availability.name(),
                if availability == "erased" {
                    "erased"
                } else {
                    "unavailable"
                }
            );
        }
    }
}

#[test]
fn memory_explanation_rechecks_the_current_eligibility_generation() {
    let (_temp, mut workspace) = setup();
    let assertion = propose(
        &mut workspace,
        "proposal",
        &scope(),
        ProposalInput {
            evidence_id: rid(0x10),
            evidence_revision: rev(0x11),
            assertion_id: rid(0x20),
            assertion_revision: rev(0x21),
            predicate: "storage-engine",
            value: mneme_core::Value::string("SQLite"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    decide(
        &mut workspace,
        "accept",
        DecisionInput {
            assertion,
            lifecycle: mneme_core::Lifecycle::Accepted,
            decision_id: rid(0x30),
            decision_revision: rev(0x31),
            assertion_revision: rev(0x22),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let generation = workspace.eligibility_generation().expect("generation");
    workspace.advance_eligibility_barrier().expect("barrier");
    let memory = mneme_memory::Memory::new(&mut workspace);
    let error = memory
        .explain_at(
            assertion,
            Some(generation),
            mneme_memory::Policy {
                max_explanation_nodes: 64,
                max_excerpt_bytes: 4096,
            },
        )
        .expect_err("stale generation");
    assert!(matches!(
        error,
        mneme_memory::MemoryError::Store(mneme_store::StoreError::BarrierAdvanced { .. })
    ));
}
