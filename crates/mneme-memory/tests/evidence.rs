//! End-to-end evidence-memory tests over the durable workspace.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use mneme_core::{
    Lifecycle, Origin, RecordEnvelope, RecordId, Reference, RevisionId, ScopeClass, ScopeId,
    SourceSpan, Symbol, Timestamp, ValidTime, Value, WorkspaceRevisionId, fixtures,
};
use mneme_memory::{
    BeliefView, DecisionKind, Memory, MemoryBatch, Policy, Stance, build_assertion_revision,
    build_checkpoint, build_decision, build_derivation, build_episode, build_evidence,
    build_proposed_assertion, build_source, build_unavailable_source,
};
use mneme_store::{FixedClock, NoFaults, RecordDraft, SourceBlobDraft, Workspace, WorkspaceConfig};
use tempfile::TempDir;

fn scope() -> ScopeId {
    ScopeId::new(ScopeClass::Project, "cedar").expect("scope")
}

fn rid(byte: u8) -> RecordId {
    RecordId::from_bytes([byte; 16])
}

fn rev(byte: u8) -> RevisionId {
    RevisionId::from_bytes([byte; 16])
}

fn config() -> WorkspaceConfig {
    WorkspaceConfig {
        clock: Box::new(FixedClock::new(Timestamp::from_nanos(1_000))),
        faults: Box::new(NoFaults),
    }
}

fn batch(key: &str, records: Vec<RecordDraft>, sources: Vec<SourceBlobDraft>) -> MemoryBatch {
    batch_in(&scope(), key, records, sources)
}

fn batch_in(
    scope: &ScopeId,
    key: &str,
    records: Vec<RecordDraft>,
    sources: Vec<SourceBlobDraft>,
) -> MemoryBatch {
    MemoryBatch {
        actor: "test-author".to_owned(),
        scope: scope.clone(),
        idempotency_key: key.to_owned(),
        records,
        source_blobs: sources,
        publications: Vec::new(),
    }
}

fn draft(envelope: &RecordEnvelope) -> RecordDraft {
    RecordDraft {
        schema_version: envelope.schema_version,
        kind: envelope.kind,
        record_id: envelope.record_id,
        revision_id: envelope.revision_id,
        predecessor: envelope.predecessor,
        scope: envelope.scope.clone(),
        payload: envelope.payload.clone(),
    }
}

const SOURCE_ID: RecordId = RecordId::from_bytes([0x02; 16]);
const SOURCE_REV: RevisionId = RevisionId::from_bytes([0x52; 16]);

fn setup() -> (TempDir, Workspace) {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = Workspace::create(temp.path(), config()).expect("create");
    {
        let mut memory = Memory::new(&mut workspace);
        memory
            .commit(batch(
                "entity",
                vec![draft(&fixtures::entity())],
                Vec::new(),
            ))
            .expect("entity");
        let (source, blob) = build_source(
            SOURCE_ID,
            SOURCE_REV,
            &scope(),
            fixtures::SOURCE_TEXT.as_bytes(),
            "text/asciidoc",
            Some(fixtures::entity_id()),
            Some("project.adoc"),
        )
        .expect("source");
        memory
            .commit(batch("source", vec![source], vec![blob]))
            .expect("source commit");
    }
    (temp, workspace)
}

fn latest(workspace: &Workspace, record: RecordId) -> RecordEnvelope {
    workspace
        .record_revisions(record)
        .expect("history")
        .last()
        .cloned()
        .expect("revision")
}

#[allow(clippy::too_many_arguments)]
fn propose(
    workspace: &mut Workspace,
    key: &str,
    scope: &ScopeId,
    evidence_id: RecordId,
    evidence_revision: RevisionId,
    assertion_id: RecordId,
    assertion_revision: RevisionId,
    predicate: &str,
    value: Value,
    stance: Stance,
    valid_time: ValidTime,
    span: Option<SourceSpan>,
    ancestry: &[Reference],
    extraction: Option<(&str, &str)>,
) -> RecordId {
    let evidence = build_evidence(
        evidence_id,
        evidence_revision,
        scope,
        assertion_id,
        SOURCE_ID,
        SOURCE_REV,
        span,
        Some("storage-decision"),
        mneme_memory::SupportRelation::Supports,
        Origin::AuthoredStatement,
        ancestry,
    );
    let assertion = build_proposed_assertion(
        assertion_id,
        assertion_revision,
        scope,
        fixtures::entity_id(),
        predicate,
        value,
        stance,
        if extraction.is_some() {
            Origin::ModelExtraction
        } else {
            Origin::AuthoredStatement
        },
        "synthetic author",
        valid_time,
        &[Reference::local(
            evidence_id,
            mneme_core::RecordKind::Evidence,
        )],
        extraction,
        None,
    );
    {
        let mut memory = Memory::new(workspace);
        memory
            .commit(batch_in(scope, key, vec![evidence, assertion], Vec::new()))
            .expect("proposal commit");
    }
    assertion_id
}

#[allow(clippy::too_many_arguments)]
fn decide(
    workspace: &mut Workspace,
    key: &str,
    assertion: RecordId,
    lifecycle: Lifecycle,
    decision_id: RecordId,
    decision_revision: RevisionId,
    assertion_revision: RevisionId,
    kind: DecisionKind,
    outcome: &str,
    related: &[Reference],
) {
    let base = workspace.current_revision().expect("base");
    let current = latest(workspace, assertion);
    let decision = build_decision(
        decision_id,
        decision_revision,
        &scope(),
        kind,
        assertion,
        "policy actor",
        "test-policy/v1",
        base,
        outcome,
        "explicit test decision",
        &[],
        related,
    );
    let revision = build_assertion_revision(
        &current,
        assertion_revision,
        lifecycle,
        Reference::local(decision_id, mneme_core::RecordKind::Decision),
        None,
    );
    let mut memory = Memory::new(workspace);
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
        rid(0x10),
        rev(0x11),
        rid(0x20),
        rev(0x21),
        "storage-engine",
        Value::string("SQLite"),
        Stance::Affirm,
        ValidTime::always(),
        None,
        &[],
        None,
    );
    let at = Timestamp::parse("2026-11-10T00:00:00Z").expect("time");
    let view = BeliefView {
        scope: scope(),
        at,
        include_hypothetical: false,
        include_disputed: false,
    };
    {
        let memory = Memory::new(&mut workspace);
        assert!(memory.beliefs(&view).expect("beliefs").is_empty());
        let explanation = memory
            .explain(assertion_id, Policy::default())
            .expect("explain");
        assert_eq!(explanation.assertion.lifecycle, Lifecycle::Proposed);
        let again = memory
            .explain(assertion_id, Policy::default())
            .expect("explain");
        assert_eq!(again.assertion.lifecycle, Lifecycle::Proposed);
    }
    assert_eq!(
        latest(&workspace, assertion_id).assertion_lifecycle(),
        Some(Lifecycle::Proposed)
    );
}

#[test]
fn invalid_span_rejects_the_whole_batch() {
    let (_temp, mut workspace) = setup();
    let before = workspace.snapshot().expect("snapshot");
    let evidence = build_evidence(
        rid(0x10),
        rev(0x11),
        &scope(),
        rid(0x20),
        SOURCE_ID,
        SOURCE_REV,
        Some(SourceSpan::new(0, 10_000).expect("ordered")),
        None,
        mneme_memory::SupportRelation::Supports,
        Origin::AuthoredStatement,
        &[],
    );
    let assertion = build_proposed_assertion(
        rid(0x20),
        rev(0x21),
        &scope(),
        fixtures::entity_id(),
        "storage-engine",
        Value::string("SQLite"),
        Stance::Affirm,
        Origin::AuthoredStatement,
        "author",
        ValidTime::always(),
        &[Reference::local(
            rid(0x10),
            mneme_core::RecordKind::Evidence,
        )],
        None,
        None,
    );
    let error = {
        let mut memory = Memory::new(&mut workspace);
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
        rid(0x10),
        rev(0x11),
        rid(0x20),
        rev(0x21),
        "storage-engine",
        Value::string("SQLite"),
        Stance::Affirm,
        ValidTime::always(),
        None,
        &[],
        None,
    );
    let current = latest(&workspace, assertion_id);
    let accepted_without_decision = build_assertion_revision(
        &current,
        rev(0x22),
        Lifecycle::Accepted,
        Reference::local(rid(0x30), mneme_core::RecordKind::Decision),
        None,
    );
    let error = {
        let mut memory = Memory::new(&mut workspace);
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
        assertion_id,
        Lifecycle::Accepted,
        rid(0x30),
        rev(0x31),
        rev(0x22),
        DecisionKind::Acceptance,
        "accepted",
        &[],
    );
    let at = Timestamp::parse("2026-11-10T00:00:00Z").expect("time");
    let memory = Memory::new(&mut workspace);
    let beliefs = memory
        .beliefs(&BeliefView {
            scope: scope(),
            at,
            include_hypothetical: false,
            include_disputed: false,
        })
        .expect("beliefs");
    assert_eq!(beliefs.len(), 1);
    assert_eq!(beliefs[0].lifecycle, Lifecycle::Accepted);
}

#[test]
fn source_change_after_extraction_keeps_the_pinned_citation() {
    let (_temp, mut workspace) = setup();
    let assertion_id = propose(
        &mut workspace,
        "proposal",
        &scope(),
        rid(0x10),
        rev(0x11),
        rid(0x20),
        rev(0x21),
        "storage-engine",
        Value::string("SQLite"),
        Stance::Affirm,
        ValidTime::always(),
        Some(
            SourceSpan::new(
                fixtures::SOURCE_TEXT.find("SQLite").expect("present") as u64,
                fixtures::SOURCE_TEXT.find("SQLite").expect("present") as u64 + 5,
            )
            .expect("span"),
        ),
        &[],
        None,
    );
    decide(
        &mut workspace,
        "accept",
        assertion_id,
        Lifecycle::Accepted,
        rid(0x30),
        rev(0x31),
        rev(0x22),
        DecisionKind::Acceptance,
        "accepted",
        &[],
    );

    let changed = fixtures::SOURCE_TEXT.replace("SQLite", "LMDB");
    let (mut source, blob) = build_source(
        SOURCE_ID,
        rev(0x0c),
        &scope(),
        changed.as_bytes(),
        "text/asciidoc",
        Some(fixtures::entity_id()),
        Some("project.adoc"),
    )
    .expect("source");
    source.predecessor = Some(SOURCE_REV);
    {
        let mut memory = Memory::new(&mut workspace);
        memory
            .commit(batch("source-v2", vec![source], vec![blob]))
            .expect("source change");
        let explanation = memory
            .explain(assertion_id, Policy::default())
            .expect("explain");
        let evidence = &explanation.evidence[0];
        assert_eq!(evidence.source_revision, SOURCE_REV);
        let excerpt = evidence.excerpt.as_ref().expect("pinned excerpt");
        assert_eq!(String::from_utf8_lossy(&excerpt.bytes), "SQLite");
        assert!(!String::from_utf8_lossy(&excerpt.bytes).contains("LMDB"));
    }
}

#[allow(clippy::too_many_arguments)]
fn propose_bare(
    workspace: &mut Workspace,
    key: &str,
    scope: &ScopeId,
    assertion_id: RecordId,
    assertion_revision: RevisionId,
    predicate: &str,
    value: Value,
) -> RecordId {
    let assertion = build_proposed_assertion(
        assertion_id,
        assertion_revision,
        scope,
        fixtures::entity_id(),
        predicate,
        value,
        Stance::Affirm,
        Origin::AuthoredStatement,
        "author",
        ValidTime::always(),
        &[],
        None,
        None,
    );
    let mut memory = Memory::new(workspace);
    memory
        .commit(batch_in(scope, key, vec![assertion], Vec::new()))
        .expect("bare proposal");
    assertion_id
}

#[test]
fn future_and_unknown_validity_do_not_answer_the_current_view() {
    let (_temp, mut workspace) = setup();
    let future = Timestamp::parse("2030-01-01T00:00:00Z").expect("future");
    let future_claim = propose(
        &mut workspace,
        "future",
        &scope(),
        rid(0x10),
        rev(0x11),
        rid(0x20),
        rev(0x21),
        "future-change",
        Value::string("scheduled"),
        Stance::Affirm,
        ValidTime::since(future),
        None,
        &[],
        None,
    );
    decide(
        &mut workspace,
        "future-accept",
        future_claim,
        Lifecycle::Accepted,
        rid(0x30),
        rev(0x31),
        rev(0x22),
        DecisionKind::Acceptance,
        "accepted",
        &[],
    );
    let unknown_claim = propose(
        &mut workspace,
        "unknown",
        &scope(),
        rid(0x12),
        rev(0x13),
        rid(0x24),
        rev(0x25),
        "unknown-time",
        Value::string("unknown"),
        Stance::Affirm,
        ValidTime::Unknown,
        None,
        &[],
        None,
    );
    decide(
        &mut workspace,
        "unknown-accept",
        unknown_claim,
        Lifecycle::Accepted,
        rid(0x32),
        rev(0x33),
        rev(0x26),
        DecisionKind::Acceptance,
        "accepted",
        &[],
    );

    let memory = Memory::new(&mut workspace);
    let today = BeliefView {
        scope: scope(),
        at: Timestamp::parse("2026-11-10T00:00:00Z").expect("today"),
        include_hypothetical: false,
        include_disputed: false,
    };
    assert!(memory.beliefs(&today).expect("today").is_empty());
    let later = BeliefView {
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
    let hypothesis_scope =
        ScopeId::new(ScopeClass::Hypothesis, "plan-1").expect("hypothesis scope");
    let assertion_id = propose(
        &mut workspace,
        "hypothesis",
        &hypothesis_scope,
        rid(0x10),
        rev(0x11),
        rid(0x20),
        rev(0x21),
        "device-state",
        Value::string("maybe-offline"),
        Stance::Hypothesis,
        ValidTime::always(),
        None,
        &[],
        None,
    );
    let today = BeliefView {
        scope: scope(),
        at: Timestamp::parse("2026-11-10T00:00:00Z").expect("today"),
        include_hypothetical: false,
        include_disputed: false,
    };
    let memory = Memory::new(&mut workspace);
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
    let mut accepted = build_assertion_revision(
        &current,
        rev(0x22),
        Lifecycle::Accepted,
        Reference::local(rid(0x30), mneme_core::RecordKind::Decision),
        None,
    );
    accepted.scope = scope();
    let base = workspace.current_revision().expect("base");
    let decision = build_decision(
        rid(0x30),
        rev(0x31),
        &scope(),
        DecisionKind::Acceptance,
        assertion_id,
        "policy actor",
        "promotion-policy/v1",
        base,
        "accepted",
        "explicit hypothesis promotion",
        &[],
        &[],
    );
    {
        let mut memory = Memory::new(&mut workspace);
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
        rid(0x10),
        rev(0x11),
        rid(0x20),
        rev(0x21),
        "storage-engine",
        Value::string("SQLite"),
        Stance::Affirm,
        ValidTime::always(),
        None,
        &[],
        None,
    );
    let second = propose(
        &mut workspace,
        "second-claim",
        &scope(),
        rid(0x12),
        rev(0x13),
        rid(0x24),
        rev(0x25),
        "storage-engine",
        Value::string("LMDB"),
        Stance::Affirm,
        ValidTime::always(),
        None,
        &[],
        None,
    );
    decide(
        &mut workspace,
        "first-accept",
        first,
        Lifecycle::Accepted,
        rid(0x30),
        rev(0x31),
        rev(0x22),
        DecisionKind::Acceptance,
        "accepted",
        &[],
    );
    decide(
        &mut workspace,
        "second-accept",
        second,
        Lifecycle::Accepted,
        rid(0x32),
        rev(0x33),
        rev(0x26),
        DecisionKind::Acceptance,
        "accepted",
        &[],
    );
    let view = BeliefView {
        scope: scope(),
        at: Timestamp::parse("2026-11-10T00:00:00Z").expect("today"),
        include_hypothetical: false,
        include_disputed: true,
    };
    let memory = Memory::new(&mut workspace);
    let conflicts = memory.conflicts(&view).expect("conflicts");
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].assertions.len(), 2);
    let _ = memory;

    // Explicitly mark both claims disputed with related links.
    let first_envelope = latest(&workspace, first);
    let second_envelope = latest(&workspace, second);
    let first_disputed = build_assertion_revision(
        &first_envelope,
        rev(0x23),
        Lifecycle::Disputed,
        Reference::local(rid(0x34), mneme_core::RecordKind::Decision),
        None,
    );
    let second_disputed = build_assertion_revision(
        &second_envelope,
        rev(0x27),
        Lifecycle::Disputed,
        Reference::local(rid(0x36), mneme_core::RecordKind::Decision),
        None,
    );
    let base = workspace.current_revision().expect("base");
    let decision_first = build_decision(
        rid(0x34),
        rev(0x35),
        &scope(),
        DecisionKind::ConflictResolution,
        first,
        "policy actor",
        "conflict-policy/v1",
        base,
        "disputed",
        "contradictory functional claims",
        &[],
        &[Reference::local(second, mneme_core::RecordKind::Assertion)],
    );
    let decision_second = build_decision(
        rid(0x36),
        rev(0x37),
        &scope(),
        DecisionKind::ConflictResolution,
        second,
        "policy actor",
        "conflict-policy/v1",
        base,
        "disputed",
        "contradictory functional claims",
        &[],
        &[Reference::local(first, mneme_core::RecordKind::Assertion)],
    );
    {
        let mut memory = Memory::new(&mut workspace);
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
        let accepted_only = BeliefView {
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
        rid(0x10),
        rev(0x11),
        rid(0x20),
        rev(0x21),
        "storage-engine",
        Value::string("SQLite"),
        Stance::Affirm,
        ValidTime::between(
            Timestamp::parse("2020-01-01T00:00:00Z").expect("start"),
            Timestamp::parse("2021-01-01T00:00:00Z").expect("end"),
        )
        .expect("interval"),
        None,
        &[],
        None,
    );
    let future = propose(
        &mut workspace,
        "future",
        &scope(),
        rid(0x12),
        rev(0x13),
        rid(0x24),
        rev(0x25),
        "storage-engine",
        Value::string("LMDB"),
        Stance::Affirm,
        ValidTime::between(
            Timestamp::parse("2022-01-01T00:00:00Z").expect("start"),
            Timestamp::parse("2023-01-01T00:00:00Z").expect("end"),
        )
        .expect("interval"),
        None,
        &[],
        None,
    );
    decide(
        &mut workspace,
        "past-accept",
        past,
        Lifecycle::Accepted,
        rid(0x30),
        rev(0x31),
        rev(0x22),
        DecisionKind::Acceptance,
        "accepted",
        &[],
    );
    decide(
        &mut workspace,
        "future-accept",
        future,
        Lifecycle::Accepted,
        rid(0x32),
        rev(0x33),
        rev(0x26),
        DecisionKind::Acceptance,
        "accepted",
        &[],
    );
    let view = BeliefView {
        scope: scope(),
        at: Timestamp::parse("2024-06-01T00:00:00Z").expect("at"),
        include_hypothetical: false,
        include_disputed: false,
    };
    let memory = Memory::new(&mut workspace);
    assert!(memory.conflicts(&view).expect("conflicts").is_empty());
}

#[test]
fn derivations_offer_independent_alternatives_and_survive_one_withdrawal() {
    let (_temp, mut workspace) = setup();
    let premise_one = propose(
        &mut workspace,
        "p1",
        &scope(),
        rid(0x10),
        rev(0x11),
        rid(0x20),
        rev(0x21),
        "premise-one",
        Value::string("yes"),
        Stance::Affirm,
        ValidTime::always(),
        None,
        &[],
        None,
    );
    let premise_two = propose(
        &mut workspace,
        "p2",
        &scope(),
        rid(0x12),
        rev(0x13),
        rid(0x24),
        rev(0x25),
        "premise-two",
        Value::string("yes"),
        Stance::Affirm,
        ValidTime::always(),
        None,
        &[],
        None,
    );
    let premise_three = propose(
        &mut workspace,
        "p3",
        &scope(),
        rid(0x14),
        rev(0x15),
        rid(0x28),
        rev(0x29),
        "premise-three",
        Value::string("yes"),
        Stance::Affirm,
        ValidTime::always(),
        None,
        &[],
        None,
    );
    decide(
        &mut workspace,
        "p1a",
        premise_one,
        Lifecycle::Accepted,
        rid(0x40),
        rev(0x41),
        rev(0x22),
        DecisionKind::Acceptance,
        "accepted",
        &[],
    );
    decide(
        &mut workspace,
        "p2a",
        premise_two,
        Lifecycle::Accepted,
        rid(0x42),
        rev(0x43),
        rev(0x26),
        DecisionKind::Acceptance,
        "accepted",
        &[],
    );
    decide(
        &mut workspace,
        "p3a",
        premise_three,
        Lifecycle::Accepted,
        rid(0x44),
        rev(0x45),
        rev(0x2a),
        DecisionKind::Acceptance,
        "accepted",
        &[],
    );
    let conclusion = propose_bare(
        &mut workspace,
        "conclusion",
        &scope(),
        rid(0x30),
        rev(0x31),
        "conclusion",
        Value::string("derived"),
    );
    decide(
        &mut workspace,
        "conclusion-a",
        conclusion,
        Lifecycle::Accepted,
        rid(0x46),
        rev(0x47),
        rev(0x32),
        DecisionKind::Acceptance,
        "accepted",
        &[],
    );
    let base = workspace.current_revision().expect("base");
    let derivation_one = build_derivation(
        rid(0x50),
        rev(0x51),
        &scope(),
        conclusion,
        &[
            Reference::local(premise_one, mneme_core::RecordKind::Assertion),
            Reference::local(premise_two, mneme_core::RecordKind::Assertion),
        ],
        "rule-a",
        1,
        base,
        "complete",
    );
    let derivation_two = build_derivation(
        rid(0x52),
        rev(0x53),
        &scope(),
        conclusion,
        &[Reference::local(
            premise_three,
            mneme_core::RecordKind::Assertion,
        )],
        "rule-b",
        1,
        base,
        "complete",
    );
    {
        let mut memory = Memory::new(&mut workspace);
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
        premise_one,
        Lifecycle::Retracted,
        rid(0x48),
        rev(0x49),
        rev(0x23),
        DecisionKind::Retraction,
        "retracted",
        &[],
    );
    let memory = Memory::new(&mut workspace);
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
        rid(0x20),
        rev(0x21),
        "cycle-a",
        Value::string("a"),
    );
    let second = propose_bare(
        &mut workspace,
        "cycle-b",
        &scope(),
        rid(0x24),
        rev(0x25),
        "cycle-b",
        Value::string("b"),
    );
    decide(
        &mut workspace,
        "cycle-a-accept",
        first,
        Lifecycle::Accepted,
        rid(0x30),
        rev(0x31),
        rev(0x22),
        DecisionKind::Acceptance,
        "accepted",
        &[],
    );
    decide(
        &mut workspace,
        "cycle-b-accept",
        second,
        Lifecycle::Accepted,
        rid(0x32),
        rev(0x33),
        rev(0x26),
        DecisionKind::Acceptance,
        "accepted",
        &[],
    );
    let base = workspace.current_revision().expect("base");
    let derivation_a = build_derivation(
        rid(0x40),
        rev(0x41),
        &scope(),
        first,
        &[Reference::local(second, mneme_core::RecordKind::Assertion)],
        "cycle-rule",
        1,
        base,
        "complete",
    );
    let derivation_b = build_derivation(
        rid(0x42),
        rev(0x43),
        &scope(),
        second,
        &[Reference::local(first, mneme_core::RecordKind::Assertion)],
        "cycle-rule",
        1,
        base,
        "complete",
    );
    let mut memory = Memory::new(&mut workspace);
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
    let evidence_one = build_evidence(
        rid(0x10),
        rev(0x11),
        &scope(),
        assertion_id,
        SOURCE_ID,
        SOURCE_REV,
        Some(SourceSpan::new(0, 3).expect("span")),
        None,
        mneme_memory::SupportRelation::Supports,
        Origin::AuthoredStatement,
        &[],
    );
    let evidence_two = build_evidence(
        rid(0x12),
        rev(0x13),
        &scope(),
        assertion_id,
        SOURCE_ID,
        SOURCE_REV,
        Some(SourceSpan::new(4, 7).expect("span")),
        None,
        mneme_memory::SupportRelation::Supports,
        Origin::AuthoredStatement,
        &[Reference::local(
            rid(0x10),
            mneme_core::RecordKind::Evidence,
        )],
    );
    let evidence_three = build_evidence(
        rid(0x14),
        rev(0x15),
        &scope(),
        assertion_id,
        SOURCE_ID,
        SOURCE_REV,
        Some(SourceSpan::new(8, 12).expect("span")),
        None,
        mneme_memory::SupportRelation::Supports,
        Origin::AuthoredStatement,
        &[Reference::local(
            rid(0x10),
            mneme_core::RecordKind::Evidence,
        )],
    );
    let assertion = build_proposed_assertion(
        assertion_id,
        rev(0x21),
        &scope(),
        fixtures::entity_id(),
        "corroborated",
        Value::string("yes"),
        Stance::Affirm,
        Origin::AuthoredStatement,
        "author",
        ValidTime::always(),
        &[
            Reference::local(rid(0x10), mneme_core::RecordKind::Evidence),
            Reference::local(rid(0x12), mneme_core::RecordKind::Evidence),
            Reference::local(rid(0x14), mneme_core::RecordKind::Evidence),
        ],
        None,
        None,
    );
    {
        let mut memory = Memory::new(&mut workspace);
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
        assertion_id,
        Lifecycle::Accepted,
        rid(0x30),
        rev(0x31),
        rev(0x22),
        DecisionKind::Acceptance,
        "accepted",
        &[],
    );
    let memory = Memory::new(&mut workspace);
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
    let evidence_one = build_evidence(
        rid(0x10),
        rev(0x11),
        &scope(),
        assertion_id,
        SOURCE_ID,
        SOURCE_REV,
        Some(SourceSpan::new(0, 3).expect("span")),
        None,
        mneme_memory::SupportRelation::Supports,
        Origin::AuthoredStatement,
        &[Reference::local(
            rid(0x12),
            mneme_core::RecordKind::Evidence,
        )],
    );
    let evidence_two = build_evidence(
        rid(0x12),
        rev(0x13),
        &scope(),
        assertion_id,
        SOURCE_ID,
        SOURCE_REV,
        Some(SourceSpan::new(4, 7).expect("span")),
        None,
        mneme_memory::SupportRelation::Supports,
        Origin::AuthoredStatement,
        &[Reference::local(
            rid(0x10),
            mneme_core::RecordKind::Evidence,
        )],
    );
    let assertion = build_proposed_assertion(
        assertion_id,
        rev(0x21),
        &scope(),
        fixtures::entity_id(),
        "cyclic",
        Value::string("no"),
        Stance::Affirm,
        Origin::AuthoredStatement,
        "author",
        ValidTime::always(),
        &[
            Reference::local(rid(0x10), mneme_core::RecordKind::Evidence),
            Reference::local(rid(0x12), mneme_core::RecordKind::Evidence),
        ],
        None,
        None,
    );
    let error = {
        let mut memory = Memory::new(&mut workspace);
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
        rid(0x10),
        rev(0x11),
        rid(0x20),
        rev(0x21),
        "storage-engine",
        Value::string("SQLite"),
        Stance::Affirm,
        ValidTime::always(),
        Some(
            SourceSpan::new(
                fixtures::SOURCE_TEXT.find("SQLite").expect("present") as u64,
                fixtures::SOURCE_TEXT.find("SQLite").expect("present") as u64 + 5,
            )
            .expect("span"),
        ),
        &[],
        None,
    );
    decide(
        &mut workspace,
        "accept",
        assertion_id,
        Lifecycle::Accepted,
        rid(0x30),
        rev(0x31),
        rev(0x22),
        DecisionKind::Acceptance,
        "accepted",
        &[],
    );
    let (mut pruned, _) = (
        build_unavailable_source(
            SOURCE_ID,
            rev(0x53),
            &scope(),
            "raw bytes pruned under retention policy",
            "pruned",
            Some(fixtures::entity_id()),
            Some("project.adoc"),
        ),
        (),
    );
    pruned.predecessor = Some(SOURCE_REV);
    {
        let mut memory = Memory::new(&mut workspace);
        memory
            .commit(batch("prune", vec![pruned], Vec::new()))
            .expect("prune");
        let explanation = memory
            .explain(assertion_id, Policy::default())
            .expect("explain");
        assert_eq!(
            explanation.evidence[0].availability,
            mneme_memory::SourceAvailability::Pruned
        );
        assert!(explanation.evidence[0].excerpt.is_none());
        assert_eq!(explanation.assertion.lifecycle, Lifecycle::Accepted);
    }
}

#[test]
fn correction_retraction_and_history_do_not_assert_the_opposite() {
    let (_temp, mut workspace) = setup();
    let assertion_id = propose(
        &mut workspace,
        "proposal",
        &scope(),
        rid(0x10),
        rev(0x11),
        rid(0x20),
        rev(0x21),
        "storage-engine",
        Value::string("SQLite"),
        Stance::Affirm,
        ValidTime::always(),
        None,
        &[],
        None,
    );
    decide(
        &mut workspace,
        "accept",
        assertion_id,
        Lifecycle::Accepted,
        rid(0x30),
        rev(0x31),
        rev(0x22),
        DecisionKind::Acceptance,
        "accepted",
        &[],
    );
    let accepted = latest(&workspace, assertion_id);
    let mut corrected = build_assertion_revision(
        &accepted,
        rev(0x23),
        Lifecycle::Accepted,
        Reference::local(rid(0x32), mneme_core::RecordKind::Decision),
        None,
    );
    corrected
        .payload
        .insert(Symbol::from("value"), Value::string("LMDB"));
    corrected.payload.insert(
        Symbol::from("valid-time"),
        ValidTime::between(
            Timestamp::parse("2020-01-01T00:00:00Z").expect("start"),
            Timestamp::parse("2021-01-01T00:00:00Z").expect("end"),
        )
        .expect("interval")
        .to_value(),
    );
    let base = workspace.current_revision().expect("base");
    let correction_decision = build_decision(
        rid(0x32),
        rev(0x33),
        &scope(),
        DecisionKind::Acceptance,
        assertion_id,
        "policy actor",
        "correction-policy/v1",
        base,
        "accepted",
        "corrected after review",
        &[],
        &[],
    );
    {
        let mut memory = Memory::new(&mut workspace);
        memory
            .commit(batch(
                "correct",
                vec![correction_decision, corrected],
                Vec::new(),
            ))
            .expect("correction");
        let beliefs = memory
            .beliefs(&BeliefView {
                scope: scope(),
                at: Timestamp::parse("2020-06-01T00:00:00Z").expect("historical"),
                include_hypothetical: false,
                include_disputed: false,
            })
            .expect("beliefs");
        assert_eq!(beliefs.len(), 1);
        assert_eq!(beliefs[0].value, Value::string("LMDB"));
        assert_eq!(memory.revisions(assertion_id).expect("history").len(), 3);
        let explanation = memory
            .explain(assertion_id, Policy::default())
            .expect("corrected explanation");
        assert_eq!(explanation.assertion.lifecycle, Lifecycle::Accepted);
        assert!(explanation.decisions.len() >= 2);
        assert_eq!(
            explanation.evidence[0].availability,
            mneme_memory::SourceAvailability::Retained
        );
    }
    decide(
        &mut workspace,
        "retract",
        assertion_id,
        Lifecycle::Retracted,
        rid(0x34),
        rev(0x35),
        rev(0x24),
        DecisionKind::Retraction,
        "retracted",
        &[],
    );
    let memory = Memory::new(&mut workspace);
    assert!(
        memory
            .beliefs(&BeliefView {
                scope: scope(),
                at: Timestamp::parse("2026-11-10T00:00:00Z").expect("today"),
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
            .all(|assertion| !matches!(assertion.stance, Stance::Deny))
    );
}

#[test]
fn action_intent_without_an_observed_outcome_cannot_be_completed() {
    let (_temp, mut workspace) = setup();
    let intent = build_episode(
        rid(0x10),
        rev(0x11),
        &scope(),
        "agent",
        "intent",
        ValidTime::Unknown,
        "plan to test the device",
        None,
        &[],
    );
    let attempt = build_episode(
        rid(0x12),
        rev(0x13),
        &scope(),
        "agent",
        "attempt",
        ValidTime::Unknown,
        "attempted the test with unknown result",
        None,
        &[Reference::local(rid(0x10), mneme_core::RecordKind::Episode)],
    );
    {
        let mut memory = Memory::new(&mut workspace);
        memory
            .commit(batch("episodes", vec![intent, attempt], Vec::new()))
            .expect("episodes");
    }
    let assertion_id = rid(0x20);
    let evidence = build_evidence(
        rid(0x14),
        rev(0x15),
        &scope(),
        assertion_id,
        SOURCE_ID,
        SOURCE_REV,
        Some(SourceSpan::new(0, 4).expect("span")),
        None,
        mneme_memory::SupportRelation::Supports,
        Origin::Observation,
        &[Reference::local(rid(0x12), mneme_core::RecordKind::Episode)],
    );
    let completed = build_proposed_assertion(
        assertion_id,
        rev(0x21),
        &scope(),
        fixtures::entity_id(),
        "action-completed",
        Value::string("device tested"),
        Stance::Affirm,
        Origin::Observation,
        "agent",
        ValidTime::always(),
        &[Reference::local(
            rid(0x14),
            mneme_core::RecordKind::Evidence,
        )],
        None,
        None,
    );
    {
        let mut memory = Memory::new(&mut workspace);
        let error = memory
            .commit(batch(
                "false-completion",
                vec![evidence, completed],
                Vec::new(),
            ))
            .expect_err("no observed outcome");
        assert!(error.to_string().contains("observed outcome"));
    }

    let outcome = build_episode(
        rid(0x16),
        rev(0x17),
        &scope(),
        "agent",
        "outcome",
        ValidTime::Unknown,
        "device responded",
        None,
        &[Reference::local(rid(0x12), mneme_core::RecordKind::Episode)],
    );
    {
        let mut memory = Memory::new(&mut workspace);
        memory
            .commit(batch("outcome", vec![outcome], Vec::new()))
            .expect("outcome");
    }
    let evidence = build_evidence(
        rid(0x14),
        rev(0x15),
        &scope(),
        assertion_id,
        SOURCE_ID,
        SOURCE_REV,
        Some(SourceSpan::new(0, 4).expect("span")),
        None,
        mneme_memory::SupportRelation::Supports,
        Origin::Observation,
        &[Reference::local(rid(0x16), mneme_core::RecordKind::Episode)],
    );
    let completed = build_proposed_assertion(
        assertion_id,
        rev(0x21),
        &scope(),
        fixtures::entity_id(),
        "action-completed",
        Value::string("device tested"),
        Stance::Affirm,
        Origin::Observation,
        "agent",
        ValidTime::always(),
        &[Reference::local(
            rid(0x14),
            mneme_core::RecordKind::Evidence,
        )],
        None,
        None,
    );
    let checkpoint = build_checkpoint(
        rid(0x18),
        rev(0x19),
        &scope(),
        "verify device",
        "awaiting-verification",
        &[Reference::local(rid(0x10), mneme_core::RecordKind::Episode)],
        &[Reference::local(rid(0x16), mneme_core::RecordKind::Episode)],
        workspace.current_revision().expect("revision"),
        None,
    );
    {
        let mut memory = Memory::new(&mut workspace);
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
    let mut assertion = build_proposed_assertion(
        assertion_id,
        rev(0x21),
        &scope(),
        fixtures::entity_id(),
        "blocker",
        Value::string("none"),
        Stance::Deny,
        Origin::AuthoredStatement,
        "author",
        ValidTime::always(),
        &[],
        None,
        None,
    );
    {
        let mut memory = Memory::new(&mut workspace);
        memory
            .commit(batch("absence", vec![assertion.clone()], Vec::new()))
            .expect("proposed absence");
    }
    let current = latest(&workspace, assertion_id);
    let accepted = build_assertion_revision(
        &current,
        rev(0x22),
        Lifecycle::Accepted,
        Reference::local(rid(0x30), mneme_core::RecordKind::Decision),
        None,
    );
    let base = workspace.current_revision().expect("base");
    let decision = build_decision(
        rid(0x30),
        rev(0x31),
        &scope(),
        DecisionKind::Acceptance,
        assertion_id,
        "policy actor",
        "absence-policy/v1",
        base,
        "accepted",
        "attempted acceptance",
        &[],
        &[],
    );
    {
        let mut memory = Memory::new(&mut workspace);
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
        Symbol::from("completeness"),
        Value::symbol("declared-complete"),
    );
    assertion.revision_id = rev(0x23);
    assertion.predecessor = Some(rev(0x21));
    {
        let mut memory = Memory::new(&mut workspace);
        memory
            .commit(batch("declared-absence", vec![assertion], Vec::new()))
            .expect("declared complete basis");
    }
    let current = latest(&workspace, assertion_id);
    let accepted = build_assertion_revision(
        &current,
        rev(0x24),
        Lifecycle::Accepted,
        Reference::local(rid(0x32), mneme_core::RecordKind::Decision),
        None,
    );
    let base = workspace.current_revision().expect("base");
    let decision = build_decision(
        rid(0x32),
        rev(0x33),
        &scope(),
        DecisionKind::Acceptance,
        assertion_id,
        "policy actor",
        "absence-policy/v1",
        base,
        "accepted",
        "declared-complete absence",
        &[],
        &[],
    );
    let mut memory = Memory::new(&mut workspace);
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
        rid(0x10),
        rev(0x11),
        rid(0x20),
        rev(0x21),
        "storage-engine",
        Value::string("SQLite"),
        Stance::Affirm,
        ValidTime::always(),
        None,
        &[],
        None,
    );
    decide(
        &mut workspace,
        "old-accept",
        old,
        Lifecycle::Accepted,
        rid(0x30),
        rev(0x31),
        rev(0x22),
        DecisionKind::Acceptance,
        "accepted",
        &[],
    );
    let replacement = propose(
        &mut workspace,
        "new",
        &scope(),
        rid(0x12),
        rev(0x13),
        rid(0x24),
        rev(0x25),
        "storage-engine",
        Value::string("LMDB"),
        Stance::Affirm,
        ValidTime::always(),
        None,
        &[],
        None,
    );
    decide(
        &mut workspace,
        "new-accept",
        replacement,
        Lifecycle::Accepted,
        rid(0x32),
        rev(0x33),
        rev(0x26),
        DecisionKind::Acceptance,
        "accepted",
        &[],
    );
    let current_old = latest(&workspace, old);
    let mut superseded = build_assertion_revision(
        &current_old,
        rev(0x23),
        Lifecycle::Superseded,
        Reference::local(rid(0x34), mneme_core::RecordKind::Decision),
        Some(Reference::local(
            replacement,
            mneme_core::RecordKind::Assertion,
        )),
    );
    superseded.predecessor = Some(current_old.revision_id);
    let base = workspace.current_revision().expect("base");
    let decision = build_decision(
        rid(0x34),
        rev(0x35),
        &scope(),
        DecisionKind::Supersession,
        old,
        "policy actor",
        "supersession-policy/v1",
        base,
        "superseded",
        "replaced by LMDB",
        &[],
        &[Reference::local(
            replacement,
            mneme_core::RecordKind::Assertion,
        )],
    );
    {
        let mut memory = Memory::new(&mut workspace);
        memory
            .commit(batch("supersede", vec![decision, superseded], Vec::new()))
            .expect("supersession");
        let beliefs = memory
            .beliefs(&BeliefView {
                scope: scope(),
                at: Timestamp::parse("2026-11-10T00:00:00Z").expect("today"),
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
    let evidence = build_evidence(
        rid(0x10),
        rev(0x11),
        &scope(),
        assertion_id,
        SOURCE_ID,
        rev(0x54),
        Some(SourceSpan::new(0, 3).expect("span")),
        None,
        mneme_memory::SupportRelation::Supports,
        Origin::AuthoredStatement,
        &[],
    );
    let assertion = build_proposed_assertion(
        assertion_id,
        rev(0x21),
        &scope(),
        fixtures::entity_id(),
        "storage-engine",
        Value::string("SQLite"),
        Stance::Affirm,
        Origin::AuthoredStatement,
        "author",
        ValidTime::always(),
        &[Reference::local(
            rid(0x10),
            mneme_core::RecordKind::Evidence,
        )],
        None,
        None,
    );
    {
        let mut memory = Memory::new(&mut workspace);
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
        rid(0x12),
        rev(0x13),
        rid(0x24),
        rev(0x25),
        "stale-decision",
        Value::string("value"),
        Stance::Affirm,
        ValidTime::always(),
        None,
        &[],
        None,
    );
    // Advance the workspace so the decision's input revision is stale.
    let mut workspace = workspace;
    {
        let mut memory = Memory::new(&mut workspace);
        memory
            .commit(batch(
                "advance",
                vec![build_proposed_assertion(
                    rid(0x30),
                    rev(0x31),
                    &scope(),
                    fixtures::entity_id(),
                    "unrelated",
                    Value::string("x"),
                    Stance::Affirm,
                    Origin::AuthoredStatement,
                    "author",
                    ValidTime::always(),
                    &[],
                    None,
                    None,
                )],
                Vec::new(),
            ))
            .expect("advance");
    }
    let current = latest(&workspace, assertion_id);
    let accepted = build_assertion_revision(
        &current,
        rev(0x26),
        Lifecycle::Accepted,
        Reference::local(rid(0x40), mneme_core::RecordKind::Decision),
        None,
    );
    let decision = build_decision(
        rid(0x40),
        rev(0x41),
        &scope(),
        DecisionKind::Acceptance,
        assertion_id,
        "policy actor",
        "stale-policy/v1",
        WorkspaceRevisionId::from_bytes([0x7f; 16]),
        "accepted",
        "stale decision",
        &[],
        &[],
    );
    let mut memory = Memory::new(&mut workspace);
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
            rid(0x10),
            rev(0x11),
            rid(0x20),
            rev(0x21),
            "storage-engine",
            Value::string("SQLite"),
            Stance::Affirm,
            ValidTime::always(),
            Some(SourceSpan::new(0, 5).expect("span")),
            &[],
            None,
        );
        decide(
            &mut workspace,
            "accept",
            assertion,
            Lifecycle::Accepted,
            rid(0x30),
            rev(0x31),
            rev(0x22),
            DecisionKind::Acceptance,
            "accepted",
            &[],
        );
        let mut replacement = build_unavailable_source(
            SOURCE_ID,
            rev(0x55),
            &scope(),
            reason,
            availability,
            Some(fixtures::entity_id()),
            Some("project.adoc"),
        );
        replacement.predecessor = Some(SOURCE_REV);
        {
            let mut memory = Memory::new(&mut workspace);
            memory
                .commit(batch("unavailable", vec![replacement], Vec::new()))
                .expect("source state");
            let explanation = memory
                .explain(assertion, Policy::default())
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
        rid(0x10),
        rev(0x11),
        rid(0x20),
        rev(0x21),
        "storage-engine",
        Value::string("SQLite"),
        Stance::Affirm,
        ValidTime::always(),
        None,
        &[],
        None,
    );
    decide(
        &mut workspace,
        "accept",
        assertion,
        Lifecycle::Accepted,
        rid(0x30),
        rev(0x31),
        rev(0x22),
        DecisionKind::Acceptance,
        "accepted",
        &[],
    );
    let generation = workspace.eligibility_generation().expect("generation");
    workspace.advance_eligibility_barrier().expect("barrier");
    let memory = Memory::new(&mut workspace);
    let error = memory
        .explain_at(assertion, Some(generation), Policy::default())
        .expect_err("stale generation");
    assert!(matches!(
        error,
        mneme_memory::MemoryError::Store(mneme_store::StoreError::BarrierAdvanced { .. })
    ));
}
