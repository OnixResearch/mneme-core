//! End-to-end ASPIC+ argumentation and Subjective Logic opinion tests.
#![allow(unknown_lints, no_unwrap)] // test assertions panic on failure
#![allow(clippy::unwrap_used, clippy::expect_used)] // test assertions panic on failure

const SOURCE_ID: mneme_core::RecordId = mneme_core::RecordId::from_bytes([0x02; 16]);
const SOURCE_REV: mneme_core::RevisionId = mneme_core::RevisionId::from_bytes([0x52; 16]);

fn scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
}

fn rid(byte: u8) -> mneme_core::RecordId {
    mneme_core::RecordId::from_bytes([byte; 16])
}

fn rev(byte: u8) -> mneme_core::RevisionId {
    mneme_core::RevisionId::from_bytes([byte; 16])
}

fn engine(workspace: &mut mneme_store::Workspace) -> mneme_memory::Engine<'_> {
    mneme_memory::Engine::new(workspace, mneme_memory::Access::Operator)
}

fn batch(
    key: &str,
    records: Vec<mneme_store::RecordDraft>,
    sources: Vec<mneme_store::SourceBlobDraft>,
) -> mneme_memory::Batch {
    mneme_memory::Batch {
        actor: "test-author".to_owned(),
        scope: scope(),
        idempotency_key: key.to_owned(),
        records,
        source_blobs: sources,
        publications: Vec::new(),
    }
}

fn setup() -> (tempfile::TempDir, mneme_store::Workspace) {
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
    let ent = mneme_core::fixtures::entity();
    let ent_draft = mneme_store::RecordDraft {
        schema_version: ent.schema_version,
        kind: ent.kind,
        record_id: ent.record_id,
        revision_id: ent.revision_id,
        predecessor: ent.predecessor,
        scope: ent.scope,
        payload: ent.payload,
    };
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
    {
        let mut memory = engine(&mut workspace);
        memory
            .commit(batch("init", vec![ent_draft, source], vec![blob]))
            .expect("init commit");
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

struct Transition<'a> {
    assertion: mneme_core::RecordId,
    lifecycle: mneme_core::Lifecycle,
    decision_id: mneme_core::RecordId,
    decision_rev: mneme_core::RevisionId,
    assertion_rev: mneme_core::RevisionId,
    kind: mneme_memory::DecisionKind,
    outcome: &'a str,
    evidence: &'a [mneme_core::Reference],
    related: &'a [mneme_core::Reference],
}

fn decide(workspace: &mut mneme_store::Workspace, key: &str, tr: Transition<'_>) {
    let base = workspace.current_revision().expect("base");
    let current = latest(workspace, tr.assertion);
    let decision = mneme_memory::build_decision(
        tr.decision_id,
        tr.decision_rev,
        &scope(),
        mneme_memory::DecisionOptions {
            kind: tr.kind,
            target: tr.assertion,
            actor: "test-author",
            policy: "test-policy/v1",
            input_revision: base,
            outcome: tr.outcome,
            rationale: "explicit test decision",
            evidence: tr.evidence,
            related: tr.related,
        },
    );
    let revision = mneme_memory::build_assertion_revision(
        &current,
        tr.assertion_rev,
        tr.lifecycle,
        mneme_core::Reference::local(tr.decision_id, mneme_core::RecordKind::Decision),
        None,
    );
    let mut memory = engine(workspace);
    memory
        .commit(batch(key, vec![decision, revision], Vec::new()))
        .expect("decision commit");
}

fn accept(
    workspace: &mut mneme_store::Workspace,
    key: &str,
    assertion: mneme_core::RecordId,
    ids: (
        mneme_core::RecordId,
        mneme_core::RevisionId,
        mneme_core::RevisionId,
    ),
    related: &[mneme_core::Reference],
) {
    decide(
        workspace,
        key,
        Transition {
            assertion,
            lifecycle: mneme_core::Lifecycle::Accepted,
            decision_id: ids.0,
            decision_rev: ids.1,
            assertion_rev: ids.2,
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            evidence: &[],
            related,
        },
    );
}

fn commit_source(
    workspace: &mut mneme_store::Workspace,
    key: &str,
    source_id: mneme_core::RecordId,
    source_rev: mneme_core::RevisionId,
    body: &[u8],
) {
    let (source, blob) = mneme_memory::build_source(
        source_id,
        source_rev,
        &scope(),
        mneme_memory::SourceOptions {
            bytes: body,
            media_type: "text/plain",
            entity: Some(mneme_core::fixtures::entity_id()),
            path_hint: Some("note.txt"),
        },
    )
    .expect("build source");
    let mut memory = engine(workspace);
    memory
        .commit(batch(key, vec![source], vec![blob]))
        .expect("commit source");
}

fn withdraw_record(
    workspace: &mut mneme_store::Workspace,
    key: &str,
    target: mneme_core::RecordId,
    target_kind: &str,
) {
    let base = workspace.current_revision().expect("base");
    let generation = workspace
        .eligibility_generation()
        .expect("generation")
        .saturating_add(1);
    workspace
        .commit(mneme_store::CommitCommand {
            base,
            actor: "test-author".to_owned(),
            scope: scope(),
            idempotency_key: key.to_owned(),
            records: Vec::new(),
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: Some(mneme_store::RetentionCommit {
                operation_id: key.to_owned(),
                operation_kind: "withdraw".to_owned(),
                policy_version: "1".to_owned(),
                selectors: Vec::new(),
                suppressions: vec![mneme_store::RetentionSuppression {
                    operation_id: key.to_owned(),
                    target,
                    revision: None,
                    target_kind: target_kind.to_owned(),
                    mode: mneme_store::SuppressionMode::Withdrawn,
                    content_digest: None,
                    generation,
                }],
                locations: Vec::new(),
                retained_metadata: Vec::new(),
            }),
        })
        .expect("withdraw commit");
}

fn belief_view() -> mneme_memory::BeliefView {
    mneme_memory::BeliefView {
        scope: scope(),
        at: mneme_core::Timestamp::from_nanos(1_000),
        include_disputed: true,
        include_hypothetical: false,
    }
}

fn explain_policy() -> mneme_memory::Policy {
    mneme_memory::Policy {
        max_explanation_nodes: 64,
        max_excerpt_bytes: 256,
    }
}

fn propose_bare(
    workspace: &mut mneme_store::Workspace,
    key: &str,
    id_byte: u8,
    predicate: &str,
    value: &str,
) -> mneme_core::RecordId {
    let assertion = mneme_memory::build_proposed_assertion(
        rid(id_byte),
        rev(id_byte),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate,
            value: mneme_core::Value::String(value.to_owned()),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[],
            extraction: None,
            superseded_by: None,
        },
    );
    let mut memory = engine(workspace);
    memory
        .commit(batch(key, vec![assertion], Vec::new()))
        .expect("bare proposal");
    rid(id_byte)
}

fn propose_accepted_claim(
    workspace: &mut mneme_store::Workspace,
    key: &str,
    ids: (u8, u8, u8),
    predicate: &str,
    value: &str,
) -> mneme_core::RecordId {
    let evidence = mneme_memory::build_evidence(
        rid(ids.0),
        rev(ids.0),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: rid(ids.1),
            source: SOURCE_ID,
            source_revision: SOURCE_REV,
            span: None,
            anchor: Some("claim"),
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let assertion = mneme_memory::build_proposed_assertion(
        rid(ids.1),
        rev(ids.1),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate,
            value: mneme_core::Value::String(value.to_owned()),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                rid(ids.0),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    {
        let mut memory = engine(workspace);
        memory
            .commit(batch(
                &format!("prop-{key}"),
                vec![evidence, assertion],
                Vec::new(),
            ))
            .expect("proposal commit");
    }
    accept(
        workspace,
        &format!("acc-{key}"),
        rid(ids.1),
        (rid(ids.2), rev(ids.2), rev(ids.2.saturating_add(0x40))),
        &[],
    );
    rid(ids.1)
}

fn setup_derived_pair(
    workspace: &mut mneme_store::Workspace,
) -> (mneme_core::RecordId, mneme_core::RecordId) {
    let premise = propose_accepted_claim(
        workspace,
        "premise",
        (0x21, 0x31, 0x41),
        "storage_engine",
        "sqlite",
    );
    let conclusion = propose_bare(
        workspace,
        "prop-conclusion",
        0x33,
        "deployment_mode",
        "single_file",
    );
    accept(
        workspace,
        "acc-conclusion",
        conclusion,
        (rid(0x42), rev(0x42), rev(0x34)),
        &[],
    );
    let base = workspace.current_revision().expect("base");
    let deriv = mneme_memory::build_derivation(
        rid(0x50),
        rev(0x50),
        &scope(),
        mneme_memory::DerivationOptions {
            conclusion,
            premises: &[mneme_core::Reference::local(
                premise,
                mneme_core::RecordKind::Assertion,
            )],
            rule_id: "sqlite-implies-single-file",
            rule_version: 1,
            evaluation_revision: base,
            completeness: "complete",
        },
    );
    let mut memory = engine(workspace);
    memory
        .commit(batch("deriv", vec![deriv], Vec::new()))
        .expect("commit derivation");
    (premise, conclusion)
}

fn attach_challenge(
    workspace: &mut mneme_store::Workspace,
    target: mneme_core::RecordId,
    source_byte: u8,
    challenge_byte: u8,
) -> mneme_core::RecordId {
    commit_source(
        workspace,
        "src-challenge",
        rid(source_byte),
        rev(source_byte),
        b"counter-evidence: sqlite WAL corrupted",
    );
    let challenge = mneme_memory::build_evidence(
        rid(challenge_byte),
        rev(challenge_byte),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: target,
            source: rid(source_byte),
            source_revision: rev(source_byte),
            span: None,
            anchor: Some("challenge"),
            relation: mneme_memory::SupportRelation::Challenges,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let mut memory = engine(workspace);
    memory
        .commit(batch("challenge", vec![challenge], Vec::new()))
        .expect("commit challenge");
    rid(challenge_byte)
}

#[test]
fn reinstatement_after_challenge_withdrawal_restores_premise_and_derivation() {
    let (_temp, mut workspace) = setup();
    let (premise, conclusion) = setup_derived_pair(&mut workspace);
    {
        let memory = engine(&mut workspace);
        let view = memory.view().expect("view");
        assert_eq!(
            view.argumentation_verdict(premise).expect("v").status,
            mneme_memory::ArgumentationStatus::In
        );
        assert_eq!(
            view.argumentation_verdict(conclusion).expect("v").status,
            mneme_memory::ArgumentationStatus::In
        );
    }

    let challenge_id = attach_challenge(&mut workspace, premise, 0x60, 0x61);
    {
        let memory = engine(&mut workspace);
        let view = memory.view().expect("view");
        let premise_v = view.argumentation_verdict(premise).expect("premise v");
        assert_eq!(premise_v.status, mneme_memory::ArgumentationStatus::Undec);
        assert_eq!(
            view.argumentation_verdict(conclusion).expect("c").status,
            mneme_memory::ArgumentationStatus::Undec
        );
        assert!(
            premise_v
                .defeats
                .iter()
                .any(|d| d.kind == mneme_memory::DefeatKind::Undercut)
        );
        let conflicts = view.conflicts(&belief_view()).expect("conflicts");
        assert!(conflicts.iter().any(|g| g.predicate == "storage_engine"));
        let expl = view.explain(premise, explain_policy()).expect("explain");
        assert!(expl.opinion.d_num > 0);
        assert!(expl.opinion.conflict_num > 0);
    }

    decide(
        &mut workspace,
        "dispute-premise",
        Transition {
            assertion: premise,
            lifecycle: mneme_core::Lifecycle::Disputed,
            decision_id: rid(0x45),
            decision_rev: rev(0x45),
            assertion_rev: rev(0x39),
            kind: mneme_memory::DecisionKind::ConflictResolution,
            outcome: "disputed",
            evidence: &[mneme_core::Reference::local(
                challenge_id,
                mneme_core::RecordKind::Evidence,
            )],
            related: &[],
        },
    );
    {
        let memory = engine(&mut workspace);
        let view = memory.view().expect("view");
        assert_eq!(
            view.argumentation_verdict(premise).expect("v").status,
            mneme_memory::ArgumentationStatus::Out
        );
        assert_eq!(
            view.argumentation_verdict(conclusion).expect("v").status,
            mneme_memory::ArgumentationStatus::Out
        );
    }

    withdraw_record(&mut workspace, "withdraw-ch", challenge_id, "evidence");
    let memory = engine(&mut workspace);
    let view = memory.view().expect("view");
    assert_eq!(
        view.argumentation_verdict(premise).expect("v").status,
        mneme_memory::ArgumentationStatus::In
    );
    assert_eq!(
        view.argumentation_verdict(conclusion).expect("v").status,
        mneme_memory::ArgumentationStatus::In
    );
}

#[test]
fn rebuttal_preferences_and_conflict_resolution_asymmetric_defeat() {
    let (_temp, mut workspace) = setup();
    let first = propose_accepted_claim(
        &mut workspace,
        "first",
        (0x21, 0x31, 0x41),
        "db_backend",
        "sqlite",
    );
    let second = propose_accepted_claim(
        &mut workspace,
        "second",
        (0x22, 0x32, 0x42),
        "db_backend",
        "postgres",
    );
    {
        let memory = engine(&mut workspace);
        let view = memory.view().expect("view");
        assert_eq!(
            view.argumentation_verdict(first).expect("v1").status,
            mneme_memory::ArgumentationStatus::Undec
        );
        assert_eq!(
            view.argumentation_verdict(second).expect("v2").status,
            mneme_memory::ArgumentationStatus::Undec
        );
        let groups = view.conflicts(&belief_view()).expect("conflicts");
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].argumentation.status,
            mneme_memory::ArgumentationStatus::Undec
        );
    }

    decide(
        &mut workspace,
        "dispute-second",
        Transition {
            assertion: second,
            lifecycle: mneme_core::Lifecycle::Disputed,
            decision_id: rid(0x43),
            decision_rev: rev(0x43),
            assertion_rev: rev(0x35),
            kind: mneme_memory::DecisionKind::ConflictResolution,
            outcome: "disputed",
            evidence: &[],
            related: &[mneme_core::Reference::local(
                first,
                mneme_core::RecordKind::Assertion,
            )],
        },
    );
    accept(
        &mut workspace,
        "reaccept-first",
        first,
        (rid(0x44), rev(0x44), rev(0x36)),
        &[mneme_core::Reference::local(
            second,
            mneme_core::RecordKind::Assertion,
        )],
    );
    let memory = engine(&mut workspace);
    let view = memory.view().expect("view");
    assert_eq!(
        view.argumentation_verdict(first).expect("v1").status,
        mneme_memory::ArgumentationStatus::In
    );
    assert_eq!(
        view.argumentation_verdict(second).expect("v2").status,
        mneme_memory::ArgumentationStatus::Out
    );
}

#[test]
fn echo_chamber_invariance_holds_for_derivative_copies() {
    let (_temp, mut workspace) = setup();
    let ev1_id = rid(0x21);
    let ev2_id = rid(0x22);
    let ev3_id = rid(0x23);
    let assertion_id = rid(0x31);
    let make_ev = |id, rv, anchor, origin, ancestry: &[mneme_core::Reference]| {
        mneme_memory::build_evidence(
            id,
            rv,
            &scope(),
            mneme_memory::EvidenceOptions {
                assertion: assertion_id,
                source: SOURCE_ID,
                source_revision: SOURCE_REV,
                span: None,
                anchor: Some(anchor),
                relation: mneme_memory::SupportRelation::Supports,
                origin,
                ancestry,
            },
        )
    };
    let root_ev = make_ev(
        ev1_id,
        rev(0x21),
        "root",
        mneme_core::Origin::AuthoredStatement,
        &[],
    );
    let copy_a = make_ev(
        ev2_id,
        rev(0x22),
        "copy-a",
        mneme_core::Origin::ModelExtraction,
        &[mneme_core::Reference::local(
            ev1_id,
            mneme_core::RecordKind::Evidence,
        )],
    );
    let copy_b = make_ev(
        ev3_id,
        rev(0x23),
        "copy-b",
        mneme_core::Origin::ModelExtraction,
        &[mneme_core::Reference::local(
            ev2_id,
            mneme_core::RecordKind::Evidence,
        )],
    );
    let assertion = mneme_memory::build_proposed_assertion(
        assertion_id,
        rev(0x31),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "echo_claim",
            value: mneme_core::Value::String("repeated".to_owned()),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[
                mneme_core::Reference::local(ev1_id, mneme_core::RecordKind::Evidence),
                mneme_core::Reference::local(ev2_id, mneme_core::RecordKind::Evidence),
                mneme_core::Reference::local(ev3_id, mneme_core::RecordKind::Evidence),
            ],
            extraction: None,
            superseded_by: None,
        },
    );
    {
        let mut memory = engine(&mut workspace);
        memory
            .commit(batch(
                "echo-chamber",
                vec![root_ev, copy_a, copy_b, assertion],
                Vec::new(),
            ))
            .expect("commit echo chamber");
    }
    let memory = engine(&mut workspace);
    let view = memory.view().expect("view");
    let corr = view.corroboration(assertion_id).expect("corroboration");
    assert_eq!(corr.independent_supports, 1);
    assert!(corr.shared_ancestry);
    assert_eq!(
        corr.opinion.u_num.saturating_mul(3),
        corr.opinion.denom.saturating_mul(2)
    );
    assert_eq!(corr.opinion.b_num.saturating_mul(3), corr.opinion.denom);
    assert_eq!(corr.opinion.d_num, 0);
}

#[test]
fn independent_corroboration_reduces_uncertainty_as_two_over_k_plus_two() {
    let (_temp, mut workspace) = setup();
    commit_source(&mut workspace, "s2", rid(0x12), rev(0x12), b"s2");
    commit_source(&mut workspace, "s3", rid(0x13), rev(0x13), b"s3");
    let assertion_id = rid(0x31);
    let make_ev = |id, rv, source, source_rev, anchor| {
        mneme_memory::build_evidence(
            id,
            rv,
            &scope(),
            mneme_memory::EvidenceOptions {
                assertion: assertion_id,
                source,
                source_revision: source_rev,
                span: None,
                anchor: Some(anchor),
                relation: mneme_memory::SupportRelation::Supports,
                origin: mneme_core::Origin::AuthoredStatement,
                ancestry: &[],
            },
        )
    };
    let ev1 = make_ev(rid(0x21), rev(0x21), SOURCE_ID, SOURCE_REV, "s1");
    let ev2 = make_ev(rid(0x22), rev(0x22), rid(0x12), rev(0x12), "s2");
    let ev3 = make_ev(rid(0x23), rev(0x23), rid(0x13), rev(0x13), "s3");
    let assertion = mneme_memory::build_proposed_assertion(
        assertion_id,
        rev(0x31),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "corroborated_claim",
            value: mneme_core::Value::String("verified".to_owned()),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[
                mneme_core::Reference::local(rid(0x21), mneme_core::RecordKind::Evidence),
                mneme_core::Reference::local(rid(0x22), mneme_core::RecordKind::Evidence),
                mneme_core::Reference::local(rid(0x23), mneme_core::RecordKind::Evidence),
            ],
            extraction: None,
            superseded_by: None,
        },
    );
    {
        let mut memory = engine(&mut workspace);
        memory
            .commit(batch(
                "indep-corr",
                vec![ev1, ev2, ev3, assertion],
                Vec::new(),
            ))
            .expect("commit");
    }
    let memory = engine(&mut workspace);
    let view = memory.view().expect("view");
    let corr = view.corroboration(assertion_id).expect("corroboration");
    assert_eq!(corr.independent_supports, 3);
    assert_eq!(
        corr.opinion.u_num.saturating_mul(5),
        corr.opinion.denom.saturating_mul(2)
    );
    assert_eq!(
        corr.opinion.b_num.saturating_mul(5),
        corr.opinion.denom.saturating_mul(3)
    );
    assert_eq!(corr.opinion.d_num, 0);
    assert_eq!(corr.opinion.conflict_num, 0);
}

#[test]
fn vacuous_hypothesis_distinguished_from_challenged_and_never_promoted() {
    let (_temp, mut workspace) = setup();
    let hypothesis = propose_bare(
        &mut workspace,
        "bare-hyp",
        0x31,
        "open_hypothesis",
        "untested",
    );
    {
        let memory = engine(&mut workspace);
        let view = memory.view().expect("view");
        let op = view.opinion(hypothesis).expect("opinion");
        assert_eq!(op.b_num, 0);
        assert_eq!(op.d_num, 0);
        assert_eq!(op.u_num, op.denom);
        assert_eq!(op.conflict_num, 0);
        let expl = view.explain(hypothesis, explain_policy()).expect("explain");
        assert_eq!(expl.assertion.lifecycle, mneme_core::Lifecycle::Proposed);
        assert_eq!(expl.opinion, op);
    }

    let _challenge = attach_challenge(&mut workspace, hypothesis, 0x60, 0x61);
    let memory = engine(&mut workspace);
    let view = memory.view().expect("view");
    let op = view.opinion(hypothesis).expect("opinion");
    assert_eq!(op.b_num, 0);
    assert!(op.d_num > 0);
    assert!(op.u_num < op.denom);
    assert_eq!(
        view.argumentation_verdict(hypothesis).expect("v").status,
        mneme_memory::ArgumentationStatus::Out
    );
    assert_eq!(
        view.assertion(hypothesis).expect("assertion").lifecycle,
        mneme_core::Lifecycle::Proposed
    );
}
