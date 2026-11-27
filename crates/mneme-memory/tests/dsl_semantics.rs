//! End-to-end tests for Predicate Traits (`Functional`, `Inertial`),
//! Event-Calculus fluent clipping (`#71` non-promotion), `PosBool(X)`
//! minimal-support antichains, decision-level defeat & reinstatement,
//! and `certain` vs `shadow` 3-way `Active` / `Dead` / `Absent` diffs.
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

fn ts(nanos: i64) -> mneme_core::Timestamp {
    mneme_core::Timestamp::from_nanos(nanos)
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
            clock: Box::new(mneme_store::FixedClock::new(ts(1_000))),
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
    let mut memory = engine(&mut workspace);
    memory
        .commit(batch("init", vec![ent_draft, source], vec![blob]))
        .expect("init commit");
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

struct ClaimSpec<'a> {
    ev_byte: u8,
    assertion_byte: u8,
    predicate: &'a str,
    value: &'a str,
    stance: mneme_memory::Stance,
    valid_time: mneme_core::ValidTime,
}

fn propose_supported(
    workspace: &mut mneme_store::Workspace,
    key: &str,
    spec: ClaimSpec<'_>,
) -> mneme_core::RecordId {
    let evidence = mneme_memory::build_evidence(
        rid(spec.ev_byte),
        rev(spec.ev_byte),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: rid(spec.assertion_byte),
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
        rid(spec.assertion_byte),
        rev(spec.assertion_byte),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: spec.predicate,
            value: mneme_core::Value::string(spec.value),
            stance: spec.stance,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: spec.valid_time,
            evidence: &[mneme_core::Reference::local(
                rid(spec.ev_byte),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    let mut memory = engine(workspace);
    memory
        .commit(batch(key, vec![evidence, assertion], Vec::new()))
        .expect("propose commit");
    rid(spec.assertion_byte)
}

struct TransitionSpec<'a> {
    assertion: mneme_core::RecordId,
    lifecycle: mneme_core::Lifecycle,
    kind: mneme_memory::DecisionKind,
    outcome: &'a str,
    ids: (u8, u8),
}

fn transition_assertion(
    workspace: &mut mneme_store::Workspace,
    key: &str,
    spec: TransitionSpec<'_>,
) {
    let base = workspace.current_revision().expect("base");
    let current = latest(workspace, spec.assertion);
    let decision = mneme_memory::build_decision(
        rid(spec.ids.0),
        rev(spec.ids.0),
        &scope(),
        mneme_memory::DecisionOptions {
            kind: spec.kind,
            target: spec.assertion,
            actor: "test-author",
            policy: "dsl-test-policy/v1",
            input_revision: base,
            outcome: spec.outcome,
            rationale: "explicit test lifecycle decision",
            evidence: &[],
            related: &[],
        },
    );
    let revision = mneme_memory::build_assertion_revision(
        &current,
        rev(spec.ids.1),
        spec.lifecycle,
        mneme_core::Reference::local(rid(spec.ids.0), mneme_core::RecordKind::Decision),
        None,
    );
    let mut memory = engine(workspace);
    memory
        .commit(batch(key, vec![decision, revision], Vec::new()))
        .expect("transition commit");
}

fn accept_assertion(
    workspace: &mut mneme_store::Workspace,
    key: &str,
    assertion: mneme_core::RecordId,
    ids: (u8, u8),
) {
    transition_assertion(
        workspace,
        key,
        TransitionSpec {
            assertion,
            lifecycle: mneme_core::Lifecycle::Accepted,
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            ids,
        },
    );
}

fn declare_trait(
    workspace: &mut mneme_store::Workspace,
    key: &str,
    predicate: &str,
    kind: mneme_memory::PredicateTrait,
    ids: (u8, u8, u8, u8),
) -> mneme_core::RecordId {
    let ev_id = rid(ids.0);
    let trait_id = rid(ids.1);
    let ev = mneme_memory::build_evidence(
        ev_id,
        rev(ids.0),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: trait_id,
            source: SOURCE_ID,
            source_revision: SOURCE_REV,
            span: None,
            anchor: Some("schema"),
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let trait_draft = mneme_memory::build_predicate_trait(
        trait_id,
        rev(ids.1),
        &scope(),
        mneme_memory::PredicateTraitOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate,
            kind,
            asserted_by: "schema-author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                ev_id,
                mneme_core::RecordKind::Evidence,
            )],
        },
    );
    {
        let mut memory = engine(workspace);
        memory
            .commit(batch(key, vec![ev, trait_draft], Vec::new()))
            .expect("commit trait");
    }
    accept_assertion(
        workspace,
        &format!("{key}-accept"),
        trait_id,
        (ids.2, ids.3),
    );
    trait_id
}

#[test]
fn functional_predicate_registers_automatic_rebuttal_on_valid_time_overlap() {
    let (_temp, mut workspace) = setup();
    declare_trait(
        &mut workspace,
        "trait-owner",
        "owner",
        mneme_memory::PredicateTrait::Functional,
        (0x10, 0x11, 0x12, 0x13),
    );

    // Non-overlapping half-open intervals [100, 200) and [200, 300) are clean.
    let a1 = propose_supported(
        &mut workspace,
        "owner-alice",
        ClaimSpec {
            ev_byte: 0x20,
            assertion_byte: 0x21,
            predicate: "owner",
            value: "alice",
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::Bounded {
                start: Some(ts(100)),
                end: Some(ts(200)),
            },
        },
    );
    accept_assertion(&mut workspace, "accept-alice", a1, (0x22, 0x23));

    let a2 = propose_supported(
        &mut workspace,
        "owner-bob",
        ClaimSpec {
            ev_byte: 0x24,
            assertion_byte: 0x25,
            predicate: "owner",
            value: "bob",
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::Bounded {
                start: Some(ts(200)),
                end: Some(ts(300)),
            },
        },
    );
    accept_assertion(&mut workspace, "accept-bob", a2, (0x26, 0x27));

    {
        let memory = engine(&mut workspace);
        let view = memory.view().expect("view");
        let violations = view
            .functional_violations(&scope(), mneme_memory::QueryLayer::Certain)
            .expect("violations");
        assert!(violations.is_empty());
        assert_eq!(
            view.argumentation_verdict(a1).expect("v1").status,
            mneme_memory::ArgumentationStatus::In
        );
    }

    // Add overlapping [150, 250) with distinct value "carol" -> functional violation + rebuttal!
    let a3 = propose_supported(
        &mut workspace,
        "owner-carol",
        ClaimSpec {
            ev_byte: 0x28,
            assertion_byte: 0x29,
            predicate: "owner",
            value: "carol",
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::Bounded {
                start: Some(ts(150)),
                end: Some(ts(250)),
            },
        },
    );
    accept_assertion(&mut workspace, "accept-carol", a3, (0x2a, 0x2b));

    let memory = engine(&mut workspace);
    let view = memory.view().expect("view");
    let violations = view
        .functional_violations(&scope(), mneme_memory::QueryLayer::Certain)
        .expect("violations");
    assert_eq!(violations.len(), 2);
    assert_eq!(
        view.argumentation_verdict(a3).expect("v3").status,
        mneme_memory::ArgumentationStatus::Undec
    );
    let has_rebuttal = view
        .argumentation_verdict(a3)
        .expect("v3")
        .defeats
        .iter()
        .any(|d| d.kind == mneme_memory::DefeatKind::Rebuttal);
    assert!(has_rebuttal);
}

#[test]
fn inertial_fluent_clipping_enforces_non_promotion_of_proposed_events() {
    let subject = mneme_core::fixtures::entity_id();
    let functional = std::collections::BTreeSet::from(["status".to_owned()]);
    let events = vec![
        mneme_memory::FluentEvent {
            event_id: rid(0x01),
            subject,
            predicate: "status".to_owned(),
            value: mneme_core::Value::string("open"),
            kind: mneme_memory::FluentTransitionKind::Initiates,
            at: ts(100),
            authority: mneme_kernel::argumentation::Authority::Accepted,
        },
        // Proposed event at t=200 MUST NOT clip the Accepted fluent from t=100!
        mneme_memory::FluentEvent {
            event_id: rid(0x02),
            subject,
            predicate: "status".to_owned(),
            value: mneme_core::Value::string("closed"),
            kind: mneme_memory::FluentTransitionKind::Initiates,
            at: ts(200),
            authority: mneme_kernel::argumentation::Authority::Proposed,
        },
        // Accepted event at t=300 DOES clip the Accepted fluent to [100, 300)
        // AND clips the Proposed fluent to [200, 300)!
        mneme_memory::FluentEvent {
            event_id: rid(0x03),
            subject,
            predicate: "status".to_owned(),
            value: mneme_core::Value::string("archived"),
            kind: mneme_memory::FluentTransitionKind::Initiates,
            at: ts(300),
            authority: mneme_kernel::argumentation::Authority::Accepted,
        },
        // Accepted terminate at t=400 clips "archived" to [300, 400).
        mneme_memory::FluentEvent {
            event_id: rid(0x04),
            subject,
            predicate: "status".to_owned(),
            value: mneme_core::Value::string("archived"),
            kind: mneme_memory::FluentTransitionKind::Terminates,
            at: ts(400),
            authority: mneme_kernel::argumentation::Authority::Accepted,
        },
    ];

    let fluents = mneme_memory::clip_inertial_fluents(&events, &functional);
    assert_eq!(fluents.len(), 3);

    // Accepted "open" skipped Proposed at t=200 and clipped at Accepted t=300.
    assert_eq!(fluents[0].initiated_by, rid(0x01));
    assert_eq!(fluents[0].terminated_by, Some(rid(0x03)));
    assert_eq!(fluents[0].period.start, 100);
    assert_eq!(fluents[0].period.stop, 300);

    // Proposed "closed" at t=200 clipped by higher-authority Accepted at t=300.
    assert_eq!(fluents[1].initiated_by, rid(0x02));
    assert_eq!(fluents[1].terminated_by, Some(rid(0x03)));
    assert_eq!(fluents[1].period.start, 200);
    assert_eq!(fluents[1].period.stop, 300);

    // Accepted "archived" at t=300 clipped by Accepted terminate at t=400.
    assert_eq!(fluents[2].initiated_by, rid(0x03));
    assert_eq!(fluents[2].terminated_by, Some(rid(0x04)));
    assert_eq!(fluents[2].period.start, 300);
    assert_eq!(fluents[2].period.stop, 400);
}

#[test]
fn antichain_absorption_invariants_and_explain_minimal_supports() {
    // Property check on absorb_support_sets over mixed subsets, duplicates, and supersets.
    let sets = vec![
        std::collections::BTreeSet::from([rid(1), rid(2), rid(3)]),
        std::collections::BTreeSet::from([rid(1), rid(2)]),
        std::collections::BTreeSet::from([rid(2), rid(1)]),
        std::collections::BTreeSet::from([rid(4)]),
        std::collections::BTreeSet::from([rid(4), rid(5)]),
        std::collections::BTreeSet::new(),
    ];
    let (antichain, is_truncated) =
        mneme_memory::absorb_support_sets(sets.clone(), mneme_memory::MAX_ANTICHAIN_SETS);
    assert!(!is_truncated);
    assert_eq!(antichain.len(), 2);
    assert_eq!(antichain[0], std::collections::BTreeSet::from([rid(4)]));
    assert_eq!(
        antichain[1],
        std::collections::BTreeSet::from([rid(1), rid(2)])
    );

    // Invariant 1: no set in antichain is a strict subset of another.
    for (i, left) in antichain.iter().enumerate() {
        for (j, right) in antichain.iter().enumerate() {
            if i != j {
                assert!(!left.is_subset(right));
            }
        }
    }
    // Invariant 2: every non-empty input set is a superset of at least one returned set.
    for original in sets.iter().filter(|s| !s.is_empty()) {
        let is_covered = antichain.iter().any(|min| min.is_subset(original));
        assert!(is_covered);
    }

    // End-to-end View::explain minimal_supports over redundant vs minimal derivations.
    let (_temp, mut workspace) = setup();
    let p1 = propose_supported(
        &mut workspace,
        "p1",
        ClaimSpec {
            ev_byte: 0x30,
            assertion_byte: 0x31,
            predicate: "premise",
            value: "p1",
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
        },
    );
    accept_assertion(&mut workspace, "acc-p1", p1, (0x32, 0x33));
    let p2 = propose_supported(
        &mut workspace,
        "p2",
        ClaimSpec {
            ev_byte: 0x34,
            assertion_byte: 0x35,
            predicate: "premise",
            value: "p2",
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
        },
    );
    accept_assertion(&mut workspace, "acc-p2", p2, (0x36, 0x37));
    let p3 = propose_supported(
        &mut workspace,
        "p3",
        ClaimSpec {
            ev_byte: 0x38,
            assertion_byte: 0x39,
            predicate: "premise",
            value: "p3",
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
        },
    );
    accept_assertion(&mut workspace, "acc-p3", p3, (0x3a, 0x3b));

    // Conclusion derived via {p1}, {p1, p2} (superset -> absorbed!), and {p2, p3} (minimal).
    let conclusion_draft = mneme_memory::build_proposed_assertion(
        rid(0x40),
        rev(0x40),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "derived",
            value: mneme_core::Value::string("goal"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[],
            extraction: None,
            superseded_by: None,
        },
    );
    {
        let mut memory = engine(&mut workspace);
        memory
            .commit(batch("prop-goal", vec![conclusion_draft], Vec::new()))
            .expect("commit goal");
    }
    accept_assertion(&mut workspace, "acc-goal", rid(0x40), (0x41, 0x42));
    let base = workspace.current_revision().expect("base");
    let d_minimal_1 = mneme_memory::build_derivation(
        rid(0x51),
        rev(0x51),
        &scope(),
        mneme_memory::DerivationOptions {
            conclusion: rid(0x40),
            premises: &[mneme_core::Reference::local(
                p1,
                mneme_core::RecordKind::Assertion,
            )],
            rule_id: "r-p1",
            rule_version: 1,
            evaluation_revision: base,
            completeness: "complete",
        },
    );
    let d_superset = mneme_memory::build_derivation(
        rid(0x54),
        rev(0x54),
        &scope(),
        mneme_memory::DerivationOptions {
            conclusion: rid(0x40),
            premises: &[
                mneme_core::Reference::local(p1, mneme_core::RecordKind::Assertion),
                mneme_core::Reference::local(p2, mneme_core::RecordKind::Assertion),
            ],
            rule_id: "r-p1-p2",
            rule_version: 1,
            evaluation_revision: base,
            completeness: "complete",
        },
    );
    let d_minimal_2 = mneme_memory::build_derivation(
        rid(0x53),
        rev(0x53),
        &scope(),
        mneme_memory::DerivationOptions {
            conclusion: rid(0x40),
            premises: &[
                mneme_core::Reference::local(p2, mneme_core::RecordKind::Assertion),
                mneme_core::Reference::local(p3, mneme_core::RecordKind::Assertion),
            ],
            rule_id: "r-p2-p3",
            rule_version: 1,
            evaluation_revision: base,
            completeness: "complete",
        },
    );
    {
        let mut memory = engine(&mut workspace);
        memory
            .commit(batch(
                "derivs",
                vec![d_minimal_1, d_superset, d_minimal_2],
                Vec::new(),
            ))
            .expect("commit derivs");
    }

    let memory = engine(&mut workspace);
    let expl = memory
        .explain(rid(0x40), mneme_memory::Policy::default())
        .expect("explain");
    assert_eq!(expl.minimal_supports.len(), 2);
    assert_eq!(
        expl.minimal_supports[0],
        std::collections::BTreeSet::from([p1])
    );
    assert_eq!(
        expl.minimal_supports[1],
        std::collections::BTreeSet::from([p2, p3])
    );
}

#[test]
fn defeat_withdrawal_counter_defeat_and_reinstatement_round_trip() {
    let (_temp, mut workspace) = setup();
    let premise = propose_supported(
        &mut workspace,
        "premise",
        ClaimSpec {
            ev_byte: 0x60,
            assertion_byte: 0x61,
            predicate: "engine",
            value: "sqlite",
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
        },
    );
    accept_assertion(&mut workspace, "acc-premise", premise, (0x62, 0x63));
    let conclusion_draft = mneme_memory::build_proposed_assertion(
        rid(0x64),
        rev(0x64),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "mode",
            value: mneme_core::Value::string("embedded"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[],
            extraction: None,
            superseded_by: None,
        },
    );
    {
        let mut memory = engine(&mut workspace);
        memory
            .commit(batch("prop-c", vec![conclusion_draft], Vec::new()))
            .expect("commit c");
    }
    accept_assertion(&mut workspace, "acc-c", rid(0x64), (0x65, 0x66));
    let reason = propose_supported(
        &mut workspace,
        "reason-r1",
        ClaimSpec {
            ev_byte: 0x68,
            assertion_byte: 0x69,
            predicate: "defect",
            value: "wal-corrupt",
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
        },
    );
    accept_assertion(&mut workspace, "acc-r1", reason, (0x6a, 0x6b));
    let base = workspace.current_revision().expect("base");
    let deriv = mneme_memory::build_derivation(
        rid(0x67),
        rev(0x67),
        &scope(),
        mneme_memory::DerivationOptions {
            conclusion: rid(0x64),
            premises: &[mneme_core::Reference::local(
                premise,
                mneme_core::RecordKind::Assertion,
            )],
            rule_id: "sqlite-embedded",
            rule_version: 1,
            evaluation_revision: base,
            completeness: "complete",
        },
    );
    let defeat_1 = mneme_memory::build_explicit_defeat(
        rid(0x6c),
        rev(0x6c),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: premise,
            source: SOURCE_ID,
            source_revision: SOURCE_REV,
            span: None,
            anchor: Some("defeat-premise"),
            relation: mneme_memory::SupportRelation::Challenges,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[mneme_core::Reference::local(
                reason,
                mneme_core::RecordKind::Assertion,
            )],
        },
    );
    {
        let mut memory = engine(&mut workspace);
        memory
            .commit(batch("defeat-1", vec![deriv, defeat_1], Vec::new()))
            .expect("commit defeat-1");
    }

    // Both premise and derived conclusion are OUT under explicit defeat!
    {
        let memory = engine(&mut workspace);
        let view = memory.view().expect("view");
        assert_eq!(
            view.argumentation_verdict(premise).expect("p").status,
            mneme_memory::ArgumentationStatus::Out
        );
        assert_eq!(
            view.argumentation_verdict(rid(0x64)).expect("c").status,
            mneme_memory::ArgumentationStatus::Out
        );
    }

    // Counter-defeat reason `r1` -> automatically reinstates premise AND conclusion!
    let counter_defeat = mneme_memory::build_explicit_defeat(
        rid(0x6d),
        rev(0x6d),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: reason,
            source: SOURCE_ID,
            source_revision: SOURCE_REV,
            span: None,
            anchor: Some("counter-defeat"),
            relation: mneme_memory::SupportRelation::Challenges,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    {
        let mut memory = engine(&mut workspace);
        memory
            .commit(batch("counter-defeat", vec![counter_defeat], Vec::new()))
            .expect("commit counter");
    }

    let memory = engine(&mut workspace);
    let view = memory.view().expect("view");
    assert_eq!(
        view.argumentation_verdict(reason).expect("r").status,
        mneme_memory::ArgumentationStatus::Out
    );
    assert_eq!(
        view.argumentation_verdict(premise).expect("p").status,
        mneme_memory::ArgumentationStatus::In
    );
    assert_eq!(
        view.argumentation_verdict(rid(0x64)).expect("c").status,
        mneme_memory::ArgumentationStatus::In
    );
}

#[test]
fn dead_vs_absent_and_certain_vs_shadow_diff_classification() {
    let (_temp, mut workspace) = setup();
    let subject = mneme_core::fixtures::entity_id();

    let a_retract = propose_supported(
        &mut workspace,
        "a-ret",
        ClaimSpec {
            ev_byte: 0x70,
            assertion_byte: 0x71,
            predicate: "retracted_pred",
            value: "v1",
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
        },
    );
    accept_assertion(&mut workspace, "acc-ret", a_retract, (0x72, 0x73));

    let a_super = propose_supported(
        &mut workspace,
        "a-sup",
        ClaimSpec {
            ev_byte: 0x74,
            assertion_byte: 0x75,
            predicate: "superseded_pred",
            value: "old",
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
        },
    );
    accept_assertion(&mut workspace, "acc-sup", a_super, (0x76, 0x77));

    let a_defeat = propose_supported(
        &mut workspace,
        "a-def",
        ClaimSpec {
            ev_byte: 0x78,
            assertion_byte: 0x79,
            predicate: "defeated_pred",
            value: "claim",
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
        },
    );
    accept_assertion(&mut workspace, "acc-def", a_defeat, (0x7a, 0x7b));

    let _a_shadow = propose_supported(
        &mut workspace,
        "a-shadow",
        ClaimSpec {
            ev_byte: 0x7c,
            assertion_byte: 0x7d,
            predicate: "shadow_pred",
            value: "draft",
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
        },
    );

    let view_before = {
        let memory = engine(&mut workspace);
        memory.view().expect("before view")
    };

    // Apply retraction, supersession, and explicit defeat.
    transition_assertion(
        &mut workspace,
        "do-retract",
        TransitionSpec {
            assertion: a_retract,
            lifecycle: mneme_core::Lifecycle::Retracted,
            kind: mneme_memory::DecisionKind::Retraction,
            outcome: "retracted",
            ids: (0x80, 0x81),
        },
    );
    let a_replacement = propose_supported(
        &mut workspace,
        "a-sup-new",
        ClaimSpec {
            ev_byte: 0x85,
            assertion_byte: 0x86,
            predicate: "superseded_replacement",
            value: "new",
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
        },
    );
    {
        let base = workspace.current_revision().expect("base");
        let current = latest(&workspace, a_super);
        let decision = mneme_memory::build_decision(
            rid(0x82),
            rev(0x82),
            &scope(),
            mneme_memory::DecisionOptions {
                kind: mneme_memory::DecisionKind::Supersession,
                target: a_super,
                actor: "test-author",
                policy: "dsl-test-policy/v1",
                input_revision: base,
                outcome: "superseded",
                rationale: "explicit test supersession",
                evidence: &[],
                related: &[mneme_core::Reference::local(
                    a_replacement,
                    mneme_core::RecordKind::Assertion,
                )],
            },
        );
        let revision = mneme_memory::build_assertion_revision(
            &current,
            rev(0x83),
            mneme_core::Lifecycle::Superseded,
            mneme_core::Reference::local(rid(0x82), mneme_core::RecordKind::Decision),
            Some(mneme_core::Reference::local(
                a_replacement,
                mneme_core::RecordKind::Assertion,
            )),
        );
        let mut memory = engine(&mut workspace);
        memory
            .commit(batch("do-supersede", vec![decision, revision], Vec::new()))
            .expect("supersede commit");
    }
    let defeat_ev = mneme_memory::build_explicit_defeat(
        rid(0x84),
        rev(0x84),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: a_defeat,
            source: SOURCE_ID,
            source_revision: SOURCE_REV,
            span: None,
            anchor: Some("defeat"),
            relation: mneme_memory::SupportRelation::Challenges,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    {
        let mut memory = engine(&mut workspace);
        memory
            .commit(batch("do-defeat", vec![defeat_ev], Vec::new()))
            .expect("defeat commit");
    }

    let view_after = {
        let memory = engine(&mut workspace);
        memory.view().expect("after view")
    };

    let slots = vec![
        (subject, "retracted_pred".to_owned()),
        (subject, "superseded_pred".to_owned()),
        (subject, "defeated_pred".to_owned()),
        (subject, "shadow_pred".to_owned()),
        (subject, "never_asserted".to_owned()),
    ];

    let certain_diff = mneme_memory::View::slot_diff(
        &view_before,
        &view_after,
        &mneme_memory::SlotDiffRequest {
            scope: scope(),
            at: ts(1_000),
            layer: mneme_memory::QueryLayer::Certain,
            slots: slots.clone(),
        },
    )
    .expect("certain diff");

    assert!(matches!(
        certain_diff[0].after,
        mneme_memory::SlotStatus::Dead {
            reason: mneme_memory::DeadReason::Retracted,
            ..
        }
    ));
    assert!(matches!(
        certain_diff[1].after,
        mneme_memory::SlotStatus::Dead {
            reason: mneme_memory::DeadReason::Superseded,
            ..
        }
    ));
    assert!(matches!(
        certain_diff[2].after,
        mneme_memory::SlotStatus::Dead {
            reason: mneme_memory::DeadReason::Defeated,
            ..
        }
    ));
    // Shadow-only proposed assertion is Absent in Certain layer (non-promotion!).
    assert_eq!(certain_diff[3].after, mneme_memory::SlotStatus::Absent);
    assert_eq!(certain_diff[4].after, mneme_memory::SlotStatus::Absent);

    let shadow_diff = mneme_memory::View::slot_diff(
        &view_before,
        &view_after,
        &mneme_memory::SlotDiffRequest {
            scope: scope(),
            at: ts(1_000),
            layer: mneme_memory::QueryLayer::Shadow,
            slots,
        },
    )
    .expect("shadow diff");

    // Shadow layer exposes shadow_pred as Active(Shadow) while keeping never_asserted Absent.
    assert!(matches!(
        shadow_diff[3].after,
        mneme_memory::SlotStatus::Active {
            layer: mneme_memory::QueryLayer::Shadow,
            ..
        }
    ));
    assert_eq!(shadow_diff[4].after, mneme_memory::SlotStatus::Absent);
}
