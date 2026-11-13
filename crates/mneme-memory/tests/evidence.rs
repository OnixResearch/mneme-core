//! End-to-end evidence-memory tests over the durable workspace.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

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
    let current = common::latest(workspace, assertion);
    let decision = mneme_memory::build_decision(
        decision_id,
        decision_revision,
        &common::scope(),
        mneme_memory::DecisionOptions {
            kind,
            target: assertion,
            actor: "test-author",
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
    let mut memory = common::engine(workspace);
    memory
        .commit(common::batch(key, vec![decision, revision], Vec::new()))
        .expect("decision commit");
}

#[test]
fn proposed_assertion_is_not_promoted_by_retrieval_or_explanation() {
    let (_temp, mut workspace) = common::setup();
    let assertion_id = common::propose(
        &mut workspace,
        "proposal",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x10),
            evidence_revision: common::rev(0x11),
            assertion_id: common::rid(0x20),
            assertion_revision: common::rev(0x21),
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
        scope: common::scope(),
        at,
        include_hypothetical: false,
        include_disputed: false,
    };
    {
        let memory = common::engine(&mut workspace);
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
        common::latest(&workspace, assertion_id).assertion_lifecycle(),
        Some(mneme_core::Lifecycle::Proposed)
    );
}

#[test]
fn invalid_span_rejects_the_whole_batch() {
    let (_temp, mut workspace) = common::setup();
    let before = workspace.snapshot().expect("snapshot");
    let evidence = mneme_memory::build_evidence(
        common::rid(0x10),
        common::rev(0x11),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: common::rid(0x20),
            source: common::SOURCE_ID,
            source_revision: common::SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(0, 10_000).expect("ordered")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let assertion = mneme_memory::build_proposed_assertion(
        common::rid(0x20),
        common::rev(0x21),
        &common::scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "storage-engine",
            value: mneme_core::Value::string("SQLite"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                common::rid(0x10),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    let error = {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch(
                "bad-span",
                vec![evidence, assertion],
                Vec::new(),
            ))
            .expect_err("span beyond source")
    };
    assert!(error.to_string().contains("beyond"));
    let after = workspace.snapshot().expect("snapshot");
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.records.len(), before.records.len());
}

#[test]
fn acceptance_requires_a_matching_decision() {
    let (_temp, mut workspace) = common::setup();
    let assertion_id = common::propose(
        &mut workspace,
        "proposal",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x10),
            evidence_revision: common::rev(0x11),
            assertion_id: common::rid(0x20),
            assertion_revision: common::rev(0x21),
            predicate: "storage-engine",
            value: mneme_core::Value::string("SQLite"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    let current = common::latest(&workspace, assertion_id);
    let accepted_without_decision = mneme_memory::build_assertion_revision(
        &current,
        common::rev(0x22),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(common::rid(0x30), mneme_core::RecordKind::Decision),
        None,
    );
    let error = {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch(
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
            decision_id: common::rid(0x30),
            decision_revision: common::rev(0x31),
            assertion_revision: common::rev(0x22),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let at = mneme_core::Timestamp::parse("2026-11-10T00:00:00Z").expect("time");
    let memory = common::engine(&mut workspace);
    let beliefs = memory
        .beliefs(&mneme_memory::BeliefView {
            scope: common::scope(),
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
    let (_temp, mut workspace) = common::setup();
    let assertion_id = common::propose(
        &mut workspace,
        "proposal",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x10),
            evidence_revision: common::rev(0x11),
            assertion_id: common::rid(0x20),
            assertion_revision: common::rev(0x21),
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
            decision_id: common::rid(0x30),
            decision_revision: common::rev(0x31),
            assertion_revision: common::rev(0x22),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );

    let changed = mneme_core::fixtures::SOURCE_TEXT.replace("SQLite", "LMDB");
    let (mut source, blob) = mneme_memory::build_source(
        common::SOURCE_ID,
        common::rev(0x0c),
        &common::scope(),
        mneme_memory::SourceOptions {
            bytes: changed.as_bytes(),
            media_type: "text/asciidoc",
            entity: Some(mneme_core::fixtures::entity_id()),
            path_hint: Some("project.adoc"),
        },
    )
    .expect("source");
    source.predecessor = Some(common::SOURCE_REV);
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch("source-v2", vec![source], vec![blob]))
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
        assert_eq!(evidence.source_revision, common::SOURCE_REV);
        let excerpt = evidence.excerpt.as_ref().expect("pinned excerpt");
        assert_eq!(String::from_utf8_lossy(&excerpt.bytes), "SQLite");
        assert!(!String::from_utf8_lossy(&excerpt.bytes).contains("LMDB"));
    }
}

#[test]
fn future_and_unknown_validity_do_not_answer_the_current_view() {
    let (_temp, mut workspace) = common::setup();
    let future = mneme_core::Timestamp::parse("2030-01-01T00:00:00Z").expect("future");
    let future_claim = common::propose(
        &mut workspace,
        "future",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x10),
            evidence_revision: common::rev(0x11),
            assertion_id: common::rid(0x20),
            assertion_revision: common::rev(0x21),
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
            decision_id: common::rid(0x30),
            decision_revision: common::rev(0x31),
            assertion_revision: common::rev(0x22),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let unknown_claim = common::propose(
        &mut workspace,
        "unknown",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x12),
            evidence_revision: common::rev(0x13),
            assertion_id: common::rid(0x24),
            assertion_revision: common::rev(0x25),
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
            decision_id: common::rid(0x32),
            decision_revision: common::rev(0x33),
            assertion_revision: common::rev(0x26),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );

    let memory = common::engine(&mut workspace);
    let today = mneme_memory::BeliefView {
        scope: common::scope(),
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
    let (_temp, mut workspace) = common::setup();
    let hypothesis_scope = mneme_core::ScopeId::new(mneme_core::ScopeClass::Hypothesis, "plan-1")
        .expect("hypothesis scope");
    let assertion_id = common::rid(0x20);
    {
        // The planner may read the project the hypothesis is about, and the
        // batch's own scope is implicitly authorized.
        let proposal = mneme_memory::build_proposed_assertion(
            assertion_id,
            common::rev(0x21),
            &hypothesis_scope,
            mneme_memory::ProposedAssertionOptions {
                subject: mneme_core::fixtures::entity_id(),
                predicate: "device-state",
                value: mneme_core::Value::string("maybe-offline"),
                stance: mneme_memory::Stance::Hypothesis,
                origin: mneme_core::Origin::AuthoredStatement,
                asserted_by: "synthetic author",
                valid_time: mneme_core::ValidTime::always(),
                evidence: &[],
                extraction: None,
                superseded_by: None,
            },
        );
        let mut memory = mneme_memory::Engine::new(
            &mut workspace,
            mneme_memory::Access::scopes([common::scope()]),
        );
        memory
            .commit(common::batch_in(
                &hypothesis_scope,
                "hypothesis",
                vec![proposal],
                Vec::new(),
            ))
            .expect("hypothesis proposal");
    }
    let today = mneme_memory::BeliefView {
        scope: common::scope(),
        at: mneme_core::Timestamp::parse("2026-11-10T00:00:00Z").expect("today"),
        include_hypothetical: false,
        include_disputed: false,
    };
    let memory = common::engine(&mut workspace);
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

    // Promotion requires an accepted revision in the operational scope, an
    // acceptance decision committed in the same batch, and access to the
    // hypothesis scope the record came from.
    let current = common::latest(&workspace, assertion_id);
    let mut accepted = mneme_memory::build_assertion_revision(
        &current,
        common::rev(0x22),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(common::rid(0x30), mneme_core::RecordKind::Decision),
        None,
    );
    accepted.scope = common::scope();
    // Operational memory may not cite hypothesis-scope records, so the
    // promotion imports the claim's support into the operational scope in the
    // same batch.
    let support_reference =
        mneme_core::Reference::local(common::rid(0x10), mneme_core::RecordKind::Evidence);
    accepted.payload.insert(
        mneme_core::Symbol::from("evidence"),
        mneme_core::Value::set([support_reference.to_value()]),
    );
    let support = sound_evidence(
        common::rid(0x10),
        common::rev(0x11),
        &common::scope(),
        assertion_id,
    );
    let base = workspace.current_revision().expect("base");
    let decision = mneme_memory::build_decision(
        common::rid(0x30),
        common::rev(0x31),
        &common::scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: assertion_id,
            actor: "test-author",
            policy: "promotion-policy/v1",
            input_revision: base,
            outcome: "accepted",
            rationale: "explicit hypothesis promotion",
            evidence: &[],
            related: &[],
        },
    );
    {
        // Without authorization for the hypothesis scope the promotion is
        // refused before anything is written.
        let mut memory = mneme_memory::Engine::new(
            &mut workspace,
            mneme_memory::Access::Scopes(std::collections::BTreeSet::new()),
        );
        let error = memory
            .commit(common::batch(
                "promote-unauthorized",
                vec![decision.clone(), accepted.clone()],
                Vec::new(),
            ))
            .expect_err("promotion without hypothesis access");
        assert!(error.to_string().contains("scope"));
        assert_eq!(
            common::latest(&workspace, assertion_id).scope,
            hypothesis_scope
        );
    }
    {
        // The cited acceptance decision must be new in this batch.
        let mut memory = mneme_memory::Engine::new(
            &mut workspace,
            mneme_memory::Access::scopes([hypothesis_scope.clone()]),
        );
        let error = memory
            .commit(common::batch(
                "promote-undecided",
                vec![accepted.clone()],
                Vec::new(),
            ))
            .expect_err("promotion without an acceptance decision");
        assert!(error.to_string().contains("scope"));
        assert_eq!(
            common::latest(&workspace, assertion_id).scope,
            hypothesis_scope
        );
    }
    {
        let mut memory = mneme_memory::Engine::new(
            &mut workspace,
            mneme_memory::Access::scopes([hypothesis_scope.clone()]),
        );
        memory
            .commit(common::batch(
                "promote",
                vec![decision, accepted, support],
                Vec::new(),
            ))
            .expect("promotion");
        let beliefs = memory.beliefs(&today).expect("project view");
        assert_eq!(beliefs.len(), 1);
        assert_eq!(beliefs[0].record.scope, common::scope());
    }
}

#[test]
fn conflicts_remain_visible_and_resolution_is_recorded() {
    let (_temp, mut workspace) = common::setup();
    let first = common::propose(
        &mut workspace,
        "first-claim",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x10),
            evidence_revision: common::rev(0x11),
            assertion_id: common::rid(0x20),
            assertion_revision: common::rev(0x21),
            predicate: "storage-engine",
            value: mneme_core::Value::string("SQLite"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    let second = common::propose(
        &mut workspace,
        "second-claim",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x12),
            evidence_revision: common::rev(0x13),
            assertion_id: common::rid(0x24),
            assertion_revision: common::rev(0x25),
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
            decision_id: common::rid(0x30),
            decision_revision: common::rev(0x31),
            assertion_revision: common::rev(0x22),
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
            decision_id: common::rid(0x32),
            decision_revision: common::rev(0x33),
            assertion_revision: common::rev(0x26),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let view = mneme_memory::BeliefView {
        scope: common::scope(),
        at: mneme_core::Timestamp::parse("2026-11-10T00:00:00Z").expect("today"),
        include_hypothetical: false,
        include_disputed: true,
    };
    let memory = common::engine(&mut workspace);
    let conflicts = memory.conflicts(&view).expect("conflicts");
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].assertions.len(), 2);
    let _ = memory;

    // Explicitly mark both claims disputed with related links.
    let first_envelope = common::latest(&workspace, first);
    let second_envelope = common::latest(&workspace, second);
    let first_disputed = mneme_memory::build_assertion_revision(
        &first_envelope,
        common::rev(0x23),
        mneme_core::Lifecycle::Disputed,
        mneme_core::Reference::local(common::rid(0x34), mneme_core::RecordKind::Decision),
        None,
    );
    let second_disputed = mneme_memory::build_assertion_revision(
        &second_envelope,
        common::rev(0x27),
        mneme_core::Lifecycle::Disputed,
        mneme_core::Reference::local(common::rid(0x36), mneme_core::RecordKind::Decision),
        None,
    );
    let base = workspace.current_revision().expect("base");
    let decision_first = mneme_memory::build_decision(
        common::rid(0x34),
        common::rev(0x35),
        &common::scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::ConflictResolution,
            target: first,
            actor: "test-author",
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
        common::rid(0x36),
        common::rev(0x37),
        &common::scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::ConflictResolution,
            target: second,
            actor: "test-author",
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
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch(
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
    let (_temp, mut workspace) = common::setup();
    let past = common::propose(
        &mut workspace,
        "past",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x10),
            evidence_revision: common::rev(0x11),
            assertion_id: common::rid(0x20),
            assertion_revision: common::rev(0x21),
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
    let future = common::propose(
        &mut workspace,
        "future",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x12),
            evidence_revision: common::rev(0x13),
            assertion_id: common::rid(0x24),
            assertion_revision: common::rev(0x25),
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
            decision_id: common::rid(0x30),
            decision_revision: common::rev(0x31),
            assertion_revision: common::rev(0x22),
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
            decision_id: common::rid(0x32),
            decision_revision: common::rev(0x33),
            assertion_revision: common::rev(0x26),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let view = mneme_memory::BeliefView {
        scope: common::scope(),
        at: mneme_core::Timestamp::parse("2024-06-01T00:00:00Z").expect("at"),
        include_hypothetical: false,
        include_disputed: false,
    };
    let memory = common::engine(&mut workspace);
    assert!(memory.conflicts(&view).expect("conflicts").is_empty());
}

#[test]
fn derivations_offer_independent_alternatives_and_survive_one_withdrawal() {
    let (_temp, mut workspace) = common::setup();
    let premise_one = common::propose(
        &mut workspace,
        "p1",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x10),
            evidence_revision: common::rev(0x11),
            assertion_id: common::rid(0x20),
            assertion_revision: common::rev(0x21),
            predicate: "premise-one",
            value: mneme_core::Value::string("yes"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    let premise_two = common::propose(
        &mut workspace,
        "p2",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x12),
            evidence_revision: common::rev(0x13),
            assertion_id: common::rid(0x24),
            assertion_revision: common::rev(0x25),
            predicate: "premise-two",
            value: mneme_core::Value::string("yes"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    let premise_three = common::propose(
        &mut workspace,
        "p3",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x14),
            evidence_revision: common::rev(0x15),
            assertion_id: common::rid(0x28),
            assertion_revision: common::rev(0x29),
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
            decision_id: common::rid(0x40),
            decision_revision: common::rev(0x41),
            assertion_revision: common::rev(0x22),
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
            decision_id: common::rid(0x42),
            decision_revision: common::rev(0x43),
            assertion_revision: common::rev(0x26),
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
            decision_id: common::rid(0x44),
            decision_revision: common::rev(0x45),
            assertion_revision: common::rev(0x2a),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let conclusion = common::propose_bare(
        &mut workspace,
        "conclusion",
        &common::scope(),
        common::BareProposalInput {
            assertion_id: common::rid(0x30),
            assertion_revision: common::rev(0x31),
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
            decision_id: common::rid(0x46),
            decision_revision: common::rev(0x47),
            assertion_revision: common::rev(0x32),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let base = workspace.current_revision().expect("base");
    let derivation_one = mneme_memory::build_derivation(
        common::rid(0x50),
        common::rev(0x51),
        &common::scope(),
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
        common::rid(0x52),
        common::rev(0x53),
        &common::scope(),
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
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch(
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
            decision_id: common::rid(0x48),
            decision_revision: common::rev(0x49),
            assertion_revision: common::rev(0x23),
            kind: mneme_memory::DecisionKind::Retraction,
            outcome: "retracted",
            related: &[],
        },
    );
    let memory = common::engine(&mut workspace);
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
    let (_temp, mut workspace) = common::setup();
    let first = common::propose_bare(
        &mut workspace,
        "cycle-a",
        &common::scope(),
        common::BareProposalInput {
            assertion_id: common::rid(0x20),
            assertion_revision: common::rev(0x21),
            predicate: "cycle-a",
            value: mneme_core::Value::string("a"),
        },
    );
    let second = common::propose_bare(
        &mut workspace,
        "cycle-b",
        &common::scope(),
        common::BareProposalInput {
            assertion_id: common::rid(0x24),
            assertion_revision: common::rev(0x25),
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
            decision_id: common::rid(0x30),
            decision_revision: common::rev(0x31),
            assertion_revision: common::rev(0x22),
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
            decision_id: common::rid(0x32),
            decision_revision: common::rev(0x33),
            assertion_revision: common::rev(0x26),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let base = workspace.current_revision().expect("base");
    let derivation_a = mneme_memory::build_derivation(
        common::rid(0x40),
        common::rev(0x41),
        &common::scope(),
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
        common::rid(0x42),
        common::rev(0x43),
        &common::scope(),
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
    let mut memory = common::engine(&mut workspace);
    memory
        .commit(common::batch(
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
    let (_temp, mut workspace) = common::setup();
    let assertion_id = common::rid(0x20);
    let evidence_one = mneme_memory::build_evidence(
        common::rid(0x10),
        common::rev(0x11),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: common::SOURCE_ID,
            source_revision: common::SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let evidence_two = mneme_memory::build_evidence(
        common::rid(0x12),
        common::rev(0x13),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: common::SOURCE_ID,
            source_revision: common::SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(4, 7).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[mneme_core::Reference::local(
                common::rid(0x10),
                mneme_core::RecordKind::Evidence,
            )],
        },
    );
    let evidence_three = mneme_memory::build_evidence(
        common::rid(0x14),
        common::rev(0x15),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: common::SOURCE_ID,
            source_revision: common::SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(8, 12).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[mneme_core::Reference::local(
                common::rid(0x10),
                mneme_core::RecordKind::Evidence,
            )],
        },
    );
    let assertion = mneme_memory::build_proposed_assertion(
        assertion_id,
        common::rev(0x21),
        &common::scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "corroborated",
            value: mneme_core::Value::string("yes"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[
                mneme_core::Reference::local(common::rid(0x10), mneme_core::RecordKind::Evidence),
                mneme_core::Reference::local(common::rid(0x12), mneme_core::RecordKind::Evidence),
                mneme_core::Reference::local(common::rid(0x14), mneme_core::RecordKind::Evidence),
            ],
            extraction: None,
            superseded_by: None,
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch(
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
            decision_id: common::rid(0x30),
            decision_revision: common::rev(0x31),
            assertion_revision: common::rev(0x22),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let memory = common::engine(&mut workspace);
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
    let (_temp, mut workspace) = common::setup();
    let assertion_id = common::rid(0x20);
    let evidence_one = mneme_memory::build_evidence(
        common::rid(0x10),
        common::rev(0x11),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: common::SOURCE_ID,
            source_revision: common::SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[mneme_core::Reference::local(
                common::rid(0x12),
                mneme_core::RecordKind::Evidence,
            )],
        },
    );
    let evidence_two = mneme_memory::build_evidence(
        common::rid(0x12),
        common::rev(0x13),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: common::SOURCE_ID,
            source_revision: common::SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(4, 7).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[mneme_core::Reference::local(
                common::rid(0x10),
                mneme_core::RecordKind::Evidence,
            )],
        },
    );
    let assertion = mneme_memory::build_proposed_assertion(
        assertion_id,
        common::rev(0x21),
        &common::scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "cyclic",
            value: mneme_core::Value::string("no"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[
                mneme_core::Reference::local(common::rid(0x10), mneme_core::RecordKind::Evidence),
                mneme_core::Reference::local(common::rid(0x12), mneme_core::RecordKind::Evidence),
            ],
            extraction: None,
            superseded_by: None,
        },
    );
    let error = {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch(
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
    let (_temp, mut workspace) = common::setup();
    let assertion_id = common::propose(
        &mut workspace,
        "proposal",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x10),
            evidence_revision: common::rev(0x11),
            assertion_id: common::rid(0x20),
            assertion_revision: common::rev(0x21),
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
            decision_id: common::rid(0x30),
            decision_revision: common::rev(0x31),
            assertion_revision: common::rev(0x22),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let (mut pruned, _) = (
        mneme_memory::build_unavailable_source(
            common::SOURCE_ID,
            common::rev(0x53),
            &common::scope(),
            mneme_memory::UnavailableSourceOptions {
                reason: "raw bytes pruned under retention policy",
                availability: "pruned",
                entity: Some(mneme_core::fixtures::entity_id()),
                path_hint: Some("project.adoc"),
            },
        ),
        (),
    );
    pruned.predecessor = Some(common::SOURCE_REV);
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch("prune", vec![pruned], Vec::new()))
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
    let (_temp, mut workspace) = common::setup();
    let assertion_id = common::propose(
        &mut workspace,
        "proposal",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x10),
            evidence_revision: common::rev(0x11),
            assertion_id: common::rid(0x20),
            assertion_revision: common::rev(0x21),
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
            decision_id: common::rid(0x30),
            decision_revision: common::rev(0x31),
            assertion_revision: common::rev(0x22),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let accepted = common::latest(&workspace, assertion_id);
    let mut corrected = mneme_memory::build_assertion_revision(
        &accepted,
        common::rev(0x23),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(common::rid(0x32), mneme_core::RecordKind::Decision),
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
        common::rid(0x32),
        common::rev(0x33),
        &common::scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: assertion_id,
            actor: "test-author",
            policy: "correction-policy/v1",
            input_revision: base,
            outcome: "accepted",
            rationale: "corrected after review",
            evidence: &[],
            related: &[],
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch(
                "correct",
                vec![correction_decision, corrected],
                Vec::new(),
            ))
            .expect("correction");
        let beliefs = memory
            .beliefs(&mneme_memory::BeliefView {
                scope: common::scope(),
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
            decision_id: common::rid(0x34),
            decision_revision: common::rev(0x35),
            assertion_revision: common::rev(0x24),
            kind: mneme_memory::DecisionKind::Retraction,
            outcome: "retracted",
            related: &[],
        },
    );
    let memory = common::engine(&mut workspace);
    assert!(
        memory
            .beliefs(&mneme_memory::BeliefView {
                scope: common::scope(),
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
    let (_temp, mut workspace) = common::setup();
    let intent = mneme_memory::build_episode(
        common::rid(0x10),
        common::rev(0x11),
        &common::scope(),
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
        common::rid(0x12),
        common::rev(0x13),
        &common::scope(),
        mneme_memory::EpisodeOptions {
            actor: "agent",
            episode_type: "attempt",
            occurred: mneme_core::ValidTime::Unknown,
            summary: "attempted the test with unknown result",
            source: None,
            related: &[mneme_core::Reference::local(
                common::rid(0x10),
                mneme_core::RecordKind::Episode,
            )],
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch("episodes", vec![intent, attempt], Vec::new()))
            .expect("episodes");
    }
    let assertion_id = common::rid(0x20);
    let evidence = mneme_memory::build_evidence(
        common::rid(0x14),
        common::rev(0x15),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: common::SOURCE_ID,
            source_revision: common::SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(0, 4).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::Observation,
            ancestry: &[mneme_core::Reference::local(
                common::rid(0x12),
                mneme_core::RecordKind::Episode,
            )],
        },
    );
    let completed = mneme_memory::build_proposed_assertion(
        assertion_id,
        common::rev(0x21),
        &common::scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "action-completed",
            value: mneme_core::Value::string("device tested"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::Observation,
            asserted_by: "agent",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                common::rid(0x14),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        let error = memory
            .commit(common::batch(
                "false-completion",
                vec![evidence, completed],
                Vec::new(),
            ))
            .expect_err("no observed outcome");
        assert!(error.to_string().contains("observed outcome"));
    }

    let outcome = mneme_memory::build_episode(
        common::rid(0x16),
        common::rev(0x17),
        &common::scope(),
        mneme_memory::EpisodeOptions {
            actor: "agent",
            episode_type: "outcome",
            occurred: mneme_core::ValidTime::Unknown,
            summary: "device responded",
            source: None,
            related: &[mneme_core::Reference::local(
                common::rid(0x12),
                mneme_core::RecordKind::Episode,
            )],
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch("outcome", vec![outcome], Vec::new()))
            .expect("outcome");
    }
    let evidence = mneme_memory::build_evidence(
        common::rid(0x14),
        common::rev(0x15),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: common::SOURCE_ID,
            source_revision: common::SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(0, 4).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::Observation,
            ancestry: &[mneme_core::Reference::local(
                common::rid(0x16),
                mneme_core::RecordKind::Episode,
            )],
        },
    );
    let completed = mneme_memory::build_proposed_assertion(
        assertion_id,
        common::rev(0x21),
        &common::scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "action-completed",
            value: mneme_core::Value::string("device tested"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::Observation,
            asserted_by: "agent",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                common::rid(0x14),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    let checkpoint = mneme_memory::build_checkpoint(
        common::rid(0x18),
        common::rev(0x19),
        &common::scope(),
        mneme_memory::CheckpointOptions {
            goal: "verify device",
            state: "awaiting-verification",
            episodes: &[mneme_core::Reference::local(
                common::rid(0x10),
                mneme_core::RecordKind::Episode,
            )],
            verified_outcomes: &[mneme_core::Reference::local(
                common::rid(0x16),
                mneme_core::RecordKind::Episode,
            )],
            revision: workspace.current_revision().expect("revision"),
            note: None,
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch(
                "observed-completion",
                vec![evidence, completed, checkpoint],
                Vec::new(),
            ))
            .expect("completed action with observed outcome");
    }
}

#[test]
fn accepted_absence_requires_an_explicit_completeness_basis() {
    let (_temp, mut workspace) = common::setup();
    let assertion_id = common::rid(0x20);
    let mut assertion = mneme_memory::build_proposed_assertion(
        assertion_id,
        common::rev(0x21),
        &common::scope(),
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
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch(
                "absence",
                vec![assertion.clone()],
                Vec::new(),
            ))
            .expect("proposed absence");
    }
    let current = common::latest(&workspace, assertion_id);
    let accepted = mneme_memory::build_assertion_revision(
        &current,
        common::rev(0x22),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(common::rid(0x30), mneme_core::RecordKind::Decision),
        None,
    );
    let base = workspace.current_revision().expect("base");
    let decision = mneme_memory::build_decision(
        common::rid(0x30),
        common::rev(0x31),
        &common::scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: assertion_id,
            actor: "test-author",
            policy: "absence-policy/v1",
            input_revision: base,
            outcome: "accepted",
            rationale: "attempted acceptance",
            evidence: &[],
            related: &[],
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        let error = memory
            .commit(common::batch(
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
    assertion.revision_id = common::rev(0x23);
    assertion.predecessor = Some(common::rev(0x21));
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch(
                "declared-absence",
                vec![assertion],
                Vec::new(),
            ))
            .expect("declared complete basis");
    }
    let current = common::latest(&workspace, assertion_id);
    let accepted = mneme_memory::build_assertion_revision(
        &current,
        common::rev(0x24),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(common::rid(0x32), mneme_core::RecordKind::Decision),
        None,
    );
    let base = workspace.current_revision().expect("base");
    let decision = mneme_memory::build_decision(
        common::rid(0x32),
        common::rev(0x33),
        &common::scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: assertion_id,
            actor: "test-author",
            policy: "absence-policy/v1",
            input_revision: base,
            outcome: "accepted",
            rationale: "declared-complete absence",
            evidence: &[],
            related: &[],
        },
    );
    let mut memory = common::engine(&mut workspace);
    memory
        .commit(common::batch(
            "accept-declared-absence",
            vec![decision, accepted],
            Vec::new(),
        ))
        .expect("accepted declared absence");
}

#[test]
fn supersession_is_explicit_and_preserves_the_prior_revision() {
    let (_temp, mut workspace) = common::setup();
    let old = common::propose(
        &mut workspace,
        "old",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x10),
            evidence_revision: common::rev(0x11),
            assertion_id: common::rid(0x20),
            assertion_revision: common::rev(0x21),
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
            decision_id: common::rid(0x30),
            decision_revision: common::rev(0x31),
            assertion_revision: common::rev(0x22),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let replacement = common::propose(
        &mut workspace,
        "new",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x12),
            evidence_revision: common::rev(0x13),
            assertion_id: common::rid(0x24),
            assertion_revision: common::rev(0x25),
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
            decision_id: common::rid(0x32),
            decision_revision: common::rev(0x33),
            assertion_revision: common::rev(0x26),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let current_old = common::latest(&workspace, old);
    let mut superseded = mneme_memory::build_assertion_revision(
        &current_old,
        common::rev(0x23),
        mneme_core::Lifecycle::Superseded,
        mneme_core::Reference::local(common::rid(0x34), mneme_core::RecordKind::Decision),
        Some(mneme_core::Reference::local(
            replacement,
            mneme_core::RecordKind::Assertion,
        )),
    );
    superseded.predecessor = Some(current_old.revision_id);
    let base = workspace.current_revision().expect("base");
    let decision = mneme_memory::build_decision(
        common::rid(0x34),
        common::rev(0x35),
        &common::scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Supersession,
            target: old,
            actor: "test-author",
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
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch(
                "supersede",
                vec![decision, superseded],
                Vec::new(),
            ))
            .expect("supersession");
        let beliefs = memory
            .beliefs(&mneme_memory::BeliefView {
                scope: common::scope(),
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
    let (_temp, mut workspace) = common::setup();
    let assertion_id = common::rid(0x20);
    let evidence = mneme_memory::build_evidence(
        common::rid(0x10),
        common::rev(0x11),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: common::SOURCE_ID,
            source_revision: common::rev(0x54),
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let assertion = mneme_memory::build_proposed_assertion(
        assertion_id,
        common::rev(0x21),
        &common::scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "storage-engine",
            value: mneme_core::Value::string("SQLite"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                common::rid(0x10),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        let error = memory
            .commit(common::batch(
                "pinned-mismatch",
                vec![evidence, assertion],
                Vec::new(),
            ))
            .expect_err("mismatched pinned revision");
        assert!(error.to_string().contains("missing source"));
    }

    let assertion_id = common::propose(
        &mut workspace,
        "proposal",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x12),
            evidence_revision: common::rev(0x13),
            assertion_id: common::rid(0x24),
            assertion_revision: common::rev(0x25),
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
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch(
                "advance",
                vec![mneme_memory::build_proposed_assertion(
                    common::rid(0x30),
                    common::rev(0x31),
                    &common::scope(),
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
    let current = common::latest(&workspace, assertion_id);
    let accepted = mneme_memory::build_assertion_revision(
        &current,
        common::rev(0x26),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(common::rid(0x40), mneme_core::RecordKind::Decision),
        None,
    );
    let decision = mneme_memory::build_decision(
        common::rid(0x40),
        common::rev(0x41),
        &common::scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: assertion_id,
            actor: "test-author",
            policy: "stale-policy/v1",
            input_revision: mneme_core::WorkspaceRevisionId::from_bytes([0x7f; 16]),
            outcome: "accepted",
            rationale: "stale decision",
            evidence: &[],
            related: &[],
        },
    );
    let mut memory = common::engine(&mut workspace);
    let error = memory
        .commit(common::batch(
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
        let (_temp, mut workspace) = common::setup();
        let assertion = common::propose(
            &mut workspace,
            "proposal",
            &common::scope(),
            common::ProposalInput {
                evidence_id: common::rid(0x10),
                evidence_revision: common::rev(0x11),
                assertion_id: common::rid(0x20),
                assertion_revision: common::rev(0x21),
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
                decision_id: common::rid(0x30),
                decision_revision: common::rev(0x31),
                assertion_revision: common::rev(0x22),
                kind: mneme_memory::DecisionKind::Acceptance,
                outcome: "accepted",
                related: &[],
            },
        );
        let mut replacement = mneme_memory::build_unavailable_source(
            common::SOURCE_ID,
            common::rev(0x55),
            &common::scope(),
            mneme_memory::UnavailableSourceOptions {
                reason,
                availability,
                entity: Some(mneme_core::fixtures::entity_id()),
                path_hint: Some("project.adoc"),
            },
        );
        replacement.predecessor = Some(common::SOURCE_REV);
        {
            let mut memory = common::engine(&mut workspace);
            memory
                .commit(common::batch("unavailable", vec![replacement], Vec::new()))
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
    let (_temp, mut workspace) = common::setup();
    let assertion = common::propose(
        &mut workspace,
        "proposal",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x10),
            evidence_revision: common::rev(0x11),
            assertion_id: common::rid(0x20),
            assertion_revision: common::rev(0x21),
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
            decision_id: common::rid(0x30),
            decision_revision: common::rev(0x31),
            assertion_revision: common::rev(0x22),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let generation = workspace.eligibility_generation().expect("generation");
    workspace.advance_eligibility_barrier().expect("barrier");
    let memory = common::engine(&mut workspace);
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
        mneme_memory::EvidenceError::Store(mneme_store::Failure::BarrierAdvanced { .. })
    ));
}

fn sound_evidence(
    evidence_id: mneme_core::RecordId,
    evidence_revision: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    assertion: mneme_core::RecordId,
) -> mneme_store::RecordDraft {
    mneme_memory::build_evidence(
        evidence_id,
        evidence_revision,
        scope,
        mneme_memory::EvidenceOptions {
            assertion,
            source: common::SOURCE_ID,
            source_revision: common::SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    )
}

fn sound_assertion(
    assertion_id: mneme_core::RecordId,
    assertion_revision: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    predicate: &str,
    value: mneme_core::Value,
) -> mneme_store::RecordDraft {
    mneme_memory::build_proposed_assertion(
        assertion_id,
        assertion_revision,
        scope,
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate,
            value,
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "synthetic author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[],
            extraction: None,
            superseded_by: None,
        },
    )
}

#[test]
fn cross_scope_evidence_is_refused_unless_the_caller_is_authorized() {
    let (_temp, mut workspace) = common::setup();
    let cedar = common::scope();
    let birch = common::project_scope("birch");
    let birch_source = common::rid(0x60);
    let birch_revision = common::rev(0x61);
    {
        let (source, blob) = mneme_memory::build_source(
            birch_source,
            birch_revision,
            &birch,
            mneme_memory::SourceOptions {
                bytes: b"BIRCH ONLY: the acquisition target is Initech\n",
                media_type: "text/asciidoc",
                entity: None,
                path_hint: None,
            },
        )
        .expect("birch source");
        let mut memory = mneme_memory::Engine::new(
            &mut workspace,
            mneme_memory::Access::scopes([birch.clone()]),
        );
        memory
            .commit(common::batch_in(
                &birch,
                "birch-source",
                vec![source],
                vec![blob],
            ))
            .expect("birch source commit");
    }
    let cite = |source: mneme_core::RecordId, revision: mneme_core::RevisionId| {
        let evidence = mneme_memory::build_evidence(
            common::rid(0x10),
            common::rev(0x11),
            &cedar,
            mneme_memory::EvidenceOptions {
                assertion: common::rid(0x20),
                source,
                source_revision: revision,
                span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
                anchor: None,
                relation: mneme_memory::SupportRelation::Supports,
                origin: mneme_core::Origin::AuthoredStatement,
                ancestry: &[],
            },
        );
        let assertion = mneme_memory::build_proposed_assertion(
            common::rid(0x20),
            common::rev(0x21),
            &cedar,
            mneme_memory::ProposedAssertionOptions {
                subject: mneme_core::fixtures::entity_id(),
                predicate: "storage-engine",
                value: mneme_core::Value::string("SQLite"),
                stance: mneme_memory::Stance::Affirm,
                origin: mneme_core::Origin::AuthoredStatement,
                asserted_by: "synthetic author",
                valid_time: mneme_core::ValidTime::always(),
                evidence: &[mneme_core::Reference::local(
                    common::rid(0x10),
                    mneme_core::RecordKind::Evidence,
                )],
                extraction: None,
                superseded_by: None,
            },
        );
        (evidence, assertion)
    };
    let (foreign_evidence, foreign_assertion) = cite(birch_source, birch_revision);
    let (absent_evidence, absent_assertion) = cite(common::rid(0x7e), common::rev(0x7f));
    {
        let mut memory = mneme_memory::Engine::new(
            &mut workspace,
            mneme_memory::Access::scopes([cedar.clone()]),
        );
        let foreign = memory
            .commit(common::batch(
                "cite-foreign",
                vec![foreign_evidence.clone(), foreign_assertion.clone()],
                Vec::new(),
            ))
            .expect_err("cross-scope citation");
        // A record the caller cannot reach is reported exactly like an
        // identifier that names nothing.
        let absent = memory
            .commit(common::batch(
                "cite-absent",
                vec![absent_evidence, absent_assertion],
                Vec::new(),
            ))
            .expect_err("absent citation");
        assert_eq!(foreign.to_string(), absent.to_string());
        assert!(!foreign.to_string().contains("BIRCH"));
        assert!(foreign.to_string().contains("unavailable"));
    }
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch(
                "cite-foreign-operator",
                vec![foreign_evidence, foreign_assertion],
                Vec::new(),
            ))
            .expect("an operator may cite another authorized scope");
    }

    // An operational record never depends on a hypothesis, even when the
    // caller is authorized for the hypothesis scope.
    let plan = common::hypothesis_scope("plan-x");
    let plan_episode = common::rid(0x74);
    {
        let episode = mneme_memory::build_episode(
            plan_episode,
            common::rev(0x75),
            &plan,
            mneme_memory::EpisodeOptions {
                actor: "planner",
                episode_type: "observation",
                occurred: mneme_core::ValidTime::Unknown,
                summary: "plan-only observation",
                source: None,
                related: &[],
            },
        );
        let mut memory =
            mneme_memory::Engine::new(&mut workspace, mneme_memory::Access::scopes([plan.clone()]));
        memory
            .commit(common::batch_in(
                &plan,
                "plan-episode",
                vec![episode],
                Vec::new(),
            ))
            .expect("plan episode");
    }
    let evidence = mneme_memory::build_evidence(
        common::rid(0x12),
        common::rev(0x13),
        &cedar,
        mneme_memory::EvidenceOptions {
            assertion: common::rid(0x22),
            source: common::SOURCE_ID,
            source_revision: common::SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::Observation,
            ancestry: &[mneme_core::Reference::local(
                plan_episode,
                mneme_core::RecordKind::Episode,
            )],
        },
    );
    let mut assertion = sound_assertion(
        common::rid(0x22),
        common::rev(0x23),
        &cedar,
        "storage-engine",
        mneme_core::Value::string("SQLite"),
    );
    assertion.payload.insert(
        mneme_core::Symbol::from("evidence"),
        mneme_core::Value::set([mneme_core::Reference::local(
            common::rid(0x12),
            mneme_core::RecordKind::Evidence,
        )
        .to_value()]),
    );
    let mut memory = common::engine(&mut workspace);
    let error = memory
        .commit(common::batch(
            "cite-hypothesis",
            vec![evidence, assertion],
            Vec::new(),
        ))
        .expect_err("operational premise from a hypothesis scope");
    assert!(error.to_string().contains("may not reference"));
}

#[test]
fn another_scopes_record_cannot_be_revised_into_the_callers_scope() {
    let (_temp, mut workspace) = common::setup();
    let cedar = common::scope();
    let birch = common::project_scope("birch");
    let entity = mneme_core::fixtures::entity_id();
    let current = common::latest(&workspace, entity);
    let mut moved = common::draft(&current);
    moved.revision_id = common::rev(0x80);
    moved.predecessor = Some(current.revision_id);
    moved.scope = birch.clone();
    moved.payload.insert(
        mneme_core::Symbol::from("label"),
        mneme_core::Value::string("hijacked"),
    );
    let error = {
        let mut memory = mneme_memory::Engine::new(
            &mut workspace,
            mneme_memory::Access::scopes([birch.clone()]),
        );
        memory
            .commit(common::batch_in(
                &birch,
                "takeover",
                vec![moved],
                Vec::new(),
            ))
            .expect_err("cross-scope revision")
    };
    assert!(error.to_string().contains("scope"));
    assert!(!error.to_string().contains(&entity.to_string()));
    assert_eq!(common::latest(&workspace, entity).scope, cedar);
}

#[test]
fn committed_decisions_cannot_promote_later_content() {
    let (_temp, mut workspace) = common::setup();
    let assertion_id = common::propose(
        &mut workspace,
        "proposal",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x10),
            evidence_revision: common::rev(0x11),
            assertion_id: common::rid(0x20),
            assertion_revision: common::rev(0x21),
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
            decision_id: common::rid(0x30),
            decision_revision: common::rev(0x31),
            assertion_revision: common::rev(0x22),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    decide(
        &mut workspace,
        "retract",
        DecisionInput {
            assertion: assertion_id,
            lifecycle: mneme_core::Lifecycle::Retracted,
            decision_id: common::rid(0x32),
            decision_revision: common::rev(0x33),
            assertion_revision: common::rev(0x23),
            kind: mneme_memory::DecisionKind::Retraction,
            outcome: "retracted",
            related: &[],
        },
    );
    let current = common::latest(&workspace, assertion_id);
    assert_eq!(
        current.assertion_lifecycle(),
        Some(mneme_core::Lifecycle::Retracted)
    );
    // The acceptance decision committed earlier cannot resurrect the retracted
    // assertion or accept its changed content.
    let mut resurrect = mneme_memory::build_assertion_revision(
        &current,
        common::rev(0x24),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(common::rid(0x30), mneme_core::RecordKind::Decision),
        None,
    );
    resurrect.payload.insert(
        mneme_core::Symbol::from("value"),
        mneme_core::Value::string("LMDB"),
    );
    {
        let mut memory = common::engine(&mut workspace);
        let error = memory
            .commit(common::batch("resurrect", vec![resurrect], Vec::new()))
            .expect_err("stale acceptance");
        assert!(error.to_string().contains("admissible"));
        assert_eq!(
            common::latest(&workspace, assertion_id).assertion_lifecycle(),
            Some(mneme_core::Lifecycle::Retracted)
        );
    }
    // A retracted assertion cannot be retracted a second time.
    let base = workspace.current_revision().expect("base");
    let retract = mneme_memory::build_decision(
        common::rid(0x34),
        common::rev(0x35),
        &common::scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Retraction,
            target: assertion_id,
            actor: "test-author",
            policy: "test-policy/v1",
            input_revision: base,
            outcome: "retracted",
            rationale: "retract again",
            evidence: &[],
            related: &[],
        },
    );
    let again = mneme_memory::build_assertion_revision(
        &current,
        common::rev(0x26),
        mneme_core::Lifecycle::Retracted,
        mneme_core::Reference::local(common::rid(0x34), mneme_core::RecordKind::Decision),
        None,
    );
    let mut memory = common::engine(&mut workspace);
    let error = memory
        .commit(common::batch(
            "retract-again",
            vec![retract, again],
            Vec::new(),
        ))
        .expect_err("repeated retraction");
    assert!(error.to_string().contains("admissible"));
}

#[test]
fn forged_decision_actors_and_born_accepted_assertions_are_refused() {
    let (_temp, mut workspace) = common::setup();
    let assertion_id = common::propose(
        &mut workspace,
        "proposal",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x10),
            evidence_revision: common::rev(0x11),
            assertion_id: common::rid(0x20),
            assertion_revision: common::rev(0x21),
            predicate: "storage-engine",
            value: mneme_core::Value::string("SQLite"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    let current = common::latest(&workspace, assertion_id);
    let base = workspace.current_revision().expect("base");
    let forged = mneme_memory::build_decision(
        common::rid(0x30),
        common::rev(0x31),
        &common::scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: assertion_id,
            actor: "human:alice (workspace owner)",
            policy: "owner-review/v2",
            input_revision: base,
            outcome: "accepted",
            rationale: "forged acceptance",
            evidence: &[],
            related: &[],
        },
    );
    let accepted = mneme_memory::build_assertion_revision(
        &current,
        common::rev(0x22),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(common::rid(0x30), mneme_core::RecordKind::Decision),
        None,
    );
    {
        let mut memory = common::engine(&mut workspace);
        let error = memory
            .commit(common::batch(
                "forged-accept",
                vec![forged, accepted],
                Vec::new(),
            ))
            .expect_err("decision actor differs from the batch actor");
        assert!(error.to_string().contains("actor"));
        assert_eq!(
            common::latest(&workspace, assertion_id).assertion_lifecycle(),
            Some(mneme_core::Lifecycle::Proposed)
        );
    }
    // A first revision can never be accepted: new assertions start proposed.
    let born_id = common::rid(0x40);
    let mut born = sound_assertion(
        born_id,
        common::rev(0x41),
        &common::scope(),
        "born-accepted",
        mneme_core::Value::string("yes"),
    );
    born.payload.insert(
        mneme_core::Symbol::from("lifecycle"),
        mneme_core::Value::symbol("accepted"),
    );
    born.payload.insert(
        mneme_core::Symbol::from("decision"),
        mneme_core::Reference::local(common::rid(0x42), mneme_core::RecordKind::Decision)
            .to_value(),
    );
    let decision = mneme_memory::build_decision(
        common::rid(0x42),
        common::rev(0x43),
        &common::scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: born_id,
            actor: "test-author",
            policy: "self-accept/v1",
            input_revision: base,
            outcome: "accepted",
            rationale: "accept on creation",
            evidence: &[],
            related: &[],
        },
    );
    let mut memory = common::engine(&mut workspace);
    let error = memory
        .commit(common::batch(
            "born-accepted",
            vec![decision, born],
            Vec::new(),
        ))
        .expect_err("new assertion born accepted");
    assert!(error.to_string().contains("admissible"));
}

#[test]
fn lost_response_retries_replay_and_stale_bases_conflict() {
    let (_temp, mut workspace) = common::setup();
    let assertion_id = common::propose(
        &mut workspace,
        "proposal",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x10),
            evidence_revision: common::rev(0x11),
            assertion_id: common::rid(0x20),
            assertion_revision: common::rev(0x21),
            predicate: "storage-engine",
            value: mneme_core::Value::string("SQLite"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    let current = common::latest(&workspace, assertion_id);
    let base = workspace.current_revision().expect("base");
    let decision = mneme_memory::build_decision(
        common::rid(0x30),
        common::rev(0x31),
        &common::scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: assertion_id,
            actor: "test-author",
            policy: "test-policy/v1",
            input_revision: base,
            outcome: "accepted",
            rationale: "explicit acceptance",
            evidence: &[],
            related: &[],
        },
    );
    let accepted = mneme_memory::build_assertion_revision(
        &current,
        common::rev(0x22),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(common::rid(0x30), mneme_core::RecordKind::Decision),
        None,
    );
    let request = common::batch("accept", vec![decision, accepted], Vec::new());
    let first = {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit_at_base(request.clone(), base)
            .expect("accept")
    };
    // The client lost the response and retries the identical command.
    let replay = {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit_at_base(request, base)
            .expect("replayed accept")
    };
    assert_eq!(first.revision, replay.revision);
    assert_eq!(first.sequence, replay.sequence);
    assert_eq!(
        common::latest(&workspace, assertion_id).assertion_lifecycle(),
        Some(mneme_core::Lifecycle::Accepted)
    );
    assert_eq!(
        workspace.current_revision().expect("current"),
        first.revision
    );
    // A new command on the now-stale base conflicts instead of failing as
    // invalid input.
    let later = sound_assertion(
        common::rid(0x50),
        common::rev(0x51),
        &common::scope(),
        "later-claim",
        mneme_core::Value::string("later"),
    );
    let stale = {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit_at_base(common::batch("stale", vec![later], Vec::new()), base)
            .expect_err("stale base")
    };
    assert!(matches!(
        stale,
        mneme_memory::EvidenceError::Store(mneme_store::Failure::StaleBase { .. })
    ));
    // Reusing the accept key for a different request is a key conflict.
    let current_revision = workspace.current_revision().expect("current");
    let other = sound_assertion(
        common::rid(0x52),
        common::rev(0x53),
        &common::scope(),
        "other-claim",
        mneme_core::Value::string("other"),
    );
    let reused = {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit_at_base(
                common::batch("accept", vec![other], Vec::new()),
                current_revision,
            )
            .expect_err("key reuse")
    };
    assert!(matches!(
        reused,
        mneme_memory::EvidenceError::Store(mneme_store::Failure::IdempotencyConflict { .. })
    ));
}

#[test]
fn unpinned_evidence_is_refused() {
    let (_temp, mut workspace) = common::setup();
    let mut evidence = sound_evidence(
        common::rid(0x10),
        common::rev(0x11),
        &common::scope(),
        common::rid(0x20),
    );
    evidence.payload.insert(
        mneme_core::Symbol::from("source"),
        mneme_core::Reference::local(common::SOURCE_ID, mneme_core::RecordKind::SourceRevision)
            .to_value(),
    );
    let mut assertion = sound_assertion(
        common::rid(0x20),
        common::rev(0x21),
        &common::scope(),
        "storage-engine",
        mneme_core::Value::string("SQLite"),
    );
    assertion.payload.insert(
        mneme_core::Symbol::from("evidence"),
        mneme_core::Value::set([mneme_core::Reference::local(
            common::rid(0x10),
            mneme_core::RecordKind::Evidence,
        )
        .to_value()]),
    );
    let mut memory = common::engine(&mut workspace);
    let error = memory
        .commit(common::batch(
            "unpinned",
            vec![evidence, assertion],
            Vec::new(),
        ))
        .expect_err("unpinned source reference");
    assert!(error.to_string().contains("pin"));
}

#[test]
fn incomplete_derivations_cannot_support_accepted_conclusions() {
    let (_temp, mut workspace) = common::setup();
    let conclusion = common::propose_bare(
        &mut workspace,
        "conclusion",
        &common::scope(),
        common::BareProposalInput {
            assertion_id: common::rid(0x20),
            assertion_revision: common::rev(0x21),
            predicate: "derived-flag",
            value: mneme_core::Value::string("derived"),
        },
    );
    decide(
        &mut workspace,
        "conclusion-accept",
        DecisionInput {
            assertion: conclusion,
            lifecycle: mneme_core::Lifecycle::Accepted,
            decision_id: common::rid(0x30),
            decision_revision: common::rev(0x31),
            assertion_revision: common::rev(0x22),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
            related: &[],
        },
    );
    let base = workspace.current_revision().expect("base");
    let partial = mneme_memory::build_derivation(
        common::rid(0x40),
        common::rev(0x41),
        &common::scope(),
        mneme_memory::DerivationOptions {
            conclusion,
            premises: &[],
            rule_id: "partial-rule",
            rule_version: 1,
            evaluation_revision: base,
            completeness: "partial",
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        let error = memory
            .commit(common::batch(
                "partial-derivation",
                vec![partial],
                Vec::new(),
            ))
            .expect_err("incomplete justification of an accepted conclusion");
        assert!(error.to_string().contains("incomplete"));
    }
    // The same justification may accompany an unresolved proposal.
    let proposed = common::propose_bare(
        &mut workspace,
        "proposed-conclusion",
        &common::scope(),
        common::BareProposalInput {
            assertion_id: common::rid(0x24),
            assertion_revision: common::rev(0x25),
            predicate: "proposed-flag",
            value: mneme_core::Value::string("proposed"),
        },
    );
    let base = workspace.current_revision().expect("base");
    let partial = mneme_memory::build_derivation(
        common::rid(0x42),
        common::rev(0x43),
        &common::scope(),
        mneme_memory::DerivationOptions {
            conclusion: proposed,
            premises: &[],
            rule_id: "partial-rule",
            rule_version: 1,
            evaluation_revision: base,
            completeness: "partial",
        },
    );
    let mut memory = common::engine(&mut workspace);
    memory
        .commit(common::batch("partial-proposal", vec![partial], Vec::new()))
        .expect("incomplete justification of a proposal");
}

#[test]
fn completed_action_claims_are_guarded_by_claim_type() {
    let (_temp, mut workspace) = common::setup();
    let observation = mneme_memory::build_episode(
        common::rid(0x10),
        common::rev(0x11),
        &common::scope(),
        mneme_memory::EpisodeOptions {
            actor: "agent",
            episode_type: "observation",
            occurred: mneme_core::ValidTime::Unknown,
            summary: "it rained on Tuesday",
            source: None,
            related: &[],
        },
    );
    let intent = mneme_memory::build_episode(
        common::rid(0x12),
        common::rev(0x13),
        &common::scope(),
        mneme_memory::EpisodeOptions {
            actor: "agent",
            episode_type: "intent",
            occurred: mneme_core::ValidTime::Unknown,
            summary: "intend to test device D-7",
            source: None,
            related: &[],
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch(
                "episodes",
                vec![observation, intent],
                Vec::new(),
            ))
            .expect("episodes");
    }
    let unrelated = mneme_memory::build_evidence(
        common::rid(0x16),
        common::rev(0x17),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: common::rid(0x20),
            source: common::SOURCE_ID,
            source_revision: common::SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::Observation,
            ancestry: &[mneme_core::Reference::local(
                common::rid(0x10),
                mneme_core::RecordKind::Episode,
            )],
        },
    );
    let guarded = |evidence: mneme_core::RecordId| {
        let mut completed = sound_assertion(
            common::rid(0x20),
            common::rev(0x21),
            &common::scope(),
            "device-tested",
            mneme_core::Value::string("device D-7 tested"),
        );
        completed.payload.insert(
            mneme_core::Symbol::from("claim-type"),
            mneme_core::Value::symbol("action-completed"),
        );
        completed.payload.insert(
            mneme_core::Symbol::from("evidence"),
            mneme_core::Value::set([mneme_core::Reference::local(
                evidence,
                mneme_core::RecordKind::Evidence,
            )
            .to_value()]),
        );
        completed
    };
    let completed = guarded(common::rid(0x16));
    {
        let mut memory = common::engine(&mut workspace);
        let error = memory
            .commit(common::batch(
                "false-completion",
                vec![unrelated, completed],
                Vec::new(),
            ))
            .expect_err("unrelated observation");
        assert!(error.to_string().contains("observed outcome"));
    }
    let outcome = mneme_memory::build_episode(
        common::rid(0x14),
        common::rev(0x15),
        &common::scope(),
        mneme_memory::EpisodeOptions {
            actor: "agent",
            episode_type: "outcome",
            occurred: mneme_core::ValidTime::Unknown,
            summary: "device responded",
            source: None,
            related: &[mneme_core::Reference::local(
                common::rid(0x12),
                mneme_core::RecordKind::Episode,
            )],
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch("outcome", vec![outcome], Vec::new()))
            .expect("outcome");
    }
    let observed = mneme_memory::build_evidence(
        common::rid(0x18),
        common::rev(0x19),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: common::rid(0x20),
            source: common::SOURCE_ID,
            source_revision: common::SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::Observation,
            ancestry: &[mneme_core::Reference::local(
                common::rid(0x14),
                mneme_core::RecordKind::Episode,
            )],
        },
    );
    let completed = guarded(common::rid(0x18));
    let mut memory = common::engine(&mut workspace);
    memory
        .commit(common::batch(
            "observed-completion",
            vec![observed, completed],
            Vec::new(),
        ))
        .expect("observed outcome");
}

#[test]
fn checkpoints_cannot_verify_intents_as_outcomes() {
    let (_temp, mut workspace) = common::setup();
    let intent = mneme_memory::build_episode(
        common::rid(0x10),
        common::rev(0x11),
        &common::scope(),
        mneme_memory::EpisodeOptions {
            actor: "agent",
            episode_type: "intent",
            occurred: mneme_core::ValidTime::Unknown,
            summary: "intend to test device D-7 tomorrow",
            source: None,
            related: &[],
        },
    );
    let outcome = mneme_memory::build_episode(
        common::rid(0x12),
        common::rev(0x13),
        &common::scope(),
        mneme_memory::EpisodeOptions {
            actor: "agent",
            episode_type: "outcome",
            occurred: mneme_core::ValidTime::Unknown,
            summary: "device responded",
            source: None,
            related: &[mneme_core::Reference::local(
                common::rid(0x10),
                mneme_core::RecordKind::Episode,
            )],
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch("episodes", vec![intent, outcome], Vec::new()))
            .expect("episodes");
    }
    let revision = workspace.current_revision().expect("revision");
    let bad = mneme_memory::build_checkpoint(
        common::rid(0x14),
        common::rev(0x15),
        &common::scope(),
        mneme_memory::CheckpointOptions {
            goal: "verify device",
            state: "awaiting-verification",
            episodes: &[mneme_core::Reference::local(
                common::rid(0x10),
                mneme_core::RecordKind::Episode,
            )],
            verified_outcomes: &[mneme_core::Reference::local(
                common::rid(0x10),
                mneme_core::RecordKind::Episode,
            )],
            revision,
            note: None,
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        let error = memory
            .commit(common::batch("verify-intent", vec![bad], Vec::new()))
            .expect_err("an intent is not a verified outcome");
        assert!(error.to_string().contains("outcome"));
    }
    let good = mneme_memory::build_checkpoint(
        common::rid(0x16),
        common::rev(0x17),
        &common::scope(),
        mneme_memory::CheckpointOptions {
            goal: "verify device",
            state: "awaiting-verification",
            episodes: &[mneme_core::Reference::local(
                common::rid(0x10),
                mneme_core::RecordKind::Episode,
            )],
            verified_outcomes: &[mneme_core::Reference::local(
                common::rid(0x12),
                mneme_core::RecordKind::Episode,
            )],
            revision,
            note: None,
        },
    );
    let mut memory = common::engine(&mut workspace);
    memory
        .commit(common::batch("verify-outcome", vec![good], Vec::new()))
        .expect("an outcome is a verified outcome");
}

#[test]
fn model_extracted_assertions_require_input_evidence() {
    let (_temp, mut workspace) = common::setup();
    let mut extracted = sound_assertion(
        common::rid(0x20),
        common::rev(0x21),
        &common::scope(),
        "storage-engine",
        mneme_core::Value::string("SQLite"),
    );
    extracted.payload.insert(
        mneme_core::Symbol::from("origin"),
        mneme_core::Value::symbol("model-extraction"),
    );
    extracted.payload.insert(
        mneme_core::Symbol::from("extraction"),
        mneme_core::Value::record_named(
            "extraction",
            vec![
                mneme_core::Value::string("synthetic-extractor"),
                mneme_core::Value::string("prompt/v1"),
            ],
        ),
    );
    {
        let mut memory = common::engine(&mut workspace);
        let error = memory
            .commit(common::batch(
                "extraction",
                vec![extracted.clone()],
                Vec::new(),
            ))
            .expect_err("interpretation without input evidence");
        assert!(error.to_string().contains("input evidence"));
    }
    let evidence = sound_evidence(
        common::rid(0x10),
        common::rev(0x11),
        &common::scope(),
        common::rid(0x20),
    );
    extracted.payload.insert(
        mneme_core::Symbol::from("evidence"),
        mneme_core::Value::set([mneme_core::Reference::local(
            common::rid(0x10),
            mneme_core::RecordKind::Evidence,
        )
        .to_value()]),
    );
    let mut memory = common::engine(&mut workspace);
    memory
        .commit(common::batch(
            "extraction-evidence",
            vec![evidence, extracted],
            Vec::new(),
        ))
        .expect("model extraction with input evidence");
}
