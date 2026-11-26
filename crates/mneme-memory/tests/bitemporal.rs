//! Half-open valid-time handoff, legacy `Instant` compatibility, and
//! `View::bitemporal_diff` tests over durable workspaces.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::unwrap_used, clippy::expect_used)] // test/fixture code fails by panic, not a production path

#[allow(dead_code)]
mod common;

struct AcceptSpec {
    assertion: mneme_core::RecordId,
    decision_id: mneme_core::RecordId,
    decision_rev: mneme_core::RevisionId,
    assertion_rev: mneme_core::RevisionId,
}

fn accept_assertion(workspace: &mut mneme_store::Workspace, key: &str, spec: AcceptSpec) {
    let base = workspace.current_revision().expect("base");
    let current = common::latest(workspace, spec.assertion);
    let decision = mneme_memory::build_decision(
        spec.decision_id,
        spec.decision_rev,
        &common::scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: spec.assertion,
            actor: "test-author",
            policy: "bitemporal-policy/v1",
            input_revision: base,
            outcome: "accepted",
            rationale: "accept for bitemporal test",
            evidence: &[],
            related: &[],
        },
    );
    let revised = mneme_memory::build_assertion_revision(
        &current,
        spec.assertion_rev,
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(spec.decision_id, mneme_core::RecordKind::Decision),
        None,
    );
    let mut memory = common::engine(workspace);
    memory
        .commit(common::batch(key, vec![decision, revised], Vec::new()))
        .expect("accept commit");
}

#[test]
fn half_open_handoff_and_legacy_instant_compatibility() {
    let (_temp, mut workspace) = common::setup();
    let handoff = mneme_core::Timestamp::from_nanos(10_000);
    let before_handoff = mneme_core::Timestamp::from_nanos(9_999);
    let instant_ts = mneme_core::Timestamp::from_nanos(20_000);

    let first = common::propose(
        &mut workspace,
        "first",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x10),
            evidence_revision: common::rev(0x11),
            assertion_id: common::rid(0x20),
            assertion_revision: common::rev(0x21),
            predicate: "storage-engine",
            value: mneme_core::Value::string("SQLite"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::until(handoff),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    accept_assertion(
        &mut workspace,
        "first-accept",
        AcceptSpec {
            assertion: first,
            decision_id: common::rid(0x30),
            decision_rev: common::rev(0x31),
            assertion_rev: common::rev(0x22),
        },
    );

    let replacement = common::propose(
        &mut workspace,
        "replacement",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x12),
            evidence_revision: common::rev(0x13),
            assertion_id: common::rid(0x24),
            assertion_revision: common::rev(0x25),
            predicate: "storage-engine",
            value: mneme_core::Value::string("LMDB"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::since(handoff),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    accept_assertion(
        &mut workspace,
        "replacement-accept",
        AcceptSpec {
            assertion: replacement,
            decision_id: common::rid(0x32),
            decision_rev: common::rev(0x33),
            assertion_rev: common::rev(0x26),
        },
    );

    let point_claim = common::propose(
        &mut workspace,
        "point",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x14),
            evidence_revision: common::rev(0x15),
            assertion_id: common::rid(0x28),
            assertion_revision: common::rev(0x29),
            predicate: "deploy-marker",
            value: mneme_core::Value::string("v2.0"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::instant(instant_ts),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    accept_assertion(
        &mut workspace,
        "point-accept",
        AcceptSpec {
            assertion: point_claim,
            decision_id: common::rid(0x34),
            decision_rev: common::rev(0x35),
            assertion_rev: common::rev(0x2a),
        },
    );

    let memory = common::engine(&mut workspace);
    let view_before = mneme_memory::BeliefView {
        scope: common::scope(),
        at: before_handoff,
        include_hypothetical: false,
        include_disputed: false,
    };
    assert!(memory.conflicts(&view_before).expect("before").is_empty());
    let beliefs_before = memory.beliefs(&view_before).expect("beliefs before");
    assert_eq!(beliefs_before.len(), 1);
    assert_eq!(beliefs_before[0].record.record_id, first);

    let view_handoff = mneme_memory::BeliefView {
        scope: common::scope(),
        at: handoff,
        include_hypothetical: false,
        include_disputed: false,
    };
    assert!(
        memory.conflicts(&view_handoff).expect("handoff").is_empty(),
        "half-open [start, T) and [T, +inf) must produce 0 conflicts at T"
    );
    let beliefs_handoff = memory.beliefs(&view_handoff).expect("beliefs handoff");
    assert_eq!(beliefs_handoff.len(), 1);
    assert_eq!(beliefs_handoff[0].record.record_id, replacement);

    // Legacy `ValidTime::instant(T)` decodes as `[T, T + 1ns)`.
    let view_point = mneme_memory::BeliefView {
        scope: common::scope(),
        at: instant_ts,
        include_hypothetical: false,
        include_disputed: false,
    };
    let beliefs_at_point = memory.beliefs(&view_point).expect("point");
    assert!(
        beliefs_at_point
            .iter()
            .any(|b| b.record.record_id == point_claim)
    );
    let view_after_point = mneme_memory::BeliefView {
        scope: common::scope(),
        at: mneme_core::Timestamp::from_nanos(20_001),
        include_hypothetical: false,
        include_disputed: false,
    };
    assert!(
        !memory
            .beliefs(&view_after_point)
            .expect("after point")
            .iter()
            .any(|b| b.record.record_id == point_claim)
    );
}

#[test]
fn bitemporal_diff_distinguishes_world_evolution_from_retroactive_correction() {
    let (_temp, mut workspace) = common::setup();
    let t1 = mneme_core::Timestamp::from_nanos(1_000);
    let t2 = mneme_core::Timestamp::from_nanos(2_000);
    let t3 = mneme_core::Timestamp::from_nanos(3_000);
    let window = mneme_kernel::temporal::Period {
        start: 0,
        stop: 10_000,
    };

    // Baseline revision A: claim A1 valid on [1000, +inf).
    let a1 = common::propose(
        &mut workspace,
        "a1",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x40),
            evidence_revision: common::rev(0x41),
            assertion_id: common::rid(0x50),
            assertion_revision: common::rev(0x51),
            predicate: "primary-db",
            value: mneme_core::Value::string("SQLite"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::since(t1),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    accept_assertion(
        &mut workspace,
        "a1-accept",
        AcceptSpec {
            assertion: a1,
            decision_id: common::rid(0x60),
            decision_rev: common::rev(0x61),
            assertion_rev: common::rev(0x72),
        },
    );
    let rev_a = workspace.current_revision().expect("rev_a");

    // Revision B (WorldEvolution): cleanly expire A1 at t2 and add A2 since t2.
    let current_a1 = common::latest(&workspace, a1);
    let mut expired_a1 = mneme_memory::build_assertion_revision(
        &current_a1,
        common::rev(0x53),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(common::rid(0x62), mneme_core::RecordKind::Decision),
        None,
    );
    expired_a1.payload.insert(
        mneme_core::Symbol::from("valid-time"),
        mneme_core::ValidTime::between(t1, t2)
            .expect("bounds")
            .to_value(),
    );
    let exp_decision = mneme_memory::build_decision(
        common::rid(0x62),
        common::rev(0x63),
        &common::scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: a1,
            actor: "test-author",
            policy: "bitemporal-policy/v1",
            input_revision: rev_a,
            outcome: "accepted",
            rationale: "expire open-ended claim at handoff",
            evidence: &[],
            related: &[],
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch(
                "expire-a1",
                vec![exp_decision, expired_a1],
                Vec::new(),
            ))
            .expect("expire commit");
    }
    let a2 = common::propose(
        &mut workspace,
        "a2",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x42),
            evidence_revision: common::rev(0x43),
            assertion_id: common::rid(0x54),
            assertion_revision: common::rev(0x55),
            predicate: "primary-db",
            value: mneme_core::Value::string("Postgres"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::since(t2),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    accept_assertion(
        &mut workspace,
        "a2-accept",
        AcceptSpec {
            assertion: a2,
            decision_id: common::rid(0x64),
            decision_rev: common::rev(0x65),
            assertion_rev: common::rev(0x56),
        },
    );
    let rev_b = workspace.current_revision().expect("rev_b");

    // Revision C (RetroactiveCorrection): rewrite A1's historical value during [t1, t2)
    // and insert an overlapping backdated claim A3 during [1500, t3).
    let current_a1_b = common::latest(&workspace, a1);
    let mut corrected_a1 = mneme_memory::build_assertion_revision(
        &current_a1_b,
        common::rev(0x57),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(common::rid(0x66), mneme_core::RecordKind::Decision),
        None,
    );
    corrected_a1.payload.insert(
        mneme_core::Symbol::from("value"),
        mneme_core::Value::string("DuckDB"),
    );
    let corr_decision = mneme_memory::build_decision(
        common::rid(0x66),
        common::rev(0x67),
        &common::scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: a1,
            actor: "test-author",
            policy: "bitemporal-policy/v1",
            input_revision: rev_b,
            outcome: "accepted",
            rationale: "retroactive correction of historical db",
            evidence: &[],
            related: &[],
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch(
                "correct-a1",
                vec![corr_decision, corrected_a1],
                Vec::new(),
            ))
            .expect("correct commit");
    }
    let a3 = common::propose(
        &mut workspace,
        "a3",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x44),
            evidence_revision: common::rev(0x45),
            assertion_id: common::rid(0x58),
            assertion_revision: common::rev(0x59),
            predicate: "primary-db",
            value: mneme_core::Value::string("RocksDB"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::between(
                mneme_core::Timestamp::from_nanos(1_500),
                t3,
            )
            .expect("bounds"),
            span: None,
            ancestry: &[],
            extraction: None,
        },
    );
    accept_assertion(
        &mut workspace,
        "a3-accept",
        AcceptSpec {
            assertion: a3,
            decision_id: common::rid(0x68),
            decision_rev: common::rev(0x69),
            assertion_rev: common::rev(0x5a),
        },
    );
    let rev_c = workspace.current_revision().expect("rev_c");

    let view_at_rev = |ws: &mneme_store::Workspace, rev: mneme_core::WorkspaceRevisionId| {
        let snapshot = ws.snapshot_at(rev, None).expect("snapshot_at");
        let context = mneme_memory::view_context(ws, &snapshot).expect("view_context");
        let suppressions = ws.active_suppressions().expect("suppressions");
        mneme_memory::View::with_retention(
            snapshot,
            ws.root(),
            context.history,
            context.revision_sequences,
            suppressions,
        )
        .with_access(mneme_memory::Access::Operator)
    };
    let view_a = view_at_rev(&workspace, rev_a);
    let view_b = view_at_rev(&workspace, rev_b);
    let view_c = view_at_rev(&workspace, rev_c);

    let diff_ab = mneme_memory::View::bitemporal_diff(&view_a, &view_b, window).expect("diff ab");
    assert_eq!(diff_ab.world_evolutions().count(), 2);
    assert_eq!(diff_ab.retroactive_corrections().count(), 0);

    let diff_bc = mneme_memory::View::bitemporal_diff(&view_b, &view_c, window).expect("diff bc");
    assert_eq!(diff_bc.world_evolutions().count(), 0);
    assert_eq!(diff_bc.retroactive_corrections().count(), 2);

    // A window completely outside all valid times returns 0 changes.
    let disjoint_window = mneme_kernel::temporal::Period {
        start: 0,
        stop: 500,
    };
    let diff_empty =
        mneme_memory::View::bitemporal_diff(&view_a, &view_c, disjoint_window).expect("empty");
    assert!(diff_empty.changes.is_empty());
}
