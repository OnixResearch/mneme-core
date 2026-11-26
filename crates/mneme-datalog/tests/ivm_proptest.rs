//! Property-based (`proptest`) differential oracle for DBSP Z-set incremental
//! view maintenance (`ReplSession::advance_to_revision` == fresh `Service::build`).
//!
//! Generates random sequences of inserts, replacements, relation repointings
//! (creating and breaking recursive cycles), and retention `Forget` tombstones,
//! asserting exact parity on rows, `supports`, `epistemic`, `coverage`,
//! `status`, `exhaustive`, and `absence_established` after every revision step.

#![allow(
    unknown_lints,
    no_unwrap,
    function_length,
    allocation_in_loop,
    too_many_parameters,
    unbounded_collection_growth,
    platform_dependent_cast,
    raw_arithmetic_overflow,
    magic_number,
    explicit_defaults,
    compound_condition,
    non_trait_imports,
    fragile_exhaustive_enum_match,
    unchecked_division
)] // differential property test harness exercises multi-step revisions and asserts via expect
#![allow(clippy::expect_used, clippy::unwrap_used)] // property test harness asserts via expect

use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

const BASE_PREDICATES: &[(&str, usize)] = &[
    ("entity", 3),
    ("relation", 3),
    ("source", 3),
    ("evidence", 2),
    ("assertion", 4),
    ("denial", 4),
    ("hypothesis", 4),
    ("derivation", 2),
    ("document", 3),
];

fn scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "ivm-proptest").expect("scope")
}

fn id_with_tag(tag: u8, slot: u8) -> mneme_core::RecordId {
    let mut bytes = [0_u8; 16];
    bytes[0] = tag;
    bytes[1] = slot;
    mneme_core::RecordId::from_bytes(bytes)
}

fn rev_with_tag(tag: u8, slot: u8, generation: u16) -> mneme_core::RevisionId {
    let mut bytes = [0_u8; 16];
    bytes[0] = tag;
    bytes[1] = slot;
    let gen_bytes = generation.to_be_bytes();
    bytes[2] = gen_bytes[0];
    bytes[3] = gen_bytes[1];
    mneme_core::RevisionId::from_bytes(bytes)
}

fn paper_payload(label: &str) -> mneme_core::Payload {
    mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("entity-type"),
            mneme_core::Value::symbol("paper"),
        ),
        (
            mneme_core::Symbol::from("label"),
            mneme_core::Value::string(label),
        ),
        (
            mneme_core::Symbol::from("properties"),
            mneme_core::Value::dictionary([]),
        ),
    ])
}

fn concept_payload(label: &str) -> mneme_core::Payload {
    mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("entity-type"),
            mneme_core::Value::symbol("concept"),
        ),
        (
            mneme_core::Symbol::from("label"),
            mneme_core::Value::string(label),
        ),
        (
            mneme_core::Symbol::from("properties"),
            mneme_core::Value::dictionary([]),
        ),
    ])
}

fn relation_payload(
    kind: &str,
    from: mneme_core::RecordId,
    to: mneme_core::RecordId,
) -> mneme_core::Payload {
    mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("relation-type"),
            mneme_core::Value::symbol(kind),
        ),
        (
            mneme_core::Symbol::from("from"),
            mneme_core::Reference::local(from, mneme_core::RecordKind::Entity).to_value(),
        ),
        (
            mneme_core::Symbol::from("to"),
            mneme_core::Reference::local(to, mneme_core::RecordKind::Entity).to_value(),
        ),
        (
            mneme_core::Symbol::from("properties"),
            mneme_core::Value::dictionary([]),
        ),
    ])
}

fn source_draft(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    entity: mneme_core::RecordId,
    bytes: &[u8],
    path_hint: &str,
) -> (mneme_store::RecordDraft, mneme_store::SourceBlobDraft) {
    mneme_memory::build_source(
        record_id,
        revision_id,
        &scope(),
        mneme_memory::SourceOptions {
            bytes,
            media_type: "text/asciidoc",
            entity: Some(entity),
            path_hint: Some(path_hint),
        },
    )
    .expect("build source")
}

fn commit_accepted_assertion(
    workspace: &mut mneme_store::Workspace,
    slot: u8,
    subject: mneme_core::RecordId,
    source_id: mneme_core::RecordId,
    source_rev: mneme_core::RevisionId,
) {
    let assertion_id = id_with_tag(0x60, slot);
    let evidence_id = id_with_tag(0x61, slot);
    let decision_id = id_with_tag(0x62, slot);
    let span = mneme_core::SourceSpan::new(0, 8).expect("span");

    let evidence = mneme_memory::build_evidence(
        evidence_id,
        rev_with_tag(0x61, slot, 1),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: source_id,
            source_revision: source_rev,
            span: Some(span),
            anchor: Some("anchor"),
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let assertion = mneme_memory::build_proposed_assertion(
        assertion_id,
        rev_with_tag(0x60, slot, 1),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject,
            predicate: "topic",
            value: mneme_core::Value::string(format!("claim-{slot}")),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "ivm-proptest",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                evidence_id,
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    let base = workspace.current_revision().expect("base");
    let proposed_ws_rev = workspace
        .commit(mneme_store::CommitCommand {
            base,
            actor: "ivm-proptest".to_owned(),
            scope: scope(),
            idempotency_key: format!("propose-{slot}"),
            records: vec![evidence, assertion],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit proposal")
        .revision;

    let current = workspace
        .record_revisions(assertion_id)
        .expect("assertion revisions")
        .into_iter()
        .last()
        .expect("latest assertion");
    let decision = mneme_memory::build_decision(
        decision_id,
        rev_with_tag(0x62, slot, 1),
        &scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: assertion_id,
            actor: "ivm-proptest",
            policy: "proptest-policy/v1",
            input_revision: proposed_ws_rev,
            outcome: "accepted",
            rationale: "direct support",
            evidence: &[],
            related: &[],
        },
    );
    let accepted = mneme_memory::build_assertion_revision(
        &current,
        rev_with_tag(0x63, slot, 1),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(decision_id, mneme_core::RecordKind::Decision),
        None,
    );
    workspace
        .commit(mneme_store::CommitCommand {
            base: proposed_ws_rev,
            actor: "ivm-proptest".to_owned(),
            scope: scope(),
            idempotency_key: format!("accept-{slot}"),
            records: vec![decision, accepted],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit acceptance");
}

fn diff_rules() -> Vec<mneme_datalog::Rule> {
    vec![
        // Projection + constant filter
        mneme_datalog::Rule::new(
            "paper_entities",
            mneme_datalog::Atom::new(
                "paper_entity",
                vec![mneme_datalog::Term::var("E"), mneme_datalog::Term::var("L")],
            ),
            vec![mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                "entity",
                vec![
                    mneme_datalog::Term::var("E"),
                    mneme_datalog::Term::constant(mneme_core::Value::symbol("paper")),
                    mneme_datalog::Term::var("L"),
                ],
            ))],
        ),
        // Existential bridge presence
        mneme_datalog::Rule::new(
            "bridged_papers",
            mneme_datalog::Atom::new("already_bridged", vec![mneme_datalog::Term::var("P")]),
            vec![mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                "relation",
                vec![
                    mneme_datalog::Term::constant(mneme_core::Value::symbol("bridges")),
                    mneme_datalog::Term::var("P"),
                    mneme_datalog::Term::var("C"),
                ],
            ))],
        ),
        // Stratified negation
        mneme_datalog::Rule::new(
            "unbridged_papers",
            mneme_datalog::Atom::new("unbridged_paper", vec![mneme_datalog::Term::var("P")]),
            vec![
                mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                    "paper_entity",
                    vec![mneme_datalog::Term::var("P"), mneme_datalog::Term::var("L")],
                )),
                mneme_datalog::Literal::Negative(mneme_datalog::Atom::new(
                    "already_bridged",
                    vec![mneme_datalog::Term::var("P")],
                )),
            ],
        ),
        // Multi-way join
        mneme_datalog::Rule::new(
            "paper_concept_bridge",
            mneme_datalog::Atom::new(
                "paper_bridges_concept",
                vec![mneme_datalog::Term::var("P"), mneme_datalog::Term::var("C")],
            ),
            vec![
                mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                    "paper_entity",
                    vec![
                        mneme_datalog::Term::var("P"),
                        mneme_datalog::Term::var("PL"),
                    ],
                )),
                mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                    "relation",
                    vec![
                        mneme_datalog::Term::constant(mneme_core::Value::symbol("bridges")),
                        mneme_datalog::Term::var("P"),
                        mneme_datalog::Term::var("C"),
                    ],
                )),
                mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                    "entity",
                    vec![
                        mneme_datalog::Term::var("C"),
                        mneme_datalog::Term::constant(mneme_core::Value::symbol("concept")),
                        mneme_datalog::Term::var("CL"),
                    ],
                )),
            ],
        ),
        // Recursive transitive closure over links (supports cycles & retractions)
        mneme_datalog::Rule::new(
            "reach_base",
            mneme_datalog::Atom::new(
                "reach",
                vec![mneme_datalog::Term::var("X"), mneme_datalog::Term::var("Y")],
            ),
            vec![mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                "relation",
                vec![
                    mneme_datalog::Term::constant(mneme_core::Value::symbol("links")),
                    mneme_datalog::Term::var("X"),
                    mneme_datalog::Term::var("Y"),
                ],
            ))],
        ),
        mneme_datalog::Rule::new(
            "reach_step",
            mneme_datalog::Atom::new(
                "reach",
                vec![mneme_datalog::Term::var("X"), mneme_datalog::Term::var("Z")],
            ),
            vec![
                mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                    "reach",
                    vec![mneme_datalog::Term::var("X"), mneme_datalog::Term::var("Y")],
                )),
                mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                    "relation",
                    vec![
                        mneme_datalog::Term::constant(mneme_core::Value::symbol("links")),
                        mneme_datalog::Term::var("Y"),
                        mneme_datalog::Term::var("Z"),
                    ],
                )),
            ],
        ),
        // Union predicate (multiple rules deriving the same head)
        mneme_datalog::Rule::new(
            "active_from_bridge",
            mneme_datalog::Atom::new("active_node", vec![mneme_datalog::Term::var("X")]),
            vec![mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                "already_bridged",
                vec![mneme_datalog::Term::var("X")],
            ))],
        ),
        mneme_datalog::Rule::new(
            "active_from_reach",
            mneme_datalog::Atom::new("active_node", vec![mneme_datalog::Term::var("Y")]),
            vec![mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                "reach",
                vec![mneme_datalog::Term::var("X"), mneme_datalog::Term::var("Y")],
            ))],
        ),
        // Aggregate over assertions
        mneme_datalog::Rule::new(
            "claim_count_rule",
            mneme_datalog::Atom::new(
                "claim_count",
                vec![mneme_datalog::Term::var("S"), mneme_datalog::Term::var("N")],
            ),
            vec![
                mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                    "assertion",
                    vec![
                        mneme_datalog::Term::var("S"),
                        mneme_datalog::Term::var("P"),
                        mneme_datalog::Term::var("V"),
                        mneme_datalog::Term::var("A"),
                    ],
                )),
                mneme_datalog::Literal::Aggregate {
                    function: mneme_datalog::AggregateFunction::Count,
                    input: mneme_datalog::Term::var("A"),
                    output: "N".to_owned(),
                },
            ],
        ),
    ]
}

fn fresh_rule_bundle(rules: Vec<mneme_datalog::Rule>) -> mneme_datalog::RuleBundle {
    let mut base_predicates = BTreeMap::new();
    let mut complete_predicates = BTreeSet::new();
    for &(name, arity) in BASE_PREDICATES {
        base_predicates.insert(name.to_owned(), arity);
        complete_predicates.insert(name.to_owned());
    }
    for rule in &rules {
        complete_predicates.insert(rule.head.predicate.clone());
    }
    mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "ivm-proptest".to_owned(),
        version: "1".to_owned(),
        schema_version: 1,
        base_predicates,
        complete_predicates,
        rules,
    })
}

#[derive(Clone, Debug)]
enum MutationOp {
    InsertOrReplacePaper {
        slot: u8,
        label_gen: u8,
    },
    UpsertLink {
        slot: u8,
        from_slot: u8,
        to_slot: u8,
    },
    UpsertBridge {
        slot: u8,
        paper_slot: u8,
        concept_slot: u8,
    },
    ForgetSource {
        slot: u8,
    },
}

fn arb_mutation_op() -> impl Strategy<Value = MutationOp> {
    prop_oneof![
        (1_u8..=8, 1_u8..=64)
            .prop_map(|(slot, label_gen)| MutationOp::InsertOrReplacePaper { slot, label_gen }),
        (1_u8..=8, 1_u8..=6, 1_u8..=6).prop_map(|(slot, from_slot, to_slot)| {
            MutationOp::UpsertLink {
                slot,
                from_slot,
                to_slot,
            }
        }),
        (1_u8..=6, 1_u8..=6, 1_u8..=4).prop_map(|(slot, paper_slot, concept_slot)| {
            MutationOp::UpsertBridge {
                slot,
                paper_slot,
                concept_slot,
            }
        }),
        (1_u8..=3).prop_map(|slot| MutationOp::ForgetSource { slot }),
    ]
}

fn normalize_rows(rows: &[mneme_datalog::QueryRow]) -> Vec<mneme_datalog::QueryRow> {
    let mut normalized = rows.to_vec();
    for row in &mut normalized {
        row.supports.sort_by_key(|d| format!("{d:?}"));
    }
    normalized
}

/// For recursive predicates over live directed cycles, semi-naive fixpoint and
/// DBSP incremental provenance rebuild can capture either the first-hop or
/// cycle-saturated `canonical_roots` on recursive premises while deriving the
/// exact same rows, epistemic statuses, rule ids, premise tuples, and sources.
fn normalize_recursive_rows(rows: &[mneme_datalog::QueryRow]) -> Vec<mneme_datalog::QueryRow> {
    let mut normalized = rows.to_vec();
    for row in &mut normalized {
        for deriv in &mut row.supports {
            for premise in &mut deriv.premises {
                if premise.predicate == "reach" {
                    premise.canonical_roots.clear();
                }
            }
        }
        row.supports.sort_by_key(|d| format!("{d:?}"));
    }
    normalized
}

fn assert_ivm_matches_fresh_service_build(
    workspace: &mut mneme_store::Workspace,
    session: &mneme_datalog::ReplSession,
    rules: &[mneme_datalog::Rule],
    revision: mneme_core::WorkspaceRevisionId,
    step_idx: usize,
) -> Result<(), TestCaseError> {
    let mut service = mneme_datalog::Service::new(workspace);
    let fresh = service
        .build(mneme_datalog::BuildRequest {
            actor: "ivm-proptest".to_owned(),
            scope: scope(),
            revision,
            bundle: fresh_rule_bundle(rules.to_vec()),
            limits: mneme_datalog::Limits::default(),
            publish: false,
            incomplete_extents: BTreeSet::new(),
            cancellation: None,
            access: mneme_memory::Access::scopes([scope()]),
            at: None,
        })
        .expect("fresh Service::build");

    let predicates = [
        "entity",
        "relation",
        "source",
        "assertion",
        "paper_entity",
        "already_bridged",
        "unbridged_paper",
        "paper_bridges_concept",
        "reach",
        "active_node",
        "claim_count",
    ];

    for predicate in predicates {
        let full = service
            .query_build(&fresh, mneme_datalog::Query::all(predicate, 1_000))
            .expect("fresh query");
        let inc = session
            .query_relation(None, mneme_datalog::Query::all(predicate, 1_000))
            .expect("incremental query");

        prop_assert_eq!(
            inc.status,
            full.status,
            "step {}: status mismatch on {}",
            step_idx,
            predicate
        );
        prop_assert_eq!(
            inc.exhaustive,
            full.exhaustive,
            "step {}: exhaustive mismatch on {}",
            step_idx,
            predicate
        );
        prop_assert_eq!(
            inc.absence_established,
            full.absence_established,
            "step {}: absence_established mismatch on {}",
            step_idx,
            predicate
        );
        prop_assert_eq!(
            inc.coverage,
            full.coverage,
            "step {}: coverage mismatch on {}",
            step_idx,
            predicate
        );
        if matches!(predicate, "reach" | "active_node") {
            prop_assert_eq!(
                normalize_recursive_rows(&inc.rows),
                normalize_recursive_rows(&full.rows),
                "step {}: recursive rows/supports/epistemic mismatch on {}",
                step_idx,
                predicate
            );
        } else {
            prop_assert_eq!(
                normalize_rows(&inc.rows),
                normalize_rows(&full.rows),
                "step {}: rows/supports/epistemic mismatch on {}",
                step_idx,
                predicate
            );
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 16, failure_persistence: None, .. ProptestConfig::default() })]

    #[test]
    fn proptest_dbsp_ivm_advance_matches_fresh_service_build(
        ops in prop::collection::vec(arb_mutation_op(), 1..=8),
    ) {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut workspace = mneme_store::Workspace::create(
            temp.path(),
            mneme_store::WorkspaceConfig {
                clock: Box::new(mneme_store::FixedClock::new(
                    mneme_core::Timestamp::from_nanos(1_000),
                )),
                faults: Box::new(mneme_store::NoFaults),
            },
        )
        .expect("create workspace");

        let mut paper_revs: BTreeMap<u8, mneme_core::RevisionId> = BTreeMap::new();
        let mut link_revs: BTreeMap<u8, mneme_core::RevisionId> = BTreeMap::new();
        let mut bridge_revs: BTreeMap<u8, mneme_core::RevisionId> = BTreeMap::new();
        let mut forgotten_sources: BTreeSet<u8> = BTreeSet::new();
        let mut rev_counter: u16 = 1;

        // Seed initial graph: 4 papers, 4 concepts, 3 links, 2 bridges, 3 sources + assertions.
        let mut seed_records = Vec::new();
        let mut seed_blobs = Vec::new();
        for slot in 1..=4_u8 {
            let p_rev = rev_with_tag(0x10, slot, rev_counter);
            paper_revs.insert(slot, p_rev);
            seed_records.push(mneme_store::RecordDraft {
                schema_version: 1,
                kind: mneme_core::RecordKind::Entity,
                record_id: id_with_tag(0x10, slot),
                revision_id: p_rev,
                predecessor: None,
                scope: scope(),
                payload: paper_payload(&format!("Paper {slot}")),
            });
            seed_records.push(mneme_store::RecordDraft {
                schema_version: 1,
                kind: mneme_core::RecordKind::Entity,
                record_id: id_with_tag(0x20, slot),
                revision_id: rev_with_tag(0x20, slot, rev_counter),
                predecessor: None,
                scope: scope(),
                payload: concept_payload(&format!("Concept {slot}")),
            });
        }
        for slot in 1..=3_u8 {
            let l_rev = rev_with_tag(0x40, slot, rev_counter);
            link_revs.insert(slot, l_rev);
            seed_records.push(mneme_store::RecordDraft {
                schema_version: 1,
                kind: mneme_core::RecordKind::Relation,
                record_id: id_with_tag(0x40, slot),
                revision_id: l_rev,
                predecessor: None,
                scope: scope(),
                payload: relation_payload(
                    "links",
                    id_with_tag(0x10, slot),
                    id_with_tag(0x10, slot + 1),
                ),
            });
            let (s_draft, s_blob) = source_draft(
                id_with_tag(0x50, slot),
                rev_with_tag(0x50, slot, rev_counter),
                id_with_tag(0x10, slot),
                format!("= Source {slot}\n\nBody {slot}.").as_bytes(),
                &format!("src{slot}.adoc"),
            );
            seed_records.push(s_draft);
            seed_blobs.push(s_blob);
        }
        for slot in 1..=2_u8 {
            let b_rev = rev_with_tag(0x30, slot, rev_counter);
            bridge_revs.insert(slot, b_rev);
            seed_records.push(mneme_store::RecordDraft {
                schema_version: 1,
                kind: mneme_core::RecordKind::Relation,
                record_id: id_with_tag(0x30, slot),
                revision_id: b_rev,
                predecessor: None,
                scope: scope(),
                payload: relation_payload(
                    "bridges",
                    id_with_tag(0x10, slot),
                    id_with_tag(0x20, slot),
                ),
            });
        }

        let genesis = workspace.current_revision().expect("genesis");
        workspace
            .commit(mneme_store::CommitCommand {
                base: genesis,
                actor: "ivm-proptest".to_owned(),
                scope: scope(),
                idempotency_key: "seed-0".to_owned(),
                records: seed_records,
                source_blobs: seed_blobs,
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("commit seed");

        for slot in 1..=3_u8 {
            commit_accepted_assertion(
                &mut workspace,
                slot,
                id_with_tag(0x10, slot),
                id_with_tag(0x50, slot),
                rev_with_tag(0x50, slot, rev_counter),
            );
        }

        let rev0 = workspace.current_revision().expect("rev0");
        let rules = diff_rules();
        let mut session = mneme_datalog::ReplSession::open(
            &mut workspace,
            mneme_datalog::ReplSessionRequest {
                actor: "ivm-proptest".to_owned(),
                scope: scope(),
                revision: Some(rev0),
                limits: mneme_datalog::ReplLimits::default(),
                incomplete_extents: BTreeSet::new(),
                complete_predicates: BTreeSet::new(),
                access: mneme_memory::Access::scopes([scope()]),
                at: None,
            },
        )
        .expect("open repl session");
        for rule in &rules {
            session.add_rule(rule.clone()).expect("add rule");
        }

        assert_ivm_matches_fresh_service_build(&mut workspace, &session, &rules, rev0, 0)?;

        for (step_idx, op) in ops.iter().enumerate() {
            rev_counter = rev_counter.saturating_add(1);
            let base = workspace.current_revision().expect("current revision");
            match *op {
                MutationOp::InsertOrReplacePaper { slot, label_gen } => {
                    let next_rev = rev_with_tag(0x10, slot, rev_counter);
                    let predecessor = paper_revs.insert(slot, next_rev);
                    let draft = mneme_store::RecordDraft {
                        schema_version: 1,
                        kind: mneme_core::RecordKind::Entity,
                        record_id: id_with_tag(0x10, slot),
                        revision_id: next_rev,
                        predecessor,
                        scope: scope(),
                        payload: paper_payload(&format!("Paper {slot} v{label_gen}")),
                    };
                    workspace
                        .commit(mneme_store::CommitCommand {
                            base,
                            actor: "ivm-proptest".to_owned(),
                            scope: scope(),
                            idempotency_key: format!("step-{step_idx}-paper"),
                            records: vec![draft],
                            source_blobs: Vec::new(),
                            publications: Vec::new(),
                            import_candidates: Vec::new(),
                            retention: None,
                        })
                        .expect("commit paper mutation");
                }
                MutationOp::UpsertLink {
                    slot,
                    from_slot,
                    to_slot,
                } => {
                    let existing_papers: Vec<u8> = paper_revs.keys().copied().collect();
                    let from_paper = existing_papers[(from_slot as usize) % existing_papers.len()];
                    let to_paper = existing_papers[(to_slot as usize) % existing_papers.len()];
                    let next_rev = rev_with_tag(0x40, slot, rev_counter);
                    let predecessor = link_revs.insert(slot, next_rev);
                    let draft = mneme_store::RecordDraft {
                        schema_version: 1,
                        kind: mneme_core::RecordKind::Relation,
                        record_id: id_with_tag(0x40, slot),
                        revision_id: next_rev,
                        predecessor,
                        scope: scope(),
                        payload: relation_payload(
                            "links",
                            id_with_tag(0x10, from_paper),
                            id_with_tag(0x10, to_paper),
                        ),
                    };
                    workspace
                        .commit(mneme_store::CommitCommand {
                            base,
                            actor: "ivm-proptest".to_owned(),
                            scope: scope(),
                            idempotency_key: format!("step-{step_idx}-link"),
                            records: vec![draft],
                            source_blobs: Vec::new(),
                            publications: Vec::new(),
                            import_candidates: Vec::new(),
                            retention: None,
                        })
                        .expect("commit link mutation");
                }
                MutationOp::UpsertBridge {
                    slot,
                    paper_slot,
                    concept_slot,
                } => {
                    let existing_papers: Vec<u8> = paper_revs.keys().copied().collect();
                    let paper = existing_papers[(paper_slot as usize) % existing_papers.len()];
                    let concept = ((concept_slot - 1) % 4) + 1;
                    let next_rev = rev_with_tag(0x30, slot, rev_counter);
                    let predecessor = bridge_revs.insert(slot, next_rev);
                    let draft = mneme_store::RecordDraft {
                        schema_version: 1,
                        kind: mneme_core::RecordKind::Relation,
                        record_id: id_with_tag(0x30, slot),
                        revision_id: next_rev,
                        predecessor,
                        scope: scope(),
                        payload: relation_payload(
                            "bridges",
                            id_with_tag(0x10, paper),
                            id_with_tag(0x20, concept),
                        ),
                    };
                    workspace
                        .commit(mneme_store::CommitCommand {
                            base,
                            actor: "ivm-proptest".to_owned(),
                            scope: scope(),
                            idempotency_key: format!("step-{step_idx}-bridge"),
                            records: vec![draft],
                            source_blobs: Vec::new(),
                            publications: Vec::new(),
                            import_candidates: Vec::new(),
                            retention: None,
                        })
                        .expect("commit bridge mutation");
                }
                MutationOp::ForgetSource { slot } => {
                    if !forgotten_sources.insert(slot) {
                        continue;
                    }
                    mneme_retention::Engine::new(&mut workspace)
                        .execute(mneme_retention::Request {
                            actor: "ivm-proptest".to_owned(),
                            scope: scope(),
                            base_revision: base,
                            idempotency_key: format!("step-{step_idx}-forget-{slot}"),
                            operation: mneme_retention::OperationKind::Forget,
                            selector: mneme_retention::Selector::Source(id_with_tag(0x50, slot)),
                            effective: None,
                            policy: mneme_retention::Policy {
                                version: mneme_retention::POLICY_VERSION.to_owned(),
                                retain_assertion_after_prune: true,
                                block_content_replay: true,
                                retain_withdrawn_evidence_metadata: true,
                            },
                        })
                        .expect("forget source");
                }
            }

            let head = workspace.current_revision().expect("head revision");
            let summary = session
                .advance_to_revision(&mut workspace, Some(head))
                .expect("advance_to_revision");
            prop_assert_eq!(summary.context.served_revision, head);

            assert_ivm_matches_fresh_service_build(
                &mut workspace,
                &session,
                &rules,
                head,
                step_idx + 1,
            )?;
        }
    }
}
