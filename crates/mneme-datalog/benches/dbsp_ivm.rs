//! Criterion micro-benchmark comparing DBSP IVM single-commit delta advance
//! (`ReplSession::advance_to_revision`) against full from-scratch `Service::build`.

#![allow(
    unknown_lints,
    no_unwrap,
    function_length,
    allocation_in_loop,
    unbounded_collection_growth,
    platform_dependent_cast,
    raw_arithmetic_overflow,
    magic_number,
    explicit_defaults,
    non_trait_imports
)] // benchmark harness constructs synthetic workspaces, uses criterion macros, and asserts via expect
#![allow(clippy::expect_used, clippy::unwrap_used)] // benchmark harness asserts via expect

use criterion::{Criterion, black_box, criterion_group, criterion_main};
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

fn bench_scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "bench-ivm").expect("scope")
}

fn id_pair(tag: u8, idx: u16) -> (mneme_core::RecordId, mneme_core::RevisionId) {
    let mut raw = [0_u8; 16];
    raw[0] = tag;
    raw[1..3].copy_from_slice(&idx.to_be_bytes());
    (
        mneme_core::RecordId::from_bytes(raw),
        mneme_core::RevisionId::from_bytes(raw),
    )
}

fn ivm_rules() -> Vec<mneme_datalog::Rule> {
    vec![
        mneme_datalog::Rule::new(
            "paper_entity",
            mneme_datalog::Atom::new(
                "paper",
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
    ]
}

fn ivm_bundle(rules: Vec<mneme_datalog::Rule>) -> mneme_datalog::RuleBundle {
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
        id: "bench-ivm".to_owned(),
        version: "1".to_owned(),
        schema_version: 1,
        base_predicates,
        complete_predicates,
        rules,
    })
}

fn seed_ivm_workspace() -> (
    tempfile::TempDir,
    mneme_store::Workspace,
    mneme_core::WorkspaceRevisionId,
    mneme_core::WorkspaceRevisionId,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ws = mneme_store::Workspace::create(
        dir.path(),
        mneme_store::WorkspaceConfig {
            clock: Box::new(mneme_store::FixedClock::new(
                mneme_core::Timestamp::from_nanos(1_000),
            )),
            faults: Box::new(mneme_store::NoFaults),
        },
    )
    .expect("create workspace");
    let genesis = ws.current_revision().expect("genesis");

    let mut records = Vec::with_capacity(140);
    for idx in 1..=80_u16 {
        let (rid, rev) = id_pair(0x10, idx);
        records.push(mneme_store::RecordDraft {
            schema_version: 1,
            kind: mneme_core::RecordKind::Entity,
            record_id: rid,
            revision_id: rev,
            predecessor: None,
            scope: bench_scope(),
            payload: mneme_core::Payload::new([
                (
                    mneme_core::Symbol::from("entity-type"),
                    mneme_core::Value::symbol("paper"),
                ),
                (
                    mneme_core::Symbol::from("label"),
                    mneme_core::Value::string(format!("Paper {idx}")),
                ),
                (
                    mneme_core::Symbol::from("properties"),
                    mneme_core::Value::dictionary([]),
                ),
            ]),
        });
    }
    // 20 disjoint 4-node chains (60 edges, bounded transitive closure well within default Limits).
    let mut edge_idx: u16 = 0;
    for chain in 0..20_u16 {
        let base = chain * 4 + 1;
        for step in 0..3_u16 {
            edge_idx += 1;
            let (rid, rev) = id_pair(0x20, edge_idx);
            let (from_id, _) = id_pair(0x10, base + step);
            let (to_id, _) = id_pair(0x10, base + step + 1);
            records.push(mneme_store::RecordDraft {
                schema_version: 1,
                kind: mneme_core::RecordKind::Relation,
                record_id: rid,
                revision_id: rev,
                predecessor: None,
                scope: bench_scope(),
                payload: mneme_core::Payload::new([
                    (
                        mneme_core::Symbol::from("relation-type"),
                        mneme_core::Value::symbol("links"),
                    ),
                    (
                        mneme_core::Symbol::from("from"),
                        mneme_core::Reference::local(from_id, mneme_core::RecordKind::Entity)
                            .to_value(),
                    ),
                    (
                        mneme_core::Symbol::from("to"),
                        mneme_core::Reference::local(to_id, mneme_core::RecordKind::Entity)
                            .to_value(),
                    ),
                    (
                        mneme_core::Symbol::from("properties"),
                        mneme_core::Value::dictionary([]),
                    ),
                ]),
            });
        }
    }

    let rev0 = ws
        .commit(mneme_store::CommitCommand {
            base: genesis,
            actor: "bench".to_owned(),
            scope: bench_scope(),
            idempotency_key: "seed-rev0".to_owned(),
            records,
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit rev0")
        .revision;

    let (new_rid, new_rev) = id_pair(0x10, 81);
    let rev1 = ws
        .commit(mneme_store::CommitCommand {
            base: rev0,
            actor: "bench".to_owned(),
            scope: bench_scope(),
            idempotency_key: "delta-rev1".to_owned(),
            records: vec![mneme_store::RecordDraft {
                schema_version: 1,
                kind: mneme_core::RecordKind::Entity,
                record_id: new_rid,
                revision_id: new_rev,
                predecessor: None,
                scope: bench_scope(),
                payload: mneme_core::Payload::new([
                    (
                        mneme_core::Symbol::from("entity-type"),
                        mneme_core::Value::symbol("paper"),
                    ),
                    (
                        mneme_core::Symbol::from("label"),
                        mneme_core::Value::string("Paper 81"),
                    ),
                    (
                        mneme_core::Symbol::from("properties"),
                        mneme_core::Value::dictionary([]),
                    ),
                ]),
            }],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit rev1")
        .revision;

    (dir, ws, rev0, rev1)
}

fn bench_dbsp_ivm(c: &mut Criterion) {
    let (_dir, mut ws, rev0, rev1) = seed_ivm_workspace();
    let rules = ivm_rules();
    let bundle = ivm_bundle(rules.clone());

    let mut group = c.benchmark_group("dbsp_ivm_vs_full_rebuild");
    group.bench_function("ivm_single_commit_advance", |b| {
        b.iter(|| {
            let mut session = mneme_datalog::ReplSession::open(
                &mut ws,
                mneme_datalog::ReplSessionRequest {
                    actor: "bench".to_owned(),
                    scope: bench_scope(),
                    revision: Some(rev0),
                    limits: mneme_datalog::ReplLimits::default(),
                    incomplete_extents: BTreeSet::new(),
                    complete_predicates: BTreeSet::new(),
                    access: mneme_memory::Access::scopes([bench_scope()]),
                    at: None,
                },
            )
            .expect("open session");
            for rule in &rules {
                session.add_rule(rule.clone()).expect("add rule");
            }
            let summary = session
                .advance_to_revision(&mut ws, Some(rev1))
                .expect("advance_to_revision");
            black_box(summary.step_work)
        });
    });

    group.bench_function("full_service_build_rev1", |b| {
        b.iter(|| {
            let mut svc = mneme_datalog::Service::new(&mut ws);
            let build = svc
                .build(mneme_datalog::BuildRequest {
                    actor: "bench".to_owned(),
                    scope: bench_scope(),
                    revision: rev1,
                    bundle: bundle.clone(),
                    limits: mneme_datalog::Limits::default(),
                    publish: false,
                    incomplete_extents: BTreeSet::new(),
                    cancellation: None,
                    access: mneme_memory::Access::scopes([bench_scope()]),
                    at: None,
                })
                .expect("full build");
            black_box(build.work())
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dbsp_ivm);
criterion_main!(benches);
