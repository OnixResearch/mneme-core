//! Criterion micro-benchmarks for `mneme-datalog` Free Join cyclic queries
//! (triangle, 4-clique, and 5-atom paper/concept bridge queries).

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
)] // benchmark harness sets up synthetic graphs, uses criterion macros, and asserts via expect
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
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "bench-freejoin").expect("scope")
}

fn node_id(tag: u8, idx: u16) -> mneme_core::RecordId {
    let mut raw = [0_u8; 16];
    raw[0] = tag;
    raw[1..3].copy_from_slice(&idx.to_be_bytes());
    mneme_core::RecordId::from_bytes(raw)
}

fn node_rev(tag: u8, idx: u16) -> mneme_core::RevisionId {
    let mut raw = [0_u8; 16];
    raw[0] = tag;
    raw[1..3].copy_from_slice(&idx.to_be_bytes());
    mneme_core::RevisionId::from_bytes(raw)
}

fn entity_payload(kind: &str, label: &str) -> mneme_core::Payload {
    mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("entity-type"),
            mneme_core::Value::symbol(kind),
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

fn build_cyclic_workspace() -> (
    tempfile::TempDir,
    mneme_store::Workspace,
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

    let mut records = Vec::new();
    let mut edge_idx: u16 = 0;

    // 24 nodes arranged in 6 disjoint 4-cliques plus cross-links and paper/concept bridges.
    for i in 0..24_u16 {
        let kind = if i % 2 == 0 { "paper" } else { "concept" };
        records.push(mneme_store::RecordDraft {
            schema_version: 1,
            kind: mneme_core::RecordKind::Entity,
            record_id: node_id(0x10, i),
            revision_id: node_rev(0x10, i),
            predecessor: None,
            scope: bench_scope(),
            payload: entity_payload(kind, &format!("Node {i}")),
        });
    }
    for clique in 0..6_u16 {
        let base = clique * 4;
        for a in 0..4_u16 {
            for b in (a + 1)..4_u16 {
                edge_idx += 1;
                records.push(mneme_store::RecordDraft {
                    schema_version: 1,
                    kind: mneme_core::RecordKind::Relation,
                    record_id: node_id(0x20, edge_idx),
                    revision_id: node_rev(0x20, edge_idx),
                    predecessor: None,
                    scope: bench_scope(),
                    payload: relation_payload(
                        "edge",
                        node_id(0x10, base + a),
                        node_id(0x10, base + b),
                    ),
                });
            }
        }
    }
    for i in (0..24_u16).step_by(2) {
        edge_idx += 1;
        records.push(mneme_store::RecordDraft {
            schema_version: 1,
            kind: mneme_core::RecordKind::Relation,
            record_id: node_id(0x20, edge_idx),
            revision_id: node_rev(0x20, edge_idx),
            predecessor: None,
            scope: bench_scope(),
            payload: relation_payload("bridges", node_id(0x10, i), node_id(0x10, i + 1)),
        });
    }

    let rev = ws
        .commit(mneme_store::CommitCommand {
            base: genesis,
            actor: "bench".to_owned(),
            scope: bench_scope(),
            idempotency_key: "seed-cyclic".to_owned(),
            records,
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit cyclic graph")
        .revision;

    (dir, ws, rev)
}

fn bundle_with_rules(id: &str, rules: Vec<mneme_datalog::Rule>) -> mneme_datalog::RuleBundle {
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
        id: id.to_owned(),
        version: "1".to_owned(),
        schema_version: 1,
        base_predicates,
        complete_predicates,
        rules,
    })
}

fn edge_lit(u: &str, v: &str) -> mneme_datalog::Literal {
    mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
        "relation",
        vec![
            mneme_datalog::Term::constant(mneme_core::Value::symbol("edge")),
            mneme_datalog::Term::var(u),
            mneme_datalog::Term::var(v),
        ],
    ))
}

fn triangle_bundle() -> mneme_datalog::RuleBundle {
    bundle_with_rules(
        "bench-triangle",
        vec![mneme_datalog::Rule::new(
            "triangle",
            mneme_datalog::Atom::new(
                "tri",
                vec![
                    mneme_datalog::Term::var("X"),
                    mneme_datalog::Term::var("Y"),
                    mneme_datalog::Term::var("Z"),
                ],
            ),
            vec![edge_lit("X", "Y"), edge_lit("Y", "Z"), edge_lit("X", "Z")],
        )],
    )
}

fn four_clique_bundle() -> mneme_datalog::RuleBundle {
    bundle_with_rules(
        "bench-4clique",
        vec![mneme_datalog::Rule::new(
            "four_clique",
            mneme_datalog::Atom::new(
                "k4",
                vec![
                    mneme_datalog::Term::var("A"),
                    mneme_datalog::Term::var("B"),
                    mneme_datalog::Term::var("C"),
                    mneme_datalog::Term::var("D"),
                ],
            ),
            vec![
                edge_lit("A", "B"),
                edge_lit("A", "C"),
                edge_lit("A", "D"),
                edge_lit("B", "C"),
                edge_lit("B", "D"),
                edge_lit("C", "D"),
            ],
        )],
    )
}

fn five_atom_bridge_bundle() -> mneme_datalog::RuleBundle {
    bundle_with_rules(
        "bench-5atom-bridge",
        vec![mneme_datalog::Rule::new(
            "bridge_triangle",
            mneme_datalog::Atom::new(
                "bridged_pair",
                vec![
                    mneme_datalog::Term::var("P"),
                    mneme_datalog::Term::var("C"),
                    mneme_datalog::Term::var("N"),
                ],
            ),
            vec![
                mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                    "entity",
                    vec![
                        mneme_datalog::Term::var("P"),
                        mneme_datalog::Term::constant(mneme_core::Value::symbol("paper")),
                        mneme_datalog::Term::var("PL"),
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
                mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                    "relation",
                    vec![
                        mneme_datalog::Term::constant(mneme_core::Value::symbol("bridges")),
                        mneme_datalog::Term::var("P"),
                        mneme_datalog::Term::var("C"),
                    ],
                )),
                edge_lit("P", "N"),
                edge_lit("C", "N"),
            ],
        )],
    )
}

fn bench_freejoin(c: &mut Criterion) {
    let (_dir, mut ws, rev) = build_cyclic_workspace();

    let mut group = c.benchmark_group("freejoin_cyclic");
    for (name, bundle, pred) in [
        ("triangle", triangle_bundle(), "tri"),
        ("4_clique", four_clique_bundle(), "k4"),
        ("5_atom_bridge", five_atom_bridge_bundle(), "bridged_pair"),
    ] {
        group.bench_function(name, |b| {
            b.iter(|| {
                let mut svc = mneme_datalog::Service::new(&mut ws);
                let build = svc
                    .build(mneme_datalog::BuildRequest {
                        actor: "bench".to_owned(),
                        scope: bench_scope(),
                        revision: rev,
                        bundle: bundle.clone(),
                        limits: mneme_datalog::Limits::default(),
                        publish: false,
                        incomplete_extents: BTreeSet::new(),
                        cancellation: None,
                        access: mneme_memory::Access::scopes([bench_scope()]),
                        at: None,
                    })
                    .expect("build");
                let res = svc
                    .query_build(&build, mneme_datalog::Query::all(pred, 500))
                    .expect("query");
                black_box(res.rows.len())
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_freejoin);
criterion_main!(benches);
