use super::tests::*;
use super::*;

struct EntityBatchSpec<'a> {
    entity_type: &'a str,
    prefix: &'a str,
    count: usize,
}

fn push_entities(
    facts: &mut Vec<(String, FactKey, mneme_core::RecordId)>,
    next_id: &mut u16,
    spec: EntityBatchSpec<'_>,
) -> Vec<mneme_core::RecordId> {
    assert!(!spec.entity_type.is_empty());
    let mut ids = Vec::with_capacity(spec.count);
    for idx in 0..spec.count {
        let id = rid(*next_id);
        *next_id = next_id.saturating_add(1);
        ids.push(id);
        facts.push((
            "entity".to_owned(),
            vec![
                id.to_value(),
                mneme_core::Value::symbol(spec.entity_type),
                mneme_core::Value::string(format!("{} {idx}", spec.prefix)),
            ],
            id,
        ));
    }
    assert_eq!(ids.len(), spec.count);
    ids
}

struct InClassEdgeBatch<'a> {
    members: &'a [mneme_core::RecordId],
    classes: &'a [mneme_core::RecordId],
}

fn push_in_class_edges(
    facts: &mut Vec<(String, FactKey, mneme_core::RecordId)>,
    next_id: &mut u16,
    batch: InClassEdgeBatch<'_>,
) {
    assert!(!batch.classes.is_empty());
    let before = facts.len();
    for (idx, member) in batch.members.iter().enumerate() {
        for offset in 0..2_usize {
            let class_idx = idx
                .saturating_add(offset)
                .checked_rem(batch.classes.len())
                .expect("non-empty classes");
            let class = batch.classes[class_idx];
            let id = rid(*next_id);
            *next_id = next_id.saturating_add(1);
            facts.push((
                "relation".to_owned(),
                vec![
                    mneme_core::Value::symbol("in_class"),
                    member.to_value(),
                    class.to_value(),
                ],
                id,
            ));
        }
    }
    assert_eq!(
        facts.len(),
        before.saturating_add(batch.members.len().saturating_mul(2))
    );
}

fn five_atom_fixture_facts() -> Vec<(String, FactKey, mneme_core::RecordId)> {
    let mut facts = Vec::with_capacity(194);
    assert!(facts.is_empty());
    let mut next_id = 1_u16;
    let papers = push_entities(
        &mut facts,
        &mut next_id,
        EntityBatchSpec {
            entity_type: "paper",
            prefix: "Paper",
            count: 25,
        },
    );
    let principles = push_entities(
        &mut facts,
        &mut next_id,
        EntityBatchSpec {
            entity_type: "principle",
            prefix: "Principle",
            count: 25,
        },
    );
    let classes = push_entities(
        &mut facts,
        &mut next_id,
        EntityBatchSpec {
            entity_type: "problem_class",
            prefix: "Class",
            count: 10,
        },
    );
    let _notes = push_entities(
        &mut facts,
        &mut next_id,
        EntityBatchSpec {
            entity_type: "note",
            prefix: "Note",
            count: 20,
        },
    );
    // 50 in_class edges for papers, 50 for principles, 14 bridged edges (114 relations; 194 total)
    let edge_batches = [
        InClassEdgeBatch {
            members: &papers,
            classes: &classes,
        },
        InClassEdgeBatch {
            members: &principles,
            classes: &classes,
        },
    ];
    for batch in edge_batches {
        push_in_class_edges(&mut facts, &mut next_id, batch);
    }
    for (paper, principle) in papers.iter().zip(&principles).take(14) {
        let id = rid(next_id);
        next_id = next_id.saturating_add(1);
        facts.push((
            "relation".to_owned(),
            vec![
                mneme_core::Value::symbol("bridged"),
                paper.to_value(),
                principle.to_value(),
            ],
            id,
        ));
    }
    assert_eq!(facts.len(), 194);
    facts
}

#[test]
fn five_atom_bridge_query_and_permutations_match_naive_with_low_work() {
    let base_facts = five_atom_fixture_facts();
    assert_eq!(base_facts.len(), 194);

    let atoms = [
        crate::Literal::Positive(atom(
            "entity",
            vec![var("paper"), sym("paper"), var("p_label")],
        )),
        crate::Literal::Positive(atom(
            "entity",
            vec![var("principle"), sym("principle"), var("pr_label")],
        )),
        crate::Literal::Positive(atom(
            "entity",
            vec![var("class"), sym("problem_class"), var("c_label")],
        )),
        crate::Literal::Positive(atom(
            "relation",
            vec![sym("in_class"), var("paper"), var("class")],
        )),
        crate::Literal::Positive(atom(
            "relation",
            vec![sym("in_class"), var("principle"), var("class")],
        )),
    ];
    let negation = crate::Literal::Negative(atom(
        "relation",
        vec![sym("bridged"), var("paper"), var("principle")],
    ));

    let unfactored = crate::RuleBundle::new(crate::RuleBundleOptions {
        id: "bridge-unfactored".to_owned(),
        version: "1".to_owned(),
        schema_version: 3,
        base_predicates: std::collections::BTreeMap::from([
            ("entity".to_owned(), 3),
            ("relation".to_owned(), 3),
        ]),
        complete_predicates: std::collections::BTreeSet::from(["relation".to_owned()]),
        rules: vec![crate::Rule::new(
            "unbridged_candidate",
            atom(
                "unbridged_candidate",
                vec![var("paper"), var("principle"), var("class")],
            ),
            // Natural 5-atom chained order (avoids intermediate Cartesian row limit,
            // yet still exceeds 100,000 work under naive full-table scans).
            vec![
                atoms[0].clone(),
                atoms[3].clone(),
                atoms[2].clone(),
                atoms[4].clone(),
                atoms[1].clone(),
                negation.clone(),
            ],
        )],
    });

    let default_limits = crate::Limits::default();
    let program = unfactored.validate().expect("valid");
    let context = test_context(&unfactored);
    let sources = AvailabilityMap::new();
    let default_fixture = EvaluationFixture {
        bundle: &unfactored,
        context: &context,
        limits: &default_limits,
        current_sources: &sources,
        base_facts: &base_facts,
    };

    let mut naive_default = make_evaluation(&default_fixture);
    evaluate_rules_naive(&mut naive_default, &program.strata);
    assert_eq!(naive_default.budget.status, crate::ExecutionStatus::Timeout);
    assert!(naive_default.budget.limit_reached);

    let mut planned_default = make_evaluation(&default_fixture);
    evaluate_rules(&mut planned_default, &program.strata);
    assert_eq!(
        planned_default.budget.status,
        crate::ExecutionStatus::Complete
    );
    assert!(!planned_default.budget.limit_reached);
    assert!(
        planned_default.budget.work < 15_000,
        "planned work {} should be well under 100k",
        planned_default.budget.work
    );

    let generous_limits = crate::Limits {
        max_work: 50_000_000,
        max_time_ms: 60_000,
        max_result_rows: 10_000,
        ..default_limits
    };
    let (naive_work, planned_work) =
        assert_equivalent_to_naive(&unfactored, &base_facts, &generous_limits);
    eprintln!("5-atom chained bridge: naive_work={naive_work}, planned_work={planned_work}");
    assert!(naive_work > 100_000);
    assert!(planned_work < 15_000);

    // Permutations of positive atoms + early placement of negation all match
    // the unfactored canonical rows and complete well under default limits.
    let permutations: [[usize; 5]; 6] = [
        [0, 1, 2, 3, 4],
        [4, 3, 2, 1, 0],
        [2, 3, 4, 0, 1],
        [3, 0, 2, 4, 1],
        [1, 4, 2, 3, 0],
        [3, 4, 0, 1, 2],
    ];
    for perm in permutations {
        let body = vec![
            atoms[perm[0]].clone(),
            atoms[perm[1]].clone(),
            negation.clone(),
            atoms[perm[2]].clone(),
            atoms[perm[3]].clone(),
            atoms[perm[4]].clone(),
        ];
        let permuted = crate::RuleBundle::new(crate::RuleBundleOptions {
            id: "bridge-perm".to_owned(),
            version: "1".to_owned(),
            schema_version: 3,
            base_predicates: unfactored.base_predicates.clone(),
            complete_predicates: unfactored.complete_predicates.clone(),
            rules: vec![crate::Rule::new(
                "unbridged_candidate",
                atom(
                    "unbridged_candidate",
                    vec![var("paper"), var("principle"), var("class")],
                ),
                body,
            )],
        });
        let (perm_naive, perm_planned) =
            assert_equivalent_to_naive(&permuted, &base_facts, &generous_limits);
        assert!(
            perm_planned < 15_000,
            "perm {:?} planned_work={}",
            perm,
            perm_planned
        );
        assert!(perm_planned < perm_naive);
    }
}

#[test]
fn equivalence_against_naive_across_cyclic_compare_aggregates_and_truncation() {
    let mut base_facts = Vec::with_capacity(96);
    for idx in 1..=12_u16 {
        let id = rid(idx);
        base_facts.push((
            "node".to_owned(),
            vec![
                mneme_core::Value::integer(i64::from(idx)),
                mneme_core::Value::symbol(if idx % 2 == 0 { "even" } else { "odd" }),
            ],
            id,
        ));
    }
    let mut edge_id = 100_u16;
    for src in 1..=12_i64 {
        for dst in [src % 12 + 1, (src + 1) % 12 + 1, (src + 3) % 12 + 1] {
            edge_id = edge_id.saturating_add(1);
            base_facts.push((
                "edge".to_owned(),
                vec![
                    mneme_core::Value::integer(src),
                    mneme_core::Value::integer(dst),
                ],
                rid(edge_id),
            ));
        }
    }
    // Self-loop edge + blocked pair + multi-proof witness table
    edge_id = edge_id.saturating_add(1);
    base_facts.push((
        "edge".to_owned(),
        vec![mneme_core::Value::integer(1), mneme_core::Value::integer(1)],
        rid(edge_id),
    ));
    base_facts.push((
        "blocked".to_owned(),
        vec![mneme_core::Value::integer(2), mneme_core::Value::integer(3)],
        rid(400),
    ));
    for a in 1..=4_i64 {
        for b in 1..=4_i64 {
            base_facts.push((
                "witness".to_owned(),
                vec![
                    mneme_core::Value::integer(1),
                    mneme_core::Value::integer(a),
                    mneme_core::Value::integer(b),
                ],
                rid(500 + u16::try_from(a * 10 + b).expect("small")),
            ));
        }
    }
    for b in 1..=4_i64 {
        for a in 1..=4_i64 {
            if (a + b) % 2 == 0 {
                base_facts.push((
                    "pair_filter".to_owned(),
                    vec![mneme_core::Value::integer(b), mneme_core::Value::integer(a)],
                    rid(700 + u16::try_from(b * 10 + a).expect("small")),
                ));
            }
        }
    }

    let bundle = crate::RuleBundle::new(crate::RuleBundleOptions {
        id: "equivalence-suite".to_owned(),
        version: "1".to_owned(),
        schema_version: 3,
        base_predicates: std::collections::BTreeMap::from([
            ("node".to_owned(), 2),
            ("edge".to_owned(), 2),
            ("blocked".to_owned(), 2),
            ("witness".to_owned(), 3),
            ("pair_filter".to_owned(), 2),
        ]),
        complete_predicates: std::collections::BTreeSet::from([
            "node".to_owned(),
            "edge".to_owned(),
            "blocked".to_owned(),
            "witness".to_owned(),
            "pair_filter".to_owned(),
        ]),
        rules: vec![
            // Cyclic triangle with stratified negation + Compare pushdown
            crate::Rule::new(
                "triangle",
                atom("triangle", vec![var("a"), var("b"), var("c")]),
                vec![
                    crate::Literal::Positive(atom("edge", vec![var("a"), var("b")])),
                    crate::Literal::Positive(atom("node", vec![var("c"), sym("even")])),
                    crate::Literal::Positive(atom("edge", vec![var("b"), var("c")])),
                    crate::Literal::Positive(atom("edge", vec![var("c"), var("a")])),
                    crate::Literal::Negative(atom("blocked", vec![var("a"), var("b")])),
                    crate::Literal::Compare {
                        op: crate::CompareOp::Lt,
                        left: var("a"),
                        right: var("c"),
                    },
                ],
            ),
            // Self-join with repeated variable in an atom
            crate::Rule::new(
                "self_loop",
                atom("self_loop", vec![var("x")]),
                vec![crate::Literal::Positive(atom(
                    "edge",
                    vec![var("x"), var("x")],
                ))],
            ),
            // Projected-out variables (y, z) where pair_filter has smaller extent than witness
            crate::Rule::new(
                "projected",
                atom("projected", vec![var("x")]),
                vec![
                    crate::Literal::Positive(atom("witness", vec![var("x"), var("y"), var("z")])),
                    crate::Literal::Positive(atom("pair_filter", vec![var("z"), var("y")])),
                ],
            ),
            // Recursive reachability
            crate::Rule::new(
                "reach_base",
                atom("reach", vec![var("x"), var("y")]),
                vec![crate::Literal::Positive(atom(
                    "edge",
                    vec![var("x"), var("y")],
                ))],
            ),
            crate::Rule::new(
                "reach_step",
                atom("reach", vec![var("x"), var("z")]),
                vec![
                    crate::Literal::Positive(atom("reach", vec![var("x"), var("y")])),
                    crate::Literal::Positive(atom("edge", vec![var("y"), var("z")])),
                    crate::Literal::Compare {
                        op: crate::CompareOp::Ne,
                        left: var("x"),
                        right: var("z"),
                    },
                ],
            ),
            // Aggregate over reordered body
            crate::Rule::new(
                "out_sum",
                atom("out_sum", vec![var("a"), var("total")]),
                vec![
                    crate::Literal::Positive(atom("edge", vec![var("a"), var("b")])),
                    crate::Literal::Positive(atom("node", vec![var("b"), sym("odd")])),
                    crate::Literal::Aggregate {
                        function: crate::AggregateFunction::Sum,
                        input: var("b"),
                        output: "total".to_owned(),
                    },
                ],
            ),
            // Ground false comparison short-circuit
            crate::Rule::new(
                "impossible",
                atom("impossible", vec![var("x")]),
                vec![
                    crate::Literal::Positive(atom("node", vec![var("x"), var("k")])),
                    crate::Literal::Compare {
                        op: crate::CompareOp::Gt,
                        left: int_const(1),
                        right: int_const(2),
                    },
                ],
            ),
        ],
    });

    let limits = crate::Limits {
        max_work: 5_000_000,
        max_time_ms: 60_000,
        max_result_rows: 1_000,
        max_supports_per_fact: 2,
        max_recursion_depth: 16,
    };
    let (naive_work, planned_work) = assert_equivalent_to_naive(&bundle, &base_facts, &limits);
    assert!(planned_work < naive_work);
}

#[test]
fn property_equivalence_against_naive_across_seeded_programs() {
    let mut seed = 0x9E37_79B9_7F4A_7C15_u64;
    let mut next_u64 = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };

    let preds = ["p0", "p1", "p2", "p3"];
    let vars = ["a", "b", "c", "d"];

    for case_idx in 0..30_usize {
        let mut base_facts = Vec::with_capacity(60);
        let mut next_rid = 1_u16;
        for (pred_idx, pred) in preds.iter().enumerate() {
            // Deliberately skew extent sizes (some empty, some small, some medium).
            let row_count = match (case_idx + pred_idx) % 4 {
                0 => 0,
                1 => 3,
                2 => 8,
                _ => 18,
            };
            for _ in 0..row_count {
                let v0 = i64::try_from(next_u64() % 5).expect("mod 5");
                let v1 = i64::try_from(next_u64() % 5).expect("mod 5");
                let v2 = i64::try_from(next_u64() % 4).expect("mod 4");
                let id = rid(next_rid);
                next_rid = next_rid.saturating_add(1);
                let row = if pred_idx < 2 {
                    vec![
                        mneme_core::Value::integer(v0),
                        mneme_core::Value::integer(v1),
                    ]
                } else {
                    vec![
                        mneme_core::Value::integer(v0),
                        mneme_core::Value::integer(v1),
                        mneme_core::Value::integer(v2),
                    ]
                };
                base_facts.push(((*pred).to_owned(), row, id));
            }
        }

        let num_pos = 2 + usize::try_from(next_u64() % 3).expect("mod 3");
        let mut body = Vec::with_capacity(num_pos + 2);
        let mut used_vars = Vec::with_capacity(4);
        for pos_idx in 0..num_pos {
            let pred_idx = usize::try_from(next_u64() % 4).expect("mod 4");
            let arity = if pred_idx < 2 { 2 } else { 3 };
            let mut terms = Vec::with_capacity(arity);
            for col in 0..arity {
                let choice = next_u64() % 5;
                if choice == 0 && (pos_idx > 0 || col > 0) {
                    terms.push(int_const(i64::try_from(next_u64() % 4).expect("mod 4")));
                } else {
                    let var_name = if !used_vars.is_empty() && next_u64() % 2 == 0 {
                        let idx = usize::try_from(next_u64())
                            .expect("u64")
                            .checked_rem(used_vars.len())
                            .expect("non-empty used_vars");
                        used_vars[idx]
                    } else {
                        let name = vars[usize::try_from(next_u64() % 4).expect("mod 4")];
                        if !used_vars.contains(&name) {
                            used_vars.push(name);
                        }
                        name
                    };
                    terms.push(var(var_name));
                }
            }
            body.push(crate::Literal::Positive(atom(preds[pred_idx], terms)));
        }
        if let Some(&v0) = used_vars.first() {
            let v1 = *used_vars.get(1).unwrap_or(&v0);
            if next_u64() % 2 == 0 {
                body.push(crate::Literal::Negative(atom("p0", vec![var(v0), var(v1)])));
            }
            if next_u64() % 2 == 0 {
                body.push(crate::Literal::Compare {
                    op: crate::CompareOp::Le,
                    left: var(v0),
                    right: var(v1),
                });
            }
        }
        let head_terms = if used_vars.len() >= 2 {
            vec![var(used_vars[0]), var(used_vars[1])]
        } else if let Some(&v0) = used_vars.first() {
            vec![var(v0)]
        } else {
            vec![int_const(1)]
        };

        let bundle = crate::RuleBundle::new(crate::RuleBundleOptions {
            id: format!("prop-{case_idx}"),
            version: "1".to_owned(),
            schema_version: 3,
            base_predicates: std::collections::BTreeMap::from([
                ("p0".to_owned(), 2),
                ("p1".to_owned(), 2),
                ("p2".to_owned(), 3),
                ("p3".to_owned(), 3),
            ]),
            complete_predicates: std::collections::BTreeSet::from([
                "p0".to_owned(),
                "p1".to_owned(),
                "p2".to_owned(),
                "p3".to_owned(),
            ]),
            rules: vec![crate::Rule::new("out", atom("out", head_terms), body)],
        });

        let limits = crate::Limits {
            max_work: 5_000_000,
            max_time_ms: 60_000,
            max_result_rows: 1_000,
            max_supports_per_fact: 3,
            max_recursion_depth: 16,
        };
        assert_equivalent_to_naive(&bundle, &base_facts, &limits);
    }
}

#[test]
fn greedy_planner_orders_most_bound_and_smallest_extent_with_written_tie_break() {
    let mut facts = std::collections::BTreeMap::new();
    let mut big = FactStore::default();
    for idx in 0..20_i64 {
        big.rows.insert(
            vec![
                mneme_core::Value::integer(idx),
                mneme_core::Value::integer(idx + 1),
            ],
            crate::FactData {
                supports: Vec::new(),
                sources: std::collections::BTreeSet::new(),
                truncated: false,
                canonical: None,
                canonical_roots: std::collections::BTreeSet::new(),
                vaults: std::collections::BTreeSet::new(),
                temporal: Vec::new(),
                epistemic: crate::EpistemicStatus::Accepted,
            },
        );
    }
    let mut small = FactStore::default();
    for idx in 0..3_i64 {
        small.rows.insert(
            vec![
                mneme_core::Value::integer(idx),
                mneme_core::Value::integer(idx + 1),
            ],
            crate::FactData {
                supports: Vec::new(),
                sources: std::collections::BTreeSet::new(),
                truncated: false,
                canonical: None,
                canonical_roots: std::collections::BTreeSet::new(),
                vaults: std::collections::BTreeSet::new(),
                temporal: Vec::new(),
                epistemic: crate::EpistemicStatus::Accepted,
            },
        );
    }
    let mut tie_a = small.clone();
    let mut tie_b = small.clone();
    let _ = (&mut tie_a, &mut tie_b);
    facts.insert("big".to_owned(), big);
    facts.insert("small".to_owned(), small.clone());
    facts.insert("tie_a".to_owned(), small.clone());
    facts.insert("tie_b".to_owned(), small);

    // Smaller extent beats larger extent; ready negative/compare runs before next join.
    let rule = crate::Rule::new(
        "ordered",
        atom("out", vec![var("x"), var("z")]),
        vec![
            crate::Literal::Positive(atom("big", vec![var("y"), var("z")])),
            crate::Literal::Negative(atom("small", vec![var("x"), var("y")])),
            crate::Literal::Compare {
                op: crate::CompareOp::Lt,
                left: var("x"),
                right: var("y"),
            },
            crate::Literal::Positive(atom("small", vec![var("x"), var("y")])),
        ],
    );
    let plan = plan_rule_body(&rule, &facts);
    assert!(plan.positive_reordered);
    let order = plan
        .steps
        .iter()
        .map(|step| {
            if let PlanStep::Positive { body_index, .. } = step {
                *body_index
            } else if let PlanStep::Negative { body_index } = step {
                *body_index
            } else if let PlanStep::Compare { body_index } = step {
                *body_index
            } else {
                unreachable!("unexpected plan step")
            }
        })
        .collect::<Vec<_>>();
    // 3: small(x, y) first -> 2: Compare(x < y) -> 1: Negative(small(x, y)) -> 0: big(y, z)
    assert_eq!(order, vec![3, 2, 1, 0]);

    // Equal extent & equal bound positions tie-break by written order.
    let tie_rule = crate::Rule::new(
        "tie",
        atom("out", vec![var("x"), var("z")]),
        vec![
            crate::Literal::Positive(atom("tie_a", vec![var("x"), var("y")])),
            crate::Literal::Positive(atom("tie_b", vec![var("y"), var("z")])),
        ],
    );
    let tie_plan = plan_rule_body(&tie_rule, &facts);
    assert!(!tie_plan.positive_reordered);
}

#[test]
fn join_only_visits_matching_rows_for_bound_positions() {
    let mut base_facts = Vec::with_capacity(200);
    for idx in 0..100_i64 {
        let id = rid(u16::try_from(idx + 1).expect("small"));
        base_facts.push((
            "left".to_owned(),
            vec![
                mneme_core::Value::integer(idx),
                mneme_core::Value::integer(idx % 5),
            ],
            id,
        ));
        base_facts.push((
            "right".to_owned(),
            vec![
                mneme_core::Value::integer(idx),
                mneme_core::Value::string(format!("v-{idx}")),
            ],
            rid(u16::try_from(idx + 201).expect("small")),
        ));
    }
    let bundle = crate::RuleBundle::new(crate::RuleBundleOptions {
        id: "indexed-probe".to_owned(),
        version: "1".to_owned(),
        schema_version: 3,
        base_predicates: std::collections::BTreeMap::from([
            ("left".to_owned(), 2),
            ("right".to_owned(), 2),
        ]),
        complete_predicates: std::collections::BTreeSet::from([
            "left".to_owned(),
            "right".to_owned(),
        ]),
        rules: vec![crate::Rule::new(
            "joined",
            atom("joined", vec![var("k"), var("s")]),
            vec![
                crate::Literal::Positive(atom("left", vec![var("k"), int_const(0)])),
                crate::Literal::Positive(atom("right", vec![var("k"), var("s")])),
            ],
        )],
    });
    let limits = crate::Limits::default();
    let (naive_work, planned_work) = assert_equivalent_to_naive(&bundle, &base_facts, &limits);
    // Naive scans 100 rows on left + 20 * 100 = 2000 rows on right per round (~4,500 total).
    // Indexed builds indexes once (~200) + probes (~20 * 2 per round) (~700 total including base load).
    eprintln!("indexed-probe: naive_work={naive_work}, planned_work={planned_work}");
    assert!(naive_work > 4_000);
    assert!(planned_work < 800);
}

fn assert_evaluations_match(expected: &Evaluation<'_>, actual: &Evaluation<'_>) {
    assert_eq!(actual.budget.status, expected.budget.status);
    assert_eq!(actual.budget.limit_reached, expected.budget.limit_reached);
    assert_eq!(
        actual.budget.support_truncated,
        expected.budget.support_truncated
    );
    assert_eq!(final_coverage(actual), final_coverage(expected));
    assert_eq!(
        actual.facts.keys().collect::<Vec<_>>(),
        expected.facts.keys().collect::<Vec<_>>()
    );
    for (predicate, expected_store) in &expected.facts {
        let actual_store = actual.facts.get(predicate).expect("matching predicate");
        assert_eq!(actual_store.truncated, expected_store.truncated);
        assert_eq!(
            actual_store.rows.keys().collect::<Vec<_>>(),
            expected_store.rows.keys().collect::<Vec<_>>()
        );
        for (key, expected_data) in &expected_store.rows {
            let actual_data = actual_store.rows.get(key).expect("matching row");
            assert_eq!(actual_data.supports, expected_data.supports);
            assert_eq!(actual_data.sources, expected_data.sources);
            assert_eq!(actual_data.truncated, expected_data.truncated);
            assert_eq!(actual_data.canonical, expected_data.canonical);
            assert_eq!(actual_data.canonical_roots, expected_data.canonical_roots);
            assert_eq!(actual_data.temporal, expected_data.temporal);
        }
    }
}

fn assert_equivalent_to_binary(
    bundle: &crate::RuleBundle,
    base_facts: &[(String, FactKey, mneme_core::RecordId)],
    limits: &crate::Limits,
) -> (u64, u64) {
    assert!(!bundle.rules.is_empty());
    let program = bundle.validate().expect("valid bundle");
    assert!(!program.strata.is_empty());
    let context = test_context(bundle);
    let current_sources = AvailabilityMap::new();
    let fixture = EvaluationFixture {
        bundle,
        context: &context,
        limits,
        current_sources: &current_sources,
        base_facts,
    };
    let mut binary = make_evaluation(&fixture);
    evaluate_rules_binary(&mut binary, &program.strata);

    let mut free_join = make_evaluation(&fixture);
    evaluate_rules(&mut free_join, &program.strata);

    assert_evaluations_match(&binary, &free_join);
    (binary.budget.work, free_join.budget.work)
}

fn assert_equivalent_to_binary_and_naive(
    bundle: &crate::RuleBundle,
    base_facts: &[(String, FactKey, mneme_core::RecordId)],
    limits: &crate::Limits,
) -> (u64, u64, u64) {
    assert!(!bundle.rules.is_empty());
    let program = bundle.validate().expect("valid bundle");
    assert!(!program.strata.is_empty());
    let context = test_context(bundle);
    let current_sources = AvailabilityMap::new();
    let fixture = EvaluationFixture {
        bundle,
        context: &context,
        limits,
        current_sources: &current_sources,
        base_facts,
    };
    let mut naive = make_evaluation(&fixture);
    evaluate_rules_naive(&mut naive, &program.strata);

    let mut binary = make_evaluation(&fixture);
    evaluate_rules_binary(&mut binary, &program.strata);

    let mut free_join = make_evaluation(&fixture);
    evaluate_rules(&mut free_join, &program.strata);

    assert_evaluations_match(&naive, &binary);
    assert_evaluations_match(&naive, &free_join);
    (naive.budget.work, binary.budget.work, free_join.budget.work)
}

#[test]
fn cyclic_triangle_hub_query_completes_under_default_limits_vs_binary_blowup() {
    // Hub node 0 has 120 incoming edges (1..=120 -> 0) and 120 outgoing edges
    // (0 -> 121..=240). Nodes 1..=120 also each have 1 incoming edge from
    // 301..=420 so `edge(c, a)` cannot reject them before `a` is inspected.
    // Plus 5 disjoint triangles on 501..=515 (15 edges) -> 375 edges total.
    let mut base_facts = Vec::new();
    let mut next_id = 1_u16;
    let mut push_edge = |src: i64, dst: i64| {
        let id = rid(next_id);
        next_id = next_id.saturating_add(1);
        base_facts.push((
            "edge".to_owned(),
            vec![
                mneme_core::Value::integer(src),
                mneme_core::Value::integer(dst),
            ],
            id,
        ));
    };
    for idx in 1..=120_i64 {
        push_edge(idx, 0);
        push_edge(0, 120 + idx);
        push_edge(300 + idx, idx);
    }
    for tri in 0..5_i64 {
        let base = 500 + tri * 3;
        push_edge(base, base + 1);
        push_edge(base + 1, base + 2);
        push_edge(base + 2, base);
    }

    assert_eq!(base_facts.len(), 375);

    assert_eq!(base_facts.len(), 375);

    let bundle = crate::RuleBundle::new(crate::RuleBundleOptions {
        id: "cyclic-triangle-hub".to_owned(),
        version: "1".to_owned(),
        schema_version: 3,
        base_predicates: std::collections::BTreeMap::from([("edge".to_owned(), 2)]),
        complete_predicates: std::collections::BTreeSet::from(["edge".to_owned()]),
        rules: vec![crate::Rule::new(
            "triangle",
            atom("triangle", vec![var("a"), var("b"), var("c")]),
            vec![
                crate::Literal::Positive(atom("edge", vec![var("a"), var("b")])),
                crate::Literal::Positive(atom("edge", vec![var("b"), var("c")])),
                crate::Literal::Positive(atom("edge", vec![var("c"), var("a")])),
            ],
        )],
    });

    let default_limits = crate::Limits::default();
    let program = bundle.validate().expect("valid");
    let context = test_context(&bundle);
    let sources = AvailabilityMap::new();
    let fixture = EvaluationFixture {
        bundle: &bundle,
        context: &context,
        limits: &default_limits,
        current_sources: &sources,
        base_facts: &base_facts,
    };

    // Under default limits (`max_result_rows: 1_000`), binary join blows past
    // the intermediate binding limit on `edge(a, b) ⋈ edge(b, c)` (14,400 tuples).
    let mut binary_default = make_evaluation(&fixture);
    evaluate_rules_binary(&mut binary_default, &program.strata);
    assert_eq!(
        binary_default.budget.status,
        crate::ExecutionStatus::Partial
    );
    assert!(binary_default.budget.limit_reached);

    // Free Join completes exhaustively well within default limits.
    let mut free_default = make_evaluation(&fixture);
    evaluate_rules(&mut free_default, &program.strata);
    assert_eq!(free_default.budget.status, crate::ExecutionStatus::Complete);
    assert!(!free_default.budget.limit_reached);
    assert!(!free_default.facts["triangle"].truncated);
    assert_eq!(
        free_default.coverage_status("triangle"),
        crate::CoverageStatus::Complete
    );
    assert_eq!(free_default.facts["triangle"].rows.len(), 15);
    assert!(
        free_default.budget.work < 5_000,
        "free join work {} should be well under 5,000",
        free_default.budget.work
    );

    // Compare full exact work under raised row/work caps.
    let generous_limits = crate::Limits {
        max_work: 5_000_000,
        max_time_ms: 60_000,
        max_result_rows: 50_000,
        ..default_limits
    };
    let (binary_work, free_work) =
        assert_equivalent_to_binary(&bundle, &base_facts, &generous_limits);
    eprintln!(
        "cyclic-triangle-hub (375 edges, 15 triangles): binary={binary_work}, free_join={free_work}"
    );
    assert!(binary_work > 50_000);
    assert!(free_work < 5_000);
}

#[test]
fn cyclic_four_clique_completes_under_default_limits_vs_binary_blowup() {
    // Hub node 0 has 160 outgoing edges (0 -> 1..=160), plus two disjoint
    // directed 4-cliques on 201..=204 and 205..=208 (24 edges) -> 184 edges total.
    // Binary join `edge(a, b) ⋈ edge(a, c)` produces 160*160 = 25,600 intermediate
    // bindings before checking `edge(b, c)`, failing default `max_result_rows` (1,000)
    // and exceeding default `max_work` (100,000) even with raised row caps.
    let mut base_facts = Vec::new();
    let mut next_id = 1_u16;
    let mut push_edge = |src: i64, dst: i64| {
        let id = rid(next_id);
        next_id = next_id.saturating_add(1);
        base_facts.push((
            "edge".to_owned(),
            vec![
                mneme_core::Value::integer(src),
                mneme_core::Value::integer(dst),
            ],
            id,
        ));
    };
    for idx in 1..=160_i64 {
        push_edge(0, idx);
    }
    for base in [201_i64, 205_i64] {
        for i in 0..4_i64 {
            for j in 0..4_i64 {
                if i != j {
                    push_edge(base + i, base + j);
                }
            }
        }
    }

    let bundle = crate::RuleBundle::new(crate::RuleBundleOptions {
        id: "cyclic-k4-hub".to_owned(),
        version: "1".to_owned(),
        schema_version: 3,
        base_predicates: std::collections::BTreeMap::from([("edge".to_owned(), 2)]),
        complete_predicates: std::collections::BTreeSet::from(["edge".to_owned()]),
        rules: vec![crate::Rule::new(
            "k4",
            atom("k4", vec![var("a"), var("b"), var("c"), var("d")]),
            vec![
                crate::Literal::Positive(atom("edge", vec![var("a"), var("b")])),
                crate::Literal::Positive(atom("edge", vec![var("a"), var("c")])),
                crate::Literal::Positive(atom("edge", vec![var("a"), var("d")])),
                crate::Literal::Positive(atom("edge", vec![var("b"), var("c")])),
                crate::Literal::Positive(atom("edge", vec![var("b"), var("d")])),
                crate::Literal::Positive(atom("edge", vec![var("c"), var("d")])),
            ],
        )],
    });

    let default_limits = crate::Limits::default();
    let program = bundle.validate().expect("valid");
    let context = test_context(&bundle);
    let sources = AvailabilityMap::new();
    let fixture = EvaluationFixture {
        bundle: &bundle,
        context: &context,
        limits: &default_limits,
        current_sources: &sources,
        base_facts: &base_facts,
    };

    // Binary join fails under default limits (`Partial` at 1,000 intermediate bindings).
    let mut binary_default = make_evaluation(&fixture);
    evaluate_rules_binary(&mut binary_default, &program.strata);
    assert_eq!(
        binary_default.budget.status,
        crate::ExecutionStatus::Partial
    );
    assert!(binary_default.budget.limit_reached);

    // Even with raised `max_result_rows`, binary join hits `Timeout` at 100k work.
    let raised_rows = crate::Limits {
        max_result_rows: 100_000,
        ..default_limits
    };
    let raised_fixture = EvaluationFixture {
        limits: &raised_rows,
        ..fixture
    };
    let mut binary_raised = make_evaluation(&raised_fixture);
    evaluate_rules_binary(&mut binary_raised, &program.strata);
    assert_eq!(binary_raised.budget.status, crate::ExecutionStatus::Timeout);
    assert!(binary_raised.budget.limit_reached);

    // Free Join completes exhaustively under default limits in ~2k work.
    let mut free_default = make_evaluation(&fixture);
    evaluate_rules(&mut free_default, &program.strata);
    assert_eq!(free_default.budget.status, crate::ExecutionStatus::Complete);
    assert!(!free_default.budget.limit_reached);
    assert_eq!(free_default.facts["k4"].rows.len(), 48);
    assert!(
        free_default.budget.work < 5_000,
        "free join k4 work {} should be well under 5,000",
        free_default.budget.work
    );

    let generous_limits = crate::Limits {
        max_work: 5_000_000,
        max_time_ms: 60_000,
        max_result_rows: 100_000,
        ..default_limits
    };
    let (binary_work, free_work) =
        assert_equivalent_to_binary(&bundle, &base_facts, &generous_limits);
    eprintln!(
        "cyclic-4-clique-hub (184 edges, 48 k4 tuples): binary={binary_work}, free_join={free_work}"
    );
    assert!(binary_work > 100_000);
    assert!(free_work < 5_000);
}

#[test]
fn property_equivalence_against_binary_and_naive_across_cyclic_seeded_programs() {
    let mut seed = 0x517C_C1B7_2722_0A95_u64;
    let mut next_u64 = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };

    let preds = ["e0", "e1", "t0"];
    let vars = ["a", "b", "c", "d"];

    for case_idx in 0..40_usize {
        let mut base_facts = Vec::with_capacity(60);
        let mut next_rid = 1_u16;
        for (pred_idx, pred) in preds.iter().enumerate() {
            let row_count = 4 + usize::try_from(next_u64() % 14).expect("mod 14");
            for _ in 0..row_count {
                let v0 = i64::try_from(next_u64() % 5).expect("mod 5");
                let v1 = i64::try_from(next_u64() % 5).expect("mod 5");
                let v2 = i64::try_from(next_u64() % 4).expect("mod 4");
                let id = rid(next_rid);
                next_rid = next_rid.saturating_add(1);
                let row = if pred_idx < 2 {
                    vec![
                        mneme_core::Value::integer(v0),
                        mneme_core::Value::integer(v1),
                    ]
                } else {
                    vec![
                        mneme_core::Value::integer(v0),
                        mneme_core::Value::integer(v1),
                        mneme_core::Value::integer(v2),
                    ]
                };
                base_facts.push(((*pred).to_owned(), row, id));
            }
        }

        // Build cyclic and self-join shapes with constants, negation, and compares.
        let body = vec![
            crate::Literal::Positive(atom("e0", vec![var("a"), var("b")])),
            crate::Literal::Positive(atom("e1", vec![var("b"), var("c")])),
            crate::Literal::Positive(atom(
                if case_idx % 2 == 0 { "e0" } else { "e1" },
                vec![var("c"), var("a")],
            )),
            crate::Literal::Positive(atom(
                "t0",
                vec![
                    var(vars[case_idx % 3]),
                    var(vars[(case_idx + 1) % 3]),
                    if case_idx % 3 == 0 {
                        int_const(i64::try_from(next_u64() % 4).expect("mod 4"))
                    } else {
                        var("d")
                    },
                ],
            )),
            crate::Literal::Negative(atom("e1", vec![var("a"), var("c")])),
            crate::Literal::Compare {
                op: crate::CompareOp::Ne,
                left: var("a"),
                right: var("b"),
            },
        ];
        let head_terms = if case_idx % 4 == 0 {
            vec![var("a"), var("c")]
        } else {
            vec![var("a"), var("b"), var("c")]
        };
        let bundle = crate::RuleBundle::new(crate::RuleBundleOptions {
            id: format!("cyclic-prop-{case_idx}"),
            version: "1".to_owned(),
            schema_version: 3,
            base_predicates: std::collections::BTreeMap::from([
                ("e0".to_owned(), 2),
                ("e1".to_owned(), 2),
                ("t0".to_owned(), 3),
            ]),
            complete_predicates: std::collections::BTreeSet::from([
                "e0".to_owned(),
                "e1".to_owned(),
                "t0".to_owned(),
            ]),
            rules: vec![crate::Rule::new("cyc", atom("cyc", head_terms), body)],
        });

        let limits = crate::Limits {
            max_work: 5_000_000,
            max_time_ms: 60_000,
            max_result_rows: 1_000,
            max_supports_per_fact: 2,
            max_recursion_depth: 16,
        };
        assert_equivalent_to_binary_and_naive(&bundle, &base_facts, &limits);
    }
}

#[test]
fn build_fact_data_with_budget_exhaustion_never_promotes_to_accepted() {
    let rule = crate::Rule::new(
        "r-join",
        atom("joined", vec![var("x")]),
        vec![
            crate::Literal::Positive(atom("p1", vec![var("x")])),
            crate::Literal::Positive(atom("p2", vec![var("x")])),
        ],
    );
    let bundle = crate::RuleBundle::new(crate::RuleBundleOptions {
        id: "timeout-promotion-guard".to_owned(),
        version: "1".to_owned(),
        schema_version: 1,
        base_predicates: std::collections::BTreeMap::from([
            ("p1".to_owned(), 1),
            ("p2".to_owned(), 1),
        ]),
        complete_predicates: std::collections::BTreeSet::from(["p1".to_owned(), "p2".to_owned()]),
        rules: vec![rule.clone()],
    });
    let context = test_context(&bundle);
    let x_val = mneme_core::Value::string("k1");
    let make_row = |id: u16, epistemic: crate::EpistemicStatus| crate::FactData {
        supports: vec![crate::Derivation {
            rule_id: "canonical".to_owned(),
            rule_version: "1".to_owned(),
            premises: Vec::new(),
            sources: std::collections::BTreeSet::new(),
            vaults: std::collections::BTreeSet::from([crate::PRIMARY_VAULT_ALIAS.to_owned()]),
            temporal_parameters: Vec::new(),
            revision: context.served_revision,
            scope: context.scope.clone(),
            truncated: false,
            epistemic,
        }],
        sources: std::collections::BTreeSet::new(),
        truncated: false,
        canonical: Some(rid(id)),
        canonical_roots: std::collections::BTreeSet::from([rid(id)]),
        vaults: std::collections::BTreeSet::from([crate::PRIMARY_VAULT_ALIAS.to_owned()]),
        temporal: Vec::new(),
        epistemic,
    };
    let mut facts = std::collections::BTreeMap::new();
    let mut p1_store = FactStore::default();
    p1_store.rows.insert(
        vec![x_val.clone()],
        make_row(1, crate::EpistemicStatus::Accepted),
    );
    let mut p2_store = FactStore::default();
    p2_store.rows.insert(
        vec![x_val.clone()],
        make_row(2, crate::EpistemicStatus::Proposed),
    );
    facts.insert("p1".to_owned(), p1_store);
    facts.insert("p2".to_owned(), p2_store);
    let coverage_map = std::collections::BTreeMap::from([
        ("p1".to_owned(), crate::CoverageStatus::Complete),
        ("p2".to_owned(), crate::CoverageStatus::Complete),
    ]);
    let bindings = vec![Binding::from([("x".to_owned(), x_val.clone())])];
    let target_terms = vec![x_val];

    // Budget allows premise 1 (Accepted) to be charged, then exhausts on premise 2 (Proposed).
    // Must abort without committing a silently promoted Accepted row.
    let tight_limits = crate::Limits {
        max_work: 1,
        max_time_ms: 10_000,
        max_result_rows: 100,
        max_supports_per_fact: 8,
        max_recursion_depth: 8,
    };
    let mut budget = Budget {
        limits: &tight_limits,
        work: 0,
        stored_rows: 0,
        start: evaluation_start(),
        cancellation: None,
        status: crate::ExecutionStatus::Complete,
        limit_reached: false,
        support_truncated: false,
    };
    let mut target_store = FactStore::default();
    let _ = build_ordinary_fact_data_from_bindings(
        FactDataBuildRequest {
            rule: &rule,
            context: &context,
            facts: &facts,
            coverage_map: &coverage_map,
            bindings: &bindings,
            target_terms: &target_terms,
        },
        &mut budget,
        &mut target_store,
    );
    assert!(!budget.is_active());
    assert!(budget.limit_reached);
    assert_eq!(budget.status, crate::ExecutionStatus::Timeout);
    assert!(
        target_store.rows.is_empty(),
        "timed-out refresh must never commit a silently promoted Accepted row"
    );

    // Same check for aggregate refresh under budget exhaustion.
    let mut agg_budget = Budget {
        limits: &tight_limits,
        work: 0,
        stored_rows: 0,
        start: evaluation_start(),
        cancellation: None,
        status: crate::ExecutionStatus::Complete,
        limit_reached: false,
        support_truncated: false,
    };
    let mut agg_store = FactStore::default();
    let _ = build_aggregate_fact_data_from_bindings(
        FactDataBuildRequest {
            rule: &rule,
            context: &context,
            facts: &facts,
            coverage_map: &coverage_map,
            bindings: &bindings,
            target_terms: &target_terms,
        },
        &mut agg_budget,
        &mut agg_store,
    );
    assert!(!agg_budget.is_active());
    assert!(agg_budget.limit_reached);
    assert!(agg_store.rows.is_empty());

    // With ample budget, both premises resolve and join cleanly to Proposed (not Accepted).
    let ample_limits = crate::Limits::default();
    let mut ok_budget = Budget {
        limits: &ample_limits,
        work: 0,
        stored_rows: 0,
        start: evaluation_start(),
        cancellation: None,
        status: crate::ExecutionStatus::Complete,
        limit_reached: false,
        support_truncated: false,
    };
    let mut ok_store = FactStore::default();
    let _ = build_ordinary_fact_data_from_bindings(
        FactDataBuildRequest {
            rule: &rule,
            context: &context,
            facts: &facts,
            coverage_map: &coverage_map,
            bindings: &bindings,
            target_terms: &target_terms,
        },
        &mut ok_budget,
        &mut ok_store,
    );
    assert!(ok_budget.is_active());
    assert!(ok_budget.work >= 3);
    let row = ok_store.rows.get(&target_terms).expect("refreshed row");
    assert_eq!(row.epistemic, crate::EpistemicStatus::Proposed);
}
