//! Integration and scale regression tests for epistemic-stratified e-graphs
//! (`Action::Union`, two-tier `EClassTable`, lattice congruence closure, and Free Join
//! `FactTrie` recanonicalization).
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::expect_used)] // test assertions use expect for failure diagnostics

fn scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "egglog").expect("scope")
}

fn tagged_rid(prefix: u8, tag: u32) -> mneme_core::RecordId {
    let mut bytes = [0_u8; 16];
    bytes[0] = prefix;
    let [b0, b1, b2, b3] = tag.to_be_bytes();
    bytes[12] = b0;
    bytes[13] = b1;
    bytes[14] = b2;
    bytes[15] = b3;
    mneme_core::RecordId::from_bytes(bytes)
}

fn tagged_rev(prefix: u8, tag: u32) -> mneme_core::RevisionId {
    let mut bytes = [0_u8; 16];
    bytes[0] = prefix;
    let [b0, b1, b2, b3] = tag.to_be_bytes();
    bytes[12] = b0;
    bytes[13] = b1;
    bytes[14] = b2;
    bytes[15] = b3;
    mneme_core::RevisionId::from_bytes(bytes)
}

fn atom(predicate: &str, terms: Vec<mneme_datalog::Term>) -> mneme_datalog::Atom {
    mneme_datalog::Atom::new(predicate, terms)
}

fn var(name: &str) -> mneme_datalog::Term {
    mneme_datalog::Term::var(name)
}

fn sym(name: &str) -> mneme_datalog::Term {
    mneme_datalog::Term::constant(mneme_core::Value::symbol(name))
}

fn entity_draft(
    id: mneme_core::RecordId,
    rev: mneme_core::RevisionId,
    label: &str,
    status: mneme_datalog::EpistemicStatus,
) -> mneme_store::RecordDraft {
    let payload = mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("entity-type"),
            mneme_core::Value::symbol("symbol"),
        ),
        (
            mneme_core::Symbol::from("label"),
            mneme_core::Value::string(label.to_owned()),
        ),
        (
            mneme_core::Symbol::from("properties"),
            mneme_core::Value::symbol_dictionary([(
                mneme_core::Symbol::from("status"),
                mneme_core::Value::symbol(status.name()),
            )]),
        ),
    ]);
    mneme_store::RecordDraft {
        schema_version: 1,
        kind: mneme_core::RecordKind::Entity,
        record_id: id,
        revision_id: rev,
        predecessor: None,
        scope: scope(),
        payload,
    }
}

struct RelationDraftSpec<'a> {
    id: mneme_core::RecordId,
    rev: mneme_core::RevisionId,
    relation_type: &'a str,
    from: mneme_core::RecordId,
    to: mneme_core::RecordId,
    status: mneme_datalog::EpistemicStatus,
}

fn relation_draft(spec: RelationDraftSpec<'_>) -> mneme_store::RecordDraft {
    let payload = mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("relation-type"),
            mneme_core::Value::symbol(spec.relation_type),
        ),
        (
            mneme_core::Symbol::from("from"),
            mneme_core::Reference::local(spec.from, mneme_core::RecordKind::Entity).to_value(),
        ),
        (
            mneme_core::Symbol::from("to"),
            mneme_core::Reference::local(spec.to, mneme_core::RecordKind::Entity).to_value(),
        ),
        (
            mneme_core::Symbol::from("properties"),
            mneme_core::Value::symbol_dictionary([(
                mneme_core::Symbol::from("status"),
                mneme_core::Value::symbol(spec.status.name()),
            )]),
        ),
    ]);
    mneme_store::RecordDraft {
        schema_version: 1,
        kind: mneme_core::RecordKind::Relation,
        record_id: spec.id,
        revision_id: spec.rev,
        predecessor: None,
        scope: scope(),
        payload,
    }
}

struct Harness {
    _temp: tempfile::TempDir,
    root: std::path::PathBuf,
    workspace: mneme_store::Workspace,
}

impl Harness {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().to_path_buf();
        let workspace = mneme_store::Workspace::create(
            &root,
            mneme_store::WorkspaceConfig {
                clock: Box::new(mneme_store::FixedClock::new(
                    mneme_core::Timestamp::from_nanos(1_000),
                )),
                faults: Box::new(mneme_store::NoFaults),
            },
        )
        .expect("workspace create");
        Self {
            _temp: temp,
            root,
            workspace,
        }
    }

    fn commit(&mut self, key: &str, records: Vec<mneme_store::RecordDraft>) {
        self.workspace
            .commit(mneme_store::CommitCommand {
                base: self.workspace.current_revision().expect("base rev"),
                actor: "egraph-test".to_owned(),
                scope: scope(),
                idempotency_key: key.to_owned(),
                records,
                source_blobs: Vec::new(),
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("commit");
    }

    fn build_with(
        &mut self,
        bundle: mneme_datalog::RuleBundle,
        limits: mneme_datalog::Limits,
        egraph_config: mneme_datalog::EGraphConfig,
    ) -> mneme_datalog::Build {
        let revision = self.workspace.current_revision().expect("rev");
        let mut service = mneme_datalog::Service::new(&mut self.workspace);
        service
            .build_with_egraph_config(
                mneme_datalog::BuildRequest {
                    actor: "egraph-test".to_owned(),
                    scope: scope(),
                    revision,
                    bundle,
                    limits,
                    publish: false,
                    incomplete_extents: std::collections::BTreeSet::new(),
                    cancellation: None,
                    access: mneme_memory::Access::Operator,
                    at: None,
                },
                egraph_config,
            )
            .expect("build")
    }

    fn query_all(
        &mut self,
        build: &mneme_datalog::Build,
        predicate: &str,
        limit: usize,
    ) -> mneme_datalog::QueryResult {
        let mut service = mneme_datalog::Service::new(&mut self.workspace);
        service
            .query_build(build, mneme_datalog::Query::all(predicate, limit))
            .expect("query")
    }
}

fn seed_1000_entity_50_cluster_graph(harness: &mut Harness) -> Vec<[mneme_core::RecordId; 20]> {
    const CLUSTERS: usize = 50;
    const CLUSTER_SIZE: usize = 20;
    let mut records = Vec::with_capacity(3_000);
    let mut clusters = Vec::with_capacity(CLUSTERS);
    let mut rel_seq = 1_u32;

    for cluster in 0..CLUSTERS {
        let mut members = [mneme_core::RecordId::from_bytes([0_u8; 16]); CLUSTER_SIZE];
        for (offset, slot) in members.iter_mut().enumerate() {
            let entity_idx = u32::try_from(
                cluster
                    .saturating_mul(CLUSTER_SIZE)
                    .saturating_add(offset)
                    .saturating_add(1),
            )
            .expect("entity idx");
            let eid = tagged_rid(0x10, entity_idx);
            let erev = tagged_rev(0x11, entity_idx);
            records.push(entity_draft(
                eid,
                erev,
                &format!("cluster-{cluster}-member-{offset}"),
                mneme_datalog::EpistemicStatus::Accepted,
            ));
            *slot = eid;
        }
        // Within each cluster of 20:
        // - Members 1..10 linked to anchor member 0 by Accepted `alias_of` (verified external-id).
        // - Members 10..20 linked to anchor member 0 by Proposed `ast_clone_of` (structural clone).
        for (idx, &member) in members.iter().enumerate().skip(1) {
            let (rel_type, status) = if idx < 10 {
                ("alias_of", mneme_datalog::EpistemicStatus::Accepted)
            } else {
                ("ast_clone_of", mneme_datalog::EpistemicStatus::Proposed)
            };
            records.push(relation_draft(RelationDraftSpec {
                id: tagged_rid(0x20, rel_seq),
                rev: tagged_rev(0x21, rel_seq),
                relation_type: rel_type,
                from: members[0],
                to: member,
                status,
            }));
            rel_seq = rel_seq.saturating_add(1);
        }
        clusters.push(members);
    }

    // Add 50 cross-cluster `calls` edges (one per cluster, referencing a non-rep member
    // in each cluster to test canonical rewriting of downstream relations).
    for cluster in 0..CLUSTERS {
        let next_cluster = cluster
            .saturating_add(1)
            .checked_rem(CLUSTERS)
            .expect("non-zero cluster count");
        records.push(relation_draft(RelationDraftSpec {
            id: tagged_rid(0x20, rel_seq),
            rev: tagged_rev(0x21, rel_seq),
            relation_type: "calls",
            from: clusters[cluster][5],
            to: clusters[next_cluster][15],
            status: mneme_datalog::EpistemicStatus::Accepted,
        }));
        rel_seq = rel_seq.saturating_add(1);
    }

    harness.commit("seed-1000-entities-50-clusters", records);
    clusters
}

#[test]
fn scale_1000_entities_50_clusters_achieves_at_least_20x_work_and_row_reduction() {
    let mut harness = Harness::new();
    let clusters = seed_1000_entity_50_cluster_graph(&mut harness);

    let scale_limits = mneme_datalog::Limits {
        max_work: 500_000,
        max_time_ms: 300_000,
        max_result_rows: 100_000,
        max_supports_per_fact: 1,
        max_recursion_depth: 32,
    };

    // Baseline: transitive-symmetric `same_as` Datalog closure over the exact same
    // 1,000-entity / 50-cluster `alias_of` + `ast_clone_of` graph.
    let baseline_bundle = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "baseline-same-as".to_owned(),
        version: "1".to_owned(),
        schema_version: 1,
        base_predicates: std::collections::BTreeMap::from([("relation".to_owned(), 3)]),
        complete_predicates: std::collections::BTreeSet::from(["relation".to_owned()]),
        rules: vec![
            mneme_datalog::Rule::new(
                "same-as-alias",
                atom("same_as", vec![var("X"), var("Y")]),
                vec![mneme_datalog::Literal::Positive(atom(
                    "relation",
                    vec![sym("alias_of"), var("X"), var("Y")],
                ))],
            ),
            mneme_datalog::Rule::new(
                "same-as-clone",
                atom("same_as", vec![var("X"), var("Y")]),
                vec![mneme_datalog::Literal::Positive(atom(
                    "relation",
                    vec![sym("ast_clone_of"), var("X"), var("Y")],
                ))],
            ),
            mneme_datalog::Rule::new(
                "same-as-sym",
                atom("same_as", vec![var("Y"), var("X")]),
                vec![mneme_datalog::Literal::Positive(atom(
                    "same_as",
                    vec![var("X"), var("Y")],
                ))],
            ),
            mneme_datalog::Rule::new(
                "same-as-trans",
                atom("same_as", vec![var("X"), var("Z")]),
                vec![
                    mneme_datalog::Literal::Positive(atom("same_as", vec![var("X"), var("Y")])),
                    mneme_datalog::Literal::Positive(atom("same_as", vec![var("Y"), var("Z")])),
                ],
            ),
        ],
    });

    // Egglog: Action::Union + epistemic congruence closure.
    let egglog_bundle = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "egglog-union".to_owned(),
        version: "1".to_owned(),
        schema_version: 1,
        base_predicates: std::collections::BTreeMap::from([("relation".to_owned(), 3)]),
        complete_predicates: std::collections::BTreeSet::from(["relation".to_owned()]),
        rules: vec![
            mneme_datalog::Rule::union(
                "union-alias",
                var("X"),
                var("Y"),
                vec![mneme_datalog::Literal::Positive(atom(
                    "relation",
                    vec![sym("alias_of"), var("X"), var("Y")],
                ))],
            ),
            mneme_datalog::Rule::union(
                "union-clone",
                var("X"),
                var("Y"),
                vec![mneme_datalog::Literal::Positive(atom(
                    "relation",
                    vec![sym("ast_clone_of"), var("X"), var("Y")],
                ))],
            ),
            mneme_datalog::Rule::new(
                "egglog-calls",
                atom("canonical_calls", vec![var("X"), var("Y")]),
                vec![mneme_datalog::Literal::Positive(atom(
                    "relation",
                    vec![sym("calls"), var("X"), var("Y")],
                ))],
            ),
        ],
    });

    let egglog_build = harness.build_with(
        egglog_bundle,
        scale_limits.clone(),
        mneme_datalog::EGraphConfig::default(),
    );
    assert_eq!(
        egglog_build.status(),
        mneme_datalog::ExecutionStatus::Complete
    );

    let baseline_build = harness.build_with(
        baseline_bundle,
        scale_limits,
        mneme_datalog::EGraphConfig::default(),
    );

    // Convergence in <= 3 rebuild rounds.
    let rebuild_rounds = egglog_build.eclasses().rebuild_rounds();
    assert!(rebuild_rounds >= 1);
    assert!(rebuild_rounds <= 3);

    // Materialized derived rows comparison:
    // Baseline materializes O(|C|^2) `same_as` rows (up to 20,000);
    // Egglog materializes 0 `same_as` rows + 50 canonical `canonical_calls` rows!
    let baseline_derived_rows = baseline_build.row_count("same_as");
    let egglog_derived_rows = egglog_build.row_count("canonical_calls");
    let baseline_work = baseline_build.work();
    let egglog_work = egglog_build.work();
    assert_eq!(egglog_build.row_count("same_as"), 0);
    assert_eq!(egglog_derived_rows, 50);
    assert!(
        baseline_derived_rows >= egglog_derived_rows * 20,
        "expected >= 20x row reduction: baseline={baseline_derived_rows}, egglog={egglog_derived_rows}"
    );

    // Work-unit reduction >= 20x.
    assert!(egglog_work > 0);
    assert!(
        baseline_work >= egglog_work * 20,
        "expected >= 20x work reduction: baseline={baseline_work}, egglog={egglog_work}, ratio={:.2}x",
        baseline_work as f64 / egglog_work as f64
    );

    // Verify exact canonical representatives and strict Accepted vs Proposed separation.
    let eclasses = egglog_build.eclasses();
    for members in &clusters {
        let rep = members[0].to_value();
        for member in members {
            assert_eq!(eclasses.find_proposed(&member.to_value()), &rep);
        }
        // First 10 members are equivalent in Accepted tier.
        for member in &members[0..10] {
            assert!(eclasses.are_equivalent_accepted(&rep, &member.to_value()));
        }
        // Members 10..20 were only connected via Proposed `ast_clone_of`: NEVER in Accepted tier!
        for member in &members[10..20] {
            assert!(!eclasses.are_equivalent_accepted(&rep, &member.to_value()));
        }
    }

    // Every `canonical_calls` row referenced member[15] (Proposed-merged to rep), so
    // epistemic status MUST be Proposed (zero silent promotion!).
    let calls_result = harness.query_all(&egglog_build, "canonical_calls", 100);
    assert_eq!(calls_result.rows.len(), 50);
    for row in &calls_result.rows {
        assert_eq!(row.epistemic, mneme_datalog::EpistemicStatus::Proposed);
    }
}

#[test]
fn insertion_order_permutation_invariance() {
    let entity_ids: Vec<mneme_core::RecordId> =
        (1_u32..=30).map(|idx| tagged_rid(0x30, idx)).collect();
    let mut base_records = Vec::with_capacity(64);
    for (idx, &eid) in entity_ids.iter().enumerate() {
        let rev_tag = u32::try_from(idx.saturating_add(1)).expect("rev tag");
        base_records.push(entity_draft(
            eid,
            tagged_rev(0x31, rev_tag),
            &format!("e-{idx}"),
            mneme_datalog::EpistemicStatus::Accepted,
        ));
    }
    // 3 clusters of 10 entities each, mixing Accepted alias_of and Proposed ast_clone_of.
    let mut rel_seq = 1_u32;
    for cluster in 0..3_usize {
        let start = cluster.saturating_mul(10);
        for offset in 0..9_usize {
            let (rel_type, status) = if offset < 5 {
                ("alias_of", mneme_datalog::EpistemicStatus::Accepted)
            } else {
                ("ast_clone_of", mneme_datalog::EpistemicStatus::Proposed)
            };
            base_records.push(relation_draft(RelationDraftSpec {
                id: tagged_rid(0x32, rel_seq),
                rev: tagged_rev(0x33, rel_seq),
                relation_type: rel_type,
                from: entity_ids[start.saturating_add(offset)],
                to: entity_ids[start.saturating_add(offset).saturating_add(1)],
                status,
            }));
            rel_seq = rel_seq.saturating_add(1);
        }
        let next_cluster = cluster.saturating_add(1).checked_rem(3).expect("rem 3");
        base_records.push(relation_draft(RelationDraftSpec {
            id: tagged_rid(0x32, rel_seq),
            rev: tagged_rev(0x33, rel_seq),
            relation_type: "calls",
            from: entity_ids[start.saturating_add(3)],
            to: entity_ids[next_cluster.saturating_mul(10).saturating_add(7)],
            status: mneme_datalog::EpistemicStatus::Accepted,
        }));
        rel_seq = rel_seq.saturating_add(1);
    }

    let make_bundle = || {
        mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
            id: "perm-invariance".to_owned(),
            version: "1".to_owned(),
            schema_version: 1,
            base_predicates: std::collections::BTreeMap::from([("relation".to_owned(), 3)]),
            complete_predicates: std::collections::BTreeSet::from(["relation".to_owned()]),
            rules: vec![
                mneme_datalog::Rule::union(
                    "union-alias",
                    var("X"),
                    var("Y"),
                    vec![mneme_datalog::Literal::Positive(atom(
                        "relation",
                        vec![sym("alias_of"), var("X"), var("Y")],
                    ))],
                ),
                mneme_datalog::Rule::union(
                    "union-clone",
                    var("X"),
                    var("Y"),
                    vec![mneme_datalog::Literal::Positive(atom(
                        "relation",
                        vec![sym("ast_clone_of"), var("X"), var("Y")],
                    ))],
                ),
                mneme_datalog::Rule::new(
                    "canon-calls",
                    atom("canon_calls", vec![var("X"), var("Y")]),
                    vec![mneme_datalog::Literal::Positive(atom(
                        "relation",
                        vec![sym("calls"), var("X"), var("Y")],
                    ))],
                ),
            ],
        })
    };

    // Permutation 1: forward order.
    let forward = base_records.clone();
    // Permutation 2: reverse order (entities first so refs stay valid, relations reversed).
    let mut reversed = base_records[..30].to_vec();
    let mut rev_rels = base_records[30..].to_vec();
    rev_rels.reverse();
    reversed.extend(rev_rels);
    // Permutation 3: deterministic stride-7 permutation of entities and relations.
    let mut shuffled = Vec::with_capacity(base_records.len());
    for i in 0..30_usize {
        let pos = i.saturating_mul(7).checked_rem(30).expect("rem 30");
        shuffled.push(base_records[pos].clone());
    }
    let rel_count = base_records.len().saturating_sub(30);
    assert!(rel_count > 0);
    for i in 0..rel_count {
        let offset = i
            .saturating_mul(7)
            .checked_rem(rel_count)
            .expect("rem rel_count");
        shuffled.push(base_records[30_usize.saturating_add(offset)].clone());
    }

    let mut snapshots = Vec::with_capacity(3);
    for (idx, perm) in [forward, reversed, shuffled].into_iter().enumerate() {
        let mut harness = Harness::new();
        harness.commit(&format!("perm-{idx}"), perm);
        let build = harness.build_with(
            make_bundle(),
            mneme_datalog::Limits::default(),
            mneme_datalog::EGraphConfig::default(),
        );
        assert_eq!(build.status(), mneme_datalog::ExecutionStatus::Complete);
        let rows: Vec<(Vec<mneme_core::Value>, mneme_datalog::EpistemicStatus)> = harness
            .query_all(&build, "canon_calls", 100)
            .rows
            .into_iter()
            .map(|row| (row.values, row.epistemic))
            .collect();
        snapshots.push((
            build.eclasses().accepted_classes(),
            build.eclasses().proposed_classes(),
            rows,
        ));
    }

    assert_eq!(snapshots[0], snapshots[1]);
    assert_eq!(snapshots[0], snapshots[2]);
}

#[test]
fn accepted_times_proposed_non_promotion_and_zero_canonical_mutation() {
    // Test BOTH ID orderings: (A < A') AND (A' < A).
    for (a_tag, a_prime_tag) in [(1_u32, 2_u32), (2_u32, 1_u32)] {
        let mut harness = Harness::new();
        let a = tagged_rid(0x40, a_tag);
        let a_prime = tagged_rid(0x40, a_prime_tag);
        let b = tagged_rid(0x40, 10);
        let target = tagged_rid(0x40, 20);
        let canonical_rep = a.min(a_prime);

        harness.commit(
            "seed",
            vec![
                entity_draft(
                    a,
                    tagged_rev(0x41, 1),
                    "A",
                    mneme_datalog::EpistemicStatus::Accepted,
                ),
                entity_draft(
                    a_prime,
                    tagged_rev(0x41, 2),
                    "A-prime",
                    mneme_datalog::EpistemicStatus::Accepted,
                ),
                entity_draft(
                    b,
                    tagged_rev(0x41, 3),
                    "B",
                    mneme_datalog::EpistemicStatus::Accepted,
                ),
                entity_draft(
                    target,
                    tagged_rev(0x41, 4),
                    "Target",
                    mneme_datalog::EpistemicStatus::Accepted,
                ),
                // Accepted calls(A, B)
                relation_draft(RelationDraftSpec {
                    id: tagged_rid(0x42, 1),
                    rev: tagged_rev(0x43, 1),
                    relation_type: "calls",
                    from: a,
                    to: b,
                    status: mneme_datalog::EpistemicStatus::Accepted,
                }),
                // Accepted tagged(A', Target)
                relation_draft(RelationDraftSpec {
                    id: tagged_rid(0x42, 2),
                    rev: tagged_rev(0x43, 2),
                    relation_type: "tagged",
                    from: a_prime,
                    to: target,
                    status: mneme_datalog::EpistemicStatus::Accepted,
                }),
                // Proposed ast_clone_of(A, A')
                relation_draft(RelationDraftSpec {
                    id: tagged_rid(0x42, 3),
                    rev: tagged_rev(0x43, 3),
                    relation_type: "ast_clone_of",
                    from: a,
                    to: a_prime,
                    status: mneme_datalog::EpistemicStatus::Proposed,
                }),
            ],
        );
        let rev_before = harness.workspace.current_revision().expect("rev before");

        let bundle = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
            id: "non-promotion".to_owned(),
            version: "1".to_owned(),
            schema_version: 1,
            base_predicates: std::collections::BTreeMap::from([("relation".to_owned(), 3)]),
            complete_predicates: std::collections::BTreeSet::from(["relation".to_owned()]),
            rules: vec![
                mneme_datalog::Rule::union(
                    "union-clone",
                    var("X"),
                    var("Y"),
                    vec![mneme_datalog::Literal::Positive(atom(
                        "relation",
                        vec![sym("ast_clone_of"), var("X"), var("Y")],
                    ))],
                ),
                mneme_datalog::Rule::new(
                    "joined-call-tag",
                    atom("tagged_call", vec![var("X"), var("B"), var("T")]),
                    vec![
                        mneme_datalog::Literal::Positive(atom(
                            "relation",
                            vec![sym("calls"), var("X"), var("B")],
                        )),
                        mneme_datalog::Literal::Positive(atom(
                            "relation",
                            vec![sym("tagged"), var("X"), var("T")],
                        )),
                    ],
                ),
            ],
        });

        let build = harness.build_with(
            bundle,
            mneme_datalog::Limits::default(),
            mneme_datalog::EGraphConfig::default(),
        );
        assert_eq!(build.status(), mneme_datalog::ExecutionStatus::Complete);

        // Zero canonical workspace mutation!
        let rev_after = harness.workspace.current_revision().expect("rev after");
        assert_eq!(rev_before, rev_after);

        // Strict separation of Accepted vs Proposed tiers.
        assert!(
            !build
                .eclasses()
                .are_equivalent_accepted(&a.to_value(), &a_prime.to_value())
        );
        assert!(
            build
                .eclasses()
                .are_equivalent_proposed(&a.to_value(), &a_prime.to_value())
        );
        assert_eq!(build.eclasses().find_accepted(&a.to_value()), &a.to_value());
        assert_eq!(
            build.eclasses().find_accepted(&a_prime.to_value()),
            &a_prime.to_value()
        );
        assert_eq!(
            build.eclasses().find_proposed(&a.to_value()),
            &canonical_rep.to_value()
        );

        // Joining Accepted `calls(A, B)` with Accepted `tagged(A', Target)` via Proposed
        // `union(A, A')` MUST yield EpistemicStatus::Proposed (zero silent promotion).
        let joined = harness.query_all(&build, "tagged_call", 16);
        assert_eq!(joined.rows.len(), 1);
        assert_eq!(
            joined.rows[0].values,
            vec![canonical_rep.to_value(), b.to_value(), target.to_value()]
        );
        assert_eq!(
            joined.rows[0].epistemic,
            mneme_datalog::EpistemicStatus::Proposed
        );
    }
}

#[test]
fn congruence_closure_cascade_over_free_join_tries() {
    let mut harness = Harness::new();
    let a1 = tagged_rid(0x50, 1);
    let a2 = tagged_rid(0x50, 2);
    let b1 = tagged_rid(0x50, 3);
    let b2 = tagged_rid(0x50, 4);

    harness.commit(
        "congruence-seed",
        vec![
            entity_draft(
                a1,
                tagged_rev(0x51, 1),
                "a1",
                mneme_datalog::EpistemicStatus::Accepted,
            ),
            entity_draft(
                a2,
                tagged_rev(0x51, 2),
                "a2",
                mneme_datalog::EpistemicStatus::Accepted,
            ),
            entity_draft(
                b1,
                tagged_rev(0x51, 3),
                "b1",
                mneme_datalog::EpistemicStatus::Accepted,
            ),
            entity_draft(
                b2,
                tagged_rev(0x51, 4),
                "b2",
                mneme_datalog::EpistemicStatus::Accepted,
            ),
            // a1 == a2 (Accepted)
            relation_draft(RelationDraftSpec {
                id: tagged_rid(0x52, 1),
                rev: tagged_rev(0x53, 1),
                relation_type: "alias_of",
                from: a1,
                to: a2,
                status: mneme_datalog::EpistemicStatus::Accepted,
            }),
            // parent(a1, b1) and parent(a2, b2) -> congruence implies b1 == b2!
            relation_draft(RelationDraftSpec {
                id: tagged_rid(0x52, 2),
                rev: tagged_rev(0x53, 2),
                relation_type: "unique_child",
                from: a1,
                to: b1,
                status: mneme_datalog::EpistemicStatus::Accepted,
            }),
            relation_draft(RelationDraftSpec {
                id: tagged_rid(0x52, 3),
                rev: tagged_rev(0x53, 3),
                relation_type: "unique_child",
                from: a2,
                to: b2,
                status: mneme_datalog::EpistemicStatus::Accepted,
            }),
        ],
    );

    let bundle = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "congruence-cascade".to_owned(),
        version: "1".to_owned(),
        schema_version: 1,
        base_predicates: std::collections::BTreeMap::from([("relation".to_owned(), 3)]),
        complete_predicates: std::collections::BTreeSet::from(["relation".to_owned()]),
        rules: vec![
            mneme_datalog::Rule::union(
                "union-alias",
                var("X"),
                var("Y"),
                vec![mneme_datalog::Literal::Positive(atom(
                    "relation",
                    vec![sym("alias_of"), var("X"), var("Y")],
                ))],
            ),
            // 2-atom Free Join congruence rule: once a1 == a2 collapses tries, b1 == b2 fires!
            mneme_datalog::Rule::union(
                "congruent-child",
                var("Y1"),
                var("Y2"),
                vec![
                    mneme_datalog::Literal::Positive(atom(
                        "relation",
                        vec![sym("unique_child"), var("X"), var("Y1")],
                    )),
                    mneme_datalog::Literal::Positive(atom(
                        "relation",
                        vec![sym("unique_child"), var("X"), var("Y2")],
                    )),
                    mneme_datalog::Literal::Compare {
                        op: mneme_datalog::CompareOp::Ne,
                        left: var("Y1"),
                        right: var("Y2"),
                    },
                ],
            ),
        ],
    });

    let build = harness.build_with(
        bundle,
        mneme_datalog::Limits::default(),
        mneme_datalog::EGraphConfig::default(),
    );
    assert_eq!(build.status(), mneme_datalog::ExecutionStatus::Complete);
    assert!(
        build
            .eclasses()
            .are_equivalent_accepted(&a1.to_value(), &a2.to_value())
    );
    assert!(
        build
            .eclasses()
            .are_equivalent_accepted(&b1.to_value(), &b2.to_value())
    );
    assert_eq!(
        build.eclasses().find_accepted(&b2.to_value()),
        &b1.to_value()
    );
    assert!(build.eclasses().rebuild_rounds() >= 2);
    assert!(build.eclasses().rebuild_rounds() <= 3);
}

#[test]
fn lattice_merge_functional_head_with_epistemic_non_promotion() {
    let mut harness = Harness::new();
    let e1 = tagged_rid(0x60, 1);
    let e2 = tagged_rid(0x60, 2);

    harness.commit(
        "lattice-seed",
        vec![
            entity_draft(
                e1,
                tagged_rev(0x61, 1),
                "alpha",
                mneme_datalog::EpistemicStatus::Accepted,
            ),
            entity_draft(
                e2,
                tagged_rev(0x61, 2),
                "zeta",
                mneme_datalog::EpistemicStatus::Accepted,
            ),
            // Proposed union e1 == e2 (e1 < e2, so e1 is canonical rep).
            relation_draft(RelationDraftSpec {
                id: tagged_rid(0x62, 1),
                rev: tagged_rev(0x63, 1),
                relation_type: "ast_clone_of",
                from: e1,
                to: e2,
                status: mneme_datalog::EpistemicStatus::Proposed,
            }),
        ],
    );

    let bundle = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "lattice-merge".to_owned(),
        version: "1".to_owned(),
        schema_version: 1,
        base_predicates: std::collections::BTreeMap::from([
            ("entity".to_owned(), 3),
            ("relation".to_owned(), 3),
        ]),
        complete_predicates: std::collections::BTreeSet::from([
            "entity".to_owned(),
            "relation".to_owned(),
        ]),
        rules: vec![
            mneme_datalog::Rule::union(
                "union-clone",
                var("X"),
                var("Y"),
                vec![mneme_datalog::Literal::Positive(atom(
                    "relation",
                    vec![sym("ast_clone_of"), var("X"), var("Y")],
                ))],
            ),
            // Max over labels: "zeta" (from e2, Proposed-rewritten to e1) > "alpha" (from e1, Accepted)
            // -> winning value "zeta" MUST carry EpistemicStatus::Proposed!
            mneme_datalog::Rule::new(
                "max-label",
                atom("cluster_max_label", vec![var("E"), var("L")]),
                vec![mneme_datalog::Literal::Positive(atom(
                    "entity",
                    vec![var("E"), var("K"), var("L")],
                ))],
            )
            .with_lattice_merge(mneme_datalog::LatticeMerge {
                column: 1,
                op: mneme_datalog::LatticeOp::Max,
            }),
            // Min over labels: "alpha" (from e1, Accepted) < "zeta" -> stays EpistemicStatus::Accepted!
            mneme_datalog::Rule::new(
                "min-label",
                atom("cluster_min_label", vec![var("E"), var("L")]),
                vec![mneme_datalog::Literal::Positive(atom(
                    "entity",
                    vec![var("E"), var("K"), var("L")],
                ))],
            )
            .with_lattice_merge(mneme_datalog::LatticeMerge {
                column: 1,
                op: mneme_datalog::LatticeOp::Min,
            }),
            // SetUnion over labels: {"alpha", "zeta"} depends on both -> EpistemicStatus::Proposed!
            mneme_datalog::Rule::new(
                "all-labels",
                atom("cluster_label_set", vec![var("E"), var("L")]),
                vec![mneme_datalog::Literal::Positive(atom(
                    "entity",
                    vec![var("E"), var("K"), var("L")],
                ))],
            )
            .with_lattice_merge(mneme_datalog::LatticeMerge {
                column: 1,
                op: mneme_datalog::LatticeOp::SetUnion,
            }),
        ],
    });

    let build = harness.build_with(
        bundle,
        mneme_datalog::Limits::default(),
        mneme_datalog::EGraphConfig::default(),
    );
    assert_eq!(build.status(), mneme_datalog::ExecutionStatus::Complete);

    let max_res = harness.query_all(&build, "cluster_max_label", 16);
    assert_eq!(max_res.rows.len(), 1);
    assert_eq!(
        max_res.rows[0].values,
        vec![e1.to_value(), mneme_core::Value::string("zeta")]
    );
    assert_eq!(
        max_res.rows[0].epistemic,
        mneme_datalog::EpistemicStatus::Proposed
    );

    let min_res = harness.query_all(&build, "cluster_min_label", 16);
    assert_eq!(min_res.rows.len(), 1);
    assert_eq!(
        min_res.rows[0].values,
        vec![e1.to_value(), mneme_core::Value::string("alpha")]
    );
    assert_eq!(
        min_res.rows[0].epistemic,
        mneme_datalog::EpistemicStatus::Accepted
    );

    let set_res = harness.query_all(&build, "cluster_label_set", 16);
    assert_eq!(set_res.rows.len(), 1);
    assert_eq!(
        set_res.rows[0].values,
        vec![
            e1.to_value(),
            mneme_core::Value::set([
                mneme_core::Value::string("alpha"),
                mneme_core::Value::string("zeta"),
            ]),
        ]
    );
    assert_eq!(
        set_res.rows[0].epistemic,
        mneme_datalog::EpistemicStatus::Proposed
    );
}

#[test]
fn budget_and_egraph_bounds_fail_closed() {
    let mut harness = Harness::new();
    let mut records = Vec::with_capacity(40);
    for i in 1_u32..=20 {
        records.push(entity_draft(
            tagged_rid(0x70, i),
            tagged_rev(0x71, i),
            &format!("n-{i}"),
            mneme_datalog::EpistemicStatus::Accepted,
        ));
    }
    for i in 1_u32..20 {
        records.push(relation_draft(RelationDraftSpec {
            id: tagged_rid(0x72, i),
            rev: tagged_rev(0x73, i),
            relation_type: "alias_of",
            from: tagged_rid(0x70, i),
            to: tagged_rid(0x70, i.saturating_add(1)),
            status: mneme_datalog::EpistemicStatus::Accepted,
        }));
    }
    harness.commit("budget-seed", records);

    let bundle = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "budget-egraph".to_owned(),
        version: "1".to_owned(),
        schema_version: 1,
        base_predicates: std::collections::BTreeMap::from([("relation".to_owned(), 3)]),
        complete_predicates: std::collections::BTreeSet::from(["relation".to_owned()]),
        rules: vec![mneme_datalog::Rule::union(
            "union-alias",
            var("X"),
            var("Y"),
            vec![mneme_datalog::Literal::Positive(atom(
                "relation",
                vec![sym("alias_of"), var("X"), var("Y")],
            ))],
        )],
    });

    // 1. Tight union cap fails closed as Partial.
    let union_capped = harness.build_with(
        bundle.clone(),
        mneme_datalog::Limits::default(),
        mneme_datalog::EGraphConfig {
            max_rebuild_rounds: 32,
            max_unions: 3,
        },
    );
    assert_eq!(
        union_capped.status(),
        mneme_datalog::ExecutionStatus::Partial
    );
    assert!(union_capped.limit_reached());
    assert_eq!(union_capped.eclasses().total_unions(), 3);

    // 2. Zero rebuild round cap fails closed as Partial.
    let round_capped = harness.build_with(
        bundle.clone(),
        mneme_datalog::Limits::default(),
        mneme_datalog::EGraphConfig {
            max_rebuild_rounds: 0,
            max_unions: 1_000,
        },
    );
    assert_eq!(
        round_capped.status(),
        mneme_datalog::ExecutionStatus::Partial
    );
    assert!(round_capped.limit_reached());
    assert_eq!(round_capped.eclasses().rebuild_rounds(), 0);

    // 3. Tight work budget fails closed as Timeout.
    let work_capped = harness.build_with(
        bundle,
        mneme_datalog::Limits {
            max_work: 5,
            ..mneme_datalog::Limits::default()
        },
        mneme_datalog::EGraphConfig::default(),
    );
    assert_eq!(
        work_capped.status(),
        mneme_datalog::ExecutionStatus::Timeout
    );
    assert!(work_capped.limit_reached());
}

#[test]
fn rule_validation_rejects_invalid_egraph_actions_and_lattice_heads() {
    let base_predicates = std::collections::BTreeMap::from([("relation".to_owned(), 3)]);
    let complete_predicates = std::collections::BTreeSet::from(["relation".to_owned()]);

    // 1. Unbound variable in Action::Union.
    let unsafe_union = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "bad-union".to_owned(),
        version: "1".to_owned(),
        schema_version: 1,
        base_predicates: base_predicates.clone(),
        complete_predicates: complete_predicates.clone(),
        rules: vec![mneme_datalog::Rule::union(
            "r1",
            var("X"),
            var("UNBOUND"),
            vec![mneme_datalog::Literal::Positive(atom(
                "relation",
                vec![sym("alias_of"), var("X"), var("Y")],
            ))],
        )],
    });
    let diags = unsafe_union
        .validate()
        .expect_err("must reject unbound action var");
    assert!(diags.iter().any(|d| d.code == "unsafe-action-variable"));

    // 2. Out-of-bounds lattice merge column.
    let bad_col = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "bad-col".to_owned(),
        version: "1".to_owned(),
        schema_version: 1,
        base_predicates: base_predicates.clone(),
        complete_predicates: complete_predicates.clone(),
        rules: vec![
            mneme_datalog::Rule::new(
                "r1",
                atom("scores", vec![var("X"), var("Y")]),
                vec![mneme_datalog::Literal::Positive(atom(
                    "relation",
                    vec![sym("alias_of"), var("X"), var("Y")],
                ))],
            )
            .with_lattice_merge(mneme_datalog::LatticeMerge {
                column: 2,
                op: mneme_datalog::LatticeOp::Max,
            }),
        ],
    });
    let diags = bad_col
        .validate()
        .expect_err("must reject out-of-bounds lattice col");
    assert!(
        diags
            .iter()
            .any(|d| d.code == "lattice-column-out-of-bounds")
    );

    // 3. Conflicting lattice merges on the same head predicate.
    let conflicting = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "conflict".to_owned(),
        version: "1".to_owned(),
        schema_version: 1,
        base_predicates: base_predicates.clone(),
        complete_predicates: complete_predicates.clone(),
        rules: vec![
            mneme_datalog::Rule::new(
                "r1",
                atom("scores", vec![var("X"), var("Y")]),
                vec![mneme_datalog::Literal::Positive(atom(
                    "relation",
                    vec![sym("alias_of"), var("X"), var("Y")],
                ))],
            )
            .with_lattice_merge(mneme_datalog::LatticeMerge {
                column: 1,
                op: mneme_datalog::LatticeOp::Max,
            }),
            mneme_datalog::Rule::new(
                "r2",
                atom("scores", vec![var("X"), var("Y")]),
                vec![mneme_datalog::Literal::Positive(atom(
                    "relation",
                    vec![sym("alias_of"), var("X"), var("Y")],
                ))],
            )
            .with_lattice_merge(mneme_datalog::LatticeMerge {
                column: 1,
                op: mneme_datalog::LatticeOp::Min,
            }),
        ],
    });
    let diags = conflicting
        .validate()
        .expect_err("must reject conflicting lattice specs");
    assert!(diags.iter().any(|d| d.code == "conflicting-lattice-merge"));

    // 4. Reserved union head predicate referenced in body.
    let reserved_body = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "reserved".to_owned(),
        version: "1".to_owned(),
        schema_version: 1,
        base_predicates,
        complete_predicates,
        rules: vec![mneme_datalog::Rule::new(
            "r1",
            atom("leak", vec![var("X"), var("Y")]),
            vec![mneme_datalog::Literal::Positive(atom(
                mneme_datalog::UNION_HEAD_PREDICATE,
                vec![var("X"), var("Y")],
            ))],
        )],
    });
    let diags = reserved_body
        .validate()
        .expect_err("must reject reserved predicate in body");
    assert!(diags.iter().any(|d| d.code == "reserved-predicate"));
}

#[test]
fn federated_vaults_merge_shared_label_entities_via_egraph_union() {
    let mut primary = Harness::new();
    let mut secondary = Harness::new();

    let p_id = tagged_rid(0x80, 1);
    let s_id = tagged_rid(0x80, 2);
    let target_id = tagged_rid(0x80, 3);

    primary.commit(
        "primary-seed",
        vec![
            entity_draft(
                p_id,
                tagged_rev(0x81, 1),
                "ext:shared-service",
                mneme_datalog::EpistemicStatus::Accepted,
            ),
            entity_draft(
                target_id,
                tagged_rev(0x81, 2),
                "db:main",
                mneme_datalog::EpistemicStatus::Accepted,
            ),
            relation_draft(RelationDraftSpec {
                id: tagged_rid(0x82, 1),
                rev: tagged_rev(0x83, 1),
                relation_type: "calls",
                from: p_id,
                to: target_id,
                status: mneme_datalog::EpistemicStatus::Accepted,
            }),
        ],
    );
    secondary.commit(
        "secondary-seed",
        vec![entity_draft(
            s_id,
            tagged_rev(0x81, 3),
            "ext:shared-service",
            mneme_datalog::EpistemicStatus::Accepted,
        )],
    );

    let bundle = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "federated-egraph".to_owned(),
        version: "1".to_owned(),
        schema_version: 1,
        base_predicates: std::collections::BTreeMap::from([
            ("vault_entity".to_owned(), 4),
            ("vault_relation".to_owned(), 4),
        ]),
        complete_predicates: std::collections::BTreeSet::from([
            "vault_entity".to_owned(),
            "vault_relation".to_owned(),
        ]),
        rules: vec![
            mneme_datalog::Rule::union(
                "federated-shared-label",
                var("IdA"),
                var("IdB"),
                vec![
                    mneme_datalog::Literal::Positive(atom(
                        "vault_entity",
                        vec![var("VA"), var("IdA"), var("Kind"), var("Label")],
                    )),
                    mneme_datalog::Literal::Positive(atom(
                        "vault_entity",
                        vec![var("VB"), var("IdB"), var("Kind"), var("Label")],
                    )),
                    mneme_datalog::Literal::Compare {
                        op: mneme_datalog::CompareOp::Ne,
                        left: var("IdA"),
                        right: var("IdB"),
                    },
                ],
            ),
            mneme_datalog::Rule::new(
                "unified-calls",
                atom("unified_calls", vec![var("From"), var("To")]),
                vec![mneme_datalog::Literal::Positive(atom(
                    "vault_relation",
                    vec![var("V"), sym("calls"), var("From"), var("To")],
                ))],
            ),
        ],
    });

    let rev = primary.workspace.current_revision().expect("primary rev");
    let mut service = mneme_datalog::Service::new(&mut primary.workspace);
    let build = service
        .build_federated(mneme_datalog::FederatedBuildRequest {
            request: mneme_datalog::BuildRequest {
                actor: "egraph-test".to_owned(),
                scope: scope(),
                revision: rev,
                bundle,
                limits: mneme_datalog::Limits::default(),
                publish: false,
                incomplete_extents: std::collections::BTreeSet::new(),
                cancellation: None,
                access: mneme_memory::Access::Operator,
                at: None,
            },
            attachments: vec![mneme_datalog::VaultAttachment {
                alias: "secondary".to_owned(),
                root: secondary.root.clone(),
                revision: None,
            }],
        })
        .expect("federated build");

    assert_eq!(build.status(), mneme_datalog::ExecutionStatus::Complete);
    assert!(
        build
            .eclasses()
            .are_equivalent_accepted(&p_id.to_value(), &s_id.to_value())
    );
    assert_eq!(
        build.eclasses().find_accepted(&s_id.to_value()),
        &p_id.to_value()
    );
    let calls = service
        .query_build(&build, mneme_datalog::Query::all("unified_calls", 16))
        .expect("query");
    assert_eq!(calls.rows.len(), 1);
    assert_eq!(
        calls.rows[0].values,
        vec![p_id.to_value(), target_id.to_value()]
    );
    assert_eq!(
        calls.rows[0].epistemic,
        mneme_datalog::EpistemicStatus::Accepted
    );
}
