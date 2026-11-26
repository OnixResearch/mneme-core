//! Bitemporal sequenced joins, coalescing invariance, non-sequenced Allen
//! predicates, bounded DatalogMTL (`diamond_minus`, `box_minus`, `since`),
//! interval caps, and 100-trace discrete-timestamp oracle parity tests.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::unwrap_used, clippy::expect_used)]

const HOUR_NS: i64 = 3_600_000_000_000;
const DAY_NS: i64 = 24 * HOUR_NS;

fn scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "bitemporal-dl").expect("scope")
}

fn rid(tag: u32) -> mneme_core::RecordId {
    let mut bytes = [0_u8; 16];
    bytes[0] = 0x77;
    bytes[12..16].copy_from_slice(&tag.to_be_bytes());
    mneme_core::RecordId::from_bytes(bytes)
}

fn rev(tag: u32) -> mneme_core::RevisionId {
    let mut bytes = [0_u8; 16];
    bytes[0] = 0x88;
    bytes[12..16].copy_from_slice(&tag.to_be_bytes());
    mneme_core::RevisionId::from_bytes(bytes)
}

struct TestWorkspace {
    _temp: tempfile::TempDir,
    workspace: mneme_store::Workspace,
    next_tag: u32,
}

impl TestWorkspace {
    fn new() -> Self {
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
        let bytes = b"= Source\n\nBitemporal test fixture.\n";
        let (source, source_blob) = mneme_memory::build_source(
            rid(1),
            rev(1),
            &scope(),
            mneme_memory::SourceOptions {
                media_type: "text/asciidoc",
                bytes,
                entity: Some(rid(2)),
                path_hint: Some("fixture.adoc"),
            },
        )
        .expect("source");
        let entity_payload = std::collections::BTreeMap::from([
            (
                mneme_core::Symbol::from("entity-type"),
                mneme_core::Value::symbol("service"),
            ),
            (
                mneme_core::Symbol::from("label"),
                mneme_core::Value::string("Svc"),
            ),
            (
                mneme_core::Symbol::from("properties"),
                mneme_core::Value::dictionary([]),
            ),
        ]);
        let base = workspace.current_revision().expect("base");
        workspace
            .commit(mneme_store::CommitCommand {
                base,
                actor: "test".to_owned(),
                scope: scope(),
                idempotency_key: "init".to_owned(),
                records: vec![
                    mneme_store::RecordDraft {
                        schema_version: 1,
                        kind: mneme_core::RecordKind::Entity,
                        record_id: rid(2),
                        revision_id: rev(2),
                        predecessor: None,
                        scope: scope(),
                        payload: mneme_core::Payload::new(entity_payload),
                    },
                    source,
                ],
                source_blobs: vec![source_blob],
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("init");
        Self {
            _temp: temp,
            workspace,
            next_tag: 100,
        }
    }

    fn alloc_tag(&mut self) -> u32 {
        let tag = self.next_tag;
        self.next_tag += 1;
        tag
    }

    fn add_accepted_assertions(&mut self, specs: &[(&str, &str, mneme_core::ValidTime)]) {
        if specs.is_empty() {
            return;
        }
        let mut propose_records = Vec::with_capacity(specs.len() * 2);
        let mut ids = Vec::with_capacity(specs.len());
        for (predicate, value, valid_time) in specs {
            let ev_tag = self.alloc_tag();
            let as_tag = self.alloc_tag();
            let evidence_id = rid(ev_tag);
            let assertion_id = rid(as_tag);
            let evidence = mneme_memory::build_evidence(
                evidence_id,
                rev(ev_tag),
                &scope(),
                mneme_memory::EvidenceOptions {
                    assertion: assertion_id,
                    source: rid(1),
                    source_revision: rev(1),
                    span: None,
                    anchor: Some("fixture-anchor"),
                    relation: mneme_memory::SupportRelation::Supports,
                    origin: mneme_core::Origin::AuthoredStatement,
                    ancestry: &[],
                },
            );
            let assertion = mneme_memory::build_proposed_assertion(
                assertion_id,
                rev(as_tag),
                &scope(),
                mneme_memory::ProposedAssertionOptions {
                    subject: rid(2),
                    predicate,
                    value: mneme_core::Value::string((*value).to_owned()),
                    stance: mneme_memory::Stance::Affirm,
                    origin: mneme_core::Origin::AuthoredStatement,
                    asserted_by: "test",
                    evidence: &[mneme_core::Reference::local(
                        evidence_id,
                        mneme_core::RecordKind::Evidence,
                    )],
                    valid_time: *valid_time,
                    extraction: None,
                    superseded_by: None,
                },
            );
            propose_records.push(evidence);
            propose_records.push(assertion);
            ids.push(assertion_id);
        }
        let batch_tag = self.alloc_tag();
        {
            let mut memory =
                mneme_memory::Engine::new(&mut self.workspace, mneme_memory::Access::Operator);
            memory
                .commit(mneme_memory::Batch {
                    actor: "test".to_owned(),
                    scope: scope(),
                    idempotency_key: format!("prop-{batch_tag}"),
                    records: propose_records,
                    source_blobs: Vec::new(),
                    publications: Vec::new(),
                })
                .expect("propose batch");
        }
        let base = self.workspace.current_revision().expect("base");
        let snapshot = self.workspace.snapshot().expect("snapshot");
        let by_id: std::collections::BTreeMap<_, _> = snapshot
            .records
            .into_iter()
            .map(|r| (r.record_id, r))
            .collect();
        let mut accept_records = Vec::with_capacity(ids.len() * 2);
        for assertion_id in ids {
            let dec_tag = self.alloc_tag();
            let rev_tag = self.alloc_tag();
            let decision_id = rid(dec_tag);
            let decision = mneme_memory::build_decision(
                decision_id,
                rev(dec_tag),
                &scope(),
                mneme_memory::DecisionOptions {
                    kind: mneme_memory::DecisionKind::Acceptance,
                    target: assertion_id,
                    actor: "test",
                    policy: "test/v1",
                    input_revision: base,
                    outcome: "accepted",
                    rationale: "accept for bitemporal test",
                    evidence: &[],
                    related: &[],
                },
            );
            let revised = mneme_memory::build_assertion_revision(
                &by_id[&assertion_id],
                rev(rev_tag),
                mneme_core::Lifecycle::Accepted,
                mneme_core::Reference::local(decision_id, mneme_core::RecordKind::Decision),
                None,
            );
            accept_records.push(decision);
            accept_records.push(revised);
        }
        let mut memory =
            mneme_memory::Engine::new(&mut self.workspace, mneme_memory::Access::Operator);
        memory
            .commit(mneme_memory::Batch {
                actor: "test".to_owned(),
                scope: scope(),
                idempotency_key: format!("acc-{batch_tag}"),
                records: accept_records,
                source_blobs: Vec::new(),
                publications: Vec::new(),
            })
            .expect("accept batch");
    }

    fn build_bundle(
        &mut self,
        bundle: mneme_datalog::RuleBundle,
        at: Option<mneme_core::Timestamp>,
        limits: mneme_datalog::Limits,
        config: mneme_datalog::TemporalConfig,
    ) -> mneme_datalog::Build {
        let revision = self.workspace.current_revision().expect("rev");
        let mut service = mneme_datalog::Service::new(&mut self.workspace);
        service
            .build_with_temporal_config(
                mneme_datalog::BuildRequest {
                    actor: "test".to_owned(),
                    scope: scope(),
                    revision,
                    bundle,
                    limits,
                    publish: false,
                    incomplete_extents: std::collections::BTreeSet::new(),
                    cancellation: None,
                    access: mneme_memory::Access::Operator,
                    at,
                },
                config,
            )
            .expect("build")
    }
}

fn ts(year: &str) -> mneme_core::Timestamp {
    mneme_core::Timestamp::parse(&format!("{year}-01-01T00:00:00Z")).expect("ts")
}

fn base_assertions_bundle(rules: Vec<mneme_datalog::Rule>) -> mneme_datalog::RuleBundle {
    mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "bitemporal-test".to_owned(),
        version: "1".to_owned(),
        schema_version: 1,
        base_predicates: std::collections::BTreeMap::from([("assertion".to_owned(), 4)]),
        complete_predicates: std::collections::BTreeSet::new(),
        rules,
    })
}

#[test]
fn sequenced_join_prunes_disjoint_intervals_and_stamps_exact_overlap_at_none() {
    // Disjoint intervals: [2018, 2020) and [2022, 2024) at at == None -> 0 rows!
    let mut disjoint_ws = TestWorkspace::new();
    disjoint_ws.add_accepted_assertions(&[
        (
            "left_fact",
            "a",
            mneme_core::ValidTime::between(ts("2018"), ts("2020")).expect("bounds"),
        ),
        (
            "right_fact",
            "b",
            mneme_core::ValidTime::between(ts("2022"), ts("2024")).expect("bounds"),
        ),
    ]);
    let sequenced_bundle = base_assertions_bundle(vec![mneme_datalog::Rule::new(
        "join-lr",
        mneme_datalog::Atom::new(
            "joined",
            vec![
                mneme_datalog::Term::var("x"),
                mneme_datalog::Term::var("v1"),
                mneme_datalog::Term::var("v2"),
            ],
        ),
        vec![
            mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                "assertion",
                vec![
                    mneme_datalog::Term::var("x"),
                    mneme_datalog::Term::constant(mneme_core::Value::symbol("left_fact")),
                    mneme_datalog::Term::var("v1"),
                    mneme_datalog::Term::var("id1"),
                ],
            )),
            mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                "assertion",
                vec![
                    mneme_datalog::Term::var("x"),
                    mneme_datalog::Term::constant(mneme_core::Value::symbol("right_fact")),
                    mneme_datalog::Term::var("v2"),
                    mneme_datalog::Term::var("id2"),
                ],
            )),
        ],
    )]);
    let build = disjoint_ws.build_bundle(
        sequenced_bundle.clone(),
        None,
        mneme_datalog::Limits::default(),
        mneme_datalog::TemporalConfig::default(),
    );
    let mut svc = mneme_datalog::Service::new(&mut disjoint_ws.workspace);
    let res = svc
        .query_build(&build, mneme_datalog::Query::all("joined", 10))
        .expect("query");
    assert!(
        res.rows.is_empty(),
        "disjoint [2018, 2020) and [2022, 2024) must prune to 0 rows"
    );

    // Non-sequenced Allen Before succeeds on the exact same disjoint intervals!
    let allen_bundle = base_assertions_bundle(vec![mneme_datalog::Rule::new(
        "allen-before",
        mneme_datalog::Atom::new(
            "ordered_pair",
            vec![
                mneme_datalog::Term::var("x"),
                mneme_datalog::Term::var("v1"),
                mneme_datalog::Term::var("v2"),
            ],
        ),
        vec![mneme_datalog::Literal::Allen {
            relation: mneme_kernel::temporal::AllenRelation::Before,
            left: mneme_datalog::Atom::new(
                "assertion",
                vec![
                    mneme_datalog::Term::var("x"),
                    mneme_datalog::Term::constant(mneme_core::Value::symbol("left_fact")),
                    mneme_datalog::Term::var("v1"),
                    mneme_datalog::Term::var("id1"),
                ],
            ),
            right: mneme_datalog::Atom::new(
                "assertion",
                vec![
                    mneme_datalog::Term::var("x"),
                    mneme_datalog::Term::constant(mneme_core::Value::symbol("right_fact")),
                    mneme_datalog::Term::var("v2"),
                    mneme_datalog::Term::var("id2"),
                ],
            ),
        }],
    )]);
    let allen_build = disjoint_ws.build_bundle(
        allen_bundle,
        None,
        mneme_datalog::Limits::default(),
        mneme_datalog::TemporalConfig::default(),
    );
    let mut svc2 = mneme_datalog::Service::new(&mut disjoint_ws.workspace);
    let allen_res = svc2
        .query_build(&allen_build, mneme_datalog::Query::all("ordered_pair", 10))
        .expect("query allen");
    assert_eq!(allen_res.rows.len(), 1);

    // Overlapping intervals: [2018, 2023) and [2021, 2024) -> 1 row stamped [2021, 2023)!
    let mut overlap_ws = TestWorkspace::new();
    overlap_ws.add_accepted_assertions(&[
        (
            "left_fact",
            "a",
            mneme_core::ValidTime::between(ts("2018"), ts("2023")).expect("bounds"),
        ),
        (
            "right_fact",
            "b",
            mneme_core::ValidTime::between(ts("2021"), ts("2024")).expect("bounds"),
        ),
    ]);
    let overlap_build = overlap_ws.build_bundle(
        sequenced_bundle.clone(),
        None,
        mneme_datalog::Limits::default(),
        mneme_datalog::TemporalConfig::default(),
    );
    let key = vec![
        rid(2).to_value(),
        mneme_core::Value::string("a"),
        mneme_core::Value::string("b"),
    ];
    let intervals = overlap_build
        .fact_intervals("joined", &key)
        .expect("overlapping joined row");
    assert_eq!(
        intervals.periods(),
        &[mneme_kernel::temporal::Period {
            start: i128::from(ts("2021").nanos()),
            stop: i128::from(ts("2023").nanos()),
        }]
    );

    // Fail-closed Unknown: joining Unknown with a bounded assertion yields 0 rows!
    let mut unknown_ws = TestWorkspace::new();
    unknown_ws.add_accepted_assertions(&[
        ("left_fact", "a", mneme_core::ValidTime::Unknown),
        (
            "right_fact",
            "b",
            mneme_core::ValidTime::between(ts("2021"), ts("2024")).expect("bounds"),
        ),
    ]);
    let unknown_build = unknown_ws.build_bundle(
        sequenced_bundle,
        None,
        mneme_datalog::Limits::default(),
        mneme_datalog::TemporalConfig::default(),
    );
    assert!(unknown_build.fact_intervals("joined", &key).is_none());
}

#[test]
fn coalescing_invariance_and_interval_budget_caps() {
    let window_7d = i128::from(7 * DAY_NS);
    let make_bundle = || {
        base_assertions_bundle(vec![
            mneme_datalog::Rule::new(
                "verified-base",
                mneme_datalog::Atom::new("verified", vec![mneme_datalog::Term::var("x")]),
                vec![mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                    "assertion",
                    vec![
                        mneme_datalog::Term::var("x"),
                        mneme_datalog::Term::constant(mneme_core::Value::symbol("verified")),
                        mneme_datalog::Term::var("v"),
                        mneme_datalog::Term::var("id"),
                    ],
                ))],
            ),
            mneme_datalog::Rule::new(
                "sustained-7d",
                mneme_datalog::Atom::new(
                    "sustained_verified_7d",
                    vec![mneme_datalog::Term::var("x")],
                ),
                vec![mneme_datalog::Literal::BoxMinus {
                    atom: mneme_datalog::Atom::new("verified", vec![mneme_datalog::Term::var("x")]),
                    lower_ns: 0,
                    upper_ns: window_7d,
                }],
            ),
        ])
    };

    // Unsplit: [0d, 10d)
    let mut unsplit = TestWorkspace::new();
    unsplit.add_accepted_assertions(&[(
        "verified",
        "ok",
        mneme_core::ValidTime::between(
            mneme_core::Timestamp::from_nanos(0),
            mneme_core::Timestamp::from_nanos(10 * DAY_NS),
        )
        .expect("bounds"),
    )]);
    let b_unsplit = unsplit.build_bundle(
        make_bundle(),
        None,
        mneme_datalog::Limits::default(),
        mneme_datalog::TemporalConfig::default(),
    );

    // Split into 3 contiguous/overlapping segments: [0d, 4d), [4d, 7d), [6d, 10d)
    let mut split = TestWorkspace::new();
    split.add_accepted_assertions(&[
        (
            "verified",
            "ok-1",
            mneme_core::ValidTime::between(
                mneme_core::Timestamp::from_nanos(0),
                mneme_core::Timestamp::from_nanos(4 * DAY_NS),
            )
            .expect("bounds"),
        ),
        (
            "verified",
            "ok-2",
            mneme_core::ValidTime::between(
                mneme_core::Timestamp::from_nanos(4 * DAY_NS),
                mneme_core::Timestamp::from_nanos(7 * DAY_NS),
            )
            .expect("bounds"),
        ),
        (
            "verified",
            "ok-3",
            mneme_core::ValidTime::between(
                mneme_core::Timestamp::from_nanos(6 * DAY_NS),
                mneme_core::Timestamp::from_nanos(10 * DAY_NS),
            )
            .expect("bounds"),
        ),
    ]);
    let b_split = split.build_bundle(
        make_bundle(),
        None,
        mneme_datalog::Limits::default(),
        mneme_datalog::TemporalConfig::default(),
    );

    let key = vec![rid(2).to_value()];
    assert_eq!(
        b_unsplit.fact_intervals("verified", &key),
        b_split.fact_intervals("verified", &key),
        "contiguous/overlapping segments must coalesce identically"
    );
    assert_eq!(
        b_unsplit.fact_intervals("sustained_verified_7d", &key),
        b_split.fact_intervals("sustained_verified_7d", &key),
        "BoxMinus over split coalesced intervals must equal unsplit BoxMinus"
    );
    assert_eq!(
        b_split
            .fact_intervals("sustained_verified_7d", &key)
            .expect("sustained")
            .periods(),
        &[mneme_kernel::temporal::Period {
            start: i128::from(7 * DAY_NS),
            stop: i128::from(10 * DAY_NS),
        }]
    );

    // max_intervals_per_fact cap enforces bounded disjoint interval growth.
    let mut capped = TestWorkspace::new();
    capped.add_accepted_assertions(&[
        (
            "verified",
            "s1",
            mneme_core::ValidTime::between(
                mneme_core::Timestamp::from_nanos(0),
                mneme_core::Timestamp::from_nanos(DAY_NS),
            )
            .expect("b"),
        ),
        (
            "verified",
            "s2",
            mneme_core::ValidTime::between(
                mneme_core::Timestamp::from_nanos(3 * DAY_NS),
                mneme_core::Timestamp::from_nanos(4 * DAY_NS),
            )
            .expect("b"),
        ),
        (
            "verified",
            "s3",
            mneme_core::ValidTime::between(
                mneme_core::Timestamp::from_nanos(6 * DAY_NS),
                mneme_core::Timestamp::from_nanos(7 * DAY_NS),
            )
            .expect("b"),
        ),
        (
            "verified",
            "s4",
            mneme_core::ValidTime::between(
                mneme_core::Timestamp::from_nanos(9 * DAY_NS),
                mneme_core::Timestamp::from_nanos(10 * DAY_NS),
            )
            .expect("b"),
        ),
    ]);
    let b_capped = capped.build_bundle(
        make_bundle(),
        None,
        mneme_datalog::Limits::default(),
        mneme_datalog::TemporalConfig {
            max_intervals_per_fact: 2,
        },
    );
    let capped_intervals = b_capped
        .fact_intervals("verified", &key)
        .expect("capped verified");
    assert_eq!(capped_intervals.periods().len(), 2);
}

struct XorShift64(u64);

impl XorShift64 {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_range(&mut self, bound: usize) -> usize {
        usize::try_from(self.next_u64() % u64::try_from(bound).expect("bound")).expect("usize")
    }
}

#[test]
fn metric_temporal_100_trace_discrete_oracle_parity() {
    // Test 100 deterministic randomized traces for:
    //   1. retested_within_24h:   ♦₋_[0, 24] (tested)
    //   2. sustained_verified_7d: ■₋_[0, 7]  (verified)
    //   3. verified_since_24h:    verified S_[1, 24] refactored
    // Using discrete nanosecond ticks (1 tick = 1ns for exact exhaustive checking
    // at every single integer point t ∈ [0, HORIZON)) plus a real-scale 24h/7d check.
    const HORIZON: usize = 60;
    const W_24H: i128 = 24;
    const W_7D: i128 = 7;

    let bundle = base_assertions_bundle(vec![
        mneme_datalog::Rule::new(
            "tested-base",
            mneme_datalog::Atom::new("tested", vec![mneme_datalog::Term::var("x")]),
            vec![mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                "assertion",
                vec![
                    mneme_datalog::Term::var("x"),
                    mneme_datalog::Term::constant(mneme_core::Value::symbol("tested")),
                    mneme_datalog::Term::var("v"),
                    mneme_datalog::Term::var("id"),
                ],
            ))],
        ),
        mneme_datalog::Rule::new(
            "verified-base",
            mneme_datalog::Atom::new("verified", vec![mneme_datalog::Term::var("x")]),
            vec![mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                "assertion",
                vec![
                    mneme_datalog::Term::var("x"),
                    mneme_datalog::Term::constant(mneme_core::Value::symbol("verified")),
                    mneme_datalog::Term::var("v"),
                    mneme_datalog::Term::var("id"),
                ],
            ))],
        ),
        mneme_datalog::Rule::new(
            "refactored-base",
            mneme_datalog::Atom::new("refactored", vec![mneme_datalog::Term::var("x")]),
            vec![mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                "assertion",
                vec![
                    mneme_datalog::Term::var("x"),
                    mneme_datalog::Term::constant(mneme_core::Value::symbol("refactored")),
                    mneme_datalog::Term::var("v"),
                    mneme_datalog::Term::var("id"),
                ],
            ))],
        ),
        mneme_datalog::Rule::new(
            "retested-within-24h",
            mneme_datalog::Atom::new("retested_within_24h", vec![mneme_datalog::Term::var("x")]),
            vec![mneme_datalog::Literal::DiamondMinus {
                atom: mneme_datalog::Atom::new("tested", vec![mneme_datalog::Term::var("x")]),
                lower_ns: 0,
                upper_ns: W_24H,
            }],
        ),
        mneme_datalog::Rule::new(
            "sustained-verified-7d",
            mneme_datalog::Atom::new("sustained_verified_7d", vec![mneme_datalog::Term::var("x")]),
            vec![mneme_datalog::Literal::BoxMinus {
                atom: mneme_datalog::Atom::new("verified", vec![mneme_datalog::Term::var("x")]),
                lower_ns: 0,
                upper_ns: W_7D,
            }],
        ),
        mneme_datalog::Rule::new(
            "verified-since-refactor",
            mneme_datalog::Atom::new(
                "verified_since_refactor",
                vec![mneme_datalog::Term::var("x")],
            ),
            vec![mneme_datalog::Literal::Since {
                maintained: mneme_datalog::Atom::new(
                    "verified",
                    vec![mneme_datalog::Term::var("x")],
                ),
                trigger: mneme_datalog::Atom::new(
                    "refactored",
                    vec![mneme_datalog::Term::var("x")],
                ),
                lower_ns: 1,
                upper_ns: W_24H,
            }],
        ),
    ]);

    let mut rng = XorShift64(0x5EED_B17E_2026_1126);
    let key = vec![rid(2).to_value()];

    for trace in 0_u32..100_u32 {
        let mut ws = TestWorkspace::new();
        let mut tested_oracle = [false; HORIZON];
        let mut verified_oracle = [false; HORIZON];
        let mut refactored_oracle = [false; HORIZON];
        let mut specs: Vec<(&str, String, mneme_core::ValidTime)> = Vec::new();

        let n_tested = 1 + rng.next_range(5);
        for i in 0..n_tested {
            let s = rng.next_range(HORIZON - 1);
            let len = 1 + rng.next_range(6);
            let e = (s + len).min(HORIZON);
            for slot in &mut tested_oracle[s..e] {
                *slot = true;
            }
            let vt = if s + 1 == e {
                mneme_core::ValidTime::instant(mneme_core::Timestamp::from_nanos(
                    i64::try_from(s).expect("i64"),
                ))
            } else {
                mneme_core::ValidTime::between(
                    mneme_core::Timestamp::from_nanos(i64::try_from(s).expect("i64")),
                    mneme_core::Timestamp::from_nanos(i64::try_from(e).expect("i64")),
                )
                .expect("bounds")
            };
            specs.push(("tested", format!("t-{trace}-{i}"), vt));
        }

        let n_verified = 2 + rng.next_range(6);
        for i in 0..n_verified {
            let s = rng.next_range(HORIZON - 1);
            let len = 2 + rng.next_range(12);
            let e = (s + len).min(HORIZON);
            for slot in &mut verified_oracle[s..e] {
                *slot = true;
            }
            let vt = mneme_core::ValidTime::between(
                mneme_core::Timestamp::from_nanos(i64::try_from(s).expect("i64")),
                mneme_core::Timestamp::from_nanos(i64::try_from(e).expect("i64")),
            )
            .expect("bounds");
            specs.push(("verified", format!("v-{trace}-{i}"), vt));
        }

        let n_refactored = 1 + rng.next_range(4);
        for i in 0..n_refactored {
            let s = rng.next_range(HORIZON - 1);
            let len = 1 + rng.next_range(3);
            let e = (s + len).min(HORIZON);
            for slot in &mut refactored_oracle[s..e] {
                *slot = true;
            }
            let vt = mneme_core::ValidTime::between(
                mneme_core::Timestamp::from_nanos(i64::try_from(s).expect("i64")),
                mneme_core::Timestamp::from_nanos(i64::try_from(e).expect("i64")),
            )
            .expect("bounds");
            specs.push(("refactored", format!("r-{trace}-{i}"), vt));
        }

        let borrowed: Vec<(&str, &str, mneme_core::ValidTime)> = specs
            .iter()
            .map(|(p, v, vt)| (*p, v.as_str(), *vt))
            .collect();
        ws.add_accepted_assertions(&borrowed);
        let build = ws.build_bundle(
            bundle.clone(),
            None,
            mneme_datalog::Limits::default(),
            mneme_datalog::TemporalConfig::default(),
        );
        let retested_set = build.fact_intervals("retested_within_24h", &key);
        let sustained_set = build.fact_intervals("sustained_verified_7d", &key);
        let since_set = build.fact_intervals("verified_since_refactor", &key);

        for t in 0..HORIZON {
            let t_i128 = i128::try_from(t).expect("i128");
            // Discrete oracle for ♦₋_[0, 24](tested)
            let lo_24 = t.saturating_sub(24);
            let expected_retested = (lo_24..=t).any(|tp| tested_oracle[tp]);
            let actual_retested = retested_set.is_some_and(|set| set.contains(t_i128));
            assert_eq!(
                actual_retested, expected_retested,
                "trace {trace} tick {t}: retested_within_24h mismatch"
            );

            // Discrete oracle for ■₋_[0, 7](verified)
            let expected_sustained = t >= 7 && ((t - 7)..=t).all(|tp| verified_oracle[tp]);
            let actual_sustained = sustained_set.is_some_and(|set| set.contains(t_i128));
            assert_eq!(
                actual_sustained, expected_sustained,
                "trace {trace} tick {t}: sustained_verified_7d mismatch"
            );

            // Discrete oracle for verified S_[1, 24] refactored
            let expected_since = (lo_24..t)
                .any(|tp| refactored_oracle[tp] && ((tp + 1)..=t).all(|s| verified_oracle[s]));
            let actual_since = since_set.is_some_and(|set| set.contains(t_i128));
            assert_eq!(
                actual_since, expected_since,
                "trace {trace} tick {t}: verified_since_refactor mismatch"
            );
        }
    }

    // Verify explicit `at = Some(ts)` evaluation with real 24h nanosecond window.
    let mut point_ws = TestWorkspace::new();
    let t0 = mneme_core::Timestamp::from_nanos(10 * DAY_NS);
    point_ws.add_accepted_assertions(&[("tested", "ok", mneme_core::ValidTime::instant(t0))]);
    let real_24h_bundle = base_assertions_bundle(vec![
        mneme_datalog::Rule::new(
            "tested-base",
            mneme_datalog::Atom::new("tested", vec![mneme_datalog::Term::var("x")]),
            vec![mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                "assertion",
                vec![
                    mneme_datalog::Term::var("x"),
                    mneme_datalog::Term::constant(mneme_core::Value::symbol("tested")),
                    mneme_datalog::Term::var("v"),
                    mneme_datalog::Term::var("id"),
                ],
            ))],
        ),
        mneme_datalog::Rule::new(
            "retested-24h",
            mneme_datalog::Atom::new("retested_within_24h", vec![mneme_datalog::Term::var("x")]),
            vec![mneme_datalog::Literal::DiamondMinus {
                atom: mneme_datalog::Atom::new("tested", vec![mneme_datalog::Term::var("x")]),
                lower_ns: 0,
                upper_ns: i128::from(24 * HOUR_NS),
            }],
        ),
    ]);
    let at_within = point_ws.build_bundle(
        real_24h_bundle.clone(),
        Some(mneme_core::Timestamp::from_nanos(t0.nanos() + 12 * HOUR_NS)),
        mneme_datalog::Limits::default(),
        mneme_datalog::TemporalConfig::default(),
    );
    assert!(
        at_within
            .fact_intervals("retested_within_24h", &key)
            .is_some()
    );

    let at_outside = point_ws.build_bundle(
        real_24h_bundle,
        Some(mneme_core::Timestamp::from_nanos(t0.nanos() + 30 * HOUR_NS)),
        mneme_datalog::Limits::default(),
        mneme_datalog::TemporalConfig::default(),
    );
    assert!(
        at_outside
            .fact_intervals("retested_within_24h", &key)
            .is_none()
    );
}
