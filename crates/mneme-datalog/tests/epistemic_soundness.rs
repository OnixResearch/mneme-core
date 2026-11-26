//! Regression tests for Datalog epistemic soundness, loader parity, federated barriers, and Why-Not.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::expect_used)] // test assertions use expect for failure diagnostics

fn scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
}

fn rid(byte: u8) -> mneme_core::RecordId {
    mneme_core::RecordId::from_bytes([byte; 16])
}

fn rev(byte: u8) -> mneme_core::RevisionId {
    mneme_core::RevisionId::from_bytes([byte; 16])
}

fn indexed_rid(tag: u16) -> mneme_core::RecordId {
    let mut bytes = [0_u8; 16];
    let [hi, lo] = tag.to_be_bytes();
    bytes[0] = 0x55;
    bytes[14] = hi;
    bytes[15] = lo;
    mneme_core::RecordId::from_bytes(bytes)
}

fn indexed_rev(tag: u16) -> mneme_core::RevisionId {
    let mut bytes = [0_u8; 16];
    let [hi, lo] = tag.to_be_bytes();
    bytes[0] = 0x66;
    bytes[14] = hi;
    bytes[15] = lo;
    mneme_core::RevisionId::from_bytes(bytes)
}

fn limits() -> mneme_datalog::Limits {
    mneme_datalog::Limits {
        max_work: 100_000,
        max_time_ms: 2_000,
        max_result_rows: 1_000,
        max_supports_per_fact: 8,
        max_recursion_depth: 32,
    }
}

struct Harness {
    temp: tempfile::TempDir,
    workspace: mneme_store::Workspace,
}

impl Harness {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temp");
        let workspace = mneme_store::Workspace::create(
            temp.path(),
            mneme_store::WorkspaceConfig {
                clock: Box::new(mneme_store::FixedClock::new(
                    mneme_core::Timestamp::from_nanos(1_000),
                )),
                faults: Box::new(mneme_store::NoFaults),
            },
        )
        .expect("create");
        Self { temp, workspace }
    }

    fn commit(
        &mut self,
        key: &str,
        records: Vec<mneme_store::RecordDraft>,
        blobs: Vec<mneme_store::SourceBlobDraft>,
    ) -> mneme_store::CommitOutcome {
        assert!(!key.is_empty());
        let commit_scope = records
            .first()
            .map(|record| record.scope.clone())
            .unwrap_or_else(scope);
        let outcome = self
            .workspace
            .commit(mneme_store::CommitCommand {
                base: self.workspace.current_revision().expect("base"),
                actor: "datalog-test".to_owned(),
                scope: commit_scope,
                idempotency_key: key.to_owned(),
                records,
                source_blobs: blobs,
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("commit");
        assert!(outcome.sequence > 0);
        outcome
    }

    fn add_entity(&mut self, spec: EntitySeed<'_>) {
        assert!(!spec.key.is_empty());
        assert!(!spec.label.is_empty());
        let payload = mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("entity-type"),
                mneme_core::Value::symbol("project"),
            ),
            (
                mneme_core::Symbol::from("label"),
                mneme_core::Value::string(spec.label.to_owned()),
            ),
            (
                mneme_core::Symbol::from("properties"),
                mneme_core::Value::dictionary([]),
            ),
        ]);
        let draft = mneme_store::RecordDraft {
            schema_version: 1,
            kind: mneme_core::RecordKind::Entity,
            record_id: spec.id,
            revision_id: rev(spec.id.as_bytes()[0]),
            predecessor: None,
            scope: scope(),
            payload,
        };
        self.commit(spec.key, vec![draft], Vec::new());
    }

    fn build(&mut self, bundle: mneme_datalog::RuleBundle) -> mneme_datalog::Build {
        let revision = self.workspace.current_revision().expect("revision");
        let mut service = mneme_datalog::Service::new(&mut self.workspace);
        service
            .build(mneme_datalog::BuildRequest {
                actor: "datalog-test".to_owned(),
                scope: scope(),
                revision,
                bundle,
                limits: limits(),
                publish: false,
                incomplete_extents: std::collections::BTreeSet::new(),
                cancellation: None,
                access: mneme_memory::Access::Operator,
                at: None,
            })
            .expect("build")
    }
}

struct EntitySeed<'a> {
    key: &'a str,
    id: mneme_core::RecordId,
    label: &'a str,
}

struct EntityPayloadSpec<'a> {
    entity_type: &'a str,
    label: &'a str,
    status: mneme_datalog::EpistemicStatus,
}

fn status_entity_payload(spec: EntityPayloadSpec<'_>) -> mneme_core::Payload {
    mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("entity-type"),
            mneme_core::Value::symbol(spec.entity_type),
        ),
        (
            mneme_core::Symbol::from("label"),
            mneme_core::Value::string(spec.label.to_owned()),
        ),
        (
            mneme_core::Symbol::from("properties"),
            mneme_core::Value::symbol_dictionary([(
                mneme_core::Symbol::from("status"),
                mneme_core::Value::symbol(spec.status.name()),
            )]),
        ),
    ])
}

struct RelationPayloadSpec<'a> {
    relation_type: &'a str,
    from: mneme_core::RecordId,
    to: mneme_core::RecordId,
    status: mneme_datalog::EpistemicStatus,
}

fn status_relation_payload(spec: RelationPayloadSpec<'_>) -> mneme_core::Payload {
    assert!(!spec.relation_type.is_empty());
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
    assert!(!payload.is_empty());
    payload
}

fn atom(predicate: &str, terms: Vec<mneme_datalog::Term>) -> mneme_datalog::Atom {
    mneme_datalog::Atom::new(predicate, terms)
}

fn var(name: &str) -> mneme_datalog::Term {
    mneme_datalog::Term::var(name)
}

fn constant(value: mneme_core::Value) -> mneme_datalog::Term {
    mneme_datalog::Term::constant(value)
}

fn bundle(rules: Vec<mneme_datalog::Rule>, complete: &[&str]) -> mneme_datalog::RuleBundle {
    mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "base".to_owned(),
        version: "1".to_owned(),
        schema_version: 3,
        base_predicates: std::collections::BTreeMap::from([
            ("entity".to_owned(), 3),
            ("relation".to_owned(), 3),
        ]),
        complete_predicates: complete.iter().map(|name| (*name).to_owned()).collect(),
        rules,
    })
}

fn retention_request(
    key: &str,
    operation: mneme_retention::OperationKind,
    selector: mneme_retention::Selector,
    base: mneme_core::WorkspaceRevisionId,
) -> mneme_retention::Request {
    mneme_retention::Request {
        actor: "datalog-test".to_owned(),
        scope: scope(),
        base_revision: base,
        idempotency_key: key.to_owned(),
        operation,
        selector,
        effective: None,
        policy: mneme_retention::Policy {
            version: mneme_retention::POLICY_VERSION.to_owned(),
            retain_assertion_after_prune: true,
            block_content_replay: true,
            retain_withdrawn_evidence_metadata: true,
        },
    }
}

#[test]
fn rejected_facts_excluded_from_positive_negation_aggregates_and_whynot() {
    let mut harness = Harness::new();
    let h1 = indexed_rid(1);
    let h2 = indexed_rid(2);
    let x1 = indexed_rid(3);
    let x2 = indexed_rid(4);
    let x3 = indexed_rid(5);

    let records = vec![
        mneme_store::RecordDraft {
            schema_version: 1,
            kind: mneme_core::RecordKind::Entity,
            record_id: h1,
            revision_id: indexed_rev(1),
            predecessor: None,
            scope: scope(),
            payload: status_entity_payload(EntityPayloadSpec {
                entity_type: "hypothesis",
                label: "H1",
                status: mneme_datalog::EpistemicStatus::Accepted,
            }),
        },
        mneme_store::RecordDraft {
            schema_version: 1,
            kind: mneme_core::RecordKind::Entity,
            record_id: h2,
            revision_id: indexed_rev(2),
            predecessor: None,
            scope: scope(),
            payload: status_entity_payload(EntityPayloadSpec {
                entity_type: "hypothesis",
                label: "H2",
                status: mneme_datalog::EpistemicStatus::Accepted,
            }),
        },
        mneme_store::RecordDraft {
            schema_version: 1,
            kind: mneme_core::RecordKind::Entity,
            record_id: x1,
            revision_id: indexed_rev(3),
            predecessor: None,
            scope: scope(),
            payload: status_entity_payload(EntityPayloadSpec {
                entity_type: "evidence",
                label: "X1",
                status: mneme_datalog::EpistemicStatus::Accepted,
            }),
        },
        mneme_store::RecordDraft {
            schema_version: 1,
            kind: mneme_core::RecordKind::Entity,
            record_id: x2,
            revision_id: indexed_rev(4),
            predecessor: None,
            scope: scope(),
            payload: status_entity_payload(EntityPayloadSpec {
                entity_type: "evidence",
                label: "X2",
                status: mneme_datalog::EpistemicStatus::Accepted,
            }),
        },
        mneme_store::RecordDraft {
            schema_version: 1,
            kind: mneme_core::RecordKind::Entity,
            record_id: x3,
            revision_id: indexed_rev(5),
            predecessor: None,
            scope: scope(),
            payload: status_entity_payload(EntityPayloadSpec {
                entity_type: "evidence",
                label: "X3",
                status: mneme_datalog::EpistemicStatus::Accepted,
            }),
        },
        // H1 has ONLY a Rejected falsifier -> must remain open_hypothesis(H1)!
        mneme_store::RecordDraft {
            schema_version: 1,
            kind: mneme_core::RecordKind::Relation,
            record_id: indexed_rid(10),
            revision_id: indexed_rev(10),
            predecessor: None,
            scope: scope(),
            payload: status_relation_payload(RelationPayloadSpec {
                relation_type: "falsifies",
                from: x1,
                to: h1,
                status: mneme_datalog::EpistemicStatus::Rejected,
            }),
        },
        // H2 has one Accepted and one Rejected falsifier -> falsifier_count(H2, 1) with Accepted.
        mneme_store::RecordDraft {
            schema_version: 1,
            kind: mneme_core::RecordKind::Relation,
            record_id: indexed_rid(11),
            revision_id: indexed_rev(11),
            predecessor: None,
            scope: scope(),
            payload: status_relation_payload(RelationPayloadSpec {
                relation_type: "falsifies",
                from: x2,
                to: h2,
                status: mneme_datalog::EpistemicStatus::Accepted,
            }),
        },
        mneme_store::RecordDraft {
            schema_version: 1,
            kind: mneme_core::RecordKind::Relation,
            record_id: indexed_rid(12),
            revision_id: indexed_rev(12),
            predecessor: None,
            scope: scope(),
            payload: status_relation_payload(RelationPayloadSpec {
                relation_type: "falsifies",
                from: x3,
                to: h2,
                status: mneme_datalog::EpistemicStatus::Rejected,
            }),
        },
    ];
    harness.commit("rejected-annihilator", records, Vec::new());

    let sym = |name: &str| constant(mneme_core::Value::symbol(name));
    let rules = bundle(
        vec![
            mneme_datalog::Rule::new(
                "falsified",
                atom("falsified", vec![var("h")]),
                vec![mneme_datalog::Literal::Positive(atom(
                    "relation",
                    vec![sym("falsifies"), var("x"), var("h")],
                ))],
            ),
            // 2-positive-atom Free Join rule to verify trie excludes Rejected facts.
            mneme_datalog::Rule::new(
                "falsified_pair",
                atom("falsified_pair", vec![var("h"), var("x")]),
                vec![
                    mneme_datalog::Literal::Positive(atom(
                        "entity",
                        vec![var("h"), sym("hypothesis"), var("hl")],
                    )),
                    mneme_datalog::Literal::Positive(atom(
                        "relation",
                        vec![sym("falsifies"), var("x"), var("h")],
                    )),
                ],
            ),
            mneme_datalog::Rule::new(
                "open_hypothesis",
                atom("open_hypothesis", vec![var("h")]),
                vec![
                    mneme_datalog::Literal::Positive(atom(
                        "entity",
                        vec![var("h"), sym("hypothesis"), var("hl")],
                    )),
                    mneme_datalog::Literal::Negative(atom("falsified", vec![var("h")])),
                ],
            ),
            mneme_datalog::Rule::new(
                "open_direct_neg",
                atom("open_direct_neg", vec![var("h")]),
                vec![
                    mneme_datalog::Literal::Positive(atom(
                        "entity",
                        vec![var("h"), sym("hypothesis"), var("hl")],
                    )),
                    mneme_datalog::Literal::Negative(atom(
                        "relation",
                        vec![sym("falsifies"), constant(x1.to_value()), var("h")],
                    )),
                ],
            ),
            mneme_datalog::Rule::new(
                "falsifier_count",
                atom("falsifier_count", vec![var("h"), var("n")]),
                vec![
                    mneme_datalog::Literal::Positive(atom(
                        "relation",
                        vec![sym("falsifies"), var("x"), var("h")],
                    )),
                    mneme_datalog::Literal::Aggregate {
                        function: mneme_datalog::AggregateFunction::Count,
                        input: var("x"),
                        output: "n".to_owned(),
                    },
                ],
            ),
        ],
        &["entity", "relation", "falsified"],
    );
    let build = harness.build(rules);
    let mut service = mneme_datalog::Service::new(&mut harness.workspace);

    let open = service
        .query_build(&build, mneme_datalog::Query::all("open_hypothesis", 10))
        .expect("open_hypothesis");
    assert_eq!(open.rows.len(), 1);
    assert_eq!(open.rows[0].values, vec![h1.to_value()]);
    assert_eq!(
        open.rows[0].epistemic,
        mneme_datalog::EpistemicStatus::Accepted
    );

    let open_direct = service
        .query_build(&build, mneme_datalog::Query::all("open_direct_neg", 10))
        .expect("open_direct_neg");
    assert!(
        open_direct
            .rows
            .iter()
            .any(|row| row.values == vec![h1.to_value()]),
        "Rejected relation must not block direct stratified negation"
    );

    let pairs = service
        .query_build(&build, mneme_datalog::Query::all("falsified_pair", 10))
        .expect("falsified_pair");
    assert_eq!(pairs.rows.len(), 1);
    assert_eq!(pairs.rows[0].values, vec![h2.to_value(), x2.to_value()]);

    let counts = service
        .query_build(&build, mneme_datalog::Query::all("falsifier_count", 10))
        .expect("falsifier_count");
    assert_eq!(counts.rows.len(), 1);
    assert_eq!(
        counts.rows[0].values,
        vec![h2.to_value(), mneme_core::Value::integer(1)]
    );
    assert_eq!(
        counts.rows[0].epistemic,
        mneme_datalog::EpistemicStatus::Accepted
    );

    // Why-Not must treat Rejected base fact as absent (not satisfied).
    let explain = service
        .explain_missing_build(
            &build,
            mneme_datalog::ExplainMissingRequest::ground("falsified", vec![h1.to_value()]),
        )
        .expect("explain missing falsified(h1)");
    assert_eq!(explain.status, mneme_datalog::MissingStatus::Missing);
    assert!(explain.present_epistemic.is_none());
}

#[test]
fn assertion_evidence_and_source_respect_properties_status() {
    let mut harness = Harness::new();
    harness.add_entity(EntitySeed {
        key: "e",
        id: rid(0x10),
        label: "Subject",
    });

    let (mut src_prop, blob_prop) = mneme_memory::build_source(
        rid(0x20),
        rev(0x21),
        &scope(),
        mneme_memory::SourceOptions {
            media_type: "text/plain",
            bytes: b"proposed source",
            entity: None,
            path_hint: None,
        },
    )
    .expect("src_prop");
    src_prop.payload.insert(
        mneme_core::Symbol::from("properties"),
        mneme_core::Value::dictionary([(
            mneme_core::Value::symbol("status"),
            mneme_core::Value::symbol("proposed"),
        )]),
    );
    let (mut src_rej, blob_rej) = mneme_memory::build_source(
        rid(0x22),
        rev(0x23),
        &scope(),
        mneme_memory::SourceOptions {
            media_type: "text/plain",
            bytes: b"rejected source",
            entity: None,
            path_hint: None,
        },
    )
    .expect("src_rej");
    src_rej.payload.insert(
        mneme_core::Symbol::from("properties"),
        mneme_core::Value::dictionary([(
            mneme_core::Value::symbol("status"),
            mneme_core::Value::symbol("rejected"),
        )]),
    );
    harness.commit(
        "sources-status",
        vec![src_prop, src_rej],
        vec![blob_prop, blob_rej],
    );

    let span = mneme_core::SourceSpan::new(0, 8).expect("span");
    let mut ev_prop = mneme_memory::build_evidence(
        rid(0x30),
        rev(0x31),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: rid(0x40),
            source: rid(0x20),
            source_revision: rev(0x21),
            span: Some(span),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    ev_prop.payload.insert(
        mneme_core::Symbol::from("properties"),
        mneme_core::Value::dictionary([(
            mneme_core::Value::symbol("status"),
            mneme_core::Value::symbol("proposed"),
        )]),
    );
    let mut ev_rej = mneme_memory::build_evidence(
        rid(0x32),
        rev(0x33),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: rid(0x42),
            source: rid(0x20),
            source_revision: rev(0x21),
            span: Some(span),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    ev_rej.payload.insert(
        mneme_core::Symbol::from("properties"),
        mneme_core::Value::dictionary([(
            mneme_core::Value::symbol("status"),
            mneme_core::Value::symbol("rejected"),
        )]),
    );

    let assertion_prop = mneme_memory::build_proposed_assertion(
        rid(0x40),
        rev(0x41),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: rid(0x10),
            predicate: "claim",
            value: mneme_core::Value::string("prop-claim"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                rid(0x30),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    let assertion_rej = mneme_memory::build_proposed_assertion(
        rid(0x42),
        rev(0x43),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: rid(0x10),
            predicate: "claim",
            value: mneme_core::Value::string("rej-claim"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                rid(0x32),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    harness.commit(
        "proposed-assertions",
        vec![ev_prop, ev_rej, assertion_prop, assertion_rej],
        Vec::new(),
    );

    let input_rev = harness.workspace.current_revision().expect("input rev");
    let prop_env_1 = harness
        .workspace
        .record_revisions(rid(0x40))
        .expect("prop 1")
        .into_iter()
        .last()
        .expect("prop 1 rev");
    let prop_env_2 = harness
        .workspace
        .record_revisions(rid(0x42))
        .expect("prop 2")
        .into_iter()
        .last()
        .expect("prop 2 rev");
    let dec1 = mneme_memory::build_decision(
        rid(0x50),
        rev(0x51),
        &scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: rid(0x40),
            actor: "datalog-test",
            policy: "datalog-policy/v1",
            input_revision: input_rev,
            outcome: "accepted",
            rationale: "accept-prop",
            evidence: &[],
            related: &[],
        },
    );
    let dec2 = mneme_memory::build_decision(
        rid(0x52),
        rev(0x53),
        &scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: rid(0x42),
            actor: "datalog-test",
            policy: "datalog-policy/v1",
            input_revision: input_rev,
            outcome: "accepted",
            rationale: "accept-rej",
            evidence: &[],
            related: &[],
        },
    );
    let mut acc_prop = mneme_memory::build_assertion_revision(
        &prop_env_1,
        rev(0x44),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(rid(0x50), mneme_core::RecordKind::Decision),
        None,
    );
    acc_prop.payload.insert(
        mneme_core::Symbol::from("properties"),
        mneme_core::Value::dictionary([(
            mneme_core::Value::symbol("status"),
            mneme_core::Value::symbol("proposed"),
        )]),
    );
    let mut acc_rej = mneme_memory::build_assertion_revision(
        &prop_env_2,
        rev(0x45),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(rid(0x52), mneme_core::RecordKind::Decision),
        None,
    );
    acc_rej.payload.insert(
        mneme_core::Symbol::from("properties"),
        mneme_core::Value::dictionary([(
            mneme_core::Value::symbol("status"),
            mneme_core::Value::symbol("rejected"),
        )]),
    );
    harness.commit(
        "accepted-status",
        vec![dec1, dec2, acc_prop, acc_rej],
        Vec::new(),
    );

    let rules = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "epistemic-loaders".to_owned(),
        version: "1".to_owned(),
        schema_version: 1,
        base_predicates: std::collections::BTreeMap::from([
            ("assertion".to_owned(), 4),
            ("evidence".to_owned(), 2),
            ("source".to_owned(), 3),
        ]),
        complete_predicates: std::collections::BTreeSet::from([
            "assertion".to_owned(),
            "evidence".to_owned(),
            "source".to_owned(),
        ]),
        rules: vec![
            mneme_datalog::Rule::new(
                "derived_claim",
                atom("derived_claim", vec![var("v")]),
                vec![mneme_datalog::Literal::Positive(atom(
                    "assertion",
                    vec![var("s"), var("p"), var("v"), var("a")],
                ))],
            ),
            mneme_datalog::Rule::new(
                "derived_ev",
                atom("derived_ev", vec![var("a")]),
                vec![mneme_datalog::Literal::Positive(atom(
                    "evidence",
                    vec![var("a"), var("src")],
                ))],
            ),
            mneme_datalog::Rule::new(
                "derived_src",
                atom("derived_src", vec![var("src")]),
                vec![mneme_datalog::Literal::Positive(atom(
                    "source",
                    vec![var("src"), var("r"), var("avail")],
                ))],
            ),
        ],
    });
    let build = harness.build(rules);
    let mut service = mneme_datalog::Service::new(&mut harness.workspace);

    let claims = service
        .query_build(&build, mneme_datalog::Query::all("derived_claim", 10))
        .expect("derived_claim");
    assert_eq!(claims.rows.len(), 1);
    assert_eq!(
        claims.rows[0].values,
        vec![mneme_core::Value::string("prop-claim")]
    );
    assert_eq!(
        claims.rows[0].epistemic,
        mneme_datalog::EpistemicStatus::Proposed
    );

    let evs = service
        .query_build(&build, mneme_datalog::Query::all("derived_ev", 10))
        .expect("derived_ev");
    assert_eq!(evs.rows.len(), 1);
    assert_eq!(evs.rows[0].values, vec![rid(0x40).to_value()]);
    assert_eq!(
        evs.rows[0].epistemic,
        mneme_datalog::EpistemicStatus::Proposed
    );

    let srcs = service
        .query_build(&build, mneme_datalog::Query::all("derived_src", 10))
        .expect("derived_src");
    assert_eq!(srcs.rows.len(), 1);
    assert_eq!(srcs.rows[0].values, vec![rid(0x20).to_value()]);
    assert_eq!(
        srcs.rows[0].epistemic,
        mneme_datalog::EpistemicStatus::Proposed
    );
}

#[test]
fn federated_build_barriers_detect_attached_vault_retention_and_staleness() {
    let mut primary = Harness::new();
    let mut attached = Harness::new();
    primary.add_entity(EntitySeed {
        key: "p1",
        id: rid(0x11),
        label: "Shared",
    });
    attached.add_entity(EntitySeed {
        key: "a1",
        id: rid(0x22),
        label: "Shared",
    });
    let attached_rev1 = attached
        .workspace
        .current_revision()
        .expect("attached rev1");
    let primary_head = primary.workspace.current_revision().expect("primary head");

    let fed_bundle = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "fed-barrier-test".to_owned(),
        version: "1".to_owned(),
        schema_version: 1,
        base_predicates: std::collections::BTreeMap::from([("vault_entity".to_owned(), 4)]),
        complete_predicates: std::collections::BTreeSet::from(["vault_entity".to_owned()]),
        rules: vec![mneme_datalog::Rule::new(
            "shared_pair",
            atom("shared_pair", vec![var("p"), var("a")]),
            vec![
                mneme_datalog::Literal::Positive(atom(
                    "vault_entity",
                    vec![
                        constant(mneme_core::Value::string("primary")),
                        var("p"),
                        var("pt"),
                        var("lbl"),
                    ],
                )),
                mneme_datalog::Literal::Positive(atom(
                    "vault_entity",
                    vec![
                        constant(mneme_core::Value::string("ext")),
                        var("a"),
                        var("at"),
                        var("lbl"),
                    ],
                )),
            ],
        )],
    });

    let mut service = mneme_datalog::Service::new(&mut primary.workspace);
    let build_head = service
        .build_federated(mneme_datalog::FederatedBuildRequest {
            request: mneme_datalog::BuildRequest {
                actor: "test".to_owned(),
                scope: scope(),
                revision: primary_head,
                bundle: fed_bundle.clone(),
                limits: limits(),
                publish: false,
                incomplete_extents: std::collections::BTreeSet::new(),
                cancellation: None,
                access: mneme_memory::Access::Operator,
                at: None,
            },
            attachments: vec![mneme_datalog::VaultAttachment {
                alias: "ext".to_owned(),
                root: attached.temp.path().to_path_buf(),
                revision: None,
            }],
        })
        .expect("fed build head");
    let build_pinned = service
        .build_federated(mneme_datalog::FederatedBuildRequest {
            request: mneme_datalog::BuildRequest {
                actor: "test".to_owned(),
                scope: scope(),
                revision: primary_head,
                bundle: fed_bundle,
                limits: limits(),
                publish: false,
                incomplete_extents: std::collections::BTreeSet::new(),
                cancellation: None,
                access: mneme_memory::Access::Operator,
                at: None,
            },
            attachments: vec![mneme_datalog::VaultAttachment {
                alias: "ext".to_owned(),
                root: attached.temp.path().to_path_buf(),
                revision: Some(attached_rev1),
            }],
        })
        .expect("fed build pinned");

    // Advancing attached vault head makes head-pinned build stale unless allow_stale,
    // while explicitly revision-pinned build stays valid.
    attached.add_entity(EntitySeed {
        key: "a2",
        id: rid(0x23),
        label: "Other",
    });
    let stale_err = service
        .query_build(&build_head, mneme_datalog::Query::all("shared_pair", 10))
        .expect_err("attached head move must make unpinned federated build stale");
    assert!(matches!(stale_err, mneme_datalog::Error::Stale { .. }));
    let mut allow_stale_query = mneme_datalog::Query::all("shared_pair", 10);
    allow_stale_query.allow_stale = true;
    service
        .query_build(&build_head, allow_stale_query)
        .expect("allow_stale query succeeds");
    service
        .query_build(&build_pinned, mneme_datalog::Query::all("shared_pair", 10))
        .expect("explicitly revision-pinned build succeeds after attached commit");

    // Execute retention Forget on the attached vault, advancing its eligibility_generation!
    let (src_rec, src_blob) = mneme_memory::build_source(
        rid(0x24),
        rev(0x25),
        &scope(),
        mneme_memory::SourceOptions {
            media_type: "text/plain",
            bytes: b"attached source",
            entity: None,
            path_hint: None,
        },
    )
    .expect("attached source");
    attached.commit("attached-src", vec![src_rec], vec![src_blob]);
    let attached_base = attached.workspace.current_revision().expect("base");
    let forget = retention_request(
        "forget-attached-source",
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x24)),
        attached_base,
    );
    mneme_retention::Engine::new(&mut attached.workspace)
        .execute(forget)
        .expect("attached forget");

    // Both head-pinned AND revision-pinned cached federated builds must now fail with BarrierAdvanced!
    for build in [&build_head, &build_pinned] {
        let mut q = mneme_datalog::Query::all("shared_pair", 10);
        q.allow_stale = true;
        let err = service
            .query_build(build, q)
            .expect_err("attached retention barrier must invalidate cached federated build");
        assert!(matches!(
            err,
            mneme_datalog::Error::Store(mneme_store::Failure::BarrierAdvanced { .. })
        ));
        let explain_err = service
            .explain_missing_build(
                build,
                mneme_datalog::ExplainMissingRequest {
                    predicate: "shared_pair".to_owned(),
                    terms: vec![rid(0x11).to_value(), rid(0x22).to_value()],
                    limits: mneme_datalog::ExplainLimits::default(),
                    allow_stale: true,
                    cancellation: None,
                },
            )
            .expect_err("explain_missing must also check attached vault barriers");
        assert!(matches!(
            explain_err,
            mneme_datalog::Error::Store(mneme_store::Failure::BarrierAdvanced { .. })
        ));
    }
}

#[test]
fn explain_missing_expands_all_missing_derived_conjuncts_and_marks_truncation_honestly() {
    let mut harness = Harness::new();
    let e1 = indexed_rid(1);
    harness.add_entity(EntitySeed {
        key: "e1",
        id: e1,
        label: "Target",
    });

    let sym = |name: &str| constant(mneme_core::Value::symbol(name));
    let rules = bundle(
        vec![
            mneme_datalog::Rule::new(
                "r-left",
                atom("left_ok", vec![var("x")]),
                vec![mneme_datalog::Literal::Positive(atom(
                    "relation",
                    vec![sym("has_left"), var("x"), constant(e1.to_value())],
                ))],
            ),
            mneme_datalog::Rule::new(
                "r-right",
                atom("right_ok", vec![var("x")]),
                vec![mneme_datalog::Literal::Positive(atom(
                    "relation",
                    vec![sym("has_right"), var("x"), constant(e1.to_value())],
                ))],
            ),
            mneme_datalog::Rule::new(
                "r-both",
                atom("both_ok", vec![var("x")]),
                vec![
                    mneme_datalog::Literal::Positive(atom("left_ok", vec![var("x")])),
                    mneme_datalog::Literal::Positive(atom("right_ok", vec![var("x")])),
                ],
            ),
        ],
        &["entity", "relation"],
    );
    let build = harness.build(rules);
    let mut service = mneme_datalog::Service::new(&mut harness.workspace);

    // 1. With ample budget, BOTH missing ground derived conjuncts must be expanded.
    let full = service
        .explain_missing_build(
            &build,
            mneme_datalog::ExplainMissingRequest::ground("both_ok", vec![e1.to_value()]),
        )
        .expect("full explain");
    assert_eq!(full.status, mneme_datalog::MissingStatus::Missing);
    assert!(full.exhaustive);
    assert!(!full.truncated);
    let derived_preds: std::collections::BTreeSet<_> = full
        .reasons
        .iter()
        .filter(|reason| reason.kind == mneme_datalog::MissingReasonKind::MissingDerivedFact)
        .filter_map(|reason| reason.predicate.as_deref())
        .collect();
    assert!(derived_preds.contains("left_ok"));
    assert!(derived_preds.contains("right_ok"));

    // 2. With max_reasons = 1, second derived conjunct is truncated -> MUST report exhaustive: false!
    let mut tight = mneme_datalog::ExplainMissingRequest::ground("both_ok", vec![e1.to_value()]);
    tight.limits.max_reasons = 1;
    let truncated = service
        .explain_missing_build(&build, tight)
        .expect("truncated explain");
    assert!(
        truncated.truncated,
        "omitting a second missing derived conjunct must mark truncated = true"
    );
    assert!(
        !truncated.exhaustive,
        "omitting a second missing derived conjunct must mark exhaustive = false"
    );
    assert_eq!(truncated.status, mneme_datalog::MissingStatus::BudgetCutoff);
}
