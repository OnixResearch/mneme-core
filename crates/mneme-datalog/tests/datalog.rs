//! Datalog projection behavior over real committed snapshots.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::expect_used)]

fn scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
}

fn other_scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "birch").expect("scope")
}

fn rid(byte: u8) -> mneme_core::RecordId {
    mneme_core::RecordId::from_bytes([byte; 16])
}

fn rev(byte: u8) -> mneme_core::RevisionId {
    mneme_core::RevisionId::from_bytes([byte; 16])
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
    builds: std::collections::BTreeMap<String, mneme_datalog::Build>,
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
        Harness {
            temp,
            workspace,
            builds: std::collections::BTreeMap::new(),
        }
    }

    fn commit(
        &mut self,
        key: &str,
        records: Vec<mneme_store::RecordDraft>,
        blobs: Vec<mneme_store::SourceBlobDraft>,
    ) -> mneme_store::CommitOutcome {
        let scope = records
            .first()
            .map(|record| record.scope.clone())
            .unwrap_or_else(scope);
        self.workspace
            .commit(mneme_store::CommitCommand {
                base: self.workspace.current_revision().expect("base"),
                actor: "datalog-test".to_owned(),
                scope,
                idempotency_key: key.to_owned(),
                records,
                source_blobs: blobs,
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("commit")
    }

    fn add_entity(
        &mut self,
        key: &str,
        id: mneme_core::RecordId,
        scope: &mneme_core::ScopeId,
        label: &str,
    ) {
        self.commit(
            key,
            vec![mneme_store::RecordDraft {
                schema_version: 1,
                kind: mneme_core::RecordKind::Entity,
                record_id: id,
                revision_id: rev(id.as_bytes()[0]),
                predecessor: None,
                scope: scope.clone(),
                payload: entity_payload(label),
            }],
            Vec::new(),
        );
    }

    fn add_relation(
        &mut self,
        key: &str,
        id: mneme_core::RecordId,
        scope: &mneme_core::ScopeId,
        from: mneme_core::RecordId,
        to: mneme_core::RecordId,
    ) {
        self.commit(
            key,
            vec![mneme_store::RecordDraft {
                schema_version: 1,
                kind: mneme_core::RecordKind::Relation,
                record_id: id,
                revision_id: rev(id.as_bytes()[0].wrapping_add(0x40)),
                predecessor: None,
                scope: scope.clone(),
                payload: relation_payload(from, to),
            }],
            Vec::new(),
        );
    }

    fn request(&self, bundle: mneme_datalog::RuleBundle, limits: mneme_datalog::Limits) -> Request {
        Request {
            revision: self.workspace.current_revision().expect("revision"),
            bundle,
            limits,
            publish: false,
            incomplete_extents: std::collections::BTreeSet::new(),
            cancellation: None,
            access: mneme_memory::Access::Operator,
            at: None,
        }
    }

    fn run(&mut self, request: Request) -> mneme_datalog::Build {
        let mut service = mneme_datalog::Service::new(&mut self.workspace);
        let build = service
            .build(mneme_datalog::BuildRequest {
                actor: "datalog-test".to_owned(),
                scope: scope(),
                revision: request.revision,
                bundle: request.bundle,
                limits: request.limits,
                publish: request.publish,
                incomplete_extents: request.incomplete_extents,
                cancellation: request.cancellation,
                access: request.access,
                at: request.at,
            })
            .expect("build");
        self.builds
            .insert(build.context().projection_build_id.clone(), build.clone());
        build
    }

    fn build(&mut self, bundle: mneme_datalog::RuleBundle, publish: bool) -> mneme_datalog::Build {
        let mut request = self.request(bundle, limits());
        request.publish = publish;
        self.run(request)
    }

    fn build_at(
        &mut self,
        bundle: mneme_datalog::RuleBundle,
        at: mneme_core::Timestamp,
    ) -> mneme_datalog::Build {
        let mut request = self.request(bundle, limits());
        request.at = Some(at);
        self.run(request)
    }

    fn build_with_limits(
        &mut self,
        bundle: mneme_datalog::RuleBundle,
        limits: mneme_datalog::Limits,
    ) -> mneme_datalog::Build {
        let request = self.request(bundle, limits);
        self.run(request)
    }

    fn build_at_revision(
        &mut self,
        bundle: mneme_datalog::RuleBundle,
        revision: mneme_core::WorkspaceRevisionId,
    ) -> mneme_datalog::Build {
        let mut request = self.request(bundle, limits());
        request.revision = revision;
        self.run(request)
    }

    fn query(
        &mut self,
        build_id: &str,
        predicate: &str,
        constants: Vec<Option<mneme_core::Value>>,
    ) -> mneme_datalog::QueryResult {
        let build = self
            .builds
            .get(build_id)
            .cloned()
            .expect("build in harness");
        let mut service = mneme_datalog::Service::new(&mut self.workspace);
        service
            .query_build(
                &build,
                mneme_datalog::Query {
                    predicate: predicate.to_owned(),
                    constants,
                    limit: 100,
                    allow_stale: false,
                    cancellation: None,
                },
            )
            .expect("query")
    }
}

/// A build request with the harness defaults.
struct Request {
    revision: mneme_core::WorkspaceRevisionId,
    bundle: mneme_datalog::RuleBundle,
    limits: mneme_datalog::Limits,
    publish: bool,
    incomplete_extents: std::collections::BTreeSet<String>,
    cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    access: mneme_memory::Access,
    at: Option<mneme_core::Timestamp>,
}

fn entity_payload(label: &str) -> mneme_core::Payload {
    mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("entity-type"),
            mneme_core::Value::symbol("project"),
        ),
        (
            mneme_core::Symbol::from("label"),
            mneme_core::Value::string(label.to_owned()),
        ),
        (
            mneme_core::Symbol::from("properties"),
            mneme_core::Value::dictionary([]),
        ),
    ])
}

fn relation_payload(from: mneme_core::RecordId, to: mneme_core::RecordId) -> mneme_core::Payload {
    mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("relation-type"),
            mneme_core::Value::symbol("depends"),
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

fn path_bundle() -> mneme_datalog::RuleBundle {
    bundle(
        vec![
            mneme_datalog::Rule::new(
                "edge",
                atom("path", vec![var("x"), var("y")]),
                vec![mneme_datalog::Literal::Positive(atom(
                    "relation",
                    vec![
                        constant(mneme_core::Value::symbol("depends")),
                        var("x"),
                        var("y"),
                    ],
                ))],
            ),
            mneme_datalog::Rule::new(
                "reach",
                atom("path", vec![var("x"), var("y")]),
                vec![
                    mneme_datalog::Literal::Positive(atom("path", vec![var("x"), var("z")])),
                    mneme_datalog::Literal::Positive(atom(
                        "relation",
                        vec![
                            constant(mneme_core::Value::symbol("depends")),
                            var("z"),
                            var("y"),
                        ],
                    )),
                ],
            ),
        ],
        &["relation"],
    )
}

/// The claims profile: `claim(subject, value)` over accepted affirmative claims.
fn claims_bundle() -> mneme_datalog::RuleBundle {
    mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "claims".to_owned(),
        version: "1".to_owned(),
        schema_version: 3,
        base_predicates: std::collections::BTreeMap::from([("assertion".to_owned(), 4)]),
        complete_predicates: std::collections::BTreeSet::from(["assertion".to_owned()]),
        rules: vec![mneme_datalog::Rule::new(
            "claim",
            atom("claim", vec![var("subject"), var("value")]),
            vec![mneme_datalog::Literal::Positive(atom(
                "assertion",
                vec![
                    var("subject"),
                    constant(mneme_core::Value::symbol("claim")),
                    var("value"),
                    var("id"),
                ],
            ))],
        )],
    })
}

fn add_graph(harness: &mut Harness) {
    harness.add_entity("entity-a", rid(0x10), &scope(), "A");
    harness.add_entity("entity-b", rid(0x11), &scope(), "B");
    harness.add_entity("entity-c", rid(0x12), &scope(), "C");
    harness.add_relation("edge-ab", rid(0x20), &scope(), rid(0x10), rid(0x11));
    harness.add_relation("edge-bc", rid(0x21), &scope(), rid(0x11), rid(0x12));
}

fn assert_missing(path: &std::path::Path) {
    assert!(!path.exists(), "expected {} absent", path.display());
}

fn support_policy() -> mneme_retention::Policy {
    mneme_retention::Policy {
        version: mneme_retention::POLICY_VERSION.to_owned(),
        retain_assertion_after_prune: true,
        block_content_replay: true,
        retain_withdrawn_evidence_metadata: true,
    }
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
        policy: support_policy(),
    }
}

fn support_evidence(sources: bool) -> Vec<mneme_store::RecordDraft> {
    let span = mneme_core::SourceSpan::new(0, 10).expect("span");
    let mut evidence = vec![mneme_memory::build_evidence(
        rid(0x30),
        rev(0x31),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: rid(0x40),
            source: rid(0x20),
            source_revision: rev(0x21),
            span: Some(span),
            anchor: Some("a"),
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    )];
    if sources {
        evidence.push(mneme_memory::build_evidence(
            rid(0x32),
            rev(0x33),
            &scope(),
            mneme_memory::EvidenceOptions {
                assertion: rid(0x40),
                source: rid(0x22),
                source_revision: rev(0x23),
                span: Some(span),
                anchor: Some("b"),
                relation: mneme_memory::SupportRelation::Supports,
                origin: mneme_core::Origin::AuthoredStatement,
                ancestry: &[],
            },
        ));
    }
    evidence
}

fn add_support_sources(harness: &mut Harness, sources: bool) {
    let source_a = b"= Source A\n\nExact source A.\n";
    let source_b = b"= Source B\n\nExact source B.\n";
    let (source_record, source_blob) = mneme_memory::build_source(
        rid(0x20),
        rev(0x21),
        &scope(),
        mneme_memory::SourceOptions {
            bytes: source_a,
            media_type: "text/asciidoc",
            entity: Some(rid(0x10)),
            path_hint: Some("a.adoc"),
        },
    )
    .expect("source a");
    let mut records = vec![source_record];
    let mut blobs = vec![source_blob];
    if sources {
        let (source_record_b, source_blob_b) = mneme_memory::build_source(
            rid(0x22),
            rev(0x23),
            &scope(),
            mneme_memory::SourceOptions {
                bytes: source_b,
                media_type: "text/asciidoc",
                entity: Some(rid(0x10)),
                path_hint: Some("b.adoc"),
            },
        )
        .expect("source b");
        records.push(source_record_b);
        blobs.push(source_blob_b);
    }
    harness.commit("sources", records, blobs);
}

fn accept_support_assertion(harness: &mut Harness) {
    let current = harness
        .workspace
        .record_revisions(rid(0x40))
        .expect("assertion")
        .into_iter()
        .last()
        .expect("assertion revision");
    let decision = mneme_memory::build_decision(
        rid(0x50),
        rev(0x51),
        &scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: rid(0x40),
            actor: "datalog-test",
            policy: "datalog-policy/v1",
            input_revision: harness.workspace.current_revision().expect("base"),
            outcome: "accepted",
            rationale: "datalog fixture",
            evidence: &[],
            related: &[],
        },
    );
    let accepted = mneme_memory::build_assertion_revision(
        &current,
        rev(0x42),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(rid(0x50), mneme_core::RecordKind::Decision),
        None,
    );
    harness.commit("accept", vec![decision, accepted], Vec::new());
}

#[allow(unknown_lints)] // Octet structural exception: cohesive fixture builder
fn add_assertion_support(harness: &mut Harness, sources: bool) -> mneme_core::RecordId {
    harness.add_entity("assertion-entity", rid(0x10), &scope(), "A");
    add_support_sources(harness, sources);
    let evidence = support_evidence(sources);
    let evidence_refs = evidence
        .iter()
        .map(|record| {
            mneme_core::Reference::local(record.record_id, mneme_core::RecordKind::Evidence)
        })
        .collect::<Vec<_>>();
    let assertion = mneme_memory::build_proposed_assertion(
        rid(0x40),
        rev(0x41),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: rid(0x10),
            predicate: "claim",
            value: mneme_core::Value::string("retained"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &evidence_refs,
            extraction: None,
            superseded_by: None,
        },
    );
    harness.commit(
        "evidence",
        evidence
            .into_iter()
            .chain(std::iter::once(assertion))
            .collect(),
        Vec::new(),
    );
    accept_support_assertion(harness);
    rid(0x40)
}

/// One accepted assertion with its own evidence source, committed in the
/// memory lifecycle order: proposal and evidence, then decision and acceptance
/// in the same batch by the batch actor against the replaced revision.
struct AssertionSpec {
    record: u8,
    revision: u8,
    accepted_revision: u8,
    decision: u8,
    decision_revision: u8,
    evidence: u8,
    evidence_revision: u8,
    source: u8,
    source_revision: u8,
    subject: u8,
    predicate: &'static str,
    value: mneme_core::Value,
    stance: mneme_memory::Stance,
    valid_time: mneme_core::ValidTime,
    declared_complete: bool,
}

fn add_assertions(harness: &mut Harness, specs: &[AssertionSpec]) {
    commit_assertion_sources(harness, specs);
    commit_assertion_proposals(harness, specs);
    commit_assertion_acceptances(harness, specs);
}

/// Commit one evidence source record and its stored blob per spec.
fn commit_assertion_sources(harness: &mut Harness, specs: &[AssertionSpec]) {
    let mut source_records = Vec::with_capacity(specs.len());
    let mut source_blobs = Vec::with_capacity(specs.len());
    for spec in specs {
        let bytes = format!(
            "= Source {}\n\nExact evidence bytes for source {}.\n",
            spec.source, spec.source
        )
        .into_bytes();
        let (record, blob) = mneme_memory::build_source(
            rid(spec.source),
            rev(spec.source_revision),
            &scope(),
            mneme_memory::SourceOptions {
                bytes: bytes.as_slice(),
                media_type: "text/asciidoc",
                entity: None,
                path_hint: None,
            },
        )
        .expect("source");
        source_records.push(record);
        source_blobs.push(blob);
    }
    harness.commit("assertion-sources", source_records, source_blobs);
}

/// Commit the evidence and proposed assertion records of every spec.
fn commit_assertion_proposals(harness: &mut Harness, specs: &[AssertionSpec]) {
    let span = mneme_core::SourceSpan::new(0, 10).expect("span");
    // Two records per spec: its evidence and its proposed assertion.
    let mut proposals = Vec::with_capacity(specs.len().saturating_mul(2));
    for spec in specs {
        proposals.push(mneme_memory::build_evidence(
            rid(spec.evidence),
            rev(spec.evidence_revision),
            &scope(),
            mneme_memory::EvidenceOptions {
                assertion: rid(spec.record),
                source: rid(spec.source),
                source_revision: rev(spec.source_revision),
                span: Some(span),
                anchor: None,
                relation: mneme_memory::SupportRelation::Supports,
                origin: mneme_core::Origin::AuthoredStatement,
                ancestry: &[],
            },
        ));
        let mut assertion = mneme_memory::build_proposed_assertion(
            rid(spec.record),
            rev(spec.revision),
            &scope(),
            mneme_memory::ProposedAssertionOptions {
                subject: rid(spec.subject),
                predicate: spec.predicate,
                value: spec.value.clone(),
                stance: spec.stance,
                origin: mneme_core::Origin::AuthoredStatement,
                asserted_by: "author",
                valid_time: spec.valid_time,
                evidence: &[mneme_core::Reference::local(
                    rid(spec.evidence),
                    mneme_core::RecordKind::Evidence,
                )],
                extraction: None,
                superseded_by: None,
            },
        );
        if spec.declared_complete {
            assertion.payload.insert(
                mneme_core::Symbol::from("completeness"),
                mneme_core::Value::symbol("declared-complete"),
            );
        }
        proposals.push(assertion);
    }
    harness.commit("assertion-proposals", proposals, Vec::new());
}

/// Commit the acceptance decision and accepted revision of every spec.
fn commit_assertion_acceptances(harness: &mut Harness, specs: &[AssertionSpec]) {
    let base = harness.workspace.current_revision().expect("base");
    // Two records per spec: its acceptance decision and its accepted revision.
    let mut acceptance = Vec::with_capacity(specs.len().saturating_mul(2));
    for spec in specs {
        let proposal = harness
            .workspace
            .record_revisions(rid(spec.record))
            .expect("proposal")
            .into_iter()
            .last()
            .expect("proposal revision");
        acceptance.push(mneme_memory::build_decision(
            rid(spec.decision),
            rev(spec.decision_revision),
            &scope(),
            mneme_memory::DecisionOptions {
                kind: mneme_memory::DecisionKind::Acceptance,
                target: rid(spec.record),
                actor: "datalog-test",
                policy: "datalog-policy/v1",
                input_revision: base,
                outcome: "accepted",
                rationale: "datalog fixture",
                evidence: &[],
                related: &[],
            },
        ));
        acceptance.push(mneme_memory::build_assertion_revision(
            &proposal,
            rev(spec.accepted_revision),
            mneme_core::Lifecycle::Accepted,
            mneme_core::Reference::local(rid(spec.decision), mneme_core::RecordKind::Decision),
            None,
        ));
    }
    harness.commit("assertion-acceptance", acceptance, Vec::new());
}

/// One assertion fixture from a slot number, so record and revision identities
/// never collide. Several slots' records are committed in one batch, and the
/// store refuses a batch that repeats a revision id.
///
/// record ids: assertions 0x40+, decisions 0x50+, evidence 0x70+, sources 0x80+.
/// revision ids: proposals 0x41+, accepted 0x42+, decisions 0x51+, evidence
/// 0x71+, sources 0x81+ — each offset by the slot.
fn affirmation(
    slot: u8,
    subject: u8,
    predicate: &'static str,
    value: mneme_core::Value,
) -> AssertionSpec {
    let offset = slot.saturating_mul(4);
    AssertionSpec {
        record: 0x40 + offset,
        revision: 0x41 + offset,
        accepted_revision: 0x42 + offset,
        decision: 0x50 + offset,
        decision_revision: 0x51 + offset,
        evidence: 0x70 + offset,
        evidence_revision: 0x71 + offset,
        source: 0x80 + offset,
        source_revision: 0x81 + offset,
        subject,
        predicate,
        value,
        stance: mneme_memory::Stance::Affirm,
        valid_time: mneme_core::ValidTime::always(),
        declared_complete: false,
    }
}

#[test]
fn positive_recursive_paths_are_scoped_to_the_pinned_revision() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    // Excluded scope: C -> D with D outside the authorized scope.
    harness.add_entity("entity-d", rid(0x13), &other_scope(), "D");
    harness.add_relation("edge-cd", rid(0x22), &other_scope(), rid(0x12), rid(0x13));
    let build = harness.build(path_bundle(), false);
    assert_eq!(build.status(), mneme_datalog::ExecutionStatus::Complete);
    assert_eq!(build.context().scope, scope());
    let build_id = build.context().projection_build_id.clone();
    let result = harness.query(&build_id, "path", vec![]);
    assert_eq!(result.status, mneme_datalog::ExecutionStatus::Complete);
    assert!(result.exhaustive);
    assert_eq!(result.rows.len(), 3);
    assert!(
        result
            .rows
            .iter()
            .all(|row| { row.values != vec![rid(0x10).to_value(), rid(0x13).to_value()] })
    );
    let exact = harness.query(
        &build_id,
        "path",
        vec![Some(rid(0x10).to_value()), Some(rid(0x12).to_value())],
    );
    assert_eq!(exact.rows.len(), 1);
    let support = exact.rows[0].supports.first().expect("derived support");
    // A derived premise names the records it rests on rather than pretending to
    // be one of them.
    let recursion = support
        .premises
        .iter()
        .find(|premise| premise.predicate == "path")
        .expect("recursive premise");
    assert_eq!(recursion.canonical, None);
    let roots = support
        .premises
        .iter()
        .flat_map(|premise| premise.canonical_roots.iter().copied())
        .chain(
            support
                .premises
                .iter()
                .filter_map(|premise| premise.canonical),
        )
        .collect::<std::collections::BTreeSet<_>>();
    assert!(roots.contains(&rid(0x20)));
    assert!(roots.contains(&rid(0x21)));
    assert!(exact.rows[0].supports.iter().all(|support| {
        support
            .premises
            .iter()
            .all(|premise| premise.canonical.is_some() || !premise.canonical_roots.is_empty())
    }));
}

#[test]
fn unsafe_forbidden_non_stratified_and_schema_rules_are_rejected() {
    let unsafe_rule = mneme_datalog::Rule::new(
        "unsafe",
        atom("out", vec![var("x")]),
        vec![mneme_datalog::Literal::Positive(atom(
            "relation",
            vec![
                constant(mneme_core::Value::symbol("depends")),
                constant(rid(0x10).to_value()),
                var("y"),
            ],
        ))],
    );
    let forbidden = mneme_datalog::Rule::new(
        "forbidden",
        atom("out", vec![var("x")]),
        vec![
            mneme_datalog::Literal::Positive(atom(
                "relation",
                vec![
                    constant(mneme_core::Value::symbol("depends")),
                    var("x"),
                    var("y"),
                ],
            )),
            mneme_datalog::Literal::Forbidden("read-file".to_owned()),
        ],
    );
    let negative = mneme_datalog::Rule::new(
        "negative",
        atom("p", vec![var("x")]),
        vec![
            mneme_datalog::Literal::Positive(atom(
                "relation",
                vec![
                    constant(mneme_core::Value::symbol("depends")),
                    var("x"),
                    var("y"),
                ],
            )),
            mneme_datalog::Literal::Negative(atom("p", vec![var("x")])),
        ],
    );
    for (bundle, code) in [
        (bundle(vec![unsafe_rule], &[]), "unsafe-head-variable"),
        (bundle(vec![forbidden], &[]), "forbidden-builtin"),
        (bundle(vec![negative], &["p"]), "non-stratified"),
        (
            mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
                id: "bad".to_owned(),
                version: "1".to_owned(),
                schema_version: 0,
                base_predicates: std::collections::BTreeMap::new(),
                complete_predicates: std::collections::BTreeSet::new(),
                rules: Vec::new(),
            }),
            "schema-version",
        ),
    ] {
        let diagnostics = bundle.validate().expect_err("invalid");
        assert!(
            diagnostics.iter().any(|diagnostic| diagnostic.code == code),
            "missing {code} in {diagnostics:?}"
        );
    }
}

#[test]
fn completeness_gates_negation_and_absent_results() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let negation_rule = mneme_datalog::Rule::new(
        "isolated",
        atom("isolated", vec![var("x")]),
        vec![
            mneme_datalog::Literal::Positive(atom("entity", vec![var("x"), var("t"), var("l")])),
            mneme_datalog::Literal::Negative(atom(
                "relation",
                vec![
                    constant(mneme_core::Value::symbol("depends")),
                    var("x"),
                    var("x"),
                ],
            )),
        ],
    );
    let rule_bundle = bundle(vec![negation_rule], &["relation"]);
    let build = harness.build(rule_bundle.clone(), false);
    let result = harness.query(
        &build.context().projection_build_id,
        "isolated",
        vec![Some(rid(0x99).to_value())],
    );
    assert!(result.rows.is_empty());
    assert!(result.absence_established);
    assert_eq!(result.status, mneme_datalog::ExecutionStatus::Complete);

    let mut request = harness.request(rule_bundle, limits());
    request.incomplete_extents = std::collections::BTreeSet::from(["relation".to_owned()]);
    let incomplete = harness.run(request);
    assert_eq!(incomplete.status(), mneme_datalog::ExecutionStatus::Partial);
    let result = harness.query(
        &incomplete.context().projection_build_id,
        "isolated",
        vec![],
    );
    assert!(result.rows.is_empty());
    assert!(!result.absence_established);
    assert!(!result.exhaustive);
    assert!(result.coverage.iter().any(|coverage| {
        coverage.predicate == "isolated"
            && coverage.status == mneme_datalog::CoverageStatus::Incomplete
    }));
}

#[test]
fn aggregates_require_complete_inputs_and_return_counts() {
    let mut harness = Harness::new();
    harness.add_entity("entity-a", rid(0x10), &scope(), "A");
    harness.add_entity("entity-b", rid(0x11), &scope(), "B");
    harness.add_entity("entity-c", rid(0x12), &scope(), "C");
    harness.add_relation("ab", rid(0x20), &scope(), rid(0x10), rid(0x11));
    harness.add_relation("ac", rid(0x21), &scope(), rid(0x10), rid(0x12));
    let aggregate_rule = mneme_datalog::Rule::new(
        "degree",
        atom("degree", vec![var("x"), var("n")]),
        vec![
            mneme_datalog::Literal::Positive(atom(
                "relation",
                vec![
                    constant(mneme_core::Value::symbol("depends")),
                    var("x"),
                    var("y"),
                ],
            )),
            mneme_datalog::Literal::Aggregate {
                function: mneme_datalog::AggregateFunction::Count,
                input: var("y"),
                output: "n".to_owned(),
            },
        ],
    );
    let build = harness.build(bundle(vec![aggregate_rule], &["relation"]), false);
    let result = harness.query(
        &build.context().projection_build_id,
        "degree",
        vec![Some(rid(0x10).to_value()), None],
    );
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].values[1], mneme_core::Value::integer(2));
    assert!(!result.rows[0].supports.is_empty());
}

#[test]
fn cancellation_timeout_and_row_caps_never_establish_absence() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let mut request = harness.request(path_bundle(), limits());
    request.cancellation = Some(cancelled);
    let build = harness.run(request);
    assert_eq!(build.status(), mneme_datalog::ExecutionStatus::Cancelled);
    let result = harness.query(&build.context().projection_build_id, "path", vec![]);
    assert_eq!(result.status, mneme_datalog::ExecutionStatus::Cancelled);
    assert!(!result.absence_established);

    let timed_out = harness.build_with_limits(
        path_bundle(),
        mneme_datalog::Limits {
            max_work: 2,
            ..limits()
        },
    );
    assert_eq!(timed_out.status(), mneme_datalog::ExecutionStatus::Timeout);
    let result = harness.query(&timed_out.context().projection_build_id, "path", vec![]);
    assert_eq!(result.status, mneme_datalog::ExecutionStatus::Timeout);
    assert!(!result.absence_established);
    assert!(!result.exhaustive);
}

#[test]
fn stale_builds_require_explicit_permission_and_publication_is_registered() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let build = harness.build(path_bundle(), true);
    // The build pinned the head it was created at; later assertions compare the
    // disclosure against these observed revisions rather than reading an
    // expectation back from the context.
    let pinned = harness.workspace.current_revision().expect("pinned");
    assert_eq!(build.context().served_revision, pinned);
    assert_eq!(build.context().requested_revision, pinned);
    assert!(build.context().requested_was_head);
    let projection_name = "datalog:base:project:cedar";
    let projection = harness
        .workspace
        .projection(projection_name)
        .expect("projection")
        .expect("registered projection");
    assert_eq!(projection.revision, build.context().served_revision);
    assert_eq!(
        projection.eligibility_generation,
        build.context().eligibility_generation
    );
    assert_eq!(projection.rule_version, "1");
    assert!(
        harness
            .workspace
            .retention_participant(projection_name)
            .expect("participant")
            .is_some()
    );
    // The registration resolves as compatible for the versions the build
    // declared, including its own eligibility generation.
    let resolution = harness
        .workspace
        .resolve_projection_versions(
            projection_name,
            build.context().served_revision,
            &scope(),
            build.context().schema_version,
            &build.context().rule_bundle_version,
            mneme_datalog::INDEX_VERSION,
        )
        .expect("resolution");
    assert!(matches!(
        resolution,
        mneme_store::ProjectionResolution::Compatible(_)
    ));
    harness.add_entity("entity-d", rid(0x13), &scope(), "D");
    let stale_head = harness.workspace.current_revision().expect("head");
    assert_ne!(stale_head, pinned);
    let mut service = mneme_datalog::Service::new(&mut harness.workspace);
    let stale = service
        .query_build(&build, mneme_datalog::Query::all("path", 10))
        .expect_err("a superseded build needs explicit permission");
    // The refusal names both the revision the caller asked about and the older
    // revision the build would have served.
    assert!(
        matches!(
            &stale,
            mneme_datalog::Error::Stale { requested, served }
                if *requested == stale_head
                    && *served == pinned
                    && *requested != *served
        ),
        "the stale refusal must disclose requested and served revisions: {stale:?}"
    );
    let stale_ok = service
        .query_build(
            &build,
            mneme_datalog::Query {
                predicate: "path".to_owned(),
                constants: Vec::new(),
                limit: 10,
                allow_stale: true,
                cancellation: None,
            },
        )
        .expect("stale allowed");
    assert_eq!(stale_ok.served_revision, pinned);
    assert_eq!(
        stale_ok.requested_revision, stale_head,
        "a stale answer names the revision the caller asked about"
    );
    assert_ne!(
        stale_ok.requested_revision, stale_ok.served_revision,
        "a stale answer must disclose that the served revision differs"
    );
    assert!(stale_ok.stale, "the stale flag must be set");
    assert!(stale_ok.exhaustive);

    // A later head must be disclosed too: the cached answer for the earlier
    // request must not hide the newer requested revision.
    drop(service);
    harness.add_entity("entity-e", rid(0x14), &scope(), "E");
    let current = harness.workspace.current_revision().expect("current");
    let mut service = mneme_datalog::Service::new(&mut harness.workspace);
    let stale_again = service
        .query_build(
            &build,
            mneme_datalog::Query {
                predicate: "path".to_owned(),
                constants: Vec::new(),
                limit: 10,
                allow_stale: true,
                cancellation: None,
            },
        )
        .expect("second stale query");
    assert_eq!(stale_again.requested_revision, current);
    assert!(stale_again.stale);
    assert_eq!(stale_again.served_revision, pinned);
    assert_ne!(stale_again.requested_revision, stale_again.served_revision);
    assert_ne!(
        stale_again.requested_revision, stale_ok.requested_revision,
        "a stale query cache entry must not hide the new requested revision"
    );
}

#[test]
fn retraction_pruning_and_forget_update_datalog_support() {
    let mut harness = Harness::new();
    let assertion = add_assertion_support(&mut harness, true);
    let build = harness.build(claims_bundle(), false);
    assert_eq!(build.status(), mneme_datalog::ExecutionStatus::Complete);
    let result = harness.query(
        &build.context().projection_build_id,
        "claim",
        vec![
            Some(rid(0x10).to_value()),
            Some(mneme_core::Value::string("retained")),
        ],
    );
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].supports[0].sources.len(), 2);

    // Withdraw source A's support through the retention service.
    let base = harness.workspace.current_revision().expect("base");
    let request = retention_request(
        "withdraw-a",
        mneme_retention::OperationKind::AssertionRetraction,
        mneme_retention::Selector::SourceSupport(rid(0x20)),
        base,
    );
    mneme_retention::Engine::new(&mut harness.workspace)
        .execute(request)
        .expect("withdraw");
    let build = harness.build(claims_bundle(), false);
    let result = harness.query(
        &build.context().projection_build_id,
        "claim",
        vec![
            Some(rid(0x10).to_value()),
            Some(mneme_core::Value::string("retained")),
        ],
    );
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].supports[0].sources.len(), 1);

    // Withdraw the final support: the conclusion disappears and absence is not
    // claimed until the relation coverage is complete.
    let base = harness.workspace.current_revision().expect("base");
    let request = retention_request(
        "withdraw-b",
        mneme_retention::OperationKind::AssertionRetraction,
        mneme_retention::Selector::SourceSupport(rid(0x22)),
        base,
    );
    mneme_retention::Engine::new(&mut harness.workspace)
        .execute(request)
        .expect("withdraw b");
    let build = harness.build(claims_bundle(), false);
    let result = harness.query(
        &build.context().projection_build_id,
        "claim",
        vec![
            Some(rid(0x10).to_value()),
            Some(mneme_core::Value::string("retained")),
        ],
    );
    assert!(result.rows.is_empty());
    assert!(
        result.absence_established,
        "the complete claim relation now contains no eligible support"
    );

    // Source pruning leaves the claim eligible by policy but marks the source
    // unavailable: the bytes are gone, the provenance is not.
    let mut harness = Harness::new();
    add_assertion_support(&mut harness, false);
    let base = harness.workspace.current_revision().expect("base");
    let prune = retention_request(
        "prune-a",
        mneme_retention::OperationKind::SourcePruning,
        mneme_retention::Selector::Source(rid(0x20)),
        base,
    );
    let source_blob = mneme_store::payload::blob_path(
        harness.temp.path(),
        mneme_core::ContentDigest::of_source_bytes(b"= Source A\n\nExact source A.\n"),
    );
    mneme_retention::Engine::new(&mut harness.workspace)
        .execute(prune)
        .expect("prune");
    assert_missing(&source_blob);
    let build = harness.build(claims_bundle(), false);
    let result = harness.query(
        &build.context().projection_build_id,
        "claim",
        vec![
            Some(rid(0x10).to_value()),
            Some(mneme_core::Value::string("retained")),
        ],
    );
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.status, mneme_datalog::ExecutionStatus::Complete);
    assert!(
        result.rows[0].supports[0]
            .premises
            .iter()
            .any(|premise| { premise.source_availability.as_deref() == Some("pruned") }),
        "the surviving claim must disclose the pruned source: {:?}",
        result.rows[0].supports[0].premises
    );
    let _ = assertion;
}

#[test]
fn query_row_limit_is_non_exhaustive() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let build = harness.build(path_bundle(), false);
    let mut service = mneme_datalog::Service::new(&mut harness.workspace);
    let result = service
        .query_build(
            &build,
            mneme_datalog::Query {
                predicate: "path".to_owned(),
                constants: Vec::new(),
                limit: 1,
                allow_stale: false,
                cancellation: None,
            },
        )
        .expect("limited query");
    assert_eq!(result.rows.len(), 1);
    assert!(result.truncated);
    assert!(!result.exhaustive);
    assert!(!result.absence_established);
}

#[test]
fn explicit_forget_invalidates_builds_and_prevents_replay_rows() {
    let mut harness = Harness::new();
    add_assertion_support(&mut harness, false);
    let old_build = harness.build(claims_bundle(), false);
    let old_build_id = old_build.context().projection_build_id.clone();
    let result = harness.query(
        &old_build_id,
        "claim",
        vec![
            Some(rid(0x10).to_value()),
            Some(mneme_core::Value::string("retained")),
        ],
    );
    assert_eq!(result.rows.len(), 1);

    let base = harness.workspace.current_revision().expect("base");
    let request = retention_request(
        "forget-a",
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        base,
    );
    mneme_retention::Engine::new(&mut harness.workspace)
        .execute(request)
        .expect("forget");
    let build = harness.build(claims_bundle(), false);
    let result = harness.query(
        &build.context().projection_build_id,
        "claim",
        vec![
            Some(rid(0x10).to_value()),
            Some(mneme_core::Value::string("retained")),
        ],
    );
    assert!(result.rows.is_empty());
    assert!(result.absence_established);

    let mut service = mneme_datalog::Service::new(&mut harness.workspace);
    assert!(matches!(
        service.publish_build(&old_build),
        Err(mneme_datalog::Error::Store(
            mneme_store::Failure::BarrierAdvanced { .. }
        ))
    ));
    let stale = service.query_build(&old_build, mneme_datalog::Query::all("claim", 100));
    assert!(matches!(
        stale,
        Err(mneme_datalog::Error::Store(
            mneme_store::Failure::BarrierAdvanced { .. }
        ))
    ));
}

#[test]
fn support_budget_truncation_is_explicit() {
    let mut harness = Harness::new();
    harness.add_entity("a", rid(0x10), &scope(), "A");
    harness.add_entity("b", rid(0x11), &scope(), "B");
    harness.add_relation("first", rid(0x20), &scope(), rid(0x10), rid(0x11));
    harness.add_relation("second", rid(0x21), &scope(), rid(0x10), rid(0x11));
    let build = harness.build_with_limits(
        bundle(
            vec![mneme_datalog::Rule::new(
                "edge",
                atom("path", vec![var("x"), var("y")]),
                vec![mneme_datalog::Literal::Positive(atom(
                    "relation",
                    vec![
                        constant(mneme_core::Value::symbol("depends")),
                        var("x"),
                        var("y"),
                    ],
                ))],
            )],
            &["relation"],
        ),
        mneme_datalog::Limits {
            max_supports_per_fact: 1,
            ..limits()
        },
    );
    assert!(build.support_truncated());
    let result = harness.query(&build.context().projection_build_id, "relation", vec![]);
    assert_eq!(result.rows.len(), 1);
    assert!(result.rows[0].support_truncated);
}

#[test]
fn query_build_returns_explicit_context_and_no_absence_on_unrelated_partial_build() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let rule_bundle = bundle(
        vec![mneme_datalog::Rule::new(
            "edge",
            atom("path", vec![var("x"), var("y")]),
            vec![mneme_datalog::Literal::Positive(atom(
                "relation",
                vec![
                    constant(mneme_core::Value::symbol("depends")),
                    var("x"),
                    var("y"),
                ],
            ))],
        )],
        &["relation"],
    );
    let mut request = harness.request(rule_bundle, limits());
    request.incomplete_extents = std::collections::BTreeSet::from(["source".to_owned()]);
    let build = harness.run(request);
    assert_eq!(build.status(), mneme_datalog::ExecutionStatus::Partial);
    let result = harness.query(&build.context().projection_build_id, "path", vec![]);
    assert_eq!(result.status, mneme_datalog::ExecutionStatus::Complete);
    assert!(result.exhaustive);
}

#[test]
fn query_summary_serialization_distinguishes_complete_incomplete_and_truncated() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let complete_build = harness.build(path_bundle(), false);
    let complete = harness.query(
        &complete_build.context().projection_build_id,
        "path",
        vec![Some(rid(0x99).to_value()), Some(rid(0x98).to_value())],
    );
    assert!(complete.absence_established);
    let truncated = {
        let build = harness
            .builds
            .get(&complete_build.context().projection_build_id)
            .cloned()
            .expect("cached build");
        let mut service = mneme_datalog::Service::new(&mut harness.workspace);
        service
            .query_build(&build, mneme_datalog::Query::all("path", 1))
            .expect("truncated query")
    };
    let negation_rule = mneme_datalog::Rule::new(
        "isolated",
        atom("isolated", vec![var("x")]),
        vec![
            mneme_datalog::Literal::Positive(atom("entity", vec![var("x"), var("t"), var("l")])),
            mneme_datalog::Literal::Negative(atom(
                "relation",
                vec![
                    constant(mneme_core::Value::symbol("depends")),
                    var("x"),
                    var("x"),
                ],
            )),
        ],
    );
    let mut request = harness.request(bundle(vec![negation_rule], &["relation"]), limits());
    request.incomplete_extents = std::collections::BTreeSet::from(["relation".to_owned()]);
    let incomplete_build = harness.run(request);
    let incomplete = harness.query(
        &incomplete_build.context().projection_build_id,
        "isolated",
        vec![],
    );

    let complete_bytes = mneme_core::binary::encode(&complete.summary_value());
    let incomplete_bytes = mneme_core::binary::encode(&incomplete.summary_value());
    let truncated_bytes = mneme_core::binary::encode(&truncated.summary_value());
    assert_ne!(complete_bytes, incomplete_bytes);
    assert_ne!(complete_bytes, truncated_bytes);
    assert_ne!(incomplete_bytes, truncated_bytes);
    assert!(truncated.truncated);
    assert!(!truncated.exhaustive);
    assert!(!truncated.absence_established);
    assert!(!incomplete.exhaustive);
    assert!(!incomplete.absence_established);
    assert!(complete.exhaustive);
}

#[test]
fn invalid_or_stale_publication_never_replaces_the_registered_projection() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let projection_name = format!("datalog:base:{}", scope());
    assert!(
        harness
            .workspace
            .projection(&projection_name)
            .expect("projection lookup")
            .is_none()
    );
    let unsafe_bundle = bundle(
        vec![mneme_datalog::Rule::new(
            "unsafe",
            atom("out", vec![var("unbound")]),
            vec![mneme_datalog::Literal::Positive(atom(
                "relation",
                vec![
                    constant(mneme_core::Value::symbol("depends")),
                    var("x"),
                    var("y"),
                ],
            ))],
        )],
        &[],
    );
    {
        let mut request = harness.request(unsafe_bundle, limits());
        request.publish = true;
        let mut service = mneme_datalog::Service::new(&mut harness.workspace);
        let invalid = service.build(mneme_datalog::BuildRequest {
            actor: "datalog-test".to_owned(),
            scope: scope(),
            revision: request.revision,
            bundle: request.bundle,
            limits: request.limits,
            publish: true,
            incomplete_extents: std::collections::BTreeSet::new(),
            cancellation: None,
            access: mneme_memory::Access::Operator,
            at: None,
        });
        assert!(matches!(
            invalid,
            Err(mneme_datalog::Error::InvalidBundle(_))
        ));
    }
    assert!(
        harness
            .workspace
            .projection(&projection_name)
            .expect("projection lookup")
            .is_none()
    );
    let revision = harness.workspace.current_revision().expect("revision");
    let build = {
        let mut service = mneme_datalog::Service::new(&mut harness.workspace);
        let build = service
            .build(mneme_datalog::BuildRequest {
                actor: "datalog-test".to_owned(),
                scope: scope(),
                revision,
                bundle: path_bundle(),
                limits: limits(),
                publish: false,
                incomplete_extents: std::collections::BTreeSet::new(),
                cancellation: None,
                access: mneme_memory::Access::Operator,
                at: None,
            })
            .expect("private build");
        service.publish_build(&build).expect("publish");
        build
    };
    let published = harness
        .workspace
        .projection(&projection_name)
        .expect("projection lookup")
        .expect("published projection");
    assert_eq!(published.revision, build.context().served_revision);
    harness
        .workspace
        .advance_eligibility_barrier()
        .expect("advance barrier");
    {
        let mut service = mneme_datalog::Service::new(&mut harness.workspace);
        assert!(matches!(
            service.publish_build(&build),
            Err(mneme_datalog::Error::Store(
                mneme_store::Failure::BarrierAdvanced { .. }
            ))
        ));
    }
    let unchanged = harness
        .workspace
        .projection(&projection_name)
        .expect("projection lookup")
        .expect("existing projection");
    assert_eq!(unchanged.revision, published.revision);
}

#[test]
fn recursion_depth_exhaustion_is_partial_and_non_exhaustive() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let build = harness.build_with_limits(
        path_bundle(),
        mneme_datalog::Limits {
            max_recursion_depth: 0,
            ..limits()
        },
    );
    assert_eq!(build.status(), mneme_datalog::ExecutionStatus::Partial);
    let result = harness.query(&build.context().projection_build_id, "path", vec![]);
    assert!(!result.exhaustive);
    assert!(!result.absence_established);
    assert!(result.coverage.iter().any(|coverage| {
        coverage.predicate == "path" && coverage.status == mneme_datalog::CoverageStatus::Incomplete
    }));
}

#[test]
fn build_identity_binds_limits_incomplete_extents_and_time() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let revision = harness.workspace.current_revision().expect("revision");
    let mut service = mneme_datalog::Service::new(&mut harness.workspace);
    let request = |limits: mneme_datalog::Limits,
                   incomplete: std::collections::BTreeSet<String>,
                   at: Option<mneme_core::Timestamp>| {
        mneme_datalog::BuildRequest {
            actor: "datalog-test".to_owned(),
            scope: scope(),
            revision,
            bundle: path_bundle(),
            limits,
            publish: false,
            incomplete_extents: incomplete,
            cancellation: None,
            access: mneme_memory::Access::Operator,
            at,
        }
    };
    let default = service
        .build(request(limits(), std::collections::BTreeSet::new(), None))
        .expect("default build");
    let timed = service
        .build(request(
            mneme_datalog::Limits {
                max_work: 0,
                ..limits()
            },
            std::collections::BTreeSet::new(),
            None,
        ))
        .expect("different-limit build");
    let incomplete = service
        .build(request(
            limits(),
            std::collections::BTreeSet::from(["relation".to_owned()]),
            None,
        ))
        .expect("incomplete build");
    let timed_at = service
        .build(request(
            limits(),
            std::collections::BTreeSet::new(),
            Some(mneme_core::Timestamp::from_nanos(500)),
        ))
        .expect("effective-time build");
    assert_ne!(
        default.context().projection_build_id,
        timed.context().projection_build_id
    );
    assert_ne!(
        default.context().projection_build_id,
        incomplete.context().projection_build_id
    );
    assert_ne!(
        timed.context().projection_build_id,
        incomplete.context().projection_build_id
    );
    assert_ne!(
        default.context().projection_build_id,
        timed_at.context().projection_build_id
    );
}

#[test]
fn terminal_failures_are_recomputed_and_never_published() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let revision = harness.workspace.current_revision().expect("revision");
    let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let mut service = mneme_datalog::Service::new(&mut harness.workspace);
    let build_request =
        |publish: bool, cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>| {
            mneme_datalog::BuildRequest {
                actor: "datalog-test".to_owned(),
                scope: scope(),
                revision,
                bundle: path_bundle(),
                limits: limits(),
                publish,
                incomplete_extents: std::collections::BTreeSet::new(),
                cancellation,
                access: mneme_memory::Access::Operator,
                at: None,
            }
        };
    let first = service
        .build(build_request(false, Some(cancelled.clone())))
        .expect("cancelled build");
    assert_eq!(first.status(), mneme_datalog::ExecutionStatus::Cancelled);
    let retried = service
        .build(build_request(false, None))
        .expect("retry build");
    assert_eq!(retried.status(), mneme_datalog::ExecutionStatus::Complete);
    assert!(matches!(
        service.build(build_request(true, Some(cancelled))),
        Err(mneme_datalog::Error::Failed(_))
    ));
    drop(service);
    assert!(
        harness
            .workspace
            .projection("datalog:base:project:cedar")
            .expect("projection lookup")
            .is_none()
    );
}

#[test]
fn accepted_denial_is_not_an_affirmative_claim() {
    let mut harness = Harness::new();
    harness.add_entity("assertion-entity", rid(0x10), &scope(), "A");
    add_assertions(
        &mut harness,
        &[AssertionSpec {
            declared_complete: true,
            stance: mneme_memory::Stance::Deny,
            ..affirmation(0, 0x10, "claim", mneme_core::Value::string("retained"))
        }],
    );
    let build = harness.build(claims_bundle(), false);
    let build_id = build.context().projection_build_id.clone();
    let denied = harness.query(
        &build_id,
        "claim",
        vec![
            Some(rid(0x10).to_value()),
            Some(mneme_core::Value::string("retained")),
        ],
    );
    assert!(
        denied.rows.is_empty(),
        "accepted denial projected as an affirmative claim"
    );
    // The denial is represented, just not as an affirmative claim.
    let denial_bundle = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "denials".to_owned(),
        version: "1".to_owned(),
        schema_version: 3,
        base_predicates: std::collections::BTreeMap::from([("denial".to_owned(), 4)]),
        complete_predicates: std::collections::BTreeSet::from(["denial".to_owned()]),
        rules: Vec::new(),
    });
    let denial_build = harness.build(denial_bundle, false);
    let result = harness.query(
        &denial_build.context().projection_build_id,
        "denial",
        vec![],
    );
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].values[1], mneme_core::Value::symbol("claim"));
}

#[test]
fn hypothesis_stance_is_not_an_operational_fact() {
    let mut harness = Harness::new();
    harness.add_entity("assertion-entity", rid(0x10), &scope(), "A");
    add_assertions(
        &mut harness,
        &[AssertionSpec {
            stance: mneme_memory::Stance::Hypothesis,
            ..affirmation(0, 0x10, "claim", mneme_core::Value::string("maybe"))
        }],
    );
    let build = harness.build(claims_bundle(), false);
    let result = harness.query(
        &build.context().projection_build_id,
        "claim",
        vec![
            Some(rid(0x10).to_value()),
            Some(mneme_core::Value::string("maybe")),
        ],
    );
    assert!(
        result.rows.is_empty(),
        "a hypothesis stance became an operational claim"
    );
}

#[test]
fn withdrawn_evidence_is_not_an_eligible_fact() {
    let mut harness = Harness::new();
    add_assertion_support(&mut harness, true);
    let cites_bundle = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "cites".to_owned(),
        version: "1".to_owned(),
        schema_version: 3,
        base_predicates: std::collections::BTreeMap::from([("evidence".to_owned(), 2)]),
        complete_predicates: std::collections::BTreeSet::from(["evidence".to_owned()]),
        rules: vec![mneme_datalog::Rule::new(
            "cites",
            atom("cites", vec![var("a"), var("s")]),
            vec![mneme_datalog::Literal::Positive(atom(
                "evidence",
                vec![var("a"), var("s")],
            ))],
        )],
    });
    let build = harness.build(cites_bundle.clone(), false);
    let result = harness.query(&build.context().projection_build_id, "cites", vec![]);
    assert_eq!(result.rows.len(), 2);

    let base = harness.workspace.current_revision().expect("base");
    let request = retention_request(
        "withdraw-support",
        mneme_retention::OperationKind::AssertionRetraction,
        mneme_retention::Selector::SourceSupport(rid(0x20)),
        base,
    );
    mneme_retention::Engine::new(&mut harness.workspace)
        .execute(request)
        .expect("withdraw");
    let build = harness.build(cites_bundle, false);
    let result = harness.query(&build.context().projection_build_id, "cites", vec![]);
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].values[1], rid(0x22).to_value());
}

#[test]
fn ineligible_derivations_are_not_facts() {
    let mut harness = Harness::new();
    harness.add_entity("assertion-entity", rid(0x10), &scope(), "A");
    add_assertions(
        &mut harness,
        &[
            affirmation(0, 0x10, "claim", mneme_core::Value::string("retained")),
            affirmation(1, 0x10, "claim", mneme_core::Value::string("premise")),
        ],
    );
    let base = harness.workspace.current_revision().expect("base");
    let derivation = mneme_memory::build_derivation(
        rid(0xa0),
        rev(0xa1),
        &scope(),
        mneme_memory::DerivationOptions {
            conclusion: rid(0x40),
            premises: &[mneme_core::Reference::local(
                rid(0x44),
                mneme_core::RecordKind::Assertion,
            )],
            rule_id: "support",
            rule_version: 1,
            evaluation_revision: base,
            completeness: "complete",
        },
    );
    harness.commit("derivation", vec![derivation], Vec::new());
    let derivations_bundle = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "derivations".to_owned(),
        version: "1".to_owned(),
        schema_version: 3,
        base_predicates: std::collections::BTreeMap::from([("derivation".to_owned(), 2)]),
        complete_predicates: std::collections::BTreeSet::from(["derivation".to_owned()]),
        rules: vec![mneme_datalog::Rule::new(
            "derived",
            atom("derived", vec![var("c"), var("p")]),
            vec![mneme_datalog::Literal::Positive(atom(
                "derivation",
                vec![var("c"), var("p")],
            ))],
        )],
    });
    let build = harness.build(derivations_bundle.clone(), false);
    let result = harness.query(&build.context().projection_build_id, "derived", vec![]);
    assert_eq!(result.rows.len(), 1);

    // Retracting the premise removes the derivation's eligibility.
    let base = harness.workspace.current_revision().expect("base");
    let request = retention_request(
        "retract-premise",
        mneme_retention::OperationKind::AssertionRetraction,
        mneme_retention::Selector::Assertion(rid(0x44)),
        base,
    );
    mneme_retention::Engine::new(&mut harness.workspace)
        .execute(request)
        .expect("retract");
    let build = harness.build(derivations_bundle, false);
    let result = harness.query(&build.context().projection_build_id, "derived", vec![]);
    assert!(
        result.rows.is_empty(),
        "a retracted premise kept its derivation eligible"
    );
}

#[test]
fn challenging_evidence_is_not_support() {
    let mut harness = Harness::new();
    harness.add_entity("assertion-entity", rid(0x10), &scope(), "A");
    add_support_sources(&mut harness, true);
    let mut evidence = support_evidence(false);
    evidence.push(mneme_memory::build_evidence(
        rid(0x32),
        rev(0x33),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: rid(0x40),
            source: rid(0x22),
            source_revision: rev(0x23),
            span: Some(mneme_core::SourceSpan::new(0, 10).expect("span")),
            anchor: Some("b"),
            relation: mneme_memory::SupportRelation::Challenges,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    ));
    let evidence_refs = evidence
        .iter()
        .map(|record| {
            mneme_core::Reference::local(record.record_id, mneme_core::RecordKind::Evidence)
        })
        .collect::<Vec<_>>();
    let assertion = mneme_memory::build_proposed_assertion(
        rid(0x40),
        rev(0x41),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: rid(0x10),
            predicate: "claim",
            value: mneme_core::Value::string("retained"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &evidence_refs,
            extraction: None,
            superseded_by: None,
        },
    );
    harness.commit(
        "evidence",
        evidence.into_iter().chain([assertion]).collect(),
        Vec::new(),
    );
    accept_support_assertion(&mut harness);
    let build = harness.build(claims_bundle(), false);
    let result = harness.query(
        &build.context().projection_build_id,
        "claim",
        vec![
            Some(rid(0x10).to_value()),
            Some(mneme_core::Value::string("retained")),
        ],
    );
    assert_eq!(result.rows.len(), 1);
    assert_eq!(
        result.rows[0].supports[0].sources,
        std::collections::BTreeSet::from([(rid(0x20), rev(0x21))]),
        "a challenging source was counted as corroboration"
    );
}

#[test]
fn excluded_scope_evidence_cannot_ground_in_scope_claims() {
    let mut harness = Harness::new();
    harness.add_entity("entity", rid(0x10), &scope(), "A");
    // The claim is proposed first so every later reference to it resolves: the
    // store refuses a reference to a record that is not already committed.
    let proposal = mneme_memory::build_proposed_assertion(
        rid(0x40),
        rev(0x41),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: rid(0x10),
            predicate: "claim",
            value: mneme_core::Value::string("retained"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[],
            extraction: None,
            superseded_by: None,
        },
    );
    harness.commit("cedar-proposal", vec![proposal], Vec::new());
    let (source, blob) = mneme_memory::build_source(
        rid(0x60),
        rev(0x61),
        &other_scope(),
        mneme_memory::SourceOptions {
            bytes: b"= B\n\nBirch only.\n",
            media_type: "text/asciidoc",
            entity: None,
            path_hint: Some("b.adoc"),
        },
    )
    .expect("source");
    harness.commit("birch-source", vec![source], vec![blob]);
    let evidence = mneme_memory::build_evidence(
        rid(0x62),
        rev(0x63),
        &other_scope(),
        mneme_memory::EvidenceOptions {
            assertion: rid(0x40),
            source: rid(0x60),
            source_revision: rev(0x61),
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            anchor: Some("b"),
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    harness.commit("birch-evidence", vec![evidence], Vec::new());
    // Accept the claim while citing only the out-of-scope evidence. The citation
    // is admitted because the operator may reference the other scope, but the
    // build never sees that record.
    let base = harness.workspace.current_revision().expect("base");
    let current = harness
        .workspace
        .record_revisions(rid(0x40))
        .expect("proposal")
        .into_iter()
        .last()
        .expect("proposal revision");
    let decision = mneme_memory::build_decision(
        rid(0x50),
        rev(0x51),
        &scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: rid(0x40),
            actor: "datalog-test",
            policy: "datalog-policy/v1",
            input_revision: base,
            outcome: "accepted",
            rationale: "datalog fixture",
            evidence: &[],
            related: &[],
        },
    );
    let mut accepted = mneme_memory::build_assertion_revision(
        &current,
        rev(0x42),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(rid(0x50), mneme_core::RecordKind::Decision),
        None,
    );
    accepted.payload.insert(
        mneme_core::Symbol::from("evidence"),
        mneme_core::Value::set([mneme_core::Reference::local(
            rid(0x62),
            mneme_core::RecordKind::Evidence,
        )
        .to_value()]),
    );
    harness.commit("cedar-acceptance", vec![decision, accepted], Vec::new());
    let build = harness.build(claims_bundle(), false);
    let result = harness.query(&build.context().projection_build_id, "claim", vec![]);
    assert!(
        result.rows.is_empty(),
        "{:?}",
        result
            .rows
            .first()
            .map(|row| row.supports[0].sources.clone())
    );
}

#[test]
fn max_result_rows_bounds_materialization() {
    let mut harness = Harness::new();
    let records = (0..200_u16)
        .map(|index| {
            let mut id = [0x70_u8; 16];
            let [high, low] = index.to_be_bytes();
            id[1] = high;
            id[2] = low;
            let mut revision = id;
            revision[3] = 0x01;
            mneme_store::RecordDraft {
                schema_version: 1,
                kind: mneme_core::RecordKind::Entity,
                record_id: mneme_core::RecordId::from_bytes(id),
                revision_id: mneme_core::RevisionId::from_bytes(revision),
                predecessor: None,
                scope: scope(),
                payload: entity_payload("E"),
            }
        })
        .collect();
    harness.commit("many", records, Vec::new());
    let pair = mneme_datalog::Rule::new(
        "pair",
        atom("pair", vec![var("a"), var("b")]),
        vec![
            mneme_datalog::Literal::Positive(atom("entity", vec![var("a"), var("t1"), var("l1")])),
            mneme_datalog::Literal::Positive(atom("entity", vec![var("b"), var("t2"), var("l2")])),
        ],
    );
    let build = harness.build_with_limits(
        bundle(vec![pair], &["entity"]),
        mneme_datalog::Limits {
            max_work: 100_000,
            max_time_ms: 60_000,
            max_result_rows: 1_000,
            max_supports_per_fact: 8,
            max_recursion_depth: 32,
        },
    );
    assert!(
        build.row_count("pair") <= build.limits().max_result_rows,
        "status {:?} work {} rows {}",
        build.status(),
        build.work(),
        build.row_count("pair")
    );
    assert!(
        build.row_count("entity") + build.row_count("pair") <= build.limits().max_result_rows,
        "stored rows exceeded the configured bound"
    );
    assert!(
        build.limit_reached(),
        "the stored-row bound must be reported"
    );
    let result = harness.query(&build.context().projection_build_id, "pair", vec![]);
    assert!(!result.exhaustive);
    assert!(!result.absence_established);
}

#[test]
fn loading_stopped_early_marks_base_extents_incomplete() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let build = harness.build_with_limits(
        path_bundle(),
        mneme_datalog::Limits {
            max_work: 2,
            ..limits()
        },
    );
    assert_eq!(build.status(), mneme_datalog::ExecutionStatus::Timeout);
    assert!(build.limit_reached());
    assert!(
        build
            .coverage()
            .iter()
            .all(|coverage| coverage.status != mneme_datalog::CoverageStatus::Complete),
        "a stopped load must not report complete extents: {:?}",
        build.coverage()
    );
}

#[test]
fn declared_built_in_arity_mismatch_is_a_bundle_error() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let mismatched = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "base".to_owned(),
        version: "1".to_owned(),
        schema_version: 3,
        base_predicates: std::collections::BTreeMap::from([
            ("entity".to_owned(), 3),
            // The loader emits three columns for `relation`.
            ("relation".to_owned(), 2),
        ]),
        complete_predicates: std::collections::BTreeSet::from(["relation".to_owned()]),
        rules: Vec::new(),
    });
    let diagnostics = mismatched.validate().expect_err("arity mismatch");
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "predicate-arity"),
        "missing arity diagnostic in {diagnostics:?}"
    );
    let revision = harness.workspace.current_revision().expect("revision");
    let mut service = mneme_datalog::Service::new(&mut harness.workspace);
    let result = service.build(mneme_datalog::BuildRequest {
        actor: "datalog-test".to_owned(),
        scope: scope(),
        revision,
        bundle: mismatched,
        limits: limits(),
        publish: false,
        incomplete_extents: std::collections::BTreeSet::new(),
        cancellation: None,
        access: mneme_memory::Access::Operator,
        at: None,
    });
    assert!(matches!(
        result,
        Err(mneme_datalog::Error::InvalidBundle(_))
    ));

    // A constant of another kind in a canonical column is refused too.
    let wrong_kind = bundle(
        vec![mneme_datalog::Rule::new(
            "edge",
            atom("edge", vec![var("x"), var("y")]),
            vec![mneme_datalog::Literal::Positive(atom(
                "relation",
                vec![
                    constant(mneme_core::Value::string("depends")),
                    var("x"),
                    var("y"),
                ],
            ))],
        )],
        &[],
    );
    let diagnostics = wrong_kind.validate().expect_err("kind mismatch");
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "predicate-kind"),
        "missing kind diagnostic in {diagnostics:?}"
    );
}

#[test]
fn canonical_extent_names_cannot_be_rule_heads() {
    for head in ["entity", "relation", "source", "derivation"] {
        let canonical_head = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
            id: "overwrite".to_owned(),
            version: "1".to_owned(),
            schema_version: 3,
            base_predicates: std::collections::BTreeMap::from([("relation".to_owned(), 3)]),
            complete_predicates: std::collections::BTreeSet::new(),
            rules: vec![mneme_datalog::Rule::new(
                "overwrite",
                atom(head, vec![var("x"), var("t"), var("l")]),
                vec![mneme_datalog::Literal::Positive(atom(
                    "relation",
                    vec![
                        constant(mneme_core::Value::symbol("depends")),
                        var("x"),
                        var("t"),
                    ],
                ))],
            )],
        });
        let diagnostics = canonical_head.validate().expect_err("canonical head");
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "base-overwrite"),
            "missing base-overwrite for {head} in {diagnostics:?}"
        );
    }
}

#[test]
fn stratified_negation_over_a_base_relation_is_accepted() {
    let rules = vec![
        mneme_datalog::Rule::new(
            "edge",
            atom("reach", vec![var("x"), var("y")]),
            vec![mneme_datalog::Literal::Positive(atom(
                "relation",
                vec![
                    constant(mneme_core::Value::symbol("depends")),
                    var("x"),
                    var("y"),
                ],
            ))],
        ),
        mneme_datalog::Rule::new(
            "step",
            atom("reach", vec![var("x"), var("y")]),
            vec![
                mneme_datalog::Literal::Positive(atom("reach", vec![var("x"), var("z")])),
                mneme_datalog::Literal::Positive(atom(
                    "relation",
                    vec![
                        constant(mneme_core::Value::symbol("depends")),
                        var("z"),
                        var("y"),
                    ],
                )),
                mneme_datalog::Literal::Negative(atom(
                    "relation",
                    vec![
                        constant(mneme_core::Value::symbol("blocks")),
                        var("z"),
                        var("y"),
                    ],
                )),
            ],
        ),
    ];
    let program = bundle(rules, &["relation"])
        .validate()
        .expect("valid stratified program");
    assert_eq!(program.strata.get("reach").copied(), Some(1));
}

#[test]
fn negated_premises_are_recorded_as_absences() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let negation_rule = mneme_datalog::Rule::new(
        "isolated",
        atom("isolated", vec![var("x")]),
        vec![
            mneme_datalog::Literal::Positive(atom("entity", vec![var("x"), var("t"), var("l")])),
            mneme_datalog::Literal::Negative(atom(
                "relation",
                vec![
                    constant(mneme_core::Value::symbol("depends")),
                    var("x"),
                    var("x"),
                ],
            )),
        ],
    );
    let build = harness.build(bundle(vec![negation_rule], &["relation"]), false);
    let result = harness.query(
        &build.context().projection_build_id,
        "isolated",
        vec![Some(rid(0x10).to_value())],
    );
    assert_eq!(result.rows.len(), 1);
    let absent = result.rows[0].supports[0]
        .premises
        .iter()
        .find(|premise| premise.absent)
        .expect("negated premise recorded");
    assert_eq!(absent.predicate, "relation");
    assert_eq!(absent.coverage.as_deref(), Some("complete"));
    assert_eq!(absent.canonical, None);
}

#[test]
fn repeated_proof_is_recorded_once_when_a_premise_gains_sources() {
    let mut harness = Harness::new();
    for (key, id, label) in [
        ("entity-x", 0x10, "X"),
        ("entity-z", 0x11, "Z"),
        ("entity-w", 0x12, "W"),
        ("entity-v", 0x13, "V"),
    ] {
        harness.add_entity(key, rid(id), &scope(), label);
    }
    add_assertions(
        &mut harness,
        &[
            affirmation(0, 0x10, "next", rid(0x11).to_value()),
            affirmation(1, 0x11, "next", rid(0x12).to_value()),
            affirmation(2, 0x10, "next", rid(0x13).to_value()),
            affirmation(3, 0x13, "next", rid(0x11).to_value()),
        ],
    );
    let rules = vec![
        mneme_datalog::Rule::new(
            "link",
            atom("link", vec![var("a"), var("b")]),
            vec![mneme_datalog::Literal::Positive(atom(
                "assertion",
                vec![
                    var("a"),
                    constant(mneme_core::Value::symbol("next")),
                    var("b"),
                    var("id"),
                ],
            ))],
        ),
        mneme_datalog::Rule::new(
            "seed",
            atom("reach", vec![var("a"), var("b")]),
            vec![mneme_datalog::Literal::Positive(atom(
                "link",
                vec![var("a"), var("b")],
            ))],
        ),
        mneme_datalog::Rule::new(
            "step",
            atom("reach", vec![var("a"), var("c")]),
            vec![
                mneme_datalog::Literal::Positive(atom("reach", vec![var("a"), var("b")])),
                mneme_datalog::Literal::Positive(atom("link", vec![var("b"), var("c")])),
            ],
        ),
    ];
    let reach_bundle = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "next-reach".to_owned(),
        version: "1".to_owned(),
        schema_version: 3,
        base_predicates: std::collections::BTreeMap::from([("assertion".to_owned(), 4)]),
        complete_predicates: std::collections::BTreeSet::from(["assertion".to_owned()]),
        rules,
    });
    let build = harness.build(reach_bundle.clone(), false);
    let result = harness.query(
        &build.context().projection_build_id,
        "reach",
        vec![Some(rid(0x10).to_value()), Some(rid(0x12).to_value())],
    );
    assert_eq!(result.rows.len(), 1);
    assert_eq!(
        result.rows[0].supports.len(),
        1,
        "the same proof was recorded twice after a premise gained sources"
    );
    assert_eq!(
        result.rows[0].supports[0].sources.len(),
        4,
        "the single support lost the sources its premise gained"
    );

    // With one support per fact, a duplicate proof would be reported as
    // truncation even though only one proof exists.
    let limited = harness.build_with_limits(
        reach_bundle,
        mneme_datalog::Limits {
            max_supports_per_fact: 1,
            ..limits()
        },
    );
    let result = harness.query(
        &limited.context().projection_build_id,
        "reach",
        vec![Some(rid(0x10).to_value()), Some(rid(0x12).to_value())],
    );
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].supports.len(), 1);
    assert!(
        !result.rows[0].support_truncated,
        "one proof was mistaken for two"
    );
}

#[test]
fn failed_aggregate_is_confined_to_its_relation() {
    let mut harness = Harness::new();
    harness.add_entity("assertion-entity", rid(0x10), &scope(), "A");
    add_assertions(
        &mut harness,
        &[
            affirmation(0, 0x10, "score", mneme_core::Value::integer(5_i64)),
            affirmation(1, 0x10, "score", mneme_core::Value::string("not a number")),
        ],
    );
    let total_rule = mneme_datalog::Rule::new(
        "total",
        atom("total", vec![var("n")]),
        vec![
            mneme_datalog::Literal::Positive(atom(
                "assertion",
                vec![
                    var("subject"),
                    constant(mneme_core::Value::symbol("score")),
                    var("value"),
                    var("id"),
                ],
            )),
            mneme_datalog::Literal::Aggregate {
                function: mneme_datalog::AggregateFunction::Sum,
                input: var("value"),
                output: "n".to_owned(),
            },
        ],
    );
    let subjects_rule = mneme_datalog::Rule::new(
        "subjects",
        atom("subjects", vec![var("subject")]),
        vec![mneme_datalog::Literal::Positive(atom(
            "assertion",
            vec![var("subject"), var("predicate"), var("value"), var("id")],
        ))],
    );
    let build = harness.build(
        mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
            id: "totals".to_owned(),
            version: "1".to_owned(),
            schema_version: 3,
            base_predicates: std::collections::BTreeMap::from([("assertion".to_owned(), 4)]),
            complete_predicates: std::collections::BTreeSet::from(["assertion".to_owned()]),
            rules: vec![total_rule, subjects_rule],
        }),
        false,
    );
    assert_ne!(build.status(), mneme_datalog::ExecutionStatus::Failed);
    let result = harness.query(&build.context().projection_build_id, "total", vec![]);
    assert!(result.rows.is_empty());
    assert!(!result.absence_established);
    assert!(result.coverage.iter().any(|coverage| {
        coverage.predicate == "total"
            && coverage.status == mneme_datalog::CoverageStatus::Incomplete
    }));
    // The rest of the same build still materialized: only the failing aggregate
    // relation lost its answer instead of the whole build failing.
    let subjects = harness.query(&build.context().projection_build_id, "subjects", vec![]);
    assert_eq!(subjects.rows.len(), 1);
    assert_eq!(subjects.rows[0].values[0], rid(0x10).to_value());
}

#[test]
fn sum_uses_arbitrary_precision_integers() {
    let mut harness = Harness::new();
    harness.add_entity("assertion-entity", rid(0x10), &scope(), "A");
    add_assertions(
        &mut harness,
        &[
            affirmation(0, 0x10, "score", mneme_core::Value::integer(i64::MAX)),
            affirmation(1, 0x10, "score", mneme_core::Value::integer(i64::MAX)),
            affirmation(2, 0x10, "score", mneme_core::Value::integer(i64::MAX)),
        ],
    );
    let total_rule = mneme_datalog::Rule::new(
        "total",
        atom("total", vec![var("n")]),
        vec![
            mneme_datalog::Literal::Positive(atom(
                "assertion",
                vec![
                    var("subject"),
                    constant(mneme_core::Value::symbol("score")),
                    var("value"),
                    var("id"),
                ],
            )),
            mneme_datalog::Literal::Aggregate {
                function: mneme_datalog::AggregateFunction::Sum,
                input: var("value"),
                output: "n".to_owned(),
            },
        ],
    );
    let build = harness.build(
        mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
            id: "totals".to_owned(),
            version: "1".to_owned(),
            schema_version: 3,
            base_predicates: std::collections::BTreeMap::from([("assertion".to_owned(), 4)]),
            complete_predicates: std::collections::BTreeSet::from(["assertion".to_owned()]),
            rules: vec![total_rule],
        }),
        false,
    );
    let result = harness.query(&build.context().projection_build_id, "total", vec![]);
    assert_eq!(result.rows.len(), 1);
    assert_eq!(
        result.rows[0].values[0],
        mneme_core::Value::integer(27_670_116_110_564_327_421_i128)
    );
}

#[test]
fn numeric_comparisons_and_min_max_order_by_value() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let degree_rule = mneme_datalog::Rule::new(
        "degree",
        atom("degree", vec![var("x"), var("n")]),
        vec![
            mneme_datalog::Literal::Positive(atom(
                "relation",
                vec![
                    constant(mneme_core::Value::symbol("depends")),
                    var("x"),
                    var("y"),
                ],
            )),
            mneme_datalog::Literal::Aggregate {
                function: mneme_datalog::AggregateFunction::Count,
                input: var("y"),
                output: "n".to_owned(),
            },
        ],
    );
    let low_rule = mneme_datalog::Rule::new(
        "low",
        atom("low", vec![var("x")]),
        vec![
            mneme_datalog::Literal::Positive(atom("degree", vec![var("x"), var("n")])),
            mneme_datalog::Literal::Compare {
                op: mneme_datalog::CompareOp::Lt,
                left: var("n"),
                right: constant(mneme_core::Value::double(1.5)),
            },
        ],
    );
    let build = harness.build(bundle(vec![degree_rule, low_rule], &["relation"]), false);
    let result = harness.query(&build.context().projection_build_id, "low", vec![]);
    assert_eq!(
        result.rows.len(),
        2,
        "an integer degree must compare numerically with a double bound"
    );
    let missing = harness.query(
        &build.context().projection_build_id,
        "low",
        vec![Some(rid(0x10).to_value())],
    );
    assert_eq!(missing.rows.len(), 1);

    // min/max over mixed integer and double values use numeric order.
    let mut harness = Harness::new();
    harness.add_entity("assertion-entity", rid(0x10), &scope(), "A");
    add_assertions(
        &mut harness,
        &[
            affirmation(0, 0x10, "score", mneme_core::Value::double(1.5)),
            affirmation(1, 0x10, "score", mneme_core::Value::integer(2_i64)),
        ],
    );
    // At most one aggregate literal is supported.
    let min_rule = mneme_datalog::Rule::new(
        "lowest",
        atom("lowest", vec![var("subject"), var("value_out")]),
        vec![
            mneme_datalog::Literal::Positive(atom(
                "assertion",
                vec![
                    var("subject"),
                    constant(mneme_core::Value::symbol("score")),
                    var("value"),
                    var("id"),
                ],
            )),
            mneme_datalog::Literal::Aggregate {
                function: mneme_datalog::AggregateFunction::Min,
                input: var("value"),
                output: "value_out".to_owned(),
            },
        ],
    );
    let build = harness.build(
        mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
            id: "bounds".to_owned(),
            version: "1".to_owned(),
            schema_version: 3,
            base_predicates: std::collections::BTreeMap::from([("assertion".to_owned(), 4)]),
            complete_predicates: std::collections::BTreeSet::from(["assertion".to_owned()]),
            rules: vec![min_rule],
        }),
        false,
    );
    let result = harness.query(
        &build.context().projection_build_id,
        "lowest",
        vec![Some(rid(0x10).to_value()), None],
    );
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].values[1], mneme_core::Value::double(1.5));
}

#[test]
fn expired_assertions_are_temporal_parameters_and_excluded_by_time() {
    let mut harness = Harness::new();
    harness.add_entity("assertion-entity", rid(0x10), &scope(), "A");
    add_assertions(
        &mut harness,
        &[AssertionSpec {
            valid_time: mneme_core::ValidTime::until(mneme_core::Timestamp::from_nanos(500)),
            ..affirmation(0, 0x10, "claim", mneme_core::Value::string("retained"))
        }],
    );
    let build = harness.build(claims_bundle(), false);
    let result = harness.query(
        &build.context().projection_build_id,
        "claim",
        vec![
            Some(rid(0x10).to_value()),
            Some(mneme_core::Value::string("retained")),
        ],
    );
    assert_eq!(result.rows.len(), 1);
    assert!(
        result.rows[0].supports[0]
            .temporal_parameters
            .iter()
            .any(|parameter| parameter == "valid-time-end:500"),
        "valid time is not disclosed as a temporal parameter: {:?}",
        result.rows[0].supports[0].temporal_parameters
    );

    let within = harness.build_at(claims_bundle(), mneme_core::Timestamp::from_nanos(400));
    let visible = harness.query(&within.context().projection_build_id, "claim", vec![]);
    assert_eq!(visible.rows.len(), 1);
    let expired = harness.build_at(claims_bundle(), mneme_core::Timestamp::from_nanos(1_000));
    let hidden = harness.query(&expired.context().projection_build_id, "claim", vec![]);
    assert!(
        hidden.rows.is_empty(),
        "an assertion outside its valid time was loaded as a current fact"
    );
    assert!(hidden.absence_established);
}

#[test]
fn pruned_source_is_marked_for_builds_of_earlier_revisions() {
    let mut harness = Harness::new();
    add_assertion_support(&mut harness, false);
    let earlier = harness.workspace.current_revision().expect("earlier");
    let base = harness.workspace.current_revision().expect("base");
    let prune = retention_request(
        "prune-a",
        mneme_retention::OperationKind::SourcePruning,
        mneme_retention::Selector::Source(rid(0x20)),
        base,
    );
    mneme_retention::Engine::new(&mut harness.workspace)
        .execute(prune)
        .expect("prune");
    let bundle = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "pruned".to_owned(),
        version: "1".to_owned(),
        schema_version: 3,
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
        rules: vec![mneme_datalog::Rule::new(
            "claim",
            atom("claim", vec![var("subject"), var("value")]),
            vec![mneme_datalog::Literal::Positive(atom(
                "assertion",
                vec![
                    var("subject"),
                    constant(mneme_core::Value::symbol("claim")),
                    var("value"),
                    var("id"),
                ],
            ))],
        )],
    });
    let build = harness.build_at_revision(bundle.clone(), earlier);
    assert!(!build.context().requested_was_head);
    let earlier_build = build.context().projection_build_id.clone();
    // Pruning removes the bytes but policy lets the claim keep its eligibility,
    // so a build of the earlier revision still derives it and must disclose that
    // the exact source revision it cites was pruned.
    let result = harness.query(
        &earlier_build,
        "claim",
        vec![
            Some(rid(0x10).to_value()),
            Some(mneme_core::Value::string("retained")),
        ],
    );
    assert_eq!(result.rows.len(), 1);
    assert!(
        result.rows[0].supports[0]
            .premises
            .iter()
            .any(|premise| premise.source_availability.as_deref() == Some("pruned")),
        "an earlier build labelled a pruned source as available: {:?}",
        result.rows[0].supports[0].premises
    );
    // The retention outcome is disclosed, never reported as corruption: the
    // source extent names the pinned revision and its pruned state.
    let sources = harness.query(&earlier_build, "source", vec![]);
    assert!(
        sources.rows.iter().any(|row| {
            row.values
                == vec![
                    rid(0x20).to_value(),
                    rev(0x21).to_value(),
                    mneme_core::Value::string("pruned"),
                ]
        }),
        "pruning was not reported as a retention outcome: {:?}",
        sources.rows
    );
    // The evidence record survives pruning; its support must carry the pruned
    // availability instead of looking retained.
    let evidence = harness.query(&earlier_build, "evidence", vec![]);
    assert!(
        evidence.rows.iter().any(|row| {
            row.values == vec![rid(0x40).to_value(), rid(0x20).to_value()]
                && row.supports.iter().any(|support| {
                    support
                        .premises
                        .iter()
                        .any(|premise| premise.source_availability.as_deref() == Some("pruned"))
                })
        }),
        "an earlier build did not disclose the pruned source: {:?}",
        evidence.rows
    );

    // The current revision reports the same retention outcome: pruned, never
    // corruption, and the claim survives there too.
    let head = harness.build(bundle, false);
    let head_id = head.context().projection_build_id.clone();
    let head_sources = harness.query(&head_id, "source", vec![]);
    let source_id = rid(0x20).to_value();
    let pruned = mneme_core::Value::string("pruned");
    let corrupt = mneme_core::Value::string("corrupt");
    assert!(
        head_sources.rows.iter().any(|row| {
            row.values.first() == Some(&source_id) && row.values.get(2) == Some(&pruned)
        }),
        "the current revision did not report the source as pruned: {:?}",
        head_sources.rows
    );
    assert!(
        head_sources
            .rows
            .iter()
            .all(|row| row.values.get(2) != Some(&corrupt)),
        "authorized pruning was misreported as corruption: {:?}",
        head_sources.rows
    );
    let head_claim = harness.query(&head_id, "claim", vec![]);
    assert_eq!(head_claim.rows.len(), 1);
}

#[test]
fn older_build_reports_its_own_requested_revision() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let earlier = harness.workspace.current_revision().expect("earlier");
    harness.add_entity("entity-d", rid(0x13), &scope(), "D");
    let build = harness.build_at_revision(path_bundle(), earlier);
    let mut service = mneme_datalog::Service::new(&mut harness.workspace);
    let result = service
        .query_build(&build, mneme_datalog::Query::all("path", 100))
        .expect("a deliberately older build is not stale");
    assert_eq!(result.requested_revision, earlier);
    assert_eq!(result.served_revision, earlier);
    assert_eq!(result.context.requested_revision, earlier);
    assert!(
        !result.stale,
        "a deliberately older build answers for the revision it asked for"
    );
    assert!(result.exhaustive);
    assert_eq!(result.rows.len(), 3);
}

#[test]
fn query_result_names_its_relation_and_dependencies() {
    let mut harness = Harness::new();
    add_assertion_support(&mut harness, false);
    let build = harness.build(claims_bundle(), false);
    let result = harness.query(&build.context().projection_build_id, "claim", vec![]);
    assert_eq!(result.relation, "claim");
    assert_eq!(
        result
            .coverage
            .iter()
            .map(|coverage| coverage.predicate.clone())
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from(["assertion".to_owned(), "claim".to_owned()]),
        "coverage must name exactly the relations the answer depends on"
    );
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let build = harness.build(path_bundle(), false);
    let result = harness.query(&build.context().projection_build_id, "path", vec![]);
    assert_eq!(result.relation, "path");
    assert!(
        result
            .coverage
            .iter()
            .all(|coverage| coverage.predicate != "entity"),
        "an unrelated extent made the answer incomplete"
    );
}

#[test]
fn query_cache_distinguishes_build_status() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let revision = harness.workspace.current_revision().expect("revision");
    let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let mut service = mneme_datalog::Service::new(&mut harness.workspace);
    let request = |cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>| {
        mneme_datalog::BuildRequest {
            actor: "datalog-test".to_owned(),
            scope: scope(),
            revision,
            bundle: path_bundle(),
            limits: limits(),
            publish: false,
            incomplete_extents: std::collections::BTreeSet::new(),
            cancellation,
            access: mneme_memory::Access::Operator,
            at: None,
        }
    };
    let cancelled_build = service
        .build(request(Some(cancelled)))
        .expect("cancelled build");
    let build_id = cancelled_build.context().projection_build_id.clone();
    let before = service
        .query(&build_id, mneme_datalog::Query::all("path", 100))
        .expect("cancelled query");
    assert_eq!(before.status, mneme_datalog::ExecutionStatus::Cancelled);
    assert!(before.rows.is_empty());
    let rebuilt = service.build(request(None)).expect("rebuilt");
    assert_eq!(rebuilt.status(), mneme_datalog::ExecutionStatus::Complete);
    let after = service
        .query(&build_id, mneme_datalog::Query::all("path", 100))
        .expect("completed query");
    assert_eq!(after.status, mneme_datalog::ExecutionStatus::Complete);
    assert_eq!(
        after.rows.len(),
        3,
        "a cached cancellation answer was served for a completed build"
    );
}

#[test]
fn build_barrier_fields_are_rechecked_and_only_complete_builds_publish() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let build = harness.build(path_bundle(), false);
    assert_eq!(
        build.context().eligibility_generation,
        harness
            .workspace
            .eligibility_generation()
            .expect("generation")
    );
    let timed_out = harness.build_with_limits(
        path_bundle(),
        mneme_datalog::Limits {
            max_work: 0,
            ..limits()
        },
    );
    assert_eq!(timed_out.status(), mneme_datalog::ExecutionStatus::Timeout);
    {
        let mut service = mneme_datalog::Service::new(&mut harness.workspace);
        assert!(matches!(
            service.publish_build(&timed_out),
            Err(mneme_datalog::Error::Failed(_))
        ));
    }
    harness
        .workspace
        .advance_eligibility_barrier()
        .expect("advance barrier");
    let mut service = mneme_datalog::Service::new(&mut harness.workspace);
    assert!(matches!(
        service.query_build(&build, mneme_datalog::Query::all("path", 10)),
        Err(mneme_datalog::Error::Store(
            mneme_store::Failure::BarrierAdvanced { .. }
        ))
    ));
    assert!(matches!(
        service.publish_build(&build),
        Err(mneme_datalog::Error::Store(
            mneme_store::Failure::BarrierAdvanced { .. }
        ))
    ));
}

#[test]
fn absence_is_established_only_for_a_complete_declared_current_answer() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let build = harness.build(path_bundle(), false);
    let absent = harness.query(
        &build.context().projection_build_id,
        "path",
        vec![Some(rid(0x77).to_value()), Some(rid(0x78).to_value())],
    );
    assert!(absent.rows.is_empty());
    assert!(absent.absence_established);
    assert!(absent.exhaustive);
    assert_eq!(absent.status, mneme_datalog::ExecutionStatus::Complete);

    // An incomplete declared extent cannot establish absence.
    let mut request = harness.request(path_bundle(), limits());
    request.incomplete_extents = std::collections::BTreeSet::from(["relation".to_owned()]);
    let incomplete = harness.run(request);
    let absent = harness.query(
        &incomplete.context().projection_build_id,
        "path",
        vec![Some(rid(0x77).to_value()), Some(rid(0x78).to_value())],
    );
    assert!(absent.rows.is_empty());
    assert!(!absent.absence_established);
    assert!(!absent.exhaustive);

    // A build that pinned head is not current after head moves.
    harness.add_entity("entity-d", rid(0x13), &scope(), "D");
    let mut service = mneme_datalog::Service::new(&mut harness.workspace);
    assert!(matches!(
        service.query_build(&build, mneme_datalog::Query::all("path", 10)),
        Err(mneme_datalog::Error::Stale { .. })
    ));
    drop(service);

    // A query over an undeclared relation is refused rather than answered.
    let fresh = harness.build(path_bundle(), false);
    let mut service = mneme_datalog::Service::new(&mut harness.workspace);
    assert!(matches!(
        service.query_build(&fresh, mneme_datalog::Query::all("undeclared", 10)),
        Err(mneme_datalog::Error::UnknownPredicate(_))
    ));
}
