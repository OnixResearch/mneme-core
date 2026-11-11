//! Datalog projection behavior over real committed snapshots.

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use mneme_core::{
    Lifecycle, Origin, RecordId, Reference, RevisionId, ScopeClass, ScopeId, SourceSpan, Timestamp,
    ValidTime, Value,
};
use mneme_datalog::{
    AggregateFunction, Atom, BuildRequest, CoverageStatus, DatalogError, DatalogService,
    ExecutionStatus, Limits, Literal, Query, Rule, RuleBundle, Term,
};
use mneme_memory::{
    DecisionKind, Stance, build_assertion_revision, build_decision, build_evidence,
    build_proposed_assertion, build_source,
};
use mneme_retention::{OperationKind, Retention, RetentionPolicy, RetentionRequest, Selector};
use mneme_store::{
    CommitCommand, FixedClock, NoFaults, RecordDraft, StoreError, Workspace, WorkspaceConfig, blob,
};
use tempfile::TempDir;

fn scope() -> ScopeId {
    ScopeId::new(ScopeClass::Project, "cedar").expect("scope")
}

fn other_scope() -> ScopeId {
    ScopeId::new(ScopeClass::Project, "birch").expect("scope")
}

fn rid(byte: u8) -> RecordId {
    RecordId::from_bytes([byte; 16])
}

fn rev(byte: u8) -> RevisionId {
    RevisionId::from_bytes([byte; 16])
}

struct Harness {
    temp: TempDir,
    workspace: Workspace,
    builds: BTreeMap<String, mneme_datalog::DatalogBuild>,
}

impl Harness {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temp");
        let workspace = Workspace::create(
            temp.path(),
            WorkspaceConfig {
                clock: Box::new(FixedClock::new(Timestamp::from_nanos(1_000))),
                faults: Box::new(NoFaults),
            },
        )
        .expect("create");
        Harness {
            temp,
            workspace,
            builds: BTreeMap::new(),
        }
    }

    fn commit(
        &mut self,
        key: &str,
        records: Vec<RecordDraft>,
        blobs: Vec<mneme_store::SourceBlobDraft>,
    ) -> mneme_store::CommitOutcome {
        let scope = records
            .first()
            .map(|record| record.scope.clone())
            .unwrap_or_else(scope);
        self.workspace
            .commit(CommitCommand {
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

    fn add_entity(&mut self, key: &str, id: RecordId, scope: &ScopeId, label: &str) {
        self.commit(
            key,
            vec![RecordDraft {
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
        id: RecordId,
        scope: &ScopeId,
        from: RecordId,
        to: RecordId,
    ) {
        self.commit(
            key,
            vec![RecordDraft {
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

    fn build(&mut self, bundle: RuleBundle, publish: bool) -> mneme_datalog::DatalogBuild {
        let revision = self.workspace.current_revision().expect("revision");
        let mut service = DatalogService::new(&mut self.workspace);
        let build = service
            .build(BuildRequest {
                actor: "datalog-test".to_owned(),
                scope: scope(),
                revision,
                bundle,
                limits: Limits::default(),
                publish,
                incomplete_extents: BTreeSet::new(),
                cancellation: None,
            })
            .expect("build");
        self.builds
            .insert(build.context.projection_build_id.clone(), build.clone());
        build
    }

    fn query(
        &mut self,
        build_id: &str,
        predicate: &str,
        constants: Vec<Option<Value>>,
    ) -> mneme_datalog::QueryResult {
        let build = self
            .builds
            .get(build_id)
            .cloned()
            .expect("build in harness");
        let mut service = DatalogService::new(&mut self.workspace);
        service
            .query_build(
                &build,
                Query {
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

fn entity_payload(label: &str) -> mneme_core::Payload {
    mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("entity-type"),
            Value::symbol("project"),
        ),
        (
            mneme_core::Symbol::from("label"),
            Value::string(label.to_owned()),
        ),
        (
            mneme_core::Symbol::from("properties"),
            Value::dictionary([]),
        ),
    ])
}

fn relation_payload(from: RecordId, to: RecordId) -> mneme_core::Payload {
    mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("relation-type"),
            Value::symbol("depends"),
        ),
        (
            mneme_core::Symbol::from("from"),
            Reference::local(from, mneme_core::RecordKind::Entity).to_value(),
        ),
        (
            mneme_core::Symbol::from("to"),
            Reference::local(to, mneme_core::RecordKind::Entity).to_value(),
        ),
        (
            mneme_core::Symbol::from("properties"),
            Value::dictionary([]),
        ),
    ])
}

fn atom(predicate: &str, terms: Vec<Term>) -> Atom {
    Atom::new(predicate, terms)
}

fn var(name: &str) -> Term {
    Term::var(name)
}

fn constant(value: Value) -> Term {
    Term::constant(value)
}

fn bundle(rules: Vec<Rule>, complete: &[&str]) -> RuleBundle {
    RuleBundle::new(
        "base",
        "1",
        3,
        BTreeMap::from([("entity".to_owned(), 3), ("relation".to_owned(), 3)]),
        complete.iter().map(|name| (*name).to_owned()).collect(),
        rules,
    )
}

fn path_bundle() -> RuleBundle {
    bundle(
        vec![
            Rule::new(
                "edge",
                atom("path", vec![var("x"), var("y")]),
                vec![Literal::Positive(atom(
                    "relation",
                    vec![constant(Value::symbol("depends")), var("x"), var("y")],
                ))],
            ),
            Rule::new(
                "reach",
                atom("path", vec![var("x"), var("y")]),
                vec![
                    Literal::Positive(atom("path", vec![var("x"), var("z")])),
                    Literal::Positive(atom(
                        "relation",
                        vec![constant(Value::symbol("depends")), var("z"), var("y")],
                    )),
                ],
            ),
        ],
        &["relation"],
    )
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

#[test]
fn positive_recursive_paths_are_scoped_to_the_pinned_revision() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    // Excluded scope: C -> D with D outside the authorized scope.
    harness.add_entity("entity-d", rid(0x13), &other_scope(), "D");
    harness.add_relation("edge-cd", rid(0x22), &other_scope(), rid(0x12), rid(0x13));
    let build = harness.build(path_bundle(), false);
    assert_eq!(build.status, ExecutionStatus::Complete);
    assert_eq!(build.context.scope, scope());
    let result = harness.query(&build.context.projection_build_id, "path", vec![]);
    assert_eq!(result.status, ExecutionStatus::Complete);
    assert!(result.exhaustive);
    assert_eq!(result.rows.len(), 3);
    assert!(
        result
            .rows
            .iter()
            .all(|row| { row.values != vec![rid(0x10).to_value(), rid(0x13).to_value()] })
    );
    let exact = harness.query(
        &build.context.projection_build_id,
        "path",
        vec![Some(rid(0x10).to_value()), Some(rid(0x12).to_value())],
    );
    assert_eq!(exact.rows.len(), 1);
    let support = exact.rows[0].supports.first().expect("derived support");
    let canonical = support
        .premises
        .iter()
        .filter_map(|premise| premise.canonical)
        .collect::<BTreeSet<_>>();
    assert!(canonical.contains(&rid(0x20)));
    assert!(canonical.contains(&rid(0x21)));
    assert!(exact.rows[0].supports.iter().all(|support| {
        support
            .premises
            .iter()
            .all(|premise| premise.canonical.is_some())
    }));
}

#[test]
fn unsafe_forbidden_non_stratified_and_schema_rules_are_rejected() {
    let unsafe_rule = Rule::new(
        "unsafe",
        atom("out", vec![var("x")]),
        vec![Literal::Positive(atom(
            "relation",
            vec![
                constant(Value::symbol("depends")),
                constant(rid(0x10).to_value()),
                var("y"),
            ],
        ))],
    );
    let forbidden = Rule::new(
        "forbidden",
        atom("out", vec![var("x")]),
        vec![
            Literal::Positive(atom(
                "relation",
                vec![constant(Value::symbol("depends")), var("x"), var("y")],
            )),
            Literal::Forbidden("read-file".to_owned()),
        ],
    );
    let negative = Rule::new(
        "negative",
        atom("p", vec![var("x")]),
        vec![
            Literal::Positive(atom(
                "relation",
                vec![constant(Value::symbol("depends")), var("x"), var("y")],
            )),
            Literal::Negative(atom("p", vec![var("x")])),
        ],
    );
    for (bundle, code) in [
        (bundle(vec![unsafe_rule], &[]), "unsafe-head-variable"),
        (bundle(vec![forbidden], &[]), "forbidden-builtin"),
        (bundle(vec![negative], &["p"]), "non-stratified"),
        (
            RuleBundle::new("bad", "1", 0, BTreeMap::new(), BTreeSet::new(), Vec::new()),
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
    let negation_rule = Rule::new(
        "isolated",
        atom("isolated", vec![var("x")]),
        vec![
            Literal::Positive(atom("entity", vec![var("x"), var("t"), var("l")])),
            Literal::Negative(atom(
                "relation",
                vec![constant(Value::symbol("depends")), var("x"), var("x")],
            )),
        ],
    );
    let bundle = bundle(vec![negation_rule], &["relation"]);
    let build = harness.build(bundle.clone(), false);
    let result = harness.query(
        &build.context.projection_build_id,
        "isolated",
        vec![Some(rid(0x99).to_value())],
    );
    assert!(result.rows.is_empty());
    assert!(result.absence_established);
    assert_eq!(result.status, ExecutionStatus::Complete);

    let revision = harness.workspace.current_revision().expect("revision");
    let mut service = DatalogService::new(&mut harness.workspace);
    let incomplete = service
        .build(BuildRequest {
            actor: "datalog-test".to_owned(),
            scope: scope(),
            revision,
            bundle,
            limits: Limits::default(),
            publish: false,
            incomplete_extents: BTreeSet::from(["relation".to_owned()]),
            cancellation: None,
        })
        .expect("incomplete build");
    assert_eq!(incomplete.status, ExecutionStatus::Partial);
    let result = service
        .query(
            &incomplete.context.projection_build_id,
            Query::all("isolated", 100),
        )
        .expect("query");
    assert!(result.rows.is_empty());
    assert!(!result.absence_established);
    assert!(!result.exhaustive);
    assert!(result.coverage.iter().any(|coverage| {
        coverage.predicate == "isolated" && coverage.status == CoverageStatus::Incomplete
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
    let aggregate_rule = Rule::new(
        "degree",
        atom("degree", vec![var("x"), var("n")]),
        vec![
            Literal::Positive(atom(
                "relation",
                vec![constant(Value::symbol("depends")), var("x"), var("y")],
            )),
            Literal::Aggregate {
                function: AggregateFunction::Count,
                input: var("y"),
                output: "n".to_owned(),
            },
        ],
    );
    let build = harness.build(bundle(vec![aggregate_rule], &["relation"]), false);
    let result = harness.query(
        &build.context.projection_build_id,
        "degree",
        vec![Some(rid(0x10).to_value()), None],
    );
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].values[1], Value::integer(2));
    assert!(!result.rows[0].supports.is_empty());
}

#[test]
fn cancellation_timeout_and_row_caps_never_establish_absence() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let cancelled = Arc::new(AtomicBool::new(true));
    let revision = harness.workspace.current_revision().expect("revision");
    let mut service = DatalogService::new(&mut harness.workspace);
    let build = service
        .build(BuildRequest {
            actor: "datalog-test".to_owned(),
            scope: scope(),
            revision,
            bundle: path_bundle(),
            limits: Limits::default(),
            publish: false,
            incomplete_extents: BTreeSet::new(),
            cancellation: Some(cancelled),
        })
        .expect("cancelled build");
    assert_eq!(build.status, ExecutionStatus::Cancelled);
    let result = service
        .query(&build.context.projection_build_id, Query::all("path", 100))
        .expect("cancelled query");
    assert_eq!(result.status, ExecutionStatus::Cancelled);
    assert!(!result.absence_established);

    let revision = harness.workspace.current_revision().expect("revision");
    let mut service = DatalogService::new(&mut harness.workspace);
    let timed_out = service
        .build(BuildRequest {
            actor: "datalog-test".to_owned(),
            scope: scope(),
            revision,
            bundle: path_bundle(),
            limits: Limits {
                max_work: 2,
                ..Limits::default()
            },
            publish: false,
            incomplete_extents: BTreeSet::new(),
            cancellation: None,
        })
        .expect("timeout build");
    assert_eq!(timed_out.status, ExecutionStatus::Timeout);
    let result = service
        .query(
            &timed_out.context.projection_build_id,
            Query {
                predicate: "path".to_owned(),
                constants: Vec::new(),
                limit: 1,
                allow_stale: false,
                cancellation: None,
            },
        )
        .expect("timeout query");
    assert_eq!(result.status, ExecutionStatus::Timeout);
    assert!(!result.absence_established);
    assert!(!result.exhaustive);
}

#[test]
fn stale_builds_require_explicit_permission_and_publication_is_registered() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let build = harness.build(path_bundle(), true);
    let projection = harness
        .workspace
        .projection("datalog:base:project:cedar")
        .expect("projection")
        .expect("registered projection");
    assert_eq!(projection.revision, build.context.served_revision);
    assert_eq!(projection.rule_version, "1");
    assert!(
        harness
            .workspace
            .retention_participant("datalog:base:project:cedar")
            .expect("participant")
            .is_some()
    );
    harness.add_entity("entity-d", rid(0x13), &scope(), "D");
    let mut service = DatalogService::new(&mut harness.workspace);
    let stale = service.query_build(&build, Query::all("path", 10));
    assert!(matches!(stale, Err(DatalogError::Stale { .. })));
    let stale_ok = service
        .query_build(
            &build,
            Query {
                predicate: "path".to_owned(),
                constants: Vec::new(),
                limit: 10,
                allow_stale: true,
                cancellation: None,
            },
        )
        .expect("stale allowed");
    assert_eq!(stale_ok.served_revision, build.context.served_revision);
    assert_ne!(stale_ok.requested_revision, stale_ok.served_revision);
    assert!(stale_ok.exhaustive);
    drop(service);
    harness.add_entity("entity-e", rid(0x14), &scope(), "E");
    let current = harness.workspace.current_revision().expect("current");
    let mut service = DatalogService::new(&mut harness.workspace);
    let stale_again = service
        .query_build(
            &build,
            Query {
                predicate: "path".to_owned(),
                constants: Vec::new(),
                limit: 10,
                allow_stale: true,
                cancellation: None,
            },
        )
        .expect("second stale query");
    assert_eq!(stale_again.requested_revision, current);
    assert_ne!(
        stale_again.requested_revision, stale_ok.requested_revision,
        "a stale query cache entry must not hide the new requested revision"
    );
}

fn add_assertion_support(harness: &mut Harness, sources: bool) -> RecordId {
    harness.add_entity("assertion-entity", rid(0x10), &scope(), "A");
    let source_a = b"= Source A\n\nExact source A.\n";
    let source_b = b"= Source B\n\nExact source B.\n";
    let (source_record, source_blob) = build_source(
        rid(0x20),
        rev(0x21),
        &scope(),
        source_a,
        "text/asciidoc",
        Some(rid(0x10)),
        Some("a.adoc"),
    )
    .expect("source a");
    let mut records = vec![source_record];
    let mut blobs = vec![source_blob];
    if sources {
        let (source_record_b, source_blob_b) = build_source(
            rid(0x22),
            rev(0x23),
            &scope(),
            source_b,
            "text/asciidoc",
            Some(rid(0x10)),
            Some("b.adoc"),
        )
        .expect("source b");
        records.push(source_record_b);
        blobs.push(source_blob_b);
    }
    harness.commit("sources", records, blobs);
    let span = SourceSpan::new(0, 10).expect("span");
    let mut evidence = vec![build_evidence(
        rid(0x30),
        rev(0x31),
        &scope(),
        rid(0x40),
        rid(0x20),
        rev(0x21),
        Some(span),
        Some("a"),
        mneme_memory::SupportRelation::Supports,
        Origin::AuthoredStatement,
        &[],
    )];
    if sources {
        evidence.push(build_evidence(
            rid(0x32),
            rev(0x33),
            &scope(),
            rid(0x40),
            rid(0x22),
            rev(0x23),
            Some(span),
            Some("b"),
            mneme_memory::SupportRelation::Supports,
            Origin::AuthoredStatement,
            &[],
        ));
    }
    let evidence_refs = evidence
        .iter()
        .map(|record| Reference::local(record.record_id, mneme_core::RecordKind::Evidence))
        .collect::<Vec<_>>();
    let assertion = build_proposed_assertion(
        rid(0x40),
        rev(0x41),
        &scope(),
        rid(0x10),
        "claim",
        Value::string("retained"),
        Stance::Affirm,
        Origin::AuthoredStatement,
        "author",
        ValidTime::always(),
        &evidence_refs,
        None,
        None,
    );
    harness.commit(
        "evidence",
        evidence
            .into_iter()
            .chain(std::iter::once(assertion))
            .collect(),
        Vec::new(),
    );
    let current = harness
        .workspace
        .record_revisions(rid(0x40))
        .expect("assertion")
        .into_iter()
        .last()
        .expect("assertion revision");
    let decision = build_decision(
        rid(0x50),
        rev(0x51),
        &scope(),
        DecisionKind::Acceptance,
        rid(0x40),
        "author",
        "datalog-policy/v1",
        harness.workspace.current_revision().expect("base"),
        "accepted",
        "datalog fixture",
        &[],
        &[],
    );
    let accepted = build_assertion_revision(
        &current,
        rev(0x42),
        Lifecycle::Accepted,
        Reference::local(rid(0x50), mneme_core::RecordKind::Decision),
        None,
    );
    harness.commit("accept", vec![decision, accepted], Vec::new());
    rid(0x40)
}

#[test]
fn retraction_pruning_and_forget_update_datalog_support() {
    let mut harness = Harness::new();
    let assertion = add_assertion_support(&mut harness, true);
    let bundle = RuleBundle::new(
        "claims",
        "1",
        3,
        BTreeMap::from([("assertion".to_owned(), 4)]),
        BTreeSet::from(["assertion".to_owned()]),
        vec![Rule::new(
            "claim",
            atom("claim", vec![var("subject"), var("value")]),
            vec![Literal::Positive(atom(
                "assertion",
                vec![
                    var("subject"),
                    constant(Value::symbol("claim")),
                    var("value"),
                    var("id"),
                ],
            ))],
        )],
    );
    let build = harness.build(bundle.clone(), false);
    assert_eq!(build.status, ExecutionStatus::Complete);
    let result = harness.query(
        &build.context.projection_build_id,
        "claim",
        vec![Some(rid(0x10).to_value()), Some(Value::string("retained"))],
    );
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].supports[0].sources.len(), 2);

    // Withdraw source A's support through the retention service.
    let request = RetentionRequest {
        actor: "datalog-test".to_owned(),
        scope: scope(),
        base_revision: harness.workspace.current_revision().expect("base"),
        idempotency_key: "withdraw-a".to_owned(),
        operation: OperationKind::AssertionRetraction,
        selector: Selector::SourceSupport(rid(0x20)),
        effective: None,
        policy: RetentionPolicy::default(),
    };
    Retention::new(&mut harness.workspace)
        .execute(request)
        .expect("withdraw");
    let build = harness.build(bundle.clone(), false);
    let result = harness.query(
        &build.context.projection_build_id,
        "claim",
        vec![Some(rid(0x10).to_value()), Some(Value::string("retained"))],
    );
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].supports[0].sources.len(), 1);

    // Withdraw the final support: the conclusion disappears and absence is not
    // claimed until the relation coverage is complete.
    let request = RetentionRequest {
        actor: "datalog-test".to_owned(),
        scope: scope(),
        base_revision: harness.workspace.current_revision().expect("base"),
        idempotency_key: "withdraw-b".to_owned(),
        operation: OperationKind::AssertionRetraction,
        selector: Selector::SourceSupport(rid(0x22)),
        effective: None,
        policy: RetentionPolicy::default(),
    };
    Retention::new(&mut harness.workspace)
        .execute(request)
        .expect("withdraw b");
    let build = harness.build(bundle, false);
    let result = harness.query(
        &build.context.projection_build_id,
        "claim",
        vec![Some(rid(0x10).to_value()), Some(Value::string("retained"))],
    );
    assert!(result.rows.is_empty());
    assert!(
        result.absence_established,
        "the complete claim relation now contains no eligible support"
    );

    // Source pruning leaves the claim eligible but marks the source unavailable.
    let mut harness = Harness::new();
    add_assertion_support(&mut harness, false);
    let prune = RetentionRequest {
        actor: "datalog-test".to_owned(),
        scope: scope(),
        base_revision: harness.workspace.current_revision().expect("base"),
        idempotency_key: "prune-a".to_owned(),
        operation: OperationKind::SourcePruning,
        selector: Selector::Source(rid(0x20)),
        effective: None,
        policy: RetentionPolicy::default(),
    };
    let source_blob = blob::blob_path(
        harness.temp.path(),
        mneme_core::ContentDigest::of_source_bytes(b"= Source A\n\nExact source A.\n"),
    );
    Retention::new(&mut harness.workspace)
        .execute(prune)
        .expect("prune");
    assert_missing(&source_blob);
    let bundle = RuleBundle::new(
        "pruned",
        "1",
        3,
        BTreeMap::from([("assertion".to_owned(), 4)]),
        BTreeSet::from(["assertion".to_owned()]),
        vec![Rule::new(
            "claim",
            atom("claim", vec![var("subject"), var("value")]),
            vec![Literal::Positive(atom(
                "assertion",
                vec![
                    var("subject"),
                    constant(Value::symbol("claim")),
                    var("value"),
                    var("id"),
                ],
            ))],
        )],
    );
    let build = harness.build(bundle, false);
    let result = harness.query(
        &build.context.projection_build_id,
        "claim",
        vec![Some(rid(0x10).to_value()), Some(Value::string("retained"))],
    );
    assert_eq!(result.rows.len(), 1);
    assert!(
        result.rows[0].supports[0]
            .premises
            .iter()
            .any(|premise| { premise.source_availability.as_deref() == Some("pruned") })
    );
    let _ = assertion;
}

#[test]
fn query_row_limit_is_non_exhaustive() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let build = harness.build(path_bundle(), false);
    let mut service = DatalogService::new(&mut harness.workspace);
    let result = service
        .query_build(
            &build,
            Query {
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
    let bundle = RuleBundle::new(
        "forget",
        "1",
        3,
        BTreeMap::from([("assertion".to_owned(), 4)]),
        BTreeSet::from(["assertion".to_owned()]),
        vec![Rule::new(
            "claim",
            atom("claim", vec![var("subject"), var("value")]),
            vec![Literal::Positive(atom(
                "assertion",
                vec![
                    var("subject"),
                    constant(Value::symbol("claim")),
                    var("value"),
                    var("id"),
                ],
            ))],
        )],
    );
    let old_build = harness.build(bundle.clone(), false);
    let old_build_id = old_build.context.projection_build_id.clone();
    let result = harness.query(
        &old_build_id,
        "claim",
        vec![Some(rid(0x10).to_value()), Some(Value::string("retained"))],
    );
    assert_eq!(result.rows.len(), 1);

    let request = RetentionRequest {
        actor: "datalog-test".to_owned(),
        scope: scope(),
        base_revision: harness.workspace.current_revision().expect("base"),
        idempotency_key: "forget-a".to_owned(),
        operation: OperationKind::Forget,
        selector: Selector::Source(rid(0x20)),
        effective: None,
        policy: RetentionPolicy::default(),
    };
    Retention::new(&mut harness.workspace)
        .execute(request)
        .expect("forget");
    let build = harness.build(bundle, false);
    let result = harness.query(
        &build.context.projection_build_id,
        "claim",
        vec![Some(rid(0x10).to_value()), Some(Value::string("retained"))],
    );
    assert!(result.rows.is_empty());
    assert!(result.absence_established);

    let mut service = DatalogService::new(&mut harness.workspace);
    assert!(matches!(
        service.publish_build(&old_build),
        Err(DatalogError::Store(StoreError::BarrierAdvanced { .. }))
    ));
    let stale = service.query_build(&old_build, Query::all("claim", 100));
    assert!(matches!(
        stale,
        Err(DatalogError::Store(StoreError::BarrierAdvanced { .. }))
    ));
}

#[test]
fn support_budget_truncation_is_explicit() {
    let mut harness = Harness::new();
    harness.add_entity("a", rid(0x10), &scope(), "A");
    harness.add_entity("b", rid(0x11), &scope(), "B");
    harness.add_relation("first", rid(0x20), &scope(), rid(0x10), rid(0x11));
    harness.add_relation("second", rid(0x21), &scope(), rid(0x10), rid(0x11));
    let revision = harness.workspace.current_revision().expect("revision");
    let mut service = DatalogService::new(&mut harness.workspace);
    let build = service
        .build(BuildRequest {
            actor: "datalog-test".to_owned(),
            scope: scope(),
            revision,
            bundle: bundle(
                vec![Rule::new(
                    "edge",
                    atom("path", vec![var("x"), var("y")]),
                    vec![Literal::Positive(atom(
                        "relation",
                        vec![constant(Value::symbol("depends")), var("x"), var("y")],
                    ))],
                )],
                &["relation"],
            ),
            limits: Limits {
                max_supports_per_fact: 1,
                ..Limits::default()
            },
            publish: false,
            incomplete_extents: BTreeSet::new(),
            cancellation: None,
        })
        .expect("build");
    assert!(build.support_truncated);
    let result = service
        .query_build(&build, Query::all("relation", 10))
        .expect("query");
    assert_eq!(result.rows.len(), 1);
    assert!(result.rows[0].support_truncated);
}

#[test]
fn query_build_returns_explicit_context_and_no_absence_on_unrelated_partial_build() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let bundle = bundle(
        vec![Rule::new(
            "edge",
            atom("path", vec![var("x"), var("y")]),
            vec![Literal::Positive(atom(
                "relation",
                vec![constant(Value::symbol("depends")), var("x"), var("y")],
            ))],
        )],
        &["relation"],
    );
    let revision = harness.workspace.current_revision().expect("revision");
    let mut service = DatalogService::new(&mut harness.workspace);
    let build = service
        .build(BuildRequest {
            actor: "datalog-test".to_owned(),
            scope: scope(),
            revision,
            bundle,
            limits: Limits::default(),
            publish: false,
            incomplete_extents: BTreeSet::from(["source".to_owned()]),
            cancellation: None,
        })
        .expect("build");
    assert_eq!(build.status, ExecutionStatus::Partial);
    let result = service
        .query_build(&build, Query::all("path", 10))
        .expect("query");
    assert_eq!(result.status, ExecutionStatus::Complete);
    assert!(result.exhaustive);
}

#[test]
fn query_summary_serialization_distinguishes_complete_incomplete_and_truncated() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let complete_build = harness.build(path_bundle(), false);
    let complete = harness.query(
        &complete_build.context.projection_build_id,
        "path",
        vec![Some(rid(0x99).to_value()), Some(rid(0x98).to_value())],
    );
    assert!(complete.absence_established);
    let truncated = {
        let build = harness
            .builds
            .get(&complete_build.context.projection_build_id)
            .cloned()
            .expect("cached build");
        let mut service = DatalogService::new(&mut harness.workspace);
        service
            .query_build(&build, Query::all("path", 1))
            .expect("truncated query")
    };
    let negation_rule = Rule::new(
        "isolated",
        atom("isolated", vec![var("x")]),
        vec![
            Literal::Positive(atom("entity", vec![var("x"), var("t"), var("l")])),
            Literal::Negative(atom(
                "relation",
                vec![constant(Value::symbol("depends")), var("x"), var("x")],
            )),
        ],
    );
    let rules = bundle(vec![negation_rule], &["relation"]);
    let revision = harness.workspace.current_revision().expect("revision");
    let mut service = DatalogService::new(&mut harness.workspace);
    let incomplete = service
        .build(BuildRequest {
            actor: "datalog-test".to_owned(),
            scope: scope(),
            revision,
            bundle: rules,
            limits: Limits::default(),
            publish: false,
            incomplete_extents: BTreeSet::from(["relation".to_owned()]),
            cancellation: None,
        })
        .expect("incomplete build");
    let incomplete = service
        .query(
            &incomplete.context.projection_build_id,
            Query::all("isolated", 100),
        )
        .expect("incomplete query");

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
        vec![Rule::new(
            "unsafe",
            atom("out", vec![var("unbound")]),
            vec![Literal::Positive(atom(
                "relation",
                vec![constant(Value::symbol("depends")), var("x"), var("y")],
            ))],
        )],
        &[],
    );
    let revision = harness.workspace.current_revision().expect("revision");
    {
        let mut service = DatalogService::new(&mut harness.workspace);
        let invalid = service.build(BuildRequest {
            actor: "datalog-test".to_owned(),
            scope: scope(),
            revision,
            bundle: unsafe_bundle,
            limits: Limits::default(),
            publish: true,
            incomplete_extents: BTreeSet::new(),
            cancellation: None,
        });
        assert!(matches!(invalid, Err(DatalogError::InvalidBundle(_))));
    }
    assert!(
        harness
            .workspace
            .projection(&projection_name)
            .expect("projection lookup")
            .is_none()
    );
    let build = {
        let mut service = DatalogService::new(&mut harness.workspace);
        let build = service
            .build(BuildRequest {
                actor: "datalog-test".to_owned(),
                scope: scope(),
                revision,
                bundle: path_bundle(),
                limits: Limits::default(),
                publish: false,
                incomplete_extents: BTreeSet::new(),
                cancellation: None,
            })
            .expect("private build");
        service.publish_build(&build).expect("publish");
        build
    };
    assert!(
        harness
            .workspace
            .projection(&projection_name)
            .expect("projection lookup")
            .is_some()
    );
    let published = harness
        .workspace
        .projection(&projection_name)
        .expect("projection lookup")
        .expect("published projection");
    assert_eq!(published.revision, build.context.served_revision);
    harness
        .workspace
        .advance_eligibility_barrier()
        .expect("advance barrier");
    {
        let mut service = DatalogService::new(&mut harness.workspace);
        assert!(matches!(
            service.publish_build(&build),
            Err(DatalogError::Store(StoreError::BarrierAdvanced { .. }))
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
    let revision = harness.workspace.current_revision().expect("revision");
    let mut service = DatalogService::new(&mut harness.workspace);
    let build = service
        .build(BuildRequest {
            actor: "datalog-test".to_owned(),
            scope: scope(),
            revision,
            bundle: path_bundle(),
            limits: Limits {
                max_recursion_depth: 0,
                ..Limits::default()
            },
            publish: false,
            incomplete_extents: BTreeSet::new(),
            cancellation: None,
        })
        .expect("depth-limited build");
    assert_eq!(build.status, ExecutionStatus::Partial);
    let result = service
        .query_build(&build, Query::all("path", 100))
        .expect("depth-limited query");
    assert!(!result.exhaustive);
    assert!(!result.absence_established);
    assert!(result.coverage.iter().any(|coverage| {
        coverage.predicate == "path" && coverage.status == CoverageStatus::Incomplete
    }));
}

#[test]
fn build_identity_binds_limits_and_incomplete_extents() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let revision = harness.workspace.current_revision().expect("revision");
    let mut service = DatalogService::new(&mut harness.workspace);
    let request = |limits: Limits, incomplete: BTreeSet<String>| BuildRequest {
        actor: "datalog-test".to_owned(),
        scope: scope(),
        revision,
        bundle: path_bundle(),
        limits,
        publish: false,
        incomplete_extents: incomplete,
        cancellation: None,
    };
    let default = service
        .build(request(Limits::default(), BTreeSet::new()))
        .expect("default build");
    let timed = service
        .build(request(
            Limits {
                max_work: 0,
                ..Limits::default()
            },
            BTreeSet::new(),
        ))
        .expect("different-limit build");
    let incomplete = service
        .build(request(
            Limits::default(),
            BTreeSet::from(["relation".to_owned()]),
        ))
        .expect("incomplete build");
    assert_ne!(
        default.context.projection_build_id,
        timed.context.projection_build_id
    );
    assert_ne!(
        default.context.projection_build_id,
        incomplete.context.projection_build_id
    );
    assert_ne!(
        timed.context.projection_build_id,
        incomplete.context.projection_build_id
    );
}

#[test]
fn terminal_failures_are_recomputed_and_never_published() {
    let mut harness = Harness::new();
    add_graph(&mut harness);
    let revision = harness.workspace.current_revision().expect("revision");
    let cancelled = Arc::new(AtomicBool::new(true));
    let mut service = DatalogService::new(&mut harness.workspace);
    let build_request = |publish: bool, cancellation: Option<Arc<AtomicBool>>| BuildRequest {
        actor: "datalog-test".to_owned(),
        scope: scope(),
        revision,
        bundle: path_bundle(),
        limits: Limits::default(),
        publish,
        incomplete_extents: BTreeSet::new(),
        cancellation,
    };
    let first = service
        .build(build_request(false, Some(cancelled.clone())))
        .expect("cancelled build");
    assert_eq!(first.status, ExecutionStatus::Cancelled);
    let retried = service
        .build(build_request(false, None))
        .expect("retry build");
    assert_eq!(retried.status, ExecutionStatus::Complete);
    assert!(matches!(
        service.build(build_request(true, Some(cancelled))),
        Err(DatalogError::Failed(_))
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
