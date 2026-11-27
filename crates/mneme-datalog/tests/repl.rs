//! Dynamic Datalog REPL session tests over committed snapshots.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::expect_used)] // test/fixture code fails by expect, not a production path

fn scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
}

fn rid(byte: u8) -> mneme_core::RecordId {
    mneme_core::RecordId::from_bytes([byte; 16])
}

fn rev(byte: u8) -> mneme_core::RevisionId {
    mneme_core::RevisionId::from_bytes([byte; 16])
}

fn draft(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    kind: mneme_core::RecordKind,
    scope: mneme_core::ScopeId,
    payload: mneme_core::Payload,
) -> mneme_store::RecordDraft {
    mneme_store::RecordDraft {
        schema_version: 1,
        kind,
        record_id,
        revision_id,
        predecessor: None,
        scope,
        payload,
    }
}

fn paper_payload(label: &str) -> mneme_core::Payload {
    mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("entity-type"),
            mneme_core::Value::symbol("paper"),
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

fn concept_payload(label: &str) -> mneme_core::Payload {
    mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("entity-type"),
            mneme_core::Value::symbol("concept"),
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

fn setup_workspace() -> (
    tempfile::TempDir,
    mneme_store::Workspace,
    mneme_core::WorkspaceRevisionId,
) {
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

    let e1 = draft(
        rid(1),
        rev(1),
        mneme_core::RecordKind::Entity,
        scope(),
        paper_payload("Paper One"),
    );
    let e2 = draft(
        rid(2),
        rev(2),
        mneme_core::RecordKind::Entity,
        scope(),
        paper_payload("Paper Two"),
    );
    let e3 = draft(
        rid(3),
        rev(3),
        mneme_core::RecordKind::Entity,
        scope(),
        concept_payload("Concept A"),
    );
    let rel = draft(
        rid(4),
        rev(4),
        mneme_core::RecordKind::Relation,
        scope(),
        relation_payload("bridges", rid(1), rid(3)),
    );

    let outcome = workspace
        .commit(mneme_store::CommitCommand {
            base: workspace.current_revision().expect("base"),
            actor: "repl-test".to_owned(),
            scope: scope(),
            idempotency_key: "seed".to_owned(),
            records: vec![e1, e2, e3, rel],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit");

    assert_eq!(
        workspace.current_revision().expect("head"),
        outcome.revision
    );
    assert!(outcome.revision.to_hex().len() == 32);
    (temp, workspace, outcome.revision)
}

fn open_session(
    workspace: &mut mneme_store::Workspace,
    revision: Option<mneme_core::WorkspaceRevisionId>,
    limits: mneme_datalog::ReplLimits,
) -> mneme_datalog::ReplSession {
    mneme_datalog::ReplSession::open(
        workspace,
        mneme_datalog::ReplSessionRequest {
            actor: "repl-test".to_owned(),
            scope: scope(),
            revision,
            limits,
            incomplete_extents: std::collections::BTreeSet::new(),
            complete_predicates: std::collections::BTreeSet::new(),
            access: mneme_memory::Access::Operator,
            at: None,
        },
    )
    .expect("open repl session")
}

fn paper_rule() -> mneme_datalog::Rule {
    mneme_datalog::Rule::new(
        "r-paper",
        mneme_datalog::Atom::new(
            "paper_in_class",
            vec![
                mneme_datalog::Term::var("E"),
                mneme_datalog::Term::var("Name"),
            ],
        ),
        vec![mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
            "entity",
            vec![
                mneme_datalog::Term::var("E"),
                mneme_datalog::Term::constant(mneme_core::Value::symbol("paper")),
                mneme_datalog::Term::var("Name"),
            ],
        ))],
    )
}

fn bridged_rule() -> mneme_datalog::Rule {
    mneme_datalog::Rule::new(
        "r-bridged",
        mneme_datalog::Atom::new("already_bridged", vec![mneme_datalog::Term::var("E")]),
        vec![mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
            "relation",
            vec![
                mneme_datalog::Term::constant(mneme_core::Value::symbol("bridges")),
                mneme_datalog::Term::var("E"),
                mneme_datalog::Term::var("Target"),
            ],
        ))],
    )
}

fn unbridged_rule() -> mneme_datalog::Rule {
    mneme_datalog::Rule::new(
        "r-unbridged",
        mneme_datalog::Atom::new(
            "unbridged_candidate",
            vec![
                mneme_datalog::Term::var("E"),
                mneme_datalog::Term::var("Name"),
            ],
        ),
        vec![
            mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                "paper_in_class",
                vec![
                    mneme_datalog::Term::var("E"),
                    mneme_datalog::Term::var("Name"),
                ],
            )),
            mneme_datalog::Literal::Negative(mneme_datalog::Atom::new(
                "already_bridged",
                vec![mneme_datalog::Term::var("E")],
            )),
        ],
    )
}

#[test]
fn incremental_stratified_negation_reuses_unaffected_relations_and_retracts_cleanly() {
    let (_temp, mut workspace, rev1) = setup_workspace();
    let mut session = open_session(
        &mut workspace,
        Some(rev1),
        mneme_datalog::ReplLimits::default(),
    );

    let step1 = session.add_rule(paper_rule()).expect("add paper rule");
    assert_eq!(step1.rule_count, 1);
    assert_eq!(step1.affected_predicates, vec!["paper_in_class"]);
    assert!(step1.reused_predicates.is_empty());

    // Adding an independent relation reuses `paper_in_class` without re-evaluating it.
    let step2 = session.add_rule(bridged_rule()).expect("add bridged rule");
    assert_eq!(step2.rule_count, 2);
    assert_eq!(step2.affected_predicates, vec!["already_bridged"]);
    assert_eq!(step2.reused_predicates, vec!["paper_in_class"]);

    // Stratified negation over both derived relations.
    let step3 = session
        .add_rule(unbridged_rule())
        .expect("add unbridged rule");
    assert_eq!(step3.rule_count, 3);
    assert_eq!(step3.affected_predicates, vec!["unbridged_candidate"]);
    assert_eq!(
        step3.reused_predicates,
        vec!["already_bridged", "paper_in_class"]
    );

    let result = session
        .query_relation(
            Some(&mut workspace),
            mneme_datalog::Query::all("unbridged_candidate", 10),
        )
        .expect("query unbridged_candidate");
    assert_eq!(result.rows.len(), 1);
    assert_eq!(
        result.rows[0].values,
        vec![rid(2).to_value(), mneme_core::Value::string("Paper Two")]
    );
    assert!(result.exhaustive);
    assert!(!result.truncated);

    // Retracting `already_bridged` while `unbridged_candidate` still depends on it fails closed.
    let err = session
        .retract_rule("r-bridged")
        .expect_err("dangling negated predicate must be rejected");
    assert!(matches!(err, mneme_datalog::Error::InvalidBundle(_)));

    // Retracting `unbridged_candidate` first, then `already_bridged`, succeeds and keeps `paper_in_class`.
    let retract1 = session
        .retract_rule("r-unbridged")
        .expect("retract unbridged");
    assert_eq!(retract1.rule_count, 2);
    assert_eq!(
        retract1.reused_predicates,
        vec!["already_bridged", "paper_in_class"]
    );

    let retract2 = session.retract_rule("r-bridged").expect("retract bridged");
    assert_eq!(retract2.rule_count, 1);
    assert_eq!(retract2.reused_predicates, vec!["paper_in_class"]);

    let papers = session
        .query_relation(
            Some(&mut workspace),
            mneme_datalog::Query::all("paper_in_class", 10),
        )
        .expect("query paper_in_class");
    assert_eq!(papers.rows.len(), 2);
}

#[test]
fn invalid_rules_are_rejected_without_mutating_session_state() {
    let (_temp, mut workspace, rev1) = setup_workspace();
    let mut session = open_session(
        &mut workspace,
        Some(rev1),
        mneme_datalog::ReplLimits::default(),
    );
    session.add_rule(paper_rule()).expect("seed rule");
    let work_before = session.total_work();

    // 1. Unsafe rule (unbound head variable `Z`).
    let unsafe_rule = mneme_datalog::Rule::new(
        "r-unsafe",
        mneme_datalog::Atom::new("bad_rel", vec![mneme_datalog::Term::var("Z")]),
        vec![mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
            "paper_in_class",
            vec![mneme_datalog::Term::var("E"), mneme_datalog::Term::var("N")],
        ))],
    );
    assert!(matches!(
        session.add_rule(unsafe_rule),
        Err(mneme_datalog::Error::InvalidBundle(_))
    ));

    // 2. Non-stratified negation (self-negation).
    let non_stratified = mneme_datalog::Rule::new(
        "r-cycle-neg",
        mneme_datalog::Atom::new("loop_neg", vec![mneme_datalog::Term::var("E")]),
        vec![
            mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                "paper_in_class",
                vec![mneme_datalog::Term::var("E"), mneme_datalog::Term::var("N")],
            )),
            mneme_datalog::Literal::Negative(mneme_datalog::Atom::new(
                "loop_neg",
                vec![mneme_datalog::Term::var("E")],
            )),
        ],
    );
    assert!(matches!(
        session.add_rule(non_stratified),
        Err(mneme_datalog::Error::InvalidBundle(_))
    ));

    // 3. Duplicate rule id.
    assert!(matches!(
        session.add_rule(paper_rule()),
        Err(mneme_datalog::Error::InvalidBundle(_))
    ));

    // 4. Canonical extent as head.
    let canonical_head = mneme_datalog::Rule::new(
        "r-canonical-head",
        mneme_datalog::Atom::new(
            "entity",
            vec![
                mneme_datalog::Term::var("E"),
                mneme_datalog::Term::constant(mneme_core::Value::symbol("paper")),
                mneme_datalog::Term::var("N"),
            ],
        ),
        vec![mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
            "paper_in_class",
            vec![mneme_datalog::Term::var("E"), mneme_datalog::Term::var("N")],
        ))],
    );
    assert!(matches!(
        session.add_rule(canonical_head),
        Err(mneme_datalog::Error::InvalidBundle(_))
    ));

    assert_eq!(session.rules().len(), 1);
    assert_eq!(session.total_work(), work_before);
}

#[test]
fn repl_enforces_rule_work_and_row_limits_and_revision_pinning() {
    let (_temp, mut workspace, rev1) = setup_workspace();

    // Rule limit = 1.
    let mut rule_limited = open_session(
        &mut workspace,
        Some(rev1),
        mneme_datalog::ReplLimits {
            max_rules: 1,
            ..mneme_datalog::ReplLimits::default()
        },
    );
    rule_limited.add_rule(paper_rule()).expect("first rule");
    let err = rule_limited
        .add_rule(bridged_rule())
        .expect_err("second rule exceeds max_rules");
    assert!(matches!(err, mneme_datalog::Error::LimitExceeded(_)));

    // Tight total work limit: open succeeds, rule evaluation exceeds budget and rolls back.
    let open_only = open_session(
        &mut workspace,
        Some(rev1),
        mneme_datalog::ReplLimits::default(),
    );
    let base_work = open_only.total_work();
    let mut work_limited = open_session(
        &mut workspace,
        Some(rev1),
        mneme_datalog::ReplLimits {
            max_total_work: base_work + 1,
            ..mneme_datalog::ReplLimits::default()
        },
    );
    let err = work_limited
        .add_rule(paper_rule())
        .expect_err("rule exceeds max_total_work");
    assert!(matches!(err, mneme_datalog::Error::LimitExceeded(_)));
    assert!(work_limited.rules().is_empty());

    // Query row limit truncation.
    let mut session = open_session(&mut workspace, None, mneme_datalog::ReplLimits::default());
    session.add_rule(paper_rule()).expect("add paper rule");
    let truncated = session
        .query_relation(
            Some(&mut workspace),
            mneme_datalog::Query::all("paper_in_class", 1),
        )
        .expect("query limit 1");
    assert_eq!(truncated.rows.len(), 1);
    assert!(truncated.truncated);
    assert!(!truncated.exhaustive);

    // Commit a new entity on head; pinned session still serves rev1 and reports stale = true
    // because it was opened with `revision: None` (head at open time).
    let e4 = draft(
        rid(10),
        rev(10),
        mneme_core::RecordKind::Entity,
        scope(),
        paper_payload("Paper Three"),
    );
    workspace
        .commit(mneme_store::CommitCommand {
            base: rev1,
            actor: "repl-test".to_owned(),
            scope: scope(),
            idempotency_key: "commit-2".to_owned(),
            records: vec![e4],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit 2");

    let stale_view = session
        .query_relation(
            Some(&mut workspace),
            mneme_datalog::Query::all("paper_in_class", 10),
        )
        .expect("query after commit");
    assert_eq!(stale_view.rows.len(), 2);
    assert!(stale_view.stale);
    assert_eq!(stale_view.served_revision, rev1);
}

fn id_with_tag(parts: [u8; 2]) -> mneme_core::RecordId {
    let mut bytes = [0_u8; 16];
    bytes[0] = parts[0];
    bytes[15] = parts[1];
    mneme_core::RecordId::from_bytes(bytes)
}

fn rev_with_tag(parts: [u8; 2]) -> mneme_core::RevisionId {
    let mut bytes = [0_u8; 16];
    bytes[0] = parts[0];
    bytes[15] = parts[1];
    mneme_core::RevisionId::from_bytes(bytes)
}

fn source_draft(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    entity: mneme_core::RecordId,
    bytes: &[u8],
    hint: &str,
) -> (mneme_store::RecordDraft, mneme_store::SourceBlobDraft) {
    mneme_memory::build_source(
        record_id,
        revision_id,
        &scope(),
        mneme_memory::SourceOptions {
            bytes,
            media_type: "text/asciidoc",
            entity: Some(entity),
            path_hint: Some(hint),
        },
    )
    .expect("build source")
}

struct AcceptedAssertionFixture<'a> {
    assertion_id: mneme_core::RecordId,
    proposed_rev: mneme_core::RevisionId,
    accepted_rev: mneme_core::RevisionId,
    evidence_id: mneme_core::RecordId,
    evidence_rev: mneme_core::RevisionId,
    decision_id: mneme_core::RecordId,
    decision_rev: mneme_core::RevisionId,
    subject: mneme_core::RecordId,
    source_id: mneme_core::RecordId,
    source_rev: mneme_core::RevisionId,
    claim_value: &'a str,
    key_prefix: &'a str,
}

fn propose_assertion_for_fixture(
    workspace: &mut mneme_store::Workspace,
    fixture: &AcceptedAssertionFixture<'_>,
) -> mneme_core::WorkspaceRevisionId {
    let span = mneme_core::SourceSpan::new(0, 10).expect("span");
    let evidence = mneme_memory::build_evidence(
        fixture.evidence_id,
        fixture.evidence_rev,
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: fixture.assertion_id,
            source: fixture.source_id,
            source_revision: fixture.source_rev,
            span: Some(span),
            anchor: Some("anchor"),
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let assertion = mneme_memory::build_proposed_assertion(
        fixture.assertion_id,
        fixture.proposed_rev,
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: fixture.subject,
            predicate: "topic",
            value: mneme_core::Value::string(fixture.claim_value.to_owned()),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "repl-test",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                fixture.evidence_id,
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    let base = workspace.current_revision().expect("base");
    let proposed_workspace_rev = workspace
        .commit(mneme_store::CommitCommand {
            base,
            actor: "repl-test".to_owned(),
            scope: scope(),
            idempotency_key: format!("{}-propose", fixture.key_prefix),
            records: vec![evidence, assertion],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit proposal")
        .revision;
    assert_ne!(proposed_workspace_rev, base);
    assert!(!fixture.claim_value.is_empty());
    proposed_workspace_rev
}

fn commit_accepted_assertion(
    workspace: &mut mneme_store::Workspace,
    fixture: AcceptedAssertionFixture<'_>,
) {
    let proposed_workspace_rev = propose_assertion_for_fixture(workspace, &fixture);
    let current = workspace
        .record_revisions(fixture.assertion_id)
        .expect("assertion revisions")
        .into_iter()
        .last()
        .expect("latest assertion");
    let decision = mneme_memory::build_decision(
        fixture.decision_id,
        fixture.decision_rev,
        &scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: fixture.assertion_id,
            actor: "repl-test",
            policy: "repl-policy/v1",
            input_revision: proposed_workspace_rev,
            outcome: "accepted",
            rationale: "direct support",
            evidence: &[],
            related: &[],
        },
    );
    let accepted = mneme_memory::build_assertion_revision(
        &current,
        fixture.accepted_rev,
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(fixture.decision_id, mneme_core::RecordKind::Decision),
        None,
    );
    let committed = workspace
        .commit(mneme_store::CommitCommand {
            base: proposed_workspace_rev,
            actor: "repl-test".to_owned(),
            scope: scope(),
            idempotency_key: format!("{}-accept", fixture.key_prefix),
            records: vec![decision, accepted],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit acceptance");
    assert_ne!(committed.revision, proposed_workspace_rev);
    assert!(committed.sequence > 0);
}

fn dbsp_test_rules() -> Vec<mneme_datalog::Rule> {
    let mut rules = dbsp_join_union_rules();
    rules.extend(dbsp_reach_aggregate_rules());
    rules
}

fn dbsp_join_union_rules() -> Vec<mneme_datalog::Rule> {
    vec![
        paper_rule(),
        bridged_rule(),
        unbridged_rule(),
        mneme_datalog::Rule::new(
            "r-bridge-join",
            mneme_datalog::Atom::new(
                "paper_bridges_concept",
                vec![
                    mneme_datalog::Term::var("E"),
                    mneme_datalog::Term::var("Name"),
                    mneme_datalog::Term::var("CName"),
                ],
            ),
            vec![
                mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                    "entity",
                    vec![
                        mneme_datalog::Term::var("E"),
                        mneme_datalog::Term::constant(mneme_core::Value::symbol("paper")),
                        mneme_datalog::Term::var("Name"),
                    ],
                )),
                mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                    "relation",
                    vec![
                        mneme_datalog::Term::constant(mneme_core::Value::symbol("bridges")),
                        mneme_datalog::Term::var("E"),
                        mneme_datalog::Term::var("C"),
                    ],
                )),
                mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                    "entity",
                    vec![
                        mneme_datalog::Term::var("C"),
                        mneme_datalog::Term::constant(mneme_core::Value::symbol("concept")),
                        mneme_datalog::Term::var("CName"),
                    ],
                )),
            ],
        ),
        mneme_datalog::Rule::new(
            "r-union-paper",
            mneme_datalog::Atom::new("active_node", vec![mneme_datalog::Term::var("E")]),
            vec![mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                "paper_in_class",
                vec![
                    mneme_datalog::Term::var("E"),
                    mneme_datalog::Term::var("Name"),
                ],
            ))],
        ),
    ]
}

fn dbsp_reach_aggregate_rules() -> Vec<mneme_datalog::Rule> {
    let mut rules = dbsp_reach_rules();
    rules.push(dbsp_claim_count_rule());
    rules
}

fn dbsp_reach_rules() -> Vec<mneme_datalog::Rule> {
    vec![
        mneme_datalog::Rule::new(
            "r-union-concept",
            mneme_datalog::Atom::new("active_node", vec![mneme_datalog::Term::var("E")]),
            vec![mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                "entity",
                vec![
                    mneme_datalog::Term::var("E"),
                    mneme_datalog::Term::constant(mneme_core::Value::symbol("concept")),
                    mneme_datalog::Term::var("Name"),
                ],
            ))],
        ),
        mneme_datalog::Rule::new(
            "r-reach-base",
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
            "r-reach-step",
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

fn dbsp_claim_count_rule() -> mneme_datalog::Rule {
    mneme_datalog::Rule::new(
        "r-claim-count",
        mneme_datalog::Atom::new(
            "claim_count",
            vec![mneme_datalog::Term::var("E"), mneme_datalog::Term::var("N")],
        ),
        vec![
            mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                "assertion",
                vec![
                    mneme_datalog::Term::var("E"),
                    mneme_datalog::Term::var("Pred"),
                    mneme_datalog::Term::var("Val"),
                    mneme_datalog::Term::var("Aid"),
                ],
            )),
            mneme_datalog::Literal::Aggregate {
                function: mneme_datalog::AggregateFunction::Count,
                input: mneme_datalog::Term::var("Aid"),
                output: "N".to_owned(),
            },
        ],
    )
}

#[test]
fn dbsp_zset_incremental_advance_matches_from_scratch_and_reduces_work() {
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
    let genesis = workspace.current_revision().expect("genesis");

    // Seed rev0 with 30 papers, 30 concepts, 20 bridges, 20 chain links, and 2 sources + assertions.
    let mut records = Vec::with_capacity(97);
    let mut blobs = Vec::with_capacity(2);
    for idx in 1..=30_u8 {
        records.push(draft(
            id_with_tag([0x10, idx]),
            rev_with_tag([0x10, idx]),
            mneme_core::RecordKind::Entity,
            scope(),
            paper_payload(&format!("Paper {idx}")),
        ));
        records.push(draft(
            id_with_tag([0x20, idx]),
            rev_with_tag([0x20, idx]),
            mneme_core::RecordKind::Entity,
            scope(),
            concept_payload(&format!("Concept {idx}")),
        ));
    }
    for idx in 1..=20_u8 {
        records.push(draft(
            id_with_tag([0x30, idx]),
            rev_with_tag([0x30, idx]),
            mneme_core::RecordKind::Relation,
            scope(),
            relation_payload(
                "bridges",
                id_with_tag([0x10, idx]),
                id_with_tag([0x20, idx]),
            ),
        ));
    }
    for idx in 1..=15_u8 {
        records.push(draft(
            id_with_tag([0x40, idx]),
            rev_with_tag([0x40, idx]),
            mneme_core::RecordKind::Relation,
            scope(),
            relation_payload(
                "links",
                id_with_tag([0x10, idx]),
                id_with_tag([0x10, idx + 1]),
            ),
        ));
    }
    let (src1, blob1) = source_draft(
        id_with_tag([0x50, 1]),
        rev_with_tag([0x50, 1]),
        id_with_tag([0x10, 1]),
        b"= Source One\n\nEvidence one.",
        "s1.adoc",
    );
    let (src2, blob2) = source_draft(
        id_with_tag([0x50, 2]),
        rev_with_tag([0x50, 2]),
        id_with_tag([0x10, 2]),
        b"= Source Two\n\nEvidence two.",
        "s2.adoc",
    );
    records.push(src1);
    records.push(src2);
    blobs.push(blob1);
    blobs.push(blob2);

    let _seed_entities = workspace
        .commit(mneme_store::CommitCommand {
            base: genesis,
            actor: "repl-test".to_owned(),
            scope: scope(),
            idempotency_key: "rev0-entities".to_owned(),
            records,
            source_blobs: blobs,
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit seed entities");

    commit_accepted_assertion(
        &mut workspace,
        AcceptedAssertionFixture {
            assertion_id: id_with_tag([0x60, 1]),
            proposed_rev: rev_with_tag([0x60, 1]),
            accepted_rev: rev_with_tag([0x63, 1]),
            evidence_id: id_with_tag([0x61, 1]),
            evidence_rev: rev_with_tag([0x61, 1]),
            decision_id: id_with_tag([0x62, 1]),
            decision_rev: rev_with_tag([0x62, 1]),
            subject: id_with_tag([0x10, 1]),
            source_id: id_with_tag([0x50, 1]),
            source_rev: rev_with_tag([0x50, 1]),
            claim_value: "retained-claim",
            key_prefix: "claim-1",
        },
    );
    commit_accepted_assertion(
        &mut workspace,
        AcceptedAssertionFixture {
            assertion_id: id_with_tag([0x60, 2]),
            proposed_rev: rev_with_tag([0x60, 2]),
            accepted_rev: rev_with_tag([0x63, 2]),
            evidence_id: id_with_tag([0x61, 2]),
            evidence_rev: rev_with_tag([0x61, 2]),
            decision_id: id_with_tag([0x62, 2]),
            decision_rev: rev_with_tag([0x62, 2]),
            subject: id_with_tag([0x10, 2]),
            source_id: id_with_tag([0x50, 2]),
            source_rev: rev_with_tag([0x50, 2]),
            claim_value: "forgotten-claim",
            key_prefix: "claim-2",
        },
    );
    let rev0 = workspace.current_revision().expect("rev0");

    let mut session = open_session(
        &mut workspace,
        Some(rev0),
        mneme_datalog::ReplLimits::default(),
    );
    for rule in dbsp_test_rules() {
        session.add_rule(rule).expect("add rule at rev0");
    }

    // rev1: insert 1 new paper (idx 31), 1 link closing a path (16 -> 17), 1 bridge,
    // and replace Paper 1's label.
    let new_paper = draft(
        id_with_tag([0x10, 31]),
        rev_with_tag([0x10, 31]),
        mneme_core::RecordKind::Entity,
        scope(),
        paper_payload("Paper 31"),
    );
    let mut updated_paper_1 = draft(
        id_with_tag([0x10, 1]),
        rev_with_tag([0x11, 1]),
        mneme_core::RecordKind::Entity,
        scope(),
        paper_payload("Paper One Revised"),
    );
    updated_paper_1.predecessor = Some(rev_with_tag([0x10, 1]));
    let new_bridge = draft(
        id_with_tag([0x30, 31]),
        rev_with_tag([0x30, 31]),
        mneme_core::RecordKind::Relation,
        scope(),
        relation_payload("bridges", id_with_tag([0x10, 31]), id_with_tag([0x20, 1])),
    );
    let new_link = draft(
        id_with_tag([0x40, 16]),
        rev_with_tag([0x40, 16]),
        mneme_core::RecordKind::Relation,
        scope(),
        relation_payload("links", id_with_tag([0x10, 16]), id_with_tag([0x10, 31])),
    );
    let rev1 = workspace
        .commit(mneme_store::CommitCommand {
            base: rev0,
            actor: "repl-test".to_owned(),
            scope: scope(),
            idempotency_key: "rev1".to_owned(),
            records: vec![new_paper, updated_paper_1, new_bridge, new_link],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit rev1")
        .revision;

    let adv1 = session
        .advance_to_revision(&mut workspace, Some(rev1))
        .expect("advance to rev1");
    assert_eq!(adv1.context.served_revision, rev1);
    assert!(adv1.reused_predicates.contains(&"claim_count".to_owned()));

    // Measure full from-scratch evaluation work at rev1.
    let mut scratch_rev1 = open_session(
        &mut workspace,
        Some(rev1),
        mneme_datalog::ReplLimits::default(),
    );
    for rule in dbsp_test_rules() {
        scratch_rev1.add_rule(rule).expect("scratch rev1 add");
    }
    assert!(
        adv1.step_work * 5 < scratch_rev1.total_work(),
        "expected >5x work reduction on rev1 advance: inc={} vs full={}",
        adv1.step_work,
        scratch_rev1.total_work()
    );

    // rev2: Forget Source Two (tombstone/forget advancing eligibility_generation and retracting
    // source 2 + evidence 2 + assertion 2), and also replace Paper 31's label.
    let _forget_outcome = mneme_retention::Engine::new(&mut workspace)
        .execute(mneme_retention::Request {
            actor: "repl-test".to_owned(),
            scope: scope(),
            base_revision: rev1,
            idempotency_key: "forget-src2".to_owned(),
            operation: mneme_retention::OperationKind::Forget,
            selector: mneme_retention::Selector::Source(id_with_tag([0x50, 2])),
            effective: None,
            policy: mneme_retention::Policy {
                version: mneme_retention::POLICY_VERSION.to_owned(),
                retain_assertion_after_prune: true,
                block_content_replay: true,
                retain_withdrawn_evidence_metadata: true,
            },
        })
        .expect("forget src2");
    let after_forget = workspace.current_revision().expect("after forget");
    let mut updated_paper_31 = draft(
        id_with_tag([0x10, 31]),
        rev_with_tag([0x11, 31]),
        mneme_core::RecordKind::Entity,
        scope(),
        paper_payload("Paper 31 Revised"),
    );
    updated_paper_31.predecessor = Some(rev_with_tag([0x10, 31]));
    let rev2 = workspace
        .commit(mneme_store::CommitCommand {
            base: after_forget,
            actor: "repl-test".to_owned(),
            scope: scope(),
            idempotency_key: "rev2-edit".to_owned(),
            records: vec![updated_paper_31],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit rev2")
        .revision;

    let adv2 = session
        .advance_to_revision(&mut workspace, None)
        .expect("advance to head rev2");
    assert_eq!(adv2.context.served_revision, rev2);
    assert!(adv2.reused_predicates.contains(&"reach".to_owned()));
    assert!(
        adv2.reused_predicates
            .contains(&"already_bridged".to_owned())
    );

    // Full from-scratch ReplSession at rev2.
    let mut scratch_rev2 = open_session(
        &mut workspace,
        Some(rev2),
        mneme_datalog::ReplLimits::default(),
    );
    for rule in dbsp_test_rules() {
        scratch_rev2.add_rule(rule).expect("scratch rev2 add");
    }
    assert!(
        adv2.step_work * 5 < scratch_rev2.total_work(),
        "expected >5x work reduction on rev2 advance: inc={} vs full={}",
        adv2.step_work,
        scratch_rev2.total_work()
    );

    // Exact equivalence across EVERY base and derived predicate at rev2!
    for predicate in [
        "entity",
        "relation",
        "assertion",
        "evidence",
        "source",
        "paper_in_class",
        "already_bridged",
        "unbridged_candidate",
        "paper_bridges_concept",
        "active_node",
        "reach",
        "claim_count",
    ] {
        let inc = session
            .query_relation(
                Some(&mut workspace),
                mneme_datalog::Query::all(predicate, 1_000),
            )
            .expect("inc query");
        let full = scratch_rev2
            .query_relation(
                Some(&mut workspace),
                mneme_datalog::Query::all(predicate, 1_000),
            )
            .expect("full query");
        assert_eq!(inc.status, full.status, "status mismatch on {predicate}");
        assert_eq!(
            inc.exhaustive, full.exhaustive,
            "exhaustive mismatch on {predicate}"
        );
        assert_eq!(
            inc.absence_established, full.absence_established,
            "absence mismatch on {predicate}"
        );
        assert_eq!(
            inc.rows, full.rows,
            "row/provenance mismatch on {predicate}"
        );
    }
}

#[test]
fn dbsp_recursive_cycle_retraction_and_union_support_match_from_scratch() {
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
    let genesis = workspace.current_revision().expect("genesis");

    let n1 = id_with_tag([0x70, 1]);
    let n2 = id_with_tag([0x70, 2]);
    let n3 = id_with_tag([0x70, 3]);
    let e12 = id_with_tag([0x71, 1]);
    let e23 = id_with_tag([0x71, 2]);
    let e31 = id_with_tag([0x71, 3]);
    let b1 = id_with_tag([0x72, 1]);

    let rev0 = workspace
        .commit(mneme_store::CommitCommand {
            base: genesis,
            actor: "cycle-test".to_owned(),
            scope: scope(),
            idempotency_key: "cycle-rev0".to_owned(),
            records: vec![
                draft(
                    n1,
                    rev_with_tag([0x70, 1]),
                    mneme_core::RecordKind::Entity,
                    scope(),
                    paper_payload("N1"),
                ),
                draft(
                    n2,
                    rev_with_tag([0x70, 2]),
                    mneme_core::RecordKind::Entity,
                    scope(),
                    paper_payload("N2"),
                ),
                draft(
                    n3,
                    rev_with_tag([0x70, 3]),
                    mneme_core::RecordKind::Entity,
                    scope(),
                    paper_payload("N3"),
                ),
                draft(
                    e12,
                    rev_with_tag([0x71, 1]),
                    mneme_core::RecordKind::Relation,
                    scope(),
                    relation_payload("links", n1, n2),
                ),
                draft(
                    e23,
                    rev_with_tag([0x71, 2]),
                    mneme_core::RecordKind::Relation,
                    scope(),
                    relation_payload("links", n2, n3),
                ),
                draft(
                    e31,
                    rev_with_tag([0x71, 3]),
                    mneme_core::RecordKind::Relation,
                    scope(),
                    relation_payload("links", n3, n1),
                ),
                draft(
                    b1,
                    rev_with_tag([0x72, 1]),
                    mneme_core::RecordKind::Relation,
                    scope(),
                    relation_payload("bridges", n1, n2),
                ),
            ],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit cycle rev0")
        .revision;

    let mut session = open_session(
        &mut workspace,
        Some(rev0),
        mneme_datalog::ReplLimits::default(),
    );
    let cycle_rules = vec![
        mneme_datalog::Rule::new(
            "r-reach-base",
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
            "r-reach-step",
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
        mneme_datalog::Rule::new(
            "r-union-links",
            mneme_datalog::Atom::new("connected_src", vec![mneme_datalog::Term::var("X")]),
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
            "r-union-bridges",
            mneme_datalog::Atom::new("connected_src", vec![mneme_datalog::Term::var("X")]),
            vec![mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                "relation",
                vec![
                    mneme_datalog::Term::constant(mneme_core::Value::symbol("bridges")),
                    mneme_datalog::Term::var("X"),
                    mneme_datalog::Term::var("Y"),
                ],
            ))],
        ),
    ];
    for rule in cycle_rules.clone() {
        session.add_rule(rule).expect("add cycle rule");
    }
    let reach0 = session
        .query_relation(
            Some(&mut workspace),
            mneme_datalog::Query::all("reach", 100),
        )
        .expect("reach0");
    assert_eq!(reach0.rows.len(), 9, "3-cycle produces all 9 pairs");

    // Break the cycle at rev1 by replacing edge e12 (n1 -> n2) with an unrelated relation kind.
    let mut broken_e12 = draft(
        e12,
        rev_with_tag([0x73, 1]),
        mneme_core::RecordKind::Relation,
        scope(),
        relation_payload("other", n1, n2),
    );
    broken_e12.predecessor = Some(rev_with_tag([0x71, 1]));
    let rev1 = workspace
        .commit(mneme_store::CommitCommand {
            base: rev0,
            actor: "cycle-test".to_owned(),
            scope: scope(),
            idempotency_key: "cycle-rev1".to_owned(),
            records: vec![broken_e12],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit cycle rev1")
        .revision;

    session
        .advance_to_revision(&mut workspace, Some(rev1))
        .expect("advance to rev1");
    let mut scratch = open_session(
        &mut workspace,
        Some(rev1),
        mneme_datalog::ReplLimits::default(),
    );
    for rule in cycle_rules {
        scratch.add_rule(rule).expect("scratch rule");
    }
    // Remaining links: n2 -> n3 -> n1 => 3 pairs (n2,n3), (n3,n1), (n2,n1) — NO cycle ghosts!
    let inc_reach = session
        .query_relation(
            Some(&mut workspace),
            mneme_datalog::Query::all("reach", 100),
        )
        .expect("inc reach");
    let full_reach = scratch
        .query_relation(
            Some(&mut workspace),
            mneme_datalog::Query::all("reach", 100),
        )
        .expect("full reach");
    assert_eq!(inc_reach.rows.len(), 3);
    assert_eq!(inc_reach.rows, full_reach.rows);

    // n1 lost its `links` edge, so `connected_src(n1)` survives solely via `bridges` with updated support!
    let inc_conn = session
        .query_relation(
            Some(&mut workspace),
            mneme_datalog::Query::all("connected_src", 100),
        )
        .expect("inc conn");
    let full_conn = scratch
        .query_relation(
            Some(&mut workspace),
            mneme_datalog::Query::all("connected_src", 100),
        )
        .expect("full conn");
    assert_eq!(inc_conn.rows, full_conn.rows);
}

#[test]
fn dbsp_advance_enforces_limits_and_rolls_back_without_partial_state() {
    let (_temp, mut workspace, rev1) = setup_workspace();
    let base_only = open_session(
        &mut workspace,
        Some(rev1),
        mneme_datalog::ReplLimits::default(),
    );
    let base_work = base_only.total_work();

    let e4 = draft(
        rid(10),
        rev(10),
        mneme_core::RecordKind::Entity,
        scope(),
        paper_payload("Paper Three"),
    );
    let rev2 = workspace
        .commit(mneme_store::CommitCommand {
            base: rev1,
            actor: "repl-test".to_owned(),
            scope: scope(),
            idempotency_key: "commit-limit".to_owned(),
            records: vec![e4],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit 2")
        .revision;

    let mut tight = open_session(
        &mut workspace,
        Some(rev1),
        mneme_datalog::ReplLimits {
            max_total_work: base_work + 1,
            ..mneme_datalog::ReplLimits::default()
        },
    );
    let err = tight
        .advance_to_revision(&mut workspace, Some(rev2))
        .expect_err("tight budget must refuse advance");
    assert!(matches!(err, mneme_datalog::Error::LimitExceeded(_)));
    assert_eq!(tight.context().served_revision, rev1);
}

fn status_relation_payload(
    relation_type: &str,
    from: mneme_core::RecordId,
    to: mneme_core::RecordId,
    status: mneme_datalog::EpistemicStatus,
) -> mneme_core::Payload {
    mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("relation-type"),
            mneme_core::Value::symbol(relation_type),
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
            mneme_core::Value::dictionary([(
                mneme_core::Value::symbol("status"),
                mneme_core::Value::symbol(status.name()),
            )]),
        ),
    ])
}

#[test]
fn repl_incomplete_extents_gate_negation_and_aggregates_on_add_and_advance() {
    let (_temp, mut workspace, rev1) = setup_workspace();
    let mut session = mneme_datalog::ReplSession::open(
        &mut workspace,
        mneme_datalog::ReplSessionRequest {
            actor: "repl-test".to_owned(),
            scope: scope(),
            revision: Some(rev1),
            limits: mneme_datalog::ReplLimits::default(),
            incomplete_extents: std::collections::BTreeSet::from(["relation".to_owned()]),
            complete_predicates: std::collections::BTreeSet::new(),
            access: mneme_memory::Access::Operator,
            at: None,
        },
    )
    .expect("open session with incomplete relation");

    let neg_rule = mneme_datalog::Rule::new(
        "r-unlinked",
        mneme_datalog::Atom::new("unlinked", vec![mneme_datalog::Term::var("E")]),
        vec![
            mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                "entity",
                vec![
                    mneme_datalog::Term::var("E"),
                    mneme_datalog::Term::constant(mneme_core::Value::symbol("paper")),
                    mneme_datalog::Term::var("L"),
                ],
            )),
            mneme_datalog::Literal::Negative(mneme_datalog::Atom::new(
                "relation",
                vec![
                    mneme_datalog::Term::constant(mneme_core::Value::symbol("cites")),
                    mneme_datalog::Term::var("E"),
                    mneme_datalog::Term::constant(rid(2).to_value()),
                ],
            )),
        ],
    );
    let agg_rule = mneme_datalog::Rule::new(
        "r-cite-count",
        mneme_datalog::Atom::new(
            "cite_count",
            vec![
                mneme_datalog::Term::var("From"),
                mneme_datalog::Term::var("N"),
            ],
        ),
        vec![
            mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                "relation",
                vec![
                    mneme_datalog::Term::constant(mneme_core::Value::symbol("cites")),
                    mneme_datalog::Term::var("From"),
                    mneme_datalog::Term::var("To"),
                ],
            )),
            mneme_datalog::Literal::Aggregate {
                function: mneme_datalog::AggregateFunction::Count,
                input: mneme_datalog::Term::var("To"),
                output: "N".to_owned(),
            },
        ],
    );

    let add_neg = session.add_rule(neg_rule).expect("add neg rule");
    assert_eq!(add_neg.status, mneme_datalog::ExecutionStatus::Partial);
    let add_agg = session.add_rule(agg_rule).expect("add agg rule");
    assert_eq!(add_agg.status, mneme_datalog::ExecutionStatus::Partial);

    let q_neg_1 = session
        .query_relation(None, mneme_datalog::Query::all("unlinked", 10))
        .expect("query unlinked rev1");
    assert!(q_neg_1.rows.is_empty());
    assert!(!q_neg_1.exhaustive);
    let q_agg_1 = session
        .query_relation(None, mneme_datalog::Query::all("cite_count", 10))
        .expect("query cite_count rev1");
    assert!(q_agg_1.rows.is_empty());
    assert!(!q_agg_1.exhaustive);

    // Commit a new paper and citation at rev2; advance_to_revision must keep gating both rules.
    let e_new = draft(
        rid(40),
        rev(40),
        mneme_core::RecordKind::Entity,
        scope(),
        paper_payload("Paper Extra"),
    );
    let r_new = draft(
        rid(41),
        rev(41),
        mneme_core::RecordKind::Relation,
        scope(),
        relation_payload("cites", rid(40), rid(1)),
    );
    let rev2 = workspace
        .commit(mneme_store::CommitCommand {
            base: rev1,
            actor: "repl-test".to_owned(),
            scope: scope(),
            idempotency_key: "commit-incomplete-advance".to_owned(),
            records: vec![e_new, r_new],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit rev2")
        .revision;

    let adv = session
        .advance_to_revision(&mut workspace, Some(rev2))
        .expect("advance to rev2");
    assert_eq!(adv.status, mneme_datalog::ExecutionStatus::Partial);

    let q_neg_2 = session
        .query_relation(None, mneme_datalog::Query::all("unlinked", 10))
        .expect("query unlinked rev2");
    assert!(
        q_neg_2.rows.is_empty(),
        "incomplete extent must never materialize false-absence rows on advance"
    );
    assert!(!q_neg_2.exhaustive);

    let q_agg_2 = session
        .query_relation(None, mneme_datalog::Query::all("cite_count", 10))
        .expect("query cite_count rev2");
    assert!(
        q_agg_2.rows.is_empty(),
        "incomplete extent must never materialize under-counted aggregate rows on advance"
    );
    assert!(!q_agg_2.exhaustive);
}

#[test]
fn dbsp_recursive_epistemic_upgrade_across_rounds_matches_fresh_build() {
    let (_temp, mut workspace) = {
        let temp = tempfile::tempdir().expect("tempdir");
        let ws = mneme_store::Workspace::create(
            temp.path(),
            mneme_store::WorkspaceConfig::new(
                Box::new(mneme_store::SystemClock),
                Box::new(mneme_store::NoFaults),
            ),
        )
        .expect("create ws");
        (temp, ws)
    };
    let a = rid(1);
    let b = rid(2);
    let c = rid(3);
    let d = rid(4);
    let base0 = workspace.current_revision().expect("base0");
    // rev0: direct Proposed edges a->c, a->d, b->d, and Accepted edges a->b, c->d.
    let rev0 = workspace
        .commit(mneme_store::CommitCommand {
            base: base0,
            actor: "repl-test".to_owned(),
            scope: scope(),
            idempotency_key: "rec-upgrade-0".to_owned(),
            records: vec![
                draft(
                    a,
                    rev(1),
                    mneme_core::RecordKind::Entity,
                    scope(),
                    paper_payload("A"),
                ),
                draft(
                    b,
                    rev(2),
                    mneme_core::RecordKind::Entity,
                    scope(),
                    paper_payload("B"),
                ),
                draft(
                    c,
                    rev(3),
                    mneme_core::RecordKind::Entity,
                    scope(),
                    paper_payload("C"),
                ),
                draft(
                    d,
                    rev(4),
                    mneme_core::RecordKind::Entity,
                    scope(),
                    paper_payload("D"),
                ),
                draft(
                    rid(10),
                    rev(10),
                    mneme_core::RecordKind::Relation,
                    scope(),
                    status_relation_payload("edge", a, b, mneme_datalog::EpistemicStatus::Accepted),
                ),
                draft(
                    rid(11),
                    rev(11),
                    mneme_core::RecordKind::Relation,
                    scope(),
                    status_relation_payload("edge", a, c, mneme_datalog::EpistemicStatus::Proposed),
                ),
                draft(
                    rid(12),
                    rev(12),
                    mneme_core::RecordKind::Relation,
                    scope(),
                    status_relation_payload("edge", c, d, mneme_datalog::EpistemicStatus::Accepted),
                ),
                draft(
                    rid(13),
                    rev(13),
                    mneme_core::RecordKind::Relation,
                    scope(),
                    status_relation_payload("edge", a, d, mneme_datalog::EpistemicStatus::Proposed),
                ),
            ],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit rev0")
        .revision;

    let mut session = open_session(
        &mut workspace,
        Some(rev0),
        mneme_datalog::ReplLimits::default(),
    );
    let reach_base = mneme_datalog::Rule::new(
        "r-reach-base",
        mneme_datalog::Atom::new(
            "reach",
            vec![mneme_datalog::Term::var("X"), mneme_datalog::Term::var("Y")],
        ),
        vec![mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
            "relation",
            vec![
                mneme_datalog::Term::constant(mneme_core::Value::symbol("edge")),
                mneme_datalog::Term::var("X"),
                mneme_datalog::Term::var("Y"),
            ],
        ))],
    );
    let reach_step = mneme_datalog::Rule::new(
        "r-reach-step",
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
                    mneme_datalog::Term::constant(mneme_core::Value::symbol("edge")),
                    mneme_datalog::Term::var("Y"),
                    mneme_datalog::Term::var("Z"),
                ],
            )),
        ],
    );
    session.add_rule(reach_base.clone()).expect("add base");
    session.add_rule(reach_step.clone()).expect("add step");

    // At rev0, reach(a, c) and reach(a, d) are Proposed.
    let q0 = session
        .query_relation(None, mneme_datalog::Query::all("reach", 20))
        .expect("q0");
    let ac0 = q0
        .rows
        .iter()
        .find(|row| row.values == vec![a.to_value(), c.to_value()])
        .expect("ac rev0");
    assert_eq!(ac0.epistemic, mneme_datalog::EpistemicStatus::Proposed);

    // rev1: commit Accepted edge b -> c. Round-0 still derives reach(a,c) as Proposed,
    // round-1 derives reach(a,c) as Accepted via a->b->c, and reach(a,d) upgrades to Accepted via a->c->d!
    let rev1 = workspace
        .commit(mneme_store::CommitCommand {
            base: rev0,
            actor: "repl-test".to_owned(),
            scope: scope(),
            idempotency_key: "rec-upgrade-1".to_owned(),
            records: vec![draft(
                rid(14),
                rev(14),
                mneme_core::RecordKind::Relation,
                scope(),
                status_relation_payload("edge", b, c, mneme_datalog::EpistemicStatus::Accepted),
            )],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit rev1")
        .revision;

    session
        .advance_to_revision(&mut workspace, Some(rev1))
        .expect("advance rev1");
    let inc = session
        .query_relation(None, mneme_datalog::Query::all("reach", 20))
        .expect("inc reach");

    // Compare against fresh ReplSession (from-scratch evaluation) at rev1.
    let mut fresh = open_session(
        &mut workspace,
        Some(rev1),
        mneme_datalog::ReplLimits::default(),
    );
    fresh.add_rule(reach_base).expect("fresh base");
    fresh.add_rule(reach_step).expect("fresh step");
    let scratch = fresh
        .query_relation(None, mneme_datalog::Query::all("reach", 20))
        .expect("scratch reach");

    let inc_ac = inc
        .rows
        .iter()
        .find(|row| row.values == vec![a.to_value(), c.to_value()])
        .expect("inc ac");
    let inc_ad = inc
        .rows
        .iter()
        .find(|row| row.values == vec![a.to_value(), d.to_value()])
        .expect("inc ad");
    assert_eq!(inc_ac.epistemic, mneme_datalog::EpistemicStatus::Accepted);
    assert_eq!(inc_ad.epistemic, mneme_datalog::EpistemicStatus::Accepted);

    let inc_map: std::collections::BTreeMap<_, _> = inc
        .rows
        .iter()
        .map(|r| (r.values.clone(), r.epistemic))
        .collect();
    let scratch_map: std::collections::BTreeMap<_, _> = scratch
        .rows
        .iter()
        .map(|r| (r.values.clone(), r.epistemic))
        .collect();
    assert_eq!(inc_map, scratch_map);
}

#[test]
fn dbsp_zero_positive_atom_negated_rule_retracts_and_reappears() {
    let (_temp, mut workspace, rev1) = setup_workspace();
    let mut session = open_session(
        &mut workspace,
        Some(rev1),
        mneme_datalog::ReplLimits::default(),
    );

    // 0-positive-atom rule: all_clear("yes") :- not relation(alert, rid(1), rid(2))
    let rule = mneme_datalog::Rule::new(
        "r-all-clear",
        mneme_datalog::Atom::new(
            "all_clear",
            vec![mneme_datalog::Term::constant(mneme_core::Value::string(
                "yes",
            ))],
        ),
        vec![mneme_datalog::Literal::Negative(mneme_datalog::Atom::new(
            "relation",
            vec![
                mneme_datalog::Term::constant(mneme_core::Value::symbol("alert")),
                mneme_datalog::Term::constant(rid(1).to_value()),
                mneme_datalog::Term::constant(rid(2).to_value()),
            ],
        ))],
    );
    session.add_rule(rule).expect("add zero-pos rule");

    let q1 = session
        .query_relation(None, mneme_datalog::Query::all("all_clear", 10))
        .expect("q1");
    assert_eq!(q1.rows.len(), 1);
    assert_eq!(q1.rows[0].values, vec![mneme_core::Value::string("yes")]);

    // rev2: commit blocking alert relation -> must emit -1 delta and retract all_clear("yes").
    let rev2 = workspace
        .commit(mneme_store::CommitCommand {
            base: rev1,
            actor: "repl-test".to_owned(),
            scope: scope(),
            idempotency_key: "zero-pos-block".to_owned(),
            records: vec![draft(
                rid(90),
                rev(90),
                mneme_core::RecordKind::Relation,
                scope(),
                status_relation_payload(
                    "alert",
                    rid(1),
                    rid(2),
                    mneme_datalog::EpistemicStatus::Accepted,
                ),
            )],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit alert")
        .revision;

    session
        .advance_to_revision(&mut workspace, Some(rev2))
        .expect("advance rev2");
    let q2 = session
        .query_relation(None, mneme_datalog::Query::all("all_clear", 10))
        .expect("q2");
    assert!(
        q2.rows.is_empty(),
        "0-positive-atom negated rule must retract cleanly when blocker is committed"
    );

    // rev3: update alert relation to Rejected (ZERO) -> blocker disappears and all_clear("yes") reappears.
    let rev3 = workspace
        .commit(mneme_store::CommitCommand {
            base: rev2,
            actor: "repl-test".to_owned(),
            scope: scope(),
            idempotency_key: "zero-pos-unblock".to_owned(),
            records: vec![mneme_store::RecordDraft {
                schema_version: 1,
                kind: mneme_core::RecordKind::Relation,
                record_id: rid(90),
                revision_id: rev(91),
                predecessor: Some(rev(90)),
                scope: scope(),
                payload: status_relation_payload(
                    "alert",
                    rid(1),
                    rid(2),
                    mneme_datalog::EpistemicStatus::Rejected,
                ),
            }],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit rejected alert")
        .revision;

    session
        .advance_to_revision(&mut workspace, Some(rev3))
        .expect("advance rev3");
    let q3 = session
        .query_relation(None, mneme_datalog::Query::all("all_clear", 10))
        .expect("q3");
    assert_eq!(q3.rows.len(), 1);
    assert_eq!(q3.rows[0].values, vec![mneme_core::Value::string("yes")]);
}

#[test]
fn repl_sync_after_rule_change_enforces_step_limits_and_charges_total_work() {
    let (_temp, mut workspace, rev1) = setup_workspace();

    // Measure full work (evaluate_incremental + sync_after_rule_change) for adding paper_rule.
    let mut reference = open_session(
        &mut workspace,
        Some(rev1),
        mneme_datalog::ReplLimits::default(),
    );
    let base_work = reference.total_work();
    let step = reference.add_rule(paper_rule()).expect("reference add");
    assert!(step.step_work > 0);
    assert_eq!(reference.total_work(), base_work + step.step_work);

    // Now pick a step work budget strictly smaller than `step.step_work` (specifically 1 less),
    // which is large enough for `evaluate_incremental` to succeed yet tight enough for
    // `sync_after_rule_change` to hit `LimitExceeded` and roll back while charging total_work.
    let tight_step_work = step.step_work.saturating_sub(1).max(1);
    let mut tight = open_session(
        &mut workspace,
        Some(rev1),
        mneme_datalog::ReplLimits {
            per_step: mneme_datalog::Limits {
                max_work: tight_step_work,
                ..mneme_datalog::Limits::default()
            },
            max_total_work: base_work + tight_step_work,
            ..mneme_datalog::ReplLimits::default()
        },
    );
    let work_before = tight.total_work();
    let err = tight
        .add_rule(paper_rule())
        .expect_err("sync_after_rule_change must enforce step_limits");
    assert!(matches!(err, mneme_datalog::Error::LimitExceeded(_)));
    assert!(
        tight.total_work() > work_before,
        "failed sync_after_rule_change must charge total_work"
    );
    assert!(tight.total_work() <= tight.limits().max_total_work);
    assert!(
        tight.rules().is_empty(),
        "failed sync_after_rule_change must roll back without partial state"
    );
}

fn status_entity_payload(
    entity_type: &str,
    label: &str,
    status: mneme_datalog::EpistemicStatus,
) -> mneme_core::Payload {
    mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("entity-type"),
            mneme_core::Value::symbol(entity_type),
        ),
        (
            mneme_core::Symbol::from("label"),
            mneme_core::Value::string(label),
        ),
        (
            mneme_core::Symbol::from("properties"),
            mneme_core::Value::symbol_dictionary([(
                mneme_core::Symbol::from("status"),
                mneme_core::Value::symbol(status.name()),
            )]),
        ),
    ])
}

#[test]
fn k_relation_ivm_tracks_epistemic_downgrade_upgrade_and_kleene_negation_with_fresh_parity() {
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
    let h1 = id_with_tag([0x91, 1]);
    let v1 = id_with_tag([0x91, 2]);
    let falsify_id = id_with_tag([0x92, 1]);

    let genesis = workspace.current_revision().expect("genesis");
    let rev1 = workspace
        .commit(mneme_store::CommitCommand {
            base: genesis,
            actor: "k-ivm-test".to_owned(),
            scope: scope(),
            idempotency_key: "k-ivm-rev1".to_owned(),
            records: vec![
                draft(
                    h1,
                    rev_with_tag([0x91, 1]),
                    mneme_core::RecordKind::Entity,
                    scope(),
                    status_entity_payload(
                        "hypothesis",
                        "H1",
                        mneme_datalog::EpistemicStatus::Accepted,
                    ),
                ),
                draft(
                    v1,
                    rev_with_tag([0x91, 2]),
                    mneme_core::RecordKind::Entity,
                    scope(),
                    status_entity_payload(
                        "oracle_verdict",
                        "V1",
                        mneme_datalog::EpistemicStatus::Accepted,
                    ),
                ),
            ],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("rev1")
        .revision;

    let mut session = open_session(
        &mut workspace,
        Some(rev1),
        mneme_datalog::ReplLimits::default(),
    );
    let rules = vec![
        mneme_datalog::Rule::new(
            "r-falsified",
            mneme_datalog::Atom::new("falsified", vec![mneme_datalog::Term::var("H")]),
            vec![mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                "relation",
                vec![
                    mneme_datalog::Term::constant(mneme_core::Value::symbol("falsifies")),
                    mneme_datalog::Term::var("V"),
                    mneme_datalog::Term::var("H"),
                ],
            ))],
        ),
        mneme_datalog::Rule::new(
            "r-open-hyp",
            mneme_datalog::Atom::new("open_hypothesis", vec![mneme_datalog::Term::var("H")]),
            vec![
                mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                    "entity",
                    vec![
                        mneme_datalog::Term::var("H"),
                        mneme_datalog::Term::constant(mneme_core::Value::symbol("hypothesis")),
                        mneme_datalog::Term::var("L"),
                    ],
                )),
                mneme_datalog::Literal::Negative(mneme_datalog::Atom::new(
                    "falsified",
                    vec![mneme_datalog::Term::var("H")],
                )),
            ],
        ),
    ];
    for rule in &rules {
        session.add_rule(rule.clone()).expect("add rule");
    }

    // Rev 1: no falsifier -> open_hypothesis(h1) is Accepted.
    let q1 = session
        .query_relation(None, mneme_datalog::Query::all("open_hypothesis", 10))
        .expect("q1");
    assert_eq!(q1.rows.len(), 1);
    assert_eq!(
        q1.rows[0].epistemic,
        mneme_datalog::EpistemicStatus::Accepted
    );

    // Rev 2: insert Proposed falsifies(v1, h1) -> Kleene IVM downgrades open_hypothesis(h1) to Proposed!
    let r2_edge = rev_with_tag([0x92, 2]);
    let rev2 = workspace
        .commit(mneme_store::CommitCommand {
            base: rev1,
            actor: "k-ivm-test".to_owned(),
            scope: scope(),
            idempotency_key: "k-ivm-rev2".to_owned(),
            records: vec![draft(
                falsify_id,
                r2_edge,
                mneme_core::RecordKind::Relation,
                scope(),
                status_relation_payload(
                    "falsifies",
                    v1,
                    h1,
                    mneme_datalog::EpistemicStatus::Proposed,
                ),
            )],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("rev2")
        .revision;
    session
        .advance_to_revision(&mut workspace, Some(rev2))
        .expect("advance rev2");
    let q2 = session
        .query_relation(None, mneme_datalog::Query::all("open_hypothesis", 10))
        .expect("q2");
    assert_eq!(q2.rows.len(), 1);
    assert_eq!(
        q2.rows[0].epistemic,
        mneme_datalog::EpistemicStatus::Proposed
    );
    assert!(!session.justifications().is_empty());

    // Rev 3: promote falsifies(v1, h1) to Accepted -> Kleene IVM retracts open_hypothesis(h1)!
    let r3_edge = rev_with_tag([0x92, 3]);
    let rev3 = workspace
        .commit(mneme_store::CommitCommand {
            base: rev2,
            actor: "k-ivm-test".to_owned(),
            scope: scope(),
            idempotency_key: "k-ivm-rev3".to_owned(),
            records: vec![mneme_store::RecordDraft {
                schema_version: 1,
                kind: mneme_core::RecordKind::Relation,
                record_id: falsify_id,
                revision_id: r3_edge,
                predecessor: Some(r2_edge),
                scope: scope(),
                payload: status_relation_payload(
                    "falsifies",
                    v1,
                    h1,
                    mneme_datalog::EpistemicStatus::Accepted,
                ),
            }],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("rev3")
        .revision;
    session
        .advance_to_revision(&mut workspace, Some(rev3))
        .expect("advance rev3");
    let q3 = session
        .query_relation(None, mneme_datalog::Query::all("open_hypothesis", 10))
        .expect("q3");
    assert!(q3.rows.is_empty());

    // Rev 4: reject falsifies(v1, h1) -> Kleene IVM restores open_hypothesis(h1) as Accepted!
    let r4_edge = rev_with_tag([0x92, 4]);
    let rev4 = workspace
        .commit(mneme_store::CommitCommand {
            base: rev3,
            actor: "k-ivm-test".to_owned(),
            scope: scope(),
            idempotency_key: "k-ivm-rev4".to_owned(),
            records: vec![mneme_store::RecordDraft {
                schema_version: 1,
                kind: mneme_core::RecordKind::Relation,
                record_id: falsify_id,
                revision_id: r4_edge,
                predecessor: Some(r3_edge),
                scope: scope(),
                payload: status_relation_payload(
                    "falsifies",
                    v1,
                    h1,
                    mneme_datalog::EpistemicStatus::Rejected,
                ),
            }],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("rev4")
        .revision;
    session
        .advance_to_revision(&mut workspace, Some(rev4))
        .expect("advance rev4");
    let q4 = session
        .query_relation(None, mneme_datalog::Query::all("open_hypothesis", 10))
        .expect("q4");
    assert_eq!(q4.rows.len(), 1);
    assert_eq!(
        q4.rows[0].epistemic,
        mneme_datalog::EpistemicStatus::Accepted
    );
}
