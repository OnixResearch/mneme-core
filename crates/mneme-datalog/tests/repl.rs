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
