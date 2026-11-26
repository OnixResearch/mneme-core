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

fn id_with_tag(tag: u8, idx: u8) -> mneme_core::RecordId {
    let mut bytes = [0_u8; 16];
    bytes[0] = tag;
    bytes[15] = idx;
    mneme_core::RecordId::from_bytes(bytes)
}

fn rev_with_tag(tag: u8, idx: u8) -> mneme_core::RevisionId {
    let mut bytes = [0_u8; 16];
    bytes[0] = tag;
    bytes[15] = idx;
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

fn commit_accepted_assertion(
    workspace: &mut mneme_store::Workspace,
    fixture: AcceptedAssertionFixture<'_>,
) {
    let AcceptedAssertionFixture {
        assertion_id,
        proposed_rev,
        accepted_rev,
        evidence_id,
        evidence_rev,
        decision_id,
        decision_rev,
        subject,
        source_id,
        source_rev,
        claim_value,
        key_prefix,
    } = fixture;
    let span = mneme_core::SourceSpan::new(0, 10).expect("span");
    let evidence = mneme_memory::build_evidence(
        evidence_id,
        evidence_rev,
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: source_id,
            source_revision: source_rev,
            span: Some(span),
            anchor: Some("anchor"),
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let assertion = mneme_memory::build_proposed_assertion(
        assertion_id,
        proposed_rev,
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject,
            predicate: "topic",
            value: mneme_core::Value::string(claim_value.to_owned()),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "repl-test",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                evidence_id,
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
            idempotency_key: format!("{key_prefix}-propose"),
            records: vec![evidence, assertion],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit proposal")
        .revision;
    let current = workspace
        .record_revisions(assertion_id)
        .expect("assertion revisions")
        .into_iter()
        .last()
        .expect("latest assertion");
    let decision = mneme_memory::build_decision(
        decision_id,
        decision_rev,
        &scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: assertion_id,
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
        accepted_rev,
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(decision_id, mneme_core::RecordKind::Decision),
        None,
    );
    workspace
        .commit(mneme_store::CommitCommand {
            base: proposed_workspace_rev,
            actor: "repl-test".to_owned(),
            scope: scope(),
            idempotency_key: format!("{key_prefix}-accept"),
            records: vec![decision, accepted],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit acceptance");
}

fn dbsp_test_rules() -> Vec<mneme_datalog::Rule> {
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
        ),
    ]
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
    let mut records = Vec::new();
    let mut blobs = Vec::new();
    for idx in 1..=30_u8 {
        records.push(draft(
            id_with_tag(0x10, idx),
            rev_with_tag(0x10, idx),
            mneme_core::RecordKind::Entity,
            scope(),
            paper_payload(&format!("Paper {idx}")),
        ));
        records.push(draft(
            id_with_tag(0x20, idx),
            rev_with_tag(0x20, idx),
            mneme_core::RecordKind::Entity,
            scope(),
            concept_payload(&format!("Concept {idx}")),
        ));
    }
    for idx in 1..=20_u8 {
        records.push(draft(
            id_with_tag(0x30, idx),
            rev_with_tag(0x30, idx),
            mneme_core::RecordKind::Relation,
            scope(),
            relation_payload("bridges", id_with_tag(0x10, idx), id_with_tag(0x20, idx)),
        ));
    }
    for idx in 1..=15_u8 {
        records.push(draft(
            id_with_tag(0x40, idx),
            rev_with_tag(0x40, idx),
            mneme_core::RecordKind::Relation,
            scope(),
            relation_payload("links", id_with_tag(0x10, idx), id_with_tag(0x10, idx + 1)),
        ));
    }
    let (src1, blob1) = source_draft(
        id_with_tag(0x50, 1),
        rev_with_tag(0x50, 1),
        id_with_tag(0x10, 1),
        b"= Source One\n\nEvidence one.",
        "s1.adoc",
    );
    let (src2, blob2) = source_draft(
        id_with_tag(0x50, 2),
        rev_with_tag(0x50, 2),
        id_with_tag(0x10, 2),
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
            assertion_id: id_with_tag(0x60, 1),
            proposed_rev: rev_with_tag(0x60, 1),
            accepted_rev: rev_with_tag(0x63, 1),
            evidence_id: id_with_tag(0x61, 1),
            evidence_rev: rev_with_tag(0x61, 1),
            decision_id: id_with_tag(0x62, 1),
            decision_rev: rev_with_tag(0x62, 1),
            subject: id_with_tag(0x10, 1),
            source_id: id_with_tag(0x50, 1),
            source_rev: rev_with_tag(0x50, 1),
            claim_value: "retained-claim",
            key_prefix: "claim-1",
        },
    );
    commit_accepted_assertion(
        &mut workspace,
        AcceptedAssertionFixture {
            assertion_id: id_with_tag(0x60, 2),
            proposed_rev: rev_with_tag(0x60, 2),
            accepted_rev: rev_with_tag(0x63, 2),
            evidence_id: id_with_tag(0x61, 2),
            evidence_rev: rev_with_tag(0x61, 2),
            decision_id: id_with_tag(0x62, 2),
            decision_rev: rev_with_tag(0x62, 2),
            subject: id_with_tag(0x10, 2),
            source_id: id_with_tag(0x50, 2),
            source_rev: rev_with_tag(0x50, 2),
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
        id_with_tag(0x10, 31),
        rev_with_tag(0x10, 31),
        mneme_core::RecordKind::Entity,
        scope(),
        paper_payload("Paper 31"),
    );
    let mut updated_paper_1 = draft(
        id_with_tag(0x10, 1),
        rev_with_tag(0x11, 1),
        mneme_core::RecordKind::Entity,
        scope(),
        paper_payload("Paper One Revised"),
    );
    updated_paper_1.predecessor = Some(rev_with_tag(0x10, 1));
    let new_bridge = draft(
        id_with_tag(0x30, 31),
        rev_with_tag(0x30, 31),
        mneme_core::RecordKind::Relation,
        scope(),
        relation_payload("bridges", id_with_tag(0x10, 31), id_with_tag(0x20, 1)),
    );
    let new_link = draft(
        id_with_tag(0x40, 16),
        rev_with_tag(0x40, 16),
        mneme_core::RecordKind::Relation,
        scope(),
        relation_payload("links", id_with_tag(0x10, 16), id_with_tag(0x10, 31)),
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
            selector: mneme_retention::Selector::Source(id_with_tag(0x50, 2)),
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
        id_with_tag(0x10, 31),
        rev_with_tag(0x11, 31),
        mneme_core::RecordKind::Entity,
        scope(),
        paper_payload("Paper 31 Revised"),
    );
    updated_paper_31.predecessor = Some(rev_with_tag(0x10, 31));
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

    let n1 = id_with_tag(0x70, 1);
    let n2 = id_with_tag(0x70, 2);
    let n3 = id_with_tag(0x70, 3);
    let e12 = id_with_tag(0x71, 1);
    let e23 = id_with_tag(0x71, 2);
    let e31 = id_with_tag(0x71, 3);
    let b1 = id_with_tag(0x72, 1);

    let rev0 = workspace
        .commit(mneme_store::CommitCommand {
            base: genesis,
            actor: "cycle-test".to_owned(),
            scope: scope(),
            idempotency_key: "cycle-rev0".to_owned(),
            records: vec![
                draft(
                    n1,
                    rev_with_tag(0x70, 1),
                    mneme_core::RecordKind::Entity,
                    scope(),
                    paper_payload("N1"),
                ),
                draft(
                    n2,
                    rev_with_tag(0x70, 2),
                    mneme_core::RecordKind::Entity,
                    scope(),
                    paper_payload("N2"),
                ),
                draft(
                    n3,
                    rev_with_tag(0x70, 3),
                    mneme_core::RecordKind::Entity,
                    scope(),
                    paper_payload("N3"),
                ),
                draft(
                    e12,
                    rev_with_tag(0x71, 1),
                    mneme_core::RecordKind::Relation,
                    scope(),
                    relation_payload("links", n1, n2),
                ),
                draft(
                    e23,
                    rev_with_tag(0x71, 2),
                    mneme_core::RecordKind::Relation,
                    scope(),
                    relation_payload("links", n2, n3),
                ),
                draft(
                    e31,
                    rev_with_tag(0x71, 3),
                    mneme_core::RecordKind::Relation,
                    scope(),
                    relation_payload("links", n3, n1),
                ),
                draft(
                    b1,
                    rev_with_tag(0x72, 1),
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
        rev_with_tag(0x73, 1),
        mneme_core::RecordKind::Relation,
        scope(),
        relation_payload("other", n1, n2),
    );
    broken_e12.predecessor = Some(rev_with_tag(0x71, 1));
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
