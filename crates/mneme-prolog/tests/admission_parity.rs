//! Cross-engine parity tests verifying that `mneme-datalog` (full rebuild),
//! `mneme-datalog` IVM (`ReplSession`), and `mneme-prolog` share the identical
//! formally verified `mneme_kernel::admission` and `mneme_kernel::epistemic` gates.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::expect_used)] // test assertions use expect for failure diagnostics

fn scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "parity").expect("scope")
}

fn rid(byte: u8) -> mneme_core::RecordId {
    mneme_core::RecordId::from_bytes([byte; 16])
}

fn rev(byte: u8) -> mneme_core::RevisionId {
    mneme_core::RevisionId::from_bytes([byte; 16])
}

fn commit_records(
    workspace: &mut mneme_store::Workspace,
    key: &str,
    records: Vec<mneme_store::RecordDraft>,
    blobs: Vec<mneme_store::SourceBlobDraft>,
    retention: Option<mneme_store::RetentionCommit>,
) {
    let base = workspace.current_revision().expect("base");
    workspace
        .commit(mneme_store::CommitCommand {
            base,
            actor: "parity-test".to_owned(),
            scope: scope(),
            idempotency_key: key.to_owned(),
            records,
            source_blobs: blobs,
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention,
        })
        .expect("commit");
}

fn build_source_and_evidence(
    source_id: mneme_core::RecordId,
    source_rev: mneme_core::RevisionId,
    evidence_id: mneme_core::RecordId,
    evidence_rev: mneme_core::RevisionId,
    assertion_id: mneme_core::RecordId,
    content: &[u8],
) -> (
    mneme_store::RecordDraft,
    mneme_store::SourceBlobDraft,
    mneme_store::RecordDraft,
) {
    let (source, blob) = mneme_memory::build_source(
        source_id,
        source_rev,
        &scope(),
        mneme_memory::SourceOptions {
            media_type: "text/plain",
            bytes: content,
            entity: None,
            path_hint: None,
        },
    )
    .expect("build source");
    let span = mneme_core::SourceSpan::new(0, content.len() as u64).expect("span");
    let evidence = mneme_memory::build_evidence(
        evidence_id,
        evidence_rev,
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: source_id,
            source_revision: source_rev,
            span: Some(span),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    (source, blob, evidence)
}

struct AcceptedAssertionSpec<'a> {
    key_prefix: &'a str,
    subject_id: mneme_core::RecordId,
    assertion_id: mneme_core::RecordId,
    proposed_rev: mneme_core::RevisionId,
    accepted_rev: mneme_core::RevisionId,
    decision_id: mneme_core::RecordId,
    decision_rev: mneme_core::RevisionId,
    source_id: mneme_core::RecordId,
    source_rev: mneme_core::RevisionId,
    evidence_id: mneme_core::RecordId,
    evidence_rev: mneme_core::RevisionId,
    source_bytes: &'a [u8],
    claim_value: &'a str,
    epistemic_status: Option<&'a str>,
}

fn build_accepted_assertion(
    workspace: &mut mneme_store::Workspace,
    spec: AcceptedAssertionSpec<'_>,
) {
    let (source, blob, evidence) = build_source_and_evidence(
        spec.source_id,
        spec.source_rev,
        spec.evidence_id,
        spec.evidence_rev,
        spec.assertion_id,
        spec.source_bytes,
    );
    let proposed = mneme_memory::build_proposed_assertion(
        spec.assertion_id,
        spec.proposed_rev,
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: spec.subject_id,
            predicate: "claim",
            value: mneme_core::Value::string(spec.claim_value.to_owned()),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "parity-test",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                spec.evidence_id,
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    commit_records(
        workspace,
        &format!("{}-propose", spec.key_prefix),
        vec![source, evidence, proposed],
        vec![blob],
        None,
    );

    let input_rev = workspace.current_revision().expect("input rev");
    let proposed_env = workspace
        .record_revisions(spec.assertion_id)
        .expect("revs")
        .into_iter()
        .last()
        .expect("last rev");
    let decision = mneme_memory::build_decision(
        spec.decision_id,
        spec.decision_rev,
        &scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: spec.assertion_id,
            actor: "parity-test",
            policy: "parity-policy/v1",
            input_revision: input_rev,
            outcome: "accepted",
            rationale: "accept-parity",
            evidence: &[],
            related: &[],
        },
    );
    let mut accepted = mneme_memory::build_assertion_revision(
        &proposed_env,
        spec.accepted_rev,
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(spec.decision_id, mneme_core::RecordKind::Decision),
        None,
    );
    if let Some(status) = spec.epistemic_status {
        accepted.payload.insert(
            mneme_core::Symbol::from("properties"),
            mneme_core::Value::dictionary([(
                mneme_core::Value::symbol("status"),
                mneme_core::Value::symbol(status),
            )]),
        );
    }
    commit_records(
        workspace,
        &format!("{}-accept", spec.key_prefix),
        vec![decision, accepted],
        Vec::new(),
        None,
    );
}

#[test]
fn datalog_ivm_and_prolog_admit_identical_assertion_sets() {
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
    .expect("create workspace");

    let live_subject = rid(0x10);
    let entity_payload = mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("entity-type"),
            mneme_core::Value::symbol("project"),
        ),
        (
            mneme_core::Symbol::from("label"),
            mneme_core::Value::string("ParitySubject".to_owned()),
        ),
        (
            mneme_core::Symbol::from("properties"),
            mneme_core::Value::dictionary([]),
        ),
    ]);
    commit_records(
        &mut workspace,
        "entity",
        vec![mneme_store::RecordDraft {
            schema_version: 1,
            kind: mneme_core::RecordKind::Entity,
            record_id: live_subject,
            revision_id: rev(0x10),
            predecessor: None,
            scope: scope(),
            payload: entity_payload,
        }],
        Vec::new(),
        None,
    );

    // 1. Valid accepted assertion -> MUST be admitted by Datalog, IVM, and Prolog.
    let valid_id = rid(0x41);
    build_accepted_assertion(
        &mut workspace,
        AcceptedAssertionSpec {
            key_prefix: "valid",
            subject_id: live_subject,
            assertion_id: valid_id,
            proposed_rev: rev(0x41),
            accepted_rev: rev(0x51),
            decision_id: rid(0x61),
            decision_rev: rev(0x61),
            source_id: rid(0x21),
            source_rev: rev(0x21),
            evidence_id: rid(0x31),
            evidence_rev: rev(0x31),
            source_bytes: b"src1",
            claim_value: "admitted-claim",
            epistemic_status: None,
        },
    );

    // 2. Unaccepted (proposed lifecycle) assertion -> MUST be excluded by all 3 engines.
    let unaccepted_id = rid(0x42);
    let (src2, blob2, ev2) = build_source_and_evidence(
        rid(0x22),
        rev(0x22),
        rid(0x32),
        rev(0x32),
        unaccepted_id,
        b"src2",
    );
    let unaccepted = mneme_memory::build_proposed_assertion(
        unaccepted_id,
        rev(0x42),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: live_subject,
            predicate: "claim",
            value: mneme_core::Value::string("unaccepted-claim".to_owned()),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "parity-test",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                rid(0x32),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    commit_records(
        &mut workspace,
        "unaccepted",
        vec![src2, ev2, unaccepted],
        vec![blob2],
        None,
    );

    // 3. Accepted assertion whose supporting evidence is later withdrawn (unbacked) -> EXCLUDED.
    let unbacked_id = rid(0x43);
    let unbacked_ev_id = rid(0x33);
    build_accepted_assertion(
        &mut workspace,
        AcceptedAssertionSpec {
            key_prefix: "unbacked",
            subject_id: live_subject,
            assertion_id: unbacked_id,
            proposed_rev: rev(0x43),
            accepted_rev: rev(0x53),
            decision_id: rid(0x63),
            decision_rev: rev(0x63),
            source_id: rid(0x23),
            source_rev: rev(0x23),
            evidence_id: unbacked_ev_id,
            evidence_rev: rev(0x33),
            source_bytes: b"src3",
            claim_value: "unbacked-claim",
            epistemic_status: None,
        },
    );

    // 4. Accepted assertion that is itself suppressed (withdrawn) -> EXCLUDED.
    let suppressed_id = rid(0x44);
    build_accepted_assertion(
        &mut workspace,
        AcceptedAssertionSpec {
            key_prefix: "suppressed",
            subject_id: live_subject,
            assertion_id: suppressed_id,
            proposed_rev: rev(0x44),
            accepted_rev: rev(0x54),
            decision_id: rid(0x64),
            decision_rev: rev(0x64),
            source_id: rid(0x24),
            source_rev: rev(0x24),
            evidence_id: rid(0x34),
            evidence_rev: rev(0x34),
            source_bytes: b"src4",
            claim_value: "suppressed-claim",
            epistemic_status: None,
        },
    );

    // 5. Accepted assertion marked epistemic Rejected (ZERO annihilator) -> EXCLUDED.
    let rejected_id = rid(0x45);
    build_accepted_assertion(
        &mut workspace,
        AcceptedAssertionSpec {
            key_prefix: "rejected-epistemic",
            subject_id: live_subject,
            assertion_id: rejected_id,
            proposed_rev: rev(0x45),
            accepted_rev: rev(0x55),
            decision_id: rid(0x65),
            decision_rev: rev(0x65),
            source_id: rid(0x25),
            source_rev: rev(0x25),
            evidence_id: rid(0x35),
            evidence_rev: rev(0x35),
            source_bytes: b"src5",
            claim_value: "rejected-claim",
            epistemic_status: Some("rejected"),
        },
    );

    // Apply suppressions: withdraw `unbacked_ev_id` (removing basis) and `suppressed_id` itself.
    let elig_gen = workspace.eligibility_generation().expect("gen");
    commit_records(
        &mut workspace,
        "withdraw-parity",
        Vec::new(),
        Vec::new(),
        Some(mneme_store::RetentionCommit {
            operation_id: "op-parity-withdraw".to_owned(),
            operation_kind: "withdraw".to_owned(),
            policy_version: "1".to_owned(),
            selectors: Vec::new(),
            suppressions: vec![
                mneme_store::RetentionSuppression {
                    operation_id: "op-parity-withdraw".to_owned(),
                    target: unbacked_ev_id,
                    revision: None,
                    target_kind: "evidence".to_owned(),
                    mode: mneme_store::SuppressionMode::Withdrawn,
                    content_digest: None,
                    generation: elig_gen.saturating_add(1),
                },
                mneme_store::RetentionSuppression {
                    operation_id: "op-parity-withdraw".to_owned(),
                    target: suppressed_id,
                    revision: None,
                    target_kind: "assertion".to_owned(),
                    mode: mneme_store::SuppressionMode::Withdrawn,
                    content_digest: None,
                    generation: elig_gen.saturating_add(1),
                },
            ],
            locations: Vec::new(),
            retained_metadata: Vec::new(),
        }),
    );

    let head = workspace.current_revision().expect("head");
    let head_gen = workspace.eligibility_generation().expect("head gen");

    // Engine 1: mneme-datalog full rebuild.
    let bundle = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "parity-rules".to_owned(),
        version: "1".to_owned(),
        schema_version: 1,
        base_predicates: std::collections::BTreeMap::from([("assertion".to_owned(), 4)]),
        complete_predicates: std::collections::BTreeSet::from(["assertion".to_owned()]),
        rules: vec![mneme_datalog::Rule::new(
            "r-admitted",
            mneme_datalog::Atom::new("admitted_claim", vec![mneme_datalog::Term::var("V")]),
            vec![mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                "assertion",
                vec![
                    mneme_datalog::Term::var("S"),
                    mneme_datalog::Term::var("P"),
                    mneme_datalog::Term::var("V"),
                    mneme_datalog::Term::var("A"),
                ],
            ))],
        )],
    });
    let build = {
        let mut service = mneme_datalog::Service::new(&mut workspace);
        service
            .build(mneme_datalog::BuildRequest {
                actor: "parity-test".to_owned(),
                scope: scope(),
                revision: head,
                bundle,
                limits: mneme_datalog::Limits::default(),
                publish: false,
                incomplete_extents: std::collections::BTreeSet::new(),
                cancellation: None,
                access: mneme_memory::Access::Operator,
                at: None,
            })
            .expect("datalog build")
    };
    let datalog_claims: std::collections::BTreeSet<String> = {
        let mut service = mneme_datalog::Service::new(&mut workspace);
        service
            .query_build(&build, mneme_datalog::Query::all("admitted_claim", 32))
            .expect("datalog query")
            .rows
            .into_iter()
            .filter_map(|row| {
                row.values
                    .first()
                    .and_then(|v| v.as_string())
                    .map(str::to_owned)
            })
            .collect()
    };

    // Engine 2: mneme-datalog IVM (ReplSession).
    let mut repl = mneme_datalog::ReplSession::open(
        &mut workspace,
        mneme_datalog::ReplSessionRequest {
            actor: "parity-test".to_owned(),
            scope: scope(),
            revision: Some(head),
            limits: mneme_datalog::ReplLimits::default(),
            incomplete_extents: std::collections::BTreeSet::new(),
            complete_predicates: std::collections::BTreeSet::from(["assertion".to_owned()]),
            access: mneme_memory::Access::Operator,
            at: None,
        },
    )
    .expect("open repl");
    repl.add_rule(mneme_datalog::Rule::new(
        "r-admitted",
        mneme_datalog::Atom::new("admitted_claim", vec![mneme_datalog::Term::var("V")]),
        vec![mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
            "assertion",
            vec![
                mneme_datalog::Term::var("S"),
                mneme_datalog::Term::var("P"),
                mneme_datalog::Term::var("V"),
                mneme_datalog::Term::var("A"),
            ],
        ))],
    ))
    .expect("add rule");
    let ivm_claims: std::collections::BTreeSet<String> = repl
        .query_relation(
            Some(&mut workspace),
            mneme_datalog::Query::all("admitted_claim", 32),
        )
        .expect("ivm query")
        .rows
        .into_iter()
        .filter_map(|row| {
            row.values
                .first()
                .and_then(|v| v.as_string())
                .map(str::to_owned)
        })
        .collect();

    // Engine 3: mneme-prolog snapshot admission.
    let view = mneme_memory::Engine::new(&mut workspace, mneme_memory::Access::Operator)
        .view_at(Some(head_gen))
        .expect("prolog view");
    let prolog_image =
        mneme_prolog::snapshot::build_input_image(&view, &scope(), head, head_gen, Vec::new())
            .expect("prolog image");
    let prolog_claims: std::collections::BTreeSet<String> = prolog_image
        .canonical
        .into_iter()
        .filter_map(|fact| fact.value.as_string().map(str::to_owned))
        .collect();

    let expected = std::collections::BTreeSet::from(["admitted-claim".to_owned()]);
    assert_eq!(datalog_claims, expected);
    assert_eq!(ivm_claims, expected);
    assert_eq!(prolog_claims, expected);
}

#[test]
fn datalog_and_ivm_block_non_monotonic_rules_under_incomplete_coverage() {
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
    .expect("create workspace");

    let e1 = rid(0x11);
    let payload = mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("entity-type"),
            mneme_core::Value::symbol("project"),
        ),
        (
            mneme_core::Symbol::from("label"),
            mneme_core::Value::string("Alpha".to_owned()),
        ),
        (
            mneme_core::Symbol::from("properties"),
            mneme_core::Value::dictionary([]),
        ),
    ]);
    commit_records(
        &mut workspace,
        "e1",
        vec![mneme_store::RecordDraft {
            schema_version: 1,
            kind: mneme_core::RecordKind::Entity,
            record_id: e1,
            revision_id: rev(0x11),
            predecessor: None,
            scope: scope(),
            payload,
        }],
        Vec::new(),
        None,
    );
    let head = workspace.current_revision().expect("head");

    let neg_rule = mneme_datalog::Rule::new(
        "r-unlinked",
        mneme_datalog::Atom::new("unlinked", vec![mneme_datalog::Term::var("E")]),
        vec![
            mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                "entity",
                vec![
                    mneme_datalog::Term::var("E"),
                    mneme_datalog::Term::var("T"),
                    mneme_datalog::Term::var("L"),
                ],
            )),
            mneme_datalog::Literal::Negative(mneme_datalog::Atom::new(
                "relation",
                vec![
                    mneme_datalog::Term::constant(mneme_core::Value::symbol("links")),
                    mneme_datalog::Term::var("E"),
                    mneme_datalog::Term::var("E"),
                ],
            )),
        ],
    );

    let incomplete = std::collections::BTreeSet::from(["relation".to_owned()]);
    let bundle = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "incomplete-neg".to_owned(),
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
        rules: vec![neg_rule.clone()],
    });
    let build = {
        let mut service = mneme_datalog::Service::new(&mut workspace);
        service
            .build(mneme_datalog::BuildRequest {
                actor: "parity-test".to_owned(),
                scope: scope(),
                revision: head,
                bundle,
                limits: mneme_datalog::Limits::default(),
                publish: false,
                incomplete_extents: incomplete.clone(),
                cancellation: None,
                access: mneme_memory::Access::Operator,
                at: None,
            })
            .expect("build")
    };
    let datalog_rows = {
        let mut service = mneme_datalog::Service::new(&mut workspace);
        service
            .query_build(&build, mneme_datalog::Query::all("unlinked", 16))
            .expect("query")
            .rows
    };

    let mut repl = mneme_datalog::ReplSession::open(
        &mut workspace,
        mneme_datalog::ReplSessionRequest {
            actor: "parity-test".to_owned(),
            scope: scope(),
            revision: Some(head),
            limits: mneme_datalog::ReplLimits::default(),
            incomplete_extents: incomplete,
            complete_predicates: std::collections::BTreeSet::from([
                "entity".to_owned(),
                "relation".to_owned(),
            ]),
            access: mneme_memory::Access::Operator,
            at: None,
        },
    )
    .expect("open repl");
    repl.add_rule(neg_rule).expect("add neg rule");
    let ivm_rows = repl
        .query_relation(
            Some(&mut workspace),
            mneme_datalog::Query::all("unlinked", 16),
        )
        .expect("ivm query")
        .rows;

    assert!(datalog_rows.is_empty());
    assert!(ivm_rows.is_empty());
}
