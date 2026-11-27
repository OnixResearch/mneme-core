//! Integration tests for Datalog `verdict/6` base predicate projection and
//! staleness derivation (`stale_verdict`) on artifact or toolchain digest drift.

const FIXED_CLOCK_NANOS: i64 = 1_700_000_000_000_000_000;

fn scope() -> Result<mneme_core::ScopeId, Box<dyn std::error::Error>> {
    Ok(mneme_core::ScopeId::new(
        mneme_core::ScopeClass::Project,
        "lakatos",
    )?)
}

fn fixed_config() -> mneme_store::WorkspaceConfig {
    mneme_store::WorkspaceConfig::new(
        Box::new(mneme_store::FixedClock::new(
            mneme_core::Timestamp::from_nanos(FIXED_CLOCK_NANOS),
        )),
        Box::new(mneme_store::NoFaults),
    )
}

fn make_entity_draft(
    id_byte: u8,
    kind: &str,
    label: &str,
    scope: &mneme_core::ScopeId,
) -> mneme_store::RecordDraft {
    mneme_store::RecordDraft {
        schema_version: 1,
        kind: mneme_core::RecordKind::Entity,
        record_id: mneme_core::RecordId::from_bytes([id_byte; 16]),
        revision_id: mneme_core::RevisionId::from_bytes([id_byte.wrapping_add(0x40); 16]),
        predecessor: None,
        scope: scope.clone(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("entity-type"),
                mneme_core::Value::symbol(kind),
            ),
            (
                mneme_core::Symbol::from("label"),
                mneme_core::Value::string(label),
            ),
            (
                mneme_core::Symbol::from("properties"),
                mneme_core::Value::dictionary([]),
            ),
        ]),
    }
}

fn make_relation_draft(
    id_byte: u8,
    rel_type: &str,
    from: mneme_core::RecordId,
    to: mneme_core::RecordId,
    scope: &mneme_core::ScopeId,
) -> mneme_store::RecordDraft {
    let from_ref = mneme_core::Value::record_named(
        "local-ref",
        vec![from.to_value(), mneme_core::Value::symbol("entity")],
    );
    let to_ref = mneme_core::Value::record_named(
        "local-ref",
        vec![to.to_value(), mneme_core::Value::symbol("entity")],
    );
    mneme_store::RecordDraft {
        schema_version: 1,
        kind: mneme_core::RecordKind::Relation,
        record_id: mneme_core::RecordId::from_bytes([id_byte; 16]),
        revision_id: mneme_core::RevisionId::from_bytes([id_byte.wrapping_add(0x60); 16]),
        predecessor: None,
        scope: scope.clone(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("relation-type"),
                mneme_core::Value::symbol(rel_type),
            ),
            (mneme_core::Symbol::from("from"), from_ref),
            (mneme_core::Symbol::from("to"), to_ref),
            (
                mneme_core::Symbol::from("properties"),
                mneme_core::Value::dictionary([]),
            ),
        ]),
    }
}

fn make_verdict_episode_draft(
    id_byte: u8,
    target_id: mneme_core::RecordId,
    verdict: &mneme_core::OracleVerdict,
    scope: &mneme_core::ScopeId,
) -> mneme_store::RecordDraft {
    let occurred =
        mneme_core::ValidTime::instant(mneme_core::Timestamp::from_nanos(FIXED_CLOCK_NANOS))
            .to_value();
    let target_ref = mneme_core::Value::record_named(
        "local-ref",
        vec![target_id.to_value(), mneme_core::Value::symbol("entity")],
    );
    mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::Episode,
        record_id: mneme_core::RecordId::from_bytes([id_byte; 16]),
        revision_id: mneme_core::RevisionId::from_bytes([id_byte.wrapping_add(0x80); 16]),
        predecessor: None,
        scope: scope.clone(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("actor"),
                mneme_core::Value::string(verdict.tool.clone()),
            ),
            (
                mneme_core::Symbol::from("episode-type"),
                mneme_core::Value::symbol("oracle_verdict"),
            ),
            (mneme_core::Symbol::from("occurred"), occurred),
            (
                mneme_core::Symbol::from("summary"),
                mneme_core::Value::string(format!("{}: {}", verdict.tool, verdict.outcome)),
            ),
            (
                mneme_core::Symbol::from("oracle-kind"),
                mneme_core::Value::symbol(verdict.tool.clone()),
            ),
            (
                mneme_core::Symbol::from("verdict"),
                mneme_core::Value::symbol(verdict.outcome.clone()),
            ),
            (mneme_core::Symbol::from("target-entity"), target_ref),
            (
                mneme_core::Symbol::from("oracle-verdict"),
                verdict.to_value(),
            ),
        ]),
    }
}

#[test]
fn datalog_projects_verdict_6_and_derives_stale_verdict() -> Result<(), Box<dyn std::error::Error>>
{
    let temp = tempfile::tempdir()?;
    let sc = scope()?;
    let mut ws = mneme_store::Workspace::create(temp.path(), fixed_config())?;

    let target_id = mneme_core::RecordId::from_bytes([0x01; 16]);
    let head_digest_id = mneme_core::RecordId::from_bytes([0x03; 16]);
    let old_digest = "aa".repeat(32);
    let new_digest = "ff".repeat(32);
    let toolchain_digest = "bb".repeat(32);

    let verdict = mneme_core::OracleVerdict {
        tool: "just-proofs".to_owned(),
        target: "crates/mneme-kernel".to_owned(),
        outcome: "verified".to_owned(),
        artifact_digest: old_digest.clone(),
        toolchain_digest: toolchain_digest.clone(),
        eval_rev: "rev-1".to_owned(),
        receipt: Some(mneme_core::ReproducibilityReceipt {
            subject_digest: old_digest,
            git_rev: "rev-1".to_owned(),
            flake_lock_digest: toolchain_digest,
            command_spec_digest: "cc".repeat(32),
            seed_class: "deterministic".to_owned(),
            boundary_conditions: vec!["no-std".to_owned()],
            outcome: "verified".to_owned(),
            metrics_digest: "dd".repeat(32),
        }),
    };

    let base = ws.current_revision()?;
    let _ = ws.commit(mneme_store::CommitCommand {
        base,
        actor: "test".to_owned(),
        scope: sc.clone(),
        idempotency_key: "verdict-seed".to_owned(),
        records: vec![
            make_entity_draft(0x01, "file", "crates/mneme-kernel/src/lib.rs", &sc),
            make_verdict_episode_draft(0x02, target_id, &verdict, &sc),
            make_entity_draft(0x03, "digest", &new_digest, &sc),
            make_relation_draft(
                0x04,
                "current_subject_digest",
                target_id,
                head_digest_id,
                &sc,
            ),
        ],
        source_blobs: Vec::new(),
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: None,
    })?;

    let bundle = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "verdict-staleness-test".to_owned(),
        version: "1".to_owned(),
        schema_version: 3,
        base_predicates: std::collections::BTreeMap::from([
            ("verdict".to_owned(), 6),
            ("entity".to_owned(), 3),
            ("relation".to_owned(), 3),
        ]),
        complete_predicates: std::collections::BTreeSet::from([
            "verdict".to_owned(),
            "entity".to_owned(),
            "relation".to_owned(),
        ]),
        rules: vec![mneme_datalog::Rule::new(
            "stale-on-subject-drift",
            mneme_datalog::Atom::new(
                "stale_verdict",
                vec![
                    mneme_datalog::Term::var("V"),
                    mneme_datalog::Term::var("Target"),
                ],
            ),
            vec![
                mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                    "verdict",
                    vec![
                        mneme_datalog::Term::var("V"),
                        mneme_datalog::Term::var("Target"),
                        mneme_datalog::Term::var("Outcome"),
                        mneme_datalog::Term::var("Digest"),
                        mneme_datalog::Term::var("Toolchain"),
                        mneme_datalog::Term::var("Rev"),
                    ],
                )),
                mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                    "relation",
                    vec![
                        mneme_datalog::Term::constant(mneme_core::Value::symbol(
                            "current_subject_digest",
                        )),
                        mneme_datalog::Term::var("Target"),
                        mneme_datalog::Term::var("DigestEnt"),
                    ],
                )),
                mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                    "entity",
                    vec![
                        mneme_datalog::Term::var("DigestEnt"),
                        mneme_datalog::Term::constant(mneme_core::Value::symbol("digest")),
                        mneme_datalog::Term::var("HeadDigest"),
                    ],
                )),
                mneme_datalog::Literal::Compare {
                    op: mneme_datalog::CompareOp::Ne,
                    left: mneme_datalog::Term::var("Digest"),
                    right: mneme_datalog::Term::var("HeadDigest"),
                },
            ],
        )],
    });

    let head_rev = ws.current_revision()?;
    let mut service = mneme_datalog::Service::new(&mut ws);
    let build = service.build(mneme_datalog::BuildRequest {
        actor: "test".to_owned(),
        scope: sc.clone(),
        revision: head_rev,
        bundle,
        limits: mneme_datalog::Limits::default(),
        publish: false,
        incomplete_extents: std::collections::BTreeSet::new(),
        cancellation: None,
        access: mneme_memory::Access::scopes([sc]),
        at: None,
    })?;

    let verdicts = service.query_build(&build, mneme_datalog::Query::all("verdict", 16))?;
    assert_eq!(verdicts.rows.len(), 1);
    let stale = service.query_build(&build, mneme_datalog::Query::all("stale_verdict", 16))?;
    assert_eq!(stale.rows.len(), 1);
    assert_eq!(
        stale.rows[0].values[0],
        mneme_core::RecordId::from_bytes([0x02; 16]).to_value()
    );
    assert_eq!(stale.rows[0].values[1], target_id.to_value());
    Ok(())
}
