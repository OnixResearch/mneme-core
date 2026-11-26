//! Integration tests for Heterogeneous Personalized PageRank (`Mode::GraphPpr`)
//! and opt-in Conformal Risk Control threshold filtering (`Request::calibration`).
// Octet structural exception: domain-qualified names and macro-only imports are intentional

const ACTOR: &str = "ppr-test";
const SERVICES: u8 = 32;
const EDGES: [(u8, u8); 2] = [(7, 1), (11, 5)];
const NAMES: [&str; 32] = [
    "alder", "birch", "cedar", "dogwood", "elm", "fir", "ginkgo", "hazel", "ironwood", "juniper",
    "katsura", "larch", "maple", "nutmeg", "oak", "pine", "quince", "redwood", "spruce",
    "tamarack", "ulmus", "viburnum", "walnut", "xylosma", "yew", "zelkova", "acacia", "baobab",
    "cypress", "durian", "ebony", "fig",
];
const NOUNS: [&str; 8] = [
    "ledger",
    "sessions",
    "events",
    "metrics",
    "invoices",
    "profiles",
    "logs",
    "artifacts",
];
const STORES: [&str; 8] = [
    "Postgres",
    "Redis",
    "SQLite",
    "Kafka",
    "Cassandra",
    "DuckDB",
    "etcd",
    "MinIO",
];

type TestError = Box<dyn std::error::Error>;

struct ClaimFixture<'a> {
    key: &'a str,
    subject: mneme_core::RecordId,
    index: u8,
    text: &'a str,
}

fn rec(tag: u8, index: u8) -> mneme_core::RecordId {
    let mut bytes = [tag; 16];
    bytes[1] = index;
    mneme_core::RecordId::from_bytes(bytes)
}

fn rev(tag: u8, index: u8) -> mneme_core::RevisionId {
    let mut bytes = [tag; 16];
    bytes[1] = index;
    mneme_core::RevisionId::from_bytes(bytes)
}

fn new_workspace() -> Result<(tempfile::TempDir, mneme_store::Workspace), TestError> {
    let temp = tempfile::tempdir()?;
    let workspace = mneme_store::Workspace::create(
        temp.path(),
        mneme_store::WorkspaceConfig {
            clock: Box::new(mneme_store::FixedClock::new(
                mneme_core::Timestamp::from_nanos(1_000),
            )),
            faults: Box::new(mneme_store::NoFaults),
        },
    )?;
    Ok((temp, workspace))
}

fn commit(
    workspace: &mut mneme_store::Workspace,
    scope: &mneme_core::ScopeId,
    key: &str,
    records: Vec<mneme_store::RecordDraft>,
    source_blobs: Vec<mneme_store::SourceBlobDraft>,
) -> Result<(), TestError> {
    let base = workspace.current_revision()?;
    workspace.commit(mneme_store::CommitCommand {
        base,
        actor: ACTOR.to_owned(),
        scope: scope.clone(),
        idempotency_key: key.to_owned(),
        records,
        source_blobs,
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: None,
    })?;
    Ok(())
}

fn draft(
    scope: &mneme_core::ScopeId,
    kind: mneme_core::RecordKind,
    ids: (mneme_core::RecordId, mneme_core::RevisionId),
    payload: mneme_core::Payload,
) -> mneme_store::RecordDraft {
    mneme_store::RecordDraft {
        schema_version: 1,
        kind,
        record_id: ids.0,
        revision_id: ids.1,
        predecessor: None,
        scope: scope.clone(),
        payload,
    }
}

fn entity_payload(label: &str) -> mneme_core::Payload {
    mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("entity-type"),
            mneme_core::Value::symbol("service"),
        ),
        (
            mneme_core::Symbol::from("label"),
            mneme_core::Value::string(label),
        ),
        (
            mneme_core::Symbol::from("properties"),
            mneme_core::Value::dictionary([]),
        ),
    ])
}

fn relation_payload(
    relation_type: &str,
    from: mneme_core::RecordId,
    to: mneme_core::RecordId,
    status: Option<&str>,
) -> mneme_core::Payload {
    let props = match status {
        Some(value) => mneme_core::Value::dictionary([(
            mneme_core::Value::symbol("status"),
            mneme_core::Value::symbol(value),
        )]),
        None => mneme_core::Value::dictionary([]),
    };
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
        (mneme_core::Symbol::from("properties"), props),
    ])
}

fn add_accepted_claim(
    workspace: &mut mneme_store::Workspace,
    scope: &mneme_core::ScopeId,
    fixture: &ClaimFixture<'_>,
) -> Result<(), TestError> {
    commit_proposed_claim(workspace, scope, fixture)?;
    accept_claim(workspace, scope, fixture.key, fixture.index)
}

fn commit_proposed_claim(
    workspace: &mut mneme_store::Workspace,
    scope: &mneme_core::ScopeId,
    fixture: &ClaimFixture<'_>,
) -> Result<(), TestError> {
    let (source, blob) = mneme_memory::build_source(
        rec(4, fixture.index),
        rev(4, fixture.index),
        scope,
        mneme_memory::SourceOptions {
            bytes: fixture.text.as_bytes(),
            media_type: "text/plain",
            entity: Some(fixture.subject),
            path_hint: None,
        },
    )?;
    commit(
        workspace,
        scope,
        &format!("{}-src", fixture.key),
        vec![source],
        vec![blob],
    )?;
    let end = u64::try_from(fixture.text.len())?.saturating_sub(1);
    let evidence = mneme_memory::build_evidence(
        rec(5, fixture.index),
        rev(5, fixture.index),
        scope,
        mneme_memory::EvidenceOptions {
            assertion: rec(6, fixture.index),
            source: rec(4, fixture.index),
            source_revision: rev(4, fixture.index),
            span: Some(mneme_core::SourceSpan::new(0, end)?),
            anchor: Some("store"),
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let assertion = mneme_memory::build_proposed_assertion(
        rec(6, fixture.index),
        rev(6, fixture.index),
        scope,
        mneme_memory::ProposedAssertionOptions {
            subject: fixture.subject,
            predicate: "store",
            value: mneme_core::Value::string(fixture.text),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: ACTOR,
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                rec(5, fixture.index),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    commit(
        workspace,
        scope,
        &format!("{}-claim", fixture.key),
        vec![evidence, assertion],
        Vec::new(),
    )
}

fn accept_claim(
    workspace: &mut mneme_store::Workspace,
    scope: &mneme_core::ScopeId,
    key: &str,
    index: u8,
) -> Result<(), TestError> {
    let input_revision = workspace.current_revision()?;
    let current = workspace
        .record_revisions(rec(6, index))?
        .into_iter()
        .last()
        .ok_or("proposed claim missing revision")?;
    let decision = mneme_memory::build_decision(
        rec(7, index),
        rev(7, index),
        scope,
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: rec(6, index),
            actor: ACTOR,
            policy: "ppr-test/v1",
            input_revision,
            outcome: "accepted",
            rationale: "test fixture",
            evidence: &[],
            related: &[],
        },
    );
    let accepted = mneme_memory::build_assertion_revision(
        &current,
        rev(8, index),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(rec(7, index), mneme_core::RecordKind::Decision),
        None,
    );
    commit(
        workspace,
        scope,
        &format!("{key}-accept"),
        vec![decision, accepted],
        Vec::new(),
    )
}

fn dependencies(index: u8) -> impl Iterator<Item = u8> {
    EDGES.into_iter().filter_map(move |(multiplier, offset)| {
        let target = u16::from(index)
            .checked_mul(u16::from(multiplier))?
            .checked_add(u16::from(offset))?
            .checked_rem(u16::from(SERVICES))?;
        let target = u8::try_from(target).ok()?;
        (target != index).then_some(target)
    })
}

fn gold_sources(
    seed: u8,
) -> std::collections::BTreeSet<(mneme_core::RecordId, mneme_core::RevisionId)> {
    let mut seen = std::collections::BTreeSet::from([seed]);
    let mut frontier = vec![seed];
    for _ in 0..2 {
        let next = frontier
            .iter()
            .flat_map(|service| dependencies(*service))
            .filter(|service| seen.insert(*service))
            .collect::<Vec<_>>();
        frontier = next;
    }
    seen.remove(&seed);
    seen.into_iter()
        .map(|service| (rec(4, service), rev(4, service)))
        .collect()
}

fn service_claim_text(index: u8) -> String {
    let slot = usize::from(index);
    let noun = slot.checked_rem(NOUNS.len()).unwrap_or_default();
    let store = slot
        .checked_div(NOUNS.len())
        .unwrap_or_default()
        .saturating_add(slot)
        .checked_rem(STORES.len())
        .unwrap_or_default();
    format!(
        "The {} service keeps its {} in {}.",
        NAMES[slot], NOUNS[noun], STORES[store]
    )
}

fn build_service_graph(
    workspace: &mut mneme_store::Workspace,
    scope: &mneme_core::ScopeId,
) -> Result<(), TestError> {
    let records: Vec<mneme_store::RecordDraft> = (0..SERVICES)
        .flat_map(|index| {
            let entity = std::iter::once(draft(
                scope,
                mneme_core::RecordKind::Entity,
                (rec(1, index), rev(1, index)),
                entity_payload(NAMES[usize::from(index)]),
            ));
            let edges = dependencies(index).enumerate().map(move |(edge, target)| {
                let tag = if edge == 0 { 2 } else { 3 };
                draft(
                    scope,
                    mneme_core::RecordKind::Relation,
                    (rec(tag, index), rev(tag, index)),
                    relation_payload("depends", rec(1, index), rec(1, target), None),
                )
            });
            entity.chain(edges)
        })
        .collect();
    commit(workspace, scope, "graph", records, Vec::new())?;
    for index in 0..SERVICES {
        let text = service_claim_text(index);
        let key = format!("svc-{index}");
        add_accepted_claim(
            workspace,
            scope,
            &ClaimFixture {
                key: &key,
                subject: rec(1, index),
                index,
                text: &text,
            },
        )?;
    }
    Ok(())
}

#[test]
fn entity_seeded_ppr_lifts_citable_evidence_above_targets() {
    let (_temp, mut workspace) = new_workspace().expect("workspace");
    let scope =
        mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "services").expect("scope");
    build_service_graph(&mut workspace, &scope).expect("service graph");
    let revision = workspace.current_revision().expect("rev");

    for (max_items, max_bytes, target_citable) in
        [(8_usize, 4_096_usize, 0.65_f64), (4, 1_024, 0.30)]
    {
        let mut citable_hits = 0_usize;
        let mut gold_total = 0_usize;
        let mut service = mneme_recall::Service::new(&mut workspace);
        for seed in 0..SERVICES {
            let mut config = mneme_recall::ppr::Config::new();
            config.seeds.insert(rec(1, seed));
            config.relation_types.insert("depends".to_owned());
            let mut req = mneme_recall::Request::lexical(
                ACTOR,
                scope.clone(),
                revision,
                mneme_core::Timestamp::from_nanos(2_000),
                format!(
                    "Which stores do the dependencies of the {} service use?",
                    NAMES[usize::from(seed)]
                ),
            )
            .with_graph_ppr(config);
            req.max_items = max_items;
            req.max_context_bytes = max_bytes;
            let resp = service.recall(req).expect("recall");
            assert_eq!(resp.status, mneme_recall::Execution::Complete);
            assert!(!resp.exhaustive);
            assert!(!resp.absence_established);
            for candidate in &resp.candidates {
                assert_ne!(
                    candidate.content_kind,
                    mneme_recall::ContentKind::StructuredRow
                );
            }
            let gold = gold_sources(seed);
            let hits = resp
                .candidates
                .iter()
                .filter(|c| {
                    matches!(
                        c.content_kind,
                        mneme_recall::ContentKind::Claim | mneme_recall::ContentKind::SourceExcerpt
                    )
                })
                .flat_map(|c| c.ancestry_roots.iter().copied())
                .filter(|root| gold.contains(root))
                .collect::<std::collections::BTreeSet<_>>()
                .len();
            citable_hits = citable_hits.saturating_add(hits);
            gold_total = gold_total.saturating_add(gold.len());
        }
        let ratio = (citable_hits as f64) / (gold_total as f64);
        assert!(
            ratio >= target_citable,
            "budget ({max_items}, {max_bytes}): citable {ratio:.3} ({citable_hits}/{gold_total}) < {target_citable:.2}"
        );
    }
}

#[test]
fn graph_ppr_auto_seeds_from_bm25f_and_excludes_proposed_rejected_edges() {
    let (_temp, mut workspace) = new_workspace().expect("workspace");
    let scope =
        mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "epistemic").expect("scope");
    commit(
        &mut workspace,
        &scope,
        "entities-relations",
        vec![
            draft(
                &scope,
                mneme_core::RecordKind::Entity,
                (rec(1, 0), rev(1, 0)),
                entity_payload("orion"),
            ),
            draft(
                &scope,
                mneme_core::RecordKind::Entity,
                (rec(1, 1), rev(1, 1)),
                entity_payload("lyra"),
            ),
            draft(
                &scope,
                mneme_core::RecordKind::Entity,
                (rec(1, 2), rev(1, 2)),
                entity_payload("draco"),
            ),
            draft(
                &scope,
                mneme_core::RecordKind::Entity,
                (rec(1, 3), rev(1, 3)),
                entity_payload("hydra"),
            ),
            draft(
                &scope,
                mneme_core::RecordKind::Relation,
                (rec(2, 1), rev(2, 1)),
                relation_payload("depends", rec(1, 0), rec(1, 1), Some("accepted")),
            ),
            draft(
                &scope,
                mneme_core::RecordKind::Relation,
                (rec(2, 2), rev(2, 2)),
                relation_payload("depends", rec(1, 0), rec(1, 2), Some("proposed")),
            ),
            draft(
                &scope,
                mneme_core::RecordKind::Relation,
                (rec(2, 3), rev(2, 3)),
                relation_payload("depends", rec(1, 0), rec(1, 3), Some("rejected")),
            ),
        ],
        Vec::new(),
    )
    .expect("commit");
    for fixture in [
        ClaimFixture {
            key: "c0",
            subject: rec(1, 0),
            index: 0,
            text: "Orion gateway routes telemetry.",
        },
        ClaimFixture {
            key: "c1",
            subject: rec(1, 1),
            index: 1,
            text: "Lyra broker persists batches in DuckDB.",
        },
        ClaimFixture {
            key: "c2",
            subject: rec(1, 2),
            index: 2,
            text: "Draco unreviewed edge secret.",
        },
        ClaimFixture {
            key: "c3",
            subject: rec(1, 3),
            index: 3,
            text: "Hydra rejected edge secret.",
        },
    ] {
        add_accepted_claim(&mut workspace, &scope, &fixture).expect("claim");
    }

    let revision = workspace.current_revision().expect("rev");
    let mut req = mneme_recall::Request::lexical(
        ACTOR,
        scope,
        revision,
        mneme_core::Timestamp::from_nanos(2_000),
        "Orion gateway",
    );
    req.modes = std::collections::BTreeSet::from([mneme_recall::Mode::GraphPpr]);
    req.graph_ppr = Some(mneme_recall::ppr::Config::new());

    let resp = mneme_recall::Service::new(&mut workspace)
        .recall(req)
        .expect("recall");
    let ids: std::collections::BTreeSet<String> =
        resp.candidates.iter().map(|c| c.id.clone()).collect();
    assert!(ids.contains(&format!("assertion:{}", rec(6, 1))));
    assert!(!ids.contains(&format!("assertion:{}", rec(6, 2))));
    assert!(!ids.contains(&format!("assertion:{}", rec(6, 3))));
}

#[test]
fn graph_ppr_resists_hub_dilution() {
    let (_temp, mut workspace) = new_workspace().expect("workspace");
    let scope = mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "hubs").expect("scope");
    let mut records = vec![
        draft(
            &scope,
            mneme_core::RecordKind::Entity,
            (rec(1, 0), rev(1, 0)),
            entity_payload("specific"),
        ),
        draft(
            &scope,
            mneme_core::RecordKind::Entity,
            (rec(1, 1), rev(1, 1)),
            entity_payload("target-specific"),
        ),
        draft(
            &scope,
            mneme_core::RecordKind::Relation,
            (rec(2, 1), rev(2, 1)),
            relation_payload("depends", rec(1, 0), rec(1, 1), None),
        ),
        draft(
            &scope,
            mneme_core::RecordKind::Entity,
            (rec(1, 10), rev(1, 10)),
            entity_payload("megahub"),
        ),
    ];
    records.extend((20_u8..55_u8).flat_map(|idx| {
        [
            draft(
                &scope,
                mneme_core::RecordKind::Entity,
                (rec(1, idx), rev(1, idx)),
                entity_payload(&format!("spoke-{idx}")),
            ),
            draft(
                &scope,
                mneme_core::RecordKind::Relation,
                (rec(2, idx), rev(2, idx)),
                relation_payload("depends", rec(1, 10), rec(1, idx), None),
            ),
        ]
    }));
    commit(&mut workspace, &scope, "hub-graph", records, Vec::new()).expect("commit");
    add_accepted_claim(
        &mut workspace,
        &scope,
        &ClaimFixture {
            key: "spec",
            subject: rec(1, 1),
            index: 1,
            text: "Specific neighbor claim.",
        },
    )
    .expect("spec");
    add_accepted_claim(
        &mut workspace,
        &scope,
        &ClaimFixture {
            key: "hub-spoke",
            subject: rec(1, 20),
            index: 20,
            text: "Hub spoke claim.",
        },
    )
    .expect("spoke");

    let revision = workspace.current_revision().expect("rev");
    let mut config = mneme_recall::ppr::Config::new();
    config.seeds.insert(rec(1, 0));
    config.seeds.insert(rec(1, 10));
    config.solver = mneme_recall::ppr::Solver::PowerIteration;
    config.push_tolerance = 1e-6;
    let mut req = mneme_recall::Request::lexical(
        ACTOR,
        scope,
        revision,
        mneme_core::Timestamp::from_nanos(2_000),
        "hub test",
    );
    req.modes = std::collections::BTreeSet::from([mneme_recall::Mode::GraphPpr]);
    req.graph_ppr = Some(config);
    let resp = mneme_recall::Service::new(&mut workspace)
        .recall(req)
        .expect("recall");

    let spec_id = format!("assertion:{}", rec(6, 1));
    let spoke_id = format!("assertion:{}", rec(6, 20));
    let spec_score = resp
        .candidates
        .iter()
        .find(|c| c.id == spec_id)
        .and_then(|c| c.score_components.get("graph-ppr"))
        .copied()
        .expect("specific claim ranked");
    let spoke_score = resp
        .candidates
        .iter()
        .find(|c| c.id == spoke_id)
        .and_then(|c| c.score_components.get("graph-ppr"))
        .copied()
        .unwrap_or(0.0);
    assert!(spec_score > spoke_score * 10.0);
}

#[test]
fn graph_ppr_has_zero_ulp_drift_from_forgotten_and_other_scope_records() {
    let scope_a =
        mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "alpha").expect("scope");
    let scope_b = mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "beta").expect("scope");

    let (_t1, mut clean) = new_workspace().expect("clean");
    commit(
        &mut clean,
        &scope_a,
        "base",
        vec![
            draft(
                &scope_a,
                mneme_core::RecordKind::Entity,
                (rec(1, 0), rev(1, 0)),
                entity_payload("root"),
            ),
            draft(
                &scope_a,
                mneme_core::RecordKind::Entity,
                (rec(1, 1), rev(1, 1)),
                entity_payload("mid"),
            ),
            draft(
                &scope_a,
                mneme_core::RecordKind::Entity,
                (rec(1, 2), rev(1, 2)),
                entity_payload("leaf"),
            ),
            draft(
                &scope_a,
                mneme_core::RecordKind::Relation,
                (rec(2, 1), rev(2, 1)),
                relation_payload("depends", rec(1, 0), rec(1, 1), None),
            ),
            draft(
                &scope_a,
                mneme_core::RecordKind::Relation,
                (rec(2, 2), rev(2, 2)),
                relation_payload("depends", rec(1, 1), rec(1, 2), None),
            ),
        ],
        Vec::new(),
    )
    .expect("commit clean");
    add_accepted_claim(
        &mut clean,
        &scope_a,
        &ClaimFixture {
            key: "c1",
            subject: rec(1, 1),
            index: 1,
            text: "Mid service stores state in Postgres.",
        },
    )
    .expect("c1");
    add_accepted_claim(
        &mut clean,
        &scope_a,
        &ClaimFixture {
            key: "c2",
            subject: rec(1, 2),
            index: 2,
            text: "Leaf service stores logs in Kafka.",
        },
    )
    .expect("c2");

    let (_t2, mut polluted) = new_workspace().expect("polluted");
    commit(
        &mut polluted,
        &scope_a,
        "base",
        vec![
            draft(
                &scope_a,
                mneme_core::RecordKind::Entity,
                (rec(1, 0), rev(1, 0)),
                entity_payload("root"),
            ),
            draft(
                &scope_a,
                mneme_core::RecordKind::Entity,
                (rec(1, 1), rev(1, 1)),
                entity_payload("mid"),
            ),
            draft(
                &scope_a,
                mneme_core::RecordKind::Entity,
                (rec(1, 2), rev(1, 2)),
                entity_payload("leaf"),
            ),
            draft(
                &scope_a,
                mneme_core::RecordKind::Relation,
                (rec(2, 1), rev(2, 1)),
                relation_payload("depends", rec(1, 0), rec(1, 1), None),
            ),
            draft(
                &scope_a,
                mneme_core::RecordKind::Relation,
                (rec(2, 2), rev(2, 2)),
                relation_payload("depends", rec(1, 1), rec(1, 2), None),
            ),
        ],
        Vec::new(),
    )
    .expect("commit polluted");
    add_accepted_claim(
        &mut polluted,
        &scope_a,
        &ClaimFixture {
            key: "c1",
            subject: rec(1, 1),
            index: 1,
            text: "Mid service stores state in Postgres.",
        },
    )
    .expect("c1");
    add_accepted_claim(
        &mut polluted,
        &scope_a,
        &ClaimFixture {
            key: "c2",
            subject: rec(1, 2),
            index: 2,
            text: "Leaf service stores logs in Kafka.",
        },
    )
    .expect("c2");
    add_accepted_claim(
        &mut polluted,
        &scope_a,
        &ClaimFixture {
            key: "c9",
            subject: rec(1, 1),
            index: 9,
            text: "Erased service secret on mid.",
        },
    )
    .expect("c9");

    commit(
        &mut polluted,
        &scope_b,
        "other-scope",
        vec![
            draft(
                &scope_b,
                mneme_core::RecordKind::Entity,
                (rec(1, 15), rev(1, 15)),
                entity_payload("foreign"),
            ),
            draft(
                &scope_b,
                mneme_core::RecordKind::Relation,
                (rec(2, 15), rev(2, 15)),
                relation_payload("depends", rec(1, 0), rec(1, 15), None),
            ),
        ],
        Vec::new(),
    )
    .expect("other scope");
    add_accepted_claim(
        &mut polluted,
        &scope_b,
        &ClaimFixture {
            key: "c15",
            subject: rec(1, 15),
            index: 15,
            text: "Foreign scope secret.",
        },
    )
    .expect("c15");

    let policy = mneme_retention::Policy {
        version: mneme_retention::POLICY_VERSION.to_owned(),
        retain_assertion_after_prune: false,
        block_content_replay: true,
        retain_withdrawn_evidence_metadata: true,
    };
    let base_revision = polluted.current_revision().expect("base rev");
    mneme_retention::Engine::new(&mut polluted)
        .execute(mneme_retention::Request {
            actor: ACTOR.to_owned(),
            scope: scope_a.clone(),
            base_revision,
            idempotency_key: "forget-c9".to_owned(),
            operation: mneme_retention::OperationKind::Forget,
            selector: mneme_retention::Selector::Source(rec(4, 9)),
            effective: None,
            policy,
        })
        .expect("forget");

    let run = |ws: &mut mneme_store::Workspace| -> Vec<(String, u64, u64)> {
        let rev_id = ws.current_revision().expect("rev");
        let mut config = mneme_recall::ppr::Config::new();
        config.seeds.insert(rec(1, 0));
        let mut req = mneme_recall::Request::lexical(
            ACTOR,
            scope_a.clone(),
            rev_id,
            mneme_core::Timestamp::from_nanos(2_000),
            "service stores",
        )
        .with_graph_ppr(config);
        req.modes = std::collections::BTreeSet::from([mneme_recall::Mode::GraphPpr]);
        let resp = mneme_recall::Service::new(ws).recall(req).expect("recall");
        resp.candidates
            .into_iter()
            .map(|c| {
                let raw = c.score_components.get("graph-ppr").copied().unwrap_or(0.0);
                (c.id, c.score.to_bits(), raw.to_bits())
            })
            .collect()
    };

    let clean_scores = run(&mut clean);
    let polluted_scores = run(&mut polluted);
    assert!(!clean_scores.is_empty());
    assert_eq!(clean_scores, polluted_scores);
}

#[test]
fn conformal_calibration_filters_below_threshold_and_never_establishes_absence() {
    let (_temp, mut workspace) = new_workspace().expect("workspace");
    let scope = mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "crc").expect("scope");
    commit(
        &mut workspace,
        &scope,
        "entities",
        vec![
            draft(
                &scope,
                mneme_core::RecordKind::Entity,
                (rec(1, 0), rev(1, 0)),
                entity_payload("alpha"),
            ),
            draft(
                &scope,
                mneme_core::RecordKind::Entity,
                (rec(1, 1), rev(1, 1)),
                entity_payload("beta"),
            ),
        ],
        Vec::new(),
    )
    .expect("commit");
    add_accepted_claim(
        &mut workspace,
        &scope,
        &ClaimFixture {
            key: "strong",
            subject: rec(1, 0),
            index: 0,
            text: "Quantum cryptography protocol uses lattice signatures for verification.",
        },
    )
    .expect("strong");
    add_accepted_claim(
        &mut workspace,
        &scope,
        &ClaimFixture {
            key: "weak",
            subject: rec(1, 1),
            index: 1,
            text: "The cafeteria serves protocol sandwiches every Tuesday afternoon.",
        },
    )
    .expect("weak");
    let revision = workspace.current_revision().expect("rev");

    let req = mneme_recall::Request::lexical(
        ACTOR,
        scope.clone(),
        revision,
        mneme_core::Timestamp::from_nanos(2_000),
        "quantum cryptography protocol lattice signatures",
    )
    .with_calibration(mneme_recall::CalibrationConfig {
        profile_digest: "b3:test-profile-v1".to_owned(),
        lambda_hat: 0.55,
        alpha: 0.1,
        score_mode: Some(mneme_recall::Mode::Lexical),
    });
    let resp = mneme_recall::Service::new(&mut workspace)
        .recall(req)
        .expect("recall");
    assert!(!resp.candidates.is_empty());
    assert!(resp.candidates.iter().all(|c| {
        mneme_recall::pre_rrf_normalized_score(c, Some(mneme_recall::Mode::Lexical)) >= 0.45
    }));
    assert!(
        resp.omissions
            .iter()
            .any(|o| o.reason == "below-conformal-threshold")
    );
    assert!(!resp.exhaustive);
    assert!(!resp.absence_established);

    let abstaining = mneme_recall::Request::lexical(
        ACTOR,
        scope,
        revision,
        mneme_core::Timestamp::from_nanos(2_000),
        "protocol zephyr unicorn",
    )
    .with_calibration(mneme_recall::CalibrationConfig {
        profile_digest: "b3:test-profile-abs".to_owned(),
        lambda_hat: 0.10,
        alpha: 0.05,
        score_mode: Some(mneme_recall::Mode::Lexical),
    });
    let abs_resp = mneme_recall::Service::new(&mut workspace)
        .recall(abstaining)
        .expect("abstaining recall");
    assert!(abs_resp.candidates.is_empty());
    assert!(!abs_resp.omissions.is_empty());
    assert!(
        abs_resp
            .omissions
            .iter()
            .all(|o| o.reason == "below-conformal-threshold")
    );
    assert!(!abs_resp.exhaustive);
    assert!(!abs_resp.absence_established);
}
