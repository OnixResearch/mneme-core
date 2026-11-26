//! Entity-seeded expansion beside lexical recall at one context budget.
//!
//! The example builds a synthetic workspace of services connected by `depends`
//! relations. Each service has one accepted, sourced claim that names only that
//! service. For every service it asks which stores the service's dependencies
//! use; the gold evidence is the sources of the claims about services one or two
//! hops away. Three conditions share every request budget: lexical recall
//! alone, lexical recall plus the expansion profile in record order, and plus
//! the profile in distance order. Over the packed candidates it reports two
//! measures separately:
//!
//! - evidence reached: gold sources among any packed candidate's ancestry
//!   roots, whatever the candidate's kind;
//! - citable evidence: gold sources among packed claim and excerpt candidates,
//!   the kinds a reader quotes and cites.
//!
//! The gap between the two is the contract recall lacks today: an expansion
//! row names the claims it reached but is not one of them.
//!
//! Run with `cargo run --release -p mneme-recall --example entity_seeded_comparison`.

/// Services in the synthetic workspace.
const SERVICES: u8 = 32;
/// Each service depends on the services at these multiplier and offset pairs.
const EDGES: [(u8, u8); 2] = [(7, 1), (11, 5)];
/// Hops the expansion follows; the gold evidence lies within them.
const HOPS: u8 = 2;
/// Budgets as `(items, context bytes)`: the request default and a tight one.
const BUDGETS: [(usize, usize); 2] = [(8, 4_096), (4, 1_024)];
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
const ACTOR: &str = "comparison";

type Error = Box<dyn std::error::Error>;

/// Record identity by kind tag and service index, distinct across kinds.
fn record(tag: u8, index: u8) -> mneme_core::RecordId {
    let mut bytes = [tag; 16];
    bytes[1] = index;
    mneme_core::RecordId::from_bytes(bytes)
}

fn revision(tag: u8, index: u8) -> mneme_core::RevisionId {
    let mut bytes = [tag; 16];
    bytes[1] = index;
    mneme_core::RevisionId::from_bytes(bytes)
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

fn claim_text(index: u8) -> String {
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

fn entity_payload(index: u8) -> mneme_core::Payload {
    mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("entity-type"),
            mneme_core::Value::symbol("service"),
        ),
        (
            mneme_core::Symbol::from("label"),
            mneme_core::Value::string(NAMES[usize::from(index)]),
        ),
        (
            mneme_core::Symbol::from("properties"),
            mneme_core::Value::dictionary([]),
        ),
    ])
}

fn relation_payload(from: u8, to: u8) -> mneme_core::Payload {
    mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("relation-type"),
            mneme_core::Value::symbol("depends"),
        ),
        (
            mneme_core::Symbol::from("from"),
            mneme_core::Reference::local(record(1, from), mneme_core::RecordKind::Entity)
                .to_value(),
        ),
        (
            mneme_core::Symbol::from("to"),
            mneme_core::Reference::local(record(1, to), mneme_core::RecordKind::Entity).to_value(),
        ),
        (
            mneme_core::Symbol::from("properties"),
            mneme_core::Value::dictionary([]),
        ),
    ])
}

fn commit(
    workspace: &mut mneme_store::Workspace,
    scope: &mneme_core::ScopeId,
    key: &str,
    records: Vec<mneme_store::RecordDraft>,
    source_blobs: Vec<mneme_store::SourceBlobDraft>,
) -> Result<(), Error> {
    workspace.commit(mneme_store::CommitCommand {
        base: workspace.current_revision()?,
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
    (record_id, revision_id): (mneme_core::RecordId, mneme_core::RevisionId),
    payload: mneme_core::Payload,
) -> mneme_store::RecordDraft {
    mneme_store::RecordDraft {
        schema_version: 1,
        kind,
        record_id,
        revision_id,
        predecessor: None,
        scope: scope.clone(),
        payload,
    }
}

/// Entities and their `depends` relations in one commit.
fn commit_graph(
    workspace: &mut mneme_store::Workspace,
    scope: &mneme_core::ScopeId,
) -> Result<(), Error> {
    let mut records =
        Vec::with_capacity(usize::from(SERVICES).saturating_mul(EDGES.len().saturating_add(1)));
    for index in 0..SERVICES {
        records.push(draft(
            scope,
            mneme_core::RecordKind::Entity,
            (record(1, index), revision(1, index)),
            entity_payload(index),
        ));
        for (edge, target) in dependencies(index).enumerate() {
            let tag = if edge == 0 { 2 } else { 3 };
            records.push(draft(
                scope,
                mneme_core::RecordKind::Relation,
                (record(tag, index), revision(tag, index)),
                relation_payload(index, target),
            ));
        }
    }
    commit(workspace, scope, "graph", records, Vec::new())
}

/// One sourced claim per service, proposed and then accepted.
fn commit_claims(
    workspace: &mut mneme_store::Workspace,
    scope: &mneme_core::ScopeId,
) -> Result<(), Error> {
    let services = usize::from(SERVICES);
    let mut sources = Vec::with_capacity(services);
    let mut blobs = Vec::with_capacity(services);
    let mut claims = Vec::with_capacity(services.saturating_mul(2));
    for index in 0..SERVICES {
        let text = claim_text(index);
        let path = format!("services/{}.txt", NAMES[usize::from(index)]);
        let (source, blob) = mneme_memory::build_source(
            record(4, index),
            revision(4, index),
            scope,
            mneme_memory::SourceOptions {
                bytes: text.as_bytes(),
                media_type: "text/plain",
                entity: Some(record(1, index)),
                path_hint: Some(&path),
            },
        )?;
        sources.push(source);
        blobs.push(blob);
        claims.extend(claim_records(scope, index, &text)?);
    }
    commit(workspace, scope, "sources", sources, blobs)?;
    commit(workspace, scope, "claims", claims, Vec::new())?;
    accept_claims(workspace, scope)
}

fn claim_records(
    scope: &mneme_core::ScopeId,
    index: u8,
    text: &str,
) -> Result<[mneme_store::RecordDraft; 2], Error> {
    let end = u64::try_from(text.len())?.saturating_sub(1);
    let evidence = mneme_memory::build_evidence(
        record(5, index),
        revision(5, index),
        scope,
        mneme_memory::EvidenceOptions {
            assertion: record(6, index),
            source: record(4, index),
            source_revision: revision(4, index),
            span: Some(mneme_core::SourceSpan::new(0, end)?),
            anchor: Some("store"),
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let assertion = mneme_memory::build_proposed_assertion(
        record(6, index),
        revision(6, index),
        scope,
        mneme_memory::ProposedAssertionOptions {
            subject: record(1, index),
            predicate: "store",
            value: mneme_core::Value::string(text),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: ACTOR,
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                record(5, index),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    Ok([evidence, assertion])
}

fn accept_claims(
    workspace: &mut mneme_store::Workspace,
    scope: &mneme_core::ScopeId,
) -> Result<(), Error> {
    let input_revision = workspace.current_revision()?;
    let mut records = Vec::with_capacity(usize::from(SERVICES).saturating_mul(2));
    for index in 0..SERVICES {
        let current = workspace
            .record_revisions(record(6, index))?
            .into_iter()
            .last()
            .ok_or("a proposed claim has no revision")?;
        records.push(mneme_memory::build_decision(
            record(7, index),
            revision(7, index),
            scope,
            mneme_memory::DecisionOptions {
                kind: mneme_memory::DecisionKind::Acceptance,
                target: record(6, index),
                actor: ACTOR,
                policy: "comparison-policy/v1",
                input_revision,
                outcome: "accepted",
                rationale: "synthetic comparison fixture",
                evidence: &[],
                related: &[],
            },
        ));
        records.push(mneme_memory::build_assertion_revision(
            &current,
            revision(8, index),
            mneme_core::Lifecycle::Accepted,
            mneme_core::Reference::local(record(7, index), mneme_core::RecordKind::Decision),
            None,
        ));
    }
    commit(workspace, scope, "acceptance", records, Vec::new())
}

/// Sources of the claims about services one to `HOPS` steps from `seed`.
fn gold(seed: u8) -> std::collections::BTreeSet<(mneme_core::RecordId, mneme_core::RevisionId)> {
    let mut seen = std::collections::BTreeSet::from([seed]);
    let mut frontier = vec![seed];
    for _ in 0..HOPS {
        let next = frontier
            .iter()
            .flat_map(|service| dependencies(*service))
            .filter(|service| seen.insert(*service))
            .collect::<Vec<_>>();
        frontier = next;
    }
    seen.remove(&seed);
    seen.into_iter()
        .map(|service| (record(4, service), revision(4, service)))
        .collect()
}

#[derive(Clone, Copy)]
enum Condition {
    Lexical,
    Expansion(mneme_recall::expansion::Order),
    GraphPpr,
}

impl Condition {
    fn name(self) -> &'static str {
        match self {
            Condition::Lexical => "lexical",
            Condition::Expansion(mneme_recall::expansion::Order::Record) => {
                "lexical + expansion (record order)"
            }
            Condition::Expansion(mneme_recall::expansion::Order::Distance) => {
                "lexical + expansion (distance order)"
            }
            Condition::GraphPpr => "lexical + graph-ppr",
        }
    }
}

struct Question {
    seed: u8,
    items: usize,
    context_bytes: usize,
}

#[derive(Default)]
struct Tally {
    reached: usize,
    citable: usize,
    gold: usize,
    packed_items: u64,
    packed_rows: usize,
    packed_bytes: u64,
    structured_work: u64,
    elapsed: std::time::Duration,
}

fn recall(
    workspace: &mut mneme_store::Workspace,
    scope: &mneme_core::ScopeId,
    condition: Condition,
    question: &Question,
) -> Result<mneme_recall::Response, Error> {
    let mut request = mneme_recall::Request::lexical(
        ACTOR,
        scope.clone(),
        workspace.current_revision()?,
        mneme_core::Timestamp::from_nanos(2_000),
        format!(
            "Which stores do the dependencies of the {} service use?",
            NAMES[usize::from(question.seed)]
        ),
    );
    request.max_items = question.items;
    request.max_context_bytes = question.context_bytes;
    if let Condition::Expansion(order) = condition {
        let profile = mneme_recall::expansion::Profile {
            seeds: std::collections::BTreeSet::from([record(1, question.seed)]),
            relation_types: std::collections::BTreeSet::from(["depends".to_owned()]),
            hops: HOPS,
            is_undirected: false,
            output: mneme_recall::expansion::Output::Claims,
            order,
            max_rows: 32,
            limits: mneme_datalog::Limits::default(),
        };
        request.modes.insert(mneme_recall::Mode::Structured);
        request.structured = Some(profile.structured_request()?);
    } else if matches!(condition, Condition::GraphPpr) {
        let mut config = mneme_recall::ppr::Config::new();
        config.seeds.insert(record(1, question.seed));
        config.relation_types.insert("depends".to_owned());
        request.modes.insert(mneme_recall::Mode::GraphPpr);
        request.graph_ppr = Some(config);
    }
    Ok(mneme_recall::Service::new(workspace).recall(request)?)
}

fn score(tally: &mut Tally, response: &mneme_recall::Response, seed: u8) {
    let gold = gold(seed);
    let roots = |is_citable: bool| {
        response
            .candidates
            .iter()
            .filter(|candidate| {
                !is_citable
                    || matches!(
                        candidate.content_kind,
                        mneme_recall::ContentKind::Claim | mneme_recall::ContentKind::SourceExcerpt
                    )
            })
            .flat_map(|candidate| candidate.ancestry_roots.iter().copied())
            .filter(|root| gold.contains(root))
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    };
    let rows = response
        .candidates
        .iter()
        .filter(|candidate| candidate.content_kind == mneme_recall::ContentKind::StructuredRow)
        .count();
    let work = response
        .modes
        .iter()
        .filter_map(|mode| mode.structured_work)
        .fold(0_u64, u64::saturating_add);
    tally.reached = tally.reached.saturating_add(roots(false));
    tally.citable = tally.citable.saturating_add(roots(true));
    tally.gold = tally.gold.saturating_add(gold.len());
    tally.packed_items = tally
        .packed_items
        .saturating_add(response.budget.items_used);
    tally.packed_rows = tally.packed_rows.saturating_add(rows);
    tally.packed_bytes = tally
        .packed_bytes
        .saturating_add(response.budget.text_bytes_used);
    tally.structured_work = tally.structured_work.saturating_add(work);
}

const fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        return 0.0;
    }
    numerator as f64 / denominator as f64
}

#[allow(unknown_lints, ambient_clock)] // timing is part of this example's report
fn main() -> Result<(), Error> {
    let temp = tempfile::tempdir()?;
    let mut workspace = mneme_store::Workspace::create(
        temp.path(),
        mneme_store::WorkspaceConfig {
            clock: Box::new(mneme_store::FixedClock::new(
                mneme_core::Timestamp::from_nanos(1_000),
            )),
            faults: Box::new(mneme_store::NoFaults),
        },
    )?;
    let scope = mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "services")?;
    commit_graph(&mut workspace, &scope)?;
    commit_claims(&mut workspace, &scope)?;
    let conditions = [
        Condition::Lexical,
        Condition::Expansion(mneme_recall::expansion::Order::Record),
        Condition::Expansion(mneme_recall::expansion::Order::Distance),
        Condition::GraphPpr,
    ];
    println!(
        "| Budget (items, bytes) | Condition | Evidence reached | Citable evidence | Mean packed items | Mean packed expansion rows | Mean packed bytes | Mean structured work | Mean time (µs) |"
    );
    println!("|---|---|---:|---:|---:|---:|---:|---:|---:|");
    for (items, context_bytes) in BUDGETS {
        for condition in conditions {
            let mut tally = Tally::default();
            for seed in 0..SERVICES {
                let question = Question {
                    seed,
                    items,
                    context_bytes,
                };
                let started = std::time::Instant::now();
                let response = recall(&mut workspace, &scope, condition, &question)?;
                tally.elapsed = tally.elapsed.saturating_add(started.elapsed());
                score(&mut tally, &response, seed);
            }
            let questions = u64::from(SERVICES);
            println!(
                "| ({items}, {context_bytes}) | {} | {:.3} ({}/{}) | {:.3} ({}/{}) | {:.2} | {:.2} | {:.0} | {:.0} | {:.0} |",
                condition.name(),
                ratio(tally.reached, tally.gold),
                tally.reached,
                tally.gold,
                ratio(tally.citable, tally.gold),
                tally.citable,
                tally.gold,
                tally.packed_items as f64 / questions as f64,
                tally.packed_rows as f64 / questions as f64,
                tally.packed_bytes as f64 / questions as f64,
                tally.structured_work as f64 / questions as f64,
                tally.elapsed.as_micros() as f64 / questions as f64,
            );
        }
    }
    Ok(())
}
