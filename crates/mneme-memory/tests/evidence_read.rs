//! Read-side evidence-memory tests over the durable workspace.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

// ---------------------------------------------------------------------------
// Read-side regressions: scope-aware, bounded belief and explanation views
// (EvidenceMemory-1/-3/-4/-6/-8/-9/-13/-14/-15/-18/-19).
// ---------------------------------------------------------------------------

struct ReadDecision<'a> {
    scope: &'a mneme_core::ScopeId,
    assertion: mneme_core::RecordId,
    lifecycle: mneme_core::Lifecycle,
    decision_id: mneme_core::RecordId,
    decision_revision: mneme_core::RevisionId,
    assertion_revision: mneme_core::RevisionId,
    kind: mneme_memory::DecisionKind,
    outcome: &'a str,
}

fn read_decide(workspace: &mut mneme_store::Workspace, key: &str, input: ReadDecision<'_>) {
    let ReadDecision {
        scope,
        assertion,
        lifecycle,
        decision_id,
        decision_revision,
        assertion_revision,
        kind,
        outcome,
    } = input;
    let base = workspace.current_revision().expect("base");
    let current = common::latest(workspace, assertion);
    let decision = mneme_memory::build_decision(
        decision_id,
        decision_revision,
        scope,
        mneme_memory::DecisionOptions {
            kind,
            target: assertion,
            actor: "test-author",
            policy: "test-policy/v1",
            input_revision: base,
            outcome,
            rationale: "explicit read-side test decision",
            evidence: &[],
            related: &[],
        },
    );
    let revision = mneme_memory::build_assertion_revision(
        &current,
        assertion_revision,
        lifecycle,
        mneme_core::Reference::local(decision_id, mneme_core::RecordKind::Decision),
        None,
    );
    let mut memory = common::engine(workspace);
    memory
        .commit(common::batch_in(
            scope,
            key,
            vec![decision, revision],
            Vec::new(),
        ))
        .expect("decision commit");
}

fn read_raw_commit(
    workspace: &mut mneme_store::Workspace,
    scope: &mneme_core::ScopeId,
    key: &str,
    records: Vec<mneme_store::RecordDraft>,
) {
    let base = workspace.current_revision().expect("base");
    workspace
        .commit(mneme_store::CommitCommand {
            base,
            actor: "test-author".to_owned(),
            scope: scope.clone(),
            idempotency_key: key.to_owned(),
            records,
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("raw commit");
}

fn read_belief_view(include_hypothetical: bool) -> mneme_memory::BeliefView {
    mneme_memory::BeliefView {
        scope: common::scope(),
        at: mneme_core::Timestamp::parse("2026-11-10T00:00:00Z").expect("today"),
        include_hypothetical,
        include_disputed: false,
    }
}

fn read_policy() -> mneme_memory::Policy {
    mneme_memory::Policy {
        max_explanation_nodes: 64,
        max_excerpt_bytes: 4096,
    }
}

fn read_id(tag: u8, index: u16) -> mneme_core::RecordId {
    let mut bytes = [tag; 16];
    bytes[14..].copy_from_slice(&index.to_be_bytes());
    mneme_core::RecordId::from_bytes(bytes)
}

fn read_rev(tag: u8, index: u16) -> mneme_core::RevisionId {
    let mut bytes = [tag; 16];
    bytes[14..].copy_from_slice(&index.to_be_bytes());
    mneme_core::RevisionId::from_bytes(bytes)
}

/// One read-side acceptance: its commit key and the identity bytes it records.
struct ReadAcceptance<'a> {
    key: &'a str,
    assertion: mneme_core::RecordId,
    decision_byte: u8,
    revision_byte: u8,
    assertion_revision_byte: u8,
}

fn read_accept(
    workspace: &mut mneme_store::Workspace,
    scope: &mneme_core::ScopeId,
    acceptance: ReadAcceptance<'_>,
) {
    let ReadAcceptance {
        key,
        assertion,
        decision_byte,
        revision_byte,
        assertion_revision_byte,
    } = acceptance;
    read_decide(
        workspace,
        key,
        ReadDecision {
            scope,
            assertion,
            lifecycle: mneme_core::Lifecycle::Accepted,
            decision_id: common::rid(decision_byte),
            decision_revision: common::rev(revision_byte),
            assertion_revision: common::rev(assertion_revision_byte),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
        },
    );
}

#[test]
fn read_side_hypothetical_beliefs_require_scope_access() {
    let (_temp, mut workspace) = common::setup();
    let project_claim = common::propose(
        &mut workspace,
        "project",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x10),
            evidence_revision: common::rev(0x11),
            assertion_id: common::rid(0x20),
            assertion_revision: common::rev(0x21),
            predicate: "project-claim",
            value: mneme_core::Value::string("yes"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            ancestry: &[],
            extraction: None,
        },
    );
    read_accept(
        &mut workspace,
        &common::scope(),
        ReadAcceptance {
            key: "project-accept",
            assertion: project_claim,
            decision_byte: 0x30,
            revision_byte: 0x31,
            assertion_revision_byte: 0x22,
        },
    );
    let other_team = common::hypothesis_scope("other-team-plan");
    let hidden = common::propose(
        &mut workspace,
        "hidden",
        &other_team,
        common::ProposalInput {
            evidence_id: common::rid(0x12),
            evidence_revision: common::rev(0x13),
            assertion_id: common::rid(0x24),
            assertion_revision: common::rev(0x25),
            predicate: "plan",
            value: mneme_core::Value::string("sell the company"),
            stance: mneme_memory::Stance::Hypothesis,
            valid_time: mneme_core::ValidTime::always(),
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            ancestry: &[],
            extraction: None,
        },
    );
    read_accept(
        &mut workspace,
        &other_team,
        ReadAcceptance {
            key: "hidden-accept",
            assertion: hidden,
            decision_byte: 0x32,
            revision_byte: 0x33,
            assertion_revision_byte: 0x26,
        },
    );

    // A session limited to the project scope cannot widen its plan view to
    // another team's hypothesis scope.
    let restricted = mneme_memory::Engine::new(
        &mut workspace,
        mneme_memory::Access::scopes([common::scope()]),
    );
    let beliefs = restricted
        .beliefs(&read_belief_view(true))
        .expect("restricted planner view");
    assert!(
        beliefs
            .iter()
            .any(|belief| belief.record.record_id == project_claim)
    );
    assert!(
        beliefs
            .iter()
            .all(|belief| belief.record.record_id != hidden)
    );
    drop(restricted);

    // The local operator authorized for the hypothesis scope does see it, but
    // only when the view explicitly asks for hypothetical claims.
    let operator = common::engine(&mut workspace);
    let beliefs = operator
        .beliefs(&read_belief_view(true))
        .expect("operator planner view");
    assert!(
        beliefs
            .iter()
            .any(|belief| belief.record.record_id == hidden)
    );
    let beliefs = operator
        .beliefs(&read_belief_view(false))
        .expect("operator operational view");
    assert!(
        beliefs
            .iter()
            .all(|belief| belief.record.record_id != hidden)
    );
}

#[test]
fn read_side_explanation_withholds_unreadable_source_content() {
    const SECRET: &[u8] = b"BIRCH ONLY: launch code 0000\n";
    let (_temp, mut workspace) = common::setup();
    let birch = common::project_scope("birch");
    let (birch_source, blob) = mneme_memory::build_source(
        common::rid(0x60),
        common::rev(0x61),
        &birch,
        mneme_memory::SourceOptions {
            bytes: SECRET,
            media_type: "text/plain",
            entity: None,
            path_hint: None,
        },
    )
    .expect("birch source");
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch_in(
                &birch,
                "birch-source",
                vec![birch_source],
                vec![blob],
            ))
            .expect("birch source commit");
    }
    let assertion_id = common::rid(0x20);
    let evidence = mneme_memory::build_evidence(
        common::rid(0x10),
        common::rev(0x11),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: common::rid(0x60),
            source_revision: common::rev(0x61),
            span: Some(mneme_core::SourceSpan::new(0, SECRET.len() as u64 - 1).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let claim = mneme_memory::build_proposed_assertion(
        assertion_id,
        common::rev(0x21),
        &common::scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "probe",
            value: mneme_core::Value::string("x"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "test-author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                common::rid(0x10),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch(
                "cedar-citation",
                vec![evidence, claim],
                Vec::new(),
            ))
            .expect("cross-scope citation");
    }
    read_accept(
        &mut workspace,
        &common::scope(),
        ReadAcceptance {
            key: "probe-accept",
            assertion: assertion_id,
            decision_byte: 0x30,
            revision_byte: 0x31,
            assertion_revision_byte: 0x22,
        },
    );

    let restricted = mneme_memory::Engine::new(
        &mut workspace,
        mneme_memory::Access::scopes([common::scope()]),
    );
    let explanation = restricted
        .explain(assertion_id, read_policy())
        .expect("restricted explain");
    assert_eq!(explanation.evidence.len(), 1);
    let item = &explanation.evidence[0];
    assert!(item.inaccessible);
    assert!(!item.eligible);
    assert!(item.excerpt.is_none());
    assert!(item.span_start.is_none());
    assert!(item.span_end.is_none());
    assert!(item.ancestry_roots.is_empty());
    assert_ne!(item.source, common::rid(0x60));
    assert_ne!(item.source_revision, common::rev(0x61));
    assert!(matches!(
        item.availability,
        mneme_memory::SourceAvailability::Unavailable { .. }
    ));
    assert!(!format!("{explanation:?}").contains("BIRCH ONLY"));
    drop(restricted);

    let operator = common::engine(&mut workspace);
    let explanation = operator
        .explain(assertion_id, read_policy())
        .expect("operator explain");
    let item = &explanation.evidence[0];
    assert_eq!(item.source, common::rid(0x60));
    assert_eq!(
        item.excerpt
            .as_ref()
            .map(|excerpt| excerpt.bytes.as_slice()),
        Some(SECRET)
    );

    // An oversized span recorded before validation cannot turn the read path
    // into a length oracle for the foreign source either.
    let probe = common::rid(0x22);
    let oversized = mneme_memory::build_evidence(
        common::rid(0x12),
        common::rev(0x13),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: probe,
            source: common::rid(0x60),
            source_revision: common::rev(0x61),
            span: Some(mneme_core::SourceSpan::new(0, 100_000).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let probe_claim = mneme_memory::build_proposed_assertion(
        probe,
        common::rev(0x23),
        &common::scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "probe",
            value: mneme_core::Value::string("y"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "test-author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                common::rid(0x12),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    read_raw_commit(
        &mut workspace,
        &common::scope(),
        "oversized-probe",
        vec![oversized, probe_claim],
    );
    let restricted = mneme_memory::Engine::new(
        &mut workspace,
        mneme_memory::Access::scopes([common::scope()]),
    );
    let explanation = restricted
        .explain(probe, read_policy())
        .expect("probe explain");
    assert!(explanation.evidence[0].inaccessible);
    assert!(explanation.evidence[0].span_start.is_none());
    assert!(explanation.evidence[0].span_end.is_none());
}

#[test]
fn read_side_stale_acceptance_does_not_back_a_belief() {
    let (_temp, mut workspace) = common::setup();
    let assertion_id = common::propose(
        &mut workspace,
        "proposal",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x10),
            evidence_revision: common::rev(0x11),
            assertion_id: common::rid(0x20),
            assertion_revision: common::rev(0x21),
            predicate: "storage-engine",
            value: mneme_core::Value::string("SQLite"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            ancestry: &[],
            extraction: None,
        },
    );
    read_accept(
        &mut workspace,
        &common::scope(),
        ReadAcceptance {
            key: "accept",
            assertion: assertion_id,
            decision_byte: 0x30,
            revision_byte: 0x31,
            assertion_revision_byte: 0x22,
        },
    );
    read_decide(
        &mut workspace,
        "retract",
        ReadDecision {
            scope: &common::scope(),
            assertion: assertion_id,
            lifecycle: mneme_core::Lifecycle::Retracted,
            decision_id: common::rid(0x32),
            decision_revision: common::rev(0x33),
            assertion_revision: common::rev(0x23),
            kind: mneme_memory::DecisionKind::Retraction,
            outcome: "retracted",
        },
    );
    // An older build could record this revision: the retracted assertion
    // re-accepted with the original acceptance decision.
    let current = common::latest(&workspace, assertion_id);
    let resurrect = mneme_memory::build_assertion_revision(
        &current,
        common::rev(0x24),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(common::rid(0x30), mneme_core::RecordKind::Decision),
        None,
    );
    read_raw_commit(
        &mut workspace,
        &common::scope(),
        "resurrect",
        vec![resurrect],
    );

    let memory = common::engine(&mut workspace);
    let view = memory.view().expect("view");
    let assertion = view.assertion(assertion_id).expect("assertion");
    assert_eq!(assertion.lifecycle, mneme_core::Lifecycle::Accepted);
    assert!(!view.lifecycle_decision_valid(&assertion).expect("decision"));
    assert!(!view.assertion_eligible(assertion_id));
    assert!(
        memory
            .beliefs(&read_belief_view(false))
            .expect("beliefs")
            .iter()
            .all(|belief| belief.record.record_id != assertion_id)
    );
}

// ---------------------------------------------------------------------------
// Conflict views evaluate valid time at the requested instant
// (EvidenceMemory-21).
// ---------------------------------------------------------------------------

/// One accepted affirm claim about the shared predicate over a closed window.
struct ReadWindowClaim<'a> {
    key: &'a str,
    evidence_byte: u8,
    evidence_revision_byte: u8,
    assertion_byte: u8,
    proposal_revision_byte: u8,
    accepted_revision_byte: u8,
    decision_byte: u8,
    decision_revision_byte: u8,
    value: &'a str,
    start: &'a str,
    end: &'a str,
}

fn read_window_claim(
    workspace: &mut mneme_store::Workspace,
    claim: ReadWindowClaim<'_>,
) -> mneme_core::RecordId {
    let ReadWindowClaim {
        key,
        evidence_byte,
        evidence_revision_byte,
        assertion_byte,
        proposal_revision_byte,
        accepted_revision_byte,
        decision_byte,
        decision_revision_byte,
        value,
        start,
        end,
    } = claim;
    let valid_time = mneme_core::ValidTime::between(
        mneme_core::Timestamp::parse(start).expect("start"),
        mneme_core::Timestamp::parse(end).expect("end"),
    )
    .expect("interval");
    let assertion = common::propose(
        workspace,
        key,
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(evidence_byte),
            evidence_revision: common::rev(evidence_revision_byte),
            assertion_id: common::rid(assertion_byte),
            assertion_revision: common::rev(proposal_revision_byte),
            predicate: "storage-engine",
            value: mneme_core::Value::string(value),
            stance: mneme_memory::Stance::Affirm,
            valid_time,
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            ancestry: &[],
            extraction: None,
        },
    );
    let accept_key = format!("{key}-accept");
    read_accept(
        workspace,
        &common::scope(),
        ReadAcceptance {
            key: accept_key.as_str(),
            assertion,
            decision_byte,
            revision_byte: decision_revision_byte,
            assertion_revision_byte: accepted_revision_byte,
        },
    );
    assertion
}

/// The three accepted claims of `read_side_conflicts_honour_the_view_instant`.
struct ReadInstantClaims {
    early: mneme_core::RecordId,
    later: mneme_core::RecordId,
    overlap: mneme_core::RecordId,
}

fn read_instant_claims(workspace: &mut mneme_store::Workspace) -> ReadInstantClaims {
    let early = read_window_claim(
        workspace,
        ReadWindowClaim {
            key: "early",
            evidence_byte: 0x10,
            evidence_revision_byte: 0x11,
            assertion_byte: 0x20,
            proposal_revision_byte: 0x21,
            accepted_revision_byte: 0x22,
            decision_byte: 0x30,
            decision_revision_byte: 0x31,
            value: "SQLite",
            start: "2020-01-01T00:00:00Z",
            end: "2021-01-01T00:00:00Z",
        },
    );
    let later = read_window_claim(
        workspace,
        ReadWindowClaim {
            key: "later",
            evidence_byte: 0x12,
            evidence_revision_byte: 0x13,
            assertion_byte: 0x24,
            proposal_revision_byte: 0x25,
            accepted_revision_byte: 0x26,
            decision_byte: 0x32,
            decision_revision_byte: 0x33,
            value: "LMDB",
            start: "2022-01-01T00:00:00Z",
            end: "2023-01-01T00:00:00Z",
        },
    );
    let overlap = read_window_claim(
        workspace,
        ReadWindowClaim {
            key: "overlap",
            evidence_byte: 0x14,
            evidence_revision_byte: 0x15,
            assertion_byte: 0x28,
            proposal_revision_byte: 0x29,
            accepted_revision_byte: 0x2a,
            decision_byte: 0x34,
            decision_revision_byte: 0x35,
            value: "RocksDB",
            start: "2020-01-01T00:00:00Z",
            end: "2020-07-01T00:00:00Z",
        },
    );
    ReadInstantClaims {
        early,
        later,
        overlap,
    }
}

fn read_instant_view(at: &str) -> mneme_memory::BeliefView {
    mneme_memory::BeliefView {
        scope: common::scope(),
        at: mneme_core::Timestamp::parse(at).expect("at"),
        include_hypothetical: false,
        include_disputed: true,
    }
}

#[test]
fn read_side_conflicts_honour_the_view_instant() {
    let (_temp, mut workspace) = common::setup();
    let claims = read_instant_claims(&mut workspace);
    let memory = common::engine(&mut workspace);

    // `overlap` has ended before 2020-09-01 and `early` has not, so only one
    // claim applies and there is nothing to disagree with.
    assert!(
        memory
            .conflicts(&read_instant_view("2020-09-01T00:00:00Z"))
            .expect("early alone")
            .is_empty()
    );
    // `early` has expired by 2022-06-01 and `later` is not yet valid before
    // 2022, so at 2022-06-01 `later` stands alone.
    assert!(
        memory
            .conflicts(&read_instant_view("2022-06-01T00:00:00Z"))
            .expect("later alone")
            .is_empty()
    );
    assert!(
        memory
            .conflicts(&read_instant_view("2024-06-01T00:00:00Z"))
            .expect("after every window")
            .is_empty()
    );

    // One instant both windows cover: exactly the two claims that apply are a
    // conflict, and `later` takes no part because it is not yet valid.
    let shared = read_instant_view("2020-03-01T00:00:00Z");
    let conflicts = memory.conflicts(&shared).expect("shared instant");
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].predicate, "storage-engine");
    let participants: Vec<mneme_core::RecordId> = conflicts[0]
        .assertions
        .iter()
        .map(|assertion| assertion.record.record_id)
        .collect();
    assert_eq!(participants.len(), 2);
    assert!(participants.contains(&claims.early));
    assert!(participants.contains(&claims.overlap));
    assert!(!participants.contains(&claims.later));
    let beliefs = memory.beliefs(&shared).expect("shared beliefs");
    assert_eq!(beliefs.len(), 2);
}

#[test]
fn read_side_conflict_windows_include_both_bounds() {
    let (_temp, mut workspace) = common::setup();
    let claims = read_instant_claims(&mut workspace);
    let memory = common::engine(&mut workspace);

    // `early` and `overlap` both start at 2020-01-01, so a start bound that is
    // inclusive still reports the pair as a conflict at the exact start.
    let at_start = read_instant_view("2020-01-01T00:00:00Z");
    let conflicts = memory.conflicts(&at_start).expect("window start");
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].assertions.len(), 2);
    assert_eq!(memory.beliefs(&at_start).expect("start beliefs").len(), 2);

    // `early` ends at 2021-01-01 and `overlap` ended in 2020, so an inclusive
    // end still applies `early` there and leaves it without a partner.
    let at_end = read_instant_view("2021-01-01T00:00:00Z");
    assert!(memory.conflicts(&at_end).expect("window end").is_empty());
    let beliefs = memory.beliefs(&at_end).expect("end beliefs");
    assert_eq!(beliefs.len(), 1);
    assert_eq!(beliefs[0].record.record_id, claims.early);

    // One second past its end, `early` answers nothing at all.
    let after_end = read_instant_view("2021-01-01T00:00:01Z");
    assert!(
        memory
            .conflicts(&after_end)
            .expect("past window end")
            .is_empty()
    );
    assert!(
        memory
            .beliefs(&after_end)
            .expect("past end beliefs")
            .is_empty()
    );
}

/// A view over the workspace snapshot with one record omitted, as retention
/// leaves a citation whose ancestor was suppressed.
fn read_view_without(
    workspace: &mneme_store::Workspace,
    omitted: mneme_core::RecordId,
) -> mneme_memory::View {
    let snapshot = workspace.snapshot().expect("snapshot");
    let records: Vec<mneme_core::RecordEnvelope> = snapshot
        .records
        .into_iter()
        .filter(|record| record.record_id != omitted)
        .collect();
    let mut index = mneme_core::SnapshotIndex::new();
    for record in &records {
        index.insert(record.record_id, record.kind, record.revision_id);
    }
    let history: std::collections::BTreeMap<
        (mneme_core::RecordId, mneme_core::RevisionId),
        mneme_core::RecordEnvelope,
    > = records
        .iter()
        .flat_map(|record| {
            workspace
                .record_revisions(record.record_id)
                .expect("revisions")
        })
        .map(|revision| ((revision.record_id, revision.revision_id), revision))
        .collect();
    let sequences = workspace.revision_sequences().expect("sequences");
    let suppressions = workspace.active_suppressions().expect("suppressions");
    mneme_memory::View::with_retention(
        mneme_store::Snapshot {
            revision: snapshot.revision,
            sequence: snapshot.sequence,
            parent: snapshot.parent,
            manifest_digest: snapshot.manifest_digest,
            eligibility_generation: snapshot.eligibility_generation,
            records,
            index,
        },
        workspace.root(),
        history,
        sequences,
        suppressions,
    )
    .with_access(mneme_memory::Access::Operator)
}

#[test]
fn read_side_declared_ancestry_roots_follow_the_ancestors() {
    let (_temp, mut workspace) = common::setup();
    let summary = common::rid(0x62);
    let summary_revision = common::rev(0x63);
    let (source, blob) = mneme_memory::build_source(
        summary,
        summary_revision,
        &common::scope(),
        mneme_memory::SourceOptions {
            bytes: b"= Summary\n\ncopied summary source\n",
            media_type: "text/asciidoc",
            entity: Some(mneme_core::fixtures::entity_id()),
            path_hint: Some("summary.adoc"),
        },
    )
    .expect("summary source");
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch("summary-source", vec![source], vec![blob]))
            .expect("summary source commit");
    }
    let grounded = common::rid(0x20);
    let origin_evidence = mneme_memory::build_evidence(
        common::rid(0x10),
        common::rev(0x11),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: grounded,
            source: common::SOURCE_ID,
            source_revision: common::SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let first_summary = mneme_memory::build_evidence(
        common::rid(0x12),
        common::rev(0x13),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: grounded,
            source: summary,
            source_revision: summary_revision,
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[mneme_core::Reference::local(
                common::rid(0x10),
                mneme_core::RecordKind::Evidence,
            )],
        },
    );
    let second_summary = mneme_memory::build_evidence(
        common::rid(0x14),
        common::rev(0x15),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: grounded,
            source: summary,
            source_revision: summary_revision,
            span: Some(mneme_core::SourceSpan::new(4, 7).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[mneme_core::Reference::local(
                common::rid(0x10),
                mneme_core::RecordKind::Evidence,
            )],
        },
    );
    let grounded_claim = mneme_memory::build_proposed_assertion(
        grounded,
        common::rev(0x21),
        &common::scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "corroborated",
            value: mneme_core::Value::string("yes"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "test-author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[
                mneme_core::Reference::local(common::rid(0x10), mneme_core::RecordKind::Evidence),
                mneme_core::Reference::local(common::rid(0x12), mneme_core::RecordKind::Evidence),
                mneme_core::Reference::local(common::rid(0x14), mneme_core::RecordKind::Evidence),
            ],
            extraction: None,
            superseded_by: None,
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch(
                "summaries",
                vec![
                    origin_evidence,
                    first_summary,
                    second_summary,
                    grounded_claim,
                ],
                Vec::new(),
            ))
            .expect("summary citations");
    }

    let memory = common::engine(&mut workspace);
    let view = memory.view().expect("view");
    // Summaries that declare their origin are not independent observations
    // and root only at the origin.
    let corroboration = view.corroboration(grounded).expect("corroboration");
    assert_eq!(corroboration.independent_supports, 1);
    assert!(corroboration.shared_ancestry);
    assert_eq!(
        corroboration.roots,
        std::collections::BTreeSet::from([(common::SOURCE_ID, common::SOURCE_REV)])
    );
    let explanation = view.explain(grounded, read_policy()).expect("explain");
    assert_eq!(
        explanation.corroboration.roots,
        std::collections::BTreeSet::from([(common::SOURCE_ID, common::SOURCE_REV)])
    );
    let origin_roots = std::collections::BTreeSet::from([(common::SOURCE_ID, common::SOURCE_REV)]);
    assert!(
        explanation
            .evidence
            .iter()
            .all(|evidence| evidence.ancestry_roots == origin_roots)
    );
    assert!(!explanation.truncated);

    drop(memory);

    // Revising the declarations away makes the same citations root at their
    // own sources, so the result is sensitive to the ancestry being followed.
    let mut first_plain = mneme_memory::build_evidence(
        common::rid(0x12),
        common::rev(0x1c),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: grounded,
            source: summary,
            source_revision: summary_revision,
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    first_plain.predecessor = Some(common::rev(0x13));
    let mut second_plain = mneme_memory::build_evidence(
        common::rid(0x14),
        common::rev(0x1d),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: grounded,
            source: summary,
            source_revision: summary_revision,
            span: Some(mneme_core::SourceSpan::new(4, 7).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    second_plain.predecessor = Some(common::rev(0x15));
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch(
                "plain-summaries",
                vec![first_plain, second_plain],
                Vec::new(),
            ))
            .expect("plain citations");
    }
    let memory = common::engine(&mut workspace);
    let view = memory.view().expect("view");
    let plain_corroboration = view.corroboration(grounded).expect("plain corroboration");
    assert_eq!(plain_corroboration.independent_supports, 2);
    assert!(!plain_corroboration.shared_ancestry);
    assert_eq!(
        plain_corroboration.roots,
        std::collections::BTreeSet::from([
            (common::SOURCE_ID, common::SOURCE_REV),
            (summary, summary_revision),
        ])
    );
    drop(memory);

    // An ancestry declaration that no longer resolves is neither independent
    // nor a fallback to the cited source, and the explanation flags it.
    let dangling = common::rid(0x28);
    let dangling_evidence = mneme_memory::build_evidence(
        common::rid(0x1a),
        common::rev(0x1b),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: dangling,
            source: summary,
            source_revision: summary_revision,
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[mneme_core::Reference::local(
                common::rid(0x99),
                mneme_core::RecordKind::Episode,
            )],
        },
    );
    let dangling_claim = mneme_memory::build_proposed_assertion(
        dangling,
        common::rev(0x29),
        &common::scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "dangling",
            value: mneme_core::Value::string("yes"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "test-author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                common::rid(0x1a),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    let episode = mneme_memory::build_episode(
        common::rid(0x99),
        common::rev(0x9a),
        &common::scope(),
        mneme_memory::EpisodeOptions {
            actor: "test-author",
            episode_type: "observation",
            occurred: mneme_core::ValidTime::always(),
            summary: "suppressed provenance",
            source: None,
            related: &[],
        },
    );
    read_raw_commit(
        &mut workspace,
        &common::scope(),
        "dangling-ancestry",
        vec![episode, dangling_evidence, dangling_claim],
    );
    let view = read_view_without(&workspace, common::rid(0x99));
    let corroboration = view.corroboration(dangling).expect("corroboration");
    assert_eq!(corroboration.independent_supports, 0);
    assert!(!corroboration.shared_ancestry);
    let explanation = view.explain(dangling, read_policy()).expect("explain");
    assert!(explanation.truncated);
    assert!(!explanation.evidence[0].eligible);
    assert!(explanation.evidence[0].ancestry_roots.is_empty());
    assert!(!explanation.evidence[0].inaccessible);
}

#[test]
fn read_side_deep_derivation_chain_is_bounded() {
    const LEVELS: u16 = 24;
    let (_temp, mut workspace) = common::setup();
    let proposals: Vec<mneme_store::RecordDraft> = (0..=LEVELS)
        .map(|index| {
            mneme_memory::build_proposed_assertion(
                read_id(0xa0, index),
                read_rev(0xa1, index),
                &common::scope(),
                mneme_memory::ProposedAssertionOptions {
                    subject: mneme_core::fixtures::entity_id(),
                    predicate: "level",
                    value: mneme_core::Value::string("x"),
                    stance: mneme_memory::Stance::Affirm,
                    origin: mneme_core::Origin::AuthoredStatement,
                    asserted_by: "test-author",
                    valid_time: mneme_core::ValidTime::always(),
                    evidence: &[],
                    extraction: None,
                    superseded_by: None,
                },
            )
        })
        .collect();
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch("levels", proposals, Vec::new()))
            .expect("proposals");
    }
    let base = workspace.current_revision().expect("base");
    // Two records per accepted level: the decision and the accepted revision.
    let mut accepts = Vec::with_capacity(2 * (usize::from(LEVELS) + 1));
    for index in 0..=LEVELS {
        let current = common::latest(&workspace, read_id(0xa0, index));
        accepts.push(mneme_memory::build_decision(
            read_id(0xc0, index),
            read_rev(0xc1, index),
            &common::scope(),
            mneme_memory::DecisionOptions {
                kind: mneme_memory::DecisionKind::Acceptance,
                target: read_id(0xa0, index),
                actor: "test-author",
                policy: "test-policy/v1",
                input_revision: base,
                outcome: "accepted",
                rationale: "level acceptance",
                evidence: &[],
                related: &[],
            },
        ));
        accepts.push(mneme_memory::build_assertion_revision(
            &current,
            read_rev(0xa2, index),
            mneme_core::Lifecycle::Accepted,
            mneme_core::Reference::local(read_id(0xc0, index), mneme_core::RecordKind::Decision),
            None,
        ));
    }
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch("level-accepts", accepts, Vec::new()))
            .expect("acceptances");
    }
    let base = workspace.current_revision().expect("base");
    // Each level above the root has two alternative derivations.
    let mut derivations = Vec::with_capacity(2 * usize::from(LEVELS));
    for index in 1..=LEVELS {
        for alternative in 0..2_u8 {
            derivations.push(mneme_memory::build_derivation(
                read_id(0xd0 + alternative, index),
                read_rev(0xd2 + alternative, index),
                &common::scope(),
                mneme_memory::DerivationOptions {
                    conclusion: read_id(0xa0, index),
                    premises: &[mneme_core::Reference::local(
                        read_id(0xa0, index - 1),
                        mneme_core::RecordKind::Assertion,
                    )],
                    rule_id: "level-rule",
                    rule_version: 1,
                    evaluation_revision: base,
                    completeness: "complete",
                },
            ));
        }
    }
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch("levels-derivations", derivations, Vec::new()))
            .expect("derivations");
    }
    let memory = common::engine(&mut workspace);
    let started = std::time::Instant::now();
    let explanation = memory
        .explain(
            read_id(0xa0, LEVELS),
            mneme_memory::Policy {
                max_explanation_nodes: 4096,
                max_excerpt_bytes: 4096,
            },
        )
        .expect("deep explanation");
    let elapsed = started.elapsed();
    assert!(!explanation.truncated, "the walk must fit its budget");
    assert!(
        explanation.visited_nodes <= 256,
        "memoized walk visited {} nodes",
        explanation.visited_nodes
    );
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "walk took {elapsed:?}"
    );
    assert_eq!(explanation.derivations.len(), 2);
}

#[test]
fn read_side_partial_derivation_does_not_ground_its_conclusion() {
    let (_temp, mut workspace) = common::setup();
    let premise = common::propose(
        &mut workspace,
        "premise",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x10),
            evidence_revision: common::rev(0x11),
            assertion_id: common::rid(0x20),
            assertion_revision: common::rev(0x21),
            predicate: "premise",
            value: mneme_core::Value::string("yes"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            ancestry: &[],
            extraction: None,
        },
    );
    read_accept(
        &mut workspace,
        &common::scope(),
        ReadAcceptance {
            key: "premise-accept",
            assertion: premise,
            decision_byte: 0x30,
            revision_byte: 0x31,
            assertion_revision_byte: 0x22,
        },
    );
    let conclusion = common::propose_bare(
        &mut workspace,
        "conclusion",
        &common::scope(),
        common::BareProposalInput {
            assertion_id: common::rid(0x24),
            assertion_revision: common::rev(0x25),
            predicate: "conclusion",
            value: mneme_core::Value::string("derived"),
        },
    );
    read_accept(
        &mut workspace,
        &common::scope(),
        ReadAcceptance {
            key: "conclusion-accept",
            assertion: conclusion,
            decision_byte: 0x32,
            revision_byte: 0x33,
            assertion_revision_byte: 0x26,
        },
    );
    // A writer declared this justification partial; the read side must not
    // turn it into support for an accepted conclusion.
    let base = workspace.current_revision().expect("base");
    let partial = mneme_memory::build_derivation(
        common::rid(0x40),
        common::rev(0x41),
        &common::scope(),
        mneme_memory::DerivationOptions {
            conclusion,
            premises: &[mneme_core::Reference::local(
                premise,
                mneme_core::RecordKind::Assertion,
            )],
            rule_id: "partial-rule",
            rule_version: 1,
            evaluation_revision: base,
            completeness: "partial",
        },
    );
    read_raw_commit(&mut workspace, &common::scope(), "partial", vec![partial]);

    let memory = common::engine(&mut workspace);
    let view = memory.view().expect("view");
    assert!(!view.assertion_eligible(conclusion));
    let alternatives = view
        .derivation_alternatives(conclusion)
        .expect("alternatives");
    assert_eq!(alternatives.len(), 1);
    assert!(!alternatives[0].eligible);
    assert!(
        alternatives[0]
            .reasons
            .iter()
            .any(|reason| reason.contains("partial"))
    );
    assert!(
        memory
            .beliefs(&read_belief_view(false))
            .expect("beliefs")
            .iter()
            .all(|belief| belief.record.record_id != conclusion)
    );
}

#[test]
fn read_side_retracted_ancestor_withdraws_derived_support() {
    let (_temp, mut workspace) = common::setup();
    let premise = common::propose(
        &mut workspace,
        "premise",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x10),
            evidence_revision: common::rev(0x11),
            assertion_id: common::rid(0x20),
            assertion_revision: common::rev(0x21),
            predicate: "premise",
            value: mneme_core::Value::string("yes"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            ancestry: &[],
            extraction: None,
        },
    );
    read_accept(
        &mut workspace,
        &common::scope(),
        ReadAcceptance {
            key: "premise-accept",
            assertion: premise,
            decision_byte: 0x30,
            revision_byte: 0x31,
            assertion_revision_byte: 0x22,
        },
    );
    let summary = common::propose(
        &mut workspace,
        "summary",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x12),
            evidence_revision: common::rev(0x13),
            assertion_id: common::rid(0x24),
            assertion_revision: common::rev(0x25),
            predicate: "summary",
            value: mneme_core::Value::string("release-ready"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: Some(mneme_core::SourceSpan::new(4, 7).expect("span")),
            ancestry: &[mneme_core::Reference::local(
                premise,
                mneme_core::RecordKind::Assertion,
            )],
            extraction: None,
        },
    );
    read_accept(
        &mut workspace,
        &common::scope(),
        ReadAcceptance {
            key: "summary-accept",
            assertion: summary,
            decision_byte: 0x32,
            revision_byte: 0x33,
            assertion_revision_byte: 0x26,
        },
    );
    {
        let memory = common::engine(&mut workspace);
        let view = memory.view().expect("view");
        assert!(view.assertion_eligible(summary));
        assert_eq!(
            view.corroboration(summary)
                .expect("corroboration")
                .independent_supports,
            1
        );
    }
    read_decide(
        &mut workspace,
        "retract-premise",
        ReadDecision {
            scope: &common::scope(),
            assertion: premise,
            lifecycle: mneme_core::Lifecycle::Retracted,
            decision_id: common::rid(0x34),
            decision_revision: common::rev(0x35),
            assertion_revision: common::rev(0x23),
            kind: mneme_memory::DecisionKind::Retraction,
            outcome: "retracted",
        },
    );
    let memory = common::engine(&mut workspace);
    let view = memory.view().expect("view");
    assert!(!view.assertion_eligible(summary));
    assert_eq!(
        view.corroboration(summary)
            .expect("corroboration")
            .independent_supports,
        0
    );
    let explanation = memory.explain(summary, read_policy()).expect("explain");
    assert!(!explanation.evidence[0].eligible);
    assert!(
        memory
            .beliefs(&read_belief_view(false))
            .expect("beliefs")
            .iter()
            .all(|belief| belief.record.record_id != summary)
    );
}

#[test]
fn read_side_truncated_explanation_withholds_unestablished_corroboration() {
    let (_temp, mut workspace) = common::setup();
    let second = common::rid(0x62);
    let second_revision = common::rev(0x63);
    let (source, blob) = mneme_memory::build_source(
        second,
        second_revision,
        &common::scope(),
        mneme_memory::SourceOptions {
            bytes: b"= B\n\nsecond source\n",
            media_type: "text/asciidoc",
            entity: Some(mneme_core::fixtures::entity_id()),
            path_hint: Some("second.adoc"),
        },
    )
    .expect("second source");
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch("second-source", vec![source], vec![blob]))
            .expect("second source commit");
    }
    let assertion_id = common::rid(0x20);
    let first_evidence = mneme_memory::build_evidence(
        common::rid(0x10),
        common::rev(0x11),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: common::SOURCE_ID,
            source_revision: common::SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let second_evidence = mneme_memory::build_evidence(
        common::rid(0x12),
        common::rev(0x13),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: second,
            source_revision: second_revision,
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let claim = mneme_memory::build_proposed_assertion(
        assertion_id,
        common::rev(0x21),
        &common::scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "corroborated",
            value: mneme_core::Value::string("yes"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "test-author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[
                mneme_core::Reference::local(common::rid(0x10), mneme_core::RecordKind::Evidence),
                mneme_core::Reference::local(common::rid(0x12), mneme_core::RecordKind::Evidence),
            ],
            extraction: None,
            superseded_by: None,
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch(
                "corroborated",
                vec![first_evidence, second_evidence, claim],
                Vec::new(),
            ))
            .expect("corroborated claim");
    }
    read_accept(
        &mut workspace,
        &common::scope(),
        ReadAcceptance {
            key: "accept",
            assertion: assertion_id,
            decision_byte: 0x30,
            revision_byte: 0x31,
            assertion_revision_byte: 0x22,
        },
    );

    let memory = common::engine(&mut workspace);
    let full = memory
        .explain(assertion_id, read_policy())
        .expect("full explanation");
    assert!(!full.truncated);
    assert_eq!(full.corroboration.independent_supports, 2);
    assert!(!full.corroboration.shared_ancestry);

    let bounded = memory
        .explain(
            assertion_id,
            mneme_memory::Policy {
                max_explanation_nodes: 2,
                max_excerpt_bytes: 4096,
            },
        )
        .expect("bounded explanation");
    assert!(bounded.truncated);
    assert_eq!(
        bounded.evidence.len(),
        1,
        "the budget bounds the evidence list"
    );
    assert!(!bounded.corroboration.shared_ancestry);
    assert_eq!(
        bounded.corroboration.independent_supports, 2,
        "corroboration comes from the full support set, so it is established"
    );

    let excerpted = memory
        .explain(
            assertion_id,
            mneme_memory::Policy {
                max_explanation_nodes: 64,
                max_excerpt_bytes: 2,
            },
        )
        .expect("bounded excerpt");
    let excerpt = excerpted.evidence[0]
        .excerpt
        .as_ref()
        .expect("retained excerpt");
    assert!(excerpt.truncated);
    assert!(excerpt.bytes.len() <= 2);
}

#[test]
fn read_side_duplicate_sources_and_provenance_are_not_independent() {
    let (_temp, mut workspace) = common::setup();
    let duplicate = common::rid(0x62);
    let duplicate_revision = common::rev(0x63);
    let (source, blob) = mneme_memory::build_source(
        duplicate,
        duplicate_revision,
        &common::scope(),
        mneme_memory::SourceOptions {
            bytes: mneme_core::fixtures::SOURCE_TEXT.as_bytes(),
            media_type: "text/asciidoc",
            entity: Some(mneme_core::fixtures::entity_id()),
            path_hint: Some("copy.adoc"),
        },
    )
    .expect("duplicate source");
    let episode = mneme_memory::build_episode(
        common::rid(0x40),
        common::rev(0x41),
        &common::scope(),
        mneme_memory::EpisodeOptions {
            actor: "test-author",
            episode_type: "observation",
            occurred: mneme_core::ValidTime::always(),
            summary: "unrelated provenance",
            source: None,
            related: &[],
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch(
                "duplicate-source",
                vec![source, episode],
                vec![blob],
            ))
            .expect("duplicate source commit");
    }
    let assertion_id = common::rid(0x20);
    let first = mneme_memory::build_evidence(
        common::rid(0x10),
        common::rev(0x11),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: common::SOURCE_ID,
            source_revision: common::SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let copy = mneme_memory::build_evidence(
        common::rid(0x12),
        common::rev(0x13),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: duplicate,
            source_revision: duplicate_revision,
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let self_declared = mneme_memory::build_evidence(
        common::rid(0x14),
        common::rev(0x15),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: common::SOURCE_ID,
            source_revision: common::SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(8, 12).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[mneme_core::Reference::local(
                common::rid(0x40),
                mneme_core::RecordKind::Episode,
            )],
        },
    );
    let claim = mneme_memory::build_proposed_assertion(
        assertion_id,
        common::rev(0x21),
        &common::scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "corroborated",
            value: mneme_core::Value::string("yes"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "test-author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[
                mneme_core::Reference::local(common::rid(0x10), mneme_core::RecordKind::Evidence),
                mneme_core::Reference::local(common::rid(0x12), mneme_core::RecordKind::Evidence),
                mneme_core::Reference::local(common::rid(0x14), mneme_core::RecordKind::Evidence),
            ],
            extraction: None,
            superseded_by: None,
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch(
                "duplicate-corroboration",
                vec![first, copy, self_declared, claim],
                Vec::new(),
            ))
            .expect("duplicate corroboration claim");
    }
    read_accept(
        &mut workspace,
        &common::scope(),
        ReadAcceptance {
            key: "accept",
            assertion: assertion_id,
            decision_byte: 0x30,
            revision_byte: 0x31,
            assertion_revision_byte: 0x22,
        },
    );
    let memory = common::engine(&mut workspace);
    let corroboration = memory
        .view()
        .expect("view")
        .corroboration(assertion_id)
        .expect("corroboration");
    assert_eq!(corroboration.independent_supports, 1);
    assert!(corroboration.shared_ancestry);
}

#[test]
fn read_side_pruned_citation_stays_pruned_after_reimport() {
    let (temp, mut workspace) = common::setup();
    let assertion_id = common::propose(
        &mut workspace,
        "proposal",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x10),
            evidence_revision: common::rev(0x11),
            assertion_id: common::rid(0x20),
            assertion_revision: common::rev(0x21),
            predicate: "storage-engine",
            value: mneme_core::Value::string("SQLite"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            ancestry: &[],
            extraction: None,
        },
    );
    read_accept(
        &mut workspace,
        &common::scope(),
        ReadAcceptance {
            key: "accept",
            assertion: assertion_id,
            decision_byte: 0x30,
            revision_byte: 0x31,
            assertion_revision_byte: 0x22,
        },
    );
    let digest =
        mneme_core::ContentDigest::of_source_bytes(mneme_core::fixtures::SOURCE_TEXT.as_bytes());
    let current = common::latest(&workspace, common::SOURCE_ID);
    let mut pruned = mneme_memory::build_unavailable_source_with_digest(
        common::SOURCE_ID,
        common::rev(0x53),
        &common::scope(),
        mneme_memory::UnavailableSourceWithDigestOptions {
            reason: "pruned under retention policy",
            availability: "pruned",
            prior_digest: Some(digest),
            entity: Some(mneme_core::fixtures::entity_id()),
            path_hint: Some("project.adoc"),
        },
    );
    pruned.predecessor = Some(current.revision_id);
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch("prune", vec![pruned], Vec::new()))
            .expect("pruned revision");
    }
    let current = common::latest(&workspace, common::SOURCE_ID);
    let (reimport, blob) = mneme_memory::build_source(
        common::SOURCE_ID,
        common::rev(0x54),
        &common::scope(),
        mneme_memory::SourceOptions {
            bytes: b"Storage engine: LMDB\n",
            media_type: "text/asciidoc",
            entity: Some(mneme_core::fixtures::entity_id()),
            path_hint: Some("project.adoc"),
        },
    )
    .expect("reimport");
    let mut reimport = reimport;
    reimport.predecessor = Some(current.revision_id);
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch("reimport", vec![reimport], vec![blob]))
            .expect("reimport commit");
    }
    // Physical cleanup already removed the pruned blob.
    std::fs::remove_file(mneme_store::payload::blob_path(temp.path(), digest))
        .expect("remove pruned blob");
    let memory = common::engine(&mut workspace);
    let explanation = memory
        .explain(assertion_id, read_policy())
        .expect("explain pruned citation");
    assert_eq!(
        explanation.evidence[0].availability,
        mneme_memory::SourceAvailability::Pruned
    );
    assert!(explanation.evidence[0].excerpt.is_none());
}

#[test]
fn read_side_declared_complete_does_not_ground_an_affirmative_claim() {
    let (_temp, mut workspace) = common::setup();
    let affirmative = mneme_memory::build_proposed_assertion(
        common::rid(0x20),
        common::rev(0x21),
        &common::scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "release-approved",
            value: mneme_core::Value::string("yes"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "test-author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[],
            extraction: None,
            superseded_by: None,
        },
    );
    let mut affirmative = affirmative;
    affirmative.payload.insert(
        mneme_core::Symbol::from("completeness"),
        mneme_core::Value::symbol("declared-complete"),
    );
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch("affirmative", vec![affirmative], Vec::new()))
            .expect("affirmative proposal");
    }
    read_accept(
        &mut workspace,
        &common::scope(),
        ReadAcceptance {
            key: "affirmative-accept",
            assertion: common::rid(0x20),
            decision_byte: 0x30,
            revision_byte: 0x31,
            assertion_revision_byte: 0x22,
        },
    );

    let mut denial = mneme_memory::build_proposed_assertion(
        common::rid(0x24),
        common::rev(0x25),
        &common::scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "blocker",
            value: mneme_core::Value::string("none"),
            stance: mneme_memory::Stance::Deny,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "test-author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[],
            extraction: None,
            superseded_by: None,
        },
    );
    denial.payload.insert(
        mneme_core::Symbol::from("completeness"),
        mneme_core::Value::symbol("declared-complete"),
    );
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch("denial", vec![denial], Vec::new()))
            .expect("denial proposal");
    }
    read_accept(
        &mut workspace,
        &common::scope(),
        ReadAcceptance {
            key: "denial-accept",
            assertion: common::rid(0x24),
            decision_byte: 0x32,
            revision_byte: 0x33,
            assertion_revision_byte: 0x26,
        },
    );

    let memory = common::engine(&mut workspace);
    let beliefs = memory.beliefs(&read_belief_view(false)).expect("beliefs");
    assert!(
        beliefs
            .iter()
            .all(|belief| belief.record.record_id != common::rid(0x20)),
        "an unsupported affirmative claim is not a belief"
    );
    assert!(
        beliefs
            .iter()
            .any(|belief| belief.record.record_id == common::rid(0x24)),
        "an accepted absence basis still grounds a denial"
    );
}

#[test]
fn read_side_explain_reports_ancestry_errors_instead_of_swallowing_them() {
    let (_temp, mut workspace) = common::setup();
    let assertion_id = common::rid(0x20);
    let first = mneme_memory::build_evidence(
        common::rid(0x10),
        common::rev(0x11),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: common::SOURCE_ID,
            source_revision: common::SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[mneme_core::Reference::local(
                common::rid(0x12),
                mneme_core::RecordKind::Evidence,
            )],
        },
    );
    let second = mneme_memory::build_evidence(
        common::rid(0x12),
        common::rev(0x13),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: common::SOURCE_ID,
            source_revision: common::SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(4, 7).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[mneme_core::Reference::local(
                common::rid(0x10),
                mneme_core::RecordKind::Evidence,
            )],
        },
    );
    let claim = mneme_memory::build_proposed_assertion(
        assertion_id,
        common::rev(0x21),
        &common::scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "cyclic",
            value: mneme_core::Value::string("no"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "test-author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                common::rid(0x10),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    // The workspace commit path bypasses memory validation, so a cyclic
    // ancestry can exist in a view built by an older writer.
    read_raw_commit(
        &mut workspace,
        &common::scope(),
        "cyclic",
        vec![first, second, claim],
    );
    let memory = common::engine(&mut workspace);
    let error = memory
        .explain(assertion_id, read_policy())
        .expect_err("explain must not swallow a cyclic ancestry");
    assert!(error.to_string().contains("cycle"));
    assert!(
        memory
            .view()
            .expect("view")
            .corroboration(assertion_id)
            .is_err()
    );
}

#[test]
fn read_side_excerpts_are_bounded_and_boundary_safe() {
    let (_temp, mut workspace) = common::setup();
    let assertion_id = common::propose(
        &mut workspace,
        "proposal",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x10),
            evidence_revision: common::rev(0x11),
            assertion_id: common::rid(0x20),
            assertion_revision: common::rev(0x21),
            predicate: "storage-engine",
            value: mneme_core::Value::string("SQLite"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: Some(mneme_core::SourceSpan::new(0, 9).expect("span")),
            ancestry: &[],
            extraction: None,
        },
    );
    read_accept(
        &mut workspace,
        &common::scope(),
        ReadAcceptance {
            key: "accept",
            assertion: assertion_id,
            decision_byte: 0x30,
            revision_byte: 0x31,
            assertion_revision_byte: 0x22,
        },
    );
    let memory = common::engine(&mut workspace);
    let bounded = memory
        .explain(
            assertion_id,
            mneme_memory::Policy {
                max_explanation_nodes: 64,
                max_excerpt_bytes: 4,
            },
        )
        .expect("bounded excerpt");
    let excerpt = bounded.evidence[0]
        .excerpt
        .as_ref()
        .expect("retained excerpt");
    assert!(excerpt.truncated);
    assert_eq!(excerpt.bytes.len(), 4);
    let complete = memory
        .explain(assertion_id, read_policy())
        .expect("complete excerpt");
    let excerpt = complete.evidence[0]
        .excerpt
        .as_ref()
        .expect("retained excerpt");
    assert!(!excerpt.truncated);
    assert_eq!(
        excerpt.bytes,
        mneme_core::fixtures::SOURCE_TEXT.as_bytes()[0..10].to_vec()
    );
    drop(memory);

    // A cut that falls inside a multi-byte character is floored to a
    // character boundary instead of returning invalid UTF-8.
    let text = "αβγδε";
    let (source, blob) = mneme_memory::build_source(
        common::rid(0x70),
        common::rev(0x71),
        &common::scope(),
        mneme_memory::SourceOptions {
            bytes: text.as_bytes(),
            media_type: "text/plain",
            entity: None,
            path_hint: None,
        },
    )
    .expect("utf8 source");
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch("utf8-source", vec![source], vec![blob]))
            .expect("utf8 source commit");
    }
    let utf8_assertion = common::rid(0x72);
    let evidence = mneme_memory::build_evidence(
        common::rid(0x74),
        common::rev(0x75),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: utf8_assertion,
            source: common::rid(0x70),
            source_revision: common::rev(0x71),
            span: Some(mneme_core::SourceSpan::new(0, 9).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let claim = mneme_memory::build_proposed_assertion(
        utf8_assertion,
        common::rev(0x73),
        &common::scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "utf8",
            value: mneme_core::Value::string("yes"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "test-author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                common::rid(0x74),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch(
                "utf8-claim",
                vec![evidence, claim],
                Vec::new(),
            ))
            .expect("utf8 claim");
    }
    read_accept(
        &mut workspace,
        &common::scope(),
        ReadAcceptance {
            key: "utf8-accept",
            assertion: utf8_assertion,
            decision_byte: 0x36,
            revision_byte: 0x37,
            assertion_revision_byte: 0x76,
        },
    );
    let memory = common::engine(&mut workspace);
    let explanation = memory
        .explain(
            utf8_assertion,
            mneme_memory::Policy {
                max_explanation_nodes: 64,
                max_excerpt_bytes: 3,
            },
        )
        .expect("utf8 excerpt");
    let excerpt = explanation.evidence[0]
        .excerpt
        .as_ref()
        .expect("retained excerpt");
    assert!(excerpt.truncated);
    assert!(excerpt.bytes.len() <= 3);
    assert!(std::str::from_utf8(&excerpt.bytes).is_ok());
}

#[test]
fn read_side_explanation_marks_unreadable_premises_and_decisions_inaccessible() {
    let (_temp, mut workspace) = common::setup();
    let birch = common::project_scope("birch");
    let (source, blob) = mneme_memory::build_source(
        common::rid(0x60),
        common::rev(0x61),
        &birch,
        mneme_memory::SourceOptions {
            bytes: b"birch premise\n",
            media_type: "text/plain",
            entity: None,
            path_hint: None,
        },
    )
    .expect("birch source");
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch_in(
                &birch,
                "birch-source",
                vec![source],
                vec![blob],
            ))
            .expect("birch source");
    }
    let birch_assertion = common::rid(0x62);
    let birch_evidence = mneme_memory::build_evidence(
        common::rid(0x64),
        common::rev(0x65),
        &birch,
        mneme_memory::EvidenceOptions {
            assertion: birch_assertion,
            source: common::rid(0x60),
            source_revision: common::rev(0x61),
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let birch_claim = mneme_memory::build_proposed_assertion(
        birch_assertion,
        common::rev(0x63),
        &birch,
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "birch-premise",
            value: mneme_core::Value::string("yes"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "test-author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                common::rid(0x64),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch_in(
                &birch,
                "birch-claim",
                vec![birch_evidence, birch_claim],
                Vec::new(),
            ))
            .expect("birch claim");
    }
    read_decide(
        &mut workspace,
        "birch-accept",
        ReadDecision {
            scope: &birch,
            assertion: birch_assertion,
            lifecycle: mneme_core::Lifecycle::Accepted,
            decision_id: common::rid(0x66),
            decision_revision: common::rev(0x67),
            assertion_revision: common::rev(0x68),
            kind: mneme_memory::DecisionKind::Acceptance,
            outcome: "accepted",
        },
    );
    let conclusion = common::propose_bare(
        &mut workspace,
        "conclusion",
        &common::scope(),
        common::BareProposalInput {
            assertion_id: common::rid(0x20),
            assertion_revision: common::rev(0x21),
            predicate: "conclusion",
            value: mneme_core::Value::string("derived"),
        },
    );
    read_accept(
        &mut workspace,
        &common::scope(),
        ReadAcceptance {
            key: "conclusion-accept",
            assertion: conclusion,
            decision_byte: 0x30,
            revision_byte: 0x31,
            assertion_revision_byte: 0x22,
        },
    );
    let base = workspace.current_revision().expect("base");
    let derivation = mneme_memory::build_derivation(
        common::rid(0x40),
        common::rev(0x41),
        &common::scope(),
        mneme_memory::DerivationOptions {
            conclusion,
            premises: &[mneme_core::Reference::local(
                birch_assertion,
                mneme_core::RecordKind::Assertion,
            )],
            rule_id: "cross-scope-rule",
            rule_version: 1,
            evaluation_revision: base,
            completeness: "complete",
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch(
                "cross-scope-derivation",
                vec![derivation],
                Vec::new(),
            ))
            .expect("cross-scope derivation");
    }
    // A decision recorded in the other scope targets this assertion; only the
    // count may cross the barrier.
    let foreign = mneme_memory::build_decision(
        common::rid(0x69),
        common::rev(0x6a),
        &birch,
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: conclusion,
            actor: "test-author",
            policy: "foreign-policy/v1",
            input_revision: base,
            outcome: "accepted",
            rationale: "foreign decision",
            evidence: &[],
            related: &[],
        },
    );
    read_raw_commit(&mut workspace, &birch, "foreign-decision", vec![foreign]);

    let restricted = mneme_memory::Engine::new(
        &mut workspace,
        mneme_memory::Access::scopes([common::scope()]),
    );
    let explanation = restricted
        .explain(conclusion, read_policy())
        .expect("restricted explain");
    assert_eq!(explanation.derivations.len(), 1);
    assert!(!explanation.derivations[0].eligible);
    let reasons = explanation.derivations[0].reasons.join(" ");
    assert!(reasons.contains("outside the readable scopes"));
    assert!(!reasons.contains(&birch_assertion.to_string()));
    assert_eq!(explanation.inaccessible_decisions, 1);
    assert!(
        explanation
            .decisions
            .iter()
            .all(|decision| decision.record.scope == common::scope())
    );
    drop(restricted);

    let operator = common::engine(&mut workspace);
    let explanation = operator
        .explain(conclusion, read_policy())
        .expect("operator explain");
    assert_eq!(explanation.derivations.len(), 1);
    assert!(explanation.derivations[0].eligible);
}

#[test]
fn read_side_evidence_only_rewrite_keeps_its_decision() {
    let (_temp, mut workspace) = common::setup();
    let second = common::rid(0x62);
    let second_revision = common::rev(0x63);
    let (source, blob) = mneme_memory::build_source(
        second,
        second_revision,
        &common::scope(),
        mneme_memory::SourceOptions {
            bytes: b"= B\n\nsecond source\n",
            media_type: "text/asciidoc",
            entity: Some(mneme_core::fixtures::entity_id()),
            path_hint: Some("second.adoc"),
        },
    )
    .expect("second source");
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch("second-source", vec![source], vec![blob]))
            .expect("second source commit");
    }
    let assertion_id = common::rid(0x20);
    let first = mneme_memory::build_evidence(
        common::rid(0x10),
        common::rev(0x11),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: common::SOURCE_ID,
            source_revision: common::SOURCE_REV,
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let second_evidence = mneme_memory::build_evidence(
        common::rid(0x12),
        common::rev(0x13),
        &common::scope(),
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: second,
            source_revision: second_revision,
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let claim = mneme_memory::build_proposed_assertion(
        assertion_id,
        common::rev(0x21),
        &common::scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "storage-engine",
            value: mneme_core::Value::string("SQLite"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "test-author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[
                mneme_core::Reference::local(common::rid(0x10), mneme_core::RecordKind::Evidence),
                mneme_core::Reference::local(common::rid(0x12), mneme_core::RecordKind::Evidence),
            ],
            extraction: None,
            superseded_by: None,
        },
    );
    {
        let mut memory = common::engine(&mut workspace);
        memory
            .commit(common::batch(
                "two-citations",
                vec![first, second_evidence, claim],
                Vec::new(),
            ))
            .expect("two citations");
    }
    read_accept(
        &mut workspace,
        &common::scope(),
        ReadAcceptance {
            key: "accept",
            assertion: assertion_id,
            decision_byte: 0x30,
            revision_byte: 0x31,
            assertion_revision_byte: 0x22,
        },
    );

    // Retention drops a citation by rewriting only the evidence set; the
    // acceptance decision that backed the lifecycle still backs it.
    let current = common::latest(&workspace, assertion_id);
    let mut rewritten = mneme_memory::build_assertion_revision(
        &current,
        common::rev(0x24),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(common::rid(0x30), mneme_core::RecordKind::Decision),
        None,
    );
    rewritten.payload.insert(
        mneme_core::Symbol::from("evidence"),
        mneme_core::Value::set([mneme_core::Reference::local(
            common::rid(0x12),
            mneme_core::RecordKind::Evidence,
        )
        .to_value()]),
    );
    read_raw_commit(
        &mut workspace,
        &common::scope(),
        "evidence-rewrite",
        vec![rewritten],
    );
    {
        let memory = common::engine(&mut workspace);
        let view = memory.view().expect("view");
        let assertion = view.assertion(assertion_id).expect("assertion");
        assert_eq!(assertion.lifecycle, mneme_core::Lifecycle::Accepted);
        assert!(view.lifecycle_decision_valid(&assertion).expect("decision"));
        assert!(view.assertion_eligible(assertion_id));
        assert!(
            memory
                .beliefs(&read_belief_view(false))
                .expect("beliefs")
                .iter()
                .any(|belief| belief.record.record_id == assertion_id)
        );
    }

    // Changed content under the same old decision is not accepted knowledge.
    let current = common::latest(&workspace, assertion_id);
    let mut changed = mneme_memory::build_assertion_revision(
        &current,
        common::rev(0x25),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(common::rid(0x30), mneme_core::RecordKind::Decision),
        None,
    );
    changed.payload.insert(
        mneme_core::Symbol::from("value"),
        mneme_core::Value::string("LMDB"),
    );
    read_raw_commit(
        &mut workspace,
        &common::scope(),
        "value-change",
        vec![changed],
    );
    let memory = common::engine(&mut workspace);
    let view = memory.view().expect("view");
    let assertion = view.assertion(assertion_id).expect("assertion");
    assert!(!view.lifecycle_decision_valid(&assertion).expect("decision"));
    assert!(
        memory
            .beliefs(&read_belief_view(false))
            .expect("beliefs")
            .iter()
            .all(|belief| belief.record.record_id != assertion_id)
    );
}

/// The two accepted claims `read_side_view_context_reads_only_...` pins.
struct ReadViewClaims {
    claim: mneme_core::RecordId,
    claim_proposed: mneme_core::WorkspaceRevisionId,
    rival_proposed: mneme_core::WorkspaceRevisionId,
}

/// Commit two claims that disagree, each accepted by a decision in a later
/// batch than the proposal it decides.
fn read_view_claims(workspace: &mut mneme_store::Workspace) -> ReadViewClaims {
    let claim = common::propose(
        workspace,
        "view-claim",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x10),
            evidence_revision: common::rev(0x11),
            assertion_id: common::rid(0x20),
            assertion_revision: common::rev(0x21),
            predicate: "storage-engine",
            value: mneme_core::Value::string("LMDB"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: Some(mneme_core::SourceSpan::new(0, 3).expect("span")),
            ancestry: &[],
            extraction: None,
        },
    );
    let claim_proposed = workspace.current_revision().expect("claim revision");
    read_accept(
        workspace,
        &common::scope(),
        ReadAcceptance {
            key: "view-accept-claim",
            assertion: claim,
            decision_byte: 0x30,
            revision_byte: 0x31,
            assertion_revision_byte: 0x22,
        },
    );
    let rival = common::propose(
        workspace,
        "view-rival",
        &common::scope(),
        common::ProposalInput {
            evidence_id: common::rid(0x12),
            evidence_revision: common::rev(0x13),
            assertion_id: common::rid(0x24),
            assertion_revision: common::rev(0x25),
            predicate: "storage-engine",
            value: mneme_core::Value::string("SQLite"),
            stance: mneme_memory::Stance::Affirm,
            valid_time: mneme_core::ValidTime::always(),
            span: Some(mneme_core::SourceSpan::new(4, 7).expect("span")),
            ancestry: &[],
            extraction: None,
        },
    );
    let rival_proposed = workspace.current_revision().expect("rival revision");
    read_accept(
        workspace,
        &common::scope(),
        ReadAcceptance {
            key: "view-accept-rival",
            assertion: rival,
            decision_byte: 0x32,
            revision_byte: 0x33,
            assertion_revision_byte: 0x26,
        },
    );
    ReadViewClaims {
        claim,
        claim_proposed,
        rival_proposed,
    }
}

/// A conclusion and the derivation that evaluates it at one revision.
struct ReadViewDerivation {
    conclusion: mneme_core::RecordId,
    evaluation: mneme_core::WorkspaceRevisionId,
}

/// Commit a conclusion and a derivation that evaluates it at the revision
/// before the derivation itself was committed.
fn read_view_derivation(
    workspace: &mut mneme_store::Workspace,
    claim: mneme_core::RecordId,
) -> ReadViewDerivation {
    let conclusion = common::propose_bare(
        workspace,
        "view-conclusion",
        &common::scope(),
        common::BareProposalInput {
            assertion_id: common::rid(0x40),
            assertion_revision: common::rev(0x41),
            predicate: "conclusion",
            value: mneme_core::Value::string("derived"),
        },
    );
    let evaluation = workspace.current_revision().expect("conclusion revision");
    let derivation = mneme_memory::build_derivation(
        common::rid(0x50),
        common::rev(0x51),
        &common::scope(),
        mneme_memory::DerivationOptions {
            conclusion,
            premises: &[mneme_core::Reference::local(
                claim,
                mneme_core::RecordKind::Assertion,
            )],
            rule_id: "view-context-rule",
            rule_version: 1,
            evaluation_revision: evaluation,
            completeness: "complete",
        },
    );
    {
        let mut memory = common::engine(workspace);
        memory
            .commit(common::batch(
                "view-derivation",
                vec![derivation],
                Vec::new(),
            ))
            .expect("view derivation");
    }
    ReadViewDerivation {
        conclusion,
        evaluation,
    }
}

/// The revision a view is pinned at, and an unrelated revision committed after
/// it that nothing in a view names.
struct ReadViewLater {
    snapshot: mneme_core::WorkspaceRevisionId,
    unrelated: mneme_core::WorkspaceRevisionId,
}

/// Revise a proposed claim, then commit an unrelated entity after it.
fn read_view_later(workspace: &mut mneme_store::Workspace) -> ReadViewLater {
    let revised = common::propose_bare(
        workspace,
        "view-revised",
        &common::scope(),
        common::BareProposalInput {
            assertion_id: common::rid(0x60),
            assertion_revision: common::rev(0x61),
            predicate: "draft-note",
            value: mneme_core::Value::string("first"),
        },
    );
    let current = common::latest(workspace, revised);
    let mut revision = mneme_memory::build_proposed_assertion(
        revised,
        common::rev(0x62),
        &common::scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "draft-note",
            value: mneme_core::Value::string("second"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[],
            extraction: None,
            superseded_by: None,
        },
    );
    revision.predecessor = Some(current.revision_id);
    read_raw_commit(workspace, &common::scope(), "view-revise", vec![revision]);
    let snapshot = workspace.current_revision().expect("revised revision");
    let mut entity = common::draft(&mneme_core::fixtures::entity());
    entity.record_id = common::rid(0x70);
    entity.revision_id = common::rev(0x71);
    read_raw_commit(workspace, &common::scope(), "view-unrelated", vec![entity]);
    let unrelated = workspace.current_revision().expect("unrelated revision");
    ReadViewLater {
        snapshot,
        unrelated,
    }
}

/// The history `Workspace::record_revisions` reads one record at a time.
fn read_looped_history(
    workspace: &mneme_store::Workspace,
    snapshot: &mneme_store::Snapshot,
) -> std::collections::BTreeMap<
    (mneme_core::RecordId, mneme_core::RevisionId),
    mneme_core::RecordEnvelope,
> {
    snapshot
        .records
        .iter()
        .flat_map(|record| {
            workspace
                .record_revisions(record.record_id)
                .expect("record revisions")
        })
        .map(|revision| ((revision.record_id, revision.revision_id), revision))
        .collect()
}

/// Assert a view built from the two set-based reads answers exactly as one
/// built from the whole-ledger maps, and that both answers rest on the decision
/// and derivation revisions the context carries.
fn read_assert_same_answers(
    context_view: &mneme_memory::View,
    full_view: &mneme_memory::View,
    claim: mneme_core::RecordId,
    conclusion: mneme_core::RecordId,
    claim_proposed: mneme_core::WorkspaceRevisionId,
) {
    let belief_view = read_belief_view(false);
    let beliefs = context_view
        .current_beliefs(&belief_view)
        .expect("context beliefs");
    assert_eq!(beliefs.len(), 2);
    assert_eq!(
        beliefs,
        full_view
            .current_beliefs(&belief_view)
            .expect("full beliefs")
    );
    let instant = read_instant_view("2026-11-10T00:00:00Z");
    let conflicts = context_view.conflicts(&instant).expect("context conflicts");
    assert_eq!(conflicts.len(), 1);
    assert_eq!(
        conflicts,
        full_view.conflicts(&instant).expect("full conflicts")
    );
    let explanation = context_view
        .explain(claim, read_policy())
        .expect("context explanation");
    assert_eq!(
        explanation,
        full_view
            .explain(claim, read_policy())
            .expect("full explanation")
    );
    assert_eq!(explanation.decisions.len(), 1);
    assert_eq!(explanation.decisions[0].input_revision, claim_proposed);
    let derived = context_view
        .explain(conclusion, read_policy())
        .expect("context conclusion");
    assert_eq!(
        derived,
        full_view
            .explain(conclusion, read_policy())
            .expect("full conclusion")
    );
    assert_eq!(derived.derivations.len(), 1);
    assert!(derived.derivations[0].eligible);
}

#[test]
fn read_side_view_context_reads_only_the_history_and_revisions_a_view_uses() {
    let (_temp, mut workspace) = common::setup();
    let claims = read_view_claims(&mut workspace);
    let derived = read_view_derivation(&mut workspace, claims.claim);
    let later = read_view_later(&mut workspace);
    let snapshot = workspace
        .snapshot_at(later.snapshot, None)
        .expect("pinned snapshot");
    let expected_history = read_looped_history(&workspace, &snapshot);
    let full_sequences = workspace.revision_sequences().expect("sequences");
    let suppressions = workspace.active_suppressions().expect("suppressions");
    let context = mneme_memory::view_context(&workspace, &snapshot).expect("view context");

    assert_eq!(context.history, expected_history);
    assert!(context.revision_sequences.contains_key(&later.snapshot));
    assert!(
        context
            .revision_sequences
            .contains_key(&claims.claim_proposed)
    );
    assert!(
        context
            .revision_sequences
            .contains_key(&claims.rival_proposed)
    );
    assert!(context.revision_sequences.contains_key(&derived.evaluation));
    assert!(!context.revision_sequences.contains_key(&later.unrelated));
    assert!(full_sequences.contains_key(&later.unrelated));
    // One sequence for the pinned revision, one for each decision's input
    // revision and one for the derivation's evaluation revision.
    assert_eq!(context.revision_sequences.len(), 4);

    let context_view = mneme_memory::View::with_retention(
        snapshot.clone(),
        workspace.root(),
        context.history,
        context.revision_sequences,
        suppressions.clone(),
    )
    .with_access(mneme_memory::Access::Operator);
    let full_view = mneme_memory::View::with_retention(
        snapshot,
        workspace.root(),
        expected_history,
        full_sequences,
        suppressions,
    )
    .with_access(mneme_memory::Access::Operator);
    read_assert_same_answers(
        &context_view,
        &full_view,
        claims.claim,
        derived.conclusion,
        claims.claim_proposed,
    );
}
