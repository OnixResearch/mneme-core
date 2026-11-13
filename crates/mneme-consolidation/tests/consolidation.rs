//! End-to-end consolidation over a durable workspace.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::unwrap_used, clippy::expect_used)]

const ACTOR: &str = "test-author";
const POLICY: &str = "test-policy/v1";

fn scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
}

fn rid(byte: u8) -> mneme_core::RecordId {
    mneme_core::RecordId::from_bytes([byte; 16])
}

fn rev(byte: u8) -> mneme_core::RevisionId {
    mneme_core::RevisionId::from_bytes([byte; 16])
}

fn at() -> mneme_core::Timestamp {
    mneme_core::Timestamp::parse("2026-11-10T00:00:00Z").expect("time")
}

fn config() -> mneme_store::WorkspaceConfig {
    mneme_store::WorkspaceConfig {
        clock: Box::new(mneme_store::FixedClock::new(at())),
        faults: Box::new(mneme_store::NoFaults),
    }
}

fn engine(workspace: &mut mneme_store::Workspace) -> mneme_memory::Engine<'_> {
    mneme_memory::Engine::new(workspace, mneme_memory::Access::Operator)
}

fn view(workspace: &mut mneme_store::Workspace) -> mneme_memory::View {
    engine(workspace).view().expect("view")
}

fn batch(
    workspace: &mut mneme_store::Workspace,
    key: &str,
    records: Vec<mneme_store::RecordDraft>,
) -> mneme_store::CommitOutcome {
    batch_at(workspace, key, records, None)
}

fn batch_at(
    workspace: &mut mneme_store::Workspace,
    key: &str,
    records: Vec<mneme_store::RecordDraft>,
    base: Option<mneme_core::WorkspaceRevisionId>,
) -> mneme_store::CommitOutcome {
    let batch = mneme_memory::Batch {
        actor: ACTOR.to_owned(),
        scope: scope(),
        idempotency_key: key.to_owned(),
        records,
        source_blobs: Vec::new(),
        publications: Vec::new(),
    };
    match base {
        Some(base) => engine(workspace).commit_at_base(batch, base),
        None => engine(workspace).commit(batch),
    }
    .expect("commit")
}

fn source_key() -> mneme_consolidation::InputKey {
    mneme_consolidation::InputKey {
        record_id: SOURCE_ID,
        revision_id: SOURCE_REV,
    }
}

fn draft(envelope: &mneme_core::RecordEnvelope) -> mneme_store::RecordDraft {
    mneme_store::RecordDraft {
        schema_version: envelope.schema_version,
        kind: envelope.kind,
        record_id: envelope.record_id,
        revision_id: envelope.revision_id,
        predecessor: envelope.predecessor,
        scope: envelope.scope.clone(),
        payload: envelope.payload.clone(),
    }
}

const ENTITY_ID: mneme_core::RecordId = mneme_core::RecordId::from_bytes([0x01; 16]);
const SOURCE_ID: mneme_core::RecordId = mneme_core::RecordId::from_bytes([0x02; 16]);
const SOURCE_REV: mneme_core::RevisionId = mneme_core::RevisionId::from_bytes([0x12; 16]);
const EVIDENCE_ID: mneme_core::RecordId = mneme_core::RecordId::from_bytes([0x05; 16]);
const EVIDENCE_REV: mneme_core::RevisionId = mneme_core::RevisionId::from_bytes([0x15; 16]);
const ASSERTION_ID: mneme_core::RecordId = mneme_core::RecordId::from_bytes([0x04; 16]);
const ASSERTION_REV: mneme_core::RevisionId = mneme_core::RevisionId::from_bytes([0x14; 16]);
const ACCEPTED_REV: mneme_core::RevisionId = mneme_core::RevisionId::from_bytes([0x16; 16]);
const DECISION_ID: mneme_core::RecordId = mneme_core::RecordId::from_bytes([0x06; 16]);
const DECISION_REV: mneme_core::RevisionId = mneme_core::RevisionId::from_bytes([0x17; 16]);

fn asserted_span() -> mneme_core::SourceSpan {
    let text = mneme_core::fixtures::SOURCE_TEXT;
    let sentence = mneme_core::fixtures::ASSERTED_SENTENCE;
    let start = text.find(sentence).expect("sentence");
    let end = start + sentence.len() - 1;
    mneme_core::SourceSpan::new(
        u64::try_from(start).expect("start"),
        u64::try_from(end).expect("end"),
    )
    .expect("span")
}

fn source_digest() -> mneme_core::ContentDigest {
    mneme_core::ContentDigest::of_source_bytes(mneme_core::fixtures::SOURCE_TEXT.as_bytes())
}

/// A workspace with an entity, a source, its evidence, and one accepted assertion
/// built by the memory lifecycle rule: proposed first, then promoted by a
/// decision committed in the second batch by the batch actor against the exact
/// revision being replaced.
fn setup() -> (tempfile::TempDir, mneme_store::Workspace) {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config()).expect("create");
    batch(
        &mut workspace,
        "entity",
        vec![draft(&mneme_core::fixtures::entity())],
    );
    seed_source(&mut workspace);
    seed_acceptance(&mut workspace);
    (temp, workspace)
}

/// Commit the entity's source bytes together with their blob.
fn seed_source(workspace: &mut mneme_store::Workspace) {
    let (source, blob) = mneme_memory::build_source(
        SOURCE_ID,
        SOURCE_REV,
        &scope(),
        mneme_memory::SourceOptions {
            bytes: mneme_core::fixtures::SOURCE_TEXT.as_bytes(),
            media_type: "text/asciidoc",
            entity: Some(ENTITY_ID),
            path_hint: Some("notes.adoc"),
        },
    )
    .expect("source");
    let batch = mneme_memory::Batch {
        actor: ACTOR.to_owned(),
        scope: scope(),
        idempotency_key: "source".to_owned(),
        records: vec![source],
        source_blobs: vec![blob],
        publications: Vec::new(),
    };
    engine(workspace).commit(batch).expect("source");
}

/// Commit the supporting evidence, the proposed assertion, and the decision that
/// promotes the assertion to an accepted revision.
fn seed_acceptance(workspace: &mut mneme_store::Workspace) {
    let evidence = mneme_memory::build_evidence(
        EVIDENCE_ID,
        EVIDENCE_REV,
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: ASSERTION_ID,
            source: SOURCE_ID,
            source_revision: SOURCE_REV,
            span: Some(asserted_span()),
            anchor: Some("storage-decision"),
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let assertion = mneme_memory::build_proposed_assertion(
        ASSERTION_ID,
        ASSERTION_REV,
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: ENTITY_ID,
            predicate: "storage-engine",
            value: mneme_core::Value::string("SQLite"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "synthetic author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                EVIDENCE_ID,
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    batch(workspace, "proposal", vec![evidence, assertion]);
    let base = workspace.current_revision().expect("base");
    let current = latest(workspace, ASSERTION_ID);
    let decision = mneme_memory::build_decision(
        DECISION_ID,
        DECISION_REV,
        &scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: ASSERTION_ID,
            actor: ACTOR,
            policy: POLICY,
            input_revision: base,
            outcome: "accepted",
            rationale: "the cited sentence states the engine",
            evidence: &[],
            related: &[],
        },
    );
    let accepted = mneme_memory::build_assertion_revision(
        &current,
        ACCEPTED_REV,
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(DECISION_ID, mneme_core::RecordKind::Decision),
        None,
    );
    batch(workspace, "acceptance", vec![decision, accepted]);
}

fn latest(
    workspace: &mneme_store::Workspace,
    record: mneme_core::RecordId,
) -> mneme_core::RecordEnvelope {
    let mut revisions = workspace.record_revisions(record).expect("history");
    revisions.pop().expect("revision")
}

/// A request that consolidates the source scope.
fn request(key: &str) -> mneme_consolidation::adapter::WorkspaceJob {
    let job_id = format!("job-{key}");
    let mut request = mneme_consolidation::adapter::WorkspaceJob::new(
        scope(),
        mneme_memory::Access::Operator,
        mneme_consolidation::adapter::JobRequest {
            actor: ACTOR,
            job_id: &job_id,
            idempotency_key: key,
            query: "Cedar",
            at: at(),
            recorded_at: at(),
        },
    );
    request.limits.max_model_calls = 0;
    request
}

fn is_accepted(workspace: &mneme_store::Workspace, assertion: mneme_core::RecordId) -> bool {
    latest(workspace, assertion).assertion_lifecycle() == Some(mneme_core::Lifecycle::Accepted)
}

fn accepted_assertion_count(workspace: &mut mneme_store::Workspace) -> usize {
    view(workspace)
        .assertions()
        .expect("assertions")
        .into_iter()
        .filter(|assertion| assertion.lifecycle == mneme_core::Lifecycle::Accepted)
        .count()
}

#[test]
fn a_job_commits_only_proposed_assertions_with_pinned_evidence() {
    let (_temp, mut workspace) = setup();
    assert!(
        is_accepted(&workspace, ASSERTION_ID),
        "the fixture assertion is accepted before consolidation"
    );
    let accepted_before = accepted_assertion_count(&mut workspace);
    let receipt =
        mneme_consolidation::adapter::consolidate_workspace(&mut workspace, &request("k1"))
            .expect("consolidation");

    assert!(!receipt.replayed);
    assert!(!receipt.committed.is_empty(), "the job committed nothing");
    for committed in &receipt.committed {
        let record = latest(&workspace, committed.assertion);
        assert_eq!(
            record.assertion_lifecycle(),
            Some(mneme_core::Lifecycle::Proposed),
            "consolidation must never accept"
        );
        let evidence = latest(&workspace, committed.evidence);
        assert_eq!(evidence.kind, mneme_core::RecordKind::Evidence);
        let parsed = mneme_memory::EvidenceView::parse(evidence).expect("evidence view");
        assert_eq!(parsed.source, SOURCE_ID);
        assert_eq!(
            parsed.source_reference,
            mneme_core::Reference::pinned(
                SOURCE_ID,
                SOURCE_REV,
                mneme_core::RecordKind::SourceRevision
            ),
            "evidence pins the exact source revision"
        );
        assert!(parsed.span.is_some(), "evidence pins exact bytes");
    }
    assert_eq!(
        accepted_assertion_count(&mut workspace),
        accepted_before,
        "consolidation accepted no assertion"
    );

    // The same request after the job's own commit replays and commits nothing.
    let head = workspace.current_revision().expect("head");
    let replay =
        mneme_consolidation::adapter::consolidate_workspace(&mut workspace, &request("k1"))
            .expect("replay");
    assert!(replay.replayed);
    assert_eq!(replay.committed, receipt.committed);
    assert_eq!(workspace.current_revision().expect("head"), head);
}

#[test]
fn a_forgotten_source_yields_no_proposal() {
    let (_temp, mut workspace) = setup();
    let first = mneme_consolidation::adapter::consolidate_workspace(&mut workspace, &request("k1"))
        .expect("consolidation");
    assert!(!first.committed.is_empty());

    forget_source(&mut workspace);
    let head = workspace.current_revision().expect("head");
    let mut after = request("k2");
    after.job_id = "job-after-forget".to_owned();
    let receipt =
        mneme_consolidation::adapter::consolidate_workspace(&mut workspace, &after).expect("run");
    assert!(
        receipt.committed.is_empty(),
        "a forgotten source produced a proposal"
    );
    assert_eq!(
        workspace.current_revision().expect("head"),
        head,
        "nothing was committed after the forget"
    );
    assert!(
        is_accepted(&workspace, ASSERTION_ID),
        "the pre-existing accepted assertion record remains"
    );
    assert!(
        workspace.record_revisions(SOURCE_ID).is_err(),
        "the forgotten source is no longer served"
    );
}

#[test]
fn a_pruned_source_is_skipped_with_its_reason() {
    let (_temp, mut workspace) = setup();
    let mut pruned = mneme_memory::build_unavailable_source_with_digest(
        SOURCE_ID,
        rev(0x31),
        &scope(),
        mneme_memory::UnavailableSourceWithDigestOptions {
            reason: "source bytes pruned under retention policy",
            availability: "pruned",
            prior_digest: Some(source_digest()),
            entity: Some(ENTITY_ID),
            path_hint: Some("notes.adoc"),
        },
    );
    pruned.predecessor = Some(SOURCE_REV);
    batch(&mut workspace, "prune", vec![pruned]);

    let receipt =
        mneme_consolidation::adapter::consolidate_workspace(&mut workspace, &request("k3"))
            .expect("consolidation");
    assert!(
        receipt.committed.is_empty(),
        "pruned bytes were re-extracted: {:?}",
        receipt.committed
    );
    assert!(
        receipt.skipped.iter().any(|skipped| {
            skipped.key.record_id == SOURCE_ID && skipped.reason.contains("pruned")
        }),
        "the pruned unit was not reported: {:?}",
        receipt.skipped
    );
}

#[test]
fn observed_acceptance_state_is_read_from_the_workspace() {
    let (_temp, mut workspace) = setup();
    let source = source_key();
    let mut proposal = summary_proposal(source);
    let observed = observe_at_head(&mut workspace, &mut proposal);
    assert_eq!(
        observed.base_revision,
        workspace.current_revision().expect("head")
    );
    let source_state = observed.sources.get(&source).expect("source state");
    assert!(source_state.is_quotable());
    assert_eq!(
        source_state.digest(),
        format!("sha256:{}", source_digest().to_hex())
    );

    // A caller-fabricated base cannot be registered: the proposal was reviewed
    // against the state the workspace actually had.
    let mut fabricated = observed.clone();
    fabricated.base_revision = mneme_core::WorkspaceRevisionId::from_bytes([0x99; 16]);
    let mut registry = mneme_consolidation::commands::ProposalRegistry::new(fabricated.clone());
    assert!(
        registry
            .register(mneme_consolidation::commands::Registration {
                proposal: proposal.clone(),
                proposal_revision: 1,
                expected: fabricated,
                coverage: mneme_consolidation::commands::ReviewedCoverage::complete(),
            })
            .is_err()
    );

    let mut registry = mneme_consolidation::commands::ProposalRegistry::new(observed.clone());
    registry
        .register(mneme_consolidation::commands::Registration {
            proposal: proposal.clone(),
            proposal_revision: 1,
            expected: observed.clone(),
            coverage: mneme_consolidation::commands::ReviewedCoverage::complete(),
        })
        .expect("register observed state");

    // Advance the workspace behind the proposal's back: acceptance must notice.
    commit_unrelated_source(&mut workspace);
    let current = view(&mut workspace);
    let suppressions = workspace.active_suppressions().expect("suppressions");
    registry.current = mneme_consolidation::commands::AcceptanceState::observe(
        &current,
        &scope(),
        &proposal,
        &suppressions,
    )
    .expect("current state");
    let outcome = registry.accept(mneme_consolidation::commands::AcceptanceCommand {
        idempotency_key: "accept-observed".to_owned(),
        proposal_id: proposal.proposal_id.clone(),
        proposal_revision: 1,
        expected: observed,
        decision: rid(0x50),
    });
    assert!(
        matches!(
            outcome,
            mneme_consolidation::commands::CommandOutcome::Conflict {
                kind: mneme_consolidation::commands::ConflictKind::StaleBase,
                ..
            }
        ),
        "{outcome:?}"
    );
}

#[test]
fn unsupported_detail_is_refused_at_the_acceptance_boundary() {
    let (_temp, mut workspace) = setup();
    let source = source_key();
    let mut proposal = summary_proposal(source);
    proposal.support = mneme_consolidation::SupportReview {
        actor: "reviewer".to_owned(),
        policy: "semantic-support/v1".to_owned(),
        outcome: mneme_consolidation::SupportOutcome::Rejected,
        detail: "the cited bytes do not state the extracted detail".to_owned(),
    };
    let observed = observe_at_head(&mut workspace, &mut proposal);
    let mut registry = mneme_consolidation::commands::ProposalRegistry::new(observed.clone());
    registry
        .register(mneme_consolidation::commands::Registration {
            proposal: proposal.clone(),
            proposal_revision: 1,
            expected: observed.clone(),
            coverage: mneme_consolidation::commands::ReviewedCoverage::complete(),
        })
        .expect("register");
    let outcome = registry.accept(mneme_consolidation::commands::AcceptanceCommand {
        idempotency_key: "accept-unsupported".to_owned(),
        proposal_id: proposal.proposal_id.clone(),
        proposal_revision: 1,
        expected: observed,
        decision: rid(0x51),
    });
    assert!(
        matches!(
            outcome,
            mneme_consolidation::commands::CommandOutcome::Conflict {
                kind: mneme_consolidation::commands::ConflictKind::UnsupportedAcceptance,
                ..
            }
        ),
        "{outcome:?}"
    );
}

#[test]
fn forgetting_suppresses_an_in_flight_proposal() {
    let (_temp, mut workspace) = setup();
    let mut proposal = summary_proposal(source_key());
    let observed = observe_at_head(&mut workspace, &mut proposal);
    let mut registry = mneme_consolidation::commands::ProposalRegistry::new(observed.clone());
    registry
        .register(mneme_consolidation::commands::Registration {
            proposal: proposal.clone(),
            proposal_revision: 1,
            expected: observed,
            coverage: mneme_consolidation::commands::ReviewedCoverage::complete(),
        })
        .expect("register");
    assert!(registry.inspect(&proposal.proposal_id).is_ok());

    forget_source(&mut workspace);
    let current = view(&mut workspace);
    let suppressions = workspace.active_suppressions().expect("suppressions");
    registry.current = mneme_consolidation::commands::AcceptanceState::observe(
        &current,
        &scope(),
        &proposal,
        &suppressions,
    )
    .expect("current state");
    assert!(registry.current.forgotten.contains(&SOURCE_ID));
    assert_eq!(
        registry.suppress_forgotten(),
        vec![proposal.proposal_id.clone()]
    );
    assert!(
        registry.inspect(&proposal.proposal_id).is_err(),
        "inspect kept serving a suppressed proposal"
    );
}

/// Forget the source record through a committed retention barrier.
fn forget_source(workspace: &mut mneme_store::Workspace) {
    let generation = workspace.eligibility_generation().expect("generation");
    let operation_id = "forget-source".to_owned();
    let retention = mneme_store::RetentionCommit {
        operation_id: operation_id.clone(),
        operation_kind: "forget".to_owned(),
        policy_version: "retention-policy/v1".to_owned(),
        selectors: vec![mneme_store::RetentionSelector {
            ordinal: 1,
            kind: "source".to_owned(),
            target: Some(SOURCE_ID),
            revision: Some(SOURCE_REV),
            digest: Some(source_digest()),
        }],
        suppressions: vec![mneme_store::RetentionSuppression {
            operation_id,
            target: SOURCE_ID,
            // A forget covers the record's whole history, so it suppresses the
            // identity rather than one revision.
            revision: None,
            target_kind: "source-revision".to_owned(),
            mode: mneme_store::SuppressionMode::Forgotten,
            content_digest: Some(source_digest()),
            generation: generation.saturating_add(1),
        }],
        locations: Vec::new(),
        retained_metadata: Vec::new(),
    };
    let fingerprint = mneme_core::request_fingerprint(&mneme_core::Value::record_named(
        "forget-request",
        vec![
            mneme_core::Value::string("forget-source"),
            SOURCE_ID.to_value(),
            SOURCE_REV.to_value(),
            source_digest().to_value(),
            mneme_core::Value::string(retention.policy_version.clone()),
        ],
    ));
    let base = workspace.current_revision().expect("base");
    workspace
        .commit_bound(
            mneme_store::CommitCommand {
                base,
                actor: ACTOR.to_owned(),
                scope: scope(),
                idempotency_key: "forget-source".to_owned(),
                records: Vec::new(),
                source_blobs: Vec::new(),
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: Some(retention),
            },
            fingerprint,
        )
        .expect("forget commit");
}

/// A summary proposal citing the fixture source, reviewed under the current policy.
fn summary_proposal(source: mneme_consolidation::InputKey) -> mneme_consolidation::Proposal {
    mneme_consolidation::Proposal {
        proposal_id: "proposal-summary".to_owned(),
        job_id: "job-observed".to_owned(),
        recorded_at: at(),
        base_revision: mneme_core::WorkspaceRevisionId::from_bytes([0xb0; 16]),
        scope: scope(),
        policy_version: "consolidation-policy/v1".to_owned(),
        eligibility_generation: 0,
        operation: mneme_consolidation::ProposalOperation::Summary(
            mneme_consolidation::SummaryProposal {
                text: "The Cedar prototype uses SQLite.".to_owned(),
            },
        ),
        premises: vec![mneme_consolidation::ProposalPremise {
            record_id: source.record_id,
            revision_id: source.revision_id,
            span: Some(asserted_span()),
            derivation: None,
            ancestry_roots: std::collections::BTreeSet::from([source]),
            authority: mneme_consolidation::ProposalAuthority::Observed,
        }],
        rationale: "summarize pinned evidence".to_owned(),
        support: mneme_consolidation::SupportReview {
            actor: "reviewer".to_owned(),
            policy: "semantic-support/v1".to_owned(),
            outcome: mneme_consolidation::SupportOutcome::Supported,
            detail: "the cited span states the claim".to_owned(),
        },
        disposition: mneme_consolidation::ProposalDisposition::Pending,
    }
}

/// Observe the acceptance state at the current head and bind the proposal to it.
///
/// A proposal generated at the observed revision carries that revision and
/// erasure generation, so registration compares the same state the workspace
/// holds instead of a caller-supplied one.
fn observe_at_head(
    workspace: &mut mneme_store::Workspace,
    proposal: &mut mneme_consolidation::Proposal,
) -> mneme_consolidation::commands::AcceptanceState {
    let pinned = view(workspace);
    let suppressions = workspace.active_suppressions().expect("suppressions");
    let observed = mneme_consolidation::commands::AcceptanceState::observe(
        &pinned,
        &scope(),
        proposal,
        &suppressions,
    )
    .expect("observed state");
    proposal.base_revision = observed.base_revision;
    proposal.eligibility_generation = observed.eligibility_generation;
    observed
}

/// Commit one unrelated retained source so the workspace head advances.
fn commit_unrelated_source(workspace: &mut mneme_store::Workspace) {
    let (record, blob) = mneme_memory::build_source(
        rid(0x30),
        rev(0x40),
        &scope(),
        mneme_memory::SourceOptions {
            bytes: b"an unrelated note",
            media_type: "text/plain",
            entity: None,
            path_hint: Some("unrelated.txt"),
        },
    )
    .expect("source");
    let batch = mneme_memory::Batch {
        actor: ACTOR.to_owned(),
        scope: scope(),
        idempotency_key: "unrelated".to_owned(),
        records: vec![record],
        source_blobs: vec![blob],
        publications: Vec::new(),
    };
    engine(workspace).commit(batch).expect("unrelated");
}
