//! Engine behavior over real workspaces, evidence records, and blobs.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::expect_used)]

fn scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
}

fn other_scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "birch").expect("scope")
}

fn rid(byte: u8) -> mneme_core::RecordId {
    mneme_core::RecordId::from_bytes([byte; 16])
}

fn rev(byte: u8) -> mneme_core::RevisionId {
    mneme_core::RevisionId::from_bytes([byte; 16])
}

const SOURCE_A: &[u8] = b"= Cedar\n\nThe service stores exact bytes. [anchor-a]\n";
const SOURCE_B: &[u8] = b"= Birch\n\nAn independent source. [anchor-b]\n";

struct Harness {
    temp: tempfile::TempDir,
    workspace: mneme_store::Workspace,
}

impl Harness {
    fn new(faults: Box<dyn mneme_store::FaultInjector>) -> Self {
        let temp = tempfile::tempdir().expect("temp");
        let workspace = mneme_store::Workspace::create(
            temp.path(),
            mneme_store::WorkspaceConfig {
                clock: Box::new(mneme_store::FixedClock::new(
                    mneme_core::Timestamp::from_nanos(1_000),
                )),
                faults,
            },
        )
        .expect("create");
        let mut harness = Harness { temp, workspace };
        harness.commit("entity", vec![entity()], Vec::new(), None);
        harness
    }

    fn reopen(&mut self) {
        self.reopen_with(Box::new(mneme_store::NoFaults));
    }

    fn reopen_with(&mut self, faults: Box<dyn mneme_store::FaultInjector>) {
        self.workspace = mneme_store::Workspace::open(
            self.temp.path(),
            mneme_store::WorkspaceConfig {
                clock: Box::new(mneme_store::FixedClock::new(
                    mneme_core::Timestamp::from_nanos(2_000),
                )),
                faults,
            },
        )
        .expect("open");
    }

    fn commit(
        &mut self,
        key: &str,
        records: Vec<mneme_store::RecordDraft>,
        sources: Vec<mneme_store::SourceBlobDraft>,
        retention: Option<mneme_store::RetentionCommit>,
    ) -> mneme_store::CommitOutcome {
        let scope = records
            .first()
            .map(|record| record.scope.clone())
            .unwrap_or_else(scope);
        let base = self.workspace.current_revision().expect("base");
        self.workspace
            .commit(mneme_store::CommitCommand {
                base,
                actor: "retention-test".to_owned(),
                scope,
                idempotency_key: key.to_owned(),
                records,
                source_blobs: sources,
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention,
            })
            .expect("commit")
    }

    fn add_source(
        &mut self,
        key: &str,
        id: u8,
        revision: u8,
        scope: &mneme_core::ScopeId,
        bytes: &[u8],
    ) {
        let (source, blob) = mneme_memory::build_source(
            rid(id),
            rev(revision),
            scope,
            mneme_memory::SourceOptions {
                bytes,
                media_type: "text/asciidoc",
                entity: Some(mneme_core::fixtures::entity_id()),
                path_hint: None,
            },
        )
        .expect("source");
        self.commit(key, vec![source], vec![blob], None);
    }

    fn add_source_with_file(&mut self, key: &str, id: u8, revision: u8, path: &str, bytes: &[u8]) {
        let (source, blob) = mneme_memory::build_source(
            rid(id),
            rev(revision),
            &scope(),
            mneme_memory::SourceOptions {
                bytes,
                media_type: "text/asciidoc",
                entity: Some(mneme_core::fixtures::entity_id()),
                path_hint: Some(path),
            },
        )
        .expect("source");
        let base = self.workspace.current_revision().expect("base");
        self.workspace
            .commit(mneme_store::CommitCommand {
                base,
                actor: "retention-test".to_owned(),
                scope: scope(),
                idempotency_key: key.to_owned(),
                records: vec![source],
                source_blobs: vec![blob],
                publications: vec![mneme_store::PublicationDraft {
                    path: path.to_owned(),
                    expected_previous: None,
                    bytes: bytes.to_vec(),
                }],
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("source publication");
    }

    fn accept_assertion(
        &mut self,
        key: &str,
        assertion: mneme_core::RecordId,
        assertion_revision: u8,
        decision: mneme_core::RecordId,
        decision_revision: u8,
    ) {
        let current = self
            .workspace
            .record_revisions(assertion)
            .expect("revisions")
            .into_iter()
            .last()
            .expect("assertion");
        let decision_record = mneme_memory::build_decision(
            decision,
            rev(decision_revision),
            &current.scope,
            mneme_memory::DecisionOptions {
                kind: mneme_memory::DecisionKind::Acceptance,
                target: assertion,
                actor: "author",
                policy: "test-policy/v1",
                input_revision: self.workspace.current_revision().expect("base"),
                outcome: "accepted",
                rationale: "supported acceptance",
                evidence: &[],
                related: &[],
            },
        );
        let accepted = mneme_memory::build_assertion_revision(
            &current,
            rev(assertion_revision),
            mneme_core::Lifecycle::Accepted,
            mneme_core::Reference::local(decision, mneme_core::RecordKind::Decision),
            None,
        );
        self.commit(key, vec![decision_record, accepted], Vec::new(), None);
    }

    fn request(
        &self,
        operation: mneme_retention::OperationKind,
        selector: mneme_retention::Selector,
        key: &str,
        scope: mneme_core::ScopeId,
    ) -> mneme_retention::Request {
        mneme_retention::Request {
            actor: "retention-author".to_owned(),
            scope,
            base_revision: self.workspace.current_revision().expect("base"),
            idempotency_key: key.to_owned(),
            operation,
            selector,
            effective: None,
            policy: mneme_retention::Policy {
                version: mneme_retention::POLICY_VERSION.to_owned(),
                retain_assertion_after_prune: true,
                block_content_replay: true,
                retain_withdrawn_evidence_metadata: true,
            },
        }
    }
}

fn entity() -> mneme_store::RecordDraft {
    mneme_store::RecordDraft {
        schema_version: 1,
        kind: mneme_core::RecordKind::Entity,
        record_id: mneme_core::fixtures::entity_id(),
        revision_id: rev(0x0b),
        predecessor: None,
        scope: scope(),
        payload: mneme_core::fixtures::entity().payload,
    }
}

fn evidence_references(evidence: &[mneme_store::RecordDraft]) -> Vec<mneme_core::Reference> {
    evidence
        .iter()
        .map(|draft| {
            mneme_core::Reference::local(draft.record_id, mneme_core::RecordKind::Evidence)
        })
        .collect()
}

fn add_supported_assertion(
    harness: &mut Harness,
    with_second_source: bool,
) -> mneme_core::RecordId {
    add_supported_assertion_with_valid_time(
        harness,
        with_second_source,
        mneme_core::ValidTime::always(),
    )
}

fn add_supported_assertion_with_valid_time(
    harness: &mut Harness,
    with_second_source: bool,
    valid_time: mneme_core::ValidTime,
) -> mneme_core::RecordId {
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    if with_second_source {
        harness.add_source("source-b", 0x22, 0x23, &scope(), SOURCE_B);
    }
    let span = mneme_core::SourceSpan::new(0, 10).expect("span");
    let mut evidence = vec![mneme_memory::build_evidence(
        rid(0x30),
        rev(0x31),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: rid(0x40),
            source: rid(0x20),
            source_revision: rev(0x21),
            span: Some(mneme_core::SourceSpan::new(0, 10).expect("span")),
            anchor: Some("anchor-a"),
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    )];
    if with_second_source {
        evidence.push(mneme_memory::build_evidence(
            rid(0x32),
            rev(0x33),
            &scope(),
            mneme_memory::EvidenceOptions {
                assertion: rid(0x40),
                source: rid(0x22),
                source_revision: rev(0x23),
                span: Some(span),
                anchor: Some("anchor-b"),
                relation: mneme_memory::SupportRelation::Supports,
                origin: mneme_core::Origin::AuthoredStatement,
                ancestry: &[],
            },
        ));
    }
    let evidence_references = evidence_references(&evidence);
    let assertion = mneme_memory::build_proposed_assertion(
        rid(0x40),
        rev(0x41),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "storage-policy",
            value: mneme_core::Value::string("retain exact bytes"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time,
            evidence: &evidence_references,
            extraction: None,
            superseded_by: None,
        },
    );
    harness.commit(
        "assertion-batch",
        evidence
            .into_iter()
            .chain(std::iter::once(assertion))
            .collect(),
        Vec::new(),
        None,
    );
    harness.accept_assertion("accept", rid(0x40), 0x42, rid(0x50), 0x51);
    rid(0x40)
}

fn source_blob_path(harness: &Harness, bytes: &[u8]) -> std::path::PathBuf {
    mneme_store::payload::blob_path(
        harness.temp.path(),
        mneme_core::ContentDigest::of_source_bytes(bytes),
    )
}

fn record_blob_path(harness: &Harness, record: &mneme_core::RecordEnvelope) -> std::path::PathBuf {
    mneme_store::payload::blob_path(harness.temp.path(), record.full_digest())
}

fn assert_missing(path: &std::path::Path) {
    assert!(!path.exists(), "expected {} to be absent", path.display());
}

fn beliefs(harness: &mut Harness) -> Vec<mneme_memory::AssertionView> {
    let memory = mneme_memory::Engine::new(&mut harness.workspace, mneme_memory::Access::Operator);
    memory
        .view()
        .expect("view")
        .current_beliefs(&mneme_memory::BeliefView {
            scope: scope(),
            at: mneme_core::Timestamp::from_nanos(5_000),
            include_hypothetical: false,
            include_disputed: false,
        })
        .expect("beliefs")
}

#[test]
fn pruning_keeps_a_permitted_assertion_and_reports_pruned_bytes() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    let assertion = add_supported_assertion(&mut harness, false);
    let source_path = source_blob_path(&harness, SOURCE_A);
    let request = harness.request(
        mneme_retention::OperationKind::SourcePruning,
        mneme_retention::Selector::Source(rid(0x20)),
        "prune-a",
        scope(),
    );
    let plan = {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let plan = retention.plan(request.clone()).expect("plan");
        assert_eq!(plan.surviving_assertions, vec![assertion]);
        assert!(
            !plan
                .suppressed
                .iter()
                .any(|suppression| suppression.kind == mneme_core::RecordKind::SourceRevision),
            "pruning keeps every source revision envelope readable"
        );
        plan
    };
    assert_eq!(plan.source_targets, vec![rid(0x20)]);
    let result = {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        retention.execute(request).expect("execute")
    };
    assert!(result.logical_withdrawal);
    assert!(result.physical_cleanup_complete, "{result:?}");
    assert_missing(&source_path);
    {
        let memory =
            mneme_memory::Engine::new(&mut harness.workspace, mneme_memory::Access::Operator);
        let view = memory.view().expect("view");
        let source = view.source(rid(0x20)).expect("source");
        assert_eq!(
            source.availability,
            mneme_memory::SourceAvailability::Pruned
        );
        assert_eq!(
            source.prior_digest,
            Some(mneme_core::ContentDigest::of_source_bytes(SOURCE_A))
        );
        // A policy-permitted accepted assertion and its provenance envelope
        // survive pruning: the pinned citation resolves to content-pruned
        // metadata and the claim stays eligible.
        assert!(view.assertion_eligible(assertion));
        let explanation = view
            .explain(
                assertion,
                mneme_memory::Policy {
                    max_explanation_nodes: 64,
                    max_excerpt_bytes: 4096,
                },
            )
            .expect("explain");
        assert!(
            explanation
                .evidence
                .iter()
                .all(|evidence| evidence.excerpt.is_none())
        );
    }
    assert_eq!(beliefs(&mut harness).len(), 1);
    // Pruning is not content-wide erasure: importing the same bytes again is
    // not blocked by the barrier.
    let replay = replay_source(&mut harness, "replay-pruned-bytes", 0x26, SOURCE_A);
    assert!(
        replay.is_ok(),
        "pruning does not block an import: {replay:?}"
    );
}

#[test]
fn out_of_scope_selector_is_reported_like_an_unknown_target() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    let before = harness.workspace.snapshot().expect("before");
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "wrong-scope",
        other_scope(),
    );
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        // A record in a scope the request does not cover is reported exactly
        // like a record that does not exist, so the request is not an oracle.
        let error = retention.plan(request).expect_err("unknown target");
        assert!(matches!(error, mneme_retention::PolicyError::NotFound));
    }
    let after = harness.workspace.snapshot().expect("after");
    assert_eq!(before.revision, after.revision);
    assert_eq!(before.eligibility_generation, after.eligibility_generation);
}

#[test]
fn forget_hides_dependents_and_purges_payload_blobs() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    let assertion = add_supported_assertion(&mut harness, false);
    let source_record = harness
        .workspace
        .record_revisions(rid(0x20))
        .expect("source")
        .last()
        .expect("source revision")
        .clone();
    let evidence_record = harness
        .workspace
        .record_revisions(rid(0x30))
        .expect("evidence")
        .last()
        .expect("evidence revision")
        .clone();
    let assertion_record = harness
        .workspace
        .record_revisions(assertion)
        .expect("assertion")
        .last()
        .expect("assertion revision")
        .clone();
    let source_path = source_blob_path(&harness, SOURCE_A);
    let source_record_path = record_blob_path(&harness, &source_record);
    let evidence_path = record_blob_path(&harness, &evidence_record);
    let assertion_path = record_blob_path(&harness, &assertion_record);
    let old_revision = harness.workspace.current_revision().expect("old");
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "forget-a",
        scope(),
    );
    let result = {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        retention.execute(request).expect("forget")
    };
    assert!(result.logical_withdrawal);
    for path in [
        &source_path,
        &source_record_path,
        &evidence_path,
        &assertion_path,
    ] {
        assert_missing(path);
    }
    {
        let memory =
            mneme_memory::Engine::new(&mut harness.workspace, mneme_memory::Access::Operator);
        let view = memory.view().expect("view");
        assert!(view.source(rid(0x20)).is_err());
        assert!(view.assertion(assertion).is_err());
        assert!(view.evidence(rid(0x30)).is_err());
    }
    let historical = harness
        .workspace
        .snapshot_at(old_revision, None)
        .expect("historical");
    assert!(
        historical
            .records
            .iter()
            .all(|record| record.record_id != rid(0x20)
                && record.record_id != assertion
                && record.record_id != rid(0x30))
    );
}

#[test]
fn support_retraction_keeps_an_independent_proof() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    let assertion = add_supported_assertion(&mut harness, true);
    let request = harness.request(
        mneme_retention::OperationKind::AssertionRetraction,
        mneme_retention::Selector::SourceSupport(rid(0x20)),
        "withdraw-a-support",
        scope(),
    );
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let plan = retention.plan(request.clone()).expect("plan");
        assert!(plan.surviving_assertions.contains(&assertion));
        assert_eq!(plan.withdrawn_evidence, vec![rid(0x30)]);
        let result = retention.execute(request).expect("execute");
        assert!(result.physical_cleanup_complete, "{result:?}");
    }
    {
        let memory =
            mneme_memory::Engine::new(&mut harness.workspace, mneme_memory::Access::Operator);
        let view = memory.view().expect("view");
        assert!(view.assertion_eligible(assertion));
        let explanation = view
            .explain(
                assertion,
                mneme_memory::Policy {
                    max_explanation_nodes: 64,
                    max_excerpt_bytes: 4096,
                },
            )
            .expect("explain");
        let withdrawn = explanation
            .evidence
            .iter()
            .find(|evidence| evidence.evidence == rid(0x30))
            .expect("withdrawn evidence retained for inspection");
        assert!(withdrawn.withdrawn);
        assert!(!withdrawn.eligible);
        assert!(
            explanation
                .evidence
                .iter()
                .find(|evidence| evidence.evidence == rid(0x32))
                .expect("independent evidence")
                .eligible
        );
        assert_eq!(
            explanation.corroboration.roots,
            std::collections::BTreeSet::from([(rid(0x22), rev(0x23))])
        );
    }
    assert_eq!(beliefs(&mut harness).len(), 1);
}

#[test]
fn support_retraction_without_independent_proof_removes_current_belief() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    let assertion = add_supported_assertion(&mut harness, false);
    let request = harness.request(
        mneme_retention::OperationKind::AssertionRetraction,
        mneme_retention::Selector::SourceSupport(rid(0x20)),
        "withdraw-only-support",
        scope(),
    );
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        retention.execute(request).expect("execute");
    }
    {
        let memory =
            mneme_memory::Engine::new(&mut harness.workspace, mneme_memory::Access::Operator);
        let view = memory.view().expect("view");
        assert!(!view.assertion_eligible(assertion));
    }
    assert!(beliefs(&mut harness).is_empty());
}

#[test]
fn forget_preserves_an_independent_assertion_without_its_forgotten_citation() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    let assertion = add_supported_assertion(&mut harness, true);
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "forget-one-of-two",
        scope(),
    );
    let result = {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        retention.execute(request).expect("forget")
    };
    assert!(result.logical_withdrawal);
    {
        let memory =
            mneme_memory::Engine::new(&mut harness.workspace, mneme_memory::Access::Operator);
        let view = memory.view().expect("view");
        assert!(view.source(rid(0x20)).is_err());
        assert!(view.source(rid(0x22)).is_ok());
        assert!(view.assertion(assertion).is_ok());
        let current = view.assertion(assertion).expect("assertion");
        assert_eq!(
            current.evidence,
            std::collections::BTreeSet::from([rid(0x32)])
        );
        let explanation = view
            .explain(
                assertion,
                mneme_memory::Policy {
                    max_explanation_nodes: 64,
                    max_excerpt_bytes: 4096,
                },
            )
            .expect("explain");
        assert!(
            explanation
                .evidence
                .iter()
                .all(|evidence| evidence.evidence != rid(0x30))
        );
        assert!(
            explanation
                .evidence
                .iter()
                .all(|evidence| evidence.excerpt.is_none() || evidence.source != rid(0x20))
        );
    }
    assert_eq!(beliefs(&mut harness).len(), 1);
}

#[test]
fn retraction_records_lifecycle_and_invalidates_dependent_derivation() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    let premise = add_supported_assertion(&mut harness, false);
    let conclusion = rid(0x60);
    let mut conclusion_assertion = mneme_memory::build_proposed_assertion(
        conclusion,
        rev(0x61),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "conclusion",
            value: mneme_core::Value::string("derived"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[],
            extraction: None,
            superseded_by: None,
        },
    );
    conclusion_assertion.payload.insert(
        mneme_core::Symbol::from("completeness"),
        mneme_core::Value::symbol("declared-complete"),
    );
    harness.commit("conclusion", vec![conclusion_assertion], Vec::new(), None);
    harness.accept_assertion("accept-conclusion", conclusion, 0x62, rid(0x70), 0x71);
    let derivation = mneme_memory::build_derivation(
        rid(0x72),
        rev(0x73),
        &scope(),
        mneme_memory::DerivationOptions {
            conclusion,
            premises: &[mneme_core::Reference::local(
                premise,
                mneme_core::RecordKind::Assertion,
            )],
            rule_id: "rule-a",
            rule_version: 1,
            evaluation_revision: harness.workspace.current_revision().expect("base"),
            completeness: "complete",
        },
    );
    harness.commit("derivation", vec![derivation], Vec::new(), None);
    let request = harness.request(
        mneme_retention::OperationKind::AssertionRetraction,
        mneme_retention::Selector::Assertion(premise),
        "retract-premise",
        scope(),
    );
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let plan = retention.plan(request.clone()).expect("plan");
        assert!(plan.invalidated_derivations.contains(&rid(0x72)));
        retention.execute(request).expect("retract");
    }
    let memory = mneme_memory::Engine::new(&mut harness.workspace, mneme_memory::Access::Operator);
    let view = memory.view().expect("view");
    assert!(
        view.assertion(premise)
            .expect("retracted assertion")
            .lifecycle
            == mneme_core::Lifecycle::Retracted
    );
    assert!(!view.assertion_eligible(premise));
    assert!(
        view.derivation_alternatives(conclusion)
            .expect("alternatives")
            .iter()
            .all(|alternative| !alternative.eligible)
    );
}

#[test]
fn valid_time_expiry_removes_current_applicability_without_deleting_history() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    let assertion = add_supported_assertion(&mut harness, false);
    let effective = mneme_core::Timestamp::from_nanos(4_000);
    let mut request = harness.request(
        mneme_retention::OperationKind::ValidTimeExpiry,
        mneme_retention::Selector::Assertion(assertion),
        "expire-assertion",
        scope(),
    );
    request.effective = Some(effective);
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        retention.execute(request).expect("expire");
    }
    let memory = mneme_memory::Engine::new(&mut harness.workspace, mneme_memory::Access::Operator);
    let view = memory.view().expect("view");
    let current = view.assertion(assertion).expect("assertion");
    assert_eq!(
        current.valid_time,
        mneme_core::ValidTime::Bounded {
            start: None,
            end: Some(effective),
        }
    );
    assert!(
        !view
            .current_beliefs(&mneme_memory::BeliefView {
                scope: scope(),
                at: mneme_core::Timestamp::from_nanos(5_000),
                include_hypothetical: false,
                include_disputed: false,
            })
            .expect("after")
            .iter()
            .any(|belief| belief.record.record_id == assertion)
    );
    assert_eq!(
        memory.revisions(assertion).expect("history").len(),
        3,
        "expiry preserves the proposed and accepted revisions"
    );
}

#[test]
fn repeated_command_returns_the_same_operation_and_generation() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    let request = harness.request(
        mneme_retention::OperationKind::SourcePruning,
        mneme_retention::Selector::Source(rid(0x20)),
        "once",
        scope(),
    );
    let first = {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        retention.execute(request.clone()).expect("first")
    };
    let generation = harness
        .workspace
        .eligibility_generation()
        .expect("generation");
    let second = {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        retention.execute(request).expect("second")
    };
    assert_eq!(first.operation_id, second.operation_id);
    assert_eq!(
        harness
            .workspace
            .eligibility_generation()
            .expect("generation"),
        generation
    );
}

#[test]
fn cleanup_resumes_after_a_fault_and_keeps_the_barrier() {
    let mut harness = Harness::new(Box::new(mneme_store::FaultAt(
        mneme_store::FaultPoint::BeforeRetentionPurge,
    )));
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    let source_path = source_blob_path(&harness, SOURCE_A);
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "resume-forget",
        scope(),
    );
    let operation_id = {
        let error = {
            let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
            retention.execute(request.clone()).expect_err("fault")
        };
        assert!(matches!(
            error,
            mneme_retention::PolicyError::Store(mneme_store::Failure::InjectedFault(_))
        ));
        // The barrier committed before cleanup failed.
        let generation = harness
            .workspace
            .eligibility_generation()
            .expect("generation");
        let pending = harness
            .workspace
            .retention_operation_by_key("retention-author", &scope(), "resume-forget")
            .expect("lookup")
            .expect("operation");
        assert_eq!(pending.generation, generation);
        let memory =
            mneme_memory::Engine::new(&mut harness.workspace, mneme_memory::Access::Operator);
        assert!(memory.view().expect("view").source(rid(0x20)).is_err());
        pending.operation_id
    };
    harness.reopen();
    let result = {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        retention.resume(&operation_id).expect("resume")
    };
    assert_eq!(result.operation_id, operation_id);
    assert!(result.physical_cleanup_complete, "{result:?}");
    assert_missing(&source_path);
}

#[test]
fn shared_content_address_retains_bytes_and_reports_without_owner_detail() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    {
        let (source, blob) = mneme_memory::build_source(
            rid(0x24),
            rev(0x25),
            &other_scope(),
            mneme_memory::SourceOptions {
                bytes: SOURCE_A,
                media_type: "text/asciidoc",
                entity: None,
                path_hint: None,
            },
        )
        .expect("shared source");
        let base = harness.workspace.current_revision().expect("base");
        harness
            .workspace
            .commit(mneme_store::CommitCommand {
                base,
                actor: "other-author".to_owned(),
                scope: other_scope(),
                idempotency_key: "shared-source".to_owned(),
                records: vec![source],
                source_blobs: vec![blob],
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("shared commit");
    }
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "shared-forget",
        scope(),
    );
    let result = {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        retention.execute(request).expect("forget")
    };
    assert!(!result.physical_cleanup_complete, "{result:?}");
    assert!(result.cleanup.retained_shared > 0);
    assert!(
        result
            .locations
            .iter()
            .any(|location| location.location_kind == "source-blob"
                && location.state == mneme_store::RetentionLocationState::RetainedShared)
    );
    assert!(
        result
            .limitations
            .contains(&"shared-content-addressed-bytes-retained".to_owned())
    );
    let blob_path = source_blob_path(&harness, SOURCE_A);
    assert!(blob_path.exists());
    {
        let memory =
            mneme_memory::Engine::new(&mut harness.workspace, mneme_memory::Access::Operator);
        let view = memory.view().expect("view");
        // The forgetting owner's records are gone and every path to them is
        // hidden.
        assert!(view.source(rid(0x20)).is_err());
        // The other owner's record survives and its bytes are still readable.
        assert!(view.source(rid(0x24)).is_ok());
        assert_eq!(
            view.source_status(rid(0x24)).expect("shared source status"),
            mneme_memory::SourceStatus::Retained(SOURCE_A.to_vec())
        );
    }
    let owner_id = rid(0x24).to_hex();
    let owner_revision = rev(0x25).to_hex();
    for location in &result.locations {
        assert!(
            !location.location_id.contains(&owner_id),
            "a location names the other scope's record: {location:?}"
        );
        assert!(
            !location.locator.contains(&owner_id),
            "a location names the other scope's record: {location:?}"
        );
        assert!(
            !location.location_id.contains(&owner_revision),
            "a location names the other scope's revision: {location:?}"
        );
        assert!(
            !location.locator.contains(&owner_revision),
            "a location names the other scope's record: {location:?}"
        );
    }
    for limitation in &result.limitations {
        assert!(
            !limitation.contains(&owner_id),
            "a limitation names the other scope's record: {limitation}"
        );
        assert!(
            !limitation.contains(&owner_revision),
            "a limitation names the other scope's record: {limitation}"
        );
    }
}

#[test]
fn forgetting_a_source_suppresses_dependent_checkpoint() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    let episode = mneme_memory::build_episode(
        rid(0x70),
        rev(0x71),
        &scope(),
        mneme_memory::EpisodeOptions {
            actor: "author",
            episode_type: "statement",
            occurred: mneme_core::ValidTime::always(),
            summary: "exact source summary",
            source: Some(mneme_core::Reference::pinned(
                rid(0x20),
                rev(0x21),
                mneme_core::RecordKind::SourceRevision,
            )),
            related: &[],
        },
    );
    let checkpoint = mneme_memory::build_checkpoint(
        rid(0x72),
        rev(0x73),
        &scope(),
        mneme_memory::CheckpointOptions {
            goal: "resume task",
            state: "planned",
            episodes: &[mneme_core::Reference::local(
                rid(0x70),
                mneme_core::RecordKind::Episode,
            )],
            verified_outcomes: &[],
            revision: harness.workspace.current_revision().expect("base"),
            note: Some("depends on the source"),
        },
    );
    harness.commit("checkpoint", vec![episode, checkpoint], Vec::new(), None);
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "forget-checkpoint",
        scope(),
    );
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let plan = retention.plan(request.clone()).expect("plan");
        assert!(
            plan.suppressed
                .iter()
                .any(|suppression| suppression.target == rid(0x70))
        );
        assert!(
            plan.suppressed
                .iter()
                .any(|suppression| suppression.target == rid(0x72))
        );
        retention.execute(request).expect("forget");
    }
    let memory = mneme_memory::Engine::new(&mut harness.workspace, mneme_memory::Access::Operator);
    let view = memory.view().expect("view");
    assert!(view.record(rid(0x70)).is_err());
    assert!(view.record(rid(0x72)).is_err());
}

#[test]
fn forgotten_content_cannot_be_replayed_under_a_new_identity() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "forget-replay",
        scope(),
    );
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        retention.execute(request).expect("forget");
    }
    let (replayed, blob) = mneme_memory::build_source(
        rid(0x26),
        rev(0x27),
        &scope(),
        mneme_memory::SourceOptions {
            bytes: SOURCE_A,
            media_type: "text/asciidoc",
            entity: None,
            path_hint: None,
        },
    )
    .expect("replay source");
    let base = harness.workspace.current_revision().expect("base");
    let error = harness
        .workspace
        .commit(mneme_store::CommitCommand {
            base,
            actor: "attacker".to_owned(),
            scope: scope(),
            idempotency_key: "replay".to_owned(),
            records: vec![replayed],
            source_blobs: vec![blob],
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect_err("content replay must be refused");
    assert!(matches!(
        error,
        mneme_store::Failure::RetentionSuppressed { .. }
    ));
}

fn copy_tree(source: &std::path::Path, destination: &std::path::Path) {
    std::fs::create_dir_all(destination).expect("destination");
    let mut directories = vec![std::fs::read_dir(source).expect("source entries")];
    let mut destinations = vec![destination.to_path_buf()];
    let mut steps = 0_usize;
    while let Some(entries) = directories.last_mut() {
        steps += 1;
        if steps > 1_000_000 {
            break;
        }
        let next = entries.next();
        let Some(entry) = next else {
            directories.pop();
            destinations.pop();
            continue;
        };
        let entry = entry.expect("entry");
        let target = destinations
            .last()
            .expect("destination path")
            .join(entry.file_name());
        if entry.file_type().expect("type").is_dir() {
            std::fs::create_dir_all(&target).expect("destination");
            let child_source = entry.path();
            destinations.push(target);
            directories.push(std::fs::read_dir(child_source).expect("source entries"));
        } else {
            std::fs::copy(entry.path(), target).expect("copy file");
        }
    }
}

#[test]
fn restore_without_current_suppression_state_fails_closed_until_applied() {
    let temp = tempfile::tempdir().expect("temp");
    let backup = tempfile::tempdir().expect("backup");
    {
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
        let base = workspace.current_revision().expect("base");
        workspace
            .commit(mneme_store::CommitCommand {
                base,
                actor: "test".to_owned(),
                scope: scope(),
                idempotency_key: "entity".to_owned(),
                records: vec![entity()],
                source_blobs: Vec::new(),
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("entity");
        let (source, blob) = mneme_memory::build_source(
            rid(0x20),
            rev(0x21),
            &scope(),
            mneme_memory::SourceOptions {
                bytes: SOURCE_A,
                media_type: "text/asciidoc",
                entity: Some(mneme_core::fixtures::entity_id()),
                path_hint: None,
            },
        )
        .expect("source");
        let base = workspace.current_revision().expect("base");
        workspace
            .commit(mneme_store::CommitCommand {
                base,
                actor: "test".to_owned(),
                scope: scope(),
                idempotency_key: "source".to_owned(),
                records: vec![source],
                source_blobs: vec![blob],
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("source");
    }
    copy_tree(temp.path(), backup.path());
    let mut current = mneme_store::Workspace::open(
        temp.path(),
        mneme_store::WorkspaceConfig {
            clock: Box::new(mneme_store::FixedClock::new(
                mneme_core::Timestamp::from_nanos(1_500),
            )),
            faults: Box::new(mneme_store::NoFaults),
        },
    )
    .expect("current");
    let request = mneme_retention::Request {
        actor: "retention-author".to_owned(),
        scope: scope(),
        base_revision: current.current_revision().expect("base"),
        idempotency_key: "restore-forget".to_owned(),
        operation: mneme_retention::OperationKind::Forget,
        selector: mneme_retention::Selector::Source(rid(0x20)),
        effective: None,
        policy: mneme_retention::Policy {
            version: mneme_retention::POLICY_VERSION.to_owned(),
            retain_assertion_after_prune: true,
            block_content_replay: true,
            retain_withdrawn_evidence_metadata: true,
        },
    };
    {
        let mut retention = mneme_retention::Engine::new(&mut current);
        retention.execute(request).expect("forget");
    }
    let ledger = current.export_suppression_ledger().expect("ledger");
    let mut restored = mneme_store::Workspace::open_restored(
        backup.path(),
        mneme_store::WorkspaceConfig {
            clock: Box::new(mneme_store::FixedClock::new(
                mneme_core::Timestamp::from_nanos(2_000),
            )),
            faults: Box::new(mneme_store::NoFaults),
        },
    )
    .expect("restore");
    assert!(matches!(
        restored.snapshot().expect_err("blocked read"),
        mneme_store::Failure::MissingRetentionState { .. }
    ));
    restored
        .apply_restore_suppression_ledger(&ledger)
        .expect("apply ledger");
    let snapshot = restored.snapshot().expect("visible");
    assert!(
        snapshot
            .records
            .iter()
            .all(|record| record.record_id != rid(0x20))
    );
    assert!(restored.export_suppression_ledger().expect("state").len() > ledger.len() / 2);
}

#[test]
fn future_payload_store_cannot_enable_without_retention_contract() {
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
    let incomplete = mneme_store::RetentionParticipant {
        name: "vector-cache".to_owned(),
        storage_role: "vector-index".to_owned(),
        supports_invalidation: true,
        supports_purge: false,
        checks_generation: true,
        inventory_locator: "cache/vectors".to_owned(),
    };
    assert!(
        workspace
            .register_retention_participant(incomplete)
            .is_err()
    );
    let no_inventory = mneme_store::RetentionParticipant {
        name: "vector-cache".to_owned(),
        storage_role: "vector-index".to_owned(),
        supports_invalidation: true,
        supports_purge: true,
        checks_generation: true,
        inventory_locator: String::new(),
    };
    assert!(
        workspace
            .register_retention_participant(no_inventory)
            .is_err()
    );
    let revision = workspace.current_revision().expect("revision");
    let generation = workspace.eligibility_generation().expect("generation");
    let error = workspace
        .register_projection(mneme_store::ProjectionRegistration {
            name: "vector-cache".to_owned(),
            revision,
            eligibility_generation: generation,
            schema_version: 1,
            rule_version: "none".to_owned(),
            index_version: "v1".to_owned(),
            scope: scope().to_string(),
        })
        .expect_err("unregistered payload store");
    assert!(matches!(
        error,
        mneme_store::Failure::MissingRetentionParticipant { .. }
    ));
    workspace
        .register_retention_participant(mneme_store::RetentionParticipant {
            name: "vector-cache".to_owned(),
            storage_role: "vector-index".to_owned(),
            supports_invalidation: true,
            supports_purge: true,
            checks_generation: true,
            inventory_locator: "cache/vectors".to_owned(),
        })
        .expect("complete participant");
    workspace
        .register_projection(mneme_store::ProjectionRegistration {
            name: "vector-cache".to_owned(),
            revision,
            eligibility_generation: generation,
            schema_version: 1,
            rule_version: "none".to_owned(),
            index_version: "v1".to_owned(),
            scope: scope().to_string(),
        })
        .expect("registered projection");
}

#[test]
fn policy_can_refuse_pruning_when_it_would_hide_required_support() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    let assertion = add_supported_assertion(&mut harness, false);
    let source_path = source_blob_path(&harness, SOURCE_A);
    let mut request = harness.request(
        mneme_retention::OperationKind::SourcePruning,
        mneme_retention::Selector::Source(rid(0x20)),
        "refused-prune",
        scope(),
    );
    request.policy.retain_assertion_after_prune = false;
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let error = retention.execute(request).expect_err("policy refusal");
        assert!(matches!(error, mneme_retention::PolicyError::Policy(_)));
    }
    assert!(source_path.exists());
    let memory = mneme_memory::Engine::new(&mut harness.workspace, mneme_memory::Access::Operator);
    let view = memory.view().expect("view");
    assert!(view.assertion_eligible(assertion));
}

#[test]
fn fault_before_barrier_commit_leaves_source_and_generation_unchanged() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    harness.reopen_with(Box::new(mneme_store::FaultAt(
        mneme_store::FaultPoint::BeforeCommitTransaction,
    )));
    let before = harness.workspace.snapshot().expect("before");
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "failed-barrier",
        scope(),
    );
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let error = retention.execute(request).expect_err("fault");
        assert!(matches!(
            error,
            mneme_retention::PolicyError::Store(mneme_store::Failure::InjectedFault(_))
        ));
    }
    let after = harness.workspace.snapshot().expect("after");
    assert_eq!(before.revision, after.revision);
    assert_eq!(before.eligibility_generation, after.eligibility_generation);
    assert!(
        harness
            .workspace
            .retention_operation_by_key("retention-author", &scope(), "failed-barrier")
            .expect("lookup")
            .is_none()
    );
}

#[test]
fn ambiguous_operation_and_selector_combinations_are_rejected_before_mutation() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    let request = harness.request(
        mneme_retention::OperationKind::ValidTimeExpiry,
        mneme_retention::Selector::Source(rid(0x20)),
        "ambiguous-expiry",
        scope(),
    );
    let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
    let error = retention.plan(request).expect_err("ambiguous");
    assert!(matches!(error, mneme_retention::PolicyError::Invalid(_)));
}

#[test]
fn failed_managed_cache_keeps_barrier_and_reports_incomplete_cleanup() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    let base = harness.workspace.current_revision().expect("base");
    let generation = harness
        .workspace
        .eligibility_generation()
        .expect("generation")
        .saturating_add(1);
    let operation_id = "retention-cache-failure".to_owned();
    harness
        .workspace
        .commit(mneme_store::CommitCommand {
            base,
            actor: "retention-author".to_owned(),
            scope: scope(),
            idempotency_key: "cache-failure".to_owned(),
            records: Vec::new(),
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: Some(mneme_store::RetentionCommit {
                operation_id: operation_id.clone(),
                operation_kind: "forget".to_owned(),
                policy_version: mneme_retention::Policy {
                    version: mneme_retention::POLICY_VERSION.to_owned(),
                    retain_assertion_after_prune: true,
                    block_content_replay: true,
                    retain_withdrawn_evidence_metadata: true,
                }
                .version,
                selectors: Vec::new(),
                suppressions: Vec::new(),
                locations: vec![mneme_store::RetentionLocationPlan {
                    location_id: "cache:vectors".to_owned(),
                    location_kind: "managed-cache".to_owned(),
                    locator: "cache/vectors".to_owned(),
                }],
                retained_metadata: vec!["operation-generation".to_owned()],
            }),
        })
        .expect("barrier commit");
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let cancelled = retention.cancel(&operation_id).expect("cancel");
        assert!(cancelled.logical_withdrawal);
        assert!(!cancelled.physical_cleanup_complete);
        assert_eq!(cancelled.cleanup.pending, 1);
        let result = retention.resume(&operation_id).expect("cleanup result");
        assert!(!result.physical_cleanup_complete);
        assert_eq!(result.cleanup.failed, 1);
        // A failed attempt is a failed job, not a settled one: the summary the
        // kernel produces decides the state.
        assert!(result.state == mneme_store::RetentionJobState::Failed);
        assert!(
            result
                .limitations
                .contains(&"managed-cleanup-failed".to_owned())
        );
        assert!(result.logical_withdrawal);
    }
    assert_eq!(
        harness
            .workspace
            .eligibility_generation()
            .expect("generation"),
        generation
    );
}

#[test]
fn rebuild_from_a_pre_forget_snapshot_is_refused() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    add_supported_assertion(&mut harness, false);
    let old = harness.workspace.snapshot().expect("old snapshot");
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "rebuild-forget",
        scope(),
    );
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        retention.execute(request).expect("forget");
    }
    {
        // The rebuild guard runs in the production view-rebuild path, not only
        // in a directly called helper.
        let retention = mneme_retention::Engine::new(&mut harness.workspace);
        let error = retention
            .rebuild_view(old)
            .expect_err("old snapshot contains forgotten data");
        assert!(matches!(
            error,
            mneme_retention::PolicyError::Store(mneme_store::Failure::RetentionSuppressed { .. })
        ));
    }
    let current = harness.workspace.snapshot().expect("current");
    let retention = mneme_retention::Engine::new(&mut harness.workspace);
    assert!(retention.rebuild_view(current).is_ok());
}

#[test]
fn forget_suppresses_a_pending_publication_before_recovery() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    harness.reopen_with(Box::new(mneme_store::FaultAt(
        mneme_store::FaultPoint::AfterCommit,
    )));
    let base = harness.workspace.current_revision().expect("base");
    let error = harness
        .workspace
        .commit(mneme_store::CommitCommand {
            base,
            actor: "publisher".to_owned(),
            scope: scope(),
            idempotency_key: "pending-publication".to_owned(),
            records: Vec::new(),
            source_blobs: Vec::new(),
            publications: vec![mneme_store::PublicationDraft {
                path: "leak.adoc".to_owned(),
                expected_previous: None,
                bytes: SOURCE_A.to_vec(),
            }],
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect_err("fault after commit");
    assert!(matches!(error, mneme_store::Failure::InjectedFault(_)));
    harness.reopen();
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "forget-pending",
        scope(),
    );
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        retention.execute(request).expect("forget");
    }
    let intents = harness
        .workspace
        .publication_intents()
        .expect("publication intents");
    assert_eq!(intents.len(), 1);
    assert_eq!(intents[0].state, mneme_store::PublicationState::Suppressed);
    let pending = harness.workspace.publish_pending().expect("publish");
    assert!(pending.is_empty());
    assert!(
        mneme_store::payload::read_working_file(harness.temp.path(), "leak.adoc")
            .expect("working file")
            .is_none()
    );
}

#[test]
fn a_query_pinned_before_the_barrier_cannot_publish_after_it() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    let assertion = add_supported_assertion(&mut harness, true);
    let generation = harness
        .workspace
        .eligibility_generation()
        .expect("generation");
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "barrier-during-query",
        scope(),
    );
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        retention.execute(request).expect("forget");
    }
    let memory = mneme_memory::Engine::new(&mut harness.workspace, mneme_memory::Access::Operator);
    let error = memory
        .explain_at(assertion, Some(generation), Default::default())
        .expect_err("stale generation");
    assert!(matches!(
        error,
        mneme_memory::EvidenceError::Store(mneme_store::Failure::BarrierAdvanced { .. })
    ));
}

#[test]
fn pruning_removes_only_an_exact_managed_working_copy() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source_with_file("source-file", 0x20, 0x21, "project.adoc", SOURCE_A);
    let request = harness.request(
        mneme_retention::OperationKind::SourcePruning,
        mneme_retention::Selector::Source(rid(0x20)),
        "prune-file",
        scope(),
    );
    let result = {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        retention.execute(request).expect("prune")
    };
    assert!(result.physical_cleanup_complete, "{result:?}");
    assert!(
        mneme_store::payload::read_working_file(harness.temp.path(), "project.adoc")
            .expect("working file")
            .is_none()
    );
}

#[test]
fn external_working_edit_is_preserved_and_reported_unavailable() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source_with_file("source-file", 0x20, 0x21, "project.adoc", SOURCE_A);
    let edited = b"= Cedar\n\nA later external edit.\n";
    mneme_store::payload::publish_working_file(harness.temp.path(), "project.adoc", edited)
        .expect("external edit");
    let request = harness.request(
        mneme_retention::OperationKind::SourcePruning,
        mneme_retention::Selector::Source(rid(0x20)),
        "prune-edited-file",
        scope(),
    );
    let result = {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        retention.execute(request).expect("prune")
    };
    assert!(!result.physical_cleanup_complete);
    assert_eq!(
        mneme_store::payload::read_working_file(harness.temp.path(), "project.adoc").expect("file"),
        Some(edited.to_vec())
    );
    assert!(result.locations.iter().any(|location| {
        location.location_kind == "working-file"
            && location.state == mneme_store::RetentionLocationState::Unavailable
            && location.detail_code.as_deref() == Some("external-edit-present")
    }));
}

#[test]
fn idempotency_key_reuse_with_a_different_selector_conflicts() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    harness.add_source("source-b", 0x22, 0x23, &scope(), SOURCE_B);
    let first = harness.request(
        mneme_retention::OperationKind::SourcePruning,
        mneme_retention::Selector::Source(rid(0x20)),
        "same-key",
        scope(),
    );
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        retention.execute(first).expect("first");
    }
    let second = harness.request(
        mneme_retention::OperationKind::SourcePruning,
        mneme_retention::Selector::Source(rid(0x22)),
        "same-key",
        scope(),
    );
    let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
    let error = retention.execute(second).expect_err("conflict");
    assert!(matches!(
        error,
        mneme_retention::PolicyError::Store(mneme_store::Failure::IdempotencyConflict { .. })
    ));
}

#[test]
fn content_selector_targets_only_authorized_matching_sources() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    harness.add_source("source-a-copy", 0x22, 0x23, &scope(), SOURCE_A);
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Content(mneme_core::ContentDigest::of_source_bytes(SOURCE_A)),
        "forget-content",
        scope(),
    );
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let plan = retention.plan(request.clone()).expect("content plan");
        assert_eq!(plan.source_targets.len(), 2);
        retention.execute(request).expect("content forget");
    }
    let memory = mneme_memory::Engine::new(&mut harness.workspace, mneme_memory::Access::Operator);
    let view = memory.view().expect("view");
    assert!(view.source(rid(0x20)).is_err());
    assert!(view.source(rid(0x22)).is_err());

    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    let mut foreign = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Content(mneme_core::ContentDigest::of_source_bytes(SOURCE_A)),
        "foreign-content",
        other_scope(),
    );
    foreign.scope = other_scope();
    let absent = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Content(mneme_core::ContentDigest::of_source_bytes(
            b"bytes no scope holds",
        )),
        "absent-content",
        other_scope(),
    );
    let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
    // The bytes exist only in another scope. The answer must be identical to
    // the answer for bytes nobody holds, so the caller cannot use retention to
    // learn about another scope.
    let foreign_error = retention.plan(foreign).expect_err("foreign content");
    assert!(matches!(
        &foreign_error,
        mneme_retention::PolicyError::NotFound
    ));
    let absent_error = retention.plan(absent).expect_err("absent content");
    assert_eq!(
        format!("{foreign_error}"),
        format!("{absent_error}"),
        "an out-of-scope match must not be distinguishable from absence"
    );
}

/// One fixture source revision and the revision it replaces.
struct SourceRevisionFixture<'a> {
    commit_key: &'a str,
    record: u8,
    revision: u8,
    predecessor: u8,
    bytes: &'a [u8],
    path: Option<&'a str>,
}

/// Commit the next revision of an existing source record.
fn add_source_revision(harness: &mut Harness, fixture: &SourceRevisionFixture<'_>) {
    let (mut source, blob) = mneme_memory::build_source(
        rid(fixture.record),
        rev(fixture.revision),
        &scope(),
        mneme_memory::SourceOptions {
            bytes: fixture.bytes,
            media_type: "text/asciidoc",
            entity: Some(mneme_core::fixtures::entity_id()),
            path_hint: fixture.path,
        },
    )
    .expect("source revision");
    source.predecessor = Some(rev(fixture.predecessor));
    harness.commit(fixture.commit_key, vec![source], vec![blob], None);
}

/// The records `document import` creates for one source revision.
fn document_records(
    source: mneme_core::RecordId,
    source_revision: mneme_core::RevisionId,
) -> Vec<mneme_store::RecordDraft> {
    let source_reference = mneme_core::Reference::pinned(
        source,
        source_revision,
        mneme_core::RecordKind::SourceRevision,
    );
    vec![
        document_draft(&source_reference),
        anchor_draft(&source_reference),
        binding_draft(&source_reference),
    ]
}

/// The imported document record.
fn document_draft(source_reference: &mneme_core::Reference) -> mneme_store::RecordDraft {
    mneme_store::RecordDraft {
        schema_version: 3,
        kind: mneme_core::RecordKind::Document,
        record_id: rid(0x60),
        revision_id: rev(0x61),
        predecessor: None,
        scope: scope(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("title"),
                mneme_core::Value::string("Secret Plan Beta"),
            ),
            (
                mneme_core::Symbol::from("source-revision"),
                source_reference.to_value(),
            ),
            (
                mneme_core::Symbol::from("path"),
                mneme_core::Value::string("notes.adoc"),
            ),
            (
                mneme_core::Symbol::from("render-config"),
                mneme_core::Value::string("mneme-preview/v1"),
            ),
        ]),
    }
}

/// The document anchor record.
fn anchor_draft(source_reference: &mneme_core::Reference) -> mneme_store::RecordDraft {
    mneme_store::RecordDraft {
        schema_version: 3,
        kind: mneme_core::RecordKind::DocumentAnchor,
        record_id: rid(0x62),
        revision_id: rev(0x63),
        predecessor: None,
        scope: scope(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("document"),
                mneme_core::Reference::local(rid(0x60), mneme_core::RecordKind::Document)
                    .to_value(),
            ),
            (
                mneme_core::Symbol::from("source-revision"),
                source_reference.to_value(),
            ),
            (
                mneme_core::Symbol::from("span"),
                mneme_core::SourceSpan::new(0, 10).expect("span").to_value(),
            ),
            (
                mneme_core::Symbol::from("anchor"),
                mneme_core::Value::string("beta-anchor"),
            ),
            (
                mneme_core::Symbol::from("label"),
                mneme_core::Value::string("Beta label"),
            ),
            (
                mneme_core::Symbol::from("line"),
                mneme_core::Value::integer(3_i64),
            ),
            (
                mneme_core::Symbol::from("column"),
                mneme_core::Value::integer(1_i64),
            ),
        ]),
    }
}

/// The document binding record.
fn binding_draft(source_reference: &mneme_core::Reference) -> mneme_store::RecordDraft {
    mneme_store::RecordDraft {
        schema_version: 3,
        kind: mneme_core::RecordKind::DocumentBinding,
        record_id: rid(0x64),
        revision_id: rev(0x65),
        predecessor: None,
        scope: scope(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("document"),
                mneme_core::Reference::local(rid(0x60), mneme_core::RecordKind::Document)
                    .to_value(),
            ),
            (
                mneme_core::Symbol::from("entity"),
                mneme_core::Reference::local(
                    mneme_core::fixtures::entity_id(),
                    mneme_core::RecordKind::Entity,
                )
                .to_value(),
            ),
            (
                mneme_core::Symbol::from("status"),
                mneme_core::Value::symbol("bound"),
            ),
            (
                mneme_core::Symbol::from("basis"),
                mneme_core::Value::string("source-header"),
            ),
            (
                mneme_core::Symbol::from("source-revision"),
                source_reference.to_value(),
            ),
        ]),
    }
}

/// Attempt a source commit and report the coordinator's answer.
fn replay_source(
    harness: &mut Harness,
    key: &str,
    id: u8,
    bytes: &[u8],
) -> std::result::Result<mneme_store::CommitOutcome, mneme_store::Failure> {
    let (source, blob) = mneme_memory::build_source(
        rid(id),
        rev(id),
        &scope(),
        mneme_memory::SourceOptions {
            bytes,
            media_type: "text/asciidoc",
            entity: None,
            path_hint: None,
        },
    )
    .expect("replay source");
    let base = harness.workspace.current_revision().expect("base");
    harness.workspace.commit(mneme_store::CommitCommand {
        base,
        actor: "replayer".to_owned(),
        scope: scope(),
        idempotency_key: key.to_owned(),
        records: vec![source],
        source_blobs: vec![blob],
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: None,
    })
}

/// Commit a barrier-only retention operation with the given locations.
fn commit_barrier(
    harness: &mut Harness,
    key: &str,
    operation_id: &str,
    locations: Vec<mneme_store::RetentionLocationPlan>,
) {
    let base = harness.workspace.current_revision().expect("base");
    harness
        .workspace
        .commit(mneme_store::CommitCommand {
            base,
            actor: "retention-test".to_owned(),
            scope: scope(),
            idempotency_key: key.to_owned(),
            records: Vec::new(),
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: Some(mneme_store::RetentionCommit {
                operation_id: operation_id.to_owned(),
                operation_kind: "forget".to_owned(),
                policy_version: mneme_retention::POLICY_VERSION.to_owned(),
                selectors: Vec::new(),
                suppressions: Vec::new(),
                locations,
                retained_metadata: vec!["operation-generation".to_owned()],
            }),
        })
        .expect("barrier commit");
}

#[test]
fn content_selector_covers_every_retained_revision() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    harness.add_source("source-b", 0x22, 0x23, &scope(), SOURCE_B);
    add_source_revision(
        &mut harness,
        &SourceRevisionFixture {
            commit_key: "source-b-revision",
            record: 0x22,
            revision: 0x24,
            predecessor: 0x23,
            bytes: SOURCE_A,
            path: None,
        },
    );
    let old_revision = harness.workspace.current_revision().expect("old");
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Content(mneme_core::ContentDigest::of_source_bytes(SOURCE_A)),
        "content-history",
        scope(),
    );
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let plan = retention.plan(request.clone()).expect("plan");
        // The second source holds the content in an earlier revision only; the
        // selector must still resolve it.
        assert!(plan.source_targets.contains(&rid(0x20)));
        assert!(plan.source_targets.contains(&rid(0x22)));
        retention.execute(request).expect("forget");
    }
    assert_missing(&source_blob_path(&harness, SOURCE_A));
    assert_missing(&source_blob_path(&harness, SOURCE_B));
    let historical = harness
        .workspace
        .snapshot_at(old_revision, None)
        .expect("historical");
    assert!(
        historical
            .records
            .iter()
            .all(|record| { record.record_id != rid(0x20) && record.record_id != rid(0x22) })
    );
}

#[test]
fn pruning_and_then_forgetting_cover_every_source_revision() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    add_source_revision(
        &mut harness,
        &SourceRevisionFixture {
            commit_key: "source-a-revision",
            record: 0x20,
            revision: 0x22,
            predecessor: 0x21,
            bytes: SOURCE_B,
            path: Some("history.adoc"),
        },
    );
    let old_revision = harness.workspace.current_revision().expect("old");
    let digest_a = mneme_core::ContentDigest::of_source_bytes(SOURCE_A);
    let digest_b = mneme_core::ContentDigest::of_source_bytes(SOURCE_B);
    let prune = harness.request(
        mneme_retention::OperationKind::SourcePruning,
        mneme_retention::Selector::Source(rid(0x20)),
        "prune-history",
        scope(),
    );
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let plan = retention.plan(prune.clone()).expect("prune plan");
        assert!(
            !plan
                .suppressed
                .iter()
                .any(|suppression| suppression.kind == mneme_core::RecordKind::SourceRevision),
            "pruning keeps every source revision envelope readable"
        );
        for digest in [digest_a, digest_b] {
            assert!(
                plan.locations
                    .iter()
                    .any(|location| location.location_id
                        == format!("source-blob:{}", digest.to_hex())),
                "every retained revision digest is inventoried"
            );
        }
        retention.execute(prune).expect("prune");
    }
    // The replaced revision's bytes are gone; the source reports itself pruned.
    // The earlier revision's digest is still reported as required by the
    // coordinator's allowed-absence rule (see the Needs entry for
    // `include_source_record_digest`); the plan inventories it and the forget
    // below removes it once the revision is suppressed.
    assert_missing(&source_blob_path(&harness, SOURCE_B));
    {
        let memory =
            mneme_memory::Engine::new(&mut harness.workspace, mneme_memory::Access::Operator);
        let view = memory.view().expect("view");
        assert_eq!(
            view.source_status(rid(0x20)).expect("source status"),
            mneme_memory::SourceStatus::Pruned
        );
    }
    let historical = harness
        .workspace
        .snapshot_at(old_revision, None)
        .expect("historical");
    assert!(
        historical
            .records
            .iter()
            .any(|record| record.record_id == rid(0x20)),
        "pruning keeps every revision's record envelope"
    );
    let forget = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "forget-after-prune",
        scope(),
    );
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let plan = retention.plan(forget.clone()).expect("forget plan");
        // A forget after pruning covers the pruned revision's recorded prior
        // digest as well as every earlier retained revision digest.
        for digest in [digest_a, digest_b] {
            assert!(
                plan.suppressed.iter().any(|suppression| {
                    suppression.target == rid(0x20) && suppression.content_digest == Some(digest)
                }),
                "{digest:?}: {:?}",
                plan.suppressed
            );
        }
        let result = retention.execute(forget).expect("forget");
        assert!(result.physical_cleanup_complete, "{result:?}");
    }
    assert_missing(&source_blob_path(&harness, SOURCE_A));
    assert_missing(&source_blob_path(&harness, SOURCE_B));
    for (key, id, bytes) in [
        ("replay-forgotten-a", 0x28, SOURCE_A),
        ("replay-forgotten-b", 0x2a, SOURCE_B),
    ] {
        let replay = replay_source(&mut harness, key, id, bytes);
        assert!(matches!(
            replay,
            Err(mneme_store::Failure::RetentionSuppressed { .. })
        ));
    }
}

#[test]
fn publication_and_import_candidate_replay_is_refused() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "forget-publication",
        scope(),
    );
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        retention.execute(request).expect("forget");
    }
    let base = harness.workspace.current_revision().expect("base");
    let publication = harness.workspace.commit(mneme_store::CommitCommand {
        base,
        actor: "publisher".to_owned(),
        scope: scope(),
        idempotency_key: "replay-publication".to_owned(),
        records: Vec::new(),
        source_blobs: Vec::new(),
        publications: vec![mneme_store::PublicationDraft {
            path: "leak.adoc".to_owned(),
            expected_previous: None,
            bytes: SOURCE_A.to_vec(),
        }],
        import_candidates: Vec::new(),
        retention: None,
    });
    assert!(matches!(
        publication,
        Err(mneme_store::Failure::RetentionSuppressed { .. })
    ));
    mneme_store::payload::publish_working_file(harness.temp.path(), "rb.adoc", SOURCE_A)
        .expect("working file");
    let (source, _blob) = mneme_memory::build_source(
        rid(0x2a),
        rev(0x2b),
        &scope(),
        mneme_memory::SourceOptions {
            bytes: SOURCE_A,
            media_type: "text/asciidoc",
            entity: None,
            path_hint: Some("rb.adoc"),
        },
    )
    .expect("candidate source");
    let base = harness.workspace.current_revision().expect("base");
    let candidate = harness.workspace.commit(mneme_store::CommitCommand {
        base,
        actor: "importer".to_owned(),
        scope: scope(),
        idempotency_key: "replay-candidate".to_owned(),
        records: vec![source],
        source_blobs: Vec::new(),
        publications: Vec::new(),
        import_candidates: vec![mneme_store::ImportCandidateDraft {
            path: "rb.adoc".to_owned(),
            bytes: SOURCE_A.to_vec(),
        }],
        retention: None,
    });
    assert!(matches!(
        candidate,
        Err(mneme_store::Failure::RetentionSuppressed { .. })
    ));
}

#[test]
fn forget_keeps_a_conclusion_with_an_independent_derivation() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source("source-s", 0x20, 0x21, &scope(), SOURCE_A);
    harness.add_source("source-t", 0x22, 0x23, &scope(), SOURCE_B);
    let span = mneme_core::SourceSpan::new(0, 10).expect("span");
    let evidence_s = mneme_memory::build_evidence(
        rid(0x30),
        rev(0x31),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: rid(0x40),
            source: rid(0x20),
            source_revision: rev(0x21),
            span: Some(span),
            anchor: Some("anchor-a"),
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let evidence_t = mneme_memory::build_evidence(
        rid(0x32),
        rev(0x33),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: rid(0x50),
            source: rid(0x22),
            source_revision: rev(0x23),
            span: Some(span),
            anchor: Some("anchor-b"),
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let premise_s = mneme_memory::build_proposed_assertion(
        rid(0x40),
        rev(0x41),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "premise-one",
            value: mneme_core::Value::string("supported by S"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                rid(0x30),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    let premise_t = mneme_memory::build_proposed_assertion(
        rid(0x50),
        rev(0x51),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "premise-two",
            value: mneme_core::Value::string("supported by T"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                rid(0x32),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    let conclusion = mneme_memory::build_proposed_assertion(
        rid(0x60),
        rev(0x61),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "conclusion",
            value: mneme_core::Value::string("derived"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[],
            extraction: None,
            superseded_by: None,
        },
    );
    harness.commit(
        "premises",
        vec![evidence_s, evidence_t, premise_s, premise_t, conclusion],
        Vec::new(),
        None,
    );
    let evaluation_revision = harness.workspace.current_revision().expect("base");
    let derivation_s = mneme_memory::build_derivation(
        rid(0x70),
        rev(0x71),
        &scope(),
        mneme_memory::DerivationOptions {
            conclusion: rid(0x60),
            premises: &[mneme_core::Reference::local(
                rid(0x40),
                mneme_core::RecordKind::Assertion,
            )],
            rule_id: "rule-s",
            rule_version: 1,
            evaluation_revision,
            completeness: "complete",
        },
    );
    let derivation_t = mneme_memory::build_derivation(
        rid(0x72),
        rev(0x73),
        &scope(),
        mneme_memory::DerivationOptions {
            conclusion: rid(0x60),
            premises: &[mneme_core::Reference::local(
                rid(0x50),
                mneme_core::RecordKind::Assertion,
            )],
            rule_id: "rule-t",
            rule_version: 1,
            evaluation_revision,
            completeness: "complete",
        },
    );
    harness.commit(
        "derivations",
        vec![derivation_s, derivation_t],
        Vec::new(),
        None,
    );
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "forget-independent",
        scope(),
    );
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let plan = retention.plan(request.clone()).expect("plan");
        let suppressed: std::collections::BTreeSet<_> = plan
            .suppressed
            .iter()
            .map(|suppression| suppression.target)
            .collect();
        assert!(suppressed.contains(&rid(0x30)));
        assert!(suppressed.contains(&rid(0x40)));
        assert!(suppressed.contains(&rid(0x70)));
        assert!(!suppressed.contains(&rid(0x60)));
        assert!(!suppressed.contains(&rid(0x72)));
        retention.execute(request).expect("forget");
    }
    let memory = mneme_memory::Engine::new(&mut harness.workspace, mneme_memory::Access::Operator);
    let view = memory.view().expect("view");
    assert!(view.record(rid(0x40)).is_err());
    assert!(view.record(rid(0x70)).is_err());
    assert!(view.record(rid(0x60)).is_ok());
    assert!(view.record(rid(0x72)).is_ok());
}

#[test]
fn derivation_with_a_forgotten_episode_premise_is_invalidated() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    let episode = mneme_memory::build_episode(
        rid(0x70),
        rev(0x71),
        &scope(),
        mneme_memory::EpisodeOptions {
            actor: "author",
            episode_type: "observation",
            occurred: mneme_core::ValidTime::always(),
            summary: "observed in the forgotten source",
            source: Some(mneme_core::Reference::pinned(
                rid(0x20),
                rev(0x21),
                mneme_core::RecordKind::SourceRevision,
            )),
            related: &[],
        },
    );
    let conclusion = mneme_memory::build_proposed_assertion(
        rid(0x60),
        rev(0x61),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "launch-date",
            value: mneme_core::Value::string("derived: launch is May 5"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[],
            extraction: None,
            superseded_by: None,
        },
    );
    harness.commit("episode", vec![episode, conclusion], Vec::new(), None);
    let derivation = mneme_memory::build_derivation(
        rid(0x72),
        rev(0x73),
        &scope(),
        mneme_memory::DerivationOptions {
            conclusion: rid(0x60),
            premises: &[mneme_core::Reference::local(
                rid(0x70),
                mneme_core::RecordKind::Episode,
            )],
            rule_id: "rule-episode",
            rule_version: 1,
            evaluation_revision: harness.workspace.current_revision().expect("base"),
            completeness: "complete",
        },
    );
    harness.commit("derivation", vec![derivation], Vec::new(), None);
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "forget-episode-premise",
        scope(),
    );
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let plan = retention.plan(request.clone()).expect("plan");
        let suppressed: std::collections::BTreeSet<_> = plan
            .suppressed
            .iter()
            .map(|suppression| suppression.target)
            .collect();
        assert!(suppressed.contains(&rid(0x70)));
        assert!(suppressed.contains(&rid(0x72)));
        assert!(suppressed.contains(&rid(0x60)));
        retention.execute(request).expect("forget");
    }
    let memory = mneme_memory::Engine::new(&mut harness.workspace, mneme_memory::Access::Operator);
    let view = memory.view().expect("view");
    assert!(view.record(rid(0x70)).is_err());
    assert!(view.record(rid(0x72)).is_err());
    assert!(view.record(rid(0x60)).is_err());
}

#[test]
fn evidence_ancestry_through_an_assertion_is_followed() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source("source-s", 0x20, 0x21, &scope(), SOURCE_A);
    harness.add_source("source-t", 0x22, 0x23, &scope(), SOURCE_B);
    let span = mneme_core::SourceSpan::new(0, 10).expect("span");
    let evidence_s = mneme_memory::build_evidence(
        rid(0x30),
        rev(0x31),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: rid(0x40),
            source: rid(0x20),
            source_revision: rev(0x21),
            span: Some(span),
            anchor: Some("anchor-a"),
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let premise = mneme_memory::build_proposed_assertion(
        rid(0x40),
        rev(0x41),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "premise-one",
            value: mneme_core::Value::string("supported by S"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                rid(0x30),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    let summary_evidence = mneme_memory::build_evidence(
        rid(0x32),
        rev(0x33),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: rid(0x60),
            source: rid(0x22),
            source_revision: rev(0x23),
            span: Some(span),
            anchor: Some("anchor-b"),
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[mneme_core::Reference::local(
                rid(0x40),
                mneme_core::RecordKind::Assertion,
            )],
        },
    );
    let summary = mneme_memory::build_proposed_assertion(
        rid(0x60),
        rev(0x61),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "summary",
            value: mneme_core::Value::string("summary claim"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                rid(0x32),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    harness.commit(
        "summary-ancestry",
        vec![evidence_s, premise, summary_evidence, summary],
        Vec::new(),
        None,
    );
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "forget-summary-ancestry",
        scope(),
    );
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let plan = retention.plan(request.clone()).expect("plan");
        let suppressed: std::collections::BTreeSet<_> = plan
            .suppressed
            .iter()
            .map(|suppression| suppression.target)
            .collect();
        assert!(suppressed.contains(&rid(0x30)));
        assert!(suppressed.contains(&rid(0x32)));
        assert!(suppressed.contains(&rid(0x60)));
        retention.execute(request).expect("forget");
    }
    {
        let memory =
            mneme_memory::Engine::new(&mut harness.workspace, mneme_memory::Access::Operator);
        let view = memory.view().expect("view");
        assert!(view.record(rid(0x32)).is_err());
        assert!(view.record(rid(0x60)).is_err());
    }
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source("source-s", 0x20, 0x21, &scope(), SOURCE_A);
    harness.add_source("source-t", 0x22, 0x23, &scope(), SOURCE_B);
    let evidence_s = mneme_memory::build_evidence(
        rid(0x30),
        rev(0x31),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: rid(0x40),
            source: rid(0x20),
            source_revision: rev(0x21),
            span: Some(span),
            anchor: Some("anchor-a"),
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let premise = mneme_memory::build_proposed_assertion(
        rid(0x40),
        rev(0x41),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "premise-one",
            value: mneme_core::Value::string("supported by S"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                rid(0x30),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    let summary_evidence = mneme_memory::build_evidence(
        rid(0x32),
        rev(0x33),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion: rid(0x60),
            source: rid(0x22),
            source_revision: rev(0x23),
            span: Some(span),
            anchor: Some("anchor-b"),
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[mneme_core::Reference::local(
                rid(0x40),
                mneme_core::RecordKind::Assertion,
            )],
        },
    );
    let summary = mneme_memory::build_proposed_assertion(
        rid(0x60),
        rev(0x61),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate: "summary",
            value: mneme_core::Value::string("summary claim"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                rid(0x32),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    harness.commit(
        "summary-ancestry-retract",
        vec![evidence_s, premise, summary_evidence, summary],
        Vec::new(),
        None,
    );
    let request = harness.request(
        mneme_retention::OperationKind::AssertionRetraction,
        mneme_retention::Selector::SourceSupport(rid(0x20)),
        "retract-summary-ancestry",
        scope(),
    );
    let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
    let plan = retention.plan(request).expect("retract plan");
    assert!(plan.withdrawn_evidence.contains(&rid(0x30)));
    assert!(plan.withdrawn_evidence.contains(&rid(0x32)));
    assert!(!plan.surviving_assertions.contains(&rid(0x60)));
}

#[test]
fn source_specific_forget_does_not_block_another_scope() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    {
        let (source, blob) = mneme_memory::build_source(
            rid(0x24),
            rev(0x25),
            &other_scope(),
            mneme_memory::SourceOptions {
                bytes: SOURCE_A,
                media_type: "text/asciidoc",
                entity: None,
                path_hint: None,
            },
        )
        .expect("shared source");
        let base = harness.workspace.current_revision().expect("base");
        harness
            .workspace
            .commit(mneme_store::CommitCommand {
                base,
                actor: "other-author".to_owned(),
                scope: other_scope(),
                idempotency_key: "shared-source".to_owned(),
                records: vec![source],
                source_blobs: vec![blob],
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("shared commit");
    }
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "scope-local-forget",
        scope(),
    );
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        retention.execute(request).expect("forget");
    }
    // The other scope keeps the same bytes and may still import them.
    let (source, blob) = mneme_memory::build_source(
        rid(0x26),
        rev(0x27),
        &other_scope(),
        mneme_memory::SourceOptions {
            bytes: SOURCE_A,
            media_type: "text/asciidoc",
            entity: None,
            path_hint: None,
        },
    )
    .expect("other scope source");
    let base = harness.workspace.current_revision().expect("base");
    harness
        .workspace
        .commit(mneme_store::CommitCommand {
            base,
            actor: "other-author".to_owned(),
            scope: other_scope(),
            idempotency_key: "other-scope-import".to_owned(),
            records: vec![source],
            source_blobs: vec![blob],
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("the other scope is unaffected");
}

#[test]
fn expiry_refuses_unknown_validity() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    let assertion = add_supported_assertion_with_valid_time(
        &mut harness,
        false,
        mneme_core::ValidTime::Unknown,
    );
    let effective = mneme_core::Timestamp::from_nanos(4_000);
    let mut request = harness.request(
        mneme_retention::OperationKind::ValidTimeExpiry,
        mneme_retention::Selector::Assertion(assertion),
        "expire-unknown",
        scope(),
    );
    request.effective = Some(effective);
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let error = retention
            .plan(request.clone())
            .expect_err("unknown validity");
        assert!(matches!(error, mneme_retention::PolicyError::Conflict(_)));
        let error = retention.execute(request).expect_err("unknown validity");
        assert!(matches!(error, mneme_retention::PolicyError::Conflict(_)));
    }
    let memory = mneme_memory::Engine::new(&mut harness.workspace, mneme_memory::Access::Operator);
    let view = memory.view().expect("view");
    assert_eq!(
        view.assertion(assertion).expect("assertion").valid_time,
        mneme_core::ValidTime::Unknown
    );
    assert!(
        view.current_beliefs(&mneme_memory::BeliefView {
            scope: scope(),
            at: mneme_core::Timestamp::from_nanos(0),
            include_hypothetical: false,
            include_disputed: false,
        })
        .expect("beliefs")
        .is_empty()
    );
}

#[test]
fn failed_cleanup_locations_are_retried_on_resume() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    let bytes = b"orphan cleanup payload";
    let digest = mneme_core::ContentDigest::of_source_bytes(bytes);
    mneme_store::payload::stage(harness.temp.path(), digest, bytes).expect("stage orphan");
    let location = mneme_store::RetentionLocationPlan {
        location_id: format!("source-blob:{}", digest.to_hex()),
        location_kind: "source-blob".to_owned(),
        locator: digest.to_hex(),
    };
    commit_barrier(
        &mut harness,
        "failed-cleanup",
        "retention-failed-cleanup",
        vec![location.clone()],
    );
    harness
        .workspace
        .verify_retention_location(
            "retention-failed-cleanup",
            &location.location_id,
            mneme_store::RetentionLocationState::Failed,
            Some("payload-removal-failed"),
        )
        .expect("record failure");
    let blob = mneme_store::payload::blob_path(harness.temp.path(), digest);
    assert!(blob.exists());
    {
        // A failed location is not settled, so resume must attempt it again.
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let result = retention
            .resume("retention-failed-cleanup")
            .expect("resume");
        assert!(result.physical_cleanup_complete, "{result:?}");
        assert_eq!(result.state, mneme_store::RetentionJobState::Complete);
    }
    assert_missing(&blob);
    let locations = harness
        .workspace
        .retention_locations("retention-failed-cleanup")
        .expect("locations");
    assert_eq!(locations[0].attempts, 2);
}

#[test]
fn idempotency_fingerprint_covers_effective_time_and_policy() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    let assertion = add_supported_assertion(&mut harness, false);
    let mut first = harness.request(
        mneme_retention::OperationKind::ValidTimeExpiry,
        mneme_retention::Selector::Assertion(assertion),
        "exp-1",
        scope(),
    );
    first.effective = Some(mneme_core::Timestamp::from_nanos(4_000));
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        retention.execute(first.clone()).expect("first expiry");
    }
    let revision = harness.workspace.current_revision().expect("revision");
    let mut changed_effective = first.clone();
    changed_effective.effective = Some(mneme_core::Timestamp::from_nanos(5_000));
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let error = retention
            .execute(changed_effective)
            .expect_err("a different effective time is a different request");
        assert!(matches!(
            error,
            mneme_retention::PolicyError::Store(mneme_store::Failure::IdempotencyConflict { .. })
        ));
    }
    let mut changed_policy = first.clone();
    changed_policy.policy.retain_assertion_after_prune = false;
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let error = retention
            .execute(changed_policy)
            .expect_err("a different policy is a different request");
        assert!(matches!(
            error,
            mneme_retention::PolicyError::Store(mneme_store::Failure::IdempotencyConflict { .. })
        ));
    }
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let error = retention
            .plan(first)
            .expect_err("a dry run with a used key reports the existing operation");
        assert!(matches!(error, mneme_retention::PolicyError::Conflict(_)));
    }
    assert_eq!(
        harness.workspace.current_revision().expect("revision"),
        revision,
        "a refused dry run and conflicting retries leave the workspace unchanged"
    );
}

#[test]
fn forget_inventories_registered_participants() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness
        .workspace
        .register_retention_participant(mneme_store::RetentionParticipant {
            name: "vector-cache".to_owned(),
            storage_role: "vector-index".to_owned(),
            supports_invalidation: true,
            supports_purge: true,
            checks_generation: true,
            inventory_locator: "cache/vectors".to_owned(),
        })
        .expect("participant");
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "forget-participant",
        scope(),
    );
    let result = {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let plan = retention.plan(request.clone()).expect("plan");
        assert!(
            plan.locations
                .iter()
                .any(|location| location.locator == "cache/vectors")
        );
        retention.execute(request).expect("forget")
    };
    assert!(!result.physical_cleanup_complete, "{result:?}");
    assert!(result.locations.iter().any(|location| {
        location.locator == "cache/vectors"
            && location.state == mneme_store::RetentionLocationState::Unavailable
    }));
}

#[test]
fn document_keyed_participant_files_are_purged() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness
        .workspace
        .register_retention_participant(mneme_store::RetentionParticipant {
            name: "mneme-desktop-drafts".to_owned(),
            storage_role: "document-keyed-files".to_owned(),
            supports_invalidation: true,
            supports_purge: true,
            checks_generation: true,
            inventory_locator: ".mneme-ui/drafts".to_owned(),
        })
        .expect("participant");
    harness
        .workspace
        .register_retention_participant(mneme_store::RetentionParticipant {
            name: "mneme-desktop-draft-sessions".to_owned(),
            storage_role: "document-session-files".to_owned(),
            supports_invalidation: true,
            supports_purge: true,
            checks_generation: true,
            inventory_locator: ".mneme-ui/drafts".to_owned(),
        })
        .expect("session participant");
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    harness.commit(
        "document",
        document_records(rid(0x20), rev(0x21)),
        Vec::new(),
        None,
    );
    let draft_directory = harness.temp.path().join(".mneme-ui/drafts");
    std::fs::create_dir_all(&draft_directory).expect("draft directory");
    let draft = draft_directory.join(format!("{}.json", rid(0x60).to_hex()));
    let temporary = draft_directory.join(format!("{}.json.tmp", rid(0x60).to_hex()));
    let quarantined = draft_directory.join(format!("{}.json.corrupt", rid(0x60).to_hex()));
    let other_document = draft_directory.join(format!("{}.json", rid(0x70).to_hex()));
    let session = rid(0x80).to_hex();
    let session_directory = draft_directory.join(rid(0x60).to_hex()).join(&session);
    std::fs::create_dir_all(&session_directory).expect("session directory");
    let session_final = session_directory.join("00000000000000000001.json");
    let session_temporary = session_directory.join("00000000000000000002.tmp");
    let session_quarantine = session_directory.join("00000000000000000003.corrupt");
    let session_lock = session_directory.join(".owner.lock");
    std::fs::write(&draft, b"{\"source\":\"= Secret Plan Beta\"}").expect("draft");
    std::fs::write(&temporary, b"post-flush temporary").expect("temporary");
    std::fs::write(&quarantined, b"quarantined source bytes").expect("quarantine");
    std::fs::write(&other_document, b"other document draft").expect("other document draft");
    std::fs::write(&session_final, b"session final text").expect("session final");
    std::fs::write(&session_temporary, b"session temporary text").expect("session temporary");
    std::fs::write(&session_quarantine, b"session quarantined text").expect("session quarantine");
    std::fs::write(&session_lock, b"").expect("session lock");
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "forget-drafts",
        scope(),
    );
    let result = {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let plan = retention.plan(request.clone()).expect("plan");
        assert!(plan.locations.iter().any(|location| {
            location.location_kind == "participant-file"
                && location.locator == format!(".mneme-ui/drafts/{}.json", rid(0x60).to_hex())
        }));
        for path in [
            ".owner.lock",
            "00000000000000000001.json",
            "00000000000000000002.tmp",
            "00000000000000000003.corrupt",
        ] {
            assert!(
                plan.locations.iter().any(|location| {
                    location.location_kind == "participant-file"
                        && location.locator
                            == format!(".mneme-ui/drafts/{}/{session}/{path}", rid(0x60).to_hex())
                }),
                "session artifact {path} must be individually inventoried"
            );
        }
        retention.execute(request).expect("forget")
    };
    assert!(result.physical_cleanup_complete, "{result:?}");
    assert_missing(&draft);
    assert_missing(&temporary);
    assert_missing(&quarantined);
    assert_missing(&session_final);
    assert_missing(&session_temporary);
    assert_missing(&session_quarantine);
    assert_missing(&session_lock);
    assert_eq!(
        std::fs::read(&other_document).expect("other document retained"),
        b"other document draft"
    );
}

#[test]
fn unknown_session_descendants_are_not_purged_or_reported_complete() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    for participant in [
        mneme_store::RetentionParticipant {
            name: "mneme-desktop-drafts".to_owned(),
            storage_role: "document-keyed-files".to_owned(),
            supports_invalidation: true,
            supports_purge: true,
            checks_generation: true,
            inventory_locator: ".mneme-ui/drafts".to_owned(),
        },
        mneme_store::RetentionParticipant {
            name: "mneme-desktop-draft-sessions".to_owned(),
            storage_role: "document-session-files".to_owned(),
            supports_invalidation: true,
            supports_purge: true,
            checks_generation: true,
            inventory_locator: ".mneme-ui/drafts".to_owned(),
        },
    ] {
        harness
            .workspace
            .register_retention_participant(participant)
            .expect("draft participant");
    }
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    harness.commit(
        "document",
        document_records(rid(0x20), rev(0x21)),
        Vec::new(),
        None,
    );
    let draft_root = harness.temp.path().join(".mneme-ui/drafts");
    let session_directory = draft_root.join(rid(0x60).to_hex()).join(rid(0x80).to_hex());
    std::fs::create_dir_all(&session_directory).expect("session directory");
    let known = session_directory.join("00000000000000000001.json");
    let unknown = session_directory.join("unrecognized-copy.bin");
    std::fs::write(&known, b"target draft").expect("known draft");
    std::fs::write(session_directory.join(".owner.lock"), b"").expect("owner lock");
    std::fs::write(&unknown, b"unknown retained bytes").expect("unknown artifact");

    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "forget-unknown-session-child",
        scope(),
    );
    let result = mneme_retention::Engine::new(&mut harness.workspace)
        .execute(request)
        .expect("honest incomplete cleanup result");

    assert!(!result.physical_cleanup_complete, "{result:?}");
    assert_missing(&known);
    assert_missing(&session_directory.join(".owner.lock"));
    assert_eq!(
        std::fs::read(&unknown).expect("unknown bytes preserved"),
        b"unknown retained bytes"
    );
}

#[test]
fn unregistered_descendants_beneath_mneme_ui_keep_cleanup_incomplete() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness
        .workspace
        .register_retention_participant(mneme_store::RetentionParticipant {
            name: "mneme-desktop-drafts".to_owned(),
            storage_role: "document-keyed-files".to_owned(),
            supports_invalidation: true,
            supports_purge: true,
            checks_generation: true,
            inventory_locator: ".mneme-ui/drafts".to_owned(),
        })
        .expect("participant");
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    let unknown = harness
        .temp
        .path()
        .join(".mneme-ui/unowned-cache/payload.json");
    std::fs::create_dir_all(unknown.parent().expect("unknown parent")).expect("unknown store");
    std::fs::write(&unknown, b"unregistered retained text").expect("unknown payload");

    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "forget-ui-descendant",
        scope(),
    );
    let result = mneme_retention::Engine::new(&mut harness.workspace)
        .execute(request)
        .expect("forget receipt");

    assert!(!result.physical_cleanup_complete, "{result:?}");
    assert_eq!(
        std::fs::read(&unknown).expect("unknown payload retained"),
        b"unregistered retained text"
    );
}

#[cfg(unix)]
#[test]
fn draft_participant_refuses_symlink_escape_without_following_it() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness
        .workspace
        .register_retention_participant(mneme_store::RetentionParticipant {
            name: "mneme-desktop-drafts".to_owned(),
            storage_role: "document-keyed-files".to_owned(),
            supports_invalidation: true,
            supports_purge: true,
            checks_generation: true,
            inventory_locator: ".mneme-ui/drafts".to_owned(),
        })
        .expect("participant");
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    harness.commit(
        "document",
        document_records(rid(0x20), rev(0x21)),
        Vec::new(),
        None,
    );
    let outside = tempfile::tempdir().expect("outside directory");
    let escaped = outside.path().join(format!("{}.json", rid(0x60).to_hex()));
    std::fs::write(&escaped, b"must not be followed or removed").expect("outside payload");
    let ui = harness.temp.path().join(".mneme-ui");
    std::fs::create_dir_all(&ui).expect("ui directory");
    std::os::unix::fs::symlink(outside.path(), ui.join("drafts")).expect("drafts symlink");

    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "forget-ui-symlink",
        scope(),
    );
    let result = mneme_retention::Engine::new(&mut harness.workspace)
        .execute(request)
        .expect("incomplete but truthful receipt");

    assert!(!result.physical_cleanup_complete, "{result:?}");
    assert!(
        std::fs::symlink_metadata(ui.join("drafts"))
            .expect("symlink remains")
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        std::fs::read(&escaped).expect("outside bytes preserved"),
        b"must not be followed or removed"
    );
}

#[test]
fn forget_removes_document_copies_of_the_source() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    let assertion = add_supported_assertion(&mut harness, false);
    harness.commit(
        "document-copies",
        document_records(rid(0x20), rev(0x21)),
        Vec::new(),
        None,
    );
    let annotation = mneme_memory::build_decision(
        rid(0x52),
        rev(0x53),
        &scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Other("annotation".to_owned()),
            target: assertion,
            actor: "author",
            policy: "test-policy/v1",
            input_revision: harness.workspace.current_revision().expect("base"),
            outcome: "noted",
            rationale: "a note about the claim",
            evidence: &[],
            related: &[],
        },
    );
    harness.commit("annotation", vec![annotation], Vec::new(), None);
    let records = harness
        .workspace
        .snapshot()
        .expect("snapshot")
        .records
        .iter()
        .filter(|record| [rid(0x60), rid(0x62), rid(0x64), rid(0x52)].contains(&record.record_id))
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 4);
    let old_revision = harness.workspace.current_revision().expect("old");
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "forget-documents",
        scope(),
    );
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let plan = retention.plan(request.clone()).expect("plan");
        let suppressed: std::collections::BTreeSet<_> = plan
            .suppressed
            .iter()
            .map(|suppression| suppression.target)
            .collect();
        for record in &records {
            assert!(
                suppressed.contains(&record.record_id),
                "document copy {record:?} must be forgotten"
            );
        }
        retention.execute(request).expect("forget");
    }
    for record in &records {
        assert_missing(&record_blob_path(&harness, record));
    }
    let memory = mneme_memory::Engine::new(&mut harness.workspace, mneme_memory::Access::Operator);
    let view = memory.view().expect("view");
    assert!(view.record(rid(0x60)).is_err());
    assert!(view.record(rid(0x62)).is_err());
    assert!(view.record(rid(0x64)).is_err());
    assert!(view.record(rid(0x52)).is_err());
    let historical = harness
        .workspace
        .snapshot_at(old_revision, None)
        .expect("historical");
    assert!(historical.records.iter().all(|record| {
        ![rid(0x60), rid(0x62), rid(0x64), rid(0x52)].contains(&record.record_id)
    }));
}

#[test]
fn copy_detection_reaches_a_fixpoint_independent_of_record_id_order() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    let episode = mneme_memory::build_episode(
        rid(0x70),
        rev(0x71),
        &scope(),
        mneme_memory::EpisodeOptions {
            actor: "author",
            episode_type: "statement",
            occurred: mneme_core::ValidTime::always(),
            summary: "observed in the forgotten source",
            source: Some(mneme_core::Reference::pinned(
                rid(0x20),
                rev(0x21),
                mneme_core::RecordKind::SourceRevision,
            )),
            related: &[],
        },
    );
    let checkpoint = mneme_memory::build_checkpoint(
        rid(0x72),
        rev(0x73),
        &scope(),
        mneme_memory::CheckpointOptions {
            goal: "resume the task",
            state: "planned",
            episodes: &[mneme_core::Reference::local(
                rid(0x70),
                mneme_core::RecordKind::Episode,
            )],
            verified_outcomes: &[],
            revision: harness.workspace.current_revision().expect("base"),
            note: Some("depends on the episode"),
        },
    );
    // The proposal sorts before the checkpoint it copies, which defeats a
    // single-pass traversal.
    let proposal = mneme_store::RecordDraft {
        schema_version: 1,
        kind: mneme_core::RecordKind::Proposal,
        record_id: rid(0x0a),
        revision_id: rev(0x09),
        predecessor: None,
        scope: scope(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("proposal-kind"),
                mneme_core::Value::symbol("summary"),
            ),
            (
                mneme_core::Symbol::from("candidate"),
                mneme_core::Value::record_named(
                    "candidate",
                    vec![
                        mneme_core::Reference::local(rid(0x72), mneme_core::RecordKind::Checkpoint)
                            .to_value(),
                        mneme_core::Value::string("summary repeating the checkpoint"),
                    ],
                ),
            ),
            (
                mneme_core::Symbol::from("rationale"),
                mneme_core::Value::string("copies the checkpoint"),
            ),
            (
                mneme_core::Symbol::from("status"),
                mneme_core::Value::symbol("proposed"),
            ),
        ]),
    };
    harness.commit(
        "copy-chain",
        vec![episode, checkpoint, proposal],
        Vec::new(),
        None,
    );
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "forget-copy-chain",
        scope(),
    );
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let plan = retention.plan(request.clone()).expect("plan");
        let suppressed: std::collections::BTreeSet<_> = plan
            .suppressed
            .iter()
            .map(|suppression| suppression.target)
            .collect();
        assert!(suppressed.contains(&rid(0x70)));
        assert!(suppressed.contains(&rid(0x72)));
        assert!(suppressed.contains(&rid(0x0a)));
        retention.execute(request).expect("forget");
    }
    let memory = mneme_memory::Engine::new(&mut harness.workspace, mneme_memory::Access::Operator);
    let view = memory.view().expect("view");
    assert!(view.record(rid(0x0a)).is_err());
    assert!(view.record(rid(0x72)).is_err());
}

#[test]
fn forgetting_a_source_purges_its_working_copy_even_when_bytes_are_shared() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source_with_file("source-file", 0x20, 0x21, "one.adoc", SOURCE_A);
    harness.add_source("source-copy", 0x22, 0x23, &scope(), SOURCE_A);
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "forget-shared-file",
        scope(),
    );
    let result = {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        retention.execute(request).expect("forget")
    };
    // The content-addressed blob is still needed by the other record, but the
    // path-addressed working copy belonged to the forgotten source only.
    assert!(result.cleanup.retained_shared > 0, "{result:?}");
    assert!(
        mneme_store::payload::read_working_file(harness.temp.path(), "one.adoc")
            .expect("working file")
            .is_none()
    );
    assert!(result.locations.iter().any(|location| {
        location.location_kind == "working-file"
            && location.state == mneme_store::RetentionLocationState::Purged
    }));
}

#[test]
fn staging_residue_is_inspected_and_purged() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    let staging = harness.temp.path().join("staging");
    std::fs::create_dir_all(&staging).expect("staging");
    let residue = staging.join(".mneme-tmp-0011223344556677");
    std::fs::write(&residue, SOURCE_A).expect("residue");
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "forget-staging-residue",
        scope(),
    );
    let result = {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        retention.execute(request).expect("forget")
    };
    assert!(result.physical_cleanup_complete, "{result:?}");
    assert_missing(&residue);
    assert!(result.locations.iter().any(|location| {
        location.location_kind == "staging"
            && location.state == mneme_store::RetentionLocationState::Purged
    }));
}

#[test]
fn a_published_copy_is_purged_and_its_intent_reported() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    let base = harness.workspace.current_revision().expect("base");
    harness
        .workspace
        .commit(mneme_store::CommitCommand {
            base,
            actor: "publisher".to_owned(),
            scope: scope(),
            idempotency_key: "published-copy".to_owned(),
            records: Vec::new(),
            source_blobs: Vec::new(),
            publications: vec![mneme_store::PublicationDraft {
                path: "pre.adoc".to_owned(),
                expected_previous: None,
                bytes: SOURCE_A.to_vec(),
            }],
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("published copy");
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "forget-published",
        scope(),
    );
    let result = {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let plan = retention.plan(request.clone()).expect("plan");
        assert!(
            plan.locations
                .iter()
                .any(|location| location.location_kind == "publication-intent")
        );
        retention.execute(request).expect("forget")
    };
    // The working copy is removed, but the recorded publication intent cannot
    // be un-published, so the receipt must not claim complete cleanup.
    assert!(
        mneme_store::payload::read_working_file(harness.temp.path(), "pre.adoc")
            .expect("working file")
            .is_none()
    );
    assert!(!result.physical_cleanup_complete, "{result:?}");
    assert!(result.locations.iter().any(|location| {
        location.location_kind == "publication-intent"
            && location.state == mneme_store::RetentionLocationState::Failed
            && location.detail_code.as_deref() == Some("publication-not-suppressed")
    }));
}

#[test]
fn forget_plan_declares_managed_working_paths() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source_with_file("source-file", 0x20, 0x21, "project.adoc", SOURCE_A);
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "forget-working-path",
        scope(),
    );
    let plan = {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        retention.plan(request.clone()).expect("plan")
    };
    assert!(
        plan.retained_metadata
            .iter()
            .any(|entry| entry == "managed-working-path")
    );
    assert!(
        plan.locations
            .iter()
            .any(|location| location.location_kind == "working-file")
    );
    let undeclared = mneme_store::RetentionCommit {
        operation_id: "retention-undeclared".to_owned(),
        operation_kind: "forget".to_owned(),
        policy_version: mneme_retention::POLICY_VERSION.to_owned(),
        selectors: Vec::new(),
        suppressions: Vec::new(),
        locations: vec![mneme_store::RetentionLocationPlan {
            location_id: "working-file:project.adoc".to_owned(),
            location_kind: "working-file".to_owned(),
            locator: format!("project.adoc#{}", plan.source_targets[0].to_hex()),
        }],
        retained_metadata: Vec::new(),
    };
    assert!(
        undeclared.validate().is_err(),
        "a plan that keeps a path hint must declare it"
    );
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let result = retention.execute(request).expect("forget");
        assert!(result.physical_cleanup_complete, "{result:?}");
    }
}

#[test]
fn cleanup_attempt_bound_is_reported_and_resumable() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    let attempts =
        usize::try_from(mneme_retention::MAX_CLEANUP_ATTEMPTS_PER_RUN).expect("attempt bound");
    let orphans = attempts + 4;
    let mut locations = Vec::with_capacity(orphans);
    let mut digests = Vec::with_capacity(orphans);
    for index in 0..orphans {
        let text = format!("orphan payload {index}");
        let digest = mneme_core::ContentDigest::of_source_bytes(text.as_bytes());
        mneme_store::payload::stage(harness.temp.path(), digest, text.as_bytes())
            .expect("stage orphan");
        locations.push(mneme_store::RetentionLocationPlan {
            location_id: format!("source-blob:{}", digest.to_hex()),
            location_kind: "source-blob".to_owned(),
            locator: digest.to_hex(),
        });
        digests.push(digest);
    }
    commit_barrier(&mut harness, "cleanup-bound", "retention-bound", locations);
    {
        let mut retention = mneme_retention::Engine::new(&mut harness.workspace);
        let result = retention.resume("retention-bound").expect("first run");
        assert!(!result.physical_cleanup_complete);
        assert!(
            result.cleanup.pending > 0,
            "the run stops at the attempt bound"
        );
        assert!(
            result
                .limitations
                .contains(&"cleanup-attempt-bound-reached".to_owned()),
            "{result:?}"
        );
        assert_eq!(result.state, mneme_store::RetentionJobState::CleanupPending);
        let result = retention.resume("retention-bound").expect("second run");
        assert!(result.physical_cleanup_complete, "{result:?}");
        assert!(
            !result
                .limitations
                .contains(&"cleanup-attempt-bound-reached".to_owned())
        );
    }
    for digest in &digests {
        assert_missing(&mneme_store::payload::blob_path(
            harness.temp.path(),
            *digest,
        ));
    }
}
