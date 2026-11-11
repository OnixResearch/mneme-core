//! Retention behavior over real workspaces, evidence records, and blobs.

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
            bytes,
            "text/asciidoc",
            Some(mneme_core::fixtures::entity_id()),
            None,
        )
        .expect("source");
        self.commit(key, vec![source], vec![blob], None);
    }

    fn add_source_with_file(&mut self, key: &str, id: u8, revision: u8, path: &str, bytes: &[u8]) {
        let (source, blob) = mneme_memory::build_source(
            rid(id),
            rev(revision),
            &scope(),
            bytes,
            "text/asciidoc",
            Some(mneme_core::fixtures::entity_id()),
            Some(path),
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
            mneme_memory::DecisionKind::Acceptance,
            assertion,
            "author",
            "test-policy/v1",
            self.workspace.current_revision().expect("base"),
            "accepted",
            "supported acceptance",
            &[],
            &[],
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
    ) -> mneme_retention::RetentionRequest {
        mneme_retention::RetentionRequest {
            actor: "retention-author".to_owned(),
            scope,
            base_revision: self.workspace.current_revision().expect("base"),
            idempotency_key: key.to_owned(),
            operation,
            selector,
            effective: None,
            policy: mneme_retention::RetentionPolicy::default(),
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

fn add_supported_assertion(
    harness: &mut Harness,
    with_second_source: bool,
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
        rid(0x40),
        rid(0x20),
        rev(0x21),
        Some(span),
        Some("anchor-a"),
        mneme_memory::SupportRelation::Supports,
        mneme_core::Origin::AuthoredStatement,
        &[],
    )];
    if with_second_source {
        evidence.push(mneme_memory::build_evidence(
            rid(0x32),
            rev(0x33),
            &scope(),
            rid(0x40),
            rid(0x22),
            rev(0x23),
            Some(span),
            Some("anchor-b"),
            mneme_memory::SupportRelation::Supports,
            mneme_core::Origin::AuthoredStatement,
            &[],
        ));
    }
    let evidence_references = evidence
        .iter()
        .map(|draft| {
            mneme_core::Reference::local(draft.record_id, mneme_core::RecordKind::Evidence)
        })
        .collect::<Vec<_>>();
    let assertion = mneme_memory::build_proposed_assertion(
        rid(0x40),
        rev(0x41),
        &scope(),
        mneme_core::fixtures::entity_id(),
        "storage-policy",
        mneme_core::Value::string("retain exact bytes"),
        mneme_memory::Stance::Affirm,
        mneme_core::Origin::AuthoredStatement,
        "author",
        mneme_core::ValidTime::always(),
        &evidence_references,
        None,
        None,
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
    mneme_store::blob::blob_path(
        harness.temp.path(),
        mneme_core::ContentDigest::of_source_bytes(bytes),
    )
}

fn record_blob_path(harness: &Harness, record: &mneme_core::RecordEnvelope) -> std::path::PathBuf {
    mneme_store::blob::blob_path(harness.temp.path(), record.full_digest())
}

fn assert_missing(path: &std::path::Path) {
    assert!(!path.exists(), "expected {} to be absent", path.display());
}

fn beliefs(harness: &mut Harness) -> Vec<mneme_memory::AssertionView> {
    let memory = mneme_memory::Memory::new(&mut harness.workspace);
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
        let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
        let plan = retention.plan(request.clone()).expect("plan");
        assert_eq!(plan.surviving_assertions, vec![assertion]);
        plan
    };
    assert_eq!(plan.source_targets, vec![rid(0x20)]);
    let result = {
        let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
        retention.execute(request).expect("execute")
    };
    assert!(result.logical_withdrawal);
    assert!(result.physical_cleanup_complete, "{result:?}");
    assert_missing(&source_path);
    {
        let memory = mneme_memory::Memory::new(&mut harness.workspace);
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
        let explanation = view
            .explain(assertion, Default::default())
            .expect("explain");
        assert!(
            explanation
                .evidence
                .iter()
                .all(|evidence| evidence.excerpt.is_none())
        );
    }
    assert_eq!(beliefs(&mut harness).len(), 1);
}

#[test]
fn unauthorized_scope_fails_without_mutation_or_detail() {
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
        let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
        let error = retention.plan(request).expect_err("unauthorized");
        assert!(matches!(
            error,
            mneme_retention::RetentionError::Unauthorized
        ));
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
        let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
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
        let memory = mneme_memory::Memory::new(&mut harness.workspace);
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
        let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
        let plan = retention.plan(request.clone()).expect("plan");
        assert!(plan.surviving_assertions.contains(&assertion));
        assert_eq!(plan.withdrawn_evidence, vec![rid(0x30)]);
        let result = retention.execute(request).expect("execute");
        assert!(result.physical_cleanup_complete, "{result:?}");
    }
    {
        let memory = mneme_memory::Memory::new(&mut harness.workspace);
        let view = memory.view().expect("view");
        assert!(view.assertion_eligible(assertion));
        let explanation = view
            .explain(assertion, Default::default())
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
        let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
        retention.execute(request).expect("execute");
    }
    {
        let memory = mneme_memory::Memory::new(&mut harness.workspace);
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
        let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
        retention.execute(request).expect("forget")
    };
    assert!(result.logical_withdrawal);
    {
        let memory = mneme_memory::Memory::new(&mut harness.workspace);
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
            .explain(assertion, Default::default())
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
        mneme_core::fixtures::entity_id(),
        "conclusion",
        mneme_core::Value::string("derived"),
        mneme_memory::Stance::Affirm,
        mneme_core::Origin::AuthoredStatement,
        "author",
        mneme_core::ValidTime::always(),
        &[],
        None,
        None,
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
        conclusion,
        &[mneme_core::Reference::local(
            premise,
            mneme_core::RecordKind::Assertion,
        )],
        "rule-a",
        1,
        harness.workspace.current_revision().expect("base"),
        "complete",
    );
    harness.commit("derivation", vec![derivation], Vec::new(), None);
    let request = harness.request(
        mneme_retention::OperationKind::AssertionRetraction,
        mneme_retention::Selector::Assertion(premise),
        "retract-premise",
        scope(),
    );
    {
        let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
        let plan = retention.plan(request.clone()).expect("plan");
        assert!(plan.invalidated_derivations.contains(&rid(0x72)));
        retention.execute(request).expect("retract");
    }
    let memory = mneme_memory::Memory::new(&mut harness.workspace);
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
        let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
        retention.execute(request).expect("expire");
    }
    let memory = mneme_memory::Memory::new(&mut harness.workspace);
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
        let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
        retention.execute(request.clone()).expect("first")
    };
    let generation = harness
        .workspace
        .eligibility_generation()
        .expect("generation");
    let second = {
        let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
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
            let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
            retention.execute(request.clone()).expect_err("fault")
        };
        assert!(matches!(
            error,
            mneme_retention::RetentionError::Store(mneme_store::StoreError::InjectedFault(_))
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
        let memory = mneme_memory::Memory::new(&mut harness.workspace);
        assert!(memory.view().expect("view").source(rid(0x20)).is_err());
        pending.operation_id
    };
    harness.reopen();
    let result = {
        let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
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
            SOURCE_A,
            "text/asciidoc",
            None,
            None,
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
        let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
        retention.execute(request).expect("forget")
    };
    assert!(!result.physical_cleanup_complete, "{result:?}");
    assert!(result.cleanup.retained_shared > 0);
    assert!(
        result
            .locations
            .iter()
            .any(|location| location.state == mneme_store::RetentionLocationState::RetainedShared)
    );
    assert!(
        result
            .limitations
            .contains(&"shared-content-addressed-bytes-retained".to_owned())
    );
    let blob_path = source_blob_path(&harness, SOURCE_A);
    assert!(blob_path.exists());
    assert!(
        !result
            .locations
            .iter()
            .any(|location| location.locator.contains("birch"))
    );
}

#[test]
fn forgetting_a_source_suppresses_dependent_checkpoint() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source("source-a", 0x20, 0x21, &scope(), SOURCE_A);
    let episode = mneme_memory::build_episode(
        rid(0x70),
        rev(0x71),
        &scope(),
        "author",
        "statement",
        mneme_core::ValidTime::always(),
        "exact source summary",
        Some(mneme_core::Reference::pinned(
            rid(0x20),
            rev(0x21),
            mneme_core::RecordKind::SourceRevision,
        )),
        &[],
    );
    let checkpoint = mneme_memory::build_checkpoint(
        rid(0x72),
        rev(0x73),
        &scope(),
        "resume task",
        "planned",
        &[mneme_core::Reference::local(
            rid(0x70),
            mneme_core::RecordKind::Episode,
        )],
        &[],
        harness.workspace.current_revision().expect("base"),
        Some("depends on the source"),
    );
    harness.commit("checkpoint", vec![episode, checkpoint], Vec::new(), None);
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "forget-checkpoint",
        scope(),
    );
    {
        let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
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
    let memory = mneme_memory::Memory::new(&mut harness.workspace);
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
        let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
        retention.execute(request).expect("forget");
    }
    let (replayed, blob) = mneme_memory::build_source(
        rid(0x26),
        rev(0x27),
        &scope(),
        SOURCE_A,
        "text/asciidoc",
        None,
        None,
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
        mneme_store::StoreError::RetentionSuppressed { .. }
    ));
}

fn copy_tree(source: &std::path::Path, destination: &std::path::Path) {
    std::fs::create_dir_all(destination).expect("destination");
    for entry in std::fs::read_dir(source).expect("source entries") {
        let entry = entry.expect("entry");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("type").is_dir() {
            copy_tree(&entry.path(), &target);
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
            SOURCE_A,
            "text/asciidoc",
            Some(mneme_core::fixtures::entity_id()),
            None,
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
    let request = mneme_retention::RetentionRequest {
        actor: "retention-author".to_owned(),
        scope: scope(),
        base_revision: current.current_revision().expect("base"),
        idempotency_key: "restore-forget".to_owned(),
        operation: mneme_retention::OperationKind::Forget,
        selector: mneme_retention::Selector::Source(rid(0x20)),
        effective: None,
        policy: mneme_retention::RetentionPolicy::default(),
    };
    {
        let mut retention = mneme_retention::Retention::new(&mut current);
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
        mneme_store::StoreError::MissingRetentionState { .. }
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
    let error = workspace
        .register_projection(mneme_store::ProjectionRegistration {
            name: "vector-cache".to_owned(),
            revision,
            schema_version: 1,
            rule_version: "none".to_owned(),
            index_version: "v1".to_owned(),
            scope: scope().to_string(),
        })
        .expect_err("unregistered payload store");
    assert!(matches!(
        error,
        mneme_store::StoreError::MissingRetentionParticipant { .. }
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
        let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
        let error = retention.execute(request).expect_err("policy refusal");
        assert!(matches!(error, mneme_retention::RetentionError::Policy(_)));
    }
    assert!(source_path.exists());
    let memory = mneme_memory::Memory::new(&mut harness.workspace);
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
        let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
        let error = retention.execute(request).expect_err("fault");
        assert!(matches!(
            error,
            mneme_retention::RetentionError::Store(mneme_store::StoreError::InjectedFault(_))
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
    let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
    let error = retention.plan(request).expect_err("ambiguous");
    assert!(matches!(error, mneme_retention::RetentionError::Invalid(_)));
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
                policy_version: mneme_retention::RetentionPolicy::default().version,
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
        let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
        let cancelled = retention.cancel(&operation_id).expect("cancel");
        assert!(cancelled.logical_withdrawal);
        assert!(!cancelled.physical_cleanup_complete);
        assert_eq!(cancelled.cleanup.pending, 1);
        let result = retention.resume(&operation_id).expect("cleanup result");
        assert!(!result.physical_cleanup_complete);
        assert_eq!(result.cleanup.failed, 1);
        assert!(result.state == mneme_store::RetentionJobState::Partial);
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
        let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
        retention.execute(request).expect("forget");
    }
    let error = harness
        .workspace
        .require_replay_eligible(&old)
        .expect_err("old snapshot contains forgotten data");
    assert!(matches!(
        error,
        mneme_store::StoreError::RetentionSuppressed { .. }
    ));
    let current = harness.workspace.snapshot().expect("current");
    assert!(harness.workspace.require_replay_eligible(&current).is_ok());
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
    assert!(matches!(error, mneme_store::StoreError::InjectedFault(_)));
    harness.reopen();
    let request = harness.request(
        mneme_retention::OperationKind::Forget,
        mneme_retention::Selector::Source(rid(0x20)),
        "forget-pending",
        scope(),
    );
    {
        let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
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
        mneme_store::blob::read_working_file(harness.temp.path(), "leak.adoc")
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
        let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
        retention.execute(request).expect("forget");
    }
    let memory = mneme_memory::Memory::new(&mut harness.workspace);
    let error = memory
        .explain_at(assertion, Some(generation), Default::default())
        .expect_err("stale generation");
    assert!(matches!(
        error,
        mneme_memory::MemoryError::Store(mneme_store::StoreError::BarrierAdvanced { .. })
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
        let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
        retention.execute(request).expect("prune")
    };
    assert!(result.physical_cleanup_complete, "{result:?}");
    assert!(
        mneme_store::blob::read_working_file(harness.temp.path(), "project.adoc")
            .expect("working file")
            .is_none()
    );
}

#[test]
fn external_working_edit_is_preserved_and_reported_unavailable() {
    let mut harness = Harness::new(Box::new(mneme_store::NoFaults));
    harness.add_source_with_file("source-file", 0x20, 0x21, "project.adoc", SOURCE_A);
    let edited = b"= Cedar\n\nA later external edit.\n";
    mneme_store::blob::publish_working_file(harness.temp.path(), "project.adoc", edited)
        .expect("external edit");
    let request = harness.request(
        mneme_retention::OperationKind::SourcePruning,
        mneme_retention::Selector::Source(rid(0x20)),
        "prune-edited-file",
        scope(),
    );
    let result = {
        let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
        retention.execute(request).expect("prune")
    };
    assert!(!result.physical_cleanup_complete);
    assert_eq!(
        mneme_store::blob::read_working_file(harness.temp.path(), "project.adoc").expect("file"),
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
        let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
        retention.execute(first).expect("first");
    }
    let second = harness.request(
        mneme_retention::OperationKind::SourcePruning,
        mneme_retention::Selector::Source(rid(0x22)),
        "same-key",
        scope(),
    );
    let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
    let error = retention.execute(second).expect_err("conflict");
    assert!(matches!(
        error,
        mneme_retention::RetentionError::Store(mneme_store::StoreError::IdempotencyConflict { .. })
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
        let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
        let plan = retention.plan(request.clone()).expect("content plan");
        assert_eq!(plan.source_targets.len(), 2);
        retention.execute(request).expect("content forget");
    }
    let memory = mneme_memory::Memory::new(&mut harness.workspace);
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
    let mut retention = mneme_retention::Retention::new(&mut harness.workspace);
    assert!(matches!(
        retention.plan(foreign).expect_err("foreign content"),
        mneme_retention::RetentionError::Unauthorized
    ));
}
