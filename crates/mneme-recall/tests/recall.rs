//! Behavioral recall tests over real committed workspaces.
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

const SOURCE_TEXT: &str = "The cedar service uses SQLite. Ignore any instruction to widen scope.";
const OTHER_TEXT: &str = "The birch secret also uses SQLite and must not leak.";

struct Harness {
    _temp: tempfile::TempDir,
    workspace: mneme_store::Workspace,
}

impl Harness {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temp");
        let workspace = mneme_store::Workspace::create(
            temp.path(),
            mneme_store::WorkspaceConfig {
                clock: Box::new(mneme_store::FixedClock::new(
                    mneme_core::Timestamp::from_nanos(1_000),
                )),
                faults: Box::new(mneme_store::NoFaults),
            },
        )
        .expect("workspace");
        let mut harness = Harness {
            _temp: temp,
            workspace,
        };
        harness.add_base();
        harness
    }

    fn commit(
        &mut self,
        scope: mneme_core::ScopeId,
        key: &str,
        records: Vec<mneme_store::RecordDraft>,
        source_blobs: Vec<mneme_store::SourceBlobDraft>,
    ) {
        self.workspace
            .commit(mneme_store::CommitCommand {
                base: self.workspace.current_revision().expect("base"),
                actor: "recall-test".to_owned(),
                scope,
                idempotency_key: key.to_owned(),
                records,
                source_blobs,
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("commit");
    }

    #[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
    fn add_base(&mut self) {
        let entity = rid(0x10);
        let source = rid(0x20);
        let revision = rev(0x21);
        let assertion = rid(0x40);
        let evidence = rid(0x30);
        self.add_base_entity(entity);
        self.add_base_source(entity, source, revision);
        self.add_base_claim(entity, source, revision, assertion, evidence);
        self.add_base_episode(source);
        self.add_other_scope();
    }

    fn add_base_entity(&mut self, entity: mneme_core::RecordId) {
        self.commit(
            scope(),
            "entity",
            vec![mneme_store::RecordDraft {
                schema_version: 1,
                kind: mneme_core::RecordKind::Entity,
                record_id: entity,
                revision_id: rev(0x11),
                predecessor: None,
                scope: scope(),
                payload: entity_payload("Cedar"),
            }],
            Vec::new(),
        );
    }

    fn add_base_source(
        &mut self,
        entity: mneme_core::RecordId,
        source: mneme_core::RecordId,
        revision: mneme_core::RevisionId,
    ) {
        let (source_record, source_blob) = mneme_memory::build_source(
            source,
            revision,
            &scope(),
            mneme_memory::SourceOptions {
                bytes: SOURCE_TEXT.as_bytes(),
                media_type: "text/plain",
                entity: Some(entity),
                path_hint: Some("docs/cedar.txt"),
            },
        )
        .expect("source");
        self.commit(scope(), "source", vec![source_record], vec![source_blob]);
    }

    fn add_base_claim(
        &mut self,
        entity: mneme_core::RecordId,
        source: mneme_core::RecordId,
        revision: mneme_core::RevisionId,
        assertion: mneme_core::RecordId,
        evidence: mneme_core::RecordId,
    ) {
        let evidence_record = mneme_memory::build_evidence(
            evidence,
            rev(0x31),
            &scope(),
            mneme_memory::EvidenceOptions {
                assertion,
                source,
                source_revision: revision,
                span: Some(
                    mneme_core::SourceSpan::new(0, SOURCE_TEXT.len() as u64 - 1).expect("span"),
                ),
                anchor: Some("deployment"),
                relation: mneme_memory::SupportRelation::Supports,
                origin: mneme_core::Origin::AuthoredStatement,
                ancestry: &[],
            },
        );
        let proposed = mneme_memory::build_proposed_assertion(
            assertion,
            rev(0x41),
            &scope(),
            mneme_memory::ProposedAssertionOptions {
                subject: entity,
                predicate: "deployment",
                value: mneme_core::Value::string("SQLite"),
                stance: mneme_memory::Stance::Affirm,
                origin: mneme_core::Origin::AuthoredStatement,
                asserted_by: "author",
                valid_time: mneme_core::ValidTime::always(),
                evidence: &[mneme_core::Reference::local(
                    evidence,
                    mneme_core::RecordKind::Evidence,
                )],
                extraction: None,
                superseded_by: None,
            },
        );
        self.commit(
            scope(),
            "claim",
            vec![evidence_record, proposed],
            Vec::new(),
        );
        self.accept(assertion, 0x50, 0x51, 0x42);
    }

    fn add_base_episode(&mut self, source: mneme_core::RecordId) {
        let episode = mneme_memory::build_episode(
            rid(0x60),
            rev(0x61),
            &scope(),
            mneme_memory::EpisodeOptions {
                actor: "agent",
                episode_type: "observation",
                occurred: mneme_core::ValidTime::always(),
                summary: "Cedar episode records a SQLite rollout without embeddings",
                source: Some(mneme_core::Reference::local(
                    source,
                    mneme_core::RecordKind::SourceRevision,
                )),
                related: &[],
            },
        );
        self.commit(scope(), "episode", vec![episode], Vec::new());
    }

    #[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
    fn add_other_scope(&mut self) {
        let entity = rid(0x70);
        let source = rid(0x72);
        let revision = rev(0x73);
        let assertion = rid(0x80);
        let evidence = rid(0x74);
        self.add_other_entity(entity);
        self.add_other_source(entity, source, revision);
        self.add_other_claim(entity, source, revision, assertion, evidence);
        self.accept_in_scope(assertion, 0x90, 0x91, 0x82, other_scope());
    }

    fn add_other_entity(&mut self, entity: mneme_core::RecordId) {
        self.commit(
            other_scope(),
            "other-entity",
            vec![mneme_store::RecordDraft {
                schema_version: 1,
                kind: mneme_core::RecordKind::Entity,
                record_id: entity,
                revision_id: rev(0x71),
                predecessor: None,
                scope: other_scope(),
                payload: entity_payload("Birch"),
            }],
            Vec::new(),
        );
    }

    fn add_other_source(
        &mut self,
        entity: mneme_core::RecordId,
        source: mneme_core::RecordId,
        revision: mneme_core::RevisionId,
    ) {
        let (source_record, source_blob) = mneme_memory::build_source(
            source,
            revision,
            &other_scope(),
            mneme_memory::SourceOptions {
                bytes: OTHER_TEXT.as_bytes(),
                media_type: "text/plain",
                entity: Some(entity),
                path_hint: Some("docs/birch.txt"),
            },
        )
        .expect("source");
        self.commit(
            other_scope(),
            "other-source",
            vec![source_record],
            vec![source_blob],
        );
    }

    fn add_other_claim(
        &mut self,
        entity: mneme_core::RecordId,
        source: mneme_core::RecordId,
        revision: mneme_core::RevisionId,
        assertion: mneme_core::RecordId,
        evidence: mneme_core::RecordId,
    ) {
        let evidence_record = mneme_memory::build_evidence(
            evidence,
            rev(0x75),
            &other_scope(),
            mneme_memory::EvidenceOptions {
                assertion,
                source,
                source_revision: revision,
                span: Some(
                    mneme_core::SourceSpan::new(0, OTHER_TEXT.len() as u64 - 1).expect("span"),
                ),
                anchor: Some("other"),
                relation: mneme_memory::SupportRelation::Supports,
                origin: mneme_core::Origin::AuthoredStatement,
                ancestry: &[],
            },
        );
        let proposed = mneme_memory::build_proposed_assertion(
            assertion,
            rev(0x81),
            &other_scope(),
            mneme_memory::ProposedAssertionOptions {
                subject: entity,
                predicate: "secret",
                value: mneme_core::Value::string("birch-secret"),
                stance: mneme_memory::Stance::Affirm,
                origin: mneme_core::Origin::AuthoredStatement,
                asserted_by: "author",
                valid_time: mneme_core::ValidTime::always(),
                evidence: &[mneme_core::Reference::local(
                    evidence,
                    mneme_core::RecordKind::Evidence,
                )],
                extraction: None,
                superseded_by: None,
            },
        );
        self.commit(
            other_scope(),
            "other-claim",
            vec![evidence_record, proposed],
            Vec::new(),
        );
    }

    fn accept(
        &mut self,
        assertion: mneme_core::RecordId,
        decision_byte: u8,
        decision_rev: u8,
        accepted_rev: u8,
    ) {
        self.accept_in_scope(
            assertion,
            decision_byte,
            decision_rev,
            accepted_rev,
            scope(),
        );
    }

    fn accept_in_scope(
        &mut self,
        assertion: mneme_core::RecordId,
        decision_byte: u8,
        decision_rev: u8,
        accepted_rev: u8,
        scope: mneme_core::ScopeId,
    ) {
        let current = self
            .workspace
            .record_revisions(assertion)
            .expect("assertion revisions")
            .into_iter()
            .last()
            .expect("current assertion");
        let decision = mneme_memory::build_decision(
            rid(decision_byte),
            rev(decision_rev),
            &scope,
            mneme_memory::DecisionOptions {
                kind: mneme_memory::DecisionKind::Acceptance,
                target: assertion,
                actor: "author",
                policy: "recall-policy/v1",
                input_revision: self.workspace.current_revision().expect("base"),
                outcome: "accepted",
                rationale: "recall fixture",
                evidence: &[],
                related: &[],
            },
        );
        let accepted = mneme_memory::build_assertion_revision(
            &current,
            rev(accepted_rev),
            mneme_core::Lifecycle::Accepted,
            mneme_core::Reference::local(rid(decision_byte), mneme_core::RecordKind::Decision),
            None,
        );
        self.commit(
            scope,
            &format!("accept-{decision_byte}"),
            vec![decision, accepted],
            Vec::new(),
        );
    }

    fn add_copied_claim(&mut self) {
        let assertion = rid(0x42);
        let evidence = rid(0x32);
        let evidence_record = mneme_memory::build_evidence(
            evidence,
            rev(0x33),
            &scope(),
            mneme_memory::EvidenceOptions {
                assertion,
                source: rid(0x20),
                source_revision: rev(0x21),
                span: Some(
                    mneme_core::SourceSpan::new(0, SOURCE_TEXT.len() as u64 - 1).expect("span"),
                ),
                anchor: Some("copied"),
                relation: mneme_memory::SupportRelation::Supports,
                origin: mneme_core::Origin::AuthoredStatement,
                ancestry: &[],
            },
        );
        let proposed = mneme_memory::build_proposed_assertion(
            assertion,
            rev(0x43),
            &scope(),
            mneme_memory::ProposedAssertionOptions {
                subject: rid(0x10),
                predicate: "summary",
                value: mneme_core::Value::string("Cedar deployment uses SQLite"),
                stance: mneme_memory::Stance::Affirm,
                origin: mneme_core::Origin::AuthoredStatement,
                asserted_by: "author",
                valid_time: mneme_core::ValidTime::always(),
                evidence: &[mneme_core::Reference::local(
                    evidence,
                    mneme_core::RecordKind::Evidence,
                )],
                extraction: None,
                superseded_by: None,
            },
        );
        self.commit(
            scope(),
            "copied",
            vec![evidence_record, proposed],
            Vec::new(),
        );
        self.accept(assertion, 0x52, 0x53, 0x44);
    }

    fn request(&self, query: &str) -> mneme_recall::RecallRequest {
        mneme_recall::RecallRequest::lexical(
            "recall-test",
            scope(),
            self.workspace.current_revision().expect("revision"),
            mneme_core::Timestamp::from_nanos(2_000),
            query,
        )
    }
}

fn entity_payload(label: &str) -> mneme_core::Payload {
    mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("entity-type"),
            mneme_core::Value::symbol("project"),
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

fn atom(predicate: &str, terms: Vec<mneme_datalog::Term>) -> mneme_datalog::Atom {
    mneme_datalog::Atom::new(predicate, terms)
}

fn var(name: &str) -> mneme_datalog::Term {
    mneme_datalog::Term::var(name)
}

fn constant(value: mneme_core::Value) -> mneme_datalog::Term {
    mneme_datalog::Term::constant(value)
}

fn claim_bundle() -> mneme_datalog::RuleBundle {
    mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "recall".to_owned(),
        version: "1".to_owned(),
        schema_version: 3,
        base_predicates: std::collections::BTreeMap::from([("assertion".to_owned(), 4)]),
        complete_predicates: std::collections::BTreeSet::from(["assertion".to_owned()]),
        rules: vec![mneme_datalog::Rule::new(
            "claim",
            atom("claim", vec![var("subject"), var("value")]),
            vec![mneme_datalog::Literal::Positive(atom(
                "assertion",
                vec![
                    var("subject"),
                    constant(mneme_core::Value::symbol("deployment")),
                    var("value"),
                    var("id"),
                ],
            ))],
        )],
    })
}

#[test]
fn lexical_source_quote_and_claim_keep_exact_provenance() {
    let mut harness = Harness::new();
    let request = harness.request("SQLite");
    let revision = request.revision;
    let mut service = mneme_recall::RecallService::new(&mut harness.workspace);
    let response = service.recall(request).expect("recall");
    assert_eq!(response.context.requested_revision, revision);
    assert_eq!(response.context.served_revision, revision);
    assert!(!response.exhaustive);
    assert!(!response.absence_established);
    assert!(
        response
            .candidates
            .iter()
            .any(
                |candidate| candidate.content_kind == mneme_recall::ContentKind::Claim
                    && candidate.claim_status.is_some()
            )
    );
    let source = response
        .candidates
        .iter()
        .find(|candidate| candidate.content_kind == mneme_recall::ContentKind::SourceExcerpt)
        .expect("source candidate");
    assert!(source.text.contains("SQLite"));
    assert_eq!(source.source, Some(rid(0x20)));
    let span = source.span.expect("exact span");
    assert_eq!(
        &SOURCE_TEXT.as_bytes()[usize::try_from(span.start()).expect("span start")
            ..=usize::try_from(span.end()).expect("span end")],
        source.text.as_bytes()
    );
    assert!(response.boundary.instructions_are_data);
    assert!(!response.boundary.may_change_scope);
}

#[test]
fn scope_and_empty_search_do_not_claim_absence() {
    let mut harness = Harness::new();
    let excluded_request = harness.request("birch");
    let empty_request = harness.request("zebra");
    let mut service = mneme_recall::RecallService::new(&mut harness.workspace);
    let excluded = service.recall(excluded_request).expect("scope query");
    assert!(excluded.candidates.is_empty());
    assert_eq!(excluded.status, mneme_recall::RecallExecution::Complete);
    assert!(!excluded.exhaustive);
    assert!(!excluded.absence_established);

    let empty = service.recall(empty_request).expect("empty query");
    assert!(empty.candidates.is_empty());
    assert_eq!(empty.status, mneme_recall::RecallExecution::Complete);
    assert!(!empty.exhaustive);
    assert!(!empty.absence_established);
}

#[test]
fn local_vector_mode_recalls_approximate_terms() {
    let mut harness = Harness::new();
    let mut request = harness.request("SQlitee");
    request.modes = std::collections::BTreeSet::from([mneme_recall::RecallMode::Vector]);
    let response = mneme_recall::RecallService::new(&mut harness.workspace)
        .recall(request)
        .expect("vector recall");
    assert!(
        response
            .modes
            .iter()
            .any(|mode| mode.mode == mneme_recall::RecallMode::Vector
                && mode.status == mneme_recall::ModeStatus::Used)
    );
    assert!(!response.candidates.is_empty());
    assert!(!response.exhaustive);
}

#[test]
fn budget_truncation_keeps_source_span_and_reports_omissions() {
    let mut harness = Harness::new();
    let mut request = harness.request("cedar service");
    request.max_context_bytes = 32;
    request.max_quote_bytes = 100;
    let response = mneme_recall::RecallService::new(&mut harness.workspace)
        .recall(request)
        .expect("budget recall");
    let source = response
        .candidates
        .iter()
        .find(|candidate| candidate.content_kind == mneme_recall::ContentKind::SourceExcerpt)
        .expect("truncated source");
    assert!(source.text_truncated);
    assert_eq!(
        &SOURCE_TEXT.as_bytes()[usize::try_from(source.span.expect("span").start())
            .expect("span start")
            ..=usize::try_from(source.span.expect("span").end()).expect("span end")],
        source.text.as_bytes()
    );
    assert!(response.truncated);

    let mut item_limited = harness.request("SQLite");
    item_limited.max_items = 1;
    let response = mneme_recall::RecallService::new(&mut harness.workspace)
        .recall(item_limited)
        .expect("item recall");
    assert_eq!(response.candidates.len(), 1);
    assert!(!response.omissions.is_empty());
}

#[test]
fn shared_ancestry_is_not_counted_as_independent_claims() {
    let mut harness = Harness::new();
    harness.add_copied_claim();
    let request = harness.request("SQLite");
    let response = mneme_recall::RecallService::new(&mut harness.workspace)
        .recall(request)
        .expect("ancestry recall");
    let claims = response
        .candidates
        .iter()
        .filter(|candidate| candidate.content_kind == mneme_recall::ContentKind::Claim)
        .collect::<Vec<_>>();
    assert!(claims.len() >= 2);
    assert_eq!(
        claims
            .iter()
            .filter(|candidate| candidate.independent_support)
            .count(),
        1
    );
}

#[test]
fn structured_candidates_keep_datalog_coverage_and_derivations() {
    let mut harness = Harness::new();
    let mut request = harness.request("SQLite");
    request.modes = std::collections::BTreeSet::from([
        mneme_recall::RecallMode::Lexical,
        mneme_recall::RecallMode::Structured,
    ]);
    request.structured = Some(mneme_recall::StructuredRequest {
        bundle: claim_bundle(),
        query: mneme_datalog::Query::all("claim", 10),
        limits: mneme_datalog::Limits {
            max_work: 100_000,
            max_time_ms: 2_000,
            max_result_rows: 1_000,
            max_supports_per_fact: 8,
            max_recursion_depth: 32,
        },
        incomplete_extents: std::collections::BTreeSet::new(),
    });
    let response = mneme_recall::RecallService::new(&mut harness.workspace)
        .recall(request)
        .expect("structured recall");
    let structured = response
        .candidates
        .iter()
        .find(|candidate| candidate.content_kind == mneme_recall::ContentKind::StructuredRow)
        .expect("structured candidate");
    assert!(!structured.derivations.is_empty());
    let mode = response
        .modes
        .iter()
        .find(|mode| mode.mode == mneme_recall::RecallMode::Structured)
        .expect("structured mode");
    assert_eq!(mode.relation_exhaustive, Some(true));
    assert!(mode.coverage.complete);
}

#[test]
fn stale_revision_disclosure_is_explicit() {
    let mut harness = Harness::new();
    let old = harness.workspace.current_revision().expect("old");
    harness.commit(
        scope(),
        "later-entity",
        vec![mneme_store::RecordDraft {
            schema_version: 1,
            kind: mneme_core::RecordKind::Entity,
            record_id: rid(0xa0),
            revision_id: rev(0xa1),
            predecessor: None,
            scope: scope(),
            payload: entity_payload("Later"),
        }],
        Vec::new(),
    );
    let mut request = harness.request("SQLite");
    request.revision = old;
    request.allow_stale = false;
    assert!(matches!(
        mneme_recall::RecallService::new(&mut harness.workspace).recall(request.clone()),
        Err(mneme_recall::RecallError::StaleRevision { .. })
    ));
    request.allow_stale = true;
    let response = mneme_recall::RecallService::new(&mut harness.workspace)
        .recall(request)
        .expect("stale recall");
    assert_eq!(response.context.requested_revision, old);
    assert_eq!(response.context.served_revision, old);
    assert_ne!(
        response.context.served_revision,
        harness.workspace.current_revision().expect("new")
    );
}

#[test]
fn forget_invalidates_warm_index_and_removes_source_candidates() {
    let mut harness = Harness::new();
    let warm_request = harness.request("widen scope");
    let first = mneme_recall::RecallService::new(&mut harness.workspace)
        .recall(warm_request)
        .expect("warm recall");
    assert!(!first.candidates.is_empty());
    let request = mneme_retention::RetentionRequest {
        actor: "recall-test".to_owned(),
        scope: scope(),
        base_revision: harness.workspace.current_revision().expect("base"),
        idempotency_key: "forget-recall-source".to_owned(),
        operation: mneme_retention::OperationKind::Forget,
        selector: mneme_retention::Selector::Source(rid(0x20)),
        effective: None,
        policy: mneme_retention::RetentionPolicy {
            version: mneme_retention::POLICY_VERSION.to_owned(),
            retain_assertion_after_prune: true,
            block_content_replay: true,
            retain_withdrawn_evidence_metadata: true,
        },
    };
    mneme_retention::Retention::new(&mut harness.workspace)
        .execute(request)
        .expect("forget");
    let after_request = harness.request("widen scope");
    let after = mneme_recall::RecallService::new(&mut harness.workspace)
        .recall(after_request)
        .expect("post-forget recall");
    assert!(after.candidates.is_empty());
    assert!(
        after
            .candidates
            .iter()
            .all(|candidate| candidate.source != Some(rid(0x20)))
    );
}

#[test]
fn historical_inspection_preserves_superseded_unknown_time() {
    let mut harness = Harness::new();
    let assertion = rid(0x46);
    let evidence = rid(0x36);
    let evidence_record = mneme_memory::build_evidence(
        evidence,
        rev(0x37),
        &scope(),
        mneme_memory::EvidenceOptions {
            assertion,
            source: rid(0x20),
            source_revision: rev(0x21),
            span: Some(mneme_core::SourceSpan::new(0, 10).expect("span")),
            anchor: Some("historical"),
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let proposed = mneme_memory::build_proposed_assertion(
        assertion,
        rev(0x47),
        &scope(),
        mneme_memory::ProposedAssertionOptions {
            subject: rid(0x10),
            predicate: "legacy",
            value: mneme_core::Value::string("legacy-value"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::Unknown,
            evidence: &[mneme_core::Reference::local(
                evidence,
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    harness.commit(
        scope(),
        "historical",
        vec![evidence_record, proposed],
        Vec::new(),
    );
    let current = harness
        .workspace
        .record_revisions(assertion)
        .expect("revisions")
        .into_iter()
        .last()
        .expect("current");
    let decision = mneme_memory::build_decision(
        rid(0x56),
        rev(0x57),
        &scope(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Supersession,
            target: assertion,
            actor: "author",
            policy: "recall-policy/v1",
            input_revision: harness.workspace.current_revision().expect("base"),
            outcome: "superseded",
            rationale: "retained for inspection",
            evidence: &[],
            related: &[],
        },
    );
    let superseded = mneme_memory::build_assertion_revision(
        &current,
        rev(0x48),
        mneme_core::Lifecycle::Superseded,
        mneme_core::Reference::local(rid(0x56), mneme_core::RecordKind::Decision),
        Some(mneme_core::Reference::local(
            rid(0x40),
            mneme_core::RecordKind::Assertion,
        )),
    );
    harness.commit(scope(), "supersede", vec![decision, superseded], Vec::new());
    let mut request = harness.request("legacy-value");
    request.temporal = mneme_recall::TemporalMode::Historical;
    let response = mneme_recall::RecallService::new(&mut harness.workspace)
        .recall(request)
        .expect("historical recall");
    let candidate = response
        .candidates
        .iter()
        .find(|candidate| candidate.assertion == Some(assertion))
        .expect("superseded candidate");
    let status = candidate.claim_status.as_ref().expect("status");
    assert_eq!(status.lifecycle, "superseded");
    assert_eq!(status.valid_time, mneme_core::ValidTime::Unknown);
}

#[test]
fn cancellation_and_time_budget_never_look_successful() {
    let mut harness = Harness::new();
    let mut cancelled = harness.request("SQLite");
    cancelled.cancellation = Some(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
        true,
    )));
    let response = mneme_recall::RecallService::new(&mut harness.workspace)
        .recall(cancelled)
        .expect("cancelled response");
    assert_eq!(response.status, mneme_recall::RecallExecution::Cancelled);
    assert!(response.candidates.is_empty());
    assert!(!response.absence_established);

    let mut timed = harness.request("SQLite");
    timed.max_time_ms = 0;
    let response = mneme_recall::RecallService::new(&mut harness.workspace)
        .recall(timed)
        .expect("timeout response");
    assert!(matches!(
        response.status,
        mneme_recall::RecallExecution::Timeout | mneme_recall::RecallExecution::Complete
    ));
    assert!(!response.absence_established);
    if response.status == mneme_recall::RecallExecution::Timeout {
        assert!(response.candidates.is_empty());
    }
}

#[test]
fn source_pruning_keeps_claim_envelope_without_a_quote() {
    let mut harness = Harness::new();
    let request = mneme_retention::RetentionRequest {
        actor: "recall-test".to_owned(),
        scope: scope(),
        base_revision: harness.workspace.current_revision().expect("base"),
        idempotency_key: "prune-recall-source".to_owned(),
        operation: mneme_retention::OperationKind::SourcePruning,
        selector: mneme_retention::Selector::Source(rid(0x20)),
        effective: None,
        policy: mneme_retention::RetentionPolicy {
            version: mneme_retention::POLICY_VERSION.to_owned(),
            retain_assertion_after_prune: true,
            block_content_replay: true,
            retain_withdrawn_evidence_metadata: true,
        },
    };
    mneme_retention::Retention::new(&mut harness.workspace)
        .execute(request)
        .expect("prune");
    let pruned_request = harness.request("SQLite");
    let response = mneme_recall::RecallService::new(&mut harness.workspace)
        .recall(pruned_request)
        .expect("pruned recall");
    let claim = response
        .candidates
        .iter()
        .find(|candidate| candidate.assertion == Some(rid(0x40)))
        .expect("claim envelope remains retrievable");
    assert!(
        claim
            .evidence
            .iter()
            .all(|evidence| evidence.availability.name() == "pruned")
    );
    assert!(
        response
            .candidates
            .iter()
            .all(|candidate| candidate.content_kind != mneme_recall::ContentKind::SourceExcerpt)
    );
    assert!(!response.exhaustive);
}

#[test]
fn structured_unavailable_uses_declared_lexical_fallback() {
    let mut harness = Harness::new();
    let mut request = harness.request("SQLite");
    request.modes = std::collections::BTreeSet::from([mneme_recall::RecallMode::Structured]);
    request.allow_fallback = true;
    let response = mneme_recall::RecallService::new(&mut harness.workspace)
        .recall(request)
        .expect("fallback recall");
    assert_eq!(response.status, mneme_recall::RecallExecution::Partial);
    assert!(!response.candidates.is_empty());
    assert!(response.modes.iter().any(|mode| {
        mode.mode == mneme_recall::RecallMode::Lexical
            && mode.status == mneme_recall::ModeStatus::Used
            && mode
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("fallback"))
    }));
    assert!(response.modes.iter().any(|mode| {
        mode.mode == mneme_recall::RecallMode::Structured
            && mode.status == mneme_recall::ModeStatus::Unavailable
    }));
}

#[test]
fn independent_contradiction_survives_copied_descendants() {
    let mut harness = Harness::new();
    harness.add_copied_claim();
    harness.add_independent_contradiction();
    let request = harness.request("SQLite");
    let response = mneme_recall::RecallService::new(&mut harness.workspace)
        .recall(request)
        .expect("contradiction recall");
    let independent = response
        .candidates
        .iter()
        .find(|candidate| candidate.assertion == Some(rid(0x49)))
        .expect("independent contradiction missing");
    assert!(independent.independent_support);
    let claims = response
        .candidates
        .iter()
        .filter(|candidate| candidate.content_kind == mneme_recall::ContentKind::Claim)
        .collect::<Vec<_>>();
    assert!(claims.len() >= 3);
    assert!(
        claims
            .iter()
            .filter(|candidate| candidate.independent_support)
            .count()
            >= 2
    );
}

impl Harness {
    fn add_independent_contradiction(&mut self) {
        let source = rid(0x24);
        let revision = rev(0x25);
        let evidence = rid(0x34);
        let assertion = rid(0x49);
        let text = b"Independent report: deployment may be PostgreSQL, not only SQLite.";
        let (source_record, source_blob) = mneme_memory::build_source(
            source,
            revision,
            &scope(),
            mneme_memory::SourceOptions {
                bytes: text,
                media_type: "text/plain",
                entity: Some(rid(0x10)),
                path_hint: Some("docs/independent.txt"),
            },
        )
        .expect("independent source");
        self.commit(
            scope(),
            "independent-source",
            vec![source_record],
            vec![source_blob],
        );
        let evidence_record = mneme_memory::build_evidence(
            evidence,
            rev(0x35),
            &scope(),
            mneme_memory::EvidenceOptions {
                assertion,
                source,
                source_revision: revision,
                span: Some(mneme_core::SourceSpan::new(0, text.len() as u64 - 1).expect("span")),
                anchor: Some("independent"),
                relation: mneme_memory::SupportRelation::Supports,
                origin: mneme_core::Origin::AuthoredStatement,
                ancestry: &[],
            },
        );
        let proposed = mneme_memory::build_proposed_assertion(
            assertion,
            rev(0x4a),
            &scope(),
            mneme_memory::ProposedAssertionOptions {
                subject: rid(0x10),
                predicate: "deployment",
                value: mneme_core::Value::string("PostgreSQL, not only SQLite"),
                stance: mneme_memory::Stance::Deny,
                origin: mneme_core::Origin::AuthoredStatement,
                asserted_by: "reviewer",
                valid_time: mneme_core::ValidTime::always(),
                evidence: &[mneme_core::Reference::local(
                    evidence,
                    mneme_core::RecordKind::Evidence,
                )],
                extraction: None,
                superseded_by: None,
            },
        );
        self.commit(
            scope(),
            "independent-claim",
            vec![evidence_record, proposed],
            Vec::new(),
        );
        self.accept(assertion, 0x58, 0x59, 0x4b);
    }
}
