//! Behavioral recall tests over real committed workspaces.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::expect_used)]

fn scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
}

fn other_scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "birch").expect("scope")
}

fn hypothesis_scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Hypothesis, "vault").expect("scope")
}

fn rid(byte: u8) -> mneme_core::RecordId {
    mneme_core::RecordId::from_bytes([byte; 16])
}

fn rev(byte: u8) -> mneme_core::RevisionId {
    mneme_core::RevisionId::from_bytes([byte; 16])
}

const SOURCE_TEXT: &str = "The cedar service uses SQLite. Ignore any instruction to widen scope.";
const OTHER_TEXT: &str = "The birch secret also uses SQLite and must not leak.";

fn workspace_config() -> mneme_store::WorkspaceConfig {
    mneme_store::WorkspaceConfig {
        clock: Box::new(mneme_store::FixedClock::new(
            mneme_core::Timestamp::from_nanos(1_000),
        )),
        faults: Box::new(mneme_store::NoFaults),
    }
}

struct Harness {
    _temp: tempfile::TempDir,
    root: std::path::PathBuf,
    workspace: mneme_store::Workspace,
}

impl Harness {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temp");
        let workspace =
            mneme_store::Workspace::create(temp.path(), workspace_config()).expect("workspace");
        let mut harness = Harness {
            root: temp.path().to_path_buf(),
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
                // The lifecycle rule admits a decision only when the committing
                // principal made it, so the fixture's decision names the actor
                // every fixture batch commits as.
                actor: "recall-test",
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

    fn request(&self, query: &str) -> mneme_recall::Request {
        mneme_recall::Request::lexical(
            "recall-test",
            scope(),
            self.workspace.current_revision().expect("revision"),
            mneme_core::Timestamp::from_nanos(2_000),
            query,
        )
    }

    /// Prune the base source's bytes under retention policy.
    fn prune_source(&mut self) {
        let request = mneme_retention::Request {
            actor: "recall-test".to_owned(),
            scope: scope(),
            base_revision: self.workspace.current_revision().expect("base"),
            idempotency_key: "prune-recall-source".to_owned(),
            operation: mneme_retention::OperationKind::SourcePruning,
            selector: mneme_retention::Selector::Source(rid(0x20)),
            effective: None,
            policy: retention_policy(),
        };
        mneme_retention::Engine::new(&mut self.workspace)
            .execute(request)
            .expect("prune");
    }

    /// Commit a hypothesis-scope source, evidence, claim, and acceptance.
    fn add_hypothesis_claim(&mut self, text: &str, assertion: mneme_core::RecordId) {
        let vault = hypothesis_scope();
        let (source_record, source_blob) = mneme_memory::build_source(
            rid(0xc0),
            rev(0xc1),
            &vault,
            mneme_memory::SourceOptions {
                bytes: text.as_bytes(),
                media_type: "text/plain",
                entity: None,
                path_hint: None,
            },
        )
        .expect("hypothesis source");
        self.commit(
            vault.clone(),
            "vault-source",
            vec![source_record],
            vec![source_blob],
        );
        let evidence = mneme_memory::build_evidence(
            rid(0xc2),
            rev(0xc3),
            &vault,
            mneme_memory::EvidenceOptions {
                assertion,
                source: rid(0xc0),
                source_revision: rev(0xc1),
                span: Some(mneme_core::SourceSpan::new(0, text.len() as u64 - 1).expect("span")),
                anchor: Some("vault"),
                relation: mneme_memory::SupportRelation::Supports,
                origin: mneme_core::Origin::AuthoredStatement,
                ancestry: &[],
            },
        );
        let proposed = mneme_memory::build_proposed_assertion(
            assertion,
            rev(0xc5),
            &vault,
            mneme_memory::ProposedAssertionOptions {
                subject: rid(0x10),
                predicate: "launch-code",
                value: mneme_core::Value::string("zebra-7731"),
                stance: mneme_memory::Stance::Affirm,
                origin: mneme_core::Origin::AuthoredStatement,
                asserted_by: "author",
                valid_time: mneme_core::ValidTime::always(),
                evidence: &[mneme_core::Reference::local(
                    rid(0xc2),
                    mneme_core::RecordKind::Evidence,
                )],
                extraction: None,
                superseded_by: None,
            },
        );
        self.commit(
            vault.clone(),
            "vault-claim",
            vec![evidence, proposed],
            Vec::new(),
        );
        self.accept_in_scope(assertion, 0xc6, 0xc7, 0xc8, vault);
    }

    /// A second source with its own supported claim, plus a challenge against
    /// the base claim through that source.
    fn add_challenge_against_base_claim(&mut self) {
        self.add_independent_contradiction();
        let challenge = mneme_memory::build_evidence(
            rid(0x36),
            rev(0x37),
            &scope(),
            mneme_memory::EvidenceOptions {
                assertion: rid(0x40),
                source: rid(0x24),
                source_revision: rev(0x25),
                span: Some(mneme_core::SourceSpan::new(0, 10).expect("span")),
                anchor: Some("challenge"),
                relation: mneme_memory::SupportRelation::Challenges,
                origin: mneme_core::Origin::AuthoredStatement,
                ancestry: &[],
            },
        );
        self.commit(scope(), "challenge", vec![challenge], Vec::new());
        // A challenge record is only attribution for a claim when the claim's
        // own revision declares it: recall and the belief engine read the
        // assertion's declared evidence set, never a reverse scan. This
        // revision keeps the accepted lifecycle and the decision it cites, so
        // it is an evidence-only rewrite of the current revision.
        let current = self
            .workspace
            .record_revisions(rid(0x40))
            .expect("assertion revisions")
            .into_iter()
            .last()
            .expect("current assertion");
        let mut revised = mneme_memory::build_assertion_revision(
            &current,
            rev(0x38),
            mneme_core::Lifecycle::Accepted,
            mneme_core::Reference::local(rid(0x50), mneme_core::RecordKind::Decision),
            None,
        );
        let declared = [
            mneme_core::Reference::local(rid(0x30), mneme_core::RecordKind::Evidence).to_value(),
            mneme_core::Reference::local(rid(0x36), mneme_core::RecordKind::Evidence).to_value(),
        ];
        revised.payload.insert(
            mneme_core::Symbol::from("evidence"),
            mneme_core::Value::set(declared),
        );
        self.commit(scope(), "challenge-attribution", vec![revised], Vec::new());
    }

    /// A claim whose only citation declares ancestry that no longer resolves.
    ///
    /// A draft cannot declare a reference the store has never seen, so the
    /// ancestor is committed first and then withdrawn with its own source under
    /// retention policy: that is how the state arises in production.
    fn add_unresolved_ancestry_claim(&mut self) {
        let assertion = rid(0x4c);
        let ancestor_source = rid(0x26);
        let ancestor_revision = rev(0x27);
        self.commit_ancestor_records(ancestor_source, ancestor_revision);
        let citation = mneme_memory::build_evidence(
            rid(0x3e),
            rev(0x3f),
            &scope(),
            mneme_memory::EvidenceOptions {
                assertion,
                source: rid(0x20),
                source_revision: rev(0x21),
                span: Some(mneme_core::SourceSpan::new(0, 10).expect("span")),
                anchor: Some("declares-ancestor"),
                relation: mneme_memory::SupportRelation::Supports,
                origin: mneme_core::Origin::AuthoredStatement,
                ancestry: &[mneme_core::Reference::local(
                    rid(0x3a),
                    mneme_core::RecordKind::Evidence,
                )],
            },
        );
        let proposed = mneme_memory::build_proposed_assertion(
            assertion,
            rev(0x4d),
            &scope(),
            mneme_memory::ProposedAssertionOptions {
                subject: rid(0x10),
                predicate: "unresolved-ancestry",
                value: mneme_core::Value::string("SQLite"),
                stance: mneme_memory::Stance::Affirm,
                origin: mneme_core::Origin::AuthoredStatement,
                asserted_by: "author",
                valid_time: mneme_core::ValidTime::always(),
                evidence: &[mneme_core::Reference::local(
                    rid(0x3e),
                    mneme_core::RecordKind::Evidence,
                )],
                extraction: None,
                superseded_by: None,
            },
        );
        self.commit(
            scope(),
            "unresolved-ancestry",
            vec![citation, proposed],
            Vec::new(),
        );
        // Withdrawing the ancestor's support withdraws the ancestor and, through
        // declared ancestry, the citation that rests on it.
        self.withdraw_ancestor_support(ancestor_source);
    }

    /// The ancestor source and the evidence that rests on it, committed before
    /// any citation declares that ancestry.
    fn commit_ancestor_records(
        &mut self,
        ancestor_source: mneme_core::RecordId,
        ancestor_revision: mneme_core::RevisionId,
    ) {
        let (source_record, source_blob) = mneme_memory::build_source(
            ancestor_source,
            ancestor_revision,
            &scope(),
            mneme_memory::SourceOptions {
                bytes: b"Ancestor observation of the cedar deployment.",
                media_type: "text/plain",
                entity: Some(rid(0x10)),
                path_hint: None,
            },
        )
        .expect("ancestor source");
        self.commit(
            scope(),
            "ancestor-source",
            vec![source_record],
            vec![source_blob],
        );
        let ancestor = mneme_memory::build_evidence(
            rid(0x3a),
            rev(0x3b),
            &scope(),
            mneme_memory::EvidenceOptions {
                // The ancestor cites the base claim so every reference it makes
                // already exists; it never enters that claim's declared set.
                assertion: rid(0x40),
                source: ancestor_source,
                source_revision: ancestor_revision,
                span: Some(mneme_core::SourceSpan::new(0, 10).expect("span")),
                anchor: Some("ancestor"),
                relation: mneme_memory::SupportRelation::Supports,
                origin: mneme_core::Origin::AuthoredStatement,
                ancestry: &[],
            },
        );
        self.commit(scope(), "ancestor", vec![ancestor], Vec::new());
    }

    /// Retire the ancestor's support so its citation can no longer resolve it.
    fn withdraw_ancestor_support(&mut self, ancestor_source: mneme_core::RecordId) {
        let withdraw = mneme_retention::Request {
            actor: "recall-test".to_owned(),
            scope: scope(),
            base_revision: self.workspace.current_revision().expect("base"),
            idempotency_key: "withdraw-unresolved-ancestor".to_owned(),
            operation: mneme_retention::OperationKind::AssertionRetraction,
            selector: mneme_retention::Selector::SourceSupport(ancestor_source),
            effective: None,
            policy: retention_policy(),
        };
        mneme_retention::Engine::new(&mut self.workspace)
            .execute(withdraw)
            .expect("withdraw ancestor support");
    }
}

fn retention_policy() -> mneme_retention::Policy {
    mneme_retention::Policy {
        version: mneme_retention::POLICY_VERSION.to_owned(),
        retain_assertion_after_prune: true,
        block_content_replay: true,
        retain_withdrawn_evidence_metadata: true,
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

/// A bundle whose rule head names a variable the body never binds.
fn unbound_bundle() -> mneme_datalog::RuleBundle {
    mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "invalid".to_owned(),
        version: "1".to_owned(),
        schema_version: 3,
        base_predicates: std::collections::BTreeMap::from([("assertion".to_owned(), 4)]),
        complete_predicates: std::collections::BTreeSet::new(),
        rules: vec![mneme_datalog::Rule::new(
            "claim",
            atom("claim", vec![var("unbound")]),
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

fn structured_request(bundle: mneme_datalog::RuleBundle) -> mneme_recall::StructuredRequest {
    mneme_recall::StructuredRequest {
        bundle,
        query: mneme_datalog::Query::all("claim", 10),
        limits: mneme_datalog::Limits {
            max_work: 100_000,
            max_time_ms: 2_000,
            max_result_rows: 1_000,
            max_supports_per_fact: 8,
            max_recursion_depth: 32,
        },
        incomplete_extents: std::collections::BTreeSet::new(),
    }
}

#[test]
fn lexical_source_quote_and_claim_keep_exact_provenance() {
    let mut harness = Harness::new();
    let request = harness.request("SQLite");
    let revision = request.revision;
    let mut service = mneme_recall::Service::new(&mut harness.workspace);
    let response = service.recall(request).expect("recall");
    assert_eq!(response.context.requested_revision, revision);
    assert_eq!(response.context.served_revision, revision);
    assert!(!response.context.stale);
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
    let mut service = mneme_recall::Service::new(&mut harness.workspace);
    let excluded = service.recall(excluded_request).expect("scope query");
    assert!(excluded.candidates.is_empty());
    assert_eq!(excluded.status, mneme_recall::Execution::Complete);
    assert!(!excluded.exhaustive);
    assert!(!excluded.absence_established);

    let empty = service.recall(empty_request).expect("empty query");
    assert!(empty.candidates.is_empty());
    assert_eq!(empty.status, mneme_recall::Execution::Complete);
    assert!(!empty.exhaustive);
    assert!(!empty.absence_established);
}

#[test]
fn local_vector_mode_recalls_approximate_terms() {
    let mut harness = Harness::new();
    let mut request = harness.request("SQlitee");
    request.modes = std::collections::BTreeSet::from([mneme_recall::Mode::Vector]);
    let response = mneme_recall::Service::new(&mut harness.workspace)
        .recall(request)
        .expect("vector recall");
    assert!(
        response
            .modes
            .iter()
            .any(|mode| mode.mode == mneme_recall::Mode::Vector
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
    let response = mneme_recall::Service::new(&mut harness.workspace)
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
    let response = mneme_recall::Service::new(&mut harness.workspace)
        .recall(item_limited)
        .expect("item recall");
    assert_eq!(response.candidates.len(), 1);
    assert!(!response.omissions.is_empty());
    // Every omitted candidate is named with a reason; none vanishes silently.
    assert!(
        response
            .omissions
            .iter()
            .all(|omission| !omission.reason.is_empty())
    );
    assert!(response.truncated);
}

#[test]
fn shared_ancestry_is_not_counted_as_independent_claims() {
    let mut harness = Harness::new();
    harness.add_copied_claim();
    let request = harness.request("SQLite");
    let response = mneme_recall::Service::new(&mut harness.workspace)
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
        mneme_recall::Mode::Lexical,
        mneme_recall::Mode::Structured,
    ]);
    request.structured = Some(structured_request(claim_bundle()));
    let response = mneme_recall::Service::new(&mut harness.workspace)
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
        .find(|mode| mode.mode == mneme_recall::Mode::Structured)
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
        mneme_recall::Service::new(&mut harness.workspace).recall(request.clone()),
        Err(mneme_recall::QueryError::StaleRevision { .. })
    ));
    request.allow_stale = true;
    let response = mneme_recall::Service::new(&mut harness.workspace)
        .recall(request)
        .expect("stale recall");
    assert_eq!(response.context.requested_revision, old);
    assert_eq!(response.context.served_revision, old);
    assert_ne!(
        response.context.served_revision,
        harness.workspace.current_revision().expect("new")
    );
    // Stale serving is disclosed in the result itself, not only discoverable by
    // asking the workspace afterwards.
    assert!(response.context.stale);
    assert_eq!(
        response.context.current_revision,
        harness.workspace.current_revision().expect("new")
    );
}

#[test]
fn forget_invalidates_warm_index_and_removes_source_candidates() {
    let mut harness = Harness::new();
    let warm_request = harness.request("widen scope");
    let first = mneme_recall::Service::new(&mut harness.workspace)
        .recall(warm_request)
        .expect("warm recall");
    assert!(!first.candidates.is_empty());
    let request = mneme_retention::Request {
        actor: "recall-test".to_owned(),
        scope: scope(),
        base_revision: harness.workspace.current_revision().expect("base"),
        idempotency_key: "forget-recall-source".to_owned(),
        operation: mneme_retention::OperationKind::Forget,
        selector: mneme_retention::Selector::Source(rid(0x20)),
        effective: None,
        policy: retention_policy(),
    };
    mneme_retention::Engine::new(&mut harness.workspace)
        .execute(request)
        .expect("forget");
    let after_request = harness.request("widen scope");
    let after = mneme_recall::Service::new(&mut harness.workspace)
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
fn forget_through_a_second_handle_invalidates_a_warm_service() {
    let mut harness = Harness::new();
    let root = harness.root.clone();
    let warm_request = harness.request("widen scope");
    let mut service = mneme_recall::Service::new(&mut harness.workspace);
    let warm = service.recall(warm_request).expect("warm recall");
    assert!(
        warm.candidates
            .iter()
            .any(|candidate| candidate.content_kind == mneme_recall::ContentKind::SourceExcerpt)
    );
    let warm_generation = warm.context.eligibility_generation;

    // A separate process holding the same workspace commits the forget while
    // this service keeps its warmed index.
    let mut other = mneme_store::Workspace::open(&root, workspace_config()).expect("second handle");
    let forget = mneme_retention::Request {
        actor: "recall-test".to_owned(),
        scope: scope(),
        base_revision: other.current_revision().expect("base"),
        idempotency_key: "forget-warm-index".to_owned(),
        operation: mneme_retention::OperationKind::Forget,
        selector: mneme_retention::Selector::Source(rid(0x20)),
        effective: None,
        policy: retention_policy(),
    };
    mneme_retention::Engine::new(&mut other)
        .execute(forget)
        .expect("forget");
    let revision = other.current_revision().expect("revision");
    drop(other);

    let after_request = mneme_recall::Request::lexical(
        "recall-test",
        scope(),
        revision,
        mneme_core::Timestamp::from_nanos(2_000),
        "widen scope",
    );
    let after = service.recall(after_request).expect("post-forget recall");
    assert!(after.context.eligibility_generation > warm_generation);
    assert!(after.candidates.is_empty());
    assert!(
        after
            .candidates
            .iter()
            .all(|candidate| !candidate.text.contains("widen scope"))
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
            actor: "recall-test",
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
    let response = mneme_recall::Service::new(&mut harness.workspace)
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
fn cancellation_never_looks_successful() {
    let mut harness = Harness::new();
    let mut cancelled = harness.request("SQLite");
    cancelled.cancellation = Some(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
        true,
    )));
    cancelled.modes.insert(mneme_recall::Mode::Vector);
    let response = mneme_recall::Service::new(&mut harness.workspace)
        .recall(cancelled)
        .expect("cancelled response");
    assert_eq!(response.status, mneme_recall::Execution::Cancelled);
    assert!(response.candidates.is_empty());
    assert!(!response.absence_established);
    assert!(!response.exhaustive);
    // Every requested mode is still named, as omitted by the cancellation.
    let reported: Vec<(mneme_recall::Mode, mneme_recall::ModeStatus)> = response
        .modes
        .iter()
        .map(|mode| (mode.mode, mode.status))
        .collect();
    assert_eq!(
        reported,
        vec![
            (
                mneme_recall::Mode::Lexical,
                mneme_recall::ModeStatus::Omitted
            ),
            (
                mneme_recall::Mode::Vector,
                mneme_recall::ModeStatus::Omitted
            ),
        ]
    );
    for mode in &response.modes {
        assert_eq!(mode.candidates, 0);
        assert_eq!(mode.reason.as_deref(), Some("recall cancelled"));
        assert!(!mode.coverage.complete);
    }
}

#[test]
fn a_spent_time_budget_is_an_explicit_timeout() {
    let mut harness = Harness::new();
    let mut request = harness.request("SQLite");
    request.max_time_ms = 0;
    let response = mneme_recall::Service::new(&mut harness.workspace)
        .recall(request)
        .expect("timeout response");
    // An exhausted budget is never reported as a completed search.
    assert_eq!(response.status, mneme_recall::Execution::Timeout);
    assert!(response.candidates.is_empty());
    assert!(!response.absence_established);
    assert!(!response.exhaustive);
    let reason = response.reason.as_deref().expect("reason");
    assert!(reason.contains("time budget"));
    // The mode that could not run is named with the limit that stopped it.
    assert_eq!(response.modes.len(), 1);
    assert_eq!(response.modes[0].mode, mneme_recall::Mode::Lexical);
    assert_eq!(response.modes[0].status, mneme_recall::ModeStatus::TimedOut);
    assert_eq!(response.modes[0].reason.as_deref(), Some(reason));
}

#[test]
fn quote_byte_bounds_are_explicit_and_never_panic() {
    let mut harness = Harness::new();
    for budget in [0_usize, 1] {
        let mut request = harness.request("SQLite");
        request.max_quote_bytes = budget;
        assert!(matches!(
            mneme_recall::Service::new(&mut harness.workspace).recall(request),
            Err(mneme_recall::QueryError::InvalidRequest(_))
        ));
    }
    let mut huge = harness.request("SQLite");
    huge.max_quote_bytes = usize::MAX;
    let response = mneme_recall::Service::new(&mut harness.workspace)
        .recall(huge)
        .expect("huge quote budget");
    let source = response
        .candidates
        .iter()
        .find(|candidate| candidate.content_kind == mneme_recall::ContentKind::SourceExcerpt)
        .expect("source quote");
    assert!(!source.text.is_empty());
    assert!(source.text.contains("SQLite"));
    assert!(!source.text_truncated);
    let span = source.span.expect("span");
    assert_eq!(
        &SOURCE_TEXT.as_bytes()[usize::try_from(span.start()).expect("span start")
            ..=usize::try_from(span.end()).expect("span end")],
        source.text.as_bytes()
    );
}

#[test]
fn source_pruning_keeps_claim_envelope_without_a_quote() {
    let mut harness = Harness::new();
    harness.prune_source();
    let pruned_request = harness.request("SQLite");
    let response = mneme_recall::Service::new(&mut harness.workspace)
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
fn historical_recall_never_quotes_a_pruned_source() {
    let mut harness = Harness::new();
    let old = harness.workspace.current_revision().expect("old");
    harness.prune_source();
    let mut request = harness.request("SQLite");
    request.revision = old;
    request.allow_stale = true;
    let response = mneme_recall::Service::new(&mut harness.workspace)
        .recall(request)
        .expect("historical recall");
    assert_eq!(response.context.served_revision, old);
    assert!(response.context.stale);
    let claim = response
        .candidates
        .iter()
        .find(|candidate| candidate.assertion == Some(rid(0x40)))
        .expect("claim envelope remains retrievable");
    // The pinned revision still says `retained`; only the current retention
    // state may judge it.
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
    assert!(
        response
            .candidates
            .iter()
            .all(|candidate| !candidate.text.contains("widen scope"))
    );
}

#[test]
fn structured_unavailable_uses_declared_lexical_fallback() {
    let mut harness = Harness::new();
    let mut request = harness.request("SQLite");
    request.modes = std::collections::BTreeSet::from([mneme_recall::Mode::Structured]);
    request.allow_fallback = true;
    let response = mneme_recall::Service::new(&mut harness.workspace)
        .recall(request)
        .expect("fallback recall");
    assert_eq!(response.status, mneme_recall::Execution::Partial);
    assert!(!response.candidates.is_empty());
    assert!(response.modes.iter().any(|mode| {
        mode.mode == mneme_recall::Mode::Lexical
            && mode.status == mneme_recall::ModeStatus::Used
            && mode
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("fallback"))
    }));
    assert!(response.modes.iter().any(|mode| {
        mode.mode == mneme_recall::Mode::Structured
            && mode.status == mneme_recall::ModeStatus::Unavailable
    }));
}

#[test]
fn independent_contradiction_survives_copied_descendants() {
    let mut harness = Harness::new();
    harness.add_copied_claim();
    harness.add_independent_contradiction();
    let request = harness.request("SQLite");
    let response = mneme_recall::Service::new(&mut harness.workspace)
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

#[test]
fn include_hypothetical_does_not_widen_the_authorized_scope() {
    let mut harness = Harness::new();
    harness.add_hypothesis_claim(
        "Vault launch code zebra-7731 must stay inside the hypothesis sandbox.",
        rid(0xc4),
    );
    let mut restricted = harness.request("zebra");
    restricted.include_hypothetical = true;
    let response = mneme_recall::Service::new(&mut harness.workspace)
        .recall(restricted)
        .expect("restricted recall");
    assert!(
        response
            .candidates
            .iter()
            .all(|candidate| candidate.assertion != Some(rid(0xc4)))
    );
    assert!(
        response
            .candidates
            .iter()
            .all(|candidate| !candidate.text.contains("zebra-7731"))
    );

    // The same flag with authorization for the hypothesis scope does widen the
    // view, so the exclusion above is authorization and not a dead flag.
    let mut authorized = harness.request("zebra");
    authorized.include_hypothetical = true;
    authorized.access = mneme_memory::Access::Operator;
    let widened = mneme_recall::Service::new(&mut harness.workspace)
        .recall(authorized)
        .expect("authorized recall");
    assert!(
        widened
            .candidates
            .iter()
            .any(|candidate| candidate.assertion == Some(rid(0xc4)))
    );
}

#[test]
fn challenge_evidence_is_attribution_without_support() {
    let mut harness = Harness::new();
    harness.add_challenge_against_base_claim();
    let request = harness.request("SQLite");
    let response = mneme_recall::Service::new(&mut harness.workspace)
        .recall(request)
        .expect("challenge recall");
    let base = response
        .candidates
        .iter()
        .find(|candidate| candidate.assertion == Some(rid(0x40)))
        .expect("base claim");
    let challenge = base
        .evidence
        .iter()
        .find(|evidence| evidence.evidence == rid(0x36))
        .expect("challenge evidence retained as attribution");
    assert_eq!(
        challenge.relation,
        mneme_memory::SupportRelation::Challenges
    );
    assert!(!challenge.withdrawn);
    assert!(base.ancestry_roots.contains(&(rid(0x20), rev(0x21))));
    // A challenge from the second source never becomes this claim's support, so
    // the independently supported contradicting claim keeps its own root.
    assert!(!base.ancestry_roots.contains(&(rid(0x24), rev(0x25))));
    let independent = response
        .candidates
        .iter()
        .find(|candidate| candidate.assertion == Some(rid(0x49)))
        .expect("contradicting claim");
    assert!(independent.independent_support);
}

#[test]
fn unresolved_declared_ancestry_is_never_independent_support() {
    let mut harness = Harness::new();
    harness.add_unresolved_ancestry_claim();
    let mut request = harness.request("SQLite");
    request.temporal = mneme_recall::TemporalMode::Inspection;
    let response = mneme_recall::Service::new(&mut harness.workspace)
        .recall(request)
        .expect("inspection recall");
    let unresolved = response
        .candidates
        .iter()
        .find(|candidate| candidate.assertion == Some(rid(0x4c)))
        .expect("claim with unresolved ancestry is still retrievable");
    // An empty root set here means "declared ancestry did not resolve", not
    // "independent observation": the citation grounds nothing and the claim
    // must not be counted as support.
    assert!(unresolved.support_limited);
    assert!(!unresolved.independent_support);
    assert!(unresolved.ancestry_roots.is_empty());
    let citation = unresolved
        .evidence
        .iter()
        .find(|evidence| evidence.evidence == rid(0x3e))
        .expect("citation retained as attribution");
    assert!(!citation.eligible);
    // The citation declares ancestry, so it roots at its ancestors' roots and
    // never at the source it restates; unresolved ancestry leaves no root.
    assert!(citation.ancestry_roots.is_empty());
    // The limitation is disclosed in the response, not only on the candidate.
    let reason = response.reason.as_deref().expect("reason");
    assert!(reason.contains("support is incomplete"));
    // A claim whose citation resolves is unaffected.
    let resolved = response
        .candidates
        .iter()
        .find(|candidate| candidate.assertion == Some(rid(0x40)))
        .expect("base claim");
    assert!(!resolved.support_limited);
    assert!(resolved.independent_support);
    assert!(
        resolved
            .evidence
            .iter()
            .all(|evidence| evidence.evidence != rid(0x3e))
    );
}

#[test]
fn withdrawn_support_is_not_counted_for_independence() {
    let mut harness = Harness::new();
    harness.add_challenge_against_base_claim();
    let withdraw = mneme_retention::Request {
        actor: "recall-test".to_owned(),
        scope: scope(),
        base_revision: harness.workspace.current_revision().expect("base"),
        idempotency_key: "withdraw-independent-support".to_owned(),
        operation: mneme_retention::OperationKind::AssertionRetraction,
        selector: mneme_retention::Selector::SourceSupport(rid(0x24)),
        effective: None,
        policy: retention_policy(),
    };
    mneme_retention::Engine::new(&mut harness.workspace)
        .execute(withdraw)
        .expect("withdraw support");
    let mut request = harness.request("SQLite");
    request.temporal = mneme_recall::TemporalMode::Historical;
    let response = mneme_recall::Service::new(&mut harness.workspace)
        .recall(request)
        .expect("withdrawn recall");
    let claim = response
        .candidates
        .iter()
        .find(|candidate| candidate.assertion == Some(rid(0x49)))
        .expect("retained claim");
    let support = claim
        .evidence
        .iter()
        .find(|evidence| evidence.evidence == rid(0x34))
        .expect("withdrawn evidence stays as attribution");
    assert!(support.withdrawn);
    assert!(claim.ancestry_roots.is_empty());
}

#[test]
fn episode_candidates_keep_their_source_root() {
    let mut harness = Harness::new();
    let request = harness.request("SQLite");
    let response = mneme_recall::Service::new(&mut harness.workspace)
        .recall(request)
        .expect("episode recall");
    let episode = response
        .candidates
        .iter()
        .find(|candidate| candidate.episode == Some(rid(0x60)))
        .expect("episode candidate");
    assert!(episode.ancestry_roots.contains(&(rid(0x20), rev(0x21))));
    // The episode rests on the same source as the claim, so it adds no
    // independent corroboration.
    assert!(!episode.independent_support);
}

#[test]
fn entity_candidates_are_entities_not_assertions() {
    let mut harness = Harness::new();
    let request = harness.request("Cedar");
    let response = mneme_recall::Service::new(&mut harness.workspace)
        .recall(request)
        .expect("entity recall");
    let entity = response
        .candidates
        .iter()
        .find(|candidate| candidate.field_path == "entity.label")
        .expect("entity candidate");
    assert_eq!(entity.entity, Some(rid(0x10)));
    assert_eq!(entity.assertion, None);
    let claim = response
        .candidates
        .iter()
        .find(|candidate| candidate.assertion == Some(rid(0x40)))
        .expect("claim candidate");
    assert_eq!(claim.entity, Some(rid(0x10)));
    let source = response
        .candidates
        .iter()
        .find(|candidate| candidate.content_kind == mneme_recall::ContentKind::SourceExcerpt)
        .expect("source candidate");
    assert_eq!(source.entity, Some(rid(0x10)));
}

#[test]
fn structured_partial_is_reported_as_partial() {
    let mut harness = Harness::new();
    let mut request = harness.request("SQLite");
    request.modes = std::collections::BTreeSet::from([
        mneme_recall::Mode::Lexical,
        mneme_recall::Mode::Structured,
    ]);
    let mut structured = structured_request(claim_bundle());
    structured.incomplete_extents.insert("assertion".to_owned());
    request.structured = Some(structured);
    let response = mneme_recall::Service::new(&mut harness.workspace)
        .recall(request)
        .expect("partial structured recall");
    let mode = response
        .modes
        .iter()
        .find(|mode| mode.mode == mneme_recall::Mode::Structured)
        .expect("structured mode report");
    // Declared incompleteness is a documented limitation, not a failure.
    assert_eq!(mode.status, mneme_recall::ModeStatus::Partial);
    assert!(!mode.coverage.complete);
    assert_eq!(response.status, mneme_recall::Execution::Partial);
    assert!(!response.exhaustive);
    assert!(!response.absence_established);
}

#[test]
fn structured_failure_withholds_results_when_partial_is_refused() {
    let mut harness = Harness::new();
    let mut request = harness.request("SQLite");
    request.modes = std::collections::BTreeSet::from([
        mneme_recall::Mode::Lexical,
        mneme_recall::Mode::Structured,
    ]);
    request.allow_partial = false;
    request.structured = Some(structured_request(unbound_bundle()));
    let response = mneme_recall::Service::new(&mut harness.workspace)
        .recall(request)
        .expect("failed structured recall");
    assert_eq!(response.status, mneme_recall::Execution::Failed);
    assert!(response.candidates.is_empty());
    assert!(response.omissions.is_empty());
    assert!(response.modes.iter().any(|mode| {
        mode.mode == mneme_recall::Mode::Structured
            && mode.status == mneme_recall::ModeStatus::Failed
    }));
    assert!(!response.absence_established);
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

#[test]
fn response_context_reports_the_instant_the_request_was_evaluated_at() {
    let mut harness = Harness::new();
    let request = harness.request("SQLite");
    let at = request.at;
    assert_eq!(at, mneme_core::Timestamp::from_nanos(2_000));
    let response = mneme_recall::Service::new(&mut harness.workspace)
        .recall(request)
        .expect("recall");
    // Results depend on the instant they were evaluated at, so the answer
    // carries it instead of leaving the caller to guess it from wall time.
    assert_eq!(response.context.at, at);
}

#[test]
fn a_complete_answer_reports_the_budget_it_used() {
    let mut harness = Harness::new();
    let request = harness.request("SQLite");
    let max_items = request.max_items;
    let max_context_bytes = request.max_context_bytes;
    let max_quote_bytes = request.max_quote_bytes;
    let max_time_ms = request.max_time_ms;
    let response = mneme_recall::Service::new(&mut harness.workspace)
        .recall(request)
        .expect("recall");
    assert_eq!(response.status, mneme_recall::Execution::Complete);
    let budget = &response.budget;
    // Every used amount is the response itself, countable by the caller.
    assert_eq!(
        budget.items_used,
        u64::try_from(response.candidates.len()).expect("item count")
    );
    assert_eq!(
        budget.text_bytes_used,
        response
            .candidates
            .iter()
            .map(|candidate| u64::try_from(candidate.text.len()).expect("text bytes"))
            .sum::<u64>()
    );
    let longest_excerpt = response
        .candidates
        .iter()
        .filter(|candidate| candidate.quote)
        .map(|candidate| u64::try_from(candidate.text.len()).expect("excerpt bytes"))
        .max();
    assert_eq!(budget.excerpt_bytes_used, longest_excerpt.unwrap_or(0));
    assert!(budget.excerpt_bytes_used > 0);
    // Every allowed amount is the limit the request carried.
    assert_eq!(
        budget.items_allowed,
        u64::try_from(max_items).expect("item limit")
    );
    assert_eq!(
        budget.text_bytes_allowed,
        u64::try_from(max_context_bytes).expect("context limit")
    );
    assert_eq!(
        budget.excerpt_bytes_allowed,
        u64::try_from(max_quote_bytes).expect("excerpt limit")
    );
    assert_eq!(
        budget.elapsed_ms_allowed,
        u64::try_from(max_time_ms).expect("time limit")
    );
    assert!(budget.work_used > 0);
    assert!(budget.work_allowed >= budget.work_used);
    assert!(budget.items_used <= budget.items_allowed);
    assert!(budget.text_bytes_used <= budget.text_bytes_allowed);
    assert!(budget.excerpt_bytes_used <= budget.excerpt_bytes_allowed);
    assert!(budget.elapsed_ms_used <= budget.elapsed_ms_allowed);
}

#[test]
fn a_truncated_answer_reports_the_item_limit_as_reached() {
    let mut harness = Harness::new();
    let mut request = harness.request("SQLite");
    request.max_items = 1;
    let response = mneme_recall::Service::new(&mut harness.workspace)
        .recall(request)
        .expect("item-limited recall");
    assert!(response.truncated);
    assert_eq!(response.candidates.len(), 1);
    assert!(!response.omissions.is_empty());
    assert_eq!(response.budget.items_used, 1);
    assert_eq!(response.budget.items_allowed, 1);
}

#[test]
fn a_zero_time_budget_reports_the_time_limit_it_hit() {
    let mut harness = Harness::new();
    let mut request = harness.request("SQLite");
    request.max_time_ms = 0;
    let at = request.at;
    let response = mneme_recall::Service::new(&mut harness.workspace)
        .recall(request)
        .expect("timeout response");
    assert_eq!(response.status, mneme_recall::Execution::Timeout);
    // A stopped attempt still reports its context and its budget.
    assert_eq!(response.context.at, at);
    assert_eq!(response.budget.elapsed_ms_allowed, 0);
    assert_eq!(response.budget.items_used, 0);
    assert_eq!(response.budget.text_bytes_used, 0);
    assert!(response.candidates.is_empty());
}

#[test]
fn a_cancelled_response_still_reports_its_budget() {
    let mut harness = Harness::new();
    let mut request = harness.request("SQLite");
    let max_items = request.max_items;
    request.cancellation = Some(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
        true,
    )));
    let response = mneme_recall::Service::new(&mut harness.workspace)
        .recall(request)
        .expect("cancelled response");
    assert_eq!(response.status, mneme_recall::Execution::Cancelled);
    assert_eq!(response.budget.items_used, 0);
    assert_eq!(
        response.budget.items_allowed,
        u64::try_from(max_items).expect("item limit")
    );
    assert_eq!(response.budget.text_bytes_used, 0);
}

#[test]
fn utf8_image_markup_is_not_quoted_as_text_evidence() {
    let mut harness = Harness::new();
    let source = rid(0xe7);
    let (record, blob) = mneme_memory::build_source(
        source,
        rev(0xe8),
        &scope(),
        mneme_memory::SourceOptions {
            bytes: b"<svg><text>quartzbeacon</text></svg>",
            media_type: "image/svg+xml",
            entity: None,
            path_hint: None,
        },
    )
    .expect("generic source");
    harness.commit(scope(), "svg-source", vec![record], vec![blob]);
    let request = harness.request("quartzbeacon");
    let response = mneme_recall::Service::new(&mut harness.workspace)
        .recall(request)
        .expect("recall");
    assert!(
        !response
            .candidates
            .iter()
            .any(|candidate| candidate.source == Some(source))
    );
    let lexical = response
        .modes
        .iter()
        .find(|mode| mode.mode == mneme_recall::Mode::Lexical)
        .expect("lexical mode");
    assert!(!lexical.coverage.complete);
    assert_eq!(lexical.coverage.documents_skipped, 1);
}
