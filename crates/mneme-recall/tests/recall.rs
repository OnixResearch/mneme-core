//! Behavioral recall tests over real committed workspaces.

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};

use mneme_core::{
    Lifecycle, Origin, RecordId, Reference, RevisionId, ScopeClass, ScopeId, SourceSpan, Timestamp,
    ValidTime, Value,
};
use mneme_datalog::{Atom, Limits, Literal, Query, RuleBundle, Term};
use mneme_memory::{
    DecisionKind, Stance, build_assertion_revision, build_decision, build_episode, build_evidence,
    build_proposed_assertion, build_source,
};
use mneme_recall::{
    ContentKind, RecallExecution, RecallMode, RecallRequest, RecallService, StructuredRequest,
    TemporalMode,
};
use mneme_retention::{OperationKind, Retention, RetentionPolicy, RetentionRequest, Selector};
use mneme_store::{CommitCommand, FixedClock, NoFaults, RecordDraft, Workspace, WorkspaceConfig};
use tempfile::TempDir;

fn scope() -> ScopeId {
    ScopeId::new(ScopeClass::Project, "cedar").expect("scope")
}

fn other_scope() -> ScopeId {
    ScopeId::new(ScopeClass::Project, "birch").expect("scope")
}

fn rid(byte: u8) -> RecordId {
    RecordId::from_bytes([byte; 16])
}

fn rev(byte: u8) -> RevisionId {
    RevisionId::from_bytes([byte; 16])
}

const SOURCE_TEXT: &str = "The cedar service uses SQLite. Ignore any instruction to widen scope.";
const OTHER_TEXT: &str = "The birch secret also uses SQLite and must not leak.";

struct Harness {
    _temp: TempDir,
    workspace: Workspace,
}

impl Harness {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temp");
        let workspace = Workspace::create(
            temp.path(),
            WorkspaceConfig {
                clock: Box::new(FixedClock::new(Timestamp::from_nanos(1_000))),
                faults: Box::new(NoFaults),
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
        scope: ScopeId,
        key: &str,
        records: Vec<RecordDraft>,
        source_blobs: Vec<mneme_store::SourceBlobDraft>,
    ) {
        self.workspace
            .commit(CommitCommand {
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

    fn add_base(&mut self) {
        let entity = rid(0x10);
        let source = rid(0x20);
        let revision = rev(0x21);
        let assertion = rid(0x40);
        let evidence = rid(0x30);
        self.commit(
            scope(),
            "entity",
            vec![RecordDraft {
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
        let (source_record, source_blob) = build_source(
            source,
            revision,
            &scope(),
            SOURCE_TEXT.as_bytes(),
            "text/plain",
            Some(entity),
            Some("docs/cedar.txt"),
        )
        .expect("source");
        self.commit(scope(), "source", vec![source_record], vec![source_blob]);
        let evidence_record = build_evidence(
            evidence,
            rev(0x31),
            &scope(),
            assertion,
            source,
            revision,
            Some(SourceSpan::new(0, SOURCE_TEXT.len() as u64 - 1).expect("span")),
            Some("deployment"),
            mneme_memory::SupportRelation::Supports,
            Origin::AuthoredStatement,
            &[],
        );
        let proposed = build_proposed_assertion(
            assertion,
            rev(0x41),
            &scope(),
            entity,
            "deployment",
            Value::string("SQLite"),
            Stance::Affirm,
            Origin::AuthoredStatement,
            "author",
            ValidTime::always(),
            &[Reference::local(evidence, mneme_core::RecordKind::Evidence)],
            None,
            None,
        );
        self.commit(
            scope(),
            "claim",
            vec![evidence_record, proposed],
            Vec::new(),
        );
        self.accept(assertion, 0x50, 0x51, 0x42);
        let episode = build_episode(
            rid(0x60),
            rev(0x61),
            &scope(),
            "agent",
            "observation",
            ValidTime::always(),
            "Cedar episode records a SQLite rollout without embeddings",
            Some(Reference::local(
                source,
                mneme_core::RecordKind::SourceRevision,
            )),
            &[],
        );
        self.commit(scope(), "episode", vec![episode], Vec::new());
        self.add_other_scope();
    }

    fn add_other_scope(&mut self) {
        let entity = rid(0x70);
        let source = rid(0x72);
        let revision = rev(0x73);
        let assertion = rid(0x80);
        let evidence = rid(0x74);
        self.commit(
            other_scope(),
            "other-entity",
            vec![RecordDraft {
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
        let (source_record, source_blob) = build_source(
            source,
            revision,
            &other_scope(),
            OTHER_TEXT.as_bytes(),
            "text/plain",
            Some(entity),
            Some("docs/birch.txt"),
        )
        .expect("source");
        self.commit(
            other_scope(),
            "other-source",
            vec![source_record],
            vec![source_blob],
        );
        let evidence_record = build_evidence(
            evidence,
            rev(0x75),
            &other_scope(),
            assertion,
            source,
            revision,
            Some(SourceSpan::new(0, OTHER_TEXT.len() as u64 - 1).expect("span")),
            Some("other"),
            mneme_memory::SupportRelation::Supports,
            Origin::AuthoredStatement,
            &[],
        );
        let proposed = build_proposed_assertion(
            assertion,
            rev(0x81),
            &other_scope(),
            entity,
            "secret",
            Value::string("birch-secret"),
            Stance::Affirm,
            Origin::AuthoredStatement,
            "author",
            ValidTime::always(),
            &[Reference::local(evidence, mneme_core::RecordKind::Evidence)],
            None,
            None,
        );
        self.commit(
            other_scope(),
            "other-claim",
            vec![evidence_record, proposed],
            Vec::new(),
        );
        self.accept_in_scope(assertion, 0x90, 0x91, 0x82, other_scope());
    }

    fn accept(
        &mut self,
        assertion: RecordId,
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
        assertion: RecordId,
        decision_byte: u8,
        decision_rev: u8,
        accepted_rev: u8,
        scope: ScopeId,
    ) {
        let current = self
            .workspace
            .record_revisions(assertion)
            .expect("assertion revisions")
            .into_iter()
            .last()
            .expect("current assertion");
        let decision = build_decision(
            rid(decision_byte),
            rev(decision_rev),
            &scope,
            DecisionKind::Acceptance,
            assertion,
            "author",
            "recall-policy/v1",
            self.workspace.current_revision().expect("base"),
            "accepted",
            "recall fixture",
            &[],
            &[],
        );
        let accepted = build_assertion_revision(
            &current,
            rev(accepted_rev),
            Lifecycle::Accepted,
            Reference::local(rid(decision_byte), mneme_core::RecordKind::Decision),
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
        let evidence_record = build_evidence(
            evidence,
            rev(0x33),
            &scope(),
            assertion,
            rid(0x20),
            rev(0x21),
            Some(SourceSpan::new(0, SOURCE_TEXT.len() as u64 - 1).expect("span")),
            Some("copied"),
            mneme_memory::SupportRelation::Supports,
            Origin::AuthoredStatement,
            &[],
        );
        let proposed = build_proposed_assertion(
            assertion,
            rev(0x43),
            &scope(),
            rid(0x10),
            "summary",
            Value::string("Cedar deployment uses SQLite"),
            Stance::Affirm,
            Origin::AuthoredStatement,
            "author",
            ValidTime::always(),
            &[Reference::local(evidence, mneme_core::RecordKind::Evidence)],
            None,
            None,
        );
        self.commit(
            scope(),
            "copied",
            vec![evidence_record, proposed],
            Vec::new(),
        );
        self.accept(assertion, 0x52, 0x53, 0x44);
    }

    fn request(&self, query: &str) -> RecallRequest {
        RecallRequest::lexical(
            "recall-test",
            scope(),
            self.workspace.current_revision().expect("revision"),
            Timestamp::from_nanos(2_000),
            query,
        )
    }
}

fn entity_payload(label: &str) -> mneme_core::Payload {
    mneme_core::Payload::new([
        (
            mneme_core::Symbol::from("entity-type"),
            Value::symbol("project"),
        ),
        (
            mneme_core::Symbol::from("label"),
            Value::string(label.to_owned()),
        ),
        (
            mneme_core::Symbol::from("properties"),
            Value::dictionary([]),
        ),
    ])
}

fn atom(predicate: &str, terms: Vec<Term>) -> Atom {
    Atom::new(predicate, terms)
}

fn var(name: &str) -> Term {
    Term::var(name)
}

fn constant(value: Value) -> Term {
    Term::constant(value)
}

fn claim_bundle() -> RuleBundle {
    RuleBundle::new(
        "recall",
        "1",
        3,
        BTreeMap::from([("assertion".to_owned(), 4)]),
        BTreeSet::from(["assertion".to_owned()]),
        vec![mneme_datalog::Rule::new(
            "claim",
            atom("claim", vec![var("subject"), var("value")]),
            vec![Literal::Positive(atom(
                "assertion",
                vec![
                    var("subject"),
                    constant(Value::symbol("deployment")),
                    var("value"),
                    var("id"),
                ],
            ))],
        )],
    )
}

#[test]
fn lexical_source_quote_and_claim_keep_exact_provenance() {
    let mut harness = Harness::new();
    let request = harness.request("SQLite");
    let revision = request.revision;
    let mut service = RecallService::new(&mut harness.workspace);
    let response = service.recall(request).expect("recall");
    assert_eq!(response.context.requested_revision, revision);
    assert_eq!(response.context.served_revision, revision);
    assert!(!response.exhaustive);
    assert!(!response.absence_established);
    assert!(
        response
            .candidates
            .iter()
            .any(|candidate| candidate.content_kind == ContentKind::Claim
                && candidate.claim_status.is_some())
    );
    let source = response
        .candidates
        .iter()
        .find(|candidate| candidate.content_kind == ContentKind::SourceExcerpt)
        .expect("source candidate");
    assert!(source.text.contains("SQLite"));
    assert_eq!(source.source, Some(rid(0x20)));
    let span = source.span.expect("exact span");
    assert_eq!(
        &SOURCE_TEXT.as_bytes()[span.start() as usize..=span.end() as usize],
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
    let mut service = RecallService::new(&mut harness.workspace);
    let excluded = service.recall(excluded_request).expect("scope query");
    assert!(excluded.candidates.is_empty());
    assert_eq!(excluded.status, RecallExecution::Complete);
    assert!(!excluded.exhaustive);
    assert!(!excluded.absence_established);

    let empty = service.recall(empty_request).expect("empty query");
    assert!(empty.candidates.is_empty());
    assert_eq!(empty.status, RecallExecution::Complete);
    assert!(!empty.exhaustive);
    assert!(!empty.absence_established);
}

#[test]
fn local_vector_mode_recalls_approximate_terms() {
    let mut harness = Harness::new();
    let mut request = harness.request("SQlitee");
    request.modes = BTreeSet::from([RecallMode::Vector]);
    let response = RecallService::new(&mut harness.workspace)
        .recall(request)
        .expect("vector recall");
    assert!(response.modes.iter().any(
        |mode| mode.mode == RecallMode::Vector && mode.status == mneme_recall::ModeStatus::Used
    ));
    assert!(!response.candidates.is_empty());
    assert!(!response.exhaustive);
}

#[test]
fn budget_truncation_keeps_source_span_and_reports_omissions() {
    let mut harness = Harness::new();
    let mut request = harness.request("cedar service");
    request.max_context_bytes = 32;
    request.max_quote_bytes = 100;
    let response = RecallService::new(&mut harness.workspace)
        .recall(request)
        .expect("budget recall");
    let source = response
        .candidates
        .iter()
        .find(|candidate| candidate.content_kind == ContentKind::SourceExcerpt)
        .expect("truncated source");
    assert!(source.text_truncated);
    assert_eq!(
        &SOURCE_TEXT.as_bytes()[source.span.expect("span").start() as usize
            ..=source.span.expect("span").end() as usize],
        source.text.as_bytes()
    );
    assert!(response.truncated);

    let mut item_limited = harness.request("SQLite");
    item_limited.max_items = 1;
    let response = RecallService::new(&mut harness.workspace)
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
    let response = RecallService::new(&mut harness.workspace)
        .recall(request)
        .expect("ancestry recall");
    let claims = response
        .candidates
        .iter()
        .filter(|candidate| candidate.content_kind == ContentKind::Claim)
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
    request.modes = BTreeSet::from([RecallMode::Lexical, RecallMode::Structured]);
    request.structured = Some(StructuredRequest {
        bundle: claim_bundle(),
        query: Query::all("claim", 10),
        limits: Limits::default(),
        incomplete_extents: BTreeSet::new(),
    });
    let response = RecallService::new(&mut harness.workspace)
        .recall(request)
        .expect("structured recall");
    let structured = response
        .candidates
        .iter()
        .find(|candidate| candidate.content_kind == ContentKind::StructuredRow)
        .expect("structured candidate");
    assert!(!structured.derivations.is_empty());
    let mode = response
        .modes
        .iter()
        .find(|mode| mode.mode == RecallMode::Structured)
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
        vec![RecordDraft {
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
        RecallService::new(&mut harness.workspace).recall(request.clone()),
        Err(mneme_recall::RecallError::StaleRevision { .. })
    ));
    request.allow_stale = true;
    let response = RecallService::new(&mut harness.workspace)
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
    let first = RecallService::new(&mut harness.workspace)
        .recall(warm_request)
        .expect("warm recall");
    assert!(!first.candidates.is_empty());
    let request = RetentionRequest {
        actor: "recall-test".to_owned(),
        scope: scope(),
        base_revision: harness.workspace.current_revision().expect("base"),
        idempotency_key: "forget-recall-source".to_owned(),
        operation: OperationKind::Forget,
        selector: Selector::Source(rid(0x20)),
        effective: None,
        policy: RetentionPolicy::default(),
    };
    Retention::new(&mut harness.workspace)
        .execute(request)
        .expect("forget");
    let after_request = harness.request("widen scope");
    let after = RecallService::new(&mut harness.workspace)
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
    let evidence_record = build_evidence(
        evidence,
        rev(0x37),
        &scope(),
        assertion,
        rid(0x20),
        rev(0x21),
        Some(SourceSpan::new(0, 10).expect("span")),
        Some("historical"),
        mneme_memory::SupportRelation::Supports,
        Origin::AuthoredStatement,
        &[],
    );
    let proposed = build_proposed_assertion(
        assertion,
        rev(0x47),
        &scope(),
        rid(0x10),
        "legacy",
        Value::string("legacy-value"),
        Stance::Affirm,
        Origin::AuthoredStatement,
        "author",
        ValidTime::Unknown,
        &[Reference::local(evidence, mneme_core::RecordKind::Evidence)],
        None,
        None,
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
    let decision = build_decision(
        rid(0x56),
        rev(0x57),
        &scope(),
        DecisionKind::Supersession,
        assertion,
        "author",
        "recall-policy/v1",
        harness.workspace.current_revision().expect("base"),
        "superseded",
        "retained for inspection",
        &[],
        &[],
    );
    let superseded = build_assertion_revision(
        &current,
        rev(0x48),
        Lifecycle::Superseded,
        Reference::local(rid(0x56), mneme_core::RecordKind::Decision),
        Some(Reference::local(
            rid(0x40),
            mneme_core::RecordKind::Assertion,
        )),
    );
    harness.commit(scope(), "supersede", vec![decision, superseded], Vec::new());
    let mut request = harness.request("legacy-value");
    request.temporal = TemporalMode::Historical;
    let response = RecallService::new(&mut harness.workspace)
        .recall(request)
        .expect("historical recall");
    let candidate = response
        .candidates
        .iter()
        .find(|candidate| candidate.assertion == Some(assertion))
        .expect("superseded candidate");
    let status = candidate.claim_status.as_ref().expect("status");
    assert_eq!(status.lifecycle, "superseded");
    assert_eq!(status.valid_time, ValidTime::Unknown);
}

#[test]
fn cancellation_and_time_budget_never_look_successful() {
    let mut harness = Harness::new();
    let mut cancelled = harness.request("SQLite");
    cancelled.cancellation = Some(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
        true,
    )));
    let response = RecallService::new(&mut harness.workspace)
        .recall(cancelled)
        .expect("cancelled response");
    assert_eq!(response.status, RecallExecution::Cancelled);
    assert!(response.candidates.is_empty());
    assert!(!response.absence_established);

    let mut timed = harness.request("SQLite");
    timed.max_time_ms = 0;
    let response = RecallService::new(&mut harness.workspace)
        .recall(timed)
        .expect("timeout response");
    assert!(matches!(
        response.status,
        RecallExecution::Timeout | RecallExecution::Complete
    ));
    assert!(!response.absence_established);
    if response.status == RecallExecution::Timeout {
        assert!(response.candidates.is_empty());
    }
}

#[test]
fn source_pruning_keeps_claim_envelope_without_a_quote() {
    let mut harness = Harness::new();
    let request = RetentionRequest {
        actor: "recall-test".to_owned(),
        scope: scope(),
        base_revision: harness.workspace.current_revision().expect("base"),
        idempotency_key: "prune-recall-source".to_owned(),
        operation: OperationKind::SourcePruning,
        selector: Selector::Source(rid(0x20)),
        effective: None,
        policy: RetentionPolicy::default(),
    };
    Retention::new(&mut harness.workspace)
        .execute(request)
        .expect("prune");
    let pruned_request = harness.request("SQLite");
    let response = RecallService::new(&mut harness.workspace)
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
            .all(|candidate| candidate.content_kind != ContentKind::SourceExcerpt)
    );
    assert!(!response.exhaustive);
}

#[test]
fn structured_unavailable_uses_declared_lexical_fallback() {
    let mut harness = Harness::new();
    let mut request = harness.request("SQLite");
    request.modes = BTreeSet::from([RecallMode::Structured]);
    request.allow_fallback = true;
    let response = RecallService::new(&mut harness.workspace)
        .recall(request)
        .expect("fallback recall");
    assert_eq!(response.status, RecallExecution::Partial);
    assert!(!response.candidates.is_empty());
    assert!(response.modes.iter().any(|mode| {
        mode.mode == RecallMode::Lexical
            && mode.status == mneme_recall::ModeStatus::Used
            && mode
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("fallback"))
    }));
    assert!(response.modes.iter().any(|mode| {
        mode.mode == RecallMode::Structured && mode.status == mneme_recall::ModeStatus::Unavailable
    }));
}

#[test]
fn independent_contradiction_survives_copied_descendants() {
    let mut harness = Harness::new();
    harness.add_copied_claim();
    harness.add_independent_contradiction();
    let request = harness.request("SQLite");
    let response = RecallService::new(&mut harness.workspace)
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
        .filter(|candidate| candidate.content_kind == ContentKind::Claim)
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
        let (source_record, source_blob) = build_source(
            source,
            revision,
            &scope(),
            text,
            "text/plain",
            Some(rid(0x10)),
            Some("docs/independent.txt"),
        )
        .expect("independent source");
        self.commit(
            scope(),
            "independent-source",
            vec![source_record],
            vec![source_blob],
        );
        let evidence_record = build_evidence(
            evidence,
            rev(0x35),
            &scope(),
            assertion,
            source,
            revision,
            Some(SourceSpan::new(0, text.len() as u64 - 1).expect("span")),
            Some("independent"),
            mneme_memory::SupportRelation::Supports,
            Origin::AuthoredStatement,
            &[],
        );
        let proposed = build_proposed_assertion(
            assertion,
            rev(0x4a),
            &scope(),
            rid(0x10),
            "deployment",
            Value::string("PostgreSQL, not only SQLite"),
            Stance::Deny,
            Origin::AuthoredStatement,
            "reviewer",
            ValidTime::always(),
            &[Reference::local(evidence, mneme_core::RecordKind::Evidence)],
            None,
            None,
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
