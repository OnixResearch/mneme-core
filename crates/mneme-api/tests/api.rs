//! Shared API behavior over a real workspace and tagged command documents.

#![allow(clippy::expect_used)]

use std::collections::BTreeSet;

use mneme_api::{ApiCommand, ApiService, LocalSession, ReviseAction, decode_command};
use mneme_core::{
    RecordId, RevisionId, ScopeClass, ScopeId, Timestamp, Value, WorkspaceRevisionId, fixtures,
};
use mneme_recall::{RecallMode, TemporalMode};
use mneme_store::{FixedClock, NoFaults, Workspace, WorkspaceConfig};
use serde_json::json;
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

struct Harness {
    _temp: TempDir,
    root: std::path::PathBuf,
    session_path: std::path::PathBuf,
}

impl Harness {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temp");
        let root = temp.path().join("workspace");
        Workspace::create(
            &root,
            WorkspaceConfig {
                clock: Box::new(FixedClock::new(Timestamp::from_nanos(1_000))),
                faults: Box::new(NoFaults),
            },
        )
        .expect("workspace");
        let session_path = temp.path().join("session.json");
        std::fs::write(
            &session_path,
            serde_json::to_vec(&json!({
                "principal": "agent-cedar",
                "workspace_root": root,
                "scopes": ["project:cedar"]
            }))
            .expect("session JSON"),
        )
        .expect("session file");
        Harness {
            _temp: temp,
            root,
            session_path,
        }
    }

    fn service(&self) -> ApiService {
        ApiService::new(LocalSession::load(&self.session_path).expect("session"))
    }

    fn revision(&self) -> WorkspaceRevisionId {
        Workspace::open(&self.root, WorkspaceConfig::default())
            .expect("workspace")
            .current_revision()
            .expect("revision")
    }

    fn record(&self, base: WorkspaceRevisionId, key: &str) -> ApiCommand {
        ApiCommand::Record {
            request_id: format!("record-{key}"),
            scope: scope(),
            base,
            key: key.to_owned(),
            records: fixtures::fixture_batch(),
            sources: vec![mneme_store::SourceBlobDraft {
                bytes: fixtures::SOURCE_TEXT.as_bytes().to_vec(),
                media_type: "text/asciidoc".into(),
            }],
        }
    }

    fn accept(&self, base: WorkspaceRevisionId) -> ApiCommand {
        ApiCommand::Accept {
            request_id: "accept".to_owned(),
            scope: scope(),
            base,
            key: "accept-author".to_owned(),
            assertion: fixtures::proposed_assertion().record_id,
            decision: rid(0xa1),
            decision_revision: rev(0xa2),
            accepted_revision: rev(0xa3),
            policy: "agent-api/v1".to_owned(),
            rationale: "accepted in API test".to_owned(),
        }
    }
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    value
        .as_dictionary()
        .and_then(|entries| entries.get(&Value::symbol(name)))
        .expect("response field")
}

fn symbol_text(value: &Value) -> &str {
    value
        .as_symbol()
        .map(|symbol| symbol.as_str())
        .expect("symbol")
}

fn revision_from(value: &Value) -> WorkspaceRevisionId {
    WorkspaceRevisionId::from_value(value, &mneme_core::Path::root()).expect("revision")
}

#[test]
fn record_retries_are_idempotent_and_conflicts_are_structural() {
    let harness = Harness::new();
    let service = harness.service();
    let base = harness.revision();
    let first = service.execute(&harness.record(base, "record-1"));
    assert!(first.ok);
    let first_revision = revision_from(field(field(&first.value, "data"), "revision"));
    let retry = service.execute(&harness.record(base, "record-1"));
    assert!(retry.ok);
    assert_eq!(
        revision_from(field(field(&retry.value, "data"), "revision")),
        first_revision
    );

    let mut changed = harness.record(base, "record-1");
    if let ApiCommand::Record { records, .. } = &mut changed {
        records.pop();
    }
    let conflict = service.execute(&changed);
    assert!(!conflict.ok);
    assert_eq!(
        symbol_text(field(field(&conflict.value, "error"), "code")),
        "conflict"
    );

    let stale = service.execute(&harness.record(base, "record-2"));
    assert!(!stale.ok);
    assert_eq!(
        symbol_text(field(field(&stale.value, "error"), "code")),
        "conflict"
    );
}

#[test]
fn acceptance_recall_and_explain_share_one_revision() {
    let harness = Harness::new();
    let service = harness.service();
    let base = harness.revision();
    let record = service.execute(&harness.record(base, "record"));
    assert!(record.ok);
    let after_record = revision_from(field(field(&record.value, "data"), "revision"));
    let accept = service.execute(&harness.accept(after_record));
    assert!(accept.ok, "{:?}", accept.value);
    let after_accept = revision_from(field(field(&accept.value, "data"), "revision"));

    let recall = ApiCommand::Recall {
        request_id: "recall".to_owned(),
        scope: scope(),
        revision: Some(after_accept),
        query: "SQLite".to_owned(),
        at: Timestamp::from_nanos(2_000),
        temporal: TemporalMode::Current,
        modes: BTreeSet::from([RecallMode::Lexical]),
        allow_stale: false,
        allow_fallback: true,
        allow_partial: true,
        include_disputed: false,
        include_hypothetical: false,
        max_items: 8,
        max_context_bytes: 4096,
        max_quote_bytes: 1024,
        max_time_ms: 500,
    };
    let recalled = service.execute(&recall);
    assert!(recalled.ok, "{:?}", recalled.value);
    assert_eq!(symbol_text(field(&recalled.value, "status")), "ok");
    let candidates = field(field(&recalled.value, "data"), "candidates")
        .as_sequence()
        .expect("candidates");
    assert!(!candidates.is_empty());
    assert_eq!(
        field(field(&recalled.value, "data"), "absence-established"),
        &Value::Boolean(false)
    );

    let explain = ApiCommand::Explain {
        request_id: "explain".to_owned(),
        scope: scope(),
        assertion: fixtures::proposed_assertion().record_id,
        max_nodes: 64,
        max_excerpt_bytes: 4096,
    };
    let explained = service.execute(&explain);
    assert!(explained.ok, "{:?}", explained.value);
    assert_eq!(
        field(field(&explained.value, "data"), "workspace-revision"),
        &after_accept.to_value()
    );
}

#[test]
fn scope_is_checked_before_content_or_receipt_lookup() {
    let harness = Harness::new();
    let service = harness.service();
    let mut command = harness.record(harness.revision(), "cross-scope");
    if let ApiCommand::Record { scope, .. } = &mut command {
        *scope = other_scope();
    }
    let response = service.execute(&command);
    assert!(!response.ok);
    assert_eq!(
        symbol_text(field(field(&response.value, "error"), "code")),
        "denied"
    );
    assert!(
        response
            .value
            .as_dictionary()
            .and_then(|entries| entries.get(&Value::symbol("context")))
            .is_none()
    );
}

#[test]
fn unsupported_versions_fail_before_mutation() {
    let value = Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("format"),
            Value::string("mneme.agent-command"),
        ),
        (mneme_core::Symbol::from("version"), Value::integer(99)),
        (mneme_core::Symbol::from("request-id"), Value::string("bad")),
        (
            mneme_core::Symbol::from("operation"),
            Value::symbol("record"),
        ),
        (mneme_core::Symbol::from("payload"), Value::dictionary([])),
    ]);
    let error = decode_command(&mneme_core::encode_document_string(&value))
        .expect_err("unsupported version");
    assert_eq!(error.code.as_str(), "unsupported-version");
}

#[test]
fn revise_dispute_and_retract_preserve_history() {
    let harness = Harness::new();
    let service = harness.service();
    let base = harness.revision();
    let record = service.execute(&harness.record(base, "record"));
    assert!(record.ok);
    let base = revision_from(field(field(&record.value, "data"), "revision"));
    let accepted = service.execute(&harness.accept(base));
    assert!(accepted.ok);
    let base = revision_from(field(field(&accepted.value, "data"), "revision"));
    let revise = ApiCommand::Revise {
        request_id: "dispute".to_owned(),
        scope: scope(),
        base,
        key: "dispute".to_owned(),
        assertion: fixtures::proposed_assertion().record_id,
        action: ReviseAction::Dispute,
        rationale: "conflicting evidence".to_owned(),
        decision: rid(0xb1),
        decision_revision: rev(0xb2),
        revised_revision: rev(0xb3),
        superseded_by: None,
    };
    let response = service.execute(&revise);
    assert!(response.ok, "{:?}", response.value);
    let after = revision_from(field(field(&response.value, "data"), "revision"));
    let view = mneme_memory::Memory::new(
        &mut Workspace::open(&harness.root, WorkspaceConfig::default()).expect("workspace"),
    )
    .view()
    .expect("view");
    let assertion = view
        .assertion(fixtures::proposed_assertion().record_id)
        .expect("assertion");
    assert_eq!(assertion.lifecycle, mneme_core::Lifecycle::Disputed);
    assert_eq!(view.revision(), after);
    drop(view);
    let reopened = Workspace::open(&harness.root, WorkspaceConfig::default()).expect("reopen");
    assert_eq!(
        reopened
            .record_revisions(fixtures::proposed_assertion().record_id)
            .expect("history")
            .len(),
        3
    );
}

#[test]
fn resume_is_read_only_and_forget_reports_lifecycle_progress() {
    let harness = Harness::new();
    let service = harness.service();
    let base = harness.revision();
    let record = service.execute(&harness.record(base, "record"));
    assert!(record.ok);
    let base = revision_from(field(field(&record.value, "data"), "revision"));
    let checkpoint = mneme_memory::build_checkpoint(
        rid(0xc1),
        rev(0xc2),
        &scope(),
        "finish the memory task",
        "waiting",
        &[],
        &[],
        base,
        Some("environment: test host"),
    )
    .into_envelope(mneme_core::RecordedTime::new(
        Timestamp::from_nanos(3_000),
        1,
    ));
    let record_checkpoint = ApiCommand::Record {
        request_id: "checkpoint".to_owned(),
        scope: scope(),
        base,
        key: "checkpoint".to_owned(),
        records: vec![checkpoint],
        sources: Vec::new(),
    };
    let checkpoint_commit = service.execute(&record_checkpoint);
    assert!(checkpoint_commit.ok, "{:?}", checkpoint_commit.value);
    let base = revision_from(field(field(&checkpoint_commit.value, "data"), "revision"));
    let resume = ApiCommand::Resume {
        request_id: "resume".to_owned(),
        scope: scope(),
        checkpoint: rid(0xc1),
    };
    let response = service.execute(&resume);
    assert!(response.ok, "{:?}", response.value);
    assert_eq!(
        field(field(&response.value, "data"), "goal"),
        &Value::string("finish the memory task")
    );
    assert_eq!(
        field(field(&response.value, "data"), "state"),
        &Value::symbol("waiting")
    );
    assert_eq!(harness.revision(), base);

    let forget = ApiCommand::Forget {
        request_id: "forget".to_owned(),
        scope: scope(),
        base,
        key: "forget-source".to_owned(),
        selector: mneme_retention::Selector::Source(fixtures::source_revision().record_id),
        effective: None,
    };
    let response = service.execute(&forget);
    assert!(response.ok, "{:?}", response.value);
    assert_eq!(
        field(field(&response.value, "data"), "logical-withdrawal"),
        &Value::Boolean(true)
    );
    assert!(
        field(field(&response.value, "data"), "physical-cleanup-complete")
            .as_boolean()
            .is_some()
    );
}

#[test]
fn proposal_inspection_keeps_proposed_status_before_acceptance() {
    let harness = Harness::new();
    let service = harness.service();
    let base = harness.revision();
    let record = service.execute(&harness.record(base, "record-proposal"));
    assert!(record.ok);
    let inspect = ApiCommand::ProposalInspect {
        request_id: "proposal".to_owned(),
        scope: scope(),
        assertion: fixtures::proposed_assertion().record_id,
    };
    let response = service.execute(&inspect);
    assert!(response.ok, "{:?}", response.value);
    assert_eq!(
        field(field(&response.value, "data"), "lifecycle"),
        &Value::symbol("proposed")
    );
}

#[test]
fn vertical_slice_lost_response_timeout_resume_and_forget() {
    let harness = Harness::new();
    let service = harness.service();
    let base = harness.revision();
    let first = service.execute(&harness.record(base, "vertical-record"));
    assert!(first.ok);
    let committed = revision_from(field(field(&first.value, "data"), "revision"));
    // The caller loses the first response and retries the identical command.
    let retry = service.execute(&harness.record(base, "vertical-record"));
    assert!(retry.ok);
    assert_eq!(
        revision_from(field(field(&retry.value, "data"), "revision")),
        committed
    );

    let accepted = service.execute(&harness.accept(committed));
    assert!(accepted.ok);
    let accepted_revision = revision_from(field(field(&accepted.value, "data"), "revision"));

    let recall = |max_time_ms| ApiCommand::Recall {
        request_id: "vertical-recall".to_owned(),
        scope: scope(),
        revision: Some(accepted_revision),
        query: "SQLite".to_owned(),
        at: Timestamp::from_nanos(2_000),
        temporal: TemporalMode::Current,
        modes: BTreeSet::from([RecallMode::Lexical]),
        allow_stale: false,
        allow_fallback: true,
        allow_partial: true,
        include_disputed: false,
        include_hypothetical: false,
        max_items: 2,
        max_context_bytes: 512,
        max_quote_bytes: 128,
        max_time_ms,
    };
    let timed = service.execute(&recall(0));
    assert!(
        !timed.ok || {
            let status = field(&timed.value, "status")
                .as_symbol()
                .map(|s| s.as_str());
            status == Some("ok") || status == Some("timeout")
        }
    );
    assert_eq!(
        field(field(&timed.value, "data"), "absence-established"),
        &Value::Boolean(false)
    );
    let bounded = service.execute(&recall(500));
    assert!(bounded.ok);
    let candidates = field(field(&bounded.value, "data"), "candidates")
        .as_sequence()
        .expect("candidates");
    assert!(!candidates.is_empty());
    assert!(candidates.len() <= 2);

    let explain = ApiCommand::Explain {
        request_id: "vertical-explain".to_owned(),
        scope: scope(),
        assertion: fixtures::proposed_assertion().record_id,
        max_nodes: 64,
        max_excerpt_bytes: 4096,
    };
    assert!(service.execute(&explain).ok);

    let checkpoint = mneme_memory::build_checkpoint(
        rid(0xd1),
        rev(0xd2),
        &scope(),
        "vertical task",
        "paused",
        &[],
        &[],
        accepted_revision,
        Some("environment observed before restart"),
    )
    .into_envelope(mneme_core::RecordedTime::new(
        Timestamp::from_nanos(3_000),
        1,
    ));
    let checkpoint_commit = ApiCommand::Record {
        request_id: "vertical-checkpoint".to_owned(),
        scope: scope(),
        base: accepted_revision,
        key: "vertical-checkpoint".to_owned(),
        records: vec![checkpoint],
        sources: Vec::new(),
    };
    let checkpoint_commit = service.execute(&checkpoint_commit);
    assert!(checkpoint_commit.ok);
    let checkpoint_revision =
        revision_from(field(field(&checkpoint_commit.value, "data"), "revision"));
    let resume = ApiCommand::Resume {
        request_id: "vertical-resume".to_owned(),
        scope: scope(),
        checkpoint: rid(0xd1),
    };
    let resumed = service.execute(&resume);
    assert!(resumed.ok);
    assert_eq!(
        field(field(&resumed.value, "data"), "current-revision"),
        &checkpoint_revision.to_value()
    );

    let revise = ApiCommand::Revise {
        request_id: "vertical-revise".to_owned(),
        scope: scope(),
        base: checkpoint_revision,
        key: "vertical-revise".to_owned(),
        assertion: fixtures::proposed_assertion().record_id,
        action: ReviseAction::Retract,
        rationale: "vertical slice retraction".to_owned(),
        decision: rid(0xd3),
        decision_revision: rev(0xd4),
        revised_revision: rev(0xd5),
        superseded_by: None,
    };
    assert!(service.execute(&revise).ok);

    let forget_base = harness.revision();
    let forget = ApiCommand::Forget {
        request_id: "vertical-forget".to_owned(),
        scope: scope(),
        base: forget_base,
        key: "vertical-forget".to_owned(),
        selector: mneme_retention::Selector::Source(fixtures::source_revision().record_id),
        effective: None,
    };
    let forgotten = service.execute(&forget);
    assert!(forgotten.ok);
    let receipt = field(field(&forgotten.value, "data"), "logical-withdrawal");
    assert_eq!(receipt, &Value::Boolean(true));
}
