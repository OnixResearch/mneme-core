//! Shared API behavior over a real workspace and tagged command documents.
#![allow(unknown_lints, no_unwrap)] // Octet custom lint names and test allowances
#![allow(clippy::expect_used)]

const CEDAR_TEXT: &str = "= Cedar Notes\n\n== Storage decision\n\nThe Cedar prototype uses SQLite for its local revision manifest.\n";
const BIRCH_TEXT: &str = "= Birch Private\n\nThe vault passphrase is tangerine-42.\n";
const PLAN_TEXT: &str = "= Birch plan\n\nWe could buy SQLite acquisition: 12 million.\n";

fn cedar() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
}
fn birch() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "birch").expect("scope")
}
fn plan_scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Hypothesis, "birch-plan").expect("scope")
}
fn rid(byte: u8) -> mneme_core::RecordId {
    mneme_core::RecordId::from_bytes([byte; 16])
}
fn rev(byte: u8) -> mneme_core::RevisionId {
    mneme_core::RevisionId::from_bytes([byte; 16])
}

/// Fixed identities for one seeded scope.
struct Ids {
    entity: u8,
    entity_revision: u8,
    source: u8,
    source_revision: u8,
    evidence: u8,
    evidence_revision: u8,
    assertion: u8,
    assertion_revision: u8,
}

const CEDAR_IDS: Ids = Ids {
    entity: 0x01,
    entity_revision: 0x11,
    source: 0x02,
    source_revision: 0x12,
    evidence: 0x05,
    evidence_revision: 0x15,
    assertion: 0x04,
    assertion_revision: 0x14,
};
const BIRCH_IDS: Ids = Ids {
    entity: 0x61,
    entity_revision: 0x71,
    source: 0x62,
    source_revision: 0x72,
    evidence: 0x65,
    evidence_revision: 0x75,
    assertion: 0x64,
    assertion_revision: 0x74,
};
const PLAN_IDS: Ids = Ids {
    entity: 0x81,
    entity_revision: 0x91,
    source: 0x82,
    source_revision: 0x92,
    evidence: 0x85,
    evidence_revision: 0x95,
    assertion: 0x84,
    assertion_revision: 0x94,
};

/// One seeded scope's record identities and the revision after seeding.
struct Seeded {
    source: mneme_core::RecordId,
    evidence: mneme_core::RecordId,
    assertion: mneme_core::RecordId,
    revision: mneme_core::WorkspaceRevisionId,
}

struct Harness {
    _temp: tempfile::TempDir,
    root: std::path::PathBuf,
    cedar_session: std::path::PathBuf,
    plan_session: std::path::PathBuf,
}

impl Harness {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temp");
        let root = temp.path().join("workspace");
        mneme_store::Workspace::create(
            &root,
            mneme_store::WorkspaceConfig {
                clock: Box::new(mneme_store::FixedClock::new(
                    mneme_core::Timestamp::from_nanos(1_000),
                )),
                faults: Box::new(mneme_store::NoFaults),
            },
        )
        .expect("workspace");
        let harness = Harness {
            _temp: temp,
            root,
            cedar_session: std::path::PathBuf::new(),
            plan_session: std::path::PathBuf::new(),
        };
        let cedar_session = harness.write_session("cedar-session.json", &["project:cedar"]);
        let plan_session = harness.write_session(
            "plan-session.json",
            &["project:cedar", "hypothesis:birch-plan"],
        );
        Harness {
            cedar_session,
            plan_session,
            ..harness
        }
    }

    fn write_session(&self, name: &str, scopes: &[&str]) -> std::path::PathBuf {
        let path = self.root.parent().expect("session directory").join(name);
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "principal": "agent-cedar",
                "workspace_root": self.root,
                "scopes": scopes
            }))
            .expect("session JSON"),
        )
        .expect("session file");
        path
    }

    fn service(&self, session: &std::path::Path) -> mneme_api::ApiService {
        mneme_api::ApiService::new(mneme_api::LocalSession::load(session).expect("session"))
    }

    fn cedar_service(&self) -> mneme_api::ApiService {
        self.service(&self.cedar_session)
    }

    fn open(&self) -> mneme_store::Workspace {
        mneme_store::Workspace::open(
            &self.root,
            mneme_store::WorkspaceConfig::new(
                Box::new(mneme_store::SystemClock),
                Box::new(mneme_store::NoFaults),
            ),
        )
        .expect("workspace")
    }

    fn revision(&self) -> mneme_core::WorkspaceRevisionId {
        self.open().current_revision().expect("revision")
    }

    fn operator_commit(
        &self,
        scope: &mneme_core::ScopeId,
        key: &str,
        records: Vec<mneme_store::RecordDraft>,
        sources: Vec<mneme_store::SourceBlobDraft>,
    ) -> mneme_core::WorkspaceRevisionId {
        let mut workspace = self.open();
        mneme_memory::Engine::new(&mut workspace, mneme_memory::Access::Operator)
            .commit(mneme_memory::Batch {
                actor: "operator".to_owned(),
                scope: scope.clone(),
                idempotency_key: key.to_owned(),
                records,
                source_blobs: sources,
                publications: Vec::new(),
            })
            .expect("operator commit")
            .revision
    }

    fn seed(
        &self,
        scope: &mneme_core::ScopeId,
        ids: &Ids,
        text: &'static str,
        value: &str,
    ) -> Seeded {
        self.seed_source(scope, ids, text);
        let span = mneme_core::SourceSpan::new(0, text.len() as u64 - 1).expect("span");
        let evidence = mneme_memory::build_evidence(
            rid(ids.evidence),
            rev(ids.evidence_revision),
            scope,
            mneme_memory::EvidenceOptions {
                assertion: rid(ids.assertion),
                source: rid(ids.source),
                source_revision: rev(ids.source_revision),
                span: Some(span),
                anchor: Some("storage-decision"),
                relation: mneme_memory::SupportRelation::Supports,
                origin: mneme_core::Origin::AuthoredStatement,
                ancestry: &[],
            },
        );
        let assertion = mneme_memory::build_proposed_assertion(
            rid(ids.assertion),
            rev(ids.assertion_revision),
            scope,
            mneme_memory::ProposedAssertionOptions {
                subject: rid(ids.entity),
                predicate: "storage-engine",
                value: mneme_core::Value::string(value),
                stance: mneme_memory::Stance::Affirm,
                origin: mneme_core::Origin::AuthoredStatement,
                asserted_by: "synthetic author",
                valid_time: mneme_core::ValidTime::always(),
                evidence: &[mneme_core::Reference::local(
                    rid(ids.evidence),
                    mneme_core::RecordKind::Evidence,
                )],
                extraction: None,
                superseded_by: None,
            },
        );
        let revision = self.operator_commit(
            scope,
            "seed-proposal",
            vec![evidence, assertion],
            Vec::new(),
        );
        Seeded {
            source: rid(ids.source),
            evidence: rid(ids.evidence),
            assertion: rid(ids.assertion),
            revision,
        }
    }

    /// Seed the entity and the source document that the seeded claim cites.
    fn seed_source(&self, scope: &mneme_core::ScopeId, ids: &Ids, text: &str) {
        self.operator_commit(
            scope,
            "seed-entity",
            vec![entity_draft(
                rid(ids.entity),
                rev(ids.entity_revision),
                scope,
            )],
            Vec::new(),
        );
        let (source, blob) = mneme_memory::build_source(
            rid(ids.source),
            rev(ids.source_revision),
            scope,
            mneme_memory::SourceOptions {
                bytes: text.as_bytes(),
                media_type: "text/asciidoc",
                entity: Some(rid(ids.entity)),
                path_hint: None,
            },
        )
        .expect("source");
        self.operator_commit(scope, "seed-source", vec![source], vec![blob]);
    }

    fn episode(
        &self,
        scope: &mneme_core::ScopeId,
        record: u8,
        revision: u8,
        kind: &str,
        summary: &str,
    ) -> mneme_core::RecordId {
        let draft = mneme_memory::build_episode(
            rid(record),
            rev(revision),
            scope,
            mneme_memory::EpisodeOptions {
                actor: "agent-cedar",
                episode_type: kind,
                occurred: mneme_core::ValidTime::always(),
                summary,
                source: None,
                related: &[],
            },
        );
        self.operator_commit(scope, &format!("episode-{record}"), vec![draft], Vec::new());
        rid(record)
    }

    fn envelope(&self, record: mneme_core::RecordId) -> mneme_core::RecordEnvelope {
        let workspace = self.open();
        let snapshot = workspace.snapshot().expect("snapshot");
        snapshot
            .records
            .into_iter()
            .find(|candidate| candidate.record_id == record)
            .expect("record")
    }
}

fn entity_draft(
    record: mneme_core::RecordId,
    revision: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
) -> mneme_store::RecordDraft {
    mneme_store::RecordDraft {
        schema_version: 1,
        kind: mneme_core::RecordKind::Entity,
        record_id: record,
        revision_id: revision,
        predecessor: None,
        scope: scope.clone(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("entity-type"),
                mneme_core::Value::symbol("project"),
            ),
            (
                mneme_core::Symbol::from("label"),
                mneme_core::Value::string("seeded project"),
            ),
            (
                mneme_core::Symbol::from("properties"),
                mneme_core::Value::symbol_dictionary([]),
            ),
        ]),
    }
}

fn envelope(draft: mneme_store::RecordDraft) -> mneme_core::RecordEnvelope {
    draft.into_envelope(mneme_core::RecordedTime::new(
        mneme_core::Timestamp::from_nanos(1),
        1,
    ))
}

fn field<'a>(value: &'a mneme_core::Value, name: &str) -> &'a mneme_core::Value {
    value
        .as_dictionary()
        .and_then(|entries| entries.get(&mneme_core::Value::symbol(name)))
        .expect("response field")
}

fn optional<'a>(value: &'a mneme_core::Value, name: &str) -> Option<&'a mneme_core::Value> {
    value
        .as_dictionary()
        .and_then(|entries| entries.get(&mneme_core::Value::symbol(name)))
}

fn symbol_text(value: &mneme_core::Value) -> &str {
    value
        .as_symbol()
        .map(|symbol| symbol.as_str())
        .expect("symbol")
}

fn text(value: &mneme_core::Value) -> &str {
    value.as_string().expect("text")
}

fn boolean(value: &mneme_core::Value) -> bool {
    value.as_boolean().expect("boolean")
}

fn integer(value: &mneme_core::Value) -> i64 {
    value
        .as_integer()
        .and_then(|integer| integer.to_i64())
        .expect("integer")
}

fn sequence<'a>(value: &'a mneme_core::Value, name: &str) -> &'a [mneme_core::Value] {
    field(value, name).as_sequence().expect("sequence")
}

fn data(response: &mneme_api::CallResponse) -> &mneme_core::Value {
    field(&response.value, "data")
}

fn error_of(response: &mneme_api::CallResponse) -> (&str, &str) {
    let error = field(&response.value, "error");
    (
        symbol_text(field(error, "code")),
        text(field(error, "message")),
    )
}

fn revision_from(value: &mneme_core::Value) -> mneme_core::WorkspaceRevisionId {
    mneme_core::WorkspaceRevisionId::from_value(value, &mneme_core::Path::root()).expect("revision")
}

fn committed_revision(response: &mneme_api::CallResponse) -> mneme_core::WorkspaceRevisionId {
    revision_from(field(data(response), "revision"))
}

fn context_revision(response: &mneme_api::CallResponse) -> mneme_core::WorkspaceRevisionId {
    revision_from(field(
        field(&response.value, "context"),
        "workspace-revision",
    ))
}

fn encoded(response: &mneme_api::CallResponse) -> String {
    mneme_core::encode_document_string(&response.value)
}

fn record_command(
    scope: &mneme_core::ScopeId,
    base: mneme_core::WorkspaceRevisionId,
    key: &str,
    records: Vec<mneme_core::RecordEnvelope>,
    sources: Vec<mneme_store::SourceBlobDraft>,
) -> mneme_api::ApiCommand {
    mneme_api::ApiCommand::Record {
        request_id: format!("record-{key}"),
        scope: scope.clone(),
        base,
        key: key.to_owned(),
        records,
        sources,
    }
}

fn accept_command(
    base: mneme_core::WorkspaceRevisionId,
    key: &str,
    assertion: mneme_core::RecordId,
) -> mneme_api::ApiCommand {
    mneme_api::ApiCommand::Accept {
        request_id: format!("accept-{key}"),
        scope: cedar(),
        base,
        key: key.to_owned(),
        assertion,
        decision: rid(0xa1),
        decision_revision: rev(0xa2),
        accepted_revision: rev(0xa3),
        policy: "agent-api/v1".to_owned(),
        rationale: "accepted in API test".to_owned(),
    }
}

fn revise_command(
    base: mneme_core::WorkspaceRevisionId,
    key: &str,
    assertion: mneme_core::RecordId,
    action: mneme_api::ReviseAction,
) -> mneme_api::ApiCommand {
    mneme_api::ApiCommand::Revise {
        request_id: format!("revise-{key}"),
        scope: cedar(),
        base,
        key: key.to_owned(),
        assertion,
        action,
        rationale: "explicit revision in API test".to_owned(),
        decision: rid(0xb1),
        decision_revision: rev(0xb2),
        revised_revision: rev(0xb3),
        superseded_by: None,
    }
}

/// The recall options that vary between fixtures.
#[derive(Clone, Copy)]
struct RecallOptions {
    temporal: mneme_recall::TemporalMode,
    include_hypothetical: bool,
    allow_stale: bool,
    max_items: usize,
}

impl RecallOptions {
    /// Current statements only, no flag set, and at most eight candidates.
    const CURRENT: RecallOptions = RecallOptions {
        temporal: mneme_recall::TemporalMode::Current,
        include_hypothetical: false,
        allow_stale: false,
        max_items: 8,
    };
}

fn recall_command(
    scope: &mneme_core::ScopeId,
    revision: Option<mneme_core::WorkspaceRevisionId>,
    query: &str,
    options: RecallOptions,
) -> mneme_api::ApiCommand {
    mneme_api::ApiCommand::Recall {
        request_id: "recall".to_owned(),
        scope: scope.clone(),
        revision,
        query: query.to_owned(),
        at: mneme_core::Timestamp::from_nanos(2_000),
        temporal: options.temporal,
        modes: std::collections::BTreeSet::from([mneme_recall::Mode::Lexical]),
        structured: None,
        allow_stale: options.allow_stale,
        allow_fallback: true,
        allow_partial: true,
        include_disputed: false,
        include_hypothetical: options.include_hypothetical,
        max_items: options.max_items,
        max_context_bytes: 4096,
        max_quote_bytes: 1024,
        max_time_ms: 500,
    }
}

fn explain_command(
    assertion: mneme_core::RecordId,
    max_excerpt_bytes: usize,
) -> mneme_api::ApiCommand {
    mneme_api::ApiCommand::Explain {
        request_id: "explain".to_owned(),
        scope: cedar(),
        assertion,
        max_nodes: 64,
        max_excerpt_bytes,
    }
}

fn forget_command(
    base: mneme_core::WorkspaceRevisionId,
    key: &str,
    selector: mneme_retention::Selector,
) -> mneme_api::ApiCommand {
    mneme_api::ApiCommand::Forget {
        request_id: format!("forget-{key}"),
        scope: cedar(),
        base,
        key: key.to_owned(),
        selector,
        effective: None,
    }
}

fn assert_no_context(response: &mneme_api::CallResponse) {
    assert!(
        optional(&response.value, "context").is_none(),
        "a failed response must not carry a context revision"
    );
}

#[test]
fn record_retries_are_idempotent_and_conflicts_are_structural() {
    let harness = Harness::new();
    let service = harness.cedar_service();
    let base = harness.revision();
    let first = service.execute(&record_command(
        &cedar(),
        base,
        "record-1",
        vec![envelope(entity_draft(rid(0x21), rev(0x31), &cedar()))],
        Vec::new(),
    ));
    assert!(first.ok, "{:?}", first.value);
    let retry = service.execute(&record_command(
        &cedar(),
        base,
        "record-1",
        vec![envelope(entity_draft(rid(0x21), rev(0x31), &cedar()))],
        Vec::new(),
    ));
    assert!(retry.ok);
    assert_eq!(committed_revision(&retry), committed_revision(&first));
    let conflict = service.execute(&record_command(
        &cedar(),
        base,
        "record-1",
        vec![envelope(entity_draft(rid(0x22), rev(0x32), &cedar()))],
        Vec::new(),
    ));
    assert!(!conflict.ok);
    assert_eq!(error_of(&conflict).0, "conflict");
    let stale = service.execute(&record_command(
        &cedar(),
        base,
        "record-2",
        vec![envelope(entity_draft(rid(0x23), rev(0x33), &cedar()))],
        Vec::new(),
    ));
    assert!(!stale.ok);
    assert_eq!(error_of(&stale).0, "conflict");
}

#[test]
fn accept_retries_replay_and_a_stale_base_is_a_conflict() {
    let harness = Harness::new();
    let service = harness.cedar_service();
    let seeded = harness.seed(&cedar(), &CEDAR_IDS, CEDAR_TEXT, "SQLite");
    let accepted = service.execute(&accept_command(
        seeded.revision,
        "accept-1",
        seeded.assertion,
    ));
    assert!(accepted.ok, "{:?}", accepted.value);
    let accepted_revision = committed_revision(&accepted);
    let retry = service.execute(&accept_command(
        seeded.revision,
        "accept-1",
        seeded.assertion,
    ));
    assert!(retry.ok, "a lost response must replay: {:?}", retry.value);
    assert_eq!(committed_revision(&retry), accepted_revision);
    // A different fresh command from the superseded base is a conflict, not
    // invalid input.
    let stale = service.execute(&accept_command(
        seeded.revision,
        "accept-2",
        seeded.assertion,
    ));
    assert!(!stale.ok);
    assert_eq!(error_of(&stale).0, "conflict");
    assert!(error_of(&stale).1.contains("base revision"));
    assert_eq!(harness.revision(), accepted_revision);
}

#[test]
fn explain_returns_the_revision_it_evaluated() {
    let harness = Harness::new();
    let service = harness.cedar_service();
    let seeded = harness.seed(&cedar(), &CEDAR_IDS, CEDAR_TEXT, "SQLite");
    let accepted = service.execute(&accept_command(seeded.revision, "accept", seeded.assertion));
    assert!(accepted.ok, "{:?}", accepted.value);
    let accepted_revision = committed_revision(&accepted);
    let explained = service.execute(&explain_command(seeded.assertion, 4096));
    assert!(explained.ok, "{:?}", explained.value);
    assert_eq!(
        revision_from(field(data(&explained), "workspace-revision")),
        accepted_revision
    );
    assert_eq!(context_revision(&explained), accepted_revision);
}

#[test]
fn dispute_through_the_api_changes_lifecycle_and_preserves_history() {
    let harness = Harness::new();
    let service = harness.cedar_service();
    let seeded = harness.seed(&cedar(), &CEDAR_IDS, CEDAR_TEXT, "SQLite");
    let accepted = service.execute(&accept_command(seeded.revision, "accept", seeded.assertion));
    assert!(accepted.ok, "{:?}", accepted.value);
    let accepted_revision = committed_revision(&accepted);
    let response = service.execute(&revise_command(
        accepted_revision,
        "dispute",
        seeded.assertion,
        mneme_api::ReviseAction::Dispute,
    ));
    assert!(response.ok, "{:?}", response.value);
    let after = committed_revision(&response);
    let mut workspace = harness.open();
    let view = mneme_memory::Engine::new(&mut workspace, mneme_memory::Access::Operator)
        .view()
        .expect("view");
    let assertion = view.assertion(seeded.assertion).expect("assertion");
    assert_eq!(assertion.lifecycle, mneme_core::Lifecycle::Disputed);
    assert_eq!(view.revision(), after);
    drop(view);
    assert_eq!(
        workspace
            .record_revisions(seeded.assertion)
            .expect("history")
            .len(),
        3
    );
}

#[test]
fn cross_scope_reads_look_like_unknown_ids() {
    let harness = Harness::new();
    let service = harness.cedar_service();
    let cedar_seeded = harness.seed(&cedar(), &CEDAR_IDS, CEDAR_TEXT, "SQLite");
    let birch_seeded = harness.seed(&birch(), &BIRCH_IDS, BIRCH_TEXT, "tangerine-42");
    let birch_checkpoint = harness.operator_commit(
        &birch(),
        "birch-checkpoint",
        vec![mneme_memory::build_checkpoint(
            rid(0xc9),
            rev(0xca),
            &birch(),
            mneme_memory::CheckpointOptions {
                goal: "birch private task",
                state: "paused",
                episodes: &[],
                verified_outcomes: &[],
                revision: birch_seeded.revision,
                note: None,
            },
        )],
        Vec::new(),
    );
    let before = birch_checkpoint;
    let unknown = rid(0xee);

    let foreign_explain = service.execute(&explain_command(birch_seeded.assertion, 4096));
    let unknown_explain = service.execute(&explain_command(unknown, 4096));
    assert_eq!(error_of(&foreign_explain), error_of(&unknown_explain));
    assert_eq!(error_of(&foreign_explain).0, "unavailable");
    assert_no_context(&foreign_explain);

    let foreign_inspect = service.execute(&mneme_api::ApiCommand::ProposalInspect {
        request_id: "inspect-foreign".to_owned(),
        scope: cedar(),
        assertion: birch_seeded.assertion,
    });
    let unknown_inspect = service.execute(&mneme_api::ApiCommand::ProposalInspect {
        request_id: "inspect-unknown".to_owned(),
        scope: cedar(),
        assertion: unknown,
    });
    assert_eq!(error_of(&foreign_inspect), error_of(&unknown_inspect));
    assert_no_context(&foreign_inspect);

    let foreign_resume = service.execute(&mneme_api::ApiCommand::Resume {
        request_id: "resume-foreign".to_owned(),
        scope: cedar(),
        checkpoint: rid(0xc9),
    });
    let unknown_resume = service.execute(&mneme_api::ApiCommand::Resume {
        request_id: "resume-unknown".to_owned(),
        scope: cedar(),
        checkpoint: unknown,
    });
    assert_eq!(error_of(&foreign_resume), error_of(&unknown_resume));
    assert_no_context(&foreign_resume);

    // A same-scope record of the wrong kind is a request error, not an
    // authorization answer.
    let wrong_kind = service.execute(&mneme_api::ApiCommand::Resume {
        request_id: "resume-assertion".to_owned(),
        scope: cedar(),
        checkpoint: cedar_seeded.assertion,
    });
    assert_eq!(error_of(&wrong_kind).0, "invalid-input");

    let foreign_forget = service.execute(&forget_command(
        harness.revision(),
        "forget-foreign",
        mneme_retention::Selector::Source(birch_seeded.source),
    ));
    let unknown_forget = service.execute(&forget_command(
        harness.revision(),
        "forget-unknown",
        mneme_retention::Selector::Source(unknown),
    ));
    assert_eq!(error_of(&foreign_forget), error_of(&unknown_forget));
    assert_eq!(error_of(&foreign_forget).0, "unavailable");
    assert_no_context(&foreign_forget);

    // Recall in the caller's own scope cannot reach another scope's text.
    let scoped = service.execute(&recall_command(
        &cedar(),
        Some(before),
        "tangerine",
        RecallOptions {
            temporal: mneme_recall::TemporalMode::Inspection,
            ..RecallOptions::CURRENT
        },
    ));
    assert!(scoped.ok, "{:?}", scoped.value);
    assert!(sequence(data(&scoped), "candidates").is_empty());
    assert!(!boolean(field(data(&scoped), "absence-established")));
    assert_eq!(harness.revision(), before);
}

#[test]
fn cross_scope_evidence_is_refused_on_write() {
    let harness = Harness::new();
    let service = harness.cedar_service();
    let birch_seeded = harness.seed(&birch(), &BIRCH_IDS, BIRCH_TEXT, "tangerine-42");
    harness.seed(&cedar(), &CEDAR_IDS, CEDAR_TEXT, "SQLite");
    let before = harness.revision();
    let evidence = mneme_memory::build_evidence(
        rid(0x0a),
        rev(0x1a),
        &cedar(),
        mneme_memory::EvidenceOptions {
            assertion: rid(0x0b),
            source: birch_seeded.source,
            source_revision: rev(BIRCH_IDS.source_revision),
            span: Some(mneme_core::SourceSpan::new(0, 5).expect("span")),
            anchor: Some("vault"),
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    let assertion = mneme_memory::build_proposed_assertion(
        rid(0x0b),
        rev(0x1b),
        &cedar(),
        mneme_memory::ProposedAssertionOptions {
            subject: rid(CEDAR_IDS.entity),
            predicate: "storage-engine",
            value: mneme_core::Value::string("tangerine-42"),
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "agent-cedar",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[mneme_core::Reference::local(
                rid(0x0a),
                mneme_core::RecordKind::Evidence,
            )],
            extraction: None,
            superseded_by: None,
        },
    );
    let response = service.execute(&record_command(
        &cedar(),
        before,
        "cross-evidence",
        vec![envelope(evidence), envelope(assertion)],
        Vec::new(),
    ));
    assert!(!response.ok, "{:?}", response.value);
    assert_eq!(error_of(&response).0, "invalid-input");
    let document = encoded(&response);
    assert!(!document.contains(&birch_seeded.source.to_hex()));
    assert!(!document.contains(&rev(BIRCH_IDS.source_revision).to_hex()));
    assert_eq!(harness.revision(), before);
    assert_eq!(
        error_of(&service.execute(&explain_command(rid(0x0b), 4096))).0,
        "unavailable"
    );
}

#[test]
fn record_cannot_take_over_or_rescope_a_foreign_record() {
    let harness = Harness::new();
    let service = harness.cedar_service();
    harness.seed(&birch(), &BIRCH_IDS, BIRCH_TEXT, "tangerine-42");
    let before = harness.revision();
    let mut hijack = harness.envelope(rid(BIRCH_IDS.assertion));
    hijack.scope = cedar();
    hijack.predecessor = None;
    hijack.payload.insert(
        mneme_core::Symbol::from("value"),
        mneme_core::Value::string("hijacked by cedar"),
    );
    let response = service.execute(&record_command(
        &cedar(),
        before,
        "hijack",
        vec![hijack],
        Vec::new(),
    ));
    assert!(!response.ok, "{:?}", response.value);
    assert_eq!(error_of(&response).0, "unavailable");
    assert_eq!(error_of(&response).1, mneme_api::UNAVAILABLE_RECORD);
    let document = encoded(&response);
    assert!(!document.contains(&rev(BIRCH_IDS.assertion_revision).to_hex()));
    assert_eq!(harness.revision(), before);
    let stored = harness.envelope(rid(BIRCH_IDS.assertion));
    assert_eq!(
        field(&stored.payload.to_value(), "value"),
        &mneme_core::Value::string("tangerine-42")
    );
    assert_eq!(stored.scope, birch());
}

#[test]
fn record_refuses_decisions_and_lifecycle_revisions() {
    let harness = Harness::new();
    let service = harness.cedar_service();
    let seeded = harness.seed(&cedar(), &CEDAR_IDS, CEDAR_TEXT, "SQLite");
    let before = harness.revision();
    let forged = mneme_memory::build_decision(
        rid(0x51),
        rev(0x52),
        &cedar(),
        mneme_memory::DecisionOptions {
            kind: mneme_memory::DecisionKind::Acceptance,
            target: seeded.assertion,
            actor: "human:britton (manual review)",
            policy: "manual-review/v1",
            input_revision: before,
            outcome: "accepted",
            rationale: "forged reviewer",
            evidence: &[],
            related: &[],
        },
    );
    let decision = service.execute(&record_command(
        &cedar(),
        before,
        "forged-decision",
        vec![envelope(forged)],
        Vec::new(),
    ));
    assert!(!decision.ok);
    assert_eq!(error_of(&decision).0, "invalid-input");
    assert!(error_of(&decision).1.contains("accept or revise"));

    let current = harness.envelope(seeded.assertion);
    let accepted = mneme_memory::build_assertion_revision(
        &current,
        rev(0x53),
        mneme_core::Lifecycle::Accepted,
        mneme_core::Reference::local(rid(0x54), mneme_core::RecordKind::Decision),
        None,
    );
    let lifecycle = service.execute(&record_command(
        &cedar(),
        before,
        "forged-acceptance",
        vec![envelope(accepted)],
        Vec::new(),
    ));
    assert!(!lifecycle.ok);
    assert_eq!(error_of(&lifecycle).0, "invalid-input");
    assert_eq!(harness.revision(), before);
}

#[test]
fn accept_and_revise_check_the_from_state() {
    let harness = Harness::new();
    let service = harness.cedar_service();
    let seeded = harness.seed(&cedar(), &CEDAR_IDS, CEDAR_TEXT, "SQLite");
    let accepted = service.execute(&accept_command(seeded.revision, "accept", seeded.assertion));
    assert!(accepted.ok, "{:?}", accepted.value);
    let accepted_revision = committed_revision(&accepted);

    let again = service.execute(&accept_command(
        accepted_revision,
        "accept-again",
        seeded.assertion,
    ));
    assert!(!again.ok);
    assert_eq!(error_of(&again).0, "conflict");
    assert!(error_of(&again).1.contains("not permitted"));

    let retracted = service.execute(&revise_command(
        accepted_revision,
        "retract",
        seeded.assertion,
        mneme_api::ReviseAction::Retract,
    ));
    assert!(retracted.ok, "{:?}", retracted.value);
    let retracted_revision = committed_revision(&retracted);

    let double = service.execute(&revise_command(
        retracted_revision,
        "retract-again",
        seeded.assertion,
        mneme_api::ReviseAction::Retract,
    ));
    assert!(!double.ok);
    assert_eq!(error_of(&double).0, "conflict");

    let reaccept = service.execute(&accept_command(
        retracted_revision,
        "accept-rejected",
        seeded.assertion,
    ));
    assert!(!reaccept.ok);
    assert_eq!(error_of(&reaccept).0, "conflict");
    assert!(error_of(&reaccept).1.contains("retracted"));
}

#[test]
fn recall_reports_claim_status_and_limitations() {
    let harness = Harness::new();
    let service = harness.cedar_service();
    let seeded = harness.seed(&cedar(), &CEDAR_IDS, CEDAR_TEXT, "SQLite");
    let accepted = service.execute(&accept_command(seeded.revision, "accept", seeded.assertion));
    assert!(accepted.ok);
    let accepted_revision = committed_revision(&accepted);

    let current = service.execute(&recall_command(
        &cedar(),
        Some(accepted_revision),
        "SQLite",
        RecallOptions::CURRENT,
    ));
    assert!(current.ok, "{:?}", current.value);
    let claim = claim_candidate(&current);
    assert_eq!(
        symbol_text(field(field(claim, "claim-status"), "lifecycle")),
        "accepted"
    );
    assert_eq!(
        symbol_text(field(field(claim, "claim-status"), "stance")),
        "affirm"
    );
    let evidence = field(claim, "evidence")
        .as_sequence()
        .expect("evidence")
        .first()
        .expect("one evidence item");
    assert_eq!(symbol_text(field(evidence, "relation")), "supports");
    assert!(!boolean(field(evidence, "withdrawn")));
    let modes = field(data(&current), "modes").as_sequence().expect("modes");
    let lexical = modes
        .iter()
        .find(|mode| symbol_text(field(mode, "mode")) == "lexical")
        .expect("lexical report");
    assert!(optional(lexical, "index-version").is_some());
    assert!(optional(lexical, "relation-exhaustive").is_some());
    assert!(optional(lexical, "reason").is_some());
    assert!(optional(field(lexical, "coverage"), "reason").is_some());
    assert!(integer(field(field(data(&current), "context"), "schema-version")) > 0);
    assert!(!boolean(field(field(data(&current), "context"), "stale")));

    // Inspection of the earlier pinned revision still reports the proposal.
    let inspection = service.execute(&recall_command(
        &cedar(),
        Some(seeded.revision),
        "SQLite",
        RecallOptions {
            temporal: mneme_recall::TemporalMode::Inspection,
            allow_stale: true,
            ..RecallOptions::CURRENT
        },
    ));
    assert!(inspection.ok, "{:?}", inspection.value);
    assert!(boolean(field(field(data(&inspection), "context"), "stale")));
    let proposed = claim_candidate(&inspection);
    assert_eq!(
        symbol_text(field(field(proposed, "claim-status"), "lifecycle")),
        "proposed"
    );
}

fn claim_candidate(response: &mneme_api::CallResponse) -> &mneme_core::Value {
    sequence(data(response), "candidates")
        .iter()
        .find(|candidate| symbol_text(field(candidate, "content-kind")) == "claim")
        .expect("claim candidate")
}

#[test]
fn recall_does_not_widen_hypothetical_scopes() {
    let harness = Harness::new();
    harness.seed(&cedar(), &CEDAR_IDS, CEDAR_TEXT, "SQLite");
    harness.seed(
        &plan_scope(),
        &PLAN_IDS,
        PLAN_TEXT,
        "SQLite acquisition: 12 million",
    );
    let revision = harness.revision();
    let query = recall_command(
        &cedar(),
        Some(revision),
        "SQLite",
        RecallOptions {
            temporal: mneme_recall::TemporalMode::Inspection,
            include_hypothetical: true,
            ..RecallOptions::CURRENT
        },
    );
    let plan_assertion = rid(PLAN_IDS.assertion).to_value();
    let limited = harness.cedar_service().execute(&query);
    assert!(limited.ok, "{:?}", limited.value);
    assert!(
        !sequence(data(&limited), "candidates")
            .iter()
            .any(|candidate| optional(candidate, "assertion") == Some(&plan_assertion))
    );

    let authorized = harness.service(&harness.plan_session).execute(&query);
    assert!(authorized.ok, "{:?}", authorized.value);
    assert!(
        sequence(data(&authorized), "candidates")
            .iter()
            .any(|candidate| optional(candidate, "assertion") == Some(&plan_assertion))
    );
}

#[test]
fn explain_reports_spans_truncation_and_derivations() {
    let harness = Harness::new();
    let service = harness.cedar_service();
    let seeded = harness.seed(&cedar(), &CEDAR_IDS, CEDAR_TEXT, "SQLite");
    let cut = service.execute(&explain_command(seeded.assertion, 5));
    assert!(cut.ok, "{:?}", cut.value);
    assert!(boolean(field(data(&cut), "truncated")));
    assert_eq!(integer(field(data(&cut), "inaccessible-decisions")), 0);
    assert!(integer(field(data(&cut), "visited-nodes")) >= 1);
    assert!(field(data(&cut), "derivations").as_sequence().is_some());
    let evidence = sequence(data(&cut), "evidence")
        .first()
        .expect("one evidence item")
        .clone();
    assert_eq!(integer(field(&evidence, "span-start")), 0);
    assert_eq!(
        integer(field(&evidence, "span-end")),
        CEDAR_TEXT.len() as i64 - 1
    );
    assert!(boolean(field(&evidence, "excerpt-truncated")));
    assert!(!boolean(field(&evidence, "withdrawn")));
    assert!(boolean(field(&evidence, "eligible")));
    let excerpt = field(&evidence, "excerpt").as_bytes().expect("excerpt");
    assert!(excerpt.len() <= 5);

    let whole = service.execute(&explain_command(seeded.assertion, 4096));
    assert!(whole.ok);
    assert!(!boolean(field(data(&whole), "truncated")));
    let evidence = sequence(data(&whole), "evidence")
        .first()
        .expect("one evidence item")
        .clone();
    assert!(!boolean(field(&evidence, "excerpt-truncated")));
}

#[test]
fn resume_reports_plan_uncertainty_and_pinned_revision() {
    let harness = Harness::new();
    let service = harness.cedar_service();
    harness.seed(&cedar(), &CEDAR_IDS, CEDAR_TEXT, "SQLite");
    let intent = harness.episode(&cedar(), 0x31, 0x41, "intent", "write the report");
    let attempt = harness.episode(&cedar(), 0x32, 0x42, "attempt", "publish the report");
    let observation = harness.episode(&cedar(), 0x33, 0x43, "observation", "host clock is UTC");
    let outcome = harness.episode(&cedar(), 0x34, 0x44, "outcome", "report drafted");
    let base = harness.revision();
    let checkpoint = mneme_memory::build_checkpoint(
        rid(0xc1),
        rev(0xc2),
        &cedar(),
        mneme_memory::CheckpointOptions {
            goal: "finish the memory task",
            state: "waiting",
            episodes: &[
                mneme_core::Reference::local(intent, mneme_core::RecordKind::Episode),
                mneme_core::Reference::local(attempt, mneme_core::RecordKind::Episode),
                mneme_core::Reference::local(observation, mneme_core::RecordKind::Episode),
                mneme_core::Reference::local(outcome, mneme_core::RecordKind::Episode),
            ],
            verified_outcomes: &[mneme_core::Reference::local(
                outcome,
                mneme_core::RecordKind::Episode,
            )],
            revision: base,
            note: Some("environment: test host"),
        },
    );
    let committed = service.execute(&record_command(
        &cedar(),
        base,
        "checkpoint",
        vec![envelope(checkpoint)],
        Vec::new(),
    ));
    assert!(committed.ok, "{:?}", committed.value);
    let checkpoint_revision = committed_revision(&committed);
    let resume = mneme_api::ApiCommand::Resume {
        request_id: "resume".to_owned(),
        scope: cedar(),
        checkpoint: rid(0xc1),
    };
    let resumed = service.execute(&resume);
    assert!(resumed.ok, "{:?}", resumed.value);
    assert_eq!(
        field(data(&resumed), "goal"),
        &mneme_core::Value::string("finish the memory task")
    );
    assert_eq!(
        field(data(&resumed), "state"),
        &mneme_core::Value::symbol("waiting")
    );
    assert_eq!(context_revision(&resumed), checkpoint_revision);
    assert_eq!(
        revision_from(field(data(&resumed), "current-revision")),
        checkpoint_revision
    );
    assert!(!boolean(field(data(&resumed), "revision-changed")));
    assert_eq!(
        integer(field(data(&resumed), "revisions-after-checkpoint")),
        0
    );
    assert_eq!(
        field(data(&resumed), "planned")
            .as_sequence()
            .expect("planned")
            .len(),
        1
    );
    assert_eq!(
        field(data(&resumed), "outcomes")
            .as_sequence()
            .expect("outcomes")
            .len(),
        1
    );
    let unresolved = sequence(data(&resumed), "unresolved-attempts");
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0], attempt.to_value());
    assert!(!sequence(data(&resumed), "uncertainties").is_empty());
    assert!(!sequence(data(&resumed), "preconditions").is_empty());
    assert!(!boolean(field(data(&resumed), "precondition-changed")));

    harness.episode(&cedar(), 0x35, 0x45, "observation", "host clock moved");
    let changed = service.execute(&resume);
    assert!(changed.ok);
    assert!(boolean(field(data(&changed), "revision-changed")));
    assert!(integer(field(data(&changed), "revisions-after-checkpoint")) >= 1);
    assert!(boolean(field(data(&changed), "precondition-changed")));
    assert!(
        sequence(data(&changed), "preconditions")
            .iter()
            .any(|entry| symbol_text(field(entry, "basis")) == "newer")
    );
    assert_eq!(
        revision_from(field(data(&changed), "current-revision")),
        context_revision(&changed)
    );
    assert_eq!(harness.revision(), context_revision(&changed));
}

#[test]
fn forgotten_target_differs_from_a_never_existing_id() {
    let harness = Harness::new();
    let service = harness.cedar_service();
    let seeded = harness.seed(&cedar(), &CEDAR_IDS, CEDAR_TEXT, "SQLite");
    let forgotten = service.execute(&forget_command(
        seeded.revision,
        "forget-source",
        mneme_retention::Selector::Source(seeded.source),
    ));
    assert_eq!(
        field(data(&forgotten), "logical-withdrawal"),
        &mneme_core::Value::Boolean(true),
        "{:?}",
        forgotten.value
    );

    let erased = service.execute(&explain_command(seeded.evidence, 4096));
    let unknown = service.execute(&explain_command(rid(0xee), 4096));
    assert_eq!(error_of(&erased).0, "unavailable");
    assert_eq!(error_of(&unknown).0, "unavailable");
    assert_eq!(error_of(&erased).1, mneme_api::FORGOTTEN_TARGET);
    assert_eq!(error_of(&unknown).1, mneme_api::UNAVAILABLE_RECORD);
}

#[test]
fn proposal_inspection_reports_status_at_the_read_revision() {
    let harness = Harness::new();
    let service = harness.cedar_service();
    let seeded = harness.seed(&cedar(), &CEDAR_IDS, CEDAR_TEXT, "SQLite");
    let response = service.execute(&mneme_api::ApiCommand::ProposalInspect {
        request_id: "inspect".to_owned(),
        scope: cedar(),
        assertion: seeded.assertion,
    });
    assert!(response.ok, "{:?}", response.value);
    assert_eq!(symbol_text(field(data(&response), "lifecycle")), "proposed");
    assert_eq!(context_revision(&response), seeded.revision);
}

#[test]
fn forget_receipt_reports_replay_prevention_and_barrier() {
    let harness = Harness::new();
    let service = harness.cedar_service();
    let seeded = harness.seed(&cedar(), &CEDAR_IDS, CEDAR_TEXT, "SQLite");
    let forget = forget_command(
        seeded.revision,
        "forget-receipt",
        mneme_retention::Selector::Source(seeded.source),
    );
    let receipt = service.execute(&forget);
    assert_eq!(
        field(data(&receipt), "logical-withdrawal"),
        &mneme_core::Value::Boolean(true),
        "{:?}",
        receipt.value
    );
    // The transport status is a completion claim: reporting success while
    // cleanup is incomplete would hide pending deletion.
    if receipt.ok {
        assert!(boolean(field(data(&receipt), "physical-cleanup-complete")));
    }
    let operation = text(field(data(&receipt), "operation-id")).to_owned();
    let barrier = revision_from(field(data(&receipt), "outcome-revision"));
    assert_eq!(context_revision(&receipt), barrier);
    assert_eq!(
        symbol_text(field(data(&receipt), "operation-kind")),
        "forget"
    );
    assert!(boolean(field(data(&receipt), "replay-prevention")));
    assert!(
        sequence(data(&receipt), "retained-metadata")
            .iter()
            .any(|entry| text(entry) == "content-replay-block")
    );
    assert!(!sequence(data(&receipt), "locations").is_empty());
    assert!(
        integer(field(
            field(data(&receipt), "dependent-invalidation"),
            "suppressed-records"
        )) >= 1
    );

    // An unrelated commit must not relabel the receipt on retry.
    let after = harness.revision();
    let advance = service.execute(&record_command(
        &cedar(),
        after,
        "unrelated",
        vec![envelope(entity_draft(rid(0x26), rev(0x36), &cedar()))],
        Vec::new(),
    ));
    assert!(advance.ok, "{:?}", advance.value);
    let retry = service.execute(&forget);
    assert_eq!(text(field(data(&retry), "operation-id")), operation);
    assert_eq!(context_revision(&retry), barrier);
    assert_eq!(
        revision_from(field(data(&retry), "outcome-revision")),
        barrier
    );
}

fn command_document(operation: &str, payload: mneme_core::Value) -> String {
    mneme_core::encode_document_string(&mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("format"),
            mneme_core::Value::string(mneme_api::COMMAND_FORMAT),
        ),
        (
            mneme_core::Symbol::from("version"),
            mneme_core::Value::integer(mneme_api::COMMAND_VERSION),
        ),
        (
            mneme_core::Symbol::from("request-id"),
            mneme_core::Value::string("malformed"),
        ),
        (
            mneme_core::Symbol::from("operation"),
            mneme_core::Value::symbol(operation),
        ),
        (mneme_core::Symbol::from("payload"), payload),
    ]))
}

fn recall_payload(extra: Vec<(&str, mneme_core::Value)>) -> mneme_core::Value {
    let mut entries = vec![
        (
            mneme_core::Symbol::from("scope"),
            mneme_core::Value::string("project:cedar"),
        ),
        (
            mneme_core::Symbol::from("query"),
            mneme_core::Value::string("SQLite"),
        ),
        (
            mneme_core::Symbol::from("at"),
            mneme_core::Value::string("1970-01-01T00:00:00.000002Z"),
        ),
        (
            mneme_core::Symbol::from("temporal"),
            mneme_core::Value::symbol("current"),
        ),
    ];
    for (name, value) in extra {
        entries.push((mneme_core::Symbol::from(name), value));
    }
    mneme_core::Value::symbol_dictionary(entries)
}

#[test]
fn malformed_and_unknown_members_are_refused() {
    // The documented enum encoding is a symbol, consistent with every other
    // enum member.
    let decoded = mneme_api::decode(&command_document(
        "recall",
        recall_payload(vec![("temporal", mneme_core::Value::symbol("historical"))]),
    ))
    .expect("symbol temporal decodes");
    assert!(
        matches!(
            decoded,
            mneme_api::ApiCommand::Recall {
                temporal: mneme_recall::TemporalMode::Historical,
                ..
            }
        ),
        "the symbol decodes as a historical recall command"
    );
    let unknown_mode = mneme_api::decode(&command_document(
        "recall",
        recall_payload(vec![(
            "temporal",
            mneme_core::Value::symbol("no-such-mode"),
        )]),
    ))
    .expect_err("unknown temporal symbol is refused");
    assert_eq!(unknown_mode.code.as_str(), "invalid-input");

    let text_temporal = mneme_api::decode(&command_document(
        "recall",
        recall_payload(vec![("temporal", mneme_core::Value::string("current"))]),
    ))
    .expect_err("text temporal is refused");
    assert_eq!(text_temporal.code.as_str(), "invalid-input");

    let wrong_boolean = mneme_api::decode(&command_document(
        "recall",
        recall_payload(vec![("allow-stale", mneme_core::Value::string("true"))]),
    ))
    .expect_err("text boolean is refused");
    assert_eq!(wrong_boolean.code.as_str(), "invalid-input");

    let unknown_member = mneme_api::decode(&command_document(
        "recall",
        recall_payload(vec![("max_items", mneme_core::Value::integer(1))]),
    ))
    .expect_err("unknown member is refused");
    assert_eq!(unknown_member.code.as_str(), "invalid-input");
    assert!(
        unknown_member
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.to_string().contains("max_items"))
    );

    let unsupported_option = mneme_api::decode(&command_document(
        "recall",
        recall_payload(vec![
            ("tokenizer", mneme_core::Value::string("cl100k_base")),
            ("max-context-tokens", mneme_core::Value::integer(1)),
        ]),
    ))
    .expect_err("unsupported tokenizer option is refused");
    assert_eq!(unsupported_option.code.as_str(), "invalid-input");
}

#[test]
fn unsupported_schema_and_tag_failures_keep_their_codes_and_diagnostics() {
    let harness = Harness::new();
    let before = harness.revision();
    let mut newer = mneme_core::fixtures::entity();
    newer.schema_version = 99;
    let document = command_document(
        "record",
        mneme_core::Value::symbol_dictionary([
            (
                mneme_core::Symbol::from("scope"),
                mneme_core::Value::string("project:cedar"),
            ),
            (mneme_core::Symbol::from("base-revision"), before.to_value()),
            (
                mneme_core::Symbol::from("idempotency-key"),
                mneme_core::Value::string("schema-99"),
            ),
            (
                mneme_core::Symbol::from("records"),
                mneme_core::Value::sequence(vec![newer.to_value()]),
            ),
        ]),
    );
    let error = mneme_api::decode(&document).expect_err("schema 99 is refused");
    assert_eq!(error.code.as_str(), "unsupported-version");
    assert!(error.diagnostics.iter().any(|diagnostic| {
        diagnostic
            .to_string()
            .contains("unsupported-schema-version")
    }));
    let adapter = mneme_api::error_document_for(&error);
    let diagnostics = field(field(&adapter, "error"), "diagnostics")
        .as_sequence()
        .expect("diagnostics");
    assert_eq!(diagnostics.len(), error.diagnostics.len());

    // A transport tag the codec does not implement, inside a valid transport
    // document: the envelope itself must not be the reason for the refusal.
    let tag_error = mneme_api::decode(
        "{\"format\":\"mneme.preserves-tagged-json\",\"version\":1,\"value\":{\"t\":\"float32\"}}",
    )
    .expect_err("unsupported tag is refused");
    assert_eq!(tag_error.code.as_str(), "unsupported-version");
    assert!(!tag_error.diagnostics.is_empty());
    assert_eq!(harness.revision(), before);
}

#[test]
fn structured_recall_returns_rows_with_coverage() {
    let harness = Harness::new();
    let service = harness.cedar_service();
    let seeded = harness.seed(&cedar(), &CEDAR_IDS, CEDAR_TEXT, "SQLite");
    let accepted = service.execute(&accept_command(seeded.revision, "accept", seeded.assertion));
    assert!(accepted.ok);
    let accepted_revision = committed_revision(&accepted);
    let mut command = recall_command(
        &cedar(),
        Some(accepted_revision),
        "SQLite",
        RecallOptions::CURRENT,
    );
    if let mneme_api::ApiCommand::Recall {
        modes, structured, ..
    } = &mut command
    {
        modes.clear();
        *structured = Some(Box::new(mneme_api::StructuredQuery {
            bundle: Some(claim_bundle()),
            bundle_path: None,
            relation: "claim".to_owned(),
            constants: Vec::new(),
            limit: 10,
            limits: mneme_datalog::Limits {
                max_work: 100_000,
                max_time_ms: 2_000,
                max_result_rows: 1_000,
                max_supports_per_fact: 8,
                max_recursion_depth: 32,
            },
            incomplete_extents: std::collections::BTreeSet::new(),
        }));
    }
    let response = service.execute(&command);
    assert!(response.ok, "{:?}", response.value);
    let modes = sequence(data(&response), "modes");
    let structured = modes
        .iter()
        .find(|mode| symbol_text(field(mode, "mode")) == "structured")
        .expect("structured report");
    assert_eq!(symbol_text(field(structured, "status")), "used");
    assert!(boolean(field(field(structured, "coverage"), "complete")));
    assert!(
        field(structured, "relation-exhaustive")
            .as_boolean()
            .is_some()
    );
    assert!(!boolean(field(data(&response), "absence-established")));
    assert!(
        sequence(data(&response), "candidates")
            .iter()
            .any(|candidate| symbol_text(field(candidate, "content-kind")) == "structured-row")
    );
}

fn claim_bundle() -> mneme_datalog::RuleBundle {
    fn atom(predicate: &str, terms: Vec<mneme_datalog::Term>) -> mneme_datalog::Atom {
        mneme_datalog::Atom::new(predicate, terms)
    }
    mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "api-test".to_owned(),
        version: "1".to_owned(),
        schema_version: mneme_api::RULE_BUNDLE_SCHEMA_VERSION,
        base_predicates: std::collections::BTreeMap::from([("assertion".to_owned(), 4)]),
        complete_predicates: std::collections::BTreeSet::from(["assertion".to_owned()]),
        rules: vec![mneme_datalog::Rule::new(
            "claim",
            atom(
                "claim",
                vec![
                    mneme_datalog::Term::var("subject"),
                    mneme_datalog::Term::var("value"),
                ],
            ),
            vec![mneme_datalog::Literal::Positive(atom(
                "assertion",
                vec![
                    mneme_datalog::Term::var("subject"),
                    mneme_datalog::Term::constant(mneme_core::Value::symbol("storage-engine")),
                    mneme_datalog::Term::var("value"),
                    mneme_datalog::Term::var("id"),
                ],
            ))],
        )],
    })
}

#[test]
fn recall_bounds_and_timeouts_are_reported_exactly() {
    let harness = Harness::new();
    let service = harness.cedar_service();
    let seeded = harness.seed(&cedar(), &CEDAR_IDS, CEDAR_TEXT, "SQLite");
    let accepted = service.execute(&accept_command(seeded.revision, "accept", seeded.assertion));
    assert!(accepted.ok);
    let accepted_revision = committed_revision(&accepted);
    let bounded = service.execute(&recall_command(
        &cedar(),
        Some(accepted_revision),
        "SQLite",
        RecallOptions {
            max_items: 1,
            ..RecallOptions::CURRENT
        },
    ));
    assert!(bounded.ok);
    assert_eq!(symbol_text(field(&bounded.value, "status")), "ok");
    assert_eq!(
        symbol_text(field(data(&bounded), "execution-status")),
        "complete"
    );
    assert!(boolean(field(data(&bounded), "truncated")));
    assert!(!sequence(data(&bounded), "omissions").is_empty());
    assert_eq!(sequence(data(&bounded), "candidates").len(), 1);

    let mut timed_command = recall_command(
        &cedar(),
        Some(accepted_revision),
        "SQLite",
        RecallOptions::CURRENT,
    );
    if let mneme_api::ApiCommand::Recall { max_time_ms, .. } = &mut timed_command {
        *max_time_ms = 0;
    }
    let timed = service.execute(&timed_command);
    assert!(!timed.ok);
    assert_eq!(symbol_text(field(&timed.value, "status")), "timeout");
    assert_eq!(
        symbol_text(field(data(&timed), "execution-status")),
        "timeout"
    );
    assert_eq!(
        field(data(&timed), "absence-established"),
        &mneme_core::Value::Boolean(false)
    );
    assert!(
        field(data(&timed), "candidates")
            .as_sequence()
            .is_none_or(<[mneme_core::Value]>::is_empty)
    );
}

#[test]
fn scope_is_authorized_before_content_or_receipt_lookup() {
    let harness = Harness::new();
    let service = harness.cedar_service();
    let seeded = harness.seed(&cedar(), &CEDAR_IDS, CEDAR_TEXT, "SQLite");
    let before = harness.revision();
    let crossed = [
        mneme_api::ApiCommand::Recall {
            request_id: "recall".to_owned(),
            scope: birch(),
            revision: Some(before),
            query: "tangerine".to_owned(),
            at: mneme_core::Timestamp::from_nanos(2_000),
            temporal: mneme_recall::TemporalMode::Current,
            modes: std::collections::BTreeSet::from([mneme_recall::Mode::Lexical]),
            structured: None,
            allow_stale: false,
            allow_fallback: true,
            allow_partial: true,
            include_disputed: false,
            include_hypothetical: false,
            max_items: 8,
            max_context_bytes: 4096,
            max_quote_bytes: 1024,
            max_time_ms: 500,
        },
        mneme_api::ApiCommand::Explain {
            request_id: "explain".to_owned(),
            scope: birch(),
            assertion: seeded.assertion,
            max_nodes: 64,
            max_excerpt_bytes: 4096,
        },
        mneme_api::ApiCommand::Resume {
            request_id: "resume".to_owned(),
            scope: birch(),
            checkpoint: rid(0xc9),
        },
        mneme_api::ApiCommand::Forget {
            request_id: "forget".to_owned(),
            scope: birch(),
            base: before,
            key: "cross".to_owned(),
            selector: mneme_retention::Selector::Source(seeded.source),
            effective: None,
        },
        mneme_api::ApiCommand::ProposalInspect {
            request_id: "inspect".to_owned(),
            scope: birch(),
            assertion: seeded.assertion,
        },
    ];
    for command in &crossed {
        let response = service.execute(command);
        assert!(!response.ok, "{:?}", response.value);
        assert_eq!(error_of(&response).0, "denied");
        assert_no_context(&response);
    }
    assert_eq!(harness.revision(), before);
}

#[test]
fn refusal_documents_carry_a_field_address() {
    let harness = Harness::new();
    let service = harness.cedar_service();
    let seeded = harness.seed(&cedar(), &CEDAR_IDS, CEDAR_TEXT, "SQLite");
    let before = harness.revision();
    let mut evidence = mneme_memory::build_evidence(
        rid(0x0c),
        rev(0x1c),
        &cedar(),
        mneme_memory::EvidenceOptions {
            assertion: seeded.assertion,
            source: seeded.source,
            source_revision: rev(CEDAR_IDS.source_revision),
            span: Some(mneme_core::SourceSpan::new(0, 5).expect("span")),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry: &[],
        },
    );
    // An unpinned citation: the memory layer refuses it as a policy violation,
    // with no record index, so the address cannot be finer than the payload.
    evidence.payload.insert(
        mneme_core::Symbol::from("source"),
        mneme_core::Reference::local(seeded.source, mneme_core::RecordKind::SourceRevision)
            .to_value(),
    );
    let response = service.execute(&record_command(
        &cedar(),
        before,
        "unpinned-evidence",
        vec![envelope(evidence)],
        Vec::new(),
    ));
    assert!(!response.ok, "{:?}", response.value);
    assert_eq!(error_of(&response).0, "invalid-input");
    assert!(
        error_of(&response)
            .1
            .contains("pin the exact source revision")
    );
    let diagnostics = field(field(&response.value, "error"), "diagnostics")
        .as_sequence()
        .expect("diagnostics");
    assert!(!diagnostics.is_empty());
    for diagnostic in diagnostics {
        assert!(field(diagnostic, "code").as_symbol().is_some());
        assert!(field(diagnostic, "path").as_string().is_some());
        assert!(field(diagnostic, "message").as_string().is_some());
    }
    assert_eq!(text(field(&diagnostics[0], "path")), "$.payload");
    assert!(text(field(&diagnostics[0], "message")).contains("pin the exact source revision"));
    assert_eq!(harness.revision(), before);

    // A malformed member is refused at its own address, not at the root.
    let unknown_member = mneme_api::decode(&command_document(
        "recall",
        recall_payload(vec![("max_items", mneme_core::Value::integer(1))]),
    ))
    .expect_err("unknown member is refused");
    let adapter = mneme_api::error_document_for(&unknown_member);
    let entry = field(field(&adapter, "error"), "diagnostics")
        .as_sequence()
        .expect("diagnostics")
        .first()
        .expect("one diagnostic")
        .clone();
    assert!(text(field(&entry, "path")).contains("max_items"));
    assert!(field(&entry, "code").as_symbol().is_some());
}

#[test]
fn a_shared_record_cache_serves_the_same_documents() {
    let harness = Harness::new();
    let seeded = harness.seed(&cedar(), &CEDAR_IDS, CEDAR_TEXT, "SQLite");
    let shared = mneme_store::SharedRecordCache::new();
    let plain = harness.cedar_service();
    let cached = harness.cedar_service().with_record_cache(shared.clone());

    // Record: one commit, replayed for the second service.
    let record = record_command(
        &cedar(),
        seeded.revision,
        "cache-record",
        vec![envelope(entity_draft(rid(0x31), rev(0x41), &cedar()))],
        Vec::new(),
    );
    let plain_record = plain.execute(&record);
    assert!(plain_record.ok, "{:?}", plain_record.value);
    let cached_record = cached.execute(&record);
    assert!(cached_record.ok, "{:?}", cached_record.value);
    assert_eq!(plain_record.value, cached_record.value);
    let recorded_revision = committed_revision(&plain_record);

    // Accept: one commit from the recorded revision, replayed likewise.
    let accept = accept_command(recorded_revision, "cache-accept", seeded.assertion);
    let plain_accept = plain.execute(&accept);
    assert!(plain_accept.ok, "{:?}", plain_accept.value);
    let cached_accept = cached.execute(&accept);
    assert!(cached_accept.ok, "{:?}", cached_accept.value);
    assert_eq!(plain_accept.value, cached_accept.value);
    let accepted_revision = committed_revision(&plain_accept);

    // Recall: the whole document, budget included, is a function of the
    // workspace state and the command, so the cache cannot change it.
    let plain_recall = plain.execute(&recall_command(
        &cedar(),
        Some(accepted_revision),
        "SQLite",
        RecallOptions::CURRENT,
    ));
    assert!(plain_recall.ok, "{:?}", plain_recall.value);
    let cached_recall = cached.execute(&recall_command(
        &cedar(),
        Some(accepted_revision),
        "SQLite",
        RecallOptions::CURRENT,
    ));
    assert!(cached_recall.ok, "{:?}", cached_recall.value);
    assert_eq!(plain_recall.value, cached_recall.value);

    // Explain: one document, whatever cache served it.
    let explain = explain_command(seeded.assertion, 4096);
    let plain_explain = plain.execute(&explain);
    assert!(plain_explain.ok, "{:?}", plain_explain.value);
    let cached_explain = cached.execute(&explain);
    assert!(cached_explain.ok, "{:?}", cached_explain.value);
    assert_eq!(plain_explain.value, cached_explain.value);

    // Two services on one cache see each other's commits: the reader resolves
    // what the writer committed and reads the writer's revision as the head.
    let writer = harness.cedar_service().with_record_cache(shared.clone());
    let reader = harness.cedar_service().with_record_cache(shared);
    let written = writer.execute(&record_command(
        &cedar(),
        accepted_revision,
        "cache-written",
        vec![envelope(entity_draft(rid(0x32), rev(0x42), &cedar()))],
        Vec::new(),
    ));
    assert!(written.ok, "{:?}", written.value);
    let written_revision = committed_revision(&written);
    let query = recall_command(&cedar(), None, "SQLite", RecallOptions::CURRENT);
    let read = reader.execute(&query);
    assert!(read.ok, "{:?}", read.value);
    assert_eq!(context_revision(&read), written_revision);
    let followed = reader.execute(&record_command(
        &cedar(),
        written_revision,
        "cache-follows",
        vec![envelope(entity_draft(rid(0x33), rev(0x43), &cedar()))],
        Vec::new(),
    ));
    assert!(followed.ok, "{:?}", followed.value);
}

#[test]
fn recall_reports_budget_use_and_the_evaluation_instant() {
    let harness = Harness::new();
    let service = harness.cedar_service();
    let seeded = harness.seed(&cedar(), &CEDAR_IDS, CEDAR_TEXT, "SQLite");
    let response = service.execute(&recall_command(
        &cedar(),
        Some(seeded.revision),
        "SQLite",
        RecallOptions {
            max_items: 3,
            ..RecallOptions::CURRENT
        },
    ));
    assert!(response.ok, "{:?}", response.value);

    // The context names the instant the request was evaluated at.
    let context = field(data(&response), "context");
    let request_at = mneme_core::Timestamp::from_nanos(2_000);
    assert_eq!(text(field(context, "at")), request_at.to_rfc3339());

    // One budget entry per limit the request carried, and no use above a limit.
    let budget = field(data(&response), "budget");
    assert_budget_limit(budget, "items", 3);
    assert_budget_limit(budget, "context-bytes", 4096);
    assert_budget_limit(budget, "quote-bytes", 1024);
    // The work limit is the recall engine's own bound, not a request field.
    let work = field(budget, "work");
    assert!(integer(field(work, "used")) <= integer(field(work, "allowed")));
    // The time limit is reported, but no measured duration is: a complete
    // answer did not exhaust it.
    let time = field(budget, "time-ms");
    assert_eq!(integer(field(time, "allowed")), 500);
    assert!(!boolean(field(time, "exhausted")));
    assert!(optional(time, "used").is_none());
    assert_eq!(time.as_dictionary().expect("dictionary").len(), 2);

    // A spent time budget is the timeout status, and the entry says so.
    let mut spent = recall_command(
        &cedar(),
        Some(seeded.revision),
        "SQLite",
        RecallOptions::CURRENT,
    );
    if let mneme_api::ApiCommand::Recall { max_time_ms, .. } = &mut spent {
        *max_time_ms = 0;
    }
    let timed = service.execute(&spent);
    assert!(!timed.ok);
    assert_eq!(
        symbol_text(field(data(&timed), "execution-status")),
        "timeout"
    );
    let time = field(field(data(&timed), "budget"), "time-ms");
    assert_eq!(integer(field(time, "allowed")), 0);
    assert!(boolean(field(time, "exhausted")));
}

/// One budget entry, allowed exactly `allowed`, used no more than that.
fn assert_budget_limit(budget: &mneme_core::Value, limit: &str, allowed: i64) {
    let entry = field(budget, limit);
    assert_eq!(integer(field(entry, "allowed")), allowed, "{limit}");
    let used = integer(field(entry, "used"));
    assert!(used <= allowed, "{limit} use {used} exceeds {allowed}");
}

#[test]
fn unpinned_recall_reports_the_revision_it_served_across_commits() {
    let harness = Harness::new();
    let service = harness.cedar_service();
    let seeded = harness.seed(&cedar(), &CEDAR_IDS, CEDAR_TEXT, "SQLite");
    let query = recall_command(&cedar(), None, "SQLite", RecallOptions::CURRENT);
    let first = service.execute(&query);
    assert!(first.ok, "{:?}", first.value);
    assert_eq!(context_revision(&first), seeded.revision);
    assert_eq!(
        revision_from(field(field(data(&first), "context"), "served-revision")),
        seeded.revision
    );

    // Another handle commits between the two calls.
    let committed = harness.operator_commit(
        &cedar(),
        "between-recalls",
        vec![entity_draft(rid(0x34), rev(0x44), &cedar())],
        Vec::new(),
    );
    assert_ne!(committed, seeded.revision);

    let second = service.execute(&query);
    assert!(second.ok, "{:?}", second.value);
    assert_eq!(context_revision(&second), committed);
    let context = field(data(&second), "context");
    assert_eq!(revision_from(field(context, "served-revision")), committed);
    assert!(!boolean(field(context, "stale")));
    assert!(field(context, "at").as_string().is_some());
}
