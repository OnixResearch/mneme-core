//! Shared execution of validated agent-memory commands.

use mneme_core::{
    Lifecycle, RecordId, RecordKind, Reference, RevisionId, ScopeId, SourceSpan, Value,
    WorkspaceRevisionId,
};
use mneme_memory::{
    AssertionView, DecisionKind, EpisodeView, Explanation, Memory, MemoryBatch, Policy, Stance,
    build_assertion_revision, build_decision,
};
use mneme_recall::{RecallCandidate, RecallEvidence, RecallMode, RecallRequest, RecallService};
use mneme_retention::{
    OperationKind, Retention, RetentionPolicy, RetentionRequest, RetentionResult,
};
use mneme_store::{CommitOutcome, PublicationOutcome, Workspace, WorkspaceConfig};

use crate::command::{ApiCommand, ReviseAction, record_draft};
use crate::error::{ApiError, ApiErrorCode, ApiResult};

/// A transport-neutral response. `value` is a versioned tagged JSON document.
#[derive(Clone, Debug)]
pub struct ApiResponse {
    pub value: Value,
    pub ok: bool,
}

/// One local API service bound to an authorized principal and scopes.
#[derive(Clone, Debug)]
pub struct ApiService {
    session: crate::command::LocalSession,
}

impl ApiService {
    pub fn new(session: crate::command::LocalSession) -> Self {
        ApiService { session }
    }

    pub fn session(&self) -> &crate::command::LocalSession {
        &self.session
    }

    /// Execute one command and always return a structured transport document.
    pub fn execute(&self, command: &ApiCommand) -> ApiResponse {
        if let Some(scope) = command.scope()
            && let Err(error) = self.session.authorize(scope)
        {
            return response_for_error(command, error, None);
        }
        match self.dispatch(command) {
            Ok((value, context)) => ApiResponse {
                value: response_envelope(command, "ok", context.as_ref(), value, None),
                ok: true,
            },
            Err(error) => response_for_error(command, error, None),
        }
    }

    fn dispatch(&self, command: &ApiCommand) -> ApiResult<(Value, Option<Context>)> {
        match command {
            ApiCommand::Capabilities { .. } => Ok((capabilities_value(), None)),
            ApiCommand::Record {
                scope,
                base,
                key,
                records,
                sources,
                ..
            } => {
                for record in records {
                    if &record.scope != scope {
                        return Err(ApiError::invalid(
                            "record scope does not match command scope",
                        ));
                    }
                }
                let mut workspace = self.open()?;
                let batch = MemoryBatch {
                    actor: self.session.principal.clone(),
                    scope: scope.clone(),
                    idempotency_key: key.clone(),
                    records: records
                        .iter()
                        .cloned()
                        .map(record_draft)
                        .collect::<Vec<_>>(),
                    source_blobs: sources.clone(),
                    publications: Vec::new(),
                };
                let outcome = Memory::new(&mut workspace)
                    .commit_at_base(batch, *base)
                    .map_err(ApiError::from_memory)?;
                Ok((commit_value(&outcome), Some(self.context(scope, &outcome))))
            }
            ApiCommand::Accept {
                scope,
                base,
                key,
                assertion,
                decision,
                decision_revision,
                accepted_revision,
                policy,
                rationale,
                ..
            } => {
                let mut workspace = self.open()?;
                let current = current_assertion(&workspace, *assertion, scope)?;
                let decision_draft = build_decision(
                    *decision,
                    *decision_revision,
                    scope,
                    DecisionKind::Acceptance,
                    *assertion,
                    &self.session.principal,
                    policy,
                    *base,
                    "accepted",
                    rationale,
                    &[],
                    &[],
                );
                let accepted = build_assertion_revision(
                    &current,
                    *accepted_revision,
                    Lifecycle::Accepted,
                    Reference::local(*decision, RecordKind::Decision),
                    None,
                );
                let batch = MemoryBatch {
                    actor: self.session.principal.clone(),
                    scope: scope.clone(),
                    idempotency_key: key.clone(),
                    records: vec![decision_draft, accepted],
                    source_blobs: Vec::new(),
                    publications: Vec::new(),
                };
                let outcome = Memory::new(&mut workspace)
                    .commit_at_base(batch, *base)
                    .map_err(ApiError::from_memory)?;
                Ok((commit_value(&outcome), Some(self.context(scope, &outcome))))
            }
            ApiCommand::Recall {
                scope,
                revision,
                query,
                at,
                temporal,
                modes,
                allow_stale,
                allow_fallback,
                allow_partial,
                include_disputed,
                include_hypothetical,
                max_items,
                max_context_bytes,
                max_quote_bytes,
                max_time_ms,
                ..
            } => {
                let mut workspace = self.open()?;
                let revision =
                    revision.unwrap_or(workspace.current_revision().map_err(ApiError::from_store)?);
                let request = RecallRequest {
                    actor: self.session.principal.clone(),
                    scope: scope.clone(),
                    revision,
                    query: query.clone(),
                    at: *at,
                    temporal: *temporal,
                    modes: modes.clone(),
                    structured: None,
                    allow_stale: *allow_stale,
                    allow_fallback: *allow_fallback,
                    allow_partial: *allow_partial,
                    include_disputed: *include_disputed,
                    include_hypothetical: *include_hypothetical,
                    max_items: *max_items,
                    max_context_bytes: *max_context_bytes,
                    max_quote_bytes: *max_quote_bytes,
                    max_time_ms: *max_time_ms,
                    cancellation: None,
                };
                let response = RecallService::new(&mut workspace)
                    .recall(request)
                    .map_err(ApiError::from_recall)?;
                let context = Context {
                    revision: response.context.served_revision,
                    scope: scope.clone(),
                    generation: response.context.eligibility_generation,
                };
                Ok((recall_value(&response), Some(context)))
            }
            ApiCommand::Explain {
                scope,
                assertion,
                max_nodes,
                max_excerpt_bytes,
                ..
            } => {
                let mut workspace = self.open()?;
                for attempt in 0..2 {
                    let generation = workspace
                        .eligibility_generation()
                        .map_err(ApiError::from_store)?;
                    let explanation = {
                        let memory = Memory::new(&mut workspace);
                        let view = memory.view().map_err(ApiError::from_memory)?;
                        let record = view.record(*assertion).map_err(ApiError::from_memory)?;
                        if &record.scope != scope {
                            return Err(ApiError::denied());
                        }
                        memory
                            .explain(
                                *assertion,
                                Policy {
                                    max_explanation_nodes: *max_nodes,
                                    max_excerpt_bytes: *max_excerpt_bytes,
                                },
                            )
                            .map_err(ApiError::from_memory)?
                    };
                    let after = workspace
                        .eligibility_generation()
                        .map_err(ApiError::from_store)?;
                    if after == generation {
                        let revision = explanation.workspace_revision;
                        return Ok((
                            explain_value(&explanation),
                            Some(Context {
                                revision,
                                scope: scope.clone(),
                                generation,
                            }),
                        ));
                    }
                    if attempt == 1 {
                        return Err(ApiError::new(
                            ApiErrorCode::Conflict,
                            "eligibility barrier advanced during explanation",
                        ));
                    }
                }
                Err(ApiError::new(
                    ApiErrorCode::Failed,
                    "explanation retry exhausted",
                ))
            }
            ApiCommand::Revise {
                scope,
                base,
                key,
                assertion,
                action,
                rationale,
                decision,
                decision_revision,
                revised_revision,
                superseded_by,
                ..
            } => {
                let mut workspace = self.open()?;
                let current = current_assertion(&workspace, *assertion, scope)?;
                let (kind, lifecycle, outcome) = match action {
                    ReviseAction::Supersede => (
                        DecisionKind::Supersession,
                        Lifecycle::Superseded,
                        "superseded",
                    ),
                    ReviseAction::Dispute => (
                        DecisionKind::ConflictResolution,
                        Lifecycle::Disputed,
                        "disputed",
                    ),
                    ReviseAction::Retract => {
                        (DecisionKind::Retraction, Lifecycle::Retracted, "retracted")
                    }
                };
                let decision_draft = build_decision(
                    *decision,
                    *decision_revision,
                    scope,
                    kind,
                    *assertion,
                    &self.session.principal,
                    "agent-api/v1",
                    *base,
                    outcome,
                    rationale,
                    &[],
                    &[],
                );
                let superseded =
                    superseded_by.map(|target| Reference::local(target, RecordKind::Assertion));
                let revised = build_assertion_revision(
                    &current,
                    *revised_revision,
                    lifecycle,
                    Reference::local(*decision, RecordKind::Decision),
                    superseded,
                );
                let batch = MemoryBatch {
                    actor: self.session.principal.clone(),
                    scope: scope.clone(),
                    idempotency_key: key.clone(),
                    records: vec![decision_draft, revised],
                    source_blobs: Vec::new(),
                    publications: Vec::new(),
                };
                let outcome = Memory::new(&mut workspace)
                    .commit_at_base(batch, *base)
                    .map_err(ApiError::from_memory)?;
                Ok((commit_value(&outcome), Some(self.context(scope, &outcome))))
            }
            ApiCommand::Resume {
                scope, checkpoint, ..
            } => {
                let mut workspace = self.open()?;
                let generation = workspace
                    .eligibility_generation()
                    .map_err(ApiError::from_store)?;
                let value = resume_value(&mut workspace, *checkpoint, scope)?;
                let after = workspace
                    .eligibility_generation()
                    .map_err(ApiError::from_store)?;
                if after != generation {
                    return Err(ApiError::new(
                        ApiErrorCode::Conflict,
                        "eligibility barrier advanced during resume",
                    ));
                }
                let revision = workspace.current_revision().map_err(ApiError::from_store)?;
                Ok((
                    value,
                    Some(Context {
                        revision,
                        scope: scope.clone(),
                        generation,
                    }),
                ))
            }
            ApiCommand::Forget {
                scope,
                base,
                key,
                selector,
                effective,
                ..
            } => {
                let mut workspace = self.open()?;
                let request = RetentionRequest {
                    actor: self.session.principal.clone(),
                    scope: scope.clone(),
                    base_revision: *base,
                    idempotency_key: key.clone(),
                    operation: OperationKind::Forget,
                    selector: selector.clone(),
                    effective: *effective,
                    policy: RetentionPolicy::default(),
                };
                let result = Retention::new(&mut workspace)
                    .execute(request)
                    .map_err(ApiError::from_retention)?;
                let generation = result.generation;
                let revision = workspace.current_revision().map_err(ApiError::from_store)?;
                Ok((
                    forget_value(&result),
                    Some(Context {
                        revision,
                        scope: scope.clone(),
                        generation,
                    }),
                ))
            }
            ApiCommand::ProposalInspect {
                scope, assertion, ..
            } => {
                let mut workspace = self.open()?;
                let memory = Memory::new(&mut workspace);
                let view = memory.view().map_err(ApiError::from_memory)?;
                let record = view.record(*assertion).map_err(ApiError::from_memory)?;
                if &record.scope != scope {
                    return Err(ApiError::denied());
                }
                let assertion = view.assertion(*assertion).map_err(ApiError::from_memory)?;
                let generation = view.snapshot().eligibility_generation;
                let revision = view.revision();
                Ok((
                    assertion_value(&assertion),
                    Some(Context {
                        revision,
                        scope: scope.clone(),
                        generation,
                    }),
                ))
            }
        }
    }

    fn open(&self) -> ApiResult<Workspace> {
        Workspace::open(&self.session.workspace_root, WorkspaceConfig::default())
            .map_err(ApiError::from_store)
    }

    fn context(&self, scope: &ScopeId, outcome: &CommitOutcome) -> Context {
        Context {
            revision: outcome.revision,
            scope: scope.clone(),
            generation: outcome.eligibility_generation,
        }
    }
}

#[derive(Clone, Debug)]
struct Context {
    revision: WorkspaceRevisionId,
    scope: ScopeId,
    generation: u64,
}

fn current_assertion(
    workspace: &Workspace,
    assertion: RecordId,
    scope: &ScopeId,
) -> ApiResult<mneme_core::RecordEnvelope> {
    let snapshot = workspace.snapshot().map_err(ApiError::from_store)?;
    let record = snapshot
        .records
        .iter()
        .find(|record| record.record_id == assertion && record.kind == RecordKind::Assertion)
        .cloned()
        .ok_or_else(|| ApiError::new(ApiErrorCode::Unavailable, "assertion is unavailable"))?;
    if &record.scope != scope {
        return Err(ApiError::denied());
    }
    Ok(record)
}

fn response_for_error(
    command: &ApiCommand,
    error: ApiError,
    context: Option<&Context>,
) -> ApiResponse {
    ApiResponse {
        value: response_envelope(
            command,
            error.code.as_str(),
            context,
            none_value(),
            Some(&error),
        ),
        ok: false,
    }
}

fn response_envelope(
    command: &ApiCommand,
    status: &str,
    context: Option<&Context>,
    data: Value,
    error: Option<&ApiError>,
) -> Value {
    let mut entries = vec![
        (
            Value::symbol("format"),
            Value::string(crate::command::RESULT_FORMAT),
        ),
        (
            Value::symbol("version"),
            Value::integer(crate::command::RESULT_VERSION),
        ),
        (
            Value::symbol("request-id"),
            Value::string(command.request_id().to_owned()),
        ),
        (
            Value::symbol("operation"),
            Value::symbol(command.operation()),
        ),
        (Value::symbol("status"), Value::symbol(status)),
        (Value::symbol("data"), data),
    ];
    if let Some(context) = context {
        entries.push((
            Value::symbol("context"),
            Value::symbol_dictionary([
                (
                    mneme_core::Symbol::from("workspace-revision"),
                    context.revision.to_value(),
                ),
                (mneme_core::Symbol::from("scope"), context.scope.to_value()),
                (
                    mneme_core::Symbol::from("eligibility-generation"),
                    Value::integer(context.generation),
                ),
                (
                    mneme_core::Symbol::from("schema-version"),
                    Value::integer(1),
                ),
            ]),
        ));
    }
    if let Some(error) = error {
        entries.push((
            Value::symbol("error"),
            Value::symbol_dictionary([
                (
                    mneme_core::Symbol::from("code"),
                    Value::symbol(error.code.as_str()),
                ),
                (
                    mneme_core::Symbol::from("message"),
                    Value::string(error.message.clone()),
                ),
                (
                    mneme_core::Symbol::from("diagnostics"),
                    Value::sequence(
                        error
                            .diagnostics
                            .iter()
                            .map(|diagnostic| Value::string(diagnostic.to_string()))
                            .collect(),
                    ),
                ),
            ]),
        ));
    }
    Value::symbol_dictionary(entries.into_iter().map(|(key, value)| {
        (
            mneme_core::Symbol::from(
                key.as_symbol()
                    .map(|symbol| symbol.as_str())
                    .unwrap_or_default(),
            ),
            value,
        )
    }))
}

fn commit_value(outcome: &CommitOutcome) -> Value {
    Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("revision"),
            outcome.revision.to_value(),
        ),
        (
            mneme_core::Symbol::from("sequence"),
            Value::integer(outcome.sequence),
        ),
        (
            mneme_core::Symbol::from("generation"),
            Value::integer(outcome.eligibility_generation),
        ),
        (
            mneme_core::Symbol::from("manifest-digest"),
            outcome.manifest_digest.to_value(),
        ),
        (
            mneme_core::Symbol::from("publications"),
            Value::sequence(outcome.publications.iter().map(publication_value).collect()),
        ),
    ])
}

fn publication_value(publication: &PublicationOutcome) -> Value {
    Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("intent-id"),
            Value::string(publication.intent_id.clone()),
        ),
        (
            mneme_core::Symbol::from("path"),
            Value::string(publication.path.clone()),
        ),
        (
            mneme_core::Symbol::from("state"),
            Value::symbol(publication.state.as_str()),
        ),
        (
            mneme_core::Symbol::from("detail"),
            publication
                .detail
                .as_ref()
                .map(|detail| Value::string(detail.clone()))
                .unwrap_or_else(|| Value::string("")),
        ),
    ])
}

fn assertion_value(assertion: &AssertionView) -> Value {
    Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("record-id"),
            assertion.record.record_id.to_value(),
        ),
        (
            mneme_core::Symbol::from("subject"),
            assertion.subject.to_value(),
        ),
        (
            mneme_core::Symbol::from("predicate"),
            Value::string(assertion.predicate.clone()),
        ),
        (mneme_core::Symbol::from("value"), assertion.value.clone()),
        (
            mneme_core::Symbol::from("stance"),
            Value::symbol(match assertion.stance {
                Stance::Affirm => "affirm",
                Stance::Deny => "deny",
                Stance::Hypothesis => "hypothesis",
            }),
        ),
        (
            mneme_core::Symbol::from("lifecycle"),
            Value::symbol(assertion.lifecycle.symbol()),
        ),
        (
            mneme_core::Symbol::from("origin"),
            Value::symbol(assertion.origin.symbol()),
        ),
        (
            mneme_core::Symbol::from("asserted-by"),
            Value::string(assertion.asserted_by.clone()),
        ),
        (
            mneme_core::Symbol::from("valid-time"),
            assertion.valid_time.to_value(),
        ),
        (
            mneme_core::Symbol::from("recorded-time"),
            assertion.record.recorded.to_value(),
        ),
        (
            mneme_core::Symbol::from("evidence"),
            Value::sequence(
                assertion
                    .evidence
                    .iter()
                    .map(|evidence| evidence.to_value())
                    .collect(),
            ),
        ),
        (
            mneme_core::Symbol::from("superseded-by"),
            assertion
                .superseded_by
                .map(RecordId::to_value)
                .unwrap_or_else(none_value),
        ),
    ])
}

fn recall_value(response: &mneme_recall::RecallResponse) -> Value {
    let context = Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("scope"),
            response.context.scope.to_value(),
        ),
        (
            mneme_core::Symbol::from("requested-revision"),
            response.context.requested_revision.to_value(),
        ),
        (
            mneme_core::Symbol::from("served-revision"),
            response.context.served_revision.to_value(),
        ),
        (
            mneme_core::Symbol::from("eligibility-generation"),
            Value::integer(response.context.eligibility_generation),
        ),
        (
            mneme_core::Symbol::from("temporal"),
            Value::symbol(response.context.temporal.name()),
        ),
        (
            mneme_core::Symbol::from("fusion-policy"),
            Value::string(response.context.fusion_policy.clone()),
        ),
        (
            mneme_core::Symbol::from("index-versions"),
            Value::symbol_dictionary(response.context.index_versions.iter().map(
                |(mode, version)| {
                    (
                        mneme_core::Symbol::from(mode.as_str()),
                        Value::string(version.clone()),
                    )
                },
            )),
        ),
    ]);
    Value::symbol_dictionary([
        (mneme_core::Symbol::from("context"), context),
        (
            mneme_core::Symbol::from("execution-status"),
            Value::symbol(response.status.name()),
        ),
        (
            mneme_core::Symbol::from("modes"),
            Value::sequence(response.modes.iter().map(mode_value).collect()),
        ),
        (
            mneme_core::Symbol::from("candidates"),
            Value::sequence(response.candidates.iter().map(candidate_value).collect()),
        ),
        (
            mneme_core::Symbol::from("exhaustive"),
            Value::Boolean(response.exhaustive),
        ),
        (
            mneme_core::Symbol::from("absence-established"),
            Value::Boolean(response.absence_established),
        ),
        (
            mneme_core::Symbol::from("truncated"),
            Value::Boolean(response.truncated),
        ),
        (
            mneme_core::Symbol::from("omissions"),
            Value::sequence(
                response
                    .omissions
                    .iter()
                    .map(|omission| {
                        Value::symbol_dictionary([
                            (
                                mneme_core::Symbol::from("candidate"),
                                Value::string(omission.candidate.clone()),
                            ),
                            (
                                mneme_core::Symbol::from("reason"),
                                Value::string(omission.reason.clone()),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            mneme_core::Symbol::from("reason"),
            response
                .reason
                .as_ref()
                .map(|reason| Value::string(reason.clone()))
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("boundary"),
            Value::symbol_dictionary([
                (
                    mneme_core::Symbol::from("kind"),
                    Value::string(response.boundary.kind.clone()),
                ),
                (
                    mneme_core::Symbol::from("instructions-are-data"),
                    Value::Boolean(response.boundary.instructions_are_data),
                ),
                (
                    mneme_core::Symbol::from("may-change-scope"),
                    Value::Boolean(response.boundary.may_change_scope),
                ),
                (
                    mneme_core::Symbol::from("may-execute-code"),
                    Value::Boolean(response.boundary.may_execute_code),
                ),
                (
                    mneme_core::Symbol::from("may-register-rules"),
                    Value::Boolean(response.boundary.may_register_rules),
                ),
            ]),
        ),
    ])
}

fn mode_value(mode: &mneme_recall::ModeReport) -> Value {
    Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("mode"),
            Value::symbol(mode.mode.name()),
        ),
        (
            mneme_core::Symbol::from("status"),
            Value::symbol(mode.status.name()),
        ),
        (
            mneme_core::Symbol::from("revision"),
            mode.revision
                .map(|revision| revision.to_value())
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("coverage-complete"),
            Value::Boolean(mode.coverage.complete),
        ),
        (
            mneme_core::Symbol::from("documents-indexed"),
            Value::integer(mode.coverage.documents_indexed),
        ),
        (
            mneme_core::Symbol::from("documents-skipped"),
            Value::integer(mode.coverage.documents_skipped),
        ),
        (
            mneme_core::Symbol::from("candidates"),
            Value::integer(mode.candidates),
        ),
    ])
}

fn candidate_value(candidate: &RecallCandidate) -> Value {
    Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("id"),
            Value::string(candidate.id.clone()),
        ),
        (
            mneme_core::Symbol::from("content-kind"),
            Value::symbol(candidate.content_kind.name()),
        ),
        (
            mneme_core::Symbol::from("text"),
            Value::string(candidate.text.clone()),
        ),
        (
            mneme_core::Symbol::from("text-truncated"),
            Value::Boolean(candidate.text_truncated),
        ),
        (
            mneme_core::Symbol::from("quote"),
            Value::Boolean(candidate.quote),
        ),
        (
            mneme_core::Symbol::from("source"),
            candidate
                .source
                .map(RecordId::to_value)
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("source-revision"),
            candidate
                .source_revision
                .map(RevisionId::to_value)
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("span"),
            candidate
                .span
                .map(SourceSpan::to_value)
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("field-path"),
            Value::string(candidate.field_path.clone()),
        ),
        (
            mneme_core::Symbol::from("assertion"),
            candidate
                .assertion
                .map(RecordId::to_value)
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("episode"),
            candidate
                .episode
                .map(RecordId::to_value)
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("independent-support"),
            Value::Boolean(candidate.independent_support),
        ),
        (
            mneme_core::Symbol::from("origins"),
            Value::sequence(
                candidate
                    .origins
                    .iter()
                    .map(|mode| Value::symbol(mode.name()))
                    .collect(),
            ),
        ),
        (
            mneme_core::Symbol::from("score"),
            Value::double(candidate.score),
        ),
        (
            mneme_core::Symbol::from("evidence"),
            Value::sequence(
                candidate
                    .evidence
                    .iter()
                    .map(recall_evidence_value)
                    .collect(),
            ),
        ),
        (
            mneme_core::Symbol::from("derivations"),
            Value::sequence(candidate.derivations.iter().map(derivation_value).collect()),
        ),
        (
            mneme_core::Symbol::from("ancestry-roots"),
            Value::sequence(
                candidate
                    .ancestry_roots
                    .iter()
                    .map(|(record, revision)| {
                        Value::sequence(vec![record.to_value(), revision.to_value()])
                    })
                    .collect(),
            ),
        ),
    ])
}

fn recall_evidence_value(evidence: &RecallEvidence) -> Value {
    Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("evidence"),
            evidence.evidence.to_value(),
        ),
        (
            mneme_core::Symbol::from("source"),
            evidence.source.to_value(),
        ),
        (
            mneme_core::Symbol::from("source-revision"),
            evidence
                .source_revision
                .map(RevisionId::to_value)
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("availability"),
            Value::symbol(evidence.availability.name()),
        ),
        (
            mneme_core::Symbol::from("span"),
            evidence
                .span
                .map(SourceSpan::to_value)
                .unwrap_or_else(none_value),
        ),
    ])
}

fn derivation_value(derivation: &mneme_datalog::Derivation) -> Value {
    Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("rule-id"),
            Value::string(derivation.rule_id.clone()),
        ),
        (
            mneme_core::Symbol::from("rule-version"),
            Value::string(derivation.rule_version.clone()),
        ),
        (
            mneme_core::Symbol::from("revision"),
            derivation.revision.to_value(),
        ),
        (
            mneme_core::Symbol::from("scope"),
            derivation.scope.to_value(),
        ),
        (
            mneme_core::Symbol::from("truncated"),
            Value::Boolean(derivation.truncated),
        ),
        (
            mneme_core::Symbol::from("premises"),
            Value::sequence(
                derivation
                    .premises
                    .iter()
                    .map(|premise| {
                        Value::symbol_dictionary([
                            (
                                mneme_core::Symbol::from("predicate"),
                                Value::string(premise.predicate.clone()),
                            ),
                            (
                                mneme_core::Symbol::from("terms"),
                                Value::sequence(premise.terms.clone()),
                            ),
                            (
                                mneme_core::Symbol::from("canonical"),
                                premise
                                    .canonical
                                    .map(RecordId::to_value)
                                    .unwrap_or_else(none_value),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

fn explain_value(explanation: &Explanation) -> Value {
    Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("assertion"),
            assertion_value(&explanation.assertion),
        ),
        (
            mneme_core::Symbol::from("workspace-revision"),
            explanation.workspace_revision.to_value(),
        ),
        (
            mneme_core::Symbol::from("decisions"),
            Value::sequence(
                explanation
                    .decisions
                    .iter()
                    .map(|decision| {
                        Value::symbol_dictionary([
                            (
                                mneme_core::Symbol::from("record-id"),
                                decision.record.record_id.to_value(),
                            ),
                            (
                                mneme_core::Symbol::from("kind"),
                                Value::symbol(decision.decision_kind.name()),
                            ),
                            (
                                mneme_core::Symbol::from("outcome"),
                                Value::string(decision.outcome.clone()),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            mneme_core::Symbol::from("evidence"),
            Value::sequence(
                explanation
                    .evidence
                    .iter()
                    .map(|evidence| {
                        Value::symbol_dictionary([
                            (
                                mneme_core::Symbol::from("evidence"),
                                evidence.evidence.to_value(),
                            ),
                            (
                                mneme_core::Symbol::from("source"),
                                evidence.source.to_value(),
                            ),
                            (
                                mneme_core::Symbol::from("source-revision"),
                                evidence.source_revision.to_value(),
                            ),
                            (
                                mneme_core::Symbol::from("availability"),
                                Value::symbol(evidence.availability.name()),
                            ),
                            (
                                mneme_core::Symbol::from("excerpt"),
                                evidence
                                    .excerpt
                                    .as_ref()
                                    .map(|excerpt| Value::bytes(excerpt.bytes.clone()))
                                    .unwrap_or_else(none_value),
                            ),
                            (
                                mneme_core::Symbol::from("eligible"),
                                Value::Boolean(evidence.eligible),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            mneme_core::Symbol::from("corroboration"),
            Value::symbol_dictionary([
                (
                    mneme_core::Symbol::from("roots"),
                    Value::sequence(
                        explanation
                            .corroboration
                            .roots
                            .iter()
                            .map(|(record, revision)| {
                                Value::sequence(vec![record.to_value(), revision.to_value()])
                            })
                            .collect(),
                    ),
                ),
                (
                    mneme_core::Symbol::from("independent-supports"),
                    Value::integer(explanation.corroboration.independent_supports),
                ),
                (
                    mneme_core::Symbol::from("shared-ancestry"),
                    Value::Boolean(explanation.corroboration.shared_ancestry),
                ),
            ]),
        ),
        (
            mneme_core::Symbol::from("truncated"),
            Value::Boolean(explanation.truncated),
        ),
    ])
}

fn resume_value(
    workspace: &mut Workspace,
    checkpoint: RecordId,
    scope: &ScopeId,
) -> ApiResult<Value> {
    let memory = Memory::new(workspace);
    let view = memory.view().map_err(ApiError::from_memory)?;
    let record = view.record(checkpoint).map_err(ApiError::from_memory)?;
    if record.kind != RecordKind::Checkpoint || &record.scope != scope {
        return Err(ApiError::denied());
    }
    let (checkpoint_revision, episode_ids, verified) = view
        .checkpoint_revision(checkpoint)
        .map_err(ApiError::from_memory)?;
    let goal = record
        .payload
        .get("goal")
        .and_then(Value::as_string)
        .unwrap_or("");
    let state = record
        .payload
        .get("state")
        .and_then(Value::as_symbol)
        .map(|symbol| symbol.as_str())
        .unwrap_or("unknown");
    let note = record.payload.get("note").and_then(Value::as_string);
    let mut episodes = Vec::new();
    let mut attempts = Vec::new();
    let mut observations = Vec::new();
    for episode_id in &episode_ids {
        let episode = view.episode(*episode_id).map_err(ApiError::from_memory)?;
        let entry = episode_value(&episode);
        match episode.episode_type {
            mneme_memory::EpisodeType::Attempt => attempts.push(entry.clone()),
            mneme_memory::EpisodeType::Observation => observations.push(entry.clone()),
            _ => {}
        }
        episodes.push(entry);
    }
    let current = view.revision();
    let mut pending = Vec::new();
    for assertion in view.assertions().map_err(ApiError::from_memory)? {
        if assertion.lifecycle == Lifecycle::Proposed && &assertion.record.scope == scope {
            pending.push(assertion_value(&assertion));
        }
    }
    Ok(Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("checkpoint"),
            checkpoint.to_value(),
        ),
        (
            mneme_core::Symbol::from("checkpoint-revision"),
            checkpoint_revision.to_value(),
        ),
        (
            mneme_core::Symbol::from("current-revision"),
            current.to_value(),
        ),
        (
            mneme_core::Symbol::from("revision-changed"),
            Value::Boolean(checkpoint_revision != current),
        ),
        (
            mneme_core::Symbol::from("goal"),
            Value::string(goal.to_owned()),
        ),
        (mneme_core::Symbol::from("state"), Value::symbol(state)),
        (
            mneme_core::Symbol::from("note"),
            note.map(|note| Value::string(note.to_owned()))
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("episodes"),
            Value::sequence(episodes),
        ),
        (
            mneme_core::Symbol::from("attempts"),
            Value::sequence(attempts),
        ),
        (
            mneme_core::Symbol::from("observations"),
            Value::sequence(observations),
        ),
        (
            mneme_core::Symbol::from("pending-proposals"),
            Value::sequence(pending),
        ),
        (
            mneme_core::Symbol::from("verified-outcomes"),
            Value::sequence(verified.iter().map(|record| record.to_value()).collect()),
        ),
    ]))
}

fn episode_value(episode: &EpisodeView) -> Value {
    Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("record-id"),
            episode.record.record_id.to_value(),
        ),
        (
            mneme_core::Symbol::from("type"),
            Value::symbol(episode.episode_type.name()),
        ),
        (
            mneme_core::Symbol::from("actor"),
            Value::string(episode.actor.clone()),
        ),
        (
            mneme_core::Symbol::from("summary"),
            Value::string(episode.summary.clone()),
        ),
        (
            mneme_core::Symbol::from("occurred"),
            episode.occurred.to_value(),
        ),
    ])
}

fn forget_value(result: &RetentionResult) -> Value {
    Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("operation-id"),
            Value::string(result.operation_id.clone()),
        ),
        (
            mneme_core::Symbol::from("state"),
            Value::symbol(result.state.as_str()),
        ),
        (
            mneme_core::Symbol::from("generation"),
            Value::integer(result.generation),
        ),
        (
            mneme_core::Symbol::from("logical-withdrawal"),
            Value::Boolean(result.logical_withdrawal),
        ),
        (
            mneme_core::Symbol::from("physical-cleanup-complete"),
            Value::Boolean(result.physical_cleanup_complete),
        ),
        (
            mneme_core::Symbol::from("cleanup"),
            Value::symbol_dictionary([
                (
                    mneme_core::Symbol::from("purged"),
                    Value::integer(result.cleanup.purged),
                ),
                (
                    mneme_core::Symbol::from("absent"),
                    Value::integer(result.cleanup.absent),
                ),
                (
                    mneme_core::Symbol::from("retained-shared"),
                    Value::integer(result.cleanup.retained_shared),
                ),
                (
                    mneme_core::Symbol::from("unavailable"),
                    Value::integer(result.cleanup.unavailable),
                ),
                (
                    mneme_core::Symbol::from("failed"),
                    Value::integer(result.cleanup.failed),
                ),
                (
                    mneme_core::Symbol::from("pending"),
                    Value::integer(result.cleanup.pending),
                ),
            ]),
        ),
        (
            mneme_core::Symbol::from("limitations"),
            Value::sequence(
                result
                    .limitations
                    .iter()
                    .map(|limitation| Value::string(limitation.clone()))
                    .collect(),
            ),
        ),
    ])
}

fn capabilities_value() -> Value {
    Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("api-version"),
            Value::integer(crate::command::COMMAND_VERSION),
        ),
        (
            mneme_core::Symbol::from("operations"),
            Value::sequence(
                [
                    "record",
                    "accept",
                    "recall",
                    "explain",
                    "revise",
                    "resume",
                    "forget",
                    "proposal.inspect",
                ]
                .into_iter()
                .map(Value::symbol)
                .collect(),
            ),
        ),
        (
            mneme_core::Symbol::from("recall-modes"),
            Value::sequence(
                [RecallMode::Lexical, RecallMode::Vector]
                    .into_iter()
                    .map(|mode| Value::symbol(mode.name()))
                    .collect(),
            ),
        ),
        (
            mneme_core::Symbol::from("unavailable-modes"),
            Value::sequence(vec![Value::symbol_dictionary([
                (
                    mneme_core::Symbol::from("mode"),
                    Value::symbol("structured"),
                ),
                (
                    mneme_core::Symbol::from("reason"),
                    Value::string("tagged rule-request encoding is not exposed"),
                ),
            ])]),
        ),
    ])
}

fn none_value() -> Value {
    Value::symbol("none")
}

/// A structured tagged error document for adapter-level parse failures.
pub fn error_document(code: ApiErrorCode, message: &str) -> Value {
    response_envelope_for_error("unknown", "invalid", code, message)
}

fn response_envelope_for_error(
    request_id: &str,
    operation: &str,
    code: ApiErrorCode,
    message: &str,
) -> Value {
    Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("format"),
            Value::string(crate::command::RESULT_FORMAT),
        ),
        (
            mneme_core::Symbol::from("version"),
            Value::integer(crate::command::RESULT_VERSION),
        ),
        (
            mneme_core::Symbol::from("request-id"),
            Value::string(request_id),
        ),
        (
            mneme_core::Symbol::from("operation"),
            Value::symbol(operation),
        ),
        (
            mneme_core::Symbol::from("status"),
            Value::symbol(code.as_str()),
        ),
        (mneme_core::Symbol::from("data"), none_value()),
        (
            mneme_core::Symbol::from("error"),
            Value::symbol_dictionary([
                (
                    mneme_core::Symbol::from("code"),
                    Value::symbol(code.as_str()),
                ),
                (mneme_core::Symbol::from("message"), Value::string(message)),
            ]),
        ),
    ])
}
