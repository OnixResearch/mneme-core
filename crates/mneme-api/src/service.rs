//! Shared execution of validated agent-memory commands.
#![allow(path_segment_repetition, unbounded_collection_growth)] // Octet structural exception: domain-qualified names and macro-only imports are intentional

/// A transport-neutral response. `value` is a versioned tagged JSON document.
#[derive(Clone, Debug)]
pub struct ApiResponse {
    pub value: mneme_core::Value,
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
    pub fn execute(&self, command: &crate::command::ApiCommand) -> ApiResponse {
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

    #[allow(unknown_lints, function_length)] // Octet structural exception: cohesive state-machine code; split tracked separately
    fn dispatch(
        &self,
        command: &crate::command::ApiCommand,
    ) -> crate::error::ApiResult<(mneme_core::Value, Option<Context>)> {
        match command {
            crate::command::ApiCommand::Capabilities { .. } => Ok((capabilities_value(), None)),
            crate::command::ApiCommand::Record {
                scope,
                base,
                key,
                records,
                sources,
                ..
            } => {
                for record in records {
                    if &record.scope != scope {
                        return Err(crate::error::ApiError::invalid(
                            "record scope does not match command scope",
                        ));
                    }
                }
                let mut workspace = self.open()?;
                let batch = mneme_memory::MemoryBatch {
                    actor: self.session.principal.clone(),
                    scope: scope.clone(),
                    idempotency_key: key.clone(),
                    records: records
                        .iter()
                        .cloned()
                        .map(crate::command::record_draft)
                        .collect::<Vec<_>>(),
                    source_blobs: sources.clone(),
                    publications: Vec::new(),
                };
                let outcome = mneme_memory::Memory::new(&mut workspace)
                    .commit_at_base(batch, *base)
                    .map_err(crate::error::ApiError::from_memory)?;
                Ok((commit_value(&outcome), Some(self.context(scope, &outcome))))
            }
            crate::command::ApiCommand::Accept {
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
                let decision_draft = mneme_memory::build_decision(
                    *decision,
                    *decision_revision,
                    scope,
                    mneme_memory::DecisionKind::Acceptance,
                    *assertion,
                    &self.session.principal,
                    policy,
                    *base,
                    "accepted",
                    rationale,
                    &[],
                    &[],
                );
                let accepted = mneme_memory::build_assertion_revision(
                    &current,
                    *accepted_revision,
                    mneme_core::Lifecycle::Accepted,
                    mneme_core::Reference::local(*decision, mneme_core::RecordKind::Decision),
                    None,
                );
                let batch = mneme_memory::MemoryBatch {
                    actor: self.session.principal.clone(),
                    scope: scope.clone(),
                    idempotency_key: key.clone(),
                    records: vec![decision_draft, accepted],
                    source_blobs: Vec::new(),
                    publications: Vec::new(),
                };
                let outcome = mneme_memory::Memory::new(&mut workspace)
                    .commit_at_base(batch, *base)
                    .map_err(crate::error::ApiError::from_memory)?;
                Ok((commit_value(&outcome), Some(self.context(scope, &outcome))))
            }
            crate::command::ApiCommand::Recall {
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
                let revision = revision.unwrap_or(
                    workspace
                        .current_revision()
                        .map_err(crate::error::ApiError::from_store)?,
                );
                let request = mneme_recall::RecallRequest {
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
                let response = mneme_recall::RecallService::new(&mut workspace)
                    .recall(request)
                    .map_err(crate::error::ApiError::from_recall)?;
                let context = Context {
                    revision: response.context.served_revision,
                    scope: scope.clone(),
                    generation: response.context.eligibility_generation,
                };
                Ok((recall_value(&response), Some(context)))
            }
            crate::command::ApiCommand::Explain {
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
                        .map_err(crate::error::ApiError::from_store)?;
                    let explanation = {
                        let memory = mneme_memory::Memory::new(&mut workspace);
                        let view = memory.view().map_err(crate::error::ApiError::from_memory)?;
                        let record = view
                            .record(*assertion)
                            .map_err(crate::error::ApiError::from_memory)?;
                        if &record.scope != scope {
                            return Err(crate::error::ApiError::denied());
                        }
                        memory
                            .explain(
                                *assertion,
                                mneme_memory::Policy {
                                    max_explanation_nodes: *max_nodes,
                                    max_excerpt_bytes: *max_excerpt_bytes,
                                },
                            )
                            .map_err(crate::error::ApiError::from_memory)?
                    };
                    let after = workspace
                        .eligibility_generation()
                        .map_err(crate::error::ApiError::from_store)?;
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
                        return Err(crate::error::ApiError::new(
                            crate::error::ApiErrorCode::Conflict,
                            "eligibility barrier advanced during explanation",
                        ));
                    }
                }
                Err(crate::error::ApiError::new(
                    crate::error::ApiErrorCode::Failed,
                    "explanation retry exhausted",
                ))
            }
            crate::command::ApiCommand::Revise {
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
                    crate::command::ReviseAction::Supersede => (
                        mneme_memory::DecisionKind::Supersession,
                        mneme_core::Lifecycle::Superseded,
                        "superseded",
                    ),
                    crate::command::ReviseAction::Dispute => (
                        mneme_memory::DecisionKind::ConflictResolution,
                        mneme_core::Lifecycle::Disputed,
                        "disputed",
                    ),
                    crate::command::ReviseAction::Retract => (
                        mneme_memory::DecisionKind::Retraction,
                        mneme_core::Lifecycle::Retracted,
                        "retracted",
                    ),
                };
                let decision_draft = mneme_memory::build_decision(
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
                let superseded = superseded_by.map(|target| {
                    mneme_core::Reference::local(target, mneme_core::RecordKind::Assertion)
                });
                let revised = mneme_memory::build_assertion_revision(
                    &current,
                    *revised_revision,
                    lifecycle,
                    mneme_core::Reference::local(*decision, mneme_core::RecordKind::Decision),
                    superseded,
                );
                let batch = mneme_memory::MemoryBatch {
                    actor: self.session.principal.clone(),
                    scope: scope.clone(),
                    idempotency_key: key.clone(),
                    records: vec![decision_draft, revised],
                    source_blobs: Vec::new(),
                    publications: Vec::new(),
                };
                let outcome = mneme_memory::Memory::new(&mut workspace)
                    .commit_at_base(batch, *base)
                    .map_err(crate::error::ApiError::from_memory)?;
                Ok((commit_value(&outcome), Some(self.context(scope, &outcome))))
            }
            crate::command::ApiCommand::Resume {
                scope, checkpoint, ..
            } => {
                let mut workspace = self.open()?;
                let generation = workspace
                    .eligibility_generation()
                    .map_err(crate::error::ApiError::from_store)?;
                let value = resume_value(&mut workspace, *checkpoint, scope)?;
                let after = workspace
                    .eligibility_generation()
                    .map_err(crate::error::ApiError::from_store)?;
                if after != generation {
                    return Err(crate::error::ApiError::new(
                        crate::error::ApiErrorCode::Conflict,
                        "eligibility barrier advanced during resume",
                    ));
                }
                let revision = workspace
                    .current_revision()
                    .map_err(crate::error::ApiError::from_store)?;
                Ok((
                    value,
                    Some(Context {
                        revision,
                        scope: scope.clone(),
                        generation,
                    }),
                ))
            }
            crate::command::ApiCommand::Forget {
                scope,
                base,
                key,
                selector,
                effective,
                ..
            } => {
                let mut workspace = self.open()?;
                let request = mneme_retention::RetentionRequest {
                    actor: self.session.principal.clone(),
                    scope: scope.clone(),
                    base_revision: *base,
                    idempotency_key: key.clone(),
                    operation: mneme_retention::OperationKind::Forget,
                    selector: selector.clone(),
                    effective: *effective,
                    policy: mneme_retention::RetentionPolicy {
                        version: mneme_retention::POLICY_VERSION.to_owned(),
                        retain_assertion_after_prune: true,
                        block_content_replay: true,
                        retain_withdrawn_evidence_metadata: true,
                    },
                };
                let result = mneme_retention::Retention::new(&mut workspace)
                    .execute(request)
                    .map_err(crate::error::ApiError::from_retention)?;
                let generation = result.generation;
                let revision = workspace
                    .current_revision()
                    .map_err(crate::error::ApiError::from_store)?;
                Ok((
                    forget_value(&result),
                    Some(Context {
                        revision,
                        scope: scope.clone(),
                        generation,
                    }),
                ))
            }
            crate::command::ApiCommand::ProposalInspect {
                scope, assertion, ..
            } => {
                let mut workspace = self.open()?;
                let memory = mneme_memory::Memory::new(&mut workspace);
                let view = memory.view().map_err(crate::error::ApiError::from_memory)?;
                let record = view
                    .record(*assertion)
                    .map_err(crate::error::ApiError::from_memory)?;
                if &record.scope != scope {
                    return Err(crate::error::ApiError::denied());
                }
                let assertion = view
                    .assertion(*assertion)
                    .map_err(crate::error::ApiError::from_memory)?;
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

    fn open(&self) -> crate::error::ApiResult<mneme_store::Workspace> {
        mneme_store::Workspace::open(
            &self.session.workspace_root,
            mneme_store::WorkspaceConfig::new(
                Box::new(mneme_store::SystemClock),
                Box::new(mneme_store::NoFaults),
            ),
        )
        .map_err(crate::error::ApiError::from_store)
    }

    fn context(
        &self,
        scope: &mneme_core::ScopeId,
        outcome: &mneme_store::CommitOutcome,
    ) -> Context {
        Context {
            revision: outcome.revision,
            scope: scope.clone(),
            generation: outcome.eligibility_generation,
        }
    }
}

#[derive(Clone, Debug)]
struct Context {
    revision: mneme_core::WorkspaceRevisionId,
    scope: mneme_core::ScopeId,
    generation: u64,
}

fn current_assertion(
    workspace: &mneme_store::Workspace,
    assertion: mneme_core::RecordId,
    scope: &mneme_core::ScopeId,
) -> crate::error::ApiResult<mneme_core::RecordEnvelope> {
    let snapshot = workspace
        .snapshot()
        .map_err(crate::error::ApiError::from_store)?;
    let record = snapshot
        .records
        .iter()
        .find(|record| {
            record.record_id == assertion && record.kind == mneme_core::RecordKind::Assertion
        })
        .cloned()
        .ok_or_else(|| {
            crate::error::ApiError::new(
                crate::error::ApiErrorCode::Unavailable,
                "assertion is unavailable",
            )
        })?;
    if &record.scope != scope {
        return Err(crate::error::ApiError::denied());
    }
    Ok(record)
}

fn response_for_error(
    command: &crate::command::ApiCommand,
    error: crate::error::ApiError,
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

#[allow(unknown_lints, function_length)] // Octet structural exception: cohesive state-machine code; split tracked separately
fn response_envelope(
    command: &crate::command::ApiCommand,
    status: &str,
    context: Option<&Context>,
    data: mneme_core::Value,
    error: Option<&crate::error::ApiError>,
) -> mneme_core::Value {
    let mut entries = vec![
        (
            mneme_core::Value::symbol("format"),
            mneme_core::Value::string(crate::command::RESULT_FORMAT),
        ),
        (
            mneme_core::Value::symbol("version"),
            mneme_core::Value::integer(crate::command::RESULT_VERSION),
        ),
        (
            mneme_core::Value::symbol("request-id"),
            mneme_core::Value::string(command.request_id().to_owned()),
        ),
        (
            mneme_core::Value::symbol("operation"),
            mneme_core::Value::symbol(command.operation()),
        ),
        (
            mneme_core::Value::symbol("status"),
            mneme_core::Value::symbol(status),
        ),
        (mneme_core::Value::symbol("data"), data),
    ];
    if let Some(context) = context {
        entries.push((
            mneme_core::Value::symbol("context"),
            mneme_core::Value::symbol_dictionary([
                (
                    mneme_core::Symbol::from("workspace-revision"),
                    context.revision.to_value(),
                ),
                (mneme_core::Symbol::from("scope"), context.scope.to_value()),
                (
                    mneme_core::Symbol::from("eligibility-generation"),
                    mneme_core::Value::integer(context.generation),
                ),
                (
                    mneme_core::Symbol::from("schema-version"),
                    mneme_core::Value::integer(1),
                ),
            ]),
        ));
    }
    if let Some(error) = error {
        entries.push((
            mneme_core::Value::symbol("error"),
            mneme_core::Value::symbol_dictionary([
                (
                    mneme_core::Symbol::from("code"),
                    mneme_core::Value::symbol(error.code.as_str()),
                ),
                (
                    mneme_core::Symbol::from("message"),
                    mneme_core::Value::string(error.message.clone()),
                ),
                (
                    mneme_core::Symbol::from("diagnostics"),
                    mneme_core::Value::sequence(
                        error
                            .diagnostics
                            .iter()
                            .map(|diagnostic| mneme_core::Value::string(diagnostic.to_string()))
                            .collect(),
                    ),
                ),
            ]),
        ));
    }
    mneme_core::Value::symbol_dictionary(entries.into_iter().map(|(key, value)| {
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

fn commit_value(outcome: &mneme_store::CommitOutcome) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("revision"),
            outcome.revision.to_value(),
        ),
        (
            mneme_core::Symbol::from("sequence"),
            mneme_core::Value::integer(outcome.sequence),
        ),
        (
            mneme_core::Symbol::from("generation"),
            mneme_core::Value::integer(outcome.eligibility_generation),
        ),
        (
            mneme_core::Symbol::from("manifest-digest"),
            outcome.manifest_digest.to_value(),
        ),
        (
            mneme_core::Symbol::from("publications"),
            mneme_core::Value::sequence(
                outcome.publications.iter().map(publication_value).collect(),
            ),
        ),
    ])
}

fn publication_value(publication: &mneme_store::PublicationOutcome) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("intent-id"),
            mneme_core::Value::string(publication.intent_id.clone()),
        ),
        (
            mneme_core::Symbol::from("path"),
            mneme_core::Value::string(publication.path.clone()),
        ),
        (
            mneme_core::Symbol::from("state"),
            mneme_core::Value::symbol(publication.state.as_str()),
        ),
        (
            mneme_core::Symbol::from("detail"),
            publication
                .detail
                .as_ref()
                .map(|detail| mneme_core::Value::string(detail.clone()))
                .unwrap_or_else(|| mneme_core::Value::string("")),
        ),
    ])
}

fn assertion_value(assertion: &mneme_memory::AssertionView) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
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
            mneme_core::Value::string(assertion.predicate.clone()),
        ),
        (mneme_core::Symbol::from("value"), assertion.value.clone()),
        (
            mneme_core::Symbol::from("stance"),
            mneme_core::Value::symbol(match assertion.stance {
                mneme_memory::Stance::Affirm => "affirm",
                mneme_memory::Stance::Deny => "deny",
                mneme_memory::Stance::Hypothesis => "hypothesis",
            }),
        ),
        (
            mneme_core::Symbol::from("lifecycle"),
            mneme_core::Value::symbol(assertion.lifecycle.symbol()),
        ),
        (
            mneme_core::Symbol::from("origin"),
            mneme_core::Value::symbol(assertion.origin.symbol()),
        ),
        (
            mneme_core::Symbol::from("asserted-by"),
            mneme_core::Value::string(assertion.asserted_by.clone()),
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
            mneme_core::Value::sequence(
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
                .map(mneme_core::RecordId::to_value)
                .unwrap_or_else(none_value),
        ),
    ])
}

#[allow(unknown_lints, function_length)] // Octet structural exception: cohesive state-machine code; split tracked separately
fn recall_value(response: &mneme_recall::RecallResponse) -> mneme_core::Value {
    let context = mneme_core::Value::symbol_dictionary([
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
            mneme_core::Value::integer(response.context.eligibility_generation),
        ),
        (
            mneme_core::Symbol::from("temporal"),
            mneme_core::Value::symbol(response.context.temporal.name()),
        ),
        (
            mneme_core::Symbol::from("fusion-policy"),
            mneme_core::Value::string(response.context.fusion_policy.clone()),
        ),
        (
            mneme_core::Symbol::from("index-versions"),
            mneme_core::Value::symbol_dictionary(response.context.index_versions.iter().map(
                |(mode, version)| {
                    (
                        mneme_core::Symbol::from(mode.as_str()),
                        mneme_core::Value::string(version.clone()),
                    )
                },
            )),
        ),
    ]);
    mneme_core::Value::symbol_dictionary([
        (mneme_core::Symbol::from("context"), context),
        (
            mneme_core::Symbol::from("execution-status"),
            mneme_core::Value::symbol(response.status.name()),
        ),
        (
            mneme_core::Symbol::from("modes"),
            mneme_core::Value::sequence(response.modes.iter().map(mode_value).collect()),
        ),
        (
            mneme_core::Symbol::from("candidates"),
            mneme_core::Value::sequence(response.candidates.iter().map(candidate_value).collect()),
        ),
        (
            mneme_core::Symbol::from("exhaustive"),
            mneme_core::Value::Boolean(response.exhaustive),
        ),
        (
            mneme_core::Symbol::from("absence-established"),
            mneme_core::Value::Boolean(response.absence_established),
        ),
        (
            mneme_core::Symbol::from("truncated"),
            mneme_core::Value::Boolean(response.truncated),
        ),
        (
            mneme_core::Symbol::from("omissions"),
            mneme_core::Value::sequence(
                response
                    .omissions
                    .iter()
                    .map(|omission| {
                        mneme_core::Value::symbol_dictionary([
                            (
                                mneme_core::Symbol::from("candidate"),
                                mneme_core::Value::string(omission.candidate.clone()),
                            ),
                            (
                                mneme_core::Symbol::from("reason"),
                                mneme_core::Value::string(omission.reason.clone()),
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
                .map(|reason| mneme_core::Value::string(reason.clone()))
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("boundary"),
            mneme_core::Value::symbol_dictionary([
                (
                    mneme_core::Symbol::from("kind"),
                    mneme_core::Value::string(response.boundary.kind.clone()),
                ),
                (
                    mneme_core::Symbol::from("instructions-are-data"),
                    mneme_core::Value::Boolean(response.boundary.instructions_are_data),
                ),
                (
                    mneme_core::Symbol::from("may-change-scope"),
                    mneme_core::Value::Boolean(response.boundary.may_change_scope),
                ),
                (
                    mneme_core::Symbol::from("may-execute-code"),
                    mneme_core::Value::Boolean(response.boundary.may_execute_code),
                ),
                (
                    mneme_core::Symbol::from("may-register-rules"),
                    mneme_core::Value::Boolean(response.boundary.may_register_rules),
                ),
            ]),
        ),
    ])
}

fn mode_value(mode: &mneme_recall::ModeReport) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("mode"),
            mneme_core::Value::symbol(mode.mode.name()),
        ),
        (
            mneme_core::Symbol::from("status"),
            mneme_core::Value::symbol(mode.status.name()),
        ),
        (
            mneme_core::Symbol::from("revision"),
            mode.revision
                .map(|revision| revision.to_value())
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("coverage-complete"),
            mneme_core::Value::Boolean(mode.coverage.complete),
        ),
        (
            mneme_core::Symbol::from("documents-indexed"),
            mneme_core::Value::integer(mode.coverage.documents_indexed),
        ),
        (
            mneme_core::Symbol::from("documents-skipped"),
            mneme_core::Value::integer(mode.coverage.documents_skipped),
        ),
        (
            mneme_core::Symbol::from("candidates"),
            mneme_core::Value::integer(mode.candidates),
        ),
    ])
}

#[allow(unknown_lints, function_length)] // Octet structural exception: cohesive state-machine code; split tracked separately
fn candidate_value(candidate: &mneme_recall::RecallCandidate) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("id"),
            mneme_core::Value::string(candidate.id.clone()),
        ),
        (
            mneme_core::Symbol::from("content-kind"),
            mneme_core::Value::symbol(candidate.content_kind.name()),
        ),
        (
            mneme_core::Symbol::from("text"),
            mneme_core::Value::string(candidate.text.clone()),
        ),
        (
            mneme_core::Symbol::from("text-truncated"),
            mneme_core::Value::Boolean(candidate.text_truncated),
        ),
        (
            mneme_core::Symbol::from("quote"),
            mneme_core::Value::Boolean(candidate.quote),
        ),
        (
            mneme_core::Symbol::from("source"),
            candidate
                .source
                .map(mneme_core::RecordId::to_value)
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("source-revision"),
            candidate
                .source_revision
                .map(mneme_core::RevisionId::to_value)
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("span"),
            candidate
                .span
                .map(mneme_core::SourceSpan::to_value)
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("field-path"),
            mneme_core::Value::string(candidate.field_path.clone()),
        ),
        (
            mneme_core::Symbol::from("assertion"),
            candidate
                .assertion
                .map(mneme_core::RecordId::to_value)
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("episode"),
            candidate
                .episode
                .map(mneme_core::RecordId::to_value)
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("independent-support"),
            mneme_core::Value::Boolean(candidate.independent_support),
        ),
        (
            mneme_core::Symbol::from("origins"),
            mneme_core::Value::sequence(
                candidate
                    .origins
                    .iter()
                    .map(|mode| mneme_core::Value::symbol(mode.name()))
                    .collect(),
            ),
        ),
        (
            mneme_core::Symbol::from("score"),
            mneme_core::Value::double(candidate.score),
        ),
        (
            mneme_core::Symbol::from("evidence"),
            mneme_core::Value::sequence(
                candidate
                    .evidence
                    .iter()
                    .map(recall_evidence_value)
                    .collect(),
            ),
        ),
        (
            mneme_core::Symbol::from("derivations"),
            mneme_core::Value::sequence(
                candidate.derivations.iter().map(derivation_value).collect(),
            ),
        ),
        (
            mneme_core::Symbol::from("ancestry-roots"),
            mneme_core::Value::sequence(
                candidate
                    .ancestry_roots
                    .iter()
                    .map(|(record, revision)| {
                        mneme_core::Value::sequence(vec![record.to_value(), revision.to_value()])
                    })
                    .collect(),
            ),
        ),
    ])
}

fn recall_evidence_value(evidence: &mneme_recall::RecallEvidence) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
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
                .map(mneme_core::RevisionId::to_value)
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("availability"),
            mneme_core::Value::symbol(evidence.availability.name()),
        ),
        (
            mneme_core::Symbol::from("span"),
            evidence
                .span
                .map(mneme_core::SourceSpan::to_value)
                .unwrap_or_else(none_value),
        ),
    ])
}

fn derivation_value(derivation: &mneme_datalog::Derivation) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("rule-id"),
            mneme_core::Value::string(derivation.rule_id.clone()),
        ),
        (
            mneme_core::Symbol::from("rule-version"),
            mneme_core::Value::string(derivation.rule_version.clone()),
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
            mneme_core::Value::Boolean(derivation.truncated),
        ),
        (
            mneme_core::Symbol::from("premises"),
            mneme_core::Value::sequence(
                derivation
                    .premises
                    .iter()
                    .map(|premise| {
                        mneme_core::Value::symbol_dictionary([
                            (
                                mneme_core::Symbol::from("predicate"),
                                mneme_core::Value::string(premise.predicate.clone()),
                            ),
                            (
                                mneme_core::Symbol::from("terms"),
                                mneme_core::Value::sequence(premise.terms.clone()),
                            ),
                            (
                                mneme_core::Symbol::from("canonical"),
                                premise
                                    .canonical
                                    .map(mneme_core::RecordId::to_value)
                                    .unwrap_or_else(none_value),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

#[allow(unknown_lints, function_length)] // Octet structural exception: cohesive state-machine code; split tracked separately
fn explain_value(explanation: &mneme_memory::Explanation) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
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
            mneme_core::Value::sequence(
                explanation
                    .decisions
                    .iter()
                    .map(|decision| {
                        mneme_core::Value::symbol_dictionary([
                            (
                                mneme_core::Symbol::from("record-id"),
                                decision.record.record_id.to_value(),
                            ),
                            (
                                mneme_core::Symbol::from("kind"),
                                mneme_core::Value::symbol(decision.decision_kind.name()),
                            ),
                            (
                                mneme_core::Symbol::from("outcome"),
                                mneme_core::Value::string(decision.outcome.clone()),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            mneme_core::Symbol::from("evidence"),
            mneme_core::Value::sequence(
                explanation
                    .evidence
                    .iter()
                    .map(|evidence| {
                        mneme_core::Value::symbol_dictionary([
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
                                mneme_core::Value::symbol(evidence.availability.name()),
                            ),
                            (
                                mneme_core::Symbol::from("excerpt"),
                                evidence
                                    .excerpt
                                    .as_ref()
                                    .map(|excerpt| mneme_core::Value::bytes(excerpt.bytes.clone()))
                                    .unwrap_or_else(none_value),
                            ),
                            (
                                mneme_core::Symbol::from("eligible"),
                                mneme_core::Value::Boolean(evidence.eligible),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            mneme_core::Symbol::from("corroboration"),
            mneme_core::Value::symbol_dictionary([
                (
                    mneme_core::Symbol::from("roots"),
                    mneme_core::Value::sequence(
                        explanation
                            .corroboration
                            .roots
                            .iter()
                            .map(|(record, revision)| {
                                mneme_core::Value::sequence(vec![
                                    record.to_value(),
                                    revision.to_value(),
                                ])
                            })
                            .collect(),
                    ),
                ),
                (
                    mneme_core::Symbol::from("independent-supports"),
                    mneme_core::Value::integer(explanation.corroboration.independent_supports),
                ),
                (
                    mneme_core::Symbol::from("shared-ancestry"),
                    mneme_core::Value::Boolean(explanation.corroboration.shared_ancestry),
                ),
            ]),
        ),
        (
            mneme_core::Symbol::from("truncated"),
            mneme_core::Value::Boolean(explanation.truncated),
        ),
    ])
}

#[allow(unknown_lints, function_length)] // Octet structural exception: cohesive state-machine code; split tracked separately
fn resume_value(
    workspace: &mut mneme_store::Workspace,
    checkpoint: mneme_core::RecordId,
    scope: &mneme_core::ScopeId,
) -> crate::error::ApiResult<mneme_core::Value> {
    let memory = mneme_memory::Memory::new(workspace);
    let view = memory.view().map_err(crate::error::ApiError::from_memory)?;
    let record = view
        .record(checkpoint)
        .map_err(crate::error::ApiError::from_memory)?;
    if record.kind != mneme_core::RecordKind::Checkpoint || &record.scope != scope {
        return Err(crate::error::ApiError::denied());
    }
    let (checkpoint_revision, episode_ids, verified) = view
        .checkpoint_revision(checkpoint)
        .map_err(crate::error::ApiError::from_memory)?;
    let goal = record
        .payload
        .get("goal")
        .and_then(mneme_core::Value::as_string)
        .unwrap_or("");
    let state = record
        .payload
        .get("state")
        .and_then(mneme_core::Value::as_symbol)
        .map(|symbol| symbol.as_str())
        .unwrap_or("unknown");
    let note = record
        .payload
        .get("note")
        .and_then(mneme_core::Value::as_string);
    let mut episodes = Vec::with_capacity(episode_ids.len());
    let mut attempts = Vec::with_capacity(episode_ids.len());
    let mut observations = Vec::with_capacity(episode_ids.len());
    for episode_id in &episode_ids {
        let episode = view
            .episode(*episode_id)
            .map_err(crate::error::ApiError::from_memory)?;
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
    for assertion in view
        .assertions()
        .map_err(crate::error::ApiError::from_memory)?
    {
        if assertion.lifecycle == mneme_core::Lifecycle::Proposed
            && &assertion.record.scope == scope
        {
            pending.push(assertion_value(&assertion));
        }
    }
    Ok(mneme_core::Value::symbol_dictionary([
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
            mneme_core::Value::Boolean(checkpoint_revision != current),
        ),
        (
            mneme_core::Symbol::from("goal"),
            mneme_core::Value::string(goal.to_owned()),
        ),
        (
            mneme_core::Symbol::from("state"),
            mneme_core::Value::symbol(state),
        ),
        (
            mneme_core::Symbol::from("note"),
            note.map(|note| mneme_core::Value::string(note.to_owned()))
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("episodes"),
            mneme_core::Value::sequence(episodes),
        ),
        (
            mneme_core::Symbol::from("attempts"),
            mneme_core::Value::sequence(attempts),
        ),
        (
            mneme_core::Symbol::from("observations"),
            mneme_core::Value::sequence(observations),
        ),
        (
            mneme_core::Symbol::from("pending-proposals"),
            mneme_core::Value::sequence(pending),
        ),
        (
            mneme_core::Symbol::from("verified-outcomes"),
            mneme_core::Value::sequence(verified.iter().map(|record| record.to_value()).collect()),
        ),
    ]))
}

fn episode_value(episode: &mneme_memory::EpisodeView) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("record-id"),
            episode.record.record_id.to_value(),
        ),
        (
            mneme_core::Symbol::from("type"),
            mneme_core::Value::symbol(episode.episode_type.name()),
        ),
        (
            mneme_core::Symbol::from("actor"),
            mneme_core::Value::string(episode.actor.clone()),
        ),
        (
            mneme_core::Symbol::from("summary"),
            mneme_core::Value::string(episode.summary.clone()),
        ),
        (
            mneme_core::Symbol::from("occurred"),
            episode.occurred.to_value(),
        ),
    ])
}

fn forget_value(result: &mneme_retention::RetentionResult) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("operation-id"),
            mneme_core::Value::string(result.operation_id.clone()),
        ),
        (
            mneme_core::Symbol::from("state"),
            mneme_core::Value::symbol(result.state.as_str()),
        ),
        (
            mneme_core::Symbol::from("generation"),
            mneme_core::Value::integer(result.generation),
        ),
        (
            mneme_core::Symbol::from("logical-withdrawal"),
            mneme_core::Value::Boolean(result.logical_withdrawal),
        ),
        (
            mneme_core::Symbol::from("physical-cleanup-complete"),
            mneme_core::Value::Boolean(result.physical_cleanup_complete),
        ),
        (
            mneme_core::Symbol::from("cleanup"),
            mneme_core::Value::symbol_dictionary([
                (
                    mneme_core::Symbol::from("purged"),
                    mneme_core::Value::integer(result.cleanup.purged),
                ),
                (
                    mneme_core::Symbol::from("absent"),
                    mneme_core::Value::integer(result.cleanup.absent),
                ),
                (
                    mneme_core::Symbol::from("retained-shared"),
                    mneme_core::Value::integer(result.cleanup.retained_shared),
                ),
                (
                    mneme_core::Symbol::from("unavailable"),
                    mneme_core::Value::integer(result.cleanup.unavailable),
                ),
                (
                    mneme_core::Symbol::from("failed"),
                    mneme_core::Value::integer(result.cleanup.failed),
                ),
                (
                    mneme_core::Symbol::from("pending"),
                    mneme_core::Value::integer(result.cleanup.pending),
                ),
            ]),
        ),
        (
            mneme_core::Symbol::from("limitations"),
            mneme_core::Value::sequence(
                result
                    .limitations
                    .iter()
                    .map(|limitation| mneme_core::Value::string(limitation.clone()))
                    .collect(),
            ),
        ),
    ])
}

fn capabilities_value() -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("api-version"),
            mneme_core::Value::integer(crate::command::COMMAND_VERSION),
        ),
        (
            mneme_core::Symbol::from("operations"),
            mneme_core::Value::sequence(
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
                .map(mneme_core::Value::symbol)
                .collect(),
            ),
        ),
        (
            mneme_core::Symbol::from("recall-modes"),
            mneme_core::Value::sequence(
                [
                    mneme_recall::RecallMode::Lexical,
                    mneme_recall::RecallMode::Vector,
                ]
                .into_iter()
                .map(|mode| mneme_core::Value::symbol(mode.name()))
                .collect(),
            ),
        ),
        (
            mneme_core::Symbol::from("unavailable-modes"),
            mneme_core::Value::sequence(vec![mneme_core::Value::symbol_dictionary([
                (
                    mneme_core::Symbol::from("mode"),
                    mneme_core::Value::symbol("structured"),
                ),
                (
                    mneme_core::Symbol::from("reason"),
                    mneme_core::Value::string("tagged rule-request encoding is not exposed"),
                ),
            ])]),
        ),
    ])
}

fn none_value() -> mneme_core::Value {
    mneme_core::Value::symbol("none")
}

/// A structured tagged error document for adapter-level parse failures.
pub fn error_document(code: crate::error::ApiErrorCode, message: &str) -> mneme_core::Value {
    response_envelope_for_error("unknown", "invalid", code, message)
}

fn response_envelope_for_error(
    request_id: &str,
    operation: &str,
    code: crate::error::ApiErrorCode,
    message: &str,
) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("format"),
            mneme_core::Value::string(crate::command::RESULT_FORMAT),
        ),
        (
            mneme_core::Symbol::from("version"),
            mneme_core::Value::integer(crate::command::RESULT_VERSION),
        ),
        (
            mneme_core::Symbol::from("request-id"),
            mneme_core::Value::string(request_id),
        ),
        (
            mneme_core::Symbol::from("operation"),
            mneme_core::Value::symbol(operation),
        ),
        (
            mneme_core::Symbol::from("status"),
            mneme_core::Value::symbol(code.as_str()),
        ),
        (mneme_core::Symbol::from("data"), none_value()),
        (
            mneme_core::Symbol::from("error"),
            mneme_core::Value::symbol_dictionary([
                (
                    mneme_core::Symbol::from("code"),
                    mneme_core::Value::symbol(code.as_str()),
                ),
                (
                    mneme_core::Symbol::from("message"),
                    mneme_core::Value::string(message),
                ),
            ]),
        ),
    ])
}
