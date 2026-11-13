//! Shared execution of validated agent-memory commands.
//!
//! Every command is authorized against the session allowlist before the
//! workspace is opened, reads one pinned view, and reports the revision it read
//! from. A record held outside the allowlist is reported exactly like a record
//! that does not exist.
//!
//! A recall is pinned, bounded and never cancelled: the dispatch serves exactly
//! one revision, the request carries the time and context limits it must stay
//! inside, and this transport has no channel that reaches a call in progress,
//! so a recall ends in a result or in `timeout`, never in `cancelled`. The
//! transport status reports that outcome (`ok`, `partial`, `timeout`,
//! `cancelled`, `failed`) instead of reporting every reply as success.
//!
//! A service may share one verified-record cache across every workspace handle
//! it opens (`with_record_cache`); without one it opens workspaces exactly as
//! before.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// A transport-neutral response. `value` is a versioned tagged JSON document.
#[derive(Clone, Debug)]
pub struct CallResponse {
    pub value: mneme_core::Value,
    pub ok: bool,
}

/// The transport level outcome of a completed dispatch.
struct Dispatch {
    value: mneme_core::Value,
    context: Option<Context>,
    status: &'static str,
}

impl Dispatch {
    fn ok(value: mneme_core::Value, context: Option<Context>) -> Self {
        Dispatch {
            value,
            context,
            status: STATUS_OK,
        }
    }

    fn qualified(value: mneme_core::Value, context: Option<Context>, status: &'static str) -> Self {
        Dispatch {
            value,
            context,
            status,
        }
    }
}

/// The status of a fully completed command.
const STATUS_OK: &str = "ok";

/// One local API service bound to an authorized principal and scopes.
#[derive(Clone)]
pub struct ApiService {
    session: crate::command::LocalSession,
    /// The verified-record cache every workspace handle this service opens
    /// shares, when the caller supplied one.
    record_cache: Option<mneme_store::SharedRecordCache>,
}

impl std::fmt::Debug for ApiService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApiService")
            .field("session", &self.session)
            .field("has_record_cache", &self.record_cache.is_some())
            .finish()
    }
}

impl ApiService {
    /// Bind one loaded session.
    pub fn new(session: crate::command::LocalSession) -> Self {
        ApiService {
            session,
            record_cache: None,
        }
    }

    /// Every workspace handle this service opens shares `cache`.
    ///
    /// A shared cache lets two services on one workspace reuse each other's
    /// verified-record facts, so neither re-reads and re-verifies a record the
    /// other already resolved.
    pub fn with_record_cache(mut self, cache: mneme_store::SharedRecordCache) -> Self {
        self.record_cache = Some(cache);
        self
    }

    /// The bound session.
    pub fn session(&self) -> &crate::command::LocalSession {
        &self.session
    }

    /// Execute one command and always return a structured transport document.
    pub fn execute(&self, command: &crate::command::ApiCommand) -> CallResponse {
        if let Some(scope) = command.scope()
            && let Err(error) = self.session.authorize(scope)
        {
            return response_for_error(command, error);
        }
        match self.dispatch(command) {
            Ok(dispatch) => CallResponse {
                value: response_envelope(
                    command,
                    dispatch.status,
                    dispatch.context.as_ref(),
                    dispatch.value,
                    None,
                ),
                ok: dispatch.status == STATUS_OK,
            },
            Err(error) => response_for_error(command, error),
        }
    }

    #[allow(unknown_lints)] // Octet structural exception: cohesive dispatch table; split tracked separately
    fn dispatch(&self, command: &crate::command::ApiCommand) -> crate::error::CallResult<Dispatch> {
        match command {
            crate::command::ApiCommand::Capabilities { .. } => {
                Ok(Dispatch::ok(capabilities_value(), None))
            }
            crate::command::ApiCommand::Record { .. } => self.dispatch_record(command),
            crate::command::ApiCommand::Accept { .. } => self.dispatch_accept(command),
            crate::command::ApiCommand::Recall { .. } => self.dispatch_recall(command),
            crate::command::ApiCommand::Explain { .. } => self.dispatch_explain(command),
            crate::command::ApiCommand::Revise { .. } => self.dispatch_revise(command),
            crate::command::ApiCommand::Resume { .. } => self.dispatch_resume(command),
            crate::command::ApiCommand::ImageRead { .. } => self.dispatch_image(command),
            crate::command::ApiCommand::Forget { .. } => self.dispatch_forget(command),
            crate::command::ApiCommand::ProposalInspect { .. } => {
                self.dispatch_proposal_inspect(command)
            }
        }
    }

    /// The scopes this session may read and write.
    fn access(&self) -> mneme_memory::Access {
        mneme_memory::Access::scopes(self.session.scopes().cloned())
    }

    fn allows(&self, scope: &mneme_core::ScopeId) -> bool {
        self.session.authorize(scope).is_ok()
    }

    /// A memory engine bound to this session's authorization.
    fn memory<'w>(&self, workspace: &'w mut mneme_store::Workspace) -> mneme_memory::Engine<'w> {
        mneme_memory::Engine::new(workspace, self.access())
    }

    /// Open one pinned view, retrying once when the eligibility barrier moved.
    fn pinned_view(
        &self,
        workspace: &mut mneme_store::Workspace,
    ) -> crate::error::CallResult<(mneme_memory::View, u64)> {
        for attempt in 0..2 {
            let generation = workspace
                .eligibility_generation()
                .map_err(crate::error::ApiError::from_store)?;
            match self.memory(workspace).view_at(Some(generation)) {
                Ok(view) => return Ok((view, generation)),
                Err(error) if attempt == 0 && barrier_advanced(&error) => continue,
                Err(error) => return Err(crate::error::ApiError::from_memory(error)),
            }
        }
        Err(crate::error::ApiError::new(
            crate::error::ApiErrorCode::Conflict,
            "eligibility barrier advanced during the request",
        ))
    }

    fn dispatch_record(
        &self,
        command: &crate::command::ApiCommand,
    ) -> crate::error::CallResult<Dispatch> {
        let crate::command::ApiCommand::Record {
            scope,
            base,
            key,
            records,
            sources,
            ..
        } = command
        else {
            return Err(crate::error::ApiError::invalid(
                "record dispatch receives a record command",
            ));
        };
        for (index, record) in records.iter().enumerate() {
            if &record.scope != scope {
                return Err(member_refusal(
                    record_member(index, "scope"),
                    "record scope does not match command scope",
                ));
            }
            refuse_forbidden_record(index, record)?;
        }
        let mut workspace = self.open()?;
        let snapshot = workspace
            .snapshot()
            .map_err(crate::error::ApiError::from_store)?;
        for record in records {
            self.guard_identity(&snapshot, record)?;
        }
        let batch = mneme_memory::Batch {
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
        let outcome = self
            .memory(&mut workspace)
            .commit_at_base(batch, *base)
            .map_err(crate::error::ApiError::from_memory)?;
        Ok(Dispatch::ok(
            commit_value(&outcome),
            Some(self.context(scope, &outcome)),
        ))
    }

    /// Refuse a record identity held in a scope the caller cannot resolve.
    ///
    /// Only the foreign case is decided here: a revision of a record in the
    /// caller's own scope is validated by the coordinator, and a retry of a
    /// committed command must reach the engine's replay path unchanged.
    fn guard_identity(
        &self,
        snapshot: &mneme_store::Snapshot,
        draft: &mneme_core::RecordEnvelope,
    ) -> crate::error::CallResult<()> {
        let Some(existing) = snapshot
            .records
            .iter()
            .find(|record| record.record_id == draft.record_id)
        else {
            return Ok(());
        };
        if !self.allows(&existing.scope) {
            // Answered exactly like a record id that does not resolve: the
            // writer learns nothing about the other scope's record.
            return Err(crate::error::ApiError::missing());
        }
        Ok(())
    }

    fn dispatch_accept(
        &self,
        command: &crate::command::ApiCommand,
    ) -> crate::error::CallResult<Dispatch> {
        let crate::command::ApiCommand::Accept {
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
        } = command
        else {
            return Err(crate::error::ApiError::invalid(
                "accept dispatch receives an accept command",
            ));
        };
        let mut workspace = self.open()?;
        let current = self.assertion_at(&workspace, *base, *assertion)?;
        check_accept_state(current.assertion_lifecycle())?;
        let decision_draft = mneme_memory::build_decision(
            *decision,
            *decision_revision,
            scope,
            mneme_memory::DecisionOptions {
                kind: mneme_memory::DecisionKind::Acceptance,
                target: *assertion,
                actor: &self.session.principal,
                policy,
                input_revision: *base,
                outcome: "accepted",
                rationale,
                evidence: &[],
                related: &[],
            },
        );
        let accepted = mneme_memory::build_assertion_revision(
            &current,
            *accepted_revision,
            mneme_core::Lifecycle::Accepted,
            mneme_core::Reference::local(*decision, mneme_core::RecordKind::Decision),
            None,
        );
        let batch = mneme_memory::Batch {
            actor: self.session.principal.clone(),
            scope: scope.clone(),
            idempotency_key: key.clone(),
            records: vec![decision_draft, accepted],
            source_blobs: Vec::new(),
            publications: Vec::new(),
        };
        let outcome = self
            .memory(&mut workspace)
            .commit_at_base(batch, *base)
            .map_err(crate::error::ApiError::from_memory)?;
        Ok(Dispatch::ok(
            commit_value(&outcome),
            Some(self.context(scope, &outcome)),
        ))
    }

    /// Serve one recall request at exactly one pinned revision.
    ///
    /// The revision is the caller's, or, for a caller that names none, the head
    /// read here. That single revision is what the request pins and what the
    /// result context reports, so a commit landing between this read and
    /// recall's own head read is served at the pinned revision (and disclosed
    /// as `stale`) instead of being refused as a conflict the caller did not
    /// cause.
    ///
    /// A call cannot be cancelled through this transport: an API or MCP caller
    /// has no channel that reaches a dispatch already in progress, so the
    /// recall service is given no cancellation flag and `cancelled` is never
    /// produced here. Every call is bounded by the request's time limit
    /// instead: the limit travels to recall, which observes that clock as it
    /// charges work and ends the call with `timeout`, and the result reports
    /// that limit as the `time-ms` entry of `budget`, together with whether
    /// this call exhausted it. The elapsed time itself is measured, so it stays
    /// out of the document and two transports answering one command agree.
    fn dispatch_recall(
        &self,
        command: &crate::command::ApiCommand,
    ) -> crate::error::CallResult<Dispatch> {
        if !matches!(command, crate::command::ApiCommand::Recall { .. }) {
            return Err(crate::error::ApiError::invalid(
                "recall dispatch receives a recall command",
            ));
        }
        let mut workspace = self.open()?;
        let selection = self.recall_selection(&workspace, command)?;
        let revision = match selection.pinned {
            Some(revision) => revision,
            None => workspace
                .current_revision()
                .map_err(crate::error::ApiError::from_store)?,
        };
        let request = self.recall_request(command, &selection, revision)?;
        let response = mneme_recall::Service::new(&mut workspace)
            .recall(request)
            .map_err(crate::error::ApiError::from_recall)?;
        let context = Context {
            revision: response.context.served_revision,
            scope: selection.scope.clone(),
            generation: response.context.eligibility_generation,
        };
        Ok(Dispatch::qualified(
            recall_value(&response),
            Some(context),
            execution_status(response.status),
        ))
    }

    /// Resolve the revision-independent parts of a recall command.
    fn recall_selection(
        &self,
        workspace: &mneme_store::Workspace,
        command: &crate::command::ApiCommand,
    ) -> crate::error::CallResult<RecallSelection> {
        let crate::command::ApiCommand::Recall {
            scope,
            revision,
            modes,
            structured,
            allow_stale,
            ..
        } = command
        else {
            return Err(crate::error::ApiError::invalid(
                "recall dispatch receives a recall command",
            ));
        };
        // A caller that named no revision is served at the head this dispatch
        // pins, so a commit that lands before the structured build reads that
        // head must not fail the query for it either.
        let is_stale_permitted = *allow_stale || revision.is_none();
        let structured = match structured {
            Some(query) => Some(self.structured_request(workspace, query, is_stale_permitted)?),
            None => None,
        };
        // A structured query is itself an explicit request for the structured
        // mode, even when the caller constructed the command without listing it.
        let mut requested_modes = modes.clone();
        if structured.is_some() {
            requested_modes.insert(mneme_recall::Mode::Structured);
        }
        Ok(RecallSelection {
            scope: scope.clone(),
            pinned: *revision,
            modes: requested_modes,
            structured,
        })
    }

    /// Build the recall request to serve at one revision.
    fn recall_request(
        &self,
        command: &crate::command::ApiCommand,
        selection: &RecallSelection,
        revision: mneme_core::WorkspaceRevisionId,
    ) -> crate::error::CallResult<mneme_recall::Request> {
        let crate::command::ApiCommand::Recall {
            query,
            at,
            temporal,
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
        } = command
        else {
            return Err(crate::error::ApiError::invalid(
                "recall dispatch receives a recall command",
            ));
        };
        Ok(mneme_recall::Request {
            actor: self.session.principal.clone(),
            access: self.access(),
            scope: selection.scope.clone(),
            revision,
            query: query.clone(),
            at: *at,
            temporal: *temporal,
            modes: selection.modes.clone(),
            structured: selection.structured.clone(),
            // A caller that named no revision asked for the head read above, so
            // a commit that lands before recall re-reads the head must serve
            // that pinned revision rather than report a conflict the caller
            // did not cause. The context still says the served revision is not
            // the head (`stale`), so nothing is hidden.
            allow_stale: *allow_stale || selection.pinned.is_none(),
            allow_fallback: *allow_fallback,
            allow_partial: *allow_partial,
            include_disputed: *include_disputed,
            include_hypothetical: *include_hypothetical,
            max_items: *max_items,
            max_context_bytes: *max_context_bytes,
            max_quote_bytes: *max_quote_bytes,
            max_time_ms: *max_time_ms,
            cancellation: None,
        })
    }

    /// Build the structured request, resolving a bundle reference if given.
    fn structured_request(
        &self,
        workspace: &mneme_store::Workspace,
        query: &crate::command::StructuredQuery,
        allow_stale: bool,
    ) -> crate::error::CallResult<mneme_recall::StructuredRequest> {
        let bundle = match (&query.bundle, &query.bundle_path) {
            (Some(bundle), None) => bundle.clone(),
            (None, Some(path)) => bundle_from_path(workspace, path)?,
            _ => {
                return Err(member_refusal(
                    payload_member("structured"),
                    "structured request needs exactly one of bundle or bundle-path",
                ));
            }
        };
        Ok(mneme_recall::StructuredRequest {
            bundle,
            query: mneme_datalog::Query {
                predicate: query.relation.clone(),
                constants: query.constants.clone(),
                limit: query.limit,
                allow_stale,
                cancellation: None,
            },
            limits: query.limits.clone(),
            incomplete_extents: query.incomplete_extents.clone(),
        })
    }

    fn dispatch_explain(
        &self,
        command: &crate::command::ApiCommand,
    ) -> crate::error::CallResult<Dispatch> {
        let crate::command::ApiCommand::Explain {
            scope,
            assertion,
            max_nodes,
            max_excerpt_bytes,
            ..
        } = command
        else {
            return Err(crate::error::ApiError::invalid(
                "explain dispatch receives an explain command",
            ));
        };
        let mut workspace = self.open()?;
        // One view authorizes the target and serves the explanation, so a
        // commit between the two cannot change what is disclosed.
        let (view, generation) = self.pinned_view(&mut workspace)?;
        let record = self.visible_record(&view, &workspace, *assertion)?;
        if record.kind != mneme_core::RecordKind::Assertion {
            return Err(member_refusal(
                payload_member("assertion"),
                "requested record is not an assertion",
            ));
        }
        let explanation = view
            .explain(
                *assertion,
                mneme_memory::Policy {
                    max_explanation_nodes: *max_nodes,
                    max_excerpt_bytes: *max_excerpt_bytes,
                },
            )
            .map_err(crate::error::ApiError::from_memory)?;
        Ok(Dispatch::ok(
            explain_value(&explanation),
            Some(Context {
                revision: explanation.workspace_revision,
                scope: scope.clone(),
                generation,
            }),
        ))
    }

    fn dispatch_revise(
        &self,
        command: &crate::command::ApiCommand,
    ) -> crate::error::CallResult<Dispatch> {
        let crate::command::ApiCommand::Revise {
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
        } = command
        else {
            return Err(crate::error::ApiError::invalid(
                "revise dispatch receives a revise command",
            ));
        };
        let mut workspace = self.open()?;
        let current = self.assertion_at(&workspace, *base, *assertion)?;
        let (kind, lifecycle, outcome) = revise_action(action);
        check_transition(current.assertion_lifecycle(), lifecycle)?;
        let decision_draft = mneme_memory::build_decision(
            *decision,
            *decision_revision,
            scope,
            mneme_memory::DecisionOptions {
                kind,
                target: *assertion,
                actor: &self.session.principal,
                policy: "agent-api/v1",
                input_revision: *base,
                outcome,
                rationale,
                evidence: &[],
                related: &[],
            },
        );
        let superseded = superseded_by
            .map(|target| mneme_core::Reference::local(target, mneme_core::RecordKind::Assertion));
        let revised = mneme_memory::build_assertion_revision(
            &current,
            *revised_revision,
            lifecycle,
            mneme_core::Reference::local(*decision, mneme_core::RecordKind::Decision),
            superseded,
        );
        let batch = mneme_memory::Batch {
            actor: self.session.principal.clone(),
            scope: scope.clone(),
            idempotency_key: key.clone(),
            records: vec![decision_draft, revised],
            source_blobs: Vec::new(),
            publications: Vec::new(),
        };
        let outcome = self
            .memory(&mut workspace)
            .commit_at_base(batch, *base)
            .map_err(crate::error::ApiError::from_memory)?;
        Ok(Dispatch::ok(
            commit_value(&outcome),
            Some(self.context(scope, &outcome)),
        ))
    }

    fn dispatch_resume(
        &self,
        command: &crate::command::ApiCommand,
    ) -> crate::error::CallResult<Dispatch> {
        let crate::command::ApiCommand::Resume {
            scope, checkpoint, ..
        } = command
        else {
            return Err(crate::error::ApiError::invalid(
                "resume dispatch receives a resume command",
            ));
        };
        let mut workspace = self.open()?;
        let (view, generation) = self.pinned_view(&mut workspace)?;
        let record = self.visible_record(&view, &workspace, *checkpoint)?;
        if record.kind != mneme_core::RecordKind::Checkpoint {
            return Err(member_refusal(
                payload_member("checkpoint"),
                "requested record is not a checkpoint",
            ));
        }
        let value = resume_value(&view, &workspace, &record, scope)?;
        Ok(Dispatch::ok(
            value,
            Some(Context {
                revision: view.revision(),
                scope: scope.clone(),
                generation,
            }),
        ))
    }

    fn dispatch_image(
        &self,
        command: &crate::command::ApiCommand,
    ) -> crate::error::CallResult<Dispatch> {
        let crate::command::ApiCommand::ImageRead {
            scope,
            source,
            source_revision,
            revision,
            ..
        } = command
        else {
            return Err(crate::error::ApiError::invalid(
                "image dispatch requires an image read",
            ));
        };
        let mut workspace = self.open()?;
        let image = mneme_doc::images::load(
            &mut workspace,
            scope,
            mneme_doc::SourcePin {
                source: *source,
                revision: *source_revision,
            },
            *revision,
        )
        .map_err(|_| crate::error::ApiError::missing())?;
        let context = Context {
            revision: image.workspace_revision,
            scope: scope.clone(),
            generation: image.generation,
        };
        let value = image_value(image);
        if workspace
            .eligibility_generation()
            .map_err(crate::error::ApiError::from_store)?
            != context.generation
        {
            return Err(crate::error::ApiError::new(
                crate::error::ApiErrorCode::Conflict,
                "eligibility barrier advanced during image read",
            ));
        }
        Ok(Dispatch::ok(value, Some(context)))
    }

    fn dispatch_forget(
        &self,
        command: &crate::command::ApiCommand,
    ) -> crate::error::CallResult<Dispatch> {
        let crate::command::ApiCommand::Forget {
            scope,
            base,
            key,
            selector,
            effective,
            ..
        } = command
        else {
            return Err(crate::error::ApiError::invalid(
                "forget dispatch receives a forget command",
            ));
        };
        let mut workspace = self.open()?;
        let request = mneme_retention::Request {
            actor: self.session.principal.clone(),
            scope: scope.clone(),
            base_revision: *base,
            idempotency_key: key.clone(),
            operation: mneme_retention::OperationKind::Forget,
            selector: selector.clone(),
            effective: *effective,
            policy: mneme_retention::Policy {
                version: mneme_retention::POLICY_VERSION.to_owned(),
                retain_assertion_after_prune: true,
                block_content_replay: true,
                retain_withdrawn_evidence_metadata: true,
            },
        };
        let executed = mneme_retention::Engine::new(&mut workspace).execute(request);
        let result = match executed {
            Ok(result) => result,
            Err(mneme_retention::PolicyError::NotFound) => {
                return Err(match selector_target(selector) {
                    Some(target) if self.forgotten(&workspace, target) => {
                        crate::error::ApiError::forgotten()
                    }
                    _ => crate::error::ApiError::from_retention(
                        mneme_retention::PolicyError::NotFound,
                    ),
                });
            }
            Err(error) => return Err(crate::error::ApiError::from_retention(error)),
        };
        let audit = mneme_retention::Engine::new(&mut workspace)
            .audit(&result.operation_id)
            .map_err(crate::error::ApiError::from_retention)?;
        // The receipt names the revision that committed the barrier, so a
        // retry after unrelated commits reports the same context revision.
        let operation = workspace
            .retention_operation(&result.operation_id)
            .map_err(crate::error::ApiError::from_store)?
            .ok_or_else(|| {
                crate::error::ApiError::new(
                    crate::error::ApiErrorCode::Failed,
                    "retention operation is unavailable",
                )
            })?;
        let status = forget_status(result.state);
        Ok(Dispatch::qualified(
            forget_value(&result, &audit, operation.outcome_revision),
            Some(Context {
                revision: operation.outcome_revision,
                scope: scope.clone(),
                generation: result.generation,
            }),
            status,
        ))
    }

    fn dispatch_proposal_inspect(
        &self,
        command: &crate::command::ApiCommand,
    ) -> crate::error::CallResult<Dispatch> {
        let crate::command::ApiCommand::ProposalInspect {
            scope, assertion, ..
        } = command
        else {
            return Err(crate::error::ApiError::invalid(
                "proposal inspection dispatch receives its command",
            ));
        };
        let mut workspace = self.open()?;
        let (view, generation) = self.pinned_view(&mut workspace)?;
        let record = self.visible_record(&view, &workspace, *assertion)?;
        if record.kind != mneme_core::RecordKind::Assertion {
            return Err(member_refusal(
                payload_member("assertion"),
                "requested record is not an assertion",
            ));
        }
        let assertion = view
            .assertion(*assertion)
            .map_err(crate::error::ApiError::from_memory)?;
        Ok(Dispatch::ok(
            assertion_value(&assertion),
            Some(Context {
                revision: view.revision(),
                scope: scope.clone(),
                generation,
            }),
        ))
    }

    /// One record the caller may read from `view`.
    fn visible_record(
        &self,
        view: &mneme_memory::View,
        workspace: &mneme_store::Workspace,
        record: mneme_core::RecordId,
    ) -> crate::error::CallResult<mneme_core::RecordEnvelope> {
        match view.record(record) {
            Ok(envelope) if self.allows(&envelope.scope) => Ok(envelope.clone()),
            Ok(_) | Err(mneme_memory::EvidenceError::Missing { .. }) => {
                Err(self.absent_error(workspace, record))
            }
            Err(error) => Err(crate::error::ApiError::from_memory(error)),
        }
    }

    /// The answer for a record id the caller cannot resolve.
    fn absent_error(
        &self,
        workspace: &mneme_store::Workspace,
        record: mneme_core::RecordId,
    ) -> crate::error::ApiError {
        if self.forgotten(workspace, record) {
            crate::error::ApiError::forgotten()
        } else {
            crate::error::ApiError::missing()
        }
    }

    /// Whether an authorized forget covers this target.
    fn forgotten(&self, workspace: &mneme_store::Workspace, record: mneme_core::RecordId) -> bool {
        let Ok(suppressions) = workspace.active_suppressions() else {
            return false;
        };
        suppressions
            .iter()
            .filter(|suppression| {
                suppression.target == record
                    && suppression.mode == mneme_store::SuppressionMode::Forgotten
            })
            .filter_map(|suppression| {
                workspace
                    .retention_operation(&suppression.operation_id)
                    .ok()
                    .flatten()
            })
            .any(|operation| self.allows(&operation.scope))
    }

    /// The assertion record as of the caller's base revision.
    ///
    /// A retry of a committed command rebuilds exactly the drafts it sent the
    /// first time, so the memory engine replays its recorded outcome before it
    /// validates anything.
    fn assertion_at(
        &self,
        workspace: &mneme_store::Workspace,
        base: mneme_core::WorkspaceRevisionId,
        assertion: mneme_core::RecordId,
    ) -> crate::error::CallResult<mneme_core::RecordEnvelope> {
        let base_revisions = std::collections::BTreeSet::from([base]);
        let is_committed = workspace
            .revision_sequences_for(&base_revisions)
            .map_err(crate::error::ApiError::from_store)?
            .contains_key(&base);
        if !is_committed {
            return Err(crate::error::ApiError::new(
                crate::error::ApiErrorCode::Conflict,
                "base revision is not current",
            ));
        }
        let snapshot = workspace
            .snapshot_at(base, None)
            .map_err(crate::error::ApiError::from_store)?;
        if let Some(record) = snapshot
            .records
            .iter()
            .find(|record| record.record_id == assertion)
        {
            if !self.allows(&record.scope) {
                return Err(self.absent_error(workspace, assertion));
            }
            if record.kind != mneme_core::RecordKind::Assertion {
                return Err(member_refusal(
                    payload_member("assertion"),
                    "requested record is not an assertion",
                ));
            }
            return Ok(record.clone());
        }
        let current = workspace
            .current_revision()
            .map_err(crate::error::ApiError::from_store)?;
        if current != base {
            return Err(crate::error::ApiError::new(
                crate::error::ApiErrorCode::Conflict,
                "base revision is not current",
            ));
        }
        Err(self.absent_error(workspace, assertion))
    }

    fn open(&self) -> crate::error::CallResult<mneme_store::Workspace> {
        let config = mneme_store::WorkspaceConfig::new(
            Box::new(mneme_store::SystemClock),
            Box::new(mneme_store::NoFaults),
        );
        let root = &self.session.workspace_root;
        let opened = match &self.record_cache {
            Some(cache) => mneme_store::Workspace::open_with_cache(root, config, cache.clone()),
            None => mneme_store::Workspace::open(root, config),
        };
        opened.map_err(crate::error::ApiError::from_store)
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

/// Whether a memory failure is an eligibility barrier change.
fn barrier_advanced(error: &mneme_memory::EvidenceError) -> bool {
    matches!(
        error,
        mneme_memory::EvidenceError::Store(mneme_store::Failure::BarrierAdvanced { .. })
    )
}

/// Refuse record kinds and revisions that only accept or revise may commit.
fn refuse_forbidden_record(
    index: usize,
    record: &mneme_core::RecordEnvelope,
) -> crate::error::CallResult<()> {
    if record.kind == mneme_core::RecordKind::Decision {
        return Err(member_refusal(
            record_member(index, "kind"),
            "decision records are committed only through accept or revise",
        ));
    }
    if record.kind != mneme_core::RecordKind::Assertion {
        return Ok(());
    }
    if record.payload.get("decision").is_some() {
        return Err(member_refusal(
            record_member(index, "decision"),
            "a lifecycle-changing assertion revision is committed only through accept or revise",
        ));
    }
    match record
        .payload
        .get("lifecycle")
        .and_then(mneme_core::Value::as_symbol)
        .map(mneme_core::Symbol::as_str)
    {
        Some("proposed") => Ok(()),
        _ => Err(member_refusal(
            record_member(index, "lifecycle"),
            "recorded assertions must be proposed; accept or revise changes lifecycle",
        )),
    }
}

/// The parts of a recall command that do not change with the served revision.
struct RecallSelection {
    scope: mneme_core::ScopeId,
    /// The revision the caller pinned, if any.
    pinned: Option<mneme_core::WorkspaceRevisionId>,
    modes: std::collections::BTreeSet<mneme_recall::Mode>,
    structured: Option<mneme_recall::StructuredRequest>,
}

/// A refusal addressed at one member of the command payload.
fn member_refusal(path: mneme_core::Path, message: impl Into<String>) -> crate::error::ApiError {
    let message = message.into();
    crate::error::ApiError::new(crate::error::ApiErrorCode::InvalidInput, message.clone())
        .with_diagnostic(mneme_core::Diagnostic::new(
            mneme_core::Stage::Envelope,
            mneme_core::ErrorCode::TypeMismatch,
            path,
            message,
        ))
}

fn payload_member(member: &'static str) -> mneme_core::Path {
    mneme_core::Path::root().field("payload").field(member)
}

fn record_member(index: usize, member: &'static str) -> mneme_core::Path {
    mneme_core::Path::root()
        .field("payload")
        .field("records")
        .index(index)
        .field(member)
}

/// Require that the memory lifecycle rule permits this transition.
fn check_transition(
    from: Option<mneme_core::Lifecycle>,
    next: mneme_core::Lifecycle,
) -> crate::error::CallResult<()> {
    let is_allowed = mneme_kernel::claim::transition_allowed(
        from.map(mneme_core::Lifecycle::to_kernel),
        next.to_kernel(),
    );
    if is_allowed {
        return Ok(());
    }
    Err(not_permitted(from, next))
}

/// Acceptance is exactly the transition from a proposal.
///
/// The kernel permits later non-proposed revisions, but a claim is accepted
/// once: re-accepting an accepted, disputed or retracted claim would accumulate
/// decisions without reaching an eligible state.
fn check_accept_state(from: Option<mneme_core::Lifecycle>) -> crate::error::CallResult<()> {
    if from == Some(mneme_core::Lifecycle::Proposed) {
        Ok(())
    } else {
        Err(not_permitted(from, mneme_core::Lifecycle::Accepted))
    }
}

fn not_permitted(
    from: Option<mneme_core::Lifecycle>,
    next: mneme_core::Lifecycle,
) -> crate::error::ApiError {
    crate::error::ApiError::new(
        crate::error::ApiErrorCode::Conflict,
        format!(
            "lifecycle transition from {} to {} is not permitted",
            from.map_or("absent", mneme_core::Lifecycle::symbol),
            next.symbol()
        ),
    )
}

fn revise_action(
    action: &crate::command::ReviseAction,
) -> (
    mneme_memory::DecisionKind,
    mneme_core::Lifecycle,
    &'static str,
) {
    match action {
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
    }
}

/// Resolve one rule bundle reference under the workspace root.
fn bundle_from_path(
    workspace: &mneme_store::Workspace,
    path: &str,
) -> crate::error::CallResult<mneme_datalog::RuleBundle> {
    let reference = payload_member("structured").field("bundle-path");
    let root = std::fs::canonicalize(workspace.root()).map_err(|_| {
        member_refusal(
            reference.clone(),
            "cannot resolve the rule bundle reference",
        )
    })?;
    let resolved = std::fs::canonicalize(root.join(path)).map_err(|_| {
        member_refusal(
            reference.clone(),
            "cannot resolve the rule bundle reference",
        )
    })?;
    if !resolved.starts_with(&root) {
        return Err(member_refusal(
            reference.clone(),
            "rule bundle reference is outside the workspace",
        ));
    }
    let text = std::fs::read_to_string(&resolved)
        .map_err(|_| member_refusal(reference, "cannot read the rule bundle reference"))?;
    let value =
        mneme_core::decode_document(&text).map_err(crate::error::ApiError::from_diagnostic)?;
    crate::command::parse_bundle(&value, &mneme_core::Path::root())
}

/// The record a selector names, when it names one identity.
fn selector_target(selector: &mneme_retention::Selector) -> Option<mneme_core::RecordId> {
    match selector {
        mneme_retention::Selector::Source(record)
        | mneme_retention::Selector::SourceSupport(record)
        | mneme_retention::Selector::Assertion(record)
        | mneme_retention::Selector::SourceRevision(record, _) => Some(*record),
        mneme_retention::Selector::Content(_) => None,
    }
}

#[derive(Clone, Debug)]
struct Context {
    revision: mneme_core::WorkspaceRevisionId,
    scope: mneme_core::ScopeId,
    generation: u64,
}

fn response_for_error(
    command: &crate::command::ApiCommand,
    error: crate::error::ApiError,
) -> CallResponse {
    CallResponse {
        value: response_envelope(
            command,
            error.code.as_str(),
            None,
            none_value(),
            Some(&error),
        ),
        ok: false,
    }
}

#[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
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
        entries.push((mneme_core::Value::symbol("context"), context_value(context)));
    }
    if let Some(error) = error {
        entries.push((mneme_core::Value::symbol("error"), error_value(error)));
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

fn context_value(context: &Context) -> mneme_core::Value {
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
    ])
}

fn error_value(error: &crate::error::ApiError) -> mneme_core::Value {
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
            diagnostics_value(&error_diagnostics(error)),
        ),
    ])
}

/// The diagnostics a public error document carries.
///
/// A malformed request or an incompatible document always carries at least one
/// field-addressed entry. When the underlying refusal named no member, the
/// command payload root is the only address the adapter can honestly give;
/// inventing a finer one would point at a place that did not fail.
fn error_diagnostics(error: &crate::error::ApiError) -> Vec<mneme_core::Diagnostic> {
    if !error.diagnostics.is_empty() {
        return error.diagnostics.clone();
    }
    let (stage, code) = match error.code {
        crate::error::ApiErrorCode::InvalidInput => (
            mneme_core::Stage::Domain,
            mneme_core::ErrorCode::TypeMismatch,
        ),
        crate::error::ApiErrorCode::UnsupportedVersion => (
            mneme_core::Stage::Envelope,
            mneme_core::ErrorCode::UnsupportedSchemaVersion,
        ),
        _ => return Vec::new(),
    };
    vec![mneme_core::Diagnostic::new(
        stage,
        code,
        mneme_core::Path::root().field("payload"),
        error.message.clone(),
    )]
}

/// One diagnostic as a client-readable entry: class, address and detail.
fn diagnostics_value(diagnostics: &[mneme_core::Diagnostic]) -> mneme_core::Value {
    mneme_core::Value::sequence(
        diagnostics
            .iter()
            .map(|diagnostic| {
                mneme_core::Value::symbol_dictionary([
                    (
                        mneme_core::Symbol::from("code"),
                        mneme_core::Value::symbol(diagnostic.code.as_str()),
                    ),
                    (
                        mneme_core::Symbol::from("stage"),
                        mneme_core::Value::symbol(diagnostic.stage.as_str()),
                    ),
                    (
                        mneme_core::Symbol::from("path"),
                        mneme_core::Value::string(diagnostic.path.to_string()),
                    ),
                    (
                        mneme_core::Symbol::from("message"),
                        mneme_core::Value::string(diagnostic.message.clone()),
                    ),
                ])
            })
            .collect(),
    )
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
            mneme_core::Value::symbol(stance_name(assertion.stance)),
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

fn stance_name(stance: mneme_memory::Stance) -> &'static str {
    match stance {
        mneme_memory::Stance::Affirm => "affirm",
        mneme_memory::Stance::Deny => "deny",
        mneme_memory::Stance::Hypothesis => "hypothesis",
    }
}

fn support_relation_name(relation: mneme_memory::SupportRelation) -> &'static str {
    match relation {
        mneme_memory::SupportRelation::Supports => "supports",
        mneme_memory::SupportRelation::Challenges => "challenges",
    }
}

/// The transport status of a completed recall execution.
fn execution_status(status: mneme_recall::Execution) -> &'static str {
    match status {
        mneme_recall::Execution::Complete => STATUS_OK,
        mneme_recall::Execution::Partial => "partial",
        mneme_recall::Execution::Timeout => "timeout",
        mneme_recall::Execution::Cancelled => "cancelled",
        mneme_recall::Execution::Failed => "failed",
    }
}

/// The transport status of a retention cleanup state.
fn forget_status(state: mneme_store::RetentionJobState) -> &'static str {
    match state {
        mneme_store::RetentionJobState::Complete => STATUS_OK,
        mneme_store::RetentionJobState::Partial => "partial",
        mneme_store::RetentionJobState::Failed => "failed",
        mneme_store::RetentionJobState::BarrierCommitted
        | mneme_store::RetentionJobState::CleanupPending => "partial",
    }
}

#[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
fn recall_value(response: &mneme_recall::Response) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("context"),
            recall_context_value(response),
        ),
        (
            mneme_core::Symbol::from("budget"),
            budget_value(&response.budget, response.status),
        ),
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
            recall_omissions_value(response),
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
            recall_boundary_value(response),
        ),
    ])
}

fn recall_context_value(response: &mneme_recall::Response) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("schema-version"),
            mneme_core::Value::integer(response.context.schema_version),
        ),
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
            mneme_core::Symbol::from("current-revision"),
            response.context.current_revision.to_value(),
        ),
        (
            mneme_core::Symbol::from("stale"),
            mneme_core::Value::Boolean(response.context.stale),
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
            mneme_core::Symbol::from("at"),
            mneme_core::Value::string(response.context.at.to_rfc3339()),
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
    ])
}

fn recall_omissions_value(response: &mneme_recall::Response) -> mneme_core::Value {
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
    )
}

fn recall_boundary_value(response: &mneme_recall::Response) -> mneme_core::Value {
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
    ])
}

/// The recall budget: one entry per limit the request carries.
///
/// The document must be the same for one command on one workspace whatever
/// transport executed it, so no entry reports a measured duration: the item,
/// context, excerpt and work entries carry deterministic `used` and `allowed`
/// amounts, and `time-ms` carries the limit with whether the response
/// exhausted it, which follows from the execution status rather than from a
/// clock reading. Elapsed time stays available to in-process callers through
/// `mneme_recall::BudgetUse` and never enters the document.
fn budget_value(
    budget: &mneme_recall::BudgetUse,
    status: mneme_recall::Execution,
) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("items"),
            limit_use_value(budget.items_used, budget.items_allowed),
        ),
        (
            mneme_core::Symbol::from("context-bytes"),
            limit_use_value(budget.text_bytes_used, budget.text_bytes_allowed),
        ),
        (
            mneme_core::Symbol::from("quote-bytes"),
            limit_use_value(budget.excerpt_bytes_used, budget.excerpt_bytes_allowed),
        ),
        (
            mneme_core::Symbol::from("time-ms"),
            time_limit_value(budget.elapsed_ms_allowed, status),
        ),
        (
            mneme_core::Symbol::from("work"),
            limit_use_value(budget.work_used, budget.work_allowed),
        ),
    ])
}

/// One limit's used and allowed amounts.
fn limit_use_value(used: u64, allowed: u64) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("used"),
            mneme_core::Value::integer(used),
        ),
        (
            mneme_core::Symbol::from("allowed"),
            mneme_core::Value::integer(allowed),
        ),
    ])
}

/// The time limit the request carried, and whether this response ran out of it.
fn time_limit_value(allowed: u64, status: mneme_recall::Execution) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("allowed"),
            mneme_core::Value::integer(allowed),
        ),
        (
            mneme_core::Symbol::from("exhausted"),
            mneme_core::Value::Boolean(status == mneme_recall::Execution::Timeout),
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
            mneme_core::Symbol::from("index-version"),
            mode.index_version
                .as_ref()
                .map(|version| mneme_core::Value::string(version.clone()))
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("relation-exhaustive"),
            mode.relation_exhaustive
                .map(mneme_core::Value::Boolean)
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("reason"),
            mode.reason
                .as_ref()
                .map(|reason| mneme_core::Value::string(reason.clone()))
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("coverage"),
            coverage_value(&mode.coverage),
        ),
        (
            mneme_core::Symbol::from("candidates"),
            mneme_core::Value::integer(mode.candidates),
        ),
    ])
}

fn coverage_value(coverage: &mneme_recall::IndexCoverage) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("complete"),
            mneme_core::Value::Boolean(coverage.complete),
        ),
        (
            mneme_core::Symbol::from("documents-indexed"),
            mneme_core::Value::integer(coverage.documents_indexed),
        ),
        (
            mneme_core::Symbol::from("documents-skipped"),
            mneme_core::Value::integer(coverage.documents_skipped),
        ),
        (
            mneme_core::Symbol::from("reason"),
            coverage
                .reason
                .as_ref()
                .map(|reason| mneme_core::Value::string(reason.clone()))
                .unwrap_or_else(none_value),
        ),
    ])
}

fn candidate_value(candidate: &mneme_recall::Candidate) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary(
        candidate_identity_entries(candidate)
            .into_iter()
            .chain(candidate_reference_entries(candidate))
            .chain(candidate_support_entries(candidate)),
    )
}

/// The identity and text of one candidate, before its references.
fn candidate_identity_entries(
    candidate: &mneme_recall::Candidate,
) -> [(mneme_core::Symbol, mneme_core::Value); 5] {
    [
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
    ]
}

/// The records and span one candidate cites, as `none` when it cites none.
fn candidate_reference_entries(
    candidate: &mneme_recall::Candidate,
) -> [(mneme_core::Symbol, mneme_core::Value); 8] {
    let (source, source_revision, span) = candidate_source_values(candidate);
    [
        (mneme_core::Symbol::from("source"), source),
        (mneme_core::Symbol::from("source-revision"), source_revision),
        (mneme_core::Symbol::from("span"), span),
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
            mneme_core::Symbol::from("entity"),
            candidate
                .entity
                .map(mneme_core::RecordId::to_value)
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("claim-status"),
            candidate
                .claim_status
                .as_ref()
                .map(claim_status_value)
                .unwrap_or_else(none_value),
        ),
    ]
}

/// The ranking and provenance of one candidate.
fn candidate_support_entries(
    candidate: &mneme_recall::Candidate,
) -> [(mneme_core::Symbol, mneme_core::Value); 7] {
    let (origins, evidence, derivations) = candidate_provenance_values(candidate);
    let ancestry_roots = candidate_ancestry_roots_value(candidate);
    [
        (
            mneme_core::Symbol::from("independent-support"),
            mneme_core::Value::Boolean(candidate.independent_support),
        ),
        (
            mneme_core::Symbol::from("support-limited"),
            mneme_core::Value::Boolean(candidate.support_limited),
        ),
        (mneme_core::Symbol::from("origins"), origins),
        (
            mneme_core::Symbol::from("score"),
            mneme_core::Value::double(candidate.score),
        ),
        (mneme_core::Symbol::from("evidence"), evidence),
        (mneme_core::Symbol::from("derivations"), derivations),
        (mneme_core::Symbol::from("ancestry-roots"), ancestry_roots),
    ]
}

fn claim_status_value(status: &mneme_recall::ClaimStatus) -> mneme_core::Value {
    // Both fields hold enum names derived from the lifecycle and stance
    // vocabularies, so they are encoded as symbols like every other enum in a
    // result document; a client compares `#accepted` rather than text.
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("lifecycle"),
            mneme_core::Value::symbol(status.lifecycle.clone()),
        ),
        (
            mneme_core::Symbol::from("stance"),
            mneme_core::Value::symbol(status.stance.clone()),
        ),
        (
            mneme_core::Symbol::from("valid-time"),
            status.valid_time.to_value(),
        ),
        (
            mneme_core::Symbol::from("recorded"),
            status.recorded.to_value(),
        ),
        (
            mneme_core::Symbol::from("superseded-by"),
            status
                .superseded_by
                .map(mneme_core::RecordId::to_value)
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("decision"),
            status
                .decision
                .map(mneme_core::RecordId::to_value)
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("asserted-by"),
            mneme_core::Value::string(status.asserted_by.clone()),
        ),
    ])
}

fn candidate_source_values(
    candidate: &mneme_recall::Candidate,
) -> (mneme_core::Value, mneme_core::Value, mneme_core::Value) {
    (
        candidate
            .source
            .map(mneme_core::RecordId::to_value)
            .unwrap_or_else(none_value),
        candidate
            .source_revision
            .map(mneme_core::RevisionId::to_value)
            .unwrap_or_else(none_value),
        candidate
            .span
            .map(mneme_core::SourceSpan::to_value)
            .unwrap_or_else(none_value),
    )
}

fn candidate_provenance_values(
    candidate: &mneme_recall::Candidate,
) -> (mneme_core::Value, mneme_core::Value, mneme_core::Value) {
    let origins = mneme_core::Value::sequence(
        candidate
            .origins
            .iter()
            .map(|mode| mneme_core::Value::symbol(mode.name()))
            .collect(),
    );
    let evidence = mneme_core::Value::sequence(
        candidate
            .evidence
            .iter()
            .map(recall_evidence_value)
            .collect(),
    );
    let derivations =
        mneme_core::Value::sequence(candidate.derivations.iter().map(derivation_value).collect());
    (origins, evidence, derivations)
}

fn candidate_ancestry_roots_value(candidate: &mneme_recall::Candidate) -> mneme_core::Value {
    ancestry_roots_value(&candidate.ancestry_roots)
}

fn ancestry_roots_value(
    roots: &std::collections::BTreeSet<(mneme_core::RecordId, mneme_core::RevisionId)>,
) -> mneme_core::Value {
    mneme_core::Value::sequence(
        roots
            .iter()
            .map(|(record, revision)| {
                mneme_core::Value::sequence(vec![record.to_value(), revision.to_value()])
            })
            .collect(),
    )
}

fn recall_evidence_value(evidence: &mneme_recall::Evidence) -> mneme_core::Value {
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
        (
            mneme_core::Symbol::from("relation"),
            mneme_core::Value::symbol(support_relation_name(evidence.relation)),
        ),
        (
            mneme_core::Symbol::from("withdrawn"),
            mneme_core::Value::Boolean(evidence.withdrawn),
        ),
        (
            mneme_core::Symbol::from("eligible"),
            mneme_core::Value::Boolean(evidence.eligible),
        ),
        (
            mneme_core::Symbol::from("ancestry-roots"),
            ancestry_roots_value(&evidence.ancestry_roots),
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
                            (
                                mneme_core::Symbol::from("absent"),
                                mneme_core::Value::Boolean(premise.absent),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

fn explain_value(explanation: &mneme_memory::Explanation) -> mneme_core::Value {
    let evidence = explanation_evidence_value(explanation);
    // A cut excerpt is a cut citation: the explanation is truncated when any
    // quotation in it was shortened, not only when the node bound was hit.
    let is_truncated = explanation.truncated
        || explanation.evidence.iter().any(|evidence| {
            evidence
                .excerpt
                .as_ref()
                .is_some_and(|excerpt| excerpt.truncated)
        });
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
            explanation_decisions_value(explanation),
        ),
        (
            mneme_core::Symbol::from("inaccessible-decisions"),
            mneme_core::Value::integer(explanation.inaccessible_decisions),
        ),
        (mneme_core::Symbol::from("evidence"), evidence),
        (
            mneme_core::Symbol::from("derivations"),
            explanation_derivations_value(explanation),
        ),
        (
            mneme_core::Symbol::from("corroboration"),
            explanation_corroboration_value(explanation),
        ),
        (
            mneme_core::Symbol::from("truncated"),
            mneme_core::Value::Boolean(is_truncated),
        ),
        (
            mneme_core::Symbol::from("visited-nodes"),
            mneme_core::Value::integer(explanation.visited_nodes),
        ),
    ])
}

fn explanation_decisions_value(explanation: &mneme_memory::Explanation) -> mneme_core::Value {
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
                    (
                        mneme_core::Symbol::from("actor"),
                        mneme_core::Value::string(decision.actor.clone()),
                    ),
                    (
                        mneme_core::Symbol::from("policy"),
                        mneme_core::Value::string(decision.policy.clone()),
                    ),
                    (
                        mneme_core::Symbol::from("input-revision"),
                        decision.input_revision.to_value(),
                    ),
                ])
            })
            .collect(),
    )
}

fn explanation_evidence_value(explanation: &mneme_memory::Explanation) -> mneme_core::Value {
    mneme_core::Value::sequence(
        explanation
            .evidence
            .iter()
            .map(explanation_evidence_entry)
            .collect(),
    )
}

fn explanation_evidence_entry(evidence: &mneme_memory::EvidenceExplanation) -> mneme_core::Value {
    if evidence.inaccessible {
        // Identities, spans and bytes of an unreadable item are withheld, so the
        // report says only that one item exists.
        return mneme_core::Value::symbol_dictionary([(
            mneme_core::Symbol::from("inaccessible"),
            mneme_core::Value::Boolean(true),
        )]);
    }
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
            mneme_core::Symbol::from("span-start"),
            evidence
                .span_start
                .map(mneme_core::Value::integer)
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("span-end"),
            evidence
                .span_end
                .map(mneme_core::Value::integer)
                .unwrap_or_else(none_value),
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
            mneme_core::Symbol::from("excerpt-truncated"),
            mneme_core::Value::Boolean(
                evidence
                    .excerpt
                    .as_ref()
                    .is_some_and(|excerpt| excerpt.truncated),
            ),
        ),
        (
            mneme_core::Symbol::from("ancestry-roots"),
            ancestry_roots_value(&evidence.ancestry_roots),
        ),
        (
            mneme_core::Symbol::from("withdrawn"),
            mneme_core::Value::Boolean(evidence.withdrawn),
        ),
        (
            mneme_core::Symbol::from("eligible"),
            mneme_core::Value::Boolean(evidence.eligible),
        ),
    ])
}

fn explanation_derivations_value(explanation: &mneme_memory::Explanation) -> mneme_core::Value {
    mneme_core::Value::sequence(
        explanation
            .derivations
            .iter()
            .map(|derivation| {
                mneme_core::Value::symbol_dictionary([
                    (
                        mneme_core::Symbol::from("derivation"),
                        derivation.derivation.to_value(),
                    ),
                    (
                        mneme_core::Symbol::from("rule-id"),
                        mneme_core::Value::string(derivation.rule_id.clone()),
                    ),
                    (
                        mneme_core::Symbol::from("rule-version"),
                        mneme_core::Value::integer(derivation.rule_version),
                    ),
                    (
                        mneme_core::Symbol::from("eligible"),
                        mneme_core::Value::Boolean(derivation.eligible),
                    ),
                    (
                        mneme_core::Symbol::from("reasons"),
                        mneme_core::Value::sequence(
                            derivation
                                .reasons
                                .iter()
                                .map(|reason| mneme_core::Value::string(reason.clone()))
                                .collect(),
                        ),
                    ),
                ])
            })
            .collect(),
    )
}

fn explanation_corroboration_value(explanation: &mneme_memory::Explanation) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("roots"),
            ancestry_roots_value(&explanation.corroboration.roots),
        ),
        (
            mneme_core::Symbol::from("independent-supports"),
            mneme_core::Value::integer(explanation.corroboration.independent_supports),
        ),
        (
            mneme_core::Symbol::from("shared-ancestry"),
            mneme_core::Value::Boolean(explanation.corroboration.shared_ancestry),
        ),
    ])
}

/// Planned, attempted, observed and concluded work recorded by a checkpoint.
struct ResumeCollections {
    planned: Vec<mneme_core::Value>,
    episodes: Vec<mneme_core::Value>,
    attempts: Vec<mneme_core::Value>,
    observations: Vec<mneme_core::Value>,
    outcomes: Vec<mneme_core::Value>,
    pending: Vec<mneme_core::Value>,
    unresolved: Vec<mneme_core::Value>,
    uncertainties: Vec<mneme_core::Value>,
    preconditions: Vec<mneme_core::Value>,
    precondition_changed: bool,
}

struct ResumePayload<'a> {
    checkpoint: mneme_core::RecordId,
    checkpoint_revision: mneme_core::WorkspaceRevisionId,
    commit_revision: Option<mneme_core::WorkspaceRevisionId>,
    revisions_after: u64,
    current: mneme_core::WorkspaceRevisionId,
    goal: &'a str,
    state: &'a str,
    note: Option<&'a str>,
    collections: ResumeCollections,
    verified: &'a std::collections::BTreeSet<mneme_core::RecordId>,
}

#[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
fn resume_value(
    view: &mneme_memory::View,
    workspace: &mneme_store::Workspace,
    record: &mneme_core::RecordEnvelope,
    scope: &mneme_core::ScopeId,
) -> crate::error::CallResult<mneme_core::Value> {
    let checkpoint = record.record_id;
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
        .map(mneme_core::Symbol::as_str)
        .unwrap_or("unknown");
    let note = record
        .payload
        .get("note")
        .and_then(mneme_core::Value::as_string);
    // The record's assignment order is its commit sequence, so the revision
    // carrying that sequence is the revision that committed the checkpoint.
    let order = record.recorded.revision_order();
    let commit_revision = workspace
        .revision_at_sequence(order)
        .map_err(crate::error::ApiError::from_store)?;
    let revisions_after = view.snapshot().sequence.saturating_sub(order);
    let collections = resume_collections(view, &episode_ids, &verified, scope, order)?;
    Ok(resume_payload_value(ResumePayload {
        checkpoint,
        checkpoint_revision,
        commit_revision,
        revisions_after,
        current: view.revision(),
        goal,
        state,
        note,
        collections,
        verified: &verified,
    }))
}

fn resume_collections(
    view: &mneme_memory::View,
    episode_ids: &std::collections::BTreeSet<mneme_core::RecordId>,
    verified: &std::collections::BTreeSet<mneme_core::RecordId>,
    scope: &mneme_core::ScopeId,
    checkpoint_order: u64,
) -> crate::error::CallResult<ResumeCollections> {
    let capacity = episode_ids.len();
    let mut collections = ResumeCollections {
        planned: Vec::with_capacity(capacity),
        episodes: Vec::with_capacity(capacity),
        attempts: Vec::with_capacity(capacity),
        observations: Vec::with_capacity(capacity),
        outcomes: Vec::with_capacity(capacity),
        pending: Vec::new(),
        unresolved: Vec::new(),
        uncertainties: Vec::new(),
        preconditions: Vec::new(),
        precondition_changed: false,
    };
    for episode_id in episode_ids {
        let episode = authorized_episode(view, *episode_id, scope)?;
        let entry = episode_value(&episode);
        match episode.episode_type {
            mneme_memory::EpisodeType::Intent => collections.planned.push(entry.clone()),
            mneme_memory::EpisodeType::Attempt => {
                if !verified.contains(episode_id) {
                    collections.unresolved.push(episode_id.to_value());
                    collections.uncertainties.push(uncertainty_value(&episode));
                }
                collections.attempts.push(entry.clone());
            }
            mneme_memory::EpisodeType::Observation => {
                collections
                    .preconditions
                    .push(precondition_value(&episode, "checkpoint"));
                collections.observations.push(entry.clone());
            }
            mneme_memory::EpisodeType::Outcome => collections.outcomes.push(entry.clone()),
            _ => {}
        }
        collections.episodes.push(entry);
    }
    for episode in newer_observations(view, episode_ids, scope, checkpoint_order)? {
        collections.precondition_changed = true;
        collections
            .preconditions
            .push(precondition_value(&episode, "newer"));
        collections.observations.push(episode_value(&episode));
    }
    for assertion in view
        .assertions()
        .map_err(crate::error::ApiError::from_memory)?
    {
        if assertion.lifecycle == mneme_core::Lifecycle::Proposed
            && &assertion.record.scope == scope
        {
            collections.pending.push(assertion_value(&assertion));
        }
    }
    Ok(collections)
}

/// One episode the checkpoint names, which must be in the resume scope.
fn authorized_episode(
    view: &mneme_memory::View,
    episode: mneme_core::RecordId,
    scope: &mneme_core::ScopeId,
) -> crate::error::CallResult<mneme_memory::EpisodeView> {
    let record = view
        .record(episode)
        .map_err(crate::error::ApiError::from_memory)?;
    if &record.scope != scope {
        return Err(crate::error::ApiError::denied());
    }
    view.episode(episode)
        .map_err(crate::error::ApiError::from_memory)
}

/// Observations committed after the checkpoint that it did not record.
fn newer_observations(
    view: &mneme_memory::View,
    known: &std::collections::BTreeSet<mneme_core::RecordId>,
    scope: &mneme_core::ScopeId,
    checkpoint_order: u64,
) -> crate::error::CallResult<Vec<mneme_memory::EpisodeView>> {
    let records = &view.snapshot().records;
    // Every observation is one of the records read here, so the snapshot
    // length bounds the result.
    let mut observations = Vec::with_capacity(records.len());
    for record in records {
        if record.kind != mneme_core::RecordKind::Episode
            || &record.scope != scope
            || known.contains(&record.record_id)
            || record.recorded.revision_order() <= checkpoint_order
        {
            continue;
        }
        let Ok(episode) = mneme_memory::EpisodeView::parse(record.clone()) else {
            continue;
        };
        if episode.episode_type == mneme_memory::EpisodeType::Observation {
            observations.push(episode);
        }
    }
    Ok(observations)
}

fn uncertainty_value(episode: &mneme_memory::EpisodeView) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("record-id"),
            episode.record.record_id.to_value(),
        ),
        (
            mneme_core::Symbol::from("reason"),
            mneme_core::Value::string("attempt has no verified outcome"),
        ),
        (
            mneme_core::Symbol::from("summary"),
            mneme_core::Value::string(episode.summary.clone()),
        ),
    ])
}

fn precondition_value(
    episode: &mneme_memory::EpisodeView,
    basis: &'static str,
) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("record-id"),
            episode.record.record_id.to_value(),
        ),
        (
            mneme_core::Symbol::from("summary"),
            mneme_core::Value::string(episode.summary.clone()),
        ),
        (
            mneme_core::Symbol::from("occurred"),
            episode.occurred.to_value(),
        ),
        (
            mneme_core::Symbol::from("basis"),
            mneme_core::Value::symbol(basis),
        ),
        (
            mneme_core::Symbol::from("verified"),
            mneme_core::Value::Boolean(basis == "checkpoint"),
        ),
    ])
}

fn resume_payload_value(payload: ResumePayload<'_>) -> mneme_core::Value {
    let ResumePayload {
        checkpoint,
        checkpoint_revision,
        commit_revision,
        revisions_after,
        current,
        goal,
        state,
        note,
        collections,
        verified,
    } = payload;
    // Staleness is measured from the revision that committed the checkpoint,
    // not from the revision it planned against, so resuming immediately after
    // the checkpoint reports no change.
    let is_revision_changed = commit_revision.unwrap_or(checkpoint_revision) != current;
    let checkpoint_entries = [
        (
            mneme_core::Symbol::from("checkpoint"),
            checkpoint.to_value(),
        ),
        (
            mneme_core::Symbol::from("checkpoint-revision"),
            checkpoint_revision.to_value(),
        ),
        (
            mneme_core::Symbol::from("checkpoint-commit-revision"),
            commit_revision
                .map(mneme_core::WorkspaceRevisionId::to_value)
                .unwrap_or_else(none_value),
        ),
        (
            mneme_core::Symbol::from("revisions-after-checkpoint"),
            mneme_core::Value::integer(revisions_after),
        ),
        (
            mneme_core::Symbol::from("current-revision"),
            current.to_value(),
        ),
        (
            mneme_core::Symbol::from("revision-changed"),
            mneme_core::Value::Boolean(is_revision_changed),
        ),
    ];
    mneme_core::Value::symbol_dictionary(
        checkpoint_entries
            .into_iter()
            .chain(resume_goal_entries(goal, state, note))
            .chain(resume_state_entries(collections, verified)),
    )
}

/// The plan a checkpoint names, which a resume repeats for the agent.
fn resume_goal_entries(
    goal: &str,
    state: &str,
    note: Option<&str>,
) -> [(mneme_core::Symbol, mneme_core::Value); 3] {
    [
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
    ]
}

/// The collected records a resume reports, each already rendered.
fn resume_state_entries(
    collections: ResumeCollections,
    verified: &std::collections::BTreeSet<mneme_core::RecordId>,
) -> [(mneme_core::Symbol, mneme_core::Value); 11] {
    [
        (
            mneme_core::Symbol::from("planned"),
            mneme_core::Value::sequence(collections.planned),
        ),
        (
            mneme_core::Symbol::from("episodes"),
            mneme_core::Value::sequence(collections.episodes),
        ),
        (
            mneme_core::Symbol::from("attempts"),
            mneme_core::Value::sequence(collections.attempts),
        ),
        (
            mneme_core::Symbol::from("observations"),
            mneme_core::Value::sequence(collections.observations),
        ),
        (
            mneme_core::Symbol::from("outcomes"),
            mneme_core::Value::sequence(collections.outcomes),
        ),
        (
            mneme_core::Symbol::from("pending-proposals"),
            mneme_core::Value::sequence(collections.pending),
        ),
        (
            mneme_core::Symbol::from("verified-outcomes"),
            mneme_core::Value::sequence(verified.iter().map(|record| record.to_value()).collect()),
        ),
        (
            mneme_core::Symbol::from("unresolved-attempts"),
            mneme_core::Value::sequence(collections.unresolved),
        ),
        (
            mneme_core::Symbol::from("uncertainties"),
            mneme_core::Value::sequence(collections.uncertainties),
        ),
        (
            mneme_core::Symbol::from("preconditions"),
            mneme_core::Value::sequence(collections.preconditions),
        ),
        (
            mneme_core::Symbol::from("precondition-changed"),
            mneme_core::Value::Boolean(collections.precondition_changed),
        ),
    ]
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

fn forget_value(
    result: &mneme_retention::Outcome,
    audit: &mneme_retention::Audit,
    outcome_revision: mneme_core::WorkspaceRevisionId,
) -> mneme_core::Value {
    let is_replay_prevention = result
        .retained_metadata
        .iter()
        .any(|entry| entry == "content-replay-block");
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("operation-id"),
            mneme_core::Value::string(result.operation_id.clone()),
        ),
        (
            mneme_core::Symbol::from("operation-kind"),
            mneme_core::Value::symbol(result.operation_kind.as_str()),
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
            mneme_core::Symbol::from("outcome-revision"),
            outcome_revision.to_value(),
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
            mneme_core::Symbol::from("replay-prevention"),
            mneme_core::Value::Boolean(is_replay_prevention),
        ),
        (
            mneme_core::Symbol::from("dependent-invalidation"),
            dependent_invalidation_value(audit),
        ),
        (
            mneme_core::Symbol::from("cleanup"),
            cleanup_value(&result.cleanup),
        ),
        (
            mneme_core::Symbol::from("locations"),
            mneme_core::Value::sequence(result.locations.iter().map(location_value).collect()),
        ),
        (
            mneme_core::Symbol::from("retained-metadata"),
            text_sequence(&result.retained_metadata),
        ),
        (
            mneme_core::Symbol::from("limitations"),
            text_sequence(&result.limitations),
        ),
    ])
}

/// What one forget invalidated among the records that depended on it.
fn dependent_invalidation_value(audit: &mneme_retention::Audit) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("suppressed-records"),
            mneme_core::Value::integer(audit.suppressed_records),
        ),
        (
            mneme_core::Symbol::from("selector-kinds"),
            text_sequence(&audit.selector_kinds),
        ),
    ])
}

/// One sequence holding each text, in order.
fn text_sequence(entries: &[String]) -> mneme_core::Value {
    mneme_core::Value::sequence(
        entries
            .iter()
            .map(|entry| mneme_core::Value::string(entry.clone()))
            .collect(),
    )
}

fn cleanup_value(cleanup: &mneme_retention::CleanupSummary) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("purged"),
            mneme_core::Value::integer(cleanup.purged),
        ),
        (
            mneme_core::Symbol::from("absent"),
            mneme_core::Value::integer(cleanup.absent),
        ),
        (
            mneme_core::Symbol::from("retained-shared"),
            mneme_core::Value::integer(cleanup.retained_shared),
        ),
        (
            mneme_core::Symbol::from("unavailable"),
            mneme_core::Value::integer(cleanup.unavailable),
        ),
        (
            mneme_core::Symbol::from("failed"),
            mneme_core::Value::integer(cleanup.failed),
        ),
        (
            mneme_core::Symbol::from("pending"),
            mneme_core::Value::integer(cleanup.pending),
        ),
    ])
}

/// One managed location's state, without its locator: a locator can carry a
/// workspace path or a digest that only the ledger needs.
fn location_value(location: &mneme_store::RetentionLocationStateRecord) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("kind"),
            mneme_core::Value::string(location.location_kind.clone()),
        ),
        (
            mneme_core::Symbol::from("state"),
            mneme_core::Value::symbol(location.state.as_str()),
        ),
        (
            mneme_core::Symbol::from("attempts"),
            mneme_core::Value::integer(location.attempts),
        ),
        (
            mneme_core::Symbol::from("verified"),
            mneme_core::Value::Boolean(location.verified),
        ),
        (
            mneme_core::Symbol::from("detail-code"),
            location
                .detail_code
                .as_ref()
                .map(|code| mneme_core::Value::string(code.clone()))
                .unwrap_or_else(none_value),
        ),
    ])
}

fn image_value(image: mneme_doc::images::Loaded) -> mneme_core::Value {
    mneme_core::Value::symbol_dictionary([
        (
            mneme_core::Symbol::from("source"),
            image.pin.source.to_value(),
        ),
        (
            mneme_core::Symbol::from("source-revision"),
            image.pin.revision.to_value(),
        ),
        (
            mneme_core::Symbol::from("digest"),
            mneme_core::Value::string(image.digest.to_hex()),
        ),
        (
            mneme_core::Symbol::from("media-type"),
            mneme_core::Value::string(image.media_type),
        ),
        (
            mneme_core::Symbol::from("width"),
            mneme_core::Value::integer(image.width),
        ),
        (
            mneme_core::Symbol::from("height"),
            mneme_core::Value::integer(image.height),
        ),
        (
            mneme_core::Symbol::from("bytes"),
            mneme_core::Value::bytes(image.bytes),
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
                    "image.read",
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
                    mneme_recall::Mode::Lexical,
                    mneme_recall::Mode::Structured,
                    mneme_recall::Mode::Vector,
                ]
                .into_iter()
                .map(|mode| mneme_core::Value::symbol(mode.name()))
                .collect(),
            ),
        ),
        (
            mneme_core::Symbol::from("unavailable-modes"),
            mneme_core::Value::sequence(Vec::new()),
        ),
    ])
}

fn none_value() -> mneme_core::Value {
    mneme_core::Value::symbol("none")
}

/// A structured tagged error document for adapter-level parse failures.
pub fn error_document(code: crate::error::ApiErrorCode, message: &str) -> mneme_core::Value {
    let error = crate::error::ApiError::new(code, message);
    response_envelope_for_error(
        "unknown",
        "invalid",
        error.code,
        &error.message,
        &error_diagnostics(&error),
    )
}

/// A structured tagged error document that keeps field diagnostics.
///
/// Adapters use this form so a client sees the exact member that failed, while
/// the diagnostics stay off the protocol's stdout stream.
pub fn error_document_for(error: &crate::error::ApiError) -> mneme_core::Value {
    response_envelope_for_error(
        "unknown",
        "invalid",
        error.code,
        &error.message,
        &error_diagnostics(error),
    )
}

fn response_envelope_for_error(
    request_id: &str,
    operation: &str,
    code: crate::error::ApiErrorCode,
    message: &str,
    diagnostics: &[mneme_core::Diagnostic],
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
                (
                    mneme_core::Symbol::from("diagnostics"),
                    diagnostics_value(diagnostics),
                ),
            ]),
        ),
    ])
}
