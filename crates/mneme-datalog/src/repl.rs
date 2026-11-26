//! Session-scoped, read-only Dynamic Datalog REPL over one pinned revision.
//!
//! Base canonical extents are loaded once when the session opens. Adding or
//! retracting rules validates the resulting stratified program, reuses any
//! unaffected cached derived relations, and enforces per-step and total
//! session work/row/rule bounds without mutating the workspace.

/// Session-wide and per-step evaluation limits for a Dynamic Datalog REPL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplLimits {
    /// Bounds applied to each individual evaluation step and query.
    pub per_step: crate::Limits,
    /// Cumulative work budget across the entire REPL session (including open).
    pub max_total_work: u64,
    /// Maximum number of active rules allowed in the session at one time.
    pub max_rules: u32,
    /// Maximum number of materialized rows across all relations in the session.
    pub max_total_rows: u64,
}

impl Default for ReplLimits {
    fn default() -> Self {
        ReplLimits {
            per_step: crate::Limits::default(),
            max_total_work: 500_000,
            max_rules: 64,
            max_total_rows: 10_000,
        }
    }
}

/// Request to open one pinned, read-only Dynamic Datalog REPL session.
#[derive(Clone, Debug)]
pub struct ReplSessionRequest {
    pub actor: String,
    pub scope: mneme_core::ScopeId,
    /// Explicit revision to pin, or `None` to pin the current head at open time.
    pub revision: Option<mneme_core::WorkspaceRevisionId>,
    pub limits: ReplLimits,
    /// Base predicates whose extents are explicitly incomplete.
    pub incomplete_extents: std::collections::BTreeSet<String>,
    /// Predicates that may be used under negation or absence-sensitive
    /// aggregation. When empty, all canonical base predicates are marked complete.
    pub complete_predicates: std::collections::BTreeSet<String>,
    /// Caller's scope authorization.
    pub access: mneme_memory::Access,
    /// Optional valid-time instant for claims.
    pub at: Option<mneme_core::Timestamp>,
}

/// Summary returned after opening a session or applying a rule change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplStepSummary {
    pub context: crate::BuildContext,
    pub status: crate::ExecutionStatus,
    pub step_work: u64,
    pub total_work: u64,
    pub remaining_work: u64,
    pub total_rows: u64,
    pub rule_count: u32,
    pub limit_reached: bool,
    pub support_truncated: bool,
    pub affected_predicates: Vec<String>,
    pub reused_predicates: Vec<String>,
}

/// A bounded, read-only, revision-pinned Dynamic Datalog REPL session.
pub struct ReplSession {
    base: crate::engine::BaseSnapshot,
    ivm: crate::ivm::ViewState,
    build: crate::Build,
    program: crate::RuleProgram,
    repl_limits: ReplLimits,
    total_work: u64,
    incomplete_extents: std::collections::BTreeSet<String>,
    at: Option<mneme_core::Timestamp>,
}

struct PreparedAdvance {
    target_revision: mneme_core::WorkspaceRevisionId,
    step_limits: crate::Limits,
    next_context: crate::BuildContext,
}

struct IncrementalStepContext {
    step_limits: crate::Limits,
    start: std::time::Instant,
}

impl ReplSession {
    /// Open a new REPL session pinned to one workspace revision and scope.
    pub fn open(
        workspace: &mut mneme_store::Workspace,
        request: ReplSessionRequest,
    ) -> Result<Self, crate::Error> {
        let start = crate::engine::evaluation_start();
        let head_revision = workspace.current_revision()?;
        let revision = request.revision.unwrap_or(head_revision);
        let requested_was_head = request.revision.is_none();
        let generation = workspace.eligibility_generation()?;
        let bundle = initial_bundle(&request.complete_predicates);
        let program = bundle.validate().map_err(crate::Error::InvalidBundle)?;
        let context = build_session_context(
            revision,
            &request,
            generation,
            &program.bundle,
            requested_was_head,
        );
        let base = load_session_base(workspace, &request, &program, &context, start)?;
        let initial_rows = count_store_rows(&base.facts)?;
        if initial_rows > request.limits.max_total_rows {
            return Err(crate::Error::LimitExceeded(
                "session row limit exceeded while loading base extents".to_owned(),
            ));
        }
        let ivm = crate::ivm::ViewState::from_base_facts(&base.facts)?;
        let build = crate::Build {
            context,
            status: base.status,
            coverage: base.coverage.clone(),
            limits: request.limits.per_step.clone(),
            work: base.work,
            support_truncated: base.support_truncated,
            limit_reached: base.limit_reached,
            declaration_valid: true,
            facts: unwrap_fact_stores(&base.facts),
            arities: program.arities.clone(),
            bundle: program.bundle.clone(),
            vault_barriers: Vec::new(),
        };
        let total_work = base.work;
        debug_assert!(total_work <= request.limits.max_total_work);
        debug_assert!(initial_rows <= request.limits.max_total_rows);
        Ok(ReplSession {
            base,
            ivm,
            build,
            program,
            repl_limits: request.limits,
            total_work,
            incomplete_extents: request.incomplete_extents,
            at: request.at,
        })
    }

    /// Add one exploratory rule, incrementally maintaining affected derived relations.
    pub fn add_rule(&mut self, rule: crate::Rule) -> Result<ReplStepSummary, crate::Error> {
        if rule.id.trim().is_empty() {
            return Err(crate::Error::InvalidBundle(vec![crate::RuleDiagnostic {
                rule: None,
                code: "empty-rule-id",
                message: "rule id must not be empty".to_owned(),
            }]));
        }
        if self
            .build
            .bundle
            .rules
            .iter()
            .any(|existing| existing.id == rule.id)
        {
            return Err(crate::Error::InvalidBundle(vec![crate::RuleDiagnostic {
                rule: Some(rule.id),
                code: "duplicate-rule-id",
                message: "a rule with this id already exists in the session".to_owned(),
            }]));
        }
        let next_count = u32::try_from(self.build.bundle.rules.len().saturating_add(1))
            .map_err(|_| crate::Error::LimitExceeded("session rule count overflow".to_owned()))?;
        if next_count > self.repl_limits.max_rules {
            return Err(crate::Error::LimitExceeded(format!(
                "session rule limit ({}) exceeded",
                self.repl_limits.max_rules
            )));
        }

        let head_predicate = rule.head.predicate.clone();
        debug_assert!(!head_predicate.is_empty());
        debug_assert!(next_count <= self.repl_limits.max_rules);
        let mut candidate_bundle = self.build.bundle.clone();
        candidate_bundle.rules.push(rule);
        candidate_bundle
            .complete_predicates
            .insert(head_predicate.clone());
        let candidate_program = candidate_bundle
            .validate()
            .map_err(crate::Error::InvalidBundle)?;

        let affected = affected_predicates(&candidate_program.bundle, &head_predicate);
        self.apply_incremental(candidate_program, affected)
    }

    /// Retract one exploratory rule by id, keeping unaffected derived relations cached.
    pub fn retract_rule(&mut self, rule_id: &str) -> Result<ReplStepSummary, crate::Error> {
        let Some(index) = self
            .build
            .bundle
            .rules
            .iter()
            .position(|rule| rule.id == rule_id)
        else {
            return Err(crate::Error::InvalidQuery(
                "rule id is not present in the REPL session",
            ));
        };
        let head_predicate = self.build.bundle.rules[index].head.predicate.clone();
        debug_assert!(!head_predicate.is_empty());
        debug_assert!(index < self.build.bundle.rules.len());
        let affected = affected_predicates(&self.build.bundle, &head_predicate);

        let mut candidate_bundle = self.build.bundle.clone();
        candidate_bundle.rules.remove(index);
        let still_derived = candidate_bundle
            .rules
            .iter()
            .any(|rule| rule.head.predicate == head_predicate);
        if !still_derived
            && !candidate_bundle
                .base_predicates
                .contains_key(&head_predicate)
        {
            candidate_bundle.complete_predicates.remove(&head_predicate);
        }
        let candidate_program = candidate_bundle
            .validate()
            .map_err(crate::Error::InvalidBundle)?;

        self.apply_incremental(candidate_program, affected)
    }

    /// Query one relation (base or derived) from the current session state.
    pub fn query_relation(
        &self,
        workspace: Option<&mut mneme_store::Workspace>,
        mut query: crate::Query,
    ) -> Result<crate::QueryResult, crate::Error> {
        let requested_revision = if let Some(workspace) = workspace {
            let current_generation = workspace.eligibility_generation()?;
            if current_generation != self.build.context.eligibility_generation {
                return Err(mneme_store::Failure::BarrierAdvanced {
                    pinned: self.build.context.eligibility_generation,
                    current: current_generation,
                }
                .into());
            }
            let current_revision = workspace.current_revision()?;
            if self.build.context.requested_was_head {
                current_revision
            } else {
                self.build.context.requested_revision
            }
        } else {
            self.build.context.requested_revision
        };
        query.allow_stale = true;
        crate::validate_query_arity(&self.build, &query)?;
        let coverage = crate::dependency_coverage(&self.build, &query.predicate);
        let rows = crate::matching_query_rows(&self.build, &query);
        debug_assert!(!coverage.is_empty());
        debug_assert!(query.allow_stale);
        Ok(crate::query_result(
            &self.build,
            &query,
            coverage,
            rows,
            requested_revision,
        ))
    }

    /// Pinned evaluation context for this session.
    pub fn context(&self) -> &crate::BuildContext {
        &self.build.context
    }

    /// Active rules in this session.
    pub fn rules(&self) -> &[crate::Rule] {
        &self.build.bundle.rules
    }

    /// Session and per-step limits.
    pub fn limits(&self) -> &ReplLimits {
        &self.repl_limits
    }

    /// Cumulative work charged to this session so far.
    pub fn total_work(&self) -> u64 {
        self.total_work
    }

    /// Total materialized rows currently held in this session.
    pub fn total_rows(&self) -> Result<u64, crate::Error> {
        count_fact_rows(&self.build.facts)
    }

    /// Row counts per predicate currently held in this session.
    pub fn relation_row_counts(
        &self,
    ) -> Result<std::collections::BTreeMap<String, u64>, crate::Error> {
        let mut counts = std::collections::BTreeMap::new();
        for (predicate, rows) in &self.build.facts {
            let count = u64::try_from(rows.len()).map_err(|_| {
                crate::Error::LimitExceeded("relation row count overflow".to_owned())
            })?;
            counts.insert(predicate.clone(), count);
        }
        Ok(counts)
    }

    /// Current session status summary without mutating any rules.
    pub fn summary(&self) -> Result<ReplStepSummary, crate::Error> {
        let total_rows = self.total_rows()?;
        let rule_count = u32::try_from(self.build.bundle.rules.len())
            .map_err(|_| crate::Error::LimitExceeded("session rule count overflow".to_owned()))?;
        debug_assert!(self.total_work <= self.repl_limits.max_total_work);
        debug_assert!(total_rows <= self.repl_limits.max_total_rows);
        Ok(ReplStepSummary {
            context: self.build.context.clone(),
            status: self.build.status,
            step_work: 0,
            total_work: self.total_work,
            remaining_work: self
                .repl_limits
                .max_total_work
                .saturating_sub(self.total_work),
            total_rows,
            rule_count,
            limit_reached: self.build.limit_reached,
            support_truncated: self.build.support_truncated,
            affected_predicates: Vec::new(),
            reused_predicates: self.derived_predicates(),
        })
    }

    fn derived_predicates(&self) -> Vec<String> {
        self.program
            .arities
            .keys()
            .filter(|predicate| !self.build.bundle.base_predicates.contains_key(*predicate))
            .cloned()
            .collect()
    }

    fn apply_incremental(
        &mut self,
        candidate_program: crate::RuleProgram,
        affected: std::collections::BTreeSet<String>,
    ) -> Result<ReplStepSummary, crate::Error> {
        let remaining_work = self
            .repl_limits
            .max_total_work
            .saturating_sub(self.total_work);
        if remaining_work == 0 {
            return Err(crate::Error::LimitExceeded(
                "session total work budget exhausted".to_owned(),
            ));
        }

        let start = crate::engine::evaluation_start();
        let mut step_limits = self.repl_limits.per_step.clone();
        step_limits.max_work = step_limits.max_work.min(remaining_work);
        debug_assert!(step_limits.max_work > 0);
        debug_assert!(step_limits.max_work <= remaining_work);
        let kept_facts = self.kept_facts(&candidate_program, &affected);
        let reused_predicates: Vec<String> = kept_facts
            .keys()
            .filter(|predicate| {
                !candidate_program
                    .bundle
                    .base_predicates
                    .contains_key(*predicate)
            })
            .cloned()
            .collect();

        let evaluated = crate::engine::evaluate_incremental(
            &self.base,
            crate::engine::IncrementalRequest {
                bundle: &candidate_program.bundle,
                program: &candidate_program,
                context: &self.build.context,
                limits: &step_limits,
                kept_facts,
                affected_predicates: &affected,
                at: self.at,
                start,
            },
        );
        self.commit_incremental(
            candidate_program,
            affected,
            reused_predicates,
            evaluated,
            IncrementalStepContext { step_limits, start },
        )
    }

    fn kept_facts(
        &self,
        candidate_program: &crate::RuleProgram,
        affected: &std::collections::BTreeSet<String>,
    ) -> std::collections::BTreeMap<String, crate::engine::FactStore> {
        let mut kept_facts = std::collections::BTreeMap::new();
        for (predicate, rows) in &self.build.facts {
            let is_base = candidate_program
                .bundle
                .base_predicates
                .contains_key(predicate);
            let is_still_defined = candidate_program.arities.contains_key(predicate);
            if is_base || (is_still_defined && !affected.contains(predicate)) {
                kept_facts.insert(
                    predicate.clone(),
                    crate::engine::FactStore::from_rows(rows.clone()),
                );
            }
        }
        for (predicate, store) in &self.base.facts {
            kept_facts
                .entry(predicate.clone())
                .or_insert_with(|| store.clone());
        }
        kept_facts
    }

    fn commit_incremental(
        &mut self,
        candidate_program: crate::RuleProgram,
        affected: std::collections::BTreeSet<String>,
        reused_predicates: Vec<String>,
        evaluated: crate::engine::BuildFacts,
        step_ctx: IncrementalStepContext,
    ) -> Result<ReplStepSummary, crate::Error> {
        // Charge work even if the step hit a limit, so repeated failing steps
        // cannot bypass the cumulative session work budget.
        self.total_work = self.total_work.saturating_add(evaluated.work);

        if evaluated.limit_reached {
            return Err(crate::Error::LimitExceeded(format!(
                "step limit reached ({})",
                evaluated.status.name()
            )));
        }
        let next_total_rows = count_store_rows(&evaluated.facts)?;
        if next_total_rows > self.repl_limits.max_total_rows {
            return Err(crate::Error::LimitExceeded(format!(
                "session total row limit ({}) exceeded",
                self.repl_limits.max_total_rows
            )));
        }

        let next_build_id = crate::rules::build_id(crate::rules::BuildIdContext {
            revision: self.build.context.requested_revision,
            scope: &self.build.context.scope,
            generation: self.build.context.eligibility_generation,
            bundle: &candidate_program.bundle,
            limits: &self.repl_limits.per_step,
            incomplete_extents: &self.incomplete_extents,
            at: self.at,
        });
        let mut next_context = self.build.context.clone();
        next_context.projection_build_id = next_build_id;

        let next_facts = unwrap_fact_stores(&evaluated.facts);
        let sync_work = self.sync_ivm_after_rule_change(
            &candidate_program,
            &next_facts,
            &affected,
            evaluated.work,
            &step_ctx,
        )?;
        let step_work = evaluated.work.saturating_add(sync_work);

        self.build = crate::Build {
            context: next_context.clone(),
            status: evaluated.status,
            coverage: evaluated.coverage,
            limits: self.repl_limits.per_step.clone(),
            work: step_work,
            support_truncated: evaluated.support_truncated,
            limit_reached: evaluated.limit_reached,
            declaration_valid: evaluated.declaration_valid,
            facts: next_facts,
            arities: candidate_program.arities.clone(),
            bundle: candidate_program.bundle.clone(),
            vault_barriers: Vec::new(),
        };
        self.program = candidate_program;

        let rule_count = u32::try_from(self.build.bundle.rules.len())
            .map_err(|_| crate::Error::LimitExceeded("session rule count overflow".to_owned()))?;
        debug_assert!(self.total_work <= self.repl_limits.max_total_work);
        debug_assert!(next_total_rows <= self.repl_limits.max_total_rows);
        Ok(ReplStepSummary {
            context: next_context,
            status: self.build.status,
            step_work,
            total_work: self.total_work,
            remaining_work: self
                .repl_limits
                .max_total_work
                .saturating_sub(self.total_work),
            total_rows: next_total_rows,
            rule_count,
            limit_reached: false,
            support_truncated: self.build.support_truncated,
            affected_predicates: affected.into_iter().collect(),
            reused_predicates,
        })
    }

    fn sync_ivm_after_rule_change(
        &mut self,
        candidate_program: &crate::RuleProgram,
        next_facts: &std::collections::BTreeMap<
            String,
            std::collections::BTreeMap<Vec<mneme_core::Value>, crate::FactData>,
        >,
        affected: &std::collections::BTreeSet<String>,
        evaluated_work: u64,
        step_ctx: &IncrementalStepContext,
    ) -> Result<u64, crate::Error> {
        debug_assert!(step_ctx.step_limits.max_work > 0);
        let mut sync_work = 0_u64;
        let sync_result = self.ivm.sync_after_rule_change(
            crate::ivm::SyncRuleChangeRequest {
                program: candidate_program,
                build_facts: next_facts,
                affected,
                base_coverage: &self.base.base_coverage,
                coverage_reasons: &self.base.coverage_reasons,
                limits: &step_ctx.step_limits,
                initial_work: evaluated_work,
                start: step_ctx.start,
            },
            &mut sync_work,
        );
        self.total_work = self.total_work.saturating_add(sync_work);
        debug_assert!(self.total_work <= self.repl_limits.max_total_work);
        sync_result?;
        Ok(sync_work)
    }

    /// Step this session to `revision` (or current workspace head when `None`)
    /// using DBSP Z-set delta maintenance without reloading unchanged base facts.
    pub fn advance_to_revision(
        &mut self,
        workspace: &mut mneme_store::Workspace,
        revision: Option<mneme_core::WorkspaceRevisionId>,
    ) -> Result<ReplStepSummary, crate::Error> {
        let remaining_work = self.remaining_total_work()?;
        let start = crate::engine::evaluation_start();
        let mut prepared = self.prepare_advance(workspace, revision, remaining_work)?;
        let base_advance = crate::engine::advance_base_snapshot(
            &self.base,
            crate::engine::BaseAdvanceRequest {
                workspace,
                target_revision: prepared.target_revision,
                next_context: &prepared.next_context,
                bundle: &self.program.bundle,
                limits: &prepared.step_limits,
                incomplete_extents: &self.incomplete_extents,
                at: self.at,
                start,
            },
        )?;
        self.sync_advance_generation(
            &mut prepared.next_context,
            base_advance.eligibility_generation,
        );
        if base_advance.limit_reached {
            self.total_work = self.total_work.saturating_add(base_advance.work);
            return Err(crate::Error::LimitExceeded(format!(
                "advance base delta limit reached ({})",
                base_advance.status.name()
            )));
        }

        let ivm_result = self.run_advance_ivm(&base_advance, &prepared, start)?;
        self.commit_advance_state(base_advance.next_base, ivm_result, prepared.next_context)
    }

    fn remaining_total_work(&self) -> Result<u64, crate::Error> {
        let remaining_work = self
            .repl_limits
            .max_total_work
            .saturating_sub(self.total_work);
        if remaining_work == 0 {
            return Err(crate::Error::LimitExceeded(
                "session total work budget exhausted".to_owned(),
            ));
        }
        Ok(remaining_work)
    }

    fn prepare_advance(
        &self,
        workspace: &mneme_store::Workspace,
        revision: Option<mneme_core::WorkspaceRevisionId>,
        remaining_work: u64,
    ) -> Result<PreparedAdvance, crate::Error> {
        assert!(remaining_work > 0);
        assert!(self.repl_limits.max_total_rows > 0);
        let target_revision = match revision {
            Some(rev) => rev,
            None => workspace.current_revision()?,
        };
        let was_head_requested = revision.is_none();
        let generation = workspace.eligibility_generation()?;
        let mut step_limits = self.repl_limits.per_step.clone();
        step_limits.max_work = step_limits.max_work.min(remaining_work);
        let max_total_rows = usize::try_from(self.repl_limits.max_total_rows).map_err(|_| {
            crate::Error::LimitExceeded("max_total_rows exceeds platform range".to_owned())
        })?;
        step_limits.max_result_rows = max_total_rows.max(step_limits.max_result_rows);

        let mut next_context = self.build.context.clone();
        next_context.requested_revision = target_revision;
        next_context.served_revision = target_revision;
        next_context.eligibility_generation = generation;
        next_context.requested_was_head = was_head_requested;
        next_context.projection_build_id = self.advance_build_id(target_revision, generation);
        Ok(PreparedAdvance {
            target_revision,
            step_limits,
            next_context,
        })
    }

    fn advance_build_id(
        &self,
        revision: mneme_core::WorkspaceRevisionId,
        generation: u64,
    ) -> String {
        crate::rules::build_id(crate::rules::BuildIdContext {
            revision,
            scope: &self.build.context.scope,
            generation,
            bundle: &self.program.bundle,
            limits: &self.repl_limits.per_step,
            incomplete_extents: &self.incomplete_extents,
            at: self.at,
        })
    }

    fn sync_advance_generation(&self, next_context: &mut crate::BuildContext, generation: u64) {
        if next_context.eligibility_generation != generation {
            next_context.eligibility_generation = generation;
            next_context.projection_build_id =
                self.advance_build_id(next_context.served_revision, generation);
        }
    }

    fn run_advance_ivm(
        &mut self,
        base_advance: &crate::engine::BaseAdvanceResult,
        prepared: &PreparedAdvance,
        start: std::time::Instant,
    ) -> Result<crate::ivm::AdvanceViewResult, crate::Error> {
        assert!(prepared.step_limits.max_work > 0);
        let ivm_result = crate::ivm::advance_view(
            &self.ivm,
            crate::ivm::AdvanceViewRequest {
                program: &self.program,
                base_deltas: base_advance.base_deltas.clone(),
                dirty_provenance: base_advance.dirty_provenance.clone(),
                next_base: &base_advance.next_base,
                next_context: &prepared.next_context,
                limits: &prepared.step_limits,
                initial_work: base_advance.work,
                current_facts: &self.build.facts,
                at: self.at,
                start,
            },
        )?;
        self.total_work = self.total_work.saturating_add(ivm_result.work);
        debug_assert!(ivm_result.work >= base_advance.work);
        if ivm_result.limit_reached {
            return Err(crate::Error::LimitExceeded(format!(
                "advance incremental limit reached ({})",
                ivm_result.status.name()
            )));
        }
        Ok(ivm_result)
    }

    fn commit_advance_state(
        &mut self,
        next_base: crate::engine::BaseSnapshot,
        ivm_result: crate::ivm::AdvanceViewResult,
        next_context: crate::BuildContext,
    ) -> Result<ReplStepSummary, crate::Error> {
        let next_total_rows = count_fact_rows(&ivm_result.next_facts)?;
        if next_total_rows > self.repl_limits.max_total_rows {
            return Err(crate::Error::LimitExceeded(format!(
                "session total row limit ({}) exceeded",
                self.repl_limits.max_total_rows
            )));
        }

        self.base = next_base;
        self.ivm = ivm_result.next_view;
        self.build = crate::Build {
            context: next_context.clone(),
            status: ivm_result.status,
            coverage: ivm_result.coverage,
            limits: self.repl_limits.per_step.clone(),
            work: ivm_result.work,
            support_truncated: ivm_result.support_truncated,
            limit_reached: false,
            declaration_valid: true,
            facts: ivm_result.next_facts,
            arities: self.program.arities.clone(),
            bundle: self.program.bundle.clone(),
            vault_barriers: Vec::new(),
        };

        let rule_count = u32::try_from(self.build.bundle.rules.len())
            .map_err(|_| crate::Error::LimitExceeded("session rule count overflow".to_owned()))?;
        debug_assert!(self.total_work <= self.repl_limits.max_total_work);
        debug_assert!(next_total_rows <= self.repl_limits.max_total_rows);
        Ok(ReplStepSummary {
            context: next_context,
            status: self.build.status,
            step_work: ivm_result.work,
            total_work: self.total_work,
            remaining_work: self
                .repl_limits
                .max_total_work
                .saturating_sub(self.total_work),
            total_rows: next_total_rows,
            rule_count,
            limit_reached: false,
            support_truncated: self.build.support_truncated,
            affected_predicates: ivm_result.affected_predicates,
            reused_predicates: ivm_result.reused_predicates,
        })
    }
}

fn build_session_context(
    revision: mneme_core::WorkspaceRevisionId,
    request: &ReplSessionRequest,
    generation: u64,
    bundle: &crate::RuleBundle,
    requested_was_head: bool,
) -> crate::BuildContext {
    assert!(!bundle.id.is_empty());
    assert!(bundle.schema_version > 0);
    let build_id = crate::rules::build_id(crate::rules::BuildIdContext {
        revision,
        scope: &request.scope,
        generation,
        bundle,
        limits: &request.limits.per_step,
        incomplete_extents: &request.incomplete_extents,
        at: request.at,
    });
    crate::BuildContext {
        requested_revision: revision,
        served_revision: revision,
        scope: request.scope.clone(),
        schema_version: bundle.schema_version,
        rule_bundle_id: bundle.id.clone(),
        rule_bundle_version: bundle.version.clone(),
        projection_build_id: build_id,
        eligibility_generation: generation,
        requested_was_head,
        vaults: Vec::new(),
    }
}

fn load_session_base(
    workspace: &mut mneme_store::Workspace,
    request: &ReplSessionRequest,
    program: &crate::RuleProgram,
    context: &crate::BuildContext,
    start: std::time::Instant,
) -> Result<crate::engine::BaseSnapshot, crate::Error> {
    assert!(request.limits.max_total_work > 0);
    assert!(request.limits.max_total_rows > 0);
    let revision = context.served_revision;
    let snapshot = workspace.snapshot_at(revision, None)?;
    let snapshot = crate::visible_snapshot(snapshot, &request.scope, &request.access);
    let loaded =
        mneme_memory::view_context(workspace, &snapshot).map_err(crate::view_context_error)?;
    if loaded.history.len() > 1_000_000 {
        return Err(crate::Error::Failed(
            "workspace history exceeds the 1M revision bound".to_owned(),
        ));
    }
    let suppressions = workspace.active_suppressions()?;
    let current_sources = crate::source_availability_overlay(workspace, revision)?;
    let view = mneme_memory::View::with_retention(
        snapshot,
        workspace.root(),
        loaded.history.clone(),
        loaded.revision_sequences.clone(),
        suppressions.clone(),
    )
    .with_access(request.access.clone());

    let mut load_limits = request.limits.per_step.clone();
    load_limits.max_work = load_limits.max_work.min(request.limits.max_total_work);
    let max_total_rows = usize::try_from(request.limits.max_total_rows).map_err(|_| {
        crate::Error::LimitExceeded("max_total_rows exceeds platform range".to_owned())
    })?;
    load_limits.max_result_rows = max_total_rows.max(load_limits.max_result_rows);

    let base = crate::engine::load_base_snapshot(
        &view,
        crate::engine::BaseLoadRequest {
            bundle: &program.bundle,
            context,
            limits: &load_limits,
            incomplete_extents: &request.incomplete_extents,
            current_sources,
            history: loaded.history,
            revision_sequences: loaded.revision_sequences,
            suppressions,
            at: request.at,
            start,
        },
    );
    if base.limit_reached || base.work > request.limits.max_total_work {
        return Err(crate::Error::LimitExceeded(
            "session limit exceeded while loading base extents".to_owned(),
        ));
    }
    Ok(base)
}

fn initial_bundle(complete_predicates: &std::collections::BTreeSet<String>) -> crate::RuleBundle {
    let mut base_predicates = std::collections::BTreeMap::new();
    let mut default_complete = std::collections::BTreeSet::new();
    for predicate in crate::engine::canonical_extents() {
        if let Some(arity) = crate::rules::canonical_arity(predicate) {
            base_predicates.insert((*predicate).to_owned(), arity);
            default_complete.insert((*predicate).to_owned());
        }
    }
    let complete = if complete_predicates.is_empty() {
        default_complete
    } else {
        complete_predicates.clone()
    };
    debug_assert!(!base_predicates.is_empty());
    debug_assert!(!complete.is_empty());
    crate::RuleBundle::new(crate::RuleBundleOptions {
        id: "repl-session".to_owned(),
        version: "1".to_owned(),
        schema_version: 1,
        base_predicates,
        complete_predicates: complete,
        rules: Vec::new(),
    })
}

/// Compute all derived predicates that depend (directly or transitively) on `seed`.
fn affected_predicates(
    bundle: &crate::RuleBundle,
    seed: &str,
) -> std::collections::BTreeSet<String> {
    let mut affected = std::collections::BTreeSet::from([seed.to_owned()]);
    debug_assert!(!seed.is_empty());
    loop {
        let mut added = false;
        for rule in &bundle.rules {
            if affected.contains(&rule.head.predicate) {
                continue;
            }
            let depends = rule.body.iter().any(|literal| match literal {
                crate::Literal::Positive(atom)
                | crate::Literal::Negative(atom)
                | crate::Literal::DiamondMinus { atom, .. }
                | crate::Literal::BoxMinus { atom, .. } => affected.contains(&atom.predicate),
                crate::Literal::Since {
                    maintained,
                    trigger,
                    ..
                } => {
                    affected.contains(&maintained.predicate)
                        || affected.contains(&trigger.predicate)
                }
                crate::Literal::Allen { left, right, .. } => {
                    affected.contains(&left.predicate) || affected.contains(&right.predicate)
                }
                crate::Literal::Compare { .. }
                | crate::Literal::Aggregate { .. }
                | crate::Literal::Forbidden(_) => false,
            });
            if depends {
                affected.insert(rule.head.predicate.clone());
                added = true;
            }
        }
        if !added {
            break;
        }
    }
    debug_assert!(affected.contains(seed));
    affected
}

fn count_fact_rows(
    facts: &std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<Vec<mneme_core::Value>, crate::FactData>,
    >,
) -> Result<u64, crate::Error> {
    let mut total = 0_u64;
    for rows in facts.values() {
        let count = u64::try_from(rows.len())
            .map_err(|_| crate::Error::LimitExceeded("session row count overflow".to_owned()))?;
        total = total.saturating_add(count);
    }
    Ok(total)
}

fn count_store_rows(
    facts: &std::collections::BTreeMap<String, crate::engine::FactStore>,
) -> Result<u64, crate::Error> {
    let mut total = 0_u64;
    for store in facts.values() {
        let count = u64::try_from(store.rows.len())
            .map_err(|_| crate::Error::LimitExceeded("session row count overflow".to_owned()))?;
        total = total.saturating_add(count);
    }
    Ok(total)
}

fn unwrap_fact_stores(
    facts: &std::collections::BTreeMap<String, crate::engine::FactStore>,
) -> std::collections::BTreeMap<
    String,
    std::collections::BTreeMap<Vec<mneme_core::Value>, crate::FactData>,
> {
    facts
        .iter()
        .map(|(predicate, store)| (predicate.clone(), store.rows.clone()))
        .collect()
}
