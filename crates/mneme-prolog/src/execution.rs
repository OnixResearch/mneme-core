//! Compare-and-swap acceptance for reviewable Prolog plans.
//!
//! A plan is data. This registry rechecks base revision, preconditions, evidence
//! digests, forgotten support, and idempotency before recording acceptance. It
//! never executes actions or applies canonical effects.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// Current source availability and digest for one plan premise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanSourceState {
    Retained { digest: String },
    Pruned { digest: String },
    Forgotten { digest: String },
}

impl PlanSourceState {
    pub fn digest(&self) -> &str {
        match self {
            PlanSourceState::Retained { digest }
            | PlanSourceState::Pruned { digest }
            | PlanSourceState::Forgotten { digest } => digest,
        }
    }
}

/// Current conditions against which a plan is accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanState {
    pub scope: mneme_core::ScopeId,
    pub base_revision: mneme_core::WorkspaceRevisionId,
    pub preconditions: std::collections::BTreeSet<String>,
    pub sources:
        std::collections::BTreeMap<(mneme_core::RecordId, mneme_core::RevisionId), PlanSourceState>,
    pub forgotten: std::collections::BTreeSet<mneme_core::RecordId>,
}

/// Read-only plan registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredPlan {
    pub plan: crate::PlanProposal,
    pub revision: u64,
    pub expected: PlanState,
    pub accepted: Option<mneme_core::RecordId>,
}

/// Read-only inspection of a plan and its current state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanInspection {
    pub plan: crate::PlanProposal,
    pub revision: u64,
    pub expected: PlanState,
    pub current: PlanState,
    pub accepted: Option<mneme_core::RecordId>,
}

/// A separate plan acceptance command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanAcceptanceCommand {
    pub idempotency_key: String,
    pub plan_id: String,
    pub plan_revision: u64,
    pub expected: PlanState,
    pub decision: mneme_core::RecordId,
}

/// Why a plan command did not apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanConflictKind {
    MissingPlan,
    StalePlanRevision,
    StaleBase,
    ChangedPreconditions,
    AlteredSource,
    ForgottenSource,
    PrunedSource,
    AlreadyDecided,
    IdempotencyMismatch,
}

/// Result of a plan acceptance command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanOutcome {
    Accepted {
        plan_id: String,
        decision: mneme_core::RecordId,
        revision: u64,
    },
    PriorOutcome {
        plan_id: String,
        detail: String,
    },
    Conflict {
        kind: PlanConflictKind,
        detail: String,
    },
}

/// One plan registry. Acceptance records a decision, never an effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanRegistry {
    pub current: PlanState,
    plans: std::collections::BTreeMap<String, RegisteredPlan>,
    acceptances: std::collections::BTreeMap<String, (PlanAcceptanceCommand, PlanOutcome)>,
}

impl PlanRegistry {
    pub fn new(current: PlanState) -> Self {
        PlanRegistry {
            current,
            plans: std::collections::BTreeMap::new(),
            acceptances: std::collections::BTreeMap::new(),
        }
    }

    pub fn register(
        &mut self,
        plan: crate::PlanProposal,
        revision: u64,
        expected: PlanState,
    ) -> Result<(), String> {
        if revision == 0 || plan.id.trim().is_empty() {
            return Err("plan revision and identity are required".to_owned());
        }
        if plan.scope != expected.scope || plan.base_revision != expected.base_revision {
            return Err("plan scope/base does not match its acceptance state".to_owned());
        }
        if self.plans.contains_key(&plan.id) {
            return Err("plan is already registered".to_owned());
        }
        self.plans.insert(
            plan.id.clone(),
            RegisteredPlan {
                plan,
                revision,
                expected,
                accepted: None,
            },
        );
        Ok(())
    }

    pub fn inspect(&self, plan_id: &str) -> Result<PlanInspection, String> {
        let registered = self
            .plans
            .get(plan_id)
            .ok_or_else(|| format!("unknown plan {plan_id}"))?;
        Ok(PlanInspection {
            plan: registered.plan.clone(),
            revision: registered.revision,
            expected: registered.expected.clone(),
            current: self.current.clone(),
            accepted: registered.accepted,
        })
    }

    /// Record plan acceptance after all CAS/precondition checks. No action is run.
    #[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
    pub fn accept(&mut self, command: PlanAcceptanceCommand) -> PlanOutcome {
        if let Some(outcome) = self.prior_acceptance(&command) {
            return outcome;
        }
        let Some(registered) = self.plans.get(&command.plan_id).cloned() else {
            return conflict(PlanConflictKind::MissingPlan, "plan is not registered");
        };
        if let Some(outcome) = self
            .validate_acceptance_state(&command, &registered)
            .or_else(|| self.validate_acceptance_sources(&registered))
        {
            return outcome;
        }
        let Some(registered) = self.plans.get_mut(&command.plan_id) else {
            return conflict(PlanConflictKind::MissingPlan, "plan disappeared");
        };
        registered.accepted = Some(command.decision);
        registered.revision = registered.revision.saturating_add(1);
        let outcome = PlanOutcome::Accepted {
            plan_id: command.plan_id.clone(),
            decision: command.decision,
            revision: registered.revision,
        };
        self.acceptances
            .insert(command.idempotency_key.clone(), (command, outcome.clone()));
        outcome
    }

    fn prior_acceptance(&self, command: &PlanAcceptanceCommand) -> Option<PlanOutcome> {
        self.acceptances
            .get(&command.idempotency_key)
            .map(|(stored, _)| {
                if stored == command {
                    PlanOutcome::PriorOutcome {
                        plan_id: command.plan_id.clone(),
                        detail: "plan acceptance already recorded".to_owned(),
                    }
                } else {
                    PlanOutcome::Conflict {
                        kind: PlanConflictKind::IdempotencyMismatch,
                        detail: "idempotency key was reused with a different plan acceptance"
                            .to_owned(),
                    }
                }
            })
    }

    fn validate_acceptance_state(
        &self,
        command: &PlanAcceptanceCommand,
        registered: &RegisteredPlan,
    ) -> Option<PlanOutcome> {
        if registered.accepted.is_some() {
            return Some(conflict(
                PlanConflictKind::AlreadyDecided,
                "plan already has an acceptance decision",
            ));
        }
        if registered.revision != command.plan_revision {
            return Some(conflict(
                PlanConflictKind::StalePlanRevision,
                "plan revision changed",
            ));
        }
        if command.expected != registered.expected {
            return Some(conflict(
                PlanConflictKind::ChangedPreconditions,
                "acceptance state differs from the reviewed plan",
            ));
        }
        if self.current.base_revision != registered.expected.base_revision {
            return Some(conflict(
                PlanConflictKind::StaleBase,
                "base revision changed",
            ));
        }
        if self.current.preconditions != registered.expected.preconditions {
            return Some(conflict(
                PlanConflictKind::ChangedPreconditions,
                "plan preconditions changed",
            ));
        }
        None
    }

    fn validate_acceptance_sources(&self, registered: &RegisteredPlan) -> Option<PlanOutcome> {
        for premise in &registered.plan.evidence {
            let key = (premise.record_id, premise.revision_id);
            if self.current.forgotten.contains(&premise.record_id)
                || premise
                    .ancestry_roots
                    .iter()
                    .any(|(record, _)| self.current.forgotten.contains(record))
            {
                return Some(conflict(
                    PlanConflictKind::ForgottenSource,
                    "plan depends on forgotten evidence",
                ));
            }
            let Some(current_source) = self.current.sources.get(&key) else {
                return Some(conflict(
                    PlanConflictKind::AlteredSource,
                    "plan source is missing",
                ));
            };
            let Some(expected_source) = registered.expected.sources.get(&key) else {
                return Some(conflict(
                    PlanConflictKind::AlteredSource,
                    "plan source was not reviewed",
                ));
            };
            if current_source.digest() != expected_source.digest() {
                return Some(conflict(
                    PlanConflictKind::AlteredSource,
                    "plan source changed",
                ));
            }
            if matches!(current_source, PlanSourceState::Forgotten { .. }) {
                return Some(conflict(
                    PlanConflictKind::ForgottenSource,
                    "plan source was forgotten",
                ));
            }
            if matches!(current_source, PlanSourceState::Pruned { .. })
                && premise.span.is_some()
                && matches!(premise.availability, crate::PremiseAvailability::Retained)
            {
                return Some(conflict(
                    PlanConflictKind::PrunedSource,
                    "plan requires pruned source bytes",
                ));
            }
        }
        None
    }
}

fn conflict(kind: PlanConflictKind, detail: &str) -> PlanOutcome {
    PlanOutcome::Conflict {
        kind,
        detail: detail.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> mneme_core::ScopeId {
        mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
    }

    fn revision() -> mneme_core::WorkspaceRevisionId {
        mneme_core::WorkspaceRevisionId::from_bytes([0xb0; 16])
    }

    fn source() -> (mneme_core::RecordId, mneme_core::RevisionId) {
        (
            mneme_core::RecordId::from_bytes([0x20; 16]),
            mneme_core::RevisionId::from_bytes([0x21; 16]),
        )
    }

    fn plan() -> crate::PlanProposal {
        let (record, source_revision) = source();
        crate::PlanProposal {
            id: "plan-1".to_owned(),
            base_revision: revision(),
            scope: scope(),
            actions: vec![crate::PlanAction {
                action: "write-file".to_owned(),
                parameters: std::collections::BTreeMap::new(),
            }],
            preconditions: Vec::new(),
            assumptions: std::collections::BTreeSet::new(),
            evidence: vec![crate::Premise {
                record_id: record,
                revision_id: source_revision,
                span: None,
                derivation: None,
                ancestry_roots: std::collections::BTreeSet::from([(record, source_revision)]),
                availability: crate::PremiseAvailability::Retained,
            }],
            expected_effects: vec!["file-created".to_owned()],
        }
    }

    fn state() -> PlanState {
        let (record, source_revision) = source();
        PlanState {
            scope: scope(),
            base_revision: revision(),
            preconditions: std::collections::BTreeSet::from(["workspace-clean".to_owned()]),
            sources: std::collections::BTreeMap::from([(
                (record, source_revision),
                PlanSourceState::Retained {
                    digest: "sha256:source".to_owned(),
                },
            )]),
            forgotten: std::collections::BTreeSet::new(),
        }
    }

    fn command() -> PlanAcceptanceCommand {
        PlanAcceptanceCommand {
            idempotency_key: "accept-plan".to_owned(),
            plan_id: "plan-1".to_owned(),
            plan_revision: 1,
            expected: state(),
            decision: mneme_core::RecordId::from_bytes([0x60; 16]),
        }
    }

    fn registry() -> PlanRegistry {
        let mut registry = PlanRegistry::new(state());
        registry.register(plan(), 1, state()).expect("register");
        registry
    }

    #[test]
    fn acceptance_records_decision_without_executing_action() {
        let temp = tempfile::tempdir().expect("tempdir");
        let fake_path = temp.path().join("must-not-exist");
        let mut plan = plan();
        plan.actions[0].action = format!("write-file:{}", fake_path.display());
        let mut registry = PlanRegistry::new(state());
        registry.register(plan, 1, state()).expect("register");
        assert!(matches!(
            registry.accept(command()),
            PlanOutcome::Accepted { .. }
        ));
        assert!(!fake_path.exists());
        assert_eq!(
            registry.inspect("plan-1").expect("inspect").accepted,
            Some(mneme_core::RecordId::from_bytes([0x60; 16]))
        );
    }

    #[test]
    fn stale_base_and_changed_preconditions_conflict() {
        let mut stale = registry();
        stale.current.base_revision = mneme_core::WorkspaceRevisionId::from_bytes([0x99; 16]);
        assert!(matches!(
            stale.accept(command()),
            PlanOutcome::Conflict {
                kind: PlanConflictKind::StaleBase,
                ..
            }
        ));
        let mut changed = registry();
        changed.current.preconditions.insert("different".to_owned());
        assert!(matches!(
            changed.accept(command()),
            PlanOutcome::Conflict {
                kind: PlanConflictKind::ChangedPreconditions,
                ..
            }
        ));
    }

    #[test]
    fn erased_source_is_a_conflict() {
        let mut registry = registry();
        registry.current.forgotten.insert(source().0);
        assert!(matches!(
            registry.accept(command()),
            PlanOutcome::Conflict {
                kind: PlanConflictKind::ForgottenSource,
                ..
            }
        ));
    }

    #[test]
    fn repeated_acceptance_returns_prior_outcome() {
        let mut registry = registry();
        assert!(matches!(
            registry.accept(command()),
            PlanOutcome::Accepted { .. }
        ));
        assert!(matches!(
            registry.accept(command()),
            PlanOutcome::PriorOutcome { .. }
        ));
        assert_eq!(registry.inspect("plan-1").expect("inspect").revision, 2);
    }
}
