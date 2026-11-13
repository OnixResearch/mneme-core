//! Proposal inspection, retention suppression, and separate compare-and-swap
//! acceptance/rejection.
//!
//! Registration validates the proposal against the workspace state it was
//! reviewed under, not against whatever the caller supplies: the base revision,
//! policy, eligibility generation, operation targets and premise sources are all
//! pinned before a proposal may be inspected, and a premise that is no longer
//! quotable refuses registration outright so derived content of forgotten,
//! pruned, erased or corrupt bytes never enters the registry. Acceptance
//! rechecks that pinned state against the current state, including coverage for
//! absence/cleanup proposals and every source digest, and returns the recorded
//! outcome of a repeated command instead of a generic acknowledgement.

use crate::flow::ProcedureValidator;

/// Current workspace state used by acceptance preconditions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptanceState {
    pub scope: mneme_core::ScopeId,
    pub base_revision: mneme_core::WorkspaceRevisionId,
    pub eligibility_generation: u64,
    /// The consolidation policy the proposal was derived under.
    pub policy_version: String,
    pub forgotten: std::collections::BTreeSet<mneme_core::RecordId>,
    pub targets: std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RevisionId>,
    pub sources: std::collections::BTreeMap<crate::InputKey, SourceState>,
}

impl AcceptanceState {
    /// Observe the state that governs one proposal from a pinned view.
    ///
    /// Every field comes from the view and the proposal's own pinned keys, so a
    /// caller cannot widen the targets or sources a proposal is compared
    /// against. Suppressions carry the forget decisions that a snapshot no
    /// longer contains.
    pub fn observe(
        view: &mneme_memory::View,
        scope: &mneme_core::ScopeId,
        proposal: &crate::Proposal,
        suppressions: &[mneme_store::RetentionSuppression],
    ) -> Result<Self, String> {
        if &proposal.scope != scope {
            return Err("proposal scope does not match the observed scope".to_owned());
        }
        let forgotten = suppressions
            .iter()
            .filter(|suppression| suppression.mode == mneme_store::SuppressionMode::Forgotten)
            .map(|suppression| suppression.target)
            .collect::<std::collections::BTreeSet<_>>();
        let targets = proposal
            .operation_targets()
            .into_iter()
            .map(|target| {
                let record = view
                    .record(target)
                    .map_err(|_| "proposal target is not present in the workspace".to_owned())?;
                Ok((record.record_id, record.revision_id))
            })
            .collect::<Result<std::collections::BTreeMap<_, _>, String>>()?;
        let sources = proposal
            .premises
            .iter()
            .map(|premise| {
                (
                    crate::InputKey {
                        record_id: premise.record_id,
                        revision_id: premise.revision_id,
                    },
                    premise_state(view, premise),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        Ok(AcceptanceState {
            scope: scope.clone(),
            base_revision: view.revision(),
            eligibility_generation: view.snapshot().eligibility_generation,
            policy_version: proposal.policy_version.clone(),
            forgotten,
            targets,
            sources,
        })
    }
}

/// Availability and exact content identity of one source premise.
///
/// The identity is the cited revision's own content digest, never the current
/// revision's, so a newer retained revision with different bytes cannot pass for
/// the cited one while an identical newer revision still does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceState {
    Retained {
        digest: String,
    },
    Pruned {
        digest: String,
    },
    Forgotten {
        digest: String,
    },
    Corrupt {
        digest: String,
    },
    /// The cited record revision is no longer in the workspace at all.
    Absent {
        digest: String,
    },
}

impl SourceState {
    pub fn digest(&self) -> &str {
        match self {
            SourceState::Retained { digest }
            | SourceState::Pruned { digest }
            | SourceState::Forgotten { digest }
            | SourceState::Corrupt { digest }
            | SourceState::Absent { digest } => digest,
        }
    }

    /// Whether exact bytes may be quoted from this premise.
    pub fn is_quotable(&self) -> bool {
        matches!(self, SourceState::Retained { .. })
    }
}

/// The reviewed extent one proposal was generated from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewedCoverage {
    /// Whether the reviewed extent may support an absence or cleanup conclusion.
    pub allows_absence_or_cleanup: bool,
    /// Why the extent cannot support one, when it cannot.
    pub limitation: String,
}

impl ReviewedCoverage {
    /// A complete, declared extent that reviewed everything it claims.
    pub fn complete() -> Self {
        ReviewedCoverage {
            allows_absence_or_cleanup: true,
            limitation: String::new(),
        }
    }

    /// A ranked or truncated extent that reviewed only part of the corpus.
    pub fn incomplete(limitation: impl Into<String>) -> Self {
        ReviewedCoverage {
            allows_absence_or_cleanup: false,
            limitation: limitation.into(),
        }
    }

    /// The coverage the batch itself claims.
    pub fn from_batch(batch: &crate::InputBatch) -> Self {
        if batch.allows_absence_or_cleanup() {
            ReviewedCoverage::complete()
        } else {
            match &batch.coverage {
                crate::BatchCoverage::Partial { reason }
                | crate::BatchCoverage::Unknown { reason } => ReviewedCoverage::incomplete(reason),
                crate::BatchCoverage::Complete => {
                    ReviewedCoverage::incomplete("the reviewed extent is not exhaustive".to_owned())
                }
            }
        }
    }
}

/// A registered proposal plus the state it was reviewed against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredProposal {
    pub proposal: crate::Proposal,
    pub proposal_revision: u64,
    pub expected: AcceptanceState,
    pub coverage: ReviewedCoverage,
}

/// A registration request: the proposal and everything it was reviewed under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    pub proposal: crate::Proposal,
    pub proposal_revision: u64,
    pub expected: AcceptanceState,
    pub coverage: ReviewedCoverage,
}

/// Read-only proposal inspection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalInspection {
    pub proposal: crate::Proposal,
    pub proposal_revision: u64,
    pub expected: AcceptanceState,
    pub current: AcceptanceState,
}

/// A compare-and-swap acceptance command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptanceCommand {
    pub idempotency_key: String,
    pub proposal_id: String,
    pub proposal_revision: u64,
    pub expected: AcceptanceState,
    pub decision: mneme_core::RecordId,
}

/// A separate rejection command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejectionCommand {
    pub idempotency_key: String,
    pub proposal_id: String,
    pub proposal_revision: u64,
    pub reason: String,
}

/// A separate procedural acceptance command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcedureAcceptanceCommand {
    pub idempotency_key: String,
    pub proposal_id: String,
    pub proposal_revision: u64,
    pub expected: AcceptanceState,
    pub decision: mneme_core::RecordId,
}

/// Why acceptance or rejection did not apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictKind {
    MissingProposal,
    StaleProposalRevision,
    StaleBase,
    StaleGeneration,
    ChangedPolicy,
    Unauthorized,
    ChangedTarget,
    AlteredSource,
    ForgottenSource,
    PrunedSource,
    CorruptSource,
    IncompleteCoverage,
    AlreadyDecided,
    ProcedureRequiresValidator,
    UnsupportedAcceptance,
    IdempotencyMismatch,
}

/// A terminal or conflict result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandOutcome {
    Accepted {
        proposal_id: String,
        decision: mneme_core::RecordId,
        proposal_revision: u64,
    },
    Rejected {
        proposal_id: String,
        reason: String,
        proposal_revision: u64,
    },
    Conflict {
        kind: ConflictKind,
        detail: String,
    },
}

/// Why a proposal could not be registered.
///
/// The kind is the one acceptance reports for the same refusal, so a caller that
/// handles a conflict handles a refused registration without a second rule.
/// A refused registration stores nothing: the proposal and the text derived from
/// its premises never enter the registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationRefusal {
    /// The conflict kind acceptance would report for this refusal.
    pub kind: ConflictKind,
    /// What about the proposal or the observed state refused it.
    pub detail: String,
}

impl RegistrationRefusal {
    fn new(kind: ConflictKind, detail: impl Into<String>) -> Self {
        RegistrationRefusal {
            kind,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for RegistrationRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for RegistrationRefusal {}

/// In-memory proposal registry with CAS commands. The registry never applies an
/// acceptance from a generation run; callers must issue one of these commands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalRegistry {
    pub current: AcceptanceState,
    proposals: std::collections::BTreeMap<String, RegisteredProposal>,
    acceptances: std::collections::BTreeMap<String, (AcceptanceCommand, CommandOutcome)>,
    rejections: std::collections::BTreeMap<String, (RejectionCommand, CommandOutcome)>,
    procedure_acceptances:
        std::collections::BTreeMap<String, (ProcedureAcceptanceCommand, CommandOutcome)>,
}

impl ProposalRegistry {
    pub fn new(current: AcceptanceState) -> Self {
        ProposalRegistry {
            current,
            proposals: std::collections::BTreeMap::new(),
            acceptances: std::collections::BTreeMap::new(),
            rejections: std::collections::BTreeMap::new(),
            procedure_acceptances: std::collections::BTreeMap::new(),
        }
    }

    /// Register a reviewed proposal under the state it was reviewed against.
    ///
    /// Registration is where the workspace state is bound to the proposal: the
    /// proposal's own base revision, policy and generation must equal the
    /// observed ones, every operation target must be pinned, and an absence or
    /// cleanup conclusion needs a complete reviewed extent. Without these
    /// checks a stale proposal would be silently rebased onto a newer state.
    ///
    /// A proposal whose premise is no longer quotable is refused here, with the
    /// same [`ConflictKind`] acceptance would report: registering it would keep
    /// derived text of pruned, erased, corrupt or forgotten content in the
    /// registry for as long as it lives. Nothing is stored on refusal.
    pub fn register(&mut self, registration: Registration) -> Result<(), RegistrationRefusal> {
        let Registration {
            proposal,
            proposal_revision,
            expected,
            coverage,
        } = registration;
        if let Some(denial) = self.refusal(&proposal, proposal_revision, &expected, &coverage) {
            return Err(denial);
        }
        self.proposals.insert(
            proposal.proposal_id.clone(),
            RegisteredProposal {
                proposal,
                proposal_revision,
                expected,
                coverage,
            },
        );
        Ok(())
    }

    /// The refusal a registration earns against the observed state, if any.
    ///
    /// The checks run in the order their conflicts are most specific: a
    /// mistyped revision or an already decided proposal is reported before the
    /// pinned state is compared at all.
    fn refusal(
        &self,
        proposal: &crate::Proposal,
        proposal_revision: u64,
        expected: &AcceptanceState,
        coverage: &ReviewedCoverage,
    ) -> Option<RegistrationRefusal> {
        if proposal_revision == 0 {
            return Some(RegistrationRefusal::new(
                ConflictKind::StaleProposalRevision,
                "proposal revision must be positive",
            ));
        }
        if self.proposals.contains_key(&proposal.proposal_id) {
            return Some(RegistrationRefusal::new(
                ConflictKind::AlreadyDecided,
                "proposal is already registered",
            ));
        }
        let unsupported =
            |detail: String| RegistrationRefusal::new(ConflictKind::UnsupportedAcceptance, detail);
        if let Err(detail) = proposal.validate() {
            return Some(unsupported(detail));
        }
        for premise in &proposal.premises {
            if let Some((kind, detail)) = premise_conflict(premise, expected, expected) {
                return Some(RegistrationRefusal::new(kind, detail));
            }
        }
        if proposal.scope != expected.scope {
            return Some(RegistrationRefusal::new(
                ConflictKind::Unauthorized,
                "proposal scope does not match the acceptance state",
            ));
        }
        if proposal.base_revision != expected.base_revision {
            return Some(RegistrationRefusal::new(
                ConflictKind::StaleBase,
                "proposal base revision does not match the observed state",
            ));
        }
        if proposal.policy_version != expected.policy_version {
            return Some(RegistrationRefusal::new(
                ConflictKind::ChangedPolicy,
                "proposal policy version does not match the observed state",
            ));
        }
        if proposal.eligibility_generation != expected.eligibility_generation {
            return Some(RegistrationRefusal::new(
                ConflictKind::StaleGeneration,
                "proposal generation does not match the observed state",
            ));
        }
        for target in proposal.operation_targets() {
            if !expected.targets.contains_key(&target) {
                return Some(RegistrationRefusal::new(
                    ConflictKind::ChangedTarget,
                    "proposal target is not pinned by the acceptance state",
                ));
            }
        }
        if needs_complete_extent(proposal) && !coverage.allows_absence_or_cleanup {
            return Some(RegistrationRefusal::new(
                ConflictKind::IncompleteCoverage,
                "an absence or cleanup proposal needs a complete reviewed extent",
            ));
        }
        None
    }

    /// Inspect a proposal without mutating it.
    ///
    /// A proposal whose premises are forgotten is refused outright: serving it
    /// would keep the forgotten citation, and its summary or value, in front of
    /// a caller.
    pub fn inspect(&self, proposal_id: &str) -> Result<ProposalInspection, String> {
        let registered = self
            .proposals
            .get(proposal_id)
            .ok_or_else(|| "unknown proposal".to_owned())?;
        if self.is_suppressed(registered) {
            return Err("proposal is suppressed by retention".to_owned());
        }
        Ok(ProposalInspection {
            proposal: registered.proposal.clone(),
            proposal_revision: registered.proposal_revision,
            expected: registered.expected.clone(),
            current: self.current.clone(),
        })
    }

    /// Block and redact every proposal that depends on forgotten content.
    ///
    /// In-flight outputs derived from forgotten bytes are suppressed here, not
    /// only at the next acceptance attempt, so nothing keeps serving them.
    /// Returns the identities that are suppressed.
    pub fn suppress_forgotten(&mut self) -> Vec<String> {
        let suppressed = self
            .proposals
            .iter()
            .filter(|(_, registered)| self.is_suppressed(registered))
            .map(|(proposal_id, _)| proposal_id.clone())
            .collect::<Vec<_>>();
        for proposal_id in &suppressed {
            if let Some(registered) = self.proposals.get_mut(proposal_id) {
                registered
                    .proposal
                    .suppress("proposal depends on explicitly forgotten evidence");
            }
        }
        suppressed
    }

    /// Why one registered proposal was suppressed by retention.
    ///
    /// A suppressed proposal keeps only its identity and this reason; `None`
    /// means it is not suppressed, so a caller can answer later commands about a
    /// blocked proposal without the content it was derived from.
    pub fn suppression_reason(&self, proposal_id: &str) -> Option<&str> {
        let registered = self.proposals.get(proposal_id)?;
        if !self.is_suppressed(registered) {
            return None;
        }
        match &registered.proposal.disposition {
            crate::ProposalDisposition::Blocked { reason } => Some(reason.as_str()),
            crate::ProposalDisposition::Pending
            | crate::ProposalDisposition::Accepted { .. }
            | crate::ProposalDisposition::Rejected { .. } => None,
        }
    }

    /// Apply a compare-and-swap acceptance or report a conflict/prior outcome.
    pub fn accept(&mut self, command: AcceptanceCommand) -> CommandOutcome {
        if let Some(outcome) = self.prior_acceptance(&command) {
            return outcome;
        }
        let Some(registered) = self.proposals.get(&command.proposal_id).cloned() else {
            return self.conflict(ConflictKind::MissingProposal, "proposal is not registered");
        };
        if let Some(outcome) =
            self.validate_preconditions(&command.proposal_revision, &command.expected, &registered)
        {
            return outcome;
        }
        if matches!(
            &registered.proposal.operation,
            crate::ProposalOperation::Procedure(_)
        ) {
            return self.conflict(
                ConflictKind::ProcedureRequiresValidator,
                "procedural proposal requires its separate validator command",
            );
        }
        if !matches!(
            &registered.proposal.support.outcome,
            crate::SupportOutcome::Supported
        ) {
            return self.conflict(
                ConflictKind::UnsupportedAcceptance,
                "proposal support was not accepted by review",
            );
        }
        let Some(registered) = self.proposals.get_mut(&command.proposal_id) else {
            return self.conflict(ConflictKind::MissingProposal, "proposal disappeared");
        };
        registered.proposal.disposition = crate::ProposalDisposition::Accepted {
            decision: command.decision,
        };
        registered.proposal_revision = registered.proposal_revision.saturating_add(1);
        let outcome = CommandOutcome::Accepted {
            proposal_id: command.proposal_id.clone(),
            decision: command.decision,
            proposal_revision: registered.proposal_revision,
        };
        self.acceptances
            .insert(command.idempotency_key.clone(), (command, outcome.clone()));
        outcome
    }

    /// Reject a pending proposal. This is a separate command from acceptance.
    pub fn reject(&mut self, command: RejectionCommand) -> CommandOutcome {
        if command.reason.trim().is_empty() {
            return self.conflict(
                ConflictKind::UnsupportedAcceptance,
                "rejection reason is required",
            );
        }
        if let Some((stored, outcome)) = self.rejections.get(&command.idempotency_key) {
            return if stored == &command {
                outcome.clone()
            } else {
                self.conflict(
                    ConflictKind::IdempotencyMismatch,
                    "idempotency key was reused with a different rejection",
                )
            };
        }
        let Some(registered) = self.proposals.get(&command.proposal_id).cloned() else {
            return self.conflict(ConflictKind::MissingProposal, "proposal is not registered");
        };
        if !matches!(
            &registered.proposal.disposition,
            crate::ProposalDisposition::Pending
        ) {
            return self.conflict(
                ConflictKind::AlreadyDecided,
                "proposal already has a terminal disposition",
            );
        }
        if registered.proposal_revision != command.proposal_revision {
            return self.conflict(
                ConflictKind::StaleProposalRevision,
                "proposal revision changed",
            );
        }
        let Some(registered) = self.proposals.get_mut(&command.proposal_id) else {
            return self.conflict(ConflictKind::MissingProposal, "proposal disappeared");
        };
        registered.proposal.disposition = crate::ProposalDisposition::Rejected {
            reason: command.reason.clone(),
        };
        registered.proposal_revision = registered.proposal_revision.saturating_add(1);
        let outcome = CommandOutcome::Rejected {
            proposal_id: command.proposal_id.clone(),
            reason: command.reason.clone(),
            proposal_revision: registered.proposal_revision,
        };
        self.rejections
            .insert(command.idempotency_key.clone(), (command, outcome.clone()));
        outcome
    }

    /// Validate and accept a procedural proposal through its own command.
    ///
    /// The same state, source and coverage preconditions as ordinary acceptance
    /// run first, so a stale base, a forgotten premise or an incomplete reviewed
    /// extent is refused before any validator is consulted. The validator then
    /// inspects content only: no instruction, rule, or tool is executed and
    /// worker privileges are not mutated.
    pub fn accept_procedure(
        &mut self,
        command: ProcedureAcceptanceCommand,
        validator: &dyn ProcedureValidator,
        privileges: &crate::flow::WorkerPrivileges,
    ) -> CommandOutcome {
        if let Some(outcome) = self.prior_procedure_acceptance(&command) {
            return outcome;
        }
        let Some(registered) = self.proposals.get(&command.proposal_id).cloned() else {
            return self.conflict(ConflictKind::MissingProposal, "proposal is not registered");
        };
        if let Some(outcome) =
            self.validate_preconditions(&command.proposal_revision, &command.expected, &registered)
        {
            return outcome;
        }
        if !matches!(
            &registered.proposal.operation,
            crate::ProposalOperation::Procedure(_)
        ) {
            return self.conflict(
                ConflictKind::UnsupportedAcceptance,
                "proposal is not procedural",
            );
        }
        let validation =
            match crate::flow::validate_procedure(&registered.proposal, validator, privileges) {
                Ok(validation) => validation,
                Err(error) => {
                    return self.conflict(ConflictKind::UnsupportedAcceptance, &error);
                }
            };
        if !validation.approved {
            return self.conflict(
                ConflictKind::UnsupportedAcceptance,
                "procedural validator rejected the proposal",
            );
        }
        let Some(registered) = self.proposals.get_mut(&command.proposal_id) else {
            return self.conflict(ConflictKind::MissingProposal, "proposal disappeared");
        };
        registered.proposal.disposition = crate::ProposalDisposition::Accepted {
            decision: command.decision,
        };
        registered.proposal_revision = registered.proposal_revision.saturating_add(1);
        let outcome = CommandOutcome::Accepted {
            proposal_id: command.proposal_id.clone(),
            decision: command.decision,
            proposal_revision: registered.proposal_revision,
        };
        self.procedure_acceptances
            .insert(command.idempotency_key.clone(), (command, outcome.clone()));
        outcome
    }

    /// Whether this proposal's premises or ancestry reach forgotten content.
    fn is_suppressed(&self, registered: &RegisteredProposal) -> bool {
        if registered.proposal.premises.is_empty()
            && matches!(
                registered.proposal.disposition,
                crate::ProposalDisposition::Blocked { .. }
            )
        {
            return true;
        }
        registered.proposal.premises.iter().any(|premise| {
            self.current.forgotten.contains(&premise.record_id)
                || premise
                    .ancestry_roots
                    .iter()
                    .any(|root| self.current.forgotten.contains(&root.record_id))
        })
    }

    fn prior_acceptance(&self, command: &AcceptanceCommand) -> Option<CommandOutcome> {
        self.acceptances
            .get(&command.idempotency_key)
            .map(|(stored, outcome)| {
                if stored == command {
                    outcome.clone()
                } else {
                    self.conflict(
                        ConflictKind::IdempotencyMismatch,
                        "idempotency key was reused with a different acceptance",
                    )
                }
            })
    }

    fn prior_procedure_acceptance(
        &self,
        command: &ProcedureAcceptanceCommand,
    ) -> Option<CommandOutcome> {
        self.procedure_acceptances
            .get(&command.idempotency_key)
            .map(|(stored, outcome)| {
                if stored == command {
                    outcome.clone()
                } else {
                    self.conflict(
                        ConflictKind::IdempotencyMismatch,
                        "idempotency key was reused with a different procedural acceptance",
                    )
                }
            })
    }

    /// Every precondition both acceptance paths share.
    fn validate_preconditions(
        &self,
        proposal_revision: &u64,
        expected: &AcceptanceState,
        registered: &RegisteredProposal,
    ) -> Option<CommandOutcome> {
        if !matches!(
            registered.proposal.disposition,
            crate::ProposalDisposition::Pending
        ) {
            return Some(self.conflict(
                ConflictKind::AlreadyDecided,
                "proposal already has a terminal disposition",
            ));
        }
        if &registered.proposal_revision != proposal_revision {
            return Some(self.conflict(
                ConflictKind::StaleProposalRevision,
                "proposal revision changed",
            ));
        }
        if expected != &registered.expected {
            return Some(self.conflict(
                ConflictKind::ChangedTarget,
                "acceptance preconditions differ from the reviewed proposal",
            ));
        }
        if self.current.base_revision != registered.expected.base_revision {
            return Some(self.conflict(ConflictKind::StaleBase, "base revision changed"));
        }
        if self.current.scope != registered.expected.scope
            || registered.proposal.scope != self.current.scope
        {
            return Some(self.conflict(
                ConflictKind::Unauthorized,
                "proposal is outside the current authorized scope",
            ));
        }
        if self.current.eligibility_generation != registered.expected.eligibility_generation {
            return Some(self.conflict(
                ConflictKind::StaleGeneration,
                "eligibility generation changed",
            ));
        }
        if self.current.policy_version != registered.proposal.policy_version
            || registered.expected.policy_version != registered.proposal.policy_version
        {
            return Some(self.conflict(
                ConflictKind::ChangedPolicy,
                "consolidation policy changed since review",
            ));
        }
        if needs_complete_extent(&registered.proposal)
            && !registered.coverage.allows_absence_or_cleanup
        {
            return Some(self.conflict(
                ConflictKind::IncompleteCoverage,
                "absence or cleanup conclusion needs a complete reviewed extent",
            ));
        }
        if self.current.targets != registered.expected.targets {
            return Some(self.conflict(ConflictKind::ChangedTarget, "target revision changed"));
        }
        self.validate_acceptance_sources(registered)
    }

    fn validate_acceptance_sources(
        &self,
        registered: &RegisteredProposal,
    ) -> Option<CommandOutcome> {
        for premise in &registered.proposal.premises {
            if let Some((kind, detail)) =
                premise_conflict(premise, &self.current, &registered.expected)
            {
                return Some(self.conflict(kind, detail));
            }
        }
        None
    }

    fn conflict(&self, kind: ConflictKind, detail: &str) -> CommandOutcome {
        CommandOutcome::Conflict {
            kind,
            detail: detail.to_owned(),
        }
    }
}

/// Whether an absence or cleanup conclusion needs a complete reviewed extent.
fn needs_complete_extent(proposal: &crate::Proposal) -> bool {
    matches!(
        &proposal.operation,
        crate::ProposalOperation::Absence(_) | crate::ProposalOperation::Cleanup(_)
    )
}

/// The conflict one premise raises against `current`.
///
/// Registration and acceptance share this rule, so a premise that is forgotten,
/// gone, pruned or corrupt is refused at both boundaries with one kind. `current`
/// and `expected` are the same state at registration, which makes the digest
/// comparison a no-op and leaves the availability checks to decide.
fn premise_conflict(
    premise: &crate::ProposalPremise,
    current: &AcceptanceState,
    expected: &AcceptanceState,
) -> Option<(ConflictKind, &'static str)> {
    if current.forgotten.contains(&premise.record_id)
        || premise
            .ancestry_roots
            .iter()
            .any(|root| current.forgotten.contains(&root.record_id))
    {
        return Some((
            ConflictKind::ForgottenSource,
            "proposal depends on explicitly forgotten evidence",
        ));
    }
    let key = crate::InputKey {
        record_id: premise.record_id,
        revision_id: premise.revision_id,
    };
    let Some(current_source) = current.sources.get(&key) else {
        return Some((ConflictKind::AlteredSource, "source is no longer present"));
    };
    if expected
        .sources
        .get(&key)
        .is_none_or(|pinned| pinned.digest() != current_source.digest())
    {
        return Some((ConflictKind::AlteredSource, "source digest changed"));
    }
    match current_source {
        SourceState::Forgotten { .. } => Some((
            ConflictKind::ForgottenSource,
            "proposal source was forgotten",
        )),
        SourceState::Absent { .. } => Some((
            ConflictKind::AlteredSource,
            "proposal source is no longer present",
        )),
        SourceState::Pruned { .. } if premise.span.is_some() => Some((
            ConflictKind::PrunedSource,
            "proposal requires pruned source bytes",
        )),
        SourceState::Corrupt { .. } if premise.span.is_some() => Some((
            ConflictKind::CorruptSource,
            "proposal requires source bytes that cannot be read",
        )),
        SourceState::Retained { .. } | SourceState::Pruned { .. } | SourceState::Corrupt { .. } => {
            None
        }
    }
}

/// The exact content identity of one premise revision in the current view.
fn premise_state(view: &mneme_memory::View, premise: &crate::ProposalPremise) -> SourceState {
    let Ok(current) = view.record(premise.record_id) else {
        return SourceState::Absent {
            digest: String::new(),
        };
    };
    if !view.access().allows(&current.scope) {
        return SourceState::Absent {
            digest: String::new(),
        };
    }
    if current.kind != mneme_core::RecordKind::SourceRevision {
        return SourceState::Retained {
            digest: payload_identity(&current.payload),
        };
    }
    let Ok(pinned) = view.source_at(premise.record_id, premise.revision_id) else {
        return SourceState::Absent {
            digest: payload_identity(&current.payload),
        };
    };
    let digest = match pinned.digest().or(pinned.prior_digest) {
        Some(digest) => content_identity(digest),
        None => payload_identity(&pinned.record.payload),
    };
    match view.source_status_for(&pinned) {
        Ok(mneme_memory::SourceStatus::Retained(_)) => SourceState::Retained { digest },
        Ok(status) => match status.availability() {
            mneme_memory::SourceAvailability::Pruned => SourceState::Pruned { digest },
            mneme_memory::SourceAvailability::Erased => SourceState::Forgotten { digest },
            mneme_memory::SourceAvailability::Retained => SourceState::Retained { digest },
            mneme_memory::SourceAvailability::Inaccessible
            | mneme_memory::SourceAvailability::Corrupt { .. }
            | mneme_memory::SourceAvailability::Unavailable { .. } => {
                SourceState::Corrupt { digest }
            }
        },
        Err(_) => SourceState::Corrupt { digest },
    }
}

/// Render a content digest as a stable identity string.
fn content_identity(digest: mneme_core::ContentDigest) -> String {
    format!("sha256:{}", digest.to_hex())
}

/// The identity of one record revision's payload, for premises with no bytes.
fn payload_identity(payload: &mneme_core::Payload) -> String {
    content_identity(mneme_core::ContentDigest::of_payload(&payload.to_value()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_key() -> crate::InputKey {
        crate::InputKey {
            record_id: mneme_core::RecordId::from_bytes([0x20; 16]),
            revision_id: mneme_core::RevisionId::from_bytes([0x21; 16]),
        }
    }

    fn state() -> AcceptanceState {
        let fixture = crate::fixture().expect("fixture");
        AcceptanceState {
            scope: fixture.job.scope.clone(),
            base_revision: fixture.job.base_revision,
            eligibility_generation: fixture.job.batch.eligibility_generation,
            policy_version: "consolidation-policy/v1".to_owned(),
            forgotten: std::collections::BTreeSet::new(),
            targets: std::collections::BTreeMap::new(),
            sources: std::collections::BTreeMap::from([(
                source_key(),
                SourceState::Retained {
                    digest: "sha256:source".to_owned(),
                },
            )]),
        }
    }

    fn registration() -> Registration {
        let fixture = crate::fixture().expect("fixture");
        Registration {
            proposal: fixture.proposals[0].clone(),
            proposal_revision: 1,
            expected: state(),
            coverage: ReviewedCoverage::from_batch(&fixture.job.batch),
        }
    }

    fn command() -> AcceptanceCommand {
        AcceptanceCommand {
            idempotency_key: "accept-1".to_owned(),
            proposal_id: "proposal-summary".to_owned(),
            proposal_revision: 1,
            expected: state(),
            decision: mneme_core::RecordId::from_bytes([0x50; 16]),
        }
    }

    fn registry() -> ProposalRegistry {
        let mut registry = ProposalRegistry::new(state());
        registry.register(registration()).expect("register");
        registry
    }

    #[test]
    fn inspection_is_read_only() {
        let registry = registry();
        let before = registry.clone();
        let inspection = registry.inspect("proposal-summary").expect("inspect");
        assert!(matches!(
            inspection.proposal.disposition,
            crate::ProposalDisposition::Pending
        ));
        assert_eq!(registry, before);
    }

    #[test]
    fn stale_base_changed_target_and_altered_source_conflict() {
        for kind in [
            ConflictKind::StaleBase,
            ConflictKind::ChangedTarget,
            ConflictKind::AlteredSource,
        ] {
            let mut registry = registry();
            if kind == ConflictKind::StaleBase {
                registry.current.base_revision =
                    mneme_core::WorkspaceRevisionId::from_bytes([0x99; 16]);
            } else if kind == ConflictKind::ChangedTarget {
                registry.current.targets.insert(
                    mneme_core::RecordId::from_bytes([0x40; 16]),
                    mneme_core::RevisionId::from_bytes([0x99; 16]),
                );
            } else {
                registry.current.sources.insert(
                    source_key(),
                    SourceState::Retained {
                        digest: "sha256:altered".to_owned(),
                    },
                );
            }
            let outcome = registry.accept(command());
            assert!(matches!(
                outcome,
                CommandOutcome::Conflict { kind: actual, .. } if actual == kind
            ));
            assert!(
                registry
                    .inspect("proposal-summary")
                    .expect("inspect")
                    .proposal
                    .disposition
                    == crate::ProposalDisposition::Pending
            );
        }
    }

    #[test]
    fn repeated_acceptance_returns_the_recorded_outcome() {
        let mut registry = registry();
        let first = registry.accept(command());
        assert!(matches!(first, CommandOutcome::Accepted { .. }));
        let revision = registry
            .inspect("proposal-summary")
            .expect("inspect")
            .proposal_revision;
        let second = registry.accept(command());
        assert_eq!(second, first);
        assert_eq!(
            registry
                .inspect("proposal-summary")
                .expect("inspect")
                .proposal_revision,
            revision
        );
    }

    #[test]
    fn different_key_after_acceptance_conflicts() {
        let mut registry = registry();
        assert!(matches!(
            registry.accept(command()),
            CommandOutcome::Accepted { .. }
        ));
        let mut next = command();
        next.idempotency_key = "accept-2".to_owned();
        assert!(matches!(
            registry.accept(next),
            CommandOutcome::Conflict {
                kind: ConflictKind::AlreadyDecided,
                ..
            }
        ));
    }

    #[test]
    fn rejection_is_separate_and_idempotent() {
        let mut registry = registry();
        let rejection = RejectionCommand {
            idempotency_key: "reject-1".to_owned(),
            proposal_id: "proposal-summary".to_owned(),
            proposal_revision: 1,
            reason: "unsupported interpretation".to_owned(),
        };
        let first = registry.reject(rejection.clone());
        assert!(matches!(first, CommandOutcome::Rejected { .. }));
        assert_eq!(registry.reject(rejection), first);
        assert!(matches!(
            registry.accept(command()),
            CommandOutcome::Conflict {
                kind: ConflictKind::AlreadyDecided,
                ..
            }
        ));
    }

    #[test]
    fn forgotten_evidence_blocks_acceptance_and_replay() {
        let mut registry = registry();
        registry
            .current
            .forgotten
            .insert(mneme_core::RecordId::from_bytes([0x20; 16]));
        let first = registry.accept(command());
        assert!(matches!(
            first,
            CommandOutcome::Conflict {
                kind: ConflictKind::ForgottenSource,
                ..
            }
        ));
        assert_eq!(registry.accept(command()), first);
    }

    #[test]
    fn pruned_bytes_block_quotation_but_allow_claim_envelope() {
        let mut quoted = registry();
        quoted.current.sources.insert(
            source_key(),
            SourceState::Pruned {
                digest: "sha256:source".to_owned(),
            },
        );
        assert!(matches!(
            quoted.accept(command()),
            CommandOutcome::Conflict {
                kind: ConflictKind::PrunedSource,
                ..
            }
        ));

        let mut envelope = registry();
        envelope
            .proposals
            .get_mut("proposal-summary")
            .expect("proposal")
            .proposal
            .premises[0]
            .span = None;
        let mut envelope_command = command();
        envelope_command.idempotency_key = "accept-envelope".to_owned();
        envelope.current.sources.insert(
            source_key(),
            SourceState::Pruned {
                digest: "sha256:source".to_owned(),
            },
        );
        let outcome = envelope.accept(envelope_command);
        assert!(
            matches!(outcome, CommandOutcome::Accepted { .. }),
            "{outcome:?}"
        );
    }

    #[test]
    fn corrupt_bytes_block_quotation_but_allow_claim_envelope() {
        let mut registry = registry();
        registry.current.sources.insert(
            source_key(),
            SourceState::Corrupt {
                digest: "sha256:source".to_owned(),
            },
        );
        assert!(matches!(
            registry.accept(command()),
            CommandOutcome::Conflict {
                kind: ConflictKind::CorruptSource,
                ..
            }
        ));
    }

    #[test]
    fn generation_scope_and_policy_changes_conflict() {
        let mut generation = registry();
        generation.current.eligibility_generation += 1;
        assert!(matches!(
            generation.accept(command()),
            CommandOutcome::Conflict {
                kind: ConflictKind::StaleGeneration,
                ..
            }
        ));

        let mut scope = registry();
        scope.current.scope =
            mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "birch").expect("scope");
        assert!(matches!(
            scope.accept(command()),
            CommandOutcome::Conflict {
                kind: ConflictKind::Unauthorized,
                ..
            }
        ));

        let mut policy = registry();
        policy.current.policy_version = "consolidation-policy/v2".to_owned();
        assert!(matches!(
            policy.accept(command()),
            CommandOutcome::Conflict {
                kind: ConflictKind::ChangedPolicy,
                ..
            }
        ));
    }

    #[test]
    fn registration_rebinds_nothing_and_pins_its_state() {
        let mut stale = registration();
        stale.expected.base_revision = mneme_core::WorkspaceRevisionId::from_bytes([0x99; 16]);
        let mut registry = ProposalRegistry::new(stale.expected.clone());
        assert!(registry.register(stale).is_err());

        let mut generation = registration();
        generation.expected.eligibility_generation = 7;
        let mut registry = ProposalRegistry::new(generation.expected.clone());
        assert!(registry.register(generation).is_err());

        let mut policy = registration();
        policy.expected.policy_version = "consolidation-policy/v2".to_owned();
        let mut registry = ProposalRegistry::new(policy.expected.clone());
        assert!(registry.register(policy).is_err());

        let mut unpinned = registration();
        unpinned.proposal.operation =
            crate::ProposalOperation::Supersession(crate::SupersessionProposal {
                prior: mneme_core::RecordId::from_bytes([0x40; 16]),
                prior_authority: crate::ProposalAuthority::Authored,
                replacement: mneme_core::Value::string("PostgreSQL"),
                reason: "the source corrects the engine".to_owned(),
                basis: crate::SupersessionBasis::ExplicitCorrection,
            });
        let mut registry = ProposalRegistry::new(unpinned.expected.clone());
        assert!(registry.register(unpinned).is_err());

        let mut pinned = registration();
        pinned.proposal.operation =
            crate::ProposalOperation::Supersession(crate::SupersessionProposal {
                prior: mneme_core::RecordId::from_bytes([0x40; 16]),
                prior_authority: crate::ProposalAuthority::Authored,
                replacement: mneme_core::Value::string("PostgreSQL"),
                reason: "the source corrects the engine".to_owned(),
                basis: crate::SupersessionBasis::ExplicitCorrection,
            });
        pinned.expected.targets.insert(
            mneme_core::RecordId::from_bytes([0x40; 16]),
            mneme_core::RevisionId::from_bytes([0x41; 16]),
        );
        let mut registry = ProposalRegistry::new(pinned.expected.clone());
        registry.register(pinned).expect("pinned supersession");
    }

    #[test]
    fn unsupported_support_cannot_be_accepted() {
        for outcome in [
            crate::SupportOutcome::Rejected,
            crate::SupportOutcome::UnsupportedHypothesis,
        ] {
            let mut registration = registration();
            registration.proposal.support = crate::SupportReview {
                actor: "reviewer".to_owned(),
                policy: "semantic-support/v1".to_owned(),
                outcome,
                detail: "cited bytes do not support the claim".to_owned(),
            };
            let mut registry = ProposalRegistry::new(registration.expected.clone());
            registry.register(registration).expect("register");
            assert!(matches!(
                registry.accept(command()),
                CommandOutcome::Conflict {
                    kind: ConflictKind::UnsupportedAcceptance,
                    ..
                }
            ));
            assert!(matches!(
                registry
                    .inspect("proposal-summary")
                    .expect("inspect")
                    .proposal
                    .disposition,
                crate::ProposalDisposition::Pending
            ));
        }
    }

    #[test]
    fn absence_and_cleanup_need_complete_coverage_at_acceptance() {
        for operation in [
            crate::ProposalOperation::Absence(crate::AbsenceProposal {
                subject: mneme_core::RecordId::from_bytes([0x10; 16]),
                predicate: "storage-engine".to_owned(),
                reason: "no retained source names one".to_owned(),
            }),
            crate::ProposalOperation::Cleanup(crate::CleanupProposal {
                records: std::collections::BTreeSet::from([mneme_core::RecordId::from_bytes(
                    [0x40; 16],
                )]),
                reason: "remove stale memory".to_owned(),
            }),
        ] {
            let mut candidate = registration();
            candidate.proposal.operation = operation.clone();
            for target in candidate.proposal.operation_targets() {
                candidate
                    .expected
                    .targets
                    .insert(target, mneme_core::RevisionId::from_bytes([0x41; 16]));
            }
            candidate.coverage =
                ReviewedCoverage::incomplete("ranked recall is not a complete extent");
            let mut registry = ProposalRegistry::new(candidate.expected.clone());
            assert!(registry.register(candidate).is_err());

            let mut complete = registration();
            complete.proposal.operation = operation;
            for target in complete.proposal.operation_targets() {
                complete
                    .expected
                    .targets
                    .insert(target, mneme_core::RevisionId::from_bytes([0x41; 16]));
            }
            complete.coverage = ReviewedCoverage::complete();
            let expected = complete.expected.clone();
            let mut registry = ProposalRegistry::new(expected.clone());
            registry.register(complete).expect("complete extent");
            // A registration that recorded only a partial extent can never
            // certify absence or cleanup, even when the acceptance state still
            // matches.
            registry
                .proposals
                .get_mut("proposal-summary")
                .expect("proposal")
                .coverage = ReviewedCoverage::incomplete("withheld extent");
            assert!(matches!(
                registry.accept(AcceptanceCommand {
                    idempotency_key: "accept-coverage".to_owned(),
                    proposal_id: "proposal-summary".to_owned(),
                    proposal_revision: 1,
                    expected,
                    decision: mneme_core::RecordId::from_bytes([0x50; 16]),
                }),
                CommandOutcome::Conflict {
                    kind: ConflictKind::IncompleteCoverage,
                    ..
                }
            ));
        }
    }

    #[test]
    fn forgotten_premises_suppress_in_flight_outputs() {
        let mut registry = registry();
        registry
            .current
            .forgotten
            .insert(mneme_core::RecordId::from_bytes([0x20; 16]));
        assert!(registry.inspect("proposal-summary").is_err());
        assert_eq!(
            registry.suppress_forgotten(),
            vec!["proposal-summary".to_owned()]
        );
        let inspection = registry
            .proposals
            .get("proposal-summary")
            .expect("proposal");
        assert!(matches!(
            inspection.proposal.disposition,
            crate::ProposalDisposition::Blocked { .. }
        ));
        assert!(inspection.proposal.premises.is_empty());
        let redacted = match &inspection.proposal.operation {
            crate::ProposalOperation::Summary(summary) => summary.text.clone(),
            _ => "not-a-summary".to_owned(),
        };
        assert!(redacted.is_empty());
        assert!(registry.inspect("proposal-summary").is_err());
        assert!(matches!(
            registry.accept(command()),
            CommandOutcome::Conflict {
                kind: ConflictKind::AlreadyDecided,
                ..
            }
        ));
        assert_eq!(registry.suppress_forgotten().len(), 1);
    }

    #[test]
    fn registration_refuses_premises_that_are_not_quotable() {
        // A premise record already forgotten in the observed state.
        let mut forgotten = registration();
        forgotten
            .expected
            .forgotten
            .insert(mneme_core::RecordId::from_bytes([0x20; 16]));
        let mut registry = ProposalRegistry::new(forgotten.expected.clone());
        let refusal = registry.register(forgotten).expect_err("forgotten premise");
        assert_eq!(refusal.kind, ConflictKind::ForgottenSource);
        assert!(
            registry.proposals.is_empty(),
            "a refused proposal was stored"
        );
        assert!(registry.inspect("proposal-summary").is_err());

        // A premise whose ancestry root is forgotten.
        let mut root = registration();
        let ancestry = crate::InputKey {
            record_id: mneme_core::RecordId::from_bytes([0x77; 16]),
            revision_id: mneme_core::RevisionId::from_bytes([0x78; 16]),
        };
        root.proposal.premises[0].ancestry_roots.insert(ancestry);
        root.expected.forgotten.insert(ancestry.record_id);
        let mut registry = ProposalRegistry::new(root.expected.clone());
        assert_eq!(
            registry
                .register(root)
                .expect_err("forgotten ancestry")
                .kind,
            ConflictKind::ForgottenSource
        );
        assert!(registry.proposals.is_empty());

        // Pruned bytes the proposal quotes.
        let mut pruned = registration();
        pruned.expected.sources.insert(
            source_key(),
            SourceState::Pruned {
                digest: "sha256:source".to_owned(),
            },
        );
        let mut registry = ProposalRegistry::new(pruned.expected.clone());
        assert_eq!(
            registry.register(pruned).expect_err("pruned bytes").kind,
            ConflictKind::PrunedSource
        );

        // Unreadable bytes the proposal quotes.
        let mut corrupt = registration();
        corrupt.expected.sources.insert(
            source_key(),
            SourceState::Corrupt {
                digest: "sha256:source".to_owned(),
            },
        );
        let mut registry = ProposalRegistry::new(corrupt.expected.clone());
        assert_eq!(
            registry.register(corrupt).expect_err("corrupt bytes").kind,
            ConflictKind::CorruptSource
        );

        // A premise the observed state no longer holds.
        let mut absent = registration();
        absent.expected.sources.remove(&source_key());
        let mut registry = ProposalRegistry::new(absent.expected.clone());
        assert_eq!(
            registry.register(absent).expect_err("absent source").kind,
            ConflictKind::AlteredSource
        );

        // A claim envelope from pruned bytes cites no span, so it is admissible.
        let mut envelope = registration();
        envelope.proposal.premises[0].span = None;
        envelope.expected.sources.insert(
            source_key(),
            SourceState::Pruned {
                digest: "sha256:source".to_owned(),
            },
        );
        let mut registry = ProposalRegistry::new(envelope.expected.clone());
        registry
            .register(envelope)
            .expect("pruned bytes are not needed for the claim envelope");
    }

    #[test]
    fn suppression_keeps_only_the_identity_and_reason() {
        let mut registry = registry();
        assert!(registry.inspect("proposal-summary").is_ok());
        assert_eq!(registry.suppression_reason("proposal-summary"), None);
        registry
            .current
            .forgotten
            .insert(mneme_core::RecordId::from_bytes([0x20; 16]));
        assert_eq!(
            registry.suppress_forgotten(),
            vec!["proposal-summary".to_owned()]
        );
        {
            let stored = registry
                .proposals
                .get("proposal-summary")
                .expect("proposal");
            assert_eq!(stored.proposal.proposal_id, "proposal-summary");
            assert!(matches!(
                stored.proposal.disposition,
                crate::ProposalDisposition::Blocked { .. }
            ));
            assert!(stored.proposal.premises.is_empty());
            let text = match &stored.proposal.operation {
                crate::ProposalOperation::Summary(summary) => summary.text.clone(),
                _ => "not-a-summary".to_owned(),
            };
            assert!(text.is_empty(), "summary text survived suppression");
            assert_eq!(
                stored.proposal.support.outcome,
                crate::SupportOutcome::Rejected
            );
            assert!(
                !stored.proposal.support.detail.contains("cited span"),
                "support detail survived suppression"
            );
            assert!(!stored.proposal.rationale.contains("summarize"));
        }
        assert_eq!(
            registry.suppression_reason("proposal-summary"),
            Some("proposal depends on explicitly forgotten evidence")
        );
        assert_eq!(registry.suppression_reason("proposal-other"), None);
        assert!(registry.inspect("proposal-summary").is_err());
        assert!(matches!(
            registry.accept(command()),
            CommandOutcome::Conflict {
                kind: ConflictKind::AlreadyDecided,
                ..
            }
        ));
    }

    #[test]
    fn ancestry_roots_are_checked_against_forgotten_content() {
        let mut registration = registration();
        let root = crate::InputKey {
            record_id: mneme_core::RecordId::from_bytes([0x77; 16]),
            revision_id: mneme_core::RevisionId::from_bytes([0x78; 16]),
        };
        registration.proposal.premises[0]
            .ancestry_roots
            .insert(root);
        let mut registry = ProposalRegistry::new(registration.expected.clone());
        registry.register(registration).expect("register");
        registry.current.forgotten.insert(root.record_id);
        assert!(matches!(
            registry.accept(command()),
            CommandOutcome::Conflict {
                kind: ConflictKind::ForgottenSource,
                ..
            }
        ));
        assert!(registry.inspect("proposal-summary").is_err());
    }

    struct TestValidator {
        approved: bool,
        executed: bool,
        effects: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl ProcedureValidator for TestValidator {
        fn identity(&self) -> &str {
            "prolog-policy/v1"
        }

        fn supports(&self, kind: crate::ProcedureKind) -> bool {
            kind == crate::ProcedureKind::Rule
        }

        fn validate(
            &self,
            _procedure: &crate::ProcedureProposal,
            _privileges: &crate::flow::WorkerPrivileges,
        ) -> Result<crate::flow::ProcedureValidation, String> {
            self.effects
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(crate::flow::ProcedureValidation {
                validator: self.identity().to_owned(),
                approved: self.approved,
                rationale: "content inspected as data".to_owned(),
                embedded_instructions_are_data: true,
                executed: self.executed,
            })
        }
    }

    fn procedure_registration() -> Registration {
        let fixture = crate::fixture().expect("fixture");
        let mut registration = registration();
        let mut proposal = fixture.proposals[2].clone();
        proposal.disposition = crate::ProposalDisposition::Pending;
        registration.proposal = proposal;
        registration
    }

    fn procedure_command(registration: &Registration) -> ProcedureAcceptanceCommand {
        ProcedureAcceptanceCommand {
            idempotency_key: "procedure-1".to_owned(),
            proposal_id: "proposal-procedure".to_owned(),
            proposal_revision: 1,
            expected: registration.expected.clone(),
            decision: mneme_core::RecordId::from_bytes([0x60; 16]),
        }
    }

    fn effects() -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
        std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0))
    }

    #[test]
    fn normal_acceptance_requires_the_procedure_validator() {
        let registration = procedure_registration();
        let mut registry = ProposalRegistry::new(registration.expected.clone());
        registry.register(registration).expect("register procedure");
        let mut command = command();
        command.proposal_id = "proposal-procedure".to_owned();
        assert!(matches!(
            registry.accept(command),
            CommandOutcome::Conflict {
                kind: ConflictKind::ProcedureRequiresValidator,
                ..
            }
        ));
    }

    #[test]
    fn procedure_acceptance_rechecks_state_before_any_validator_runs() {
        let registration = procedure_registration();
        let command = procedure_command(&registration);
        let mut registry = ProposalRegistry::new(registration.expected.clone());
        registry.register(registration).expect("register procedure");
        let effects = effects();
        let validator = TestValidator {
            approved: true,
            executed: false,
            effects: effects.clone(),
        };
        let privileges = crate::flow::WorkerPrivileges {
            allowed_tools: std::collections::BTreeSet::from(["recall".to_owned()]),
            may_install_procedures: false,
        };

        registry
            .current
            .forgotten
            .insert(mneme_core::RecordId::from_bytes([0x20; 16]));
        assert!(matches!(
            registry.accept_procedure(command.clone(), &validator, &privileges),
            CommandOutcome::Conflict {
                kind: ConflictKind::ForgottenSource,
                ..
            }
        ));
        assert_eq!(
            effects.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "content must not reach a validator for a blocked proposal"
        );

        registry.current.forgotten.clear();
        registry.current.base_revision = mneme_core::WorkspaceRevisionId::from_bytes([0x99; 16]);
        assert!(matches!(
            registry.accept_procedure(command, &validator, &privileges),
            CommandOutcome::Conflict {
                kind: ConflictKind::StaleBase,
                ..
            }
        ));
        assert_eq!(
            effects.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "content must not reach a validator for a stale proposal"
        );
    }

    #[test]
    fn procedure_validation_cannot_execute_or_change_privileges() {
        let registration = procedure_registration();
        let command = procedure_command(&registration);
        let mut registry = ProposalRegistry::new(registration.expected.clone());
        registry.register(registration).expect("register procedure");
        let privileges = crate::flow::WorkerPrivileges {
            allowed_tools: std::collections::BTreeSet::from(["recall".to_owned()]),
            may_install_procedures: false,
        };
        let before = privileges.clone();
        let content_before = registry
            .inspect("proposal-procedure")
            .expect("inspect")
            .proposal;

        // A validator that executes the content it inspects reports it, and the
        // registry refuses the result after exactly one inspection.
        let executing = TestValidator {
            approved: true,
            executed: true,
            effects: effects(),
        };
        assert!(matches!(
            registry.accept_procedure(command.clone(), &executing, &privileges),
            CommandOutcome::Conflict {
                kind: ConflictKind::UnsupportedAcceptance,
                ..
            }
        ));
        assert_eq!(
            executing.effects.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(privileges, before);
        assert!(matches!(
            registry
                .inspect("proposal-procedure")
                .expect("inspect")
                .proposal
                .disposition,
            crate::ProposalDisposition::Pending
        ));

        // A validating inspector is consulted once and only once per acceptance.
        let inspecting = TestValidator {
            approved: true,
            executed: false,
            effects: effects(),
        };
        let mut second = ProposalRegistry::new(procedure_registration().expected.clone());
        second
            .register(procedure_registration())
            .expect("register procedure");
        assert!(matches!(
            second.accept_procedure(command.clone(), &inspecting, &privileges),
            CommandOutcome::Accepted { .. }
        ));
        assert_eq!(
            inspecting
                .effects
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(privileges, before);
        let content_after = second
            .inspect("proposal-procedure")
            .expect("inspect")
            .proposal;
        assert_eq!(content_before.operation, content_after.operation);
    }

    #[test]
    fn rejected_or_executing_validators_cannot_accept_procedure() {
        let registration = procedure_registration();
        let command = procedure_command(&registration);
        let mut rejected = ProposalRegistry::new(registration.expected.clone());
        rejected
            .register(registration.clone())
            .expect("register procedure");
        let privileges = crate::flow::WorkerPrivileges {
            allowed_tools: std::collections::BTreeSet::new(),
            may_install_procedures: false,
        };
        let validator = TestValidator {
            approved: false,
            executed: false,
            effects: effects(),
        };
        assert!(matches!(
            rejected.accept_procedure(command, &validator, &privileges),
            CommandOutcome::Conflict {
                kind: ConflictKind::UnsupportedAcceptance,
                ..
            }
        ));
        assert!(matches!(
            rejected
                .inspect("proposal-procedure")
                .expect("inspect")
                .proposal
                .disposition,
            crate::ProposalDisposition::Pending
        ));
    }
}
