//! Proposal inspection and separate compare-and-swap acceptance/rejection.
//!
//! Acceptance rechecks the reviewed proposal revision, base revision, target
//! revisions, and exact source digests against current state. A repeated command
//! with the same idempotency key returns its prior outcome; a different key
//! after a terminal decision is an explicit conflict.

use std::collections::{BTreeMap, BTreeSet};

use mneme_core::{RecordId, RevisionId, ScopeId, WorkspaceRevisionId};

use crate::{ConsolidationProposal, InputKey, ProposalDisposition, SupportOutcome};

/// Current workspace state used by acceptance preconditions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptanceState {
    pub scope: ScopeId,
    pub base_revision: WorkspaceRevisionId,
    pub eligibility_generation: u64,
    pub forgotten: BTreeSet<RecordId>,
    pub targets: BTreeMap<RecordId, RevisionId>,
    pub sources: BTreeMap<InputKey, SourceState>,
}

/// Availability and exact digest of one source premise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceState {
    Retained { digest: String },
    Pruned { digest: String },
    Forgotten { digest: String },
}

impl SourceState {
    pub fn digest(&self) -> &str {
        match self {
            SourceState::Retained { digest }
            | SourceState::Pruned { digest }
            | SourceState::Forgotten { digest } => digest,
        }
    }
}

/// A registered proposal plus the state it was reviewed against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredProposal {
    pub proposal: ConsolidationProposal,
    pub proposal_revision: u64,
    pub expected: AcceptanceState,
}

/// Read-only proposal inspection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalInspection {
    pub proposal: ConsolidationProposal,
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
    pub decision: RecordId,
}

/// A separate rejection command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejectionCommand {
    pub idempotency_key: String,
    pub proposal_id: String,
    pub proposal_revision: u64,
    pub reason: String,
}

/// Why acceptance or rejection did not apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictKind {
    MissingProposal,
    StaleProposalRevision,
    StaleBase,
    StaleGeneration,
    Unauthorized,
    ChangedTarget,
    AlteredSource,
    ForgottenSource,
    PrunedSource,
    AlreadyDecided,
    UnsupportedAcceptance,
    IdempotencyMismatch,
}

/// A terminal or conflict result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandOutcome {
    Accepted {
        proposal_id: String,
        decision: RecordId,
        proposal_revision: u64,
    },
    Rejected {
        proposal_id: String,
        reason: String,
        proposal_revision: u64,
    },
    PriorOutcome {
        proposal_id: String,
        detail: String,
    },
    Conflict {
        kind: ConflictKind,
        detail: String,
    },
}

/// In-memory proposal registry with CAS commands. The registry never applies an
/// acceptance from a generation run; callers must issue one of these commands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalRegistry {
    pub current: AcceptanceState,
    proposals: BTreeMap<String, RegisteredProposal>,
    acceptances: BTreeMap<String, (AcceptanceCommand, CommandOutcome)>,
    rejections: BTreeMap<String, (RejectionCommand, CommandOutcome)>,
}

impl ProposalRegistry {
    pub fn new(current: AcceptanceState) -> Self {
        ProposalRegistry {
            current,
            proposals: BTreeMap::new(),
            acceptances: BTreeMap::new(),
            rejections: BTreeMap::new(),
        }
    }

    pub fn register(
        &mut self,
        proposal: ConsolidationProposal,
        proposal_revision: u64,
        expected: AcceptanceState,
    ) -> Result<(), String> {
        if proposal_revision == 0 {
            return Err("proposal revision must be positive".to_owned());
        }
        if self.proposals.contains_key(&proposal.proposal_id) {
            return Err("proposal is already registered".to_owned());
        }
        proposal.validate()?;
        if proposal.scope != expected.scope {
            return Err("proposal scope does not match the acceptance state".to_owned());
        }
        self.proposals.insert(
            proposal.proposal_id.clone(),
            RegisteredProposal {
                proposal,
                proposal_revision,
                expected,
            },
        );
        Ok(())
    }

    /// Inspect a proposal without mutating it.
    pub fn inspect(&self, proposal_id: &str) -> Result<ProposalInspection, String> {
        let registered = self
            .proposals
            .get(proposal_id)
            .ok_or_else(|| format!("unknown proposal {proposal_id}"))?;
        Ok(ProposalInspection {
            proposal: registered.proposal.clone(),
            proposal_revision: registered.proposal_revision,
            expected: registered.expected.clone(),
            current: self.current.clone(),
        })
    }

    /// Apply a compare-and-swap acceptance or report a conflict/prior outcome.
    pub fn accept(&mut self, command: AcceptanceCommand) -> CommandOutcome {
        if let Some((stored, _)) = self.acceptances.get(&command.idempotency_key) {
            return if stored == &command {
                CommandOutcome::PriorOutcome {
                    proposal_id: command.proposal_id,
                    detail: "acceptance already recorded".to_owned(),
                }
            } else {
                CommandOutcome::Conflict {
                    kind: ConflictKind::IdempotencyMismatch,
                    detail: "idempotency key was reused with a different acceptance".to_owned(),
                }
            };
        }
        let Some(registered) = self.proposals.get(&command.proposal_id).cloned() else {
            return self.conflict(ConflictKind::MissingProposal, "proposal is not registered");
        };
        if !matches!(
            registered.proposal.disposition,
            ProposalDisposition::Pending
        ) {
            return CommandOutcome::Conflict {
                kind: ConflictKind::AlreadyDecided,
                detail: "proposal already has a terminal disposition".to_owned(),
            };
        }
        if registered.proposal_revision != command.proposal_revision {
            return self.conflict(
                ConflictKind::StaleProposalRevision,
                "proposal revision changed",
            );
        }
        if !matches!(
            registered.proposal.support.outcome,
            SupportOutcome::Supported
        ) {
            return self.conflict(
                ConflictKind::UnsupportedAcceptance,
                "proposal support was not accepted by review",
            );
        }
        if command.expected != registered.expected {
            return self.conflict(
                ConflictKind::ChangedTarget,
                "acceptance preconditions differ from the reviewed proposal",
            );
        }
        if self.current.base_revision != registered.expected.base_revision {
            return self.conflict(ConflictKind::StaleBase, "base revision changed");
        }
        if self.current.scope != registered.expected.scope
            || registered.proposal.scope != self.current.scope
        {
            return self.conflict(
                ConflictKind::Unauthorized,
                "proposal is outside the current authorized scope",
            );
        }
        if self.current.eligibility_generation != registered.expected.eligibility_generation {
            return self.conflict(
                ConflictKind::StaleGeneration,
                "eligibility generation changed",
            );
        }
        for premise in &registered.proposal.premises {
            if self.current.forgotten.contains(&premise.record_id)
                || premise
                    .ancestry_roots
                    .iter()
                    .any(|root| self.current.forgotten.contains(&root.record_id))
            {
                return self.conflict(
                    ConflictKind::ForgottenSource,
                    "proposal depends on explicitly forgotten evidence",
                );
            }
            let Some(current_source) = self.current.sources.get(&InputKey {
                record_id: premise.record_id,
                revision_id: premise.revision_id,
            }) else {
                return self.conflict(ConflictKind::AlteredSource, "source is no longer present");
            };
            let expected_source = registered.expected.sources.get(&InputKey {
                record_id: premise.record_id,
                revision_id: premise.revision_id,
            });
            if expected_source.is_none_or(|expected| expected.digest() != current_source.digest()) {
                return self.conflict(ConflictKind::AlteredSource, "source digest changed");
            }
            match current_source {
                SourceState::Forgotten { .. } => {
                    return self.conflict(
                        ConflictKind::ForgottenSource,
                        "proposal source was forgotten",
                    );
                }
                SourceState::Pruned { .. } if premise.span.is_some() => {
                    return self.conflict(
                        ConflictKind::PrunedSource,
                        "proposal requires pruned source bytes",
                    );
                }
                SourceState::Retained { .. } | SourceState::Pruned { .. } => {}
            }
        }
        if self.current.targets != registered.expected.targets {
            return self.conflict(ConflictKind::ChangedTarget, "target revision changed");
        }
        let Some(registered) = self.proposals.get_mut(&command.proposal_id) else {
            return CommandOutcome::Conflict {
                kind: ConflictKind::MissingProposal,
                detail: "proposal disappeared".to_owned(),
            };
        };
        registered.proposal.disposition = ProposalDisposition::Accepted {
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
            return CommandOutcome::Conflict {
                kind: ConflictKind::UnsupportedAcceptance,
                detail: "rejection reason is required".to_owned(),
            };
        }
        if let Some((stored, _)) = self.rejections.get(&command.idempotency_key) {
            return if stored == &command {
                CommandOutcome::PriorOutcome {
                    proposal_id: command.proposal_id,
                    detail: "rejection already recorded".to_owned(),
                }
            } else {
                CommandOutcome::Conflict {
                    kind: ConflictKind::IdempotencyMismatch,
                    detail: "idempotency key was reused with a different rejection".to_owned(),
                }
            };
        }
        let Some(registered) = self.proposals.get(&command.proposal_id).cloned() else {
            return CommandOutcome::Conflict {
                kind: ConflictKind::MissingProposal,
                detail: "proposal is not registered".to_owned(),
            };
        };
        if !matches!(
            registered.proposal.disposition,
            ProposalDisposition::Pending
        ) {
            return CommandOutcome::Conflict {
                kind: ConflictKind::AlreadyDecided,
                detail: "proposal already has a terminal disposition".to_owned(),
            };
        }
        if registered.proposal_revision != command.proposal_revision {
            return CommandOutcome::Conflict {
                kind: ConflictKind::StaleProposalRevision,
                detail: "proposal revision changed".to_owned(),
            };
        }
        let Some(registered) = self.proposals.get_mut(&command.proposal_id) else {
            return CommandOutcome::Conflict {
                kind: ConflictKind::MissingProposal,
                detail: "proposal disappeared".to_owned(),
            };
        };
        registered.proposal.disposition = ProposalDisposition::Rejected {
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

    fn conflict(&self, kind: ConflictKind, detail: &str) -> CommandOutcome {
        CommandOutcome::Conflict {
            kind,
            detail: detail.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture;

    fn command() -> (AcceptanceCommand, AcceptanceState) {
        let fixture = fixture().expect("fixture");
        let proposal = fixture.proposals[0].clone();
        let source = InputKey {
            record_id: RecordId::from_bytes([0x20; 16]),
            revision_id: RevisionId::from_bytes([0x21; 16]),
        };
        let state = AcceptanceState {
            scope: fixture.job.scope.clone(),
            base_revision: fixture.job.base_revision,
            eligibility_generation: fixture.job.batch.eligibility_generation,
            forgotten: BTreeSet::new(),
            targets: BTreeMap::new(),
            sources: BTreeMap::from([(
                source,
                SourceState::Retained {
                    digest: "sha256:source".to_owned(),
                },
            )]),
        };
        (
            AcceptanceCommand {
                idempotency_key: "accept-1".to_owned(),
                proposal_id: proposal.proposal_id.clone(),
                proposal_revision: 1,
                expected: state.clone(),
                decision: RecordId::from_bytes([0x50; 16]),
            },
            state,
        )
    }

    fn registry() -> ProposalRegistry {
        let fixture = fixture().expect("fixture");
        let (command, state) = command();
        let mut registry = ProposalRegistry::new(state.clone());
        registry
            .register(fixture.proposals[0].clone(), 1, state)
            .expect("register");
        let _ = command;
        registry
    }

    #[test]
    fn inspection_is_read_only() {
        let registry = registry();
        let before = registry.clone();
        let inspection = registry.inspect("proposal-summary").expect("inspect");
        assert!(matches!(
            inspection.proposal.disposition,
            ProposalDisposition::Pending
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
                registry.current.base_revision = WorkspaceRevisionId::from_bytes([0x99; 16]);
            } else if kind == ConflictKind::ChangedTarget {
                registry.current.targets.insert(
                    RecordId::from_bytes([0x40; 16]),
                    RevisionId::from_bytes([0x99; 16]),
                );
            } else {
                registry.current.sources.insert(
                    InputKey {
                        record_id: RecordId::from_bytes([0x20; 16]),
                        revision_id: RevisionId::from_bytes([0x21; 16]),
                    },
                    SourceState::Retained {
                        digest: "sha256:altered".to_owned(),
                    },
                );
            }
            let (command, _) = command();
            let outcome = registry.accept(command);
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
                    == ProposalDisposition::Pending
            );
        }
    }

    #[test]
    fn repeated_acceptance_returns_prior_outcome_without_duplication() {
        let mut registry = registry();
        let (command, _) = command();
        let first = registry.accept(command.clone());
        let revision = match first {
            CommandOutcome::Accepted {
                proposal_revision, ..
            } => proposal_revision,
            _ => return,
        };
        let second = registry.accept(command);
        assert!(matches!(second, CommandOutcome::PriorOutcome { .. }));
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
        let (command, _) = command();
        assert!(matches!(
            registry.accept(command.clone()),
            CommandOutcome::Accepted { .. }
        ));
        let mut next = command;
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
        assert!(matches!(
            registry.reject(rejection.clone()),
            CommandOutcome::Rejected { .. }
        ));
        assert!(matches!(
            registry.reject(rejection),
            CommandOutcome::PriorOutcome { .. }
        ));
        let (command, _) = command();
        assert!(matches!(
            registry.accept(command),
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
            .insert(RecordId::from_bytes([0x20; 16]));
        let (command, _) = command();
        let first = registry.accept(command.clone());
        assert!(matches!(
            first,
            CommandOutcome::Conflict {
                kind: ConflictKind::ForgottenSource,
                ..
            }
        ));
        let second = registry.accept(command);
        assert!(matches!(
            second,
            CommandOutcome::Conflict {
                kind: ConflictKind::ForgottenSource,
                ..
            }
        ));
    }

    #[test]
    fn pruned_bytes_block_quotation_but_allow_claim_envelope() {
        let mut quoted = registry();
        let (quoted_command, _) = command();
        let source = InputKey {
            record_id: RecordId::from_bytes([0x20; 16]),
            revision_id: RevisionId::from_bytes([0x21; 16]),
        };
        quoted.current.sources.insert(
            source,
            SourceState::Pruned {
                digest: "sha256:source".to_owned(),
            },
        );
        assert!(matches!(
            quoted.accept(quoted_command),
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
        let (mut envelope_command, _) = command();
        envelope_command.idempotency_key = "accept-envelope".to_owned();
        envelope.current.sources.insert(
            source,
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
    fn generation_and_scope_changes_conflict() {
        let mut generation = registry();
        generation.current.eligibility_generation += 1;
        let (generation_command, _) = command();
        assert!(matches!(
            generation.accept(generation_command),
            CommandOutcome::Conflict {
                kind: ConflictKind::StaleGeneration,
                ..
            }
        ));

        let mut scope = registry();
        scope.current.scope =
            mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "birch").expect("scope");
        let (scope_command, _) = command();
        assert!(matches!(
            scope.accept(scope_command),
            CommandOutcome::Conflict {
                kind: ConflictKind::Unauthorized,
                ..
            }
        ));
    }
}
