//! Assertion lifecycle transitions and the decisions that back them.
//!
//! An assertion is born proposed. Every other lifecycle is reached only by a
//! revision that cites a decision of the matching kind, about this assertion,
//! about exactly the revision being replaced. A decision therefore cannot be
//! reused to promote later content, and a retracted assertion stays retracted.

/// The lifecycle of an assertion revision.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum Lifecycle {
    /// Recorded, not yet accepted.
    Proposed,
    /// Accepted as current knowledge.
    Accepted,
    /// In unresolved conflict with another assertion.
    Disputed,
    /// Replaced by a newer assertion.
    Superseded,
    /// Withdrawn.
    Retracted,
}

/// The kind of an attributed decision.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum DecisionKind {
    /// Accepts a proposal.
    Acceptance,
    /// Records or resolves a conflict.
    ConflictResolution,
    /// Withdraws an assertion.
    Retraction,
    /// Replaces an assertion with a newer one.
    Supersession,
}

/// Whether a revision may move an assertion from `prior` to `next`.
///
/// `prior` is `None` for the first revision of a new assertion.
pub fn transition_allowed(prior: Option<Lifecycle>, next: Lifecycle) -> bool {
    match prior {
        None => matches!(next, Lifecycle::Proposed),
        Some(Lifecycle::Proposed) => true,
        Some(Lifecycle::Accepted) => !matches!(next, Lifecycle::Proposed),
        Some(Lifecycle::Disputed) => !matches!(next, Lifecycle::Proposed),
        Some(Lifecycle::Superseded) => matches!(next, Lifecycle::Retracted),
        Some(Lifecycle::Retracted) => false,
    }
}

/// The decision kind a revision in this lifecycle must cite.
pub fn required_decision(state: Lifecycle) -> Option<DecisionKind> {
    match state {
        Lifecycle::Proposed => None,
        Lifecycle::Accepted => Some(DecisionKind::Acceptance),
        Lifecycle::Disputed => Some(DecisionKind::ConflictResolution),
        Lifecycle::Superseded => Some(DecisionKind::Supersession),
        Lifecycle::Retracted => Some(DecisionKind::Retraction),
    }
}

/// Whether two decision kinds are the same.
pub fn kind_eq(left: DecisionKind, right: DecisionKind) -> bool {
    matches!(
        (left, right),
        (DecisionKind::Acceptance, DecisionKind::Acceptance)
            | (
                DecisionKind::ConflictResolution,
                DecisionKind::ConflictResolution
            )
            | (DecisionKind::Retraction, DecisionKind::Retraction)
            | (DecisionKind::Supersession, DecisionKind::Supersession)
    )
}

/// Facts about the decision record an assertion revision cites.
#[derive(Clone, Copy)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct CitedDecision {
    /// The decision's kind.
    pub kind: DecisionKind,
    /// The decision's outcome word is the one for the revision's lifecycle.
    pub outcome_matches: bool,
    /// The decision targets this assertion record.
    pub targets_assertion: bool,
    /// The decision's input revision is the revision this one replaces.
    pub binds_replaced_revision: bool,
}

/// Whether a cited decision backs an assertion revision's lifecycle.
///
/// Used whenever beliefs are computed: a revision whose decision does not back
/// it is not accepted, retracted, superseded or disputed knowledge.
pub fn decision_backs(state: Lifecycle, cited: &Option<CitedDecision>) -> bool {
    match (required_decision(state), cited) {
        (None, None) => true,
        (None, Some(_)) => false,
        (Some(_), None) => false,
        (Some(required), Some(decision)) => {
            kind_eq(required, decision.kind)
                && decision.outcome_matches
                && decision.targets_assertion
                && decision.binds_replaced_revision
        }
    }
}

/// Facts known only while a batch is being committed.
#[derive(Clone, Copy)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct CommitTimeFacts {
    /// The cited decision record is committed by the same batch.
    pub decision_in_batch: bool,
    /// The decision's actor is the principal committing the batch.
    pub actor_is_committer: bool,
}

/// Whether a batch may commit an assertion revision.
///
/// The transition must be allowed, the cited decision must back the new
/// lifecycle, and a cited decision must be new in this batch and made by the
/// committing principal.
pub fn revision_admissible(
    prior: Option<Lifecycle>,
    next: Lifecycle,
    cited: &Option<CitedDecision>,
    commit: &CommitTimeFacts,
) -> bool {
    let is_fresh_decision = match cited {
        None => true,
        Some(_) => commit.decision_in_batch && commit.actor_is_committer,
    };
    transition_allowed(prior, next) && decision_backs(next, cited) && is_fresh_decision
}
