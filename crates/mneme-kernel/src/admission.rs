//! Commit admission: idempotent replay, base compare-and-swap, erasure fence.
//!
//! The coordinator reads these facts inside its immediate transaction and acts
//! on the decision in the same transaction. A stored command for the same
//! actor, scope and idempotency key is consulted before the base revision, so
//! a retry of a committed command returns its recorded outcome even after the
//! workspace has advanced.

/// The command row already stored under one actor, scope and idempotency key.
#[derive(Clone, Copy)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct StoredCommand {
    /// Digest of the complete stored command.
    pub command: crate::hashing::Digest,
    /// Adapter request fingerprint stored with the command, if one was bound.
    pub fingerprint: Option<crate::hashing::Digest>,
}

/// Facts read inside the commit transaction.
#[derive(Clone, Copy)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct CommitFacts {
    /// The row stored under this actor, scope and idempotency key, if any.
    pub stored: Option<StoredCommand>,
    /// Digest of the command being committed.
    pub command: crate::hashing::Digest,
    /// Adapter request fingerprint bound to this commit, if any.
    pub fingerprint: Option<crate::hashing::Digest>,
    /// The command's base revision is the current revision.
    pub base_is_current: bool,
    /// The erasure generation equals the generation pinned during preparation.
    pub generation_is_pinned: bool,
}

/// What the coordinator must do with a prepared command.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum CommitDecision {
    /// Write the new revision.
    Proceed,
    /// Return the outcome recorded for the stored command; write nothing.
    Replay,
    /// The key is already bound to a different request.
    IdempotencyConflict,
    /// The base revision is no longer current.
    StaleBase,
    /// An erasure barrier advanced after preparation.
    BarrierAdvanced,
}

/// Whether a stored command row is the same request as the one offered.
///
/// When both sides carry an adapter fingerprint, the fingerprints decide:
/// an adapter rebuilds its command from current state, so the command digest
/// of a retry may legitimately differ. Otherwise the command digests decide.
pub fn same_request(
    stored: &StoredCommand,
    command: &crate::hashing::Digest,
    fingerprint: &Option<crate::hashing::Digest>,
) -> bool {
    match (&stored.fingerprint, fingerprint) {
        (Some(kept), Some(offered)) => crate::hashing::digest_eq(kept, offered),
        _ => crate::hashing::digest_eq(&stored.command, command),
    }
}

/// Decide the fate of a prepared command.
pub fn decide_commit(facts: &CommitFacts) -> CommitDecision {
    match &facts.stored {
        Some(stored) => {
            if same_request(stored, &facts.command, &facts.fingerprint) {
                CommitDecision::Replay
            } else {
                CommitDecision::IdempotencyConflict
            }
        }
        None => {
            if !facts.base_is_current {
                CommitDecision::StaleBase
            } else if !facts.generation_is_pinned {
                CommitDecision::BarrierAdvanced
            } else {
                CommitDecision::Proceed
            }
        }
    }
}

/// What an adapter must do before it rebuilds a command for a key.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum ReplayDecision {
    /// No command is stored under the key; build and commit.
    Fresh,
    /// The stored command is this request; return its recorded outcome.
    Replay,
    /// The key is bound to a different request, or to a command without a
    /// fingerprint; refuse.
    Conflict,
}

/// Decide whether a request fingerprint replays a stored command.
pub fn decide_replay(
    stored: &Option<StoredCommand>,
    fingerprint: &crate::hashing::Digest,
) -> ReplayDecision {
    match stored {
        None => ReplayDecision::Fresh,
        Some(row) => match &row.fingerprint {
            Some(kept) => {
                if crate::hashing::digest_eq(kept, fingerprint) {
                    ReplayDecision::Replay
                } else {
                    ReplayDecision::Conflict
                }
            }
            None => ReplayDecision::Conflict,
        },
    }
}
