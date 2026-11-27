//! Epistemic provenance semiring (`Rejected < Proposed < Accepted`).
//!
//! Epistemic provenance forms a commutative idempotent semiring
//! `(EpistemicStatus, union, join, Rejected, Accepted)`:
//! - `join` (`×`) combines premises within one derivation by taking the weakest
//!   premise (`min`), enforcing non-promotion by construction.
//! - `union` (`+`) combines independent derivations of the same tuple by taking
//!   the strongest derivation (`max`).
//! - `Rejected` is the additive identity and multiplicative annihilator (`ZERO`):
//!   it is excluded from active projections (`is_active`) and never blocks
//!   stratified negation (`negation_blocks`).

/// Epistemic provenance semiring element (`Rejected < Proposed < Accepted`).
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum EpistemicStatus {
    /// Annihilator (`ZERO`): excluded from active facts and negation.
    Rejected,
    /// Intermediate hypothetical or proposed provenance.
    Proposed,
    /// Multiplicative identity (`ONE`): accepted canonical provenance.
    Accepted,
}

/// Monotonic numeric rank of an epistemic status (`Rejected < Proposed < Accepted`).
pub fn rank(status: EpistemicStatus) -> u8 {
    match status {
        EpistemicStatus::Rejected => 0,
        EpistemicStatus::Proposed => 1,
        EpistemicStatus::Accepted => 2,
    }
}

/// Semiring multiplication (`×`): conjunction over rule premises (`min`).
pub fn join(left: EpistemicStatus, right: EpistemicStatus) -> EpistemicStatus {
    if rank(left) <= rank(right) {
        left
    } else {
        right
    }
}

/// Semiring addition (`+`): disjunction over independent derivations (`max`).
pub fn union(left: EpistemicStatus, right: EpistemicStatus) -> EpistemicStatus {
    if rank(left) >= rank(right) {
        left
    } else {
        right
    }
}

/// Whether a fact with `status` is active (not annihilated by `Rejected`).
pub fn is_active(status: EpistemicStatus) -> bool {
    !matches!(status, EpistemicStatus::Rejected)
}

/// Whether a fact with `status` blocks a strict negated literal (`strict_not p(...)`).
///
/// Rejected (`ZERO`) facts are absent from active relations and never block
/// negation; active (`Proposed` or `Accepted`) facts block strict negation.
pub fn negation_blocks(status: EpistemicStatus) -> bool {
    is_active(status)
}

/// Kleene three-valued epistemic negation over `{Rejected, Proposed, Accepted}`:
/// - `negate(Accepted) = Rejected` (blocks rule)
/// - `negate(Proposed) = Proposed` (attenuates derived head to `Proposed`)
/// - `negate(Rejected) = Accepted` (does not block or attenuate)
pub fn negate(status: EpistemicStatus) -> EpistemicStatus {
    if matches!(status, EpistemicStatus::Accepted) {
        EpistemicStatus::Rejected
    } else if matches!(status, EpistemicStatus::Proposed) {
        EpistemicStatus::Proposed
    } else {
        EpistemicStatus::Accepted
    }
}

/// Strict classical epistemic negation over `{Rejected, Proposed, Accepted}`:
/// - `strict_negate(Accepted) = Rejected`
/// - `strict_negate(Proposed) = Rejected`
/// - `strict_negate(Rejected) = Accepted`
pub fn strict_negate(status: EpistemicStatus) -> EpistemicStatus {
    if is_active(status) {
        EpistemicStatus::Rejected
    } else {
        EpistemicStatus::Accepted
    }
}

/// Whether a fact with `status` blocks a Kleene three-valued negated literal (`not p(...)`).
///
/// Only `Accepted` facts annihilate a Kleene negated literal (`negate(Accepted) = Rejected`);
/// `Proposed` facts attenuate rather than block, and `Rejected` facts yield `Accepted`.
pub fn kleene_negation_blocks(status: EpistemicStatus) -> bool {
    !is_active(negate(status))
}
