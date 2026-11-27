//! ASPIC+ structured argumentation preferences and Dung grounded labelling.
//!
//! Based on P. M. Dung (AIJ 77(2), 1995) and S. Modgil & H. Prakken,
//! *The ASPIC+ Framework for Structured Argumentation* (Argument & Computation
//! 5(1), 2014):
//! - **Authority preference (`authority_rank`, `preference_defeats`)**:
//!   strictly ordered by explicit authority (`Proposed < Accepted <
//!   ConflictResolution`). Ties yield symmetric defeat (`Undec`, fail-closed,
//!   never auto-promoting).
//! - **Dung grounded labelling (`next_label`, `is_fixpoint`,
//!   `is_conflict_free`, `is_admissible`)**: monotone characteristic operator
//!   $F_{AF}$ whose least fixpoint starting from all-`Undec` terminates in at
//!   most $|Ar|$ rounds, producing the unique conflict-free, admissible,
//!   permutation-invariant grounded labelling.
//! - **Alternative-argument join (`best_label`)**: combines multiple arguments
//!   for the same conclusion (`In > Undec > Out`).

const RANK_PROPOSED: u8 = 0;
const RANK_ACCEPTED: u8 = 1;
const RANK_CONFLICT_RESOLUTION: u8 = 2;

const LABEL_RANK_OUT: u8 = 0;
const LABEL_RANK_UNDEC: u8 = 1;
const LABEL_RANK_IN: u8 = 2;

/// Dung / Caminada grounded labelling status of an argument.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum Label {
    /// Defeated by at least one `In` attacker.
    Out,
    /// Neither defended (`In`) nor decisively defeated (`Out`).
    Undec,
    /// All attackers are `Out` (defended by the grounded extension).
    In,
}

/// Explicit authority tier for ASPIC+ preference ordering ($\preceq$).
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum Authority {
    /// Provisional / proposed assertion (lowest authority).
    Proposed,
    /// Accepted assertion backed by an acceptance decision.
    Accepted,
    /// Explicit conflict resolution or supersession decision (highest authority).
    ConflictResolution,
}

/// Directed defeat edge `attacker -> target` in a finite argumentation framework.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
#[allow(unknown_lints, usize_in_public_api)] // argument index into flat label slice
pub struct DefeatEdge {
    /// Index of the attacking argument.
    pub attacker: usize,
    /// Index of the attacked argument.
    pub target: usize,
}

/// Monotonic numeric rank of an [`Authority`] tier (`0 < 1 < 2`).
pub fn authority_rank(authority: Authority) -> u8 {
    if matches!(authority, Authority::Proposed) {
        RANK_PROPOSED
    } else if matches!(authority, Authority::Accepted) {
        RANK_ACCEPTED
    } else {
        RANK_CONFLICT_RESOLUTION
    }
}

/// Whether `attacker` defeats `target` on a preference-dependent attack
/// (rebuttal or un-adjudicated undercut): `true` iff `attacker` is not
/// strictly weaker than `target` (`rank(attacker) >= rank(target)`).
///
/// Equal authority yields symmetric defeat (`preference_defeats(a, b)` and
/// `preference_defeats(b, a)` both hold), causing Dung grounded labelling to
/// mark both arguments `Undec` rather than auto-promoting either side.
pub fn preference_defeats(attacker: Authority, target: Authority) -> bool {
    authority_rank(attacker) >= authority_rank(target)
}

const fn label_rank(label: Label) -> u8 {
    if matches!(label, Label::Out) {
        LABEL_RANK_OUT
    } else if matches!(label, Label::Undec) {
        LABEL_RANK_UNDEC
    } else {
        LABEL_RANK_IN
    }
}

/// Combine two alternative arguments supporting the same conclusion
/// (`In > Undec > Out`).
pub fn best_label(left: Label, right: Label) -> Label {
    if label_rank(left) >= label_rank(right) {
        left
    } else {
        right
    }
}

/// One step of Dung's monotone characteristic operator $F_{AF}$ for `node`.
///
/// - Returns `Label::Out` if any in-bounds attacker of `node` is `Label::In`.
/// - Returns `Label::In` if `node` is in bounds and every in-bounds attacker
///   of `node` is `Label::Out`.
/// - Returns `Label::Undec` otherwise (including when `node` is out of bounds).
#[allow(unknown_lints, usize_in_public_api)] // node index into flat label slice
pub fn next_label(node: usize, defeats: &[DefeatEdge], labels: &[Label]) -> Label {
    if node >= labels.len() {
        Label::Undec
    } else {
        let mut has_in_attacker = false;
        let mut has_non_out_attacker = false;
        let mut index = 0_usize;
        while index < defeats.len() {
            let edge = defeats[index];
            if edge.target == node && edge.attacker < labels.len() {
                let attacker_label = labels[edge.attacker];
                if matches!(attacker_label, Label::In) {
                    has_in_attacker = true;
                }
                if !matches!(attacker_label, Label::Out) {
                    has_non_out_attacker = true;
                }
            }
            index = index.saturating_add(1);
        }
        if has_in_attacker {
            Label::Out
        } else if !has_non_out_attacker {
            Label::In
        } else {
            Label::Undec
        }
    }
}

/// Whether `labels` is a fixpoint of Dung's characteristic operator $F_{AF}$:
/// every in-bounds node satisfies `next_label(node, defeats, labels) == labels[node]`.
pub fn is_fixpoint(defeats: &[DefeatEdge], labels: &[Label]) -> bool {
    let mut is_all_fixed = true;
    let mut index = 0_usize;
    while index < labels.len() && is_all_fixed {
        let updated = next_label(index, defeats, labels);
        if updated != labels[index] {
            is_all_fixed = false;
        }
        index = index.saturating_add(1);
    }
    is_all_fixed
}

/// Whether the `In`-labelled set of `labels` is conflict-free: no in-bounds
/// defeat edge links an `In` attacker to an `In` target.
pub fn is_conflict_free(defeats: &[DefeatEdge], labels: &[Label]) -> bool {
    let mut is_free = true;
    let mut index = 0_usize;
    while index < defeats.len() && is_free {
        let edge = defeats[index];
        if edge.attacker < labels.len() && edge.target < labels.len() {
            let is_both_in = matches!(labels[edge.attacker], Label::In)
                && matches!(labels[edge.target], Label::In);
            if is_both_in {
                is_free = false;
            }
        }
        index = index.saturating_add(1);
    }
    is_free
}

/// Whether `attacker` is counter-attacked by at least one `In` argument.
fn has_in_counterattacker(attacker: usize, defeats: &[DefeatEdge], labels: &[Label]) -> bool {
    let mut has_defender = false;
    let mut index = 0_usize;
    while index < defeats.len() && !has_defender {
        let edge = defeats[index];
        if edge.target == attacker
            && edge.attacker < labels.len()
            && matches!(labels[edge.attacker], Label::In)
        {
            has_defender = true;
        }
        index = index.saturating_add(1);
    }
    has_defender
}

/// Whether the `In`-labelled set of `labels` is admissible: conflict-free, and
/// every in-bounds attacker of an `In` argument is counter-attacked by some
/// `In` argument.
pub fn is_admissible(defeats: &[DefeatEdge], labels: &[Label]) -> bool {
    if !is_conflict_free(defeats, labels) {
        false
    } else {
        let mut is_defended = true;
        let mut index = 0_usize;
        while index < defeats.len() && is_defended {
            let edge = defeats[index];
            if edge.attacker < labels.len() && edge.target < labels.len() {
                let is_undefended = matches!(labels[edge.target], Label::In)
                    && !has_in_counterattacker(edge.attacker, defeats, labels);
                if is_undefended {
                    is_defended = false;
                }
            }
            index = index.saturating_add(1);
        }
        is_defended
    }
}
