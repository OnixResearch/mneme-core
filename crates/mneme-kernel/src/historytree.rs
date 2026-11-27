//! Crosby-Wallach / RFC 6962 Merkle history tree verification kernel.
//!
//! Pure structural verification of inclusion proofs, append-only consistency
//! proofs, and equivocation detection over pre-hashed 256-bit digests.
//! The imperative shell computes BLAKE3 leaf and interior digests:
//! - leaf: `BLAKE3(0x00 || seq_le || revision_id || manifest_digest || eligibility_generation_le)`
//! - interior: `BLAKE3(0x01 || left || right)`
//!   and supplies the verified hash steps to this kernel.

const BIT_MASK_LSB: u64 = 1;
const BIT_SHIFT_ONE: u32 = 1;

/// Which side of the current path the sibling digest sits on.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum SiblingSide {
    /// Sibling is the left child: `parent = H(0x01 || sibling || current)`.
    Left,
    /// Sibling is the right child: `parent = H(0x01 || current || sibling)`.
    Right,
}

/// One pre-hashed step of a Merkle inclusion proof.
///
/// The imperative shell must compute `parent = H(0x01 || left || right)`
/// before passing steps to [`verify_inclusion_proof`].
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct InclusionStep {
    /// Which child is the sibling (the other child is the running hash).
    pub side: SiblingSide,
    /// Left child digest of this interior node.
    pub left: crate::hashing::Digest,
    /// Right child digest of this interior node.
    pub right: crate::hashing::Digest,
    /// Shell-computed interior digest `H(0x01 || left || right)`.
    pub parent: crate::hashing::Digest,
}

/// Parameters for verifying that one leaf digest belongs to a committed root.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct InclusionCheck {
    /// Zero-based leaf sequence index (`0 <= leaf_index < tree_size`).
    pub leaf_index: u64,
    /// Number of leaves in the committed tree (`tree_size >= 1`).
    pub tree_size: u64,
    /// Leaf digest at `leaf_index`.
    pub leaf_digest: crate::hashing::Digest,
    /// Expected tree root digest for `tree_size`.
    pub expected_root: crate::hashing::Digest,
}

/// One pre-hashed step of a Merkle append-only consistency proof.
///
/// When `side == SiblingSide::Left`, the sibling lies to the left of both the
/// old-tree frontier and the new-tree frontier:
/// - `old_parent = H(0x01 || sibling || old_right)`
/// - `new_parent = H(0x01 || sibling || new_child)`
///
/// When `side == SiblingSide::Right`, the sibling lies to the right in the
/// newer tree only (leaving the old-tree accumulator unchanged):
/// - `new_parent = H(0x01 || new_child || sibling)`
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct ConsistencyStep {
    /// Whether this step folds a shared left sibling or a new-tree-only right sibling.
    pub side: SiblingSide,
    /// Shared sibling digest.
    pub sibling: crate::hashing::Digest,
    /// Old-tree right child (used when `side == Left`).
    pub old_right: crate::hashing::Digest,
    /// Old-tree parent `H(0x01 || sibling || old_right)` (used when `side == Left`).
    pub old_parent: crate::hashing::Digest,
    /// New-tree child on the active path (`right` when `Left`, `left` when `Right`).
    pub new_child: crate::hashing::Digest,
    /// New-tree parent digest computed by the shell.
    pub new_parent: crate::hashing::Digest,
}

/// Parameters for verifying that `old_root` (at `old_size`) is an append-only
/// prefix of `new_root` (at `new_size`).
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct ConsistencyCheck {
    /// Number of leaves in the older tree (`1 <= old_size <= new_size`).
    pub old_size: u64,
    /// Number of leaves in the newer tree.
    pub new_size: u64,
    /// Committed root digest of the older tree.
    pub old_root: crate::hashing::Digest,
    /// Committed root digest of the newer tree.
    pub new_root: crate::hashing::Digest,
    /// Starting subtree digest (`old_root` when `old_size` is a power of two;
    /// first proof element otherwise).
    pub initial_digest: crate::hashing::Digest,
}

/// Outcome of verifying a consistency proof between two tree heads of different sizes.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum ConsistencyVerdict {
    /// Consistency proof verified cleanly.
    Consistent,
    /// Consistency proof was missing, malformed, or failed root verification.
    Inconsistent,
}

/// Authenticated facts extracted from two signed tree heads from one peer/scope.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct EquivocationFacts {
    /// Whether both signed tree heads carried valid Ed25519 signatures from the same origin.
    pub is_both_signed_same_origin: bool,
    /// Tree size of the first signed tree head.
    pub first_size: u64,
    /// Root digest of the first signed tree head.
    pub first_root: crate::hashing::Digest,
    /// Tree size of the second signed tree head.
    pub second_size: u64,
    /// Root digest of the second signed tree head.
    pub second_root: crate::hashing::Digest,
    /// Result of checking consistency between the smaller and larger tree head.
    pub consistency: ConsistencyVerdict,
}

/// Running node-index cursor for Crosby-Wallach / RFC 6962 proof traversal.
#[derive(Clone, Copy, PartialEq, Eq)]
struct IndexCursor {
    fn_idx: u64,
    sn_idx: u64,
}

/// Accumulated state during inclusion proof verification.
#[derive(Clone, Copy, PartialEq, Eq)]
struct InclusionState {
    cursor: IndexCursor,
    current: crate::hashing::Digest,
}

/// Accumulated state during consistency proof verification.
#[derive(Clone, Copy, PartialEq, Eq)]
struct ConsistencyState {
    cursor: IndexCursor,
    old_acc: crate::hashing::Digest,
    new_acc: crate::hashing::Digest,
}

/// Whether two digests are equal by value (avoids borrow-abstraction joins in Aeneas).
const fn same_digest(left: crate::hashing::Digest, right: crate::hashing::Digest) -> bool {
    left.hi == right.hi && left.lo == right.lo
}

/// Whether the current RFC 6962 step consumes a left sibling.
const fn is_left_sibling_step(cursor: IndexCursor) -> bool {
    (cursor.fn_idx & BIT_MASK_LSB) == BIT_MASK_LSB || cursor.fn_idx == cursor.sn_idx
}

/// Drop trailing zero bits from `fn_idx` together with `sn_idx` while `fn_idx != 0`.
fn shift_trailing_zeros(cursor: IndexCursor) -> IndexCursor {
    let mut fn_idx = cursor.fn_idx;
    let mut sn_idx = cursor.sn_idx;
    while fn_idx != 0 && (fn_idx & BIT_MASK_LSB) == 0 {
        fn_idx >>= BIT_SHIFT_ONE;
        sn_idx >>= BIT_SHIFT_ONE;
    }
    IndexCursor { fn_idx, sn_idx }
}

/// Drop trailing one bits from `fn_idx` together with `sn_idx`.
fn shift_trailing_ones(cursor: IndexCursor) -> IndexCursor {
    let mut fn_idx = cursor.fn_idx;
    let mut sn_idx = cursor.sn_idx;
    while (fn_idx & BIT_MASK_LSB) == BIT_MASK_LSB {
        fn_idx >>= BIT_SHIFT_ONE;
        sn_idx >>= BIT_SHIFT_ONE;
    }
    IndexCursor { fn_idx, sn_idx }
}

/// Advance one inclusion proof step, returning `None` on structural or digest mismatch.
fn apply_inclusion_step(state: InclusionState, step: InclusionStep) -> Option<InclusionState> {
    let is_left_eq = same_digest(step.left, state.current);
    let is_right_eq = same_digest(step.right, state.current);
    if state.cursor.sn_idx == 0 {
        None
    } else if is_left_sibling_step(state.cursor) {
        let is_side_ok = matches!(step.side, SiblingSide::Left);
        if is_side_ok && is_right_eq {
            let shifted = shift_trailing_zeros(state.cursor);
            Some(InclusionState {
                cursor: IndexCursor {
                    fn_idx: shifted.fn_idx >> BIT_SHIFT_ONE,
                    sn_idx: shifted.sn_idx >> BIT_SHIFT_ONE,
                },
                current: step.parent,
            })
        } else {
            None
        }
    } else {
        let is_side_ok = matches!(step.side, SiblingSide::Right);
        if is_side_ok && is_left_eq {
            Some(InclusionState {
                cursor: IndexCursor {
                    fn_idx: state.cursor.fn_idx >> BIT_SHIFT_ONE,
                    sn_idx: state.cursor.sn_idx >> BIT_SHIFT_ONE,
                },
                current: step.parent,
            })
        } else {
            None
        }
    }
}

/// Advance one consistency proof step, returning `None` on structural or digest mismatch.
fn apply_consistency_step(
    state: ConsistencyState,
    step: ConsistencyStep,
) -> Option<ConsistencyState> {
    let is_old_ok = same_digest(step.old_right, state.old_acc);
    let is_new_ok = same_digest(step.new_child, state.new_acc);
    if state.cursor.sn_idx == 0 {
        None
    } else if is_left_sibling_step(state.cursor) {
        let is_side_ok = matches!(step.side, SiblingSide::Left);
        if is_side_ok && is_old_ok && is_new_ok {
            let shifted = shift_trailing_zeros(state.cursor);
            Some(ConsistencyState {
                cursor: IndexCursor {
                    fn_idx: shifted.fn_idx >> BIT_SHIFT_ONE,
                    sn_idx: shifted.sn_idx >> BIT_SHIFT_ONE,
                },
                old_acc: step.old_parent,
                new_acc: step.new_parent,
            })
        } else {
            None
        }
    } else {
        let is_side_ok = matches!(step.side, SiblingSide::Right);
        if is_side_ok && is_new_ok {
            Some(ConsistencyState {
                cursor: IndexCursor {
                    fn_idx: state.cursor.fn_idx >> BIT_SHIFT_ONE,
                    sn_idx: state.cursor.sn_idx >> BIT_SHIFT_ONE,
                },
                old_acc: state.old_acc,
                new_acc: step.new_parent,
            })
        } else {
            None
        }
    }
}

/// Verify an RFC 6962 / Crosby-Wallach Merkle inclusion proof.
///
/// Returns `true` iff `leaf_index < tree_size`, every pre-hashed step matches
/// the exact bit-level path from `leaf_index` to the root of a tree of size
/// `tree_size`, no trailing steps remain, and the resulting root equals
/// `expected_root`.
pub fn verify_inclusion_proof(check: &InclusionCheck, steps: &[InclusionStep]) -> bool {
    let tree_size = check.tree_size;
    let leaf_index = check.leaf_index;
    let leaf_digest = check.leaf_digest;
    let expected_root = check.expected_root;
    if tree_size == 0 || leaf_index >= tree_size {
        false
    } else {
        let mut state = InclusionState {
            cursor: IndexCursor {
                fn_idx: leaf_index,
                sn_idx: tree_size.saturating_sub(1),
            },
            current: leaf_digest,
        };
        let mut is_valid = true;
        let mut index = 0_usize;
        while index < steps.len() && is_valid {
            match apply_inclusion_step(state, steps[index]) {
                Some(next) => {
                    state = next;
                }
                None => {
                    is_valid = false;
                }
            }
            index = index.saturating_add(1);
        }
        let is_root_ok = same_digest(state.current, expected_root);
        is_valid && state.cursor.sn_idx == 0 && is_root_ok
    }
}

/// Verify an RFC 6962 / Crosby-Wallach append-only consistency proof.
///
/// Returns `true` iff `1 <= old_size <= new_size` and the supplied steps prove
/// that `old_root` commits to the exact prefix `[0..old_size)` of the tree
/// committed by `new_root`.
pub fn verify_consistency_proof(check: &ConsistencyCheck, steps: &[ConsistencyStep]) -> bool {
    let old_size = check.old_size;
    let new_size = check.new_size;
    let old_root = check.old_root;
    let new_root = check.new_root;
    let initial_digest = check.initial_digest;
    let is_same_root = same_digest(old_root, new_root);
    let is_initial_root = same_digest(initial_digest, old_root);
    if old_size == 0 || old_size > new_size {
        false
    } else if old_size == new_size {
        steps.is_empty() && is_same_root
    } else {
        let initial = shift_trailing_ones(IndexCursor {
            fn_idx: old_size.saturating_sub(1),
            sn_idx: new_size.saturating_sub(1),
        });
        let is_pow2_ok = initial.fn_idx != 0 || is_initial_root;
        let mut state = ConsistencyState {
            cursor: initial,
            old_acc: initial_digest,
            new_acc: initial_digest,
        };
        let mut is_valid = is_pow2_ok;
        let mut index = 0_usize;
        while index < steps.len() && is_valid {
            match apply_consistency_step(state, steps[index]) {
                Some(next) => {
                    state = next;
                }
                None => {
                    is_valid = false;
                }
            }
            index = index.saturating_add(1);
        }
        let is_old_match = same_digest(state.old_acc, old_root);
        let is_new_match = same_digest(state.new_acc, new_root);
        is_valid && state.cursor.sn_idx == 0 && is_old_match && is_new_match
    }
}

/// Whether two authenticated signed tree heads from the same origin prove
/// Byzantine equivocation (split-view or history rewrite).
pub fn equivocation_detected(facts: EquivocationFacts) -> bool {
    let is_same_root = same_digest(facts.first_root, facts.second_root);
    if !facts.is_both_signed_same_origin || facts.first_size == 0 || facts.second_size == 0 {
        false
    } else if facts.first_size == facts.second_size {
        !is_same_root
    } else {
        matches!(facts.consistency, ConsistencyVerdict::Inconsistent)
    }
}
