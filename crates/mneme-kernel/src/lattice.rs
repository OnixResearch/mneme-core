//! Bloom^L Merkle-CRDT multi-parent DAG join-semilattice, concurrent frontier
//! projection, and suppression dominance.
//!
//! Based on:
//! - N. Conway et al., *Logic and Lattices for Distributed Programming
//!   (`Bloom^L`)* (ACM SoCC 2012);
//! - H. Sanjuán et al., *Merkle-CRDTs* (2020; Shapiro et al., SSS 2011).
//!
//! Every record's causal DAG state forms a Stratum M join-semilattice:
//! - Ingested revision nodes (`nodes_mask`) and cited parent links
//!   (`cited_mask`) grow monotonically under bitwise union (associative,
//!   commutative, idempotent, inflationary).
//! - The active maximal frontier is `nodes_mask & !cited_mask`.
//! - Any concurrent frontier (`|frontier(r)| > 1`) deterministically projects
//!   to [`crate::claim::Lifecycle::Disputed`] (never LWW silent overwrite and
//!   never auto-promoting to `Accepted`) until an explicit
//!   `ConflictResolution` merge decision cites every frontier parent.
//! - Inflationary suppression (`None < Withdrawn < Forgotten`) dominates all
//!   DAG branches.
#![allow(unknown_lints, type_accumulation, fragile_exhaustive_enum_match)] // cohesive Bloom^L lattice decision family verified exhaustively in Lean 4

/// Minimum frontier cardinality that indicates concurrent offline edits.
pub const CONCURRENT_FRONTIER_MIN: u32 = 2;

const EMPTY_FRONTIER_MASK: u64 = 0;
const SINGLE_BIT_STEP: u64 = 1;
const EMPTY_FRONTIER_COUNT: u32 = 0;
const SUPPRESSION_NONE_RANK: u8 = 0;
const SUPPRESSION_WITHDRAWN_RANK: u8 = 1;
const SUPPRESSION_FORGOTTEN_RANK: u8 = 2;

/// Compact join-semilattice state of a record's Merkle-CRDT causal DAG.
///
/// Each bit position `0..64` corresponds to a revision slot within one bounded
/// causal comparison window.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct FrontierState {
    /// G-Set bitmask of ingested revision nodes.
    pub nodes_mask: u64,
    /// G-Set bitmask of revision nodes cited as a parent by an ingested child.
    pub cited_mask: u64,
    /// Inflationary suppression state across all DAG branches.
    pub suppression: crate::calm::SuppressionState,
}

/// Stratum M join-semilattice operation over [`FrontierState`].
///
/// Unions the ingested node set and cited-parent set, and joins the
/// inflationary suppression state (`None < Withdrawn < Forgotten`,
/// `max(generation)`).
pub fn join_frontier(left: FrontierState, right: FrontierState) -> FrontierState {
    FrontierState {
        nodes_mask: left.nodes_mask | right.nodes_mask,
        cited_mask: left.cited_mask | right.cited_mask,
        suppression: crate::calm::join_suppression(left.suppression, right.suppression),
    }
}

/// Active maximal frontier bitmask: ingested nodes not cited as any parent.
pub fn frontier_mask(state: FrontierState) -> u64 {
    state.nodes_mask & !state.cited_mask
}

/// Apply one revision node and its parent bitmask to a [`FrontierState`].
pub fn ingest_node(state: FrontierState, node_bit: u64, parents_mask: u64) -> FrontierState {
    FrontierState {
        nodes_mask: state.nodes_mask | node_bit,
        cited_mask: state.cited_mask | parents_mask,
        suppression: state.suppression,
    }
}

/// Whether `mask` represents two or more concurrent maximal frontier heads.
pub fn is_concurrent_mask(mask: u64) -> bool {
    if mask == EMPTY_FRONTIER_MASK {
        false
    } else {
        (mask & mask.wrapping_sub(SINGLE_BIT_STEP)) != EMPTY_FRONTIER_MASK
    }
}

/// Whether a maximal frontier cardinality indicates concurrent offline edits.
pub fn is_concurrent_frontier(frontier_count: u32) -> bool {
    frontier_count >= CONCURRENT_FRONTIER_MIN
}

/// Facts needed to project a record's maximal frontier and suppression state
/// into an epistemic view.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct FrontierProjectionInput {
    /// Cardinality `|frontier(r)|` of the record's active maximal frontier.
    pub frontier_count: u32,
    /// Lifecycle of the unique frontier head when `frontier_count == 1`.
    pub head_lifecycle: crate::claim::Lifecycle,
    /// Joined suppression level across all DAG branches.
    pub suppression: crate::calm::SuppressionLevel,
}

/// Deterministic epistemic projection of a record's Merkle-CRDT frontier.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum ProjectedView {
    /// Record has no active frontier nodes and is not suppressed.
    Absent,
    /// Record has a unique maximal frontier head with the given lifecycle.
    Active(crate::claim::Lifecycle),
    /// Record has multiple concurrent maximal frontier heads (`>= 2`); always
    /// surfaces as `Disputed` until resolved by an explicit merge `Decision`.
    DisputedConcurrent { frontier_count: u32 },
    /// Record is suppressed as `Withdrawn`, dominating all DAG branches.
    Withdrawn,
    /// Record is permanently `Forgotten`, absorbing and dominating all branches.
    Forgotten,
}

/// Project a record's maximal frontier and suppression state into a
/// deterministic [`ProjectedView`].
///
/// Suppression dominates all DAG branches (`Forgotten` and `Withdrawn` override
/// any frontier). Otherwise, any multi-head frontier (`frontier_count >= 2`)
/// projects to [`ProjectedView::DisputedConcurrent`] — never LWW overwrite and
/// never auto-promoting to `Accepted`.
pub fn project_frontier(input: &FrontierProjectionInput) -> ProjectedView {
    let rank = crate::calm::suppression_rank(input.suppression);
    if rank >= SUPPRESSION_FORGOTTEN_RANK {
        ProjectedView::Forgotten
    } else if rank == SUPPRESSION_WITHDRAWN_RANK {
        ProjectedView::Withdrawn
    } else if input.frontier_count == EMPTY_FRONTIER_COUNT {
        ProjectedView::Absent
    } else if is_concurrent_frontier(input.frontier_count) {
        ProjectedView::DisputedConcurrent {
            frontier_count: input.frontier_count,
        }
    } else {
        ProjectedView::Active(input.head_lifecycle)
    }
}

/// Effective assertion lifecycle implied by a [`ProjectedView`].
///
/// Concurrent frontiers always yield `Some(Lifecycle::Disputed)`, and
/// suppressed or absent views yield `None`.
pub fn projected_lifecycle(view: ProjectedView) -> Option<crate::claim::Lifecycle> {
    match view {
        ProjectedView::Active(lifecycle) => Some(lifecycle),
        ProjectedView::DisputedConcurrent { .. } => Some(crate::claim::Lifecycle::Disputed),
        ProjectedView::Absent | ProjectedView::Withdrawn | ProjectedView::Forgotten => None,
    }
}

/// Facts checked when an explicit merge revision resolves a concurrent frontier.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct MergeResolutionFacts {
    /// Current cardinality of the record's maximal frontier.
    pub frontier_count: u32,
    /// Number of current maximal frontier heads cited in the merge's `parents`.
    pub cited_frontier_count: u32,
    /// Whether an explicit `ConflictResolution` decision backs this merge.
    pub has_conflict_resolution_decision: bool,
    /// Joined suppression level across all DAG branches.
    pub suppression: crate::calm::SuppressionLevel,
}

/// Outcome of validating an explicit merge revision over a concurrent frontier.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum MergeResolutionVerdict {
    /// Merge cites every frontier parent and carries an explicit decision.
    Allowed,
    /// Record is withdrawn or forgotten; suppression dominates merges.
    RefusedSuppressed,
    /// Merge does not cite every active frontier head (or frontier is not concurrent).
    RefusedIncompleteParents,
    /// Merge lacks an explicit `ConflictResolution` decision.
    RefusedMissingDecision,
}

/// Decide whether a merge revision may resolve a disputed concurrent frontier.
pub fn decide_frontier_merge(facts: &MergeResolutionFacts) -> MergeResolutionVerdict {
    let rank = crate::calm::suppression_rank(facts.suppression);
    if rank > SUPPRESSION_NONE_RANK {
        MergeResolutionVerdict::RefusedSuppressed
    } else if !is_concurrent_frontier(facts.frontier_count)
        || facts.cited_frontier_count != facts.frontier_count
    {
        MergeResolutionVerdict::RefusedIncompleteParents
    } else if !facts.has_conflict_resolution_decision {
        MergeResolutionVerdict::RefusedMissingDecision
    } else {
        MergeResolutionVerdict::Allowed
    }
}
