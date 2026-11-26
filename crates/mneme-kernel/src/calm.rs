//! CALM monotonicity stratification, inflationary suppression lattice, and
//! `CalmSeal` gating for federated closed-world negation.
//!
//! Based on Hellerstein & Alvaro, *Keeping CALM: When Distributed Consistency
//! Is Easy* (CACM 63(9), 2020; Ameloot et al., PODS 2011):
//! - **Stratum M (`CalmStratum::Monotonic`)**: coordination-free monotonic
//!   operations whose joins form a join-semilattice (associative, commutative,
//!   idempotent, and inflationary).
//! - **Stratum B (`CalmStratum::Barrier`)**: non-monotonic operations that
//!   require an explicit signed [`CalmSealFacts`] barrier before claiming
//!   global completeness or absence.

const SUPPRESSION_RANK_NONE: u8 = 0;
const SUPPRESSION_RANK_WITHDRAWN: u8 = 1;
const SUPPRESSION_RANK_FORGOTTEN: u8 = 2;

/// CALM coordination stratum for a distributed Mneme operation.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum CalmStratum {
    /// Stratum M: coordination-free monotonic operation.
    Monotonic,
    /// Stratum B: barrier-gated non-monotonic operation.
    Barrier,
}

/// Distributed Mneme operation classified under CALM stratification.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum DistributedOp {
    /// Appending an immutable `SourceRevision`, `Entity`, `Relation`, or `Proposed` `Assertion`.
    AppendImmutableRecord,
    /// Merging a signed capability `RevocationTombstone` into the G-Set.
    MergeRevocationTombstone,
    /// Merging an inflationary retention suppression (`None < Withdrawn < Forgotten`).
    MergeSuppression,
    /// Evaluating positive (negation-free) federated Datalog.
    PositiveFederatedDatalog,
    /// Promoting a `Decision` (`Proposed -> Accepted` or `ConflictResolution`).
    PromoteDecision,
    /// Evaluating closed-world negated federated Datalog (`absence_established`).
    NegatedFederatedDatalog,
    /// Reclaiming shared physical blobs during retention garbage collection.
    SharedBlobPhysicalGc,
}

/// Classify a distributed Mneme operation into Stratum M or Stratum B.
pub fn classify_op(op: DistributedOp) -> CalmStratum {
    match op {
        DistributedOp::AppendImmutableRecord => CalmStratum::Monotonic,
        DistributedOp::MergeRevocationTombstone => CalmStratum::Monotonic,
        DistributedOp::MergeSuppression => CalmStratum::Monotonic,
        DistributedOp::PositiveFederatedDatalog => CalmStratum::Monotonic,
        DistributedOp::PromoteDecision => CalmStratum::Barrier,
        DistributedOp::NegatedFederatedDatalog => CalmStratum::Barrier,
        DistributedOp::SharedBlobPhysicalGc => CalmStratum::Barrier,
    }
}

/// Whether `op` requires an explicit Stratum B coordination barrier (`CalmSeal`).
pub fn requires_barrier(op: DistributedOp) -> bool {
    matches!(classify_op(op), CalmStratum::Barrier)
}

/// Ordered suppression lattice element (`None < Withdrawn < Forgotten`).
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum SuppressionLevel {
    /// Record is active and visible.
    None,
    /// Record is withdrawn from default views.
    Withdrawn,
    /// Record is permanently forgotten; never resurrected by sync or replay.
    Forgotten,
}

/// Monotonic numeric rank of a suppression level (`None (0) < Withdrawn (1) < Forgotten (2)`).
pub fn suppression_rank(level: SuppressionLevel) -> u8 {
    match level {
        SuppressionLevel::None => SUPPRESSION_RANK_NONE,
        SuppressionLevel::Withdrawn => SUPPRESSION_RANK_WITHDRAWN,
        SuppressionLevel::Forgotten => SUPPRESSION_RANK_FORGOTTEN,
    }
}

/// Inflationary join on [`SuppressionLevel`]: the stronger suppression always wins.
pub fn join_suppression_level(left: SuppressionLevel, right: SuppressionLevel) -> SuppressionLevel {
    if suppression_rank(left) >= suppression_rank(right) {
        left
    } else {
        right
    }
}

/// Suppression state paired with its monotonic eligibility generation barrier.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct SuppressionState {
    /// Current suppression level in `None < Withdrawn < Forgotten`.
    pub level: SuppressionLevel,
    /// Monotonic eligibility generation at which this suppression was established.
    pub generation: u64,
}

/// Stratum M join-semilattice operation over [`SuppressionState`]:
/// takes the stronger suppression level and `max(generation)`.
pub fn join_suppression(left: SuppressionState, right: SuppressionState) -> SuppressionState {
    let level = join_suppression_level(left.level, right.level);
    let generation = if left.generation >= right.generation {
        left.generation
    } else {
        right.generation
    };
    SuppressionState { level, generation }
}

/// Verified facts about a signed cross-vault `CalmSeal`.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct CalmSealFacts {
    /// A cryptographically signed `CalmSeal` covering the query scope is present.
    pub sealed: bool,
    /// Every attached vault in the frontier satisfies the seal's signed heads.
    pub quorum_satisfied: bool,
    /// The seal's epoch generation matches the pinned eligibility generation.
    pub epoch_matches: bool,
}

/// Whether a `CalmSeal` satisfies all barrier prerequisites.
pub fn seal_valid(facts: &CalmSealFacts) -> bool {
    facts.sealed && facts.quorum_satisfied && facts.epoch_matches
}

/// Facts governing whether a federated query may emit `absence_established = true`.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct FederatedNegationFacts {
    /// Result of single-vault [`crate::completeness::absence_established`].
    pub local_absence_established: bool,
    /// CALM stratum of the query (`Barrier` for negated/closed-world federated Datalog).
    pub stratum: CalmStratum,
    /// Whether the query is evaluated across a federation boundary.
    pub is_federated: bool,
    /// Verified `CalmSeal` barrier facts for this query.
    pub barrier_seal: CalmSealFacts,
}

/// Gate `absence_established` for federated queries under CALM stratification.
///
/// An unsealed federated Stratum B (negated) query never admits
/// `absence_established = true`.
pub fn federated_absence_established(facts: &FederatedNegationFacts) -> bool {
    if !facts.local_absence_established {
        false
    } else if facts.is_federated && matches!(facts.stratum, CalmStratum::Barrier) {
        seal_valid(&facts.barrier_seal)
    } else {
        true
    }
}
