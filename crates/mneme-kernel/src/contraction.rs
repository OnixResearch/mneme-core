//! Well-founded groundedness reachability and Hansson finite-base kernel
//! contraction with deterministic epistemic-entrenchment incision.
//!
//! Based on Alchourrón, Gärdenfors, & Makinson (JSL 1985) and S. O. Hansson,
//! *Kernel Contraction* (JSL 59(3), 1994; *A Textbook of Belief Dynamics*, 1999):
//! - **Well-founded groundedness (`edge_is_grounded`, `node_next_grounded`)**:
//!   starting from surviving non-withdrawn root leaves, iteratively grounds any
//!   target node with a complete non-empty supporting hyperedge whose premises
//!   are all grounded. Any unfounded self-supporting cycle disjoint from
//!   surviving roots remains ungrounded across every step and at fixpoint.
//! - **Hansson kernel contraction (`select_incision`, `is_incised`,
//!   `survives_incision`, `any_proof_survives`)**: given a finite base `B` and
//!   minimal `φ`-kernel family `B ⊥ φ`, applies a deterministic
//!   epistemic-entrenchment incision `σ` ordered strictly by
//!   `OriginTier` (`ModelExtraction < Imported < Authored`), independent
//!   `RootIdentity` corroboration count, and canonical `RecordId` tie-break.

const RANK_MODEL_EXTRACTION: u8 = 0;
const RANK_IMPORTED: u8 = 1;
const RANK_AUTHORED: u8 = 2;

/// Epistemic origin tier ordered from least to most entrenched.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum OriginTier {
    /// Lowest entrenchment: machine extraction or derived inference.
    ModelExtraction,
    /// Middle entrenchment: external import or automated observation.
    Imported,
    /// Highest entrenchment: human-authored statement.
    Authored,
}

/// Deterministic epistemic-entrenchment key for one candidate base record.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct EntrenchmentKey {
    /// Origin tier (`ModelExtraction < Imported < Authored`).
    pub origin: OriginTier,
    /// Count of distinct surviving `RootIdentity` corroborations.
    pub root_count: u64,
    /// Canonical `RecordId` tie-breaker (`u128::from_be_bytes`).
    pub record_id: u128,
}

/// Contiguous slice range `[start, start + len)` into a flat support table.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
#[allow(unknown_lints, usize_in_public_api)] // slice offset and length indexing flat kernel buffers
pub struct RangeSpan {
    /// Starting element index in the backing slice.
    pub start: usize,
    /// Number of elements in the span.
    pub len: usize,
}

/// One conjunctive supporting hyperedge `premises -> target`.
///
/// `target` becomes grounded once `premises` is non-empty, in bounds, and
/// every referenced premise node is grounded.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
#[allow(unknown_lints, usize_in_public_api)] // node index into flat grounded slice
pub struct SupportEdge {
    /// Node index grounded by this supporting hyperedge.
    pub target: usize,
    /// Range of premise node indices in the flat `premises` table.
    pub premises: RangeSpan,
}

/// Monotonic numeric rank of an [`OriginTier`] (`0 < 1 < 2`).
pub fn origin_rank(tier: OriginTier) -> u8 {
    if matches!(tier, OriginTier::ModelExtraction) {
        RANK_MODEL_EXTRACTION
    } else if matches!(tier, OriginTier::Imported) {
        RANK_IMPORTED
    } else {
        RANK_AUTHORED
    }
}

/// Strict total epistemic-entrenchment order: `true` iff `left` is strictly
/// less entrenched than `right` (and therefore incised before `right`).
pub fn less_entrenched(left: &EntrenchmentKey, right: &EntrenchmentKey) -> bool {
    let left_rank = origin_rank(left.origin);
    let right_rank = origin_rank(right.origin);
    if left_rank != right_rank {
        left_rank < right_rank
    } else if left.root_count != right.root_count {
        left.root_count < right.root_count
    } else {
        left.record_id < right.record_id
    }
}

/// Validate a non-empty [`RangeSpan`] against a backing slice of length `limit`,
/// returning its exclusive stop index `start + len` when in bounds.
fn span_stop(span: RangeSpan, limit: usize) -> Option<usize> {
    if span.len == 0 {
        None
    } else {
        match span.start.checked_add(span.len) {
            Some(stop) => {
                if stop <= limit {
                    Some(stop)
                } else {
                    None
                }
            }
            None => None,
        }
    }
}

/// Select the unique least-entrenched candidate in the minimal-proof slice
/// `members[span.start .. span.start + span.len]`.
///
/// Returns `None` when `span` is empty or out of bounds.
pub fn select_incision(members: &[EntrenchmentKey], span: RangeSpan) -> Option<EntrenchmentKey> {
    match span_stop(span, members.len()) {
        None => None,
        Some(stop) => {
            let mut chosen = members[span.start];
            let mut cursor = span.start.saturating_add(1);
            while cursor < stop {
                let candidate = members[cursor];
                if less_entrenched(&candidate, &chosen) {
                    chosen = candidate;
                }
                cursor = cursor.saturating_add(1);
            }
            Some(chosen)
        }
    }
}

/// Whether `record_id` is selected for removal by the entrenchment incision
/// `σ(B ⊥ φ)` over the minimal-proof family `(members, spans)`.
pub fn is_incised(record_id: u128, members: &[EntrenchmentKey], spans: &[RangeSpan]) -> bool {
    let mut is_cut = false;
    let mut index = 0_usize;
    while index < spans.len() && !is_cut {
        if let Some(chosen) = select_incision(members, spans[index]) {
            is_cut = chosen.record_id == record_id;
        }
        index = index.saturating_add(1);
    }
    is_cut
}

/// Whether `record_id` occurs in the finite belief base `base`.
fn in_base(record_id: u128, base: &[u128]) -> bool {
    let mut is_member = false;
    let mut index = 0_usize;
    while index < base.len() && !is_member {
        if base[index] == record_id {
            is_member = true;
        }
        index = index.saturating_add(1);
    }
    is_member
}

/// Membership in the Hansson contracted belief base `B ÷_σ φ = B \ σ(B ⊥ φ)`.
pub fn survives_incision(
    record_id: u128,
    base: &[u128],
    members: &[EntrenchmentKey],
    spans: &[RangeSpan],
) -> bool {
    in_base(record_id, base) && !is_incised(record_id, members, spans)
}

/// Whether every element of one valid non-empty minimal proof `span` survives
/// in `B ÷_σ φ`.
fn span_all_survive(
    base: &[u128],
    members: &[EntrenchmentKey],
    span: RangeSpan,
    all_spans: &[RangeSpan],
) -> bool {
    match span_stop(span, members.len()) {
        None => false,
        Some(stop) => {
            let mut is_all_surviving = true;
            let mut cursor = span.start;
            while cursor < stop && is_all_surviving {
                is_all_surviving =
                    survives_incision(members[cursor].record_id, base, members, all_spans);
                cursor = cursor.saturating_add(1);
            }
            is_all_surviving
        }
    }
}

/// Whether any valid non-empty minimal proof in `(members, spans)` remains
/// entirely inside `B ÷_σ φ`.
///
/// By Hansson's Success postulate, this is always `false` when every proof in
/// `spans` is non-empty and in bounds.
pub fn any_proof_survives(base: &[u128], members: &[EntrenchmentKey], spans: &[RangeSpan]) -> bool {
    let mut has_surviving = false;
    let mut index = 0_usize;
    while index < spans.len() && !has_surviving {
        has_surviving = span_all_survive(base, members, spans[index], spans);
        index = index.saturating_add(1);
    }
    has_surviving
}

/// Whether `edge` is a valid non-empty supporting hyperedge whose premises are
/// all currently marked grounded.
#[allow(unknown_lints, usize_in_public_api)] // premise indices into flat grounded slice
pub fn edge_is_grounded(edge: &SupportEdge, premises: &[usize], grounded: &[bool]) -> bool {
    if edge.target >= grounded.len() {
        false
    } else {
        match span_stop(edge.premises, premises.len()) {
            None => false,
            Some(stop) => {
                let mut is_all_grounded = true;
                let mut cursor = edge.premises.start;
                while cursor < stop && is_all_grounded {
                    let premise = premises[cursor];
                    is_all_grounded = premise < grounded.len() && grounded[premise];
                    cursor = cursor.saturating_add(1);
                }
                is_all_grounded
            }
        }
    }
}

/// Single well-founded grounding step for `node`: returns `true` iff `node` is
/// in bounds and is either already grounded or supported by at least one
/// complete non-empty hyperedge in `edges` whose premises are all grounded.
///
/// Any unfounded self-supporting cycle disjoint from initially grounded
/// surviving roots never becomes grounded under repeated application.
#[allow(unknown_lints, usize_in_public_api)] // node and premise indices into flat grounded slice
pub fn node_next_grounded(
    node: usize,
    edges: &[SupportEdge],
    premises: &[usize],
    grounded: &[bool],
) -> bool {
    if node >= grounded.len() {
        false
    } else if grounded[node] {
        true
    } else {
        let mut is_grounded = false;
        let mut index = 0_usize;
        while index < edges.len() && !is_grounded {
            let edge = edges[index];
            if edge.target == node && edge_is_grounded(&edge, premises, grounded) {
                is_grounded = true;
            }
            index = index.saturating_add(1);
        }
        is_grounded
    }
}
