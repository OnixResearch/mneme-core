//! Completeness and absence.
//!
//! An empty answer establishes absence only when the evaluation was
//! exhaustive over complete, correctly declared inputs, no limit was reached,
//! and no erasure barrier advanced while it ran. A top-k result, a timeout, a
//! stale projection or a mis-declared relation cannot establish absence.

/// How much of a relation's canonical extent was loaded.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum Coverage {
    /// Every retained fact of the relation was loaded.
    Complete,
    /// Loading stopped early or some facts were unavailable.
    Incomplete,
    /// The relation is not a known canonical extent.
    Unknown,
}

/// Facts about one answer.
#[derive(Clone, Copy)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct AnswerFacts {
    /// Number of rows or candidates in the answer.
    pub rows: u64,
    /// The evaluation ran to its fixpoint or scanned its whole input.
    pub exhaustive: bool,
    /// Combined coverage of every relation the answer depends on.
    pub coverage: Coverage,
    /// A row, work, byte, time or cancellation limit was reached.
    pub limit_reached: bool,
    /// Every declared relation shape matches its canonical extent.
    pub declaration_valid: bool,
    /// The erasure generation is unchanged since the snapshot was pinned.
    pub generation_current: bool,
}

/// Whether the answer contains every row that exists.
pub fn answer_complete(facts: &AnswerFacts) -> bool {
    facts.exhaustive
        && matches!(facts.coverage, Coverage::Complete)
        && !facts.limit_reached
        && facts.declaration_valid
        && facts.generation_current
}

/// Whether an empty answer establishes that no row exists.
pub fn absence_established(facts: &AnswerFacts) -> bool {
    facts.rows == 0 && answer_complete(facts)
}

/// The weaker of two coverage levels: unknown, then incomplete, then complete.
pub fn combine_coverage(left: Coverage, right: Coverage) -> Coverage {
    match (left, right) {
        (Coverage::Unknown, _) => Coverage::Unknown,
        (_, Coverage::Unknown) => Coverage::Unknown,
        (Coverage::Incomplete, _) => Coverage::Incomplete,
        (_, Coverage::Incomplete) => Coverage::Incomplete,
        (Coverage::Complete, Coverage::Complete) => Coverage::Complete,
    }
}
