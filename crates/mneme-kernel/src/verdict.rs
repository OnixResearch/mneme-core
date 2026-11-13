//! Acceptance status algebra.
//!
//! Statuses combine by severity. Nothing aggregates to `Passed` from an empty
//! set: a suite without cases, a capability without suites and a requirement
//! list without capabilities are all unimplemented, never satisfied.

/// The outcome of a case, suite or capability.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum Status {
    /// Every check ran and held.
    Passed,
    /// At least one check failed.
    Failed,
    /// The case was declared skipped and did not fail.
    Skipped,
    /// No runner or no evidence exists.
    Unimplemented,
}

/// Severity order: passed < skipped < unimplemented < failed.
pub fn severity(outcome: Status) -> u8 {
    match outcome {
        Status::Passed => 0,
        Status::Skipped => 1,
        Status::Unimplemented => 2,
        Status::Failed => 3,
    }
}

/// The more severe of two statuses.
pub fn merge(left: Status, right: Status) -> Status {
    if severity(left) >= severity(right) {
        left
    } else {
        right
    }
}

/// Whether a case's fixture declared that the case is skipped.
#[derive(Clone, Copy)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum SkipDeclaration {
    /// The fixture declares no skip.
    NotDeclared,
    /// The fixture declares the case skipped.
    Declared,
}

/// The status of a case that was run.
///
/// A declared skip never hides a failure: a skipped case that fails is failed.
pub fn case_status(declaration: SkipDeclaration, observed: Status) -> Status {
    if matches!(observed, Status::Failed) {
        Status::Failed
    } else if matches!(declaration, SkipDeclaration::Declared) {
        Status::Skipped
    } else {
        observed
    }
}

/// The combined status of a non-empty set; `Unimplemented` for an empty set.
pub fn aggregate(statuses: &[Status]) -> Status {
    if statuses.is_empty() {
        Status::Unimplemented
    } else {
        let mut combined = Status::Passed;
        let mut index = 0_usize;
        while index < statuses.len() {
            combined = merge(combined, statuses[index]);
            index += 1;
        }
        combined
    }
}

/// Whether a strict acceptance gate is satisfied: at least one capability is
/// required and every capability passed.
pub fn acceptance_satisfied(capabilities: &[Status]) -> bool {
    matches!(aggregate(capabilities), Status::Passed)
}
