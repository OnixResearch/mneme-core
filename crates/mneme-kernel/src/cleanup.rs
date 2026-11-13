//! Retention cleanup accounting.
//!
//! A retention job is complete only when every inventoried location is settled:
//! purged, found absent by inspection, or verified after a purge. A location
//! that failed, is still pending, holds shared bytes, or could not be reached
//! is never reported as cleaned.

/// The recorded state of one inventoried cleanup location.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum LocationState {
    /// Not yet attempted.
    Pending,
    /// The bytes were deleted.
    Purged,
    /// Inspection found nothing at the location.
    Absent,
    /// Another retained owner still needs the same bytes.
    RetainedShared,
    /// The location could not be reached or is not a managed regular file.
    Unavailable,
    /// A purge was verified by a later inspection.
    Verified,
    /// The last attempt failed.
    Failed,
}

/// Whether a location holds none of the targeted bytes.
pub fn is_settled(state: LocationState) -> bool {
    matches!(
        state,
        LocationState::Purged | LocationState::Absent | LocationState::Verified
    )
}

/// Whether a resume must attempt or re-inspect a location.
///
/// Failed purges are retried. Shared and unavailable locations are inspected
/// again because the sharing owner may be gone or the location reachable.
pub fn needs_attempt(state: LocationState) -> bool {
    matches!(
        state,
        LocationState::Pending
            | LocationState::Failed
            | LocationState::RetainedShared
            | LocationState::Unavailable
    )
}

/// The overall state of a cleanup job.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum JobSummary {
    /// Every location is settled.
    Complete,
    /// No work is pending or failed, but some bytes are shared or unreachable.
    Partial,
    /// At least one location has not been attempted.
    Pending,
    /// At least one attempt failed and none is pending.
    Failed,
}

/// Whether every location is settled.
///
/// An empty inventory is not complete: a cleanup that inspected nothing cannot
/// claim that nothing remains.
pub fn physically_complete(states: &[LocationState]) -> bool {
    let mut is_all_settled = !states.is_empty();
    let mut index = 0_usize;
    while index < states.len() && is_all_settled {
        is_all_settled = is_settled(states[index]);
        index += 1;
    }
    is_all_settled
}

/// Summarize a cleanup job from its location states.
pub fn summarize(states: &[LocationState]) -> JobSummary {
    let mut has_pending = false;
    let mut has_failed = false;
    let mut is_partial = states.is_empty();
    let mut index = 0_usize;
    while index < states.len() {
        let state = states[index];
        has_pending = has_pending || matches!(state, LocationState::Pending);
        has_failed = has_failed || matches!(state, LocationState::Failed);
        is_partial = is_partial
            || matches!(
                state,
                LocationState::RetainedShared | LocationState::Unavailable
            );
        index += 1;
    }
    if has_pending {
        JobSummary::Pending
    } else if has_failed {
        JobSummary::Failed
    } else if is_partial {
        JobSummary::Partial
    } else {
        JobSummary::Complete
    }
}
