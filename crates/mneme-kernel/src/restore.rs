//! Restore gating: a restored copy serves nothing until a current suppression
//! ledger for the same workspace has been applied.

/// The durable restore marker of a workspace handle.
///
/// The marker is written by `open_restored` and read from the ledger on every
/// open, so a process restart cannot clear it.
#[derive(Clone, Copy)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum Marker {
    /// No restore is pending: the copy was never restored, or it applied a
    /// current suppression ledger.
    Clear,
    /// The copy was opened as a restored copy and has not applied a ledger.
    Pending,
}

/// Whether a workspace handle may serve reads, commits, publication, recovery
/// or ledger export.
pub fn may_serve(marker: Marker) -> bool {
    matches!(marker, Marker::Clear)
}

/// Facts about a suppression ledger offered to a restored copy.
#[derive(Clone, Copy)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct LedgerFacts {
    /// The ledger names this workspace's genesis revision.
    pub same_workspace: bool,
    /// The erasure generation recorded in the offered ledger.
    pub ledger_generation: u64,
    /// The erasure generation of the restored copy.
    pub restored_generation: u64,
}

/// What to do with an offered suppression ledger.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum LedgerDecision {
    /// Apply the ledger and clear the pending marker.
    Apply,
    /// The ledger belongs to another workspace.
    ForeignWorkspace,
    /// The ledger is older than the restored copy's own suppression state.
    Stale,
}

/// Decide whether an offered ledger may be applied.
pub fn decide_ledger(facts: &LedgerFacts) -> LedgerDecision {
    if !facts.same_workspace {
        LedgerDecision::ForeignWorkspace
    } else if facts.ledger_generation < facts.restored_generation {
        LedgerDecision::Stale
    } else {
        LedgerDecision::Apply
    }
}
