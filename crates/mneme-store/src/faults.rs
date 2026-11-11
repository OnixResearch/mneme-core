//! Fault injection points for durability and recovery tests.

/// A durable boundary at which a test may simulate a process stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FaultPoint {
    /// Immutable blobs are staged but no manifest transaction has started.
    AfterBlobStaging,
    /// Immediately before the ledger transaction begins.
    BeforeCommitTransaction,
    /// The ledger transaction committed but publication has not run.
    AfterCommit,
    /// Immediately before an atomic working-file replacement.
    BeforeFileReplace,
    /// After the working-file rename but before publication is marked done.
    AfterFileReplace,
    /// Immediately before a retention payload is removed.
    BeforeRetentionPurge,
    /// After a retention payload removal but before its ledger state is saved.
    AfterRetentionPurge,
}

/// A policy deciding whether to inject a fault at a boundary.
pub trait FaultInjector: Send + Sync {
    /// Whether the process should stop at this point.
    fn inject(&self, point: FaultPoint) -> bool;
}

/// No injected faults.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoFaults;

impl FaultInjector for NoFaults {
    fn inject(&self, _point: FaultPoint) -> bool {
        false
    }
}

/// Inject a fault at exactly one boundary.
#[derive(Clone, Copy, Debug)]
pub struct FaultAt(pub FaultPoint);

impl FaultInjector for FaultAt {
    fn inject(&self, point: FaultPoint) -> bool {
        point == self.0
    }
}

/// Stop at a boundary if the injector requests it.
pub fn check(faults: &dyn FaultInjector, point: FaultPoint) -> crate::error::Result<()> {
    if faults.inject(point) {
        Err(crate::error::StoreError::InjectedFault(point))
    } else {
        Ok(())
    }
}
