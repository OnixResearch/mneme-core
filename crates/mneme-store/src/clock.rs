//! Explicit clocks and fault injection for the workspace coordinator.
//!
//! Recorded time is assigned by the coordinator, never by the caller. Tests
//! supply a fixed clock and explicit fault points; production uses the system
//! clock and no injected faults.

use std::time::{SystemTime, UNIX_EPOCH};

use mneme_core::Timestamp;

/// A source of wall-clock instants for recorded time.
pub trait Clock: Send + Sync {
    /// The current instant.
    fn now(&self) -> Timestamp;
}

/// The system clock, truncated to the supported nanosecond range.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_nanos()).ok())
            .unwrap_or(0);
        Timestamp::from_nanos(nanos)
    }
}

/// A clock returning one fixed instant.
#[derive(Clone, Copy, Debug)]
pub struct FixedClock {
    at: Timestamp,
}

impl FixedClock {
    /// Construct a fixed clock.
    pub const fn new(at: Timestamp) -> Self {
        FixedClock { at }
    }
}

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        self.at
    }
}
