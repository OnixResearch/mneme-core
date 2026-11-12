//! Explicit clocks and fault injection for the workspace coordinator.
//!
//! Recorded time is assigned by the coordinator, never by the caller. Tests
//! supply a fixed clock and explicit fault points; production uses the system
//! clock and no injected faults.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// A source of wall-clock instants for recorded time.
pub trait Clock: Send + Sync {
    /// The current instant.
    fn now(&self) -> mneme_core::Timestamp;
}

/// The system clock, truncated to the supported nanosecond range.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    // This is the one explicit system-clock adapter; core code receives `Clock`.
    #[allow(unknown_lints, ambient_clock)]
    fn now(&self) -> mneme_core::Timestamp {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_nanos()).ok())
            .unwrap_or(0);
        mneme_core::Timestamp::from_nanos(nanos)
    }
}

/// A clock returning one fixed instant.
#[derive(Clone, Copy, Debug)]
pub struct FixedClock {
    at: mneme_core::Timestamp,
}

impl FixedClock {
    /// Construct a fixed clock.
    pub const fn new(at: mneme_core::Timestamp) -> Self {
        FixedClock { at }
    }
}

impl Clock for FixedClock {
    fn now(&self) -> mneme_core::Timestamp {
        self.at
    }
}
