//! Hybrid Logical Clock (HLC) transition rules and drift guards.
//!
//! Pure `no_std` implementation of Kulkarni et al., *Logical Physical Clocks
//! and Consistent Snapshots in Globally Distributed Databases* (OPODIS 2014).
//!
//! Every transition enforces:
//! - **Causal monotonicity**: every local tick or receive strictly advances the
//!   `(physical_ns, logical)` pair beyond its causal predecessors.
//! - **Bounded physical drift**: the physical component never drifts further
//!   than `max_skew_ns` from the node's local physical clock `physical_ns`,
//!   failing closed with [`HlcError::ClockSkewExceeded`] on excessive skew.

/// Default maximum permitted physical clock skew (5 seconds in nanoseconds).
pub const DEFAULT_MAX_SKEW_NS: i64 = 5_000_000_000;

/// 12-byte-payload Hybrid Logical Clock timestamp `(physical_ns, logical)`.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct HybridTimestamp {
    /// Physical time component in Unix nanoseconds.
    pub physical_ns: i64,
    /// Logical counter disambiguating causal events sharing `physical_ns`.
    pub logical: u32,
}

/// Total lexicographic ordering between two [`HybridTimestamp`] values.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum ClockOrder {
    /// Left timestamp strictly precedes right timestamp.
    Less,
    /// Both timestamps are equal.
    Equal,
    /// Left timestamp strictly follows right timestamp.
    Greater,
}

/// Fail-closed HLC transition error.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum HlcError {
    /// Remote or local physical time diverged beyond `max_skew_ns`.
    ClockSkewExceeded,
    /// Logical counter reached `u32::MAX` without physical time advancing.
    LogicalOverflow,
    /// Caller supplied a negative `max_skew_ns` bound.
    InvalidMaxSkew,
}

/// Lexicographic comparison of two [`HybridTimestamp`] values.
pub fn compare(left: HybridTimestamp, right: HybridTimestamp) -> ClockOrder {
    if left.physical_ns < right.physical_ns {
        ClockOrder::Less
    } else if left.physical_ns > right.physical_ns {
        ClockOrder::Greater
    } else if left.logical < right.logical {
        ClockOrder::Less
    } else if left.logical > right.logical {
        ClockOrder::Greater
    } else {
        ClockOrder::Equal
    }
}

/// Whether `left` strictly precedes `right` in HLC order (`left < right`).
pub fn is_before(left: HybridTimestamp, right: HybridTimestamp) -> bool {
    matches!(compare(left, right), ClockOrder::Less)
}

/// Whether `left` precedes or equals `right` in HLC order (`left <= right`).
pub fn is_at_or_before(left: HybridTimestamp, right: HybridTimestamp) -> bool {
    !matches!(compare(left, right), ClockOrder::Greater)
}

/// Overflow-free check that `|sample_ns - reference_ns| <= max_skew_ns`
/// for non-negative `max_skew_ns`.
pub fn within_skew(sample_ns: i64, reference_ns: i64, max_skew_ns: i64) -> bool {
    if max_skew_ns < 0 {
        return false;
    }
    let ceiling = i64::MAX - max_skew_ns;
    if reference_ns <= ceiling {
        let upper = reference_ns + max_skew_ns;
        if sample_ns > upper {
            return false;
        }
    }
    if sample_ns <= ceiling {
        let lower = sample_ns + max_skew_ns;
        if reference_ns > lower {
            return false;
        }
    }
    true
}

/// Advance the local HLC on a local commit or outbound send event.
///
/// Fails closed with [`HlcError::ClockSkewExceeded`] if `last.physical_ns`
/// exceeds `physical_ns` by more than `max_skew_ns`, and with
/// [`HlcError::LogicalOverflow`] if `last.logical == u32::MAX` while physical
/// time has not advanced.
pub fn tick_local(
    last: HybridTimestamp,
    physical_ns: i64,
    max_skew_ns: i64,
) -> Result<HybridTimestamp, HlcError> {
    if max_skew_ns < 0 {
        Err(HlcError::InvalidMaxSkew)
    } else if physical_ns > last.physical_ns {
        Ok(HybridTimestamp {
            physical_ns,
            logical: 0,
        })
    } else if !within_skew(last.physical_ns, physical_ns, max_skew_ns) {
        Err(HlcError::ClockSkewExceeded)
    } else if last.logical == u32::MAX {
        Err(HlcError::LogicalOverflow)
    } else {
        Ok(HybridTimestamp {
            physical_ns: last.physical_ns,
            logical: last.logical + 1,
        })
    }
}

/// Advance the local HLC upon receiving a message carrying `remote`.
///
/// Fails closed with [`HlcError::ClockSkewExceeded`] if
/// `|remote.physical_ns - physical_ns| > max_skew_ns` or if the resulting
/// physical component drifts beyond `max_skew_ns` from `physical_ns`.
pub fn receive(
    last: HybridTimestamp,
    physical_ns: i64,
    remote: HybridTimestamp,
    max_skew_ns: i64,
) -> Result<HybridTimestamp, HlcError> {
    if max_skew_ns < 0 {
        Err(HlcError::InvalidMaxSkew)
    } else if !within_skew(remote.physical_ns, physical_ns, max_skew_ns) {
        Err(HlcError::ClockSkewExceeded)
    } else {
        let max_lr = if last.physical_ns >= remote.physical_ns {
            last.physical_ns
        } else {
            remote.physical_ns
        };
        let next_physical = if max_lr >= physical_ns {
            max_lr
        } else {
            physical_ns
        };
        if !within_skew(next_physical, physical_ns, max_skew_ns) {
            Err(HlcError::ClockSkewExceeded)
        } else if next_physical == last.physical_ns && next_physical == remote.physical_ns {
            let max_logical = if last.logical >= remote.logical {
                last.logical
            } else {
                remote.logical
            };
            if max_logical == u32::MAX {
                Err(HlcError::LogicalOverflow)
            } else {
                Ok(HybridTimestamp {
                    physical_ns: next_physical,
                    logical: max_logical + 1,
                })
            }
        } else if next_physical == last.physical_ns {
            if last.logical == u32::MAX {
                Err(HlcError::LogicalOverflow)
            } else {
                Ok(HybridTimestamp {
                    physical_ns: next_physical,
                    logical: last.logical + 1,
                })
            }
        } else if next_physical == remote.physical_ns {
            if remote.logical == u32::MAX {
                Err(HlcError::LogicalOverflow)
            } else {
                Ok(HybridTimestamp {
                    physical_ns: next_physical,
                    logical: remote.logical + 1,
                })
            }
        } else {
            Ok(HybridTimestamp {
                physical_ns: next_physical,
                logical: 0,
            })
        }
    }
}
