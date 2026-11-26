//! Half-open bitemporal interval algebra, Allen's 13 interval relations,
//! coalescing, and bounded DatalogMTL metric operators.
//!
//! Every interval is represented as a half-open nanosecond range
//! `[start, stop)` with `start < stop` for non-empty periods. Open bounds use
//! the absorbing sentinels [`NEG_INF`] (`-∞`) and [`POS_INF`] (`+∞`), leaving
//! the full signed 64-bit nanosecond timestamp range strictly interior so
//! legacy instants `[t, t + 1ns)` and finite metric shifts never overflow.
//!
//! [`Validity::Unknown`] is fail-closed bottom (`⊥`): it never contains any
//! instant, cannot be expired, and never satisfies any Allen predicate or
//! bounded DatalogMTL operator.

/// Lower sentinel representing an open (`-∞`) valid-time start bound.
pub const NEG_INF: i128 = i128::MIN;

/// Upper sentinel representing an open (`+∞`) valid-time stop bound.
pub const POS_INF: i128 = i128::MAX;

/// Single nanosecond width used to decode legacy point-instant valid times.
const ONE_NS: i128 = 1;

/// Zero nanosecond lower bound for metric windows.
const ZERO_NS: i128 = 0;

/// Half-open nanosecond valid-time period `[start, stop)`.
///
/// A period is non-empty (valid) iff `start < stop`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct Period {
    /// Inclusive lower bound in nanoseconds (or [`NEG_INF`] for open start).
    pub start: i128,
    /// Exclusive upper bound in nanoseconds (or [`POS_INF`] for open stop).
    pub stop: i128,
}

/// Canonical borrowed view over a slice of half-open [`Period`] values.
#[derive(Clone, Copy)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct IntervalSet<'a> {
    /// Periods in the set.
    pub periods: &'a [Period],
}

/// Fail-closed temporal validity for a single period.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum Validity {
    /// Applicable period is unknown (fail-closed bottom `⊥`).
    Unknown,
    /// Known half-open validity period `[start, stop)`.
    Known(Period),
}

/// Bounded metric window `ρ = [lower, upper]` in nanoseconds (`0 <= lower <= upper`).
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct MetricWindow {
    /// Inclusive minimum lag in nanoseconds (`>= 0`).
    pub lower: i128,
    /// Inclusive maximum lag in nanoseconds (`>= lower`).
    pub upper: i128,
}

/// Allen's 13 mutually exclusive, jointly exhaustive interval relations (CACM 1983)
/// over valid non-empty half-open periods.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum AllenRelation {
    /// `left.stop < right.start`
    Before,
    /// `left.stop == right.start`
    Meets,
    /// `left.start < right.start && right.start < left.stop && left.stop < right.stop`
    Overlaps,
    /// `left.start < right.start && left.stop == right.stop`
    FinishedBy,
    /// `left.start < right.start && right.stop < left.stop`
    Contains,
    /// `left.start == right.start && left.stop < right.stop`
    Starts,
    /// `left.start == right.start && left.stop == right.stop`
    Equals,
    /// `left.start == right.start && right.stop < left.stop`
    StartedBy,
    /// `right.start < left.start && left.stop < right.stop`
    During,
    /// `right.start < left.start && left.stop == right.stop`
    Finishes,
    /// `right.start < left.start && left.start < right.stop && right.stop < left.stop`
    OverlappedBy,
    /// `right.stop == left.start`
    MetBy,
    /// `right.stop < left.start`
    After,
}

/// Decision for bounding an assertion's valid time by an explicit expiry instant.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum ExpiryDecision {
    /// Expiry produces the valid shortened half-open period.
    Allowed(Period),
    /// Validity is unknown or malformed and cannot be expired.
    UnknownValidity,
    /// Requested expiry is at or before the interval's start.
    ExpiryNotAfterStart,
    /// Interval already ends at or before the requested expiry.
    AlreadyExpired,
}

/// Shift an endpoint forward by a non-negative `delta`, keeping [`NEG_INF`]
/// and [`POS_INF`] as absorbing infinities without integer overflow.
fn shift_forward(endpoint: i128, delta: i128) -> i128 {
    if endpoint == NEG_INF {
        NEG_INF
    } else if endpoint == POS_INF {
        POS_INF
    } else if delta <= ZERO_NS {
        endpoint
    } else if endpoint > POS_INF - delta {
        POS_INF
    } else {
        endpoint + delta
    }
}

/// Shift a finite endpoint backward by 1 nanosecond, keeping [`NEG_INF`] and
/// [`POS_INF`] as absorbing infinities without integer overflow.
fn shift_back_one(endpoint: i128) -> i128 {
    if endpoint == NEG_INF {
        NEG_INF
    } else if endpoint == POS_INF {
        POS_INF
    } else {
        endpoint - ONE_NS
    }
}

/// Whether `period` is a valid non-empty half-open interval (`start < stop`).
pub fn is_valid(period: Period) -> bool {
    period.start < period.stop
}

/// Whether `period` contains `instant` under half-open `[start, stop)` semantics.
pub fn contains(period: Period, instant: i128) -> bool {
    period.start <= instant && instant < period.stop
}

/// Whether `validity` covers `instant`. [`Validity::Unknown`] fails closed (`false`).
pub fn validity_contains(validity: Validity, instant: i128) -> bool {
    match validity {
        Validity::Unknown => false,
        Validity::Known(period) => contains(period, instant),
    }
}

/// Decode optional 64-bit nanosecond bounds into a half-open [`Period`].
///
/// Open bounds map to [`NEG_INF`] / [`POS_INF`]. A legacy point-instant bound
/// where `start == stop` decodes to `[t, t + 1ns)`. Inverted bounds (`start > stop`)
/// return `None`.
pub fn from_legacy_bounds(start: Option<i64>, stop: Option<i64>) -> Option<Period> {
    match (start, stop) {
        (None, None) => Some(Period {
            start: NEG_INF,
            stop: POS_INF,
        }),
        (Some(lo), None) => Some(Period {
            start: lo as i128,
            stop: POS_INF,
        }),
        (None, Some(hi)) => Some(Period {
            start: NEG_INF,
            stop: hi as i128,
        }),
        (Some(lo), Some(hi)) => {
            if lo < hi {
                Some(Period {
                    start: lo as i128,
                    stop: hi as i128,
                })
            } else if lo == hi {
                let lo_wide = lo as i128;
                Some(Period {
                    start: lo_wide,
                    stop: lo_wide + ONE_NS,
                })
            } else {
                None
            }
        }
    }
}

/// Decide whether `validity` can be expired at `effective` under half-open
/// `[start, effective)` handoff semantics.
pub fn expire_bounds(validity: Validity, effective: i64) -> ExpiryDecision {
    match validity {
        Validity::Unknown => ExpiryDecision::UnknownValidity,
        Validity::Known(period) => {
            if !is_valid(period) {
                ExpiryDecision::UnknownValidity
            } else {
                let eff = effective as i128;
                if eff <= period.start {
                    ExpiryDecision::ExpiryNotAfterStart
                } else if period.stop <= eff {
                    ExpiryDecision::AlreadyExpired
                } else {
                    ExpiryDecision::Allowed(Period {
                        start: period.start,
                        stop: eff,
                    })
                }
            }
        }
    }
}

/// Half-open intersection of two periods, or `None` if disjoint or invalid.
pub fn intersect(left: Period, right: Period) -> Option<Period> {
    if !is_valid(left) || !is_valid(right) {
        None
    } else {
        let start = if left.start >= right.start {
            left.start
        } else {
            right.start
        };
        let stop = if left.stop <= right.stop {
            left.stop
        } else {
            right.stop
        };
        if start < stop {
            Some(Period { start, stop })
        } else {
            None
        }
    }
}

/// Monoidal intersection over optional periods, with `None` as absorbing empty `∅`.
pub fn intersect_option(left: Option<Period>, right: Option<Period>) -> Option<Period> {
    match (left, right) {
        (Some(lhs), Some(rhs)) => intersect(lhs, rhs),
        _ => None,
    }
}

/// Whether two valid periods overlap or meet and therefore coalesce into one period.
pub fn can_coalesce(left: Period, right: Period) -> bool {
    is_valid(left) && is_valid(right) && left.start <= right.stop && right.start <= left.stop
}

/// Coalesce two overlapping or adjacent valid periods into one single period.
pub fn coalesce_pair(left: Period, right: Period) -> Option<Period> {
    if !can_coalesce(left, right) {
        None
    } else {
        let start = if left.start <= right.start {
            left.start
        } else {
            right.start
        };
        let stop = if left.stop >= right.stop {
            left.stop
        } else {
            right.stop
        };
        Some(Period { start, stop })
    }
}

/// Whether any period in `set` contains `instant`.
pub fn interval_set_contains(set: IntervalSet<'_>, instant: i128) -> bool {
    let mut is_member = false;
    let mut index = 0_usize;
    while index < set.periods.len() && !is_member {
        is_member = contains(set.periods[index], instant);
        index += 1;
    }
    is_member
}

/// Whether `set` is in canonical coalesced form: every period is valid
/// (`start < stop`) and consecutive periods are strictly separated (`prev.stop < next.start`).
pub fn interval_set_is_coalesced(set: IntervalSet<'_>) -> bool {
    let mut is_canonical = true;
    let mut index = 0_usize;
    while index < set.periods.len() && is_canonical {
        let current = set.periods[index];
        if !is_valid(current) {
            is_canonical = false;
        } else if index > 0 {
            let prev = set.periods[index - 1];
            if prev.stop >= current.start {
                is_canonical = false;
            }
        }
        index += 1;
    }
    is_canonical
}

/// Coalesce a start-sorted slice of half-open periods in place, returning the
/// length of the canonical coalesced prefix `periods[0..len]`.
///
/// Invalid periods (`start >= stop`) are dropped; overlapping or adjacent
/// periods (`next.start <= prev.stop`) are merged into their exact union.
#[allow(unknown_lints, usize_in_public_api)] // prefix length indexing the input slice
pub fn coalesce_sorted(periods: &mut [Period]) -> usize {
    let mut write = 0_usize;
    let mut read = 0_usize;
    while read < periods.len() {
        let candidate = periods[read];
        if is_valid(candidate) {
            if write == 0 {
                periods[0] = candidate;
                write = 1;
            } else {
                let prev = periods[write - 1];
                if candidate.start <= prev.stop {
                    let merged_stop = if candidate.stop >= prev.stop {
                        candidate.stop
                    } else {
                        prev.stop
                    };
                    periods[write - 1] = Period {
                        start: prev.start,
                        stop: merged_stop,
                    };
                } else {
                    periods[write] = candidate;
                    write += 1;
                }
            }
        }
        read += 1;
    }
    write
}

/// Classify the exact Allen interval relation between two valid half-open periods.
///
/// Returns `None` if either period is invalid (`start >= stop`).
pub fn allen_relation(left: Period, right: Period) -> Option<AllenRelation> {
    if !is_valid(left) || !is_valid(right) {
        None
    } else if left.start < right.start {
        if left.stop < right.start {
            Some(AllenRelation::Before)
        } else if left.stop == right.start {
            Some(AllenRelation::Meets)
        } else if left.stop < right.stop {
            Some(AllenRelation::Overlaps)
        } else if left.stop == right.stop {
            Some(AllenRelation::FinishedBy)
        } else {
            Some(AllenRelation::Contains)
        }
    } else if left.start == right.start {
        if left.stop < right.stop {
            Some(AllenRelation::Starts)
        } else if left.stop == right.stop {
            Some(AllenRelation::Equals)
        } else {
            Some(AllenRelation::StartedBy)
        }
    } else if left.stop < right.stop {
        Some(AllenRelation::During)
    } else if left.stop == right.stop {
        Some(AllenRelation::Finishes)
    } else if left.start < right.stop {
        Some(AllenRelation::OverlappedBy)
    } else if left.start == right.stop {
        Some(AllenRelation::MetBy)
    } else {
        Some(AllenRelation::After)
    }
}

/// Whether `left` and `right` satisfy `relation`. Fails closed (`false`) on
/// [`Validity::Unknown`] or invalid periods.
pub fn allen_holds(left: Validity, right: Validity, relation: AllenRelation) -> bool {
    match (left, right) {
        (Validity::Known(lhs), Validity::Known(rhs)) => match allen_relation(lhs, rhs) {
            Some(actual) => actual == relation,
            None => false,
        },
        _ => false,
    }
}

/// Whether `window` is a valid bounded metric window (`0 <= lower <= upper`).
pub fn window_valid(window: MetricWindow) -> bool {
    window.lower >= ZERO_NS && window.lower <= window.upper
}

/// Bounded DatalogMTL past-diamond operator `♦₋_[lower, upper](validity)`.
///
/// For a valid half-open period `[a, b)` and `0 <= lower <= upper`, returns
/// `[a + lower, b + upper)` (clamped at infinities). Fails closed (`None`) on
/// [`Validity::Unknown`], invalid periods, or invalid windows.
pub fn diamond_minus(validity: Validity, window: MetricWindow) -> Option<Period> {
    if !window_valid(window) {
        None
    } else {
        match validity {
            Validity::Unknown => None,
            Validity::Known(period) => {
                if !is_valid(period) {
                    None
                } else {
                    let start = shift_forward(period.start, window.lower);
                    let stop = shift_forward(period.stop, window.upper);
                    if start < stop {
                        Some(Period { start, stop })
                    } else {
                        None
                    }
                }
            }
        }
    }
}

/// Bounded DatalogMTL past-box operator `■₋_[lower, upper](validity)`.
///
/// For a maximal valid half-open period `[a, b)` and `0 <= lower <= upper`,
/// returns `[a + upper, b + lower)` when non-empty. Fails closed (`None`) on
/// [`Validity::Unknown`], invalid periods, or invalid windows.
pub fn box_minus(validity: Validity, window: MetricWindow) -> Option<Period> {
    if !window_valid(window) {
        None
    } else {
        match validity {
            Validity::Unknown => None,
            Validity::Known(period) => {
                if !is_valid(period) {
                    None
                } else {
                    let start = shift_forward(period.start, window.upper);
                    let stop = shift_forward(period.stop, window.lower);
                    if start < stop {
                        Some(Period { start, stop })
                    } else {
                        None
                    }
                }
            }
        }
    }
}

/// Bounded DatalogMTL metric-since operator `maintained S_[lower, upper] trigger`.
///
/// Under discrete half-open semantics, `t` satisfies `I1 S_[l, u] I2` iff there
/// exists `t' ∈ I2` with `l <= t - t' <= u` such that every `s ∈ (t', t]` lies
/// in `I1`. Fails closed (`None`) when either operand is [`Validity::Unknown`],
/// invalid, or `window` is invalid.
pub fn since(maintained: Validity, trigger: Validity, window: MetricWindow) -> Option<Period> {
    if !window_valid(window) {
        None
    } else {
        match (maintained, trigger) {
            (Validity::Known(m), Validity::Known(t)) => {
                if !is_valid(m) || !is_valid(t) {
                    None
                } else {
                    let m_start_prev = shift_back_one(m.start);
                    let m_stop_prev = shift_back_one(m.stop);
                    let j_start = if t.start >= m_start_prev {
                        t.start
                    } else {
                        m_start_prev
                    };
                    let j_stop = if t.stop <= m_stop_prev {
                        t.stop
                    } else {
                        m_stop_prev
                    };
                    let strict_lower = if window.lower >= ONE_NS {
                        window.lower
                    } else {
                        ONE_NS
                    };
                    let has_strict = j_start < j_stop && strict_lower <= window.upper;
                    if window.lower == ZERO_NS {
                        if has_strict {
                            let shifted_stop = shift_forward(j_stop, window.upper);
                            let capped_stop = if shifted_stop <= m.stop {
                                shifted_stop
                            } else {
                                m.stop
                            };
                            let final_stop = if t.stop >= capped_stop {
                                t.stop
                            } else {
                                capped_stop
                            };
                            if t.start < final_stop {
                                Some(Period {
                                    start: t.start,
                                    stop: final_stop,
                                })
                            } else {
                                None
                            }
                        } else {
                            Some(t)
                        }
                    } else if has_strict {
                        let start = shift_forward(j_start, strict_lower);
                        let shifted_stop = shift_forward(j_stop, window.upper);
                        let stop = if shifted_stop <= m.stop {
                            shifted_stop
                        } else {
                            m.stop
                        };
                        if start < stop {
                            Some(Period { start, stop })
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
            }
            _ => None,
        }
    }
}
