//! Structured coalesced [`IntervalSet`] and fail-closed [`FactValidity`]
//! backed by the Lean-proved [`mneme_kernel::temporal`] algebra.

/// Default bound on coalesced intervals retained per materialized fact.
pub const DEFAULT_MAX_INTERVALS_PER_FACT: u64 = 64;

/// Configuration for temporal interval bounds during Datalog evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemporalConfig {
    /// Maximum number of disjoint coalesced periods retained per fact.
    pub max_intervals_per_fact: u64,
}

impl Default for TemporalConfig {
    fn default() -> Self {
        Self {
            max_intervals_per_fact: DEFAULT_MAX_INTERVALS_PER_FACT,
        }
    }
}

/// Canonical, sorted, disjoint, coalesced set of half-open nanosecond periods.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IntervalSet {
    periods: Vec<mneme_kernel::temporal::Period>,
}

/// Result of a budgeted interval operation together with truncation status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BoundedIntervals {
    pub set: IntervalSet,
    pub is_truncated: bool,
}

impl IntervalSet {
    /// Empty interval set (`∅`).
    pub fn empty() -> Self {
        Self {
            periods: Vec::new(),
        }
    }

    /// Unbounded always-valid interval set (`(-∞, +∞)`).
    pub fn always() -> Self {
        Self {
            periods: vec![mneme_kernel::temporal::Period {
                start: mneme_kernel::temporal::NEG_INF,
                stop: mneme_kernel::temporal::POS_INF,
            }],
        }
    }

    /// Interval set containing one period, or empty when `period` is invalid.
    pub fn singleton(period: mneme_kernel::temporal::Period) -> Self {
        if mneme_kernel::temporal::is_valid(period) {
            Self {
                periods: vec![period],
            }
        } else {
            Self::empty()
        }
    }

    /// Construct a canonical coalesced interval set from arbitrary periods.
    pub fn from_periods(mut periods: Vec<mneme_kernel::temporal::Period>) -> Self {
        periods.sort_by_key(|period| (period.start, period.stop));
        let len = mneme_kernel::temporal::coalesce_sorted(&mut periods);
        periods.truncate(len);
        Self { periods }
    }

    /// Borrow the canonical coalesced slice of periods.
    pub fn periods(&self) -> &[mneme_kernel::temporal::Period] {
        &self.periods
    }

    /// Borrow as a kernel [`mneme_kernel::temporal::IntervalSet`] view.
    pub fn as_kernel(&self) -> mneme_kernel::temporal::IntervalSet<'_> {
        mneme_kernel::temporal::IntervalSet {
            periods: &self.periods,
        }
    }

    /// Whether the set contains no valid periods (`∅`).
    pub fn is_empty(&self) -> bool {
        self.periods.is_empty()
    }

    /// Whether the set is the single unbounded period `(-∞, +∞)`.
    pub fn is_always(&self) -> bool {
        self.periods.len() == 1
            && self.periods[0].start == mneme_kernel::temporal::NEG_INF
            && self.periods[0].stop == mneme_kernel::temporal::POS_INF
    }

    /// Whether `instant` lies inside any period of this set.
    pub fn contains(&self, instant: i128) -> bool {
        mneme_kernel::temporal::interval_set_contains(self.as_kernel(), instant)
    }

    /// Whether this set satisfies the kernel's canonical coalesced invariant.
    pub fn is_coalesced(&self) -> bool {
        mneme_kernel::temporal::interval_set_is_coalesced(self.as_kernel())
    }

    /// Coalesce `periods`, enforcing `max_intervals` and returning truncation status.
    fn finish_bounded(
        mut periods: Vec<mneme_kernel::temporal::Period>,
        max_intervals: u64,
    ) -> BoundedIntervals {
        periods.sort_by_key(|period| (period.start, period.stop));
        let len = mneme_kernel::temporal::coalesce_sorted(&mut periods);
        periods.truncate(len);
        let cap = max_intervals.max(1);
        let mut kept = Vec::with_capacity(periods.len());
        let mut count = 0_u64;
        let mut is_truncated = false;
        for period in periods {
            if count < cap {
                kept.push(period);
                count = count.saturating_add(1);
            } else {
                is_truncated = true;
                break;
            }
        }
        BoundedIntervals {
            set: Self { periods: kept },
            is_truncated,
        }
    }

    /// Sequenced intersection (`self ∩ other`) using a linear two-pointer scan
    /// over canonical coalesced slices, charging [`crate::engine::Budget`].
    pub(crate) fn intersect_bounded(
        &self,
        other: &Self,
        max_intervals: u64,
        budget: &mut crate::engine::Budget<'_>,
    ) -> Option<BoundedIntervals> {
        if self.is_empty() || other.is_empty() {
            return Some(BoundedIntervals {
                set: Self::empty(),
                is_truncated: false,
            });
        }
        if self.is_always() {
            return Some(Self::finish_bounded(other.periods.clone(), max_intervals));
        }
        if other.is_always() {
            return Some(Self::finish_bounded(self.periods.clone(), max_intervals));
        }
        let mut out = Vec::new();
        let mut left_idx = 0_usize;
        let mut right_idx = 0_usize;
        while left_idx < self.periods.len() && right_idx < other.periods.len() {
            if !budget.charge(1) {
                return None;
            }
            let lhs = self.periods[left_idx];
            let rhs = other.periods[right_idx];
            if let Some(overlap) = mneme_kernel::temporal::intersect(lhs, rhs) {
                out.push(overlap);
            }
            if lhs.stop <= rhs.stop {
                left_idx += 1;
            } else {
                right_idx += 1;
            }
        }
        Some(Self::finish_bounded(out, max_intervals))
    }

    /// Coalesced union (`coalesce(self ∪ other)`), charging [`crate::engine::Budget`].
    pub(crate) fn union_bounded(
        &self,
        other: &Self,
        max_intervals: u64,
        budget: &mut crate::engine::Budget<'_>,
    ) -> Option<BoundedIntervals> {
        let total = self.periods.len().saturating_add(other.periods.len());
        let charge = u64::try_from(total.max(1)).ok()?;
        if !budget.charge(charge) {
            return None;
        }
        let mut combined = Vec::with_capacity(total);
        combined.extend_from_slice(&self.periods);
        combined.extend_from_slice(&other.periods);
        Some(Self::finish_bounded(combined, max_intervals))
    }

    /// Bounded DatalogMTL past-diamond (`♦₋_window(self)`), charging [`crate::engine::Budget`].
    pub(crate) fn diamond_minus_bounded(
        &self,
        window: mneme_kernel::temporal::MetricWindow,
        max_intervals: u64,
        budget: &mut crate::engine::Budget<'_>,
    ) -> Option<BoundedIntervals> {
        let mut out = Vec::with_capacity(self.periods.len());
        for period in &self.periods {
            if !budget.charge(1) {
                return None;
            }
            if let Some(shifted) = mneme_kernel::temporal::diamond_minus(
                mneme_kernel::temporal::Validity::Known(*period),
                window,
            ) {
                out.push(shifted);
            }
        }
        Some(Self::finish_bounded(out, max_intervals))
    }

    /// Bounded DatalogMTL past-box (`■₋_window(self)`), charging [`crate::engine::Budget`].
    ///
    /// Because `self` is already coalesced, every contiguous sub-interval lies
    /// within a single maximal period of `self`.
    pub(crate) fn box_minus_bounded(
        &self,
        window: mneme_kernel::temporal::MetricWindow,
        max_intervals: u64,
        budget: &mut crate::engine::Budget<'_>,
    ) -> Option<BoundedIntervals> {
        let mut out = Vec::with_capacity(self.periods.len());
        for period in &self.periods {
            if !budget.charge(1) {
                return None;
            }
            if let Some(shrunk) = mneme_kernel::temporal::box_minus(
                mneme_kernel::temporal::Validity::Known(*period),
                window,
            ) {
                out.push(shrunk);
            }
        }
        Some(Self::finish_bounded(out, max_intervals))
    }

    /// Bounded DatalogMTL metric-since (`self S_window trigger`), charging [`crate::engine::Budget`].
    pub(crate) fn since_bounded(
        &self,
        trigger: &Self,
        window: mneme_kernel::temporal::MetricWindow,
        max_intervals: u64,
        budget: &mut crate::engine::Budget<'_>,
    ) -> Option<BoundedIntervals> {
        if !mneme_kernel::temporal::window_valid(window) || trigger.is_empty() {
            return Some(BoundedIntervals {
                set: Self::empty(),
                is_truncated: false,
            });
        }
        let mut out = Vec::new();
        if window.lower == 0 {
            for trig in &trigger.periods {
                if !budget.charge(1) {
                    return None;
                }
                out.push(*trig);
            }
        }
        for maintained in &self.periods {
            for trig in &trigger.periods {
                if !budget.charge(1) {
                    return None;
                }
                if let Some(period) = mneme_kernel::temporal::since(
                    mneme_kernel::temporal::Validity::Known(*maintained),
                    mneme_kernel::temporal::Validity::Known(*trig),
                    window,
                ) {
                    out.push(period);
                }
            }
        }
        Some(Self::finish_bounded(out, max_intervals))
    }

    /// Non-sequenced Allen interval relation join (`allen(relation, self, other)`),
    /// returning the coalesced union of matching interval pairs.
    pub(crate) fn allen_bounded(
        &self,
        other: &Self,
        relation: mneme_kernel::temporal::AllenRelation,
        max_intervals: u64,
        budget: &mut crate::engine::Budget<'_>,
    ) -> Option<BoundedIntervals> {
        let mut matched = Vec::new();
        for lhs in &self.periods {
            for rhs in &other.periods {
                if !budget.charge(1) {
                    return None;
                }
                if mneme_kernel::temporal::allen_holds(
                    mneme_kernel::temporal::Validity::Known(*lhs),
                    mneme_kernel::temporal::Validity::Known(*rhs),
                    relation,
                ) {
                    matched.push(*lhs);
                    matched.push(*rhs);
                }
            }
        }
        Some(Self::finish_bounded(matched, max_intervals))
    }
}

/// Fact-level temporal validity carrying either a canonical coalesced
/// [`IntervalSet`] or fail-closed [`FactValidity::Unknown`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FactValidity {
    /// Applicability period is unknown (fail-closed bottom `⊥`).
    Unknown,
    /// Known coalesced set of half-open validity periods.
    Known(IntervalSet),
}

impl Default for FactValidity {
    fn default() -> Self {
        Self::always()
    }
}

impl FactValidity {
    /// Always-valid (`(-∞, +∞)`) temporal validity for timeless canonical facts.
    pub fn always() -> Self {
        Self::Known(IntervalSet::always())
    }

    /// Decode a canonical [`mneme_core::ValidTime`] via the verified kernel.
    pub fn from_valid_time(valid_time: mneme_core::ValidTime) -> Self {
        match mneme_memory::valid_time_to_kernel(valid_time) {
            mneme_kernel::temporal::Validity::Unknown => Self::Unknown,
            mneme_kernel::temporal::Validity::Known(period) => {
                Self::Known(IntervalSet::singleton(period))
            }
        }
    }

    /// Borrow the underlying [`IntervalSet`] when validity is known.
    pub fn as_interval_set(&self) -> Option<&IntervalSet> {
        match self {
            Self::Unknown => None,
            Self::Known(set) => Some(set),
        }
    }

    /// Whether this validity covers `at`. Fails closed (`false`) on `Unknown`.
    pub fn contains_timestamp(&self, at: mneme_core::Timestamp) -> bool {
        match self {
            Self::Unknown => false,
            Self::Known(set) => set.contains(i128::from(at.nanos())),
        }
    }

    /// Whether this validity is non-empty (`Known` with at least one period).
    pub fn is_known_non_empty(&self) -> bool {
        matches!(self, Self::Known(set) if !set.is_empty())
    }

    /// Project this structured validity into backward-compatible stringified
    /// `temporal_parameters` for [`crate::Derivation`] and JSON/federation wire formats.
    pub fn to_temporal_parameters(&self) -> Vec<String> {
        match self {
            Self::Unknown => vec!["valid-time:unknown".to_owned()],
            Self::Known(set) => {
                if set.is_empty() || set.is_always() {
                    return Vec::new();
                }
                if set.periods().len() == 1 {
                    let period = set.periods()[0];
                    let mut parameters = Vec::new();
                    if period.start != mneme_kernel::temporal::NEG_INF {
                        parameters.push(format!("valid-time-start:{}", period.start));
                    }
                    if period.stop != mneme_kernel::temporal::POS_INF {
                        parameters.push(format!("valid-time-end:{}", period.stop));
                    }
                    return parameters;
                }
                set.periods()
                    .iter()
                    .map(|period| {
                        format!(
                            "valid-time:[{},{})",
                            format_bound(period.start),
                            format_bound(period.stop)
                        )
                    })
                    .collect()
            }
        }
    }

    /// Sequenced intersection of two fact validities. Fails closed to empty on `Unknown`.
    pub(crate) fn intersect_bounded(
        &self,
        other: &Self,
        max_intervals: u64,
        budget: &mut crate::engine::Budget<'_>,
    ) -> Option<BoundedIntervals> {
        match (self, other) {
            (Self::Known(lhs), Self::Known(rhs)) => {
                lhs.intersect_bounded(rhs, max_intervals, budget)
            }
            _ => Some(BoundedIntervals {
                set: IntervalSet::empty(),
                is_truncated: false,
            }),
        }
    }

    /// Coalesced union of two fact validities when merging derivations of the same tuple.
    pub(crate) fn union_bounded(
        &self,
        other: &Self,
        max_intervals: u64,
        budget: &mut crate::engine::Budget<'_>,
    ) -> Option<(Self, bool)> {
        match (self, other) {
            (Self::Known(lhs), Self::Known(rhs)) => {
                let bounded = lhs.union_bounded(rhs, max_intervals, budget)?;
                Some((Self::Known(bounded.set), bounded.is_truncated))
            }
            (Self::Unknown, Self::Known(rhs)) => Some((Self::Known(rhs.clone()), false)),
            (Self::Known(lhs), Self::Unknown) => Some((Self::Known(lhs.clone()), false)),
            (Self::Unknown, Self::Unknown) => Some((Self::Unknown, false)),
        }
    }
}

fn format_bound(bound: i128) -> String {
    if bound == mneme_kernel::temporal::NEG_INF || bound == mneme_kernel::temporal::POS_INF {
        "open".to_owned()
    } else {
        bound.to_string()
    }
}
