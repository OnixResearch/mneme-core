//! Structured coalesced [`IntervalSet`] and fail-closed [`FactValidity`]
//! backed by the Lean-proved [`mneme_kernel::temporal`] algebra.

/// Default bound on coalesced intervals retained per materialized fact.
pub const DEFAULT_MAX_INTERVALS_PER_FACT: u64 = 64;

/// Canonical, sorted, disjoint, coalesced set of half-open nanosecond periods.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IntervalSet {
    periods: Vec<mneme_kernel::temporal::Period>,
}

/// Result of a budgeted interval operation together with truncation status and work steps spent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BoundedIntervals {
    pub set: IntervalSet,
    pub is_truncated: bool,
    pub steps: u64,
}

/// Result of a budgeted validity union together with truncation status and work steps spent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BoundedValidity {
    pub validity: FactValidity,
    pub is_truncated: bool,
    pub steps: u64,
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
        steps: u64,
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
            steps,
        }
    }

    /// Pure sequenced intersection (`self ∩ other`) using a linear two-pointer scan
    /// over canonical coalesced slices, bounded by `remaining_steps`.
    pub(crate) fn intersect_bounded(
        &self,
        other: &Self,
        max_intervals: u64,
        remaining_steps: u64,
    ) -> Option<BoundedIntervals> {
        if self.is_empty() || other.is_empty() {
            return Some(BoundedIntervals {
                set: Self::empty(),
                is_truncated: false,
                steps: 0,
            });
        }
        if self.is_always() {
            return Some(Self::finish_bounded(
                other.periods.clone(),
                max_intervals,
                0,
            ));
        }
        if other.is_always() {
            return Some(Self::finish_bounded(self.periods.clone(), max_intervals, 0));
        }
        let capacity = self.periods.len().saturating_add(other.periods.len());
        let mut out = Vec::with_capacity(capacity);
        let mut left_idx = 0_usize;
        let mut right_idx = 0_usize;
        let mut steps = 0_u64;
        while left_idx < self.periods.len() && right_idx < other.periods.len() {
            let next_steps = steps.checked_add(1)?;
            if next_steps > remaining_steps {
                return None;
            }
            steps = next_steps;
            let lhs = self.periods[left_idx];
            let rhs = other.periods[right_idx];
            if let Some(overlap) = mneme_kernel::temporal::intersect(lhs, rhs) {
                out.push(overlap);
            }
            if lhs.stop <= rhs.stop {
                left_idx = left_idx.saturating_add(1);
            } else {
                right_idx = right_idx.saturating_add(1);
            }
        }
        Some(Self::finish_bounded(out, max_intervals, steps))
    }

    /// Pure coalesced union (`coalesce(self ∪ other)`), bounded by `remaining_steps`.
    pub(crate) fn union_bounded(
        &self,
        other: &Self,
        max_intervals: u64,
        remaining_steps: u64,
    ) -> Option<BoundedIntervals> {
        let total = self.periods.len().saturating_add(other.periods.len());
        let charge = u64::try_from(total.max(1)).ok()?;
        if charge > remaining_steps {
            return None;
        }
        let mut combined = Vec::with_capacity(total);
        combined.extend_from_slice(&self.periods);
        combined.extend_from_slice(&other.periods);
        Some(Self::finish_bounded(combined, max_intervals, charge))
    }

    /// Pure bounded DatalogMTL past-diamond (`♦₋_window(self)`).
    pub(crate) fn diamond_minus_bounded(
        &self,
        window: mneme_kernel::temporal::MetricWindow,
        max_intervals: u64,
        remaining_steps: u64,
    ) -> Option<BoundedIntervals> {
        let charge = u64::try_from(self.periods.len()).ok()?;
        if charge > remaining_steps {
            return None;
        }
        let mut out = Vec::with_capacity(self.periods.len());
        for period in &self.periods {
            if let Some(shifted) = mneme_kernel::temporal::diamond_minus(
                mneme_kernel::temporal::Validity::Known(*period),
                window,
            ) {
                out.push(shifted);
            }
        }
        Some(Self::finish_bounded(out, max_intervals, charge))
    }

    /// Pure bounded DatalogMTL past-box (`■₋_window(self)`).
    ///
    /// Because `self` is already coalesced, every contiguous sub-interval lies
    /// within a single maximal period of `self`.
    pub(crate) fn box_minus_bounded(
        &self,
        window: mneme_kernel::temporal::MetricWindow,
        max_intervals: u64,
        remaining_steps: u64,
    ) -> Option<BoundedIntervals> {
        let charge = u64::try_from(self.periods.len()).ok()?;
        if charge > remaining_steps {
            return None;
        }
        let mut out = Vec::with_capacity(self.periods.len());
        for period in &self.periods {
            if let Some(shrunk) = mneme_kernel::temporal::box_minus(
                mneme_kernel::temporal::Validity::Known(*period),
                window,
            ) {
                out.push(shrunk);
            }
        }
        Some(Self::finish_bounded(out, max_intervals, charge))
    }

    /// Pure bounded DatalogMTL metric-since (`self S_window trigger`).
    pub(crate) fn since_bounded(
        &self,
        trigger: &Self,
        window: mneme_kernel::temporal::MetricWindow,
        max_intervals: u64,
        remaining_steps: u64,
    ) -> Option<BoundedIntervals> {
        if !mneme_kernel::temporal::window_valid(window) || trigger.is_empty() {
            return Some(BoundedIntervals {
                set: Self::empty(),
                is_truncated: false,
                steps: 0,
            });
        }
        let zero_steps = if window.lower == 0 {
            trigger.periods.len()
        } else {
            0
        };
        let pair_steps = self.periods.len().saturating_mul(trigger.periods.len());
        let total_steps = zero_steps.saturating_add(pair_steps);
        let charge = u64::try_from(total_steps).ok()?;
        if charge > remaining_steps {
            return None;
        }
        let mut out = Vec::with_capacity(total_steps);
        if window.lower == 0 {
            out.extend_from_slice(&trigger.periods);
        }
        for maintained in &self.periods {
            for trig in &trigger.periods {
                if let Some(period) = mneme_kernel::temporal::since(
                    mneme_kernel::temporal::Validity::Known(*maintained),
                    mneme_kernel::temporal::Validity::Known(*trig),
                    window,
                ) {
                    out.push(period);
                }
            }
        }
        Some(Self::finish_bounded(out, max_intervals, charge))
    }

    /// Pure non-sequenced Allen interval relation join (`allen(relation, self, other)`),
    /// returning the coalesced union of matching interval pairs.
    pub(crate) fn allen_bounded(
        &self,
        other: &Self,
        relation: mneme_kernel::temporal::AllenRelation,
        max_intervals: u64,
        remaining_steps: u64,
    ) -> Option<BoundedIntervals> {
        let pair_steps = self.periods.len().saturating_mul(other.periods.len());
        let charge = u64::try_from(pair_steps).ok()?;
        if charge > remaining_steps {
            return None;
        }
        let mut matched = Vec::with_capacity(pair_steps.saturating_mul(2));
        for lhs in &self.periods {
            for rhs in &other.periods {
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
        Some(Self::finish_bounded(matched, max_intervals, charge))
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
        if let Self::Known(set) = self {
            Some(set)
        } else {
            None
        }
    }

    /// Whether this validity covers `at`. Fails closed (`false`) on `Unknown`.
    pub fn contains_timestamp(&self, at: mneme_core::Timestamp) -> bool {
        self.as_interval_set()
            .is_some_and(|set| set.contains(i128::from(at.nanos())))
    }

    /// Whether this validity is non-empty (`Known` with at least one period).
    pub fn is_known_non_empty(&self) -> bool {
        self.as_interval_set().is_some_and(|set| !set.is_empty())
    }

    /// Project this structured validity into backward-compatible stringified
    /// `temporal_parameters` for [`crate::Derivation`] and JSON/federation wire formats.
    pub fn to_temporal_parameters(&self) -> Vec<String> {
        let Some(set) = self.as_interval_set() else {
            return vec!["valid-time:unknown".to_owned()];
        };
        if set.is_empty() || set.is_always() {
            return Vec::new();
        }
        if set.periods().len() == 1 {
            let period = set.periods()[0];
            let mut parameters = Vec::with_capacity(2);
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

    /// Pure sequenced intersection of two fact validities. Fails closed to empty on `Unknown`.
    pub(crate) fn intersect_bounded(
        &self,
        other: &Self,
        max_intervals: u64,
        remaining_steps: u64,
    ) -> Option<BoundedIntervals> {
        let (Some(lhs), Some(rhs)) = (self.as_interval_set(), other.as_interval_set()) else {
            return Some(BoundedIntervals {
                set: IntervalSet::empty(),
                is_truncated: false,
                steps: 0,
            });
        };
        lhs.intersect_bounded(rhs, max_intervals, remaining_steps)
    }

    /// Pure coalesced union of two fact validities when merging derivations of the same tuple.
    pub(crate) fn union_bounded(
        &self,
        other: &Self,
        max_intervals: u64,
        remaining_steps: u64,
    ) -> Option<BoundedValidity> {
        match (self.as_interval_set(), other.as_interval_set()) {
            (Some(lhs), Some(rhs)) => {
                let bounded = lhs.union_bounded(rhs, max_intervals, remaining_steps)?;
                Some(BoundedValidity {
                    validity: Self::Known(bounded.set),
                    is_truncated: bounded.is_truncated,
                    steps: bounded.steps,
                })
            }
            (None, Some(rhs)) => Some(BoundedValidity {
                validity: Self::Known(rhs.clone()),
                is_truncated: false,
                steps: 0,
            }),
            (Some(lhs), None) => Some(BoundedValidity {
                validity: Self::Known(lhs.clone()),
                is_truncated: false,
                steps: 0,
            }),
            (None, None) => Some(BoundedValidity {
                validity: Self::Unknown,
                is_truncated: false,
                steps: 0,
            }),
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
