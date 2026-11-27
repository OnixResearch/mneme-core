//! Exact fixed-point rational Subjective Logic binomial opinions.
//!
//! Based on A. Jøsang, *Subjective Logic* (Springer 2016 / AIJ 2001):
//! - A non-dogmatic binomial opinion $\omega_x = (b_x, d_x, u_x, a_x)$ is
//!   represented by exact integer evidence counts `(r, s, w, base_rate)` with
//!   $w > 0$ (canonical prior weight $W = 2$), giving exact fractions
//!   $b = r/(r+s+w)$, $d = s/(r+s+w)$, $u = w/(r+s+w)$, and internal dissonance
//!   $\text{conflict} = 2 \min(r, s)/(r+s+w)$ with zero IEEE-754 drift.
//! - **Cumulative Fusion (`cumulative_fuse`, $\oplus$)**: fuses evidence from
//!   independent `RootIdentity` clusters (commutative and associative).
//! - **Averaging Fusion (`averaging_fuse`, `averaging_cluster`, $\underline{\diamond}$)**:
//!   fuses derivative copies sharing a `RootIdentity` (idempotent, preventing
//!   echo-chamber uncertainty collapse).
//! - **Trust Discounting (`trust_discount`, $\otimes$)**: attenuates an opinion
//!   by source trust without inflating belief or disbelief or shrinking
//!   uncertainty.

/// Canonical non-informative prior weight $W = 2$.
pub const PRIOR_WEIGHT: u128 = 2;

/// Fixed-point denominator for base rate $a \in [0, 1]$ (`1_000_000` = 1.0).
pub const BASE_RATE_SCALE: u64 = 1_000_000;

/// Default uninformative base rate $a = 0.5$.
pub const DEFAULT_BASE_RATE: u64 = 500_000;

/// Exact homogeneous rational evidence representation of a binomial opinion.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct Evidence {
    /// Supporting evidence numerator.
    pub r: u128,
    /// Challenging evidence numerator.
    pub s: u128,
    /// Prior uncertainty weight denominator (must be positive for validity).
    pub w: u128,
    /// Base rate numerator in `[0, BASE_RATE_SCALE]`.
    pub base_rate: u64,
}

/// Exact rational projection of a binomial opinion onto the simplex.
///
/// Every value produced by [`project`] satisfies:
/// `b_num + d_num + u_num == denom`, `denom > 0`, and
/// `conflict_num <= b_num + d_num < denom`.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct Projected {
    /// Belief numerator (`b = b_num / denom`).
    pub b_num: u128,
    /// Disbelief numerator (`d = d_num / denom`).
    pub d_num: u128,
    /// Uncertainty numerator (`u = u_num / denom`).
    pub u_num: u128,
    /// Common strictly positive denominator (`r + s + w`).
    pub denom: u128,
    /// Internal dissonance / conflict numerator (`2 * min(r, s) / denom`).
    pub conflict_num: u128,
    /// Base rate numerator (`a = base_rate / BASE_RATE_SCALE`).
    pub base_rate: u64,
}

const fn clamp_base_rate(base_rate: u64) -> u64 {
    if base_rate <= BASE_RATE_SCALE {
        base_rate
    } else {
        BASE_RATE_SCALE
    }
}

const fn min_base_rate(left: u64, right: u64) -> u64 {
    if left <= right { left } else { right }
}

const fn checked_denom(r: u128, s: u128, w: u128) -> Option<u128> {
    match r.checked_add(s) {
        None => None,
        Some(rs) => rs.checked_add(w),
    }
}

const fn checked_cross_sum(a: u128, b: u128, c: u128, d: u128) -> Option<u128> {
    match a.checked_mul(b) {
        None => None,
        Some(left_prod) => match c.checked_mul(d) {
            None => None,
            Some(right_prod) => left_prod.checked_add(right_prod),
        },
    }
}

const fn build_valid(r: u128, s: u128, w: u128, base_rate: u64) -> Option<Evidence> {
    if w == 0 || base_rate > BASE_RATE_SCALE {
        None
    } else {
        match checked_denom(r, s, w) {
            Some(_) => Some(Evidence { r, s, w, base_rate }),
            None => None,
        }
    }
}

/// Whether `ev` is a well-formed non-dogmatic opinion whose denominator
/// `r + s + w` fits in `u128` without overflow.
pub fn is_valid(ev: &Evidence) -> bool {
    if ev.w == 0 || ev.base_rate > BASE_RATE_SCALE {
        false
    } else {
        checked_denom(ev.r, ev.s, ev.w).is_some()
    }
}

/// Exact vacuous opinion `(b = 0, d = 0, u = 1, a = base_rate / BASE_RATE_SCALE)`.
pub fn vacuous(base_rate: u64) -> Evidence {
    Evidence {
        r: 0,
        s: 0,
        w: PRIOR_WEIGHT,
        base_rate: clamp_base_rate(base_rate),
    }
}

/// Exact multi-source averaging fusion ($\underline{\diamond}$) of `supports`
/// unit supporting observations and `challenges` unit challenging observations
/// sharing one `RootIdentity`.
///
/// Any `k >= 1` pure derivative copies keep uncertainty strictly invariant at
/// `u = 2/3` (`r = 1, s = 0, w = 2` for pure supports; `r = 0, s = 1, w = 2`
/// for pure challenges; `r = supports, s = challenges, w = 2 * (supports + challenges)`
/// for mixed observations within the same root). Zero observations yield the
/// exact vacuous opinion `(0, 0, 1, a)`.
pub fn averaging_cluster(supports: u64, challenges: u64, base_rate: u64) -> Evidence {
    let clamped = clamp_base_rate(base_rate);
    if supports == 0 && challenges == 0 {
        Evidence {
            r: 0,
            s: 0,
            w: PRIOR_WEIGHT,
            base_rate: clamped,
        }
    } else if challenges == 0 {
        Evidence {
            r: 1,
            s: 0,
            w: PRIOR_WEIGHT,
            base_rate: clamped,
        }
    } else if supports == 0 {
        Evidence {
            r: 0,
            s: 1,
            w: PRIOR_WEIGHT,
            base_rate: clamped,
        }
    } else {
        let r = supports as u128;
        let s = challenges as u128;
        let total = r.saturating_add(s);
        let w = total.saturating_add(total);
        Evidence {
            r,
            s,
            w,
            base_rate: clamped,
        }
    }
}

/// Project exact evidence counts onto the binomial simplex `(b, d, u, a, conflict)`.
pub fn project(ev: &Evidence) -> Option<Projected> {
    if ev.w == 0 || ev.base_rate > BASE_RATE_SCALE {
        None
    } else {
        match checked_denom(ev.r, ev.s, ev.w) {
            None => None,
            Some(denom) => {
                let min_rs = if ev.r <= ev.s { ev.r } else { ev.s };
                let conflict_num = min_rs.saturating_add(min_rs);
                Some(Projected {
                    b_num: ev.r,
                    d_num: ev.s,
                    u_num: ev.w,
                    denom,
                    conflict_num,
                    base_rate: ev.base_rate,
                })
            }
        }
    }
}

fn cumulative_fuse_equal_weight(
    left: &Evidence,
    right: &Evidence,
    base_rate: u64,
) -> Option<Evidence> {
    match left.r.checked_add(right.r) {
        None => None,
        Some(r) => match left.s.checked_add(right.s) {
            None => None,
            Some(s) => build_valid(r, s, left.w, base_rate),
        },
    }
}

fn cumulative_fuse_general(left: &Evidence, right: &Evidence, base_rate: u64) -> Option<Evidence> {
    match checked_cross_sum(left.r, right.w, right.r, left.w) {
        None => None,
        Some(r) => match checked_cross_sum(left.s, right.w, right.s, left.w) {
            None => None,
            Some(s) => match left.w.checked_mul(right.w) {
                None => None,
                Some(w) => build_valid(r, s, w, base_rate),
            },
        },
    }
}

/// Jøsang Cumulative Fusion ($\oplus$) of two independent opinions.
///
/// Exact rational evidence addition: commutative structurally and associative
/// up to exact rational equivalence (and structurally when weights match).
pub fn cumulative_fuse(left: &Evidence, right: &Evidence) -> Option<Evidence> {
    if !is_valid(left) || !is_valid(right) {
        None
    } else {
        let base_rate = min_base_rate(left.base_rate, right.base_rate);
        if left.w == right.w {
            cumulative_fuse_equal_weight(left, right, base_rate)
        } else {
            cumulative_fuse_general(left, right, base_rate)
        }
    }
}

fn averaging_fuse_equal_weight(
    left: &Evidence,
    right: &Evidence,
    base_rate: u64,
) -> Option<Evidence> {
    match left.r.checked_add(right.r) {
        None => None,
        Some(r) => match left.s.checked_add(right.s) {
            None => None,
            Some(s) => match left.w.checked_mul(PRIOR_WEIGHT) {
                None => None,
                Some(w) => build_valid(r, s, w, base_rate),
            },
        },
    }
}

const fn checked_double_mul(a: u128, b: u128) -> Option<u128> {
    match a.checked_mul(b) {
        None => None,
        Some(prod) => prod.checked_mul(PRIOR_WEIGHT),
    }
}

fn averaging_fuse_general(left: &Evidence, right: &Evidence, base_rate: u64) -> Option<Evidence> {
    match checked_cross_sum(left.r, right.w, right.r, left.w) {
        None => None,
        Some(r) => match checked_cross_sum(left.s, right.w, right.s, left.w) {
            None => None,
            Some(s) => match checked_double_mul(left.w, right.w) {
                None => None,
                Some(w) => build_valid(r, s, w, base_rate),
            },
        },
    }
}

/// Jøsang Averaging Fusion ($\underline{\diamond}$) of two dependent opinions.
///
/// Exact rational evidence averaging: commutative and idempotent
/// (`averaging_fuse(x, x)` represents the exact same `(b, d, u, a)` as `x`).
pub fn averaging_fuse(left: &Evidence, right: &Evidence) -> Option<Evidence> {
    if !is_valid(left) || !is_valid(right) {
        None
    } else {
        let base_rate = min_base_rate(left.base_rate, right.base_rate);
        if left.w == right.w {
            averaging_fuse_equal_weight(left, right, base_rate)
        } else {
            averaging_fuse_general(left, right, base_rate)
        }
    }
}

fn trust_discount_inner(
    trust: &Evidence,
    target: &Evidence,
    target_denom: u128,
    trust_non_belief: u128,
) -> Option<Evidence> {
    match trust.r.checked_mul(target.r) {
        None => None,
        Some(r) => match trust.r.checked_mul(target.s) {
            None => None,
            Some(s) => match checked_cross_sum(trust_non_belief, target_denom, trust.r, target.w) {
                None => None,
                Some(w) => build_valid(r, s, w, target.base_rate),
            },
        },
    }
}

/// Jøsang Trust Discounting ($\otimes$): discounts `target` by source `trust`.
///
/// Preserves the simplex (`b' + d' + u' = 1`) and never inflates belief
/// (`b' <= b_target`, `b' <= b_trust`) or disbelief (`d' <= d_target`), nor
/// decreases uncertainty (`u' >= u_target`).
pub fn trust_discount(trust: &Evidence, target: &Evidence) -> Option<Evidence> {
    if !is_valid(trust) || !is_valid(target) {
        None
    } else {
        match checked_denom(target.r, target.s, target.w) {
            None => None,
            Some(target_denom) => match trust.s.checked_add(trust.w) {
                None => None,
                Some(trust_non_belief) => {
                    trust_discount_inner(trust, target, target_denom, trust_non_belief)
                }
            },
        }
    }
}
