//! Deterministic Z-set algebra and indexed delta operators (DBSP, Budiu et al. VLDB 2023).
//!
//! A Z-set maps keys to non-zero integer weights (`+1` for insertions, `-1` for
//! retractions, and arbitrary integer multiplicities for intermediate multisets).
//! Zero-weight entries are compacted out immediately so equality and iteration
//! remain canonical and deterministic.

/// A finite map from keys of type `K` to non-zero integer weights.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZSet<K> {
    weights: std::collections::BTreeMap<K, i64>,
}

impl<K> Default for ZSet<K> {
    fn default() -> Self {
        ZSet {
            weights: std::collections::BTreeMap::new(),
        }
    }
}

impl<K: Ord + Clone> ZSet<K> {
    /// Construct an empty Z-set.
    pub const fn new() -> Self {
        ZSet {
            weights: std::collections::BTreeMap::new(),
        }
    }

    /// Construct a Z-set from `(key, weight)` entries, compacting zero weights.
    pub fn from_entries<I>(entries: I) -> Result<Self, crate::Error>
    where
        I: IntoIterator<Item = (K, i64)>,
    {
        let mut set = ZSet::new();
        for (key, weight) in entries {
            set.insert_weighted(key, weight)?;
        }
        Ok(set)
    }

    /// Add `delta` to the weight of `key`, removing the key if its weight becomes zero.
    pub fn insert_weighted(&mut self, key: K, delta: i64) -> Result<(), crate::Error> {
        if delta == 0 {
            return Ok(());
        }
        let current = self.weights.get(&key).copied().unwrap_or(0);
        let next = current
            .checked_add(delta)
            .ok_or_else(|| crate::Error::LimitExceeded("Z-set weight overflow".to_owned()))?;
        if next == 0 {
            self.weights.remove(&key);
        } else {
            self.weights.insert(key, next);
        }
        Ok(())
    }

    /// The weight of `key` (`0` if absent).
    pub fn weight(&self, key: &K) -> i64 {
        self.weights.get(key).copied().unwrap_or(0)
    }

    /// Whether this Z-set has no non-zero entries.
    pub fn is_empty(&self) -> bool {
        self.weights.is_empty()
    }

    /// Number of keys with non-zero weight.
    pub fn entry_count(&self) -> Result<u64, crate::Error> {
        u64::try_from(self.weights.len())
            .map_err(|_| crate::Error::LimitExceeded("Z-set entry count overflow".to_owned()))
    }

    /// Deterministic ordered iterator over `(key, weight)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&K, i64)> {
        self.weights.iter().map(|(key, weight)| (key, *weight))
    }

    /// Deterministic ordered iterator over keys with non-zero weight.
    pub fn keys(&self) -> std::collections::btree_map::Keys<'_, K, i64> {
        self.weights.keys()
    }

    /// Pointwise sum `self + other` with zero-weight compaction.
    pub fn add(&self, other: &Self) -> Result<Self, crate::Error> {
        let mut out = self.clone();
        out.add_in_place(other)?;
        debug_assert!(out.weights.values().all(|weight| *weight != 0));
        debug_assert!(out.weights.len() <= self.weights.len().saturating_add(other.weights.len()));
        Ok(out)
    }

    /// Pointwise accumulate `other` into `self` with zero-weight compaction.
    pub fn add_in_place(&mut self, other: &Self) -> Result<(), crate::Error> {
        for (key, weight) in other.iter() {
            self.insert_weighted(key.clone(), weight)?;
        }
        Ok(())
    }

    /// Pointwise negation `-self`.
    pub fn negate(&self) -> Result<Self, crate::Error> {
        let mut out = ZSet::new();
        for (key, weight) in self.iter() {
            let negated = weight.checked_neg().ok_or_else(negation_overflow)?;
            out.weights.insert(key.clone(), negated);
        }
        debug_assert_eq!(out.weights.len(), self.weights.len());
        debug_assert!(out.weights.values().all(|weight| *weight != 0));
        Ok(out)
    }

    /// Pointwise difference `self - other` with zero-weight compaction.
    pub fn subtract(&self, other: &Self) -> Result<Self, crate::Error> {
        let mut out = self.clone();
        for (key, weight) in other.iter() {
            let negated = weight.checked_neg().ok_or_else(negation_overflow)?;
            out.insert_weighted(key.clone(), negated)?;
        }
        debug_assert!(out.weights.values().all(|weight| *weight != 0));
        debug_assert!(out.weights.len() <= self.weights.len().saturating_add(other.weights.len()));
        Ok(out)
    }

    /// Set projection `distinct(self)`: keeps every positive-weight key at weight `+1`.
    pub fn distinct(&self) -> Self {
        let mut out = ZSet::new();
        for (key, weight) in self.iter() {
            if weight > 0 {
                out.weights.insert(key.clone(), 1);
            }
        }
        debug_assert!(out.weights.values().all(|weight| *weight == 1));
        debug_assert!(out.weights.len() <= self.weights.len());
        out
    }

    /// Incremental `distinct` operator: given integrated prior multiset `self` and
    /// `delta`, returns `distinct(self + delta) - distinct(self)` in `O(|delta|)`.
    pub fn delta_distinct(&self, delta: &Self) -> Result<Self, crate::Error> {
        let mut out = ZSet::new();
        for (key, delta_weight) in delta.iter() {
            let old_weight = self.weight(key);
            let new_weight = old_weight
                .checked_add(delta_weight)
                .ok_or_else(weight_overflow)?;
            if old_weight <= 0 && new_weight > 0 {
                out.weights.insert(key.clone(), 1);
            } else if old_weight > 0 && new_weight <= 0 {
                out.weights.insert(key.clone(), -1);
            }
        }
        debug_assert!(out.weights.len() <= delta.weights.len());
        debug_assert!(
            out.weights
                .values()
                .all(|weight| *weight == 1 || *weight == -1)
        );
        Ok(out)
    }

    /// Linear filter operator: retains entries matching `predicate`.
    pub fn filter<P>(&self, mut predicate: P) -> Self
    where
        P: FnMut(&K) -> bool,
    {
        let mut out = ZSet::new();
        for (key, weight) in self.iter() {
            if predicate(key) {
                out.weights.insert(key.clone(), weight);
            }
        }
        out
    }

    /// Linear projection/map operator: maps each key via `map_fn` and sums weights.
    pub fn map_project<K2, F>(&self, mut map_fn: F) -> Result<ZSet<K2>, crate::Error>
    where
        K2: Ord + Clone,
        F: FnMut(&K) -> Option<K2>,
    {
        let mut out = ZSet::new();
        for (key, weight) in self.iter() {
            if let Some(mapped) = map_fn(key) {
                out.insert_weighted(mapped, weight)?;
            }
        }
        Ok(out)
    }
}

/// An indexed Z-set grouping values of type `V` under deterministic join keys `K`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedZSet<K, V> {
    buckets: std::collections::BTreeMap<K, ZSet<V>>,
}

impl<K, V> Default for IndexedZSet<K, V> {
    fn default() -> Self {
        IndexedZSet {
            buckets: std::collections::BTreeMap::new(),
        }
    }
}

impl<K: Ord + Clone, V: Ord + Clone> IndexedZSet<K, V> {
    /// Construct an empty indexed Z-set.
    pub const fn new() -> Self {
        IndexedZSet {
            buckets: std::collections::BTreeMap::new(),
        }
    }

    /// Whether the index contains no non-empty buckets.
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    /// Look up the bucket of weighted values for `key`.
    pub fn get(&self, key: &K) -> Option<&ZSet<V>> {
        self.buckets.get(key)
    }

    /// Deterministic ordered iterator over `(key, bucket)` pairs.
    pub fn iter(&self) -> std::collections::btree_map::Iter<'_, K, ZSet<V>> {
        self.buckets.iter()
    }

    /// Index a `ZSet<V>` by extracting a join key for each value.
    pub fn from_zset<F>(zset: &ZSet<V>, mut key_fn: F) -> Result<Self, crate::Error>
    where
        F: FnMut(&V) -> K,
    {
        let mut indexed = IndexedZSet::new();
        indexed.apply_delta_with(zset, &mut key_fn)?;
        Ok(indexed)
    }

    /// Apply a delta `ZSet<V>` to this index, compacting empty buckets.
    pub fn apply_delta_with<F>(
        &mut self,
        delta: &ZSet<V>,
        mut key_fn: F,
    ) -> Result<(), crate::Error>
    where
        F: FnMut(&V) -> K,
    {
        for (value, weight) in delta.iter() {
            let key = key_fn(value);
            self.insert_weighted(key, value.clone(), weight)?;
        }
        Ok(())
    }

    /// Add `delta` to `(key, value)` and remove empty buckets.
    pub fn insert_weighted(&mut self, key: K, value: V, delta: i64) -> Result<(), crate::Error> {
        if delta == 0 {
            return Ok(());
        }
        if let Some(bucket) = self.buckets.get_mut(&key) {
            bucket.insert_weighted(value, delta)?;
            let is_empty_after = bucket.is_empty();
            if is_empty_after {
                self.buckets.remove(&key);
            }
            return Ok(());
        }
        let mut bucket = ZSet::new();
        bucket.insert_weighted(value, delta)?;
        if !bucket.is_empty() {
            self.buckets.insert(key, bucket);
        }
        Ok(())
    }
}

/// Inputs for the DBSP bilinear join delta:
/// `Δ(A ⋈ B) = (ΔA ⋈ B_prev) + (A_prev ⋈ ΔB) + (ΔA ⋈ ΔB)`.
pub struct BilinearJoin<'a, K, V1, V2> {
    pub left_prev: &'a IndexedZSet<K, V1>,
    pub left_delta: &'a IndexedZSet<K, V1>,
    pub right_prev: &'a IndexedZSet<K, V2>,
    pub right_delta: &'a IndexedZSet<K, V2>,
}

/// Compute the exact DBSP bilinear join delta `(ΔA ⋈ B_prev) + (A_prev ⋈ ΔB) + (ΔA ⋈ ΔB)`.
pub fn delta_join<K, V1, V2, V3, F, C>(
    inputs: BilinearJoin<'_, K, V1, V2>,
    mut combine: F,
    mut charge: C,
) -> Result<ZSet<V3>, crate::Error>
where
    K: Ord + Clone,
    V1: Ord + Clone,
    V2: Ord + Clone,
    V3: Ord + Clone,
    F: FnMut(&V1, &V2) -> Option<V3>,
    C: FnMut(u64) -> Result<(), crate::Error>,
{
    let BilinearJoin {
        left_prev,
        left_delta,
        right_prev,
        right_delta,
    } = inputs;
    let mut output = ZSet::new();
    if left_delta.is_empty() && right_delta.is_empty() {
        return Ok(output);
    }
    join_indexed(
        left_delta,
        right_prev,
        &mut combine,
        &mut charge,
        &mut output,
    )?;
    join_indexed(
        left_prev,
        right_delta,
        &mut combine,
        &mut charge,
        &mut output,
    )?;
    join_indexed(
        left_delta,
        right_delta,
        &mut combine,
        &mut charge,
        &mut output,
    )?;
    debug_assert!(
        !(left_delta.is_empty() && right_delta.is_empty()) || output.is_empty(),
        "empty input deltas must yield empty join delta"
    );
    debug_assert!(output.iter().all(|(_, weight)| weight != 0));
    Ok(output)
}

fn join_indexed<K, V1, V2, V3, F, C>(
    left: &IndexedZSet<K, V1>,
    right: &IndexedZSet<K, V2>,
    combine: &mut F,
    charge: &mut C,
    output: &mut ZSet<V3>,
) -> Result<(), crate::Error>
where
    K: Ord + Clone,
    V1: Ord + Clone,
    V2: Ord + Clone,
    V3: Ord + Clone,
    F: FnMut(&V1, &V2) -> Option<V3>,
    C: FnMut(u64) -> Result<(), crate::Error>,
{
    if left.is_empty() || right.is_empty() {
        return Ok(());
    }
    debug_assert!(!left.buckets.is_empty());
    debug_assert!(!right.buckets.is_empty());
    if left.buckets.len() <= right.buckets.len() {
        for (key, left_bucket) in left.iter() {
            charge(1)?;
            let Some(right_bucket) = right.get(key) else {
                continue;
            };
            join_bucket_pair(left_bucket, right_bucket, combine, charge, output)?;
        }
    } else {
        for (key, right_bucket) in right.iter() {
            charge(1)?;
            let Some(left_bucket) = left.get(key) else {
                continue;
            };
            join_bucket_pair(left_bucket, right_bucket, combine, charge, output)?;
        }
    }
    Ok(())
}

fn join_bucket_pair<V1, V2, V3, F, C>(
    left_bucket: &ZSet<V1>,
    right_bucket: &ZSet<V2>,
    combine: &mut F,
    charge: &mut C,
    output: &mut ZSet<V3>,
) -> Result<(), crate::Error>
where
    V1: Ord + Clone,
    V2: Ord + Clone,
    V3: Ord + Clone,
    F: FnMut(&V1, &V2) -> Option<V3>,
    C: FnMut(u64) -> Result<(), crate::Error>,
{
    for (v1, w1) in left_bucket.iter() {
        for (v2, w2) in right_bucket.iter() {
            charge(1)?;
            let weight = w1.checked_mul(w2).ok_or_else(join_weight_overflow)?;
            if let Some(combined) = combine(v1, v2) {
                output.insert_weighted(combined, weight)?;
            }
        }
    }
    Ok(())
}

fn negation_overflow() -> crate::Error {
    crate::Error::LimitExceeded("Z-set negation overflow".to_owned())
}

fn weight_overflow() -> crate::Error {
    crate::Error::LimitExceeded("Z-set weight overflow".to_owned())
}

fn join_weight_overflow() -> crate::Error {
    crate::Error::LimitExceeded("Z-set join weight overflow".to_owned())
}

/// Per-epistemic-level integer multiplicity in the K-relation Z-module
/// $\mathbb{Z}[\text{Proposed}, \text{Accepted}]$.
///
/// `Rejected` is the semiring zero and is represented by `(0, 0)`.
/// Effective epistemic status of an integrated multiset weight is computed
/// in $O(1)$ via [`EpistemicWeight::effective_status`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EpistemicWeight {
    pub proposed: i64,
    pub accepted: i64,
}

impl EpistemicWeight {
    /// Additive identity `(0, 0)`.
    pub const ZERO: Self = Self {
        proposed: 0,
        accepted: 0,
    };

    /// Multiplicative identity `(0, 1)` (`Accepted` with weight `+1`).
    pub const ONE: Self = Self {
        proposed: 0,
        accepted: 1,
    };

    /// Construct a weight at one epistemic tier (`Rejected` yields [`Self::ZERO`]).
    pub const fn from_status(status: crate::EpistemicStatus, weight: i64) -> Self {
        if matches!(status, crate::EpistemicStatus::Accepted) {
            Self {
                proposed: 0,
                accepted: weight,
            }
        } else if matches!(status, crate::EpistemicStatus::Proposed) {
            Self {
                proposed: weight,
                accepted: 0,
            }
        } else {
            Self::ZERO
        }
    }

    /// Whether both epistemic tier weights are zero.
    pub const fn is_zero(self) -> bool {
        self.proposed == 0 && self.accepted == 0
    }

    /// Whether at least one active epistemic tier has positive weight.
    pub const fn is_active(self) -> bool {
        self.accepted > 0 || self.proposed > 0
    }

    /// Exact `EpistemicStatus::union` (`max`) over all positive-weight tiers in $O(1)$.
    pub const fn effective_status(self) -> crate::EpistemicStatus {
        if self.accepted > 0 {
            crate::EpistemicStatus::Accepted
        } else if self.proposed > 0 {
            crate::EpistemicStatus::Proposed
        } else {
            crate::EpistemicStatus::Rejected
        }
    }

    /// Total multiplicity across active tiers.
    pub fn total_weight(self) -> Result<i64, crate::Error> {
        self.proposed
            .checked_add(self.accepted)
            .ok_or_else(weight_overflow)
    }

    /// Pointwise addition in $\mathbb{Z}^2$.
    pub fn checked_add(self, rhs: Self) -> Result<Self, crate::Error> {
        Ok(Self {
            proposed: self
                .proposed
                .checked_add(rhs.proposed)
                .ok_or_else(weight_overflow)?,
            accepted: self
                .accepted
                .checked_add(rhs.accepted)
                .ok_or_else(weight_overflow)?,
        })
    }

    /// Pointwise negation in $\mathbb{Z}^2$.
    pub fn checked_neg(self) -> Result<Self, crate::Error> {
        Ok(Self {
            proposed: self.proposed.checked_neg().ok_or_else(negation_overflow)?,
            accepted: self.accepted.checked_neg().ok_or_else(negation_overflow)?,
        })
    }

    /// Bilinear semiring multiplication over $\mathbb{Z}[(\{\text{Proposed}, \text{Accepted}\}, \min)]$:
    /// `(p1, a1) ⊗ (p2, a2) = (a1*p2 + p1*a2 + p1*p2, a1*a2)`.
    pub fn join_mul(self, rhs: Self) -> Result<Self, crate::Error> {
        let accepted = self
            .accepted
            .checked_mul(rhs.accepted)
            .ok_or_else(join_weight_overflow)?;
        let ap = self
            .accepted
            .checked_mul(rhs.proposed)
            .ok_or_else(join_weight_overflow)?;
        let pa = self
            .proposed
            .checked_mul(rhs.accepted)
            .ok_or_else(join_weight_overflow)?;
        let pp = self
            .proposed
            .checked_mul(rhs.proposed)
            .ok_or_else(join_weight_overflow)?;
        let proposed = ap
            .checked_add(pa)
            .and_then(|sum| sum.checked_add(pp))
            .ok_or_else(join_weight_overflow)?;
        Ok(Self { proposed, accepted })
    }

    /// Bilinear Kleene antijoin mask subtracted from `self` when negated atom has distinct weight `neg`.
    ///
    /// - `neg = (0, 0)` (absent): mask `(0, 0)` → retains `(p_L, a_L)`.
    /// - `neg = (1, 0)` (`Proposed`): mask `(-a_L, a_L)` → attenuates to `(p_L + a_L, 0)`.
    /// - `neg = (0, 1)` (`Accepted`): mask `(p_L, a_L)` → blocks to `(0, 0)`.
    pub fn kleene_antijoin_mask(self, neg: Self) -> Result<Self, crate::Error> {
        let neg_any = neg
            .proposed
            .checked_add(neg.accepted)
            .ok_or_else(join_weight_overflow)?;
        let accepted = self
            .accepted
            .checked_mul(neg_any)
            .ok_or_else(join_weight_overflow)?;
        let pa = self
            .proposed
            .checked_mul(neg.accepted)
            .ok_or_else(join_weight_overflow)?;
        let ap = self
            .accepted
            .checked_mul(neg.proposed)
            .ok_or_else(join_weight_overflow)?;
        let proposed = pa.checked_sub(ap).ok_or_else(join_weight_overflow)?;
        Ok(Self { proposed, accepted })
    }

    /// Bilinear strict antijoin mask subtracted from `self` when negated atom has distinct weight `neg`.
    ///
    /// Blocks on either `Proposed` or `Accepted`.
    pub fn strict_antijoin_mask(self, neg: Self) -> Result<Self, crate::Error> {
        let neg_any = neg
            .proposed
            .checked_add(neg.accepted)
            .ok_or_else(join_weight_overflow)?;
        let proposed = self
            .proposed
            .checked_mul(neg_any)
            .ok_or_else(join_weight_overflow)?;
        let accepted = self
            .accepted
            .checked_mul(neg_any)
            .ok_or_else(join_weight_overflow)?;
        Ok(Self { proposed, accepted })
    }
}

/// Semiring-valued K-relation Z-set mapping keys `K` to non-zero [`EpistemicWeight`]s.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpistemicZSet<K> {
    weights: std::collections::BTreeMap<K, EpistemicWeight>,
}

impl<K> Default for EpistemicZSet<K> {
    fn default() -> Self {
        Self {
            weights: std::collections::BTreeMap::new(),
        }
    }
}

impl<K: Ord + Clone> EpistemicZSet<K> {
    /// Construct an empty K-relation Z-set.
    pub const fn new() -> Self {
        Self {
            weights: std::collections::BTreeMap::new(),
        }
    }

    /// Construct from `(key, status, weight)` entries, compacting zeros.
    pub fn from_status_entries<I>(entries: I) -> Result<Self, crate::Error>
    where
        I: IntoIterator<Item = (K, crate::EpistemicStatus, i64)>,
    {
        let mut set = Self::new();
        for (key, status, weight) in entries {
            set.insert_status(key, status, weight)?;
        }
        Ok(set)
    }

    /// Add `delta` to `key`'s weight, removing `key` if both tiers become zero.
    pub fn insert_weight(&mut self, key: K, delta: EpistemicWeight) -> Result<(), crate::Error> {
        if delta.is_zero() {
            return Ok(());
        }
        let current = self.weight(&key);
        let next = current.checked_add(delta)?;
        if next.is_zero() {
            self.weights.remove(&key);
        } else {
            self.weights.insert(key, next);
        }
        Ok(())
    }

    /// Add `delta` at a single epistemic tier for `key`.
    pub fn insert_status(
        &mut self,
        key: K,
        status: crate::EpistemicStatus,
        delta: i64,
    ) -> Result<(), crate::Error> {
        self.insert_weight(key, EpistemicWeight::from_status(status, delta))
    }

    /// The per-tier weight of `key` (`EpistemicWeight::ZERO` if absent).
    pub fn weight(&self, key: &K) -> EpistemicWeight {
        self.weights
            .get(key)
            .copied()
            .unwrap_or(EpistemicWeight::ZERO)
    }

    /// Exact effective [`crate::EpistemicStatus`] of `key` in $O(1)$.
    pub fn epistemic_status(&self, key: &K) -> crate::EpistemicStatus {
        self.weight(key).effective_status()
    }

    /// Whether this K-relation Z-set has no non-zero entries.
    pub fn is_empty(&self) -> bool {
        self.weights.is_empty()
    }

    /// Number of keys with non-zero weight.
    pub fn entry_count(&self) -> Result<u64, crate::Error> {
        u64::try_from(self.weights.len())
            .map_err(|_| crate::Error::LimitExceeded("Z-set entry count overflow".to_owned()))
    }

    /// Deterministic ordered iterator over `(key, EpistemicWeight)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&K, EpistemicWeight)> {
        self.weights.iter().map(|(key, weight)| (key, *weight))
    }

    /// Pointwise sum `self + other`.
    pub fn add(&self, other: &Self) -> Result<Self, crate::Error> {
        let mut out = self.clone();
        out.add_in_place(other)?;
        Ok(out)
    }

    /// Pointwise accumulate `other` into `self`.
    pub fn add_in_place(&mut self, other: &Self) -> Result<(), crate::Error> {
        for (key, weight) in other.iter() {
            self.insert_weight(key.clone(), weight)?;
        }
        Ok(())
    }

    /// Pointwise difference `self - other`.
    pub fn subtract(&self, other: &Self) -> Result<Self, crate::Error> {
        let mut out = self.clone();
        for (key, weight) in other.iter() {
            out.insert_weight(key.clone(), weight.checked_neg()?)?;
        }
        Ok(out)
    }

    /// Exact epistemic set projection: maps each active key to `+1` at its
    /// highest positive tier (`Accepted` if `accepted > 0`, else `Proposed`).
    pub fn distinct(&self) -> Self {
        let mut out = Self::new();
        for (key, weight) in self.iter() {
            let status = weight.effective_status();
            if status.is_active() {
                out.weights
                    .insert(key.clone(), EpistemicWeight::from_status(status, 1));
            }
        }
        out
    }

    /// Incremental epistemic `distinct`: returns `distinct(self + delta) - distinct(self)`
    /// in $O(|\text{delta}|)$.
    pub fn delta_distinct(&self, delta: &Self) -> Result<Self, crate::Error> {
        let mut out = Self::new();
        for (key, delta_weight) in delta.iter() {
            let old_weight = self.weight(key);
            let new_weight = old_weight.checked_add(delta_weight)?;
            let old_status = old_weight.effective_status();
            let new_status = new_weight.effective_status();
            if old_status != new_status {
                if old_status.is_active() {
                    out.insert_status(key.clone(), old_status, -1)?;
                }
                if new_status.is_active() {
                    out.insert_status(key.clone(), new_status, 1)?;
                }
            }
        }
        Ok(out)
    }
}

/// Indexed K-relation Z-set grouping values `V` under join keys `K`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedEpistemicZSet<K, V> {
    buckets: std::collections::BTreeMap<K, EpistemicZSet<V>>,
}

impl<K, V> Default for IndexedEpistemicZSet<K, V> {
    fn default() -> Self {
        Self {
            buckets: std::collections::BTreeMap::new(),
        }
    }
}

impl<K: Ord + Clone, V: Ord + Clone> IndexedEpistemicZSet<K, V> {
    /// Construct an empty indexed K-relation Z-set.
    pub const fn new() -> Self {
        Self {
            buckets: std::collections::BTreeMap::new(),
        }
    }

    /// Whether the index has no non-empty buckets.
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    /// Look up the bucket for `key`.
    pub fn get(&self, key: &K) -> Option<&EpistemicZSet<V>> {
        self.buckets.get(key)
    }

    /// Deterministic ordered iterator over `(key, bucket)` pairs.
    pub fn iter(&self) -> std::collections::btree_map::Iter<'_, K, EpistemicZSet<V>> {
        self.buckets.iter()
    }

    /// Index an [`EpistemicZSet<V>`] using `key_fn`.
    pub fn from_zset<F>(zset: &EpistemicZSet<V>, mut key_fn: F) -> Result<Self, crate::Error>
    where
        F: FnMut(&V) -> K,
    {
        let mut indexed = Self::new();
        indexed.apply_delta_with(zset, &mut key_fn)?;
        Ok(indexed)
    }

    /// Apply a delta [`EpistemicZSet<V>`] to this index, compacting empty buckets.
    pub fn apply_delta_with<F>(
        &mut self,
        delta: &EpistemicZSet<V>,
        mut key_fn: F,
    ) -> Result<(), crate::Error>
    where
        F: FnMut(&V) -> K,
    {
        for (value, weight) in delta.iter() {
            let key = key_fn(value);
            self.insert_weight(key, value.clone(), weight)?;
        }
        Ok(())
    }

    /// Add `delta` to `(key, value)` and remove empty buckets.
    pub fn insert_weight(
        &mut self,
        key: K,
        value: V,
        delta: EpistemicWeight,
    ) -> Result<(), crate::Error> {
        if delta.is_zero() {
            return Ok(());
        }
        if let Some(bucket) = self.buckets.get_mut(&key) {
            bucket.insert_weight(value, delta)?;
            if bucket.is_empty() {
                self.buckets.remove(&key);
            }
            return Ok(());
        }
        let mut bucket = EpistemicZSet::new();
        bucket.insert_weight(value, delta)?;
        if !bucket.is_empty() {
            self.buckets.insert(key, bucket);
        }
        Ok(())
    }
}

/// Inputs for a bilinear K-relation join delta:
/// `Δ(A ⋈_K B) = (ΔA ⋈_K B_prev) + (A_prev ⋈_K ΔB) + (ΔA ⋈_K ΔB)`.
pub struct EpistemicBilinearJoin<'a, K, V1, V2> {
    pub left_prev: &'a IndexedEpistemicZSet<K, V1>,
    pub left_delta: &'a IndexedEpistemicZSet<K, V1>,
    pub right_prev: &'a IndexedEpistemicZSet<K, V2>,
    pub right_delta: &'a IndexedEpistemicZSet<K, V2>,
}

/// Bilinear weight combiner for K-relation joins and antijoins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpistemicCombineOp {
    /// Positive semiring join `×` (`EpistemicWeight::join_mul`).
    Join,
    /// Kleene three-valued antijoin mask (`EpistemicWeight::kleene_antijoin_mask`).
    KleeneAntijoinMask,
    /// Strict classical antijoin mask (`EpistemicWeight::strict_antijoin_mask`).
    StrictAntijoinMask,
}

impl EpistemicCombineOp {
    fn apply(
        self,
        left: EpistemicWeight,
        right: EpistemicWeight,
    ) -> Result<EpistemicWeight, crate::Error> {
        if self == Self::Join {
            left.join_mul(right)
        } else if self == Self::KleeneAntijoinMask {
            left.kleene_antijoin_mask(right)
        } else {
            left.strict_antijoin_mask(right)
        }
    }
}

struct EpistemicJoinSink<'a, V3, F, C> {
    combine_op: EpistemicCombineOp,
    combine: &'a mut F,
    charge: &'a mut C,
    output: &'a mut EpistemicZSet<V3>,
}

/// Compute an exact bilinear K-relation delta over indexed epistemic Z-sets.
pub fn delta_epistemic_join<K, V1, V2, V3, F, C>(
    inputs: EpistemicBilinearJoin<'_, K, V1, V2>,
    combine_op: EpistemicCombineOp,
    mut combine: F,
    mut charge: C,
) -> Result<EpistemicZSet<V3>, crate::Error>
where
    K: Ord + Clone,
    V1: Ord + Clone,
    V2: Ord + Clone,
    V3: Ord + Clone,
    F: FnMut(&V1, &V2) -> Option<V3>,
    C: FnMut(u64) -> Result<(), crate::Error>,
{
    let EpistemicBilinearJoin {
        left_prev,
        left_delta,
        right_prev,
        right_delta,
    } = inputs;
    let mut output = EpistemicZSet::new();
    if left_delta.is_empty() && right_delta.is_empty() {
        return Ok(output);
    }
    let mut sink = EpistemicJoinSink {
        combine_op,
        combine: &mut combine,
        charge: &mut charge,
        output: &mut output,
    };
    join_epistemic_indexed(left_delta, right_prev, &mut sink)?;
    join_epistemic_indexed(left_prev, right_delta, &mut sink)?;
    join_epistemic_indexed(left_delta, right_delta, &mut sink)?;
    Ok(output)
}

fn join_epistemic_indexed<K, V1, V2, V3, F, C>(
    left: &IndexedEpistemicZSet<K, V1>,
    right: &IndexedEpistemicZSet<K, V2>,
    sink: &mut EpistemicJoinSink<'_, V3, F, C>,
) -> Result<(), crate::Error>
where
    K: Ord + Clone,
    V1: Ord + Clone,
    V2: Ord + Clone,
    V3: Ord + Clone,
    F: FnMut(&V1, &V2) -> Option<V3>,
    C: FnMut(u64) -> Result<(), crate::Error>,
{
    if left.is_empty() || right.is_empty() {
        return Ok(());
    }
    if left.buckets.len() <= right.buckets.len() {
        for (key, left_bucket) in left.iter() {
            (sink.charge)(1)?;
            let Some(right_bucket) = right.get(key) else {
                continue;
            };
            join_epistemic_buckets(left_bucket, right_bucket, sink)?;
        }
    } else {
        for (key, right_bucket) in right.iter() {
            (sink.charge)(1)?;
            let Some(left_bucket) = left.get(key) else {
                continue;
            };
            join_epistemic_buckets(left_bucket, right_bucket, sink)?;
        }
    }
    Ok(())
}

fn join_epistemic_buckets<V1, V2, V3, F, C>(
    left_bucket: &EpistemicZSet<V1>,
    right_bucket: &EpistemicZSet<V2>,
    sink: &mut EpistemicJoinSink<'_, V3, F, C>,
) -> Result<(), crate::Error>
where
    V1: Ord + Clone,
    V2: Ord + Clone,
    V3: Ord + Clone,
    F: FnMut(&V1, &V2) -> Option<V3>,
    C: FnMut(u64) -> Result<(), crate::Error>,
{
    for (v1, w1) in left_bucket.iter() {
        for (v2, w2) in right_bucket.iter() {
            (sink.charge)(1)?;
            let weight = sink.combine_op.apply(w1, w2)?;
            if !weight.is_zero()
                && let Some(combined) = (sink.combine)(v1, v2)
            {
                sink.output.insert_weight(combined, weight)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn compacts_zero_weights_and_computes_delta_distinct() {
        let mut a = super::ZSet::from_entries([("x", 1), ("y", 2)]).expect("zset");
        a.insert_weighted("x", -1).expect("compact x");
        assert_eq!(a.weight(&"x"), 0);
        assert_eq!(a.entry_count().expect("count"), 1);

        let delta = super::ZSet::from_entries([("x", 2), ("y", -1), ("z", 1)]).expect("delta");
        let dist_delta = a.delta_distinct(&delta).expect("delta distinct");
        // x: 0 -> 2 (+1); y: 2 -> 1 (0); z: 0 -> 1 (+1).
        assert_eq!(dist_delta.weight(&"x"), 1);
        assert_eq!(dist_delta.weight(&"y"), 0);
        assert_eq!(dist_delta.weight(&"z"), 1);

        let b = a.add(&delta).expect("add");
        assert_eq!(
            a.distinct().add(&dist_delta).expect("inc"),
            b.distinct(),
            "delta_distinct must match from-scratch distinct"
        );
    }

    #[test]
    fn bilinear_join_delta_matches_from_scratch_across_inserts_and_retractions() {
        let a0 = super::ZSet::from_entries([((1_i64, "a1"), 1), ((2, "a2"), 1)]).expect("a0");
        let b0 = super::ZSet::from_entries([((1_i64, "b1"), 1), ((2, "b2"), 1)]).expect("b0");
        let da =
            super::ZSet::from_entries([((1_i64, "a1"), -1), ((2, "a2_new"), 1), ((3, "a3"), 1)])
                .expect("da");
        let db = super::ZSet::from_entries([((1_i64, "b1"), -1), ((3, "b3"), 1)]).expect("db");

        let ia0 = super::IndexedZSet::from_zset(&a0, |(k, _)| *k).expect("ia0");
        let ib0 = super::IndexedZSet::from_zset(&b0, |(k, _)| *k).expect("ib0");
        let ida = super::IndexedZSet::from_zset(&da, |(k, _)| *k).expect("ida");
        let idb = super::IndexedZSet::from_zset(&db, |(k, _)| *k).expect("idb");

        let mut work = 0_u64;
        let djoin = super::delta_join(
            super::BilinearJoin {
                left_prev: &ia0,
                left_delta: &ida,
                right_prev: &ib0,
                right_delta: &idb,
            },
            |(_, va), (_, vb)| Some((*va, *vb)),
            |cost| {
                work = work.saturating_add(cost);
                Ok(())
            },
        )
        .expect("delta join");

        let j0 = super::delta_join(
            super::BilinearJoin {
                left_prev: &super::IndexedZSet::new(),
                left_delta: &ia0,
                right_prev: &super::IndexedZSet::new(),
                right_delta: &ib0,
            },
            |(_, va), (_, vb)| Some((*va, *vb)),
            |_| Ok(()),
        )
        .expect("j0");

        let a1 = a0.add(&da).expect("a1");
        let b1 = b0.add(&db).expect("b1");
        let ia1 = super::IndexedZSet::from_zset(&a1, |(k, _)| *k).expect("ia1");
        let ib1 = super::IndexedZSet::from_zset(&b1, |(k, _)| *k).expect("ib1");
        let j1_from_scratch = super::delta_join(
            super::BilinearJoin {
                left_prev: &super::IndexedZSet::new(),
                left_delta: &ia1,
                right_prev: &super::IndexedZSet::new(),
                right_delta: &ib1,
            },
            |(_, va), (_, vb)| Some((*va, *vb)),
            |_| Ok(()),
        )
        .expect("j1");

        let j1_inc = j0.add(&djoin).expect("inc join");
        assert_eq!(j1_inc, j1_from_scratch);
        assert!(work > 0);
    }

    #[test]
    fn epistemic_distinct_and_kleene_antijoin_are_exact_under_deltas() {
        let mut m = super::EpistemicZSet::from_status_entries([
            ("a", crate::EpistemicStatus::Accepted, 1),
            ("a", crate::EpistemicStatus::Proposed, 1),
            ("b", crate::EpistemicStatus::Proposed, 1),
        ])
        .expect("m");
        assert_eq!(m.epistemic_status(&"a"), crate::EpistemicStatus::Accepted);
        assert_eq!(m.epistemic_status(&"b"), crate::EpistemicStatus::Proposed);

        // Retract Accepted derivation of "a" -> downgrades to Proposed in O(1)!
        let delta = super::EpistemicZSet::from_status_entries([
            ("a", crate::EpistemicStatus::Accepted, -1),
            ("b", crate::EpistemicStatus::Accepted, 1),
        ])
        .expect("delta");
        let dist_before = m.distinct();
        let ddist = m.delta_distinct(&delta).expect("ddist");
        m.add_in_place(&delta).expect("apply");
        assert_eq!(dist_before.add(&ddist).expect("inc distinct"), m.distinct());
        assert_eq!(m.epistemic_status(&"a"), crate::EpistemicStatus::Proposed);
        assert_eq!(m.epistemic_status(&"b"), crate::EpistemicStatus::Accepted);

        // Verify Kleene antijoin bilinearity across Accepted -> Proposed -> Rejected transitions.
        let l0 = super::EpistemicZSet::from_status_entries([
            ("h1", crate::EpistemicStatus::Accepted, 1),
            ("h2", crate::EpistemicStatus::Accepted, 1),
            ("h3", crate::EpistemicStatus::Proposed, 1),
        ])
        .expect("l0");
        let q0 = super::EpistemicZSet::from_status_entries([
            ("h1", crate::EpistemicStatus::Accepted, 1),
            ("h2", crate::EpistemicStatus::Proposed, 1),
        ])
        .expect("q0");
        let il0 = super::IndexedEpistemicZSet::from_zset(&l0, |k| *k).expect("il0");
        let iq0 = super::IndexedEpistemicZSet::from_zset(&q0, |k| *k).expect("iq0");
        let mask0 = super::delta_epistemic_join(
            super::EpistemicBilinearJoin {
                left_prev: &super::IndexedEpistemicZSet::new(),
                left_delta: &il0,
                right_prev: &super::IndexedEpistemicZSet::new(),
                right_delta: &iq0,
            },
            super::EpistemicCombineOp::KleeneAntijoinMask,
            |k, _| Some(*k),
            |_| Ok(()),
        )
        .expect("mask0");
        let out0 = l0.subtract(&mask0).expect("out0");
        assert_eq!(
            out0.epistemic_status(&"h1"),
            crate::EpistemicStatus::Rejected
        );
        assert_eq!(
            out0.epistemic_status(&"h2"),
            crate::EpistemicStatus::Proposed
        );
        assert_eq!(
            out0.epistemic_status(&"h3"),
            crate::EpistemicStatus::Proposed
        );

        // Downgrade h1 from Accepted -> Proposed, remove h2 from Q, add h3 as Proposed to Q.
        let dq = super::EpistemicZSet::from_status_entries([
            ("h1", crate::EpistemicStatus::Accepted, -1),
            ("h1", crate::EpistemicStatus::Proposed, 1),
            ("h2", crate::EpistemicStatus::Proposed, -1),
            ("h3", crate::EpistemicStatus::Proposed, 1),
        ])
        .expect("dq");
        let idq = super::IndexedEpistemicZSet::from_zset(&dq, |k| *k).expect("idq");
        let dmask = super::delta_epistemic_join(
            super::EpistemicBilinearJoin {
                left_prev: &il0,
                left_delta: &super::IndexedEpistemicZSet::new(),
                right_prev: &iq0,
                right_delta: &idq,
            },
            super::EpistemicCombineOp::KleeneAntijoinMask,
            |k, _| Some(*k),
            |_| Ok(()),
        )
        .expect("dmask");
        let out1 = out0.subtract(&dmask).expect("out1");
        assert_eq!(
            out1.epistemic_status(&"h1"),
            crate::EpistemicStatus::Proposed
        );
        assert_eq!(
            out1.epistemic_status(&"h2"),
            crate::EpistemicStatus::Accepted
        );
        assert_eq!(
            out1.epistemic_status(&"h3"),
            crate::EpistemicStatus::Proposed
        );
    }
}
