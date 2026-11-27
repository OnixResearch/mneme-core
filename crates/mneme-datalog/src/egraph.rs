//! Projection-local, epistemic-stratified relational e-graphs and congruence closure.
//!
//! Canonical workspace records are never mutated. Equivalence classes live strictly
//! inside a disposable projection build and are stratified into two union-find tiers:
//! - `accepted`: populated exclusively by `EpistemicStatus::Accepted` unions.
//! - `proposed`: overlays `accepted` with `EpistemicStatus::Proposed` unions.
//!
//! Any term canonicalized through an edge present only in `proposed`
//! (`find_accepted(v) != find_proposed(v)`) inherits `EpistemicStatus::Proposed`
//! via semiring conjunction (`Accepted × Proposed = Proposed`), preventing silent
//! epistemic promotion by construction.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// Reserved synthetic head predicate for pure `Action::Union` rules.
pub const UNION_HEAD_PREDICATE: &str = "__egraph_union";
/// Default maximum congruence-closure rebuild rounds permitted per stratum.
pub const DEFAULT_MAX_EGRAPH_REBUILD_ROUNDS: u64 = 32;
/// Default maximum total e-graph union operations permitted in one build.
pub const DEFAULT_MAX_EGRAPH_UNIONS: u64 = 100_000;

/// Configuration bounding projection-local e-graph equality saturation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EGraphConfig {
    /// Maximum congruence-closure rebuild rounds permitted per stratum.
    pub max_rebuild_rounds: u64,
    /// Maximum total e-graph union operations permitted in one build.
    pub max_unions: u64,
}

impl Default for EGraphConfig {
    fn default() -> Self {
        Self {
            max_rebuild_rounds: DEFAULT_MAX_EGRAPH_REBUILD_ROUNDS,
            max_unions: DEFAULT_MAX_EGRAPH_UNIONS,
        }
    }
}

/// An equality-saturation action executed when a rule body matches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Merge the equivalence classes of `left` and `right` in the projection-local
    /// epistemic-stratified e-graph.
    Union {
        left: crate::Term,
        right: crate::Term,
    },
}

/// Monotone semilattice join operator for functional e-graph head columns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LatticeOp {
    /// Keep the greatest value under canonical (numeric-aware) ordering.
    Max,
    /// Keep the least value under canonical (numeric-aware) ordering.
    Min,
    /// Take the set union of `Value::Set` values (promoting scalars to singletons).
    SetUnion,
}

impl LatticeOp {
    /// Stable lower-case name.
    pub const fn name(self) -> &'static str {
        if matches!(self, Self::Max) {
            "max"
        } else if matches!(self, Self::Min) {
            "min"
        } else {
            "set-union"
        }
    }
}

/// Functional lattice merge specification on a rule head predicate.
///
/// Treats all columns other than `column` as the functional key and merges
/// values in `column` via `op` during congruence closure (`rebuild`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LatticeMerge {
    /// Zero-based column index in the head atom holding the lattice value.
    pub column: u32,
    /// Monotone join operator applied when two rows share the same canonical key.
    pub op: LatticeOp,
}

/// Outcome of one e-graph union operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnionStatus {
    /// Both values were already in the same equivalence class (or the union was inactive).
    Unchanged,
    /// Two distinct equivalence classes were merged.
    Merged,
}

fn slot(id: u32) -> Option<usize> {
    usize::try_from(id).ok()
}

/// Deterministic union-find selecting the lexicographically smallest
/// [`mneme_core::Value`] (including `<record-id "…">`) as canonical representative.
///
/// Uses interned `u32` identifiers and iterative path compression (zero recursion)
/// for insertion-order-invariant canonicalization.
#[derive(Clone, Debug, Default)]
pub struct UnionFind {
    value_to_id: std::collections::BTreeMap<mneme_core::Value, u32>,
    id_to_value: Vec<mneme_core::Value>,
    parent: Vec<u32>,
    node_count: u64,
    union_count: u64,
}

impl PartialEq for UnionFind {
    fn eq(&self, other: &Self) -> bool {
        self.classes() == other.classes()
    }
}

impl Eq for UnionFind {}

impl UnionFind {
    /// Construct an empty union-find.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of distinct values tracked in this union-find.
    pub const fn len(&self) -> u64 {
        self.node_count
    }

    /// Whether no values have been unioned or interned.
    pub fn is_empty(&self) -> bool {
        self.id_to_value.is_empty()
    }

    /// Total number of non-trivial merges performed.
    pub const fn union_count(&self) -> u64 {
        self.union_count
    }

    /// Return the canonical representative of `value` without mutating internal state.
    pub fn find_ref<'a>(&'a self, value: &'a mneme_core::Value) -> &'a mneme_core::Value {
        let Some(&id) = self.value_to_id.get(value) else {
            return value;
        };
        let root = self.find_root_id(id);
        slot(root)
            .and_then(|idx| self.id_to_value.get(idx))
            .unwrap_or(value)
    }

    /// Return the cloned canonical representative of `value`.
    pub fn find(&self, value: &mneme_core::Value) -> mneme_core::Value {
        self.find_ref(value).clone()
    }

    /// Merge the equivalence classes of `left` and `right`, choosing the
    /// lexicographically smallest value as the canonical representative.
    pub fn union(&mut self, left: &mneme_core::Value, right: &mneme_core::Value) -> UnionStatus {
        let (next, status) = std::mem::take(self).into_union(left, right);
        *self = next;
        status
    }

    /// Pure state-transition merge returning the updated union-find and status.
    pub(crate) fn into_union(
        self,
        left: &mneme_core::Value,
        right: &mneme_core::Value,
    ) -> (Self, UnionStatus) {
        if left == right {
            return (self, UnionStatus::Unchanged);
        }
        let Some((s1, id_left)) = self.into_intern(left) else {
            return (Self::default(), UnionStatus::Unchanged);
        };
        let Some((mut s2, id_right)) = s1.into_intern(right) else {
            return (Self::default(), UnionStatus::Unchanged);
        };
        let root_left = s2.find_root_id(id_left);
        let root_right = s2.find_root_id(id_right);
        s2 = s2.into_compress_path(id_left, root_left);
        s2 = s2.into_compress_path(id_right, root_right);
        if root_left == root_right {
            return (s2, UnionStatus::Unchanged);
        }
        let (winner, loser) = match (
            slot(root_left).and_then(|idx| s2.id_to_value.get(idx)),
            slot(root_right).and_then(|idx| s2.id_to_value.get(idx)),
        ) {
            (Some(val_left), Some(val_right)) if val_left <= val_right => (root_left, root_right),
            _ => (root_right, root_left),
        };
        if let Some(target) = slot(loser).and_then(|idx| s2.parent.get_mut(idx)) {
            *target = winner;
        }
        s2.union_count = s2.union_count.saturating_add(1);
        (s2, UnionStatus::Merged)
    }

    /// Whether `left` and `right` belong to the same equivalence class.
    pub fn are_equivalent(&self, left: &mneme_core::Value, right: &mneme_core::Value) -> bool {
        left == right || self.find_ref(left) == self.find_ref(right)
    }

    /// Flatten every parent pointer directly to its canonical root.
    pub fn into_compressed(mut self) -> Self {
        let count = self.parent.len();
        for index in 0..count {
            let Ok(id) = u32::try_from(index) else {
                break;
            };
            let root = self.find_root_id(id);
            if let Some(target) = self.parent.get_mut(index) {
                *target = root;
            }
        }
        self
    }

    /// Materialize all equivalence classes as `canonical_rep -> members`.
    pub fn classes(
        &self,
    ) -> std::collections::BTreeMap<mneme_core::Value, std::collections::BTreeSet<mneme_core::Value>>
    {
        let mut out: std::collections::BTreeMap<
            mneme_core::Value,
            std::collections::BTreeSet<mneme_core::Value>,
        > = std::collections::BTreeMap::new();
        for (index, value) in self.id_to_value.iter().enumerate() {
            let Ok(id) = u32::try_from(index) else {
                break;
            };
            let root = self.find_root_id(id);
            let rep = slot(root)
                .and_then(|idx| self.id_to_value.get(idx))
                .unwrap_or(value);
            out.entry(rep.clone()).or_default().insert(value.clone());
        }
        out
    }

    fn into_intern(mut self, value: &mneme_core::Value) -> Option<(Self, u32)> {
        if let Some(&id) = self.value_to_id.get(value) {
            return Some((self, id));
        }
        let next_id = u32::try_from(self.id_to_value.len()).ok()?;
        self.id_to_value.push(value.clone());
        self.parent.push(next_id);
        self.value_to_id.insert(value.clone(), next_id);
        self.node_count = self.node_count.saturating_add(1);
        Some((self, next_id))
    }

    fn find_root_id(&self, start: u32) -> u32 {
        let mut current = start;
        for _ in 0..self.parent.len() {
            let Some(&next) = slot(current).and_then(|idx| self.parent.get(idx)) else {
                break;
            };
            if next == current {
                return current;
            }
            current = next;
        }
        current
    }

    fn into_compress_path(mut self, start: u32, root: u32) -> Self {
        let mut current = start;
        for _ in 0..self.parent.len() {
            let Some(&next) = slot(current).and_then(|idx| self.parent.get(idx)) else {
                break;
            };
            if next == root {
                break;
            }
            if let Some(target) = slot(current).and_then(|idx| self.parent.get_mut(idx)) {
                *target = root;
            }
            current = next;
        }
        self
    }
}

/// Two-tier epistemic-stratified equivalence class table.
///
/// `accepted` holds ONLY `Accepted` equivalences and is never mutated by `Proposed`
/// unions. `proposed` overlays `accepted` with `Proposed` equivalences.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EClassTable {
    accepted: UnionFind,
    proposed: UnionFind,
    accepted_unions: u64,
    proposed_unions: u64,
    rebuild_rounds: u64,
    is_dirty: bool,
}

impl EClassTable {
    /// Construct an empty epistemic-stratified e-class table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge `left` and `right` at the given `epistemic` tier.
    ///
    /// - `Accepted` updates both the `accepted` base and the `proposed` overlay.
    /// - `Proposed` updates ONLY the `proposed` overlay (`accepted` is never mutated).
    /// - `Rejected` is a no-op.
    pub fn union(
        &mut self,
        left: &mneme_core::Value,
        right: &mneme_core::Value,
        epistemic: crate::EpistemicStatus,
    ) -> UnionStatus {
        let (next, status) = std::mem::take(self).into_union(left, right, epistemic);
        *self = next;
        status
    }

    pub(crate) fn into_union(
        mut self,
        left: &mneme_core::Value,
        right: &mneme_core::Value,
        epistemic: crate::EpistemicStatus,
    ) -> (Self, UnionStatus) {
        if epistemic == crate::EpistemicStatus::Rejected {
            return (self, UnionStatus::Unchanged);
        }
        if epistemic == crate::EpistemicStatus::Accepted {
            let (next_acc, acc_status) = self.accepted.into_union(left, right);
            let (next_prop, prop_status) = self.proposed.into_union(left, right);
            self.accepted = next_acc;
            self.proposed = next_prop;
            if acc_status == UnionStatus::Merged {
                self.accepted_unions = self.accepted_unions.saturating_add(1);
            }
            if acc_status == UnionStatus::Merged || prop_status == UnionStatus::Merged {
                self.is_dirty = true;
                return (self, UnionStatus::Merged);
            }
            return (self, UnionStatus::Unchanged);
        }
        let (next_prop, prop_status) = self.proposed.into_union(left, right);
        self.proposed = next_prop;
        if prop_status == UnionStatus::Merged {
            self.proposed_unions = self.proposed_unions.saturating_add(1);
            self.is_dirty = true;
        }
        (self, prop_status)
    }

    /// Canonical representative in the strict `Accepted` tier.
    pub fn find_accepted<'a>(&'a self, value: &'a mneme_core::Value) -> &'a mneme_core::Value {
        self.accepted.find_ref(value)
    }

    /// Canonical representative in the `Proposed` overlay tier (includes `Accepted` unions).
    pub fn find_proposed<'a>(&'a self, value: &'a mneme_core::Value) -> &'a mneme_core::Value {
        self.proposed.find_ref(value)
    }

    /// Canonicalize one value and report the epistemic status of the rewrite step.
    ///
    /// Returns `(rep, EpistemicStatus::Accepted)` iff `value` is equivalent to `rep`
    /// using exclusively `Accepted` unions (`find_accepted(value) == find_proposed(value)`).
    /// Otherwise returns `(rep, EpistemicStatus::Proposed)`.
    pub fn canonicalize_term<'a>(
        &'a self,
        value: &'a mneme_core::Value,
    ) -> (&'a mneme_core::Value, crate::EpistemicStatus) {
        let accepted_rep = self.accepted.find_ref(value);
        let proposed_rep = self.proposed.find_ref(value);
        let epistemic = if accepted_rep == proposed_rep {
            crate::EpistemicStatus::Accepted
        } else {
            crate::EpistemicStatus::Proposed
        };
        (proposed_rep, epistemic)
    }

    /// Canonicalize a tuple of values and combine the per-term epistemic tags via `join`.
    pub fn canonicalize_tuple(
        &self,
        terms: &[mneme_core::Value],
    ) -> (Vec<mneme_core::Value>, crate::EpistemicStatus) {
        let mut out = Vec::with_capacity(terms.len());
        let mut epistemic = crate::EpistemicStatus::Accepted;
        for term in terms {
            let (rep, term_epistemic) = self.canonicalize_term(term);
            out.push(rep.clone());
            epistemic = epistemic.join(term_epistemic);
        }
        (out, epistemic)
    }

    /// Whether `left` and `right` are equivalent using exclusively `Accepted` unions.
    pub fn are_equivalent_accepted(
        &self,
        left: &mneme_core::Value,
        right: &mneme_core::Value,
    ) -> bool {
        self.accepted.are_equivalent(left, right)
    }

    /// Whether `left` and `right` are equivalent in the `Proposed` overlay tier.
    pub fn are_equivalent_proposed(
        &self,
        left: &mneme_core::Value,
        right: &mneme_core::Value,
    ) -> bool {
        self.proposed.are_equivalent(left, right)
    }

    /// All equivalence classes in the strict `Accepted` tier.
    pub fn accepted_classes(
        &self,
    ) -> std::collections::BTreeMap<mneme_core::Value, std::collections::BTreeSet<mneme_core::Value>>
    {
        self.accepted.classes()
    }

    /// All equivalence classes in the `Proposed` overlay tier.
    pub fn proposed_classes(
        &self,
    ) -> std::collections::BTreeMap<mneme_core::Value, std::collections::BTreeSet<mneme_core::Value>>
    {
        self.proposed.classes()
    }

    /// Number of non-trivial unions applied in the `Accepted` tier.
    pub const fn accepted_unions(&self) -> u64 {
        self.accepted_unions
    }

    /// Number of non-trivial unions applied solely in the `Proposed` overlay tier.
    pub const fn proposed_unions(&self) -> u64 {
        self.proposed_unions
    }

    /// Total non-trivial unions applied across both tiers.
    pub const fn total_unions(&self) -> u64 {
        self.accepted_unions.saturating_add(self.proposed_unions)
    }

    /// Number of congruence-closure rebuild rounds executed.
    pub const fn rebuild_rounds(&self) -> u64 {
        self.rebuild_rounds
    }

    /// Whether no unions have been recorded in either tier.
    pub fn is_empty(&self) -> bool {
        self.accepted.is_empty() && self.proposed.is_empty()
    }

    /// Whether unions have been added since the last `rebuild`.
    pub const fn is_dirty(&self) -> bool {
        self.is_dirty
    }

    fn into_prepared_for_rebuild(mut self) -> Self {
        self.rebuild_rounds = self.rebuild_rounds.saturating_add(1);
        self.accepted = self.accepted.into_compressed();
        self.proposed = self.proposed.into_compressed();
        self.is_dirty = false;
        self
    }
}

/// Apply one monotone lattice join operator to two values.
pub fn lattice_join(
    op: LatticeOp,
    left: &mneme_core::Value,
    right: &mneme_core::Value,
) -> mneme_core::Value {
    if op == LatticeOp::Max {
        if crate::engine::compare_fact_values(crate::CompareOp::Gt, left, right) {
            left.clone()
        } else if crate::engine::compare_fact_values(crate::CompareOp::Lt, left, right) {
            right.clone()
        } else if left >= right {
            left.clone()
        } else {
            right.clone()
        }
    } else if op == LatticeOp::Min {
        if crate::engine::compare_fact_values(crate::CompareOp::Lt, left, right) {
            left.clone()
        } else if crate::engine::compare_fact_values(crate::CompareOp::Gt, left, right) {
            right.clone()
        } else if left <= right {
            left.clone()
        } else {
            right.clone()
        }
    } else {
        let merged = extend_set_elements(std::collections::BTreeSet::new(), left);
        let merged = extend_set_elements(merged, right);
        mneme_core::Value::set(merged)
    }
}

fn extend_set_elements(
    mut target: std::collections::BTreeSet<mneme_core::Value>,
    value: &mneme_core::Value,
) -> std::collections::BTreeSet<mneme_core::Value> {
    if let Some(items) = value.as_set() {
        for item in items {
            target.insert(item.clone());
        }
    } else {
        target.insert(value.clone());
    }
    target
}

/// Whether a rule bundle declares any e-graph union action or lattice merge head.
pub(crate) fn bundle_has_rules(bundle: &crate::RuleBundle) -> bool {
    bundle
        .rules
        .iter()
        .any(|rule| !rule.actions.is_empty() || rule.lattice_merge.is_some())
}

/// Collect validated per-predicate functional lattice merge specifications.
pub(crate) fn collect_lattice_specs(
    bundle: &crate::RuleBundle,
) -> std::collections::BTreeMap<String, LatticeMerge> {
    let mut specs = std::collections::BTreeMap::new();
    for rule in &bundle.rules {
        if specs.len() >= bundle.rules.len() {
            break;
        }
        if let Some(merge) = rule.lattice_merge {
            specs.insert(rule.head.predicate.clone(), merge);
        }
    }
    specs
}

/// Owned input for executing all actions for one matched binding.
pub(crate) struct ActionStepInput<'a> {
    pub eclasses: EClassTable,
    pub rule: &'a crate::Rule,
    pub binding: &'a crate::engine::Binding,
    pub epistemic: crate::EpistemicStatus,
    pub max_unions: u64,
    pub remaining_steps: u64,
}

/// Pure outcome of executing all actions for one matched binding.
pub(crate) struct ActionStepResult {
    pub eclasses: EClassTable,
    pub steps: u64,
    pub is_merged: bool,
    pub is_union_limit_hit: bool,
    pub is_budget_exhausted: bool,
}

/// Execute all e-graph actions attached to one rule for one matched binding
/// as a pure state transition over `eclasses`.
pub(crate) fn apply_rule_actions_step(input: ActionStepInput<'_>) -> ActionStepResult {
    let ActionStepInput {
        mut eclasses,
        rule,
        binding,
        epistemic,
        max_unions,
        remaining_steps,
    } = input;
    if !epistemic.is_active() {
        return ActionStepResult {
            eclasses,
            steps: 0,
            is_merged: false,
            is_union_limit_hit: false,
            is_budget_exhausted: false,
        };
    }
    let mut steps = 0_u64;
    let mut is_merged = false;
    let mut is_union_limit_hit = false;
    let mut is_budget_exhausted = false;
    for action in &rule.actions {
        let Action::Union { left, right } = action;
        if steps >= remaining_steps {
            is_budget_exhausted = true;
            break;
        }
        steps = steps.saturating_add(1);
        let Some(left_val) = crate::engine::term_value_crate(left, binding) else {
            continue;
        };
        let Some(right_val) = crate::engine::term_value_crate(right, binding) else {
            continue;
        };
        if !would_merge(&eclasses, &left_val, &right_val, epistemic) {
            continue;
        }
        if eclasses.total_unions() >= max_unions {
            is_union_limit_hit = true;
            break;
        }
        let (next_eclasses, status) = eclasses.into_union(&left_val, &right_val, epistemic);
        eclasses = next_eclasses;
        if status == UnionStatus::Merged {
            is_merged = true;
        }
    }
    ActionStepResult {
        eclasses,
        steps,
        is_merged,
        is_union_limit_hit,
        is_budget_exhausted,
    }
}

fn would_merge(
    eclasses: &EClassTable,
    left: &mneme_core::Value,
    right: &mneme_core::Value,
    epistemic: crate::EpistemicStatus,
) -> bool {
    if left == right || epistemic == crate::EpistemicStatus::Rejected {
        return false;
    }
    if epistemic == crate::EpistemicStatus::Accepted {
        !eclasses.are_equivalent_accepted(left, right)
            || !eclasses.are_equivalent_proposed(left, right)
    } else {
        !eclasses.are_equivalent_proposed(left, right)
    }
}

/// Result of running one congruence-closure rebuild pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RebuildOutcome {
    Clean,
    Unchanged,
    Changed,
    LimitReached,
}

/// Owned inputs for one pure congruence-closure rebuild pass.
pub(crate) struct RebuildInput<'a> {
    pub eclasses: EClassTable,
    pub facts: std::collections::BTreeMap<String, crate::engine::FactStore>,
    pub round_deltas: std::collections::BTreeMap<String, crate::engine::FactStore>,
    pub lattice_specs: &'a std::collections::BTreeMap<String, LatticeMerge>,
    pub stratum_rebuild_rounds: u64,
    pub max_rebuild_rounds: u64,
    pub max_supports: usize,
    pub max_intervals: u64,
    pub remaining_steps: u64,
}

/// Owned outputs from one pure congruence-closure rebuild pass.
pub(crate) struct RebuildOutput {
    pub eclasses: EClassTable,
    pub facts: std::collections::BTreeMap<String, crate::engine::FactStore>,
    pub round_deltas: std::collections::BTreeMap<String, crate::engine::FactStore>,
    pub stratum_rebuild_rounds: u64,
    pub stored_rows: u64,
    pub steps: u64,
    pub is_support_truncated: bool,
    pub is_timeout: bool,
    pub is_round_limit_hit: bool,
    pub outcome: RebuildOutcome,
}

/// Run metered congruence closure (`rebuild`) across materialized tables and
/// `FactTrie`s whenever new unions or lattice-headed rows arrived in a round.
pub(crate) fn rebuild_step(input: RebuildInput<'_>) -> RebuildOutput {
    let is_unions_dirty = input.eclasses.is_dirty();
    let is_lattice_dirty = input
        .round_deltas
        .keys()
        .any(|predicate| input.lattice_specs.contains_key(predicate));
    if !is_unions_dirty && !is_lattice_dirty {
        return passthrough_rebuild(input, RebuildOutcome::Clean, false);
    }
    if input.stratum_rebuild_rounds >= input.max_rebuild_rounds {
        return passthrough_rebuild(input, RebuildOutcome::LimitReached, true);
    }
    execute_rebuild_pass(input, is_unions_dirty)
}

fn passthrough_rebuild(
    input: RebuildInput<'_>,
    outcome: RebuildOutcome,
    is_round_limit_hit: bool,
) -> RebuildOutput {
    let stored_rows = count_stored_rows(&input.facts);
    RebuildOutput {
        eclasses: input.eclasses,
        facts: input.facts,
        round_deltas: input.round_deltas,
        stratum_rebuild_rounds: input.stratum_rebuild_rounds,
        stored_rows,
        steps: 0,
        is_support_truncated: false,
        is_timeout: false,
        is_round_limit_hit,
        outcome,
    }
}

fn execute_rebuild_pass(input: RebuildInput<'_>, is_unions_dirty: bool) -> RebuildOutput {
    let next_stratum_rounds = input.stratum_rebuild_rounds.saturating_add(1);
    let eclasses = input.eclasses.into_prepared_for_rebuild();
    let mut facts = input.facts;
    let mut round_deltas = input.round_deltas;
    let predicates: Vec<String> = facts.keys().cloned().collect();
    let mut is_any_changed = false;
    let mut steps = 0_u64;
    let mut is_support_truncated = false;
    let mut is_timeout = false;

    for predicate in predicates {
        let lattice = input.lattice_specs.get(&predicate).copied();
        if !is_unions_dirty && lattice.is_none() {
            continue;
        }
        let Some(store) = facts.remove(&predicate) else {
            continue;
        };
        let pred_result = rebuild_predicate_store(PredicateRebuildArgs {
            store,
            lattice,
            eclasses: &eclasses,
            max_supports: input.max_supports,
            max_intervals: input.max_intervals,
            remaining_steps: input.remaining_steps.saturating_sub(steps),
        });
        steps = steps.saturating_add(pred_result.steps);
        is_support_truncated = is_support_truncated || pred_result.is_support_truncated;
        if pred_result.is_changed {
            is_any_changed = true;
            round_deltas = record_predicate_deltas(
                round_deltas,
                &predicate,
                &pred_result.store,
                &pred_result.changed_keys,
            );
        }
        facts.insert(predicate, pred_result.store);
        if pred_result.is_timeout {
            is_timeout = true;
            break;
        }
    }

    let stored_rows = count_stored_rows(&facts);
    let outcome = if is_timeout {
        RebuildOutcome::LimitReached
    } else if is_any_changed {
        RebuildOutcome::Changed
    } else {
        RebuildOutcome::Unchanged
    };
    RebuildOutput {
        eclasses,
        facts,
        round_deltas,
        stratum_rebuild_rounds: next_stratum_rounds,
        stored_rows,
        steps,
        is_support_truncated,
        is_timeout,
        is_round_limit_hit: false,
        outcome,
    }
}

fn count_stored_rows(facts: &std::collections::BTreeMap<String, crate::engine::FactStore>) -> u64 {
    facts.values().fold(0_u64, |acc, store| {
        if let Ok(rows) = u64::try_from(store.rows.len()) {
            acc.saturating_add(rows)
        } else {
            acc
        }
    })
}

struct PredicateRebuildArgs<'a> {
    store: crate::engine::FactStore,
    lattice: Option<LatticeMerge>,
    eclasses: &'a EClassTable,
    max_supports: usize,
    max_intervals: u64,
    remaining_steps: u64,
}

struct PredicateRebuildResult {
    store: crate::engine::FactStore,
    changed_keys: std::collections::BTreeSet<crate::engine::FactKey>,
    steps: u64,
    is_changed: bool,
    is_support_truncated: bool,
    is_timeout: bool,
}

fn rebuild_predicate_store(args: PredicateRebuildArgs<'_>) -> PredicateRebuildResult {
    let PredicateRebuildArgs {
        mut store,
        lattice,
        eclasses,
        max_supports,
        max_intervals,
        remaining_steps,
    } = args;
    if store.rows.is_empty() {
        return PredicateRebuildResult {
            store,
            changed_keys: std::collections::BTreeSet::new(),
            steps: 0,
            is_changed: false,
            is_support_truncated: false,
            is_timeout: false,
        };
    }
    let old_rows = std::mem::take(&mut store.rows);
    let row_result = match lattice {
        None => rebuild_plain_rows(PlainRowsArgs {
            old_rows,
            eclasses,
            max_supports,
            max_intervals,
            remaining_steps,
        }),
        Some(spec) => rebuild_lattice_rows(LatticeRowsArgs {
            old_rows,
            spec,
            eclasses,
            max_supports,
            max_intervals,
            remaining_steps,
        }),
    };
    store.rows = row_result.rows;
    let mut steps = row_result.steps;
    let mut is_timeout = row_result.is_timeout;
    if row_result.is_changed {
        store.indexes.clear();
        if lattice.is_some() {
            store.tries.clear();
        } else if !is_timeout && !store.tries.is_empty() {
            let trie_budget = remaining_steps.saturating_sub(steps);
            let trie_result =
                recanonicalize_tries(std::mem::take(&mut store.tries), eclasses, trie_budget);
            store.tries = trie_result.tries;
            steps = steps.saturating_add(trie_result.steps);
            if !trie_result.is_ok {
                is_timeout = true;
            }
        }
    }
    PredicateRebuildResult {
        store,
        changed_keys: row_result.changed_keys,
        steps,
        is_changed: row_result.is_changed,
        is_support_truncated: row_result.is_support_truncated,
        is_timeout,
    }
}

type TrieMap = std::collections::BTreeMap<(usize, Vec<usize>), crate::freejoin::FactTrie>;

struct RecanonicalizedTries {
    tries: TrieMap,
    steps: u64,
    is_ok: bool,
}

fn recanonicalize_tries(
    tries: TrieMap,
    eclasses: &EClassTable,
    remaining_steps: u64,
) -> RecanonicalizedTries {
    let max_tries = tries.len();
    let mut rebuilt = std::collections::BTreeMap::new();
    let mut steps = 0_u64;
    let mut is_ok = true;
    for (key, trie) in tries {
        let left = remaining_steps.saturating_sub(steps);
        let (next_trie, trie_steps, is_done) =
            trie.into_recanonicalized(left, &|value| eclasses.find_proposed(value).clone());
        steps = steps.saturating_add(trie_steps);
        if rebuilt.len() < max_tries {
            rebuilt.insert(key, next_trie);
        }
        if !is_done {
            is_ok = false;
            break;
        }
    }
    RecanonicalizedTries {
        tries: rebuilt,
        steps,
        is_ok,
    }
}

fn record_predicate_deltas(
    mut round_deltas: std::collections::BTreeMap<String, crate::engine::FactStore>,
    predicate: &str,
    store: &crate::engine::FactStore,
    changed_keys: &std::collections::BTreeSet<crate::engine::FactKey>,
) -> std::collections::BTreeMap<String, crate::engine::FactStore> {
    if changed_keys.is_empty() {
        return round_deltas;
    }
    let delta_store = round_deltas.entry(predicate.to_owned()).or_default();
    for key in changed_keys {
        if let Some(data) = store.rows.get(key)
            && data.is_active()
        {
            delta_store.rows.insert(key.clone(), data.clone());
        }
    }
    round_deltas
}

struct PlainRowsArgs<'a> {
    old_rows: std::collections::BTreeMap<crate::engine::FactKey, crate::FactData>,
    eclasses: &'a EClassTable,
    max_supports: usize,
    max_intervals: u64,
    remaining_steps: u64,
}

struct RowsRebuildResult {
    rows: std::collections::BTreeMap<crate::engine::FactKey, crate::FactData>,
    changed_keys: std::collections::BTreeSet<crate::engine::FactKey>,
    steps: u64,
    is_changed: bool,
    is_support_truncated: bool,
    is_timeout: bool,
}

fn rebuild_plain_rows(args: PlainRowsArgs<'_>) -> RowsRebuildResult {
    let max_entries = args.old_rows.len();
    let mut state = RowsRebuildResult {
        rows: std::collections::BTreeMap::new(),
        changed_keys: std::collections::BTreeSet::new(),
        steps: 0,
        is_changed: false,
        is_support_truncated: false,
        is_timeout: false,
    };
    for (old_key, mut data) in args.old_rows {
        if state.steps >= args.remaining_steps {
            state.is_timeout = true;
            return state;
        }
        state.steps = state.steps.saturating_add(1);
        let (canon_key, canon_epistemic) = args.eclasses.canonicalize_tuple(&old_key);
        if canon_key != old_key {
            state.is_changed = true;
            if state.changed_keys.len() < max_entries {
                state.changed_keys.insert(canon_key.clone());
            }
        }
        if canon_epistemic == crate::EpistemicStatus::Proposed {
            data = demote_fact_data_to_proposed(data);
        }
        let bounds = MergeBounds {
            max_supports: args.max_supports,
            max_intervals: args.max_intervals,
            remaining_steps: args.remaining_steps.saturating_sub(state.steps),
        };
        state = insert_or_merge_plain(state, canon_key, data, max_entries, bounds);
        if state.is_timeout {
            return state;
        }
    }
    state
}

fn insert_or_merge_plain(
    mut state: RowsRebuildResult,
    canon_key: crate::engine::FactKey,
    data: crate::FactData,
    max_entries: usize,
    bounds: MergeBounds,
) -> RowsRebuildResult {
    if let Some(existing) = state.rows.remove(&canon_key) {
        state.is_changed = true;
        if state.changed_keys.len() < max_entries {
            state.changed_keys.insert(canon_key.clone());
        }
        let Some((merged, merge_steps, is_trunc)) = merge_fact_data(existing, data, bounds) else {
            state.is_timeout = true;
            return state;
        };
        state.steps = state.steps.saturating_add(merge_steps);
        state.is_support_truncated = state.is_support_truncated || is_trunc;
        state.rows.insert(canon_key, merged);
    } else if state.rows.len() < max_entries {
        state.rows.insert(canon_key, data);
    }
    state
}

struct LatticeRowsArgs<'a> {
    old_rows: std::collections::BTreeMap<crate::engine::FactKey, crate::FactData>,
    spec: LatticeMerge,
    eclasses: &'a EClassTable,
    max_supports: usize,
    max_intervals: u64,
    remaining_steps: u64,
}

fn rebuild_lattice_rows(args: LatticeRowsArgs<'_>) -> RowsRebuildResult {
    let Some(col) = slot(args.spec.column) else {
        return empty_rebuild_result(args.old_rows, false);
    };
    let max_entries = args.old_rows.len();
    let mut grouped = LatticeGroupingState {
        grouped: std::collections::BTreeMap::new(),
        moved_groups: std::collections::BTreeSet::new(),
        steps: 0,
        is_changed: false,
        is_support_truncated: false,
        is_timeout: false,
    };
    for (old_key, mut data) in args.old_rows {
        if grouped.steps >= args.remaining_steps {
            return empty_rebuild_result(std::collections::BTreeMap::new(), true);
        }
        grouped.steps = grouped.steps.saturating_add(1);
        let Some(lattice_val) = old_key.get(col).cloned() else {
            continue;
        };
        let (group_key, canon_epistemic, is_key_moved) =
            canonicalize_key_columns(&old_key, col, args.eclasses);
        if is_key_moved {
            grouped.is_changed = true;
            if grouped.moved_groups.len() < max_entries {
                grouped.moved_groups.insert(group_key.clone());
            }
        }
        if canon_epistemic == crate::EpistemicStatus::Proposed {
            data = demote_fact_data_to_proposed(data);
        }
        let bounds = MergeBounds {
            max_supports: args.max_supports,
            max_intervals: args.max_intervals,
            remaining_steps: args.remaining_steps.saturating_sub(grouped.steps),
        };
        grouped = insert_lattice_bucket(
            grouped,
            LatticeBucketItem {
                group_key,
                lattice_val,
                data,
                max_entries,
                bounds,
            },
        );
        if grouped.is_timeout {
            return empty_rebuild_result(std::collections::BTreeMap::new(), true);
        }
    }
    fold_lattice_groups(FoldLatticeArgs {
        grouped: grouped.grouped,
        spec: args.spec,
        moved_groups: grouped.moved_groups,
        is_changed: grouped.is_changed,
        is_support_truncated: grouped.is_support_truncated,
        steps: grouped.steps,
        max_supports: args.max_supports,
        max_intervals: args.max_intervals,
        remaining_steps: args.remaining_steps,
    })
}

fn empty_rebuild_result(
    rows: std::collections::BTreeMap<crate::engine::FactKey, crate::FactData>,
    is_timeout: bool,
) -> RowsRebuildResult {
    RowsRebuildResult {
        rows,
        changed_keys: std::collections::BTreeSet::new(),
        steps: 0,
        is_changed: false,
        is_support_truncated: false,
        is_timeout,
    }
}

struct LatticeGroupingState {
    grouped: std::collections::BTreeMap<
        crate::engine::FactKey,
        std::collections::BTreeMap<mneme_core::Value, crate::FactData>,
    >,
    moved_groups: std::collections::BTreeSet<crate::engine::FactKey>,
    steps: u64,
    is_changed: bool,
    is_support_truncated: bool,
    is_timeout: bool,
}

struct LatticeBucketItem {
    group_key: crate::engine::FactKey,
    lattice_val: mneme_core::Value,
    data: crate::FactData,
    max_entries: usize,
    bounds: MergeBounds,
}

fn insert_lattice_bucket(
    mut state: LatticeGroupingState,
    item: LatticeBucketItem,
) -> LatticeGroupingState {
    let LatticeBucketItem {
        group_key,
        lattice_val,
        data,
        max_entries,
        bounds,
    } = item;
    let bucket = state.grouped.entry(group_key.clone()).or_default();
    if let Some(existing) = bucket.remove(&lattice_val) {
        state.is_changed = true;
        if state.moved_groups.len() < max_entries {
            state.moved_groups.insert(group_key);
        }
        let Some((merged, merge_steps, is_trunc)) = merge_fact_data(existing, data, bounds) else {
            state.is_timeout = true;
            return state;
        };
        state.steps = state.steps.saturating_add(merge_steps);
        state.is_support_truncated = state.is_support_truncated || is_trunc;
        bucket.insert(lattice_val, merged);
    } else if bucket.len() < max_entries {
        bucket.insert(lattice_val, data);
    }
    state
}

fn canonicalize_key_columns(
    terms: &[mneme_core::Value],
    lattice_col: usize,
    eclasses: &EClassTable,
) -> (crate::engine::FactKey, crate::EpistemicStatus, bool) {
    let mut key = Vec::with_capacity(terms.len().saturating_sub(1));
    let mut epistemic = crate::EpistemicStatus::Accepted;
    let mut is_moved = false;
    for (index, term) in terms.iter().enumerate() {
        if index == lattice_col {
            continue;
        }
        let (rep, term_epistemic) = eclasses.canonicalize_term(term);
        if rep != term {
            is_moved = true;
        }
        key.push(rep.clone());
        epistemic = epistemic.join(term_epistemic);
    }
    (key, epistemic, is_moved)
}

struct FoldLatticeArgs {
    grouped: std::collections::BTreeMap<
        crate::engine::FactKey,
        std::collections::BTreeMap<mneme_core::Value, crate::FactData>,
    >,
    spec: LatticeMerge,
    moved_groups: std::collections::BTreeSet<crate::engine::FactKey>,
    is_changed: bool,
    is_support_truncated: bool,
    steps: u64,
    max_supports: usize,
    max_intervals: u64,
    remaining_steps: u64,
}

fn fold_lattice_groups(args: FoldLatticeArgs) -> RowsRebuildResult {
    let Some(col) = slot(args.spec.column) else {
        return empty_rebuild_result(std::collections::BTreeMap::new(), false);
    };
    let max_groups = args.grouped.len();
    let mut state = RowsRebuildResult {
        rows: std::collections::BTreeMap::new(),
        changed_keys: std::collections::BTreeSet::new(),
        steps: args.steps,
        is_changed: args.is_changed,
        is_support_truncated: args.is_support_truncated,
        is_timeout: false,
    };
    for (group_key, values_map) in args.grouped {
        let is_group_merged = values_map.len() > 1;
        if is_group_merged {
            state.is_changed = true;
        }
        let bounds = MergeBounds {
            max_supports: args.max_supports,
            max_intervals: args.max_intervals,
            remaining_steps: args.remaining_steps.saturating_sub(state.steps),
        };
        let Some((win_val, win_data, fold_steps, is_trunc)) =
            fold_one_lattice_group(args.spec.op, values_map, bounds)
        else {
            state.is_timeout = true;
            return state;
        };
        state.steps = state.steps.saturating_add(fold_steps);
        state.is_support_truncated = state.is_support_truncated || is_trunc;
        let full_key = reconstruct_full_key(&group_key, col, win_val);
        if (is_group_merged || args.moved_groups.contains(&group_key))
            && state.changed_keys.len() < max_groups
        {
            state.changed_keys.insert(full_key.clone());
        }
        if state.rows.len() < max_groups {
            state.rows.insert(full_key, win_data);
        }
    }
    state
}

fn fold_one_lattice_group(
    op: LatticeOp,
    values_map: std::collections::BTreeMap<mneme_core::Value, crate::FactData>,
    bounds: MergeBounds,
) -> Option<(mneme_core::Value, crate::FactData, u64, bool)> {
    let mut iter = values_map.into_iter();
    let (mut acc_val, mut acc_data) = iter.next()?;
    let mut steps = 0_u64;
    let mut is_truncated = false;
    for (next_val, next_data) in iter {
        if steps >= bounds.remaining_steps {
            return None;
        }
        steps = steps.saturating_add(1);
        let pair_bounds = MergeBounds {
            max_supports: bounds.max_supports,
            max_intervals: bounds.max_intervals,
            remaining_steps: bounds.remaining_steps.saturating_sub(steps),
        };
        let (joined_val, joined_data, merge_steps, is_trunc) =
            merge_lattice_pair(op, (acc_val, acc_data), (next_val, next_data), pair_bounds)?;
        steps = steps.saturating_add(merge_steps);
        is_truncated = is_truncated || is_trunc;
        acc_val = joined_val;
        acc_data = joined_data;
    }
    Some((acc_val, acc_data, steps, is_truncated))
}

fn reconstruct_full_key(
    group_key: &[mneme_core::Value],
    lattice_col: usize,
    lattice_val: mneme_core::Value,
) -> crate::engine::FactKey {
    let mut full = Vec::with_capacity(group_key.len().saturating_add(1));
    let mut group_iter = group_key.iter();
    for index in 0..=group_key.len() {
        if index == lattice_col {
            full.push(lattice_val.clone());
        } else if let Some(val) = group_iter.next() {
            full.push(val.clone());
        }
    }
    full
}

#[derive(Clone, Copy)]
struct MergeBounds {
    max_supports: usize,
    max_intervals: u64,
    remaining_steps: u64,
}

fn merge_lattice_pair(
    op: LatticeOp,
    left: (mneme_core::Value, crate::FactData),
    right: (mneme_core::Value, crate::FactData),
    bounds: MergeBounds,
) -> Option<(mneme_core::Value, crate::FactData, u64, bool)> {
    let (val_l, data_l) = left;
    let (val_r, data_r) = right;
    let joined = lattice_join(op, &val_l, &val_r);
    if joined == val_l && joined != val_r {
        return Some((joined, data_l, 0, false));
    }
    if joined == val_r && joined != val_l {
        return Some((joined, data_r, 0, false));
    }
    if joined == val_l && joined == val_r {
        let (merged, steps, is_trunc) = merge_fact_data(data_l, data_r, bounds)?;
        return Some((joined, merged, steps, is_trunc));
    }
    // Joined value genuinely combines both operands (e.g., SetUnion({a}, {b}) = {a, b}):
    // epistemic status MUST be their conjunction (`Accepted × Proposed = Proposed`).
    let combined_epistemic = data_l.epistemic.join(data_r.epistemic);
    let (mut merged, steps, is_trunc) = merge_fact_data(data_l, data_r, bounds)?;
    merged.epistemic = combined_epistemic;
    for support in &mut merged.supports {
        support.epistemic = support.epistemic.join(combined_epistemic);
    }
    Some((joined, merged, steps, is_trunc))
}

fn demote_fact_data_to_proposed(mut data: crate::FactData) -> crate::FactData {
    data.epistemic = data.epistemic.join(crate::EpistemicStatus::Proposed);
    for support in &mut data.supports {
        support.epistemic = support.epistemic.join(crate::EpistemicStatus::Proposed);
    }
    data
}

fn merge_fact_data(
    mut target: crate::FactData,
    incoming: crate::FactData,
    bounds: MergeBounds,
) -> Option<(crate::FactData, u64, bool)> {
    target.epistemic = target.epistemic.union(incoming.epistemic);
    let bounded = target.validity.union_bounded(
        &incoming.validity,
        bounds.max_intervals,
        bounds.remaining_steps,
    )?;
    let mut is_truncated = bounded.is_truncated || incoming.truncated;
    target.validity = bounded.validity;
    if is_truncated {
        target.truncated = true;
    }
    target.sources.extend(incoming.sources);
    target.canonical_roots.extend(incoming.canonical_roots);
    target.vaults.extend(incoming.vaults);
    if target.canonical != incoming.canonical {
        target.canonical = None;
    }
    for support in incoming.supports {
        if target.supports.contains(&support) {
            continue;
        }
        if target.supports.len() >= bounds.max_supports {
            target.truncated = true;
            is_truncated = true;
            break;
        }
        target.supports.push(support);
    }
    Some((target, bounded.steps, is_truncated))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rid(byte: u8) -> mneme_core::Value {
        mneme_core::RecordId::from_bytes([byte; 16]).to_value()
    }

    #[test]
    fn union_find_picks_smallest_rep_regardless_of_order() {
        let vals = [rid(1), rid(2), rid(3), rid(4), rid(5)];

        let mut forward = UnionFind::new();
        for pair in vals.windows(2) {
            assert_eq!(forward.union(&pair[0], &pair[1]), UnionStatus::Merged);
        }

        let mut reverse = UnionFind::new();
        for pair in vals.windows(2).rev() {
            assert_eq!(reverse.union(&pair[1], &pair[0]), UnionStatus::Merged);
        }

        let mut star = UnionFind::new();
        assert_eq!(star.union(&vals[4], &vals[2]), UnionStatus::Merged);
        assert_eq!(star.union(&vals[0], &vals[3]), UnionStatus::Merged);
        assert_eq!(star.union(&vals[1], &vals[4]), UnionStatus::Merged);
        assert_eq!(star.union(&vals[2], &vals[3]), UnionStatus::Merged);

        for val in &vals {
            assert_eq!(forward.find_ref(val), &vals[0]);
            assert_eq!(reverse.find_ref(val), &vals[0]);
            assert_eq!(star.find_ref(val), &vals[0]);
        }
        assert_eq!(forward, reverse);
        assert_eq!(forward, star);
    }

    #[test]
    fn eclass_table_strictly_separates_accepted_and_proposed_tiers() {
        let a = rid(1);
        let b = rid(2);
        let c = rid(3);
        let mut table = EClassTable::new();

        assert_eq!(
            table.union(&a, &b, crate::EpistemicStatus::Accepted),
            UnionStatus::Merged
        );
        assert!(table.are_equivalent_accepted(&a, &b));
        assert!(table.are_equivalent_proposed(&a, &b));
        assert_eq!(
            table.canonicalize_term(&b),
            (&a, crate::EpistemicStatus::Accepted)
        );

        assert_eq!(
            table.union(&b, &c, crate::EpistemicStatus::Proposed),
            UnionStatus::Merged
        );
        assert!(!table.are_equivalent_accepted(&a, &c));
        assert!(!table.are_equivalent_accepted(&b, &c));
        assert_eq!(table.find_accepted(&c), &c);
        assert!(table.are_equivalent_proposed(&a, &c));
        assert_eq!(table.find_proposed(&c), &a);
        assert_eq!(
            table.canonicalize_term(&c),
            (&a, crate::EpistemicStatus::Proposed)
        );
        assert_eq!(
            table.canonicalize_term(&b),
            (&a, crate::EpistemicStatus::Accepted)
        );
    }

    #[test]
    fn eclass_table_proposed_smaller_rep_demotes_accepted_member() {
        let smaller = rid(1);
        let larger = rid(2);
        let mut table = EClassTable::new();

        assert_eq!(
            table.union(&larger, &smaller, crate::EpistemicStatus::Proposed),
            UnionStatus::Merged
        );
        assert_eq!(table.find_accepted(&larger), &larger);
        assert_eq!(table.find_accepted(&smaller), &smaller);
        assert!(!table.are_equivalent_accepted(&larger, &smaller));
        assert_eq!(
            table.canonicalize_term(&larger),
            (&smaller, crate::EpistemicStatus::Proposed)
        );
        assert_eq!(
            table.canonicalize_term(&smaller),
            (&smaller, crate::EpistemicStatus::Accepted)
        );
    }

    #[test]
    fn lattice_join_operators_are_monotone_and_commutative() {
        let ten = mneme_core::Value::integer(10);
        let fifty = mneme_core::Value::integer(50);
        assert_eq!(lattice_join(LatticeOp::Max, &ten, &fifty), fifty);
        assert_eq!(lattice_join(LatticeOp::Max, &fifty, &ten), fifty);
        assert_eq!(lattice_join(LatticeOp::Min, &ten, &fifty), ten);
        assert_eq!(lattice_join(LatticeOp::Min, &fifty, &ten), ten);

        let s1 = mneme_core::Value::set([mneme_core::Value::symbol("alpha")]);
        let s2 = mneme_core::Value::set([mneme_core::Value::symbol("beta")]);
        let expected = mneme_core::Value::set([
            mneme_core::Value::symbol("alpha"),
            mneme_core::Value::symbol("beta"),
        ]);
        assert_eq!(lattice_join(LatticeOp::SetUnion, &s1, &s2), expected);
        assert_eq!(lattice_join(LatticeOp::SetUnion, &s2, &s1), expected);
    }

    #[test]
    fn fact_trie_recanonicalize_matches_fresh_canonical_trie_and_meters_budget() {
        let mut table = EClassTable::new();
        let a1 = rid(1);
        let a2 = rid(2);
        let b1 = rid(3);
        let b2 = rid(4);
        assert_eq!(
            table.union(&a1, &a2, crate::EpistemicStatus::Accepted),
            UnionStatus::Merged
        );
        assert_eq!(
            table.union(&b1, &b2, crate::EpistemicStatus::Proposed),
            UnionStatus::Merged
        );

        let cols = [0_usize, 1_usize];
        let tuples = vec![
            vec![a2.clone(), b2.clone()],
            vec![a1.clone(), b2.clone()],
            vec![a2.clone(), b1.clone()],
        ];
        let mut trie = crate::freejoin::FactTrie::default();
        for tuple in &tuples {
            trie.insert(tuple, &cols);
        }

        let (rebuilt, steps, is_ok) =
            trie.into_recanonicalized(100, &|v| table.find_proposed(v).clone());
        assert!(is_ok);
        assert!(steps > 0);

        let mut expected = crate::freejoin::FactTrie::default();
        expected.insert(&[a1.clone(), b1.clone()], &cols);
        assert_eq!(rebuilt, expected);

        let mut tiny_trie = crate::freejoin::FactTrie::default();
        tiny_trie.insert(&[a2, b2], &cols);
        let (_, _, is_tiny_ok) =
            tiny_trie.into_recanonicalized(1, &|v| table.find_proposed(v).clone());
        assert!(!is_tiny_ok);
    }
}
