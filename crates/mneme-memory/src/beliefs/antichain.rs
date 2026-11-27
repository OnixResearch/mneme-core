//! Bounded, deterministic `PosBool(X)` DNF absorption for minimal-support
//! antichains over assertion evidence and derivations.
//!
//! Every returned support set is a sorted `BTreeSet<RecordId>` of leaf root
//! supports such that no returned set is a subset of another (`S1 ⊄ S2`).
//! Removing any single root from a support set breaks that support path, and
//! hitting every set in the antichain is the exact minimal kernel incision.

/// Hard bound on the number of minimal support sets retained in one antichain.
pub const MAX_ANTICHAIN_SETS: u32 = 64;

/// Perform bounded, deterministic `PosBool(X)` DNF absorption over `sets`.
///
/// Empty sets are dropped, sets are ordered by `(len, elements)`, any superset
/// `S2` of an already-retained `S1` (`S1 ⊆ S2`) is discarded, and the output
/// is capped at `max_sets`. Returns `(antichain, is_truncated)`.
pub fn absorb_support_sets(
    sets: Vec<std::collections::BTreeSet<mneme_core::RecordId>>,
    max_sets: u32,
) -> (Vec<std::collections::BTreeSet<mneme_core::RecordId>>, bool) {
    let limit = u64::from(max_sets);
    let mut non_empty: Vec<std::collections::BTreeSet<mneme_core::RecordId>> =
        sets.into_iter().filter(|set| !set.is_empty()).collect();
    non_empty.sort_by(|left, right| left.len().cmp(&right.len()).then_with(|| left.cmp(right)));

    let mut minimal: Vec<std::collections::BTreeSet<mneme_core::RecordId>> =
        Vec::with_capacity(non_empty.len());
    let mut is_truncated = false;
    for candidate in non_empty {
        let is_subsumed = minimal
            .iter()
            .any(|existing| existing.is_subset(&candidate));
        if is_subsumed {
            continue;
        }
        if (minimal.len() as u64) >= limit {
            is_truncated = true;
            break;
        }
        minimal.push(candidate);
    }
    (minimal, is_truncated)
}

/// Conjoin two support families (`A ∧ B` in `PosBool(X)`) by pairwise set union
/// and immediate bounded absorption so intermediate blowup stays bounded.
fn conjoin_families(
    left: &[std::collections::BTreeSet<mneme_core::RecordId>],
    right: &[std::collections::BTreeSet<mneme_core::RecordId>],
    max_sets: u32,
) -> (Vec<std::collections::BTreeSet<mneme_core::RecordId>>, bool) {
    let limit = u64::from(max_sets);
    let max_raw = limit.saturating_mul(limit).max(limit);
    let cap = left.len().saturating_mul(right.len());
    let mut combined = Vec::with_capacity(cap);
    let mut is_product_truncated = false;
    for lhs in left {
        for rhs in right {
            if (combined.len() as u64) >= max_raw {
                is_product_truncated = true;
                break;
            }
            let mut merged = lhs.clone();
            merged.extend(rhs.iter().copied());
            combined.push(merged);
        }
        if is_product_truncated {
            break;
        }
    }
    let (absorbed, is_absorbed_truncated) = absorb_support_sets(combined, max_sets);
    (absorbed, is_product_truncated || is_absorbed_truncated)
}

type SupportSets = Vec<std::collections::BTreeSet<mneme_core::RecordId>>;
type DerivationIndex =
    std::collections::BTreeMap<mneme_core::RecordId, Vec<crate::model::DerivationView>>;

fn build_readable_derivation_index(
    view: &crate::beliefs::View,
    base: &mneme_core::ScopeId,
) -> DerivationIndex {
    let mut index: DerivationIndex = std::collections::BTreeMap::new();
    for envelope in view.all_envelopes() {
        if envelope.kind != mneme_core::RecordKind::Derivation {
            continue;
        }
        if let Ok(deriv) = crate::model::DerivationView::parse(envelope.clone())
            && view.content_readable_in(&deriv.record.scope, base)
        {
            index.entry(deriv.conclusion).or_default().push(deriv);
        }
    }
    index
}

fn is_derivation_structurally_valid(
    view: &crate::beliefs::View,
    derivation: &crate::model::DerivationView,
) -> bool {
    let is_withdrawn = view
        .suppression_for(&derivation.record)
        .is_some_and(|s| s.mode == mneme_store::SuppressionMode::Withdrawn);
    let is_complete = derivation.completeness == crate::model::COMPLETE_COMPLETENESS;
    let is_non_empty = !derivation.premises.is_empty();
    let is_rev_ok = view.derivation_revision_matches(derivation);
    !is_withdrawn && is_complete && is_non_empty && is_rev_ok
}

fn has_direct_eligible_evidence(
    view: &crate::beliefs::View,
    assertion: &crate::model::AssertionView,
    base: &mneme_core::ScopeId,
) -> bool {
    let mut ancestry =
        crate::beliefs::Ancestry::new(view, crate::beliefs::MAX_ANCESTRY_NODES, false);
    for evidence_id in &assertion.evidence {
        let Ok(ev) = view.evidence(*evidence_id) else {
            continue;
        };
        let is_matching_support = ev.assertion == assertion.record.record_id
            && matches!(ev.relation, crate::model::SupportRelation::Supports);
        if !is_matching_support {
            continue;
        }
        if !view.content_readable_in(&ev.record.scope, base) {
            continue;
        }
        if view.suppression_for(&ev.record).is_some() {
            continue;
        }
        let Ok(facts) = ancestry.evaluate(ev.record.record_id) else {
            continue;
        };
        let is_complete_and_eligible = facts.complete && facts.eligible;
        if !ancestry.exhausted && is_complete_and_eligible {
            return true;
        }
    }
    false
}

#[derive(Clone, Copy)]
enum SupportRole {
    Target,
    Premise,
}

fn is_assertion_supportable(
    view: &crate::beliefs::View,
    assertion: &crate::model::AssertionView,
    role: SupportRole,
) -> bool {
    let is_withdrawn = view
        .suppression_for(&assertion.record)
        .is_some_and(|s| s.mode == mneme_store::SuppressionMode::Withdrawn);
    let is_terminal = matches!(
        assertion.lifecycle,
        mneme_core::Lifecycle::Retracted | mneme_core::Lifecycle::Superseded
    );
    if is_withdrawn || is_terminal {
        return false;
    }
    if matches!(role, SupportRole::Target) {
        return true;
    }
    matches!(assertion.lifecycle, mneme_core::Lifecycle::Accepted)
        && view.accepted_decision(assertion).unwrap_or(false)
}

enum WalkStep {
    Enter(mneme_core::RecordId),
    Finish(mneme_core::RecordId),
}

struct SupportWalker<'v> {
    view: &'v crate::beliefs::View,
    base: mneme_core::ScopeId,
    target: mneme_core::RecordId,
    derivations: DerivationIndex,
    memo: std::collections::BTreeMap<mneme_core::RecordId, SupportSets>,
    active: std::collections::BTreeSet<mneme_core::RecordId>,
    stack: Vec<WalkStep>,
    visited: u64,
    limit: u64,
    max_sets: u32,
    is_truncated: bool,
}

impl<'v> SupportWalker<'v> {
    fn new(
        view: &'v crate::beliefs::View,
        base: mneme_core::ScopeId,
        target: mneme_core::RecordId,
        limit: u64,
        max_sets: u32,
    ) -> Self {
        let derivations = build_readable_derivation_index(view, &base);
        SupportWalker {
            view,
            base,
            target,
            derivations,
            memo: std::collections::BTreeMap::new(),
            active: std::collections::BTreeSet::new(),
            stack: vec![WalkStep::Enter(target)],
            visited: 0,
            limit,
            max_sets,
            is_truncated: false,
        }
    }

    fn compute(mut self) -> (SupportSets, bool) {
        while let Some(step) = self.stack.pop() {
            self = if let WalkStep::Enter(record_id) = step {
                self.enter(record_id)
            } else if let WalkStep::Finish(record_id) = step {
                self.finish(record_id)
            } else {
                self
            };
        }
        let result = self.memo.remove(&self.target).unwrap_or_default();
        (result, self.is_truncated)
    }

    fn enter(mut self, record_id: mneme_core::RecordId) -> Self {
        if self.memo.contains_key(&record_id) || self.active.contains(&record_id) {
            return self;
        }
        if self.visited >= self.limit {
            self.is_truncated = true;
            self.memo.insert(record_id, Vec::new());
            return self;
        }
        self.visited = self.visited.saturating_add(1);
        let Ok(envelope) = self.view.record(record_id) else {
            self.memo.insert(record_id, Vec::new());
            return self;
        };
        if !self.view.content_readable_in(&envelope.scope, &self.base) {
            self.memo.insert(record_id, Vec::new());
            return self;
        }
        match envelope.kind {
            mneme_core::RecordKind::Episode => {
                let is_withdrawn = self
                    .view
                    .suppression_for(envelope)
                    .is_some_and(|s| s.mode == mneme_store::SuppressionMode::Withdrawn);
                let sets = if is_withdrawn {
                    Vec::new()
                } else {
                    vec![std::collections::BTreeSet::from([record_id])]
                };
                self.memo.insert(record_id, sets);
                self
            }
            mneme_core::RecordKind::Assertion => self.enter_assertion(record_id, envelope),
            mneme_core::RecordKind::Entity
            | mneme_core::RecordKind::Relation
            | mneme_core::RecordKind::Document
            | mneme_core::RecordKind::SourceRevision
            | mneme_core::RecordKind::Evidence
            | mneme_core::RecordKind::Derivation
            | mneme_core::RecordKind::Checkpoint
            | mneme_core::RecordKind::Proposal
            | mneme_core::RecordKind::Decision
            | mneme_core::RecordKind::RetentionDirective
            | mneme_core::RecordKind::DocumentBinding
            | mneme_core::RecordKind::DocumentAnchor
            | mneme_core::RecordKind::Comment
            | mneme_core::RecordKind::RecognitionRun
            | mneme_core::RecordKind::RecognitionSegment => {
                self.memo.insert(record_id, Vec::new());
                self
            }
        }
    }

    fn enter_assertion(
        mut self,
        record_id: mneme_core::RecordId,
        envelope: &mneme_core::RecordEnvelope,
    ) -> Self {
        let Ok(assertion) = crate::model::AssertionView::parse(envelope.clone()) else {
            self.memo.insert(record_id, Vec::new());
            return self;
        };
        let role = if record_id == self.target {
            SupportRole::Target
        } else {
            SupportRole::Premise
        };
        if !is_assertion_supportable(self.view, &assertion, role) {
            self.memo.insert(record_id, Vec::new());
            return self;
        }
        let derivs = self
            .derivations
            .get(&record_id)
            .cloned()
            .unwrap_or_default();
        self.active.insert(record_id);
        self.stack.push(WalkStep::Finish(record_id));
        for deriv in &derivs {
            if !is_derivation_structurally_valid(self.view, deriv) {
                continue;
            }
            for &premise in deriv.premises.iter().rev() {
                let is_unseen =
                    !self.memo.contains_key(&premise) && !self.active.contains(&premise);
                if is_unseen && (self.stack.len() as u64) < self.limit {
                    self.stack.push(WalkStep::Enter(premise));
                }
            }
        }
        self
    }

    fn finish(mut self, record_id: mneme_core::RecordId) -> Self {
        self.active.remove(&record_id);
        let Ok(assertion) = self.view.assertion(record_id) else {
            self.memo.insert(record_id, Vec::new());
            return self;
        };
        let derivs = self
            .derivations
            .get(&record_id)
            .cloned()
            .unwrap_or_default();
        let mut all_sets: SupportSets = Vec::with_capacity(derivs.len().saturating_add(1));
        if has_direct_eligible_evidence(self.view, &assertion, &self.base) {
            all_sets.push(std::collections::BTreeSet::from([record_id]));
        }
        for deriv in &derivs {
            if !is_derivation_structurally_valid(self.view, deriv) {
                continue;
            }
            let (deriv_sets, is_trunc) = self.derivation_supports(deriv);
            if is_trunc {
                self.is_truncated = true;
            }
            all_sets.extend(deriv_sets);
        }
        let (absorbed, is_trunc) = absorb_support_sets(all_sets, self.max_sets);
        if is_trunc {
            self.is_truncated = true;
        }
        self.memo.insert(record_id, absorbed);
        self
    }

    fn derivation_supports(
        &self,
        derivation: &crate::model::DerivationView,
    ) -> (SupportSets, bool) {
        let mut current: Option<SupportSets> = None;
        let mut is_truncated = false;
        for premise in &derivation.premises {
            let Some(premise_sets) = self.memo.get(premise) else {
                return (Vec::new(), false);
            };
            if premise_sets.is_empty() {
                return (Vec::new(), false);
            }
            current = match current {
                None => Some(premise_sets.clone()),
                Some(acc) => {
                    let (next, is_step_trunc) = conjoin_families(&acc, premise_sets, self.max_sets);
                    if is_step_trunc {
                        is_truncated = true;
                    }
                    Some(next)
                }
            };
        }
        (current.unwrap_or_default(), is_truncated)
    }
}

/// Compute the bounded minimal-support antichain (`PosBool(X)` absorption) for
/// `assertion` over `view`.
pub(crate) fn compute_minimal_supports(
    view: &crate::beliefs::View,
    assertion: &crate::model::AssertionView,
    node_limit: u64,
    max_sets: u32,
) -> (SupportSets, bool) {
    let walker = SupportWalker::new(
        view,
        assertion.record.scope.clone(),
        assertion.record.record_id,
        node_limit,
        max_sets,
    );
    walker.compute()
}
