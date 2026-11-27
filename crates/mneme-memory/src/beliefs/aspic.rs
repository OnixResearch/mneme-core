//! ASPIC+ structured argumentation compilation and RootIdentity-partitioned
//! Subjective Logic opinion projection over a pinned `View`.
//!
//! All reasoning here is read-only and strictly preserves non-promotion:
//! a `Proposed` assertion is never promoted to `Accepted`.

const FALLBACK_RESCALE_DENOM: u128 = 1_000_000_000;
const ROUND_LIMIT_EXTRA: u64 = 1;
const MAX_GRAPH_NODES: usize = 1_000_000;

/// Read-only Subjective Logic binomial opinion projected from exact fixed-point
/// rational evidence counts `(r, s, w, a)`.
///
/// Simplex invariant guaranteed by `mneme_kernel::opinion::project`:
/// `b_num + d_num + u_num == denom`, `denom > 0`, and
/// `conflict_num == 2 * min(b_num, d_num) <= b_num + d_num < denom`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opinion {
    pub b_num: u128,
    pub d_num: u128,
    pub u_num: u128,
    pub denom: u128,
    pub conflict_num: u128,
    pub base_rate: u64,
}

impl Opinion {
    /// Exact vacuous opinion `(b = 0, d = 0, u = 1, a = 0.5, conflict = 0)`.
    pub fn vacuous() -> Self {
        Self::vacuous_with_base_rate(mneme_kernel::opinion::DEFAULT_BASE_RATE)
    }

    /// Exact vacuous opinion with an explicit base rate numerator in
    /// `[0, mneme_kernel::opinion::BASE_RATE_SCALE]`.
    pub fn vacuous_with_base_rate(base_rate: u64) -> Self {
        Self::from_evidence(mneme_kernel::opinion::vacuous(base_rate))
    }

    /// Construct from a verified kernel [`mneme_kernel::opinion::Projected`].
    pub fn from_projected(projected: mneme_kernel::opinion::Projected) -> Self {
        Opinion {
            b_num: projected.b_num,
            d_num: projected.d_num,
            u_num: projected.u_num,
            denom: projected.denom,
            conflict_num: projected.conflict_num,
            base_rate: projected.base_rate,
        }
    }

    /// Project an exact kernel [`mneme_kernel::opinion::Evidence`] onto the simplex,
    /// falling back to the vacuous opinion only if the input is invalid.
    pub fn from_evidence(evidence: mneme_kernel::opinion::Evidence) -> Self {
        match mneme_kernel::opinion::project(&evidence) {
            Some(projected) => Self::from_projected(projected),
            None => Opinion {
                b_num: 0,
                d_num: 0,
                u_num: mneme_kernel::opinion::PRIOR_WEIGHT,
                denom: mneme_kernel::opinion::PRIOR_WEIGHT,
                conflict_num: 0,
                base_rate: mneme_kernel::opinion::DEFAULT_BASE_RATE,
            },
        }
    }

    /// Belief mass `b = b_num / denom` in `[0, 1]`.
    pub fn b(&self) -> f64 {
        ratio_f64(self.b_num, self.denom)
    }

    /// Disbelief mass `d = d_num / denom` in `[0, 1]`.
    pub fn d(&self) -> f64 {
        ratio_f64(self.d_num, self.denom)
    }

    /// Uncertainty mass `u = u_num / denom` in `(0, 1]`.
    pub fn u(&self) -> f64 {
        ratio_f64(self.u_num, self.denom)
    }

    /// Base rate `a = base_rate / BASE_RATE_SCALE` in `[0, 1]`.
    pub fn a(&self) -> f64 {
        (self.base_rate as f64) / (mneme_kernel::opinion::BASE_RATE_SCALE as f64)
    }

    /// Internal dissonance / conflict `2 * min(b, d)` in `[0, 1)`.
    pub fn conflict(&self) -> f64 {
        ratio_f64(self.conflict_num, self.denom)
    }

    /// Projected probability expectation `E = b + a * u`.
    pub fn expected_probability(&self) -> f64 {
        self.b() + self.a() * self.u()
    }
}

/// Dung grounded-semantics label for an assertion or conflict group.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArgumentationStatus {
    /// Defended in Dung's unique grounded extension (`IN`).
    In,
    /// Neither defended nor decisively defeated (`UNDEC`).
    Undec,
    /// Defeated by at least one `IN` attacker (`OUT`).
    Out,
}

impl ArgumentationStatus {
    /// Stable lowercase wire label.
    pub fn name(self) -> &'static str {
        if matches!(self, ArgumentationStatus::In) {
            "in"
        } else if matches!(self, ArgumentationStatus::Undec) {
            "undec"
        } else {
            "out"
        }
    }

    /// Convert from the Lean-verified kernel label.
    pub fn from_kernel(label: mneme_kernel::argumentation::Label) -> Self {
        match label {
            mneme_kernel::argumentation::Label::In => ArgumentationStatus::In,
            mneme_kernel::argumentation::Label::Undec => ArgumentationStatus::Undec,
            mneme_kernel::argumentation::Label::Out => ArgumentationStatus::Out,
        }
    }
}

/// Classification of an ASPIC+ defeat edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DefeatKind {
    /// Incompatible `(subject, predicate)` assertion overlapping in `ValidTime`.
    Rebuttal,
    /// Active `SupportRelation::Challenges` evidence targeting an assertion or premise.
    Undercut,
    /// Retracted, superseded, suppressed, or withdrawn premise root.
    Undermine,
}

impl DefeatKind {
    /// Stable lowercase wire label.
    pub fn name(self) -> &'static str {
        if matches!(self, DefeatKind::Rebuttal) {
            "rebuttal"
        } else if matches!(self, DefeatKind::Undercut) {
            "undercut"
        } else {
            "undermine"
        }
    }
}

/// One active ASPIC+ defeat affecting an assertion or its supporting derivation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DefeatReason {
    pub kind: DefeatKind,
    pub attacker: mneme_core::RecordId,
    pub target: mneme_core::RecordId,
    pub is_symmetric: bool,
}

/// Grounded ASPIC+ argumentation verdict attached to an [`crate::Explanation`]
/// or [`crate::ConflictGroup`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArgumentationVerdict {
    pub status: ArgumentationStatus,
    pub defeats: Vec<DefeatReason>,
    pub rounds: u64,
    pub is_truncated: bool,
}

impl ArgumentationVerdict {
    /// Unchallenged `IN` verdict with no defeats.
    pub fn unchallenged() -> Self {
        ArgumentationVerdict {
            status: ArgumentationStatus::In,
            defeats: Vec::new(),
            rounds: 1,
            is_truncated: false,
        }
    }

    /// Undetermined `UNDEC` verdict with no recorded defeats.
    pub fn undetermined() -> Self {
        ArgumentationVerdict {
            status: ArgumentationStatus::Undec,
            defeats: Vec::new(),
            rounds: 0,
            is_truncated: false,
        }
    }
}

const fn ratio_f64(numerator: u128, denom: u128) -> f64 {
    if denom == 0 {
        0.0
    } else {
        (numerator as f64) / (denom as f64)
    }
}

const fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let rem = match a.checked_rem(b) {
            Some(r) => r,
            None => 0,
        };
        a = b;
        b = rem;
    }
    a
}

fn reduce_evidence(ev: mneme_kernel::opinion::Evidence) -> mneme_kernel::opinion::Evidence {
    let divisor = gcd_u128(ev.r, gcd_u128(ev.s, ev.w));
    if divisor > 1 {
        mneme_kernel::opinion::Evidence {
            r: ev.r.checked_div(divisor).unwrap_or(ev.r),
            s: ev.s.checked_div(divisor).unwrap_or(ev.s),
            w: ev.w.checked_div(divisor).unwrap_or(ev.w),
            base_rate: ev.base_rate,
        }
    } else {
        ev
    }
}

fn rescale_for_overflow(ev: mneme_kernel::opinion::Evidence) -> mneme_kernel::opinion::Evidence {
    if ev.w <= FALLBACK_RESCALE_DENOM {
        return ev;
    }
    let scale = ev.w.checked_div(FALLBACK_RESCALE_DENOM).unwrap_or(1);
    if scale <= 1 {
        return ev;
    }
    let new_w =
        ev.w.checked_div(scale)
            .unwrap_or(mneme_kernel::opinion::PRIOR_WEIGHT)
            .max(mneme_kernel::opinion::PRIOR_WEIGHT);
    mneme_kernel::opinion::Evidence {
        r: ev.r.checked_div(scale).unwrap_or(ev.r),
        s: ev.s.checked_div(scale).unwrap_or(ev.s),
        w: new_w,
        base_rate: ev.base_rate,
    }
}

type RootClusterMap = std::collections::BTreeMap<crate::beliefs::RootIdentity, (u64, u64)>;
type DerivationMap =
    std::collections::BTreeMap<mneme_core::RecordId, Vec<crate::model::DerivationView>>;
type ChallengeMap =
    std::collections::BTreeMap<mneme_core::RecordId, Vec<crate::model::EvidenceView>>;

/// Fuse a `RootIdentity`-partitioned count map using `averaging_cluster` (`◇`)
/// within each root and `cumulative_fuse` (`⊕`) across disjoint roots.
pub(crate) fn fuse_root_clusters(clusters: &RootClusterMap, base_rate: u64) -> Opinion {
    let mut acc = mneme_kernel::opinion::vacuous(base_rate);
    for &(supports, challenges) in clusters.values() {
        let cluster = mneme_kernel::opinion::averaging_cluster(supports, challenges, base_rate);
        let reduced = reduce_evidence(cluster);
        acc = match mneme_kernel::opinion::cumulative_fuse(&acc, &reduced) {
            Some(fused) => reduce_evidence(fused),
            None => {
                let left_scaled = rescale_for_overflow(acc);
                let right_scaled = rescale_for_overflow(reduced);
                mneme_kernel::opinion::cumulative_fuse(&left_scaled, &right_scaled)
                    .map(reduce_evidence)
                    .unwrap_or(left_scaled)
            }
        };
    }
    Opinion::from_evidence(acc)
}

fn collect_assertion_evidence(
    view: &crate::beliefs::View,
    assertion: &crate::model::AssertionView,
) -> Vec<crate::model::EvidenceView> {
    let mut seen: std::collections::BTreeSet<mneme_core::RecordId> =
        std::collections::BTreeSet::new();
    let mut out = Vec::with_capacity(assertion.evidence.len());
    for evidence_id in &assertion.evidence {
        if out.len() >= MAX_GRAPH_NODES || !seen.insert(*evidence_id) {
            continue;
        }
        if let Ok(evidence) = view.evidence(*evidence_id)
            && evidence.assertion == assertion.record.record_id
        {
            out.push(evidence);
        }
    }
    for envelope in view.all_envelopes() {
        if out.len() >= MAX_GRAPH_NODES {
            break;
        }
        if envelope.kind != mneme_core::RecordKind::Evidence || !seen.insert(envelope.record_id) {
            continue;
        }
        if let Ok(evidence) = crate::model::EvidenceView::parse(envelope.clone()) {
            let is_target_challenge = evidence.assertion == assertion.record.record_id
                && matches!(evidence.relation, crate::model::SupportRelation::Challenges);
            if is_target_challenge {
                out.push(evidence);
            }
        }
    }
    out
}

/// Collect `RootIdentity`-partitioned `(supports, challenges)` counts for one
/// assertion across eligible supporting evidence and readable challenging evidence.
pub(crate) fn assertion_opinion_clusters(
    view: &crate::beliefs::View,
    assertion: &crate::model::AssertionView,
) -> crate::failure::Result<(RootClusterMap, bool)> {
    let base = &assertion.record.scope;
    let mut ancestry =
        crate::beliefs::Ancestry::new(view, crate::beliefs::MAX_ANCESTRY_NODES, true);
    let mut clusters: RootClusterMap = std::collections::BTreeMap::new();
    let items = collect_assertion_evidence(view, assertion);

    for evidence in items {
        if !view.content_readable_in(&evidence.record.scope, base)
            || view.suppression_for(&evidence.record).is_some()
        {
            continue;
        }
        let facts = ancestry.evaluate(evidence.record.record_id)?;
        if !facts.complete || !facts.eligible {
            continue;
        }
        let (visible, _) = view.visible_roots(&facts.roots, base);
        let content_ids: Vec<crate::beliefs::RootIdentity> = visible
            .iter()
            .filter(|(identity, key)| view.is_content_root(identity, **key))
            .map(|(identity, _)| identity.clone())
            .collect();
        let chosen: Vec<crate::beliefs::RootIdentity> = if content_ids.is_empty() {
            visible.keys().cloned().collect()
        } else {
            content_ids
        };
        let is_support = matches!(evidence.relation, crate::model::SupportRelation::Supports);
        for identity in chosen {
            let entry = clusters.entry(identity).or_insert((0, 0));
            if is_support {
                entry.0 = entry.0.saturating_add(1);
            } else {
                entry.1 = entry.1.saturating_add(1);
            }
        }
    }

    Ok((clusters, ancestry.exhausted))
}

/// Compute the read-only Subjective Logic opinion for one assertion.
pub(crate) fn compute_assertion_opinion(
    view: &crate::beliefs::View,
    assertion: &crate::model::AssertionView,
) -> crate::failure::Result<Opinion> {
    let (clusters, _) = assertion_opinion_clusters(view, assertion)?;
    Ok(fuse_root_clusters(
        &clusters,
        mneme_kernel::opinion::DEFAULT_BASE_RATE,
    ))
}

/// Compute a combined conflict-group opinion: primary assertion supports vs
/// rival assertions' supports and challenging evidence, partitioned by `RootIdentity`.
pub(crate) fn compute_conflict_group_opinion(
    view: &crate::beliefs::View,
    assertions: &[crate::model::AssertionView],
) -> crate::failure::Result<Opinion> {
    let Some((primary, rivals)) = assertions.split_first() else {
        return Ok(Opinion::vacuous());
    };
    let (mut clusters, _) = assertion_opinion_clusters(view, primary)?;
    for rival in rivals {
        let (rival_clusters, _) = assertion_opinion_clusters(view, rival)?;
        for (identity, (rival_supports, _)) in rival_clusters {
            if rival_supports > 0 {
                let entry = clusters.entry(identity).or_insert((0, 0));
                entry.1 = entry.1.saturating_add(rival_supports);
            }
        }
    }
    Ok(fuse_root_clusters(
        &clusters,
        mneme_kernel::opinion::DEFAULT_BASE_RATE,
    ))
}

/// Whether two assertions on the same `(subject, predicate)` have incompatible
/// stance/value semantics.
pub(crate) fn assertions_incompatible(
    left: &crate::model::AssertionView,
    right: &crate::model::AssertionView,
) -> bool {
    if left.subject != right.subject || left.predicate != right.predicate {
        return false;
    }
    let is_left_affirm = matches!(left.stance, crate::model::Stance::Affirm);
    let is_right_affirm = matches!(right.stance, crate::model::Stance::Affirm);
    let is_left_deny = matches!(left.stance, crate::model::Stance::Deny);
    let is_right_deny = matches!(right.stance, crate::model::Stance::Deny);
    if (is_left_affirm && is_right_deny) || (is_left_deny && is_right_affirm) {
        true
    } else if is_left_affirm && is_right_affirm {
        left.value != right.value
    } else {
        false
    }
}

fn valid_times_overlap(left: mneme_core::ValidTime, right: mneme_core::ValidTime) -> bool {
    let left_v = crate::beliefs::valid_time_to_kernel(left);
    let right_v = crate::beliefs::valid_time_to_kernel(right);
    match (left_v, right_v) {
        (
            mneme_kernel::temporal::Validity::Known(left_p),
            mneme_kernel::temporal::Validity::Known(right_p),
        ) => mneme_kernel::temporal::intersect(left_p, right_p).is_some(),
        (mneme_kernel::temporal::Validity::Unknown, _)
        | (_, mneme_kernel::temporal::Validity::Unknown) => false,
    }
}

fn assertion_authority(
    view: &crate::beliefs::View,
    assertion: &crate::model::AssertionView,
) -> mneme_kernel::argumentation::Authority {
    let is_accepted = matches!(assertion.lifecycle, mneme_core::Lifecycle::Accepted)
        && view.accepted_decision(assertion).unwrap_or(false);
    if is_accepted {
        let is_resolution_winner = assertion
            .decision
            .and_then(|id| view.decision(id).ok())
            .is_some_and(|decision| !decision.related.is_empty());
        if is_resolution_winner {
            return mneme_kernel::argumentation::Authority::ConflictResolution;
        }
        return mneme_kernel::argumentation::Authority::Accepted;
    }
    let is_disputed = matches!(assertion.lifecycle, mneme_core::Lifecycle::Disputed)
        && view.lifecycle_decision_valid(assertion).unwrap_or(false);
    if is_disputed {
        mneme_kernel::argumentation::Authority::Accepted
    } else {
        mneme_kernel::argumentation::Authority::Proposed
    }
}

fn challenge_authority(
    view: &crate::beliefs::View,
    evidence: &crate::model::EvidenceView,
    target: &crate::model::AssertionView,
) -> mneme_kernel::argumentation::Authority {
    let base = &target.record.scope;
    for target_id in [target.record.record_id, evidence.record.record_id] {
        let Ok(decisions) = view.decisions_for(target_id) else {
            continue;
        };
        for decision in decisions {
            if !view.content_readable_in(&decision.record.scope, base) {
                continue;
            }
            let is_cr = matches!(
                decision.decision_kind,
                crate::model::DecisionKind::ConflictResolution
                    | crate::model::DecisionKind::Supersession
            );
            let is_cited_challenge = decision.target == evidence.record.record_id
                || decision.evidence.contains(&evidence.record.record_id)
                || decision.related.contains(&evidence.record.record_id);
            if is_cr && is_cited_challenge {
                return mneme_kernel::argumentation::Authority::ConflictResolution;
            }
        }
    }
    mneme_kernel::argumentation::Authority::Accepted
}

#[derive(Clone, Copy)]
struct ArgNode {
    record_id: mneme_core::RecordId,
    kind: DefeatKind,
}

struct DefeatGraph {
    nodes: Vec<ArgNode>,
    defeats: Vec<mneme_kernel::argumentation::DefeatEdge>,
    assertion_args: std::collections::BTreeMap<mneme_core::RecordId, Vec<usize>>,
    derivation_premises: Vec<(usize, Vec<mneme_core::RecordId>)>,
    is_truncated: bool,
}

impl DefeatGraph {
    fn new(is_truncated: bool) -> Self {
        DefeatGraph {
            nodes: Vec::new(),
            defeats: Vec::new(),
            assertion_args: std::collections::BTreeMap::new(),
            derivation_premises: Vec::new(),
            is_truncated,
        }
    }

    fn with_node(
        mut self,
        record_id: mneme_core::RecordId,
        kind: DefeatKind,
    ) -> (Self, Option<usize>) {
        if self.nodes.len() >= MAX_GRAPH_NODES {
            self.is_truncated = true;
            return (self, None);
        }
        let idx = self.nodes.len();
        self.nodes.push(ArgNode { record_id, kind });
        (self, Some(idx))
    }

    fn with_defeat(mut self, attacker: usize, target: usize) -> Self {
        let edge = mneme_kernel::argumentation::DefeatEdge { attacker, target };
        if self.defeats.len() < MAX_GRAPH_NODES && !self.defeats.contains(&edge) {
            self.defeats.push(edge);
        }
        self
    }

    fn with_propagated_derivations(mut self) -> Self {
        let max_passes = self.derivation_premises.len().saturating_add(1);
        let mut pass = 0_usize;
        while pass < max_passes {
            let new_edges = collect_propagated_edges(
                &self.derivation_premises,
                &self.assertion_args,
                &self.defeats,
            );
            if new_edges.is_empty() {
                break;
            }
            for edge in new_edges {
                if self.defeats.len() < MAX_GRAPH_NODES {
                    self.defeats.push(edge);
                }
            }
            pass = pass.saturating_add(1);
        }
        self
    }

    fn solve_grounded(&self) -> (Vec<mneme_kernel::argumentation::Label>, u64) {
        let count = self.nodes.len();
        let mut labels = vec![mneme_kernel::argumentation::Label::Undec; count];
        let mut next_labels = vec![mneme_kernel::argumentation::Label::Undec; count];
        let max_rounds = (count as u64).saturating_add(ROUND_LIMIT_EXTRA);
        let mut rounds: u64 = 0;
        while rounds < max_rounds {
            let mut is_changed = false;
            let mut idx = 0_usize;
            while idx < count {
                let updated = mneme_kernel::argumentation::next_label(idx, &self.defeats, &labels);
                if updated != labels[idx] {
                    is_changed = true;
                }
                next_labels[idx] = updated;
                idx = idx.saturating_add(1);
            }
            rounds = rounds.saturating_add(1);
            if !is_changed {
                break;
            }
            labels.copy_from_slice(&next_labels);
        }
        (labels, rounds)
    }

    fn verdict_for(
        &self,
        assertion_id: mneme_core::RecordId,
        labels: &[mneme_kernel::argumentation::Label],
        rounds: u64,
    ) -> ArgumentationVerdict {
        let Some(arg_indices) = self.assertion_args.get(&assertion_id) else {
            return ArgumentationVerdict::undetermined();
        };
        let Some((&first, rest)) = arg_indices.split_first() else {
            return ArgumentationVerdict::undetermined();
        };
        let mut combined = labels
            .get(first)
            .copied()
            .unwrap_or(mneme_kernel::argumentation::Label::Undec);
        for &idx in rest {
            let next = labels
                .get(idx)
                .copied()
                .unwrap_or(mneme_kernel::argumentation::Label::Undec);
            combined = mneme_kernel::argumentation::best_label(combined, next);
        }
        let mut defeats: Vec<DefeatReason> = Vec::new();
        for &arg_idx in arg_indices {
            for edge in &self.defeats {
                if edge.target != arg_idx || defeats.len() >= MAX_GRAPH_NODES {
                    continue;
                }
                let attacker_label = labels
                    .get(edge.attacker)
                    .copied()
                    .unwrap_or(mneme_kernel::argumentation::Label::Undec);
                if matches!(attacker_label, mneme_kernel::argumentation::Label::Out) {
                    continue;
                }
                let Some(attacker_node) = self.nodes.get(edge.attacker) else {
                    continue;
                };
                let is_symmetric = self
                    .defeats
                    .iter()
                    .any(|rev| rev.attacker == edge.target && rev.target == edge.attacker);
                let reason = DefeatReason {
                    kind: attacker_node.kind,
                    attacker: attacker_node.record_id,
                    target: assertion_id,
                    is_symmetric,
                };
                if !defeats.contains(&reason) {
                    defeats.push(reason);
                }
            }
        }
        defeats.sort();
        ArgumentationVerdict {
            status: ArgumentationStatus::from_kernel(combined),
            defeats,
            rounds,
            is_truncated: self.is_truncated,
        }
    }
}

fn collect_propagated_edges(
    derivation_premises: &[(usize, Vec<mneme_core::RecordId>)],
    assertion_args: &std::collections::BTreeMap<mneme_core::RecordId, Vec<usize>>,
    defeats: &[mneme_kernel::argumentation::DefeatEdge],
) -> Vec<mneme_kernel::argumentation::DefeatEdge> {
    let mut new_edges: Vec<mneme_kernel::argumentation::DefeatEdge> = Vec::new();
    for (deriv_idx, premises) in derivation_premises {
        for premise_id in premises {
            let Some(premise_args) = assertion_args.get(premise_id) else {
                continue;
            };
            let Some(&first_arg) = premise_args.first() else {
                continue;
            };
            for edge in defeats {
                if edge.target != first_arg || new_edges.len() >= MAX_GRAPH_NODES {
                    continue;
                }
                let is_shared = premise_args.iter().all(|&p_arg| {
                    defeats
                        .iter()
                        .any(|other| other.attacker == edge.attacker && other.target == p_arg)
                });
                if is_shared {
                    let prop = mneme_kernel::argumentation::DefeatEdge {
                        attacker: edge.attacker,
                        target: *deriv_idx,
                    };
                    if !defeats.contains(&prop) && !new_edges.contains(&prop) {
                        new_edges.push(prop);
                    }
                }
            }
        }
    }
    new_edges
}

fn index_derivations_and_challenges(
    view: &crate::beliefs::View,
) -> (
    DerivationMap,
    ChallengeMap,
    Vec<crate::model::AssertionView>,
) {
    let mut derivations: DerivationMap = std::collections::BTreeMap::new();
    let mut challenges: ChallengeMap = std::collections::BTreeMap::new();
    let mut assertions = Vec::new();

    for envelope in view.all_envelopes() {
        match envelope.kind {
            mneme_core::RecordKind::Derivation => {
                if let Ok(deriv) = crate::model::DerivationView::parse(envelope.clone()) {
                    derivations.entry(deriv.conclusion).or_default().push(deriv);
                }
            }
            mneme_core::RecordKind::Evidence => {
                if let Ok(ev) = crate::model::EvidenceView::parse(envelope.clone())
                    && matches!(ev.relation, crate::model::SupportRelation::Challenges)
                {
                    challenges.entry(ev.assertion).or_default().push(ev);
                }
            }
            mneme_core::RecordKind::Assertion => {
                if assertions.len() < MAX_GRAPH_NODES
                    && let Ok(assertion) = crate::model::AssertionView::parse(envelope.clone())
                {
                    assertions.push(assertion);
                }
            }
            mneme_core::RecordKind::Entity
            | mneme_core::RecordKind::Relation
            | mneme_core::RecordKind::Episode
            | mneme_core::RecordKind::Proposal
            | mneme_core::RecordKind::Decision
            | mneme_core::RecordKind::RetentionDirective
            | mneme_core::RecordKind::DocumentBinding
            | mneme_core::RecordKind::DocumentAnchor
            | mneme_core::RecordKind::SourceRevision
            | mneme_core::RecordKind::Document
            | mneme_core::RecordKind::Comment
            | mneme_core::RecordKind::Checkpoint
            | mneme_core::RecordKind::RecognitionRun
            | mneme_core::RecordKind::RecognitionSegment => {}
        }
    }
    (derivations, challenges, assertions)
}

fn is_assertion_undermined(
    view: &crate::beliefs::View,
    assertion: &crate::model::AssertionView,
    has_derivations: bool,
) -> bool {
    let is_terminal_lifecycle = matches!(
        assertion.lifecycle,
        mneme_core::Lifecycle::Retracted | mneme_core::Lifecycle::Superseded
    );
    if is_terminal_lifecycle
        || view.suppression_for(&assertion.record).is_some()
        || view.is_withdrawn(assertion.record.record_id)
    {
        return true;
    }
    let mut has_supporting_citation = false;
    let mut has_eligible_support = false;
    let mut ancestry =
        crate::beliefs::Ancestry::new(view, crate::beliefs::MAX_ANCESTRY_NODES, false);
    for evidence_id in &assertion.evidence {
        let Ok(ev) = view.evidence(*evidence_id) else {
            continue;
        };
        if ev.assertion != assertion.record.record_id
            || !matches!(ev.relation, crate::model::SupportRelation::Supports)
        {
            continue;
        }
        has_supporting_citation = true;
        if view.suppression_for(&ev.record).is_some() {
            continue;
        }
        if let Ok(facts) = ancestry.evaluate(ev.record.record_id)
            && facts.complete
            && facts.eligible
        {
            has_eligible_support = true;
        }
    }
    has_supporting_citation && !has_eligible_support && !has_derivations
}

fn is_challenge_undermined(
    view: &crate::beliefs::View,
    challenge: &crate::model::EvidenceView,
) -> bool {
    if view.suppression_for(&challenge.record).is_some()
        || view.is_withdrawn(challenge.record.record_id)
    {
        return true;
    }
    let mut ancestry =
        crate::beliefs::Ancestry::new(view, crate::beliefs::MAX_ANCESTRY_NODES, false);
    match ancestry.evaluate(challenge.record.record_id) {
        Ok(facts) => !facts.complete || !facts.eligible,
        Err(_) => true,
    }
}

fn is_rebuttal_eligible(assertion: &crate::model::AssertionView) -> bool {
    match assertion.lifecycle {
        mneme_core::Lifecycle::Accepted
        | mneme_core::Lifecycle::Disputed
        | mneme_core::Lifecycle::Proposed => true,
        mneme_core::Lifecycle::Retracted | mneme_core::Lifecycle::Superseded => false,
    }
}

fn is_rebuttal_neighbor(
    view: &crate::beliefs::View,
    current: &crate::model::AssertionView,
    other: &crate::model::AssertionView,
    eval_at: Option<mneme_core::Timestamp>,
) -> bool {
    let is_distinct_eligible =
        other.record.record_id != current.record.record_id && is_rebuttal_eligible(other);
    if !is_distinct_eligible
        || !view.content_readable_in(&other.record.scope, &current.record.scope)
    {
        return false;
    }
    let is_time_overlap = match eval_at {
        Some(at) => {
            crate::beliefs::View::valid_time_applies(current.valid_time, at)
                && crate::beliefs::View::valid_time_applies(other.valid_time, at)
        }
        None => valid_times_overlap(current.valid_time, other.valid_time),
    };
    is_time_overlap && assertions_incompatible(current, other)
}

fn collect_closure(
    view: &crate::beliefs::View,
    seeds: &[crate::model::AssertionView],
    all_assertions: &[crate::model::AssertionView],
    derivations: &DerivationMap,
    eval_at: Option<mneme_core::Timestamp>,
) -> (
    std::collections::BTreeMap<mneme_core::RecordId, crate::model::AssertionView>,
    bool,
) {
    let mut closure: std::collections::BTreeMap<mneme_core::RecordId, crate::model::AssertionView> =
        std::collections::BTreeMap::new();
    let mut queue: std::collections::VecDeque<mneme_core::RecordId> =
        std::collections::VecDeque::new();
    let mut is_truncated = false;
    let assertion_map: std::collections::BTreeMap<
        mneme_core::RecordId,
        &crate::model::AssertionView,
    > = all_assertions
        .iter()
        .map(|a| (a.record.record_id, a))
        .collect();

    for seed in seeds {
        if closure
            .insert(seed.record.record_id, seed.clone())
            .is_none()
        {
            queue.push_back(seed.record.record_id);
        }
    }

    while let Some(current_id) = queue.pop_front() {
        let Some(current) = closure.get(&current_id).cloned() else {
            continue;
        };
        if let Some(deriv_list) = derivations.get(&current_id) {
            for deriv in deriv_list {
                if !view.content_readable_in(&deriv.record.scope, &current.record.scope) {
                    continue;
                }
                for premise_id in &deriv.premises {
                    let Some(&premise) = assertion_map.get(premise_id) else {
                        continue;
                    };
                    if !view.content_readable_in(&premise.record.scope, &current.record.scope) {
                        continue;
                    }
                    if closure.len() >= MAX_GRAPH_NODES {
                        is_truncated = true;
                        break;
                    }
                    if closure.insert(*premise_id, premise.clone()).is_none() {
                        queue.push_back(*premise_id);
                    }
                }
            }
        }
        for other in all_assertions {
            if !is_rebuttal_neighbor(view, &current, other, eval_at) {
                continue;
            }
            if closure.len() >= MAX_GRAPH_NODES {
                is_truncated = true;
                break;
            }
            if closure
                .insert(other.record.record_id, other.clone())
                .is_none()
            {
                queue.push_back(other.record.record_id);
            }
        }
    }

    (closure, is_truncated)
}

type AuthorityMap =
    std::collections::BTreeMap<mneme_core::RecordId, mneme_kernel::argumentation::Authority>;
type ClosureMap = std::collections::BTreeMap<mneme_core::RecordId, crate::model::AssertionView>;

fn build_assertion_nodes(
    view: &crate::beliefs::View,
    closure: &ClosureMap,
    derivations: &DerivationMap,
    is_truncated: bool,
) -> (DefeatGraph, AuthorityMap) {
    let mut graph = DefeatGraph::new(is_truncated);
    let authorities: AuthorityMap = closure
        .iter()
        .map(|(id, assertion)| (*id, assertion_authority(view, assertion)))
        .collect();

    for (id, assertion) in closure {
        let deriv_list = derivations.get(id).map(Vec::as_slice).unwrap_or(&[]);
        let readable_derivs: Vec<&crate::model::DerivationView> = deriv_list
            .iter()
            .filter(|d| view.content_readable_in(&d.record.scope, &assertion.record.scope))
            .collect();
        let has_direct_support = assertion.evidence.iter().any(|ev_id| {
            view.evidence(*ev_id).is_ok_and(|ev| {
                ev.assertion == *id
                    && matches!(ev.relation, crate::model::SupportRelation::Supports)
            })
        });
        if readable_derivs.is_empty() || has_direct_support {
            let (next_graph, base_opt) = graph.with_node(*id, DefeatKind::Rebuttal);
            graph = next_graph;
            if let Some(base_idx) = base_opt {
                graph.assertion_args.entry(*id).or_default().push(base_idx);
            }
        }
        for deriv in &readable_derivs {
            let (next_graph, deriv_opt) = graph.with_node(*id, DefeatKind::Rebuttal);
            graph = next_graph;
            let Some(deriv_idx) = deriv_opt else {
                continue;
            };
            graph.assertion_args.entry(*id).or_default().push(deriv_idx);
            if graph.derivation_premises.len() < MAX_GRAPH_NODES {
                graph
                    .derivation_premises
                    .push((deriv_idx, deriv.premises.iter().copied().collect()));
            }
            let is_deriv_bad = view.suppression_for(&deriv.record).is_some()
                || deriv.completeness != "complete"
                || deriv.premises.is_empty()
                || !view.derivation_revision_matches(deriv);
            if is_deriv_bad {
                let (next_g, u_opt) =
                    graph.with_node(deriv.record.record_id, DefeatKind::Undermine);
                graph = next_g;
                if let Some(u_idx) = u_opt {
                    graph = graph.with_defeat(u_idx, deriv_idx);
                }
            }
        }
        if is_assertion_undermined(view, assertion, !readable_derivs.is_empty()) {
            let (next_g, u_opt) = graph.with_node(*id, DefeatKind::Undermine);
            graph = next_g;
            if let Some(u_idx) = u_opt {
                let target_args = graph.assertion_args.get(id).cloned().unwrap_or_default();
                for target_idx in target_args {
                    graph = graph.with_defeat(u_idx, target_idx);
                }
            }
        }
    }
    (graph, authorities)
}

fn wire_challenge_defeats(
    view: &crate::beliefs::View,
    closure: &ClosureMap,
    challenges: &ChallengeMap,
    authorities: &AuthorityMap,
    mut graph: DefeatGraph,
) -> DefeatGraph {
    for (id, assertion) in closure {
        let Some(challenge_list) = challenges.get(id) else {
            continue;
        };
        let target_auth = authorities
            .get(id)
            .copied()
            .unwrap_or(mneme_kernel::argumentation::Authority::Proposed);
        let target_args = graph.assertion_args.get(id).cloned().unwrap_or_default();
        for challenge in challenge_list {
            if !view.content_readable_in(&challenge.record.scope, &assertion.record.scope) {
                continue;
            }
            let (next_g, ch_opt) =
                graph.with_node(challenge.record.record_id, DefeatKind::Undercut);
            graph = next_g;
            let Some(ch_idx) = ch_opt else {
                continue;
            };
            if is_challenge_undermined(view, challenge) {
                let (next_g2, u_opt) =
                    graph.with_node(challenge.record.record_id, DefeatKind::Undermine);
                graph = next_g2;
                if let Some(u_idx) = u_opt {
                    graph = graph.with_defeat(u_idx, ch_idx);
                }
            }
            let ch_auth = challenge_authority(view, challenge, assertion);
            let is_target_defends =
                mneme_kernel::argumentation::preference_defeats(target_auth, ch_auth);
            for &target_idx in &target_args {
                graph = graph.with_defeat(ch_idx, target_idx);
                if is_target_defends {
                    graph = graph.with_defeat(target_idx, ch_idx);
                }
            }
        }
    }
    graph
}

fn wire_rebuttal_defeats(
    closure: &ClosureMap,
    authorities: &AuthorityMap,
    eval_at: Option<mneme_core::Timestamp>,
    mut graph: DefeatGraph,
) -> DefeatGraph {
    let closure_vec: Vec<&crate::model::AssertionView> = closure.values().collect();
    for (i, left) in closure_vec.iter().enumerate() {
        for right in closure_vec.iter().skip(i.saturating_add(1)) {
            if !assertions_incompatible(left, right) {
                continue;
            }
            let is_time_overlap = match eval_at {
                Some(at) => {
                    crate::beliefs::View::valid_time_applies(left.valid_time, at)
                        && crate::beliefs::View::valid_time_applies(right.valid_time, at)
                }
                None => valid_times_overlap(left.valid_time, right.valid_time),
            };
            if !is_time_overlap {
                continue;
            }
            let left_auth = authorities
                .get(&left.record.record_id)
                .copied()
                .unwrap_or(mneme_kernel::argumentation::Authority::Proposed);
            let right_auth = authorities
                .get(&right.record.record_id)
                .copied()
                .unwrap_or(mneme_kernel::argumentation::Authority::Proposed);
            let left_args = graph
                .assertion_args
                .get(&left.record.record_id)
                .cloned()
                .unwrap_or_default();
            let right_args = graph
                .assertion_args
                .get(&right.record.record_id)
                .cloned()
                .unwrap_or_default();
            if mneme_kernel::argumentation::preference_defeats(left_auth, right_auth) {
                for &la in &left_args {
                    for &ra in &right_args {
                        graph = graph.with_defeat(la, ra);
                    }
                }
            }
            if mneme_kernel::argumentation::preference_defeats(right_auth, left_auth) {
                for &ra in &right_args {
                    for &la in &left_args {
                        graph = graph.with_defeat(ra, la);
                    }
                }
            }
        }
    }
    graph
}

fn compile_defeat_graph(
    view: &crate::beliefs::View,
    seeds: &[crate::model::AssertionView],
    eval_at: Option<mneme_core::Timestamp>,
) -> DefeatGraph {
    let (derivations, challenges, all_assertions) = index_derivations_and_challenges(view);
    let (closure, is_closure_truncated) =
        collect_closure(view, seeds, &all_assertions, &derivations, eval_at);
    let (graph, authorities) =
        build_assertion_nodes(view, &closure, &derivations, is_closure_truncated);
    let graph = wire_challenge_defeats(view, &closure, &challenges, &authorities, graph);
    let graph = wire_rebuttal_defeats(&closure, &authorities, eval_at, graph);
    graph.with_propagated_derivations()
}

/// Evaluate the Dung grounded ASPIC+ verdict for a single assertion (used by `Explanation`).
pub(crate) fn evaluate_assertion_verdict(
    view: &crate::beliefs::View,
    assertion: &crate::model::AssertionView,
) -> ArgumentationVerdict {
    let graph = compile_defeat_graph(view, std::slice::from_ref(assertion), None);
    let (labels, rounds) = graph.solve_grounded();
    graph.verdict_for(assertion.record.record_id, &labels, rounds)
}

/// Evaluate the Dung grounded ASPIC+ verdicts for a set of assertions at an
/// instant `at` (used by `View::conflicts`).
pub(crate) fn evaluate_assertions_at(
    view: &crate::beliefs::View,
    assertions: &[crate::model::AssertionView],
    at: mneme_core::Timestamp,
) -> std::collections::BTreeMap<mneme_core::RecordId, ArgumentationVerdict> {
    if assertions.is_empty() {
        return std::collections::BTreeMap::new();
    }
    let graph = compile_defeat_graph(view, assertions, Some(at));
    let (labels, rounds) = graph.solve_grounded();
    assertions
        .iter()
        .map(|assertion| {
            (
                assertion.record.record_id,
                graph.verdict_for(assertion.record.record_id, &labels, rounds),
            )
        })
        .collect()
}

/// Summarize one `ConflictGroup`'s per-assertion verdicts into a single group verdict.
pub(crate) fn summarize_conflict_group_verdict(
    assertions: &[crate::model::AssertionView],
    verdicts: &std::collections::BTreeMap<mneme_core::RecordId, ArgumentationVerdict>,
) -> ArgumentationVerdict {
    let mut best = mneme_kernel::argumentation::Label::Out;
    let mut has_any = false;
    let mut defeats: Vec<DefeatReason> = Vec::new();
    let mut rounds: u64 = 0;
    let mut is_truncated = false;
    for assertion in assertions {
        let Some(verdict) = verdicts.get(&assertion.record.record_id) else {
            continue;
        };
        let kernel_label = if matches!(verdict.status, ArgumentationStatus::In) {
            mneme_kernel::argumentation::Label::In
        } else if matches!(verdict.status, ArgumentationStatus::Undec) {
            mneme_kernel::argumentation::Label::Undec
        } else {
            mneme_kernel::argumentation::Label::Out
        };
        if has_any {
            best = mneme_kernel::argumentation::best_label(best, kernel_label);
        } else {
            best = kernel_label;
            has_any = true;
        }
        rounds = rounds.max(verdict.rounds);
        is_truncated = is_truncated || verdict.is_truncated;
        for reason in &verdict.defeats {
            if defeats.len() < MAX_GRAPH_NODES && !defeats.contains(reason) {
                defeats.push(reason.clone());
            }
        }
    }
    defeats.sort();
    if !has_any {
        return ArgumentationVerdict::undetermined();
    }
    ArgumentationVerdict {
        status: ArgumentationStatus::from_kernel(best),
        defeats,
        rounds,
        is_truncated,
    }
}
