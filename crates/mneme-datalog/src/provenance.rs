//! Epistemic provenance semiring and bounded Why-Not (`explain_missing`) engine.
//!
//! Epistemic provenance forms a commutative idempotent semiring
//! `(EpistemicStatus, +, ×, Rejected, Accepted)` following Green, Karvounarakis,
//! and Tannen (PODS 2007):
//! - `join` (`×`) combines premises within one derivation by taking the weakest
//!   premise (`min`), enforcing non-promotion by construction
//!   (`Accepted × Proposed = Proposed`, `Rejected × Accepted = Rejected`).
//! - `union` (`+`) combines independent derivations of the same tuple by taking
//!   the strongest derivation (`max`, `Proposed + Accepted = Accepted`).

type Binding = std::collections::BTreeMap<String, mneme_core::Value>;
type GoalKey = (String, Vec<mneme_core::Value>);

/// Epistemic provenance semiring element (`Accepted > Proposed > Rejected`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EpistemicStatus {
    Rejected,
    Proposed,
    Accepted,
}

impl EpistemicStatus {
    /// Additive identity and multiplicative annihilator (`0 = Rejected`).
    pub const ZERO: Self = Self::Rejected;
    /// Multiplicative identity (`1 = Accepted`).
    pub const ONE: Self = Self::Accepted;

    /// Convert to the formally verified kernel epistemic status.
    pub const fn to_kernel(self) -> mneme_kernel::epistemic::EpistemicStatus {
        if matches!(self, Self::Accepted) {
            mneme_kernel::epistemic::EpistemicStatus::Accepted
        } else if matches!(self, Self::Proposed) {
            mneme_kernel::epistemic::EpistemicStatus::Proposed
        } else {
            mneme_kernel::epistemic::EpistemicStatus::Rejected
        }
    }

    /// Construct from the formally verified kernel epistemic status.
    pub const fn from_kernel(status: mneme_kernel::epistemic::EpistemicStatus) -> Self {
        match status {
            mneme_kernel::epistemic::EpistemicStatus::Rejected => Self::Rejected,
            mneme_kernel::epistemic::EpistemicStatus::Proposed => Self::Proposed,
            mneme_kernel::epistemic::EpistemicStatus::Accepted => Self::Accepted,
        }
    }

    /// Semiring multiplication (`×`): conjunction over rule premises.
    pub fn join(self, other: Self) -> Self {
        Self::from_kernel(mneme_kernel::epistemic::join(
            self.to_kernel(),
            other.to_kernel(),
        ))
    }

    /// Semiring addition (`+`): disjunction over independent derivations.
    pub fn union(self, other: Self) -> Self {
        Self::from_kernel(mneme_kernel::epistemic::union(
            self.to_kernel(),
            other.to_kernel(),
        ))
    }

    /// Whether a fact with this epistemic status is active (not `ZERO` / `Rejected`).
    pub fn is_active(self) -> bool {
        mneme_kernel::epistemic::is_active(self.to_kernel())
    }

    /// Whether a fact with this epistemic status blocks a strict negated literal (`strict_not p(...)`).
    pub fn negation_blocks(self) -> bool {
        mneme_kernel::epistemic::negation_blocks(self.to_kernel())
    }

    /// Kleene three-valued epistemic negation:
    /// `¬Accepted = Rejected`, `¬Proposed = Proposed`, `¬Rejected = Accepted`.
    pub fn negate(self) -> Self {
        Self::from_kernel(mneme_kernel::epistemic::negate(self.to_kernel()))
    }

    /// Strict classical epistemic negation:
    /// `¬Accepted = Rejected`, `¬Proposed = Rejected`, `¬Rejected = Accepted`.
    pub fn strict_negate(self) -> Self {
        Self::from_kernel(mneme_kernel::epistemic::strict_negate(self.to_kernel()))
    }

    /// Whether a fact with this epistemic status blocks a Kleene three-valued negated literal.
    pub fn kleene_negation_blocks(self) -> bool {
        mneme_kernel::epistemic::kleene_negation_blocks(self.to_kernel())
    }

    /// Stable lower-case symbol name.
    pub const fn name(self) -> &'static str {
        const NAMES: [&str; 3] = ["rejected", "proposed", "accepted"];
        NAMES[self as usize]
    }

    /// Parse a declared epistemic status symbol or text value.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "accepted" => Some(Self::Accepted),
            "proposed" => Some(Self::Proposed),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }
}

impl std::fmt::Display for EpistemicStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::ops::Add for EpistemicStatus {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.union(rhs)
    }
}

impl std::ops::Mul for EpistemicStatus {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.join(rhs)
    }
}

fn status_property(record: &mneme_core::RecordEnvelope) -> Option<&mneme_core::Value> {
    let properties = record
        .payload
        .get("properties")
        .and_then(mneme_core::Value::as_dictionary)?;
    properties
        .get(&mneme_core::Value::symbol("status"))
        .or_else(|| properties.get(&mneme_core::Value::string("status")))
}

/// Extract epistemic status from a canonical record's `properties.status` field,
/// defaulting to [`EpistemicStatus::Accepted`] when no epistemic status property is set.
pub(crate) fn record_epistemic_status(record: &mneme_core::RecordEnvelope) -> EpistemicStatus {
    status_property(record)
        .and_then(|value| {
            value
                .as_symbol()
                .map(mneme_core::Symbol::as_str)
                .or_else(|| value.as_string())
        })
        .and_then(EpistemicStatus::parse)
        .unwrap_or(EpistemicStatus::Accepted)
}

/// Bounds for one read-only `explain_missing` Why-Not traversal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplainLimits {
    pub max_work: u64,
    pub max_depth: u32,
    pub max_reasons: u32,
}

impl Default for ExplainLimits {
    fn default() -> Self {
        Self {
            max_work: 10_000,
            max_depth: 16,
            max_reasons: 64,
        }
    }
}

/// Request to explain why a ground atom was not derived in a build.
#[derive(Clone, Debug)]
pub struct ExplainMissingRequest {
    pub predicate: String,
    pub terms: Vec<mneme_core::Value>,
    pub limits: ExplainLimits,
    pub allow_stale: bool,
    pub cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl ExplainMissingRequest {
    /// Construct a request for a ground atom with default explanation limits.
    pub fn ground(predicate: impl Into<String>, terms: Vec<mneme_core::Value>) -> Self {
        Self {
            predicate: predicate.into(),
            terms,
            limits: ExplainLimits::default(),
            allow_stale: false,
            cancellation: None,
        }
    }
}

/// Top-level outcome of a Why-Not explanation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MissingStatus {
    /// The target ground atom is actually derived/present in the build.
    Present,
    /// All candidate rules were evaluated and at least one blocking reason was found.
    Missing,
    /// The underlying build or explanation traversal hit a budget or coverage cutoff.
    BudgetCutoff,
}

impl MissingStatus {
    /// Stable lower-case name.
    pub const fn name(self) -> &'static str {
        const NAMES: [&str; 3] = ["present", "missing", "budget_cutoff"];
        NAMES[self as usize]
    }
}

/// Specific category of a Why-Not explanation cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MissingReasonKind {
    MissingBaseFact,
    MissingDerivedFact,
    MissingExistentialMatch,
    BlockingNegation,
    UnmetConstraint,
    HeadMismatch,
    NoDefiningRules,
    BudgetCutoff,
    Cycle,
}

impl MissingReasonKind {
    /// Stable lower-case snake name.
    pub const fn name(self) -> &'static str {
        const NAMES: [&str; 9] = [
            "missing_base_fact",
            "missing_derived_fact",
            "missing_existential_match",
            "blocking_negation",
            "unmet_constraint",
            "head_mismatch",
            "no_defining_rules",
            "budget_cutoff",
            "cycle",
        ];
        NAMES[self as usize]
    }
}

/// One structured cause explaining why a ground atom was not derived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissingReason {
    pub kind: MissingReasonKind,
    pub rule_id: Option<String>,
    pub predicate: Option<String>,
    pub terms: Vec<crate::Term>,
    pub detail: String,
    pub blocker_epistemic: Option<EpistemicStatus>,
    pub blocker_supports: Vec<crate::Derivation>,
    pub causes: Vec<MissingReason>,
}

/// Read-only Why-Not provenance explanation for one ground atom.
#[derive(Clone, Debug)]
pub struct MissingExplanation {
    pub predicate: String,
    pub terms: Vec<mneme_core::Value>,
    pub status: MissingStatus,
    pub context: crate::BuildContext,
    pub build_status: crate::ExecutionStatus,
    pub coverage: Vec<crate::Coverage>,
    pub present_epistemic: Option<EpistemicStatus>,
    pub present_supports: Vec<crate::Derivation>,
    pub reasons: Vec<MissingReason>,
    pub truncated: bool,
    pub exhaustive: bool,
    pub stale: bool,
    pub requested_revision: mneme_core::WorkspaceRevisionId,
    pub served_revision: mneme_core::WorkspaceRevisionId,
    pub work: u64,
}

#[derive(Clone)]
struct BodyBranch {
    remaining: Vec<usize>,
    binding: Binding,
}

struct GoalFrame<'a> {
    goal: GoalKey,
    depth: u32,
    parent_rule_id: Option<String>,
    rules: Vec<&'a crate::Rule>,
    next_rule: usize,
    any_head_matched: bool,
    head_mismatches: Vec<MissingReason>,
    pending_subgoals: Vec<(GoalKey, String)>,
    branches: Vec<BodyBranch>,
    aggregate_bindings: Vec<Binding>,
    active_rule: Option<&'a crate::Rule>,
    reasons: Vec<MissingReason>,
}

struct ExplainState<'a> {
    build: &'a crate::Build,
    limits: &'a ExplainLimits,
    cancellation: Option<&'a std::sync::Arc<std::sync::atomic::AtomicBool>>,
    work: u64,
    truncated: bool,
    visiting: std::collections::BTreeSet<GoalKey>,
}

impl ExplainState<'_> {
    fn charge(&mut self, amount: u64) -> bool {
        if self
            .cancellation
            .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed))
        {
            self.truncated = true;
            return false;
        }
        match mneme_kernel::budget::charge(self.work, amount, self.limits.max_work) {
            Some(next) => {
                self.work = next;
                true
            }
            None => {
                self.truncated = true;
                false
            }
        }
    }

    fn at_reason_limit(&self, count: usize) -> bool {
        u32::try_from(count).is_ok_and(|used| used >= self.limits.max_reasons)
    }
}

pub(crate) struct ExplainContext<'a> {
    pub requested_revision: mneme_core::WorkspaceRevisionId,
    pub stale: bool,
    pub limits: &'a ExplainLimits,
    pub cancellation: Option<&'a std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

struct ExplainTarget<'a> {
    build: &'a crate::Build,
    predicate: &'a str,
    terms: &'a [mneme_core::Value],
    context: &'a ExplainContext<'a>,
}

/// Explain why `predicate(terms...)` was or was not derived in `build`.
pub(crate) fn explain_missing_in_build(
    build: &crate::Build,
    predicate: &str,
    terms: &[mneme_core::Value],
    context: ExplainContext<'_>,
) -> Result<MissingExplanation, crate::Error> {
    validate_target_atom(build, predicate, terms)?;
    let coverage = crate::dependency_coverage(build, predicate);
    let target = ExplainTarget {
        build,
        predicate,
        terms,
        context: &context,
    };
    if let Some(present) = check_present(build, predicate, terms, &coverage, &context) {
        return Ok(present);
    }
    if let Some(cutoff) = check_build_cutoff(&target, &coverage) {
        return Ok(cutoff);
    }
    run_iterative_explain(&target, coverage)
}

fn validate_target_atom(
    build: &crate::Build,
    predicate: &str,
    terms: &[mneme_core::Value],
) -> Result<(), crate::Error> {
    let arity = build
        .arities
        .get(predicate)
        .copied()
        .ok_or_else(|| crate::Error::UnknownPredicate(predicate.to_owned()))?;
    if terms.len() != arity {
        return Err(crate::Error::InvalidQuery(
            "target atom term count does not match predicate arity",
        ));
    }
    assert_eq!(terms.len(), arity);
    assert!(!predicate.is_empty());
    validate_canonical_kinds(predicate, terms)
}

fn validate_canonical_kinds(
    predicate: &str,
    terms: &[mneme_core::Value],
) -> Result<(), crate::Error> {
    if let Some(schema) = crate::rules::canonical_schema(predicate) {
        for (value, kind) in terms.iter().zip(schema) {
            if !kind.accepts(value) {
                return Err(crate::Error::InvalidQuery(
                    "target atom term kind does not match the canonical extent",
                ));
            }
        }
    }
    Ok(())
}

fn check_present(
    build: &crate::Build,
    predicate: &str,
    terms: &[mneme_core::Value],
    coverage: &[crate::Coverage],
    context: &ExplainContext<'_>,
) -> Option<MissingExplanation> {
    let data = build.facts.get(predicate)?.get(terms)?;
    if !data.is_active() {
        return None;
    }
    assert!(data.is_active());
    assert!(!predicate.is_empty());
    let is_deps_complete = coverage
        .iter()
        .all(|item| item.status == crate::CoverageStatus::Complete);
    let fact_ref = (predicate.to_owned(), terms.to_vec());
    let (projected, _) = build.justifications.project_derivations_bounded(
        &fact_ref,
        build.context.served_revision,
        &build.context.scope,
        build.limits.max_supports_per_fact,
    );
    let present_supports = if projected.is_empty() {
        data.supports.clone()
    } else {
        projected
    };
    Some(MissingExplanation {
        predicate: predicate.to_owned(),
        terms: terms.to_vec(),
        status: MissingStatus::Present,
        context: build.context.clone(),
        build_status: build.status,
        coverage: coverage.to_vec(),
        present_epistemic: Some(data.epistemic),
        present_supports,
        reasons: Vec::new(),
        truncated: false,
        exhaustive: is_deps_complete && !build.limit_reached,
        stale: context.stale,
        requested_revision: context.requested_revision,
        served_revision: build.context.served_revision,
        work: 1,
    })
}

fn check_build_cutoff(
    target: &ExplainTarget<'_>,
    coverage: &[crate::Coverage],
) -> Option<MissingExplanation> {
    assert!(target.build.arities.contains_key(target.predicate));
    assert_eq!(target.terms.len(), target.build.arities[target.predicate]);
    let incomplete = coverage
        .iter()
        .filter(|item| item.status != crate::CoverageStatus::Complete)
        .map(|item| format!("{}:{}", item.predicate, item.status.name()))
        .collect::<Vec<_>>();
    let is_terminal_stop = matches!(
        target.build.status,
        crate::ExecutionStatus::Timeout
            | crate::ExecutionStatus::Cancelled
            | crate::ExecutionStatus::Failed
    );
    if !target.build.limit_reached && !is_terminal_stop && incomplete.is_empty() {
        return None;
    }
    let detail = cutoff_detail(target.build, target.predicate, &incomplete);
    Some(cutoff_explanation(target, coverage, detail))
}

fn cutoff_detail(build: &crate::Build, predicate: &str, incomplete: &[String]) -> String {
    if incomplete.is_empty() {
        format!(
            "build stopped before completing evaluation (status={}, work={}/{}, max_rows={}, limit_reached={})",
            build.status.name(),
            build.work,
            build.limits.max_work,
            build.limits.max_result_rows,
            build.limit_reached
        )
    } else {
        format!(
            "build incomplete for {} (status={}, work={}/{}, incomplete=[{}])",
            predicate,
            build.status.name(),
            build.work,
            build.limits.max_work,
            incomplete.join(", ")
        )
    }
}

fn cutoff_explanation(
    target: &ExplainTarget<'_>,
    coverage: &[crate::Coverage],
    detail: String,
) -> MissingExplanation {
    assert!(!target.predicate.is_empty());
    assert!(!detail.is_empty());
    MissingExplanation {
        predicate: target.predicate.to_owned(),
        terms: target.terms.to_vec(),
        status: MissingStatus::BudgetCutoff,
        context: target.build.context.clone(),
        build_status: target.build.status,
        coverage: coverage.to_vec(),
        present_epistemic: None,
        present_supports: Vec::new(),
        reasons: vec![MissingReason {
            kind: MissingReasonKind::BudgetCutoff,
            rule_id: None,
            predicate: Some(target.predicate.to_owned()),
            terms: const_terms(target.terms),
            detail,
            blocker_epistemic: None,
            blocker_supports: Vec::new(),
            causes: Vec::new(),
        }],
        truncated: true,
        exhaustive: false,
        stale: target.context.stale,
        requested_revision: target.context.requested_revision,
        served_revision: target.build.context.served_revision,
        work: 1,
    }
}

fn run_iterative_explain(
    target: &ExplainTarget<'_>,
    coverage: Vec<crate::Coverage>,
) -> Result<MissingExplanation, crate::Error> {
    assert!(target.build.arities.contains_key(target.predicate));
    assert_eq!(target.terms.len(), target.build.arities[target.predicate]);
    let mut state = ExplainState {
        build: target.build,
        limits: target.context.limits,
        cancellation: target.context.cancellation,
        work: 0,
        truncated: false,
        visiting: std::collections::BTreeSet::new(),
    };
    let root_goal = (target.predicate.to_owned(), target.terms.to_vec());
    let mut stack = vec![make_goal_frame(target.build, root_goal.clone(), 0, None)];
    let root_reasons = drain_explain_stack(&mut state, &mut stack);
    Ok(assemble_missing_explanation(
        target,
        root_goal,
        coverage,
        &state,
        root_reasons,
    ))
}

fn drain_explain_stack<'a>(
    state: &mut ExplainState<'a>,
    stack: &mut Vec<GoalFrame<'a>>,
) -> Vec<MissingReason> {
    assert!(!stack.is_empty());
    let mut root_reasons = Vec::new();
    while !stack.is_empty() {
        let Some(step_result) = step_top_frame(state, stack) else {
            continue;
        };
        if let FrameStep::PushChild(child) = step_result {
            stack.push(child);
        } else if let FrameStep::PopFinished(finished) = step_result {
            let Some(parent) = stack.last_mut() else {
                root_reasons = finished.reasons;
                break;
            };
            if !state.at_reason_limit(parent.reasons.len()) {
                parent.reasons.push(wrap_derived_reason(finished));
            } else {
                state.truncated = true;
            }
        }
    }
    assert!(stack.is_empty());
    root_reasons
}

fn assemble_missing_explanation(
    target: &ExplainTarget<'_>,
    root_goal: GoalKey,
    coverage: Vec<crate::Coverage>,
    state: &ExplainState<'_>,
    reasons: Vec<MissingReason>,
) -> MissingExplanation {
    assert!(!root_goal.0.is_empty());
    assert!(state.work <= state.limits.max_work);
    let status = if state.truncated {
        MissingStatus::BudgetCutoff
    } else {
        MissingStatus::Missing
    };
    MissingExplanation {
        predicate: root_goal.0,
        terms: root_goal.1,
        status,
        context: target.build.context.clone(),
        build_status: target.build.status,
        coverage,
        present_epistemic: None,
        present_supports: Vec::new(),
        reasons,
        truncated: state.truncated,
        exhaustive: !state.truncated,
        stale: target.context.stale,
        requested_revision: target.context.requested_revision,
        served_revision: target.build.context.served_revision,
        work: state.work,
    }
}

enum FrameStep<'a> {
    PushChild(GoalFrame<'a>),
    PopFinished(GoalFrame<'a>),
}

fn make_goal_frame<'a>(
    build: &'a crate::Build,
    goal: GoalKey,
    depth: u32,
    parent_rule_id: Option<String>,
) -> GoalFrame<'a> {
    let rules: Vec<&'a crate::Rule> = build
        .bundle
        .rules
        .iter()
        .filter(|rule| rule.head.predicate == goal.0)
        .collect();
    assert!(rules.len() <= build.bundle.rules.len());
    assert!(rules.iter().all(|rule| rule.head.predicate == goal.0));
    GoalFrame {
        goal,
        depth,
        parent_rule_id,
        rules,
        next_rule: 0,
        any_head_matched: false,
        head_mismatches: Vec::new(),
        pending_subgoals: Vec::new(),
        branches: Vec::new(),
        aggregate_bindings: Vec::new(),
        active_rule: None,
        reasons: Vec::new(),
    }
}

fn wrap_derived_reason(finished: GoalFrame<'_>) -> MissingReason {
    let (predicate, terms) = finished.goal;
    let detail = format!(
        "derived premise {} was not derived",
        format_atom(&predicate, &terms)
    );
    MissingReason {
        kind: MissingReasonKind::MissingDerivedFact,
        rule_id: finished.parent_rule_id,
        predicate: Some(predicate),
        terms: const_terms(&terms),
        detail,
        blocker_epistemic: None,
        blocker_supports: Vec::new(),
        causes: finished.reasons,
    }
}

fn step_top_frame<'a>(
    state: &mut ExplainState<'a>,
    stack: &mut Vec<GoalFrame<'a>>,
) -> Option<FrameStep<'a>> {
    assert!(state.work <= state.limits.max_work);
    let frame = stack.last_mut()?;
    assert!(frame.next_rule <= frame.rules.len());
    if frame.next_rule == 0 && frame.active_rule.is_none() && frame.reasons.is_empty() {
        if let Some(early) = check_frame_entry(state, frame) {
            frame.reasons.push(early);
            return Some(FrameStep::PopFinished(stack.pop()?));
        }
        state.visiting.insert(frame.goal.clone());
    }
    let has_remaining_work = !frame.pending_subgoals.is_empty()
        || !frame.branches.is_empty()
        || frame.active_rule.is_some()
        || frame.next_rule < frame.rules.len();
    if state.truncated || (has_remaining_work && state.at_reason_limit(frame.reasons.len())) {
        return finish_truncated_frame(state, stack);
    }
    if let Some((subgoal, rule_id)) = frame.pending_subgoals.pop() {
        return Some(FrameStep::PushChild(make_goal_frame(
            state.build,
            subgoal,
            frame.depth.saturating_add(1),
            Some(rule_id),
        )));
    }
    if let Some(branch) = frame.branches.pop() {
        return step_branch(state, frame, branch).map(FrameStep::PushChild);
    }
    if let Some(rule) = frame.active_rule.take() {
        finish_active_rule(state, frame, rule);
        return None;
    }
    if let Some(rule) = frame.rules.get(frame.next_rule).copied() {
        frame.next_rule = frame.next_rule.saturating_add(1);
        start_rule(frame, rule);
        return None;
    }
    if !frame.any_head_matched {
        frame.reasons.append(&mut frame.head_mismatches);
    }
    state.visiting.remove(&frame.goal);
    Some(FrameStep::PopFinished(stack.pop()?))
}

fn finish_truncated_frame<'a>(
    state: &mut ExplainState<'a>,
    stack: &mut Vec<GoalFrame<'a>>,
) -> Option<FrameStep<'a>> {
    let frame = stack.last_mut()?;
    state.truncated = true;
    if !state.at_reason_limit(frame.reasons.len()) {
        frame.reasons.push(budget_cutoff_reason(
            &frame.goal,
            "explanation reason bound reached",
        ));
    }
    state.visiting.remove(&frame.goal);
    Some(FrameStep::PopFinished(stack.pop()?))
}

fn check_frame_entry(state: &mut ExplainState<'_>, frame: &GoalFrame<'_>) -> Option<MissingReason> {
    assert!(frame.next_rule <= frame.rules.len());
    assert!(state.work <= state.limits.max_work);
    if !state.charge(1) {
        return Some(budget_cutoff_reason(
            &frame.goal,
            "explanation work budget exhausted",
        ));
    }
    if state.visiting.contains(&frame.goal) {
        return Some(cycle_reason(frame));
    }
    if frame.depth >= state.limits.max_depth {
        state.truncated = true;
        return Some(budget_cutoff_reason(
            &frame.goal,
            "explanation recursion depth limit reached",
        ));
    }
    if frame.rules.is_empty() {
        return Some(missing_leaf_reason(state, frame));
    }
    None
}

fn cycle_reason(frame: &GoalFrame<'_>) -> MissingReason {
    MissingReason {
        kind: MissingReasonKind::Cycle,
        rule_id: frame.parent_rule_id.clone(),
        predicate: Some(frame.goal.0.clone()),
        terms: const_terms(&frame.goal.1),
        detail: format!(
            "recursive cycle encountered while explaining {}",
            format_atom(&frame.goal.0, &frame.goal.1)
        ),
        blocker_epistemic: None,
        blocker_supports: Vec::new(),
        causes: Vec::new(),
    }
}

fn missing_leaf_reason(state: &ExplainState<'_>, frame: &GoalFrame<'_>) -> MissingReason {
    assert!(frame.rules.is_empty());
    let is_base = state
        .build
        .bundle
        .base_predicates
        .contains_key(&frame.goal.0)
        || crate::rules::canonical_schema(&frame.goal.0).is_some();
    let kind = if is_base {
        MissingReasonKind::MissingBaseFact
    } else {
        MissingReasonKind::NoDefiningRules
    };
    assert_eq!(kind == MissingReasonKind::MissingBaseFact, is_base);
    let detail = if is_base {
        format!(
            "base fact {} is absent from snapshot",
            format_atom(&frame.goal.0, &frame.goal.1)
        )
    } else {
        format!("no rule in bundle defines predicate {:?}", frame.goal.0)
    };
    MissingReason {
        kind,
        rule_id: frame.parent_rule_id.clone(),
        predicate: Some(frame.goal.0.clone()),
        terms: const_terms(&frame.goal.1),
        detail,
        blocker_epistemic: None,
        blocker_supports: Vec::new(),
        causes: Vec::new(),
    }
}

fn start_rule<'a>(frame: &mut GoalFrame<'a>, rule: &'a crate::Rule) {
    assert!(frame.branches.is_empty());
    assert!(frame.active_rule.is_none());
    let Some(binding) = unify_head(&rule.head, &frame.goal.1) else {
        frame.head_mismatches.push(MissingReason {
            kind: MissingReasonKind::HeadMismatch,
            rule_id: Some(rule.id.clone()),
            predicate: Some(rule.head.predicate.clone()),
            terms: rule.head.terms.clone(),
            detail: format!("rule {} head does not unify with target atom", rule.id),
            blocker_epistemic: None,
            blocker_supports: Vec::new(),
            causes: Vec::new(),
        });
        return;
    };
    frame.any_head_matched = true;
    let remaining = non_aggregate_indices(&rule.body);
    frame.active_rule = Some(rule);
    frame.aggregate_bindings.clear();
    frame.branches.push(BodyBranch { remaining, binding });
}

fn non_aggregate_indices(body: &[crate::Literal]) -> Vec<usize> {
    body.iter()
        .enumerate()
        .filter_map(|(idx, literal)| {
            if matches!(
                literal,
                crate::Literal::Aggregate { .. } | crate::Literal::Forbidden(_)
            ) {
                None
            } else {
                Some(idx)
            }
        })
        .collect()
}

fn finish_active_rule(state: &mut ExplainState<'_>, frame: &mut GoalFrame<'_>, rule: &crate::Rule) {
    assert!(frame.branches.is_empty());
    assert_eq!(rule.head.predicate, frame.goal.0);
    let Some(aggregate) = rule.body.iter().find_map(|literal| {
        if let crate::Literal::Aggregate {
            function,
            input,
            output,
        } = literal
        {
            Some((*function, input, output.as_str()))
        } else {
            None
        }
    }) else {
        return;
    };
    if frame.aggregate_bindings.is_empty() {
        return;
    }
    if state.at_reason_limit(frame.reasons.len()) {
        state.truncated = true;
        return;
    }
    let detail = describe_aggregate_mismatch(
        &rule.head,
        &frame.goal.1,
        aggregate,
        &frame.aggregate_bindings,
    );
    frame.reasons.push(MissingReason {
        kind: MissingReasonKind::UnmetConstraint,
        rule_id: Some(rule.id.clone()),
        predicate: Some(rule.head.predicate.clone()),
        terms: const_terms(&frame.goal.1),
        detail,
        blocker_epistemic: None,
        blocker_supports: Vec::new(),
        causes: Vec::new(),
    });
}

fn describe_aggregate_mismatch(
    head: &crate::Atom,
    target: &[mneme_core::Value],
    aggregate: (crate::AggregateFunction, &crate::Term, &str),
    bindings: &[Binding],
) -> String {
    let (function, input, output) = aggregate;
    let values = bindings
        .iter()
        .filter_map(|binding| resolve_term(input, binding))
        .collect::<Vec<_>>();
    let computed = crate::engine::compute_aggregate_value(function, values);
    let expected = head.terms.iter().zip(target).find_map(|(term, val)| {
        if let crate::Term::Variable(name) = term
            && name == output
        {
            Some(val)
        } else {
            None
        }
    });
    format_aggregate_detail(function, computed, expected)
}

fn format_aggregate_detail(
    function: crate::AggregateFunction,
    computed: Result<mneme_core::Value, &'static str>,
    expected: Option<&mneme_core::Value>,
) -> String {
    match (computed, expected) {
        (Ok(actual), Some(expected)) => format!(
            "aggregate {:?} produced {} instead of expected {}",
            function,
            mneme_core::text::render(&actual),
            mneme_core::text::render(expected)
        ),
        (Ok(actual), None) => format!(
            "aggregate {:?} produced {}, which did not match target",
            function,
            mneme_core::text::render(&actual)
        ),
        (Err(reason), _) => format!("aggregate evaluation failed: {reason}"),
    }
}

fn step_branch<'a>(
    state: &mut ExplainState<'a>,
    frame: &mut GoalFrame<'a>,
    mut branch: BodyBranch,
) -> Option<GoalFrame<'a>> {
    assert!(state.work <= state.limits.max_work);
    if !state.charge(1) {
        frame.reasons.push(budget_cutoff_reason(
            &frame.goal,
            "explanation work budget exhausted",
        ));
        return None;
    }
    let rule = frame.active_rule?;
    assert_eq!(rule.head.predicate, frame.goal.0);
    let (is_failed, missing_derived, still_remaining) =
        partition_branch_literals(state, frame, rule, &branch);
    let mut derived_iter = missing_derived.into_iter();
    if let Some(first_subgoal) = derived_iter.next() {
        let rest = derived_iter.collect::<Vec<_>>();
        for subgoal in rest.into_iter().rev() {
            frame.pending_subgoals.push((subgoal, rule.id.clone()));
        }
        return Some(make_goal_frame(
            state.build,
            first_subgoal,
            frame.depth.saturating_add(1),
            Some(rule.id.clone()),
        ));
    }
    if is_failed {
        return None;
    }
    if still_remaining.is_empty() {
        frame.aggregate_bindings.push(branch.binding);
        return None;
    }
    branch.remaining = still_remaining;
    expand_existential_literal(state, frame, rule, branch);
    None
}

fn partition_branch_literals(
    state: &mut ExplainState<'_>,
    frame: &mut GoalFrame<'_>,
    rule: &crate::Rule,
    branch: &BodyBranch,
) -> (bool, Vec<GoalKey>, Vec<usize>) {
    assert!(branch.remaining.iter().all(|&idx| idx < rule.body.len()));
    let mut is_failed = false;
    let mut missing_derived: Vec<GoalKey> = Vec::with_capacity(branch.remaining.len());
    let mut still_remaining = Vec::with_capacity(branch.remaining.len());
    for &idx in &branch.remaining {
        let literal = &rule.body[idx];
        if !literal_all_bound(literal, &branch.binding) {
            still_remaining.push(idx);
            continue;
        }
        let check = check_ground_literal(state, rule, literal, &branch.binding);
        if let GroundCheck::Failed(reason) = check {
            is_failed = true;
            record_branch_reason(state, frame, reason);
        } else if let GroundCheck::MissingDerived(subgoal) = check {
            is_failed = true;
            if !missing_derived.contains(&subgoal) {
                missing_derived.push(subgoal);
            }
        }
    }
    assert!(still_remaining.len() <= branch.remaining.len());
    (is_failed, missing_derived, still_remaining)
}

fn record_branch_reason(
    state: &mut ExplainState<'_>,
    frame: &mut GoalFrame<'_>,
    reason: MissingReason,
) {
    if !state.at_reason_limit(frame.reasons.len()) {
        frame.reasons.push(reason);
    } else {
        state.truncated = true;
    }
}

enum GroundCheck {
    Satisfied,
    Failed(MissingReason),
    MissingDerived(GoalKey),
}

fn check_ground_literal(
    state: &ExplainState<'_>,
    rule: &crate::Rule,
    literal: &crate::Literal,
    binding: &Binding,
) -> GroundCheck {
    if let crate::Literal::Positive(atom) = literal {
        return check_ground_positive(state, rule, atom, binding);
    }
    if let crate::Literal::Negative(atom) = literal {
        return check_ground_negative(state, rule, atom, binding);
    }
    if let crate::Literal::Compare { op, left, right } = literal {
        return check_ground_compare(rule, *op, left, right, binding);
    }
    GroundCheck::Satisfied
}

fn check_ground_positive(
    state: &ExplainState<'_>,
    rule: &crate::Rule,
    atom: &crate::Atom,
    binding: &Binding,
) -> GroundCheck {
    let terms = resolved_terms(atom, binding);
    assert_eq!(terms.len(), atom.terms.len());
    let is_present = state
        .build
        .facts
        .get(&atom.predicate)
        .and_then(|rows| rows.get(&terms))
        .is_some_and(crate::FactData::is_active);
    if is_present {
        return GroundCheck::Satisfied;
    }
    let is_derived = state
        .build
        .bundle
        .rules
        .iter()
        .any(|candidate| candidate.head.predicate == atom.predicate);
    if is_derived {
        return GroundCheck::MissingDerived((atom.predicate.clone(), terms));
    }
    assert!(!is_present);
    GroundCheck::Failed(missing_base_fact_reason(rule, &atom.predicate, &terms))
}

fn missing_base_fact_reason(
    rule: &crate::Rule,
    predicate: &str,
    terms: &[mneme_core::Value],
) -> MissingReason {
    MissingReason {
        kind: MissingReasonKind::MissingBaseFact,
        rule_id: Some(rule.id.clone()),
        predicate: Some(predicate.to_owned()),
        terms: const_terms(terms),
        detail: format!(
            "base fact {} is absent from snapshot",
            format_atom(predicate, terms)
        ),
        blocker_epistemic: None,
        blocker_supports: Vec::new(),
        causes: Vec::new(),
    }
}

fn check_ground_negative(
    state: &ExplainState<'_>,
    rule: &crate::Rule,
    atom: &crate::Atom,
    binding: &Binding,
) -> GroundCheck {
    let terms = resolved_terms(atom, binding);
    let is_strict = state.build.negation_semantics == crate::NegationSemantics::Strict;
    let Some(data) = state
        .build
        .facts
        .get(&atom.predicate)
        .and_then(|rows| rows.get(&terms))
        .filter(|data| {
            data.is_active()
                && if is_strict {
                    data.epistemic.negation_blocks()
                } else {
                    data.epistemic.kleene_negation_blocks()
                }
        })
    else {
        return GroundCheck::Satisfied;
    };
    let fact_ref = (atom.predicate.clone(), terms.clone());
    let (projected, _) = state.build.justifications.project_derivations_bounded(
        &fact_ref,
        state.build.context.served_revision,
        &state.build.context.scope,
        state.build.limits.max_supports_per_fact,
    );
    let blocker_supports = if projected.is_empty() {
        data.supports.clone()
    } else {
        projected
    };
    GroundCheck::Failed(blocking_negation_reason(
        rule,
        &atom.predicate,
        &terms,
        data.epistemic,
        blocker_supports,
    ))
}

fn blocking_negation_reason(
    rule: &crate::Rule,
    predicate: &str,
    terms: &[mneme_core::Value],
    blocker_epistemic: EpistemicStatus,
    blocker_supports: Vec<crate::Derivation>,
) -> MissingReason {
    MissingReason {
        kind: MissingReasonKind::BlockingNegation,
        rule_id: Some(rule.id.clone()),
        predicate: Some(predicate.to_owned()),
        terms: const_terms(terms),
        detail: format!(
            "negated literal not {} is blocked by existing fact",
            format_atom(predicate, terms)
        ),
        blocker_epistemic: Some(blocker_epistemic),
        blocker_supports,
        causes: Vec::new(),
    }
}

fn check_ground_compare(
    rule: &crate::Rule,
    op: crate::CompareOp,
    left: &crate::Term,
    right: &crate::Term,
    binding: &Binding,
) -> GroundCheck {
    let (Some(left_val), Some(right_val)) =
        (resolve_term(left, binding), resolve_term(right, binding))
    else {
        return GroundCheck::Failed(unbound_compare_reason(rule, left, right));
    };
    if crate::engine::compare_fact_values(op, &left_val, &right_val) {
        return GroundCheck::Satisfied;
    }
    GroundCheck::Failed(unmet_compare_reason(rule, op, &left_val, &right_val))
}

fn unbound_compare_reason(
    rule: &crate::Rule,
    left: &crate::Term,
    right: &crate::Term,
) -> MissingReason {
    MissingReason {
        kind: MissingReasonKind::UnmetConstraint,
        rule_id: Some(rule.id.clone()),
        predicate: None,
        terms: vec![left.clone(), right.clone()],
        detail: "constraint operands are unbound".to_owned(),
        blocker_epistemic: None,
        blocker_supports: Vec::new(),
        causes: Vec::new(),
    }
}

fn unmet_compare_reason(
    rule: &crate::Rule,
    op: crate::CompareOp,
    left_val: &mneme_core::Value,
    right_val: &mneme_core::Value,
) -> MissingReason {
    MissingReason {
        kind: MissingReasonKind::UnmetConstraint,
        rule_id: Some(rule.id.clone()),
        predicate: None,
        terms: vec![
            crate::Term::Constant(left_val.clone()),
            crate::Term::Constant(right_val.clone()),
        ],
        detail: format!(
            "constraint {} {} {} evaluated to false",
            mneme_core::text::render(left_val),
            compare_symbol(op),
            mneme_core::text::render(right_val)
        ),
        blocker_epistemic: None,
        blocker_supports: Vec::new(),
        causes: Vec::new(),
    }
}

fn expand_existential_literal(
    state: &mut ExplainState<'_>,
    frame: &mut GoalFrame<'_>,
    rule: &crate::Rule,
    branch: BodyBranch,
) {
    let Some((pos, body_idx)) = select_next_existential(state.build, rule, &branch) else {
        return;
    };
    assert!(pos < branch.remaining.len());
    let crate::Literal::Positive(atom) = &rule.body[body_idx] else {
        return;
    };
    let matches = collect_matching_bindings(state, atom, &branch.binding);
    if matches.is_empty() {
        record_missing_existential(state, frame, rule, atom, &branch.binding);
        return;
    }
    assert!(!matches.is_empty());
    let mut next_remaining = branch.remaining;
    next_remaining.remove(pos);
    for extended in matches.into_iter().rev() {
        frame.branches.push(BodyBranch {
            remaining: next_remaining.clone(),
            binding: extended,
        });
    }
}

fn record_missing_existential(
    state: &mut ExplainState<'_>,
    frame: &mut GoalFrame<'_>,
    rule: &crate::Rule,
    atom: &crate::Atom,
    binding: &Binding,
) {
    if state.truncated {
        return;
    }
    if state.at_reason_limit(frame.reasons.len()) {
        state.truncated = true;
        return;
    }
    let terms = instantiate_terms(atom, binding);
    assert_eq!(terms.len(), atom.terms.len());
    assert!(!state.at_reason_limit(frame.reasons.len()));
    frame.reasons.push(MissingReason {
        kind: MissingReasonKind::MissingExistentialMatch,
        rule_id: Some(rule.id.clone()),
        predicate: Some(atom.predicate.clone()),
        terms: terms.clone(),
        detail: format!(
            "no fact matches pattern {}({})",
            atom.predicate,
            render_terms(&terms)
        ),
        blocker_epistemic: None,
        blocker_supports: Vec::new(),
        causes: Vec::new(),
    });
}

fn existential_candidate_score(
    build: &crate::Build,
    atom: &crate::Atom,
    binding: &Binding,
    body_idx: usize,
) -> (usize, usize, usize, usize) {
    let extent = build
        .facts
        .get(&atom.predicate)
        .map_or(0, |rows| rows.len());
    let unbound = atom
        .terms
        .iter()
        .filter(|term| resolve_term(term, binding).is_none())
        .count();
    (usize::from(extent > 0), unbound, extent, body_idx)
}

fn select_next_existential(
    build: &crate::Build,
    rule: &crate::Rule,
    branch: &BodyBranch,
) -> Option<(usize, usize)> {
    let mut best: Option<((usize, usize, usize, usize), usize)> = None;
    for (pos, &body_idx) in branch.remaining.iter().enumerate() {
        let crate::Literal::Positive(atom) = &rule.body[body_idx] else {
            continue;
        };
        let score = existential_candidate_score(build, atom, &branch.binding, body_idx);
        if best.is_none_or(|(current, _)| score < current) {
            best = Some((score, pos));
        }
    }
    best.map(|(_, pos)| (pos, branch.remaining[pos]))
}

fn collect_matching_bindings(
    state: &mut ExplainState<'_>,
    atom: &crate::Atom,
    binding: &Binding,
) -> Vec<Binding> {
    let Some(rows) = state.build.facts.get(&atom.predicate) else {
        return Vec::new();
    };
    let mut matches = Vec::with_capacity(rows.len());
    for (terms, data) in rows {
        if !state.charge(1) {
            break;
        }
        if let Some(extended) = unify_atom(atom, terms, binding, data) {
            matches.push(extended);
        }
    }
    matches
}

fn unify_head(head: &crate::Atom, target: &[mneme_core::Value]) -> Option<Binding> {
    if head.terms.len() != target.len() {
        return None;
    }
    let mut binding = Binding::new();
    for (term, value) in head.terms.iter().zip(target) {
        if !bind_term(term, value, &mut binding, target.len()) {
            return None;
        }
    }
    Some(binding)
}

fn unify_atom(
    atom: &crate::Atom,
    terms: &[mneme_core::Value],
    binding: &Binding,
    data: &crate::FactData,
) -> Option<Binding> {
    if !data.is_active() || terms.len() != atom.terms.len() {
        return None;
    }
    let mut extended = binding.clone();
    let max_len = binding.len().saturating_add(terms.len());
    for (term, value) in atom.terms.iter().zip(terms) {
        if !bind_term(term, value, &mut extended, max_len) {
            return None;
        }
    }
    Some(extended)
}

fn bind_term(
    term: &crate::Term,
    value: &mneme_core::Value,
    binding: &mut Binding,
    max_len: usize,
) -> bool {
    if let crate::Term::Constant(expected) = term {
        return expected == value;
    }
    if let crate::Term::Variable(name) = term {
        if let Some(existing) = binding.get(name) {
            return existing == value;
        }
        if binding.len() >= max_len {
            return false;
        }
        binding.insert(name.clone(), value.clone());
    }
    true
}

fn literal_all_bound(literal: &crate::Literal, binding: &Binding) -> bool {
    if let crate::Literal::Positive(atom) | crate::Literal::Negative(atom) = literal {
        return atom
            .terms
            .iter()
            .all(|term| resolve_term(term, binding).is_some());
    }
    if let crate::Literal::Compare { left, right, .. } = literal {
        return resolve_term(left, binding).is_some() && resolve_term(right, binding).is_some();
    }
    false
}

fn resolved_terms(atom: &crate::Atom, binding: &Binding) -> Vec<mneme_core::Value> {
    atom.terms
        .iter()
        .filter_map(|term| resolve_term(term, binding))
        .collect()
}

fn resolve_term(term: &crate::Term, binding: &Binding) -> Option<mneme_core::Value> {
    if let crate::Term::Constant(value) = term {
        Some(value.clone())
    } else if let crate::Term::Variable(name) = term {
        binding.get(name).cloned()
    } else {
        None
    }
}

fn instantiate_terms(atom: &crate::Atom, binding: &Binding) -> Vec<crate::Term> {
    atom.terms
        .iter()
        .map(|term| match resolve_term(term, binding) {
            Some(value) => crate::Term::Constant(value),
            None => term.clone(),
        })
        .collect()
}

fn const_terms(values: &[mneme_core::Value]) -> Vec<crate::Term> {
    values.iter().cloned().map(crate::Term::Constant).collect()
}

fn budget_cutoff_reason(goal: &GoalKey, detail: &str) -> MissingReason {
    MissingReason {
        kind: MissingReasonKind::BudgetCutoff,
        rule_id: None,
        predicate: Some(goal.0.clone()),
        terms: const_terms(&goal.1),
        detail: detail.to_owned(),
        blocker_epistemic: None,
        blocker_supports: Vec::new(),
        causes: Vec::new(),
    }
}

fn format_atom(predicate: &str, terms: &[mneme_core::Value]) -> String {
    let rendered = terms
        .iter()
        .map(mneme_core::text::render)
        .collect::<Vec<_>>()
        .join(", ");
    format!("{predicate}({rendered})")
}

fn render_terms(terms: &[crate::Term]) -> String {
    terms
        .iter()
        .map(|term| {
            if let crate::Term::Variable(name) = term {
                format!("?{name}")
            } else if let crate::Term::Constant(value) = term {
                mneme_core::text::render(value)
            } else {
                String::new()
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

const fn compare_symbol(op: crate::CompareOp) -> &'static str {
    const SYMBOLS: [&str; 6] = ["=", "!=", "<", "<=", ">", ">="];
    SYMBOLS[op as usize]
}
