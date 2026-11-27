//! `s(CASP)`-style dual-rule guarded negation and bounded abductive reasoning.
//!
//! Compiles dual rules (Clark completion / `s(CASP)`, Arias et al. TPLP 2018)
//! for guarded negation strictly gated by [`crate::evaluate_negative_guard`]
//! (`mneme_kernel::completeness::absence_established`), and synthesizes
//! subset-minimal assumption sets `Δ` (`|Δ| <= max_assumptions`) consistent
//! with `denial` integrity constraints. All abduced conclusions remain
//! `EpistemicStatus::Proposed` and surface exclusively as reviewable
//! [`crate::PlanProposal`]s requiring [`crate::execution::PlanRegistry::accept`].
// Octet structural exception: domain-qualified names keep core types unambiguous

/// Default step budget for bounded abductive search and consistency checks.
pub const DEFAULT_STEP_BUDGET: u64 = 250_000;

/// Maximum depth of the active abductive call stack to prevent cyclic loops.
const MAX_CALL_DEPTH: usize = 64;

/// Maximum candidate derivations collected before deduplication and minimality filtering.
const MAX_SEARCH_CANDIDATES: usize = 4_096;

/// One `s(CASP)` dual disjunct for a single positive rule clause.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DualDisjunct {
    /// The target atom does not unify with the positive clause head.
    HeadMismatch { head_pattern: crate::Atom },
    /// The target atom unifies with the clause head, a prefix of body literals
    /// holds, and the next body literal fails (is negated).
    BodyFailure {
        head_pattern: crate::Atom,
        prefix: Vec<crate::Literal>,
        failed_literal: crate::Literal,
    },
}

/// Compiled dual representation for one positive rule clause.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DualClause {
    pub source_rule_id: String,
    pub disjuncts: Vec<DualDisjunct>,
}

/// Compiled `s(CASP)` dual predicate: `not p(X)` holds iff every clause's dual
/// holds and no base fact matches `p(X)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DualPredicate {
    pub predicate: String,
    pub arity: u32,
    pub clauses: Vec<DualClause>,
}

/// Full compiled `s(CASP)` dual program for a rule manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DualProgram {
    pub predicates: std::collections::BTreeMap<crate::slg::PredKey, DualPredicate>,
}

/// Result of evaluating a guarded negative subgoal through the dual program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DualVerdict {
    /// Absence is established under complete, unpruned coverage and verified
    /// by the compiled dual rules.
    EstablishedAbsent,
    /// The positive atom is derivable, so negation fails.
    RefutedPresent,
    /// Absence cannot be established (incomplete coverage, pruned source,
    /// non-ground subgoal, or limit reached).
    Unknown,
}

/// Compile `s(CASP)`-style dual rules for every predicate defined in `rules`.
pub fn compile_dual_program(rules: &[crate::Rule]) -> DualProgram {
    let mut predicates: std::collections::BTreeMap<crate::slg::PredKey, DualPredicate> =
        std::collections::BTreeMap::new();
    for rule in rules {
        let key = crate::slg::atom_key(&rule.head);
        let entry = predicates
            .entry(key.clone())
            .or_insert_with(|| DualPredicate {
                predicate: key.0.clone(),
                arity: key.1,
                clauses: Vec::new(),
            });
        entry.clauses.push(build_dual_clause(rule));
    }
    DualProgram { predicates }
}

fn build_dual_clause(rule: &crate::Rule) -> DualClause {
    let head = DualDisjunct::HeadMismatch {
        head_pattern: rule.head.clone(),
    };
    let tail = rule
        .body
        .iter()
        .enumerate()
        .map(|(idx, literal)| DualDisjunct::BodyFailure {
            head_pattern: rule.head.clone(),
            prefix: rule.body[..idx].to_vec(),
            failed_literal: literal.clone(),
        });
    let mut disjuncts = Vec::with_capacity(rule.body.len().saturating_add(1));
    disjuncts.push(head);
    disjuncts.extend(tail);
    DualClause {
        source_rule_id: rule.id.clone(),
        disjuncts,
    }
}

/// Bundled state for evaluating dual-rule negation and denial consistency.
struct EvalEnv<'a> {
    dual: &'a DualProgram,
    db: &'a crate::slg::ProgramDb,
    profile: crate::TermProfile,
    control: &'a crate::process::WorkerControl,
}

/// Evaluate a guarded negative literal `not subgoal` using the compiled
/// `s(CASP)` dual program, strictly gated by [`crate::evaluate_negative_guard`]
/// (`mneme_kernel::completeness::absence_established`).
fn evaluate_dual_negation(
    subgoal: &crate::Atom,
    env: &EvalEnv<'_>,
    budget: &mut crate::slg::StepBudget,
) -> Result<DualVerdict, crate::slg::StopReason> {
    budget.charge(1, env.control)?;
    let is_ground = crate::slg::is_ground_atom(subgoal);
    let conditions = crate::NegativeConditions {
        relation_complete: env.db.coverage_complete,
        subgoal_completed: true,
        subgoal_ground: is_ground,
        source_pruned: env.db.source_pruned,
        within_limits: true,
    };
    if !matches!(
        crate::evaluate_negative_guard(conditions),
        crate::NegativeConclusion::Established
    ) {
        return Ok(DualVerdict::Unknown);
    }
    let empty = crate::slg::Subst::new();
    for fact in env.db.matching_facts(subgoal) {
        if crate::slg::unify_atoms(subgoal, fact, &empty, budget, env.control)?.is_some() {
            return Ok(DualVerdict::RefutedPresent);
        }
    }
    let key = crate::slg::atom_key(subgoal);
    let Some(dual_pred) = env.dual.predicates.get(&key) else {
        return Ok(DualVerdict::EstablishedAbsent);
    };
    let mut slg =
        crate::slg::Engine::new(env.db, env.profile, remaining_budget(budget), env.control);
    for clause in &dual_pred.clauses {
        budget.charge(1, env.control)?;
        if !dual_clause_holds(subgoal, clause, &mut slg, budget)? {
            return Ok(DualVerdict::RefutedPresent);
        }
    }
    if !matches!(
        crate::evaluate_negative_guard(conditions),
        crate::NegativeConclusion::Established
    ) {
        return Ok(DualVerdict::Unknown);
    }
    Ok(DualVerdict::EstablishedAbsent)
}

fn remaining_budget(budget: &crate::slg::StepBudget) -> u64 {
    DEFAULT_STEP_BUDGET.saturating_sub(budget.used())
}

fn dual_clause_holds(
    subgoal: &crate::Atom,
    clause: &DualClause,
    slg: &mut crate::slg::Engine<'_>,
    budget: &mut crate::slg::StepBudget,
) -> Result<bool, crate::slg::StopReason> {
    let Some(DualDisjunct::HeadMismatch { head_pattern }) = clause.disjuncts.first() else {
        return Ok(true);
    };
    let empty = crate::slg::Subst::new();
    if crate::slg::unify_atoms(subgoal, head_pattern, &empty, budget, slg.control)?.is_none() {
        return Ok(true);
    }
    let answers = slg.evaluate_goal(subgoal)?;
    budget.charge(slg.budget.used().min(1), slg.control)?;
    Ok(answers.is_empty())
}

/// One candidate abductive derivation `(output_bindings, Δ)`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Candidate {
    bindings: std::collections::BTreeMap<String, crate::Term>,
    assumptions: std::collections::BTreeSet<crate::Atom>,
    negative_guards: std::collections::BTreeSet<crate::Atom>,
}

/// Search state for iterative goal-directed abductive resolution.
struct SearchFrame {
    remaining: Vec<crate::Literal>,
    subst: crate::slg::Subst,
    assumptions: std::collections::BTreeSet<crate::Atom>,
    negative_guards: std::collections::BTreeSet<crate::Atom>,
    call_depth: usize,
    active_calls: Vec<crate::slg::CallKey>,
}

struct SearchContext<'a> {
    request: &'a crate::Request,
    image: &'a crate::snapshot::InputImage,
    metadata: &'a crate::CapabilityMetadata,
    abducibles: &'a std::collections::BTreeSet<String>,
    max_assumptions: u32,
    base_db: &'a crate::slg::ProgramDb,
    dual: &'a DualProgram,
    control: &'a crate::process::WorkerControl,
}

struct SearchMutable {
    fresh_counter: u64,
    budget: crate::slg::StepBudget,
    stack: Vec<SearchFrame>,
}

/// Run `QueryMode::Abduce { abducibles, max_assumptions }` over an immutable
/// snapshot image, returning a validated [`crate::Outcome`] with strictly
/// `Proposed` solutions and reviewable [`crate::Proposal::Plan`] entries.
#[allow(unknown_lints, ambient_clock)] // wall-clock measurement mirrors run_query
pub(crate) fn run(
    metadata: &crate::CapabilityMetadata,
    image: &crate::snapshot::InputImage,
    request: &crate::Request,
    identity: &crate::ProtocolIdentity,
    runtime: &crate::process::WorkerRuntime<'_>,
) -> Result<crate::Outcome, crate::CapabilityError> {
    let crate::QueryMode::Abduce {
        abducibles,
        max_assumptions,
    } = &request.mode
    else {
        return Err(crate::CapabilityError::InvalidRequest(
            "abductive runner requires QueryMode::Abduce".to_owned(),
        ));
    };
    crate::slg::check_stratified(&request.rules)?;
    if runtime.control.is_cancelled() {
        return Ok(cancelled_outcome(image, request, identity));
    }
    let started = std::time::Instant::now();
    let base_db = crate::slg::ProgramDb::from_request(image, request, &[])?;
    let dual = compile_dual_program(&request.rules);
    let ctx = SearchContext {
        request,
        image,
        metadata,
        abducibles,
        max_assumptions: *max_assumptions,
        base_db: &base_db,
        dual: &dual,
        control: runtime.control,
    };
    let mut budget = crate::slg::StepBudget::new(DEFAULT_STEP_BUDGET);
    let raw_candidates = match search_candidates(&ctx, &mut budget) {
        Ok(candidates) => candidates,
        Err(crate::slg::StopReason::Cancelled) => {
            return Ok(cancelled_outcome(image, request, identity));
        }
        Err(crate::slg::StopReason::BudgetExhausted) => {
            let elapsed_ms = crate::slg::elapsed_millis_u64(started.elapsed());
            return Ok(timeout_outcome(image, request, identity, elapsed_ms));
        }
    };
    let consistent = match filter_consistent(&ctx, raw_candidates, &mut budget) {
        Ok(items) => items,
        Err(crate::slg::StopReason::Cancelled) => {
            return Ok(cancelled_outcome(image, request, identity));
        }
        Err(crate::slg::StopReason::BudgetExhausted) => {
            let elapsed_ms = crate::slg::elapsed_millis_u64(started.elapsed());
            return Ok(timeout_outcome(image, request, identity, elapsed_ms));
        }
    };
    let minimal = select_subset_minimal(consistent);
    let elapsed_ms = crate::slg::elapsed_millis_u64(started.elapsed());
    build_outcome(&ctx, identity, minimal, elapsed_ms)
}

fn search_candidates(
    ctx: &SearchContext<'_>,
    budget: &mut crate::slg::StepBudget,
) -> Result<Vec<Candidate>, crate::slg::StopReason> {
    let output_vars: Vec<&str> = ctx
        .request
        .variables
        .iter()
        .filter(|var| var.role == crate::VariableRole::Output)
        .map(|var| var.name.as_str())
        .collect();
    let mut state = SearchMutable {
        fresh_counter: 0,
        budget: *budget,
        stack: vec![SearchFrame {
            remaining: vec![crate::Literal::Positive(ctx.request.goal.clone())],
            subst: crate::slg::Subst::new(),
            assumptions: std::collections::BTreeSet::new(),
            negative_guards: std::collections::BTreeSet::new(),
            call_depth: 0,
            active_calls: Vec::new(),
        }],
    };
    let mut found: Vec<Candidate> = Vec::with_capacity(16);
    while let Some(frame) = state.stack.pop() {
        state.budget.charge(1, ctx.control)?;
        if frame.remaining.is_empty() {
            if found.len() < MAX_SEARCH_CANDIDATES
                && let Some(candidate) = extract_candidate(&frame, &output_vars, ctx.metadata.terms)
            {
                found.push(candidate);
            }
            continue;
        }
        if frame.call_depth > MAX_CALL_DEPTH {
            continue;
        }
        let Some((chosen_idx, literal)) = select_next_literal(&frame, ctx) else {
            continue;
        };
        let mut rest = frame.remaining.clone();
        rest.remove(chosen_idx);
        expand_literal(ctx, &frame, literal, rest, &mut state)?;
    }
    *budget = state.budget;
    Ok(found)
}

fn select_next_literal(
    frame: &SearchFrame,
    ctx: &SearchContext<'_>,
) -> Option<(usize, crate::Literal)> {
    let max_depth = ctx.metadata.terms.max_depth;
    let mut best: Option<(usize, u8, crate::Literal)> = None;
    for (idx, raw_lit) in frame.remaining.iter().enumerate() {
        let applied = apply_literal_subst(raw_lit, &frame.subst, max_depth)?;
        let priority = literal_priority(&applied, ctx.abducibles);
        if best
            .as_ref()
            .is_none_or(|(_, best_prio, _)| priority < *best_prio)
        {
            best = Some((idx, priority, applied));
        }
    }
    best.map(|(idx, _, lit)| (idx, lit))
}

fn apply_literal_subst(
    raw_lit: &crate::Literal,
    subst: &crate::slg::Subst,
    max_depth: usize,
) -> Option<crate::Literal> {
    if let crate::Literal::Negative(atom) = raw_lit {
        let resolved = crate::slg::apply_subst_atom(atom, subst, max_depth)?;
        Some(crate::Literal::Negative(resolved))
    } else {
        let atom = crate::slg::literal_atom(raw_lit);
        let resolved = crate::slg::apply_subst_atom(atom, subst, max_depth)?;
        Some(crate::Literal::Positive(resolved))
    }
}

fn literal_priority(
    literal: &crate::Literal,
    abducibles: &std::collections::BTreeSet<String>,
) -> u8 {
    if let crate::Literal::Negative(atom) = literal {
        return if crate::slg::is_ground_atom(atom) {
            3
        } else {
            5
        };
    }
    let atom = crate::slg::literal_atom(literal);
    let is_abducible = abducibles.contains(&atom.predicate);
    let is_ground = crate::slg::is_ground_atom(atom);
    if !is_abducible && is_ground {
        0
    } else if !is_abducible {
        1
    } else if is_ground {
        2
    } else {
        4
    }
}

fn expand_literal(
    ctx: &SearchContext<'_>,
    frame: &SearchFrame,
    literal: crate::Literal,
    rest: Vec<crate::Literal>,
    state: &mut SearchMutable,
) -> Result<(), crate::slg::StopReason> {
    if let crate::Literal::Negative(atom) = literal {
        let env = EvalEnv {
            dual: ctx.dual,
            db: ctx.base_db,
            profile: ctx.metadata.terms,
            control: ctx.control,
        };
        let verdict = evaluate_dual_negation(&atom, &env, &mut state.budget)?;
        if verdict == DualVerdict::EstablishedAbsent && !frame.assumptions.contains(&atom) {
            let mut next_guards = frame.negative_guards.clone();
            next_guards.insert(atom);
            state.stack.push(SearchFrame {
                remaining: rest,
                subst: frame.subst.clone(),
                assumptions: frame.assumptions.clone(),
                negative_guards: next_guards,
                call_depth: frame.call_depth,
                active_calls: frame.active_calls.clone(),
            });
        }
        return Ok(());
    }
    let atom = crate::slg::literal_atom(&literal);
    expand_positive(ctx, frame, atom, &rest, state)
}

fn expand_positive(
    ctx: &SearchContext<'_>,
    frame: &SearchFrame,
    atom: &crate::Atom,
    rest: &[crate::Literal],
    state: &mut SearchMutable,
) -> Result<(), crate::slg::StopReason> {
    expand_from_assumptions_and_facts(ctx, frame, atom, rest, state)?;
    expand_from_rules(ctx, frame, atom, rest, state)?;
    maybe_push_abduced_branch(ctx, frame, atom, rest, state);
    Ok(())
}

fn expand_from_assumptions_and_facts(
    ctx: &SearchContext<'_>,
    frame: &SearchFrame,
    atom: &crate::Atom,
    rest: &[crate::Literal],
    state: &mut SearchMutable,
) -> Result<(), crate::slg::StopReason> {
    for assumed in &frame.assumptions {
        if let Some(next_subst) =
            crate::slg::unify_atoms(atom, assumed, &frame.subst, &mut state.budget, ctx.control)?
        {
            push_next_frame(frame, rest, next_subst, state);
        }
    }
    for fact in ctx.base_db.matching_facts(atom) {
        if let Some(next_subst) =
            crate::slg::unify_atoms(atom, fact, &frame.subst, &mut state.budget, ctx.control)?
        {
            push_next_frame(frame, rest, next_subst, state);
        }
    }
    Ok(())
}

fn push_next_frame(
    frame: &SearchFrame,
    rest: &[crate::Literal],
    next_subst: crate::slg::Subst,
    state: &mut SearchMutable,
) {
    state.stack.push(SearchFrame {
        remaining: rest.to_vec(),
        subst: next_subst,
        assumptions: frame.assumptions.clone(),
        negative_guards: frame.negative_guards.clone(),
        call_depth: frame.call_depth,
        active_calls: frame.active_calls.clone(),
    });
}

fn expand_from_rules(
    ctx: &SearchContext<'_>,
    frame: &SearchFrame,
    atom: &crate::Atom,
    rest: &[crate::Literal],
    state: &mut SearchMutable,
) -> Result<(), crate::slg::StopReason> {
    if atom.predicate == "denial" {
        return Ok(());
    }
    let call_key = crate::slg::canonicalize_atom(atom);
    if frame.active_calls.contains(&call_key) {
        return Ok(());
    }
    let key = crate::slg::atom_key(atom);
    let Some(rules) = ctx.base_db.rules.get(&key) else {
        return Ok(());
    };
    for rule in rules {
        state.fresh_counter = state.fresh_counter.saturating_add(1);
        let renamed = crate::slg::rename_rule(rule, state.fresh_counter);
        let Some(next_subst) = crate::slg::unify_atoms(
            atom,
            &renamed.head,
            &frame.subst,
            &mut state.budget,
            ctx.control,
        )?
        else {
            continue;
        };
        push_rule_frame(
            frame,
            RuleExpansion {
                rest,
                body: renamed.body,
                next_subst,
                call_key: &call_key,
            },
            state,
        );
    }
    Ok(())
}

struct RuleExpansion<'a> {
    rest: &'a [crate::Literal],
    body: Vec<crate::Literal>,
    next_subst: crate::slg::Subst,
    call_key: &'a crate::slg::CallKey,
}

fn push_rule_frame(frame: &SearchFrame, expansion: RuleExpansion<'_>, state: &mut SearchMutable) {
    let mut next_remaining =
        Vec::with_capacity(expansion.rest.len().saturating_add(expansion.body.len()));
    next_remaining.extend_from_slice(expansion.rest);
    next_remaining.extend(expansion.body);
    let mut next_active = Vec::with_capacity(frame.active_calls.len().saturating_add(1));
    next_active.extend_from_slice(&frame.active_calls);
    next_active.push(expansion.call_key.clone());
    state.stack.push(SearchFrame {
        remaining: next_remaining,
        subst: expansion.next_subst,
        assumptions: frame.assumptions.clone(),
        negative_guards: frame.negative_guards.clone(),
        call_depth: frame.call_depth.saturating_add(1),
        active_calls: next_active,
    });
}

fn maybe_push_abduced_branch(
    ctx: &SearchContext<'_>,
    frame: &SearchFrame,
    atom: &crate::Atom,
    rest: &[crate::Literal],
    state: &mut SearchMutable,
) {
    let is_abducible = ctx.abducibles.contains(&atom.predicate) && crate::slg::is_ground_atom(atom);
    if !is_abducible {
        return;
    }
    let is_within = atom
        .terms
        .iter()
        .all(|t| crate::slg::term_within_profile(t, ctx.metadata.terms));
    let is_fresh = !frame.assumptions.contains(atom) && !frame.negative_guards.contains(atom);
    let current_count = crate::slg::saturating_u32(frame.assumptions.len());
    if !is_within || !is_fresh || current_count >= ctx.max_assumptions {
        return;
    }
    let mut next_assumptions = frame.assumptions.clone();
    next_assumptions.insert(atom.clone());
    state.stack.push(SearchFrame {
        remaining: rest.to_vec(),
        subst: frame.subst.clone(),
        assumptions: next_assumptions,
        negative_guards: frame.negative_guards.clone(),
        call_depth: frame.call_depth,
        active_calls: frame.active_calls.clone(),
    });
}

fn extract_candidate(
    frame: &SearchFrame,
    output_vars: &[&str],
    profile: crate::TermProfile,
) -> Option<Candidate> {
    let bindings: std::collections::BTreeMap<String, crate::Term> = output_vars
        .iter()
        .map(|&var| {
            let raw = frame.subst.get(var)?;
            let resolved = crate::slg::apply_subst_term(raw, &frame.subst, profile.max_depth)?;
            if !crate::slg::is_ground_term(&resolved)
                || !crate::slg::term_within_profile(&resolved, profile)
            {
                return None;
            }
            Some((var.to_owned(), resolved))
        })
        .collect::<Option<_>>()?;
    Some(Candidate {
        bindings,
        assumptions: frame.assumptions.clone(),
        negative_guards: frame.negative_guards.clone(),
    })
}

fn filter_consistent(
    ctx: &SearchContext<'_>,
    candidates: Vec<Candidate>,
    budget: &mut crate::slg::StepBudget,
) -> Result<Vec<Candidate>, crate::slg::StopReason> {
    let denial_arities = collect_denial_arities(&ctx.request.rules);
    let mut consistent = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        budget.charge(1, ctx.control)?;
        if is_candidate_consistent(ctx, &candidate, &denial_arities, budget)? {
            consistent.push(candidate);
        }
    }
    Ok(consistent)
}

fn is_candidate_consistent(
    ctx: &SearchContext<'_>,
    candidate: &Candidate,
    denial_arities: &std::collections::BTreeSet<usize>,
    budget: &mut crate::slg::StepBudget,
) -> Result<bool, crate::slg::StopReason> {
    let extra: Vec<crate::Atom> = candidate.assumptions.iter().cloned().collect();
    let Ok(extended_db) = crate::slg::ProgramDb::from_request(ctx.image, ctx.request, &extra)
    else {
        return Ok(false);
    };
    let env = EvalEnv {
        dual: ctx.dual,
        db: &extended_db,
        profile: ctx.metadata.terms,
        control: ctx.control,
    };
    if has_denial_violation(denial_arities, &env, budget)? {
        return Ok(false);
    }
    all_negative_guards_hold(&candidate.negative_guards, &env, budget)
}

fn collect_denial_arities(rules: &[crate::Rule]) -> std::collections::BTreeSet<usize> {
    let mut arities = std::collections::BTreeSet::new();
    for rule in rules {
        if rule.head.predicate == "denial" {
            arities.insert(rule.head.terms.len());
        }
    }
    arities
}

fn has_denial_violation(
    denial_arities: &std::collections::BTreeSet<usize>,
    env: &EvalEnv<'_>,
    budget: &mut crate::slg::StepBudget,
) -> Result<bool, crate::slg::StopReason> {
    for &arity in denial_arities {
        budget.charge(1, env.control)?;
        let query = build_denial_query(arity);
        let mut slg =
            crate::slg::Engine::new(env.db, env.profile, remaining_budget(budget), env.control);
        let violations = slg.evaluate_goal(&query)?;
        budget.charge(slg.budget.used().min(1), env.control)?;
        if !violations.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn build_denial_query(arity: usize) -> crate::Atom {
    let mut terms = Vec::with_capacity(arity);
    for idx in 0..arity {
        terms.push(crate::Term::Variable(format!("_D{idx}")));
    }
    crate::Atom {
        predicate: "denial".to_owned(),
        terms,
    }
}

fn all_negative_guards_hold(
    guards: &std::collections::BTreeSet<crate::Atom>,
    env: &EvalEnv<'_>,
    budget: &mut crate::slg::StepBudget,
) -> Result<bool, crate::slg::StopReason> {
    for atom in guards {
        let verdict = evaluate_dual_negation(atom, env, budget)?;
        if verdict != DualVerdict::EstablishedAbsent {
            return Ok(false);
        }
    }
    Ok(true)
}

fn select_subset_minimal(candidates: Vec<Candidate>) -> Vec<Candidate> {
    let mut unique: Vec<Candidate> = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let is_seen = unique.iter().any(|existing| {
            existing.bindings == candidate.bindings && existing.assumptions == candidate.assumptions
        });
        if !is_seen {
            unique.push(candidate);
        }
    }
    let mut minimal = Vec::with_capacity(unique.len());
    for (idx, candidate) in unique.iter().enumerate() {
        let is_superset = unique.iter().enumerate().any(|(other_idx, other)| {
            other_idx != idx
                && other.bindings == candidate.bindings
                && other.assumptions.is_subset(&candidate.assumptions)
                && other.assumptions.len() < candidate.assumptions.len()
        });
        if !is_superset {
            minimal.push(candidate.clone());
        }
    }
    minimal.sort_by(|left, right| {
        left.assumptions
            .len()
            .cmp(&right.assumptions.len())
            .then_with(|| left.assumptions.cmp(&right.assumptions))
            .then_with(|| left.bindings.cmp(&right.bindings))
    });
    minimal
}

fn build_outcome(
    ctx: &SearchContext<'_>,
    identity: &crate::ProtocolIdentity,
    minimal: Vec<Candidate>,
    elapsed_ms: u64,
) -> Result<crate::Outcome, crate::CapabilityError> {
    let total_found = minimal.len();
    let max_solutions = ctx.request.limits.max_solutions;
    let is_truncated = total_found > max_solutions;
    let base_assumptions: std::collections::BTreeSet<String> = ctx
        .request
        .assumptions
        .iter()
        .map(|a| a.id.clone())
        .collect();
    let goal_text = crate::encode_atom(
        &ctx.request.goal,
        ctx.metadata.terms,
        ctx.metadata.limits.max_output_bytes,
    )?;

    let kept_cap = total_found.min(max_solutions);
    let mut solutions = Vec::with_capacity(kept_cap);
    let mut proposals = Vec::with_capacity(kept_cap);
    for (idx, candidate) in minimal.into_iter().take(max_solutions).enumerate() {
        let (proposal, solution) =
            package_candidate(ctx, identity, &base_assumptions, &goal_text, idx, candidate)?;
        proposals.push(proposal);
        solutions.push(solution);
    }

    let status = if is_truncated {
        crate::ExecutionStatus::Partial
    } else {
        crate::ExecutionStatus::Complete
    };
    let stop = if is_truncated {
        crate::SearchStop::ResultLimit
    } else {
        crate::SearchStop::Exhausted
    };
    let is_exhaustive = !is_truncated && ctx.image.coverage.complete;
    let outcome = crate::Outcome {
        status,
        mode: ctx.request.mode.clone(),
        operation_completed: true,
        stop,
        exhaustive: is_exhaustive,
        coverage: ctx.image.coverage.clone(),
        context: ctx.image.context.clone(),
        identity: identity.clone(),
        result: crate::QueryResult::Collect { solutions },
        proposals,
        consumed: crate::ConsumedLimits {
            elapsed_ms,
            solutions: total_found,
            output_bytes: 0,
        },
        output_limit_exceeded: false,
        solution_limit_exceeded: is_truncated,
        readback_valid: true,
        reason: is_truncated.then(|| "solution limit reached".to_owned()),
    };
    outcome.validate_for_request(ctx.request)?;
    Ok(outcome)
}

#[allow(unknown_lints, too_many_parameters)] // internal packaging helper
fn package_candidate(
    ctx: &SearchContext<'_>,
    identity: &crate::ProtocolIdentity,
    base_assumptions: &std::collections::BTreeSet<String>,
    goal_text: &str,
    idx: usize,
    candidate: Candidate,
) -> Result<(crate::Proposal, crate::Solution), crate::CapabilityError> {
    let mut assumption_names = base_assumptions.clone();
    let mut actions = Vec::with_capacity(candidate.assumptions.len());
    let mut preconditions = Vec::with_capacity(candidate.assumptions.len());
    for atom in &candidate.assumptions {
        let rendered = crate::encode_atom(
            atom,
            ctx.metadata.terms,
            ctx.metadata.limits.max_output_bytes,
        )?;
        assumption_names.insert(rendered.clone());
        let parameters = build_action_parameters(&atom.terms);
        actions.push(crate::PlanAction {
            action: format!("assume:{}", atom.predicate),
            parameters,
        });
        preconditions.push(crate::Precondition {
            description: rendered,
            atom: Some(atom.clone()),
            evidence: Vec::new(),
        });
    }
    let plan_id = format!(
        "abduce-plan-{idx:04}-{}",
        short_digest(&identity.request_digest)
    );
    let proposal = crate::Proposal::Plan(crate::PlanProposal {
        id: plan_id,
        base_revision: ctx.request.revision,
        scope: ctx.request.scope.clone(),
        actions,
        preconditions,
        assumptions: assumption_names.clone(),
        evidence: Vec::new(),
        expected_effects: vec![format!("satisfies:{goal_text}")],
    });
    let solution = crate::Solution {
        bindings: candidate.bindings,
        premises: Vec::new(),
        assumptions: assumption_names,
        certification: crate::Certification::Uncertified {
            reason: "abduced preconditions remain Proposed until accepted via PlanRegistry::accept"
                .to_owned(),
        },
        epistemic: mneme_datalog::EpistemicStatus::Proposed,
        proof: None,
    };
    Ok((proposal, solution))
}

fn build_action_parameters(
    terms: &[crate::Term],
) -> std::collections::BTreeMap<String, crate::Term> {
    terms
        .iter()
        .enumerate()
        .map(|(arg_idx, term)| (format!("arg{arg_idx}"), term.clone()))
        .collect()
}

fn short_digest(digest: &str) -> &str {
    let trimmed = digest.strip_prefix("sha256:").unwrap_or(digest);
    trimmed.get(..12).unwrap_or(trimmed)
}

fn cancelled_outcome(
    image: &crate::snapshot::InputImage,
    request: &crate::Request,
    identity: &crate::ProtocolIdentity,
) -> crate::Outcome {
    crate::Outcome {
        status: crate::ExecutionStatus::Cancelled,
        mode: request.mode.clone(),
        operation_completed: false,
        stop: crate::SearchStop::Cancelled,
        exhaustive: false,
        coverage: image.coverage.clone(),
        context: image.context.clone(),
        identity: identity.clone(),
        result: crate::QueryResult::Collect {
            solutions: Vec::new(),
        },
        proposals: Vec::new(),
        consumed: crate::ConsumedLimits {
            elapsed_ms: 0,
            solutions: 0,
            output_bytes: 0,
        },
        output_limit_exceeded: false,
        solution_limit_exceeded: false,
        readback_valid: false,
        reason: Some("abductive search cancelled".to_owned()),
    }
}

fn timeout_outcome(
    image: &crate::snapshot::InputImage,
    request: &crate::Request,
    identity: &crate::ProtocolIdentity,
    elapsed_ms: u64,
) -> crate::Outcome {
    crate::Outcome {
        status: crate::ExecutionStatus::Timeout,
        mode: request.mode.clone(),
        operation_completed: false,
        stop: crate::SearchStop::Timeout,
        exhaustive: false,
        coverage: image.coverage.clone(),
        context: image.context.clone(),
        identity: identity.clone(),
        result: crate::QueryResult::Collect {
            solutions: Vec::new(),
        },
        proposals: Vec::new(),
        consumed: crate::ConsumedLimits {
            elapsed_ms,
            solutions: 0,
            output_bytes: 0,
        },
        output_limit_exceeded: false,
        solution_limit_exceeded: false,
        readback_valid: false,
        reason: Some("abductive step budget exhausted".to_owned()),
    }
}
