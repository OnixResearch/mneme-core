//! Well-founded groundedness reachability, Hansson finite-base kernel
//! contraction, and Levi-identity belief-revision planning.
//!
//! All core groundedness and entrenchment-incision decisions delegate to the
//! Lean 4–proved functions in [`mneme_kernel::contraction`].

/// Default ancestry node budget for bounded kernel enumeration (matches
/// `mneme_memory::beliefs::MAX_ANCESTRY_NODES`).
pub const MAX_ANCESTRY_NODES: u64 = 1_000_000;

/// Maximum number of minimal kernels retained during bounded enumeration.
const MAX_MINIMAL_KERNELS: usize = 4_096;

/// Identity a corroboration root is counted by: exact content digest when
/// known, falling back to `(RecordId, RevisionId)` when bytes are absent.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum RootIdentity {
    Digest(mneme_core::ContentDigest),
    Revision((mneme_core::RecordId, mneme_core::RevisionId)),
}

/// Entrenchment ranking metadata for one candidate base record in `B ⊥ φ`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PremiseEntrenchment {
    /// Candidate base record identifier.
    pub record_id: mneme_core::RecordId,
    /// Epistemic origin tier (`ModelExtraction < Imported < Authored`).
    pub origin: mneme_kernel::contraction::OriginTier,
    /// Count of distinct surviving `RootIdentity` corroborations.
    pub root_count: u64,
    /// Whether the deterministic incision `σ` selected this premise for removal.
    pub incised: bool,
}

/// Inspectable Hansson kernel-contraction report attached to a [`crate::Plan`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelReport {
    /// Primary contracted target assertion (`φ`), or `None` for empty conflict set.
    pub target: Option<mneme_core::RecordId>,
    /// All inclusion-minimal `φ`-kernels (`B ⊥ φ`), sorted canonically.
    pub kernels: Vec<Vec<mneme_core::RecordId>>,
    /// Base premises selected by epistemic-entrenchment incision `σ(B ⊥ φ)`.
    pub incised_premises: Vec<mneme_core::RecordId>,
    /// Entrenchment ranking details for every base record appearing in any kernel.
    pub entrenchment: Vec<PremiseEntrenchment>,
    /// Independent downstream derivations that remain grounded after incision.
    pub surviving_derivations: Vec<mneme_core::RecordId>,
    /// Nodes charged against the ancestry budget during kernel enumeration.
    pub visited_nodes: u64,
}

/// Proposed new assertion `+φ` paired with minimal contraction `B ÷_σ ¬φ`
/// under the Levi identity `B * φ = (B ÷_σ ¬φ) + φ`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposedAssertionSpec {
    /// Subject entity identifier.
    pub subject: mneme_core::RecordId,
    /// Predicate name.
    pub predicate: String,
    /// Proposed assertion value.
    pub value: mneme_core::Value,
    /// Proposed epistemic stance.
    pub stance: mneme_memory::Stance,
    /// Declared origin of the proposed assertion.
    pub origin: mneme_core::Origin,
}

/// Request to build a strictly read-only Levi-identity revision plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevisionRequest {
    pub actor: String,
    pub scope: mneme_core::ScopeId,
    pub base_revision: mneme_core::WorkspaceRevisionId,
    pub idempotency_key: String,
    /// Explicit assertion IDs to contract (`¬φ` or falsified conclusions).
    pub contract_targets: Vec<mneme_core::RecordId>,
    /// Optional proposed new assertion (`+φ`) under the Levi identity.
    pub proposed: Option<ProposedAssertionSpec>,
    pub policy: crate::Policy,
    /// Optional ancestry node budget override; defaults to `MAX_ANCESTRY_NODES`.
    pub max_ancestry_nodes: Option<u64>,
}

/// Reviewable, non-mutating plan for a Levi-identity belief revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevisionPlan {
    /// Underlying retention plan carrying incision drafts and downstream impact.
    pub plan: crate::Plan,
    /// All conflicting assertions contracted (explicit targets + discovered conflicts).
    pub conflicting_assertions: Vec<mneme_core::RecordId>,
    /// Detailed Hansson kernel-contraction analysis.
    pub report: KernelReport,
    /// Proposed new assertion `+φ` (never auto-committed by planning).
    pub proposed: Option<ProposedAssertionSpec>,
}

/// Downstream impact of retracting or incising a set of base records.
pub(crate) struct DownstreamImpact {
    pub(crate) invalidated_derivations: Vec<mneme_core::RecordId>,
    pub(crate) surviving_derivations: Vec<mneme_core::RecordId>,
    pub(crate) surviving_assertions: Vec<mneme_core::RecordId>,
}

/// Compiled support hypergraph over a snapshot for well-founded groundedness.
struct GroundedHypergraph {
    index_of: std::collections::BTreeMap<mneme_core::RecordId, usize>,
    edges: Vec<mneme_kernel::contraction::SupportEdge>,
    premises: Vec<usize>,
    grounded: Vec<bool>,
}

/// Compute the greatest well-founded grounded set of records reachable from
/// surviving non-withdrawn `RootIdentity` leaves, excluding `excluded_sources`
/// and `excluded_records`.
pub(crate) fn compute_grounded_set(
    context: &crate::PlanContext<'_>,
    excluded_sources: &std::collections::BTreeSet<mneme_core::RecordId>,
    excluded_records: &std::collections::BTreeSet<mneme_core::RecordId>,
) -> crate::Result<std::collections::BTreeSet<mneme_core::RecordId>> {
    let mut graph = build_hypergraph(context, excluded_sources, excluded_records)?;
    let node_count = graph.grounded.len();
    for _ in 0..node_count {
        let is_changed = run_grounding_pass(&graph.edges, &graph.premises, &mut graph.grounded);
        if !is_changed {
            break;
        }
    }
    let mut grounded_ids = std::collections::BTreeSet::new();
    for (idx, record) in context.records.iter().enumerate() {
        if graph.grounded.get(idx).copied().unwrap_or(false) {
            grounded_ids.insert(record.record_id);
        }
    }
    Ok(grounded_ids)
}

/// Run one monotone pass of [`mneme_kernel::contraction::edge_is_grounded`].
fn run_grounding_pass(
    edges: &[mneme_kernel::contraction::SupportEdge],
    premises: &[usize],
    grounded: &mut [bool],
) -> bool {
    let mut is_changed = false;
    for edge in edges {
        let is_target_open = edge.target < grounded.len() && !grounded[edge.target];
        if is_target_open && mneme_kernel::contraction::edge_is_grounded(edge, premises, grounded) {
            grounded[edge.target] = true;
            is_changed = true;
        }
    }
    is_changed
}

/// Build the finite support hypergraph over `context.records`.
fn build_hypergraph(
    context: &crate::PlanContext<'_>,
    excluded_sources: &std::collections::BTreeSet<mneme_core::RecordId>,
    excluded_records: &std::collections::BTreeSet<mneme_core::RecordId>,
) -> crate::Result<GroundedHypergraph> {
    let node_count = context.records.len();
    let index_of: std::collections::BTreeMap<mneme_core::RecordId, usize> = context
        .records
        .iter()
        .enumerate()
        .map(|(idx, record)| (record.record_id, idx))
        .collect();
    let mut graph = GroundedHypergraph {
        index_of,
        edges: Vec::new(),
        premises: Vec::new(),
        grounded: vec![false; node_count],
    };
    for (idx, record) in context.records.iter().enumerate() {
        let is_excluded = excluded_sources.contains(&record.record_id)
            || excluded_records.contains(&record.record_id)
            || is_already_withdrawn(context, record);
        if !is_excluded {
            register_record_edges(context, idx, record, &mut graph)?;
        }
    }
    Ok(graph)
}

/// Whether `record` is already suppressed as withdrawn in the current snapshot.
fn is_already_withdrawn(
    context: &crate::PlanContext<'_>,
    record: &mneme_core::RecordEnvelope,
) -> bool {
    context
        .view
        .suppression_for(record)
        .is_some_and(|suppression| suppression.mode == mneme_store::SuppressionMode::Withdrawn)
}

/// Register root-leaf status or conjunctive hyperedges for one record.
fn register_record_edges(
    context: &crate::PlanContext<'_>,
    idx: usize,
    record: &mneme_core::RecordEnvelope,
    graph: &mut GroundedHypergraph,
) -> crate::Result<()> {
    match record.kind {
        mneme_core::RecordKind::SourceRevision => register_source_edge(context, idx, record, graph),
        mneme_core::RecordKind::Episode => register_episode_edge(context, idx, record, graph),
        mneme_core::RecordKind::Evidence => register_evidence_edge(context, idx, record, graph),
        mneme_core::RecordKind::Derivation => register_derivation_edge(context, idx, record, graph),
        mneme_core::RecordKind::Assertion => register_assertion_edges(context, idx, record, graph),
        mneme_core::RecordKind::Entity
        | mneme_core::RecordKind::Relation
        | mneme_core::RecordKind::Checkpoint
        | mneme_core::RecordKind::Proposal
        | mneme_core::RecordKind::Decision
        | mneme_core::RecordKind::RetentionDirective
        | mneme_core::RecordKind::Document
        | mneme_core::RecordKind::DocumentAnchor
        | mneme_core::RecordKind::DocumentBinding
        | mneme_core::RecordKind::Comment
        | mneme_core::RecordKind::RecognitionRun
        | mneme_core::RecordKind::RecognitionSegment => {
            graph.grounded[idx] = true;
            Ok(())
        }
    }
}

fn register_source_edge(
    context: &crate::PlanContext<'_>,
    idx: usize,
    record: &mneme_core::RecordEnvelope,
    graph: &mut GroundedHypergraph,
) -> crate::Result<()> {
    let source = context.view.source(record.record_id)?;
    match crate::foreign_parent(context, record.record_id, source)? {
        None => {
            graph.grounded[idx] = true;
        }
        Some(parent) => {
            push_hyperedge(graph, idx, &[parent]);
        }
    }
    Ok(())
}

fn register_episode_edge(
    context: &crate::PlanContext<'_>,
    idx: usize,
    record: &mneme_core::RecordEnvelope,
    graph: &mut GroundedHypergraph,
) -> crate::Result<()> {
    let episode = context.view.episode(record.record_id)?;
    let mut deps = Vec::with_capacity(episode.related.len().saturating_add(1));
    if let Some(source) = episode.source {
        deps.push(source);
    }
    deps.extend(episode.related.iter().copied());
    if deps.is_empty() {
        graph.grounded[idx] = true;
    } else {
        push_hyperedge(graph, idx, &deps);
    }
    Ok(())
}

fn register_evidence_edge(
    context: &crate::PlanContext<'_>,
    idx: usize,
    record: &mneme_core::RecordEnvelope,
    graph: &mut GroundedHypergraph,
) -> crate::Result<()> {
    let evidence = context.view.evidence(record.record_id)?;
    let mut deps = Vec::with_capacity(evidence.ancestry.len().saturating_add(1));
    deps.push(evidence.source);
    deps.extend(evidence.ancestry.iter().copied());
    push_hyperedge(graph, idx, &deps);
    Ok(())
}

fn register_derivation_edge(
    context: &crate::PlanContext<'_>,
    idx: usize,
    record: &mneme_core::RecordEnvelope,
    graph: &mut GroundedHypergraph,
) -> crate::Result<()> {
    let derivation = context.view.derivation(record.record_id)?;
    if !derivation.premises.is_empty() && derivation.completeness == "complete" {
        let deps: Vec<mneme_core::RecordId> = derivation.premises.iter().copied().collect();
        push_hyperedge(graph, idx, &deps);
    }
    Ok(())
}

fn register_assertion_edges(
    context: &crate::PlanContext<'_>,
    idx: usize,
    record: &mneme_core::RecordEnvelope,
    graph: &mut GroundedHypergraph,
) -> crate::Result<()> {
    let assertion = context.view.assertion(record.record_id)?;
    if assertion.lifecycle == mneme_core::Lifecycle::Retracted {
        return Ok(());
    }
    for evidence_id in &assertion.evidence {
        let is_supporting = context.view.evidence(*evidence_id).is_ok_and(|ev| {
            ev.relation == mneme_memory::SupportRelation::Supports
                && ev.assertion == record.record_id
        });
        if is_supporting {
            push_hyperedge(graph, idx, &[*evidence_id]);
        }
    }
    if let Some(derivation_ids) = context.derivations.get(&record.record_id) {
        for derivation_id in derivation_ids {
            push_hyperedge(graph, idx, &[*derivation_id]);
        }
    }
    Ok(())
}

/// Append one conjunctive hyperedge into `graph`, mapping missing nodes to an
/// out-of-bounds sentinel so incomplete edges never fire.
fn push_hyperedge(graph: &mut GroundedHypergraph, target: usize, dep_ids: &[mneme_core::RecordId]) {
    let sentinel = graph.grounded.len();
    let start = graph.premises.len();
    for dep in dep_ids {
        let dep_idx = graph.index_of.get(dep).copied().unwrap_or(sentinel);
        graph.premises.push(dep_idx);
    }
    graph.edges.push(mneme_kernel::contraction::SupportEdge {
        target,
        premises: mneme_kernel::contraction::RangeSpan {
            start,
            len: dep_ids.len(),
        },
    });
}

/// Compute well-founded withdrawal for `sources` over `deps` in `scope`:
/// every dependent record not in the greatest grounded set rooted at surviving
/// non-withdrawn `RootIdentity` leaves is withdrawn.
pub(crate) fn compute_well_founded_withdrawal(
    context: &crate::PlanContext<'_>,
    sources: &[mneme_core::RecordId],
    deps: &crate::Dependencies,
    scope: &mneme_core::ScopeId,
) -> crate::Result<std::collections::BTreeSet<mneme_core::RecordId>> {
    let excluded_sources: std::collections::BTreeSet<mneme_core::RecordId> =
        sources.iter().copied().collect();
    let empty_records = std::collections::BTreeSet::new();
    let grounded = compute_grounded_set(context, &excluded_sources, &empty_records)?;
    let mut withdrawn = excluded_sources;
    for id in &deps.derived_sources {
        if !grounded.contains(id) {
            withdrawn.insert(*id);
        }
    }
    for id in &deps.episodes {
        if !grounded.contains(id) {
            withdrawn.insert(*id);
        }
    }
    for id in &deps.evidence {
        if !grounded.contains(id) {
            withdrawn.insert(*id);
        }
    }
    for id in &deps.derivations {
        if !grounded.contains(id) {
            withdrawn.insert(*id);
        }
    }
    for id in &deps.assertions {
        let is_in_scope_assertion = context.by_id.get(id).is_some_and(|record| {
            record.kind == mneme_core::RecordKind::Assertion && &record.scope == scope
        });
        if is_in_scope_assertion && !grounded.contains(id) {
            withdrawn.insert(*id);
        }
    }
    Ok(withdrawn)
}

/// Compute downstream derivations invalidated vs. surviving after retracting
/// `retracted_ids`, preserving downstream conclusions with independent proofs.
pub(crate) fn downstream_impact_after_retraction(
    context: &crate::PlanContext<'_>,
    retracted_ids: &std::collections::BTreeSet<mneme_core::RecordId>,
    scope: &mneme_core::ScopeId,
) -> crate::Result<DownstreamImpact> {
    let mut downstream_nodes = retracted_ids.clone();
    let mut downstream_derivations = std::collections::BTreeSet::new();
    let mut downstream_assertions = std::collections::BTreeSet::new();
    let bound = context.records.len().saturating_add(1);
    for _ in 0..bound {
        let mut is_changed = false;
        for record in context.records {
            if record.kind != mneme_core::RecordKind::Derivation
                || &record.scope != scope
                || downstream_derivations.contains(&record.record_id)
            {
                continue;
            }
            let derivation = context.view.derivation(record.record_id)?;
            if derivation
                .premises
                .iter()
                .any(|premise| downstream_nodes.contains(premise))
            {
                downstream_derivations.insert(record.record_id);
                downstream_nodes.insert(record.record_id);
                downstream_nodes.insert(derivation.conclusion);
                if !retracted_ids.contains(&derivation.conclusion) {
                    downstream_assertions.insert(derivation.conclusion);
                }
                is_changed = true;
            }
        }
        if !is_changed {
            break;
        }
    }
    let empty_sources = std::collections::BTreeSet::new();
    let grounded_after = compute_grounded_set(context, &empty_sources, retracted_ids)?;
    let mut invalidated_derivations = Vec::with_capacity(downstream_derivations.len());
    let mut surviving_derivations = Vec::with_capacity(downstream_derivations.len());
    for deriv_id in downstream_derivations {
        if grounded_after.contains(&deriv_id) {
            surviving_derivations.push(deriv_id);
        } else {
            invalidated_derivations.push(deriv_id);
        }
    }
    let surviving_assertions = downstream_assertions
        .into_iter()
        .filter(|assertion_id| grounded_after.contains(assertion_id))
        .collect();
    Ok(DownstreamImpact {
        invalidated_derivations,
        surviving_derivations,
        surviving_assertions,
    })
}

/// Plan an [`crate::OperationKind::KernelContract`] operation for one target
/// assertion `φ`.
pub(crate) fn plan_kernel_incision(
    context: &crate::PlanContext<'_>,
    request: &crate::Request,
    plan: &mut crate::Plan,
) -> crate::Result<()> {
    let crate::Selector::Assertion(target_id) = request.selector else {
        return Err(crate::PolicyError::Invalid(
            "kernel contraction requires an assertion selector",
        ));
    };
    let assertion = context
        .view
        .assertion(target_id)
        .map_err(crate::map_missing)?;
    crate::require_in_scope(&assertion.record, &request.scope)?;
    let report = apply_incision_targets(context, request, &[target_id], MAX_ANCESTRY_NODES, plan)?;
    plan.contraction = Some(report);
    Ok(())
}

/// Plan a strictly non-mutating Levi-identity revision `B * φ = (B ÷_σ ¬φ) + φ`.
pub(crate) fn build_revision_plan(
    workspace: &mneme_store::Workspace,
    view: &mneme_memory::View,
    request: &RevisionRequest,
) -> crate::Result<RevisionPlan> {
    if request.actor.trim().is_empty() || request.actor.len() > 128 {
        return Err(crate::PolicyError::Invalid("actor is empty or too long"));
    }
    if request.idempotency_key.trim().is_empty() || request.idempotency_key.len() > 256 {
        return Err(crate::PolicyError::Invalid(
            "idempotency key is empty or too long",
        ));
    }
    if request.policy.version.trim().is_empty() {
        return Err(crate::PolicyError::Invalid("policy version is empty"));
    }
    if request.contract_targets.is_empty() && request.proposed.is_none() {
        return Err(crate::PolicyError::Invalid(
            "revision requires at least one contract target or a proposed assertion",
        ));
    }
    let context = crate::PlanContext::new(view)?;
    let empty = std::collections::BTreeSet::new();
    let grounded = compute_grounded_set(&context, &empty, &empty)?;
    let conflicting_assertions = collect_conflicting_targets(&context, &grounded, request)?;
    let primary_target = conflicting_assertions
        .first()
        .copied()
        .or_else(|| request.proposed.as_ref().map(|spec| spec.subject))
        .ok_or(crate::PolicyError::Invalid(
            "revision target could not be resolved",
        ))?;
    let retention_request = crate::Request {
        actor: request.actor.clone(),
        scope: request.scope.clone(),
        base_revision: request.base_revision,
        idempotency_key: request.idempotency_key.clone(),
        operation: crate::OperationKind::KernelContract,
        selector: crate::Selector::Assertion(primary_target),
        effective: None,
        policy: request.policy.clone(),
    };
    let operation_id = format!("retention-{}", mneme_store::payload::random_hex(16)?);
    let generation = workspace.eligibility_generation()?.saturating_add(1);
    let mut plan = crate::empty_plan(operation_id, &retention_request, generation);
    let budget = request.max_ancestry_nodes.unwrap_or(MAX_ANCESTRY_NODES);
    let report = apply_incision_targets(
        &context,
        &retention_request,
        &conflicting_assertions,
        budget,
        &mut plan,
    )?;
    plan.contraction = Some(report.clone());
    crate::finalize_plan(workspace, &mut plan)?;
    Ok(RevisionPlan {
        plan,
        conflicting_assertions,
        report,
        proposed: request.proposed.clone(),
    })
}

/// Collect all explicit contract targets and grounded assertions conflicting
/// with `request.proposed`.
fn collect_conflicting_targets(
    context: &crate::PlanContext<'_>,
    grounded: &std::collections::BTreeSet<mneme_core::RecordId>,
    request: &RevisionRequest,
) -> crate::Result<Vec<mneme_core::RecordId>> {
    let mut targets = std::collections::BTreeSet::new();
    for target_id in &request.contract_targets {
        let assertion = context
            .view
            .assertion(*target_id)
            .map_err(crate::map_missing)?;
        crate::require_in_scope(&assertion.record, &request.scope)?;
        targets.insert(*target_id);
    }
    if let Some(proposed) = &request.proposed {
        for record in context.records {
            if record.kind != mneme_core::RecordKind::Assertion || record.scope != request.scope {
                continue;
            }
            if !grounded.contains(&record.record_id) {
                continue;
            }
            let assertion = context.view.assertion(record.record_id)?;
            if assertion_conflicts(&assertion, proposed) {
                targets.insert(record.record_id);
            }
        }
    }
    Ok(targets.into_iter().collect())
}

/// Whether an existing grounded assertion conflicts with `proposed`.
fn assertion_conflicts(
    existing: &mneme_memory::AssertionView,
    proposed: &ProposedAssertionSpec,
) -> bool {
    if existing.subject != proposed.subject || existing.predicate != proposed.predicate {
        return false;
    }
    if matches!(
        existing.lifecycle,
        mneme_core::Lifecycle::Retracted | mneme_core::Lifecycle::Superseded
    ) {
        return false;
    }
    match (proposed.stance, existing.stance) {
        (mneme_memory::Stance::Affirm, mneme_memory::Stance::Affirm) => {
            existing.value != proposed.value
        }
        (mneme_memory::Stance::Affirm, mneme_memory::Stance::Deny)
        | (mneme_memory::Stance::Deny, mneme_memory::Stance::Affirm) => {
            existing.value == proposed.value
        }
        (mneme_memory::Stance::Deny, mneme_memory::Stance::Deny)
        | (mneme_memory::Stance::Hypothesis, _)
        | (_, mneme_memory::Stance::Hypothesis) => false,
    }
}

/// Enumerate bounded minimal kernels for `targets`, compute the Lean-verified
/// entrenchment incision `σ`, and populate `plan`.
fn apply_incision_targets(
    context: &crate::PlanContext<'_>,
    request: &crate::Request,
    targets: &[mneme_core::RecordId],
    max_ancestry_nodes: u64,
    plan: &mut crate::Plan,
) -> crate::Result<KernelReport> {
    let empty = std::collections::BTreeSet::new();
    let grounded_before = compute_grounded_set(context, &empty, &empty)?;
    let (kernels, visited_nodes) = enumerate_minimal_kernels(
        context,
        &grounded_before,
        targets,
        &request.scope,
        max_ancestry_nodes,
    )?;
    let (incised_premises, entrenchment) =
        compute_entrenchment_incision(context, &grounded_before, &kernels)?;
    let incised_set: std::collections::BTreeSet<mneme_core::RecordId> =
        incised_premises.iter().copied().collect();
    emit_incision_drafts(context, request, &incised_premises, plan)?;
    let impact = downstream_impact_after_retraction(context, &incised_set, &request.scope)?;
    plan.invalidated_derivations = impact.invalidated_derivations;
    plan.surviving_assertions = impact.surviving_assertions;
    plan.retained_metadata
        .push("hansson-kernel-contraction".to_owned());
    plan.retained_metadata
        .push("withdrawn-assertion-history".to_owned());
    plan.limitations
        .push("kernel-contraction-requires-explicit-apply".to_owned());
    Ok(KernelReport {
        target: targets.first().copied(),
        kernels,
        incised_premises,
        entrenchment,
        surviving_derivations: impact.surviving_derivations,
        visited_nodes,
    })
}

/// Emit retraction or withdrawal drafts for each incised base premise.
fn emit_incision_drafts(
    context: &crate::PlanContext<'_>,
    request: &crate::Request,
    incised_premises: &[mneme_core::RecordId],
    plan: &mut crate::Plan,
) -> crate::Result<()> {
    for premise_id in incised_premises {
        let Some(envelope) = context.by_id.get(premise_id) else {
            continue;
        };
        if envelope.kind == mneme_core::RecordKind::Assertion {
            let assertion = context.view.assertion(*premise_id)?;
            if assertion.lifecycle == mneme_core::Lifecycle::Retracted {
                continue;
            }
            let decision_id = crate::fresh_id()?;
            let decision = mneme_memory::build_decision(
                decision_id,
                crate::fresh_revision()?,
                &assertion.record.scope,
                mneme_memory::DecisionOptions {
                    kind: mneme_memory::DecisionKind::Retraction,
                    target: *premise_id,
                    actor: &request.actor,
                    policy: &request.policy.version,
                    input_revision: request.base_revision,
                    outcome: "retracted",
                    rationale: "hansson kernel contraction epistemic-entrenchment incision",
                    evidence: &[],
                    related: &[],
                },
            );
            let retracted = mneme_memory::build_assertion_revision(
                &assertion.record,
                crate::fresh_revision()?,
                mneme_core::Lifecycle::Retracted,
                mneme_core::Reference::local(decision_id, mneme_core::RecordKind::Decision),
                None,
            );
            plan.records.push(decision);
            plan.records.push(retracted);
            plan.retracted_assertions.push(*premise_id);
        } else {
            plan.suppressed.push(crate::PlannedSuppression {
                target: *premise_id,
                revision: None,
                kind: envelope.kind,
                mode: mneme_store::SuppressionMode::Withdrawn,
                content_digest: None,
            });
        }
    }
    Ok(())
}

/// Pending obligation in iterative minimal-kernel search.
struct ProofGoal {
    pending: Vec<(
        mneme_core::RecordId,
        std::collections::BTreeSet<mneme_core::RecordId>,
    )>,
    leaves: std::collections::BTreeSet<mneme_core::RecordId>,
}

/// Shared read-only context and mutable accumulators for iterative kernel search.
struct KernelSearch<'a> {
    context: &'a crate::PlanContext<'a>,
    grounded: &'a std::collections::BTreeSet<mneme_core::RecordId>,
    scope: &'a mneme_core::ScopeId,
    minimal_sets: Vec<std::collections::BTreeSet<mneme_core::RecordId>>,
    worklist: Vec<ProofGoal>,
}

/// Iteratively enumerate all inclusion-minimal acyclic proofs of any target in
/// `targets`, charging `mneme_kernel::budget::charge` against `max_nodes`.
///
/// Fails closed with [`mneme_memory::EvidenceError::Truncated`] when the
/// budget is exceeded.
fn enumerate_minimal_kernels(
    context: &crate::PlanContext<'_>,
    grounded: &std::collections::BTreeSet<mneme_core::RecordId>,
    targets: &[mneme_core::RecordId],
    scope: &mneme_core::ScopeId,
    max_nodes: u64,
) -> crate::Result<(Vec<Vec<mneme_core::RecordId>>, u64)> {
    let mut worklist = Vec::with_capacity(targets.len());
    for target in targets {
        if grounded.contains(target) {
            worklist.push(ProofGoal {
                pending: vec![(*target, std::collections::BTreeSet::new())],
                leaves: std::collections::BTreeSet::new(),
            });
        }
    }
    let mut search = KernelSearch {
        context,
        grounded,
        scope,
        minimal_sets: Vec::new(),
        worklist,
    };
    let mut used = 0_u64;
    let step_limit = usize::try_from(max_nodes)
        .map_err(|_| crate::PolicyError::Policy("ancestry budget exceeds platform limit"))?
        .saturating_add(1);
    for _ in 0..step_limit {
        let Some(goal) = search.worklist.pop() else {
            break;
        };
        let Some(next_used) = mneme_kernel::budget::charge(used, 1, max_nodes) else {
            return Err(crate::PolicyError::Engine(
                mneme_memory::EvidenceError::Truncated,
            ));
        };
        used = next_used;
        expand_proof_goal(&mut search, goal)?;
        if search.minimal_sets.len() > MAX_MINIMAL_KERNELS {
            return Err(crate::PolicyError::Engine(
                mneme_memory::EvidenceError::Truncated,
            ));
        }
    }
    if !search.worklist.is_empty() {
        return Err(crate::PolicyError::Engine(
            mneme_memory::EvidenceError::Truncated,
        ));
    }
    let mut kernels: Vec<Vec<mneme_core::RecordId>> = search
        .minimal_sets
        .into_iter()
        .map(|set| set.into_iter().collect())
        .collect();
    kernels.sort();
    Ok((kernels, used))
}

fn expand_proof_goal(search: &mut KernelSearch<'_>, mut goal: ProofGoal) -> crate::Result<()> {
    if is_subsumed(&goal.leaves, &search.minimal_sets) {
        return Ok(());
    }
    let Some((node, path)) = goal.pending.pop() else {
        insert_minimal_kernel(goal.leaves, &mut search.minimal_sets);
        return Ok(());
    };
    if path.contains(&node) || !search.grounded.contains(&node) {
        return Ok(());
    }
    if goal.leaves.contains(&node) {
        search.worklist.push(goal);
        return Ok(());
    }
    let Some(envelope) = search.context.by_id.get(&node) else {
        return Ok(());
    };
    if &envelope.scope != search.scope {
        return Ok(());
    }
    let mut next_path = path;
    next_path.insert(node);
    if has_direct_base_support(search.context, search.grounded, envelope)? {
        let mut leaves = goal.leaves.clone();
        leaves.insert(node);
        if !is_subsumed(&leaves, &search.minimal_sets) {
            search.worklist.push(ProofGoal {
                pending: goal.pending.clone(),
                leaves,
            });
        }
    }
    if envelope.kind == mneme_core::RecordKind::Assertion {
        push_derivation_branches(search, node, &next_path, &goal)?;
    }
    Ok(())
}

/// Push one branch onto `search.worklist` for each grounded in-scope derivation of `node`.
fn push_derivation_branches(
    search: &mut KernelSearch<'_>,
    node: mneme_core::RecordId,
    next_path: &std::collections::BTreeSet<mneme_core::RecordId>,
    goal: &ProofGoal,
) -> crate::Result<()> {
    let Some(derivation_ids) = search.context.derivations.get(&node) else {
        return Ok(());
    };
    for deriv_id in derivation_ids {
        if !search.grounded.contains(deriv_id) {
            continue;
        }
        let Some(deriv_env) = search.context.by_id.get(deriv_id) else {
            continue;
        };
        if &deriv_env.scope != search.scope {
            continue;
        }
        let derivation = search.context.view.derivation(*deriv_id)?;
        let is_cyclic_or_ungrounded = derivation
            .premises
            .iter()
            .any(|premise| next_path.contains(premise) || !search.grounded.contains(premise));
        if is_cyclic_or_ungrounded || derivation.premises.is_empty() {
            continue;
        }
        let mut next_pending = goal.pending.clone();
        for premise in derivation.premises.iter().rev() {
            next_pending.push((*premise, next_path.clone()));
        }
        search.worklist.push(ProofGoal {
            pending: next_pending,
            leaves: goal.leaves.clone(),
        });
    }
    Ok(())
}

/// Whether `envelope` is a grounded base record (an episode, or an assertion
/// directly supported by at least one grounded `Supports` evidence item).
fn has_direct_base_support(
    context: &crate::PlanContext<'_>,
    grounded: &std::collections::BTreeSet<mneme_core::RecordId>,
    envelope: &mneme_core::RecordEnvelope,
) -> crate::Result<bool> {
    if envelope.kind == mneme_core::RecordKind::Episode {
        return Ok(true);
    }
    if envelope.kind != mneme_core::RecordKind::Assertion {
        return Ok(false);
    }
    let assertion = context.view.assertion(envelope.record_id)?;
    let has_support = assertion.evidence.iter().any(|evidence_id| {
        grounded.contains(evidence_id)
            && context.view.evidence(*evidence_id).is_ok_and(|ev| {
                ev.relation == mneme_memory::SupportRelation::Supports
                    && ev.assertion == envelope.record_id
            })
    });
    Ok(has_support)
}

fn is_subsumed(
    candidate: &std::collections::BTreeSet<mneme_core::RecordId>,
    minimal_sets: &[std::collections::BTreeSet<mneme_core::RecordId>],
) -> bool {
    minimal_sets
        .iter()
        .any(|existing| existing.is_subset(candidate))
}

fn insert_minimal_kernel(
    candidate: std::collections::BTreeSet<mneme_core::RecordId>,
    minimal_sets: &mut Vec<std::collections::BTreeSet<mneme_core::RecordId>>,
) {
    if candidate.is_empty() || is_subsumed(&candidate, minimal_sets) {
        return;
    }
    minimal_sets.retain(|existing| !candidate.is_subset(existing));
    minimal_sets.push(candidate);
}

/// Apply the Lean 4–proved epistemic-entrenchment incision from
/// [`mneme_kernel::contraction`] over `kernels`.
fn compute_entrenchment_incision(
    context: &crate::PlanContext<'_>,
    grounded: &std::collections::BTreeSet<mneme_core::RecordId>,
    kernels: &[Vec<mneme_core::RecordId>],
) -> crate::Result<(Vec<mneme_core::RecordId>, Vec<PremiseEntrenchment>)> {
    let candidate_ids: std::collections::BTreeSet<mneme_core::RecordId> = kernels
        .iter()
        .flat_map(|kernel| kernel.iter().copied())
        .collect();
    let keys_by_id: std::collections::BTreeMap<
        mneme_core::RecordId,
        mneme_kernel::contraction::EntrenchmentKey,
    > = candidate_ids
        .iter()
        .map(|record_id| {
            let key = build_entrenchment_key(context, grounded, *record_id)?;
            Ok((*record_id, key))
        })
        .collect::<crate::Result<_>>()?;
    let total_members: usize = kernels.iter().map(Vec::len).sum();
    let mut members = Vec::with_capacity(total_members);
    let mut spans = Vec::with_capacity(kernels.len());
    for kernel in kernels {
        let start = members.len();
        for record_id in kernel {
            if let Some(key) = keys_by_id.get(record_id) {
                members.push(*key);
            }
        }
        spans.push(mneme_kernel::contraction::RangeSpan {
            start,
            len: members.len().saturating_sub(start),
        });
    }
    let base_ids: Vec<u128> = candidate_ids
        .iter()
        .map(|id| u128::from_be_bytes(*id.as_bytes()))
        .collect();
    if mneme_kernel::contraction::any_proof_survives(&base_ids, &members, &spans) {
        return Err(crate::PolicyError::Policy(
            "kernel contraction invariant failed: a minimal kernel survived incision",
        ));
    }
    let mut incised = Vec::with_capacity(candidate_ids.len());
    let mut entrenchment = Vec::with_capacity(candidate_ids.len());
    for record_id in candidate_ids {
        let Some(key) = keys_by_id.get(&record_id) else {
            continue;
        };
        let is_cut = mneme_kernel::contraction::is_incised(key.record_id, &members, &spans);
        if is_cut {
            incised.push(record_id);
        }
        entrenchment.push(PremiseEntrenchment {
            record_id,
            origin: key.origin,
            root_count: key.root_count,
            incised: is_cut,
        });
    }
    Ok((incised, entrenchment))
}

/// Build the deterministic [`mneme_kernel::contraction::EntrenchmentKey`] for
/// one candidate base record.
fn build_entrenchment_key(
    context: &crate::PlanContext<'_>,
    grounded: &std::collections::BTreeSet<mneme_core::RecordId>,
    record_id: mneme_core::RecordId,
) -> crate::Result<mneme_kernel::contraction::EntrenchmentKey> {
    let is_assertion = context
        .by_id
        .get(&record_id)
        .is_some_and(|env| env.kind == mneme_core::RecordKind::Assertion);
    let origin = if is_assertion {
        let assertion = context.view.assertion(record_id)?;
        map_origin_tier(assertion.origin)
    } else {
        mneme_kernel::contraction::OriginTier::Imported
    };
    let root_count = count_surviving_roots(context, grounded, record_id)?;
    Ok(mneme_kernel::contraction::EntrenchmentKey {
        origin,
        root_count,
        record_id: u128::from_be_bytes(*record_id.as_bytes()),
    })
}

fn map_origin_tier(origin: mneme_core::Origin) -> mneme_kernel::contraction::OriginTier {
    match origin {
        mneme_core::Origin::ModelExtraction | mneme_core::Origin::Inference => {
            mneme_kernel::contraction::OriginTier::ModelExtraction
        }
        mneme_core::Origin::Import | mneme_core::Origin::Observation => {
            mneme_kernel::contraction::OriginTier::Imported
        }
        mneme_core::Origin::AuthoredStatement => mneme_kernel::contraction::OriginTier::Authored,
    }
}

/// Count distinct surviving [`RootIdentity`] leaves supporting `record_id`.
fn count_surviving_roots(
    context: &crate::PlanContext<'_>,
    grounded: &std::collections::BTreeSet<mneme_core::RecordId>,
    record_id: mneme_core::RecordId,
) -> crate::Result<u64> {
    let mut roots = std::collections::BTreeSet::new();
    let mut visited = std::collections::BTreeSet::new();
    let mut stack = vec![record_id];
    let limit = context.records.len().saturating_add(1);
    for _ in 0..limit {
        let Some(current) = stack.pop() else {
            break;
        };
        if !visited.insert(current) || !grounded.contains(&current) {
            continue;
        }
        let Some(envelope) = context.by_id.get(&current) else {
            continue;
        };
        collect_node_roots(context, envelope, &mut roots, &mut stack)?;
    }
    u64::try_from(roots.len())
        .map_err(|_| crate::PolicyError::Policy("corroboration root count exceeds u64"))
}

fn collect_node_roots(
    context: &crate::PlanContext<'_>,
    envelope: &mneme_core::RecordEnvelope,
    roots: &mut std::collections::BTreeSet<RootIdentity>,
    stack: &mut Vec<mneme_core::RecordId>,
) -> crate::Result<()> {
    match envelope.kind {
        mneme_core::RecordKind::SourceRevision => {
            let source = context.view.source(envelope.record_id)?;
            match crate::foreign_parent(context, envelope.record_id, source.clone())? {
                Some(parent) => stack.push(parent),
                None => {
                    roots.insert(source_root_identity(&source));
                }
            }
        }
        mneme_core::RecordKind::Episode => {
            let episode = context.view.episode(envelope.record_id)?;
            if let Some(source) = episode.source {
                stack.push(source);
            } else {
                roots.insert(RootIdentity::Revision((
                    envelope.record_id,
                    envelope.revision_id,
                )));
            }
        }
        mneme_core::RecordKind::Evidence => {
            let evidence = context.view.evidence(envelope.record_id)?;
            if evidence.ancestry.is_empty() {
                stack.push(evidence.source);
            } else {
                stack.extend(evidence.ancestry.iter().copied());
            }
        }
        mneme_core::RecordKind::Assertion => {
            let assertion = context.view.assertion(envelope.record_id)?;
            for evidence_id in &assertion.evidence {
                let is_support = context.view.evidence(*evidence_id).is_ok_and(|ev| {
                    ev.relation == mneme_memory::SupportRelation::Supports
                        && ev.assertion == envelope.record_id
                });
                if is_support {
                    stack.push(*evidence_id);
                }
            }
        }
        mneme_core::RecordKind::Derivation
        | mneme_core::RecordKind::Entity
        | mneme_core::RecordKind::Relation
        | mneme_core::RecordKind::Checkpoint
        | mneme_core::RecordKind::Proposal
        | mneme_core::RecordKind::Decision
        | mneme_core::RecordKind::RetentionDirective
        | mneme_core::RecordKind::Document
        | mneme_core::RecordKind::DocumentAnchor
        | mneme_core::RecordKind::DocumentBinding
        | mneme_core::RecordKind::Comment
        | mneme_core::RecordKind::RecognitionRun
        | mneme_core::RecordKind::RecognitionSegment => {}
    }
    Ok(())
}

fn source_root_identity(source: &mneme_memory::SourceView) -> RootIdentity {
    source.digest().or(source.prior_digest).map_or(
        RootIdentity::Revision((source.record.record_id, source.record.revision_id)),
        RootIdentity::Digest,
    )
}
