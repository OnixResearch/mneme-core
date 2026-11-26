//! Heterogeneous Personalized PageRank (`Mode::GraphPpr`) over one pinned snapshot.
//!
//! Builds an ephemeral heterogeneous graph strictly from visible, accepted,
//! non-suppressed records inside the request's `CachedIndex` and
//! `mneme_memory::View` snapshot:
//! - eligible accepted `Relation` edges (excluding `proposed`/`rejected`),
//! - `Entity <-> Assertion` membership edges,
//! - eligible `Supports` `Assertion <-> SourceRevision` edges, and
//! - `Episode <-> SourceRevision` edges.
//!
//! Seeds are weighted by `s_0(u) / ln(e + deg(u))` to resist hub dilution,
//! walked deterministically via canonical-`RecordId`-ordered ACL push or bounded
//! power iteration while charging every edge traversal to `WorkBudget`, and
//! projected directly onto existing indexed `assertion:{id}` and
//! `source:{id}:{rev}` candidates.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// Index/algorithm version reported for `Mode::GraphPpr`.
pub const GRAPH_INDEX_VERSION: &str = "mneme-graph-ppr-v1";
/// Default teleport/restart probability `alpha`.
pub const DEFAULT_DAMPING: f64 = 0.5;
/// Default and maximum power-iteration steps.
pub const DEFAULT_MAX_ITERATIONS: u32 = 20;
/// Maximum allowed power-iteration steps.
pub const MAX_ITERATIONS_LIMIT: u32 = 20;
/// Default ACL push residual-per-degree tolerance `epsilon`.
pub const DEFAULT_PUSH_TOLERANCE: f64 = 1e-3;
/// Default bounded push operations for ACL push.
pub const DEFAULT_MAX_PUSHES: u32 = 20_000;
/// Maximum allowed push operations for ACL push.
pub const MAX_PUSHES_LIMIT: u32 = 200_000;
/// Default number of top BM25F lexical matches used when no explicit seeds are given.
pub const DEFAULT_MAX_LEXICAL_SEEDS: u32 = 8;
/// Maximum explicit seed entities accepted in one request.
pub const MAX_SEED_ENTITIES: u32 = 64;
/// Maximum allowlisted relation types accepted in one request.
pub const MAX_RELATION_TYPES: u32 = 32;
/// Longest allowed relation type name, in bytes.
pub const MAX_RELATION_TYPE_BYTES: u32 = 128;

/// Whether `Relation` edges are traversed only forward or in both directions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdgeDirection {
    /// Follow `from -> to` only.
    Directed,
    /// Follow both `from -> to` and `to -> from`.
    Undirected,
}

/// Deterministic Personalized PageRank solver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Solver {
    /// Canonical-`RecordId`-ordered Andersen-Chung-Lang local push.
    AclPush,
    /// Bounded dense power iteration (`T <= 20`).
    PowerIteration,
}

/// Caller configuration for `Mode::GraphPpr`.
#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    /// Explicit seed entity (or assertion) record identities. When empty,
    /// seeds are drawn deterministically from top-`max_lexical_seeds` BM25F matches.
    pub seeds: std::collections::BTreeSet<mneme_core::RecordId>,
    /// Optional relation-type allowlist. When empty, all eligible accepted
    /// relation types are followed.
    pub relation_types: std::collections::BTreeSet<String>,
    /// Directionality of `Relation` edges (`Entity <-> Assertion`,
    /// `Assertion <-> Source`, and `Episode <-> Source` are always traversable
    /// in both directions so query seeds can reach connected claims).
    pub direction: EdgeDirection,
    /// Teleport probability `alpha` in `(0.0, 1.0)`.
    pub damping: f64,
    /// Bounded iteration count for `Solver::PowerIteration` (`1..=20`).
    pub max_iterations: u32,
    /// Local push tolerance `epsilon` in `(0.0, 1.0)` for `Solver::AclPush`
    /// and projection noise floor for `Solver::PowerIteration`.
    pub push_tolerance: f64,
    /// Maximum push steps for `Solver::AclPush`.
    pub max_pushes: u32,
    /// Maximum top BM25F matches used for automatic seeding when `seeds` is empty.
    pub max_lexical_seeds: u32,
    /// Deterministic solver algorithm.
    pub solver: Solver,
}

impl Config {
    /// Construct a bounded graph-PPR configuration with standard defaults.
    pub const fn new() -> Self {
        Config {
            seeds: std::collections::BTreeSet::new(),
            relation_types: std::collections::BTreeSet::new(),
            direction: EdgeDirection::Directed,
            damping: DEFAULT_DAMPING,
            max_iterations: DEFAULT_MAX_ITERATIONS,
            push_tolerance: DEFAULT_PUSH_TOLERANCE,
            max_pushes: DEFAULT_MAX_PUSHES,
            max_lexical_seeds: DEFAULT_MAX_LEXICAL_SEEDS,
            solver: Solver::AclPush,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config::new()
    }
}

/// Validate a graph-PPR configuration before touching any snapshot data.
pub(crate) fn validate(config: &Config) -> crate::failure::Result<()> {
    let max_seeds = usize::try_from(MAX_SEED_ENTITIES).map_err(|_| {
        crate::failure::QueryError::InvalidRequest("seed bound exceeds platform range".to_owned())
    })?;
    if config.seeds.len() > max_seeds {
        return Err(crate::failure::QueryError::InvalidRequest(format!(
            "graph-ppr accepts at most {MAX_SEED_ENTITIES} explicit seeds"
        )));
    }
    let max_relations = usize::try_from(MAX_RELATION_TYPES).map_err(|_| {
        crate::failure::QueryError::InvalidRequest(
            "relation type bound exceeds platform range".to_owned(),
        )
    })?;
    if config.relation_types.len() > max_relations {
        return Err(crate::failure::QueryError::InvalidRequest(format!(
            "graph-ppr accepts at most {MAX_RELATION_TYPES} relation types"
        )));
    }
    let max_rel_bytes = usize::try_from(MAX_RELATION_TYPE_BYTES).map_err(|_| {
        crate::failure::QueryError::InvalidRequest(
            "relation type length bound exceeds platform range".to_owned(),
        )
    })?;
    for rel_type in &config.relation_types {
        if rel_type.is_empty()
            || rel_type.len() > max_rel_bytes
            || rel_type.chars().any(char::is_control)
        {
            return Err(crate::failure::QueryError::InvalidRequest(
                "graph-ppr relation type must be 1..=128 non-control bytes".to_owned(),
            ));
        }
    }
    validate_numeric_params(config)
}

fn validate_numeric_params(config: &Config) -> crate::failure::Result<()> {
    if !config.damping.is_finite() || config.damping <= 0.0 || config.damping >= 1.0 {
        return Err(crate::failure::QueryError::InvalidRequest(
            "graph-ppr damping must be finite and strictly inside (0, 1)".to_owned(),
        ));
    }
    if !config.push_tolerance.is_finite()
        || config.push_tolerance <= 0.0
        || config.push_tolerance >= 1.0
    {
        return Err(crate::failure::QueryError::InvalidRequest(
            "graph-ppr push_tolerance must be finite and strictly inside (0, 1)".to_owned(),
        ));
    }
    if config.max_iterations == 0 || config.max_iterations > MAX_ITERATIONS_LIMIT {
        return Err(crate::failure::QueryError::InvalidRequest(format!(
            "graph-ppr max_iterations must be in 1..={MAX_ITERATIONS_LIMIT}"
        )));
    }
    if config.max_pushes == 0 || config.max_pushes > MAX_PUSHES_LIMIT {
        return Err(crate::failure::QueryError::InvalidRequest(format!(
            "graph-ppr max_pushes must be in 1..={MAX_PUSHES_LIMIT}"
        )));
    }
    if config.max_lexical_seeds == 0 {
        return Err(crate::failure::QueryError::InvalidRequest(
            "graph-ppr max_lexical_seeds must be greater than zero".to_owned(),
        ));
    }
    Ok(())
}

/// Canonical heterogeneous graph node identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Node {
    Entity(mneme_core::RecordId),
    Assertion(mneme_core::RecordId),
    Source(mneme_core::RecordId, mneme_core::RevisionId),
    Episode(mneme_core::RecordId),
}

/// Output of one deterministic heterogeneous PPR run.
pub(crate) struct RunOutput {
    /// Ranked citable candidates `(candidate_id, pi_score)`, sorted by score desc, id asc.
    pub ranking: Vec<(String, f64)>,
    /// Number of edge traversals charged during diffusion.
    pub work: u64,
}

/// Ephemeral heterogeneous graph built from one pinned view and `CachedIndex`.
struct Graph {
    nodes: std::collections::BTreeSet<Node>,
    adjacency: std::collections::BTreeMap<Node, std::collections::BTreeSet<Node>>,
    in_degree: std::collections::BTreeMap<Node, u64>,
    citable_ids: std::collections::BTreeMap<Node, String>,
}

impl Graph {
    const fn new() -> Self {
        Graph {
            nodes: std::collections::BTreeSet::new(),
            adjacency: std::collections::BTreeMap::new(),
            in_degree: std::collections::BTreeMap::new(),
            citable_ids: std::collections::BTreeMap::new(),
        }
    }

    fn add_edge(&mut self, from: Node, to: Node) {
        if !self.nodes.contains(&from) || !self.nodes.contains(&to) || from == to {
            return;
        }
        let is_inserted = self.adjacency.entry(from).or_default().insert(to);
        if is_inserted {
            let slot = self.in_degree.entry(to).or_insert(0);
            *slot = slot.saturating_add(1);
        }
    }

    fn add_undirected_edge(&mut self, left: Node, right: Node) {
        self.add_edge(left, right);
        self.add_edge(right, left);
    }

    fn out_degree(&self, node: Node) -> usize {
        self.adjacency
            .get(&node)
            .map_or(0, std::collections::BTreeSet::len)
    }

    fn total_degree(&self, node: Node) -> f64 {
        let out_deg = self.out_degree(node) as f64;
        let in_deg = self.in_degree.get(&node).copied().unwrap_or(0) as f64;
        out_deg + in_deg
    }
}

/// Inputs for executing one heterogeneous PPR ranking pass.
pub(crate) struct RankInputs<'a> {
    pub index: &'a crate::model::CachedIndex,
    pub view: &'a mneme_memory::View,
    pub request: &'a crate::model::Request,
    pub config: &'a Config,
    pub lexical_ranking: Option<&'a [(String, f64)]>,
    pub budget: &'a mut crate::engine::WorkBudget,
}

/// Execute heterogeneous PPR over the pinned snapshot and project directly onto
/// citable `assertion:{id}` and `source:{id}:{rev}` candidates.
pub(crate) fn rank(inputs: RankInputs<'_>) -> crate::engine::AttemptResult<RunOutput> {
    let RankInputs {
        index,
        view,
        request,
        config,
        lexical_ranking,
        budget,
    } = inputs;
    budget.check()?;
    let graph = build_graph(index, view, request, config, budget)?;
    if graph.citable_ids.is_empty() {
        return Ok(RunOutput {
            ranking: Vec::new(),
            work: 0,
        });
    }
    let seeds = build_seed_vector(SeedInputs {
        graph: &graph,
        index,
        request,
        config,
        lexical_ranking,
        budget,
    })?;
    if seeds.is_empty() {
        return Ok(RunOutput {
            ranking: Vec::new(),
            work: 0,
        });
    }
    let (pi, work) = if config.solver == Solver::AclPush {
        run_acl_push(&graph, &seeds, config, budget)?
    } else {
        run_power_iteration(&graph, &seeds, config, budget)?
    };
    let ranking = project_citable(&graph, &pi, config);
    Ok(RunOutput { ranking, work })
}

fn build_graph(
    index: &crate::model::CachedIndex,
    view: &mneme_memory::View,
    request: &crate::model::Request,
    config: &Config,
    budget: &mut crate::engine::WorkBudget,
) -> crate::engine::AttemptResult<Graph> {
    let mut graph = Graph::new();
    collect_eligible_entities(&mut graph, view, request, budget)?;
    collect_indexed_nodes(&mut graph, index, budget)?;
    connect_relations(&mut graph, view, request, config, budget)?;
    connect_indexed_edges(&mut graph, index, view, budget)?;
    Ok(graph)
}

fn collect_eligible_entities(
    graph: &mut Graph,
    view: &mneme_memory::View,
    request: &crate::model::Request,
    budget: &mut crate::engine::WorkBudget,
) -> crate::engine::AttemptResult<()> {
    for record in &view.snapshot().records {
        if record.kind != mneme_core::RecordKind::Entity {
            continue;
        }
        budget.charge(1)?;
        if !is_record_visible(request, &record.scope) {
            continue;
        }
        if view.suppression_for(record).is_some() || view.is_withdrawn(record.record_id) {
            continue;
        }
        if !is_record_accepted(record) {
            continue;
        }
        graph.nodes.insert(Node::Entity(record.record_id));
    }
    Ok(())
}

fn collect_indexed_nodes(
    graph: &mut Graph,
    index: &crate::model::CachedIndex,
    budget: &mut crate::engine::WorkBudget,
) -> crate::engine::AttemptResult<()> {
    for document in &index.documents {
        budget.charge(1)?;
        if document.kind == crate::model::ContentKind::Claim {
            if !is_claim_eligible(document) {
                continue;
            }
            if let Some(assertion_id) = document.assertion {
                let node = Node::Assertion(assertion_id);
                graph.nodes.insert(node);
                graph.citable_ids.insert(node, document.id.clone());
            }
        } else if document.kind == crate::model::ContentKind::SourceExcerpt {
            if let (Some(source_id), Some(source_rev)) = (document.source, document.source_revision)
            {
                let node = Node::Source(source_id, source_rev);
                graph.nodes.insert(node);
                graph.citable_ids.insert(node, document.id.clone());
            }
        } else if document.kind == crate::model::ContentKind::EpisodeSummary
            && let Some(episode_id) = document.episode
        {
            graph.nodes.insert(Node::Episode(episode_id));
        }
    }
    Ok(())
}

fn connect_relations(
    graph: &mut Graph,
    view: &mneme_memory::View,
    request: &crate::model::Request,
    config: &Config,
    budget: &mut crate::engine::WorkBudget,
) -> crate::engine::AttemptResult<()> {
    for record in &view.snapshot().records {
        if record.kind != mneme_core::RecordKind::Relation {
            continue;
        }
        budget.charge(1)?;
        if !is_record_visible(request, &record.scope) {
            continue;
        }
        if view.suppression_for(record).is_some() || view.is_withdrawn(record.record_id) {
            continue;
        }
        if !is_record_accepted(record) {
            continue;
        }
        if !is_relation_type_allowed(record, &config.relation_types) {
            continue;
        }
        let Some(from_id) = reference_target(record, "from") else {
            continue;
        };
        let Some(to_id) = reference_target(record, "to") else {
            continue;
        };
        let Some(from_node) = resolve_relation_node(graph, from_id) else {
            continue;
        };
        let Some(to_node) = resolve_relation_node(graph, to_id) else {
            continue;
        };
        if config.direction == EdgeDirection::Undirected {
            graph.add_undirected_edge(from_node, to_node);
        } else {
            graph.add_edge(from_node, to_node);
        }
    }
    Ok(())
}

fn connect_indexed_edges(
    graph: &mut Graph,
    index: &crate::model::CachedIndex,
    view: &mneme_memory::View,
    budget: &mut crate::engine::WorkBudget,
) -> crate::engine::AttemptResult<()> {
    for document in &index.documents {
        budget.charge(1)?;
        if document.kind == crate::model::ContentKind::Claim {
            if !is_claim_eligible(document) {
                continue;
            }
            let Some(assertion_id) = document.assertion else {
                continue;
            };
            let assertion_node = Node::Assertion(assertion_id);
            if let Some(entity_id) = document.entity {
                graph.add_undirected_edge(Node::Entity(entity_id), assertion_node);
            }
            connect_claim_evidence(graph, view, assertion_node, &document.evidence, budget)?;
        } else if document.kind == crate::model::ContentKind::EpisodeSummary
            && let (Some(episode_id), Some(source_id), Some(source_rev)) =
                (document.episode, document.source, document.source_revision)
        {
            graph.add_undirected_edge(
                Node::Episode(episode_id),
                Node::Source(source_id, source_rev),
            );
        }
    }
    Ok(())
}

fn connect_claim_evidence(
    graph: &mut Graph,
    view: &mneme_memory::View,
    assertion_node: Node,
    evidence_list: &[crate::model::Evidence],
    budget: &mut crate::engine::WorkBudget,
) -> crate::engine::AttemptResult<()> {
    for evidence in evidence_list {
        budget.charge(1)?;
        if evidence.relation != mneme_memory::SupportRelation::Supports {
            continue;
        }
        if evidence.withdrawn
            || view.is_withdrawn(evidence.evidence)
            || view.is_withdrawn(evidence.source)
        {
            continue;
        }
        if let Some(source_rev) = evidence.source_revision {
            let source_node = Node::Source(evidence.source, source_rev);
            graph.add_undirected_edge(assertion_node, source_node);
        }
    }
    Ok(())
}

struct SeedInputs<'a> {
    graph: &'a Graph,
    index: &'a crate::model::CachedIndex,
    request: &'a crate::model::Request,
    config: &'a Config,
    lexical_ranking: Option<&'a [(String, f64)]>,
    budget: &'a mut crate::engine::WorkBudget,
}

fn build_seed_vector(
    inputs: SeedInputs<'_>,
) -> crate::engine::AttemptResult<std::collections::BTreeMap<Node, f64>> {
    let SeedInputs {
        graph,
        index,
        request,
        config,
        lexical_ranking,
        budget,
    } = inputs;
    let mut raw_seeds: std::collections::BTreeMap<Node, f64> = std::collections::BTreeMap::new();
    if !config.seeds.is_empty() {
        for seed_id in &config.seeds {
            budget.charge(1)?;
            if let Some(node) = resolve_relation_node(graph, *seed_id) {
                raw_seeds.insert(node, 1.0);
            }
        }
    } else {
        let computed;
        let ranking: &[(String, f64)] = match lexical_ranking {
            Some(existing) => existing,
            None => {
                computed = crate::engine::lexical_rank(index, request, budget)?;
                &computed
            }
        };
        let limit = usize::try_from(config.max_lexical_seeds).map_err(|_| {
            crate::failure::QueryError::InvalidRequest(
                "graph-ppr max_lexical_seeds exceeds platform range".to_owned(),
            )
        })?;
        for (doc_id, score) in ranking.iter().take(limit) {
            budget.charge(1)?;
            if !score.is_finite() || *score <= 0.0 {
                continue;
            }
            let Some(document) = index.document(doc_id) else {
                continue;
            };
            if let Some(node) = node_for_document(graph, document) {
                let slot = raw_seeds.entry(node).or_insert(0.0);
                *slot = (*slot).max(*score);
            }
        }
    }
    Ok(normalize_degree_weighted_seeds(graph, &raw_seeds))
}

fn normalize_degree_weighted_seeds(
    graph: &Graph,
    raw_seeds: &std::collections::BTreeMap<Node, f64>,
) -> std::collections::BTreeMap<Node, f64> {
    let weighted: std::collections::BTreeMap<Node, f64> = raw_seeds
        .iter()
        .filter_map(|(&node, &raw_score)| {
            let deg = graph.total_degree(node);
            let denom = (std::f64::consts::E + deg).ln();
            let weight = if denom > 0.0 {
                raw_score / denom
            } else {
                raw_score
            };
            (weight.is_finite() && weight > 0.0).then_some((node, weight))
        })
        .collect();
    let total: f64 = weighted.values().copied().sum();
    if total <= 0.0 || !total.is_finite() {
        return std::collections::BTreeMap::new();
    }
    weighted
        .into_iter()
        .map(|(node, weight)| (node, weight / total))
        .collect()
}

fn run_acl_push(
    graph: &Graph,
    seeds: &std::collections::BTreeMap<Node, f64>,
    config: &Config,
    budget: &mut crate::engine::WorkBudget,
) -> crate::engine::AttemptResult<(std::collections::BTreeMap<Node, f64>, u64)> {
    let alpha = config.damping;
    let one_minus_alpha = 1.0 - alpha;
    let eps = config.push_tolerance;
    let mut pi: std::collections::BTreeMap<Node, f64> = std::collections::BTreeMap::new();
    let mut residual = seeds.clone();
    let mut active: std::collections::BTreeSet<Node> = residual
        .iter()
        .filter_map(|(&node, &r_val)| {
            needs_push(r_val, graph.out_degree(node), eps).then_some(node)
        })
        .collect();
    let mut work: u64 = 0;
    for _ in 0..config.max_pushes {
        let Some(node) = active.pop_first() else {
            break;
        };
        let r_val = residual.remove(&node).unwrap_or(0.0);
        let out_deg = graph.out_degree(node);
        if !needs_push(r_val, out_deg, eps) {
            continue;
        }
        *pi.entry(node).or_insert(0.0) += alpha * r_val;
        if out_deg == 0 {
            budget.charge(1)?;
            work = work.saturating_add(1);
            continue;
        }
        let share = one_minus_alpha * r_val / (out_deg as f64);
        if let Some(neighbors) = graph.adjacency.get(&node) {
            for &neighbor in neighbors {
                budget.charge(1)?;
                work = work.saturating_add(1);
                let next_r = residual.entry(neighbor).or_insert(0.0);
                *next_r += share;
                if needs_push(*next_r, graph.out_degree(neighbor), eps) {
                    active.insert(neighbor);
                }
            }
        }
    }
    Ok((pi, work))
}

fn needs_push(residual: f64, out_degree: usize, eps: f64) -> bool {
    if !residual.is_finite() || residual <= 0.0 {
        return false;
    }
    if out_degree == 0 {
        residual >= eps
    } else {
        (residual / (out_degree as f64)) >= eps
    }
}

fn run_power_iteration(
    graph: &Graph,
    seeds: &std::collections::BTreeMap<Node, f64>,
    config: &Config,
    budget: &mut crate::engine::WorkBudget,
) -> crate::engine::AttemptResult<(std::collections::BTreeMap<Node, f64>, u64)> {
    let alpha = config.damping;
    let one_minus_alpha = 1.0 - alpha;
    let mut pi = seeds.clone();
    let mut work: u64 = 0;
    for _ in 0..config.max_iterations {
        let mut next: std::collections::BTreeMap<Node, f64> = std::collections::BTreeMap::new();
        for (&seed_node, &seed_mass) in seeds {
            *next.entry(seed_node).or_insert(0.0) += alpha * seed_mass;
        }
        let mut dangling_mass = 0.0_f64;
        for (&node, &mass) in &pi {
            if !mass.is_finite() || mass <= 0.0 {
                continue;
            }
            let out_deg = graph.out_degree(node);
            if out_deg == 0 {
                dangling_mass += one_minus_alpha * mass;
                budget.charge(1)?;
                work = work.saturating_add(1);
                continue;
            }
            let share = one_minus_alpha * mass / (out_deg as f64);
            if let Some(neighbors) = graph.adjacency.get(&node) {
                for &neighbor in neighbors {
                    budget.charge(1)?;
                    work = work.saturating_add(1);
                    *next.entry(neighbor).or_insert(0.0) += share;
                }
            }
        }
        if dangling_mass > 0.0 {
            for (&seed_node, &seed_mass) in seeds {
                *next.entry(seed_node).or_insert(0.0) += dangling_mass * seed_mass;
            }
        }
        pi = next;
    }
    Ok((pi, work))
}

fn project_citable(
    graph: &Graph,
    pi: &std::collections::BTreeMap<Node, f64>,
    config: &Config,
) -> Vec<(String, f64)> {
    let floor = if config.solver == Solver::AclPush {
        0.0
    } else {
        config.push_tolerance
    };
    let mut entries = Vec::with_capacity(graph.citable_ids.len());
    for (&node, &mass) in pi {
        if !mass.is_finite() || mass <= floor {
            continue;
        }
        if let Some(doc_id) = graph.citable_ids.get(&node) {
            entries.push((doc_id.clone(), mass));
        }
    }
    entries.sort_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    entries
}

fn is_record_visible(request: &crate::model::Request, scope: &mneme_core::ScopeId) -> bool {
    mneme_kernel::isolation::record_visible(&mneme_kernel::isolation::VisibilityFacts {
        same_scope: scope == &request.scope,
        record_class: scope.class().to_kernel(),
        include_hypothetical: request.include_hypothetical,
        record_scope_authorized: request.access.allows(scope),
    })
}

fn is_claim_eligible(document: &crate::model::IndexedDocument) -> bool {
    match &document.claim_status {
        None => true,
        Some(status) => !matches!(
            status.lifecycle.as_str(),
            "proposed" | "rejected" | "retracted" | "superseded"
        ),
    }
}

fn is_record_accepted(record: &mneme_core::RecordEnvelope) -> bool {
    if let Some(status) = status_text(record.payload.get("lifecycle"))
        && is_excluded_status(status)
    {
        return false;
    }
    if let Some(status) = status_text(record.payload.get("status"))
        && is_excluded_status(status)
    {
        return false;
    }
    if let Some(properties) = record
        .payload
        .get("properties")
        .and_then(mneme_core::Value::as_dictionary)
    {
        let prop_status = properties
            .get(&mneme_core::Value::symbol("status"))
            .or_else(|| properties.get(&mneme_core::Value::string("status")));
        if let Some(status) = status_text(prop_status)
            && is_excluded_status(status)
        {
            return false;
        }
    }
    true
}

fn status_text(value: Option<&mneme_core::Value>) -> Option<&str> {
    value.and_then(|item| {
        item.as_symbol()
            .map(mneme_core::Symbol::as_str)
            .or_else(|| item.as_string())
    })
}

fn is_excluded_status(status: &str) -> bool {
    matches!(status, "proposed" | "rejected" | "retracted" | "superseded")
}

fn is_relation_type_allowed(
    record: &mneme_core::RecordEnvelope,
    allowed: &std::collections::BTreeSet<String>,
) -> bool {
    if allowed.is_empty() {
        return true;
    }
    let rel_type = status_text(record.payload.get("relation-type"));
    rel_type.is_some_and(|name| allowed.contains(name))
}

fn reference_target(
    record: &mneme_core::RecordEnvelope,
    field: &str,
) -> Option<mneme_core::RecordId> {
    let value = record.payload.get(field)?;
    let reference = mneme_core::Reference::from_value(value, &mneme_core::Path::root()).ok()?;
    reference.target()
}

fn resolve_relation_node(graph: &Graph, id: mneme_core::RecordId) -> Option<Node> {
    let entity = Node::Entity(id);
    if graph.nodes.contains(&entity) {
        return Some(entity);
    }
    let assertion = Node::Assertion(id);
    if graph.nodes.contains(&assertion) {
        return Some(assertion);
    }
    let episode = Node::Episode(id);
    if graph.nodes.contains(&episode) {
        return Some(episode);
    }
    None
}

fn node_for_document(graph: &Graph, document: &crate::model::IndexedDocument) -> Option<Node> {
    let candidate = if document.kind == crate::model::ContentKind::Claim {
        document.assertion.map(Node::Assertion)
    } else if document.kind == crate::model::ContentKind::SourceExcerpt {
        document
            .source
            .zip(document.source_revision)
            .map(|(src, rev)| Node::Source(src, rev))
    } else if document.kind == crate::model::ContentKind::EpisodeSummary {
        document.episode.map(Node::Episode)
    } else if document.kind == crate::model::ContentKind::TypedField {
        document.entity.map(Node::Entity)
    } else {
        None
    }?;
    graph.nodes.contains(&candidate).then_some(candidate)
}
