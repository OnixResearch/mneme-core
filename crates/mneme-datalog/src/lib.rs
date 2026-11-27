//! Bounded Datalog projections over authorized committed snapshots.
//!
//! Canonical records remain authoritative. Projection facts are disposable and
//! carry rule, revision, scope, coverage, and source-support metadata.
#![allow(unknown_lints)] // Octet structural exception: domain-qualified names and macro-only imports are intentional
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

/// The supported rule-profile version.
pub const PROFILE_VERSION: &str = "mneme-datalog-profile/v1";
/// The projection index version for full recomputation.
pub const INDEX_VERSION: &str = "full-rebuild-v1";
/// Reserved alias for the primary workspace in federated queries.
pub const PRIMARY_VAULT_ALIAS: &str = "primary";

/// One read-only attached vault specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultAttachment {
    pub alias: String,
    pub root: std::path::PathBuf,
    /// Optional explicit revision to pin; `None` pins the vault's head at query start.
    pub revision: Option<mneme_core::WorkspaceRevisionId>,
}

/// Resolved revision metadata for one participating vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultRevision {
    pub alias: String,
    pub root: std::path::PathBuf,
    pub requested_revision: mneme_core::WorkspaceRevisionId,
    pub served_revision: mneme_core::WorkspaceRevisionId,
}

impl VaultRevision {
    /// Remote peer identifier when `root` uses the `iroh://<node-id>` scheme.
    pub fn peer(&self) -> Option<&str> {
        self.root
            .to_str()
            .and_then(|text| text.strip_prefix("iroh://"))
    }
}

/// One pre-loaded read-only vault view supplied by an external transport
/// (for example, a pinned snapshot fetched over `irpc`).
#[derive(Clone, Debug)]
pub struct ExternalVaultView {
    pub metadata: VaultRevision,
    pub eligibility_generation: u64,
    pub view: mneme_memory::View,
    pub current_sources:
        std::collections::BTreeMap<mneme_core::RecordId, mneme_memory::SourceAvailability>,
}

/// One attached vault source in a federated build, either local or pre-loaded.
#[derive(Clone, Debug)]
pub enum FederatedVaultSource {
    Local(VaultAttachment),
    External(Box<ExternalVaultView>),
}

impl FederatedVaultSource {
    /// Alias assigned to this attached vault.
    pub fn alias(&self) -> &str {
        if let FederatedVaultSource::Local(attachment) = self {
            &attachment.alias
        } else if let FederatedVaultSource::External(external) = self {
            &external.metadata.alias
        } else {
            ""
        }
    }
}

/// Validate an attached vault alias before opening its workspace.
pub fn validate_vault_alias(alias: &str) -> Result<(), Error> {
    if alias.is_empty()
        || alias == PRIMARY_VAULT_ALIAS
        || !alias
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(Error::InvalidQuery(
            "attached vault alias must be non-empty [A-Za-z0-9_-] and not 'primary'",
        ));
    }
    Ok(())
}

pub mod egraph;
pub mod justification;
pub mod repl;
pub mod temporal;
pub mod zset;
pub use egraph::{
    Action, DEFAULT_MAX_EGRAPH_REBUILD_ROUNDS, DEFAULT_MAX_EGRAPH_UNIONS, EClassTable,
    EGraphConfig, LatticeMerge, LatticeOp, UNION_HEAD_PREDICATE, UnionFind, UnionStatus,
};
pub use justification::{
    DEFAULT_MAX_JUSTIFICATION_NODES, FactRef, Hypergraph, Node, NodeId, PremiseEdge,
};
pub type JustificationGraph = justification::Hypergraph;
pub type JustificationNode = justification::Node;
pub type JustificationId = justification::NodeId;
pub use repl::{ReplLimits, ReplSession, ReplSessionRequest, ReplStepSummary};
pub use temporal::{DEFAULT_MAX_INTERVALS_PER_FACT, FactValidity, IntervalSet};
pub use zset::{
    BilinearJoin, EpistemicBilinearJoin, EpistemicCombineOp, EpistemicWeight, EpistemicZSet,
    IndexedEpistemicZSet, IndexedZSet, ZSet, delta_epistemic_join, delta_join,
};

/// Configuration for temporal interval bounds during Datalog evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemporalConfig {
    /// Maximum number of disjoint coalesced periods retained per fact.
    pub max_intervals_per_fact: u64,
}

impl Default for TemporalConfig {
    fn default() -> Self {
        Self {
            max_intervals_per_fact: DEFAULT_MAX_INTERVALS_PER_FACT,
        }
    }
}

/// Epistemic semantics for negated body literals (`not p(...)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum NegationSemantics {
    /// Kleene three-valued epistemic negation (`¬Accepted = Rejected`,
    /// `¬Proposed = Proposed`, `¬Rejected = Accepted`): a `Proposed` negated fact
    /// attenuates the derived head to `Proposed` instead of silently suppressing it.
    #[default]
    Kleene,
    /// Strict classical negation blocking on any active fact (`Accepted | Proposed`).
    Strict,
}

/// Fixpoint evaluation mode for rule programs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum EvaluationMode {
    /// Stratified fixpoint evaluation (default).
    #[default]
    Stratified,
    /// Bounded alternating-fixpoint Well-Founded Semantics (WFS) supporting
    /// bounded belief-revision cycles through negation.
    WellFounded,
}

/// Evaluation configuration combining temporal bounds, negation semantics, WFS mode, and e-graph bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct EvaluationConfig {
    pub temporal: TemporalConfig,
    pub negation: NegationSemantics,
    pub mode: EvaluationMode,
    pub egraph: EGraphConfig,
}

/// A Datalog term.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Term {
    Variable(String),
    Constant(mneme_core::Value),
}

impl Term {
    /// Construct a variable term.
    pub fn var(name: impl Into<String>) -> Self {
        Term::Variable(name.into())
    }

    /// Construct a constant term.
    pub fn constant(value: mneme_core::Value) -> Self {
        Term::Constant(value)
    }
}

/// An atom with a predicate and terms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Atom {
    pub predicate: String,
    pub terms: Vec<Term>,
}

impl Atom {
    /// Construct an atom.
    pub fn new(predicate: impl Into<String>, terms: Vec<Term>) -> Self {
        Atom {
            predicate: predicate.into(),
            terms,
        }
    }

    fn arity(&self) -> usize {
        self.terms.len()
    }
}

/// Aggregate functions supported by the bounded profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggregateFunction {
    Count,
    Sum,
    Min,
    Max,
}

/// One body literal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Literal {
    Positive(Atom),
    Negative(Atom),
    Compare {
        op: CompareOp,
        left: Term,
        right: Term,
    },
    /// An aggregate over the positive body. It must be the final literal and
    /// groups by all head variables except `output`.
    Aggregate {
        function: AggregateFunction,
        input: Term,
        output: String,
    },
    /// Bounded DatalogMTL past-diamond: `atom` held at some instant within `[lower_ns, upper_ns]` ago.
    DiamondMinus {
        atom: Atom,
        lower_ns: i128,
        upper_ns: i128,
    },
    /// Bounded DatalogMTL past-box: `atom` held continuously over `[t - upper_ns, t - lower_ns]`.
    BoxMinus {
        atom: Atom,
        lower_ns: i128,
        upper_ns: i128,
    },
    /// Bounded DatalogMTL metric-since: `trigger` held within `[lower_ns, upper_ns]` ago and
    /// `maintained` held continuously on `(t', t]`.
    Since {
        maintained: Atom,
        trigger: Atom,
        lower_ns: i128,
        upper_ns: i128,
    },
    /// Opt-in non-sequenced Allen interval relation between two positive body atoms.
    Allen {
        relation: mneme_kernel::temporal::AllenRelation,
        left: Atom,
        right: Atom,
    },
    /// Explicitly unsupported external operation, rejected at registration.
    Forbidden(String),
}

/// Supported comparison operators.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

/// One validated rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub head: Atom,
    pub body: Vec<Literal>,
    /// Optional equality-saturation actions (such as [`Action::Union`]) executed
    /// for each matched body binding.
    pub actions: Vec<Action>,
    /// Optional functional lattice merge on one head column during congruence closure.
    pub lattice_merge: Option<LatticeMerge>,
}

impl Rule {
    /// Construct a rule.
    pub fn new(id: impl Into<String>, head: Atom, body: Vec<Literal>) -> Self {
        Rule {
            id: id.into(),
            head,
            body,
            actions: Vec::new(),
            lattice_merge: None,
        }
    }

    /// Construct a pure e-graph equivalence union rule (`Action::Union { left, right }`)
    /// that merges equivalence classes without materializing quadratic `same_as` rows.
    pub fn union(id: impl Into<String>, left: Term, right: Term, body: Vec<Literal>) -> Self {
        Rule {
            id: id.into(),
            head: Atom::new(UNION_HEAD_PREDICATE, vec![left.clone(), right.clone()]),
            body,
            actions: vec![Action::Union { left, right }],
            lattice_merge: None,
        }
    }

    /// Attach an equality-saturation action to this rule.
    pub fn with_action(mut self, action: Action) -> Self {
        self.actions.push(action);
        self
    }

    /// Attach multiple equality-saturation actions to this rule.
    pub fn with_actions(mut self, actions: Vec<Action>) -> Self {
        self.actions.extend(actions);
        self
    }

    /// Attach a functional lattice merge column specification to this rule's head.
    pub const fn with_lattice_merge(mut self, merge: LatticeMerge) -> Self {
        self.lattice_merge = Some(merge);
        self
    }

    /// Whether this rule executes only e-graph union actions without materializing a derived head relation.
    pub fn is_union_only(&self) -> bool {
        self.head.predicate == UNION_HEAD_PREDICATE && !self.actions.is_empty()
    }
}

/// A versioned rule bundle. Registration is explicitly separate from execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleBundle {
    pub id: String,
    pub version: String,
    pub schema_version: u32,
    pub base_predicates: std::collections::BTreeMap<String, usize>,
    /// Predicates that may be used under negation or absence-sensitive
    /// aggregation only after their declared extent completes.
    pub complete_predicates: std::collections::BTreeSet<String>,
    pub rules: Vec<Rule>,
}

/// Named fields for constructing a versioned rule bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleBundleOptions {
    pub id: String,
    pub version: String,
    pub schema_version: u32,
    pub base_predicates: std::collections::BTreeMap<String, usize>,
    pub complete_predicates: std::collections::BTreeSet<String>,
    pub rules: Vec<Rule>,
}

impl RuleBundle {
    /// Construct a bundle.
    pub fn new(options: RuleBundleOptions) -> Self {
        RuleBundle {
            id: options.id,
            version: options.version,
            schema_version: options.schema_version,
            base_predicates: options.base_predicates,
            complete_predicates: options.complete_predicates,
            rules: options.rules,
        }
    }
}

/// A registration diagnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleDiagnostic {
    pub code: &'static str,
    pub rule: Option<String>,
    pub message: String,
}

/// A validated rule program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleProgram {
    pub bundle: RuleBundle,
    /// Predicate arities for base and derived predicates.
    pub arities: std::collections::BTreeMap<String, usize>,
    /// Predicate strata.
    pub strata: std::collections::BTreeMap<String, usize>,
}

/// Failure to register or build a projection.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("rule bundle is invalid")]
    InvalidBundle(Vec<RuleDiagnostic>),
    #[error(transparent)]
    Store(#[from] mneme_store::Failure),
    #[error(transparent)]
    Engine(#[from] mneme_memory::EvidenceError),
    #[error("unknown predicate {0}")]
    UnknownPredicate(String),
    #[error("datalog projection {0} is missing")]
    MissingBuild(String),
    #[error(
        "datalog projection is stale: requested revision {requested}, served revision {served}"
    )]
    Stale {
        requested: mneme_core::WorkspaceRevisionId,
        served: mneme_core::WorkspaceRevisionId,
    },
    #[error("datalog evaluation was cancelled")]
    Cancelled,
    #[error("datalog evaluation failed: {0}")]
    Failed(String),
    #[error("datalog query is invalid: {0}")]
    InvalidQuery(&'static str),
    #[error("datalog limit exceeded: {0}")]
    LimitExceeded(String),
}

/// Execution status for a build or query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionStatus {
    Complete,
    Partial,
    Timeout,
    Cancelled,
    Failed,
}

impl ExecutionStatus {
    /// Stable lower-case name.
    pub const fn name(self) -> &'static str {
        if matches!(self, ExecutionStatus::Complete) {
            "complete"
        } else if matches!(self, ExecutionStatus::Partial) {
            "partial"
        } else if matches!(self, ExecutionStatus::Timeout) {
            "timeout"
        } else if matches!(self, ExecutionStatus::Cancelled) {
            "cancelled"
        } else {
            "failed"
        }
    }
}

/// Relation coverage state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverageStatus {
    Complete,
    Incomplete,
    Unknown,
}

impl CoverageStatus {
    /// Stable lower-case name.
    pub const fn name(self) -> &'static str {
        if matches!(self, CoverageStatus::Complete) {
            "complete"
        } else if matches!(self, CoverageStatus::Incomplete) {
            "incomplete"
        } else {
            "unknown"
        }
    }
}

/// Coverage for one predicate at the pinned context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coverage {
    pub predicate: String,
    pub status: CoverageStatus,
    pub reason: Option<String>,
}

/// The immutable evaluation context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildContext {
    pub requested_revision: mneme_core::WorkspaceRevisionId,
    pub served_revision: mneme_core::WorkspaceRevisionId,
    pub scope: mneme_core::ScopeId,
    pub schema_version: u32,
    pub rule_bundle_id: String,
    pub rule_bundle_version: String,
    pub projection_build_id: String,
    pub eligibility_generation: u64,
    /// Whether the build request named the head revision when it was built.
    ///
    /// A build that pinned head becomes stale when head moves. A build that
    /// deliberately requested an older revision keeps answering for that
    /// revision and reports it as both requested and served.
    pub requested_was_head: bool,
    /// Participating vaults `(alias, root, requested_revision, served_revision)`.
    pub vaults: Vec<VaultRevision>,
}

/// Evaluation limits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_work: u64,
    pub max_time_ms: u128,
    pub max_result_rows: usize,
    pub max_supports_per_fact: usize,
    pub max_recursion_depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_work: 100_000,
            max_time_ms: 2_000,
            max_result_rows: 1_000,
            max_supports_per_fact: 8,
            max_recursion_depth: 32,
        }
    }
}

/// A build request.
#[derive(Clone, Debug)]
pub struct BuildRequest {
    pub actor: String,
    pub scope: mneme_core::ScopeId,
    pub revision: mneme_core::WorkspaceRevisionId,
    pub bundle: RuleBundle,
    pub limits: Limits,
    pub publish: bool,
    /// Explicitly incomplete source extents, such as a top-k input.
    pub incomplete_extents: std::collections::BTreeSet<String>,
    pub cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// The caller's scope authorization; the memory view is built with it and
    /// only records visible under it participate in the evaluation.
    pub access: mneme_memory::Access,
    /// The instant claims must be valid at. `None` includes every eligible
    /// claim and records its validity as a temporal parameter of the
    /// derivation instead of excluding it.
    pub at: Option<mneme_core::Timestamp>,
}

/// A federated build request across the primary workspace and read-only attached vaults.
#[derive(Clone, Debug)]
pub struct FederatedBuildRequest {
    pub request: BuildRequest,
    pub attachments: Vec<VaultAttachment>,
}

/// A canonical source/revision root used in support.
pub type SourceKey = (mneme_core::RecordId, mneme_core::RevisionId);

/// One premise of a conditional derivation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Premise {
    pub predicate: String,
    pub terms: Vec<mneme_core::Value>,
    /// The canonical record this premise fact came from, when it is a base fact.
    ///
    /// A derived premise has no single canonical record, so this is `None` and
    /// [`Premise::canonical_roots`] names every record it rests on.
    pub canonical: Option<mneme_core::RecordId>,
    /// Every canonical record the premise fact rests on, transitively.
    pub canonical_roots: std::collections::BTreeSet<mneme_core::RecordId>,
    pub sources: std::collections::BTreeSet<SourceKey>,
    pub source_availability: Option<String>,
    /// Originating vault alias when this premise comes from a single vault.
    pub vault: Option<String>,
    /// Every originating vault alias this premise rests on transitively.
    pub vaults: std::collections::BTreeSet<String>,
    /// Whether the premise is a negated literal that matched no row.
    pub absent: bool,
    /// The relation coverage an absent premise relied on.
    pub coverage: Option<String>,
    /// Epistemic provenance carried by this premise in the semiring.
    pub epistemic: EpistemicStatus,
}

/// A bounded conditional derivation support.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Derivation {
    pub rule_id: String,
    pub rule_version: String,
    pub premises: Vec<Premise>,
    pub sources: std::collections::BTreeSet<SourceKey>,
    /// Every originating vault alias this derivation rests on.
    pub vaults: std::collections::BTreeSet<String>,
    pub temporal_parameters: Vec<String>,
    pub revision: mneme_core::WorkspaceRevisionId,
    pub scope: mneme_core::ScopeId,
    pub truncated: bool,
    /// Combined epistemic provenance across premises (`×` join).
    pub epistemic: EpistemicStatus,
}

/// Pinned barrier invariants recorded for each participating vault in a [`Build`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VaultBarrier {
    pub(crate) alias: String,
    pub(crate) root: std::path::PathBuf,
    pub(crate) served_revision: mneme_core::WorkspaceRevisionId,
    pub(crate) eligibility_generation: u64,
    pub(crate) requested_was_head: bool,
    pub(crate) is_external: bool,
}

/// The built projection.
///
/// The barrier fields are private: a caller cannot relabel a build's revision,
/// generation, status or coverage, and every query or publication re-checks the
/// pinned fields against the workspace.
#[derive(Clone, Debug)]
pub struct Build {
    pub(crate) context: BuildContext,
    pub(crate) status: ExecutionStatus,
    pub(crate) coverage: Vec<Coverage>,
    pub(crate) limits: Limits,
    pub(crate) work: u64,
    pub(crate) support_truncated: bool,
    pub(crate) limit_reached: bool,
    pub(crate) declaration_valid: bool,
    pub(crate) facts: std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<Vec<mneme_core::Value>, FactData>,
    >,
    pub(crate) justifications: JustificationGraph,
    pub(crate) negation_semantics: NegationSemantics,
    pub(crate) eclasses: egraph::EClassTable,
    pub(crate) arities: std::collections::BTreeMap<String, usize>,
    pub(crate) bundle: RuleBundle,
    pub(crate) vault_barriers: Vec<VaultBarrier>,
}

impl Build {
    /// The pinned evaluation context.
    pub fn context(&self) -> &BuildContext {
        &self.context
    }

    /// The execution status.
    pub fn status(&self) -> ExecutionStatus {
        self.status
    }

    /// Coverage of every relation of this build.
    pub fn coverage(&self) -> &[Coverage] {
        &self.coverage
    }

    /// The limits the build ran under.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Work charged to the build budget.
    pub fn work(&self) -> u64 {
        self.work
    }

    /// Whether any fact lost support because the support bound was reached.
    pub fn support_truncated(&self) -> bool {
        self.support_truncated
    }

    /// Whether a work, row, time or cancellation limit stopped the build.
    pub fn limit_reached(&self) -> bool {
        self.limit_reached
    }

    /// Whether every declared base predicate matches its canonical extent.
    pub fn declaration_valid(&self) -> bool {
        self.declaration_valid
    }

    /// Bounded content-addressed justification hypergraph for derived and base facts.
    pub fn justifications(&self) -> &JustificationGraph {
        &self.justifications
    }

    /// Epistemic negation semantics used to construct this build.
    pub const fn negation_semantics(&self) -> NegationSemantics {
        self.negation_semantics
    }

    /// Projection-local, epistemic-stratified equivalence class table built for this projection.
    pub const fn eclasses(&self) -> &EClassTable {
        &self.eclasses
    }

    /// Number of materialized rows in one predicate.
    #[allow(unknown_lints, usize_in_public_api)] // row counts mirror collection lengths
    pub fn row_count(&self, predicate: &str) -> usize {
        self.facts
            .get(predicate)
            .map_or(0, std::collections::BTreeMap::len)
    }

    /// Explain why a target ground atom was or was not derived in this build.
    pub fn explain_missing(
        &self,
        predicate: &str,
        terms: Vec<mneme_core::Value>,
        limits: ExplainLimits,
    ) -> Result<MissingExplanation, Error> {
        provenance::explain_missing_in_build(
            self,
            predicate,
            &terms,
            provenance::ExplainContext {
                requested_revision: self.context.requested_revision,
                stale: false,
                limits: &limits,
                cancellation: None,
            },
        )
    }
    /// Inspect the structured coalesced temporal validity of a materialized fact.
    pub fn fact_validity(
        &self,
        predicate: &str,
        terms: &[mneme_core::Value],
    ) -> Option<&FactValidity> {
        self.facts
            .get(predicate)
            .and_then(|rows| rows.get(terms))
            .filter(|data| data.is_active())
            .map(|data| &data.validity)
    }

    /// Inspect the canonical coalesced [`IntervalSet`] of a materialized fact,
    /// returning `None` if the fact is absent or has `Unknown` validity.
    pub fn fact_intervals(
        &self,
        predicate: &str,
        terms: &[mneme_core::Value],
    ) -> Option<&IntervalSet> {
        self.fact_validity(predicate, terms)
            .and_then(FactValidity::as_interval_set)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct FactData {
    supports: Vec<Derivation>,
    sources: std::collections::BTreeSet<SourceKey>,
    truncated: bool,
    /// The canonical record a base fact came from; `None` for derived facts.
    canonical: Option<mneme_core::RecordId>,
    /// Every canonical record the fact rests on, transitively.
    canonical_roots: std::collections::BTreeSet<mneme_core::RecordId>,
    /// Originating vault aliases this fact rests on transitively.
    vaults: std::collections::BTreeSet<String>,
    /// Structured coalesced valid-time intervals (or fail-closed `Unknown`).
    validity: FactValidity,
    /// Epistemic provenance union (`+`) over all derivations of this row.
    epistemic: EpistemicStatus,
}

impl FactData {
    /// Whether this row is active: backed by support and not `EpistemicStatus::Rejected` (`ZERO`).
    pub(crate) fn is_active(&self) -> bool {
        !self.supports.is_empty() && self.epistemic != EpistemicStatus::Rejected
    }
}

/// A query over a built projection.
#[derive(Clone, Debug)]
pub struct Query {
    pub predicate: String,
    /// `None` leaves the position free; `Some` requires an exact value.
    pub constants: Vec<Option<mneme_core::Value>>,
    #[allow(unknown_lints)] // query limit mirrors collection lengths
    pub limit: usize,
    /// Allow an older served revision when the caller explicitly requests it.
    pub allow_stale: bool,
    pub cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl Query {
    /// A query with all positions free.
    #[allow(unknown_lints, usize_in_public_api)] // query limits mirror collection lengths
    pub fn all(predicate: impl Into<String>, limit: usize) -> Self {
        Query {
            predicate: predicate.into(),
            constants: Vec::new(),
            limit,
            allow_stale: false,
            cancellation: None,
        }
    }
}

/// One query row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryRow {
    pub values: Vec<mneme_core::Value>,
    pub supports: Vec<Derivation>,
    pub support_truncated: bool,
    pub epistemic: EpistemicStatus,
}

/// Query result with execution, coverage, and freshness kept separate.
#[derive(Clone, Debug)]
pub struct QueryResult {
    /// The relation the query names.
    pub relation: String,
    pub context: BuildContext,
    pub status: ExecutionStatus,
    /// Coverage of exactly the relations this answer depends on.
    pub coverage: Vec<Coverage>,
    pub rows: Vec<QueryRow>,
    pub exhaustive: bool,
    pub truncated: bool,
    pub absence_established: bool,
    /// Whether the answer serves a build older than the revision asked about.
    ///
    /// When set, [`QueryResult::requested_revision`] names the revision the
    /// caller asked about and [`QueryResult::served_revision`] the older build
    /// that answered it. A query without `allow_stale` is refused with
    /// [`Error::Stale`] instead of being answered.
    pub stale: bool,
    pub reason: Option<String>,
    /// The revision the answer was requested for: the current head, or the
    /// older revision a build deliberately named.
    pub requested_revision: mneme_core::WorkspaceRevisionId,
    /// The revision of the build that answered.
    pub served_revision: mneme_core::WorkspaceRevisionId,
    /// Participating vaults `(alias, root, requested_revision, served_revision)`.
    pub vaults: Vec<VaultRevision>,
    pub work: u64,
}

impl QueryResult {
    /// A stable metadata summary for transport and evaluation fixtures.
    ///
    /// Rows and derivations are intentionally omitted; their canonical values
    /// are transported separately. The summary keeps status, coverage,
    /// exhaustiveness, absence, and truncation distinguishable.
    #[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
    pub fn summary_value(&self) -> mneme_core::Value {
        let coverage = self.coverage_value();
        let mut entries = self.summary_header_entries();
        entries.extend(self.summary_context_entries());
        entries.extend(self.summary_state_entries(coverage));
        mneme_core::Value::symbol_dictionary(entries)
    }

    fn coverage_value(&self) -> mneme_core::Value {
        mneme_core::Value::sequence(
            self.coverage
                .iter()
                .map(|coverage| {
                    let mut entries = vec![
                        (
                            mneme_core::Symbol::from("predicate"),
                            mneme_core::Value::string(coverage.predicate.clone()),
                        ),
                        (
                            mneme_core::Symbol::from("status"),
                            mneme_core::Value::symbol(coverage.status.name()),
                        ),
                    ];
                    if let Some(reason) = &coverage.reason {
                        entries.push((
                            mneme_core::Symbol::from("reason"),
                            mneme_core::Value::string(reason.clone()),
                        ));
                    }
                    mneme_core::Value::symbol_dictionary(entries)
                })
                .collect(),
        )
    }

    fn summary_header_entries(&self) -> Vec<(mneme_core::Symbol, mneme_core::Value)> {
        vec![
            (
                mneme_core::Symbol::from("format"),
                mneme_core::Value::symbol("mneme.datalog.query-result"),
            ),
            (
                mneme_core::Symbol::from("version"),
                mneme_core::Value::integer(1),
            ),
            (
                mneme_core::Symbol::from("relation"),
                mneme_core::Value::string(self.relation.clone()),
            ),
            (
                mneme_core::Symbol::from("status"),
                mneme_core::Value::symbol(self.status.name()),
            ),
            (
                mneme_core::Symbol::from("requested-revision"),
                self.requested_revision.to_value(),
            ),
            (
                mneme_core::Symbol::from("served-revision"),
                self.served_revision.to_value(),
            ),
        ]
    }

    fn summary_context_entries(&self) -> Vec<(mneme_core::Symbol, mneme_core::Value)> {
        let mut entries = vec![
            (
                mneme_core::Symbol::from("scope"),
                self.context.scope.to_value(),
            ),
            (
                mneme_core::Symbol::from("schema-version"),
                mneme_core::Value::integer(self.context.schema_version),
            ),
            (
                mneme_core::Symbol::from("rule-bundle-id"),
                mneme_core::Value::string(self.context.rule_bundle_id.clone()),
            ),
            (
                mneme_core::Symbol::from("rule-bundle-version"),
                mneme_core::Value::string(self.context.rule_bundle_version.clone()),
            ),
            (
                mneme_core::Symbol::from("projection-build-id"),
                mneme_core::Value::string(self.context.projection_build_id.clone()),
            ),
            (
                mneme_core::Symbol::from("eligibility-generation"),
                mneme_core::Value::integer(self.context.eligibility_generation),
            ),
        ];
        if self.vaults.len() > 1 {
            entries.push((
                mneme_core::Symbol::from("vaults"),
                vault_revision_sequence(&self.vaults),
            ));
        }
        assert!(!self.context.projection_build_id.is_empty());
        assert!(!self.context.rule_bundle_id.is_empty());
        entries
    }

    fn summary_state_entries(
        &self,
        coverage: mneme_core::Value,
    ) -> Vec<(mneme_core::Symbol, mneme_core::Value)> {
        let mut entries = vec![
            (mneme_core::Symbol::from("coverage"), coverage),
            (
                mneme_core::Symbol::from("row-count"),
                mneme_core::Value::integer(self.rows.len() as i64),
            ),
            (
                mneme_core::Symbol::from("exhaustive"),
                mneme_core::Value::Boolean(self.exhaustive),
            ),
            (
                mneme_core::Symbol::from("truncated"),
                mneme_core::Value::Boolean(self.truncated),
            ),
            (
                mneme_core::Symbol::from("absence-established"),
                mneme_core::Value::Boolean(self.absence_established),
            ),
            (
                mneme_core::Symbol::from("stale"),
                mneme_core::Value::Boolean(self.stale),
            ),
            (
                mneme_core::Symbol::from("work"),
                mneme_core::Value::integer(self.work),
            ),
        ];
        if let Some(reason) = &self.reason {
            entries.push((
                mneme_core::Symbol::from("reason"),
                mneme_core::Value::string(reason.clone()),
            ));
        }
        entries
    }
}

/// A bounded projection service over one mutable workspace.
pub struct Service<'w> {
    workspace: &'w mut mneme_store::Workspace,
    builds: std::collections::BTreeMap<String, Build>,
    query_cache: std::collections::BTreeMap<QueryCacheKey, QueryResult>,
    participants: std::collections::BTreeSet<String>,
}

/// The values [`Service::build`] pins before any snapshot is read.
///
/// They travel together so the evaluated context, the wall-clock budget and the
/// identity derived from them cannot be paired with the wrong snapshot.
struct BuildInvocation {
    /// The content-derived build identity.
    build_id: String,
    /// The eligibility generation the build observes.
    generation: u64,
    /// Whether the request named the head revision when the build started.
    requested_was_head: bool,
    /// The instant taken before the snapshot and history were loaded.
    start: std::time::Instant,
    /// Evaluation configuration (temporal interval bounds, negation semantics, and WFS mode).
    config: EvaluationConfig,
}

/// The query cache identity.
///
/// The build's status and work join the key: a terminal build is rebuilt under
/// the same identity, and an answer computed from the earlier attempt must not
/// be served for the newer one.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct QueryCacheKey {
    build_id: String,
    requested_revision: mneme_core::WorkspaceRevisionId,
    status: &'static str,
    work: u64,
    predicate: String,
    constants: Vec<Option<mneme_core::Value>>,
    limit: usize,
    allow_stale: bool,
}

mod engine;
mod freejoin;
mod ivm;
mod provenance;
mod rules;

pub use provenance::{
    EpistemicStatus, ExplainLimits, ExplainMissingRequest, MissingExplanation, MissingReason,
    MissingReasonKind, MissingStatus,
};

impl RuleBundle {
    /// Validate this bundle without registering or executing it.
    pub fn validate(&self) -> Result<RuleProgram, Vec<RuleDiagnostic>> {
        rules::validate(self)
    }

    /// Validate this bundle for bounded Well-Founded Semantics evaluation,
    /// permitting bounded cycles through negation.
    pub fn validate_well_founded(&self) -> Result<RuleProgram, Vec<RuleDiagnostic>> {
        rules::validate_well_founded(self)
    }
}

fn config_build_id(mut build_id: String, config: EvaluationConfig) -> String {
    if config.temporal != TemporalConfig::default() {
        build_id.push_str(&format!(":ti{}", config.temporal.max_intervals_per_fact));
    }
    if config.negation == NegationSemantics::Strict {
        build_id.push_str(":neg-strict");
    }
    if config.mode == EvaluationMode::WellFounded {
        build_id.push_str(":wfs");
    }
    if config.egraph != EGraphConfig::default() {
        build_id.push_str(&format!(
            ":eg{}:{}",
            config.egraph.max_rebuild_rounds, config.egraph.max_unions
        ));
    }
    build_id
}

/// The public build assembled from one evaluation's facts.
fn assembled_build(
    request: &BuildRequest,
    program: RuleProgram,
    context: BuildContext,
    evaluated: engine::BuildFacts,
    vault_barriers: Vec<VaultBarrier>,
) -> Build {
    Build {
        context,
        status: evaluated.status,
        coverage: evaluated.coverage,
        limits: request.limits.clone(),
        work: evaluated.work,
        support_truncated: evaluated.support_truncated,
        limit_reached: evaluated.limit_reached,
        declaration_valid: evaluated.declaration_valid,
        facts: evaluated
            .facts
            .into_iter()
            .map(|(predicate, store)| (predicate, store.rows))
            .collect(),
        justifications: evaluated.justifications,
        negation_semantics: evaluated.negation_semantics,
        eclasses: evaluated.eclasses,
        arities: program.arities,
        bundle: program.bundle,
        vault_barriers,
    }
}

impl<'w> Service<'w> {
    /// Wrap a workspace.
    pub fn new(workspace: &'w mut mneme_store::Workspace) -> Self {
        Service {
            workspace,
            builds: std::collections::BTreeMap::new(),
            query_cache: std::collections::BTreeMap::new(),
            participants: std::collections::BTreeSet::new(),
        }
    }

    /// Build a private projection and optionally publish its pointer through
    /// the workspace projection registry.
    pub fn build(&mut self, request: BuildRequest) -> Result<Build, Error> {
        self.build_with_config(request, EvaluationConfig::default())
    }

    /// Build a projection with an explicit [`TemporalConfig`] bounding
    /// per-fact coalesced intervals.
    pub fn build_with_temporal_config(
        &mut self,
        request: BuildRequest,
        temporal_config: TemporalConfig,
    ) -> Result<Build, Error> {
        self.build_with_config(
            request,
            EvaluationConfig {
                temporal: temporal_config,
                ..EvaluationConfig::default()
            },
        )
    }

    /// Build a projection with an explicit [`EGraphConfig`] bounding e-graph
    /// rebuild rounds and total union operations.
    pub fn build_with_egraph_config(
        &mut self,
        request: BuildRequest,
        egraph_config: EGraphConfig,
    ) -> Result<Build, Error> {
        self.build_with_config(
            request,
            EvaluationConfig {
                egraph: egraph_config,
                ..EvaluationConfig::default()
            },
        )
    }

    /// Build a projection with an explicit [`EvaluationConfig`] selecting
    /// temporal interval bounds, epistemic negation semantics, and WFS mode.
    #[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
    pub fn build_with_config(
        &mut self,
        request: BuildRequest,
        config: EvaluationConfig,
    ) -> Result<Build, Error> {
        // The clock starts before the snapshot and history are read, so the
        // wall-clock bound covers loading as well as evaluation.
        let start = engine::evaluation_start();
        let program = if config.mode == EvaluationMode::WellFounded {
            request.bundle.validate_well_founded()
        } else {
            request.bundle.validate()
        }
        .map_err(Error::InvalidBundle)?;
        let generation = self.workspace.eligibility_generation()?;
        let head_revision = self.workspace.current_revision()?;
        let build_id = config_build_id(
            rules::build_id(rules::BuildIdContext {
                revision: request.revision,
                scope: &request.scope,
                generation,
                bundle: &program.bundle,
                limits: &request.limits,
                incomplete_extents: &request.incomplete_extents,
                at: request.at,
            }),
            config,
        );
        let is_cancellation_requested = request
            .cancellation
            .as_ref()
            .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed));
        if let Some(existing) = self.builds.get(&build_id).cloned()
            && !is_cancellation_requested
            && !matches!(
                existing.status,
                ExecutionStatus::Timeout | ExecutionStatus::Cancelled | ExecutionStatus::Failed
            )
        {
            if request.publish {
                self.publish(&existing)?;
            }
            return Ok(existing);
        }
        let max_cached_builds = 1_024;
        if !self.builds.contains_key(&build_id) && self.builds.len() >= max_cached_builds {
            return Err(Error::Failed(
                "Datalog build cache exceeds the 1024-entry bound".to_owned(),
            ));
        }
        let snapshot = self.workspace.snapshot_at(request.revision, None)?;
        let build = self.build_from_snapshot(
            &request,
            program,
            BuildInvocation {
                build_id: build_id.clone(),
                generation,
                requested_was_head: request.revision == head_revision,
                start,
                config,
            },
            snapshot,
        )?;
        if request.publish {
            self.publish(&build)?;
        }
        self.builds.insert(build_id, build.clone());
        Ok(build)
    }

    /// Build a non-published federated projection across the primary workspace
    /// and strictly read-only attached vaults.
    pub fn build_federated(&mut self, federated: FederatedBuildRequest) -> Result<Build, Error> {
        let FederatedBuildRequest {
            request,
            attachments,
        } = federated;
        let sources = attachments
            .into_iter()
            .map(FederatedVaultSource::Local)
            .collect();
        self.build_federated_sources(request, sources)
    }

    /// Build a non-published federated projection across the primary workspace
    /// and an ordered mix of local and pre-loaded external attached vaults.
    pub fn build_federated_sources(
        &mut self,
        request: BuildRequest,
        sources: Vec<FederatedVaultSource>,
    ) -> Result<Build, Error> {
        if sources.is_empty() {
            return self.build(request);
        }
        if request.publish {
            return Err(Error::Failed(
                "cannot publish a federated multi-vault projection".to_owned(),
            ));
        }
        validate_federated_sources(&sources)?;
        let start = engine::evaluation_start();
        let program = request.bundle.validate().map_err(Error::InvalidBundle)?;
        let primary_generation = self.workspace.eligibility_generation()?;
        let primary_head = self.workspace.current_revision()?;
        let primary_loaded = load_vault_context(VaultLoadSpec {
            workspace: self.workspace,
            alias: PRIMARY_VAULT_ALIAS,
            requested_revision: request.revision,
            pinned_generation: None,
            scope: &request.scope,
            access: &request.access,
        })?;
        let attached_states =
            open_federated_vault_sources(&sources, &request.scope, &request.access)?;
        assert_eq!(attached_states.len(), sources.len());
        let vault_build_ids = collect_vault_build_ids(
            self.workspace,
            primary_generation,
            &primary_loaded,
            &attached_states,
        );
        let build_id = rules::federated_build_id(
            rules::BuildIdContext {
                revision: request.revision,
                scope: &request.scope,
                generation: primary_generation,
                bundle: &program.bundle,
                limits: &request.limits,
                incomplete_extents: &request.incomplete_extents,
                at: request.at,
            },
            &vault_build_ids,
        );
        assert!(!build_id.is_empty());
        if let Some(mut existing) = self.cached_build(&request, &build_id)? {
            existing.context.requested_was_head = request.revision == primary_head;
            existing.vault_barriers = collect_vault_barriers(&attached_states);
            return Ok(existing);
        }
        let context = BuildContext {
            requested_revision: request.revision,
            served_revision: primary_loaded.metadata.served_revision,
            scope: request.scope.clone(),
            schema_version: program.bundle.schema_version,
            rule_bundle_id: program.bundle.id.clone(),
            rule_bundle_version: program.bundle.version.clone(),
            projection_build_id: build_id.clone(),
            eligibility_generation: primary_generation,
            requested_was_head: request.revision == primary_head,
            vaults: collect_vault_revisions(&primary_loaded, &attached_states),
        };
        let sources = collect_vault_sources(&primary_loaded, &attached_states);
        let evaluated = engine::build_federated(&sources, &request, &context, &program, start);
        verify_federated_barriers(self.workspace, primary_generation, &attached_states)?;
        let vault_barriers = collect_vault_barriers(&attached_states);
        let build = assembled_build(&request, program, context, evaluated, vault_barriers);
        self.builds.insert(build_id, build.clone());
        Ok(build)
    }

    fn cached_build(&self, request: &BuildRequest, build_id: &str) -> Result<Option<Build>, Error> {
        assert!(!build_id.is_empty());
        let is_cancellation_requested = request
            .cancellation
            .as_ref()
            .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed));
        if let Some(existing) = self.builds.get(build_id).cloned()
            && !is_cancellation_requested
            && !matches!(
                existing.status,
                ExecutionStatus::Timeout | ExecutionStatus::Cancelled | ExecutionStatus::Failed
            )
        {
            return Ok(Some(existing));
        }
        let max_cached_builds = 1_024;
        if !self.builds.contains_key(build_id) && self.builds.len() >= max_cached_builds {
            return Err(Error::Failed(
                "Datalog build cache exceeds the 1024-entry bound".to_owned(),
            ));
        }
        assert!(self.builds.len() <= max_cached_builds);
        Ok(None)
    }

    fn build_from_snapshot(
        &mut self,
        request: &BuildRequest,
        program: RuleProgram,
        invocation: BuildInvocation,
        snapshot: mneme_store::Snapshot,
    ) -> Result<Build, Error> {
        let BuildInvocation {
            build_id,
            generation,
            requested_was_head,
            start,
            config,
        } = invocation;
        debug_assert!(!build_id.is_empty());
        debug_assert!(!program.bundle.id.is_empty());
        let loaded = load_vault_from_snapshot(
            VaultLoadSpec {
                workspace: self.workspace,
                alias: PRIMARY_VAULT_ALIAS,
                requested_revision: request.revision,
                pinned_generation: Some(generation),
                scope: &request.scope,
                access: &request.access,
            },
            snapshot,
        )?;
        let context = BuildContext {
            requested_revision: request.revision,
            served_revision: loaded.metadata.served_revision,
            scope: request.scope.clone(),
            schema_version: program.bundle.schema_version,
            rule_bundle_id: program.bundle.id.clone(),
            rule_bundle_version: program.bundle.version.clone(),
            projection_build_id: build_id,
            eligibility_generation: generation,
            requested_was_head,
            vaults: vec![loaded.metadata],
        };
        let evaluated = engine::build(
            &loaded.view,
            request,
            &context,
            &program,
            engine::BuildEnvironment {
                start,
                current_sources: &loaded.current_sources,
                config,
            },
        );
        if self.workspace.eligibility_generation()? != generation {
            return Err(Error::Failed(
                "eligibility barrier advanced during projection build".to_owned(),
            ));
        }
        Ok(assembled_build(
            request,
            program,
            context,
            evaluated,
            Vec::new(),
        ))
    }

    /// Byte availability currently in force, keyed by source record.
    ///
    /// A build of an earlier revision sees that revision's records, but pruning
    /// or erasure that happened afterwards still decides whether its bytes may
    /// be quoted. An empty overlay means the pinned revision is head.
    #[allow(dead_code)]
    fn source_availability_overlay(
        &self,
        pinned: mneme_core::WorkspaceRevisionId,
    ) -> Result<engine::AvailabilityMap, Error> {
        workspace_source_availability_overlay(self.workspace, pinned)
    }

    /// Publish a previously built private projection after a fresh barrier
    /// check. A build whose eligibility generation is no longer current is
    /// rejected without replacing the registered projection.
    pub fn publish_build(&mut self, build: &Build) -> Result<(), Error> {
        self.publish(build)
    }

    fn publish(&mut self, build: &Build) -> Result<(), Error> {
        if build.status != ExecutionStatus::Complete {
            return Err(Error::Failed(
                "cannot publish a partial, timed-out, cancelled, or failed projection".to_owned(),
            ));
        }
        let generation = self.workspace.eligibility_generation()?;
        if generation != build.context.eligibility_generation {
            return Err(mneme_store::Failure::BarrierAdvanced {
                pinned: build.context.eligibility_generation,
                current: generation,
            }
            .into());
        }
        let projection_name = format!("datalog:{}:{}", build.bundle.id, build.context.scope);
        let participant = projection_name.clone();
        if !self.participants.contains(&participant) {
            self.workspace
                .register_retention_participant(mneme_store::RetentionParticipant {
                    name: participant.clone(),
                    storage_role: "datalog-projection".to_owned(),
                    supports_invalidation: true,
                    supports_purge: true,
                    checks_generation: true,
                    inventory_locator: format!("projection/datalog/{}", build.bundle.id),
                })?;
            self.participants.insert(participant);
        }
        self.workspace
            .register_projection(mneme_store::ProjectionRegistration {
                name: projection_name.clone(),
                revision: build.context.served_revision,
                // The build's own generation, never whatever is current when
                // registration happens.
                eligibility_generation: build.context.eligibility_generation,
                schema_version: build.context.schema_version,
                rule_version: build.context.rule_bundle_version.clone(),
                index_version: INDEX_VERSION.to_owned(),
                scope: build.context.scope.to_string(),
            })?;
        // Read the registration back so a projection that a consumer would
        // reject as incompatible is reported here, not at its first use.
        let resolution = self.workspace.resolve_projection_versions(
            &projection_name,
            build.context.served_revision,
            &build.context.scope,
            build.context.schema_version,
            &build.context.rule_bundle_version,
            INDEX_VERSION,
        )?;
        if !matches!(resolution, mneme_store::ProjectionResolution::Compatible(_)) {
            return Err(Error::Failed(
                "the registered projection did not resolve as compatible".to_owned(),
            ));
        }
        Ok(())
    }

    /// Query a built projection. A changed eligibility generation always fails;
    /// a build that pinned head and has since been superseded requires
    /// `allow_stale`.
    pub fn query(&mut self, build_id: &str, query: Query) -> Result<QueryResult, Error> {
        let build = self
            .builds
            .get(build_id)
            .cloned()
            .ok_or_else(|| Error::MissingBuild(build_id.to_owned()))?;
        self.query_loaded(build, query)
    }

    /// Query an explicit build object, re-checking the barrier fields its
    /// private state records against the workspace.
    pub fn query_build(&mut self, build: &Build, query: Query) -> Result<QueryResult, Error> {
        self.query_loaded(build.clone(), query)
    }

    /// Explain why a target ground atom was or was not derived in a built projection.
    pub fn explain_missing(
        &mut self,
        build_id: &str,
        request: ExplainMissingRequest,
    ) -> Result<MissingExplanation, Error> {
        let build = self
            .builds
            .get(build_id)
            .cloned()
            .ok_or_else(|| Error::MissingBuild(build_id.to_owned()))?;
        self.explain_missing_build(&build, request)
    }

    /// Explain why a target ground atom was or was not derived in an explicit build,
    /// re-checking workspace barriers and staleness.
    pub fn explain_missing_build(
        &mut self,
        build: &Build,
        request: ExplainMissingRequest,
    ) -> Result<MissingExplanation, Error> {
        let (requested_revision, stale) = self.verify_build_barriers(build, request.allow_stale)?;
        provenance::explain_missing_in_build(
            build,
            &request.predicate,
            &request.terms,
            provenance::ExplainContext {
                requested_revision,
                stale,
                limits: &request.limits,
                cancellation: request.cancellation.as_ref(),
            },
        )
    }

    fn verify_build_barriers(
        &self,
        build: &Build,
        allow_stale: bool,
    ) -> Result<(mneme_core::WorkspaceRevisionId, bool), Error> {
        assert!(!build.context.projection_build_id.is_empty());
        assert!(build.context.schema_version > 0);
        let current_generation = self.workspace.eligibility_generation()?;
        if current_generation != build.context.eligibility_generation {
            return Err(mneme_store::Failure::BarrierAdvanced {
                pinned: build.context.eligibility_generation,
                current: current_generation,
            }
            .into());
        }
        let served_revisions = std::collections::BTreeSet::from([build.context.served_revision]);
        if !self
            .workspace
            .revision_sequences_for(&served_revisions)?
            .contains_key(&build.context.served_revision)
        {
            return Err(Error::Failed(
                "the build serves a revision that is not committed in this workspace".to_owned(),
            ));
        }
        let current_revision = self.workspace.current_revision()?;
        let requested_revision = if build.context.requested_was_head {
            current_revision
        } else {
            build.context.requested_revision
        };
        let mut is_stale = requested_revision != build.context.served_revision;
        if is_stale && !allow_stale {
            return Err(Error::Stale {
                requested: requested_revision,
                served: build.context.served_revision,
            });
        }
        let staleness_policy = if allow_stale {
            StalenessPolicy::AllowStale
        } else {
            StalenessPolicy::Strict
        };
        for barrier in &build.vault_barriers {
            if verify_attached_vault_barrier(barrier, &build.context.vaults, staleness_policy)? {
                is_stale = true;
            }
        }
        Ok((requested_revision, is_stale))
    }

    #[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
    fn query_loaded(&mut self, build: Build, query: Query) -> Result<QueryResult, Error> {
        let (requested_revision, is_stale) =
            self.verify_build_barriers(&build, query.allow_stale)?;
        if query
            .cancellation
            .as_ref()
            .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed))
        {
            return Ok(QueryResult {
                relation: query.predicate.clone(),
                context: build.context.clone(),
                status: ExecutionStatus::Cancelled,
                coverage: build.coverage.clone(),
                rows: Vec::new(),
                exhaustive: false,
                truncated: false,
                absence_established: false,
                stale: is_stale,
                reason: Some("query cancelled".to_owned()),
                requested_revision,
                served_revision: build.context.served_revision,
                vaults: build.context.vaults.clone(),
                work: 0,
            });
        }
        self.query_cached(&build, &query, requested_revision)
    }

    fn query_cached(
        &mut self,
        build: &Build,
        query: &Query,
        requested_revision: mneme_core::WorkspaceRevisionId,
    ) -> Result<QueryResult, Error> {
        let key = QueryCacheKey {
            build_id: build.context.projection_build_id.clone(),
            requested_revision,
            status: build.status.name(),
            work: build.work,
            predicate: query.predicate.clone(),
            constants: query.constants.clone(),
            limit: query.limit,
            allow_stale: query.allow_stale,
        };
        if let Some(cached) = self.query_cache.get(&key) {
            return Ok(cached.clone());
        }
        validate_query_arity(build, query)?;
        let coverage = dependency_coverage(build, &query.predicate);
        let rows = matching_query_rows(build, query);
        let result = query_result(build, query, coverage, rows, requested_revision);
        self.query_cache.insert(key, result.clone());
        Ok(result)
    }
}

/// The records this build may see: exactly those visible under the kernel
/// visibility rule for the build's scope and the caller's access.
///
/// Projections are operational, so a hypothesis scope never widens the view even
/// when the caller is authorized for it: an excluded record must not ground an
/// in-scope fact, change a count, or leak its identity into support.
/// Filter a committed snapshot down to the records visible under the kernel's
/// operational projection rule for `scope` and `access`.
pub fn filter_visible_snapshot(
    snapshot: mneme_store::Snapshot,
    scope: &mneme_core::ScopeId,
    access: &mneme_memory::Access,
) -> mneme_store::Snapshot {
    visible_snapshot(snapshot, scope, access)
}

pub(crate) fn source_availability_overlay(
    workspace: &mneme_store::Workspace,
    pinned: mneme_core::WorkspaceRevisionId,
) -> Result<engine::AvailabilityMap, Error> {
    workspace_source_availability_overlay(workspace, pinned)
}

pub(crate) fn visible_snapshot(
    mut snapshot: mneme_store::Snapshot,
    scope: &mneme_core::ScopeId,
    access: &mneme_memory::Access,
) -> mneme_store::Snapshot {
    snapshot.records.retain(|record| {
        mneme_kernel::isolation::record_visible(&mneme_kernel::isolation::VisibilityFacts {
            same_scope: record.scope == *scope,
            record_class: record.scope.class().to_kernel(),
            include_hypothetical: false,
            record_scope_authorized: access.allows(&record.scope),
        })
    });
    snapshot
}

/// A view-context refusal, with a store refusal kept on its own variant.
pub(crate) fn view_context_error(error: mneme_memory::EvidenceError) -> Error {
    match error {
        mneme_memory::EvidenceError::Store(error) => Error::Store(error),
        error @ mneme_memory::EvidenceError::InvalidRecord { .. }
        | error @ mneme_memory::EvidenceError::Missing { .. }
        | error @ mneme_memory::EvidenceError::Policy(_)
        | error @ mneme_memory::EvidenceError::Validation(_)
        | error @ mneme_memory::EvidenceError::Invalid(_)
        | error @ mneme_memory::EvidenceError::Truncated => Error::Engine(error),
    }
}

pub(crate) fn validate_query_arity(build: &Build, query: &Query) -> Result<(), Error> {
    let arity = build
        .arities
        .get(&query.predicate)
        .copied()
        .ok_or_else(|| Error::UnknownPredicate(query.predicate.clone()))?;
    if query.constants.is_empty() {
        return Ok(());
    }
    if query.constants.len() != arity {
        return Err(Error::InvalidQuery(
            "query constant count does not match predicate arity",
        ));
    }
    if let Some(schema) = rules::canonical_schema(&query.predicate) {
        for (constant, kind) in query.constants.iter().zip(schema) {
            if let Some(constant) = constant
                && !kind.accepts(constant)
            {
                return Err(Error::InvalidQuery(
                    "query constant kind does not match the canonical extent",
                ));
            }
        }
    }
    Ok(())
}

/// Coverage of exactly the relations one answer depends on.
///
/// Reporting the whole build's coverage made every answer depend on unrelated
/// extents and left the queried relation unnamed.
pub(crate) fn dependency_coverage(build: &Build, predicate: &str) -> Vec<Coverage> {
    let mut needed = std::collections::BTreeSet::new();
    let mut pending = vec![predicate.to_owned()];
    while let Some(current) = pending.pop() {
        if !needed.insert(current.clone()) {
            continue;
        }
        for rule in &build.bundle.rules {
            if rule.head.predicate != current {
                continue;
            }
            for literal in &rule.body {
                match literal {
                    Literal::Positive(atom)
                    | Literal::Negative(atom)
                    | Literal::DiamondMinus { atom, .. }
                    | Literal::BoxMinus { atom, .. } => {
                        pending.push(atom.predicate.clone());
                    }
                    Literal::Since {
                        maintained,
                        trigger,
                        ..
                    } => {
                        pending.push(maintained.predicate.clone());
                        pending.push(trigger.predicate.clone());
                    }
                    Literal::Allen { left, right, .. } => {
                        pending.push(left.predicate.clone());
                        pending.push(right.predicate.clone());
                    }
                    Literal::Compare { .. } | Literal::Aggregate { .. } | Literal::Forbidden(_) => {
                    }
                }
            }
        }
    }
    needed
        .into_iter()
        .map(|name| {
            build
                .coverage
                .iter()
                .find(|coverage| coverage.predicate == name)
                .cloned()
                .unwrap_or(Coverage {
                    predicate: name,
                    status: CoverageStatus::Unknown,
                    reason: Some("predicate is absent from this build".to_owned()),
                })
        })
        .collect()
}

fn matches_query_constants(query: &Query, terms: &[mneme_core::Value]) -> bool {
    (query.constants.is_empty() || query.constants.len() == terms.len())
        && query
            .constants
            .iter()
            .zip(terms)
            .all(|(constant, value)| constant.as_ref().is_none_or(|c| c == value))
}

pub(crate) fn matching_query_rows(build: &Build, query: &Query) -> Vec<QueryRow> {
    let Some(facts) = build.facts.get(&query.predicate) else {
        return Vec::new();
    };
    facts
        .iter()
        .filter(|(terms, _)| matches_query_constants(query, terms))
        .map(|(terms, data)| QueryRow {
            values: terms.clone(),
            supports: data.supports.clone(),
            support_truncated: data.truncated,
            epistemic: data.epistemic,
        })
        .collect()
}

fn kernel_coverage(status: CoverageStatus) -> mneme_kernel::completeness::Coverage {
    if status == CoverageStatus::Complete {
        mneme_kernel::completeness::Coverage::Complete
    } else if status == CoverageStatus::Incomplete {
        mneme_kernel::completeness::Coverage::Incomplete
    } else {
        mneme_kernel::completeness::Coverage::Unknown
    }
}

pub(crate) fn query_result(
    build: &Build,
    query: &Query,
    coverage: Vec<Coverage>,
    mut rows: Vec<QueryRow>,
    requested_revision: mneme_core::WorkspaceRevisionId,
) -> QueryResult {
    let total = rows.len();
    let limit = if query.limit == 0 {
        build.limits.max_result_rows
    } else {
        query.limit.min(build.limits.max_result_rows)
    };
    rows.truncate(limit);
    let is_truncated = total > limit;
    let is_terminal_failure = matches!(
        build.status,
        ExecutionStatus::Timeout | ExecutionStatus::Cancelled | ExecutionStatus::Failed
    );
    let combined = coverage.iter().fold(
        mneme_kernel::completeness::Coverage::Complete,
        |combined, coverage| {
            mneme_kernel::completeness::combine_coverage(combined, kernel_coverage(coverage.status))
        },
    );
    // A row vector cannot be longer than `usize::MAX`, which fits `u64` on every
    // supported target; the clamp only keeps the conversion total, and a
    // saturated count still reports the answer as non-empty.
    let (row_count, is_row_count_exact) = match u64::try_from(total) {
        Ok(row_count) => (row_count, true),
        Err(_) => (u64::MAX, false),
    };
    let is_exhaustive = combined == mneme_kernel::completeness::Coverage::Complete
        && !is_truncated
        && !is_terminal_failure
        && is_row_count_exact;
    let facts = mneme_kernel::completeness::AnswerFacts {
        rows: row_count,
        exhaustive: is_exhaustive,
        coverage: combined,
        limit_reached: is_truncated || is_terminal_failure || build.limit_reached,
        declaration_valid: build.declaration_valid,
        generation_current: true,
    };
    let is_complete = mneme_kernel::completeness::answer_complete(&facts);
    let is_absence_established = mneme_kernel::completeness::absence_established(&facts);
    // An exhaustive answer over complete dependencies is a complete answer even
    // when an unrelated extent of the build is partial.
    let status = if is_complete {
        ExecutionStatus::Complete
    } else {
        build.status
    };
    QueryResult {
        relation: query.predicate.clone(),
        context: build.context.clone(),
        status,
        coverage,
        rows,
        exhaustive: is_exhaustive,
        truncated: is_truncated,
        absence_established: is_absence_established,
        stale: requested_revision != build.context.served_revision,
        reason: if is_absence_established {
            Some("absence within the declared complete relation".to_owned())
        } else if !is_exhaustive {
            Some("result is not exhaustive for this context".to_owned())
        } else {
            None
        },
        requested_revision,
        served_revision: build.context.served_revision,
        vaults: build.context.vaults.clone(),
        work: build.work,
    }
}

struct LoadedVaultView {
    metadata: VaultRevision,
    view: mneme_memory::View,
    current_sources: engine::AvailabilityMap,
}

fn vault_revision_sequence(vaults: &[VaultRevision]) -> mneme_core::Value {
    mneme_core::Value::sequence(
        vaults
            .iter()
            .map(|vault| {
                let mut entries = vec![
                    (
                        mneme_core::Symbol::from("alias"),
                        mneme_core::Value::string(vault.alias.clone()),
                    ),
                    (
                        mneme_core::Symbol::from("root"),
                        mneme_core::Value::string(vault.root.display().to_string()),
                    ),
                    (
                        mneme_core::Symbol::from("requested-revision"),
                        vault.requested_revision.to_value(),
                    ),
                    (
                        mneme_core::Symbol::from("served-revision"),
                        vault.served_revision.to_value(),
                    ),
                ];
                if let Some(peer) = vault.peer() {
                    entries.push((
                        mneme_core::Symbol::from("peer"),
                        mneme_core::Value::string(peer.to_owned()),
                    ));
                }
                mneme_core::Value::symbol_dictionary(entries)
            })
            .collect(),
    )
}

struct VaultLoadSpec<'a> {
    workspace: &'a mneme_store::Workspace,
    alias: &'a str,
    requested_revision: mneme_core::WorkspaceRevisionId,
    pinned_generation: Option<u64>,
    scope: &'a mneme_core::ScopeId,
    access: &'a mneme_memory::Access,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StalenessPolicy {
    Strict,
    AllowStale,
}

fn verify_attached_vault_barrier(
    barrier: &VaultBarrier,
    context_vaults: &[VaultRevision],
    staleness_policy: StalenessPolicy,
) -> Result<bool, Error> {
    assert!(!barrier.alias.is_empty());
    debug_assert!(!context_vaults.is_empty());
    let has_context_match = context_vaults.iter().any(|vault| {
        vault.alias == barrier.alias && vault.served_revision == barrier.served_revision
    });
    if !has_context_match {
        return Err(Error::Failed(format!(
            "attached vault {:?} barrier does not match build context revision",
            barrier.alias
        )));
    }
    if barrier.is_external {
        return Ok(false);
    }
    let attached = mneme_store::Workspace::open_read_only(
        &barrier.root,
        mneme_store::WorkspaceConfig::new(
            Box::new(mneme_store::SystemClock),
            Box::new(mneme_store::NoFaults),
        ),
    )?;
    let current_generation = attached.eligibility_generation()?;
    if current_generation != barrier.eligibility_generation {
        return Err(mneme_store::Failure::BarrierAdvanced {
            pinned: barrier.eligibility_generation,
            current: current_generation,
        }
        .into());
    }
    let served_revisions = std::collections::BTreeSet::from([barrier.served_revision]);
    if !attached
        .revision_sequences_for(&served_revisions)?
        .contains_key(&barrier.served_revision)
    {
        return Err(Error::Failed(format!(
            "attached vault {:?} build serves a revision that is not committed in its workspace",
            barrier.alias
        )));
    }
    if barrier.requested_was_head {
        let current_revision = attached.current_revision()?;
        if current_revision != barrier.served_revision {
            if staleness_policy == StalenessPolicy::Strict {
                return Err(Error::Stale {
                    requested: current_revision,
                    served: barrier.served_revision,
                });
            }
            return Ok(true);
        }
    }
    Ok(false)
}

struct AttachedVaultState {
    workspace: Option<mneme_store::Workspace>,
    generation: u64,
    requested_was_head: bool,
    loaded: LoadedVaultView,
}

fn collect_vault_barriers(attached_states: &[AttachedVaultState]) -> Vec<VaultBarrier> {
    assert!(!attached_states.is_empty());
    attached_states
        .iter()
        .map(|state| VaultBarrier {
            alias: state.loaded.metadata.alias.clone(),
            root: state.workspace.as_ref().map_or_else(
                || state.loaded.metadata.root.clone(),
                |ws| ws.root().to_path_buf(),
            ),
            served_revision: state.loaded.metadata.served_revision,
            eligibility_generation: state.generation,
            requested_was_head: state.requested_was_head,
            is_external: state.workspace.is_none(),
        })
        .collect()
}

fn open_federated_vault_sources(
    sources: &[FederatedVaultSource],
    scope: &mneme_core::ScopeId,
    access: &mneme_memory::Access,
) -> Result<Vec<AttachedVaultState>, Error> {
    assert!(!sources.is_empty());
    let attached_states = sources
        .iter()
        .map(|source| {
            if let FederatedVaultSource::Local(attachment) = source {
                let (workspace, generation, loaded) =
                    open_single_attached_vault(attachment, scope, access)?;
                Ok(AttachedVaultState {
                    workspace: Some(workspace),
                    generation,
                    requested_was_head: attachment.revision.is_none(),
                    loaded,
                })
            } else if let FederatedVaultSource::External(external) = source {
                if external.view.revision() != external.metadata.served_revision {
                    return Err(Error::Failed(format!(
                        "external vault {:?} view revision does not match served revision",
                        external.metadata.alias
                    )));
                }
                Ok(AttachedVaultState {
                    workspace: None,
                    generation: external.eligibility_generation,
                    requested_was_head: false,
                    loaded: LoadedVaultView {
                        metadata: external.metadata.clone(),
                        view: external.view.clone(),
                        current_sources: external.current_sources.clone(),
                    },
                })
            } else {
                Err(Error::Failed(
                    "unsupported federated vault source".to_owned(),
                ))
            }
        })
        .collect::<Result<Vec<_>, Error>>()?;
    assert_eq!(attached_states.len(), sources.len());
    Ok(attached_states)
}

fn open_single_attached_vault(
    attachment: &VaultAttachment,
    scope: &mneme_core::ScopeId,
    access: &mneme_memory::Access,
) -> Result<(mneme_store::Workspace, u64, LoadedVaultView), Error> {
    assert!(!attachment.alias.is_empty());
    let workspace = mneme_store::Workspace::open_read_only(
        &attachment.root,
        mneme_store::WorkspaceConfig::new(
            Box::new(mneme_store::SystemClock),
            Box::new(mneme_store::NoFaults),
        ),
    )?;
    let generation = workspace.eligibility_generation()?;
    let head = workspace.current_revision()?;
    let requested_revision = attachment.revision.unwrap_or(head);
    let loaded = load_vault_context(VaultLoadSpec {
        workspace: &workspace,
        alias: &attachment.alias,
        requested_revision,
        pinned_generation: Some(generation),
        scope,
        access,
    })?;
    assert_eq!(loaded.metadata.alias, attachment.alias);
    Ok((workspace, generation, loaded))
}

fn collect_vault_build_ids<'a>(
    primary_workspace: &'a mneme_store::Workspace,
    primary_generation: u64,
    primary_loaded: &'a LoadedVaultView,
    attached_states: &'a [AttachedVaultState],
) -> Vec<rules::VaultBuildId<'a>> {
    std::iter::once(rules::VaultBuildId {
        alias: PRIMARY_VAULT_ALIAS,
        root: primary_workspace.root(),
        revision: primary_loaded.metadata.served_revision,
        generation: primary_generation,
    })
    .chain(attached_states.iter().map(|state| {
        rules::VaultBuildId {
            alias: &state.loaded.metadata.alias,
            root: state
                .workspace
                .as_ref()
                .map_or(state.loaded.metadata.root.as_path(), |ws| ws.root()),
            revision: state.loaded.metadata.served_revision,
            generation: state.generation,
        }
    }))
    .collect()
}

fn collect_vault_revisions(
    primary_loaded: &LoadedVaultView,
    attached_states: &[AttachedVaultState],
) -> Vec<VaultRevision> {
    std::iter::once(primary_loaded.metadata.clone())
        .chain(
            attached_states
                .iter()
                .map(|state| state.loaded.metadata.clone()),
        )
        .collect()
}

fn collect_vault_sources<'a>(
    primary_loaded: &'a LoadedVaultView,
    attached_states: &'a [AttachedVaultState],
) -> Vec<engine::VaultSource<'a>> {
    std::iter::once(primary_loaded)
        .chain(attached_states.iter().map(|state| &state.loaded))
        .map(|loaded| engine::VaultSource {
            alias: &loaded.metadata.alias,
            served_revision: loaded.metadata.served_revision,
            view: &loaded.view,
            current_sources: &loaded.current_sources,
        })
        .collect()
}

fn verify_federated_barriers(
    primary_workspace: &mneme_store::Workspace,
    primary_generation: u64,
    attached_states: &[AttachedVaultState],
) -> Result<(), Error> {
    if primary_workspace.eligibility_generation()? != primary_generation {
        return Err(Error::Failed(
            "eligibility barrier advanced during projection build".to_owned(),
        ));
    }
    for state in attached_states {
        if let Some(workspace) = &state.workspace
            && workspace.eligibility_generation()? != state.generation
        {
            return Err(Error::Failed(
                "attached vault eligibility barrier advanced during projection build".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_federated_sources(sources: &[FederatedVaultSource]) -> Result<(), Error> {
    let mut aliases = std::collections::BTreeSet::new();
    for source in sources {
        let alias = source.alias();
        validate_vault_alias(alias)?;
        if !aliases.insert(alias) {
            return Err(Error::InvalidQuery("duplicate attached vault alias"));
        }
    }
    Ok(())
}

fn load_vault_context(spec: VaultLoadSpec<'_>) -> Result<LoadedVaultView, Error> {
    let snapshot = spec
        .workspace
        .snapshot_at(spec.requested_revision, spec.pinned_generation)?;
    load_vault_from_snapshot(spec, snapshot)
}

fn load_vault_from_snapshot(
    spec: VaultLoadSpec<'_>,
    snapshot: mneme_store::Snapshot,
) -> Result<LoadedVaultView, Error> {
    let served_revision = snapshot.revision;
    let snapshot = visible_snapshot(snapshot, spec.scope, spec.access);
    // The history is bounded to one million retained revisions; the sequences
    // cover only the revisions the view may look up, so the size of the whole
    // ledger no longer decides whether a build can proceed.
    let loaded =
        mneme_memory::view_context(spec.workspace, &snapshot).map_err(view_context_error)?;
    if loaded.history.len() > 1_000_000 {
        return Err(Error::Failed(
            "workspace history exceeds the 1M revision bound".to_owned(),
        ));
    }
    assert!(loaded.history.len() <= 1_000_000);
    let suppressions = spec.workspace.active_suppressions()?;
    let current_sources = workspace_source_availability_overlay(spec.workspace, served_revision)?;
    let view = mneme_memory::View::with_retention(
        snapshot,
        spec.workspace.root(),
        loaded.history,
        loaded.revision_sequences,
        suppressions,
    )
    .with_access(spec.access.clone());
    assert!(!spec.alias.is_empty());
    Ok(LoadedVaultView {
        metadata: VaultRevision {
            alias: spec.alias.to_owned(),
            root: spec.workspace.root().to_path_buf(),
            requested_revision: spec.requested_revision,
            served_revision,
        },
        view,
        current_sources,
    })
}

fn workspace_source_availability_overlay(
    workspace: &mneme_store::Workspace,
    pinned: mneme_core::WorkspaceRevisionId,
) -> Result<engine::AvailabilityMap, Error> {
    let mut overlay = engine::AvailabilityMap::new();
    if workspace.current_revision()? == pinned {
        return Ok(overlay);
    }
    let current = workspace.snapshot()?;
    overlay.extend(current.records.iter().filter_map(|record| {
        let Ok(source) = mneme_memory::SourceView::parse(record.clone()) else {
            return None;
        };
        Some((record.record_id, source.availability))
    }));
    Ok(overlay)
}
