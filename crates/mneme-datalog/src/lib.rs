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
}

impl Rule {
    /// Construct a rule.
    pub fn new(id: impl Into<String>, head: Atom, body: Vec<Literal>) -> Self {
        Rule {
            id: id.into(),
            head,
            body,
        }
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
        match self {
            ExecutionStatus::Complete => "complete",
            ExecutionStatus::Partial => "partial",
            ExecutionStatus::Timeout => "timeout",
            ExecutionStatus::Cancelled => "cancelled",
            ExecutionStatus::Failed => "failed",
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
        match self {
            CoverageStatus::Complete => "complete",
            CoverageStatus::Incomplete => "incomplete",
            CoverageStatus::Unknown => "unknown",
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
}

/// A canonical source/revision root used in support.
pub type SourceKey = (mneme_core::RecordId, mneme_core::RevisionId);

/// One premise of a conditional derivation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Premise {
    pub predicate: String,
    pub terms: Vec<mneme_core::Value>,
    pub canonical: Option<mneme_core::RecordId>,
    pub sources: std::collections::BTreeSet<SourceKey>,
    pub source_availability: Option<String>,
}

/// A bounded conditional derivation support.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Derivation {
    pub rule_id: String,
    pub rule_version: String,
    pub premises: Vec<Premise>,
    pub sources: std::collections::BTreeSet<SourceKey>,
    pub temporal_parameters: Vec<String>,
    pub revision: mneme_core::WorkspaceRevisionId,
    pub scope: mneme_core::ScopeId,
    pub truncated: bool,
}

/// The built projection.
#[derive(Clone, Debug)]
pub struct Build {
    pub context: BuildContext,
    pub status: ExecutionStatus,
    pub coverage: Vec<Coverage>,
    pub limits: Limits,
    pub work: u64,
    pub support_truncated: bool,
    facts: std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<Vec<mneme_core::Value>, FactData>,
    >,
    arities: std::collections::BTreeMap<String, usize>,
    bundle: RuleBundle,
}

impl Build {
    /// Number of materialized rows in one predicate.
    #[allow(unknown_lints, usize_in_public_api)] // row counts mirror collection lengths
    pub fn row_count(&self, predicate: &str) -> usize {
        self.facts
            .get(predicate)
            .map_or(0, std::collections::BTreeMap::len)
    }
}

#[derive(Clone, Debug)]
struct FactData {
    supports: Vec<Derivation>,
    sources: std::collections::BTreeSet<SourceKey>,
    truncated: bool,
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
}

/// Query result with execution, coverage, and freshness kept separate.
#[derive(Clone, Debug)]
pub struct QueryResult {
    pub context: BuildContext,
    pub status: ExecutionStatus,
    pub coverage: Vec<Coverage>,
    pub rows: Vec<QueryRow>,
    pub exhaustive: bool,
    pub truncated: bool,
    pub absence_established: bool,
    pub reason: Option<String>,
    pub requested_revision: mneme_core::WorkspaceRevisionId,
    pub served_revision: mneme_core::WorkspaceRevisionId,
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
        vec![
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
        ]
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct QueryCacheKey {
    build_id: String,
    requested_revision: mneme_core::WorkspaceRevisionId,
    predicate: String,
    constants: Vec<Option<mneme_core::Value>>,
    limit: usize,
    allow_stale: bool,
}

mod engine;
mod rules;

impl RuleBundle {
    /// Validate this bundle without registering or executing it.
    pub fn validate(&self) -> Result<RuleProgram, Vec<RuleDiagnostic>> {
        rules::validate(self)
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
    #[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
    pub fn build(&mut self, request: BuildRequest) -> Result<Build, Error> {
        let program = request.bundle.validate().map_err(Error::InvalidBundle)?;
        let generation = self.workspace.eligibility_generation()?;
        let build_id = rules::build_id(rules::BuildIdContext {
            revision: request.revision,
            scope: &request.scope,
            generation,
            bundle: &program.bundle,
            limits: &request.limits,
            incomplete_extents: &request.incomplete_extents,
        });
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
        let build =
            self.build_from_snapshot(&request, program, build_id.clone(), generation, snapshot)?;
        if request.publish {
            if matches!(
                build.status,
                ExecutionStatus::Timeout | ExecutionStatus::Cancelled | ExecutionStatus::Failed
            ) {
                return Err(Error::Failed(
                    "cannot publish a timed-out, cancelled, or failed projection".to_owned(),
                ));
            }
            self.publish(&build)?;
        }
        self.builds.insert(build_id, build.clone());
        Ok(build)
    }

    fn build_from_snapshot(
        &mut self,
        request: &BuildRequest,
        program: RuleProgram,
        build_id: String,
        generation: u64,
        snapshot: mneme_store::Snapshot,
    ) -> Result<Build, Error> {
        let history = {
            let mut history = std::collections::BTreeMap::new();
            for record in &snapshot.records {
                for revision in self.workspace.record_revisions(record.record_id)? {
                    if history.len() >= 1_000_000 {
                        return Err(Error::Failed(
                            "workspace history exceeds the 1M revision bound".to_owned(),
                        ));
                    }
                    history.insert((revision.record_id, revision.revision_id), revision);
                }
            }
            history
        };
        let sequences = self.workspace.revision_sequences()?;
        let suppressions = self.workspace.active_suppressions()?;
        let view = mneme_memory::View::with_retention(
            snapshot.clone(),
            self.workspace.root(),
            history,
            sequences,
            suppressions,
        );
        let context = BuildContext {
            requested_revision: request.revision,
            served_revision: snapshot.revision,
            scope: request.scope.clone(),
            schema_version: program.bundle.schema_version,
            rule_bundle_id: program.bundle.id.clone(),
            rule_bundle_version: program.bundle.version.clone(),
            projection_build_id: build_id,
            eligibility_generation: generation,
        };
        let evaluated = engine::build(&view, request, &context, &program)?;
        if self.workspace.eligibility_generation()? != generation {
            return Err(Error::Failed(
                "eligibility barrier advanced during projection build".to_owned(),
            ));
        }
        Ok(Build {
            context,
            status: evaluated.status,
            coverage: evaluated.coverage,
            limits: request.limits.clone(),
            work: evaluated.work,
            support_truncated: evaluated.support_truncated,
            facts: evaluated
                .facts
                .into_iter()
                .map(|(predicate, store)| (predicate, store.rows))
                .collect(),
            arities: program.arities,
            bundle: program.bundle,
        })
    }

    /// Publish a previously built private projection after a fresh barrier
    /// check. A build whose eligibility generation is no longer current is
    /// rejected without replacing the registered projection.
    pub fn publish_build(&mut self, build: &Build) -> Result<(), Error> {
        self.publish(build)
    }

    fn publish(&mut self, build: &Build) -> Result<(), Error> {
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
                name: projection_name,
                revision: build.context.served_revision,
                schema_version: build.context.schema_version,
                rule_version: build.context.rule_bundle_version.clone(),
                index_version: INDEX_VERSION.to_owned(),
                scope: build.context.scope.to_string(),
            })?;
        Ok(())
    }

    /// Query a built projection. A changed eligibility generation always fails;
    /// an older revision requires `allow_stale`.
    pub fn query(&mut self, build_id: &str, query: Query) -> Result<QueryResult, Error> {
        let build = self
            .builds
            .get(build_id)
            .cloned()
            .ok_or_else(|| Error::MissingBuild(build_id.to_owned()))?;
        self.query_loaded(build, query)
    }

    /// Query an explicit build object, checking current barrier and revision.
    pub fn query_build(&mut self, build: &Build, query: Query) -> Result<QueryResult, Error> {
        self.query_loaded(build.clone(), query)
    }

    #[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
    fn query_loaded(&mut self, build: Build, query: Query) -> Result<QueryResult, Error> {
        let current_generation = self.workspace.eligibility_generation()?;
        if current_generation != build.context.eligibility_generation {
            return Err(mneme_store::Failure::BarrierAdvanced {
                pinned: build.context.eligibility_generation,
                current: current_generation,
            }
            .into());
        }
        let current_revision = self.workspace.current_revision()?;
        let requested_revision = current_revision;
        if current_revision != build.context.served_revision && !query.allow_stale {
            return Err(Error::Stale {
                requested: current_revision,
                served: build.context.served_revision,
            });
        }
        if query
            .cancellation
            .as_ref()
            .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed))
        {
            return Ok(QueryResult {
                context: build.context.clone(),
                status: ExecutionStatus::Cancelled,
                coverage: build.coverage.clone(),
                rows: Vec::new(),
                exhaustive: false,
                truncated: false,
                absence_established: false,
                reason: Some("query cancelled".to_owned()),
                requested_revision,
                served_revision: build.context.served_revision,
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
            predicate: query.predicate.clone(),
            constants: query.constants.clone(),
            limit: query.limit,
            allow_stale: query.allow_stale,
        };
        if let Some(cached) = self.query_cache.get(&key) {
            return Ok(cached.clone());
        }
        validate_query_arity(build, query)?;
        let coverage = build
            .coverage
            .iter()
            .find(|coverage| coverage.predicate == query.predicate)
            .cloned()
            .unwrap_or(Coverage {
                predicate: query.predicate.clone(),
                status: CoverageStatus::Unknown,
                reason: Some("predicate is absent from this build".to_owned()),
            });
        let rows = matching_query_rows(build, query);
        let result = query_result(build, query, coverage, rows, requested_revision);
        self.query_cache.insert(key, result.clone());
        Ok(result)
    }
}

fn validate_query_arity(build: &Build, query: &Query) -> Result<(), Error> {
    let arity = build
        .arities
        .get(&query.predicate)
        .copied()
        .ok_or_else(|| Error::UnknownPredicate(query.predicate.clone()))?;
    if !query.constants.is_empty() && query.constants.len() != arity {
        return Err(Error::InvalidQuery(
            "query constant count does not match predicate arity",
        ));
    }
    Ok(())
}

fn matching_query_rows(build: &Build, query: &Query) -> Vec<QueryRow> {
    let mut rows = Vec::new();
    if let Some(facts) = build.facts.get(&query.predicate) {
        for (terms, data) in facts {
            if (query.constants.is_empty() || query.constants.len() == terms.len())
                && query.constants.iter().zip(terms).all(|(constant, value)| {
                    constant.as_ref().is_none_or(|constant| constant == value)
                })
            {
                rows.push(QueryRow {
                    values: terms.clone(),
                    supports: data.supports.clone(),
                    support_truncated: data.truncated,
                });
            }
        }
    }
    rows
}

fn query_result(
    build: &Build,
    query: &Query,
    coverage: Coverage,
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
    let is_exhaustive =
        coverage.status == CoverageStatus::Complete && !is_truncated && !is_terminal_failure;
    let is_absence_established = is_exhaustive && rows.is_empty();
    let status = if is_exhaustive {
        ExecutionStatus::Complete
    } else {
        build.status
    };
    QueryResult {
        context: build.context.clone(),
        status,
        coverage: build.coverage.clone(),
        rows,
        exhaustive: is_exhaustive,
        truncated: is_truncated,
        absence_established: is_absence_established,
        reason: if is_absence_established {
            Some("absence within the declared complete relation".to_owned())
        } else if !is_exhaustive {
            Some("result is not exhaustive for this context".to_owned())
        } else {
            None
        },
        requested_revision,
        served_revision: build.context.served_revision,
        work: build.work,
    }
}
