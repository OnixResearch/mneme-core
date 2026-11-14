//! Engine-neutral contracts for optional, bounded Prolog reasoning.
//!
//! This crate carries capability metadata, finite request terms, qualified
//! results, conditional premises, and reviewable plan/fact proposals, plus the
//! bounded worker that executes a request against one immutable input image.
//! The capability starts disabled; ordinary memory operations do not depend on
//! this crate.
//!
//! # Text boundary
//!
//! Exactly one encoder renders request text into the generated engine script.
//! Predicate names and compound functors must satisfy
//! [`mneme_kernel::text::is_safe_atom`], must not be [forbidden predicates], and
//! must appear in the profile's allowed-predicate set; symbols must satisfy the
//! same atom grammar and must not be forbidden. Strings are emitted as quoted
//! literals with every control character escaped, so no request text can become
//! program text. Anything else is refused with [`CapabilityError`] before a
//! process starts.
//!
//! [forbidden predicates]: is_forbidden_predicate
//!
//! # Input image relations
//!
//! The image is rendered as ground clauses of two fixed, safe relations. Their
//! names never come from image data, so assertion predicates and selected
//! relation names cannot inject program text:
//!
//! - `assertion(Predicate, Subject, Value)` — one accepted canonical fact; the
//!   predicate and the subject record id are strings, the value is a tagged
//!   term (see [`snapshot::value_term`]).
//! - `relation(Name, [Value, …])` — one selected Datalog row.
//!
//! A goal or rule body reaches them by naming `assertion/3` or `relation/2`,
//! which the profile therefore has to allow-list.
//!
//! # Variables
//!
//! Variables match `[A-Z][A-Za-z0-9_]*` and are permitted in the goal and in
//! rules (heads and body literals). A rule must be range restricted: every head
//! variable occurs in its body, and every variable occurs at least twice in the
//! clause, so a rule cannot assert a non-ground fact and the engine cannot
//! write a singleton warning into the solution stream. Assumptions and image
//! facts are ground and refuse variables.
//!
//! # Solution protocol
//!
//! The generated script emits a request-bound protocol header, typed binding
//! frames, and one terminal search observation. [`run_query`] validates every
//! frame and term against the selected profile before building a mode-shaped
//! result. Stdout and stderr share a live production byte bound; enumeration
//! is stopped after the first row above its result cap. Collection deduplicates
//! binding maps before applying its cap, so repeated derivations are not
//! independent evidence. Engine solutions carry no premise certificate and
//! remain uncertified.
#![cfg_attr(test, allow(clippy::expect_used))]

pub mod execution;
pub mod process;
pub mod snapshot;

/// Prefix for an output candidate that is not ground.
pub const UNBOUND_MARKER: &str = "!mneme-unbound";

/// Version of the request-bound, line-oriented worker response protocol.
pub const RESPONSE_PROTOCOL_VERSION: u32 = 1;

/// First response frame; its fields bind every subsequent frame to the request.
pub const RESPONSE_HEADER_PREFIX: &str = "!mneme-response-v1";
/// One ordered binding frame.
pub const RESPONSE_ROW_PREFIX: &str = "!mneme-row-v1";
/// Terminal search observation frame.
pub const RESPONSE_STOP_PREFIX: &str = "!mneme-stop-v1";

/// Relation that carries one accepted canonical fact.
///
/// Rendered as `assertion(Predicate, Subject, Value)`: the accepted
/// assertion's predicate and the subject record id are strings, and the value
/// is a tagged term (see [`snapshot::value_term`]). The name is fixed here, so
/// no image data can supply a predicate or functor.
pub const ASSERTION_RELATION: &str = "assertion";

/// Relation that carries one selected Datalog row.
///
/// Rendered as `relation(Name, [Value, …])`, where `Name` is the relation the
/// Datalog result names and the list holds the row's ground values.
pub const RELATION_RELATION: &str = "relation";

/// Longest nesting depth accepted from an engine solution line.
///
/// The parser rejects deeper output instead of recursing without a bound.
const MAX_PARSED_DEPTH: usize = 64;

/// Prefix the generated script keeps for its own predicates.
const RESERVED_PREFIX: &str = "mneme_";

/// Required feature names for a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Feature {
    PositiveQuery,
    HypotheticalAssumptions,
    Plans,
    GuardedNegation,
    Aggregation,
    CertifiedProofs,
}

impl Feature {
    pub const fn name(self) -> &'static str {
        match self {
            Feature::PositiveQuery => "positive-query",
            Feature::HypotheticalAssumptions => "hypothetical-assumptions",
            Feature::Plans => "plans",
            Feature::GuardedNegation => "guarded-negation",
            Feature::Aggregation => "aggregation",
            Feature::CertifiedProofs => "certified-proofs",
        }
    }
}

impl std::fmt::Display for Feature {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.name())
    }
}

/// Preconditions for an absence-sensitive negative conclusion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NegativeConditions {
    pub relation_complete: bool,
    pub subgoal_completed: bool,
    pub subgoal_ground: bool,
    pub source_pruned: bool,
    pub within_limits: bool,
}

/// A guarded negative conclusion. `Established` is about the contracted goal
/// and snapshot, not universal real-world falsity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NegativeConclusion {
    Established,
    Unknown { reason: String },
}

/// Evaluate whether a negative conclusion is permitted.
///
/// The decision is [`mneme_kernel::completeness::absence_established`] over
/// zero rows: an empty answer establishes absence only for a completed,
/// exhaustive, complete-coverage evaluation that reached no limit, is grounded
/// in valid declarations, and did not depend on pruned bytes. Every condition
/// here maps onto exactly one of those kernel facts, so Datalog, recall and this
/// adapter share one proved rule.
pub fn evaluate_negative_guard(conditions: NegativeConditions) -> NegativeConclusion {
    let facts = mneme_kernel::completeness::AnswerFacts {
        rows: 0,
        exhaustive: conditions.subgoal_completed,
        coverage: if conditions.relation_complete {
            mneme_kernel::completeness::Coverage::Complete
        } else {
            mneme_kernel::completeness::Coverage::Incomplete
        },
        limit_reached: !conditions.within_limits,
        declaration_valid: conditions.subgoal_ground,
        generation_current: !conditions.source_pruned,
    };
    if mneme_kernel::completeness::absence_established(&facts) {
        return NegativeConclusion::Established;
    }
    NegativeConclusion::Unknown {
        reason: unknown_negative_reason(conditions),
    }
}

/// The first unmet condition, so a caller can report why absence is unknown.
fn unknown_negative_reason(conditions: NegativeConditions) -> String {
    if !conditions.relation_complete {
        return "input relation is not complete".to_owned();
    }
    if !conditions.subgoal_completed {
        return "subgoal search did not complete".to_owned();
    }
    if !conditions.subgoal_ground {
        return "subgoal is not ground".to_owned();
    }
    if conditions.source_pruned {
        return "negative search depends on pruned source bytes".to_owned();
    }
    if !conditions.within_limits {
        return "negative search exhausted its limits".to_owned();
    }
    "the negative guard conditions are not established".to_owned()
}

/// Whether an optional Prolog profile can be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapabilityState {
    Disabled { reason: String },
    Enabled,
}

/// Exact engine identity. Engine choice never grants a capability by itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineIdentity {
    pub name: String,
    pub version: String,
    pub source_revision: String,
}

/// Enforced profile bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProfileLimits {
    pub max_time_ms: u64,
    pub max_solutions: usize,
    pub max_output_bytes: usize,
    pub max_term_depth: usize,
    pub max_rule_count: usize,
}

/// Finite term profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TermProfile {
    pub max_depth: usize,
    pub max_collection: usize,
    pub references_allowed: bool,
}

/// Versioned capability metadata returned to clients.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityMetadata {
    pub adapter_version: String,
    pub profile: String,
    pub engine: Option<EngineIdentity>,
    pub state: CapabilityState,
    pub features: std::collections::BTreeSet<Feature>,
    /// Predicates (and compound functors) a request may name.
    pub allowed_predicates: std::collections::BTreeSet<String>,
    pub limits: ProfileLimits,
    pub terms: TermProfile,
}

impl CapabilityMetadata {
    /// A disabled capability with no advertised features.
    pub fn disabled(reason: impl Into<String>) -> Self {
        CapabilityMetadata {
            adapter_version: "0".to_owned(),
            profile: "disabled".to_owned(),
            engine: None,
            state: CapabilityState::Disabled {
                reason: reason.into(),
            },
            features: std::collections::BTreeSet::new(),
            allowed_predicates: std::collections::BTreeSet::new(),
            limits: ProfileLimits {
                max_time_ms: 0,
                max_solutions: 0,
                max_output_bytes: 0,
                max_term_depth: 0,
                max_rule_count: 0,
            },
            terms: TermProfile {
                max_depth: 0,
                max_collection: 0,
                references_allowed: false,
            },
        }
    }

    /// Validate the advertised metadata envelope.
    pub fn validate(&self) -> Result<(), CapabilityError> {
        if self.adapter_version.trim().is_empty() || self.profile.trim().is_empty() {
            return Err(CapabilityError::InvalidMetadata(
                "adapter version and profile are required".to_owned(),
            ));
        }
        match &self.state {
            CapabilityState::Disabled { reason } => self.validate_disabled(reason),
            CapabilityState::Enabled => self.validate_enabled(),
        }
    }

    /// Reject a disabled capability that still advertises reachable surface.
    fn validate_disabled(&self, reason: &str) -> Result<(), CapabilityError> {
        if reason.trim().is_empty() {
            return Err(CapabilityError::InvalidMetadata(
                "disabled capability needs a reason".to_owned(),
            ));
        }
        if !self.features.is_empty() || !self.allowed_predicates.is_empty() {
            return Err(CapabilityError::InvalidMetadata(
                "disabled capability must not advertise features".to_owned(),
            ));
        }
        Ok(())
    }

    /// Reject an enabled capability whose profile or limits are unusable.
    fn validate_enabled(&self) -> Result<(), CapabilityError> {
        if self.features.contains(&Feature::GuardedNegation)
            || self.features.contains(&Feature::Aggregation)
        {
            return Err(CapabilityError::InvalidMetadata(
                "guarded negation and aggregation are disabled in this profile".to_owned(),
            ));
        }
        if self.allowed_predicates.is_empty() {
            return Err(CapabilityError::InvalidMetadata(
                "enabled capability needs an allowed predicate set".to_owned(),
            ));
        }
        let Some(engine) = &self.engine else {
            return Err(CapabilityError::InvalidMetadata(
                "enabled capability needs an engine identity".to_owned(),
            ));
        };
        if engine.name.trim().is_empty()
            || engine.version.trim().is_empty()
            || engine.source_revision.trim().is_empty()
        {
            return Err(CapabilityError::InvalidMetadata(
                "engine identity fields are required".to_owned(),
            ));
        }
        if self.limits.max_time_ms == 0
            || self.limits.max_solutions == 0
            || self.limits.max_output_bytes == 0
            || self.limits.max_term_depth == 0
            || self.limits.max_rule_count == 0
        {
            return Err(CapabilityError::InvalidMetadata(
                "enabled profile limits must be positive".to_owned(),
            ));
        }
        if self.terms.max_depth == 0 || self.terms.max_collection == 0 {
            return Err(CapabilityError::InvalidMetadata(
                "enabled term profile limits must be positive".to_owned(),
            ));
        }
        for predicate in &self.allowed_predicates {
            if !mneme_kernel::text::is_safe_atom(predicate.as_bytes())
                || is_forbidden_predicate(predicate)
            {
                return Err(CapabilityError::InvalidMetadata(
                    "allowed predicates must be safe, non-reserved atoms".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Check that a request is advertised, inside the profile, and renderable.
    ///
    /// Every goal term, rule head and body literal, assumption and nested term
    /// is validated here, so a refused request never reaches the encoder and
    /// never starts a process. Variables are permitted in the goal and in
    /// rules; they are refused in assumptions, and rules must be range
    /// restricted.
    pub fn ensure_request(&self, request: &Request) -> Result<(), CapabilityError> {
        self.ensure_advertised(request)?;
        if request.actor.trim().is_empty() || request.image_digest.trim().is_empty() {
            return Err(CapabilityError::InvalidRequest(
                "actor and image digest are required".to_owned(),
            ));
        }
        check_atom(
            &request.goal,
            self.terms,
            Some(&self.allowed_predicates),
            Variables::Allowed,
        )?;
        self.ensure_query_variables(request)?;
        if request.mode == QueryMode::Collect
            && request.limits.max_solutions > self.terms.max_collection
        {
            return Err(CapabilityError::LimitExceeded(
                "collection size exceeds the term collection limit".to_owned(),
            ));
        }
        let mut rule_ids = std::collections::BTreeSet::new();
        for rule in &request.rules {
            if !rule_ids.insert(rule.id.as_str()) {
                return Err(CapabilityError::InvalidRequest(
                    "rule identities must be unique within the ordered manifest".to_owned(),
                ));
            }
            self.ensure_rule(rule)?;
        }
        for assumption in &request.assumptions {
            self.ensure_assumption(assumption)?;
        }
        Ok(())
    }

    fn ensure_query_variables(&self, request: &Request) -> Result<(), CapabilityError> {
        let mentioned = goal_variables(&request.goal)
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        let mut declared = std::collections::BTreeSet::new();
        for variable in &request.variables {
            if !is_variable_name(&variable.name) {
                return Err(CapabilityError::InvalidRequest(
                    "declared variable names must match [A-Z][A-Za-z0-9_]*".to_owned(),
                ));
            }
            if !declared.insert(variable.name.as_str()) {
                return Err(CapabilityError::InvalidRequest(
                    "query variable declarations must be unique".to_owned(),
                ));
            }
        }
        if mentioned.len() != declared.len()
            || !mentioned
                .iter()
                .all(|name| declared.contains(name.as_str()))
        {
            return Err(CapabilityError::InvalidRequest(
                "every query variable must have exactly one declaration, and undeclared output variables are forbidden".to_owned(),
            ));
        }
        if request.mode == QueryMode::GroundTest && !mentioned.is_empty() {
            return Err(CapabilityError::InvalidRequest(
                "ground-test mode requires a ground goal".to_owned(),
            ));
        }
        Ok(())
    }

    fn ensure_advertised(&self, request: &Request) -> Result<(), CapabilityError> {
        if let CapabilityState::Disabled { reason } = &self.state {
            return Err(CapabilityError::Unavailable {
                reason: reason.clone(),
            });
        }
        if !request.features.contains(&Feature::PositiveQuery) {
            return Err(CapabilityError::UnsupportedFeature(Feature::PositiveQuery));
        }
        for feature in &request.features {
            if matches!(feature, Feature::GuardedNegation | Feature::Aggregation) {
                return Err(CapabilityError::UnsupportedFeature(*feature));
            }
            if !self.features.contains(feature) {
                return Err(CapabilityError::UnsupportedFeature(*feature));
            }
        }
        if request.limits.max_time_ms == 0
            || request.limits.max_time_ms > self.limits.max_time_ms
            || request.limits.max_solutions == 0
            || request.limits.max_solutions > self.limits.max_solutions
            || request.limits.max_output_bytes == 0
            || request.limits.max_output_bytes > self.limits.max_output_bytes
        {
            return Err(CapabilityError::LimitExceeded(
                "request exceeds the advertised profile limits".to_owned(),
            ));
        }
        if request.rules.len() > self.limits.max_rule_count {
            return Err(CapabilityError::LimitExceeded(
                "rule count exceeds the profile".to_owned(),
            ));
        }
        Ok(())
    }

    fn ensure_rule(&self, rule: &Rule) -> Result<(), CapabilityError> {
        if rule.id.trim().is_empty() || rule.version.trim().is_empty() {
            return Err(CapabilityError::InvalidRequest(
                "rule identity and version are required".to_owned(),
            ));
        }
        check_atom(
            &rule.head,
            self.terms,
            Some(&self.allowed_predicates),
            Variables::Allowed,
        )?;
        for literal in &rule.body {
            match literal {
                Literal::Negative(_) => {
                    return Err(CapabilityError::UnsupportedFeature(
                        Feature::GuardedNegation,
                    ));
                }
                Literal::Positive(atom) => check_atom(
                    atom,
                    self.terms,
                    Some(&self.allowed_predicates),
                    Variables::Allowed,
                )?,
            }
        }
        ensure_rule_variables(rule)
    }

    fn ensure_assumption(&self, assumption: &Assumption) -> Result<(), CapabilityError> {
        if !self.features.contains(&Feature::HypotheticalAssumptions) {
            return Err(CapabilityError::UnsupportedFeature(
                Feature::HypotheticalAssumptions,
            ));
        }
        if assumption.id.trim().is_empty() || assumption.rationale.trim().is_empty() {
            return Err(CapabilityError::InvalidRequest(
                "assumption identity and rationale are required".to_owned(),
            ));
        }
        // An assumption is hypothetical input, never canonical image content.
        if assumption.atom.predicate.as_str() == ASSERTION_RELATION
            || assumption.atom.predicate.as_str() == RELATION_RELATION
        {
            return Err(CapabilityError::InvalidRequest(
                "an assumption cannot name an image relation".to_owned(),
            ));
        }
        check_atom(
            &assumption.atom,
            self.terms,
            Some(&self.allowed_predicates),
            Variables::Forbidden,
        )
    }
}

/// Predicates and functors that must never enter the bounded positive profile.
///
/// The list covers effectful and meta-level predicates, the control builtins
/// that can end or reshape the run (`halt`, `true`, `fail`, `repeat`), the
/// output builtins the solution protocol depends on, the type and term tests
/// the generated script itself relies on, and the reserved `mneme_` namespace
/// the generated script uses for its own predicates. The `datalog_*` names are
/// the explicit cross-engine guard: a Prolog request can never call a Datalog
/// engine, whether or not a profile happens to allow-list the name.
pub fn is_forbidden_predicate(predicate: &str) -> bool {
    predicate.starts_with(RESERVED_PREFIX)
        || is_forbidden_clause_predicate(predicate)
        || is_forbidden_io_predicate(predicate)
        || is_forbidden_control_predicate(predicate)
        || is_forbidden_test_predicate(predicate)
}

/// Clause storage, module loading and the cross-engine guard names.
fn is_forbidden_clause_predicate(predicate: &str) -> bool {
    matches!(
        predicate,
        "datalog"
            | "datalog_query"
            | "datalog_result"
            | "datalog_insert"
            | "consult"
            | "use_module"
            | "ensure_loaded"
            | "load_files"
            | "module"
            | "initialization"
            | "op"
            | "assert"
            | "asserta"
            | "assertz"
            | "retract"
            | "retractall"
            | "abolish"
            | "dynamic"
            | "discontiguous"
            | "multifile"
            | "database"
            | "file"
            | "import"
    )
}

/// File, stream and host-effect predicates.
fn is_forbidden_io_predicate(predicate: &str) -> bool {
    matches!(
        predicate,
        "open"
            | "close"
            | "read"
            | "read_term"
            | "write"
            | "write_term"
            | "writeq"
            | "display"
            | "print"
            | "format"
            | "nl"
            | "tab"
            | "put_char"
            | "put_code"
            | "get_char"
            | "peek_char"
            | "shell"
            | "process"
            | "network"
            | "socket"
    )
}

/// Control builtins, engine flags and global-variable access.
fn is_forbidden_control_predicate(predicate: &str) -> bool {
    matches!(
        predicate,
        "call"
            | "catch"
            | "throw"
            | "set_prolog_flag"
            | "current_prolog_flag"
            | "nb_setval"
            | "nb_getval"
            | "b_setval"
            | "b_getval"
            | "halt"
            | "true"
            | "fail"
            | "false"
            | "repeat"
    )
}

/// Type and term tests, and arithmetic, that the generated script owns.
fn is_forbidden_test_predicate(predicate: &str) -> bool {
    matches!(
        predicate,
        "ground"
            | "atom"
            | "atom_chars"
            | "atom_codes"
            | "char_code"
            | "integer"
            | "float"
            | "number"
            | "var"
            | "nonvar"
            | "compound"
            | "is"
            | "mod"
    )
}

/// Whether request text is a safe, non-reserved atom.
fn check_name(name: &str) -> Result<(), CapabilityError> {
    if !mneme_kernel::text::is_safe_atom(name.as_bytes()) {
        return Err(CapabilityError::InvalidRequest(
            "predicate or functor text is not permitted".to_owned(),
        ));
    }
    if is_forbidden_predicate(name) {
        return Err(CapabilityError::DisallowedPredicate(name.to_owned()));
    }
    Ok(())
}

/// Whether request text is safe, non-reserved, and in the profile's set.
fn check_allowed_name(
    name: &str,
    allowed: Option<&std::collections::BTreeSet<String>>,
) -> Result<(), CapabilityError> {
    check_name(name)?;
    if let Some(set) = allowed
        && !set.contains(name)
    {
        return Err(CapabilityError::DisallowedPredicate(name.to_owned()));
    }
    Ok(())
}

/// Whether variables are permitted in a term walk.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Variables {
    /// Ground positions: image facts, assumptions and solution bindings.
    Forbidden,
    /// The goal and rule positions, where `[A-Z][A-Za-z0-9_]*` variables bind.
    Allowed,
}

/// Whether text has the query-variable shape.
fn is_variable_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    match bytes.next() {
        Some(first) if first.is_ascii_uppercase() => {}
        _ => return false,
    }
    bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn check_term(
    term: &Term,
    profile: TermProfile,
    allowed: Option<&std::collections::BTreeSet<String>>,
    variables: Variables,
) -> Result<(), CapabilityError> {
    let mut pending = vec![(term, 1_usize)];
    while let Some((term, depth)) = pending.pop() {
        if depth > profile.max_depth {
            return Err(CapabilityError::LimitExceeded(
                "term exceeds the depth profile".to_owned(),
            ));
        }
        match term {
            Term::Variable(name) => {
                if !is_variable_name(name) {
                    return Err(CapabilityError::InvalidRequest(
                        "variable names must match [A-Z][A-Za-z0-9_]*".to_owned(),
                    ));
                }
                if variables == Variables::Forbidden {
                    return Err(CapabilityError::InvalidRequest(
                        "variables are not valid in this position".to_owned(),
                    ));
                }
            }
            Term::Symbol(text) => check_name(text)?,
            Term::List(items) => {
                if items.len() > profile.max_collection {
                    return Err(CapabilityError::LimitExceeded(
                        "list exceeds the term collection limit".to_owned(),
                    ));
                }
                for item in items {
                    pending.push((item, depth + 1));
                }
            }
            Term::Compound { functor, args } => {
                check_allowed_name(functor, allowed)?;
                if args.len() > profile.max_collection {
                    return Err(CapabilityError::LimitExceeded(
                        "compound term exceeds the argument limit".to_owned(),
                    ));
                }
                for arg in args {
                    pending.push((arg, depth + 1));
                }
            }
            Term::Reference { .. } if !profile.references_allowed => {
                return Err(CapabilityError::InvalidRequest(
                    "record references are not allowed by this profile".to_owned(),
                ));
            }
            Term::Integer(_) | Term::String(_) | Term::Reference { .. } => {}
        }
    }
    Ok(())
}

fn check_atom(
    atom: &Atom,
    profile: TermProfile,
    allowed: Option<&std::collections::BTreeSet<String>>,
    variables: Variables,
) -> Result<(), CapabilityError> {
    check_allowed_name(&atom.predicate, allowed)?;
    if atom.terms.len() > profile.max_collection {
        return Err(CapabilityError::LimitExceeded(
            "atom arity exceeds the term profile".to_owned(),
        ));
    }
    for term in &atom.terms {
        check_term(term, profile, allowed, variables)?;
    }
    Ok(())
}

/// Capability or request validation failure.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CapabilityError {
    #[error("Prolog is unavailable: {reason}")]
    Unavailable { reason: String },
    #[error("feature {0} is not advertised or enabled")]
    UnsupportedFeature(Feature),
    #[error("predicate {0} is not permitted by the positive profile")]
    DisallowedPredicate(String),
    #[error("invalid capability metadata: {0}")]
    InvalidMetadata(String),
    #[error("limit exceeded: {0}")]
    LimitExceeded(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
}

/// A finite, typed Prolog term. Recursive values are represented explicitly;
/// cyclic/rational terms are not representable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Term {
    Integer(i64),
    String(String),
    Symbol(String),
    Variable(String),
    Reference {
        record_id: mneme_core::RecordId,
        revision_id: Option<mneme_core::RevisionId>,
    },
    List(Vec<Term>),
    Compound {
        functor: String,
        args: Vec<Term>,
    },
}

impl Term {
    fn check(&self, profile: TermProfile) -> Result<(), CapabilityError> {
        check_term(self, profile, None, Variables::Allowed)
    }

    /// Validate a term that must be ground, such as a solution binding.
    fn check_ground(&self, profile: TermProfile) -> Result<(), CapabilityError> {
        check_term(self, profile, None, Variables::Forbidden)
    }
}

/// A predicate application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Atom {
    pub predicate: String,
    pub terms: Vec<Term>,
}

impl Atom {
    fn check(&self, profile: TermProfile) -> Result<(), CapabilityError> {
        check_atom(self, profile, None, Variables::Allowed)
    }

    fn variables(&self) -> Vec<String> {
        let mut names = Vec::new();
        for term in &self.terms {
            collect_variables(term, &mut names);
        }
        let mut seen = std::collections::BTreeSet::new();
        names.retain(|name| seen.insert(name.clone()));
        names
    }
}

/// The goal's distinct variables in first-occurrence order.
pub fn goal_variables(goal: &Atom) -> Vec<String> {
    goal.variables()
}

/// Append every variable occurrence under one term, in traversal order.
fn collect_variables(term: &Term, names: &mut Vec<String>) {
    let mut pending = vec![term];
    while let Some(term) = pending.pop() {
        match term {
            Term::Variable(name) => names.push(name.clone()),
            Term::List(items) | Term::Compound { args: items, .. } => {
                // Depth-first, left-to-right: push children reversed so the
                // first one is visited first.
                for item in items.iter().rev() {
                    pending.push(item);
                }
            }
            Term::Integer(_) | Term::String(_) | Term::Symbol(_) | Term::Reference { .. } => {}
        }
    }
}

/// Every variable occurrence in one atom, including duplicates.
fn atom_variable_occurrences(atom: &Atom) -> Vec<String> {
    let mut names = Vec::new();
    for term in &atom.terms {
        collect_variables(term, &mut names);
    }
    names
}

/// Enforce the rule wellformedness the engine profile depends on.
///
/// A head variable that does not occur in the body would let the rule assert a
/// non-ground fact, so it is refused (range restriction). A variable that
/// occurs only once in the whole clause would make the engine write a singleton
/// warning to standard output, which the solution protocol parses strictly, so
/// it is refused as well.
fn ensure_rule_variables(rule: &Rule) -> Result<(), CapabilityError> {
    let head = atom_variable_occurrences(&rule.head);
    // Every body literal contributes one atom's occurrences, so the literal
    // count and the count appended per literal are the bounds reserved here.
    let mut body = Vec::with_capacity(rule.body.len());
    for literal in &rule.body {
        match literal {
            Literal::Positive(atom) | Literal::Negative(atom) => {
                let occurrences = atom_variable_occurrences(atom);
                body.reserve(occurrences.len());
                body.extend(occurrences);
            }
        }
    }
    for name in &head {
        if !body.contains(name) {
            return Err(CapabilityError::InvalidRequest(
                "rule head variable does not occur in the rule body".to_owned(),
            ));
        }
    }
    let mut counts = std::collections::BTreeMap::new();
    for name in head.iter().chain(body.iter()) {
        *counts.entry(name.as_str()).or_insert(0_usize) += 1;
    }
    if counts.values().any(|count| *count < 2) {
        return Err(CapabilityError::InvalidRequest(
            "a rule variable occurs only once".to_owned(),
        ));
    }
    Ok(())
}

/// A rule body literal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Literal {
    Positive(Atom),
    Negative(Atom),
}

/// One allowlisted rule. Rules are data; no engine registration is implied.
///
/// Variables are permitted in the head and body, but the rule must be range
/// restricted: every head variable occurs in the body and every variable
/// occurs at least twice in the clause. A rule with an empty body is emitted as
/// a plain fact, so its head must be ground.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub version: String,
    pub head: Atom,
    pub body: Vec<Literal>,
}

/// A request-local hypothetical assumption.
///
/// Assumptions are ground: a variable in an assumption is refused. They are
/// rendered as ground facts and are never attributed to one solution, because
/// the engine supplies no proof instrumentation; every solution is therefore
/// uncertified and names every declared assumption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assumption {
    pub id: String,
    pub atom: Atom,
    pub rationale: String,
}

/// Per-request bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestLimits {
    pub max_time_ms: u64,
    pub max_solutions: usize,
    pub max_output_bytes: usize,
}

/// One versioned query operation. Enumeration is ordered by the selected
/// profile's input and rule order; collection returns distinct binding maps in
/// first-seen order. Neither operation treats repeated derivations as
/// independent evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryMode {
    /// Test one ground goal; an incomplete input image can only yield Unknown.
    GroundTest,
    /// Return the first output binding that passes output admission. Search is
    /// complete for this operation once a binding is returned, not exhaustive.
    FindOne,
    /// Return at most `RequestLimits::max_solutions` ordered derivation rows.
    Enumerate,
    /// Return at most `RequestLimits::max_solutions` distinct binding maps.
    Collect,
}

impl QueryMode {
    /// Stable wire name for this query mode.
    pub const fn name(self) -> &'static str {
        match self {
            QueryMode::GroundTest => "ground-test",
            QueryMode::FindOne => "find-one",
            QueryMode::Enumerate => "enumerate",
            QueryMode::Collect => "collect",
        }
    }
}

/// Role of one explicitly declared query-scope variable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VariableRole {
    /// Return this variable in each admitted binding.
    Output,
    /// Keep this variable query-local and existentially project it away.
    Local,
}

/// One variable declaration in the query scope. Rule variables are separately
/// scoped to their rule clause and are not declared here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryVariable {
    pub name: String,
    pub role: VariableRole,
}

/// Engine-neutral query request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub actor: String,
    pub scope: mneme_core::ScopeId,
    pub revision: mneme_core::WorkspaceRevisionId,
    pub eligibility_generation: u64,
    pub image_digest: String,
    pub mode: QueryMode,
    pub goal: Atom,
    pub variables: Vec<QueryVariable>,
    pub rules: Vec<Rule>,
    pub assumptions: Vec<Assumption>,
    pub features: std::collections::BTreeSet<Feature>,
    pub limits: RequestLimits,
}

/// Execution status, separate from search exhaustiveness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionStatus {
    Complete,
    Partial,
    Timeout,
    Cancelled,
    Failed,
    Disabled,
}

/// Input coverage at the pinned context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputCoverage {
    pub complete: bool,
    pub reason: Option<String>,
}

/// The exact context a result came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchContext {
    pub revision: mneme_core::WorkspaceRevisionId,
    pub scope: mneme_core::ScopeId,
    pub eligibility_generation: u64,
    pub image_digest: String,
    pub profile: String,
    pub rule_versions: std::collections::BTreeMap<String, String>,
}

/// Host-derived identities bound into every response-protocol frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolIdentity {
    pub version: u32,
    pub request_digest: String,
    pub profile_digest: String,
    pub rule_manifest_digest: String,
    pub input_order_digest: String,
    pub image_digest: String,
}

/// Search truth for a ground test. Unknown is not a negative answer: it means
/// the worker completed only over incomplete input coverage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryTruth {
    True,
    False,
    Unknown,
}

/// Mode-shaped logical answer, separate from worker/process status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueryResult {
    GroundTest { truth: QueryTruth },
    FindOne { solution: Option<Solution> },
    Enumerate { solutions: Vec<Solution> },
    Collect { solutions: Vec<Solution> },
}

/// Terminal observation from the worker protocol or the host supervisor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SearchStop {
    Exhausted,
    GroundSuccess,
    GroundFailure,
    FoundOne,
    ResultLimit,
    OutputLimit,
    Timeout,
    Cancelled,
    EngineFailure,
    InvalidReadback,
}

/// Source availability for one premise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PremiseAvailability {
    Retained,
    Pruned { reason: String },
}

/// One canonical or derived premise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Premise {
    pub record_id: mneme_core::RecordId,
    pub revision_id: mneme_core::RevisionId,
    pub span: Option<mneme_core::SourceSpan>,
    pub derivation: Option<mneme_core::RecordId>,
    pub ancestry_roots: std::collections::BTreeSet<(mneme_core::RecordId, mneme_core::RevisionId)>,
    pub availability: PremiseAvailability,
}

/// Certification state of a solution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Certification {
    Certified,
    Uncertified { reason: String },
}

/// One binding and its conditional support.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Solution {
    pub bindings: std::collections::BTreeMap<String, Term>,
    pub premises: Vec<Premise>,
    pub assumptions: std::collections::BTreeSet<String>,
    pub certification: Certification,
}

/// Resource consumption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsumedLimits {
    pub elapsed_ms: u64,
    pub solutions: usize,
    pub output_bytes: usize,
}

/// One action in a reviewable plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanAction {
    pub action: String,
    pub parameters: std::collections::BTreeMap<String, Term>,
}

/// A plan precondition, optionally tied to an atom/evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Precondition {
    pub description: String,
    pub atom: Option<Atom>,
    pub evidence: Vec<Premise>,
}

/// A plan proposal. It is never executed by search.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanProposal {
    pub id: String,
    pub base_revision: mneme_core::WorkspaceRevisionId,
    pub scope: mneme_core::ScopeId,
    pub actions: Vec<PlanAction>,
    pub preconditions: Vec<Precondition>,
    pub assumptions: std::collections::BTreeSet<String>,
    pub evidence: Vec<Premise>,
    pub expected_effects: Vec<String>,
}

/// A proposed ordinary fact/record change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactChangeProposal {
    pub id: String,
    pub base_revision: mneme_core::WorkspaceRevisionId,
    pub scope: mneme_core::ScopeId,
    pub operation: String,
    pub target: Option<mneme_core::RecordId>,
    pub evidence: Vec<Premise>,
    pub assumptions: std::collections::BTreeSet<String>,
}

/// A reviewable output from search.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Proposal {
    Plan(PlanProposal),
    FactChange(FactChangeProposal),
}

/// Bounded result envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub status: ExecutionStatus,
    pub mode: QueryMode,
    /// Whether the requested operation returned its defined result shape.
    /// A completed `FindOne` need not have exhaustively searched alternatives.
    pub operation_completed: bool,
    pub stop: SearchStop,
    pub exhaustive: bool,
    pub coverage: InputCoverage,
    pub context: SearchContext,
    pub identity: ProtocolIdentity,
    pub result: QueryResult,
    pub proposals: Vec<Proposal>,
    pub consumed: ConsumedLimits,
    /// Independent limit observations remain visible even when timeout,
    /// cancellation, or engine failure determines `status`.
    pub output_limit_exceeded: bool,
    pub solution_limit_exceeded: bool,
    pub readback_valid: bool,
    pub reason: Option<String>,
}

impl Outcome {
    /// A disabled capability result.
    pub fn disabled(reason: impl Into<String>, context: SearchContext) -> Self {
        Outcome {
            status: ExecutionStatus::Disabled,
            mode: QueryMode::GroundTest,
            operation_completed: false,
            stop: SearchStop::InvalidReadback,
            exhaustive: false,
            coverage: InputCoverage {
                complete: false,
                reason: Some("Prolog is disabled".to_owned()),
            },
            context,
            identity: ProtocolIdentity {
                version: RESPONSE_PROTOCOL_VERSION,
                request_digest: String::new(),
                profile_digest: String::new(),
                rule_manifest_digest: String::new(),
                input_order_digest: String::new(),
                image_digest: String::new(),
            },
            result: QueryResult::GroundTest {
                truth: QueryTruth::Unknown,
            },
            proposals: Vec::new(),
            consumed: ConsumedLimits {
                elapsed_ms: 0,
                solutions: 0,
                output_bytes: 0,
            },
            output_limit_exceeded: false,
            solution_limit_exceeded: false,
            readback_valid: false,
            reason: Some(reason.into()),
        }
    }

    /// Validate that non-complete searches cannot claim exhaustiveness.
    pub fn validate(&self) -> Result<(), CapabilityError> {
        if self.exhaustive
            && (self.status != ExecutionStatus::Complete
                || !self.operation_completed
                || !self.coverage.complete)
        {
            return Err(CapabilityError::InvalidRequest(
                "exhaustiveness requires a completed operation and complete input coverage"
                    .to_owned(),
            ));
        }
        let (mode_matches, result_count) = match (&self.mode, &self.result) {
            (QueryMode::GroundTest, QueryResult::GroundTest { truth }) => {
                let is_truth_consistent_with_stop = match truth {
                    QueryTruth::True => self.stop == SearchStop::GroundSuccess,
                    QueryTruth::False => self.stop == SearchStop::GroundFailure,
                    QueryTruth::Unknown => matches!(
                        self.stop,
                        SearchStop::GroundFailure | SearchStop::InvalidReadback
                    ),
                };
                (is_truth_consistent_with_stop, 0)
            }
            (QueryMode::FindOne, QueryResult::FindOne { solution }) => {
                (true, usize::from(solution.is_some()))
            }
            (QueryMode::Enumerate, QueryResult::Enumerate { solutions }) => (true, solutions.len()),
            (QueryMode::Collect, QueryResult::Collect { solutions }) => (true, solutions.len()),
            _ => (false, 0),
        };
        if !mode_matches {
            return Err(CapabilityError::InvalidRequest(
                "result shape does not match the requested query mode".to_owned(),
            ));
        }
        if self.status == ExecutionStatus::Complete
            && (!self.operation_completed || !self.readback_valid)
        {
            return Err(CapabilityError::InvalidRequest(
                "a complete operation requires admitted readback".to_owned(),
            ));
        }
        if self.readback_valid
            && (self.identity.version != RESPONSE_PROTOCOL_VERSION
                || self.identity.request_digest.is_empty()
                || self.identity.profile_digest.is_empty()
                || self.identity.rule_manifest_digest.is_empty()
                || self.identity.input_order_digest.is_empty()
                || self.identity.image_digest.is_empty())
        {
            return Err(CapabilityError::InvalidRequest(
                "admitted readback must carry a complete supported protocol identity".to_owned(),
            ));
        }
        if matches!(
            &self.result,
            QueryResult::GroundTest {
                truth: QueryTruth::False
            }
        ) && !self.coverage.complete
        {
            return Err(CapabilityError::InvalidRequest(
                "incomplete input coverage cannot establish a negative ground result".to_owned(),
            ));
        }
        if self.consumed.solutions < result_count {
            return Err(CapabilityError::InvalidRequest(
                "consumed solution count is smaller than the result set".to_owned(),
            ));
        }
        Ok(())
    }
}

impl Request {
    /// Derive protocol identities from the validated host request, profile,
    /// rule order and immutable image. No identity component is accepted from
    /// worker output or a caller-supplied result.
    pub fn protocol_identity(
        &self,
        metadata: &CapabilityMetadata,
        image: &snapshot::InputImage,
    ) -> Result<ProtocolIdentity, CapabilityError> {
        metadata.ensure_request(self)?;
        image.verify_for_request(self).map_err(|_| {
            CapabilityError::InvalidRequest(
                "input image does not match the request identity".to_owned(),
            )
        })?;
        if image.context.profile != metadata.profile {
            return Err(CapabilityError::InvalidRequest(
                "input image profile differs from the configured profile".to_owned(),
            ));
        }
        let profile_value = profile_identity_value(metadata);
        let profile_digest = digest_value(&profile_value);
        let rules_value =
            mneme_core::Value::sequence(self.rules.iter().map(rule_identity_value).collect());
        let rule_manifest_digest = digest_value(&rules_value);
        let input_order_value = input_order_identity_value(image);
        let input_order_digest = digest_value(&input_order_value);
        let request_value = request_identity_value(
            self,
            rules_value,
            &profile_digest,
            &rule_manifest_digest,
            &input_order_digest,
        );
        Ok(ProtocolIdentity {
            version: RESPONSE_PROTOCOL_VERSION,
            request_digest: digest_value(&request_value),
            profile_digest,
            rule_manifest_digest,
            input_order_digest,
            image_digest: self.image_digest.clone(),
        })
    }
}

fn request_identity_value(
    request: &Request,
    rules_value: mneme_core::Value,
    profile_digest: &str,
    rule_manifest_digest: &str,
    input_order_digest: &str,
) -> mneme_core::Value {
    mneme_core::Value::record_named(
        "prolog-query-request-v1",
        vec![
            mneme_core::Value::string(request.actor.clone()),
            request.scope.to_value(),
            request.revision.to_value(),
            mneme_core::Value::string(request.eligibility_generation.to_string()),
            mneme_core::Value::symbol(request.mode.name()),
            atom_identity_value(&request.goal),
            request_variable_identity_value(request),
            rules_value,
            request_assumption_identity_value(request),
            mneme_core::Value::sequence(
                request
                    .features
                    .iter()
                    .map(|feature| mneme_core::Value::symbol(feature.name()))
                    .collect(),
            ),
            request_limits_identity_value(request),
            mneme_core::Value::string(profile_digest.to_owned()),
            mneme_core::Value::string(rule_manifest_digest.to_owned()),
            mneme_core::Value::string(input_order_digest.to_owned()),
            mneme_core::Value::string(request.image_digest.clone()),
        ],
    )
}

fn request_variable_identity_value(request: &Request) -> mneme_core::Value {
    mneme_core::Value::sequence(
        request
            .variables
            .iter()
            .map(|variable| {
                mneme_core::Value::record_named(
                    "query-variable",
                    vec![
                        mneme_core::Value::string(variable.name.clone()),
                        mneme_core::Value::symbol(match variable.role {
                            VariableRole::Output => "output",
                            VariableRole::Local => "local",
                        }),
                    ],
                )
            })
            .collect(),
    )
}

fn request_assumption_identity_value(request: &Request) -> mneme_core::Value {
    mneme_core::Value::sequence(
        request
            .assumptions
            .iter()
            .map(|assumption| {
                mneme_core::Value::record_named(
                    "assumption",
                    vec![
                        mneme_core::Value::string(assumption.id.clone()),
                        atom_identity_value(&assumption.atom),
                        mneme_core::Value::string(assumption.rationale.clone()),
                    ],
                )
            })
            .collect(),
    )
}

fn request_limits_identity_value(request: &Request) -> mneme_core::Value {
    mneme_core::Value::record_named(
        "request-limits",
        vec![
            mneme_core::Value::string(request.limits.max_time_ms.to_string()),
            mneme_core::Value::string(request.limits.max_solutions.to_string()),
            mneme_core::Value::string(request.limits.max_output_bytes.to_string()),
        ],
    )
}

fn digest_value(value: &mneme_core::Value) -> String {
    format!(
        "sha256:{}",
        mneme_core::ContentDigest::of_payload(value).to_hex()
    )
}

fn profile_identity_value(metadata: &CapabilityMetadata) -> mneme_core::Value {
    let engine = metadata.engine.as_ref().map_or_else(
        || mneme_core::Value::symbol("none"),
        |engine| {
            mneme_core::Value::record_named(
                "engine",
                vec![
                    mneme_core::Value::string(engine.name.clone()),
                    mneme_core::Value::string(engine.version.clone()),
                    mneme_core::Value::string(engine.source_revision.clone()),
                ],
            )
        },
    );
    mneme_core::Value::record_named(
        "prolog-profile-v1",
        vec![
            mneme_core::Value::string(metadata.adapter_version.clone()),
            mneme_core::Value::string(metadata.profile.clone()),
            engine,
            mneme_core::Value::sequence(
                metadata
                    .features
                    .iter()
                    .map(|feature| mneme_core::Value::symbol(feature.name()))
                    .collect(),
            ),
            mneme_core::Value::sequence(
                metadata
                    .allowed_predicates
                    .iter()
                    .cloned()
                    .map(mneme_core::Value::string)
                    .collect(),
            ),
            mneme_core::Value::record_named(
                "profile-limits",
                vec![
                    mneme_core::Value::string(metadata.limits.max_time_ms.to_string()),
                    mneme_core::Value::string(metadata.limits.max_solutions.to_string()),
                    mneme_core::Value::string(metadata.limits.max_output_bytes.to_string()),
                    mneme_core::Value::string(metadata.limits.max_term_depth.to_string()),
                    mneme_core::Value::string(metadata.limits.max_rule_count.to_string()),
                ],
            ),
            mneme_core::Value::record_named(
                "term-profile",
                vec![
                    mneme_core::Value::string(metadata.terms.max_depth.to_string()),
                    mneme_core::Value::string(metadata.terms.max_collection.to_string()),
                    mneme_core::Value::Boolean(metadata.terms.references_allowed),
                ],
            ),
        ],
    )
}

fn input_order_identity_value(image: &snapshot::InputImage) -> mneme_core::Value {
    mneme_core::Value::record_named(
        "prolog-input-order-v1",
        vec![
            mneme_core::Value::string(image.context.image_digest.clone()),
            mneme_core::Value::sequence(
                image
                    .canonical
                    .iter()
                    .map(|fact| {
                        mneme_core::Value::record_named(
                            "fact-order",
                            vec![fact.record_id.to_value(), fact.revision_id.to_value()],
                        )
                    })
                    .collect(),
            ),
            mneme_core::Value::sequence(
                image
                    .relations
                    .iter()
                    .map(|relation| {
                        mneme_core::Value::record_named(
                            "relation-order",
                            vec![
                                mneme_core::Value::string(relation.predicate.clone()),
                                mneme_core::Value::sequence(
                                    relation
                                        .rows
                                        .iter()
                                        .map(|row| mneme_core::Value::sequence(row.values.clone()))
                                        .collect(),
                                ),
                            ],
                        )
                    })
                    .collect(),
            ),
        ],
    )
}

fn rule_identity_value(rule: &Rule) -> mneme_core::Value {
    mneme_core::Value::record_named(
        "ordered-rule",
        vec![
            mneme_core::Value::string(rule.id.clone()),
            mneme_core::Value::string(rule.version.clone()),
            atom_identity_value(&rule.head),
            mneme_core::Value::sequence(
                rule.body
                    .iter()
                    .map(|literal| match literal {
                        Literal::Positive(atom) => mneme_core::Value::record_named(
                            "positive",
                            vec![atom_identity_value(atom)],
                        ),
                        Literal::Negative(atom) => mneme_core::Value::record_named(
                            "negative",
                            vec![atom_identity_value(atom)],
                        ),
                    })
                    .collect(),
            ),
        ],
    )
}

fn atom_identity_value(atom: &Atom) -> mneme_core::Value {
    mneme_core::Value::record_named(
        "atom",
        vec![
            mneme_core::Value::string(atom.predicate.clone()),
            mneme_core::Value::sequence(atom.terms.iter().map(term_identity_value).collect()),
        ],
    )
}

fn term_identity_value(term: &Term) -> mneme_core::Value {
    match term {
        Term::Integer(value) => mneme_core::Value::record_named(
            "integer",
            vec![mneme_core::Value::string(value.to_string())],
        ),
        Term::String(value) => mneme_core::Value::record_named(
            "string",
            vec![mneme_core::Value::string(value.clone())],
        ),
        Term::Symbol(value) => mneme_core::Value::record_named(
            "symbol",
            vec![mneme_core::Value::string(value.clone())],
        ),
        Term::Variable(value) => mneme_core::Value::record_named(
            "variable",
            vec![mneme_core::Value::string(value.clone())],
        ),
        Term::Reference {
            record_id,
            revision_id,
        } => mneme_core::Value::record_named(
            "reference",
            vec![
                record_id.to_value(),
                revision_id.map_or_else(
                    || mneme_core::Value::symbol("current"),
                    mneme_core::RevisionId::to_value,
                ),
            ],
        ),
        Term::List(items) => mneme_core::Value::record_named(
            "list",
            vec![mneme_core::Value::sequence(
                items.iter().map(term_identity_value).collect(),
            )],
        ),
        Term::Compound { functor, args } => mneme_core::Value::record_named(
            "compound",
            vec![
                mneme_core::Value::string(functor.clone()),
                mneme_core::Value::sequence(args.iter().map(term_identity_value).collect()),
            ],
        ),
    }
}

/// Run one bounded query through the configured engine.
///
/// This is the single entry point adapters use. The worker it drives validates
/// the request, refuses an image whose context or content digest differs from
/// the request, and only then starts a contained process group with the
/// request's own time, solution and output bounds (narrowed by `limits`). This
/// function parses every solution line strictly, builds the [`Solution`]s and
/// returns a qualified [`Outcome`]. A disabled or invalid request fails before
/// any process starts; unparsable engine output, and a non-ground answer
/// reported through [`UNBOUND_MARKER`], yield [`ExecutionStatus::Failed`] with
/// an explanatory reason, never a partial success.
#[allow(unknown_lints, too_many_parameters)] // published entry point mneme-eval and mneme-cli call positionally
pub fn run_query(
    engine: &std::path::Path,
    metadata: &CapabilityMetadata,
    image: &snapshot::InputImage,
    request: &Request,
    control: &process::WorkerControl,
    limits: process::WorkerLimits,
) -> Result<Outcome, CapabilityError> {
    let identity = request.protocol_identity(metadata, image)?;
    // The worker validates the request and refuses a mismatched image before it
    // spawns anything, so this path never starts a process for an invalid call.
    let effective = process::WorkerLimits {
        max_wall_ms: limits.max_wall_ms.min(request.limits.max_time_ms),
        max_output_bytes: limits.max_output_bytes.min(request.limits.max_output_bytes),
    };
    let runtime = process::WorkerRuntime {
        control,
        limits: effective,
    };
    let worker = process::run_worker(engine, metadata, image, request, &runtime)?;
    let outcome = outcome_from_worker(&worker, image, request, &identity);
    outcome.validate_for_request(request)?;
    Ok(outcome)
}

/// Build the qualified result from one worker run.
fn outcome_from_worker(
    worker: &process::WorkerOutcome,
    image: &snapshot::InputImage,
    request: &Request,
    identity: &ProtocolIdentity,
) -> Outcome {
    let assumptions = request
        .assumptions
        .iter()
        .map(|assumption| assumption.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let classification = classify_output(worker, request, identity, &assumptions);
    let parsed = match classification {
        OutputClassification::Rejected(reason) => {
            return rejected_outcome(reason, worker, image, request, identity);
        }
        OutputClassification::Parsed(parsed) => parsed,
    };
    let context = image.context.clone();
    let coverage = image.coverage.clone();
    let elapsed_ms = worker.elapsed_ms;
    let status = resolved_status(worker.status, &parsed);
    let result = result_for_request(request, &parsed, &coverage);
    let is_operation_completed = operation_completed(request, &parsed, &result, status);
    let is_exhaustive = search_is_exhaustive(request, &parsed, &coverage, status);
    let stop = resolved_stop(worker, &parsed);
    let reason = outcome_reason(worker, status, parsed.truncated);
    Outcome {
        status,
        mode: request.mode,
        operation_completed: is_operation_completed,
        stop,
        exhaustive: is_exhaustive,
        coverage,
        context,
        identity: identity.clone(),
        result,
        proposals: Vec::new(),
        consumed: ConsumedLimits {
            elapsed_ms,
            solutions: parsed.rows_seen,
            output_bytes: worker.captured_bytes,
        },
        output_limit_exceeded: worker.output_limit_exceeded,
        solution_limit_exceeded: worker.solution_limit_exceeded || parsed.truncated,
        readback_valid: parsed.terminal.is_some()
            || worker.status != process::WorkerStatus::Complete,
        reason,
    }
}

/// A malformed or crossed response cannot become a logical answer. Preserve
/// the observed worker disposition separately from failed readback admission.
fn rejected_outcome(
    reason: &str,
    worker: &process::WorkerOutcome,
    image: &snapshot::InputImage,
    request: &Request,
    identity: &ProtocolIdentity,
) -> Outcome {
    // A worker stopped by timeout, cancellation, a limit or a failed exit
    // usually never wrote a valid response. Keep that disposition first so the
    // caller learns why the worker stopped, not only that readback failed.
    let reason = match worker.reason.as_deref() {
        Some(disposition) if worker.status != process::WorkerStatus::Complete => {
            format!("{disposition}; readback rejected: {reason}")
        }
        Some(_) | None => reason.to_owned(),
    };
    Outcome {
        status: match worker.status {
            process::WorkerStatus::Complete | process::WorkerStatus::Failed => {
                ExecutionStatus::Failed
            }
            process::WorkerStatus::Partial => ExecutionStatus::Partial,
            process::WorkerStatus::Timeout => ExecutionStatus::Timeout,
            process::WorkerStatus::Cancelled => ExecutionStatus::Cancelled,
        },
        mode: request.mode,
        operation_completed: false,
        stop: resolved_worker_stop(worker),
        exhaustive: false,
        coverage: image.coverage.clone(),
        context: image.context.clone(),
        identity: identity.clone(),
        result: empty_result(request.mode),
        proposals: Vec::new(),
        consumed: ConsumedLimits {
            elapsed_ms: worker.elapsed_ms,
            solutions: 0,
            output_bytes: worker.captured_bytes,
        },
        output_limit_exceeded: worker.output_limit_exceeded,
        solution_limit_exceeded: worker.solution_limit_exceeded,
        readback_valid: false,
        reason: Some(reason),
    }
}

/// Qualify process disposition with a valid terminal protocol observation.
fn resolved_status(status: process::WorkerStatus, parsed: &ParsedOutput) -> ExecutionStatus {
    match status {
        process::WorkerStatus::Failed => ExecutionStatus::Failed,
        process::WorkerStatus::Partial => ExecutionStatus::Partial,
        process::WorkerStatus::Timeout => ExecutionStatus::Timeout,
        process::WorkerStatus::Cancelled => ExecutionStatus::Cancelled,
        process::WorkerStatus::Complete if parsed.terminal.is_none() => ExecutionStatus::Failed,
        process::WorkerStatus::Complete if parsed.truncated => ExecutionStatus::Partial,
        process::WorkerStatus::Complete => ExecutionStatus::Complete,
    }
}

fn resolved_worker_stop(worker: &process::WorkerOutcome) -> SearchStop {
    match worker.status {
        process::WorkerStatus::Failed => SearchStop::EngineFailure,
        process::WorkerStatus::Partial if worker.output_limit_exceeded => SearchStop::OutputLimit,
        process::WorkerStatus::Partial => SearchStop::ResultLimit,
        process::WorkerStatus::Timeout => SearchStop::Timeout,
        process::WorkerStatus::Cancelled => SearchStop::Cancelled,
        process::WorkerStatus::Complete => SearchStop::InvalidReadback,
    }
}

fn resolved_stop(worker: &process::WorkerOutcome, parsed: &ParsedOutput) -> SearchStop {
    match worker.status {
        process::WorkerStatus::Failed => SearchStop::EngineFailure,
        process::WorkerStatus::Timeout => SearchStop::Timeout,
        process::WorkerStatus::Cancelled => SearchStop::Cancelled,
        process::WorkerStatus::Partial if worker.output_limit_exceeded => SearchStop::OutputLimit,
        process::WorkerStatus::Partial => SearchStop::ResultLimit,
        process::WorkerStatus::Complete if worker.output_limit_exceeded => SearchStop::OutputLimit,
        process::WorkerStatus::Complete if worker.solution_limit_exceeded || parsed.truncated => {
            SearchStop::ResultLimit
        }
        process::WorkerStatus::Complete => parsed.terminal.unwrap_or(SearchStop::InvalidReadback),
    }
}

fn empty_result(mode: QueryMode) -> QueryResult {
    match mode {
        QueryMode::GroundTest => QueryResult::GroundTest {
            truth: QueryTruth::Unknown,
        },
        QueryMode::FindOne => QueryResult::FindOne { solution: None },
        QueryMode::Enumerate => QueryResult::Enumerate {
            solutions: Vec::new(),
        },
        QueryMode::Collect => QueryResult::Collect {
            solutions: Vec::new(),
        },
    }
}

fn result_for_request(
    request: &Request,
    parsed: &ParsedOutput,
    coverage: &InputCoverage,
) -> QueryResult {
    match request.mode {
        QueryMode::GroundTest => {
            let truth = match parsed.terminal {
                Some(SearchStop::GroundSuccess) => QueryTruth::True,
                Some(SearchStop::GroundFailure) if coverage.complete => QueryTruth::False,
                Some(SearchStop::GroundFailure) | None => QueryTruth::Unknown,
                Some(_) => QueryTruth::Unknown,
            };
            QueryResult::GroundTest { truth }
        }
        QueryMode::FindOne => QueryResult::FindOne {
            solution: parsed.solutions.first().cloned(),
        },
        QueryMode::Enumerate => QueryResult::Enumerate {
            solutions: parsed.solutions.clone(),
        },
        QueryMode::Collect => QueryResult::Collect {
            solutions: parsed.solutions.clone(),
        },
    }
}

fn collect_distinct(mut solutions: Vec<Solution>) -> Vec<Solution> {
    let mut unique_count = 0;
    for current_index in 0..solutions.len() {
        let is_duplicate = solutions[..unique_count]
            .iter()
            .any(|existing| existing.bindings == solutions[current_index].bindings);
        if !is_duplicate {
            solutions.swap(unique_count, current_index);
            unique_count = unique_count.saturating_add(1);
        }
    }
    solutions.truncate(unique_count);
    solutions
}

fn operation_completed(
    request: &Request,
    parsed: &ParsedOutput,
    result: &QueryResult,
    status: ExecutionStatus,
) -> bool {
    if status == ExecutionStatus::Complete && parsed.terminal.is_some() {
        return true;
    }
    match (request.mode, result) {
        (QueryMode::FindOne, QueryResult::FindOne { solution: Some(_) }) => true,
        (QueryMode::Enumerate, QueryResult::Enumerate { .. }) => {
            parsed.rows_seen >= request.limits.max_solutions
        }
        (QueryMode::Collect, QueryResult::Collect { solutions }) => {
            solutions.len() >= request.limits.max_solutions
        }
        _ => false,
    }
}

fn search_is_exhaustive(
    request: &Request,
    parsed: &ParsedOutput,
    coverage: &InputCoverage,
    status: ExecutionStatus,
) -> bool {
    if status != ExecutionStatus::Complete || !coverage.complete {
        return false;
    }
    matches!(
        (request.mode, parsed.terminal),
        (
            QueryMode::GroundTest,
            Some(SearchStop::GroundSuccess | SearchStop::GroundFailure)
        ) | (QueryMode::FindOne, Some(SearchStop::Exhausted))
            | (QueryMode::Enumerate, Some(SearchStop::Exhausted))
            | (QueryMode::Collect, Some(SearchStop::Exhausted))
    )
}

fn outcome_reason(
    worker: &process::WorkerOutcome,
    status: ExecutionStatus,
    truncated: bool,
) -> Option<String> {
    if status == ExecutionStatus::Complete {
        return None;
    }
    if status == ExecutionStatus::Failed {
        return Some(if worker.status == process::WorkerStatus::Failed {
            "worker exited with an error status".to_owned()
        } else {
            "worker did not report completion".to_owned()
        });
    }
    if truncated {
        return Some("solution limit reached".to_owned());
    }
    worker.reason.clone()
}

/// What the worker's output text amounts to.
enum OutputClassification {
    Parsed(ParsedOutput),
    /// The output cannot become an answer; the reason explains why.
    Rejected(&'static str),
}

struct ParsedOutput {
    solutions: Vec<Solution>,
    terminal: Option<SearchStop>,
    rows_seen: usize,
    /// The engine produced more solutions than the request permits.
    truncated: bool,
}

/// Parse complete solution lines, dropping only a cut-off final fragment.
fn classify_output(
    worker: &process::WorkerOutcome,
    request: &Request,
    identity: &ProtocolIdentity,
    assumptions: &std::collections::BTreeSet<String>,
) -> OutputClassification {
    if !worker.output_utf8_valid {
        return OutputClassification::Rejected(
            "worker response is not valid UTF-8 and cannot be admitted losslessly",
        );
    }
    let text = worker.output.as_str();
    // Only newline-terminated frames are complete; a cut-off fragment is never
    // admitted as a binding or terminal observation.
    let complete_len = text.rfind('\n').map_or(0, |index| index + 1);
    let complete_output = &text[..complete_len];
    let complete_line_count = complete_output
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count();
    let mut lines = complete_output.split_terminator('\n');
    let header = protocol_header(identity, request.mode);
    if lines.next() != Some(header.as_str()) {
        return OutputClassification::Rejected(
            "worker response header is missing or bound to another request",
        );
    }
    let variables = request
        .variables
        .iter()
        .filter(|variable| variable.role == VariableRole::Output)
        .map(|variable| variable.name.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let solutions = Vec::with_capacity(complete_line_count.saturating_sub(1));
    let (solutions, terminal) = match parse_response_frames(
        lines,
        ResponseFrameContext {
            identity,
            variables: &variables,
            assumptions,
            worker_status: worker.status,
        },
        solutions,
    ) {
        Ok(parsed) => parsed,
        Err(reason) => return OutputClassification::Rejected(reason),
    };
    finish_output_classification(request, solutions, terminal)
}

fn finish_output_classification(
    request: &Request,
    mut solutions: Vec<Solution>,
    terminal: Option<SearchStop>,
) -> OutputClassification {
    let is_terminal_valid_for_mode = match (request.mode, terminal) {
        (QueryMode::GroundTest, Some(SearchStop::GroundSuccess | SearchStop::GroundFailure)) => {
            solutions.is_empty()
        }
        (QueryMode::FindOne, Some(SearchStop::FoundOne)) => solutions.len() == 1,
        (QueryMode::FindOne, Some(SearchStop::Exhausted)) => solutions.is_empty(),
        (QueryMode::Enumerate | QueryMode::Collect, Some(SearchStop::Exhausted)) => true,
        (_, None) => true,
        _ => false,
    };
    if !is_terminal_valid_for_mode {
        return OutputClassification::Rejected(
            "worker terminal observation does not match the requested query mode",
        );
    }
    let rows_seen = solutions.len();
    let is_truncated = match request.mode {
        QueryMode::Enumerate => rows_seen > request.limits.max_solutions,
        QueryMode::Collect => {
            solutions = collect_distinct(solutions);
            solutions.len() > request.limits.max_solutions
        }
        QueryMode::GroundTest | QueryMode::FindOne => false,
    };
    if is_truncated {
        solutions.truncate(request.limits.max_solutions);
    }
    OutputClassification::Parsed(ParsedOutput {
        solutions,
        terminal,
        rows_seen,
        truncated: is_truncated,
    })
}

struct ResponseFrameContext<'a> {
    identity: &'a ProtocolIdentity,
    variables: &'a std::collections::BTreeSet<String>,
    assumptions: &'a std::collections::BTreeSet<String>,
    worker_status: process::WorkerStatus,
}

fn parse_response_frames<'a>(
    lines: impl Iterator<Item = &'a str>,
    context: ResponseFrameContext<'_>,
    mut solutions: Vec<Solution>,
) -> Result<(Vec<Solution>, Option<SearchStop>), &'static str> {
    let ResponseFrameContext {
        identity,
        variables,
        assumptions,
        worker_status,
    } = context;
    let mut terminal = None;
    for line in lines {
        if terminal.is_some() {
            return Err("worker response contains frames after its terminal observation");
        }
        if let Some(bindings) = line.strip_prefix(&format!(
            "{}\t{}\t",
            RESPONSE_ROW_PREFIX, identity.request_digest
        )) {
            match parse_solution_line(bindings, variables, assumptions) {
                Ok(solution) => solutions.push(solution),
                Err(_) => {
                    return Err("worker binding frame is malformed or has an unexpected variable");
                }
            }
        } else if line == format!("{}\t{}", UNBOUND_MARKER, identity.request_digest) {
            return Err("worker reported an unbound output candidate");
        } else if let Some(stop_name) = line.strip_prefix(&format!(
            "{}\t{}\t",
            RESPONSE_STOP_PREFIX, identity.request_digest
        )) {
            terminal = parse_terminal(stop_name);
            if terminal.is_none() {
                return Err("worker terminal observation is malformed");
            }
        } else {
            return Err("worker output contains an unknown frame");
        }
    }
    if worker_status == process::WorkerStatus::Complete && terminal.is_none() {
        return Err("worker completed without a terminal search observation");
    }
    Ok((solutions, terminal))
}

fn parse_terminal(value: &str) -> Option<SearchStop> {
    match value {
        "exhausted" => Some(SearchStop::Exhausted),
        "ground-success" => Some(SearchStop::GroundSuccess),
        "ground-failure" => Some(SearchStop::GroundFailure),
        "found-one" => Some(SearchStop::FoundOne),
        _ => None,
    }
}

pub(crate) fn protocol_header(identity: &ProtocolIdentity, mode: QueryMode) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}",
        RESPONSE_HEADER_PREFIX,
        identity.request_digest,
        identity.profile_digest,
        identity.rule_manifest_digest,
        identity.input_order_digest,
        identity.image_digest,
        mode.name()
    )
}

/// Parse one solution line in the restricted term syntax.
///
/// The grammar is exactly what the generated script emits: an empty line for a
/// solution with no bindings, otherwise `Name=Term` pairs separated by commas,
/// where a term is an integer, a quoted string, a safe atom, a proper list, or
/// a compound of a safe functor. Every binding must name one of `variables`
/// exactly once, and every variable must be bound. Each returned solution names
/// all declared assumptions and is uncertified, because the engine provides no
/// premise certificate.
pub fn parse_solution_line(
    line: &str,
    variables: &std::collections::BTreeSet<String>,
    assumptions: &std::collections::BTreeSet<String>,
) -> Result<Solution, CapabilityError> {
    TermParser::new(line).parse_solution(variables, assumptions)
}

fn invalid_solution() -> CapabilityError {
    CapabilityError::InvalidRequest("worker output is not a valid solution line".to_owned())
}

struct TermParser<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl<'a> TermParser<'a> {
    fn new(text: &'a str) -> Self {
        TermParser {
            bytes: text.as_bytes(),
            index: 0,
        }
    }

    fn parse_solution(
        mut self,
        variables: &std::collections::BTreeSet<String>,
        assumptions: &std::collections::BTreeSet<String>,
    ) -> Result<Solution, CapabilityError> {
        let bindings = if self.bytes.is_empty() {
            std::collections::BTreeMap::new()
        } else {
            self.parse_bindings()?
        };
        if self.index != self.bytes.len() {
            return Err(invalid_solution());
        }
        if bindings.len() != variables.len() {
            return Err(invalid_solution());
        }
        if variables.iter().any(|name| !bindings.contains_key(name)) {
            return Err(invalid_solution());
        }
        Ok(Solution {
            bindings,
            premises: Vec::new(),
            assumptions: assumptions.clone(),
            certification: Certification::Uncertified {
                reason: "engine returned no premise certificate".to_owned(),
            },
        })
    }

    fn parse_bindings(
        &mut self,
    ) -> Result<std::collections::BTreeMap<String, Term>, CapabilityError> {
        let mut bindings = std::collections::BTreeMap::new();
        loop {
            let name = self.parse_variable()?;
            self.require_byte(b'=')?;
            let term = self.parse_term(0)?;
            if bindings.insert(name, term).is_some() {
                return Err(invalid_solution());
            }
            match self.peek() {
                Some(b',') => self.index += 1,
                Some(_) => return Err(invalid_solution()),
                None => break,
            }
        }
        Ok(bindings)
    }

    fn parse_variable(&mut self) -> Result<String, CapabilityError> {
        let start = self.index;
        match self.bump() {
            Some(byte) if byte.is_ascii_uppercase() => {}
            _ => return Err(invalid_solution()),
        }
        while let Some(byte) = self.peek() {
            if byte.is_ascii_alphanumeric() || byte == b'_' {
                self.index += 1;
            } else {
                break;
            }
        }
        self.text(start, self.index)
    }

    fn parse_term(&mut self, depth: usize) -> Result<Term, CapabilityError> {
        if depth > MAX_PARSED_DEPTH {
            return Err(invalid_solution());
        }
        match self.peek() {
            Some(b'-') | Some(b'0'..=b'9') => self.parse_integer(),
            Some(b'"') => self.parse_string(),
            Some(b'[') => self.parse_list(depth),
            Some(byte) if byte.is_ascii_lowercase() => self.parse_atom_term(depth),
            _ => Err(invalid_solution()),
        }
    }

    fn parse_integer(&mut self) -> Result<Term, CapabilityError> {
        let start = self.index;
        if self.peek() == Some(b'-') {
            self.index += 1;
        }
        let digits = self.index;
        while let Some(byte) = self.peek() {
            if byte.is_ascii_digit() {
                self.index += 1;
            } else {
                break;
            }
        }
        if self.index == digits {
            return Err(invalid_solution());
        }
        let text = self.text(start, self.index)?;
        let unsigned = text.strip_prefix('-').unwrap_or(text.as_str());
        if unsigned.len() > 1 && unsigned.starts_with('0') {
            return Err(invalid_solution());
        }
        text.parse::<i64>()
            .map(Term::Integer)
            .map_err(|_| invalid_solution())
    }

    fn parse_string(&mut self) -> Result<Term, CapabilityError> {
        self.index += 1;
        // Every decoded byte costs at least one input byte, so the remaining
        // input bounds the literal.
        let mut bytes = Vec::with_capacity(self.remaining());
        loop {
            match self.bump() {
                Some(b'"') => break,
                Some(b'\\') => match self.bump() {
                    Some(b'"') => bytes.push(b'"'),
                    Some(b'\\') => bytes.push(b'\\'),
                    Some(b'x') => {
                        let code = self.parse_hex_escape()?;
                        self.require_byte(b'\\')?;
                        let Some(character) = char::from_u32(u32::from(code)) else {
                            return Err(invalid_solution());
                        };
                        let mut buffer = [0_u8; 4];
                        bytes.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
                    }
                    _ => return Err(invalid_solution()),
                },
                Some(byte) if byte < 0x20 || byte == 0x7f => return Err(invalid_solution()),
                Some(byte) => bytes.push(byte),
                None => return Err(invalid_solution()),
            }
        }
        let text = String::from_utf8(bytes).map_err(|_| invalid_solution())?;
        Ok(Term::String(text))
    }

    fn parse_hex_digit(&mut self) -> Result<u8, CapabilityError> {
        match self.bump() {
            Some(byte) if byte.is_ascii_digit() => Ok(byte - b'0'),
            Some(byte) if (b'a'..=b'f').contains(&byte) => Ok(byte - b'a' + 10),
            _ => Err(invalid_solution()),
        }
    }

    /// Read the hex digits of an ISO `\xHH…\` escape into a code point.
    fn parse_hex_escape(&mut self) -> Result<u16, CapabilityError> {
        let mut digits = 0_u32;
        let mut value = 0_u32;
        while digits < 6 {
            let Some(byte) = self.peek() else {
                return Err(invalid_solution());
            };
            if !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte) {
                break;
            }
            let digit = u32::from(self.parse_hex_digit()?);
            value = value * 16 + digit;
            digits += 1;
        }
        if digits < 2 || value > u32::from(u16::MAX) {
            return Err(invalid_solution());
        }
        u16::try_from(value).map_err(|_| invalid_solution())
    }

    fn parse_list(&mut self, depth: usize) -> Result<Term, CapabilityError> {
        self.index += 1;
        // Every list item consumes at least one input byte.
        let mut items = Vec::with_capacity(self.remaining());
        if self.peek() == Some(b']') {
            self.index += 1;
            return Ok(Term::List(items));
        }
        loop {
            items.push(self.parse_term(depth + 1)?);
            match self.bump() {
                Some(b',') => {}
                Some(b']') => break,
                _ => return Err(invalid_solution()),
            }
        }
        Ok(Term::List(items))
    }

    fn parse_atom_term(&mut self, depth: usize) -> Result<Term, CapabilityError> {
        let start = self.index;
        while let Some(byte) = self.peek() {
            if byte.is_ascii_alphanumeric() || byte == b'_' {
                self.index += 1;
            } else {
                break;
            }
        }
        let name = self.text(start, self.index)?;
        if is_forbidden_predicate(&name) {
            return Err(invalid_solution());
        }
        if self.peek() != Some(b'(') {
            return Ok(Term::Symbol(name));
        }
        self.index += 1;
        // Every argument consumes at least one input byte.
        let mut args = Vec::with_capacity(self.remaining());
        loop {
            args.push(self.parse_term(depth + 1)?);
            match self.bump() {
                Some(b',') => {}
                Some(b')') => break,
                _ => return Err(invalid_solution()),
            }
        }
        Ok(Term::Compound {
            functor: name,
            args,
        })
    }

    fn text(&self, start: usize, end: usize) -> Result<String, CapabilityError> {
        std::str::from_utf8(&self.bytes[start..end])
            .map(str::to_owned)
            .map_err(|_| invalid_solution())
    }

    /// Input bytes not yet consumed.
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.index)
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.index).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.index += 1;
        Some(byte)
    }

    fn require_byte(&mut self, expected: u8) -> Result<(), CapabilityError> {
        match self.bump() {
            Some(byte) if byte == expected => Ok(()),
            _ => Err(invalid_solution()),
        }
    }
}

/// Encode one finite term into the restricted engine syntax.
///
/// A variable is rendered by name after the variable grammar check; whether a
/// variable is legal *here* is a request-position decision taken by
/// [`CapabilityMetadata::ensure_request`].
#[allow(unknown_lints, usize_in_public_api)] // byte budgets mirror string lengths
pub fn encode_term(
    term: &Term,
    profile: TermProfile,
    max_bytes: usize,
) -> Result<String, CapabilityError> {
    term.check(profile)?;
    let encoded = encode_term_inner(term, &[])?;
    if encoded.len() > max_bytes {
        return Err(CapabilityError::LimitExceeded(
            "encoded term exceeds the output budget".to_owned(),
        ));
    }
    Ok(encoded)
}

/// Encode one atom after finite-term validation.
///
/// Variables are rendered by name, so this also renders goals and rule clauses;
/// ground positions are enforced by request validation, not by the encoder.
#[allow(unknown_lints, usize_in_public_api)] // byte budgets mirror string lengths
pub fn encode_atom(
    atom: &Atom,
    profile: TermProfile,
    max_bytes: usize,
) -> Result<String, CapabilityError> {
    atom.check(profile)?;
    let encoded = encode_atom_inner(atom, &[])?;
    if encoded.len() > max_bytes {
        return Err(CapabilityError::LimitExceeded(
            "encoded atom exceeds the output budget".to_owned(),
        ));
    }
    Ok(encoded)
}

/// Render query-local variables in a private named-anonymous namespace. Scryer
/// prints singleton warnings on protocol stdout for ordinary local names.
pub(crate) fn encode_query_goal(
    request: &Request,
    metadata: &CapabilityMetadata,
) -> Result<String, CapabilityError> {
    request.goal.check(metadata.terms)?;
    let encoded = encode_atom_inner(&request.goal, &request.variables)?;
    if encoded.len() > metadata.limits.max_output_bytes {
        return Err(CapabilityError::LimitExceeded(
            "encoded query exceeds the output budget".to_owned(),
        ));
    }
    Ok(encoded)
}

/// Render one validated atom, without parentheses when it has no arguments.
fn encode_atom_inner(atom: &Atom, variables: &[QueryVariable]) -> Result<String, CapabilityError> {
    check_name(&atom.predicate)?;
    let mut output = atom.predicate.clone();
    if atom.terms.is_empty() {
        return Ok(output);
    }
    output.push('(');
    for (index, term) in atom.terms.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str(&encode_term_inner(term, variables)?);
    }
    output.push(')');
    Ok(output)
}

/// Serialize finite solution bindings under an output-byte budget.
#[allow(unknown_lints, usize_in_public_api)] // byte budgets mirror string lengths
pub fn serialize_solution(
    solution: &Solution,
    profile: TermProfile,
    max_bytes: usize,
) -> Result<String, CapabilityError> {
    let mut output = String::new();
    for (index, (name, term)) in solution.bindings.iter().enumerate() {
        if !is_variable_name(name) {
            return Err(CapabilityError::InvalidRequest(
                "binding name is not a query variable".to_owned(),
            ));
        }
        // A binding reports a value, so it has to be ground.
        term.check_ground(profile)?;
        if index > 0 {
            output.push(',');
        }
        output.push_str(name);
        output.push('=');
        output.push_str(&encode_term_inner(term, &[])?);
        if output.len() > max_bytes {
            return Err(CapabilityError::LimitExceeded(
                "serialized solution exceeds the output budget".to_owned(),
            ));
        }
    }
    Ok(output)
}

/// One pending step of iterative term rendering.
enum RenderStep<'a> {
    /// Render this term.
    Term(&'a Term),
    /// Emit this literal separator or closing text.
    Text(&'static str),
}

/// Render one validated term. Callers validate first; the checks here keep the
/// encoder total for direct callers.
fn encode_term_inner(term: &Term, variables: &[QueryVariable]) -> Result<String, CapabilityError> {
    // An explicit work stack keeps rendering off the call stack: a decoded
    // engine line is only depth-checked after it is parsed, so this walk must
    // not assume the caller's term is shallow.
    let mut output = String::new();
    let mut pending = vec![RenderStep::Term(term)];
    while let Some(step) = pending.pop() {
        let term = match step {
            RenderStep::Text(text) => {
                output.push_str(text);
                continue;
            }
            RenderStep::Term(term) => term,
        };
        match term {
            Term::Integer(value) => output.push_str(&value.to_string()),
            Term::String(value) => {
                output.push('"');
                output.push_str(&escape_string(value));
                output.push('"');
            }
            Term::Symbol(value) => {
                check_name(value)?;
                output.push_str(value);
            }
            Term::Variable(value) => {
                if !is_variable_name(value) {
                    return Err(CapabilityError::InvalidRequest(
                        "variable name is not permitted".to_owned(),
                    ));
                }
                if variables
                    .iter()
                    .any(|variable| variable.role == VariableRole::Local && variable.name == *value)
                {
                    output.push('_');
                }
                output.push_str(value);
            }
            Term::Reference {
                record_id,
                revision_id,
            } => {
                output.push_str("ref(");
                output.push_str(&record_id.to_hex());
                output.push(',');
                match revision_id {
                    Some(revision) => output.push_str(&revision.to_hex()),
                    None => output.push_str("current"),
                }
                output.push(')');
            }
            Term::List(items) => {
                output.push('[');
                pending.push(RenderStep::Text("]"));
                queue_separated(&mut pending, items);
            }
            Term::Compound { functor, args } => {
                check_name(functor)?;
                output.push_str(functor);
                if args.is_empty() {
                    continue;
                }
                output.push('(');
                pending.push(RenderStep::Text(")"));
                queue_separated(&mut pending, args);
            }
        }
    }
    Ok(output)
}

/// Queue comma-separated terms so the work stack yields them left to right.
fn queue_separated<'a>(pending: &mut Vec<RenderStep<'a>>, terms: &'a [Term]) {
    pending.reserve(terms.len().saturating_mul(2));
    for (index, item) in terms.iter().enumerate().rev() {
        pending.push(RenderStep::Term(item));
        if index > 0 {
            pending.push(RenderStep::Text(","));
        }
    }
}

/// Quote a string literal, escaping every character that could end it, start an
/// escape, or break the source line.
fn escape_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            character if character.is_control() => {
                output.push_str(&format!("\\x{:02x}\\", u32::from(character)));
            }
            character => output.push(character),
        }
    }
    output
}

impl Solution {
    /// Distinct ancestry roots, not the number of duplicated summaries.
    #[allow(unknown_lints, usize_in_public_api)] // support counts mirror collection lengths
    pub fn independent_support_count(&self) -> usize {
        self.premises
            .iter()
            .flat_map(|premise| premise.ancestry_roots.iter().copied())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    }

    /// Premises whose bytes are unavailable but whose retained claim envelope
    /// remains inspectable. Never fabricate a quotation for these.
    pub fn unavailable_premises(&self) -> Vec<&Premise> {
        self.premises
            .iter()
            .filter(|premise| matches!(premise.availability, PremiseAvailability::Pruned { .. }))
            .collect()
    }

    /// Validate support and hypothetical-assumption provenance.
    pub fn validate(
        &self,
        declared_assumptions: &std::collections::BTreeSet<String>,
    ) -> Result<(), CapabilityError> {
        for premise in &self.premises {
            if matches!(premise.availability, PremiseAvailability::Pruned { .. })
                && premise.span.is_some()
            {
                return Err(CapabilityError::InvalidRequest(format!(
                    "premise {} quotes pruned source bytes",
                    premise.record_id
                )));
            }
        }
        for assumption in &self.assumptions {
            if !declared_assumptions.contains(assumption) {
                return Err(CapabilityError::InvalidRequest(format!(
                    "solution uses undeclared assumption {assumption}"
                )));
            }
        }
        match &self.certification {
            Certification::Certified => {
                if self.premises.is_empty()
                    || self
                        .premises
                        .iter()
                        .any(|premise| premise.ancestry_roots.is_empty())
                {
                    return Err(CapabilityError::InvalidRequest(
                        "certified solution needs a complete premise chain".to_owned(),
                    ));
                }
                if !self.assumptions.is_empty() {
                    return Err(CapabilityError::InvalidRequest(
                        "hypothetical assumptions cannot be certified".to_owned(),
                    ));
                }
            }
            Certification::Uncertified { reason } => {
                if reason.trim().is_empty() {
                    return Err(CapabilityError::InvalidRequest(
                        "uncertified solution needs a reason".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

impl Outcome {
    /// Validate this result against the request that produced it, including
    /// context, premise chains, pruning disclosure, and assumptions.
    pub fn validate_for_request(&self, request: &Request) -> Result<(), CapabilityError> {
        self.validate()?;
        if self.mode != request.mode
            || self.context.revision != request.revision
            || self.context.scope != request.scope
            || self.context.eligibility_generation != request.eligibility_generation
            || self.context.image_digest != request.image_digest
            || (self.readback_valid && self.identity.image_digest != request.image_digest)
        {
            return Err(CapabilityError::InvalidRequest(
                "result context differs from its request".to_owned(),
            ));
        }
        let declared = request
            .assumptions
            .iter()
            .map(|assumption| assumption.id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let output_variables = request
            .variables
            .iter()
            .filter(|variable| variable.role == VariableRole::Output)
            .map(|variable| variable.name.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let solutions = match &self.result {
            QueryResult::GroundTest { .. } => Vec::new(),
            QueryResult::FindOne { solution } => solution.iter().collect(),
            QueryResult::Enumerate { solutions } | QueryResult::Collect { solutions } => {
                solutions.iter().collect()
            }
        };
        for solution in solutions {
            if solution
                .bindings
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>()
                != output_variables
            {
                return Err(CapabilityError::InvalidRequest(
                    "solution bindings differ from the declared output variables".to_owned(),
                ));
            }
            solution.validate(&declared)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> mneme_core::ScopeId {
        mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
    }

    fn revision() -> mneme_core::WorkspaceRevisionId {
        mneme_core::WorkspaceRevisionId::from_bytes([0xb0; 16])
    }

    fn request(features: std::collections::BTreeSet<Feature>) -> Request {
        Request {
            actor: "agent".to_owned(),
            scope: scope(),
            revision: revision(),
            eligibility_generation: 1,
            image_digest: "sha256:image".to_owned(),
            mode: QueryMode::GroundTest,
            goal: Atom {
                predicate: "path".to_owned(),
                terms: vec![Term::String("a".to_owned())],
            },
            variables: Vec::new(),
            rules: Vec::new(),
            assumptions: Vec::new(),
            features,
            limits: RequestLimits {
                max_time_ms: 50,
                max_solutions: 4,
                max_output_bytes: 1024,
            },
        }
    }

    fn enabled(features: std::collections::BTreeSet<Feature>) -> CapabilityMetadata {
        CapabilityMetadata {
            adapter_version: "1".to_owned(),
            profile: "positive-minimal/v1".to_owned(),
            engine: Some(EngineIdentity {
                name: "scryer-prolog".to_owned(),
                version: "0.10.0".to_owned(),
                source_revision: "nixpkgs-pinned".to_owned(),
            }),
            state: CapabilityState::Enabled,
            features,
            allowed_predicates: std::collections::BTreeSet::from([
                "path".to_owned(),
                "member".to_owned(),
            ]),
            limits: ProfileLimits {
                max_time_ms: 100,
                max_solutions: 8,
                max_output_bytes: 2048,
                max_term_depth: 4,
                max_rule_count: 4,
            },
            terms: TermProfile {
                max_depth: 4,
                max_collection: 8,
                references_allowed: false,
            },
        }
    }

    fn positive() -> CapabilityMetadata {
        enabled(std::collections::BTreeSet::from([Feature::PositiveQuery]))
    }

    /// A sealed image for tests that only exercise output classification.
    fn search_image() -> snapshot::InputImage {
        let mut image = snapshot::InputImage {
            context: SearchContext {
                revision: revision(),
                scope: scope(),
                eligibility_generation: 1,
                image_digest: String::new(),
                profile: "positive-minimal/v1".to_owned(),
                rule_versions: std::collections::BTreeMap::new(),
            },
            canonical: Vec::new(),
            relations: Vec::new(),
            coverage: InputCoverage {
                complete: true,
                reason: None,
            },
        };
        image.seal();
        image
    }

    fn worker_output(status: process::WorkerStatus, output: &str) -> process::WorkerOutcome {
        process::WorkerOutcome {
            status,
            output: output.to_owned(),
            stderr: String::new(),
            captured_bytes: output.len(),
            output_utf8_valid: true,
            elapsed_ms: 1,
            output_limit_exceeded: false,
            solution_limit_exceeded: false,
            reason: None,
        }
    }

    fn request_with_goal(names: &[&str], image: &snapshot::InputImage) -> Request {
        let mut request = request(std::collections::BTreeSet::from([Feature::PositiveQuery]));
        request.image_digest = image.context.image_digest.clone();
        request.mode = QueryMode::Enumerate;
        request.goal = Atom {
            predicate: "path".to_owned(),
            terms: names
                .iter()
                .map(|name| Term::Variable((*name).to_owned()))
                .collect(),
        };
        request.variables = names
            .iter()
            .map(|name| QueryVariable {
                name: (*name).to_owned(),
                role: VariableRole::Output,
            })
            .collect();
        request
    }

    fn test_identity(image: &snapshot::InputImage) -> ProtocolIdentity {
        ProtocolIdentity {
            version: RESPONSE_PROTOCOL_VERSION,
            request_digest: "sha256:test-request".to_owned(),
            profile_digest: "sha256:test-profile".to_owned(),
            rule_manifest_digest: "sha256:test-rules".to_owned(),
            input_order_digest: "sha256:test-order".to_owned(),
            image_digest: image.context.image_digest.clone(),
        }
    }

    fn test_response(identity: &ProtocolIdentity, rows: &[&str], terminal: Option<&str>) -> String {
        test_response_for_mode(identity, QueryMode::Enumerate, rows, terminal)
    }

    fn test_response_for_mode(
        identity: &ProtocolIdentity,
        mode: QueryMode,
        rows: &[&str],
        terminal: Option<&str>,
    ) -> String {
        let mut output = protocol_header(identity, mode);
        output.push('\n');
        for row in rows {
            output.push_str(RESPONSE_ROW_PREFIX);
            output.push('\t');
            output.push_str(&identity.request_digest);
            output.push('\t');
            output.push_str(row);
            output.push('\n');
        }
        if let Some(terminal) = terminal {
            output.push_str(RESPONSE_STOP_PREFIX);
            output.push('\t');
            output.push_str(&identity.request_digest);
            output.push('\t');
            output.push_str(terminal);
            output.push('\n');
        }
        output
    }

    fn outcome_from_test_worker(
        worker: &process::WorkerOutcome,
        image: &snapshot::InputImage,
        request: &Request,
    ) -> Outcome {
        outcome_from_worker(worker, image, request, &test_identity(image))
    }

    fn result_solutions(outcome: &Outcome) -> &[Solution] {
        match &outcome.result {
            QueryResult::GroundTest { .. } => &[],
            QueryResult::FindOne { solution } => solution.as_slice(),
            QueryResult::Enumerate { solutions } | QueryResult::Collect { solutions } => solutions,
        }
    }

    #[test]
    fn disabled_capability_is_explicit_and_unavailable() {
        let metadata = CapabilityMetadata::disabled("engine not enabled");
        metadata.validate().expect("disabled metadata");
        assert!(matches!(
            metadata.ensure_request(&request(std::collections::BTreeSet::new())),
            Err(CapabilityError::Unavailable { .. })
        ));
    }

    #[test]
    fn enabled_metadata_requires_engine_and_limits() {
        let mut metadata = positive();
        metadata.engine = None;
        assert!(metadata.validate().is_err());
        let mut metadata = positive();
        metadata.limits.max_solutions = 0;
        assert!(metadata.validate().is_err());
        let mut metadata = positive();
        metadata.allowed_predicates.insert("not-safe!".to_owned());
        assert!(metadata.validate().is_err());
    }

    #[test]
    fn unadvertised_features_are_refused() {
        let metadata = positive();
        let mut request = request(std::collections::BTreeSet::from([Feature::PositiveQuery]));
        assert!(metadata.ensure_request(&request).is_ok());
        request.features.insert(Feature::Plans);
        assert_eq!(
            metadata.ensure_request(&request),
            Err(CapabilityError::UnsupportedFeature(Feature::Plans))
        );
    }

    #[test]
    fn finite_terms_reject_depth_violations() {
        let metadata = positive();
        let mut request = request(std::collections::BTreeSet::from([Feature::PositiveQuery]));
        request.goal.terms = vec![Term::List(vec![Term::List(vec![Term::List(vec![
            Term::List(vec![Term::Integer(1)]),
        ])])])];
        assert!(matches!(
            metadata.ensure_request(&request),
            Err(CapabilityError::LimitExceeded(_))
        ));
    }

    #[test]
    fn non_complete_results_cannot_claim_exhaustiveness() {
        let context = SearchContext {
            revision: revision(),
            scope: scope(),
            eligibility_generation: 1,
            image_digest: "sha256:image".to_owned(),
            profile: "positive-minimal/v1".to_owned(),
            rule_versions: std::collections::BTreeMap::new(),
        };
        let mut result = Outcome::disabled("disabled", context);
        assert!(!result.exhaustive);
        assert!(result.validate().is_ok());
        result.status = ExecutionStatus::Timeout;
        result.exhaustive = true;
        assert!(result.validate().is_err());
    }

    #[test]
    fn disabled_capability_leaves_baseline_workspace_usable() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = mneme_store::Workspace::create(
            temp.path(),
            mneme_store::WorkspaceConfig::new(
                Box::new(mneme_store::SystemClock),
                Box::new(mneme_store::NoFaults),
            ),
        )
        .expect("workspace");
        let before = workspace.status().expect("baseline status");
        let metadata = CapabilityMetadata::disabled("Prolog disabled");
        assert!(
            metadata
                .ensure_request(&request(std::collections::BTreeSet::new()))
                .is_err()
        );
        let after = workspace
            .status()
            .expect("baseline status after Prolog refusal");
        assert_eq!(before.sequence, after.sequence);
        assert!(workspace.snapshot().is_ok());
    }

    #[test]
    fn effectful_and_unadvertised_predicates_are_refused() {
        let metadata = positive();
        let mut request = request(std::collections::BTreeSet::from([Feature::PositiveQuery]));
        request.goal.predicate = "open".to_owned();
        assert_eq!(
            metadata.ensure_request(&request),
            Err(CapabilityError::DisallowedPredicate("open".to_owned()))
        );
        request.goal.predicate = "assertz".to_owned();
        assert_eq!(
            metadata.ensure_request(&request),
            Err(CapabilityError::DisallowedPredicate("assertz".to_owned()))
        );
        request.goal.predicate = "unadvertised".to_owned();
        assert_eq!(
            metadata.ensure_request(&request),
            Err(CapabilityError::DisallowedPredicate(
                "unadvertised".to_owned()
            ))
        );
        // A cross-engine callback is refused even when a profile allow-lists
        // the name, so the guard does not depend on the allow-list.
        let mut cross_engine = positive();
        cross_engine.allowed_predicates.insert("datalog".to_owned());
        request.goal.predicate = "datalog".to_owned();
        assert_eq!(
            cross_engine.ensure_request(&request),
            Err(CapabilityError::DisallowedPredicate("datalog".to_owned()))
        );
    }

    #[test]
    fn reserved_and_unsafe_names_never_reach_the_encoder() {
        let metadata = positive();
        let mut request = request(std::collections::BTreeSet::from([Feature::PositiveQuery]));
        request.goal.predicate = "mneme_emit_term".to_owned();
        assert!(matches!(
            metadata.ensure_request(&request),
            Err(CapabilityError::DisallowedPredicate(_))
        ));
        request.goal.predicate = "path".to_owned();
        request.goal.terms = vec![Term::Symbol("consult(other".to_owned())];
        assert!(matches!(
            metadata.ensure_request(&request),
            Err(CapabilityError::InvalidRequest(_))
        ));
        // A safe symbol that names a forbidden predicate is data, not a call,
        // but it is still refused so no refusal path depends on position.
        request.goal.terms = vec![Term::Symbol("shell".to_owned())];
        assert!(matches!(
            metadata.ensure_request(&request),
            Err(CapabilityError::DisallowedPredicate(_))
        ));
    }

    #[test]
    fn compound_functors_and_nested_terms_are_validated() {
        let metadata = positive();
        let mut request = request(std::collections::BTreeSet::from([Feature::PositiveQuery]));
        request.goal.terms = vec![Term::Compound {
            functor: "path".to_owned(),
            args: vec![Term::Integer(1)],
        }];
        assert!(metadata.ensure_request(&request).is_ok());
        request.goal.terms = vec![Term::Compound {
            functor: "shell".to_owned(),
            args: vec![Term::Integer(1)],
        }];
        assert!(matches!(
            metadata.ensure_request(&request),
            Err(CapabilityError::DisallowedPredicate(_))
        ));
        request.goal.terms = vec![Term::List(vec![Term::Compound {
            functor: "consult(other".to_owned(),
            args: vec![Term::Integer(1)],
        }])];
        assert!(matches!(
            metadata.ensure_request(&request),
            Err(CapabilityError::InvalidRequest(_))
        ));
    }

    #[test]
    fn rule_bodies_and_assumptions_are_validated() {
        let metadata = enabled(std::collections::BTreeSet::from([
            Feature::PositiveQuery,
            Feature::HypotheticalAssumptions,
        ]));
        let mut request = request(std::collections::BTreeSet::from([
            Feature::PositiveQuery,
            Feature::HypotheticalAssumptions,
        ]));
        request.rules = vec![Rule {
            id: "r1".to_owned(),
            version: "1".to_owned(),
            head: Atom {
                predicate: "path".to_owned(),
                terms: vec![Term::String("derived".to_owned())],
            },
            body: vec![Literal::Positive(Atom {
                predicate: "path".to_owned(),
                terms: vec![Term::String("a".to_owned())],
            })],
        }];
        assert!(metadata.ensure_request(&request).is_ok());
        request.rules[0].body = vec![Literal::Negative(Atom {
            predicate: "path".to_owned(),
            terms: vec![Term::String("a".to_owned())],
        })];
        assert_eq!(
            metadata.ensure_request(&request),
            Err(CapabilityError::UnsupportedFeature(
                Feature::GuardedNegation
            ))
        );
        request.rules.clear();
        request.assumptions = vec![Assumption {
            id: "assumption-1".to_owned(),
            atom: Atom {
                predicate: "path".to_owned(),
                terms: vec![Term::Symbol("other".to_owned())],
            },
            rationale: "what-if".to_owned(),
        }];
        assert!(metadata.ensure_request(&request).is_ok());
        request.assumptions[0].atom.terms = vec![Term::Variable("X".to_owned())];
        assert!(matches!(
            metadata.ensure_request(&request),
            Err(CapabilityError::InvalidRequest(_))
        ));
        request.assumptions[0].atom = Atom {
            predicate: ASSERTION_RELATION.to_owned(),
            terms: vec![Term::String("canonical-looking".to_owned())],
        };
        assert_eq!(
            metadata.ensure_request(&request),
            Err(CapabilityError::InvalidRequest(
                "an assumption cannot name an image relation".to_owned()
            ))
        );
    }

    #[test]
    fn goal_variables_are_permitted_with_valid_names() {
        let metadata = positive();
        let mut request = request(std::collections::BTreeSet::from([Feature::PositiveQuery]));
        request.mode = QueryMode::FindOne;
        request.goal.terms = vec![Term::Variable("X".to_owned())];
        request.variables = vec![QueryVariable {
            name: "X".to_owned(),
            role: VariableRole::Output,
        }];
        assert!(metadata.ensure_request(&request).is_ok());
        request.goal.terms = vec![Term::Variable("x".to_owned())];
        request.variables[0].name = "x".to_owned();
        assert!(matches!(
            metadata.ensure_request(&request),
            Err(CapabilityError::InvalidRequest(_))
        ));
        request.goal.terms = vec![Term::Variable("_X".to_owned())];
        request.variables[0].name = "_X".to_owned();
        assert!(matches!(
            metadata.ensure_request(&request),
            Err(CapabilityError::InvalidRequest(_))
        ));
        request.goal.terms = vec![Term::Variable("X".to_owned())];
        request.variables.clear();
        assert!(matches!(
            metadata.ensure_request(&request),
            Err(CapabilityError::InvalidRequest(_))
        ));
    }

    #[test]
    fn variables_are_permitted_in_rules_when_range_restricted() {
        let metadata = positive();
        let mut request = request(std::collections::BTreeSet::from([Feature::PositiveQuery]));
        // A head variable that occurs in the body is a usable rule.
        request.rules = vec![Rule {
            id: "r1".to_owned(),
            version: "1".to_owned(),
            head: Atom {
                predicate: "path".to_owned(),
                terms: vec![Term::Variable("X".to_owned())],
            },
            body: vec![Literal::Positive(Atom {
                predicate: "path".to_owned(),
                terms: vec![Term::Variable("X".to_owned())],
            })],
        }];
        assert!(metadata.ensure_request(&request).is_ok());

        // A head variable that never occurs in the body would assert a
        // non-ground fact.
        request.rules[0].body = vec![Literal::Positive(Atom {
            predicate: "path".to_owned(),
            terms: vec![Term::String("a".to_owned())],
        })];
        assert_eq!(
            metadata.ensure_request(&request),
            Err(CapabilityError::InvalidRequest(
                "rule head variable does not occur in the rule body".to_owned()
            ))
        );

        // A variable that occurs once in the whole clause would make the
        // engine write a singleton warning into the solution stream.
        request.rules[0].head = Atom {
            predicate: "path".to_owned(),
            terms: vec![Term::String("ground".to_owned())],
        };
        request.rules[0].body = vec![Literal::Positive(Atom {
            predicate: "path".to_owned(),
            terms: vec![Term::Variable("Y".to_owned())],
        })];
        assert_eq!(
            metadata.ensure_request(&request),
            Err(CapabilityError::InvalidRequest(
                "a rule variable occurs only once".to_owned()
            ))
        );
    }

    #[test]
    fn finite_encoding_and_output_budgets_are_enforced() {
        let profile = TermProfile {
            max_depth: 4,
            max_collection: 8,
            references_allowed: true,
        };
        assert_eq!(
            encode_term(
                &Term::Compound {
                    functor: "f".to_owned(),
                    args: vec![Term::Integer(1)],
                },
                profile,
                64,
            ),
            Ok("f(1)".to_owned())
        );
        assert!(matches!(
            encode_term(&Term::String("too long".to_owned()), profile, 4),
            Err(CapabilityError::LimitExceeded(_))
        ));
        let solution = Solution {
            bindings: std::collections::BTreeMap::from([("X".to_owned(), Term::Integer(42))]),
            premises: Vec::new(),
            assumptions: std::collections::BTreeSet::new(),
            certification: Certification::Uncertified {
                reason: "no proof certificate".to_owned(),
            },
        };
        assert_eq!(
            serialize_solution(&solution, profile, 64),
            Ok("X=42".to_owned())
        );
        assert!(matches!(
            serialize_solution(&solution, profile, 2),
            Err(CapabilityError::LimitExceeded(_))
        ));
        // Bindings report values, so a variable there is not renderable.
        let variable_binding = Solution {
            bindings: std::collections::BTreeMap::from([(
                "X".to_owned(),
                Term::Variable("Y".to_owned()),
            )]),
            premises: Vec::new(),
            assumptions: std::collections::BTreeSet::new(),
            certification: Certification::Uncertified {
                reason: "no proof certificate".to_owned(),
            },
        };
        assert!(matches!(
            serialize_solution(&variable_binding, profile, 64),
            Err(CapabilityError::InvalidRequest(_))
        ));
        // A term or atom may carry a variable that a goal or rule binds; the
        // name still has to match the variable grammar.
        assert_eq!(
            encode_term(&Term::Variable("X".to_owned()), profile, 64),
            Ok("X".to_owned())
        );
        assert!(matches!(
            encode_term(&Term::Variable("_x".to_owned()), profile, 64),
            Err(CapabilityError::InvalidRequest(_))
        ));
        assert_eq!(
            encode_atom(
                &Atom {
                    predicate: "path".to_owned(),
                    terms: vec![Term::Variable("X".to_owned())],
                },
                profile,
                64,
            ),
            Ok("path(X)".to_owned())
        );
    }

    #[test]
    fn zero_arity_atoms_render_without_parentheses() {
        let profile = TermProfile {
            max_depth: 4,
            max_collection: 8,
            references_allowed: false,
        };
        assert_eq!(
            encode_atom(
                &Atom {
                    predicate: "ready".to_owned(),
                    terms: Vec::new(),
                },
                profile,
                64,
            ),
            Ok("ready".to_owned())
        );
        assert_eq!(
            encode_atom(
                &Atom {
                    predicate: "path".to_owned(),
                    terms: vec![Term::String("a".to_owned())],
                },
                profile,
                64,
            ),
            Ok("path(\"a\")".to_owned())
        );
    }

    #[test]
    fn strings_escape_every_control_character() {
        assert_eq!(
            encode_term(
                &Term::String("a\"b\\c\nd\te\u{7f}f\u{1}".to_owned()),
                TermProfile {
                    max_depth: 2,
                    max_collection: 4,
                    references_allowed: false,
                },
                256,
            ),
            Ok("\"a\\\"b\\\\c\\x0a\\d\\x09\\e\\x7f\\f\\x01\\\"".to_owned())
        );
        assert!(
            encode_term(
                &Term::Symbol("a\nb".to_owned()),
                TermProfile {
                    max_depth: 2,
                    max_collection: 4,
                    references_allowed: false,
                },
                256,
            )
            .is_err()
        );
    }

    #[test]
    fn goal_variables_keep_first_occurrence_order() {
        let goal = Atom {
            predicate: "path".to_owned(),
            terms: vec![
                Term::Variable("B".to_owned()),
                Term::Compound {
                    functor: "f".to_owned(),
                    args: vec![
                        Term::Variable("A".to_owned()),
                        Term::Variable("B".to_owned()),
                    ],
                },
            ],
        };
        assert_eq!(goal_variables(&goal), vec!["B".to_owned(), "A".to_owned()]);
    }

    fn names(values: &[&str]) -> std::collections::BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn solution_lines_round_trip_through_the_restricted_grammar() {
        let variables = names(&["X", "Y"]);
        let solution = parse_solution_line(
            "X=42,Y=f(g(1),\"a\\x0a\\b\",[x,y],[])",
            &variables,
            &names(&["assumption-1"]),
        )
        .expect("line");
        assert_eq!(solution.bindings.get("X"), Some(&Term::Integer(42)));
        assert_eq!(
            solution.bindings.get("Y"),
            Some(&Term::Compound {
                functor: "f".to_owned(),
                args: vec![
                    Term::Compound {
                        functor: "g".to_owned(),
                        args: vec![Term::Integer(1)],
                    },
                    Term::String("a\nb".to_owned()),
                    Term::List(vec![
                        Term::Symbol("x".to_owned()),
                        Term::Symbol("y".to_owned())
                    ]),
                    Term::List(Vec::new()),
                ],
            })
        );
        assert_eq!(solution.assumptions, names(&["assumption-1"]));
        assert!(solution.validate(&names(&["assumption-1"])).is_ok());
    }

    #[test]
    fn empty_solution_line_has_no_bindings() {
        let solution = parse_solution_line(
            "",
            &std::collections::BTreeSet::new(),
            &std::collections::BTreeSet::new(),
        )
        .expect("ground solution");
        assert!(solution.bindings.is_empty());
        assert!(matches!(
            parse_solution_line("", &names(&["X"]), &std::collections::BTreeSet::new()),
            Err(CapabilityError::InvalidRequest(_))
        ));
    }

    #[test]
    fn solution_lines_outside_the_grammar_are_refused() {
        let variables = names(&["X"]);
        for line in [
            "X=Y",
            "X='atom needing quotes'",
            "X=f()",
            "X=[a|b]",
            "X=$unsupported",
            "X=1e3",
            "X=007",
            "X=99999999999999999999999",
            "X=1,Y=2",
            "Y=1",
            "X=1,",
            "X=1 X=2",
            "X=1\\",
            "X=\"unterminated",
            "X=\"raw\nnewline\"",
            "X=shell(a)",
            "X=mneme_emit_term(a)",
            "X=-",
        ] {
            assert!(
                parse_solution_line(line, &variables, &std::collections::BTreeSet::new()).is_err(),
                "{line:?} was accepted"
            );
        }
    }

    #[test]
    fn multi_binding_solution_lines_carry_every_binding() {
        let image = search_image();
        let request = request_with_goal(&["S", "V"], &image);
        let identity = test_identity(&image);
        let worker = worker_output(
            process::WorkerStatus::Complete,
            &test_response(
                &identity,
                &["S=\"1010\",V=-7", "S=\"2020\",V=plain"],
                Some("exhausted"),
            ),
        );
        let outcome = outcome_from_test_worker(&worker, &image, &request);
        assert_eq!(outcome.status, ExecutionStatus::Complete);
        assert!(outcome.exhaustive);
        assert_eq!(result_solutions(&outcome).len(), 2);
        assert_eq!(
            result_solutions(&outcome)[0].bindings,
            std::collections::BTreeMap::from([
                ("S".to_owned(), Term::String("1010".to_owned())),
                ("V".to_owned(), Term::Integer(-7)),
            ])
        );
        assert_eq!(
            result_solutions(&outcome)[1].bindings,
            std::collections::BTreeMap::from([
                ("S".to_owned(), Term::String("2020".to_owned())),
                ("V".to_owned(), Term::Symbol("plain".to_owned())),
            ])
        );
    }

    #[test]
    fn bindings_without_a_separator_are_not_a_solution_line() {
        // The engine printed this shape while the `,` between bindings was a
        // body conjunction instead of output; the strict parser refuses it.
        let image = search_image();
        let request = request_with_goal(&["S", "V"], &image);
        let identity = test_identity(&image);
        let worker = worker_output(
            process::WorkerStatus::Complete,
            &test_response(&identity, &["S=\"1010\"V=-7"], Some("exhausted")),
        );
        let outcome = outcome_from_test_worker(&worker, &image, &request);
        assert_eq!(outcome.status, ExecutionStatus::Failed);
        assert!(result_solutions(&outcome).is_empty());
        assert_eq!(
            outcome.reason.as_deref(),
            Some("worker binding frame is malformed or has an unexpected variable")
        );
    }

    #[test]
    fn crossed_request_identity_is_rejected_before_bindings_are_admitted() {
        let image = search_image();
        let request = request_with_goal(&["X"], &image);
        let expected = test_identity(&image);
        let mut crossed = expected.clone();
        crossed.request_digest = "sha256:another-request".to_owned();
        let output = test_response_for_mode(
            &crossed,
            QueryMode::Enumerate,
            &["X=answer"],
            Some("exhausted"),
        );
        let worker = worker_output(process::WorkerStatus::Complete, &output);
        let outcome = outcome_from_worker(&worker, &image, &request, &expected);
        assert_eq!(outcome.status, ExecutionStatus::Failed);
        assert!(!outcome.readback_valid);
        assert!(result_solutions(&outcome).is_empty());
        assert_eq!(
            outcome.reason.as_deref(),
            Some("worker response header is missing or bound to another request")
        );
    }

    #[test]
    fn a_timed_out_worker_without_a_response_keeps_its_timeout_reason() {
        let image = search_image();
        let request = request_with_goal(&["X"], &image);
        let identity = test_identity(&image);
        let mut worker = worker_output(process::WorkerStatus::Timeout, "");
        worker.reason = Some("worker exceeded its wall-clock budget".to_owned());
        let outcome = outcome_from_worker(&worker, &image, &request, &identity);
        assert_eq!(outcome.status, ExecutionStatus::Timeout);
        assert_eq!(outcome.stop, SearchStop::Timeout);
        assert!(!outcome.readback_valid);
        assert!(result_solutions(&outcome).is_empty());
        assert!(
            outcome
                .reason
                .as_deref()
                .is_some_and(|reason| reason.starts_with("worker exceeded its wall-clock budget"))
        );
    }

    #[test]
    fn response_bindings_must_match_the_declared_output_set_exactly() {
        let image = search_image();
        let request = request_with_goal(&["X"], &image);
        let identity = test_identity(&image);
        let worker = worker_output(
            process::WorkerStatus::Complete,
            &test_response(&identity, &["Y=unexpected"], Some("exhausted")),
        );
        let outcome = outcome_from_test_worker(&worker, &image, &request);
        assert_eq!(outcome.status, ExecutionStatus::Failed);
        assert!(!outcome.readback_valid);
        assert!(result_solutions(&outcome).is_empty());
        assert_eq!(
            outcome.reason.as_deref(),
            Some("worker binding frame is malformed or has an unexpected variable")
        );
    }

    #[test]
    fn cancellation_and_timeout_causes_survive_output_limit_observations() {
        let image = search_image();
        let request = request_with_goal(&["X"], &image);
        for (worker_status, expected_status, expected_stop) in [
            (
                process::WorkerStatus::Cancelled,
                ExecutionStatus::Cancelled,
                SearchStop::Cancelled,
            ),
            (
                process::WorkerStatus::Timeout,
                ExecutionStatus::Timeout,
                SearchStop::Timeout,
            ),
        ] {
            let mut worker = worker_output(worker_status, "");
            worker.output_limit_exceeded = true;
            worker.captured_bytes = 1024;
            let outcome = outcome_from_test_worker(&worker, &image, &request);
            assert_eq!(outcome.status, expected_status);
            assert_eq!(outcome.stop, expected_stop);
            assert!(outcome.output_limit_exceeded);
            assert!(!outcome.exhaustive);
            assert!(result_solutions(&outcome).is_empty());
        }
    }

    #[test]
    fn lossy_utf8_output_never_becomes_a_binding() {
        let image = search_image();
        let request = request_with_goal(&["X"], &image);
        let identity = test_identity(&image);
        let output = test_response_for_mode(
            &identity,
            QueryMode::Enumerate,
            &["X=\"replacement-shaped\u{fffd}\""],
            Some("exhausted"),
        );
        let mut worker = worker_output(process::WorkerStatus::Complete, &output);
        worker.output_utf8_valid = false;
        worker.captured_bytes = output.len().saturating_add(1);
        let outcome = outcome_from_test_worker(&worker, &image, &request);
        assert_eq!(outcome.status, ExecutionStatus::Failed);
        assert!(!outcome.readback_valid);
        assert!(result_solutions(&outcome).is_empty());
        assert_eq!(outcome.consumed.output_bytes, worker.captured_bytes);
        assert_eq!(
            outcome.reason.as_deref(),
            Some("worker response is not valid UTF-8 and cannot be admitted losslessly")
        );
    }

    #[test]
    fn protocol_identities_bind_profile_rule_order_variables_and_image_order() {
        let mut image = search_image();
        image.relations = vec![snapshot::SelectedRelation {
            predicate: "member".to_owned(),
            rows: vec![
                snapshot::SelectedRow {
                    values: vec![mneme_core::Value::string("a")],
                    supports: Vec::new(),
                },
                snapshot::SelectedRow {
                    values: vec![mneme_core::Value::string("b")],
                    supports: Vec::new(),
                },
            ],
            coverage: InputCoverage {
                complete: true,
                reason: None,
            },
        }];
        image.seal();
        let mut request = request(std::collections::BTreeSet::from([Feature::PositiveQuery]));
        request.image_digest = image.context.image_digest.clone();
        request.mode = QueryMode::Enumerate;
        request.goal = Atom {
            predicate: "path".to_owned(),
            terms: vec![
                Term::Variable("X".to_owned()),
                Term::Variable("Y".to_owned()),
            ],
        };
        request.variables = vec![
            QueryVariable {
                name: "X".to_owned(),
                role: VariableRole::Output,
            },
            QueryVariable {
                name: "Y".to_owned(),
                role: VariableRole::Output,
            },
        ];
        let metadata = positive();
        let original = request
            .protocol_identity(&metadata, &image)
            .expect("identity");

        let mut reordered_variables = request.clone();
        reordered_variables.variables.reverse();
        let reordered_identity = reordered_variables
            .protocol_identity(&metadata, &image)
            .expect("reordered variable identity");
        assert_ne!(original.request_digest, reordered_identity.request_digest);

        let mut changed_profile = metadata.clone();
        changed_profile.terms.max_depth += 1;
        let changed_profile_identity = request
            .protocol_identity(&changed_profile, &image)
            .expect("profile identity");
        assert_ne!(
            original.profile_digest,
            changed_profile_identity.profile_digest
        );

        let mut changed_rules = request.clone();
        changed_rules.rules = vec![
            Rule {
                id: "first".to_owned(),
                version: "1".to_owned(),
                head: Atom {
                    predicate: "path".to_owned(),
                    terms: vec![Term::String("a".to_owned())],
                },
                body: Vec::new(),
            },
            Rule {
                id: "second".to_owned(),
                version: "1".to_owned(),
                head: Atom {
                    predicate: "path".to_owned(),
                    terms: vec![Term::String("b".to_owned())],
                },
                body: Vec::new(),
            },
        ];
        let ordered = changed_rules
            .protocol_identity(&metadata, &image)
            .expect("ordered rules");
        changed_rules.rules.reverse();
        let reversed = changed_rules
            .protocol_identity(&metadata, &image)
            .expect("reversed rules");
        assert_ne!(ordered.rule_manifest_digest, reversed.rule_manifest_digest);
        assert_ne!(ordered.request_digest, reversed.request_digest);

        let mut changed_image = image.clone();
        changed_image.relations[0].rows.reverse();
        changed_image.seal();
        let mut changed_request = request;
        changed_request.image_digest = changed_image.context.image_digest.clone();
        let changed_order = changed_request
            .protocol_identity(&metadata, &changed_image)
            .expect("changed image order");
        assert_ne!(
            original.input_order_digest,
            changed_order.input_order_digest
        );
        assert_ne!(original.image_digest, changed_order.image_digest);
    }

    #[test]
    fn non_ground_answers_are_reported_rather_than_parsed() {
        let image = search_image();
        let request = request_with_goal(&["S", "V"], &image);
        let identity = test_identity(&image);
        // A valid answer followed by a non-ground one: the whole result is a
        // qualified failure, never a partial success.
        let mut output = test_response(&identity, &["S=\"1010\",V=-7"], None);
        output.push_str(UNBOUND_MARKER);
        output.push('\t');
        output.push_str(&identity.request_digest);
        output.push('\n');
        output.push_str(RESPONSE_STOP_PREFIX);
        output.push('\t');
        output.push_str(&identity.request_digest);
        output.push_str("\texhausted\n");
        let worker = worker_output(process::WorkerStatus::Complete, &output);
        let outcome = outcome_from_test_worker(&worker, &image, &request);
        assert_eq!(outcome.status, ExecutionStatus::Failed);
        assert!(!outcome.exhaustive);
        assert!(result_solutions(&outcome).is_empty());
        assert_eq!(
            outcome.reason.as_deref(),
            Some("worker reported an unbound output candidate")
        );
        assert_eq!(outcome.consumed.solutions, 0);
    }

    fn premise(
        roots: std::collections::BTreeSet<(mneme_core::RecordId, mneme_core::RevisionId)>,
        quoted: bool,
    ) -> Premise {
        Premise {
            record_id: mneme_core::RecordId::from_bytes([0x40; 16]),
            revision_id: mneme_core::RevisionId::from_bytes([0x41; 16]),
            span: quoted.then(|| mneme_core::SourceSpan::new(0, 0).expect("span")),
            derivation: None,
            ancestry_roots: roots,
            availability: PremiseAvailability::Retained,
        }
    }

    #[test]
    fn copied_premises_share_one_independent_root() {
        let root = (
            mneme_core::RecordId::from_bytes([0x20; 16]),
            mneme_core::RevisionId::from_bytes([0x21; 16]),
        );
        let solution = Solution {
            bindings: std::collections::BTreeMap::new(),
            premises: vec![
                premise(std::collections::BTreeSet::from([root]), true),
                premise(std::collections::BTreeSet::from([root]), false),
            ],
            assumptions: std::collections::BTreeSet::new(),
            certification: Certification::Certified,
        };
        assert_eq!(solution.independent_support_count(), 1);
        solution
            .validate(&std::collections::BTreeSet::new())
            .expect("shared ancestry");
    }

    #[test]
    fn certified_solution_needs_a_complete_premise_chain() {
        let empty = Solution {
            bindings: std::collections::BTreeMap::new(),
            premises: Vec::new(),
            assumptions: std::collections::BTreeSet::new(),
            certification: Certification::Certified,
        };
        assert!(empty.validate(&std::collections::BTreeSet::new()).is_err());
        let root = (
            mneme_core::RecordId::from_bytes([0x20; 16]),
            mneme_core::RevisionId::from_bytes([0x21; 16]),
        );
        let complete = Solution {
            bindings: std::collections::BTreeMap::new(),
            premises: vec![premise(std::collections::BTreeSet::from([root]), false)],
            assumptions: std::collections::BTreeSet::new(),
            certification: Certification::Certified,
        };
        assert!(
            complete
                .validate(&std::collections::BTreeSet::new())
                .is_ok()
        );
    }

    #[test]
    fn hypothetical_assumptions_remain_uncertified_and_must_be_declared() {
        let root = (
            mneme_core::RecordId::from_bytes([0x20; 16]),
            mneme_core::RevisionId::from_bytes([0x21; 16]),
        );
        let mut solution = Solution {
            bindings: std::collections::BTreeMap::new(),
            premises: vec![premise(std::collections::BTreeSet::from([root]), false)],
            assumptions: std::collections::BTreeSet::from(["assumption-1".to_owned()]),
            certification: Certification::Certified,
        };
        assert!(
            solution
                .validate(&std::collections::BTreeSet::from([
                    "assumption-1".to_owned()
                ]))
                .is_err()
        );
        solution.certification = Certification::Uncertified {
            reason: "hypothetical dependency".to_owned(),
        };
        assert!(
            solution
                .validate(&std::collections::BTreeSet::from([
                    "assumption-1".to_owned()
                ]))
                .is_ok()
        );
        assert!(
            solution
                .validate(&std::collections::BTreeSet::new())
                .is_err()
        );
    }

    #[test]
    fn pruned_premises_disclose_unavailable_bytes_without_quotes() {
        let root = (
            mneme_core::RecordId::from_bytes([0x20; 16]),
            mneme_core::RevisionId::from_bytes([0x21; 16]),
        );
        let mut pruned = premise(std::collections::BTreeSet::from([root]), false);
        pruned.availability = PremiseAvailability::Pruned {
            reason: "source bytes pruned".to_owned(),
        };
        let solution = Solution {
            bindings: std::collections::BTreeMap::new(),
            premises: vec![pruned],
            assumptions: std::collections::BTreeSet::new(),
            certification: Certification::Certified,
        };
        assert_eq!(solution.unavailable_premises().len(), 1);
        assert!(
            solution
                .validate(&std::collections::BTreeSet::new())
                .is_ok()
        );
        let mut quoted = solution;
        quoted.premises[0].span = Some(mneme_core::SourceSpan::new(0, 0).expect("span"));
        assert!(quoted.validate(&std::collections::BTreeSet::new()).is_err());
    }

    #[test]
    fn uncertified_fallback_requires_a_reason() {
        let solution = Solution {
            bindings: std::collections::BTreeMap::new(),
            premises: Vec::new(),
            assumptions: std::collections::BTreeSet::new(),
            certification: Certification::Uncertified {
                reason: "engine did not provide proof".to_owned(),
            },
        };
        assert!(
            solution
                .validate(&std::collections::BTreeSet::new())
                .is_ok()
        );
        let mut missing = solution;
        missing.certification = Certification::Uncertified {
            reason: String::new(),
        };
        assert!(
            missing
                .validate(&std::collections::BTreeSet::new())
                .is_err()
        );
    }

    #[test]
    fn guarded_negation_and_aggregation_are_disabled() {
        let mut metadata = positive();
        metadata.features.insert(Feature::GuardedNegation);
        assert!(metadata.validate().is_err());
        let mut request = request(std::collections::BTreeSet::from([Feature::PositiveQuery]));
        request.features.insert(Feature::Aggregation);
        assert_eq!(
            positive().ensure_request(&request),
            Err(CapabilityError::UnsupportedFeature(Feature::Aggregation))
        );
    }

    #[test]
    fn incomplete_or_pruned_conditions_never_establish_negative() {
        let complete = NegativeConditions {
            relation_complete: true,
            subgoal_completed: true,
            subgoal_ground: true,
            source_pruned: false,
            within_limits: true,
        };
        assert_eq!(
            evaluate_negative_guard(complete),
            NegativeConclusion::Established
        );
        for conditions in [
            NegativeConditions {
                relation_complete: false,
                ..complete
            },
            NegativeConditions {
                subgoal_completed: false,
                ..complete
            },
            NegativeConditions {
                subgoal_ground: false,
                ..complete
            },
            NegativeConditions {
                source_pruned: true,
                ..complete
            },
            NegativeConditions {
                within_limits: false,
                ..complete
            },
        ] {
            assert!(matches!(
                evaluate_negative_guard(conditions),
                NegativeConclusion::Unknown { .. }
            ));
        }
    }

    #[test]
    fn negative_guard_agrees_with_the_kernel_rule() {
        // Every condition maps onto one kernel fact, so the local answer and
        // the shared proved rule can never disagree.
        for relation_complete in [false, true] {
            for subgoal_completed in [false, true] {
                for subgoal_ground in [false, true] {
                    for source_pruned in [false, true] {
                        for within_limits in [false, true] {
                            let conditions = NegativeConditions {
                                relation_complete,
                                subgoal_completed,
                                subgoal_ground,
                                source_pruned,
                                within_limits,
                            };
                            let is_expected = relation_complete
                                && subgoal_completed
                                && subgoal_ground
                                && !source_pruned
                                && within_limits;
                            let is_established = matches!(
                                evaluate_negative_guard(conditions),
                                NegativeConclusion::Established
                            );
                            assert_eq!(is_established, is_expected);
                        }
                    }
                }
            }
        }
    }
}
