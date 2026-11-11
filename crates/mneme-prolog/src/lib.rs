//! Engine-neutral contracts for optional, bounded Prolog reasoning.
//!
//! This crate carries capability metadata, finite request terms, qualified
//! results, conditional premises, and reviewable plan/fact proposals. It does
//! not invoke an engine. The capability starts disabled; ordinary memory
//! operations do not depend on this crate.

#![cfg_attr(test, allow(clippy::expect_used))]

pub mod image;
pub mod worker;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use mneme_core::{RecordId, RevisionId, ScopeId, SourceSpan, WorkspaceRevisionId};

/// Required feature names for a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Feature {
    PositiveQuery,
    HypotheticalAssumptions,
    Plans,
    GuardedNegation,
    CertifiedProofs,
}

impl Feature {
    pub const fn name(self) -> &'static str {
        match self {
            Feature::PositiveQuery => "positive-query",
            Feature::HypotheticalAssumptions => "hypothetical-assumptions",
            Feature::Plans => "plans",
            Feature::GuardedNegation => "guarded-negation",
            Feature::CertifiedProofs => "certified-proofs",
        }
    }
}

impl fmt::Display for Feature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
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
    pub features: BTreeSet<Feature>,
    pub allowed_predicates: BTreeSet<String>,
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
            features: BTreeSet::new(),
            allowed_predicates: BTreeSet::new(),
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
            CapabilityState::Disabled { reason } => {
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
            }
            CapabilityState::Enabled => {
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
            }
        }
        Ok(())
    }

    /// Check that a request is advertised and within the profile.
    pub fn ensure_request(&self, request: &PrologRequest) -> Result<(), CapabilityError> {
        if let CapabilityState::Disabled { reason } = &self.state {
            return Err(CapabilityError::Unavailable {
                reason: reason.clone(),
            });
        }
        for feature in &request.features {
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
        self.ensure_predicate(&request.goal.predicate)?;
        for rule in &request.rules {
            self.ensure_predicate(&rule.head.predicate)?;
            for literal in &rule.body {
                match literal {
                    Literal::Positive(atom) | Literal::Negative(atom) => {
                        self.ensure_predicate(&atom.predicate)?;
                    }
                }
            }
        }
        request.validate_terms(self.terms)
    }

    fn ensure_predicate(&self, predicate: &str) -> Result<(), CapabilityError> {
        if is_forbidden_predicate(predicate) || !self.allowed_predicates.contains(predicate) {
            return Err(CapabilityError::DisallowedPredicate(predicate.to_owned()));
        }
        Ok(())
    }
}

/// Predicates that must never enter the bounded positive profile.
pub fn is_forbidden_predicate(predicate: &str) -> bool {
    matches!(
        predicate,
        "open"
            | "close"
            | "read"
            | "write"
            | "shell"
            | "process"
            | "network"
            | "socket"
            | "consult"
            | "use_module"
            | "load_files"
            | "initialization"
            | "op"
            | "assert"
            | "asserta"
            | "assertz"
            | "retract"
            | "retractall"
            | "abolish"
            | "call"
            | "catch"
            | "throw"
            | "set_prolog_flag"
            | "nb_setval"
            | "b_setval"
            | "database"
            | "file"
            | "import"
    )
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
        record_id: RecordId,
        revision_id: Option<RevisionId>,
    },
    List(Vec<Term>),
    Compound {
        functor: String,
        args: Vec<Term>,
    },
}

impl Term {
    fn depth(&self) -> usize {
        match self {
            Term::List(items) => 1 + items.iter().map(Term::depth).max().unwrap_or(0),
            Term::Compound { args, .. } => 1 + args.iter().map(Term::depth).max().unwrap_or(0),
            _ => 1,
        }
    }

    fn check(&self, profile: TermProfile) -> Result<(), CapabilityError> {
        match self {
            Term::Variable(_) => {
                return Err(CapabilityError::InvalidRequest(
                    "variables are not valid input terms".to_owned(),
                ));
            }
            Term::List(items) => {
                if items.len() > profile.max_collection {
                    return Err(CapabilityError::LimitExceeded(
                        "list exceeds the term collection limit".to_owned(),
                    ));
                }
                for item in items {
                    item.check(profile)?;
                }
            }
            Term::Compound { args, .. } => {
                if args.len() > profile.max_collection {
                    return Err(CapabilityError::LimitExceeded(
                        "compound term exceeds the argument limit".to_owned(),
                    ));
                }
                for arg in args {
                    arg.check(profile)?;
                }
            }
            Term::Reference { .. } if !profile.references_allowed => {
                return Err(CapabilityError::InvalidRequest(
                    "record references are not allowed by this profile".to_owned(),
                ));
            }
            Term::Integer(_) | Term::String(_) | Term::Symbol(_) | Term::Reference { .. } => {}
        }
        if self.depth() > profile.max_depth {
            return Err(CapabilityError::LimitExceeded(
                "term exceeds the depth profile".to_owned(),
            ));
        }
        Ok(())
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
        if self.predicate.trim().is_empty() {
            return Err(CapabilityError::InvalidRequest(
                "predicate name is required".to_owned(),
            ));
        }
        if self.terms.len() > profile.max_collection {
            return Err(CapabilityError::LimitExceeded(
                "atom arity exceeds the term profile".to_owned(),
            ));
        }
        for term in &self.terms {
            term.check(profile)?;
        }
        Ok(())
    }
}

/// A rule body literal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Literal {
    Positive(Atom),
    Negative(Atom),
}

/// One allowlisted rule. Rules are data; no engine registration is implied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrologRule {
    pub id: String,
    pub version: String,
    pub head: Atom,
    pub body: Vec<Literal>,
}

/// A request-local hypothetical assumption.
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

/// Engine-neutral query request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrologRequest {
    pub actor: String,
    pub scope: ScopeId,
    pub revision: WorkspaceRevisionId,
    pub eligibility_generation: u64,
    pub image_digest: String,
    pub goal: Atom,
    pub rules: Vec<PrologRule>,
    pub assumptions: Vec<Assumption>,
    pub features: BTreeSet<Feature>,
    pub limits: RequestLimits,
}

impl PrologRequest {
    fn validate_terms(&self, profile: TermProfile) -> Result<(), CapabilityError> {
        if self.actor.trim().is_empty() || self.image_digest.trim().is_empty() {
            return Err(CapabilityError::InvalidRequest(
                "actor and image digest are required".to_owned(),
            ));
        }
        self.goal.check(profile)?;
        for rule in &self.rules {
            if rule.id.trim().is_empty() || rule.version.trim().is_empty() {
                return Err(CapabilityError::InvalidRequest(
                    "rule identity and version are required".to_owned(),
                ));
            }
            rule.head.check(profile)?;
            for literal in &rule.body {
                match literal {
                    Literal::Positive(atom) => atom.check(profile)?,
                    Literal::Negative(atom) => {
                        atom.check(profile)?;
                        if !self.features.contains(&Feature::GuardedNegation) {
                            return Err(CapabilityError::InvalidRequest(
                                "negative literal requires guarded-negation".to_owned(),
                            ));
                        }
                    }
                }
            }
        }
        for assumption in &self.assumptions {
            if assumption.id.trim().is_empty() || assumption.rationale.trim().is_empty() {
                return Err(CapabilityError::InvalidRequest(
                    "assumption identity and rationale are required".to_owned(),
                ));
            }
            assumption.atom.check(profile)?;
            if !self.features.contains(&Feature::HypotheticalAssumptions) {
                return Err(CapabilityError::InvalidRequest(
                    "assumptions require hypothetical-assumptions".to_owned(),
                ));
            }
        }
        Ok(())
    }
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
    pub revision: WorkspaceRevisionId,
    pub scope: ScopeId,
    pub eligibility_generation: u64,
    pub image_digest: String,
    pub profile: String,
    pub rule_versions: BTreeMap<String, String>,
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
    pub record_id: RecordId,
    pub revision_id: RevisionId,
    pub span: Option<SourceSpan>,
    pub derivation: Option<RecordId>,
    pub ancestry_roots: BTreeSet<(RecordId, RevisionId)>,
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
    pub bindings: BTreeMap<String, Term>,
    pub premises: Vec<Premise>,
    pub assumptions: BTreeSet<String>,
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
    pub parameters: BTreeMap<String, Term>,
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
    pub actions: Vec<PlanAction>,
    pub preconditions: Vec<Precondition>,
    pub assumptions: BTreeSet<String>,
    pub evidence: Vec<Premise>,
    pub expected_effects: Vec<String>,
}

/// A proposed ordinary fact/record change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactChangeProposal {
    pub id: String,
    pub operation: String,
    pub target: Option<RecordId>,
    pub evidence: Vec<Premise>,
    pub assumptions: BTreeSet<String>,
}

/// A reviewable output from search.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrologProposal {
    Plan(PlanProposal),
    FactChange(FactChangeProposal),
}

/// Bounded result envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrologResult {
    pub status: ExecutionStatus,
    pub exhaustive: bool,
    pub coverage: InputCoverage,
    pub context: SearchContext,
    pub solutions: Vec<Solution>,
    pub proposals: Vec<PrologProposal>,
    pub consumed: ConsumedLimits,
    pub reason: Option<String>,
}

impl PrologResult {
    /// A disabled capability result.
    pub fn disabled(reason: impl Into<String>, context: SearchContext) -> Self {
        PrologResult {
            status: ExecutionStatus::Disabled,
            exhaustive: false,
            coverage: InputCoverage {
                complete: false,
                reason: Some("Prolog is disabled".to_owned()),
            },
            context,
            solutions: Vec::new(),
            proposals: Vec::new(),
            consumed: ConsumedLimits {
                elapsed_ms: 0,
                solutions: 0,
                output_bytes: 0,
            },
            reason: Some(reason.into()),
        }
    }

    /// Validate that non-complete searches cannot claim exhaustiveness.
    pub fn validate(&self) -> Result<(), CapabilityError> {
        if self.status != ExecutionStatus::Complete && self.exhaustive {
            return Err(CapabilityError::InvalidRequest(
                "non-complete search cannot be exhaustive".to_owned(),
            ));
        }
        if self.consumed.solutions < self.solutions.len() {
            return Err(CapabilityError::InvalidRequest(
                "consumed solution count is smaller than the result set".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Encode one finite term into the restricted engine syntax.
pub fn encode_term(
    term: &Term,
    profile: TermProfile,
    max_bytes: usize,
) -> Result<String, CapabilityError> {
    term.check(profile)?;
    let encoded = encode_term_inner(term);
    if encoded.len() > max_bytes {
        return Err(CapabilityError::LimitExceeded(
            "encoded term exceeds the output budget".to_owned(),
        ));
    }
    Ok(encoded)
}

/// Encode one atom after finite-term validation.
pub fn encode_atom(
    atom: &Atom,
    profile: TermProfile,
    max_bytes: usize,
) -> Result<String, CapabilityError> {
    atom.check(profile)?;
    let mut output = atom.predicate.clone();
    output.push('(');
    for (index, term) in atom.terms.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str(&encode_term_inner(term));
    }
    output.push(')');
    if output.len() > max_bytes {
        return Err(CapabilityError::LimitExceeded(
            "encoded atom exceeds the output budget".to_owned(),
        ));
    }
    Ok(output)
}

/// Serialize finite solution bindings under an output-byte budget.
pub fn serialize_solution(
    solution: &Solution,
    profile: TermProfile,
    max_bytes: usize,
) -> Result<String, CapabilityError> {
    let mut output = String::new();
    for (index, (name, term)) in solution.bindings.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str(name);
        output.push('=');
        output.push_str(&encode_term_inner(term));
        if output.len() > max_bytes {
            return Err(CapabilityError::LimitExceeded(
                "serialized solution exceeds the output budget".to_owned(),
            ));
        }
    }
    for term in solution.bindings.values() {
        term.check(profile)?;
    }
    Ok(output)
}

fn encode_term_inner(term: &Term) -> String {
    match term {
        Term::Integer(value) => value.to_string(),
        Term::String(value) => format!("\"{}\"", escape_string(value)),
        Term::Symbol(value) => value.clone(),
        Term::Variable(value) => value.clone(),
        Term::Reference {
            record_id,
            revision_id,
        } => format!(
            "ref({},{})",
            record_id.to_hex(),
            revision_id.map_or_else(|| "current".to_owned(), RevisionId::to_hex)
        ),
        Term::List(items) => format!(
            "[{}]",
            items
                .iter()
                .map(encode_term_inner)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Term::Compound { functor, args } => format!(
            "{}({})",
            functor,
            args.iter()
                .map(encode_term_inner)
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

fn escape_string(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

impl Solution {
    /// Distinct ancestry roots, not the number of duplicated summaries.
    pub fn independent_support_count(&self) -> usize {
        self.premises
            .iter()
            .flat_map(|premise| premise.ancestry_roots.iter().copied())
            .collect::<BTreeSet<_>>()
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
    pub fn validate(&self, declared_assumptions: &BTreeSet<String>) -> Result<(), CapabilityError> {
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

impl PrologResult {
    /// Validate this result against the request that produced it, including
    /// context, premise chains, pruning disclosure, and assumptions.
    pub fn validate_for_request(&self, request: &PrologRequest) -> Result<(), CapabilityError> {
        self.validate()?;
        if self.context.revision != request.revision
            || self.context.scope != request.scope
            || self.context.eligibility_generation != request.eligibility_generation
            || self.context.image_digest != request.image_digest
        {
            return Err(CapabilityError::InvalidRequest(
                "result context differs from its request".to_owned(),
            ));
        }
        let declared = request
            .assumptions
            .iter()
            .map(|assumption| assumption.id.clone())
            .collect::<BTreeSet<_>>();
        for solution in &self.solutions {
            solution.validate(&declared)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mneme_core::ScopeClass;

    fn scope() -> ScopeId {
        ScopeId::new(ScopeClass::Project, "cedar").expect("scope")
    }

    fn revision() -> WorkspaceRevisionId {
        WorkspaceRevisionId::from_bytes([0xb0; 16])
    }

    fn request(features: BTreeSet<Feature>) -> PrologRequest {
        PrologRequest {
            actor: "agent".to_owned(),
            scope: scope(),
            revision: revision(),
            eligibility_generation: 1,
            image_digest: "sha256:image".to_owned(),
            goal: Atom {
                predicate: "path".to_owned(),
                terms: vec![Term::String("a".to_owned())],
            },
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

    fn enabled(features: BTreeSet<Feature>) -> CapabilityMetadata {
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
            allowed_predicates: BTreeSet::from(["path".to_owned(), "member".to_owned()]),
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

    #[test]
    fn disabled_capability_is_explicit_and_unavailable() {
        let metadata = CapabilityMetadata::disabled("engine not enabled");
        metadata.validate().expect("disabled metadata");
        assert!(matches!(
            metadata.ensure_request(&request(BTreeSet::new())),
            Err(CapabilityError::Unavailable { .. })
        ));
    }

    #[test]
    fn enabled_metadata_requires_engine_and_limits() {
        let mut metadata = enabled(BTreeSet::from([Feature::PositiveQuery]));
        metadata.engine = None;
        assert!(metadata.validate().is_err());
        let mut metadata = enabled(BTreeSet::from([Feature::PositiveQuery]));
        metadata.limits.max_solutions = 0;
        assert!(metadata.validate().is_err());
    }

    #[test]
    fn unadvertised_features_are_refused() {
        let metadata = enabled(BTreeSet::from([Feature::PositiveQuery]));
        let mut request = request(BTreeSet::from([Feature::PositiveQuery]));
        assert!(metadata.ensure_request(&request).is_ok());
        request.features.insert(Feature::Plans);
        assert_eq!(
            metadata.ensure_request(&request),
            Err(CapabilityError::UnsupportedFeature(Feature::Plans))
        );
    }

    #[test]
    fn finite_terms_reject_depth_violations() {
        let metadata = enabled(BTreeSet::from([Feature::PositiveQuery]));
        let mut request = request(BTreeSet::from([Feature::PositiveQuery]));
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
            rule_versions: BTreeMap::new(),
        };
        let mut result = PrologResult::disabled("disabled", context);
        assert!(!result.exhaustive);
        assert!(result.validate().is_ok());
        result.status = ExecutionStatus::Timeout;
        result.exhaustive = true;
        assert!(result.validate().is_err());
    }

    #[test]
    fn disabled_capability_leaves_baseline_workspace_usable() {
        use mneme_store::{Workspace, WorkspaceConfig};
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace =
            Workspace::create(temp.path(), WorkspaceConfig::default()).expect("workspace");
        let before = workspace.status().expect("baseline status");
        let metadata = CapabilityMetadata::disabled("Prolog disabled");
        assert!(metadata.ensure_request(&request(BTreeSet::new())).is_err());
        let after = workspace
            .status()
            .expect("baseline status after Prolog refusal");
        assert_eq!(before.sequence, after.sequence);
        assert!(workspace.snapshot().is_ok());
    }

    #[test]
    fn effectful_and_unadvertised_predicates_are_refused() {
        let metadata = enabled(BTreeSet::from([Feature::PositiveQuery]));
        let mut request = request(BTreeSet::from([Feature::PositiveQuery]));
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
            bindings: BTreeMap::from([("X".to_owned(), Term::Integer(42))]),
            premises: Vec::new(),
            assumptions: BTreeSet::new(),
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
    }

    fn premise(roots: BTreeSet<(RecordId, RevisionId)>, quoted: bool) -> Premise {
        Premise {
            record_id: RecordId::from_bytes([0x40; 16]),
            revision_id: RevisionId::from_bytes([0x41; 16]),
            span: quoted.then(|| SourceSpan::new(0, 0).expect("span")),
            derivation: None,
            ancestry_roots: roots,
            availability: PremiseAvailability::Retained,
        }
    }

    #[test]
    fn copied_premises_share_one_independent_root() {
        let root = (
            RecordId::from_bytes([0x20; 16]),
            RevisionId::from_bytes([0x21; 16]),
        );
        let solution = Solution {
            bindings: BTreeMap::new(),
            premises: vec![
                premise(BTreeSet::from([root]), true),
                premise(BTreeSet::from([root]), false),
            ],
            assumptions: BTreeSet::new(),
            certification: Certification::Certified,
        };
        assert_eq!(solution.independent_support_count(), 1);
        solution
            .validate(&BTreeSet::new())
            .expect("shared ancestry");
    }

    #[test]
    fn certified_solution_needs_a_complete_premise_chain() {
        let empty = Solution {
            bindings: BTreeMap::new(),
            premises: Vec::new(),
            assumptions: BTreeSet::new(),
            certification: Certification::Certified,
        };
        assert!(empty.validate(&BTreeSet::new()).is_err());
        let root = (
            RecordId::from_bytes([0x20; 16]),
            RevisionId::from_bytes([0x21; 16]),
        );
        let complete = Solution {
            bindings: BTreeMap::new(),
            premises: vec![premise(BTreeSet::from([root]), false)],
            assumptions: BTreeSet::new(),
            certification: Certification::Certified,
        };
        assert!(complete.validate(&BTreeSet::new()).is_ok());
    }

    #[test]
    fn hypothetical_assumptions_remain_uncertified_and_must_be_declared() {
        let root = (
            RecordId::from_bytes([0x20; 16]),
            RevisionId::from_bytes([0x21; 16]),
        );
        let mut solution = Solution {
            bindings: BTreeMap::new(),
            premises: vec![premise(BTreeSet::from([root]), false)],
            assumptions: BTreeSet::from(["assumption-1".to_owned()]),
            certification: Certification::Certified,
        };
        assert!(
            solution
                .validate(&BTreeSet::from(["assumption-1".to_owned()]))
                .is_err()
        );
        solution.certification = Certification::Uncertified {
            reason: "hypothetical dependency".to_owned(),
        };
        assert!(
            solution
                .validate(&BTreeSet::from(["assumption-1".to_owned()]))
                .is_ok()
        );
        assert!(solution.validate(&BTreeSet::new()).is_err());
    }

    #[test]
    fn pruned_premises_disclose_unavailable_bytes_without_quotes() {
        let root = (
            RecordId::from_bytes([0x20; 16]),
            RevisionId::from_bytes([0x21; 16]),
        );
        let mut pruned = premise(BTreeSet::from([root]), false);
        pruned.availability = PremiseAvailability::Pruned {
            reason: "source bytes pruned".to_owned(),
        };
        let solution = Solution {
            bindings: BTreeMap::new(),
            premises: vec![pruned],
            assumptions: BTreeSet::new(),
            certification: Certification::Certified,
        };
        assert_eq!(solution.unavailable_premises().len(), 1);
        assert!(solution.validate(&BTreeSet::new()).is_ok());
        let mut quoted = solution;
        quoted.premises[0].span = Some(SourceSpan::new(0, 0).expect("span"));
        assert!(quoted.validate(&BTreeSet::new()).is_err());
    }

    #[test]
    fn uncertified_fallback_requires_a_reason() {
        let solution = Solution {
            bindings: BTreeMap::new(),
            premises: Vec::new(),
            assumptions: BTreeSet::new(),
            certification: Certification::Uncertified {
                reason: "engine did not provide proof".to_owned(),
            },
        };
        assert!(solution.validate(&BTreeSet::new()).is_ok());
        let mut missing = solution;
        missing.certification = Certification::Uncertified {
            reason: String::new(),
        };
        assert!(missing.validate(&BTreeSet::new()).is_err());
    }
}
