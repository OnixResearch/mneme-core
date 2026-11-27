//! Host-side certified proof trees and independent verification for bounded Prolog.
//!
//! When a request activates [`crate::Feature::CertifiedProofs`], the isolated
//! Prolog worker returns an explicit proof term alongside each binding row.
//! The worker is untrusted: this module parses the proof term iteratively and
//! independently re-verifies every rule step and leaf against the sealed
//! [`crate::snapshot::InputImage`] and [`crate::Request`] using Robinson
//! unification with occurs check before marking a [`crate::Solution`] as
//! [`crate::Certification::Certified`].

const MAX_DEPTH: usize = 64;
const MAX_NODES: usize = 4_096;
const MAX_UNIFY_STEPS: usize = 16_384;

/// Leaf of a certified Prolog derivation tree, referencing one exact sealed input item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Leaf {
    /// Index into [`crate::snapshot::InputImage::canonical`] (`assertion/3`).
    Canonical { index: u64 },
    /// Indices into [`crate::snapshot::InputImage::relations`] and its rows (`relation/2`, `Accepted` only).
    Relation { relation_index: u64, row_index: u64 },
    /// Indices into [`crate::snapshot::InputImage::relations`] and its rows (`relation_epistemic/3`).
    RelationEpistemic { relation_index: u64, row_index: u64 },
    /// Index into [`crate::Request::assumptions`] (cannot be certified).
    Assumption { index: u64 },
}

/// One node in a finite Prolog proof tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    Leaf(Leaf),
    RuleStep {
        rule_index: u64,
        children: Vec<Node>,
    },
}

/// Content-addressed proof certificate attached to a solution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    /// Content digest (`sha256:...`) over the canonical representation of `root`.
    pub digest: String,
    /// Verified proof tree rooted at the request goal.
    pub root: Node,
    /// Combined epistemic status propagated across all verified leaves (`min`).
    pub epistemic: mneme_datalog::EpistemicStatus,
}

impl Certificate {
    /// Construct a sealed certificate from a parsed proof tree and verified epistemic status.
    pub fn seal(root: Node, epistemic: mneme_datalog::EpistemicStatus) -> Self {
        let digest = compute_digest(&root);
        Self {
            digest,
            root,
            epistemic,
        }
    }
}

/// Output of host-side proof certificate verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub premises: Vec<crate::Premise>,
    pub assumptions: std::collections::BTreeSet<String>,
    pub epistemic: mneme_datalog::EpistemicStatus,
    pub certificate: Certificate,
    /// When `Some`, the proof is structurally valid against the image/request
    /// but cannot be certified (e.g. relies on assumptions or truncated supports).
    pub uncertified_reason: Option<String>,
}

/// Compute the deterministic `sha256:` content digest of a [`Node`] iteratively.
pub fn compute_digest(root: &Node) -> String {
    let value = node_to_value(root);
    format!(
        "sha256:{}",
        mneme_core::ContentDigest::of_payload(&value).to_hex()
    )
}

enum ValueBuildStep<'a> {
    Enter(&'a Node),
    FinishRule { rule_index: u64, child_count: usize },
}

fn node_to_value(root: &Node) -> mneme_core::Value {
    let mut work = Vec::with_capacity(16);
    work.push(ValueBuildStep::Enter(root));
    let mut results: Vec<mneme_core::Value> = Vec::with_capacity(16);
    while let Some(step) = work.pop() {
        if let ValueBuildStep::Enter(node) = step {
            if let Node::Leaf(leaf) = node {
                results.push(leaf_to_value(leaf));
            } else if let Node::RuleStep {
                rule_index,
                children,
            } = node
            {
                work.push(ValueBuildStep::FinishRule {
                    rule_index: *rule_index,
                    child_count: children.len(),
                });
                work.reserve(children.len());
                for child in children.iter().rev() {
                    work.push(ValueBuildStep::Enter(child));
                }
            }
        } else if let ValueBuildStep::FinishRule {
            rule_index,
            child_count,
        } = step
        {
            let start = results.len().saturating_sub(child_count);
            let child_vals = results.split_off(start);
            results.push(mneme_core::Value::record_named(
                "proof-step",
                vec![
                    mneme_core::Value::integer(rule_index),
                    mneme_core::Value::sequence(child_vals),
                ],
            ));
        }
    }
    results
        .pop()
        .unwrap_or_else(|| mneme_core::Value::symbol("invalid-proof"))
}

fn leaf_to_value(leaf: &Leaf) -> mneme_core::Value {
    if let Leaf::Canonical { index } = leaf {
        return mneme_core::Value::record_named(
            "proof-leaf-canonical",
            vec![mneme_core::Value::integer(*index)],
        );
    }
    if let Leaf::Relation {
        relation_index,
        row_index,
    } = leaf
    {
        return mneme_core::Value::record_named(
            "proof-leaf-relation",
            vec![
                mneme_core::Value::integer(*relation_index),
                mneme_core::Value::integer(*row_index),
            ],
        );
    }
    if let Leaf::RelationEpistemic {
        relation_index,
        row_index,
    } = leaf
    {
        return mneme_core::Value::record_named(
            "proof-leaf-relation-epistemic",
            vec![
                mneme_core::Value::integer(*relation_index),
                mneme_core::Value::integer(*row_index),
            ],
        );
    }
    if let Leaf::Assumption { index } = leaf {
        return mneme_core::Value::record_named(
            "proof-leaf-assumption",
            vec![mneme_core::Value::integer(*index)],
        );
    }
    mneme_core::Value::symbol("invalid-leaf")
}

/// Parse one serialized proof term (`mneme_leaf(...)` / `mneme_step(R, [...])`) iteratively.
pub fn parse_node(text: &str) -> Result<Node, crate::CapabilityError> {
    let mut parser = TermTreeParser {
        bytes: text.as_bytes(),
        index: 0,
        nodes_parsed: 0,
    };
    let node = parser.parse_root()?;
    if parser.index != parser.bytes.len() {
        return Err(err_invalid("trailing bytes after proof term"));
    }
    Ok(node)
}

/// Parse a serialized proof frame from the worker and verify it against the sealed image.
pub fn verify_term(
    proof_text: &str,
    bindings: &std::collections::BTreeMap<String, crate::Term>,
    request: &crate::Request,
    image: &crate::snapshot::InputImage,
) -> Result<Verified, crate::CapabilityError> {
    let root = parse_node(proof_text)?;
    verify_node(&root, bindings, request, image)
}

/// Independently verify a [`Certificate`] against `request`, `bindings`, and `image`.
pub fn verify_certificate(
    certificate: &Certificate,
    bindings: &std::collections::BTreeMap<String, crate::Term>,
    request: &crate::Request,
    image: &crate::snapshot::InputImage,
) -> Result<Verified, crate::CapabilityError> {
    let expected_digest = compute_digest(&certificate.root);
    if certificate.digest != expected_digest {
        return Err(err_invalid(
            "proof certificate digest does not match its proof tree",
        ));
    }
    let verified = verify_node(&certificate.root, bindings, request, image)?;
    if certificate.epistemic != verified.epistemic {
        return Err(err_invalid(
            "proof certificate epistemic status does not match verified leaves",
        ));
    }
    Ok(verified)
}

// ---------------------------------------------------------------------------
// Iterative Proof Term Parser
// ---------------------------------------------------------------------------

struct TermTreeParser<'a> {
    bytes: &'a [u8],
    index: usize,
    nodes_parsed: usize,
}

enum ParseFrame {
    StepChildren {
        rule_index: u64,
        children: Vec<Node>,
    },
}

impl ParseFrame {
    fn step_children(rule_index: u64) -> Self {
        Self::StepChildren {
            rule_index,
            children: Vec::with_capacity(4),
        }
    }
}

impl<'a> TermTreeParser<'a> {
    fn parse_root(&mut self) -> Result<Node, crate::CapabilityError> {
        let mut frames: Vec<ParseFrame> = Vec::with_capacity(MAX_DEPTH.min(16));
        loop {
            if frames.len() > MAX_DEPTH {
                return Err(err_invalid("proof tree exceeds maximum depth"));
            }
            let ident = self.read_ident()?;
            if ident == "mneme_leaf" {
                let leaf = self.parse_leaf_args()?;
                let node = Node::Leaf(leaf);
                if let Some(finished) = self.attach_node(&mut frames, node)? {
                    return Ok(finished);
                }
            } else if ident == "mneme_step" {
                self.bump_node_count()?;
                self.expect_byte(b'(')?;
                let rule_index = self.read_u64()?;
                self.expect_byte(b',')?;
                self.expect_byte(b'[')?;
                if self.peek() == Some(b']') {
                    self.index = self.index.saturating_add(1);
                    self.expect_byte(b')')?;
                    let node = Node::RuleStep {
                        rule_index,
                        children: Vec::new(),
                    };
                    if let Some(finished) = self.attach_node(&mut frames, node)? {
                        return Ok(finished);
                    }
                } else {
                    frames.push(ParseFrame::step_children(rule_index));
                }
            } else {
                return Err(err_invalid("unknown proof node functor"));
            }
        }
    }

    fn attach_node(
        &mut self,
        frames: &mut Vec<ParseFrame>,
        mut node: Node,
    ) -> Result<Option<Node>, crate::CapabilityError> {
        loop {
            let Some(ParseFrame::StepChildren {
                rule_index,
                children,
            }) = frames.last_mut()
            else {
                return Ok(Some(node));
            };
            children.push(node);
            match self.peek() {
                Some(b',') => {
                    self.index = self.index.saturating_add(1);
                    return Ok(None);
                }
                Some(b']') => {
                    self.index = self.index.saturating_add(1);
                    self.expect_byte(b')')?;
                    let finished_rule = *rule_index;
                    let finished_children = std::mem::take(children);
                    frames.pop();
                    node = Node::RuleStep {
                        rule_index: finished_rule,
                        children: finished_children,
                    };
                }
                Some(_) | None => return Err(err_invalid("malformed proof step child list")),
            }
        }
    }

    fn parse_leaf_args(&mut self) -> Result<Leaf, crate::CapabilityError> {
        self.bump_node_count()?;
        self.expect_byte(b'(')?;
        let kind = self.read_ident()?;
        self.expect_byte(b',')?;
        let leaf = match kind.as_str() {
            "canonical" => Leaf::Canonical {
                index: self.read_u64()?,
            },
            "assumption" => Leaf::Assumption {
                index: self.read_u64()?,
            },
            "relation" => {
                let relation_index = self.read_u64()?;
                self.expect_byte(b',')?;
                let row_index = self.read_u64()?;
                Leaf::Relation {
                    relation_index,
                    row_index,
                }
            }
            "relation_epistemic" => {
                let relation_index = self.read_u64()?;
                self.expect_byte(b',')?;
                let row_index = self.read_u64()?;
                Leaf::RelationEpistemic {
                    relation_index,
                    row_index,
                }
            }
            _ => return Err(err_invalid("unknown proof leaf kind")),
        };
        self.expect_byte(b')')?;
        Ok(leaf)
    }

    fn bump_node_count(&mut self) -> Result<(), crate::CapabilityError> {
        self.nodes_parsed = self.nodes_parsed.saturating_add(1);
        if self.nodes_parsed > MAX_NODES {
            return Err(err_invalid("proof tree exceeds maximum node count"));
        }
        Ok(())
    }

    fn read_ident(&mut self) -> Result<String, crate::CapabilityError> {
        let start = self.index;
        while let Some(byte) = self.peek() {
            if byte.is_ascii_alphanumeric() || byte == b'_' {
                self.index = self.index.saturating_add(1);
            } else {
                break;
            }
        }
        if self.index == start {
            return Err(err_invalid("expected identifier in proof term"));
        }
        std::str::from_utf8(&self.bytes[start..self.index])
            .map(str::to_owned)
            .map_err(|_| err_invalid("non-UTF-8 identifier in proof term"))
    }

    fn read_u64(&mut self) -> Result<u64, crate::CapabilityError> {
        let start = self.index;
        while let Some(byte) = self.peek() {
            if byte.is_ascii_digit() {
                self.index = self.index.saturating_add(1);
            } else {
                break;
            }
        }
        if self.index == start {
            return Err(err_invalid("expected non-negative integer in proof term"));
        }
        let text = std::str::from_utf8(&self.bytes[start..self.index])
            .map_err(|_| err_invalid("invalid integer in proof term"))?;
        text.parse::<u64>()
            .map_err(|_| err_invalid("integer overflow in proof term"))
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.index).copied()
    }

    fn expect_byte(&mut self, expected: u8) -> Result<(), crate::CapabilityError> {
        if self.peek() == Some(expected) {
            self.index = self.index.saturating_add(1);
            Ok(())
        } else {
            Err(err_invalid("unexpected character in proof term"))
        }
    }
}

// ---------------------------------------------------------------------------
// Independent Iterative Robinson Unification & Host-Side Proof Verification
// ---------------------------------------------------------------------------

type VarKey = (u64, String);

#[derive(Clone, Debug, PartialEq, Eq)]
enum ScopedTerm {
    Integer(i64),
    String(String),
    Symbol(String),
    Var(VarKey),
    Reference {
        record_id: mneme_core::RecordId,
        revision_id: Option<mneme_core::RevisionId>,
    },
    List(Vec<ScopedTerm>),
    Compound {
        functor: String,
        args: Vec<ScopedTerm>,
    },
}

#[derive(Clone, Debug)]
struct ScopedAtom {
    predicate: String,
    terms: Vec<ScopedTerm>,
}

struct Unifier {
    subst: std::collections::BTreeMap<VarKey, ScopedTerm>,
    steps: usize,
}

impl Unifier {
    fn new() -> Self {
        Self {
            subst: std::collections::BTreeMap::new(),
            steps: 0,
        }
    }

    fn deref_term<'a>(&'a self, mut term: &'a ScopedTerm) -> &'a ScopedTerm {
        let mut hops = 0_usize;
        while let ScopedTerm::Var(key) = term {
            let Some(next) = self.subst.get(key) else {
                break;
            };
            term = next;
            hops = hops.saturating_add(1);
            if hops > MAX_UNIFY_STEPS {
                break;
            }
        }
        term
    }

    fn occurs(&self, target: &VarKey, root: &ScopedTerm) -> bool {
        let mut stack = Vec::with_capacity(16);
        stack.push(root);
        let mut visited = 0_usize;
        while let Some(term) = stack.pop() {
            visited = visited.saturating_add(1);
            if visited > MAX_UNIFY_STEPS {
                return true;
            }
            let deref = self.deref_term(term);
            if let ScopedTerm::Var(key) = deref {
                if key == target {
                    return true;
                }
            } else if let ScopedTerm::List(items) = deref {
                stack.extend(items.iter());
            } else if let ScopedTerm::Compound { args, .. } = deref {
                stack.extend(args.iter());
            }
        }
        false
    }

    fn unify_atoms(
        &mut self,
        left: &ScopedAtom,
        right: &ScopedAtom,
    ) -> Result<(), crate::CapabilityError> {
        if left.predicate != right.predicate || left.terms.len() != right.terms.len() {
            return Err(err_invalid(
                "proof step predicate or arity does not match goal",
            ));
        }
        let mut work: Vec<(ScopedTerm, ScopedTerm)> = left
            .terms
            .iter()
            .cloned()
            .zip(right.terms.iter().cloned())
            .collect();
        while let Some((lhs, rhs)) = work.pop() {
            self.steps = self.steps.saturating_add(1);
            if self.steps > MAX_UNIFY_STEPS {
                return Err(err_invalid("proof unification step bound exceeded"));
            }
            let lhs = self.deref_term(&lhs).clone();
            let rhs = self.deref_term(&rhs).clone();
            if lhs == rhs {
                continue;
            }
            match (lhs, rhs) {
                (ScopedTerm::Var(var), other) | (other, ScopedTerm::Var(var)) => {
                    if self.occurs(&var, &other) {
                        return Err(err_invalid("occurs check failed during proof verification"));
                    }
                    self.subst.insert(var, other);
                }
                (ScopedTerm::List(l_items), ScopedTerm::List(r_items)) => {
                    if l_items.len() != r_items.len() {
                        return Err(err_invalid(
                            "list length mismatch during proof verification",
                        ));
                    }
                    work.reserve(l_items.len());
                    for pair in l_items.into_iter().zip(r_items) {
                        work.push(pair);
                    }
                }
                (
                    ScopedTerm::Compound {
                        functor: lf,
                        args: la,
                    },
                    ScopedTerm::Compound {
                        functor: rf,
                        args: ra,
                    },
                ) => {
                    if lf != rf || la.len() != ra.len() {
                        return Err(err_invalid(
                            "compound term mismatch during proof verification",
                        ));
                    }
                    work.reserve(la.len());
                    for pair in la.into_iter().zip(ra) {
                        work.push(pair);
                    }
                }
                _ => {
                    return Err(err_invalid("term unification failed during proof check"));
                }
            }
        }
        Ok(())
    }
}

enum ScopeConvertStep<'a> {
    Enter(&'a crate::Term),
    BuildList(usize),
    BuildCompound(String, usize),
}

fn scope_term(root: &crate::Term, scope_id: u64) -> ScopedTerm {
    let mut work = Vec::with_capacity(16);
    work.push(ScopeConvertStep::Enter(root));
    let mut out: Vec<ScopedTerm> = Vec::with_capacity(16);
    while let Some(step) = work.pop() {
        if let ScopeConvertStep::Enter(term) = step {
            push_enter_scope_term(term, scope_id, &mut work, &mut out);
        } else if let ScopeConvertStep::BuildList(len) = step {
            let start = out.len().saturating_sub(len);
            let items = out.split_off(start);
            out.push(ScopedTerm::List(items));
        } else if let ScopeConvertStep::BuildCompound(functor, len) = step {
            let start = out.len().saturating_sub(len);
            let args = out.split_off(start);
            out.push(ScopedTerm::Compound { functor, args });
        }
    }
    out.pop()
        .unwrap_or_else(|| ScopedTerm::Symbol("invalid".to_owned()))
}

fn push_enter_scope_term<'a>(
    term: &'a crate::Term,
    scope_id: u64,
    work: &mut Vec<ScopeConvertStep<'a>>,
    out: &mut Vec<ScopedTerm>,
) {
    if let crate::Term::Integer(v) = term {
        out.push(ScopedTerm::Integer(*v));
    } else if let crate::Term::String(s) = term {
        out.push(ScopedTerm::String(s.clone()));
    } else if let crate::Term::Symbol(s) = term {
        out.push(ScopedTerm::Symbol(s.clone()));
    } else if let crate::Term::Variable(name) = term {
        out.push(ScopedTerm::Var((scope_id, name.clone())));
    } else if let crate::Term::Reference {
        record_id,
        revision_id,
    } = term
    {
        out.push(ScopedTerm::Reference {
            record_id: *record_id,
            revision_id: *revision_id,
        });
    } else if let crate::Term::List(items) = term {
        work.push(ScopeConvertStep::BuildList(items.len()));
        work.reserve(items.len());
        for item in items.iter().rev() {
            work.push(ScopeConvertStep::Enter(item));
        }
    } else if let crate::Term::Compound { functor, args } = term {
        work.push(ScopeConvertStep::BuildCompound(functor.clone(), args.len()));
        work.reserve(args.len());
        for arg in args.iter().rev() {
            work.push(ScopeConvertStep::Enter(arg));
        }
    }
}

fn scope_atom(atom: &crate::Atom, scope_id: u64) -> ScopedAtom {
    ScopedAtom {
        predicate: atom.predicate.clone(),
        terms: atom
            .terms
            .iter()
            .map(|term| scope_term(term, scope_id))
            .collect(),
    }
}

struct VerifyState<'a> {
    request: &'a crate::Request,
    image: &'a crate::snapshot::InputImage,
    unifier: Unifier,
    next_scope: u64,
    premises: Vec<crate::Premise>,
    assumptions: std::collections::BTreeSet<String>,
    epistemic: mneme_datalog::EpistemicStatus,
    uncertified_reason: Option<String>,
}

fn verify_node(
    root: &Node,
    bindings: &std::collections::BTreeMap<String, crate::Term>,
    request: &crate::Request,
    image: &crate::snapshot::InputImage,
) -> Result<Verified, crate::CapabilityError> {
    let mut unifier = Unifier::new();
    for (name, term) in bindings {
        unifier
            .subst
            .insert((0_u64, name.clone()), scope_term(term, 0_u64));
    }
    let mut state = VerifyState {
        request,
        image,
        unifier,
        next_scope: 1_u64,
        premises: Vec::new(),
        assumptions: std::collections::BTreeSet::new(),
        epistemic: mneme_datalog::EpistemicStatus::Accepted,
        uncertified_reason: None,
    };

    let mut work: Vec<(ScopedAtom, &Node, usize)> = Vec::with_capacity(16);
    work.push((scope_atom(&request.goal, 0_u64), root, 0_usize));
    let mut steps_checked = 0_usize;

    while let Some((target, node, depth)) = work.pop() {
        steps_checked = steps_checked.saturating_add(1);
        if depth > MAX_DEPTH || steps_checked > MAX_NODES {
            return Err(err_invalid(
                "proof verification exceeded depth or node bound",
            ));
        }
        if let Node::Leaf(leaf) = node {
            verify_leaf(&mut state, &target, leaf)?;
        } else if let Node::RuleStep {
            rule_index,
            children,
        } = node
        {
            expand_rule_step(
                &mut state,
                RuleStepArgs {
                    target: &target,
                    rule_index: *rule_index,
                    children,
                    depth,
                },
                &mut work,
            )?;
        }
    }

    let premises = dedup_premises(state.premises);
    let mut uncertified_reason = state.uncertified_reason;
    if premises.is_empty() && uncertified_reason.is_none() {
        uncertified_reason =
            Some("proof derivation rests on no canonical image premises".to_owned());
    }
    let certificate = Certificate::seal(root.clone(), state.epistemic);
    Ok(Verified {
        premises,
        assumptions: state.assumptions,
        epistemic: state.epistemic,
        certificate,
        uncertified_reason,
    })
}

struct RuleStepArgs<'a, 'b> {
    target: &'b ScopedAtom,
    rule_index: u64,
    children: &'a [Node],
    depth: usize,
}

fn expand_rule_step<'a>(
    state: &mut VerifyState<'_>,
    args: RuleStepArgs<'a, '_>,
    work: &mut Vec<(ScopedAtom, &'a Node, usize)>,
) -> Result<(), crate::CapabilityError> {
    let idx =
        usize::try_from(args.rule_index).map_err(|_| err_invalid("rule index out of range"))?;
    let rule = state
        .request
        .rules
        .get(idx)
        .ok_or_else(|| err_invalid("proof references unknown rule index"))?;
    if args.children.len() != rule.body.len() {
        return Err(err_invalid("proof step child count differs from rule body"));
    }
    let step_scope = state.next_scope;
    state.next_scope = state.next_scope.saturating_add(1);
    let head_atom = scope_atom(&rule.head, step_scope);
    state.unifier.unify_atoms(args.target, &head_atom)?;
    work.reserve(args.children.len());
    for (literal, child) in rule.body.iter().zip(args.children.iter()).rev() {
        let crate::Literal::Positive(body_atom) = literal else {
            return Err(err_invalid(
                "negative rule literal cannot be proof-certified",
            ));
        };
        work.push((
            scope_atom(body_atom, step_scope),
            child,
            args.depth.saturating_add(1),
        ));
    }
    Ok(())
}

fn verify_leaf(
    state: &mut VerifyState<'_>,
    target: &ScopedAtom,
    leaf: &Leaf,
) -> Result<(), crate::CapabilityError> {
    if let Leaf::Canonical { index } = leaf {
        return verify_canonical_leaf(state, target, *index);
    }
    if let Leaf::Relation {
        relation_index,
        row_index,
    } = leaf
    {
        return verify_relation_leaf(
            state,
            target,
            *relation_index,
            *row_index,
            RelationLeafMode::AcceptedOnly,
        );
    }
    if let Leaf::RelationEpistemic {
        relation_index,
        row_index,
    } = leaf
    {
        return verify_relation_leaf(
            state,
            target,
            *relation_index,
            *row_index,
            RelationLeafMode::EpistemicTagged,
        );
    }
    if let Leaf::Assumption { index } = leaf {
        return verify_assumption_leaf(state, target, *index);
    }
    Err(err_invalid("unrecognized proof leaf"))
}

fn verify_canonical_leaf(
    state: &mut VerifyState<'_>,
    target: &ScopedAtom,
    index: u64,
) -> Result<(), crate::CapabilityError> {
    let idx = usize::try_from(index).map_err(|_| err_invalid("canonical leaf index overflow"))?;
    let fact = state
        .image
        .canonical
        .get(idx)
        .ok_or_else(|| err_invalid("proof references out-of-bounds canonical assertion"))?;
    let val_term = crate::snapshot::value_term(&fact.value)
        .map_err(|_| err_invalid("canonical value is unrepresentable"))?;
    let expected = scope_atom(
        &crate::Atom {
            predicate: crate::ASSERTION_RELATION.to_owned(),
            terms: vec![
                crate::Term::String(fact.predicate.clone()),
                crate::Term::String(fact.subject.to_hex()),
                val_term,
            ],
        },
        0_u64,
    );
    state.unifier.unify_atoms(target, &expected)?;
    state.premises.push(crate::Premise {
        record_id: fact.record_id,
        revision_id: fact.revision_id,
        span: None,
        derivation: None,
        ancestry_roots: std::collections::BTreeSet::from([(fact.record_id, fact.revision_id)]),
        availability: crate::PremiseAvailability::Retained,
    });
    state.epistemic = state
        .epistemic
        .join(mneme_datalog::EpistemicStatus::Accepted);
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RelationLeafMode {
    AcceptedOnly,
    EpistemicTagged,
}

fn verify_relation_leaf(
    state: &mut VerifyState<'_>,
    target: &ScopedAtom,
    relation_index: u64,
    row_index: u64,
    mode: RelationLeafMode,
) -> Result<(), crate::CapabilityError> {
    let r_idx =
        usize::try_from(relation_index).map_err(|_| err_invalid("relation index overflow"))?;
    let row_idx = usize::try_from(row_index).map_err(|_| err_invalid("row index overflow"))?;
    let relation = state
        .image
        .relations
        .get(r_idx)
        .ok_or_else(|| err_invalid("proof references out-of-bounds selected relation"))?;
    let row = relation
        .rows
        .get(row_idx)
        .ok_or_else(|| err_invalid("proof references out-of-bounds selected relation row"))?;
    if !row.epistemic.is_active() {
        return Err(err_invalid(
            "proof references a Rejected selected Datalog row",
        ));
    }
    if mode == RelationLeafMode::AcceptedOnly
        && row.epistemic != mneme_datalog::EpistemicStatus::Accepted
    {
        return Err(err_invalid(
            "unqualified relation/2 leaf requires an Accepted Datalog row",
        ));
    }
    let value_terms = row
        .values
        .iter()
        .map(crate::snapshot::value_term)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| err_invalid("selected row contains unrepresentable value"))?;
    let expected_atom = if mode == RelationLeafMode::AcceptedOnly {
        crate::Atom {
            predicate: crate::RELATION_RELATION.to_owned(),
            terms: vec![
                crate::Term::String(relation.predicate.clone()),
                crate::Term::List(value_terms),
            ],
        }
    } else {
        crate::Atom {
            predicate: crate::snapshot::SelectedRow::EPISTEMIC_RELATION.to_owned(),
            terms: vec![
                crate::Term::String(relation.predicate.clone()),
                crate::Term::List(value_terms),
                crate::Term::String(row.epistemic.name().to_owned()),
            ],
        }
    };
    state
        .unifier
        .unify_atoms(target, &scope_atom(&expected_atom, 0_u64))?;

    let extracted = extract_row_premises(row, state.image);
    if row.support_truncated {
        state.uncertified_reason =
            Some("selected Datalog row support was truncated and cannot be certified".to_owned());
    } else if extracted.is_empty() {
        state.uncertified_reason =
            Some("selected Datalog row has no canonical premises to certify".to_owned());
    }
    state.premises.extend(extracted);
    state.epistemic = state.epistemic.join(row.epistemic);
    Ok(())
}

fn verify_assumption_leaf(
    state: &mut VerifyState<'_>,
    target: &ScopedAtom,
    index: u64,
) -> Result<(), crate::CapabilityError> {
    let idx = usize::try_from(index).map_err(|_| err_invalid("assumption leaf index overflow"))?;
    let assumption = state
        .request
        .assumptions
        .get(idx)
        .ok_or_else(|| err_invalid("proof references out-of-bounds assumption"))?;
    let expected = scope_atom(&assumption.atom, 0_u64);
    state.unifier.unify_atoms(target, &expected)?;
    state.assumptions.insert(assumption.id.clone());
    state.uncertified_reason = Some(format!(
        "solution relies on hypothetical assumption {}",
        assumption.id
    ));
    Ok(())
}

fn extract_row_premises(
    row: &crate::snapshot::SelectedRow,
    image: &crate::snapshot::InputImage,
) -> Vec<crate::Premise> {
    let canonical_revs: std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RevisionId> =
        image
            .canonical
            .iter()
            .map(|fact| (fact.record_id, fact.revision_id))
            .collect();
    let cap: usize = row
        .supports
        .iter()
        .map(|d| {
            d.sources
                .len()
                .max(d.premises.iter().map(|p| p.canonical_roots.len()).sum())
        })
        .sum();
    let mut out = Vec::with_capacity(cap);
    for derivation in &row.supports {
        let pruned_by_record = pruned_availability_map(derivation);
        if !derivation.sources.is_empty() {
            for &(rec_id, rev_id) in &derivation.sources {
                let availability = match pruned_by_record.get(&rec_id) {
                    Some(reason) => crate::PremiseAvailability::Pruned {
                        reason: reason.clone(),
                    },
                    None => crate::PremiseAvailability::Retained,
                };
                out.push(crate::Premise {
                    record_id: rec_id,
                    revision_id: rev_id,
                    span: None,
                    derivation: None,
                    ancestry_roots: std::collections::BTreeSet::from([(rec_id, rev_id)]),
                    availability,
                });
            }
            continue;
        }
        let fallback_rev = mneme_core::RevisionId::from_bytes(*derivation.revision.as_bytes());
        for prem in &derivation.premises {
            for &root_id in &prem.canonical_roots {
                let rev_id = canonical_revs
                    .get(&root_id)
                    .copied()
                    .unwrap_or(fallback_rev);
                out.push(crate::Premise {
                    record_id: root_id,
                    revision_id: rev_id,
                    span: None,
                    derivation: None,
                    ancestry_roots: std::collections::BTreeSet::from([(root_id, rev_id)]),
                    availability: crate::PremiseAvailability::Retained,
                });
            }
        }
    }
    out
}

fn pruned_availability_map(
    derivation: &mneme_datalog::Derivation,
) -> std::collections::BTreeMap<mneme_core::RecordId, String> {
    derivation
        .premises
        .iter()
        .filter_map(|prem| {
            let avail = prem.source_availability.as_ref()?;
            if avail == "retained" {
                return None;
            }
            Some((prem, avail))
        })
        .flat_map(|(prem, avail)| {
            prem.sources
                .iter()
                .map(move |&(rec_id, _)| (rec_id, avail.clone()))
        })
        .collect()
}

fn dedup_premises(premises: Vec<crate::Premise>) -> Vec<crate::Premise> {
    let mut seen: std::collections::BTreeSet<(mneme_core::RecordId, mneme_core::RevisionId)> =
        std::collections::BTreeSet::new();
    let mut unique = Vec::with_capacity(premises.len());
    for premise in premises {
        if seen.insert((premise.record_id, premise.revision_id)) {
            unique.push(premise);
        }
    }
    unique
}

fn err_invalid(detail: &str) -> crate::CapabilityError {
    crate::CapabilityError::InvalidRequest(format!("invalid proof certificate: {detail}"))
}
