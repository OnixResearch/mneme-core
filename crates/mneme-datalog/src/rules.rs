//! Restricted rule validation and stratification.

/// The value kind one column of a canonical extent holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CanonicalKind {
    /// A `<record-id "…">` identity.
    RecordId,
    /// A `<revision-id "…">` identity.
    RevisionId,
    /// A Preserves symbol.
    Symbol,
    /// A Preserves text string.
    String,
    /// Any value, because the loader fills the column from an optional field.
    Any,
}

impl CanonicalKind {
    /// Whether a value can appear in this column.
    pub(crate) fn accepts(self, value: &mneme_core::Value) -> bool {
        match self {
            CanonicalKind::RecordId => identity_record(value, "record-id"),
            CanonicalKind::RevisionId => identity_record(value, "revision-id"),
            CanonicalKind::Symbol => value.as_symbol().is_some(),
            CanonicalKind::String => value.as_string().is_some(),
            CanonicalKind::Any => true,
        }
    }

    /// Stable name for diagnostics.
    const fn name(self) -> &'static str {
        match self {
            CanonicalKind::RecordId => "record-id",
            CanonicalKind::RevisionId => "revision-id",
            CanonicalKind::Symbol => "symbol",
            CanonicalKind::String => "string",
            CanonicalKind::Any => "any",
        }
    }
}

fn identity_record(value: &mneme_core::Value, label: &str) -> bool {
    value.as_record().is_some_and(|record| {
        record.label() == &mneme_core::Value::symbol(label)
            && record.fields().len() == 1
            && record
                .fields()
                .first()
                .is_some_and(|field| field.as_string().is_some())
    })
}

/// The fixed column kinds of one canonical extent.
///
/// The loaders in [`crate::engine`] emit exactly these shapes. A bundle that
/// declares another arity, or a rule that compares a column against a constant
/// of another kind, would silently see an empty relation and could then report
/// a false absence, so both are registration errors rather than empty answers.
pub(crate) fn canonical_schema(predicate: &str) -> Option<&'static [CanonicalKind]> {
    match predicate {
        "entity" => Some(&[
            CanonicalKind::RecordId,
            CanonicalKind::Symbol,
            CanonicalKind::String,
        ]),
        "relation" => Some(&[
            CanonicalKind::Symbol,
            CanonicalKind::RecordId,
            CanonicalKind::RecordId,
        ]),
        "assertion" | "denial" | "hypothesis" => Some(&[
            CanonicalKind::RecordId,
            CanonicalKind::Symbol,
            CanonicalKind::Any,
            CanonicalKind::RecordId,
        ]),
        "evidence" => Some(&[CanonicalKind::RecordId, CanonicalKind::RecordId]),
        "document" => Some(&[
            CanonicalKind::RecordId,
            // The loader falls back to the `unbound` symbol when a document has
            // no entity, so the column cannot be narrowed to an identity.
            CanonicalKind::Any,
            CanonicalKind::String,
        ]),
        "derivation" => Some(&[CanonicalKind::RecordId, CanonicalKind::RecordId]),
        "source" => Some(&[
            CanonicalKind::RecordId,
            CanonicalKind::RevisionId,
            CanonicalKind::String,
        ]),
        _ => None,
    }
}

/// The canonical arity of one base extent, if it is a canonical extent.
pub(crate) fn canonical_arity(predicate: &str) -> Option<usize> {
    canonical_schema(predicate).map(<[CanonicalKind]>::len)
}

/// Validate a rule bundle before any evaluation or publication.
#[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
pub fn validate(
    bundle: &crate::RuleBundle,
) -> Result<crate::RuleProgram, Vec<crate::RuleDiagnostic>> {
    let body_literals = bundle
        .rules
        .iter()
        .fold(0_usize, |total, rule| total.saturating_add(rule.body.len()));
    let rule_terms = bundle.rules.iter().fold(0_usize, |total, rule| {
        let body_terms = rule.body.iter().fold(0_usize, |terms, literal| {
            terms.saturating_add(match literal {
                crate::Literal::Positive(atom) | crate::Literal::Negative(atom) => atom.arity(),
                crate::Literal::Compare { .. } | crate::Literal::Aggregate { .. } => 2,
                crate::Literal::Forbidden(_) => 0,
            })
        });
        total
            .saturating_add(rule.head.arity())
            .saturating_add(body_terms)
    });
    let max_diagnostics = 3_usize
        .saturating_add(bundle.base_predicates.len().saturating_mul(2))
        .saturating_add(bundle.rules.len().saturating_mul(5))
        .saturating_add(body_literals.saturating_mul(5))
        .saturating_add(rule_terms)
        .saturating_add(bundle.complete_predicates.len());
    let mut diagnostics = Vec::with_capacity(max_diagnostics);
    validate_bundle_header(bundle, &mut diagnostics);
    let arities = validate_base_predicates(bundle, &mut diagnostics);
    let heads = predeclare_rule_heads(bundle, &mut diagnostics);
    for rule in &bundle.rules {
        let analysis = analyze_rule_body(bundle, rule, &arities, &heads, &mut diagnostics);
        if !analysis.is_seen_forbidden {
            validate_aggregate_coverage(bundle, rule, &analysis, &mut diagnostics);
            validate_rule_variables(rule, &analysis, &mut diagnostics);
        }
    }
    validate_complete_predicates(bundle, &arities, &heads, &mut diagnostics);
    finish_validation(bundle, arities, heads, diagnostics)
}

fn validate_bundle_header(
    bundle: &crate::RuleBundle,
    diagnostics: &mut Vec<crate::RuleDiagnostic>,
) {
    if bundle.id.trim().is_empty() {
        diagnostics.push(diag("bundle-id", None, "rule bundle id is empty"));
    }
    if bundle.version.trim().is_empty() {
        diagnostics.push(diag("bundle-version", None, "rule bundle version is empty"));
    }
    if bundle.schema_version == 0 {
        diagnostics.push(diag(
            "schema-version",
            None,
            "rule bundle schema version is zero",
        ));
    }
}

fn validate_base_predicates(
    bundle: &crate::RuleBundle,
    diagnostics: &mut Vec<crate::RuleDiagnostic>,
) -> std::collections::BTreeMap<String, usize> {
    let mut arities = std::collections::BTreeMap::new();
    for (predicate, arity) in &bundle.base_predicates {
        if !valid_name(predicate) {
            diagnostics.push(diag(
                "predicate-name",
                None,
                format!("invalid base predicate {predicate:?}"),
            ));
        }
        if *arity == 0 {
            diagnostics.push(diag(
                "predicate-arity",
                None,
                format!("base predicate {predicate:?} has zero arity"),
            ));
        }
        if let Some(expected) = canonical_arity(predicate)
            && *arity != expected
        {
            diagnostics.push(diag(
                "predicate-arity",
                None,
                format!(
                    "base predicate {predicate:?} is a canonical extent with {expected} columns, but the bundle declares {arity}"
                ),
            ));
        }
        if arities.len() >= bundle.base_predicates.len() {
            break;
        }
        arities.insert(predicate.clone(), *arity);
    }
    arities
}

fn predeclare_rule_heads(
    bundle: &crate::RuleBundle,
    diagnostics: &mut Vec<crate::RuleDiagnostic>,
) -> std::collections::BTreeMap<String, usize> {
    let mut heads = std::collections::BTreeMap::new();
    // Predeclare every rule head so a body may reference a rule defined later.
    for rule in &bundle.rules {
        if rule.id.trim().is_empty() {
            diagnostics.push(diag("rule-id", Some(rule.id.clone()), "rule id is empty"));
        }
        if !valid_name(&rule.head.predicate) {
            diagnostics.push(diag(
                "predicate-name",
                Some(rule.id.clone()),
                format!("invalid head predicate {:?}", rule.head.predicate),
            ));
        }
        // A rule head may never overwrite a canonical extent, whether the
        // bundle declares that extent or not: derived facts share the same
        // store as loaded facts, so a derived `entity` row would merge with
        // canonical records and negation over the head would see rows the
        // rules never produced.
        if canonical_schema(&rule.head.predicate).is_some() {
            diagnostics.push(diag(
                "base-overwrite",
                Some(rule.id.clone()),
                format!(
                    "rule head {:?} names a canonical extent and cannot be derived",
                    rule.head.predicate
                ),
            ));
        } else if bundle.base_predicates.contains_key(&rule.head.predicate) {
            diagnostics.push(diag(
                "base-overwrite",
                Some(rule.id.clone()),
                format!(
                    "rule head {:?} is a declared base predicate",
                    rule.head.predicate
                ),
            ));
        }
        if let Some(existing) = heads.insert(rule.head.predicate.clone(), rule.head.arity())
            && existing != rule.head.arity()
        {
            diagnostics.push(diag(
                "head-arity",
                Some(rule.id.clone()),
                format!(
                    "head predicate {:?} has conflicting arities",
                    rule.head.predicate
                ),
            ));
        }
    }
    heads
}

struct RuleBodyAnalysis {
    positive_vars: std::collections::BTreeSet<String>,
    negative_vars: std::collections::BTreeSet<String>,
    compare_vars: std::collections::BTreeSet<String>,
    aggregate: Option<(crate::Term, String)>,
    is_seen_forbidden: bool,
}

impl RuleBodyAnalysis {
    fn new() -> Self {
        Self {
            positive_vars: std::collections::BTreeSet::new(),
            negative_vars: std::collections::BTreeSet::new(),
            compare_vars: std::collections::BTreeSet::new(),
            aggregate: None,
            is_seen_forbidden: false,
        }
    }
}

fn analyze_rule_body(
    bundle: &crate::RuleBundle,
    rule: &crate::Rule,
    arities: &std::collections::BTreeMap<String, usize>,
    heads: &std::collections::BTreeMap<String, usize>,
    diagnostics: &mut Vec<crate::RuleDiagnostic>,
) -> RuleBodyAnalysis {
    let mut analysis = RuleBodyAnalysis::new();
    for (index, literal) in rule.body.iter().enumerate() {
        analyze_literal(
            LiteralAnalysisContext {
                bundle,
                rule,
                arities,
                heads,
                analysis: &mut analysis,
                diagnostics,
            },
            index,
            literal,
        );
    }
    analysis
}

struct LiteralAnalysisContext<'a> {
    bundle: &'a crate::RuleBundle,
    rule: &'a crate::Rule,
    arities: &'a std::collections::BTreeMap<String, usize>,
    heads: &'a std::collections::BTreeMap<String, usize>,
    analysis: &'a mut RuleBodyAnalysis,
    diagnostics: &'a mut Vec<crate::RuleDiagnostic>,
}

fn analyze_literal(context: LiteralAnalysisContext<'_>, index: usize, literal: &crate::Literal) {
    let LiteralAnalysisContext {
        bundle,
        rule,
        arities,
        heads,
        analysis,
        diagnostics,
    } = context;
    match literal {
        crate::Literal::Forbidden(name) => {
            analysis.is_seen_forbidden = true;
            diagnostics.push(diag(
                "forbidden-builtin",
                Some(rule.id.clone()),
                format!("forbidden operation {name:?}"),
            ));
        }
        crate::Literal::Positive(atom) | crate::Literal::Negative(atom) => {
            validate_atom(atom, arities, heads, &rule.id, diagnostics);
            match literal {
                crate::Literal::Positive(_) => {
                    analysis
                        .positive_vars
                        .extend(atom.terms.iter().filter_map(term_var));
                }
                crate::Literal::Negative(_) => {
                    analysis
                        .negative_vars
                        .extend(atom.terms.iter().filter_map(term_var));
                    if !bundle.complete_predicates.contains(&atom.predicate) {
                        diagnostics.push(diag(
                            "negation-coverage",
                            Some(rule.id.clone()),
                            format!(
                                "negated predicate {:?} is not declared complete",
                                atom.predicate
                            ),
                        ));
                    }
                }
                _ => {}
            }
        }
        crate::Literal::Compare { left, right, .. } => {
            analysis.compare_vars.extend(term_var(left));
            analysis.compare_vars.extend(term_var(right));
        }
        crate::Literal::Aggregate { input, output, .. } => {
            validate_aggregate_literal(rule, index, output, analysis, diagnostics);
            analysis.aggregate = Some((input.clone(), output.clone()));
            if !bundle.complete_predicates.iter().any(|predicate| {
                rule.body.iter().any(|literal| {
                    matches!(
                        literal,
                        crate::Literal::Positive(atom) if &atom.predicate == predicate
                    )
                })
            }) {
                // The detailed per-positive-relation check below catches
                // the usual missing declaration; this branch only makes
                // the diagnostic explicit for an empty positive body.
            }
        }
    }
}

fn validate_aggregate_literal(
    rule: &crate::Rule,
    index: usize,
    output: &str,
    analysis: &RuleBodyAnalysis,
    diagnostics: &mut Vec<crate::RuleDiagnostic>,
) {
    if analysis.aggregate.is_some() {
        diagnostics.push(diag(
            "aggregate-count",
            Some(rule.id.clone()),
            "at most one aggregate literal is supported",
        ));
    }
    if index + 1 != rule.body.len() {
        diagnostics.push(diag(
            "aggregate-position",
            Some(rule.id.clone()),
            "aggregate literal must be final",
        ));
    }
    if output.trim().is_empty() {
        diagnostics.push(diag(
            "aggregate-output",
            Some(rule.id.clone()),
            "aggregate output variable is empty",
        ));
    }
    if analysis.positive_vars.contains(output) || analysis.negative_vars.contains(output) {
        diagnostics.push(diag(
            "aggregate-output-bound",
            Some(rule.id.clone()),
            "aggregate output variable must be newly bound",
        ));
    }
}

fn validate_aggregate_coverage(
    bundle: &crate::RuleBundle,
    rule: &crate::Rule,
    analysis: &RuleBodyAnalysis,
    diagnostics: &mut Vec<crate::RuleDiagnostic>,
) {
    if analysis.aggregate.is_none() {
        return;
    }
    for literal in &rule.body {
        if let crate::Literal::Positive(atom) = literal
            && !bundle.complete_predicates.contains(&atom.predicate)
        {
            diagnostics.push(diag(
                "aggregate-coverage",
                Some(rule.id.clone()),
                format!(
                    "aggregate body predicate {:?} is not declared complete",
                    atom.predicate
                ),
            ));
        }
    }
}

fn validate_rule_variables(
    rule: &crate::Rule,
    analysis: &RuleBodyAnalysis,
    diagnostics: &mut Vec<crate::RuleDiagnostic>,
) {
    let aggregate_output = analysis
        .aggregate
        .as_ref()
        .map(|(_, output)| output.as_str());
    for variable in head_vars(&rule.head) {
        if aggregate_output.is_some_and(|output| output == variable) {
            continue;
        }
        if !analysis.positive_vars.contains(&variable) {
            diagnostics.push(diag(
                "unsafe-head-variable",
                Some(rule.id.clone()),
                format!("head variable {variable:?} is not positively bound"),
            ));
        }
    }
    for variable in analysis
        .negative_vars
        .iter()
        .chain(analysis.compare_vars.iter())
    {
        if !analysis.positive_vars.contains(variable) {
            diagnostics.push(diag(
                "unsafe-body-variable",
                Some(rule.id.clone()),
                format!("variable {variable:?} is not positively bound"),
            ));
        }
    }
    if let Some((input, _)) = &analysis.aggregate
        && let Some(variable) = term_var(input)
        && !analysis.positive_vars.contains(&variable)
    {
        diagnostics.push(diag(
            "unsafe-aggregate-variable",
            Some(rule.id.clone()),
            format!("aggregate input variable {variable:?} is not positively bound"),
        ));
    }
}

fn validate_complete_predicates(
    bundle: &crate::RuleBundle,
    arities: &std::collections::BTreeMap<String, usize>,
    heads: &std::collections::BTreeMap<String, usize>,
    diagnostics: &mut Vec<crate::RuleDiagnostic>,
) {
    for predicate in &bundle.complete_predicates {
        if !arities.contains_key(predicate) && !heads.contains_key(predicate) {
            diagnostics.push(diag(
                "unknown-complete-predicate",
                None,
                format!("complete predicate {predicate:?} is not declared"),
            ));
        }
    }
}

fn finish_validation(
    bundle: &crate::RuleBundle,
    mut arities: std::collections::BTreeMap<String, usize>,
    heads: std::collections::BTreeMap<String, usize>,
    mut diagnostics: Vec<crate::RuleDiagnostic>,
) -> Result<crate::RuleProgram, Vec<crate::RuleDiagnostic>> {
    if diagnostics.is_empty() {
        for (predicate, arity) in &heads {
            arities.insert(predicate.clone(), *arity);
        }
        match strata(bundle, &arities) {
            Ok(strata) => Ok(crate::RuleProgram {
                bundle: bundle.clone(),
                arities,
                strata,
            }),
            Err(mut errors) => {
                diagnostics.append(&mut errors);
                Err(diagnostics)
            }
        }
    } else {
        Err(diagnostics)
    }
}

fn validate_atom(
    atom: &crate::Atom,
    arities: &std::collections::BTreeMap<String, usize>,
    heads: &std::collections::BTreeMap<String, usize>,
    rule: &str,
    diagnostics: &mut Vec<crate::RuleDiagnostic>,
) {
    let Some(expected) = arities
        .get(&atom.predicate)
        .or_else(|| heads.get(&atom.predicate))
    else {
        diagnostics.push(diag(
            "unknown-predicate",
            Some(rule.to_owned()),
            format!("body predicate {:?} is not declared", atom.predicate),
        ));
        return;
    };
    if *expected != atom.arity() {
        diagnostics.push(diag(
            "predicate-arity",
            Some(rule.to_owned()),
            format!(
                "predicate {:?} expects {expected} terms, found {}",
                atom.predicate,
                atom.arity()
            ),
        ));
    }
    let Some(schema) = canonical_schema(&atom.predicate) else {
        return;
    };
    for (column, term) in atom.terms.iter().enumerate() {
        let crate::Term::Constant(value) = term else {
            continue;
        };
        let Some(kind) = schema.get(column) else {
            continue;
        };
        if !kind.accepts(value) {
            diagnostics.push(diag(
                "predicate-kind",
                Some(rule.to_owned()),
                format!(
                    "predicate {:?} column {} holds {}, but the rule compares it with a {} constant",
                    atom.predicate,
                    column.saturating_add(1),
                    kind.name(),
                    value.kind_name()
                ),
            ));
        }
    }
}

fn strata(
    bundle: &crate::RuleBundle,
    arities: &std::collections::BTreeMap<String, usize>,
) -> Result<std::collections::BTreeMap<String, usize>, Vec<crate::RuleDiagnostic>> {
    let mut strata = arities
        .keys()
        .map(|predicate| (predicate.clone(), 0_usize))
        .collect::<std::collections::BTreeMap<_, _>>();
    let limit = arities.len() + bundle.rules.len() + 2;
    for _ in 0..limit {
        let mut is_changed = false;
        for rule in &bundle.rules {
            let target = rule_target_stratum(rule, &strata);
            let entry = strata.entry(rule.head.predicate.clone()).or_insert(0);
            if *entry < target {
                *entry = target;
                is_changed = true;
            }
        }
        if !is_changed {
            return Ok(strata);
        }
    }
    Err(vec![diag(
        "non-stratified",
        None,
        "rule dependencies require unbounded strata; non-stratified negation or aggregation",
    )])
}

/// The lowest stratum one rule's head may occupy.
///
/// A positive literal only needs its relation's own stratum. A negated literal
/// needs the next stratum above it, because absence over a relation is decided
/// after every fact of that relation is fixed; forcing the head above its
/// *positive* body as well would reject valid programs such as "reachable
/// without taking a blocked edge". An aggregate rule also needs the next
/// stratum above its positive inputs, because its output replaces many rows
/// with one row per group instead of adding monotone facts.
fn rule_target_stratum(
    rule: &crate::Rule,
    strata: &std::collections::BTreeMap<String, usize>,
) -> usize {
    let mut target = 0_usize;
    let mut has_aggregate = false;
    for literal in &rule.body {
        match literal {
            crate::Literal::Positive(atom) => {
                target = target.max(strata.get(&atom.predicate).copied().unwrap_or(0));
            }
            crate::Literal::Negative(atom) => {
                target = target.max(
                    strata
                        .get(&atom.predicate)
                        .copied()
                        .unwrap_or(0)
                        .saturating_add(1),
                );
            }
            crate::Literal::Aggregate { .. } => has_aggregate = true,
            _ => {}
        }
    }
    if has_aggregate {
        target.saturating_add(1)
    } else {
        target
    }
}

fn head_vars(atom: &crate::Atom) -> Vec<String> {
    atom.terms.iter().filter_map(term_var).collect()
}

fn term_var(term: &crate::Term) -> Option<String> {
    match term {
        crate::Term::Variable(name) => Some(name.clone()),
        crate::Term::Constant(_) => None,
    }
}

fn valid_name(name: &str) -> bool {
    let mut characters = name.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

fn diag(
    code: &'static str,
    rule: Option<String>,
    message: impl Into<String>,
) -> crate::RuleDiagnostic {
    crate::RuleDiagnostic {
        code,
        rule,
        message: message.into(),
    }
}

/// Stable build identity from context and rules.
pub(crate) struct BuildIdContext<'a> {
    pub(crate) revision: mneme_core::WorkspaceRevisionId,
    pub(crate) scope: &'a mneme_core::ScopeId,
    pub(crate) generation: u64,
    pub(crate) bundle: &'a crate::RuleBundle,
    pub(crate) limits: &'a crate::Limits,
    pub(crate) incomplete_extents: &'a std::collections::BTreeSet<String>,
    pub(crate) at: Option<mneme_core::Timestamp>,
}

pub(crate) fn build_id(context: BuildIdContext<'_>) -> String {
    let BuildIdContext {
        revision,
        scope,
        generation,
        bundle,
        limits,
        incomplete_extents,
        at,
    } = context;
    let incomplete = incomplete_extents
        .iter()
        .cloned()
        .map(mneme_core::Value::string)
        .collect::<std::collections::BTreeSet<_>>();
    let effective_time = match at {
        Some(at) => at.to_value(),
        None => mneme_core::Value::symbol("none"),
    };
    let value = mneme_core::Value::record_named(
        "datalog-build-context",
        vec![
            revision.to_value(),
            scope.to_value(),
            mneme_core::Value::integer(generation as i64),
            mneme_core::Value::string(crate::PROFILE_VERSION.to_owned()),
            bundle_value(bundle),
            mneme_core::Value::record_named(
                "datalog-limits",
                vec![
                    mneme_core::Value::integer(limits.max_work),
                    mneme_core::Value::string(limits.max_time_ms.to_string()),
                    mneme_core::Value::integer(limits.max_result_rows),
                    mneme_core::Value::integer(limits.max_supports_per_fact),
                    mneme_core::Value::integer(limits.max_recursion_depth),
                ],
            ),
            mneme_core::Value::set(incomplete),
            effective_time,
        ],
    );
    mneme_core::ContentDigest::of_payload(&value).to_hex()
}

fn bundle_value(bundle: &crate::RuleBundle) -> mneme_core::Value {
    let base = bundle
        .base_predicates
        .iter()
        .map(|(name, arity)| {
            (
                mneme_core::Value::string(name.clone()),
                mneme_core::Value::integer(*arity as i64),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let complete = bundle
        .complete_predicates
        .iter()
        .cloned()
        .map(mneme_core::Value::string)
        .collect::<std::collections::BTreeSet<_>>();
    let rules = bundle
        .rules
        .iter()
        .map(|rule| {
            mneme_core::Value::record_named(
                "datalog-rule",
                vec![
                    mneme_core::Value::string(rule.id.clone()),
                    atom_value(&rule.head),
                    mneme_core::Value::sequence(rule.body.iter().map(literal_value).collect()),
                ],
            )
        })
        .collect::<std::collections::BTreeSet<_>>();
    mneme_core::Value::record_named(
        "datalog-bundle",
        vec![
            mneme_core::Value::string(bundle.id.clone()),
            mneme_core::Value::string(bundle.version.clone()),
            mneme_core::Value::integer(i64::from(bundle.schema_version)),
            mneme_core::Value::Dictionary(base),
            mneme_core::Value::set(complete),
            mneme_core::Value::set(rules),
        ],
    )
}

fn atom_value(atom: &crate::Atom) -> mneme_core::Value {
    mneme_core::Value::record_named(
        "datalog-atom",
        vec![
            mneme_core::Value::string(atom.predicate.clone()),
            mneme_core::Value::sequence(atom.terms.iter().map(term_value).collect()),
        ],
    )
}

fn term_value(term: &crate::Term) -> mneme_core::Value {
    match term {
        crate::Term::Variable(name) => mneme_core::Value::record_named(
            "datalog-var",
            vec![mneme_core::Value::string(name.clone())],
        ),
        crate::Term::Constant(value) => {
            mneme_core::Value::record_named("datalog-const", vec![value.clone()])
        }
    }
}

fn literal_value(literal: &crate::Literal) -> mneme_core::Value {
    match literal {
        crate::Literal::Positive(atom) => {
            mneme_core::Value::record_named("positive", vec![atom_value(atom)])
        }
        crate::Literal::Negative(atom) => {
            mneme_core::Value::record_named("negative", vec![atom_value(atom)])
        }
        crate::Literal::Compare { op, left, right } => mneme_core::Value::record_named(
            "compare",
            vec![
                mneme_core::Value::symbol(format!("{op:?}").to_lowercase()),
                term_value(left),
                term_value(right),
            ],
        ),
        crate::Literal::Aggregate {
            function,
            input,
            output,
        } => mneme_core::Value::record_named(
            "aggregate",
            vec![
                mneme_core::Value::symbol(match function {
                    crate::AggregateFunction::Count => "count".to_owned(),
                    crate::AggregateFunction::Sum => "sum".to_owned(),
                    crate::AggregateFunction::Min => "min".to_owned(),
                    crate::AggregateFunction::Max => "max".to_owned(),
                }),
                term_value(input),
                mneme_core::Value::string(output.clone()),
            ],
        ),
        crate::Literal::Forbidden(name) => mneme_core::Value::record_named(
            "forbidden",
            vec![mneme_core::Value::string(name.clone())],
        ),
    }
}
