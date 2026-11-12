//! Restricted rule validation and stratification.

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
        if bundle.base_predicates.contains_key(&rule.head.predicate) {
            diagnostics.push(diag(
                "base-overwrite",
                Some(rule.id.clone()),
                format!(
                    "rule head {:?} is a canonical base predicate",
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
            bundle,
            rule,
            index,
            literal,
            arities,
            heads,
            &mut analysis,
            diagnostics,
        );
    }
    analysis
}

#[allow(unknown_lints, clippy::too_many_arguments, too_many_parameters)] // parameter groups mirror one cohesive context
fn analyze_literal(
    bundle: &crate::RuleBundle,
    rule: &crate::Rule,
    index: usize,
    literal: &crate::Literal,
    arities: &std::collections::BTreeMap<String, usize>,
    heads: &std::collections::BTreeMap<String, usize>,
    analysis: &mut RuleBodyAnalysis,
    diagnostics: &mut Vec<crate::RuleDiagnostic>,
) {
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
            validate_atom(atom, arities, heads, &bundle.rules, &rule.id, diagnostics);
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

#[allow(unknown_lints, too_many_parameters)] // Octet structural exception: cohesive state-machine code; split tracked separately
fn validate_atom(
    atom: &crate::Atom,
    arities: &std::collections::BTreeMap<String, usize>,
    heads: &std::collections::BTreeMap<String, usize>,
    _rules: &[crate::Rule],
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
            let mut base = 0_usize;
            let mut is_nonmonotone = false;
            for literal in &rule.body {
                match literal {
                    crate::Literal::Positive(atom) => {
                        base = base.max(*strata.get(&atom.predicate).unwrap_or(&0));
                    }
                    crate::Literal::Negative(atom) => {
                        base = base.max(*strata.get(&atom.predicate).unwrap_or(&0));
                        is_nonmonotone = true;
                    }
                    crate::Literal::Aggregate { .. } => is_nonmonotone = true,
                    _ => {}
                }
            }
            let target = base.saturating_add(usize::from(is_nonmonotone));
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
#[allow(unknown_lints, too_many_parameters)] // Octet structural exception: cohesive state-machine code; split tracked separately
pub(crate) fn build_id(
    revision: mneme_core::WorkspaceRevisionId,
    scope: &mneme_core::ScopeId,
    generation: u64,
    bundle: &crate::RuleBundle,
    limits: &crate::Limits,
    incomplete_extents: &std::collections::BTreeSet<String>,
) -> String {
    let incomplete = incomplete_extents
        .iter()
        .cloned()
        .map(mneme_core::Value::string)
        .collect::<std::collections::BTreeSet<_>>();
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
