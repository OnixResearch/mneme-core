//! Restricted rule validation and stratification.

use std::collections::{BTreeMap, BTreeSet};

use mneme_core::{ContentDigest, ScopeId, Value, WorkspaceRevisionId};

use crate::{
    AggregateFunction, Atom, Limits, Literal, PROFILE_VERSION, RuleBundle, RuleDiagnostic,
    RuleProgram, Term,
};

/// Validate a rule bundle before any evaluation or publication.
pub fn validate(bundle: &RuleBundle) -> Result<RuleProgram, Vec<RuleDiagnostic>> {
    let mut diagnostics = Vec::new();
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
    let mut arities = BTreeMap::new();
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
        arities.insert(predicate.clone(), *arity);
    }
    let mut heads = BTreeMap::new();
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
    for rule in &bundle.rules {
        let mut positive_vars = BTreeSet::new();
        let mut negative_vars = BTreeSet::new();
        let mut compare_vars = BTreeSet::new();
        let mut aggregate = None;
        let mut is_seen_forbidden = false;
        for (index, literal) in rule.body.iter().enumerate() {
            match literal {
                Literal::Forbidden(name) => {
                    is_seen_forbidden = true;
                    diagnostics.push(diag(
                        "forbidden-builtin",
                        Some(rule.id.clone()),
                        format!("forbidden operation {name:?}"),
                    ));
                }
                Literal::Positive(atom) | Literal::Negative(atom) => {
                    validate_atom(
                        atom,
                        &arities,
                        &heads,
                        &bundle.rules,
                        &rule.id,
                        &mut diagnostics,
                    );
                    match literal {
                        Literal::Positive(_) => {
                            positive_vars.extend(atom.terms.iter().filter_map(term_var));
                        }
                        Literal::Negative(_) => {
                            negative_vars.extend(atom.terms.iter().filter_map(term_var));
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
                Literal::Compare { left, right, .. } => {
                    compare_vars.extend(term_var(left));
                    compare_vars.extend(term_var(right));
                }
                Literal::Aggregate { input, output, .. } => {
                    if aggregate.is_some() {
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
                    if positive_vars.contains(output) || negative_vars.contains(output) {
                        diagnostics.push(diag(
                            "aggregate-output-bound",
                            Some(rule.id.clone()),
                            "aggregate output variable must be newly bound",
                        ));
                    }
                    aggregate = Some((input.clone(), output.clone()));
                    if !bundle.complete_predicates.iter().any(|predicate| {
                        rule.body.iter().any(|literal| {
                            matches!(
                                literal,
                                Literal::Positive(atom) if &atom.predicate == predicate
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
        if is_seen_forbidden {
            continue;
        }
        if aggregate.is_some() {
            let mut is_all_positive_complete = true;
            for literal in &rule.body {
                if let Literal::Positive(atom) = literal
                    && !bundle.complete_predicates.contains(&atom.predicate)
                {
                    is_all_positive_complete = false;
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
            if !is_all_positive_complete {
                // The diagnostic above is sufficient.
            }
        }
        let aggregate_output = aggregate.as_ref().map(|(_, output)| output.as_str());
        for variable in head_vars(&rule.head) {
            if aggregate_output.is_some_and(|output| output == variable) {
                continue;
            }
            if !positive_vars.contains(&variable) {
                diagnostics.push(diag(
                    "unsafe-head-variable",
                    Some(rule.id.clone()),
                    format!("head variable {variable:?} is not positively bound"),
                ));
            }
        }
        for variable in negative_vars.iter().chain(compare_vars.iter()) {
            if !positive_vars.contains(variable) {
                diagnostics.push(diag(
                    "unsafe-body-variable",
                    Some(rule.id.clone()),
                    format!("variable {variable:?} is not positively bound"),
                ));
            }
        }
        if let Some((input, _)) = aggregate
            && let Some(variable) = term_var(&input)
            && !positive_vars.contains(&variable)
        {
            diagnostics.push(diag(
                "unsafe-aggregate-variable",
                Some(rule.id.clone()),
                format!("aggregate input variable {variable:?} is not positively bound"),
            ));
        }
    }
    for predicate in &bundle.complete_predicates {
        if !arities.contains_key(predicate) && !heads.contains_key(predicate) {
            diagnostics.push(diag(
                "unknown-complete-predicate",
                None,
                format!("complete predicate {predicate:?} is not declared"),
            ));
        }
    }
    if diagnostics.is_empty() {
        for (predicate, arity) in &heads {
            arities.insert(predicate.clone(), *arity);
        }
        match strata(bundle, &arities) {
            Ok(strata) => Ok(RuleProgram {
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
    atom: &Atom,
    arities: &BTreeMap<String, usize>,
    heads: &BTreeMap<String, usize>,
    _rules: &[crate::Rule],
    rule: &str,
    diagnostics: &mut Vec<RuleDiagnostic>,
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
    bundle: &RuleBundle,
    arities: &BTreeMap<String, usize>,
) -> Result<BTreeMap<String, usize>, Vec<RuleDiagnostic>> {
    let mut strata = arities
        .keys()
        .map(|predicate| (predicate.clone(), 0_usize))
        .collect::<BTreeMap<_, _>>();
    let limit = arities.len() + bundle.rules.len() + 2;
    for _ in 0..limit {
        let mut is_changed = false;
        for rule in &bundle.rules {
            let mut base = 0_usize;
            let mut is_nonmonotone = false;
            for literal in &rule.body {
                match literal {
                    Literal::Positive(atom) => {
                        base = base.max(*strata.get(&atom.predicate).unwrap_or(&0));
                    }
                    Literal::Negative(atom) => {
                        base = base.max(*strata.get(&atom.predicate).unwrap_or(&0));
                        is_nonmonotone = true;
                    }
                    Literal::Aggregate { .. } => is_nonmonotone = true,
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

fn head_vars(atom: &Atom) -> Vec<String> {
    atom.terms.iter().filter_map(term_var).collect()
}

fn term_var(term: &Term) -> Option<String> {
    match term {
        Term::Variable(name) => Some(name.clone()),
        Term::Constant(_) => None,
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

fn diag(code: &'static str, rule: Option<String>, message: impl Into<String>) -> RuleDiagnostic {
    RuleDiagnostic {
        code,
        rule,
        message: message.into(),
    }
}

/// Stable build identity from context and rules.
pub(crate) fn build_id(
    revision: WorkspaceRevisionId,
    scope: &ScopeId,
    generation: u64,
    bundle: &RuleBundle,
    limits: &Limits,
    incomplete_extents: &BTreeSet<String>,
) -> String {
    let incomplete = incomplete_extents
        .iter()
        .cloned()
        .map(Value::string)
        .collect::<BTreeSet<_>>();
    let value = Value::record_named(
        "datalog-build-context",
        vec![
            revision.to_value(),
            scope.to_value(),
            Value::integer(generation as i64),
            Value::string(PROFILE_VERSION.to_owned()),
            bundle_value(bundle),
            Value::record_named(
                "datalog-limits",
                vec![
                    Value::integer(limits.max_work),
                    Value::string(limits.max_time_ms.to_string()),
                    Value::integer(limits.max_result_rows),
                    Value::integer(limits.max_supports_per_fact),
                    Value::integer(limits.max_recursion_depth),
                ],
            ),
            Value::set(incomplete),
        ],
    );
    ContentDigest::of_payload(&value).to_hex()
}

fn bundle_value(bundle: &RuleBundle) -> Value {
    let base = bundle
        .base_predicates
        .iter()
        .map(|(name, arity)| (Value::string(name.clone()), Value::integer(*arity as i64)))
        .collect::<BTreeMap<_, _>>();
    let complete = bundle
        .complete_predicates
        .iter()
        .cloned()
        .map(Value::string)
        .collect::<BTreeSet<_>>();
    let rules = bundle
        .rules
        .iter()
        .map(|rule| {
            Value::record_named(
                "datalog-rule",
                vec![
                    Value::string(rule.id.clone()),
                    atom_value(&rule.head),
                    Value::sequence(rule.body.iter().map(literal_value).collect()),
                ],
            )
        })
        .collect::<BTreeSet<_>>();
    Value::record_named(
        "datalog-bundle",
        vec![
            Value::string(bundle.id.clone()),
            Value::string(bundle.version.clone()),
            Value::integer(i64::from(bundle.schema_version)),
            Value::Dictionary(base),
            Value::set(complete),
            Value::set(rules),
        ],
    )
}

fn atom_value(atom: &Atom) -> Value {
    Value::record_named(
        "datalog-atom",
        vec![
            Value::string(atom.predicate.clone()),
            Value::sequence(atom.terms.iter().map(term_value).collect()),
        ],
    )
}

fn term_value(term: &Term) -> Value {
    match term {
        Term::Variable(name) => {
            Value::record_named("datalog-var", vec![Value::string(name.clone())])
        }
        Term::Constant(value) => Value::record_named("datalog-const", vec![value.clone()]),
    }
}

fn literal_value(literal: &Literal) -> Value {
    match literal {
        Literal::Positive(atom) => Value::record_named("positive", vec![atom_value(atom)]),
        Literal::Negative(atom) => Value::record_named("negative", vec![atom_value(atom)]),
        Literal::Compare { op, left, right } => Value::record_named(
            "compare",
            vec![
                Value::symbol(format!("{op:?}").to_lowercase()),
                term_value(left),
                term_value(right),
            ],
        ),
        Literal::Aggregate {
            function,
            input,
            output,
        } => Value::record_named(
            "aggregate",
            vec![
                Value::symbol(match function {
                    AggregateFunction::Count => "count".to_owned(),
                    AggregateFunction::Sum => "sum".to_owned(),
                    AggregateFunction::Min => "min".to_owned(),
                    AggregateFunction::Max => "max".to_owned(),
                }),
                term_value(input),
                Value::string(output.clone()),
            ],
        ),
        Literal::Forbidden(name) => {
            Value::record_named("forbidden", vec![Value::string(name.clone())])
        }
    }
}
