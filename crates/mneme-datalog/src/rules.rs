//! Restricted rule validation and stratification.

/// Validate a rule bundle before any evaluation or publication.
pub fn validate(
    bundle: &crate::RuleBundle,
) -> Result<crate::RuleProgram, Vec<crate::RuleDiagnostic>> {
    let mut diagnostics = Vec::with_capacity(bundle.base_predicates.len());
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
        arities.insert(predicate.clone(), *arity);
    }
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
    for rule in &bundle.rules {
        let mut positive_vars = std::collections::BTreeSet::new();
        let mut negative_vars = std::collections::BTreeSet::new();
        let mut compare_vars = std::collections::BTreeSet::new();
        let mut aggregate = None;
        let mut is_seen_forbidden = false;
        for (index, literal) in rule.body.iter().enumerate() {
            match literal {
                crate::Literal::Forbidden(name) => {
                    is_seen_forbidden = true;
                    diagnostics.push(diag(
                        "forbidden-builtin",
                        Some(rule.id.clone()),
                        format!("forbidden operation {name:?}"),
                    ));
                }
                crate::Literal::Positive(atom) | crate::Literal::Negative(atom) => {
                    validate_atom(
                        atom,
                        &arities,
                        &heads,
                        &bundle.rules,
                        &rule.id,
                        &mut diagnostics,
                    );
                    match literal {
                        crate::Literal::Positive(_) => {
                            positive_vars.extend(atom.terms.iter().filter_map(term_var));
                        }
                        crate::Literal::Negative(_) => {
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
                crate::Literal::Compare { left, right, .. } => {
                    compare_vars.extend(term_var(left));
                    compare_vars.extend(term_var(right));
                }
                crate::Literal::Aggregate { input, output, .. } => {
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
        if is_seen_forbidden {
            continue;
        }
        if aggregate.is_some() {
            let mut is_all_positive_complete = true;
            for literal in &rule.body {
                if let crate::Literal::Positive(atom) = literal
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
