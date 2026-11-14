//! Real-engine tests for the bounded Prolog worker.
//!
//! Every test here drives the pinned Scryer Prolog 0.10.0 binary named by
//! `MNEME_SCRYER_PROLOG`. The development shell and the Nix check set that
//! variable; when it is missing these tests fail loudly instead of passing
//! without running an engine.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::expect_used)]

// The check environment names the pinned engine; the worker only ever receives
// the resolved absolute path, so this is the file's only environment read.
#[allow(unknown_lints, ambient_env)]
fn engine() -> std::path::PathBuf {
    let value = std::env::var("MNEME_SCRYER_PROLOG").unwrap_or_default();
    assert!(
        !value.trim().is_empty(),
        "MNEME_SCRYER_PROLOG is not set: this test needs the pinned Scryer Prolog 0.10.0 \
         executable, which the development shell and the Nix check provide. It must not pass \
         without running a real engine."
    );
    let path = std::path::PathBuf::from(value);
    assert!(
        path.is_file(),
        "MNEME_SCRYER_PROLOG does not name a file; it must be the pinned Scryer Prolog 0.10.0 \
         executable"
    );
    path
}

fn scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
}

fn revision() -> mneme_core::WorkspaceRevisionId {
    mneme_core::WorkspaceRevisionId::from_bytes([0xb0; 16])
}

const GENERATION: u64 = 7;

fn subject(byte: u8) -> mneme_core::RecordId {
    mneme_core::RecordId::from_bytes([byte; 16])
}

fn metadata() -> mneme_prolog::CapabilityMetadata {
    mneme_prolog::CapabilityMetadata {
        adapter_version: "1".to_owned(),
        profile: "positive-minimal/v1".to_owned(),
        engine: Some(mneme_prolog::EngineIdentity {
            name: "scryer-prolog".to_owned(),
            version: "0.10.0".to_owned(),
            source_revision: "nixpkgs-pinned".to_owned(),
        }),
        state: mneme_prolog::CapabilityState::Enabled,
        features: std::collections::BTreeSet::from([mneme_prolog::Feature::PositiveQuery]),
        allowed_predicates: std::collections::BTreeSet::from([
            "assertion".to_owned(),
            "relation".to_owned(),
            "path".to_owned(),
            "derived".to_owned(),
            "loop".to_owned(),
            "missing".to_owned(),
        ]),
        limits: mneme_prolog::ProfileLimits {
            max_time_ms: 5_000,
            max_solutions: 16,
            max_output_bytes: 65_536,
            max_term_depth: 8,
            max_rule_count: 4,
        },
        terms: mneme_prolog::TermProfile {
            max_depth: 8,
            max_collection: 32,
            references_allowed: false,
        },
    }
}

fn context() -> mneme_prolog::SearchContext {
    mneme_prolog::SearchContext {
        revision: revision(),
        scope: scope(),
        eligibility_generation: GENERATION,
        image_digest: String::new(),
        profile: "positive-minimal/v1".to_owned(),
        rule_versions: std::collections::BTreeMap::new(),
    }
}

fn fact(
    predicate: &str,
    subject_byte: u8,
    value: mneme_core::Value,
) -> mneme_prolog::snapshot::CanonicalFact {
    mneme_prolog::snapshot::CanonicalFact {
        record_id: subject(subject_byte.wrapping_add(0x40)),
        revision_id: mneme_core::RevisionId::from_bytes([subject_byte.wrapping_add(0x20); 16]),
        scope: scope(),
        subject: subject(subject_byte),
        predicate: predicate.to_owned(),
        value,
        valid_time: mneme_core::ValidTime::always(),
    }
}

fn input_image(
    canonical: Vec<mneme_prolog::snapshot::CanonicalFact>,
    relations: Vec<mneme_prolog::snapshot::SelectedRelation>,
) -> mneme_prolog::snapshot::InputImage {
    let mut image = mneme_prolog::snapshot::InputImage {
        context: context(),
        canonical,
        relations,
        coverage: mneme_prolog::InputCoverage {
            complete: true,
            reason: None,
        },
    };
    image.seal();
    image
}

fn relation(
    name: &str,
    rows: Vec<Vec<mneme_core::Value>>,
) -> mneme_prolog::snapshot::SelectedRelation {
    mneme_prolog::snapshot::SelectedRelation {
        predicate: name.to_owned(),
        rows: rows
            .into_iter()
            .map(|values| mneme_prolog::snapshot::SelectedRow {
                values,
                supports: Vec::new(),
            })
            .collect(),
        coverage: mneme_prolog::InputCoverage {
            complete: true,
            reason: None,
        },
    }
}

fn string(value: &str) -> mneme_core::Value {
    mneme_core::Value::string(value)
}

fn atom(predicate: &str, terms: Vec<mneme_prolog::Term>) -> mneme_prolog::Atom {
    mneme_prolog::Atom {
        predicate: predicate.to_owned(),
        terms,
    }
}

fn request_for(
    image: &mneme_prolog::snapshot::InputImage,
    goal: mneme_prolog::Atom,
    rules: Vec<mneme_prolog::Rule>,
) -> mneme_prolog::Request {
    let variables = mneme_prolog::goal_variables(&goal)
        .into_iter()
        .map(|name| mneme_prolog::QueryVariable {
            name,
            role: mneme_prolog::VariableRole::Output,
        })
        .collect();
    mneme_prolog::Request {
        actor: "agent".to_owned(),
        scope: scope(),
        revision: revision(),
        eligibility_generation: GENERATION,
        image_digest: image.context.image_digest.clone(),
        mode: mneme_prolog::QueryMode::Enumerate,
        goal,
        variables,
        rules,
        assumptions: Vec::new(),
        features: std::collections::BTreeSet::from([mneme_prolog::Feature::PositiveQuery]),
        limits: mneme_prolog::RequestLimits {
            max_time_ms: 2_000,
            max_solutions: 8,
            max_output_bytes: 8_192,
        },
    }
}

fn with_mode(
    mut request: mneme_prolog::Request,
    mode: mneme_prolog::QueryMode,
) -> mneme_prolog::Request {
    request.mode = mode;
    request
}

fn limits() -> mneme_prolog::process::WorkerLimits {
    mneme_prolog::process::WorkerLimits {
        max_wall_ms: 2_000,
        max_output_bytes: 8_192,
    }
}

fn run(
    metadata: &mneme_prolog::CapabilityMetadata,
    image: &mneme_prolog::snapshot::InputImage,
    request: &mneme_prolog::Request,
    limits: mneme_prolog::process::WorkerLimits,
) -> Result<mneme_prolog::Outcome, mneme_prolog::CapabilityError> {
    mneme_prolog::run_query(
        &engine(),
        metadata,
        image,
        request,
        &mneme_prolog::process::WorkerControl::new(),
        limits,
    )
}

fn bound_string(solution: &mneme_prolog::Solution, name: &str) -> String {
    let binding = solution.bindings.get(name);
    let found = binding.and_then(|term| match term {
        mneme_prolog::Term::String(text) => Some(text.clone()),
        mneme_prolog::Term::Integer(_)
        | mneme_prolog::Term::Symbol(_)
        | mneme_prolog::Term::Variable(_)
        | mneme_prolog::Term::Reference { .. }
        | mneme_prolog::Term::List(_)
        | mneme_prolog::Term::Compound { .. } => None,
    });
    assert!(
        found.is_some(),
        "binding {name} is not the expected string: {binding:?}"
    );
    found.expect("binding was asserted to hold a string")
}

fn solutions(outcome: &mneme_prolog::Outcome) -> &[mneme_prolog::Solution] {
    match &outcome.result {
        mneme_prolog::QueryResult::GroundTest { .. } => &[],
        mneme_prolog::QueryResult::FindOne { solution } => solution.as_slice(),
        mneme_prolog::QueryResult::Enumerate { solutions }
        | mneme_prolog::QueryResult::Collect { solutions } => solutions,
    }
}

fn sorted_strings(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort();
    values
}

fn rule(
    id: &str,
    head: mneme_prolog::Atom,
    body: Vec<mneme_prolog::Literal>,
) -> mneme_prolog::Rule {
    mneme_prolog::Rule {
        id: id.to_owned(),
        version: "1".to_owned(),
        head,
        body,
    }
}

fn fact_rule(id: &str, head: mneme_prolog::Atom) -> mneme_prolog::Rule {
    rule(id, head, Vec::new())
}

#[test]
fn ground_goal_over_image_facts_succeeds() {
    let canonical = subject(0x10).to_hex();
    let image = input_image(
        vec![
            fact("path", 0x10, string("a")),
            fact("path", 0x11, string("b")),
        ],
        Vec::new(),
    );
    let request = request_for(
        &image,
        atom(
            "assertion",
            vec![
                mneme_prolog::Term::String("path".to_owned()),
                mneme_prolog::Term::String(canonical.clone()),
                mneme_prolog::Term::String("a".to_owned()),
            ],
        ),
        Vec::new(),
    );
    let outcome = run(&metadata(), &image, &request, limits()).expect("query");
    assert_eq!(outcome.status, mneme_prolog::ExecutionStatus::Complete);
    assert!(
        outcome.exhaustive,
        "ground goal was not reported exhaustive"
    );
    assert_eq!(solutions(&outcome).len(), 1);
    assert!(solutions(&outcome)[0].bindings.is_empty());
    assert!(outcome.proposals.is_empty());
    assert_eq!(outcome.consumed.solutions, 1);
    outcome
        .validate_for_request(&request)
        .expect("qualified outcome");

    // The same ground goal with a different value has no solution but still
    // completes exhaustively, because the image defines the relation.
    let absent = request_for(
        &image,
        atom(
            "assertion",
            vec![
                mneme_prolog::Term::String("path".to_owned()),
                mneme_prolog::Term::String(canonical),
                mneme_prolog::Term::String("zzz".to_owned()),
            ],
        ),
        Vec::new(),
    );
    let outcome = run(&metadata(), &image, &absent, limits()).expect("query");
    assert_eq!(outcome.status, mneme_prolog::ExecutionStatus::Complete);
    assert!(outcome.exhaustive);
    assert!(solutions(&outcome).is_empty());
}

#[test]
fn goal_with_variables_returns_expected_bindings() {
    let canonical = subject(0x12).to_hex();
    let image = input_image(
        vec![
            fact("path", 0x12, string("a")),
            fact("path", 0x12, string("b")),
            fact("path", 0x13, string("c")),
        ],
        Vec::new(),
    );
    let request = request_for(
        &image,
        atom(
            "assertion",
            vec![
                mneme_prolog::Term::String("path".to_owned()),
                mneme_prolog::Term::String(canonical.clone()),
                mneme_prolog::Term::Variable("X".to_owned()),
            ],
        ),
        Vec::new(),
    );
    let outcome = run(&metadata(), &image, &request, limits()).expect("query");
    assert_eq!(outcome.status, mneme_prolog::ExecutionStatus::Complete);
    assert!(outcome.exhaustive);
    let values = sorted_strings(
        solutions(&outcome)
            .iter()
            .map(|solution| bound_string(solution, "X")),
    );
    assert_eq!(values, vec!["a".to_owned(), "b".to_owned()]);
    for solution in solutions(&outcome) {
        assert_eq!(bound_string(solution, "X").len(), 1);
        assert!(matches!(
            solution.certification,
            mneme_prolog::Certification::Uncertified { .. }
        ));
        assert!(solution.premises.is_empty());
    }
    assert_eq!(
        mneme_prolog::goal_variables(&request.goal),
        vec!["X".to_owned()]
    );

    // Selected relation rows are queryable the same way, and the bindings are
    // the exact ground values from the image.
    let relations = input_image(
        Vec::new(),
        vec![relation(
            "ancestor",
            vec![
                vec![mneme_core::Value::integer(1), mneme_core::Value::integer(2)],
                vec![mneme_core::Value::integer(2), mneme_core::Value::integer(3)],
            ],
        )],
    );
    let request = request_for(
        &relations,
        atom(
            "relation",
            vec![
                mneme_prolog::Term::String("ancestor".to_owned()),
                mneme_prolog::Term::Variable("Row".to_owned()),
            ],
        ),
        Vec::new(),
    );
    let outcome = run(&metadata(), &relations, &request, limits()).expect("query");
    assert_eq!(outcome.status, mneme_prolog::ExecutionStatus::Complete);
    assert_eq!(solutions(&outcome).len(), 2);
    for expected in [
        mneme_prolog::Term::List(vec![
            mneme_prolog::Term::Integer(1),
            mneme_prolog::Term::Integer(2),
        ]),
        mneme_prolog::Term::List(vec![
            mneme_prolog::Term::Integer(2),
            mneme_prolog::Term::Integer(3),
        ]),
    ] {
        assert!(
            solutions(&outcome)
                .iter()
                .any(|solution| solution.bindings.get("Row") == Some(&expected)),
            "missing selected relation row {expected:?}"
        );
    }
}

#[test]
fn ground_test_distinguishes_true_false_and_incomplete_unknown() {
    let image = input_image(vec![fact("path", 0x20, string("a"))], Vec::new());
    let ground_goal = |value: &str| {
        atom(
            "assertion",
            vec![
                mneme_prolog::Term::String("path".to_owned()),
                mneme_prolog::Term::String(subject(0x20).to_hex()),
                mneme_prolog::Term::String(value.to_owned()),
            ],
        )
    };

    let true_request = with_mode(
        request_for(&image, ground_goal("a"), Vec::new()),
        mneme_prolog::QueryMode::GroundTest,
    );
    let true_outcome = run(&metadata(), &image, &true_request, limits()).expect("true test");
    assert_eq!(true_outcome.status, mneme_prolog::ExecutionStatus::Complete);
    assert!(true_outcome.exhaustive);
    assert_eq!(true_outcome.stop, mneme_prolog::SearchStop::GroundSuccess);
    assert_eq!(
        true_outcome.result,
        mneme_prolog::QueryResult::GroundTest {
            truth: mneme_prolog::QueryTruth::True,
        }
    );

    let false_request = with_mode(
        request_for(&image, ground_goal("missing"), Vec::new()),
        mneme_prolog::QueryMode::GroundTest,
    );
    let false_outcome = run(&metadata(), &image, &false_request, limits()).expect("false test");
    assert_eq!(
        false_outcome.status,
        mneme_prolog::ExecutionStatus::Complete
    );
    assert!(false_outcome.exhaustive);
    assert_eq!(false_outcome.stop, mneme_prolog::SearchStop::GroundFailure);
    assert_eq!(
        false_outcome.result,
        mneme_prolog::QueryResult::GroundTest {
            truth: mneme_prolog::QueryTruth::False,
        }
    );

    let mut incomplete = image.clone();
    incomplete.coverage.complete = false;
    incomplete.coverage.reason = Some("the selected input was incomplete".to_owned());
    incomplete.seal();
    let unknown_request = with_mode(
        request_for(&incomplete, ground_goal("missing"), Vec::new()),
        mneme_prolog::QueryMode::GroundTest,
    );
    let unknown =
        run(&metadata(), &incomplete, &unknown_request, limits()).expect("incomplete ground test");
    assert_eq!(unknown.status, mneme_prolog::ExecutionStatus::Complete);
    assert!(!unknown.exhaustive);
    assert_eq!(unknown.stop, mneme_prolog::SearchStop::GroundFailure);
    assert_eq!(
        unknown.result,
        mneme_prolog::QueryResult::GroundTest {
            truth: mneme_prolog::QueryTruth::Unknown,
        }
    );
    unknown
        .validate_for_request(&unknown_request)
        .expect("incomplete coverage is not a negative proof");
}

#[test]
fn find_one_searches_the_complete_qualifying_goal() {
    let first_subject = subject(0x21);
    let second_subject = subject(0x22);
    let mut eligible = fact("eligible", 0x23, string("yes"));
    eligible.subject = second_subject;
    let image = input_image(
        vec![
            fact("path", 0x21, string("first")),
            fact("path", 0x22, string("second")),
            eligible,
        ],
        Vec::new(),
    );
    let rules = vec![rule(
        "qualified-path",
        atom(
            "qualified",
            vec![mneme_prolog::Term::Variable("X".to_owned())],
        ),
        vec![
            mneme_prolog::Literal::Positive(atom(
                "assertion",
                vec![
                    mneme_prolog::Term::String("path".to_owned()),
                    mneme_prolog::Term::Variable("S".to_owned()),
                    mneme_prolog::Term::Variable("X".to_owned()),
                ],
            )),
            mneme_prolog::Literal::Positive(atom(
                "assertion",
                vec![
                    mneme_prolog::Term::String("eligible".to_owned()),
                    mneme_prolog::Term::Variable("S".to_owned()),
                    mneme_prolog::Term::String("yes".to_owned()),
                ],
            )),
        ],
    )];
    let request = with_mode(
        request_for(
            &image,
            atom(
                "qualified",
                vec![mneme_prolog::Term::Variable("X".to_owned())],
            ),
            rules,
        ),
        mneme_prolog::QueryMode::FindOne,
    );
    let mut profile = metadata();
    profile.allowed_predicates.insert("qualified".to_owned());
    let outcome = run(&profile, &image, &request, limits()).expect("qualifying search");
    assert_eq!(outcome.status, mneme_prolog::ExecutionStatus::Complete);
    assert!(outcome.operation_completed);
    assert!(!outcome.exhaustive);
    assert_eq!(outcome.stop, mneme_prolog::SearchStop::FoundOne);
    let solution = match &outcome.result {
        mneme_prolog::QueryResult::FindOne { solution } => solution.as_ref(),
        mneme_prolog::QueryResult::GroundTest { .. }
        | mneme_prolog::QueryResult::Enumerate { .. }
        | mneme_prolog::QueryResult::Collect { .. } => None,
    }
    .expect("find-one result contains a qualifying solution");
    assert_eq!(
        solution.bindings.get("X"),
        Some(&mneme_prolog::Term::String("second".to_owned()))
    );
    assert_ne!(first_subject, second_subject);
}

#[test]
fn enumerate_and_collect_report_duplicate_and_capped_bindings_truthfully() {
    let image = input_image(
        vec![
            fact("path", 0x24, string("a")),
            fact("path", 0x25, string("b")),
            fact("other", 0x26, string("a")),
        ],
        Vec::new(),
    );
    let derived = || {
        atom(
            "derived",
            vec![mneme_prolog::Term::Variable("X".to_owned())],
        )
    };
    let assertion_rule = |id: &str, predicate: &str, subject_byte: u8| {
        rule(
            id,
            derived(),
            vec![mneme_prolog::Literal::Positive(atom(
                "assertion",
                vec![
                    mneme_prolog::Term::String(predicate.to_owned()),
                    mneme_prolog::Term::String(subject(subject_byte).to_hex()),
                    mneme_prolog::Term::Variable("X".to_owned()),
                ],
            ))],
        )
    };
    let rules = vec![
        assertion_rule("path-a", "path", 0x24),
        assertion_rule("path-b", "path", 0x25),
        assertion_rule("other-a", "other", 0x26),
    ];
    let mut profile = metadata();
    profile.allowed_predicates.insert("derived".to_owned());

    let mut exact_enumeration = request_for(&image, derived(), rules.clone());
    exact_enumeration.limits.max_solutions = 3;
    let exact = run(&profile, &image, &exact_enumeration, limits()).expect("exact enumeration");
    assert_eq!(exact.status, mneme_prolog::ExecutionStatus::Complete);
    assert!(exact.exhaustive);
    assert_eq!(exact.stop, mneme_prolog::SearchStop::Exhausted);
    assert_eq!(solutions(&exact).len(), 3);
    assert_eq!(
        sorted_strings(
            solutions(&exact)
                .iter()
                .map(|solution| bound_string(solution, "X"))
        ),
        vec!["a".to_owned(), "a".to_owned(), "b".to_owned()]
    );
    assert!(
        solutions(&exact)
            .iter()
            .all(|solution| solution.independent_support_count() == 0)
    );
    let repeated = run(&profile, &image, &exact_enumeration, limits()).expect("repeat");
    assert_eq!(solutions(&repeated), solutions(&exact));

    let mut capped_enumeration = exact_enumeration.clone();
    capped_enumeration.limits.max_solutions = 2;
    let capped = run(&profile, &image, &capped_enumeration, limits()).expect("capped enumeration");
    assert_eq!(capped.status, mneme_prolog::ExecutionStatus::Partial);
    assert!(!capped.exhaustive);
    assert_eq!(capped.stop, mneme_prolog::SearchStop::ResultLimit);
    assert!(capped.solution_limit_exceeded);
    assert_eq!(solutions(&capped).len(), 2);

    let mut exact_collection = exact_enumeration.clone();
    exact_collection.mode = mneme_prolog::QueryMode::Collect;
    exact_collection.limits.max_solutions = 2;
    let collected = run(&profile, &image, &exact_collection, limits()).expect("collection");
    assert_eq!(collected.status, mneme_prolog::ExecutionStatus::Complete);
    assert!(collected.exhaustive);
    assert_eq!(collected.stop, mneme_prolog::SearchStop::Exhausted);
    assert_eq!(solutions(&collected).len(), 2);
    assert_eq!(
        solutions(&collected)
            .iter()
            .map(|solution| bound_string(solution, "X"))
            .collect::<Vec<_>>(),
        vec!["a".to_owned(), "b".to_owned()]
    );

    let mut capped_collection = exact_collection;
    capped_collection.limits.max_solutions = 1;
    let capped = run(&profile, &image, &capped_collection, limits()).expect("capped collection");
    assert_eq!(capped.status, mneme_prolog::ExecutionStatus::Partial);
    assert!(!capped.exhaustive);
    assert_eq!(capped.stop, mneme_prolog::SearchStop::ResultLimit);
    assert!(capped.solution_limit_exceeded);
    assert_eq!(solutions(&capped).len(), 1);
}

#[test]
fn local_query_variables_are_not_returned_as_bindings() {
    let image = input_image(vec![fact("path", 0x27, string("secret-local"))], Vec::new());
    let mut request = request_for(
        &image,
        atom(
            "assertion",
            vec![
                mneme_prolog::Term::String("path".to_owned()),
                mneme_prolog::Term::String(subject(0x27).to_hex()),
                mneme_prolog::Term::Variable("Hidden".to_owned()),
            ],
        ),
        Vec::new(),
    );
    request.mode = mneme_prolog::QueryMode::Enumerate;
    request.variables[0].role = mneme_prolog::VariableRole::Local;
    let outcome = run(&metadata(), &image, &request, limits()).expect("local variable query");
    assert_eq!(outcome.status, mneme_prolog::ExecutionStatus::Complete);
    assert!(outcome.exhaustive);
    assert_eq!(solutions(&outcome).len(), 1);
    assert!(solutions(&outcome)[0].bindings.is_empty());
}

#[test]
fn rule_derives_a_fact_from_the_image() {
    let canonical = subject(0x14).to_hex();
    let image = input_image(vec![fact("path", 0x14, string("source"))], Vec::new());
    let rules = vec![
        fact_rule(
            "path-a",
            atom("path", vec![mneme_prolog::Term::String("a".to_owned())]),
        ),
        rule(
            "path-b",
            atom("path", vec![mneme_prolog::Term::String("b".to_owned())]),
            vec![mneme_prolog::Literal::Positive(atom(
                "assertion",
                vec![
                    mneme_prolog::Term::String("path".to_owned()),
                    mneme_prolog::Term::String(canonical),
                    mneme_prolog::Term::String("source".to_owned()),
                ],
            ))],
        ),
    ];
    let request = request_for(
        &image,
        atom("path", vec![mneme_prolog::Term::Variable("X".to_owned())]),
        rules,
    );
    let outcome = run(&metadata(), &image, &request, limits()).expect("query");
    assert_eq!(outcome.status, mneme_prolog::ExecutionStatus::Complete);
    assert!(outcome.exhaustive);
    assert_eq!(
        sorted_strings(
            solutions(&outcome)
                .iter()
                .map(|solution| bound_string(solution, "X"))
        ),
        vec!["a".to_owned(), "b".to_owned()]
    );
}

#[test]
fn rule_with_variables_derives_bindings() {
    // A rule head variable that occurs in the body is a real rule: the engine
    // binds it from the image facts and reports it through the goal variable.
    let canonical = subject(0x18).to_hex();
    let image = input_image(
        vec![
            fact("path", 0x18, string("a")),
            fact("path", 0x18, string("b")),
        ],
        Vec::new(),
    );
    let rules = vec![rule(
        "derived",
        atom(
            "derived",
            vec![mneme_prolog::Term::Variable("X".to_owned())],
        ),
        vec![mneme_prolog::Literal::Positive(atom(
            "assertion",
            vec![
                mneme_prolog::Term::String("path".to_owned()),
                mneme_prolog::Term::String(canonical),
                mneme_prolog::Term::Variable("X".to_owned()),
            ],
        ))],
    )];
    let request = request_for(
        &image,
        atom(
            "derived",
            vec![mneme_prolog::Term::Variable("X".to_owned())],
        ),
        rules,
    );
    let outcome = run(&metadata(), &image, &request, limits()).expect("query");
    assert_eq!(outcome.status, mneme_prolog::ExecutionStatus::Complete);
    assert!(outcome.exhaustive);
    assert_eq!(
        sorted_strings(
            solutions(&outcome)
                .iter()
                .map(|solution| bound_string(solution, "X"))
        ),
        vec!["a".to_owned(), "b".to_owned()]
    );
}

#[test]
fn two_variable_goal_returns_exact_bindings() {
    // Two bindings are printed on one line, separated by a printed comma; the
    // strict parser must recover both, including a negative integer value.
    let image = input_image(
        vec![
            fact("path", 0x19, mneme_core::Value::integer(-7)),
            fact("path", 0x1a, mneme_core::Value::integer(42)),
        ],
        Vec::new(),
    );
    let request = request_for(
        &image,
        atom(
            "assertion",
            vec![
                mneme_prolog::Term::String("path".to_owned()),
                mneme_prolog::Term::Variable("S".to_owned()),
                mneme_prolog::Term::Variable("V".to_owned()),
            ],
        ),
        Vec::new(),
    );
    let outcome = run(&metadata(), &image, &request, limits()).expect("query");
    assert_eq!(outcome.status, mneme_prolog::ExecutionStatus::Complete);
    assert!(outcome.exhaustive);
    assert_eq!(solutions(&outcome).len(), 2);
    for (subject_byte, value) in [(0x19_u8, -7_i64), (0x1a, 42)] {
        let expected_subject = mneme_prolog::Term::String(subject(subject_byte).to_hex());
        let expected_value = mneme_prolog::Term::Integer(value);
        assert!(
            solutions(&outcome).iter().any(|solution| {
                solution.bindings.get("S") == Some(&expected_subject)
                    && solution.bindings.get("V") == Some(&expected_value)
            }),
            "missing bindings S={expected_subject:?} V={expected_value:?}"
        );
    }
    for solution in solutions(&outcome) {
        assert_eq!(solution.bindings.len(), 2);
    }
}

#[test]
fn escaped_values_with_separators_round_trip() {
    // A value that itself contains the binding separator, a quote, a backslash
    // and a newline must come back exactly; the engine quotes and escapes it,
    // and the parser reads it inside the quoted term.
    let payload = "a,b\"c\\d\ne\u{0}λ☃🧠";
    let image = input_image(vec![fact("path", 0x1b, string(payload))], Vec::new());
    let request = request_for(
        &image,
        atom(
            "assertion",
            vec![
                mneme_prolog::Term::String("path".to_owned()),
                mneme_prolog::Term::Variable("S".to_owned()),
                mneme_prolog::Term::Variable("V".to_owned()),
            ],
        ),
        Vec::new(),
    );
    let outcome = run(&metadata(), &image, &request, limits()).expect("query");
    assert_eq!(outcome.status, mneme_prolog::ExecutionStatus::Complete);
    assert!(outcome.exhaustive);
    assert_eq!(solutions(&outcome).len(), 1);
    assert_eq!(
        solutions(&outcome)[0].bindings.get("S"),
        Some(&mneme_prolog::Term::String(subject(0x1b).to_hex()))
    );
    assert_eq!(bound_string(&solutions(&outcome)[0], "V"), payload);
}

#[test]
fn multi_binding_solution_stream_is_counted_and_limited() {
    // An infinite stream of two-binding answers: the solution budget counts
    // solution lines (not bindings), returns exactly the budget and stays
    // non-exhaustive.
    let image = input_image(
        vec![fact("path", 0x1c, mneme_core::Value::integer(-7))],
        Vec::new(),
    );
    let rules = vec![
        fact_rule(
            "pair",
            atom(
                "derived",
                vec![
                    mneme_prolog::Term::String(subject(0x1c).to_hex()),
                    mneme_prolog::Term::Integer(-7),
                ],
            ),
        ),
        rule(
            "pair-loop",
            atom(
                "derived",
                vec![
                    mneme_prolog::Term::Variable("S".to_owned()),
                    mneme_prolog::Term::Variable("V".to_owned()),
                ],
            ),
            vec![mneme_prolog::Literal::Positive(atom(
                "derived",
                vec![
                    mneme_prolog::Term::Variable("S".to_owned()),
                    mneme_prolog::Term::Variable("V".to_owned()),
                ],
            ))],
        ),
    ];
    let mut request = request_for(
        &image,
        atom(
            "derived",
            vec![
                mneme_prolog::Term::Variable("S".to_owned()),
                mneme_prolog::Term::Variable("V".to_owned()),
            ],
        ),
        rules,
    );
    request.limits.max_solutions = 2;
    request.limits.max_output_bytes = 65_536;
    let outcome = run(
        &metadata(),
        &image,
        &request,
        mneme_prolog::process::WorkerLimits {
            max_wall_ms: 2_000,
            max_output_bytes: 65_536,
        },
    )
    .expect("solution-limited query");
    assert_eq!(outcome.status, mneme_prolog::ExecutionStatus::Partial);
    assert!(!outcome.exhaustive);
    assert_eq!(solutions(&outcome).len(), 2);
    assert!(outcome.consumed.solutions > request.limits.max_solutions);
    assert!(outcome.consumed.output_bytes > 0);
    assert_eq!(outcome.stop, mneme_prolog::SearchStop::ResultLimit);
    for solution in solutions(&outcome) {
        assert_eq!(solution.bindings.len(), 2);
        assert_eq!(
            solution.bindings.get("S"),
            Some(&mneme_prolog::Term::String(subject(0x1c).to_hex()))
        );
        assert_eq!(
            solution.bindings.get("V"),
            Some(&mneme_prolog::Term::Integer(-7))
        );
    }
}

#[test]
fn multi_binding_output_is_stopped_at_the_byte_limit() {
    // One answer with two bindings whose printed line is longer than the whole
    // output budget: the byte limit must hold whether the worker is caught
    // mid-flight or the engine finishes first.
    let long = "x".repeat(200);
    let image = input_image(vec![fact("path", 0x1d, string(&long))], Vec::new());
    let request = request_for(
        &image,
        atom(
            "assertion",
            vec![
                mneme_prolog::Term::String("path".to_owned()),
                mneme_prolog::Term::Variable("S".to_owned()),
                mneme_prolog::Term::Variable("V".to_owned()),
            ],
        ),
        Vec::new(),
    );
    let outcome = run(
        &metadata(),
        &image,
        &request,
        mneme_prolog::process::WorkerLimits {
            max_wall_ms: 2_000,
            max_output_bytes: 64,
        },
    )
    .expect("byte-limited query");
    assert_eq!(outcome.status, mneme_prolog::ExecutionStatus::Partial);
    assert!(!outcome.exhaustive);
    assert!(outcome.consumed.output_bytes <= 64);
    assert_eq!(outcome.stop, mneme_prolog::SearchStop::OutputLimit);
}

#[test]
fn missing_relation_answers_with_no_solutions() {
    let image = input_image(Vec::new(), Vec::new());
    let request = request_for(
        &image,
        atom("missing", vec![mneme_prolog::Term::String("x".to_owned())]),
        Vec::new(),
    );
    let outcome = run(&metadata(), &image, &request, limits()).expect("query");
    assert_eq!(outcome.status, mneme_prolog::ExecutionStatus::Complete);
    assert!(outcome.exhaustive);
    assert!(solutions(&outcome).is_empty());
}

#[test]
fn injection_text_is_refused_as_program_text_and_neutralized_as_data() {
    let metadata = metadata();
    let image = input_image(Vec::new(), Vec::new());
    let absent_engine = std::path::Path::new("/nonexistent/mneme-test-engine");

    // A symbol whose text would close the term and start a second goal is
    // refused, and the refusal happens before any process is spawned: the
    // engine path does not exist, so reaching the spawn would surface a
    // different error.
    let symbol_request = request_for(
        &image,
        atom(
            "assertion",
            vec![mneme_prolog::Term::Symbol(
                "a), consult(other_file".to_owned(),
            )],
        ),
        Vec::new(),
    );
    assert_eq!(
        metadata.ensure_request(&symbol_request),
        Err(mneme_prolog::CapabilityError::InvalidRequest(
            "predicate or functor text is not permitted".to_owned()
        ))
    );
    assert!(matches!(
        mneme_prolog::run_query(
            absent_engine,
            &metadata,
            &image,
            &symbol_request,
            &mneme_prolog::process::WorkerControl::new(),
            limits()
        ),
        Err(mneme_prolog::CapabilityError::InvalidRequest(_))
    ));

    // A compound functor that names a forbidden predicate is refused before
    // rendering, again without a process.
    let functor_request = request_for(
        &image,
        atom(
            "assertion",
            vec![mneme_prolog::Term::Compound {
                functor: "shell".to_owned(),
                args: vec![mneme_prolog::Term::Integer(1)],
            }],
        ),
        Vec::new(),
    );
    assert_eq!(
        metadata.ensure_request(&functor_request),
        Err(mneme_prolog::CapabilityError::DisallowedPredicate(
            "shell".to_owned()
        ))
    );
    assert!(matches!(
        mneme_prolog::run_query(
            absent_engine,
            &metadata,
            &image,
            &functor_request,
            &mneme_prolog::process::WorkerControl::new(),
            limits()
        ),
        Err(mneme_prolog::CapabilityError::DisallowedPredicate(_))
    ));

    // The same text as a string is data: the encoder quotes every quote,
    // backslash and control character, so the engine sees one literal. The
    // round trip proves the text never became program text.
    let payload = "a\"), consult(other_file(\"x\"\n";
    let canonical = subject(0x15).to_hex();
    let probe = input_image(vec![fact("path", 0x15, string(payload))], Vec::new());
    let string_request = request_for(
        &probe,
        atom(
            "assertion",
            vec![
                mneme_prolog::Term::String("path".to_owned()),
                mneme_prolog::Term::String(canonical),
                mneme_prolog::Term::Variable("V".to_owned()),
            ],
        ),
        Vec::new(),
    );
    let outcome = run(&metadata, &probe, &string_request, limits()).expect("query");
    assert_eq!(outcome.status, mneme_prolog::ExecutionStatus::Complete);
    assert_eq!(solutions(&outcome).len(), 1);
    assert_eq!(bound_string(&solutions(&outcome)[0], "V"), payload);

    // The goal itself may carry injection-shaped text as a string argument: it
    // stays a literal, so the goal simply has no solution.
    let literal_request = request_for(
        &probe,
        atom(
            "assertion",
            vec![mneme_prolog::Term::String(
                "a\"), consult(other_file(".to_owned(),
            )],
        ),
        Vec::new(),
    );
    let outcome = run(&metadata, &probe, &literal_request, limits()).expect("query");
    assert_eq!(outcome.status, mneme_prolog::ExecutionStatus::Complete);
    assert!(outcome.exhaustive);
    assert!(solutions(&outcome).is_empty());

    // A string longer than the whole encoded-program budget is refused before
    // the engine starts, so no request can make the script unbounded.
    let oversized = request_for(
        &probe,
        atom(
            "assertion",
            vec![mneme_prolog::Term::String("x".repeat(70_000))],
        ),
        Vec::new(),
    );
    assert!(matches!(
        mneme_prolog::run_query(
            absent_engine,
            &metadata,
            &probe,
            &oversized,
            &mneme_prolog::process::WorkerControl::new(),
            limits()
        ),
        Err(mneme_prolog::CapabilityError::LimitExceeded(_))
    ));
}

#[test]
fn non_terminating_goal_is_stopped_at_the_time_limit() {
    let image = input_image(Vec::new(), Vec::new());
    let rules = vec![rule(
        "loop",
        atom("loop", vec![mneme_prolog::Term::String("a".to_owned())]),
        vec![mneme_prolog::Literal::Positive(atom(
            "loop",
            vec![mneme_prolog::Term::String("a".to_owned())],
        ))],
    )];
    let mut request = request_for(
        &image,
        atom("loop", vec![mneme_prolog::Term::String("a".to_owned())]),
        rules,
    );
    request.limits.max_time_ms = 200;
    let outcome = run(
        &metadata(),
        &image,
        &request,
        mneme_prolog::process::WorkerLimits {
            max_wall_ms: 2_000,
            max_output_bytes: 8_192,
        },
    )
    .expect("timed-out query");
    assert_eq!(outcome.status, mneme_prolog::ExecutionStatus::Timeout);
    assert!(!outcome.exhaustive);
    assert!(
        outcome.consumed.elapsed_ms < 1_500,
        "timeout was not enforced promptly"
    );
    assert!(solutions(&outcome).is_empty());

    // Independent work stays available: a fresh bounded query over the same
    // image still completes.
    let next = request_for(
        &image,
        atom("missing", vec![mneme_prolog::Term::String("x".to_owned())]),
        Vec::new(),
    );
    let outcome = run(&metadata(), &image, &next, limits()).expect("follow-up query");
    assert_eq!(outcome.status, mneme_prolog::ExecutionStatus::Complete);
}

#[test]
fn output_flood_is_stopped_at_the_output_limit() {
    let canonical = subject(0x16).to_hex();
    let long = "x".repeat(256);
    let image = input_image(vec![fact("path", 0x16, string(&long))], Vec::new());
    let request = request_for(
        &image,
        atom(
            "assertion",
            vec![
                mneme_prolog::Term::String("path".to_owned()),
                mneme_prolog::Term::String(canonical),
                mneme_prolog::Term::Variable("V".to_owned()),
            ],
        ),
        Vec::new(),
    );
    let outcome = run(
        &metadata(),
        &image,
        &request,
        mneme_prolog::process::WorkerLimits {
            max_wall_ms: 2_000,
            max_output_bytes: 32,
        },
    )
    .expect("output-limited query");
    assert_eq!(outcome.status, mneme_prolog::ExecutionStatus::Partial);
    assert!(!outcome.exhaustive);
    assert!(outcome.consumed.output_bytes <= 32);
    assert_eq!(outcome.stop, mneme_prolog::SearchStop::OutputLimit);
}

#[test]
fn infinite_solution_stream_is_stopped_at_the_solution_limit() {
    let image = input_image(Vec::new(), Vec::new());
    let rules = vec![
        fact_rule(
            "p-fact",
            atom("path", vec![mneme_prolog::Term::String("a".to_owned())]),
        ),
        rule(
            "p-loop",
            atom("path", vec![mneme_prolog::Term::String("a".to_owned())]),
            vec![mneme_prolog::Literal::Positive(atom(
                "path",
                vec![mneme_prolog::Term::String("a".to_owned())],
            ))],
        ),
    ];
    let mut request = request_for(
        &image,
        atom("path", vec![mneme_prolog::Term::String("a".to_owned())]),
        rules,
    );
    request.limits.max_solutions = 2;
    request.limits.max_output_bytes = 65_536;
    let outcome = run(
        &metadata(),
        &image,
        &request,
        mneme_prolog::process::WorkerLimits {
            max_wall_ms: 2_000,
            max_output_bytes: 65_536,
        },
    )
    .expect("solution-limited query");
    assert_eq!(outcome.status, mneme_prolog::ExecutionStatus::Partial);
    assert!(!outcome.exhaustive);
    assert_eq!(solutions(&outcome).len(), 2);
    assert_eq!(outcome.reason.as_deref(), Some("solution limit reached"));
}

#[test]
fn mismatched_image_or_context_is_refused_before_the_engine_runs() {
    let metadata = metadata();
    let absent_engine = std::path::Path::new("/nonexistent/mneme-test-engine");
    let image = input_image(Vec::new(), Vec::new());
    let request = request_for(
        &image,
        atom("missing", vec![mneme_prolog::Term::String("x".to_owned())]),
        Vec::new(),
    );

    let mut tampered = image.clone();
    tampered.context.image_digest = format!("sha256:{}", "0".repeat(64));
    assert!(matches!(
        mneme_prolog::run_query(
            absent_engine,
            &metadata,
            &tampered,
            &request,
            &mneme_prolog::process::WorkerControl::new(),
            limits()
        ),
        Err(mneme_prolog::CapabilityError::InvalidRequest(_))
    ));

    let mut stale = request.clone();
    stale.eligibility_generation = GENERATION.saturating_add(1);
    assert!(matches!(
        mneme_prolog::run_query(
            absent_engine,
            &metadata,
            &image,
            &stale,
            &mneme_prolog::process::WorkerControl::new(),
            limits()
        ),
        Err(mneme_prolog::CapabilityError::InvalidRequest(_))
    ));

    let mut other_image = request;
    other_image.image_digest = "sha256:not-the-image".to_owned();
    assert!(matches!(
        mneme_prolog::run_query(
            absent_engine,
            &metadata,
            &image,
            &other_image,
            &mneme_prolog::process::WorkerControl::new(),
            limits()
        ),
        Err(mneme_prolog::CapabilityError::InvalidRequest(_))
    ));
}

#[test]
fn cancelled_query_reports_cancellation_and_starts_no_work() {
    let image = input_image(Vec::new(), Vec::new());
    let request = request_for(
        &image,
        atom("missing", vec![mneme_prolog::Term::String("x".to_owned())]),
        Vec::new(),
    );
    let control = mneme_prolog::process::WorkerControl::new();
    control.cancel();
    let outcome =
        mneme_prolog::run_query(&engine(), &metadata(), &image, &request, &control, limits())
            .expect("cancelled query");
    assert_eq!(outcome.status, mneme_prolog::ExecutionStatus::Cancelled);
    assert!(!outcome.exhaustive);
    assert!(solutions(&outcome).is_empty());
}

#[test]
fn real_engine_worker_status_reflects_the_process() {
    // Direct worker use keeps the transport-level status observable: a helper
    // that always fails must report a failed engine, never a pass.
    let image = input_image(Vec::new(), Vec::new());
    let request = request_for(
        &image,
        atom("missing", vec![mneme_prolog::Term::String("x".to_owned())]),
        Vec::new(),
    );
    let outcome = mneme_prolog::process::run_worker(
        &engine(),
        &metadata(),
        &image,
        &request,
        &mneme_prolog::process::WorkerRuntime {
            control: &mneme_prolog::process::WorkerControl::new(),
            limits: limits(),
        },
    )
    .expect("worker");
    assert_eq!(
        outcome.status,
        mneme_prolog::process::WorkerStatus::Complete
    );
    assert!(
        outcome
            .output
            .lines()
            .last()
            .is_some_and(|line| line.starts_with(mneme_prolog::RESPONSE_STOP_PREFIX))
    );
}

#[test]
fn premises_and_assumption_bookkeeping_stay_consistent() {
    // Engine solutions are uncertified and never fabricated premises; the
    // request's declared assumptions are named so no solution claims
    // unconditional truth.
    let image = input_image(vec![fact("path", 0x17, string("a"))], Vec::new());
    let mut metadata = metadata();
    metadata
        .features
        .insert(mneme_prolog::Feature::HypotheticalAssumptions);
    let mut request = request_for(
        &image,
        atom(
            "assertion",
            vec![
                mneme_prolog::Term::String("path".to_owned()),
                mneme_prolog::Term::String(subject(0x17).to_hex()),
                mneme_prolog::Term::Variable("V".to_owned()),
            ],
        ),
        Vec::new(),
    );
    request
        .features
        .insert(mneme_prolog::Feature::HypotheticalAssumptions);
    request.assumptions = vec![mneme_prolog::Assumption {
        id: "assumption-1".to_owned(),
        atom: atom(
            "path",
            vec![mneme_prolog::Term::String("assumed".to_owned())],
        ),
        rationale: "explore a hypothetical extension".to_owned(),
    }];
    let outcome = run(&metadata, &image, &request, limits()).expect("query");
    assert_eq!(outcome.status, mneme_prolog::ExecutionStatus::Complete);
    assert_eq!(solutions(&outcome).len(), 1);
    let solution = &solutions(&outcome)[0];
    assert_eq!(
        solution.assumptions,
        std::collections::BTreeSet::from(["assumption-1".to_owned()])
    );
    assert!(matches!(
        solution.certification,
        mneme_prolog::Certification::Uncertified { .. }
    ));
    assert!(solution.unavailable_premises().is_empty());
    assert_eq!(solution.independent_support_count(), 0);
    assert!(solution.premises.is_empty());
    solution
        .validate(&std::collections::BTreeSet::from([
            "assumption-1".to_owned()
        ]))
        .expect("declared assumption");

    // A pruned premise would be reported separately; nothing here fabricates
    // one, and the model still refuses a pruned premise that quotes bytes.
    let mut pruned = mneme_prolog::Premise {
        record_id: subject(0x01),
        revision_id: mneme_core::RevisionId::from_bytes([0x02; 16]),
        span: Some(mneme_core::SourceSpan::new(0, 0).expect("span")),
        derivation: None,
        ancestry_roots: std::collections::BTreeSet::new(),
        availability: mneme_prolog::PremiseAvailability::Pruned {
            reason: "source bytes pruned".to_owned(),
        },
    };
    let fabricated = mneme_prolog::Solution {
        bindings: std::collections::BTreeMap::new(),
        premises: vec![pruned.clone()],
        assumptions: std::collections::BTreeSet::new(),
        certification: mneme_prolog::Certification::Certified,
    };
    assert!(
        fabricated
            .validate(&std::collections::BTreeSet::new())
            .is_err()
    );
    pruned.span = None;
    pruned.ancestry_roots.insert((
        subject(0x01),
        mneme_core::RevisionId::from_bytes([0x02; 16]),
    ));
    let disclosed = mneme_prolog::Solution {
        bindings: std::collections::BTreeMap::new(),
        premises: vec![pruned],
        assumptions: std::collections::BTreeSet::new(),
        certification: mneme_prolog::Certification::Certified,
    };
    assert_eq!(disclosed.unavailable_premises().len(), 1);
    assert!(
        disclosed
            .validate(&std::collections::BTreeSet::new())
            .is_ok()
    );
}
