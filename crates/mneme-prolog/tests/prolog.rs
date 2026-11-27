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
                epistemic: mneme_datalog::EpistemicStatus::Accepted,
                support_truncated: false,
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
    // A multi-derivation stream of two-binding answers: the solution budget
    // counts solution lines (not bindings), returns exactly the budget and
    // stays non-exhaustive.
    let image = input_image(
        vec![fact("path", 0x1c, mneme_core::Value::integer(-7))],
        Vec::new(),
    );
    let derived_fact = atom(
        "derived",
        vec![
            mneme_prolog::Term::String(subject(0x1c).to_hex()),
            mneme_prolog::Term::Integer(-7),
        ],
    );
    let rules = vec![
        fact_rule("pair-1", derived_fact.clone()),
        fact_rule("pair-2", derived_fact.clone()),
        fact_rule("pair-3", derived_fact),
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
    // Non-recursive combinatorial search exceeding the 200 ms wall-time cap
    // proves Scryer worker timeouts are still enforced promptly even after
    // cyclic rules terminate cleanly via SLG tabling.
    let facts = (0_u8..20)
        .map(|i| fact("path", i.wrapping_add(1), string("shared")))
        .collect();
    let image = input_image(facts, Vec::new());
    let join_var = |name: &str| {
        mneme_prolog::Literal::Positive(atom(
            "assertion",
            vec![
                mneme_prolog::Term::String("path".to_owned()),
                mneme_prolog::Term::Variable(name.to_owned()),
                mneme_prolog::Term::Variable("V".to_owned()),
            ],
        ))
    };
    let rules = vec![rule(
        "heavy-join",
        atom("loop", vec![mneme_prolog::Term::String("a".to_owned())]),
        vec![
            join_var("A"),
            join_var("B"),
            join_var("C"),
            join_var("D"),
            join_var("E"),
            join_var("F"),
            join_var("A"),
            join_var("B"),
            join_var("C"),
            join_var("D"),
            join_var("E"),
            join_var("F"),
            mneme_prolog::Literal::Positive(atom(
                "missing",
                vec![mneme_prolog::Term::Variable("V".to_owned())],
            )),
        ],
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
    let path_fact = atom("path", vec![mneme_prolog::Term::String("a".to_owned())]);
    let rules = vec![
        fact_rule("p-fact-1", path_fact.clone()),
        fact_rule("p-fact-2", path_fact.clone()),
        fact_rule("p-fact-3", path_fact),
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
        epistemic: mneme_datalog::EpistemicStatus::Accepted,
        proof: None,
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
        epistemic: mneme_datalog::EpistemicStatus::Accepted,
        proof: None,
    };
    assert_eq!(disclosed.unavailable_premises().len(), 1);
    assert!(
        disclosed
            .validate(&std::collections::BTreeSet::new())
            .is_ok()
    );
}

#[test]
fn federated_prolog_query_joins_across_two_vaults_with_real_engine() {
    let temp_a = tempfile::tempdir().expect("temp a");
    let temp_b = tempfile::tempdir().expect("temp b");
    let cfg = || {
        mneme_store::WorkspaceConfig::new(
            Box::new(mneme_store::SystemClock),
            Box::new(mneme_store::NoFaults),
        )
    };
    let mut ws_a = mneme_store::Workspace::create(temp_a.path(), cfg()).expect("ws a");
    let mut ws_b = mneme_store::Workspace::create(temp_b.path(), cfg()).expect("ws b");

    let commit_typed = |ws: &mut mneme_store::Workspace, id: u8, kind: &str, label: &str| {
        let base = ws.current_revision().expect("base");
        let payload = mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("entity-type"),
                mneme_core::Value::symbol(kind),
            ),
            (
                mneme_core::Symbol::from("label"),
                mneme_core::Value::string(label),
            ),
            (
                mneme_core::Symbol::from("properties"),
                mneme_core::Value::dictionary([]),
            ),
        ]);
        ws.commit(mneme_store::CommitCommand {
            base,
            actor: "test".to_owned(),
            scope: scope(),
            idempotency_key: format!("entity-{id}"),
            records: vec![mneme_store::RecordDraft {
                schema_version: 1,
                kind: mneme_core::RecordKind::Entity,
                record_id: subject(id),
                revision_id: mneme_core::RevisionId::from_bytes([id.wrapping_add(1); 16]),
                predecessor: None,
                scope: scope(),
                payload,
            }],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit");
    };

    commit_typed(&mut ws_a, 0x11, "principle", "shared-concept");
    commit_typed(&mut ws_b, 0x22, "paper", "shared-concept");
    let rev_a = ws_a.current_revision().expect("rev a");
    let rev_b = ws_b.current_revision().expect("rev b");
    let gen_a = ws_a.eligibility_generation().expect("gen a");
    let gen_b = ws_b.eligibility_generation().expect("gen b");

    let ro_b = mneme_store::Workspace::open_read_only(temp_b.path(), cfg()).expect("ro b");
    let view_a = mneme_memory::Engine::new(&mut ws_a, mneme_memory::Access::Operator)
        .view_at(Some(gen_a))
        .expect("view a");
    let snap_b = ro_b.snapshot_at(rev_b, Some(gen_b)).expect("snap b");
    let ctx_b = mneme_memory::view_context(&ro_b, &snap_b).expect("ctx b");
    let view_b = mneme_memory::View::with_retention(
        snap_b,
        ro_b.root(),
        ctx_b.history,
        ctx_b.revision_sequences,
        ro_b.active_suppressions().expect("suppressions b"),
    )
    .with_access(mneme_memory::Access::Operator);

    let federated = mneme_prolog::snapshot::build_federated_input_image(
        mneme_prolog::snapshot::FederatedVaultInput {
            alias: "primary",
            root: ws_a.root(),
            view: &view_a,
            requested_revision: rev_a,
            served_revision: rev_a,
            eligibility_generation: gen_a,
        },
        &[mneme_prolog::snapshot::FederatedVaultInput {
            alias: "bookmarks",
            root: ro_b.root(),
            view: &view_b,
            requested_revision: rev_b,
            served_revision: rev_b,
            eligibility_generation: gen_b,
        }],
        &scope(),
        Vec::new(),
    )
    .expect("federated image");

    let mut md = metadata();
    md.allowed_predicates.insert("bridge".to_owned());
    md.allowed_predicates.insert("vault_entity".to_owned());
    let req = mneme_prolog::Request {
        actor: "agent".to_owned(),
        scope: scope(),
        revision: rev_a,
        eligibility_generation: gen_a,
        image_digest: federated.image.context.image_digest.clone(),
        mode: mneme_prolog::QueryMode::Enumerate,
        goal: atom(
            "bridge",
            vec![
                mneme_prolog::Term::Variable("Paper".to_owned()),
                mneme_prolog::Term::Variable("Principle".to_owned()),
                mneme_prolog::Term::Variable("Label".to_owned()),
            ],
        ),
        variables: vec![
            mneme_prolog::QueryVariable {
                name: "Paper".to_owned(),
                role: mneme_prolog::VariableRole::Output,
            },
            mneme_prolog::QueryVariable {
                name: "Principle".to_owned(),
                role: mneme_prolog::VariableRole::Output,
            },
            mneme_prolog::QueryVariable {
                name: "Label".to_owned(),
                role: mneme_prolog::VariableRole::Output,
            },
        ],
        rules: vec![mneme_prolog::Rule {
            id: "r-bridge".to_owned(),
            version: "1".to_owned(),
            head: atom(
                "bridge",
                vec![
                    mneme_prolog::Term::Variable("Paper".to_owned()),
                    mneme_prolog::Term::Variable("Principle".to_owned()),
                    mneme_prolog::Term::Variable("Label".to_owned()),
                ],
            ),
            body: vec![
                mneme_prolog::Literal::Positive(atom(
                    "vault_entity",
                    vec![
                        mneme_prolog::Term::String("bookmarks".to_owned()),
                        mneme_prolog::Term::Variable("Paper".to_owned()),
                        mneme_prolog::Term::String("paper".to_owned()),
                        mneme_prolog::Term::Variable("Label".to_owned()),
                    ],
                )),
                mneme_prolog::Literal::Positive(atom(
                    "vault_entity",
                    vec![
                        mneme_prolog::Term::String("primary".to_owned()),
                        mneme_prolog::Term::Variable("Principle".to_owned()),
                        mneme_prolog::Term::String("principle".to_owned()),
                        mneme_prolog::Term::Variable("Label".to_owned()),
                    ],
                )),
            ],
        }],
        assumptions: Vec::new(),
        features: std::collections::BTreeSet::from([mneme_prolog::Feature::PositiveQuery]),
        limits: mneme_prolog::RequestLimits {
            max_time_ms: 1_000,
            max_solutions: 8,
            max_output_bytes: 16_384,
        },
    };
    let control = mneme_prolog::process::WorkerControl::new();
    let runtime = mneme_prolog::process::WorkerRuntime {
        control: &control,
        limits: limits(),
    };
    let result = mneme_prolog::run_federated_query(&engine(), &md, &federated, &req, &runtime)
        .expect("federated prolog query");
    assert_eq!(
        result.outcome.status,
        mneme_prolog::ExecutionStatus::Complete
    );
    assert_eq!(result.vaults.len(), 2);
    let sols = solutions(&result.outcome);
    assert_eq!(sols.len(), 1);
    assert_eq!(bound_string(&sols[0], "Paper"), subject(0x22).to_hex());
    assert_eq!(bound_string(&sols[0], "Principle"), subject(0x11).to_hex());
    assert_eq!(bound_string(&sols[0], "Label"), "shared-concept");
}

#[test]
fn proposed_and_rejected_datalog_rows_are_never_promoted_to_unqualified_relation() {
    let rel = mneme_prolog::snapshot::SelectedRelation {
        predicate: "verdict".to_owned(),
        rows: vec![
            mneme_prolog::snapshot::SelectedRow {
                values: vec![string("accepted-item")],
                supports: Vec::new(),
                epistemic: mneme_datalog::EpistemicStatus::Accepted,
                support_truncated: false,
            },
            mneme_prolog::snapshot::SelectedRow {
                values: vec![string("proposed-item")],
                supports: Vec::new(),
                epistemic: mneme_datalog::EpistemicStatus::Proposed,
                support_truncated: false,
            },
            mneme_prolog::snapshot::SelectedRow {
                values: vec![string("rejected-item")],
                supports: Vec::new(),
                epistemic: mneme_datalog::EpistemicStatus::Rejected,
                support_truncated: false,
            },
        ],
        coverage: mneme_prolog::InputCoverage {
            complete: true,
            reason: None,
        },
    };
    let image = input_image(Vec::new(), vec![rel]);

    // 1. Unqualified `relation("verdict", [Item])` must ONLY return Accepted rows.
    let mut md = metadata();
    md.allowed_predicates
        .insert(mneme_prolog::snapshot::SelectedRow::EPISTEMIC_RELATION.to_owned());
    let req_unqualified = request_for(
        &image,
        atom(
            mneme_prolog::RELATION_RELATION,
            vec![
                mneme_prolog::Term::String("verdict".to_owned()),
                mneme_prolog::Term::List(vec![mneme_prolog::Term::Variable("Item".to_owned())]),
            ],
        ),
        Vec::new(),
    );
    let out_unqualified = run(&md, &image, &req_unqualified, limits()).expect("unqualified query");
    assert_eq!(
        out_unqualified.status,
        mneme_prolog::ExecutionStatus::Complete
    );
    let unqualified_items: Vec<String> = solutions(&out_unqualified)
        .iter()
        .map(|sol| bound_string(sol, "Item"))
        .collect();
    assert_eq!(
        unqualified_items,
        vec!["accepted-item".to_owned()],
        "Proposed and Rejected rows must never be silently promoted into unqualified relation/2"
    );

    // 2. Tagged `relation_epistemic("verdict", [Item], Status)` exposes Accepted + Proposed
    // with their exact epistemic tags and excludes Rejected.
    let req_tagged = request_for(
        &image,
        atom(
            mneme_prolog::snapshot::SelectedRow::EPISTEMIC_RELATION,
            vec![
                mneme_prolog::Term::String("verdict".to_owned()),
                mneme_prolog::Term::List(vec![mneme_prolog::Term::Variable("Item".to_owned())]),
                mneme_prolog::Term::Variable("Status".to_owned()),
            ],
        ),
        Vec::new(),
    );
    let out_tagged = run(&md, &image, &req_tagged, limits()).expect("tagged query");
    assert_eq!(out_tagged.status, mneme_prolog::ExecutionStatus::Complete);
    let tagged_pairs: Vec<(String, String)> = solutions(&out_tagged)
        .iter()
        .map(|sol| (bound_string(sol, "Item"), bound_string(sol, "Status")))
        .collect();
    assert_eq!(
        tagged_pairs,
        vec![
            ("accepted-item".to_owned(), "accepted".to_owned()),
            ("proposed-item".to_owned(), "proposed".to_owned()),
        ]
    );
}

#[test]
fn certified_proofs_verify_multi_hop_canonical_and_epistemic_derivations_and_reject_tampering() {
    let s1 = subject(0x41);
    let s2 = subject(0x42);
    let rec1 = mneme_core::RecordId::from_bytes([0x51; 16]);
    let rev1 = mneme_core::RevisionId::from_bytes([0x61; 16]);
    let rec2 = mneme_core::RecordId::from_bytes([0x52; 16]);
    let rev2 = mneme_core::RevisionId::from_bytes([0x62; 16]);

    let canonical = vec![mneme_prolog::snapshot::CanonicalFact {
        record_id: rec1,
        revision_id: rev1,
        scope: scope(),
        subject: s1,
        predicate: "owner".to_owned(),
        value: string("alice"),
        valid_time: mneme_core::ValidTime::always(),
    }];
    let proposed_support = mneme_datalog::Derivation {
        rule_id: "r-proposed".to_owned(),
        rule_version: "1".to_owned(),
        premises: vec![mneme_datalog::Premise {
            predicate: "relation".to_owned(),
            terms: vec![
                mneme_core::Value::symbol("links"),
                s1.to_value(),
                s2.to_value(),
            ],
            canonical: Some(rec2),
            canonical_roots: std::collections::BTreeSet::from([rec2]),
            sources: std::collections::BTreeSet::from([(rec2, rev2)]),
            source_availability: None,
            vault: Some("primary".to_owned()),
            vaults: std::collections::BTreeSet::from(["primary".to_owned()]),
            absent: false,
            coverage: None,
            epistemic: mneme_datalog::EpistemicStatus::Proposed,
        }],
        sources: std::collections::BTreeSet::from([(rec2, rev2)]),
        vaults: std::collections::BTreeSet::from(["primary".to_owned()]),
        temporal_parameters: Vec::new(),
        revision: revision(),
        scope: scope(),
        truncated: false,
        epistemic: mneme_datalog::EpistemicStatus::Proposed,
    };
    let rel = mneme_prolog::snapshot::SelectedRelation {
        predicate: "link".to_owned(),
        rows: vec![mneme_prolog::snapshot::SelectedRow {
            values: vec![string(&s1.to_hex()), string(&s2.to_hex())],
            supports: vec![proposed_support],
            epistemic: mneme_datalog::EpistemicStatus::Proposed,
            support_truncated: false,
        }],
        coverage: mneme_prolog::InputCoverage {
            complete: true,
            reason: None,
        },
    };
    let image = input_image(canonical, vec![rel]);

    let mut md = metadata();
    md.features.insert(mneme_prolog::Feature::CertifiedProofs);
    md.features
        .insert(mneme_prolog::Feature::HypotheticalAssumptions);
    md.allowed_predicates
        .insert(mneme_prolog::snapshot::SelectedRow::EPISTEMIC_RELATION.to_owned());
    md.allowed_predicates.insert("string".to_owned());
    md.allowed_predicates.insert("linked_owner".to_owned());
    md.allowed_predicates.insert("assumed_flag".to_owned());
    md.allowed_predicates.insert("flagged_owner".to_owned());

    let rule = mneme_prolog::Rule {
        id: "linked-owner-rule".to_owned(),
        version: "1".to_owned(),
        head: atom(
            "linked_owner",
            vec![
                mneme_prolog::Term::Variable("Owner".to_owned()),
                mneme_prolog::Term::Variable("Target".to_owned()),
                mneme_prolog::Term::Variable("Status".to_owned()),
            ],
        ),
        body: vec![
            mneme_prolog::Literal::Positive(atom(
                mneme_prolog::ASSERTION_RELATION,
                vec![
                    mneme_prolog::Term::String("owner".to_owned()),
                    mneme_prolog::Term::Variable("Subj".to_owned()),
                    mneme_prolog::Term::Variable("Owner".to_owned()),
                ],
            )),
            mneme_prolog::Literal::Positive(atom(
                mneme_prolog::snapshot::SelectedRow::EPISTEMIC_RELATION,
                vec![
                    mneme_prolog::Term::String("link".to_owned()),
                    mneme_prolog::Term::List(vec![
                        mneme_prolog::Term::Variable("Subj".to_owned()),
                        mneme_prolog::Term::Variable("Target".to_owned()),
                    ]),
                    mneme_prolog::Term::Variable("Status".to_owned()),
                ],
            )),
        ],
    };
    let mut req = request_for(
        &image,
        atom(
            "linked_owner",
            vec![
                mneme_prolog::Term::Variable("Owner".to_owned()),
                mneme_prolog::Term::Variable("Target".to_owned()),
                mneme_prolog::Term::Variable("Status".to_owned()),
            ],
        ),
        vec![rule],
    );
    req.features.insert(mneme_prolog::Feature::CertifiedProofs);

    let out = run(&md, &image, &req, limits()).expect("certified query");
    assert_eq!(out.status, mneme_prolog::ExecutionStatus::Complete);
    let sols = solutions(&out);
    assert_eq!(sols.len(), 1);
    let sol = &sols[0];
    assert_eq!(sol.certification, mneme_prolog::Certification::Certified);
    assert_eq!(sol.epistemic, mneme_datalog::EpistemicStatus::Proposed);
    assert_eq!(bound_string(sol, "Owner"), "alice");
    assert_eq!(bound_string(sol, "Target"), s2.to_hex());
    assert_eq!(bound_string(sol, "Status"), "proposed");
    assert_eq!(sol.independent_support_count(), 2);

    // Independent host verification succeeds on the returned certificate.
    let cert = sol.proof.as_ref().expect("proof certificate present");
    let verified = mneme_prolog::proof::verify_certificate(cert, &sol.bindings, &req, &image)
        .expect("independent verification succeeds");
    assert_eq!(verified.epistemic, mneme_datalog::EpistemicStatus::Proposed);

    // Tampering with epistemic status or proof tree must fail verification.
    let mut tampered_epistemic = cert.clone();
    tampered_epistemic.epistemic = mneme_datalog::EpistemicStatus::Accepted;
    assert!(
        mneme_prolog::proof::verify_certificate(&tampered_epistemic, &sol.bindings, &req, &image)
            .is_err(),
        "forged epistemic promotion must fail host verification"
    );
    let mut tampered_root = cert.clone();
    tampered_root.root =
        mneme_prolog::proof::Node::Leaf(mneme_prolog::proof::Leaf::Canonical { index: 0 });
    assert!(
        mneme_prolog::proof::verify_certificate(&tampered_root, &sol.bindings, &req, &image)
            .is_err(),
        "tampered proof root must fail host verification"
    );

    // Hypothetical assumptions stay Uncertified even under Feature::CertifiedProofs.
    let assumption_rule = mneme_prolog::Rule {
        id: "flagged-rule".to_owned(),
        version: "1".to_owned(),
        head: atom(
            "flagged_owner",
            vec![mneme_prolog::Term::Variable("Owner".to_owned())],
        ),
        body: vec![
            mneme_prolog::Literal::Positive(atom(
                mneme_prolog::ASSERTION_RELATION,
                vec![
                    mneme_prolog::Term::String("owner".to_owned()),
                    mneme_prolog::Term::Variable("Subj".to_owned()),
                    mneme_prolog::Term::Variable("Owner".to_owned()),
                ],
            )),
            mneme_prolog::Literal::Positive(atom(
                "assumed_flag",
                vec![mneme_prolog::Term::Variable("Subj".to_owned())],
            )),
        ],
    };
    let mut req_hyp = request_for(
        &image,
        atom(
            "flagged_owner",
            vec![mneme_prolog::Term::Variable("Owner".to_owned())],
        ),
        vec![assumption_rule],
    );
    req_hyp
        .features
        .insert(mneme_prolog::Feature::CertifiedProofs);
    req_hyp
        .features
        .insert(mneme_prolog::Feature::HypotheticalAssumptions);
    req_hyp.assumptions.push(mneme_prolog::Assumption {
        id: "hyp-1".to_owned(),
        atom: atom(
            "assumed_flag",
            vec![mneme_prolog::Term::String(s1.to_hex())],
        ),
        rationale: "what-if flag".to_owned(),
    });
    let out_hyp = run(&md, &image, &req_hyp, limits()).expect("hypothetical certified query");
    assert_eq!(out_hyp.status, mneme_prolog::ExecutionStatus::Complete);
    let hyp_sols = solutions(&out_hyp);
    assert_eq!(hyp_sols.len(), 1);
    assert!(matches!(
        hyp_sols[0].certification,
        mneme_prolog::Certification::Uncertified { .. }
    ));
    assert!(hyp_sols[0].assumptions.contains("hyp-1"));
    assert!(hyp_sols[0].proof.is_some());
}

#[test]
fn slg_detects_recursive_sccs_and_terminates_cyclic_and_mutual_recursion() {
    // Direct self-loop terminates cleanly with Complete and 0 solutions (no timeout).
    let image = input_image(Vec::new(), Vec::new());
    let self_loop_rules = vec![rule(
        "self-loop",
        atom("loop", vec![mneme_prolog::Term::String("a".to_owned())]),
        vec![mneme_prolog::Literal::Positive(atom(
            "loop",
            vec![mneme_prolog::Term::String("a".to_owned())],
        ))],
    )];
    let detected = mneme_prolog::slg::recursive_predicates(&self_loop_rules);
    assert_eq!(
        detected,
        std::collections::BTreeSet::from([("loop".to_owned(), 1_u32)])
    );
    let directives = mneme_prolog::slg::tabling_directives(&self_loop_rules);
    assert_eq!(
        directives,
        vec![
            ":- use_module(library(tabling)).".to_owned(),
            ":- table loop/1.".to_owned(),
        ]
    );
    let loop_req = request_for(
        &image,
        atom("loop", vec![mneme_prolog::Term::String("a".to_owned())]),
        self_loop_rules,
    );
    let loop_out = run(&metadata(), &image, &loop_req, limits()).expect("self-loop SLG");
    assert_eq!(loop_out.status, mneme_prolog::ExecutionStatus::Complete);
    assert!(solutions(&loop_out).is_empty());

    // Mutually recursive SCC (`ping` <-> `pong`) over a 4-node cycle terminates cleanly.
    let mut md = metadata();
    md.allowed_predicates.insert("ping".to_owned());
    md.allowed_predicates.insert("pong".to_owned());
    md.allowed_predicates.insert("edge".to_owned());
    md.limits.max_rule_count = 16;
    let cycle_rows = vec![
        vec![string("a"), string("b")],
        vec![string("b"), string("c")],
        vec![string("c"), string("d")],
        vec![string("d"), string("a")],
    ];
    let cycle_image = input_image(Vec::new(), vec![relation("edge", cycle_rows)]);
    let mutual_rules = vec![
        rule(
            "edge-bridge",
            atom(
                "edge",
                vec![
                    mneme_prolog::Term::Variable("X".to_owned()),
                    mneme_prolog::Term::Variable("Y".to_owned()),
                ],
            ),
            vec![mneme_prolog::Literal::Positive(atom(
                "relation",
                vec![
                    mneme_prolog::Term::String("edge".to_owned()),
                    mneme_prolog::Term::List(vec![
                        mneme_prolog::Term::Variable("X".to_owned()),
                        mneme_prolog::Term::Variable("Y".to_owned()),
                    ]),
                ],
            ))],
        ),
        rule(
            "ping-base",
            atom("ping", vec![mneme_prolog::Term::Variable("X".to_owned())]),
            vec![mneme_prolog::Literal::Positive(atom(
                "edge",
                vec![
                    mneme_prolog::Term::String("a".to_owned()),
                    mneme_prolog::Term::Variable("X".to_owned()),
                ],
            ))],
        ),
        rule(
            "ping-step",
            atom("ping", vec![mneme_prolog::Term::Variable("Y".to_owned())]),
            vec![
                mneme_prolog::Literal::Positive(atom(
                    "pong",
                    vec![mneme_prolog::Term::Variable("X".to_owned())],
                )),
                mneme_prolog::Literal::Positive(atom(
                    "edge",
                    vec![
                        mneme_prolog::Term::Variable("X".to_owned()),
                        mneme_prolog::Term::Variable("Y".to_owned()),
                    ],
                )),
            ],
        ),
        rule(
            "pong-step",
            atom("pong", vec![mneme_prolog::Term::Variable("Y".to_owned())]),
            vec![
                mneme_prolog::Literal::Positive(atom(
                    "ping",
                    vec![mneme_prolog::Term::Variable("X".to_owned())],
                )),
                mneme_prolog::Literal::Positive(atom(
                    "edge",
                    vec![
                        mneme_prolog::Term::Variable("X".to_owned()),
                        mneme_prolog::Term::Variable("Y".to_owned()),
                    ],
                )),
            ],
        ),
    ];
    let scc_preds = mneme_prolog::slg::recursive_predicates(&mutual_rules);
    assert_eq!(
        scc_preds,
        std::collections::BTreeSet::from([("ping".to_owned(), 1_u32), ("pong".to_owned(), 1_u32),])
    );
    let mutual_req = request_for(
        &cycle_image,
        atom("ping", vec![mneme_prolog::Term::Variable("N".to_owned())]),
        mutual_rules,
    );
    let mutual_out = run(&md, &cycle_image, &mutual_req, limits()).expect("mutual recursion");
    assert_eq!(mutual_out.status, mneme_prolog::ExecutionStatus::Complete);
    let got: Vec<String> = sorted_strings(
        solutions(&mutual_out)
            .iter()
            .map(|sol| bound_string(sol, "N")),
    );
    assert_eq!(got, vec!["b".to_owned(), "d".to_owned()]);
}

#[test]
fn cyclic_left_recursive_reach_50_nodes_matches_datalog_blast_radius_under_50ms() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut workspace = mneme_store::Workspace::create(
        dir.path(),
        mneme_store::WorkspaceConfig {
            clock: Box::new(mneme_store::FixedClock::new(
                mneme_core::Timestamp::from_nanos(1_000),
            )),
            faults: Box::new(mneme_store::NoFaults),
        },
    )
    .expect("workspace");
    let mut node_ids = Vec::with_capacity(50);
    for idx in 0_u8..50 {
        let mut raw = [0_u8; 16];
        raw[0] = 0x50;
        raw[15] = idx.wrapping_add(1);
        node_ids.push(mneme_core::RecordId::from_bytes(raw));
    }
    let mut records = Vec::with_capacity(110);
    for (idx, &id) in node_ids.iter().enumerate() {
        let mut entity_rev = [0x61_u8; 16];
        entity_rev[15] = u8::try_from(idx.wrapping_add(1)).expect("u8");
        let payload = mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("entity-type"),
                mneme_core::Value::symbol("symbol"),
            ),
            (
                mneme_core::Symbol::from("label"),
                mneme_core::Value::string(format!("fn_{idx:02}")),
            ),
            (
                mneme_core::Symbol::from("properties"),
                mneme_core::Value::dictionary([]),
            ),
        ]);
        records.push(mneme_store::RecordDraft {
            schema_version: 1,
            kind: mneme_core::RecordKind::Entity,
            record_id: id,
            revision_id: mneme_core::RevisionId::from_bytes(entity_rev),
            predecessor: None,
            scope: scope(),
            payload,
        });
    }
    // 50-node directed cycle `n0 -> n1 -> ... -> n49 -> n0` plus cyclic cross-edges.
    let mut edge_pairs: Vec<(usize, usize)> = (0..50).map(|i| (i, (i + 1) % 50)).collect();
    edge_pairs.push((0, 25));
    edge_pairs.push((25, 10));
    edge_pairs.push((12, 37));
    for (edge_idx, &(from_idx, to_idx)) in edge_pairs.iter().enumerate() {
        let mut rec_bytes = [0_u8; 16];
        rec_bytes[0] = 0x70;
        rec_bytes[15] = u8::try_from(edge_idx.wrapping_add(1)).expect("u8");
        let mut rev_bytes = [0_u8; 16];
        rev_bytes[0] = 0x71;
        rev_bytes[15] = u8::try_from(edge_idx.wrapping_add(1)).expect("u8");
        let payload = mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("relation-type"),
                mneme_core::Value::symbol("calls"),
            ),
            (
                mneme_core::Symbol::from("from"),
                mneme_core::Reference::local(node_ids[from_idx], mneme_core::RecordKind::Entity)
                    .to_value(),
            ),
            (
                mneme_core::Symbol::from("to"),
                mneme_core::Reference::local(node_ids[to_idx], mneme_core::RecordKind::Entity)
                    .to_value(),
            ),
            (
                mneme_core::Symbol::from("properties"),
                mneme_core::Value::dictionary([]),
            ),
        ]);
        records.push(mneme_store::RecordDraft {
            schema_version: 1,
            kind: mneme_core::RecordKind::Relation,
            record_id: mneme_core::RecordId::from_bytes(rec_bytes),
            revision_id: mneme_core::RevisionId::from_bytes(rev_bytes),
            predecessor: None,
            scope: scope(),
            payload,
        });
    }
    let base = workspace.current_revision().expect("base");
    let head = workspace
        .commit(mneme_store::CommitCommand {
            base,
            actor: "parity-seed".to_owned(),
            scope: scope(),
            idempotency_key: "seed-50-cycle".to_owned(),
            records,
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit")
        .revision;

    // 1. Evaluate `blast_radius` via real `mneme-datalog`.
    let bundle = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "blast-radius-rules".to_owned(),
        version: "1".to_owned(),
        schema_version: 1,
        base_predicates: std::collections::BTreeMap::from([("relation".to_owned(), 3)]),
        complete_predicates: std::collections::BTreeSet::from(["relation".to_owned()]),
        rules: vec![
            mneme_datalog::Rule::new(
                "r-calls",
                mneme_datalog::Atom::new(
                    "call_edge",
                    vec![mneme_datalog::Term::var("X"), mneme_datalog::Term::var("Y")],
                ),
                vec![mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                    "relation",
                    vec![
                        mneme_datalog::Term::constant(mneme_core::Value::symbol("calls")),
                        mneme_datalog::Term::var("X"),
                        mneme_datalog::Term::var("Y"),
                    ],
                ))],
            ),
            mneme_datalog::Rule::new(
                "r-blast-base",
                mneme_datalog::Atom::new(
                    "blast_radius",
                    vec![mneme_datalog::Term::var("X"), mneme_datalog::Term::var("Y")],
                ),
                vec![mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                    "call_edge",
                    vec![mneme_datalog::Term::var("X"), mneme_datalog::Term::var("Y")],
                ))],
            ),
            mneme_datalog::Rule::new(
                "r-blast-rec",
                mneme_datalog::Atom::new(
                    "blast_radius",
                    vec![mneme_datalog::Term::var("X"), mneme_datalog::Term::var("Y")],
                ),
                vec![
                    mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                        "blast_radius",
                        vec![mneme_datalog::Term::var("X"), mneme_datalog::Term::var("Z")],
                    )),
                    mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(
                        "call_edge",
                        vec![mneme_datalog::Term::var("Z"), mneme_datalog::Term::var("Y")],
                    )),
                ],
            ),
        ],
    });
    let mut datalog_limits = mneme_datalog::Limits::default();
    datalog_limits.max_work = 500_000;
    datalog_limits.max_recursion_depth = 128;
    datalog_limits.max_result_rows = 5_000;
    let build = {
        let mut service = mneme_datalog::Service::new(&mut workspace);
        service
            .build(mneme_datalog::BuildRequest {
                actor: "parity-test".to_owned(),
                scope: scope(),
                revision: head,
                bundle,
                limits: datalog_limits,
                publish: false,
                incomplete_extents: std::collections::BTreeSet::new(),
                cancellation: None,
                access: mneme_memory::Access::Operator,
                at: None,
            })
            .expect("datalog build")
    };
    let start_val = node_ids[0].to_value();
    let datalog_edges_result = {
        let mut service = mneme_datalog::Service::new(&mut workspace);
        service
            .query_build(&build, mneme_datalog::Query::all("call_edge", 200))
            .expect("call_edge query")
    };
    let datalog_blast: std::collections::BTreeSet<String> = {
        let mut service = mneme_datalog::Service::new(&mut workspace);
        service
            .query_build(&build, mneme_datalog::Query::all("blast_radius", 5_000))
            .expect("blast_radius query")
            .rows
            .into_iter()
            .filter_map(|row| {
                let from = row.values.first()?;
                let to = row.values.get(1)?;
                let to_id = mneme_core::RecordId::from_value(to, &mneme_core::Path::root()).ok()?;
                (*from == start_val).then(|| to_id.to_hex())
            })
            .collect()
    };
    assert_eq!(datalog_blast.len(), 50);

    // 2. Build the Prolog snapshot image carrying the exact `call_edge` rows and
    // run left-recursive `reach(X, Y)` through SLG tabling.
    let mut md = metadata();
    md.allowed_predicates.insert("reach".to_owned());
    md.allowed_predicates.insert("call_edge".to_owned());
    md.limits.max_solutions = 100;
    md.limits.max_rule_count = 16;
    md.terms.max_collection = 100;

    let selected_rows: Vec<Vec<mneme_core::Value>> = datalog_edges_result
        .rows
        .iter()
        .map(|row| {
            let from_id =
                mneme_core::RecordId::from_value(&row.values[0], &mneme_core::Path::root())
                    .expect("from record id");
            let to_id = mneme_core::RecordId::from_value(&row.values[1], &mneme_core::Path::root())
                .expect("to record id");
            vec![string(&from_id.to_hex()), string(&to_id.to_hex())]
        })
        .collect();
    let start_hex = node_ids[0].to_hex();
    let image = input_image(Vec::new(), vec![relation("call_edge", selected_rows)]);
    let reach_rules = vec![
        rule(
            "r-edge",
            atom(
                "call_edge",
                vec![
                    mneme_prolog::Term::Variable("X".to_owned()),
                    mneme_prolog::Term::Variable("Y".to_owned()),
                ],
            ),
            vec![mneme_prolog::Literal::Positive(atom(
                "relation",
                vec![
                    mneme_prolog::Term::String("call_edge".to_owned()),
                    mneme_prolog::Term::List(vec![
                        mneme_prolog::Term::Variable("X".to_owned()),
                        mneme_prolog::Term::Variable("Y".to_owned()),
                    ]),
                ],
            ))],
        ),
        rule(
            "r-reach-base",
            atom(
                "reach",
                vec![
                    mneme_prolog::Term::Variable("X".to_owned()),
                    mneme_prolog::Term::Variable("Y".to_owned()),
                ],
            ),
            vec![mneme_prolog::Literal::Positive(atom(
                "call_edge",
                vec![
                    mneme_prolog::Term::Variable("X".to_owned()),
                    mneme_prolog::Term::Variable("Y".to_owned()),
                ],
            ))],
        ),
        rule(
            "r-reach-left-rec",
            atom(
                "reach",
                vec![
                    mneme_prolog::Term::Variable("X".to_owned()),
                    mneme_prolog::Term::Variable("Y".to_owned()),
                ],
            ),
            vec![
                mneme_prolog::Literal::Positive(atom(
                    "reach",
                    vec![
                        mneme_prolog::Term::Variable("X".to_owned()),
                        mneme_prolog::Term::Variable("Z".to_owned()),
                    ],
                )),
                mneme_prolog::Literal::Positive(atom(
                    "call_edge",
                    vec![
                        mneme_prolog::Term::Variable("Z".to_owned()),
                        mneme_prolog::Term::Variable("Y".to_owned()),
                    ],
                )),
            ],
        ),
    ];
    let mut request = request_for(
        &image,
        atom(
            "reach",
            vec![
                mneme_prolog::Term::String(start_hex.clone()),
                mneme_prolog::Term::Variable("Target".to_owned()),
            ],
        ),
        reach_rules,
    );
    request.limits.max_solutions = 100;

    // Verify direct SLG worker status and latency (< 50 ms).
    let control = mneme_prolog::process::WorkerControl::new();
    let runtime = mneme_prolog::process::WorkerRuntime {
        control: &control,
        limits: limits(),
    };
    let worker = mneme_prolog::slg::run_worker(
        &md,
        &image,
        &request,
        &runtime,
        mneme_prolog::slg::Config::standard(),
    )
    .expect("slg worker");
    assert_eq!(worker.status, mneme_prolog::process::WorkerStatus::Complete);
    assert!(
        worker.elapsed_ms < 50,
        "cyclic 50-node SLG reach exceeded 50 ms budget: {} ms",
        worker.elapsed_ms
    );

    // Verify end-to-end `run_query` parity with `mneme-datalog` `blast_radius`.
    let outcome = run(&md, &image, &request, limits()).expect("slg run_query");
    assert_eq!(outcome.status, mneme_prolog::ExecutionStatus::Complete);
    assert!(outcome.exhaustive);
    assert!(
        outcome.consumed.elapsed_ms < 50,
        "run_query cyclic 50-node reach exceeded 50 ms: {} ms",
        outcome.consumed.elapsed_ms
    );
    let prolog_reach: std::collections::BTreeSet<String> = solutions(&outcome)
        .iter()
        .map(|sol| bound_string(sol, "Target"))
        .collect();
    assert_eq!(prolog_reach, datalog_blast);
    eprintln!(
        "SLG 50-node cyclic left-recursive reach: {} nodes, worker={}ms, run_query={}ms, datalog parity=100%",
        prolog_reach.len(),
        worker.elapsed_ms,
        outcome.consumed.elapsed_ms
    );
}

#[test]
fn slg_step_budget_metering_halts_cleanly_on_exhaustion() {
    let mut md = metadata();
    md.allowed_predicates.insert("reach".to_owned());
    md.allowed_predicates.insert("edge".to_owned());
    md.limits.max_rule_count = 8;
    let rows: Vec<Vec<mneme_core::Value>> = (0..20)
        .map(|i| {
            vec![
                string(&format!("n{i}")),
                string(&format!("n{}", (i + 1) % 20)),
            ]
        })
        .collect();
    let image = input_image(Vec::new(), vec![relation("edge", rows)]);
    let rules = vec![
        rule(
            "r-edge",
            atom(
                "edge",
                vec![
                    mneme_prolog::Term::Variable("X".to_owned()),
                    mneme_prolog::Term::Variable("Y".to_owned()),
                ],
            ),
            vec![mneme_prolog::Literal::Positive(atom(
                "relation",
                vec![
                    mneme_prolog::Term::String("edge".to_owned()),
                    mneme_prolog::Term::List(vec![
                        mneme_prolog::Term::Variable("X".to_owned()),
                        mneme_prolog::Term::Variable("Y".to_owned()),
                    ]),
                ],
            ))],
        ),
        rule(
            "r-reach-base",
            atom(
                "reach",
                vec![
                    mneme_prolog::Term::Variable("X".to_owned()),
                    mneme_prolog::Term::Variable("Y".to_owned()),
                ],
            ),
            vec![mneme_prolog::Literal::Positive(atom(
                "edge",
                vec![
                    mneme_prolog::Term::Variable("X".to_owned()),
                    mneme_prolog::Term::Variable("Y".to_owned()),
                ],
            ))],
        ),
        rule(
            "r-reach-rec",
            atom(
                "reach",
                vec![
                    mneme_prolog::Term::Variable("X".to_owned()),
                    mneme_prolog::Term::Variable("Y".to_owned()),
                ],
            ),
            vec![
                mneme_prolog::Literal::Positive(atom(
                    "reach",
                    vec![
                        mneme_prolog::Term::Variable("X".to_owned()),
                        mneme_prolog::Term::Variable("Z".to_owned()),
                    ],
                )),
                mneme_prolog::Literal::Positive(atom(
                    "edge",
                    vec![
                        mneme_prolog::Term::Variable("Z".to_owned()),
                        mneme_prolog::Term::Variable("Y".to_owned()),
                    ],
                )),
            ],
        ),
    ];
    let request = request_for(
        &image,
        atom(
            "reach",
            vec![
                mneme_prolog::Term::String("n0".to_owned()),
                mneme_prolog::Term::Variable("Y".to_owned()),
            ],
        ),
        rules,
    );
    let control = mneme_prolog::process::WorkerControl::new();
    let runtime = mneme_prolog::process::WorkerRuntime {
        control: &control,
        limits: limits(),
    };
    let outcome = mneme_prolog::slg::run_query(
        &md,
        &image,
        &request,
        &runtime,
        mneme_prolog::slg::Config { step_budget: 25 },
    )
    .expect("budget-exhausted SLG query");
    assert_eq!(outcome.status, mneme_prolog::ExecutionStatus::Timeout);
    assert!(!outcome.exhaustive);
}

#[test]
fn abduce_returns_unique_minimal_consistent_proposed_plan_and_commits_zero_records() {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = mneme_store::Workspace::create(
        dir.path(),
        mneme_store::WorkspaceConfig {
            clock: Box::new(mneme_store::FixedClock::new(
                mneme_core::Timestamp::from_nanos(1_000),
            )),
            faults: Box::new(mneme_store::NoFaults),
        },
    )
    .expect("workspace");
    let head_before = workspace.current_revision().expect("head before");

    let mut md = metadata();
    md.features
        .insert(mneme_prolog::Feature::HypotheticalAssumptions);
    md.features.insert(mneme_prolog::Feature::GuardedNegation);
    md.features.insert(mneme_prolog::Feature::Plans);
    for pred in [
        "deploy_ready",
        "schema_migrated",
        "tests_green",
        "frozen",
        "force_override",
        "extra_audit",
        "protected_env",
        "denial",
    ] {
        md.allowed_predicates.insert(pred.to_owned());
    }
    md.limits.max_rule_count = 16;

    let image = input_image(Vec::new(), Vec::new());
    let rules = vec![
        // Protected environment fact.
        fact_rule(
            "f-protected",
            atom(
                "protected_env",
                vec![mneme_prolog::Term::String("prod".to_owned())],
            ),
        ),
        // Valid route missing 2 preconditions + guarded negation `not frozen(Env)`.
        rule(
            "r-deploy-safe",
            atom(
                "deploy_ready",
                vec![mneme_prolog::Term::Variable("Env".to_owned())],
            ),
            vec![
                mneme_prolog::Literal::Positive(atom(
                    "schema_migrated",
                    vec![mneme_prolog::Term::Variable("Env".to_owned())],
                )),
                mneme_prolog::Literal::Positive(atom(
                    "tests_green",
                    vec![mneme_prolog::Term::Variable("Env".to_owned())],
                )),
                mneme_prolog::Literal::Negative(atom(
                    "frozen",
                    vec![mneme_prolog::Term::Variable("Env".to_owned())],
                )),
            ],
        ),
        // Denial-conflicting 1-assumption shortcut (must be rejected!).
        rule(
            "r-deploy-override",
            atom(
                "deploy_ready",
                vec![mneme_prolog::Term::Variable("Env".to_owned())],
            ),
            vec![mneme_prolog::Literal::Positive(atom(
                "force_override",
                vec![mneme_prolog::Term::Variable("Env".to_owned())],
            ))],
        ),
        // Non-minimal 3-assumption superset (must be pruned by minimality!).
        rule(
            "r-deploy-superset",
            atom(
                "deploy_ready",
                vec![mneme_prolog::Term::Variable("Env".to_owned())],
            ),
            vec![
                mneme_prolog::Literal::Positive(atom(
                    "schema_migrated",
                    vec![mneme_prolog::Term::Variable("Env".to_owned())],
                )),
                mneme_prolog::Literal::Positive(atom(
                    "tests_green",
                    vec![mneme_prolog::Term::Variable("Env".to_owned())],
                )),
                mneme_prolog::Literal::Positive(atom(
                    "extra_audit",
                    vec![mneme_prolog::Term::Variable("Env".to_owned())],
                )),
            ],
        ),
        // Integrity constraint: overriding a protected environment is denied.
        rule(
            "r-denial-override",
            atom(
                "denial",
                vec![mneme_prolog::Term::Variable("Env".to_owned())],
            ),
            vec![
                mneme_prolog::Literal::Positive(atom(
                    "force_override",
                    vec![mneme_prolog::Term::Variable("Env".to_owned())],
                )),
                mneme_prolog::Literal::Positive(atom(
                    "protected_env",
                    vec![mneme_prolog::Term::Variable("Env".to_owned())],
                )),
            ],
        ),
    ];

    // Verify compiled s(CASP) dual rules exist for the program.
    let dual = mneme_prolog::abduce::compile_dual_program(&rules);
    assert!(
        dual.predicates
            .contains_key(&("deploy_ready".to_owned(), 1))
    );

    let mut request = request_for(
        &image,
        atom(
            "deploy_ready",
            vec![mneme_prolog::Term::String("prod".to_owned())],
        ),
        rules,
    );
    request.mode = mneme_prolog::QueryMode::Abduce {
        abducibles: std::collections::BTreeSet::from([
            "schema_migrated".to_owned(),
            "tests_green".to_owned(),
            "force_override".to_owned(),
            "extra_audit".to_owned(),
        ]),
        max_assumptions: 3,
    };
    request
        .features
        .insert(mneme_prolog::Feature::HypotheticalAssumptions);
    request
        .features
        .insert(mneme_prolog::Feature::GuardedNegation);
    request.features.insert(mneme_prolog::Feature::Plans);

    let outcome = run(&md, &image, &request, limits()).expect("abduce query");
    assert_eq!(outcome.status, mneme_prolog::ExecutionStatus::Complete);
    assert!(outcome.exhaustive);

    let sols = solutions(&outcome);
    assert_eq!(sols.len(), 1);
    assert_eq!(sols[0].epistemic, mneme_datalog::EpistemicStatus::Proposed);
    assert_eq!(
        sols[0].assumptions,
        std::collections::BTreeSet::from([
            "schema_migrated(\"prod\")".to_owned(),
            "tests_green(\"prod\")".to_owned(),
        ])
    );
    assert_eq!(outcome.proposals.len(), 1);
    let mneme_prolog::Proposal::Plan(plan) = &outcome.proposals[0] else {
        panic!("abduction must emit a PlanProposal");
    };
    assert_eq!(plan.preconditions.len(), 2);
    assert_eq!(plan.assumptions, sols[0].assumptions);

    // Plan stays unaccepted until explicitly reviewed through PlanRegistry::accept.
    let expected_state = mneme_prolog::execution::PlanState {
        scope: scope(),
        base_revision: revision(),
        preconditions: plan.assumptions.clone(),
        sources: std::collections::BTreeMap::new(),
        forgotten: std::collections::BTreeSet::new(),
    };
    let mut registry = mneme_prolog::execution::PlanRegistry::new(expected_state.clone());
    registry
        .register(plan.clone(), 1, expected_state.clone())
        .expect("register abduced plan");
    assert!(
        registry
            .inspect(&plan.id)
            .expect("inspect")
            .accepted
            .is_none()
    );
    let accepted = registry.accept(mneme_prolog::execution::PlanAcceptanceCommand {
        idempotency_key: "review-abduced-plan".to_owned(),
        plan_id: plan.id.clone(),
        plan_revision: 1,
        expected: expected_state,
        decision: subject(0x99),
    });
    assert!(matches!(
        accepted,
        mneme_prolog::execution::PlanOutcome::Accepted { .. }
    ));

    // Zero canonical records committed by abductive reasoning.
    assert_eq!(
        workspace.current_revision().expect("head after"),
        head_before
    );
}

#[test]
fn abduce_guarded_negation_refuses_absence_under_incomplete_coverage() {
    let mut md = metadata();
    md.features
        .insert(mneme_prolog::Feature::HypotheticalAssumptions);
    md.features.insert(mneme_prolog::Feature::GuardedNegation);
    for pred in ["deploy_ready", "schema_migrated", "frozen"] {
        md.allowed_predicates.insert(pred.to_owned());
    }
    let mut image = input_image(Vec::new(), Vec::new());
    image.coverage = mneme_prolog::InputCoverage {
        complete: false,
        reason: Some("partial snapshot".to_owned()),
    };
    image.context.image_digest = format!("sha256:{}", image.content_digest().to_hex());
    let rules = vec![rule(
        "r-guarded",
        atom(
            "deploy_ready",
            vec![mneme_prolog::Term::Variable("Env".to_owned())],
        ),
        vec![
            mneme_prolog::Literal::Positive(atom(
                "schema_migrated",
                vec![mneme_prolog::Term::Variable("Env".to_owned())],
            )),
            mneme_prolog::Literal::Negative(atom(
                "frozen",
                vec![mneme_prolog::Term::Variable("Env".to_owned())],
            )),
        ],
    )];
    let mut request = request_for(
        &image,
        atom(
            "deploy_ready",
            vec![mneme_prolog::Term::String("prod".to_owned())],
        ),
        rules,
    );
    request.mode = mneme_prolog::QueryMode::Abduce {
        abducibles: std::collections::BTreeSet::from(["schema_migrated".to_owned()]),
        max_assumptions: 2,
    };
    request
        .features
        .insert(mneme_prolog::Feature::HypotheticalAssumptions);
    request
        .features
        .insert(mneme_prolog::Feature::GuardedNegation);
    let outcome = run(&md, &image, &request, limits()).expect("incomplete coverage abduce");
    assert_eq!(outcome.status, mneme_prolog::ExecutionStatus::Complete);
    assert!(!outcome.exhaustive);
    assert!(solutions(&outcome).is_empty());
    assert!(outcome.proposals.is_empty());
}
