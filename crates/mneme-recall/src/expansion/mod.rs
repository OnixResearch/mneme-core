//! Bounded entity-seeded expansion through structured recall.
//!
//! A [`Profile`] compiles host-selected seed entities, allowlisted relation
//! types and a hop bound into a versioned Datalog bundle. Structured recall
//! evaluates that bundle like any other: under the request's scope and access,
//! at the pinned revision, within its work, time, row and support limits. The
//! profile adds no authority and no ranking of its own.
//!
//! - A seed contributes only if it is a visible entity in the view, so a
//!   missing seed and an unreadable one expand identically, to nothing.
//! - Relations load only between visible endpoints, and only allowlisted
//!   relation types become edges.
//! - Claims are the accepted, decision-backed, currently based claims the
//!   structured extent admits; proposed, disputed and superseded claims never
//!   become expansion rows.
//! - Each reached entity appears once, at its shortest distance, however many
//!   paths or cycles reach it, so a repeated path cannot add a row.
//! - Rows are ordered by distance or by record identity, as [`Order`] selects.
//!
//! The rows are structured candidates: they carry their derivations and
//! evidence roots but are not claim or excerpt candidates. Connecting a row to
//! the reader-facing candidates of the records it names is a separate,
//! undecided contract, recorded in `docs/entity-seeded-recall.md`.

/// The profile's bundle identity.
pub const PROFILE_ID: &str = "mneme-entity-seeded-expansion";
/// The profile version. Any change to the generated rules changes it.
pub const PROFILE_VERSION: &str = "1";
/// The rule-bundle schema the generated rules are written against: the
/// version the agent API accepts.
pub const BUNDLE_SCHEMA_VERSION: u32 = 3;
/// The relation every expansion query reads.
pub const OUTPUT_PREDICATE: &str = "expanded";
/// Most seed entities one profile may name.
pub const MAX_SEEDS: usize = 16;
/// Most relation types one profile may allow.
pub const MAX_RELATION_TYPES: usize = 8;
/// Longest relation type name, in bytes.
pub const MAX_RELATION_TYPE_BYTES: usize = 128;
/// Most hops one profile may follow.
pub const MAX_HOPS: u8 = 4;
/// Evaluation rounds a profile needs beyond its hops: one for seeds and edges
/// and one for the seeds' own distance.
pub const ROUNDS_BEYOND_HOPS: usize = 2;

/// What an expansion row describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Output {
    /// One row per reached entity: `expanded(distance, entity)` in
    /// [`Order::Distance`], `expanded(entity, distance)` in [`Order::Record`].
    Entities,
    /// One row per admitted claim whose subject is a reached entity:
    /// `expanded(distance, entity, predicate, value, assertion)` in
    /// [`Order::Distance`], `expanded(assertion, entity, predicate, value,
    /// distance)` in [`Order::Record`].
    Claims,
}

/// How structured recall orders expansion rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Order {
    /// Nearest first: the distance is the first column.
    Distance,
    /// By record identity, so distance does not affect a row's position.
    Record,
}

/// A bounded expansion from host-selected seed entities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// Entities expansion starts from, at distance zero.
    pub seeds: std::collections::BTreeSet<mneme_core::RecordId>,
    /// Relation types expansion may follow.
    pub relation_types: std::collections::BTreeSet<String>,
    /// Most relation steps from a seed.
    pub hops: u8,
    /// Follow allowed relations against their direction too.
    pub is_undirected: bool,
    pub output: Output,
    pub order: Order,
    /// Most rows the query returns.
    #[allow(unknown_lints)] // a row bound mirrors the query's collection length
    pub max_rows: usize,
    /// Work, time, row, support and recursion limits for the evaluation.
    pub limits: mneme_datalog::Limits,
}

/// A profile refused before any rule is built.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("an expansion profile needs at least one seed entity")]
    NoSeeds,
    #[error("an expansion profile may name at most {MAX_SEEDS} seeds, not {0}")]
    TooManySeeds(usize),
    #[error("an expansion profile needs at least one allowed relation type")]
    NoRelationTypes,
    #[error("an expansion profile may allow at most {MAX_RELATION_TYPES} relation types, not {0}")]
    TooManyRelationTypes(usize),
    #[error(
        "relation type {0:?} must be between one and {MAX_RELATION_TYPE_BYTES} bytes and contain no control characters"
    )]
    InvalidRelationType(String),
    #[error("an expansion profile must follow between 1 and {MAX_HOPS} hops, not {0}")]
    HopsOutOfRange(u8),
    #[error("an expansion profile must return between 1 and {limit_rows} rows, not {rows}")]
    RowsOutOfRange { rows: usize, limit_rows: usize },
    #[error(
        "a recursion depth of {depth} cannot reach {hops} hops; it must be at least {required}"
    )]
    RecursionBelowHops {
        depth: usize,
        hops: u8,
        required: usize,
    },
}

impl Profile {
    /// Check every bound before any rule is built.
    pub fn validate(&self) -> Result<(), Refusal> {
        if self.seeds.is_empty() {
            return Err(Refusal::NoSeeds);
        }
        if self.seeds.len() > MAX_SEEDS {
            return Err(Refusal::TooManySeeds(self.seeds.len()));
        }
        if self.relation_types.is_empty() {
            return Err(Refusal::NoRelationTypes);
        }
        if self.relation_types.len() > MAX_RELATION_TYPES {
            return Err(Refusal::TooManyRelationTypes(self.relation_types.len()));
        }
        if let Some(invalid) = self
            .relation_types
            .iter()
            .find(|relation_type| !is_valid_relation_type(relation_type))
        {
            return Err(Refusal::InvalidRelationType(invalid.clone()));
        }
        if self.hops == 0 || self.hops > MAX_HOPS {
            return Err(Refusal::HopsOutOfRange(self.hops));
        }
        if self.max_rows == 0 || self.max_rows > self.limits.max_result_rows {
            return Err(Refusal::RowsOutOfRange {
                rows: self.max_rows,
                limit_rows: self.limits.max_result_rows,
            });
        }
        let required = usize::from(self.hops).saturating_add(ROUNDS_BEYOND_HOPS);
        if self.limits.max_recursion_depth < required {
            return Err(Refusal::RecursionBelowHops {
                depth: self.limits.max_recursion_depth,
                hops: self.hops,
                required,
            });
        }
        Ok(())
    }

    /// The versioned rule bundle this profile compiles to.
    pub fn bundle(&self) -> Result<mneme_datalog::RuleBundle, Refusal> {
        self.validate()?;
        let mut rules = Vec::with_capacity(
            self.seeds
                .len()
                .saturating_add(self.relation_types.len().saturating_mul(2))
                .saturating_add(usize::from(self.hops))
                .saturating_add(3),
        );
        rules.extend(
            self.seeds
                .iter()
                .enumerate()
                .map(|(index, seed)| seed_rule(index, *seed)),
        );
        rules.push(start_rule());
        for (index, relation_type) in self.relation_types.iter().enumerate() {
            rules.push(edge_rule(index, relation_type, false));
            if self.is_undirected {
                rules.push(edge_rule(index, relation_type, true));
            }
        }
        rules.extend((1..=self.hops).map(hop_rule));
        rules.push(nearest_rule());
        rules.push(output_rule(self.output, self.order));
        Ok(mneme_datalog::RuleBundle::new(
            mneme_datalog::RuleBundleOptions {
                id: PROFILE_ID.to_owned(),
                version: PROFILE_VERSION.to_owned(),
                schema_version: BUNDLE_SCHEMA_VERSION,
                base_predicates: base_predicates(self.output),
                complete_predicates: std::collections::BTreeSet::from(["reached".to_owned()]),
                rules,
            },
        ))
    }

    /// The structured recall request that evaluates this profile.
    pub fn structured_request(&self) -> Result<crate::model::StructuredRequest, Refusal> {
        Ok(crate::model::StructuredRequest {
            bundle: self.bundle()?,
            query: mneme_datalog::Query::all(OUTPUT_PREDICATE, self.max_rows),
            limits: self.limits.clone(),
            incomplete_extents: std::collections::BTreeSet::new(),
        })
    }
}

fn is_valid_relation_type(relation_type: &str) -> bool {
    !relation_type.is_empty()
        && relation_type.len() <= MAX_RELATION_TYPE_BYTES
        && !relation_type.chars().any(char::is_control)
}

fn base_predicates(output: Output) -> std::collections::BTreeMap<String, usize> {
    let mut predicates =
        std::collections::BTreeMap::from([("entity".to_owned(), 3), ("relation".to_owned(), 3)]);
    match output {
        Output::Entities => {}
        Output::Claims => {
            predicates.insert("assertion".to_owned(), 4);
        }
    }
    predicates
}

fn var(name: &str) -> mneme_datalog::Term {
    mneme_datalog::Term::var(name)
}

fn distance(hops: u8) -> mneme_datalog::Term {
    mneme_datalog::Term::constant(mneme_core::Value::integer(hops))
}

fn positive(predicate: &str, terms: Vec<mneme_datalog::Term>) -> mneme_datalog::Literal {
    mneme_datalog::Literal::Positive(mneme_datalog::Atom::new(predicate, terms))
}

/// `seed(s) :- entity(s, type, label)`: a seed exists only as a visible entity.
fn seed_rule(index: usize, seed: mneme_core::RecordId) -> mneme_datalog::Rule {
    let record = mneme_datalog::Term::constant(seed.to_value());
    mneme_datalog::Rule::new(
        format!("seed-{index}"),
        mneme_datalog::Atom::new("seed", vec![record.clone()]),
        vec![positive("entity", vec![record, var("type"), var("label")])],
    )
}

/// `reached(0, x) :- seed(x)`.
fn start_rule() -> mneme_datalog::Rule {
    mneme_datalog::Rule::new(
        "start",
        mneme_datalog::Atom::new("reached", vec![distance(0), var("x")]),
        vec![positive("seed", vec![var("x")])],
    )
}

/// `edge(x, y) :- relation(type, x, y)`, or `relation(type, y, x)` reversed.
fn edge_rule(index: usize, relation_type: &str, is_reversed: bool) -> mneme_datalog::Rule {
    let (id, from, to) = if is_reversed {
        (format!("edge-{index}-reversed"), var("y"), var("x"))
    } else {
        (format!("edge-{index}"), var("x"), var("y"))
    };
    mneme_datalog::Rule::new(
        id,
        mneme_datalog::Atom::new("edge", vec![var("x"), var("y")]),
        vec![positive(
            "relation",
            vec![
                mneme_datalog::Term::constant(mneme_core::Value::symbol(relation_type)),
                from,
                to,
            ],
        )],
    )
}

/// `reached(k, y) :- reached(k - 1, x), edge(x, y)`: one rule per hop, so the
/// hop bound, not the recursion limit, bounds distance.
fn hop_rule(hops: u8) -> mneme_datalog::Rule {
    mneme_datalog::Rule::new(
        format!("hop-{hops}"),
        mneme_datalog::Atom::new("reached", vec![distance(hops), var("y")]),
        vec![
            positive("reached", vec![distance(hops.saturating_sub(1)), var("x")]),
            positive("edge", vec![var("x"), var("y")]),
        ],
    )
}

/// `nearest(d, x) :- reached(k, x), d = min(k)`: one row per entity.
fn nearest_rule() -> mneme_datalog::Rule {
    mneme_datalog::Rule::new(
        "nearest",
        mneme_datalog::Atom::new("nearest", vec![var("distance"), var("x")]),
        vec![
            positive("reached", vec![var("hops"), var("x")]),
            mneme_datalog::Literal::Aggregate {
                function: mneme_datalog::AggregateFunction::Min,
                input: var("hops"),
                output: "distance".to_owned(),
            },
        ],
    )
}

fn output_rule(output: Output, order: Order) -> mneme_datalog::Rule {
    let nearest = positive("nearest", vec![var("distance"), var("x")]);
    let (head, body) = match output {
        Output::Entities => (
            match order {
                Order::Distance => vec![var("distance"), var("x")],
                Order::Record => vec![var("x"), var("distance")],
            },
            vec![nearest],
        ),
        Output::Claims => (
            match order {
                Order::Distance => vec![
                    var("distance"),
                    var("x"),
                    var("predicate"),
                    var("value"),
                    var("assertion"),
                ],
                Order::Record => vec![
                    var("assertion"),
                    var("x"),
                    var("predicate"),
                    var("value"),
                    var("distance"),
                ],
            },
            vec![
                nearest,
                positive(
                    "assertion",
                    vec![var("x"), var("predicate"), var("value"), var("assertion")],
                ),
            ],
        ),
    };
    mneme_datalog::Rule::new(
        "output",
        mneme_datalog::Atom::new(OUTPUT_PREDICATE, head),
        body,
    )
}
