//! Bounded, read-only inline Datalog query blocks for AsciiDoc previews.
//!
//! Supports `[mneme-query, ...]` attribute blocks referencing either a named
//! standing rule bundle or an inline read-only Datalog rule body, evaluated
//! against one pinned workspace revision without mutating the ledger.

use std::collections::BTreeMap;

/// Default maximum rows returned by one inline query block.
pub const DEFAULT_QUERY_LIMIT: u32 = 25;
/// Hard ceiling on rows returned by one inline query block.
pub const MAX_QUERY_LIMIT: u32 = 200;
/// Default work budget for one inline query block.
pub const DEFAULT_MAX_WORK: u64 = 50_000;
/// Hard ceiling on work units for one inline query block.
pub const MAX_QUERY_WORK: u64 = 100_000;
/// Default wall-clock budget (ms) for one inline query block.
pub const DEFAULT_MAX_TIME_MS: u64 = 1_000;
/// Hard ceiling on wall-clock time (ms) for one inline query block.
pub const MAX_QUERY_TIME_MS: u64 = 2_000;
/// Maximum inline query blocks evaluated in one document preview.
pub const MAX_INLINE_QUERIES_PER_PREVIEW: usize = 16;
/// Maximum byte length of an inline Datalog rule body.
pub const MAX_INLINE_BODY_BYTES: usize = 16 * 1024;

/// How an inline query block should be rendered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryLayout {
    Table,
    List,
}

/// Parsed `[mneme-query, ...]` block attributes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuerySpec {
    pub bundle: Option<String>,
    pub relation: Option<String>,
    pub limit: u32,
    pub max_work: u64,
    pub max_time_ms: u64,
    pub layout: QueryLayout,
}

impl Default for QuerySpec {
    fn default() -> Self {
        QuerySpec {
            bundle: None,
            relation: None,
            limit: DEFAULT_QUERY_LIMIT,
            max_work: DEFAULT_MAX_WORK,
            max_time_ms: DEFAULT_MAX_TIME_MS,
            layout: QueryLayout::Table,
        }
    }
}

/// One cell in a rendered query result row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryCell {
    pub display: String,
    pub record_id: Option<mneme_core::RecordId>,
    pub document_id: Option<mneme_core::RecordId>,
}

/// Result of evaluating one inline query block against a workspace revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryOutcome {
    pub relation: String,
    pub layout: QueryLayout,
    pub status: mneme_datalog::ExecutionStatus,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<QueryCell>>,
    pub truncated: bool,
    pub exhaustive: bool,
    pub absence_established: bool,
    pub work: u64,
    pub diagnostic: Option<crate::asciidoc::Diagnostic>,
    pub revision: mneme_core::WorkspaceRevisionId,
}

/// A validated query ready for evaluation.
#[derive(Clone, Debug)]
pub struct PreparedQuery {
    pub spec: QuerySpec,
    pub bundle: mneme_datalog::RuleBundle,
    pub relation: String,
    pub columns: Vec<String>,
    pub constants: Vec<Option<mneme_core::Value>>,
}

/// Context passed when evaluating a query block against a workspace snapshot.
pub struct EvaluationContext {
    pub revision: mneme_core::WorkspaceRevisionId,
    pub scope: mneme_core::ScopeId,
    pub allow_stale: bool,
}

/// Parse a trimmed AsciiDoc attribute line if it starts with `[mneme-query`.
///
/// Returns `None` when the line is not a `mneme-query` block attribute.
pub fn parse_attribute_line(trimmed: &str) -> Option<Result<QuerySpec, String>> {
    let rest = trimmed.strip_prefix("[mneme-query")?;
    if !rest.is_empty()
        && !rest.starts_with(']')
        && !rest.starts_with(',')
        && !rest.starts_with(char::is_whitespace)
    {
        return None;
    }
    let Some(inner) = rest.strip_suffix(']') else {
        return Some(Err(
            "malformed [mneme-query] attribute: missing closing `]`".to_owned(),
        ));
    };
    Some(parse_attributes(inner))
}

fn parse_attributes(inner: &str) -> Result<QuerySpec, String> {
    let mut spec = QuerySpec::default();
    let trimmed = inner.trim();
    if trimmed.is_empty() {
        return Ok(spec);
    }
    let parts = split_outside_quotes(trimmed, ',')?;
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let Some((raw_key, raw_val)) = part.split_once('=') else {
            return Err(format!(
                "malformed mneme-query attribute `{part}`: expected `key=value`"
            ));
        };
        let key = raw_key.trim();
        let val = unquote(raw_val.trim())?;
        apply_attribute(&mut spec, key, &val)?;
    }
    Ok(spec)
}

fn apply_attribute(spec: &mut QuerySpec, key: &str, val: &str) -> Result<(), String> {
    match key {
        "bundle" => {
            if val.is_empty() {
                return Err("mneme-query `bundle` cannot be empty".to_owned());
            }
            spec.bundle = Some(val.to_owned());
        }
        "relation" => {
            if val.is_empty() {
                return Err("mneme-query `relation` cannot be empty".to_owned());
            }
            spec.relation = Some(val.to_owned());
        }
        "limit" => {
            let parsed = val
                .parse::<u32>()
                .map_err(|_| format!("invalid mneme-query `limit`: `{val}`"))?;
            if parsed == 0 {
                return Err("mneme-query `limit` must be at least 1".to_owned());
            }
            spec.limit = parsed.min(MAX_QUERY_LIMIT);
        }
        "work" | "max_work" => {
            let parsed = val
                .parse::<u64>()
                .map_err(|_| format!("invalid mneme-query `{key}`: `{val}`"))?;
            if parsed == 0 {
                return Err(format!("mneme-query `{key}` must be at least 1"));
            }
            spec.max_work = parsed.min(MAX_QUERY_WORK);
        }
        "time_ms" | "max_time_ms" => {
            let parsed = val
                .parse::<u64>()
                .map_err(|_| format!("invalid mneme-query `{key}`: `{val}`"))?;
            if parsed == 0 {
                return Err(format!("mneme-query `{key}` must be at least 1"));
            }
            spec.max_time_ms = parsed.min(MAX_QUERY_TIME_MS);
        }
        "layout" => {
            spec.layout = match val {
                "table" => QueryLayout::Table,
                "list" => QueryLayout::List,
                _ => {
                    return Err(format!(
                        "invalid mneme-query `layout`: `{val}` (expected `table` or `list`)"
                    ));
                }
            };
        }
        _ => {
            return Err(format!("unknown mneme-query attribute `{key}`"));
        }
    }
    Ok(())
}

/// Prepare a `mneme-query` block from its parsed attributes and optional inline body.
pub fn prepare(spec: &QuerySpec, body: Option<&str>) -> Result<PreparedQuery, String> {
    if let Some(body_text) = body {
        let trimmed = body_text.trim();
        if !trimmed.is_empty() {
            if trimmed.len() > MAX_INLINE_BODY_BYTES {
                return Err(format!(
                    "inline Datalog query exceeds the {MAX_INLINE_BODY_BYTES}-byte limit"
                ));
            }
            return prepare_inline(spec, trimmed);
        }
    }
    prepare_standing(spec)
}

fn prepare_standing(spec: &QuerySpec) -> Result<PreparedQuery, String> {
    let relation = spec
        .relation
        .as_deref()
        .ok_or_else(|| "standing mneme-query requires `relation=<name>`".to_owned())?;
    let bundle_name = spec.bundle.as_deref().unwrap_or_else(|| {
        if is_base_predicate(relation) {
            "base"
        } else {
            "auto-relations"
        }
    });
    match bundle_name {
        "auto-relations" | "builtin-auto-relations" => {
            let bundle = builtin_auto_relations_bundle();
            let columns = standing_columns(relation)?;
            Ok(PreparedQuery {
                spec: spec.clone(),
                bundle,
                relation: relation.to_owned(),
                columns,
                constants: Vec::new(),
            })
        }
        "base" => {
            let (bundle, columns) = base_predicate_bundle(relation)?;
            Ok(PreparedQuery {
                spec: spec.clone(),
                bundle,
                relation: relation.to_owned(),
                columns,
                constants: Vec::new(),
            })
        }
        other => Err(format!("unknown standing rule bundle `{other}`")),
    }
}

fn standing_columns(relation: &str) -> Result<Vec<String>, String> {
    match relation {
        "proposed_links" => Ok(vec!["from".to_owned(), "to".to_owned(), "kind".to_owned()]),
        "shared_artifact" => Ok(vec!["a".to_owned(), "b".to_owned(), "target".to_owned()]),
        "co_author" => Ok(vec!["a".to_owned(), "b".to_owned(), "author".to_owned()]),
        "unlinked_entities" => Ok(vec![
            "entity".to_owned(),
            "type".to_owned(),
            "label".to_owned(),
        ]),
        other => Err(format!(
            "relation `{other}` is not defined in standing bundle `auto-relations`"
        )),
    }
}

fn base_predicate_arity(predicate: &str) -> Option<(usize, &'static [&'static str])> {
    match predicate {
        "entity" => Some((3, &["entity", "type", "label"])),
        "relation" => Some((3, &["kind", "from", "to"])),
        "document" => Some((3, &["document", "entity", "path"])),
        "assertion" => Some((4, &["subject", "predicate", "value", "id"])),
        "denial" => Some((4, &["subject", "predicate", "value", "id"])),
        "hypothesis" => Some((4, &["subject", "predicate", "value", "id"])),
        "evidence" => Some((2, &["assertion", "source"])),
        "source" => Some((3, &["source", "revision", "availability"])),
        "derivation" => Some((2, &["conclusion", "premise"])),
        _ => None,
    }
}

fn is_base_predicate(predicate: &str) -> bool {
    base_predicate_arity(predicate).is_some()
}

fn base_predicate_bundle(
    predicate: &str,
) -> Result<(mneme_datalog::RuleBundle, Vec<String>), String> {
    let Some((arity, cols)) = base_predicate_arity(predicate) else {
        return Err(format!("unknown base predicate `{predicate}`"));
    };
    let mut base_predicates = BTreeMap::new();
    base_predicates.insert(predicate.to_owned(), arity);
    let mut complete_predicates = std::collections::BTreeSet::new();
    complete_predicates.insert(predicate.to_owned());
    let bundle = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: format!("inline-base-{predicate}"),
        version: "1".to_owned(),
        schema_version: 3,
        base_predicates,
        complete_predicates,
        rules: Vec::new(),
    });
    Ok((bundle, cols.iter().map(|c| (*c).to_owned()).collect()))
}

fn builtin_auto_relations_bundle() -> mneme_datalog::RuleBundle {
    use mneme_datalog::{Atom, CompareOp, Literal, Rule, Term};

    let mut base_predicates = BTreeMap::new();
    base_predicates.insert("entity".to_owned(), 3);
    base_predicates.insert("relation".to_owned(), 3);
    base_predicates.insert("document".to_owned(), 3);

    let mut complete_predicates = std::collections::BTreeSet::new();
    complete_predicates.insert("entity".to_owned());
    complete_predicates.insert("relation".to_owned());
    complete_predicates.insert("document".to_owned());
    complete_predicates.insert("linked_entity".to_owned());

    let sym = |name: &str| Term::constant(mneme_core::Value::symbol(name));
    let var = Term::var;

    let rules = vec![
        Rule::new(
            "proposed-links",
            Atom::new("proposed_links", vec![var("From"), var("To"), var("Kind")]),
            vec![Literal::Positive(Atom::new(
                "relation",
                vec![var("Kind"), var("From"), var("To")],
            ))],
        ),
        Rule::new(
            "shared-repo",
            Atom::new("shared_artifact", vec![var("A"), var("B"), var("Target")]),
            vec![
                Literal::Positive(Atom::new(
                    "relation",
                    vec![sym("links_repo"), var("A"), var("Target")],
                )),
                Literal::Positive(Atom::new(
                    "relation",
                    vec![sym("links_repo"), var("B"), var("Target")],
                )),
                Literal::Compare {
                    op: CompareOp::Ne,
                    left: var("A"),
                    right: var("B"),
                },
            ],
        ),
        Rule::new(
            "shared-paper",
            Atom::new("shared_artifact", vec![var("A"), var("B"), var("Target")]),
            vec![
                Literal::Positive(Atom::new(
                    "relation",
                    vec![sym("cites_arxiv"), var("A"), var("Target")],
                )),
                Literal::Positive(Atom::new(
                    "relation",
                    vec![sym("cites_arxiv"), var("B"), var("Target")],
                )),
                Literal::Compare {
                    op: CompareOp::Ne,
                    left: var("A"),
                    right: var("B"),
                },
            ],
        ),
        Rule::new(
            "co-author",
            Atom::new("co_author", vec![var("A"), var("B"), var("Author")]),
            vec![
                Literal::Positive(Atom::new(
                    "relation",
                    vec![sym("authored_by"), var("A"), var("Author")],
                )),
                Literal::Positive(Atom::new(
                    "relation",
                    vec![sym("authored_by"), var("B"), var("Author")],
                )),
                Literal::Compare {
                    op: CompareOp::Ne,
                    left: var("A"),
                    right: var("B"),
                },
            ],
        ),
        Rule::new(
            "linked-entity",
            Atom::new("linked_entity", vec![var("Id")]),
            vec![Literal::Positive(Atom::new(
                "document",
                vec![var("Doc"), var("Id"), var("Path")],
            ))],
        ),
        Rule::new(
            "unlinked-entities",
            Atom::new(
                "unlinked_entities",
                vec![var("Id"), var("Type"), var("Label")],
            ),
            vec![
                Literal::Positive(Atom::new(
                    "entity",
                    vec![var("Id"), var("Type"), var("Label")],
                )),
                Literal::Negative(Atom::new("linked_entity", vec![var("Id")])),
            ],
        ),
    ];

    mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "builtin-auto-relations".to_owned(),
        version: "1".to_owned(),
        schema_version: 3,
        base_predicates,
        complete_predicates,
        rules,
    })
}

/// Evaluate a prepared query against one pinned workspace revision (read-only).
pub fn evaluate(
    workspace: &mut mneme_store::Workspace,
    ctx: &EvaluationContext,
    prepared: &PreparedQuery,
) -> QueryOutcome {
    let row_limit = usize::try_from(prepared.spec.limit).unwrap_or(DEFAULT_QUERY_LIMIT as usize);
    let limits = mneme_datalog::Limits {
        max_work: prepared.spec.max_work,
        max_time_ms: u128::from(prepared.spec.max_time_ms),
        max_result_rows: mneme_datalog::Limits::default()
            .max_result_rows
            .max(row_limit),
        max_supports_per_fact: 4,
        max_recursion_depth: 16,
    };
    let mut service = mneme_datalog::Service::new(workspace);
    let build = match service.build(mneme_datalog::BuildRequest {
        actor: "inline-query-preview".to_owned(),
        scope: ctx.scope.clone(),
        revision: ctx.revision,
        bundle: prepared.bundle.clone(),
        limits,
        publish: false,
        incomplete_extents: std::collections::BTreeSet::new(),
        cancellation: None,
        access: mneme_memory::Access::Operator,
        at: None,
    }) {
        Ok(build) => build,
        Err(error) => {
            return failed_outcome(prepared, ctx.revision, format_datalog_error(&error));
        }
    };

    let mut query = mneme_datalog::Query::all(&prepared.relation, row_limit);
    query.constants = prepared.columns_constants(&prepared.constants);
    query.allow_stale = ctx.allow_stale;

    let result = match service.query_build(&build, query) {
        Ok(result) => result,
        Err(error) => {
            return failed_outcome(prepared, ctx.revision, format_datalog_error(&error));
        }
    };

    let labels = load_record_labels(workspace, ctx.revision, &ctx.scope);
    let rows = result
        .rows
        .iter()
        .map(|row| {
            row.values
                .iter()
                .map(|val| format_cell(val, &labels))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let diagnostic = outcome_diagnostic(&result);
    QueryOutcome {
        relation: result.relation,
        layout: prepared.spec.layout,
        status: result.status,
        columns: prepared.columns.clone(),
        rows,
        truncated: result.truncated,
        exhaustive: result.exhaustive,
        absence_established: result.absence_established,
        work: result.work,
        diagnostic,
        revision: result.served_revision,
    }
}

impl PreparedQuery {
    fn columns_constants(
        &self,
        constants: &[Option<mneme_core::Value>],
    ) -> Vec<Option<mneme_core::Value>> {
        constants.to_vec()
    }
}

fn failed_outcome(
    prepared: &PreparedQuery,
    revision: mneme_core::WorkspaceRevisionId,
    message: String,
) -> QueryOutcome {
    QueryOutcome {
        relation: prepared.relation.clone(),
        layout: prepared.spec.layout,
        status: mneme_datalog::ExecutionStatus::Failed,
        columns: prepared.columns.clone(),
        rows: Vec::new(),
        truncated: false,
        exhaustive: false,
        absence_established: false,
        work: 0,
        diagnostic: Some(crate::asciidoc::Diagnostic::warning(
            "datalog-query-invalid",
            message,
            1,
            1,
            None,
        )),
        revision,
    }
}

fn outcome_diagnostic(result: &mneme_datalog::QueryResult) -> Option<crate::asciidoc::Diagnostic> {
    match result.status {
        mneme_datalog::ExecutionStatus::Complete if !result.truncated => None,
        mneme_datalog::ExecutionStatus::Complete => Some(crate::asciidoc::Diagnostic::warning(
            "datalog-query-truncated",
            format!(
                "query `{}` truncated at row limit ({} rows shown)",
                result.relation,
                result.rows.len()
            ),
            1,
            1,
            None,
        )),
        mneme_datalog::ExecutionStatus::Timeout => Some(crate::asciidoc::Diagnostic::warning(
            "datalog-query-timeout",
            result
                .reason
                .clone()
                .unwrap_or_else(|| format!("query `{}` exceeded its time budget", result.relation)),
            1,
            1,
            None,
        )),
        mneme_datalog::ExecutionStatus::Partial => Some(crate::asciidoc::Diagnostic::warning(
            "datalog-query-budget-exceeded",
            result.reason.clone().unwrap_or_else(|| {
                format!(
                    "query `{}` stopped at work/row budget ({} work units)",
                    result.relation, result.work
                )
            }),
            1,
            1,
            None,
        )),
        mneme_datalog::ExecutionStatus::Cancelled => Some(crate::asciidoc::Diagnostic::warning(
            "datalog-query-cancelled",
            format!("query `{}` was cancelled", result.relation),
            1,
            1,
            None,
        )),
        mneme_datalog::ExecutionStatus::Failed => Some(crate::asciidoc::Diagnostic::warning(
            "datalog-query-failed",
            result
                .reason
                .clone()
                .unwrap_or_else(|| format!("query `{}` failed", result.relation)),
            1,
            1,
            None,
        )),
    }
}

fn format_datalog_error(error: &mneme_datalog::Error) -> String {
    match error {
        mneme_datalog::Error::InvalidBundle(diagnostics) => diagnostics
            .iter()
            .map(|d| {
                format!(
                    "{}{}: {}",
                    d.rule
                        .as_ref()
                        .map(|r| format!("rule {r}: "))
                        .unwrap_or_default(),
                    d.code,
                    d.message
                )
            })
            .collect::<Vec<_>>()
            .join("; "),
        other => other.to_string(),
    }
}

#[derive(Default)]
struct RecordLabels {
    titles: BTreeMap<mneme_core::RecordId, String>,
    entity_to_doc: BTreeMap<mneme_core::RecordId, mneme_core::RecordId>,
}

fn load_record_labels(
    workspace: &mneme_store::Workspace,
    revision: mneme_core::WorkspaceRevisionId,
    scope: &mneme_core::ScopeId,
) -> RecordLabels {
    let mut labels = RecordLabels::default();
    let Ok(snapshot) = workspace.snapshot_at(revision, None) else {
        return labels;
    };
    for record in &snapshot.records {
        if &record.scope != scope {
            continue;
        }
        match record.kind {
            mneme_core::RecordKind::Entity => {
                if let Some(label) = record
                    .payload
                    .get("label")
                    .and_then(mneme_core::Value::as_string)
                {
                    labels.titles.insert(record.record_id, label.to_owned());
                }
            }
            mneme_core::RecordKind::Document => {
                let title = record
                    .payload
                    .get("title")
                    .and_then(mneme_core::Value::as_string)
                    .filter(|s| !s.is_empty())
                    .or_else(|| {
                        record
                            .payload
                            .get("path")
                            .and_then(mneme_core::Value::as_string)
                    });
                if let Some(title) = title {
                    labels.titles.insert(record.record_id, title.to_owned());
                }
                if let Some(entity_val) = record.payload.get("entity")
                    && let Ok(entity_id) =
                        mneme_core::RecordId::from_value(entity_val, &mneme_core::Path::root())
                {
                    labels
                        .entity_to_doc
                        .entry(entity_id)
                        .or_insert(record.record_id);
                }
            }
            _ => {}
        }
    }
    labels
}

fn format_cell(value: &mneme_core::Value, labels: &RecordLabels) -> QueryCell {
    if let Ok(record_id) = mneme_core::RecordId::from_value(value, &mneme_core::Path::root()) {
        let document_id = if labels.entity_to_doc.contains_key(&record_id) {
            labels.entity_to_doc.get(&record_id).copied()
        } else {
            // If it's a document record itself (or unknown), keep Some(record_id) if it's in titles
            labels.titles.contains_key(&record_id).then_some(record_id)
        };
        let display = labels
            .titles
            .get(&record_id)
            .cloned()
            .unwrap_or_else(|| short_record_hex(record_id));
        return QueryCell {
            display,
            record_id: Some(record_id),
            document_id,
        };
    }
    let display = if let Some(s) = value.as_string() {
        s.to_owned()
    } else if let Some(s) = value.as_symbol() {
        s.as_str().to_owned()
    } else if let Some(i) = value.as_integer() {
        i.to_string()
    } else if let Some(b) = value.as_boolean() {
        b.to_string()
    } else {
        mneme_core::encode_value(value).to_string()
    };
    QueryCell {
        display,
        record_id: None,
        document_id: None,
    }
}

fn short_record_hex(id: mneme_core::RecordId) -> String {
    let hex = id.to_hex();
    hex.get(..12).map_or(hex.clone(), ToOwned::to_owned)
}

// ---------------------------------------------------------------------------
// Inline Datalog rule parser
// ---------------------------------------------------------------------------

fn prepare_inline(spec: &QuerySpec, body: &str) -> Result<PreparedQuery, String> {
    let statements = split_statements(body)?;
    if statements.is_empty() {
        return Err("inline mneme-query block contains no rules".to_owned());
    }
    let mut rules = Vec::new();
    let mut query_goal: Option<(String, Vec<mneme_datalog::Term>)> = None;
    let mut anon_counter = 0_usize;

    for (idx, stmt) in statements.iter().enumerate() {
        let trimmed = stmt.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(goal_str) = trimmed.strip_prefix("?-") {
            let atom = parse_atom(goal_str.trim(), &mut anon_counter)?;
            query_goal = Some((atom.predicate, atom.terms));
            continue;
        }
        let Some((head_str, body_str)) = trimmed.split_once(":-") else {
            return Err(format!(
                "invalid Datalog rule `{trimmed}`: expected `head(...) :- body.` or `?- query(...).`"
            ));
        };
        let head = parse_atom(head_str.trim(), &mut anon_counter)?;
        let body_parts = split_outside_quotes_and_parens(body_str.trim(), ',')?;
        if body_parts.is_empty() {
            return Err(format!("rule `{}` has an empty body", head.predicate));
        }
        let mut literals = Vec::with_capacity(body_parts.len());
        for part in body_parts {
            let lit_str = part.trim();
            if lit_str.is_empty() {
                continue;
            }
            literals.push(parse_literal(lit_str, &mut anon_counter)?);
        }
        rules.push(mneme_datalog::Rule::new(
            format!("inline-rule-{}", idx + 1),
            head,
            literals,
        ));
    }

    let InlineTarget {
        relation,
        constants,
        columns,
    } = resolve_inline_target(spec, &rules, query_goal.as_ref())?;

    let mut base_predicates = BTreeMap::new();
    let mut complete_predicates = std::collections::BTreeSet::new();
    for rule in &rules {
        for lit in &rule.body {
            if let mneme_datalog::Literal::Negative(atom) = lit {
                complete_predicates.insert(atom.predicate.clone());
            }
            let pred = match lit {
                mneme_datalog::Literal::Positive(atom) | mneme_datalog::Literal::Negative(atom) => {
                    Some(atom.predicate.as_str())
                }
                _ => None,
            };
            if let Some(pred) = pred
                && let Some((arity, _)) = base_predicate_arity(pred)
            {
                base_predicates.insert(pred.to_owned(), arity);
                complete_predicates.insert(pred.to_owned());
            }
        }
    }
    if let Some((arity, _)) = base_predicate_arity(&relation) {
        base_predicates.insert(relation.clone(), arity);
        complete_predicates.insert(relation.clone());
    }

    let bundle = mneme_datalog::RuleBundle::new(mneme_datalog::RuleBundleOptions {
        id: "inline-query".to_owned(),
        version: "1".to_owned(),
        schema_version: 3,
        base_predicates,
        complete_predicates,
        rules,
    });

    Ok(PreparedQuery {
        spec: spec.clone(),
        bundle,
        relation,
        columns,
        constants,
    })
}

struct InlineTarget {
    relation: String,
    constants: Vec<Option<mneme_core::Value>>,
    columns: Vec<String>,
}

fn resolve_inline_target(
    spec: &QuerySpec,
    rules: &[mneme_datalog::Rule],
    query_goal: Option<&(String, Vec<mneme_datalog::Term>)>,
) -> Result<InlineTarget, String> {
    let relation = if let Some(rel) = &spec.relation {
        rel.clone()
    } else if let Some((pred, _)) = query_goal {
        pred.clone()
    } else if let Some(first) = rules.first() {
        first.head.predicate.clone()
    } else {
        return Err("inline mneme-query has no target relation".to_owned());
    };

    let constants = match query_goal {
        Some((pred, terms)) if pred == &relation => terms
            .iter()
            .map(|term| match term {
                mneme_datalog::Term::Constant(v) => Some(v.clone()),
                mneme_datalog::Term::Variable(_) => None,
            })
            .collect(),
        _ => Vec::new(),
    };

    let columns = if let Some((_, cols)) = base_predicate_arity(&relation) {
        cols.iter().map(|c| (*c).to_owned()).collect()
    } else if let Some(rule) = rules.iter().find(|r| r.head.predicate == relation) {
        rule.head
            .terms
            .iter()
            .enumerate()
            .map(|(i, term)| match term {
                mneme_datalog::Term::Variable(name) => name.clone(),
                mneme_datalog::Term::Constant(_) => format!("col{}", i + 1),
            })
            .collect()
    } else {
        Vec::new()
    };

    Ok(InlineTarget {
        relation,
        constants,
        columns,
    })
}

fn parse_literal(text: &str, anon_counter: &mut usize) -> Result<mneme_datalog::Literal, String> {
    if let Some(rest) = text.strip_prefix("not ") {
        return Ok(mneme_datalog::Literal::Negative(parse_atom(
            rest.trim(),
            anon_counter,
        )?));
    }
    if let Some(rest) = text.strip_prefix("\\+") {
        return Ok(mneme_datalog::Literal::Negative(parse_atom(
            rest.trim(),
            anon_counter,
        )?));
    }
    if let Some((left_str, op, right_str)) = split_comparison(text) {
        let left = parse_term(left_str.trim(), anon_counter)?;
        let right = parse_term(right_str.trim(), anon_counter)?;
        return Ok(mneme_datalog::Literal::Compare { op, left, right });
    }
    Ok(mneme_datalog::Literal::Positive(parse_atom(
        text,
        anon_counter,
    )?))
}

fn split_comparison(text: &str) -> Option<(&str, mneme_datalog::CompareOp, &str)> {
    // Only match comparison operators outside parentheses and quotes.
    let mut depth = 0_usize;
    let mut in_quote: Option<char> = None;
    let mut escaped = false;
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let ch = bytes[i] as char;
        if let Some(q) = in_quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }
        match ch {
            '"' | '\'' => in_quote = Some(ch),
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            _ if depth == 0 => {
                let rest = &text[i..];
                for (sym, op) in [
                    ("==", mneme_datalog::CompareOp::Eq),
                    ("!=", mneme_datalog::CompareOp::Ne),
                    ("<=", mneme_datalog::CompareOp::Le),
                    (">=", mneme_datalog::CompareOp::Ge),
                    ("=", mneme_datalog::CompareOp::Eq),
                    ("<", mneme_datalog::CompareOp::Lt),
                    (">", mneme_datalog::CompareOp::Gt),
                ] {
                    if rest.starts_with(sym) {
                        return Some((&text[..i], op, &text[i + sym.len()..]));
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn parse_atom(text: &str, anon_counter: &mut usize) -> Result<mneme_datalog::Atom, String> {
    let Some(open_idx) = text.find('(') else {
        return Err(format!("invalid atom `{text}`: expected `pred(...)`"));
    };
    let Some(inner) = text[open_idx + 1..].strip_suffix(')') else {
        return Err(format!("invalid atom `{text}`: missing closing `)`"));
    };
    let predicate = text[..open_idx].trim();
    if predicate.is_empty()
        || !predicate
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(format!("invalid predicate name `{predicate}`"));
    }
    let arg_parts = if inner.trim().is_empty() {
        Vec::new()
    } else {
        split_outside_quotes_and_parens(inner, ',')?
    };
    let mut terms = Vec::with_capacity(arg_parts.len());
    for part in arg_parts {
        terms.push(parse_term(part.trim(), anon_counter)?);
    }
    Ok(mneme_datalog::Atom::new(predicate, terms))
}

fn parse_term(text: &str, anon_counter: &mut usize) -> Result<mneme_datalog::Term, String> {
    if text.is_empty() {
        return Err("empty term in Datalog rule".to_owned());
    }
    if text == "_" {
        let name = format!("_anon_{anon_counter}");
        *anon_counter = anon_counter.saturating_add(1);
        return Ok(mneme_datalog::Term::var(name));
    }
    if text.starts_with('"') {
        let val = unquote(text)?;
        return Ok(mneme_datalog::Term::constant(mneme_core::Value::string(
            val,
        )));
    }
    if text.starts_with('\'') {
        let val = unquote(text)?;
        return Ok(mneme_datalog::Term::constant(mneme_core::Value::symbol(
            val,
        )));
    }
    if let Some(sym) = text.strip_prefix(':') {
        if sym.is_empty() {
            return Err("empty symbol literal `:`".to_owned());
        }
        return Ok(mneme_datalog::Term::constant(mneme_core::Value::symbol(
            sym,
        )));
    }
    if text == "true" {
        return Ok(mneme_datalog::Term::constant(mneme_core::Value::Boolean(
            true,
        )));
    }
    if text == "false" {
        return Ok(mneme_datalog::Term::constant(mneme_core::Value::Boolean(
            false,
        )));
    }
    if let Ok(int_val) = text.parse::<i64>() {
        return Ok(mneme_datalog::Term::constant(mneme_core::Value::integer(
            int_val,
        )));
    }
    let first = text.chars().next().unwrap_or('_');
    if first.is_ascii_uppercase() || first == '_' {
        return Ok(mneme_datalog::Term::var(text));
    }
    if text
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Ok(mneme_datalog::Term::constant(mneme_core::Value::symbol(
            text,
        )));
    }
    Err(format!("invalid Datalog term `{text}`"))
}

fn split_statements(body: &str) -> Result<Vec<String>, String> {
    let mut cleaned = String::with_capacity(body.len());
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('%') || trimmed.starts_with("//") {
            continue;
        }
        cleaned.push_str(line);
        cleaned.push('\n');
    }
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut in_quote: Option<char> = None;
    let mut escaped = false;
    for ch in cleaned.chars() {
        if let Some(q) = in_quote {
            current.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                in_quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => {
                in_quote = Some(ch);
                current.push(ch);
            }
            '.' => {
                let stmt = current.trim().to_owned();
                if !stmt.is_empty() {
                    statements.push(stmt);
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if in_quote.is_some() {
        return Err("unterminated string literal in Datalog block".to_owned());
    }
    if !current.trim().is_empty() {
        return Err(format!(
            "missing trailing `.` on Datalog statement `{}`",
            current.trim()
        ));
    }
    Ok(statements)
}

fn split_outside_quotes(text: &str, sep: char) -> Result<Vec<String>, String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quote: Option<char> = None;
    let mut escaped = false;
    for ch in text.chars() {
        if let Some(q) = in_quote {
            current.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                in_quote = None;
            }
            continue;
        }
        if ch == '"' || ch == '\'' {
            in_quote = Some(ch);
            current.push(ch);
        } else if ch == sep {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    if in_quote.is_some() {
        return Err("unterminated quoted value in mneme-query".to_owned());
    }
    parts.push(current);
    Ok(parts)
}

fn split_outside_quotes_and_parens(text: &str, sep: char) -> Result<Vec<String>, String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth = 0_usize;
    let mut in_quote: Option<char> = None;
    let mut escaped = false;
    for ch in text.chars() {
        if let Some(q) = in_quote {
            current.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                in_quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => {
                in_quote = Some(ch);
                current.push(ch);
            }
            '(' => {
                depth += 1;
                current.push(ch);
            }
            ')' => {
                depth = depth.saturating_sub(1);
                current.push(ch);
            }
            _ if ch == sep && depth == 0 => {
                parts.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    if in_quote.is_some() {
        return Err("unterminated quoted literal in Datalog rule".to_owned());
    }
    if depth != 0 {
        return Err("unbalanced parentheses in Datalog rule".to_owned());
    }
    parts.push(current);
    Ok(parts)
}

fn unquote(text: &str) -> Result<String, String> {
    let first = text.chars().next();
    let last = text.chars().last();
    if matches!(
        (first, last),
        (Some('"'), Some('"')) | (Some('\''), Some('\''))
    ) && text.len() >= 2
    {
        Ok(text[1..text.len() - 1].to_owned())
    } else {
        Ok(text.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_attribute_line_accepts_standing_and_options() {
        let spec = parse_attribute_line("[mneme-query, relation=proposed_links, limit=25]")
            .expect("should match")
            .expect("should parse");
        assert_eq!(spec.relation.as_deref(), Some("proposed_links"));
        assert_eq!(spec.limit, 25);
        assert_eq!(spec.layout, QueryLayout::Table);
    }

    #[test]
    fn parse_attribute_line_caps_limits_and_rejects_unknown_keys() {
        let spec = parse_attribute_line("[mneme-query, relation=entity, limit=9999, work=999999]")
            .expect("should match")
            .expect("should parse");
        assert_eq!(spec.limit, MAX_QUERY_LIMIT);
        assert_eq!(spec.max_work, MAX_QUERY_WORK);

        let err = parse_attribute_line("[mneme-query, bogus=1]")
            .expect("should match")
            .expect_err("unknown key should fail");
        assert!(err.contains("unknown mneme-query attribute"));
    }

    #[test]
    fn prepare_inline_parses_rules_negation_and_comparison() {
        let spec = QuerySpec {
            relation: Some("shared".to_owned()),
            ..QuerySpec::default()
        };
        let body = r#"
            % Find distinct pairs sharing a repo
            shared(A, B, T) :- relation(:links_repo, A, T), relation(:links_repo, B, T), A != B, not relation(:ignores, A, B).
        "#;
        let prepared = prepare(&spec, Some(body)).expect("inline rule should parse");
        assert_eq!(prepared.relation, "shared");
        assert_eq!(prepared.columns, vec!["A", "B", "T"]);
        assert_eq!(prepared.bundle.rules.len(), 1);
        assert_eq!(
            prepared.bundle.base_predicates.get("relation").copied(),
            Some(3)
        );
    }
}
