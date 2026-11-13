//! Authorized immutable input-image construction for bounded Prolog search.
//!
//! The image is built from one committed memory view and selected Datalog query
//! results. Revision, scope, eligibility generation, rule context, and every
//! canonical premise must match before any fact is admitted. The image carries
//! a content digest so two images built at the same revision cannot share a
//! cache key by accident.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// One accepted canonical assertion in the image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalFact {
    pub record_id: mneme_core::RecordId,
    pub revision_id: mneme_core::RevisionId,
    pub scope: mneme_core::ScopeId,
    pub subject: mneme_core::RecordId,
    pub predicate: String,
    pub value: mneme_core::Value,
    pub valid_time: mneme_core::ValidTime,
}

/// One selected Datalog relation and its retained rows/derivations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedRelation {
    /// The relation the query names, as carried by the Datalog result.
    pub predicate: String,
    pub rows: Vec<SelectedRow>,
    pub coverage: crate::InputCoverage,
}

/// One selected Datalog row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedRow {
    pub values: Vec<mneme_core::Value>,
    pub supports: Vec<mneme_datalog::Derivation>,
}

/// One immutable input image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputImage {
    pub context: crate::SearchContext,
    pub canonical: Vec<CanonicalFact>,
    pub relations: Vec<SelectedRelation>,
    pub coverage: crate::InputCoverage,
}

/// Input-image construction failures.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ImageError {
    #[error("memory view revision {actual} does not match expected {expected}")]
    RevisionMismatch {
        expected: mneme_core::WorkspaceRevisionId,
        actual: mneme_core::WorkspaceRevisionId,
    },
    #[error("Datalog result context does not match the image context: {0}")]
    ContextMismatch(String),
    #[error("stale eligibility barrier: expected {expected}, current {actual}")]
    StaleBarrier { expected: u64, actual: u64 },
    #[error("premise {0} is outside the requested scope")]
    HiddenScope(String),
    #[error("premise {0} is absent from the pinned view")]
    MissingPremise(String),
    #[error("selected Datalog results use mixed rule contexts")]
    MixedRuleContext,
    #[error("input image digest does not match its content")]
    DigestMismatch,
    #[error("request context differs from the input image")]
    RequestMismatch,
    #[error("invalid input image: {0}")]
    Invalid(String),
}

/// Build an immutable image from one view and selected Datalog results.
pub fn build_input_image(
    view: &mneme_memory::View,
    scope: &mneme_core::ScopeId,
    expected_revision: mneme_core::WorkspaceRevisionId,
    expected_generation: u64,
    results: Vec<mneme_datalog::QueryResult>,
) -> Result<InputImage, ImageError> {
    if view.revision() != expected_revision {
        return Err(ImageError::RevisionMismatch {
            expected: expected_revision,
            actual: view.revision(),
        });
    }
    // A view pinned before the current erasure barrier would package facts the
    // workspace has already made ineligible, so the view's own generation is
    // checked, not only the Datalog results'.
    let view_generation = view.snapshot().eligibility_generation;
    if view_generation != expected_generation {
        return Err(ImageError::StaleBarrier {
            expected: expected_generation,
            actual: view_generation,
        });
    }
    let canonical = canonical_facts(view, scope)?;
    let mut relations = Vec::with_capacity(results.len());
    let mut validation = ResultContextValidation::default();
    let mut is_all_complete = true;
    for result in results {
        let is_coverage_complete = validate_result_context(
            &result,
            scope,
            expected_revision,
            expected_generation,
            &mut validation,
        )?;
        is_all_complete &= is_coverage_complete;
        let rows = selected_rows(view, scope, expected_revision, &result)?;
        relations.push(selected_relation(result, rows, is_coverage_complete));
    }
    let mut image = InputImage {
        context: crate::SearchContext {
            revision: expected_revision,
            scope: scope.clone(),
            eligibility_generation: expected_generation,
            image_digest: String::new(),
            profile: "positive-minimal/v1".to_owned(),
            rule_versions: validation.rule_versions,
        },
        canonical,
        relations,
        coverage: crate::InputCoverage {
            complete: is_all_complete,
            reason: if is_all_complete {
                None
            } else {
                Some("one or more selected Datalog relations are incomplete".to_owned())
            },
        },
    };
    image.seal();
    Ok(image)
}

impl InputImage {
    /// Replace the stored digest with the digest of this image's content.
    ///
    /// Builders call this after assembling the image; [`InputImage::verify_digest`]
    /// re-derives the same value before the image is used.
    pub fn seal(&mut self) {
        self.context.image_digest = self.content_digest_text();
    }

    /// The digest of everything except the stored digest field.
    pub fn content_digest(&self) -> mneme_core::ContentDigest {
        mneme_core::ContentDigest::of_payload(&self.content_value())
    }

    /// The digest rendered as `sha256:<64 lowercase hex>`.
    pub fn content_digest_text(&self) -> String {
        format!("sha256:{}", self.content_digest().to_hex())
    }

    /// Fail when the stored digest is not the digest of the image content.
    pub fn verify_digest(&self) -> Result<(), ImageError> {
        if self.context.image_digest == self.content_digest_text() {
            Ok(())
        } else {
            Err(ImageError::DigestMismatch)
        }
    }

    /// Fail when the request names a different context or a different image.
    pub fn verify_for_request(&self, request: &crate::Request) -> Result<(), ImageError> {
        if self.context.revision != request.revision
            || self.context.scope != request.scope
            || self.context.eligibility_generation != request.eligibility_generation
            || self.context.image_digest != request.image_digest
        {
            return Err(ImageError::RequestMismatch);
        }
        self.verify_digest()
    }

    /// Canonical value of the digestible image content.
    fn content_value(&self) -> mneme_core::Value {
        mneme_core::Value::record_named(
            "prolog-input-image",
            vec![
                mneme_core::Value::string(self.context.profile.clone()),
                mneme_core::Value::symbol_dictionary(self.context.rule_versions.iter().map(
                    |(id, version)| {
                        (
                            mneme_core::Symbol::from(id.as_str()),
                            mneme_core::Value::string(version.clone()),
                        )
                    },
                )),
                self.context.revision.to_value(),
                self.context.scope.to_value(),
                mneme_core::Value::integer(self.context.eligibility_generation),
                mneme_core::Value::sequence(
                    self.canonical
                        .iter()
                        .map(canonical_fact_value)
                        .collect::<Vec<_>>(),
                ),
                mneme_core::Value::sequence(
                    self.relations
                        .iter()
                        .map(selected_relation_value)
                        .collect::<Vec<_>>(),
                ),
                coverage_value(&self.coverage),
            ],
        )
    }
}

fn coverage_value(coverage: &crate::InputCoverage) -> mneme_core::Value {
    mneme_core::Value::record_named(
        "coverage",
        vec![
            mneme_core::Value::Boolean(coverage.complete),
            coverage.reason.as_ref().map_or_else(
                || mneme_core::Value::symbol("complete"),
                |reason| mneme_core::Value::string(reason.clone()),
            ),
        ],
    )
}

fn canonical_fact_value(fact: &CanonicalFact) -> mneme_core::Value {
    mneme_core::Value::record_named(
        "canonical-fact",
        vec![
            fact.record_id.to_value(),
            fact.revision_id.to_value(),
            fact.scope.to_value(),
            fact.subject.to_value(),
            mneme_core::Value::string(fact.predicate.clone()),
            fact.value.clone(),
            fact.valid_time.to_value(),
        ],
    )
}

fn selected_relation_value(relation: &SelectedRelation) -> mneme_core::Value {
    mneme_core::Value::record_named(
        "selected-relation",
        vec![
            mneme_core::Value::string(relation.predicate.clone()),
            mneme_core::Value::sequence(
                relation
                    .rows
                    .iter()
                    .map(|row| mneme_core::Value::sequence(row.values.clone()))
                    .collect::<Vec<_>>(),
            ),
            coverage_value(&relation.coverage),
        ],
    )
}

/// Convert one Preserves value into a restricted-profile term.
///
/// The mapping is total except for embedded values, which are live objects and
/// never valid durable input. Every non-native variant is tagged with a fixed
/// safe functor, so image data never supplies a predicate or functor name:
///
/// | Value | Term |
/// | --- | --- |
/// | boolean | `bool(1)` / `bool(0)` |
/// | double | `double("<16 hex digits>")` |
/// | integer within `i64` | integer |
/// | integer outside `i64` | `bigint("<decimal>")` |
/// | string | quoted string |
/// | byte string | `bytes("<lower hex>")` |
/// | symbol | `symbol("<text>")` |
/// | record | `record(<label>, [fields])` |
/// | sequence | list |
/// | set | `set([items])` |
/// | dictionary | `assoc([kv(<key>,<value>), …])` |
pub fn value_term(value: &mneme_core::Value) -> Result<crate::Term, ImageError> {
    // An explicit work stack replaces recursion: a durable value nests as deep
    // as its producer made it, and the term profile depth check only runs after
    // conversion, so this walk must not consume the call stack.
    let mut conversion = Conversion {
        pending: vec![ConversionStep::Value(value)],
        built: Vec::new(),
    };
    while let Some(step) = conversion.pending.pop() {
        match step {
            ConversionStep::Value(value) => convert_value(value, &mut conversion)?,
            ConversionStep::Record(field_count) => {
                let fields = take_terms(&mut conversion.built, field_count)?;
                let label = take_term(&mut conversion.built)?;
                conversion
                    .built
                    .push(compound("record", vec![label, crate::Term::List(fields)]));
            }
            ConversionStep::Sequence(item_count) => {
                let items = take_terms(&mut conversion.built, item_count)?;
                conversion.built.push(crate::Term::List(items));
            }
            ConversionStep::Set(item_count) => {
                let items = take_terms(&mut conversion.built, item_count)?;
                conversion
                    .built
                    .push(compound("set", vec![crate::Term::List(items)]));
            }
            ConversionStep::Dictionary(entry_count) => {
                let terms = take_terms(&mut conversion.built, entry_count.saturating_mul(2))?;
                let mut entries = Vec::with_capacity(entry_count);
                let mut pairs = terms.into_iter();
                while let (Some(key), Some(value)) = (pairs.next(), pairs.next()) {
                    entries.push(compound("kv", vec![key, value]));
                }
                conversion
                    .built
                    .push(compound("assoc", vec![crate::Term::List(entries)]));
            }
        }
    }
    if conversion.built.len() != 1 {
        return Err(ImageError::Invalid(
            "value conversion did not produce exactly one term".to_owned(),
        ));
    }
    take_term(&mut conversion.built)
}

/// Work state of the iterative value conversion.
struct Conversion<'a> {
    /// Steps still to take; each composite queues one collecting frame.
    pending: Vec<ConversionStep<'a>>,
    /// Converted terms, most recent last.
    built: Vec<crate::Term>,
}

/// One pending step of the iterative value conversion.
enum ConversionStep<'a> {
    /// Convert this value and push its term.
    Value(&'a mneme_core::Value),
    /// Collect a label and this many fields into `record(<label>, [fields])`.
    Record(usize),
    /// Collect this many items into a list.
    Sequence(usize),
    /// Collect this many items into `set([items])`.
    Set(usize),
    /// Collect this many key/value pairs into `assoc([kv(<key>,<value>), …])`.
    Dictionary(usize),
}

/// Convert one value, queueing its children when it is composite.
fn convert_value<'a>(
    value: &'a mneme_core::Value,
    conversion: &mut Conversion<'a>,
) -> Result<(), ImageError> {
    let Conversion { pending, built } = conversion;
    match value {
        mneme_core::Value::Boolean(flag) => built.push(compound(
            "bool",
            vec![crate::Term::Integer(if *flag { 1 } else { 0 })],
        )),
        mneme_core::Value::Double(double) => {
            built.push(compound(
                "double",
                vec![text(hex(&double.bits().to_be_bytes()))],
            ));
        }
        mneme_core::Value::SignedInteger(integer_value) => match integer_value.to_i64() {
            Some(number) => built.push(crate::Term::Integer(number)),
            None => built.push(compound("bigint", vec![text(integer_value.to_string())])),
        },
        mneme_core::Value::String(value) => built.push(crate::Term::String(value.clone())),
        mneme_core::Value::ByteString(bytes) => {
            built.push(compound("bytes", vec![text(hex(bytes.as_slice()))]));
        }
        mneme_core::Value::Symbol(symbol) => {
            built.push(compound("symbol", vec![text(symbol.as_str().to_owned())]));
        }
        mneme_core::Value::Record(record) => {
            pending.push(ConversionStep::Record(record.fields().len()));
            push_values(pending, record.fields());
            pending.push(ConversionStep::Value(record.label()));
        }
        mneme_core::Value::Sequence(items) => {
            pending.push(ConversionStep::Sequence(items.len()));
            push_values(pending, items);
        }
        mneme_core::Value::Set(items) => {
            pending.push(ConversionStep::Set(items.len()));
            pending.reserve(items.len());
            for item in items.iter().rev() {
                pending.push(ConversionStep::Value(item));
            }
        }
        mneme_core::Value::Dictionary(entries) => {
            pending.push(ConversionStep::Dictionary(entries.len()));
            pending.reserve(entries.len().saturating_mul(2));
            for (key, value) in entries.iter().rev() {
                pending.push(ConversionStep::Value(value));
                pending.push(ConversionStep::Value(key));
            }
        }
        mneme_core::Value::Embedded(_) => {
            return Err(ImageError::Invalid(
                "embedded values are not valid input terms".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Queue values so the work stack yields them in their original order.
fn push_values<'a>(pending: &mut Vec<ConversionStep<'a>>, values: &'a [mneme_core::Value]) {
    pending.reserve(values.len());
    for value in values.iter().rev() {
        pending.push(ConversionStep::Value(value));
    }
}

/// Take the last `count` built terms, in their original order.
fn take_terms(built: &mut Vec<crate::Term>, count: usize) -> Result<Vec<crate::Term>, ImageError> {
    let start = built.len().checked_sub(count).ok_or_else(lost_subterm)?;
    // Children are queued so the work stack converts them in source order, so
    // the tail of `built` is already ordered: reversing here would swap every
    // pair of siblings (a dictionary pair, a record's fields, list items).
    Ok(built.split_off(start))
}

/// Take the last built term.
fn take_term(built: &mut Vec<crate::Term>) -> Result<crate::Term, ImageError> {
    built.pop().ok_or_else(lost_subterm)
}

/// The conversion queued a frame that has fewer subterms than it needs.
fn lost_subterm() -> ImageError {
    ImageError::Invalid("value conversion lost a subterm".to_owned())
}

fn compound(functor: &str, args: Vec<crate::Term>) -> crate::Term {
    crate::Term::Compound {
        functor: functor.to_owned(),
        args,
    }
}

fn text(value: String) -> crate::Term {
    crate::Term::String(value)
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn canonical_facts(
    view: &mneme_memory::View,
    scope: &mneme_core::ScopeId,
) -> Result<Vec<CanonicalFact>, ImageError> {
    let assertions = view
        .assertions()
        .map_err(|error| ImageError::Invalid(error.to_string()))?;
    let mut canonical = Vec::with_capacity(assertions.len());
    for assertion in assertions {
        if assertion.lifecycle != mneme_core::Lifecycle::Accepted
            || &assertion.record.scope != scope
        {
            continue;
        }
        canonical.push(CanonicalFact {
            record_id: assertion.record.record_id,
            revision_id: assertion.record.revision_id,
            scope: assertion.record.scope.clone(),
            subject: assertion.subject,
            predicate: assertion.predicate,
            value: assertion.value,
            valid_time: assertion.valid_time,
        });
    }
    Ok(canonical)
}

#[derive(Default)]
struct ResultContextValidation {
    rule_context: Option<(String, String)>,
    rule_versions: std::collections::BTreeMap<String, String>,
}

fn validate_result_context(
    result: &mneme_datalog::QueryResult,
    scope: &mneme_core::ScopeId,
    expected_revision: mneme_core::WorkspaceRevisionId,
    expected_generation: u64,
    validation: &mut ResultContextValidation,
) -> Result<bool, ImageError> {
    if result.context.served_revision != expected_revision
        || result.served_revision != expected_revision
        || result.requested_revision != expected_revision
        || result.stale
    {
        return Err(ImageError::ContextMismatch(
            "Datalog revision differs from the pinned image".to_owned(),
        ));
    }
    if &result.context.scope != scope {
        return Err(ImageError::ContextMismatch(
            "Datalog scope differs from the pinned image".to_owned(),
        ));
    }
    if result.context.eligibility_generation != expected_generation {
        return Err(ImageError::StaleBarrier {
            expected: expected_generation,
            actual: result.context.eligibility_generation,
        });
    }
    let context = (
        result.context.rule_bundle_id.clone(),
        result.context.rule_bundle_version.clone(),
    );
    if let Some(existing) = validation.rule_context.as_ref() {
        if existing != &context {
            return Err(ImageError::MixedRuleContext);
        }
    } else {
        validation.rule_context = Some(context);
        validation.rule_versions.insert(
            result.context.rule_bundle_id.clone(),
            result.context.rule_bundle_version.clone(),
        );
    }
    Ok(result.exhaustive
        && result
            .coverage
            .iter()
            .all(|coverage| coverage.status == mneme_datalog::CoverageStatus::Complete)
        && result.status == mneme_datalog::ExecutionStatus::Complete)
}

fn selected_rows(
    view: &mneme_memory::View,
    scope: &mneme_core::ScopeId,
    expected_revision: mneme_core::WorkspaceRevisionId,
    result: &mneme_datalog::QueryResult,
) -> Result<Vec<SelectedRow>, ImageError> {
    let mut rows = Vec::with_capacity(result.rows.len());
    for row in &result.rows {
        for support in &row.supports {
            if support.revision != expected_revision || &support.scope != scope {
                return Err(ImageError::ContextMismatch(
                    "derivation revision/scope differs from the image".to_owned(),
                ));
            }
            for premise in &support.premises {
                let Some(canonical_id) = premise.canonical else {
                    continue;
                };
                let record = view
                    .record(canonical_id)
                    .map_err(|_| ImageError::MissingPremise(canonical_id.to_hex()))?;
                if &record.scope != scope {
                    return Err(ImageError::HiddenScope(canonical_id.to_hex()));
                }
            }
        }
        rows.push(SelectedRow {
            values: row.values.clone(),
            supports: row.supports.clone(),
        });
    }
    Ok(rows)
}

fn selected_relation(
    result: mneme_datalog::QueryResult,
    rows: Vec<SelectedRow>,
    is_coverage_complete: bool,
) -> SelectedRelation {
    SelectedRelation {
        predicate: result.relation,
        rows,
        coverage: crate::InputCoverage {
            complete: is_coverage_complete,
            reason: result.reason,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> mneme_core::ScopeId {
        mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
    }

    fn other_scope() -> mneme_core::ScopeId {
        mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "birch").expect("scope")
    }

    fn commit_entity(
        workspace: &mut mneme_store::Workspace,
        scope: &mneme_core::ScopeId,
        id: u8,
        key: &str,
    ) -> Result<(), String> {
        let base = workspace
            .current_revision()
            .map_err(|error| error.to_string())?;
        workspace
            .commit(mneme_store::CommitCommand {
                base,
                actor: "prolog-test".to_owned(),
                scope: scope.clone(),
                idempotency_key: key.to_owned(),
                records: vec![mneme_store::RecordDraft {
                    schema_version: 1,
                    kind: mneme_core::RecordKind::Entity,
                    record_id: mneme_core::RecordId::from_bytes([id; 16]),
                    revision_id: mneme_core::RevisionId::from_bytes([id.wrapping_add(1); 16]),
                    predecessor: None,
                    scope: scope.clone(),
                    payload: mneme_core::fixtures::entity().payload,
                }],
                source_blobs: Vec::new(),
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn setup() -> Result<
        (
            tempfile::TempDir,
            mneme_memory::View,
            mneme_core::WorkspaceRevisionId,
            u64,
        ),
        String,
    > {
        let temp = tempfile::tempdir().map_err(|error| error.to_string())?;
        let mut workspace = mneme_store::Workspace::create(
            temp.path(),
            mneme_store::WorkspaceConfig::new(
                Box::new(mneme_store::SystemClock),
                Box::new(mneme_store::NoFaults),
            ),
        )
        .map_err(|e| e.to_string())?;
        commit_entity(&mut workspace, &scope(), 0x10, "cedar")?;
        commit_entity(&mut workspace, &other_scope(), 0x70, "birch")?;
        let revision = workspace.current_revision().map_err(|e| e.to_string())?;
        let generation = workspace
            .eligibility_generation()
            .map_err(|e| e.to_string())?;
        let view = mneme_memory::View::new(
            workspace.snapshot().map_err(|e| e.to_string())?,
            workspace.root(),
        );
        Ok((temp, view, revision, generation))
    }

    fn result(
        revision: mneme_core::WorkspaceRevisionId,
        generation: u64,
        canonical: mneme_core::RecordId,
    ) -> mneme_datalog::QueryResult {
        mneme_datalog::QueryResult {
            relation: "path".to_owned(),
            context: mneme_datalog::BuildContext {
                requested_revision: revision,
                served_revision: revision,
                scope: scope(),
                schema_version: 1,
                rule_bundle_id: "base".to_owned(),
                rule_bundle_version: "1".to_owned(),
                projection_build_id: "build-1".to_owned(),
                eligibility_generation: generation,
                requested_was_head: true,
            },
            status: mneme_datalog::ExecutionStatus::Complete,
            coverage: vec![mneme_datalog::Coverage {
                predicate: "path".to_owned(),
                status: mneme_datalog::CoverageStatus::Complete,
                reason: None,
            }],
            rows: vec![mneme_datalog::QueryRow {
                values: Vec::new(),
                supports: vec![mneme_datalog::Derivation {
                    rule_id: "path".to_owned(),
                    rule_version: "1".to_owned(),
                    premises: vec![mneme_datalog::Premise {
                        predicate: "entity".to_owned(),
                        terms: Vec::new(),
                        canonical: Some(canonical),
                        canonical_roots: std::collections::BTreeSet::from([canonical]),
                        sources: std::collections::BTreeSet::new(),
                        source_availability: None,
                        // The premise is a positive base fact, so no absence was
                        // relied on and no coverage reason applies.
                        absent: false,
                        coverage: None,
                    }],
                    sources: std::collections::BTreeSet::new(),
                    temporal_parameters: Vec::new(),
                    revision,
                    scope: scope(),
                    truncated: false,
                }],
                support_truncated: false,
            }],
            exhaustive: true,
            truncated: false,
            absence_established: false,
            reason: None,
            requested_revision: revision,
            served_revision: revision,
            stale: false,
            work: 1,
        }
    }

    #[test]
    fn builds_one_immutable_image_with_context_and_coverage() {
        let (_temp, view, revision, generation) = setup().expect("setup");
        let image = build_input_image(
            &view,
            &scope(),
            revision,
            generation,
            vec![result(
                revision,
                generation,
                mneme_core::RecordId::from_bytes([0x10; 16]),
            )],
        )
        .expect("image");
        assert_eq!(image.context.revision, revision);
        assert_eq!(image.context.eligibility_generation, generation);
        assert_eq!(image.context.scope, scope());
        assert_eq!(image.relations.len(), 1);
        assert_eq!(image.relations[0].predicate, "path");
        assert!(image.relations[0].coverage.complete);
        assert!(image.coverage.complete);
        assert!(image.verify_digest().is_ok());
    }

    #[test]
    fn stale_view_generation_is_rejected() {
        let (_temp, view, revision, generation) = setup().expect("setup");
        assert_eq!(
            build_input_image(
                &view,
                &scope(),
                revision,
                generation.saturating_add(1),
                Vec::new()
            ),
            Err(ImageError::StaleBarrier {
                expected: generation.saturating_add(1),
                actual: generation,
            })
        );
    }

    #[test]
    fn mixed_revision_and_stale_generation_are_rejected() {
        let (_temp, view, revision, generation) = setup().expect("setup");
        let mut mixed = result(
            revision,
            generation,
            mneme_core::RecordId::from_bytes([0x10; 16]),
        );
        mixed.served_revision = mneme_core::WorkspaceRevisionId::from_bytes([0x99; 16]);
        assert!(matches!(
            build_input_image(&view, &scope(), revision, generation, vec![mixed]),
            Err(ImageError::ContextMismatch(_))
        ));
        let stale = result(
            revision,
            generation.saturating_add(1),
            mneme_core::RecordId::from_bytes([0x10; 16]),
        );
        assert!(matches!(
            build_input_image(&view, &scope(), revision, generation, vec![stale]),
            Err(ImageError::StaleBarrier { .. })
        ));
    }

    #[test]
    fn hidden_scope_premise_is_rejected() {
        let (_temp, view, revision, generation) = setup().expect("setup");
        let hidden = result(
            revision,
            generation,
            mneme_core::RecordId::from_bytes([0x70; 16]),
        );
        assert_eq!(
            build_input_image(&view, &scope(), revision, generation, vec![hidden]),
            Err(ImageError::HiddenScope(
                mneme_core::RecordId::from_bytes([0x70; 16]).to_hex()
            ))
        );
    }

    #[test]
    fn digest_tracks_image_content_not_only_its_context() {
        let (_temp, view, revision, generation) = setup().expect("setup");
        let canonical = mneme_core::RecordId::from_bytes([0x10; 16]);
        let empty = build_input_image(&view, &scope(), revision, generation, Vec::new())
            .expect("empty image");
        let with_row = build_input_image(
            &view,
            &scope(),
            revision,
            generation,
            vec![result(revision, generation, canonical)],
        )
        .expect("image with a row");
        assert_ne!(empty.context.image_digest, with_row.context.image_digest);
        assert!(with_row.context.image_digest.starts_with("sha256:"));
        assert_eq!(with_row.context.image_digest.len(), "sha256:".len() + 64);
        let mut tampered = with_row.clone();
        tampered.context.image_digest = empty.context.image_digest;
        assert_eq!(tampered.verify_digest(), Err(ImageError::DigestMismatch));
    }

    #[test]
    fn selected_relation_uses_the_result_relation_name() {
        let (_temp, view, revision, generation) = setup().expect("setup");
        let mut named = result(
            revision,
            generation,
            mneme_core::RecordId::from_bytes([0x10; 16]),
        );
        named.relation = "ancestor".to_owned();
        let image =
            build_input_image(&view, &scope(), revision, generation, vec![named]).expect("image");
        assert_eq!(image.relations[0].predicate, "ancestor");
    }

    #[test]
    fn values_render_as_tagged_ground_terms() {
        let value = mneme_core::Value::record_named(
            "claim",
            vec![
                mneme_core::Value::string("a\nb"),
                mneme_core::Value::integer(7),
                mneme_core::Value::bytes([0x01, 0xab]),
                mneme_core::Value::symbol("tag"),
                mneme_core::Value::sequence(vec![mneme_core::Value::Boolean(true)]),
                mneme_core::Value::set([mneme_core::Value::double(1.5)]),
                mneme_core::Value::symbol_dictionary([(
                    mneme_core::Symbol::from("k"),
                    mneme_core::Value::integer(1),
                )]),
            ],
        );
        let term = value_term(&value).expect("term");
        assert!(matches!(term, crate::Term::Compound { .. }));
        let encoded = crate::encode_term(
            &term,
            crate::TermProfile {
                max_depth: 24,
                max_collection: 32,
                references_allowed: false,
            },
            4096,
        )
        .expect("encoded");
        assert!(encoded.starts_with("record(symbol(\"claim\"),["));
        assert!(encoded.contains("bytes(\"01ab\")"));
        assert!(encoded.contains("assoc([kv(symbol(\"k\"),1)])"));
        assert!(encoded.contains("bool(1)"));
    }

    /// Render one value through the conversion and the restricted encoder.
    fn render(value: &mneme_core::Value) -> String {
        let term = value_term(value).expect("term");
        crate::encode_term(
            &term,
            crate::TermProfile {
                max_depth: 24,
                max_collection: 32,
                references_allowed: false,
            },
            4096,
        )
        .expect("encoded")
    }

    #[test]
    fn every_value_kind_renders_exactly() {
        // Sibling order is the fragile part of the iterative conversion and of
        // the iterative encoder: each expectation below changes if either work
        // stack emits a pair of children in the wrong order.
        let boolean = mneme_core::Value::Boolean(true);
        assert_eq!(render(&boolean), "bool(1)");
        let integer = mneme_core::Value::integer(7);
        assert_eq!(render(&integer), "7");
        let double = mneme_core::Value::double(1.5);
        assert_eq!(render(&double), "double(\"3ff8000000000000\")");
        let string = mneme_core::Value::string("plain");
        assert_eq!(render(&string), "\"plain\"");
        let bytes = mneme_core::Value::bytes([0x01, 0xab]);
        assert_eq!(render(&bytes), "bytes(\"01ab\")");
        let symbol = mneme_core::Value::symbol("tag");
        assert_eq!(render(&symbol), "symbol(\"tag\")");
        let sequence = mneme_core::Value::sequence(vec![
            mneme_core::Value::integer(1),
            mneme_core::Value::integer(2),
        ]);
        assert_eq!(render(&sequence), "[1,2]");
        let set =
            mneme_core::Value::set([mneme_core::Value::integer(2), mneme_core::Value::integer(1)]);
        assert_eq!(render(&set), "set([1,2])");
        let record = mneme_core::Value::record_named(
            "node",
            vec![
                mneme_core::Value::integer(3),
                mneme_core::Value::symbol("leaf"),
            ],
        );
        assert_eq!(
            render(&record),
            "record(symbol(\"node\"),[3,symbol(\"leaf\")])"
        );
        let dictionary = mneme_core::Value::symbol_dictionary([
            (mneme_core::Symbol::from("b"), mneme_core::Value::integer(2)),
            (mneme_core::Symbol::from("a"), mneme_core::Value::integer(1)),
        ]);
        assert_eq!(
            render(&dictionary),
            "assoc([kv(symbol(\"a\"),1),kv(symbol(\"b\"),2)])"
        );
        let nested = mneme_core::Value::symbol_dictionary([(
            mneme_core::Symbol::from("k"),
            mneme_core::Value::sequence(vec![mneme_core::Value::record_named(
                "node",
                vec![
                    mneme_core::Value::integer(3),
                    mneme_core::Value::symbol("leaf"),
                ],
            )]),
        )]);
        assert_eq!(
            render(&nested),
            "assoc([kv(symbol(\"k\"),[record(symbol(\"node\"),[3,symbol(\"leaf\")])])])"
        );
    }

    #[test]
    fn embedded_values_are_refused() {
        assert!(matches!(
            value_term(&mneme_core::Value::embedded(mneme_core::Value::integer(1))),
            Err(ImageError::Invalid(_))
        ));
    }
}
