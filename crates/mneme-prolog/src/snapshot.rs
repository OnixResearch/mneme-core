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
    pub epistemic: mneme_datalog::EpistemicStatus,
    pub support_truncated: bool,
}

impl SelectedRow {
    /// Prolog predicate carrying selected Datalog rows with their explicit epistemic status:
    /// `relation_epistemic(Name, [Value, …], Status)`.
    pub const EPISTEMIC_RELATION: &'static str = "relation_epistemic";
}

/// One immutable input image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputImage {
    pub context: crate::SearchContext,
    pub canonical: Vec<CanonicalFact>,
    pub relations: Vec<SelectedRelation>,
    pub coverage: crate::InputCoverage,
}

/// One participating vault input for a federated Prolog image.
pub struct FederatedVaultInput<'a> {
    pub alias: &'a str,
    pub root: &'a std::path::Path,
    pub view: &'a mneme_memory::View,
    pub requested_revision: mneme_core::WorkspaceRevisionId,
    pub served_revision: mneme_core::WorkspaceRevisionId,
    pub eligibility_generation: u64,
}

/// Resolved revision metadata for one participating vault in a federated Prolog image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultRevision {
    pub alias: String,
    pub root: std::path::PathBuf,
    pub requested_revision: mneme_core::WorkspaceRevisionId,
    pub served_revision: mneme_core::WorkspaceRevisionId,
}

impl VaultRevision {
    /// Remote peer identifier when `root` uses the `iroh://<node-id>` scheme.
    pub fn peer(&self) -> Option<&str> {
        self.root
            .to_str()
            .and_then(|text| text.strip_prefix("iroh://"))
    }
}

/// One vault-tagged base fact exposed to federated Prolog queries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultFact {
    pub record_name: &'static str,
    pub predicate: &'static str,
    pub digest_fields: Vec<mneme_core::Value>,
    pub leading_strings: Vec<String>,
    pub trailing_value: Option<mneme_core::Value>,
    pub trailing_record_id: Option<String>,
    pub short_assertion_strings: Option<Vec<String>>,
}

struct EntityFactFields<'a> {
    vault: &'a str,
    record_id: mneme_core::RecordId,
    entity_type: &'a str,
    label: &'a str,
}

#[derive(Clone, Copy)]
struct AssertionFactKind {
    record_name: &'static str,
    predicate_name: &'static str,
    with_short: bool,
}

impl VaultFact {
    fn entity(fields: EntityFactFields<'_>) -> Self {
        Self {
            record_name: "vault-entity",
            predicate: "vault_entity",
            digest_fields: vec![
                mneme_core::Value::string(fields.vault.to_owned()),
                fields.record_id.to_value(),
                mneme_core::Value::string(fields.entity_type.to_owned()),
                mneme_core::Value::string(fields.label.to_owned()),
            ],
            leading_strings: vec![
                fields.vault.to_owned(),
                fields.record_id.to_hex(),
                fields.entity_type.to_owned(),
                fields.label.to_owned(),
            ],
            trailing_value: None,
            trailing_record_id: None,
            short_assertion_strings: None,
        }
    }

    fn relation(
        vault: &str,
        relation_type: String,
        from: mneme_core::RecordId,
        to: mneme_core::RecordId,
    ) -> Self {
        Self {
            record_name: "vault-relation",
            predicate: "vault_relation",
            digest_fields: vec![
                mneme_core::Value::string(vault.to_owned()),
                mneme_core::Value::string(relation_type.clone()),
                from.to_value(),
                to.to_value(),
            ],
            leading_strings: vec![vault.to_owned(), relation_type, from.to_hex(), to.to_hex()],
            trailing_value: None,
            trailing_record_id: None,
            short_assertion_strings: None,
        }
    }

    fn assertion(vault: &str, assertion: &mneme_memory::AssertionView) -> Self {
        Self::from_assertion_view(
            AssertionFactKind {
                record_name: "vault-assertion",
                predicate_name: "vault_assertion",
                with_short: true,
            },
            vault,
            assertion,
        )
    }

    fn denial(vault: &str, assertion: &mneme_memory::AssertionView) -> Self {
        Self::from_assertion_view(
            AssertionFactKind {
                record_name: "vault-denial",
                predicate_name: "vault_denial",
                with_short: false,
            },
            vault,
            assertion,
        )
    }

    fn hypothesis(vault: &str, assertion: &mneme_memory::AssertionView) -> Self {
        Self::from_assertion_view(
            AssertionFactKind {
                record_name: "vault-hypothesis",
                predicate_name: "vault_hypothesis",
                with_short: false,
            },
            vault,
            assertion,
        )
    }

    fn from_assertion_view(
        kind: AssertionFactKind,
        vault: &str,
        assertion: &mneme_memory::AssertionView,
    ) -> Self {
        assert!(!vault.is_empty());
        assert!(!assertion.predicate.is_empty());
        let short_assertion_strings = kind.with_short.then(|| {
            vec![
                vault.to_owned(),
                assertion.predicate.clone(),
                assertion.subject.to_hex(),
            ]
        });
        Self {
            record_name: kind.record_name,
            predicate: kind.predicate_name,
            digest_fields: vec![
                mneme_core::Value::string(vault.to_owned()),
                assertion.subject.to_value(),
                mneme_core::Value::string(assertion.predicate.clone()),
                assertion.value.clone(),
                assertion.record.record_id.to_value(),
            ],
            leading_strings: vec![
                vault.to_owned(),
                assertion.subject.to_hex(),
                assertion.predicate.clone(),
            ],
            trailing_value: Some(assertion.value.clone()),
            trailing_record_id: Some(assertion.record.record_id.to_hex()),
            short_assertion_strings,
        }
    }
}

/// One immutable federated input image across a primary vault and attached read-only vaults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederatedImage {
    pub image: InputImage,
    pub vaults: Vec<VaultRevision>,
    pub facts: Vec<VaultFact>,
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
    debug_assert!(results.len() < usize::MAX);
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
    let canonical = canonical_facts(view, &[view], scope)?;
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
    assert!(!image.context.image_digest.is_empty());
    Ok(image)
}

/// Build an immutable federated input image across a primary vault and
/// read-only attached vaults.
pub fn build_federated_input_image(
    primary: FederatedVaultInput<'_>,
    attached: &[FederatedVaultInput<'_>],
    scope: &mneme_core::ScopeId,
    results: Vec<mneme_datalog::QueryResult>,
) -> Result<FederatedImage, ImageError> {
    let mut all_inputs = Vec::with_capacity(attached.len().saturating_add(1));
    all_inputs.push(&primary);
    all_inputs.extend(attached);
    assert!(!all_inputs.is_empty());
    verify_federated_inputs(&all_inputs)?;
    let vault_data = collect_federated_vault_data(&all_inputs, scope)?;
    let all_views = all_inputs
        .iter()
        .map(|input| input.view)
        .collect::<Vec<_>>();
    let (relations, is_all_complete) =
        collect_federated_relations(&all_inputs, &all_views, scope, &primary, results)?;
    let mut federated = FederatedImage {
        image: InputImage {
            context: crate::SearchContext {
                revision: primary.served_revision,
                scope: scope.clone(),
                eligibility_generation: primary.eligibility_generation,
                image_digest: String::new(),
                profile: "positive-minimal/v1".to_owned(),
                rule_versions: relations.rule_versions,
            },
            canonical: vault_data.canonical,
            relations: relations.selected,
            coverage: crate::InputCoverage {
                complete: is_all_complete,
                reason: if is_all_complete {
                    None
                } else {
                    Some("one or more selected Datalog relations are incomplete".to_owned())
                },
            },
        },
        vaults: vault_data.vaults,
        facts: vault_data.facts,
    };
    federated.seal();
    assert_eq!(federated.vaults.len(), all_inputs.len());
    Ok(federated)
}

const MAX_FEDERATED_CANONICAL_FACTS: usize = 1_000_000;

struct CollectedVaultData {
    vaults: Vec<VaultRevision>,
    canonical: Vec<CanonicalFact>,
    facts: Vec<VaultFact>,
}

struct CollectedRelations {
    selected: Vec<SelectedRelation>,
    rule_versions: std::collections::BTreeMap<String, String>,
}

fn verify_federated_inputs(all_inputs: &[&FederatedVaultInput<'_>]) -> Result<(), ImageError> {
    for input in all_inputs {
        if input.view.revision() != input.served_revision {
            return Err(ImageError::RevisionMismatch {
                expected: input.served_revision,
                actual: input.view.revision(),
            });
        }
        let view_generation = input.view.snapshot().eligibility_generation;
        if view_generation != input.eligibility_generation {
            return Err(ImageError::StaleBarrier {
                expected: input.eligibility_generation,
                actual: view_generation,
            });
        }
    }
    Ok(())
}

fn collect_federated_vault_data(
    all_inputs: &[&FederatedVaultInput<'_>],
    scope: &mneme_core::ScopeId,
) -> Result<CollectedVaultData, ImageError> {
    assert!(!all_inputs.is_empty());
    let all_views = all_inputs
        .iter()
        .map(|input| input.view)
        .collect::<Vec<_>>();
    let vaults = all_inputs
        .iter()
        .map(|input| vault_revision_entry(input))
        .collect::<Vec<_>>();
    let canonical_chunks = all_inputs
        .iter()
        .map(|input| canonical_facts(input.view, &all_views, scope))
        .collect::<Result<Vec<_>, _>>()?;
    let total_canonical: usize = canonical_chunks.iter().map(Vec::len).sum();
    if total_canonical > MAX_FEDERATED_CANONICAL_FACTS {
        return Err(ImageError::ContextMismatch(
            "federated canonical fact count exceeds bound".to_owned(),
        ));
    }
    let canonical = canonical_chunks.into_iter().flatten().collect();
    let mut facts = Vec::new();
    for input in all_inputs {
        collect_vault_facts(input.alias, input.view, &all_views, scope, &mut facts)?;
    }
    assert_eq!(vaults.len(), all_inputs.len());
    Ok(CollectedVaultData {
        vaults,
        canonical,
        facts,
    })
}

fn vault_revision_entry(input: &FederatedVaultInput<'_>) -> VaultRevision {
    VaultRevision {
        alias: input.alias.to_owned(),
        root: input.root.to_path_buf(),
        requested_revision: input.requested_revision,
        served_revision: input.served_revision,
    }
}

fn collect_federated_relations(
    all_inputs: &[&FederatedVaultInput<'_>],
    all_views: &[&mneme_memory::View],
    scope: &mneme_core::ScopeId,
    primary: &FederatedVaultInput<'_>,
    results: Vec<mneme_datalog::QueryResult>,
) -> Result<(CollectedRelations, bool), ImageError> {
    assert!(!all_inputs.is_empty());
    assert!(!all_views.is_empty());
    let vault_revisions = all_inputs
        .iter()
        .map(|input| input.served_revision)
        .collect::<std::collections::BTreeSet<_>>();
    let mut selected = Vec::with_capacity(results.len());
    let mut validation = ResultContextValidation::default();
    let mut is_all_complete = true;
    for result in results {
        let is_coverage_complete = validate_result_context(
            &result,
            scope,
            primary.served_revision,
            primary.eligibility_generation,
            &mut validation,
        )?;
        is_all_complete &= is_coverage_complete;
        let rows = selected_rows_in_views(all_views, scope, &vault_revisions, &result)?;
        selected.push(selected_relation(result, rows, is_coverage_complete));
    }
    Ok((
        CollectedRelations {
            selected,
            rule_versions: validation.rule_versions,
        },
        is_all_complete,
    ))
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
    pub(crate) fn content_value(&self) -> mneme_core::Value {
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
                    .map(selected_row_value)
                    .collect::<Vec<_>>(),
            ),
            coverage_value(&relation.coverage),
        ],
    )
}

fn selected_row_value(row: &SelectedRow) -> mneme_core::Value {
    mneme_core::Value::record_named(
        "selected-row",
        vec![
            mneme_core::Value::sequence(row.values.clone()),
            mneme_core::Value::symbol(row.epistemic.name()),
            mneme_core::Value::Boolean(row.support_truncated),
        ],
    )
}

impl FederatedImage {
    /// Replace the stored digest with the digest of this federated image's content.
    pub fn seal(&mut self) {
        self.image.context.image_digest = self.content_digest_text();
    }

    /// The digest of everything except the stored digest field.
    pub fn content_digest(&self) -> mneme_core::ContentDigest {
        mneme_core::ContentDigest::of_payload(&self.content_value())
    }

    /// The digest rendered as `sha256:<64 lowercase hex>`.
    pub fn content_digest_text(&self) -> String {
        format!("sha256:{}", self.content_digest().to_hex())
    }

    /// Fail when the stored digest is not the digest of the federated image content.
    pub fn verify_digest(&self) -> Result<(), ImageError> {
        if self.image.context.image_digest == self.content_digest_text() {
            Ok(())
        } else {
            Err(ImageError::DigestMismatch)
        }
    }

    /// Fail when the request names a different context or a different image.
    pub fn verify_for_request(&self, request: &crate::Request) -> Result<(), ImageError> {
        let context = &self.image.context;
        if context.revision != request.revision || context.scope != request.scope {
            return Err(ImageError::RequestMismatch);
        }
        if context.eligibility_generation != request.eligibility_generation
            || context.image_digest != request.image_digest
        {
            return Err(ImageError::RequestMismatch);
        }
        self.verify_digest()
    }

    fn content_value(&self) -> mneme_core::Value {
        mneme_core::Value::record_named(
            "prolog-federated-input-image",
            vec![
                self.image.content_value(),
                mneme_core::Value::sequence(
                    self.vaults
                        .iter()
                        .map(|vault| {
                            mneme_core::Value::record_named(
                                "vault-revision",
                                vec![
                                    mneme_core::Value::string(vault.alias.clone()),
                                    mneme_core::Value::string(vault.root.display().to_string()),
                                    vault.requested_revision.to_value(),
                                    vault.served_revision.to_value(),
                                ],
                            )
                        })
                        .collect(),
                ),
                mneme_core::Value::sequence(self.facts.iter().map(vault_fact_value).collect()),
            ],
        )
    }
}

fn vault_fact_value(fact: &VaultFact) -> mneme_core::Value {
    mneme_core::Value::record_named(fact.record_name, fact.digest_fields.clone())
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

fn is_suppressed(view: &mneme_memory::View, record: &mneme_core::RecordEnvelope) -> bool {
    view.suppression_for(record)
        .is_some_and(|suppression| matches!(suppression.mode.as_str(), "withdrawn" | "forgotten"))
}

fn record_epistemic_status(record: &mneme_core::RecordEnvelope) -> mneme_datalog::EpistemicStatus {
    debug_assert!(record.schema_version > 0);
    let Some(properties) = record
        .payload
        .get("properties")
        .and_then(mneme_core::Value::as_dictionary)
    else {
        return mneme_datalog::EpistemicStatus::Accepted;
    };
    let status = properties
        .get(&mneme_core::Value::symbol("status"))
        .or_else(|| properties.get(&mneme_core::Value::string("status")))
        .and_then(|value| {
            value
                .as_symbol()
                .map(mneme_core::Symbol::as_str)
                .or_else(|| value.as_string())
        })
        .and_then(mneme_datalog::EpistemicStatus::parse)
        .unwrap_or(mneme_datalog::EpistemicStatus::Accepted);
    debug_assert!(!status.name().is_empty());
    status
}

fn is_assertion_admissible(
    view: &mneme_memory::View,
    all_views: &[&mneme_memory::View],
    scope: &mneme_core::ScopeId,
    assertion: &mneme_memory::AssertionView,
) -> bool {
    assert!(!all_views.is_empty());
    assertion.lifecycle == mneme_core::Lifecycle::Accepted
        && &assertion.record.scope == scope
        && !is_suppressed(view, &assertion.record)
        && view.accepted_decision(assertion).unwrap_or(false)
        && view.assertion_has_current_basis(assertion)
        && view_has_record(all_views, assertion.subject)
}

fn canonical_facts(
    view: &mneme_memory::View,
    all_views: &[&mneme_memory::View],
    scope: &mneme_core::ScopeId,
) -> Result<Vec<CanonicalFact>, ImageError> {
    assert!(!all_views.is_empty());
    let assertions = view
        .assertions()
        .map_err(|error| ImageError::Invalid(error.to_string()))?;
    let mut canonical = Vec::with_capacity(assertions.len());
    let total_assertions = assertions.len();
    for assertion in assertions {
        if assertion.stance != mneme_memory::Stance::Affirm
            || !is_assertion_admissible(view, all_views, scope, &assertion)
            || record_epistemic_status(&assertion.record)
                != mneme_datalog::EpistemicStatus::Accepted
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
    debug_assert!(canonical.len() <= total_assertions);
    Ok(canonical)
}

struct VaultCollectContext<'a> {
    alias: &'a str,
    view: &'a mneme_memory::View,
    all_views: &'a [&'a mneme_memory::View],
    scope: &'a mneme_core::ScopeId,
}

fn collect_vault_facts(
    alias: &str,
    view: &mneme_memory::View,
    all_views: &[&mneme_memory::View],
    scope: &mneme_core::ScopeId,
    facts: &mut Vec<VaultFact>,
) -> Result<(), ImageError> {
    assert!(!alias.is_empty());
    assert!(!all_views.is_empty());
    let ctx = VaultCollectContext {
        alias,
        view,
        all_views,
        scope,
    };
    for record in &view.snapshot().records {
        if &record.scope != scope
            || is_suppressed(view, record)
            || record_epistemic_status(record) == mneme_datalog::EpistemicStatus::Rejected
        {
            continue;
        }
        collect_record_vault_fact(&ctx, record, facts);
    }
    Ok(())
}

fn collect_record_vault_fact(
    ctx: &VaultCollectContext<'_>,
    record: &mneme_core::RecordEnvelope,
    facts: &mut Vec<VaultFact>,
) {
    match record.kind {
        mneme_core::RecordKind::Entity => push_entity_vault_fact(ctx.alias, record, facts),
        mneme_core::RecordKind::Relation => {
            push_relation_vault_fact(ctx.alias, record, ctx.all_views, facts);
        }
        mneme_core::RecordKind::Assertion => {
            push_assertion_vault_fact(ctx, record, facts);
        }
        mneme_core::RecordKind::Document
        | mneme_core::RecordKind::SourceRevision
        | mneme_core::RecordKind::Episode
        | mneme_core::RecordKind::Evidence
        | mneme_core::RecordKind::Derivation
        | mneme_core::RecordKind::Checkpoint
        | mneme_core::RecordKind::Proposal
        | mneme_core::RecordKind::Decision
        | mneme_core::RecordKind::RetentionDirective
        | mneme_core::RecordKind::DocumentBinding
        | mneme_core::RecordKind::DocumentAnchor
        | mneme_core::RecordKind::Comment
        | mneme_core::RecordKind::RecognitionRun
        | mneme_core::RecordKind::RecognitionSegment => {}
    }
}

fn push_entity_vault_fact(
    alias: &str,
    record: &mneme_core::RecordEnvelope,
    facts: &mut Vec<VaultFact>,
) {
    let entity_type = record
        .payload
        .get("entity-type")
        .and_then(mneme_core::Value::as_symbol)
        .map_or("unknown", mneme_core::Symbol::as_str);
    let label = record
        .payload
        .get("label")
        .and_then(mneme_core::Value::as_string)
        .unwrap_or_default();
    facts.push(VaultFact::entity(EntityFactFields {
        vault: alias,
        record_id: record.record_id,
        entity_type,
        label,
    }));
}

fn push_relation_vault_fact(
    alias: &str,
    record: &mneme_core::RecordEnvelope,
    all_views: &[&mneme_memory::View],
    facts: &mut Vec<VaultFact>,
) {
    let relation_type = record
        .payload
        .get("relation-type")
        .and_then(mneme_core::Value::as_symbol)
        .map_or_else(|| "unknown".to_owned(), |s| s.as_str().to_owned());
    let from = reference_field_target(record, "from");
    let to = reference_field_target(record, "to");
    if let (Some(from), Some(to)) = (from, to)
        && view_has_record(all_views, from)
        && view_has_record(all_views, to)
    {
        facts.push(VaultFact::relation(alias, relation_type, from, to));
    }
}

fn push_assertion_vault_fact(
    ctx: &VaultCollectContext<'_>,
    record: &mneme_core::RecordEnvelope,
    facts: &mut Vec<VaultFact>,
) {
    assert!(!ctx.alias.is_empty());
    assert_eq!(record.kind, mneme_core::RecordKind::Assertion);
    let Ok(assertion) = mneme_memory::AssertionView::parse(record.clone()) else {
        return;
    };
    if !is_assertion_admissible(ctx.view, ctx.all_views, ctx.scope, &assertion) {
        return;
    }
    let epistemic = record_epistemic_status(&assertion.record);
    if epistemic == mneme_datalog::EpistemicStatus::Rejected {
        return;
    }
    match assertion.stance {
        mneme_memory::Stance::Affirm if epistemic == mneme_datalog::EpistemicStatus::Accepted => {
            facts.push(VaultFact::assertion(ctx.alias, &assertion));
        }
        mneme_memory::Stance::Deny if epistemic == mneme_datalog::EpistemicStatus::Accepted => {
            facts.push(VaultFact::denial(ctx.alias, &assertion));
        }
        mneme_memory::Stance::Hypothesis
            if ctx.scope.class() == mneme_core::ScopeClass::Hypothesis =>
        {
            facts.push(VaultFact::hypothesis(ctx.alias, &assertion));
        }
        mneme_memory::Stance::Affirm
        | mneme_memory::Stance::Deny
        | mneme_memory::Stance::Hypothesis => {}
    }
}

fn reference_field_target(
    record: &mneme_core::RecordEnvelope,
    field: &str,
) -> Option<mneme_core::RecordId> {
    record
        .payload
        .get(field)
        .and_then(|v| mneme_core::Reference::from_value(v, &mneme_core::Path::root()).ok())
        .and_then(|r| r.target())
}

fn view_has_record(views: &[&mneme_memory::View], id: mneme_core::RecordId) -> bool {
    views.iter().any(|v| v.record(id).is_ok())
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
    let revisions = std::collections::BTreeSet::from([expected_revision]);
    selected_rows_in_views(&[view], scope, &revisions, result)
}

fn selected_rows_in_views(
    views: &[&mneme_memory::View],
    scope: &mneme_core::ScopeId,
    expected_revisions: &std::collections::BTreeSet<mneme_core::WorkspaceRevisionId>,
    result: &mneme_datalog::QueryResult,
) -> Result<Vec<SelectedRow>, ImageError> {
    assert!(!views.is_empty());
    assert!(!expected_revisions.is_empty());
    let mut rows = Vec::with_capacity(result.rows.len());
    for row in &result.rows {
        if row.epistemic == mneme_datalog::EpistemicStatus::Rejected {
            continue;
        }
        for support in &row.supports {
            if !expected_revisions.contains(&support.revision) || &support.scope != scope {
                return Err(ImageError::ContextMismatch(
                    "derivation revision/scope differs from the image".to_owned(),
                ));
            }
            for premise in &support.premises {
                let Some(canonical_id) = premise.canonical else {
                    continue;
                };
                let record = views
                    .iter()
                    .find_map(|view| view.record(canonical_id).ok())
                    .ok_or_else(|| ImageError::MissingPremise(canonical_id.to_hex()))?;
                if &record.scope != scope {
                    return Err(ImageError::HiddenScope(canonical_id.to_hex()));
                }
            }
        }
        rows.push(SelectedRow {
            values: row.values.clone(),
            supports: row.supports.clone(),
            epistemic: row.epistemic,
            support_truncated: row.support_truncated,
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
                vaults: Vec::new(),
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
                        vault: None,
                        vaults: std::collections::BTreeSet::new(),
                        // The premise is a positive base fact, so no absence was
                        // relied on and no coverage reason applies.
                        absent: false,
                        coverage: None,
                        epistemic: mneme_datalog::EpistemicStatus::Accepted,
                    }],
                    sources: std::collections::BTreeSet::new(),
                    vaults: std::collections::BTreeSet::new(),
                    temporal_parameters: Vec::new(),
                    revision,
                    scope: scope(),
                    truncated: false,
                    epistemic: mneme_datalog::EpistemicStatus::Accepted,
                }],
                support_truncated: false,
                epistemic: mneme_datalog::EpistemicStatus::Accepted,
            }],
            exhaustive: true,
            truncated: false,
            absence_established: false,
            reason: None,
            requested_revision: revision,
            served_revision: revision,
            vaults: Vec::new(),
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

    #[test]
    fn canonical_facts_and_vault_facts_enforce_datalog_admission_parity() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut workspace = mneme_store::Workspace::create(
            temp.path(),
            mneme_store::WorkspaceConfig::new(
                Box::new(mneme_store::SystemClock),
                Box::new(mneme_store::NoFaults),
            ),
        )
        .expect("workspace");
        let subj = mneme_core::RecordId::from_bytes([0x10; 16]);
        let hidden_subj = mneme_core::RecordId::from_bytes([0x70; 16]);
        commit_entity(&mut workspace, &scope(), 0x10, "subject").expect("commit entity");
        commit_entity(&mut workspace, &other_scope(), 0x70, "other-subject")
            .expect("commit other entity");

        // Commit a retained source for backing valid evidence.
        let src_id = mneme_core::RecordId::from_bytes([0x20; 16]);
        let src_rev = mneme_core::RevisionId::from_bytes([0x21; 16]);
        let (src_rec, src_blob) = mneme_memory::build_source(
            src_id,
            src_rev,
            &scope(),
            mneme_memory::SourceOptions {
                media_type: "text/plain",
                bytes: b"supporting text",
                entity: None,
                path_hint: None,
            },
        )
        .expect("source");
        let base = workspace.current_revision().expect("base");
        workspace
            .commit(mneme_store::CommitCommand {
                base,
                actor: "prolog-test".to_owned(),
                scope: scope(),
                idempotency_key: "source".to_owned(),
                records: vec![src_rec],
                source_blobs: vec![src_blob],
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("commit source");

        let span = mneme_core::SourceSpan::new(0, 8).expect("span");
        let ev_valid = mneme_memory::build_evidence(
            mneme_core::RecordId::from_bytes([0x30; 16]),
            mneme_core::RevisionId::from_bytes([0x31; 16]),
            &scope(),
            mneme_memory::EvidenceOptions {
                assertion: mneme_core::RecordId::from_bytes([0x40; 16]),
                source: src_id,
                source_revision: src_rev,
                span: Some(span),
                anchor: None,
                relation: mneme_memory::SupportRelation::Supports,
                origin: mneme_core::Origin::AuthoredStatement,
                ancestry: &[],
            },
        );
        let ev_suppressed = mneme_memory::build_evidence(
            mneme_core::RecordId::from_bytes([0x32; 16]),
            mneme_core::RevisionId::from_bytes([0x33; 16]),
            &scope(),
            mneme_memory::EvidenceOptions {
                assertion: mneme_core::RecordId::from_bytes([0x44; 16]),
                source: src_id,
                source_revision: src_rev,
                span: Some(span),
                anchor: None,
                relation: mneme_memory::SupportRelation::Supports,
                origin: mneme_core::Origin::AuthoredStatement,
                ancestry: &[],
            },
        );
        let ev_orphan = mneme_memory::build_evidence(
            mneme_core::RecordId::from_bytes([0x34; 16]),
            mneme_core::RevisionId::from_bytes([0x35; 16]),
            &scope(),
            mneme_memory::EvidenceOptions {
                assertion: mneme_core::RecordId::from_bytes([0x46; 16]),
                source: src_id,
                source_revision: src_rev,
                span: Some(span),
                anchor: None,
                relation: mneme_memory::SupportRelation::Supports,
                origin: mneme_core::Origin::AuthoredStatement,
                ancestry: &[],
            },
        );
        let prop_valid = mneme_memory::build_proposed_assertion(
            mneme_core::RecordId::from_bytes([0x40; 16]),
            mneme_core::RevisionId::from_bytes([0x41; 16]),
            &scope(),
            mneme_memory::ProposedAssertionOptions {
                subject: subj,
                predicate: "admitted",
                value: mneme_core::Value::string("yes"),
                stance: mneme_memory::Stance::Affirm,
                origin: mneme_core::Origin::AuthoredStatement,
                asserted_by: "author",
                valid_time: mneme_core::ValidTime::always(),
                evidence: &[mneme_core::Reference::local(
                    ev_valid.record_id,
                    mneme_core::RecordKind::Evidence,
                )],
                extraction: None,
                superseded_by: None,
            },
        );
        let prop_no_basis = mneme_memory::build_proposed_assertion(
            mneme_core::RecordId::from_bytes([0x42; 16]),
            mneme_core::RevisionId::from_bytes([0x43; 16]),
            &scope(),
            mneme_memory::ProposedAssertionOptions {
                subject: subj,
                predicate: "unbacked",
                value: mneme_core::Value::string("no"),
                stance: mneme_memory::Stance::Affirm,
                origin: mneme_core::Origin::AuthoredStatement,
                asserted_by: "author",
                valid_time: mneme_core::ValidTime::always(),
                evidence: &[],
                extraction: None,
                superseded_by: None,
            },
        );
        let prop_suppressed = mneme_memory::build_proposed_assertion(
            mneme_core::RecordId::from_bytes([0x44; 16]),
            mneme_core::RevisionId::from_bytes([0x45; 16]),
            &scope(),
            mneme_memory::ProposedAssertionOptions {
                subject: subj,
                predicate: "suppressed",
                value: mneme_core::Value::string("no"),
                stance: mneme_memory::Stance::Affirm,
                origin: mneme_core::Origin::AuthoredStatement,
                asserted_by: "author",
                valid_time: mneme_core::ValidTime::always(),
                evidence: &[mneme_core::Reference::local(
                    ev_suppressed.record_id,
                    mneme_core::RecordKind::Evidence,
                )],
                extraction: None,
                superseded_by: None,
            },
        );
        let prop_orphan = mneme_memory::build_proposed_assertion(
            mneme_core::RecordId::from_bytes([0x46; 16]),
            mneme_core::RevisionId::from_bytes([0x47; 16]),
            &scope(),
            mneme_memory::ProposedAssertionOptions {
                subject: hidden_subj,
                predicate: "orphan",
                value: mneme_core::Value::string("no"),
                stance: mneme_memory::Stance::Affirm,
                origin: mneme_core::Origin::AuthoredStatement,
                asserted_by: "author",
                valid_time: mneme_core::ValidTime::always(),
                evidence: &[mneme_core::Reference::local(
                    ev_orphan.record_id,
                    mneme_core::RecordKind::Evidence,
                )],
                extraction: None,
                superseded_by: None,
            },
        );
        let prop_no_dec = mneme_memory::build_proposed_assertion(
            mneme_core::RecordId::from_bytes([0x48; 16]),
            mneme_core::RevisionId::from_bytes([0x49; 16]),
            &scope(),
            mneme_memory::ProposedAssertionOptions {
                subject: subj,
                predicate: "no_decision",
                value: mneme_core::Value::string("no"),
                stance: mneme_memory::Stance::Affirm,
                origin: mneme_core::Origin::AuthoredStatement,
                asserted_by: "author",
                valid_time: mneme_core::ValidTime::always(),
                evidence: &[mneme_core::Reference::local(
                    ev_valid.record_id,
                    mneme_core::RecordKind::Evidence,
                )],
                extraction: None,
                superseded_by: None,
            },
        );
        let base = workspace.current_revision().expect("base");
        workspace
            .commit(mneme_store::CommitCommand {
                base,
                actor: "prolog-test".to_owned(),
                scope: scope(),
                idempotency_key: "props".to_owned(),
                records: vec![
                    ev_valid.clone(),
                    ev_suppressed.clone(),
                    ev_orphan.clone(),
                    prop_valid.clone(),
                    prop_no_basis.clone(),
                    prop_suppressed.clone(),
                    prop_orphan.clone(),
                    prop_no_dec.clone(),
                ],
                source_blobs: Vec::new(),
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("commit props");

        let input_rev = workspace.current_revision().expect("input rev");
        let accept_pair = |ws: &mneme_store::Workspace,
                           prop_id: mneme_core::RecordId,
                           dec_id: mneme_core::RecordId,
                           dec_rev: mneme_core::RevisionId,
                           acc_rev: mneme_core::RevisionId| {
            let env = ws
                .record_revisions(prop_id)
                .expect("prop revs")
                .into_iter()
                .last()
                .expect("last rev");
            let dec = mneme_memory::build_decision(
                dec_id,
                dec_rev,
                &scope(),
                mneme_memory::DecisionOptions {
                    kind: mneme_memory::DecisionKind::Acceptance,
                    target: prop_id,
                    actor: "prolog-test",
                    policy: "prolog-policy/v1",
                    input_revision: input_rev,
                    outcome: "accepted",
                    rationale: "accept",
                    evidence: &[],
                    related: &[],
                },
            );
            let acc = mneme_memory::build_assertion_revision(
                &env,
                acc_rev,
                mneme_core::Lifecycle::Accepted,
                mneme_core::Reference::local(dec_id, mneme_core::RecordKind::Decision),
                None,
            );
            (dec, acc)
        };
        let (dec_valid, acc_valid) = accept_pair(
            &workspace,
            prop_valid.record_id,
            mneme_core::RecordId::from_bytes([0x50; 16]),
            mneme_core::RevisionId::from_bytes([0x51; 16]),
            mneme_core::RevisionId::from_bytes([0x60; 16]),
        );
        let (dec_no_basis, acc_no_basis) = accept_pair(
            &workspace,
            prop_no_basis.record_id,
            mneme_core::RecordId::from_bytes([0x52; 16]),
            mneme_core::RevisionId::from_bytes([0x53; 16]),
            mneme_core::RevisionId::from_bytes([0x61; 16]),
        );
        let (dec_suppressed, acc_suppressed) = accept_pair(
            &workspace,
            prop_suppressed.record_id,
            mneme_core::RecordId::from_bytes([0x54; 16]),
            mneme_core::RevisionId::from_bytes([0x55; 16]),
            mneme_core::RevisionId::from_bytes([0x62; 16]),
        );
        let (dec_orphan, acc_orphan) = accept_pair(
            &workspace,
            prop_orphan.record_id,
            mneme_core::RecordId::from_bytes([0x56; 16]),
            mneme_core::RevisionId::from_bytes([0x57; 16]),
            mneme_core::RevisionId::from_bytes([0x63; 16]),
        );
        let prop_no_dec_env = workspace
            .record_revisions(prop_no_dec.record_id)
            .expect("no_dec revs")
            .into_iter()
            .last()
            .expect("no_dec env");
        // Decision with non-accepted outcome ("rejected") so `accepted_decision` is false.
        let dec_rejected = mneme_memory::build_decision(
            mneme_core::RecordId::from_bytes([0x58; 16]),
            mneme_core::RevisionId::from_bytes([0x59; 16]),
            &scope(),
            mneme_memory::DecisionOptions {
                kind: mneme_memory::DecisionKind::Acceptance,
                target: prop_no_dec.record_id,
                actor: "prolog-test",
                policy: "prolog-policy/v1",
                input_revision: input_rev,
                outcome: "rejected",
                rationale: "not accepted",
                evidence: &[],
                related: &[],
            },
        );
        let acc_no_dec = mneme_memory::build_assertion_revision(
            &prop_no_dec_env,
            mneme_core::RevisionId::from_bytes([0x64; 16]),
            mneme_core::Lifecycle::Accepted,
            mneme_core::Reference::local(dec_rejected.record_id, mneme_core::RecordKind::Decision),
            None,
        );
        workspace
            .commit(mneme_store::CommitCommand {
                base: input_rev,
                actor: "prolog-test".to_owned(),
                scope: scope(),
                idempotency_key: "accept".to_owned(),
                records: vec![
                    dec_valid,
                    dec_no_basis,
                    dec_suppressed,
                    dec_orphan,
                    dec_rejected,
                    acc_valid.clone(),
                    acc_no_basis,
                    acc_suppressed.clone(),
                    acc_orphan,
                    acc_no_dec,
                ],
                source_blobs: Vec::new(),
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("commit accepted");

        let revision = workspace.current_revision().expect("rev");
        let generation = workspace.eligibility_generation().expect("gen");
        let access = mneme_memory::Access::Scopes(std::collections::BTreeSet::from([scope()]));
        let snapshot = mneme_datalog::filter_visible_snapshot(
            workspace.snapshot().expect("snapshot"),
            &scope(),
            &access,
        );
        let ctx = mneme_memory::view_context(&workspace, &snapshot).expect("view context");
        let suppressions = vec![mneme_store::RetentionSuppression {
            operation_id: "op-withdraw-1".to_owned(),
            target: acc_suppressed.record_id,
            target_kind: mneme_core::RecordKind::Assertion.symbol().to_owned(),
            revision: Some(acc_suppressed.revision_id),
            content_digest: None,
            mode: mneme_store::SuppressionMode::Withdrawn,
            generation,
        }];
        let view = mneme_memory::View::with_retention(
            snapshot,
            workspace.root(),
            ctx.history,
            ctx.revision_sequences,
            suppressions,
        );

        let image = build_input_image(&view, &scope(), revision, generation, Vec::new())
            .expect("input image");
        let preds: Vec<&str> = image
            .canonical
            .iter()
            .map(|fact| fact.predicate.as_str())
            .collect();
        assert_eq!(
            preds,
            vec!["admitted"],
            "only accepted, decision-backed, current-basis, unsuppressed, live-subject assertions are admitted"
        );

        let federated = build_federated_input_image(
            FederatedVaultInput {
                alias: "primary",
                root: workspace.root(),
                view: &view,
                requested_revision: revision,
                served_revision: revision,
                eligibility_generation: generation,
            },
            &[],
            &scope(),
            Vec::new(),
        )
        .expect("federated image");
        let vault_assertion_preds: Vec<&str> = federated
            .facts
            .iter()
            .filter(|fact| fact.predicate == "vault_assertion")
            .filter_map(|fact| fact.leading_strings.get(2).map(String::as_str))
            .collect();
        assert_eq!(vault_assertion_preds, vec!["admitted"]);
    }

    #[test]
    fn selected_rows_carry_epistemic_and_truncation_in_digest_and_exclude_rejected() {
        let (_temp, view, revision, generation) = setup().expect("setup");
        let canonical = mneme_core::RecordId::from_bytes([0x10; 16]);

        let mut accepted_res = result(revision, generation, canonical);
        accepted_res.rows[0].values = vec![mneme_core::Value::string("ok")];

        let mut proposed_res = accepted_res.clone();
        proposed_res.rows[0].epistemic = mneme_datalog::EpistemicStatus::Proposed;

        let mut truncated_res = accepted_res.clone();
        truncated_res.rows[0].support_truncated = true;

        let mut rejected_res = accepted_res.clone();
        rejected_res.rows[0].epistemic = mneme_datalog::EpistemicStatus::Rejected;

        let img_acc = build_input_image(&view, &scope(), revision, generation, vec![accepted_res])
            .expect("acc image");
        let img_prop = build_input_image(&view, &scope(), revision, generation, vec![proposed_res])
            .expect("prop image");
        let img_trunc =
            build_input_image(&view, &scope(), revision, generation, vec![truncated_res])
                .expect("trunc image");
        let img_rej = build_input_image(&view, &scope(), revision, generation, vec![rejected_res])
            .expect("rej image");

        assert_eq!(
            img_acc.relations[0].rows[0].epistemic,
            mneme_datalog::EpistemicStatus::Accepted
        );
        assert!(!img_acc.relations[0].rows[0].support_truncated);
        assert_eq!(
            img_prop.relations[0].rows[0].epistemic,
            mneme_datalog::EpistemicStatus::Proposed
        );
        assert!(img_trunc.relations[0].rows[0].support_truncated);
        assert!(
            img_rej.relations[0].rows.is_empty(),
            "Rejected Datalog rows must never be admitted into Prolog SelectedRow"
        );
        assert_ne!(
            img_acc.content_digest(),
            img_prop.content_digest(),
            "InputImage content_digest must distinguish Accepted vs Proposed rows"
        );
        assert_ne!(
            img_acc.content_digest(),
            img_trunc.content_digest(),
            "InputImage content_digest must distinguish support_truncated"
        );
    }
}
