//! Versioned record kinds, payload field schemas, and schema registries.
//!
//! Version 1 declares the record kinds and their ordinary authoritative fields.
//! Validation is pure: it checks structure, types, intervals, and references
//! without promoting an assertion's epistemic lifecycle or rewriting payloads.
//! Unknown extension fields are retained under the version 1 compatibility
//! rule; an editor that cannot preserve one must refuse the edit instead.
#![allow(path_segment_repetition)] // Octet structural exception: domain-qualified names and macro-only imports are intentional

/// The record kinds declared by the version 1 application schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordKind {
    Entity,
    Relation,
    Document,
    SourceRevision,
    Episode,
    Assertion,
    Evidence,
    Derivation,
    Checkpoint,
    Proposal,
    Decision,
    RetentionDirective,
    DocumentBinding,
    DocumentAnchor,
}

impl RecordKind {
    /// Every declared kind.
    pub const ALL: [RecordKind; 14] = [
        RecordKind::Entity,
        RecordKind::Relation,
        RecordKind::Document,
        RecordKind::SourceRevision,
        RecordKind::Episode,
        RecordKind::Assertion,
        RecordKind::Evidence,
        RecordKind::Derivation,
        RecordKind::Checkpoint,
        RecordKind::Proposal,
        RecordKind::Decision,
        RecordKind::RetentionDirective,
        RecordKind::DocumentBinding,
        RecordKind::DocumentAnchor,
    ];

    /// The schema symbol for this kind.
    pub const fn symbol(self) -> &'static str {
        match self {
            RecordKind::Entity => "entity",
            RecordKind::Relation => "relation",
            RecordKind::Document => "document",
            RecordKind::SourceRevision => "source-revision",
            RecordKind::Episode => "episode",
            RecordKind::Assertion => "assertion",
            RecordKind::Evidence => "evidence",
            RecordKind::Derivation => "derivation",
            RecordKind::Checkpoint => "checkpoint",
            RecordKind::Proposal => "proposal",
            RecordKind::Decision => "decision",
            RecordKind::RetentionDirective => "retention-directive",
            RecordKind::DocumentBinding => "document-binding",
            RecordKind::DocumentAnchor => "document-anchor",
        }
    }

    /// Parse a declared kind symbol.
    pub fn parse(text: &str) -> Option<Self> {
        RecordKind::ALL
            .into_iter()
            .find(|kind| kind.symbol() == text)
    }

    /// Encode this kind as its schema symbol.
    pub fn to_value(self) -> crate::value::Value {
        crate::value::Value::symbol(self.symbol())
    }

    /// Decode and require a declared kind.
    pub fn from_value(
        value: &crate::value::Value,
        path: &crate::error::Path,
    ) -> Result<Self, crate::error::Diagnostic> {
        let Some(symbol) = value.as_symbol() else {
            return Err(crate::error::Diagnostic::new(
                crate::error::Stage::Envelope,
                crate::error::ErrorCode::UnknownRecordKind,
                path.clone(),
                "record kind must be a declared symbol",
            ));
        };
        RecordKind::parse(symbol.as_str()).ok_or_else(|| {
            crate::error::Diagnostic::new(
                crate::error::Stage::Envelope,
                crate::error::ErrorCode::UnknownRecordKind,
                path.clone(),
                format!("unknown record kind {symbol}"),
            )
        })
    }
}

/// The epistemic lifecycle of an assertion.
///
/// Structural validation preserves this value exactly. Only an explicit,
/// attributed acceptance decision may promote an assertion; storing,
/// retrieving, or summarizing it must not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Lifecycle {
    Proposed,
    Accepted,
    Disputed,
    Superseded,
    Retracted,
}

impl Lifecycle {
    /// Schema symbol.
    pub const fn symbol(self) -> &'static str {
        match self {
            Lifecycle::Proposed => "proposed",
            Lifecycle::Accepted => "accepted",
            Lifecycle::Disputed => "disputed",
            Lifecycle::Superseded => "superseded",
            Lifecycle::Retracted => "retracted",
        }
    }

    /// Parse a declared lifecycle value.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "proposed" => Some(Lifecycle::Proposed),
            "accepted" => Some(Lifecycle::Accepted),
            "disputed" => Some(Lifecycle::Disputed),
            "superseded" => Some(Lifecycle::Superseded),
            "retracted" => Some(Lifecycle::Retracted),
            _ => None,
        }
    }

    /// Decode and require a declared lifecycle value.
    pub fn from_value(
        value: &crate::value::Value,
        path: &crate::error::Path,
    ) -> Result<Self, crate::error::Diagnostic> {
        let Some(symbol) = value.as_symbol() else {
            return Err(crate::error::Diagnostic::new(
                crate::error::Stage::Domain,
                crate::error::ErrorCode::TypeMismatch,
                path.clone(),
                "assertion lifecycle must be a symbol",
            ));
        };
        Lifecycle::parse(symbol.as_str()).ok_or_else(|| {
            crate::error::Diagnostic::new(
                crate::error::Stage::Domain,
                crate::error::ErrorCode::TypeMismatch,
                path.clone(),
                format!("unknown assertion lifecycle {symbol}"),
            )
        })
    }
}

/// The declared origin category of an assertion or episode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    Observation,
    AuthoredStatement,
    ModelExtraction,
    Inference,
    Import,
}

impl Origin {
    /// Schema symbol.
    pub const fn symbol(self) -> &'static str {
        match self {
            Origin::Observation => "observation",
            Origin::AuthoredStatement => "authored-statement",
            Origin::ModelExtraction => "model-extraction",
            Origin::Inference => "inference",
            Origin::Import => "import",
        }
    }

    /// Parse a declared origin.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "observation" => Some(Origin::Observation),
            "authored-statement" => Some(Origin::AuthoredStatement),
            "model-extraction" => Some(Origin::ModelExtraction),
            "inference" => Some(Origin::Inference),
            "import" => Some(Origin::Import),
            _ => None,
        }
    }
}

/// A schema-declared field type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldType {
    Symbol,
    Text,
    Integer,
    Boolean,
    Any,
    Dictionary,
    Reference {
        kind: Option<RecordKind>,
        allow_external: bool,
        allow_unresolved: bool,
    },
    ReferenceSet {
        kind: Option<RecordKind>,
        allow_external: bool,
        allow_unresolved: bool,
    },
    ValidTime,
    Digest,
    Span,
    SourceContent,
    WorkspaceRevision,
}

/// One declared payload field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldSpec {
    pub name: &'static str,
    pub ty: FieldType,
    pub required: bool,
}

const fn required(name: &'static str, ty: FieldType) -> FieldSpec {
    FieldSpec {
        name,
        ty,
        required: true,
    }
}

const fn optional(name: &'static str, ty: FieldType) -> FieldSpec {
    FieldSpec {
        name,
        ty,
        required: false,
    }
}

const fn reference(kind: Option<RecordKind>) -> FieldType {
    FieldType::Reference {
        kind,
        allow_external: false,
        allow_unresolved: false,
    }
}

const fn reference_set(kind: Option<RecordKind>) -> FieldType {
    FieldType::ReferenceSet {
        kind,
        allow_external: false,
        allow_unresolved: false,
    }
}

/// How a schema treats payload fields it does not declare.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtensionPolicy {
    /// Retain typed extension values as ordinary payload data.
    Retain,
    /// Refuse the record until the extension is declared.
    Refuse,
}

/// The declared fields for one record kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KindSchema {
    kind: RecordKind,
    fields: Vec<FieldSpec>,
    extensions: ExtensionPolicy,
}

impl KindSchema {
    /// Construct a kind schema.
    pub fn new(kind: RecordKind, fields: Vec<FieldSpec>, extensions: ExtensionPolicy) -> Self {
        KindSchema {
            kind,
            fields,
            extensions,
        }
    }

    /// The record kind.
    pub const fn kind(&self) -> RecordKind {
        self.kind
    }

    /// Declared fields in canonical order.
    pub fn fields(&self) -> &[FieldSpec] {
        &self.fields
    }

    /// A declared field by name.
    pub fn field(&self, name: &str) -> Option<&FieldSpec> {
        self.fields.iter().find(|field| field.name == name)
    }

    /// The extension policy.
    pub const fn extensions(&self) -> ExtensionPolicy {
        self.extensions
    }

    /// Add a field to this kind schema, used by explicit version migrations.
    pub fn with_field(mut self, field: FieldSpec) -> Self {
        self.fields.push(field);
        self
    }
}

/// One versioned application schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordSchema {
    version: u32,
    kinds: Vec<KindSchema>,
}

impl RecordSchema {
    /// Construct a schema version from declared kinds.
    pub fn new(version: u32, kinds: Vec<KindSchema>) -> Self {
        RecordSchema { version, kinds }
    }

    /// The version 1 application schema.
    #[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
    pub fn v1() -> Self {
        let mut kinds = Vec::with_capacity(11);
        push_v1_entity_kinds(&mut kinds);
        push_v1_document_kinds(&mut kinds);
        push_v1_assertion_kinds(&mut kinds);
        push_v1_evidence_kinds(&mut kinds);
        push_v1_workflow_kinds(&mut kinds);
        RecordSchema::new(1, kinds)
    }

    /// The production version 2 schema introduced by `evidence-memory`.
    ///
    /// It keeps every version 1 kind and field, adds explicit assertion
    /// decision/extraction fields, source availability, and the decision record
    /// kind. Version 1 records remain interpretable and are not rewritten.
    pub fn evidence_v2() -> Self {
        let mut schema = RecordSchema::v1();
        schema.version = 2;
        for kind in &mut schema.kinds {
            match kind.kind {
                RecordKind::Assertion => {
                    kind.fields
                        .push(optional("decision", reference(Some(RecordKind::Decision))));
                    kind.fields.push(optional("extraction", FieldType::Any));
                    kind.fields
                        .push(optional("completeness", FieldType::Symbol));
                }
                RecordKind::SourceRevision => {
                    kind.fields
                        .push(optional("availability", FieldType::Symbol));
                    // A pruned revision keeps the identity of the bytes it no
                    // longer stores so historical reads can distinguish an
                    // authorized absence from corruption.
                    kind.fields
                        .push(optional("content-digest", FieldType::Digest));
                }
                RecordKind::Episode => {
                    kind.fields.push(optional("related", reference_set(None)));
                }
                RecordKind::Checkpoint => {
                    kind.fields
                        .push(optional("revision", FieldType::WorkspaceRevision));
                }
                _ => {}
            }
        }
        schema.kinds.push(KindSchema::new(
            RecordKind::Decision,
            vec![
                required("decision-kind", FieldType::Symbol),
                required("target", reference(None)),
                required("actor", FieldType::Text),
                required("policy", FieldType::Text),
                required("input-revision", FieldType::WorkspaceRevision),
                required("outcome", FieldType::Symbol),
                required("rationale", FieldType::Text),
                required("evidence", reference_set(None)),
                optional("related", reference_set(None)),
            ],
            ExtensionPolicy::Retain,
        ));
        schema
    }

    /// The production version 3 schema introduced by `document-authoring`.
    ///
    /// It keeps every version 1/2 kind, makes the document entity binding
    /// optional, and adds explicit binding and source-anchor records.
    pub fn documents_v3() -> Self {
        let mut schema = RecordSchema::evidence_v2();
        schema.version = 3;
        for kind in &mut schema.kinds {
            if kind.kind == RecordKind::Document {
                *kind = KindSchema::new(
                    RecordKind::Document,
                    vec![
                        required("title", FieldType::Text),
                        optional("entity", reference(Some(RecordKind::Entity))),
                        required(
                            "source-revision",
                            reference(Some(RecordKind::SourceRevision)),
                        ),
                        optional("path", FieldType::Text),
                        optional("binding", reference(Some(RecordKind::DocumentBinding))),
                        optional("includes", FieldType::Dictionary),
                        optional("render-config", FieldType::Text),
                    ],
                    ExtensionPolicy::Retain,
                );
            }
        }
        schema.kinds.push(KindSchema::new(
            RecordKind::DocumentBinding,
            vec![
                required("document", reference(Some(RecordKind::Document))),
                required("entity", reference(Some(RecordKind::Entity))),
                required("status", FieldType::Symbol),
                required("basis", FieldType::Text),
                required(
                    "source-revision",
                    reference(Some(RecordKind::SourceRevision)),
                ),
            ],
            ExtensionPolicy::Retain,
        ));
        schema.kinds.push(KindSchema::new(
            RecordKind::DocumentAnchor,
            vec![
                required("document", reference(Some(RecordKind::Document))),
                required(
                    "source-revision",
                    reference(Some(RecordKind::SourceRevision)),
                ),
                required("span", FieldType::Span),
                required("anchor", FieldType::Text),
                optional("label", FieldType::Text),
                optional("line", FieldType::Integer),
                optional("column", FieldType::Integer),
            ],
            ExtensionPolicy::Retain,
        ));
        schema
    }

    /// A synthetic version 2 schema used only by migration fixtures.
    ///
    /// It adds one required `extraction` field to assertions. It is not a
    /// production schema version: a runtime registry accepts only versions it
    /// registers explicitly. It is intentionally distinct from
    /// [`RecordSchema::evidence_v2`] and is never registered with it.
    pub fn synthetic_migration_v2() -> Self {
        let mut schema = RecordSchema::v1();
        schema.version = 2;
        for kind in &mut schema.kinds {
            if kind.kind == RecordKind::Assertion {
                kind.fields.push(required("extraction", FieldType::Text));
            }
        }
        schema
    }

    /// The schema version.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Every declared kind in this version.
    pub fn kinds(&self) -> &[KindSchema] {
        &self.kinds
    }

    /// A kind schema by kind.
    pub fn kind(&self, kind: RecordKind) -> Option<&KindSchema> {
        self.kinds.iter().find(|schema| schema.kind == kind)
    }
}

fn push_v1_entity_kinds(kinds: &mut Vec<KindSchema>) {
    kinds.push(KindSchema::new(
        RecordKind::Entity,
        vec![
            required("entity-type", FieldType::Symbol),
            required("label", FieldType::Text),
            required("properties", FieldType::Dictionary),
        ],
        ExtensionPolicy::Retain,
    ));
    kinds.push(KindSchema::new(
        RecordKind::Relation,
        vec![
            required("relation-type", FieldType::Symbol),
            required("from", reference(None)),
            required("to", reference(None)),
            required("properties", FieldType::Dictionary),
        ],
        ExtensionPolicy::Retain,
    ));
}

fn push_v1_document_kinds(kinds: &mut Vec<KindSchema>) {
    kinds.push(KindSchema::new(
        RecordKind::Document,
        vec![
            required("title", FieldType::Text),
            required("entity", reference(Some(RecordKind::Entity))),
            required(
                "source-revision",
                reference(Some(RecordKind::SourceRevision)),
            ),
        ],
        ExtensionPolicy::Retain,
    ));
    kinds.push(KindSchema::new(
        RecordKind::SourceRevision,
        vec![
            required("content", FieldType::SourceContent),
            required("acquisition", FieldType::Symbol),
            optional("entity", reference(Some(RecordKind::Entity))),
            optional("path-hint", FieldType::Text),
        ],
        ExtensionPolicy::Retain,
    ));
    kinds.push(KindSchema::new(
        RecordKind::Episode,
        vec![
            required("actor", FieldType::Text),
            required("episode-type", FieldType::Symbol),
            required("occurred", FieldType::ValidTime),
            required("summary", FieldType::Text),
            optional("source", reference(Some(RecordKind::SourceRevision))),
        ],
        ExtensionPolicy::Retain,
    ));
}

fn push_v1_assertion_kinds(kinds: &mut Vec<KindSchema>) {
    kinds.push(KindSchema::new(
        RecordKind::Assertion,
        vec![
            required("subject", reference(None)),
            required("predicate", FieldType::Symbol),
            required("value", FieldType::Any),
            required("stance", FieldType::Symbol),
            required("lifecycle", FieldType::Symbol),
            required("origin", FieldType::Symbol),
            required("asserted-by", FieldType::Text),
            required("valid-time", FieldType::ValidTime),
            required("evidence", reference_set(Some(RecordKind::Evidence))),
            optional("confidence", FieldType::Any),
            optional("superseded-by", reference(Some(RecordKind::Assertion))),
        ],
        ExtensionPolicy::Retain,
    ));
}

fn push_v1_evidence_kinds(kinds: &mut Vec<KindSchema>) {
    kinds.push(KindSchema::new(
        RecordKind::Evidence,
        vec![
            required("assertion", reference(Some(RecordKind::Assertion))),
            required("source", reference(Some(RecordKind::SourceRevision))),
            optional("span", FieldType::Span),
            optional("anchor", FieldType::Text),
            required("relation", FieldType::Symbol),
            required("origin", FieldType::Symbol),
            required("ancestry", reference_set(None)),
        ],
        ExtensionPolicy::Retain,
    ));
}

fn push_v1_workflow_kinds(kinds: &mut Vec<KindSchema>) {
    kinds.push(KindSchema::new(
        RecordKind::Derivation,
        vec![
            required("conclusion", reference(None)),
            required("premises", reference_set(None)),
            required("rule-id", FieldType::Text),
            required("rule-version", FieldType::Integer),
            required("evaluation-revision", FieldType::WorkspaceRevision),
            required("completeness", FieldType::Symbol),
        ],
        ExtensionPolicy::Retain,
    ));
    kinds.push(KindSchema::new(
        RecordKind::Checkpoint,
        vec![
            required("goal", FieldType::Text),
            required("state", FieldType::Symbol),
            required("episodes", reference_set(Some(RecordKind::Episode))),
            required(
                "verified-outcomes",
                reference_set(Some(RecordKind::Episode)),
            ),
            optional("note", FieldType::Text),
        ],
        ExtensionPolicy::Retain,
    ));
    kinds.push(KindSchema::new(
        RecordKind::Proposal,
        vec![
            required("proposal-kind", FieldType::Symbol),
            required("candidate", FieldType::Any),
            required("rationale", FieldType::Text),
            required("status", FieldType::Symbol),
        ],
        ExtensionPolicy::Retain,
    ));
    kinds.push(KindSchema::new(
        RecordKind::RetentionDirective,
        vec![
            required("target", reference(None)),
            required("mode", FieldType::Symbol),
            required("policy", FieldType::Text),
            required("effective", FieldType::ValidTime),
        ],
        ExtensionPolicy::Retain,
    ));
}

/// The schemas this build is prepared to interpret.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SchemaRegistry {
    versions: std::collections::BTreeMap<u32, RecordSchema>,
}

impl SchemaRegistry {
    /// A registry containing the production version 1 schema.
    pub fn v1() -> Self {
        let mut registry = SchemaRegistry::default();
        registry.register(RecordSchema::v1());
        registry
    }

    /// The production registry: version 1 plus the evidence version 2 kinds.
    pub fn production() -> Self {
        let mut registry = SchemaRegistry::v1();
        registry.register(RecordSchema::evidence_v2());
        registry.register(RecordSchema::documents_v3());
        registry
    }

    /// Register a schema version explicitly.
    pub fn register(&mut self, schema: RecordSchema) {
        self.versions.insert(schema.version(), schema);
    }

    /// Add a schema version, consuming and returning the registry.
    #[must_use]
    pub fn with_version(mut self, schema: RecordSchema) -> Self {
        self.register(schema);
        self
    }

    /// The schema for an exact version, if this build supports it.
    pub fn schema(&self, version: u32) -> Option<&RecordSchema> {
        self.versions.get(&version)
    }

    /// Supported versions in ascending order.
    pub fn supported_versions(&self) -> Vec<u32> {
        self.versions.keys().copied().collect()
    }
}

/// Validate one declared payload field.
#[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
pub fn validate_field(
    ty: FieldType,
    value: &crate::value::Value,
    path: &crate::error::Path,
    index: Option<&crate::reference::SnapshotIndex>,
) -> Vec<crate::error::Diagnostic> {
    match ty {
        FieldType::Symbol
        | FieldType::Text
        | FieldType::Integer
        | FieldType::Boolean
        | FieldType::Any
        | FieldType::Dictionary => validate_scalar_field(ty, value, path),
        FieldType::Reference {
            kind,
            allow_external,
            allow_unresolved,
        } => match crate::reference::Reference::from_value(value, path) {
            Err(diagnostic) => vec![diagnostic],
            Ok(reference) => validate_reference(
                &reference,
                kind,
                ReferenceValidation {
                    allow_external,
                    allow_unresolved,
                },
                path,
                index,
            ),
        },
        FieldType::ReferenceSet {
            kind,
            allow_external,
            allow_unresolved,
        } => validate_reference_set_field(
            value,
            path,
            index,
            kind,
            ReferenceValidation {
                allow_external,
                allow_unresolved,
            },
        ),
        FieldType::ValidTime => validate_valid_time_field(value, path),
        FieldType::Digest => {
            validate_parsed_field(crate::digest::ContentDigest::from_value(value, path))
        }
        FieldType::Span => {
            validate_parsed_field(crate::payload::SourceSpan::from_value(value, path))
        }
        FieldType::SourceContent => {
            validate_parsed_field(crate::payload::SourceContent::from_value(value, path))
        }
        FieldType::WorkspaceRevision => {
            validate_parsed_field(crate::ids::WorkspaceRevisionId::from_value(value, path))
        }
    }
}

fn validate_scalar_field(
    ty: FieldType,
    value: &crate::value::Value,
    path: &crate::error::Path,
) -> Vec<crate::error::Diagnostic> {
    match ty {
        FieldType::Symbol => expect(value.as_symbol().is_some(), value, path, "symbol"),
        FieldType::Text => expect(value.as_string().is_some(), value, path, "string"),
        FieldType::Integer => expect(value.as_integer().is_some(), value, path, "integer"),
        FieldType::Boolean => expect(value.as_boolean().is_some(), value, path, "boolean"),
        FieldType::Any => Vec::new(),
        FieldType::Dictionary => expect(value.as_dictionary().is_some(), value, path, "dictionary"),
        _ => expect(false, value, path, "scalar"),
    }
}

fn validate_reference_set_field(
    value: &crate::value::Value,
    path: &crate::error::Path,
    index: Option<&crate::reference::SnapshotIndex>,
    kind: Option<RecordKind>,
    validation: ReferenceValidation,
) -> Vec<crate::error::Diagnostic> {
    let Some(items) = value.as_set() else {
        return type_mismatch(value, path, "set of references");
    };
    let mut diagnostics = Vec::with_capacity(items.len().saturating_mul(2));
    for (position, item) in items.iter().enumerate() {
        match crate::reference::Reference::from_value(item, &path.index(position)) {
            Err(diagnostic) => diagnostics.push(diagnostic),
            Ok(reference) => diagnostics.extend(validate_reference(
                &reference,
                kind,
                validation,
                &path.index(position),
                index,
            )),
        }
    }
    diagnostics
}

fn validate_valid_time_field(
    value: &crate::value::Value,
    path: &crate::error::Path,
) -> Vec<crate::error::Diagnostic> {
    match crate::time::ValidTime::from_value(value, path) {
        Err(diagnostic) => vec![diagnostic],
        Ok(valid_time) => match valid_time.validate(path) {
            Ok(()) => Vec::new(),
            Err(diagnostic) => vec![diagnostic],
        },
    }
}

fn validate_parsed_field<T>(
    result: Result<T, crate::error::Diagnostic>,
) -> Vec<crate::error::Diagnostic> {
    match result {
        Ok(_) => Vec::new(),
        Err(diagnostic) => vec![diagnostic],
    }
}

#[derive(Clone, Copy)]
struct ReferenceValidation {
    allow_external: bool,
    allow_unresolved: bool,
}

fn validate_reference(
    reference: &crate::reference::Reference,
    expected: Option<RecordKind>,
    validation: ReferenceValidation,
    path: &crate::error::Path,
    index: Option<&crate::reference::SnapshotIndex>,
) -> Vec<crate::error::Diagnostic> {
    let mut diagnostics = Vec::new();
    if let Some(expected) = expected
        && reference.kind() != expected
    {
        diagnostics.push(crate::error::Diagnostic::new(
            crate::error::Stage::Domain,
            crate::error::ErrorCode::ReferenceKindMismatch,
            path.clone(),
            format!(
                "reference names kind {} where {} is required",
                reference.kind().symbol(),
                expected.symbol()
            ),
        ));
    }
    if reference.is_external() && !validation.allow_external {
        diagnostics.push(crate::error::Diagnostic::new(
            crate::error::Stage::Domain,
            crate::error::ErrorCode::ExternalReferenceRefused,
            path.clone(),
            "this field does not permit an external reference",
        ));
        return diagnostics;
    }
    if reference.is_unresolved() && !validation.allow_unresolved {
        diagnostics.push(crate::error::Diagnostic::new(
            crate::error::Stage::Domain,
            crate::error::ErrorCode::UnresolvedReference,
            path.clone(),
            "this field does not permit a typed unresolved reference",
        ));
        return diagnostics;
    }
    if let Some(index) = index
        && let Err(diagnostic) = reference.validate(index, path)
        // A typed unresolved reference is permitted even when the target is
        // absent; the field flag already decided that case. External
        // references are not resolved locally by contract.
        && !(reference.is_unresolved() && validation.allow_unresolved)
    {
        diagnostics.push(diagnostic);
    }
    diagnostics
}

fn expect(
    present: bool,
    value: &crate::value::Value,
    path: &crate::error::Path,
    expected: &'static str,
) -> Vec<crate::error::Diagnostic> {
    if present {
        Vec::new()
    } else {
        type_mismatch(value, path, expected)
    }
}

fn type_mismatch(
    value: &crate::value::Value,
    path: &crate::error::Path,
    expected: &'static str,
) -> Vec<crate::error::Diagnostic> {
    vec![crate::error::Diagnostic::new(
        crate::error::Stage::Domain,
        crate::error::ErrorCode::TypeMismatch,
        path.clone(),
        format!("expected {expected}, found {}", value.kind_name()),
    )]
}

/// Run kind-specific domain checks after field types pass.
#[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
pub fn validate_domain(
    kind: RecordKind,
    payload: &std::collections::BTreeMap<crate::value::Symbol, crate::value::Value>,
    path: &crate::error::Path,
) -> Vec<crate::error::Diagnostic> {
    match kind {
        RecordKind::Assertion => validate_assertion_domain(payload, path),
        RecordKind::Evidence => validate_evidence_domain(payload, path),
        _ => Vec::new(),
    }
}

fn validate_assertion_domain(
    payload: &std::collections::BTreeMap<crate::value::Symbol, crate::value::Value>,
    path: &crate::error::Path,
) -> Vec<crate::error::Diagnostic> {
    let mut diagnostics = Vec::new();
    if let Some(value) = payload.get(&crate::value::Symbol::from("lifecycle")) {
        match Lifecycle::from_value(value, &path.field("lifecycle")) {
            Err(diagnostic) => diagnostics.push(diagnostic),
            Ok(Lifecycle::Superseded)
                if !payload.contains_key(&crate::value::Symbol::from("superseded-by")) =>
            {
                diagnostics.push(crate::error::Diagnostic::new(
                    crate::error::Stage::Domain,
                    crate::error::ErrorCode::MissingField,
                    path.field("superseded-by"),
                    "a superseded assertion must name its replacement",
                ));
            }
            Ok(_) => {}
        }
    }
    if let Some(value) = payload.get(&crate::value::Symbol::from("stance"))
        && !matches!(
            value.as_symbol().map(crate::value::Symbol::as_str),
            Some("affirm" | "deny" | "hypothesis")
        )
    {
        diagnostics.push(crate::error::Diagnostic::new(
            crate::error::Stage::Domain,
            crate::error::ErrorCode::TypeMismatch,
            path.field("stance"),
            "stance must be affirm, deny, or hypothesis",
        ));
    }
    if let Some(value) = payload.get(&crate::value::Symbol::from("origin"))
        && value
            .as_symbol()
            .and_then(|symbol| Origin::parse(symbol.as_str()))
            .is_none()
    {
        diagnostics.push(crate::error::Diagnostic::new(
            crate::error::Stage::Domain,
            crate::error::ErrorCode::TypeMismatch,
            path.field("origin"),
            "origin must be observation, authored-statement, model-extraction, inference, or import",
        ));
    }
    diagnostics
}

fn validate_evidence_domain(
    payload: &std::collections::BTreeMap<crate::value::Symbol, crate::value::Value>,
    path: &crate::error::Path,
) -> Vec<crate::error::Diagnostic> {
    let mut diagnostics = Vec::new();
    let has_span = payload.contains_key(&crate::value::Symbol::from("span"));
    let has_anchor = payload.contains_key(&crate::value::Symbol::from("anchor"));
    if !has_span && !has_anchor {
        diagnostics.push(crate::error::Diagnostic::new(
            crate::error::Stage::Domain,
            crate::error::ErrorCode::MissingField,
            path.clone(),
            "evidence requires an exact span or a stable anchor",
        ));
    }
    if let Some(value) = payload.get(&crate::value::Symbol::from("relation"))
        && !matches!(
            value.as_symbol().map(crate::value::Symbol::as_str),
            Some("supports" | "challenges")
        )
    {
        diagnostics.push(crate::error::Diagnostic::new(
            crate::error::Stage::Domain,
            crate::error::ErrorCode::TypeMismatch,
            path.field("relation"),
            "evidence relation must be supports or challenges",
        ));
    }
    diagnostics
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_one_declares_every_core_kind() {
        let schema = RecordSchema::v1();
        assert_eq!(schema.version(), 1);
        let later = [
            RecordKind::Decision,
            RecordKind::DocumentBinding,
            RecordKind::DocumentAnchor,
        ];
        for kind in RecordKind::ALL
            .into_iter()
            .filter(|kind| !later.contains(kind))
        {
            assert!(
                schema.kind(kind).is_some(),
                "{} must be declared",
                kind.symbol()
            );
        }
        for kind in later {
            assert!(schema.kind(kind).is_none());
        }
        assert_eq!(schema.kinds().len(), RecordKind::ALL.len() - later.len());
    }

    #[test]
    fn unsupported_versions_are_not_in_the_v1_registry() {
        let registry = SchemaRegistry::v1();
        assert_eq!(registry.supported_versions(), vec![1]);
        assert!(registry.schema(2).is_none());
    }

    #[test]
    fn synthetic_migration_v2_is_registered_only_explicitly() {
        let registry = SchemaRegistry::v1().with_version(RecordSchema::synthetic_migration_v2());
        assert_eq!(registry.supported_versions(), vec![1, 2]);
        let assertion = registry
            .schema(2)
            .and_then(|schema| schema.kind(RecordKind::Assertion))
            .expect("assertion v2");
        assert!(assertion.field("extraction").is_some());
        let v1 = registry
            .schema(1)
            .and_then(|schema| schema.kind(RecordKind::Assertion))
            .expect("assertion v1");
        assert!(v1.field("extraction").is_none());
    }

    #[test]
    fn production_registry_adds_decision_and_document_kinds() {
        let registry = SchemaRegistry::production();
        assert_eq!(registry.supported_versions(), vec![1, 2, 3]);
        assert!(
            registry
                .schema(1)
                .and_then(|schema| schema.kind(RecordKind::Decision))
                .is_none()
        );
        let decision = registry
            .schema(2)
            .and_then(|schema| schema.kind(RecordKind::Decision))
            .expect("decision v2");
        assert!(decision.field("policy").is_some());
        assert!(decision.field("input-revision").is_some());
        let assertion = registry
            .schema(2)
            .and_then(|schema| schema.kind(RecordKind::Assertion))
            .expect("assertion v2");
        assert!(assertion.field("decision").is_some());
        assert!(
            registry
                .schema(2)
                .and_then(|schema| schema.kind(RecordKind::DocumentBinding))
                .is_none()
        );
        let document = registry
            .schema(3)
            .and_then(|schema| schema.kind(RecordKind::Document))
            .expect("document v3");
        assert!(!document.field("entity").expect("entity").required);
        assert!(document.field("path").is_some());
        assert!(
            registry
                .schema(3)
                .and_then(|schema| schema.kind(RecordKind::DocumentBinding))
                .is_some()
        );
        assert!(
            registry
                .schema(3)
                .and_then(|schema| schema.kind(RecordKind::DocumentAnchor))
                .is_some()
        );
    }

    #[test]
    fn lifecycle_and_origin_parse_declared_values() {
        for lifecycle in [
            Lifecycle::Proposed,
            Lifecycle::Accepted,
            Lifecycle::Disputed,
            Lifecycle::Superseded,
            Lifecycle::Retracted,
        ] {
            assert_eq!(Lifecycle::parse(lifecycle.symbol()), Some(lifecycle));
        }
        for origin in [
            Origin::Observation,
            Origin::AuthoredStatement,
            Origin::ModelExtraction,
            Origin::Inference,
            Origin::Import,
        ] {
            assert_eq!(Origin::parse(origin.symbol()), Some(origin));
        }
    }
}
