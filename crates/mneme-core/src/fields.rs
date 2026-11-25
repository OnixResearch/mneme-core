//! Versioned record kinds, payload field schemas, and schema registries.
//!
//! Version 1 declares the record kinds and their ordinary authoritative fields.
//! Validation is pure: it checks structure, types, intervals, and references
//! without promoting an assertion's epistemic lifecycle or rewriting payloads.
//! Unknown extension fields are retained under the version 1 compatibility
//! rule; an editor that cannot preserve one must refuse the edit instead.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

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
    Comment,
    RecognitionRun,
    RecognitionSegment,
}

impl RecordKind {
    /// Every declared kind.
    pub const ALL: [RecordKind; 17] = [
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
        RecordKind::Comment,
        RecordKind::RecognitionRun,
        RecordKind::RecognitionSegment,
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
            RecordKind::Comment => "comment",
            RecordKind::RecognitionRun => "recognition-run",
            RecordKind::RecognitionSegment => "recognition-segment",
        }
    }

    /// Parse a declared kind symbol.
    pub fn parse(text: &str) -> Option<Self> {
        RecordKind::ALL
            .into_iter()
            .find(|kind| kind.symbol() == text)
    }

    /// Encode this kind as its schema symbol.
    pub fn to_value(self) -> crate::typed::Value {
        crate::typed::Value::symbol(self.symbol())
    }

    /// Decode and require a declared kind.
    pub fn from_value(
        value: &crate::typed::Value,
        path: &crate::problem::Path,
    ) -> Result<Self, crate::problem::Diagnostic> {
        let Some(symbol) = value.as_symbol() else {
            return Err(crate::problem::Diagnostic::new(
                crate::problem::Stage::Envelope,
                crate::problem::ErrorCode::UnknownRecordKind,
                path.clone(),
                "record kind must be a declared symbol",
            ));
        };
        RecordKind::parse(symbol.as_str()).ok_or_else(|| {
            crate::problem::Diagnostic::new(
                crate::problem::Stage::Envelope,
                crate::problem::ErrorCode::UnknownRecordKind,
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
        value: &crate::typed::Value,
        path: &crate::problem::Path,
    ) -> Result<Self, crate::problem::Diagnostic> {
        let Some(symbol) = value.as_symbol() else {
            return Err(crate::problem::Diagnostic::new(
                crate::problem::Stage::Domain,
                crate::problem::ErrorCode::TypeMismatch,
                path.clone(),
                "assertion lifecycle must be a symbol",
            ));
        };
        Lifecycle::parse(symbol.as_str()).ok_or_else(|| {
            crate::problem::Diagnostic::new(
                crate::problem::Stage::Domain,
                crate::problem::ErrorCode::TypeMismatch,
                path.clone(),
                format!("unknown assertion lifecycle {symbol}"),
            )
        })
    }

    /// Convert to the decision kernel's lifecycle.
    ///
    /// The exhaustive `match` means a lifecycle added here cannot be handed to
    /// the kernel under some other state's transition rules.
    pub const fn to_kernel(self) -> mneme_kernel::claim::Lifecycle {
        match self {
            Lifecycle::Proposed => mneme_kernel::claim::Lifecycle::Proposed,
            Lifecycle::Accepted => mneme_kernel::claim::Lifecycle::Accepted,
            Lifecycle::Disputed => mneme_kernel::claim::Lifecycle::Disputed,
            Lifecycle::Superseded => mneme_kernel::claim::Lifecycle::Superseded,
            Lifecycle::Retracted => mneme_kernel::claim::Lifecycle::Retracted,
        }
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
    /// `<extraction model prompt>`: the model and prompt behind a value.
    Extraction,
    /// A document include closure: text paths to pinned source revisions.
    IncludeMap,
    /// Acquisition provenance on a source revision: a closed symbol class.
    Acquisition,
    /// Acquisition provenance that may also be a structured
    /// `derived(source, backend, backend-version)` record (schema version 6).
    DerivableAcquisition,
    /// Declared media bounds for a source revision.
    MediaExtent,
    /// Typed source transform mapping.
    MediaTransform,
    /// Audio, page, or ink location.
    MediaLocation,
    /// The part of a capture a recognition run covers.
    CapturePart,
    /// Recognition unit coverage.
    RecognitionCoverage,
    /// Bounded provider score sequence.
    RecognitionScores,
    /// Bounded provider alternative sequence.
    RecognitionAlternatives,
    /// Layout block identity, reading kind, label and optional order.
    RecognitionBlock,
    /// Raster page frames, unknown/partial detection coverage and regions.
    RecognitionPage,
    /// Human correction provenance and alignment disposition.
    CorrectionProvenance,
    /// The coordinate frame a page or ink source's pages use.
    CoordinateFrame,
    /// The stroke ids an ink source declares, by page and layer.
    InkInventory,
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
                    // Model extractions are ordinary authoritative data: a
                    // malformed one would break every belief and conflict view
                    // in the workspace, so its shape is schema-checked here.
                    kind.fields
                        .push(optional("extraction", FieldType::Extraction));
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
                        // The include closure decides which source bytes a
                        // rendered document depends on, so it is authoritative
                        // data rather than an untyped dictionary.
                        optional("includes", FieldType::IncludeMap),
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

    /// The production version 4 schema introduced by `comment-records`.
    ///
    /// It keeps every version 1/2/3 kind and adds the comment record kind.
    pub fn comments_v4() -> Self {
        let mut schema = RecordSchema::documents_v3();
        schema.version = 4;
        schema.kinds.push(KindSchema::new(
            RecordKind::Comment,
            vec![
                required("actor", FieldType::Text),
                required("document", reference(Some(RecordKind::Document))),
                required(
                    "source-revision",
                    reference(Some(RecordKind::SourceRevision)),
                ),
                optional("span", FieldType::Span),
                optional("block", FieldType::Text),
                required("text", FieldType::Text),
                optional("reply-to", reference(Some(RecordKind::Comment))),
                optional("mentions", FieldType::Any),
                required("status", FieldType::Symbol),
                optional("resolves", reference(Some(RecordKind::Comment))),
            ],
            ExtensionPolicy::Retain,
        ));
        schema
    }

    /// The production version 5 schema introduced by `media-recognition`.
    ///
    /// It preserves versions 1-4, strengthens source acquisition typing, and
    /// adds explicit media extents, source transforms, recognition runs and
    /// segment-to-media mappings.
    pub fn media_v5() -> Self {
        let mut schema = RecordSchema::comments_v4();
        schema.version = 5;
        for kind in &mut schema.kinds {
            if kind.kind == RecordKind::SourceRevision {
                if let Some(acquisition) = kind
                    .fields
                    .iter_mut()
                    .find(|field| field.name == "acquisition")
                {
                    acquisition.ty = FieldType::Acquisition;
                }
                kind.fields.extend([
                    optional("derived-from", reference(Some(RecordKind::SourceRevision))),
                    optional("media-extent", FieldType::MediaExtent),
                    optional("media-transform", FieldType::MediaTransform),
                    optional("media-frame", FieldType::CoordinateFrame),
                    optional("ink-strokes", FieldType::InkInventory),
                    optional("correction", FieldType::CorrectionProvenance),
                ]);
            }
        }
        schema.kinds.push(KindSchema::new(
            RecordKind::RecognitionRun,
            vec![
                required("input", reference(Some(RecordKind::SourceRevision))),
                required("input-digest", FieldType::Digest),
                required("output", reference(Some(RecordKind::SourceRevision))),
                required("output-digest", FieldType::Digest),
                required("model", FieldType::Text),
                required("runtime", FieldType::Text),
                required("adapter", FieldType::Text),
                required("preprocessing", FieldType::Text),
                required("configuration", FieldType::Text),
                required(
                    "segments",
                    reference_set(Some(RecordKind::RecognitionSegment)),
                ),
                required("coverage", FieldType::RecognitionCoverage),
                required("status", FieldType::Symbol),
                optional("scores", FieldType::RecognitionScores),
                optional("alternatives", FieldType::RecognitionAlternatives),
                optional("covers", FieldType::CapturePart),
                optional("page", FieldType::RecognitionPage),
            ],
            ExtensionPolicy::Retain,
        ));
        schema.kinds.push(KindSchema::new(
            RecordKind::RecognitionSegment,
            vec![
                optional("run", reference(Some(RecordKind::RecognitionRun))),
                required("text-source", reference(Some(RecordKind::SourceRevision))),
                required("span", FieldType::Span),
                required("media-source", reference(Some(RecordKind::SourceRevision))),
                required("media-digest", FieldType::Digest),
                required("location", FieldType::MediaLocation),
                optional("block", FieldType::RecognitionBlock),
            ],
            ExtensionPolicy::Retain,
        ));
        schema
    }

    /// The production version 6 schema introduced by `derived-acquisition`.
    ///
    /// It preserves versions 1-5 and lets a source revision declare
    /// `acquisition: derived(source, backend, backend-version)`.
    pub fn derived_v6() -> Self {
        let mut schema = RecordSchema::media_v5();
        schema.version = 6;
        for kind in &mut schema.kinds {
            if kind.kind == RecordKind::SourceRevision
                && let Some(acquisition) = kind
                    .fields
                    .iter_mut()
                    .find(|field| field.name == "acquisition")
            {
                acquisition.ty = FieldType::DerivableAcquisition;
            }
        }
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

    /// The production registry through derived-acquisition schema version 6.
    pub fn production() -> Self {
        let mut registry = SchemaRegistry::v1();
        registry.register(RecordSchema::evidence_v2());
        registry.register(RecordSchema::documents_v3());
        registry.register(RecordSchema::comments_v4());
        registry.register(RecordSchema::media_v5());
        registry.register(RecordSchema::derived_v6());
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

    /// The declared field a later version introduces for a kind.
    ///
    /// An earlier version retains unknown payload fields as extensions. When
    /// the unknown name is one a later version declares authoritative for the
    /// same kind, the version that introduced it still governs its type:
    /// otherwise a record written under the compatibility rule could carry a
    /// malformed value that every consumer of the later version then has to
    /// reject. The lowest later version wins, so the type is the one the field
    /// had when it was introduced. The returned spec carries the declared
    /// static name, so a diagnostic can address the field the way the declaring
    /// version does. Only the type and the name apply: the field is absent from
    /// the earlier version's schema, so a missing value is not a missing field.
    pub fn later_field(&self, kind: RecordKind, name: &str, version: u32) -> Option<FieldSpec> {
        let start = std::ops::Bound::Excluded(version);
        let stop = std::ops::Bound::Unbounded;
        self.versions.range((start, stop)).find_map(|(_, schema)| {
            schema
                .kind(kind)
                .and_then(|kind_schema| kind_schema.field(name))
                .copied()
        })
    }
}

/// Validate one declared payload field.
pub fn validate_field(
    ty: FieldType,
    value: &crate::typed::Value,
    path: &crate::problem::Path,
    index: Option<&crate::pointer::SnapshotIndex>,
) -> Vec<crate::problem::Diagnostic> {
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
        }
        | FieldType::ReferenceSet {
            kind,
            allow_external,
            allow_unresolved,
        } => {
            let validation = ReferenceValidation {
                allow_external,
                allow_unresolved,
            };
            if matches!(ty, FieldType::ReferenceSet { .. }) {
                validate_reference_set_field(value, path, index, kind, validation)
            } else {
                validate_reference_field(value, path, index, kind, validation)
            }
        }
        FieldType::ValidTime => validate_valid_time_field(value, path),
        FieldType::Digest => parsed(crate::hashing::ContentDigest::from_value, value, path),
        FieldType::Span => parsed(crate::payload::SourceSpan::from_value, value, path),
        FieldType::SourceContent => parsed(crate::payload::SourceContent::from_value, value, path),
        FieldType::WorkspaceRevision => {
            parsed(crate::ids::WorkspaceRevisionId::from_value, value, path)
        }
        FieldType::Extraction => validate_extraction_field(value, path),
        FieldType::IncludeMap => validate_include_map_field(value, path, index),
        FieldType::Acquisition => {
            parsed(crate::lineage::Acquisition::from_symbol_value, value, path)
        }
        FieldType::DerivableAcquisition => {
            parsed(crate::lineage::Acquisition::from_value, value, path)
        }
        FieldType::MediaExtent => parsed(crate::lineage::MediaExtent::from_value, value, path),
        FieldType::MediaTransform => {
            parsed(crate::lineage::MediaTransform::from_value, value, path)
        }
        FieldType::MediaLocation => parsed(crate::lineage::MediaLocation::from_value, value, path),
        FieldType::CapturePart => parsed(crate::lineage::CapturePart::from_value, value, path),
        FieldType::RecognitionCoverage => {
            parsed(crate::lineage::RecognitionCoverage::from_value, value, path)
        }
        FieldType::RecognitionScores => {
            validate_sequence_field(value, path, crate::lineage::validate_scores)
        }
        FieldType::RecognitionAlternatives => {
            validate_sequence_field(value, path, crate::lineage::validate_alternatives)
        }
        FieldType::RecognitionBlock => {
            parsed(crate::layout::RecognitionBlock::from_value, value, path)
        }
        FieldType::RecognitionPage => {
            parsed(crate::raster::RecognitionPage::from_value, value, path)
        }
        FieldType::CorrectionProvenance => parsed(
            crate::lineage::CorrectionProvenance::from_value,
            value,
            path,
        ),
        FieldType::CoordinateFrame => {
            parsed(crate::lineage::CoordinateFrame::from_value, value, path)
        }
        FieldType::InkInventory => parsed(crate::lineage::InkInventory::from_value, value, path),
    }
}

/// Validate `<extraction model prompt>`.
///
/// The label, the arity and both field types are fixed: a consumer that parses
/// an extraction must be able to do so without a fallback.
fn validate_extraction_field(
    value: &crate::typed::Value,
    path: &crate::problem::Path,
) -> Vec<crate::problem::Diagnostic> {
    let shape_error = || {
        vec![crate::problem::Diagnostic::new(
            crate::problem::Stage::Domain,
            crate::problem::ErrorCode::TypeMismatch,
            path.clone(),
            "expected <extraction model prompt> with two strings",
        )]
    };
    let Some(record) = value.as_record() else {
        return shape_error();
    };
    if record.label() != &crate::typed::Value::symbol("extraction") || record.fields().len() != 2 {
        return shape_error();
    }
    let mut diagnostics = Vec::with_capacity(2);
    for (position, field) in record.fields().iter().enumerate() {
        if field.as_string().is_none() {
            diagnostics.extend(type_mismatch(field, &path.index(position), "string"));
        }
    }
    diagnostics
}

/// Validate a document include closure: text paths to pinned source revisions.
///
/// A closure entry names exact source bytes, so it must be a revision pin and
/// not a snapshot-local, external or unresolved reference; otherwise a rendered
/// document could depend on bytes it never recorded.
fn validate_include_map_field(
    value: &crate::typed::Value,
    path: &crate::problem::Path,
    index: Option<&crate::pointer::SnapshotIndex>,
) -> Vec<crate::problem::Diagnostic> {
    let Some(entries) = value.as_dictionary() else {
        return type_mismatch(
            value,
            path,
            "dictionary of include paths to pinned source revisions",
        );
    };
    // One entry yields at most one type mismatch or one reference validation,
    // and a reference validation reports at most three diagnostics.
    let mut diagnostics = Vec::with_capacity(entries.len().saturating_mul(3));
    for (position, (key, reference_value)) in entries.iter().enumerate() {
        let entry_path = match key.as_string() {
            Some(text) => path.named(text),
            None => path.index(position),
        };
        if key.as_string().is_none() {
            diagnostics.extend(type_mismatch(key, &entry_path, "include path string"));
            continue;
        }
        match crate::pointer::Reference::from_value(reference_value, &entry_path) {
            Err(diagnostic) => diagnostics.push(diagnostic),
            Ok(reference) => {
                if matches!(reference, crate::pointer::Reference::Pinned { .. }) {
                    diagnostics.extend(validate_reference(
                        &reference,
                        Some(RecordKind::SourceRevision),
                        ReferenceValidation {
                            allow_external: false,
                            allow_unresolved: false,
                        },
                        &entry_path,
                        index,
                    ));
                } else {
                    diagnostics.extend(type_mismatch(
                        reference_value,
                        &entry_path,
                        "pinned source-revision reference",
                    ));
                }
            }
        }
    }
    diagnostics
}

fn validate_scalar_field(
    ty: FieldType,
    value: &crate::typed::Value,
    path: &crate::problem::Path,
) -> Vec<crate::problem::Diagnostic> {
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
    value: &crate::typed::Value,
    path: &crate::problem::Path,
    index: Option<&crate::pointer::SnapshotIndex>,
    kind: Option<RecordKind>,
    validation: ReferenceValidation,
) -> Vec<crate::problem::Diagnostic> {
    let Some(items) = value.as_set() else {
        return type_mismatch(value, path, "set of references");
    };
    let mut diagnostics = Vec::with_capacity(items.len().saturating_mul(2));
    for (position, item) in items.iter().enumerate() {
        match crate::pointer::Reference::from_value(item, &path.index(position)) {
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

fn validate_reference_field(
    value: &crate::typed::Value,
    path: &crate::problem::Path,
    index: Option<&crate::pointer::SnapshotIndex>,
    kind: Option<RecordKind>,
    validation: ReferenceValidation,
) -> Vec<crate::problem::Diagnostic> {
    match crate::pointer::Reference::from_value(value, path) {
        Err(diagnostic) => vec![diagnostic],
        Ok(reference) => validate_reference(&reference, kind, validation, path, index),
    }
}

fn validate_valid_time_field(
    value: &crate::typed::Value,
    path: &crate::problem::Path,
) -> Vec<crate::problem::Diagnostic> {
    match crate::clock::ValidTime::from_value(value, path) {
        Err(diagnostic) => vec![diagnostic],
        Ok(valid_time) => match valid_time.validate(path) {
            Ok(()) => Vec::new(),
            Err(diagnostic) => vec![diagnostic],
        },
    }
}

/// Diagnostics from parsing `value` as one typed field.
fn parsed<T>(
    parse: fn(&crate::typed::Value, &crate::problem::Path) -> Result<T, crate::problem::Diagnostic>,
    value: &crate::typed::Value,
    path: &crate::problem::Path,
) -> Vec<crate::problem::Diagnostic> {
    validate_parsed_field(parse(value, path))
}

fn validate_parsed_field<T>(
    result: Result<T, crate::problem::Diagnostic>,
) -> Vec<crate::problem::Diagnostic> {
    match result {
        Ok(_) => Vec::new(),
        Err(diagnostic) => vec![diagnostic],
    }
}

fn validate_sequence_field(
    value: &crate::typed::Value,
    path: &crate::problem::Path,
    validate: fn(
        &crate::typed::Value,
        &crate::problem::Path,
    ) -> Result<(), crate::problem::Diagnostic>,
) -> Vec<crate::problem::Diagnostic> {
    validate_parsed_field(validate(value, path))
}

#[derive(Clone, Copy)]
struct ReferenceValidation {
    allow_external: bool,
    allow_unresolved: bool,
}

fn validate_reference(
    reference: &crate::pointer::Reference,
    expected: Option<RecordKind>,
    validation: ReferenceValidation,
    path: &crate::problem::Path,
    index: Option<&crate::pointer::SnapshotIndex>,
) -> Vec<crate::problem::Diagnostic> {
    let mut diagnostics = Vec::new();
    if let Some(expected) = expected
        && reference.kind() != expected
    {
        diagnostics.push(crate::problem::Diagnostic::new(
            crate::problem::Stage::Domain,
            crate::problem::ErrorCode::ReferenceKindMismatch,
            path.clone(),
            format!(
                "reference names kind {} where {} is required",
                reference.kind().symbol(),
                expected.symbol()
            ),
        ));
    }
    if reference.is_external() && !validation.allow_external {
        diagnostics.push(crate::problem::Diagnostic::new(
            crate::problem::Stage::Domain,
            crate::problem::ErrorCode::ExternalReferenceRefused,
            path.clone(),
            "this field does not permit an external reference",
        ));
        return diagnostics;
    }
    if reference.is_unresolved() && !validation.allow_unresolved {
        diagnostics.push(crate::problem::Diagnostic::new(
            crate::problem::Stage::Domain,
            crate::problem::ErrorCode::UnresolvedReference,
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
    value: &crate::typed::Value,
    path: &crate::problem::Path,
    expected: &'static str,
) -> Vec<crate::problem::Diagnostic> {
    if present {
        Vec::new()
    } else {
        type_mismatch(value, path, expected)
    }
}

fn type_mismatch(
    value: &crate::typed::Value,
    path: &crate::problem::Path,
    expected: &'static str,
) -> Vec<crate::problem::Diagnostic> {
    vec![crate::problem::Diagnostic::new(
        crate::problem::Stage::Domain,
        crate::problem::ErrorCode::TypeMismatch,
        path.clone(),
        format!("expected {expected}, found {}", value.kind_name()),
    )]
}

/// Run kind-specific domain checks after field types pass.
#[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
pub fn validate_domain(
    kind: RecordKind,
    schema_version: u32,
    payload: &std::collections::BTreeMap<crate::typed::Symbol, crate::typed::Value>,
    path: &crate::problem::Path,
) -> Vec<crate::problem::Diagnostic> {
    match kind {
        // Sources written before the closed acquisition classes keep the
        // symbol their schema allowed.
        RecordKind::SourceRevision
            if schema_version < crate::lineage::ACQUISITION_SCHEMA_VERSION =>
        {
            Vec::new()
        }
        RecordKind::Assertion => validate_assertion_domain(payload, path),
        RecordKind::Evidence => validate_evidence_domain(payload, path),
        RecordKind::Comment => validate_comment_domain(payload, path),
        RecordKind::SourceRevision => validate_source_domain(payload, path),
        RecordKind::RecognitionRun => validate_recognition_run_domain(payload, path),
        RecordKind::RecognitionSegment => validate_recognition_segment_domain(payload, path),
        _ => Vec::new(),
    }
}

fn validate_assertion_domain(
    payload: &std::collections::BTreeMap<crate::typed::Symbol, crate::typed::Value>,
    path: &crate::problem::Path,
) -> Vec<crate::problem::Diagnostic> {
    let mut diagnostics = Vec::new();
    if let Some(value) = payload.get(&crate::typed::Symbol::from("lifecycle")) {
        match Lifecycle::from_value(value, &path.field("lifecycle")) {
            Err(diagnostic) => diagnostics.push(diagnostic),
            Ok(Lifecycle::Superseded)
                if !payload.contains_key(&crate::typed::Symbol::from("superseded-by")) =>
            {
                diagnostics.push(crate::problem::Diagnostic::new(
                    crate::problem::Stage::Domain,
                    crate::problem::ErrorCode::MissingField,
                    path.field("superseded-by"),
                    "a superseded assertion must name its replacement",
                ));
            }
            Ok(_) => {}
        }
    }
    if let Some(value) = payload.get(&crate::typed::Symbol::from("stance"))
        && !matches!(
            value.as_symbol().map(crate::typed::Symbol::as_str),
            Some("affirm" | "deny" | "hypothesis")
        )
    {
        diagnostics.push(crate::problem::Diagnostic::new(
            crate::problem::Stage::Domain,
            crate::problem::ErrorCode::TypeMismatch,
            path.field("stance"),
            "stance must be affirm, deny, or hypothesis",
        ));
    }
    if let Some(value) = payload.get(&crate::typed::Symbol::from("origin"))
        && value
            .as_symbol()
            .and_then(|symbol| Origin::parse(symbol.as_str()))
            .is_none()
    {
        diagnostics.push(crate::problem::Diagnostic::new(
            crate::problem::Stage::Domain,
            crate::problem::ErrorCode::TypeMismatch,
            path.field("origin"),
            "origin must be observation, authored-statement, model-extraction, inference, or import",
        ));
    }
    diagnostics
}

fn validate_evidence_domain(
    payload: &std::collections::BTreeMap<crate::typed::Symbol, crate::typed::Value>,
    path: &crate::problem::Path,
) -> Vec<crate::problem::Diagnostic> {
    let mut diagnostics = Vec::new();
    let has_span = payload.contains_key(&crate::typed::Symbol::from("span"));
    let has_anchor = payload.contains_key(&crate::typed::Symbol::from("anchor"));
    if !has_span && !has_anchor {
        diagnostics.push(crate::problem::Diagnostic::new(
            crate::problem::Stage::Domain,
            crate::problem::ErrorCode::MissingField,
            path.clone(),
            "evidence requires an exact span or a stable anchor",
        ));
    }
    if let Some(value) = payload.get(&crate::typed::Symbol::from("relation"))
        && !matches!(
            value.as_symbol().map(crate::typed::Symbol::as_str),
            Some("supports" | "challenges")
        )
    {
        diagnostics.push(crate::problem::Diagnostic::new(
            crate::problem::Stage::Domain,
            crate::problem::ErrorCode::TypeMismatch,
            path.field("relation"),
            "evidence relation must be supports or challenges",
        ));
    }
    diagnostics
}

fn validate_comment_domain(
    payload: &std::collections::BTreeMap<crate::typed::Symbol, crate::typed::Value>,
    path: &crate::problem::Path,
) -> Vec<crate::problem::Diagnostic> {
    let mut diagnostics = Vec::new();
    if let Some(value) = payload.get(&crate::typed::Symbol::from("status")) {
        match value.as_symbol().map(crate::typed::Symbol::as_str) {
            Some("proposed" | "open" | "resolved" | "dismissed") => {}
            _ => {
                diagnostics.push(crate::problem::Diagnostic::new(
                    crate::problem::Stage::Domain,
                    crate::problem::ErrorCode::TypeMismatch,
                    path.field("status"),
                    "status must be proposed, open, resolved, or dismissed",
                ));
            }
        }
    }
    if let Some(value) = payload.get(&crate::typed::Symbol::from("text")) {
        let is_invalid = match value.as_string() {
            Some(text) => text.is_empty() || text.len() > 16384,
            None => true,
        };
        if is_invalid {
            diagnostics.push(crate::problem::Diagnostic::new(
                crate::problem::Stage::Domain,
                crate::problem::ErrorCode::TypeMismatch,
                path.field("text"),
                "text must be non-empty and at most 16384 bytes",
            ));
        }
    }
    diagnostics
}

fn validate_source_domain(
    payload: &std::collections::BTreeMap<crate::typed::Symbol, crate::typed::Value>,
    path: &crate::problem::Path,
) -> Vec<crate::problem::Diagnostic> {
    let mut diagnostics = Vec::with_capacity(6);
    let acquisition = payload
        .get(&crate::typed::Symbol::from("acquisition"))
        .map(|value| crate::lineage::Acquisition::from_value(value, &path.field("acquisition")));
    let acquisition = match acquisition {
        Some(Ok(acquisition)) => Some(acquisition),
        Some(Err(diagnostic)) => {
            diagnostics.push(diagnostic);
            None
        }
        None => None,
    };
    let correction = payload.get(&crate::typed::Symbol::from("correction"));
    let has_correction = correction.is_some();
    if let Some(correction) = correction
        && let Err(diagnostic) =
            crate::lineage::CorrectionProvenance::from_value(correction, &path.field("correction"))
    {
        diagnostics.push(diagnostic);
    }
    if acquisition
        .is_some_and(|value| (value == crate::lineage::Acquisition::Corrected) != has_correction)
    {
        diagnostics.push(domain_error(
            &path.field("correction"),
            "corrected acquisition requires correction provenance; other acquisitions must not carry it",
        ));
    }
    if acquisition == Some(crate::lineage::Acquisition::Derived) {
        diagnostics.extend(validate_derived_acquisition(payload, path));
    }
    if let Some(reference) = payload.get(&crate::typed::Symbol::from("derived-from"))
        && crate::lineage::SourcePin::from_value(reference, &path.field("derived-from")).is_err()
    {
        diagnostics.push(domain_error(
            &path.field("derived-from"),
            "a source transformation must pin its exact parent source revision",
        ));
    }
    if payload.contains_key(&crate::typed::Symbol::from("media-transform"))
        && !payload.contains_key(&crate::typed::Symbol::from("derived-from"))
    {
        diagnostics.push(domain_error(
            &path.field("media-transform"),
            "a media transform requires an exact derived-from source pin",
        ));
    }
    diagnostics.extend(validate_page_media(payload, path));
    diagnostics
}

/// A derived source pins its upstream through `derived-from`, which must be
/// the exact revision its acquisition names.
fn validate_derived_acquisition(
    payload: &std::collections::BTreeMap<crate::typed::Symbol, crate::typed::Value>,
    path: &crate::problem::Path,
) -> Vec<crate::problem::Diagnostic> {
    let named = payload
        .get(&crate::typed::Symbol::from("acquisition"))
        .and_then(|value| {
            crate::lineage::DerivedAcquisition::from_value(value, &path.field("acquisition")).ok()
        });
    let pinned = payload
        .get(&crate::typed::Symbol::from("derived-from"))
        .and_then(|value| {
            crate::lineage::SourcePin::from_value(value, &path.field("derived-from")).ok()
        });
    match (named, pinned) {
        (Some(named), Some(pinned)) if named.source() != pinned => vec![domain_error(
            &path.field("derived-from"),
            "derived-from must equal the source named by the derived acquisition",
        )],
        (Some(_), None) => vec![domain_error(
            &path.field("derived-from"),
            "a derived acquisition requires an exact derived-from source pin",
        )],
        _ => Vec::new(),
    }
}

/// A page frame belongs to a page or ink source, and an ink inventory to an
/// ink source whose pages cover every layer it declares.
fn validate_page_media(
    payload: &std::collections::BTreeMap<crate::typed::Symbol, crate::typed::Value>,
    path: &crate::problem::Path,
) -> Vec<crate::problem::Diagnostic> {
    let extent = payload
        .get(&crate::typed::Symbol::from("media-extent"))
        .and_then(|value| {
            crate::lineage::MediaExtent::from_value(value, &path.field("media-extent")).ok()
        });
    let page_count = match extent {
        Some(
            crate::lineage::MediaExtent::Pages { page_count }
            | crate::lineage::MediaExtent::InkPages { page_count },
        ) => Some(page_count),
        Some(crate::lineage::MediaExtent::Audio { .. }) | None => None,
    };
    let mut diagnostics = Vec::new();
    if payload.contains_key(&crate::typed::Symbol::from("media-frame")) && page_count.is_none() {
        diagnostics.push(domain_error(
            &path.field("media-frame"),
            "a page frame requires a page or ink media extent",
        ));
    }
    if let Some(value) = payload.get(&crate::typed::Symbol::from("ink-strokes")) {
        let is_ink = matches!(extent, Some(crate::lineage::MediaExtent::InkPages { .. }));
        let is_covered =
            crate::lineage::InkInventory::from_value(value, &path.field("ink-strokes"))
                .ok()
                .and_then(|inventory| inventory.last_page())
                .is_none_or(|last| page_count.is_some_and(|count| last < count));
        if !(is_ink && is_covered) {
            diagnostics.push(domain_error(
                &path.field("ink-strokes"),
                "an ink inventory requires an ink extent covering its pages",
            ));
        }
    }
    diagnostics
}

fn validate_recognition_run_domain(
    payload: &std::collections::BTreeMap<crate::typed::Symbol, crate::typed::Value>,
    path: &crate::problem::Path,
) -> Vec<crate::problem::Diagnostic> {
    let mut diagnostics = Vec::with_capacity(9);
    for name in [
        "model",
        "runtime",
        "adapter",
        "preprocessing",
        "configuration",
    ] {
        if let Some(value) = payload.get(&crate::typed::Symbol::from(name))
            && value
                .as_string()
                .is_none_or(|text| text.trim().is_empty() || text.len() > 4096)
        {
            diagnostics.push(domain_error(
                &path.field(name),
                "recognition identity must be non-empty text of at most 4096 bytes",
            ));
        }
    }
    if let (Some(status), Some(coverage)) = (
        payload.get(&crate::typed::Symbol::from("status")),
        payload.get(&crate::typed::Symbol::from("coverage")),
    ) {
        let parsed_status = status
            .as_symbol()
            .and_then(|symbol| crate::lineage::RecognitionStatus::parse(symbol.as_str()));
        let parsed_coverage =
            crate::lineage::RecognitionCoverage::from_value(coverage, &path.field("coverage"));
        match (parsed_status, parsed_coverage) {
            (Some(status), Ok(coverage)) => {
                if let Err(message) = status.validate_coverage(coverage) {
                    diagnostics.push(domain_error(&path.field("status"), message));
                }
                diagnostics.extend(validate_run_page(payload, (coverage, status), path));
            }
            (None, _) => diagnostics.push(domain_error(
                &path.field("status"),
                "recognition status must be complete, partial, failed, unsupported, or cancelled",
            )),
            (_, Err(diagnostic)) => diagnostics.push(diagnostic),
        }
    }
    for name in ["input", "output"] {
        if let Some(value) = payload.get(&crate::typed::Symbol::from(name))
            && crate::lineage::SourcePin::from_value(value, &path.field(name)).is_err()
        {
            diagnostics.push(domain_error(
                &path.field(name),
                "recognition run must pin the exact source revision",
            ));
        }
    }
    diagnostics
}

fn validate_run_page(
    payload: &std::collections::BTreeMap<crate::typed::Symbol, crate::typed::Value>,
    result: (crate::RecognitionCoverage, crate::RecognitionStatus),
    path: &crate::Path,
) -> Vec<crate::Diagnostic> {
    let Some(value) = payload.get(&crate::Symbol::from("page")) else {
        return Vec::new();
    };
    let page = match crate::RecognitionPage::from_value(value, &path.field("page")) {
        Ok(page) => page,
        Err(error) => return vec![error],
    };
    let Some(segments) = payload
        .get(&crate::Symbol::from("segments"))
        .and_then(crate::Value::as_set)
    else {
        return vec![domain_error(
            &path.field("segments"),
            "a page run needs its segment set",
        )];
    };
    let covers = match payload.get(&crate::Symbol::from("covers")) {
        Some(value) => match crate::CapturePart::from_value(value, &path.field("covers")) {
            Ok(covers) => covers,
            Err(error) => return vec![error],
        },
        None => crate::CapturePart::Whole,
    };
    let Ok(segment_count) = u64::try_from(segments.len()) else {
        return vec![domain_error(
            &path.field("segments"),
            "a page run's segment set exceeds its bound",
        )];
    };
    match page.validate_result(result, covers, segment_count) {
        Ok(()) => Vec::new(),
        Err(message) => vec![domain_error(&path.field("page"), message)],
    }
}

fn validate_recognition_segment_domain(
    payload: &std::collections::BTreeMap<crate::typed::Symbol, crate::typed::Value>,
    path: &crate::problem::Path,
) -> Vec<crate::problem::Diagnostic> {
    let mut diagnostics = Vec::with_capacity(3);
    for name in ["text-source", "media-source"] {
        if let Some(value) = payload.get(&crate::typed::Symbol::from(name))
            && crate::lineage::SourcePin::from_value(value, &path.field(name)).is_err()
        {
            diagnostics.push(domain_error(
                &path.field(name),
                "recognition segment must pin the exact source revision",
            ));
        }
    }
    if let Some(value) = payload.get(&crate::typed::Symbol::from("location"))
        && let Err(diagnostic) =
            crate::lineage::MediaLocation::from_value(value, &path.field("location"))
    {
        diagnostics.push(diagnostic);
    }
    diagnostics
}

fn domain_error(path: &crate::problem::Path, message: &str) -> crate::problem::Diagnostic {
    crate::problem::Diagnostic::new(
        crate::problem::Stage::Domain,
        crate::problem::ErrorCode::TypeMismatch,
        path.clone(),
        message,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_one_declares_every_kind() {
        let schema = RecordSchema::v1();
        assert_eq!(schema.version(), 1);
        let later = [
            RecordKind::Decision,
            RecordKind::DocumentBinding,
            RecordKind::DocumentAnchor,
            RecordKind::Comment,
            RecordKind::RecognitionRun,
            RecordKind::RecognitionSegment,
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
    fn production_registry_preserves_prior_versions_and_adds_media_v5_and_derived_v6() {
        let registry = SchemaRegistry::production();
        assert_eq!(registry.supported_versions(), vec![1, 2, 3, 4, 5, 6]);
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
        let source = registry
            .schema(5)
            .and_then(|schema| schema.kind(RecordKind::SourceRevision))
            .expect("source v5");
        assert_eq!(
            source.field("acquisition").expect("acquisition").ty,
            FieldType::Acquisition
        );
        assert_eq!(
            source.field("derived-from").expect("parent").ty,
            FieldType::Reference {
                kind: Some(RecordKind::SourceRevision),
                allow_external: false,
                allow_unresolved: false,
            }
        );
        assert!(
            registry
                .schema(4)
                .and_then(|schema| schema.kind(RecordKind::RecognitionRun))
                .is_none()
        );
        assert!(
            registry
                .schema(5)
                .and_then(|schema| schema.kind(RecordKind::RecognitionRun))
                .is_some()
        );
        let legacy_source = registry
            .schema(4)
            .and_then(|schema| schema.kind(RecordKind::SourceRevision))
            .expect("source v4");
        assert_eq!(
            legacy_source
                .field("acquisition")
                .expect("legacy acquisition")
                .ty,
            FieldType::Symbol
        );
        assert!(
            registry
                .schema(4)
                .and_then(|schema| schema.kind(RecordKind::Comment))
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
    fn production_registry_roundtrips_legacy_source_revisions() {
        let registry = SchemaRegistry::production();
        let source = crate::fixtures::source_revision();
        crate::wire::validate_record_value(&source.to_value(), &registry, None)
            .expect("legacy source validates under the production registry");
        let decoded =
            crate::wire::RecordEnvelope::from_value_with_registry(&source.to_value(), &registry)
                .expect("legacy source decodes");
        assert_eq!(decoded, source);
        assert_eq!(decoded.schema_version, 1);
        assert_eq!(decoded.payload, source.payload);
    }

    #[test]
    fn a_legacy_source_keeps_an_acquisition_symbol_outside_the_closed_set() {
        let registry = SchemaRegistry::production();
        let mut source = crate::fixtures::source_revision();
        let mut payload = source.payload.as_map().clone();
        payload.insert(
            crate::typed::Symbol::from("acquisition"),
            crate::typed::Value::symbol("scanned-by-peer"),
        );
        source.payload = crate::wire::Payload::new(payload);
        crate::wire::validate_record_value(&source.to_value(), &registry, None)
            .expect("a v1 source may declare any acquisition symbol");
        source.schema_version = crate::lineage::ACQUISITION_SCHEMA_VERSION;
        assert!(
            crate::wire::validate_record_value(&source.to_value(), &registry, None).is_err(),
            "a v5 source must declare a closed acquisition class"
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

    #[test]
    fn lifecycle_converts_to_the_kernel_state() {
        for (lifecycle, kernel) in [
            (
                Lifecycle::Proposed,
                mneme_kernel::claim::Lifecycle::Proposed,
            ),
            (
                Lifecycle::Accepted,
                mneme_kernel::claim::Lifecycle::Accepted,
            ),
            (
                Lifecycle::Disputed,
                mneme_kernel::claim::Lifecycle::Disputed,
            ),
            (
                Lifecycle::Superseded,
                mneme_kernel::claim::Lifecycle::Superseded,
            ),
            (
                Lifecycle::Retracted,
                mneme_kernel::claim::Lifecycle::Retracted,
            ),
        ] {
            assert_eq!(lifecycle.to_kernel(), kernel, "{}", lifecycle.symbol());
        }
    }

    #[test]
    fn malformed_extraction_is_refused_by_the_assertion_schema() {
        let registry = SchemaRegistry::production();
        let assertion = registry
            .schema(2)
            .and_then(|schema| schema.kind(RecordKind::Assertion))
            .expect("assertion v2");
        let extraction = assertion.field("extraction").expect("extraction");
        assert_eq!(extraction.ty, FieldType::Extraction);
        let path = crate::problem::Path::root();

        // A free-text model note is not an extraction record.
        let note = crate::typed::Value::string("free-text model note");
        let error = validate_field(extraction.ty, &note, &path, None);
        assert_eq!(error[0].code, crate::problem::ErrorCode::TypeMismatch);

        // The declared label with a non-string prompt is refused at that field.
        let wrong_prompt = crate::typed::Value::record_named(
            "extraction",
            vec![
                crate::typed::Value::string("model"),
                crate::typed::Value::integer(1_i64),
            ],
        );
        let error = validate_field(extraction.ty, &wrong_prompt, &path, None);
        assert_eq!(error.len(), 1);
        assert_eq!(error[0].code, crate::problem::ErrorCode::TypeMismatch);
        assert_eq!(error[0].path.to_string(), "$[1]");

        // The shape every consumer parses stays valid.
        let valid = crate::typed::Value::record_named(
            "extraction",
            vec![
                crate::typed::Value::string("model"),
                crate::typed::Value::string("prompt"),
            ],
        );
        assert!(validate_field(extraction.ty, &valid, &path, None).is_empty());
    }

    #[test]
    fn malformed_include_map_is_refused_by_the_document_schema() {
        let registry = SchemaRegistry::production();
        let document = registry
            .schema(3)
            .and_then(|schema| schema.kind(RecordKind::Document))
            .expect("document v3");
        let includes = document.field("includes").expect("includes");
        assert_eq!(includes.ty, FieldType::IncludeMap);
        let path = crate::problem::Path::root();

        let pin = pinned_source(RecordKind::SourceRevision);
        let valid = include_entry("chapters/one.adoc", pin);
        assert!(validate_field(includes.ty, &valid, &path, None).is_empty());

        // An integer is not a reference to pinned bytes.
        let untyped = include_entry("x.adoc", crate::typed::Value::integer(1_i64));
        let error = validate_field(includes.ty, &untyped, &path, None);
        assert_eq!(error[0].path.to_string(), "$[\"x.adoc\"]");

        // A snapshot-local reference does not pin the bytes that were included.
        let source = crate::ids::RecordId::from_bytes([2; 16]);
        let local_reference = crate::pointer::Reference::local(source, RecordKind::SourceRevision);
        let local = include_entry("x.adoc", local_reference.to_value());
        let error = validate_field(includes.ty, &local, &path, None);
        assert_eq!(error[0].code, crate::problem::ErrorCode::TypeMismatch);

        // A pin of the wrong kind cannot be an included source revision.
        let wrong_pin = pinned_source(RecordKind::Entity);
        let wrong_kind = include_entry("x.adoc", wrong_pin);
        let error = validate_field(includes.ty, &wrong_kind, &path, None);
        assert_eq!(
            error[0].code,
            crate::problem::ErrorCode::ReferenceKindMismatch
        );
    }

    fn include_entry(path: &str, value: crate::typed::Value) -> crate::typed::Value {
        let key = crate::typed::Value::string(path);
        crate::typed::Value::dictionary([(key, value)])
    }

    fn pinned_source(revision_kind: RecordKind) -> crate::typed::Value {
        let source = crate::ids::RecordId::from_bytes([2; 16]);
        let revision = crate::ids::RevisionId::from_bytes([3; 16]);
        let reference = crate::pointer::Reference::pinned(source, revision, revision_kind);
        reference.to_value()
    }

    #[test]
    fn earlier_versions_use_the_type_a_later_version_declares() {
        let registry = SchemaRegistry::production();
        let extraction = registry
            .later_field(RecordKind::Assertion, "extraction", 1)
            .expect("version 2 declares extraction");
        assert_eq!(extraction.ty, FieldType::Extraction);
        // The declared name is static, so diagnostics address the field the
        // same way a record of the declaring version does.
        assert_eq!(extraction.name, "extraction");
        let includes = registry
            .later_field(RecordKind::Document, "includes", 1)
            .expect("version 3 declares includes");
        assert_eq!(includes.ty, FieldType::IncludeMap);
        assert_eq!(includes.name, "includes");
        // A name no version declares stays a plain retained extension.
        assert_eq!(
            registry.later_field(RecordKind::Assertion, "x-ext", 1),
            None
        );
        // Nothing is later than the newest registered schema.
        assert_eq!(
            registry.later_field(RecordKind::Document, "includes", 6),
            None
        );
    }
}

#[cfg(test)]
mod remark_tests {
    use super::*;

    fn payload(
        status: &str,
        text: &str,
    ) -> std::collections::BTreeMap<crate::typed::Symbol, crate::typed::Value> {
        let mut map = std::collections::BTreeMap::new();
        map.insert(
            crate::typed::Symbol::from("actor"),
            crate::typed::Value::string("alice"),
        );
        map.insert(
            crate::typed::Symbol::from("document"),
            crate::pointer::Reference::local(
                crate::ids::RecordId::from_bytes([1; 16]),
                RecordKind::Document,
            )
            .to_value(),
        );
        map.insert(
            crate::typed::Symbol::from("source-revision"),
            crate::pointer::Reference::local(
                crate::ids::RecordId::from_bytes([2; 16]),
                RecordKind::SourceRevision,
            )
            .to_value(),
        );
        map.insert(
            crate::typed::Symbol::from("text"),
            crate::typed::Value::string(text),
        );
        map.insert(
            crate::typed::Symbol::from("status"),
            crate::typed::Value::symbol(status),
        );
        map
    }

    #[test]
    fn valid_comment_passes_domain_validation() {
        let path = crate::problem::Path::root();
        for status in ["proposed", "open", "resolved", "dismissed"] {
            let p = payload(status, "hello");
            let diagnostics = validate_domain(RecordKind::Comment, 5, &p, &path.field("payload"));
            assert!(diagnostics.is_empty(), "{status}: {diagnostics:?}");
        }
    }

    #[test]
    fn unknown_status_is_refused() {
        let p = payload("bogus", "hello");
        let path = crate::problem::Path::root();
        let diagnostics = validate_domain(RecordKind::Comment, 5, &p, &path.field("payload"));
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].path.to_string(), "$.payload.status");
    }

    #[test]
    fn empty_text_is_refused() {
        let p = payload("open", "");
        let path = crate::problem::Path::root();
        let diagnostics = validate_domain(RecordKind::Comment, 5, &p, &path.field("payload"));
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].path.to_string(), "$.payload.text");
    }

    #[test]
    fn oversized_text_is_refused() {
        let big = "a".repeat(16385);
        let p = payload("open", &big);
        let path = crate::problem::Path::root();
        let diagnostics = validate_domain(RecordKind::Comment, 5, &p, &path.field("payload"));
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].path.to_string(), "$.payload.text");
    }
}
