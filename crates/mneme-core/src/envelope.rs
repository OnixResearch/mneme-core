//! Versioned record envelopes, payloads, and validation.
//!
//! An envelope identifies the schema version, kind, stable record identity,
//! immutable revision, optional predecessor, scope, recorded transaction time,
//! and typed payload. Validation has distinct syntax, envelope, and domain
//! stages, reports field-addressed diagnostics, and never changes an assertion's
//! epistemic lifecycle.

use std::collections::{BTreeMap, BTreeSet};

use crate::digest::ContentDigest;
use crate::error::{Diagnostic, ErrorCode, Path, Stage};
use crate::ids::{RecordId, RevisionId};
use crate::reference::SnapshotIndex;
use crate::schema::{
    ExtensionPolicy, Lifecycle, RecordKind, SchemaRegistry, validate_domain, validate_field,
};
use crate::scope::ScopeId;
use crate::time::RecordedTime;
use crate::value::{Symbol, Value};

/// The label of a durable Mneme record envelope.
pub const RECORD_LABEL: &str = "mneme-record";
/// The production schema version this build writes.
pub const PRODUCTION_SCHEMA_VERSION: u32 = 1;

/// A typed payload: an ordinary dictionary keyed by declared field symbols.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Payload {
    fields: BTreeMap<Symbol, Value>,
}

impl Payload {
    /// Construct from symbol-keyed entries.
    pub fn new(entries: impl IntoIterator<Item = (Symbol, Value)>) -> Self {
        Payload {
            fields: entries.into_iter().collect(),
        }
    }

    /// A payload field by name.
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.fields.get(&Symbol::from(name))
    }

    /// Whether a field is present.
    pub fn contains(&self, name: &str) -> bool {
        self.fields.contains_key(&Symbol::from(name))
    }

    /// Insert or replace a field.
    pub fn insert(&mut self, name: impl Into<Symbol>, value: Value) -> Option<Value> {
        self.fields.insert(name.into(), value)
    }

    /// Remove a field.
    pub fn remove(&mut self, name: &str) -> Option<Value> {
        self.fields.remove(&Symbol::from(name))
    }

    /// The number of fields.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether the payload has no fields.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// The sorted fields.
    pub fn as_map(&self) -> &BTreeMap<Symbol, Value> {
        &self.fields
    }

    /// Field names in canonical order.
    pub fn names(&self) -> impl Iterator<Item = &Symbol> {
        self.fields.keys()
    }

    /// Encode as a symbol-keyed dictionary.
    pub fn to_value(&self) -> Value {
        Value::dictionary(
            self.fields
                .iter()
                .map(|(key, value)| (Value::Symbol(key.clone()), value.clone())),
        )
    }

    /// Decode a symbol-keyed dictionary.
    pub fn from_value(value: &Value, path: &Path) -> Result<Self, Diagnostic> {
        let type_error = || {
            Diagnostic::new(
                Stage::Envelope,
                ErrorCode::TypeMismatch,
                path.clone(),
                "payload must be a dictionary with symbol field names",
            )
        };
        let entries = value.as_dictionary().ok_or_else(type_error)?;
        let mut fields = BTreeMap::new();
        for (key, item) in entries {
            let Some(symbol) = key.as_symbol() else {
                return Err(Diagnostic::new(
                    Stage::Envelope,
                    ErrorCode::TypeMismatch,
                    path.clone(),
                    "payload field names must be declared symbols",
                ));
            };
            fields.insert(symbol.clone(), item.clone());
        }
        Ok(Payload { fields })
    }
}

/// A durable record envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordEnvelope {
    pub schema_version: u32,
    pub kind: RecordKind,
    pub record_id: RecordId,
    pub revision_id: RevisionId,
    pub predecessor: Option<RevisionId>,
    pub scope: ScopeId,
    pub recorded: RecordedTime,
    pub payload: Payload,
}

impl RecordEnvelope {
    /// Encode the envelope as `<mneme-record …>`.
    pub fn to_value(&self) -> Value {
        let predecessor = match self.predecessor {
            Some(revision) => revision.to_value(),
            None => Value::symbol("none"),
        };
        Value::record_named(
            RECORD_LABEL,
            vec![
                Value::integer(i64::from(self.schema_version)),
                self.kind.to_value(),
                self.record_id.to_value(),
                self.revision_id.to_value(),
                predecessor,
                self.scope.to_value(),
                self.recorded.to_value(),
                self.payload.to_value(),
            ],
        )
    }

    /// Decode envelope structure. Schema and domain validation follow in
    /// [`validate_record`].
    pub fn from_value(value: &Value) -> Result<Self, Vec<Diagnostic>> {
        let mut diagnostics = Vec::new();
        let Some(record) = value.as_record() else {
            return Err(vec![Diagnostic::new(
                Stage::Envelope,
                ErrorCode::TypeMismatch,
                Path::root(),
                format!("expected <{RECORD_LABEL} …>"),
            )]);
        };
        if record.label() != &Value::symbol(RECORD_LABEL) {
            return Err(vec![Diagnostic::new(
                Stage::Envelope,
                ErrorCode::TypeMismatch,
                Path::root(),
                format!("expected <{RECORD_LABEL} …>"),
            )]);
        }
        if value.contains_embedded() {
            return Err(vec![Diagnostic::new(
                Stage::Envelope,
                ErrorCode::EmbeddedValueNotDurable,
                Path::root(),
                "durable records must not contain live embedded values",
            )]);
        }
        if record.fields().len() != 8 {
            return Err(vec![Diagnostic::new(
                Stage::Envelope,
                ErrorCode::MalformedEncoding,
                Path::root(),
                format!(
                    "envelope must have 8 fields, found {}",
                    record.fields().len()
                ),
            )]);
        }
        let schema_version = match unsigned(&record.fields()[0]) {
            Some(version) => match u32::try_from(version) {
                Ok(version) => version,
                Err(_) => {
                    diagnostics.push(Diagnostic::new(
                        Stage::Envelope,
                        ErrorCode::UnsupportedSchemaVersion,
                        Path::root().field("schema-version"),
                        "schema version exceeds the supported integer range",
                    ));
                    0
                }
            },
            None => {
                diagnostics.push(Diagnostic::new(
                    Stage::Envelope,
                    ErrorCode::UnsupportedSchemaVersion,
                    Path::root().field("schema-version"),
                    "schema version must be a non-negative integer",
                ));
                0
            }
        };
        let kind = match RecordKind::from_value(&record.fields()[1], &Path::root().field("kind")) {
            Ok(kind) => Some(kind),
            Err(diagnostic) => {
                diagnostics.push(diagnostic);
                None
            }
        };
        let record_id = push_id(
            RecordId::from_value(&record.fields()[2], &Path::root().field("record-id")),
            &mut diagnostics,
        );
        let revision_id = push_id(
            RevisionId::from_value(&record.fields()[3], &Path::root().field("revision-id")),
            &mut diagnostics,
        );
        let predecessor = match &record.fields()[4] {
            Value::Symbol(symbol) if symbol.as_str() == "none" => Some(None),
            other => match RevisionId::from_value(other, &Path::root().field("predecessor")) {
                Ok(revision) => Some(Some(revision)),
                Err(diagnostic) => {
                    diagnostics.push(diagnostic);
                    None
                }
            },
        };
        let scope = match ScopeId::from_value(&record.fields()[5], &Path::root().field("scope")) {
            Ok(scope) => Some(scope),
            Err(diagnostic) => {
                diagnostics.push(diagnostic);
                None
            }
        };
        let recorded = match RecordedTime::from_value(
            &record.fields()[6],
            &Path::root().field("recorded-time"),
        ) {
            Ok(recorded) => Some(recorded),
            Err(diagnostic) => {
                diagnostics.push(diagnostic);
                None
            }
        };
        let payload = match Payload::from_value(&record.fields()[7], &Path::root().field("payload"))
        {
            Ok(payload) => Some(payload),
            Err(diagnostic) => {
                diagnostics.push(diagnostic);
                None
            }
        };
        match (
            kind,
            record_id,
            revision_id,
            predecessor,
            scope,
            recorded,
            payload,
        ) {
            (
                Some(kind),
                Some(record_id),
                Some(revision_id),
                Some(predecessor),
                Some(scope),
                Some(recorded),
                Some(payload),
            ) if diagnostics.is_empty() => Ok(RecordEnvelope {
                schema_version,
                kind,
                record_id,
                revision_id,
                predecessor,
                scope,
                recorded,
                payload,
            }),
            _ => Err(diagnostics),
        }
    }

    /// The assertion lifecycle, when this is an assertion carrying one.
    pub fn assertion_lifecycle(&self) -> Option<Lifecycle> {
        if self.kind != RecordKind::Assertion {
            return None;
        }
        self.payload
            .get("lifecycle")
            .and_then(Value::as_symbol)
            .and_then(|symbol| Lifecycle::parse(symbol.as_str()))
    }

    /// Digest of the complete envelope, including identity and provenance.
    pub fn full_digest(&self) -> ContentDigest {
        ContentDigest::of_full_record(&self.to_value())
    }

    /// Digest of only the payload.
    pub fn payload_digest(&self) -> ContentDigest {
        ContentDigest::of_payload(&self.payload.to_value())
    }
}

fn push_id<T>(result: Result<T, Diagnostic>, diagnostics: &mut Vec<Diagnostic>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            None
        }
    }
}

fn unsigned(value: &Value) -> Option<u64> {
    use num_traits::ToPrimitive;
    value
        .as_integer()
        .and_then(|integer| integer.as_bigint().to_u64())
}

/// The indexes and schema used to validate one record.
///
/// `resolution` supplies targets for references, including the batch's own
/// records. `prior` describes the snapshot before this batch and decides
/// replacement lineage. Both are absent when only structure is checked.
#[derive(Clone, Copy, Debug)]
pub struct RecordContext<'a> {
    pub registry: &'a SchemaRegistry,
    pub resolution: Option<&'a SnapshotIndex>,
    pub prior: Option<&'a SnapshotIndex>,
}

impl<'a> RecordContext<'a> {
    /// Context for validating one record in isolation.
    pub fn isolated(registry: &'a SchemaRegistry) -> Self {
        RecordContext {
            registry,
            resolution: None,
            prior: None,
        }
    }

    /// Context for validating one record against an existing snapshot.
    pub fn against(registry: &'a SchemaRegistry, snapshot: &'a SnapshotIndex) -> Self {
        RecordContext {
            registry,
            resolution: Some(snapshot),
            prior: Some(snapshot),
        }
    }
}

/// Validate one envelope against a schema registry and snapshot contexts.
pub fn validate_record(
    envelope: &RecordEnvelope,
    context: &RecordContext<'_>,
    path: &Path,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    if envelope.predecessor == Some(envelope.revision_id) {
        diagnostics.push(Diagnostic::new(
            Stage::Envelope,
            ErrorCode::InvalidPredecessor,
            path.field("predecessor"),
            "a revision cannot be its own predecessor",
        ));
    }
    if let Some(prior) = context.prior {
        match prior.get(&envelope.record_id) {
            Some(entry) => {
                if entry.kind != envelope.kind {
                    diagnostics.push(Diagnostic::new(
                        Stage::Envelope,
                        ErrorCode::InvalidPredecessor,
                        path.field("kind"),
                        format!(
                            "record kind cannot change between revisions ({} became {})",
                            entry.kind.symbol(),
                            envelope.kind.symbol()
                        ),
                    ));
                }
                if envelope.predecessor != Some(entry.revision) {
                    diagnostics.push(Diagnostic::new(
                        Stage::Envelope,
                        ErrorCode::InvalidPredecessor,
                        path.field("predecessor"),
                        format!(
                            "replacement must name predecessor revision {}",
                            entry.revision
                        ),
                    ));
                }
            }
            None => {
                if envelope.predecessor.is_some() {
                    diagnostics.push(Diagnostic::new(
                        Stage::Envelope,
                        ErrorCode::InvalidPredecessor,
                        path.field("predecessor"),
                        "a new record cannot name a predecessor revision",
                    ));
                }
            }
        }
    }

    let Some(schema) = context.registry.schema(envelope.schema_version) else {
        diagnostics.push(Diagnostic::new(
            Stage::Envelope,
            ErrorCode::UnsupportedSchemaVersion,
            path.field("schema-version"),
            format!(
                "schema version {} is not registered; supported versions: {:?}",
                envelope.schema_version,
                context.registry.supported_versions()
            ),
        ));
        return diagnostics;
    };
    let Some(kind_schema) = schema.kind(envelope.kind) else {
        diagnostics.push(Diagnostic::new(
            Stage::Envelope,
            ErrorCode::UnknownRecordKind,
            path.field("kind"),
            format!(
                "record kind {} is not declared by schema version {}",
                envelope.kind.symbol(),
                schema.version()
            ),
        ));
        return diagnostics;
    };

    for field in kind_schema.fields() {
        let field_path = path.field("payload").field(field.name);
        match envelope.payload.get(field.name) {
            None if field.required => diagnostics.push(Diagnostic::new(
                Stage::Domain,
                ErrorCode::MissingField,
                field_path,
                format!("required field {} is absent", field.name),
            )),
            None => {}
            Some(value) => diagnostics.extend(validate_field(
                field.ty,
                value,
                &field_path,
                context.resolution,
            )),
        }
    }
    if kind_schema.extensions() == ExtensionPolicy::Refuse {
        for name in envelope.payload.names() {
            if kind_schema.field(name.as_str()).is_none() {
                diagnostics.push(Diagnostic::new(
                    Stage::Domain,
                    ErrorCode::UnsupportedExtension,
                    path.field("payload").named(name.as_str()),
                    format!("field {} is not declared and extensions are refused", name),
                ));
            }
        }
    }
    diagnostics.extend(validate_domain(
        envelope.kind,
        envelope.payload.as_map(),
        &path.field("payload"),
    ));
    diagnostics
}

/// Validate one encoded envelope value.
pub fn validate_record_value(
    value: &Value,
    registry: &SchemaRegistry,
    index: Option<&SnapshotIndex>,
) -> Result<RecordEnvelope, Vec<Diagnostic>> {
    let envelope = RecordEnvelope::from_value(value)?;
    let context = match index {
        Some(snapshot) => RecordContext::against(registry, snapshot),
        None => RecordContext::isolated(registry),
    };
    let diagnostics = validate_record(&envelope, &context, &Path::root());
    if diagnostics.is_empty() {
        Ok(envelope)
    } else {
        Err(diagnostics)
    }
}

/// A validated set of records and the snapshot index they establish.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedBatch {
    pub records: Vec<RecordEnvelope>,
    pub index: SnapshotIndex,
}

/// Validate a batch as one committed snapshot.
///
/// Every record is structurally parsed first so references may resolve within
/// the batch. Records already present in the optional external index are
/// replacements: they must name the indexed revision as their predecessor.
pub fn validate_batch(
    values: &[Value],
    registry: &SchemaRegistry,
    external_index: Option<&SnapshotIndex>,
) -> Result<ValidatedBatch, Vec<Diagnostic>> {
    let mut diagnostics = Vec::new();
    let mut envelopes = Vec::new();
    for (position, value) in values.iter().enumerate() {
        match RecordEnvelope::from_value(value) {
            Ok(envelope) => envelopes.push(envelope),
            Err(record_diagnostics) => {
                let prefix = Path::root().index(position);
                diagnostics.extend(record_diagnostics.into_iter().map(|mut diagnostic| {
                    diagnostic.path = rebase(diagnostic.path, &prefix);
                    diagnostic
                }));
            }
        }
    }
    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }

    // Detect duplicate identities inside one batch before building its index.
    let mut record_ids = BTreeMap::new();
    let mut revision_ids = BTreeSet::new();
    let mut seen_records = BTreeSet::new();
    for (position, envelope) in envelopes.iter().enumerate() {
        let prefix = Path::root().index(position);
        if !seen_records.insert(envelope.record_id) {
            diagnostics.push(Diagnostic::new(
                Stage::Envelope,
                ErrorCode::DuplicateRecordId,
                prefix.clone().field("record-id"),
                format!(
                    "record {} appears more than once in one batch",
                    envelope.record_id
                ),
            ));
        } else {
            record_ids.insert(envelope.record_id, position);
        }
        if !revision_ids.insert(envelope.revision_id) {
            diagnostics.push(Diagnostic::new(
                Stage::Envelope,
                ErrorCode::DuplicateRevisionId,
                prefix.clone().field("revision-id"),
                format!(
                    "revision {} appears more than once in one batch",
                    envelope.revision_id
                ),
            ));
        }
    }
    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }

    let mut index = external_index.cloned().unwrap_or_default();
    for envelope in &envelopes {
        if index.get(&envelope.record_id).is_some() {
            index.upsert(envelope.record_id, envelope.kind, envelope.revision_id);
        } else {
            index.insert(envelope.record_id, envelope.kind, envelope.revision_id);
        }
    }

    let context = RecordContext {
        registry,
        resolution: Some(&index),
        prior: external_index,
    };
    for (position, envelope) in envelopes.iter().enumerate() {
        let prefix = Path::root().index(position);
        diagnostics.extend(validate_record(envelope, &context, &prefix));
    }
    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }
    Ok(ValidatedBatch {
        records: envelopes,
        index,
    })
}

fn rebase(path: Path, prefix: &Path) -> Path {
    let mut segments = prefix.segments().to_vec();
    segments.extend_from_slice(path.segments());
    Path::from_segments(segments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::ContentDigest;
    use crate::payload::SourceContent;
    use crate::reference::Reference;
    use crate::schema::{RecordSchema, SchemaRegistry};
    use crate::scope::ScopeClass;
    use crate::time::{Timestamp, ValidTime};

    fn record_id(byte: u8) -> RecordId {
        RecordId::from_bytes([byte; 16])
    }

    fn revision_id(byte: u8) -> RevisionId {
        RevisionId::from_bytes([byte; 16])
    }

    fn scope() -> ScopeId {
        ScopeId::new(ScopeClass::Project, "cedar").expect("scope")
    }

    fn recorded() -> RecordedTime {
        RecordedTime::new(Timestamp::from_nanos(1_000), 1)
    }

    fn entity() -> RecordEnvelope {
        RecordEnvelope {
            schema_version: 1,
            kind: RecordKind::Entity,
            record_id: record_id(1),
            revision_id: revision_id(1),
            predecessor: None,
            scope: scope(),
            recorded: recorded(),
            payload: Payload::new([
                (Symbol::from("entity-type"), Value::symbol("project")),
                (Symbol::from("label"), Value::string("Cedar Notes")),
                (Symbol::from("properties"), Value::dictionary([])),
            ]),
        }
    }

    fn source_revision() -> RecordEnvelope {
        RecordEnvelope {
            schema_version: 1,
            kind: RecordKind::SourceRevision,
            record_id: record_id(2),
            revision_id: revision_id(2),
            predecessor: None,
            scope: scope(),
            recorded: recorded(),
            payload: Payload::new([
                (
                    Symbol::from("content"),
                    SourceContent::Retained(
                        crate::payload::RetainedSource::new(
                            ContentDigest::of_source_bytes(b"= Cedar Notes\n"),
                            14,
                            "text/asciidoc",
                        )
                        .expect("retained"),
                    )
                    .to_value(),
                ),
                (Symbol::from("acquisition"), Value::symbol("authored")),
            ]),
        }
    }

    fn assertion(lifecycle: &str) -> RecordEnvelope {
        RecordEnvelope {
            schema_version: 1,
            kind: RecordKind::Assertion,
            record_id: record_id(3),
            revision_id: revision_id(3),
            predecessor: None,
            scope: scope(),
            recorded: recorded(),
            payload: Payload::new([
                (
                    Symbol::from("subject"),
                    Reference::local(record_id(1), RecordKind::Entity).to_value(),
                ),
                (Symbol::from("predicate"), Value::symbol("storage-engine")),
                (Symbol::from("value"), Value::string("SQLite")),
                (Symbol::from("stance"), Value::symbol("affirm")),
                (Symbol::from("lifecycle"), Value::symbol(lifecycle)),
                (Symbol::from("origin"), Value::symbol("authored-statement")),
                (
                    Symbol::from("asserted-by"),
                    Value::string("synthetic author"),
                ),
                (Symbol::from("valid-time"), ValidTime::Unknown.to_value()),
                (Symbol::from("evidence"), Value::set([])),
            ]),
        }
    }

    fn batch(records: &[RecordEnvelope]) -> Vec<Value> {
        records.iter().map(RecordEnvelope::to_value).collect()
    }

    #[test]
    fn valid_batch_resolves_references_and_keeps_proposed_lifecycle() {
        let values = batch(&[entity(), source_revision(), assertion("proposed")]);
        let validated = validate_batch(&values, &SchemaRegistry::v1(), None).expect("valid batch");
        let assertion = &validated.records[2];
        assert_eq!(assertion.assertion_lifecycle(), Some(Lifecycle::Proposed));
        assert!(!validated.index.is_empty());
    }

    #[test]
    fn accepted_lifecycle_is_preserved_but_never_inferred() {
        let proposed = assertion("proposed");
        let accepted = assertion("accepted");
        assert_eq!(proposed.assertion_lifecycle(), Some(Lifecycle::Proposed));
        assert_eq!(accepted.assertion_lifecycle(), Some(Lifecycle::Accepted));
        assert_ne!(proposed.full_digest(), accepted.full_digest());
    }

    #[test]
    fn unknown_schema_version_is_refused_at_the_version_field() {
        let mut record = entity();
        record.schema_version = 99;
        let error = validate_record_value(&record.to_value(), &SchemaRegistry::v1(), None)
            .expect_err("unsupported version");
        assert_eq!(error[0].code, ErrorCode::UnsupportedSchemaVersion);
        assert_eq!(error[0].path.to_string(), "$.schema-version");
    }

    #[test]
    fn unknown_kind_is_refused_at_the_kind_field() {
        let value = Value::record_named(
            RECORD_LABEL,
            vec![
                Value::integer(1_i64),
                Value::symbol("tenant"),
                record_id(1).to_value(),
                revision_id(1).to_value(),
                Value::symbol("none"),
                scope().to_value(),
                recorded().to_value(),
                Payload::default().to_value(),
            ],
        );
        let error = RecordEnvelope::from_value(&value).expect_err("unknown kind");
        assert_eq!(error[0].code, ErrorCode::UnknownRecordKind);
        assert_eq!(error[0].path.to_string(), "$.kind");
    }

    #[test]
    fn invalid_reference_kind_fails_the_batch() {
        let mut record = assertion("proposed");
        record.payload.insert(
            Symbol::from("subject"),
            Reference::local(record_id(1), RecordKind::Document).to_value(),
        );
        let error = validate_batch(&batch(&[entity(), record]), &SchemaRegistry::v1(), None)
            .expect_err("kind mismatch");
        assert!(
            error
                .iter()
                .any(|diagnostic| diagnostic.code == ErrorCode::ReferenceKindMismatch)
        );
    }

    #[test]
    fn unresolved_reference_fails_the_batch() {
        let mut record = assertion("proposed");
        record.payload.insert(
            Symbol::from("subject"),
            Reference::local(record_id(9), RecordKind::Entity).to_value(),
        );
        let error =
            validate_batch(&batch(&[record]), &SchemaRegistry::v1(), None).expect_err("unresolved");
        assert!(
            error
                .iter()
                .any(|diagnostic| diagnostic.code == ErrorCode::UnresolvedReference)
        );
    }

    #[test]
    fn embedded_values_are_refused_in_durable_records() {
        let mut record = entity();
        record.payload.insert(
            Symbol::from("properties"),
            Value::embedded(Value::string("live object")),
        );
        let error = validate_record_value(&record.to_value(), &SchemaRegistry::v1(), None)
            .expect_err("embedded");
        assert_eq!(error[0].code, ErrorCode::EmbeddedValueNotDurable);
    }

    #[test]
    fn replacement_requires_the_indexed_predecessor() {
        let original = entity();
        let mut index = SnapshotIndex::new();
        assert!(index.insert(original.record_id, original.kind, original.revision_id));
        let mut replacement = entity();
        replacement.revision_id = revision_id(7);
        replacement.predecessor = None;
        let registry = SchemaRegistry::v1();
        let context = RecordContext::against(&registry, &index);
        let error = validate_record(&replacement, &context, &Path::root());
        assert!(
            error
                .iter()
                .any(|diagnostic| diagnostic.code == ErrorCode::InvalidPredecessor)
        );
        replacement.predecessor = Some(original.revision_id);
        let validated = validate_record(&replacement, &context, &Path::root());
        assert!(validated.is_empty(), "{validated:?}");
    }

    #[test]
    fn full_record_digest_covers_identity_and_provenance() {
        let original = entity();
        let mut renamed = original.clone();
        renamed
            .payload
            .insert(Symbol::from("label"), Value::string("Cedar Notes v2"));
        assert_ne!(original.payload_digest(), renamed.payload_digest());
        assert_ne!(original.full_digest(), renamed.full_digest());

        let mut equal_payload_other_identity = original.clone();
        equal_payload_other_identity.record_id = record_id(8);
        equal_payload_other_identity.revision_id = revision_id(8);
        assert_eq!(
            original.payload_digest(),
            equal_payload_other_identity.payload_digest()
        );
        assert_ne!(
            original.full_digest(),
            equal_payload_other_identity.full_digest()
        );
        assert_eq!(
            ContentDigest::of_full_record(&original.to_value()),
            original.full_digest()
        );
    }

    #[test]
    fn extension_fields_are_retained_by_version_one() {
        let mut record = entity();
        record.payload.insert(
            Symbol::from("unrecognized-extension"),
            Value::set([Value::integer(1_i64)]),
        );
        let validated = validate_record_value(&record.to_value(), &SchemaRegistry::v1(), None)
            .expect("retained");
        assert!(validated.payload.contains("unrecognized-extension"));
    }

    #[test]
    fn provenance_changes_alter_the_digest_while_the_claim_text_stays_equal() {
        let base = assertion("proposed");
        let mut other_author = base.clone();
        other_author.payload.insert(
            Symbol::from("asserted-by"),
            Value::string("different attributed author"),
        );
        assert_eq!(
            base.payload.get("value"),
            other_author.payload.get("value"),
            "the asserted text is unchanged"
        );
        assert_ne!(base.payload_digest(), other_author.payload_digest());
        assert_ne!(base.full_digest(), other_author.full_digest());

        let mut later_recording = base.clone();
        later_recording.recorded = RecordedTime::new(Timestamp::from_nanos(9_999), 42);
        assert_eq!(
            base.payload_digest(),
            later_recording.payload_digest(),
            "recorded time is envelope provenance, not payload text"
        );
        assert_ne!(base.full_digest(), later_recording.full_digest());
        // The prior revision remains separately identifiable through lineage.
        let mut corrected = base.clone();
        corrected.revision_id = revision_id(99);
        corrected.predecessor = Some(base.revision_id);
        assert_eq!(corrected.predecessor, Some(base.revision_id));
        assert_ne!(base.full_digest(), corrected.full_digest());
    }

    #[test]
    fn synthetic_version_two_requires_the_new_field() {
        let registry = SchemaRegistry::v1().with_version(RecordSchema::synthetic_v2());
        let mut v2 = assertion("proposed");
        v2.schema_version = 2;
        let error = validate_record_value(&v2.to_value(), &registry, None)
            .expect_err("missing synthetic v2 field");
        assert!(
            error
                .iter()
                .any(|diagnostic| diagnostic.code == ErrorCode::MissingField
                    && diagnostic.path.to_string() == "$.payload.extraction")
        );
        v2.payload
            .insert(Symbol::from("extraction"), Value::string("synthetic"));
        validate_record_value(&v2.to_value(), &registry, None).expect("v2 assertion");

        // Version 1 records stay interpreted by version 1 even when a later
        // version is registered; the envelope version is the authority.
        validate_record_value(&assertion("proposed").to_value(), &registry, None)
            .expect("v1 record remains valid");
    }
}
