//! Versioned record envelopes, payloads, and validation.
//!
//! An envelope identifies the schema version, kind, stable record identity,
//! immutable revision, optional predecessor, scope, recorded transaction time,
//! and typed payload. Validation has distinct syntax, envelope, and domain
//! stages, reports field-addressed diagnostics, and never changes an assertion's
//! epistemic lifecycle.
#![allow(path_segment_repetition, unbounded_collection_growth)] // Octet structural exception: domain-qualified names and macro-only imports are intentional

/// The label of a durable Mneme record envelope.
pub const RECORD_LABEL: &str = "mneme-record";
/// The production schema version this build writes.
pub const PRODUCTION_SCHEMA_VERSION: u32 = 1;

/// A typed payload: an ordinary dictionary keyed by declared field symbols.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Payload {
    fields: std::collections::BTreeMap<crate::value::Symbol, crate::value::Value>,
}

impl Payload {
    /// Construct from symbol-keyed entries.
    pub fn new(
        entries: impl IntoIterator<Item = (crate::value::Symbol, crate::value::Value)>,
    ) -> Self {
        Payload {
            fields: entries.into_iter().collect(),
        }
    }

    /// A payload field by name.
    pub fn get(&self, name: &str) -> Option<&crate::value::Value> {
        self.fields.get(&crate::value::Symbol::from(name))
    }

    /// Whether a field is present.
    pub fn contains(&self, name: &str) -> bool {
        self.fields.contains_key(&crate::value::Symbol::from(name))
    }

    /// Insert or replace a field.
    pub fn insert(
        &mut self,
        name: impl Into<crate::value::Symbol>,
        value: crate::value::Value,
    ) -> Option<crate::value::Value> {
        self.fields.insert(name.into(), value)
    }

    /// Remove a field.
    pub fn remove(&mut self, name: &str) -> Option<crate::value::Value> {
        self.fields.remove(&crate::value::Symbol::from(name))
    }

    /// The number of fields.
    #[allow(unknown_lints, usize_in_public_api)] // std-shaped collection length
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether the payload has no fields.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// The sorted fields.
    pub fn as_map(&self) -> &std::collections::BTreeMap<crate::value::Symbol, crate::value::Value> {
        &self.fields
    }

    /// Field names in canonical order.
    pub fn names(&self) -> impl Iterator<Item = &crate::value::Symbol> {
        self.fields.keys()
    }

    /// Encode as a symbol-keyed dictionary.
    pub fn to_value(&self) -> crate::value::Value {
        crate::value::Value::dictionary(
            self.fields
                .iter()
                .map(|(key, value)| (crate::value::Value::Symbol(key.clone()), value.clone())),
        )
    }

    /// Decode a symbol-keyed dictionary.
    #[allow(unknown_lints, unbounded_collection_growth)] // Octet structural exception: cohesive state-machine code; split tracked separately
    pub fn from_value(
        value: &crate::value::Value,
        path: &crate::error::Path,
    ) -> Result<Self, crate::error::Diagnostic> {
        let type_error = || {
            crate::error::Diagnostic::new(
                crate::error::Stage::Envelope,
                crate::error::ErrorCode::TypeMismatch,
                path.clone(),
                "payload must be a dictionary with symbol field names",
            )
        };
        let entries = value.as_dictionary().ok_or_else(type_error)?;
        let mut fields = std::collections::BTreeMap::new();
        for (key, item) in entries {
            let Some(symbol) = key.as_symbol() else {
                return Err(crate::error::Diagnostic::new(
                    crate::error::Stage::Envelope,
                    crate::error::ErrorCode::TypeMismatch,
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
    pub kind: crate::schema::RecordKind,
    pub record_id: crate::ids::RecordId,
    pub revision_id: crate::ids::RevisionId,
    pub predecessor: Option<crate::ids::RevisionId>,
    pub scope: crate::scope::ScopeId,
    pub recorded: crate::time::RecordedTime,
    pub payload: Payload,
}

impl RecordEnvelope {
    /// Encode the envelope as `<mneme-record …>`.
    pub fn to_value(&self) -> crate::value::Value {
        let predecessor = match self.predecessor {
            Some(revision) => revision.to_value(),
            None => crate::value::Value::symbol("none"),
        };
        crate::value::Value::record_named(
            RECORD_LABEL,
            vec![
                crate::value::Value::integer(i64::from(self.schema_version)),
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
    #[allow(unknown_lints, function_length)] // Octet structural exception: cohesive state-machine code; split tracked separately
    pub fn from_value(value: &crate::value::Value) -> Result<Self, Vec<crate::error::Diagnostic>> {
        let mut diagnostics = Vec::new();
        let Some(record) = value.as_record() else {
            return Err(vec![crate::error::Diagnostic::new(
                crate::error::Stage::Envelope,
                crate::error::ErrorCode::TypeMismatch,
                crate::error::Path::root(),
                format!("expected <{RECORD_LABEL} …>"),
            )]);
        };
        if record.label() != &crate::value::Value::symbol(RECORD_LABEL) {
            return Err(vec![crate::error::Diagnostic::new(
                crate::error::Stage::Envelope,
                crate::error::ErrorCode::TypeMismatch,
                crate::error::Path::root(),
                format!("expected <{RECORD_LABEL} …>"),
            )]);
        }
        if value.contains_embedded() {
            return Err(vec![crate::error::Diagnostic::new(
                crate::error::Stage::Envelope,
                crate::error::ErrorCode::EmbeddedValueNotDurable,
                crate::error::Path::root(),
                "durable records must not contain live embedded values",
            )]);
        }
        if record.fields().len() != 8 {
            return Err(vec![crate::error::Diagnostic::new(
                crate::error::Stage::Envelope,
                crate::error::ErrorCode::MalformedEncoding,
                crate::error::Path::root(),
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
                    diagnostics.push(crate::error::Diagnostic::new(
                        crate::error::Stage::Envelope,
                        crate::error::ErrorCode::UnsupportedSchemaVersion,
                        crate::error::Path::root().field("schema-version"),
                        "schema version exceeds the supported integer range",
                    ));
                    0
                }
            },
            None => {
                diagnostics.push(crate::error::Diagnostic::new(
                    crate::error::Stage::Envelope,
                    crate::error::ErrorCode::UnsupportedSchemaVersion,
                    crate::error::Path::root().field("schema-version"),
                    "schema version must be a non-negative integer",
                ));
                0
            }
        };
        let kind = match crate::schema::RecordKind::from_value(
            &record.fields()[1],
            &crate::error::Path::root().field("kind"),
        ) {
            Ok(kind) => Some(kind),
            Err(diagnostic) => {
                diagnostics.push(diagnostic);
                None
            }
        };
        let record_id = push_id(
            crate::ids::RecordId::from_value(
                &record.fields()[2],
                &crate::error::Path::root().field("record-id"),
            ),
            &mut diagnostics,
        );
        let revision_id = push_id(
            crate::ids::RevisionId::from_value(
                &record.fields()[3],
                &crate::error::Path::root().field("revision-id"),
            ),
            &mut diagnostics,
        );
        let predecessor = match &record.fields()[4] {
            crate::value::Value::Symbol(symbol) if symbol.as_str() == "none" => Some(None),
            other => match crate::ids::RevisionId::from_value(
                other,
                &crate::error::Path::root().field("predecessor"),
            ) {
                Ok(revision) => Some(Some(revision)),
                Err(diagnostic) => {
                    diagnostics.push(diagnostic);
                    None
                }
            },
        };
        let scope = match crate::scope::ScopeId::from_value(
            &record.fields()[5],
            &crate::error::Path::root().field("scope"),
        ) {
            Ok(scope) => Some(scope),
            Err(diagnostic) => {
                diagnostics.push(diagnostic);
                None
            }
        };
        let recorded = match crate::time::RecordedTime::from_value(
            &record.fields()[6],
            &crate::error::Path::root().field("recorded-time"),
        ) {
            Ok(recorded) => Some(recorded),
            Err(diagnostic) => {
                diagnostics.push(diagnostic);
                None
            }
        };
        let payload = match Payload::from_value(
            &record.fields()[7],
            &crate::error::Path::root().field("payload"),
        ) {
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
    pub fn assertion_lifecycle(&self) -> Option<crate::schema::Lifecycle> {
        if self.kind != crate::schema::RecordKind::Assertion {
            return None;
        }
        self.payload
            .get("lifecycle")
            .and_then(crate::value::Value::as_symbol)
            .and_then(|symbol| crate::schema::Lifecycle::parse(symbol.as_str()))
    }

    /// Digest of the complete envelope, including identity and provenance.
    pub fn full_digest(&self) -> crate::digest::ContentDigest {
        crate::digest::ContentDigest::of_full_record(&self.to_value())
    }

    /// Digest of only the payload.
    pub fn payload_digest(&self) -> crate::digest::ContentDigest {
        crate::digest::ContentDigest::of_payload(&self.payload.to_value())
    }
}

fn push_id<T>(
    result: Result<T, crate::error::Diagnostic>,
    diagnostics: &mut Vec<crate::error::Diagnostic>,
) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            None
        }
    }
}

fn unsigned(value: &crate::value::Value) -> Option<u64> {
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
    pub registry: &'a crate::schema::SchemaRegistry,
    pub resolution: Option<&'a crate::reference::SnapshotIndex>,
    pub prior: Option<&'a crate::reference::SnapshotIndex>,
}

impl<'a> RecordContext<'a> {
    /// Context for validating one record in isolation.
    pub fn isolated(registry: &'a crate::schema::SchemaRegistry) -> Self {
        RecordContext {
            registry,
            resolution: None,
            prior: None,
        }
    }

    /// Context for validating one record against an existing snapshot.
    pub fn against(
        registry: &'a crate::schema::SchemaRegistry,
        snapshot: &'a crate::reference::SnapshotIndex,
    ) -> Self {
        RecordContext {
            registry,
            resolution: Some(snapshot),
            prior: Some(snapshot),
        }
    }
}

/// Validate one envelope against a schema registry and snapshot contexts.
#[allow(unknown_lints, function_length)] // Octet structural exception: cohesive state-machine code; split tracked separately
pub fn validate_record(
    envelope: &RecordEnvelope,
    context: &RecordContext<'_>,
    path: &crate::error::Path,
) -> Vec<crate::error::Diagnostic> {
    let mut diagnostics = Vec::new();
    if envelope.predecessor == Some(envelope.revision_id) {
        diagnostics.push(crate::error::Diagnostic::new(
            crate::error::Stage::Envelope,
            crate::error::ErrorCode::InvalidPredecessor,
            path.field("predecessor"),
            "a revision cannot be its own predecessor",
        ));
    }
    if let Some(prior) = context.prior {
        match prior.get(&envelope.record_id) {
            Some(entry) => {
                if entry.kind != envelope.kind {
                    diagnostics.push(crate::error::Diagnostic::new(
                        crate::error::Stage::Envelope,
                        crate::error::ErrorCode::InvalidPredecessor,
                        path.field("kind"),
                        format!(
                            "record kind cannot change between revisions ({} became {})",
                            entry.kind.symbol(),
                            envelope.kind.symbol()
                        ),
                    ));
                }
                if envelope.predecessor != Some(entry.revision) {
                    diagnostics.push(crate::error::Diagnostic::new(
                        crate::error::Stage::Envelope,
                        crate::error::ErrorCode::InvalidPredecessor,
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
                    diagnostics.push(crate::error::Diagnostic::new(
                        crate::error::Stage::Envelope,
                        crate::error::ErrorCode::InvalidPredecessor,
                        path.field("predecessor"),
                        "a new record cannot name a predecessor revision",
                    ));
                }
            }
        }
    }

    let Some(schema) = context.registry.schema(envelope.schema_version) else {
        diagnostics.push(crate::error::Diagnostic::new(
            crate::error::Stage::Envelope,
            crate::error::ErrorCode::UnsupportedSchemaVersion,
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
        diagnostics.push(crate::error::Diagnostic::new(
            crate::error::Stage::Envelope,
            crate::error::ErrorCode::UnknownRecordKind,
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
            None if field.required => diagnostics.push(crate::error::Diagnostic::new(
                crate::error::Stage::Domain,
                crate::error::ErrorCode::MissingField,
                field_path,
                format!("required field {} is absent", field.name),
            )),
            None => {}
            Some(value) => diagnostics.extend(crate::schema::validate_field(
                field.ty,
                value,
                &field_path,
                context.resolution,
            )),
        }
    }
    if kind_schema.extensions() == crate::schema::ExtensionPolicy::Refuse {
        for name in envelope.payload.names() {
            if kind_schema.field(name.as_str()).is_none() {
                diagnostics.push(crate::error::Diagnostic::new(
                    crate::error::Stage::Domain,
                    crate::error::ErrorCode::UnsupportedExtension,
                    path.field("payload").named(name.as_str()),
                    format!("field {} is not declared and extensions are refused", name),
                ));
            }
        }
    }
    diagnostics.extend(crate::schema::validate_domain(
        envelope.kind,
        envelope.payload.as_map(),
        &path.field("payload"),
    ));
    diagnostics
}

/// Validate one encoded envelope value.
pub fn validate_record_value(
    value: &crate::value::Value,
    registry: &crate::schema::SchemaRegistry,
    index: Option<&crate::reference::SnapshotIndex>,
) -> Result<RecordEnvelope, Vec<crate::error::Diagnostic>> {
    let envelope = RecordEnvelope::from_value(value)?;
    let context = match index {
        Some(snapshot) => RecordContext::against(registry, snapshot),
        None => RecordContext::isolated(registry),
    };
    let diagnostics = validate_record(&envelope, &context, &crate::error::Path::root());
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
    pub index: crate::reference::SnapshotIndex,
}

/// Validate a batch as one committed snapshot.
///
/// Every record is structurally parsed first so references may resolve within
/// the batch. Records already present in the optional external index are
/// replacements: they must name the indexed revision as their predecessor.
#[allow(unknown_lints, function_length, unbounded_collection_growth)] // Octet structural exception: cohesive state-machine code; split tracked separately
pub fn validate_batch(
    values: &[crate::value::Value],
    registry: &crate::schema::SchemaRegistry,
    external_index: Option<&crate::reference::SnapshotIndex>,
) -> Result<ValidatedBatch, Vec<crate::error::Diagnostic>> {
    let mut diagnostics = Vec::new();
    let mut envelopes = Vec::new();
    for (position, value) in values.iter().enumerate() {
        match RecordEnvelope::from_value(value) {
            Ok(envelope) => envelopes.push(envelope),
            Err(record_diagnostics) => {
                let prefix = crate::error::Path::root().index(position);
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
    let mut record_ids = std::collections::BTreeMap::new();
    let mut revision_ids = std::collections::BTreeSet::new();
    let mut seen_records = std::collections::BTreeSet::new();
    for (position, envelope) in envelopes.iter().enumerate() {
        let prefix = crate::error::Path::root().index(position);
        if !seen_records.insert(envelope.record_id) {
            diagnostics.push(crate::error::Diagnostic::new(
                crate::error::Stage::Envelope,
                crate::error::ErrorCode::DuplicateRecordId,
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
            diagnostics.push(crate::error::Diagnostic::new(
                crate::error::Stage::Envelope,
                crate::error::ErrorCode::DuplicateRevisionId,
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
        let prefix = crate::error::Path::root().index(position);
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

fn rebase(path: crate::error::Path, prefix: &crate::error::Path) -> crate::error::Path {
    let mut segments = prefix.segments().to_vec();
    segments.extend_from_slice(path.segments());
    crate::error::Path::from_segments(segments)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_id(byte: u8) -> crate::ids::RecordId {
        crate::ids::RecordId::from_bytes([byte; 16])
    }

    fn revision_id(byte: u8) -> crate::ids::RevisionId {
        crate::ids::RevisionId::from_bytes([byte; 16])
    }

    fn scope() -> crate::scope::ScopeId {
        crate::scope::ScopeId::new(crate::scope::ScopeClass::Project, "cedar").expect("scope")
    }

    fn recorded() -> crate::time::RecordedTime {
        crate::time::RecordedTime::new(crate::time::Timestamp::from_nanos(1_000), 1)
    }

    fn entity() -> RecordEnvelope {
        RecordEnvelope {
            schema_version: 1,
            kind: crate::schema::RecordKind::Entity,
            record_id: record_id(1),
            revision_id: revision_id(1),
            predecessor: None,
            scope: scope(),
            recorded: recorded(),
            payload: Payload::new([
                (
                    crate::value::Symbol::from("entity-type"),
                    crate::value::Value::symbol("project"),
                ),
                (
                    crate::value::Symbol::from("label"),
                    crate::value::Value::string("Cedar Notes"),
                ),
                (
                    crate::value::Symbol::from("properties"),
                    crate::value::Value::dictionary([]),
                ),
            ]),
        }
    }

    fn source_revision() -> RecordEnvelope {
        RecordEnvelope {
            schema_version: 1,
            kind: crate::schema::RecordKind::SourceRevision,
            record_id: record_id(2),
            revision_id: revision_id(2),
            predecessor: None,
            scope: scope(),
            recorded: recorded(),
            payload: Payload::new([
                (
                    crate::value::Symbol::from("content"),
                    crate::payload::SourceContent::Retained(
                        crate::payload::RetainedSource::new(
                            crate::digest::ContentDigest::of_source_bytes(b"= Cedar Notes\n"),
                            14,
                            "text/asciidoc",
                        )
                        .expect("retained"),
                    )
                    .to_value(),
                ),
                (
                    crate::value::Symbol::from("acquisition"),
                    crate::value::Value::symbol("authored"),
                ),
            ]),
        }
    }

    fn assertion(lifecycle: &str) -> RecordEnvelope {
        RecordEnvelope {
            schema_version: 1,
            kind: crate::schema::RecordKind::Assertion,
            record_id: record_id(3),
            revision_id: revision_id(3),
            predecessor: None,
            scope: scope(),
            recorded: recorded(),
            payload: Payload::new([
                (
                    crate::value::Symbol::from("subject"),
                    crate::reference::Reference::local(
                        record_id(1),
                        crate::schema::RecordKind::Entity,
                    )
                    .to_value(),
                ),
                (
                    crate::value::Symbol::from("predicate"),
                    crate::value::Value::symbol("storage-engine"),
                ),
                (
                    crate::value::Symbol::from("value"),
                    crate::value::Value::string("SQLite"),
                ),
                (
                    crate::value::Symbol::from("stance"),
                    crate::value::Value::symbol("affirm"),
                ),
                (
                    crate::value::Symbol::from("lifecycle"),
                    crate::value::Value::symbol(lifecycle),
                ),
                (
                    crate::value::Symbol::from("origin"),
                    crate::value::Value::symbol("authored-statement"),
                ),
                (
                    crate::value::Symbol::from("asserted-by"),
                    crate::value::Value::string("synthetic author"),
                ),
                (
                    crate::value::Symbol::from("valid-time"),
                    crate::time::ValidTime::Unknown.to_value(),
                ),
                (
                    crate::value::Symbol::from("evidence"),
                    crate::value::Value::set([]),
                ),
            ]),
        }
    }

    fn batch(records: &[RecordEnvelope]) -> Vec<crate::value::Value> {
        records.iter().map(RecordEnvelope::to_value).collect()
    }

    #[test]
    fn valid_batch_resolves_references_and_keeps_proposed_lifecycle() {
        let values = batch(&[entity(), source_revision(), assertion("proposed")]);
        let validated = validate_batch(&values, &crate::schema::SchemaRegistry::v1(), None)
            .expect("valid batch");
        let assertion = &validated.records[2];
        assert_eq!(
            assertion.assertion_lifecycle(),
            Some(crate::schema::Lifecycle::Proposed)
        );
        assert!(!validated.index.is_empty());
    }

    #[test]
    fn accepted_lifecycle_is_preserved_but_never_inferred() {
        let proposed = assertion("proposed");
        let accepted = assertion("accepted");
        assert_eq!(
            proposed.assertion_lifecycle(),
            Some(crate::schema::Lifecycle::Proposed)
        );
        assert_eq!(
            accepted.assertion_lifecycle(),
            Some(crate::schema::Lifecycle::Accepted)
        );
        assert_ne!(proposed.full_digest(), accepted.full_digest());
    }

    #[test]
    fn unknown_schema_version_is_refused_at_the_version_field() {
        let mut record = entity();
        record.schema_version = 99;
        let error = validate_record_value(
            &record.to_value(),
            &crate::schema::SchemaRegistry::v1(),
            None,
        )
        .expect_err("unsupported version");
        assert_eq!(
            error[0].code,
            crate::error::ErrorCode::UnsupportedSchemaVersion
        );
        assert_eq!(error[0].path.to_string(), "$.schema-version");
    }

    #[test]
    fn unknown_kind_is_refused_at_the_kind_field() {
        let value = crate::value::Value::record_named(
            RECORD_LABEL,
            vec![
                crate::value::Value::integer(1_i64),
                crate::value::Value::symbol("tenant"),
                record_id(1).to_value(),
                revision_id(1).to_value(),
                crate::value::Value::symbol("none"),
                scope().to_value(),
                recorded().to_value(),
                Payload::default().to_value(),
            ],
        );
        let error = RecordEnvelope::from_value(&value).expect_err("unknown kind");
        assert_eq!(error[0].code, crate::error::ErrorCode::UnknownRecordKind);
        assert_eq!(error[0].path.to_string(), "$.kind");
    }

    #[test]
    fn invalid_reference_kind_fails_the_batch() {
        let mut record = assertion("proposed");
        record.payload.insert(
            crate::value::Symbol::from("subject"),
            crate::reference::Reference::local(record_id(1), crate::schema::RecordKind::Document)
                .to_value(),
        );
        let error = validate_batch(
            &batch(&[entity(), record]),
            &crate::schema::SchemaRegistry::v1(),
            None,
        )
        .expect_err("kind mismatch");
        assert!(
            error
                .iter()
                .any(|diagnostic| diagnostic.code == crate::error::ErrorCode::ReferenceKindMismatch)
        );
    }

    #[test]
    fn unresolved_reference_fails_the_batch() {
        let mut record = assertion("proposed");
        record.payload.insert(
            crate::value::Symbol::from("subject"),
            crate::reference::Reference::local(record_id(9), crate::schema::RecordKind::Entity)
                .to_value(),
        );
        let error = validate_batch(
            &batch(&[record]),
            &crate::schema::SchemaRegistry::v1(),
            None,
        )
        .expect_err("unresolved");
        assert!(
            error
                .iter()
                .any(|diagnostic| diagnostic.code == crate::error::ErrorCode::UnresolvedReference)
        );
    }

    #[test]
    fn embedded_values_are_refused_in_durable_records() {
        let mut record = entity();
        record.payload.insert(
            crate::value::Symbol::from("properties"),
            crate::value::Value::embedded(crate::value::Value::string("live object")),
        );
        let error = validate_record_value(
            &record.to_value(),
            &crate::schema::SchemaRegistry::v1(),
            None,
        )
        .expect_err("embedded");
        assert_eq!(
            error[0].code,
            crate::error::ErrorCode::EmbeddedValueNotDurable
        );
    }

    #[test]
    fn replacement_requires_the_indexed_predecessor() {
        let original = entity();
        let mut index = crate::reference::SnapshotIndex::new();
        assert!(index.insert(original.record_id, original.kind, original.revision_id));
        let mut replacement = entity();
        replacement.revision_id = revision_id(7);
        replacement.predecessor = None;
        let registry = crate::schema::SchemaRegistry::v1();
        let context = RecordContext::against(&registry, &index);
        let error = validate_record(&replacement, &context, &crate::error::Path::root());
        assert!(
            error
                .iter()
                .any(|diagnostic| diagnostic.code == crate::error::ErrorCode::InvalidPredecessor)
        );
        replacement.predecessor = Some(original.revision_id);
        let validated = validate_record(&replacement, &context, &crate::error::Path::root());
        assert!(validated.is_empty(), "{validated:?}");
    }

    #[test]
    fn full_record_digest_covers_identity_and_provenance() {
        let original = entity();
        let mut renamed = original.clone();
        renamed.payload.insert(
            crate::value::Symbol::from("label"),
            crate::value::Value::string("Cedar Notes v2"),
        );
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
            crate::digest::ContentDigest::of_full_record(&original.to_value()),
            original.full_digest()
        );
    }

    #[test]
    fn extension_fields_are_retained_by_version_one() {
        let mut record = entity();
        record.payload.insert(
            crate::value::Symbol::from("unrecognized-extension"),
            crate::value::Value::set([crate::value::Value::integer(1_i64)]),
        );
        let validated = validate_record_value(
            &record.to_value(),
            &crate::schema::SchemaRegistry::v1(),
            None,
        )
        .expect("retained");
        assert!(validated.payload.contains("unrecognized-extension"));
    }

    #[test]
    fn provenance_changes_alter_the_digest_while_the_claim_text_stays_equal() {
        let base = assertion("proposed");
        let mut other_author = base.clone();
        other_author.payload.insert(
            crate::value::Symbol::from("asserted-by"),
            crate::value::Value::string("different attributed author"),
        );
        assert_eq!(
            base.payload.get("value"),
            other_author.payload.get("value"),
            "the asserted text is unchanged"
        );
        assert_ne!(base.payload_digest(), other_author.payload_digest());
        assert_ne!(base.full_digest(), other_author.full_digest());

        let mut later_recording = base.clone();
        later_recording.recorded =
            crate::time::RecordedTime::new(crate::time::Timestamp::from_nanos(9_999), 42);
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
        let registry = crate::schema::SchemaRegistry::v1()
            .with_version(crate::schema::RecordSchema::synthetic_migration_v2());
        let mut v2 = assertion("proposed");
        v2.schema_version = 2;
        let error = validate_record_value(&v2.to_value(), &registry, None)
            .expect_err("missing synthetic v2 field");
        assert!(error.iter().any(|diagnostic| diagnostic.code
            == crate::error::ErrorCode::MissingField
            && diagnostic.path.to_string() == "$.payload.extraction"));
        v2.payload.insert(
            crate::value::Symbol::from("extraction"),
            crate::value::Value::string("synthetic"),
        );
        validate_record_value(&v2.to_value(), &registry, None).expect("v2 assertion");

        // Version 1 records stay interpreted by version 1 even when a later
        // version is registered; the envelope version is the authority.
        validate_record_value(&assertion("proposed").to_value(), &registry, None)
            .expect("v1 record remains valid");
    }
}
