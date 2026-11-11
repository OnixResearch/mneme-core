//! End-to-end domain scenarios for the typed-record contract.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::unwrap_used, clippy::expect_used)]

use mneme_core::{
    ContentDigest, Lifecycle, Payload, RecordContext, RecordEnvelope, RecordId, Reference,
    RevisionId, SchemaRegistry, ScopeClass, ScopeId, SnapshotIndex, Timestamp, ValidTime, Value,
    binary, decode, decode_document, encode_document_string, fixtures, validate_batch,
    validate_record,
};

const IDENTITY: RecordId = RecordId::from_bytes([7; 16]);
const REVISION_ONE: RevisionId = RevisionId::from_bytes([0x10; 16]);
const REVISION_TWO: RevisionId = RevisionId::from_bytes([0x11; 16]);
const RELATION_ID: RecordId = RecordId::from_bytes([6; 16]);

fn scope() -> ScopeId {
    ScopeId::new(ScopeClass::Project, "cedar").expect("scope")
}

fn document(record: RecordId, revision: RevisionId, title: &str) -> RecordEnvelope {
    RecordEnvelope {
        schema_version: 1,
        kind: mneme_core::RecordKind::Document,
        record_id: record,
        revision_id: revision,
        predecessor: None,
        scope: scope(),
        recorded: mneme_core::RecordedTime::new(Timestamp::from_nanos(10), 10),
        payload: Payload::new([
            (mneme_core::Symbol::from("title"), Value::string(title)),
            (
                mneme_core::Symbol::from("entity"),
                Reference::local(fixtures::entity_id(), mneme_core::RecordKind::Entity).to_value(),
            ),
            (
                mneme_core::Symbol::from("source-revision"),
                Reference::local(
                    fixtures::source_revision_id(),
                    mneme_core::RecordKind::SourceRevision,
                )
                .to_value(),
            ),
        ]),
    }
}

fn relation() -> RecordEnvelope {
    RecordEnvelope {
        schema_version: 1,
        kind: mneme_core::RecordKind::Relation,
        record_id: RELATION_ID,
        revision_id: RevisionId::from_bytes([0x0F; 16]),
        predecessor: None,
        scope: scope(),
        recorded: mneme_core::RecordedTime::new(Timestamp::from_nanos(11), 11),
        payload: Payload::new([
            (
                mneme_core::Symbol::from("relation-type"),
                Value::symbol("about"),
            ),
            (
                mneme_core::Symbol::from("from"),
                Reference::local(IDENTITY, mneme_core::RecordKind::Document).to_value(),
            ),
            (
                mneme_core::Symbol::from("to"),
                Reference::local(fixtures::entity_id(), mneme_core::RecordKind::Entity).to_value(),
            ),
            (
                mneme_core::Symbol::from("properties"),
                Value::dictionary([]),
            ),
        ]),
    }
}

fn validate(values: &[Value], prior: Option<&SnapshotIndex>) -> mneme_core::ValidatedBatch {
    validate_batch(values, &SchemaRegistry::v1(), prior).expect("valid batch")
}

#[test]
fn document_move_preserves_identity_and_incoming_references() {
    let document_one = document(IDENTITY, REVISION_ONE, "Cedar Notes");
    let duplicate = document(RecordId::from_bytes([9; 16]), REVISION_ONE, "Cedar Notes");
    // Equal content, distinct identity: no implicit merge.
    assert_eq!(document_one.payload_digest(), duplicate.payload_digest());
    assert_ne!(document_one.record_id, duplicate.record_id);

    let before = [
        fixtures::entity(),
        fixtures::source_revision(),
        document_one.clone(),
        relation(),
    ];
    let before_values: Vec<Value> = before.iter().map(RecordEnvelope::to_value).collect();
    let prior = validate(&before_values, None);

    let mut renamed = document(IDENTITY, REVISION_TWO, "Cedar Notes (renamed)");
    renamed.predecessor = Some(REVISION_ONE);
    renamed.recorded = mneme_core::RecordedTime::new(Timestamp::from_nanos(12), 12);
    let after = validate(&[renamed.to_value()], Some(&prior.index));
    let current = after
        .records
        .iter()
        .find(|record| record.record_id == IDENTITY)
        .expect("renamed document");
    assert_eq!(current.predecessor, Some(REVISION_ONE));
    assert_eq!(current.kind, mneme_core::RecordKind::Document);

    // The incoming relation still resolves to the stable document identity.
    let RelationTarget { target, kind } = incoming_relation_target(&prior);
    assert_eq!(target, IDENTITY);
    assert_eq!(kind, mneme_core::RecordKind::Document);
}

struct RelationTarget {
    target: RecordId,
    kind: mneme_core::RecordKind,
}

fn incoming_relation_target(batch: &mneme_core::ValidatedBatch) -> RelationTarget {
    let relation = batch
        .records
        .iter()
        .find(|record| record.record_id == RELATION_ID)
        .expect("relation");
    let reference = Reference::from_value(
        relation.payload.get("from").expect("from reference"),
        &mneme_core::Path::root(),
    )
    .expect("typed reference");
    RelationTarget {
        target: reference.target().expect("local target"),
        kind: reference.kind(),
    }
}

#[test]
fn annotation_omitting_codec_preserves_authoritative_fields() {
    let assertion = fixtures::proposed_assertion();
    let encoded = binary::encode(&assertion.to_value());
    let annotation = binary::encode(&Value::record_named(
        "source-location",
        vec![Value::string("fixture note")],
    ));
    let mut annotated = Vec::with_capacity(encoded.len() + annotation.len() + 1);
    annotated.push(0x85);
    annotated.extend_from_slice(&annotation);
    annotated.extend_from_slice(&encoded);

    let decoded = decode(&annotated).expect("annotation-omitting decode");
    assert_eq!(decoded, assertion.to_value());
    let validated = validate_record(
        &RecordEnvelope::from_value(&decoded).expect("envelope"),
        &RecordContext::isolated(&SchemaRegistry::v1()),
        &mneme_core::Path::root(),
    );
    assert!(validated.is_empty(), "{validated:?}");
    let restored = RecordEnvelope::from_value(&decoded).expect("envelope");
    assert_eq!(restored.assertion_lifecycle(), Some(Lifecycle::Proposed));
    assert_eq!(restored.record_id, assertion.record_id);
    assert_eq!(restored.full_digest(), assertion.full_digest());
}

#[test]
fn future_valid_time_remains_distinct_from_unknown() {
    let future = Timestamp::parse("2030-01-01T00:00:00Z").expect("future timestamp");
    let mut records = fixtures::fixture_batch();
    let assertion = records
        .iter_mut()
        .find(|record| record.record_id == fixtures::assertion_id())
        .expect("assertion");
    assertion
        .payload
        .insert("valid-time", ValidTime::since(future).to_value());
    let values: Vec<Value> = records.iter().map(RecordEnvelope::to_value).collect();
    let validated = validate_batch(&values, &SchemaRegistry::v1(), None)
        .expect("future-effective assertion validates structurally");
    let assertion = validated
        .records
        .iter()
        .find(|record| record.record_id == fixtures::assertion_id())
        .expect("validated assertion");
    let valid_time = ValidTime::from_value(
        assertion.payload.get("valid-time").expect("valid-time"),
        &mneme_core::Path::root(),
    )
    .expect("valid time");
    assert_ne!(valid_time, ValidTime::Unknown);
    assert_eq!(
        valid_time,
        ValidTime::Bounded {
            start: Some(future),
            end: None
        }
    );

    let roundtripped = decode_document(&encode_document_string(&assertion.to_value()))
        .expect("transport roundtrip");
    let roundtripped_time = ValidTime::from_value(
        RecordEnvelope::from_value(&roundtripped)
            .expect("envelope")
            .payload
            .get("valid-time")
            .expect("valid-time"),
        &mneme_core::Path::root(),
    )
    .expect("valid time");
    assert_eq!(roundtripped_time, valid_time);
}

#[test]
fn raw_source_digest_is_separate_from_semantic_payload_digest() {
    let source = ContentDigest::of_source_bytes(fixtures::SOURCE_TEXT.as_bytes());
    let semantic = ContentDigest::of_payload(&Value::string(fixtures::SOURCE_TEXT));
    assert_ne!(source, semantic);
    assert_eq!(source.profile(), mneme_core::EncodingProfile::RawBytesV1);
    assert_eq!(source.boundary(), mneme_core::ValueBoundary::SourceBytes);
}
