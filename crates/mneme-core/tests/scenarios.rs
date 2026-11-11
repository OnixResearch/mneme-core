//! End-to-end domain scenarios for the typed-record contract.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::unwrap_used, clippy::expect_used)]

const IDENTITY: mneme_core::RecordId = mneme_core::RecordId::from_bytes([7; 16]);
const REVISION_ONE: mneme_core::RevisionId = mneme_core::RevisionId::from_bytes([0x10; 16]);
const REVISION_TWO: mneme_core::RevisionId = mneme_core::RevisionId::from_bytes([0x11; 16]);
const RELATION_ID: mneme_core::RecordId = mneme_core::RecordId::from_bytes([6; 16]);

fn scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
}

fn document(
    record: mneme_core::RecordId,
    revision: mneme_core::RevisionId,
    title: &str,
) -> mneme_core::RecordEnvelope {
    mneme_core::RecordEnvelope {
        schema_version: 1,
        kind: mneme_core::RecordKind::Document,
        record_id: record,
        revision_id: revision,
        predecessor: None,
        scope: scope(),
        recorded: mneme_core::RecordedTime::new(mneme_core::Timestamp::from_nanos(10), 10),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("title"),
                mneme_core::Value::string(title),
            ),
            (
                mneme_core::Symbol::from("entity"),
                mneme_core::Reference::local(
                    mneme_core::fixtures::entity_id(),
                    mneme_core::RecordKind::Entity,
                )
                .to_value(),
            ),
            (
                mneme_core::Symbol::from("source-revision"),
                mneme_core::Reference::local(
                    mneme_core::fixtures::source_revision_id(),
                    mneme_core::RecordKind::SourceRevision,
                )
                .to_value(),
            ),
        ]),
    }
}

fn relation() -> mneme_core::RecordEnvelope {
    mneme_core::RecordEnvelope {
        schema_version: 1,
        kind: mneme_core::RecordKind::Relation,
        record_id: RELATION_ID,
        revision_id: mneme_core::RevisionId::from_bytes([0x0F; 16]),
        predecessor: None,
        scope: scope(),
        recorded: mneme_core::RecordedTime::new(mneme_core::Timestamp::from_nanos(11), 11),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("relation-type"),
                mneme_core::Value::symbol("about"),
            ),
            (
                mneme_core::Symbol::from("from"),
                mneme_core::Reference::local(IDENTITY, mneme_core::RecordKind::Document).to_value(),
            ),
            (
                mneme_core::Symbol::from("to"),
                mneme_core::Reference::local(
                    mneme_core::fixtures::entity_id(),
                    mneme_core::RecordKind::Entity,
                )
                .to_value(),
            ),
            (
                mneme_core::Symbol::from("properties"),
                mneme_core::Value::dictionary([]),
            ),
        ]),
    }
}

fn validate(
    values: &[mneme_core::Value],
    prior: Option<&mneme_core::SnapshotIndex>,
) -> mneme_core::ValidatedBatch {
    mneme_core::validate_batch(values, &mneme_core::SchemaRegistry::v1(), prior)
        .expect("valid batch")
}

#[test]
fn document_move_preserves_identity_and_incoming_references() {
    let document_one = document(IDENTITY, REVISION_ONE, "Cedar Notes");
    let duplicate = document(
        mneme_core::RecordId::from_bytes([9; 16]),
        REVISION_ONE,
        "Cedar Notes",
    );
    // Equal content, distinct identity: no implicit merge.
    assert_eq!(document_one.payload_digest(), duplicate.payload_digest());
    assert_ne!(document_one.record_id, duplicate.record_id);

    let before = [
        mneme_core::fixtures::entity(),
        mneme_core::fixtures::source_revision(),
        document_one.clone(),
        relation(),
    ];
    let before_values: Vec<mneme_core::Value> = before
        .iter()
        .map(mneme_core::RecordEnvelope::to_value)
        .collect();
    let prior = validate(&before_values, None);

    let mut renamed = document(IDENTITY, REVISION_TWO, "Cedar Notes (renamed)");
    renamed.predecessor = Some(REVISION_ONE);
    renamed.recorded = mneme_core::RecordedTime::new(mneme_core::Timestamp::from_nanos(12), 12);
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
    target: mneme_core::RecordId,
    kind: mneme_core::RecordKind,
}

fn incoming_relation_target(batch: &mneme_core::ValidatedBatch) -> RelationTarget {
    let relation = batch
        .records
        .iter()
        .find(|record| record.record_id == RELATION_ID)
        .expect("relation");
    let reference = mneme_core::Reference::from_value(
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
    let assertion = mneme_core::fixtures::proposed_assertion();
    let encoded = mneme_core::binary::encode(&assertion.to_value());
    let annotation = mneme_core::binary::encode(&mneme_core::Value::record_named(
        "source-location",
        vec![mneme_core::Value::string("fixture note")],
    ));
    let mut annotated = Vec::with_capacity(encoded.len() + annotation.len() + 1);
    annotated.push(0x85);
    annotated.extend_from_slice(&annotation);
    annotated.extend_from_slice(&encoded);

    let decoded = mneme_core::decode(&annotated).expect("annotation-omitting decode");
    assert_eq!(decoded, assertion.to_value());
    let validated = mneme_core::validate_record(
        &mneme_core::RecordEnvelope::from_value(&decoded).expect("envelope"),
        &mneme_core::RecordContext::isolated(&mneme_core::SchemaRegistry::v1()),
        &mneme_core::Path::root(),
    );
    assert!(validated.is_empty(), "{validated:?}");
    let restored = mneme_core::RecordEnvelope::from_value(&decoded).expect("envelope");
    assert_eq!(
        restored.assertion_lifecycle(),
        Some(mneme_core::Lifecycle::Proposed)
    );
    assert_eq!(restored.record_id, assertion.record_id);
    assert_eq!(restored.full_digest(), assertion.full_digest());
}

#[test]
fn future_valid_time_remains_distinct_from_unknown() {
    let future = mneme_core::Timestamp::parse("2030-01-01T00:00:00Z").expect("future timestamp");
    let mut records = mneme_core::fixtures::fixture_batch();
    let assertion = records
        .iter_mut()
        .find(|record| record.record_id == mneme_core::fixtures::assertion_id())
        .expect("assertion");
    assertion.payload.insert(
        "valid-time",
        mneme_core::ValidTime::since(future).to_value(),
    );
    let values: Vec<mneme_core::Value> = records
        .iter()
        .map(mneme_core::RecordEnvelope::to_value)
        .collect();
    let validated = mneme_core::validate_batch(&values, &mneme_core::SchemaRegistry::v1(), None)
        .expect("future-effective assertion validates structurally");
    let assertion = validated
        .records
        .iter()
        .find(|record| record.record_id == mneme_core::fixtures::assertion_id())
        .expect("validated assertion");
    let valid_time = mneme_core::ValidTime::from_value(
        assertion.payload.get("valid-time").expect("valid-time"),
        &mneme_core::Path::root(),
    )
    .expect("valid time");
    assert_ne!(valid_time, mneme_core::ValidTime::Unknown);
    assert_eq!(
        valid_time,
        mneme_core::ValidTime::Bounded {
            start: Some(future),
            end: None
        }
    );

    let roundtripped =
        mneme_core::decode_document(&mneme_core::encode_document_string(&assertion.to_value()))
            .expect("transport roundtrip");
    let roundtripped_time = mneme_core::ValidTime::from_value(
        mneme_core::RecordEnvelope::from_value(&roundtripped)
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
    let source =
        mneme_core::ContentDigest::of_source_bytes(mneme_core::fixtures::SOURCE_TEXT.as_bytes());
    let semantic = mneme_core::ContentDigest::of_payload(&mneme_core::Value::string(
        mneme_core::fixtures::SOURCE_TEXT,
    ));
    assert_ne!(source, semantic);
    assert_eq!(source.profile(), mneme_core::EncodingProfile::RawBytesV1);
    assert_eq!(source.boundary(), mneme_core::ValueBoundary::SourceBytes);
}
