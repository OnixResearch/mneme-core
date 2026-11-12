//! Shared codec and domain fixtures for dependent capabilities.
//!
//! These are synthetic, deterministic records with fixed identities and a small
//! exact source text. They are intentionally *not* runtime data: tests and
//! evaluation suites load them to prove that reference resolution, identity,
//! time, and lifecycle behave as specified. The proposed and accepted variants
//! differ only in explicit lifecycle fields; no validation path promotes one to
//! the other.
#![allow(unknown_lints, no_unwrap)]
// documented boundary allowance
// Octet structural exception: domain-qualified names and macro-only imports are intentional

// The fixture constructors build from compile-time constants whose validity is
// asserted by the fixture tests below. Keeping the construction infallible makes
// fixture use readable in dependent capabilities; the same inputs are rejected
// if any of those invariants changes.
// test/fixture code fails by panic, not a production path
#![allow(clippy::expect_used)]

/// The exact synthetic source bytes used by the shared fixtures.
pub const SOURCE_TEXT: &str = "= Cedar Notes\n\n[[storage-decision]]\n== Storage decision\n\nThe Cedar prototype uses SQLite for its local revision manifest.\n";

/// The sentence asserted by the shared fixtures.
pub const ASSERTED_SENTENCE: &str =
    "The Cedar prototype uses SQLite for its local revision manifest.";

fn record_id(byte: u8) -> crate::ids::RecordId {
    crate::ids::RecordId::from_bytes([byte; 16])
}

fn revision_id(byte: u8) -> crate::ids::RevisionId {
    crate::ids::RevisionId::from_bytes([byte; 16])
}

fn scope() -> crate::tenancy::ScopeId {
    crate::tenancy::ScopeId::new(crate::tenancy::ScopeClass::Project, "cedar")
        .expect("constant synthetic scope")
}

fn recorded(order: u64) -> crate::clock::RecordedTime {
    crate::clock::RecordedTime::new(crate::clock::Timestamp::from_nanos(order as i64), order)
}

/// The fixture entity identity.
pub fn entity_id() -> crate::ids::RecordId {
    record_id(1)
}

/// The fixture source-revision record identity.
pub fn source_revision_id() -> crate::ids::RecordId {
    record_id(2)
}

/// The fixture assertion record identity.
pub fn assertion_id() -> crate::ids::RecordId {
    record_id(4)
}

/// The fixture evidence record identity.
pub fn evidence_id() -> crate::ids::RecordId {
    record_id(5)
}

/// The entity record.
pub fn entity() -> crate::wire::RecordEnvelope {
    crate::wire::RecordEnvelope {
        schema_version: 1,
        kind: crate::fields::RecordKind::Entity,
        record_id: entity_id(),
        revision_id: revision_id(11),
        predecessor: None,
        scope: scope(),
        recorded: recorded(1),
        payload: crate::wire::Payload::new([
            (
                crate::typed::Symbol::from("entity-type"),
                crate::typed::Value::symbol("project"),
            ),
            (
                crate::typed::Symbol::from("label"),
                crate::typed::Value::string("Cedar Notes"),
            ),
            (
                crate::typed::Symbol::from("properties"),
                crate::typed::Value::symbol_dictionary([]),
            ),
        ]),
    }
}

/// The retained source-revision record.
pub fn source_revision() -> crate::wire::RecordEnvelope {
    let retained = crate::payload::RetainedSource::new(
        crate::hashing::ContentDigest::of_source_bytes(SOURCE_TEXT.as_bytes()),
        SOURCE_TEXT.len() as u64,
        "text/asciidoc",
    )
    .expect("fixture source is retained");
    crate::wire::RecordEnvelope {
        schema_version: 1,
        kind: crate::fields::RecordKind::SourceRevision,
        record_id: source_revision_id(),
        revision_id: revision_id(12),
        predecessor: None,
        scope: scope(),
        recorded: recorded(2),
        payload: crate::wire::Payload::new([
            (
                crate::typed::Symbol::from("content"),
                crate::payload::SourceContent::Retained(retained).to_value(),
            ),
            (
                crate::typed::Symbol::from("acquisition"),
                crate::typed::Value::symbol("authored"),
            ),
            (
                crate::typed::Symbol::from("entity"),
                crate::pointer::Reference::local(entity_id(), crate::fields::RecordKind::Entity)
                    .to_value(),
            ),
            (
                crate::typed::Symbol::from("path-hint"),
                crate::typed::Value::string("project.adoc"),
            ),
        ]),
    }
}

/// The recorded authored statement episode.
pub fn episode() -> crate::wire::RecordEnvelope {
    crate::wire::RecordEnvelope {
        schema_version: 1,
        kind: crate::fields::RecordKind::Episode,
        record_id: record_id(3),
        revision_id: revision_id(13),
        predecessor: None,
        scope: scope(),
        recorded: recorded(3),
        payload: crate::wire::Payload::new([
            (
                crate::typed::Symbol::from("actor"),
                crate::typed::Value::string("synthetic author"),
            ),
            (
                crate::typed::Symbol::from("episode-type"),
                crate::typed::Value::symbol("statement"),
            ),
            (
                crate::typed::Symbol::from("occurred"),
                crate::clock::ValidTime::Unknown.to_value(),
            ),
            (
                crate::typed::Symbol::from("summary"),
                crate::typed::Value::string(ASSERTED_SENTENCE),
            ),
            (
                crate::typed::Symbol::from("source"),
                crate::pointer::Reference::local(
                    source_revision_id(),
                    crate::fields::RecordKind::SourceRevision,
                )
                .to_value(),
            ),
        ]),
    }
}

fn span() -> crate::payload::SourceSpan {
    let start = SOURCE_TEXT
        .find(ASSERTED_SENTENCE)
        .expect("fixture sentence is present") as u64;
    let end = start + ASSERTED_SENTENCE.len() as u64 - 1;
    crate::payload::SourceSpan::new(start, end).expect("fixture span is ordered")
}

/// The evidence record supporting the fixture assertion.
pub fn evidence() -> crate::wire::RecordEnvelope {
    crate::wire::RecordEnvelope {
        schema_version: 1,
        kind: crate::fields::RecordKind::Evidence,
        record_id: evidence_id(),
        revision_id: revision_id(15),
        predecessor: None,
        scope: scope(),
        recorded: recorded(4),
        payload: crate::wire::Payload::new([
            (
                crate::typed::Symbol::from("assertion"),
                crate::pointer::Reference::local(
                    assertion_id(),
                    crate::fields::RecordKind::Assertion,
                )
                .to_value(),
            ),
            (
                crate::typed::Symbol::from("source"),
                crate::pointer::Reference::local(
                    source_revision_id(),
                    crate::fields::RecordKind::SourceRevision,
                )
                .to_value(),
            ),
            (crate::typed::Symbol::from("span"), span().to_value()),
            (
                crate::typed::Symbol::from("relation"),
                crate::typed::Value::symbol("supports"),
            ),
            (
                crate::typed::Symbol::from("origin"),
                crate::typed::Value::symbol("authored-statement"),
            ),
            (
                crate::typed::Symbol::from("ancestry"),
                crate::typed::Value::set([]),
            ),
        ]),
    }
}

fn assertion_with_lifecycle(
    lifecycle: crate::fields::Lifecycle,
    revision_byte: u8,
) -> crate::wire::RecordEnvelope {
    crate::wire::RecordEnvelope {
        schema_version: 1,
        kind: crate::fields::RecordKind::Assertion,
        record_id: assertion_id(),
        revision_id: revision_id(revision_byte),
        predecessor: None,
        scope: scope(),
        recorded: recorded(5),
        payload: crate::wire::Payload::new([
            (
                crate::typed::Symbol::from("subject"),
                crate::pointer::Reference::local(entity_id(), crate::fields::RecordKind::Entity)
                    .to_value(),
            ),
            (
                crate::typed::Symbol::from("predicate"),
                crate::typed::Value::symbol("storage-engine"),
            ),
            (
                crate::typed::Symbol::from("value"),
                crate::typed::Value::string("SQLite"),
            ),
            (
                crate::typed::Symbol::from("stance"),
                crate::typed::Value::symbol("affirm"),
            ),
            (
                crate::typed::Symbol::from("lifecycle"),
                crate::typed::Value::symbol(lifecycle.symbol()),
            ),
            (
                crate::typed::Symbol::from("origin"),
                crate::typed::Value::symbol("authored-statement"),
            ),
            (
                crate::typed::Symbol::from("asserted-by"),
                crate::typed::Value::string("synthetic author"),
            ),
            (
                crate::typed::Symbol::from("valid-time"),
                crate::clock::ValidTime::Unknown.to_value(),
            ),
            (
                crate::typed::Symbol::from("evidence"),
                crate::typed::Value::set([crate::pointer::Reference::local(
                    evidence_id(),
                    crate::fields::RecordKind::Evidence,
                )
                .to_value()]),
            ),
        ]),
    }
}

/// A stored assertion that remains proposed.
pub fn proposed_assertion() -> crate::wire::RecordEnvelope {
    assertion_with_lifecycle(crate::fields::Lifecycle::Proposed, 14)
}

/// An assertion whose explicit acceptance decision exists elsewhere.
///
/// The fixture does not invent that decision; it only models the record state a
/// policy-produced acceptance revision would carry.
pub fn accepted_assertion() -> crate::wire::RecordEnvelope {
    let mut accepted = assertion_with_lifecycle(crate::fields::Lifecycle::Accepted, 24);
    accepted.predecessor = Some(revision_id(14));
    accepted
}

/// The complete fixture batch in reference order.
pub fn fixture_batch() -> Vec<crate::wire::RecordEnvelope> {
    vec![
        entity(),
        source_revision(),
        episode(),
        proposed_assertion(),
        evidence(),
    ]
}

/// Encode the fixture batch as a Preserves sequence value.
pub fn fixture_batch_value() -> crate::typed::Value {
    crate::typed::Value::sequence(
        fixture_batch()
            .iter()
            .map(crate::wire::RecordEnvelope::to_value)
            .collect(),
    )
}

/// A schema registry that additionally declares the synthetic migration
/// version 2. It is distinct from the production evidence version 2 and the two
/// are never registered together.
pub fn synthetic_v2_registry() -> crate::fields::SchemaRegistry {
    crate::fields::SchemaRegistry::v1()
        .with_version(crate::fields::RecordSchema::synthetic_migration_v2())
}

/// The synthetic version 1 to version 2 migration fixture.
pub fn synthetic_v1_to_v2_migration() -> crate::upgrade::Migration {
    crate::upgrade::Migration::new(
        "synthetic-v1-to-v2",
        1,
        2,
        |payload: &crate::wire::Payload| -> Result<crate::wire::Payload, crate::problem::Diagnostic> {
            let mut output = payload.clone();
            output.insert(
                crate::typed::Symbol::from("extraction"),
                crate::typed::Value::string("synthetic-v2-fixture"),
            );
            Ok(output)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_batch_validates_and_keeps_the_assertion_proposed() {
        let values: Vec<crate::typed::Value> = fixture_batch()
            .iter()
            .map(crate::wire::RecordEnvelope::to_value)
            .collect();
        let validated =
            crate::wire::validate_batch(&values, &crate::fields::SchemaRegistry::v1(), None)
                .expect("fixture batch");
        let assertion = validated
            .records
            .iter()
            .find(|record| record.record_id == assertion_id())
            .expect("assertion present");
        assert_eq!(
            assertion.assertion_lifecycle(),
            Some(crate::fields::Lifecycle::Proposed)
        );
        assert_ne!(
            proposed_assertion().full_digest(),
            accepted_assertion().full_digest()
        );
    }

    #[test]
    fn proposed_and_accepted_differ_only_in_explicit_lifecycle_and_lineage() {
        let proposed = proposed_assertion();
        let accepted = accepted_assertion();
        assert_eq!(proposed.record_id, accepted.record_id);
        assert_eq!(proposed.kind, accepted.kind);
        assert_eq!(proposed.scope, accepted.scope);
        for name in proposed.payload.names() {
            if name.as_str() == "lifecycle" {
                continue;
            }
            assert_eq!(
                proposed.payload.get(name.as_str()),
                accepted.payload.get(name.as_str())
            );
        }
        assert_eq!(
            proposed.assertion_lifecycle(),
            Some(crate::fields::Lifecycle::Proposed)
        );
        assert_eq!(
            accepted.assertion_lifecycle(),
            Some(crate::fields::Lifecycle::Accepted)
        );
        assert_eq!(accepted.predecessor, Some(proposed.revision_id));
    }

    #[test]
    fn synthetic_migration_fixture_produces_a_valid_version_two_record() {
        let registry = synthetic_v2_registry();
        let source = proposed_assertion();
        let outcome = synthetic_v1_to_v2_migration()
            .execute(&registry, &source, revision_id(44), recorded(44))
            .expect("migration fixture");
        assert_eq!(outcome.lineage.from_version, 1);
        assert_eq!(outcome.lineage.to_version, 2);
        crate::wire::validate_record_value(&outcome.target.to_value(), &registry, None)
            .expect("version two target");
    }
}
