//! Shared codec and domain fixtures for dependent capabilities.
//!
//! These are synthetic, deterministic records with fixed identities and a small
//! exact source text. They are intentionally *not* runtime data: tests and
//! evaluation suites load them to prove that reference resolution, identity,
//! time, and lifecycle behave as specified. The proposed and accepted variants
//! differ only in explicit lifecycle fields; no validation path promotes one to
//! the other.

// The fixture constructors build from compile-time constants whose validity is
// asserted by the fixture tests below. Keeping the construction infallible makes
// fixture use readable in dependent capabilities; the same inputs are rejected
// if any of those invariants changes.
#![allow(clippy::expect_used)]

use crate::digest::ContentDigest;
use crate::envelope::{Payload, RecordEnvelope};
use crate::ids::{RecordId, RevisionId};
use crate::migration::Migration;
use crate::payload::{RetainedSource, SourceContent, SourceSpan};
use crate::reference::Reference;
use crate::schema::{Lifecycle, RecordKind, RecordSchema, SchemaRegistry};
use crate::scope::{ScopeClass, ScopeId};
use crate::time::{RecordedTime, Timestamp, ValidTime};
use crate::value::{Symbol, Value};

/// The exact synthetic source bytes used by the shared fixtures.
pub const SOURCE_TEXT: &str = "= Cedar Notes\n\n[[storage-decision]]\n== Storage decision\n\nThe Cedar prototype uses SQLite for its local revision manifest.\n";

/// The sentence asserted by the shared fixtures.
pub const ASSERTED_SENTENCE: &str =
    "The Cedar prototype uses SQLite for its local revision manifest.";

fn record_id(byte: u8) -> RecordId {
    RecordId::from_bytes([byte; 16])
}

fn revision_id(byte: u8) -> RevisionId {
    RevisionId::from_bytes([byte; 16])
}

fn scope() -> ScopeId {
    ScopeId::new(ScopeClass::Project, "cedar").expect("constant synthetic scope")
}

fn recorded(order: u64) -> RecordedTime {
    RecordedTime::new(Timestamp::from_nanos(order as i64), order)
}

/// The fixture entity identity.
pub fn entity_id() -> RecordId {
    record_id(1)
}

/// The fixture source-revision record identity.
pub fn source_revision_id() -> RecordId {
    record_id(2)
}

/// The fixture assertion record identity.
pub fn assertion_id() -> RecordId {
    record_id(4)
}

/// The fixture evidence record identity.
pub fn evidence_id() -> RecordId {
    record_id(5)
}

/// The entity record.
pub fn entity() -> RecordEnvelope {
    RecordEnvelope {
        schema_version: 1,
        kind: RecordKind::Entity,
        record_id: entity_id(),
        revision_id: revision_id(11),
        predecessor: None,
        scope: scope(),
        recorded: recorded(1),
        payload: Payload::new([
            (Symbol::from("entity-type"), Value::symbol("project")),
            (Symbol::from("label"), Value::string("Cedar Notes")),
            (Symbol::from("properties"), Value::symbol_dictionary([])),
        ]),
    }
}

/// The retained source-revision record.
pub fn source_revision() -> RecordEnvelope {
    let retained = RetainedSource::new(
        ContentDigest::of_source_bytes(SOURCE_TEXT.as_bytes()),
        SOURCE_TEXT.len() as u64,
        "text/asciidoc",
    )
    .expect("fixture source is retained");
    RecordEnvelope {
        schema_version: 1,
        kind: RecordKind::SourceRevision,
        record_id: source_revision_id(),
        revision_id: revision_id(12),
        predecessor: None,
        scope: scope(),
        recorded: recorded(2),
        payload: Payload::new([
            (
                Symbol::from("content"),
                SourceContent::Retained(retained).to_value(),
            ),
            (Symbol::from("acquisition"), Value::symbol("authored")),
            (
                Symbol::from("entity"),
                Reference::local(entity_id(), RecordKind::Entity).to_value(),
            ),
            (Symbol::from("path-hint"), Value::string("project.adoc")),
        ]),
    }
}

/// The recorded authored statement episode.
pub fn episode() -> RecordEnvelope {
    RecordEnvelope {
        schema_version: 1,
        kind: RecordKind::Episode,
        record_id: record_id(3),
        revision_id: revision_id(13),
        predecessor: None,
        scope: scope(),
        recorded: recorded(3),
        payload: Payload::new([
            (Symbol::from("actor"), Value::string("synthetic author")),
            (Symbol::from("episode-type"), Value::symbol("statement")),
            (Symbol::from("occurred"), ValidTime::Unknown.to_value()),
            (Symbol::from("summary"), Value::string(ASSERTED_SENTENCE)),
            (
                Symbol::from("source"),
                Reference::local(source_revision_id(), RecordKind::SourceRevision).to_value(),
            ),
        ]),
    }
}

fn span() -> SourceSpan {
    let start = SOURCE_TEXT
        .find(ASSERTED_SENTENCE)
        .expect("fixture sentence is present") as u64;
    let end = start + ASSERTED_SENTENCE.len() as u64 - 1;
    SourceSpan::new(start, end).expect("fixture span is ordered")
}

/// The evidence record supporting the fixture assertion.
pub fn evidence() -> RecordEnvelope {
    RecordEnvelope {
        schema_version: 1,
        kind: RecordKind::Evidence,
        record_id: evidence_id(),
        revision_id: revision_id(15),
        predecessor: None,
        scope: scope(),
        recorded: recorded(4),
        payload: Payload::new([
            (
                Symbol::from("assertion"),
                Reference::local(assertion_id(), RecordKind::Assertion).to_value(),
            ),
            (
                Symbol::from("source"),
                Reference::local(source_revision_id(), RecordKind::SourceRevision).to_value(),
            ),
            (Symbol::from("span"), span().to_value()),
            (Symbol::from("relation"), Value::symbol("supports")),
            (Symbol::from("origin"), Value::symbol("authored-statement")),
            (Symbol::from("ancestry"), Value::set([])),
        ]),
    }
}

fn assertion_with_lifecycle(lifecycle: Lifecycle, revision_byte: u8) -> RecordEnvelope {
    RecordEnvelope {
        schema_version: 1,
        kind: RecordKind::Assertion,
        record_id: assertion_id(),
        revision_id: revision_id(revision_byte),
        predecessor: None,
        scope: scope(),
        recorded: recorded(5),
        payload: Payload::new([
            (
                Symbol::from("subject"),
                Reference::local(entity_id(), RecordKind::Entity).to_value(),
            ),
            (Symbol::from("predicate"), Value::symbol("storage-engine")),
            (Symbol::from("value"), Value::string("SQLite")),
            (Symbol::from("stance"), Value::symbol("affirm")),
            (Symbol::from("lifecycle"), Value::symbol(lifecycle.symbol())),
            (Symbol::from("origin"), Value::symbol("authored-statement")),
            (
                Symbol::from("asserted-by"),
                Value::string("synthetic author"),
            ),
            (Symbol::from("valid-time"), ValidTime::Unknown.to_value()),
            (
                Symbol::from("evidence"),
                Value::set([Reference::local(evidence_id(), RecordKind::Evidence).to_value()]),
            ),
        ]),
    }
}

/// A stored assertion that remains proposed.
pub fn proposed_assertion() -> RecordEnvelope {
    assertion_with_lifecycle(Lifecycle::Proposed, 14)
}

/// An assertion whose explicit acceptance decision exists elsewhere.
///
/// The fixture does not invent that decision; it only models the record state a
/// policy-produced acceptance revision would carry.
pub fn accepted_assertion() -> RecordEnvelope {
    let mut accepted = assertion_with_lifecycle(Lifecycle::Accepted, 24);
    accepted.predecessor = Some(revision_id(14));
    accepted
}

/// The complete fixture batch in reference order.
pub fn fixture_batch() -> Vec<RecordEnvelope> {
    vec![
        entity(),
        source_revision(),
        episode(),
        proposed_assertion(),
        evidence(),
    ]
}

/// Encode the fixture batch as a Preserves sequence value.
pub fn fixture_batch_value() -> Value {
    Value::sequence(
        fixture_batch()
            .iter()
            .map(RecordEnvelope::to_value)
            .collect(),
    )
}

/// A schema registry that additionally declares the synthetic migration
/// version 2. Production code registers version 1 only.
pub fn synthetic_v2_registry() -> SchemaRegistry {
    SchemaRegistry::v1().with_version(RecordSchema::synthetic_v2())
}

/// The synthetic version 1 to version 2 migration fixture.
pub fn synthetic_v1_to_v2_migration() -> Migration {
    Migration::new(
        "synthetic-v1-to-v2",
        1,
        2,
        |payload: &Payload| -> Result<Payload, crate::error::Diagnostic> {
            let mut output = payload.clone();
            output.insert(
                Symbol::from("extraction"),
                Value::string("synthetic-v2-fixture"),
            );
            Ok(output)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{validate_batch, validate_record_value};
    use crate::schema::SchemaRegistry;

    #[test]
    fn fixture_batch_validates_and_keeps_the_assertion_proposed() {
        let values: Vec<Value> = fixture_batch()
            .iter()
            .map(RecordEnvelope::to_value)
            .collect();
        let validated =
            validate_batch(&values, &SchemaRegistry::v1(), None).expect("fixture batch");
        let assertion = validated
            .records
            .iter()
            .find(|record| record.record_id == assertion_id())
            .expect("assertion present");
        assert_eq!(assertion.assertion_lifecycle(), Some(Lifecycle::Proposed));
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
        assert_eq!(proposed.assertion_lifecycle(), Some(Lifecycle::Proposed));
        assert_eq!(accepted.assertion_lifecycle(), Some(Lifecycle::Accepted));
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
        validate_record_value(&outcome.target.to_value(), &registry, None)
            .expect("version two target");
    }
}
