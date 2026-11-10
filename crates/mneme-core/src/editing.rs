//! Editor compatibility for retained extension fields.
//!
//! Version 1 retains typed payload extensions. An editor that only understands
//! a declared subset must either preserve every field it does not understand or
//! refuse the edit. Silently dropping a retained extension is never permitted.

use std::collections::BTreeSet;

use crate::envelope::{Payload, RecordEnvelope};
use crate::error::{Diagnostic, ErrorCode, Path, Stage};
use crate::schema::RecordKind;
use crate::value::Symbol;

/// A narrowed editor view over one record kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EditorView {
    kind: RecordKind,
    supported: BTreeSet<Symbol>,
}

impl EditorView {
    /// Declare the field names this editor understands.
    pub fn new<I, S>(kind: RecordKind, supported: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<Symbol>,
    {
        EditorView {
            kind,
            supported: supported.into_iter().map(Into::into).collect(),
        }
    }

    /// The record kind this editor edits.
    pub const fn kind(&self) -> RecordKind {
        self.kind
    }

    /// Whether the editor declares support for a field.
    pub fn supports(&self, name: &str) -> bool {
        self.supported.contains(&Symbol::from(name))
    }

    /// Replace a record's payload, preserving every retained extension field.
    ///
    /// The caller assigns the next revision through the workspace coordinator;
    /// this method only produces a compatible payload.
    pub fn replace_payload(
        &self,
        envelope: &RecordEnvelope,
        replacement: Payload,
    ) -> Result<Payload, Vec<Diagnostic>> {
        let mut diagnostics = Vec::new();
        if envelope.kind != self.kind {
            return Err(vec![Diagnostic::new(
                Stage::Editor,
                ErrorCode::TypeMismatch,
                Path::root(),
                format!(
                    "editor edits {} records but was given {}",
                    self.kind.symbol(),
                    envelope.kind.symbol()
                ),
            )]);
        }
        for name in envelope.payload.names() {
            if !self.supported.contains(name) && !replacement.contains(name.as_str()) {
                diagnostics.push(Diagnostic::new(
                    Stage::Editor,
                    ErrorCode::UnsupportedExtension,
                    Path::root().field("payload").named(name.as_str()),
                    format!(
                        "editor cannot preserve retained extension {name}; refusing to drop it"
                    ),
                ));
            }
        }
        for name in replacement.names() {
            if self.supported.contains(name) {
                continue;
            }
            // An editor may carry an unknown field through verbatim, but it
            // cannot validate or change it.
            if envelope.payload.get(name.as_str()) == replacement.get(name.as_str()) {
                continue;
            }
            diagnostics.push(Diagnostic::new(
                Stage::Editor,
                ErrorCode::UnsupportedExtension,
                Path::root().field("payload").named(name.as_str()),
                format!("editor cannot validate field {name}"),
            ));
        }
        if diagnostics.is_empty() {
            Ok(replacement)
        } else {
            Err(diagnostics)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::RecordEnvelope;
    use crate::ids::{RecordId, RevisionId};
    use crate::schema::RecordKind;
    use crate::scope::{ScopeClass, ScopeId};
    use crate::time::{RecordedTime, Timestamp};
    use crate::value::Value;

    fn entity_with_extension() -> RecordEnvelope {
        let mut payload = Payload::new([
            (Symbol::from("entity-type"), Value::symbol("project")),
            (Symbol::from("label"), Value::string("Cedar")),
            (Symbol::from("properties"), Value::dictionary([])),
        ]);
        payload.insert(
            Symbol::from("future-extension"),
            Value::set([Value::integer(7_i64)]),
        );
        RecordEnvelope {
            schema_version: 1,
            kind: RecordKind::Entity,
            record_id: RecordId::from_bytes([1; 16]),
            revision_id: RevisionId::from_bytes([1; 16]),
            predecessor: None,
            scope: ScopeId::new(ScopeClass::Project, "cedar").expect("scope"),
            recorded: RecordedTime::new(Timestamp::from_nanos(1), 1),
            payload,
        }
    }

    #[test]
    fn older_editor_refuses_to_drop_an_extension() {
        let record = entity_with_extension();
        let editor = EditorView::new(RecordKind::Entity, ["entity-type", "label", "properties"]);
        let replacement = Payload::new([
            (Symbol::from("entity-type"), Value::symbol("project")),
            (Symbol::from("label"), Value::string("Cedar renamed")),
            (Symbol::from("properties"), Value::dictionary([])),
        ]);
        let error = editor
            .replace_payload(&record, replacement)
            .expect_err("extension would be dropped");
        assert_eq!(error[0].code, ErrorCode::UnsupportedExtension);
        assert_eq!(error[0].path.to_string(), "$.payload[\"future-extension\"]");
        // The existing record is untouched: replacement produced only an error.
        assert!(record.payload.contains("future-extension"));
    }

    #[test]
    fn editor_that_preserves_the_extension_roundtrips_it() {
        let record = entity_with_extension();
        let editor = EditorView::new(RecordKind::Entity, ["entity-type", "label", "properties"]);
        let mut replacement = Payload::new([
            (Symbol::from("entity-type"), Value::symbol("project")),
            (Symbol::from("label"), Value::string("Cedar renamed")),
            (Symbol::from("properties"), Value::dictionary([])),
        ]);
        replacement.insert(
            Symbol::from("future-extension"),
            record
                .payload
                .get("future-extension")
                .cloned()
                .expect("retained extension"),
        );
        let result = editor
            .replace_payload(&record, replacement)
            .expect("preserved");
        assert_eq!(
            result.get("future-extension"),
            record.payload.get("future-extension")
        );
    }

    #[test]
    fn editor_refuses_a_different_kind() {
        let record = entity_with_extension();
        let editor = EditorView::new(RecordKind::Assertion, ["value"]);
        let error = editor
            .replace_payload(&record, Payload::default())
            .expect_err("kind mismatch");
        assert_eq!(error[0].code, ErrorCode::TypeMismatch);
    }
}
