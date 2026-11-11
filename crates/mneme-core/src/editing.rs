//! Editor compatibility for retained extension fields.
//!
//! Version 1 retains typed payload extensions. An editor that only understands
//! a declared subset must either preserve every field it does not understand or
//! refuse the edit. Silently dropping a retained extension is never permitted.

/// A narrowed editor view over one record kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EditorView {
    kind: crate::schema::RecordKind,
    supported: std::collections::BTreeSet<crate::value::Symbol>,
}

impl EditorView {
    /// Declare the field names this editor understands.
    pub fn new<I, S>(kind: crate::schema::RecordKind, supported: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<crate::value::Symbol>,
    {
        EditorView {
            kind,
            supported: supported.into_iter().map(Into::into).collect(),
        }
    }

    /// The record kind this editor edits.
    pub const fn kind(&self) -> crate::schema::RecordKind {
        self.kind
    }

    /// Whether the editor declares support for a field.
    pub fn supports(&self, name: &str) -> bool {
        self.supported.contains(&crate::value::Symbol::from(name))
    }

    /// Replace a record's payload, preserving every retained extension field.
    ///
    /// The caller assigns the next revision through the workspace coordinator;
    /// this method only produces a compatible payload.
    pub fn replace_payload(
        &self,
        envelope: &crate::envelope::RecordEnvelope,
        replacement: crate::envelope::Payload,
    ) -> Result<crate::envelope::Payload, Vec<crate::error::Diagnostic>> {
        let mut diagnostics = Vec::new();
        if envelope.kind != self.kind {
            return Err(vec![crate::error::Diagnostic::new(
                crate::error::Stage::Editor,
                crate::error::ErrorCode::TypeMismatch,
                crate::error::Path::root(),
                format!(
                    "editor edits {} records but was given {}",
                    self.kind.symbol(),
                    envelope.kind.symbol()
                ),
            )]);
        }
        for name in envelope.payload.names() {
            if !self.supported.contains(name) && !replacement.contains(name.as_str()) {
                diagnostics.push(crate::error::Diagnostic::new(
                    crate::error::Stage::Editor,
                    crate::error::ErrorCode::UnsupportedExtension,
                    crate::error::Path::root()
                        .field("payload")
                        .named(name.as_str()),
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
            diagnostics.push(crate::error::Diagnostic::new(
                crate::error::Stage::Editor,
                crate::error::ErrorCode::UnsupportedExtension,
                crate::error::Path::root()
                    .field("payload")
                    .named(name.as_str()),
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

    fn entity_with_extension() -> crate::envelope::RecordEnvelope {
        let mut payload = crate::envelope::Payload::new([
            (
                crate::value::Symbol::from("entity-type"),
                crate::value::Value::symbol("project"),
            ),
            (
                crate::value::Symbol::from("label"),
                crate::value::Value::string("Cedar"),
            ),
            (
                crate::value::Symbol::from("properties"),
                crate::value::Value::dictionary([]),
            ),
        ]);
        payload.insert(
            crate::value::Symbol::from("future-extension"),
            crate::value::Value::set([crate::value::Value::integer(7_i64)]),
        );
        crate::envelope::RecordEnvelope {
            schema_version: 1,
            kind: crate::schema::RecordKind::Entity,
            record_id: crate::ids::RecordId::from_bytes([1; 16]),
            revision_id: crate::ids::RevisionId::from_bytes([1; 16]),
            predecessor: None,
            scope: crate::scope::ScopeId::new(crate::scope::ScopeClass::Project, "cedar")
                .expect("scope"),
            recorded: crate::time::RecordedTime::new(crate::time::Timestamp::from_nanos(1), 1),
            payload,
        }
    }

    #[test]
    fn older_editor_refuses_to_drop_an_extension() {
        let record = entity_with_extension();
        let editor = EditorView::new(
            crate::schema::RecordKind::Entity,
            ["entity-type", "label", "properties"],
        );
        let replacement = crate::envelope::Payload::new([
            (
                crate::value::Symbol::from("entity-type"),
                crate::value::Value::symbol("project"),
            ),
            (
                crate::value::Symbol::from("label"),
                crate::value::Value::string("Cedar renamed"),
            ),
            (
                crate::value::Symbol::from("properties"),
                crate::value::Value::dictionary([]),
            ),
        ]);
        let error = editor
            .replace_payload(&record, replacement)
            .expect_err("extension would be dropped");
        assert_eq!(error[0].code, crate::error::ErrorCode::UnsupportedExtension);
        assert_eq!(error[0].path.to_string(), "$.payload[\"future-extension\"]");
        // The existing record is untouched: replacement produced only an error.
        assert!(record.payload.contains("future-extension"));
    }

    #[test]
    fn editor_that_preserves_the_extension_roundtrips_it() {
        let record = entity_with_extension();
        let editor = EditorView::new(
            crate::schema::RecordKind::Entity,
            ["entity-type", "label", "properties"],
        );
        let mut replacement = crate::envelope::Payload::new([
            (
                crate::value::Symbol::from("entity-type"),
                crate::value::Value::symbol("project"),
            ),
            (
                crate::value::Symbol::from("label"),
                crate::value::Value::string("Cedar renamed"),
            ),
            (
                crate::value::Symbol::from("properties"),
                crate::value::Value::dictionary([]),
            ),
        ]);
        replacement.insert(
            crate::value::Symbol::from("future-extension"),
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
        let editor = EditorView::new(crate::schema::RecordKind::Assertion, ["value"]);
        let error = editor
            .replace_payload(&record, crate::envelope::Payload::default())
            .expect_err("kind mismatch");
        assert_eq!(error[0].code, crate::error::ErrorCode::TypeMismatch);
    }
}
