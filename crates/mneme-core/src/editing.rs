//! Editor compatibility for retained extension fields.
//!
//! Version 1 retains typed payload extensions. An editor that only understands
//! a declared subset must either preserve every field it does not understand or
//! refuse the edit. Silently dropping a retained extension is never permitted.

/// A narrowed editor view over one record kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EditorView {
    kind: crate::fields::RecordKind,
    supported: std::collections::BTreeSet<crate::typed::Symbol>,
}

impl EditorView {
    /// Declare the field names this editor understands.
    pub fn new<I, S>(kind: crate::fields::RecordKind, supported: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<crate::typed::Symbol>,
    {
        EditorView {
            kind,
            supported: supported.into_iter().map(Into::into).collect(),
        }
    }

    /// The record kind this editor edits.
    pub const fn kind(&self) -> crate::fields::RecordKind {
        self.kind
    }

    /// Whether the editor declares support for a field.
    pub fn supports(&self, name: &str) -> bool {
        self.supported.contains(&crate::typed::Symbol::from(name))
    }

    /// Replace a record's payload, preserving every retained extension field.
    ///
    /// The caller assigns the next revision through the workspace coordinator;
    /// this method only produces a compatible payload.
    #[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
    pub fn replace_payload(
        &self,
        envelope: &crate::wire::RecordEnvelope,
        replacement: crate::wire::Payload,
    ) -> Result<crate::wire::Payload, Vec<crate::problem::Diagnostic>> {
        if envelope.kind != self.kind {
            return Err(vec![crate::problem::Diagnostic::new(
                crate::problem::Stage::Editor,
                crate::problem::ErrorCode::TypeMismatch,
                crate::problem::Path::root(),
                format!(
                    "editor edits {} records but was given {}",
                    self.kind.symbol(),
                    envelope.kind.symbol()
                ),
            )]);
        }
        let mut diagnostics =
            Vec::with_capacity(envelope.payload.len().saturating_add(replacement.len()));
        for name in envelope.payload.names() {
            if !self.supported.contains(name) && !replacement.contains(name.as_str()) {
                diagnostics.push(crate::problem::Diagnostic::new(
                    crate::problem::Stage::Editor,
                    crate::problem::ErrorCode::UnsupportedExtension,
                    crate::problem::Path::root()
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
            diagnostics.push(crate::problem::Diagnostic::new(
                crate::problem::Stage::Editor,
                crate::problem::ErrorCode::UnsupportedExtension,
                crate::problem::Path::root()
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

    fn entity_with_extension() -> crate::wire::RecordEnvelope {
        let mut payload = crate::wire::Payload::new([
            (
                crate::typed::Symbol::from("entity-type"),
                crate::typed::Value::symbol("project"),
            ),
            (
                crate::typed::Symbol::from("label"),
                crate::typed::Value::string("Cedar"),
            ),
            (
                crate::typed::Symbol::from("properties"),
                crate::typed::Value::dictionary([]),
            ),
        ]);
        payload.insert(
            crate::typed::Symbol::from("future-extension"),
            crate::typed::Value::set([crate::typed::Value::integer(7_i64)]),
        );
        crate::wire::RecordEnvelope {
            schema_version: 1,
            kind: crate::fields::RecordKind::Entity,
            record_id: crate::ids::RecordId::from_bytes([1; 16]),
            revision_id: crate::ids::RevisionId::from_bytes([1; 16]),
            predecessor: None,
            scope: crate::tenancy::ScopeId::new(crate::tenancy::ScopeClass::Project, "cedar")
                .expect("scope"),
            recorded: crate::clock::RecordedTime::new(crate::clock::Timestamp::from_nanos(1), 1),
            payload,
        }
    }

    #[test]
    fn older_editor_refuses_to_drop_an_extension() {
        let record = entity_with_extension();
        let editor = EditorView::new(
            crate::fields::RecordKind::Entity,
            ["entity-type", "label", "properties"],
        );
        let replacement = crate::wire::Payload::new([
            (
                crate::typed::Symbol::from("entity-type"),
                crate::typed::Value::symbol("project"),
            ),
            (
                crate::typed::Symbol::from("label"),
                crate::typed::Value::string("Cedar renamed"),
            ),
            (
                crate::typed::Symbol::from("properties"),
                crate::typed::Value::dictionary([]),
            ),
        ]);
        let error = editor
            .replace_payload(&record, replacement)
            .expect_err("extension would be dropped");
        assert_eq!(
            error[0].code,
            crate::problem::ErrorCode::UnsupportedExtension
        );
        assert_eq!(error[0].path.to_string(), "$.payload[\"future-extension\"]");
        // The existing record is untouched: replacement produced only an error.
        assert!(record.payload.contains("future-extension"));
    }

    #[test]
    fn editor_that_preserves_the_extension_roundtrips_it() {
        let record = entity_with_extension();
        let editor = EditorView::new(
            crate::fields::RecordKind::Entity,
            ["entity-type", "label", "properties"],
        );
        let mut replacement = crate::wire::Payload::new([
            (
                crate::typed::Symbol::from("entity-type"),
                crate::typed::Value::symbol("project"),
            ),
            (
                crate::typed::Symbol::from("label"),
                crate::typed::Value::string("Cedar renamed"),
            ),
            (
                crate::typed::Symbol::from("properties"),
                crate::typed::Value::dictionary([]),
            ),
        ]);
        replacement.insert(
            crate::typed::Symbol::from("future-extension"),
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
        let editor = EditorView::new(crate::fields::RecordKind::Assertion, ["value"]);
        let error = editor
            .replace_payload(&record, crate::wire::Payload::default())
            .expect_err("kind mismatch");
        assert_eq!(error[0].code, crate::problem::ErrorCode::TypeMismatch);
    }
}
