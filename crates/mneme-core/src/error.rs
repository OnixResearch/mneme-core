//! Field-addressed diagnostics shared by every Mneme codec, validator, and
//! adapter.
//!
//! A diagnostic identifies the validation stage, a stable error code, and the
//! exact location in the encoded or decoded structure. Stages are kept
//! separate so a caller can distinguish malformed syntax from a schema or
//! domain refusal.

use std::fmt;

use serde::Serialize;
use serde::ser::Serializer;

/// The validation stage that produced a diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    /// Byte-level or textual syntax errors.
    Syntax,
    /// Application envelope errors: versions, kinds, identifiers, and scope.
    Envelope,
    /// Domain payload errors: required fields, typed values, and invariants.
    Domain,
    /// Tagged JSON transport errors.
    Transport,
    /// Adapter capability or numeric range errors.
    Adapter,
    /// Editor compatibility errors.
    Editor,
    /// Migration planning or execution errors.
    Migration,
    /// Evaluation fixture or report errors.
    Fixture,
}

impl Stage {
    /// Stable lower-case name used in reports and human output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Stage::Syntax => "syntax",
            Stage::Envelope => "envelope",
            Stage::Domain => "domain",
            Stage::Transport => "transport",
            Stage::Adapter => "adapter",
            Stage::Editor => "editor",
            Stage::Migration => "migration",
            Stage::Fixture => "fixture",
        }
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Stable machine-readable diagnostic codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCode {
    // Syntax and encoding.
    MalformedEncoding,
    NonCanonicalEncoding,
    TrailingBytes,
    DepthLimitExceeded,
    AnnotationLimitExceeded,
    DuplicateSetElement,
    DuplicateDictionaryKey,
    UnsupportedValueKind,
    UnsupportedTag,
    InvalidBase64,
    InvalidIntegerText,
    InvalidFloatBits,

    // Envelope and schema.
    UnsupportedSchemaVersion,
    UnknownRecordKind,
    MissingField,
    UnexpectedFieldKind,
    TypeMismatch,
    InvalidIdentifier,
    InvalidScope,
    InvalidInterval,
    InvalidTimestamp,
    UnsupportedAlgorithm,
    UnsupportedEncodingProfile,
    EmbeddedValueNotDurable,
    DuplicateRecordId,
    DuplicateRevisionId,
    ReferenceKindMismatch,
    UnresolvedReference,
    ExternalReferenceRefused,
    InvalidPredecessor,

    // Transport and evolution.
    InvalidTaggedJson,
    UnsupportedExtension,
    MigrationFailed,

    // Adapters.
    AdapterUnsupportedKind,
    AdapterIntegerOutOfRange,
    AdapterCoercionRefused,

    // Evaluation.
    FixtureInvalid,
    FixtureRequiredButUnimplemented,
}

impl ErrorCode {
    /// Stable lower-case name used in reports and human output.
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCode::MalformedEncoding => "malformed-encoding",
            ErrorCode::NonCanonicalEncoding => "non-canonical-encoding",
            ErrorCode::TrailingBytes => "trailing-bytes",
            ErrorCode::DepthLimitExceeded => "depth-limit-exceeded",
            ErrorCode::AnnotationLimitExceeded => "annotation-limit-exceeded",
            ErrorCode::DuplicateSetElement => "duplicate-set-element",
            ErrorCode::DuplicateDictionaryKey => "duplicate-dictionary-key",
            ErrorCode::UnsupportedValueKind => "unsupported-value-kind",
            ErrorCode::UnsupportedTag => "unsupported-tag",
            ErrorCode::InvalidBase64 => "invalid-base64",
            ErrorCode::InvalidIntegerText => "invalid-integer-text",
            ErrorCode::InvalidFloatBits => "invalid-float-bits",
            ErrorCode::UnsupportedSchemaVersion => "unsupported-schema-version",
            ErrorCode::UnknownRecordKind => "unknown-record-kind",
            ErrorCode::MissingField => "missing-field",
            ErrorCode::UnexpectedFieldKind => "unexpected-field-kind",
            ErrorCode::TypeMismatch => "type-mismatch",
            ErrorCode::InvalidIdentifier => "invalid-identifier",
            ErrorCode::InvalidScope => "invalid-scope",
            ErrorCode::InvalidInterval => "invalid-interval",
            ErrorCode::InvalidTimestamp => "invalid-timestamp",
            ErrorCode::UnsupportedAlgorithm => "unsupported-algorithm",
            ErrorCode::UnsupportedEncodingProfile => "unsupported-encoding-profile",
            ErrorCode::EmbeddedValueNotDurable => "embedded-value-not-durable",
            ErrorCode::DuplicateRecordId => "duplicate-record-id",
            ErrorCode::DuplicateRevisionId => "duplicate-revision-id",
            ErrorCode::ReferenceKindMismatch => "reference-kind-mismatch",
            ErrorCode::UnresolvedReference => "unresolved-reference",
            ErrorCode::ExternalReferenceRefused => "external-reference-refused",
            ErrorCode::InvalidPredecessor => "invalid-predecessor",
            ErrorCode::InvalidTaggedJson => "invalid-tagged-json",
            ErrorCode::UnsupportedExtension => "unsupported-extension",
            ErrorCode::MigrationFailed => "migration-failed",
            ErrorCode::AdapterUnsupportedKind => "adapter-unsupported-kind",
            ErrorCode::AdapterIntegerOutOfRange => "adapter-integer-out-of-range",
            ErrorCode::AdapterCoercionRefused => "adapter-coercion-refused",
            ErrorCode::FixtureInvalid => "fixture-invalid",
            ErrorCode::FixtureRequiredButUnimplemented => "fixture-required-but-unimplemented",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One segment of a field-addressed diagnostic path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Segment {
    /// A static schema field name.
    Field(&'static str),
    /// A dynamic field name, such as a retained extension.
    Named(String),
    /// A position in an encoded sequence, set, or dictionary.
    Index(usize),
}

/// A field-addressed location such as `record.payload.valid-time`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Path {
    segments: Vec<Segment>,
}

impl Path {
    /// The root path, rendered as `$`.
    pub fn root() -> Self {
        Path {
            segments: Vec::new(),
        }
    }

    /// Construct a path from explicit segments.
    pub fn from_segments(segments: Vec<Segment>) -> Self {
        Path { segments }
    }

    /// Append a static schema field.
    #[must_use]
    pub fn field(&self, name: &'static str) -> Self {
        let mut path = self.clone();
        path.segments.push(Segment::Field(name));
        path
    }

    /// Append a dynamic field name.
    #[must_use]
    pub fn named(&self, name: impl Into<String>) -> Self {
        let mut path = self.clone();
        path.segments.push(Segment::Named(name.into()));
        path
    }

    /// Append a sequence position.
    #[must_use]
    #[allow(unknown_lints, usize_in_public_api)] // std-shaped path index
    pub fn index(&self, index: usize) -> Self {
        let mut path = self.clone();
        path.segments.push(Segment::Index(index));
        path
    }

    /// Whether this path is the root.
    pub fn is_root(&self) -> bool {
        self.segments.is_empty()
    }

    /// The segments of this path.
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }
}

impl fmt::Display for Path {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("$")?;
        for segment in &self.segments {
            match segment {
                Segment::Field(name) => {
                    formatter.write_str(".")?;
                    formatter.write_str(name)?;
                }
                Segment::Named(name) => {
                    write!(formatter, "[{name:?}]")?;
                }
                Segment::Index(index) => {
                    write!(formatter, "[{index}]")?;
                }
            }
        }
        Ok(())
    }
}

impl Serialize for Path {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

/// A field-addressed validation diagnostic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    pub stage: Stage,
    pub code: ErrorCode,
    pub path: Path,
    pub message: String,
}

impl Diagnostic {
    /// Construct a diagnostic.
    pub fn new(stage: Stage, code: ErrorCode, path: Path, message: impl Into<String>) -> Self {
        Diagnostic {
            stage,
            code,
            path,
            message: message.into(),
        }
    }

    /// Whether the diagnostic is at the given code.
    pub fn is(&self, code: ErrorCode) -> bool {
        self.code == code
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}: {}", self.path, self.code, self.message)
    }
}

impl std::error::Error for Diagnostic {}

/// Render a diagnostic list for human output.
pub fn render_diagnostics(diagnostics: &[Diagnostic]) -> String {
    diagnostics
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_renders_static_and_dynamic_segments() {
        let path = Path::root()
            .field("record")
            .field("payload")
            .named("custom field")
            .index(3);
        assert_eq!(path.to_string(), "$.record.payload[\"custom field\"][3]");
    }

    #[test]
    fn diagnostics_display_path_code_and_message() {
        let diagnostic = Diagnostic::new(
            Stage::Domain,
            ErrorCode::MissingField,
            Path::root().field("record").field("payload"),
            "required field lifecycle is absent",
        );
        assert_eq!(
            diagnostic.to_string(),
            "$.record.payload: missing-field: required field lifecycle is absent"
        );
    }
}
