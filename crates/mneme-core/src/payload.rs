//! Shared payload primitives: source spans and source availability.
//!
//! A span identifies exact bytes in one source revision. A source may also be
//! explicitly unavailable: policy may permit a retained claim whose original
//! bytes were pruned, and that state must be represented rather than replaced
//! with invented text or an empty document.

use crate::digest::{ContentDigest, EncodingProfile, ValueBoundary};
use crate::error::{Diagnostic, ErrorCode, Path, Stage};
use crate::value::{Symbol, Value};

/// An inclusive byte span over exact retained source bytes.
///
/// `start` and `end` are byte offsets in the exact source revision and the
/// interval includes `end`, so a single-byte quotation at offset 0 has the
/// span `<span 0 0>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceSpan {
    start: u64,
    end: u64,
}

impl SourceSpan {
    /// Construct a validated inclusive span.
    pub fn new(start: u64, end: u64) -> Result<Self, &'static str> {
        if end < start {
            return Err("source span end precedes its start");
        }
        Ok(SourceSpan { start, end })
    }

    /// Inclusive start offset.
    pub const fn start(self) -> u64 {
        self.start
    }

    /// Inclusive end offset.
    pub const fn end(self) -> u64 {
        self.end
    }

    /// Number of bytes covered.
    pub fn length(self) -> u64 {
        self.end - self.start + 1
    }

    /// Encode as `<span start end>`.
    pub fn to_value(self) -> Value {
        Value::record_named(
            "span",
            vec![Value::integer(self.start), Value::integer(self.end)],
        )
    }

    /// Decode and validate `<span start end>`.
    pub fn from_value(value: &Value, path: &Path) -> Result<Self, Diagnostic> {
        let type_error = || {
            Diagnostic::new(
                Stage::Domain,
                ErrorCode::TypeMismatch,
                path.clone(),
                "expected <span start end> with non-negative byte offsets",
            )
        };
        let record = value.as_record().ok_or_else(type_error)?;
        if record.label() != &Value::symbol("span") || record.fields().len() != 2 {
            return Err(type_error());
        }
        let start = unsigned(&record.fields()[0]).ok_or_else(type_error)?;
        let end = unsigned(&record.fields()[1]).ok_or_else(type_error)?;
        Self::new(start, end).map_err(|message| {
            Diagnostic::new(
                Stage::Domain,
                ErrorCode::InvalidInterval,
                path.clone(),
                message,
            )
        })
    }
}

/// A retained source payload with exact content identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedSource {
    digest: ContentDigest,
    byte_length: u64,
    media_type: Symbol,
}

impl RetainedSource {
    /// Construct a retained source description.
    pub fn new(
        digest: ContentDigest,
        byte_length: u64,
        media_type: impl Into<Symbol>,
    ) -> Result<Self, &'static str> {
        if digest.profile() != EncodingProfile::RawBytesV1
            || digest.boundary() != ValueBoundary::SourceBytes
        {
            return Err("retained source content requires a raw source-byte digest");
        }
        Ok(RetainedSource {
            digest,
            byte_length,
            media_type: media_type.into(),
        })
    }

    /// Exact source-byte digest.
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    /// Exact byte length.
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// Declared media type.
    pub fn media_type(&self) -> &Symbol {
        &self.media_type
    }
}

/// Whether exact source bytes are retained or explicitly unavailable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceContent {
    /// The exact bytes were retained and have this identity.
    Retained(RetainedSource),
    /// Policy removed or never obtained the bytes; no excerpt is invented.
    Unavailable { reason: String },
}

impl SourceContent {
    /// Encode as `<source-content …>`.
    pub fn to_value(&self) -> Value {
        match self {
            SourceContent::Retained(retained) => Value::record_named(
                "source-content",
                vec![
                    Value::symbol("retained"),
                    retained.digest.to_value(),
                    Value::integer(retained.byte_length),
                    Value::symbol(retained.media_type.as_str().to_owned()),
                ],
            ),
            SourceContent::Unavailable { reason } => Value::record_named(
                "source-content",
                vec![Value::symbol("unavailable"), Value::string(reason.clone())],
            ),
        }
    }

    /// Decode and validate `<source-content …>`.
    pub fn from_value(value: &Value, path: &Path) -> Result<Self, Diagnostic> {
        let type_error = || {
            Diagnostic::new(
                Stage::Domain,
                ErrorCode::TypeMismatch,
                path.clone(),
                "expected <source-content retained …> or <source-content unavailable \"reason\">",
            )
        };
        let record = value.as_record().ok_or_else(type_error)?;
        if record.label() != &Value::symbol("source-content") {
            return Err(type_error());
        }
        let Some(state) = record.fields().first().and_then(Value::as_symbol) else {
            return Err(type_error());
        };
        match state.as_str() {
            "retained" => {
                if record.fields().len() != 4 {
                    return Err(type_error());
                }
                let digest = ContentDigest::from_value(&record.fields()[1], &path.index(1))?;
                let Some(byte_length) = unsigned(&record.fields()[2]) else {
                    return Err(type_error());
                };
                let Some(media_type) = record.fields()[3].as_symbol() else {
                    return Err(type_error());
                };
                let retained = RetainedSource::new(digest, byte_length, media_type.clone())
                    .map_err(|message| {
                        Diagnostic::new(
                            Stage::Domain,
                            ErrorCode::UnsupportedEncodingProfile,
                            path.clone(),
                            message,
                        )
                    })?;
                Ok(SourceContent::Retained(retained))
            }
            "unavailable" => {
                if record.fields().len() != 2 {
                    return Err(type_error());
                }
                let reason = record.fields()[1].as_string().ok_or_else(type_error)?;
                if reason.trim().is_empty() {
                    return Err(Diagnostic::new(
                        Stage::Domain,
                        ErrorCode::MissingField,
                        path.clone(),
                        "an unavailable source must state a reason",
                    ));
                }
                Ok(SourceContent::Unavailable {
                    reason: reason.to_owned(),
                })
            }
            _ => Err(type_error()),
        }
    }
}

fn unsigned(value: &Value) -> Option<u64> {
    use num_traits::ToPrimitive;
    value
        .as_integer()
        .and_then(|integer| integer.as_bigint().to_u64())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_roundtrips_and_rejects_inverted_offsets() {
        let span = SourceSpan::new(3, 9).expect("valid");
        assert_eq!(
            SourceSpan::from_value(&span.to_value(), &Path::root()).expect("decode"),
            span
        );
        assert_eq!(span.length(), 7);
        let inverted =
            Value::record_named("span", vec![Value::integer(9_i64), Value::integer(3_i64)]);
        assert_eq!(
            SourceSpan::from_value(&inverted, &Path::root())
                .expect_err("inverted")
                .code,
            ErrorCode::InvalidInterval
        );
    }

    #[test]
    fn retained_source_requires_a_raw_byte_digest() {
        let raw = ContentDigest::of_source_bytes(b"exact");
        let retained = RetainedSource::new(raw, 5, "text/asciidoc").expect("valid");
        assert!(
            RetainedSource::new(
                ContentDigest::of_payload(&Value::string("exact")),
                5,
                "text/asciidoc"
            )
            .is_err()
        );
        let content = SourceContent::Retained(retained);
        assert_eq!(
            SourceContent::from_value(&content.to_value(), &Path::root()).expect("decode"),
            content
        );
    }

    #[test]
    fn unavailable_source_states_a_reason() {
        let content = SourceContent::Unavailable {
            reason: "raw bytes pruned under policy".to_owned(),
        };
        assert_eq!(
            SourceContent::from_value(&content.to_value(), &Path::root()).expect("decode"),
            content
        );
        let empty = SourceContent::Unavailable {
            reason: "  ".to_owned(),
        };
        assert_eq!(
            SourceContent::from_value(&empty.to_value(), &Path::root())
                .expect_err("empty reason")
                .code,
            ErrorCode::MissingField
        );
    }
}
