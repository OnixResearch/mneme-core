//! Shared payload primitives: source spans and source availability.
//!
//! A span identifies exact bytes in one source revision. A source may also be
//! explicitly unavailable: policy may permit a retained claim whose original
//! bytes were pruned, and that state must be represented rather than replaced
//! with invented text or an empty document.

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
    pub fn to_value(self) -> crate::value::Value {
        crate::value::Value::record_named(
            "span",
            vec![
                crate::value::Value::integer(self.start),
                crate::value::Value::integer(self.end),
            ],
        )
    }

    /// Decode and validate `<span start end>`.
    pub fn from_value(
        value: &crate::value::Value,
        path: &crate::error::Path,
    ) -> Result<Self, crate::error::Diagnostic> {
        let type_error = || {
            crate::error::Diagnostic::new(
                crate::error::Stage::Domain,
                crate::error::ErrorCode::TypeMismatch,
                path.clone(),
                "expected <span start end> with non-negative byte offsets",
            )
        };
        let record = value.as_record().ok_or_else(type_error)?;
        if record.label() != &crate::value::Value::symbol("span") || record.fields().len() != 2 {
            return Err(type_error());
        }
        let start = unsigned(&record.fields()[0]).ok_or_else(type_error)?;
        let end = unsigned(&record.fields()[1]).ok_or_else(type_error)?;
        Self::new(start, end).map_err(|message| {
            crate::error::Diagnostic::new(
                crate::error::Stage::Domain,
                crate::error::ErrorCode::InvalidInterval,
                path.clone(),
                message,
            )
        })
    }
}

/// A retained source payload with exact content identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedSource {
    digest: crate::digest::ContentDigest,
    byte_length: u64,
    media_type: crate::value::Symbol,
}

impl RetainedSource {
    /// Construct a retained source description.
    pub fn new(
        digest: crate::digest::ContentDigest,
        byte_length: u64,
        media_type: impl Into<crate::value::Symbol>,
    ) -> Result<Self, &'static str> {
        if digest.profile() != crate::digest::EncodingProfile::RawBytesV1
            || digest.boundary() != crate::digest::ValueBoundary::SourceBytes
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
    pub const fn digest(&self) -> crate::digest::ContentDigest {
        self.digest
    }

    /// Exact byte length.
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// Declared media type.
    pub fn media_type(&self) -> &crate::value::Symbol {
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
    pub fn to_value(&self) -> crate::value::Value {
        match self {
            SourceContent::Retained(retained) => crate::value::Value::record_named(
                "source-content",
                vec![
                    crate::value::Value::symbol("retained"),
                    retained.digest.to_value(),
                    crate::value::Value::integer(retained.byte_length),
                    crate::value::Value::symbol(retained.media_type.as_str().to_owned()),
                ],
            ),
            SourceContent::Unavailable { reason } => crate::value::Value::record_named(
                "source-content",
                vec![
                    crate::value::Value::symbol("unavailable"),
                    crate::value::Value::string(reason.clone()),
                ],
            ),
        }
    }

    /// Decode and validate `<source-content …>`.
    pub fn from_value(
        value: &crate::value::Value,
        path: &crate::error::Path,
    ) -> Result<Self, crate::error::Diagnostic> {
        let type_error = || {
            crate::error::Diagnostic::new(
                crate::error::Stage::Domain,
                crate::error::ErrorCode::TypeMismatch,
                path.clone(),
                "expected <source-content retained …> or <source-content unavailable \"reason\">",
            )
        };
        let record = value.as_record().ok_or_else(type_error)?;
        if record.label() != &crate::value::Value::symbol("source-content") {
            return Err(type_error());
        }
        let Some(state) = record
            .fields()
            .first()
            .and_then(crate::value::Value::as_symbol)
        else {
            return Err(type_error());
        };
        match state.as_str() {
            "retained" => {
                if record.fields().len() != 4 {
                    return Err(type_error());
                }
                let digest =
                    crate::digest::ContentDigest::from_value(&record.fields()[1], &path.index(1))?;
                let Some(byte_length) = unsigned(&record.fields()[2]) else {
                    return Err(type_error());
                };
                let Some(media_type) = record.fields()[3].as_symbol() else {
                    return Err(type_error());
                };
                let retained = RetainedSource::new(digest, byte_length, media_type.clone())
                    .map_err(|message| {
                        crate::error::Diagnostic::new(
                            crate::error::Stage::Domain,
                            crate::error::ErrorCode::UnsupportedEncodingProfile,
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
                    return Err(crate::error::Diagnostic::new(
                        crate::error::Stage::Domain,
                        crate::error::ErrorCode::MissingField,
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

fn unsigned(value: &crate::value::Value) -> Option<u64> {
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
            SourceSpan::from_value(&span.to_value(), &crate::error::Path::root()).expect("decode"),
            span
        );
        assert_eq!(span.length(), 7);
        let inverted = crate::value::Value::record_named(
            "span",
            vec![
                crate::value::Value::integer(9_i64),
                crate::value::Value::integer(3_i64),
            ],
        );
        assert_eq!(
            SourceSpan::from_value(&inverted, &crate::error::Path::root())
                .expect_err("inverted")
                .code,
            crate::error::ErrorCode::InvalidInterval
        );
    }

    #[test]
    fn retained_source_requires_a_raw_byte_digest() {
        let raw = crate::digest::ContentDigest::of_source_bytes(b"exact");
        let retained = RetainedSource::new(raw, 5, "text/asciidoc").expect("valid");
        assert!(
            RetainedSource::new(
                crate::digest::ContentDigest::of_payload(&crate::value::Value::string("exact")),
                5,
                "text/asciidoc"
            )
            .is_err()
        );
        let content = SourceContent::Retained(retained);
        assert_eq!(
            SourceContent::from_value(&content.to_value(), &crate::error::Path::root())
                .expect("decode"),
            content
        );
    }

    #[test]
    fn unavailable_source_states_a_reason() {
        let content = SourceContent::Unavailable {
            reason: "raw bytes pruned under policy".to_owned(),
        };
        assert_eq!(
            SourceContent::from_value(&content.to_value(), &crate::error::Path::root())
                .expect("decode"),
            content
        );
        let empty = SourceContent::Unavailable {
            reason: "  ".to_owned(),
        };
        assert_eq!(
            SourceContent::from_value(&empty.to_value(), &crate::error::Path::root())
                .expect_err("empty reason")
                .code,
            crate::error::ErrorCode::MissingField
        );
    }
}
