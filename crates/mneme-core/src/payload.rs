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

    /// Number of bytes covered, or `None` when the inclusive length is not
    /// representable in `u64`.
    ///
    /// Only the span `<span 0 18446744073709551615>` is unrepresentable: it
    /// covers `2^64` bytes. Both offsets are otherwise ordered because
    /// [`SourceSpan::new`] and [`SourceSpan::from_value`] refuse a span whose
    /// end precedes its start, so this method cannot wrap or panic.
    pub fn length(self) -> Option<u64> {
        mneme_kernel::extent::span_length(self.start, self.end)?.checked_add(1)
    }

    /// Encode as `<span start end>`.
    pub fn to_value(self) -> crate::typed::Value {
        crate::typed::Value::record_named(
            "span",
            vec![
                crate::typed::Value::integer(self.start),
                crate::typed::Value::integer(self.end),
            ],
        )
    }

    /// Decode and validate `<span start end>`.
    pub fn from_value(
        value: &crate::typed::Value,
        path: &crate::problem::Path,
    ) -> Result<Self, crate::problem::Diagnostic> {
        let type_error = || {
            crate::problem::Diagnostic::new(
                crate::problem::Stage::Domain,
                crate::problem::ErrorCode::TypeMismatch,
                path.clone(),
                "expected <span start end> with non-negative byte offsets",
            )
        };
        let record = value.as_record().ok_or_else(type_error)?;
        if record.label() != &crate::typed::Value::symbol("span") || record.fields().len() != 2 {
            return Err(type_error());
        }
        let start = unsigned(&record.fields()[0]).ok_or_else(type_error)?;
        let end = unsigned(&record.fields()[1]).ok_or_else(type_error)?;
        Self::new(start, end).map_err(|message| {
            crate::problem::Diagnostic::new(
                crate::problem::Stage::Domain,
                crate::problem::ErrorCode::InvalidInterval,
                path.clone(),
                message,
            )
        })
    }
}

/// A retained source payload with exact content identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedSource {
    digest: crate::hashing::ContentDigest,
    byte_length: u64,
    media_type: crate::typed::Symbol,
}

impl RetainedSource {
    /// Construct a retained source description.
    pub fn new(
        digest: crate::hashing::ContentDigest,
        byte_length: u64,
        media_type: impl Into<crate::typed::Symbol>,
    ) -> Result<Self, &'static str> {
        if digest.profile() != crate::hashing::EncodingProfile::RawBytesV1
            || digest.boundary() != crate::hashing::ValueBoundary::SourceBytes
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
    pub const fn digest(&self) -> crate::hashing::ContentDigest {
        self.digest
    }

    /// Exact byte length.
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// Declared media type.
    pub fn media_type(&self) -> &crate::typed::Symbol {
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
    pub fn to_value(&self) -> crate::typed::Value {
        match self {
            SourceContent::Retained(retained) => crate::typed::Value::record_named(
                "source-content",
                vec![
                    crate::typed::Value::symbol("retained"),
                    retained.digest.to_value(),
                    crate::typed::Value::integer(retained.byte_length),
                    crate::typed::Value::symbol(retained.media_type.as_str().to_owned()),
                ],
            ),
            SourceContent::Unavailable { reason } => crate::typed::Value::record_named(
                "source-content",
                vec![
                    crate::typed::Value::symbol("unavailable"),
                    crate::typed::Value::string(reason.clone()),
                ],
            ),
        }
    }

    /// Decode and validate `<source-content …>`.
    pub fn from_value(
        value: &crate::typed::Value,
        path: &crate::problem::Path,
    ) -> Result<Self, crate::problem::Diagnostic> {
        let type_error = || {
            crate::problem::Diagnostic::new(
                crate::problem::Stage::Domain,
                crate::problem::ErrorCode::TypeMismatch,
                path.clone(),
                "expected <source-content retained …> or <source-content unavailable \"reason\">",
            )
        };
        let record = value.as_record().ok_or_else(type_error)?;
        if record.label() != &crate::typed::Value::symbol("source-content") {
            return Err(type_error());
        }
        let Some(state) = record
            .fields()
            .first()
            .and_then(crate::typed::Value::as_symbol)
        else {
            return Err(type_error());
        };
        match state.as_str() {
            "retained" => {
                if record.fields().len() != 4 {
                    return Err(type_error());
                }
                let digest =
                    crate::hashing::ContentDigest::from_value(&record.fields()[1], &path.index(1))?;
                let Some(byte_length) = unsigned(&record.fields()[2]) else {
                    return Err(type_error());
                };
                let Some(media_type) = record.fields()[3].as_symbol() else {
                    return Err(type_error());
                };
                let retained = RetainedSource::new(digest, byte_length, media_type.clone())
                    .map_err(|message| {
                        crate::problem::Diagnostic::new(
                            crate::problem::Stage::Domain,
                            crate::problem::ErrorCode::UnsupportedEncodingProfile,
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
                    return Err(crate::problem::Diagnostic::new(
                        crate::problem::Stage::Domain,
                        crate::problem::ErrorCode::MissingField,
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

fn unsigned(value: &crate::typed::Value) -> Option<u64> {
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
            SourceSpan::from_value(&span.to_value(), &crate::problem::Path::root())
                .expect("decode"),
            span
        );
        assert_eq!(span.length(), Some(7));
        let single = SourceSpan::new(0, 0).expect("single byte");
        assert_eq!(single.length(), Some(1));
        assert!(SourceSpan::new(9, 3).is_err(), "construction must refuse");
        let inverted = crate::typed::Value::record_named(
            "span",
            vec![
                crate::typed::Value::integer(9_i64),
                crate::typed::Value::integer(3_i64),
            ],
        );
        assert_eq!(
            SourceSpan::from_value(&inverted, &crate::problem::Path::root())
                .expect_err("inverted")
                .code,
            crate::problem::ErrorCode::InvalidInterval
        );
    }

    #[test]
    fn maximum_span_length_is_reported_instead_of_wrapping() {
        // The widest span the decoder accepts covers 2^64 bytes, which no u64
        // can hold; the length must report that rather than overflow.
        let root = crate::problem::Path::root();
        let decoded = crate::typed::Value::record_named(
            "span",
            vec![
                crate::typed::Value::integer(0_i64),
                crate::typed::Value::integer(i64::MAX),
            ],
        );
        let span = SourceSpan::from_value(&decoded, &root).expect("ordered span");
        assert_eq!(span.length(), Some(9_223_372_036_854_775_808));
        let widest = SourceSpan::new(0, u64::MAX).expect("ordered offsets");
        assert_eq!(widest.length(), None);
        let nearly_widest = SourceSpan::new(1, u64::MAX).expect("ordered offsets");
        assert_eq!(nearly_widest.length(), Some(u64::MAX));
    }

    #[test]
    fn retained_source_requires_a_raw_byte_digest() {
        let raw = crate::hashing::ContentDigest::of_source_bytes(b"exact");
        let retained = RetainedSource::new(raw, 5, "text/asciidoc").expect("valid");
        assert!(
            RetainedSource::new(
                crate::hashing::ContentDigest::of_payload(&crate::typed::Value::string("exact")),
                5,
                "text/asciidoc"
            )
            .is_err()
        );
        let content = SourceContent::Retained(retained);
        assert_eq!(
            SourceContent::from_value(&content.to_value(), &crate::problem::Path::root())
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
            SourceContent::from_value(&content.to_value(), &crate::problem::Path::root())
                .expect("decode"),
            content
        );
        let empty = SourceContent::Unavailable {
            reason: "  ".to_owned(),
        };
        assert_eq!(
            SourceContent::from_value(&empty.to_value(), &crate::problem::Path::root())
                .expect_err("empty reason")
                .code,
            crate::problem::ErrorCode::MissingField
        );
    }
}
