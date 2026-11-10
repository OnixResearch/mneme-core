//! Versioned content identity.
//!
//! A digest records the hash algorithm, the encoding profile, and the exact
//! value boundary that was hashed. Full-record digests cover ordinary identity
//! and provenance fields, so two records are never conflated because their
//! payloads happen to match. Exact AsciiDoc source bytes use the raw-byte
//! profile and never a semantic projection.

use sha2::{Digest, Sha256};

use crate::binary;
use crate::error::{Diagnostic, ErrorCode, Path, Stage};
use crate::value::Value;

/// The supported hash algorithm.
pub const ALGORITHM_SHA256: &str = "sha256";
/// The canonical Preserves binary encoding profile.
pub const PROFILE_CANONICAL_BINARY_V1: &str = "preserves-canonical-binary-v1";
/// The exact source-byte encoding profile.
pub const PROFILE_RAW_BYTES_V1: &str = "raw-bytes-v1";

/// A hash algorithm understood by this build.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HashAlgorithm {
    Sha256,
}

impl HashAlgorithm {
    /// Schema symbol.
    pub const fn symbol(self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => ALGORITHM_SHA256,
        }
    }

    /// Parse a supported algorithm.
    pub fn parse(text: &str) -> Option<Self> {
        if text == ALGORITHM_SHA256 {
            Some(HashAlgorithm::Sha256)
        } else {
            None
        }
    }
}

/// The encoding profile applied before hashing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EncodingProfile {
    /// Canonical Preserves binary encoding, annotation-free.
    CanonicalBinaryV1,
    /// The exact bytes, with no transformation.
    RawBytesV1,
}

impl EncodingProfile {
    /// Schema symbol.
    pub const fn symbol(self) -> &'static str {
        match self {
            EncodingProfile::CanonicalBinaryV1 => PROFILE_CANONICAL_BINARY_V1,
            EncodingProfile::RawBytesV1 => PROFILE_RAW_BYTES_V1,
        }
    }

    /// Parse a supported profile.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            PROFILE_CANONICAL_BINARY_V1 => Some(EncodingProfile::CanonicalBinaryV1),
            PROFILE_RAW_BYTES_V1 => Some(EncodingProfile::RawBytesV1),
            _ => None,
        }
    }
}

/// Which value boundary was hashed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValueBoundary {
    /// The complete record envelope, including identity and provenance.
    FullRecord,
    /// Only the record payload.
    Payload,
    /// Exact source bytes.
    SourceBytes,
}

impl ValueBoundary {
    /// Schema symbol.
    pub const fn symbol(self) -> &'static str {
        match self {
            ValueBoundary::FullRecord => "full-record",
            ValueBoundary::Payload => "payload",
            ValueBoundary::SourceBytes => "source-bytes",
        }
    }

    /// Parse a supported boundary.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "full-record" => Some(ValueBoundary::FullRecord),
            "payload" => Some(ValueBoundary::Payload),
            "source-bytes" => Some(ValueBoundary::SourceBytes),
            _ => None,
        }
    }

    fn is_compatible_with(self, profile: EncodingProfile) -> bool {
        match profile {
            EncodingProfile::CanonicalBinaryV1 => {
                matches!(self, ValueBoundary::FullRecord | ValueBoundary::Payload)
            }
            EncodingProfile::RawBytesV1 => self == ValueBoundary::SourceBytes,
        }
    }
}

/// A content digest with explicit algorithm, encoding, and boundary metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentDigest {
    algorithm: HashAlgorithm,
    profile: EncodingProfile,
    boundary: ValueBoundary,
    bytes: [u8; 32],
}

impl ContentDigest {
    /// Digest a complete record envelope value.
    pub fn of_full_record(value: &Value) -> Self {
        Self::of_value(value, ValueBoundary::FullRecord)
    }

    /// Digest a selected payload value.
    pub fn of_payload(value: &Value) -> Self {
        Self::of_value(value, ValueBoundary::Payload)
    }

    /// Digest exact source bytes.
    pub fn of_source_bytes(bytes: &[u8]) -> Self {
        ContentDigest {
            algorithm: HashAlgorithm::Sha256,
            profile: EncodingProfile::RawBytesV1,
            boundary: ValueBoundary::SourceBytes,
            bytes: Sha256::digest(bytes).into(),
        }
    }

    fn of_value(value: &Value, boundary: ValueBoundary) -> Self {
        let encoded = binary::encode(value);
        ContentDigest {
            algorithm: HashAlgorithm::Sha256,
            profile: EncodingProfile::CanonicalBinaryV1,
            boundary,
            bytes: Sha256::digest(encoded).into(),
        }
    }

    /// The hash algorithm.
    pub const fn algorithm(self) -> HashAlgorithm {
        self.algorithm
    }

    /// The encoding profile.
    pub const fn profile(self) -> EncodingProfile {
        self.profile
    }

    /// The hashed value boundary.
    pub const fn boundary(self) -> ValueBoundary {
        self.boundary
    }

    /// The raw digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Lowercase hexadecimal digest.
    pub fn to_hex(self) -> String {
        let mut output = String::with_capacity(64);
        for byte in self.bytes {
            output.push_str(&format!("{byte:02x}"));
        }
        output
    }

    /// Encode as `<digest algorithm profile boundary #"…">`.
    pub fn to_value(self) -> Value {
        Value::record_named(
            "digest",
            vec![
                Value::symbol(self.algorithm.symbol()),
                Value::symbol(self.profile.symbol()),
                Value::symbol(self.boundary.symbol()),
                Value::bytes(self.bytes.to_vec()),
            ],
        )
    }

    /// Decode and verify supported metadata.
    pub fn from_value(value: &Value, path: &Path) -> Result<Self, Diagnostic> {
        let type_error = || {
            Diagnostic::new(
                Stage::Domain,
                ErrorCode::TypeMismatch,
                path.clone(),
                "expected <digest algorithm profile boundary #\"32-byte-digest\">",
            )
        };
        let record = value.as_record().ok_or_else(type_error)?;
        if record.label() != &Value::symbol("digest") || record.fields().len() != 4 {
            return Err(type_error());
        }
        let algorithm_text = record.fields()[0].as_symbol().ok_or_else(type_error)?;
        let Some(algorithm) = HashAlgorithm::parse(algorithm_text.as_str()) else {
            return Err(Diagnostic::new(
                Stage::Domain,
                ErrorCode::UnsupportedAlgorithm,
                path.clone(),
                format!("unsupported digest algorithm {algorithm_text}"),
            ));
        };
        let profile_text = record.fields()[1].as_symbol().ok_or_else(type_error)?;
        let Some(profile) = EncodingProfile::parse(profile_text.as_str()) else {
            return Err(Diagnostic::new(
                Stage::Domain,
                ErrorCode::UnsupportedEncodingProfile,
                path.clone(),
                format!("unsupported digest encoding profile {profile_text}"),
            ));
        };
        let boundary_text = record.fields()[2].as_symbol().ok_or_else(type_error)?;
        let Some(boundary) = ValueBoundary::parse(boundary_text.as_str()) else {
            return Err(Diagnostic::new(
                Stage::Domain,
                ErrorCode::UnsupportedEncodingProfile,
                path.clone(),
                format!("unsupported digest value boundary {boundary_text}"),
            ));
        };
        if !boundary.is_compatible_with(profile) {
            return Err(Diagnostic::new(
                Stage::Domain,
                ErrorCode::UnsupportedEncodingProfile,
                path.clone(),
                format!(
                    "encoding profile {profile_text} cannot cover value boundary {boundary_text}"
                ),
            ));
        }
        let Some(bytes) = record.fields()[3].as_bytes() else {
            return Err(type_error());
        };
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            Diagnostic::new(
                Stage::Domain,
                ErrorCode::TypeMismatch,
                path.clone(),
                "digest bytes must be exactly 32 bytes",
            )
        })?;
        Ok(ContentDigest {
            algorithm,
            profile,
            boundary,
            bytes,
        })
    }

    /// Verify that this digest matches freshly computed source bytes.
    pub fn verify_source_bytes(self, bytes: &[u8]) -> bool {
        self == ContentDigest::of_source_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equivalent_unordered_collections_have_equal_digests() {
        let left = Value::dictionary([
            (Value::symbol("a"), Value::integer(1_i64)),
            (Value::symbol("b"), Value::integer(2_i64)),
        ]);
        let right = Value::dictionary([
            (Value::symbol("b"), Value::integer(2_i64)),
            (Value::symbol("a"), Value::integer(1_i64)),
        ]);
        assert_eq!(
            ContentDigest::of_payload(&left),
            ContentDigest::of_payload(&right)
        );
    }

    #[test]
    fn metadata_roundtrips_and_rejects_incompatible_profiles() {
        let digest = ContentDigest::of_source_bytes(b"exact bytes");
        let decoded = ContentDigest::from_value(&digest.to_value(), &Path::root()).expect("decode");
        assert_eq!(decoded, digest);
        assert!(decoded.verify_source_bytes(b"exact bytes"));
        assert!(!decoded.verify_source_bytes(b"different"));

        let incompatible = Value::record_named(
            "digest",
            vec![
                Value::symbol("sha256"),
                Value::symbol("raw-bytes-v1"),
                Value::symbol("full-record"),
                Value::bytes(vec![0_u8; 32]),
            ],
        );
        assert_eq!(
            ContentDigest::from_value(&incompatible, &Path::root())
                .expect_err("incompatible")
                .code,
            ErrorCode::UnsupportedEncodingProfile
        );

        let unsupported = Value::record_named(
            "digest",
            vec![
                Value::symbol("md5"),
                Value::symbol("raw-bytes-v1"),
                Value::symbol("source-bytes"),
                Value::bytes(vec![0_u8; 32]),
            ],
        );
        assert_eq!(
            ContentDigest::from_value(&unsupported, &Path::root())
                .expect_err("unsupported")
                .code,
            ErrorCode::UnsupportedAlgorithm
        );
    }

    #[test]
    fn raw_source_bytes_are_hashed_separately_from_semantic_values() {
        let source = ContentDigest::of_source_bytes(b"hello");
        let semantic = ContentDigest::of_payload(&Value::string("hello"));
        assert_ne!(source, semantic);
        assert_eq!(source.profile(), EncodingProfile::RawBytesV1);
        assert_eq!(source.boundary(), ValueBoundary::SourceBytes);
        assert_eq!(semantic.profile(), EncodingProfile::CanonicalBinaryV1);
        assert_eq!(semantic.boundary(), ValueBoundary::Payload);
    }
}
