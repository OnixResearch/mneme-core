//! Versioned content identity.
//!
//! A digest records the hash algorithm, the encoding profile, and the exact
//! value boundary that was hashed. Full-record digests cover ordinary identity
//! and provenance fields, so two records are never conflated because their
//! payloads happen to match. Exact AsciiDoc source bytes use the raw-byte
//! profile and never a semantic projection.
#![allow(path_segment_repetition)] // Octet structural exception: domain-qualified names and macro-only imports are intentional

use sha2::Digest;

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
    /// Construct a digest from already computed bytes and explicit metadata.
    ///
    /// The profile/boundary pair must be compatible; the caller is responsible
    /// for having hashed the boundary those metadata describe.
    pub fn from_parts(
        algorithm: HashAlgorithm,
        profile: EncodingProfile,
        boundary: ValueBoundary,
        bytes: [u8; 32],
    ) -> Result<Self, &'static str> {
        if !boundary.is_compatible_with(profile) {
            return Err("encoding profile cannot cover the declared value boundary");
        }
        Ok(ContentDigest {
            algorithm,
            profile,
            boundary,
            bytes,
        })
    }

    /// Digest a complete record envelope value.
    pub fn of_full_record(value: &crate::value::Value) -> Self {
        Self::of_value(value, ValueBoundary::FullRecord)
    }

    /// Digest a selected payload value.
    pub fn of_payload(value: &crate::value::Value) -> Self {
        Self::of_value(value, ValueBoundary::Payload)
    }

    /// Digest exact source bytes.
    pub fn of_source_bytes(bytes: &[u8]) -> Self {
        ContentDigest {
            algorithm: HashAlgorithm::Sha256,
            profile: EncodingProfile::RawBytesV1,
            boundary: ValueBoundary::SourceBytes,
            bytes: sha2::Sha256::digest(bytes).into(),
        }
    }

    fn of_value(value: &crate::value::Value, boundary: ValueBoundary) -> Self {
        let encoded = crate::binary::encode(value);
        ContentDigest {
            algorithm: HashAlgorithm::Sha256,
            profile: EncodingProfile::CanonicalBinaryV1,
            boundary,
            bytes: sha2::Sha256::digest(encoded).into(),
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
    pub fn to_value(self) -> crate::value::Value {
        crate::value::Value::record_named(
            "digest",
            vec![
                crate::value::Value::symbol(self.algorithm.symbol()),
                crate::value::Value::symbol(self.profile.symbol()),
                crate::value::Value::symbol(self.boundary.symbol()),
                crate::value::Value::bytes(self.bytes.to_vec()),
            ],
        )
    }

    /// Decode and verify supported metadata.
    pub fn from_value(
        value: &crate::value::Value,
        path: &crate::error::Path,
    ) -> Result<Self, crate::error::Diagnostic> {
        let type_error = || {
            crate::error::Diagnostic::new(
                crate::error::Stage::Domain,
                crate::error::ErrorCode::TypeMismatch,
                path.clone(),
                "expected <digest algorithm profile boundary #\"32-byte-digest\">",
            )
        };
        let record = value.as_record().ok_or_else(type_error)?;
        if record.label() != &crate::value::Value::symbol("digest") || record.fields().len() != 4 {
            return Err(type_error());
        }
        let algorithm_text = record.fields()[0].as_symbol().ok_or_else(type_error)?;
        let Some(algorithm) = HashAlgorithm::parse(algorithm_text.as_str()) else {
            return Err(crate::error::Diagnostic::new(
                crate::error::Stage::Domain,
                crate::error::ErrorCode::UnsupportedAlgorithm,
                path.clone(),
                format!("unsupported digest algorithm {algorithm_text}"),
            ));
        };
        let profile_text = record.fields()[1].as_symbol().ok_or_else(type_error)?;
        let Some(profile) = EncodingProfile::parse(profile_text.as_str()) else {
            return Err(crate::error::Diagnostic::new(
                crate::error::Stage::Domain,
                crate::error::ErrorCode::UnsupportedEncodingProfile,
                path.clone(),
                format!("unsupported digest encoding profile {profile_text}"),
            ));
        };
        let boundary_text = record.fields()[2].as_symbol().ok_or_else(type_error)?;
        let Some(boundary) = ValueBoundary::parse(boundary_text.as_str()) else {
            return Err(crate::error::Diagnostic::new(
                crate::error::Stage::Domain,
                crate::error::ErrorCode::UnsupportedEncodingProfile,
                path.clone(),
                format!("unsupported digest value boundary {boundary_text}"),
            ));
        };
        if !boundary.is_compatible_with(profile) {
            return Err(crate::error::Diagnostic::new(
                crate::error::Stage::Domain,
                crate::error::ErrorCode::UnsupportedEncodingProfile,
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
            crate::error::Diagnostic::new(
                crate::error::Stage::Domain,
                crate::error::ErrorCode::TypeMismatch,
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

impl std::fmt::Display for ContentDigest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equivalent_unordered_collections_have_equal_digests() {
        let left = crate::value::Value::dictionary([
            (
                crate::value::Value::symbol("a"),
                crate::value::Value::integer(1_i64),
            ),
            (
                crate::value::Value::symbol("b"),
                crate::value::Value::integer(2_i64),
            ),
        ]);
        let right = crate::value::Value::dictionary([
            (
                crate::value::Value::symbol("b"),
                crate::value::Value::integer(2_i64),
            ),
            (
                crate::value::Value::symbol("a"),
                crate::value::Value::integer(1_i64),
            ),
        ]);
        assert_eq!(
            ContentDigest::of_payload(&left),
            ContentDigest::of_payload(&right)
        );
    }

    #[test]
    fn metadata_roundtrips_and_rejects_incompatible_profiles() {
        let digest = ContentDigest::of_source_bytes(b"exact bytes");
        let decoded = ContentDigest::from_value(&digest.to_value(), &crate::error::Path::root())
            .expect("decode");
        assert_eq!(decoded, digest);
        assert!(decoded.verify_source_bytes(b"exact bytes"));
        assert!(!decoded.verify_source_bytes(b"different"));

        let incompatible = crate::value::Value::record_named(
            "digest",
            vec![
                crate::value::Value::symbol("sha256"),
                crate::value::Value::symbol("raw-bytes-v1"),
                crate::value::Value::symbol("full-record"),
                crate::value::Value::bytes(vec![0_u8; 32]),
            ],
        );
        assert_eq!(
            ContentDigest::from_value(&incompatible, &crate::error::Path::root())
                .expect_err("incompatible")
                .code,
            crate::error::ErrorCode::UnsupportedEncodingProfile
        );

        let unsupported = crate::value::Value::record_named(
            "digest",
            vec![
                crate::value::Value::symbol("md5"),
                crate::value::Value::symbol("raw-bytes-v1"),
                crate::value::Value::symbol("source-bytes"),
                crate::value::Value::bytes(vec![0_u8; 32]),
            ],
        );
        assert_eq!(
            ContentDigest::from_value(&unsupported, &crate::error::Path::root())
                .expect_err("unsupported")
                .code,
            crate::error::ErrorCode::UnsupportedAlgorithm
        );
    }

    #[test]
    fn raw_source_bytes_are_hashed_separately_from_semantic_values() {
        let source = ContentDigest::of_source_bytes(b"hello");
        let semantic = ContentDigest::of_payload(&crate::value::Value::string("hello"));
        assert_ne!(source, semantic);
        assert_eq!(source.profile(), EncodingProfile::RawBytesV1);
        assert_eq!(source.boundary(), ValueBoundary::SourceBytes);
        assert_eq!(semantic.profile(), EncodingProfile::CanonicalBinaryV1);
        assert_eq!(semantic.boundary(), ValueBoundary::Payload);
    }
}
