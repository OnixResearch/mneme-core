//! Versioned content identity.
//!
//! A digest records the hash algorithm, the encoding profile, and the exact
//! value boundary that was hashed. Full-record digests cover ordinary identity
//! and provenance fields, so two records are never conflated because their
//! payloads happen to match. Exact AsciiDoc source bytes use the raw-byte
//! profile and never a semantic projection.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

use sha2::Digest;

/// The SHA-256 hash algorithm symbol.
pub const ALGORITHM_SHA256: &str = "sha256";
/// The BLAKE3 hash algorithm symbol.
pub const ALGORITHM_BLAKE3: &str = "blake3";
/// The canonical Preserves binary encoding profile.
pub const PROFILE_CANONICAL_BINARY_V1: &str = "preserves-canonical-binary-v1";
/// The exact source-byte encoding profile.
pub const PROFILE_RAW_BYTES_V1: &str = "raw-bytes-v1";

/// Convert 32 digest bytes into the decision kernel's two-word digest.
///
/// The first sixteen bytes become the high word and the last sixteen the low
/// word, each read big-endian. `u128::from_be_bytes` is injective, so equal
/// kernel digests are equal byte digests and different byte digests never
/// collide in the kernel.
pub fn kernel_digest(bytes: &[u8; 32]) -> mneme_kernel::hashing::Digest {
    let (high, low) = bytes.split_at(16);
    mneme_kernel::hashing::Digest {
        hi: u128::from_be_bytes(word_16(high)),
        lo: u128::from_be_bytes(word_16(low)),
    }
}

/// The idempotency fingerprint of one request payload.
///
/// A caller builds the value from every input that can change the outcome of
/// the command, and the digest is taken over the payload boundary, so two
/// requests replay each other only when those inputs are identical.
pub fn request_fingerprint(value: &crate::typed::Value) -> ContentDigest {
    ContentDigest::of_payload(value)
}

/// Read sixteen bytes; `split_at(16)` on a 32-byte array always yields two.
fn word_16(bytes: &[u8]) -> [u8; 16] {
    let mut word = [0_u8; 16];
    word.copy_from_slice(bytes);
    word
}

/// A hash algorithm understood by this build.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HashAlgorithm {
    /// Legacy SHA-256 content addressing.
    Sha256,
    /// Default BLAKE3 content addressing.
    #[default]
    Blake3,
}

impl HashAlgorithm {
    /// Schema symbol.
    pub const fn symbol(self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => ALGORITHM_SHA256,
            HashAlgorithm::Blake3 => ALGORITHM_BLAKE3,
        }
    }

    /// Parse a supported algorithm.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            ALGORITHM_SHA256 => Some(HashAlgorithm::Sha256),
            ALGORITHM_BLAKE3 => Some(HashAlgorithm::Blake3),
            _ => None,
        }
    }

    /// Compute the 32-byte digest of exact bytes using this algorithm.
    pub fn hash_bytes(self, bytes: &[u8]) -> [u8; 32] {
        match self {
            HashAlgorithm::Sha256 => sha2::Sha256::digest(bytes).into(),
            HashAlgorithm::Blake3 => *blake3::hash(bytes).as_bytes(),
        }
    }
}

/// Streaming hasher for a [`HashAlgorithm`].
pub struct StreamingHasher(StreamingHasherInner);

enum StreamingHasherInner {
    Sha256(sha2::Sha256),
    Blake3(Box<blake3::Hasher>),
}

impl StreamingHasher {
    /// Start a streaming hash for `algorithm`.
    pub fn new(algorithm: HashAlgorithm) -> Self {
        match algorithm {
            HashAlgorithm::Sha256 => Self(StreamingHasherInner::Sha256(sha2::Sha256::new())),
            HashAlgorithm::Blake3 => Self(StreamingHasherInner::Blake3(Box::new(
                blake3::Hasher::new(),
            ))),
        }
    }

    /// Feed `bytes` into the hasher.
    pub fn update(&mut self, bytes: &[u8]) {
        match &mut self.0 {
            StreamingHasherInner::Sha256(hasher) => hasher.update(bytes),
            StreamingHasherInner::Blake3(hasher) => {
                hasher.update(bytes);
            }
        }
    }

    /// Finalize the stream and return its 32-byte digest.
    pub fn finish(self) -> [u8; 32] {
        match self.0 {
            StreamingHasherInner::Sha256(hasher) => hasher.finalize().into(),
            StreamingHasherInner::Blake3(hasher) => *hasher.finalize().as_bytes(),
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

/// Temporary canonical encoder storage for hashing full records in one operation.
///
/// Each call recomputes the digest from the supplied value. No record identity,
/// digest, or integrity result survives a call. Keep this scratch on the
/// operation's stack, not in a workspace or a shared cache.
#[derive(Default)]
pub struct FullRecordDigestScratch {
    encoder: crate::binary::EncodeScratch,
}

impl FullRecordDigestScratch {
    /// Start an operation with no retained encoding buffers.
    pub fn new() -> Self {
        Self::default()
    }

    /// Hash a complete record envelope with the canonical binary profile.
    pub fn digest(&mut self, value: &crate::typed::Value) -> ContentDigest {
        self.digest_with(value, HashAlgorithm::default())
    }

    /// Hash a complete record envelope with the canonical binary profile and an explicit algorithm.
    pub fn digest_with(
        &mut self,
        value: &crate::typed::Value,
        algorithm: HashAlgorithm,
    ) -> ContentDigest {
        let encoded = self.encoder.encode(value);
        let digest = ContentDigest::of_encoding(&encoded, ValueBoundary::FullRecord, algorithm);
        self.encoder.recycle(encoded);
        digest
    }
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
    pub fn of_full_record(value: &crate::typed::Value) -> Self {
        Self::of_full_record_with(value, HashAlgorithm::default())
    }

    /// Digest a complete record envelope value with an explicit hash algorithm.
    pub fn of_full_record_with(value: &crate::typed::Value, algorithm: HashAlgorithm) -> Self {
        Self::of_value(value, ValueBoundary::FullRecord, algorithm)
    }

    /// Digest a selected payload value.
    pub fn of_payload(value: &crate::typed::Value) -> Self {
        Self::of_payload_with(value, HashAlgorithm::default())
    }

    /// Digest a selected payload value with an explicit hash algorithm.
    pub fn of_payload_with(value: &crate::typed::Value, algorithm: HashAlgorithm) -> Self {
        Self::of_value(value, ValueBoundary::Payload, algorithm)
    }

    /// Digest exact source bytes read incrementally from `reader`.
    ///
    /// Memory use is constant; the digest equals [`Self::of_source_bytes`] of
    /// the same bytes. Returns the digest and the number of bytes read.
    pub fn of_source_reader(reader: &mut impl std::io::Read) -> std::io::Result<(Self, u64)> {
        let algorithm = HashAlgorithm::default();
        let mut hasher = StreamingHasher::new(algorithm);
        let mut buffer = vec![0_u8; 64 * 1024];
        let mut total_bytes = 0_u64;
        loop {
            let read = match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            debug_assert!(read <= buffer.len());
            hasher.update(&buffer[..read]);
            total_bytes = total_bytes.saturating_add(read as u64);
            debug_assert!(total_bytes >= read as u64);
        }
        Ok((
            ContentDigest {
                algorithm,
                profile: EncodingProfile::RawBytesV1,
                boundary: ValueBoundary::SourceBytes,
                bytes: hasher.finish(),
            },
            total_bytes,
        ))
    }

    /// Digest exact source bytes.
    pub fn of_source_bytes(bytes: &[u8]) -> Self {
        Self::of_source_bytes_with(bytes, HashAlgorithm::default())
    }

    /// Digest exact source bytes with an explicit hash algorithm.
    pub fn of_source_bytes_with(bytes: &[u8], algorithm: HashAlgorithm) -> Self {
        ContentDigest {
            algorithm,
            profile: EncodingProfile::RawBytesV1,
            boundary: ValueBoundary::SourceBytes,
            bytes: algorithm.hash_bytes(bytes),
        }
    }

    fn of_value(
        value: &crate::typed::Value,
        boundary: ValueBoundary,
        algorithm: HashAlgorithm,
    ) -> Self {
        Self::of_encoding(&crate::binary::encode(value), boundary, algorithm)
    }

    fn of_encoding(encoded: &[u8], boundary: ValueBoundary, algorithm: HashAlgorithm) -> Self {
        ContentDigest {
            algorithm,
            profile: EncodingProfile::CanonicalBinaryV1,
            boundary,
            bytes: algorithm.hash_bytes(encoded),
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

    /// Convert to the decision kernel's two-word digest.
    pub fn to_kernel(&self) -> mneme_kernel::hashing::Digest {
        kernel_digest(&self.bytes)
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
    pub fn to_value(self) -> crate::typed::Value {
        crate::typed::Value::record_named(
            "digest",
            vec![
                crate::typed::Value::symbol(self.algorithm.symbol()),
                crate::typed::Value::symbol(self.profile.symbol()),
                crate::typed::Value::symbol(self.boundary.symbol()),
                crate::typed::Value::bytes(self.bytes.to_vec()),
            ],
        )
    }

    /// Decode and verify supported metadata.
    pub fn from_value(
        value: &crate::typed::Value,
        path: &crate::problem::Path,
    ) -> Result<Self, crate::problem::Diagnostic> {
        let type_error = || {
            crate::problem::Diagnostic::new(
                crate::problem::Stage::Domain,
                crate::problem::ErrorCode::TypeMismatch,
                path.clone(),
                "expected <digest algorithm profile boundary #\"32-byte-digest\">",
            )
        };
        let record = value.as_record().ok_or_else(type_error)?;
        if record.label() != &crate::typed::Value::symbol("digest") || record.fields().len() != 4 {
            return Err(type_error());
        }
        let algorithm_text = record.fields()[0].as_symbol().ok_or_else(type_error)?;
        let Some(algorithm) = HashAlgorithm::parse(algorithm_text.as_str()) else {
            return Err(crate::problem::Diagnostic::new(
                crate::problem::Stage::Domain,
                crate::problem::ErrorCode::UnsupportedAlgorithm,
                path.clone(),
                format!("unsupported digest algorithm {algorithm_text}"),
            ));
        };
        let profile_text = record.fields()[1].as_symbol().ok_or_else(type_error)?;
        let Some(profile) = EncodingProfile::parse(profile_text.as_str()) else {
            return Err(crate::problem::Diagnostic::new(
                crate::problem::Stage::Domain,
                crate::problem::ErrorCode::UnsupportedEncodingProfile,
                path.clone(),
                format!("unsupported digest encoding profile {profile_text}"),
            ));
        };
        let boundary_text = record.fields()[2].as_symbol().ok_or_else(type_error)?;
        let Some(boundary) = ValueBoundary::parse(boundary_text.as_str()) else {
            return Err(crate::problem::Diagnostic::new(
                crate::problem::Stage::Domain,
                crate::problem::ErrorCode::UnsupportedEncodingProfile,
                path.clone(),
                format!("unsupported digest value boundary {boundary_text}"),
            ));
        };
        if !boundary.is_compatible_with(profile) {
            return Err(crate::problem::Diagnostic::new(
                crate::problem::Stage::Domain,
                crate::problem::ErrorCode::UnsupportedEncodingProfile,
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
            crate::problem::Diagnostic::new(
                crate::problem::Stage::Domain,
                crate::problem::ErrorCode::TypeMismatch,
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
        self.profile == EncodingProfile::RawBytesV1
            && self.boundary == ValueBoundary::SourceBytes
            && self.algorithm.hash_bytes(bytes) == self.bytes
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
        let left = crate::typed::Value::dictionary([
            (
                crate::typed::Value::symbol("a"),
                crate::typed::Value::integer(1_i64),
            ),
            (
                crate::typed::Value::symbol("b"),
                crate::typed::Value::integer(2_i64),
            ),
        ]);
        let right = crate::typed::Value::dictionary([
            (
                crate::typed::Value::symbol("b"),
                crate::typed::Value::integer(2_i64),
            ),
            (
                crate::typed::Value::symbol("a"),
                crate::typed::Value::integer(1_i64),
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
        let decoded = ContentDigest::from_value(&digest.to_value(), &crate::problem::Path::root())
            .expect("decode");
        assert_eq!(decoded, digest);
        assert!(decoded.verify_source_bytes(b"exact bytes"));
        assert!(!decoded.verify_source_bytes(b"different"));

        let incompatible = crate::typed::Value::record_named(
            "digest",
            vec![
                crate::typed::Value::symbol("sha256"),
                crate::typed::Value::symbol("raw-bytes-v1"),
                crate::typed::Value::symbol("full-record"),
                crate::typed::Value::bytes(vec![0_u8; 32]),
            ],
        );
        assert_eq!(
            ContentDigest::from_value(&incompatible, &crate::problem::Path::root())
                .expect_err("incompatible")
                .code,
            crate::problem::ErrorCode::UnsupportedEncodingProfile
        );

        let unsupported = crate::typed::Value::record_named(
            "digest",
            vec![
                crate::typed::Value::symbol("md5"),
                crate::typed::Value::symbol("raw-bytes-v1"),
                crate::typed::Value::symbol("source-bytes"),
                crate::typed::Value::bytes(vec![0_u8; 32]),
            ],
        );
        assert_eq!(
            ContentDigest::from_value(&unsupported, &crate::problem::Path::root())
                .expect_err("unsupported")
                .code,
            crate::problem::ErrorCode::UnsupportedAlgorithm
        );
    }

    #[test]
    fn full_record_scratch_hashes_each_exact_value() {
        let cases = [
            (
                crate::typed::Value::record_named("n", vec![crate::typed::Value::Boolean(true)]),
                &[0xb4, 0xb3, 0x01, b'n', 0x81, 0x84][..],
            ),
            (
                crate::typed::Value::record_named("n", Vec::new()),
                &[0xb4, 0xb3, 0x01, b'n', 0x84][..],
            ),
        ];
        let mut scratch = FullRecordDigestScratch::new();
        for (value, canonical) in cases.iter().chain(cases.iter().rev()) {
            let digest = scratch.digest(value);
            let expected: [u8; 32] = *blake3::hash(canonical).as_bytes();
            assert_eq!(digest.algorithm(), HashAlgorithm::Blake3);
            assert_eq!(*digest.as_bytes(), expected);
            assert_eq!(digest, ContentDigest::of_full_record(value));
            assert_eq!(digest.boundary(), ValueBoundary::FullRecord);
            assert_eq!(digest.profile(), EncodingProfile::CanonicalBinaryV1);

            let legacy = scratch.digest_with(value, HashAlgorithm::Sha256);
            let legacy_expected: [u8; 32] = sha2::Sha256::digest(canonical).into();
            assert_eq!(legacy.algorithm(), HashAlgorithm::Sha256);
            assert_eq!(*legacy.as_bytes(), legacy_expected);
            assert_eq!(
                legacy,
                ContentDigest::of_full_record_with(value, HashAlgorithm::Sha256)
            );
        }
    }

    #[test]
    fn raw_source_bytes_are_hashed_separately_from_semantic_values() {
        let source = ContentDigest::of_source_bytes(b"hello");
        let semantic = ContentDigest::of_payload(&crate::typed::Value::string("hello"));
        assert_ne!(source, semantic);
        assert_eq!(source.profile(), EncodingProfile::RawBytesV1);
        assert_eq!(source.boundary(), ValueBoundary::SourceBytes);
        assert_eq!(semantic.profile(), EncodingProfile::CanonicalBinaryV1);
        assert_eq!(semantic.boundary(), ValueBoundary::Payload);
    }

    #[test]
    fn kernel_digest_reads_each_half_big_endian() {
        let mut bytes = [0_u8; 32];
        bytes[0] = 0x01;
        bytes[15] = 0x02;
        bytes[16] = 0x03;
        bytes[31] = 0x04;
        let digest = kernel_digest(&bytes);
        // Big-endian: byte 0 is the most significant byte of the high word and
        // byte 15 the least significant; a little-endian reading would swap
        // them.
        assert_eq!(digest.hi >> 120, 0x01);
        assert_eq!(digest.hi & 0xff, 0x02);
        assert_eq!(digest.lo >> 120, 0x03);
        assert_eq!(digest.lo & 0xff, 0x04);
    }

    #[test]
    fn kernel_digests_agree_exactly_when_the_digests_do() {
        let left = ContentDigest::of_source_bytes(b"left");
        let same = ContentDigest::of_source_bytes(b"left");
        let other = ContentDigest::of_source_bytes(b"right");
        assert_eq!(left, same);
        assert_eq!(left.to_kernel(), same.to_kernel());
        assert_ne!(left, other);
        assert_ne!(left.to_kernel(), other.to_kernel());
        assert_eq!(left.to_kernel(), kernel_digest(left.as_bytes()));
    }

    #[test]
    fn request_fingerprint_is_the_payload_digest() {
        let value = request_value("notes/cedar.adoc");
        let fingerprint = request_fingerprint(&value);
        assert_eq!(fingerprint, ContentDigest::of_payload(&value));
        assert_eq!(fingerprint.boundary(), ValueBoundary::Payload);
        let other = request_value("notes/other.adoc");
        assert_ne!(fingerprint, request_fingerprint(&other));
    }

    fn request_value(path: &str) -> crate::typed::Value {
        let fields = vec![crate::typed::Value::string(path)];
        crate::typed::Value::record_named("document-import-request", fields)
    }
}
