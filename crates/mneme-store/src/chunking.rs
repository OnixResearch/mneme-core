//! Deterministic Gear-hash FastCDC content-defined chunking and chunk manifests.
//!
//! Implements the normalized content-defined chunking algorithm of
//! Xia et al., *FastCDC: A Fast and Efficient Content-Defined Chunking Approach
//! for Data Deduplication* (USENIX ATC 2016), storing immutable chunk manifests
//! (`MNCDC01\0`) over content-addressed chunks while preserving the canonical
//! uncompressed SHA-256 `ContentDigest` and `byte_length`.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// Minimum allowed FastCDC chunk size (64 bytes, one Gear window).
pub const MIN_FASTCDC_CHUNK_BYTES: u32 = 64;

/// Maximum allowed FastCDC chunk size (1 MiB).
pub const MAX_FASTCDC_CHUNK_BYTES: u32 = 1024 * 1024;

/// Default minimum normalized FastCDC chunk size (16 KiB).
pub const DEFAULT_MIN_CHUNK_BYTES: u32 = 16 * 1024;

/// Default target normalized FastCDC chunk size (32 KiB).
pub const DEFAULT_NORMAL_CHUNK_BYTES: u32 = 32 * 1024;

/// Default maximum normalized FastCDC chunk size (64 KiB).
pub const DEFAULT_MAX_CHUNK_BYTES: u32 = 64 * 1024;

/// Default minimum blob size before FastCDC chunking applies (128 KiB).
pub const DEFAULT_MIN_BLOB_BYTES: u64 = 128 * 1024;

/// On-disk magic prefix for FastCDC chunk manifest blobs.
pub(crate) const CDC_MANIFEST_MAGIC: &[u8; 8] = b"MNCDC01\0";

/// Byte length of the fixed `MNCDC01` manifest header.
pub(crate) const CDC_HEADER_LEN: usize = 24;

/// Byte length of each chunk entry in an `MNCDC01` manifest (32-byte digest + 8-byte length).
const CDC_ENTRY_LEN: usize = 40;

/// Maximum number of chunks permitted in a single manifest.
const MAX_CDC_CHUNKS: u32 = 65_536;

/// Deterministic 256-entry 64-bit Gear hash table seeded via SplitMix64.
const GEAR_TABLE: [u64; 256] = {
    let mut table = [0_u64; 256];
    let mut state = 0x4d4e_454d_4543_4443_u64;
    let mut index = 0_usize;
    while index < 256 {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut mixed = state;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        mixed ^= mixed >> 31;
        table[index] = mixed;
        index = index.saturating_add(1);
    }
    table
};

/// Configuration for Gear-hash FastCDC content-defined chunking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FastCdcConfig {
    min_chunk_bytes: u32,
    normal_chunk_bytes: u32,
    max_chunk_bytes: u32,
    min_blob_bytes: u64,
}

impl Default for FastCdcConfig {
    fn default() -> Self {
        Self {
            min_chunk_bytes: DEFAULT_MIN_CHUNK_BYTES,
            normal_chunk_bytes: DEFAULT_NORMAL_CHUNK_BYTES,
            max_chunk_bytes: DEFAULT_MAX_CHUNK_BYTES,
            min_blob_bytes: DEFAULT_MIN_BLOB_BYTES,
        }
    }
}

impl FastCdcConfig {
    /// Construct and validate a FastCDC chunking configuration.
    pub fn new(
        min_chunk_bytes: u32,
        normal_chunk_bytes: u32,
        max_chunk_bytes: u32,
        min_blob_bytes: u64,
    ) -> crate::error::Result<Self> {
        if min_chunk_bytes < MIN_FASTCDC_CHUNK_BYTES {
            return Err(crate::error::Failure::InvalidCommand(format!(
                "FastCDC minimum chunk size {min_chunk_bytes} is below {MIN_FASTCDC_CHUNK_BYTES}"
            )));
        }
        if normal_chunk_bytes < min_chunk_bytes || max_chunk_bytes < normal_chunk_bytes {
            return Err(crate::error::Failure::InvalidCommand(
                "FastCDC chunk sizes must satisfy min <= normal <= max".to_owned(),
            ));
        }
        if max_chunk_bytes > MAX_FASTCDC_CHUNK_BYTES {
            return Err(crate::error::Failure::InvalidCommand(format!(
                "FastCDC maximum chunk size {max_chunk_bytes} exceeds {MAX_FASTCDC_CHUNK_BYTES}"
            )));
        }
        if !normal_chunk_bytes.is_power_of_two() {
            return Err(crate::error::Failure::InvalidCommand(
                "FastCDC normal chunk size must be a power of two".to_owned(),
            ));
        }
        Ok(Self {
            min_chunk_bytes,
            normal_chunk_bytes,
            max_chunk_bytes,
            min_blob_bytes,
        })
    }

    /// Minimum chunk size in bytes.
    pub const fn min_chunk_bytes(self) -> u32 {
        self.min_chunk_bytes
    }

    /// Normalized target chunk size in bytes.
    pub const fn normal_chunk_bytes(self) -> u32 {
        self.normal_chunk_bytes
    }

    /// Maximum chunk size in bytes.
    pub const fn max_chunk_bytes(self) -> u32 {
        self.max_chunk_bytes
    }

    /// Minimum blob byte length required before chunking is applied.
    pub const fn min_blob_bytes(self) -> u64 {
        self.min_blob_bytes
    }

    /// Return this configuration with a custom `min_blob_bytes` threshold.
    pub const fn with_min_blob_bytes(mut self, min_blob_bytes: u64) -> Self {
        self.min_blob_bytes = min_blob_bytes;
        self
    }

    fn validate(self) -> crate::error::Result<()> {
        let _ = Self::new(
            self.min_chunk_bytes,
            self.normal_chunk_bytes,
            self.max_chunk_bytes,
            self.min_blob_bytes,
        )?;
        Ok(())
    }
}

/// On-disk chunking policy for newly staged `source-bytes` blobs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum BlobChunking {
    /// Store blobs as single files (default).
    #[default]
    None,
    /// Split blobs at or above `FastCdcConfig::min_blob_bytes()` using
    /// deterministic Gear-hash FastCDC and store a chunk manifest plus
    /// content-addressed chunks.
    FastCdc(FastCdcConfig),
}

/// Byte span of one FastCDC chunk inside an uncompressed blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkSpan {
    pub offset_bytes: u64,
    pub length_bytes: u64,
}

/// Partition `bytes` into deterministic normalized FastCDC chunk spans.
pub fn fastcdc_chunk_spans(
    bytes: &[u8],
    config: FastCdcConfig,
) -> crate::error::Result<Vec<ChunkSpan>> {
    config.validate()?;
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let mut spans = Vec::new();
    let mut offset_bytes = 0_usize;
    while offset_bytes < bytes.len() {
        let chunk_len = next_cut(&bytes[offset_bytes..], config)?;
        debug_assert!(chunk_len > 0 && offset_bytes.saturating_add(chunk_len) <= bytes.len());
        let span_offset = u64::try_from(offset_bytes).map_err(|_| {
            crate::error::Failure::InvalidCommand("chunk offset exceeds u64".to_owned())
        })?;
        let span_len = u64::try_from(chunk_len).map_err(|_| {
            crate::error::Failure::InvalidCommand("chunk length exceeds u64".to_owned())
        })?;
        spans.push(ChunkSpan {
            offset_bytes: span_offset,
            length_bytes: span_len,
        });
        offset_bytes = offset_bytes.saturating_add(chunk_len);
    }
    Ok(spans)
}

/// Compute the next normalized FastCDC cut length within `slice`.
fn next_cut(slice: &[u8], config: FastCdcConfig) -> crate::error::Result<usize> {
    let min = usize::try_from(config.min_chunk_bytes).map_err(|_| {
        crate::error::Failure::InvalidCommand("FastCDC min chunk size exceeds usize".to_owned())
    })?;
    if slice.len() <= min {
        return Ok(slice.len());
    }
    let max = usize::try_from(config.max_chunk_bytes)
        .map_err(|_| {
            crate::error::Failure::InvalidCommand("FastCDC max chunk size exceeds usize".to_owned())
        })?
        .min(slice.len());
    let normal = usize::try_from(config.normal_chunk_bytes)
        .map_err(|_| {
            crate::error::Failure::InvalidCommand(
                "FastCDC normal chunk size exceeds usize".to_owned(),
            )
        })?
        .min(max);
    debug_assert!(min <= normal && normal <= max && max <= slice.len());

    // Normalized chunking (NC-2, Xia et al. 2016): stronger mask before `normal`
    // suppresses tiny chunks; weaker mask after `normal` avoids hitting `max`.
    let avg_bits = config.normal_chunk_bytes.ilog2().clamp(4, 30);
    let strong_bits = avg_bits.saturating_add(2).min(60);
    let weak_bits = avg_bits.saturating_sub(2).max(1);
    let mask_s = !0_u64 << (64_u32.saturating_sub(strong_bits));
    let mask_l = !0_u64 << (64_u32.saturating_sub(weak_bits));

    // Warm up the 64-byte Gear window right before `min` so cut decisions at
    // `min` depend only on bytes inside the candidate chunk.
    let warmup_start = min.saturating_sub(64);
    let mut fp = 0_u64;
    for &byte in &slice[warmup_start..min] {
        fp = (fp << 1).wrapping_add(GEAR_TABLE[usize::from(byte)]);
    }
    for (index, &byte) in slice[min..normal].iter().enumerate() {
        fp = (fp << 1).wrapping_add(GEAR_TABLE[usize::from(byte)]);
        if (fp & mask_s) == 0 {
            return Ok(min.saturating_add(index).saturating_add(1));
        }
    }
    for (index, &byte) in slice[normal..max].iter().enumerate() {
        fp = (fp << 1).wrapping_add(GEAR_TABLE[usize::from(byte)]);
        if (fp & mask_l) == 0 {
            return Ok(normal.saturating_add(index).saturating_add(1));
        }
    }
    Ok(max)
}

/// Encode a deterministic `MNCDC01` chunk manifest for `chunks`.
pub(crate) fn encode_cdc_manifest(
    digest: mneme_core::ContentDigest,
    uncompressed_len: u64,
    chunks: &[([u8; 32], u64)],
) -> crate::error::Result<Vec<u8>> {
    let chunk_count =
        u32::try_from(chunks.len()).map_err(|_| crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "FastCDC chunk count exceeds u32".to_owned(),
        })?;
    if chunk_count > MAX_CDC_CHUNKS {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: format!("FastCDC chunk count {chunk_count} exceeds maximum {MAX_CDC_CHUNKS}"),
        });
    }
    let total_bytes = CDC_HEADER_LEN.saturating_add(chunks.len().saturating_mul(CDC_ENTRY_LEN));
    let mut out = Vec::with_capacity(total_bytes);
    out.extend_from_slice(CDC_MANIFEST_MAGIC);
    out.extend_from_slice(&uncompressed_len.to_le_bytes());
    out.extend_from_slice(&chunk_count.to_le_bytes());
    out.extend_from_slice(&0_u32.to_le_bytes());
    for (chunk_hash, chunk_len) in chunks {
        out.extend_from_slice(chunk_hash);
        out.extend_from_slice(&chunk_len.to_le_bytes());
    }
    Ok(out)
}

fn parse_cdc_header(
    digest: mneme_core::ContentDigest,
    disk_bytes: &[u8],
    max_total_bytes: u64,
) -> crate::error::Result<(u64, usize)> {
    let Some(header) = disk_bytes.get(..CDC_HEADER_LEN) else {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "chunk manifest header is truncated".to_owned(),
        });
    };
    if &header[..CDC_MANIFEST_MAGIC.len()] != CDC_MANIFEST_MAGIC {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "stored bytes do not hash to the committed digest".to_owned(),
        });
    }
    let expected_len = read_u64_le(&header[8..16]).ok_or_else(|| corrupt_manifest(digest))?;
    if expected_len > max_total_bytes {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "chunk manifest exceeds maximum supported size".to_owned(),
        });
    }
    let chunk_count = read_u32_le(&header[16..20]).ok_or_else(|| corrupt_manifest(digest))?;
    let flags = read_u32_le(&header[20..24]).ok_or_else(|| corrupt_manifest(digest))?;
    if flags != 0 {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: format!("unsupported chunk manifest flags {flags}"),
        });
    }
    if chunk_count > MAX_CDC_CHUNKS {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "chunk manifest chunk count exceeds maximum".to_owned(),
        });
    }
    let chunk_count_usize = usize::try_from(chunk_count).map_err(|_| corrupt_manifest(digest))?;
    let expected_manifest_bytes = CDC_HEADER_LEN
        .checked_add(chunk_count_usize.saturating_mul(CDC_ENTRY_LEN))
        .ok_or_else(|| corrupt_manifest(digest))?;
    if disk_bytes.len() != expected_manifest_bytes {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "chunk manifest length does not match chunk count".to_owned(),
        });
    }
    Ok((expected_len, chunk_count_usize))
}

/// Parse and validate an `MNCDC01` chunk manifest, returning `(expected_len, chunks)`.
pub(crate) fn parse_cdc_manifest(
    digest: mneme_core::ContentDigest,
    disk_bytes: &[u8],
    max_total_bytes: u64,
) -> crate::error::Result<(u64, Vec<(mneme_core::ContentDigest, u64)>)> {
    let (expected_len, chunk_count_usize) = parse_cdc_header(digest, disk_bytes, max_total_bytes)?;
    let mut chunks = Vec::with_capacity(chunk_count_usize);
    let mut total_len = 0_u64;
    let body = &disk_bytes[CDC_HEADER_LEN..];
    let (entries, remainder) = body.as_chunks::<CDC_ENTRY_LEN>();
    debug_assert!(remainder.is_empty());
    for entry in entries {
        let Ok(chunk_hash) = <[u8; 32]>::try_from(&entry[..32]) else {
            return Err(corrupt_manifest(digest));
        };
        let chunk_len = read_u64_le(&entry[32..40]).ok_or_else(|| corrupt_manifest(digest))?;
        if chunk_len == 0 || chunk_len > u64::from(MAX_FASTCDC_CHUNK_BYTES) {
            return Err(crate::error::Failure::CorruptBlob {
                digest: digest.to_hex(),
                reason: "chunk manifest contains out-of-range chunk length".to_owned(),
            });
        }
        total_len =
            total_len
                .checked_add(chunk_len)
                .ok_or_else(|| crate::error::Failure::CorruptBlob {
                    digest: digest.to_hex(),
                    reason: "chunk manifest lengths overflow u64".to_owned(),
                })?;
        let chunk_digest = mneme_core::ContentDigest::from_parts(
            mneme_core::HashAlgorithm::Sha256,
            mneme_core::EncodingProfile::RawBytesV1,
            mneme_core::ValueBoundary::SourceBytes,
            chunk_hash,
        )
        .map_err(|reason| crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: reason.to_owned(),
        })?;
        chunks.push((chunk_digest, chunk_len));
    }
    if total_len != expected_len {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "chunk manifest total length does not match header".to_owned(),
        });
    }
    Ok((expected_len, chunks))
}

fn read_u64_le(bytes: &[u8]) -> Option<u64> {
    <[u8; 8]>::try_from(bytes).ok().map(u64::from_le_bytes)
}

fn read_u32_le(bytes: &[u8]) -> Option<u32> {
    <[u8; 4]>::try_from(bytes).ok().map(u32::from_le_bytes)
}

fn corrupt_manifest(digest: mneme_core::ContentDigest) -> crate::error::Failure {
    crate::error::Failure::CorruptBlob {
        digest: digest.to_hex(),
        reason: "chunk manifest header is malformed".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_asciidoc(lines: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(lines * 64);
        for index in 0..lines {
            // Mix index digits with deterministic LCG-derived tokens so Gear
            // hashes vary naturally across the document.
            let mixed = (index as u64)
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let line = format!(
                "== Section {index:05} ({mixed:016x})\nParagraph body for line {index} with token {:08x}.\n",
                (mixed >> 32) & 0xffff_ffff
            );
            out.extend_from_slice(line.as_bytes());
        }
        out
    }

    #[test]
    fn fastcdc_chunks_are_deterministic_and_within_normalized_bounds() {
        let doc = synthetic_asciidoc(30_000); // ~2.6 MiB
        assert!(doc.len() > 2 * 1024 * 1024);

        let config = FastCdcConfig::default();
        let first = fastcdc_chunk_spans(&doc, config).expect("chunk first");
        let second = fastcdc_chunk_spans(&doc, config).expect("chunk second");
        assert_eq!(first, second);
        assert!(
            first.len() >= 32,
            "expected multi-chunk split, got {}",
            first.len()
        );

        let mut covered = 0_u64;
        for (index, span) in first.iter().enumerate() {
            assert_eq!(span.offset_bytes, covered);
            if index + 1 < first.len() {
                assert!(
                    span.length_bytes >= u64::from(config.min_chunk_bytes()),
                    "non-final chunk {index} length {} below 16KiB",
                    span.length_bytes
                );
                assert!(
                    span.length_bytes <= u64::from(config.max_chunk_bytes()),
                    "non-final chunk {index} length {} above 64KiB",
                    span.length_bytes
                );
            } else {
                assert!(span.length_bytes > 0);
                assert!(span.length_bytes <= u64::from(config.max_chunk_bytes()));
            }
            covered = covered.saturating_add(span.length_bytes);
        }
        assert_eq!(covered, doc.len() as u64);
    }

    #[test]
    fn fastcdc_resynchronizes_after_single_line_edit() {
        let doc_v1 = synthetic_asciidoc(30_000);
        let needle = b"== Section 15000";
        let edit_pos = doc_v1
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("needle");
        let mut doc_v2 = Vec::with_capacity(doc_v1.len() + 32);
        doc_v2.extend_from_slice(&doc_v1[..edit_pos]);
        doc_v2.extend_from_slice(b"== Section 15000 [REVISED LINE]\n");
        let line_end = doc_v1[edit_pos..]
            .iter()
            .position(|&byte| byte == b'\n')
            .expect("newline");
        doc_v2.extend_from_slice(&doc_v1[edit_pos + line_end + 1..]);

        let config = FastCdcConfig::default();
        let spans_v1 = fastcdc_chunk_spans(&doc_v1, config).expect("v1 spans");
        let spans_v2 = fastcdc_chunk_spans(&doc_v2, config).expect("v2 spans");

        let hashes_v1: std::collections::BTreeSet<[u8; 32]> = spans_v1
            .iter()
            .map(|span| {
                let start = usize::try_from(span.offset_bytes).expect("offset fits usize");
                let len = usize::try_from(span.length_bytes).expect("length fits usize");
                crate::payload::sha256(&doc_v1[start..start.saturating_add(len)])
            })
            .collect();
        let shared = spans_v2
            .iter()
            .filter(|span| {
                let start = usize::try_from(span.offset_bytes).expect("offset fits usize");
                let len = usize::try_from(span.length_bytes).expect("length fits usize");
                hashes_v1.contains(&crate::payload::sha256(
                    &doc_v2[start..start.saturating_add(len)],
                ))
            })
            .count();

        assert!(
            shared * 10 >= spans_v2.len() * 9,
            "expected >=90% deduplicated chunks after 1-line edit, got {shared}/{}",
            spans_v2.len()
        );
    }

    #[test]
    fn fastcdc_manifest_rejects_corruption() {
        let payload = b"manifest test payload";
        let digest = mneme_core::ContentDigest::of_source_bytes(payload);
        let chunk_hash = crate::payload::sha256(payload);
        let encoded = encode_cdc_manifest(
            digest,
            payload.len() as u64,
            &[(chunk_hash, payload.len() as u64)],
        )
        .expect("encode");
        let (len, parsed) = parse_cdc_manifest(digest, &encoded, 1024).expect("parse");
        assert_eq!(len, payload.len() as u64);
        assert_eq!(parsed.len(), 1);

        // Truncated header.
        assert!(parse_cdc_manifest(digest, &encoded[..12], 1024).is_err());

        // Non-zero flags.
        let mut bad_flags = encoded.clone();
        bad_flags[20] = 1;
        assert!(parse_cdc_manifest(digest, &bad_flags, 1024).is_err());

        // Mismatched total length.
        let mut bad_len = encoded.clone();
        bad_len[8] = 99;
        assert!(parse_cdc_manifest(digest, &bad_len, 1024).is_err());

        // Trailing garbage.
        let mut trailing = encoded;
        trailing.push(0);
        assert!(parse_cdc_manifest(digest, &trailing, 1024).is_err());
    }
}
