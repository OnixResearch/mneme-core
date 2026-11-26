//! `bao-tree` outboard Merkle trees for `O(log N)` BLAKE3 span proofs.
//!
//! Large BLAKE3 blobs (`>= THRESHOLD_BYTES`) store an optional pre-order
//! `bao-tree` outboard sidecar alongside the canonical blob at
//! `blobs/blake3/<ab>/<hex>.obao4` using 16 KiB chunk groups (`BlockSize(4)`),
//! wire-compatible with `iroh-blobs` verified streaming. Canonical blob bytes
//! and `ContentDigest` are never mutated.

use std::io::Read;

/// Log base 2 of the number of 1 KiB BLAKE3 chunks per chunk group (16 KiB).
pub const CHUNK_GROUP_LOG: u8 = 4;

/// Chunk group size (`16 KiB`), matching `iroh-blobs` verified streaming.
pub const BLOCK_SIZE: bao_tree::BlockSize = bao_tree::BlockSize::from_chunk_log(CHUNK_GROUP_LOG);

/// Minimum BLAKE3 blob length in bytes before an outboard sidecar is staged.
pub const THRESHOLD_BYTES: u64 = 64 * 1024;

/// File extension of a pre-order 16 KiB chunk-group outboard sidecar.
pub const EXTENSION: &str = "obao4";

const STREAM_BUFFER_BYTES: usize = 64 * 1024;
const TEMP_PREFIX: &str = ".mneme-tmp-";
const HASH_BYTES: usize = 32;

struct SpanQuery {
    digest: mneme_core::ContentDigest,
    blob_bytes: u64,
    range: std::ops::Range<u64>,
}

struct EncodedProof<'a> {
    root: bao_tree::blake3::Hash,
    tree: bao_tree::BaoTree,
    encoded: &'a [u8],
    group_ranges: &'a bao_tree::ChunkRangesRef,
}

/// Filesystem path of the optional `bao-tree` outboard sidecar for `digest`.
pub fn path(root: &std::path::Path, digest: mneme_core::ContentDigest) -> std::path::PathBuf {
    let mut blob = crate::payload::blob_path(root, digest);
    blob.set_extension(EXTENSION);
    blob
}

/// Read and verify `range` (`[start, end)`) of `digest` without loading the
/// whole blob when a BLAKE3 `bao-tree` outboard is present.
///
/// Falls back cleanly to streaming full-blob verification for small BLAKE3
/// blobs without outboards and for legacy SHA-256 blobs. Fails closed if a
/// present outboard is malformed or disagrees with the BLAKE3 root digest.
pub fn verify_span_range(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
    range: std::ops::Range<u64>,
) -> crate::error::Result<Vec<u8>> {
    if range.start > range.end {
        return Err(crate::error::Failure::InvalidCommand(
            "span range end precedes its start".to_owned(),
        ));
    }
    let blob_file_path = crate::payload::blob_path(root, digest);
    let file = open_regular_blob(&blob_file_path, digest)?;
    let blob_bytes = file_len_bytes(&file, &blob_file_path)?;
    if range.end > blob_bytes {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "stored bytes end before the requested range".to_owned(),
        });
    }
    debug_assert!(range.start <= range.end);
    debug_assert!(range.end <= blob_bytes);
    let query = SpanQuery {
        digest,
        blob_bytes,
        range,
    };
    if digest.algorithm() != mneme_core::HashAlgorithm::Blake3 {
        return verify_full_and_slice(file, &blob_file_path, &query);
    }
    verify_blake3_span(root, &file, &blob_file_path, &query)
}

/// Ensure a sidecar exists for a large BLAKE3 blob (`>= THRESHOLD_BYTES`).
///
/// Returns `Ok(true)` if a sidecar is present (already on disk or freshly
/// built from the verified canonical blob), and `Ok(false)` when `digest` is
/// non-BLAKE3 or smaller than `THRESHOLD_BYTES`. Fails closed if an existing
/// sidecar is non-regular or has the wrong byte length.
pub fn ensure(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
) -> crate::error::Result<bool> {
    let Some((file, blob_bytes)) = open_large_blake3_blob(root, digest)? else {
        return Ok(false);
    };
    let ob_path = path(root, digest);
    let tree = bao_tree::BaoTree::new(blob_bytes, BLOCK_SIZE);
    match std::fs::symlink_metadata(&ob_path) {
        Ok(metadata) => {
            check_sidecar_metadata(&metadata, digest, tree.outboard_size())?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let sidecar_bytes = compute_from_reader(file, blob_bytes, digest)?;
            write_atomic(root, digest, &sidecar_bytes)?;
            Ok(true)
        }
        Err(error) => Err(crate::error::Failure::io(&ob_path, error)),
    }
}

/// Deterministically rebuild the `bao-tree` sidecar from the canonical blob.
///
/// Verifies the canonical blob against `digest` before atomically replacing any
/// missing or corrupt sidecar. Returns `Ok(false)` for non-BLAKE3 blobs or
/// blobs smaller than `THRESHOLD_BYTES`.
pub fn rebuild(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
) -> crate::error::Result<bool> {
    let Some((file, blob_bytes)) = open_large_blake3_blob(root, digest)? else {
        return Ok(false);
    };
    let sidecar_bytes = compute_from_reader(file, blob_bytes, digest)?;
    write_atomic(root, digest, &sidecar_bytes)?;
    Ok(true)
}

/// Stage a sidecar alongside a newly staged large BLAKE3 blob.
pub(crate) fn stage_if_large(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
    bytes: &[u8],
) -> crate::error::Result<()> {
    if digest.algorithm() != mneme_core::HashAlgorithm::Blake3 {
        return Ok(());
    }
    let size_bytes = u64::try_from(bytes.len())
        .map_err(|_| crate::error::Failure::ValueOutOfRange("blob size"))?;
    if size_bytes < THRESHOLD_BYTES {
        return Ok(());
    }
    let expected = compute_from_reader(std::io::Cursor::new(bytes), size_bytes, digest)?;
    install_staged_sidecar(root, digest, &expected)
}

/// Compute the deterministic `bao-tree` pre-order sidecar from `reader`.
pub(crate) fn compute_from_reader(
    reader: impl Read,
    size_bytes: u64,
    digest: mneme_core::ContentDigest,
) -> crate::error::Result<Vec<u8>> {
    assert_eq!(digest.algorithm(), mneme_core::HashAlgorithm::Blake3);
    let tree = bao_tree::BaoTree::new(size_bytes, BLOCK_SIZE);
    let sidecar_len = usize::try_from(tree.outboard_size())
        .map_err(|_| crate::error::Failure::ValueOutOfRange("bao-tree outboard size"))?;
    let mut mem = bao_tree::io::outboard::PreOrderMemOutboard {
        root: bao_tree::blake3::Hash::from([0_u8; HASH_BYTES]),
        tree,
        data: vec![0_u8; sidecar_len],
    };
    let root = bao_tree::io::sync::outboard(reader, tree, &mut mem).map_err(|error| {
        crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: format!("failed to compute bao-tree outboard: {error}"),
        }
    })?;
    if root.as_bytes() != digest.as_bytes() {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "canonical blob bytes do not match BLAKE3 digest".to_owned(),
        });
    }
    assert_eq!(mem.data.len(), sidecar_len);
    Ok(mem.data)
}

/// Remove the companion sidecar file for `blob_path`, if one exists.
pub(crate) fn remove_for_blob_path(blob_path: &std::path::Path) -> crate::error::Result<()> {
    let mut ob_path = blob_path.to_path_buf();
    ob_path.set_extension(EXTENSION);
    match std::fs::remove_file(&ob_path) {
        Ok(()) => {
            if let Some(parent) = ob_path.parent() {
                crate::payload::flush_directory(parent)?;
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(crate::error::Failure::io(&ob_path, error)),
    }
}

/// Verify an on-disk sidecar against the canonical blob file at `blob_path`.
pub(crate) fn verify_matches_blob(
    blob_path: &std::path::Path,
    ob_path: &std::path::Path,
    digest: mneme_core::ContentDigest,
    expected_blob_bytes: u64,
) -> std::result::Result<(), String> {
    let file = open_regular_blob(blob_path, digest).map_err(|error| error.to_string())?;
    let actual_bytes = file_len_bytes(&file, blob_path).map_err(|error| error.to_string())?;
    if actual_bytes != expected_blob_bytes {
        return Err(format!(
            "canonical blob length {actual_bytes} differs from expected {expected_blob_bytes}"
        ));
    }
    let expected = compute_from_reader(file, expected_blob_bytes, digest)
        .map_err(|error| error.to_string())?;
    let actual = std::fs::read(ob_path).map_err(|error| error.to_string())?;
    if actual != expected {
        return Err("bao-tree outboard Merkle tree does not match canonical blob".to_owned());
    }
    Ok(())
}

fn open_large_blake3_blob(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
) -> crate::error::Result<Option<(std::fs::File, u64)>> {
    if digest.algorithm() != mneme_core::HashAlgorithm::Blake3 {
        return Ok(None);
    }
    let blob_file_path = crate::payload::blob_path(root, digest);
    let file = open_regular_blob(&blob_file_path, digest)?;
    let blob_bytes = file_len_bytes(&file, &blob_file_path)?;
    if blob_bytes < THRESHOLD_BYTES {
        return Ok(None);
    }
    Ok(Some((file, blob_bytes)))
}

fn install_staged_sidecar(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
    expected: &[u8],
) -> crate::error::Result<()> {
    debug_assert_eq!(digest.algorithm(), mneme_core::HashAlgorithm::Blake3);
    debug_assert!(!expected.is_empty());
    let ob_path = path(root, digest);
    match std::fs::symlink_metadata(&ob_path) {
        Ok(metadata) => {
            check_sidecar_metadata(&metadata, digest, expected_len_u64(expected)?)?;
            let existing = std::fs::read(&ob_path)
                .map_err(|error| crate::error::Failure::io(&ob_path, error))?;
            if existing != expected {
                return Err(crate::error::Failure::CorruptBlob {
                    digest: digest.to_hex(),
                    reason: "existing bao-tree outboard does not match canonical blob".to_owned(),
                });
            }
            if let Some(parent) = ob_path.parent() {
                crate::payload::flush_directory(parent)?;
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_atomic(root, digest, expected)
        }
        Err(error) => Err(crate::error::Failure::io(&ob_path, error)),
    }
}

fn verify_blake3_span(
    root: &std::path::Path,
    file: &std::fs::File,
    blob_file_path: &std::path::Path,
    query: &SpanQuery,
) -> crate::error::Result<Vec<u8>> {
    debug_assert_eq!(query.digest.algorithm(), mneme_core::HashAlgorithm::Blake3);
    debug_assert!(query.range.end <= query.blob_bytes);
    let ob_path = path(root, query.digest);
    let tree = bao_tree::BaoTree::new(query.blob_bytes, BLOCK_SIZE);
    let ob_meta = match std::fs::symlink_metadata(&ob_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let owned = file
                .try_clone()
                .map_err(|error| crate::error::Failure::io(blob_file_path, error))?;
            return verify_full_and_slice(owned, blob_file_path, query);
        }
        Err(error) => return Err(crate::error::Failure::io(&ob_path, error)),
    };
    check_sidecar_metadata(&ob_meta, query.digest, tree.outboard_size())?;
    if query.range.start == query.range.end {
        return verify_empty_blake3_span(query);
    }
    let ob_file = open_regular_sidecar(&ob_path, query.digest)?;
    let opened_bytes = file_len_bytes(&ob_file, &ob_path)?;
    if opened_bytes != tree.outboard_size() {
        return Err(crate::error::Failure::CorruptBlob {
            digest: query.digest.to_hex(),
            reason: format!(
                "bao-tree outboard length {opened_bytes} differs from expected {}",
                tree.outboard_size()
            ),
        });
    }
    verify_range_sidecar(file, &ob_file, tree, query)
}

fn verify_empty_blake3_span(query: &SpanQuery) -> crate::error::Result<Vec<u8>> {
    if query.blob_bytes == 0 && !query.digest.verify_source_bytes(&[]) {
        return Err(crate::error::Failure::CorruptBlob {
            digest: query.digest.to_hex(),
            reason: "empty blob does not match BLAKE3 digest".to_owned(),
        });
    }
    Ok(Vec::new())
}

fn verify_range_sidecar(
    blob_file: &std::fs::File,
    sidecar_file: &std::fs::File,
    tree: bao_tree::BaoTree,
    query: &SpanQuery,
) -> crate::error::Result<Vec<u8>> {
    assert!(query.range.start < query.range.end);
    assert!(query.range.end <= query.blob_bytes);
    let root = bao_tree::blake3::Hash::from(*query.digest.as_bytes());
    let outboard = bao_tree::io::outboard::PreOrderOutboard {
        root,
        tree,
        data: sidecar_file,
    };
    let byte_ranges = bao_tree::ByteRanges::from(query.range.clone());
    let chunk_ranges = bao_tree::io::round_up_to_chunks(&byte_ranges);
    let group_ranges = bao_tree::io::round_up_to_chunks_groups(chunk_ranges, BLOCK_SIZE);
    let mut encoded = Vec::new();
    bao_tree::io::sync::encode_ranges_validated(blob_file, &outboard, &group_ranges, &mut encoded)
        .map_err(|error| crate::error::Failure::CorruptBlob {
            digest: query.digest.to_hex(),
            reason: format!("bao-tree range verification failed: {error}"),
        })?;
    let proof = EncodedProof {
        root,
        tree,
        encoded: &encoded,
        group_ranges: &group_ranges,
    };
    extract_verified_slice(&proof, query)
}

fn extract_verified_slice(
    proof: &EncodedProof<'_>,
    query: &SpanQuery,
) -> crate::error::Result<Vec<u8>> {
    let span_bytes = query.range.end.saturating_sub(query.range.start);
    let out_len = usize::try_from(span_bytes)
        .map_err(|_| crate::error::Failure::ValueOutOfRange("span range length"))?;
    debug_assert!(query.range.start < query.range.end);
    debug_assert!(out_len > 0);
    let mut result = Vec::with_capacity(out_len);
    let decoder = bao_tree::io::sync::DecodeResponseIter::new(
        proof.root,
        proof.tree,
        std::io::Cursor::new(proof.encoded),
        proof.group_ranges,
    );
    for item in decoder {
        let item = item.map_err(|error| crate::error::Failure::CorruptBlob {
            digest: query.digest.to_hex(),
            reason: format!("bao-tree range decode failed: {error}"),
        })?;
        if let bao_tree::io::BaoContentItem::Leaf(leaf) = item {
            append_overlap(&mut result, leaf.offset, &leaf.data, &query.range)?;
        }
    }
    if result.len() != out_len {
        return Err(crate::error::Failure::CorruptBlob {
            digest: query.digest.to_hex(),
            reason: "verified range bytes did not cover requested span".to_owned(),
        });
    }
    Ok(result)
}

fn append_overlap(
    out: &mut Vec<u8>,
    chunk_offset_bytes: u64,
    chunk_bytes: &[u8],
    range: &std::ops::Range<u64>,
) -> crate::error::Result<()> {
    let chunk_len_bytes = u64::try_from(chunk_bytes.len())
        .map_err(|_| crate::error::Failure::ValueOutOfRange("chunk length"))?;
    let chunk_end_bytes = chunk_offset_bytes.saturating_add(chunk_len_bytes);
    let copy_start_bytes = range.start.max(chunk_offset_bytes);
    let copy_end_bytes = range.end.min(chunk_end_bytes);
    if copy_start_bytes < copy_end_bytes {
        let rel_start = usize::try_from(copy_start_bytes.saturating_sub(chunk_offset_bytes))
            .map_err(|_| crate::error::Failure::ValueOutOfRange("slice offset"))?;
        let rel_end = usize::try_from(copy_end_bytes.saturating_sub(chunk_offset_bytes))
            .map_err(|_| crate::error::Failure::ValueOutOfRange("slice offset"))?;
        out.extend_from_slice(&chunk_bytes[rel_start..rel_end]);
    }
    Ok(())
}

fn verify_full_and_slice(
    mut file: std::fs::File,
    file_path: &std::path::Path,
    query: &SpanQuery,
) -> crate::error::Result<Vec<u8>> {
    debug_assert!(query.range.start <= query.range.end);
    debug_assert!(query.range.end <= query.blob_bytes);
    let mut hasher = mneme_core::hashing::StreamingHasher::new(query.digest.algorithm());
    let mut buf = vec![0_u8; STREAM_BUFFER_BYTES];
    let mut offset_bytes = 0_u64;
    let out_len = usize::try_from(query.range.end.saturating_sub(query.range.start))
        .map_err(|_| crate::error::Failure::ValueOutOfRange("span range length"))?;
    let mut selected = Vec::with_capacity(out_len);
    loop {
        let read = file
            .read(&mut buf)
            .map_err(|error| crate::error::Failure::io(file_path, error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
        let read_bytes = u64::try_from(read)
            .map_err(|_| crate::error::Failure::ValueOutOfRange("read length"))?;
        append_overlap(&mut selected, offset_bytes, &buf[..read], &query.range)?;
        offset_bytes = offset_bytes.saturating_add(read_bytes);
    }
    let verification = FullBlobCheck {
        offset_bytes,
        actual_hash: hasher.finish(),
        selected_len: selected.len(),
        expected_len: out_len,
    };
    check_full_hash_and_len(&verification, query)?;
    Ok(selected)
}

struct FullBlobCheck {
    offset_bytes: u64,
    actual_hash: [u8; HASH_BYTES],
    selected_len: usize,
    expected_len: usize,
}

fn check_full_hash_and_len(check: &FullBlobCheck, query: &SpanQuery) -> crate::error::Result<()> {
    if check.offset_bytes != query.blob_bytes || check.actual_hash != *query.digest.as_bytes() {
        return Err(crate::error::Failure::CorruptBlob {
            digest: query.digest.to_hex(),
            reason: "stored bytes do not hash to the committed digest".to_owned(),
        });
    }
    if check.selected_len != check.expected_len {
        return Err(crate::error::Failure::CorruptBlob {
            digest: query.digest.to_hex(),
            reason: "stored bytes end before the requested range".to_owned(),
        });
    }
    Ok(())
}

fn check_sidecar_metadata(
    metadata: &std::fs::Metadata,
    digest: mneme_core::ContentDigest,
    expected_bytes: u64,
) -> crate::error::Result<()> {
    if !metadata.is_file() {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "bao-tree outboard path is not a regular file".to_owned(),
        });
    }
    if metadata.len() != expected_bytes {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: format!(
                "bao-tree outboard holds {} bytes; expected {expected_bytes}",
                metadata.len()
            ),
        });
    }
    Ok(())
}

fn expected_len_u64(bytes: &[u8]) -> crate::error::Result<u64> {
    u64::try_from(bytes.len())
        .map_err(|_| crate::error::Failure::ValueOutOfRange("outboard length"))
}

fn file_len_bytes(file: &std::fs::File, file_path: &std::path::Path) -> crate::error::Result<u64> {
    Ok(file
        .metadata()
        .map_err(|error| crate::error::Failure::io(file_path, error))?
        .len())
}

fn open_regular_blob(
    file_path: &std::path::Path,
    digest: mneme_core::ContentDigest,
) -> crate::error::Result<std::fs::File> {
    open_regular_with_missing(file_path, digest, || crate::error::Failure::MissingBlob {
        digest: digest.to_hex(),
    })
}

fn open_regular_sidecar(
    file_path: &std::path::Path,
    digest: mneme_core::ContentDigest,
) -> crate::error::Result<std::fs::File> {
    open_regular_with_missing(file_path, digest, || crate::error::Failure::CorruptBlob {
        digest: digest.to_hex(),
        reason: "bao-tree outboard vanished before read".to_owned(),
    })
}

fn open_regular_with_missing(
    file_path: &std::path::Path,
    digest: mneme_core::ContentDigest,
    on_not_found: impl FnOnce() -> crate::error::Failure,
) -> crate::error::Result<std::fs::File> {
    match std::fs::symlink_metadata(file_path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(non_regular_error(digest));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err(on_not_found()),
        Err(error) => return Err(crate::error::Failure::io(file_path, error)),
    }
    let file = std::fs::File::open(file_path)
        .map_err(|error| crate::error::Failure::io(file_path, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| crate::error::Failure::io(file_path, error))?;
    if !metadata.is_file() {
        return Err(non_regular_error(digest));
    }
    Ok(file)
}

fn non_regular_error(digest: mneme_core::ContentDigest) -> crate::error::Failure {
    crate::error::Failure::CorruptBlob {
        digest: digest.to_hex(),
        reason: "stored path is not a regular file".to_owned(),
    }
}

fn write_atomic(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
    sidecar_bytes: &[u8],
) -> crate::error::Result<()> {
    let target = path(root, digest);
    let parent = target.parent().ok_or_else(|| {
        crate::error::Failure::InvalidCommand("outboard path has no parent".to_owned())
    })?;
    crate::payload::create_directory_chain_flushed(parent)?;
    let staging = root.join(crate::payload::STAGING_DIRECTORY);
    crate::payload::create_directory_chain_flushed(&staging)?;
    let temporary = staging.join(format!("{TEMP_PREFIX}{}", crate::payload::random_hex(8)?));
    crate::payload::write_flushed(&temporary, sidecar_bytes)?;
    std::fs::rename(&temporary, &target)
        .map_err(|error| crate::error::Failure::io(&target, error))?;
    crate::payload::flush_directory(parent)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CountingReadAt {
        file: std::fs::File,
        bytes_read: std::sync::atomic::AtomicU64,
    }

    impl bao_tree::io::sync::ReadAt for CountingReadAt {
        fn read_at(&self, pos: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.file.read_at(pos, buf)?;
            self.bytes_read
                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
            Ok(n)
        }
    }

    #[test]
    fn verify_range_reads_only_covering_chunk_group() {
        let dir = tempfile::tempdir().expect("tempdir");
        let len_bytes = 3_usize * 1024 * 1024 + 517;
        let bytes: Vec<u8> = (0..len_bytes)
            .map(|i| {
                u8::try_from((i.wrapping_mul(17).wrapping_add(i >> 9)) & 0xff).expect("masked byte")
            })
            .collect();
        let digest = mneme_core::ContentDigest::of_source_bytes(&bytes);
        crate::payload::stage(dir.path(), digest, &bytes).expect("stage");

        let blob_reader = CountingReadAt {
            file: std::fs::File::open(crate::payload::blob_path(dir.path(), digest)).expect("blob"),
            bytes_read: std::sync::atomic::AtomicU64::new(0),
        };
        let ob_reader = CountingReadAt {
            file: std::fs::File::open(path(dir.path(), digest)).expect("outboard"),
            bytes_read: std::sync::atomic::AtomicU64::new(0),
        };

        let tree = bao_tree::BaoTree::new(bytes.len() as u64, BLOCK_SIZE);
        let root = bao_tree::blake3::Hash::from(*digest.as_bytes());
        let sidecar = bao_tree::io::outboard::PreOrderOutboard {
            root,
            tree,
            data: &ob_reader,
        };
        let range = 2_000_000_u64..2_000_256_u64;
        let group_ranges = bao_tree::io::round_up_to_chunks_groups(
            bao_tree::io::round_up_to_chunks(&bao_tree::ByteRanges::from(range.clone())),
            BLOCK_SIZE,
        );
        let mut encoded = Vec::new();
        bao_tree::io::sync::encode_ranges_validated(
            &blob_reader,
            &sidecar,
            &group_ranges,
            &mut encoded,
        )
        .expect("encode");

        let data_read = blob_reader
            .bytes_read
            .load(std::sync::atomic::Ordering::Relaxed);
        let ob_read = ob_reader
            .bytes_read
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(data_read, 16 * 1024);
        assert!(ob_read > 0, "ob_read={ob_read}");
        assert!(ob_read <= 1024, "ob_read={ob_read}");

        let query = SpanQuery {
            digest,
            blob_bytes: bytes.len() as u64,
            range: range.clone(),
        };
        let proof = EncodedProof {
            root,
            tree,
            encoded: &encoded,
            group_ranges: &group_ranges,
        };
        let extracted = extract_verified_slice(&proof, &query).expect("extract");
        let start = usize::try_from(range.start).expect("start");
        let end = usize::try_from(range.end).expect("end");
        assert_eq!(extracted, bytes[start..end]);
    }
}
