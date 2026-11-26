//! Durable blob storage and atomic working-file publication.
//!
//! Blobs are content addressed by cryptographic digest (BLAKE3 by default,
//! with SHA-256 retained for existing workspaces) and stored under
//! `blobs/<algorithm>/<first-two-hex>/<hex>`. Staging writes and flushes a temporary
//! file, verifies it, then renames it into place and flushes the directory.
//! Working files are replaced through a temporary file in the same directory,
//! so a reader never observes a partially written payload.
//!
//! A working path is written by any local process, so every read refuses
//! anything but a regular file, never follows a final symbolic link, and is
//! bounded by [`MAX_WORKING_FILE_BYTES`]. Replacement and purge first move the
//! existing entry aside (an atomic rename), so the content a decision is made
//! from cannot change between the check and the install or delete.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

use std::io::Read;
use std::io::Write;

use sha2::Digest;

const ZSTD_FRAME_MAGIC: &[u8; 8] = b"MNZSTD01";
const ZSTD_HEADER_LEN: usize = 16;
const ZSTD_DICT_FRAME_MAGIC: &[u8; 8] = b"MNZSTD02";
const ZSTD_DICT_HEADER_LEN: usize = 49;
const ZSTD_COMPRESSION_LEVEL: i32 = 3;
const MAX_DECOMPRESSED_BLOB_BYTES: u64 = 256 * 1024 * 1024;

/// On-disk compression policy for newly staged `source-bytes` blobs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum BlobCompression {
    /// Store blobs uncompressed (default).
    #[default]
    None,
    /// Compress compressible `source-bytes` blobs (`text/*`,
    /// `application/json`, `application/xml`, `application/preserves`)
    /// with zstd on disk while preserving uncompressed SHA-256 content
    /// identity.
    Zstd,
    /// Compress compressible `source-bytes` blobs with a pinned
    /// content-addressed zstd dictionary stored under `blobs/dicts/`.
    ZstdDictionary {
        dictionary: mneme_core::ContentDigest,
    },
}

/// Whether `media_type` names a compressible text or structured-text format.
pub fn is_compressible_media_type(media_type: &str) -> bool {
    let mime = media_type
        .split(';')
        .next()
        .map_or(media_type, str::trim)
        .trim();
    if mime.len() >= 5 && mime[..5].eq_ignore_ascii_case("text/") {
        return true;
    }
    mime.eq_ignore_ascii_case("application/json")
        || mime.eq_ignore_ascii_case("application/xml")
        || mime.eq_ignore_ascii_case("application/preserves")
        || mime.eq_ignore_ascii_case("application/x-preserves")
        || (mime.len() >= 5 && mime[mime.len().saturating_sub(5)..].eq_ignore_ascii_case("+json"))
        || (mime.len() >= 4 && mime[mime.len().saturating_sub(4)..].eq_ignore_ascii_case("+xml"))
        || (mime.len() >= 10
            && mime[mime.len().saturating_sub(10)..].eq_ignore_ascii_case("+preserves"))
}

/// Directory holding immutable blobs.
pub const BLOB_DIRECTORY: &str = "blobs";
/// Directory holding in-progress staged files.
pub const STAGING_DIRECTORY: &str = "staging";
/// Directory holding published working files.
pub const WORKING_DIRECTORY: &str = "working";
/// Store-owned directory holding one ownership lock file per logical job.
pub const JOB_DIRECTORY: &str = "jobs";
/// Chunks of large sources still arriving from another device. They sit
/// beside the blob store and never in it, so no part of an asset is a
/// canonical source before the whole of it is verified and committed.
pub const TRANSFER_DIRECTORY: &str = "transfers";
/// Workspace-root file naming a working tree other than `working/`: `..` for
/// the directory containing the workspace root, or the absolute path of a
/// folder elsewhere.
pub const WORKING_TREE_FILE: &str = "working-tree";

/// Where a workspace's working files live.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkingTree {
    /// The `working/` directory inside the workspace root.
    Internal,
    /// The directory containing the workspace root: a folder of notes that
    /// keeps its workspace in a hidden subdirectory. Hidden directories and
    /// files there, the workspace among them, are never working files.
    Parent,
    /// A folder of notes whose workspace lives elsewhere, by its absolute
    /// path: a folder on a file system without advisory locks, such as
    /// Android's shared storage. Hidden directories and files there are never
    /// working files.
    External(std::path::PathBuf),
}

impl WorkingTree {
    /// The layout of the workspace at `root`, read from its
    /// [`WORKING_TREE_FILE`].
    pub fn of(root: &std::path::Path) -> crate::error::Result<WorkingTree> {
        let marker = root.join(WORKING_TREE_FILE);
        match std::fs::read(&marker) {
            Ok(bytes) => WorkingTree::parse(bytes.trim_ascii()).ok_or_else(|| {
                crate::error::Failure::UnsupportedLayout(format!(
                    "{} must contain .. or an absolute folder path",
                    marker.display()
                ))
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(WorkingTree::Internal),
            Err(error) => Err(crate::error::Failure::io(&marker, error)),
        }
    }

    /// The layout a [`WORKING_TREE_FILE`] holding `content` records.
    fn parse(content: &[u8]) -> Option<WorkingTree> {
        if content == b".." {
            return Some(WorkingTree::Parent);
        }
        std::str::from_utf8(content)
            .ok()
            .map(std::path::PathBuf::from)
            .filter(|path| path.is_absolute())
            .map(WorkingTree::External)
    }

    /// What the [`WORKING_TREE_FILE`] of this layout holds, or `None` when the
    /// layout has no such file.
    pub(crate) fn marker(&self) -> crate::error::Result<Option<Vec<u8>>> {
        match self {
            WorkingTree::Internal => Ok(None),
            WorkingTree::Parent => Ok(Some(b"..\n".to_vec())),
            WorkingTree::External(folder) => {
                let text = folder
                    .to_str()
                    .filter(|_| folder.is_absolute())
                    .ok_or_else(|| {
                        crate::error::Failure::UnsupportedLayout(format!(
                            "{} is not an absolute UTF-8 folder path",
                            folder.display()
                        ))
                    })?;
                Ok(Some(format!("{text}\n").into_bytes()))
            }
        }
    }

    /// The working directory of the workspace at `root` in this layout.
    pub fn directory(&self, root: &std::path::Path) -> std::path::PathBuf {
        match self {
            WorkingTree::Internal => root.join(WORKING_DIRECTORY),
            WorkingTree::Parent => root.join(".."),
            WorkingTree::External(folder) => folder.clone(),
        }
    }

    /// Whether a canonical relative path may name a working file: every path in
    /// an internal tree, and in a folder of notes only a path without a hidden
    /// directory or file name.
    pub fn admits(&self, relative: &std::path::Path) -> bool {
        *self == WorkingTree::Internal
            || !relative
                .components()
                .any(|component| is_hidden_name(component.as_os_str()))
    }

    /// Whether a walk of this tree skips the directory named `name`.
    fn skips_directory(&self, name: &std::ffi::OsStr) -> bool {
        *self != WorkingTree::Internal && is_hidden_name(name)
    }
}

/// Whether a file or directory name starts with a dot.
fn is_hidden_name(name: &std::ffi::OsStr) -> bool {
    name.as_encoded_bytes().first() == Some(&b'.')
}

/// The working directory of the workspace at `root`.
pub fn working_directory(root: &std::path::Path) -> crate::error::Result<std::path::PathBuf> {
    Ok(WorkingTree::of(root)?.directory(root))
}

/// A validated working path and the working directory it lives under.
fn working_location(
    root: &std::path::Path,
    relative: &str,
) -> crate::error::Result<(std::path::PathBuf, std::path::PathBuf)> {
    let path = validate_relative_path(relative)?;
    let tree = WorkingTree::of(root)?;
    if !tree.admits(&path) {
        return Err(crate::error::Failure::PathEscapes(relative.to_owned()));
    }
    Ok((path, tree.directory(root)))
}
const TEMP_PREFIX: &str = ".mneme-tmp-";
const QUARANTINE_PREFIX: &str = ".mneme-quarantine-";

/// Largest working file the store reads into memory.
///
/// A working path may be written by any local process, so a read must be
/// bounded. A larger file is reported as an error instead of being loaded:
/// publication and purge compare hashes, and an oversized copy cannot be
/// verified without unbounded memory.
pub const MAX_WORKING_FILE_BYTES: u64 = 64 * 1024 * 1024;

// Linux `O_NOFOLLOW | O_NONBLOCK`. A checked path can be swapped for a FIFO
// between the metadata read and the open; these flags make the open fail
// instead of blocking forever on a FIFO, and refuse a final symbolic link.
// `O_NOFOLLOW` differs between architectures, so the value is given only where
// it is known; elsewhere the metadata checks before and after the open are the
// whole defence.
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "x86")))]
const OPEN_GUARD_FLAGS: i32 = 0o400000 | 0o4000;
#[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "arm")))]
const OPEN_GUARD_FLAGS: i32 = 0o100000 | 0o4000;

/// What a working path holds, read without following a final symbolic link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkingEntry {
    /// Nothing is there.
    Absent,
    /// A regular file with its exact bytes.
    Regular(Vec<u8>),
    /// A symbolic link, directory, FIFO, socket or device.
    NotRegular,
}

/// A staged blob's identity and length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StagedBlob {
    pub digest: mneme_core::ContentDigest,
    pub byte_length: u64,
}

/// SHA-256 of exact bytes.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(bytes).into()
}

/// BLAKE3 of exact bytes.
pub fn blake3(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// Hash exact bytes using the given digest algorithm.
pub fn hash_bytes(algorithm: mneme_core::HashAlgorithm, bytes: &[u8]) -> [u8; 32] {
    algorithm.hash_bytes(bytes)
}

/// Compute the digest bytes of `bytes` under `algorithm`.
pub(crate) fn hash_with_algorithm(algorithm: mneme_core::HashAlgorithm, bytes: &[u8]) -> [u8; 32] {
    hash_bytes(algorithm, bytes)
}

/// Random bytes from the operating system.
#[allow(unknown_lints, ambient_random)] // entropy is the blob-identity shell
pub fn random_bytes() -> crate::error::Result<[u8; 16]> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|error| crate::error::Failure::Random(error.to_string()))?;
    Ok(bytes)
}

/// Random lowercase hexadecimal text of `bytes` bytes.
pub fn random_hex(bytes: u32) -> crate::error::Result<String> {
    let capacity = usize::try_from(bytes).map_err(|_| {
        crate::error::Failure::InvalidCommand("hex output length exceeds usize".to_owned())
    })?;
    let mut output = String::with_capacity(capacity * 2);
    for _ in 0..bytes {
        let random = random_bytes()?;
        output.push_str(&format!("{:02x}", random[0]));
    }
    Ok(output)
}

/// Validate a canonical workspace-relative path.
///
/// The kernel predicate is the only path rule: one spelling per working file,
/// no empty, `.` or `..` segment, no leading or trailing separator, no NUL and
/// no backslash. Aliases such as `a//b` or `a/./b` are refused instead of being
/// normalized, so two command paths that name one file cannot both be accepted.
pub fn validate_relative_path(text: &str) -> crate::error::Result<std::path::PathBuf> {
    if !mneme_kernel::text::is_canonical_relative_path(text.as_bytes()) {
        return Err(crate::error::Failure::PathEscapes(text.to_owned()));
    }
    Ok(std::path::PathBuf::from(text))
}

/// The filesystem path for a blob digest.
pub fn blob_path(root: &std::path::Path, digest: mneme_core::ContentDigest) -> std::path::PathBuf {
    let hex = digest.to_hex();
    root.join(BLOB_DIRECTORY)
        .join(digest.algorithm().symbol())
        .join(&hex[0..2])
        .join(hex)
}

/// The directory of one pending transfer, kept under the key id of the device
/// that signed it. An owner is a key id, never a device's chosen name, so it
/// is always one path component.
pub fn transfer_path(
    root: &std::path::Path,
    owner: &str,
    digest: mneme_core::ContentDigest,
) -> crate::error::Result<std::path::PathBuf> {
    if parse_hex_32(owner).is_none() {
        return Err(crate::error::Failure::InvalidCommand(
            "a transfer owner is a 64-digit key id".to_owned(),
        ));
    }
    Ok(root
        .join(TRANSFER_DIRECTORY)
        .join(owner)
        .join(digest.to_hex()))
}

/// Read `length` bytes of a stored blob from `offset`, without the rest of it.
///
/// The caller checks what it reads against digests it already holds: a range
/// cannot be checked against the blob's own digest.
#[allow(unknown_lints, usize_in_public_api)] // a bounded in-memory read length
pub fn read_range(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
    offset: u64,
    length: usize,
) -> crate::error::Result<Vec<u8>> {
    let path = blob_path(root, digest);
    let mut file = open_blob_file(&path, digest)?;
    let magic = read_file_magic(&mut file, &path)?;
    if magic.as_ref() == Some(ZSTD_FRAME_MAGIC) || magic.as_ref() == Some(ZSTD_DICT_FRAME_MAGIC) {
        let decompressed = read(root, digest)?;
        return slice_range(digest, &decompressed, offset, length);
    }
    if magic.as_ref() == Some(crate::dedup::CDC_MANIFEST_MAGIC) {
        return read_cdc_range(root, &path, digest, offset, length);
    }
    read_raw_range(&mut file, &path, digest, offset, length)
}

fn open_blob_file(
    path: &std::path::Path,
    digest: mneme_core::ContentDigest,
) -> crate::error::Result<std::fs::File> {
    std::fs::File::open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            crate::error::Failure::MissingBlob {
                digest: digest.to_hex(),
            }
        } else {
            crate::error::Failure::io(path, error)
        }
    })
}

fn read_raw_range(
    file: &mut std::fs::File,
    path: &std::path::Path,
    digest: mneme_core::ContentDigest,
    offset_bytes: u64,
    length_bytes: usize,
) -> crate::error::Result<Vec<u8>> {
    std::io::Seek::seek(file, std::io::SeekFrom::Start(offset_bytes))
        .map_err(|error| crate::error::Failure::io(path, error))?;
    let mut bytes = vec![0; length_bytes];
    std::io::Read::read_exact(file, &mut bytes).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            crate::error::Failure::CorruptBlob {
                digest: digest.to_hex(),
                reason: "stored bytes end before the requested range".to_owned(),
            }
        } else {
            crate::error::Failure::io(path, error)
        }
    })?;
    Ok(bytes)
}

fn read_file_magic(
    file: &mut std::fs::File,
    path: &std::path::Path,
) -> crate::error::Result<Option<[u8; 8]>> {
    let mut prefix = [0_u8; 8];
    let mut read_so_far = 0_usize;
    while read_so_far < prefix.len() {
        let count = file
            .read(&mut prefix[read_so_far..])
            .map_err(|error| crate::error::Failure::io(path, error))?;
        if count == 0 {
            return Ok(None);
        }
        read_so_far = read_so_far.saturating_add(count);
    }
    Ok(Some(prefix))
}

fn read_cdc_range(
    root: &std::path::Path,
    path: &std::path::Path,
    digest: mneme_core::ContentDigest,
    offset_bytes: u64,
    length_bytes: usize,
) -> crate::error::Result<Vec<u8>> {
    let disk_bytes = std::fs::read(path).map_err(|error| crate::error::Failure::io(path, error))?;
    if hash_with_algorithm(digest.algorithm(), &disk_bytes) == *digest.as_bytes() {
        return slice_range(digest, &disk_bytes, offset_bytes, length_bytes);
    }
    let (expected_len_bytes, chunks) =
        crate::dedup::parse_cdc_manifest(digest, &disk_bytes, MAX_DECOMPRESSED_BLOB_BYTES)?;
    let end_bytes = checked_range_end(
        digest,
        RangeBounds {
            offset_bytes,
            length_bytes,
            expected_len_bytes,
        },
    )?;
    if length_bytes == 0 {
        return Ok(Vec::new());
    }
    debug_assert!(end_bytes <= expected_len_bytes);
    debug_assert!(offset_bytes < end_bytes);
    let mut result = Vec::with_capacity(length_bytes);
    let mut position_bytes = 0_u64;
    for (chunk_digest, chunk_len_bytes) in chunks {
        let chunk_end_bytes = position_bytes.saturating_add(chunk_len_bytes);
        if chunk_end_bytes > offset_bytes && position_bytes < end_bytes {
            append_chunk_overlap(
                RangeSliceRequest {
                    root,
                    blob_digest: digest,
                    chunk_digest,
                    chunk_len_bytes,
                    position_bytes,
                    offset_bytes,
                    end_bytes,
                },
                &mut result,
            )?;
        }
        position_bytes = chunk_end_bytes;
        if position_bytes >= end_bytes {
            break;
        }
    }
    Ok(result)
}

struct RangeBounds {
    offset_bytes: u64,
    length_bytes: usize,
    expected_len_bytes: u64,
}

fn checked_range_end(
    digest: mneme_core::ContentDigest,
    bounds: RangeBounds,
) -> crate::error::Result<u64> {
    let length_bytes =
        u64::try_from(bounds.length_bytes).map_err(|_| crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "stored bytes end before the requested range".to_owned(),
        })?;
    let Some(end_bytes) = bounds.offset_bytes.checked_add(length_bytes) else {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "stored bytes end before the requested range".to_owned(),
        });
    };
    if end_bytes > bounds.expected_len_bytes {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "stored bytes end before the requested range".to_owned(),
        });
    }
    debug_assert!(end_bytes >= bounds.offset_bytes);
    debug_assert!(end_bytes <= bounds.expected_len_bytes);
    Ok(end_bytes)
}

struct RangeSliceRequest<'a> {
    root: &'a std::path::Path,
    blob_digest: mneme_core::ContentDigest,
    chunk_digest: mneme_core::ContentDigest,
    chunk_len_bytes: u64,
    position_bytes: u64,
    offset_bytes: u64,
    end_bytes: u64,
}

fn append_chunk_overlap(
    request: RangeSliceRequest<'_>,
    result: &mut Vec<u8>,
) -> crate::error::Result<()> {
    let chunk_end_bytes = request
        .position_bytes
        .saturating_add(request.chunk_len_bytes);
    let chunk_bytes = read_chunk(request.root, request.chunk_digest, request.chunk_len_bytes)?;
    let slice_start = usize::try_from(request.offset_bytes.saturating_sub(request.position_bytes))
        .map_err(|_| corrupt_range_slice(request.blob_digest))?;
    let slice_end = usize::try_from(
        request
            .end_bytes
            .min(chunk_end_bytes)
            .saturating_sub(request.position_bytes),
    )
    .map_err(|_| corrupt_range_slice(request.blob_digest))?;
    let Some(overlap) = chunk_bytes.get(slice_start..slice_end) else {
        return Err(corrupt_range_slice(request.blob_digest));
    };
    debug_assert!(slice_start <= slice_end);
    result.extend_from_slice(overlap);
    debug_assert!(result.len() >= overlap.len());
    Ok(())
}

fn corrupt_range_slice(digest: mneme_core::ContentDigest) -> crate::error::Failure {
    crate::error::Failure::CorruptBlob {
        digest: digest.to_hex(),
        reason: "chunk length mismatch during range read".to_owned(),
    }
}

fn slice_range(
    digest: mneme_core::ContentDigest,
    bytes: &[u8],
    offset_bytes: u64,
    length_bytes: usize,
) -> crate::error::Result<Vec<u8>> {
    let start = usize::try_from(offset_bytes).map_err(|_| crate::error::Failure::CorruptBlob {
        digest: digest.to_hex(),
        reason: "stored bytes end before the requested range".to_owned(),
    })?;
    let Some(end) = start.checked_add(length_bytes) else {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "stored bytes end before the requested range".to_owned(),
        });
    };
    let Some(slice) = bytes.get(start..end) else {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "stored bytes end before the requested range".to_owned(),
        });
    };
    Ok(slice.to_vec())
}

/// Remove every pending transfer of a targeted digest, whichever device sent
/// it, and return how many were removed.
#[allow(unknown_lints, usize_in_public_api)] // local directory-entry count
pub fn purge_targeted_transfers(
    root: &std::path::Path,
    targets: &std::collections::BTreeSet<[u8; 32]>,
) -> crate::error::Result<usize> {
    let max_owners = 100_000_usize;
    let transfers = root.join(TRANSFER_DIRECTORY);
    if !transfers.is_dir() {
        return Ok(0);
    }
    let mut removed = 0_usize;
    for (index, owner) in std::fs::read_dir(&transfers)
        .map_err(|error| crate::error::Failure::io(&transfers, error))?
        .enumerate()
    {
        if index >= max_owners {
            return Err(crate::error::Failure::io(
                &transfers,
                std::io::Error::other("transfer inspection exceeds its owner bound"),
            ));
        }
        let owner = owner.map_err(|error| crate::error::Failure::io(&transfers, error))?;
        let is_directory = owner
            .file_type()
            .map_err(|error| crate::error::Failure::io(owner.path(), error))?
            .is_dir();
        if !is_directory {
            continue;
        }
        for target in targets {
            let path = owner.path().join(hex_32(target));
            match std::fs::remove_dir_all(&path) {
                Ok(()) => removed = removed.saturating_add(1),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(crate::error::Failure::io(&path, error)),
            }
        }
    }
    Ok(removed)
}

/// Lowercase hexadecimal of a 32-byte digest.
fn hex_32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Combined compression and FastCDC chunking policy for staging source blobs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) struct StoragePolicy {
    pub compression: BlobCompression,
    pub chunking: crate::dedup::BlobChunking,
}

/// Stage exact bytes into the immutable blob store.
pub fn stage(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
    bytes: &[u8],
) -> crate::error::Result<StagedBlob> {
    stage_with_policy(root, digest, bytes, StoragePolicy::default(), "")
}

/// Stage exact bytes into the immutable blob store, optionally compressing
/// eligible `text/*` and structured-text payloads on disk while preserving the
/// uncompressed content-addressed digest.
pub fn stage_with_compression(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
    bytes: &[u8],
    compression: BlobCompression,
    media_type: &str,
) -> crate::error::Result<StagedBlob> {
    stage_with_policy(
        root,
        digest,
        bytes,
        StoragePolicy {
            compression,
            chunking: crate::dedup::BlobChunking::None,
        },
        media_type,
    )
}

/// Stage exact bytes into the immutable blob store using the configured
/// compression and FastCDC chunking policies while preserving the canonical
/// uncompressed content identity.
pub(crate) fn stage_with_policy(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
    bytes: &[u8],
    policy: StoragePolicy,
    media_type: &str,
) -> crate::error::Result<StagedBlob> {
    if hash_bytes(digest.algorithm(), bytes) != *digest.as_bytes() {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "staged bytes do not hash to the declared digest".to_owned(),
        });
    }
    let uncompressed_len =
        u64::try_from(bytes.len()).map_err(|_| crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "staged blob length exceeds u64".to_owned(),
        })?;
    debug_assert_eq!(u64::try_from(bytes.len()).ok(), Some(uncompressed_len));
    let target = blob_path(root, digest);
    if target.exists() {
        let staged = finish_existing_stage(&target, root, digest, uncompressed_len)?;
        let file_len = std::fs::metadata(&target)
            .map_err(|error| crate::error::Failure::io(&target, error))?
            .len();
        if read_frame_header_length(&target, file_len)?.is_none() {
            crate::outboard::stage_if_large(root, digest, bytes)?;
        }
        return Ok(staged);
    }
    debug_assert!(!target.exists());
    if let crate::dedup::BlobChunking::FastCdc(cdc_config) = policy.chunking
        && uncompressed_len >= cdc_config.min_blob_bytes()
    {
        return stage_chunked_blob(ChunkedStageRequest {
            root,
            target: &target,
            digest,
            bytes,
            uncompressed_len,
            compression: policy.compression,
            cdc_config,
            media_type,
        });
    }
    let is_compressed =
        is_compressible_media_type(media_type) && !matches!(policy.compression, BlobCompression::None);
    let disk_bytes = encode_for_storage(
        root,
        digest,
        bytes,
        EncodeOptions {
            uncompressed_len,
            compression: policy.compression,
            media_type,
        },
    )?;
    write_staged_blob(root, &target, &disk_bytes)?;
    if !is_compressed {
        crate::outboard::stage_if_large(root, digest, bytes)?;
    }
    Ok(StagedBlob {
        digest,
        byte_length: uncompressed_len,
    })
}

#[derive(Clone, Copy)]
struct EncodeOptions<'a> {
    uncompressed_len: u64,
    compression: BlobCompression,
    media_type: &'a str,
}

fn encode_for_storage(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
    bytes: &[u8],
    options: EncodeOptions<'_>,
) -> crate::error::Result<Vec<u8>> {
    if !is_compressible_media_type(options.media_type) {
        return Ok(bytes.to_vec());
    }
    match options.compression {
        BlobCompression::Zstd => encode_zstd_frame(digest, bytes, options.uncompressed_len),
        BlobCompression::ZstdDictionary { dictionary } => {
            encode_zstd_dict_frame(root, digest, bytes, options.uncompressed_len, dictionary)
        }
        _ => Ok(bytes.to_vec()),
    }
}

struct ChunkedStageRequest<'a> {
    root: &'a std::path::Path,
    target: &'a std::path::Path,
    digest: mneme_core::ContentDigest,
    bytes: &'a [u8],
    uncompressed_len: u64,
    compression: BlobCompression,
    cdc_config: crate::dedup::FastCdcConfig,
    media_type: &'a str,
}

fn stage_chunked_blob(request: ChunkedStageRequest<'_>) -> crate::error::Result<StagedBlob> {
    let spans = crate::dedup::fastcdc_chunk_spans(request.bytes, request.cdc_config)?;
    debug_assert!(!spans.is_empty());
    debug_assert!(request.uncompressed_len >= request.cdc_config.min_blob_bytes());
    let mut entries = Vec::with_capacity(spans.len());
    for span in spans {
        entries.push(stage_one_chunk(&request, span)?);
    }
    let manifest =
        crate::dedup::encode_cdc_manifest(request.digest, request.uncompressed_len, &entries)?;
    write_staged_blob(request.root, request.target, &manifest)?;
    Ok(StagedBlob {
        digest: request.digest,
        byte_length: request.uncompressed_len,
    })
}

fn stage_one_chunk(
    request: &ChunkedStageRequest<'_>,
    span: crate::dedup::ChunkSpan,
) -> crate::error::Result<([u8; 32], u64)> {
    let start =
        usize::try_from(span.offset_bytes).map_err(|_| crate::error::Failure::CorruptBlob {
            digest: request.digest.to_hex(),
            reason: "chunk offset exceeds usize".to_owned(),
        })?;
    let len =
        usize::try_from(span.length_bytes).map_err(|_| crate::error::Failure::CorruptBlob {
            digest: request.digest.to_hex(),
            reason: "chunk length exceeds usize".to_owned(),
        })?;
    debug_assert!(start.saturating_add(len) <= request.bytes.len());
    let chunk_slice = &request.bytes[start..start.saturating_add(len)];
    debug_assert_eq!(chunk_slice.len(), len);
    let chunk_algo = request.digest.algorithm();
    let chunk_hash = hash_bytes(chunk_algo, chunk_slice);
    let chunk_digest = mneme_core::ContentDigest::from_parts(
        chunk_algo,
        mneme_core::EncodingProfile::RawBytesV1,
        mneme_core::ValueBoundary::SourceBytes,
        chunk_hash,
    )
    .map_err(|reason| crate::error::Failure::CorruptBlob {
        digest: request.digest.to_hex(),
        reason: reason.to_owned(),
    })?;
    debug_assert_eq!(chunk_digest.algorithm(), chunk_algo);
    let chunk_target = crate::dedup::chunk_path(request.root, chunk_digest);
    if chunk_target.exists() {
        let existing = read_chunk(request.root, chunk_digest, span.length_bytes)?;
        if existing != chunk_slice {
            return Err(crate::error::Failure::CorruptBlob {
                digest: chunk_digest.to_hex(),
                reason: "existing chunk differs from staged bytes".to_owned(),
            });
        }
        if let Some(parent) = chunk_target.parent() {
            flush_directory(parent)?;
        }
    } else {
        let disk_chunk = encode_for_storage(
            request.root,
            chunk_digest,
            chunk_slice,
            EncodeOptions {
                uncompressed_len: span.length_bytes,
                compression: request.compression,
                media_type: request.media_type,
            },
        )?;
        write_staged_blob(request.root, &chunk_target, &disk_chunk)?;
    }
    Ok((chunk_hash, span.length_bytes))
}

fn finish_existing_stage(
    target: &std::path::Path,
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
    uncompressed_len: u64,
) -> crate::error::Result<StagedBlob> {
    verify(root, digest, uncompressed_len)?;
    if let Some(parent) = target.parent() {
        flush_directory(parent)?;
    }
    Ok(StagedBlob {
        digest,
        byte_length: uncompressed_len,
    })
}

pub(crate) fn write_staged_blob(
    root: &std::path::Path,
    target: &std::path::Path,
    disk_bytes: &[u8],
) -> crate::error::Result<()> {
    let parent = target.parent().ok_or_else(|| {
        crate::error::Failure::InvalidCommand("blob path has no parent".to_owned())
    })?;
    create_directory_chain_flushed(parent)?;
    let staging = root.join(STAGING_DIRECTORY);
    create_directory_chain_flushed(&staging)?;
    let temporary = staging.join(format!("{TEMP_PREFIX}{}", random_hex(8)?));
    write_flushed(&temporary, disk_bytes)?;
    std::fs::rename(&temporary, target)
        .map_err(|error| crate::error::Failure::io(target, error))?;
    flush_directory(parent)
}

fn encode_zstd_frame(
    digest: mneme_core::ContentDigest,
    bytes: &[u8],
    uncompressed_len: u64,
) -> crate::error::Result<Vec<u8>> {
    let compressed = zstd::stream::encode_all(bytes, ZSTD_COMPRESSION_LEVEL).map_err(|error| {
        crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: format!("zstd compression failed: {error}"),
        }
    })?;
    let mut framed = Vec::with_capacity(ZSTD_HEADER_LEN.saturating_add(compressed.len()));
    framed.extend_from_slice(ZSTD_FRAME_MAGIC);
    framed.extend_from_slice(&uncompressed_len.to_le_bytes());
    framed.extend_from_slice(&compressed);
    Ok(framed)
}

fn encode_zstd_dict_frame(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
    bytes: &[u8],
    uncompressed_len: u64,
    dict_digest: mneme_core::ContentDigest,
) -> crate::error::Result<Vec<u8>> {
    let dict_bytes = crate::dedup::read_dictionary(root, dict_digest)?;
    debug_assert!(!dict_bytes.is_empty());
    debug_assert_eq!(u64::try_from(bytes.len()).ok(), Some(uncompressed_len));
    let mut encoder = zstd::stream::write::Encoder::with_dictionary(
        Vec::new(),
        ZSTD_COMPRESSION_LEVEL,
        &dict_bytes,
    )
    .map_err(|error| zstd_dict_encode_error(digest, error))?;
    encoder
        .write_all(bytes)
        .map_err(|error| zstd_dict_encode_error(digest, error))?;
    let compressed = encoder
        .finish()
        .map_err(|error| zstd_dict_encode_error(digest, error))?;
    let algo_tag = match dict_digest.algorithm() {
        mneme_core::HashAlgorithm::Sha256 => 0_u8,
        mneme_core::HashAlgorithm::Blake3 => 1_u8,
    };
    let mut framed = Vec::with_capacity(ZSTD_DICT_HEADER_LEN.saturating_add(compressed.len()));
    framed.extend_from_slice(ZSTD_DICT_FRAME_MAGIC);
    framed.extend_from_slice(&uncompressed_len.to_le_bytes());
    framed.extend_from_slice(dict_digest.as_bytes());
    framed.push(algo_tag);
    framed.extend_from_slice(&compressed);
    Ok(framed)
}

fn zstd_dict_encode_error(
    digest: mneme_core::ContentDigest,
    error: std::io::Error,
) -> crate::error::Failure {
    crate::error::Failure::CorruptBlob {
        digest: digest.to_hex(),
        reason: format!("zstd dictionary compression failed: {error}"),
    }
}

fn parse_zstd_header(
    digest: mneme_core::ContentDigest,
    disk_bytes: &[u8],
) -> crate::error::Result<(u64, &[u8])> {
    let Some(header) = disk_bytes.get(..ZSTD_HEADER_LEN) else {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "compressed blob header is truncated".to_owned(),
        });
    };
    if &header[..ZSTD_FRAME_MAGIC.len()] != ZSTD_FRAME_MAGIC {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "stored bytes do not hash to the committed digest".to_owned(),
        });
    }
    let Ok(length_bytes) = <[u8; 8]>::try_from(&header[ZSTD_FRAME_MAGIC.len()..ZSTD_HEADER_LEN])
    else {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "compressed blob header is truncated".to_owned(),
        });
    };
    let expected_len = u64::from_le_bytes(length_bytes);
    if expected_len > MAX_DECOMPRESSED_BLOB_BYTES {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "compressed blob header exceeds maximum supported size".to_owned(),
        });
    }
    Ok((expected_len, &disk_bytes[ZSTD_HEADER_LEN..]))
}

fn parse_zstd_dict_header(
    digest: mneme_core::ContentDigest,
    disk_bytes: &[u8],
) -> crate::error::Result<(u64, mneme_core::ContentDigest, &[u8])> {
    let Some(header) = disk_bytes.get(..ZSTD_DICT_HEADER_LEN) else {
        return Err(corrupt_dict_header(
            digest,
            "compressed dictionary blob header is truncated",
        ));
    };
    if &header[..ZSTD_DICT_FRAME_MAGIC.len()] != ZSTD_DICT_FRAME_MAGIC {
        return Err(corrupt_dict_header(
            digest,
            "stored bytes do not hash to the committed digest",
        ));
    }
    let Ok(length_bytes) = <[u8; 8]>::try_from(&header[8..16]) else {
        return Err(corrupt_dict_header(
            digest,
            "compressed dictionary blob header is truncated",
        ));
    };
    let expected_len = u64::from_le_bytes(length_bytes);
    if expected_len > MAX_DECOMPRESSED_BLOB_BYTES {
        return Err(corrupt_dict_header(
            digest,
            "compressed blob header exceeds maximum supported size",
        ));
    }
    let Ok(dict_hash) = <[u8; 32]>::try_from(&header[16..48]) else {
        return Err(corrupt_dict_header(
            digest,
            "compressed dictionary blob header is truncated",
        ));
    };
    let dict_algorithm = match header[48] {
        0 => mneme_core::HashAlgorithm::Sha256,
        1 => mneme_core::HashAlgorithm::Blake3,
        _ => {
            return Err(corrupt_dict_header(
                digest,
                "compressed dictionary blob header names unsupported hash algorithm",
            ));
        }
    };
    let dict_digest = mneme_core::ContentDigest::from_parts(
        dict_algorithm,
        mneme_core::EncodingProfile::RawBytesV1,
        mneme_core::ValueBoundary::SourceBytes,
        dict_hash,
    )
    .map_err(|reason| corrupt_dict_header(digest, reason))?;
    debug_assert!(expected_len <= MAX_DECOMPRESSED_BLOB_BYTES);
    debug_assert!(disk_bytes.len() >= ZSTD_DICT_HEADER_LEN);
    Ok((
        expected_len,
        dict_digest,
        &disk_bytes[ZSTD_DICT_HEADER_LEN..],
    ))
}

fn corrupt_dict_header(digest: mneme_core::ContentDigest, reason: &str) -> crate::error::Failure {
    crate::error::Failure::CorruptBlob {
        digest: digest.to_hex(),
        reason: reason.to_owned(),
    }
}

fn decode_zstd_frame(
    digest: mneme_core::ContentDigest,
    disk_bytes: &[u8],
) -> crate::error::Result<Vec<u8>> {
    let (expected_len, payload) = parse_zstd_header(digest, disk_bytes)?;
    let decoder = zstd::stream::read::Decoder::new(payload).map_err(|error| {
        crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: format!("invalid zstd blob stream: {error}"),
        }
    })?;
    read_zstd_stream(digest, decoder, expected_len)
}

fn decode_zstd_dict_frame(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
    disk_bytes: &[u8],
) -> crate::error::Result<Vec<u8>> {
    let (expected_len, dict_digest, payload) = parse_zstd_dict_header(digest, disk_bytes)?;
    let dict_bytes = crate::dedup::read_dictionary(root, dict_digest)?;
    let decoder =
        zstd::stream::read::Decoder::with_dictionary(payload, &dict_bytes).map_err(|error| {
            crate::error::Failure::CorruptBlob {
                digest: digest.to_hex(),
                reason: format!("invalid zstd dictionary blob stream: {error}"),
            }
        })?;
    read_zstd_stream(digest, decoder, expected_len)
}

fn read_zstd_stream<R: Read>(
    digest: mneme_core::ContentDigest,
    decoder: R,
    expected_len: u64,
) -> crate::error::Result<Vec<u8>> {
    let mut decompressed = Vec::new();
    decoder
        .take(expected_len.saturating_add(1))
        .read_to_end(&mut decompressed)
        .map_err(|error| crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: format!("zstd decompression failed: {error}"),
        })?;
    verify_decompressed(digest, &decompressed, expected_len)?;
    Ok(decompressed)
}

fn read_chunk(
    root: &std::path::Path,
    chunk_digest: mneme_core::ContentDigest,
    expected_len: u64,
) -> crate::error::Result<Vec<u8>> {
    let path = crate::dedup::chunk_path(root, chunk_digest);
    let disk_bytes = std::fs::read(&path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            crate::error::Failure::MissingBlob {
                digest: chunk_digest.to_hex(),
            }
        } else {
            crate::error::Failure::io(&path, error)
        }
    })?;
    let bytes = decode_single_blob_bytes(root, chunk_digest, &disk_bytes)?;
    debug_assert!(!bytes.is_empty());
    debug_assert_eq!(
        hash_with_algorithm(chunk_digest.algorithm(), &bytes),
        *chunk_digest.as_bytes()
    );
    if u64::try_from(bytes.len()).ok() != Some(expected_len) {
        return Err(crate::error::Failure::CorruptBlob {
            digest: chunk_digest.to_hex(),
            reason: format!(
                "stored chunk length {} differs from manifest {expected_len}",
                bytes.len()
            ),
        });
    }
    Ok(bytes)
}

fn decode_cdc_blob(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
    disk_bytes: &[u8],
) -> crate::error::Result<Vec<u8>> {
    let (expected_len, chunks) =
        crate::dedup::parse_cdc_manifest(digest, disk_bytes, MAX_DECOMPRESSED_BLOB_BYTES)?;
    let capacity_bytes =
        usize::try_from(expected_len).map_err(|_| crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "chunked blob length exceeds usize".to_owned(),
        })?;
    let mut reassembled = Vec::with_capacity(capacity_bytes);
    for (chunk_digest, chunk_len) in chunks {
        let chunk_bytes = read_chunk(root, chunk_digest, chunk_len)?;
        reassembled.extend_from_slice(&chunk_bytes);
    }
    verify_decompressed(digest, &reassembled, expected_len)?;
    Ok(reassembled)
}

fn decode_single_blob_bytes(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
    disk_bytes: &[u8],
) -> crate::error::Result<Vec<u8>> {
    if hash_with_algorithm(digest.algorithm(), disk_bytes) == *digest.as_bytes() {
        return Ok(disk_bytes.to_vec());
    }
    if disk_bytes.starts_with(ZSTD_FRAME_MAGIC) {
        return decode_zstd_frame(digest, disk_bytes);
    }
    if disk_bytes.starts_with(ZSTD_DICT_FRAME_MAGIC) {
        return decode_zstd_dict_frame(root, digest, disk_bytes);
    }
    Err(crate::error::Failure::CorruptBlob {
        digest: digest.to_hex(),
        reason: "stored bytes do not hash to the committed digest".to_owned(),
    })
}

fn verify_decompressed(
    digest: mneme_core::ContentDigest,
    decompressed: &[u8],
    expected_len: u64,
) -> crate::error::Result<()> {
    if u64::try_from(decompressed.len()).ok() != Some(expected_len) {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "decompressed blob length does not match header".to_owned(),
        });
    }
    if hash_bytes(digest.algorithm(), decompressed) != *digest.as_bytes() {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "decompressed bytes do not hash to the committed digest".to_owned(),
        });
    }
    Ok(())
}

/// Stream the file at `source` into the immutable blob store.
///
/// The digest is recomputed while copying and must equal `digest` and the
/// declared length, so a file that changed after it was measured is refused and
/// nothing is installed. Memory use is constant.
pub(crate) fn stage_file(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
    source: &std::path::Path,
    expected_bytes: u64,
) -> crate::error::Result<StagedBlob> {
    let target = blob_path(root, digest);
    if target.exists() {
        verify(root, digest, expected_bytes)?;
        let _ = crate::outboard::ensure(root, digest)?;
        if let Some(parent) = target.parent() {
            flush_directory(parent)?;
        }
        return Ok(StagedBlob {
            digest,
            byte_length: expected_bytes,
        });
    }
    let parent = target.parent().ok_or_else(|| {
        crate::error::Failure::InvalidCommand("blob path has no parent".to_owned())
    })?;
    create_directory_chain_flushed(parent)?;
    let staging = root.join(STAGING_DIRECTORY);
    create_directory_chain_flushed(&staging)?;
    let temporary = staging.join(format!("{TEMP_PREFIX}{}", random_hex(8)?));
    let copied = copy_hashed(digest.algorithm(), source, &temporary);
    let (actual, actual_bytes) = match copied {
        Ok(result) => result,
        Err(error) => {
            remove_temporary_best_effort(&temporary);
            return Err(error);
        }
    };
    if actual != *digest.as_bytes() || actual_bytes != expected_bytes {
        remove_temporary_best_effort(&temporary);
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "streamed source file does not match its declared digest and length".to_owned(),
        });
    }
    debug_assert_eq!(actual, *digest.as_bytes());
    debug_assert_eq!(actual_bytes, expected_bytes);
    std::fs::rename(&temporary, &target)
        .map_err(|error| crate::error::Failure::io(&target, error))?;
    flush_directory(parent)?;
    let _ = crate::outboard::ensure(root, digest)?;
    Ok(StagedBlob {
        digest,
        byte_length: expected_bytes,
    })
}

fn remove_temporary_best_effort(path: &std::path::Path) {
    if std::fs::remove_file(path).is_err() {}
}

/// Copy `source` to a new flushed file at `temporary`, hashing while copying.
fn copy_hashed(
    algorithm: mneme_core::HashAlgorithm,
    source: &std::path::Path,
    temporary: &std::path::Path,
) -> crate::error::Result<([u8; 32], u64)> {
    use std::io::Read;
    let mut input =
        std::fs::File::open(source).map_err(|error| crate::error::Failure::io(source, error))?;
    let mut output = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(temporary)
        .map_err(|error| crate::error::Failure::io(temporary, error))?;
    let mut hasher = mneme_core::hashing::StreamingHasher::new(algorithm);
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut copied_bytes = 0_u64;
    loop {
        let read = match input.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(crate::error::Failure::io(source, error)),
        };
        debug_assert!(read <= buffer.len());
        hasher.update(&buffer[..read]);
        output
            .write_all(&buffer[..read])
            .map_err(|error| crate::error::Failure::io(temporary, error))?;
        copied_bytes = copied_bytes.saturating_add(read as u64);
        debug_assert!(copied_bytes >= read as u64);
    }
    output
        .sync_all()
        .map_err(|error| crate::error::Failure::io(temporary, error))?;
    Ok((hasher.finish(), copied_bytes))
}

/// Whether the blob file exists with the expected uncompressed byte length.
///
/// Uncompressed blobs are checked from directory metadata alone. Compressed
/// blobs carry the uncompressed length in their 16-byte frame header, so only
/// that header is read. A file with a different length is reported as absent so
/// the caller's staging path re-verifies it and fails closed on real
/// corruption.
pub fn blob_is_present(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
    expected_length: u64,
) -> crate::error::Result<bool> {
    let path = blob_path(root, digest);
    let metadata = match std::fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(crate::error::Failure::io(&path, error)),
    };
    if !metadata.is_file() {
        return Ok(false);
    }
    if metadata.len() == expected_length {
        return Ok(true);
    }
    let header_len = u64::try_from(ZSTD_HEADER_LEN).unwrap_or(16);
    if metadata.len() < header_len {
        return Ok(false);
    }
    read_frame_header_length(&path, metadata.len()).map(|length| length == Some(expected_length))
}

pub(crate) fn read_frame_header_length(
    path: &std::path::Path,
    file_len: u64,
) -> crate::error::Result<Option<u64>> {
    let mut file =
        std::fs::File::open(path).map_err(|error| crate::error::Failure::io(path, error))?;
    let mut header = [0_u8; ZSTD_HEADER_LEN];
    let mut read_so_far = 0_usize;
    while read_so_far < ZSTD_HEADER_LEN {
        let count = file
            .read(&mut header[read_so_far..])
            .map_err(|error| crate::error::Failure::io(path, error))?;
        if count == 0 {
            return Ok(None);
        }
        read_so_far = read_so_far.saturating_add(count);
    }
    debug_assert_eq!(read_so_far, ZSTD_HEADER_LEN);
    let magic = &header[..ZSTD_FRAME_MAGIC.len()];
    let min_len = frame_min_length(magic);
    if min_len == 0 || file_len < min_len {
        return Ok(None);
    }
    debug_assert!(file_len >= min_len);
    Ok(
        <[u8; 8]>::try_from(&header[ZSTD_FRAME_MAGIC.len()..ZSTD_HEADER_LEN])
            .ok()
            .map(u64::from_le_bytes),
    )
}

fn frame_min_length(magic: &[u8]) -> u64 {
    if magic == ZSTD_FRAME_MAGIC {
        ZSTD_HEADER_LEN as u64
    } else if magic == ZSTD_DICT_FRAME_MAGIC {
        ZSTD_DICT_HEADER_LEN as u64
    } else if magic == crate::dedup::CDC_MANIFEST_MAGIC {
        crate::dedup::CDC_HEADER_LEN as u64
    } else {
        0
    }
}

/// Create `path` and flush the parent of every directory the call creates.
///
/// A crash after the file is renamed into a freshly created shard directory
/// must not lose that directory entry, so each new directory is reported to its
/// parent before the blob is staged below it.
pub fn create_directory_chain_flushed(path: &std::path::Path) -> crate::error::Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    // A path has at most one directory per component, which bounds the chain.
    let mut missing: Vec<&std::path::Path> = Vec::with_capacity(path.components().count());
    let mut current = path;
    while !current.is_dir() {
        let Some(parent) = current
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        else {
            break;
        };
        missing.push(current);
        current = parent;
    }
    // Each parent is reported before the directory below it exists.
    for directory in missing.iter().rev() {
        match std::fs::create_dir(directory) {
            Ok(()) => {
                if let Some(parent) = directory.parent() {
                    flush_directory(parent)?;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                // A directory that appeared in the meantime is accepted only
                // when it really is one.
                if !directory.is_dir() {
                    return Err(crate::error::Failure::io(directory, error));
                }
            }
            Err(error) => return Err(crate::error::Failure::io(directory, error)),
        }
    }
    Ok(())
}

/// Read a blob and verify its exact uncompressed bytes.
pub fn read(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
) -> crate::error::Result<Vec<u8>> {
    let path = blob_path(root, digest);
    let bytes = std::fs::read(&path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            crate::error::Failure::MissingBlob {
                digest: digest.to_hex(),
            }
        } else {
            crate::error::Failure::io(&path, error)
        }
    })?;
    if bytes.starts_with(crate::dedup::CDC_MANIFEST_MAGIC)
        && hash_bytes(digest.algorithm(), &bytes) != *digest.as_bytes()
    {
        return decode_cdc_blob(root, digest, &bytes);
    }
    decode_single_blob_bytes(root, digest, &bytes)
}

/// Verify a blob's presence, length, and hash.
pub fn verify(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
    expected_length: u64,
) -> crate::error::Result<()> {
    let bytes = read(root, digest)?;
    if bytes.len() as u64 != expected_length {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: format!(
                "stored length {} differs from declared {expected_length}",
                bytes.len()
            ),
        });
    }
    Ok(())
}

/// Read a blob and check only its presence and recorded length.
///
/// The commit path uses this for payloads it inherits: it re-hashes every blob
/// the commit stages, and an inherited blob is re-hashed by every snapshot read
/// and by recovery. The caller still decodes these bytes and matches them
/// against the ledger identity, so a truncated or replaced file fails closed.
pub(crate) fn read_with_length(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
    expected_length: u64,
) -> crate::error::Result<Vec<u8>> {
    let path = blob_path(root, digest);
    let bytes = std::fs::read(&path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            crate::error::Failure::MissingBlob {
                digest: digest.to_hex(),
            }
        } else {
            crate::error::Failure::io(&path, error)
        }
    })?;
    if bytes.len() as u64 != expected_length {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: format!(
                "stored length {} differs from declared {expected_length}",
                bytes.len()
            ),
        });
    }
    Ok(bytes)
}

/// Atomically publish bytes to a validated path under `working/`.
pub fn publish_working_file(
    root: &std::path::Path,
    relative: &str,
    bytes: &[u8],
) -> crate::error::Result<()> {
    let target = prepare_working_target(root, relative)?;
    let parent = target.parent().ok_or_else(|| {
        crate::error::Failure::InvalidCommand("working path has no parent".to_owned())
    })?;
    let temporary = parent.join(format!("{TEMP_PREFIX}{}", random_hex(8)?));
    write_flushed(&temporary, bytes)?;
    std::fs::rename(&temporary, &target)
        .map_err(|error| crate::error::Failure::io(&target, error))?;
    flush_directory(parent)?;
    Ok(())
}

/// The working path a validated relative path names, with its parent present.
///
/// Every existing parent segment must be a real directory (never a symbolic
/// link) and the resolved parent must stay beneath `working/`; both checks run
/// before anything is created or replaced.
pub fn prepare_working_target(
    root: &std::path::Path,
    relative: &str,
) -> crate::error::Result<std::path::PathBuf> {
    let (relative, working) = working_location(root, relative)?;
    let escaped = relative.to_string_lossy().into_owned();
    let target = prepare_working_parent(&working, &relative)?;
    let working_root = std::fs::canonicalize(&working)
        .map_err(|error| crate::error::Failure::io(&working, error))?;
    match std::fs::symlink_metadata(&target) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(crate::error::Failure::PathEscapes(escaped));
        }
        Ok(_) => {
            let canonical_target = std::fs::canonicalize(&target)
                .map_err(|error| crate::error::Failure::io(&target, error))?;
            if !canonical_target.starts_with(&working_root) {
                return Err(crate::error::Failure::PathEscapes(escaped));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(crate::error::Failure::io(&target, error)),
    }
    let parent = target.parent().ok_or_else(|| {
        crate::error::Failure::InvalidCommand("working path has no parent".to_owned())
    })?;
    // A racing process can still swap a checked directory for a link; re-check
    // the resolved parent immediately before the replacement.
    let canonical_parent =
        std::fs::canonicalize(parent).map_err(|error| crate::error::Failure::io(parent, error))?;
    if !canonical_parent.starts_with(&working_root) {
        return Err(crate::error::Failure::PathEscapes(escaped));
    }
    Ok(target)
}

/// The path a validated working-relative path names, with its parent present.
///
/// Missing parent directories are created one segment at a time beneath the
/// working directory, and every existing segment must be a real directory. A
/// symbolic link or a non-directory segment is refused before anything is
/// created below it, so no publication can create a directory outside the
/// working tree.
fn prepare_working_parent(
    working: &std::path::Path,
    relative: &std::path::Path,
) -> crate::error::Result<std::path::PathBuf> {
    let escaped = relative.to_string_lossy().into_owned();
    ensure_working_directory(working, &escaped)?;
    let mut parent = working.to_path_buf();
    if let Some(directory) = relative.parent() {
        for component in directory.components() {
            let std::path::Component::Normal(name) = component else {
                return Err(crate::error::Failure::PathEscapes(escaped));
            };
            parent.push(name);
            ensure_working_directory(&parent, &escaped)?;
        }
    }
    Ok(working.join(relative))
}

/// Require `path` to be a real directory, creating it when it is absent.
fn ensure_working_directory(path: &std::path::Path, escaped: &str) -> crate::error::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(crate::error::Failure::PathEscapes(escaped.to_owned()));
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(path).map_err(|error| crate::error::Failure::io(path, error))
        }
        Err(error) => Err(crate::error::Failure::io(path, error)),
    }
}

/// Read a working file relative to `working/`, returning `None` if absent.
///
/// Only a regular file is read. A symbolic link, directory, FIFO, socket or
/// device is refused without being opened, so commit, recovery and publication
/// cannot block on or follow one, and the read is bounded by
/// [`MAX_WORKING_FILE_BYTES`].
pub fn read_working_file(
    root: &std::path::Path,
    relative: &str,
) -> crate::error::Result<Option<Vec<u8>>> {
    match inspect_working_file(root, relative)? {
        WorkingEntry::Absent => Ok(None),
        WorkingEntry::Regular(bytes) => Ok(Some(bytes)),
        WorkingEntry::NotRegular => Err(crate::error::Failure::InvalidCommand(
            "working file target is not a regular file".to_owned(),
        )),
    }
}

/// What the working path holds, read without following a final symbolic link.
pub fn inspect_working_file(
    root: &std::path::Path,
    relative: &str,
) -> crate::error::Result<WorkingEntry> {
    let (relative, working) = working_location(root, relative)?;
    let target = working.join(&relative);
    // The final component is inspected, never resolved: a symbolic link is
    // reported as such, not read through.
    match std::fs::symlink_metadata(&target) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Ok(WorkingEntry::NotRegular);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(WorkingEntry::Absent);
        }
        Err(error) => return Err(crate::error::Failure::io(&target, error)),
    }
    let working_root = std::fs::canonicalize(&working)
        .map_err(|error| crate::error::Failure::io(&working, error))?;
    let canonical = std::fs::canonicalize(&target)
        .map_err(|error| crate::error::Failure::io(&target, error))?;
    if !canonical.starts_with(&working_root) {
        return Err(crate::error::Failure::PathEscapes(
            relative.to_string_lossy().into_owned(),
        ));
    }
    read_regular_bounded(&target)
}

/// Read a regular file with a size bound, without following a final link.
fn read_regular_bounded(path: &std::path::Path) -> crate::error::Result<WorkingEntry> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Ok(WorkingEntry::NotRegular);
        }
        Ok(metadata) if !metadata.is_file() => return Ok(WorkingEntry::NotRegular),
        Ok(metadata) if metadata.len() > MAX_WORKING_FILE_BYTES => return Err(too_large()),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(WorkingEntry::Absent);
        }
        Err(error) => return Err(crate::error::Failure::io(path, error)),
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(all(
        target_os = "linux",
        any(
            target_arch = "x86_64",
            target_arch = "x86",
            target_arch = "aarch64",
            target_arch = "arm"
        )
    ))]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, OPEN_GUARD_FLAGS);
    let file = options
        .open(path)
        .map_err(|error| crate::error::Failure::io(path, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| crate::error::Failure::io(path, error))?;
    if !metadata.is_file() {
        return Ok(WorkingEntry::NotRegular);
    }
    if metadata.len() > MAX_WORKING_FILE_BYTES {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    let mut limited = std::io::Read::take(file, MAX_WORKING_FILE_BYTES.saturating_add(1));
    std::io::Read::read_to_end(&mut limited, &mut bytes)
        .map_err(|error| crate::error::Failure::io(path, error))?;
    if bytes.len() as u64 > MAX_WORKING_FILE_BYTES {
        return Err(too_large());
    }
    Ok(WorkingEntry::Regular(bytes))
}

fn too_large() -> crate::error::Failure {
    crate::error::Failure::InvalidCommand(
        "working file exceeds the supported maximum size".to_owned(),
    )
}

/// A directory entry moved aside before replacement or deletion.
///
/// Renaming first means the bytes a decision is made from can no longer change
/// through the path: the decision and the install or delete act on content that
/// is already displaced.
pub struct QuarantinedFile {
    path: std::path::PathBuf,
    target: std::path::PathBuf,
}

impl std::fmt::Debug for QuarantinedFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QuarantinedFile")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl QuarantinedFile {
    /// The quarantine path holding the displaced entry.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// The path the entry was displaced from.
    pub fn target(&self) -> &std::path::Path {
        &self.target
    }

    /// What the displaced entry holds, read without following a final link.
    pub fn read(&self) -> crate::error::Result<WorkingEntry> {
        read_regular_bounded(&self.path)
    }

    /// Put the displaced entry back.
    ///
    /// Returns `false` when a new entry occupies the target, in which case the
    /// quarantined content is kept and the caller reports the divergence.
    pub fn restore(&self) -> crate::error::Result<bool> {
        match std::fs::hard_link(&self.path, &self.target) {
            Ok(()) => {
                std::fs::remove_file(&self.path)
                    .map_err(|error| crate::error::Failure::io(&self.path, error))?;
                if let Some(parent) = self.target.parent() {
                    flush_directory(parent)?;
                }
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(_) => {
                // A directory cannot be hard-linked. A rename puts it back only
                // while the target is still absent; a target that appeared is
                // reported and the quarantined content is kept.
                match std::fs::symlink_metadata(&self.target) {
                    Ok(_) => Ok(false),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        std::fs::rename(&self.path, &self.target)
                            .map_err(|error| crate::error::Failure::io(&self.target, error))?;
                        if let Some(parent) = self.target.parent() {
                            flush_directory(parent)?;
                        }
                        Ok(true)
                    }
                    Err(error) => Err(crate::error::Failure::io(&self.target, error)),
                }
            }
        }
    }

    /// Delete the displaced entry.
    pub fn remove(&self) -> crate::error::Result<()> {
        std::fs::remove_file(&self.path)
            .map_err(|error| crate::error::Failure::io(&self.path, error))?;
        if let Some(parent) = self.path.parent() {
            flush_directory(parent)?;
        }
        Ok(())
    }
}

/// Displaced content that is put back unless the caller settles it.
///
/// A publication or purge that moved a file aside must leave the user's bytes
/// in place even when it returns early with an error, so the guard restores the
/// entry on drop unless the caller restored, discarded or kept it explicitly.
pub struct QuarantineGuard {
    file: Option<QuarantinedFile>,
    settled: bool,
}

impl std::fmt::Debug for QuarantineGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QuarantineGuard")
            .field("file", &self.file)
            .field("settled", &self.settled)
            .finish()
    }
}

impl QuarantineGuard {
    /// Wrap an entry displaced by [`quarantine_working_file`].
    pub fn new(file: Option<QuarantinedFile>) -> Self {
        let is_settled = file.is_none();
        QuarantineGuard {
            file,
            settled: is_settled,
        }
    }

    /// The displaced entry, when the path held one.
    pub fn entry(&self) -> Option<&QuarantinedFile> {
        self.file.as_ref()
    }

    /// Put the displaced entry back, settling the guard.
    pub fn restore(&mut self) -> crate::error::Result<bool> {
        self.settled = true;
        match &self.file {
            Some(file) => file.restore(),
            None => Ok(true),
        }
    }

    /// Delete the displaced entry, settling the guard.
    pub fn discard(&mut self) -> crate::error::Result<()> {
        self.settled = true;
        match &self.file {
            Some(file) => file.remove(),
            None => Ok(()),
        }
    }

    /// Keep the displaced entry where it is, settling the guard.
    pub fn keep(&mut self) {
        self.settled = true;
    }
}

impl Drop for QuarantineGuard {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        if let Some(file) = &self.file {
            // Best effort: a failed restore leaves the quarantined bytes in
            // place, never deletes them.
            let _ = file.restore();
        }
    }
}

/// Move the entry at `target` to a unique sibling name.
pub fn quarantine_entry(target: &std::path::Path) -> crate::error::Result<Option<QuarantinedFile>> {
    match std::fs::symlink_metadata(target) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(crate::error::Failure::io(target, error)),
    }
    let parent = target.parent().ok_or_else(|| {
        crate::error::Failure::InvalidCommand("quarantine target has no parent".to_owned())
    })?;
    let name = target.file_name().ok_or_else(|| {
        crate::error::Failure::InvalidCommand("quarantine target has no name".to_owned())
    })?;
    let path = parent.join(quarantine_name(name)?);
    std::fs::rename(target, &path).map_err(|error| crate::error::Failure::io(target, error))?;
    flush_directory(parent)?;
    Ok(Some(QuarantinedFile {
        path,
        target: target.to_path_buf(),
    }))
}

/// Move a working file aside before replacing or purging it.
///
/// Parent directories are not created: a purge must not create the path it is
/// inspecting, and publication prepares its target first.
pub fn quarantine_working_file(
    root: &std::path::Path,
    relative: &str,
) -> crate::error::Result<QuarantineGuard> {
    let (relative, working) = working_location(root, relative)?;
    let escaped = relative.to_string_lossy().into_owned();
    let target = working.join(&relative);
    let working_root = std::fs::canonicalize(&working)
        .map_err(|error| crate::error::Failure::io(&working, error))?;
    let parent = target.parent().ok_or_else(|| {
        crate::error::Failure::InvalidCommand("working path has no parent".to_owned())
    })?;
    match std::fs::symlink_metadata(parent) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(crate::error::Failure::PathEscapes(escaped));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(QuarantineGuard::new(None));
        }
        Err(error) => return Err(crate::error::Failure::io(parent, error)),
    }
    let canonical_parent =
        std::fs::canonicalize(parent).map_err(|error| crate::error::Failure::io(parent, error))?;
    if !canonical_parent.starts_with(&working_root) {
        return Err(crate::error::Failure::PathEscapes(escaped));
    }
    Ok(QuarantineGuard::new(quarantine_entry(&target)?))
}

/// Move a workspace-relative file aside before purging it.
///
/// Accepted only for a canonical workspace-relative path whose every existing
/// parent segment is a real directory, so a symbolic link is never traversed.
pub fn quarantine_workspace_file(
    root: &std::path::Path,
    relative: &str,
) -> crate::error::Result<QuarantineGuard> {
    let relative = validate_relative_path(relative)?;
    let escaped = relative.to_string_lossy().into_owned();
    let root_path =
        std::fs::canonicalize(root).map_err(|error| crate::error::Failure::io(root, error))?;
    let mut parent = root_path.clone();
    if let Some(directory) = relative.parent() {
        for component in directory.components() {
            let std::path::Component::Normal(name) = component else {
                return Err(crate::error::Failure::PathEscapes(escaped));
            };
            parent.push(name);
            match std::fs::symlink_metadata(&parent) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() || !metadata.is_dir() {
                        return Err(crate::error::Failure::PathEscapes(escaped));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(QuarantineGuard::new(None));
                }
                Err(error) => return Err(crate::error::Failure::io(&parent, error)),
            }
        }
    }
    let target = root_path.join(&relative);
    Ok(QuarantineGuard::new(quarantine_entry(&target)?))
}

fn quarantine_name(name: &std::ffi::OsStr) -> crate::error::Result<std::ffi::OsString> {
    let mut output = std::ffi::OsString::from(QUARANTINE_PREFIX);
    output.push(name);
    output.push(".");
    output.push(random_hex(8)?);
    Ok(output)
}

/// Whether an entry name is a quarantine file left by an interrupted replace.
pub fn is_quarantine_name(name: &std::ffi::OsStr) -> bool {
    name.to_string_lossy().starts_with(QUARANTINE_PREFIX)
}

/// Install `bytes` at `target`, never replacing an entry that appeared.
///
/// Returns `false` when an entry already occupies the target, so the caller
/// reports a divergence instead of overwriting unknown content.
pub fn install_working_file(target: &std::path::Path, bytes: &[u8]) -> crate::error::Result<bool> {
    let parent = target.parent().ok_or_else(|| {
        crate::error::Failure::InvalidCommand("working path has no parent".to_owned())
    })?;
    let temporary = parent.join(format!("{TEMP_PREFIX}{}", random_hex(8)?));
    write_flushed(&temporary, bytes)?;
    let installed = std::fs::hard_link(&temporary, target);
    #[allow(unknown_lints, ignored_result)]
    // the link is already installed; the temporary is best-effort cleanup
    let _ = std::fs::remove_file(&temporary);
    match installed {
        Ok(()) => {
            flush_directory(parent)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(crate::error::Failure::io(target, error)),
    }
}

/// Remove staged temporary files and any blob file without a ledger row.
#[allow(unknown_lints, usize_in_public_api)] // local directory-entry counts
pub fn cleanup_orphans(
    root: &std::path::Path,
    known: &std::collections::BTreeSet<[u8; 32]>,
) -> crate::error::Result<(usize, usize)> {
    let mut staged = 0;
    let staging = root.join(STAGING_DIRECTORY);
    if staging.is_dir() {
        for entry in std::fs::read_dir(&staging)
            .map_err(|error| crate::error::Failure::io(&staging, error))?
        {
            let entry = entry.map_err(|error| crate::error::Failure::io(&staging, error))?;
            if entry
                .file_type()
                .map(|kind| kind.is_file())
                .unwrap_or(false)
            {
                std::fs::remove_file(entry.path())
                    .map_err(|error| crate::error::Failure::io(entry.path(), error))?;
                staged += 1;
            }
        }
    }
    let mut blobs = 0;
    let blob_root = root.join(BLOB_DIRECTORY);
    if blob_root.is_dir() {
        // Each file is decided and removed as it is read, so the sweep holds no
        // inventory of the store and needs no bound on the number of blobs.
        for file in BlobFiles::open(&blob_root)? {
            let file = file?;
            if !known.contains(&file.digest) {
                std::fs::remove_file(&file.path)
                    .map_err(|error| crate::error::Failure::io(&file.path, error))?;
                blobs += 1;
            }
        }
    }
    Ok((staged, blobs))
}

/// Remove temporary publication files left under `working/`.
#[allow(unknown_lints, usize_in_public_api)] // local directory-entry count
pub fn cleanup_working_temporaries(root: &std::path::Path) -> crate::error::Result<usize> {
    let tree = WorkingTree::of(root)?;
    let working = tree.directory(root);
    let mut removed = 0;
    if working.is_dir() {
        removed += cleanup_temporaries_in(&working, &tree)?;
    }
    Ok(removed)
}

/// Remove leftover staging and working temporary files that hold targeted bytes.
///
/// A crash between writing a flushed temporary file and renaming it into place
/// leaves the full bytes behind. Those leftovers are invisible to a ledger row
/// sweep, so a retention cleanup hashes them instead: only a regular file whose
/// exact bytes have a targeted digest is removed, and every other entry is left
/// untouched. Returns `(removed, inspected)`.
#[allow(unknown_lints, usize_in_public_api)] // local directory-entry counts
pub fn purge_targeted_temporaries(
    root: &std::path::Path,
    targets: &std::collections::BTreeSet<[u8; 32]>,
) -> crate::error::Result<(usize, usize)> {
    let mut removed = 0;
    let mut inspected = 0;
    let staging = root.join(STAGING_DIRECTORY);
    if staging.is_dir() {
        let (found_removed, found_inspected) =
            purge_targeted_in(&staging, targets, false, &WorkingTree::Internal)?;
        removed += found_removed;
        inspected += found_inspected;
    }
    let tree = WorkingTree::of(root)?;
    let working = tree.directory(root);
    if working.is_dir() {
        let (found_removed, found_inspected) = purge_targeted_in(&working, targets, true, &tree)?;
        removed += found_removed;
        inspected += found_inspected;
    }
    Ok((removed, inspected))
}

/// Remove files under `directory` whose bytes have a targeted digest, skipping
/// the directories `tree` keeps out of a working tree.
fn purge_targeted_in(
    directory: &std::path::Path,
    targets: &std::collections::BTreeSet<[u8; 32]>,
    temporaries_only: bool,
    tree: &WorkingTree,
) -> crate::error::Result<(usize, usize)> {
    let max_entries = 100_000_usize;
    let mut removed = 0_usize;
    let mut inspected = 0_usize;
    let mut pending = vec![directory.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory)
            .map_err(|error| crate::error::Failure::io(&directory, error))?
        {
            let entry = entry.map_err(|error| crate::error::Failure::io(&directory, error))?;
            let file_type = entry
                .file_type()
                .map_err(|error| crate::error::Failure::io(entry.path(), error))?;
            if file_type.is_dir() {
                if tree.skips_directory(&entry.file_name()) {
                    continue;
                }
                if pending.len() >= max_entries {
                    return Err(crate::error::Failure::io(
                        &directory,
                        std::io::Error::other("temporary inspection exceeds its directory bound"),
                    ));
                }
                pending.push(entry.path());
                continue;
            }
            let is_temporary = entry.file_name().to_string_lossy().starts_with(TEMP_PREFIX)
                || is_quarantine_name(&entry.file_name());
            if temporaries_only && !is_temporary {
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            inspected = inspected.saturating_add(1);
            if inspected > max_entries {
                return Err(crate::error::Failure::io(
                    &directory,
                    std::io::Error::other("temporary inspection exceeds its file bound"),
                ));
            }
            let path = entry.path();
            if let WorkingEntry::Regular(bytes) = read_regular_bounded(&path)?
                && (targets.contains(&sha256(&bytes)) || targets.contains(&blake3(&bytes)))
            {
                std::fs::remove_file(&path)
                    .map_err(|error| crate::error::Failure::io(&path, error))?;
                removed += 1;
            }
        }
    }
    Ok((removed, inspected))
}

/// Remove publication temporaries under `directory`, skipping the directories
/// `tree` keeps out of a working tree.
fn cleanup_temporaries_in(
    directory: &std::path::Path,
    tree: &WorkingTree,
) -> crate::error::Result<usize> {
    let mut removed = 0;
    let mut pending = vec![directory.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory)
            .map_err(|error| crate::error::Failure::io(&directory, error))?
        {
            let entry = entry.map_err(|error| crate::error::Failure::io(&directory, error))?;
            let file_type = entry
                .file_type()
                .map_err(|error| crate::error::Failure::io(entry.path(), error))?;
            if file_type.is_dir() {
                if tree.skips_directory(&entry.file_name()) {
                    continue;
                }
                if pending.len() >= 100_000 {
                    return Err(crate::error::Failure::io(
                        &directory,
                        std::io::Error::other("temporary cleanup exceeds its directory bound"),
                    ));
                }
                pending.push(entry.path());
            } else if file_type.is_file()
                && entry.file_name().to_string_lossy().starts_with(TEMP_PREFIX)
            {
                std::fs::remove_file(entry.path())
                    .map_err(|error| crate::error::Failure::io(entry.path(), error))?;
                removed += 1;
            }
        }
    }
    Ok(removed)
}

/// One regular blob file: its path and the digest its name encodes.
struct BlobFile {
    path: std::path::PathBuf,
    digest: [u8; 32],
}

/// The regular blob files under one store's blob directory, visited one entry at
/// a time.
///
/// The walk descends `blobs/<algorithm>/<shard>/<digest>` and yields each regular
/// file whose name is a lowercase hex digest as it is read, so a caller never
/// holds an inventory of the whole store and no bound on the number of files is
/// needed. Every non-directory algorithm or shard entry, non-regular file and
/// unparsable name is skipped, exactly as a collected inventory skipped them, and
/// the visit order never affects what a caller decides.
struct BlobFiles {
    blob_root: std::path::PathBuf,
    algorithms: std::fs::ReadDir,
    algorithm_dir: std::path::PathBuf,
    shards: Option<std::fs::ReadDir>,
    shard_dir: std::path::PathBuf,
    files: Option<std::fs::ReadDir>,
}

impl BlobFiles {
    /// Start a streaming walk under one store's blob directory.
    fn open(blob_root: &std::path::Path) -> crate::error::Result<Self> {
        Ok(BlobFiles {
            blob_root: blob_root.to_path_buf(),
            algorithms: std::fs::read_dir(blob_root)
                .map_err(|error| crate::error::Failure::io(blob_root, error))?,
            algorithm_dir: blob_root.to_path_buf(),
            shards: None,
            shard_dir: blob_root.to_path_buf(),
            files: None,
        })
    }

    /// Enter one directory of the walk, or report why it cannot be read.
    ///
    /// A non-directory entry is skipped, so a stray file at either directory level
    /// never becomes part of the walk.
    fn descend(
        entry: std::fs::DirEntry,
    ) -> crate::error::Result<Option<(std::path::PathBuf, std::fs::ReadDir)>> {
        if !entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
            return Ok(None);
        }
        let path = entry.path();
        let directory =
            std::fs::read_dir(&path).map_err(|error| crate::error::Failure::io(&path, error))?;
        Ok(Some((path, directory)))
    }

    /// The next regular blob file of the shard being read.
    ///
    /// `None` means the shard is exhausted (or absent), so the walk advances to
    /// the next shard instead of reporting an error.
    fn next_file(&mut self) -> Option<crate::error::Result<BlobFile>> {
        loop {
            let entry = match self.files.as_mut().map(|files| files.next()) {
                Some(Some(Ok(entry))) => entry,
                Some(Some(Err(error))) => {
                    return Some(Err(crate::error::Failure::io(&self.shard_dir, error)));
                }
                Some(None) => {
                    self.files = None;
                    return None;
                }
                None => return None,
            };
            if !entry
                .file_type()
                .map(|kind| kind.is_file())
                .unwrap_or(false)
            {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(digest) = parse_hex_32(&name).or_else(|| {
                name.strip_suffix(&format!(".{}", crate::outboard::EXTENSION))
                    .and_then(parse_hex_32)
            }) else {
                continue;
            };
            return Some(Ok(BlobFile {
                path: entry.path(),
                digest,
            }));
        }
    }

    /// Enter the next shard directory of the algorithm being read.
    ///
    /// Returns whether a shard was entered; running out of shards is not an
    /// error, so the caller advances to the next algorithm.
    fn enter_next_shard(&mut self) -> crate::error::Result<bool> {
        loop {
            let entry = match self.shards.as_mut().map(|shards| shards.next()) {
                Some(Some(Ok(entry))) => entry,
                Some(Some(Err(error))) => {
                    return Err(crate::error::Failure::io(&self.algorithm_dir, error));
                }
                Some(None) => {
                    self.shards = None;
                    return Ok(false);
                }
                None => return Ok(false),
            };
            if let Some((directory, files)) = BlobFiles::descend(entry)? {
                self.shard_dir = directory;
                self.files = Some(files);
                return Ok(true);
            }
        }
    }
}

impl Iterator for BlobFiles {
    type Item = crate::error::Result<BlobFile>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.files.is_some() {
                if let Some(file) = self.next_file() {
                    return Some(file);
                }
                continue;
            }
            if self.shards.is_some() {
                match self.enter_next_shard() {
                    Ok(_) => continue,
                    Err(error) => return Some(Err(error)),
                }
            }
            let entry = match self.algorithms.next() {
                Some(Ok(entry)) => entry,
                Some(Err(error)) => {
                    return Some(Err(crate::error::Failure::io(&self.blob_root, error)));
                }
                None => return None,
            };
            let is_algorithm = entry
                .file_name()
                .to_str()
                .and_then(mneme_core::HashAlgorithm::parse)
                .is_some();
            if !is_algorithm {
                continue;
            }
            match BlobFiles::descend(entry) {
                Ok(Some((directory, shards))) => {
                    self.algorithm_dir = directory;
                    self.shards = Some(shards);
                }
                Ok(None) => continue,
                Err(error) => return Some(Err(error)),
            }
        }
    }
}

fn parse_hex_32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (index, chunk) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        bytes[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Some(bytes)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Write a new file and flush it to disk; an existing file is refused.
pub(crate) fn write_flushed(path: &std::path::Path, bytes: &[u8]) -> crate::error::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| crate::error::Failure::io(path, error))?;
    file.write_all(bytes)
        .map_err(|error| crate::error::Failure::io(path, error))?;
    file.sync_all()
        .map_err(|error| crate::error::Failure::io(path, error))?;
    Ok(())
}

pub(crate) fn flush_directory(path: &std::path::Path) -> crate::error::Result<()> {
    // Directory flushing is best-effort on platforms that reject opening one.
    if let Ok(directory) = std::fs::File::open(path) {
        directory
            .sync_all()
            .map_err(|error| crate::error::Failure::io(path, error))?;
    }
    Ok(())
}

/// Every regular blob file on disk, by the digest its name encodes.
///
/// Read-only: nothing is removed or opened for writing. The integrity scrub
/// compares this inventory with the ledger to name files no row accounts for.
#[allow(unknown_lints, assertion_density)] // read-only directory walk returns Result<Vec<_>>
pub(crate) fn blob_file_inventory(
    root: &std::path::Path,
) -> crate::error::Result<Vec<([u8; 32], std::path::PathBuf)>> {
    let blob_root = root.join(BLOB_DIRECTORY);
    let mut files = Vec::new();
    if blob_root.is_dir() {
        for file in BlobFiles::open(&blob_root)? {
            let file = file?;
            files.push((file.digest, file.path));
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_path_validation_rejects_traversal() {
        assert!(validate_relative_path("notes/project.adoc").is_ok());
        for bad in ["", "/absolute", "../escape", "a/../b", "./a"] {
            assert!(validate_relative_path(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn staged_blob_roundtrips_and_detects_corruption() {
        let root = tempfile::tempdir().expect("temp");
        let bytes = b"exact source bytes";
        let digest = mneme_core::ContentDigest::of_source_bytes(bytes);
        let staged = stage(root.path(), digest, bytes).expect("stage");
        assert_eq!(staged.byte_length, bytes.len() as u64);
        assert_eq!(read(root.path(), digest).expect("read"), bytes);

        let path = blob_path(root.path(), digest);
        std::fs::write(&path, b"tampered").expect("tamper");
        assert!(matches!(
            read(root.path(), digest),
            Err(crate::error::Failure::CorruptBlob { .. })
        ));
    }

    #[test]
    fn atomic_publication_replaces_only_the_target() {
        let root = tempfile::tempdir().expect("temp");
        publish_working_file(root.path(), "notes/doc.adoc", b"first").expect("write");
        assert_eq!(
            read_working_file(root.path(), "notes/doc.adoc").expect("read"),
            Some(b"first".to_vec())
        );
        publish_working_file(root.path(), "notes/doc.adoc", b"second").expect("replace");
        assert_eq!(
            read_working_file(root.path(), "notes/doc.adoc").expect("read"),
            Some(b"second".to_vec())
        );
        assert_eq!(
            cleanup_working_temporaries(root.path()).expect("cleanup"),
            0
        );
    }

    #[test]
    fn text_blob_is_stored_compressed_and_reads_back_byte_identical() {
        let root = tempfile::tempdir().expect("temp");
        let bytes = b"= Heading\n\nRepeated paragraph for zstd compression.\n".repeat(32);
        let digest = mneme_core::ContentDigest::of_source_bytes(&bytes);
        let staged = stage_with_compression(
            root.path(),
            digest,
            &bytes,
            BlobCompression::Zstd,
            "text/asciidoc",
        )
        .expect("stage compressed");
        assert_eq!(staged.byte_length, bytes.len() as u64);

        let on_disk = std::fs::read(blob_path(root.path(), digest)).expect("disk bytes");
        assert!(on_disk.starts_with(ZSTD_FRAME_MAGIC));
        assert!(on_disk.len() < bytes.len());

        assert!(
            blob_is_present(root.path(), digest, bytes.len() as u64).expect("present"),
            "compressed blob must report present against uncompressed length"
        );
        verify(root.path(), digest, bytes.len() as u64).expect("verify");
        assert_eq!(read(root.path(), digest).expect("read"), bytes);
        assert_eq!(
            read_range(root.path(), digest, 10, 18).expect("read_range"),
            &bytes[10..28]
        );
    }

    #[test]
    fn binary_and_already_compressed_blobs_are_stored_uncompressed() {
        let root = tempfile::tempdir().expect("temp");
        for media_type in [
            "application/pdf",
            "application/epub+zip",
            "image/png",
            "image/jpeg",
            "application/octet-stream",
        ] {
            let bytes = format!("binary payload for {media_type} ").repeat(16);
            let raw = bytes.as_bytes();
            let digest = mneme_core::ContentDigest::of_source_bytes(raw);
            stage_with_compression(root.path(), digest, raw, BlobCompression::Zstd, media_type)
                .expect("stage binary");
            let on_disk = std::fs::read(blob_path(root.path(), digest)).expect("disk bytes");
            assert_eq!(
                on_disk, raw,
                "{media_type} must remain uncompressed on disk"
            );
            assert_eq!(read(root.path(), digest).expect("read"), raw);
        }
    }

    #[test]
    fn legacy_uncompressed_blob_reads_cleanly_even_with_zstd_magic_prefix() {
        let root = tempfile::tempdir().expect("temp");
        let mut legacy = ZSTD_FRAME_MAGIC.to_vec();
        legacy.extend_from_slice(b"legacy uncompressed payload");
        let digest = mneme_core::ContentDigest::of_source_bytes(&legacy);
        stage(root.path(), digest, &legacy).expect("stage legacy");

        assert_eq!(read(root.path(), digest).expect("read legacy"), legacy);
        assert_eq!(
            read_range(root.path(), digest, 8, 6).expect("range legacy"),
            b"legacy"
        );
    }

    #[test]
    fn corrupted_compressed_blob_fails_closed() {
        let root = tempfile::tempdir().expect("temp");
        let bytes = b"{\"key\": \"value\"}\n".repeat(24);
        let digest = mneme_core::ContentDigest::of_source_bytes(&bytes);
        stage_with_compression(
            root.path(),
            digest,
            &bytes,
            BlobCompression::Zstd,
            "application/json",
        )
        .expect("stage json");

        let path = blob_path(root.path(), digest);
        let original_disk = std::fs::read(&path).expect("disk");

        // Flip a byte in the compressed zstd payload.
        let mut flipped = original_disk.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 0xff;
        std::fs::write(&path, &flipped).expect("write flipped");
        assert!(matches!(
            read(root.path(), digest),
            Err(crate::error::Failure::CorruptBlob { .. })
        ));

        // Truncate the compressed file.
        std::fs::write(&path, &original_disk[..ZSTD_HEADER_LEN + 2]).expect("write truncated");
        assert!(matches!(
            read(root.path(), digest),
            Err(crate::error::Failure::CorruptBlob { .. })
        ));

        // Tamper with the uncompressed length in the header.
        let mut wrong_len = original_disk;
        let bogus_len = (bytes.len() as u64) + 1;
        wrong_len[ZSTD_FRAME_MAGIC.len()..ZSTD_HEADER_LEN]
            .copy_from_slice(&bogus_len.to_le_bytes());
        std::fs::write(&path, &wrong_len).expect("write wrong len");
        assert!(matches!(
            read(root.path(), digest),
            Err(crate::error::Failure::CorruptBlob { .. })
        ));
    }

    fn preserves_fixture_samples(count: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|index| {
                format!(
                    "<record \"schema-version\": 5 \"kind\": 'assertion \"scope\": \"notes/research\" \
                     \"record-id\": #:\"0000000000000000000000000000{index:04x}\" \
                     \"title\": \"Experiment Note {index:04}\" \
                     \"predicate\": 'supports-claim \"confidence\": 0.85 \
                     \"summary\": \"Observed repeatable content-defined chunk deduplication on fixture {index:04}.\">"
                )
                .into_bytes()
            })
            .collect()
    }

    #[test]
    fn zstd_dictionary_reduces_small_preserves_size_and_roundtrips() {
        let samples = preserves_fixture_samples(48);
        let sample_refs: Vec<&[u8]> = samples.iter().map(Vec::as_slice).collect();
        let dict_bytes =
            crate::dedup::train_zstd_dictionary(&sample_refs, 8192).expect("train dictionary");

        let root_dict = tempfile::tempdir().expect("temp dict");
        let root_dict_clone = tempfile::tempdir().expect("temp dict clone");
        let root_plain = tempfile::tempdir().expect("temp plain");

        let dict_digest =
            crate::dedup::stage_dictionary(root_dict.path(), &dict_bytes).expect("stage dict");
        let dict_digest_clone = crate::dedup::stage_dictionary(root_dict_clone.path(), &dict_bytes)
            .expect("stage dict clone");
        assert_eq!(dict_digest, dict_digest_clone);

        let target = preserves_fixture_samples(100).pop().expect("sample");
        let digest = mneme_core::ContentDigest::of_source_bytes(&target);

        let staged_dict = stage_with_compression(
            root_dict.path(),
            digest,
            &target,
            BlobCompression::ZstdDictionary {
                dictionary: dict_digest,
            },
            "application/preserves",
        )
        .expect("stage dict compressed");
        assert_eq!(staged_dict.byte_length, target.len() as u64);

        stage_with_compression(
            root_dict_clone.path(),
            digest,
            &target,
            BlobCompression::ZstdDictionary {
                dictionary: dict_digest,
            },
            "application/preserves",
        )
        .expect("stage dict compressed clone");

        stage_with_compression(
            root_plain.path(),
            digest,
            &target,
            BlobCompression::Zstd,
            "application/preserves",
        )
        .expect("stage plain zstd");

        let dict_disk = std::fs::read(blob_path(root_dict.path(), digest)).expect("dict disk");
        let dict_disk_clone =
            std::fs::read(blob_path(root_dict_clone.path(), digest)).expect("dict disk clone");
        let plain_disk = std::fs::read(blob_path(root_plain.path(), digest)).expect("plain disk");

        assert!(dict_disk.starts_with(ZSTD_DICT_FRAME_MAGIC));
        assert_eq!(
            dict_disk, dict_disk_clone,
            "dictionary compression must be deterministic"
        );
        assert!(
            dict_disk.len() < target.len(),
            "dict compressed {} must be smaller than raw {}",
            dict_disk.len(),
            target.len()
        );
        assert!(
            dict_disk.len() < plain_disk.len(),
            "dict compressed {} must be smaller than standalone zstd {}",
            dict_disk.len(),
            plain_disk.len()
        );

        assert!(
            blob_is_present(root_dict.path(), digest, target.len() as u64).expect("present"),
            "dict-compressed blob must report present against uncompressed length"
        );
        verify(root_dict.path(), digest, target.len() as u64).expect("verify");
        assert_eq!(read(root_dict.path(), digest).expect("read"), target);
        assert_eq!(
            read_range(root_dict.path(), digest, 12, 24).expect("read_range"),
            &target[12..36]
        );
    }

    #[test]
    fn missing_or_corrupt_zstd_dictionary_fails_closed() {
        let samples = preserves_fixture_samples(32);
        let sample_refs: Vec<&[u8]> = samples.iter().map(Vec::as_slice).collect();
        let dict_bytes = crate::dedup::train_zstd_dictionary(&sample_refs, 4096).expect("train");
        let target = samples[0].clone();
        let digest = mneme_core::ContentDigest::of_source_bytes(&target);

        let root = tempfile::tempdir().expect("temp");
        let missing_dict = mneme_core::ContentDigest::of_source_bytes(&dict_bytes);
        assert!(matches!(
            stage_with_compression(
                root.path(),
                digest,
                &target,
                BlobCompression::ZstdDictionary {
                    dictionary: missing_dict,
                },
                "application/preserves",
            ),
            Err(crate::error::Failure::MissingBlob { .. })
        ));

        let dict_digest =
            crate::dedup::stage_dictionary(root.path(), &dict_bytes).expect("stage dict");
        stage_with_compression(
            root.path(),
            digest,
            &target,
            BlobCompression::ZstdDictionary {
                dictionary: dict_digest,
            },
            "application/preserves",
        )
        .expect("stage with dict");

        // Legacy raw blob starting with MNZSTD02 still reads cleanly.
        let mut raw_magic = ZSTD_DICT_FRAME_MAGIC.to_vec();
        raw_magic.extend_from_slice(b"legacy raw bytes");
        let raw_magic_digest = mneme_core::ContentDigest::of_source_bytes(&raw_magic);
        stage(root.path(), raw_magic_digest, &raw_magic).expect("stage raw magic");
        assert_eq!(
            read(root.path(), raw_magic_digest).expect("read raw magic"),
            raw_magic
        );

        // Corrupt dictionary fails closed.
        let dict_path = crate::dedup::dictionary_path(root.path(), dict_digest);
        let mut corrupt_dict = dict_bytes.clone();
        corrupt_dict[0] ^= 0xff;
        std::fs::write(&dict_path, &corrupt_dict).expect("corrupt dict");
        assert!(matches!(
            read(root.path(), digest),
            Err(crate::error::Failure::CorruptBlob { .. })
        ));
        assert!(matches!(
            verify(root.path(), digest, target.len() as u64),
            Err(crate::error::Failure::CorruptBlob { .. })
        ));

        // Missing dictionary fails closed.
        std::fs::remove_file(&dict_path).expect("remove dict");
        assert!(matches!(
            read(root.path(), digest),
            Err(crate::error::Failure::MissingBlob { .. })
        ));
    }

    #[test]
    fn fastcdc_chunked_blob_roundtrips_range_reads_and_fails_closed() {
        let root = tempfile::tempdir().expect("temp");
        let mut doc = Vec::with_capacity(300 * 1024);
        for index in 0..4500_u64 {
            let mixed = index.wrapping_mul(2654435761);
            doc.extend_from_slice(
                format!("Line {index:04}: deterministic AsciiDoc content {mixed:08x}\n").as_bytes(),
            );
        }
        let digest = mneme_core::ContentDigest::of_source_bytes(&doc);
        let cdc_config = crate::dedup::FastCdcConfig::default();

        let staged = stage_with_policy(
            root.path(),
            digest,
            &doc,
            StoragePolicy {
                compression: BlobCompression::Zstd,
                chunking: crate::dedup::BlobChunking::FastCdc(cdc_config),
            },
            "text/asciidoc",
        )
        .expect("stage fastcdc");
        assert_eq!(staged.byte_length, doc.len() as u64);

        let manifest_path = blob_path(root.path(), digest);
        let manifest_bytes = std::fs::read(&manifest_path).expect("manifest");
        assert!(manifest_bytes.starts_with(crate::dedup::CDC_MANIFEST_MAGIC));
        assert!(blob_is_present(root.path(), digest, doc.len() as u64).expect("present"));
        verify(root.path(), digest, doc.len() as u64).expect("verify");
        assert_eq!(read(root.path(), digest).expect("read"), doc);

        // Range read across chunk boundaries.
        let spans = crate::dedup::fastcdc_chunk_spans(&doc, cdc_config).expect("spans");
        assert!(spans.len() >= 3);
        let cross_offset_bytes = spans[0].length_bytes.saturating_sub(32);
        let cross_start_bytes =
            usize::try_from(cross_offset_bytes).expect("cross offset fits usize");
        let cross_len_bytes = 128_usize;
        assert_eq!(
            read_range(root.path(), digest, cross_offset_bytes, cross_len_bytes)
                .expect("cross range"),
            &doc[cross_start_bytes..cross_start_bytes.saturating_add(cross_len_bytes)]
        );

        // Cleanup orphans keeps the manifest and does not delete chunks.
        let known = std::collections::BTreeSet::from([*digest.as_bytes()]);
        let (_, removed_blobs) = cleanup_orphans(root.path(), &known).expect("cleanup");
        assert_eq!(removed_blobs, 0);
        verify(root.path(), digest, doc.len() as u64).expect("verify after cleanup");

        // Corrupting a chunk fails closed.
        let (_, chunks) =
            crate::dedup::parse_cdc_manifest(digest, &manifest_bytes, MAX_DECOMPRESSED_BLOB_BYTES)
                .expect("parse manifest");
        let first_chunk_path = crate::dedup::chunk_path(root.path(), chunks[0].0);
        let original_chunk = std::fs::read(&first_chunk_path).expect("chunk disk");
        let mut corrupted_chunk = original_chunk.clone();
        let tail = corrupted_chunk.len() - 1;
        corrupted_chunk[tail] ^= 0xff;
        std::fs::write(&first_chunk_path, &corrupted_chunk).expect("write corrupt chunk");
        assert!(matches!(
            verify(root.path(), digest, doc.len() as u64),
            Err(crate::error::Failure::CorruptBlob { .. })
        ));

        // Deleting a chunk fails closed.
        std::fs::remove_file(&first_chunk_path).expect("remove chunk");
        assert!(matches!(
            read(root.path(), digest),
            Err(crate::error::Failure::MissingBlob { .. })
        ));
    }

    #[test]
    fn streamed_file_that_changes_after_measuring_is_refused() {
        let temp = tempfile::tempdir().expect("temp");
        let file = temp.path().join("source.bin");
        std::fs::write(&file, b"= One\n").expect("write");
        let draft =
            crate::SourceBlobDraft::from_file(&file, mneme_core::Symbol::from("text/asciidoc"))
                .expect("draft");
        std::fs::write(&file, b"= Two\n").expect("rewrite");
        let root = tempfile::tempdir().expect("root");
        let error = stage_file(root.path(), draft.digest(), &file, draft.byte_length())
            .expect_err("changed file");
        assert!(
            matches!(error, crate::error::Failure::CorruptBlob { .. }),
            "{error:?}"
        );
        assert!(!blob_path(root.path(), draft.digest()).exists());
    }
}
