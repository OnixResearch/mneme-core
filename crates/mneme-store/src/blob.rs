//! Durable blob storage and atomic working-file publication.
//!
//! Blobs are content addressed by SHA-256 and stored under
//! `blobs/sha256/<first-two-hex>/<hex>`. Staging writes and flushes a temporary
//! file, verifies it, then renames it into place and flushes the directory.
//! Working files are replaced through a temporary file in the same directory,
//! so a reader never observes a partially written payload.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use mneme_core::ContentDigest;
use sha2::{Digest, Sha256};

use crate::error::{Result, StoreError};

/// Directory holding immutable blobs.
pub const BLOB_DIRECTORY: &str = "blobs";
/// Directory holding in-progress staged files.
pub const STAGING_DIRECTORY: &str = "staging";
/// Directory holding published working files.
pub const WORKING_DIRECTORY: &str = "working";
const TEMP_PREFIX: &str = ".mneme-tmp-";

/// A staged blob's identity and length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StagedBlob {
    pub digest: ContentDigest,
    pub byte_length: u64,
}

/// SHA-256 of exact bytes.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Random bytes from the operating system.
#[allow(unknown_lints, ambient_random)] // entropy is the blob-identity shell
pub fn random_bytes() -> Result<[u8; 16]> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| StoreError::Random(error.to_string()))?;
    Ok(bytes)
}

/// Random lowercase hexadecimal text of `bytes` bytes.
pub fn random_hex(bytes: u32) -> Result<String> {
    let capacity = usize::try_from(bytes)
        .map_err(|_| StoreError::InvalidCommand("hex output length exceeds usize".to_owned()))?;
    let mut output = String::with_capacity(capacity * 2);
    for _ in 0..bytes {
        let random = random_bytes()?;
        output.push_str(&format!("{:02x}", random[0]));
    }
    Ok(output)
}

/// Validate a workspace-relative path with no traversal components.
pub fn validate_relative_path(text: &str) -> Result<PathBuf> {
    let path = Path::new(text);
    if text.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(StoreError::PathEscapes(text.to_owned()));
    }
    Ok(path.to_path_buf())
}

/// The filesystem path for a blob digest.
pub fn blob_path(root: &Path, digest: ContentDigest) -> PathBuf {
    let hex = digest.to_hex();
    root.join(BLOB_DIRECTORY)
        .join(digest.algorithm().symbol())
        .join(&hex[0..2])
        .join(hex)
}

/// Stage exact bytes into the immutable blob store.
pub fn stage(root: &Path, digest: ContentDigest, bytes: &[u8]) -> Result<StagedBlob> {
    if sha256(bytes) != *digest.as_bytes() {
        return Err(StoreError::CorruptBlob {
            digest: digest.to_hex(),
            reason: "staged bytes do not hash to the declared digest".to_owned(),
        });
    }
    let target = blob_path(root, digest);
    if target.exists() {
        verify(root, digest, bytes.len() as u64)?;
        return Ok(StagedBlob {
            digest,
            byte_length: bytes.len() as u64,
        });
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|error| StoreError::io(parent, error))?;
    }
    let staging = root.join(STAGING_DIRECTORY);
    fs::create_dir_all(&staging).map_err(|error| StoreError::io(&staging, error))?;
    let temporary = staging.join(format!("{TEMP_PREFIX}{}", random_hex(8)?));
    write_flushed(&temporary, bytes)?;
    fs::rename(&temporary, &target).map_err(|error| StoreError::io(&target, error))?;
    flush_directory(
        target
            .parent()
            .ok_or_else(|| StoreError::InvalidCommand("blob path has no parent".to_owned()))?,
    )?;
    Ok(StagedBlob {
        digest,
        byte_length: bytes.len() as u64,
    })
}

/// Read a blob and verify its exact bytes.
pub fn read(root: &Path, digest: ContentDigest) -> Result<Vec<u8>> {
    let path = blob_path(root, digest);
    let bytes = fs::read(&path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            StoreError::MissingBlob {
                digest: digest.to_hex(),
            }
        } else {
            StoreError::io(&path, error)
        }
    })?;
    if sha256(&bytes) != *digest.as_bytes() {
        return Err(StoreError::CorruptBlob {
            digest: digest.to_hex(),
            reason: "stored bytes do not hash to the committed digest".to_owned(),
        });
    }
    Ok(bytes)
}

/// Verify a blob's presence, length, and hash.
pub fn verify(root: &Path, digest: ContentDigest, expected_length: u64) -> Result<()> {
    let bytes = read(root, digest)?;
    if bytes.len() as u64 != expected_length {
        return Err(StoreError::CorruptBlob {
            digest: digest.to_hex(),
            reason: format!(
                "stored length {} differs from declared {expected_length}",
                bytes.len()
            ),
        });
    }
    Ok(())
}

/// Atomically publish bytes to a validated path under `working/`.
pub fn publish_working_file(root: &Path, relative: &str, bytes: &[u8]) -> Result<()> {
    let relative = validate_relative_path(relative)?;
    let working = root.join(WORKING_DIRECTORY);
    fs::create_dir_all(&working).map_err(|error| StoreError::io(&working, error))?;
    let working_root =
        fs::canonicalize(&working).map_err(|error| StoreError::io(&working, error))?;
    let target = working.join(&relative);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|error| StoreError::io(parent, error))?;
        let canonical_parent =
            fs::canonicalize(parent).map_err(|error| StoreError::io(parent, error))?;
        if !canonical_parent.starts_with(&working_root) {
            return Err(StoreError::PathEscapes(
                relative.to_string_lossy().into_owned(),
            ));
        }
    }
    if target.exists() {
        let canonical_target =
            fs::canonicalize(&target).map_err(|error| StoreError::io(&target, error))?;
        if !canonical_target.starts_with(&working_root) {
            return Err(StoreError::PathEscapes(
                relative.to_string_lossy().into_owned(),
            ));
        }
    }
    let parent = target
        .parent()
        .ok_or_else(|| StoreError::InvalidCommand("working path has no parent".to_owned()))?;
    let temporary = parent.join(format!("{TEMP_PREFIX}{}", random_hex(8)?));
    write_flushed(&temporary, bytes)?;
    fs::rename(&temporary, &target).map_err(|error| StoreError::io(&target, error))?;
    flush_directory(parent)?;
    Ok(())
}

/// Read a working file relative to `working/`, returning `None` if absent.
pub fn read_working_file(root: &Path, relative: &str) -> Result<Option<Vec<u8>>> {
    let relative = validate_relative_path(relative)?;
    let path = root.join(WORKING_DIRECTORY).join(&relative);
    if path.exists() {
        let working = root.join(WORKING_DIRECTORY);
        let working_root =
            fs::canonicalize(&working).map_err(|error| StoreError::io(&working, error))?;
        let canonical = fs::canonicalize(&path).map_err(|error| StoreError::io(&path, error))?;
        if !canonical.starts_with(&working_root) {
            return Err(StoreError::PathEscapes(
                relative.to_string_lossy().into_owned(),
            ));
        }
    }
    match fs::read(&path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(StoreError::io(&path, error)),
    }
}

/// Remove staged temporary files and any blob file without a ledger row.
#[allow(unknown_lints, usize_in_public_api)] // local directory-entry counts
pub fn cleanup_orphans(root: &Path, known: &BTreeSet<[u8; 32]>) -> Result<(usize, usize)> {
    let mut staged = 0;
    let staging = root.join(STAGING_DIRECTORY);
    if staging.is_dir() {
        for entry in fs::read_dir(&staging).map_err(|error| StoreError::io(&staging, error))? {
            let entry = entry.map_err(|error| StoreError::io(&staging, error))?;
            if entry
                .file_type()
                .map(|kind| kind.is_file())
                .unwrap_or(false)
            {
                fs::remove_file(entry.path())
                    .map_err(|error| StoreError::io(entry.path(), error))?;
                staged += 1;
            }
        }
    }
    let mut blobs = 0;
    let blob_root = root.join(BLOB_DIRECTORY);
    if blob_root.is_dir() {
        for (path, digest) in blob_files(&blob_root)? {
            if !known.contains(&digest) {
                fs::remove_file(&path).map_err(|error| StoreError::io(&path, error))?;
                blobs += 1;
            }
        }
    }
    Ok((staged, blobs))
}

/// Remove temporary publication files left under `working/`.
#[allow(unknown_lints, usize_in_public_api)] // local directory-entry count
pub fn cleanup_working_temporaries(root: &Path) -> Result<usize> {
    let working = root.join(WORKING_DIRECTORY);
    let mut removed = 0;
    if working.is_dir() {
        removed += cleanup_temporaries_in(&working)?;
    }
    Ok(removed)
}

fn cleanup_temporaries_in(directory: &Path) -> Result<usize> {
    let mut removed = 0;
    for entry in fs::read_dir(directory).map_err(|error| StoreError::io(directory, error))? {
        let entry = entry.map_err(|error| StoreError::io(directory, error))?;
        let file_type = entry
            .file_type()
            .map_err(|error| StoreError::io(entry.path(), error))?;
        if file_type.is_dir() {
            removed += cleanup_temporaries_in(&entry.path())?;
        } else if file_type.is_file()
            && entry.file_name().to_string_lossy().starts_with(TEMP_PREFIX)
        {
            fs::remove_file(entry.path()).map_err(|error| StoreError::io(entry.path(), error))?;
            removed += 1;
        }
    }
    Ok(removed)
}

fn blob_files(blob_root: &Path) -> Result<Vec<(PathBuf, [u8; 32])>> {
    let mut output = Vec::new();
    for algorithm in fs::read_dir(blob_root).map_err(|error| StoreError::io(blob_root, error))? {
        let algorithm = algorithm.map_err(|error| StoreError::io(blob_root, error))?;
        if !algorithm
            .file_type()
            .map(|kind| kind.is_dir())
            .unwrap_or(false)
        {
            continue;
        }
        for shard in fs::read_dir(algorithm.path())
            .map_err(|error| StoreError::io(algorithm.path(), error))?
        {
            let shard = shard.map_err(|error| StoreError::io(algorithm.path(), error))?;
            if !shard.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
                continue;
            }
            for file in
                fs::read_dir(shard.path()).map_err(|error| StoreError::io(shard.path(), error))?
            {
                let file = file.map_err(|error| StoreError::io(shard.path(), error))?;
                if !file.file_type().map(|kind| kind.is_file()).unwrap_or(false) {
                    continue;
                }
                let name = file.file_name();
                let Some(digest) = parse_hex_32(&name.to_string_lossy()) else {
                    continue;
                };
                output.push((file.path(), digest));
            }
        }
    }
    Ok(output)
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

fn write_flushed(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| StoreError::io(path, error))?;
    file.write_all(bytes)
        .map_err(|error| StoreError::io(path, error))?;
    file.sync_all()
        .map_err(|error| StoreError::io(path, error))?;
    Ok(())
}

fn flush_directory(path: &Path) -> Result<()> {
    // Directory flushing is best-effort on platforms that reject opening one.
    if let Ok(directory) = File::open(path) {
        directory
            .sync_all()
            .map_err(|error| StoreError::io(path, error))?;
    }
    Ok(())
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
        let digest = ContentDigest::of_source_bytes(bytes);
        let staged = stage(root.path(), digest, bytes).expect("stage");
        assert_eq!(staged.byte_length, bytes.len() as u64);
        assert_eq!(read(root.path(), digest).expect("read"), bytes);

        let path = blob_path(root.path(), digest);
        std::fs::write(&path, b"tampered").expect("tamper");
        assert!(matches!(
            read(root.path(), digest),
            Err(StoreError::CorruptBlob { .. })
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
}
