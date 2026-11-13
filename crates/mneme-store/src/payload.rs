//! Durable blob storage and atomic working-file publication.
//!
//! Blobs are content addressed by SHA-256 and stored under
//! `blobs/sha256/<first-two-hex>/<hex>`. Staging writes and flushes a temporary
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

use std::io::Write;

use sha2::Digest;

/// Directory holding immutable blobs.
pub const BLOB_DIRECTORY: &str = "blobs";
/// Directory holding in-progress staged files.
pub const STAGING_DIRECTORY: &str = "staging";
/// Directory holding published working files.
pub const WORKING_DIRECTORY: &str = "working";
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

/// Stage exact bytes into the immutable blob store.
pub fn stage(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
    bytes: &[u8],
) -> crate::error::Result<StagedBlob> {
    if sha256(bytes) != *digest.as_bytes() {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "staged bytes do not hash to the declared digest".to_owned(),
        });
    }
    let target = blob_path(root, digest);
    if target.exists() {
        verify(root, digest, bytes.len() as u64)?;
        // An earlier try may have renamed the file into place and stopped
        // before the directory entry was durable; this path is the retry.
        if let Some(parent) = target.parent() {
            flush_directory(parent)?;
        }
        return Ok(StagedBlob {
            digest,
            byte_length: bytes.len() as u64,
        });
    }
    let parent = target.parent().ok_or_else(|| {
        crate::error::Failure::InvalidCommand("blob path has no parent".to_owned())
    })?;
    create_directory_chain_flushed(parent)?;
    let staging = root.join(STAGING_DIRECTORY);
    create_directory_chain_flushed(&staging)?;
    let temporary = staging.join(format!("{TEMP_PREFIX}{}", random_hex(8)?));
    write_flushed(&temporary, bytes)?;
    std::fs::rename(&temporary, &target)
        .map_err(|error| crate::error::Failure::io(&target, error))?;
    flush_directory(parent)?;
    Ok(StagedBlob {
        digest,
        byte_length: bytes.len() as u64,
    })
}

/// Whether the blob file exists with the expected byte length.
///
/// Presence is checked from directory metadata alone: a commit that runs inside
/// its ledger transaction must not re-read and re-hash every payload it names.
/// A file with a different length is reported as absent so the caller's staging
/// path re-verifies it and fails closed on real corruption.
pub fn blob_is_present(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
    expected_length: u64,
) -> crate::error::Result<bool> {
    let path = blob_path(root, digest);
    match std::fs::metadata(&path) {
        Ok(metadata) => Ok(metadata.is_file() && metadata.len() == expected_length),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(crate::error::Failure::io(&path, error)),
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

/// Read a blob and verify its exact bytes.
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
    if sha256(&bytes) != *digest.as_bytes() {
        return Err(crate::error::Failure::CorruptBlob {
            digest: digest.to_hex(),
            reason: "stored bytes do not hash to the committed digest".to_owned(),
        });
    }
    Ok(bytes)
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
    let relative = validate_relative_path(relative)?;
    let escaped = relative.to_string_lossy().into_owned();
    let target = prepare_working_parent(root, &relative)?;
    let working = root.join(WORKING_DIRECTORY);
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
/// Missing parent directories are created one segment at a time beneath
/// `working/`, and every existing segment must be a real directory. A symbolic
/// link or a non-directory segment is refused before anything is created below
/// it, so no publication can create a directory outside the workspace.
fn prepare_working_parent(
    root: &std::path::Path,
    relative: &std::path::Path,
) -> crate::error::Result<std::path::PathBuf> {
    let escaped = relative.to_string_lossy().into_owned();
    let working = root.join(WORKING_DIRECTORY);
    ensure_working_directory(&working, &escaped)?;
    let mut parent = working.clone();
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
    let relative = validate_relative_path(relative)?;
    let escaped = relative.to_string_lossy().into_owned();
    let target = root.join(WORKING_DIRECTORY).join(&relative);
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
    let working = root.join(WORKING_DIRECTORY);
    let working_root = std::fs::canonicalize(&working)
        .map_err(|error| crate::error::Failure::io(&working, error))?;
    let canonical = std::fs::canonicalize(&target)
        .map_err(|error| crate::error::Failure::io(&target, error))?;
    if !canonical.starts_with(&working_root) {
        return Err(crate::error::Failure::PathEscapes(escaped));
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
    let relative = validate_relative_path(relative)?;
    let escaped = relative.to_string_lossy().into_owned();
    let target = root.join(WORKING_DIRECTORY).join(&relative);
    let working = root.join(WORKING_DIRECTORY);
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
    let working = root.join(WORKING_DIRECTORY);
    let mut removed = 0;
    if working.is_dir() {
        removed += cleanup_temporaries_in(&working)?;
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
        let (found_removed, found_inspected) = purge_targeted_in(&staging, targets, false)?;
        removed += found_removed;
        inspected += found_inspected;
    }
    let working = root.join(WORKING_DIRECTORY);
    if working.is_dir() {
        let (found_removed, found_inspected) = purge_targeted_in(&working, targets, true)?;
        removed += found_removed;
        inspected += found_inspected;
    }
    Ok((removed, inspected))
}

fn purge_targeted_in(
    directory: &std::path::Path,
    targets: &std::collections::BTreeSet<[u8; 32]>,
    temporaries_only: bool,
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
                && targets.contains(&sha256(&bytes))
            {
                std::fs::remove_file(&path)
                    .map_err(|error| crate::error::Failure::io(&path, error))?;
                removed += 1;
            }
        }
    }
    Ok((removed, inspected))
}

fn cleanup_temporaries_in(directory: &std::path::Path) -> crate::error::Result<usize> {
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
            let Some(digest) = parse_hex_32(&entry.file_name().to_string_lossy()) else {
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

fn write_flushed(path: &std::path::Path, bytes: &[u8]) -> crate::error::Result<()> {
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

fn flush_directory(path: &std::path::Path) -> crate::error::Result<()> {
    // Directory flushing is best-effort on platforms that reject opening one.
    if let Ok(directory) = std::fs::File::open(path) {
        directory
            .sync_all()
            .map_err(|error| crate::error::Failure::io(path, error))?;
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
}
