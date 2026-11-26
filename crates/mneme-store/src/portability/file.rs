//! The archive container: header, canonical manifest, blob body, and trailer.
//!
//! Layout:
//!
//! ```text
//! magic       8 bytes  b"MNEMEBK1"
//! length      4 bytes  little-endian manifest length
//! manifest    N bytes  canonical Preserves
//! blob*               32-byte digest, 8-byte little-endian length, bytes
//! checksum    32 bytes SHA-256 of every preceding byte
//! ```
//!
//! The trailer checksum covers the header, manifest, blob headers and blob
//! bytes. Every blob is also verified against the digest the manifest names, so
//! a parser finds a truncated body, a reordered blob, or a changed byte before
//! restore touches a destination.

use std::io::Read;
use std::io::Seek;
use std::io::Write;

use sha2::Digest;

const MAGIC: [u8; 8] = *b"MNEMEBK1";
const HEADER_BYTES: u64 = 12;
const TRAILER_BYTES: u64 = 32;
const BLOB_HEADER_BYTES: u64 = 32 + 8;

/// A published archive and its identity.
pub(super) struct PublishedArchive {
    pub path: std::path::PathBuf,
    pub bytes: u64,
    pub checksum: String,
}

/// A checked archive file.
pub(super) struct ArchiveReader {
    file: std::fs::File,
    path: std::path::PathBuf,
    pub(crate) manifest: super::PortableManifest,
    blob_offsets: std::collections::BTreeMap<[u8; 32], (u64, u64)>,
    checksum: [u8; 32],
    file_length: u64,
}

/// An atomic archive writer.
pub(super) struct ArchiveWriter {
    file: tempfile::NamedTempFile,
    target: std::path::PathBuf,
    hasher: sha2::Sha256,
    bytes: u64,
}

fn io(path: &std::path::Path, error: std::io::Error) -> crate::error::Failure {
    crate::error::Failure::io(path, error)
}

fn invalid(message: impl Into<String>) -> crate::error::Failure {
    crate::error::Failure::PortableArchive(message.into())
}

/// Whether a path is occupied, including by a dangling symbolic link.
fn entry_exists(path: &std::path::Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

fn hex(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

impl ArchiveWriter {
    /// Create a temporary sibling of `target`; an existing target is refused.
    pub(super) fn create(
        target: &std::path::Path,
        forbidden_root: Option<&std::path::Path>,
    ) -> crate::error::Result<Self> {
        let parent = target
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .map_or_else(
                || std::path::PathBuf::from("."),
                std::path::Path::to_path_buf,
            );
        let parent = std::fs::canonicalize(&parent).map_err(|error| io(&parent, error))?;
        let name = target.file_name().ok_or_else(|| {
            crate::error::Failure::InvalidCommand("archive destination has no file name".to_owned())
        })?;
        let target = parent.join(name);
        if let Some(root) = forbidden_root
            && target.starts_with(root)
        {
            return Err(crate::error::Failure::InvalidCommand(format!(
                "archive destination {} lies inside the live workspace",
                target.display()
            )));
        }
        if entry_exists(&target) {
            return Err(crate::error::Failure::InvalidCommand(format!(
                "archive destination {} already exists",
                target.display()
            )));
        }
        let file = tempfile::Builder::new()
            .prefix(".mneme-backup-")
            .tempfile_in(&parent)
            .map_err(|error| io(&parent, error))?;
        Ok(ArchiveWriter {
            file,
            target,
            hasher: sha2::Sha256::new(),
            bytes: 0,
        })
    }

    /// Write the header and canonical manifest.
    pub(super) fn write_manifest(&mut self, manifest: &[u8]) -> crate::error::Result<()> {
        let length = u32::try_from(manifest.len())
            .map_err(|_| crate::error::Failure::HistoryLimitExceeded)?;
        if u64::from(length) > super::MAX_PORTABLE_MANIFEST_BYTES {
            return Err(crate::error::Failure::HistoryLimitExceeded);
        }
        self.write(&MAGIC)?;
        self.write(&length.to_le_bytes())?;
        self.write(manifest)
    }

    /// Write one blob in manifest order.
    pub(super) fn write_blob(
        &mut self,
        digest: mneme_core::ContentDigest,
        bytes: &[u8],
    ) -> crate::error::Result<()> {
        let length_bytes =
            u64::try_from(bytes.len()).map_err(|_| crate::error::Failure::HistoryLimitExceeded)?;
        if length_bytes > super::MAX_PORTABLE_BLOB_BYTES {
            return Err(crate::error::Failure::HistoryLimitExceeded);
        }
        if mneme_core::ContentDigest::of_source_bytes_with(bytes, digest.algorithm()) != digest {
            return Err(crate::error::Failure::CorruptBlob {
                digest: digest.to_hex(),
                reason: "source bytes do not hash to their committed digest".to_owned(),
            });
        }
        self.write(digest.as_bytes())?;
        self.write(&length_bytes.to_le_bytes())?;
        self.write(bytes)
    }

    /// Add bytes to the file and its running checksum.
    fn write(&mut self, bytes: &[u8]) -> crate::error::Result<()> {
        let length =
            u64::try_from(bytes.len()).map_err(|_| crate::error::Failure::HistoryLimitExceeded)?;
        let written = self
            .bytes
            .checked_add(length)
            .ok_or(crate::error::Failure::HistoryLimitExceeded)?;
        if written > super::MAX_PORTABLE_ARCHIVE_BYTES {
            return Err(crate::error::Failure::HistoryLimitExceeded);
        }
        self.file
            .write_all(bytes)
            .map_err(|error| io(self.file.path(), error))?;
        self.hasher.update(bytes);
        self.bytes = written;
        Ok(())
    }

    /// Write the trailer, flush, and rename the completed archive into place.
    pub(super) fn finish(mut self) -> crate::error::Result<PublishedArchive> {
        let checksum: [u8; 32] = self.hasher.clone().finalize().into();
        self.write(&checksum)?;
        self.file
            .as_file()
            .sync_all()
            .map_err(|error| io(self.file.path(), error))?;
        let published = self
            .file
            .persist_noclobber(&self.target)
            .map_err(|error| io(&self.target, error.error))?;
        drop(published);
        let parent = self.target.parent().map_or_else(
            || std::path::PathBuf::from("."),
            std::path::Path::to_path_buf,
        );
        std::fs::File::open(&parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| io(&parent, error))?;
        Ok(PublishedArchive {
            path: self.target,
            bytes: self.bytes,
            checksum: hex(&checksum),
        })
    }
}

impl ArchiveReader {
    /// Verify an archive completely and decode its manifest.
    pub(super) fn verify(path: &std::path::Path) -> crate::error::Result<Self> {
        let fd = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| io(path, error.into()))?;
        let mut file = std::fs::File::from(fd);
        let metadata = file.metadata().map_err(|error| io(path, error))?;
        let file_length = metadata.len();
        if !metadata.is_file()
            || !(HEADER_BYTES + TRAILER_BYTES..=super::MAX_PORTABLE_ARCHIVE_BYTES)
                .contains(&file_length)
        {
            return Err(invalid("archive length is outside its admitted bound"));
        }
        let (manifest, body_start) = read_manifest(&mut file, path, file_length)?;
        let checksum = verify_checksum(&mut file, path, file_length)?;
        let blob_offsets = read_offsets(&mut file, path, &manifest, body_start, file_length)?;
        Ok(ArchiveReader {
            file,
            path: path.to_path_buf(),
            manifest,
            blob_offsets,
            checksum,
            file_length,
        })
    }

    /// Read one blob and verify its digest and declared length.
    pub(super) fn blob(&self, digest: mneme_core::ContentDigest) -> crate::error::Result<Vec<u8>> {
        debug_assert!(!self.path.as_os_str().is_empty());
        let Some((offset, length)) = self.blob_offsets.get(digest.as_bytes()).copied() else {
            return Err(invalid(format!(
                "archive does not carry blob {}",
                digest.to_hex()
            )));
        };
        if length > super::MAX_PORTABLE_BLOB_BYTES {
            return Err(crate::error::Failure::HistoryLimitExceeded);
        }
        let byte_count =
            usize::try_from(length).map_err(|_| crate::error::Failure::HistoryLimitExceeded)?;
        let mut bytes = vec![0_u8; byte_count];
        std::os::unix::fs::FileExt::read_exact_at(&self.file, &mut bytes, offset)
            .map_err(|error| io(&self.path, error))?;
        debug_assert_eq!(bytes.len(), byte_count);
        if bytes.len() as u64 != length
            || mneme_core::ContentDigest::of_source_bytes_with(&bytes, digest.algorithm()) != digest
        {
            return Err(crate::error::Failure::CorruptBlob {
                digest: digest.to_hex(),
                reason: "archive bytes do not match their declared digest".to_owned(),
            });
        }
        Ok(bytes)
    }

    /// Recheck the same file after a restore pass, without resolving its path again.
    pub(super) fn recheck(&mut self) -> crate::error::Result<()> {
        let actual_length = self
            .file
            .metadata()
            .map_err(|error| io(&self.path, error))?
            .len();
        if actual_length != self.file_length
            || verify_checksum(&mut self.file, &self.path, self.file_length)? != self.checksum
        {
            return Err(invalid("archive changed while it was being restored"));
        }
        Ok(())
    }
}

fn read_manifest(
    file: &mut std::fs::File,
    path: &std::path::Path,
    file_length: u64,
) -> crate::error::Result<(super::PortableManifest, u64)> {
    let mut magic = [0_u8; 8];
    file.read_exact(&mut magic)
        .map_err(|error| io(path, error))?;
    if magic != MAGIC {
        return Err(invalid(
            "archive does not begin with the portable vault magic",
        ));
    }
    let mut length_bytes = [0_u8; 4];
    file.read_exact(&mut length_bytes)
        .map_err(|error| io(path, error))?;
    let manifest_length = u64::from(u32::from_le_bytes(length_bytes));
    if manifest_length > super::MAX_PORTABLE_MANIFEST_BYTES
        || HEADER_BYTES + manifest_length + TRAILER_BYTES > file_length
    {
        return Err(crate::error::Failure::HistoryLimitExceeded);
    }
    let manifest_length_usize = usize::try_from(manifest_length)
        .map_err(|_| crate::error::Failure::HistoryLimitExceeded)?;
    let mut manifest_bytes = vec![0_u8; manifest_length_usize];
    file.read_exact(&mut manifest_bytes)
        .map_err(|error| io(path, error))?;
    let value = mneme_core::binary::decode_canonical(&manifest_bytes)
        .map_err(|diagnostic| invalid(format!("archive manifest: {diagnostic}")))?;
    let manifest = super::PortableManifest::from_value(&value)?;
    manifest.validate()?;
    let body_bytes = manifest
        .blobs
        .iter()
        .try_fold(0_u64, |total, blob| {
            total
                .checked_add(BLOB_HEADER_BYTES)
                .and_then(|total| total.checked_add(blob.length))
        })
        .ok_or(crate::error::Failure::HistoryLimitExceeded)?;
    let expected_length = 8_u64
        .checked_add(4)
        .and_then(|value| value.checked_add(manifest_length))
        .and_then(|value| value.checked_add(body_bytes))
        .and_then(|value| value.checked_add(TRAILER_BYTES))
        .ok_or(crate::error::Failure::HistoryLimitExceeded)?;
    if expected_length != file_length {
        return Err(invalid(
            "archive length does not match its manifest and blob descriptors",
        ));
    }
    Ok((manifest, HEADER_BYTES + manifest_length))
}

type Offsets = std::collections::BTreeMap<[u8; 32], (u64, u64)>;

fn read_offsets(
    file: &mut std::fs::File,
    path: &std::path::Path,
    manifest: &super::PortableManifest,
    body_start: u64,
    file_length: u64,
) -> crate::error::Result<Offsets> {
    let mut blob_offsets = std::collections::BTreeMap::new();
    file.seek(std::io::SeekFrom::Start(body_start))
        .map_err(|error| io(path, error))?;
    for blob in &manifest.blobs {
        let mut digest = [0_u8; 32];
        file.read_exact(&mut digest)
            .map_err(|error| io(path, error))?;
        if digest != *blob.digest.as_bytes() {
            return Err(invalid(
                "archive blob header does not match the manifest order",
            ));
        }
        let mut length = [0_u8; 8];
        file.read_exact(&mut length)
            .map_err(|error| io(path, error))?;
        let length = u64::from_le_bytes(length);
        if length != blob.length || length > super::MAX_PORTABLE_BLOB_BYTES {
            return Err(invalid(
                "archive blob header length does not match the manifest",
            ));
        }
        let offset = file.stream_position().map_err(|error| io(path, error))?;
        if blob_offsets.insert(digest, (offset, length)).is_some() {
            return Err(invalid("archive repeats one blob header"));
        }
        file.seek(std::io::SeekFrom::Current(
            i64::try_from(length).map_err(|_| crate::error::Failure::HistoryLimitExceeded)?,
        ))
        .map_err(|error| io(path, error))?;
    }
    let end = file.stream_position().map_err(|error| io(path, error))?;
    if end != file_length - TRAILER_BYTES {
        return Err(invalid("archive body does not end at its trailer"));
    }
    Ok(blob_offsets)
}

/// Verify the trailing SHA-256 checksum over every preceding byte.
fn verify_checksum(
    file: &mut std::fs::File,
    path: &std::path::Path,
    file_length: u64,
) -> crate::error::Result<[u8; 32]> {
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|error| io(path, error))?;
    let checksum_at = file_length - TRAILER_BYTES;
    let mut hasher = sha2::Sha256::new();
    let mut remaining = checksum_at;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let want = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| crate::error::Failure::HistoryLimitExceeded)?;
        let Some(slice) = buffer.get_mut(..want) else {
            return Err(crate::error::Failure::HistoryLimitExceeded);
        };
        file.read_exact(slice).map_err(|error| io(path, error))?;
        hasher.update(&*slice);
        remaining -=
            u64::try_from(want).map_err(|_| crate::error::Failure::HistoryLimitExceeded)?;
    }
    let mut trailer = [0_u8; 32];
    file.read_exact(&mut trailer)
        .map_err(|error| io(path, error))?;
    let computed: [u8; 32] = hasher.finalize().into();
    if computed != trailer {
        return Err(invalid("archive checksum does not match its bytes"));
    }
    Ok(trailer)
}
