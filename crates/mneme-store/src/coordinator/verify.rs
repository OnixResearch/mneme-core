//! Read-only workspace integrity scrub.
//!
//! [`verify_workspace`] audits a workspace's physical integrity without
//! opening a [`super::Workspace`]: it never migrates the ledger, never runs
//! recovery, never takes the commit lock, and opens the ledger with SQLite's
//! read-only flag inside one read transaction, so a concurrent writer is never
//! blocked and the audit sees one consistent ledger state.
//!
//! Three families of check run, each reporting exact identities:
//!
//! 1. every `blobs` row exists on disk under its content-addressed path with
//!    the recorded byte length (`quick` stops here) and re-hashes to its
//!    recorded digest, dispatching on the recorded hash algorithm;
//! 2. every record revision references a ledger blob, every blob the head
//!    manifest requires has a row, and blobs nothing references are reported
//!    as orphans;
//! 3. the revision chain runs from genesis to head without a gap, each parent
//!    link matches, and each stored manifest reconstructs from the ledger and
//!    carries its recorded digest.
//!
//! Orphans are reported but do not fail a scrub: an unreferenced file is
//! wasted space that recovery sweeps, not lost data.

#![allow(
    unknown_lints,
    path_segment_repetition,
    fragile_exhaustive_enum_match,
    assertion_density,
    allocation_in_loop,
    function_length,
    numeric_units
)] // Verify* names match CLI domain; exhaustive matches guard variants; scrub returns VerifyReport instead of panicking; diagnostic allocations are rare/offline; check_revisions is a cohesive single-pass loop; byte_length matches SQLite column

use rusqlite::OptionalExtension;

const SQLITE_BUSY_TIMEOUT_SECS: u64 = 5;
const STREAM_BUFFER_BYTES: usize = 64 * 1024;

/// How deeply to audit blob content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyMode {
    /// Existence and recorded byte length only; no blob content is read.
    Quick,
    /// Existence, length, and a streaming re-hash of every blob.
    Full,
}

impl VerifyMode {
    /// Stable lowercase name for reports.
    pub const fn symbol(self) -> &'static str {
        match self {
            VerifyMode::Quick => "quick",
            VerifyMode::Full => "full",
        }
    }
}

/// What a failed check found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssueKind {
    /// A `blobs` row has no file on disk.
    MissingBlob,
    /// A blob file's length differs from its row (truncation or growth).
    SizeMismatch,
    /// A blob file's bytes do not hash to its recorded digest.
    DigestMismatch,
    /// A blob file exists but cannot be read, or is not a regular file.
    UnreadableBlob,
    /// A blob row names a hash algorithm, profile or boundary this build lacks.
    UnsupportedBlob,
    /// A record revision names a full-record blob with no ledger row.
    DanglingRecordBlob,
    /// A record's stored envelope cannot be decoded or disagrees with its row.
    InvalidRecordBlob,
    /// A record needs a retained source whose blob the head manifest requires
    /// but the ledger does not hold.
    DanglingSourceBlob,
    /// A manifest blob journal names a digest with no ledger row.
    DanglingJournalBlob,
    /// The revision sequence has a gap or a parent link does not match.
    BrokenChain,
    /// A stored manifest does not decode, reconstruct, or match its digest.
    ManifestMismatch,
    /// A present `bao-tree` outboard sidecar is corrupt, wrong length, or
    /// disagrees with its canonical BLAKE3 blob.
    CorruptOutboard,
    /// SQLite metadata projection (`entities`, `relations`, `documents`)
    /// disagrees with the active non-forgotten head records.
    ProjectionMismatch,
}

impl IssueKind {
    /// Stable kebab-case name for reports.
    pub const fn symbol(self) -> &'static str {
        match self {
            IssueKind::MissingBlob => "missing-blob",
            IssueKind::SizeMismatch => "size-mismatch",
            IssueKind::DigestMismatch => "digest-mismatch",
            IssueKind::UnreadableBlob => "unreadable-blob",
            IssueKind::UnsupportedBlob => "unsupported-blob",
            IssueKind::DanglingRecordBlob => "dangling-record-blob",
            IssueKind::InvalidRecordBlob => "invalid-record-blob",
            IssueKind::DanglingSourceBlob => "dangling-source-blob",
            IssueKind::DanglingJournalBlob => "dangling-journal-blob",
            IssueKind::BrokenChain => "broken-chain",
            IssueKind::ManifestMismatch => "manifest-mismatch",
            IssueKind::CorruptOutboard => "corrupt-outboard",
            IssueKind::ProjectionMismatch => "projection-mismatch",
        }
    }
}

/// One integrity failure with the exact identities it affects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyIssue {
    pub kind: IssueKind,
    /// The blob digest (lowercase hex), when the failure concerns a blob.
    pub digest: Option<String>,
    /// The blob path relative to the workspace root, when one applies.
    pub path: Option<String>,
    /// Record ids (and revision ids) known to reference the blob.
    pub records: Vec<String>,
    /// The workspace revision the failure concerns, when one applies.
    pub revision: Option<String>,
    /// The ledger sequence of that revision.
    pub sequence: Option<u64>,
    /// Human-readable specifics (expected versus found).
    pub detail: String,
}

/// Why a blob is reported as an orphan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrphanReason {
    /// A file under `blobs/` that no ledger row accounts for.
    FileWithoutRow,
    /// A ledger row no manifest journal or record references.
    RowWithoutReference,
}

impl OrphanReason {
    /// Stable kebab-case name for reports.
    pub const fn symbol(self) -> &'static str {
        match self {
            OrphanReason::FileWithoutRow => "file-without-row",
            OrphanReason::RowWithoutReference => "row-without-reference",
        }
    }
}

/// A blob nothing accounts for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrphanBlob {
    pub reason: OrphanReason,
    pub digest: String,
    pub path: String,
}

/// The result of one scrub.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyReport {
    pub mode: VerifyMode,
    pub blobs_checked: u64,
    pub outboards_checked: u64,
    /// Bytes re-hashed and confirmed (always zero in quick mode).
    pub bytes_verified: u64,
    /// Bytes whose presence and length were confirmed from metadata.
    pub bytes_sized: u64,
    pub records_checked: u64,
    pub revisions_verified: u64,
    /// The head revision of the audited ledger.
    pub head_revision: Option<String>,
    pub issues: Vec<VerifyIssue>,
    pub orphans: Vec<OrphanBlob>,
}

impl VerifyReport {
    /// Whether no integrity check failed. Orphans do not count.
    pub fn is_healthy(&self) -> bool {
        self.issues.is_empty()
    }
}

/// Audit the workspace at `root` without modifying it.
///
/// Integrity failures are returned in the report; an `Err` means the audit
/// itself could not run (no ledger, unsupported layout, unreadable database).
pub fn verify_workspace(
    root: impl AsRef<std::path::Path>,
    mode: VerifyMode,
) -> crate::error::Result<VerifyReport> {
    let requested = root.as_ref();
    let root = std::fs::canonicalize(requested)
        .map_err(|error| crate::error::Failure::io(requested, error))?;
    let ledger = root.join(super::LEDGER_FILE);
    if !ledger.is_file() {
        return Err(crate::error::Failure::UnsupportedLayout(format!(
            "{} has no {}",
            root.display(),
            super::LEDGER_FILE
        )));
    }
    let mut connection = rusqlite::Connection::open_with_flags(
        &ledger,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(std::time::Duration::from_secs(SQLITE_BUSY_TIMEOUT_SECS))?;
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version != super::LAYOUT_VERSION {
        return Err(crate::error::Failure::UnsupportedLayout(format!(
            "ledger layout version {version} is not supported"
        )));
    }
    for table in [
        "revisions",
        "records",
        "blobs",
        "record_membership",
        "revision_blob_changes",
    ] {
        if !super::table_exists(&connection, table)? {
            return Err(crate::error::Failure::UnsupportedLayout(format!(
                "ledger has no {table} table; open the workspace once with the current mneme to migrate it"
            )));
        }
    }
    // One read transaction: every query below sees the same ledger state.
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
    let mut scrub = Scrub {
        root: &root,
        connection: &transaction,
        mode,
        report: VerifyReport {
            mode,
            blobs_checked: 0,
            outboards_checked: 0,
            bytes_verified: 0,
            bytes_sized: 0,
            records_checked: 0,
            revisions_verified: 0,
            head_revision: None,
            issues: Vec::new(),
            orphans: Vec::new(),
        },
        blob_digests: std::collections::BTreeSet::new(),
        purged_blobs: std::collections::BTreeSet::new(),
        verified: std::collections::BTreeSet::new(),
        live_framed_refs: crate::payload::FramedReferences::default(),
        record_owners: std::collections::BTreeMap::new(),
    };
    scrub.run()?;
    let report = scrub.report;
    drop(transaction);
    Ok(report)
}

struct BlobRow {
    digest: Vec<u8>,
    algorithm: String,
    profile: String,
    boundary: String,
    byte_length: i64,
}

struct Scrub<'a> {
    root: &'a std::path::Path,
    connection: &'a rusqlite::Connection,
    mode: VerifyMode,
    report: VerifyReport,
    /// Every digest the `blobs` table holds.
    blob_digests: std::collections::BTreeSet<[u8; 32]>,
    /// Blob digests explicitly recorded as purged by retention.
    purged_blobs: std::collections::BTreeSet<[u8; 32]>,
    /// Digests whose file passed every check this mode runs.
    verified: std::collections::BTreeSet<[u8; 32]>,
    /// FastCDC chunks and Zstd dictionaries referenced by live framed blobs.
    live_framed_refs: crate::payload::FramedReferences,
    /// Which records reference each blob digest, for diagnostics.
    record_owners: std::collections::BTreeMap<[u8; 32], Vec<String>>,
}

impl Scrub<'_> {
    fn run(&mut self) -> crate::error::Result<()> {
        self.load_digests()?;
        self.load_purged_blobs()?;
        self.check_records()?;
        self.check_blobs()?;
        self.check_source_references()?;
        self.check_metadata_projection()?;
        self.check_revisions()?;
        self.check_journal_digests()?;
        self.find_orphans()?;
        self.attach_owners();
        Ok(())
    }

    fn load_digests(&mut self) -> crate::error::Result<()> {
        let mut statement = self.connection.prepare("SELECT digest FROM blobs")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        for row in rows {
            if let Ok(digest) = <[u8; 32]>::try_from(row?.as_slice()) {
                self.blob_digests.insert(digest);
            }
        }
        Ok(())
    }

    fn load_purged_blobs(&mut self) -> crate::error::Result<()> {
        if !super::table_exists(self.connection, "retention_locations")? {
            return Ok(());
        }
        let mut statement = self.connection.prepare(
            "SELECT locator FROM retention_locations
             WHERE location_kind IN ('source-blob', 'record-blob') AND state = 'purged'",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        for row in rows {
            if let Some(digest) = unhex(&row?) {
                self.purged_blobs.insert(digest);
            }
        }
        Ok(())
    }

    /// Check 1: every blob row against the file on disk.
    fn check_blobs(&mut self) -> crate::error::Result<()> {
        let mut statement = self.connection.prepare(
            "SELECT digest, algorithm, profile, boundary, byte_length FROM blobs ORDER BY digest",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok(BlobRow {
                    digest: row.get(0)?,
                    algorithm: row.get(1)?,
                    profile: row.get(2)?,
                    boundary: row.get(3)?,
                    byte_length: row.get(4)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for row in rows {
            self.report.blobs_checked = self.report.blobs_checked.saturating_add(1);
            self.check_blob(&row);
        }
        Ok(())
    }

    fn check_blob(&mut self, row: &BlobRow) {
        let Ok(bytes) = <[u8; 32]>::try_from(row.digest.as_slice()) else {
            self.push(blob_issue(
                IssueKind::UnsupportedBlob,
                &hex(&row.digest),
                None,
                format!("ledger digest is {} bytes, not 32", row.digest.len()),
            ));
            return;
        };
        let Some(digest) = parse_digest(row, bytes) else {
            self.push(blob_issue(
                IssueKind::UnsupportedBlob,
                &hex(&bytes),
                None,
                format!(
                    "unsupported algorithm {:?}, profile {:?} or boundary {:?}",
                    row.algorithm, row.profile, row.boundary
                ),
            ));
            return;
        };
        let Ok(expected) = u64::try_from(row.byte_length) else {
            self.push(blob_issue(
                IssueKind::UnsupportedBlob,
                &digest.to_hex(),
                None,
                format!("recorded byte length {} is negative", row.byte_length),
            ));
            return;
        };
        let path = crate::payload::blob_path(self.root, digest);
        let shown = self.relative(&path);
        self.verify_blob_file(&path, &shown, digest, bytes, expected);
    }

    fn verify_blob_file(
        &mut self,
        path: &std::path::Path,
        shown: &str,
        digest: mneme_core::ContentDigest,
        bytes: [u8; 32],
        expected: u64,
    ) {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if self.purged_blobs.contains(&bytes) {
                    return;
                }
                self.push(blob_issue(
                    IssueKind::MissingBlob,
                    &digest.to_hex(),
                    Some(shown.to_owned()),
                    format!("no file; ledger records {expected} bytes"),
                ));
                return;
            }
            Err(error) => {
                self.push(blob_issue(
                    IssueKind::UnreadableBlob,
                    &digest.to_hex(),
                    Some(shown.to_owned()),
                    error.to_string(),
                ));
                return;
            }
        };
        if !metadata.is_file() {
            self.push(blob_issue(
                IssueKind::UnreadableBlob,
                &digest.to_hex(),
                Some(shown.to_owned()),
                "blob path is not a regular file".to_owned(),
            ));
            return;
        }
        let is_framed = crate::payload::read_frame_header_length(path, metadata.len())
            .ok()
            .flatten()
            == Some(expected);
        if metadata.len() != expected && !is_framed {
            self.push(blob_issue(
                IssueKind::SizeMismatch,
                &digest.to_hex(),
                Some(shown.to_owned()),
                format!(
                    "file holds {} bytes; ledger records {expected}",
                    metadata.len()
                ),
            ));
            return;
        }
        if is_framed {
            self.verify_framed_blob(FramedBlobTarget {
                path,
                shown,
                digest,
                bytes,
                file_len_bytes: metadata.len(),
                expected_bytes: expected,
            });
            return;
        }
        match self.mode {
            VerifyMode::Quick => {
                self.report.bytes_sized = self.report.bytes_sized.saturating_add(expected);
                self.verified.insert(bytes);
                self.check_outboard_file(path, digest, expected);
            }
            VerifyMode::Full => match hash_file(path, digest.algorithm()) {
                Ok((_, length)) if length != expected => self.push(blob_issue(
                    IssueKind::SizeMismatch,
                    &digest.to_hex(),
                    Some(shown.to_owned()),
                    format!("read {length} bytes; ledger records {expected}"),
                )),
                Ok((actual, _)) if actual != bytes => self.push(blob_issue(
                    IssueKind::DigestMismatch,
                    &digest.to_hex(),
                    Some(shown.to_owned()),
                    format!(
                        "bytes hash to {}; ledger records {}",
                        hex(&actual),
                        digest.to_hex()
                    ),
                )),
                Ok((_, length)) => {
                    self.report.bytes_verified = self.report.bytes_verified.saturating_add(length);
                    self.report.bytes_sized = self.report.bytes_sized.saturating_add(length);
                    self.verified.insert(bytes);
                    self.check_outboard_file(path, digest, expected);
                }
                Err(error) => self.push(blob_issue(
                    IssueKind::UnreadableBlob,
                    &digest.to_hex(),
                    Some(shown.to_owned()),
                    error.to_string(),
                )),
            },
        }
    }

    fn verify_framed_blob(&mut self, target: FramedBlobTarget<'_>) {
        let FramedBlobTarget {
            path,
            shown,
            digest,
            bytes,
            file_len_bytes,
            expected_bytes,
        } = target;
        self.check_stray_framed_outboard(digest);
        let framing = match crate::payload::inspect_path_framing(path, file_len_bytes) {
            Ok(framing) => framing,
            Err(error) => {
                self.push(blob_issue(
                    IssueKind::UnreadableBlob,
                    &digest.to_hex(),
                    Some(shown.to_owned()),
                    error.to_string(),
                ));
                return;
            }
        };
        let is_quick_ok =
            self.inspect_framed_subobjects(path, shown, digest, framing, expected_bytes);
        match self.mode {
            VerifyMode::Quick => {
                if is_quick_ok {
                    self.report.bytes_sized =
                        self.report.bytes_sized.saturating_add(expected_bytes);
                    self.verified.insert(bytes);
                }
            }
            VerifyMode::Full => match crate::payload::verify(self.root, digest, expected_bytes) {
                Ok(()) => {
                    self.report.bytes_verified =
                        self.report.bytes_verified.saturating_add(expected_bytes);
                    self.report.bytes_sized =
                        self.report.bytes_sized.saturating_add(expected_bytes);
                    self.verified.insert(bytes);
                }
                Err(error) => {
                    let kind = match &error {
                        crate::error::Failure::MissingBlob { .. } => IssueKind::MissingBlob,
                        crate::error::Failure::CorruptBlob { .. } => IssueKind::DigestMismatch,
                        _ => IssueKind::UnreadableBlob,
                    };
                    self.push(blob_issue(
                        kind,
                        &digest.to_hex(),
                        Some(shown.to_owned()),
                        error.to_string(),
                    ));
                }
            },
        }
    }

    fn check_stray_framed_outboard(&mut self, digest: mneme_core::ContentDigest) {
        let ob_path = crate::outboard::path(self.root, digest);
        match std::fs::symlink_metadata(&ob_path) {
            Ok(_) => {
                self.report.outboards_checked = self.report.outboards_checked.saturating_add(1);
                self.push(blob_issue(
                    IssueKind::CorruptOutboard,
                    &digest.to_hex(),
                    Some(self.relative(&ob_path)),
                    "framed blob must not carry a bao-tree outboard".to_owned(),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                self.report.outboards_checked = self.report.outboards_checked.saturating_add(1);
                self.push(blob_issue(
                    IssueKind::CorruptOutboard,
                    &digest.to_hex(),
                    Some(self.relative(&ob_path)),
                    format!("cannot inspect outboard: {error}"),
                ));
            }
        }
    }

    fn inspect_framed_subobjects(
        &mut self,
        path: &std::path::Path,
        shown: &str,
        digest: mneme_core::ContentDigest,
        framing: crate::payload::BlobFraming,
        expected: u64,
    ) -> bool {
        match framing {
            crate::payload::BlobFraming::Raw
            | crate::payload::BlobFraming::Zstd
            | crate::payload::BlobFraming::Encrypted => true,
            crate::payload::BlobFraming::ZstdDict => {
                self.inspect_zstd_dict_subobject(path, shown, digest)
            }
            crate::payload::BlobFraming::FastCdc => {
                self.inspect_cdc_subobjects(path, shown, digest, expected)
            }
        }
    }

    fn inspect_zstd_dict_subobject(
        &mut self,
        path: &std::path::Path,
        shown: &str,
        digest: mneme_core::ContentDigest,
    ) -> bool {
        let dict_digest = match crate::payload::read_zstd_dict_header_info(path, digest) {
            Ok((_, dict_digest)) => dict_digest,
            Err(error) => {
                if self.mode == VerifyMode::Quick {
                    self.push(blob_issue(
                        IssueKind::DigestMismatch,
                        &digest.to_hex(),
                        Some(shown.to_owned()),
                        error.to_string(),
                    ));
                }
                return false;
            }
        };
        self.live_framed_refs
            .dicts
            .insert((dict_digest.algorithm(), *dict_digest.as_bytes()));
        if self.mode == VerifyMode::Quick {
            return self.check_quick_dict(dict_digest);
        }
        true
    }

    fn inspect_cdc_subobjects(
        &mut self,
        path: &std::path::Path,
        shown: &str,
        digest: mneme_core::ContentDigest,
        expected: u64,
    ) -> bool {
        let disk_bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) => {
                if self.mode == VerifyMode::Quick {
                    self.push(blob_issue(
                        IssueKind::UnreadableBlob,
                        &digest.to_hex(),
                        Some(shown.to_owned()),
                        error.to_string(),
                    ));
                }
                return false;
            }
        };
        let (manifest_len, chunks) = match crate::dedup::parse_cdc_manifest(
            digest,
            &disk_bytes,
            crate::payload::MAX_DECOMPRESSED_BLOB_BYTES,
        ) {
            Ok(parsed) => parsed,
            Err(error) => {
                if self.mode == VerifyMode::Quick {
                    self.push(blob_issue(
                        IssueKind::DigestMismatch,
                        &digest.to_hex(),
                        Some(shown.to_owned()),
                        error.to_string(),
                    ));
                }
                return false;
            }
        };
        let mut is_all_ok = manifest_len == expected;
        if !is_all_ok && self.mode == VerifyMode::Quick {
            self.push(blob_issue(
                IssueKind::SizeMismatch,
                &digest.to_hex(),
                Some(shown.to_owned()),
                format!("FastCDC manifest length {manifest_len} differs from ledger {expected}"),
            ));
        }
        for (chunk_digest, chunk_len) in chunks {
            self.live_framed_refs
                .chunks
                .insert((chunk_digest.algorithm(), *chunk_digest.as_bytes()));
            if !self.inspect_cdc_chunk(chunk_digest, chunk_len) {
                is_all_ok = false;
            }
        }
        is_all_ok
    }

    fn inspect_cdc_chunk(
        &mut self,
        chunk_digest: mneme_core::ContentDigest,
        expected_len: u64,
    ) -> bool {
        let chunk_path = crate::dedup::resolve_chunk_path(self.root, chunk_digest);
        let chunk_shown = self.relative(&chunk_path);
        let metadata = match std::fs::symlink_metadata(&chunk_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if self.mode == VerifyMode::Quick {
                    self.push(blob_issue(
                        IssueKind::MissingBlob,
                        &chunk_digest.to_hex(),
                        Some(chunk_shown),
                        format!("missing FastCDC chunk; manifest records {expected_len} bytes"),
                    ));
                }
                return false;
            }
            Err(error) => {
                if self.mode == VerifyMode::Quick {
                    self.push(blob_issue(
                        IssueKind::UnreadableBlob,
                        &chunk_digest.to_hex(),
                        Some(chunk_shown),
                        error.to_string(),
                    ));
                }
                return false;
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            if self.mode == VerifyMode::Quick {
                self.push(blob_issue(
                    IssueKind::UnreadableBlob,
                    &chunk_digest.to_hex(),
                    Some(chunk_shown),
                    "FastCDC chunk path is not a regular file".to_owned(),
                ));
            }
            return false;
        }
        let framing = match crate::payload::inspect_path_framing(&chunk_path, metadata.len()) {
            Ok(framing) => framing,
            Err(error) => {
                if self.mode == VerifyMode::Quick {
                    self.push(blob_issue(
                        IssueKind::UnreadableBlob,
                        &chunk_digest.to_hex(),
                        Some(chunk_shown),
                        error.to_string(),
                    ));
                }
                return false;
            }
        };
        match framing {
            crate::payload::BlobFraming::Raw => {
                if metadata.len() != expected_len {
                    if self.mode == VerifyMode::Quick {
                        self.push(blob_issue(
                            IssueKind::SizeMismatch,
                            &chunk_digest.to_hex(),
                            Some(chunk_shown),
                            format!(
                                "FastCDC chunk holds {} bytes; manifest records {expected_len}",
                                metadata.len()
                            ),
                        ));
                    }
                    return false;
                }
                true
            }
            crate::payload::BlobFraming::Zstd | crate::payload::BlobFraming::Encrypted => {
                let header_len =
                    crate::payload::read_frame_header_length(&chunk_path, metadata.len())
                        .ok()
                        .flatten();
                if header_len != Some(expected_len) {
                    if self.mode == VerifyMode::Quick {
                        self.push(blob_issue(
                            IssueKind::SizeMismatch,
                            &chunk_digest.to_hex(),
                            Some(chunk_shown),
                            format!(
                                "compressed FastCDC chunk header length {header_len:?} differs from manifest {expected_len}"
                            ),
                        ));
                    }
                    return false;
                }
                true
            }
            crate::payload::BlobFraming::ZstdDict => {
                match crate::payload::read_zstd_dict_header_info(&chunk_path, chunk_digest) {
                    Ok((header_len, dict_digest)) => {
                        self.live_framed_refs
                            .dicts
                            .insert((dict_digest.algorithm(), *dict_digest.as_bytes()));
                        let is_len_ok = header_len == expected_len;
                        if !is_len_ok && self.mode == VerifyMode::Quick {
                            self.push(blob_issue(
                                IssueKind::SizeMismatch,
                                &chunk_digest.to_hex(),
                                Some(chunk_shown),
                                format!(
                                    "dictionary-compressed FastCDC chunk length {header_len} differs from manifest {expected_len}"
                                ),
                            ));
                        }
                        let is_dict_ok = if self.mode == VerifyMode::Quick {
                            self.check_quick_dict(dict_digest)
                        } else {
                            true
                        };
                        is_len_ok && is_dict_ok
                    }
                    Err(error) => {
                        if self.mode == VerifyMode::Quick {
                            self.push(blob_issue(
                                IssueKind::DigestMismatch,
                                &chunk_digest.to_hex(),
                                Some(chunk_shown),
                                error.to_string(),
                            ));
                        }
                        false
                    }
                }
            }
            crate::payload::BlobFraming::FastCdc => {
                if self.mode == VerifyMode::Quick {
                    self.push(blob_issue(
                        IssueKind::DigestMismatch,
                        &chunk_digest.to_hex(),
                        Some(chunk_shown),
                        "nested FastCDC manifest is not valid inside a chunk".to_owned(),
                    ));
                }
                false
            }
        }
    }

    fn check_quick_dict(&mut self, dict_digest: mneme_core::ContentDigest) -> bool {
        let dict_path = crate::dedup::resolve_dictionary_path(self.root, dict_digest);
        let dict_shown = self.relative(&dict_path);
        let metadata = match std::fs::symlink_metadata(&dict_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.push(blob_issue(
                    IssueKind::MissingBlob,
                    &dict_digest.to_hex(),
                    Some(dict_shown),
                    "referenced Zstd dictionary file is missing".to_owned(),
                ));
                return false;
            }
            Err(error) => {
                self.push(blob_issue(
                    IssueKind::UnreadableBlob,
                    &dict_digest.to_hex(),
                    Some(dict_shown),
                    error.to_string(),
                ));
                return false;
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            self.push(blob_issue(
                IssueKind::UnreadableBlob,
                &dict_digest.to_hex(),
                Some(dict_shown),
                "Zstd dictionary path is not a regular file".to_owned(),
            ));
            return false;
        }
        if metadata.len() == 0 || metadata.len() > crate::dedup::MAX_ZSTD_DICTIONARY_BYTES {
            self.push(blob_issue(
                IssueKind::SizeMismatch,
                &dict_digest.to_hex(),
                Some(dict_shown),
                format!("Zstd dictionary length {} is out of bounds", metadata.len()),
            ));
            return false;
        }
        true
    }

    fn check_outboard_file(
        &mut self,
        blob_path: &std::path::Path,
        digest: mneme_core::ContentDigest,
        expected: u64,
    ) {
        let ob_path = crate::outboard::path(self.root, digest);
        let ob_shown = self.relative(&ob_path);
        let metadata = match std::fs::symlink_metadata(&ob_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => {
                self.push(blob_issue(
                    IssueKind::CorruptOutboard,
                    &digest.to_hex(),
                    Some(ob_shown),
                    format!("cannot inspect outboard: {error}"),
                ));
                return;
            }
        };
        self.report.outboards_checked = self.report.outboards_checked.saturating_add(1);
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            self.push(blob_issue(
                IssueKind::CorruptOutboard,
                &digest.to_hex(),
                Some(ob_shown),
                "bao-tree outboard path is not a regular file".to_owned(),
            ));
            return;
        }
        if digest.algorithm() != mneme_core::HashAlgorithm::Blake3 {
            self.push(blob_issue(
                IssueKind::CorruptOutboard,
                &digest.to_hex(),
                Some(ob_shown),
                "non-BLAKE3 blob must not carry a bao-tree outboard".to_owned(),
            ));
            return;
        }
        let expected_len =
            bao_tree::BaoTree::new(expected, crate::outboard::BLOCK_SIZE).outboard_size();
        if expected_len == 0 || metadata.len() != expected_len {
            self.push(blob_issue(
                IssueKind::CorruptOutboard,
                &digest.to_hex(),
                Some(ob_shown),
                format!(
                    "bao-tree outboard holds {} bytes; expected {expected_len}",
                    metadata.len()
                ),
            ));
            return;
        }
        if self.mode == VerifyMode::Full
            && let Err(reason) =
                crate::outboard::verify_matches_blob(blob_path, &ob_path, digest, expected)
        {
            self.push(blob_issue(
                IssueKind::CorruptOutboard,
                &digest.to_hex(),
                Some(ob_shown),
                reason,
            ));
        }
    }

    /// Check 2a: every record revision names a ledger blob.
    fn check_records(&mut self) -> crate::error::Result<()> {
        let mut statement = self
            .connection
            .prepare("SELECT record_id, revision_id, full_digest FROM records ORDER BY record_id, revision_id")?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for (record, revision, full) in rows {
            self.report.records_checked = self.report.records_checked.saturating_add(1);
            let owner = format!("{}@{}", hex(&record), hex(&revision));
            let Ok(full) = <[u8; 32]>::try_from(full.as_slice()) else {
                self.push(blob_issue(
                    IssueKind::DanglingRecordBlob,
                    "",
                    None,
                    format!("record {owner} has a malformed full-record digest"),
                ));
                continue;
            };
            self.record_owners
                .entry(full)
                .or_default()
                .push(owner.clone());
            if !self.blob_digests.contains(&full) {
                let mut issue = blob_issue(
                    IssueKind::DanglingRecordBlob,
                    &hex(&full),
                    None,
                    format!("record {owner} names a full-record blob the ledger does not hold"),
                );
                issue.records.push(owner);
                self.push(issue);
            }
        }
        Ok(())
    }

    /// Check 2b: a retained source named by a stored envelope is held. Reads
    /// the (already verified) full-record blobs, so full mode only.
    fn check_source_references(&mut self) -> crate::error::Result<()> {
        if self.mode != VerifyMode::Full {
            return Ok(());
        }
        let forgotten = super::sweep::forgotten_suppressions_in(self.connection)?;
        let active_head = self.active_head_records()?;
        let envelopes: Vec<([u8; 32], Vec<String>)> = self
            .record_owners
            .iter()
            .filter(|(digest, _)| self.verified.contains(*digest))
            .map(|(digest, owners)| (*digest, owners.clone()))
            .collect();
        let mut sources: std::collections::BTreeMap<[u8; 32], Vec<String>> =
            std::collections::BTreeMap::new();
        for (digest, owners) in envelopes {
            let Some(content) = self.digest_of(digest) else {
                continue;
            };
            let bytes = match crate::payload::read(self.root, content) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            let envelope = mneme_core::binary::decode(&bytes)
                .map_err(|diagnostic| diagnostic.to_string())
                .and_then(|value| {
                    mneme_core::RecordEnvelope::from_value(&value)
                        .map_err(|diagnostics| super::join(&diagnostics))
                });
            match envelope {
                Ok(record) => {
                    if let Some(source) = super::validation::retained_source_digest(&record) {
                        sources
                            .entry(*source.as_bytes())
                            .or_default()
                            .extend(owners.clone());
                        let is_active =
                            active_head.contains(&(record.record_id, record.revision_id));
                        let is_forgotten = forgotten.matches(record.record_id, record.revision_id);
                        if is_active
                            && !is_forgotten
                            && !self.blob_digests.contains(source.as_bytes())
                        {
                            let mut issue = blob_issue(
                                IssueKind::DanglingSourceBlob,
                                &source.to_hex(),
                                Some(self.relative(&crate::payload::blob_path(self.root, source))),
                                "active source-revision references a retained source blob the ledger does not hold"
                                    .to_owned(),
                            );
                            issue.records = owners;
                            self.push(issue);
                        }
                    }
                }
                Err(reason) => {
                    let mut issue = blob_issue(
                        IssueKind::InvalidRecordBlob,
                        &content.to_hex(),
                        Some(self.relative(&crate::payload::blob_path(self.root, content))),
                        format!("stored record envelope is invalid: {reason}"),
                    );
                    issue.records = owners;
                    self.push(issue);
                }
            }
        }
        for (digest, owners) in sources {
            self.record_owners.entry(digest).or_default().extend(owners);
        }
        Ok(())
    }

    /// Check 2c: verify SQLite `#89` metadata projection parity (`entities`,
    /// `relations`, `documents`) against active non-forgotten head records.
    fn check_metadata_projection(&mut self) -> crate::error::Result<()> {
        if !super::table_exists(self.connection, "entities")?
            || !super::table_exists(self.connection, "relations")?
            || !super::table_exists(self.connection, "documents")?
        {
            return Ok(());
        }
        let forgotten = super::sweep::forgotten_suppressions_in(self.connection)?;
        let context = mneme_core::WorkspaceRevisionId::from_bytes([0; 16]);
        let mut statement = self.connection.prepare(
            "SELECT r.record_id, r.revision_id, r.kind, r.full_digest
             FROM record_membership m
             JOIN records r ON r.record_id = m.record_id AND r.revision_id = m.revision_id
             WHERE m.last_sequence IS NULL AND r.kind IN ('entity', 'relation', 'document')
             ORDER BY r.record_id",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let active: Vec<_> = rows
            .into_iter()
            .filter_map(|(record_bytes, rev_bytes, kind, full_bytes)| {
                let record_id = super::record_id_from_blob(&record_bytes, context).ok()?;
                let revision_id = super::revision_id_from_blob(&rev_bytes, context).ok()?;
                if forgotten.matches(record_id, revision_id) {
                    return None;
                }
                let decoded = if self.mode == VerifyMode::Full {
                    self.decode_verified_envelope(&full_bytes)
                } else {
                    None
                };
                Some((
                    *record_id.as_bytes(),
                    *revision_id.as_bytes(),
                    kind,
                    decoded,
                ))
            })
            .collect();
        let expected_entities: std::collections::BTreeMap<[u8; 16], ExpectedEntityRow> = active
            .iter()
            .filter(|(_, _, kind, _)| kind == "entity")
            .map(|(key, rev, _, decoded)| {
                (
                    *key,
                    ExpectedEntityRow::from_envelope(*rev, decoded.as_ref()),
                )
            })
            .collect();
        let expected_relations: std::collections::BTreeMap<[u8; 16], ExpectedRelationRow> = active
            .iter()
            .filter(|(_, _, kind, _)| kind == "relation")
            .map(|(key, rev, _, decoded)| {
                (
                    *key,
                    ExpectedRelationRow::from_envelope(*rev, decoded.as_ref()),
                )
            })
            .collect();
        let expected_documents: std::collections::BTreeMap<[u8; 16], ExpectedDocumentRow> = active
            .iter()
            .filter(|(_, _, kind, _)| kind == "document")
            .map(|(key, rev, _, decoded)| {
                (
                    *key,
                    ExpectedDocumentRow::from_envelope(*rev, decoded.as_ref()),
                )
            })
            .collect();
        self.verify_projected_entities(&expected_entities)?;
        self.verify_projected_relations(&expected_relations)?;
        self.verify_projected_documents(&expected_documents)?;
        Ok(())
    }

    fn decode_verified_envelope(&self, full_bytes: &[u8]) -> Option<mneme_core::RecordEnvelope> {
        let digest_bytes = <[u8; 32]>::try_from(full_bytes).ok()?;
        if !self.verified.contains(&digest_bytes) {
            return None;
        }
        let content = self.digest_of(digest_bytes)?;
        let bytes = crate::payload::read(self.root, content).ok()?;
        let value = mneme_core::binary::decode(&bytes).ok()?;
        mneme_core::RecordEnvelope::from_value(&value).ok()
    }

    fn verify_projected_entities(
        &mut self,
        expected: &std::collections::BTreeMap<[u8; 16], ExpectedEntityRow>,
    ) -> crate::error::Result<()> {
        let mut statement = self.connection.prepare(
            "SELECT record_id, revision_id, scope, entity_type, label, external_id FROM entities",
        )?;
        let actual_rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut seen = std::collections::BTreeSet::new();
        for (record_bytes, rev_bytes, scope, entity_type, label, external_id) in actual_rows {
            let Ok(key) = <[u8; 16]>::try_from(record_bytes.as_slice()) else {
                self.push(projection_issue(
                    None,
                    "entities projection contains malformed record_id".to_owned(),
                ));
                continue;
            };
            seen.insert(key);
            let Some(wanted) = expected.get(&key) else {
                self.push(projection_issue(
                    Some(format!("{}@{}", hex(&key), hex(&rev_bytes))),
                    "entities projection holds stale or forgotten record".to_owned(),
                ));
                continue;
            };
            if rev_bytes.as_slice() != wanted.revision_id.as_slice() {
                self.push(projection_issue(
                    Some(format!("{}@{}", hex(&key), hex(&wanted.revision_id))),
                    format!(
                        "entities projection revision {} differs from active head {}",
                        hex(&rev_bytes),
                        hex(&wanted.revision_id)
                    ),
                ));
                continue;
            }
            if let Some(fields) = &wanted.fields
                && (scope != fields.scope
                    || entity_type != fields.entity_type
                    || label != fields.label
                    || external_id != fields.external_id)
            {
                self.push(projection_issue(
                    Some(format!("{}@{}", hex(&key), hex(&wanted.revision_id))),
                    "entities projection columns disagree with active head record envelope"
                        .to_owned(),
                ));
            }
        }
        for (key, wanted) in expected {
            if !seen.contains(key) {
                self.push(projection_issue(
                    Some(format!("{}@{}", hex(key), hex(&wanted.revision_id))),
                    "active head entity record is missing from entities projection".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn verify_projected_relations(
        &mut self,
        expected: &std::collections::BTreeMap<[u8; 16], ExpectedRelationRow>,
    ) -> crate::error::Result<()> {
        let mut statement = self.connection.prepare(
            "SELECT record_id, revision_id, scope, relation_type, from_id, to_id FROM relations",
        )?;
        let actual_rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut seen = std::collections::BTreeSet::new();
        for (record_bytes, rev_bytes, scope, relation_type, from_id, to_id) in actual_rows {
            let Ok(key) = <[u8; 16]>::try_from(record_bytes.as_slice()) else {
                self.push(projection_issue(
                    None,
                    "relations projection contains malformed record_id".to_owned(),
                ));
                continue;
            };
            seen.insert(key);
            let Some(wanted) = expected.get(&key) else {
                self.push(projection_issue(
                    Some(format!("{}@{}", hex(&key), hex(&rev_bytes))),
                    "relations projection holds stale or forgotten record".to_owned(),
                ));
                continue;
            };
            if rev_bytes.as_slice() != wanted.revision_id.as_slice() {
                self.push(projection_issue(
                    Some(format!("{}@{}", hex(&key), hex(&wanted.revision_id))),
                    format!(
                        "relations projection revision {} differs from active head {}",
                        hex(&rev_bytes),
                        hex(&wanted.revision_id)
                    ),
                ));
                continue;
            }
            if let Some(fields) = &wanted.fields
                && (scope != fields.scope
                    || relation_type != fields.relation_type
                    || from_id != fields.from_id
                    || to_id != fields.to_id)
            {
                self.push(projection_issue(
                    Some(format!("{}@{}", hex(&key), hex(&wanted.revision_id))),
                    "relations projection columns disagree with active head record envelope"
                        .to_owned(),
                ));
            }
        }
        for (key, wanted) in expected {
            if !seen.contains(key) {
                self.push(projection_issue(
                    Some(format!("{}@{}", hex(key), hex(&wanted.revision_id))),
                    "active head relation record is missing from relations projection".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn verify_projected_documents(
        &mut self,
        expected: &std::collections::BTreeMap<[u8; 16], ExpectedDocumentRow>,
    ) -> crate::error::Result<()> {
        let mut statement = self.connection.prepare(
            "SELECT record_id, revision_id, scope, path, title, source_revision_id FROM documents",
        )?;
        let actual_rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut seen = std::collections::BTreeSet::new();
        for (record_bytes, rev_bytes, scope, path, title, source_revision_id) in actual_rows {
            let Ok(key) = <[u8; 16]>::try_from(record_bytes.as_slice()) else {
                self.push(projection_issue(
                    None,
                    "documents projection contains malformed record_id".to_owned(),
                ));
                continue;
            };
            seen.insert(key);
            let Some(wanted) = expected.get(&key) else {
                self.push(projection_issue(
                    Some(format!("{}@{}", hex(&key), hex(&rev_bytes))),
                    "documents projection holds stale or forgotten record".to_owned(),
                ));
                continue;
            };
            if rev_bytes.as_slice() != wanted.revision_id.as_slice() {
                self.push(projection_issue(
                    Some(format!("{}@{}", hex(&key), hex(&wanted.revision_id))),
                    format!(
                        "documents projection revision {} differs from active head {}",
                        hex(&rev_bytes),
                        hex(&wanted.revision_id)
                    ),
                ));
                continue;
            }
            if let Some(fields) = &wanted.fields
                && (scope != fields.scope
                    || path != fields.path
                    || title != fields.title
                    || source_revision_id != fields.source_revision_id)
            {
                self.push(projection_issue(
                    Some(format!("{}@{}", hex(&key), hex(&wanted.revision_id))),
                    "documents projection columns disagree with active head record envelope"
                        .to_owned(),
                ));
            }
        }
        for (key, wanted) in expected {
            if !seen.contains(key) {
                self.push(projection_issue(
                    Some(format!("{}@{}", hex(key), hex(&wanted.revision_id))),
                    "active head document record is missing from documents projection".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn active_head_records(
        &self,
    ) -> crate::error::Result<
        std::collections::BTreeSet<(mneme_core::RecordId, mneme_core::RevisionId)>,
    > {
        let context = mneme_core::WorkspaceRevisionId::from_bytes([0; 16]);
        let mut statement = self.connection.prepare(
            "SELECT record_id, revision_id FROM record_membership WHERE last_sequence IS NULL",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut active = std::collections::BTreeSet::new();
        for (record_bytes, revision_bytes) in rows {
            if let (Ok(record_id), Ok(revision_id)) = (
                super::record_id_from_blob(&record_bytes, context),
                super::revision_id_from_blob(&revision_bytes, context),
            ) {
                active.insert((record_id, revision_id));
            }
        }
        Ok(active)
    }

    /// Check 3: the chain, every manifest, and the head's blob set.
    fn check_revisions(
        &mut self,
    ) -> crate::error::Result<Option<std::collections::BTreeSet<mneme_core::ContentDigest>>> {
        let journal = self.journal()?;
        let mut cursor = 0_usize;
        let mut blobs = std::collections::BTreeSet::new();
        let mut previous: Option<(u64, mneme_core::WorkspaceRevisionId)> = None;
        let mut head = None;
        let has_algorithm_col =
            super::has_column(self.connection, "revisions", "manifest_algorithm")?;
        let query = if has_algorithm_col {
            "SELECT sequence, revision_id, parent_revision_id, manifest, manifest_digest,
                    manifest_algorithm
             FROM revisions ORDER BY sequence"
        } else {
            "SELECT sequence, revision_id, parent_revision_id, manifest, manifest_digest,
                    NULL AS manifest_algorithm
             FROM revisions ORDER BY sequence"
        };
        let mut statement = self.connection.prepare(query)?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let sequence = super::db_u64(row.get::<_, i64>(0)?, "sequence")?;
            let revision_bytes: Vec<u8> = row.get(1)?;
            let parent_bytes: Option<Vec<u8>> = row.get(2)?;
            let manifest_bytes: Vec<u8> = row.get(3)?;
            let digest_bytes: Vec<u8> = row.get(4)?;
            let manifest_algorithm: Option<String> = row.get(5)?;
            let Ok(revision) = super::revision_from_blob(&revision_bytes) else {
                self.push(chain_issue(
                    IssueKind::BrokenChain,
                    &hex(&revision_bytes),
                    sequence,
                    "revision id is not 16 bytes".to_owned(),
                ));
                continue;
            };
            let shown = revision.to_string();
            let parent = match parent_bytes.as_deref().map(super::revision_from_blob) {
                Some(Ok(parent)) => Some(parent),
                Some(Err(_)) => {
                    self.push(chain_issue(
                        IssueKind::BrokenChain,
                        &shown,
                        sequence,
                        "parent revision id is not 16 bytes".to_owned(),
                    ));
                    continue;
                }
                None => None,
            };
            if let Some(reason) = chain_fault(previous, sequence, revision, parent) {
                self.push(chain_issue(
                    IssueKind::BrokenChain,
                    &shown,
                    sequence,
                    reason,
                ));
            }
            let sequence_value = super::db_i64(sequence, "sequence")?;
            while cursor < journal.len() && journal[cursor].0 <= sequence_value {
                let (_, digest, change) = &journal[cursor];
                if let Err(error) = super::apply_blob_change(&mut blobs, *digest, change, revision)
                {
                    self.push(chain_issue(
                        IssueKind::ManifestMismatch,
                        &shown,
                        sequence,
                        error.to_string(),
                    ));
                }
                cursor = cursor.saturating_add(1);
            }
            let outcome = self.check_manifest(&ManifestRow {
                revision,
                parent,
                sequence,
                bytes: &manifest_bytes,
                digest: &digest_bytes,
                algorithm: manifest_algorithm
                    .as_deref()
                    .unwrap_or(mneme_core::hashing::ALGORITHM_SHA256),
                blobs: &blobs,
            });
            if let Err(reason) = outcome {
                self.push(chain_issue(
                    IssueKind::ManifestMismatch,
                    &shown,
                    sequence,
                    reason,
                ));
            } else {
                self.report.revisions_verified = self.report.revisions_verified.saturating_add(1);
            }
            previous = Some((sequence, revision));
            head = Some(revision);
        }
        self.report.head_revision = head.map(|revision| revision.to_string());
        Ok(head.map(|_| blobs))
    }

    fn check_manifest(&self, row: &ManifestRow<'_>) -> Result<(), String> {
        let stored_digest = super::digest_with(
            row.digest,
            row.algorithm,
            "preserves-canonical-binary-v1",
            "payload",
            row.revision,
        )
        .map_err(|error| error.to_string())?;
        let records = super::manifest_record_set(self.connection, row.sequence, row.revision)
            .map_err(|error| error.to_string())?;
        let rebuilt = crate::catalog::Manifest {
            revision: row.revision,
            parents: row.parent.into_iter().collect(),
            records,
            blobs: row.blobs.clone(),
        };
        let expected_digest = rebuilt.digest_with(stored_digest.algorithm());
        if expected_digest != stored_digest {
            return Err(format!(
                "reconstructed manifest digest {} differs from recorded {}",
                expected_digest.to_hex(),
                stored_digest.to_hex()
            ));
        }
        if !row.bytes.is_empty() {
            let value = mneme_core::binary::decode(row.bytes).map_err(|diagnostic| {
                format!("stored manifest is not valid Preserves: {diagnostic}")
            })?;
            let committed = crate::catalog::Manifest::from_value(&value)
                .map_err(|reason| format!("stored manifest is invalid: {reason}"))?;
            if committed != rebuilt || committed.encode() != row.bytes {
                return Err(
                    "stored manifest does not match the membership and blob journal the ledger reconstructs"
                        .to_owned(),
                );
            }
        }
        Ok(())
    }

    #[allow(clippy::type_complexity)] // one local row shape
    fn journal(&mut self) -> crate::error::Result<Vec<(i64, mneme_core::ContentDigest, String)>> {
        let mut statement = self.connection.prepare(
            "SELECT c.revision_sequence, c.digest, b.algorithm, b.profile, b.boundary, c.change
             FROM revision_blob_changes c
             JOIN blobs b ON b.digest = c.digest
             ORDER BY c.revision_sequence, c.digest",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut journal = Vec::with_capacity(rows.len());
        for (sequence, digest, algorithm, profile, boundary, change) in rows {
            let parsed = <[u8; 32]>::try_from(digest.as_slice())
                .ok()
                .and_then(|bytes| {
                    parse_digest(
                        &BlobRow {
                            digest: Vec::new(),
                            algorithm: algorithm.clone(),
                            profile: profile.clone(),
                            boundary: boundary.clone(),
                            byte_length: 0,
                        },
                        bytes,
                    )
                });
            match parsed {
                Some(digest) => journal.push((sequence, digest, change)),
                None => self.push(blob_issue(
                    IssueKind::UnsupportedBlob,
                    &hex(&digest),
                    None,
                    format!(
                        "blob-set journal row at sequence {sequence} has unsupported algorithm {algorithm:?}, profile {profile:?}, or boundary {boundary:?}"
                    ),
                )),
            }
        }
        Ok(journal)
    }

    /// Journal rows whose digest has no ledger row would silently drop out of
    /// the folded blob set; name them.
    fn check_journal_digests(&mut self) -> crate::error::Result<()> {
        let mut statement = self.connection.prepare(
            "SELECT DISTINCT c.digest FROM revision_blob_changes c
             LEFT JOIN blobs b ON b.digest = c.digest WHERE b.digest IS NULL",
        )?;
        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for digest in rows {
            self.push(blob_issue(
                IssueKind::DanglingJournalBlob,
                &hex(&digest),
                None,
                "a manifest blob journal names this digest but the ledger holds no row".to_owned(),
            ));
        }
        Ok(())
    }

    fn find_orphans(&mut self) -> crate::error::Result<()> {
        let mut referenced = std::collections::BTreeSet::new();
        let mut statement = self
            .connection
            .prepare("SELECT DISTINCT digest FROM revision_blob_changes UNION SELECT full_digest FROM records")?;
        for row in statement.query_map([], |row| row.get::<_, Vec<u8>>(0))? {
            if let Ok(digest) = <[u8; 32]>::try_from(row?.as_slice()) {
                referenced.insert(digest);
            }
        }
        let unreferenced: Vec<[u8; 32]> = self
            .blob_digests
            .iter()
            .filter(|digest| !referenced.contains(*digest))
            .copied()
            .collect();
        for digest in unreferenced {
            let path = self.row_path(digest);
            self.report.orphans.push(OrphanBlob {
                reason: OrphanReason::RowWithoutReference,
                digest: hex(&digest),
                path,
            });
        }
        for file in crate::payload::blob_file_inventory(self.root)? {
            let is_orphan = match file.kind {
                crate::payload::StoredObjectKind::Primary(_)
                | crate::payload::StoredObjectKind::Outboard(_) => {
                    !self.blob_digests.contains(&file.digest)
                }
                crate::payload::StoredObjectKind::Chunk(algo) => {
                    !self.live_framed_refs.contains_chunk(algo, file.digest)
                }
                crate::payload::StoredObjectKind::Dictionary(algo) => {
                    !self.live_framed_refs.contains_dict(algo, file.digest)
                }
            };
            if is_orphan {
                self.report.orphans.push(OrphanBlob {
                    reason: OrphanReason::FileWithoutRow,
                    digest: hex(&file.digest),
                    path: self.relative(&file.path),
                });
            }
        }
        Ok(())
    }

    /// Fill each blob issue's record list from the reference map.
    fn attach_owners(&mut self) {
        for issue in &mut self.report.issues {
            if !issue.records.is_empty() {
                continue;
            }
            let Some(bytes) = issue.digest.as_deref().and_then(unhex) else {
                continue;
            };
            if let Some(owners) = self.record_owners.get(&bytes) {
                let mut owners = owners.clone();
                owners.sort();
                owners.dedup();
                issue.records = owners;
            }
        }
        for issue in &mut self.report.issues {
            issue.records.sort();
            issue.records.dedup();
        }
    }

    fn push(&mut self, issue: VerifyIssue) {
        self.report.issues.push(issue);
    }

    fn relative(&self, path: &std::path::Path) -> String {
        path.strip_prefix(self.root)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned()
    }

    /// The path a row's digest would have, from the stored row metadata.
    fn row_path(&self, bytes: [u8; 32]) -> String {
        match self.digest_of(bytes) {
            Some(digest) => self.relative(&crate::payload::blob_path(self.root, digest)),
            None => hex(&bytes),
        }
    }

    /// The full digest identity for a ledger row.
    fn digest_of(&self, bytes: [u8; 32]) -> Option<mneme_core::ContentDigest> {
        let row = self
            .connection
            .query_row(
                "SELECT algorithm, profile, boundary, byte_length FROM blobs WHERE digest = ?1",
                rusqlite::params![bytes.as_slice()],
                |row| {
                    Ok(BlobRow {
                        digest: bytes.to_vec(),
                        algorithm: row.get(0)?,
                        profile: row.get(1)?,
                        boundary: row.get(2)?,
                        byte_length: row.get(3)?,
                    })
                },
            )
            .optional()
            .ok()
            .flatten()?;
        parse_digest(&row, bytes)
    }
}

struct FramedBlobTarget<'a> {
    path: &'a std::path::Path,
    shown: &'a str,
    digest: mneme_core::ContentDigest,
    bytes: [u8; 32],
    file_len_bytes: u64,
    expected_bytes: u64,
}

struct ManifestRow<'a> {
    revision: mneme_core::WorkspaceRevisionId,
    parent: Option<mneme_core::WorkspaceRevisionId>,
    sequence: u64,
    bytes: &'a [u8],
    digest: &'a [u8],
    algorithm: &'a str,
    blobs: &'a std::collections::BTreeSet<mneme_core::ContentDigest>,
}

/// Why this revision does not extend the chain, if it does not.
fn chain_fault(
    previous: Option<(u64, mneme_core::WorkspaceRevisionId)>,
    sequence: u64,
    revision: mneme_core::WorkspaceRevisionId,
    parent: Option<mneme_core::WorkspaceRevisionId>,
) -> Option<String> {
    match previous {
        None if sequence != 0 => Some(format!(
            "history starts at sequence {sequence}, not genesis 0"
        )),
        None => parent.map(|parent| format!("genesis names parent {parent}")),
        Some((last, _)) if sequence != last.saturating_add(1) => {
            Some(format!("sequence jumps from {last} to {sequence}"))
        }
        Some((_, expected)) => match parent {
            Some(parent) if parent == expected => None,
            Some(parent) => Some(format!(
                "parent is {parent}; the previous revision is {expected} (revision {revision})"
            )),
            None => Some(format!("no parent; the previous revision is {expected}")),
        },
    }
}

fn parse_digest(row: &BlobRow, bytes: [u8; 32]) -> Option<mneme_core::ContentDigest> {
    let algorithm = mneme_core::HashAlgorithm::parse(&row.algorithm)?;
    let profile = mneme_core::EncodingProfile::parse(&row.profile)?;
    let boundary = mneme_core::ValueBoundary::parse(&row.boundary)?;
    mneme_core::ContentDigest::from_parts(algorithm, profile, boundary, bytes).ok()
}

/// Stream a file through the algorithm's hasher; returns digest and length.
fn hash_file(
    path: &std::path::Path,
    algorithm: mneme_core::HashAlgorithm,
) -> std::io::Result<([u8; 32], u64)> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = mneme_core::hashing::StreamingHasher::new(algorithm);
    let mut buffer = vec![0_u8; STREAM_BUFFER_BYTES];
    let mut length = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        length = length.saturating_add(read as u64);
    }
    Ok((hasher.finish(), length))
}

fn blob_issue(kind: IssueKind, digest: &str, path: Option<String>, detail: String) -> VerifyIssue {
    VerifyIssue {
        kind,
        digest: if digest.is_empty() {
            None
        } else {
            Some(digest.to_owned())
        },
        path,
        records: Vec::new(),
        revision: None,
        sequence: None,
        detail,
    }
}

fn chain_issue(kind: IssueKind, revision: &str, sequence: u64, detail: String) -> VerifyIssue {
    VerifyIssue {
        kind,
        digest: None,
        path: None,
        records: Vec::new(),
        revision: Some(revision.to_owned()),
        sequence: Some(sequence),
        detail,
    }
}

fn projection_issue(record: Option<String>, detail: String) -> VerifyIssue {
    VerifyIssue {
        kind: IssueKind::ProjectionMismatch,
        digest: None,
        path: None,
        records: record.into_iter().collect(),
        revision: None,
        sequence: None,
        detail,
    }
}

struct ExpectedEntityFields {
    scope: String,
    entity_type: String,
    label: String,
    external_id: Option<String>,
}

struct ExpectedEntityRow {
    revision_id: [u8; 16],
    fields: Option<ExpectedEntityFields>,
}

impl ExpectedEntityRow {
    fn from_envelope(revision_id: [u8; 16], envelope: Option<&mneme_core::RecordEnvelope>) -> Self {
        let fields = envelope.map(|record| ExpectedEntityFields {
            scope: record.scope.to_string(),
            entity_type: payload_symbol(&record.payload, "entity-type"),
            label: payload_text(&record.payload, "label")
                .unwrap_or("")
                .to_owned(),
            external_id: extract_external_id(&record.payload),
        });
        Self {
            revision_id,
            fields,
        }
    }
}

struct ExpectedRelationFields {
    scope: String,
    relation_type: String,
    from_id: Option<Vec<u8>>,
    to_id: Option<Vec<u8>>,
}

struct ExpectedRelationRow {
    revision_id: [u8; 16],
    fields: Option<ExpectedRelationFields>,
}

impl ExpectedRelationRow {
    fn from_envelope(revision_id: [u8; 16], envelope: Option<&mneme_core::RecordEnvelope>) -> Self {
        let fields = envelope.map(|record| ExpectedRelationFields {
            scope: record.scope.to_string(),
            relation_type: payload_symbol(&record.payload, "relation-type"),
            from_id: extract_reference_target(record.payload.get("from"))
                .map(|id| id.as_bytes().to_vec()),
            to_id: extract_reference_target(record.payload.get("to"))
                .map(|id| id.as_bytes().to_vec()),
        });
        Self {
            revision_id,
            fields,
        }
    }
}

struct ExpectedDocumentFields {
    scope: String,
    path: Option<String>,
    title: String,
    source_revision_id: Option<Vec<u8>>,
}

struct ExpectedDocumentRow {
    revision_id: [u8; 16],
    fields: Option<ExpectedDocumentFields>,
}

impl ExpectedDocumentRow {
    fn from_envelope(revision_id: [u8; 16], envelope: Option<&mneme_core::RecordEnvelope>) -> Self {
        let fields = envelope.map(|record| ExpectedDocumentFields {
            scope: record.scope.to_string(),
            path: payload_text(&record.payload, "path").map(str::to_owned),
            title: payload_text(&record.payload, "title")
                .unwrap_or("")
                .to_owned(),
            source_revision_id: extract_reference_target(record.payload.get("source-revision"))
                .map(|id| id.as_bytes().to_vec()),
        });
        Self {
            revision_id,
            fields,
        }
    }
}

fn payload_symbol(payload: &mneme_core::Payload, field: &str) -> String {
    payload
        .get(field)
        .and_then(mneme_core::Value::as_symbol)
        .map(|symbol| symbol.as_str().to_owned())
        .unwrap_or_default()
}

fn payload_text<'a>(payload: &'a mneme_core::Payload, field: &str) -> Option<&'a str> {
    payload.get(field).and_then(mneme_core::Value::as_string)
}

fn extract_external_id(payload: &mneme_core::Payload) -> Option<String> {
    let properties = payload
        .get("properties")
        .and_then(mneme_core::Value::as_dictionary)?;
    let value = properties
        .get(&mneme_core::Value::symbol("external-id"))
        .or_else(|| properties.get(&mneme_core::Value::string("external-id")))?;
    value
        .as_string()
        .map(str::to_owned)
        .or_else(|| value.as_symbol().map(|symbol| symbol.as_str().to_owned()))
}

fn extract_reference_target(value: Option<&mneme_core::Value>) -> Option<mneme_core::RecordId> {
    value
        .and_then(|value| mneme_core::Reference::from_value(value, &mneme_core::Path::root()).ok())
        .and_then(|reference| reference.target())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn unhex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (index, slot) in bytes.iter_mut().enumerate() {
        let start = index.saturating_mul(2);
        let end = start.saturating_add(2);
        *slot = u8::from_str_radix(text.get(start..end)?, 16).ok()?;
    }
    Some(bytes)
}
