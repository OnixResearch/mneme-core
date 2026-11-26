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
        verified: std::collections::BTreeSet::new(),
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
    /// Digests whose file passed every check this mode runs.
    verified: std::collections::BTreeSet<[u8; 32]>,
    /// Which records reference each blob digest, for diagnostics.
    record_owners: std::collections::BTreeMap<[u8; 32], Vec<String>>,
}

impl Scrub<'_> {
    fn run(&mut self) -> crate::error::Result<()> {
        self.load_digests()?;
        self.check_records()?;
        self.check_blobs()?;
        self.check_source_references()?;
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
            self.verify_framed_blob(shown, digest, bytes, expected);
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

    fn verify_framed_blob(
        &mut self,
        shown: &str,
        digest: mneme_core::ContentDigest,
        bytes: [u8; 32],
        expected: u64,
    ) {
        match self.mode {
            VerifyMode::Quick => {
                self.report.bytes_sized = self.report.bytes_sized.saturating_add(expected);
                self.verified.insert(bytes);
            }
            VerifyMode::Full => match crate::payload::verify(self.root, digest, expected) {
                Ok(()) => {
                    self.report.bytes_verified =
                        self.report.bytes_verified.saturating_add(expected);
                    self.report.bytes_sized = self.report.bytes_sized.saturating_add(expected);
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
            parent: row.parent,
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
        for (digest, path) in crate::payload::blob_file_inventory(self.root)? {
            if !self.blob_digests.contains(&digest) {
                self.report.orphans.push(OrphanBlob {
                    reason: OrphanReason::FileWithoutRow,
                    digest: hex(&digest),
                    path: self.relative(&path),
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
