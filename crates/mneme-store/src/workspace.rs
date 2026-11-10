//! The durable workspace coordinator.
//!
//! One process serializes mutations through [`Workspace::commit`]. Each commit
//! stages immutable blobs, validates a complete record batch against the current
//! snapshot, checks the caller's base revision, records the manifest, command
//! outcome, and publication intents in one SQLite transaction, then publishes
//! working files as a separately recoverable step. A committed revision never
//! references a missing required blob; filesystem publication never overwrites a
//! divergent external edit.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use mneme_core::{
    ContentDigest, Diagnostic, EncodingProfile, HashAlgorithm, RecordEnvelope, RecordId,
    RecordKind, RecordedTime, Reference, RevisionId, SchemaRegistry, ScopeId, SnapshotIndex,
    SourceContent, Symbol, Value, ValueBoundary, WorkspaceRevisionId, binary, validate_batch,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::blob;
use crate::clock::{Clock, SystemClock};
use crate::command::{CommitCommand, ImportCandidateDraft, PublicationDraft, SourceBlobDraft};
use crate::error::{Result, StoreError};
use crate::faults::{FaultInjector, FaultPoint, NoFaults, check};
use crate::manifest::{Manifest, ManifestRecord};

/// The ledger file name inside a workspace root.
pub const LEDGER_FILE: &str = "ledger.sqlite3";
/// The supported on-disk layout version.
pub const LAYOUT_VERSION: i64 = 1;

const META_CURRENT_REVISION: &str = "current_revision";
const META_CURRENT_SEQUENCE: &str = "current_sequence";
const META_GENERATION: &str = "eligibility_generation";
const META_LAYOUT: &str = "layout_version";

type BlobRecord = (ContentDigest, u64, EncodingProfile, ValueBoundary);
type BlobIndex = BTreeMap<[u8; 32], BlobRecord>;

const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS revisions (
    sequence INTEGER PRIMARY KEY,
    revision_id BLOB NOT NULL UNIQUE,
    parent_revision_id BLOB,
    committed_at_ns INTEGER NOT NULL,
    actor TEXT NOT NULL,
    scope TEXT NOT NULL,
    command_id TEXT NOT NULL,
    request_digest BLOB NOT NULL,
    eligibility_generation INTEGER NOT NULL,
    manifest BLOB NOT NULL,
    manifest_digest BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
    record_id BLOB NOT NULL,
    revision_id BLOB NOT NULL,
    kind TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    scope TEXT NOT NULL,
    recorded_at_ns INTEGER NOT NULL,
    recorded_order INTEGER NOT NULL,
    envelope_digest BLOB NOT NULL,
    payload_digest BLOB NOT NULL,
    full_digest BLOB NOT NULL,
    PRIMARY KEY (record_id, revision_id)
);
CREATE TABLE IF NOT EXISTS revision_records (
    revision_sequence INTEGER NOT NULL,
    record_id BLOB NOT NULL,
    revision_id BLOB NOT NULL,
    PRIMARY KEY (revision_sequence, record_id)
);
CREATE TABLE IF NOT EXISTS blobs (
    digest BLOB PRIMARY KEY,
    algorithm TEXT NOT NULL,
    profile TEXT NOT NULL,
    boundary TEXT NOT NULL,
    byte_length INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS revision_blobs (
    revision_sequence INTEGER NOT NULL,
    digest BLOB NOT NULL,
    PRIMARY KEY (revision_sequence, digest)
);
CREATE TABLE IF NOT EXISTS commands (
    actor TEXT NOT NULL,
    scope TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_digest BLOB NOT NULL,
    base_revision BLOB NOT NULL,
    outcome_revision BLOB NOT NULL,
    outcome_sequence INTEGER NOT NULL,
    committed_at_ns INTEGER NOT NULL,
    PRIMARY KEY (actor, scope, idempotency_key)
);
CREATE TABLE IF NOT EXISTS publication_intents (
    intent_id TEXT PRIMARY KEY,
    revision_sequence INTEGER NOT NULL,
    target_path TEXT NOT NULL,
    expected_digest BLOB,
    desired_digest BLOB NOT NULL,
    eligibility_generation INTEGER NOT NULL,
    state TEXT NOT NULL,
    observed_digest BLOB,
    detail TEXT,
    updated_at_ns INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS projections (
    name TEXT PRIMARY KEY,
    revision_id BLOB NOT NULL,
    revision_sequence INTEGER NOT NULL,
    schema_version INTEGER NOT NULL,
    rule_version TEXT NOT NULL,
    index_version TEXT NOT NULL,
    scope TEXT NOT NULL,
    eligibility_generation INTEGER NOT NULL,
    built_at_ns INTEGER NOT NULL
);
"#;

/// Configuration for a workspace handle.
pub struct WorkspaceConfig {
    pub clock: Box<dyn Clock>,
    pub faults: Box<dyn FaultInjector>,
}

impl Default for WorkspaceConfig {
    fn default() -> Self {
        WorkspaceConfig {
            clock: Box::new(SystemClock),
            faults: Box::new(NoFaults),
        }
    }
}

impl std::fmt::Debug for WorkspaceConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkspaceConfig")
            .finish_non_exhaustive()
    }
}

/// Current workspace status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceStatus {
    pub revision: WorkspaceRevisionId,
    pub sequence: u64,
    pub eligibility_generation: u64,
    pub record_count: usize,
    pub blob_count: usize,
    pub pending_publications: usize,
}

/// A pinned, integrity-checked workspace snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub revision: WorkspaceRevisionId,
    pub sequence: u64,
    pub parent: Option<WorkspaceRevisionId>,
    pub manifest_digest: ContentDigest,
    pub eligibility_generation: u64,
    pub records: Vec<RecordEnvelope>,
    pub index: SnapshotIndex,
}

/// The state of one working-file publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationState {
    Pending,
    Published,
    Diverged,
    Suppressed,
    Failed,
}

impl PublicationState {
    /// Stable lower-case name for interfaces and reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            PublicationState::Pending => "pending",
            PublicationState::Published => "published",
            PublicationState::Diverged => "diverged",
            PublicationState::Suppressed => "suppressed",
            PublicationState::Failed => "failed",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "pending" => Some(PublicationState::Pending),
            "published" => Some(PublicationState::Published),
            "diverged" => Some(PublicationState::Diverged),
            "suppressed" => Some(PublicationState::Suppressed),
            "failed" => Some(PublicationState::Failed),
            _ => None,
        }
    }
}

/// The outcome of one publication intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationOutcome {
    pub intent_id: String,
    pub path: String,
    pub state: PublicationState,
    pub observed: Option<ContentDigest>,
    pub detail: Option<String>,
}

/// A committed revision plus separately observed publication results.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitOutcome {
    pub revision: WorkspaceRevisionId,
    pub sequence: u64,
    pub manifest_digest: ContentDigest,
    pub eligibility_generation: u64,
    pub publications: Vec<PublicationOutcome>,
}

/// Results of startup recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryReport {
    pub staged_files_removed: usize,
    pub orphan_blobs_removed: usize,
    pub working_temporaries_removed: usize,
    pub revision: WorkspaceRevisionId,
    pub publications: Vec<PublicationOutcome>,
}

/// A derived projection's declared envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionRegistration {
    pub name: String,
    pub revision: WorkspaceRevisionId,
    pub schema_version: u32,
    pub rule_version: String,
    pub index_version: String,
    pub scope: String,
}

/// A registered projection as stored in the ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionState {
    pub name: String,
    pub revision: WorkspaceRevisionId,
    pub sequence: u64,
    pub schema_version: u32,
    pub rule_version: String,
    pub index_version: String,
    pub scope: String,
    pub eligibility_generation: u64,
    pub built_at_ns: i64,
}

/// Whether a projection may serve a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProjectionResolution {
    Compatible(ProjectionState),
    Behind {
        projection: ProjectionState,
        requested: WorkspaceRevisionId,
    },
    ScopeMismatch {
        projection: ProjectionState,
        requested_scope: String,
    },
    BarrierAdvanced {
        projection: ProjectionState,
        current: u64,
    },
    Missing,
}

/// An open workspace coordinator.
pub struct Workspace {
    root: PathBuf,
    connection: Connection,
    clock: Box<dyn Clock>,
    faults: Box<dyn FaultInjector>,
}

impl std::fmt::Debug for Workspace {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Workspace")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl Workspace {
    /// Create a fresh workspace directory with a genesis revision.
    pub fn create(root: impl AsRef<Path>, config: WorkspaceConfig) -> Result<Self> {
        let root = root.as_ref();
        if root.exists() {
            let mut entries = fs::read_dir(root).map_err(|error| StoreError::io(root, error))?;
            if entries.next().is_some() {
                return Err(StoreError::UnsupportedLayout(format!(
                    "{} is not empty",
                    root.display()
                )));
            }
        } else {
            fs::create_dir_all(root).map_err(|error| StoreError::io(root, error))?;
        }
        let root = fs::canonicalize(root).map_err(|error| StoreError::io(root, error))?;
        for directory in [
            blob::BLOB_DIRECTORY,
            blob::STAGING_DIRECTORY,
            blob::WORKING_DIRECTORY,
        ] {
            let path = root.join(directory);
            fs::create_dir_all(&path).map_err(|error| StoreError::io(&path, error))?;
        }
        let connection = open_connection(&root)?;
        connection.execute_batch(DDL)?;
        connection.pragma_update(None, "user_version", LAYOUT_VERSION)?;

        let revision = WorkspaceRevisionId::from_bytes(blob::random_bytes()?);
        let manifest = Manifest::genesis(revision);
        let manifest_bytes = manifest.encode();
        let manifest_digest = manifest.digest();
        let committed_at = config.clock.now().nanos();
        let genesis_scope = ScopeId::new(mneme_core::ScopeClass::Workspace, "genesis")
            .map_err(|message| StoreError::InvalidCommand(message.to_owned()))?;
        connection.execute(
            "INSERT INTO revisions (sequence, revision_id, parent_revision_id, committed_at_ns,
                 actor, scope, command_id, request_digest, eligibility_generation, manifest,
                 manifest_digest)
             VALUES (0, ?1, NULL, ?2, 'system', ?3, 'genesis', ?4, 1, ?5, ?6)",
            params![
                revision.as_bytes().as_slice(),
                committed_at,
                genesis_scope.to_string(),
                [0_u8; 32].as_slice(),
                manifest_bytes,
                manifest_digest.as_bytes().as_slice(),
            ],
        )?;
        set_meta(&connection, META_LAYOUT, b"1")?;
        set_meta(&connection, META_CURRENT_REVISION, revision.as_bytes())?;
        set_meta_u64(&connection, META_CURRENT_SEQUENCE, 0)?;
        set_meta_u64(&connection, META_GENERATION, 1)?;
        Ok(Workspace {
            root,
            connection,
            clock: config.clock,
            faults: config.faults,
        })
    }

    /// Open an existing workspace without running recovery.
    pub fn open(root: impl AsRef<Path>, config: WorkspaceConfig) -> Result<Self> {
        let root = fs::canonicalize(root.as_ref())
            .map_err(|error| StoreError::io(root.as_ref(), error))?;
        let ledger = root.join(LEDGER_FILE);
        if !ledger.is_file() {
            return Err(StoreError::UnsupportedLayout(format!(
                "{} has no {LEDGER_FILE}",
                root.display()
            )));
        }
        let connection = open_connection(&root)?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version != LAYOUT_VERSION {
            return Err(StoreError::UnsupportedLayout(format!(
                "ledger layout version {version} is not supported"
            )));
        }
        if meta_blob(&connection, META_CURRENT_REVISION)?.len() != 16 {
            return Err(StoreError::UnsupportedLayout(
                "ledger has no readable current revision".to_owned(),
            ));
        }
        Ok(Workspace {
            root,
            connection,
            clock: config.clock,
            faults: config.faults,
        })
    }

    /// The canonical workspace root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The current committed revision identity.
    pub fn current_revision(&self) -> Result<WorkspaceRevisionId> {
        revision_from_blob(&meta_blob(&self.connection, META_CURRENT_REVISION)?)
    }

    /// The current committed revision sequence.
    pub fn current_sequence(&self) -> Result<u64> {
        meta_u64(&self.connection, META_CURRENT_SEQUENCE)
    }

    /// The current eligibility generation.
    pub fn eligibility_generation(&self) -> Result<u64> {
        meta_u64(&self.connection, META_GENERATION)
    }

    /// Current status for interfaces and tests.
    pub fn status(&self) -> Result<WorkspaceStatus> {
        let revision = self.current_revision()?;
        let sequence = self.current_sequence()?;
        let record_count: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM revision_records WHERE revision_sequence = ?1",
            params![i64::try_from(sequence).unwrap_or(i64::MAX)],
            |row| row.get(0),
        )?;
        let blob_count: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get(0))?;
        let pending: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM publication_intents WHERE state = 'pending'",
            [],
            |row| row.get(0),
        )?;
        Ok(WorkspaceStatus {
            revision,
            sequence,
            eligibility_generation: self.eligibility_generation()?,
            record_count: usize::try_from(record_count).unwrap_or(0),
            blob_count: usize::try_from(blob_count).unwrap_or(0),
            pending_publications: usize::try_from(pending).unwrap_or(0),
        })
    }

    /// Advance the current eligibility/erasure generation.
    pub fn advance_eligibility_barrier(&mut self) -> Result<u64> {
        let next = self.eligibility_generation()?.saturating_add(1);
        set_meta_u64(&self.connection, META_GENERATION, next)?;
        Ok(next)
    }

    /// Recheck a pinned snapshot against the current generation.
    pub fn recheck(&self, snapshot: &Snapshot) -> Result<()> {
        let current = self.eligibility_generation()?;
        if current != snapshot.eligibility_generation {
            return Err(StoreError::BarrierAdvanced {
                pinned: snapshot.eligibility_generation,
                current,
            });
        }
        Ok(())
    }

    /// Register or replace a derived projection declared against a committed
    /// revision. The current eligibility generation is recorded.
    pub fn register_projection(
        &mut self,
        registration: ProjectionRegistration,
    ) -> Result<ProjectionState> {
        if registration.name.trim().is_empty() {
            return Err(StoreError::InvalidCommand(
                "projection name must not be empty".to_owned(),
            ));
        }
        let row =
            revision_row_by_id(&self.connection, registration.revision)?.ok_or_else(|| {
                StoreError::Integrity {
                    revision: registration.revision,
                    reason: "projection names an unknown revision".to_owned(),
                }
            })?;
        let generation = self.eligibility_generation()?;
        let built_at = self.clock.now().nanos();
        let name = registration.name;
        self.connection.execute(
            "INSERT INTO projections (name, revision_id, revision_sequence, schema_version,
                 rule_version, index_version, scope, eligibility_generation, built_at_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(name) DO UPDATE SET revision_id = excluded.revision_id,
                 revision_sequence = excluded.revision_sequence,
                 schema_version = excluded.schema_version,
                 rule_version = excluded.rule_version,
                 index_version = excluded.index_version,
                 scope = excluded.scope,
                 eligibility_generation = excluded.eligibility_generation,
                 built_at_ns = excluded.built_at_ns",
            params![
                name.clone(),
                registration.revision.as_bytes().as_slice(),
                i64::try_from(row.sequence).unwrap_or(i64::MAX),
                i64::from(registration.schema_version),
                registration.rule_version,
                registration.index_version,
                registration.scope,
                i64::try_from(generation).unwrap_or(i64::MAX),
                built_at,
            ],
        )?;
        self.projection(&name)?
            .ok_or_else(|| StoreError::Integrity {
                revision: registration.revision,
                reason: "projection registration disappeared".to_owned(),
            })
    }

    /// Read a projection registration.
    pub fn projection(&self, name: &str) -> Result<Option<ProjectionState>> {
        let row = self
            .connection
            .query_row(
                "SELECT revision_id, revision_sequence, schema_version, rule_version,
                        index_version, scope, eligibility_generation, built_at_ns
                 FROM projections WHERE name = ?1",
                params![name],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            revision,
            sequence,
            schema_version,
            rule_version,
            index_version,
            scope,
            generation,
            built_at,
        )) = row
        else {
            return Ok(None);
        };
        Ok(Some(ProjectionState {
            name: name.to_owned(),
            revision: revision_from_blob(&revision)?,
            sequence: u64::try_from(sequence).unwrap_or(0),
            schema_version: u32::try_from(schema_version).unwrap_or(0),
            rule_version,
            index_version,
            scope,
            eligibility_generation: u64::try_from(generation).unwrap_or(0),
            built_at_ns: built_at,
        }))
    }

    /// Resolve a projection for a requested revision and scope.
    pub fn resolve_projection(
        &self,
        name: &str,
        requested: WorkspaceRevisionId,
        scope: &ScopeId,
    ) -> Result<ProjectionResolution> {
        let Some(projection) = self.projection(name)? else {
            return Ok(ProjectionResolution::Missing);
        };
        let current = self.eligibility_generation()?;
        if projection.eligibility_generation != current {
            return Ok(ProjectionResolution::BarrierAdvanced {
                projection,
                current,
            });
        }
        if projection.scope != scope.to_string() {
            return Ok(ProjectionResolution::ScopeMismatch {
                projection,
                requested_scope: scope.to_string(),
            });
        }
        if projection.revision != requested {
            return Ok(ProjectionResolution::Behind {
                projection,
                requested,
            });
        }
        Ok(ProjectionResolution::Compatible(projection))
    }

    /// Read the current committed snapshot.
    pub fn snapshot(&self) -> Result<Snapshot> {
        let revision = self.current_revision()?;
        self.snapshot_at(revision, None)
    }

    /// Read a pinned snapshot, requiring a matching eligibility generation.
    pub fn snapshot_at(
        &self,
        revision: WorkspaceRevisionId,
        pinned_generation: Option<u64>,
    ) -> Result<Snapshot> {
        let row = revision_row_by_id(&self.connection, revision)?.ok_or_else(|| {
            StoreError::Integrity {
                revision,
                reason: "revision is not present in the ledger".to_owned(),
            }
        })?;
        let generation = self.eligibility_generation()?;
        if let Some(pinned) = pinned_generation
            && pinned != generation
        {
            return Err(StoreError::BarrierAdvanced {
                pinned,
                current: generation,
            });
        }
        let snapshot = self.load_snapshot(row, generation)?;
        let after = self.eligibility_generation()?;
        if after != generation {
            return Err(StoreError::BarrierAdvanced {
                pinned: generation,
                current: after,
            });
        }
        Ok(snapshot)
    }

    fn load_snapshot(&self, row: RevisionRow, generation: u64) -> Result<Snapshot> {
        let revision = row.revision;
        let manifest_value =
            binary::decode(&row.manifest_bytes).map_err(|diagnostic| StoreError::Integrity {
                revision,
                reason: format!("manifest is not valid Preserves: {diagnostic}"),
            })?;
        let manifest =
            Manifest::from_value(&manifest_value).map_err(|reason| StoreError::Integrity {
                revision,
                reason: format!("manifest is invalid: {reason}"),
            })?;
        if manifest.revision != revision
            || manifest.parent != row.parent
            || ContentDigest::of_payload(&manifest_value) != row.manifest_digest
            || manifest.encode() != row.manifest_bytes
        {
            return Err(StoreError::Integrity {
                revision,
                reason: "manifest identity or digest does not match the ledger row".to_owned(),
            });
        }

        let records = self.load_records(row.sequence, revision)?;
        let mut expected_records = BTreeSet::new();
        let mut index = SnapshotIndex::new();
        for record in &records {
            expected_records.insert(ManifestRecord {
                record_id: record.record_id,
                revision_id: record.revision_id,
                kind: record.kind,
            });
            index.insert(record.record_id, record.kind, record.revision_id);
        }
        if expected_records != manifest.records {
            return Err(StoreError::Integrity {
                revision,
                reason: "manifest record set does not match the committed revision".to_owned(),
            });
        }

        let blob_rows = revision_blob_rows(&self.connection, row.sequence)?;
        let mut expected_blobs = BTreeSet::new();
        for (digest, length) in &blob_rows {
            expected_blobs.insert(*digest);
            blob::verify(&self.root, *digest, *length).map_err(|error| StoreError::Integrity {
                revision,
                reason: format!("required blob {digest} failed verification: {error}"),
            })?;
        }
        if expected_blobs != manifest.blobs {
            return Err(StoreError::Integrity {
                revision,
                reason: "manifest blob set does not match the committed revision".to_owned(),
            });
        }

        Ok(Snapshot {
            revision,
            sequence: row.sequence,
            parent: row.parent,
            manifest_digest: row.manifest_digest,
            eligibility_generation: generation,
            records,
            index,
        })
    }

    fn load_records(
        &self,
        sequence: u64,
        revision: WorkspaceRevisionId,
    ) -> Result<Vec<RecordEnvelope>> {
        let sequence = i64::try_from(sequence).map_err(|_| StoreError::Integrity {
            revision,
            reason: "revision sequence exceeds the supported range".to_owned(),
        })?;
        let mut statement = self.connection.prepare(
            "SELECT r.record_id, r.revision_id, r.kind, r.envelope_digest, r.payload_digest,
                    r.full_digest
             FROM revision_records rr
             JOIN records r ON r.record_id = rr.record_id AND r.revision_id = rr.revision_id
             WHERE rr.revision_sequence = ?1
             ORDER BY r.record_id",
        )?;
        let rows = statement
            .query_map(params![sequence], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut records = Vec::with_capacity(rows.len());
        for (record_id, revision_id, kind, envelope_digest, payload_digest, full_digest) in rows {
            let record_id = record_id_from_blob(&record_id, revision)?;
            let revision_id = revision_id_from_blob(&revision_id, revision)?;
            let kind = RecordKind::parse(&kind).ok_or_else(|| StoreError::Integrity {
                revision,
                reason: format!("unknown record kind {kind}"),
            })?;
            let digest = digest_with(
                &envelope_digest,
                "preserves-canonical-binary-v1",
                "full-record",
                revision,
            )?;
            let bytes = blob::read(&self.root, digest).map_err(|error| StoreError::Integrity {
                revision,
                reason: format!("record blob {digest} is unavailable: {error}"),
            })?;
            let value = binary::decode(&bytes).map_err(|diagnostic| StoreError::Integrity {
                revision,
                reason: format!("record blob {digest} is not valid Preserves: {diagnostic}"),
            })?;
            let record = RecordEnvelope::from_value(&value).map_err(|diagnostics| {
                StoreError::Integrity {
                    revision,
                    reason: format!(
                        "record blob {digest} is not a valid envelope: {}",
                        join(&diagnostics)
                    ),
                }
            })?;
            let payload_digest = digest_with(
                &payload_digest,
                "preserves-canonical-binary-v1",
                "payload",
                revision,
            )?;
            if record.record_id != record_id
                || record.revision_id != revision_id
                || record.kind != kind
                || record.full_digest() != digest
                || record.full_digest().as_bytes() != full_digest.as_slice()
                || record.payload_digest() != payload_digest
            {
                return Err(StoreError::Integrity {
                    revision,
                    reason: format!("record blob {digest} does not match its ledger identity"),
                });
            }
            records.push(record);
        }
        Ok(records)
    }

    /// Commit one command through the serialized coordinator.
    pub fn commit(&mut self, command: CommitCommand) -> Result<CommitOutcome> {
        validate_command(&command)?;
        let request_digest = command.request_digest();
        if let Some(stored) = self.lookup_command(&command)? {
            if stored.request_digest.as_slice() != request_digest.as_bytes() {
                return Err(StoreError::IdempotencyConflict {
                    key: command.idempotency_key,
                });
            }
            return self.outcome_for_stored(&stored);
        }

        let base = self.current_revision()?;
        if command.base != base {
            return Err(StoreError::StaleBase {
                base: command.base,
                current: base,
            });
        }
        let current_sequence = self.current_sequence()?;
        let next_sequence = current_sequence.saturating_add(1);
        let generation = self.eligibility_generation()?;
        let recorded = RecordedTime::new(self.clock.now(), next_sequence);

        let prior = self.snapshot()?;
        let envelopes: Vec<RecordEnvelope> = command
            .records
            .clone()
            .into_iter()
            .map(|draft| draft.into_envelope(recorded))
            .collect();
        let values: Vec<Value> = envelopes.iter().map(RecordEnvelope::to_value).collect();
        let validated = validate_batch(&values, &SchemaRegistry::v1(), Some(&prior.index))
            .map_err(StoreError::Validation)?;
        let new_records = validated.records;
        self.ensure_revisions_unused(&new_records)?;
        validate_bindings(&prior.records, &new_records)?;
        validate_sources(&command.source_blobs, &new_records)?;
        validate_publication_paths(&command.publications, &command.import_candidates)?;

        let mut staged: BlobIndex = BTreeMap::new();
        for record in &new_records {
            let value = record.to_value();
            let bytes = binary::encode(&value);
            let digest = ContentDigest::of_full_record(&value);
            let staged_blob = blob::stage(&self.root, digest, &bytes)?;
            staged.insert(
                *digest.as_bytes(),
                (
                    digest,
                    staged_blob.byte_length,
                    EncodingProfile::CanonicalBinaryV1,
                    ValueBoundary::FullRecord,
                ),
            );
        }
        for source in &command.source_blobs {
            let digest = source.digest();
            let staged_blob = blob::stage(&self.root, digest, &source.bytes)?;
            staged.insert(
                *digest.as_bytes(),
                (
                    digest,
                    staged_blob.byte_length,
                    EncodingProfile::RawBytesV1,
                    ValueBoundary::SourceBytes,
                ),
            );
        }
        for candidate in &command.import_candidates {
            blob::validate_relative_path(&candidate.path)?;
            let current = blob::read_working_file(&self.root, &candidate.path)?;
            if current.as_deref() != Some(candidate.bytes.as_slice()) {
                return Err(StoreError::InvalidCandidate {
                    path: candidate.path.clone(),
                });
            }
            let matching = new_records
                .iter()
                .any(|record| candidate_matches(candidate, record));
            if !matching {
                return Err(StoreError::InvalidCandidate {
                    path: candidate.path.clone(),
                });
            }
            let digest = candidate.digest();
            let staged_blob = blob::stage(&self.root, digest, &candidate.bytes)?;
            staged.insert(
                *digest.as_bytes(),
                (
                    digest,
                    staged_blob.byte_length,
                    EncodingProfile::RawBytesV1,
                    ValueBoundary::SourceBytes,
                ),
            );
        }
        for publication in &command.publications {
            blob::validate_relative_path(&publication.path)?;
            let digest = publication.desired_digest();
            let staged_blob = blob::stage(&self.root, digest, &publication.bytes)?;
            staged.insert(
                *digest.as_bytes(),
                (
                    digest,
                    staged_blob.byte_length,
                    EncodingProfile::RawBytesV1,
                    ValueBoundary::SourceBytes,
                ),
            );
        }

        check(self.faults.as_ref(), FaultPoint::AfterBlobStaging)?;

        let mut snapshot_records: BTreeMap<RecordId, RecordEnvelope> = prior
            .records
            .iter()
            .map(|record| (record.record_id, record.clone()))
            .collect();
        for record in &new_records {
            snapshot_records.insert(record.record_id, record.clone());
        }
        validate_snapshot_bindings(&snapshot_records)?;

        let manifest_records: BTreeSet<ManifestRecord> = snapshot_records
            .values()
            .map(|record| ManifestRecord {
                record_id: record.record_id,
                revision_id: record.revision_id,
                kind: record.kind,
            })
            .collect();
        let mut required_blobs = BTreeSet::new();
        for record in snapshot_records.values() {
            required_blobs.insert(ContentDigest::of_full_record(&record.to_value()));
            if let Some(digest) = retained_source_digest(record) {
                required_blobs.insert(digest);
            }
        }
        for publication in &command.publications {
            required_blobs.insert(publication.desired_digest());
        }
        let revision_id = WorkspaceRevisionId::from_bytes(blob::random_bytes()?);
        let manifest = Manifest {
            revision: revision_id,
            parent: Some(base),
            records: manifest_records,
            blobs: required_blobs,
        };
        let manifest_digest = manifest.digest();
        let manifest_bytes = manifest.encode();

        let mut blob_lengths = self.blob_lengths()?;
        for (key, (digest, length, profile, boundary)) in &staged {
            if let Some(existing) = blob_lengths.get(key) {
                if existing.1 != *length || existing.2 != *profile || existing.3 != *boundary {
                    return Err(StoreError::CorruptBlob {
                        digest: digest.to_hex(),
                        reason: "blob metadata differs from an existing digest".to_owned(),
                    });
                }
            } else {
                blob_lengths.insert(*key, (*digest, *length, *profile, *boundary));
            }
        }
        validate_snapshot_sources(&snapshot_records, &blob_lengths)?;
        for digest in &manifest.blobs {
            let Some((_, length, _, _)) = blob_lengths.get(digest.as_bytes()) else {
                return Err(StoreError::MissingBlob {
                    digest: digest.to_hex(),
                });
            };
            blob::verify(&self.root, *digest, *length)?;
        }

        check(self.faults.as_ref(), FaultPoint::BeforeCommitTransaction)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current_now = meta_blob(&transaction, META_CURRENT_REVISION)?;
        if current_now.as_slice() != base.as_bytes() {
            return Err(StoreError::StaleBase {
                base,
                current: revision_from_blob(&current_now)?,
            });
        }
        let generation_now = meta_u64(&transaction, META_GENERATION)?;
        if generation_now != generation {
            return Err(StoreError::BarrierAdvanced {
                pinned: generation,
                current: generation_now,
            });
        }
        if let Some(stored) = lookup_command_in(&transaction, &command)? {
            if stored.request_digest.as_slice() != request_digest.as_bytes() {
                return Err(StoreError::IdempotencyConflict {
                    key: command.idempotency_key,
                });
            }
            drop(transaction);
            return self.outcome_for_stored(&stored);
        }

        transaction.execute(
            "INSERT INTO revisions (sequence, revision_id, parent_revision_id, committed_at_ns,
                 actor, scope, command_id, request_digest, eligibility_generation, manifest,
                 manifest_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                i64::try_from(next_sequence).unwrap_or(i64::MAX),
                revision_id.as_bytes().as_slice(),
                base.as_bytes().as_slice(),
                recorded.at().nanos(),
                command.actor,
                command.scope.to_string(),
                command.idempotency_key,
                request_digest.as_bytes().as_slice(),
                i64::try_from(generation).unwrap_or(i64::MAX),
                manifest_bytes,
                manifest_digest.as_bytes().as_slice(),
            ],
        )?;
        for (key, (digest, length, profile, boundary)) in &staged {
            let existing = transaction
                .query_row(
                    "SELECT profile, boundary, byte_length FROM blobs WHERE digest = ?1",
                    params![key.as_slice()],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .optional()?;
            if let Some((existing_profile, existing_boundary, existing_length)) = existing {
                if existing_profile != profile.symbol()
                    || existing_boundary != boundary.symbol()
                    || existing_length != i64::try_from(*length).unwrap_or(i64::MAX)
                {
                    return Err(StoreError::CorruptBlob {
                        digest: digest.to_hex(),
                        reason: "stored blob metadata differs from this command".to_owned(),
                    });
                }
            } else {
                transaction.execute(
                    "INSERT INTO blobs (digest, algorithm, profile, boundary, byte_length)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        key.as_slice(),
                        digest.algorithm().symbol(),
                        profile.symbol(),
                        boundary.symbol(),
                        i64::try_from(*length).unwrap_or(i64::MAX),
                    ],
                )?;
            }
        }
        for record in &new_records {
            let full = record.full_digest();
            transaction.execute(
                "INSERT INTO records (record_id, revision_id, kind, schema_version, scope,
                     recorded_at_ns, recorded_order, envelope_digest, payload_digest, full_digest)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    record.record_id.as_bytes().as_slice(),
                    record.revision_id.as_bytes().as_slice(),
                    record.kind.symbol(),
                    i64::from(record.schema_version),
                    record.scope.to_string(),
                    record.recorded.at().nanos(),
                    i64::try_from(record.recorded.revision_order()).unwrap_or(i64::MAX),
                    full.as_bytes().as_slice(),
                    record.payload_digest().as_bytes().as_slice(),
                    full.as_bytes().as_slice(),
                ],
            )?;
        }
        for record in snapshot_records.values() {
            transaction.execute(
                "INSERT INTO revision_records (revision_sequence, record_id, revision_id)
                 VALUES (?1, ?2, ?3)",
                params![
                    i64::try_from(next_sequence).unwrap_or(i64::MAX),
                    record.record_id.as_bytes().as_slice(),
                    record.revision_id.as_bytes().as_slice(),
                ],
            )?;
        }
        for digest in &manifest.blobs {
            transaction.execute(
                "INSERT INTO revision_blobs (revision_sequence, digest) VALUES (?1, ?2)",
                params![
                    i64::try_from(next_sequence).unwrap_or(i64::MAX),
                    digest.as_bytes().as_slice()
                ],
            )?;
        }
        let mut intent_ids = Vec::new();
        for publication in &command.publications {
            let intent_id = blob::random_hex(16)?;
            transaction.execute(
                "INSERT INTO publication_intents (intent_id, revision_sequence, target_path,
                     expected_digest, desired_digest, eligibility_generation, state, observed_digest,
                     detail, updated_at_ns)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', NULL, NULL, ?7)",
                params![
                    intent_id,
                    i64::try_from(next_sequence).unwrap_or(i64::MAX),
                    publication.path,
                    publication
                        .expected_previous
                        .map(|digest| digest.as_bytes().to_vec()),
                    publication.desired_digest().as_bytes().as_slice(),
                    i64::try_from(generation).unwrap_or(i64::MAX),
                    recorded.at().nanos(),
                ],
            )?;
            intent_ids.push(intent_id);
        }
        transaction.execute(
            "INSERT INTO commands (actor, scope, idempotency_key, request_digest, base_revision,
                 outcome_revision, outcome_sequence, committed_at_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                command.actor,
                command.scope.to_string(),
                command.idempotency_key,
                request_digest.as_bytes().as_slice(),
                base.as_bytes().as_slice(),
                revision_id.as_bytes().as_slice(),
                i64::try_from(next_sequence).unwrap_or(i64::MAX),
                recorded.at().nanos(),
            ],
        )?;
        set_meta(&transaction, META_CURRENT_REVISION, revision_id.as_bytes())?;
        set_meta_u64(&transaction, META_CURRENT_SEQUENCE, next_sequence)?;
        transaction.commit()?;

        check(self.faults.as_ref(), FaultPoint::AfterCommit)?;

        let mut publications = Vec::new();
        for intent_id in intent_ids {
            match self.publish_intent(&intent_id) {
                Ok(outcome) => publications.push(outcome),
                Err(StoreError::InjectedFault(point)) => {
                    return Err(StoreError::InjectedFault(point));
                }
                Err(error) => {
                    self.mark_intent_failed(&intent_id, &error)?;
                    publications.push(self.publication_outcome(&intent_id)?.ok_or_else(|| {
                        StoreError::Integrity {
                            revision: revision_id,
                            reason: "publication intent disappeared".to_owned(),
                        }
                    })?);
                }
            }
        }
        Ok(CommitOutcome {
            revision: revision_id,
            sequence: next_sequence,
            manifest_digest,
            eligibility_generation: generation,
            publications,
        })
    }

    fn ensure_revisions_unused(&self, records: &[RecordEnvelope]) -> Result<()> {
        for record in records {
            let exists: Option<i64> = self
                .connection
                .query_row(
                    "SELECT 1 FROM records WHERE revision_id = ?1",
                    params![record.revision_id.as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .optional()?;
            if exists.is_some() {
                return Err(StoreError::InvalidCommand(format!(
                    "revision {} is already committed",
                    record.revision_id
                )));
            }
        }
        Ok(())
    }

    fn lookup_command(&self, command: &CommitCommand) -> Result<Option<StoredCommand>> {
        lookup_command_in(&self.connection, command)
    }

    fn outcome_for_stored(&self, stored: &StoredCommand) -> Result<CommitOutcome> {
        let row =
            revision_row_by_id(&self.connection, stored.outcome_revision)?.ok_or_else(|| {
                StoreError::Integrity {
                    revision: stored.outcome_revision,
                    reason: "idempotent outcome revision is missing".to_owned(),
                }
            })?;
        if row.sequence != stored.outcome_sequence {
            return Err(StoreError::Integrity {
                revision: stored.outcome_revision,
                reason: "idempotent outcome sequence does not match the revision row".to_owned(),
            });
        }
        let publications = publication_outcomes(&self.connection, row.sequence)?;
        Ok(CommitOutcome {
            revision: row.revision,
            sequence: row.sequence,
            manifest_digest: row.manifest_digest,
            eligibility_generation: row.eligibility_generation,
            publications,
        })
    }

    /// Publish every pending working-file intent.
    pub fn publish_pending(&mut self) -> Result<Vec<PublicationOutcome>> {
        let mut statement = self.connection.prepare(
            "SELECT intent_id FROM publication_intents WHERE state = 'pending' ORDER BY rowid",
        )?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        let mut outcomes = Vec::new();
        for intent_id in ids {
            match self.publish_intent(&intent_id) {
                Ok(outcome) => outcomes.push(outcome),
                Err(StoreError::InjectedFault(point)) => {
                    return Err(StoreError::InjectedFault(point));
                }
                Err(error) => {
                    self.mark_intent_failed(&intent_id, &error)?;
                    outcomes.push(self.publication_outcome(&intent_id)?.ok_or_else(|| {
                        StoreError::InvalidCommand("publication intent disappeared".to_owned())
                    })?);
                }
            }
        }
        Ok(outcomes)
    }

    /// Startup recovery: remove orphans, verify the current manifest, and
    /// resume pending publication intents.
    pub fn recover(&mut self) -> Result<RecoveryReport> {
        let known: BTreeSet<[u8; 32]> = {
            let mut statement = self.connection.prepare("SELECT digest FROM blobs")?;
            let digests = statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let mut set = BTreeSet::new();
            for digest in digests {
                let mut bytes = [0_u8; 32];
                if digest.len() != 32 {
                    return Err(StoreError::UnsupportedLayout(
                        "ledger blob digest is not 32 bytes".to_owned(),
                    ));
                }
                bytes.copy_from_slice(&digest);
                set.insert(bytes);
            }
            set
        };
        let (staged, orphan_blobs) = blob::cleanup_orphans(&self.root, &known)?;
        let temporaries = blob::cleanup_working_temporaries(&self.root)?;
        let snapshot = self.snapshot()?;
        let publications = self.publish_pending()?;
        Ok(RecoveryReport {
            staged_files_removed: staged,
            orphan_blobs_removed: orphan_blobs,
            working_temporaries_removed: temporaries,
            revision: snapshot.revision,
            publications,
        })
    }

    fn publish_intent(&self, intent_id: &str) -> Result<PublicationOutcome> {
        let intent = self.publication_intent(intent_id)?.ok_or_else(|| {
            StoreError::InvalidCommand(format!("publication intent {intent_id} is missing"))
        })?;
        if intent.state != PublicationState::Pending {
            return self.require_outcome(intent_id);
        }
        let current_sequence = self.current_sequence()?;
        if intent.revision_sequence != current_sequence {
            self.set_intent_state(
                intent_id,
                PublicationState::Suppressed,
                None,
                Some("revision is not current".to_owned()),
            )?;
            return self.require_outcome(intent_id);
        }
        let generation = self.eligibility_generation()?;
        if intent.eligibility_generation != generation {
            self.set_intent_state(
                intent_id,
                PublicationState::Suppressed,
                None,
                Some("eligibility generation advanced".to_owned()),
            )?;
            return self.require_outcome(intent_id);
        }
        let desired = intent.desired_digest;
        let bytes = blob::read(&self.root, desired)?;
        let current = blob::read_working_file(&self.root, &intent.target_path)?;
        if let Some(current) = &current {
            let observed = ContentDigest::of_source_bytes(current);
            if observed == desired {
                self.set_intent_state(
                    intent_id,
                    PublicationState::Published,
                    Some(observed),
                    None,
                )?;
                return self.require_outcome(intent_id);
            }
            if intent.expected_digest != Some(observed) {
                self.set_intent_state(
                    intent_id,
                    PublicationState::Diverged,
                    Some(observed),
                    Some("working file changed since the expected previous content".to_owned()),
                )?;
                return self.require_outcome(intent_id);
            }
        } else if intent.expected_digest.is_some() {
            self.set_intent_state(
                intent_id,
                PublicationState::Diverged,
                None,
                Some("expected previous working file is missing".to_owned()),
            )?;
            return self.require_outcome(intent_id);
        }
        check(self.faults.as_ref(), FaultPoint::BeforeFileReplace)?;
        blob::publish_working_file(&self.root, &intent.target_path, &bytes)?;
        check(self.faults.as_ref(), FaultPoint::AfterFileReplace)?;
        self.set_intent_state(intent_id, PublicationState::Published, Some(desired), None)?;
        self.require_outcome(intent_id)
    }

    fn require_outcome(&self, intent_id: &str) -> Result<PublicationOutcome> {
        self.publication_outcome(intent_id)?
            .ok_or_else(|| StoreError::InvalidCommand("publication intent disappeared".to_owned()))
    }

    fn mark_intent_failed(&self, intent_id: &str, error: &StoreError) -> Result<()> {
        self.set_intent_state(
            intent_id,
            PublicationState::Failed,
            None,
            Some(error.to_string()),
        )
    }

    fn set_intent_state(
        &self,
        intent_id: &str,
        state: PublicationState,
        observed: Option<ContentDigest>,
        detail: Option<String>,
    ) -> Result<()> {
        self.connection.execute(
            "UPDATE publication_intents SET state = ?1, observed_digest = ?2, detail = ?3,
                 updated_at_ns = ?4 WHERE intent_id = ?5",
            params![
                state.as_str(),
                observed.map(|digest| digest.as_bytes().to_vec()),
                detail,
                self.clock.now().nanos(),
                intent_id,
            ],
        )?;
        Ok(())
    }

    fn publication_intent(&self, intent_id: &str) -> Result<Option<StoredIntent>> {
        let row = self
            .connection
            .query_row(
                "SELECT revision_sequence, target_path, expected_digest, desired_digest,
                        eligibility_generation, state
                 FROM publication_intents WHERE intent_id = ?1",
                params![intent_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            revision_sequence,
            target_path,
            expected_digest,
            desired_digest,
            eligibility_generation,
            state,
        )) = row
        else {
            return Ok(None);
        };
        let revision = WorkspaceRevisionId::from_bytes([0; 16]);
        Ok(Some(StoredIntent {
            revision_sequence: u64::try_from(revision_sequence).unwrap_or(0),
            target_path,
            expected_digest: expected_digest
                .map(|bytes| digest_with(&bytes, "raw-bytes-v1", "source-bytes", revision))
                .transpose()?,
            desired_digest: digest_with(&desired_digest, "raw-bytes-v1", "source-bytes", revision)?,
            eligibility_generation: u64::try_from(eligibility_generation).unwrap_or(0),
            state: PublicationState::parse(&state).unwrap_or(PublicationState::Failed),
        }))
    }

    fn publication_outcome(&self, intent_id: &str) -> Result<Option<PublicationOutcome>> {
        let row = self
            .connection
            .query_row(
                "SELECT target_path, state, observed_digest, detail FROM publication_intents
                 WHERE intent_id = ?1",
                params![intent_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((path, state, observed, detail)) = row else {
            return Ok(None);
        };
        Ok(Some(PublicationOutcome {
            intent_id: intent_id.to_owned(),
            path,
            state: PublicationState::parse(&state).unwrap_or(PublicationState::Failed),
            observed: observed
                .map(|bytes| {
                    digest_with(
                        &bytes,
                        "raw-bytes-v1",
                        "source-bytes",
                        WorkspaceRevisionId::from_bytes([0; 16]),
                    )
                })
                .transpose()?,
            detail,
        }))
    }

    fn blob_lengths(&self) -> Result<BlobIndex> {
        let mut statement = self
            .connection
            .prepare("SELECT digest, profile, boundary, byte_length FROM blobs")?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut output = BTreeMap::new();
        for (digest, profile, boundary, length) in rows {
            let Some(profile) = EncodingProfile::parse(&profile) else {
                return Err(StoreError::UnsupportedLayout(format!(
                    "unknown blob profile {profile}"
                )));
            };
            let Some(boundary) = ValueBoundary::parse(&boundary) else {
                return Err(StoreError::UnsupportedLayout(format!(
                    "unknown blob boundary {boundary}"
                )));
            };
            let digest = ContentDigest::from_parts(
                HashAlgorithm::Sha256,
                profile,
                boundary,
                digest.try_into().map_err(|_| {
                    StoreError::UnsupportedLayout("ledger blob digest is not 32 bytes".to_owned())
                })?,
            )
            .map_err(|message| {
                StoreError::UnsupportedLayout(format!("ledger blob metadata: {message}"))
            })?;
            let mut key = [0_u8; 32];
            key.copy_from_slice(digest.as_bytes());
            output.insert(
                key,
                (
                    digest,
                    u64::try_from(length).unwrap_or(0),
                    profile,
                    boundary,
                ),
            );
        }
        Ok(output)
    }
}

#[derive(Clone, Debug)]
struct RevisionRow {
    revision: WorkspaceRevisionId,
    sequence: u64,
    parent: Option<WorkspaceRevisionId>,
    manifest_bytes: Vec<u8>,
    manifest_digest: ContentDigest,
    eligibility_generation: u64,
}

#[derive(Clone, Debug)]
struct StoredCommand {
    request_digest: Vec<u8>,
    outcome_revision: WorkspaceRevisionId,
    outcome_sequence: u64,
}

#[derive(Clone, Debug)]
struct StoredIntent {
    revision_sequence: u64,
    target_path: String,
    expected_digest: Option<ContentDigest>,
    desired_digest: ContentDigest,
    eligibility_generation: u64,
    state: PublicationState,
}

fn open_connection(root: &Path) -> Result<Connection> {
    let ledger = root.join(LEDGER_FILE);
    let connection = Connection::open(&ledger)?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(connection)
}

fn meta_blob(connection: &Connection, key: &str) -> Result<Vec<u8>> {
    connection
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            params![key],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .ok_or_else(|| StoreError::UnsupportedLayout(format!("ledger meta lacks {key}")))
}

fn meta_u64(connection: &Connection, key: &str) -> Result<u64> {
    let text = meta_blob(connection, key)?;
    let text = String::from_utf8(text)
        .map_err(|_| StoreError::UnsupportedLayout(format!("ledger meta {key} is not text")))?;
    text.parse::<u64>()
        .map_err(|_| StoreError::UnsupportedLayout(format!("ledger meta {key} is not a u64")))
}

fn set_meta(connection: &Connection, key: &str, value: &[u8]) -> Result<()> {
    connection.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

fn set_meta_u64(connection: &Connection, key: &str, value: u64) -> Result<()> {
    set_meta(connection, key, value.to_string().as_bytes())
}

fn revision_from_blob(bytes: &[u8]) -> Result<WorkspaceRevisionId> {
    let bytes: [u8; 16] = bytes.try_into().map_err(|_| {
        StoreError::UnsupportedLayout("ledger revision id is not 16 bytes".to_owned())
    })?;
    Ok(WorkspaceRevisionId::from_bytes(bytes))
}

fn record_id_from_blob(bytes: &[u8], revision: WorkspaceRevisionId) -> Result<RecordId> {
    let bytes: [u8; 16] = bytes.try_into().map_err(|_| StoreError::Integrity {
        revision,
        reason: "record id is not 16 bytes".to_owned(),
    })?;
    Ok(RecordId::from_bytes(bytes))
}

fn revision_id_from_blob(bytes: &[u8], revision: WorkspaceRevisionId) -> Result<RevisionId> {
    let bytes: [u8; 16] = bytes.try_into().map_err(|_| StoreError::Integrity {
        revision,
        reason: "record revision id is not 16 bytes".to_owned(),
    })?;
    Ok(RevisionId::from_bytes(bytes))
}

fn digest_with(
    bytes: &[u8],
    profile: &str,
    boundary: &str,
    revision: WorkspaceRevisionId,
) -> Result<ContentDigest> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| StoreError::Integrity {
        revision,
        reason: "blob digest is not 32 bytes".to_owned(),
    })?;
    let profile = EncodingProfile::parse(profile).ok_or_else(|| StoreError::Integrity {
        revision,
        reason: format!("unknown encoding profile {profile}"),
    })?;
    let boundary = ValueBoundary::parse(boundary).ok_or_else(|| StoreError::Integrity {
        revision,
        reason: format!("unknown value boundary {boundary}"),
    })?;
    ContentDigest::from_parts(HashAlgorithm::Sha256, profile, boundary, bytes).map_err(|message| {
        StoreError::Integrity {
            revision,
            reason: format!("digest metadata is invalid: {message}"),
        }
    })
}

fn revision_row_by_id(
    connection: &Connection,
    revision: WorkspaceRevisionId,
) -> Result<Option<RevisionRow>> {
    let row = connection
        .query_row(
            "SELECT sequence, revision_id, parent_revision_id, manifest, manifest_digest,
                    eligibility_generation
             FROM revisions WHERE revision_id = ?1",
            params![revision.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?;
    let Some((sequence, revision_bytes, parent, manifest, manifest_digest, generation)) = row
    else {
        return Ok(None);
    };
    let revision = revision_from_blob(&revision_bytes)?;
    let parent = parent.map(|bytes| revision_from_blob(&bytes)).transpose()?;
    let digest = digest_with(
        &manifest_digest,
        "preserves-canonical-binary-v1",
        "payload",
        revision,
    )?;
    Ok(Some(RevisionRow {
        revision,
        sequence: u64::try_from(sequence).unwrap_or(0),
        parent,
        manifest_bytes: manifest,
        manifest_digest: digest,
        eligibility_generation: u64::try_from(generation).unwrap_or(0),
    }))
}

fn revision_blob_rows(connection: &Connection, sequence: u64) -> Result<Vec<(ContentDigest, u64)>> {
    let mut statement = connection.prepare(
        "SELECT rb.digest, b.profile, b.boundary, b.byte_length FROM revision_blobs rb
         JOIN blobs b ON b.digest = rb.digest
         WHERE rb.revision_sequence = ?1 ORDER BY rb.digest",
    )?;
    let rows = statement
        .query_map(
            params![i64::try_from(sequence).unwrap_or(i64::MAX)],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let placeholder = WorkspaceRevisionId::from_bytes([0; 16]);
    rows.into_iter()
        .map(|(digest, profile, boundary, length)| {
            Ok((
                digest_with(&digest, &profile, &boundary, placeholder)?,
                u64::try_from(length).unwrap_or(0),
            ))
        })
        .collect()
}

fn publication_outcomes(connection: &Connection, sequence: u64) -> Result<Vec<PublicationOutcome>> {
    let mut statement = connection.prepare(
        "SELECT intent_id, target_path, state, observed_digest, detail
         FROM publication_intents WHERE revision_sequence = ?1 ORDER BY rowid",
    )?;
    let rows = statement
        .query_map(
            params![i64::try_from(sequence).unwrap_or(i64::MAX)],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let placeholder = WorkspaceRevisionId::from_bytes([0; 16]);
    rows.into_iter()
        .map(|(intent_id, path, state, observed, detail)| {
            Ok(PublicationOutcome {
                intent_id,
                path,
                state: PublicationState::parse(&state).unwrap_or(PublicationState::Failed),
                observed: observed
                    .map(|bytes| digest_with(&bytes, "raw-bytes-v1", "source-bytes", placeholder))
                    .transpose()?,
                detail,
            })
        })
        .collect()
}

fn lookup_command_in(
    connection: &Connection,
    command: &CommitCommand,
) -> Result<Option<StoredCommand>> {
    let row = connection
        .query_row(
            "SELECT request_digest, outcome_revision, outcome_sequence FROM commands
             WHERE actor = ?1 AND scope = ?2 AND idempotency_key = ?3",
            params![
                command.actor,
                command.scope.to_string(),
                command.idempotency_key
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((request_digest, outcome_revision, outcome_sequence)) = row else {
        return Ok(None);
    };
    Ok(Some(StoredCommand {
        request_digest,
        outcome_revision: revision_from_blob(&outcome_revision)?,
        outcome_sequence: u64::try_from(outcome_sequence).unwrap_or(0),
    }))
}

fn validate_command(command: &CommitCommand) -> Result<()> {
    if command.actor.trim().is_empty()
        || command.actor.len() > 128
        || command.actor.chars().any(char::is_control)
    {
        return Err(StoreError::InvalidCommand(
            "actor must be non-empty, at most 128 bytes, and contain no control characters"
                .to_owned(),
        ));
    }
    if command.idempotency_key.trim().is_empty()
        || command.idempotency_key.len() > 256
        || command.idempotency_key.chars().any(char::is_control)
    {
        return Err(StoreError::InvalidCommand(
            "idempotency key must be non-empty, at most 256 bytes, and contain no control characters"
                .to_owned(),
        ));
    }
    for record in &command.records {
        if record.scope != command.scope {
            return Err(StoreError::ScopeMismatch {
                record_scope: record.scope.to_string(),
                command_scope: command.scope.to_string(),
            });
        }
    }
    Ok(())
}

fn validate_publication_paths(
    publications: &[PublicationDraft],
    candidates: &[ImportCandidateDraft],
) -> Result<()> {
    let mut paths = BTreeSet::new();
    for publication in publications {
        if !paths.insert(publication.path.clone()) {
            return Err(StoreError::InvalidCommand(format!(
                "publication path {:?} appears more than once",
                publication.path
            )));
        }
    }
    let mut candidate_paths = BTreeSet::new();
    for candidate in candidates {
        if !candidate_paths.insert(candidate.path.clone()) {
            return Err(StoreError::InvalidCommand(format!(
                "import candidate {:?} appears more than once",
                candidate.path
            )));
        }
        if paths.contains(&candidate.path) {
            return Err(StoreError::InvalidCommand(format!(
                "path {:?} is both published and imported",
                candidate.path
            )));
        }
    }
    Ok(())
}

fn validate_bindings(prior: &[RecordEnvelope], proposed: &[RecordEnvelope]) -> Result<()> {
    let mut bindings: BTreeMap<String, RecordId> = BTreeMap::new();
    for record in prior {
        if let Some((path, entity)) = source_binding(record)?
            && let Some(existing) = bindings.insert(path.clone(), entity)
            && existing != entity
        {
            return Err(StoreError::BindingConflict(format!(
                "source path {path:?} is bound to both {existing} and {entity}"
            )));
        }
    }
    for record in prior {
        if record.kind != RecordKind::SourceRevision {
            continue;
        }
        if let Some(replacement) = proposed
            .iter()
            .find(|candidate| candidate.record_id == record.record_id)
        {
            let before = source_binding(record)?;
            let after = source_binding(replacement)?;
            if let (Some((_, before_entity)), Some((_, after_entity))) = (before, after)
                && before_entity != after_entity
            {
                return Err(StoreError::BindingConflict(format!(
                    "source record {} cannot be reassigned from entity {before_entity} to {after_entity} implicitly",
                    record.record_id
                )));
            }
        }
    }
    for record in proposed {
        if let Some((path, entity)) = source_binding(record)?
            && let Some(existing) = bindings.insert(path.clone(), entity)
            && existing != entity
        {
            return Err(StoreError::BindingConflict(format!(
                "source path {path:?} is bound to both {existing} and {entity}"
            )));
        }
    }
    Ok(())
}

fn validate_snapshot_bindings(records: &BTreeMap<RecordId, RecordEnvelope>) -> Result<()> {
    let mut bindings: BTreeMap<String, RecordId> = BTreeMap::new();
    for record in records.values() {
        if let Some((path, entity)) = source_binding(record)?
            && let Some(existing) = bindings.insert(path.clone(), entity)
            && existing != entity
        {
            return Err(StoreError::BindingConflict(format!(
                "source path {path:?} is bound to both {existing} and {entity}"
            )));
        }
    }
    Ok(())
}

fn validate_sources(supplied: &[SourceBlobDraft], proposed: &[RecordEnvelope]) -> Result<()> {
    let mut supplied_digests = BTreeMap::new();
    for source in supplied {
        let digest = source.digest();
        if let Some(existing) = supplied_digests.insert(digest, source)
            && existing.bytes != source.bytes
        {
            return Err(StoreError::InvalidCommand(
                "source blobs with the same digest have different bytes".to_owned(),
            ));
        }
    }
    let mut referenced = BTreeSet::new();
    for record in proposed {
        let Some((digest, declared_length, media_type)) = retained_source(record)? else {
            continue;
        };
        referenced.insert(digest);
        if let Some(source) = supplied_digests.get(&digest) {
            if source.bytes.len() as u64 != declared_length {
                return Err(StoreError::SourceLengthMismatch {
                    digest: digest.to_hex(),
                    declared: declared_length,
                    supplied: source.bytes.len() as u64,
                });
            }
            if source.media_type != media_type {
                return Err(StoreError::InvalidCommand(format!(
                    "source blob {digest} media type does not match its source revision"
                )));
            }
        }
    }
    for digest in supplied_digests.keys() {
        if !referenced.contains(digest) {
            return Err(StoreError::InvalidCommand(format!(
                "source blob {digest} is not referenced by a new retained source revision"
            )));
        }
    }
    Ok(())
}

fn validate_snapshot_sources(
    records: &BTreeMap<RecordId, RecordEnvelope>,
    blobs: &BlobIndex,
) -> Result<()> {
    for record in records.values() {
        let Some((digest, declared_length, _)) = retained_source(record)? else {
            continue;
        };
        if let Some((_, length, _, _)) = blobs.get(digest.as_bytes()) {
            if *length != declared_length {
                return Err(StoreError::SourceLengthMismatch {
                    digest: digest.to_hex(),
                    declared: declared_length,
                    supplied: *length,
                });
            }
        } else {
            // The inherited blob must already be registered.
            return Err(StoreError::MissingSource {
                digest: digest.to_hex(),
            });
        }
    }
    Ok(())
}

fn candidate_matches(candidate: &ImportCandidateDraft, record: &RecordEnvelope) -> bool {
    if record.kind != RecordKind::SourceRevision {
        return false;
    }
    let path = record.payload.get("path-hint").and_then(Value::as_string);
    let entity = record
        .payload
        .get("entity")
        .and_then(|value| Reference::from_value(value, &mneme_core::Path::root()).ok())
        .and_then(|reference| reference.target());
    let content = record
        .payload
        .get("content")
        .and_then(|value| SourceContent::from_value(value, &mneme_core::Path::root()).ok());
    let retained = match content {
        Some(SourceContent::Retained(retained)) => Some(retained),
        _ => None,
    };
    path == Some(candidate.path.as_str())
        && entity.is_some()
        && retained
            .map(|retained| {
                retained.digest() == candidate.digest()
                    && retained.byte_length() == candidate.bytes.len() as u64
            })
            .unwrap_or(false)
}

fn source_binding(record: &RecordEnvelope) -> Result<Option<(String, RecordId)>> {
    if record.kind != RecordKind::SourceRevision {
        return Ok(None);
    }
    let Some(path) = record.payload.get("path-hint").and_then(Value::as_string) else {
        return Ok(None);
    };
    let Some(entity) = record.payload.get("entity") else {
        return Ok(None);
    };
    let reference =
        Reference::from_value(entity, &mneme_core::Path::root()).map_err(|diagnostic| {
            StoreError::InvalidCommand(format!(
                "source record {} has an invalid entity reference: {diagnostic}",
                record.record_id
            ))
        })?;
    Ok(reference.target().map(|target| (path.to_owned(), target)))
}

fn retained_source(record: &RecordEnvelope) -> Result<Option<(ContentDigest, u64, Symbol)>> {
    if record.kind != RecordKind::SourceRevision {
        return Ok(None);
    }
    let Some(content) = record.payload.get("content") else {
        return Ok(None);
    };
    let content =
        SourceContent::from_value(content, &mneme_core::Path::root()).map_err(|diagnostic| {
            StoreError::InvalidCommand(format!(
                "source record {} has invalid content: {diagnostic}",
                record.record_id
            ))
        })?;
    match content {
        SourceContent::Retained(retained) => Ok(Some((
            retained.digest(),
            retained.byte_length(),
            retained.media_type().clone(),
        ))),
        SourceContent::Unavailable { .. } => Ok(None),
    }
}

fn retained_source_digest(record: &RecordEnvelope) -> Option<ContentDigest> {
    retained_source(record)
        .ok()
        .flatten()
        .map(|(digest, _, _)| digest)
}

fn join(diagnostics: &[Diagnostic]) -> String {
    diagnostics
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}
