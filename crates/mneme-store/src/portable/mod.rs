//! Portable, self-contained backup and restore of one vault scope.
//!
//! The archive is a single checksummed file. It contains a canonical Preserves
//! manifest plus the exact source blobs the included record revisions retain.
//! It never contains the live ledger, its WAL, working files, drafts, export
//! sites, repository files, or bytes outside the exported scope.
//!
//! Export reads one committed snapshot under the workspace eligibility guard,
//! walks each included record's retained revision chain as it stood at that
//! pinned sequence, and refuses to write a partial archive: every retained
//! source blob must still verify. Records or revisions that cannot be exported
//! are counted in the manifest's omission list by reason.
//!
//! Restore verifies the complete archive before touching the destination, then
//! rebuilds a new workspace through the ordinary commit path, installs the
//! exported retention decisions first so forgotten content cannot be replayed,
//! and publishes current source files only when the destination cannot already
//! hold their bytes. The destination must not exist; the restore is assembled
//! in a private sibling directory and renamed into place only after the
//! rebuilt workspace verifies against the archive.

mod file;
mod manifest;
mod restore;

pub use restore::restore;

use crate::error::Failure;

/// The manifest record label.
pub const PORTABLE_ARCHIVE_FORMAT: &str = "mneme-portable-vault";

/// The supported archive manifest version.
pub const PORTABLE_ARCHIVE_VERSION: u64 = 1;

/// Largest accepted archive file.
pub const MAX_PORTABLE_ARCHIVE_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Largest accepted manifest section.
pub const MAX_PORTABLE_MANIFEST_BYTES: u64 = 256 * 1024 * 1024;

/// Largest number of records one archive may contain.
pub const MAX_PORTABLE_RECORDS: usize = 100_000;

/// Largest number of record revisions one archive may contain.
pub const MAX_PORTABLE_REVISIONS: usize = 1_000_000;

/// Largest number of source blobs one archive may contain.
pub const MAX_PORTABLE_BLOBS: usize = 1_000_000;

/// Largest accepted single source blob.
pub const MAX_PORTABLE_BLOB_BYTES: u64 = 1024 * 1024 * 1024;

/// One revision in a record's retained chain, with its introducing commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableRevision {
    pub envelope: mneme_core::RecordEnvelope,
    pub commit: crate::coordinator::RevisionCommit,
}

/// The retained history of one included record, oldest first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableRecord {
    pub record_id: mneme_core::RecordId,
    pub scope: mneme_core::ScopeId,
    pub revisions: Vec<PortableRevision>,
}

/// The newest retained revision of one included record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortableCurrent {
    pub record_id: mneme_core::RecordId,
    pub revision_id: mneme_core::RevisionId,
    pub kind: mneme_core::RecordKind,
}

/// One exact source blob the archive body carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortableBlob {
    pub digest: mneme_core::ContentDigest,
    pub length: u64,
}

/// One retention suppression the imported copy must keep.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableSuppression {
    pub target: mneme_core::RecordId,
    pub revision: Option<mneme_core::RevisionId>,
    pub target_kind: String,
    pub mode: crate::lifecycle::SuppressionMode,
    pub content_digest: Option<mneme_core::ContentDigest>,
    pub generation: u64,
}

/// One pruning decision: a source revision whose bytes were authorized absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PortablePruning {
    pub source: mneme_core::RecordId,
    pub revision: mneme_core::RevisionId,
    pub digest: mneme_core::ContentDigest,
}

/// One counted omission, with a stable reason code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableOmission {
    pub reason: String,
    pub count: u64,
}

/// Everything an imported workspace needs to keep arrival-independent
/// retention semantics for the exported scope.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PortableRetentionState {
    pub generation: u64,
    pub suppressions: Vec<PortableSuppression>,
    pub prunings: Vec<PortablePruning>,
}

/// The verified contents of one archive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableManifest {
    pub scope: mneme_core::ScopeId,
    pub revision: mneme_core::WorkspaceRevisionId,
    pub sequence: u64,
    pub generation: u64,
    pub records: Vec<PortableRecord>,
    pub current: Vec<PortableCurrent>,
    pub blobs: Vec<PortableBlob>,
    pub suppressions: Vec<PortableSuppression>,
    pub prunings: Vec<PortablePruning>,
    pub omissions: Vec<PortableOmission>,
}

/// What one completed export wrote and what it could not include.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableExportReport {
    pub path: std::path::PathBuf,
    pub checksum: String,
    pub bytes: u64,
    pub scope: mneme_core::ScopeId,
    pub revision: mneme_core::WorkspaceRevisionId,
    pub sequence: u64,
    pub generation: u64,
    pub record_count: u64,
    pub revision_count: u64,
    pub blob_count: u64,
    pub omissions: Vec<PortableOmission>,
}

/// What one completed restore rebuilt and what it published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableRestoreReport {
    pub destination: std::path::PathBuf,
    pub scope: mneme_core::ScopeId,
    pub revision: mneme_core::WorkspaceRevisionId,
    pub sequence: u64,
    pub record_count: u64,
    pub revision_count: u64,
    pub blob_count: u64,
    pub rewritten_predecessors: u64,
    pub publications: Vec<crate::coordinator::PublicationOutcome>,
    pub omissions: Vec<PortableOmission>,
    pub ambiguous_publication_paths: u64,
}

/// Counted omissions while one archive is assembled.
#[derive(Default)]
pub(crate) struct OmissionCounts {
    counts: std::collections::BTreeMap<String, u64>,
}

impl OmissionCounts {
    /// Add one occurrence of a reason code.
    pub(crate) fn bump(&mut self, reason: &str, count: u64) {
        let entry = self.counts.entry(reason.to_owned()).or_default();
        *entry = entry.saturating_add(count);
    }

    /// Stable, sorted entries.
    pub(crate) fn into_vec(self) -> Vec<PortableOmission> {
        self.counts
            .into_iter()
            .filter(|(_, count)| *count != 0)
            .map(|(reason, count)| PortableOmission { reason, count })
            .collect()
    }
}

/// Retention state gathered from one ledger state, plus its derived scan sets.
pub(crate) struct PortableRetentionExport {
    pub state: PortableRetentionState,
    pub forgotten_content: std::collections::BTreeSet<[u8; 32]>,
    pub pruning_targets: std::collections::BTreeSet<(
        mneme_core::RecordId,
        mneme_core::RevisionId,
    )>,
    pub pruning_digests: std::collections::BTreeSet<(mneme_core::RecordId, [u8; 32])>,
    pub omissions: OmissionCounts,
}

impl crate::coordinator::Workspace {
    /// Write one complete portable backup of `scope` to `out`.
    ///
    /// Holding the eligibility guard blocks a retention barrier for the whole
    /// read, so no forgot operation can purge a blob this export still expects.
    /// Ordinary commits may land; this archive names the exact revision and
    /// sequence it read, and a record revised after that point is ignored
    /// because only revisions introduced at or before the pinned sequence are
    /// included.
    pub fn export_portable(
        &self,
        out: &std::path::Path,
        scope: &mneme_core::ScopeId,
    ) -> crate::error::Result<PortableExportReport> {
        // Retention state and the pinned snapshot must describe one committed
        // revision. A normal commit can land between the two reads, so retry the
        // pair a bounded number of times; a barrier makes the eligibility guard
        // refuse a generation that was already stale.
        let mut attempts = 0_u32;
        let (snapshot, retention, guard) = loop {
            attempts = attempts.saturating_add(1);
            let snapshot = self.snapshot()?;
            let retention = self.export_portable_retention(scope)?;
            if self.current_revision()? != snapshot.revision {
                if attempts >= 3 {
                    return Err(Failure::InvalidCommand(
                        "workspace changed while starting the portable backup; try again"
                            .to_owned(),
                    ));
                }
                continue;
            }
            match self.eligibility_guard(snapshot.eligibility_generation) {
                Ok(guard) => break (snapshot, retention, guard),
                Err(Failure::BarrierAdvanced { .. }) if attempts < 3 => continue,
                Err(error) => return Err(error),
            }
        };
        let mut omissions = retention.omissions;
        if retention.state.generation != snapshot.eligibility_generation {
            return Err(Failure::InvalidCommand(
                "workspace retention state changed while starting the portable backup; try again"
                    .to_owned(),
            ));
        }
        let mut records = Vec::new();
        let mut current = Vec::new();
        let mut blob_lengths: std::collections::BTreeMap<
            [u8; 32],
            (mneme_core::ContentDigest, u64),
        > = std::collections::BTreeMap::new();
        let mut snapshot_records: Vec<&mneme_core::RecordEnvelope> =
            snapshot.records.iter().collect();
        snapshot_records.sort_by_key(|record| record.record_id);
        for record in snapshot_records {
            if record.scope != *scope {
                omissions.bump("foreign-scope-record", 1);
                continue;
            }
            let Some(revisions) = self.portable_history(
                record,
                scope,
                snapshot.sequence,
                &retention.forgotten_content,
                &retention.pruning_targets,
                &retention.pruning_digests,
                &mut omissions,
            )?
            else {
                continue;
            };
            for revision in &revisions {
                let Some(retained) = portable_retained_source(&revision.envelope)? else {
                    continue;
                };
                let length = retained.byte_length();
                if length > MAX_PORTABLE_BLOB_BYTES {
                    return Err(Failure::HistoryLimitExceeded);
                }
                let key = *retained.digest().as_bytes();
                match blob_lengths.entry(key) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert((retained.digest(), length));
                    }
                    std::collections::btree_map::Entry::Occupied(entry) => {
                        if entry.get().1 != length {
                            return Err(Failure::PortableArchive(
                                "one source digest is declared with two lengths".to_owned(),
                            ));
                        }
                    }
                }
            }
            current.push(PortableCurrent {
                record_id: record.record_id,
                revision_id: record.revision_id,
                kind: record.kind,
            });
            records.push(PortableRecord {
                record_id: record.record_id,
                scope: record.scope.clone(),
                revisions,
            });
        }
        current.sort_by_key(|entry| entry.record_id);
        if blob_lengths.len() > MAX_PORTABLE_BLOBS {
            return Err(Failure::HistoryLimitExceeded);
        }
        let mut blobs = Vec::with_capacity(blob_lengths.len());
        for (_, (digest, length)) in &blob_lengths {
            let bytes = crate::payload::read(self.root(), *digest)?;
            if bytes.len() as u64 != *length {
                return Err(Failure::CorruptBlob {
                    digest: digest.to_hex(),
                    reason: "stored length differs from the length its record declares".to_owned(),
                });
            }
            blobs.push(PortableBlob {
                digest: *digest,
                length: *length,
            });
        }
        let revision_count = records
            .iter()
            .map(|record| record.revisions.len())
            .sum::<usize>();
        let manifest = PortableManifest {
            scope: scope.clone(),
            revision: snapshot.revision,
            sequence: snapshot.sequence,
            generation: snapshot.eligibility_generation,
            records,
            current,
            blobs,
            suppressions: retention.state.suppressions,
            prunings: retention.state.prunings,
            omissions: omissions.into_vec(),
        };
        manifest.validate()?;
        let bytes = manifest.encode();
        let mut writer = file::ArchiveWriter::create(out)?;
        writer.write_manifest(&bytes)?;
        for blob in &manifest.blobs {
            let source = crate::payload::read(self.root(), blob.digest)?;
            if source.len() as u64 != blob.length {
                return Err(Failure::CorruptBlob {
                    digest: blob.digest.to_hex(),
                    reason: "source bytes changed between archive checks".to_owned(),
                });
            }
            writer.write_blob(blob.digest, &source)?;
        }
        if self.current_revision()? != snapshot.revision {
            return Err(Failure::InvalidCommand(
                "workspace changed while writing the portable backup; try again".to_owned(),
            ));
        }
        let published = writer.finish()?;
        drop(guard);
        Ok(PortableExportReport {
            path: published.path,
            checksum: published.checksum,
            bytes: published.bytes,
            scope: manifest.scope,
            revision: manifest.revision,
            sequence: manifest.sequence,
            generation: manifest.generation,
            record_count: manifest.records.len() as u64,
            revision_count: revision_count as u64,
            blob_count: manifest.blobs.len() as u64,
            omissions: manifest.omissions,
        })
    }

    /// Every includable retained revision as of one sequence.
    ///
    /// Each retained revision is judged on its own: a revision in another
    /// scope, one a pruning decision hides, one whose content digest was
    /// forgotten, and one the running schema no longer validates are omitted
    /// and counted by reason. Revisions on either side of an omission stay in
    /// the archive, so retained pre-purge history is not discarded merely
    /// because a newer revision is absent. Restore relinks the kept subsequence
    /// and reports every rewritten predecessor.
    fn portable_history(
        &self,
        current: &mneme_core::RecordEnvelope,
        scope: &mneme_core::ScopeId,
        sequence: u64,
        forgotten_content: &std::collections::BTreeSet<[u8; 32]>,
        pruning_targets: &std::collections::BTreeSet<(
            mneme_core::RecordId,
            mneme_core::RevisionId,
        )>,
        pruning_digests: &std::collections::BTreeSet<(mneme_core::RecordId, [u8; 32])>,
        omissions: &mut OmissionCounts,
    ) -> crate::error::Result<Option<Vec<PortableRevision>>> {
        let mut newest_first = Vec::new();
        let mut cursor = None;
        let mut pages = 0_usize;
        loop {
            let page = match self.record_revision_commits(current.record_id, cursor) {
                Ok(page) => page,
                Err(Failure::RetentionSuppressed { .. }) => {
                    omissions.bump("forgotten-record", 1);
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
            pages = pages.saturating_add(1);
            if pages > (MAX_PORTABLE_REVISIONS / 10).saturating_add(1) {
                return Err(Failure::HistoryLimitExceeded);
            }
            if page.entries.len() > 10 {
                return Err(Failure::PortableArchive(
                    "history page exceeds its admitted entry bound".to_owned(),
                ));
            }
            newest_first.extend(
                page.entries
                    .into_iter()
                    .filter(|entry| entry.commit.sequence <= sequence),
            );
            if newest_first.len() > MAX_PORTABLE_REVISIONS {
                return Err(Failure::HistoryLimitExceeded);
            }
            if !page.has_more {
                break;
            }
            let next = page.next_before_sequence.ok_or_else(|| {
                Failure::PortableArchive("history page has no continuation cursor".to_owned())
            })?;
            if cursor.is_some_and(|previous| next >= previous) {
                return Err(Failure::PortableArchive(
                    "history continuation cursor does not advance".to_owned(),
                ));
            }
            cursor = Some(next);
        }
        if newest_first.is_empty() {
            omissions.bump("history-gap", 1);
            return Ok(None);
        }
        let mut seen_revisions = std::collections::BTreeSet::new();
        let mut previous_sequence: Option<u64> = None;
        for entry in &newest_first {
            if !seen_revisions.insert(entry.record.revision_id) {
                return Err(Failure::PortableArchive(
                    "retained history repeats one revision".to_owned(),
                ));
            }
            if previous_sequence.is_some_and(|previous| previous <= entry.commit.sequence) {
                return Err(Failure::PortableArchive(
                    "retained history is not in descending commit order".to_owned(),
                ));
            }
            previous_sequence = Some(entry.commit.sequence);
        }
        let registry = mneme_core::SchemaRegistry::production();
        let mut kept: Vec<PortableRevision> = Vec::new();
        for entry in newest_first {
            let revision_id = entry.record.revision_id;
            let in_scope = entry.record.scope == *scope;
            let retained = portable_retained_source(&entry.record)?;
            let pruned = pruning_targets.contains(&(entry.record.record_id, revision_id))
                || retained.as_ref().is_some_and(|source| {
                    pruning_digests
                        .contains(&(entry.record.record_id, *source.digest().as_bytes()))
                });
            let forgotten = retained
                .as_ref()
                .is_some_and(|source| forgotten_content.contains(source.digest().as_bytes()));
            let supported = mneme_core::validate_record_value(
                &entry.record.to_value(),
                &registry,
                None,
            )
            .is_ok();
            if in_scope && !pruned && !forgotten && supported {
                kept.push(PortableRevision {
                    envelope: entry.record,
                    commit: entry.commit,
                });
                continue;
            }
            let reason = if !in_scope {
                "foreign-scope-revision"
            } else if pruned {
                "pruned-revision"
            } else if forgotten {
                "forgotten-content"
            } else {
                "unsupported-schema"
            };
            omissions.bump(reason, 1);
        }
        if kept.is_empty() {
            return Ok(None);
        }
        // The snapshot's current revision is the newest entry. If it was
        // omitted, older revisions cannot stand in for it: the record itself is
        // not restorable as current, so leave it out and say how much history
        // went with it.
        if kept
            .first()
            .map(|entry| entry.envelope.revision_id)
            != Some(current.revision_id)
        {
            omissions.bump("current-revision-unavailable", 1);
            omissions.bump("record-history-dropped", kept.len() as u64);
            return Ok(None);
        }
        kept.reverse();
        Ok(Some(kept))
    }
}

/// The retained source a record revision names, when it retains bytes.
pub(crate) fn portable_retained_source(
    record: &mneme_core::RecordEnvelope,
) -> crate::error::Result<Option<mneme_core::RetainedSource>> {
    if record.kind != mneme_core::RecordKind::SourceRevision {
        return Ok(None);
    }
    let Some(value) = record.payload.get("content") else {
        return Ok(None);
    };
    let content = mneme_core::SourceContent::from_value(value, &mneme_core::Path::root())
        .map_err(|diagnostic| {
            Failure::PortableArchive(format!("source content: {diagnostic}"))
        })?;
    match content {
        mneme_core::SourceContent::Retained(retained) => Ok(Some(retained)),
        mneme_core::SourceContent::Unavailable { .. } => Ok(None),
    }
}
