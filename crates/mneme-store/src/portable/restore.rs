//! Restore one verified portable archive into a new, isolated workspace.
//!
//! Nothing is written until the complete archive verifies. The rebuilt
//! workspace lives in a private sibling directory; the requested destination
//! must not exist, and the staging directory is renamed into place only after
//! every imported history, current record, and source blob verifies against the
//! archive. A failure removes only the staging directory this call created.

use crate::error::Failure;
use crate::portable::file::ArchiveFile;
use crate::portable::{
    MAX_PORTABLE_BLOB_BYTES, PortableRestoreReport, portable_retained_source,
};

const RESTORE_ACTOR: &str = "portable-restore";

/// Restore `archive` into the new workspace directory `destination`.
///
/// The archive is verified twice: once before any write and once after the
/// workspace is rebuilt but before it becomes visible at `destination`.
pub fn restore(
    archive: &std::path::Path,
    destination: &std::path::Path,
    config: crate::WorkspaceConfig,
) -> crate::error::Result<PortableRestoreReport> {
    let archive = ArchiveFile::verify(archive)?;
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .map_or_else(|| std::path::PathBuf::from("."), std::path::Path::to_path_buf);
    std::fs::create_dir_all(&parent)
        .map_err(|error| crate::Failure::io(&parent, error))?;
    let parent = std::fs::canonicalize(&parent)
        .map_err(|error| crate::Failure::io(&parent, error))?;
    let name = destination.file_name().ok_or_else(|| {
        Failure::InvalidCommand("restore destination has no directory name".to_owned())
    })?;
    let target = parent.join(name);
    if std::fs::symlink_metadata(&target).is_ok() {
        return Err(Failure::InvalidCommand(format!(
            "restore destination {} already exists; restore needs a new directory",
            target.display()
        )));
    }
    let staging = parent.join(format!(
        ".{}.mneme-restore-{}",
        name.to_string_lossy(),
        crate::payload::random_hex(8)?
    ));
    let restored = (|| -> crate::error::Result<PortableRestoreReport> {
        let mut report = import_into(&archive, &staging, config)?;
        archive.recheck()?;
        publish_staging(&staging, &target)?;
        report.destination = target;
        Ok(report)
    })();
    if restored.is_err() {
        remove_staging(&staging);
    }
    restored
}

/// Rebuild the workspace in `staging` from one verified archive.
fn import_into(
    archive: &ArchiveFile,
    staging: &std::path::Path,
    config: crate::WorkspaceConfig,
) -> crate::error::Result<PortableRestoreReport> {
    let manifest = &archive.manifest;
    let mut workspace = crate::Workspace::create(staging, config)?;
    workspace.install_portable_retention(
        &manifest.scope,
        &crate::portable::PortableRetentionState {
            generation: manifest.generation,
            suppressions: manifest.suppressions.clone(),
            prunings: manifest.prunings.clone(),
        },
    )?;
    let mut rewritten_predecessors = 0_u64;
    let mut revisions = 0_u64;
    for record in &manifest.records {
        let mut previous: Option<mneme_core::RevisionId> = None;
        for revision in &record.revisions {
            let envelope = &revision.envelope;
            if envelope.predecessor != previous {
                rewritten_predecessors = rewritten_predecessors.saturating_add(1);
            }
            let mut source_blobs = Vec::new();
            if let Some(retained) = portable_retained_source(envelope)? {
                let bytes = archive.blob(retained.digest())?;
                if bytes.len() as u64 != retained.byte_length()
                    || retained.byte_length() > MAX_PORTABLE_BLOB_BYTES
                {
                    return Err(Failure::CorruptBlob {
                        digest: retained.digest().to_hex(),
                        reason: "archive source length does not match its record".to_owned(),
                    });
                }
                source_blobs.push(crate::SourceBlobDraft {
                    bytes,
                    media_type: retained.media_type().clone(),
                });
            }
            let draft = crate::RecordDraft {
                schema_version: envelope.schema_version,
                kind: envelope.kind,
                record_id: envelope.record_id,
                revision_id: envelope.revision_id,
                predecessor: previous,
                scope: envelope.scope.clone(),
                payload: envelope.payload.clone(),
            };
            let command = crate::CommitCommand {
                base: workspace.current_revision()?,
                actor: RESTORE_ACTOR.to_owned(),
                scope: manifest.scope.clone(),
                idempotency_key: restore_key(envelope.record_id, envelope.revision_id),
                records: vec![draft],
                source_blobs,
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            };
            workspace.commit(command)?;
            previous = Some(envelope.revision_id);
            revisions = revisions.saturating_add(1);
        }
    }
    let snapshot = workspace.snapshot()?;
    verify_restored(archive, &workspace, &snapshot)?;
    let (publications, ambiguous_publication_paths) =
        current_publications(archive, &snapshot)?;
    let publications = if publications.is_empty() {
        Vec::new()
    } else {
        workspace.commit(crate::CommitCommand {
            base: workspace.current_revision()?,
            actor: RESTORE_ACTOR.to_owned(),
            scope: manifest.scope.clone(),
            idempotency_key: "portable-restore:publications".to_owned(),
            records: Vec::new(),
            source_blobs: Vec::new(),
            publications,
            import_candidates: Vec::new(),
            retention: None,
        })?;
        workspace.publish_pending()?
    };
    let final_snapshot = workspace.snapshot()?;
    Ok(PortableRestoreReport {
        destination: std::path::PathBuf::new(),
        scope: manifest.scope.clone(),
        revision: final_snapshot.revision,
        sequence: final_snapshot.sequence,
        record_count: manifest.current.len() as u64,
        revision_count: revisions,
        blob_count: manifest.blobs.len() as u64,
        rewritten_predecessors,
        publications,
        omissions: manifest.omissions.clone(),
        ambiguous_publication_paths,
    })
}

/// Publication intents for current notes whose path is unambiguous.
fn current_publications(
    archive: &ArchiveFile,
    snapshot: &crate::Snapshot,
) -> crate::error::Result<(Vec<crate::PublicationDraft>, u64)> {
    struct Candidate {
        digest: mneme_core::ContentDigest,
        bytes: Vec<u8>,
    }
    let mut candidates: std::collections::BTreeMap<String, Option<Candidate>> =
        std::collections::BTreeMap::new();
    for record in &snapshot.records {
        if record.kind != mneme_core::RecordKind::SourceRevision {
            continue;
        }
        let Some(retained) = portable_retained_source(record)? else {
            continue;
        };
        let Some(path) = record
            .payload
            .get("path-hint")
            .and_then(mneme_core::Value::as_string)
        else {
            continue;
        };
        let bytes = archive.blob(retained.digest())?;
        match candidates.entry(path.to_owned()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(Some(Candidate {
                    digest: retained.digest(),
                    bytes,
                }));
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let conflicts = entry
                    .get()
                    .as_ref()
                    .is_some_and(|existing| existing.digest != retained.digest());
                if conflicts {
                    entry.insert(None);
                }
            }
        }
    }
    let mut publications = Vec::new();
    let mut ambiguous = 0_u64;
    for (path, candidate) in candidates {
        let Some(candidate) = candidate else {
            ambiguous = ambiguous.saturating_add(1);
            continue;
        };
        if candidate.bytes.len() as u64 > MAX_PORTABLE_BLOB_BYTES {
            return Err(Failure::HistoryLimitExceeded);
        }
        crate::payload::validate_relative_path(&path)?;
        publications.push(crate::PublicationDraft {
            path,
            expected_previous: None,
            bytes: candidate.bytes,
        });
    }
    Ok((publications, ambiguous))
}

/// Verify every imported history, current record, and blob against the archive.
fn verify_restored(
    archive: &ArchiveFile,
    workspace: &crate::Workspace,
    snapshot: &crate::Snapshot,
) -> crate::error::Result<()> {
    let manifest = &archive.manifest;
    if snapshot.records.len() != manifest.current.len() {
        return Err(Failure::PortableArchive(
            "restored workspace does not hold the archive's current record set".to_owned(),
        ));
    }
    let mut actual_current: std::collections::BTreeMap<
        mneme_core::RecordId,
        &mneme_core::RecordEnvelope,
    > = snapshot
        .records
        .iter()
        .map(|record| (record.record_id, record))
        .collect();
    for expected in &manifest.current {
        let Some(record) = actual_current.remove(&expected.record_id) else {
            return Err(Failure::PortableArchive(
                "restored workspace is missing one current record".to_owned(),
            ));
        };
        if record.revision_id != expected.revision_id || record.kind != expected.kind {
            return Err(Failure::PortableArchive(
                "restored workspace current revision differs from the archive".to_owned(),
            ));
        }
    }
    if !actual_current.is_empty() {
        return Err(Failure::PortableArchive(
            "restored workspace holds records the archive did not name".to_owned(),
        ));
    }
    let records: std::collections::BTreeSet<_> = manifest
        .records
        .iter()
        .map(|record| record.record_id)
        .collect();
    let histories = workspace.record_histories_of(snapshot, &records)?;
    for expected in &manifest.records {
        let Some(history) = histories.get(&expected.record_id) else {
            return Err(Failure::PortableArchive(
                "restored workspace is missing one record history".to_owned(),
            ));
        };
        if history.len() != expected.revisions.len() {
            return Err(Failure::PortableArchive(
                "restored workspace history length differs from the archive".to_owned(),
            ));
        }
        for (position, (actual, wanted)) in
            history.iter().zip(expected.revisions.iter()).enumerate()
        {
            if actual.record_id != wanted.envelope.record_id
                || actual.revision_id != wanted.envelope.revision_id
                || actual.kind != wanted.envelope.kind
                || actual.scope != wanted.envelope.scope
                || actual.schema_version != wanted.envelope.schema_version
                || actual.payload_digest() != wanted.envelope.payload_digest()
            {
                return Err(Failure::PortableArchive(
                    "restored record revision differs from the archive".to_owned(),
                ));
            }
            if position > 0 {
                let previous = history.get(position - 1).map(|entry| entry.revision_id);
                if actual.predecessor != previous {
                    return Err(Failure::PortableArchive(
                        "restored record revision chain is not contiguous".to_owned(),
                    ));
                }
            }
            let actual_source = portable_retained_source(actual)?;
            let wanted_source = portable_retained_source(&wanted.envelope)?;
            if actual_source.map(|source| (source.digest(), source.byte_length()))
                != wanted_source.map(|source| (source.digest(), source.byte_length()))
            {
                return Err(Failure::PortableArchive(
                    "restored record revision retains different source bytes".to_owned(),
                ));
            }
        }
    }
    for blob in &manifest.blobs {
        let bytes = crate::payload::read(workspace.root(), blob.digest)?;
        if bytes.len() as u64 != blob.length {
            return Err(Failure::CorruptBlob {
                digest: blob.digest.to_hex(),
                reason: "restored source length differs from the archive".to_owned(),
            });
        }
    }
    Ok(())
}

/// A deterministic idempotency key for one imported revision.
fn restore_key(
    record: mneme_core::RecordId,
    revision: mneme_core::RevisionId,
) -> String {
    format!("portable-restore:{record}:{revision}")
}

/// Move the completed staging directory to its final name.
fn publish_staging(
    staging: &std::path::Path,
    destination: &std::path::Path,
) -> crate::error::Result<()> {
    if std::fs::symlink_metadata(destination).is_ok() {
        return Err(Failure::InvalidCommand(format!(
            "restore destination {} appeared while the restore ran",
            destination.display()
        )));
    }
    std::fs::rename(staging, destination)
        .map_err(|error| crate::Failure::io(destination, error))?;
    let parent = destination
        .parent()
        .map_or_else(|| std::path::PathBuf::from("."), std::path::Path::to_path_buf);
    std::fs::File::open(&parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| crate::Failure::io(&parent, error))?;
    Ok(())
}

/// Remove only the private staging directory this restore created.
fn remove_staging(staging: &std::path::Path) {
    #[allow(unknown_lints, ignored_result)]
    // best-effort cleanup of this restore's private staging directory
    let _ = std::fs::remove_dir_all(staging);
}
