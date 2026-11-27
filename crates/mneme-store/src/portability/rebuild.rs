//! Restore one verified portable archive into a new, isolated workspace.
//!
//! Nothing is written until the complete archive verifies. The rebuilt
//! workspace lives in a private sibling directory; the requested destination
//! must not exist, and the staging directory is renamed into place only after
//! every imported history, current record, and source blob verifies against the
//! archive. A failure removes only the staging directory this call created.

const RESTORE_ACTOR: &str = "portable-restore";

/// Restore `archive` into the new workspace directory `destination`.
///
/// The archive is verified twice: once before any write and once after the
/// workspace is rebuilt but before it becomes visible at `destination`.
pub fn restore(
    archive: &std::path::Path,
    destination: &std::path::Path,
    config: crate::WorkspaceConfig,
) -> crate::error::Result<super::PortableRestoreReport> {
    let mut archive = super::file::ArchiveReader::verify(archive)?;
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .map_or_else(
            || std::path::PathBuf::from("."),
            std::path::Path::to_path_buf,
        );
    let parent =
        std::fs::canonicalize(&parent).map_err(|error| crate::Failure::io(&parent, error))?;
    let name = destination.file_name().ok_or_else(|| {
        crate::error::Failure::InvalidCommand(
            "restore destination has no directory name".to_owned(),
        )
    })?;
    let target = parent.join(name);
    if std::fs::symlink_metadata(&target).is_ok() {
        return Err(crate::error::Failure::InvalidCommand(format!(
            "restore destination {} already exists; restore needs a new directory",
            target.display()
        )));
    }
    let staging = tempfile::Builder::new()
        .prefix(".mneme-restore-")
        .tempdir_in(&parent)
        .map_err(|error| crate::Failure::io(&parent, error))?;
    let mut report = import_into(&archive, staging.path(), config)?;
    archive.recheck()?;
    publish_staging(staging.path(), &target)?;
    report.destination = target;
    Ok(report)
}

/// Rebuild the workspace in `staging` from one verified archive.
fn import_into(
    archive: &super::file::ArchiveReader,
    staging: &std::path::Path,
    config: crate::WorkspaceConfig,
) -> crate::error::Result<super::PortableRestoreReport> {
    let manifest = &archive.manifest;
    let mut workspace = crate::Workspace::create(staging, config)?;
    workspace.install_portable_retention(
        &manifest.scope,
        &crate::portability::PortableRetentionState {
            generation: manifest.generation,
            suppressions: manifest.suppressions.clone(),
            prunings: manifest.prunings.clone(),
            key_punctures: Vec::new(),
        },
    )?;
    let (revisions, rewritten_predecessors) = replay(archive, &mut workspace)?;
    let snapshot = workspace.snapshot()?;
    verify_restored(manifest, &workspace, &snapshot)?;
    let (publications, ambiguous_publication_paths) =
        publish_current(archive, &mut workspace, &snapshot)?;
    Ok(super::PortableRestoreReport {
        destination: std::path::PathBuf::new(),
        scope: manifest.scope.clone(),
        revision: workspace.current_revision()?,
        sequence: workspace.current_sequence()?,
        record_count: manifest.current.len() as u64,
        revision_count: revisions,
        blob_count: manifest.blobs.len() as u64,
        rewritten_predecessors,
        publications,
        omissions: manifest.omissions.clone(),
        ambiguous_publication_paths,
    })
}

type Predecessors = std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RevisionId>;

fn replay(
    archive: &super::file::ArchiveReader,
    workspace: &mut crate::Workspace,
) -> crate::error::Result<(u64, u64)> {
    // Replay the archive's own commit batches. Records introduced together may
    // reference each other (an assertion and its evidence, for example), so
    // importing one record revision per transaction would refuse a reference
    // the original batch resolved internally.
    let ordered = super::ordered_revisions(&archive.manifest.records);
    let mut last_imported = Predecessors::new();
    let mut rewritten_predecessors = 0_u64;
    for entries in ordered.chunk_by(super::same_batch) {
        let sequence = entries[0].commit.sequence;
        let records = entries
            .iter()
            .map(|revision| {
                let envelope = &revision.envelope;
                let predecessor = last_imported.insert(envelope.record_id, envelope.revision_id);
                if envelope.predecessor != predecessor {
                    rewritten_predecessors = rewritten_predecessors.saturating_add(1);
                }
                crate::RecordDraft {
                    schema_version: envelope.schema_version,
                    kind: envelope.kind,
                    record_id: envelope.record_id,
                    revision_id: envelope.revision_id,
                    predecessor,
                    scope: envelope.scope.clone(),
                    payload: envelope.payload.clone(),
                }
            })
            .collect();
        workspace.commit(crate::CommitCommand {
            base: workspace.current_revision()?,
            actor: RESTORE_ACTOR.to_owned(),
            scope: archive.manifest.scope.clone(),
            idempotency_key: format!("portable-restore:commit:{sequence}"),
            records,
            source_blobs: source_blobs(archive, entries)?,
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })?;
    }
    Ok((ordered.len() as u64, rewritten_predecessors))
}

fn source_blobs(
    archive: &super::file::ArchiveReader,
    entries: &[&super::PortableRevision],
) -> crate::error::Result<Vec<crate::SourceBlobDraft>> {
    let mut sources = std::collections::BTreeMap::new();
    for revision in entries {
        if let Some(retained) = super::portable_retained_source(&revision.envelope)? {
            sources
                .entry(*retained.digest().as_bytes())
                .or_insert(retained);
        }
    }
    debug_assert!(sources.len() <= entries.len());
    let expected_count = sources.len();
    let built: Vec<_> = sources
        .into_values()
        .map(|retained| {
            let bytes = archive.blob(retained.digest())?;
            if bytes.len() as u64 != retained.byte_length() {
                return Err(crate::error::Failure::CorruptBlob {
                    digest: retained.digest().to_hex(),
                    reason: "archive source length does not match its record".to_owned(),
                });
            }
            Ok(crate::SourceBlobDraft::inline(
                bytes,
                retained.media_type().clone(),
            ))
        })
        .collect::<crate::error::Result<Vec<_>>>()?;
    debug_assert_eq!(built.len(), expected_count);
    Ok(built)
}

fn publish_current(
    archive: &super::file::ArchiveReader,
    workspace: &mut crate::Workspace,
    snapshot: &crate::Snapshot,
) -> crate::error::Result<(Vec<crate::coordinator::PublicationOutcome>, u64)> {
    let (candidates, ambiguous) = current_publications(snapshot)?;
    let mut outcomes = Vec::with_capacity(candidates.len());
    for (index, (path, digest)) in candidates.into_iter().enumerate() {
        let bytes = archive.blob(digest)?;
        let published = workspace.commit(crate::CommitCommand {
            base: workspace.current_revision()?,
            actor: RESTORE_ACTOR.to_owned(),
            scope: archive.manifest.scope.clone(),
            idempotency_key: format!("portable-restore:publication:{index}"),
            records: Vec::new(),
            source_blobs: Vec::new(),
            publications: vec![crate::PublicationDraft {
                path,
                expected_previous: None,
                bytes,
            }],
            import_candidates: Vec::new(),
            retention: None,
        })?;
        for outcome in &published.publications {
            if outcome.state != crate::PublicationState::Published {
                return Err(crate::error::Failure::PortableArchive(format!(
                    "restore could not publish {} ({})",
                    outcome.path,
                    outcome.state.as_str()
                )));
            }
        }
        outcomes.extend(published.publications);
    }
    Ok((outcomes, ambiguous))
}

type WorkingPaths = std::collections::BTreeMap<String, mneme_core::ContentDigest>;

/// Publication intents for current notes whose path is unambiguous.
fn current_publications(snapshot: &crate::Snapshot) -> crate::error::Result<(WorkingPaths, u64)> {
    let mut candidates: std::collections::BTreeMap<String, Option<mneme_core::ContentDigest>> =
        std::collections::BTreeMap::new();
    for record in &snapshot.records {
        if record.kind != mneme_core::RecordKind::SourceRevision {
            continue;
        }
        let Some(retained) = super::portable_retained_source(record)? else {
            continue;
        };
        let Some(path) = record
            .payload
            .get("path-hint")
            .and_then(mneme_core::Value::as_string)
        else {
            continue;
        };
        crate::payload::validate_relative_path(path)?;
        match candidates.entry(path.to_owned()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(Some(retained.digest()));
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if *entry.get() != Some(retained.digest()) {
                    entry.insert(None);
                }
            }
        }
    }
    let total = candidates.len();
    let paths: WorkingPaths = candidates
        .into_iter()
        .filter_map(|(path, digest)| digest.map(|digest| (path, digest)))
        .collect();
    let ambiguous = total.saturating_sub(paths.len()) as u64;
    Ok((paths, ambiguous))
}

/// Verify every imported history, current record, and blob against the archive.
fn verify_restored(
    manifest: &super::PortableManifest,
    workspace: &crate::Workspace,
    snapshot: &crate::Snapshot,
) -> crate::error::Result<()> {
    verify_current(manifest, snapshot)?;
    verify_histories(manifest, workspace, snapshot)?;
    for blob in &manifest.blobs {
        let bytes = crate::payload::read(workspace.root(), blob.digest)?;
        if bytes.len() as u64 != blob.length {
            return Err(crate::error::Failure::CorruptBlob {
                digest: blob.digest.to_hex(),
                reason: "restored source length differs from the archive".to_owned(),
            });
        }
    }
    Ok(())
}

fn verify_current(
    manifest: &super::PortableManifest,
    snapshot: &crate::Snapshot,
) -> crate::error::Result<()> {
    if snapshot.records.len() != manifest.current.len() {
        return Err(crate::error::Failure::PortableArchive(
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
            return Err(crate::error::Failure::PortableArchive(
                "restored workspace is missing one current record".to_owned(),
            ));
        };
        if record.revision_id != expected.revision_id || record.kind != expected.kind {
            return Err(crate::error::Failure::PortableArchive(
                "restored workspace current revision differs from the archive".to_owned(),
            ));
        }
    }
    if !actual_current.is_empty() {
        return Err(crate::error::Failure::PortableArchive(
            "restored workspace holds records the archive did not name".to_owned(),
        ));
    }
    Ok(())
}

fn verify_histories(
    manifest: &super::PortableManifest,
    workspace: &crate::Workspace,
    snapshot: &crate::Snapshot,
) -> crate::error::Result<()> {
    let records: std::collections::BTreeSet<_> = manifest
        .records
        .iter()
        .map(|record| record.record_id)
        .collect();
    let histories = workspace.record_histories_of(snapshot, &records)?;
    for expected in &manifest.records {
        let Some(history) = histories.get(&expected.record_id) else {
            return Err(crate::error::Failure::PortableArchive(
                "restored workspace is missing one record history".to_owned(),
            ));
        };
        if history.len() != expected.revisions.len() {
            return Err(crate::error::Failure::PortableArchive(
                "restored workspace history length differs from the archive".to_owned(),
            ));
        }
        let mut previous = None;
        for (actual, wanted) in history.iter().zip(&expected.revisions) {
            if actual.record_id != wanted.envelope.record_id
                || actual.revision_id != wanted.envelope.revision_id
                || actual.kind != wanted.envelope.kind
                || actual.scope != wanted.envelope.scope
                || actual.schema_version != wanted.envelope.schema_version
                || actual.payload_digest() != wanted.envelope.payload_digest()
            {
                return Err(crate::error::Failure::PortableArchive(
                    "restored record revision differs from the archive".to_owned(),
                ));
            }
            if actual.predecessor != previous {
                return Err(crate::error::Failure::PortableArchive(
                    "restored record revision chain is not contiguous".to_owned(),
                ));
            }
            previous = Some(actual.revision_id);
        }
    }
    Ok(())
}

/// Move the completed staging directory to its final name.
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
fn publish_staging(
    staging: &std::path::Path,
    destination: &std::path::Path,
) -> crate::error::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        staging,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| crate::Failure::io(destination, error.into()))?;
    let parent = destination.parent().map_or_else(
        || std::path::PathBuf::from("."),
        std::path::Path::to_path_buf,
    );
    std::fs::File::open(&parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| crate::Failure::io(&parent, error))?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
fn publish_staging(
    _staging: &std::path::Path,
    _destination: &std::path::Path,
) -> crate::error::Result<()> {
    Err(crate::error::Failure::InvalidCommand(
        "atomic portable restore is not available on this platform".to_owned(),
    ))
}
