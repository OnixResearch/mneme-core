//! Portable revision-bundle export to `iroh-blobs` and fail-closed restore/ingest.

#![allow(
    unknown_lints,
    assertion_density,
    allocation_in_loop,
    unbounded_collection_growth,
    path_segment_repetition,
    fragile_exhaustive_enum_match,
    numeric_units
)] // returns typed Result failures instead of panicking; snapshot record count bounds loop allocations; ExportedSyncBundle matches crate domain; exhaustive match on closed disposition enum

/// Result of exporting one workspace scope into an `iroh-blobs` store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportedSyncBundle {
    pub info: crate::protocol::VaultSnapshotInfo,
    pub archive_hash: iroh_blobs::Hash,
    pub(crate) rbsr_set: crate::rbsr::RbsrSet,
    pub(crate) revisions: std::collections::BTreeMap<
        (mneme_core::RecordId, mneme_core::RevisionId),
        mneme_store::portability::PortableRevision,
    >,
    pub(crate) blobs_by_digest:
        std::collections::BTreeMap<[u8; 32], crate::protocol::BlobDigestRef>,
}

/// Result of verifying and ingesting a downloaded portable revision bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PullDisposition {
    /// Restored into a brand-new workspace directory.
    Restored,
    /// Ingested incremental batches into an existing workspace.
    Updated,
    /// Workspace already held the exact synced revisions and verified blobs.
    AlreadyUpToDate,
}

impl PullDisposition {
    /// Stable lowercase label for JSON and CLI reporting.
    pub const fn symbol(self) -> &'static str {
        match self {
            PullDisposition::Restored => "restored",
            PullDisposition::Updated => "updated",
            PullDisposition::AlreadyUpToDate => "already-up-to-date",
        }
    }
}

/// Export `scope` from `workspace` and load the portable archive, source blobs, and RBSR index.
pub async fn export_scope_to_store(
    workspace: &mneme_store::Workspace,
    vault_id: &str,
    scope: &mneme_core::ScopeId,
    blobs: &iroh_blobs::api::Store,
) -> crate::error::Result<ExportedSyncBundle> {
    let head_revision = workspace.current_revision()?;
    let head_revision_digest = workspace.head_revision_digest()?;
    let sequence = workspace.current_sequence()?;

    let temp_dir = tempfile::tempdir()
        .map_err(|error| crate::error::Failure::Io(format!("export tempdir: {error}")))?;
    let archive_path = temp_dir.path().join("bundle.mneme");
    let export_report = workspace.export_portable(&archive_path, scope)?;

    if export_report.revision != head_revision || export_report.sequence != sequence {
        return Err(crate::error::Failure::Protocol(
            "workspace advanced while exporting sync bundle; retry".to_owned(),
        ));
    }

    let manifest = mneme_store::portability::read_archive_manifest(&archive_path)?;
    let archive_bytes = std::fs::read(&archive_path)
        .map_err(|error| crate::error::Failure::Io(format!("read exported bundle: {error}")))?;
    let archive_len = archive_bytes.len() as u64;
    if archive_len > crate::protocol::MAX_SYNC_BUNDLE_BYTES {
        return Err(crate::error::Failure::SizeLimitExceeded {
            actual_bytes: archive_len,
            limit_bytes: crate::protocol::MAX_SYNC_BUNDLE_BYTES,
        });
    }
    let archive_tag = blobs
        .blobs()
        .add_bytes(archive_bytes)
        .await
        .map_err(|error| crate::error::Failure::Transport(format!("stage bundle blob: {error}")))?;

    let mut rbsr_keys = Vec::new();
    let mut revisions_map = std::collections::BTreeMap::new();
    for record in &manifest.records {
        for revision in &record.revisions {
            let key = (revision.envelope.record_id, revision.envelope.revision_id);
            rbsr_keys.push(crate::rbsr::RbsrKey::from_revision(key.0, key.1));
            revisions_map.insert(key, revision.clone());
        }
    }

    let (blob_refs, blobs_by_digest) =
        export_manifest_blobs(workspace, &manifest.blobs, blobs, &mut rbsr_keys).await?;
    let rbsr_set = crate::rbsr::RbsrSet::from_keys(rbsr_keys);

    let info = crate::protocol::VaultSnapshotInfo {
        vault_id: vault_id.to_owned(),
        scope: scope.to_string(),
        head_revision: head_revision.to_hex(),
        head_revision_digest: crate::protocol::WireDigest::from_digest(head_revision_digest),
        sequence,
        bundle_hash: archive_tag.hash.to_string(),
        bundle_bytes: archive_len,
        blobs: blob_refs,
    };

    Ok(ExportedSyncBundle {
        info,
        archive_hash: archive_tag.hash,
        rbsr_set,
        revisions: revisions_map,
        blobs_by_digest,
    })
}

async fn export_manifest_blobs(
    workspace: &mneme_store::Workspace,
    manifest_blobs: &[mneme_store::portability::PortableBlob],
    blobs: &iroh_blobs::api::Store,
    rbsr_keys: &mut Vec<crate::rbsr::RbsrKey>,
) -> crate::error::Result<(
    Vec<crate::protocol::BlobDigestRef>,
    std::collections::BTreeMap<[u8; 32], crate::protocol::BlobDigestRef>,
)> {
    let mut refs = Vec::with_capacity(manifest_blobs.len());
    let mut by_digest = std::collections::BTreeMap::new();
    for blob in manifest_blobs {
        let bytes = mneme_store::payload::read(workspace.root(), blob.digest)?;
        let byte_length = bytes.len() as u64;
        if byte_length != blob.length {
            return Err(crate::error::Failure::VerificationFailed(format!(
                "source blob {} length {byte_length} differs from manifest {}",
                blob.digest.to_hex(),
                blob.length
            )));
        }
        let tag = blobs.blobs().add_bytes(bytes).await.map_err(|error| {
            crate::error::Failure::Transport(format!("stage source blob: {error}"))
        })?;
        if blob.digest.algorithm() == mneme_core::HashAlgorithm::Blake3
            && tag.hash.as_bytes() != blob.digest.as_bytes()
        {
            return Err(crate::error::Failure::VerificationFailed(
                "iroh-blobs BLAKE3 hash diverged from Mneme ContentDigest".to_owned(),
            ));
        }
        rbsr_keys.push(crate::rbsr::RbsrKey::from_blob_digest(blob.digest));
        let blob_ref = crate::protocol::BlobDigestRef {
            content_digest: crate::protocol::WireDigest::from_digest(blob.digest),
            transport_hash: tag.hash.to_string(),
            byte_length,
        };
        by_digest.insert(*blob.digest.as_bytes(), blob_ref.clone());
        refs.push(blob_ref);
    }
    Ok((refs, by_digest))
}

/// Collect the local workspace's sorted `(revision_id / blob_digest)` RBSR set for `scope`.
pub fn collect_local_rbsr_set(
    workspace: &mneme_store::Workspace,
    scope: &mneme_core::ScopeId,
) -> crate::error::Result<crate::rbsr::RbsrSet> {
    let snapshot = workspace.snapshot()?;
    let scope_records: std::collections::BTreeSet<mneme_core::RecordId> = snapshot
        .records
        .iter()
        .filter(|record| record.scope == *scope)
        .map(|record| record.record_id)
        .collect();
    if scope_records.is_empty() {
        return Ok(crate::rbsr::RbsrSet::new());
    }
    let histories = workspace.record_histories_of(&snapshot, &scope_records)?;
    let mut keys = Vec::new();
    for (record_id, history) in histories {
        for envelope in history {
            if envelope.scope != *scope {
                continue;
            }
            keys.push(crate::rbsr::RbsrKey::from_revision(
                record_id,
                envelope.revision_id,
            ));
            if envelope.kind == mneme_core::RecordKind::SourceRevision {
                append_present_source_key(workspace.root(), &envelope, &mut keys)?;
            }
        }
    }
    Ok(crate::rbsr::RbsrSet::from_keys(keys))
}

fn append_present_source_key(
    workspace_root: &std::path::Path,
    envelope: &mneme_core::RecordEnvelope,
    keys: &mut Vec<crate::rbsr::RbsrKey>,
) -> crate::error::Result<()> {
    let Some(value) = envelope.payload.get("content") else {
        return Ok(());
    };
    let Ok(mneme_core::SourceContent::Retained(retained)) =
        mneme_core::SourceContent::from_value(value, &mneme_core::Path::root())
    else {
        return Ok(());
    };
    if mneme_store::payload::blob_is_present(
        workspace_root,
        retained.digest(),
        retained.byte_length(),
    )? {
        keys.push(crate::rbsr::RbsrKey::from_blob_digest(retained.digest()));
    }
    Ok(())
}

/// Summary returned after restoring/ingesting and verifying a pulled archive or delta.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IngestedWorkspace {
    pub disposition: PullDisposition,
    pub local_revision: mneme_core::WorkspaceRevisionId,
    pub local_sequence: u64,
    pub verify_report: mneme_store::VerifyReport,
}

/// Verify and ingest `archive_path` into `destination`, then run `verify_workspace(Full)`.
pub fn ingest_downloaded_archive(
    archive_path: &std::path::Path,
    destination: &std::path::Path,
    config: mneme_store::WorkspaceConfig,
) -> crate::error::Result<IngestedWorkspace> {
    let (disposition, local_revision, local_sequence) =
        if std::fs::symlink_metadata(destination).is_err() {
            let restored = mneme_store::portability::restore(archive_path, destination, config)?;
            (
                PullDisposition::Restored,
                restored.revision,
                restored.sequence,
            )
        } else {
            let mut workspace = mneme_store::Workspace::open(destination, config)?;
            let ingested = mneme_store::portability::ingest_into(archive_path, &mut workspace)?;
            let disposition = match ingested.status {
                mneme_store::portability::IngestOutcomeStatus::Updated => PullDisposition::Updated,
                mneme_store::portability::IngestOutcomeStatus::AlreadyUpToDate => {
                    PullDisposition::AlreadyUpToDate
                }
            };
            (
                disposition,
                ingested.local_revision,
                ingested.local_sequence,
            )
        };

    let verify_report = mneme_store::verify_workspace(destination, mneme_store::VerifyMode::Full)?;
    if !verify_report.is_healthy() {
        return Err(crate::error::Failure::VerificationFailed(format!(
            "{} integrity issues reported by verify_workspace",
            verify_report.issues.len()
        )));
    }
    Ok(IngestedWorkspace {
        disposition,
        local_revision,
        local_sequence,
        verify_report,
    })
}

/// Verify and ingest an RBSR-isolated delta into `destination`, then run `verify_workspace(Full)`.
pub fn ingest_delta_to_workspace(
    delta: &mneme_store::portability::PortableDelta,
    destination: &std::path::Path,
    config: mneme_store::WorkspaceConfig,
) -> crate::error::Result<IngestedWorkspace> {
    let mut workspace = mneme_store::Workspace::open(destination, config)?;
    let ingested = mneme_store::portability::ingest_delta(delta, &mut workspace)?;
    let disposition = match ingested.status {
        mneme_store::portability::IngestOutcomeStatus::Updated => PullDisposition::Updated,
        mneme_store::portability::IngestOutcomeStatus::AlreadyUpToDate => {
            PullDisposition::AlreadyUpToDate
        }
    };
    drop(workspace);

    let verify_report = mneme_store::verify_workspace(destination, mneme_store::VerifyMode::Full)?;
    if !verify_report.is_healthy() {
        return Err(crate::error::Failure::VerificationFailed(format!(
            "{} integrity issues reported by verify_workspace",
            verify_report.issues.len()
        )));
    }
    Ok(IngestedWorkspace {
        disposition,
        local_revision: ingested.local_revision,
        local_sequence: ingested.local_sequence,
        verify_report,
    })
}
