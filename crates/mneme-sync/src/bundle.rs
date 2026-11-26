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

/// Export `scope` from `workspace` and load the portable archive and source blobs into `blobs`.
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

    let blob_refs = export_source_blobs(workspace, scope, blobs).await?;
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
    })
}

async fn export_source_blobs(
    workspace: &mneme_store::Workspace,
    scope: &mneme_core::ScopeId,
    blobs: &iroh_blobs::api::Store,
) -> crate::error::Result<Vec<crate::protocol::BlobDigestRef>> {
    let snapshot = workspace.snapshot()?;
    let mut seen = std::collections::BTreeSet::new();
    let mut refs = Vec::new();
    for record in &snapshot.records {
        if record.scope != *scope || record.kind != mneme_core::RecordKind::SourceRevision {
            continue;
        }
        let Some(value) = record.payload.get("content") else {
            continue;
        };
        let Ok(mneme_core::SourceContent::Retained(retained)) =
            mneme_core::SourceContent::from_value(value, &mneme_core::Path::root())
        else {
            continue;
        };
        let digest = retained.digest();
        if !seen.insert(*digest.as_bytes()) {
            continue;
        }
        let bytes = mneme_store::payload::read(workspace.root(), digest)?;
        let byte_length = bytes.len() as u64;
        let tag = blobs.blobs().add_bytes(bytes).await.map_err(|error| {
            crate::error::Failure::Transport(format!("stage source blob: {error}"))
        })?;
        if digest.algorithm() == mneme_core::HashAlgorithm::Blake3
            && tag.hash.as_bytes() != digest.as_bytes()
        {
            return Err(crate::error::Failure::VerificationFailed(
                "iroh-blobs BLAKE3 hash diverged from Mneme ContentDigest".to_owned(),
            ));
        }
        refs.push(crate::protocol::BlobDigestRef {
            content_digest: crate::protocol::WireDigest::from_digest(digest),
            transport_hash: tag.hash.to_string(),
            byte_length,
        });
    }
    Ok(refs)
}

/// Summary returned after restoring/ingesting and verifying a pulled archive.
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
