//! Verified incremental and idempotent ingest of a portable archive into an existing workspace.

#![allow(
    unknown_lints,
    assertion_density,
    allocation_in_loop,
    unbounded_collection_growth,
    path_segment_repetition,
    fragile_exhaustive_enum_match
)] // returns typed Result failures instead of panicking; bounded archive/candidate counts are validated by PortableManifest; *Ingest* matches module domain; exhaustive match on closed two-variant status

const SYNC_INGEST_ACTOR: &str = "iroh-sync";

/// Outcome status of ingesting a verified portable archive into an existing workspace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngestOutcomeStatus {
    /// At least one new batch of revisions was verified and committed.
    Updated,
    /// The workspace already held every revision and verified blob in the archive.
    AlreadyUpToDate,
}

impl IngestOutcomeStatus {
    /// Stable lowercase label for reports and CLI output.
    pub const fn symbol(self) -> &'static str {
        match self {
            IngestOutcomeStatus::Updated => "updated",
            IngestOutcomeStatus::AlreadyUpToDate => "already-up-to-date",
        }
    }
}

/// One verified source blob supplied for delta ingestion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableDeltaBlob {
    pub digest: mneme_core::ContentDigest,
    pub bytes: Vec<u8>,
}

/// Verified incremental revisions and blobs isolated via set reconciliation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableDelta {
    pub scope: mneme_core::ScopeId,
    pub remote_revision: mneme_core::WorkspaceRevisionId,
    pub remote_sequence: u64,
    pub revisions: Vec<super::PortableRevision>,
    pub blobs: Vec<PortableDeltaBlob>,
}

/// Summary of ingesting one verified portable archive into an existing workspace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableIngestReport {
    pub status: IngestOutcomeStatus,
    pub scope: mneme_core::ScopeId,
    pub remote_revision: mneme_core::WorkspaceRevisionId,
    pub remote_sequence: u64,
    pub local_revision: mneme_core::WorkspaceRevisionId,
    pub local_sequence: u64,
    pub batches_applied: u64,
    pub records_committed: u64,
    pub blobs_verified: u64,
    pub publications: Vec<crate::coordinator::PublicationOutcome>,
}

type HistoryMap = std::collections::BTreeMap<mneme_core::RecordId, Vec<mneme_core::RecordEnvelope>>;
type KnownRevisions = std::collections::BTreeSet<(mneme_core::RecordId, mneme_core::RevisionId)>;
type LastRevisions = std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RevisionId>;

enum BlobLookup<'a> {
    Archive(&'a super::file::ArchiveReader),
    Delta {
        blobs: &'a std::collections::BTreeMap<[u8; 32], &'a [u8]>,
        workspace_root: &'a std::path::Path,
    },
}

impl BlobLookup<'_> {
    fn read_blob(&self, digest: mneme_core::ContentDigest) -> crate::error::Result<Vec<u8>> {
        match self {
            BlobLookup::Archive(archive) => archive.blob(digest),
            BlobLookup::Delta {
                blobs,
                workspace_root,
            } => {
                if let Some(bytes) = blobs.get(digest.as_bytes()) {
                    return Ok((*bytes).to_vec());
                }
                crate::payload::read(workspace_root, digest)
            }
        }
    }
}

struct IngestContext<'a> {
    scope: &'a mneme_core::ScopeId,
    remote_revision: mneme_core::WorkspaceRevisionId,
    blobs: &'a BlobLookup<'a>,
}

/// Verify `archive` and ingest any missing batches for its scope into `workspace`.
///
/// Existing records in `manifest.scope` must be an exact prefix of the
/// archive's retained history for each record. Re-ingesting an already-applied
/// archive is idempotent and performs no commits.
pub fn ingest_into(
    archive: &std::path::Path,
    workspace: &mut crate::Workspace,
) -> crate::error::Result<PortableIngestReport> {
    let mut archive = super::file::ArchiveReader::verify(archive)?;
    let scope = archive.manifest.scope.clone();
    let remote_revision = archive.manifest.revision;
    let remote_sequence = archive.manifest.sequence;
    let blobs_verified = archive.manifest.blobs.len() as u64;
    let snapshot = workspace.snapshot()?;
    let existing = load_existing_histories(workspace, &snapshot, &archive.manifest)?;
    let (known, mut last_committed) = check_history_prefixes(&archive.manifest, &existing)?;
    let previous_paths = existing_publication_digests(&snapshot)?;

    if workspace.current_sequence()? == 0 {
        workspace.install_portable_retention(
            &scope,
            &super::PortableRetentionState {
                generation: archive.manifest.generation,
                suppressions: archive.manifest.suppressions.clone(),
                prunings: archive.manifest.prunings.clone(),
            },
        )?;
    }

    let ordered = super::ordered_revisions(&archive.manifest.records);
    let lookup = BlobLookup::Archive(&archive);
    let ctx = IngestContext {
        scope: &scope,
        remote_revision,
        blobs: &lookup,
    };
    let (batches_applied, records_committed) =
        apply_missing_batches(&ctx, &ordered, workspace, &known, &mut last_committed)?;
    let updated_snapshot = if batches_applied == 0 {
        snapshot
    } else {
        workspace.snapshot()?
    };

    verify_scope_state(&archive.manifest, workspace, &updated_snapshot)?;
    let publications = if batches_applied == 0 {
        Vec::new()
    } else {
        publish_new_working_files(&ctx, workspace, &updated_snapshot, &previous_paths)?
    };
    archive.recheck()?;

    let status = if batches_applied == 0 {
        IngestOutcomeStatus::AlreadyUpToDate
    } else {
        IngestOutcomeStatus::Updated
    };
    Ok(PortableIngestReport {
        status,
        scope,
        remote_revision,
        remote_sequence,
        local_revision: workspace.current_revision()?,
        local_sequence: workspace.current_sequence()?,
        batches_applied,
        records_committed,
        blobs_verified,
        publications,
    })
}

/// Verify and ingest an RBSR-isolated delta of revisions and source blobs into `workspace`.
pub fn ingest_delta(
    delta: &PortableDelta,
    workspace: &mut crate::Workspace,
) -> crate::error::Result<PortableIngestReport> {
    if workspace.current_sequence()? == 0 {
        return Err(crate::error::Failure::PortableArchive(
            "delta ingest requires an initialized workspace with sequence > 0".to_owned(),
        ));
    }
    let blob_map = validate_delta_blobs(&delta.blobs)?;
    validate_delta_revisions(&delta.scope, &delta.revisions)?;

    let snapshot = workspace.snapshot()?;
    let existing = load_delta_existing_histories(delta, workspace, &snapshot)?;
    let (known, mut last_committed) = check_delta_prefixes(&delta.revisions, &existing)?;
    let previous_paths = existing_publication_digests(&snapshot)?;

    let mut ordered: Vec<&super::PortableRevision> = delta.revisions.iter().collect();
    ordered
        .sort_unstable_by_key(|revision| (revision.commit.sequence, revision.envelope.record_id));

    let workspace_root = workspace.root().to_path_buf();
    let lookup = BlobLookup::Delta {
        blobs: &blob_map,
        workspace_root: &workspace_root,
    };
    let ctx = IngestContext {
        scope: &delta.scope,
        remote_revision: delta.remote_revision,
        blobs: &lookup,
    };
    let (batches_applied, records_committed) =
        apply_missing_batches(&ctx, &ordered, workspace, &known, &mut last_committed)?;

    let updated_snapshot = if batches_applied == 0 {
        snapshot
    } else {
        workspace.snapshot()?
    };
    stage_self_healed_blobs(delta, workspace, &updated_snapshot)?;
    verify_delta_state(delta, &existing, workspace, &updated_snapshot)?;

    let publications = if batches_applied == 0 {
        Vec::new()
    } else {
        publish_new_working_files(&ctx, workspace, &updated_snapshot, &previous_paths)?
    };
    let status = if batches_applied == 0 {
        IngestOutcomeStatus::AlreadyUpToDate
    } else {
        IngestOutcomeStatus::Updated
    };
    Ok(PortableIngestReport {
        status,
        scope: delta.scope.clone(),
        remote_revision: delta.remote_revision,
        remote_sequence: delta.remote_sequence,
        local_revision: workspace.current_revision()?,
        local_sequence: workspace.current_sequence()?,
        batches_applied,
        records_committed,
        blobs_verified: delta.blobs.len() as u64,
        publications,
    })
}

fn load_delta_existing_histories(
    delta: &PortableDelta,
    workspace: &crate::Workspace,
    snapshot: &crate::Snapshot,
) -> crate::error::Result<HistoryMap> {
    let delta_record_ids: std::collections::BTreeSet<_> = delta
        .revisions
        .iter()
        .map(|revision| revision.envelope.record_id)
        .collect();
    if delta_record_ids.is_empty() {
        return Ok(std::collections::BTreeMap::new());
    }
    workspace.record_histories_of(snapshot, &delta_record_ids)
}

fn validate_delta_blobs(
    blobs: &[PortableDeltaBlob],
) -> crate::error::Result<std::collections::BTreeMap<[u8; 32], &[u8]>> {
    let mut map: std::collections::BTreeMap<[u8; 32], &[u8]> = std::collections::BTreeMap::new();
    for blob in blobs {
        if blob.bytes.len() as u64 > super::MAX_PORTABLE_BLOB_BYTES {
            return Err(crate::error::Failure::HistoryLimitExceeded);
        }
        if mneme_core::ContentDigest::of_source_bytes_with(&blob.bytes, blob.digest.algorithm())
            != blob.digest
        {
            return Err(crate::error::Failure::CorruptBlob {
                digest: blob.digest.to_hex(),
                reason: "delta blob bytes do not match their declared digest".to_owned(),
            });
        }
        if let Some(existing) = map.insert(*blob.digest.as_bytes(), blob.bytes.as_slice())
            && existing != blob.bytes.as_slice()
        {
            return Err(crate::error::Failure::PortableArchive(
                "delta repeats one source digest with different bytes".to_owned(),
            ));
        }
    }
    Ok(map)
}

fn validate_delta_revisions(
    scope: &mneme_core::ScopeId,
    revisions: &[super::PortableRevision],
) -> crate::error::Result<()> {
    if revisions.len() > super::MAX_PORTABLE_REVISIONS {
        return Err(crate::error::Failure::HistoryLimitExceeded);
    }
    let registry = mneme_core::SchemaRegistry::production();
    let mut seen = std::collections::BTreeSet::new();
    for revision in revisions {
        if revision.envelope.scope != *scope {
            return Err(crate::error::Failure::PortableArchive(
                "delta revision belongs to a different scope".to_owned(),
            ));
        }
        if !seen.insert((revision.envelope.record_id, revision.envelope.revision_id)) {
            return Err(crate::error::Failure::PortableArchive(
                "delta repeats one record revision".to_owned(),
            ));
        }
        mneme_core::validate_record_value(&revision.envelope.to_value(), &registry, None).map_err(
            |diagnostics| {
                crate::error::Failure::PortableArchive(format!(
                    "delta revision failed schema validation: {}",
                    mneme_core::render_diagnostics(&diagnostics)
                ))
            },
        )?;
    }
    Ok(())
}

fn check_delta_prefixes(
    revisions: &[super::PortableRevision],
    existing: &HistoryMap,
) -> crate::error::Result<(KnownRevisions, LastRevisions)> {
    let mut known = std::collections::BTreeSet::new();
    let mut last_committed = std::collections::BTreeMap::new();
    let mut by_key: std::collections::BTreeMap<
        (mneme_core::RecordId, mneme_core::RevisionId),
        &mneme_core::RecordEnvelope,
    > = std::collections::BTreeMap::new();
    for (record_id, history) in existing {
        for envelope in history {
            known.insert((envelope.record_id, envelope.revision_id));
            last_committed.insert(*record_id, envelope.revision_id);
            by_key.insert((envelope.record_id, envelope.revision_id), envelope);
        }
    }
    for wanted in revisions {
        let key = (wanted.envelope.record_id, wanted.envelope.revision_id);
        if let Some(actual) = by_key.get(&key)
            && !same_revision_content(actual, &wanted.envelope)
        {
            return Err(crate::error::Failure::PortableArchive(
                "destination workspace history conflicts with the pulled delta".to_owned(),
            ));
        }
    }
    Ok((known, last_committed))
}

fn stage_self_healed_blobs(
    delta: &PortableDelta,
    workspace: &crate::Workspace,
    snapshot: &crate::Snapshot,
) -> crate::error::Result<()> {
    let mut missing = Vec::new();
    for blob in &delta.blobs {
        if !crate::payload::blob_is_present(workspace.root(), blob.digest, blob.bytes.len() as u64)?
        {
            missing.push(blob);
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    let mut allowed_digests = std::collections::BTreeSet::new();
    for record in &snapshot.records {
        if record.scope == delta.scope
            && let Some(retained) = super::portable_retained_source(record)?
        {
            allowed_digests.insert(*retained.digest().as_bytes());
        }
    }
    let histories = workspace.record_histories(snapshot)?;
    for history in histories.values() {
        for envelope in history {
            if envelope.scope == delta.scope
                && let Some(retained) = super::portable_retained_source(envelope)?
            {
                allowed_digests.insert(*retained.digest().as_bytes());
            }
        }
    }
    for blob in missing {
        if !allowed_digests.contains(blob.digest.as_bytes()) {
            return Err(crate::error::Failure::PortableArchive(
                "delta supplied an unreferenced source blob".to_owned(),
            ));
        }
        let _ = crate::payload::stage(workspace.root(), blob.digest, &blob.bytes)?;
    }
    Ok(())
}

fn verify_delta_state(
    delta: &PortableDelta,
    prior_existing: &HistoryMap,
    workspace: &crate::Workspace,
    snapshot: &crate::Snapshot,
) -> crate::error::Result<()> {
    let mut expected_by_record: std::collections::BTreeMap<
        mneme_core::RecordId,
        Vec<mneme_core::RecordEnvelope>,
    > = std::collections::BTreeMap::new();
    let mut delta_grouped: std::collections::BTreeMap<
        mneme_core::RecordId,
        Vec<&super::PortableRevision>,
    > = std::collections::BTreeMap::new();
    for revision in &delta.revisions {
        delta_grouped
            .entry(revision.envelope.record_id)
            .or_default()
            .push(revision);
    }
    for (record_id, mut revisions) in delta_grouped {
        revisions.sort_unstable_by_key(|revision| revision.commit.sequence);
        let mut combined = prior_existing.get(&record_id).cloned().unwrap_or_default();
        for revision in revisions {
            if !combined
                .iter()
                .any(|existing| existing.revision_id == revision.envelope.revision_id)
            {
                combined.push(revision.envelope.clone());
            }
        }
        expected_by_record.insert(record_id, combined);
    }
    let record_ids: std::collections::BTreeSet<_> = expected_by_record.keys().copied().collect();
    if !record_ids.is_empty() {
        let actual_histories = workspace.record_histories_of(snapshot, &record_ids)?;
        for (record_id, expected) in &expected_by_record {
            let Some(actual) = actual_histories.get(record_id) else {
                return Err(crate::error::Failure::PortableArchive(
                    "synced workspace is missing one record history".to_owned(),
                ));
            };
            if actual.len() != expected.len() {
                return Err(crate::error::Failure::PortableArchive(
                    "synced workspace history length differs from the delta".to_owned(),
                ));
            }
            let mut previous = None;
            for (actual_env, wanted_env) in actual.iter().zip(expected) {
                if !same_revision_content(actual_env, wanted_env) {
                    return Err(crate::error::Failure::PortableArchive(
                        "synced record revision differs from the delta".to_owned(),
                    ));
                }
                if actual_env.predecessor != previous {
                    return Err(crate::error::Failure::PortableArchive(
                        "synced record revision chain is not contiguous".to_owned(),
                    ));
                }
                previous = Some(actual_env.revision_id);
            }
        }
    }
    for blob in &delta.blobs {
        crate::payload::verify(workspace.root(), blob.digest, blob.bytes.len() as u64)?;
    }
    Ok(())
}

fn load_existing_histories(
    workspace: &crate::Workspace,
    snapshot: &crate::Snapshot,
    manifest: &super::PortableManifest,
) -> crate::error::Result<HistoryMap> {
    let record_ids: std::collections::BTreeSet<_> = manifest
        .records
        .iter()
        .map(|record| record.record_id)
        .collect();
    if record_ids.is_empty() {
        return Ok(std::collections::BTreeMap::new());
    }
    workspace.record_histories_of(snapshot, &record_ids)
}

fn check_history_prefixes(
    manifest: &super::PortableManifest,
    existing: &HistoryMap,
) -> crate::error::Result<(KnownRevisions, LastRevisions)> {
    let mut known = std::collections::BTreeSet::new();
    let mut last_committed = std::collections::BTreeMap::new();
    for expected in &manifest.records {
        let Some(local_history) = existing.get(&expected.record_id) else {
            continue;
        };
        if local_history.len() > expected.revisions.len() {
            return Err(crate::error::Failure::PortableArchive(
                "destination workspace has revisions ahead of the pulled bundle".to_owned(),
            ));
        }
        for (actual, wanted) in local_history.iter().zip(&expected.revisions) {
            if !same_revision_content(actual, &wanted.envelope) {
                return Err(crate::error::Failure::PortableArchive(
                    "destination workspace history conflicts with the pulled bundle".to_owned(),
                ));
            }
            known.insert((actual.record_id, actual.revision_id));
            last_committed.insert(actual.record_id, actual.revision_id);
        }
    }
    Ok((known, last_committed))
}

fn same_revision_content(
    actual: &mneme_core::RecordEnvelope,
    wanted: &mneme_core::RecordEnvelope,
) -> bool {
    actual.record_id == wanted.record_id
        && actual.revision_id == wanted.revision_id
        && actual.kind == wanted.kind
        && actual.scope == wanted.scope
        && actual.schema_version == wanted.schema_version
        && actual.payload_digest() == wanted.payload_digest()
}

fn apply_missing_batches(
    ctx: &IngestContext<'_>,
    ordered: &[&super::PortableRevision],
    workspace: &mut crate::Workspace,
    known: &KnownRevisions,
    last_committed: &mut LastRevisions,
) -> crate::error::Result<(u64, u64)> {
    let mut batches_applied = 0_u64;
    let mut records_committed = 0_u64;
    for entries in ordered.chunk_by(super::same_batch) {
        let present = entries
            .iter()
            .filter(|revision| {
                known.contains(&(revision.envelope.record_id, revision.envelope.revision_id))
            })
            .count();
        if present == entries.len() {
            continue;
        }
        if present != 0 {
            return Err(crate::error::Failure::PortableArchive(
                "destination workspace holds only part of a pulled commit batch".to_owned(),
            ));
        }
        commit_sync_batch(ctx, workspace, entries, last_committed)?;
        batches_applied = batches_applied.saturating_add(1);
        records_committed = records_committed.saturating_add(entries.len() as u64);
    }
    Ok((batches_applied, records_committed))
}

fn commit_sync_batch(
    ctx: &IngestContext<'_>,
    workspace: &mut crate::Workspace,
    entries: &[&super::PortableRevision],
    last_committed: &mut LastRevisions,
) -> crate::error::Result<()> {
    let sequence = entries[0].commit.sequence;
    let mut records = Vec::with_capacity(entries.len());
    let mut drafts = Vec::with_capacity(entries.len());
    for revision in entries {
        let envelope = &revision.envelope;
        let predecessor = last_committed.insert(envelope.record_id, envelope.revision_id);
        drafts.push((envelope, predecessor));
    }
    for (envelope, predecessor) in drafts {
        records.push(crate::RecordDraft {
            schema_version: envelope.schema_version,
            kind: envelope.kind,
            record_id: envelope.record_id,
            revision_id: envelope.revision_id,
            predecessor,
            scope: envelope.scope.clone(),
            payload: envelope.payload.clone(),
        });
    }
    workspace.commit(crate::CommitCommand {
        base: workspace.current_revision()?,
        actor: SYNC_INGEST_ACTOR.to_owned(),
        scope: ctx.scope.clone(),
        idempotency_key: format!(
            "iroh-sync:commit:{}:{sequence}",
            ctx.remote_revision.to_hex()
        ),
        records,
        source_blobs: source_blobs(ctx.blobs, entries)?,
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: None,
    })?;
    Ok(())
}

fn source_blobs(
    blobs: &BlobLookup<'_>,
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
    sources
        .into_values()
        .map(|retained| {
            let bytes = blobs.read_blob(retained.digest())?;
            if bytes.len() as u64 != retained.byte_length() {
                return Err(crate::error::Failure::CorruptBlob {
                    digest: retained.digest().to_hex(),
                    reason: "archive source length does not match its record".to_owned(),
                });
            }
            Ok(crate::SourceBlobDraft {
                bytes,
                media_type: retained.media_type().clone(),
            })
        })
        .collect()
}

fn verify_scope_state(
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
                "synced workspace is missing one record history".to_owned(),
            ));
        };
        if history.len() != expected.revisions.len() {
            return Err(crate::error::Failure::PortableArchive(
                "synced workspace history length differs from the archive".to_owned(),
            ));
        }
        let mut previous = None;
        for (actual, wanted) in history.iter().zip(&expected.revisions) {
            if !same_revision_content(actual, &wanted.envelope) {
                return Err(crate::error::Failure::PortableArchive(
                    "synced record revision differs from the archive".to_owned(),
                ));
            }
            if actual.predecessor != previous {
                return Err(crate::error::Failure::PortableArchive(
                    "synced record revision chain is not contiguous".to_owned(),
                ));
            }
            previous = Some(actual.revision_id);
        }
    }
    for blob in &manifest.blobs {
        crate::payload::verify(workspace.root(), blob.digest, blob.length)?;
    }
    Ok(())
}

type WorkingPaths = std::collections::BTreeMap<String, mneme_core::ContentDigest>;

fn current_publications(snapshot: &crate::Snapshot) -> crate::error::Result<WorkingPaths> {
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
    Ok(candidates
        .into_iter()
        .filter_map(|(path, digest)| digest.map(|digest| (path, digest)))
        .collect())
}

fn existing_publication_digests(
    snapshot: &crate::Snapshot,
) -> crate::error::Result<std::collections::BTreeMap<String, mneme_core::ContentDigest>> {
    current_publications(snapshot)
}

fn publish_new_working_files(
    ctx: &IngestContext<'_>,
    workspace: &mut crate::Workspace,
    snapshot: &crate::Snapshot,
    previous_paths: &std::collections::BTreeMap<String, mneme_core::ContentDigest>,
) -> crate::error::Result<Vec<crate::coordinator::PublicationOutcome>> {
    let candidates = current_publications(snapshot)?;
    let working_dir = crate::payload::working_directory(workspace.root())?;
    let mut outcomes = Vec::with_capacity(candidates.len());
    let mut pending_publishes = Vec::with_capacity(candidates.len());
    for (index, (path, digest)) in candidates.into_iter().enumerate() {
        let target = working_dir.join(&path);
        let expected_previous = match std::fs::read(&target) {
            Ok(existing_bytes) => {
                let existing_digest = mneme_core::ContentDigest::of_source_bytes_with(
                    &existing_bytes,
                    digest.algorithm(),
                );
                if existing_digest == digest {
                    continue;
                }
                previous_paths.get(&path).copied()
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(crate::Failure::io(&target, error)),
        };
        pending_publishes.push((index, path, digest, expected_previous));
    }
    for (index, path, digest, expected_previous) in pending_publishes {
        let bytes = ctx.blobs.read_blob(digest)?;
        let published = workspace.commit(crate::CommitCommand {
            base: workspace.current_revision()?,
            actor: SYNC_INGEST_ACTOR.to_owned(),
            scope: ctx.scope.clone(),
            idempotency_key: format!("iroh-sync:publish:{}:{index}", ctx.remote_revision.to_hex()),
            records: Vec::new(),
            source_blobs: Vec::new(),
            publications: vec![crate::PublicationDraft {
                path,
                expected_previous,
                bytes,
            }],
            import_candidates: Vec::new(),
            retention: None,
        })?;
        outcomes.extend(published.publications);
    }
    Ok(outcomes)
}
