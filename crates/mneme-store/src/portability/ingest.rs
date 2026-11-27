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

/// Verified incremental revisions, blobs, and retention barriers isolated via set reconciliation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableDelta {
    pub scope: mneme_core::ScopeId,
    pub remote_revision: mneme_core::WorkspaceRevisionId,
    pub remote_sequence: u64,
    pub revisions: Vec<super::PortableRevision>,
    pub blobs: Vec<PortableDeltaBlob>,
    pub retention: Option<super::PortableRetentionState>,
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
/// Retention barriers (`PortableRetentionState`) are unconditionally merged
/// *before* applying records at any `sequence >= 0` so forgotten records are
/// never resurrected across peers. Existing retained records in `manifest.scope`
/// must be an exact prefix of the archive's non-forgotten history for each
/// record. Re-ingesting an already-applied archive is idempotent and performs no
/// commits.
pub fn ingest_into(
    archive: &std::path::Path,
    workspace: &mut crate::Workspace,
) -> crate::error::Result<PortableIngestReport> {
    let mut archive = super::file::ArchiveReader::verify(archive)?;
    let scope = archive.manifest.scope.clone();
    let remote_revision = archive.manifest.revision;
    let remote_sequence = archive.manifest.sequence;
    let blobs_verified = archive.manifest.blobs.len() as u64;

    // Barrier-first CALM Stratum M merge: install/strengthen suppressions and
    // eligibility barriers BEFORE reading or applying any records at any sequence.
    let retention_changed = workspace.merge_portable_retention(
        &scope,
        &super::PortableRetentionState {
            generation: archive.manifest.generation,
            suppressions: archive.manifest.suppressions.clone(),
            prunings: archive.manifest.prunings.clone(),
            key_punctures: Vec::new(),
        },
    )?;

    let forgotten = workspace.forgotten_filter(&scope)?;
    let eligible_records = filter_eligible_manifest_records(&archive.manifest.records, &forgotten)?;
    let snapshot = workspace.snapshot()?;
    let existing = load_existing_histories(workspace, &snapshot, &eligible_records)?;
    let (known, mut last_committed) = check_history_prefixes(&eligible_records, &existing)?;
    let previous_paths = existing_publication_digests(&snapshot)?;

    let mut ordered = super::ordered_revisions(&eligible_records);
    sort_revisions_causally(&mut ordered);
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

    verify_scope_state(
        &eligible_records,
        &archive.manifest.blobs,
        &forgotten,
        workspace,
        &updated_snapshot,
    )?;
    let publications = if batches_applied == 0 {
        Vec::new()
    } else {
        publish_new_working_files(&ctx, workspace, &updated_snapshot, &previous_paths)?
    };
    archive.recheck()?;

    let status = if batches_applied == 0 && !retention_changed {
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

/// Verify and ingest an RBSR-isolated delta of revisions, blobs, and retention
/// barriers into `workspace`.
///
/// Any supplied [`PortableDelta::retention`] state is unconditionally merged
/// *before* applying records, and revisions matching active `Forgotten`
/// suppressions are skipped so concurrent forget + append converges without
/// resurrecting forgotten records.
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

    // Barrier-first CALM Stratum M merge BEFORE reading or applying any records.
    let retention_changed = if let Some(retention) = &delta.retention {
        workspace.merge_portable_retention(&delta.scope, retention)?
    } else {
        false
    };

    let forgotten = workspace.forgotten_filter(&delta.scope)?;
    let eligible_revisions = filter_eligible_delta_revisions(&delta.revisions, &forgotten)?;
    let snapshot = workspace.snapshot()?;
    let existing = load_delta_existing_histories(&eligible_revisions, workspace, &snapshot)?;
    let (known, _last_committed) = check_delta_prefixes(&eligible_revisions, &existing)?;
    let previous_paths = existing_publication_digests(&snapshot)?;
    let ordered = sort_revisions_topologically(&eligible_revisions, &known)?;
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
        apply_merkle_delta_batches(&ctx, &ordered, workspace, &known)?;
    let updated_snapshot = if batches_applied == 0 {
        snapshot
    } else {
        workspace.snapshot()?
    };
    stage_self_healed_blobs(delta, &forgotten, workspace, &updated_snapshot)?;
    verify_delta_state(
        delta,
        &eligible_revisions,
        &forgotten,
        &existing,
        workspace,
        &updated_snapshot,
    )?;
    let publications = if batches_applied == 0 {
        Vec::new()
    } else {
        publish_new_working_files(&ctx, workspace, &updated_snapshot, &previous_paths)?
    };
    let status = if batches_applied == 0 && !retention_changed {
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

fn filter_eligible_delta_revisions<'a>(
    revisions: &'a [super::PortableRevision],
    forgotten: &crate::coordinator::custody::ForgottenFilter,
) -> crate::error::Result<Vec<&'a super::PortableRevision>> {
    let mut eligible = Vec::with_capacity(revisions.len());
    for revision in revisions {
        if !forgotten.matches_revision(revision)? {
            eligible.push(revision);
        }
    }
    Ok(eligible)
}

fn sort_revisions_causally(revisions: &mut [&super::PortableRevision]) {
    revisions.sort_unstable_by_key(|revision| {
        let hlc_key = revision
            .commit
            .hlc
            .map(|ts| (0_u8, ts.physical_ns, ts.logical))
            .unwrap_or((1_u8, 0, 0));
        (
            hlc_key,
            revision.commit.sequence,
            revision.commit.revision,
            revision.envelope.record_id,
            revision.envelope.revision_id,
        )
    });
}

fn sort_revisions_topologically<'a>(
    revisions: &[&'a super::PortableRevision],
    known: &KnownRevisions,
) -> crate::error::Result<Vec<&'a super::PortableRevision>> {
    let mut remaining: Vec<&'a super::PortableRevision> = revisions.to_vec();
    sort_revisions_causally(&mut remaining);
    let mut available = known.clone();
    let mut ordered = Vec::with_capacity(remaining.len());
    let max_rounds = remaining.len().saturating_add(1);
    for _ in 0..max_rounds {
        if remaining.is_empty() {
            return Ok(ordered);
        }
        let mut next_remaining = Vec::with_capacity(remaining.len());
        let mut has_progressed = false;
        for revision in remaining {
            let key = (revision.envelope.record_id, revision.envelope.revision_id);
            if available.contains(&key) {
                ordered.push(revision);
                has_progressed = true;
                continue;
            }
            let are_parents_ready = revision
                .envelope
                .parents()
                .iter()
                .all(|parent| available.contains(&(revision.envelope.record_id, *parent)));
            if are_parents_ready {
                available.insert(key);
                ordered.push(revision);
                has_progressed = true;
            } else {
                next_remaining.push(revision);
            }
        }
        if !has_progressed {
            return Err(crate::error::Failure::PortableArchive(
                "Merkle-CRDT delta contains revisions with missing or cyclic causal parents"
                    .to_owned(),
            ));
        }
        remaining = next_remaining;
    }
    Ok(ordered)
}

fn filter_eligible_manifest_records(
    records: &[super::PortableRecord],
    forgotten: &crate::coordinator::custody::ForgottenFilter,
) -> crate::error::Result<Vec<super::PortableRecord>> {
    let mut eligible = Vec::with_capacity(records.len());
    for record in records {
        if forgotten.matches_record_id(record.record_id) {
            continue;
        }
        let mut kept = Vec::with_capacity(record.revisions.len());
        for revision in &record.revisions {
            if !forgotten.matches_revision(revision)? {
                kept.push(revision.clone());
            }
        }
        if !kept.is_empty() {
            eligible.push(super::PortableRecord {
                record_id: record.record_id,
                scope: record.scope.clone(),
                revisions: kept,
            });
        }
    }
    Ok(eligible)
}

fn load_delta_existing_histories(
    revisions: &[&super::PortableRevision],
    workspace: &crate::Workspace,
    snapshot: &crate::Snapshot,
) -> crate::error::Result<HistoryMap> {
    let delta_record_ids: std::collections::BTreeSet<_> = revisions
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
    revisions: &[&super::PortableRevision],
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
    forgotten: &crate::coordinator::custody::ForgottenFilter,
    workspace: &crate::Workspace,
    snapshot: &crate::Snapshot,
) -> crate::error::Result<()> {
    let mut missing = Vec::new();
    for blob in &delta.blobs {
        if forgotten.matches_digest(blob.digest) {
            continue;
        }
        if !crate::payload::blob_is_present(workspace.root(), blob.digest, blob.bytes.len() as u64)?
        {
            missing.push(blob);
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    let mut allowed_digests: std::collections::BTreeMap<[u8; 32], mneme_core::Symbol> =
        std::collections::BTreeMap::new();
    for record in &snapshot.records {
        if record.scope == delta.scope
            && let Some(retained) = super::portable_retained_source(record)?
        {
            allowed_digests.insert(*retained.digest().as_bytes(), retained.media_type().clone());
        }
    }
    let histories = workspace.record_histories(snapshot)?;
    for history in histories.values() {
        for envelope in history {
            if envelope.scope == delta.scope
                && let Some(retained) = super::portable_retained_source(envelope)?
            {
                allowed_digests
                    .insert(*retained.digest().as_bytes(), retained.media_type().clone());
            }
        }
    }
    let policy = workspace.storage_policy();
    for blob in missing {
        let Some(media_type) = allowed_digests.get(blob.digest.as_bytes()) else {
            return Err(crate::error::Failure::PortableArchive(
                "delta supplied an unreferenced source blob".to_owned(),
            ));
        };
        let _ = crate::payload::stage_with_policy(
            workspace.root(),
            blob.digest,
            &blob.bytes,
            policy,
            media_type.as_str(),
        )?;
    }
    Ok(())
}

fn verify_delta_state(
    delta: &PortableDelta,
    eligible_revisions: &[&super::PortableRevision],
    forgotten: &crate::coordinator::custody::ForgottenFilter,
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
    for revision in eligible_revisions {
        delta_grouped
            .entry(revision.envelope.record_id)
            .or_default()
            .push(*revision);
    }
    for (record_id, mut revisions) in delta_grouped {
        sort_revisions_causally(&mut revisions);
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
            verify_record_delta_history(actual_histories.get(record_id), expected)?;
        }
    }
    for blob in &delta.blobs {
        if forgotten.matches_digest(blob.digest) {
            continue;
        }
        crate::payload::verify(workspace.root(), blob.digest, blob.bytes.len() as u64)?;
    }
    Ok(())
}

fn verify_record_delta_history(
    actual: Option<&Vec<mneme_core::RecordEnvelope>>,
    expected: &[mneme_core::RecordEnvelope],
) -> crate::error::Result<()> {
    let Some(actual) = actual else {
        return Err(crate::error::Failure::PortableArchive(
            "synced workspace is missing one record history".to_owned(),
        ));
    };
    if actual.len() != expected.len() {
        return Err(crate::error::Failure::PortableArchive(
            "synced workspace history length differs from the delta".to_owned(),
        ));
    }
    let actual_by_rev: std::collections::BTreeMap<
        mneme_core::RevisionId,
        &mneme_core::RecordEnvelope,
    > = actual
        .iter()
        .map(|envelope| (envelope.revision_id, envelope))
        .collect();
    for wanted_env in expected {
        let Some(actual_env) = actual_by_rev.get(&wanted_env.revision_id) else {
            return Err(crate::error::Failure::PortableArchive(
                "synced workspace is missing one delta revision".to_owned(),
            ));
        };
        if !same_revision_content(actual_env, wanted_env) {
            return Err(crate::error::Failure::PortableArchive(
                "synced record revision differs from the delta".to_owned(),
            ));
        }
        if actual_env.parents() != wanted_env.parents() {
            return Err(crate::error::Failure::PortableArchive(
                "synced record causal parents were altered during ingest".to_owned(),
            ));
        }
    }
    Ok(())
}

fn load_existing_histories(
    workspace: &crate::Workspace,
    snapshot: &crate::Snapshot,
    records: &[super::PortableRecord],
) -> crate::error::Result<HistoryMap> {
    let record_ids: std::collections::BTreeSet<_> =
        records.iter().map(|record| record.record_id).collect();
    if record_ids.is_empty() {
        return Ok(std::collections::BTreeMap::new());
    }
    workspace.record_histories_of(snapshot, &record_ids)
}

fn check_history_prefixes(
    records: &[super::PortableRecord],
    existing: &HistoryMap,
) -> crate::error::Result<(KnownRevisions, LastRevisions)> {
    let mut known = std::collections::BTreeSet::new();
    let mut last_committed = std::collections::BTreeMap::new();
    for expected in records {
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

fn apply_merkle_delta_batches(
    ctx: &IngestContext<'_>,
    ordered: &[&super::PortableRevision],
    workspace: &mut crate::Workspace,
    known: &KnownRevisions,
) -> crate::error::Result<(u64, u64)> {
    let mut batches_applied = 0_u64;
    let mut records_committed = 0_u64;
    let mut committed_keys = known.clone();
    let mut batch_ordinal = 0_u64;
    for entries in ordered.chunk_by(super::same_batch) {
        let missing: Vec<&super::PortableRevision> = entries
            .iter()
            .copied()
            .filter(|revision| {
                !committed_keys
                    .contains(&(revision.envelope.record_id, revision.envelope.revision_id))
            })
            .collect();
        if missing.is_empty() {
            continue;
        }
        commit_merkle_sync_batch(ctx, workspace, &missing, batch_ordinal)?;
        for revision in &missing {
            committed_keys.insert((revision.envelope.record_id, revision.envelope.revision_id));
        }
        batch_ordinal = batch_ordinal.saturating_add(1);
        batches_applied = batches_applied.saturating_add(1);
        records_committed = records_committed.saturating_add(missing.len() as u64);
    }
    Ok((batches_applied, records_committed))
}

fn commit_merkle_sync_batch(
    ctx: &IngestContext<'_>,
    workspace: &mut crate::Workspace,
    entries: &[&super::PortableRevision],
    batch_ordinal: u64,
) -> crate::error::Result<()> {
    let sequence = entries[0].commit.sequence;
    let mut records = Vec::with_capacity(entries.len());
    for revision in entries {
        let envelope = &revision.envelope;
        // Preserve original causal parents verbatim without rewriting predecessor.
        records.push(crate::RecordDraft {
            schema_version: envelope.schema_version,
            kind: envelope.kind,
            record_id: envelope.record_id,
            revision_id: envelope.revision_id,
            predecessor: envelope.predecessor,
            scope: envelope.scope.clone(),
            payload: envelope.payload.clone(),
        });
    }
    workspace.commit_merkle_dag(crate::CommitCommand {
        base: workspace.current_revision()?,
        actor: SYNC_INGEST_ACTOR.to_owned(),
        scope: ctx.scope.clone(),
        idempotency_key: format!(
            "iroh-sync:merkle:{}:{sequence}:{batch_ordinal}",
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
            Ok(crate::SourceBlobDraft::inline(
                bytes,
                retained.media_type().clone(),
            ))
        })
        .collect()
}

fn verify_scope_state(
    records_list: &[super::PortableRecord],
    blobs: &[super::PortableBlob],
    forgotten: &crate::coordinator::custody::ForgottenFilter,
    workspace: &crate::Workspace,
    snapshot: &crate::Snapshot,
) -> crate::error::Result<()> {
    let records: std::collections::BTreeSet<_> =
        records_list.iter().map(|record| record.record_id).collect();
    let histories = if records.is_empty() {
        std::collections::BTreeMap::new()
    } else {
        workspace.record_histories_of(snapshot, &records)?
    };
    for expected in records_list {
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
    for blob in blobs {
        if forgotten.matches_digest(blob.digest) {
            continue;
        }
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
    let mut outcomes = Vec::with_capacity(candidates.len());
    let mut pending_publishes = Vec::with_capacity(candidates.len());
    for (index, (path, digest)) in candidates.into_iter().enumerate() {
        let expected_previous = match crate::payload::inspect_working_file(workspace.root(), &path)?
        {
            crate::payload::WorkingEntry::Absent => None,
            crate::payload::WorkingEntry::Regular(existing_bytes) => {
                let existing_digest = mneme_core::ContentDigest::of_source_bytes_with(
                    &existing_bytes,
                    digest.algorithm(),
                );
                if existing_digest == digest {
                    continue;
                }
                previous_paths.get(&path).copied()
            }
            crate::payload::WorkingEntry::NotRegular => {
                return Err(crate::error::Failure::InvalidCommand(
                    "working file target is not a regular file".to_owned(),
                ));
            }
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
