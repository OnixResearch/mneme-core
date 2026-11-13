//! Snapshot membership: the interval representation of retained record
//! membership, the blob-set journal, and the one-time in-place migration from
//! per-revision rows.

/// Rewrite a ledger that copies snapshot membership once per revision.
///
/// One immediate transaction builds the intervals and the blob journal, verifies
/// every revision against the manifest identity it committed, and only then
/// drops the copied rows and clears the stored manifest bytes. A ledger whose
/// history does not reconstruct is left exactly as it was and the open fails.
pub(super) fn migrate_membership_format(
    connection: &mut rusqlite::Connection,
) -> crate::error::Result<()> {
    if let Some(marker) = super::meta_blob_optional(connection, super::META_MEMBERSHIP_FORMAT)? {
        if marker.as_slice() == b"2".as_slice() {
            return Ok(());
        }
        return Err(crate::error::Failure::UnsupportedLayout(format!(
            "ledger membership format {} is not supported",
            String::from_utf8_lossy(&marker)
        )));
    }
    let stored = super::meta_blob(connection, super::META_CURRENT_REVISION)?;
    let current = super::revision_from_blob(&stored)?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    // Another handle may have migrated between the check above and this
    // transaction; inside the write lock the marker is authoritative.
    if super::meta_blob_optional(&transaction, super::META_MEMBERSHIP_FORMAT)?.is_some() {
        transaction.commit()?;
        return Ok(());
    }
    if !super::table_exists(&transaction, "revision_records")?
        || !super::table_exists(&transaction, "revision_blobs")?
    {
        return Err(crate::error::Failure::Integrity {
            revision: current,
            reason: "ledger has no copied membership to upgrade".to_owned(),
        });
    }
    transaction.execute_batch(super::MEMBERSHIP_DDL)?;
    build_membership_intervals(&transaction, current)?;
    build_blob_set_journal(&transaction, current)?;
    verify_migrated_revisions(&transaction, current)?;
    transaction.execute_batch("DROP TABLE revision_records; DROP TABLE revision_blobs;")?;
    transaction.execute(
        "UPDATE revisions SET manifest = ?1",
        rusqlite::params![Vec::<u8>::new()],
    )?;
    super::set_meta(&transaction, super::META_MEMBERSHIP_FORMAT, b"2")?;
    transaction.commit()?;
    Ok(())
}

/// One contiguous run of sequences in which a record kept the same revision.
struct MembershipInterval {
    record_id: Vec<u8>,
    revision_id: Vec<u8>,
    first_sequence: u64,
    last_sequence: u64,
}

/// One record's copied membership rows, folded into intervals as they arrive in
/// ascending sequence order.
struct IntervalGroup {
    record_id: Vec<u8>,
    open: Option<MembershipInterval>,
    started: std::collections::BTreeSet<Vec<u8>>,
    previous_sequence: Option<u64>,
}

impl IntervalGroup {
    fn new(record_id: Vec<u8>) -> Self {
        IntervalGroup {
            record_id,
            open: None,
            started: std::collections::BTreeSet::new(),
            previous_sequence: None,
        }
    }

    /// Fold the next copied row into the open interval.
    fn push(
        &mut self,
        transaction: &rusqlite::Transaction<'_>,
        revision_id: Vec<u8>,
        sequence: u64,
        current_sequence: u64,
        context: mneme_core::WorkspaceRevisionId,
    ) -> crate::error::Result<()> {
        if let Some(previous) = self.previous_sequence
            && previous.saturating_add(1) != sequence
        {
            return Err(crate::error::Failure::Integrity {
                revision: context,
                reason: "copied membership is not contiguous for one record".to_owned(),
            });
        }
        self.previous_sequence = Some(sequence);
        if let Some(open) = self.open.as_mut()
            && open.revision_id == revision_id
        {
            open.last_sequence = sequence;
            return Ok(());
        }
        if let Some(open) = self.open.take() {
            write_interval(transaction, &open, current_sequence)?;
        }
        if !self.started.insert(revision_id.clone()) {
            return Err(crate::error::Failure::Integrity {
                revision: context,
                reason: "copied membership repeats one record revision".to_owned(),
            });
        }
        self.open = Some(MembershipInterval {
            record_id: self.record_id.clone(),
            revision_id,
            first_sequence: sequence,
            last_sequence: sequence,
        });
        Ok(())
    }

    /// Write the interval still open at the end of the record's copied rows.
    fn finish(
        mut self,
        transaction: &rusqlite::Transaction<'_>,
        current_sequence: u64,
    ) -> crate::error::Result<()> {
        if let Some(open) = self.open.take() {
            write_interval(transaction, &open, current_sequence)?;
        }
        Ok(())
    }
}

/// Insert one interval, leaving it open when it reaches the current sequence.
fn write_interval(
    transaction: &rusqlite::Transaction<'_>,
    interval: &MembershipInterval,
    current_sequence: u64,
) -> crate::error::Result<()> {
    let last = if interval.last_sequence == current_sequence {
        None
    } else {
        Some(super::db_i64(interval.last_sequence, "sequence")?)
    };
    transaction.execute(
        "INSERT INTO record_membership (record_id, revision_id, first_sequence, last_sequence)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![
            interval.record_id.as_slice(),
            interval.revision_id.as_slice(),
            super::db_i64(interval.first_sequence, "sequence")?,
            last,
        ],
    )?;
    Ok(())
}

/// Fold the copied per-revision membership rows into intervals.
fn build_membership_intervals(
    transaction: &rusqlite::Transaction<'_>,
    context: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<()> {
    let current_sequence = super::meta_u64(transaction, super::META_CURRENT_SEQUENCE)?;
    let dangling: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM revision_records rr
         LEFT JOIN records r ON r.record_id = rr.record_id AND r.revision_id = rr.revision_id
         LEFT JOIN revisions v ON v.sequence = rr.revision_sequence
         WHERE r.record_id IS NULL OR v.sequence IS NULL",
        [],
        |row| row.get(0),
    )?;
    if dangling != 0 {
        return Err(crate::error::Failure::Integrity {
            revision: context,
            reason: "copied membership names a record revision the ledger does not hold".to_owned(),
        });
    }
    let mut statement = transaction.prepare(
        "SELECT record_id, revision_id, revision_sequence FROM revision_records
         ORDER BY record_id, revision_sequence",
    )?;
    let mut rows = statement.query([])?;
    let mut group: Option<IntervalGroup> = None;
    while let Some(row) = rows.next()? {
        let record_id: Vec<u8> = row.get(0)?;
        let revision_id: Vec<u8> = row.get(1)?;
        let sequence = super::db_u64(row.get::<_, i64>(2)?, "sequence")?;
        let is_continuing = group
            .as_ref()
            .is_some_and(|group| group.record_id == record_id);
        if !is_continuing {
            if let Some(finished) = group.take() {
                finished.finish(transaction, current_sequence)?;
            }
            group = Some(IntervalGroup::new(record_id));
        }
        if let Some(active) = group.as_mut() {
            active.push(
                transaction,
                revision_id,
                sequence,
                current_sequence,
                context,
            )?;
        }
    }
    if let Some(finished) = group.take() {
        finished.finish(transaction, current_sequence)?;
    }
    Ok(())
}

/// Record how each revision's required-digest set differs from its parent's.
fn build_blob_set_journal(
    transaction: &rusqlite::Transaction<'_>,
    context: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<()> {
    let current_sequence = super::meta_u64(transaction, super::META_CURRENT_SEQUENCE)?;
    let dangling: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM revision_blobs rb
         LEFT JOIN revisions v ON v.sequence = rb.revision_sequence
         WHERE v.sequence IS NULL",
        [],
        |row| row.get(0),
    )?;
    if dangling != 0 {
        return Err(crate::error::Failure::Integrity {
            revision: context,
            reason: "copied blob membership names a revision the ledger does not hold".to_owned(),
        });
    }
    let mut statement = transaction.prepare(
        "SELECT revision_sequence, digest FROM revision_blobs
         ORDER BY revision_sequence, digest",
    )?;
    let mut rows = statement.query([])?;
    let mut previous = std::collections::BTreeSet::new();
    let mut applied = 0_u64;
    let mut grouped: Option<(u64, std::collections::BTreeSet<[u8; 32]>)> = None;
    while let Some(row) = rows.next()? {
        let sequence = super::db_u64(row.get::<_, i64>(0)?, "sequence")?;
        let digest: Vec<u8> = row.get(1)?;
        let digest: [u8; 32] = digest
            .try_into()
            .map_err(|_| crate::error::Failure::Integrity {
                revision: context,
                reason: "copied blob membership digest is not 32 bytes".to_owned(),
            })?;
        let is_current = grouped
            .as_ref()
            .is_some_and(|(group_sequence, _)| *group_sequence == sequence);
        if is_current {
            if let Some((_, digests)) = grouped.as_mut() {
                digests.insert(digest);
            }
            continue;
        }
        if let Some((closed, digests)) = grouped.take() {
            write_journal_group(transaction, closed, &digests, &mut previous, &mut applied)?;
        }
        grouped = Some((sequence, std::collections::BTreeSet::from([digest])));
    }
    if let Some((closed, digests)) = grouped.take() {
        write_journal_group(transaction, closed, &digests, &mut previous, &mut applied)?;
    }
    // A committed sequence with no copied rows requires no digest, so every
    // trailing sequence is an empty set.
    while applied <= current_sequence {
        let sequence = applied;
        let empty = std::collections::BTreeSet::new();
        write_journal_group(transaction, sequence, &empty, &mut previous, &mut applied)?;
    }
    Ok(())
}

/// Write one sequence's difference from the previous sequence's digest set.
fn write_journal_group(
    transaction: &rusqlite::Transaction<'_>,
    sequence: u64,
    digests: &std::collections::BTreeSet<[u8; 32]>,
    previous: &mut std::collections::BTreeSet<[u8; 32]>,
    applied: &mut u64,
) -> crate::error::Result<()> {
    while *applied < sequence {
        let empty = std::collections::BTreeSet::new();
        write_journal_delta(transaction, *applied, previous, &empty)?;
        *applied = applied.saturating_add(1);
    }
    write_journal_delta(transaction, sequence, previous, digests)?;
    *applied = sequence.saturating_add(1);
    Ok(())
}

/// Insert the added and removed digests between two consecutive sets.
fn write_journal_delta(
    transaction: &rusqlite::Transaction<'_>,
    sequence: u64,
    previous: &mut std::collections::BTreeSet<[u8; 32]>,
    next: &std::collections::BTreeSet<[u8; 32]>,
) -> crate::error::Result<()> {
    for digest in next.difference(previous) {
        transaction.execute(
            "INSERT INTO revision_blob_changes (revision_sequence, digest, change)
             VALUES (?1, ?2, 'add')",
            rusqlite::params![super::db_i64(sequence, "sequence")?, digest.as_slice()],
        )?;
    }
    for digest in previous.difference(next) {
        transaction.execute(
            "INSERT INTO revision_blob_changes (revision_sequence, digest, change)
             VALUES (?1, ?2, 'remove')",
            rusqlite::params![super::db_i64(sequence, "sequence")?, digest.as_slice()],
        )?;
    }
    *previous = next.clone();
    Ok(())
}

/// Require every copied revision manifest to be exactly the manifest the new
/// membership representation reconstructs.
fn verify_migrated_revisions(
    transaction: &rusqlite::Transaction<'_>,
    context: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<()> {
    let changes = journal_changes(transaction)?;
    let mut cursor = 0_usize;
    let mut blobs = std::collections::BTreeSet::new();
    let mut statement = transaction.prepare(
        "SELECT sequence, revision_id, parent_revision_id, manifest, manifest_digest
         FROM revisions ORDER BY sequence",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let sequence = super::db_u64(row.get::<_, i64>(0)?, "sequence")?;
        let revision = super::revision_from_blob(&row.get::<_, Vec<u8>>(1)?)?;
        let parent = row
            .get::<_, Option<Vec<u8>>>(2)?
            .map(|bytes| super::revision_from_blob(&bytes))
            .transpose()?;
        let stored_bytes: Vec<u8> = row.get(3)?;
        let stored_digest = super::digest_with(
            &row.get::<_, Vec<u8>>(4)?,
            "preserves-canonical-binary-v1",
            "payload",
            revision,
        )?;
        let sequence_value = super::db_i64(sequence, "sequence")?;
        while cursor < changes.len() && changes[cursor].0 <= sequence_value {
            let (_, digest, profile, boundary, change) = &changes[cursor];
            let digest = super::digest_with(digest, profile, boundary, revision)?;
            super::apply_blob_change(&mut blobs, digest, change, revision)?;
            cursor += 1;
        }
        let stored = StoredRevisionManifest {
            revision,
            parent,
            sequence,
            stored_bytes: &stored_bytes,
            stored_digest,
        };
        require_reconstructed_manifest(transaction, &blobs, &stored)?;
    }
    if cursor != changes.len() {
        return Err(crate::error::Failure::Integrity {
            revision: context,
            reason: "blob-set journal names a sequence past the committed history".to_owned(),
        });
    }
    Ok(())
}

/// One stored revision row whose copied manifest must reconstruct exactly.
struct StoredRevisionManifest<'a> {
    revision: mneme_core::WorkspaceRevisionId,
    parent: Option<mneme_core::WorkspaceRevisionId>,
    sequence: u64,
    stored_bytes: &'a [u8],
    stored_digest: mneme_core::ContentDigest,
}

/// Require one revision's stored manifest to be exactly what the migrated
/// membership and blob-set journal reconstruct from the ledger.
fn require_reconstructed_manifest(
    transaction: &rusqlite::Transaction<'_>,
    blobs: &std::collections::BTreeSet<mneme_core::ContentDigest>,
    stored: &StoredRevisionManifest<'_>,
) -> crate::error::Result<()> {
    let revision = stored.revision;
    let manifest = crate::catalog::Manifest {
        revision,
        parent: stored.parent,
        records: super::manifest_record_set(transaction, stored.sequence, revision)?,
        blobs: blobs.clone(),
    };
    let value = mneme_core::binary::decode(stored.stored_bytes).map_err(|diagnostic| {
        crate::error::Failure::Integrity {
            revision,
            reason: format!("stored manifest is not valid Preserves: {diagnostic}"),
        }
    })?;
    let committed = crate::catalog::Manifest::from_value(&value).map_err(|reason| {
        crate::error::Failure::Integrity {
            revision,
            reason: format!("stored manifest is invalid: {reason}"),
        }
    })?;
    if committed != manifest
        || manifest.digest() != stored.stored_digest
        || manifest.encode() != stored.stored_bytes
    {
        return Err(crate::error::Failure::Integrity {
            revision,
            reason: "copied manifest does not match its reconstructible membership".to_owned(),
        });
    }
    Ok(())
}

/// The recorded blob-set changes in the order they were applied.
type BlobChangeRow = (i64, Vec<u8>, String, String, String);

/// Read every recorded blob-set change once.
fn journal_changes(
    transaction: &rusqlite::Transaction<'_>,
) -> crate::error::Result<Vec<BlobChangeRow>> {
    let mut statement = transaction.prepare(
        "SELECT c.revision_sequence, c.digest, b.profile, b.boundary, c.change
         FROM revision_blob_changes c
         JOIN blobs b ON b.digest = c.digest
         ORDER BY c.revision_sequence, c.digest",
    )?;
    let changes = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(changes)
}
