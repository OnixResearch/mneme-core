//! Transactional SQLite metadata projection for entities, relations, and documents.
//!
//! These tables mirror the current committed, non-forgotten records of the
//! workspace so callers can list documents, resolve entities by `external-id`,
//! or traverse relation endpoints in O(log N) without scanning raw Preserves
//! blob files.

/// Maximum number of metadata rows returned by a single bounded query page.
pub const MAX_METADATA_PAGE_SIZE: u32 = 1_000;

/// Schema DDL for the metadata projection tables and their lookup indexes.
pub(super) const METADATA_PROJECTION_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS entities (
    record_id BLOB PRIMARY KEY,
    revision_id BLOB NOT NULL,
    scope TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    label TEXT NOT NULL,
    external_id TEXT
);
CREATE INDEX IF NOT EXISTS entities_scope_type
    ON entities(scope, entity_type, record_id);
CREATE INDEX IF NOT EXISTS entities_type
    ON entities(entity_type, record_id);
CREATE INDEX IF NOT EXISTS entities_external_id
    ON entities(external_id, record_id) WHERE external_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS entities_scope_external_id
    ON entities(scope, external_id, record_id) WHERE external_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS relations (
    record_id BLOB PRIMARY KEY,
    revision_id BLOB NOT NULL,
    scope TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    from_id BLOB,
    to_id BLOB
);
CREATE INDEX IF NOT EXISTS relations_scope_type
    ON relations(scope, relation_type, record_id);
CREATE INDEX IF NOT EXISTS relations_type
    ON relations(relation_type, record_id);
CREATE INDEX IF NOT EXISTS relations_from
    ON relations(from_id, relation_type, record_id) WHERE from_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS relations_to
    ON relations(to_id, relation_type, record_id) WHERE to_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS documents (
    record_id BLOB PRIMARY KEY,
    revision_id BLOB NOT NULL,
    scope TEXT NOT NULL,
    path TEXT,
    title TEXT NOT NULL,
    source_revision_id BLOB
);
CREATE INDEX IF NOT EXISTS documents_scope_path
    ON documents(scope, path, record_id);
CREATE INDEX IF NOT EXISTS documents_source
    ON documents(source_revision_id, record_id) WHERE source_revision_id IS NOT NULL;
"#;

/// Indexed metadata row for one active entity record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntityMetadata {
    pub record_id: mneme_core::RecordId,
    pub revision_id: mneme_core::RevisionId,
    pub scope: mneme_core::ScopeId,
    pub entity_type: String,
    pub label: String,
    pub external_id: Option<String>,
}

/// Indexed metadata row for one active relation record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelationMetadata {
    pub record_id: mneme_core::RecordId,
    pub revision_id: mneme_core::RevisionId,
    pub scope: mneme_core::ScopeId,
    pub relation_type: String,
    pub from_id: Option<mneme_core::RecordId>,
    pub to_id: Option<mneme_core::RecordId>,
}

/// Indexed metadata row for one active document record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentMetadata {
    pub record_id: mneme_core::RecordId,
    pub revision_id: mneme_core::RevisionId,
    pub scope: mneme_core::ScopeId,
    pub path: Option<String>,
    pub title: String,
    pub source_revision_id: Option<mneme_core::RecordId>,
}

/// Filter and keyset-paging parameters for querying projected entities.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EntityQuery {
    pub scope: Option<mneme_core::ScopeId>,
    pub entity_type: Option<String>,
    pub external_id: Option<String>,
    pub after: Option<mneme_core::RecordId>,
    pub limit: Option<u32>,
}

/// Filter and keyset-paging parameters for querying projected relations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelationQuery {
    pub scope: Option<mneme_core::ScopeId>,
    pub relation_type: Option<String>,
    pub from_id: Option<mneme_core::RecordId>,
    pub to_id: Option<mneme_core::RecordId>,
    pub after: Option<mneme_core::RecordId>,
    pub limit: Option<u32>,
}

/// Filter and keyset-paging parameters for querying projected documents.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DocumentQuery {
    pub scope: Option<mneme_core::ScopeId>,
    pub path: Option<String>,
    pub after: Option<mneme_core::RecordId>,
    pub limit: Option<u32>,
}

/// A bounded page of metadata projection rows ordered by `record_id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataPage<T> {
    pub items: Vec<T>,
    pub has_more: bool,
    pub next_after: Option<mneme_core::RecordId>,
}

type ActiveMetadataRow = (Vec<u8>, Vec<u8>, String, Vec<u8>, Vec<u8>, Vec<u8>);
type CurrentRecordRow = (Vec<u8>, String, Vec<u8>, Vec<u8>, Vec<u8>);

fn check_projection_marker(marker: &[u8]) -> crate::error::Result<()> {
    if marker == b"1".as_slice() {
        return Ok(());
    }
    Err(crate::error::Failure::UnsupportedLayout(format!(
        "ledger metadata projection format {} is not supported",
        String::from_utf8_lossy(marker)
    )))
}

/// Upgrade an existing ledger in place by creating and populating the metadata
/// projection tables from verified active record blobs.
pub(super) fn migrate_metadata_projection(
    root: &std::path::Path,
    connection: &mut rusqlite::Connection,
) -> crate::error::Result<()> {
    if let Some(marker) =
        super::meta_blob_optional(connection, super::META_METADATA_PROJECTION_FORMAT)?
    {
        return check_projection_marker(&marker);
    }
    migrate_projection_in_transaction(root, connection)
}

fn migrate_projection_in_transaction(
    root: &std::path::Path,
    connection: &mut rusqlite::Connection,
) -> crate::error::Result<()> {
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    if let Some(marker) =
        super::meta_blob_optional(&transaction, super::META_METADATA_PROJECTION_FORMAT)?
    {
        check_projection_marker(&marker)?;
        transaction.commit()?;
        return Ok(());
    }
    transaction.execute_batch(METADATA_PROJECTION_DDL)?;
    rebuild_from_ledger_in(&transaction, root)?;
    super::set_meta(&transaction, super::META_METADATA_PROJECTION_FORMAT, b"1")?;
    transaction.commit()?;
    Ok(())
}

/// Apply one committed batch's record upserts, closed-record removals, and
/// retention suppressions to the metadata projection inside the commit transaction.
pub(super) fn apply_commit(
    transaction: &rusqlite::Transaction<'_>,
    new_records: &[mneme_core::RecordEnvelope],
    dropped_records: &[mneme_core::RecordId],
    retention: Option<&crate::lifecycle::RetentionCommit>,
) -> crate::error::Result<()> {
    for record_id in dropped_records {
        delete_record_id(transaction, *record_id)?;
    }
    for record in new_records {
        upsert_record(transaction, record)?;
    }
    if let Some(retention) = retention {
        apply_suppressions(transaction, &retention.suppressions)?;
    }
    Ok(())
}

/// Remove any projected rows hidden by `Forgotten` retention suppressions.
pub(super) fn apply_suppressions(
    transaction: &rusqlite::Transaction<'_>,
    suppressions: &[crate::lifecycle::RetentionSuppression],
) -> crate::error::Result<()> {
    for suppression in suppressions {
        if suppression.mode != crate::lifecycle::SuppressionMode::Forgotten {
            continue;
        }
        match suppression.revision {
            None => delete_record_id(transaction, suppression.target)?,
            Some(revision) => delete_record_revision(transaction, suppression.target, revision)?,
        }
    }
    Ok(())
}

/// Clear and deterministically repopulate all projection tables from an already
/// verified snapshot record slice.
pub(super) fn replace_all_from_records(
    transaction: &rusqlite::Transaction<'_>,
    records: &[mneme_core::RecordEnvelope],
) -> crate::error::Result<()> {
    clear_tables(transaction)?;
    for record in records {
        upsert_record(transaction, record)?;
    }
    Ok(())
}

fn select_active_metadata_rows(
    transaction: &rusqlite::Transaction<'_>,
) -> crate::error::Result<Vec<ActiveMetadataRow>> {
    let mut statement = transaction.prepare(
        "SELECT r.record_id, r.revision_id, r.kind, r.envelope_digest, r.payload_digest,
                r.full_digest
         FROM record_membership m
         JOIN records r ON r.record_id = m.record_id AND r.revision_id = m.revision_id
         WHERE m.last_sequence IS NULL AND r.kind IN ('entity', 'relation', 'document')
         ORDER BY r.record_id",
    )?;
    statement
        .query_map([], map_active_metadata_row)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn map_active_metadata_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ActiveMetadataRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}

fn verify_and_upsert_active_row(
    transaction: &rusqlite::Transaction<'_>,
    root: &std::path::Path,
    entry: ActiveMetadataRow,
    context: mneme_core::WorkspaceRevisionId,
    forgotten: &super::sweep::ForgottenSuppressions,
) -> crate::error::Result<()> {
    let (record_id, revision_id, kind) = super::membership_record(&entry, context)?;
    if forgotten.matches(record_id, revision_id) {
        return Ok(());
    }
    let (_, _, _, envelope_digest, payload_digest, full_digest) = entry;
    let algorithm = super::blob_algorithm(transaction, &full_digest)?;
    let digest = verify_envelope_digest(&envelope_digest, &full_digest, algorithm, context)?;
    let payload_digest = super::digest_with(
        &payload_digest,
        algorithm.symbol(),
        "preserves-canonical-binary-v1",
        "payload",
        context,
    )?;
    let bytes = read_metadata_blob(root, digest, context)?;
    let record = super::decode_envelope(&bytes, digest, context)?;
    let identity = super::EnvelopeIdentity {
        record_id,
        revision_id,
        kind,
        full_digest: &full_digest,
    };
    super::require_envelope_identity(&identity, &record, digest, payload_digest, context)?;
    debug_assert_eq!(record.record_id, record_id);
    debug_assert_eq!(record.revision_id, revision_id);
    upsert_record(transaction, &record)
}

fn verify_envelope_digest(
    envelope_digest: &[u8],
    full_digest: &[u8],
    algorithm: mneme_core::HashAlgorithm,
    context: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<mneme_core::ContentDigest> {
    let digest = super::digest_with(
        envelope_digest,
        algorithm.symbol(),
        "preserves-canonical-binary-v1",
        "full-record",
        context,
    )?;
    if digest.as_bytes().as_slice() != full_digest {
        return Err(crate::error::Failure::Integrity {
            revision: context,
            reason: format!("record blob {digest} does not match its ledger identity"),
        });
    }
    Ok(digest)
}

fn read_metadata_blob(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
    context: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<Vec<u8>> {
    crate::payload::read(root, digest).map_err(|error| crate::error::Failure::Integrity {
        revision: context,
        reason: format!("record blob {digest} is unavailable: {error}"),
    })
}

/// Clear and deterministically rebuild all projection tables from active ledger
/// membership and verified on-disk record blobs.
pub(super) fn rebuild_from_ledger_in(
    transaction: &rusqlite::Transaction<'_>,
    root: &std::path::Path,
) -> crate::error::Result<()> {
    clear_tables(transaction)?;
    let stored = super::meta_blob(transaction, super::META_CURRENT_REVISION)?;
    let context = super::revision_from_blob(&stored)?;
    let forgotten = super::sweep::forgotten_suppressions_in(transaction)?;
    let rows = select_active_metadata_rows(transaction)?;
    for entry in rows {
        verify_and_upsert_active_row(transaction, root, entry, context, &forgotten)?;
    }
    Ok(())
}

impl super::Workspace {
    /// Rebuild the metadata projection from a verified snapshot, falling back to
    /// reading active blobs from disk if a concurrent commit moved the ledger.
    pub(super) fn rebuild_metadata_projection(
        &mut self,
        snapshot: &super::Snapshot,
    ) -> crate::error::Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current = super::revision_from_blob(&super::meta_blob(
            &transaction,
            super::META_CURRENT_REVISION,
        )?)?;
        let generation = super::meta_u64(&transaction, super::META_GENERATION)?;
        if current == snapshot.revision && generation == snapshot.eligibility_generation {
            replace_all_from_records(&transaction, &snapshot.records)?;
        } else {
            rebuild_from_ledger_in(&transaction, &self.root)?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Query indexed entities with optional scope, type, and `external-id`
    /// filters and bounded cursor paging.
    pub fn query_entities(
        &self,
        query: &EntityQuery,
    ) -> crate::error::Result<MetadataPage<EntityMetadata>> {
        self.require_restore_suppression()?;
        let max_rows = bounded_page_rows(query.limit)?;
        let context = self.current_revision()?;
        let transaction = self.connection.unchecked_transaction()?;
        let page = query_entities_in(&transaction, query, max_rows, context)?;
        transaction.commit()?;
        Ok(page)
    }

    /// Query indexed relations with optional scope, type, and endpoint filters
    /// and bounded cursor paging.
    pub fn query_relations(
        &self,
        query: &RelationQuery,
    ) -> crate::error::Result<MetadataPage<RelationMetadata>> {
        self.require_restore_suppression()?;
        let max_rows = bounded_page_rows(query.limit)?;
        let context = self.current_revision()?;
        let transaction = self.connection.unchecked_transaction()?;
        let page = query_relations_in(&transaction, query, max_rows, context)?;
        transaction.commit()?;
        Ok(page)
    }

    /// Query indexed documents with optional scope and exact path filters and
    /// bounded cursor paging.
    pub fn query_documents(
        &self,
        query: &DocumentQuery,
    ) -> crate::error::Result<MetadataPage<DocumentMetadata>> {
        self.require_restore_suppression()?;
        let max_rows = bounded_page_rows(query.limit)?;
        let context = self.current_revision()?;
        let transaction = self.connection.unchecked_transaction()?;
        let page = query_documents_in(&transaction, query, max_rows, context)?;
        transaction.commit()?;
        Ok(page)
    }

    /// Load and verify the current non-forgotten revision of one record by its
    /// `RecordId` without scanning unrelated workspace blobs.
    pub fn current_record(
        &self,
        record_id: mneme_core::RecordId,
    ) -> crate::error::Result<Option<mneme_core::RecordEnvelope>> {
        self.require_restore_suppression()?;
        let context = self.current_revision()?;
        let generation = self.eligibility_generation()?;
        let transaction = self.connection.unchecked_transaction()?;
        match self.current_record_in(&transaction, record_id, context, generation) {
            Ok(record) => {
                transaction.commit()?;
                self.require_unchanged_generation(generation)?;
                Ok(record)
            }
            Err(error) => {
                drop(transaction);
                Err(self.explain_barrier(error, generation))
            }
        }
    }

    fn require_unchanged_generation(&self, generation: u64) -> crate::error::Result<()> {
        let after = self.eligibility_generation()?;
        if after != generation {
            return Err(crate::error::Failure::BarrierAdvanced {
                pinned: generation,
                current: after,
            });
        }
        Ok(())
    }

    fn current_record_in(
        &self,
        connection: &rusqlite::Connection,
        record_id: mneme_core::RecordId,
        context: mneme_core::WorkspaceRevisionId,
        generation: u64,
    ) -> crate::error::Result<Option<mneme_core::RecordEnvelope>> {
        self.facts().align(generation);
        let forgotten = super::sweep::forgotten_suppressions_in(connection)?;
        if forgotten.identities.contains(&record_id) {
            return Err(crate::error::Failure::RetentionSuppressed {
                target: record_id.to_string(),
            });
        }
        let Some(row) = load_open_membership_row(connection, record_id)? else {
            return Ok(None);
        };
        self.load_non_forgotten_open_row(row, record_id, context, generation, &forgotten)
    }

    fn load_non_forgotten_open_row(
        &self,
        row: CurrentRecordRow,
        record_id: mneme_core::RecordId,
        context: mneme_core::WorkspaceRevisionId,
        generation: u64,
        forgotten: &super::sweep::ForgottenSuppressions,
    ) -> crate::error::Result<Option<mneme_core::RecordEnvelope>> {
        let (rev_bytes, kind_str, envelope_digest, payload_digest, full_digest) = row;
        let revision_id = super::revision_id_from_blob(&rev_bytes, context)?;
        if forgotten.revisions.contains(&(record_id, revision_id)) {
            return Err(crate::error::Failure::RetentionSuppressed {
                target: record_id.to_string(),
            });
        }
        let kind = mneme_core::RecordKind::parse(&kind_str).ok_or_else(|| {
            crate::error::Failure::Integrity {
                revision: context,
                reason: format!("unknown record kind {kind_str}"),
            }
        })?;
        let lengths = super::BlobIndex::new();
        let input = super::VerifiedRecordEnvelopeInput {
            record_id,
            revision_id,
            kind,
            envelope_digest: &envelope_digest,
            payload_digest: &payload_digest,
            full_digest: &full_digest,
            revision: context,
            generation,
            lengths: &lengths,
        };
        let envelope = self.load_verified_record_envelope(input, super::PayloadCheck::Cached)?;
        debug_assert_eq!(envelope.record_id, record_id);
        debug_assert_eq!(envelope.revision_id, revision_id);
        Ok(Some(envelope))
    }
}

fn map_current_record_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CurrentRecordRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
    ))
}

fn load_open_membership_row(
    connection: &rusqlite::Connection,
    record_id: mneme_core::RecordId,
) -> crate::error::Result<Option<CurrentRecordRow>> {
    use rusqlite::OptionalExtension;
    connection
        .query_row(
            "SELECT r.revision_id, r.kind, r.envelope_digest, r.payload_digest, r.full_digest
             FROM record_membership m
             JOIN records r ON r.record_id = m.record_id AND r.revision_id = m.revision_id
             WHERE m.record_id = ?1 AND m.last_sequence IS NULL",
            rusqlite::params![record_id.as_bytes().as_slice()],
            map_current_record_row,
        )
        .optional()
        .map_err(Into::into)
}

fn bounded_page_rows(requested_rows: Option<u32>) -> crate::error::Result<u32> {
    let row_count = requested_rows.unwrap_or(MAX_METADATA_PAGE_SIZE);
    if row_count == 0 || row_count > MAX_METADATA_PAGE_SIZE {
        return Err(crate::error::Failure::InvalidCommand(format!(
            "metadata page limit must be in 1..={MAX_METADATA_PAGE_SIZE}, got {row_count}"
        )));
    }
    Ok(row_count)
}

fn max_rows_usize(row_count: u32) -> crate::error::Result<usize> {
    usize::try_from(row_count).map_err(|_| crate::error::Failure::ValueOutOfRange("limit"))
}

fn clear_tables(transaction: &rusqlite::Transaction<'_>) -> crate::error::Result<()> {
    transaction
        .execute_batch("DELETE FROM entities; DELETE FROM relations; DELETE FROM documents;")?;
    Ok(())
}

fn delete_record_id(
    transaction: &rusqlite::Transaction<'_>,
    record_id: mneme_core::RecordId,
) -> crate::error::Result<()> {
    let bytes = record_id.as_bytes().as_slice();
    transaction.execute(
        "DELETE FROM entities WHERE record_id = ?1",
        rusqlite::params![bytes],
    )?;
    transaction.execute(
        "DELETE FROM relations WHERE record_id = ?1",
        rusqlite::params![bytes],
    )?;
    transaction.execute(
        "DELETE FROM documents WHERE record_id = ?1",
        rusqlite::params![bytes],
    )?;
    Ok(())
}

fn delete_record_revision(
    transaction: &rusqlite::Transaction<'_>,
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
) -> crate::error::Result<()> {
    let rid = record_id.as_bytes().as_slice();
    let rev = revision_id.as_bytes().as_slice();
    transaction.execute(
        "DELETE FROM entities WHERE record_id = ?1 AND revision_id = ?2",
        rusqlite::params![rid, rev],
    )?;
    transaction.execute(
        "DELETE FROM relations WHERE record_id = ?1 AND revision_id = ?2",
        rusqlite::params![rid, rev],
    )?;
    transaction.execute(
        "DELETE FROM documents WHERE record_id = ?1 AND revision_id = ?2",
        rusqlite::params![rid, rev],
    )?;
    Ok(())
}

fn upsert_record(
    transaction: &rusqlite::Transaction<'_>,
    record: &mneme_core::RecordEnvelope,
) -> crate::error::Result<()> {
    match record.kind {
        mneme_core::RecordKind::Entity => upsert_entity(transaction, record),
        mneme_core::RecordKind::Relation => upsert_relation(transaction, record),
        mneme_core::RecordKind::Document => upsert_document(transaction, record),
        mneme_core::RecordKind::SourceRevision
        | mneme_core::RecordKind::Episode
        | mneme_core::RecordKind::Assertion
        | mneme_core::RecordKind::Evidence
        | mneme_core::RecordKind::Derivation
        | mneme_core::RecordKind::Checkpoint
        | mneme_core::RecordKind::Proposal
        | mneme_core::RecordKind::Decision
        | mneme_core::RecordKind::RetentionDirective
        | mneme_core::RecordKind::DocumentBinding
        | mneme_core::RecordKind::DocumentAnchor
        | mneme_core::RecordKind::Comment
        | mneme_core::RecordKind::RecognitionRun
        | mneme_core::RecordKind::RecognitionSegment => Ok(()),
    }
}

fn payload_symbol(payload: &mneme_core::Payload, field: &str) -> String {
    payload
        .get(field)
        .and_then(mneme_core::Value::as_symbol)
        .map(|symbol| symbol.as_str().to_owned())
        .unwrap_or_default()
}

fn payload_text<'a>(payload: &'a mneme_core::Payload, field: &str) -> Option<&'a str> {
    payload.get(field).and_then(mneme_core::Value::as_string)
}

fn upsert_entity(
    transaction: &rusqlite::Transaction<'_>,
    record: &mneme_core::RecordEnvelope,
) -> crate::error::Result<()> {
    let entity_type = payload_symbol(&record.payload, "entity-type");
    let label = payload_text(&record.payload, "label").unwrap_or("");
    let external_id = extract_external_id(&record.payload);
    transaction.execute(
        "INSERT OR REPLACE INTO entities (record_id, revision_id, scope, entity_type, label, external_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            record.record_id.as_bytes().as_slice(),
            record.revision_id.as_bytes().as_slice(),
            record.scope.to_string(),
            entity_type,
            label,
            external_id,
        ],
    )?;
    Ok(())
}

fn upsert_relation(
    transaction: &rusqlite::Transaction<'_>,
    record: &mneme_core::RecordEnvelope,
) -> crate::error::Result<()> {
    let relation_type = payload_symbol(&record.payload, "relation-type");
    let from_id = extract_reference_target(record.payload.get("from"));
    let to_id = extract_reference_target(record.payload.get("to"));
    transaction.execute(
        "INSERT OR REPLACE INTO relations (record_id, revision_id, scope, relation_type, from_id, to_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            record.record_id.as_bytes().as_slice(),
            record.revision_id.as_bytes().as_slice(),
            record.scope.to_string(),
            relation_type,
            from_id.map(|id| id.as_bytes().to_vec()),
            to_id.map(|id| id.as_bytes().to_vec()),
        ],
    )?;
    Ok(())
}

fn upsert_document(
    transaction: &rusqlite::Transaction<'_>,
    record: &mneme_core::RecordEnvelope,
) -> crate::error::Result<()> {
    let path = payload_text(&record.payload, "path");
    let title = payload_text(&record.payload, "title").unwrap_or("");
    let source_revision_id = extract_reference_target(record.payload.get("source-revision"));
    transaction.execute(
        "INSERT OR REPLACE INTO documents (record_id, revision_id, scope, path, title, source_revision_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            record.record_id.as_bytes().as_slice(),
            record.revision_id.as_bytes().as_slice(),
            record.scope.to_string(),
            path,
            title,
            source_revision_id.map(|id| id.as_bytes().to_vec()),
        ],
    )?;
    Ok(())
}

fn extract_external_id(payload: &mneme_core::Payload) -> Option<String> {
    let properties = payload
        .get("properties")
        .and_then(mneme_core::Value::as_dictionary)?;
    let value = properties
        .get(&mneme_core::Value::symbol("external-id"))
        .or_else(|| properties.get(&mneme_core::Value::string("external-id")))?;
    value
        .as_string()
        .map(str::to_owned)
        .or_else(|| value.as_symbol().map(|symbol| symbol.as_str().to_owned()))
}

fn extract_reference_target(value: Option<&mneme_core::Value>) -> Option<mneme_core::RecordId> {
    value
        .and_then(|value| mneme_core::Reference::from_value(value, &mneme_core::Path::root()).ok())
        .and_then(|reference| reference.target())
}

struct SqlFilterBuilder {
    clauses: Vec<String>,
    params: Vec<rusqlite::types::Value>,
}

impl SqlFilterBuilder {
    fn new() -> Self {
        Self {
            clauses: Vec::new(),
            params: Vec::new(),
        }
    }

    fn push_eq_text(&mut self, column: &str, value: String) {
        let param_idx = self.params.len().saturating_add(1);
        self.clauses.push(format!("{column} = ?{param_idx}"));
        self.params.push(rusqlite::types::Value::Text(value));
    }

    fn push_eq_blob(&mut self, column: &str, value: Vec<u8>) {
        let param_idx = self.params.len().saturating_add(1);
        self.clauses.push(format!("{column} = ?{param_idx}"));
        self.params.push(rusqlite::types::Value::Blob(value));
    }

    fn push_gt_blob(&mut self, column: &str, value: Vec<u8>) {
        let param_idx = self.params.len().saturating_add(1);
        self.clauses.push(format!("{column} > ?{param_idx}"));
        self.params.push(rusqlite::types::Value::Blob(value));
    }

    fn push_row_limit(&mut self, rows_plus_one: u32) -> usize {
        let param_idx = self.params.len().saturating_add(1);
        self.params
            .push(rusqlite::types::Value::Integer(i64::from(rows_plus_one)));
        param_idx
    }

    fn where_sql(&self) -> String {
        if self.clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", self.clauses.join(" AND "))
        }
    }
}

fn collect_bounded_page<R, T, F>(
    rows: Vec<R>,
    max_items: usize,
    id_of: fn(&T) -> mneme_core::RecordId,
    mut map_row: F,
) -> crate::error::Result<MetadataPage<T>>
where
    F: FnMut(R) -> crate::error::Result<T>,
{
    let max_bound = max_rows_usize(MAX_METADATA_PAGE_SIZE)?;
    debug_assert!(max_items <= max_bound);
    let mut items = Vec::with_capacity(rows.len().min(max_items));
    let mut has_more = false;
    for row in rows {
        if items.len() == max_items {
            has_more = true;
            break;
        }
        items.push(map_row(row)?);
    }
    debug_assert!(items.len() <= max_items);
    let next_after = if has_more {
        items.last().map(id_of)
    } else {
        None
    };
    Ok(MetadataPage {
        items,
        has_more,
        next_after,
    })
}

fn query_entities_in(
    connection: &rusqlite::Connection,
    query: &EntityQuery,
    max_rows: u32,
    context: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<MetadataPage<EntityMetadata>> {
    let mut filter = SqlFilterBuilder::new();
    if let Some(scope) = &query.scope {
        filter.push_eq_text("scope", scope.to_string());
    }
    if let Some(entity_type) = &query.entity_type {
        filter.push_eq_text("entity_type", entity_type.clone());
    }
    if let Some(external_id) = &query.external_id {
        filter.push_eq_text("external_id", external_id.clone());
    }
    if let Some(after) = query.after {
        filter.push_gt_blob("record_id", after.as_bytes().to_vec());
    }
    run_entity_query(connection, &mut filter, max_rows, context)
}

type EntityRow = (Vec<u8>, Vec<u8>, String, String, String, Option<String>);

struct QueryTableSpec {
    table: &'static str,
    columns: &'static str,
}

fn query_filter_rows<R>(
    connection: &rusqlite::Connection,
    spec: QueryTableSpec,
    filter: &mut SqlFilterBuilder,
    max_rows: u32,
    map_row: fn(&rusqlite::Row<'_>) -> rusqlite::Result<R>,
) -> crate::error::Result<Vec<R>> {
    let where_sql = filter.where_sql();
    let slot_count = filter.push_row_limit(max_rows.saturating_add(1));
    let sql = format!(
        "SELECT {} FROM {} {where_sql} ORDER BY record_id LIMIT ?{slot_count}",
        spec.columns, spec.table
    );
    let mut statement = connection.prepare(&sql)?;
    statement
        .query_map(rusqlite::params_from_iter(filter.params.iter()), map_row)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn run_entity_query(
    connection: &rusqlite::Connection,
    filter: &mut SqlFilterBuilder,
    max_rows: u32,
    context: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<MetadataPage<EntityMetadata>> {
    let rows = query_filter_rows(
        connection,
        QueryTableSpec {
            table: "entities",
            columns: "record_id, revision_id, scope, entity_type, label, external_id",
        },
        filter,
        max_rows,
        map_entity_row,
    )?;
    let max_items = max_rows_usize(max_rows)?;
    collect_bounded_page(
        rows,
        max_items,
        |item| item.record_id,
        |row| decode_entity_row(row, context),
    )
}

fn map_entity_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EntityRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}

fn decode_entity_row(
    row: EntityRow,
    context: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<EntityMetadata> {
    let (record_bytes, revision_bytes, scope_text, entity_type, label, external_id) = row;
    Ok(EntityMetadata {
        record_id: super::record_id_from_blob(&record_bytes, context)?,
        revision_id: super::revision_id_from_blob(&revision_bytes, context)?,
        scope: parse_scope(&scope_text, context)?,
        entity_type,
        label,
        external_id,
    })
}

fn query_relations_in(
    connection: &rusqlite::Connection,
    query: &RelationQuery,
    max_rows: u32,
    context: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<MetadataPage<RelationMetadata>> {
    let mut filter = SqlFilterBuilder::new();
    if let Some(scope) = &query.scope {
        filter.push_eq_text("scope", scope.to_string());
    }
    if let Some(relation_type) = &query.relation_type {
        filter.push_eq_text("relation_type", relation_type.clone());
    }
    if let Some(from_id) = query.from_id {
        filter.push_eq_blob("from_id", from_id.as_bytes().to_vec());
    }
    if let Some(to_id) = query.to_id {
        filter.push_eq_blob("to_id", to_id.as_bytes().to_vec());
    }
    if let Some(after) = query.after {
        filter.push_gt_blob("record_id", after.as_bytes().to_vec());
    }
    run_relation_query(connection, &mut filter, max_rows, context)
}

type RelationRow = (
    Vec<u8>,
    Vec<u8>,
    String,
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

fn run_relation_query(
    connection: &rusqlite::Connection,
    filter: &mut SqlFilterBuilder,
    max_rows: u32,
    context: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<MetadataPage<RelationMetadata>> {
    let rows = query_filter_rows(
        connection,
        QueryTableSpec {
            table: "relations",
            columns: "record_id, revision_id, scope, relation_type, from_id, to_id",
        },
        filter,
        max_rows,
        map_relation_row,
    )?;
    let max_items = max_rows_usize(max_rows)?;
    collect_bounded_page(
        rows,
        max_items,
        |item| item.record_id,
        |row| decode_relation_row(row, context),
    )
}

fn map_relation_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RelationRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}

fn decode_relation_row(
    row: RelationRow,
    context: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<RelationMetadata> {
    let (record_bytes, revision_bytes, scope_text, relation_type, from_bytes, to_bytes) = row;
    Ok(RelationMetadata {
        record_id: super::record_id_from_blob(&record_bytes, context)?,
        revision_id: super::revision_id_from_blob(&revision_bytes, context)?,
        scope: parse_scope(&scope_text, context)?,
        relation_type,
        from_id: opt_record_id(from_bytes.as_deref(), context)?,
        to_id: opt_record_id(to_bytes.as_deref(), context)?,
    })
}

fn query_documents_in(
    connection: &rusqlite::Connection,
    query: &DocumentQuery,
    max_rows: u32,
    context: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<MetadataPage<DocumentMetadata>> {
    let mut filter = SqlFilterBuilder::new();
    if let Some(scope) = &query.scope {
        filter.push_eq_text("scope", scope.to_string());
    }
    if let Some(path) = &query.path {
        filter.push_eq_text("path", path.clone());
    }
    if let Some(after) = query.after {
        filter.push_gt_blob("record_id", after.as_bytes().to_vec());
    }
    run_document_query(connection, &mut filter, max_rows, context)
}

type DocumentRow = (
    Vec<u8>,
    Vec<u8>,
    String,
    Option<String>,
    String,
    Option<Vec<u8>>,
);

fn run_document_query(
    connection: &rusqlite::Connection,
    filter: &mut SqlFilterBuilder,
    max_rows: u32,
    context: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<MetadataPage<DocumentMetadata>> {
    let rows = query_filter_rows(
        connection,
        QueryTableSpec {
            table: "documents",
            columns: "record_id, revision_id, scope, path, title, source_revision_id",
        },
        filter,
        max_rows,
        map_document_row,
    )?;
    let max_items = max_rows_usize(max_rows)?;
    collect_bounded_page(
        rows,
        max_items,
        |item| item.record_id,
        |row| decode_document_row(row, context),
    )
}

fn map_document_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DocumentRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}

fn decode_document_row(
    row: DocumentRow,
    context: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<DocumentMetadata> {
    let (record_bytes, revision_bytes, scope_text, path, title, source_bytes) = row;
    Ok(DocumentMetadata {
        record_id: super::record_id_from_blob(&record_bytes, context)?,
        revision_id: super::revision_id_from_blob(&revision_bytes, context)?,
        scope: parse_scope(&scope_text, context)?,
        path,
        title,
        source_revision_id: opt_record_id(source_bytes.as_deref(), context)?,
    })
}

fn opt_record_id(
    bytes: Option<&[u8]>,
    context: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<Option<mneme_core::RecordId>> {
    bytes
        .map(|raw| super::record_id_from_blob(raw, context))
        .transpose()
}

fn parse_scope(
    text: &str,
    context: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<mneme_core::ScopeId> {
    let (class_str, local) =
        text.split_once(':')
            .ok_or_else(|| crate::error::Failure::Integrity {
                revision: context,
                reason: format!("invalid scope {text:?} in metadata projection"),
            })?;
    let class = mneme_core::ScopeClass::parse(class_str).ok_or_else(|| {
        crate::error::Failure::Integrity {
            revision: context,
            reason: format!("unknown scope class {class_str:?} in metadata projection"),
        }
    })?;
    mneme_core::ScopeId::new(class, local).map_err(|reason| crate::error::Failure::Integrity {
        revision: context,
        reason: reason.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> mneme_core::ScopeId {
        mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
    }

    fn config(at_ns: i64) -> super::super::WorkspaceConfig {
        super::super::WorkspaceConfig {
            clock: Box::new(crate::timekeeper::FixedClock::new(
                mneme_core::Timestamp::from_nanos(at_ns),
            )),
            faults: Box::new(crate::injectors::NoFaults),
        }
    }

    fn query_plan_details(
        connection: &rusqlite::Connection,
        sql: &str,
        params: &[rusqlite::types::Value],
    ) -> Vec<String> {
        let mut statement = connection
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .expect("prepare explain");
        statement
            .query_map(rusqlite::params_from_iter(params.iter()), |row| {
                row.get::<_, String>(3)
            })
            .expect("explain query")
            .map(|row| row.expect("explain row"))
            .collect()
    }

    #[test]
    fn external_id_and_projection_lookups_use_sqlite_indexes() {
        let temp = tempfile::tempdir().expect("temp");
        let workspace =
            super::super::Workspace::create(temp.path(), config(1_000)).expect("create");

        let plan = query_plan_details(
            &workspace.connection,
            "SELECT record_id FROM entities WHERE external_id = ?1 ORDER BY record_id LIMIT ?2",
            &[
                rusqlite::types::Value::Text("ext-1".to_owned()),
                rusqlite::types::Value::Integer(10),
            ],
        );
        assert!(
            plan.iter()
                .any(|detail| detail.contains("entities_external_id")),
            "expected entities_external_id index, got {plan:?}"
        );
        assert!(
            !plan.iter().any(|detail| detail.contains("SCAN entities")),
            "unexpected table scan for external_id lookup: {plan:?}"
        );

        let scoped_plan = query_plan_details(
            &workspace.connection,
            "SELECT record_id FROM entities WHERE scope = ?1 AND external_id = ?2 ORDER BY record_id LIMIT ?3",
            &[
                rusqlite::types::Value::Text(scope().to_string()),
                rusqlite::types::Value::Text("ext-1".to_owned()),
                rusqlite::types::Value::Integer(10),
            ],
        );
        assert!(
            scoped_plan
                .iter()
                .any(|detail| detail.contains("entities_scope_external_id")),
            "expected entities_scope_external_id index, got {scoped_plan:?}"
        );

        let type_plan = query_plan_details(
            &workspace.connection,
            "SELECT record_id FROM entities WHERE scope = ?1 AND entity_type = ?2 ORDER BY record_id LIMIT ?3",
            &[
                rusqlite::types::Value::Text(scope().to_string()),
                rusqlite::types::Value::Text("bookmark".to_owned()),
                rusqlite::types::Value::Integer(10),
            ],
        );
        assert!(
            type_plan
                .iter()
                .any(|detail| detail.contains("entities_scope_type")),
            "expected entities_scope_type index, got {type_plan:?}"
        );

        let from_plan = query_plan_details(
            &workspace.connection,
            "SELECT record_id FROM relations WHERE from_id = ?1 ORDER BY record_id LIMIT ?2",
            &[
                rusqlite::types::Value::Blob(vec![1_u8; 16]),
                rusqlite::types::Value::Integer(10),
            ],
        );
        assert!(
            from_plan
                .iter()
                .any(|detail| detail.contains("relations_from")),
            "expected relations_from index, got {from_plan:?}"
        );

        let doc_plan = query_plan_details(
            &workspace.connection,
            "SELECT record_id FROM documents WHERE scope = ?1 ORDER BY record_id LIMIT ?2",
            &[
                rusqlite::types::Value::Text(scope().to_string()),
                rusqlite::types::Value::Integer(10),
            ],
        );
        assert!(
            doc_plan
                .iter()
                .any(|detail| detail.contains("documents_scope_path")),
            "expected documents_scope_path index, got {doc_plan:?}"
        );
    }

    #[test]
    fn opening_pre_projection_workspace_migrates_and_populates_tables() {
        let temp = tempfile::tempdir().expect("temp");
        let mut workspace =
            super::super::Workspace::create(temp.path(), config(1_000)).expect("create");
        let base = workspace.current_revision().expect("base");
        let entity_id = mneme_core::RecordId::from_bytes([0x11; 16]);
        let entity_rev = mneme_core::RevisionId::from_bytes([0x12; 16]);
        let doc_id = mneme_core::RecordId::from_bytes([0x21; 16]);
        let doc_rev = mneme_core::RevisionId::from_bytes([0x22; 16]);
        let source_id = mneme_core::fixtures::source_revision_id();
        let source_rev = mneme_core::RevisionId::from_bytes([0x32; 16]);
        let source_bytes = b"= Cedar Note\n\nBody.\n".to_vec();
        let source_digest = mneme_core::ContentDigest::of_source_bytes(&source_bytes);
        let retained = mneme_core::RetainedSource::new(
            source_digest,
            source_bytes.len() as u64,
            "text/asciidoc",
        )
        .expect("retained source");
        workspace
            .commit(crate::CommitCommand {
                base,
                actor: "tester".to_owned(),
                scope: scope(),
                idempotency_key: "seed-migration".to_owned(),
                records: vec![
                    crate::RecordDraft {
                        schema_version: 3,
                        kind: mneme_core::RecordKind::Entity,
                        record_id: entity_id,
                        revision_id: entity_rev,
                        predecessor: None,
                        scope: scope(),
                        payload: mneme_core::Payload::new([
                            (
                                mneme_core::Symbol::from("entity-type"),
                                mneme_core::Value::symbol("bookmark"),
                            ),
                            (
                                mneme_core::Symbol::from("label"),
                                mneme_core::Value::string("Migrated Entity"),
                            ),
                            (
                                mneme_core::Symbol::from("properties"),
                                mneme_core::Value::symbol_dictionary([(
                                    mneme_core::Symbol::from("external-id"),
                                    mneme_core::Value::string("x:42"),
                                )]),
                            ),
                        ]),
                    },
                    crate::RecordDraft {
                        schema_version: 3,
                        kind: mneme_core::RecordKind::SourceRevision,
                        record_id: source_id,
                        revision_id: source_rev,
                        predecessor: None,
                        scope: scope(),
                        payload: mneme_core::Payload::new([
                            (
                                mneme_core::Symbol::from("content"),
                                mneme_core::SourceContent::Retained(retained).to_value(),
                            ),
                            (
                                mneme_core::Symbol::from("acquisition"),
                                mneme_core::Value::symbol("authored"),
                            ),
                        ]),
                    },
                    crate::RecordDraft {
                        schema_version: 3,
                        kind: mneme_core::RecordKind::Document,
                        record_id: doc_id,
                        revision_id: doc_rev,
                        predecessor: None,
                        scope: scope(),
                        payload: mneme_core::Payload::new([
                            (
                                mneme_core::Symbol::from("title"),
                                mneme_core::Value::string("Migrated Doc"),
                            ),
                            (
                                mneme_core::Symbol::from("path"),
                                mneme_core::Value::string("notes/migrated.adoc"),
                            ),
                            (
                                mneme_core::Symbol::from("source-revision"),
                                mneme_core::Reference::pinned(
                                    source_id,
                                    source_rev,
                                    mneme_core::RecordKind::SourceRevision,
                                )
                                .to_value(),
                            ),
                        ]),
                    },
                ],
                source_blobs: vec![crate::SourceBlobDraft::inline(
                    source_bytes,
                    mneme_core::Symbol::from("text/asciidoc"),
                )],
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("commit");

        workspace
            .connection
            .execute_batch(
                "DROP TABLE entities;
                 DROP TABLE relations;
                 DROP TABLE documents;",
            )
            .expect("drop projection tables");
        workspace
            .connection
            .execute(
                "DELETE FROM meta WHERE key = ?1",
                rusqlite::params![super::super::META_METADATA_PROJECTION_FORMAT],
            )
            .expect("delete migration marker");
        drop(workspace);

        let reopened = super::super::Workspace::open(temp.path(), config(2_000)).expect("reopen");
        let entities = reopened
            .query_entities(&EntityQuery {
                scope: None,
                entity_type: None,
                external_id: Some("x:42".to_owned()),
                after: None,
                limit: None,
            })
            .expect("query entities");
        assert_eq!(entities.items.len(), 1);
        assert_eq!(entities.items[0].record_id, entity_id);
        assert_eq!(entities.items[0].label, "Migrated Entity");

        let docs = reopened
            .query_documents(&DocumentQuery::default())
            .expect("query documents");
        assert_eq!(docs.items.len(), 1);
        assert_eq!(docs.items[0].record_id, doc_id);
        assert_eq!(docs.items[0].path.as_deref(), Some("notes/migrated.adoc"));
        assert_eq!(docs.items[0].source_revision_id, Some(source_id));
    }

    #[test]
    fn recover_rebuilds_corrupted_projection_tables_from_ledger() {
        let temp = tempfile::tempdir().expect("temp");
        let mut workspace =
            super::super::Workspace::create(temp.path(), config(1_000)).expect("create");
        let base = workspace.current_revision().expect("base");
        let entity_id = mneme_core::RecordId::from_bytes([0x41; 16]);
        let entity_rev = mneme_core::RevisionId::from_bytes([0x42; 16]);
        workspace
            .commit(crate::CommitCommand {
                base,
                actor: "tester".to_owned(),
                scope: scope(),
                idempotency_key: "seed-recover".to_owned(),
                records: vec![crate::RecordDraft {
                    schema_version: 3,
                    kind: mneme_core::RecordKind::Entity,
                    record_id: entity_id,
                    revision_id: entity_rev,
                    predecessor: None,
                    scope: scope(),
                    payload: mneme_core::Payload::new([
                        (
                            mneme_core::Symbol::from("entity-type"),
                            mneme_core::Value::symbol("topic"),
                        ),
                        (
                            mneme_core::Symbol::from("label"),
                            mneme_core::Value::string("Recoverable"),
                        ),
                        (
                            mneme_core::Symbol::from("properties"),
                            mneme_core::Value::symbol_dictionary([(
                                mneme_core::Symbol::from("external-id"),
                                mneme_core::Value::string("rec:1"),
                            )]),
                        ),
                    ]),
                }],
                source_blobs: Vec::new(),
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("commit");

        workspace
            .connection
            .execute_batch("DELETE FROM entities;")
            .expect("corrupt projection");
        assert!(
            workspace
                .query_entities(&EntityQuery::default())
                .expect("empty before recover")
                .items
                .is_empty()
        );

        workspace.recover().expect("recover");
        let entities = workspace
            .query_entities(&EntityQuery {
                scope: None,
                entity_type: None,
                external_id: Some("rec:1".to_owned()),
                after: None,
                limit: None,
            })
            .expect("query after recover");
        assert_eq!(entities.items.len(), 1);
        assert_eq!(entities.items[0].record_id, entity_id);
        assert_eq!(entities.items[0].label, "Recoverable");
    }
}
