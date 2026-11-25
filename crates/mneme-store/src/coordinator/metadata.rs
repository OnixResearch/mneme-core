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

/// Upgrade an existing ledger in place by creating and populating the metadata
/// projection tables from verified active record blobs.
pub(super) fn migrate_metadata_projection(
    root: &std::path::Path,
    connection: &mut rusqlite::Connection,
) -> crate::error::Result<()> {
    if let Some(marker) =
        super::meta_blob_optional(connection, super::META_METADATA_PROJECTION_FORMAT)?
    {
        if marker.as_slice() == b"1".as_slice() {
            return Ok(());
        }
        return Err(crate::error::Failure::UnsupportedLayout(format!(
            "ledger metadata projection format {} is not supported",
            String::from_utf8_lossy(&marker)
        )));
    }
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    if let Some(marker) =
        super::meta_blob_optional(&transaction, super::META_METADATA_PROJECTION_FORMAT)?
    {
        if marker.as_slice() == b"1".as_slice() {
            transaction.commit()?;
            return Ok(());
        }
        return Err(crate::error::Failure::UnsupportedLayout(format!(
            "ledger metadata projection format {} is not supported",
            String::from_utf8_lossy(&marker)
        )));
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
    let mut statement = transaction.prepare(
        "SELECT r.record_id, r.revision_id, r.kind, r.envelope_digest, r.payload_digest,
                r.full_digest
         FROM record_membership m
         JOIN records r ON r.record_id = m.record_id AND r.revision_id = m.revision_id
         WHERE m.last_sequence IS NULL
           AND r.kind IN ('entity', 'relation', 'document')
         ORDER BY r.record_id",
    )?;
    let rows = statement
        .query_map([], |row| {
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
    drop(statement);

    for entry in rows {
        let (record_id, revision_id, kind) = super::membership_record(&entry, context)?;
        if forgotten.matches(record_id, revision_id) {
            continue;
        }
        let (_, _, _, envelope_digest, payload_digest, full_digest) = entry;
        let digest = super::digest_with(
            &envelope_digest,
            "preserves-canonical-binary-v1",
            "full-record",
            context,
        )?;
        if digest.as_bytes().as_slice() != full_digest.as_slice() {
            return Err(crate::error::Failure::Integrity {
                revision: context,
                reason: format!("record blob {digest} does not match its ledger identity"),
            });
        }
        let payload_digest = super::digest_with(
            &payload_digest,
            "preserves-canonical-binary-v1",
            "payload",
            context,
        )?;
        let bytes = crate::payload::read(root, digest).map_err(|error| {
            crate::error::Failure::Integrity {
                revision: context,
                reason: format!("record blob {digest} is unavailable: {error}"),
            }
        })?;
        let record = super::decode_envelope(&bytes, digest, context)?;
        let identity = super::EnvelopeIdentity {
            record_id,
            revision_id,
            kind,
            full_digest: &full_digest,
        };
        super::require_envelope_identity(&identity, &record, digest, payload_digest, context)?;
        upsert_record(transaction, &record)?;
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
        let limit = bounded_page_limit(query.limit)?;
        let context = self.current_revision()?;
        let transaction = self.connection.unchecked_transaction()?;
        let page = query_entities_in(&transaction, query, limit, context)?;
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
        let limit = bounded_page_limit(query.limit)?;
        let context = self.current_revision()?;
        let transaction = self.connection.unchecked_transaction()?;
        let page = query_relations_in(&transaction, query, limit, context)?;
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
        let limit = bounded_page_limit(query.limit)?;
        let context = self.current_revision()?;
        let transaction = self.connection.unchecked_transaction()?;
        let page = query_documents_in(&transaction, query, limit, context)?;
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
        let loaded = self.current_record_in(&transaction, record_id, context, generation);
        match loaded {
            Ok(record) => {
                transaction.commit()?;
                let after = self.eligibility_generation()?;
                if after != generation {
                    return Err(crate::error::Failure::BarrierAdvanced {
                        pinned: generation,
                        current: after,
                    });
                }
                Ok(record)
            }
            Err(error) => {
                drop(transaction);
                Err(self.explain_barrier(error, generation))
            }
        }
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
        use rusqlite::OptionalExtension;
        type CurrentRecordRow = (Vec<u8>, String, Vec<u8>, Vec<u8>, Vec<u8>);
        let row: Option<CurrentRecordRow> = connection
            .query_row(
                "SELECT r.revision_id, r.kind, r.envelope_digest, r.payload_digest, r.full_digest
                 FROM record_membership m
                 JOIN records r ON r.record_id = m.record_id AND r.revision_id = m.revision_id
                 WHERE m.record_id = ?1 AND m.last_sequence IS NULL",
                rusqlite::params![record_id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((rev_bytes, kind_str, envelope_digest, payload_digest, full_digest)) = row else {
            return Ok(None);
        };
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
        let envelope = self.load_verified_record_envelope(
            super::VerifiedRecordEnvelopeInput {
                record_id,
                revision_id,
                kind,
                envelope_digest: &envelope_digest,
                payload_digest: &payload_digest,
                full_digest: &full_digest,
                revision: context,
                generation,
                lengths: &lengths,
            },
            super::PayloadCheck::Cached,
        )?;
        Ok(Some(envelope))
    }
}

fn bounded_page_limit(requested: Option<u32>) -> crate::error::Result<u32> {
    let limit = requested.unwrap_or(MAX_METADATA_PAGE_SIZE);
    if limit == 0 || limit > MAX_METADATA_PAGE_SIZE {
        return Err(crate::error::Failure::InvalidCommand(format!(
            "metadata page limit must be in 1..={MAX_METADATA_PAGE_SIZE}, got {limit}"
        )));
    }
    Ok(limit)
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
        _ => Ok(()),
    }
}

fn upsert_entity(
    transaction: &rusqlite::Transaction<'_>,
    record: &mneme_core::RecordEnvelope,
) -> crate::error::Result<()> {
    let entity_type = record
        .payload
        .get("entity-type")
        .and_then(mneme_core::Value::as_symbol)
        .map(|symbol| symbol.as_str().to_owned())
        .unwrap_or_default();
    let label = record
        .payload
        .get("label")
        .and_then(mneme_core::Value::as_string)
        .unwrap_or("")
        .to_owned();
    let external_id = extract_external_id(&record.payload);
    transaction.execute(
        "INSERT OR REPLACE INTO entities
             (record_id, revision_id, scope, entity_type, label, external_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
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
    let relation_type = record
        .payload
        .get("relation-type")
        .and_then(mneme_core::Value::as_symbol)
        .map(|symbol| symbol.as_str().to_owned())
        .unwrap_or_default();
    let from_id = extract_reference_target(record.payload.get("from"));
    let to_id = extract_reference_target(record.payload.get("to"));
    transaction.execute(
        "INSERT OR REPLACE INTO relations
             (record_id, revision_id, scope, relation_type, from_id, to_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
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
    let path = record
        .payload
        .get("path")
        .and_then(mneme_core::Value::as_string)
        .map(str::to_owned);
    let title = record
        .payload
        .get("title")
        .and_then(mneme_core::Value::as_string)
        .unwrap_or("")
        .to_owned();
    let source_revision_id = extract_reference_target(record.payload.get("source-revision"));
    transaction.execute(
        "INSERT OR REPLACE INTO documents
             (record_id, revision_id, scope, path, title, source_revision_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
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

    fn push_text(&mut self, column: &str, op: &str, value: String) {
        let index = self.params.len() + 1;
        self.clauses.push(format!("{column} {op} ?{index}"));
        self.params.push(rusqlite::types::Value::Text(value));
    }

    fn push_blob(&mut self, column: &str, op: &str, value: Vec<u8>) {
        let index = self.params.len() + 1;
        self.clauses.push(format!("{column} {op} ?{index}"));
        self.params.push(rusqlite::types::Value::Blob(value));
    }

    fn push_limit(&mut self, limit_plus_one: u32) -> usize {
        let index = self.params.len() + 1;
        self.params
            .push(rusqlite::types::Value::Integer(i64::from(limit_plus_one)));
        index
    }

    fn where_sql(&self) -> String {
        if self.clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", self.clauses.join(" AND "))
        }
    }
}

fn query_entities_in(
    connection: &rusqlite::Connection,
    query: &EntityQuery,
    limit: u32,
    context: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<MetadataPage<EntityMetadata>> {
    let mut filter = SqlFilterBuilder::new();
    if let Some(scope) = &query.scope {
        filter.push_text("scope", "=", scope.to_string());
    }
    if let Some(entity_type) = &query.entity_type {
        filter.push_text("entity_type", "=", entity_type.clone());
    }
    if let Some(external_id) = &query.external_id {
        filter.push_text("external_id", "=", external_id.clone());
    }
    if let Some(after) = query.after {
        filter.push_blob("record_id", ">", after.as_bytes().to_vec());
    }
    let where_sql = filter.where_sql();
    let limit_param = filter.push_limit(limit.saturating_add(1));
    let sql = format!(
        "SELECT record_id, revision_id, scope, entity_type, label, external_id
         FROM entities
         {where_sql}
         ORDER BY record_id
         LIMIT ?{limit_param}"
    );
    let mut statement = connection.prepare(&sql)?;
    let rows = statement
        .query_map(rusqlite::params_from_iter(filter.params.iter()), |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut items = Vec::with_capacity(rows.len().min(limit as usize));
    let mut has_more = false;
    for (record_bytes, revision_bytes, scope_text, entity_type, label, external_id) in rows {
        if items.len() == limit as usize {
            has_more = true;
            break;
        }
        items.push(EntityMetadata {
            record_id: super::record_id_from_blob(&record_bytes, context)?,
            revision_id: super::revision_id_from_blob(&revision_bytes, context)?,
            scope: parse_scope(&scope_text, context)?,
            entity_type,
            label,
            external_id,
        });
    }
    let next_after = if has_more {
        items.last().map(|item| item.record_id)
    } else {
        None
    };
    Ok(MetadataPage {
        items,
        has_more,
        next_after,
    })
}

fn query_relations_in(
    connection: &rusqlite::Connection,
    query: &RelationQuery,
    limit: u32,
    context: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<MetadataPage<RelationMetadata>> {
    let mut filter = SqlFilterBuilder::new();
    if let Some(scope) = &query.scope {
        filter.push_text("scope", "=", scope.to_string());
    }
    if let Some(relation_type) = &query.relation_type {
        filter.push_text("relation_type", "=", relation_type.clone());
    }
    if let Some(from_id) = query.from_id {
        filter.push_blob("from_id", "=", from_id.as_bytes().to_vec());
    }
    if let Some(to_id) = query.to_id {
        filter.push_blob("to_id", "=", to_id.as_bytes().to_vec());
    }
    if let Some(after) = query.after {
        filter.push_blob("record_id", ">", after.as_bytes().to_vec());
    }
    let where_sql = filter.where_sql();
    let limit_param = filter.push_limit(limit.saturating_add(1));
    let sql = format!(
        "SELECT record_id, revision_id, scope, relation_type, from_id, to_id
         FROM relations
         {where_sql}
         ORDER BY record_id
         LIMIT ?{limit_param}"
    );
    let mut statement = connection.prepare(&sql)?;
    let rows = statement
        .query_map(rusqlite::params_from_iter(filter.params.iter()), |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut items = Vec::with_capacity(rows.len().min(limit as usize));
    let mut has_more = false;
    for (record_bytes, revision_bytes, scope_text, relation_type, from_bytes, to_bytes) in rows {
        if items.len() == limit as usize {
            has_more = true;
            break;
        }
        items.push(RelationMetadata {
            record_id: super::record_id_from_blob(&record_bytes, context)?,
            revision_id: super::revision_id_from_blob(&revision_bytes, context)?,
            scope: parse_scope(&scope_text, context)?,
            relation_type,
            from_id: from_bytes
                .as_deref()
                .map(|bytes| super::record_id_from_blob(bytes, context))
                .transpose()?,
            to_id: to_bytes
                .as_deref()
                .map(|bytes| super::record_id_from_blob(bytes, context))
                .transpose()?,
        });
    }
    let next_after = if has_more {
        items.last().map(|item| item.record_id)
    } else {
        None
    };
    Ok(MetadataPage {
        items,
        has_more,
        next_after,
    })
}

fn query_documents_in(
    connection: &rusqlite::Connection,
    query: &DocumentQuery,
    limit: u32,
    context: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<MetadataPage<DocumentMetadata>> {
    let mut filter = SqlFilterBuilder::new();
    if let Some(scope) = &query.scope {
        filter.push_text("scope", "=", scope.to_string());
    }
    if let Some(path) = &query.path {
        filter.push_text("path", "=", path.clone());
    }
    if let Some(after) = query.after {
        filter.push_blob("record_id", ">", after.as_bytes().to_vec());
    }
    let where_sql = filter.where_sql();
    let limit_param = filter.push_limit(limit.saturating_add(1));
    let sql = format!(
        "SELECT record_id, revision_id, scope, path, title, source_revision_id
         FROM documents
         {where_sql}
         ORDER BY record_id
         LIMIT ?{limit_param}"
    );
    let mut statement = connection.prepare(&sql)?;
    let rows = statement
        .query_map(rusqlite::params_from_iter(filter.params.iter()), |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut items = Vec::with_capacity(rows.len().min(limit as usize));
    let mut has_more = false;
    for (record_bytes, revision_bytes, scope_text, path, title, source_bytes) in rows {
        if items.len() == limit as usize {
            has_more = true;
            break;
        }
        items.push(DocumentMetadata {
            record_id: super::record_id_from_blob(&record_bytes, context)?,
            revision_id: super::revision_id_from_blob(&revision_bytes, context)?,
            scope: parse_scope(&scope_text, context)?,
            path,
            title,
            source_revision_id: source_bytes
                .as_deref()
                .map(|bytes| super::record_id_from_blob(bytes, context))
                .transpose()?,
        });
    }
    let next_after = if has_more {
        items.last().map(|item| item.record_id)
    } else {
        None
    };
    Ok(MetadataPage {
        items,
        has_more,
        next_after,
    })
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

    fn config(at: i64) -> super::super::WorkspaceConfig {
        super::super::WorkspaceConfig {
            clock: Box::new(crate::timekeeper::FixedClock::new(
                mneme_core::Timestamp::from_nanos(at),
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
                source_blobs: vec![crate::SourceBlobDraft {
                    bytes: source_bytes,
                    media_type: mneme_core::Symbol::from("text/asciidoc"),
                }],
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("commit");

        // Simulate an existing workspace created before the metadata projection existed.
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
                external_id: Some("x:42".to_owned()),
                ..EntityQuery::default()
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
                external_id: Some("rec:1".to_owned()),
                ..EntityQuery::default()
            })
            .expect("query after recover");
        assert_eq!(entities.items.len(), 1);
        assert_eq!(entities.items[0].record_id, entity_id);
        assert_eq!(entities.items[0].label, "Recoverable");
    }
}
