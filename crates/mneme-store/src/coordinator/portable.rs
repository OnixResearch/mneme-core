//! Retention state for a portable restore.
//!
//! Copy-based restore applies a genesis-bound suppression ledger to an existing
//! workspace copy. A portable restore creates a new workspace with a new
//! genesis, so it installs the exported suppression and pruning decisions as
//! typed rows in that new ledger instead. Forgotten identities, forgotten
//! revisions, and forgotten content digests are installed before any content is
//! imported, so a replay of exported history can never resurrect what the
//! source workspace forgot.

use crate::error::Failure;
use crate::portable::{
    MAX_PORTABLE_REVISIONS, OmissionCounts, PortablePruning, PortableRetentionExport,
    PortableRetentionState, PortableSuppression, portable_retained_source,
};

impl super::Workspace {
    /// Gather the retention decisions a portable backup of `scope` must carry.
    pub(crate) fn export_portable_retention(
        &self,
        scope: &mneme_core::ScopeId,
    ) -> crate::error::Result<PortableRetentionExport> {
        let context = self.current_revision()?;
        let generation = self.eligibility_generation()?;
        // Pruning decisions are derived from current source bindings, which the
        // recovery reader owns; read them before opening this transaction.
        let prunings = self.ledger_prunings()?;
        let transaction = self.connection.unchecked_transaction()?;
        let loaded = self.export_portable_retention_in(
            &transaction,
            scope,
            context,
            generation,
            &prunings,
        );
        match loaded {
            Ok(export) => {
                transaction.commit()?;
                Ok(export)
            }
            Err(error) => {
                drop(transaction);
                Err(error)
            }
        }
    }

    /// Read retention rows from one ledger state.
    fn export_portable_retention_in(
        &self,
        connection: &rusqlite::Connection,
        scope: &mneme_core::ScopeId,
        context: mneme_core::WorkspaceRevisionId,
        generation: u64,
        prunings: &[super::recovery::RestoredPruning],
    ) -> crate::error::Result<PortableRetentionExport> {
        let scope_text = scope.to_string();
        let mut forgotten_content = std::collections::BTreeSet::new();
        for digest in super::sweep::forgotten_content_digests(connection, scope)? {
            let digest: [u8; 32] = digest.try_into().map_err(|_| {
                Failure::PortableArchive(
                    "a forgotten content digest is not 32 bytes".to_owned(),
                )
            })?;
            forgotten_content.insert(digest);
        }
        let mut operation_scopes = std::collections::BTreeMap::new();
        {
            let mut statement = connection.prepare(
                "SELECT operation_id, scope FROM retention_operations",
            )?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let operation_id: String = row.get(0)?;
                let stored_scope: String = row.get(1)?;
                operation_scopes.insert(operation_id, stored_scope);
            }
        }
        let mut omissions = OmissionCounts::default();
        let mut suppressions: std::collections::BTreeMap<
            (
                mneme_core::RecordId,
                Option<mneme_core::RevisionId>,
            ),
            PortableSuppression,
        > = std::collections::BTreeMap::new();
        for suppression in super::sweep::all_suppressions(connection)? {
            let scopes = record_scopes_in(connection, suppression.target)?;
            let operation_allows = match operation_scopes.get(&suppression.operation_id) {
                Some(operation_scope) => *operation_scope == scope_text,
                None => true,
            };
            // A target with retained revisions outside this scope stays out of
            // the archive even when the suppression was issued from this
            // scope, so a record promoted or moved to another scope is never
            // disclosed by its suppression row.
            let target_allows = if scopes.is_empty() {
                operation_scopes
                    .get(&suppression.operation_id)
                    .is_some_and(|operation_scope| *operation_scope == scope_text)
            } else {
                scopes.iter().all(|stored| *stored == scope_text)
            };
            let include = operation_allows && target_allows;
            if !include {
                omissions.bump("foreign-suppression", 1);
                continue;
            }
            let candidate = PortableSuppression {
                target: suppression.target,
                revision: suppression.revision,
                target_kind: suppression.target_kind,
                mode: suppression.mode,
                content_digest: suppression.content_digest,
                generation: suppression.generation,
            };
            // Repeated forget operations may name the same identity. The
            // archive carries one row per target so restore's primary key is
            // unambiguous; the forgotten mode and the newest generation win.
            match suppressions.entry((candidate.target, candidate.revision)) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(candidate);
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let existing = entry.get_mut();
                    if candidate.mode > existing.mode {
                        existing.mode = candidate.mode;
                        existing.target_kind = candidate.target_kind;
                    }
                    if candidate.generation > existing.generation {
                        existing.generation = candidate.generation;
                    }
                    if existing.content_digest.is_none() {
                        existing.content_digest = candidate.content_digest;
                    }
                }
            }
        }
        let suppressions: Vec<PortableSuppression> = suppressions.into_values().collect();
        for suppression in &suppressions {
            if suppression.mode != crate::lifecycle::SuppressionMode::Forgotten {
                continue;
            }
            if suppression.revision.is_none() {
                omissions.bump("forgotten-record", 1);
            } else {
                omissions.bump("forgotten-revision", 1);
            }
        }

        let mut pruning_rows = Vec::new();
        let mut pruning_targets = std::collections::BTreeSet::new();
        let mut pruning_digests = std::collections::BTreeSet::new();
        for pruning in prunings {
            let revisions = match self.record_revisions_in(
                connection,
                pruning.source,
                context,
                generation,
            ) {
                Ok(revisions) => revisions,
                Err(Failure::RetentionSuppressed { .. }) => {
                    omissions.bump("pruning-forgotten-source", 1);
                    continue;
                }
                Err(error) => return Err(error),
            };
            let mut in_scope = false;
            let mut matches = Vec::new();
            for revision in &revisions {
                if revision.scope != *scope {
                    continue;
                }
                in_scope = true;
                if portable_retained_source(revision)?
                    .is_some_and(|retained| retained.digest() == pruning.digest)
                {
                    matches.push(revision.revision_id);
                }
            }
            if matches.is_empty() {
                omissions.bump(
                    if in_scope {
                        "pruning-without-revision"
                    } else {
                        "pruning-foreign-scope"
                    },
                    1,
                );
                continue;
            }
            pruning_digests.insert(*pruning.digest.as_bytes());
            for revision in matches {
                if pruning_targets.insert((pruning.source, revision)) {
                    pruning_rows.push(PortablePruning {
                        source: pruning.source,
                        revision,
                        digest: pruning.digest,
                    });
                }
            }
        }
        if suppressions.len().saturating_add(pruning_rows.len()) > MAX_PORTABLE_REVISIONS {
            return Err(Failure::HistoryLimitExceeded);
        }
        Ok(PortableRetentionExport {
            state: PortableRetentionState {
                generation,
                suppressions,
                prunings: pruning_rows,
            },
            forgotten_content,
            pruning_targets,
            pruning_digests,
            omissions,
        })
    }

    /// Install exported retention decisions into a fresh restore target.
    ///
    /// Only a workspace still at its genesis sequence is accepted. The
    /// suppression rows and the advanced generation are written in one
    /// transaction, so an interrupted restore never serves content under a
    /// generation that has not yet hidden forgotten records.
    pub(crate) fn install_portable_retention(
        &mut self,
        scope: &mneme_core::ScopeId,
        state: &PortableRetentionState,
    ) -> crate::error::Result<()> {
        let sequence = self.current_sequence()?;
        if sequence != 0 {
            return Err(Failure::InvalidCommand(
                "a portable restore target must be a fresh workspace".to_owned(),
            ));
        }
        let current_generation = self.eligibility_generation()?;
        if state.generation < current_generation || state.generation == 0 {
            return Err(Failure::InvalidCommand(
                "portable retention state does not advance the target generation".to_owned(),
            ));
        }
        if state.generation > i64::MAX as u64 {
            return Err(Failure::HistoryLimitExceeded);
        }
        if state
            .suppressions
            .len()
            .saturating_add(state.prunings.len())
            > MAX_PORTABLE_REVISIONS
        {
            return Err(Failure::HistoryLimitExceeded);
        }
        let mut rows = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for suppression in &state.suppressions {
            validate_installed_suppression(suppression, state.generation)?;
            if !seen.insert((suppression.target, suppression.revision)) {
                return Err(Failure::PortableArchive(
                    "portable retention state repeats one suppression target".to_owned(),
                ));
            }
            rows.push(suppression.clone());
        }
        for pruning in &state.prunings {
            if pruning.digest.profile() != mneme_core::EncodingProfile::RawBytesV1
                || pruning.digest.boundary() != mneme_core::ValueBoundary::SourceBytes
            {
                return Err(Failure::PortableArchive(
                    "portable pruning digest is not a raw source digest".to_owned(),
                ));
            }
            if !seen.insert((pruning.source, Some(pruning.revision))) {
                // An explicit suppression for the same revision already wins;
                // the pruning adds no second row for one primary key.
                continue;
            }
            rows.push(PortableSuppression {
                target: pruning.source,
                revision: Some(pruning.revision),
                target_kind: "source-revision".to_owned(),
                mode: crate::lifecycle::SuppressionMode::Forgotten,
                content_digest: Some(pruning.digest),
                generation: state.generation,
            });
        }
        let genesis = self.genesis_revision()?;
        let now_ns = self.clock.now().nanos();
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if !rows.is_empty() {
            insert_portable_operation(
                &transaction,
                scope,
                genesis,
                state.generation,
                now_ns,
            )?;
        }
        for row in &rows {
            insert_portable_suppression(&transaction, row)?;
        }
        super::set_meta_u64(&transaction, super::META_GENERATION, state.generation)?;
        transaction.commit()?;
        self.facts().align(state.generation);
        Ok(())
    }
}

/// The scopes in which any retained revision of one record was recorded.
fn record_scopes_in(
    connection: &rusqlite::Connection,
    record: mneme_core::RecordId,
) -> crate::error::Result<std::collections::BTreeSet<String>> {
    let mut statement =
        connection.prepare("SELECT DISTINCT scope FROM records WHERE record_id = ?1")?;
    let rows = statement.query_map(
        rusqlite::params![record.as_bytes().as_slice()],
        |row| row.get::<_, String>(0),
    )?;
    let mut scopes = std::collections::BTreeSet::new();
    for row in rows {
        scopes.insert(row?);
    }
    Ok(scopes)
}

/// Revalidate one suppression before it becomes durable engine state.
fn validate_installed_suppression(
    suppression: &PortableSuppression,
    generation: u64,
) -> crate::error::Result<()> {
    if suppression.generation == 0 || suppression.generation > generation {
        return Err(Failure::PortableArchive(
            "portable suppression generation is outside the archive generation".to_owned(),
        ));
    }
    if suppression.target_kind.is_empty()
        || suppression.target_kind.len() > 64
        || !suppression
            .target_kind
            .bytes()
            .all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
            })
    {
        return Err(Failure::PortableArchive(
            "portable suppression target kind is malformed".to_owned(),
        ));
    }
    if let Some(digest) = suppression.content_digest
        && (digest.profile() != mneme_core::EncodingProfile::RawBytesV1
            || digest.boundary() != mneme_core::ValueBoundary::SourceBytes)
    {
        return Err(Failure::PortableArchive(
            "portable suppression digest is not a raw source digest".to_owned(),
        ));
    }
    Ok(())
}

/// One synthetic restore operation owning every installed suppression.
fn insert_portable_operation(
    transaction: &rusqlite::Transaction<'_>,
    scope: &mneme_core::ScopeId,
    genesis: mneme_core::WorkspaceRevisionId,
    generation: u64,
    now_ns: i64,
) -> crate::error::Result<()> {
    let operation_id = "portable-restore";
    transaction.execute(
        "INSERT INTO retention_operations (operation_id, operation_kind, actor, scope,
             policy_version, idempotency_key, request_digest, state, generation,
             outcome_revision, outcome_sequence, retained_metadata, created_at_ns,
             updated_at_ns)
         VALUES (?1, 'restore', 'portable-restore', ?2, 'portable-backup-v1', ?1, ?3,
             'complete', ?4, ?5, 0, '', ?6, ?6)
         ON CONFLICT(operation_id) DO UPDATE SET state = 'complete',
             generation = excluded.generation,
             outcome_revision = excluded.outcome_revision,
             retained_metadata = excluded.retained_metadata,
             updated_at_ns = excluded.updated_at_ns",
        rusqlite::params![
            operation_id,
            scope.to_string(),
            [0_u8; 32].as_slice(),
            super::db_i64(generation, "generation")?,
            genesis.as_bytes().as_slice(),
            now_ns,
        ],
    )?;
    Ok(())
}

/// Insert one suppression row under the synthetic restore operation.
fn insert_portable_suppression(
    transaction: &rusqlite::Transaction<'_>,
    suppression: &PortableSuppression,
) -> crate::error::Result<()> {
    transaction.execute(
        "INSERT INTO retention_suppressions (operation_id, target_id, target_revision,
             target_kind, mode, content_digest, generation)
         VALUES ('portable-restore', ?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            suppression.target.as_bytes().as_slice(),
            suppression
                .revision
                .map(|revision| revision.as_bytes().to_vec())
                .unwrap_or_default(),
            suppression.target_kind,
            suppression.mode.as_str(),
            suppression
                .content_digest
                .map(|digest| digest.as_bytes().to_vec()),
            super::db_i64(suppression.generation, "generation")?,
        ],
    )?;
    Ok(())
}
