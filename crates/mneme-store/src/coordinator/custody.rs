//! Retention state for a portable restore.
//!
//! Copy-based restore applies a genesis-bound suppression ledger to an existing
//! workspace copy. A portable restore creates a new workspace with a new
//! genesis, so it installs the exported suppression and pruning decisions as
//! typed rows in that new ledger instead. Forgotten identities, forgotten
//! revisions, and forgotten content digests are installed before any content is
//! imported, so a replay of exported history can never resurrect what the
//! source workspace forgot.

impl super::Workspace {
    /// Gather the retention decisions a portable backup of `scope` must carry.
    pub(crate) fn export_portable_retention(
        &self,
        scope: &mneme_core::ScopeId,
    ) -> crate::error::Result<crate::portability::PortableRetentionExport> {
        let context = self.current_revision()?;
        let generation = self.eligibility_generation()?;
        // Pruning decisions are derived from current source bindings, which the
        // recovery reader owns; read them before opening this transaction.
        let prunings = self.ledger_prunings()?;
        let transaction = self.connection.unchecked_transaction()?;
        let loaded =
            self.export_portable_retention_in(&transaction, scope, context, generation, &prunings);
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
    ) -> crate::error::Result<crate::portability::PortableRetentionExport> {
        let mut omissions = crate::portability::OmissionCounts::default();
        let forgotten_content = forgotten_digests(connection, scope)?;
        let suppressions = scoped_suppressions(connection, scope, &mut omissions)?;
        let mut plan = PruningPlan {
            rows: Vec::with_capacity(
                prunings
                    .len()
                    .min(crate::portability::MAX_PORTABLE_REVISIONS),
            ),
            targets: std::collections::BTreeSet::new(),
            digests: std::collections::BTreeSet::new(),
        };
        for pruning in prunings {
            let revisions =
                match self.record_revisions_in(connection, pruning.source, context, generation) {
                    Ok(revisions) => revisions,
                    Err(crate::error::Failure::RetentionSuppressed { .. }) => {
                        omissions.bump("pruning-forgotten-source", 1);
                        continue;
                    }
                    Err(error) => return Err(error),
                };
            if let Some(reason) = plan.add(scope, pruning, &revisions)? {
                omissions.bump(reason, 1);
            }
        }
        if suppressions.len().saturating_add(plan.rows.len())
            > crate::portability::MAX_PORTABLE_REVISIONS
        {
            return Err(crate::error::Failure::HistoryLimitExceeded);
        }
        Ok(crate::portability::PortableRetentionExport {
            state: crate::portability::PortableRetentionState {
                generation,
                suppressions,
                prunings: plan.rows,
            },
            forgotten_content,
            pruning_targets: plan.targets,
            pruning_digests: plan.digests,
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
        state: &crate::portability::PortableRetentionState,
    ) -> crate::error::Result<()> {
        if self.current_sequence()? != 0 {
            return Err(crate::error::Failure::InvalidCommand(
                "a portable restore target must be a fresh workspace".to_owned(),
            ));
        }
        let current_generation = self.eligibility_generation()?;
        if state.generation < current_generation || state.generation == 0 {
            return Err(crate::error::Failure::InvalidCommand(
                "portable retention state does not advance the target generation".to_owned(),
            ));
        }
        let _changed = self.merge_portable_retention(scope, state)?;
        Ok(())
    }

    /// Inflationary CALM Stratum M merge of portable retention barriers at any
    /// workspace sequence (`sequence >= 0`).
    ///
    /// Merges incoming suppressions and prunings using
    /// [`mneme_kernel::calm::join_suppression`] (`None < Withdrawn < Forgotten`,
    /// `max(generation)`), removes newly forgotten rows from metadata
    /// projections inside the same transaction, and advances the eligibility
    /// generation barrier monotonically. Returns `true` if any suppression or
    /// generation advanced.
    pub(crate) fn merge_portable_retention(
        &mut self,
        scope: &mneme_core::ScopeId,
        state: &crate::portability::PortableRetentionState,
    ) -> crate::error::Result<bool> {
        self.require_writable()?;
        if state.generation == 0 {
            return Err(crate::error::Failure::InvalidCommand(
                "portable retention state requires generation >= 1".to_owned(),
            ));
        }
        let rows = installation_rows(state)?;
        let current_sequence = self.current_sequence()?;
        let current_generation = self.eligibility_generation()?;
        let genesis = self.genesis_revision()?;
        let now_ns = self.clock.now().nanos();

        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        struct ExistingSuppression {
            state: mneme_kernel::calm::SuppressionState,
            content_digest: Option<mneme_core::ContentDigest>,
            target_kind: String,
        }
        let existing_all = super::sweep::all_suppressions(&transaction)?;
        let mut strongest_existing: std::collections::BTreeMap<
            (mneme_core::RecordId, Option<mneme_core::RevisionId>),
            ExistingSuppression,
        > = std::collections::BTreeMap::new();
        for entry in existing_all {
            let incoming_state = mneme_kernel::calm::SuppressionState {
                level: suppression_mode_to_kernel(entry.mode),
                generation: entry.generation,
            };
            match strongest_existing.entry((entry.target, entry.revision)) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(ExistingSuppression {
                        state: incoming_state,
                        content_digest: entry.content_digest,
                        target_kind: entry.target_kind,
                    });
                }
                std::collections::btree_map::Entry::Occupied(mut slot) => {
                    let existing = slot.get_mut();
                    let prev_level = existing.state.level;
                    existing.state =
                        mneme_kernel::calm::join_suppression(existing.state, incoming_state);
                    if existing.state.level != prev_level {
                        existing.target_kind = entry.target_kind;
                    }
                    if existing.content_digest.is_none() {
                        existing.content_digest = entry.content_digest;
                    }
                }
            }
        }

        let mut merged_rows = Vec::with_capacity(rows.len());
        let mut applied_suppressions = Vec::with_capacity(rows.len());
        let mut strengthened = false;
        for row in rows {
            let incoming_state = mneme_kernel::calm::SuppressionState {
                level: suppression_mode_to_kernel(row.mode),
                generation: row.generation,
            };
            let existing = strongest_existing.get(&(row.target, row.revision));
            let base_state = existing.map_or(
                mneme_kernel::calm::SuppressionState {
                    level: mneme_kernel::calm::SuppressionLevel::None,
                    generation: 0,
                },
                |entry| entry.state,
            );
            let joined = mneme_kernel::calm::join_suppression(base_state, incoming_state);
            let joined_mode = kernel_to_suppression_mode(joined.level);
            let joined_digest = existing
                .and_then(|entry| entry.content_digest)
                .or(row.content_digest);
            let joined_kind = if existing.is_some_and(|entry| entry.state.level == joined.level) {
                existing
                    .map(|entry| entry.target_kind.clone())
                    .unwrap_or(row.target_kind)
            } else {
                row.target_kind
            };
            let is_stronger = existing.is_none()
                || existing.is_some_and(|entry| {
                    mneme_kernel::calm::suppression_rank(joined.level)
                        > mneme_kernel::calm::suppression_rank(entry.state.level)
                        || joined.generation > entry.state.generation
                        || (entry.content_digest.is_none() && joined_digest.is_some())
                });
            if is_stronger {
                strengthened = true;
            }
            let merged = crate::portability::PortableSuppression {
                target: row.target,
                revision: row.revision,
                target_kind: joined_kind.clone(),
                mode: joined_mode,
                content_digest: joined_digest,
                generation: joined.generation,
            };
            applied_suppressions.push(crate::lifecycle::RetentionSuppression {
                operation_id: "portable-restore".to_owned(),
                target: merged.target,
                revision: merged.revision,
                target_kind: joined_kind,
                mode: merged.mode,
                content_digest: merged.content_digest,
                generation: merged.generation,
            });
            merged_rows.push(merged);
        }

        let mut next_generation = current_generation.max(state.generation);
        if strengthened && next_generation == current_generation && current_sequence > 0 {
            next_generation = current_generation.saturating_add(1);
        }

        if !merged_rows.is_empty() {
            insert_portable_operation(&transaction, scope, genesis, next_generation, now_ns)?;
            for row in &merged_rows {
                upsert_portable_suppression(&transaction, row)?;
            }
            super::index::apply_suppressions(&transaction, &applied_suppressions)?;
        }
        let generation_advanced = next_generation > current_generation;
        if generation_advanced {
            super::set_meta_u64(&transaction, super::META_GENERATION, next_generation)?;
        }
        transaction.commit()?;

        let changed = strengthened || generation_advanced;
        if changed {
            self.facts().align(next_generation);
            *self.requirements.borrow_mut() = None;
        }
        Ok(changed)
    }

    /// Active `Forgotten` suppressions and forgotten content digests for `scope`.
    pub(crate) fn forgotten_filter(
        &self,
        scope: &mneme_core::ScopeId,
    ) -> crate::error::Result<ForgottenFilter> {
        let suppressions = super::sweep::forgotten_suppressions_in(&self.connection)?;
        let content_digests = forgotten_digests(&self.connection, scope)?;
        Ok(ForgottenFilter {
            identities: suppressions.identities,
            revisions: suppressions.revisions,
            content_digests,
        })
    }
}

/// Active `Forgotten` suppression filter used by barrier-first sync ingestion so
/// forgotten records and blobs are never resurrected by concurrent deltas.
pub(crate) struct ForgottenFilter {
    pub(crate) identities: std::collections::BTreeSet<mneme_core::RecordId>,
    pub(crate) revisions:
        std::collections::BTreeSet<(mneme_core::RecordId, mneme_core::RevisionId)>,
    pub(crate) content_digests: std::collections::BTreeSet<[u8; 32]>,
}

impl ForgottenFilter {
    pub(crate) fn matches_record_id(&self, record_id: mneme_core::RecordId) -> bool {
        self.identities.contains(&record_id)
    }

    pub(crate) fn matches_revision(
        &self,
        revision: &crate::portability::PortableRevision,
    ) -> crate::error::Result<bool> {
        let record_id = revision.envelope.record_id;
        let revision_id = revision.envelope.revision_id;
        if self.identities.contains(&record_id)
            || self.revisions.contains(&(record_id, revision_id))
        {
            return Ok(true);
        }
        if let Some(retained) = crate::portability::portable_retained_source(&revision.envelope)?
            && self.content_digests.contains(retained.digest().as_bytes())
        {
            return Ok(true);
        }
        Ok(false)
    }

    pub(crate) fn matches_digest(&self, digest: mneme_core::ContentDigest) -> bool {
        self.content_digests.contains(digest.as_bytes())
    }
}

fn suppression_mode_to_kernel(
    mode: crate::lifecycle::SuppressionMode,
) -> mneme_kernel::calm::SuppressionLevel {
    match mode {
        crate::lifecycle::SuppressionMode::Withdrawn => {
            mneme_kernel::calm::SuppressionLevel::Withdrawn
        }
        crate::lifecycle::SuppressionMode::Forgotten => {
            mneme_kernel::calm::SuppressionLevel::Forgotten
        }
    }
}

fn kernel_to_suppression_mode(
    level: mneme_kernel::calm::SuppressionLevel,
) -> crate::lifecycle::SuppressionMode {
    match level {
        mneme_kernel::calm::SuppressionLevel::None
        | mneme_kernel::calm::SuppressionLevel::Withdrawn => {
            crate::lifecycle::SuppressionMode::Withdrawn
        }
        mneme_kernel::calm::SuppressionLevel::Forgotten => {
            crate::lifecycle::SuppressionMode::Forgotten
        }
    }
}

fn forgotten_digests(
    connection: &rusqlite::Connection,
    scope: &mneme_core::ScopeId,
) -> crate::error::Result<std::collections::BTreeSet<[u8; 32]>> {
    super::sweep::forgotten_content_digests(connection, scope)?
        .into_iter()
        .map(|digest| {
            digest.try_into().map_err(|_| {
                crate::error::Failure::PortableArchive(
                    "a forgotten content digest is not 32 bytes".to_owned(),
                )
            })
        })
        .collect()
}

fn scoped_suppressions(
    connection: &rusqlite::Connection,
    scope: &mneme_core::ScopeId,
    omissions: &mut crate::portability::OmissionCounts,
) -> crate::error::Result<Vec<crate::portability::PortableSuppression>> {
    let scope_text = scope.to_string();
    let mut operation_scope =
        connection.prepare("SELECT scope FROM retention_operations WHERE operation_id = ?1")?;
    let mut suppressions: std::collections::BTreeMap<
        (mneme_core::RecordId, Option<mneme_core::RevisionId>),
        crate::portability::PortableSuppression,
    > = std::collections::BTreeMap::new();
    for suppression in super::sweep::all_suppressions(connection)? {
        let scopes = record_scopes_in(connection, suppression.target)?;
        let stored_scope = rusqlite::OptionalExtension::optional(
            operation_scope.query_row([&suppression.operation_id], |row| row.get::<_, String>(0)),
        )?;
        // A target with retained revisions outside this scope stays out of
        // the archive even when the suppression was issued from this
        // scope, so a record promoted or moved to another scope is never
        // disclosed by its suppression row.
        let is_target_in_scope = if scopes.is_empty() {
            stored_scope.as_deref() == Some(&scope_text)
        } else {
            scopes.iter().all(|stored| *stored == scope_text)
        };
        if !is_target_in_scope
            || stored_scope
                .as_ref()
                .is_some_and(|stored| *stored != scope_text)
        {
            omissions.bump("foreign-suppression", 1);
            continue;
        }
        let candidate = crate::portability::PortableSuppression {
            target: suppression.target,
            revision: suppression.revision,
            target_kind: suppression.target_kind,
            mode: suppression.mode,
            content_digest: suppression.content_digest,
            generation: suppression.generation,
        };
        insert_strongest(&mut suppressions, candidate);
        if suppressions.len() > crate::portability::MAX_PORTABLE_REVISIONS {
            return Err(crate::error::Failure::HistoryLimitExceeded);
        }
    }
    let suppressions: Vec<crate::portability::PortableSuppression> =
        suppressions.into_values().collect();
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

    Ok(suppressions)
}

/// Deduplicate one target via the Lean-verified CALM Stratum M suppression join;
/// the stronger suppression level and newest generation win.
fn insert_strongest(
    suppressions: &mut std::collections::BTreeMap<
        (mneme_core::RecordId, Option<mneme_core::RevisionId>),
        crate::portability::PortableSuppression,
    >,
    candidate: crate::portability::PortableSuppression,
) {
    match suppressions.entry((candidate.target, candidate.revision)) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(candidate);
        }
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            let existing = entry.get_mut();
            let left = mneme_kernel::calm::SuppressionState {
                level: suppression_mode_to_kernel(existing.mode),
                generation: existing.generation,
            };
            let right = mneme_kernel::calm::SuppressionState {
                level: suppression_mode_to_kernel(candidate.mode),
                generation: candidate.generation,
            };
            let joined = mneme_kernel::calm::join_suppression(left, right);
            if joined.level != left.level {
                existing.mode = kernel_to_suppression_mode(joined.level);
                existing.target_kind = candidate.target_kind;
            }
            existing.generation = joined.generation;
            if existing.content_digest.is_none() {
                existing.content_digest = candidate.content_digest;
            }
        }
    }
}

struct PruningPlan {
    rows: Vec<crate::portability::PortablePruning>,
    targets: std::collections::BTreeSet<(mneme_core::RecordId, mneme_core::RevisionId)>,
    digests: std::collections::BTreeSet<[u8; 32]>,
}

impl PruningPlan {
    fn add(
        &mut self,
        scope: &mneme_core::ScopeId,
        pruning: &super::recovery::RestoredPruning,
        revisions: &[mneme_core::RecordEnvelope],
    ) -> crate::error::Result<Option<&'static str>> {
        let mut has_match = false;
        let mut is_in_scope = false;
        for revision in revisions.iter().filter(|revision| revision.scope == *scope) {
            is_in_scope = true;
            if !crate::portability::portable_retained_source(revision)?
                .is_some_and(|retained| retained.digest() == pruning.digest)
            {
                continue;
            }
            has_match = true;
            if self.targets.insert((pruning.source, revision.revision_id)) {
                if self.rows.len() >= crate::portability::MAX_PORTABLE_REVISIONS {
                    return Err(crate::error::Failure::HistoryLimitExceeded);
                }
                self.rows.push(crate::portability::PortablePruning {
                    source: pruning.source,
                    revision: revision.revision_id,
                    digest: pruning.digest,
                });
            }
        }
        if has_match {
            self.digests.insert(*pruning.digest.as_bytes());
            Ok(None)
        } else if is_in_scope {
            Ok(Some("pruning-without-revision"))
        } else {
            Ok(Some("pruning-foreign-scope"))
        }
    }
}

fn installation_rows(
    state: &crate::portability::PortableRetentionState,
) -> crate::error::Result<Vec<crate::portability::PortableSuppression>> {
    let capacity = state
        .suppressions
        .len()
        .saturating_add(state.prunings.len());
    if capacity > crate::portability::MAX_PORTABLE_REVISIONS
        || i64::try_from(state.generation).is_err()
    {
        return Err(crate::error::Failure::HistoryLimitExceeded);
    }
    let mut rows = Vec::with_capacity(capacity);
    let mut seen = std::collections::BTreeSet::new();
    for suppression in &state.suppressions {
        validate_installed_suppression(suppression, state.generation)?;
        if !seen.insert((suppression.target, suppression.revision)) {
            return Err(crate::error::Failure::PortableArchive(
                "portable retention state repeats one suppression target".to_owned(),
            ));
        }
        rows.push(suppression.clone());
    }
    for pruning in &state.prunings {
        if pruning.digest.profile() != mneme_core::EncodingProfile::RawBytesV1
            || pruning.digest.boundary() != mneme_core::ValueBoundary::SourceBytes
        {
            return Err(crate::error::Failure::PortableArchive(
                "portable pruning digest is not a raw source digest".to_owned(),
            ));
        }
        if !seen.insert((pruning.source, Some(pruning.revision))) {
            // An explicit suppression for the same revision already wins;
            // the pruning adds no second row for one primary key.
            continue;
        }
        rows.push(crate::portability::PortableSuppression {
            target: pruning.source,
            revision: Some(pruning.revision),
            target_kind: "source-revision".to_owned(),
            mode: crate::lifecycle::SuppressionMode::Forgotten,
            content_digest: Some(pruning.digest),
            generation: state.generation,
        });
    }
    Ok(rows)
}

/// The scopes in which any retained revision of one record was recorded.
fn record_scopes_in(
    connection: &rusqlite::Connection,
    record: mneme_core::RecordId,
) -> crate::error::Result<std::collections::BTreeSet<String>> {
    let mut statement =
        connection.prepare("SELECT DISTINCT scope FROM records WHERE record_id = ?1")?;
    let rows = statement.query_map(rusqlite::params![record.as_bytes().as_slice()], |row| {
        row.get::<_, String>(0)
    })?;
    let mut scopes = std::collections::BTreeSet::new();
    for row in rows {
        scopes.insert(row?);
    }
    Ok(scopes)
}

/// Revalidate one suppression before it becomes durable engine state.
fn validate_installed_suppression(
    suppression: &crate::portability::PortableSuppression,
    generation: u64,
) -> crate::error::Result<()> {
    if suppression.generation == 0 || suppression.generation > generation {
        return Err(crate::error::Failure::PortableArchive(
            "portable suppression generation is outside the archive generation".to_owned(),
        ));
    }
    if suppression.target_kind.is_empty()
        || suppression.target_kind.len() > 64
        || !suppression.target_kind.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
    {
        return Err(crate::error::Failure::PortableArchive(
            "portable suppression target kind is malformed".to_owned(),
        ));
    }
    if let Some(digest) = suppression.content_digest
        && (digest.profile() != mneme_core::EncodingProfile::RawBytesV1
            || digest.boundary() != mneme_core::ValueBoundary::SourceBytes)
    {
        return Err(crate::error::Failure::PortableArchive(
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

/// Upsert one suppression row under the synthetic restore operation using
/// inflationary semantics (never weakening mode or generation).
fn upsert_portable_suppression(
    transaction: &rusqlite::Transaction<'_>,
    suppression: &crate::portability::PortableSuppression,
) -> crate::error::Result<()> {
    transaction.execute(
        "INSERT INTO retention_suppressions (operation_id, target_id, target_revision,
             target_kind, mode, content_digest, generation)
         VALUES ('portable-restore', ?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(operation_id, target_id, target_revision) DO UPDATE SET
             target_kind = excluded.target_kind,
             mode = excluded.mode,
             content_digest = COALESCE(retention_suppressions.content_digest, excluded.content_digest),
             generation = MAX(retention_suppressions.generation, excluded.generation)",
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
