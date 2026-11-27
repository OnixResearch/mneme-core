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
    /// Export the portable retention state (suppressions, prunings, and key
    /// puncture barriers) for `scope`.
    pub fn export_retention_state(
        &self,
        scope: &mneme_core::ScopeId,
    ) -> crate::error::Result<crate::portability::PortableRetentionState> {
        self.export_portable_retention(scope)
            .map(|export| export.state)
    }

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
        let key_punctures = load_puncture_barriers_in(connection, scope)?;
        Ok(crate::portability::PortableRetentionExport {
            state: crate::portability::PortableRetentionState {
                generation,
                suppressions,
                prunings: plan.rows,
                key_punctures,
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
        let strongest_existing = collect_strongest_existing_suppressions(&transaction)?;
        let (merged_rows, applied_suppressions, has_strengthened) =
            join_incoming_suppressions(rows, &strongest_existing);

        let mut next_generation = current_generation.max(state.generation);
        if has_strengthened && next_generation == current_generation && current_sequence > 0 {
            next_generation = current_generation.saturating_add(1);
        }

        if !merged_rows.is_empty() {
            insert_portable_operation(&transaction, scope, genesis, next_generation, now_ns)?;
            for row in &merged_rows {
                upsert_portable_suppression(&transaction, row)?;
            }
            super::index::apply_suppressions(&transaction, &applied_suppressions)?;
        }
        let has_punctured =
            apply_portable_key_punctures(&self.root, &transaction, &state.key_punctures)?;
        let is_generation_advanced = next_generation > current_generation;
        if is_generation_advanced {
            super::set_meta_u64(&transaction, super::META_GENERATION, next_generation)?;
        }
        transaction.commit()?;

        let has_changed = has_strengthened || is_generation_advanced || has_punctured;
        if has_changed {
            self.facts().align(next_generation);
            *self.requirements.borrow_mut() = None;
        }
        Ok(has_changed)
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

struct ExistingSuppression {
    state: mneme_kernel::calm::SuppressionState,
    content_digest: Option<mneme_core::ContentDigest>,
    target_kind: String,
}

type ExistingSuppressionMap = std::collections::BTreeMap<
    (mneme_core::RecordId, Option<mneme_core::RevisionId>),
    ExistingSuppression,
>;

fn collect_strongest_existing_suppressions(
    transaction: &rusqlite::Transaction<'_>,
) -> crate::error::Result<ExistingSuppressionMap> {
    let existing_all = super::sweep::all_suppressions(transaction)?;
    let mut strongest_existing = ExistingSuppressionMap::new();
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
    Ok(strongest_existing)
}

fn join_incoming_suppressions(
    rows: Vec<crate::portability::PortableSuppression>,
    strongest_existing: &ExistingSuppressionMap,
) -> (
    Vec<crate::portability::PortableSuppression>,
    Vec<crate::lifecycle::RetentionSuppression>,
    bool,
) {
    let mut merged_rows = Vec::with_capacity(rows.len());
    let mut applied_suppressions = Vec::with_capacity(rows.len());
    let mut has_strengthened = false;
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
            has_strengthened = true;
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
    (merged_rows, applied_suppressions, has_strengthened)
}

fn apply_portable_key_punctures(
    root: &std::path::Path,
    transaction: &rusqlite::Transaction<'_>,
    barriers: &[crate::keytree::KeyPunctureBarrier],
) -> crate::error::Result<bool> {
    if barriers.is_empty() {
        return Ok(false);
    }
    ensure_retention_punctures_table(transaction)?;
    let mut has_punctured = false;
    for barrier in barriers {
        if let Some(mut tree) =
            crate::keytree::PuncturableTree::open_existing(root, &barrier.scope)?
        {
            let report = tree.puncture_slot(barrier.key_slot, barrier.generation)?;
            if !report.was_already_punctured {
                has_punctured = true;
            }
        }
        record_puncture_barrier_in(transaction, barrier)?;
    }
    Ok(has_punctured)
}

impl super::Workspace {
    /// Enable `MNENC01\0` GGM puncturable cryptographic erasure for `scope`.
    ///
    /// Confidential scopes enable encryption automatically; other scopes may
    /// opt in explicitly with this call.
    pub fn enable_scope_encryption(&self, scope: &mneme_core::ScopeId) -> crate::error::Result<()> {
        let _tree = crate::keytree::PuncturableTree::open_or_init(&self.root, scope)?;
        Ok(())
    }

    /// Apply a [`crate::keytree::KeyPunctureBarrier`] to this workspace's
    /// per-scope GGM key tree and record it in `retention_punctures`.
    pub fn apply_key_puncture_barrier(
        &mut self,
        barrier: &crate::keytree::KeyPunctureBarrier,
    ) -> crate::error::Result<crate::keytree::PunctureReport> {
        self.require_writable()?;
        ensure_retention_punctures_table(&self.connection)?;
        let report = if let Some(mut tree) =
            crate::keytree::PuncturableTree::open_existing(&self.root, &barrier.scope)?
        {
            tree.puncture_slot(barrier.key_slot, barrier.generation)?
        } else {
            crate::keytree::PunctureReport {
                key_slot: barrier.key_slot,
                generation: barrier.generation,
                sibling_keys_written: 0,
                was_already_punctured: true,
            }
        };
        record_puncture_barrier_in(&self.connection, barrier)?;
        Ok(report)
    }

    /// Read all recorded [`crate::keytree::KeyPunctureBarrier`]s for `scope`.
    pub fn key_puncture_barriers(
        &self,
        scope: &mneme_core::ScopeId,
    ) -> crate::error::Result<Vec<crate::keytree::KeyPunctureBarrier>> {
        if !super::table_exists(&self.connection, "retention_punctures")? {
            return Ok(Vec::new());
        }
        load_puncture_barriers_in(&self.connection, scope)
    }

    /// Active maximal frontier revisions for `record_id` in `snapshot`, sorted
    /// canonically by `revision_id`.
    pub fn record_frontier(
        &self,
        snapshot: &super::Snapshot,
        record_id: mneme_core::RecordId,
    ) -> Vec<mneme_core::RecordEnvelope> {
        let mut heads: Vec<mneme_core::RecordEnvelope> = snapshot
            .records
            .iter()
            .filter(|record| record.record_id == record_id)
            .cloned()
            .collect();
        heads.sort_by_key(|record| record.revision_id);
        heads
    }

    /// Joined inflationary suppression level (`None < Withdrawn < Forgotten`)
    /// across all branches of `record_id`.
    pub fn record_suppression_level(
        &self,
        record_id: mneme_core::RecordId,
    ) -> crate::error::Result<mneme_kernel::calm::SuppressionLevel> {
        let mut statement = self
            .connection
            .prepare("SELECT mode FROM retention_suppressions WHERE target_id = ?1")?;
        let modes = statement
            .query_map(rusqlite::params![record_id.as_bytes().as_slice()], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut level = mneme_kernel::calm::SuppressionLevel::None;
        for mode in modes {
            let next = match crate::lifecycle::SuppressionMode::parse(&mode) {
                Some(crate::lifecycle::SuppressionMode::Forgotten) => {
                    mneme_kernel::calm::SuppressionLevel::Forgotten
                }
                Some(crate::lifecycle::SuppressionMode::Withdrawn) => {
                    mneme_kernel::calm::SuppressionLevel::Withdrawn
                }
                None => mneme_kernel::calm::SuppressionLevel::None,
            };
            level = mneme_kernel::calm::join_suppression_level(level, next);
        }
        Ok(level)
    }

    /// Project `record_id`'s maximal frontier and suppression state using the
    /// Lean 4–verified [`mneme_kernel::lattice::project_frontier`] decision.
    pub fn project_record_frontier(
        &self,
        snapshot: &super::Snapshot,
        record_id: mneme_core::RecordId,
    ) -> crate::error::Result<mneme_kernel::lattice::ProjectedView> {
        let heads = self.record_frontier(snapshot, record_id);
        let frontier_count = u32::try_from(heads.len())
            .map_err(|_| crate::error::Failure::ValueOutOfRange("frontier_count"))?;
        let head_lifecycle = heads
            .first()
            .and_then(mneme_core::RecordEnvelope::assertion_lifecycle)
            .map(mneme_core::Lifecycle::to_kernel)
            .unwrap_or(mneme_kernel::claim::Lifecycle::Proposed);
        let suppression = self.record_suppression_level(record_id)?;
        Ok(mneme_kernel::lattice::project_frontier(
            &mneme_kernel::lattice::FrontierProjectionInput {
                frontier_count,
                head_lifecycle,
                suppression,
            },
        ))
    }

    /// Validate whether a proposed merge citing `cited_parents` may resolve a
    /// concurrent frontier on `record_id` using
    /// [`mneme_kernel::lattice::decide_frontier_merge`].
    pub fn decide_record_frontier_merge(
        &self,
        snapshot: &super::Snapshot,
        record_id: mneme_core::RecordId,
        cited_parents: &std::collections::BTreeSet<mneme_core::RevisionId>,
        decision: super::MergeDecisionPresence,
    ) -> crate::error::Result<mneme_kernel::lattice::MergeResolutionVerdict> {
        let heads = self.record_frontier(snapshot, record_id);
        let frontier_count = u32::try_from(heads.len())
            .map_err(|_| crate::error::Failure::ValueOutOfRange("frontier_count"))?;
        let cited_count = heads
            .iter()
            .filter(|head| cited_parents.contains(&head.revision_id))
            .count();
        let cited_frontier_count = u32::try_from(cited_count)
            .map_err(|_| crate::error::Failure::ValueOutOfRange("cited_frontier_count"))?;
        let suppression = self.record_suppression_level(record_id)?;
        Ok(mneme_kernel::lattice::decide_frontier_merge(
            &mneme_kernel::lattice::MergeResolutionFacts {
                frontier_count,
                cited_frontier_count,
                has_conflict_resolution_decision: matches!(
                    decision,
                    super::MergeDecisionPresence::Present
                ),
                suppression,
            },
        ))
    }
}

pub(super) fn ensure_retention_punctures_table(
    connection: &rusqlite::Connection,
) -> crate::error::Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS retention_punctures (
            scope TEXT NOT NULL,
            key_slot INTEGER NOT NULL,
            generation INTEGER NOT NULL,
            digest BLOB,
            digest_algorithm TEXT,
            digest_profile TEXT,
            digest_boundary TEXT,
            signer_key_id TEXT,
            signature_hex TEXT,
            PRIMARY KEY (scope, key_slot)
        );",
    )?;
    Ok(())
}

pub(super) fn record_puncture_barrier_in(
    connection: &rusqlite::Connection,
    barrier: &crate::keytree::KeyPunctureBarrier,
) -> crate::error::Result<()> {
    let gen_i64 = super::db_i64(barrier.generation, "generation")?;
    connection.execute(
        "INSERT INTO retention_punctures (
             scope, key_slot, generation, digest, digest_algorithm, digest_profile,
             digest_boundary, signer_key_id, signature_hex
         )
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(scope, key_slot) DO UPDATE SET
             generation = MAX(retention_punctures.generation, excluded.generation),
             digest = COALESCE(retention_punctures.digest, excluded.digest),
             digest_algorithm = COALESCE(retention_punctures.digest_algorithm, excluded.digest_algorithm),
             digest_profile = COALESCE(retention_punctures.digest_profile, excluded.digest_profile),
             digest_boundary = COALESCE(retention_punctures.digest_boundary, excluded.digest_boundary),
             signer_key_id = COALESCE(retention_punctures.signer_key_id, excluded.signer_key_id),
             signature_hex = COALESCE(retention_punctures.signature_hex, excluded.signature_hex)",
        rusqlite::params![
            barrier.scope.to_string(),
            i64::from(barrier.key_slot),
            gen_i64,
            barrier.digest.map(|d| d.as_bytes().to_vec()),
            barrier.digest.map(|d| d.algorithm().symbol().to_owned()),
            barrier.digest.map(|d| d.profile().symbol().to_owned()),
            barrier.digest.map(|d| d.boundary().symbol().to_owned()),
            barrier.signer_key_id.as_deref(),
            barrier.signature_hex.as_deref(),
        ],
    )?;
    Ok(())
}

fn decode_puncture_digest(
    digest_bytes: Option<Vec<u8>>,
    alg: Option<String>,
    prof: Option<String>,
    bound: Option<String>,
) -> crate::error::Result<Option<mneme_core::ContentDigest>> {
    let (Some(bytes), Some(alg), Some(prof), Some(bound)) = (digest_bytes, alg, prof, bound) else {
        return Ok(None);
    };
    let raw = super::digest_32(&bytes)?;
    let algorithm = mneme_core::HashAlgorithm::parse(&alg).ok_or_else(|| {
        crate::error::Failure::UnsupportedLayout("unknown puncture digest algorithm".to_owned())
    })?;
    let profile = mneme_core::EncodingProfile::parse(&prof).ok_or_else(|| {
        crate::error::Failure::UnsupportedLayout("unknown puncture digest profile".to_owned())
    })?;
    let boundary = mneme_core::ValueBoundary::parse(&bound).ok_or_else(|| {
        crate::error::Failure::UnsupportedLayout("unknown puncture digest boundary".to_owned())
    })?;
    mneme_core::ContentDigest::from_parts(algorithm, profile, boundary, raw)
        .map(Some)
        .map_err(|reason| crate::error::Failure::UnsupportedLayout(reason.to_owned()))
}

pub(super) fn load_puncture_barriers_in(
    connection: &rusqlite::Connection,
    scope: &mneme_core::ScopeId,
) -> crate::error::Result<Vec<crate::keytree::KeyPunctureBarrier>> {
    if !super::table_exists(connection, "retention_punctures")? {
        return Ok(Vec::new());
    }
    let scope_str = scope.to_string();
    let mut stmt = connection.prepare(
        "SELECT key_slot, generation, digest, digest_algorithm, digest_profile,
                digest_boundary, signer_key_id, signature_hex
         FROM retention_punctures
         WHERE scope = ?1
         ORDER BY key_slot",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![scope_str], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut out = Vec::with_capacity(rows.len());
    for (slot_i64, gen_i64, digest_bytes, alg, prof, bound, signer, sig) in rows {
        let key_slot = u32::try_from(slot_i64)
            .map_err(|_| crate::error::Failure::ValueOutOfRange("key_slot"))?;
        let generation = super::db_u64(gen_i64, "generation")?;
        let digest = decode_puncture_digest(digest_bytes, alg, prof, bound)?;
        out.push(crate::keytree::KeyPunctureBarrier {
            scope: scope.clone(),
            key_slot,
            generation,
            digest,
            signer_key_id: signer,
            signature_hex: sig,
        });
    }
    Ok(out)
}
