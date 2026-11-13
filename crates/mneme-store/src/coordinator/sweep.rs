//! Retention and purge: operation, selector, suppression and cleanup-location
//! reads, plus the blob, working-file and participant-file purge sweeps.

use rusqlite::OptionalExtension;

impl super::Workspace {
    /// Read one retention operation by identity.
    pub fn retention_operation(
        &self,
        operation_id: &str,
    ) -> crate::error::Result<Option<crate::lifecycle::RetentionOperation>> {
        let row = self
            .connection
            .query_row(
                "SELECT operation_id, operation_kind, actor, scope, policy_version, state,
                        generation, outcome_revision, outcome_sequence, retained_metadata,
                        created_at_ns, updated_at_ns
                 FROM retention_operations WHERE operation_id = ?1",
                rusqlite::params![operation_id],
                raw_retention_operation,
            )
            .optional()?;
        row.map(RawRetentionOperation::into_operation).transpose()
    }

    /// Read the operation committed under one idempotency key.
    pub fn retention_operation_by_key(
        &self,
        actor: &str,
        scope: &mneme_core::ScopeId,
        idempotency_key: &str,
    ) -> crate::error::Result<Option<crate::lifecycle::RetentionOperation>> {
        let row = self
            .connection
            .query_row(
                "SELECT operation_id, operation_kind, actor, scope, policy_version, state,
                        generation, outcome_revision, outcome_sequence, retained_metadata,
                        created_at_ns, updated_at_ns
                 FROM retention_operations
                 WHERE actor = ?1 AND scope = ?2 AND idempotency_key = ?3",
                rusqlite::params![actor, scope.to_string(), idempotency_key],
                raw_retention_operation,
            )
            .optional()?;
        row.map(RawRetentionOperation::into_operation).transpose()
    }

    /// Selectors retained in one operation's plan.
    pub fn retention_selectors(
        &self,
        operation_id: &str,
    ) -> crate::error::Result<Vec<crate::lifecycle::RetentionSelector>> {
        let mut statement = self.connection.prepare(
            "SELECT ordinal, selector_kind, target_id, target_revision, target_digest
             FROM retention_selectors WHERE operation_id = ?1 ORDER BY ordinal",
        )?;
        let rows = statement
            .query_map(rusqlite::params![operation_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut selectors = Vec::with_capacity(rows.len());
        for (ordinal, kind, target, revision, digest) in rows {
            selectors.push(crate::lifecycle::RetentionSelector {
                ordinal: super::db_u32(ordinal, "ordinal")?,
                kind,
                target: target
                    .map(|bytes| super::record_id_from_blob(&bytes, self.current_revision()?))
                    .transpose()?,
                revision: revision
                    .map(|bytes| super::revision_id_from_blob(&bytes, self.current_revision()?))
                    .transpose()?,
                digest: digest
                    .map(|bytes| {
                        super::digest_with(
                            &bytes,
                            "raw-bytes-v1",
                            "source-bytes",
                            self.current_revision()
                                .unwrap_or(mneme_core::WorkspaceRevisionId::from_bytes([0; 16])),
                        )
                    })
                    .transpose()?,
            });
        }
        Ok(selectors)
    }

    /// Every suppression in one operation.
    pub fn retention_suppressions(
        &self,
        operation_id: &str,
    ) -> crate::error::Result<Vec<crate::lifecycle::RetentionSuppression>> {
        Ok(all_suppressions(&self.connection)?
            .into_iter()
            .filter(|suppression| suppression.operation_id == operation_id)
            .collect())
    }

    /// Every currently effective suppression.
    pub fn active_suppressions(
        &self,
    ) -> crate::error::Result<Vec<crate::lifecycle::RetentionSuppression>> {
        all_suppressions(&self.connection)
    }

    /// Managed locations and their cleanup state.
    pub fn retention_locations(
        &self,
        operation_id: &str,
    ) -> crate::error::Result<Vec<crate::lifecycle::RetentionLocationStateRecord>> {
        let mut statement = self.connection.prepare(
            "SELECT location_id, location_kind, locator, state, attempts, verified, detail_code
             FROM retention_locations WHERE operation_id = ?1 ORDER BY location_id",
        )?;
        let rows = statement
            .query_map(rusqlite::params![operation_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(
                |(location_id, location_kind, locator, state, attempts, verified, detail_code)| {
                    Ok(crate::lifecycle::RetentionLocationStateRecord {
                        location_id,
                        location_kind,
                        locator,
                        state: crate::lifecycle::RetentionLocationState::parse(&state).ok_or_else(
                            || {
                                crate::error::Failure::UnsupportedLayout(format!(
                                    "unknown retention location state {state}"
                                ))
                            },
                        )?,
                        attempts: super::db_u32(attempts, "attempts")?,
                        verified: verified != 0,
                        detail_code,
                    })
                },
            )
            .collect()
    }

    /// Change a retention operation's lifecycle state.
    pub fn set_retention_state(
        &mut self,
        operation_id: &str,
        state: crate::lifecycle::RetentionJobState,
    ) -> crate::error::Result<()> {
        let changed = self.connection.execute(
            "UPDATE retention_operations SET state = ?1, updated_at_ns = ?2
             WHERE operation_id = ?3",
            rusqlite::params![state.as_str(), self.clock.now().nanos(), operation_id],
        )?;
        if changed == 0 {
            return Err(crate::error::Failure::InvalidCommand(format!(
                "retention operation {operation_id} is missing"
            )));
        }
        Ok(())
    }

    /// Remove one planned content-addressed payload when no permitted live
    /// reference requires it.
    ///
    /// The requirement set is read, the decision is taken with the kernel, and
    /// the removal and its recorded outcome happen inside one immediate
    /// transaction while the exclusive sweep lock is held, so no commit can
    /// install a new requirement between the check and the delete.
    pub fn purge_retention_blob(
        &mut self,
        operation_id: &str,
        location_id: &str,
        location_kind: &str,
        locator: &str,
    ) -> crate::error::Result<crate::lifecycle::BlobPurgeOutcome> {
        let digest = super::recovery::digest_from_locator(location_kind, locator)?;
        let path = crate::payload::blob_path(&self.root, digest);
        let now_ns = self.clock.now().nanos();
        let _sweep = self.exclusive_sweep_lock()?;
        // The requirement read runs under the ledger transaction, so the fact
        // access is built from the fields the transaction does not borrow.
        let facts = super::facts_from(&self.shared, &self.records);
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let requirements =
            cached_retention_requirements(&self.requirements, &self.root, &transaction, facts)?;
        let is_present = blob_file_present(&path)?;
        let decision = mneme_kernel::purge::decide_blob(&mneme_kernel::purge::BlobFacts {
            required: requirements.digests.contains(digest.as_bytes()),
            present: is_present,
        });
        let (outcome, state, detail) = purge_decided_blob(self.faults.as_ref(), &path, decision)?;
        update_retention_location_in(
            &transaction,
            now_ns,
            operation_id,
            location_id,
            RetentionLocationUpdate {
                state,
                detail_code: detail,
                verified: state.is_terminal(),
                increment_attempts: true,
            },
        )?;
        transaction.commit()?;
        if outcome == crate::lifecycle::BlobPurgeOutcome::Purged {
            // The removed file may be a record envelope this handle decoded or a
            // source whose identity it verified; serving either after the purge
            // would outlive the erasure.
            facts.forget_envelope(digest);
            facts.forget_source(digest);
        }
        Ok(outcome)
    }

    /// Remove an exact managed working-file copy identified by
    /// `relative-path#source-digest`.
    ///
    /// The entry is displaced first and the kernel decides over the displaced
    /// bytes, so a file edited between the plan and the purge is reported, a
    /// symbolic link is never followed or hashed through, and a non-regular
    /// entry is reported unavailable instead of deleted.
    pub fn purge_retention_working_file(
        &mut self,
        operation_id: &str,
        location_id: &str,
        locator: &str,
    ) -> crate::error::Result<crate::lifecycle::BlobPurgeOutcome> {
        let (relative, digest_hex) = locator.rsplit_once('#').ok_or_else(|| {
            crate::error::Failure::InvalidCommand(
                "working-file retention locator lacks a content digest".to_owned(),
            )
        })?;
        let relative = crate::payload::validate_relative_path(relative)?;
        let relative_text = relative.to_string_lossy().into_owned();
        let digest = super::recovery::digest_from_locator("source-blob", digest_hex)?;
        if self.working_file_required(&relative_text, digest)? {
            self.update_retention_location(
                operation_id,
                location_id,
                RetentionLocationUpdate {
                    state: crate::lifecycle::RetentionLocationState::RetainedShared,
                    detail_code: Some("shared-path-binding"),
                    verified: false,
                    increment_attempts: true,
                },
            )?;
            return Ok(crate::lifecycle::BlobPurgeOutcome::RetainedShared);
        }
        let (outcome, state, detail) = self.purge_unshared_working_file(&relative_text, digest)?;
        self.update_retention_location(
            operation_id,
            location_id,
            RetentionLocationUpdate {
                state,
                detail_code: detail,
                verified: state.is_terminal(),
                increment_attempts: true,
            },
        )?;
        Ok(outcome)
    }

    /// Whether another live binding still requires this exact working copy.
    ///
    /// A path-addressed copy is kept only when a live source binds the same path
    /// to the same bytes, or a publication intent still has to write that path.
    /// Content sharing elsewhere in the workspace does not keep it: no other
    /// record owns this path.
    fn working_file_required(
        &self,
        relative: &str,
        digest: mneme_core::ContentDigest,
    ) -> crate::error::Result<bool> {
        let requirements = self.cached_requirements(&self.connection)?;
        if requirements.pending_paths.contains(relative) {
            return Ok(true);
        }
        Ok(requirements
            .paths
            .get(relative)
            .is_some_and(|digests| digests.contains(digest.as_bytes())))
    }

    /// Purge one displaced working copy, reporting instead of deleting a
    /// divergent or non-regular entry.
    fn purge_unshared_working_file(
        &self,
        relative: &str,
        digest: mneme_core::ContentDigest,
    ) -> crate::error::Result<(
        crate::lifecycle::BlobPurgeOutcome,
        crate::lifecycle::RetentionLocationState,
        Option<&'static str>,
    )> {
        crate::injectors::check(
            self.faults.as_ref(),
            crate::injectors::FaultPoint::BeforeRetentionPurge,
        )?;
        let (state, detail) = purge_working_copy(&self.root, relative, digest)?;
        if state == crate::lifecycle::RetentionLocationState::Purged {
            crate::injectors::check(
                self.faults.as_ref(),
                crate::injectors::FaultPoint::AfterRetentionPurge,
            )?;
        }
        let outcome = match state {
            crate::lifecycle::RetentionLocationState::Purged => {
                crate::lifecycle::BlobPurgeOutcome::Purged
            }
            crate::lifecycle::RetentionLocationState::Absent => {
                crate::lifecycle::BlobPurgeOutcome::Absent
            }
            _ => crate::lifecycle::BlobPurgeOutcome::RetainedShared,
        };
        Ok((outcome, state, detail))
    }

    /// Remove one planned participant file named by a workspace-relative path.
    ///
    /// A participant manages its own store, so the path identifies the target.
    /// The entry must be a regular file that is not reached through a symbolic
    /// link. When the locator also names a digest (`path#hex`), only exactly
    /// those bytes are purged; a differing file is reported instead.
    pub fn purge_retention_participant_file(
        &mut self,
        operation_id: &str,
        location_id: &str,
        locator: &str,
    ) -> crate::error::Result<crate::lifecycle::BlobPurgeOutcome> {
        let (relative, planned) = match locator.rsplit_once('#') {
            Some((path, hex)) => {
                let digest = super::recovery::digest_from_locator("source-blob", hex)?;
                (path, Some(digest))
            }
            None => (locator, None),
        };
        crate::payload::validate_relative_path(relative)?;
        crate::injectors::check(
            self.faults.as_ref(),
            crate::injectors::FaultPoint::BeforeRetentionPurge,
        )?;
        let mut guard = crate::payload::quarantine_workspace_file(&self.root, relative)?;
        let decision = participant_file_decision(&guard, planned)?;
        let (outcome, state, detail) = self.purge_decided_working(&mut guard, decision)?;
        self.update_retention_location(
            operation_id,
            location_id,
            RetentionLocationUpdate {
                state,
                detail_code: detail,
                verified: state.is_terminal(),
                increment_attempts: true,
            },
        )?;
        Ok(outcome)
    }

    /// Apply one kernel working-entry decision to the displaced entry.
    fn purge_decided_working(
        &self,
        guard: &mut crate::payload::QuarantineGuard,
        decision: mneme_kernel::purge::WorkingDecision,
    ) -> crate::error::Result<(
        crate::lifecycle::BlobPurgeOutcome,
        crate::lifecycle::RetentionLocationState,
        Option<&'static str>,
    )> {
        match decision {
            mneme_kernel::purge::WorkingDecision::Purge => {
                guard.discard()?;
                crate::injectors::check(
                    self.faults.as_ref(),
                    crate::injectors::FaultPoint::AfterRetentionPurge,
                )?;
                Ok((
                    crate::lifecycle::BlobPurgeOutcome::Purged,
                    crate::lifecycle::RetentionLocationState::Purged,
                    None,
                ))
            }
            mneme_kernel::purge::WorkingDecision::AlreadyAbsent => {
                guard.restore()?;
                Ok((
                    crate::lifecycle::BlobPurgeOutcome::Absent,
                    crate::lifecycle::RetentionLocationState::Absent,
                    None,
                ))
            }
            mneme_kernel::purge::WorkingDecision::ExternalEdit => {
                guard.restore()?;
                Ok((
                    crate::lifecycle::BlobPurgeOutcome::RetainedShared,
                    crate::lifecycle::RetentionLocationState::Unavailable,
                    Some("external-edit-present"),
                ))
            }
            mneme_kernel::purge::WorkingDecision::Unsupported => {
                guard.restore()?;
                Ok((
                    crate::lifecycle::BlobPurgeOutcome::RetainedShared,
                    crate::lifecycle::RetentionLocationState::Unavailable,
                    Some("not-a-regular-file"),
                ))
            }
        }
    }

    /// Record the outcome of one inventory location.
    ///
    /// For the built-in inventory kinds the store inspects the location and
    /// records what it found: a location is reported absent or purged only
    /// after it was searched for the operation's targeted bytes, never because
    /// the caller asserted it. A caller may not claim success for a kind the
    /// store cannot inspect; that location is reported unavailable instead.
    pub fn verify_retention_location(
        &mut self,
        operation_id: &str,
        location_id: &str,
        state: crate::lifecycle::RetentionLocationState,
        detail_code: Option<&str>,
    ) -> crate::error::Result<()> {
        let (location_kind, locator) =
            self.retention_location_identity(operation_id, location_id)?;
        match location_kind.as_str() {
            "staging" => self.inspect_temporaries(operation_id, location_id),
            "sqlite-payloads" => self.inspect_ledger(operation_id, location_id),
            "temporary-exports" => self.inspect_unregistered_store(operation_id, location_id),
            "publication-intent" => {
                let is_suppressed = self
                    .publication_intent_has_state(&locator, super::PublicationState::Suppressed)?;
                let (state, detail) = if is_suppressed {
                    (crate::lifecycle::RetentionLocationState::Verified, None)
                } else {
                    (
                        crate::lifecycle::RetentionLocationState::Failed,
                        Some("publication-not-suppressed"),
                    )
                };
                self.record_location_state(operation_id, location_id, state, detail)
            }
            _ => {
                // The caller owns the outcome only for kinds the store cannot
                // inspect; it may not turn that into a verified success.
                let (state, detail) = if state.is_terminal() {
                    (
                        crate::lifecycle::RetentionLocationState::Unavailable,
                        Some("unverified-location-kind"),
                    )
                } else {
                    (state, detail_code)
                };
                self.record_location_state(operation_id, location_id, state, detail)
            }
        }
    }

    /// Read one location's kind and locator.
    fn retention_location_identity(
        &self,
        operation_id: &str,
        location_id: &str,
    ) -> crate::error::Result<(String, String)> {
        self.connection
            .query_row(
                "SELECT location_kind, locator FROM retention_locations
                 WHERE operation_id = ?1 AND location_id = ?2",
                rusqlite::params![operation_id, location_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .ok_or_else(|| {
                crate::error::Failure::InvalidCommand(format!(
                    "retention location {location_id} is missing"
                ))
            })
    }

    /// Record one inspected cleanup outcome.
    fn record_location_state(
        &self,
        operation_id: &str,
        location_id: &str,
        state: crate::lifecycle::RetentionLocationState,
        detail_code: Option<&str>,
    ) -> crate::error::Result<()> {
        self.update_retention_location(
            operation_id,
            location_id,
            RetentionLocationUpdate {
                state,
                detail_code,
                verified: state.is_terminal(),
                increment_attempts: true,
            },
        )
    }

    /// The digests one operation plans to remove.
    ///
    /// Blob locations name their digest; a suppression may also carry a content
    /// digest used for replay blocking. These are the only bytes a leftover in a
    /// staging or temporary file may hold for this operation's cleanup to
    /// remove it.
    fn retention_target_digests(
        &self,
        operation_id: &str,
    ) -> crate::error::Result<std::collections::BTreeSet<[u8; 32]>> {
        let mut targets = std::collections::BTreeSet::new();
        let mut statement = self.connection.prepare(
            "SELECT location_kind, locator FROM retention_locations WHERE operation_id = ?1",
        )?;
        let rows = statement
            .query_map(rusqlite::params![operation_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let max_targets = 1_000_000_usize;
        for (kind, locator) in rows {
            if !matches!(kind.as_str(), "source-blob" | "record-blob") {
                continue;
            }
            let bytes = super::recovery::decode_hex(&locator)?;
            let digest: [u8; 32] = bytes.try_into().map_err(|_| {
                crate::error::Failure::UnsupportedLayout(
                    "retention blob locator is not 32 bytes".to_owned(),
                )
            })?;
            if targets.len() >= max_targets {
                return Err(crate::error::Failure::UnsupportedLayout(
                    "retention target set exceeds its operation bound".to_owned(),
                ));
            }
            targets.insert(digest);
        }
        let mut statement = self.connection.prepare(
            "SELECT content_digest FROM retention_suppressions
             WHERE operation_id = ?1 AND content_digest IS NOT NULL",
        )?;
        let rows = statement
            .query_map(rusqlite::params![operation_id], |row| {
                row.get::<_, Vec<u8>>(0)
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for bytes in rows {
            targets.insert(super::digest_32(&bytes)?);
        }
        Ok(targets)
    }

    /// Inspect and purge leftover staging and working temporary files that hold
    /// the operation's targeted bytes.
    fn inspect_temporaries(
        &mut self,
        operation_id: &str,
        location_id: &str,
    ) -> crate::error::Result<()> {
        let targets = self.retention_target_digests(operation_id)?;
        let _sweep = self.exclusive_sweep_lock()?;
        let (removed, _inspected) =
            match crate::payload::purge_targeted_temporaries(&self.root, &targets) {
                Ok(found) => found,
                Err(_) => {
                    return self.record_location_state(
                        operation_id,
                        location_id,
                        crate::lifecycle::RetentionLocationState::Failed,
                        Some("temporary-inspection-failed"),
                    );
                }
            };
        let state = if removed > 0 {
            crate::lifecycle::RetentionLocationState::Purged
        } else {
            crate::lifecycle::RetentionLocationState::Absent
        };
        self.record_location_state(operation_id, location_id, state, None)
    }

    /// Inspect the ledger for cells holding the operation's targeted bytes.
    fn inspect_ledger(
        &mut self,
        operation_id: &str,
        location_id: &str,
    ) -> crate::error::Result<()> {
        let targets = self.retention_target_digests(operation_id)?;
        let is_found = match ledger_holds_targets(&self.connection, &targets) {
            Ok(is_found) => is_found,
            Err(_) => {
                return self.record_location_state(
                    operation_id,
                    location_id,
                    crate::lifecycle::RetentionLocationState::Failed,
                    Some("ledger-inspection-failed"),
                );
            }
        };
        let (state, detail) = if is_found {
            (
                crate::lifecycle::RetentionLocationState::Failed,
                Some("payload-present-in-ledger"),
            )
        } else {
            (crate::lifecycle::RetentionLocationState::Absent, None)
        };
        self.record_location_state(operation_id, location_id, state, detail)
    }

    /// Report unregistered payload stores under the workspace root.
    ///
    /// The application manages no temporary export store of its own, so the
    /// inspection is the root inventory: when an unregistered entry could hold
    /// payload bytes the location is reported unavailable instead of absent.
    fn inspect_unregistered_store(
        &mut self,
        operation_id: &str,
        location_id: &str,
    ) -> crate::error::Result<()> {
        let entries = self.unregistered_payload_entries()?;
        let (state, detail) = if entries.is_empty() {
            (crate::lifecycle::RetentionLocationState::Absent, None)
        } else {
            (
                crate::lifecycle::RetentionLocationState::Unavailable,
                Some("unregistered-payload-store"),
            )
        };
        self.record_location_state(operation_id, location_id, state, detail)
    }

    /// Every registered retention participant.
    pub fn retention_participants(
        &self,
    ) -> crate::error::Result<Vec<crate::lifecycle::RetentionParticipant>> {
        let mut statement = self.connection.prepare(
            "SELECT name, storage_role, supports_invalidation, supports_purge,
                    checks_generation, inventory_locator
             FROM retention_participants ORDER BY name",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok(crate::lifecycle::RetentionParticipant {
                    name: row.get(0)?,
                    storage_role: row.get(1)?,
                    supports_invalidation: row.get::<_, i64>(2)? != 0,
                    supports_purge: row.get::<_, i64>(3)? != 0,
                    checks_generation: row.get::<_, i64>(4)? != 0,
                    inventory_locator: row.get(5)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Top-level workspace entries that no store component or participant owns.
    ///
    /// These are payload stores the store cannot account for, so retention
    /// reports them instead of claiming that no copied bytes remain.
    pub fn unregistered_payload_entries(&self) -> crate::error::Result<Vec<String>> {
        let mut registered = std::collections::BTreeSet::new();
        for participant in self.retention_participants()? {
            let Ok(path) = crate::payload::validate_relative_path(&participant.inventory_locator)
            else {
                continue;
            };
            if let Some(std::path::Component::Normal(name)) = path.components().next()
                && let Some(name) = name.to_str()
            {
                registered.insert(name.to_owned());
            }
        }
        let max_entries = 100_000_usize;
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&self.root)
            .map_err(|error| crate::error::Failure::io(&self.root, error))?
        {
            let entry = entry.map_err(|error| crate::error::Failure::io(&self.root, error))?;
            let name = entry.file_name();
            if super::is_artifact_file(&name) || super::is_workspace_directory(&name) {
                continue;
            }
            let text = name.to_string_lossy().into_owned();
            if registered.contains(&text) {
                continue;
            }
            // An interrupted workspace creation leaves its own hidden sibling;
            // it is never a payload store of this workspace.
            if text.starts_with('.') && text.contains(".mneme-init-") {
                continue;
            }
            if entries.len() >= max_entries {
                return Err(crate::error::Failure::UnsupportedLayout(
                    "workspace root inventory exceeds its entry bound".to_owned(),
                ));
            }
            entries.push(text);
        }
        entries.sort();
        Ok(entries)
    }

    fn update_retention_location(
        &self,
        operation_id: &str,
        location_id: &str,
        update: RetentionLocationUpdate<'_>,
    ) -> crate::error::Result<()> {
        update_retention_location_in(
            &self.connection,
            self.clock.now().nanos(),
            operation_id,
            location_id,
            update,
        )
    }

    /// Digests still required by a live record revision, source, or pending
    /// publication.
    pub fn retention_required_digests(
        &self,
    ) -> crate::error::Result<std::collections::BTreeSet<[u8; 32]>> {
        Ok(self.cached_requirements(&self.connection)?.digests)
    }

    /// The required-digest and working-path sets for one ledger state.
    ///
    /// The answer is cached per revision and generation: a cleanup pass asks it
    /// once per location, and any commit or barrier changes the key so a stale
    /// answer is never reused.
    fn cached_requirements(
        &self,
        connection: &rusqlite::Connection,
    ) -> crate::error::Result<super::RetentionRequirements> {
        cached_retention_requirements(&self.requirements, &self.root, connection, self.facts())
    }
}

/// The forgotten suppression index for one ledger state.
pub(super) fn forgotten_suppressions_in(
    connection: &rusqlite::Connection,
) -> crate::error::Result<ForgottenSuppressions> {
    let suppressions = all_suppressions(connection)?
        .into_iter()
        .filter(|suppression| suppression.mode == crate::lifecycle::SuppressionMode::Forgotten)
        .collect::<Vec<_>>();
    Ok(ForgottenSuppressions::from(suppressions))
}

/// The required digests and working-path bindings, reused while the ledger
/// revision and generation are unchanged.
fn cached_retention_requirements(
    cache: &std::cell::RefCell<Option<super::RetentionRequirements>>,
    root: &std::path::Path,
    connection: &rusqlite::Connection,
    facts: super::FactAccess<'_>,
) -> crate::error::Result<super::RetentionRequirements> {
    let stored = super::meta_blob(connection, super::META_CURRENT_REVISION)?;
    let revision = super::revision_from_blob(&stored)?;
    let generation = super::meta_u64(connection, super::META_GENERATION)?;
    if let Some(cached) = cache.borrow().as_ref()
        && cached.revision == revision
        && cached.generation == generation
    {
        return Ok(cached.clone());
    }
    let computed = retention_requirements(connection, root, revision, generation, facts)?;
    *cache.borrow_mut() = Some(computed.clone());
    Ok(computed)
}

/// The required digests and working-path bindings for one ledger state.
pub(super) fn retention_requirements(
    connection: &rusqlite::Connection,
    root: &std::path::Path,
    revision: mneme_core::WorkspaceRevisionId,
    generation: u64,
    facts: super::FactAccess<'_>,
) -> crate::error::Result<super::RetentionRequirements> {
    let forgotten = forgotten_suppressions_in(connection)?;
    let bindings = super::recovery::current_source_bindings(connection, root, revision, facts)?;
    let mut statement = connection.prepare(
        "SELECT record_id, revision_id, kind, envelope_digest, full_digest, payload_digest
         FROM records ORDER BY recorded_order, recorded_at_ns, revision_id",
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
    let mut digests = std::collections::BTreeSet::new();
    let mut scan = RequirementScan {
        root,
        context: revision,
        forgotten: &forgotten,
        current: &bindings.states,
        required: &mut digests,
    };
    for row in rows {
        include_retention_record_digests(row, &mut scan)?;
    }
    let mut pending_paths = std::collections::BTreeSet::new();
    let mut intents = connection.prepare(
        "SELECT target_path, desired_digest FROM publication_intents
         WHERE state = 'pending'",
    )?;
    let rows = intents
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (path, bytes) in rows {
        digests.insert(super::digest_32(&bytes)?);
        pending_paths.insert(path);
    }
    Ok(super::RetentionRequirements {
        revision,
        generation,
        digests,
        paths: bindings.paths,
        pending_paths,
    })
}

/// The facts one requirement scan shares across every retained row it folds.
struct RequirementScan<'a> {
    root: &'a std::path::Path,
    context: mneme_core::WorkspaceRevisionId,
    forgotten: &'a ForgottenSuppressions,
    current: &'a std::collections::BTreeMap<mneme_core::RecordId, super::SourcePresence>,
    required: &'a mut std::collections::BTreeSet<[u8; 32]>,
}

fn include_retention_record_digests(
    row: super::RetainedRecordRow,
    scan: &mut RequirementScan<'_>,
) -> crate::error::Result<()> {
    let context = scan.context;
    let (record_id, revision_id, kind, envelope_digest, full_digest, payload_digest) = row;
    let record_id = super::record_id_from_blob(&record_id, context)?;
    let revision_id = super::revision_id_from_blob(&revision_id, context)?;
    if scan.forgotten.matches(record_id, revision_id) {
        return Ok(());
    }
    let kind =
        mneme_core::RecordKind::parse(&kind).ok_or_else(|| crate::error::Failure::Integrity {
            revision: context,
            reason: format!("unknown record kind {kind}"),
        })?;
    let full = super::digest_with(
        &full_digest,
        "preserves-canonical-binary-v1",
        "full-record",
        context,
    )?;
    if full.as_bytes() != envelope_digest.as_slice() {
        return Err(crate::error::Failure::Integrity {
            revision: context,
            reason: "record envelope digest columns disagree".to_owned(),
        });
    }
    scan.required.insert(*full.as_bytes());
    if kind == mneme_core::RecordKind::SourceRevision {
        include_source_record_digest(
            scan.root,
            super::SourceRecordDigestInput {
                record_id,
                full,
                payload_digest: &payload_digest,
                context,
                current: scan.current,
                required: &mut *scan.required,
            },
        )?;
    }
    Ok(())
}

fn include_source_record_digest(
    root: &std::path::Path,
    input: super::SourceRecordDigestInput<'_>,
) -> crate::error::Result<()> {
    let super::SourceRecordDigestInput {
        record_id,
        full,
        payload_digest,
        context,
        current,
        required,
    } = input;
    let payload = super::digest_with(
        payload_digest,
        "preserves-canonical-binary-v1",
        "payload",
        context,
    )?;
    let bytes =
        crate::payload::read(root, full).map_err(|error| crate::error::Failure::Integrity {
            revision: context,
            reason: format!("source record {record_id} blob {full} is unavailable: {error}"),
        })?;
    let value = mneme_core::binary::decode(&bytes).map_err(|diagnostic| {
        crate::error::Failure::Integrity {
            revision: context,
            reason: format!("source record {full} is not valid Preserves: {diagnostic}"),
        }
    })?;
    let record = mneme_core::RecordEnvelope::from_value(&value).map_err(|diagnostics| {
        crate::error::Failure::Integrity {
            revision: context,
            reason: format!(
                "source record {full} is not an envelope: {}",
                super::join(&diagnostics)
            ),
        }
    })?;
    if record.payload_digest() != payload {
        return Err(crate::error::Failure::Integrity {
            revision: context,
            reason: "source record payload digest disagrees".to_owned(),
        });
    }
    if let Some(digest) = super::validation::retained_source_digest(&record)
        && !super::source_payload_pruned(current, record_id)
    {
        required.insert(*digest.as_bytes());
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct RawRetentionOperation {
    operation_id: String,
    operation_kind: String,
    actor: String,
    scope: String,
    policy_version: String,
    state: String,
    generation: i64,
    outcome_revision: Vec<u8>,
    outcome_sequence: i64,
    retained_metadata: String,
    created_at_ns: i64,
    updated_at_ns: i64,
}

fn raw_retention_operation(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawRetentionOperation> {
    Ok(RawRetentionOperation {
        operation_id: row.get(0)?,
        operation_kind: row.get(1)?,
        actor: row.get(2)?,
        scope: row.get(3)?,
        policy_version: row.get(4)?,
        state: row.get(5)?,
        generation: row.get(6)?,
        outcome_revision: row.get(7)?,
        outcome_sequence: row.get(8)?,
        retained_metadata: row.get(9)?,
        created_at_ns: row.get(10)?,
        updated_at_ns: row.get(11)?,
    })
}

impl RawRetentionOperation {
    fn into_operation(self) -> crate::error::Result<crate::lifecycle::RetentionOperation> {
        Ok(crate::lifecycle::RetentionOperation {
            operation_id: self.operation_id,
            operation_kind: self.operation_kind,
            actor: self.actor,
            scope: super::recovery::scope_from_text(&self.scope)?,
            policy_version: self.policy_version,
            state: crate::lifecycle::RetentionJobState::parse(&self.state).ok_or_else(|| {
                crate::error::Failure::UnsupportedLayout(format!(
                    "unknown retention job state {}",
                    self.state
                ))
            })?,
            generation: super::db_u64(self.generation, "generation")?,
            outcome_revision: super::revision_from_blob(&self.outcome_revision)?,
            outcome_sequence: super::db_u64(self.outcome_sequence, "outcome sequence")?,
            retained_metadata: self
                .retained_metadata
                .split('\n')
                .filter(|entry| !entry.is_empty())
                .map(str::to_owned)
                .collect(),
            created_at_ns: self.created_at_ns,
            updated_at_ns: self.updated_at_ns,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct ForgottenSuppressions {
    pub(super) identities: std::collections::BTreeSet<mneme_core::RecordId>,
    pub(super) revisions:
        std::collections::BTreeSet<(mneme_core::RecordId, mneme_core::RevisionId)>,
}

impl ForgottenSuppressions {
    pub(super) fn matches(
        &self,
        record: mneme_core::RecordId,
        revision: mneme_core::RevisionId,
    ) -> bool {
        self.identities.contains(&record) || self.revisions.contains(&(record, revision))
    }
}

impl From<Vec<crate::lifecycle::RetentionSuppression>> for ForgottenSuppressions {
    fn from(suppressions: Vec<crate::lifecycle::RetentionSuppression>) -> Self {
        let mut forgotten = ForgottenSuppressions::default();
        for suppression in suppressions {
            match suppression.revision {
                Some(revision) => {
                    forgotten.revisions.insert((suppression.target, revision));
                }
                None => {
                    forgotten.identities.insert(suppression.target);
                }
            }
        }
        forgotten
    }
}

pub(super) fn all_suppressions(
    connection: &rusqlite::Connection,
) -> crate::error::Result<Vec<crate::lifecycle::RetentionSuppression>> {
    let mut statement = connection.prepare(
        "SELECT operation_id, target_id, target_revision, target_kind, mode, content_digest,
                generation
         FROM retention_suppressions ORDER BY operation_id, target_id, target_revision",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut suppressions = Vec::with_capacity(rows.len());
    for (operation_id, target, revision, target_kind, mode, digest, generation) in rows {
        let context = mneme_core::WorkspaceRevisionId::from_bytes([0; 16]);
        suppressions.push(crate::lifecycle::RetentionSuppression {
            operation_id,
            target: super::record_id_from_blob(&target, context)?,
            revision: if revision.is_empty() {
                None
            } else {
                Some(super::revision_id_from_blob(&revision, context)?)
            },
            target_kind,
            mode: crate::lifecycle::SuppressionMode::parse(&mode).ok_or_else(|| {
                crate::error::Failure::UnsupportedLayout(format!("unknown suppression mode {mode}"))
            })?,
            content_digest: digest
                .map(|bytes| super::digest_with(&bytes, "raw-bytes-v1", "source-bytes", context))
                .transpose()?,
            generation: super::db_u64(generation, "generation")?,
        });
    }
    Ok(suppressions)
}

/// Content digests forgotten by the retention operations of one scope.
///
/// Suppression by content identity is scoped to the operation that created it:
/// a forget in one scope neither blocks nor discloses the same bytes held by
/// another scope. A suppression applied by a restore ledger can outlive its
/// operation row; its scope is then read from its target record, and a
/// suppression whose target has no recorded scope keeps blocking everywhere so
/// a restore can never make forgotten content replayable.
pub(super) fn forgotten_content_digests(
    connection: &rusqlite::Connection,
    scope: &mneme_core::ScopeId,
) -> crate::error::Result<std::collections::BTreeSet<Vec<u8>>> {
    let mode = crate::lifecycle::SuppressionMode::Forgotten.as_str();
    let mut digests = std::collections::BTreeSet::new();
    let mut scoped = connection.prepare(
        "SELECT DISTINCT s.content_digest
         FROM retention_suppressions s
         JOIN retention_operations o ON o.operation_id = s.operation_id
         WHERE s.mode = ?1 AND o.scope = ?2 AND s.content_digest IS NOT NULL",
    )?;
    let rows = scoped.query_map(rusqlite::params![mode, scope.to_string()], |row| {
        row.get::<_, Vec<u8>>(0)
    })?;
    for row in rows {
        digests.insert(row?);
    }
    let mut orphaned = connection.prepare(
        "SELECT DISTINCT s.target_id, s.content_digest
         FROM retention_suppressions s
         LEFT JOIN retention_operations o ON o.operation_id = s.operation_id
         WHERE s.mode = ?1 AND o.operation_id IS NULL AND s.content_digest IS NOT NULL",
    )?;
    let rows = orphaned.query_map(rusqlite::params![mode], |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    let orphans = rows.collect::<std::result::Result<Vec<_>, _>>()?;
    for (target, digest) in orphans {
        let scopes = record_scopes(connection, &target)?;
        if scopes.is_empty() || scopes.contains(&scope.to_string()) {
            digests.insert(digest);
        }
    }
    Ok(digests)
}

/// Every scope in which a retained revision of one record was recorded.
fn record_scopes(
    connection: &rusqlite::Connection,
    target: &[u8],
) -> crate::error::Result<std::collections::BTreeSet<String>> {
    let mut statement =
        connection.prepare("SELECT DISTINCT scope FROM records WHERE record_id = ?1")?;
    let rows = statement.query_map(rusqlite::params![target], |row| row.get::<_, String>(0))?;
    let mut scopes = std::collections::BTreeSet::new();
    for row in rows {
        scopes.insert(row?);
    }
    Ok(scopes)
}

/// Map a kernel cleanup summary to the persisted job state.
pub(super) fn cleanup_job_state(
    summary: mneme_kernel::cleanup::JobSummary,
) -> crate::lifecycle::RetentionJobState {
    match summary {
        mneme_kernel::cleanup::JobSummary::Complete => {
            crate::lifecycle::RetentionJobState::Complete
        }
        mneme_kernel::cleanup::JobSummary::Partial => crate::lifecycle::RetentionJobState::Partial,
        mneme_kernel::cleanup::JobSummary::Pending => {
            crate::lifecycle::RetentionJobState::CleanupPending
        }
        mneme_kernel::cleanup::JobSummary::Failed => crate::lifecycle::RetentionJobState::Failed,
    }
}

#[derive(Clone, Copy)]
pub(super) struct RetentionLocationUpdate<'a> {
    /// The verified/attempted state the inspected location is moved to.
    pub(super) state: crate::lifecycle::RetentionLocationState,
    /// The stable detail code the stored location keeps, when it has one.
    pub(super) detail_code: Option<&'a str>,
    pub(super) verified: bool,
    pub(super) increment_attempts: bool,
}

/// Record one cleanup location outcome inside the caller's transaction.
pub(super) fn update_retention_location_in(
    connection: &rusqlite::Connection,
    now_ns: i64,
    operation_id: &str,
    location_id: &str,
    update: RetentionLocationUpdate<'_>,
) -> crate::error::Result<()> {
    let changed = connection.execute(
        "UPDATE retention_locations
         SET state = ?1, verified = ?2, detail_code = ?3, updated_at_ns = ?4,
             attempts = attempts + ?5
         WHERE operation_id = ?6 AND location_id = ?7",
        rusqlite::params![
            update.state.as_str(),
            i64::from(update.verified),
            update.detail_code,
            now_ns,
            i64::from(update.increment_attempts),
            operation_id,
            location_id,
        ],
    )?;
    if changed == 0 {
        return Err(crate::error::Failure::InvalidCommand(format!(
            "retention location {location_id} is missing"
        )));
    }
    Ok(())
}

/// Whether the blob file at this path is a regular file right now.
fn blob_file_present(path: &std::path::Path) -> crate::error::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.is_file()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(crate::error::Failure::io(path, error)),
    }
}

/// Remove one blob file, flush its directory, and report whether it existed.
fn remove_blob_file(path: &std::path::Path) -> crate::error::Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                super::sync_directory(parent)?;
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(crate::error::Failure::io(path, error)),
    }
}

/// Apply one kernel blob decision: only bytes no live revision needs are removed,
/// and a removal is reported only when the file really existed.
fn purge_decided_blob(
    faults: &dyn crate::injectors::FaultInjector,
    path: &std::path::Path,
    decision: mneme_kernel::purge::BlobDecision,
) -> crate::error::Result<(
    crate::lifecycle::BlobPurgeOutcome,
    crate::lifecycle::RetentionLocationState,
    Option<&'static str>,
)> {
    match decision {
        mneme_kernel::purge::BlobDecision::RetainShared => Ok((
            crate::lifecycle::BlobPurgeOutcome::RetainedShared,
            crate::lifecycle::RetentionLocationState::RetainedShared,
            Some("shared-live-reference"),
        )),
        mneme_kernel::purge::BlobDecision::AlreadyAbsent => Ok((
            crate::lifecycle::BlobPurgeOutcome::Absent,
            crate::lifecycle::RetentionLocationState::Absent,
            None,
        )),
        mneme_kernel::purge::BlobDecision::Purge => {
            crate::injectors::check(faults, crate::injectors::FaultPoint::BeforeRetentionPurge)?;
            let is_removed = remove_blob_file(path)?;
            crate::injectors::check(faults, crate::injectors::FaultPoint::AfterRetentionPurge)?;
            if is_removed {
                Ok((
                    crate::lifecycle::BlobPurgeOutcome::Purged,
                    crate::lifecycle::RetentionLocationState::Purged,
                    None,
                ))
            } else {
                Ok((
                    crate::lifecycle::BlobPurgeOutcome::Absent,
                    crate::lifecycle::RetentionLocationState::Absent,
                    None,
                ))
            }
        }
    }
}

/// Decide with the kernel over one participant file that was displaced.
///
/// A participant manages its own store, so without a planned digest the bytes
/// found at the locator are the bytes the plan removes.
fn participant_file_decision(
    guard: &crate::payload::QuarantineGuard,
    planned: Option<mneme_core::ContentDigest>,
) -> crate::error::Result<mneme_kernel::purge::WorkingDecision> {
    // The kernel ignores the planned digest for an absent or unsupported entry;
    // this placeholder only satisfies the facts struct.
    let placeholder = mneme_core::ContentDigest::of_source_bytes(b"").to_kernel();
    let facts = match guard.entry() {
        None => mneme_kernel::purge::WorkingFacts {
            kind: mneme_kernel::purge::EntryKind::Absent,
            observed: None,
            planned: placeholder,
        },
        Some(file) => match file.read()? {
            crate::payload::WorkingEntry::Absent => mneme_kernel::purge::WorkingFacts {
                kind: mneme_kernel::purge::EntryKind::Absent,
                observed: None,
                planned: placeholder,
            },
            crate::payload::WorkingEntry::NotRegular => mneme_kernel::purge::WorkingFacts {
                kind: mneme_kernel::purge::EntryKind::Other,
                observed: None,
                planned: placeholder,
            },
            crate::payload::WorkingEntry::Regular(bytes) => {
                let observed = mneme_core::ContentDigest::of_source_bytes(&bytes);
                mneme_kernel::purge::WorkingFacts {
                    kind: mneme_kernel::purge::EntryKind::Regular,
                    observed: Some(observed.to_kernel()),
                    planned: planned.unwrap_or(observed).to_kernel(),
                }
            }
        },
    };
    Ok(mneme_kernel::purge::decide_working(&facts))
}

/// Whether any ledger cell holds bytes with one of the targeted digests.
///
/// The ledger is meant to hold identifiers, kinds, scopes and digests only, so
/// a cell whose exact bytes hash to a targeted payload digest means a payload
/// copy survived in SQLite. Every table is scanned under a fixed cell bound;
/// exceeding the bound fails closed rather than claiming the ledger is clean.
fn ledger_holds_targets(
    connection: &rusqlite::Connection,
    targets: &std::collections::BTreeSet<[u8; 32]>,
) -> crate::error::Result<bool> {
    if targets.is_empty() {
        return Ok(false);
    }
    let mut statement =
        connection.prepare("SELECT name FROM sqlite_master WHERE type = 'table'")?;
    let tables = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let max_cells = 1_000_000_usize;
    let mut visited = 0_usize;
    for table in tables {
        let quoted = format!("\"{}\"", table.replace('"', "\"\""));
        let mut rows = connection.prepare(&format!("SELECT * FROM {quoted}"))?;
        let columns = rows.column_count();
        let mut result = rows.query([])?;
        while let Some(row) = result.next()? {
            for index in 0..columns {
                let value: rusqlite::types::Value = row.get(index)?;
                let bytes = match &value {
                    rusqlite::types::Value::Text(text) => Some(text.as_bytes()),
                    rusqlite::types::Value::Blob(bytes) => Some(bytes.as_slice()),
                    rusqlite::types::Value::Null
                    | rusqlite::types::Value::Integer(_)
                    | rusqlite::types::Value::Real(_) => None,
                };
                let Some(bytes) = bytes else {
                    continue;
                };
                visited = visited.saturating_add(1);
                if visited > max_cells {
                    return Err(crate::error::Failure::UnsupportedLayout(
                        "ledger inspection exceeds its cell bound".to_owned(),
                    ));
                }
                if targets.contains(&crate::payload::sha256(bytes)) {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// Purge one working copy by displacing it and deciding over its exact bytes.
///
/// A displaced entry that is not the planned content, or that is not a regular
/// file, is put back and reported instead of being deleted.
pub(super) fn purge_working_copy(
    root: &std::path::Path,
    relative: &str,
    digest: mneme_core::ContentDigest,
) -> crate::error::Result<(
    crate::lifecycle::RetentionLocationState,
    Option<&'static str>,
)> {
    let mut guard = crate::payload::quarantine_working_file(root, relative)?;
    let planned = digest.to_kernel();
    let facts = match guard.entry() {
        None => mneme_kernel::purge::WorkingFacts {
            kind: mneme_kernel::purge::EntryKind::Absent,
            observed: None,
            planned,
        },
        Some(file) => match file.read()? {
            crate::payload::WorkingEntry::Absent => mneme_kernel::purge::WorkingFacts {
                kind: mneme_kernel::purge::EntryKind::Absent,
                observed: None,
                planned,
            },
            crate::payload::WorkingEntry::NotRegular => mneme_kernel::purge::WorkingFacts {
                kind: mneme_kernel::purge::EntryKind::Other,
                observed: None,
                planned,
            },
            crate::payload::WorkingEntry::Regular(bytes) => mneme_kernel::purge::WorkingFacts {
                kind: mneme_kernel::purge::EntryKind::Regular,
                observed: Some(mneme_core::ContentDigest::of_source_bytes(&bytes).to_kernel()),
                planned,
            },
        },
    };
    match mneme_kernel::purge::decide_working(&facts) {
        mneme_kernel::purge::WorkingDecision::Purge => {
            guard.discard()?;
            Ok((crate::lifecycle::RetentionLocationState::Purged, None))
        }
        mneme_kernel::purge::WorkingDecision::AlreadyAbsent => {
            guard.restore()?;
            Ok((crate::lifecycle::RetentionLocationState::Absent, None))
        }
        mneme_kernel::purge::WorkingDecision::ExternalEdit => {
            guard.restore()?;
            Ok((
                crate::lifecycle::RetentionLocationState::Unavailable,
                Some("external-edit-present"),
            ))
        }
        mneme_kernel::purge::WorkingDecision::Unsupported => {
            guard.restore()?;
            Ok((
                crate::lifecycle::RetentionLocationState::Unavailable,
                Some("not-a-regular-file"),
            ))
        }
    }
}
