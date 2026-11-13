//! One commit's transaction: validation, blob staging, manifest identity, and
//! the ledger rows and publication intents the commit writes atomically.

use rusqlite::OptionalExtension;

impl super::Workspace {
    /// Commit one command through the serialized coordinator.
    ///
    /// The command carries no adapter fingerprint, so its idempotency key
    /// replays only the identical request digest. Adapters that rebuild a
    /// command from current state use [`Workspace::commit_bound`] instead.
    pub fn commit(
        &mut self,
        command: crate::requests::CommitCommand,
    ) -> crate::error::Result<super::CommitOutcome> {
        self.commit_command(command, None)
    }

    /// Commit one command whose idempotency key is bound to `fingerprint`.
    ///
    /// The fingerprint is the adapter's request identity, computed over every
    /// input that changes the outcome. A retry that rebuilt the same request on
    /// a newer base replays the recorded outcome instead of conflicting.
    pub fn commit_bound(
        &mut self,
        command: crate::requests::CommitCommand,
        fingerprint: mneme_core::ContentDigest,
    ) -> crate::error::Result<super::CommitOutcome> {
        self.commit_command(command, Some(fingerprint))
    }

    fn commit_command(
        &mut self,
        command: crate::requests::CommitCommand,
        fingerprint: Option<mneme_core::ContentDigest>,
    ) -> crate::error::Result<super::CommitOutcome> {
        self.require_restore_suppression()?;
        super::validation::validate_command(&command)?;
        self.validate_retention_command(&command)?;
        let request_digest = command.request_digest();
        // Optimisation only: the same kernel decision runs again inside the
        // transaction, where the stored row is authoritative.
        if let Some(stored) = self.lookup_command(&command)? {
            match Self::decide_stored(&stored, &request_digest, &fingerprint)? {
                mneme_kernel::admission::CommitDecision::Replay => {
                    return self.outcome_for_stored(&stored);
                }
                mneme_kernel::admission::CommitDecision::IdempotencyConflict => {
                    return Err(crate::error::Failure::IdempotencyConflict {
                        key: command.idempotency_key,
                    });
                }
                _ => {}
            }
        }

        // The shared lock covers exactly the window in which this commit's blobs
        // exist on disk without ledger rows, so no recovery sweep can mistake
        // them for orphans. Publication runs after the guard is dropped.
        let (prepared, written) = {
            let _guard = self.shared_commit_lock()?;
            let prepared = self.prepare_commit(&command, request_digest, fingerprint)?;
            let written = self.write_prepared_commit(&command, &prepared)?;
            (prepared, written)
        };
        match written {
            super::CommitWrite::Existing(outcome) => Ok(outcome),
            super::CommitWrite::New(intent_ids) => {
                self.remember_committed_records(&prepared);
                self.finish_new_commit(&command, &prepared, intent_ids)
            }
        }
    }

    /// Remember the record envelopes this commit wrote, so the next load on the
    /// same handle decodes only the records whose payloads it has never seen.
    ///
    /// Each entry carries the blob file identity that was captured immediately
    /// after the bytes were staged and verified, so a later hit is only served
    /// while that file is still in place. A retention commit advances the erasure
    /// generation first, so nothing decoded under the old generation survives it.
    fn remember_committed_records(&self, prepared: &super::PreparedCommit) {
        let facts = self.facts();
        facts.align(prepared.next_generation);
        for record in &prepared.new_records {
            let digest = record.full_digest();
            let Some((_, length, _, _)) = prepared.staged.get(digest.as_bytes()) else {
                continue;
            };
            let Ok(encoded_bytes) = usize::try_from(*length) else {
                continue;
            };
            let Some(file) = prepared.record_files.get(digest.as_bytes()).copied() else {
                continue;
            };
            let payload_digest = record.payload_digest();
            facts.store_envelope(digest, record.clone(), payload_digest, encoded_bytes, file);
        }
    }

    /// Decide what a stored command row means for the request being committed.
    fn decide_stored(
        stored: &super::StoredCommand,
        request_digest: &mneme_core::ContentDigest,
        fingerprint: &Option<mneme_core::ContentDigest>,
    ) -> crate::error::Result<mneme_kernel::admission::CommitDecision> {
        let facts = mneme_kernel::admission::CommitFacts {
            stored: Some(stored.kernel()?),
            command: request_digest.to_kernel(),
            fingerprint: fingerprint
                .as_ref()
                .map(mneme_core::ContentDigest::to_kernel),
            base_is_current: true,
            generation_is_pinned: true,
        };
        Ok(mneme_kernel::admission::decide_commit(&facts))
    }

    /// Publish the new revision's intents and report them.
    ///
    /// The revision is already committed, so a failure to record or read back a
    /// publication result must not be reported as a failed commit: the intent
    /// stays pending in the ledger and is reported as such.
    fn finish_new_commit(
        &self,
        command: &crate::requests::CommitCommand,
        prepared: &super::PreparedCommit,
        intent_ids: Vec<String>,
    ) -> crate::error::Result<super::CommitOutcome> {
        crate::injectors::check(
            self.faults.as_ref(),
            crate::injectors::FaultPoint::AfterCommit,
        )?;
        let mut publications = Vec::with_capacity(intent_ids.len());
        for (index, intent_id) in intent_ids.into_iter().enumerate() {
            let path = command
                .publications
                .get(index)
                .map(|publication| publication.path.clone())
                .unwrap_or_default();
            match self.publish_intent(&intent_id) {
                Ok(outcome) => publications.push(outcome),
                Err(crate::error::Failure::InjectedFault(point)) => {
                    return Err(crate::error::Failure::InjectedFault(point));
                }
                Err(error) => {
                    publications.push(self.recorded_publication_failure(&intent_id, &path, &error))
                }
            }
        }
        Ok(super::CommitOutcome {
            revision: prepared.revision_id,
            sequence: prepared.next_sequence,
            manifest_digest: prepared.manifest_digest,
            eligibility_generation: prepared.next_generation,
            publications,
        })
    }

    /// Record a publication failure and describe the intent as it now stands.
    ///
    /// When the bookkeeping write itself fails, the ledger still says `pending`
    /// and recovery can resume it, so that is what the caller is told.
    fn recorded_publication_failure(
        &self,
        intent_id: &str,
        path: &str,
        error: &crate::error::Failure,
    ) -> super::PublicationOutcome {
        let recorded = self
            .mark_intent_failed(intent_id, error)
            .and_then(|()| self.publication_outcome(intent_id));
        match recorded {
            Ok(Some(outcome)) => outcome,
            _ => super::PublicationOutcome {
                intent_id: intent_id.to_owned(),
                path: path.to_owned(),
                state: super::PublicationState::Pending,
                observed: None,
                detail: Some("publication state could not be recorded".to_owned()),
            },
        }
    }

    fn validate_retention_command(
        &self,
        command: &crate::requests::CommitCommand,
    ) -> crate::error::Result<()> {
        if let Some(retention) = &command.retention {
            retention
                .validate()
                .map_err(crate::error::Failure::InvalidCommand)?;
            for suppression in &retention.suppressions {
                mneme_core::RecordKind::parse(&suppression.target_kind).ok_or_else(|| {
                    crate::error::Failure::InvalidCommand(format!(
                        "unknown retention target kind {}",
                        suppression.target_kind
                    ))
                })?;
            }
        }
        Ok(())
    }

    fn prepare_commit(
        &self,
        command: &crate::requests::CommitCommand,
        request_digest: mneme_core::ContentDigest,
        fingerprint: Option<mneme_core::ContentDigest>,
    ) -> crate::error::Result<super::PreparedCommit> {
        let base = self.current_revision()?;
        if command.base != base {
            return Err(crate::error::Failure::StaleBase {
                base: command.base,
                current: base,
            });
        }
        let next_sequence = self.current_sequence()?.saturating_add(1);
        let generation = self.eligibility_generation()?;
        let next_generation = if command.retention.is_some() {
            generation.saturating_add(1)
        } else {
            generation
        };
        if let Some(retention) = &command.retention
            && retention
                .suppressions
                .iter()
                .any(|suppression| suppression.generation != next_generation)
        {
            return Err(crate::error::Failure::InvalidCommand(
                "retention suppressions must target the new eligibility generation".to_owned(),
            ));
        }
        let recorded = mneme_core::RecordedTime::new(self.clock.now(), next_sequence);
        self.ensure_not_suppressed(command)?;
        let prior = self.prior_snapshot_for_commit()?;
        let new_records = self.validate_commit_records(command, recorded, &prior)?;
        let (staged, record_files) = self.stage_commit_blobs(command, &new_records)?;
        crate::injectors::check(
            self.faults.as_ref(),
            crate::injectors::FaultPoint::AfterBlobStaging,
        )?;
        let manifest = self.create_commit_manifest(command, base, &prior, &new_records)?;
        let blob_lengths = self.verify_commit_blobs(&manifest, &staged)?;
        crate::injectors::check(
            self.faults.as_ref(),
            crate::injectors::FaultPoint::BeforeCommitTransaction,
        )?;
        Ok(super::PreparedCommit {
            request_digest,
            fingerprint,
            base,
            next_sequence,
            generation,
            next_generation,
            recorded,
            new_records,
            staged,
            record_files,
            blob_lengths,
            snapshot_records: manifest.snapshot_records,
            revision_id: manifest.revision_id,
            manifest: manifest.manifest,
            manifest_digest: manifest.manifest_digest,
        })
    }

    /// The current snapshot as a commit needs it.
    ///
    /// A commit validates its batch against this snapshot and derives the new
    /// manifest from it, so the payloads must be decoded and bound to the
    /// ledger identity. They are not re-hashed: this load checks each inherited
    /// blob for presence at its recorded length, the commit hashes every blob it
    /// stages, and the commit transaction re-checks presence once more before the
    /// rows that require them are written.
    fn prior_snapshot_for_commit(&self) -> crate::error::Result<super::Snapshot> {
        let revision = self.current_revision()?;
        let row = super::revision_row_by_id(&self.connection, revision)?.ok_or_else(|| {
            crate::error::Failure::Integrity {
                revision,
                reason: "current revision is not present in the ledger".to_owned(),
            }
        })?;
        let generation = self.eligibility_generation()?;
        self.build_snapshot(&row, generation, super::PayloadCheck::Presence)
    }

    fn validate_commit_records(
        &self,
        command: &crate::requests::CommitCommand,
        recorded: mneme_core::RecordedTime,
        prior: &super::Snapshot,
    ) -> crate::error::Result<Vec<mneme_core::RecordEnvelope>> {
        let envelopes: Vec<mneme_core::RecordEnvelope> = command
            .records
            .clone()
            .into_iter()
            .map(|draft| draft.into_envelope(recorded))
            .collect();
        let values: Vec<mneme_core::Value> = envelopes
            .iter()
            .map(mneme_core::RecordEnvelope::to_value)
            .collect();
        let validated = mneme_core::validate_batch(
            &values,
            &mneme_core::SchemaRegistry::production(),
            Some(&prior.index),
        )
        .map_err(crate::error::Failure::Validation)?;
        let new_records = validated.records;
        self.ensure_revisions_unused(&new_records)?;
        super::validation::validate_record_scopes(&command.scope, &prior.records, &new_records)?;
        super::validation::validate_bindings(&prior.records, &new_records)?;
        super::validation::validate_sources(
            &command.source_blobs,
            &command.import_candidates,
            &prior.records,
            &command.scope,
            &new_records,
        )?;
        super::validation::validate_publication_paths(
            &command.publications,
            &command.import_candidates,
        )?;
        Ok(new_records)
    }

    fn stage_commit_blobs(
        &self,
        command: &crate::requests::CommitCommand,
        new_records: &[mneme_core::RecordEnvelope],
    ) -> crate::error::Result<(
        super::BlobIndex,
        std::collections::BTreeMap<[u8; 32], super::FileIdentity>,
    )> {
        let mut staged = std::collections::BTreeMap::new();
        let mut record_files = std::collections::BTreeMap::new();
        self.stage_record_blobs(new_records, &mut staged, &mut record_files)?;
        self.stage_source_blobs(&command.source_blobs, &mut staged)?;
        self.stage_import_candidate_blobs(&command.import_candidates, new_records, &mut staged)?;
        self.stage_publication_blobs(&command.publications, &mut staged)?;
        Ok((staged, record_files))
    }

    fn stage_record_blobs(
        &self,
        records: &[mneme_core::RecordEnvelope],
        staged: &mut super::BlobIndex,
        record_files: &mut std::collections::BTreeMap<[u8; 32], super::FileIdentity>,
    ) -> crate::error::Result<()> {
        for record in records {
            let value = record.to_value();
            let bytes = mneme_core::binary::encode(&value);
            let digest = mneme_core::ContentDigest::of_full_record(&value);
            let staged_blob = crate::payload::stage(&self.root, digest, &bytes)?;
            // The identity the bytes were just verified from, so a later cache
            // hit can prove the blob file was not replaced behind it.
            if let Some(file) = super::blob_file_identity(&self.root, digest)
                && file.byte_length == staged_blob.byte_length
            {
                record_files.insert(*digest.as_bytes(), file);
            }
            staged.insert(
                *digest.as_bytes(),
                (
                    digest,
                    staged_blob.byte_length,
                    mneme_core::EncodingProfile::CanonicalBinaryV1,
                    mneme_core::ValueBoundary::FullRecord,
                ),
            );
        }
        Ok(())
    }

    fn stage_source_blobs(
        &self,
        sources: &[crate::requests::SourceBlobDraft],
        staged: &mut super::BlobIndex,
    ) -> crate::error::Result<()> {
        for source in sources {
            let digest = source.digest();
            let staged_blob = crate::payload::stage(&self.root, digest, &source.bytes)?;
            staged.insert(
                *digest.as_bytes(),
                (
                    digest,
                    staged_blob.byte_length,
                    mneme_core::EncodingProfile::RawBytesV1,
                    mneme_core::ValueBoundary::SourceBytes,
                ),
            );
        }
        Ok(())
    }

    fn stage_import_candidate_blobs(
        &self,
        candidates: &[crate::requests::ImportCandidateDraft],
        records: &[mneme_core::RecordEnvelope],
        staged: &mut super::BlobIndex,
    ) -> crate::error::Result<()> {
        for candidate in candidates {
            crate::payload::validate_relative_path(&candidate.path)?;
            let current = crate::payload::read_working_file(&self.root, &candidate.path)?;
            if current.as_deref() != Some(candidate.bytes.as_slice())
                || !records
                    .iter()
                    .any(|record| super::validation::candidate_matches(candidate, record))
            {
                return Err(crate::error::Failure::InvalidCandidate {
                    path: candidate.path.clone(),
                });
            }
            let digest = candidate.digest();
            let staged_blob = crate::payload::stage(&self.root, digest, &candidate.bytes)?;
            staged.insert(
                *digest.as_bytes(),
                (
                    digest,
                    staged_blob.byte_length,
                    mneme_core::EncodingProfile::RawBytesV1,
                    mneme_core::ValueBoundary::SourceBytes,
                ),
            );
        }
        Ok(())
    }

    fn stage_publication_blobs(
        &self,
        publications: &[crate::requests::PublicationDraft],
        staged: &mut super::BlobIndex,
    ) -> crate::error::Result<()> {
        for publication in publications {
            crate::payload::validate_relative_path(&publication.path)?;
            let digest = publication.desired_digest();
            let staged_blob = crate::payload::stage(&self.root, digest, &publication.bytes)?;
            staged.insert(
                *digest.as_bytes(),
                (
                    digest,
                    staged_blob.byte_length,
                    mneme_core::EncodingProfile::RawBytesV1,
                    mneme_core::ValueBoundary::SourceBytes,
                ),
            );
        }
        Ok(())
    }

    fn create_commit_manifest(
        &self,
        command: &crate::requests::CommitCommand,
        base: mneme_core::WorkspaceRevisionId,
        prior: &super::Snapshot,
        new_records: &[mneme_core::RecordEnvelope],
    ) -> crate::error::Result<super::CommitManifest> {
        let mut snapshot_records: std::collections::BTreeMap<
            mneme_core::RecordId,
            mneme_core::RecordEnvelope,
        > = prior
            .records
            .iter()
            .map(|record| (record.record_id, record.clone()))
            .collect();
        for record in new_records {
            snapshot_records.insert(record.record_id, record.clone());
        }
        super::validation::validate_snapshot_bindings(&snapshot_records)?;
        let manifest_records = snapshot_records
            .values()
            .map(|record| crate::catalog::ManifestRecord {
                record_id: record.record_id,
                revision_id: record.revision_id,
                kind: record.kind,
            })
            .collect();
        let mut required_blobs = std::collections::BTreeSet::new();
        for record in snapshot_records.values() {
            required_blobs.insert(mneme_core::ContentDigest::of_full_record(
                &record.to_value(),
            ));
            if let Some(digest) = super::validation::retained_source_digest(record) {
                required_blobs.insert(digest);
            }
        }
        for publication in &command.publications {
            required_blobs.insert(publication.desired_digest());
        }
        let revision_id =
            mneme_core::WorkspaceRevisionId::from_bytes(crate::payload::random_bytes()?);
        let manifest = crate::catalog::Manifest {
            revision: revision_id,
            parent: Some(base),
            records: manifest_records,
            blobs: required_blobs,
        };
        let manifest_digest = manifest.digest();
        Ok(super::CommitManifest {
            snapshot_records,
            revision_id,
            manifest,
            manifest_digest,
        })
    }

    /// The ledger facts of every blob the prepared revision requires.
    ///
    /// One statement reads exactly the digests this revision names, staged
    /// metadata is compared against any row that already holds the digest, and
    /// the resulting lengths are reused by the commit transaction instead of one
    /// statement per blob. A staged blob was hashed when it was staged and an
    /// inherited one was hashed by the read that serves it, so their presence at
    /// the recorded length is re-established once, inside the transaction.
    fn verify_commit_blobs(
        &self,
        manifest: &super::CommitManifest,
        staged: &super::BlobIndex,
    ) -> crate::error::Result<super::BlobIndex> {
        let keys = manifest
            .manifest
            .blobs
            .iter()
            .map(|digest| *digest.as_bytes())
            .collect::<std::collections::BTreeSet<_>>();
        let mut blob_lengths = super::publishing::blob_lengths_for(&self.connection, &keys)?;
        for (key, (digest, length, profile, boundary)) in staged {
            if let Some(existing) = blob_lengths.get(key) {
                if existing.1 != *length || existing.2 != *profile || existing.3 != *boundary {
                    return Err(crate::error::Failure::CorruptBlob {
                        digest: digest.to_hex(),
                        reason: "blob metadata differs from an existing digest".to_owned(),
                    });
                }
            } else {
                blob_lengths.insert(*key, (*digest, *length, *profile, *boundary));
            }
        }
        super::validation::validate_snapshot_sources(&manifest.snapshot_records, &blob_lengths)?;
        // Every manifest blob is either staged by this commit or already recorded
        // in the ledger; only a ledger that names bytes no revision committed
        // reaches this failure.
        for digest in &manifest.manifest.blobs {
            if !blob_lengths.contains_key(digest.as_bytes()) {
                return Err(crate::error::Failure::MissingBlob {
                    digest: digest.to_hex(),
                });
            }
        }
        Ok(blob_lengths)
    }

    fn write_prepared_commit(
        &mut self,
        command: &crate::requests::CommitCommand,
        prepared: &super::PreparedCommit,
    ) -> crate::error::Result<super::CommitWrite> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current_now = super::meta_blob(&transaction, super::META_CURRENT_REVISION)?;
        let generation_now = super::meta_u64(&transaction, super::META_GENERATION)?;
        let stored = super::publishing::lookup_command_in(&transaction, command)?;
        let facts = mneme_kernel::admission::CommitFacts {
            stored: stored
                .as_ref()
                .map(super::StoredCommand::kernel)
                .transpose()?,
            command: prepared.request_digest.to_kernel(),
            fingerprint: prepared
                .fingerprint
                .as_ref()
                .map(mneme_core::ContentDigest::to_kernel),
            base_is_current: current_now.as_slice() == prepared.base.as_bytes(),
            generation_is_pinned: generation_now == prepared.generation,
        };
        match mneme_kernel::admission::decide_commit(&facts) {
            mneme_kernel::admission::CommitDecision::Proceed => {}
            mneme_kernel::admission::CommitDecision::Replay => {
                let stored = stored.ok_or_else(|| crate::error::Failure::Integrity {
                    revision: prepared.base,
                    reason: "idempotent replay has no stored command".to_owned(),
                })?;
                drop(transaction);
                return self
                    .outcome_for_stored(&stored)
                    .map(super::CommitWrite::Existing);
            }
            mneme_kernel::admission::CommitDecision::IdempotencyConflict => {
                return Err(crate::error::Failure::IdempotencyConflict {
                    key: command.idempotency_key.clone(),
                });
            }
            mneme_kernel::admission::CommitDecision::StaleBase => {
                return Err(crate::error::Failure::StaleBase {
                    base: prepared.base,
                    current: super::revision_from_blob(&current_now)?,
                });
            }
            mneme_kernel::admission::CommitDecision::BarrierAdvanced => {
                return Err(crate::error::Failure::BarrierAdvanced {
                    pinned: prepared.generation,
                    current: generation_now,
                });
            }
        }
        Self::ensure_commit_blobs_present(&self.root, command, prepared)?;
        let intent_ids = Self::insert_prepared_commit(&transaction, command, prepared)?;
        transaction.commit()?;
        Ok(super::CommitWrite::New(intent_ids))
    }

    /// Re-establish every blob the prepared revision names before its rows are
    /// written.
    ///
    /// The check runs inside the immediate transaction that writes the rows, so
    /// a recovery sweep cannot delete a blob between the check and the commit.
    /// A staged blob that a concurrent sweep removed is rewritten from the
    /// command's own bytes; an inherited blob that is absent fails closed.
    fn ensure_commit_blobs_present(
        root: &std::path::Path,
        command: &crate::requests::CommitCommand,
        prepared: &super::PreparedCommit,
    ) -> crate::error::Result<()> {
        super::publishing::restore_staged_blobs(
            root,
            command,
            &prepared.new_records,
            &prepared.staged,
        )?;
        for digest in &prepared.manifest.blobs {
            if prepared.staged.contains_key(digest.as_bytes()) {
                continue;
            }
            // Blob rows are immutable once written: the length read before the
            // transaction is the length the ledger records now, and the check
            // that the file still has it runs here, inside the transaction.
            let Some((_, recorded, _, _)) = prepared.blob_lengths.get(digest.as_bytes()) else {
                return Err(crate::error::Failure::MissingBlob {
                    digest: digest.to_hex(),
                });
            };
            if !crate::payload::blob_is_present(root, *digest, *recorded)? {
                return Err(crate::error::Failure::MissingBlob {
                    digest: digest.to_hex(),
                });
            }
        }
        Ok(())
    }

    fn insert_prepared_commit(
        transaction: &rusqlite::Transaction<'_>,
        command: &crate::requests::CommitCommand,
        prepared: &super::PreparedCommit,
    ) -> crate::error::Result<Vec<String>> {
        Self::insert_revision_row(transaction, command, prepared)?;
        Self::insert_blob_rows(transaction, &prepared.staged)?;
        Self::insert_record_rows(transaction, &prepared.new_records)?;
        Self::insert_membership(transaction, prepared)?;
        Self::insert_blob_set_changes(transaction, prepared)?;
        let intent_ids = Self::insert_publication_intents(transaction, command, prepared)?;
        Self::insert_command_row(transaction, command, prepared)?;
        if command.retention.is_some() {
            Self::insert_retention_commit(transaction, command, prepared)?;
        }
        super::set_meta(
            transaction,
            super::META_CURRENT_REVISION,
            prepared.revision_id.as_bytes(),
        )?;
        super::set_meta_u64(
            transaction,
            super::META_CURRENT_SEQUENCE,
            prepared.next_sequence,
        )?;
        if command.retention.is_some() {
            super::set_meta_u64(
                transaction,
                super::META_GENERATION,
                prepared.next_generation,
            )?;
        }
        Ok(intent_ids)
    }

    fn insert_revision_row(
        transaction: &rusqlite::Transaction<'_>,
        command: &crate::requests::CommitCommand,
        prepared: &super::PreparedCommit,
    ) -> crate::error::Result<()> {
        transaction.execute(
            "INSERT INTO revisions (sequence, revision_id, parent_revision_id, committed_at_ns,
                 actor, scope, command_id, request_digest, eligibility_generation, manifest,
                 manifest_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                super::db_i64(prepared.next_sequence, "sequence")?,
                prepared.revision_id.as_bytes().as_slice(),
                prepared.base.as_bytes().as_slice(),
                prepared.recorded.at().nanos(),
                command.actor,
                command.scope.to_string(),
                command.idempotency_key,
                prepared.request_digest.as_bytes().as_slice(),
                super::db_i64(prepared.next_generation, "generation")?,
                Vec::<u8>::new(),
                prepared.manifest_digest.as_bytes().as_slice(),
            ],
        )?;
        Ok(())
    }

    fn insert_blob_rows(
        transaction: &rusqlite::Transaction<'_>,
        staged: &super::BlobIndex,
    ) -> crate::error::Result<()> {
        for (key, (digest, length, profile, boundary)) in staged {
            let existing = transaction
                .query_row(
                    "SELECT profile, boundary, byte_length FROM blobs WHERE digest = ?1",
                    rusqlite::params![key.as_slice()],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .optional()?;
            if let Some((existing_profile, existing_boundary, existing_length)) = existing {
                if existing_profile != profile.symbol()
                    || existing_boundary != boundary.symbol()
                    || existing_length != super::db_i64(*length, "blob length")?
                {
                    return Err(crate::error::Failure::CorruptBlob {
                        digest: digest.to_hex(),
                        reason: "stored blob metadata differs from this command".to_owned(),
                    });
                }
            } else {
                transaction.execute(
                    "INSERT INTO blobs (digest, algorithm, profile, boundary, byte_length)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        key.as_slice(),
                        digest.algorithm().symbol(),
                        profile.symbol(),
                        boundary.symbol(),
                        super::db_i64(*length, "blob length")?,
                    ],
                )?;
            }
        }
        Ok(())
    }

    fn insert_record_rows(
        transaction: &rusqlite::Transaction<'_>,
        records: &[mneme_core::RecordEnvelope],
    ) -> crate::error::Result<()> {
        for record in records {
            let full = record.full_digest();
            transaction.execute(
                "INSERT INTO records (record_id, revision_id, kind, schema_version, scope,
                     recorded_at_ns, recorded_order, envelope_digest, payload_digest, full_digest)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    record.record_id.as_bytes().as_slice(),
                    record.revision_id.as_bytes().as_slice(),
                    record.kind.symbol(),
                    i64::from(record.schema_version),
                    record.scope.to_string(),
                    record.recorded.at().nanos(),
                    super::db_i64(record.recorded.revision_order(), "revision order")?,
                    full.as_bytes().as_slice(),
                    record.payload_digest().as_bytes().as_slice(),
                    full.as_bytes().as_slice(),
                ],
            )?;
        }
        Ok(())
    }

    /// Close the intervals of the records this commit replaces or drops and
    /// open intervals for the records it adds.
    ///
    /// The written rows are proportional to the records this commit changes,
    /// never to the size of the snapshot.
    fn insert_membership(
        transaction: &rusqlite::Transaction<'_>,
        prepared: &super::PreparedCommit,
    ) -> crate::error::Result<()> {
        let mut statement = transaction.prepare(
            "SELECT record_id, revision_id FROM record_membership WHERE last_sequence IS NULL",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        let open = rows
            .into_iter()
            .map(|(record_id, revision_id)| {
                Ok((
                    super::record_id_from_blob(&record_id, prepared.revision_id)?,
                    super::revision_id_from_blob(&revision_id, prepared.revision_id)?,
                ))
            })
            .collect::<crate::error::Result<std::collections::BTreeMap<_, _>>>()?;
        let closing = super::db_i64(prepared.next_sequence.saturating_sub(1), "sequence")?;
        for (record_id, revision_id) in &open {
            let is_kept = prepared
                .snapshot_records
                .get(record_id)
                .is_some_and(|record| record.revision_id == *revision_id);
            if is_kept {
                continue;
            }
            transaction.execute(
                "UPDATE record_membership SET last_sequence = ?1
                 WHERE record_id = ?2 AND last_sequence IS NULL",
                rusqlite::params![closing, record_id.as_bytes().as_slice(),],
            )?;
        }
        for (record_id, record) in &prepared.snapshot_records {
            if open.get(record_id) == Some(&record.revision_id) {
                continue;
            }
            transaction.execute(
                "INSERT INTO record_membership
                     (record_id, revision_id, first_sequence, last_sequence)
                 VALUES (?1, ?2, ?3, NULL)",
                rusqlite::params![
                    record_id.as_bytes().as_slice(),
                    record.revision_id.as_bytes().as_slice(),
                    super::db_i64(prepared.next_sequence, "sequence")?,
                ],
            )?;
        }
        Ok(())
    }

    /// Record how this revision's required-digest set differs from its parent's.
    fn insert_blob_set_changes(
        transaction: &rusqlite::Transaction<'_>,
        prepared: &super::PreparedCommit,
    ) -> crate::error::Result<()> {
        let base_sequence = prepared.next_sequence.saturating_sub(1);
        let previous = super::manifest_blob_set(transaction, base_sequence, prepared.base)?;
        let sequence = super::db_i64(prepared.next_sequence, "sequence")?;
        for digest in prepared.manifest.blobs.difference(&previous) {
            transaction.execute(
                "INSERT INTO revision_blob_changes (revision_sequence, digest, change)
                 VALUES (?1, ?2, 'add')",
                rusqlite::params![sequence, digest.as_bytes().as_slice()],
            )?;
        }
        for digest in previous.difference(&prepared.manifest.blobs) {
            transaction.execute(
                "INSERT INTO revision_blob_changes (revision_sequence, digest, change)
                 VALUES (?1, ?2, 'remove')",
                rusqlite::params![sequence, digest.as_bytes().as_slice()],
            )?;
        }
        Ok(())
    }

    fn insert_publication_intents(
        transaction: &rusqlite::Transaction<'_>,
        command: &crate::requests::CommitCommand,
        prepared: &super::PreparedCommit,
    ) -> crate::error::Result<Vec<String>> {
        let mut intent_ids = Vec::with_capacity(command.publications.len());
        for publication in &command.publications {
            let intent_id = crate::payload::random_hex(16)?;
            transaction.execute(
                "INSERT INTO publication_intents (intent_id, revision_sequence, target_path,
                     expected_digest, desired_digest, eligibility_generation, state, observed_digest,
                     detail, updated_at_ns)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', NULL, NULL, ?7)",
                rusqlite::params![
                    intent_id,
                    super::db_i64(prepared.next_sequence, "sequence")?,
                    publication.path,
                    publication
                        .expected_previous
                        .map(|digest| digest.as_bytes().to_vec()),
                    publication.desired_digest().as_bytes().as_slice(),
                    super::db_i64(prepared.generation, "generation")?,
                    prepared.recorded.at().nanos(),
                ],
            )?;
            intent_ids.push(intent_id);
        }
        Ok(intent_ids)
    }

    fn insert_command_row(
        transaction: &rusqlite::Transaction<'_>,
        command: &crate::requests::CommitCommand,
        prepared: &super::PreparedCommit,
    ) -> crate::error::Result<()> {
        transaction.execute(
            "INSERT INTO commands (actor, scope, idempotency_key, request_digest, fingerprint,
                 base_revision, outcome_revision, outcome_sequence, committed_at_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                command.actor,
                command.scope.to_string(),
                command.idempotency_key,
                prepared.request_digest.as_bytes().as_slice(),
                prepared
                    .fingerprint
                    .map(|fingerprint| fingerprint.as_bytes().to_vec()),
                prepared.base.as_bytes().as_slice(),
                prepared.revision_id.as_bytes().as_slice(),
                super::db_i64(prepared.next_sequence, "sequence")?,
                prepared.recorded.at().nanos(),
            ],
        )?;
        Ok(())
    }

    fn insert_retention_commit(
        transaction: &rusqlite::Transaction<'_>,
        command: &crate::requests::CommitCommand,
        prepared: &super::PreparedCommit,
    ) -> crate::error::Result<()> {
        let Some(retention) = &command.retention else {
            return Ok(());
        };
        let retained_metadata = retention.retained_metadata.join("\n");
        transaction.execute(
            "INSERT INTO retention_operations (operation_id, operation_kind, actor, scope,
                 policy_version, idempotency_key, request_digest, state, generation,
                 outcome_revision, outcome_sequence, retained_metadata, created_at_ns,
                 updated_at_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'barrier-committed', ?8, ?9, ?10, ?11,
                 ?12, ?12)",
            rusqlite::params![
                retention.operation_id,
                retention.operation_kind,
                command.actor,
                command.scope.to_string(),
                retention.policy_version,
                command.idempotency_key,
                prepared.request_digest.as_bytes().as_slice(),
                super::db_i64(prepared.next_generation, "generation")?,
                prepared.revision_id.as_bytes().as_slice(),
                super::db_i64(prepared.next_sequence, "sequence")?,
                retained_metadata,
                prepared.recorded.at().nanos(),
            ],
        )?;
        Self::insert_retention_selectors(transaction, retention)?;
        Self::insert_retention_suppressions(transaction, retention)?;
        Self::insert_retention_locations(transaction, retention, prepared.recorded)?;
        transaction.execute(
            "UPDATE publication_intents
             SET state = 'suppressed', detail = 'retention barrier',
                 updated_at_ns = ?1
             WHERE state = 'pending' AND eligibility_generation < ?2",
            rusqlite::params![
                prepared.recorded.at().nanos(),
                super::db_i64(prepared.next_generation, "generation")?,
            ],
        )?;
        Ok(())
    }

    fn insert_retention_selectors(
        transaction: &rusqlite::Transaction<'_>,
        retention: &crate::lifecycle::RetentionCommit,
    ) -> crate::error::Result<()> {
        for selector in &retention.selectors {
            transaction.execute(
                "INSERT INTO retention_selectors (operation_id, ordinal, selector_kind,
                     target_id, target_revision, target_digest)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    retention.operation_id,
                    i64::from(selector.ordinal),
                    selector.kind,
                    selector.target.map(|target| target.as_bytes().to_vec()),
                    selector
                        .revision
                        .map(|revision| revision.as_bytes().to_vec()),
                    selector.digest.map(|digest| digest.as_bytes().to_vec()),
                ],
            )?;
        }
        Ok(())
    }

    fn insert_retention_suppressions(
        transaction: &rusqlite::Transaction<'_>,
        retention: &crate::lifecycle::RetentionCommit,
    ) -> crate::error::Result<()> {
        for suppression in &retention.suppressions {
            transaction.execute(
                "INSERT INTO retention_suppressions (operation_id, target_id, target_revision,
                     target_kind, mode, content_digest, generation)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    suppression.operation_id,
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
        }
        Ok(())
    }

    fn insert_retention_locations(
        transaction: &rusqlite::Transaction<'_>,
        retention: &crate::lifecycle::RetentionCommit,
        recorded: mneme_core::RecordedTime,
    ) -> crate::error::Result<()> {
        for location in &retention.locations {
            transaction.execute(
                "INSERT INTO retention_locations (operation_id, location_id, location_kind,
                     locator, state, attempts, verified, detail_code, updated_at_ns)
                 VALUES (?1, ?2, ?3, ?4, 'pending', 0, 0, NULL, ?5)",
                rusqlite::params![
                    retention.operation_id,
                    location.location_id,
                    location.location_kind,
                    location.locator,
                    recorded.at().nanos(),
                ],
            )?;
        }
        Ok(())
    }

    fn ensure_revisions_unused(
        &self,
        records: &[mneme_core::RecordEnvelope],
    ) -> crate::error::Result<()> {
        for record in records {
            let exists: Option<i64> = self
                .connection
                .query_row(
                    "SELECT 1 FROM records WHERE revision_id = ?1",
                    rusqlite::params![record.revision_id.as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .optional()?;
            if exists.is_some() {
                return Err(crate::error::Failure::InvalidCommand(format!(
                    "revision {} is already committed",
                    record.revision_id
                )));
            }
        }
        Ok(())
    }

    /// Refuse a command that would recreate forgotten bytes.
    ///
    /// Identity suppressions apply to every scope: a forgotten record identity
    /// stays unusable. Content suppressions apply only to the scope of the
    /// retention operation that created them, so a forget in one scope neither
    /// blocks nor discloses the same bytes held by another scope. Every byte
    /// input of the command is checked, whether the bytes arrive as a source
    /// blob, a publication, an import candidate or a bare digest reference.
    fn ensure_not_suppressed(
        &self,
        command: &crate::requests::CommitCommand,
    ) -> crate::error::Result<()> {
        let forgotten = self.forgotten_suppressions()?;
        for draft in &command.records {
            if forgotten.identities.contains(&draft.record_id)
                || forgotten
                    .revisions
                    .contains(&(draft.record_id, draft.revision_id))
            {
                return Err(crate::error::Failure::RetentionSuppressed {
                    target: draft.record_id.to_string(),
                });
            }
        }
        // Every command input contributes at most one digest reference.
        let mut digests: Vec<mneme_core::ContentDigest> = Vec::with_capacity(
            command.source_blobs.len()
                + command.publications.len()
                + command.import_candidates.len()
                + command.records.len(),
        );
        for blob in &command.source_blobs {
            digests.push(blob.digest());
        }
        for publication in &command.publications {
            digests.push(publication.desired_digest());
        }
        for candidate in &command.import_candidates {
            digests.push(candidate.digest());
        }
        for draft in &command.records {
            if let Some((digest, _, _)) = super::validation::retained_source_draft(draft)? {
                digests.push(digest);
            }
        }
        if digests.is_empty() {
            return Ok(());
        }
        let forbidden = super::sweep::forgotten_content_digests(&self.connection, &command.scope)?;
        if forbidden.is_empty() {
            return Ok(());
        }
        for digest in digests {
            if forbidden.contains(digest.as_bytes().as_slice()) {
                return Err(crate::error::Failure::RetentionSuppressed {
                    target: "forgotten-content".to_owned(),
                });
            }
        }
        Ok(())
    }

    fn lookup_command(
        &self,
        command: &crate::requests::CommitCommand,
    ) -> crate::error::Result<Option<super::StoredCommand>> {
        super::publishing::lookup_command_in(&self.connection, command)
    }

    /// Read the outcome recorded for one request fingerprint.
    ///
    /// Returns `None` when no command is stored under the key, the recorded
    /// outcome when the stored fingerprint is this request's fingerprint, and
    /// an idempotency conflict when the key is bound to a different request or
    /// to a command that was committed without a fingerprint.
    pub fn replay_outcome(
        &self,
        actor: &str,
        scope: &mneme_core::ScopeId,
        idempotency_key: &str,
        fingerprint: &mneme_core::ContentDigest,
    ) -> crate::error::Result<Option<super::CommitOutcome>> {
        let stored = super::publishing::lookup_stored_command(
            &self.connection,
            actor,
            scope,
            idempotency_key,
        )?;
        let Some(stored) = stored else {
            return Ok(None);
        };
        let offered = fingerprint.to_kernel();
        let decision = mneme_kernel::admission::decide_replay(&Some(stored.kernel()?), &offered);
        match decision {
            mneme_kernel::admission::ReplayDecision::Fresh => Ok(None),
            mneme_kernel::admission::ReplayDecision::Replay => {
                self.outcome_for_stored(&stored).map(Some)
            }
            mneme_kernel::admission::ReplayDecision::Conflict => {
                Err(crate::error::Failure::IdempotencyConflict {
                    key: idempotency_key.to_owned(),
                })
            }
        }
    }

    fn outcome_for_stored(
        &self,
        stored: &super::StoredCommand,
    ) -> crate::error::Result<super::CommitOutcome> {
        let row = super::revision_row_by_id(&self.connection, stored.outcome_revision)?
            .ok_or_else(|| crate::error::Failure::Integrity {
                revision: stored.outcome_revision,
                reason: "idempotent outcome revision is missing".to_owned(),
            })?;
        if row.sequence != stored.outcome_sequence {
            return Err(crate::error::Failure::Integrity {
                revision: stored.outcome_revision,
                reason: "idempotent outcome sequence does not match the revision row".to_owned(),
            });
        }
        let publications = super::publishing::publication_outcomes(&self.connection, row.sequence)?;
        Ok(super::CommitOutcome {
            revision: row.revision,
            sequence: row.sequence,
            manifest_digest: row.manifest_digest,
            eligibility_generation: row.eligibility_generation,
            publications,
        })
    }
}
