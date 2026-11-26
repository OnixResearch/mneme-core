//! Publication of working files and startup recovery.
//!
//! Each intent is published as a separately recoverable step: the target is
//! quarantined, decided over with the kernel, and either installed or restored,
//! so a divergent external edit is never overwritten.

use rusqlite::OptionalExtension;

impl super::Workspace {
    /// Publish every working-file intent that still needs an attempt.
    ///
    /// The kernel decides which intents are attempted: a pending intent and a
    /// failed attempt are both retried, so a transient filesystem error never
    /// leaves a committed revision permanently unpublished. A published,
    /// diverged or suppressed intent is final and keeps its recorded outcome.
    pub fn publish_pending(&mut self) -> crate::error::Result<Vec<super::PublicationOutcome>> {
        self.require_restore_suppression()?;
        let mut statement = self
            .connection
            .prepare("SELECT intent_id, state FROM publication_intents ORDER BY rowid")?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        let ids = rows
            .into_iter()
            .map(|(intent_id, state)| {
                let state = intent_state(&state);
                (intent_id, state)
            })
            .filter(|(_, state)| state.should_attempt())
            .map(|(intent_id, _)| intent_id)
            .collect::<Vec<_>>();
        let mut outcomes = Vec::with_capacity(ids.len());
        for intent_id in ids {
            match self.publish_intent(&intent_id) {
                Ok(outcome) => outcomes.push(outcome),
                Err(crate::error::Failure::InjectedFault(point)) => {
                    return Err(crate::error::Failure::InjectedFault(point));
                }
                Err(error) => {
                    self.mark_intent_failed(&intent_id, &error)?;
                    outcomes.push(self.publication_outcome(&intent_id)?.ok_or_else(|| {
                        crate::error::Failure::InvalidCommand(
                            "publication intent disappeared".to_owned(),
                        )
                    })?);
                }
            }
        }
        Ok(outcomes)
    }

    /// Startup recovery: remove orphans, verify the current manifest, and
    /// resume pending publication intents.
    ///
    /// The orphan sweep reads the ledger's blob set and deletes files inside one
    /// immediate transaction, so it cannot interleave with a commit between that
    /// commit's blob staging and its own ledger write. The verification re-hashes
    /// every payload from disk: recovery exists to observe corruption this handle
    /// may already have decoded from a good copy.
    pub fn recover(&mut self) -> crate::error::Result<super::RecoveryReport> {
        let (staged, orphan_blobs) = {
            // The exclusive lock is held across the sweep, so no commit is
            // between blob staging and its transaction while orphans are
            // removed, and two recoveries never sweep at once.
            let _guard = self.exclusive_sweep_lock()?;
            let transaction = self
                .connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let known = known_blob_digests(&transaction)?;
            let removed = crate::payload::cleanup_orphans(&self.root, &known)?;
            transaction.commit()?;
            removed
        };
        let temporaries = crate::payload::cleanup_working_temporaries(&self.root)?;
        let snapshot = self.snapshot_from_disk()?;
        self.rebuild_metadata_projection(&snapshot)?;
        let publications = self.publish_pending()?;
        #[cfg(feature = "trace-spec")]
        if let Ok(orphans_removed) = u64::try_from(orphan_blobs) {
            crate::trace::emit(crate::trace::Event::Recover { orphans_removed });
        }
        Ok(super::RecoveryReport {
            staged_files_removed: staged,
            orphan_blobs_removed: orphan_blobs,
            working_temporaries_removed: temporaries,
            revision: snapshot.revision,
            publications,
        })
    }

    pub(super) fn publish_intent(
        &self,
        intent_id: &str,
    ) -> crate::error::Result<super::PublicationOutcome> {
        let intent = self.publication_intent(intent_id)?.ok_or_else(|| {
            crate::error::Failure::InvalidCommand(format!(
                "publication intent {intent_id} is missing"
            ))
        })?;
        if !intent.state.should_attempt() {
            return self.require_outcome(intent_id);
        }
        let outcome = if let Some(outcome) = self.suppress_stale_publication(intent_id, &intent)? {
            outcome
        } else {
            self.publish_current_intent(intent_id, &intent)?
        };
        #[cfg(feature = "trace-spec")]
        crate::trace::emit(crate::trace::Event::PublishIntent(
            crate::trace::PublishIntentData {
                intent_sequence: intent.revision_sequence,
                intent_generation: intent.eligibility_generation,
                outcome: outcome.state.as_str().to_owned(),
            },
        ));
        Ok(outcome)
    }

    fn suppress_stale_publication(
        &self,
        intent_id: &str,
        intent: &StoredIntent,
    ) -> crate::error::Result<Option<super::PublicationOutcome>> {
        let current_sequence = self.current_sequence()?;
        if intent.revision_sequence != current_sequence {
            self.set_intent_state(
                intent_id,
                super::PublicationState::Suppressed,
                None,
                Some("revision is not current".to_owned()),
            )?;
            return self.require_outcome(intent_id).map(Some);
        }
        let generation = self.eligibility_generation()?;
        if intent.eligibility_generation != generation {
            self.set_intent_state(
                intent_id,
                super::PublicationState::Suppressed,
                None,
                Some("eligibility generation advanced".to_owned()),
            )?;
            return self.require_outcome(intent_id).map(Some);
        }
        Ok(None)
    }

    /// Publish one intent whose revision and generation are still current.
    ///
    /// The working entry is renamed aside first and the decision is taken over
    /// the displaced bytes, so no path-based writer can change the content
    /// between the check and the replacement. The new file is installed with a
    /// hard link, so a file that appeared meanwhile is reported as diverged
    /// instead of being overwritten, and displaced content that was not the
    /// expected one is always put back.
    fn publish_current_intent(
        &self,
        intent_id: &str,
        intent: &StoredIntent,
    ) -> crate::error::Result<super::PublicationOutcome> {
        let desired = intent.desired_digest;
        let bytes = crate::payload::read(&self.root, desired)?;
        let target = crate::payload::prepare_working_target(&self.root, &intent.target_path)?;
        let mut guard = crate::payload::quarantine_working_file(&self.root, &intent.target_path)?;
        let (observed, observed_for_kernel) = match guard.entry() {
            Some(file) => match file.read()? {
                crate::payload::WorkingEntry::Absent => (None, None),
                crate::payload::WorkingEntry::Regular(found) => {
                    let recorded = mneme_core::ContentDigest::of_source_bytes(&found);
                    let kernel_digest = if desired.verify_source_bytes(&found) {
                        desired.to_kernel()
                    } else if intent
                        .expected_digest
                        .is_some_and(|expected| expected.verify_source_bytes(&found))
                    {
                        intent
                            .expected_digest
                            .map_or_else(|| recorded.to_kernel(), |expected| expected.to_kernel())
                    } else {
                        recorded.to_kernel()
                    };
                    (Some(recorded), Some(kernel_digest))
                }
                crate::payload::WorkingEntry::NotRegular => {
                    // A FIFO, directory, symbolic link or device is never
                    // opened or replaced; put it back and report the obstacle.
                    guard.restore()?;
                    self.set_intent_state(
                        intent_id,
                        super::PublicationState::Failed,
                        None,
                        Some("working target is not a regular file".to_owned()),
                    )?;
                    return self.require_outcome(intent_id);
                }
            },
            None => (None, None),
        };
        let decision =
            mneme_kernel::publish::decide_publication(&mneme_kernel::publish::PublicationFacts {
                observed: observed_for_kernel,
                expected: intent.expected_digest.map(|digest| digest.to_kernel()),
                desired: desired.to_kernel(),
            });
        let attempt = PublicationAttempt {
            intent_id,
            target: &target,
            bytes: &bytes,
            desired,
            observed,
        };
        match decision {
            mneme_kernel::publish::PublicationDecision::AlreadyPublished => {
                self.publish_already_published(&mut guard, &attempt)
            }
            mneme_kernel::publish::PublicationDecision::Diverged => {
                self.publish_diverged(&mut guard, &attempt)
            }
            mneme_kernel::publish::PublicationDecision::Replace => {
                self.publish_replacement(&mut guard, &attempt)
            }
        }
    }

    /// Report an intent whose target already held the desired bytes.
    fn publish_already_published(
        &self,
        guard: &mut crate::payload::QuarantineGuard,
        attempt: &PublicationAttempt<'_>,
    ) -> crate::error::Result<super::PublicationOutcome> {
        let is_restored = guard.restore()?;
        if is_restored {
            self.set_intent_state(
                attempt.intent_id,
                super::PublicationState::Published,
                attempt.observed,
                None,
            )?;
        } else {
            // The displaced file already held the desired bytes, but a new entry
            // appeared at the target. The displaced content was not the expected
            // previous content, so it is kept rather than deleted, and the
            // divergence is reported.
            self.set_intent_state(
                attempt.intent_id,
                super::PublicationState::Diverged,
                attempt.observed,
                Some("working file appeared during publication".to_owned()),
            )?;
        }
        self.require_outcome(attempt.intent_id)
    }

    /// Report an intent whose target no longer held the expected previous bytes.
    fn publish_diverged(
        &self,
        guard: &mut crate::payload::QuarantineGuard,
        attempt: &PublicationAttempt<'_>,
    ) -> crate::error::Result<super::PublicationOutcome> {
        let is_restored = guard.restore()?;
        let detail = if is_restored {
            "working file changed since the expected previous content"
        } else {
            "working file appeared during publication"
        };
        self.set_intent_state(
            attempt.intent_id,
            super::PublicationState::Diverged,
            attempt.observed,
            Some(detail.to_owned()),
        )?;
        self.require_outcome(attempt.intent_id)
    }

    /// Install the desired bytes when the target still holds the expected
    /// previous content, and record the outcome either way.
    fn publish_replacement(
        &self,
        guard: &mut crate::payload::QuarantineGuard,
        attempt: &PublicationAttempt<'_>,
    ) -> crate::error::Result<super::PublicationOutcome> {
        crate::injectors::check(
            self.faults.as_ref(),
            crate::injectors::FaultPoint::BeforeFileReplace,
        )?;
        let is_installed = crate::payload::install_working_file(attempt.target, attempt.bytes)?;
        if is_installed {
            // The displaced entry was exactly the expected content, so it is the
            // only content this publication may discard.
            guard.discard()?;
            crate::injectors::check(
                self.faults.as_ref(),
                crate::injectors::FaultPoint::AfterFileReplace,
            )?;
            self.set_intent_state(
                attempt.intent_id,
                super::PublicationState::Published,
                Some(attempt.desired),
                None,
            )?;
        } else {
            // A new entry appeared between the decision and the install; it is
            // never overwritten. The displaced expected content is reproducible
            // from the blob store.
            guard.discard()?;
            self.set_intent_state(
                attempt.intent_id,
                super::PublicationState::Diverged,
                attempt.observed,
                Some("working file appeared during replacement".to_owned()),
            )?;
        }
        self.require_outcome(attempt.intent_id)
    }

    fn require_outcome(&self, intent_id: &str) -> crate::error::Result<super::PublicationOutcome> {
        self.publication_outcome(intent_id)?.ok_or_else(|| {
            crate::error::Failure::InvalidCommand("publication intent disappeared".to_owned())
        })
    }

    pub(super) fn mark_intent_failed(
        &self,
        intent_id: &str,
        error: &crate::error::Failure,
    ) -> crate::error::Result<()> {
        self.set_intent_state(
            intent_id,
            super::PublicationState::Failed,
            None,
            Some(error.to_string()),
        )
    }

    fn set_intent_state(
        &self,
        intent_id: &str,
        state: super::PublicationState,
        observed: Option<mneme_core::ContentDigest>,
        detail: Option<String>,
    ) -> crate::error::Result<()> {
        self.connection.execute(
            "UPDATE publication_intents SET state = ?1, observed_digest = ?2,
                 observed_algorithm = ?3, detail = ?4, updated_at_ns = ?5
             WHERE intent_id = ?6",
            rusqlite::params![
                state.as_str(),
                observed.map(|digest| digest.as_bytes().to_vec()),
                observed.map(|digest| digest.algorithm().symbol()),
                detail,
                self.clock.now().nanos(),
                intent_id,
            ],
        )?;
        Ok(())
    }

    fn publication_intent(&self, intent_id: &str) -> crate::error::Result<Option<StoredIntent>> {
        let row = self
            .connection
            .query_row(
                "SELECT revision_sequence, target_path, expected_digest, expected_algorithm,
                        desired_digest, eligibility_generation, state
                 FROM publication_intents WHERE intent_id = ?1",
                rusqlite::params![intent_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            revision_sequence,
            target_path,
            expected_digest,
            expected_algorithm,
            desired_digest,
            eligibility_generation,
            state,
        )) = row
        else {
            return Ok(None);
        };
        let revision = mneme_core::WorkspaceRevisionId::from_bytes([0; 16]);
        Ok(Some(StoredIntent {
            revision_sequence: super::db_u64(revision_sequence, "revision sequence")?,
            target_path,
            expected_digest: expected_digest
                .map(|bytes| {
                    intent_digest(
                        &self.connection,
                        &bytes,
                        expected_algorithm.as_deref(),
                        revision,
                    )
                })
                .transpose()?,
            desired_digest: stored_digest(&self.connection, &desired_digest, revision)?,
            eligibility_generation: super::db_u64(
                eligibility_generation,
                "eligibility generation",
            )?,
            state: intent_state(&state),
        }))
    }

    pub(super) fn publication_outcome(
        &self,
        intent_id: &str,
    ) -> crate::error::Result<Option<super::PublicationOutcome>> {
        let row = self
            .connection
            .query_row(
                "SELECT target_path, state, observed_digest, observed_algorithm, detail
                 FROM publication_intents WHERE intent_id = ?1",
                rusqlite::params![intent_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((path, state, observed, observed_algorithm, detail)) = row else {
            return Ok(None);
        };
        let revision = mneme_core::WorkspaceRevisionId::from_bytes([0; 16]);
        Ok(Some(super::PublicationOutcome {
            intent_id: intent_id.to_owned(),
            path,
            state: intent_state(&state),
            observed: observed
                .map(|bytes| {
                    intent_digest(
                        &self.connection,
                        &bytes,
                        observed_algorithm.as_deref(),
                        revision,
                    )
                })
                .transpose()?,
            detail,
        }))
    }

    /// Whether a publication intent currently has the expected state.
    pub fn publication_intent_has_state(
        &self,
        intent_id: &str,
        expected: super::PublicationState,
    ) -> crate::error::Result<bool> {
        Ok(self
            .publication_intent(intent_id)?
            .is_some_and(|intent| intent.state == expected))
    }

    /// All publication intents and their current outcomes.
    pub fn publication_intents(&self) -> crate::error::Result<Vec<super::PublicationOutcome>> {
        let mut statement = self.connection.prepare(
            "SELECT intent_id, target_path, state, observed_digest, observed_algorithm, detail
             FROM publication_intents ORDER BY rowid",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let revision = mneme_core::WorkspaceRevisionId::from_bytes([0; 16]);
        rows.into_iter()
            .map(
                |(intent_id, path, state, observed, observed_algorithm, detail)| {
                    Ok(super::PublicationOutcome {
                        intent_id,
                        path,
                        state: intent_state(&state),
                        observed: observed
                            .map(|bytes| {
                                intent_digest(
                                    &self.connection,
                                    &bytes,
                                    observed_algorithm.as_deref(),
                                    revision,
                                )
                            })
                            .transpose()?,
                        detail,
                    })
                },
            )
            .collect()
    }
}

#[derive(Clone, Debug)]
struct StoredIntent {
    revision_sequence: u64,
    target_path: String,
    expected_digest: Option<mneme_core::ContentDigest>,
    desired_digest: mneme_core::ContentDigest,
    eligibility_generation: u64,
    state: super::PublicationState,
}

/// One publication attempt: the intent it serves, the prepared target, the
/// replacement bytes and the digest observed at the target.
struct PublicationAttempt<'a> {
    intent_id: &'a str,
    target: &'a std::path::Path,
    bytes: &'a [u8],
    desired: mneme_core::ContentDigest,
    observed: Option<mneme_core::ContentDigest>,
}

pub(super) fn publication_outcomes(
    connection: &rusqlite::Connection,
    sequence: u64,
) -> crate::error::Result<Vec<super::PublicationOutcome>> {
    let mut statement = connection.prepare(
        "SELECT intent_id, target_path, state, observed_digest, observed_algorithm, detail
         FROM publication_intents WHERE revision_sequence = ?1 ORDER BY rowid",
    )?;
    let rows = statement
        .query_map(
            rusqlite::params![super::db_i64(sequence, "sequence")?],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            },
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let placeholder = mneme_core::WorkspaceRevisionId::from_bytes([0; 16]);
    rows.into_iter()
        .map(
            |(intent_id, path, state, observed, observed_algorithm, detail)| {
                Ok(super::PublicationOutcome {
                    intent_id,
                    path,
                    state: intent_state(&state),
                    observed: observed
                        .map(|bytes| {
                            intent_digest(
                                connection,
                                &bytes,
                                observed_algorithm.as_deref(),
                                placeholder,
                            )
                        })
                        .transpose()?,
                    detail,
                })
            },
        )
        .collect()
}

pub(super) fn lookup_command_in(
    connection: &rusqlite::Connection,
    command: &crate::requests::CommitCommand,
) -> crate::error::Result<Option<super::StoredCommand>> {
    lookup_stored_command(
        connection,
        &command.actor,
        &command.scope,
        &command.idempotency_key,
    )
}

/// Read the command row stored under one actor, scope and idempotency key.
pub(super) fn lookup_stored_command(
    connection: &rusqlite::Connection,
    actor: &str,
    scope: &mneme_core::ScopeId,
    idempotency_key: &str,
) -> crate::error::Result<Option<super::StoredCommand>> {
    let row = connection
        .query_row(
            "SELECT request_digest, fingerprint, outcome_revision, outcome_sequence FROM commands
             WHERE actor = ?1 AND scope = ?2 AND idempotency_key = ?3",
            rusqlite::params![actor, scope.to_string(), idempotency_key],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((request_digest, fingerprint, outcome_revision, outcome_sequence)) = row else {
        return Ok(None);
    };
    Ok(Some(super::StoredCommand {
        request_digest,
        fingerprint,
        outcome_revision: super::revision_from_blob(&outcome_revision)?,
        outcome_sequence: super::db_u64(outcome_sequence, "outcome sequence")?,
    }))
}

/// The digests the ledger currently registers as blobs.
fn known_blob_digests(
    connection: &rusqlite::Connection,
) -> crate::error::Result<std::collections::BTreeSet<[u8; 32]>> {
    let mut statement = connection.prepare("SELECT digest FROM blobs")?;
    let digests = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut known = std::collections::BTreeSet::new();
    for digest in digests {
        known.insert(super::digest_32(&digest)?);
    }
    Ok(known)
}

/// The ledger facts of the blobs a load names.
///
/// One statement reads the blob table in digest order and stops at the last
/// wanted digest, so the work follows the wanted set instead of the whole blob
/// inventory; a digest with no ledger row is simply absent from the result. The
/// keys are the raw digest bytes, exactly as the ledger stores them.
pub(super) fn blob_lengths_for(
    connection: &rusqlite::Connection,
    wanted: &std::collections::BTreeSet<[u8; 32]>,
) -> crate::error::Result<super::BlobIndex> {
    let Some(last) = wanted.iter().next_back().copied() else {
        return Ok(super::BlobIndex::new());
    };
    let mut statement = connection.prepare_cached(
        "SELECT digest, algorithm, profile, boundary, byte_length FROM blobs ORDER BY digest",
    )?;
    let mut rows = statement.query([])?;
    // At most one row per wanted digest is kept, so the scan buffer's bound is
    // the wanted set and not the blob inventory it walks.
    let mut selected = Vec::with_capacity(wanted.len());
    while let Some(row) = rows.next()? {
        let bytes: Vec<u8> = row.get(0)?;
        if bytes.as_slice() > last.as_slice() || selected.len() == wanted.len() {
            break;
        }
        let key = super::digest_32(&bytes)?;
        if !wanted.contains(&key) {
            continue;
        }
        let algorithm: String = row.get(1)?;
        let profile: String = row.get(2)?;
        let boundary: String = row.get(3)?;
        let length: i64 = row.get(4)?;
        selected.push((key, algorithm, profile, boundary, length));
    }
    let output = selected
        .into_iter()
        .map(|(key, algorithm, profile, boundary, length)| {
            blob_record(key, &algorithm, &profile, &boundary, length).map(|record| (key, record))
        })
        .collect::<crate::error::Result<super::BlobIndex>>()?;
    Ok(output)
}

/// One ledger blob row's decoded facts.
fn blob_record(
    key: [u8; 32],
    algorithm: &str,
    profile: &str,
    boundary: &str,
    length: i64,
) -> crate::error::Result<super::BlobRecord> {
    let Some(algorithm) = mneme_core::HashAlgorithm::parse(algorithm) else {
        return Err(crate::error::Failure::UnsupportedLayout(format!(
            "unknown blob algorithm {algorithm}"
        )));
    };
    let Some(profile) = mneme_core::EncodingProfile::parse(profile) else {
        return Err(crate::error::Failure::UnsupportedLayout(format!(
            "unknown blob profile {profile}"
        )));
    };
    let Some(boundary) = mneme_core::ValueBoundary::parse(boundary) else {
        return Err(crate::error::Failure::UnsupportedLayout(format!(
            "unknown blob boundary {boundary}"
        )));
    };
    let digest = mneme_core::ContentDigest::from_parts(algorithm, profile, boundary, key).map_err(
        |message| {
            crate::error::Failure::UnsupportedLayout(format!("ledger blob metadata: {message}"))
        },
    )?;
    Ok((
        digest,
        super::db_u64(length, "blob length")?,
        profile,
        boundary,
    ))
}

struct RebuiltBlob<'a> {
    bytes: Option<Vec<u8>>,
    streamed_file: Option<(&'a std::path::Path, u64)>,
    media_type: String,
    is_full_record: bool,
}

/// Re-encode or re-locate the exact bytes of one prepared blob.
///
/// A commit that finds a staged blob missing after a concurrent recovery uses
/// this to restore it from the command it is committing, without keeping a
/// second copy of every payload in memory.
fn rebuild_staged_blob<'a>(
    command: &'a crate::requests::CommitCommand,
    records: &[mneme_core::RecordEnvelope],
    digest: mneme_core::ContentDigest,
    boundary: mneme_core::ValueBoundary,
) -> Option<RebuiltBlob<'a>> {
    match boundary {
        mneme_core::ValueBoundary::FullRecord => records.iter().find_map(|record| {
            let value = record.to_value();
            (mneme_core::ContentDigest::of_full_record_with(&value, digest.algorithm()) == digest)
                .then(|| RebuiltBlob {
                    bytes: Some(mneme_core::binary::encode(&value)),
                    streamed_file: None,
                    media_type: String::new(),
                    is_full_record: true,
                })
        }),
        mneme_core::ValueBoundary::SourceBytes => rebuild_source_blob(command, records, digest),
        mneme_core::ValueBoundary::Payload => None,
    }
}

fn rebuild_source_blob<'a>(
    command: &'a crate::requests::CommitCommand,
    records: &[mneme_core::RecordEnvelope],
    digest: mneme_core::ContentDigest,
) -> Option<RebuiltBlob<'a>> {
    let algo = digest.algorithm();
    debug_assert!(!digest.as_bytes().is_empty());
    for blob in &command.source_blobs {
        if let Some(file) = &blob.file {
            if file.digest == digest {
                return Some(RebuiltBlob {
                    bytes: None,
                    streamed_file: Some((&file.path, file.size_bytes)),
                    media_type: blob.media_type.as_str().to_owned(),
                    is_full_record: false,
                });
            }
        } else if mneme_core::ContentDigest::of_source_bytes_with(&blob.bytes, algo) == digest {
            return Some(RebuiltBlob {
                bytes: Some(blob.bytes.clone()),
                streamed_file: None,
                media_type: blob.media_type.as_str().to_owned(),
                is_full_record: false,
            });
        }
    }
    if let Some(candidate) = command
        .import_candidates
        .iter()
        .find(|c| mneme_core::ContentDigest::of_source_bytes_with(&c.bytes, algo) == digest)
    {
        return Some(RebuiltBlob {
            bytes: Some(candidate.bytes.clone()),
            streamed_file: None,
            media_type: record_source_media_type(records, digest).unwrap_or_default(),
            is_full_record: false,
        });
    }
    let publication = command
        .publications
        .iter()
        .find(|p| mneme_core::ContentDigest::of_source_bytes_with(&p.bytes, algo) == digest)?;
    debug_assert!(!publication.path.is_empty());
    let media_type = record_source_media_type(records, digest).unwrap_or_else(|| {
        super::commit::infer_publication_media_type(&publication.path).to_owned()
    });
    Some(RebuiltBlob {
        bytes: Some(publication.bytes.clone()),
        streamed_file: None,
        media_type,
        is_full_record: false,
    })
}

fn record_source_media_type(
    records: &[mneme_core::RecordEnvelope],
    digest: mneme_core::ContentDigest,
) -> Option<String> {
    records.iter().find_map(|record| {
        let (record_digest, media_type) = super::validation::retained_source_media_type(record)?;
        (record_digest == digest).then(|| media_type.as_str().to_owned())
    })
}

/// Re-stage every blob of the prepared revision that is no longer on disk.
///
/// A concurrent recovery sweep removes blobs the ledger does not yet name, so a
/// commit restores its own staged payloads before it writes the rows that make
/// them required.
pub(super) fn restore_staged_blobs(
    root: &std::path::Path,
    command: &crate::requests::CommitCommand,
    records: &[mneme_core::RecordEnvelope],
    staged: &super::BlobIndex,
    policy: crate::payload::StoragePolicy,
) -> crate::error::Result<()> {
    debug_assert!(!root.as_os_str().is_empty());
    debug_assert!(records.len() <= command.records.len());
    for (digest, length, _, boundary) in staged.values() {
        if crate::payload::blob_is_present(root, *digest, *length)? {
            continue;
        }
        let Some(rebuilt) = rebuild_staged_blob(command, records, *digest, *boundary) else {
            return Err(crate::error::Failure::MissingBlob {
                digest: digest.to_hex(),
            });
        };
        if let Some((path, size_bytes)) = rebuilt.streamed_file {
            crate::payload::stage_file_with_policy(
                root,
                *digest,
                crate::payload::StreamedStageInput {
                    source: path,
                    expected_bytes: size_bytes,
                    policy,
                    media_type: &rebuilt.media_type,
                },
            )?;
        } else if let Some(bytes) = &rebuilt.bytes {
            if rebuilt.is_full_record {
                crate::payload::stage(root, *digest, bytes)?;
            } else {
                crate::payload::stage_with_policy(
                    root,
                    *digest,
                    bytes,
                    policy,
                    &rebuilt.media_type,
                )?;
            }
        }
    }
    Ok(())
}

/// Decode one persisted publication intent state.
///
/// Unknown text stays a failure: a row this build cannot name must not read as
/// pending, which would make recovery attempt an intent it cannot decide.
fn intent_state(text: &str) -> super::PublicationState {
    super::PublicationState::parse(text).unwrap_or(super::PublicationState::Failed)
}

/// Recompute one publication digest over the raw bytes a caller supplied.
fn stored_digest(
    connection: &rusqlite::Connection,
    bytes: &[u8],
    revision: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<mneme_core::ContentDigest> {
    let algorithm = super::blob_algorithm(connection, bytes)?;
    super::digest_with(
        bytes,
        algorithm.symbol(),
        "raw-bytes-v1",
        "source-bytes",
        revision,
    )
}

fn intent_digest(
    connection: &rusqlite::Connection,
    bytes: &[u8],
    recorded_algorithm: Option<&str>,
    revision: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<mneme_core::ContentDigest> {
    match recorded_algorithm {
        Some(algorithm) => {
            super::digest_with(bytes, algorithm, "raw-bytes-v1", "source-bytes", revision)
        }
        None => stored_digest(connection, bytes, revision),
    }
}
