//! Restore suppression ledgers and the source facts a snapshot verifies:
//! exporting and applying a ledger, its decoding, and the per-revision source
//! bindings a read or a purge consults.

impl super::Workspace {
    /// A digest over the current minimal suppression state.
    pub fn suppression_state_digest(&self) -> crate::error::Result<mneme_core::ContentDigest> {
        let generation = self.eligibility_generation()?;
        let suppressions = self.active_suppressions()?;
        Ok(mneme_core::ContentDigest::of_payload(
            &mneme_core::Value::record_named(
                "retention-state",
                vec![
                    mneme_core::Value::integer(super::db_i64(generation, "generation")?),
                    mneme_core::Value::set(
                        suppressions
                            .iter()
                            .map(crate::lifecycle::RetentionSuppression::to_value),
                    ),
                ],
            ),
        ))
    }

    /// Refuse to rebuild from a snapshot that contains forgotten identities or
    /// content whose replay is blocked.
    pub fn require_replay_eligible(&self, snapshot: &super::Snapshot) -> crate::error::Result<()> {
        self.require_restore_suppression()?;
        let forgotten = self.forgotten_suppressions()?;
        let mut blocked_content = std::collections::BTreeSet::new();
        for suppression in super::sweep::all_suppressions(&self.connection)? {
            if suppression.mode == crate::lifecycle::SuppressionMode::Forgotten
                && let Some(digest) = suppression.content_digest
            {
                blocked_content.insert(*digest.as_bytes());
            }
        }
        for record in &snapshot.records {
            if forgotten.matches(record.record_id, record.revision_id) {
                return Err(crate::error::Failure::RetentionSuppressed {
                    target: record.record_id.to_string(),
                });
            }
            if let Some(digest) = super::validation::retained_source_digest(record)
                && blocked_content.contains(digest.as_bytes())
            {
                return Err(crate::error::Failure::RetentionSuppressed {
                    target: "forgotten-content".to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Export the minimal current suppression ledger for a supported restore.
    ///
    /// The ledger carries this workspace's genesis revision (so it can never be
    /// applied to another workspace), the erasure generation, every suppression,
    /// and every pruning decision (a source record and the digest its bytes were
    /// pruned at), so a restored copy can finish the cleanup instead of serving
    /// pruned bytes again.
    pub fn export_suppression_ledger(&self) -> crate::error::Result<Vec<u8>> {
        self.require_restore_suppression()?;
        let generation = self.eligibility_generation()?;
        let genesis = self.genesis_revision()?;
        let suppressions = self.active_suppressions()?;
        let prunings = self.ledger_prunings()?;
        Ok(mneme_core::binary::encode(
            &mneme_core::Value::record_named(
                "retention-state",
                vec![
                    mneme_core::Value::integer(2),
                    mneme_core::Value::integer(super::db_i64(generation, "generation")?),
                    genesis.to_value(),
                    mneme_core::Value::set(
                        suppressions
                            .iter()
                            .map(crate::lifecycle::RetentionSuppression::to_value),
                    ),
                    mneme_core::Value::set(prunings.iter().map(pruning_to_value)),
                ],
            ),
        ))
    }

    /// Pruning decisions a restored copy must carry.
    ///
    /// A live source whose current revision is unavailable *because it was
    /// pruned* records the digest it was pruned at; exporting that pair lets the
    /// restored copy identify and suppress the pre-prune revision instead of
    /// serving its bytes.
    fn ledger_prunings(&self) -> crate::error::Result<Vec<RestoredPruning>> {
        let revision = self.current_revision()?;
        let bindings =
            current_source_bindings(&self.connection, &self.root, revision, self.facts())?;
        Ok(bindings.prunings)
    }

    /// Apply a current suppression ledger to a restored workspace before any
    /// restored content can be read or published.
    ///
    /// Only a ledger naming this workspace's genesis revision with a generation
    /// at or above the restored copy's is applied. Forgotten identities, their
    /// record blobs, their source bytes and their working copies are tracked as
    /// cleanup locations of a restore operation and purged here; a pruning
    /// decision suppresses the pre-prune revision so its bytes are not served
    /// again.
    pub fn apply_restore_suppression_ledger(&mut self, bytes: &[u8]) -> crate::error::Result<()> {
        let (ledger, next, operation_id) = self.require_applicable_ledger(bytes)?;
        let revision = self.current_revision()?;
        let sequence = self.current_sequence()?;
        let now_ns = self.clock.now().nanos();
        let _sweep = self.exclusive_sweep_lock()?;
        // The requirement read runs under the ledger transaction, so the fact
        // access is built from the fields the transaction does not borrow.
        let facts = super::facts_from(&self.shared, &self.records);
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let application = RestoreApplication {
            operation_id: &operation_id,
            revision,
            sequence,
            generation: next,
            now_ns,
        };
        let job_state =
            purge_restored_ledger(&transaction, &self.root, facts, &ledger, &application)?;
        transaction.execute(
            "UPDATE retention_operations SET state = ?1, updated_at_ns = ?2
             WHERE operation_id = ?3",
            rusqlite::params![job_state.as_str(), now_ns, operation_id],
        )?;
        super::set_meta_u64(&transaction, super::META_GENERATION, next)?;
        transaction.execute(
            "UPDATE publication_intents
             SET state = 'suppressed', detail = 'restored retention barrier',
                 updated_at_ns = ?1
             WHERE state = 'pending'",
            rusqlite::params![now_ns],
        )?;
        transaction.execute(
            "DELETE FROM meta WHERE key = ?1",
            rusqlite::params![super::META_RESTORE_PENDING],
        )?;
        transaction.commit()?;
        self.is_restore_required = false;
        // The applied ledger advances the generation and purges restored
        // payloads, so anything this handle decoded before is unauthorized now.
        self.facts().align(next);
        Ok(())
    }

    /// Parse an offered ledger and require this workspace to accept it.
    ///
    /// Returns the ledger, the generation it advances to and the operation
    /// identity its derived cleanup locations belong to.
    fn require_applicable_ledger(
        &self,
        bytes: &[u8],
    ) -> crate::error::Result<(RestoredLedger, u64, String)> {
        if !self.is_restore_required {
            return Err(crate::error::Failure::InvalidCommand(
                "this workspace is not awaiting a restore suppression ledger".to_owned(),
            ));
        }
        let ledger = parse_restore_suppression_ledger(bytes)?;
        let Some(ledger_genesis) = ledger.genesis else {
            return Err(crate::error::Failure::InvalidCommand(
                "suppression ledger does not name its workspace".to_owned(),
            ));
        };
        let genesis = self.genesis_revision()?;
        let restored_generation = self.eligibility_generation()?;
        let decision = mneme_kernel::restore::decide_ledger(&mneme_kernel::restore::LedgerFacts {
            same_workspace: ledger_genesis == genesis,
            ledger_generation: ledger.generation,
            restored_generation,
        });
        match decision {
            mneme_kernel::restore::LedgerDecision::Apply => {}
            mneme_kernel::restore::LedgerDecision::ForeignWorkspace => {
                return Err(crate::error::Failure::InvalidCommand(
                    "suppression ledger belongs to another workspace".to_owned(),
                ));
            }
            mneme_kernel::restore::LedgerDecision::Stale => {
                return Err(crate::error::Failure::InvalidCommand(
                    "suppression ledger is older than the restored workspace".to_owned(),
                ));
            }
        }
        let next = ledger.generation.max(restored_generation.saturating_add(1));
        let operation_id = format!("restore-{}-{}", genesis.to_hex(), ledger.generation);
        Ok((ledger, next, operation_id))
    }

    pub(super) fn forgotten_suppressions(
        &self,
    ) -> crate::error::Result<super::sweep::ForgottenSuppressions> {
        super::sweep::forgotten_suppressions_in(&self.connection)
    }

    pub(super) fn require_restore_suppression(&self) -> crate::error::Result<()> {
        let marker = if self.is_restore_required {
            mneme_kernel::restore::Marker::Pending
        } else {
            mneme_kernel::restore::Marker::Clear
        };
        if !mneme_kernel::restore::may_serve(marker) {
            return Err(crate::error::Failure::MissingRetentionState {
                reason: "restored workspace has not applied the current suppression ledger"
                    .to_owned(),
            });
        }
        Ok(())
    }

    /// The current source states of the ledger one snapshot load is reading.
    ///
    /// The load passes its own read transaction, so the states it uses to decide
    /// which retained sources are still required describe the same ledger state as
    /// the record set it just loaded.
    pub(super) fn source_states_in(
        &self,
        connection: &rusqlite::Connection,
    ) -> crate::error::Result<std::collections::BTreeMap<mneme_core::RecordId, super::SourcePresence>>
    {
        let current = super::meta_blob(connection, super::META_CURRENT_REVISION)?;
        let revision = super::revision_from_blob(&current)?;
        let bindings = current_source_bindings(connection, &self.root, revision, self.facts())?;
        Ok(bindings.states)
    }
}

/// Record the offered suppressions, purge every derived location and report the
/// operation's summary state.
///
/// A location is purged only after the requirement set was read from the ledger
/// that now holds the restored suppressions, so a forgotten or suppressed record
/// never keeps its bytes. The connection fields are passed separately because
/// the caller holds the ledger transaction.
fn purge_restored_ledger(
    transaction: &rusqlite::Transaction<'_>,
    root: &std::path::Path,
    facts: super::FactAccess<'_>,
    ledger: &RestoredLedger,
    application: &RestoreApplication<'_>,
) -> crate::error::Result<crate::lifecycle::RetentionJobState> {
    for suppression in &ledger.suppressions {
        insert_ledger_suppression(transaction, suppression)?;
    }
    let locations = collect_restore_locations(transaction, root, ledger, application.generation)?;
    insert_restore_operation(transaction, application)?;
    for (location_id, location) in &locations {
        insert_restore_location(
            transaction,
            application.operation_id,
            location_id,
            location,
            application.now_ns,
        )?;
    }
    let requirements = super::sweep::retention_requirements(
        transaction,
        root,
        application.revision,
        application.generation,
        facts,
    )?;
    let mut states = Vec::with_capacity(locations.len());
    // The source bytes and the working copy are derived from the record
    // envelope, so they are removed before it: an interrupted run can then
    // always recompute every remaining location from the ledger.
    let mut ordered = locations.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|(_, location)| restore_location_rank(location));
    for (location_id, location) in ordered {
        let (state, detail) = restore_location_state(root, &requirements, location)?;
        states.push(state);
        super::sweep::update_retention_location_in(
            transaction,
            application.now_ns,
            application.operation_id,
            location_id,
            super::sweep::RetentionLocationUpdate {
                state,
                detail_code: detail,
                verified: state.is_terminal(),
                increment_attempts: true,
            },
        )?;
    }
    let kernel_states = states
        .iter()
        .map(|state| state.to_kernel())
        .collect::<Vec<_>>();
    Ok(super::sweep::cleanup_job_state(
        mneme_kernel::cleanup::summarize(&kernel_states),
    ))
}

/// Source state and working-path bindings of one revision's live sources.
pub(super) struct SourceBindings {
    pub(super) states: std::collections::BTreeMap<mneme_core::RecordId, super::SourcePresence>,
    pub(super) paths: std::collections::BTreeMap<String, std::collections::BTreeSet<[u8; 32]>>,
    pub(super) prunings: Vec<RestoredPruning>,
}

/// What one source envelope records about its content and working path.
struct SourceEnvelopeFacts {
    presence: super::SourcePresence,
    path: Option<String>,
    content: Option<mneme_core::ContentDigest>,
    /// The source records an explicit pruning decision for its prior bytes.
    is_pruned: bool,
}

impl SourceEnvelopeFacts {
    /// The facts for an envelope this read could not decode.
    fn unknown() -> Self {
        SourceEnvelopeFacts {
            presence: super::SourcePresence::Unknown,
            path: None,
            content: None,
            is_pruned: false,
        }
    }
}

/// Read one source envelope's content state, working path and retained digest.
///
/// The envelope itself is a record payload, so it is served from the handle's
/// verified facts after the first read; the source bytes it names are only ever
/// held as a verified identity and are still read and hashed wherever a caller
/// receives them.
fn source_envelope_facts(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
    facts: super::FactAccess<'_>,
) -> SourceEnvelopeFacts {
    if let Some((record, _)) = facts.recorded_envelope(root, digest) {
        return source_facts(&record);
    }
    let identity_before = super::blob_file_identity(root, digest);
    let Some((record, encoded_bytes)) = read_record_envelope(root, digest) else {
        return SourceEnvelopeFacts::unknown();
    };
    let payload_digest = record.payload_digest();
    if let Some(file) = super::stable_blob_identity(root, digest, identity_before, encoded_bytes) {
        facts.store_envelope(digest, record.clone(), payload_digest, encoded_bytes, file);
    }
    source_facts(&record)
}

/// Read one source envelope's facts without consulting any decode cache.
///
/// A restore reads each affected envelope once while it builds the cleanup plan,
/// so there is nothing to reuse.
fn source_envelope_facts_uncached(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
) -> SourceEnvelopeFacts {
    match read_record_envelope(root, digest) {
        Some((record, _)) => source_facts(&record),
        None => SourceEnvelopeFacts::unknown(),
    }
}

/// Decode one record envelope from its blob and require its committed digest.
fn read_record_envelope(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
) -> Option<(mneme_core::RecordEnvelope, usize)> {
    let bytes = crate::payload::read(root, digest).ok()?;
    let value = mneme_core::binary::decode(&bytes).ok()?;
    let record = mneme_core::RecordEnvelope::from_value(&value).ok()?;
    if record.full_digest() != digest {
        return None;
    }
    Some((record, bytes.len()))
}

/// The availability facts one decoded source envelope records.
fn source_facts(record: &mneme_core::RecordEnvelope) -> SourceEnvelopeFacts {
    let content = record.payload.get("content").and_then(|value| {
        mneme_core::SourceContent::from_value(value, &mneme_core::Path::root().field("content"))
            .ok()
    });
    let prior = record.payload.get("content-digest").and_then(|value| {
        mneme_core::ContentDigest::from_value(
            value,
            &mneme_core::Path::root().field("content-digest"),
        )
        .ok()
    });
    let (presence, content) = match content {
        Some(mneme_core::SourceContent::Retained(retained)) => (
            super::SourcePresence::Retained(retained.digest()),
            Some(retained.digest()),
        ),
        Some(mneme_core::SourceContent::Unavailable { .. }) => {
            (super::SourcePresence::Unavailable(prior), None)
        }
        None => (super::SourcePresence::Unknown, None),
    };
    let is_pruned = record
        .payload
        .get("availability")
        .and_then(mneme_core::Value::as_symbol)
        .is_some_and(|availability| availability.as_str() == "pruned");
    let path = record
        .payload
        .get("path-hint")
        .and_then(mneme_core::Value::as_string)
        .map(str::to_owned);
    SourceEnvelopeFacts {
        presence,
        path,
        content,
        is_pruned,
    }
}

/// The live source states and working-path bindings of one revision.
pub(super) fn current_source_bindings(
    connection: &rusqlite::Connection,
    root: &std::path::Path,
    revision: mneme_core::WorkspaceRevisionId,
    facts: super::FactAccess<'_>,
) -> crate::error::Result<SourceBindings> {
    let row = super::revision_row_by_id(connection, revision)?.ok_or_else(|| {
        crate::error::Failure::Integrity {
            revision,
            reason: "revision is not present in the ledger".to_owned(),
        }
    })?;
    let forgotten = super::sweep::forgotten_suppressions_in(connection)?;
    let rows = super::membership_entries(connection, row.sequence, Some("source-revision"))?;
    let mut states = std::collections::BTreeMap::new();
    let mut paths: std::collections::BTreeMap<String, std::collections::BTreeSet<[u8; 32]>> =
        std::collections::BTreeMap::new();
    let mut prunings = Vec::with_capacity(rows.len());
    let max_source_states = rows.len();
    for entry in &rows {
        let (record_id, revision_id, _) = super::membership_record(entry, revision)?;
        let envelope_digest = &entry.3;
        if forgotten.matches(record_id, revision_id) {
            continue;
        }
        let digest = super::digest_with(
            envelope_digest,
            "preserves-canonical-binary-v1",
            "full-record",
            revision,
        )?;
        let envelope = source_envelope_facts(root, digest, facts);
        if let (Some(path), Some(content)) = (&envelope.path, envelope.content) {
            paths
                .entry(path.clone())
                .or_default()
                .insert(*content.as_bytes());
        }
        if envelope.is_pruned
            && let super::SourcePresence::Unavailable(Some(prior)) = envelope.presence
        {
            prunings.push(RestoredPruning {
                source: record_id,
                digest: prior,
            });
        }
        if states.len() >= max_source_states {
            return Err(crate::error::Failure::UnsupportedLayout(
                "source state index exceeds its input row bound".to_owned(),
            ));
        }
        states.insert(record_id, envelope.presence);
    }
    Ok(SourceBindings {
        states,
        paths,
        prunings,
    })
}

/// A ledger offered to a restored copy.
struct RestoredLedger {
    generation: u64,
    /// The genesis revision of the exporting workspace, absent in a version 1
    /// ledger, which therefore can never be applied.
    genesis: Option<mneme_core::WorkspaceRevisionId>,
    suppressions: Vec<crate::lifecycle::RetentionSuppression>,
    pub(super) prunings: Vec<RestoredPruning>,
}

/// One pruning decision carried by a suppression ledger.
#[derive(Clone, Copy)]
pub(super) struct RestoredPruning {
    source: mneme_core::RecordId,
    digest: mneme_core::ContentDigest,
}

fn pruning_to_value(pruning: &RestoredPruning) -> mneme_core::Value {
    mneme_core::Value::record_named(
        "retention-pruning",
        vec![pruning.source.to_value(), pruning.digest.to_value()],
    )
}

fn pruning_from_value(value: &mneme_core::Value) -> crate::error::Result<RestoredPruning> {
    let record = value.as_record().ok_or_else(|| {
        crate::error::Failure::InvalidCommand("retention pruning is not a record".to_owned())
    })?;
    if record.label() != &mneme_core::Value::symbol("retention-pruning")
        || record.fields().len() != 2
    {
        return Err(crate::error::Failure::InvalidCommand(
            "retention pruning has an unsupported envelope".to_owned(),
        ));
    }
    let path = mneme_core::Path::root();
    let source = mneme_core::RecordId::from_value(&record.fields()[0], &path.index(0)).map_err(
        |diagnostic| {
            crate::error::Failure::InvalidCommand(format!("retention pruning source: {diagnostic}"))
        },
    )?;
    let digest = mneme_core::ContentDigest::from_value(&record.fields()[1], &path.index(1))
        .map_err(|diagnostic| {
            crate::error::Failure::InvalidCommand(format!("retention pruning digest: {diagnostic}"))
        })?;
    Ok(RestoredPruning { source, digest })
}

fn parse_restore_suppression_ledger(bytes: &[u8]) -> crate::error::Result<RestoredLedger> {
    let value = mneme_core::binary::decode(bytes).map_err(|diagnostic| {
        crate::error::Failure::InvalidCommand(format!(
            "retention ledger is not canonical Preserves: {diagnostic}"
        ))
    })?;
    let record = value.as_record().ok_or_else(|| {
        crate::error::Failure::InvalidCommand("retention ledger is not a record".to_owned())
    })?;
    let field_count = require_ledger_envelope(record)?;
    let version = record.fields()[0]
        .as_integer()
        .and_then(|integer| integer.to_i64())
        .ok_or_else(|| {
            crate::error::Failure::InvalidCommand(
                "retention ledger version is not an integer".to_owned(),
            )
        })?;
    let (suppression_index, pruning_index) = ledger_indexes(version, field_count)?;
    let generation = record.fields()[1]
        .as_integer()
        .and_then(|integer| integer.to_i64())
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| {
            crate::error::Failure::InvalidCommand(
                "retention ledger generation is not a u64".to_owned(),
            )
        })?;
    Ok(RestoredLedger {
        generation,
        genesis: ledger_genesis(record, version)?,
        suppressions: parse_ledger_suppressions(record, suppression_index)?,
        prunings: parse_ledger_prunings(record, pruning_index)?,
    })
}

/// Require a retention ledger envelope's label and minimum field count, and
/// report the field count the version dispatch needs.
fn require_ledger_envelope(record: &mneme_core::Record) -> crate::error::Result<usize> {
    if record.label() != &mneme_core::Value::symbol("retention-state") {
        return Err(crate::error::Failure::InvalidCommand(
            "retention ledger has an unsupported envelope".to_owned(),
        ));
    }
    // The envelope is indexed below, so its minimum length is checked first.
    let field_count = record.fields().len();
    if field_count < 3 {
        return Err(crate::error::Failure::InvalidCommand(
            "retention ledger has an unsupported envelope".to_owned(),
        ));
    }
    Ok(field_count)
}

/// The field indexes one retention ledger version stores its sets at.
fn ledger_indexes(
    version: i64,
    field_count: usize,
) -> crate::error::Result<(usize, Option<usize>)> {
    match (version, field_count) {
        (1, 3) => Ok((2_usize, None)),
        (2, 5) => Ok((3_usize, Some(4_usize))),
        _ => Err(crate::error::Failure::UnsupportedLayout(format!(
            "retention ledger version {version} with {field_count} fields is not supported"
        ))),
    }
}

/// The genesis revision a version 2 ledger names.
///
/// A version 1 ledger has none, which is why it can never be applied.
fn ledger_genesis(
    record: &mneme_core::Record,
    version: i64,
) -> crate::error::Result<Option<mneme_core::WorkspaceRevisionId>> {
    if version < 2 {
        return Ok(None);
    }
    mneme_core::WorkspaceRevisionId::from_value(
        &record.fields()[2],
        &mneme_core::Path::root().index(2),
    )
    .map(Some)
    .map_err(|diagnostic| {
        crate::error::Failure::InvalidCommand(format!(
            "retention ledger genesis revision: {diagnostic}"
        ))
    })
}

/// Decode the suppressions one retention ledger carries.
fn parse_ledger_suppressions(
    record: &mneme_core::Record,
    index: usize,
) -> crate::error::Result<Vec<crate::lifecycle::RetentionSuppression>> {
    let suppressions = record.fields()[index].as_set().ok_or_else(|| {
        crate::error::Failure::InvalidCommand(
            "retention ledger suppressions are not a set".to_owned(),
        )
    })?;
    let mut parsed = Vec::with_capacity(suppressions.len());
    for suppression in suppressions {
        parsed.push(suppression_from_value(suppression)?);
    }
    Ok(parsed)
}

/// Decode the pruning decisions a version 2 retention ledger carries.
fn parse_ledger_prunings(
    record: &mneme_core::Record,
    index: Option<usize>,
) -> crate::error::Result<Vec<RestoredPruning>> {
    let Some(index) = index else {
        return Ok(Vec::new());
    };
    let entries = record.fields()[index].as_set().ok_or_else(|| {
        crate::error::Failure::InvalidCommand("retention ledger prunings are not a set".to_owned())
    })?;
    let mut prunings = Vec::with_capacity(entries.len());
    for entry in entries {
        prunings.push(pruning_from_value(entry)?);
    }
    Ok(prunings)
}

/// The synthetic operation identity that owns restore-derived suppressions and
/// cleanup locations.
const RESTORE_LEDGER_OPERATION: &str = "restore-ledger";

/// The revision, operation identity, generation and clock one restore
/// application records its cleanup under.
struct RestoreApplication<'a> {
    operation_id: &'a str,
    revision: mneme_core::WorkspaceRevisionId,
    sequence: u64,
    /// The generation the applied ledger advances the workspace to.
    generation: u64,
    now_ns: i64,
}

/// Remove one planned restored location, reporting its cleanup state.
///
/// A working copy or source blob that a live record still requires is retained
/// instead of removed, so the restored copy never destroys bytes it must serve.
fn restore_location_state(
    root: &std::path::Path,
    requirements: &super::RetentionRequirements,
    location: &RestoreLocation,
) -> crate::error::Result<(
    crate::lifecycle::RetentionLocationState,
    Option<&'static str>,
)> {
    match location {
        RestoreLocation::Blob { digest, .. } => purge_restored_blob(root, requirements, *digest),
        RestoreLocation::WorkingFile { relative, digest } => {
            let is_required = requirements.pending_paths.contains(relative)
                || requirements
                    .paths
                    .get(relative)
                    .is_some_and(|digests| digests.contains(digest.as_bytes()));
            if is_required {
                Ok((
                    crate::lifecycle::RetentionLocationState::RetainedShared,
                    Some("shared-path-binding"),
                ))
            } else {
                super::sweep::purge_working_copy(root, relative, *digest)
            }
        }
    }
}

/// One managed location a restored copy must clean up.
enum RestoreLocation {
    Blob {
        location_kind: &'static str,
        digest: mneme_core::ContentDigest,
    },
    WorkingFile {
        relative: String,
        digest: mneme_core::ContentDigest,
    },
}

/// Removal order for restored locations.
///
/// A working copy and a source blob are derived from a record envelope, so they
/// go before the envelope itself; an interrupted run can then recompute every
/// remaining location from what is still in the ledger.
fn restore_location_rank(location: &RestoreLocation) -> u8 {
    match location {
        RestoreLocation::WorkingFile { .. } => 0,
        RestoreLocation::Blob { location_kind, .. } => match *location_kind {
            "source-blob" => 1,
            _ => 2,
        },
    }
}

/// Insert one suppression carried by an offered ledger.
fn insert_ledger_suppression(
    transaction: &rusqlite::Transaction<'_>,
    suppression: &crate::lifecycle::RetentionSuppression,
) -> crate::error::Result<()> {
    transaction.execute(
        "INSERT OR IGNORE INTO retention_suppressions (operation_id, target_id,
             target_revision, target_kind, mode, content_digest, generation)
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
    Ok(())
}

/// The revisions of one record with their kind and envelope digest.
fn record_digest_rows(
    connection: &rusqlite::Connection,
    record_id: mneme_core::RecordId,
) -> crate::error::Result<Vec<(mneme_core::RevisionId, String, mneme_core::ContentDigest)>> {
    let context = mneme_core::WorkspaceRevisionId::from_bytes([0; 16]);
    let mut statement = connection
        .prepare("SELECT revision_id, kind, full_digest FROM records WHERE record_id = ?1")?;
    let rows = statement
        .query_map(rusqlite::params![record_id.as_bytes().as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut output = Vec::with_capacity(rows.len());
    for (revision, kind, full) in rows {
        let revision = super::revision_id_from_blob(&revision, context)?;
        let digest = super::digest_with(
            &full,
            "preserves-canonical-binary-v1",
            "full-record",
            context,
        )?;
        output.push((revision, kind, digest));
    }
    Ok(output)
}

fn insert_restore_blob(
    locations: &mut std::collections::BTreeMap<String, RestoreLocation>,
    location_kind: &'static str,
    digest: mneme_core::ContentDigest,
) {
    locations.insert(
        format!("{location_kind}:{}", digest.to_hex()),
        RestoreLocation::Blob {
            location_kind,
            digest,
        },
    );
}

fn insert_restore_working_file(
    locations: &mut std::collections::BTreeMap<String, RestoreLocation>,
    relative: &str,
    digest: mneme_core::ContentDigest,
) {
    locations.insert(
        format!("working-file:{relative}"),
        RestoreLocation::WorkingFile {
            relative: relative.to_owned(),
            digest,
        },
    );
}

/// Collect every payload location a restored copy must purge for one ledger.
fn collect_restore_locations(
    transaction: &rusqlite::Transaction<'_>,
    root: &std::path::Path,
    ledger: &RestoredLedger,
    generation: u64,
) -> crate::error::Result<std::collections::BTreeMap<String, RestoreLocation>> {
    let mut locations = std::collections::BTreeMap::new();
    for suppression in &ledger.suppressions {
        if let Some(digest) = suppression.content_digest {
            insert_restore_blob(&mut locations, "source-blob", digest);
        }
        if suppression.mode != crate::lifecycle::SuppressionMode::Forgotten {
            continue;
        }
        for (revision, kind, full) in record_digest_rows(transaction, suppression.target)? {
            if suppression
                .revision
                .is_some_and(|wanted| wanted != revision)
            {
                continue;
            }
            insert_restore_blob(&mut locations, "record-blob", full);
            if kind != mneme_core::RecordKind::SourceRevision.symbol() {
                continue;
            }
            let facts = source_envelope_facts_uncached(root, full);
            if let Some(content) = facts.content {
                insert_restore_blob(&mut locations, "source-blob", content);
            }
            if let (Some(path), Some(content)) = (facts.path, facts.content) {
                insert_restore_working_file(&mut locations, &path, content);
            }
        }
    }
    for pruning in &ledger.prunings {
        for (revision, kind, full) in record_digest_rows(transaction, pruning.source)? {
            if kind != mneme_core::RecordKind::SourceRevision.symbol() {
                continue;
            }
            let facts = source_envelope_facts_uncached(root, full);
            if facts.content != Some(pruning.digest) {
                continue;
            }
            // The restored copy still holds the pre-prune revision. It is
            // suppressed so its bytes are never served, and its payloads are
            // tracked for removal below.
            transaction.execute(
                "INSERT OR IGNORE INTO retention_suppressions (operation_id, target_id,
                     target_revision, target_kind, mode, content_digest, generation)
                 VALUES (?1, ?2, ?3, ?4, 'forgotten', NULL, ?5)",
                rusqlite::params![
                    RESTORE_LEDGER_OPERATION,
                    pruning.source.as_bytes().as_slice(),
                    revision.as_bytes().as_slice(),
                    kind,
                    super::db_i64(generation, "generation")?,
                ],
            )?;
            insert_restore_blob(&mut locations, "record-blob", full);
            insert_restore_blob(&mut locations, "source-blob", pruning.digest);
            if let Some(path) = facts.path {
                insert_restore_working_file(&mut locations, &path, pruning.digest);
            }
        }
    }
    Ok(locations)
}

/// Record the restore operation that owns the derived cleanup locations.
fn insert_restore_operation(
    transaction: &rusqlite::Transaction<'_>,
    application: &RestoreApplication<'_>,
) -> crate::error::Result<()> {
    let scope = mneme_core::ScopeId::new(mneme_core::ScopeClass::Workspace, "genesis")
        .map_err(|message| crate::error::Failure::InvalidCommand(message.to_owned()))?;
    let retained_metadata = crate::lifecycle::MANAGED_WORKING_PATH_DECLARATION.to_owned();
    transaction.execute(
        "INSERT INTO retention_operations (operation_id, operation_kind, actor, scope,
             policy_version, idempotency_key, request_digest, state, generation,
             outcome_revision, outcome_sequence, retained_metadata, created_at_ns,
             updated_at_ns)
         VALUES (?1, 'restore', 'restore', ?2, 'restore-v1', ?1, ?3, 'cleanup-pending',
             ?4, ?5, ?6, ?7, ?8, ?8)
         ON CONFLICT(operation_id) DO UPDATE SET state = 'cleanup-pending',
             generation = excluded.generation,
             outcome_revision = excluded.outcome_revision,
             outcome_sequence = excluded.outcome_sequence,
             retained_metadata = excluded.retained_metadata,
             updated_at_ns = excluded.updated_at_ns",
        rusqlite::params![
            application.operation_id,
            scope.to_string(),
            [0_u8; 32].as_slice(),
            super::db_i64(application.generation, "generation")?,
            application.revision.as_bytes().as_slice(),
            super::db_i64(application.sequence, "sequence")?,
            retained_metadata,
            application.now_ns,
        ],
    )?;
    Ok(())
}

/// Record one pending cleanup location of a restore operation.
fn insert_restore_location(
    transaction: &rusqlite::Transaction<'_>,
    operation_id: &str,
    location_id: &str,
    location: &RestoreLocation,
    now_ns: i64,
) -> crate::error::Result<()> {
    let (location_kind, locator) = match location {
        RestoreLocation::Blob {
            location_kind,
            digest,
        } => (*location_kind, digest.to_hex()),
        RestoreLocation::WorkingFile { relative, digest } => {
            ("working-file", format!("{relative}#{}", digest.to_hex()))
        }
    };
    transaction.execute(
        "INSERT INTO retention_locations (operation_id, location_id, location_kind, locator,
             state, attempts, verified, detail_code, updated_at_ns)
         VALUES (?1, ?2, ?3, ?4, 'pending', 0, 0, NULL, ?5)
         ON CONFLICT(operation_id, location_id) DO UPDATE SET
             location_kind = excluded.location_kind,
             locator = excluded.locator,
             state = 'pending',
             attempts = 0,
             verified = 0,
             detail_code = NULL,
             updated_at_ns = excluded.updated_at_ns",
        rusqlite::params![operation_id, location_id, location_kind, locator, now_ns],
    )?;
    Ok(())
}

/// Purge one restored blob, keeping bytes a live retained record still needs.
fn purge_restored_blob(
    root: &std::path::Path,
    requirements: &super::RetentionRequirements,
    digest: mneme_core::ContentDigest,
) -> crate::error::Result<(
    crate::lifecycle::RetentionLocationState,
    Option<&'static str>,
)> {
    let path = crate::payload::blob_path(root, digest);
    let is_present = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata.is_file(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(crate::error::Failure::io(&path, error)),
    };
    let decision = mneme_kernel::purge::decide_blob(&mneme_kernel::purge::BlobFacts {
        required: requirements.digests.contains(digest.as_bytes()),
        present: is_present,
    });
    match decision {
        mneme_kernel::purge::BlobDecision::RetainShared => Ok((
            crate::lifecycle::RetentionLocationState::RetainedShared,
            Some("shared-live-reference"),
        )),
        mneme_kernel::purge::BlobDecision::AlreadyAbsent => {
            Ok((crate::lifecycle::RetentionLocationState::Absent, None))
        }
        mneme_kernel::purge::BlobDecision::Purge => match std::fs::remove_file(&path) {
            Ok(()) => {
                if let Some(parent) = path.parent() {
                    super::sync_directory(parent)?;
                }
                Ok((crate::lifecycle::RetentionLocationState::Purged, None))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok((crate::lifecycle::RetentionLocationState::Absent, None))
            }
            Err(error) => Err(crate::error::Failure::io(&path, error)),
        },
    }
}

fn suppression_from_value(
    value: &mneme_core::Value,
) -> crate::error::Result<crate::lifecycle::RetentionSuppression> {
    let record = value.as_record().ok_or_else(|| {
        crate::error::Failure::InvalidCommand("retention suppression is not a record".to_owned())
    })?;
    if record.label() != &mneme_core::Value::symbol("retention-suppression")
        || record.fields().len() != 7
    {
        return Err(crate::error::Failure::InvalidCommand(
            "retention suppression has an unsupported envelope".to_owned(),
        ));
    }
    let operation_id = suppression_operation_id(&record.fields()[0])?;
    let (target, revision) = suppression_target_revision(record.fields())?;
    let (target_kind, mode, content_digest, generation) =
        suppression_policy_fields(record.fields())?;
    Ok(crate::lifecycle::RetentionSuppression {
        operation_id,
        target,
        revision,
        target_kind,
        mode,
        content_digest,
        generation,
    })
}

fn suppression_operation_id(value: &mneme_core::Value) -> crate::error::Result<String> {
    let operation_id = value
        .as_string()
        .ok_or_else(|| {
            crate::error::Failure::InvalidCommand(
                "retention suppression operation is not text".to_owned(),
            )
        })?
        .to_owned();
    if operation_id.trim().is_empty() {
        return Err(crate::error::Failure::InvalidCommand(
            "retention suppression operation is empty".to_owned(),
        ));
    }
    Ok(operation_id)
}

fn suppression_target_revision(
    fields: &[mneme_core::Value],
) -> crate::error::Result<(mneme_core::RecordId, Option<mneme_core::RevisionId>)> {
    let path = mneme_core::Path::root();
    let target =
        mneme_core::RecordId::from_value(&fields[1], &path.index(1)).map_err(|diagnostic| {
            crate::error::Failure::InvalidCommand(format!(
                "retention suppression target: {diagnostic}"
            ))
        })?;
    let revision = match (fields[2].as_symbol(), &fields[2]) {
        (Some(symbol), _) if symbol.as_str() == "none" => None,
        _ => Some(
            mneme_core::RevisionId::from_value(&fields[2], &path.index(2)).map_err(
                |diagnostic| {
                    crate::error::Failure::InvalidCommand(format!(
                        "retention suppression revision: {diagnostic}"
                    ))
                },
            )?,
        ),
    };
    Ok((target, revision))
}

fn suppression_policy_fields(
    fields: &[mneme_core::Value],
) -> crate::error::Result<(
    String,
    crate::lifecycle::SuppressionMode,
    Option<mneme_core::ContentDigest>,
    u64,
)> {
    let path = mneme_core::Path::root();
    let target_kind = fields[3]
        .as_symbol()
        .ok_or_else(|| {
            crate::error::Failure::InvalidCommand(
                "retention suppression kind is not a symbol".to_owned(),
            )
        })?
        .as_str()
        .to_owned();
    mneme_core::RecordKind::parse(&target_kind).ok_or_else(|| {
        crate::error::Failure::InvalidCommand("retention suppression kind is unknown".to_owned())
    })?;
    let mode = fields[4]
        .as_symbol()
        .and_then(|symbol| crate::lifecycle::SuppressionMode::parse(symbol.as_str()))
        .ok_or_else(|| {
            crate::error::Failure::InvalidCommand(
                "retention suppression mode is unknown".to_owned(),
            )
        })?;
    let content_digest = match fields[5].as_symbol() {
        Some(symbol) if symbol.as_str() == "none" => None,
        _ => Some(
            mneme_core::ContentDigest::from_value(&fields[5], &path.index(5)).map_err(
                |diagnostic| {
                    crate::error::Failure::InvalidCommand(format!(
                        "retention suppression digest: {diagnostic}"
                    ))
                },
            )?,
        ),
    };
    let generation = fields[6]
        .as_integer()
        .and_then(|integer| integer.to_i64())
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| {
            crate::error::Failure::InvalidCommand(
                "retention suppression generation is not a u64".to_owned(),
            )
        })?;
    Ok((target_kind, mode, content_digest, generation))
}

pub(super) fn scope_from_text(text: &str) -> crate::error::Result<mneme_core::ScopeId> {
    let (class, local) = text.split_once(':').ok_or_else(|| {
        crate::error::Failure::UnsupportedLayout(format!(
            "retention scope {text:?} is not class:local"
        ))
    })?;
    let class = mneme_core::ScopeClass::parse(class).ok_or_else(|| {
        crate::error::Failure::UnsupportedLayout(format!(
            "retention scope class {class:?} is unknown"
        ))
    })?;
    mneme_core::ScopeId::new(class, local.to_owned())
        .map_err(|message| crate::error::Failure::UnsupportedLayout(message.to_owned()))
}

pub(super) fn digest_from_locator(
    kind: &str,
    locator: &str,
) -> crate::error::Result<mneme_core::ContentDigest> {
    let bytes = decode_hex(locator)?;
    let (profile, boundary) = match kind {
        "source-blob" => ("raw-bytes-v1", "source-bytes"),
        "record-blob" => ("preserves-canonical-binary-v1", "full-record"),
        other => {
            return Err(crate::error::Failure::InvalidCommand(format!(
                "location kind {other} is not a content-addressed blob"
            )));
        }
    };
    super::digest_with(
        &bytes,
        profile,
        boundary,
        mneme_core::WorkspaceRevisionId::from_bytes([0; 16]),
    )
}

pub(super) fn decode_hex(text: &str) -> crate::error::Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err(crate::error::Failure::InvalidCommand(
            "blob locator has an odd number of hex characters".to_owned(),
        ));
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok(high << 4 | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> crate::error::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(crate::error::Failure::InvalidCommand(
            "blob locator is not hexadecimal".to_owned(),
        )),
    }
}
