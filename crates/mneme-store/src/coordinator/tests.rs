//! Unit tests for the coordinator's private snapshot, cache and membership
//! helpers.

fn scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
}

fn config() -> super::WorkspaceConfig {
    super::WorkspaceConfig {
        clock: Box::new(crate::timekeeper::FixedClock::new(
            mneme_core::Timestamp::from_nanos(1_000),
        )),
        faults: Box::new(crate::injectors::NoFaults),
    }
}

fn draft(envelope: &mneme_core::RecordEnvelope) -> crate::requests::RecordDraft {
    crate::requests::RecordDraft {
        schema_version: envelope.schema_version,
        kind: envelope.kind,
        record_id: envelope.record_id,
        revision_id: envelope.revision_id,
        predecessor: envelope.predecessor,
        scope: envelope.scope.clone(),
        payload: envelope.payload.clone(),
    }
}

fn fixture_command(
    base: mneme_core::WorkspaceRevisionId,
    key: &str,
) -> crate::requests::CommitCommand {
    crate::requests::CommitCommand {
        base,
        actor: "test-author".to_owned(),
        scope: scope(),
        idempotency_key: key.to_owned(),
        records: mneme_core::fixtures::fixture_batch()
            .iter()
            .map(draft)
            .collect(),
        source_blobs: vec![crate::requests::SourceBlobDraft::inline(
            mneme_core::fixtures::SOURCE_TEXT.as_bytes().to_vec(),
            mneme_core::Symbol::from("text/asciidoc"),
        )],
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: None,
    }
}

fn committed_workspace(root: &std::path::Path) -> super::Workspace {
    let mut workspace = super::Workspace::create(root, config()).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    workspace
        .commit(fixture_command(genesis, "first"))
        .expect("commit");
    workspace
}

fn replace_entity(workspace: &mut super::Workspace, serial: u8) {
    replace_entity_as(workspace, serial, "test-author");
}

fn replace_entity_as(workspace: &mut super::Workspace, serial: u8, actor: &str) {
    let snapshot = workspace.snapshot().expect("snapshot");
    let previous = snapshot
        .records
        .iter()
        .find(|record| record.record_id == mneme_core::fixtures::entity_id())
        .expect("entity");
    let mut replacement = draft(previous);
    replacement.predecessor = Some(previous.revision_id);
    replacement.revision_id = mneme_core::RevisionId::from_bytes([serial; 16]);
    replacement.payload.insert(
        mneme_core::Symbol::from("label"),
        mneme_core::Value::string("Changed Cedar"),
    );
    let mut command = fixture_command(snapshot.revision, &format!("replace-{serial}"));
    command.actor = actor.to_owned();
    command.records = vec![replacement];
    command.source_blobs.clear();
    workspace.commit(command).expect("replace entity");
}

#[test]
fn history_bound_refuses_before_decoding_an_over_budget_payload() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = committed_workspace(temp.path());
    replace_entity(&mut workspace, 0xf0);
    let snapshot = workspace.snapshot().expect("snapshot");
    let expected = snapshot
        .records
        .iter()
        .map(|record| {
            (
                record.record_id,
                workspace
                    .record_revisions(record.record_id)
                    .expect("independent history"),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let total = expected.values().map(Vec::len).sum::<usize>();
    let exact = workspace
        .record_histories_in(
            &workspace.connection,
            &snapshot,
            snapshot.revision,
            snapshot.eligibility_generation,
            total,
        )
        .expect("exact history boundary");
    assert_eq!(exact, expected);
    // Ordered history has one more row than live membership. Removing the
    // last record's blob distinguishes early refusal from decode-then-truncate.
    let last = snapshot
        .records
        .iter()
        .max_by_key(|record| record.record_id)
        .expect("last record");
    std::fs::remove_file(crate::payload::blob_path(
        &workspace.root,
        last.full_digest(),
    ))
    .expect("remove last blob");
    let over = workspace
        .record_histories_in(
            &workspace.connection,
            &snapshot,
            snapshot.revision,
            snapshot.eligibility_generation,
            total - 1,
        )
        .expect_err("history exceeds budget");
    assert!(matches!(over, crate::error::Failure::HistoryLimitExceeded));
    let within = workspace
        .record_histories_in(
            &workspace.connection,
            &snapshot,
            snapshot.revision,
            snapshot.eligibility_generation,
            total,
        )
        .expect_err("admitted payload still needs integrity verification");
    assert!(matches!(within, crate::error::Failure::Integrity { .. }));
}

#[test]
fn named_revision_read_returns_durable_actor_time_and_sequence() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = committed_workspace(temp.path());
    replace_entity_as(&mut workspace, 0xf0, "second-author");
    let first = workspace.revision_at_sequence(1).expect("first sequence");
    let first = first.expect("first committed revision");
    let second = workspace.current_revision().expect("second revision");
    let absent = mneme_core::WorkspaceRevisionId::from_bytes([0xfa; 16]);
    let revisions = std::collections::BTreeSet::from([first, second, absent]);

    let commits = workspace
        .revision_commits_for(&revisions)
        .expect("named commit metadata");
    assert_eq!(commits.len(), 2);
    assert_eq!(commits[&first].sequence, 1);
    assert_eq!(commits[&first].actor, "test-author");
    assert_eq!(commits[&first].committed_at_ns, 1_000);
    assert_eq!(commits[&second].sequence, 2);
    assert_eq!(commits[&second].actor, "second-author");
    assert_eq!(commits[&second].committed_at_ns, 1_000);
}

#[test]
fn record_revision_pages_map_each_envelope_to_its_commit_newest_first() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = committed_workspace(temp.path());
    for serial in 1..=10 {
        replace_entity(&mut workspace, serial);
    }
    let first = workspace
        .record_revision_commits(mneme_core::fixtures::entity_id(), None)
        .expect("newest history page");
    assert_eq!(first.entries.len(), super::MAX_RECORD_REVISION_PAGE);
    assert!(first.has_more);
    assert_eq!(first.entries[0].commit.sequence, 11);
    assert_eq!(first.entries[0].commit.actor, "test-author");
    assert_eq!(first.entries[0].commit.committed_at_ns, 1_000);
    assert_eq!(
        first.entries[0].record.revision_id,
        mneme_core::RevisionId::from_bytes([10; 16])
    );
    assert_eq!(
        first.next_before_sequence,
        Some(
            first.entries[super::MAX_RECORD_REVISION_PAGE - 1]
                .commit
                .sequence
        )
    );

    let older = workspace
        .record_revision_commits(
            mneme_core::fixtures::entity_id(),
            first.next_before_sequence,
        )
        .expect("older history page");
    assert_eq!(older.entries.len(), 1);
    assert!(!older.has_more);
    assert_eq!(older.entries[0].commit.sequence, 1);
    assert_eq!(
        older.entries[0].record.record_id,
        mneme_core::fixtures::entity_id()
    );
    assert_eq!(older.entries[0].commit.actor, "test-author");
    assert_eq!(older.next_before_sequence, None);
}

#[test]
fn named_revision_read_refuses_more_than_256_revisions() {
    let temp = tempfile::tempdir().expect("temp");
    let workspace = committed_workspace(temp.path());
    let revisions = (0..257_u64)
        .map(|sequence| {
            let mut bytes = [0; 16];
            bytes[..8].copy_from_slice(&sequence.to_be_bytes());
            mneme_core::WorkspaceRevisionId::from_bytes(bytes)
        })
        .collect::<std::collections::BTreeSet<_>>();

    assert!(matches!(
        workspace.revision_commits_for(&revisions),
        Err(crate::error::Failure::HistoryLimitExceeded)
    ));
}

#[test]
fn record_revision_read_refuses_a_forgotten_identity() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = committed_workspace(temp.path());
    let generation = workspace.eligibility_generation().expect("generation");
    workspace
        .commit(forget_assertion_command(
            &workspace,
            generation.saturating_add(1),
        ))
        .expect("forget assertion");

    assert!(matches!(
        workspace.record_revision_commits(mneme_core::fixtures::assertion_id(), None),
        Err(crate::error::Failure::RetentionSuppressed { .. })
    ));
}

// A concurrent forget commits its barrier and then purges payloads. These
// tests reproduce the only observable effect a read can see of that
// ordering: the generation a read started with is no longer current while a
// committed payload is missing. The read path has no fault hook, so the
// load is entered directly with the generation the read pinned.
#[test]
fn a_record_payload_purged_after_a_barrier_is_a_barrier_change() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = committed_workspace(temp.path());
    let revision = workspace.current_revision().expect("current");
    let generation = workspace.eligibility_generation().expect("generation");
    let row = super::revision_row_by_id(&workspace.connection, revision)
        .expect("row")
        .expect("present");
    let snapshot = workspace
        .load_snapshot_checked(row.clone(), generation, super::PayloadCheck::FromDisk)
        .expect("snapshot");
    let assertion = snapshot
        .records
        .iter()
        .find(|record| record.record_id == mneme_core::fixtures::assertion_id())
        .expect("assertion");
    std::fs::remove_file(crate::payload::blob_path(
        &workspace.root,
        assertion.full_digest(),
    ))
    .expect("purge the committed record blob");

    // Nothing moved during the read, so the absence is still the payload's
    // own integrity failure.
    let unchanged = workspace
        .load_snapshot_checked(row.clone(), generation, super::PayloadCheck::FromDisk)
        .expect_err("missing record payload");
    assert!(matches!(unchanged, crate::error::Failure::Integrity { .. }));

    workspace.advance_eligibility_barrier().expect("barrier");
    let stale = workspace
        .load_snapshot_checked(row, generation, super::PayloadCheck::FromDisk)
        .expect_err("barrier moved during the read");
    assert!(matches!(
        stale,
        crate::error::Failure::BarrierAdvanced { pinned, current }
            if pinned == generation && current == generation.saturating_add(1)
    ));
}

#[test]
fn generation_barrier_takes_file_lock_before_waiting_for_sqlite_writer() {
    let temp = tempfile::tempdir().expect("temp");
    let root = temp.path().to_path_buf();
    let writer = committed_workspace(&root);
    let pinned_generation = writer.eligibility_generation().expect("generation");
    let mut sqlite_blocker = super::Workspace::open(&root, config()).expect("second handle");
    let transaction = sqlite_blocker
        .connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .expect("hold SQLite writer lock");
    let (locked_sender, locked_receiver) = std::sync::mpsc::sync_channel(1);
    let barrier_root = root.clone();
    let barrier = std::thread::spawn(move || {
        let mut workspace =
            super::Workspace::open(&barrier_root, config()).expect("barrier handle");
        workspace
            .advance_eligibility_barrier_after_lock(|| {
                locked_sender.send(()).expect("report exclusive file lock");
            })
            .expect("advance after writer releases SQLite")
    });

    locked_receiver
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("barrier must acquire workspace.lock before waiting for SQLite");
    let probe = std::fs::File::open(root.join(super::LOCK_FILE)).expect("workspace lock file");
    assert!(
        probe.try_lock().is_err(),
        "an exclusive generation barrier must exclude a new guarded participant write while waiting for SQLite"
    );

    drop(transaction);
    drop(sqlite_blocker);
    assert_eq!(
        barrier.join().expect("barrier thread"),
        pinned_generation + 1
    );
    assert!(matches!(
        writer
            .eligibility_guard(pinned_generation)
            .expect_err("the stale participant write must be refused"),
        crate::error::Failure::BarrierAdvanced { pinned, current }
            if pinned == pinned_generation && current == pinned_generation + 1
    ));
}

#[test]
fn a_source_payload_purged_after_a_barrier_is_a_barrier_change() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = committed_workspace(temp.path());
    let revision = workspace.current_revision().expect("current");
    let generation = workspace.eligibility_generation().expect("generation");
    let row = super::revision_row_by_id(&workspace.connection, revision)
        .expect("row")
        .expect("present");
    let snapshot = workspace
        .load_snapshot_checked(row.clone(), generation, super::PayloadCheck::FromDisk)
        .expect("snapshot");
    let digest = snapshot
        .records
        .iter()
        .find(|record| record.record_id == mneme_core::fixtures::source_revision_id())
        .and_then(super::validation::retained_source_digest)
        .expect("source digest");
    std::fs::remove_file(crate::payload::blob_path(&workspace.root, digest))
        .expect("purge the committed source blob");

    let unchanged = workspace
        .load_snapshot_checked(row.clone(), generation, super::PayloadCheck::FromDisk)
        .expect_err("missing source payload");
    assert!(matches!(unchanged, crate::error::Failure::Integrity { .. }));

    workspace.advance_eligibility_barrier().expect("barrier");
    let stale = workspace
        .load_snapshot_checked(row, generation, super::PayloadCheck::FromDisk)
        .expect_err("barrier moved during the read");
    assert!(matches!(
        stale,
        crate::error::Failure::BarrierAdvanced { .. }
    ));
}

fn forget_assertion_command(
    workspace: &super::Workspace,
    generation: u64,
) -> crate::requests::CommitCommand {
    crate::requests::CommitCommand {
        base: workspace.current_revision().expect("base"),
        actor: "test-author".to_owned(),
        scope: scope(),
        idempotency_key: "forget".to_owned(),
        records: Vec::new(),
        source_blobs: Vec::new(),
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: Some(crate::lifecycle::RetentionCommit {
            operation_id: "forget".to_owned(),
            operation_kind: "forget".to_owned(),
            policy_version: "1".to_owned(),
            selectors: Vec::new(),
            suppressions: vec![crate::lifecycle::RetentionSuppression {
                operation_id: "forget".to_owned(),
                target: mneme_core::fixtures::assertion_id(),
                revision: None,
                target_kind: "assertion".to_owned(),
                mode: crate::lifecycle::SuppressionMode::Forgotten,
                content_digest: None,
                generation,
            }],
            locations: Vec::new(),
            retained_metadata: Vec::new(),
        }),
    }
}

#[test]
fn a_barrier_advance_drops_this_handles_decoded_records() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = committed_workspace(temp.path());
    let snapshot = workspace.snapshot().expect("snapshot");
    assert_eq!(
        workspace.records.borrow().entries.len(),
        snapshot.records.len(),
        "a read remembers the verified envelopes it decoded"
    );
    workspace.advance_eligibility_barrier().expect("barrier");
    assert!(
        workspace.records.borrow().entries.is_empty(),
        "no decode outlives the erasure generation it was read under"
    );
}

#[test]
fn a_forget_drops_this_handles_decoded_records() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = committed_workspace(temp.path());
    let snapshot = workspace.snapshot().expect("snapshot");
    let assertion = snapshot
        .records
        .iter()
        .find(|record| record.record_id == mneme_core::fixtures::assertion_id())
        .expect("assertion");
    let digest = assertion.full_digest();
    assert!(workspace.records.borrow().get(digest).is_some());

    let generation = workspace.eligibility_generation().expect("generation");
    let command = forget_assertion_command(&workspace, generation.saturating_add(1));
    workspace.commit(command).expect("forget");

    assert!(
        workspace.records.borrow().entries.is_empty(),
        "the forget advanced the generation, so no decode may be served"
    );
    let after = workspace.snapshot().expect("snapshot after the forget");
    assert!(
        after
            .records
            .iter()
            .all(|record| record.record_id != mneme_core::fixtures::assertion_id()),
        "a forgotten record leaves every later snapshot"
    );
    assert!(workspace.records.borrow().get(digest).is_none());
}

#[test]
fn a_cached_envelope_that_disagrees_with_its_ledger_row_fails_closed() {
    let temp = tempfile::tempdir().expect("temp");
    let workspace = committed_workspace(temp.path());
    let snapshot = workspace.snapshot().expect("snapshot");
    let record = snapshot
        .records
        .iter()
        .find(|record| record.record_id == mneme_core::fixtures::assertion_id())
        .expect("assertion");
    let full_digest = record.full_digest();
    let identity = super::EnvelopeIdentity {
        record_id: record.record_id,
        revision_id: record.revision_id,
        kind: record.kind,
        full_digest: full_digest.as_bytes().as_slice(),
    };
    assert!(
        workspace
            .cached_envelope(
                record.full_digest(),
                &identity,
                record.payload_digest(),
                snapshot.revision,
                super::PayloadCheck::Cached,
            )
            .expect("cached lookup")
            .is_some()
    );
    let mismatched = workspace
        .cached_envelope(
            record.full_digest(),
            &identity,
            mneme_core::ContentDigest::of_source_bytes(b"another payload"),
            snapshot.revision,
            super::PayloadCheck::Cached,
        )
        .expect_err("a payload digest the ledger row does not record");
    assert!(matches!(
        mismatched,
        crate::error::Failure::Integrity { .. }
    ));
}

fn cached_file_identity(byte_length: usize) -> super::FileIdentity {
    super::FileIdentity {
        byte_length: u64::try_from(byte_length).expect("length"),
        modified: std::time::SystemTime::UNIX_EPOCH,
        device: 0,
        inode: 0,
    }
}

#[test]
fn the_record_cache_evicts_the_oldest_entries_at_its_byte_bound() {
    let envelope = mneme_core::fixtures::entity();
    let mut cache = super::RecordCache::default();
    // One entry larger than the whole byte budget is never retained.
    let oversized = mneme_core::ContentDigest::of_source_bytes(b"oversized");
    let oversized_bytes = super::MAX_CACHED_RECORD_BYTES.saturating_add(1);
    cache.insert(
        oversized,
        envelope.clone(),
        envelope.payload_digest(),
        oversized_bytes,
        cached_file_identity(oversized_bytes),
    );
    assert!(cache.get(oversized).is_none());

    // Two entries that together exceed the byte budget keep only the newest.
    let half = super::MAX_CACHED_RECORD_BYTES / 2 + 1;
    let first = mneme_core::ContentDigest::of_source_bytes(b"first");
    let second = mneme_core::ContentDigest::of_source_bytes(b"second");
    let half_identity = cached_file_identity(half);
    cache.insert(
        first,
        envelope.clone(),
        envelope.payload_digest(),
        half,
        half_identity,
    );
    assert!(cache.get(first).is_some());
    cache.insert(
        second,
        envelope.clone(),
        envelope.payload_digest(),
        half,
        half_identity,
    );
    assert_eq!(cache.entries.len(), 1);
    assert!(cache.get(first).is_none());
    assert!(cache.get(second).is_some());
    assert_eq!(
        cache.encoded_bytes, half,
        "eviction keeps the byte accounting exact"
    );
}

#[test]
fn a_forget_through_one_handle_drops_the_shared_facts() {
    let temp = tempfile::tempdir().expect("temp");
    let cache = super::SharedRecordCache::new();
    let mut creator = super::Workspace::create(temp.path(), config()).expect("create");
    let genesis = creator.current_revision().expect("genesis");
    creator
        .commit(fixture_command(genesis, "first"))
        .expect("commit");
    drop(creator);
    let reader =
        super::Workspace::open_with_cache(temp.path(), config(), cache.clone()).expect("reader");
    let mut forgetter =
        super::Workspace::open_with_cache(temp.path(), config(), cache.clone()).expect("forgetter");
    let pinned = reader.snapshot().expect("snapshot");
    assert_eq!(
        cache.with(|facts| facts.entries.len()),
        pinned.records.len(),
        "a shared handle records every envelope it verified"
    );
    assert!(
        cache.with(|facts| !facts.sources.is_empty()),
        "a verified retained source leaves an identity fact and no bytes"
    );

    let generation = forgetter.eligibility_generation().expect("generation");
    let command = forget_assertion_command(&forgetter, generation.saturating_add(1));
    forgetter.commit(command).expect("forget");

    assert!(
        cache.with(|facts| facts.entries.is_empty() && facts.sources.is_empty()),
        "the barrier drops every fact the handles share"
    );
    let after = reader.snapshot().expect("snapshot after the forget");
    assert!(
        after
            .records
            .iter()
            .all(|record| record.record_id != mneme_core::fixtures::assertion_id()),
        "a forgotten record leaves every later snapshot"
    );
}

#[test]
fn a_snapshot_load_keeps_one_revision_while_another_handle_commits() {
    let temp = tempfile::tempdir().expect("temp");
    let first = committed_workspace(temp.path());
    let mut second = super::Workspace::open(temp.path(), config()).expect("open");
    let pinned = first.snapshot().expect("pinned");
    let row = super::revision_row_by_id(&first.connection, pinned.revision)
        .expect("row")
        .expect("present");

    let transaction = first
        .connection
        .unchecked_transaction()
        .expect("read transaction");
    // The first statement of a load pins the ledger state every later statement
    // must see.
    let head = super::sweep::forgotten_suppressions_in(&transaction).expect("suppressions");
    assert!(
        !head
            .identities
            .contains(&mneme_core::fixtures::assertion_id())
    );

    // Another handle erases the assertion while this read is open.
    let generation = second.eligibility_generation().expect("generation");
    let command = forget_assertion_command(&second, generation.saturating_add(1));
    second.commit(command).expect("forget");
    assert_eq!(second.current_sequence().expect("sequence"), 2);

    // The open read still returns exactly the revision it pinned, complete.
    let loaded = first
        .build_snapshot_in(
            &transaction,
            &row,
            pinned.eligibility_generation,
            super::PayloadCheck::Cached,
        )
        .expect("load");
    assert_eq!(loaded.sequence, pinned.sequence);
    assert_eq!(loaded.records, pinned.records);
    drop(transaction);

    // The workspace moved on while that read ran: a later load sees the erasure.
    let after = first.snapshot().expect("snapshot after the forget");
    assert_eq!(after.sequence, 2);
    assert!(
        after
            .records
            .iter()
            .all(|record| record.record_id != mneme_core::fixtures::assertion_id())
    );
}

#[test]
fn revision_delta_tracks_inserts_replacements_reverse_steps_and_forgets() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = committed_workspace(temp.path());
    let rev1 = workspace.current_revision().expect("rev1");
    let gen1 = workspace.eligibility_generation().expect("gen1");
    let old_entity_rev = mneme_core::fixtures::entity().revision_id;

    // Replace entity and insert a new entity in rev2.
    let updated_entity = crate::requests::RecordDraft {
        schema_version: 1,
        kind: mneme_core::RecordKind::Entity,
        record_id: mneme_core::fixtures::entity_id(),
        revision_id: mneme_core::RevisionId::from_bytes([0x99; 16]),
        predecessor: Some(old_entity_rev),
        scope: scope(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("entity-type"),
                mneme_core::Value::symbol("concept"),
            ),
            (
                mneme_core::Symbol::from("label"),
                mneme_core::Value::string("Updated Label".to_owned()),
            ),
            (
                mneme_core::Symbol::from("properties"),
                mneme_core::Value::dictionary([]),
            ),
        ]),
    };
    let extra_id = mneme_core::RecordId::from_bytes([0x88; 16]);
    let extra_rev = mneme_core::RevisionId::from_bytes([0x89; 16]);
    let extra_entity = crate::requests::RecordDraft {
        schema_version: 1,
        kind: mneme_core::RecordKind::Entity,
        record_id: extra_id,
        revision_id: extra_rev,
        predecessor: None,
        scope: scope(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("entity-type"),
                mneme_core::Value::symbol("paper"),
            ),
            (
                mneme_core::Symbol::from("label"),
                mneme_core::Value::string("Inserted Paper".to_owned()),
            ),
            (
                mneme_core::Symbol::from("properties"),
                mneme_core::Value::dictionary([]),
            ),
        ]),
    };
    let rev2 = workspace
        .commit(crate::requests::CommitCommand {
            base: rev1,
            actor: "delta-test".to_owned(),
            scope: scope(),
            idempotency_key: "rev2-delta".to_owned(),
            records: vec![updated_entity, extra_entity],
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        })
        .expect("commit rev2")
        .revision;

    let forward = workspace
        .revision_delta(rev1, rev2, Some(gen1))
        .expect("forward delta");
    assert_eq!(forward.removed.len(), 1);
    assert_eq!(
        forward.removed[0].record_id,
        mneme_core::fixtures::entity_id()
    );
    assert_eq!(forward.removed[0].revision_id, old_entity_rev);
    assert_eq!(forward.added.len(), 2);
    assert!(
        forward
            .added
            .iter()
            .any(|r| r.record_id == mneme_core::fixtures::entity_id()
                && r.revision_id == mneme_core::RevisionId::from_bytes([0x99; 16]))
    );
    assert!(
        forward
            .added
            .iter()
            .any(|r| r.record_id == extra_id && r.revision_id == extra_rev)
    );

    // Reverse delta rev2 -> rev1 restores the prior revision of entity and drops extra_id.
    let reverse = workspace
        .revision_delta(rev2, rev1, Some(gen1))
        .expect("reverse delta");
    assert_eq!(reverse.removed.len(), 2);
    assert_eq!(reverse.added.len(), 1);
    assert_eq!(
        reverse.added[0].record_id,
        mneme_core::fixtures::entity_id()
    );
    assert_eq!(reverse.added[0].revision_id, old_entity_rev);

    // Forget the assertion in rev3; pinned gen1 fails closed, unpinned succeeds with forgotten set.
    let forget_cmd = forget_assertion_command(&workspace, gen1.saturating_add(1));
    let rev3 = workspace.commit(forget_cmd).expect("forget").revision;
    assert!(matches!(
        workspace.revision_delta(rev2, rev3, Some(gen1)),
        Err(crate::error::Failure::BarrierAdvanced { .. })
    ));
    let forget_delta = workspace
        .revision_delta(rev2, rev3, None)
        .expect("unpinned forget delta");
    assert_eq!(forget_delta.eligibility_generation, gen1.saturating_add(1));
    assert!(
        forget_delta
            .forgotten_identities
            .contains(&mneme_core::fixtures::assertion_id())
    );
}
