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
        source_blobs: vec![crate::requests::SourceBlobDraft {
            bytes: mneme_core::fixtures::SOURCE_TEXT.as_bytes().to_vec(),
            media_type: mneme_core::Symbol::from("text/asciidoc"),
        }],
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
