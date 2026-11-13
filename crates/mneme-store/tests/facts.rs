//! Verified-fact and warm-handle regressions: the private and shared verified
//! record caches, verified retained-source identities, membership histories,
//! purge barriers and one read transaction per snapshot load.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

// `common` holds the single definition of every shared fixture. These adapters
// let the tests below keep calling a fixture by name: the lint gate rejects
// importing a non-trait item, so the name is bound here instead.
fn scope() -> mneme_core::ScopeId {
    common::scope()
}

fn config(at: i64) -> mneme_store::WorkspaceConfig {
    common::config(at)
}

fn draft(envelope: &mneme_core::RecordEnvelope) -> mneme_store::RecordDraft {
    common::draft(envelope)
}

fn fixture_command(base: mneme_core::WorkspaceRevisionId, key: &str) -> mneme_store::CommitCommand {
    common::fixture_command(base, key)
}

fn open(root: &std::path::Path, at: i64) -> mneme_store::Workspace {
    common::open(root, at)
}

fn retained_source_record(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    bytes: &[u8],
    path: Option<&str>,
) -> mneme_store::RecordDraft {
    common::retained_source_record(record_id, revision_id, scope, bytes, path)
}

fn publication_command(
    base: mneme_core::WorkspaceRevisionId,
    scope: &mneme_core::ScopeId,
    key: &str,
    path: &str,
    bytes: &[u8],
) -> mneme_store::CommitCommand {
    common::publication_command(base, scope, key, path, bytes)
}

#[allow(unknown_lints, too_many_parameters)] // every membership fixture passes the three target fields positionally
fn record_command(
    base: mneme_core::WorkspaceRevisionId,
    scope: &mneme_core::ScopeId,
    key: &str,
    records: Vec<mneme_store::RecordDraft>,
    blobs: Vec<mneme_store::SourceBlobDraft>,
    candidates: Vec<mneme_store::ImportCandidateDraft>,
) -> mneme_store::CommitCommand {
    common::record_command(base, scope, key, records, blobs, candidates)
}

fn source_blob(bytes: &[u8]) -> mneme_store::SourceBlobDraft {
    common::source_blob(bytes)
}

fn forget_content_barrier(
    target: mneme_core::RecordId,
    bytes: &[u8],
    generation: u64,
    operation_id: &str,
) -> mneme_store::RetentionCommit {
    common::forget_content_barrier(target, bytes, generation, operation_id)
}

fn audit_barrier_command(
    base: mneme_core::WorkspaceRevisionId,
    key: &str,
    retention: mneme_store::RetentionCommit,
) -> mneme_store::CommitCommand {
    common::audit_barrier_command(base, key, retention)
}

fn audit_blob_location(
    location_kind: &str,
    digest: mneme_core::ContentDigest,
) -> mneme_store::RetentionLocationPlan {
    common::audit_blob_location(location_kind, digest)
}

/// The ledger a fixed sequence of commands produces in one test.
struct MembershipHistory {
    workspace: mneme_store::Workspace,
    revisions: Vec<mneme_core::WorkspaceRevisionId>,
    entity: mneme_core::RecordId,
    source: mneme_core::RecordId,
}

const ALPHA_DRAFT: &[u8] = b"= Alpha draft\n\nFirst retained bytes.\n";
const BETA_DRAFT: &[u8] = b"= Beta draft\n\nSecond retained bytes.\n";
const PUBLISHED_NOTE: &[u8] = b"= Notes\n\nA committed publication.\n";

fn open_ledger(root: &std::path::Path) -> rusqlite::Connection {
    rusqlite::Connection::open(root.join(mneme_store::LEDGER_FILE)).expect("ledger")
}

fn workspace_identity(bytes: &[u8]) -> mneme_core::WorkspaceRevisionId {
    let mut identity = [0_u8; 16];
    identity.copy_from_slice(bytes);
    mneme_core::WorkspaceRevisionId::from_bytes(identity)
}

fn record_identity(bytes: &[u8]) -> mneme_core::RecordId {
    let mut identity = [0_u8; 16];
    identity.copy_from_slice(bytes);
    mneme_core::RecordId::from_bytes(identity)
}

fn record_revision(bytes: &[u8]) -> mneme_core::RevisionId {
    let mut identity = [0_u8; 16];
    identity.copy_from_slice(bytes);
    mneme_core::RevisionId::from_bytes(identity)
}

fn content_digest(bytes: &[u8], profile: &str, boundary: &str) -> mneme_core::ContentDigest {
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(bytes);
    mneme_core::ContentDigest::from_parts(
        mneme_core::HashAlgorithm::Sha256,
        mneme_core::EncodingProfile::parse(profile).expect("profile"),
        mneme_core::ValueBoundary::parse(boundary).expect("boundary"),
        digest,
    )
    .expect("digest")
}

fn entity_record(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    predecessor: Option<mneme_core::RevisionId>,
    label: &str,
) -> mneme_store::RecordDraft {
    let mut envelope = mneme_core::fixtures::entity();
    envelope.record_id = record_id;
    envelope.revision_id = revision_id;
    envelope.predecessor = predecessor;
    envelope.payload.insert(
        mneme_core::Symbol::from("label"),
        mneme_core::Value::string(label),
    );
    draft(&envelope)
}

fn pruned_source_record(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    predecessor: mneme_core::RevisionId,
    prior: mneme_core::ContentDigest,
) -> mneme_store::RecordDraft {
    mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::SourceRevision,
        record_id,
        revision_id,
        predecessor: Some(predecessor),
        scope: scope(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("content"),
                mneme_core::SourceContent::Unavailable {
                    reason: "pruned by retention".to_owned(),
                }
                .to_value(),
            ),
            (
                mneme_core::Symbol::from("acquisition"),
                mneme_core::Value::symbol("authored"),
            ),
            (
                mneme_core::Symbol::from("availability"),
                mneme_core::Value::symbol("pruned"),
            ),
            (mneme_core::Symbol::from("content-digest"), prior.to_value()),
        ]),
    }
}

fn snapshot_identities(
    snapshot: &mneme_store::Snapshot,
) -> Vec<(mneme_core::RecordId, mneme_core::RevisionId)> {
    let mut identities: Vec<_> = snapshot
        .records
        .iter()
        .map(|record| (record.record_id, record.revision_id))
        .collect();
    identities.sort();
    identities
}

fn membership_spans(
    connection: &rusqlite::Connection,
    record: mneme_core::RecordId,
) -> Vec<(i64, Option<i64>)> {
    let mut statement = connection
        .prepare(
            "SELECT first_sequence, last_sequence FROM record_membership
             WHERE record_id = ?1 ORDER BY first_sequence",
        )
        .expect("spans");
    statement
        .query_map(rusqlite::params![record.as_bytes().as_slice()], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?))
        })
        .expect("query")
        .collect::<std::result::Result<Vec<_>, _>>()
        .expect("rows")
}

/// The fixed record and revision identities a copied-membership history uses.
struct CopiedHistoryIds {
    entity: mneme_core::RecordId,
    source: mneme_core::RecordId,
    entity_first: mneme_core::RevisionId,
    entity_second: mneme_core::RevisionId,
    source_first: mneme_core::RevisionId,
    source_second: mneme_core::RevisionId,
}

impl CopiedHistoryIds {
    fn fixed() -> Self {
        CopiedHistoryIds {
            entity: mneme_core::RecordId::from_bytes([0x31; 16]),
            source: mneme_core::RecordId::from_bytes([0x32; 16]),
            entity_first: mneme_core::RevisionId::from_bytes([0x41; 16]),
            entity_second: mneme_core::RevisionId::from_bytes([0x42; 16]),
            source_first: mneme_core::RevisionId::from_bytes([0x43; 16]),
            source_second: mneme_core::RevisionId::from_bytes([0x44; 16]),
        }
    }
}

fn build_copied_membership_history(root: &std::path::Path) -> MembershipHistory {
    let ids = CopiedHistoryIds::fixed();
    let mut workspace = mneme_store::Workspace::create(root, config(1_000)).expect("create");
    let revisions = run_copied_history(&mut workspace, &ids);
    MembershipHistory {
        workspace,
        revisions,
        entity: ids.entity,
        source: ids.source,
    }
}

/// Commit the five revisions of a copied-membership history, genesis first.
fn run_copied_history(
    workspace: &mut mneme_store::Workspace,
    ids: &CopiedHistoryIds,
) -> Vec<mneme_core::WorkspaceRevisionId> {
    let mut revisions = vec![workspace.current_revision().expect("genesis")];
    seed_copied_history(workspace, ids, &mut revisions);
    revise_copied_history(workspace, ids, &mut revisions);
    publish_copied_note(workspace, &mut revisions);
    revisions
}

/// Commit the seed revision that writes the entity and the retained source.
fn seed_copied_history(
    workspace: &mut mneme_store::Workspace,
    ids: &CopiedHistoryIds,
    revisions: &mut Vec<mneme_core::WorkspaceRevisionId>,
) {
    let base = workspace.current_revision().expect("base");
    commit_recorded(
        workspace,
        revisions,
        "seed",
        record_command(
            base,
            &scope(),
            "seed",
            vec![
                entity_record(ids.entity, ids.entity_first, None, "Alpha"),
                retained_source_record(
                    ids.source,
                    ids.source_first,
                    &scope(),
                    ALPHA_DRAFT,
                    Some("alpha.adoc"),
                ),
            ],
            vec![source_blob(ALPHA_DRAFT)],
            Vec::new(),
        ),
    );
}

/// Commit the revisions that revise, protect and forget the seed's records.
fn revise_copied_history(
    workspace: &mut mneme_store::Workspace,
    ids: &CopiedHistoryIds,
    revisions: &mut Vec<mneme_core::WorkspaceRevisionId>,
) {
    let mut second =
        retained_source_record(ids.source, ids.source_second, &scope(), BETA_DRAFT, None);
    second.predecessor = Some(ids.source_first);
    let base = workspace.current_revision().expect("base");
    commit_recorded(
        workspace,
        revisions,
        "revise the source",
        record_command(
            base,
            &scope(),
            "revise-source",
            vec![second],
            vec![source_blob(BETA_DRAFT)],
            Vec::new(),
        ),
    );
    let base = workspace.current_revision().expect("base");
    commit_recorded(
        workspace,
        revisions,
        "revise the entity",
        record_command(
            base,
            &scope(),
            "revise-entity",
            vec![entity_record(
                ids.entity,
                ids.entity_second,
                Some(ids.entity_first),
                "Alpha revised",
            )],
            Vec::new(),
            Vec::new(),
        ),
    );
    let generation = workspace.eligibility_generation().expect("generation");
    let base = workspace.current_revision().expect("base");
    commit_recorded(
        workspace,
        revisions,
        "forget the source",
        audit_barrier_command(
            base,
            "forget-source",
            forget_content_barrier(
                ids.source,
                BETA_DRAFT,
                generation.saturating_add(1),
                "forget-source",
            ),
        ),
    );
}

/// Commit the publication of the history's working file.
fn publish_copied_note(
    workspace: &mut mneme_store::Workspace,
    revisions: &mut Vec<mneme_core::WorkspaceRevisionId>,
) {
    let base = workspace.current_revision().expect("base");
    commit_recorded(
        workspace,
        revisions,
        "publish",
        publication_command(base, &scope(), "publish", "project.adoc", PUBLISHED_NOTE),
    );
}

/// Commit one command and record the revision the workspace then serves.
fn commit_recorded(
    workspace: &mut mneme_store::Workspace,
    revisions: &mut Vec<mneme_core::WorkspaceRevisionId>,
    label: &str,
    command: mneme_store::CommitCommand,
) {
    workspace.commit(command).expect(label);
    revisions.push(workspace.current_revision().expect("current"));
}

const COPIED_MEMBERSHIP_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS revision_records (
    revision_sequence INTEGER NOT NULL,
    record_id BLOB NOT NULL,
    revision_id BLOB NOT NULL,
    PRIMARY KEY (revision_sequence, record_id)
);
CREATE TABLE IF NOT EXISTS revision_blobs (
    revision_sequence INTEGER NOT NULL,
    digest BLOB NOT NULL,
    PRIMARY KEY (revision_sequence, digest)
);
"#;

/// Rewrite a new-format ledger into the shape the previous release wrote:
/// one membership row per revision and record, one blob row per revision and
/// digest, and the full manifest bytes on every revision.
fn rewrite_membership_to_copied_rows(root: &std::path::Path) {
    let connection = open_ledger(root);
    let revisions = ledger_revisions(&connection);
    connection
        .execute_batch(COPIED_MEMBERSHIP_DDL)
        .expect("copied tables");
    for (sequence, revision, parent, digest) in revisions {
        rewrite_revision_copied(&connection, sequence, &revision, parent.as_deref(), &digest);
    }
    connection
        .execute_batch(
            "INSERT INTO revision_records (revision_sequence, record_id, revision_id)
             SELECT v.sequence, m.record_id, m.revision_id FROM record_membership m
             JOIN revisions v ON v.sequence >= m.first_sequence
                 AND (m.last_sequence IS NULL OR v.sequence <= m.last_sequence);
             DELETE FROM meta WHERE key = 'membership_format';
             DROP TABLE record_membership;
             DROP TABLE revision_blob_changes;",
        )
        .expect("copied membership");
}

/// One ledger revision row: sequence, identity, parent and manifest digest.
type LedgerRevisionRow = (i64, Vec<u8>, Option<Vec<u8>>, Vec<u8>);

/// The sequence, identity, parent and stored manifest digest of every revision.
fn ledger_revisions(connection: &rusqlite::Connection) -> Vec<LedgerRevisionRow> {
    let mut statement = connection
        .prepare(
            "SELECT sequence, revision_id, parent_revision_id, manifest_digest
             FROM revisions ORDER BY sequence",
        )
        .expect("revisions");
    statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })
        .expect("query")
        .collect::<std::result::Result<Vec<_>, _>>()
        .expect("rows")
}

/// The record revisions one sequence's copied membership row names.
fn revision_manifest_records(
    connection: &rusqlite::Connection,
    sequence: i64,
) -> std::collections::BTreeSet<mneme_store::ManifestRecord> {
    let mut statement = connection
        .prepare(
            "SELECT r.record_id, r.revision_id, r.kind
             FROM record_membership m
             JOIN records r ON r.record_id = m.record_id
                 AND r.revision_id = m.revision_id
             WHERE m.first_sequence <= ?1
               AND (m.last_sequence IS NULL OR m.last_sequence >= ?1)",
        )
        .expect("membership");
    let records = statement
        .query_map(rusqlite::params![sequence], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .expect("query")
        .collect::<std::result::Result<Vec<_>, _>>()
        .expect("rows");
    let mut manifest_records = std::collections::BTreeSet::new();
    for (record, revision, kind) in records {
        manifest_records.insert(mneme_store::ManifestRecord {
            record_id: record_identity(&record),
            revision_id: record_revision(&revision),
            kind: mneme_core::RecordKind::parse(&kind).expect("kind"),
        });
    }
    manifest_records
}

/// The digests the recorded blob-set changes require at one sequence.
fn revision_blob_requirements(
    connection: &rusqlite::Connection,
    sequence: i64,
) -> std::collections::BTreeSet<mneme_core::ContentDigest> {
    let mut statement = connection
        .prepare(
            "SELECT c.digest, b.profile, b.boundary, c.change
             FROM revision_blob_changes c
             JOIN blobs b ON b.digest = c.digest
             WHERE c.revision_sequence <= ?1
             ORDER BY c.revision_sequence, c.digest",
        )
        .expect("journal");
    let changes = statement
        .query_map(rusqlite::params![sequence], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .expect("query")
        .collect::<std::result::Result<Vec<_>, _>>()
        .expect("rows");
    let mut required = std::collections::BTreeSet::new();
    for (blob, profile, boundary, change) in changes {
        let blob = content_digest(&blob, &profile, &boundary);
        match change.as_str() {
            "add" => {
                required.insert(blob);
            }
            _ => {
                assert!(
                    required.remove(&blob),
                    "a recorded removal must name a required digest"
                );
            }
        }
    }
    required
}

/// Rewrite one revision into the copied shape: the full manifest bytes and one
/// blob row per required digest.
fn rewrite_revision_copied(
    connection: &rusqlite::Connection,
    sequence: i64,
    revision: &[u8],
    parent: Option<&[u8]>,
    digest: &[u8],
) {
    let manifest = mneme_store::Manifest {
        revision: workspace_identity(revision),
        parent: parent.map(workspace_identity),
        records: revision_manifest_records(connection, sequence),
        blobs: revision_blob_requirements(connection, sequence),
    };
    assert_eq!(
        manifest.digest().as_bytes().as_slice(),
        digest,
        "the reconstructed manifest must match the identity the commit path stored"
    );
    connection
        .execute(
            "UPDATE revisions SET manifest = ?1 WHERE sequence = ?2",
            rusqlite::params![manifest.encode(), sequence],
        )
        .expect("stored manifest");
    for blob in &manifest.blobs {
        connection
            .execute(
                "INSERT INTO revision_blobs (revision_sequence, digest) VALUES (?1, ?2)",
                rusqlite::params![sequence, blob.as_bytes().as_slice()],
            )
            .expect("blob row");
    }
}

#[test]
fn single_record_commits_keep_membership_rows_linear() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let commits = 8_u8;
    for index in 0..commits {
        let draft = entity_record(
            mneme_core::RecordId::from_bytes([0x50 + index; 16]),
            mneme_core::RevisionId::from_bytes([0x60 + index; 16]),
            None,
            "row",
        );
        let base = workspace.current_revision().expect("base");
        workspace
            .commit(record_command(
                base,
                &scope(),
                &format!("row-{index}"),
                vec![draft],
                Vec::new(),
                Vec::new(),
            ))
            .expect("commit one record");
    }
    let ledger = open_ledger(temp.path());
    let membership: i64 = ledger
        .query_row("SELECT COUNT(*) FROM record_membership", [], |row| {
            row.get(0)
        })
        .expect("membership rows");
    assert_eq!(
        membership,
        i64::from(commits),
        "each commit stores only the record it introduced, never the whole snapshot"
    );
    let copied: i64 = ledger
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'table' AND name IN ('revision_records', 'revision_blobs')",
            [],
            |row| row.get(0),
        )
        .expect("copied tables");
    assert_eq!(copied, 0, "a new ledger carries no per-revision copy");
    let stored: i64 = ledger
        .query_row(
            "SELECT COUNT(*) FROM revisions WHERE length(manifest) > 0",
            [],
            |row| row.get(0),
        )
        .expect("stored manifests");
    assert_eq!(stored, 0, "no revision stores manifest bytes");
    assert_eq!(
        workspace.status().expect("status").record_count,
        usize::from(commits)
    );
}

#[test]
fn snapshot_at_returns_the_exact_membership_of_each_revision() {
    const GAMMA_DRAFT: &[u8] = b"= Gamma draft\n\nThird retained bytes.\n";
    let entity = mneme_core::RecordId::from_bytes([0x71; 16]);
    let source = mneme_core::RecordId::from_bytes([0x72; 16]);
    let entity_first = mneme_core::RevisionId::from_bytes([0x81; 16]);
    let entity_second = mneme_core::RevisionId::from_bytes([0x82; 16]);
    let source_first = mneme_core::RevisionId::from_bytes([0x83; 16]);
    let source_second = mneme_core::RevisionId::from_bytes([0x84; 16]);
    let source_third = mneme_core::RevisionId::from_bytes([0x85; 16]);
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let mut revisions = Vec::new();
    let base = workspace.current_revision().expect("base");
    workspace
        .commit(record_command(
            base,
            &scope(),
            "seed",
            vec![
                entity_record(entity, entity_first, None, "Alpha"),
                retained_source_record(
                    source,
                    source_first,
                    &scope(),
                    ALPHA_DRAFT,
                    Some("alpha.adoc"),
                ),
            ],
            vec![source_blob(ALPHA_DRAFT)],
            Vec::new(),
        ))
        .expect("seed");
    revisions.push(workspace.current_revision().expect("current"));
    let mut second = retained_source_record(source, source_second, &scope(), BETA_DRAFT, None);
    second.predecessor = Some(source_first);
    let base = workspace.current_revision().expect("base");
    workspace
        .commit(record_command(
            base,
            &scope(),
            "revise-source",
            vec![second],
            vec![source_blob(BETA_DRAFT)],
            Vec::new(),
        ))
        .expect("revise the source");
    revisions.push(workspace.current_revision().expect("current"));
    let base = workspace.current_revision().expect("base");
    workspace
        .commit(record_command(
            base,
            &scope(),
            "revise-entity",
            vec![entity_record(
                entity,
                entity_second,
                Some(entity_first),
                "Alpha revised",
            )],
            Vec::new(),
            Vec::new(),
        ))
        .expect("revise the entity");
    revisions.push(workspace.current_revision().expect("current"));
    let mut third = retained_source_record(source, source_third, &scope(), GAMMA_DRAFT, None);
    third.predecessor = Some(source_second);
    let base = workspace.current_revision().expect("base");
    workspace
        .commit(record_command(
            base,
            &scope(),
            "revise-source-again",
            vec![third],
            vec![source_blob(GAMMA_DRAFT)],
            Vec::new(),
        ))
        .expect("revise the source again");
    revisions.push(workspace.current_revision().expect("current"));

    let early = workspace.snapshot_at(revisions[0], None).expect("early");
    assert_eq!(
        snapshot_identities(&early),
        vec![(entity, entity_first), (source, source_first)]
    );
    let replaced = workspace.snapshot_at(revisions[1], None).expect("middle");
    assert_eq!(
        snapshot_identities(&replaced),
        vec![(entity, entity_first), (source, source_second)]
    );
    let revised = workspace.snapshot_at(revisions[2], None).expect("middle");
    assert_eq!(
        snapshot_identities(&revised),
        vec![(entity, entity_second), (source, source_second)]
    );
    let latest = workspace.snapshot_at(revisions[3], None).expect("latest");
    assert_eq!(
        snapshot_identities(&latest),
        vec![(entity, entity_second), (source, source_third)]
    );

    // A record the ledger drops leaves every later snapshot but keeps the
    // membership of the revisions that contained it.
    let remove_temp = tempfile::tempdir().expect("temp");
    let mut removed =
        mneme_store::Workspace::create(remove_temp.path(), config(1_000)).expect("create");
    let kept = mneme_core::RecordId::from_bytes([0x91; 16]);
    let dropped = mneme_core::RecordId::from_bytes([0x92; 16]);
    let kept_revision = mneme_core::RevisionId::from_bytes([0x93; 16]);
    let dropped_revision = mneme_core::RevisionId::from_bytes([0x94; 16]);
    let base = removed.current_revision().expect("base");
    removed
        .commit(record_command(
            base,
            &scope(),
            "seed",
            vec![
                entity_record(kept, kept_revision, None, "Kept"),
                retained_source_record(
                    dropped,
                    dropped_revision,
                    &scope(),
                    BETA_DRAFT,
                    Some("beta.adoc"),
                ),
            ],
            vec![source_blob(BETA_DRAFT)],
            Vec::new(),
        ))
        .expect("seed");
    let with_record = removed.current_revision().expect("current");
    let generation = removed.eligibility_generation().expect("generation");
    let base = removed.current_revision().expect("base");
    removed
        .commit(audit_barrier_command(
            base,
            "forget-source",
            forget_content_barrier(
                dropped,
                BETA_DRAFT,
                generation.saturating_add(1),
                "forget-source",
            ),
        ))
        .expect("forget the source");
    let forgotten = removed.current_revision().expect("current");
    let base = removed.current_revision().expect("base");
    removed
        .commit(publication_command(
            base,
            &scope(),
            "publish",
            "project.adoc",
            PUBLISHED_NOTE,
        ))
        .expect("publish");
    let without_record = removed.current_revision().expect("current");
    for revision in [with_record, forgotten, without_record] {
        let snapshot = removed.snapshot_at(revision, None).expect("snapshot");
        assert_eq!(snapshot_identities(&snapshot), vec![(kept, kept_revision)]);
    }
    let ledger = open_ledger(remove_temp.path());
    assert_eq!(
        membership_spans(&ledger, dropped),
        vec![(1, Some(2))],
        "the dropped record's interval ends at the revision that still held it"
    );
    assert_eq!(membership_spans(&ledger, kept), vec![(1, None)]);
}

#[test]
fn a_copied_membership_ledger_migrates_to_intervals_with_identical_identities() {
    let temp = tempfile::tempdir().expect("temp");
    let root = temp.path().to_path_buf();
    let history = build_copied_membership_history(&root);
    let sequences = history.workspace.revision_sequences().expect("sequences");
    let current = history.workspace.current_revision().expect("current");
    let generation = history
        .workspace
        .eligibility_generation()
        .expect("generation");
    let mut before = Vec::with_capacity(history.revisions.len());
    for revision in &history.revisions {
        let snapshot = history
            .workspace
            .snapshot_at(*revision, None)
            .expect("snapshot");
        before.push((
            snapshot.manifest_digest,
            snapshot.parent,
            snapshot_identities(&snapshot),
        ));
    }
    drop(history.workspace);
    rewrite_membership_to_copied_rows(&root);
    let reopened = open(&root, 2_000);
    assert_eq!(
        reopened.current_revision().expect("current"),
        current,
        "migration keeps the current revision"
    );
    assert_eq!(
        reopened.eligibility_generation().expect("generation"),
        generation,
        "migration keeps the eligibility generation"
    );
    assert_eq!(
        reopened.revision_sequences().expect("sequences"),
        sequences,
        "migration keeps every revision identity and sequence"
    );
    for (index, revision) in history.revisions.iter().enumerate() {
        let snapshot = reopened
            .snapshot_at(*revision, None)
            .expect("snapshot after migration");
        assert_eq!(
            snapshot.manifest_digest, before[index].0,
            "the migrated revision keeps the manifest identity the copied ledger stored"
        );
        assert_eq!(snapshot.parent, before[index].1);
        assert_eq!(&snapshot_identities(&snapshot), &before[index].2);
    }
    let ledger = open_ledger(&root);
    let membership: i64 = ledger
        .query_row("SELECT COUNT(*) FROM record_membership", [], |row| {
            row.get(0)
        })
        .expect("membership rows");
    assert_eq!(
        membership, 4,
        "the copied rows collapse into one interval per record revision"
    );
    assert_eq!(
        membership_spans(&ledger, history.entity),
        vec![(1, Some(2)), (3, None)]
    );
    assert_eq!(
        membership_spans(&ledger, history.source),
        vec![(1, Some(1)), (2, Some(4))]
    );
    let copied: i64 = ledger
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'table' AND name IN ('revision_records', 'revision_blobs')",
            [],
            |row| row.get(0),
        )
        .expect("copied tables");
    assert_eq!(
        copied, 0,
        "the copied tables are dropped after verification"
    );
    let stored: i64 = ledger
        .query_row(
            "SELECT COUNT(*) FROM revisions WHERE length(manifest) > 0",
            [],
            |row| row.get(0),
        )
        .expect("stored manifests");
    assert_eq!(stored, 0, "stored manifest bytes are cleared");
    let format: Vec<u8> = ledger
        .query_row(
            "SELECT value FROM meta WHERE key = 'membership_format'",
            [],
            |row| row.get(0),
        )
        .expect("membership format");
    assert_eq!(format.as_slice(), b"2".as_slice());
}

#[test]
fn a_corrupt_membership_row_fails_the_snapshot_load() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let entity = mneme_core::RecordId::from_bytes([0xa1; 16]);
    let first = mneme_core::RevisionId::from_bytes([0xa2; 16]);
    let second = mneme_core::RevisionId::from_bytes([0xa3; 16]);
    let base = workspace.current_revision().expect("base");
    workspace
        .commit(record_command(
            base,
            &scope(),
            "first",
            vec![entity_record(entity, first, None, "first")],
            Vec::new(),
            Vec::new(),
        ))
        .expect("first");
    let base = workspace.current_revision().expect("base");
    workspace
        .commit(record_command(
            base,
            &scope(),
            "second",
            vec![entity_record(entity, second, Some(first), "second")],
            Vec::new(),
            Vec::new(),
        ))
        .expect("second");
    assert!(workspace.snapshot().is_ok());
    let ledger = open_ledger(temp.path());
    let corrupted = ledger
        .execute(
            "UPDATE record_membership SET last_sequence = NULL
             WHERE record_id = ?1 AND last_sequence IS NOT NULL",
            rusqlite::params![entity.as_bytes().as_slice()],
        )
        .expect("corrupt a closed interval");
    assert_eq!(corrupted, 1, "exactly one closed interval is corrupted");
    drop(ledger);
    let error = workspace
        .snapshot()
        .expect_err("two revisions of one record");
    assert!(
        matches!(&error, mneme_store::Failure::Integrity { .. }),
        "expected an integrity failure, got {error:?}"
    );
}

fn source_record_digest(record: &mneme_core::RecordEnvelope) -> Option<mneme_core::ContentDigest> {
    let content = record.payload.get("content")?;
    let content =
        mneme_core::SourceContent::from_value(content, &mneme_core::Path::root().field("content"))
            .ok()?;
    match content {
        mneme_core::SourceContent::Retained(retained) => Some(retained.digest()),
        mneme_core::SourceContent::Unavailable { .. } => None,
    }
}

#[test]
fn a_pruned_source_allows_every_earlier_digest_to_be_purged() {
    const FIRST: &[u8] = b"= First revision\n\nBody one.\n";
    const SECOND: &[u8] = b"= Second revision\n\nBody two.\n";
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let source = mneme_core::RecordId::from_bytes([0xb1; 16]);
    let first = mneme_core::RevisionId::from_bytes([0xb2; 16]);
    let second = mneme_core::RevisionId::from_bytes([0xb3; 16]);
    let pruned = mneme_core::RevisionId::from_bytes([0xb4; 16]);
    let first_digest = mneme_core::ContentDigest::of_source_bytes(FIRST);
    let second_digest = mneme_core::ContentDigest::of_source_bytes(SECOND);
    let base = workspace.current_revision().expect("base");
    workspace
        .commit(record_command(
            base,
            &scope(),
            "seed",
            vec![retained_source_record(
                source,
                first,
                &scope(),
                FIRST,
                Some("plan.adoc"),
            )],
            vec![source_blob(FIRST)],
            Vec::new(),
        ))
        .expect("seed");
    let first_revision = workspace.current_revision().expect("first revision");
    let mut revised = retained_source_record(source, second, &scope(), SECOND, None);
    revised.predecessor = Some(first);
    let base = workspace.current_revision().expect("base");
    workspace
        .commit(record_command(
            base,
            &scope(),
            "revise",
            vec![revised],
            vec![source_blob(SECOND)],
            Vec::new(),
        ))
        .expect("revise the source");
    let base = workspace.current_revision().expect("base");
    workspace
        .commit(record_command(
            base,
            &scope(),
            "prune",
            vec![pruned_source_record(source, pruned, second, second_digest)],
            Vec::new(),
            Vec::new(),
        ))
        .expect("prune the source");
    let required = workspace
        .retention_required_digests()
        .expect("requirements");
    assert!(
        !required.contains(first_digest.as_bytes()),
        "an earlier digest of a pruned source is not required"
    );
    assert!(
        !required.contains(second_digest.as_bytes()),
        "the digest the pruned revision names is not required"
    );
    let first_location = audit_blob_location("source-blob", first_digest);
    let second_location = audit_blob_location("source-blob", second_digest);
    let operation_id = "retention-prune-source".to_owned();
    let base = workspace.current_revision().expect("base");
    workspace
        .commit(audit_barrier_command(
            base,
            "prune-locations",
            mneme_store::RetentionCommit {
                operation_id: operation_id.clone(),
                operation_kind: "prune".to_owned(),
                policy_version: "1".to_owned(),
                selectors: Vec::new(),
                suppressions: Vec::new(),
                locations: vec![first_location.clone(), second_location.clone()],
                retained_metadata: Vec::new(),
            },
        ))
        .expect("prune locations");
    for (location, digest) in [
        (&first_location, first_digest),
        (&second_location, second_digest),
    ] {
        let outcome = workspace
            .purge_retention_blob(
                &operation_id,
                &location.location_id,
                "source-blob",
                &digest.to_hex(),
            )
            .expect("purge an earlier digest");
        assert_eq!(outcome, mneme_store::BlobPurgeOutcome::Purged);
        assert!(!mneme_store::payload::blob_path(temp.path(), digest).exists());
    }
    let history = workspace
        .snapshot_at(first_revision, None)
        .expect("a pruned source's earlier revision still loads");
    let record = history
        .records
        .iter()
        .find(|record| record.record_id == source)
        .expect("the earlier revision is still visible");
    assert_eq!(record.revision_id, first);
    assert_eq!(source_record_digest(record), Some(first_digest));
    assert!(matches!(
        mneme_store::payload::read(temp.path(), first_digest),
        Err(mneme_store::Failure::MissingBlob { .. })
    ));
    let other = mneme_core::RecordId::from_bytes([0xb5; 16]);
    let other_revision = mneme_core::RevisionId::from_bytes([0xb6; 16]);
    let base = workspace.current_revision().expect("base");
    workspace
        .commit(record_command(
            base,
            &scope(),
            "other",
            vec![retained_source_record(
                other,
                other_revision,
                &scope(),
                FIRST,
                Some("other.adoc"),
            )],
            vec![source_blob(FIRST)],
            Vec::new(),
        ))
        .expect("another source binds the same bytes");
    let required = workspace
        .retention_required_digests()
        .expect("requirements");
    assert!(
        required.contains(first_digest.as_bytes()),
        "a different live source keeps the digest required"
    );
    let outcome = workspace
        .purge_retention_blob(
            &operation_id,
            &first_location.location_id,
            "source-blob",
            &first_digest.to_hex(),
        )
        .expect("purge a shared digest");
    assert_eq!(outcome, mneme_store::BlobPurgeOutcome::RetainedShared);
    assert!(mneme_store::payload::blob_path(temp.path(), first_digest).exists());
}

#[cfg(unix)]
#[test]
fn an_untouched_payload_is_served_from_the_cache_without_a_content_read() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    workspace
        .commit(fixture_command(genesis, "first"))
        .expect("first");
    let first = workspace.snapshot().expect("first snapshot");
    let entity = first
        .records
        .iter()
        .find(|record| record.record_id == mneme_core::fixtures::entity_id())
        .expect("entity");
    let path = mneme_store::payload::blob_path(temp.path(), entity.full_digest());
    // Deny reads without touching the identity the cache validates: a hit needs
    // no content read, so this handle still serves the verified envelope while any
    // reader must fail. The suite runs as the unprivileged owner of the tempdir.
    let permissions = std::fs::metadata(&path).expect("metadata").permissions();
    let mut denied = permissions.clone();
    denied.set_mode(0o000);
    std::fs::set_permissions(&path, denied).expect("deny reads");

    let second = workspace
        .snapshot()
        .expect("the verified decode is served without reading the blob");
    assert_eq!(snapshot_identities(&second), snapshot_identities(&first));

    // A handle that has not decoded the record must read it and fails closed.
    assert!(matches!(
        open(temp.path(), 2_500)
            .snapshot()
            .expect_err("unreadable payload"),
        mneme_store::Failure::Integrity { .. }
    ));
    // Recovery re-reads from disk even though this handle holds a valid hit.
    assert!(matches!(
        workspace.recover().expect_err("unreadable payload"),
        mneme_store::Failure::Integrity { .. }
    ));
    std::fs::set_permissions(&path, permissions).expect("restore permissions");
}

#[test]
fn a_forget_that_purges_a_record_blob_stops_the_handle_serving_it() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    workspace
        .commit(fixture_command(genesis, "first"))
        .expect("first");
    let pinned = workspace.snapshot().expect("pinned");
    let assertion = pinned
        .records
        .iter()
        .find(|record| record.record_id == mneme_core::fixtures::assertion_id())
        .expect("assertion");
    let digest = assertion.full_digest();
    let generation = workspace.eligibility_generation().expect("generation");
    let location = audit_blob_location("record-blob", digest);
    let base = workspace.current_revision().expect("base");
    workspace
        .commit(mneme_store::CommitCommand {
            base,
            actor: "test-author".to_owned(),
            scope: scope(),
            idempotency_key: "forget-record".to_owned(),
            records: Vec::new(),
            source_blobs: Vec::new(),
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: Some(mneme_store::RetentionCommit {
                operation_id: "forget-record".to_owned(),
                operation_kind: "forget".to_owned(),
                policy_version: "1".to_owned(),
                selectors: Vec::new(),
                suppressions: vec![mneme_store::RetentionSuppression {
                    operation_id: "forget-record".to_owned(),
                    target: mneme_core::fixtures::assertion_id(),
                    revision: None,
                    target_kind: "assertion".to_owned(),
                    mode: mneme_store::SuppressionMode::Forgotten,
                    content_digest: None,
                    generation: generation.saturating_add(1),
                }],
                locations: vec![location.clone()],
                retained_metadata: Vec::new(),
            }),
        })
        .expect("forget the assertion");
    let outcome = workspace
        .purge_retention_blob(
            "forget-record",
            &location.location_id,
            "record-blob",
            &digest.to_hex(),
        )
        .expect("purge the forgotten record's payload");
    assert_eq!(outcome, mneme_store::BlobPurgeOutcome::Purged);
    // The same handle must not serve the decoded envelope after the erasure.
    let after = workspace.snapshot().expect("snapshot after the forget");
    assert!(
        after
            .records
            .iter()
            .all(|record| record.record_id != mneme_core::fixtures::assertion_id()),
        "a forgotten record leaves every later snapshot"
    );
    assert!(matches!(
        workspace.record_revisions(mneme_core::fixtures::assertion_id()),
        Err(mneme_store::Failure::RetentionSuppressed { .. })
    ));
}

// Audit remediation regressions: the shared verified-fact cache, verified
// retained-source identities, one read transaction per snapshot load, and the
// write path that must stay available after a failed read.

fn open_shared(
    root: &std::path::Path,
    at: i64,
    cache: &mneme_store::SharedRecordCache,
) -> mneme_store::Workspace {
    mneme_store::Workspace::open_with_cache(root, config(at), cache.clone())
        .expect("open a workspace sharing verified facts")
}

/// One workspace with the fixture batch committed, created and closed privately.
fn committed_root(root: &std::path::Path) {
    let mut creator = mneme_store::Workspace::create(root, config(1_000)).expect("create");
    let genesis = creator.current_revision().expect("genesis");
    creator
        .commit(fixture_command(genesis, "first"))
        .expect("first commit");
    drop(creator);
}

/// A forget plan that erases one record identity and advances the generation.
fn forget_identity_barrier(
    target: mneme_core::RecordId,
    target_kind: &str,
    generation: u64,
) -> mneme_store::RetentionCommit {
    mneme_store::RetentionCommit {
        operation_id: "forget-shared".to_owned(),
        operation_kind: "forget".to_owned(),
        policy_version: "1".to_owned(),
        selectors: Vec::new(),
        suppressions: vec![mneme_store::RetentionSuppression {
            operation_id: "forget-shared".to_owned(),
            target,
            revision: None,
            target_kind: target_kind.to_owned(),
            mode: mneme_store::SuppressionMode::Forgotten,
            content_digest: None,
            generation,
        }],
        locations: Vec::new(),
        retained_metadata: Vec::new(),
    }
}

#[cfg(unix)]
#[test]
fn a_shared_cache_serves_a_second_handle_without_a_content_read() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("temp");
    let cache = mneme_store::SharedRecordCache::new();
    committed_root(temp.path());
    let first = open_shared(temp.path(), 1_500, &cache);
    let snapshot = first.snapshot().expect("first snapshot");
    let entity = snapshot
        .records
        .iter()
        .find(|record| record.record_id == mneme_core::fixtures::entity_id())
        .expect("entity");
    let path = mneme_store::payload::blob_path(temp.path(), entity.full_digest());
    // Deny reads without touching the identity the shared facts validated: a
    // fact needs no content read, so the second handle still serves it while any
    // handle that must read the bytes fails.
    let permissions = std::fs::metadata(&path).expect("metadata").permissions();
    let mut denied = permissions.clone();
    denied.set_mode(0o000);
    std::fs::set_permissions(&path, denied).expect("deny reads");

    let second = open_shared(temp.path(), 2_000, &cache);
    let served = second
        .snapshot()
        .expect("a fact the first handle verified needs no content read");
    assert_eq!(snapshot_identities(&served), snapshot_identities(&snapshot));

    // A handle with its own cache has verified nothing and must read the blob.
    assert!(matches!(
        open(temp.path(), 2_500)
            .snapshot()
            .expect_err("unreadable payload"),
        mneme_store::Failure::Integrity { .. }
    ));
    std::fs::set_permissions(&path, permissions).expect("restore permissions");
}

#[test]
fn a_shared_cache_detects_a_removed_and_a_rewritten_record_blob() {
    let temp = tempfile::tempdir().expect("temp");
    let cache = mneme_store::SharedRecordCache::new();
    committed_root(temp.path());
    let first = open_shared(temp.path(), 1_500, &cache);
    let second = open_shared(temp.path(), 2_000, &cache);
    let snapshot = first.snapshot().expect("snapshot");
    let assertion = snapshot
        .records
        .iter()
        .find(|record| record.record_id == mneme_core::fixtures::assertion_id())
        .expect("assertion");
    let path = mneme_store::payload::blob_path(temp.path(), assertion.full_digest());
    let length =
        usize::try_from(std::fs::metadata(&path).expect("metadata").len()).expect("length");

    // A removed payload is an integrity failure on every handle that shares the
    // fact, whatever order they read in.
    std::fs::remove_file(&path).expect("remove the committed blob");
    assert!(matches!(
        second.snapshot().expect_err("removed payload"),
        mneme_store::Failure::Integrity { .. }
    ));
    assert!(matches!(
        first.snapshot().expect_err("removed payload"),
        mneme_store::Failure::Integrity { .. }
    ));

    // A rewritten payload has a different identity, so every handle re-reads it
    // and fails its digest check.
    std::fs::write(&path, vec![0x5a_u8; length]).expect("tamper");
    let tampered = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("tampered blob");
    tampered
        .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(60))
        .expect("modification time");
    drop(tampered);
    assert!(matches!(
        second.snapshot().expect_err("rewritten payload"),
        mneme_store::Failure::Integrity { .. }
    ));
    assert!(matches!(
        first.snapshot().expect_err("rewritten payload"),
        mneme_store::Failure::Integrity { .. }
    ));
}

#[test]
fn a_shared_cache_refuses_a_second_workspace() {
    let one = tempfile::tempdir().expect("temp");
    let two = tempfile::tempdir().expect("temp");
    let cache = mneme_store::SharedRecordCache::new();
    drop(mneme_store::Workspace::create(one.path(), config(1_000)).expect("create one"));
    drop(mneme_store::Workspace::create(two.path(), config(1_000)).expect("create two"));

    let bound = open_shared(one.path(), 1_500, &cache);
    assert_eq!(
        bound.genesis_revision().expect("genesis"),
        mneme_store::Workspace::open(one.path(), config(1_500))
            .expect("open")
            .genesis_revision()
            .expect("genesis")
    );
    // A cache bound by genesis revision refuses another workspace, opens nothing,
    // and still serves the workspace it is bound to.
    assert!(matches!(
        mneme_store::Workspace::open_with_cache(two.path(), config(1_500), cache.clone()),
        Err(mneme_store::Failure::InvalidCommand(_))
    ));
    drop(open_shared(one.path(), 1_500, &cache));
}

#[test]
fn a_forget_through_one_handle_stops_the_other_serving_a_shared_fact() {
    let temp = tempfile::tempdir().expect("temp");
    let cache = mneme_store::SharedRecordCache::new();
    committed_root(temp.path());
    let reader = open_shared(temp.path(), 1_500, &cache);
    let mut forgetter = open_shared(temp.path(), 2_000, &cache);
    let pinned = reader.snapshot().expect("pinned snapshot");
    assert!(
        pinned
            .records
            .iter()
            .any(|record| record.record_id == mneme_core::fixtures::assertion_id()),
        "the shared fact serves the assertion before the forget"
    );

    let generation = forgetter.eligibility_generation().expect("generation");
    let base = forgetter.current_revision().expect("base");
    forgetter
        .commit(audit_barrier_command(
            base,
            "forget-shared",
            forget_identity_barrier(
                mneme_core::fixtures::assertion_id(),
                "assertion",
                generation.saturating_add(1),
            ),
        ))
        .expect("forget the assertion");

    // The barrier drops every fact the second handle shares, so the reader cannot
    // serve the erased record from the cache either.
    let after = reader.snapshot().expect("snapshot after the forget");
    assert!(
        after
            .records
            .iter()
            .all(|record| record.record_id != mneme_core::fixtures::assertion_id())
    );
    assert!(matches!(
        reader.record_revisions(mneme_core::fixtures::assertion_id()),
        Err(mneme_store::Failure::RetentionSuppressed { .. })
    ));
}

#[cfg(unix)]
#[test]
fn a_verified_source_is_served_from_its_identity_without_a_content_read() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    workspace
        .commit(fixture_command(genesis, "first"))
        .expect("first");
    let source =
        mneme_core::ContentDigest::of_source_bytes(mneme_core::fixtures::SOURCE_TEXT.as_bytes());
    let path = mneme_store::payload::blob_path(temp.path(), source);
    let first = workspace.snapshot().expect("first snapshot");
    let permissions = std::fs::metadata(&path).expect("metadata").permissions();
    let mut denied = permissions.clone();
    denied.set_mode(0o000);
    std::fs::set_permissions(&path, denied).expect("deny reads");

    // The verified identity replaces the content read of an unchanged source.
    let second = workspace
        .snapshot()
        .expect("an unchanged verified source is not read again");
    assert_eq!(snapshot_identities(&second), snapshot_identities(&first));
    // A handle that has not verified the source reads and hashes it.
    assert!(matches!(
        open(temp.path(), 2_000)
            .snapshot()
            .expect_err("unreadable source"),
        mneme_store::Failure::Integrity { .. }
    ));
    std::fs::set_permissions(&path, permissions).expect("restore permissions");

    // A rewritten source has a different identity, so it is read and fails.
    let length =
        usize::try_from(std::fs::metadata(&path).expect("metadata").len()).expect("length");
    std::fs::write(&path, vec![0x5a_u8; length]).expect("tamper");
    let tampered = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("tampered source");
    tampered
        .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(60))
        .expect("modification time");
    drop(tampered);
    assert!(matches!(
        workspace.snapshot().expect_err("rewritten source"),
        mneme_store::Failure::Integrity { .. }
    ));
    // A read that returns the bytes still hashes exactly what it returns.
    assert!(matches!(
        mneme_store::payload::read(temp.path(), source),
        Err(mneme_store::Failure::CorruptBlob { .. })
    ));

    // A deleted source fails too.
    std::fs::remove_file(&path).expect("remove the source");
    assert!(matches!(
        workspace.snapshot().expect_err("deleted source"),
        mneme_store::Failure::Integrity { .. }
    ));
}

#[test]
fn a_failed_history_read_leaves_the_handle_writable() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    workspace
        .commit(fixture_command(genesis, "first"))
        .expect("first");
    let generation = workspace.eligibility_generation().expect("generation");
    let base = workspace.current_revision().expect("base");
    workspace
        .commit(audit_barrier_command(
            base,
            "forget-shared",
            forget_identity_barrier(
                mneme_core::fixtures::assertion_id(),
                "assertion",
                generation.saturating_add(1),
            ),
        ))
        .expect("forget the assertion");

    // The history read fails inside its own read transaction.
    assert!(matches!(
        workspace.record_revisions(mneme_core::fixtures::assertion_id()),
        Err(mneme_store::Failure::RetentionSuppressed { .. })
    ));
    // A write on the same handle still succeeds: no read transaction was left
    // open by the failed read.
    let base = workspace.current_revision().expect("base");
    workspace
        .commit(publication_command(
            base,
            &scope(),
            "after-failed-read",
            "after-failed-read.adoc",
            b"committed after a failed read",
        ))
        .expect("a commit after a failed read");
    assert_eq!(workspace.current_sequence().expect("sequence"), 3);
}

// Audit remediation: the set-based history and revision-sequence reads, and the
// streaming blob walk recovery sweeps with.

const PRUNED_ALPHA: &[u8] = b"= Alpha\n\nFirst revision body.\n";
const PRUNED_BETA: &[u8] = b"= Alpha\n\nSecond revision body.\n";

/// The fixed record and revision identities a pruned-history fixture uses.
struct PrunedHistoryIds {
    entity: mneme_core::RecordId,
    kept: mneme_core::RecordId,
    source: mneme_core::RecordId,
    forgotten: mneme_core::RecordId,
    entity_first: mneme_core::RevisionId,
    entity_second: mneme_core::RevisionId,
    kept_first: mneme_core::RevisionId,
    source_first: mneme_core::RevisionId,
    source_second: mneme_core::RevisionId,
    source_pruned: mneme_core::RevisionId,
    forgotten_first: mneme_core::RevisionId,
}

impl PrunedHistoryIds {
    fn fixed() -> Self {
        PrunedHistoryIds {
            entity: record_identity(&[0x51; 16]),
            kept: record_identity(&[0x52; 16]),
            source: record_identity(&[0x53; 16]),
            forgotten: record_identity(&[0x54; 16]),
            entity_first: record_revision(&[0x61; 16]),
            entity_second: record_revision(&[0x62; 16]),
            kept_first: record_revision(&[0x63; 16]),
            source_first: record_revision(&[0x64; 16]),
            source_second: record_revision(&[0x65; 16]),
            source_pruned: record_revision(&[0x66; 16]),
            forgotten_first: record_revision(&[0x67; 16]),
        }
    }
}

/// A workspace with several revisions per record, one forgotten revision of a
/// live record and one forgotten identity, plus its head and an older snapshot.
struct PrunedHistory {
    workspace: mneme_store::Workspace,
    head: mneme_store::Snapshot,
    older: mneme_store::Snapshot,
    ids: PrunedHistoryIds,
}

fn build_pruned_history(root: &std::path::Path) -> PrunedHistory {
    let ids = PrunedHistoryIds::fixed();
    let mut workspace = mneme_store::Workspace::create(root, config(1_000)).expect("create");
    seed_pruned_history(&mut workspace, &ids);
    revise_pruned_entity(&mut workspace, &ids);
    // This revision still holds the source's first revision, so the pinned older
    // read must answer from that membership and not the head.
    let older_revision = workspace.current_revision().expect("older revision");
    revise_and_prune_source(&mut workspace, &ids);
    forget_history_entries(&mut workspace, &ids);
    let older = workspace
        .snapshot_at(older_revision, None)
        .expect("older snapshot");
    let head = workspace.snapshot().expect("head snapshot");
    PrunedHistory {
        workspace,
        head,
        older,
        ids,
    }
}

/// Commit the seed revision: two entities, one retained source and the record a
/// later barrier forgets as a whole.
fn seed_pruned_history(workspace: &mut mneme_store::Workspace, ids: &PrunedHistoryIds) {
    let base = workspace.current_revision().expect("base");
    workspace
        .commit(record_command(
            base,
            &scope(),
            "seed",
            vec![
                entity_record(ids.entity, ids.entity_first, None, "Alpha"),
                entity_record(ids.kept, ids.kept_first, None, "Kept"),
                retained_source_record(
                    ids.source,
                    ids.source_first,
                    &scope(),
                    PRUNED_ALPHA,
                    Some("alpha.adoc"),
                ),
                entity_record(ids.forgotten, ids.forgotten_first, None, "Forgotten"),
            ],
            vec![source_blob(PRUNED_ALPHA)],
            Vec::new(),
        ))
        .expect("seed");
}

/// Revise the entity once, so the head snapshot serves its second revision.
fn revise_pruned_entity(workspace: &mut mneme_store::Workspace, ids: &PrunedHistoryIds) {
    let base = workspace.current_revision().expect("base");
    workspace
        .commit(record_command(
            base,
            &scope(),
            "revise-entity",
            vec![entity_record(
                ids.entity,
                ids.entity_second,
                Some(ids.entity_first),
                "Alpha revised",
            )],
            Vec::new(),
            Vec::new(),
        ))
        .expect("revise the entity");
}

/// Revise the source once and then record a pruned revision of it.
fn revise_and_prune_source(workspace: &mut mneme_store::Workspace, ids: &PrunedHistoryIds) {
    let mut second =
        retained_source_record(ids.source, ids.source_second, &scope(), PRUNED_BETA, None);
    second.predecessor = Some(ids.source_first);
    let base = workspace.current_revision().expect("base");
    workspace
        .commit(record_command(
            base,
            &scope(),
            "revise-source",
            vec![second],
            vec![source_blob(PRUNED_BETA)],
            Vec::new(),
        ))
        .expect("revise the source");
    let base = workspace.current_revision().expect("base");
    workspace
        .commit(record_command(
            base,
            &scope(),
            "prune-source",
            vec![pruned_source_record(
                ids.source,
                ids.source_pruned,
                ids.source_second,
                mneme_core::ContentDigest::of_source_bytes(PRUNED_BETA),
            )],
            Vec::new(),
            Vec::new(),
        ))
        .expect("prune the source");
}

/// Forget one revision of the live source and one whole record identity.
fn forget_history_entries(workspace: &mut mneme_store::Workspace, ids: &PrunedHistoryIds) {
    let generation = workspace
        .eligibility_generation()
        .expect("generation")
        .saturating_add(1);
    let operation_id = "forget-history".to_owned();
    let base = workspace.current_revision().expect("base");
    workspace
        .commit(audit_barrier_command(
            base,
            "forget-history",
            mneme_store::RetentionCommit {
                operation_id: operation_id.clone(),
                operation_kind: "forget".to_owned(),
                policy_version: "1".to_owned(),
                selectors: Vec::new(),
                suppressions: vec![
                    mneme_store::RetentionSuppression {
                        operation_id: operation_id.clone(),
                        target: ids.source,
                        revision: Some(ids.source_second),
                        target_kind: "source-revision".to_owned(),
                        mode: mneme_store::SuppressionMode::Forgotten,
                        content_digest: None,
                        generation,
                    },
                    mneme_store::RetentionSuppression {
                        operation_id,
                        target: ids.forgotten,
                        revision: None,
                        target_kind: "entity".to_owned(),
                        mode: mneme_store::SuppressionMode::Forgotten,
                        content_digest: None,
                        generation,
                    },
                ],
                locations: Vec::new(),
                retained_metadata: Vec::new(),
            },
        ))
        .expect("forget the history entries");
}

/// The history map one read per snapshot record produces.
fn expected_histories(
    workspace: &mneme_store::Workspace,
    snapshot: &mneme_store::Snapshot,
) -> std::collections::BTreeMap<mneme_core::RecordId, Vec<mneme_core::RecordEnvelope>> {
    snapshot
        .records
        .iter()
        .map(|record| {
            let history = workspace
                .record_revisions(record.record_id)
                .expect("record history");
            (record.record_id, history)
        })
        .collect()
}

/// The revision identities a history serves, in recorded order.
fn history_revisions(history: &[mneme_core::RecordEnvelope]) -> Vec<mneme_core::RevisionId> {
    history
        .iter()
        .map(|record| record.revision_id)
        .collect::<Vec<_>>()
}

#[test]
fn record_histories_matches_record_revisions_for_every_snapshot_record() {
    let temp = tempfile::tempdir().expect("temp");
    let history = build_pruned_history(temp.path());
    for snapshot in [&history.older, &history.head] {
        let histories = history
            .workspace
            .record_histories(snapshot)
            .expect("histories");
        assert_eq!(
            histories,
            expected_histories(&history.workspace, snapshot),
            "each list is exactly what record_revisions returns for that record"
        );
        assert!(
            histories
                .keys()
                .all(|record| *record != history.ids.forgotten),
            "a forgotten identity is never served by a history read"
        );
    }
    let head = history
        .workspace
        .record_histories(&history.head)
        .expect("histories");
    assert_eq!(
        head.len(),
        3,
        "the head snapshot holds the three live records"
    );
    assert_eq!(
        history_revisions(head.get(&history.ids.entity).expect("entity history")),
        vec![history.ids.entity_first, history.ids.entity_second],
        "a revised record keeps every revision in recorded order"
    );
    assert_eq!(
        history_revisions(head.get(&history.ids.source).expect("source history")),
        vec![history.ids.source_first, history.ids.source_pruned],
        "the forgotten revision is skipped and the pruned revision is retained"
    );
    let older = history
        .workspace
        .record_histories(&history.older)
        .expect("histories");
    assert_eq!(
        history_revisions(older.get(&history.ids.source).expect("source history")),
        vec![history.ids.source_first, history.ids.source_pruned],
        "an older snapshot reads the same retained history"
    );
}

#[cfg(unix)]
#[test]
fn record_histories_serves_verified_blobs_without_a_content_read() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("temp");
    let history = build_pruned_history(temp.path());
    let warmed = history
        .workspace
        .record_histories(&history.head)
        .expect("histories");
    // The entity's first revision is superseded in the head snapshot, so only the
    // history read has verified its blob.
    let superseded = warmed
        .get(&history.ids.entity)
        .expect("entity history")
        .first()
        .expect("first revision");
    let path = mneme_store::payload::blob_path(temp.path(), superseded.full_digest());
    let permissions = std::fs::metadata(&path).expect("metadata").permissions();
    let mut denied = permissions.clone();
    denied.set_mode(0o000);
    std::fs::set_permissions(&path, denied).expect("deny reads");

    // Denying reads without touching identity: a verified history needs no read.
    let served = history
        .workspace
        .record_histories(&history.head)
        .expect("a verified history needs no content read");
    assert_eq!(served, warmed);
    // A handle that has verified nothing must read the revision and fails closed.
    assert!(matches!(
        open(temp.path(), 2_500)
            .record_histories(&history.head)
            .expect_err("unreadable history"),
        mneme_store::Failure::Integrity { .. }
    ));
    std::fs::set_permissions(&path, permissions).expect("restore permissions");

    // A deleted revision blob is an integrity failure even on the warm handle.
    std::fs::remove_file(&path).expect("remove the superseded revision blob");
    assert!(matches!(
        history
            .workspace
            .record_histories(&history.head)
            .expect_err("deleted revision"),
        mneme_store::Failure::Integrity { .. }
    ));
    // The snapshot itself still loads: only the superseded blob is gone.
    assert!(
        history
            .workspace
            .snapshot_at(history.head.revision, None)
            .is_ok()
    );
}

#[test]
fn revision_sequences_for_reads_only_the_named_revisions() {
    let temp = tempfile::tempdir().expect("temp");
    let history = build_copied_membership_history(temp.path());
    let all = history.workspace.revision_sequences().expect("sequences");
    let named = all
        .keys()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        history
            .workspace
            .revision_sequences_for(&named)
            .expect("sequences"),
        all,
        "naming every committed revision answers the same inventory"
    );

    let subset = history
        .revisions
        .iter()
        .copied()
        .take(2)
        .collect::<std::collections::BTreeSet<_>>();
    let expected = all
        .iter()
        .filter(|(revision, _)| subset.contains(*revision))
        .map(|(revision, sequence)| (*revision, *sequence))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        history
            .workspace
            .revision_sequences_for(&subset)
            .expect("sequences"),
        expected,
        "a named subset answers exactly those sequences"
    );

    // An uncommitted revision is absent, never an error.
    let mut with_unknown = subset;
    with_unknown.insert(workspace_identity(&[0x7e; 16]));
    assert_eq!(
        history
            .workspace
            .revision_sequences_for(&with_unknown)
            .expect("sequences"),
        expected,
        "an unknown revision is omitted"
    );
    assert!(
        history
            .workspace
            .revision_sequences_for(&std::collections::BTreeSet::new())
            .expect("sequences")
            .is_empty(),
        "an empty set reads nothing"
    );
}

#[test]
fn revision_at_sequence_answers_every_committed_sequence() {
    let temp = tempfile::tempdir().expect("temp");
    let history = build_copied_membership_history(temp.path());
    let all = history.workspace.revision_sequences().expect("sequences");
    for (revision, sequence) in &all {
        assert_eq!(
            history
                .workspace
                .revision_at_sequence(*sequence)
                .expect("revision"),
            Some(*revision),
            "sequence {sequence} names its committed revision"
        );
    }
    let head = history.workspace.current_sequence().expect("sequence");
    assert_eq!(
        history
            .workspace
            .revision_at_sequence(head)
            .expect("head revision"),
        Some(history.workspace.current_revision().expect("current"))
    );
    assert_eq!(
        history
            .workspace
            .revision_at_sequence(head.saturating_add(1))
            .expect("past the head"),
        None
    );
}

/// Write one orphan blob file into `shard` and return its path.
///
/// The file name is a real digest, so the walk treats it as a blob file; the
/// shard directory is chosen by the caller, which is how the test shows that the
/// walk enters more than one shard.
fn orphan_blob_in(shard: &std::path::Path, tag: u8) -> std::path::PathBuf {
    let bytes = [b'o', b'r', b'p', b'h', b'a', b'n', tag];
    let digest = mneme_core::ContentDigest::of_source_bytes(&bytes);
    let path = shard.join(digest.to_hex());
    std::fs::create_dir_all(shard).expect("shard directory");
    std::fs::write(&path, b"orphan bytes").expect("orphan blob");
    path
}

#[test]
fn recovery_sweeps_orphan_blobs_through_a_streaming_walk() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config(1_000)).expect("create");
    let genesis = workspace.current_revision().expect("genesis");
    workspace
        .commit(fixture_command(genesis, "first"))
        .expect("first");
    let snapshot = workspace.snapshot().expect("snapshot");
    let retained = snapshot.records.first().expect("retained record");
    let retained_path = mneme_store::payload::blob_path(temp.path(), retained.full_digest());
    let retained_shard = retained_path.parent().expect("shard").to_path_buf();
    let algorithm = retained_shard.parent().expect("algorithm").to_path_buf();
    let blob_root = algorithm.parent().expect("blob root").to_path_buf();

    // One orphan sits among the retained files of the shard a ledger blob uses;
    // another sits in a shard no retained blob occupies. Both directory levels
    // must be walked for the sweep to see them.
    let beside = orphan_blob_in(&retained_shard, 0x11);
    let elsewhere = orphan_blob_in(&algorithm.join("zz"), 0x22);
    // An entry that is not a directory at either level, and a name that is not a
    // digest, are skipped instead of failing the walk.
    let stray_digest = mneme_core::ContentDigest::of_source_bytes(b"not a shard");
    let digest_name = stray_digest.to_hex();
    let not_a_shard = algorithm.join(&digest_name);
    std::fs::write(&not_a_shard, b"not a shard").expect("entry at the shard level");
    let not_an_algorithm = blob_root.join(&digest_name);
    std::fs::write(&not_an_algorithm, b"not an algorithm").expect("entry at the algorithm level");
    let not_a_digest = retained_shard.join("not-a-blob-digest");
    std::fs::write(&not_a_digest, b"not a digest").expect("entry with an unparsable name");

    let report = workspace.recover().expect("recovery");
    assert_eq!(
        report.orphan_blobs_removed, 2,
        "both orphans are swept: {report:?}"
    );
    assert!(
        !beside.exists(),
        "the orphan beside a retained blob is swept"
    );
    assert!(!elsewhere.exists(), "the orphan in another shard is swept");
    assert!(
        retained_path.exists(),
        "a blob the ledger names is retained"
    );
    assert!(not_a_shard.exists(), "a file is not a shard directory");
    assert!(
        not_an_algorithm.exists(),
        "a file is not an algorithm directory"
    );
    assert!(
        not_a_digest.exists(),
        "a name that is not a digest is not a blob file"
    );
}
