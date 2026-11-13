//! The durable workspace coordinator.
//!
//! One process serializes mutations through [`Workspace::commit`]. Each commit
//! stages immutable blobs, validates a complete record batch against the current
//! snapshot, checks the caller's base revision, records the manifest identity,
//! the membership it changes, command outcome, and publication intents in one
//! SQLite transaction, then publishes working files as a separately recoverable
//! step. A committed revision never references a missing required blob;
//! filesystem publication never overwrites a divergent external edit.
//!
//! Commits and recovery also exclude each other with an advisory lock on
//! [`LOCK_FILE`], because a staged blob has no ledger row until the transaction
//! commits: the commit holds a shared lock from staging to its transaction, and
//! a sweep holds an exclusive lock while it deletes unreferenced files.
//!
//! A handle remembers the record envelopes it verified, so a snapshot or a
//! commit on the same handle reads only the payloads it has never decoded. A hit
//! is served only while the blob file still has the length, modification time,
//! device and inode recorded when the bytes were verified, so a removed payload
//! fails as an integrity error and a rewritten one is re-read and fails its
//! digest check. The residual limit is in-place corruption that preserves both
//! length and modification time: the warm cache keeps serving the bytes it
//! verified, and only a handle that has not read the record, or recovery, sees
//! that corruption.
//!
//! A handle opened with [`Workspace::open_with_cache`] reads and records these
//! facts in a [`SharedRecordCache`] instead of in its own cache, so every handle
//! one process opens on one workspace verifies a payload once. The shared cache
//! is bound to the first workspace that uses it, by that ledger's genesis
//! revision rather than by a path; it holds the same number of entries and bytes
//! as a private cache, and it drops every fact when the erasure generation
//! advances, so no handle serves material read under an older generation.
//!
//! The same cache also remembers, per retained source content digest, the file
//! identity whose bytes were verified; no source bytes are kept. One metadata
//! call then replaces the content read and hash of a source this handle already
//! verified, and the digest is verified from disk again whenever the file
//! identity or the ledger's recorded length differs. Its residual limit is the
//! one the record cache states: an in-place rewrite that preserves both length
//! and modification time is not detected by the verified fact, so only a handle
//! that has not verified that source, and [`Workspace::recover`], report it. Any
//! read that returns source bytes still hashes exactly the bytes it returns.

// Octet structural exception: domain-qualified names and macro-only imports are intentional
use rusqlite::OptionalExtension;

use crate::timekeeper::Clock;

use crate::injectors::FaultInjector;

mod commit;
mod history;
mod publishing;
mod recovery;
mod sweep;
#[cfg(test)]
mod tests;
mod validation;

/// The ledger file name inside a workspace root.
pub const LEDGER_FILE: &str = "ledger.sqlite3";

/// The advisory lock file name inside a workspace root.
///
/// The file holds no data; it is store-owned state that exists only so a commit
/// and a recovery sweep can exclude each other across processes. It is never an
/// orphan payload and never an unregistered payload entry.
pub const LOCK_FILE: &str = "workspace.lock";

/// The supported on-disk layout version.
pub const LAYOUT_VERSION: i64 = 1;

const META_CURRENT_REVISION: &str = "current_revision";

const META_CURRENT_SEQUENCE: &str = "current_sequence";

const META_GENERATION: &str = "eligibility_generation";

const META_LAYOUT: &str = "layout_version";

const META_RETENTION_FORMAT: &str = "retention_format";

/// Durable marker for the ledger's snapshot-membership representation.
///
/// A ledger without it stores one membership row per revision, which grows with
/// the product of revisions and records; [`migrate_membership_format`] rewrites
/// such a ledger in place and writes this marker last.
const META_MEMBERSHIP_FORMAT: &str = "membership_format";

/// Durable marker written by [`Workspace::open_restored`].
///
/// It lives in the ledger rather than in a handle, so a process that restarts
/// between the restore and the ledger application still refuses to serve.
const META_RESTORE_PENDING: &str = "restore_pending";

type BlobRecord = (
    mneme_core::ContentDigest,
    u64,
    mneme_core::EncodingProfile,
    mneme_core::ValueBoundary,
);

type BlobIndex = std::collections::BTreeMap<[u8; 32], BlobRecord>;

/// One record revision's membership row joined with its record facts.
type MembershipEntry = (Vec<u8>, Vec<u8>, String, Vec<u8>, Vec<u8>, Vec<u8>);

/// How a snapshot load treats the payload blobs it reads.
///
/// A read must fail closed on corrupted bytes, so a miss re-hashes the payload
/// before anything is decoded. A handle's decode cache is keyed by the
/// content-addressed envelope digest the ledger records, so a hit is the value
/// the ledger names; one metadata call confirms the blob still has the identity
/// it had when it was verified, and recovery deliberately ignores the cache.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PayloadCheck {
    /// Reuse this handle's verified decode cache, hashing on a miss.
    Cached,
    /// Re-hash every payload from disk and neither read nor fill the cache.
    FromDisk,
    /// Require presence and the recorded length only; the commit path re-hashes
    /// every blob it stages and checks inherited ones for presence and length.
    Presence,
}

impl PayloadCheck {
    /// Whether this mode may serve and remember decoded payloads.
    const fn caches(self) -> bool {
        !matches!(self, PayloadCheck::FromDisk)
    }

    /// Whether this mode needs each blob's recorded length from the ledger
    /// instead of hashing the bytes it reads.
    const fn needs_ledger_lengths(self) -> bool {
        matches!(self, PayloadCheck::Presence)
    }
}

/// Most verified record envelopes one handle keeps decoded.
///
/// A hit avoids opening, reading and hashing one blob file per record of a
/// snapshot, which is the dominant cost of a commit or a read on a workspace
/// with many retained records. The bound keeps a handle that has read a large
/// history from pinning every payload it ever decoded.
const MAX_CACHED_RECORDS: usize = 262_144;

/// Largest total encoded size of the record envelopes one handle keeps.
const MAX_CACHED_RECORD_BYTES: usize = 64 * 1024 * 1024;

/// The on-disk identity of one verified blob file.
///
/// A content-addressed path can be rewritten or removed behind a running
/// handle, so a decoded envelope is only served while the file at that path is
/// still the file the bytes were verified from. These facts come from one
/// `symlink_metadata` call, never from reading content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    byte_length: u64,
    modified: std::time::SystemTime,
    device: u64,
    inode: u64,
}

/// The identity of the blob file at a digest's path, when it is a regular file.
///
/// A missing file, or one that is no longer a regular file, yields `None`; the
/// caller then drops any cached entry and re-reads, which reports the absent
/// payload as an integrity failure.
fn blob_file_identity(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
) -> Option<FileIdentity> {
    let metadata = std::fs::symlink_metadata(crate::payload::blob_path(root, digest)).ok()?;
    if !metadata.is_file() {
        return None;
    }
    let modified = metadata.modified().ok()?;
    let (device, inode) = metadata_device_and_inode(&metadata);
    Some(FileIdentity {
        byte_length: metadata.len(),
        modified,
        device,
        inode,
    })
}

#[cfg(unix)]
fn metadata_device_and_inode(metadata: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (metadata.dev(), metadata.ino())
}

#[cfg(not(unix))]
fn metadata_device_and_inode(_metadata: &std::fs::Metadata) -> (u64, u64) {
    // Length and modification time still catch a rewrite on other platforms.
    (0, 0)
}

/// The identity a cache entry may record for one verified read.
///
/// The file must have been the same regular file before and after the read and
/// must still have the length that was verified; otherwise nothing is cached and
/// the next read verifies from disk again.
fn stable_blob_identity(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
    before: Option<FileIdentity>,
    encoded_bytes: usize,
) -> Option<FileIdentity> {
    let after = blob_file_identity(root, digest)?;
    if before != Some(after) || u64::try_from(encoded_bytes).ok() != Some(after.byte_length) {
        return None;
    }
    Some(after)
}

/// One verified, decoded record envelope and the ledger facts it was checked
/// against.
struct CachedRecord {
    record: mneme_core::RecordEnvelope,
    payload_digest: mneme_core::ContentDigest,
    encoded_bytes: usize,
    /// The file identity the bytes had when this entry was verified.
    file: FileIdentity,
    /// Insertion ticket: the largest ticket is the newest fact.
    ticket: u64,
}

/// One verified retained-source blob.
///
/// No bytes are kept: a source fact only says that the file at the digest's
/// path had this identity when its bytes were hashed against the ledger's
/// recorded length. Erasure invalidates it like a record entry, and a handle
/// that has not verified the source reads and hashes it as before.
#[derive(Clone, Copy, Debug)]
struct SourceFact {
    file: FileIdentity,
    /// The ledger's recorded byte length the identity was verified against.
    byte_length: u64,
    /// Insertion ticket, shared with the record entries so one entry bound
    /// applies to the cache as a whole.
    ticket: u64,
}

/// One entry of a cache's eviction order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FactKey {
    Record(mneme_core::ContentDigest),
    Source(mneme_core::ContentDigest),
}

/// A handle's bounded cache of verified record envelopes, oldest first.
///
/// Record payloads are content addressed and immutable, so an entry keyed by
/// the envelope digest its ledger row records cannot go stale; the ledger row
/// still decides which revision a snapshot contains, and the entry is only
/// stored after the decoded envelope matched that row's identity. A hit is only
/// served while the blob file still has the identity recorded with the entry, so
/// a removed payload fails as an integrity error and a rewritten one is re-read
/// and fails its digest check. Erasure invalidates entries explicitly, because a
/// decoded payload is material the caller may no longer be allowed to read.
///
/// The same bounds hold the verified retained-source facts, which keep no bytes
/// and are evicted in the same insertion order; one entry bound therefore caps
/// the cache as a whole.
///
/// The residual limit is in-place corruption that preserves both length and
/// modification time: such a file keeps the identity a warm handle recorded, so
/// the warm cache keeps serving the bytes it verified. A handle that has not read
/// the record or the source, and [`Workspace::recover`], report that corruption.
#[derive(Default)]
struct RecordCache {
    entries: std::collections::BTreeMap<mneme_core::ContentDigest, CachedRecord>,
    /// Verified retained-source identities, keyed by content digest.
    sources: std::collections::BTreeMap<mneme_core::ContentDigest, SourceFact>,
    /// Insertion order; the front is evicted first. An entry that was re-ticketed
    /// or removed leaves a ticket behind that eviction skips.
    order: std::collections::VecDeque<(u64, FactKey)>,
    next_ticket: u64,
    encoded_bytes: usize,
    /// The erasure generation every entry was verified under.
    ///
    /// The ledger is the authority: a barrier committed by another handle is
    /// observed here before an entry from an older generation can be served.
    generation: Option<u64>,
}

impl RecordCache {
    /// The cached entry for one envelope digest.
    fn get(&self, digest: mneme_core::ContentDigest) -> Option<&CachedRecord> {
        self.entries.get(&digest)
    }

    /// The verified fact for one retained-source digest.
    fn source(&self, digest: mneme_core::ContentDigest) -> Option<SourceFact> {
        self.sources.get(&digest).copied()
    }

    /// Drop every entry that was verified under a different erasure generation.
    fn align_generation(&mut self, generation: u64) {
        if self.generation != Some(generation) {
            self.entries.clear();
            self.sources.clear();
            self.order.clear();
            self.encoded_bytes = 0;
            self.generation = Some(generation);
        }
    }

    /// Remember one verified record envelope, evicting the oldest entries that
    /// no longer fit.
    fn insert(
        &mut self,
        digest: mneme_core::ContentDigest,
        record: mneme_core::RecordEnvelope,
        payload_digest: mneme_core::ContentDigest,
        encoded_bytes: usize,
        file: FileIdentity,
    ) {
        if encoded_bytes > MAX_CACHED_RECORD_BYTES || self.entries.contains_key(&digest) {
            // Content addressing makes a second copy identical, and one entry
            // larger than the whole budget would evict everything for nothing.
            return;
        }
        let ticket = self.ticket();
        self.entries.insert(
            digest,
            CachedRecord {
                record,
                payload_digest,
                encoded_bytes,
                file,
                ticket,
            },
        );
        self.order.push_back((ticket, FactKey::Record(digest)));
        self.encoded_bytes = self.encoded_bytes.saturating_add(encoded_bytes);
        self.evict();
    }

    /// Remember one verified retained-source identity; no bytes are retained.
    fn insert_source(
        &mut self,
        digest: mneme_core::ContentDigest,
        byte_length: u64,
        file: FileIdentity,
    ) {
        let ticket = self.ticket();
        self.sources.insert(
            digest,
            SourceFact {
                file,
                byte_length,
                ticket,
            },
        );
        self.order.push_back((ticket, FactKey::Source(digest)));
        self.evict();
    }

    /// Forget one entry, e.g. because its payload was purged.
    fn remove(&mut self, digest: mneme_core::ContentDigest) {
        if let Some(entry) = self.entries.remove(&digest) {
            self.encoded_bytes = self.encoded_bytes.saturating_sub(entry.encoded_bytes);
            self.order
                .retain(|(_, key)| *key != FactKey::Record(digest));
        }
    }

    /// Forget one retained-source fact, e.g. because its bytes were purged.
    fn remove_source(&mut self, digest: mneme_core::ContentDigest) {
        if self.sources.remove(&digest).is_some() {
            self.order
                .retain(|(_, key)| *key != FactKey::Source(digest));
        }
    }

    fn drop_entry(&mut self, digest: mneme_core::ContentDigest) {
        if let Some(entry) = self.entries.remove(&digest) {
            self.encoded_bytes = self.encoded_bytes.saturating_sub(entry.encoded_bytes);
        }
    }

    /// The next insertion ticket; the oldest ticket is evicted first.
    fn ticket(&mut self) -> u64 {
        let ticket = self.next_ticket;
        self.next_ticket = self.next_ticket.saturating_add(1);
        ticket
    }

    /// Drop the oldest facts until the entry and byte bounds hold again.
    fn evict(&mut self) {
        while self.entries.len().saturating_add(self.sources.len()) > MAX_CACHED_RECORDS
            || self.encoded_bytes > MAX_CACHED_RECORD_BYTES
        {
            let Some((ticket, key)) = self.order.pop_front() else {
                break;
            };
            match key {
                FactKey::Record(digest) => {
                    let is_newest = self
                        .entries
                        .get(&digest)
                        .is_some_and(|entry| entry.ticket == ticket);
                    if is_newest {
                        self.drop_entry(digest);
                    }
                }
                FactKey::Source(digest) => {
                    let is_newest = self
                        .sources
                        .get(&digest)
                        .is_some_and(|fact| fact.ticket == ticket);
                    if is_newest {
                        // A source fact keeps no bytes, so dropping it needs no
                        // accounting beyond the entry it occupies.
                        self.sources.remove(&digest);
                    }
                }
            }
        }
    }
}

/// The verified decode recorded for one digest, with the identity it carries.
fn recorded_entry(
    cache: &RecordCache,
    digest: mneme_core::ContentDigest,
) -> Option<(
    mneme_core::RecordEnvelope,
    mneme_core::ContentDigest,
    FileIdentity,
)> {
    let entry = cache.get(digest)?;
    Some((entry.record.clone(), entry.payload_digest, entry.file))
}

/// The state one [`SharedRecordCache`] protects.
#[derive(Default)]
struct SharedFacts {
    /// The genesis revision of the workspace this cache may serve.
    genesis: Option<mneme_core::WorkspaceRevisionId>,
    facts: RecordCache,
}

/// Verified-record facts shared by every handle a process opens on one workspace.
///
/// A handle opened with [`Workspace::open_with_cache`] reads and fills this cache
/// instead of its own, so a second handle serves a payload the first one verified
/// without reading it again. The cache is bound to the genesis revision of the
/// first workspace that used it and refuses any other workspace; it holds at
/// most the entries and bytes a private cache holds, and it drops every fact when
/// the erasure generation advances. No fact is ever served without the file
/// identity check it was recorded with, so a removed or rewritten payload fails
/// on every handle that shares the cache.
///
/// A poisoned lock — a thread that stopped while updating these facts — is not a
/// panic and never serves anything unverified: the facts are discarded and the
/// operation continues as if the cache were empty, so every payload is verified
/// from disk again. The workspace binding is kept, because it is ledger state.
#[derive(Clone, Default)]
pub struct SharedRecordCache {
    state: std::sync::Arc<std::sync::Mutex<SharedFacts>>,
}

impl SharedRecordCache {
    /// An empty cache, unbound until a workspace handle uses it.
    pub fn new() -> Self {
        SharedRecordCache::default()
    }

    /// Run one operation under the cache lock.
    fn with<R>(&self, action: impl FnOnce(&mut RecordCache) -> R) -> R {
        let mut guard = self.lock();
        action(&mut guard.facts)
    }

    /// The guarded facts, recovering from a lock poisoned by a stopped thread.
    ///
    /// A thread that stopped inside an update leaves the entries and their
    /// accounting in an unknown relation, so they are discarded: the cache is
    /// treated as empty and every payload is verified from disk again.
    fn lock(&self) -> std::sync::MutexGuard<'_, SharedFacts> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                guard.facts = RecordCache::default();
                self.state.clear_poison();
                guard
            }
        }
    }

    /// Bind this cache to the workspace whose ledger has this genesis revision.
    ///
    /// The genesis identity, never a path, decides which workspace a cache may
    /// serve, so two handles that name different workspaces cannot share facts
    /// even if one root is a copy of the other.
    fn bind(&self, genesis: mneme_core::WorkspaceRevisionId) -> crate::error::Result<()> {
        let mut guard = self.lock();
        match guard.genesis {
            Some(bound) if bound == genesis => Ok(()),
            Some(_) => Err(crate::error::Failure::InvalidCommand(
                "a shared record cache serves only the workspace it was bound to".to_owned(),
            )),
            None => {
                guard.genesis = Some(genesis);
                Ok(())
            }
        }
    }
}

/// The verified-fact cache one read consults.
///
/// A handle opened with [`Workspace::open`] uses its own cache; a handle opened
/// with [`Workspace::open_with_cache`] uses the cache it shares with other
/// handles. Every operation has the same bounds, the same file-identity check and
/// the same generation invalidation on both paths.
#[derive(Clone, Copy)]
enum FactAccess<'a> {
    Private(&'a std::cell::RefCell<RecordCache>),
    Shared(&'a SharedRecordCache),
}

/// The verified-fact access one handle's two cache fields describe.
///
/// [`Workspace::facts`] borrows the whole handle, which a caller that already
/// holds the ledger connection mutably cannot do; such a caller builds the same
/// access from the two fields it does not borrow.
fn facts_from<'a>(
    shared: &'a Option<SharedRecordCache>,
    records: &'a std::cell::RefCell<RecordCache>,
) -> FactAccess<'a> {
    match shared {
        Some(shared) => FactAccess::Shared(shared),
        None => FactAccess::Private(records),
    }
}

impl FactAccess<'_> {
    /// Drop every fact that was verified under a different erasure generation.
    fn align(self, generation: u64) {
        match self {
            FactAccess::Private(cache) => cache.borrow_mut().align_generation(generation),
            FactAccess::Shared(shared) => shared.with(|cache| cache.align_generation(generation)),
        }
    }

    /// The verified decode for one digest, when the blob still names the
    /// verified file.
    ///
    /// One `symlink_metadata` call decides it and never reads content. A missing
    /// or different file drops the entry and reports a miss, so the caller
    /// re-reads: a removed payload then fails as an integrity error, and a
    /// rewritten one fails its digest check.
    fn recorded_envelope(
        self,
        root: &std::path::Path,
        digest: mneme_core::ContentDigest,
    ) -> Option<(mneme_core::RecordEnvelope, mneme_core::ContentDigest)> {
        let recorded = match self {
            FactAccess::Private(cache) => recorded_entry(&cache.borrow(), digest),
            FactAccess::Shared(shared) => shared.with(|cache| recorded_entry(cache, digest)),
        }?;
        if blob_file_identity(root, digest) == Some(recorded.2) {
            return Some((recorded.0, recorded.1));
        }
        self.forget_envelope(digest);
        None
    }

    /// Remember one verified record envelope.
    fn store_envelope(
        self,
        digest: mneme_core::ContentDigest,
        record: mneme_core::RecordEnvelope,
        payload_digest: mneme_core::ContentDigest,
        encoded_bytes: usize,
        file: FileIdentity,
    ) {
        match self {
            FactAccess::Private(cache) => {
                cache
                    .borrow_mut()
                    .insert(digest, record, payload_digest, encoded_bytes, file);
            }
            FactAccess::Shared(shared) => shared.with(|cache| {
                cache.insert(digest, record, payload_digest, encoded_bytes, file);
            }),
        }
    }

    /// Forget one verified record envelope.
    fn forget_envelope(self, digest: mneme_core::ContentDigest) {
        match self {
            FactAccess::Private(cache) => cache.borrow_mut().remove(digest),
            FactAccess::Shared(shared) => shared.with(|cache| cache.remove(digest)),
        }
    }

    /// Whether this cache already hashed one retained source's bytes at the
    /// ledger's recorded length and the file still has the identity it recorded.
    ///
    /// A file that changed identity, or a length the ledger no longer records for
    /// that digest, drops the fact and reports a miss so the bytes are verified
    /// from disk again.
    fn source_verified(
        self,
        root: &std::path::Path,
        digest: mneme_core::ContentDigest,
        byte_length: u64,
    ) -> bool {
        let recorded = match self {
            FactAccess::Private(cache) => cache.borrow().source(digest),
            FactAccess::Shared(shared) => shared.with(|cache| cache.source(digest)),
        };
        let Some(fact) = recorded else {
            return false;
        };
        if fact.byte_length == byte_length && blob_file_identity(root, digest) == Some(fact.file) {
            return true;
        }
        self.forget_source(digest);
        false
    }

    /// Remember that one retained source's bytes were verified at this identity.
    fn store_source(self, digest: mneme_core::ContentDigest, byte_length: u64, file: FileIdentity) {
        match self {
            FactAccess::Private(cache) => {
                cache.borrow_mut().insert_source(digest, byte_length, file);
            }
            FactAccess::Shared(shared) => {
                shared.with(|cache| cache.insert_source(digest, byte_length, file));
            }
        }
    }

    /// Forget one verified retained-source fact.
    fn forget_source(self, digest: mneme_core::ContentDigest) {
        match self {
            FactAccess::Private(cache) => cache.borrow_mut().remove_source(digest),
            FactAccess::Shared(shared) => shared.with(|cache| cache.remove_source(digest)),
        }
    }
}

/// Decode one record blob into its envelope, reporting either failure as one
/// integrity error naming the ledger revision that required it.
fn decode_envelope(
    bytes: &[u8],
    digest: mneme_core::ContentDigest,
    revision: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<mneme_core::RecordEnvelope> {
    let value = mneme_core::binary::decode(bytes).map_err(|diagnostic| {
        crate::error::Failure::Integrity {
            revision,
            reason: format!("record blob {digest} is not valid Preserves: {diagnostic}"),
        }
    })?;
    mneme_core::RecordEnvelope::from_value(&value).map_err(|diagnostics| {
        crate::error::Failure::Integrity {
            revision,
            reason: format!(
                "record blob {digest} is not a valid envelope: {}",
                join(&diagnostics)
            ),
        }
    })
}

/// Require one decoded envelope to carry exactly the identity its ledger row
/// names: the record, revision, kind and both digests.
fn require_envelope_identity(
    identity: &EnvelopeIdentity<'_>,
    record: &mneme_core::RecordEnvelope,
    digest: mneme_core::ContentDigest,
    payload_digest: mneme_core::ContentDigest,
    revision: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<()> {
    if record.record_id != identity.record_id
        || record.revision_id != identity.revision_id
        || record.kind != identity.kind
        || record.full_digest() != digest
        || record.full_digest().as_bytes() != identity.full_digest
        || record.payload_digest() != payload_digest
    {
        return Err(crate::error::Failure::Integrity {
            revision,
            reason: format!("record blob {digest} does not match its ledger identity"),
        });
    }
    Ok(())
}

struct VerifiedRecordEnvelopeInput<'a> {
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    kind: mneme_core::RecordKind,
    envelope_digest: &'a [u8],
    payload_digest: &'a [u8],
    full_digest: &'a [u8],
    revision: mneme_core::WorkspaceRevisionId,
    /// The erasure generation the read is pinned to, used to explain a missing
    /// payload as a barrier change instead of corruption.
    generation: u64,
    /// The ledger facts of the blobs the load needs, used by a presence-only
    /// load instead of one statement per record.
    lengths: &'a BlobIndex,
}

/// The ledger identity one decoded record envelope must carry.
///
/// A cache hit is served only when the entry was verified under exactly these
/// facts, so the comparison is shared by the cached and the re-read path.
struct EnvelopeIdentity<'a> {
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    kind: mneme_core::RecordKind,
    /// Full-envelope digest bytes exactly as the ledger recorded them.
    full_digest: &'a [u8],
}

struct SourceRecordDigestInput<'a> {
    record_id: mneme_core::RecordId,
    full: mneme_core::ContentDigest,
    payload_digest: &'a [u8],
    context: mneme_core::WorkspaceRevisionId,
    current: &'a std::collections::BTreeMap<mneme_core::RecordId, SourcePresence>,
    required: &'a mut std::collections::BTreeSet<[u8; 32]>,
}

/// One snapshot's record load: the ledger state it reads and how it treats the
/// payloads it serves.
///
/// Every statement of the load runs on one connection, which the caller holds
/// inside a single read transaction, so the membership, the record rows and the
/// blob facts all describe one ledger state.
struct RecordLoad<'a> {
    connection: &'a rusqlite::Connection,
    sequence: u64,
    revision: mneme_core::WorkspaceRevisionId,
    generation: u64,
    check: PayloadCheck,
}

/// The digests and working-path bindings live retained records still require.
#[derive(Clone)]
struct RetentionRequirements {
    revision: mneme_core::WorkspaceRevisionId,
    generation: u64,
    digests: std::collections::BTreeSet<[u8; 32]>,
    /// Each working path a live source's current revision retains bytes at.
    paths: std::collections::BTreeMap<String, std::collections::BTreeSet<[u8; 32]>>,
    /// Working paths a publication intent still has to write.
    pending_paths: std::collections::BTreeSet<String>,
}

struct PreparedCommit {
    request_digest: mneme_core::ContentDigest,
    fingerprint: Option<mneme_core::ContentDigest>,
    base: mneme_core::WorkspaceRevisionId,
    next_sequence: u64,
    generation: u64,
    next_generation: u64,
    recorded: mneme_core::RecordedTime,
    new_records: Vec<mneme_core::RecordEnvelope>,
    staged: BlobIndex,
    /// Identity of each staged record blob file at the moment its bytes were
    /// verified, keyed by the record's full digest.
    record_files: std::collections::BTreeMap<[u8; 32], FileIdentity>,
    /// The ledger facts of every blob the new revision requires, read once
    /// before staging and reused inside the commit transaction.
    blob_lengths: BlobIndex,
    snapshot_records: std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RecordEnvelope>,
    revision_id: mneme_core::WorkspaceRevisionId,
    manifest: crate::catalog::Manifest,
    manifest_digest: mneme_core::ContentDigest,
}

struct CommitManifest {
    snapshot_records: std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RecordEnvelope>,
    revision_id: mneme_core::WorkspaceRevisionId,
    manifest: crate::catalog::Manifest,
    manifest_digest: mneme_core::ContentDigest,
}

enum CommitWrite {
    Existing(CommitOutcome),
    New(Vec<String>),
}

const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS revisions (
    sequence INTEGER PRIMARY KEY,
    revision_id BLOB NOT NULL UNIQUE,
    parent_revision_id BLOB,
    committed_at_ns INTEGER NOT NULL,
    actor TEXT NOT NULL,
    scope TEXT NOT NULL,
    command_id TEXT NOT NULL,
    request_digest BLOB NOT NULL,
    eligibility_generation INTEGER NOT NULL,
    manifest BLOB NOT NULL,
    manifest_digest BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
    record_id BLOB NOT NULL,
    revision_id BLOB NOT NULL,
    kind TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    scope TEXT NOT NULL,
    recorded_at_ns INTEGER NOT NULL,
    recorded_order INTEGER NOT NULL,
    envelope_digest BLOB NOT NULL,
    payload_digest BLOB NOT NULL,
    full_digest BLOB NOT NULL,
    PRIMARY KEY (record_id, revision_id)
);
CREATE TABLE IF NOT EXISTS blobs (
    digest BLOB PRIMARY KEY,
    algorithm TEXT NOT NULL,
    profile TEXT NOT NULL,
    boundary TEXT NOT NULL,
    byte_length INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS commands (
    actor TEXT NOT NULL,
    scope TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_digest BLOB NOT NULL,
    fingerprint BLOB,
    base_revision BLOB NOT NULL,
    outcome_revision BLOB NOT NULL,
    outcome_sequence INTEGER NOT NULL,
    committed_at_ns INTEGER NOT NULL,
    PRIMARY KEY (actor, scope, idempotency_key)
);
CREATE TABLE IF NOT EXISTS publication_intents (
    intent_id TEXT PRIMARY KEY,
    revision_sequence INTEGER NOT NULL,
    target_path TEXT NOT NULL,
    expected_digest BLOB,
    desired_digest BLOB NOT NULL,
    eligibility_generation INTEGER NOT NULL,
    state TEXT NOT NULL,
    observed_digest BLOB,
    detail TEXT,
    updated_at_ns INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS projections (
    name TEXT PRIMARY KEY,
    revision_id BLOB NOT NULL,
    revision_sequence INTEGER NOT NULL,
    schema_version INTEGER NOT NULL,
    rule_version TEXT NOT NULL,
    index_version TEXT NOT NULL,
    scope TEXT NOT NULL,
    eligibility_generation INTEGER NOT NULL,
    built_at_ns INTEGER NOT NULL
);
"#;

/// The snapshot membership representation.
///
/// A record revision is stored once, with the span of committed sequences it
/// belongs to, so a commit writes rows for the records it changes instead of
/// copying the whole snapshot. The blob journal records how one manifest's
/// required digest set differs from its parent's, which reconstructs the
/// manifest without storing its bytes or a copy of its digest set.
const MEMBERSHIP_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS record_membership (
    record_id BLOB NOT NULL,
    revision_id BLOB NOT NULL,
    first_sequence INTEGER NOT NULL,
    last_sequence INTEGER,
    PRIMARY KEY (record_id, first_sequence)
);
CREATE INDEX IF NOT EXISTS record_membership_window
    ON record_membership(first_sequence, last_sequence);
CREATE INDEX IF NOT EXISTS record_membership_open
    ON record_membership(record_id, revision_id) WHERE last_sequence IS NULL;
CREATE TABLE IF NOT EXISTS revision_blob_changes (
    revision_sequence INTEGER NOT NULL,
    digest BLOB NOT NULL,
    change TEXT NOT NULL,
    PRIMARY KEY (revision_sequence, digest)
);
"#;

const RETENTION_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS retention_operations (
    operation_id TEXT PRIMARY KEY,
    operation_kind TEXT NOT NULL,
    actor TEXT NOT NULL,
    scope TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_digest BLOB NOT NULL,
    state TEXT NOT NULL,
    generation INTEGER NOT NULL,
    outcome_revision BLOB NOT NULL,
    outcome_sequence INTEGER NOT NULL,
    retained_metadata TEXT NOT NULL,
    created_at_ns INTEGER NOT NULL,
    updated_at_ns INTEGER NOT NULL,
    UNIQUE(actor, scope, idempotency_key)
);
CREATE TABLE IF NOT EXISTS retention_selectors (
    operation_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    selector_kind TEXT NOT NULL,
    target_id BLOB,
    target_revision BLOB,
    target_digest BLOB,
    PRIMARY KEY (operation_id, ordinal),
    FOREIGN KEY (operation_id) REFERENCES retention_operations(operation_id)
);
CREATE TABLE IF NOT EXISTS retention_suppressions (
    operation_id TEXT NOT NULL,
    target_id BLOB NOT NULL,
    target_revision BLOB NOT NULL,
    target_kind TEXT NOT NULL,
    mode TEXT NOT NULL,
    content_digest BLOB,
    generation INTEGER NOT NULL,
    PRIMARY KEY (operation_id, target_id, target_revision)
);
CREATE INDEX IF NOT EXISTS retention_suppressions_target
    ON retention_suppressions(target_id, target_revision, mode);
CREATE TABLE IF NOT EXISTS retention_participants (
    name TEXT PRIMARY KEY,
    storage_role TEXT NOT NULL,
    supports_invalidation INTEGER NOT NULL,
    supports_purge INTEGER NOT NULL,
    checks_generation INTEGER NOT NULL,
    inventory_locator TEXT NOT NULL,
    registered_at_ns INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS retention_locations (
    operation_id TEXT NOT NULL,
    location_id TEXT NOT NULL,
    location_kind TEXT NOT NULL,
    locator TEXT NOT NULL,
    state TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    verified INTEGER NOT NULL DEFAULT 0,
    detail_code TEXT,
    updated_at_ns INTEGER NOT NULL,
    PRIMARY KEY (operation_id, location_id),
    FOREIGN KEY (operation_id) REFERENCES retention_operations(operation_id)
);
"#;

/// Configuration for a workspace handle.
type RetainedRecordRow = (Vec<u8>, Vec<u8>, String, Vec<u8>, Vec<u8>, Vec<u8>);

pub struct WorkspaceConfig {
    pub clock: Box<dyn Clock>,
    pub faults: Box<dyn FaultInjector>,
}

impl Default for WorkspaceConfig {
    fn default() -> Self {
        WorkspaceConfig {
            clock: Box::new(crate::timekeeper::SystemClock),
            faults: Box::new(crate::injectors::NoFaults),
        }
    }
}

impl WorkspaceConfig {
    /// Construct a configuration from an explicit clock and fault injector.
    pub fn new(clock: Box<dyn Clock>, faults: Box<dyn FaultInjector>) -> Self {
        WorkspaceConfig { clock, faults }
    }
}

impl std::fmt::Debug for WorkspaceConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkspaceConfig")
            .finish_non_exhaustive()
    }
}

/// Current workspace status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceStatus {
    pub revision: mneme_core::WorkspaceRevisionId,
    pub sequence: u64,
    pub eligibility_generation: u64,
    pub record_count: usize,
    pub blob_count: usize,
    pub pending_publications: usize,
}

/// A pinned, integrity-checked workspace snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub revision: mneme_core::WorkspaceRevisionId,
    pub sequence: u64,
    pub parent: Option<mneme_core::WorkspaceRevisionId>,
    pub manifest_digest: mneme_core::ContentDigest,
    pub eligibility_generation: u64,
    pub records: Vec<mneme_core::RecordEnvelope>,
    pub index: mneme_core::SnapshotIndex,
}

/// The state of one working-file publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationState {
    Pending,
    Published,
    Diverged,
    Suppressed,
    Failed,
}

impl PublicationState {
    /// Stable lower-case name for interfaces and reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            PublicationState::Pending => "pending",
            PublicationState::Published => "published",
            PublicationState::Diverged => "diverged",
            PublicationState::Suppressed => "suppressed",
            PublicationState::Failed => "failed",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "pending" => Some(PublicationState::Pending),
            "published" => Some(PublicationState::Published),
            "diverged" => Some(PublicationState::Diverged),
            "suppressed" => Some(PublicationState::Suppressed),
            "failed" => Some(PublicationState::Failed),
            _ => None,
        }
    }

    /// The kernel phase this store state denotes.
    pub const fn to_kernel(self) -> mneme_kernel::publish::PublicationPhase {
        match self {
            PublicationState::Pending => mneme_kernel::publish::PublicationPhase::Pending,
            PublicationState::Published => mneme_kernel::publish::PublicationPhase::Published,
            PublicationState::Diverged => mneme_kernel::publish::PublicationPhase::Diverged,
            PublicationState::Suppressed => mneme_kernel::publish::PublicationPhase::Suppressed,
            PublicationState::Failed => mneme_kernel::publish::PublicationPhase::Failed,
        }
    }

    /// The store state for a kernel phase.
    pub const fn from_kernel(phase: mneme_kernel::publish::PublicationPhase) -> Self {
        match phase {
            mneme_kernel::publish::PublicationPhase::Pending => PublicationState::Pending,
            mneme_kernel::publish::PublicationPhase::Published => PublicationState::Published,
            mneme_kernel::publish::PublicationPhase::Diverged => PublicationState::Diverged,
            mneme_kernel::publish::PublicationPhase::Suppressed => PublicationState::Suppressed,
            mneme_kernel::publish::PublicationPhase::Failed => PublicationState::Failed,
        }
    }

    /// Whether recovery or an explicit publish must attempt this intent again.
    pub fn should_attempt(self) -> bool {
        mneme_kernel::publish::should_attempt(self.to_kernel())
    }
}

/// The outcome of one publication intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationOutcome {
    pub intent_id: String,
    pub path: String,
    pub state: PublicationState,
    pub observed: Option<mneme_core::ContentDigest>,
    pub detail: Option<String>,
}

/// A committed revision plus separately observed publication results.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitOutcome {
    pub revision: mneme_core::WorkspaceRevisionId,
    pub sequence: u64,
    pub manifest_digest: mneme_core::ContentDigest,
    pub eligibility_generation: u64,
    pub publications: Vec<PublicationOutcome>,
}

/// Results of startup recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryReport {
    pub staged_files_removed: usize,
    pub orphan_blobs_removed: usize,
    pub working_temporaries_removed: usize,
    pub revision: mneme_core::WorkspaceRevisionId,
    pub publications: Vec<PublicationOutcome>,
}

/// A derived projection's declared envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionRegistration {
    pub name: String,
    pub revision: mneme_core::WorkspaceRevisionId,
    /// The eligibility generation the builder read alongside `revision`.
    ///
    /// A projection built before a barrier must never resolve as compatible,
    /// so the builder's pinned generation is recorded instead of whatever
    /// generation is current when registration happens.
    pub eligibility_generation: u64,
    pub schema_version: u32,
    pub rule_version: String,
    pub index_version: String,
    pub scope: String,
}

/// A registered projection as stored in the ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionState {
    pub name: String,
    pub revision: mneme_core::WorkspaceRevisionId,
    pub sequence: u64,
    pub schema_version: u32,
    pub rule_version: String,
    pub index_version: String,
    pub scope: String,
    pub eligibility_generation: u64,
    pub built_at_ns: i64,
}

/// Whether a projection may serve a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProjectionResolution {
    Compatible(ProjectionState),
    Behind {
        projection: ProjectionState,
        requested: mneme_core::WorkspaceRevisionId,
    },
    ScopeMismatch {
        projection: ProjectionState,
        requested_scope: String,
    },
    BarrierAdvanced {
        projection: ProjectionState,
        current: u64,
    },
    /// The consumer requires schema, rule or index versions the projection
    /// was not built with.
    VersionMismatch {
        projection: ProjectionState,
        schema_version: u32,
        rule_version: String,
        index_version: String,
    },
    Missing,
}

/// An open workspace coordinator.
pub struct Workspace {
    root: std::path::PathBuf,
    connection: rusqlite::Connection,
    clock: Box<dyn Clock>,
    faults: Box<dyn FaultInjector>,
    is_restore_required: bool,
    /// Required-digest and path-binding sets, keyed by the revision and
    /// generation they were computed for.
    ///
    /// A cleanup pass asks the same question once per location; recomputing it
    /// would read and decode every source envelope again. Any commit or barrier
    /// changes the key, so a stale set is never reused.
    requirements: std::cell::RefCell<Option<RetentionRequirements>>,
    /// Verified record envelopes this handle already decoded.
    ///
    /// A snapshot load must decode every record of the revision it serves; the
    /// cache makes a second load on the same handle read only the records whose
    /// payloads it has never seen. A hit is only served while the blob file still
    /// has the identity recorded with the entry, and the cache is cleared
    /// whenever the erasure generation advances or a record payload is purged, so
    /// an entry never outlives the permission to read it.
    records: std::cell::RefCell<RecordCache>,
    /// The process-wide cache this handle shares with other handles, when it was
    /// opened with one.
    ///
    /// Such a handle leaves its own cache unused, so a private handle keeps
    /// exactly the behaviour and bounds it had, and a shared handle serves only
    /// facts the shared cache verified under the current erasure generation.
    shared: Option<SharedRecordCache>,
}

impl std::fmt::Debug for Workspace {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Workspace")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

/// A shared advisory workspace lock held across a commit's staging and
/// transaction.
///
/// Several commits may hold it at once; a recovery sweep may not, so no sweep
/// can observe a commit's staged blobs as orphans. The lock is released when the
/// guard is dropped, which happens before working-file publication.
#[must_use = "the lock is released as soon as the guard is dropped"]
pub struct CommitGuard {
    file: std::fs::File,
}

impl std::fmt::Debug for CommitGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommitGuard")
            .field("file", &LOCK_FILE)
            .finish()
    }
}

impl Drop for CommitGuard {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// An exclusive advisory workspace lock held across a sweep of unreferenced
/// files.
///
/// No commit can stage a blob, and no second sweep can run, while it is held.
#[must_use = "the lock is released as soon as the guard is dropped"]
pub struct SweepGuard {
    file: std::fs::File,
}

impl std::fmt::Debug for SweepGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SweepGuard")
            .field("file", &LOCK_FILE)
            .finish()
    }
}

impl Drop for SweepGuard {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl Workspace {
    /// Create a fresh workspace directory with a genesis revision.
    ///
    /// A new path is assembled in a hidden sibling directory and renamed into
    /// place, so a stop leaves either no workspace or a complete one. An
    /// existing empty directory is initialized in place, and a ledger left by
    /// an interrupted initialization is cleared first, so the same call can
    /// complete it. Any other content is refused untouched.
    pub fn create(
        root: impl AsRef<std::path::Path>,
        config: WorkspaceConfig,
    ) -> crate::error::Result<Self> {
        let requested = root.as_ref();
        if requested.exists() {
            let root = std::fs::canonicalize(requested)
                .map_err(|error| crate::error::Failure::io(requested, error))?;
            clear_incomplete_workspace(&root)?;
            Self::initialize(&root, &config)?;
            return Self::open(&root, config);
        }
        let parent = requested
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .map_or_else(
                || std::path::PathBuf::from("."),
                std::path::Path::to_path_buf,
            );
        std::fs::create_dir_all(&parent)
            .map_err(|error| crate::error::Failure::io(&parent, error))?;
        let parent = std::fs::canonicalize(&parent)
            .map_err(|error| crate::error::Failure::io(&parent, error))?;
        let name = requested.file_name().ok_or_else(|| {
            crate::error::Failure::InvalidCommand("workspace root has no directory name".to_owned())
        })?;
        let root = parent.join(name);
        let temporary = parent.join(format!(
            ".{}.mneme-init-{}",
            name.to_string_lossy(),
            crate::payload::random_hex(8)?
        ));
        crate::payload::create_directory_chain_flushed(&temporary)?;
        let initialized = Self::initialize(&temporary, &config).and_then(|()| {
            std::fs::rename(&temporary, &root)
                .map_err(|error| crate::error::Failure::io(&root, error))
        });
        if let Err(error) = initialized {
            // Only this call's own uniquely named temporary directory is removed.
            #[allow(unknown_lints, ignored_result)]
            // best-effort cleanup after the reported initialization failure
            let _ = std::fs::remove_dir_all(&temporary);
            return Err(error);
        }
        sync_directory(&parent)?;
        Self::open(&root, config)
    }

    /// Write the ledger, the genesis revision and the meta rows into an empty
    /// directory. One transaction makes them appear together.
    fn initialize(root: &std::path::Path, config: &WorkspaceConfig) -> crate::error::Result<()> {
        for directory in [
            crate::payload::BLOB_DIRECTORY,
            crate::payload::STAGING_DIRECTORY,
            crate::payload::WORKING_DIRECTORY,
        ] {
            crate::payload::create_directory_chain_flushed(&root.join(directory))?;
        }
        drop(open_lock_file(root)?);
        let mut connection = open_connection(root)?;
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        transaction.execute_batch(DDL)?;
        transaction.execute_batch(MEMBERSHIP_DDL)?;
        transaction.execute_batch(RETENTION_DDL)?;
        let revision = mneme_core::WorkspaceRevisionId::from_bytes(crate::payload::random_bytes()?);
        let manifest = crate::catalog::Manifest::genesis(revision);
        let manifest_digest = manifest.digest();
        let committed_at = config.clock.now().nanos();
        let genesis_scope = mneme_core::ScopeId::new(mneme_core::ScopeClass::Workspace, "genesis")
            .map_err(|message| crate::error::Failure::InvalidCommand(message.to_owned()))?;
        transaction.execute(
            "INSERT INTO revisions (sequence, revision_id, parent_revision_id, committed_at_ns,
                 actor, scope, command_id, request_digest, eligibility_generation, manifest,
                 manifest_digest)
             VALUES (0, ?1, NULL, ?2, 'system', ?3, 'genesis', ?4, 1, ?5, ?6)",
            rusqlite::params![
                revision.as_bytes().as_slice(),
                committed_at,
                genesis_scope.to_string(),
                [0_u8; 32].as_slice(),
                Vec::<u8>::new(),
                manifest_digest.as_bytes().as_slice(),
            ],
        )?;
        set_meta(&transaction, META_LAYOUT, b"1")?;
        set_meta(&transaction, META_RETENTION_FORMAT, b"1")?;
        set_meta(&transaction, META_MEMBERSHIP_FORMAT, b"2")?;
        set_meta(&transaction, META_CURRENT_REVISION, revision.as_bytes())?;
        set_meta_u64(&transaction, META_CURRENT_SEQUENCE, 0)?;
        set_meta_u64(&transaction, META_GENERATION, 1)?;
        // The layout version is the last write, so a reader never accepts a
        // ledger that is still missing its genesis state.
        transaction.pragma_update(None, "user_version", LAYOUT_VERSION)?;
        transaction.commit()?;
        drop(connection);
        sync_directory(root)
    }

    /// Open an existing workspace without running recovery.
    ///
    /// The handle verifies and remembers record envelopes and retained sources
    /// in its own cache; see [`Workspace::open_with_cache`] for a handle that
    /// shares those facts with other handles of the same workspace.
    pub fn open(
        root: impl AsRef<std::path::Path>,
        config: WorkspaceConfig,
    ) -> crate::error::Result<Self> {
        Self::open_handle(root.as_ref(), config, None)
    }

    /// Open an existing workspace, sharing verified facts through `cache`.
    ///
    /// Every handle a process opens on one workspace with the same cache verifies
    /// each record envelope and each retained source once: the first handle to
    /// read a payload records the identity its bytes were verified with, and the
    /// others serve that fact while the blob file still has it. The cache is bound
    /// to the workspace by its ledger's genesis revision, so a cache already used
    /// by another workspace is refused and no handle is opened.
    pub fn open_with_cache(
        root: impl AsRef<std::path::Path>,
        config: WorkspaceConfig,
        cache: SharedRecordCache,
    ) -> crate::error::Result<Self> {
        Self::open_handle(root.as_ref(), config, Some(cache))
    }

    /// Open one handle, optionally recording verified facts in a shared cache.
    fn open_handle(
        requested: &std::path::Path,
        config: WorkspaceConfig,
        shared: Option<SharedRecordCache>,
    ) -> crate::error::Result<Self> {
        let root = std::fs::canonicalize(requested)
            .map_err(|error| crate::error::Failure::io(requested, error))?;
        let ledger = root.join(LEDGER_FILE);
        if !ledger.is_file() {
            return Err(crate::error::Failure::UnsupportedLayout(format!(
                "{} has no {LEDGER_FILE}",
                root.display()
            )));
        }
        let mut connection = open_connection(&root)?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version != LAYOUT_VERSION {
            return Err(crate::error::Failure::UnsupportedLayout(format!(
                "ledger layout version {version} is not supported"
            )));
        }
        if meta_blob(&connection, META_CURRENT_REVISION)?.len() != 16 {
            return Err(crate::error::Failure::UnsupportedLayout(
                "ledger has no readable current revision".to_owned(),
            ));
        }
        connection.execute_batch(RETENTION_DDL)?;
        ensure_retention_format(&connection)?;
        // The ledger's membership representation is upgraded in place before
        // any read or write can observe it. A ledger that does not reconstruct
        // is refused untouched, so the open fails closed instead of serving
        // unverified membership.
        history::migrate_membership_format(&mut connection)?;
        // A restore that was interrupted before its ledger was applied leaves
        // this marker behind; every later open refuses to serve until the
        // marker and the ledger state are written together.
        let is_restore_required = meta_blob_optional(&connection, META_RESTORE_PENDING)?
            .is_some_and(|value| !value.is_empty());
        // Binding comes last, once the ledger is known to be readable: a cache
        // bound to another workspace refuses this one before a handle exists.
        let shared = match shared {
            Some(cache) => {
                cache.bind(read_genesis(&connection)?)?;
                Some(cache)
            }
            None => None,
        };
        Ok(Workspace {
            root,
            connection,
            clock: config.clock,
            faults: config.faults,
            is_restore_required,
            requirements: std::cell::RefCell::new(None),
            records: std::cell::RefCell::new(RecordCache::default()),
            shared,
        })
    }

    /// Open a workspace produced by an application-supported restore. Until
    /// the current retention ledger is applied, content publication and reads
    /// fail closed.
    ///
    /// The pending marker is written to the ledger in one transaction before
    /// this handle is returned, so a restart cannot clear it.
    pub fn open_restored(
        root: impl AsRef<std::path::Path>,
        config: WorkspaceConfig,
    ) -> crate::error::Result<Self> {
        let mut workspace = Self::open(root, config)?;
        let transaction = workspace
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        set_meta(&transaction, META_RESTORE_PENDING, b"1")?;
        transaction.commit()?;
        workspace.is_restore_required = true;
        Ok(workspace)
    }

    /// The canonical workspace root.
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    /// Take the shared lock a commit holds from staging to its transaction.
    ///
    /// Shared locks do not exclude each other, so commits stay concurrent; they
    /// exclude every exclusive sweep.
    pub fn shared_commit_lock(&self) -> crate::error::Result<CommitGuard> {
        let file = open_lock_file(&self.root)?;
        let path = self.root.join(LOCK_FILE);
        file.lock_shared()
            .map_err(|error| crate::error::Failure::io(path, error))?;
        Ok(CommitGuard { file })
    }

    /// Take the exclusive lock a sweep holds while it deletes unreferenced
    /// files.
    ///
    /// No commit can have an in-flight staged blob while it is held, so every
    /// blob without a ledger row really is uncommitted work. Retention blob
    /// purges take this lock too, for the same reason. Take it before opening a
    /// ledger transaction, never while holding one: a commit holds the shared
    /// lock before it waits for the SQLite writer lock, so the reverse order
    /// would deadlock.
    pub fn exclusive_sweep_lock(&self) -> crate::error::Result<SweepGuard> {
        let file = open_lock_file(&self.root)?;
        let path = self.root.join(LOCK_FILE);
        file.lock()
            .map_err(|error| crate::error::Failure::io(path, error))?;
        Ok(SweepGuard { file })
    }

    /// The current committed revision identity.
    pub fn current_revision(&self) -> crate::error::Result<mneme_core::WorkspaceRevisionId> {
        revision_from_blob(&meta_blob(&self.connection, META_CURRENT_REVISION)?)
    }

    /// The workspace's genesis revision identity.
    ///
    /// A suppression ledger is bound to this identity, so a ledger exported from
    /// another workspace can never be applied here.
    pub fn genesis_revision(&self) -> crate::error::Result<mneme_core::WorkspaceRevisionId> {
        read_genesis(&self.connection)
    }

    /// The verified-fact cache this handle reads and fills.
    ///
    /// A handle opened with a shared cache never touches its own, so the two
    /// kinds of handle cannot serve each other's unverified material.
    fn facts(&self) -> FactAccess<'_> {
        facts_from(&self.shared, &self.records)
    }

    /// The current committed revision sequence.
    pub fn current_sequence(&self) -> crate::error::Result<u64> {
        meta_u64(&self.connection, META_CURRENT_SEQUENCE)
    }

    /// The current eligibility generation.
    pub fn eligibility_generation(&self) -> crate::error::Result<u64> {
        meta_u64(&self.connection, META_GENERATION)
    }

    /// Current status for interfaces and tests.
    ///
    /// Every field is read from one deferred transaction, so the reported
    /// revision, sequence, counts and generation always describe one commit
    /// rather than a mixture of two.
    pub fn status(&self) -> crate::error::Result<WorkspaceStatus> {
        let transaction = self.connection.unchecked_transaction()?;
        let revision = revision_from_blob(&meta_blob(&transaction, META_CURRENT_REVISION)?)?;
        let sequence = meta_u64(&transaction, META_CURRENT_SEQUENCE)?;
        let record_count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM record_membership
             WHERE first_sequence <= ?1 AND (last_sequence IS NULL OR last_sequence >= ?1)",
            rusqlite::params![db_i64(sequence, "sequence")?],
            |row| row.get(0),
        )?;
        let blob_count: i64 =
            transaction.query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get(0))?;
        let pending: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM publication_intents WHERE state = 'pending'",
            [],
            |row| row.get(0),
        )?;
        let eligibility_generation = meta_u64(&transaction, META_GENERATION)?;
        transaction.commit()?;
        Ok(WorkspaceStatus {
            revision,
            sequence,
            eligibility_generation,
            record_count: db_usize(record_count, "record count")?,
            blob_count: db_usize(blob_count, "blob count")?,
            pending_publications: db_usize(pending, "pending publication count")?,
        })
    }

    /// Advance the current eligibility/erasure generation.
    ///
    /// The read and the write share one immediate transaction, so an advance
    /// interleaved with a retention barrier commit can never be lost.
    pub fn advance_eligibility_barrier(&mut self) -> crate::error::Result<u64> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let next = meta_u64(&transaction, META_GENERATION)?.saturating_add(1);
        set_meta_u64(&transaction, META_GENERATION, next)?;
        transaction.commit()?;
        // A barrier means material decoded under the old generation may no
        // longer be served, so no cached entry may outlive it.
        self.facts().align(next);
        Ok(next)
    }

    /// Recheck a pinned snapshot against the current generation.
    pub fn recheck(&self, snapshot: &Snapshot) -> crate::error::Result<()> {
        let current = self.eligibility_generation()?;
        if current != snapshot.eligibility_generation {
            return Err(crate::error::Failure::BarrierAdvanced {
                pinned: snapshot.eligibility_generation,
                current,
            });
        }
        Ok(())
    }

    /// Register or replace a derived projection declared against a committed
    /// revision and the eligibility generation the builder read with it.
    ///
    /// The pinned generation is compared with the current one inside one
    /// immediate transaction, so a barrier that lands between the builder's
    /// check and this registration is refused instead of being mislabelled as
    /// a projection of the newer generation.
    pub fn register_projection(
        &mut self,
        registration: ProjectionRegistration,
    ) -> crate::error::Result<ProjectionState> {
        if self.retention_participant(&registration.name)?.is_none() {
            return Err(crate::error::Failure::MissingRetentionParticipant {
                name: registration.name,
            });
        }
        if registration.name.trim().is_empty() {
            return Err(crate::error::Failure::InvalidCommand(
                "projection name must not be empty".to_owned(),
            ));
        }
        let row =
            revision_row_by_id(&self.connection, registration.revision)?.ok_or_else(|| {
                crate::error::Failure::Integrity {
                    revision: registration.revision,
                    reason: "projection names an unknown revision".to_owned(),
                }
            })?;
        let built_at = self.clock.now().nanos();
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current = meta_u64(&transaction, META_GENERATION)?;
        if registration.eligibility_generation != current {
            return Err(crate::error::Failure::BarrierAdvanced {
                pinned: registration.eligibility_generation,
                current,
            });
        }
        let name = registration.name;
        transaction.execute(
            "INSERT INTO projections (name, revision_id, revision_sequence, schema_version,
                 rule_version, index_version, scope, eligibility_generation, built_at_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(name) DO UPDATE SET revision_id = excluded.revision_id,
                 revision_sequence = excluded.revision_sequence,
                 schema_version = excluded.schema_version,
                 rule_version = excluded.rule_version,
                 index_version = excluded.index_version,
                 scope = excluded.scope,
                 eligibility_generation = excluded.eligibility_generation,
                 built_at_ns = excluded.built_at_ns",
            rusqlite::params![
                name.clone(),
                registration.revision.as_bytes().as_slice(),
                db_i64(row.sequence, "sequence")?,
                i64::from(registration.schema_version),
                registration.rule_version,
                registration.index_version,
                registration.scope,
                db_i64(registration.eligibility_generation, "generation")?,
                built_at,
            ],
        )?;
        transaction.commit()?;
        self.projection(&name)?
            .ok_or_else(|| crate::error::Failure::Integrity {
                revision: registration.revision,
                reason: "projection registration disappeared".to_owned(),
            })
    }

    /// Register a payload-bearing component only after it declares
    /// invalidation, purge, generation checks, and a storage inventory entry.
    ///
    /// Clients register their participants every time they open the
    /// workspace, so an unchanged registration is only read: rewriting it
    /// would turn every read-only open into a ledger write.
    pub fn register_retention_participant(
        &mut self,
        participant: crate::lifecycle::RetentionParticipant,
    ) -> crate::error::Result<crate::lifecycle::RetentionParticipant> {
        participant
            .validate()
            .map_err(crate::error::Failure::InvalidCommand)?;
        if self.retention_participant(&participant.name)?.as_ref() == Some(&participant) {
            return Ok(participant);
        }
        self.connection.execute(
            "INSERT INTO retention_participants (name, storage_role, supports_invalidation,
                 supports_purge, checks_generation, inventory_locator, registered_at_ns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(name) DO UPDATE SET storage_role = excluded.storage_role,
                 supports_invalidation = excluded.supports_invalidation,
                 supports_purge = excluded.supports_purge,
                 checks_generation = excluded.checks_generation,
                 inventory_locator = excluded.inventory_locator,
                 registered_at_ns = excluded.registered_at_ns",
            rusqlite::params![
                participant.name,
                participant.storage_role,
                i64::from(participant.supports_invalidation),
                i64::from(participant.supports_purge),
                i64::from(participant.checks_generation),
                participant.inventory_locator,
                self.clock.now().nanos(),
            ],
        )?;
        self.retention_participant(&participant.name)?
            .ok_or_else(|| {
                crate::error::Failure::InvalidCommand(
                    "retention participant registration disappeared".to_owned(),
                )
            })
    }

    /// Read one retention participant registration.
    pub fn retention_participant(
        &self,
        name: &str,
    ) -> crate::error::Result<Option<crate::lifecycle::RetentionParticipant>> {
        self.connection
            .query_row(
                "SELECT name, storage_role, supports_invalidation, supports_purge,
                        checks_generation, inventory_locator
                 FROM retention_participants WHERE name = ?1",
                rusqlite::params![name],
                |row| {
                    Ok(crate::lifecycle::RetentionParticipant {
                        name: row.get(0)?,
                        storage_role: row.get(1)?,
                        supports_invalidation: row.get::<_, i64>(2)? != 0,
                        supports_purge: row.get::<_, i64>(3)? != 0,
                        checks_generation: row.get::<_, i64>(4)? != 0,
                        inventory_locator: row.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(crate::error::Failure::from)
    }

    /// Read a projection registration.
    pub fn projection(&self, name: &str) -> crate::error::Result<Option<ProjectionState>> {
        let row = self
            .connection
            .query_row(
                "SELECT revision_id, revision_sequence, schema_version, rule_version,
                        index_version, scope, eligibility_generation, built_at_ns
                 FROM projections WHERE name = ?1",
                rusqlite::params![name],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            revision,
            sequence,
            schema_version,
            rule_version,
            index_version,
            scope,
            generation,
            built_at,
        )) = row
        else {
            return Ok(None);
        };
        Ok(Some(ProjectionState {
            name: name.to_owned(),
            revision: revision_from_blob(&revision)?,
            sequence: db_u64(sequence, "sequence")?,
            schema_version: db_u32(schema_version, "schema version")?,
            rule_version,
            index_version,
            scope,
            eligibility_generation: db_u64(generation, "generation")?,
            built_at_ns: built_at,
        }))
    }

    /// Resolve a projection for a requested revision and scope.
    ///
    /// The generation, scope and revision fences are checked here. A consumer
    /// that also declares schema, rule or index versions must use
    /// [`Workspace::resolve_projection_versions`] so an incompatible projection
    /// is rejected instead of being served.
    pub fn resolve_projection(
        &self,
        name: &str,
        requested: mneme_core::WorkspaceRevisionId,
        scope: &mneme_core::ScopeId,
    ) -> crate::error::Result<ProjectionResolution> {
        self.resolve_projection_required(name, requested, scope, None)
    }

    /// Resolve a projection the consumer requires schema, rule and index
    /// versions for.
    #[allow(unknown_lints, too_many_parameters)] // consumers pass the required versions positionally; the arity is public API
    pub fn resolve_projection_versions(
        &self,
        name: &str,
        requested: mneme_core::WorkspaceRevisionId,
        scope: &mneme_core::ScopeId,
        schema_version: u32,
        rule_version: &str,
        index_version: &str,
    ) -> crate::error::Result<ProjectionResolution> {
        self.resolve_projection_required(
            name,
            requested,
            scope,
            Some((schema_version, rule_version, index_version)),
        )
    }

    fn resolve_projection_required(
        &self,
        name: &str,
        requested: mneme_core::WorkspaceRevisionId,
        scope: &mneme_core::ScopeId,
        required_versions: Option<(u32, &str, &str)>,
    ) -> crate::error::Result<ProjectionResolution> {
        let Some(projection) = self.projection(name)? else {
            return Ok(ProjectionResolution::Missing);
        };
        let current = self.eligibility_generation()?;
        if projection.eligibility_generation != current {
            return Ok(ProjectionResolution::BarrierAdvanced {
                projection,
                current,
            });
        }
        if projection.scope != scope.to_string() {
            return Ok(ProjectionResolution::ScopeMismatch {
                projection,
                requested_scope: scope.to_string(),
            });
        }
        if let Some((schema_version, rule_version, index_version)) = required_versions
            && (projection.schema_version != schema_version
                || projection.rule_version != rule_version
                || projection.index_version != index_version)
        {
            return Ok(ProjectionResolution::VersionMismatch {
                projection,
                schema_version,
                rule_version: rule_version.to_owned(),
                index_version: index_version.to_owned(),
            });
        }
        if projection.revision != requested {
            return Ok(ProjectionResolution::Behind {
                projection,
                requested,
            });
        }
        Ok(ProjectionResolution::Compatible(projection))
    }

    /// Read the current committed snapshot.
    ///
    /// A record envelope this handle already decoded and verified is served from
    /// its decode cache while the blob is unchanged; see [`Workspace::snapshot_at`].
    pub fn snapshot(&self) -> crate::error::Result<Snapshot> {
        let revision = self.current_revision()?;
        self.snapshot_at(revision, None)
    }

    /// Read a pinned snapshot, requiring a matching eligibility generation.
    ///
    /// Each record envelope is read once per handle while its blob is unchanged.
    /// A payload this handle already decoded and verified is served from its
    /// decode cache only while the blob file still has the length, modification
    /// time, device and inode it had when the bytes were verified, which costs one
    /// metadata call and no content read. A removed payload is an integrity
    /// failure; a rewritten one has a different identity, so it is read again and
    /// fails its digest check. In-place corruption that preserves both length and
    /// modification time is detected by a handle that has not read the record and
    /// by [`Workspace::recover`], not by the warm cache. A retained source whose
    /// bytes this handle verified is confirmed by one metadata call instead of a
    /// content read, under the same identity and generation rules.
    ///
    /// Every ledger statement of the load runs inside one read transaction, so
    /// the record set, its history index, the manifest journal and the current
    /// source states all describe one committed revision.
    pub fn snapshot_at(
        &self,
        revision: mneme_core::WorkspaceRevisionId,
        pinned_generation: Option<u64>,
    ) -> crate::error::Result<Snapshot> {
        self.snapshot_checked(revision, pinned_generation, PayloadCheck::Cached)
    }

    /// Read the current snapshot with every record payload re-hashed from disk.
    ///
    /// Recovery must observe a corrupted payload even when this handle already
    /// decoded it, so it never consults the decode cache.
    fn snapshot_from_disk(&self) -> crate::error::Result<Snapshot> {
        let revision = self.current_revision()?;
        self.snapshot_checked(revision, None, PayloadCheck::FromDisk)
    }

    fn snapshot_checked(
        &self,
        revision: mneme_core::WorkspaceRevisionId,
        pinned_generation: Option<u64>,
        check: PayloadCheck,
    ) -> crate::error::Result<Snapshot> {
        self.require_restore_suppression()?;
        let row = revision_row_by_id(&self.connection, revision)?.ok_or_else(|| {
            crate::error::Failure::Integrity {
                revision,
                reason: "revision is not present in the ledger".to_owned(),
            }
        })?;
        let generation = self.eligibility_generation()?;
        if let Some(pinned) = pinned_generation
            && pinned != generation
        {
            return Err(crate::error::Failure::BarrierAdvanced {
                pinned,
                current: generation,
            });
        }
        let snapshot = self
            .load_snapshot_checked(row, generation, check)
            .map_err(|error| self.explain_barrier(error, generation))?;
        let after = self.eligibility_generation()?;
        if after != generation {
            return Err(crate::error::Failure::BarrierAdvanced {
                pinned: generation,
                current: after,
            });
        }
        Ok(snapshot)
    }

    /// The barrier change that explains a missing payload, when the erasure
    /// generation moved since the read was pinned.
    ///
    /// A forget commits its barrier and then purges committed payloads, so a
    /// payload that disappears while a read pinned to the older generation is
    /// running is a barrier change rather than corruption; an absence at an
    /// unchanged generation stays the payload's own integrity failure.
    fn barrier_after_missing_payload(&self, generation: u64) -> Option<crate::error::Failure> {
        let current = self.eligibility_generation().ok()?;
        if current == generation {
            return None;
        }
        Some(crate::error::Failure::BarrierAdvanced {
            pinned: generation,
            current,
        })
    }

    /// Explain a failed read by the barrier change that landed while it ran.
    ///
    /// The payload checks run inside the read transaction that pins their ledger
    /// state, so they see a barrier only when it was committed before the read
    /// started. A barrier another handle commits during the read removes payloads
    /// the pinned state still requires, so the generation is compared here, after
    /// the transaction is closed, and an absent payload is reported as the barrier
    /// change it is instead of as corruption.
    fn explain_barrier(
        &self,
        error: crate::error::Failure,
        generation: u64,
    ) -> crate::error::Failure {
        let is_payload_absence = matches!(
            &error,
            crate::error::Failure::Integrity { .. } | crate::error::Failure::MissingBlob { .. }
        );
        if !is_payload_absence {
            return error;
        }
        match self.barrier_after_missing_payload(generation) {
            Some(barrier) => barrier,
            None => error,
        }
    }

    fn load_snapshot_checked(
        &self,
        row: RevisionRow,
        generation: u64,
        check: PayloadCheck,
    ) -> crate::error::Result<Snapshot> {
        let transaction = self.connection.unchecked_transaction()?;
        let loaded = self.load_snapshot_in(&transaction, &row, generation, check);
        match loaded {
            Ok(snapshot) => {
                transaction.commit()?;
                Ok(snapshot)
            }
            Err(error) => {
                // Dropping the transaction rolls it back, so a failed load never
                // leaves a read transaction open behind it.
                drop(transaction);
                Err(error)
            }
        }
    }

    /// Load one snapshot's record set and retained sources from one ledger state.
    ///
    /// Every statement runs on the caller's read transaction, so the load takes
    /// the WAL read lock once and sees one committed revision from its first
    /// statement to its last. Source bytes are the only payloads verified here
    /// that `load_records` did not already cover: every live record payload was
    /// verified there, while a historical manifest may name a blob that only a
    /// forgotten record or an authorized pruned source referenced.
    fn load_snapshot_in(
        &self,
        connection: &rusqlite::Connection,
        row: &RevisionRow,
        generation: u64,
        check: PayloadCheck,
    ) -> crate::error::Result<Snapshot> {
        let snapshot = self.build_snapshot_in(connection, row, generation, check)?;
        // A blob that is only referenced by a forgotten record or by an
        // authorized pruned source need not remain on disk, so only the sources
        // a visible record still retains are required.
        let current_sources = self.source_states_in(connection)?;
        let wanted = required_source_digests(&snapshot.records, &current_sources);
        if wanted.is_empty() {
            return Ok(snapshot);
        }
        let keys = wanted
            .iter()
            .map(|digest| *digest.as_bytes())
            .collect::<std::collections::BTreeSet<_>>();
        let blob_lengths = publishing::blob_lengths_for(connection, &keys)?;
        self.verify_snapshot_sources(&wanted, &blob_lengths, generation, snapshot.revision)?;
        Ok(snapshot)
    }

    /// Build one pinned snapshot inside a single read transaction.
    fn build_snapshot(
        &self,
        row: &RevisionRow,
        generation: u64,
        check: PayloadCheck,
    ) -> crate::error::Result<Snapshot> {
        let transaction = self.connection.unchecked_transaction()?;
        let built = self.build_snapshot_in(&transaction, row, generation, check);
        match built {
            Ok(snapshot) => {
                transaction.commit()?;
                Ok(snapshot)
            }
            Err(error) => {
                drop(transaction);
                Err(error)
            }
        }
    }

    /// Build one pinned snapshot from its membership and record payloads.
    fn build_snapshot_in(
        &self,
        connection: &rusqlite::Connection,
        row: &RevisionRow,
        generation: u64,
        check: PayloadCheck,
    ) -> crate::error::Result<Snapshot> {
        let revision = row.revision;
        // A barrier committed anywhere drops what this handle decoded under the
        // older generation before any of it can be served.
        self.facts().align(generation);
        let forgotten = sweep::forgotten_suppressions_in(connection)?;
        let (records, manifest_records) = self.load_records(
            &RecordLoad {
                connection,
                sequence: row.sequence,
                revision,
                generation,
                check,
            },
            &forgotten,
        )?;
        // The committed manifest identity binds the complete record set, so a
        // membership row that was added, removed or left open by corruption
        // cannot match it.
        reconstructed_manifest(connection, row, manifest_records)?;
        let index = snapshot_index(connection, &records, revision, row.sequence, &forgotten)?;
        Ok(Snapshot {
            revision,
            sequence: row.sequence,
            parent: row.parent,
            manifest_digest: row.manifest_digest,
            eligibility_generation: generation,
            records,
            index,
        })
    }

    /// Verify the retained source bytes a snapshot still requires.
    ///
    /// A source whose file identity and recorded length this handle already
    /// verified is confirmed by one metadata call and no content read; anything
    /// else is read and hashed from disk, so a removed or rewritten source fails
    /// exactly as before.
    fn verify_snapshot_sources(
        &self,
        required: &std::collections::BTreeSet<mneme_core::ContentDigest>,
        blob_lengths: &BlobIndex,
        generation: u64,
        revision: mneme_core::WorkspaceRevisionId,
    ) -> crate::error::Result<()> {
        let facts = self.facts();
        for digest in required {
            let Some((_, length, _, _)) = blob_lengths.get(digest.as_bytes()).copied() else {
                if let Some(barrier) = self.barrier_after_missing_payload(generation) {
                    return Err(barrier);
                }
                return Err(crate::error::Failure::MissingBlob {
                    digest: digest.to_hex(),
                });
            };
            if facts.source_verified(&self.root, *digest, length) {
                continue;
            }
            let identity_before = blob_file_identity(&self.root, *digest);
            crate::payload::verify(&self.root, *digest, length).map_err(|error| {
                if matches!(&error, crate::error::Failure::MissingBlob { .. })
                    && let Some(barrier) = self.barrier_after_missing_payload(generation)
                {
                    return barrier;
                }
                crate::error::Failure::Integrity {
                    revision,
                    reason: format!("required source blob {digest} failed verification: {error}"),
                }
            })?;
            // Only a file that was the same before and after the read, at the
            // length that was hashed, may be recorded as verified.
            let verified = usize::try_from(length).ok().and_then(|encoded_bytes| {
                stable_blob_identity(&self.root, *digest, identity_before, encoded_bytes)
            });
            if let Some(file) = verified {
                facts.store_source(*digest, length, file);
            }
        }
        Ok(())
    }

    fn load_records(
        &self,
        load: &RecordLoad<'_>,
        forgotten: &sweep::ForgottenSuppressions,
    ) -> crate::error::Result<(
        Vec<mneme_core::RecordEnvelope>,
        std::collections::BTreeSet<crate::catalog::ManifestRecord>,
    )> {
        let revision = load.revision;
        let rows = membership_entries(load.connection, load.sequence, None)?;
        // A presence-only load reads no content, so the ledger's recorded length
        // replaces the hash it would otherwise compute. One statement answers it
        // for the whole record set instead of one per record.
        let lengths = if load.check.needs_ledger_lengths() {
            let keys = rows
                .iter()
                .map(|entry| digest_32(&entry.3))
                .collect::<crate::error::Result<std::collections::BTreeSet<_>>>()?;
            publishing::blob_lengths_for(load.connection, &keys)?
        } else {
            BlobIndex::new()
        };
        let mut records = Vec::with_capacity(rows.len());
        let mut manifest_records = std::collections::BTreeMap::new();
        for entry in &rows {
            let (record_id, revision_id, kind) = membership_record(entry, revision)?;
            let (_, _, _, envelope_digest, payload_digest, full_digest) = entry;
            if manifest_records
                .insert(
                    record_id,
                    crate::catalog::ManifestRecord {
                        record_id,
                        revision_id,
                        kind,
                    },
                )
                .is_some()
            {
                return Err(crate::error::Failure::Integrity {
                    revision,
                    reason: "snapshot membership names two revisions of one record".to_owned(),
                });
            }
            if forgotten.matches(record_id, revision_id) {
                continue;
            }
            records.push(self.load_verified_record_envelope(
                VerifiedRecordEnvelopeInput {
                    record_id,
                    revision_id,
                    kind,
                    envelope_digest,
                    payload_digest,
                    full_digest,
                    revision,
                    generation: load.generation,
                    lengths: &lengths,
                },
                load.check,
            )?);
        }
        Ok((records, manifest_records.into_values().collect()))
    }

    /// Load one record envelope, verifying it against its ledger row.
    ///
    /// A cache-serving load returns this handle's decoded envelope when the
    /// committed digest is already known: payloads are content addressed, so a
    /// hit is the same value the ledger row names, and the entry's recorded
    /// identity is compared with the row before it is served. The hit is only
    /// taken while the blob file still has the identity recorded when its bytes
    /// were verified; otherwise the entry is dropped and the payload is read and
    /// verified from disk again.
    fn load_verified_record_envelope(
        &self,
        input: VerifiedRecordEnvelopeInput<'_>,
        check: PayloadCheck,
    ) -> crate::error::Result<mneme_core::RecordEnvelope> {
        let VerifiedRecordEnvelopeInput {
            record_id,
            revision_id,
            kind,
            envelope_digest,
            payload_digest,
            full_digest,
            revision,
            generation,
            lengths,
        } = input;
        let digest = digest_with(
            envelope_digest,
            "preserves-canonical-binary-v1",
            "full-record",
            revision,
        )?;
        // The two ledger columns name the same digest; a cache hit skips the
        // recomputation a fresh read performs, so the columns are compared here
        // for both paths.
        if digest.as_bytes().as_slice() != full_digest {
            return Err(crate::error::Failure::Integrity {
                revision,
                reason: format!("record blob {digest} does not match its ledger identity"),
            });
        }
        let payload_digest = digest_with(
            payload_digest,
            "preserves-canonical-binary-v1",
            "payload",
            revision,
        )?;
        let identity = EnvelopeIdentity {
            record_id,
            revision_id,
            kind,
            full_digest,
        };
        if let Some(cached) =
            self.cached_envelope(digest, &identity, payload_digest, revision, check)?
        {
            return Ok(cached);
        }
        let identity_before = if check.caches() {
            blob_file_identity(&self.root, digest)
        } else {
            None
        };
        let bytes = self.read_envelope_bytes(digest, check, lengths, generation, revision)?;
        let record = decode_envelope(&bytes, digest, revision)?;
        require_envelope_identity(&identity, &record, digest, payload_digest, revision)?;
        if check.caches() {
            self.remember_envelope(
                digest,
                &record,
                payload_digest,
                identity_before,
                bytes.len(),
            );
        }
        Ok(record)
    }

    /// Record one freshly verified envelope while its file identity is stable.
    ///
    /// A file that changed between the two metadata calls, or that no longer has
    /// the length that was hashed, is not recorded and is read again next time.
    fn remember_envelope(
        &self,
        digest: mneme_core::ContentDigest,
        record: &mneme_core::RecordEnvelope,
        payload_digest: mneme_core::ContentDigest,
        identity_before: Option<FileIdentity>,
        encoded_bytes: usize,
    ) {
        let verified = stable_blob_identity(&self.root, digest, identity_before, encoded_bytes);
        if let Some(file) = verified {
            self.facts().store_envelope(
                digest,
                record.clone(),
                payload_digest,
                encoded_bytes,
                file,
            );
        }
    }

    /// This handle's decoded copy of one record envelope, when the identity the
    /// ledger row records is the identity the entry was verified with and the
    /// blob file still has the identity it had when the bytes were verified.
    ///
    /// A load mode that re-reads from disk never consults or fills the cache.
    fn cached_envelope(
        &self,
        digest: mneme_core::ContentDigest,
        identity: &EnvelopeIdentity<'_>,
        payload_digest: mneme_core::ContentDigest,
        revision: mneme_core::WorkspaceRevisionId,
        check: PayloadCheck,
    ) -> crate::error::Result<Option<mneme_core::RecordEnvelope>> {
        if !check.caches() {
            return Ok(None);
        }
        let recorded = self.facts().recorded_envelope(&self.root, digest);
        let Some((record, cached_payload_digest)) = recorded else {
            return Ok(None);
        };
        if record.record_id != identity.record_id
            || record.revision_id != identity.revision_id
            || record.kind != identity.kind
            || cached_payload_digest != payload_digest
        {
            return Err(crate::error::Failure::Integrity {
                revision,
                reason: format!("record blob {digest} does not match its ledger identity"),
            });
        }
        Ok(Some(record))
    }

    /// Read one record blob's bytes, explaining a vanished payload by the
    /// erasure generation it was pinned to rather than as corruption.
    ///
    /// A presence-only load trusts the ledger for the length instead of hashing
    /// the file, because the commit path hashes every blob it stages and checks
    /// each inherited blob for presence at its recorded length.
    fn read_envelope_bytes(
        &self,
        digest: mneme_core::ContentDigest,
        check: PayloadCheck,
        lengths: &BlobIndex,
        generation: u64,
        revision: mneme_core::WorkspaceRevisionId,
    ) -> crate::error::Result<Vec<u8>> {
        let read = match check {
            PayloadCheck::FromDisk | PayloadCheck::Cached => {
                crate::payload::read(&self.root, digest)
            }
            PayloadCheck::Presence => {
                let Some((_, length, _, _)) = lengths.get(digest.as_bytes()).copied() else {
                    return Err(crate::error::Failure::Integrity {
                        revision,
                        reason: format!("record blob {digest} has no ledger entry"),
                    });
                };
                crate::payload::read_with_length(&self.root, digest, length)
            }
        };
        read.map_err(|error| {
            if matches!(&error, crate::error::Failure::MissingBlob { .. })
                && let Some(barrier) = self.barrier_after_missing_payload(generation)
            {
                return barrier;
            }
            crate::error::Failure::Integrity {
                revision,
                reason: format!("record blob {digest} is unavailable: {error}"),
            }
        })
    }

    /// All retained revisions of one record identity, in recorded order.
    ///
    /// This is the historical view used by evidence correction and lineage
    /// checks; each envelope is loaded from its verified blob. The revision list
    /// and the envelopes it names are read from one ledger state.
    pub fn record_revisions(
        &self,
        record_id: mneme_core::RecordId,
    ) -> crate::error::Result<Vec<mneme_core::RecordEnvelope>> {
        self.require_restore_suppression()?;
        let context = self.current_revision()?;
        let generation = self.eligibility_generation()?;
        let transaction = self.connection.unchecked_transaction()?;
        let loaded = self.record_revisions_in(&transaction, record_id, context, generation);
        match loaded {
            Ok(records) => {
                transaction.commit()?;
                Ok(records)
            }
            Err(error) => {
                // Dropping the transaction rolls it back, so a failed history
                // read leaves nothing open behind it, and the barrier that may
                // explain a purged payload is read from the ledger as it stands.
                drop(transaction);
                Err(self.explain_barrier(error, generation))
            }
        }
    }

    /// Read one record's retained history from one ledger state.
    fn record_revisions_in(
        &self,
        connection: &rusqlite::Connection,
        record_id: mneme_core::RecordId,
        context: mneme_core::WorkspaceRevisionId,
        generation: u64,
    ) -> crate::error::Result<Vec<mneme_core::RecordEnvelope>> {
        self.facts().align(generation);
        let forgotten = sweep::forgotten_suppressions_in(connection)?;
        if forgotten.identities.contains(&record_id) {
            return Err(crate::error::Failure::RetentionSuppressed {
                target: record_id.to_string(),
            });
        }
        let mut statement = connection.prepare(
            "SELECT revision_id, kind, envelope_digest, payload_digest, full_digest
             FROM records WHERE record_id = ?1
             ORDER BY recorded_order, recorded_at_ns, revision_id",
        )?;
        let rows = statement
            .query_map(rusqlite::params![record_id.as_bytes().as_slice()], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        // A cache-serving load never needs the ledger's recorded lengths.
        let lengths = BlobIndex::new();
        let mut records = Vec::with_capacity(rows.len());
        for (revision_id, kind, envelope_digest, payload_digest, full_digest) in rows {
            let revision_id = revision_id_from_blob(&revision_id, context)?;
            if forgotten.revisions.contains(&(record_id, revision_id)) {
                continue;
            }
            let kind = mneme_core::RecordKind::parse(&kind).ok_or_else(|| {
                crate::error::Failure::Integrity {
                    revision: context,
                    reason: format!("unknown record kind {kind}"),
                }
            })?;
            records.push(self.load_verified_record_envelope(
                VerifiedRecordEnvelopeInput {
                    record_id,
                    revision_id,
                    kind,
                    envelope_digest: &envelope_digest,
                    payload_digest: &payload_digest,
                    full_digest: &full_digest,
                    revision: context,
                    generation,
                    lengths: &lengths,
                },
                PayloadCheck::Cached,
            )?);
        }
        Ok(records)
    }

    /// Every retained revision of every record a snapshot contains.
    ///
    /// One ordered scan answers the whole snapshot's history question instead of
    /// one read transaction and one statement per record, and for each record of
    /// `snapshot` the list is exactly what [`Workspace::record_revisions`]
    /// returns: the same envelopes in the same recorded order, the same forgotten
    /// identity refusing the read and forgotten revisions being skipped, and every
    /// served envelope verified through this handle's record cache with one
    /// identity check per envelope. The restore gate and the barrier explanation
    /// for a purged payload apply unchanged.
    pub fn record_histories(
        &self,
        snapshot: &Snapshot,
    ) -> crate::error::Result<
        std::collections::BTreeMap<mneme_core::RecordId, Vec<mneme_core::RecordEnvelope>>,
    > {
        self.require_restore_suppression()?;
        let context = self.current_revision()?;
        let generation = self.eligibility_generation()?;
        let transaction = self.connection.unchecked_transaction()?;
        let loaded = self.record_histories_in(&transaction, snapshot, context, generation);
        match loaded {
            Ok(histories) => {
                transaction.commit()?;
                Ok(histories)
            }
            Err(error) => {
                // Dropping the transaction rolls it back, so a failed history
                // read leaves nothing open behind it, and the barrier that may
                // explain a purged payload is read from the ledger as it stands.
                drop(transaction);
                Err(self.explain_barrier(error, generation))
            }
        }
    }

    /// Read every snapshot record's retained history from one ledger state.
    ///
    /// The rows are ordered by record identity and then by the recorded order
    /// `record_revisions` uses, so each list is that read's answer. Rows of records
    /// the snapshot does not contain are skipped before any payload is loaded, and
    /// the scan streams the ledger rows instead of collecting a row buffer, so no
    /// per-record statement and no record-count bound is needed.
    fn record_histories_in(
        &self,
        connection: &rusqlite::Connection,
        snapshot: &Snapshot,
        context: mneme_core::WorkspaceRevisionId,
        generation: u64,
    ) -> crate::error::Result<
        std::collections::BTreeMap<mneme_core::RecordId, Vec<mneme_core::RecordEnvelope>>,
    > {
        self.facts().align(generation);
        let forgotten = sweep::forgotten_suppressions_in(connection)?;
        let mut histories = snapshot
            .records
            .iter()
            .map(|record| {
                if forgotten.identities.contains(&record.record_id) {
                    Err(crate::error::Failure::RetentionSuppressed {
                        target: record.record_id.to_string(),
                    })
                } else {
                    Ok((record.record_id, Vec::new()))
                }
            })
            .collect::<crate::error::Result<
                std::collections::BTreeMap<mneme_core::RecordId, Vec<mneme_core::RecordEnvelope>>,
            >>()?;
        let mut statement = connection.prepare(
            "SELECT record_id, revision_id, kind, envelope_digest, payload_digest, full_digest
             FROM records
             ORDER BY record_id, recorded_order, recorded_at_ns, revision_id",
        )?;
        let mut rows = statement.query([])?;
        // A cache-serving load never needs the ledger's recorded lengths.
        let lengths = BlobIndex::new();
        while let Some(row) = rows.next()? {
            let record_id = record_id_from_blob(&row.get::<_, Vec<u8>>(0)?, context)?;
            let Some(history) = histories.get_mut(&record_id) else {
                continue;
            };
            let revision_id = revision_id_from_blob(&row.get::<_, Vec<u8>>(1)?, context)?;
            if forgotten.revisions.contains(&(record_id, revision_id)) {
                continue;
            }
            let kind = row.get::<_, String>(2)?;
            let kind = mneme_core::RecordKind::parse(&kind).ok_or_else(|| {
                crate::error::Failure::Integrity {
                    revision: context,
                    reason: format!("unknown record kind {kind}"),
                }
            })?;
            let envelope_digest = row.get::<_, Vec<u8>>(3)?;
            let payload_digest = row.get::<_, Vec<u8>>(4)?;
            let full_digest = row.get::<_, Vec<u8>>(5)?;
            history.push(self.load_verified_record_envelope(
                VerifiedRecordEnvelopeInput {
                    record_id,
                    revision_id,
                    kind,
                    envelope_digest: &envelope_digest,
                    payload_digest: &payload_digest,
                    full_digest: &full_digest,
                    revision: context,
                    generation,
                    lengths: &lengths,
                },
                PayloadCheck::Cached,
            )?);
        }
        Ok(histories)
    }

    /// Committed workspace revisions and their monotonic sequences.
    ///
    /// This is the whole inventory, for audit and tests, and it refuses above the
    /// 1M entry bound. A view reads only the revisions it names through
    /// [`Workspace::revision_sequences_for`].
    pub fn revision_sequences(
        &self,
    ) -> crate::error::Result<std::collections::BTreeMap<mneme_core::WorkspaceRevisionId, u64>>
    {
        let mut statement = self
            .connection
            .prepare("SELECT revision_id, sequence FROM revisions")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut sequences = std::collections::BTreeMap::new();
        let max_revision_sequences = 1_000_000;
        for row in rows {
            let (revision, sequence) = row?;
            if sequences.len() >= max_revision_sequences {
                return Err(crate::error::Failure::UnsupportedLayout(
                    "revision sequence inventory exceeds the 1M entry bound".to_owned(),
                ));
            }
            sequences.insert(
                revision_from_blob(&revision)?,
                db_u64(sequence, "sequence")?,
            );
        }
        Ok(sequences)
    }

    /// The sequences of the named revisions.
    ///
    /// Only the caller's revisions are read, one statement per batch over the
    /// unique `revision_id` index, so the answer is bounded by that set instead of
    /// the whole revision inventory and needs no inventory bound. A revision that
    /// is not committed in this workspace is absent from the result.
    pub fn revision_sequences_for(
        &self,
        revisions: &std::collections::BTreeSet<mneme_core::WorkspaceRevisionId>,
    ) -> crate::error::Result<std::collections::BTreeMap<mneme_core::WorkspaceRevisionId, u64>>
    {
        let transaction = self.connection.unchecked_transaction()?;
        let loaded = revision_sequences_lookup(&transaction, revisions);
        match loaded {
            Ok(sequences) => {
                transaction.commit()?;
                Ok(sequences)
            }
            Err(error) => {
                // Dropping the transaction rolls it back, so a failed lookup
                // leaves nothing open behind it.
                drop(transaction);
                Err(error)
            }
        }
    }

    /// The committed revision that has exactly this sequence, if any.
    ///
    /// The sequence is the revisions table's primary key, so one indexed
    /// statement answers a caller that holds a sequence instead of the whole
    /// revision inventory. The restore gate is the one every read takes, and a
    /// sequence no committed revision occupies is `None`.
    pub fn revision_at_sequence(
        &self,
        sequence: u64,
    ) -> crate::error::Result<Option<mneme_core::WorkspaceRevisionId>> {
        self.require_restore_suppression()?;
        let stored = self
            .connection
            .query_row(
                "SELECT revision_id FROM revisions WHERE sequence = ?1",
                rusqlite::params![db_i64(sequence, "sequence")?],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        let Some(bytes) = stored else {
            return Ok(None);
        };
        Ok(Some(revision_from_blob(&bytes)?))
    }
}

/// Named revisions one lookup statement answers.
///
/// The caller's set bounds the read, so no inventory cap applies; batching only
/// keeps the statement inside SQLite's bound-parameter limit. A short last batch
/// binds its final revision again to fill the fixed parameter list, which leaves
/// the selected rows unchanged.
const MAX_NAMED_REVISIONS: usize = 256;

/// The sequences of the named committed revisions from one ledger state.
fn revision_sequences_lookup(
    connection: &rusqlite::Connection,
    revisions: &std::collections::BTreeSet<mneme_core::WorkspaceRevisionId>,
) -> crate::error::Result<std::collections::BTreeMap<mneme_core::WorkspaceRevisionId, u64>> {
    let mut sequences = std::collections::BTreeMap::new();
    let named = revisions.iter().copied().collect::<Vec<_>>();
    let batch_size = named.len().min(MAX_NAMED_REVISIONS);
    if batch_size == 0 {
        return Ok(sequences);
    }
    let placeholders = (1..=batch_size)
        .map(|position| format!("?{position}"))
        .collect::<Vec<_>>()
        .join(", ");
    let query = format!(
        "SELECT revision_id, sequence FROM revisions WHERE revision_id IN ({placeholders})"
    );
    let mut statement = connection.prepare(&query)?;
    for batch in named.chunks(batch_size) {
        let Some(repeated) = batch.last().copied() else {
            continue;
        };
        let padding = batch_size.saturating_sub(batch.len());
        let params = batch
            .iter()
            .map(|revision| revision.as_bytes().as_slice())
            .chain(std::iter::repeat_n(repeated.as_bytes().as_slice(), padding));
        let mut rows = statement.query(rusqlite::params_from_iter(params))?;
        while let Some(row) = rows.next()? {
            // Every row answers one named revision, so the named set bounds
            // the result.
            if sequences.len() >= named.len() {
                return Err(crate::error::Failure::UnsupportedLayout(
                    "revision lookup returned more rows than revisions were named".to_owned(),
                ));
            }
            let revision = revision_from_blob(&row.get::<_, Vec<u8>>(0)?)?;
            sequences.insert(revision, db_u64(row.get::<_, i64>(1)?, "sequence")?);
        }
    }
    Ok(sequences)
}

/// Whether a source record's current revision records pruned bytes.
///
/// A pruned revision is an authorized absence, never corruption: once a source
/// record's current revision is pruned, every digest any retained revision of
/// that record bound is allowed to be absent. The erasure it records reaches the
/// source's history, not only the one digest the pruned revision still names.
fn source_payload_pruned(
    current: &std::collections::BTreeMap<mneme_core::RecordId, SourcePresence>,
    record: mneme_core::RecordId,
) -> bool {
    matches!(current.get(&record), Some(SourcePresence::Unavailable(_)))
}

/// The retained source digests a snapshot's visible records still require.
///
/// A record that retains no bytes, and a record whose current revision records a
/// pruned absence, contributes nothing: its payload is allowed to be gone.
fn required_source_digests(
    records: &[mneme_core::RecordEnvelope],
    current: &std::collections::BTreeMap<mneme_core::RecordId, SourcePresence>,
) -> std::collections::BTreeSet<mneme_core::ContentDigest> {
    let mut required = std::collections::BTreeSet::new();
    for record in records {
        let Some(digest) = validation::retained_source_digest(record) else {
            continue;
        };
        if source_payload_pruned(current, record.record_id) {
            continue;
        }
        required.insert(digest);
    }
    required
}

/// The snapshot index of one committed revision.
///
/// One statement answers the whole snapshot's history question instead of one
/// statement per record, and it names every retained revision of every record,
/// not only the revision a snapshot currently holds. A pinned snapshot knows only
/// the revisions that existed when it was committed, so a later revision never
/// becomes a valid pin for a historical read, and a record the snapshot no longer
/// contains contributes nothing.
fn snapshot_index(
    connection: &rusqlite::Connection,
    records: &[mneme_core::RecordEnvelope],
    revision: mneme_core::WorkspaceRevisionId,
    sequence: u64,
    forgotten: &sweep::ForgottenSuppressions,
) -> crate::error::Result<mneme_core::SnapshotIndex> {
    let mut index = mneme_core::SnapshotIndex::new();
    for record in records {
        index.insert(record.record_id, record.kind, record.revision_id);
    }
    let sequence = db_i64(sequence, "revision sequence")?;
    let mut statement = connection.prepare_cached(
        "SELECT record_id, revision_id FROM records
         WHERE recorded_order <= ?1
         ORDER BY record_id, recorded_order, recorded_at_ns, revision_id",
    )?;
    let mut rows = statement.query(rusqlite::params![sequence])?;
    while let Some(row) = rows.next()? {
        let record_id = record_id_from_blob(&row.get::<_, Vec<u8>>(0)?, revision)?;
        let retained = revision_id_from_blob(&row.get::<_, Vec<u8>>(1)?, revision)?;
        // Only a record this snapshot contains has an index entry, and a forgotten
        // revision may not serve as a pin; the current revision is already the
        // entry the loop above recorded.
        if index.get(&record_id).is_none() || forgotten.matches(record_id, retained) {
            continue;
        }
        index.record_revision(record_id, retained);
    }
    Ok(index)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourcePresence {
    Retained(mneme_core::ContentDigest),
    Unavailable(Option<mneme_core::ContentDigest>),
    Unknown,
}

fn sync_directory(path: &std::path::Path) -> crate::error::Result<()> {
    std::fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| crate::error::Failure::io(path, error))
}

#[derive(Clone, Debug)]
struct RevisionRow {
    revision: mneme_core::WorkspaceRevisionId,
    sequence: u64,
    parent: Option<mneme_core::WorkspaceRevisionId>,
    manifest_digest: mneme_core::ContentDigest,
    eligibility_generation: u64,
}

#[derive(Clone, Debug)]
struct StoredCommand {
    request_digest: Vec<u8>,
    fingerprint: Option<Vec<u8>>,
    outcome_revision: mneme_core::WorkspaceRevisionId,
    outcome_sequence: u64,
}

impl StoredCommand {
    /// The kernel's view of this stored row.
    fn kernel(&self) -> crate::error::Result<mneme_kernel::admission::StoredCommand> {
        let fingerprint = match self.fingerprint.as_deref() {
            Some(bytes) => Some(mneme_core::kernel_digest(&digest_32(bytes)?)),
            None => None,
        };
        Ok(mneme_kernel::admission::StoredCommand {
            command: mneme_core::kernel_digest(&digest_32(&self.request_digest)?),
            fingerprint,
        })
    }
}

fn open_connection(root: &std::path::Path) -> crate::error::Result<rusqlite::Connection> {
    let ledger = root.join(LEDGER_FILE);
    let connection = rusqlite::Connection::open(&ledger)?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    add_command_fingerprint_column(&connection)?;
    Ok(connection)
}

/// Add the adapter fingerprint column to a ledger written before it existed.
///
/// The column is additive and nullable, so the ledger layout version does not
/// change: rows committed without a fingerprint replay by command digest.
fn add_command_fingerprint_column(connection: &rusqlite::Connection) -> crate::error::Result<()> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version != LAYOUT_VERSION {
        // A fresh or unsupported ledger is refused (or initialized) elsewhere;
        // never alter a layout this build does not understand.
        return Ok(());
    }
    let present: Option<i64> = connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'commands'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if present.is_none() {
        return Ok(());
    }
    let mut statement = connection.prepare("PRAGMA table_info(commands)")?;
    let mut is_found = false;
    for column in statement.query_map([], |row| row.get::<_, String>(1))? {
        if column? == "fingerprint" {
            is_found = true;
        }
    }
    drop(statement);
    if !is_found {
        connection.execute("ALTER TABLE commands ADD COLUMN fingerprint BLOB", [])?;
    }
    Ok(())
}

/// Mark a ledger written before the retention ledger as retention format 1.
///
/// Layout 1 predates the retention ledger. Upgrading in place is safe because no
/// prior write could have depended on suppression state; an explicit restore path
/// verifies that prerequisite.
fn ensure_retention_format(connection: &rusqlite::Connection) -> crate::error::Result<()> {
    let present = connection
        .query_row(
            "SELECT 1 FROM meta WHERE key = ?1",
            rusqlite::params![META_RETENTION_FORMAT],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    if present.is_none() {
        set_meta(connection, META_RETENTION_FORMAT, b"1")?;
    }
    Ok(())
}

/// Accept an empty directory, or clear the artifacts an interrupted
/// initialization left in it.
///
/// Initialization writes its schema, genesis revision and meta rows in one
/// transaction, so an interrupted attempt can only leave an empty directory,
/// the store's own empty directories, and a ledger whose transaction never
/// committed. Anything else is a user's data and is refused untouched; a store
/// directory that holds anything at all is not removable state.
fn clear_incomplete_workspace(root: &std::path::Path) -> crate::error::Result<()> {
    let entries = std::fs::read_dir(root)
        .map_err(|error| crate::error::Failure::io(root, error))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| crate::error::Failure::io(root, error))?;
    let mut removable = Vec::with_capacity(entries.len());
    for entry in entries {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| crate::error::Failure::io(&path, error))?;
        let is_removable_directory = file_type.is_dir()
            && is_workspace_directory(&entry.file_name())
            && is_empty_directory(&path)?;
        if (file_type.is_file() && is_artifact_file(&entry.file_name())) || is_removable_directory {
            removable.push(path);
            continue;
        }
        return Err(crate::error::Failure::UnsupportedLayout(format!(
            "{} is not empty",
            root.display()
        )));
    }
    if removable.is_empty() {
        return Ok(());
    }
    if !ledger_is_uninitialized(root)? {
        return Err(crate::error::Failure::UnsupportedLayout(format!(
            "{} is not empty",
            root.display()
        )));
    }
    for path in removable {
        let removed = if path.is_dir() {
            std::fs::remove_dir(&path)
        } else {
            std::fs::remove_file(&path)
        };
        removed.map_err(|error| crate::error::Failure::io(&path, error))?;
    }
    Ok(())
}

/// Whether a directory entry belongs to this workspace's ledger file family.
fn is_ledger_artifact(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    match name.strip_prefix(LEDGER_FILE) {
        // SQLite's write-ahead log and shared-memory files for this ledger.
        Some(suffix) => suffix.is_empty() || suffix == "-wal" || suffix == "-shm",
        None => false,
    }
}

/// Whether a directory entry names a store-owned file in the workspace root.
fn is_artifact_file(name: &std::ffi::OsStr) -> bool {
    is_ledger_artifact(name) || name == std::ffi::OsStr::new(LOCK_FILE)
}

/// Open the store-owned advisory lock file, creating it when it is absent.
fn open_lock_file(root: &std::path::Path) -> crate::error::Result<std::fs::File> {
    let path = root.join(LOCK_FILE);
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|error| crate::error::Failure::io(&path, error))
}

/// Whether a directory entry names one of the store's own directories.
fn is_workspace_directory(name: &std::ffi::OsStr) -> bool {
    match name.to_str() {
        Some(name) => {
            name == crate::payload::BLOB_DIRECTORY
                || name == crate::payload::STAGING_DIRECTORY
                || name == crate::payload::WORKING_DIRECTORY
        }
        None => false,
    }
}

/// Whether a directory holds no entries.
fn is_empty_directory(path: &std::path::Path) -> crate::error::Result<bool> {
    let mut entries =
        std::fs::read_dir(path).map_err(|error| crate::error::Failure::io(path, error))?;
    Ok(entries.next().is_none())
}

/// Whether the ledger in `root` was never given a genesis revision.
fn ledger_is_uninitialized(root: &std::path::Path) -> crate::error::Result<bool> {
    let ledger = root.join(LEDGER_FILE);
    if !ledger.is_file() {
        return Ok(true);
    }
    let connection = rusqlite::Connection::open(&ledger)?;
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    Ok(version != LAYOUT_VERSION)
}

fn meta_blob(connection: &rusqlite::Connection, key: &str) -> crate::error::Result<Vec<u8>> {
    connection
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            rusqlite::params![key],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .ok_or_else(|| crate::error::Failure::UnsupportedLayout(format!("ledger meta lacks {key}")))
}

/// Read an optional meta value, keeping a real ledger error distinct from
/// absence.
fn meta_blob_optional(
    connection: &rusqlite::Connection,
    key: &str,
) -> crate::error::Result<Option<Vec<u8>>> {
    connection
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            rusqlite::params![key],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(crate::error::Failure::from)
}

fn meta_u64(connection: &rusqlite::Connection, key: &str) -> crate::error::Result<u64> {
    let text = meta_blob(connection, key)?;
    let text = String::from_utf8(text).map_err(|_| {
        crate::error::Failure::UnsupportedLayout(format!("ledger meta {key} is not text"))
    })?;
    text.parse::<u64>().map_err(|_| {
        crate::error::Failure::UnsupportedLayout(format!("ledger meta {key} is not a u64"))
    })
}

fn set_meta(
    connection: &rusqlite::Connection,
    key: &str,
    value: &[u8],
) -> crate::error::Result<()> {
    connection.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![key, value],
    )?;
    Ok(())
}

fn set_meta_u64(
    connection: &rusqlite::Connection,
    key: &str,
    value: u64,
) -> crate::error::Result<()> {
    set_meta(connection, key, value.to_string().as_bytes())
}

/// The genesis revision identity recorded in one ledger.
///
/// A shared record cache and a suppression ledger are both bound to this
/// identity, so two workspaces are never confused by a path.
fn read_genesis(
    connection: &rusqlite::Connection,
) -> crate::error::Result<mneme_core::WorkspaceRevisionId> {
    let bytes: Option<Vec<u8>> = connection
        .query_row(
            "SELECT revision_id FROM revisions WHERE sequence = 0",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let bytes = bytes.ok_or_else(|| {
        crate::error::Failure::UnsupportedLayout("ledger has no genesis revision row".to_owned())
    })?;
    revision_from_blob(&bytes)
}

fn revision_from_blob(bytes: &[u8]) -> crate::error::Result<mneme_core::WorkspaceRevisionId> {
    let bytes: [u8; 16] = bytes.try_into().map_err(|_| {
        crate::error::Failure::UnsupportedLayout("ledger revision id is not 16 bytes".to_owned())
    })?;
    Ok(mneme_core::WorkspaceRevisionId::from_bytes(bytes))
}

fn record_id_from_blob(
    bytes: &[u8],
    revision: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<mneme_core::RecordId> {
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| crate::error::Failure::Integrity {
            revision,
            reason: "record id is not 16 bytes".to_owned(),
        })?;
    Ok(mneme_core::RecordId::from_bytes(bytes))
}

fn revision_id_from_blob(
    bytes: &[u8],
    revision: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<mneme_core::RevisionId> {
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| crate::error::Failure::Integrity {
            revision,
            reason: "record revision id is not 16 bytes".to_owned(),
        })?;
    Ok(mneme_core::RevisionId::from_bytes(bytes))
}

fn digest_with(
    bytes: &[u8],
    profile: &str,
    boundary: &str,
    revision: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<mneme_core::ContentDigest> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| crate::error::Failure::Integrity {
            revision,
            reason: "blob digest is not 32 bytes".to_owned(),
        })?;
    let profile = mneme_core::EncodingProfile::parse(profile).ok_or_else(|| {
        crate::error::Failure::Integrity {
            revision,
            reason: format!("unknown encoding profile {profile}"),
        }
    })?;
    let boundary = mneme_core::ValueBoundary::parse(boundary).ok_or_else(|| {
        crate::error::Failure::Integrity {
            revision,
            reason: format!("unknown value boundary {boundary}"),
        }
    })?;
    mneme_core::ContentDigest::from_parts(
        mneme_core::HashAlgorithm::Sha256,
        profile,
        boundary,
        bytes,
    )
    .map_err(|message| crate::error::Failure::Integrity {
        revision,
        reason: format!("digest metadata is invalid: {message}"),
    })
}

fn revision_row_by_id(
    connection: &rusqlite::Connection,
    revision: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<Option<RevisionRow>> {
    let row = connection
        .query_row(
            "SELECT sequence, revision_id, parent_revision_id, manifest_digest,
                    eligibility_generation
             FROM revisions WHERE revision_id = ?1",
            rusqlite::params![revision.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((sequence, revision_bytes, parent, manifest_digest, generation)) = row else {
        return Ok(None);
    };
    let revision = revision_from_blob(&revision_bytes)?;
    let parent = parent.map(|bytes| revision_from_blob(&bytes)).transpose()?;
    let digest = digest_with(
        &manifest_digest,
        "preserves-canonical-binary-v1",
        "payload",
        revision,
    )?;
    Ok(Some(RevisionRow {
        revision,
        sequence: db_u64(sequence, "sequence")?,
        parent,
        manifest_digest: digest,
        eligibility_generation: db_u64(generation, "generation")?,
    }))
}

/// The record revisions that belong to one committed snapshot.
///
/// A membership interval names one record revision and the span of sequences
/// it belongs to; `last_sequence` stays null while it is the record's current
/// revision. The predicate selects exactly the rows the closed interval set
/// covers, which is what the old per-revision membership table held.
fn membership_entries(
    connection: &rusqlite::Connection,
    sequence: u64,
    kind: Option<&str>,
) -> crate::error::Result<Vec<MembershipEntry>> {
    let mut statement = connection.prepare(
        "SELECT r.record_id, r.revision_id, r.kind, r.envelope_digest, r.payload_digest,
                r.full_digest
         FROM record_membership m
         JOIN records r ON r.record_id = m.record_id AND r.revision_id = m.revision_id
         WHERE m.first_sequence <= ?1
           AND (m.last_sequence IS NULL OR m.last_sequence >= ?1)
           AND (?2 IS NULL OR r.kind = ?2)
         ORDER BY r.record_id",
    )?;
    let rows = statement
        .query_map(
            rusqlite::params![db_i64(sequence, "sequence")?, kind],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// The record identities one snapshot's manifest names.
fn manifest_record_set(
    connection: &rusqlite::Connection,
    sequence: u64,
    revision: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<std::collections::BTreeSet<crate::catalog::ManifestRecord>> {
    let mut records = std::collections::BTreeMap::new();
    for entry in membership_entries(connection, sequence, None)? {
        let (record_id, revision_id, kind) = membership_record(&entry, revision)?;
        if records
            .insert(
                record_id,
                crate::catalog::ManifestRecord {
                    record_id,
                    revision_id,
                    kind,
                },
            )
            .is_some()
        {
            return Err(crate::error::Failure::Integrity {
                revision,
                reason: "snapshot membership names two revisions of one record".to_owned(),
            });
        }
    }
    Ok(records.into_values().collect())
}

/// Decode one membership row's record identity.
fn membership_record(
    entry: &MembershipEntry,
    revision: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<(
    mneme_core::RecordId,
    mneme_core::RevisionId,
    mneme_core::RecordKind,
)> {
    let record_id = record_id_from_blob(&entry.0, revision)?;
    let revision_id = revision_id_from_blob(&entry.1, revision)?;
    let kind = mneme_core::RecordKind::parse(&entry.2).ok_or_else(|| {
        crate::error::Failure::Integrity {
            revision,
            reason: format!("unknown record kind {}", entry.2),
        }
    })?;
    Ok((record_id, revision_id, kind))
}

/// The required-digest set one committed manifest names.
///
/// The journal stores how each revision's set differs from its parent's, so the
/// set is folded once from genesis. Folding reads ledger rows only: it never
/// re-reads a payload.
fn manifest_blob_set(
    connection: &rusqlite::Connection,
    sequence: u64,
    revision: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<std::collections::BTreeSet<mneme_core::ContentDigest>> {
    let mut statement = connection.prepare(
        "SELECT c.digest, b.profile, b.boundary, c.change
         FROM revision_blob_changes c
         JOIN blobs b ON b.digest = c.digest
         WHERE c.revision_sequence <= ?1
         ORDER BY c.revision_sequence, c.digest",
    )?;
    let rows = statement
        .query_map(rusqlite::params![db_i64(sequence, "sequence")?], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut blobs = std::collections::BTreeSet::new();
    for (digest, profile, boundary, change) in rows {
        let digest = digest_with(&digest, &profile, &boundary, revision)?;
        apply_blob_change(&mut blobs, digest, &change, revision)?;
    }
    Ok(blobs)
}

/// Apply one recorded blob-set change to a folded set.
fn apply_blob_change(
    blobs: &mut std::collections::BTreeSet<mneme_core::ContentDigest>,
    digest: mneme_core::ContentDigest,
    change: &str,
    revision: mneme_core::WorkspaceRevisionId,
) -> crate::error::Result<()> {
    match change {
        "add" => {
            blobs.insert(digest);
            Ok(())
        }
        "remove" => {
            if blobs.remove(&digest) {
                Ok(())
            } else {
                Err(crate::error::Failure::Integrity {
                    revision,
                    reason: "blob-set journal removes a digest no manifest requires".to_owned(),
                })
            }
        }
        other => Err(crate::error::Failure::Integrity {
            revision,
            reason: format!("unknown blob-set journal change {other}"),
        }),
    }
}

/// Rebuild one revision's manifest and require it to match the identity the
/// ledger committed.
fn reconstructed_manifest(
    connection: &rusqlite::Connection,
    row: &RevisionRow,
    records: std::collections::BTreeSet<crate::catalog::ManifestRecord>,
) -> crate::error::Result<crate::catalog::Manifest> {
    let manifest = crate::catalog::Manifest {
        revision: row.revision,
        parent: row.parent,
        records,
        blobs: manifest_blob_set(connection, row.sequence, row.revision)?,
    };
    if manifest.digest() != row.manifest_digest {
        return Err(crate::error::Failure::Integrity {
            revision: row.revision,
            reason: "reconstructed manifest does not match the committed manifest digest"
                .to_owned(),
        });
    }
    Ok(manifest)
}

/// Whether the ledger holds a table of this exact name.
fn table_exists(
    connection: &rusqlite::Connection,
    name: &'static str,
) -> crate::error::Result<bool> {
    let found: Option<i64> = connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            rusqlite::params![name],
            |row| row.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

/// Read 32 digest bytes out of a ledger row.
fn digest_32(bytes: &[u8]) -> crate::error::Result<[u8; 32]> {
    let digest: [u8; 32] = bytes.try_into().map_err(|_| {
        crate::error::Failure::UnsupportedLayout("ledger digest is not 32 bytes".to_owned())
    })?;
    Ok(digest)
}

fn join(diagnostics: &[mneme_core::Diagnostic]) -> String {
    diagnostics
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

fn db_i64(value: u64, field: &'static str) -> crate::error::Result<i64> {
    i64::try_from(value).map_err(|_| crate::error::Failure::ValueOutOfRange(field))
}

fn db_u64(value: i64, field: &'static str) -> crate::error::Result<u64> {
    u64::try_from(value).map_err(|_| crate::error::Failure::ValueOutOfRange(field))
}

fn db_usize(value: i64, field: &'static str) -> crate::error::Result<usize> {
    usize::try_from(value).map_err(|_| crate::error::Failure::ValueOutOfRange(field))
}

fn db_u32(value: i64, field: &'static str) -> crate::error::Result<u32> {
    u32::try_from(value).map_err(|_| crate::error::Failure::ValueOutOfRange(field))
}
