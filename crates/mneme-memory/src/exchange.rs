//! Signed, bounded workspace record exchange.
//!
//! A bundle is a canonical Preserves commitment signed by a device key that
//! the receiving host already trusts. It carries current authored records,
//! exact source blobs, note aliases keyed by path and content digest, and
//! forgotten-source barriers. Authentication is deliberately separate from
//! record admission and from applying a retention barrier.

use ed25519_dalek::Signer as _;
use sha2::Digest as _;

const BUNDLE_LABEL: &str = "mneme-record-exchange-v1";
const SIGNED_LABEL: &str = "mneme-record-exchange-signed-v1";
const ENCODING_PROFILE: &str = "preserves-canonical-binary-v1";
const SIGNATURE_PROFILE: &str = "ed25519-strict-v1";
const SIGNATURE_DOMAIN: &[u8] = b"mneme.record-exchange.v1\0";
const KEY_ID_DOMAIN: &[u8] = b"mneme.record-exchange.key-id.v1\0";
const IMPORTED_ORIGIN_FIELD: &str = "exchange-origin";
const IMPORTED_ACTOR_PREFIX: &str = "mneme-exchange-import:";
const MAX_RECORDS: usize = 10_000;
const MAX_SOURCE_BLOBS: usize = 2_048;
const MAX_NOTE_REFERENCES: usize = 10_000;
const MAX_BARRIERS: usize = 10_000;

/// The maximum encoded exchange bundle size.
#[allow(unknown_lints, usize_in_public_api)] // the bound is a byte-count limit
pub const MAX_EXCHANGE_BUNDLE_BYTES: usize = 2 * 1024 * 1024;
/// The largest exact source blob admitted to one bundle.
#[allow(unknown_lints, usize_in_public_api)] // the bound is a byte-count limit
pub const MAX_EXCHANGE_SOURCE_BYTES: usize = 1024 * 1024;

/// A peer key admitted by the local trust policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    /// Device identity expected in signed bundles.
    pub issuer: String,
    /// Trusted Ed25519 public key.
    pub public_key: [u8; 32],
    /// The scopes accepted from this peer; a bundle carrying a record or a
    /// barrier in any other scope is refused.
    pub scopes: std::collections::BTreeSet<mneme_core::ScopeId>,
}

/// One trusted peer as the policy checks it.
struct TrustedPeer {
    key_id: String,
    key: ed25519_dalek::VerifyingKey,
    scopes: std::collections::BTreeSet<mneme_core::ScopeId>,
}

/// Host-owned public keys and accepted scopes for workspace exchange.
pub struct Policy {
    peers: std::collections::BTreeMap<String, TrustedPeer>,
}

impl Policy {
    /// Construct a policy from the peer keys stored by the receiving host.
    pub fn new(peers: impl IntoIterator<Item = Peer>) -> Result<Self, Error> {
        let mut trusted = std::collections::BTreeMap::new();
        for peer in peers {
            validate_issuer(&peer.issuer)?;
            if peer.scopes.is_empty() {
                return Err(Error::NoSharedScope);
            }
            let key = ed25519_dalek::VerifyingKey::from_bytes(&peer.public_key)
                .map_err(|_| Error::InvalidPublicKey)?;
            let trusted_peer = TrustedPeer {
                key_id: public_key_id(&peer.public_key),
                key,
                scopes: peer.scopes,
            };
            if trusted.insert(peer.issuer, trusted_peer).is_some() {
                return Err(Error::DuplicateIssuer);
            }
        }
        Ok(Policy { peers: trusted })
    }
}

/// A note's device-local identities and its cross-device path/content identity.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NoteReference {
    /// Device-local document record identity.
    pub document: mneme_core::RecordId,
    /// Device-local document revision identity.
    pub document_revision: mneme_core::RevisionId,
    /// Device-local entity bound to the document, when present.
    pub entity: Option<mneme_core::RecordId>,
    /// Device-local source record identity.
    pub source: mneme_core::RecordId,
    /// Exact device-local source revision identity.
    pub source_revision: mneme_core::RevisionId,
    /// Canonical vault-relative path.
    pub path: String,
    /// Digest of the exact note source bytes at `path`.
    pub content_digest: mneme_core::ContentDigest,
}

/// One signed forgotten-source barrier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Barrier {
    /// Originating retention operation identity.
    pub operation_id: String,
    /// The scope to which the originating barrier applies.
    pub scope: mneme_core::ScopeId,
    /// Kind of the originating operation (normally `forget`).
    pub operation_kind: String,
    /// Suppressed record identity in the originating workspace.
    pub target: mneme_core::RecordId,
    /// Suppressed record revision, when the barrier names one revision.
    pub revision: Option<mneme_core::RevisionId>,
    /// Typed target kind from the retention ledger.
    pub target_kind: String,
    /// Exact source digest whose replay the barrier blocks, when known.
    pub content_digest: Option<mneme_core::ContentDigest>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SourceItem {
    digest: mneme_core::ContentDigest,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SignedBundle {
    issuer: String,
    key_id: String,
    records: Vec<mneme_core::RecordEnvelope>,
    sources: Vec<SourceItem>,
    notes: Vec<NoteReference>,
    barriers: Vec<Barrier>,
    signature: [u8; 64],
}

/// A bundle whose signature and signer identity were verified against host policy.
pub struct AuthenticatedBundle {
    bundle: SignedBundle,
    digest: mneme_core::ContentDigest,
}

impl AuthenticatedBundle {
    /// The trusted device identity that signed this bundle.
    pub fn issuer(&self) -> &str {
        &self.bundle.issuer
    }

    /// The bundle content identity, independent of JSON whitespace.
    pub fn digest(&self) -> mneme_core::ContentDigest {
        self.digest
    }

    /// The signed forgotten-source barriers, to apply before importing records.
    pub fn barriers(&self) -> &[Barrier] {
        &self.bundle.barriers
    }
}

/// Record import result for one authenticated bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportOutcome {
    /// Records committed from this bundle (excluding note-local records).
    pub imported: Vec<mneme_core::RecordId>,
    /// Records already present with the same identity and content.
    pub already_present: Vec<mneme_core::RecordId>,
    /// Foreign decision records retained as history, not applied to assertions.
    pub decisions: Vec<mneme_core::RecordId>,
}

/// Exchange failures. Cryptographic verification and local policy refusals remain distinct.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The signed JSON document exceeds the bundle bound.
    #[error("record exchange bundle exceeds the byte limit")]
    InputTooLarge,
    /// The issuer is not in the receiver's host-owned trust policy.
    #[error("record exchange issuer is not trusted")]
    UntrustedIssuer,
    /// The issuer text is invalid.
    #[error("record exchange issuer identity is invalid")]
    InvalidIssuer,
    /// The public key cannot be parsed as an Ed25519 key.
    #[error("record exchange public key is invalid")]
    InvalidPublicKey,
    /// One issuer was configured more than once.
    #[error("record exchange policy has duplicate issuers")]
    DuplicateIssuer,
    /// An export or a trusted peer names no scope to share.
    #[error("record exchange names no shared scope")]
    NoSharedScope,
    /// A bundle carries a scope its issuer is not trusted for.
    #[error("record exchange bundle carries scope {0}, which is not accepted from its issuer")]
    ScopeNotAccepted(mneme_core::ScopeId),
    /// The bundle is malformed or violates an exchange bound.
    #[error("record exchange bundle is malformed")]
    MalformedBundle,
    /// The signed profile is not supported.
    #[error("record exchange bundle uses an unsupported profile")]
    UnsupportedProfile,
    /// Signature validation failed against the trusted key.
    #[error("record exchange signature is invalid")]
    InvalidSignature,
    /// A typed record does not match the current production schema.
    #[error("record exchange contains an invalid typed record")]
    InvalidRecord,
    /// An imported identity conflicts with local history or another issuer.
    #[error("record exchange record identity conflicts with local history")]
    RecordConflict,
    /// A note reference cannot be uniquely resolved by path and digest.
    #[error("record exchange note identity is ambiguous")]
    AmbiguousNote,
    /// A required durable workspace read or commit failed.
    #[error("record exchange workspace operation failed: {0}")]
    Store(#[from] mneme_store::Failure),
    /// Memory validation refused the imported records.
    #[error("record exchange memory validation failed: {0}")]
    Memory(#[from] crate::failure::EvidenceError),
}

/// Derive the public key associated with a 32-byte Ed25519 device secret.
pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(secret)
        .verifying_key()
        .to_bytes()
}

/// Export the workspace's authored records in `scopes` as one bounded,
/// signed bundle; records, barriers and notes in other scopes stay on the
/// device.
pub fn export_workspace(
    workspace: &mneme_store::Workspace,
    issuer: &str,
    secret: &[u8; 32],
    scopes: &std::collections::BTreeSet<mneme_core::ScopeId>,
) -> Result<String, Error> {
    validate_issuer(issuer)?;
    if scopes.is_empty() {
        return Err(Error::NoSharedScope);
    }
    let snapshot = workspace.snapshot()?;
    let notes = note_references(workspace, &snapshot)?;
    let note_sources = notes
        .iter()
        .map(|note| note.source)
        .collect::<std::collections::BTreeSet<_>>();
    let note_documents = notes
        .iter()
        .map(|note| note.document)
        .collect::<std::collections::BTreeSet<_>>();
    let note_entities = notes
        .iter()
        .filter_map(|note| note.entity)
        .collect::<std::collections::BTreeSet<_>>();
    let suppressions = workspace.active_suppressions()?;
    let blocked = blocked_records(&snapshot.records, &suppressions)?;
    let records = snapshot
        .records
        .iter()
        .filter(|record| scopes.contains(&record.scope))
        .filter(|record| !is_note_local(record, &note_sources, &note_documents, &note_entities))
        .filter(|record| !has_foreign_origin(record))
        .filter(|record| !blocked.contains(&record.record_id))
        .cloned()
        .collect::<Vec<_>>();
    if records.len() > MAX_RECORDS {
        return Err(Error::MalformedBundle);
    }
    let sources = source_items(workspace, &records)?;
    let notes = shared_notes(notes, &snapshot, scopes);
    let mut barriers = export_barriers(workspace, &suppressions)?;
    barriers.retain(|barrier| scopes.contains(&barrier.scope));
    let signing_key = ed25519_dalek::SigningKey::from_bytes(secret);
    let mut bundle = SignedBundle {
        issuer: issuer.to_owned(),
        key_id: public_key_id(&signing_key.verifying_key().to_bytes()),
        records,
        sources,
        notes,
        barriers,
        signature: [0; 64],
    };
    let signed = bundle.signed_value();
    let mut message =
        Vec::with_capacity(SIGNATURE_DOMAIN.len() + mneme_core::encode(&signed).len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(&mneme_core::encode(&signed));
    bundle.signature = signing_key.sign(&message).to_bytes();
    bundle.to_json_document()
}

/// Authenticate one signed bundle using only a trusted, host-owned key policy.
pub fn authenticate_json(input: &[u8], policy: &Policy) -> Result<AuthenticatedBundle, Error> {
    if input.len() > MAX_EXCHANGE_BUNDLE_BYTES {
        return Err(Error::InputTooLarge);
    }
    let text = std::str::from_utf8(input).map_err(|_| Error::MalformedBundle)?;
    let value = mneme_core::decode_document(text).map_err(|_| Error::MalformedBundle)?;
    let bundle = SignedBundle::from_value(value)?;
    let Some(peer) = policy.peers.get(&bundle.issuer) else {
        return Err(Error::UntrustedIssuer);
    };
    if peer.key_id != bundle.key_id {
        return Err(Error::InvalidSignature);
    }
    let signed = bundle.signed_value();
    let mut message =
        Vec::with_capacity(SIGNATURE_DOMAIN.len() + mneme_core::encode(&signed).len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(&mneme_core::encode(&signed));
    let signature = ed25519_dalek::Signature::from_bytes(&bundle.signature);
    peer.key
        .verify_strict(&message, &signature)
        .map_err(|_| Error::InvalidSignature)?;
    if let Some(scope) = unaccepted_scope(&bundle, &peer.scopes) {
        return Err(Error::ScopeNotAccepted(scope));
    }
    let digest = mneme_core::ContentDigest::of_payload(&signed);
    Ok(AuthenticatedBundle { bundle, digest })
}

/// The first scope of a record or a barrier in `bundle` that `accepted`
/// does not include.
fn unaccepted_scope(
    bundle: &SignedBundle,
    accepted: &std::collections::BTreeSet<mneme_core::ScopeId>,
) -> Option<mneme_core::ScopeId> {
    bundle
        .records
        .iter()
        .map(|record| &record.scope)
        .chain(bundle.barriers.iter().map(|barrier| &barrier.scope))
        .find(|scope| !accepted.contains(*scope))
        .cloned()
}

/// The notes whose document lives in a shared scope: an unshared note's path
/// and identities never leave the device.
fn shared_notes(
    notes: Vec<NoteReference>,
    snapshot: &mneme_store::Snapshot,
    scopes: &std::collections::BTreeSet<mneme_core::ScopeId>,
) -> Vec<NoteReference> {
    let shared_documents = snapshot
        .records
        .iter()
        .filter(|record| {
            record.kind == mneme_core::RecordKind::Document && scopes.contains(&record.scope)
        })
        .map(|record| record.record_id)
        .collect::<std::collections::BTreeSet<_>>();
    notes
        .into_iter()
        .filter(|note| shared_documents.contains(&note.document))
        .collect()
}

/// Import records from one verified bundle through memory validation and the workspace coordinator.
///
/// Retention barriers must be applied before this call. Imported assertions
/// are always reduced to proposals, while decisions remain archival records
/// and never change a local assertion's lifecycle.
pub fn import_records(
    workspace: &mut mneme_store::Workspace,
    authenticated: AuthenticatedBundle,
    actor: &str,
) -> Result<ImportOutcome, Error> {
    if actor.trim().is_empty() {
        return Err(Error::MalformedBundle);
    }
    let issuer = authenticated.bundle.issuer.clone();
    let snapshot = workspace.snapshot()?;
    let note_map = note_identity_map(workspace, &snapshot, &authenticated.bundle.notes)?;
    let suppressions = workspace.active_suppressions()?;
    let mut blocked = blocked_records(&snapshot.records, &suppressions)?;
    blocked.extend(blocked_records(
        &authenticated.bundle.records,
        &suppressions,
    )?);
    let mut prepared = prepare_records(
        workspace,
        &snapshot,
        &authenticated.bundle,
        &note_map,
        &blocked,
    )?;
    let mut outcome = ImportOutcome {
        imported: Vec::new(),
        already_present: Vec::new(),
        decisions: Vec::new(),
    };
    prepared.sort_by_key(|record| (record.scope.clone(), record.record_id));
    let mut scopes = std::collections::BTreeMap::<mneme_core::ScopeId, Vec<PreparedRecord>>::new();
    for record in prepared {
        scopes.entry(record.scope.clone()).or_default().push(record);
    }
    for (scope, records) in scopes {
        commit_scope(
            workspace,
            ScopeCommit {
                scope: &scope,
                actor,
                issuer: &issuer,
                bundle_digest: authenticated.digest,
            },
            records,
            &mut outcome,
        )?;
    }
    outcome.imported.sort();
    outcome.imported.dedup();
    outcome.already_present.sort();
    outcome.already_present.dedup();
    outcome.decisions.sort();
    outcome.decisions.dedup();
    Ok(outcome)
}

#[derive(Clone, Debug)]
struct PreparedRecord {
    scope: mneme_core::ScopeId,
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    predecessor: Option<mneme_core::RevisionId>,
    kind: mneme_core::RecordKind,
    schema_version: u32,
    payload: mneme_core::Payload,
    source: Option<(mneme_core::ContentDigest, Vec<u8>, mneme_core::Symbol)>,
    is_decision: bool,
    is_present: bool,
}

struct RecordPreparation<'a> {
    workspace: &'a mneme_store::Workspace,
    bundle: &'a SignedBundle,
    note_map: &'a NoteIdentityMap,
    blocked: &'a std::collections::BTreeSet<mneme_core::RecordId>,
    local: std::collections::BTreeMap<mneme_core::RecordId, &'a mneme_core::RecordEnvelope>,
}

struct ScopeCommit<'a> {
    scope: &'a mneme_core::ScopeId,
    actor: &'a str,
    issuer: &'a str,
    bundle_digest: mneme_core::ContentDigest,
}

fn commit_scope(
    workspace: &mut mneme_store::Workspace,
    options: ScopeCommit<'_>,
    records: Vec<PreparedRecord>,
    outcome: &mut ImportOutcome,
) -> Result<(), Error> {
    let record_count = records.len();
    outcome
        .imported
        .try_reserve(record_count)
        .map_err(|_| Error::InputTooLarge)?;
    outcome
        .already_present
        .try_reserve(record_count)
        .map_err(|_| Error::InputTooLarge)?;
    outcome
        .decisions
        .try_reserve(record_count)
        .map_err(|_| Error::InputTooLarge)?;
    let mut memory_records = Vec::with_capacity(record_count);
    let mut decisions = Vec::with_capacity(record_count);
    let mut source_blobs = Vec::with_capacity(record_count);
    for mut record in records {
        if record.is_present {
            outcome.already_present.push(record.record_id);
            continue;
        }
        if record.is_decision {
            outcome.decisions.push(record.record_id);
            decisions.push(record_to_draft(record));
            continue;
        }
        if let Some((digest, bytes, media_type)) = record.source.take() {
            source_blobs.push((digest, mneme_store::SourceBlobDraft { bytes, media_type }));
        }
        outcome.imported.push(record.record_id);
        memory_records.push(record_to_draft(record));
    }
    source_blobs.sort_by_key(|(digest, _)| *digest);
    source_blobs.dedup_by_key(|(digest, _)| *digest);
    if !memory_records.is_empty() {
        let source_blobs = source_blobs.into_iter().map(|(_, blob)| blob).collect();
        commit_record_batch(workspace, &options, memory_records, source_blobs)?;
    }
    if !decisions.is_empty() {
        commit_decision_records(workspace, &options, decisions)?;
    }
    Ok(())
}

fn commit_record_batch(
    workspace: &mut mneme_store::Workspace,
    options: &ScopeCommit<'_>,
    records: Vec<mneme_store::RecordDraft>,
    source_blobs: Vec<mneme_store::SourceBlobDraft>,
) -> Result<(), Error> {
    let key = import_key(
        "records",
        options.issuer,
        options.bundle_digest,
        options.scope,
    );
    let batch = crate::Batch {
        actor: options.actor.to_owned(),
        scope: options.scope.clone(),
        idempotency_key: key,
        records,
        source_blobs,
        publications: Vec::new(),
    };
    crate::Engine::new(workspace, crate::Access::Operator).commit(batch)?;
    Ok(())
}

fn commit_decision_records(
    workspace: &mut mneme_store::Workspace,
    options: &ScopeCommit<'_>,
    records: Vec<mneme_store::RecordDraft>,
) -> Result<(), Error> {
    let base = workspace.current_revision()?;
    let key = import_key(
        "decisions",
        options.issuer,
        options.bundle_digest,
        options.scope,
    );
    workspace.commit(mneme_store::CommitCommand {
        base,
        actor: options.actor.to_owned(),
        scope: options.scope.clone(),
        idempotency_key: key,
        records,
        source_blobs: Vec::new(),
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: None,
    })?;
    Ok(())
}

fn record_to_draft(record: PreparedRecord) -> mneme_store::RecordDraft {
    mneme_store::RecordDraft {
        schema_version: record.schema_version,
        kind: record.kind,
        record_id: record.record_id,
        revision_id: record.revision_id,
        predecessor: record.predecessor,
        scope: record.scope,
        payload: record.payload,
    }
}

fn prepare_records(
    workspace: &mneme_store::Workspace,
    snapshot: &mneme_store::Snapshot,
    bundle: &SignedBundle,
    note_map: &NoteIdentityMap,
    blocked: &std::collections::BTreeSet<mneme_core::RecordId>,
) -> Result<Vec<PreparedRecord>, Error> {
    let local = snapshot
        .records
        .iter()
        .map(|record| (record.record_id, record))
        .collect::<std::collections::BTreeMap<_, _>>();
    let context = RecordPreparation {
        workspace,
        bundle,
        note_map,
        blocked,
        local,
    };
    let mut candidates = Vec::new();
    candidates
        .try_reserve(bundle.records.len())
        .map_err(|_| Error::InputTooLarge)?;
    for record in &context.bundle.records {
        if let Some(candidate) = prepare_record(&context, record)? {
            candidates.push(candidate);
        }
    }
    Ok(candidates)
}

fn prepare_record(
    context: &RecordPreparation<'_>,
    record: &mneme_core::RecordEnvelope,
) -> Result<Option<PreparedRecord>, Error> {
    if is_note_local(
        record,
        &context.note_map.remote_note_sources,
        &context.note_map.remote_note_documents,
        &context.note_map.remote_note_entities,
    ) || context.blocked.contains(&record.record_id)
    {
        return Ok(None);
    }
    let payload = rewrite_payload(&record.payload, context.note_map)?;
    let payload = import_payload(record.kind, payload, &context.bundle.issuer)?;
    if dependency_targets(&record.payload).iter().any(|target| {
        context.note_map.remote_note_sources.contains(target)
            && !context.note_map.remote_to_local.contains_key(target)
    }) {
        return Err(Error::AmbiguousNote);
    }
    let is_decision = record.kind == mneme_core::RecordKind::Decision;
    let source = source_for_record(record, &context.bundle.sources, &context.local)?;
    let existing = context.local.get(&record.record_id).copied();
    let presence = match existing {
        Some(current) => existing_record_state(
            context.workspace,
            record,
            &payload,
            &context.bundle.issuer,
            current,
        )?,
        None => Some(false),
    };
    let Some(is_present) = presence else {
        return Ok(None);
    };
    Ok(Some(PreparedRecord {
        scope: record.scope.clone(),
        record_id: record.record_id,
        revision_id: record.revision_id,
        predecessor: if existing.is_some() {
            record.predecessor
        } else {
            None
        },
        kind: record.kind,
        schema_version: record.schema_version,
        payload,
        source,
        is_decision,
        is_present,
    }))
}

fn existing_record_state(
    workspace: &mneme_store::Workspace,
    record: &mneme_core::RecordEnvelope,
    payload: &mneme_core::Payload,
    issuer: &str,
    current: &mneme_core::RecordEnvelope,
) -> Result<Option<bool>, Error> {
    if !has_issuer(current, issuer) {
        return Err(Error::RecordConflict);
    }
    if current.revision_id == record.revision_id {
        verify_existing_payload(current, record, payload)?;
        return Ok(Some(true));
    }
    let history = workspace.record_revisions(record.record_id)?;
    if let Some(old) = history
        .iter()
        .find(|old| old.revision_id == record.revision_id)
    {
        if old.payload != *payload || old.predecessor != record.predecessor {
            return Err(Error::RecordConflict);
        }
        return Ok(Some(true));
    }
    if record.predecessor != Some(current.revision_id) {
        return Err(Error::RecordConflict);
    }
    if record.kind == mneme_core::RecordKind::Assertion
        && current.assertion_lifecycle() != Some(mneme_core::Lifecycle::Proposed)
    {
        return Ok(None);
    }
    Ok(Some(false))
}

fn verify_existing_payload(
    current: &mneme_core::RecordEnvelope,
    record: &mneme_core::RecordEnvelope,
    payload: &mneme_core::Payload,
) -> Result<(), Error> {
    if current.payload != *payload || current.predecessor != record.predecessor {
        return Err(Error::RecordConflict);
    }
    Ok(())
}

fn source_for_record(
    record: &mneme_core::RecordEnvelope,
    sources: &[SourceItem],
    local: &std::collections::BTreeMap<mneme_core::RecordId, &mneme_core::RecordEnvelope>,
) -> Result<Option<(mneme_core::ContentDigest, Vec<u8>, mneme_core::Symbol)>, Error> {
    if record.kind != mneme_core::RecordKind::SourceRevision {
        return Ok(None);
    }
    let source = crate::model::SourceView::parse(record.clone())?;
    let mneme_core::SourceContent::Retained(retained) = source.content else {
        return Ok(None);
    };
    if let Some(existing) = local.get(&record.record_id) {
        let existing = crate::model::SourceView::parse((*existing).clone())?;
        if existing.digest() == Some(retained.digest()) {
            return Ok(None);
        }
    }
    let Some(item) = sources.iter().find(|item| item.digest == retained.digest()) else {
        return Err(Error::MalformedBundle);
    };
    Ok(Some((
        item.digest,
        item.bytes.clone(),
        retained.media_type().clone(),
    )))
}

fn import_payload(
    kind: mneme_core::RecordKind,
    mut payload: mneme_core::Payload,
    issuer: &str,
) -> Result<mneme_core::Payload, Error> {
    payload.insert(IMPORTED_ORIGIN_FIELD, mneme_core::Value::string(issuer));
    if kind == mneme_core::RecordKind::Assertion {
        payload.insert("lifecycle", mneme_core::Value::symbol("proposed"));
        payload.insert("origin", mneme_core::Value::symbol("import"));
        payload.remove("decision");
    }
    if kind == mneme_core::RecordKind::Comment {
        payload.insert("status", mneme_core::Value::symbol("proposed"));
    }
    Ok(payload)
}

fn rewrite_payload(
    payload: &mneme_core::Payload,
    note_map: &NoteIdentityMap,
) -> Result<mneme_core::Payload, Error> {
    let rewritten = rewrite_value(&payload.to_value(), note_map)?;
    mneme_core::Payload::from_value(&rewritten, &mneme_core::Path::root())
        .map_err(|_| Error::MalformedBundle)
}

const MAX_REWRITE_TASKS: usize = mneme_core::binary::MAX_DEPTH * 2 + 2;

#[derive(Clone, Copy)]
enum RewriteBuilder {
    Record(usize),
    Sequence(usize),
    Set(usize),
    Dictionary(usize),
}

enum RewriteChildren<'a> {
    Record {
        label: Option<&'a mneme_core::Value>,
        fields: std::slice::Iter<'a, mneme_core::Value>,
    },
    Sequence(std::slice::Iter<'a, mneme_core::Value>),
    Set(std::collections::btree_set::Iter<'a, mneme_core::Value>),
    Dictionary {
        entries: std::collections::btree_map::Iter<'a, mneme_core::Value, mneme_core::Value>,
        pending_value: Option<&'a mneme_core::Value>,
    },
}

impl<'a> Iterator for RewriteChildren<'a> {
    type Item = &'a mneme_core::Value;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            RewriteChildren::Record { label, fields } => label.take().or_else(|| fields.next()),
            RewriteChildren::Sequence(items) => items.next(),
            RewriteChildren::Set(items) => items.next(),
            RewriteChildren::Dictionary {
                entries,
                pending_value,
            } => {
                if let Some(value) = pending_value.take() {
                    return Some(value);
                }
                entries.next().map(|(key, value)| {
                    *pending_value = Some(value);
                    key
                })
            }
        }
    }
}

enum RewriteTask<'a> {
    Visit(&'a mneme_core::Value, usize),
    Walk(RewriteChildren<'a>, RewriteBuilder, usize, usize),
    Finish(RewriteBuilder, usize),
}

fn rewrite_value(
    value: &mneme_core::Value,
    note_map: &NoteIdentityMap,
) -> Result<mneme_core::Value, Error> {
    let mut tasks = Vec::with_capacity(MAX_REWRITE_TASKS);
    push_rewrite_task(&mut tasks, RewriteTask::Visit(value, 0))?;
    let mut rewritten = Vec::new();
    while let Some(task) = tasks.pop() {
        match task {
            RewriteTask::Visit(value, depth) => {
                visit_rewrite_value(value, depth, note_map, &mut tasks, &mut rewritten)?;
            }
            RewriteTask::Walk(children, builder, child_count, depth) => {
                walk_rewrite_children(children, builder, child_count, depth, &mut tasks)?
            }
            RewriteTask::Finish(builder, child_count) => {
                finish_rewrite_value(builder, child_count, &mut rewritten)?;
            }
        }
    }
    if rewritten.len() != 1 {
        return Err(Error::MalformedBundle);
    }
    rewritten.pop().ok_or(Error::MalformedBundle)
}

fn visit_rewrite_value<'a>(
    value: &'a mneme_core::Value,
    depth: usize,
    note_map: &NoteIdentityMap,
    tasks: &mut Vec<RewriteTask<'a>>,
    rewritten: &mut Vec<mneme_core::Value>,
) -> Result<(), Error> {
    if depth > mneme_core::binary::MAX_DEPTH {
        return Err(Error::MalformedBundle);
    }
    if let Some(reference) = reference_value(value) {
        return push_rewritten_value(rewritten, rewrite_reference(reference, note_map)?);
    }
    if let Some((children, builder, child_count)) = rewrite_container(value)? {
        if depth >= mneme_core::binary::MAX_DEPTH {
            return Err(Error::MalformedBundle);
        }
        push_rewrite_task(tasks, RewriteTask::Finish(builder, child_count))?;
        push_rewrite_task(
            tasks,
            RewriteTask::Walk(children, builder, child_count, depth),
        )
    } else {
        push_rewritten_value(rewritten, value.clone())
    }
}

fn rewrite_container(
    value: &mneme_core::Value,
) -> Result<Option<(RewriteChildren<'_>, RewriteBuilder, usize)>, Error> {
    match value {
        mneme_core::Value::Record(record) => {
            let child_count = record
                .fields()
                .len()
                .checked_add(1)
                .ok_or(Error::MalformedBundle)?;
            Ok(Some((
                RewriteChildren::Record {
                    label: Some(record.label()),
                    fields: record.fields().iter(),
                },
                RewriteBuilder::Record(record.fields().len()),
                child_count,
            )))
        }
        mneme_core::Value::Sequence(items) => Ok(Some((
            RewriteChildren::Sequence(items.iter()),
            RewriteBuilder::Sequence(items.len()),
            items.len(),
        ))),
        mneme_core::Value::Set(items) => Ok(Some((
            RewriteChildren::Set(items.iter()),
            RewriteBuilder::Set(items.len()),
            items.len(),
        ))),
        mneme_core::Value::Dictionary(items) => Ok(Some((
            RewriteChildren::Dictionary {
                entries: items.iter(),
                pending_value: None,
            },
            RewriteBuilder::Dictionary(items.len()),
            items.len().checked_mul(2).ok_or(Error::MalformedBundle)?,
        ))),
        mneme_core::Value::Embedded(_) => Err(Error::MalformedBundle),
        mneme_core::Value::Boolean(_)
        | mneme_core::Value::Double(_)
        | mneme_core::Value::SignedInteger(_)
        | mneme_core::Value::String(_)
        | mneme_core::Value::ByteString(_)
        | mneme_core::Value::Symbol(_) => Ok(None),
    }
}

fn walk_rewrite_children<'a>(
    mut children: RewriteChildren<'a>,
    builder: RewriteBuilder,
    child_count: usize,
    depth: usize,
    tasks: &mut Vec<RewriteTask<'a>>,
) -> Result<(), Error> {
    if let Some(child) = children.next() {
        push_rewrite_task(
            tasks,
            RewriteTask::Walk(children, builder, child_count, depth),
        )?;
        let child_depth = depth.checked_add(1).ok_or(Error::MalformedBundle)?;
        push_rewrite_task(tasks, RewriteTask::Visit(child, child_depth))?;
    }
    Ok(())
}

fn finish_rewrite_value(
    builder: RewriteBuilder,
    child_count: usize,
    rewritten: &mut Vec<mneme_core::Value>,
) -> Result<(), Error> {
    let children = take_rewritten_values(rewritten, child_count)?;
    let value = build_rewritten_value(builder, children)?;
    push_rewritten_value(rewritten, value)
}

fn push_rewrite_task<'a>(
    tasks: &mut Vec<RewriteTask<'a>>,
    task: RewriteTask<'a>,
) -> Result<(), Error> {
    if tasks.len() >= MAX_REWRITE_TASKS {
        return Err(Error::MalformedBundle);
    }
    tasks.push(task);
    Ok(())
}

fn push_rewritten_value(
    values: &mut Vec<mneme_core::Value>,
    value: mneme_core::Value,
) -> Result<(), Error> {
    if values.len() >= MAX_EXCHANGE_BUNDLE_BYTES {
        return Err(Error::InputTooLarge);
    }
    values.try_reserve(1).map_err(|_| Error::InputTooLarge)?;
    values.push(value);
    Ok(())
}

fn take_rewritten_values(
    values: &mut Vec<mneme_core::Value>,
    count: usize,
) -> Result<Vec<mneme_core::Value>, Error> {
    let start = values
        .len()
        .checked_sub(count)
        .ok_or(Error::MalformedBundle)?;
    Ok(values.drain(start..).collect())
}

fn build_rewritten_value(
    builder: RewriteBuilder,
    children: Vec<mneme_core::Value>,
) -> Result<mneme_core::Value, Error> {
    match builder {
        RewriteBuilder::Record(field_count) => {
            let mut parts = children.into_iter();
            let label = parts.next().ok_or(Error::MalformedBundle)?;
            let fields: Vec<mneme_core::Value> = parts.collect();
            if fields.len() != field_count {
                return Err(Error::MalformedBundle);
            }
            Ok(mneme_core::Value::record(label, fields))
        }
        RewriteBuilder::Sequence(count) => {
            if children.len() != count {
                return Err(Error::MalformedBundle);
            }
            Ok(mneme_core::Value::sequence(children))
        }
        RewriteBuilder::Set(count) => {
            if children.len() != count {
                return Err(Error::MalformedBundle);
            }
            Ok(mneme_core::Value::set(children))
        }
        RewriteBuilder::Dictionary(count) => {
            let child_count = count.checked_mul(2).ok_or(Error::MalformedBundle)?;
            if children.len() != child_count {
                return Err(Error::MalformedBundle);
            }
            let mut parts = children.into_iter();
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                let key = parts.next().ok_or(Error::MalformedBundle)?;
                let value = parts.next().ok_or(Error::MalformedBundle)?;
                entries.push((key, value));
            }
            Ok(mneme_core::Value::dictionary(entries))
        }
    }
}

fn reference_value(value: &mneme_core::Value) -> Option<mneme_core::Reference> {
    mneme_core::Reference::from_value(value, &mneme_core::Path::root()).ok()
}

fn rewrite_reference(
    reference: mneme_core::Reference,
    note_map: &NoteIdentityMap,
) -> Result<mneme_core::Value, Error> {
    let mapped = match reference {
        mneme_core::Reference::Local { target, kind } => mneme_core::Reference::Local {
            target: note_map
                .remote_to_local
                .get(&target)
                .copied()
                .unwrap_or(target),
            kind,
        },
        mneme_core::Reference::Pinned {
            target,
            revision,
            kind,
        } => {
            let pair = (target, revision);
            let mapped = note_map.revision_to_local.get(&pair).copied().unwrap_or((
                note_map
                    .remote_to_local
                    .get(&target)
                    .copied()
                    .unwrap_or(target),
                revision,
            ));
            mneme_core::Reference::Pinned {
                target: mapped.0,
                revision: mapped.1,
                kind,
            }
        }
        mneme_core::Reference::External { locator, kind } => {
            mneme_core::Reference::External { locator, kind }
        }
        mneme_core::Reference::Unresolved {
            target,
            kind,
            reason,
        } => mneme_core::Reference::Unresolved {
            target: note_map
                .remote_to_local
                .get(&target)
                .copied()
                .unwrap_or(target),
            kind,
            reason,
        },
    };
    Ok(mapped.to_value())
}

struct NoteIdentityMap {
    remote_to_local: std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RecordId>,
    revision_to_local: std::collections::BTreeMap<
        (mneme_core::RecordId, mneme_core::RevisionId),
        (mneme_core::RecordId, mneme_core::RevisionId),
    >,
    remote_note_sources: std::collections::BTreeSet<mneme_core::RecordId>,
    remote_note_documents: std::collections::BTreeSet<mneme_core::RecordId>,
    remote_note_entities: std::collections::BTreeSet<mneme_core::RecordId>,
}

fn note_identity_map(
    workspace: &mneme_store::Workspace,
    snapshot: &mneme_store::Snapshot,
    remote_notes: &[NoteReference],
) -> Result<NoteIdentityMap, Error> {
    let local_notes = note_references(workspace, snapshot)?;
    let local_by_key = unique_note_keys(&local_notes)?;
    let mut map = NoteIdentityMap {
        remote_to_local: std::collections::BTreeMap::new(),
        revision_to_local: std::collections::BTreeMap::new(),
        remote_note_sources: std::collections::BTreeSet::new(),
        remote_note_documents: std::collections::BTreeSet::new(),
        remote_note_entities: std::collections::BTreeSet::new(),
    };
    for remote in remote_notes {
        let key = (remote.path.clone(), remote.content_digest);
        let local = local_by_key.get(&key).ok_or(Error::AmbiguousNote)?;
        insert_note_mapping(&mut map, remote.document, local.document)?;
        insert_note_mapping(&mut map, remote.source, local.source)?;
        if let (Some(remote_entity), Some(local_entity)) = (remote.entity, local.entity) {
            insert_note_mapping(&mut map, remote_entity, local_entity)?;
            map.remote_note_entities.insert(remote_entity);
        }
        map.revision_to_local.insert(
            (remote.document, remote.document_revision),
            (local.document, local.document_revision),
        );
        map.revision_to_local.insert(
            (remote.source, remote.source_revision),
            (local.source, local.source_revision),
        );
        map.remote_note_sources.insert(remote.source);
        map.remote_note_documents.insert(remote.document);
    }
    Ok(map)
}

fn unique_note_keys(
    notes: &[NoteReference],
) -> Result<std::collections::BTreeMap<(String, mneme_core::ContentDigest), &NoteReference>, Error>
{
    let mut indexed = std::collections::BTreeMap::new();
    for note in notes {
        let key = (note.path.clone(), note.content_digest);
        if let Some(previous) = indexed.insert(key, note)
            && (previous.document != note.document || previous.source != note.source)
        {
            return Err(Error::AmbiguousNote);
        }
    }
    Ok(indexed)
}

fn insert_note_mapping(
    map: &mut NoteIdentityMap,
    remote: mneme_core::RecordId,
    local: mneme_core::RecordId,
) -> Result<(), Error> {
    if map
        .remote_to_local
        .insert(remote, local)
        .is_some_and(|previous| previous != local)
    {
        return Err(Error::AmbiguousNote);
    }
    Ok(())
}

fn note_references(
    workspace: &mneme_store::Workspace,
    snapshot: &mneme_store::Snapshot,
) -> Result<Vec<NoteReference>, Error> {
    let current = snapshot
        .records
        .iter()
        .map(|record| (record.record_id, record))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut references = Vec::new();
    for document in snapshot
        .records
        .iter()
        .filter(|record| record.kind == mneme_core::RecordKind::Document)
    {
        if let Some(reference) = note_reference(workspace, &current, document) {
            if references.len() >= MAX_NOTE_REFERENCES {
                return Err(Error::MalformedBundle);
            }
            references
                .try_reserve(1)
                .map_err(|_| Error::InputTooLarge)?;
            references.push(reference);
        }
    }
    references.sort_unstable();
    references.dedup();
    Ok(references)
}

fn note_reference(
    workspace: &mneme_store::Workspace,
    current: &std::collections::BTreeMap<mneme_core::RecordId, &mneme_core::RecordEnvelope>,
    document: &mneme_core::RecordEnvelope,
) -> Option<NoteReference> {
    let path = document
        .payload
        .get("path")
        .and_then(mneme_core::Value::as_string)?;
    if !mneme_kernel::text::is_canonical_relative_path(path.as_bytes()) {
        return None;
    }
    let reference = document.payload.get("source-revision").and_then(|value| {
        mneme_core::Reference::from_value(value, &mneme_core::Path::root()).ok()
    })?;
    let source_id = reference.target()?;
    let source_revision = match reference {
        mneme_core::Reference::Pinned { revision, .. } => revision,
        mneme_core::Reference::Local { .. } => current.get(&source_id)?.revision_id,
        mneme_core::Reference::External { .. } | mneme_core::Reference::Unresolved { .. } => {
            return None;
        }
    };
    let source_record = current
        .get(&source_id)
        .filter(|record| record.revision_id == source_revision)
        .map(|record| (*record).clone())
        .or_else(|| {
            workspace
                .record_revisions(source_id)
                .ok()?
                .into_iter()
                .find(|record| record.revision_id == source_revision)
        })?;
    let source = crate::model::SourceView::parse(source_record).ok()?;
    let content_digest = source.digest().or(source.prior_digest)?;
    let entity = document
        .payload
        .get("entity")
        .and_then(|value| mneme_core::Reference::from_value(value, &mneme_core::Path::root()).ok())
        .and_then(|reference| reference.target());
    Some(NoteReference {
        document: document.record_id,
        document_revision: document.revision_id,
        entity,
        source: source_id,
        source_revision,
        path: path.to_owned(),
        content_digest,
    })
}

fn source_items(
    workspace: &mneme_store::Workspace,
    records: &[mneme_core::RecordEnvelope],
) -> Result<Vec<SourceItem>, Error> {
    let mut items = Vec::with_capacity(records.len());
    for record in records
        .iter()
        .filter(|record| record.kind == mneme_core::RecordKind::SourceRevision)
    {
        let source = crate::model::SourceView::parse(record.clone())?;
        let mneme_core::SourceContent::Retained(retained) = source.content else {
            continue;
        };
        let length = usize::try_from(retained.byte_length()).map_err(|_| Error::InputTooLarge)?;
        if length > MAX_EXCHANGE_SOURCE_BYTES {
            return Err(Error::InputTooLarge);
        }
        let bytes = mneme_store::payload::read(workspace.root(), retained.digest())?;
        if bytes.len() != length {
            return Err(Error::MalformedBundle);
        }
        items.push(SourceItem {
            digest: retained.digest(),
            bytes,
        });
    }
    items.sort_by_key(|item| item.digest);
    items.dedup_by_key(|item| item.digest);
    if items.len() > MAX_SOURCE_BLOBS {
        return Err(Error::MalformedBundle);
    }
    Ok(items)
}

fn export_barriers(
    workspace: &mneme_store::Workspace,
    suppressions: &[mneme_store::RetentionSuppression],
) -> Result<Vec<Barrier>, Error> {
    let mut barriers = std::collections::BTreeSet::new();
    for suppression in suppressions.iter().filter(|suppression| {
        suppression.mode == mneme_store::SuppressionMode::Forgotten
            && matches!(
                suppression.target_kind.as_str(),
                "source-revision" | "assertion"
            )
    }) {
        let Some(operation) = workspace.retention_operation(&suppression.operation_id)? else {
            continue;
        };
        if operation.actor.starts_with(IMPORTED_ACTOR_PREFIX) {
            continue;
        }
        barriers.insert(Barrier {
            operation_id: suppression.operation_id.clone(),
            scope: operation.scope,
            operation_kind: operation.operation_kind,
            target: suppression.target,
            revision: suppression.revision,
            target_kind: suppression.target_kind.clone(),
            content_digest: suppression.content_digest,
        });
    }
    if barriers.len() > MAX_BARRIERS {
        return Err(Error::MalformedBundle);
    }
    Ok(barriers.into_iter().collect())
}

fn blocked_records(
    records: &[mneme_core::RecordEnvelope],
    suppressions: &[mneme_store::RetentionSuppression],
) -> Result<std::collections::BTreeSet<mneme_core::RecordId>, Error> {
    let mut blocked = suppressions
        .iter()
        .filter(|suppression| suppression.mode == mneme_store::SuppressionMode::Forgotten)
        .map(|suppression| suppression.target)
        .collect::<std::collections::BTreeSet<_>>();
    let digests = suppressions
        .iter()
        .filter(|suppression| suppression.mode == mneme_store::SuppressionMode::Forgotten)
        .filter_map(|suppression| suppression.content_digest)
        .collect::<std::collections::BTreeSet<_>>();
    for record in records
        .iter()
        .filter(|record| record.kind == mneme_core::RecordKind::SourceRevision)
    {
        if let Ok(source) = crate::model::SourceView::parse(record.clone())
            && source
                .digest()
                .or(source.prior_digest)
                .is_some_and(|digest| digests.contains(&digest))
        {
            blocked.insert(record.record_id);
        }
    }
    loop {
        let prior = blocked.len();
        for record in records {
            if !blocked.contains(&record.record_id)
                && dependency_targets(&record.payload)
                    .iter()
                    .any(|target| blocked.contains(target))
            {
                blocked.insert(record.record_id);
            }
        }
        if blocked.len() == prior {
            break;
        }
    }
    Ok(blocked)
}

fn dependency_targets(
    payload: &mneme_core::Payload,
) -> std::collections::BTreeSet<mneme_core::RecordId> {
    let mut result = std::collections::BTreeSet::new();
    let mut pending = vec![payload.to_value()];
    while let Some(value) = pending.pop() {
        if let Some(reference) = reference_value(&value) {
            if let Some(target) = reference.target() {
                result.insert(target);
            }
            continue;
        }
        match value {
            mneme_core::Value::Record(record) => pending.extend(record.fields().iter().cloned()),
            mneme_core::Value::Sequence(items) => pending.extend(items),
            mneme_core::Value::Set(items) => pending.extend(items),
            mneme_core::Value::Dictionary(items) => {
                for (key, value) in items {
                    pending.push(key);
                    pending.push(value);
                }
            }
            mneme_core::Value::Embedded(_) => {}
            mneme_core::Value::Boolean(_)
            | mneme_core::Value::Double(_)
            | mneme_core::Value::SignedInteger(_)
            | mneme_core::Value::String(_)
            | mneme_core::Value::ByteString(_)
            | mneme_core::Value::Symbol(_) => {}
        }
    }
    result
}

fn is_note_local(
    record: &mneme_core::RecordEnvelope,
    sources: &std::collections::BTreeSet<mneme_core::RecordId>,
    documents: &std::collections::BTreeSet<mneme_core::RecordId>,
    entities: &std::collections::BTreeSet<mneme_core::RecordId>,
) -> bool {
    match record.kind {
        mneme_core::RecordKind::Comment => false,
        mneme_core::RecordKind::Document
        | mneme_core::RecordKind::DocumentBinding
        | mneme_core::RecordKind::DocumentAnchor => true,
        mneme_core::RecordKind::SourceRevision => sources.contains(&record.record_id),
        mneme_core::RecordKind::RecognitionRun => {
            crate::model::RecognitionRunView::parse(record.clone())
                .is_ok_and(|run| sources.contains(&run.output.source()))
        }
        mneme_core::RecordKind::RecognitionSegment => {
            crate::model::RecognitionSegmentView::parse(record.clone())
                .is_ok_and(|segment| sources.contains(&segment.text_source.source()))
        }
        mneme_core::RecordKind::Entity => entities.contains(&record.record_id),
        mneme_core::RecordKind::Relation
        | mneme_core::RecordKind::Episode
        | mneme_core::RecordKind::Assertion
        | mneme_core::RecordKind::Evidence
        | mneme_core::RecordKind::Decision
        | mneme_core::RecordKind::Derivation
        | mneme_core::RecordKind::Checkpoint
        | mneme_core::RecordKind::Proposal
        | mneme_core::RecordKind::RetentionDirective => documents.contains(&record.record_id),
    }
}

fn has_foreign_origin(record: &mneme_core::RecordEnvelope) -> bool {
    record.payload.get(IMPORTED_ORIGIN_FIELD).is_some()
}

fn has_issuer(record: &mneme_core::RecordEnvelope, issuer: &str) -> bool {
    record
        .payload
        .get(IMPORTED_ORIGIN_FIELD)
        .and_then(mneme_core::Value::as_string)
        == Some(issuer)
}

fn import_key(
    kind: &str,
    issuer: &str,
    bundle_digest: mneme_core::ContentDigest,
    scope: &mneme_core::ScopeId,
) -> String {
    let fingerprint = mneme_core::ContentDigest::of_payload(&mneme_core::Value::record_named(
        "exchange-import-key",
        vec![
            mneme_core::Value::string(kind),
            mneme_core::Value::string(issuer),
            bundle_digest.to_value(),
            scope.to_value(),
        ],
    ));
    format!("exchange-{kind}-{}", fingerprint.to_hex())
}

fn validate_issuer(issuer: &str) -> Result<(), Error> {
    if issuer.is_empty()
        || issuer.len() > 64
        || !issuer
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(Error::InvalidIssuer);
    }
    Ok(())
}

fn public_key_id(public_key: &[u8; 32]) -> String {
    let mut hash = sha2::Sha256::new();
    hash.update(KEY_ID_DOMAIN);
    hash.update(public_key);
    hex(&hash.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

impl SignedBundle {
    fn signed_value(&self) -> mneme_core::Value {
        mneme_core::Value::record_named(
            SIGNED_LABEL,
            vec![
                mneme_core::Value::symbol(ENCODING_PROFILE),
                mneme_core::Value::symbol(SIGNATURE_PROFILE),
                mneme_core::Value::string(self.issuer.clone()),
                mneme_core::Value::string(self.key_id.clone()),
                mneme_core::Value::set(
                    self.records
                        .iter()
                        .map(mneme_core::RecordEnvelope::to_value),
                ),
                mneme_core::Value::set(self.sources.iter().map(source_value)),
                mneme_core::Value::set(self.notes.iter().map(note_value)),
                mneme_core::Value::set(self.barriers.iter().map(barrier_value)),
            ],
        )
    }

    fn to_json_document(&self) -> Result<String, Error> {
        let document = mneme_core::Value::record_named(
            BUNDLE_LABEL,
            vec![
                self.signed_value(),
                mneme_core::Value::bytes(self.signature.to_vec()),
            ],
        );
        let json = mneme_core::encode_document_string(&document);
        if json.len() > MAX_EXCHANGE_BUNDLE_BYTES {
            return Err(Error::InputTooLarge);
        }
        Ok(json)
    }

    fn from_value(value: mneme_core::Value) -> Result<Self, Error> {
        let outer = record_fields(&value, BUNDLE_LABEL, 2)?;
        let signed = record_fields(&outer[0], SIGNED_LABEL, 8)?;
        if read_symbol(&signed[0])? != ENCODING_PROFILE
            || read_symbol(&signed[1])? != SIGNATURE_PROFILE
        {
            return Err(Error::UnsupportedProfile);
        }
        let issuer = read_string(&signed[2])?.to_owned();
        validate_issuer(&issuer)?;
        let key_id = read_string(&signed[3])?.to_owned();
        let records = read_record_set(&signed[4])?;
        let sources = read_source_set(&signed[5])?;
        let notes = read_note_set(&signed[6])?;
        let barriers = read_barrier_set(&signed[7])?;
        let signature_bytes = signed_bytes(&outer[1])?;
        let signature: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| Error::MalformedBundle)?;
        Ok(SignedBundle {
            issuer,
            key_id,
            records,
            sources,
            notes,
            barriers,
            signature,
        })
    }
}

fn source_value(source: &SourceItem) -> mneme_core::Value {
    mneme_core::Value::record_named(
        "exchange-source",
        vec![
            source.digest.to_value(),
            mneme_core::Value::bytes(source.bytes.clone()),
        ],
    )
}

fn note_value(note: &NoteReference) -> mneme_core::Value {
    mneme_core::Value::record_named(
        "exchange-note",
        vec![
            note.document.to_value(),
            note.document_revision.to_value(),
            note.entity
                .map_or_else(|| mneme_core::Value::symbol("none"), |id| id.to_value()),
            note.source.to_value(),
            note.source_revision.to_value(),
            mneme_core::Value::string(note.path.clone()),
            note.content_digest.to_value(),
        ],
    )
}

fn barrier_value(barrier: &Barrier) -> mneme_core::Value {
    mneme_core::Value::record_named(
        "exchange-barrier",
        vec![
            mneme_core::Value::string(barrier.operation_id.clone()),
            barrier.scope.to_value(),
            mneme_core::Value::symbol(barrier.operation_kind.clone()),
            barrier.target.to_value(),
            barrier
                .revision
                .map_or_else(|| mneme_core::Value::symbol("none"), |id| id.to_value()),
            mneme_core::Value::symbol(barrier.target_kind.clone()),
            barrier.content_digest.map_or_else(
                || mneme_core::Value::symbol("none"),
                |digest| digest.to_value(),
            ),
        ],
    )
}

fn record_fields<'a>(
    value: &'a mneme_core::Value,
    label: &str,
    length: usize,
) -> Result<&'a [mneme_core::Value], Error> {
    let Some(record) = value.as_record() else {
        return Err(Error::MalformedBundle);
    };
    if record.label() != &mneme_core::Value::symbol(label) || record.fields().len() != length {
        return Err(Error::MalformedBundle);
    }
    Ok(record.fields())
}

fn read_symbol(value: &mneme_core::Value) -> Result<&str, Error> {
    value
        .as_symbol()
        .map(mneme_core::Symbol::as_str)
        .ok_or(Error::MalformedBundle)
}

fn read_string(value: &mneme_core::Value) -> Result<&str, Error> {
    value.as_string().ok_or(Error::MalformedBundle)
}

fn signed_bytes(value: &mneme_core::Value) -> Result<&[u8], Error> {
    value.as_bytes().ok_or(Error::MalformedBundle)
}

fn read_record_set(value: &mneme_core::Value) -> Result<Vec<mneme_core::RecordEnvelope>, Error> {
    let Some(items) = value.as_set() else {
        return Err(Error::MalformedBundle);
    };
    // A bundle may carry no records: a shared scope can be empty, or hold
    // only forget barriers.
    if items.len() > MAX_RECORDS {
        return Err(Error::MalformedBundle);
    }
    items
        .iter()
        .map(|item| {
            mneme_core::RecordEnvelope::from_value_with_registry(
                item,
                &mneme_core::SchemaRegistry::production(),
            )
            .map_err(|_| Error::InvalidRecord)
        })
        .collect()
}

fn read_source_set(value: &mneme_core::Value) -> Result<Vec<SourceItem>, Error> {
    let Some(items) = value.as_set() else {
        return Err(Error::MalformedBundle);
    };
    if items.len() > MAX_SOURCE_BLOBS {
        return Err(Error::MalformedBundle);
    }
    let mut sources = Vec::with_capacity(items.len());
    let mut digests = std::collections::BTreeSet::new();
    for item in items {
        let fields = record_fields(item, "exchange-source", 2)?;
        let digest = mneme_core::ContentDigest::from_value(&fields[0], &mneme_core::Path::root())
            .map_err(|_| Error::MalformedBundle)?;
        let bytes = signed_bytes(&fields[1])?.to_vec();
        if bytes.len() > MAX_EXCHANGE_SOURCE_BYTES
            || mneme_core::ContentDigest::of_source_bytes(&bytes) != digest
            || !digests.insert(digest)
        {
            return Err(Error::MalformedBundle);
        }
        sources.push(SourceItem { digest, bytes });
    }
    Ok(sources)
}

fn read_note_set(value: &mneme_core::Value) -> Result<Vec<NoteReference>, Error> {
    let Some(items) = value.as_set() else {
        return Err(Error::MalformedBundle);
    };
    if items.len() > MAX_NOTE_REFERENCES {
        return Err(Error::MalformedBundle);
    }
    let mut notes = Vec::with_capacity(items.len());
    for item in items {
        let fields = record_fields(item, "exchange-note", 7)?;
        let document = parse_id(&fields[0])?;
        let document_revision = parse_revision(&fields[1])?;
        let entity = if read_symbol(&fields[2]).is_ok_and(|symbol| symbol == "none") {
            None
        } else {
            Some(parse_id(&fields[2])?)
        };
        let source = parse_id(&fields[3])?;
        let source_revision = parse_revision(&fields[4])?;
        let path = read_string(&fields[5])?.to_owned();
        if !mneme_kernel::text::is_canonical_relative_path(path.as_bytes()) {
            return Err(Error::MalformedBundle);
        }
        let content_digest =
            mneme_core::ContentDigest::from_value(&fields[6], &mneme_core::Path::root())
                .map_err(|_| Error::MalformedBundle)?;
        notes.push(NoteReference {
            document,
            document_revision,
            entity,
            source,
            source_revision,
            path,
            content_digest,
        });
    }
    Ok(notes)
}

fn read_barrier_set(value: &mneme_core::Value) -> Result<Vec<Barrier>, Error> {
    let Some(items) = value.as_set() else {
        return Err(Error::MalformedBundle);
    };
    if items.len() > MAX_BARRIERS {
        return Err(Error::MalformedBundle);
    }
    let mut barriers = Vec::with_capacity(items.len());
    for item in items {
        let fields = record_fields(item, "exchange-barrier", 7)?;
        let operation_id = read_string(&fields[0])?.to_owned();
        let scope = mneme_core::ScopeId::from_value(&fields[1], &mneme_core::Path::root())
            .map_err(|_| Error::MalformedBundle)?;
        let operation_kind = read_symbol(&fields[2])?.to_owned();
        let target = parse_id(&fields[3])?;
        let revision = if read_symbol(&fields[4]).is_ok_and(|symbol| symbol == "none") {
            None
        } else {
            Some(parse_revision(&fields[4])?)
        };
        let target_kind = read_symbol(&fields[5])?.to_owned();
        let content_digest = if read_symbol(&fields[6]).is_ok_and(|symbol| symbol == "none") {
            None
        } else {
            Some(
                mneme_core::ContentDigest::from_value(&fields[6], &mneme_core::Path::root())
                    .map_err(|_| Error::MalformedBundle)?,
            )
        };
        if operation_id.is_empty()
            || operation_kind != "forget"
            || !matches!(target_kind.as_str(), "source-revision" | "assertion")
        {
            return Err(Error::MalformedBundle);
        }
        barriers.push(Barrier {
            operation_id,
            scope,
            operation_kind,
            target,
            revision,
            target_kind,
            content_digest,
        });
    }
    Ok(barriers)
}

fn parse_id(value: &mneme_core::Value) -> Result<mneme_core::RecordId, Error> {
    mneme_core::RecordId::from_value(value, &mneme_core::Path::root())
        .map_err(|_| Error::MalformedBundle)
}

fn parse_revision(value: &mneme_core::Value) -> Result<mneme_core::RevisionId, Error> {
    mneme_core::RevisionId::from_value(value, &mneme_core::Path::root())
        .map_err(|_| Error::MalformedBundle)
}
