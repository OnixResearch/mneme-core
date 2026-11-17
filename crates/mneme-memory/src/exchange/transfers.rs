//! Large sources that travel beside a signed bundle as verified chunks.
//!
//! A version 2 bundle signs a manifest entry for each large source: its exact
//! identity and scope, its length and media type, the bundle records that
//! depend on it, and the digest of every chunk. Chunks travel separately and
//! may arrive in any order, any number of times, across restarts. A receiver
//! keeps them under its own `transfers/` directory, never in the blob store,
//! and publishes a source and its dependents only after every chunk, and then
//! the whole asset, hash to what the manifest signed.

use sha2::Digest as _;

/// The length a bundle's assets are cut into.
pub const ASSET_CHUNK_BYTES: u32 = 1024 * 1024;
/// The shortest chunk length a manifest may declare.
const MIN_CHUNK_BYTES: u32 = 64 * 1024;
/// The longest chunk length a manifest may declare.
const MAX_CHUNK_BYTES: u32 = 4 * 1024 * 1024;
/// Sources at most this long travel inside a version 2 bundle.
pub(super) const INLINE_SOURCE_BYTES: u64 = 64 * 1024;
/// The largest source that travels as an asset.
pub const MAX_EXCHANGE_ASSET_BYTES: u64 = 256 * 1024 * 1024;
/// The most bytes a workspace holds in pending transfers.
pub const MAX_TRANSFER_BYTES: u64 = 1024 * 1024 * 1024;
/// The most asset bytes one import publishes; the rest wait for a later one.
const MAX_PUBLISHED_BYTES: u64 = 512 * 1024 * 1024;
/// The most transfers a workspace lists.
const MAX_TRANSFERS: usize = 4_096;
/// The label of a pending transfer's manifest file.
const TRANSFER_LABEL: &str = "mneme-asset-transfer-v1";
const MANIFEST_FILE: &str = "manifest";
const CHUNK_SUFFIX: &str = ".chunk";

/// One large source of a bundle, as the bundle's manifest signs it.
///
/// An asset is only ever made by an export, a grant or an authenticated
/// bundle, so it always names bytes its maker was entitled to.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Asset {
    source: mneme_core::RecordId,
    revision: mneme_core::RevisionId,
    scope: mneme_core::ScopeId,
    digest: mneme_core::ContentDigest,
    byte_length: u64,
    media_type: mneme_core::Symbol,
    chunk_bytes: u32,
    chunks: Vec<mneme_core::ContentDigest>,
    dependents: Vec<mneme_core::RecordId>,
    count: u32,
}

impl Asset {
    /// The source record the bytes belong to.
    pub fn source(&self) -> mneme_core::RecordId {
        self.source
    }

    /// The exact source revision.
    pub fn revision(&self) -> mneme_core::RevisionId {
        self.revision
    }

    /// The scope the source lives in.
    pub fn scope(&self) -> &mneme_core::ScopeId {
        &self.scope
    }

    /// The digest of the whole asset.
    pub fn digest(&self) -> mneme_core::ContentDigest {
        self.digest
    }

    /// The asset's length.
    pub fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// The asset's media type.
    pub fn media_type(&self) -> &mneme_core::Symbol {
        &self.media_type
    }

    /// The length of every chunk but the last.
    pub fn chunk_bytes(&self) -> u32 {
        self.chunk_bytes
    }

    /// The bundle records that need the source, directly or through others.
    pub fn dependents(&self) -> &[mneme_core::RecordId] {
        &self.dependents
    }

    /// How many chunks the asset is cut into.
    pub fn chunk_count(&self) -> u32 {
        self.count
    }

    /// Where chunk `index` lies in the asset, and how long it is.
    fn chunk_span(&self, index: u32) -> Option<(u64, usize)> {
        let offset = u64::from(index).checked_mul(u64::from(self.chunk_bytes))?;
        let rest = self
            .byte_length
            .checked_sub(offset)
            .filter(|rest| *rest > 0)?;
        let length = rest.min(u64::from(self.chunk_bytes));
        Some((offset, usize::try_from(length).ok()?))
    }
}

/// What one received chunk changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkReceipt {
    /// Chunks of the asset now held.
    pub received: u32,
    /// Chunks the asset has.
    pub total: u32,
    /// Whether this chunk was not held before.
    pub is_new: bool,
}

/// A source whose bytes are still arriving.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingAsset {
    /// The device that sent the bundle naming it.
    pub issuer: String,
    /// The source record waiting for the bytes.
    pub source: mneme_core::RecordId,
    /// The exact source revision.
    pub revision: mneme_core::RevisionId,
    /// The scope the source will live in.
    pub scope: mneme_core::ScopeId,
    /// The digest of the whole asset.
    pub digest: mneme_core::ContentDigest,
    /// The asset's length.
    pub byte_length: u64,
    /// The asset's media type.
    pub media_type: mneme_core::Symbol,
    /// Chunks held.
    pub received: u32,
    /// Chunks the asset has.
    pub total: u32,
}

/// The storage pending transfers hold.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransferUsage {
    /// Pending transfers.
    pub transfers: u64,
    /// Chunks they hold.
    pub chunks: u64,
    /// Bytes their chunks hold.
    pub bytes: u64,
}

/// Where a source's original bytes stand on this device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaArrival {
    /// The source is committed with its bytes.
    Retained,
    /// The bytes are arriving.
    Pending {
        /// Chunks held.
        received: u32,
        /// Chunks the asset has.
        total: u32,
    },
    /// The source was forgotten; its bytes are refused.
    Forgotten,
    /// Nothing here names the bytes.
    Missing,
}

/// What an import decided for a bundle's assets.
#[derive(Default)]
pub(super) struct Arrivals {
    /// Bytes verified for sources the import publishes.
    pub(super) ready: std::collections::BTreeMap<mneme_core::RecordId, Vec<u8>>,
    /// Sources still waiting for bytes, and every record that needs them.
    pub(super) deferred: std::collections::BTreeSet<mneme_core::RecordId>,
    /// Assets still waiting for bytes.
    pub(super) pending: Vec<mneme_core::ContentDigest>,
    /// Assets refused: forgotten here, or chunks that do not make the asset.
    pub(super) refused: Vec<mneme_core::ContentDigest>,
}

/// One asset's chunks as a transfer holds them.
enum Assembly {
    Complete(Vec<u8>),
    Incomplete,
    Corrupt,
}

pub(super) fn asset_value(asset: &Asset) -> mneme_core::Value {
    mneme_core::Value::record_named(
        "exchange-asset",
        vec![
            asset.source.to_value(),
            asset.revision.to_value(),
            asset.scope.to_value(),
            asset.digest.to_value(),
            mneme_core::Value::integer(asset.byte_length),
            asset.media_type.clone().into_value(),
            mneme_core::Value::integer(asset.chunk_bytes),
            mneme_core::Value::sequence(
                asset.chunks.iter().map(|chunk| chunk.to_value()).collect(),
            ),
            mneme_core::Value::set(asset.dependents.iter().map(|record| record.to_value())),
        ],
    )
}

pub(super) fn read_asset_set(value: &mneme_core::Value) -> Result<Vec<Asset>, super::Error> {
    let Some(items) = value.as_set() else {
        return Err(super::Error::MalformedBundle);
    };
    if items.len() > super::MAX_SOURCE_BLOBS {
        return Err(super::Error::MalformedBundle);
    }
    let mut assets = Vec::with_capacity(items.len());
    for item in items {
        assets.push(read_asset(item)?);
    }
    Ok(assets)
}

fn read_asset(item: &mneme_core::Value) -> Result<Asset, super::Error> {
    let fields = super::record_fields(item, "exchange-asset", 9)?;
    let digest = |value: &mneme_core::Value| {
        mneme_core::ContentDigest::from_value(value, &mneme_core::Path::root())
            .map_err(|_| super::Error::MalformedBundle)
    };
    let byte_length = read_count(&fields[4])?;
    let chunk_bytes =
        u32::try_from(read_count(&fields[6])?).map_err(|_| super::Error::MalformedBundle)?;
    let Some(chunk_values) = fields[7].as_sequence() else {
        return Err(super::Error::MalformedBundle);
    };
    let Some(dependent_values) = fields[8].as_set() else {
        return Err(super::Error::MalformedBundle);
    };
    if byte_length > MAX_EXCHANGE_ASSET_BYTES {
        return Err(super::Error::AssetTooLarge);
    }
    let expected_chunks = byte_length.div_ceil(u64::from(chunk_bytes.max(1)));
    if byte_length == 0
        || !(MIN_CHUNK_BYTES..=MAX_CHUNK_BYTES).contains(&chunk_bytes)
        || u64::try_from(chunk_values.len()).ok() != Some(expected_chunks)
        || dependent_values.len() > super::MAX_RECORDS
    {
        return Err(super::Error::MalformedBundle);
    }
    let count = u32::try_from(chunk_values.len()).map_err(|_| super::Error::MalformedBundle)?;
    Ok(Asset {
        count,
        source: super::parse_id(&fields[0])?,
        revision: super::parse_revision(&fields[1])?,
        scope: mneme_core::ScopeId::from_value(&fields[2], &mneme_core::Path::root())
            .map_err(|_| super::Error::MalformedBundle)?,
        digest: digest(&fields[3])?,
        byte_length,
        media_type: mneme_core::Symbol::new(super::read_symbol(&fields[5])?),
        chunk_bytes,
        chunks: chunk_values.iter().map(digest).collect::<Result<_, _>>()?,
        dependents: dependent_values
            .iter()
            .map(super::parse_id)
            .collect::<Result<_, _>>()?,
    })
}

fn read_count(value: &mneme_core::Value) -> Result<u64, super::Error> {
    value
        .as_integer()
        .and_then(mneme_core::SignedInteger::to_i64)
        .and_then(|count| u64::try_from(count).ok())
        .ok_or(super::Error::MalformedBundle)
}

/// Check that every manifest entry names a source the bundle signs, with the
/// same digest, length, media type and scope, and with exactly the records
/// that depend on it. A substituted source or dependency fails here.
pub(super) fn check_assets(
    records: &[mneme_core::RecordEnvelope],
    inline: &std::collections::BTreeSet<mneme_core::ContentDigest>,
    assets: &[Asset],
) -> Result<(), super::Error> {
    let mut seen = std::collections::BTreeSet::new();
    let mut layouts = std::collections::BTreeMap::new();
    for asset in assets {
        // A digest is one transfer, so every source that shares bytes shares
        // their chunks.
        let layout = (asset.chunk_bytes, &asset.chunks);
        if *layouts.entry(asset.digest).or_insert(layout) != layout {
            return Err(super::Error::MalformedBundle);
        }
        let Some(record) = records
            .iter()
            .find(|record| record.record_id == asset.source)
        else {
            return Err(super::Error::MalformedBundle);
        };
        if !seen.insert(asset.source)
            || record.revision_id != asset.revision
            || record.scope != asset.scope
            || record.kind != mneme_core::RecordKind::SourceRevision
            || inline.contains(&asset.digest)
        {
            return Err(super::Error::MalformedBundle);
        }
        let source = crate::model::SourceView::parse(record.clone())?;
        let mneme_core::SourceContent::Retained(retained) = source.content else {
            return Err(super::Error::MalformedBundle);
        };
        if retained.digest() != asset.digest
            || retained.byte_length() != asset.byte_length
            || retained.media_type() != &asset.media_type
            || dependents_of(records, asset.source) != asset.dependents
        {
            return Err(super::Error::MalformedBundle);
        }
    }
    Ok(())
}

/// The records of `records` that need `source`, directly or through others.
pub(super) fn dependents_of(
    records: &[mneme_core::RecordEnvelope],
    source: mneme_core::RecordId,
) -> Vec<mneme_core::RecordId> {
    let mut set = std::collections::BTreeSet::from([source]);
    super::add_dependents(records, &mut set);
    set.remove(&source);
    set.into_iter().collect()
}

/// Cut a stored source into chunks and record their digests. The whole asset
/// is hashed as it is read, so a stored blob that no longer matches its
/// record is never offered.
pub(super) fn asset_of(
    workspace: &mneme_store::Workspace,
    record: &mneme_core::RecordEnvelope,
    retained: &mneme_core::RetainedSource,
    dependents: Vec<mneme_core::RecordId>,
) -> Result<Asset, super::Error> {
    let byte_length = retained.byte_length();
    if byte_length > MAX_EXCHANGE_ASSET_BYTES {
        return Err(super::Error::AssetTooLarge);
    }
    let count = u32::try_from(byte_length.div_ceil(u64::from(ASSET_CHUNK_BYTES)))
        .map_err(|_| super::Error::AssetTooLarge)?;
    let mut asset = Asset {
        count,
        source: record.record_id,
        revision: record.revision_id,
        scope: record.scope.clone(),
        digest: retained.digest(),
        byte_length,
        media_type: retained.media_type().clone(),
        chunk_bytes: ASSET_CHUNK_BYTES,
        chunks: Vec::with_capacity(
            usize::try_from(count).map_err(|_| super::Error::AssetTooLarge)?,
        ),
        dependents,
    };
    let mut whole = sha2::Sha256::new();
    for index in 0..count {
        let Some((offset, length)) = asset.chunk_span(index) else {
            return Err(super::Error::MalformedBundle);
        };
        let bytes =
            mneme_store::payload::read_range(workspace.root(), asset.digest, offset, length)?;
        whole.update(&bytes);
        asset
            .chunks
            .push(mneme_core::ContentDigest::of_source_bytes(&bytes));
    }
    let whole: [u8; 32] = whole.finalize().into();
    if &whole != asset.digest.as_bytes() {
        return Err(super::Error::Store(mneme_store::Failure::CorruptBlob {
            digest: asset.digest.to_hex(),
            reason: "stored bytes do not hash to the committed digest".to_owned(),
        }));
    }
    Ok(asset)
}

/// The asset of one selected source, when `scopes` share it with other
/// devices: the source revision must be current, retained and exportable.
/// Every other case, including a source that does not exist, is refused the
/// same way, so a request learns nothing of sources it may not have. A
/// digest alone never selects bytes.
pub fn grant_asset(
    workspace: &mneme_store::Workspace,
    scopes: &std::collections::BTreeSet<mneme_core::ScopeId>,
    source: mneme_core::RecordId,
    revision: mneme_core::RevisionId,
) -> Result<Asset, super::Error> {
    let records = super::exportable_records(workspace, scopes)?;
    let Some(record) = records
        .iter()
        .find(|record| record.record_id == source && record.revision_id == revision)
    else {
        return Err(super::Error::AssetUnavailable);
    };
    if record.kind != mneme_core::RecordKind::SourceRevision {
        return Err(super::Error::AssetUnavailable);
    }
    let view = crate::model::SourceView::parse(record.clone())?;
    let mneme_core::SourceContent::Retained(retained) = &view.content else {
        return Err(super::Error::AssetUnavailable);
    };
    asset_of(workspace, record, retained, dependents_of(&records, source))
}

/// Read chunk `index` of an asset this workspace holds, checked against the
/// digest its manifest signed.
pub fn asset_chunk(
    workspace: &mneme_store::Workspace,
    asset: &Asset,
    index: u32,
) -> Result<Vec<u8>, super::Error> {
    let (Some((offset, length)), Some(expected)) = (
        asset.chunk_span(index),
        usize::try_from(index)
            .ok()
            .and_then(|index| asset.chunks.get(index)),
    ) else {
        return Err(super::Error::AssetUnavailable);
    };
    let bytes = mneme_store::payload::read_range(workspace.root(), asset.digest, offset, length)?;
    if mneme_core::ContentDigest::of_source_bytes(&bytes) != *expected {
        return Err(super::Error::Store(mneme_store::Failure::CorruptBlob {
            digest: asset.digest.to_hex(),
            reason: "a stored chunk does not hash to its manifest digest".to_owned(),
        }));
    }
    Ok(bytes)
}

/// Keep one chunk of an asset the authenticated bundle names, once it hashes
/// to the digest the manifest signed for its place. The chunk is refused, and
/// what the transfer held is removed, when the source or its bytes were
/// forgotten here; a chunk that would take pending transfers past their bound
/// is refused too.
pub fn receive_chunk(
    workspace: &mneme_store::Workspace,
    bundle: &super::AuthenticatedBundle,
    digest: mneme_core::ContentDigest,
    index: u32,
    bytes: &[u8],
) -> Result<ChunkReceipt, super::Error> {
    let Some(asset) = bundle
        .bundle
        .assets
        .iter()
        .find(|asset| asset.digest == digest)
    else {
        return Err(super::Error::UnknownAsset);
    };
    let expected = usize::try_from(index)
        .ok()
        .and_then(|index| asset.chunks.get(index));
    let is_whole = asset
        .chunk_span(index)
        .is_some_and(|(_, length)| length == bytes.len());
    if !is_whole || expected != Some(&mneme_core::ContentDigest::of_source_bytes(bytes)) {
        return Err(super::Error::CorruptChunk);
    }
    let root = workspace.root();
    let directory = mneme_store::payload::transfer_path(root, &bundle.bundle.key_id, digest)?;
    let total = asset.chunk_count();
    match need(workspace, &bundle.bundle, digest)? {
        Need::Forgotten => {
            remove_transfer(&directory)?;
            return Err(super::Error::AssetForgotten);
        }
        Need::Held => {
            return Ok(ChunkReceipt {
                received: total,
                total,
                is_new: false,
            });
        }
        Need::Chunks => {}
    }
    open_transfer(&directory, &bundle.bundle.issuer, asset)?;
    let path = directory.join(chunk_name(index));
    let is_new = !is_file_of_length(&path, bytes.len())?;
    if is_new {
        let held = transfer_usage_in(root)?.bytes;
        let length = u64::try_from(bytes.len()).map_err(|_| super::Error::TransferQuotaExceeded)?;
        if held.saturating_add(length) > MAX_TRANSFER_BYTES {
            return Err(super::Error::TransferQuotaExceeded);
        }
        write_atomically(&path, bytes)?;
    }
    Ok(ChunkReceipt {
        received: held_chunks(&directory, asset)?,
        total,
        is_new,
    })
}

/// Decide each of a bundle's assets for one import: publish those whose
/// chunks are all here and make the asset, refuse forgotten ones, and defer
/// the rest with every record that needs them.
pub(super) fn arrivals(
    workspace: &mneme_store::Workspace,
    bundle: &super::SignedBundle,
    blocked: &std::collections::BTreeSet<mneme_core::RecordId>,
    local: &std::collections::BTreeMap<mneme_core::RecordId, &mneme_core::RecordEnvelope>,
) -> Result<Arrivals, super::Error> {
    let root = workspace.root();
    let mut arrivals = Arrivals::default();
    let mut published = 0_u64;
    for asset in &bundle.assets {
        let directory = mneme_store::payload::transfer_path(root, &bundle.key_id, asset.digest)?;
        if blocked.contains(&asset.source) {
            remove_transfer(&directory)?;
            arrivals.refused.push(asset.digest);
            continue;
        }
        if holds_digest(local, asset)? {
            remove_transfer(&directory)?;
            continue;
        }
        let assembly = if published.saturating_add(asset.byte_length) > MAX_PUBLISHED_BYTES {
            Assembly::Incomplete
        } else if mneme_store::payload::blob_is_present(root, asset.digest, asset.byte_length)? {
            // Another source already brought these bytes; they are verified
            // as they are read.
            Assembly::Complete(mneme_store::payload::read(root, asset.digest)?)
        } else {
            assemble(&directory, asset)?
        };
        match assembly {
            Assembly::Complete(bytes) => {
                published = published.saturating_add(asset.byte_length);
                arrivals.ready.insert(asset.source, bytes);
            }
            Assembly::Incomplete => {
                open_transfer(&directory, &bundle.issuer, asset)?;
                arrivals.pending.push(asset.digest);
                arrivals.deferred.insert(asset.source);
            }
            Assembly::Corrupt => {
                remove_transfer(&directory)?;
                arrivals.refused.push(asset.digest);
                arrivals.deferred.insert(asset.source);
            }
        }
    }
    super::add_dependents(&bundle.records, &mut arrivals.deferred);
    // A source whose bytes are here but which needs a source still arriving
    // waits with it; its chunks stay, and it is reported pending.
    let waiting = arrivals
        .ready
        .keys()
        .filter(|source| arrivals.deferred.contains(*source))
        .copied()
        .collect::<Vec<_>>();
    for source in waiting {
        arrivals.ready.remove(&source);
        if let Some(asset) = bundle.assets.iter().find(|asset| asset.source == source) {
            arrivals.pending.push(asset.digest);
        }
    }
    Ok(arrivals)
}

/// What a bundle's sources of one digest still need here.
enum Need {
    /// Every source of the digest was forgotten here.
    Forgotten,
    /// Every source of the digest is held, or its bytes are.
    Held,
    /// Chunks: a source of the digest is neither held nor forgotten.
    Chunks,
}

fn need(
    workspace: &mneme_store::Workspace,
    bundle: &super::SignedBundle,
    digest: mneme_core::ContentDigest,
) -> Result<Need, super::Error> {
    let blocked = super::blocked_records(&bundle.records, &workspace.active_suppressions()?)?;
    let open = bundle
        .assets
        .iter()
        .filter(|asset| asset.digest == digest && !blocked.contains(&asset.source))
        .collect::<Vec<_>>();
    let Some(first) = open.first() else {
        return Ok(Need::Forgotten);
    };
    if mneme_store::payload::blob_is_present(workspace.root(), digest, first.byte_length)? {
        return Ok(Need::Held);
    }
    let snapshot = workspace.snapshot()?;
    let local = snapshot
        .records
        .iter()
        .map(|record| (record.record_id, record))
        .collect();
    for asset in open {
        if !holds_digest(&local, asset)? {
            return Ok(Need::Chunks);
        }
    }
    Ok(Need::Held)
}

/// The chunks of a bundle's assets this workspace still wants, by digest; an
/// asset held, forgotten or with every chunk here is not listed. A transport
/// sends or reads only these.
pub fn wanted_chunks(
    workspace: &mneme_store::Workspace,
    bundle: &super::AuthenticatedBundle,
) -> Result<Vec<(mneme_core::ContentDigest, Vec<u32>)>, super::Error> {
    let mut digests = bundle
        .bundle
        .assets
        .iter()
        .map(|asset| asset.digest)
        .collect::<Vec<_>>();
    digests.sort();
    digests.dedup();
    let mut wanted = Vec::with_capacity(digests.len());
    for digest in digests {
        let Need::Chunks = need(workspace, &bundle.bundle, digest)? else {
            continue;
        };
        let Some(asset) = bundle
            .bundle
            .assets
            .iter()
            .find(|asset| asset.digest == digest)
        else {
            continue;
        };
        let directory =
            mneme_store::payload::transfer_path(workspace.root(), &bundle.bundle.key_id, digest)?;
        let mut missing = Vec::with_capacity(asset.chunks.len());
        for index in 0..asset.chunk_count() {
            let Some((_, length)) = asset.chunk_span(index) else {
                continue;
            };
            if !is_file_of_length(&directory.join(chunk_name(index)), length)? {
                missing.push(index);
            }
        }
        if !missing.is_empty() {
            wanted.push((digest, missing));
        }
    }
    Ok(wanted)
}

/// Remove every transfer of one source's bytes, whichever device sent it,
/// and return how many were removed.
pub fn release_pending_source(
    workspace: &mneme_store::Workspace,
    source: mneme_core::RecordId,
) -> Result<u64, super::Error> {
    let mut released = 0_u64;
    for directory in transfer_directories(workspace.root())? {
        let is_named = read_manifest(&directory)?.is_some_and(|(_, asset)| asset.source == source);
        if is_named {
            remove_transfer(&directory)?;
            released = released.saturating_add(1);
        }
    }
    Ok(released)
}

/// Remove the transfers of devices the policy no longer trusts: their chunks
/// can never be published.
pub fn release_untrusted(
    workspace: &mneme_store::Workspace,
    policy: &super::Policy,
) -> Result<u64, super::Error> {
    let trusted = policy
        .peers
        .values()
        .map(|peer| peer.key_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut released = 0_u64;
    for owner in read_directories(
        &workspace
            .root()
            .join(mneme_store::payload::TRANSFER_DIRECTORY),
    )? {
        let is_trusted = owner
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|name| trusted.contains(name));
        if !is_trusted {
            remove_transfer(&owner)?;
            released = released.saturating_add(1);
        }
    }
    Ok(released)
}

/// Remove the transfers of assets an import published.
pub(super) fn release_published(
    root: &std::path::Path,
    owner: &str,
    published: &[mneme_core::ContentDigest],
) -> Result<(), super::Error> {
    for digest in published {
        remove_transfer(&mneme_store::payload::transfer_path(root, owner, *digest)?)?;
    }
    Ok(())
}

/// Every source whose bytes are still arriving, with how many chunks are here.
pub fn pending_assets(
    workspace: &mneme_store::Workspace,
) -> Result<Vec<PendingAsset>, super::Error> {
    let directories = transfer_directories(workspace.root())?;
    let suppressions = workspace.active_suppressions()?;
    let is_forgotten = |asset: &Asset| {
        suppressions.iter().any(|suppression| {
            suppression.mode == mneme_store::SuppressionMode::Forgotten
                && (suppression.target == asset.source
                    || suppression.content_digest == Some(asset.digest))
        })
    };
    let mut pending = Vec::with_capacity(directories.len());
    for directory in directories {
        let Some((issuer, asset)) = read_manifest(&directory)? else {
            continue;
        };
        if is_forgotten(&asset) {
            continue;
        }
        pending.push(PendingAsset {
            issuer,
            source: asset.source,
            revision: asset.revision,
            scope: asset.scope.clone(),
            digest: asset.digest,
            byte_length: asset.byte_length,
            media_type: asset.media_type.clone(),
            received: held_chunks(&directory, &asset)?,
            total: asset.chunk_count(),
        });
    }
    pending.sort_by(|left, right| {
        (left.source, left.revision, &left.issuer).cmp(&(
            right.source,
            right.revision,
            &right.issuer,
        ))
    });
    Ok(pending)
}

/// The storage pending transfers hold.
pub fn transfer_usage(workspace: &mneme_store::Workspace) -> Result<TransferUsage, super::Error> {
    transfer_usage_in(workspace.root())
}

/// Where the original bytes of one source revision stand on this device.
pub fn media_arrival(
    workspace: &mneme_store::Workspace,
    source: mneme_core::RecordId,
    revision: mneme_core::RevisionId,
) -> Result<MediaArrival, super::Error> {
    let snapshot = workspace.snapshot()?;
    if let Some(record) = snapshot
        .records
        .iter()
        .find(|record| record.record_id == source)
    {
        let view = crate::model::SourceView::parse(record.clone())?;
        let is_retained = record.revision_id == revision
            && matches!(view.content, mneme_core::SourceContent::Retained(_));
        return Ok(if is_retained {
            MediaArrival::Retained
        } else {
            MediaArrival::Missing
        });
    }
    let is_forgotten = workspace.active_suppressions()?.iter().any(|suppression| {
        suppression.mode == mneme_store::SuppressionMode::Forgotten && suppression.target == source
    });
    if is_forgotten {
        return Ok(MediaArrival::Forgotten);
    }
    Ok(pending_assets(workspace)?
        .into_iter()
        .find(|pending| pending.source == source && pending.revision == revision)
        .map_or(MediaArrival::Missing, |pending| MediaArrival::Pending {
            received: pending.received,
            total: pending.total,
        }))
}

fn holds_digest(
    local: &std::collections::BTreeMap<mneme_core::RecordId, &mneme_core::RecordEnvelope>,
    asset: &Asset,
) -> Result<bool, super::Error> {
    let Some(record) = local.get(&asset.source) else {
        return Ok(false);
    };
    let view = crate::model::SourceView::parse((*record).clone())?;
    Ok(view.digest() == Some(asset.digest))
}

/// Read every chunk of a transfer in order. A chunk that no longer hashes to
/// its manifest digest is removed, to arrive again.
fn assemble(directory: &std::path::Path, asset: &Asset) -> Result<Assembly, super::Error> {
    let capacity = usize::try_from(asset.byte_length).map_err(|_| super::Error::AssetTooLarge)?;
    let mut bytes = Vec::with_capacity(capacity);
    for (index, expected) in (0..asset.chunk_count()).zip(&asset.chunks) {
        let path = directory.join(chunk_name(index));
        let chunk = match std::fs::read(&path) {
            Ok(chunk) => chunk,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Assembly::Incomplete);
            }
            Err(error) => return Err(io_error(&path, error)),
        };
        if mneme_core::ContentDigest::of_source_bytes(&chunk) != *expected {
            std::fs::remove_file(&path).map_err(|error| io_error(&path, error))?;
            return Ok(Assembly::Incomplete);
        }
        bytes.extend_from_slice(&chunk);
    }
    let is_whole = u64::try_from(bytes.len()).ok() == Some(asset.byte_length)
        && mneme_core::ContentDigest::of_source_bytes(&bytes) == asset.digest;
    Ok(if is_whole {
        Assembly::Complete(bytes)
    } else {
        Assembly::Corrupt
    })
}

/// Create a transfer's directory and its manifest, once.
fn open_transfer(
    directory: &std::path::Path,
    issuer: &str,
    asset: &Asset,
) -> Result<(), super::Error> {
    let manifest = directory.join(MANIFEST_FILE);
    if manifest.is_file() {
        return Ok(());
    }
    mneme_store::payload::create_directory_chain_flushed(directory)?;
    let value = mneme_core::Value::record_named(
        TRANSFER_LABEL,
        vec![mneme_core::Value::string(issuer), asset_value(asset)],
    );
    write_atomically(&manifest, &mneme_core::encode(&value))
}

fn read_manifest(directory: &std::path::Path) -> Result<Option<(String, Asset)>, super::Error> {
    let path = directory.join(MANIFEST_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(&path, error)),
    };
    let value = mneme_core::decode_canonical(&bytes).map_err(|_| super::Error::MalformedBundle)?;
    let fields = super::record_fields(&value, TRANSFER_LABEL, 2)?;
    Ok(Some((
        super::read_string(&fields[0])?.to_owned(),
        read_asset(&fields[1])?,
    )))
}

/// How many of an asset's chunks a transfer holds whole.
fn held_chunks(directory: &std::path::Path, asset: &Asset) -> Result<u32, super::Error> {
    let mut held = 0_u32;
    for index in 0..asset.chunk_count() {
        let Some((_, length)) = asset.chunk_span(index) else {
            continue;
        };
        if is_file_of_length(&directory.join(chunk_name(index)), length)? {
            held = held.saturating_add(1);
        }
    }
    Ok(held)
}

fn is_file_of_length(path: &std::path::Path, length: usize) -> Result<bool, super::Error> {
    match std::fs::metadata(path) {
        Ok(metadata) => {
            Ok(metadata.is_file() && u64::try_from(length).ok() == Some(metadata.len()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error(path, error)),
    }
}

fn chunk_name(index: u32) -> String {
    format!("{index}{CHUNK_SUFFIX}")
}

/// Every transfer directory: `transfers/<owner>/<digest>`.
fn transfer_directories(root: &std::path::Path) -> Result<Vec<std::path::PathBuf>, super::Error> {
    let transfers = root.join(mneme_store::payload::TRANSFER_DIRECTORY);
    let mut found = Vec::new();
    for owner in read_directories(&transfers)? {
        for transfer in read_directories(&owner)? {
            if found.len() >= MAX_TRANSFERS {
                return Err(super::Error::TransferQuotaExceeded);
            }
            found.push(transfer);
        }
    }
    found.sort();
    Ok(found)
}

fn read_directories(directory: &std::path::Path) -> Result<Vec<std::path::PathBuf>, super::Error> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(io_error(directory, error)),
    };
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| io_error(directory, error))?;
        let is_directory = entry
            .file_type()
            .map_err(|error| io_error(&entry.path(), error))?
            .is_dir();
        if is_directory {
            if found.len() >= MAX_TRANSFERS {
                return Err(super::Error::TransferQuotaExceeded);
            }
            found.push(entry.path());
        }
    }
    Ok(found)
}

fn transfer_usage_in(root: &std::path::Path) -> Result<TransferUsage, super::Error> {
    let mut usage = TransferUsage::default();
    for directory in transfer_directories(root)? {
        usage.transfers = usage.transfers.saturating_add(1);
        for entry in std::fs::read_dir(&directory).map_err(|error| io_error(&directory, error))? {
            let entry = entry.map_err(|error| io_error(&directory, error))?;
            let name = entry.file_name();
            let is_chunk = name.to_string_lossy().ends_with(CHUNK_SUFFIX);
            let metadata = entry
                .metadata()
                .map_err(|error| io_error(&entry.path(), error))?;
            // Everything a transfer holds counts against the bound, including
            // a write a crash interrupted.
            if metadata.is_file() && name != MANIFEST_FILE {
                usage.bytes = usage.bytes.saturating_add(metadata.len());
                if is_chunk {
                    usage.chunks = usage.chunks.saturating_add(1);
                }
            }
        }
    }
    Ok(usage)
}

fn remove_transfer(directory: &std::path::Path) -> Result<(), super::Error> {
    match std::fs::remove_dir_all(directory) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(directory, error)),
    }
}

/// Write a file whole or not at all: a reader never sees part of a chunk.
fn write_atomically(path: &std::path::Path, bytes: &[u8]) -> Result<(), super::Error> {
    let Some(directory) = path.parent() else {
        return Err(super::Error::MalformedBundle);
    };
    let temporary = directory.join(format!(
        ".incoming-{}",
        mneme_store::payload::random_hex(8)?
    ));
    let written = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .and_then(|mut file| {
            std::io::Write::write_all(&mut file, bytes)?;
            file.sync_all()
        });
    if let Err(error) = written {
        // A failed write takes its partial file with it; the write's own
        // error is reported unless the partial file cannot be removed.
        if let Err(cleanup) = std::fs::remove_file(&temporary)
            && cleanup.kind() != std::io::ErrorKind::NotFound
        {
            return Err(io_error(&temporary, cleanup));
        }
        return Err(io_error(&temporary, error));
    }
    std::fs::rename(&temporary, path).map_err(|error| io_error(path, error))?;
    if let Ok(handle) = std::fs::File::open(directory) {
        handle
            .sync_all()
            .map_err(|error| io_error(directory, error))?;
    }
    Ok(())
}

fn io_error(path: &std::path::Path, error: std::io::Error) -> super::Error {
    super::Error::Store(mneme_store::Failure::io(path, error))
}
