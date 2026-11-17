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
/// what the transfer held is removed, when every source of its bytes was
/// forgotten here. A transfer's first chunk is admitted only while its whole
/// asset fits beside the room every started transfer holds; a later chunk of
/// a started transfer is always kept, so a started transfer can finish.
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
    let blocked =
        super::blocked_records(&bundle.bundle.records, &workspace.active_suppressions()?)?;
    let is_forgotten = bundle
        .bundle
        .assets
        .iter()
        .filter(|asset| asset.digest == digest)
        .all(|asset| blocked.contains(&asset.source));
    if is_forgotten {
        remove_transfer(&directory)?;
        return Err(super::Error::AssetForgotten);
    }
    let total = asset.chunk_count();
    let path = directory.join(chunk_name(index));
    let is_new = !is_file_of_length(&path, bytes.len())?;
    if is_new {
        if held_chunks(&directory, asset)? == 0
            && let Some(receipt) =
                start_transfer(workspace, &bundle.bundle, asset, &blocked, &directory)?
        {
            return Ok(receipt);
        }
        open_transfer(&directory, &bundle.bundle.issuer, asset)?;
        write_atomically(&path, bytes)?;
    }
    Ok(ChunkReceipt {
        received: held_chunks(&directory, asset)?,
        total,
        is_new,
    })
}

/// Decide whether a transfer may start with this chunk. Bytes already here
/// need no transfer, and the receipt says so; an asset waits until every
/// asset it needs is here whole, so it never takes room its parent needs; and
/// the transfer must fit beside the room started transfers hold.
fn start_transfer(
    workspace: &mneme_store::Workspace,
    bundle: &super::SignedBundle,
    asset: &Asset,
    blocked: &std::collections::BTreeSet<mneme_core::RecordId>,
    directory: &std::path::Path,
) -> Result<Option<ChunkReceipt>, super::Error> {
    let snapshot = workspace.snapshot()?;
    let local = snapshot
        .records
        .iter()
        .map(|record| (record.record_id, record))
        .collect::<std::collections::BTreeMap<_, _>>();
    let here = local_bytes(workspace, &local)?;
    if is_held_here(bundle, (&local, &here), asset.digest, blocked)? {
        let total = asset.chunk_count();
        return Ok(Some(ChunkReceipt {
            received: total,
            total,
            is_new: false,
        }));
    }
    if !are_parents_here(workspace.root(), bundle, asset, (&local, &here))? {
        return Err(super::Error::AssetWaiting);
    }
    admit(workspace.root(), directory, asset.byte_length)?;
    Ok(None)
}

/// What is here already: the records by identity, and the bytes the
/// unforgotten sources of each scope hold.
type Here<'a> = (
    &'a std::collections::BTreeMap<mneme_core::RecordId, &'a mneme_core::RecordEnvelope>,
    &'a std::collections::BTreeSet<(mneme_core::ScopeId, mneme_core::ContentDigest)>,
);

/// Whether every source of these bytes the bundle offers and this workspace
/// has not forgotten is here already, or has the bytes from a source of its
/// own scope.
fn is_held_here(
    bundle: &super::SignedBundle,
    (local, here): Here<'_>,
    digest: mneme_core::ContentDigest,
    blocked: &std::collections::BTreeSet<mneme_core::RecordId>,
) -> Result<bool, super::Error> {
    for asset in bundle
        .assets
        .iter()
        .filter(|asset| asset.digest == digest && !blocked.contains(&asset.source))
    {
        if !here.contains(&(asset.scope.clone(), digest)) && !holds_digest(local, asset)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether every asset this one needs is here whole: held, its bytes held in
/// its own scope, or with every chunk received.
fn are_parents_here(
    root: &std::path::Path,
    bundle: &super::SignedBundle,
    asset: &Asset,
    (local, here): Here<'_>,
) -> Result<bool, super::Error> {
    for parent in bundle
        .assets
        .iter()
        .filter(|parent| parent.source != asset.source && parent.dependents.contains(&asset.source))
    {
        let directory = mneme_store::payload::transfer_path(root, &bundle.key_id, parent.digest)?;
        let is_here = holds_digest(local, parent)?
            || here.contains(&(parent.scope.clone(), parent.digest))
            || held_chunks(&directory, parent)? == parent.chunk_count();
        if !is_here {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Admit the first chunk of a transfer only when its whole asset fits beside
/// the room the other transfers hold: a started transfer holds room for its
/// whole asset, and anything else in a transfer directory counts as it is.
fn admit(root: &std::path::Path, own: &std::path::Path, length: u64) -> Result<(), super::Error> {
    let mut reserved = length;
    for directory in transfer_directories(root)? {
        let held = directory_usage(&directory)?.bytes;
        let whole = if directory == own {
            0
        } else {
            started_length(&directory)?
        };
        reserved = reserved.saturating_add(held.max(whole));
    }
    if reserved > MAX_TRANSFER_BYTES {
        return Err(super::Error::TransferQuotaExceeded);
    }
    Ok(())
}

/// The room a transfer holds: its whole asset's length once one of its
/// chunks is here, and none before or when its manifest cannot be read.
fn started_length(directory: &std::path::Path) -> Result<u64, super::Error> {
    let Ok(Some((_, asset))) = read_manifest(directory) else {
        return Ok(0);
    };
    Ok(if held_chunks(directory, &asset)? > 0 {
        asset.byte_length
    } else {
        0
    })
}

/// The bytes the unforgotten sources of each scope hold here, by digest: an
/// asset takes bytes already here only from a source of its own scope.
fn local_bytes(
    workspace: &mneme_store::Workspace,
    local: &std::collections::BTreeMap<mneme_core::RecordId, &mneme_core::RecordEnvelope>,
) -> Result<
    std::collections::BTreeSet<(mneme_core::ScopeId, mneme_core::ContentDigest)>,
    super::Error,
> {
    let suppressions = workspace.active_suppressions()?;
    let mut held = std::collections::BTreeSet::new();
    for record in local.values() {
        let Some(length) = super::retained_length(record) else {
            continue;
        };
        let Some(digest) = crate::model::SourceView::parse((*record).clone())?.digest() else {
            continue;
        };
        let is_forgotten = suppressions.iter().any(|suppression| {
            suppression.target == record.record_id || suppression.content_digest == Some(digest)
        });
        if !is_forgotten && mneme_store::payload::blob_is_present(workspace.root(), digest, length)?
        {
            held.insert((record.scope.clone(), digest));
        }
    }
    Ok(held)
}

/// Where one asset stands before an import reads any of its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Standing {
    /// Its source is forgotten here.
    Refused,
    /// Its source is already here with these bytes.
    Held,
    /// A source of its scope already holds its bytes here.
    Local,
    /// Every chunk is here.
    Arrived,
    /// A chunk is missing.
    Arriving,
}

fn standing(
    directory: &std::path::Path,
    asset: &Asset,
    blocked: &std::collections::BTreeSet<mneme_core::RecordId>,
    local: &std::collections::BTreeMap<mneme_core::RecordId, &mneme_core::RecordEnvelope>,
    here: &std::collections::BTreeSet<(mneme_core::ScopeId, mneme_core::ContentDigest)>,
) -> Result<Standing, super::Error> {
    if blocked.contains(&asset.source) {
        return Ok(Standing::Refused);
    }
    if holds_digest(local, asset)? {
        return Ok(Standing::Held);
    }
    if here.contains(&(asset.scope.clone(), asset.digest)) {
        return Ok(Standing::Local);
    }
    Ok(if held_chunks(directory, asset)? == asset.chunk_count() {
        Standing::Arrived
    } else {
        Standing::Arriving
    })
}

/// The assets one import publishes, in order, and the sources that wait.
#[derive(Debug, Default, PartialEq, Eq)]
struct Plan {
    /// Indexes of the assets to publish, each after every asset it needs.
    publish: Vec<usize>,
    /// Sources that wait, with every record that needs them.
    deferred: std::collections::BTreeSet<mneme_core::RecordId>,
}

/// Plan one import's publication: nothing whose bytes, or the bytes of an
/// asset it needs, are still arriving, and the rest parents first while what
/// is published stays within the budget. The defer function adds every
/// record that needs one of a set of sources.
fn plan_arrivals(
    assets: &[Asset],
    standings: &[Standing],
    budget: u64,
    defer: &dyn Fn(&mut std::collections::BTreeSet<mneme_core::RecordId>),
) -> Plan {
    let mut deferred = assets
        .iter()
        .zip(standings)
        .filter(|(_, standing)| **standing == Standing::Arriving)
        .map(|(asset, _)| asset.source)
        .collect::<std::collections::BTreeSet<_>>();
    defer(&mut deferred);
    let candidates = assets
        .iter()
        .zip(standings)
        .enumerate()
        .filter(|(_, (asset, standing))| {
            matches!(**standing, Standing::Local | Standing::Arrived)
                && !deferred.contains(&asset.source)
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let (order, tangled) = parents_first(assets, &candidates);
    let mut plan = Plan {
        publish: Vec::with_capacity(order.len()),
        deferred,
    };
    // Assets that need one another can never be published one at a time.
    if !tangled.is_empty() {
        plan.deferred.extend(
            tangled
                .iter()
                .filter_map(|index| assets.get(*index))
                .map(|asset| asset.source),
        );
        defer(&mut plan.deferred);
    }
    let mut spent = 0_u64;
    for index in order {
        let Some(asset) = assets.get(index) else {
            continue;
        };
        if plan.deferred.contains(&asset.source) {
            continue;
        }
        if spent.saturating_add(asset.byte_length) > budget {
            plan.deferred.insert(asset.source);
            defer(&mut plan.deferred);
            continue;
        }
        spent = spent.saturating_add(asset.byte_length);
        plan.publish.push(index);
    }
    plan
}

/// Order the candidates so each comes after every candidate whose
/// dependents include it, ties by index; candidates that need one another
/// are returned apart.
fn parents_first(assets: &[Asset], candidates: &[usize]) -> (Vec<usize>, Vec<usize>) {
    let is_needed_by = |parent: usize, child: usize| {
        parent != child
            && assets
                .get(parent)
                .zip(assets.get(child))
                .is_some_and(|(parent, child)| parent.dependents.contains(&child.source))
    };
    let mut unplaced = candidates
        .iter()
        .map(|&child| {
            let parents = candidates
                .iter()
                .filter(|&&parent| is_needed_by(parent, child))
                .count();
            (child, parents)
        })
        .collect::<std::collections::BTreeMap<usize, usize>>();
    let mut order = Vec::with_capacity(candidates.len());
    while let Some(next) = unplaced
        .iter()
        .find(|(_, parents)| **parents == 0)
        .map(|(index, _)| *index)
    {
        unplaced.remove(&next);
        order.push(next);
        for (child, parents) in &mut unplaced {
            if is_needed_by(next, *child) {
                *parents = parents.saturating_sub(1);
            }
        }
    }
    (order, unplaced.into_keys().collect())
}

/// Decide each of a bundle's assets for one import: refuse forgotten ones,
/// defer those whose bytes, or the bytes of an asset they need, are still
/// arriving, with every record that needs them, and publish the rest parents
/// first within the import's budget.
pub(super) fn arrivals(
    workspace: &mneme_store::Workspace,
    bundle: &super::SignedBundle,
    blocked: &std::collections::BTreeSet<mneme_core::RecordId>,
    local: &std::collections::BTreeMap<mneme_core::RecordId, &mneme_core::RecordEnvelope>,
) -> Result<Arrivals, super::Error> {
    let root = workspace.root();
    let here = local_bytes(workspace, local)?;
    let mut standings = Vec::with_capacity(bundle.assets.len());
    for asset in &bundle.assets {
        let directory = mneme_store::payload::transfer_path(root, &bundle.key_id, asset.digest)?;
        standings.push(standing(&directory, asset, blocked, local, &here)?);
    }
    let defer = |sources: &mut std::collections::BTreeSet<mneme_core::RecordId>| {
        super::add_dependents(&bundle.records, sources);
    };
    let plan = plan_arrivals(&bundle.assets, &standings, MAX_PUBLISHED_BYTES, &defer);
    let mut arrivals = Arrivals {
        deferred: plan.deferred,
        ..Arrivals::default()
    };
    for index in plan.publish {
        let (Some(asset), Some(standing)) = (bundle.assets.get(index), standings.get(index)) else {
            continue;
        };
        // An asset another one's damage held back waits with it.
        if arrivals.deferred.contains(&asset.source) {
            continue;
        }
        let directory = mneme_store::payload::transfer_path(root, &bundle.key_id, asset.digest)?;
        let assembly = if *standing == Standing::Local {
            // Bytes a source of this scope brought, verified as they are read.
            Assembly::Complete(mneme_store::payload::read(root, asset.digest)?)
        } else {
            assemble(&directory, asset)?
        };
        match assembly {
            Assembly::Complete(bytes) => {
                arrivals.ready.insert(asset.source, bytes);
            }
            Assembly::Incomplete => {
                arrivals.deferred.insert(asset.source);
                defer(&mut arrivals.deferred);
            }
            Assembly::Corrupt => {
                remove_transfer(&directory)?;
                arrivals.refused.push(asset.digest);
                arrivals.deferred.insert(asset.source);
                defer(&mut arrivals.deferred);
            }
        }
    }
    settle(root, bundle, &standings, &mut arrivals)?;
    Ok(arrivals)
}

/// Report the refused and waiting assets, keep the transfers waiting assets
/// need, and remove those nothing needs any more. A digest names one
/// transfer, which several sources of the same bytes share.
fn settle(
    root: &std::path::Path,
    bundle: &super::SignedBundle,
    standings: &[Standing],
    arrivals: &mut Arrivals,
) -> Result<(), super::Error> {
    arrivals
        .ready
        .retain(|source, _| !arrivals.deferred.contains(source));
    let mut waiting = std::collections::BTreeSet::new();
    for (asset, standing) in bundle.assets.iter().zip(standings) {
        match standing {
            Standing::Refused => arrivals.refused.push(asset.digest),
            Standing::Held => {}
            Standing::Local | Standing::Arrived | Standing::Arriving => {
                let is_waiting = arrivals.deferred.contains(&asset.source)
                    && !arrivals.refused.contains(&asset.digest);
                if is_waiting {
                    arrivals.pending.push(asset.digest);
                    if *standing != Standing::Local {
                        waiting.insert(asset.digest);
                    }
                }
            }
        }
    }
    let publishing = bundle
        .assets
        .iter()
        .filter(|asset| arrivals.ready.contains_key(&asset.source))
        .map(|asset| asset.digest)
        .collect::<std::collections::BTreeSet<_>>();
    for asset in &bundle.assets {
        let directory = mneme_store::payload::transfer_path(root, &bundle.key_id, asset.digest)?;
        if waiting.contains(&asset.digest) {
            open_transfer(&directory, &bundle.issuer, asset)?;
        } else if !publishing.contains(&asset.digest) {
            // Published bytes leave with the import's commit.
            remove_transfer(&directory)?;
        }
    }
    Ok(())
}

/// The chunks of a bundle's assets this workspace still wants, by digest: an
/// asset whose source is held or forgotten, whose bytes a source of its own
/// scope holds, or with every chunk here is not listed. A transport sends or
/// reads only these.
pub fn wanted_chunks(
    workspace: &mneme_store::Workspace,
    bundle: &super::AuthenticatedBundle,
) -> Result<Vec<(mneme_core::ContentDigest, Vec<u32>)>, super::Error> {
    let snapshot = workspace.snapshot()?;
    let local = snapshot
        .records
        .iter()
        .map(|record| (record.record_id, record))
        .collect::<std::collections::BTreeMap<_, _>>();
    let here = local_bytes(workspace, &local)?;
    let blocked =
        super::blocked_records(&bundle.bundle.records, &workspace.active_suppressions()?)?;
    let mut wanted = Vec::with_capacity(bundle.bundle.assets.len());
    for (index, asset) in bundle.bundle.assets.iter().enumerate() {
        let is_listed = wanted.iter().any(
            |(_, (digest, _)): &(usize, (mneme_core::ContentDigest, Vec<u32>))| {
                *digest == asset.digest
            },
        );
        let is_satisfied = blocked.contains(&asset.source)
            || here.contains(&(asset.scope.clone(), asset.digest))
            || holds_digest(&local, asset)?;
        if is_listed || is_satisfied {
            continue;
        }
        let directory = mneme_store::payload::transfer_path(
            workspace.root(),
            &bundle.bundle.key_id,
            asset.digest,
        )?;
        // An asset that may not start yet is not wanted yet.
        let is_started = held_chunks(&directory, asset)? > 0;
        if !is_started
            && !are_parents_here(workspace.root(), &bundle.bundle, asset, (&local, &here))?
        {
            continue;
        }
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
            wanted.push((index, (asset.digest, missing)));
        }
    }
    // Parents first, so a transport sends what others need before them.
    let indexes = wanted.iter().map(|(index, _)| *index).collect::<Vec<_>>();
    let (order, tangled) = parents_first(&bundle.bundle.assets, &indexes);
    Ok(order
        .into_iter()
        .chain(tangled)
        .filter_map(|index| {
            wanted
                .iter()
                .find(|(listed, _)| *listed == index)
                .map(|(_, entry)| entry.clone())
        })
        .collect())
}

/// Remove every transfer of one source's bytes, whichever device sent it,
/// and return how many were removed.
pub fn release_pending_source(
    workspace: &mneme_store::Workspace,
    source: mneme_core::RecordId,
) -> Result<u64, super::Error> {
    let mut released = 0_u64;
    let transfers = workspace
        .root()
        .join(mneme_store::payload::TRANSFER_DIRECTORY);
    for owner in every_directory(&transfers)? {
        for directory in every_directory(&owner)? {
            // A manifest that cannot be read names no source.
            let is_named = matches!(
                read_manifest(&directory),
                Ok(Some((_, asset))) if asset.source == source
            );
            if is_named {
                remove_transfer(&directory)?;
                released = released.saturating_add(1);
            }
        }
    }
    Ok(released)
}

/// Remove the transfers of the bundles' issuers that none of the bundles
/// names, as when a bundle left the shared folder before its bytes arrived,
/// and return how many were removed.
pub fn release_unnamed(
    workspace: &mneme_store::Workspace,
    bundles: &[&super::AuthenticatedBundle],
) -> Result<u64, super::Error> {
    let root = workspace.root();
    let named = bundles
        .iter()
        .flat_map(|bundle| {
            bundle.bundle.assets.iter().map(|asset| {
                mneme_store::payload::transfer_path(root, &bundle.bundle.key_id, asset.digest)
            })
        })
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    let owners = bundles
        .iter()
        .map(|bundle| bundle.bundle.key_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let transfers = root.join(mneme_store::payload::TRANSFER_DIRECTORY);
    let mut released = 0_u64;
    for owner in owners {
        for directory in every_directory(&transfers.join(owner))? {
            if !named.contains(&directory) {
                remove_transfer(&directory)?;
                released = released.saturating_add(1);
            }
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
        // A manifest that cannot be read names nothing arriving.
        let Ok(Some((issuer, asset))) = read_manifest(&directory) else {
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
        let held = directory_usage(&directory)?;
        usage.transfers = usage.transfers.saturating_add(held.transfers);
        usage.chunks = usage.chunks.saturating_add(held.chunks);
        usage.bytes = usage.bytes.saturating_add(held.bytes);
    }
    Ok(usage)
}

/// What one transfer directory holds; its manifest is not counted, and
/// everything else is, including a write a crash interrupted.
fn directory_usage(directory: &std::path::Path) -> Result<TransferUsage, super::Error> {
    let mut usage = TransferUsage {
        transfers: 1,
        ..TransferUsage::default()
    };
    for entry in std::fs::read_dir(directory).map_err(|error| io_error(directory, error))? {
        let entry = entry.map_err(|error| io_error(directory, error))?;
        let name = entry.file_name();
        let metadata = entry
            .metadata()
            .map_err(|error| io_error(&entry.path(), error))?;
        if metadata.is_file() && name != MANIFEST_FILE {
            usage.bytes = usage.bytes.saturating_add(metadata.len());
            if name.to_string_lossy().ends_with(CHUNK_SUFFIX) {
                usage.chunks = usage.chunks.saturating_add(1);
            }
        }
    }
    Ok(usage)
}

/// Every directory in a directory, however many there are.
fn every_directory(directory: &std::path::Path) -> Result<Vec<std::path::PathBuf>, super::Error> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(io_error(directory, error)),
    };
    entries
        .map(|entry| {
            let entry = entry.map_err(|error| io_error(directory, error))?;
            let is_directory = entry
                .file_type()
                .map_err(|error| io_error(&entry.path(), error))?
                .is_dir();
            Ok(is_directory.then(|| entry.path()))
        })
        .filter_map(Result::transpose)
        .collect()
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

#[cfg(test)]
mod tests {
    const MIB: u64 = 1024 * 1024;

    fn record(seed: u8) -> mneme_core::RecordId {
        mneme_core::RecordId::from_bytes([seed; 16])
    }

    fn asset(seed: u8, byte_length: u64, dependents: &[u8]) -> super::Asset {
        super::Asset {
            source: record(seed),
            revision: mneme_core::RevisionId::from_bytes([seed; 16]),
            scope: mneme_core::ScopeId::new(mneme_core::ScopeClass::User, "default")
                .expect("scope"),
            digest: mneme_core::ContentDigest::of_source_bytes(&[seed]),
            byte_length,
            media_type: mneme_core::Symbol::new("image/png"),
            chunk_bytes: super::ASSET_CHUNK_BYTES,
            chunks: Vec::new(),
            dependents: dependents.iter().map(|seed| record(*seed)).collect(),
            count: 0,
        }
    }

    /// Every record that needs one of the sources: a manifest's dependents
    /// already reach through others.
    fn needing(
        assets: &[super::Asset],
    ) -> impl Fn(&mut std::collections::BTreeSet<mneme_core::RecordId>) + '_ {
        |sources| {
            let more = assets
                .iter()
                .filter(|asset| sources.contains(&asset.source))
                .flat_map(|asset| asset.dependents.iter().copied())
                .collect::<Vec<_>>();
            sources.extend(more);
        }
    }

    #[test]
    fn a_parent_publishes_before_what_needs_it_spends_the_budget() {
        // Two derived images that sort before their scan.
        let assets = vec![
            asset(0xd1, 3 * MIB / 2, &[]),
            asset(0xd2, 3 * MIB / 2, &[]),
            asset(0xd9, 2 * MIB + 17, &[0xd1, 0xd2]),
        ];
        let arrived = [super::Standing::Arrived; 3];
        let first = super::plan_arrivals(&assets, &arrived, 3 * MIB, &needing(&assets));
        assert_eq!(first.publish, vec![2], "the scan goes first");
        assert_eq!(
            first.deferred,
            [record(0xd1), record(0xd2)].into_iter().collect()
        );
        // Once the scan is held, the next import publishes both images.
        let next = [
            super::Standing::Arrived,
            super::Standing::Arrived,
            super::Standing::Held,
        ];
        let second = super::plan_arrivals(&assets, &next, 3 * MIB, &needing(&assets));
        assert_eq!(second.publish, vec![0, 1]);
        assert!(second.deferred.is_empty());
    }

    #[test]
    fn an_arriving_parent_holds_back_what_needs_it_before_any_bytes_are_read() {
        let assets = vec![asset(0xd1, 10, &[]), asset(0xd9, 10, &[0xd1])];
        let standings = [super::Standing::Arrived, super::Standing::Arriving];
        let plan = super::plan_arrivals(&assets, &standings, u64::MAX, &needing(&assets));
        assert!(plan.publish.is_empty());
        assert_eq!(
            plan.deferred,
            [record(0xd1), record(0xd9)].into_iter().collect()
        );
    }

    #[test]
    fn the_budget_admits_exactly_its_bytes() {
        let assets = vec![asset(1, 6, &[]), asset(2, 4, &[]), asset(3, 1, &[])];
        let arrived = [super::Standing::Arrived; 3];
        let plan = super::plan_arrivals(&assets, &arrived, 10, &needing(&assets));
        assert_eq!(
            plan.publish,
            vec![0, 1],
            "6 and 4 fill a budget of 10 exactly"
        );
        assert_eq!(plan.deferred, [record(3)].into_iter().collect());
    }

    #[test]
    fn sources_that_need_one_another_wait() {
        let assets = vec![asset(1, 10, &[2]), asset(2, 10, &[1]), asset(3, 10, &[])];
        let local = [super::Standing::Local; 3];
        let plan = super::plan_arrivals(&assets, &local, u64::MAX, &needing(&assets));
        assert_eq!(plan.publish, vec![2]);
        assert_eq!(plan.deferred, [record(1), record(2)].into_iter().collect());
    }
}
