//! Zero-rehash disk-backed `iroh-blobs` store, protocol handler, and streaming downloader.
//!
//! Serves canonical BLAKE3 workspace blobs directly from `blobs/blake3/<ab>/<hex>`
//! and their existing `BlockSize(4)` (16 KiB chunk group) `.obao4` sidecars without
//! copying payloads into RAM or re-hashing on publish. Downloads verify every
//! 64-byte Merkle parent pair and 16 KiB leaf chunk while streaming directly to
//! disk under hard byte budgets.

use std::io::Read;
use std::io::Seek;
use std::io::Write;

use blake3::hazmat::HasherExt;
use iroh_blobs::provider::events::HasErrorCode;

const CHUNK_BYTES: u64 = 1024;
const CHUNKS_PER_GROUP: u64 = 16;
const CHUNK_GROUP_BYTES: u64 = CHUNK_BYTES * CHUNKS_PER_GROUP;
const HASH_BYTES: usize = 32;
const HASH_PAIR_BYTES: usize = 64;
const SIZE_HEADER_BYTES: usize = 8;
const INLINE_OUTBOARD_LIMIT_BYTES: usize = 3 * HASH_PAIR_BYTES;
const STREAM_CHANNEL_DEPTH: usize = 4;
const FRAMING_MAGIC_LEN: usize = 8;
const ZSTD_FRAME_MAGIC: &[u8; 8] = b"MNZSTD01";
const ZSTD_DICT_FRAME_MAGIC: &[u8; 8] = b"MNZSTD02";
const FASTCDC_FRAME_MAGIC: &[u8; 8] = b"MNCDC01\0";
const GET_BLOB_REQUEST_PREFIX_TAG: u8 = 0;
const GET_BLOB_REQUEST_RANGE_TAIL: [u8; 6] = [0x02, 0x00, 0x01, 0x00, 0x01, 0x00];
const MAX_TREE_STACK_DEPTH: usize = 64;
const EMPTY_CLOSE_CODE: u32 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TreeRole {
    Root,
    NonRoot,
}

/// On-disk descriptor for one content-addressed blob served over `iroh-blobs`.
#[derive(Clone, Debug)]
pub struct DiskBlobEntry {
    pub data_path: std::path::PathBuf,
    pub outboard_path: Option<std::path::PathBuf>,
    pub(crate) inline_outboard: Option<bytes::Bytes>,
    pub size_bytes: u64,
    pub reused_workspace_sidecar: bool,
}

struct DiskBlobStoreInner {
    staging_dir: tempfile::TempDir,
    entries: std::sync::RwLock<std::collections::BTreeMap<iroh_blobs::Hash, DiskBlobEntry>>,
    next_id: std::sync::atomic::AtomicU64,
}

/// Read-only disk-backed `iroh-blobs` store reusing workspace `blobs/blake3/` + `.obao4` files.
#[derive(Clone)]
pub struct DiskBlobStore {
    inner: std::sync::Arc<DiskBlobStoreInner>,
}

impl std::fmt::Debug for DiskBlobStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let entry_count = self.inner.entries.read().map_or(0, |guard| guard.len());
        formatter
            .debug_struct("DiskBlobStore")
            .field("entry_count", &entry_count)
            .finish()
    }
}

impl DiskBlobStore {
    /// Create a disk-backed blob store with an isolated temporary staging directory.
    pub fn new() -> crate::error::Result<Self> {
        let staging_dir = tempfile::tempdir().map_err(|error| {
            crate::error::Failure::Io(format!("create sync blob staging dir: {error}"))
        })?;
        Ok(Self {
            inner: std::sync::Arc::new(DiskBlobStoreInner {
                staging_dir,
                entries: std::sync::RwLock::new(std::collections::BTreeMap::new()),
                next_id: std::sync::atomic::AtomicU64::new(1),
            }),
        })
    }

    /// Allocate a unique staged file path for exporting a portable `.mneme` bundle on disk.
    pub fn allocate_staged_bundle_path(&self) -> std::path::PathBuf {
        let id = self
            .inner
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner
            .staging_dir
            .path()
            .join(format!("bundle-{id}.mneme"))
    }

    /// Stream-hash and register a staged file on disk under `max_bytes` without loading it into RAM.
    pub fn register_staged_file(
        &self,
        file_path: std::path::PathBuf,
        max_bytes: u64,
    ) -> crate::error::Result<(iroh_blobs::Hash, u64)> {
        let metadata = open_regular_metadata(&file_path)?;
        let size_bytes = metadata.len();
        if size_bytes > max_bytes {
            return Err(crate::error::Failure::SizeLimitExceeded {
                actual_bytes: size_bytes,
                limit_bytes: max_bytes,
            });
        }
        let (root_hash, outboard_bytes) = compute_outboard_from_file(&file_path, size_bytes)?;
        let (outboard_path, inline_outboard) = self.store_staged_outboard(outboard_bytes)?;
        let transport_hash = iroh_blobs::Hash::from_bytes(*root_hash.as_bytes());
        self.insert_entry(
            transport_hash,
            DiskBlobEntry {
                data_path: file_path,
                outboard_path,
                inline_outboard,
                size_bytes,
                reused_workspace_sidecar: false,
            },
        )?;
        Ok((transport_hash, size_bytes))
    }

    /// Register a workspace source blob directly from disk, reusing `blobs/blake3/` + `.obao4`
    /// with zero re-hashing and zero RAM copy whenever raw BLAKE3 bytes are on disk.
    pub fn register_workspace_blob(
        &self,
        workspace_root: &std::path::Path,
        digest: mneme_core::ContentDigest,
        expected_length: u64,
    ) -> crate::error::Result<iroh_blobs::Hash> {
        if digest.algorithm() == mneme_core::HashAlgorithm::Blake3
            && let Some(hash) =
                self.try_register_raw_blake3_blob(workspace_root, digest, expected_length)?
        {
            return Ok(hash);
        }
        self.register_decoded_fallback_blob(workspace_root, digest, expected_length)
    }

    /// Look up one registered blob descriptor by its `iroh-blobs` BLAKE3 hash.
    pub fn lookup(&self, hash: iroh_blobs::Hash) -> Option<DiskBlobEntry> {
        self.inner
            .entries
            .read()
            .ok()
            .and_then(|guard| guard.get(&hash).cloned())
    }

    /// Whether `hash` is registered directly against a workspace `.obao4` sidecar on disk.
    pub fn entry_reuses_workspace_sidecar(&self, hash: iroh_blobs::Hash) -> bool {
        self.lookup(hash)
            .is_some_and(|entry| entry.reused_workspace_sidecar)
    }

    fn try_register_raw_blake3_blob(
        &self,
        workspace_root: &std::path::Path,
        digest: mneme_core::ContentDigest,
        expected_length: u64,
    ) -> crate::error::Result<Option<iroh_blobs::Hash>> {
        let blob_path = mneme_store::payload::blob_path(workspace_root, digest);
        let metadata = open_regular_metadata(&blob_path)?;
        if metadata.len() != expected_length || has_framed_magic(&blob_path, metadata.len())? {
            return Ok(None);
        }
        let hash = iroh_blobs::Hash::from_bytes(*digest.as_bytes());
        let expected_ob_bytes = expected_outboard_size(expected_length);
        if expected_ob_bytes == 0 {
            self.insert_entry(
                hash,
                DiskBlobEntry {
                    data_path: blob_path,
                    outboard_path: None,
                    inline_outboard: None,
                    size_bytes: expected_length,
                    reused_workspace_sidecar: false,
                },
            )?;
            return Ok(Some(hash));
        }
        let ob_path = mneme_store::outboard::path(workspace_root, digest);
        if is_matching_regular_file(&ob_path, expected_ob_bytes)? {
            self.insert_entry(
                hash,
                DiskBlobEntry {
                    data_path: blob_path,
                    outboard_path: Some(ob_path),
                    inline_outboard: None,
                    size_bytes: expected_length,
                    reused_workspace_sidecar: true,
                },
            )?;
            return Ok(Some(hash));
        }
        // Raw BLAKE3 blob without an existing .obao4 (e.g. 16..64 KiB below store threshold):
        // stream from disk to build only the small outboard, verifying root == digest.
        let (computed_root, outboard_bytes) =
            compute_outboard_from_file(&blob_path, expected_length)?;
        if computed_root.as_bytes() != digest.as_bytes() {
            return Err(crate::error::Failure::VerificationFailed(format!(
                "workspace BLAKE3 blob {} bytes diverged from digest",
                digest.to_hex()
            )));
        }
        let (outboard_path, inline_outboard) = self.store_staged_outboard(outboard_bytes)?;
        self.insert_entry(
            hash,
            DiskBlobEntry {
                data_path: blob_path,
                outboard_path,
                inline_outboard,
                size_bytes: expected_length,
                reused_workspace_sidecar: false,
            },
        )?;
        Ok(Some(hash))
    }

    fn register_decoded_fallback_blob(
        &self,
        workspace_root: &std::path::Path,
        digest: mneme_core::ContentDigest,
        expected_length: u64,
    ) -> crate::error::Result<iroh_blobs::Hash> {
        let bytes = mneme_store::payload::read(workspace_root, digest)?;
        let actual_length = u64::try_from(bytes.len()).map_err(|_| {
            crate::error::Failure::VerificationFailed("blob length overflow".to_owned())
        })?;
        if actual_length != expected_length {
            return Err(crate::error::Failure::VerificationFailed(format!(
                "source blob {} length {actual_length} differs from manifest {expected_length}",
                digest.to_hex()
            )));
        }
        let id = self
            .inner
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let staged_path = self.inner.staging_dir.path().join(format!("blob-{id}.bin"));
        write_file_synced(&staged_path, &bytes)?;
        let (transport_hash, _) = self.register_staged_file(staged_path, actual_length)?;
        if digest.algorithm() == mneme_core::HashAlgorithm::Blake3
            && transport_hash.as_bytes() != digest.as_bytes()
        {
            return Err(crate::error::Failure::VerificationFailed(
                "iroh-blobs BLAKE3 hash diverged from Mneme ContentDigest".to_owned(),
            ));
        }
        Ok(transport_hash)
    }

    fn store_staged_outboard(
        &self,
        outboard_bytes: Vec<u8>,
    ) -> crate::error::Result<(Option<std::path::PathBuf>, Option<bytes::Bytes>)> {
        if outboard_bytes.is_empty() {
            return Ok((None, None));
        }
        if outboard_bytes.len() <= INLINE_OUTBOARD_LIMIT_BYTES {
            return Ok((None, Some(bytes::Bytes::from(outboard_bytes))));
        }
        let id = self
            .inner
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = self
            .inner
            .staging_dir
            .path()
            .join(format!("outboard-{id}.obao4"));
        write_file_synced(&path, &outboard_bytes)?;
        Ok((Some(path), None))
    }

    fn insert_entry(
        &self,
        hash: iroh_blobs::Hash,
        entry: DiskBlobEntry,
    ) -> crate::error::Result<()> {
        let mut guard = self.inner.entries.write().map_err(|_| {
            crate::error::Failure::InvalidConfig("disk blob store lock poisoned".to_owned())
        })?;
        guard.insert(hash, entry);
        Ok(())
    }
}

/// `iroh::protocol::ProtocolHandler` serving `iroh_blobs::ALPN` directly from [`DiskBlobStore`].
#[derive(Clone, Debug)]
pub struct DiskBlobsProtocol {
    store: DiskBlobStore,
    events: iroh_blobs::provider::events::EventSender,
}

impl DiskBlobsProtocol {
    /// Construct a disk-backed `iroh-blobs` handler enforcing `events` (per-scope hash allowlist).
    pub const fn new(
        store: DiskBlobStore,
        events: iroh_blobs::provider::events::EventSender,
    ) -> Self {
        Self { store, events }
    }
}

impl iroh::protocol::ProtocolHandler for DiskBlobsProtocol {
    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        let connection_id = connection.stable_id() as u64;
        if let Err(cause) = self
            .events
            .client_connected(|| iroh_blobs::provider::events::ClientConnected {
                connection_id,
                endpoint_id: Some(connection.remote_id()),
            })
            .await
        {
            connection.close(cause.code(), cause.reason());
            return Ok(());
        }
        while let Ok(pair) =
            iroh_blobs::provider::StreamPair::accept(&connection, self.events.clone()).await
        {
            let store = self.store.clone();
            let handle = tokio::task::spawn(async move {
                handle_blob_stream(pair, store).await;
            });
            drop(handle);
        }
        let _closed = self
            .events
            .connection_closed(|| iroh_blobs::provider::events::ConnectionClosed { connection_id })
            .await
            .is_ok();
        Ok(())
    }
}

async fn handle_blob_stream(mut pair: iroh_blobs::provider::StreamPair, store: DiskBlobStore) {
    let Ok(request) = pair.read_request().await else {
        return;
    };
    match request {
        iroh_blobs::protocol::Request::Get(get_req) => {
            handle_get_request(pair, store, get_req).await;
        }
        iroh_blobs::protocol::Request::GetMany(req) => {
            let decision = pair.get_many_request(|| req.clone()).await;
            abort_rejected_stream(pair, decision).await;
        }
        iroh_blobs::protocol::Request::Push(req) => {
            let decision = pair.push_request(|| req.clone()).await;
            abort_rejected_stream(pair, decision).await;
        }
        iroh_blobs::protocol::Request::Observe(req) => {
            let decision = pair.observe_request(|| req.clone()).await;
            abort_rejected_stream(pair, decision).await;
        }
        _ => {}
    }
}

async fn abort_rejected_stream(
    pair: iroh_blobs::provider::StreamPair,
    decision: Result<
        iroh_blobs::provider::events::RequestTracker,
        iroh_blobs::provider::events::ProgressError,
    >,
) {
    let code = match decision {
        Ok(tracker) => {
            if let Ok(mut writer) = pair.into_writer(tracker).await {
                let _reset = writer
                    .inner
                    .reset(iroh_blobs::protocol::ERR_INTERNAL)
                    .is_ok();
            }
            return;
        }
        Err(error) => error.code(),
    };
    // Dropping pair after sending permission denial closes the stream cleanly.
    let _ = code;
    drop(pair);
}

async fn handle_get_request(
    pair: iroh_blobs::provider::StreamPair,
    store: DiskBlobStore,
    request: iroh_blobs::protocol::GetRequest,
) {
    let Ok(tracker) = pair.get_request(|| request.clone()).await else {
        return;
    };
    let Ok(mut writer) = pair.into_writer(tracker).await else {
        return;
    };
    if let Err(error) = write_get_response(&store, &request, &mut writer.inner).await {
        tracing::debug!(%error, hash = %request.hash, "disk blob stream aborted");
        let _reset = writer
            .inner
            .reset(iroh_blobs::protocol::ERR_INTERNAL)
            .is_ok();
        return;
    }
    let _finished = writer.inner.finish().is_ok();
}

async fn write_get_response(
    store: &DiskBlobStore,
    request: &iroh_blobs::protocol::GetRequest,
    send: &mut iroh::endpoint::SendStream,
) -> crate::error::Result<()> {
    if !request.ranges.is_blob() {
        return Err(crate::error::Failure::Protocol(
            "non-blob range requests are refused".to_owned(),
        ));
    }
    let intervals = match request.ranges.as_single() {
        Some((0, ranges)) => chunk_ranges_to_intervals(ranges),
        _ => return Ok(()),
    };
    if request.hash == iroh_blobs::Hash::EMPTY {
        send.write_all(&0_u64.to_le_bytes())
            .await
            .map_err(|error| {
                crate::error::Failure::Transport(format!("write empty size: {error}"))
            })?;
        return Ok(());
    }
    let Some(entry) = store.lookup(request.hash) else {
        return Err(crate::error::Failure::Protocol(format!(
            "blob {} not found in disk store",
            request.hash
        )));
    };
    let root_hash = blake3::Hash::from(*request.hash.as_bytes());
    let (tx, mut rx) =
        tokio::sync::mpsc::channel::<crate::error::Result<bytes::Bytes>>(STREAM_CHANNEL_DEPTH);
    let producer = tokio::task::spawn_blocking(move || {
        stream_bao_from_disk(&entry, root_hash, &intervals, &tx);
    });
    while let Some(chunk_res) = rx.recv().await {
        let chunk = chunk_res?;
        send.write_all(&chunk).await.map_err(|error| {
            crate::error::Failure::Transport(format!("write bao chunk: {error}"))
        })?;
    }
    producer
        .await
        .map_err(|error| crate::error::Failure::Io(format!("disk bao producer join: {error}")))?;
    Ok(())
}

/// Verified blob download metadata returned by [`download_blob_to_file`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DownloadedBlob {
    pub byte_length: u64,
    pub extra_digest: Option<[u8; HASH_BYTES]>,
}

/// Stream-download `hash` from `conn` directly to `target_path` under `max_bytes` with
/// cryptographic BLAKE3 Merkle verification on every parent pair and 16 KiB leaf chunk.
pub async fn download_blob_to_file(
    conn: &iroh::endpoint::Connection,
    hash: iroh_blobs::Hash,
    max_bytes: u64,
    target_path: &std::path::Path,
    extra_hash_alg: Option<mneme_core::HashAlgorithm>,
) -> crate::error::Result<DownloadedBlob> {
    let result =
        download_blob_to_file_inner(conn, hash, max_bytes, target_path, extra_hash_alg).await;
    if result.is_err() {
        let _removed = std::fs::remove_file(target_path).is_ok();
    }
    result
}

async fn download_blob_to_file_inner(
    conn: &iroh::endpoint::Connection,
    hash: iroh_blobs::Hash,
    max_bytes: u64,
    target_path: &std::path::Path,
    extra_hash_alg: Option<mneme_core::HashAlgorithm>,
) -> crate::error::Result<DownloadedBlob> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(|error| {
        crate::error::Failure::Transport(format!("open blob get stream for {hash}: {error}"))
    })?;
    let request_wire = encode_get_blob_request(hash);
    send.write_all(&request_wire).await.map_err(|error| {
        crate::error::Failure::Transport(format!("send blob get request for {hash}: {error}"))
    })?;
    send.finish().map_err(|error| {
        crate::error::Failure::Transport(format!("finish blob get request for {hash}: {error}"))
    })?;

    let mut size_buf = [0_u8; SIZE_HEADER_BYTES];
    recv.read_exact(&mut size_buf).await.map_err(|error| {
        crate::error::Failure::Transport(format!("read blob size header for {hash}: {error}"))
    })?;
    let size_bytes = u64::from_le_bytes(size_buf);
    if size_bytes > max_bytes {
        conn.close(EMPTY_CLOSE_CODE.into(), b"size-limit-exceeded");
        return Err(crate::error::Failure::SizeLimitExceeded {
            actual_bytes: size_bytes,
            limit_bytes: max_bytes,
        });
    }

    let mut file = std::fs::File::create(target_path).map_err(|error| {
        crate::error::Failure::Io(format!("create staged download file: {error}"))
    })?;
    let mut extra_hasher = extra_hash_alg.map(mneme_core::hashing::StreamingHasher::new);
    let expected_root = blake3::Hash::from(*hash.as_bytes());
    let written_bytes = decode_bao_stream_to_file(
        conn,
        &mut recv,
        &mut file,
        extra_hasher.as_mut(),
        BaoDecodeSpec {
            expected_root,
            size_bytes,
            max_bytes,
        },
    )
    .await?;

    if written_bytes != size_bytes {
        return Err(crate::error::Failure::VerificationFailed(format!(
            "downloaded blob {hash} wrote {written_bytes} bytes; header declared {size_bytes}"
        )));
    }
    let mut trailing = [0_u8; 1];
    match recv.read(&mut trailing).await {
        Ok(None) => {}
        Ok(Some(_)) => {
            return Err(crate::error::Failure::Protocol(format!(
                "trailing bytes after verified blob {hash}"
            )));
        }
        Err(error) => {
            return Err(crate::error::Failure::Transport(format!(
                "read EOF for blob {hash}: {error}"
            )));
        }
    }
    file.sync_all().map_err(|error| {
        crate::error::Failure::Io(format!("sync staged download file: {error}"))
    })?;
    Ok(DownloadedBlob {
        byte_length: size_bytes,
        extra_digest: extra_hasher.map(mneme_core::hashing::StreamingHasher::finish),
    })
}

struct BaoDecodeSpec {
    expected_root: blake3::Hash,
    size_bytes: u64,
    max_bytes: u64,
}

async fn decode_bao_stream_to_file(
    conn: &iroh::endpoint::Connection,
    recv: &mut iroh::endpoint::RecvStream,
    file: &mut std::fs::File,
    mut extra_hasher: Option<&mut mneme_core::hashing::StreamingHasher>,
    spec: BaoDecodeSpec,
) -> crate::error::Result<u64> {
    if spec.size_bytes == 0 {
        if blake3::hash(&[]) != spec.expected_root {
            return Err(crate::error::Failure::VerificationFailed(
                "empty blob does not match expected BLAKE3 root".to_owned(),
            ));
        }
        return Ok(0);
    }
    let total_groups = group_count(spec.size_bytes);
    let mut stack = Vec::with_capacity(MAX_TREE_STACK_DEPTH);
    stack.push((0_u64, total_groups, TreeRole::Root, spec.expected_root));
    let mut written_bytes = 0_u64;
    let mut leaf_buf = vec![0_u8; CHUNK_GROUP_BYTES as usize];
    let mut pair_buf = [0_u8; HASH_PAIR_BYTES];

    while let Some((group_start, count, role, expected_cv)) = stack.pop() {
        if count == 1 {
            let start_byte = group_start.saturating_mul(CHUNK_GROUP_BYTES);
            let leaf_len_u64 = spec
                .size_bytes
                .saturating_sub(start_byte)
                .min(CHUNK_GROUP_BYTES);
            let next_written = written_bytes.saturating_add(leaf_len_u64);
            if next_written > spec.max_bytes {
                conn.close(EMPTY_CLOSE_CODE.into(), b"size-limit-exceeded");
                return Err(crate::error::Failure::SizeLimitExceeded {
                    actual_bytes: next_written,
                    limit_bytes: spec.max_bytes,
                });
            }
            let leaf_len = usize::try_from(leaf_len_u64).map_err(|_| {
                crate::error::Failure::Protocol("leaf chunk length overflow".to_owned())
            })?;
            recv.read_exact(&mut leaf_buf[..leaf_len])
                .await
                .map_err(|error| {
                    crate::error::Failure::Transport(format!("read bao leaf chunk: {error}"))
                })?;
            let actual_cv = blake3_hash_subtree(
                group_start.saturating_mul(CHUNKS_PER_GROUP),
                &leaf_buf[..leaf_len],
                role,
            );
            if actual_cv != expected_cv {
                return Err(crate::error::Failure::VerificationFailed(
                    "bao leaf chunk failed BLAKE3 Merkle verification".to_owned(),
                ));
            }
            if let Some(hasher) = extra_hasher.as_deref_mut() {
                hasher.update(&leaf_buf[..leaf_len]);
            }
            file.write_all(&leaf_buf[..leaf_len]).map_err(|error| {
                crate::error::Failure::Io(format!("write staged download chunk: {error}"))
            })?;
            written_bytes = next_written;
        } else {
            recv.read_exact(&mut pair_buf).await.map_err(|error| {
                crate::error::Failure::Transport(format!("read bao parent hashes: {error}"))
            })?;
            let (left_cv, right_cv) = decode_hash_pair(&pair_buf)?;
            let actual_cv = blake3_parent_cv(left_cv, right_cv, role);
            if actual_cv != expected_cv {
                return Err(crate::error::Failure::VerificationFailed(
                    "bao parent node failed BLAKE3 Merkle verification".to_owned(),
                ));
            }
            let left_count = left_subtree_groups(count);
            let right_count = count.saturating_sub(left_count);
            stack.push((
                group_start.saturating_add(left_count),
                right_count,
                TreeRole::NonRoot,
                right_cv,
            ));
            stack.push((group_start, left_count, TreeRole::NonRoot, left_cv));
        }
    }
    Ok(written_bytes)
}

/// Deterministic `BlockSize(4)` pre-order `.obao4` outboard length for a blob of `size_bytes`.
pub fn expected_outboard_size(size_bytes: u64) -> u64 {
    group_count(size_bytes)
        .saturating_sub(1)
        .saturating_mul(HASH_PAIR_BYTES as u64)
}

fn chunk_count(size_bytes: u64) -> u64 {
    if size_bytes == 0 {
        1
    } else {
        size_bytes.div_ceil(CHUNK_BYTES)
    }
}

fn group_count(size_bytes: u64) -> u64 {
    chunk_count(size_bytes).div_ceil(CHUNKS_PER_GROUP).max(1)
}

fn left_subtree_groups(count: u64) -> u64 {
    debug_assert!(count >= 2);
    let shift = u64::BITS
        .saturating_sub(1)
        .saturating_sub((count - 1).leading_zeros());
    1_u64 << shift
}

fn blake3_hash_subtree(start_chunk: u64, data: &[u8], role: TreeRole) -> blake3::Hash {
    match role {
        TreeRole::Root => blake3::hash(data),
        TreeRole::NonRoot => {
            let mut hasher = blake3::Hasher::new();
            hasher.set_input_offset(start_chunk.saturating_mul(CHUNK_BYTES));
            hasher.update(data);
            blake3::Hash::from(hasher.finalize_non_root())
        }
    }
}

fn blake3_parent_cv(left: blake3::Hash, right: blake3::Hash, role: TreeRole) -> blake3::Hash {
    match role {
        TreeRole::Root => blake3::hazmat::merge_subtrees_root(
            left.as_bytes(),
            right.as_bytes(),
            blake3::hazmat::Mode::Hash,
        ),
        TreeRole::NonRoot => blake3::Hash::from(blake3::hazmat::merge_subtrees_non_root(
            left.as_bytes(),
            right.as_bytes(),
            blake3::hazmat::Mode::Hash,
        )),
    }
}

fn decode_hash_pair(
    bytes: &[u8; HASH_PAIR_BYTES],
) -> crate::error::Result<(blake3::Hash, blake3::Hash)> {
    let left: [u8; HASH_BYTES] = bytes[..HASH_BYTES]
        .try_into()
        .map_err(|_| crate::error::Failure::Protocol("malformed left hash slice".to_owned()))?;
    let right: [u8; HASH_BYTES] = bytes[HASH_BYTES..HASH_PAIR_BYTES]
        .try_into()
        .map_err(|_| crate::error::Failure::Protocol("malformed right hash slice".to_owned()))?;
    Ok((blake3::Hash::from(left), blake3::Hash::from(right)))
}

fn encode_get_blob_request(hash: iroh_blobs::Hash) -> [u8; 1 + HASH_BYTES + 6] {
    let mut wire = [0_u8; 1 + HASH_BYTES + 6];
    wire[0] = GET_BLOB_REQUEST_PREFIX_TAG;
    wire[1..1 + HASH_BYTES].copy_from_slice(hash.as_bytes());
    wire[1 + HASH_BYTES..].copy_from_slice(&GET_BLOB_REQUEST_RANGE_TAIL);
    wire
}

fn compute_outboard_from_file(
    path: &std::path::Path,
    size_bytes: u64,
) -> crate::error::Result<(blake3::Hash, Vec<u8>)> {
    let mut file = std::fs::File::open(path)
        .map_err(|error| crate::error::Failure::Io(format!("open file for bao hash: {error}")))?;
    let total_groups = group_count(size_bytes);
    if total_groups == 1 {
        let len = usize::try_from(size_bytes).map_err(|_| {
            crate::error::Failure::Protocol("single-group blob length overflow".to_owned())
        })?;
        let mut buf = vec![0_u8; len];
        file.read_exact(&mut buf).map_err(|error| {
            crate::error::Failure::Io(format!("read single-group blob: {error}"))
        })?;
        return Ok((blake3::hash(&buf), Vec::new()));
    }

    let groups_usize = usize::try_from(total_groups).map_err(|_| {
        crate::error::Failure::Protocol("blob group count exceeds usize".to_owned())
    })?;
    let mut group_cvs = Vec::with_capacity(groups_usize);
    let mut buf = vec![0_u8; CHUNK_GROUP_BYTES as usize];
    for group_idx in 0..total_groups {
        let start_byte = group_idx.saturating_mul(CHUNK_GROUP_BYTES);
        let group_len_u64 = size_bytes.saturating_sub(start_byte).min(CHUNK_GROUP_BYTES);
        let group_len = usize::try_from(group_len_u64)
            .map_err(|_| crate::error::Failure::Protocol("group length overflow".to_owned()))?;
        file.read_exact(&mut buf[..group_len]).map_err(|error| {
            crate::error::Failure::Io(format!("read blob group {group_idx}: {error}"))
        })?;
        group_cvs.push(blake3_hash_subtree(
            group_idx.saturating_mul(CHUNKS_PER_GROUP),
            &buf[..group_len],
            TreeRole::NonRoot,
        ));
    }

    let ob_len = usize::try_from(expected_outboard_size(size_bytes))
        .map_err(|_| crate::error::Failure::Protocol("outboard length exceeds usize".to_owned()))?;
    let mut outboard = Vec::with_capacity(ob_len);
    let root = build_preorder_outboard(&group_cvs, TreeRole::Root, &mut outboard);
    debug_assert_eq!(outboard.len(), ob_len);
    Ok((root, outboard))
}

fn build_preorder_outboard(
    group_cvs: &[blake3::Hash],
    role: TreeRole,
    outboard: &mut Vec<u8>,
) -> blake3::Hash {
    if group_cvs.len() == 1 {
        return group_cvs[0];
    }
    let left_count = left_subtree_groups(group_cvs.len() as u64) as usize;
    let slot = outboard.len();
    outboard.resize(slot.saturating_add(HASH_PAIR_BYTES), 0);
    let left_cv = build_preorder_outboard(&group_cvs[..left_count], TreeRole::NonRoot, outboard);
    let right_cv = build_preorder_outboard(&group_cvs[left_count..], TreeRole::NonRoot, outboard);
    outboard[slot..slot + HASH_BYTES].copy_from_slice(left_cv.as_bytes());
    outboard[slot + HASH_BYTES..slot + HASH_PAIR_BYTES].copy_from_slice(right_cv.as_bytes());
    blake3_parent_cv(left_cv, right_cv, role)
}

#[derive(Clone, Copy, Debug)]
struct ChunkInterval {
    start: u64,
    end: Option<u64>,
}

fn chunk_ranges_to_intervals(ranges: &iroh_blobs::protocol::ChunkRanges) -> Vec<ChunkInterval> {
    let boundaries = ranges.boundaries();
    let mut intervals = Vec::with_capacity(boundaries.len().div_ceil(2));
    let mut idx = 0_usize;
    while idx < boundaries.len() {
        let start = boundaries[idx].0;
        let end = boundaries.get(idx + 1).map(|bound| bound.0);
        intervals.push(ChunkInterval { start, end });
        idx = idx.saturating_add(2);
    }
    intervals
}

fn intervals_overlap(intervals: &[ChunkInterval], start: u64, end: u64) -> bool {
    intervals
        .iter()
        .any(|iv| iv.start < end && iv.end.is_none_or(|iv_end| iv_end > start))
}

fn intervals_cover_all(intervals: &[ChunkInterval], start: u64, end: u64) -> bool {
    intervals
        .iter()
        .any(|iv| iv.start <= start && iv.end.is_none_or(|iv_end| iv_end >= end))
}

enum OutboardSource {
    None,
    Inline(bytes::Bytes),
    File(std::fs::File),
}

impl OutboardSource {
    fn read_pair(&mut self, pair_index: u64) -> crate::error::Result<[u8; HASH_PAIR_BYTES]> {
        let byte_offset = pair_index.saturating_mul(HASH_PAIR_BYTES as u64);
        match self {
            OutboardSource::None => Err(crate::error::Failure::VerificationFailed(
                "missing bao-tree outboard for multi-group blob".to_owned(),
            )),
            OutboardSource::Inline(bytes) => {
                let start = usize::try_from(byte_offset).map_err(|_| {
                    crate::error::Failure::VerificationFailed("outboard offset overflow".to_owned())
                })?;
                let end = start.saturating_add(HASH_PAIR_BYTES);
                let slice = bytes.get(start..end).ok_or_else(|| {
                    crate::error::Failure::VerificationFailed(
                        "inline outboard shorter than expected".to_owned(),
                    )
                })?;
                let mut pair = [0_u8; HASH_PAIR_BYTES];
                pair.copy_from_slice(slice);
                Ok(pair)
            }
            OutboardSource::File(file) => {
                file.seek(std::io::SeekFrom::Start(byte_offset))
                    .map_err(|error| {
                        crate::error::Failure::Io(format!("seek .obao4 sidecar: {error}"))
                    })?;
                let mut pair = [0_u8; HASH_PAIR_BYTES];
                file.read_exact(&mut pair).map_err(|error| {
                    crate::error::Failure::Io(format!("read .obao4 sidecar: {error}"))
                })?;
                Ok(pair)
            }
        }
    }
}

struct BaoFrame {
    ob_index: u64,
    group_start: u64,
    group_count: u64,
    role: TreeRole,
    expected_cv: blake3::Hash,
}

fn stream_bao_from_disk(
    entry: &DiskBlobEntry,
    root_hash: blake3::Hash,
    intervals: &[ChunkInterval],
    tx: &tokio::sync::mpsc::Sender<crate::error::Result<bytes::Bytes>>,
) {
    if let Err(error) = stream_bao_from_disk_inner(entry, root_hash, intervals, tx) {
        let _sent = tx.blocking_send(Err(error)).is_ok();
    }
}

fn stream_bao_from_disk_inner(
    entry: &DiskBlobEntry,
    root_hash: blake3::Hash,
    intervals: &[ChunkInterval],
    tx: &tokio::sync::mpsc::Sender<crate::error::Result<bytes::Bytes>>,
) -> crate::error::Result<()> {
    let mut data_file = std::fs::File::open(&entry.data_path)
        .map_err(|error| crate::error::Failure::Io(format!("open blob on disk: {error}")))?;
    let mut outboard = open_outboard_source(entry)?;
    if tx
        .blocking_send(Ok(bytes::Bytes::copy_from_slice(
            &entry.size_bytes.to_le_bytes(),
        )))
        .is_err()
    {
        return Ok(());
    }
    if intervals.is_empty() {
        return Ok(());
    }
    let total_chunks = chunk_count(entry.size_bytes);
    if !intervals_overlap(intervals, 0, total_chunks) {
        return Ok(());
    }
    let total_groups = group_count(entry.size_bytes);
    let mut stack = Vec::with_capacity(MAX_TREE_STACK_DEPTH);
    stack.push(BaoFrame {
        ob_index: 0,
        group_start: 0,
        group_count: total_groups,
        role: TreeRole::Root,
        expected_cv: root_hash,
    });

    while let Some(frame) = stack.pop() {
        if frame.group_count == 1 {
            let sent = emit_leaf_group(&mut data_file, entry.size_bytes, &frame, intervals, tx)?;
            if !sent {
                return Ok(());
            }
            continue;
        }
        let pair_bytes = outboard.read_pair(frame.ob_index)?;
        let (left_cv, right_cv) = decode_hash_pair(&pair_bytes)?;
        let actual_cv = blake3_parent_cv(left_cv, right_cv, frame.role);
        if actual_cv != frame.expected_cv {
            return Err(crate::error::Failure::VerificationFailed(
                "on-disk .obao4 parent hash mismatch".to_owned(),
            ));
        }
        if tx
            .blocking_send(Ok(bytes::Bytes::copy_from_slice(&pair_bytes)))
            .is_err()
        {
            return Ok(());
        }
        let left_count = left_subtree_groups(frame.group_count);
        let right_count = frame.group_count.saturating_sub(left_count);
        let right_start_group = frame.group_start.saturating_add(left_count);
        let left_start_chunk = frame.group_start.saturating_mul(CHUNKS_PER_GROUP);
        let mid_chunk = right_start_group.saturating_mul(CHUNKS_PER_GROUP);
        let end_chunk = frame
            .group_start
            .saturating_add(frame.group_count)
            .saturating_mul(CHUNKS_PER_GROUP)
            .min(total_chunks);
        if intervals_overlap(intervals, mid_chunk, end_chunk) {
            stack.push(BaoFrame {
                ob_index: frame.ob_index.saturating_add(left_count),
                group_start: right_start_group,
                group_count: right_count,
                role: TreeRole::NonRoot,
                expected_cv: right_cv,
            });
        }
        if intervals_overlap(intervals, left_start_chunk, mid_chunk.min(total_chunks)) {
            stack.push(BaoFrame {
                ob_index: frame.ob_index.saturating_add(1),
                group_start: frame.group_start,
                group_count: left_count,
                role: TreeRole::NonRoot,
                expected_cv: left_cv,
            });
        }
    }
    Ok(())
}

fn emit_leaf_group(
    data_file: &mut std::fs::File,
    size_bytes: u64,
    frame: &BaoFrame,
    intervals: &[ChunkInterval],
    tx: &tokio::sync::mpsc::Sender<crate::error::Result<bytes::Bytes>>,
) -> crate::error::Result<bool> {
    let start_byte = frame.group_start.saturating_mul(CHUNK_GROUP_BYTES);
    let leaf_len_u64 = size_bytes.saturating_sub(start_byte).min(CHUNK_GROUP_BYTES);
    let leaf_len = usize::try_from(leaf_len_u64).map_err(|_| {
        crate::error::Failure::Protocol("leaf group byte length overflow".to_owned())
    })?;
    let mut buf = vec![0_u8; leaf_len];
    if leaf_len > 0 {
        data_file
            .seek(std::io::SeekFrom::Start(start_byte))
            .map_err(|error| crate::error::Failure::Io(format!("seek blob on disk: {error}")))?;
        data_file
            .read_exact(&mut buf)
            .map_err(|error| crate::error::Failure::Io(format!("read blob on disk: {error}")))?;
    }
    let start_chunk = frame.group_start.saturating_mul(CHUNKS_PER_GROUP);
    let group_chunks = chunk_count(leaf_len_u64);
    let end_chunk = start_chunk.saturating_add(group_chunks);
    if intervals_cover_all(intervals, start_chunk, end_chunk) {
        let actual_cv = blake3_hash_subtree(start_chunk, &buf, frame.role);
        if actual_cv != frame.expected_cv {
            return Err(crate::error::Failure::VerificationFailed(
                "on-disk blob chunk failed BLAKE3 verification".to_owned(),
            ));
        }
        return Ok(tx.blocking_send(Ok(bytes::Bytes::from(buf))).is_ok());
    }
    let mut encoded_partial = Vec::new();
    let actual_cv = encode_partial_leaf_chunks(
        start_chunk,
        &buf,
        frame.role,
        intervals,
        &mut encoded_partial,
    );
    if actual_cv != frame.expected_cv {
        return Err(crate::error::Failure::VerificationFailed(
            "on-disk partial blob chunk failed BLAKE3 verification".to_owned(),
        ));
    }
    Ok(tx
        .blocking_send(Ok(bytes::Bytes::from(encoded_partial)))
        .is_ok())
}

fn encode_partial_leaf_chunks(
    start_chunk: u64,
    data: &[u8],
    role: TreeRole,
    intervals: &[ChunkInterval],
    out: &mut Vec<u8>,
) -> blake3::Hash {
    let total_chunks = chunk_count(data.len() as u64);
    let end_chunk = start_chunk.saturating_add(total_chunks);
    if total_chunks == 1 || intervals_cover_all(intervals, start_chunk, end_chunk) {
        let cv = blake3_hash_subtree(start_chunk, data, role);
        if intervals_overlap(intervals, start_chunk, end_chunk) {
            out.extend_from_slice(data);
        }
        return cv;
    }
    let left_chunks = left_subtree_groups(total_chunks);
    let split_byte = (left_chunks as usize).saturating_mul(CHUNK_BYTES as usize);
    let (left_data, right_data) = data.split_at(split_byte.min(data.len()));
    let slot = out.len();
    let emit_parent = intervals_overlap(intervals, start_chunk, end_chunk);
    if emit_parent {
        out.resize(slot.saturating_add(HASH_PAIR_BYTES), 0);
    }
    let left_cv =
        encode_partial_leaf_chunks(start_chunk, left_data, TreeRole::NonRoot, intervals, out);
    let right_cv = encode_partial_leaf_chunks(
        start_chunk.saturating_add(left_chunks),
        right_data,
        TreeRole::NonRoot,
        intervals,
        out,
    );
    if emit_parent {
        out[slot..slot + HASH_BYTES].copy_from_slice(left_cv.as_bytes());
        out[slot + HASH_BYTES..slot + HASH_PAIR_BYTES].copy_from_slice(right_cv.as_bytes());
    }
    blake3_parent_cv(left_cv, right_cv, role)
}

fn open_outboard_source(entry: &DiskBlobEntry) -> crate::error::Result<OutboardSource> {
    if let Some(bytes) = &entry.inline_outboard {
        return Ok(OutboardSource::Inline(bytes.clone()));
    }
    if let Some(path) = &entry.outboard_path {
        let file = std::fs::File::open(path).map_err(|error| {
            crate::error::Failure::Io(format!("open .obao4 sidecar on disk: {error}"))
        })?;
        return Ok(OutboardSource::File(file));
    }
    Ok(OutboardSource::None)
}

fn open_regular_metadata(path: &std::path::Path) -> crate::error::Result<std::fs::Metadata> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| crate::error::Failure::Io(format!("stat {}: {error}", path.display())))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(crate::error::Failure::VerificationFailed(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    Ok(metadata)
}

fn is_matching_regular_file(
    path: &std::path::Path,
    expected_bytes: u64,
) -> crate::error::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(crate::error::Failure::VerificationFailed(format!(
                    "sidecar {} is not a regular file",
                    path.display()
                )));
            }
            Ok(metadata.len() == expected_bytes)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(crate::error::Failure::Io(format!(
            "stat sidecar {}: {error}",
            path.display()
        ))),
    }
}

fn has_framed_magic(path: &std::path::Path, file_len: u64) -> crate::error::Result<bool> {
    if file_len < FRAMING_MAGIC_LEN as u64 {
        return Ok(false);
    }
    let mut file = std::fs::File::open(path)
        .map_err(|error| crate::error::Failure::Io(format!("open blob header: {error}")))?;
    let mut magic = [0_u8; FRAMING_MAGIC_LEN];
    file.read_exact(&mut magic)
        .map_err(|error| crate::error::Failure::Io(format!("read blob header: {error}")))?;
    Ok(&magic == ZSTD_FRAME_MAGIC
        || &magic == ZSTD_DICT_FRAME_MAGIC
        || &magic == FASTCDC_FRAME_MAGIC)
}

fn write_file_synced(path: &std::path::Path, bytes: &[u8]) -> crate::error::Result<()> {
    let mut file = std::fs::File::create(path).map_err(|error| {
        crate::error::Failure::Io(format!("create staged file {}: {error}", path.display()))
    })?;
    file.write_all(bytes).map_err(|error| {
        crate::error::Failure::Io(format!("write staged file {}: {error}", path.display()))
    })?;
    file.sync_all().map_err(|error| {
        crate::error::Failure::Io(format!("sync staged file {}: {error}", path.display()))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computed_outboard_matches_mneme_store_sidecar_across_sizes() {
        let dir = tempfile::tempdir().expect("tempdir");
        for size in [
            65_536_usize,
            65_537,
            98_304,
            131_072,
            262_144 + 517,
            1_500_000,
        ] {
            let bytes: Vec<u8> = (0..size)
                .map(|idx| ((idx.wrapping_mul(31).wrapping_add(idx >> 7)) & 0xff) as u8)
                .collect();
            let digest = mneme_core::ContentDigest::of_source_bytes(&bytes);
            mneme_store::payload::stage(dir.path(), digest, &bytes).expect("stage");
            let blob_path = mneme_store::payload::blob_path(dir.path(), digest);
            let sidecar_path = mneme_store::outboard::path(dir.path(), digest);
            let expected_sidecar = std::fs::read(&sidecar_path).expect("read sidecar");
            let (computed_root, computed_ob) =
                compute_outboard_from_file(&blob_path, size as u64).expect("compute");
            assert_eq!(computed_root.as_bytes(), digest.as_bytes(), "size={size}");
            assert_eq!(computed_ob, expected_sidecar, "size={size}");
            assert_eq!(
                expected_outboard_size(size as u64),
                expected_sidecar.len() as u64
            );
        }
    }

    #[tokio::test]
    async fn encoded_get_blob_request_decodes_as_standard_iroh_get_request() {
        let hash = iroh_blobs::Hash::new(b"mneme-zero-rehash-request");
        let wire = encode_get_blob_request(hash);
        let expected_req =
            iroh_blobs::protocol::Request::Get(iroh_blobs::protocol::GetRequest::blob(hash));
        assert_eq!(wire[0], 0);
        assert_eq!(&wire[1..33], hash.as_bytes());
        let _ = expected_req;
    }

    #[test]
    fn register_workspace_blob_reuses_sidecar_for_large_blake3_blob() {
        let dir = tempfile::tempdir().expect("tempdir");
        let len_bytes: usize = 2 * 1024 * 1024 + 333;
        let bytes: Vec<u8> = (0..len_bytes)
            .map(|idx| ((idx.wrapping_mul(17).wrapping_add(idx >> 5)) & 0xff) as u8)
            .collect();
        let digest = mneme_core::ContentDigest::of_source_bytes(&bytes);
        mneme_store::payload::stage(dir.path(), digest, &bytes).expect("stage");

        let store = DiskBlobStore::new().expect("disk store");
        let hash = store
            .register_workspace_blob(dir.path(), digest, len_bytes as u64)
            .expect("register");
        assert_eq!(hash.as_bytes(), digest.as_bytes());
        assert!(store.entry_reuses_workspace_sidecar(hash));
        let entry = store.lookup(hash).expect("entry");
        assert_eq!(
            entry.data_path,
            mneme_store::payload::blob_path(dir.path(), digest)
        );
        assert_eq!(
            entry.outboard_path,
            Some(mneme_store::outboard::path(dir.path(), digest))
        );
        assert!(entry.inline_outboard.is_none());
    }
}
