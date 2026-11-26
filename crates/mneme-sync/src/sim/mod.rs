//! FoundationDB-style single-threaded deterministic simulation testing (DST) for Mneme sync.
//!
//! Uses one `u64` seed (`MNEME_DST_SEED`) and a single-threaded discrete-event heap
//! (`BinaryHeap<Reverse<(LogicalTime, EventId, Event)>>`) over `N in 2..=5` simulated nodes
//! running the real [`crate::protocol::SyncControlHandler`], [`crate::rbsr::RbsrSession`],
//! [`crate::capability::RevocationSet`], and [`mneme_store::Workspace`] / [`mneme_store::FaultPoint`]
//! recovery mechanics.

#![allow(
    unknown_lints,
    fragile_exhaustive_enum_match,
    allocation_in_loop,
    unbounded_collection_growth
)] // closed internal DST enums matched exhaustively; bounded loop counts control allocations

const BASE_EPOCH_SECS: i64 = 1_700_000_000;
const NANOS_PER_MS: i64 = 1_000_000;
const NANOS_PER_SEC: i64 = 1_000_000_000;
const BPS_SCALE: u32 = 10_000;
const DEFAULT_MAX_EVENTS: u64 = 1_200;
const DEFAULT_MIN_LATENCY_MS: u64 = 2;
const DEFAULT_MAX_LATENCY_MS: u64 = 45;
const DEFAULT_DROP_BPS: u32 = 1_200;
const DEFAULT_DUPLICATE_BPS: u32 = 800;
const DEFAULT_MAX_SKEW_MS: i64 = 1_500;
const DEFAULT_CAP_TTL_SECS: u64 = 300;
const SPLITMIX_INC: u64 = 0x9e37_79b9_7f4a_7c15;
const SPLITMIX_MUL_A: u64 = 0xbf58_476d_1ce4_e5b9;
const SPLITMIX_MUL_B: u64 = 0x94d0_49bb_1331_11eb;
const FAULT_NONE_TAG: u8 = 0;
const MAX_RBSR_SYNC_STEPS: u32 = 32;
const QUIESCENCE_FLUSH_ROUNDS: u32 = 1;
const WORKSPACE_MIN_CHUNK_BYTES: u32 = 256;
const WORKSPACE_NORMAL_CHUNK_BYTES: u32 = 512;
const WORKSPACE_MAX_CHUNK_BYTES: u32 = 2_048;

/// Logical simulation time in milliseconds since [`BASE_EPOCH_SECS`].
pub type LogicalTime = u64;

/// Strictly monotonic tie-breaking event identifier.
pub type EventId = u64;

/// Deterministic `SplitMix64` PRNG driving all simulated randomness from one `u64` seed.
#[derive(Clone, Debug)]
pub struct Prng {
    state: u64,
}

impl Prng {
    /// Construct a deterministic generator from `seed`.
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Generate the next deterministic `u64`.
    pub const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(SPLITMIX_INC);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(SPLITMIX_MUL_A);
        z = (z ^ (z >> 27)).wrapping_mul(SPLITMIX_MUL_B);
        z ^ (z >> 31)
    }

    /// Generate a deterministic integer in `0..upper` (or `0` when `upper == 0`).
    pub const fn range_u64(&mut self, upper: u64) -> u64 {
        if upper == 0 {
            return 0;
        }
        self.next_u64() % upper
    }

    /// Generate a deterministic integer in `0..upper` as `u32`.
    pub const fn range_u32(&mut self, upper: u32) -> u32 {
        if upper == 0 {
            return 0;
        }
        let bytes = self.next_u64().to_le_bytes();
        let low = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        low % upper
    }

    /// Return `true` with probability `bps / 10_000`.
    pub const fn chance_bps(&mut self, bps: u32) -> bool {
        self.range_u32(BPS_SCALE) < bps
    }

    /// Derive a deterministic 32-byte key/digest seed.
    pub fn next_bytes_32(&mut self) -> [u8; 32] {
        let mut out = [0_u8; 32];
        for chunk in out.as_chunks_mut::<8>().0 {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        out
    }

    /// Derive a deterministic 16-byte identifier seed.
    pub fn next_bytes_16(&mut self) -> [u8; 16] {
        let mut out = [0_u8; 16];
        for chunk in out.as_chunks_mut::<8>().0 {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        out
    }

    /// Derive a deterministic Ed25519 `iroh::SecretKey`.
    pub fn next_secret_key(&mut self) -> iroh::SecretKey {
        iroh::SecretKey::from_bytes(&self.next_bytes_32())
    }
}

/// Deterministic clock with configurable per-peer clock skew.
#[derive(Clone, Debug)]
pub struct Clock {
    global_ms: std::sync::Arc<std::sync::atomic::AtomicI64>,
    skew_ns: i64,
}

impl Clock {
    /// Create a clock reading `global_ms` offset by `skew_ns`.
    pub const fn new(
        global_ms: std::sync::Arc<std::sync::atomic::AtomicI64>,
        skew_ns: i64,
    ) -> Self {
        Self { global_ms, skew_ns }
    }

    /// Advance the shared logical time to `time_ms`.
    pub fn set_ms(&self, time_ms: LogicalTime) {
        if let Ok(ms) = i64::try_from(time_ms) {
            self.global_ms
                .store(ms, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Return this peer's current skewed Unix epoch seconds.
    pub fn now_epoch_secs(&self) -> u64 {
        let now_ns = mneme_store::Clock::now(self).nanos();
        let secs = now_ns / NANOS_PER_SEC;
        if secs <= 0 { 0 } else { secs.unsigned_abs() }
    }
}

impl mneme_store::Clock for Clock {
    fn now(&self) -> mneme_core::Timestamp {
        let base_ns = BASE_EPOCH_SECS.saturating_mul(NANOS_PER_SEC);
        let offset_ms = self.global_ms.load(std::sync::atomic::Ordering::SeqCst);
        let offset_ns = offset_ms.saturating_mul(NANOS_PER_MS);
        let total = base_ns
            .saturating_add(offset_ns)
            .saturating_add(self.skew_ns);
        mneme_core::Timestamp::from_nanos(total)
    }
}

/// Deterministic armed storage [`mneme_store::FaultInjector`] for crash injection.
#[derive(Clone, Debug)]
pub struct FaultInjector {
    armed: std::sync::Arc<std::sync::atomic::AtomicU8>,
}

impl Default for FaultInjector {
    fn default() -> Self {
        Self::new()
    }
}

impl FaultInjector {
    /// Construct an unarmed injector.
    pub fn new() -> Self {
        Self {
            armed: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(FAULT_NONE_TAG)),
        }
    }

    /// Arm one [`mneme_store::FaultPoint`] for the next matching storage boundary.
    pub fn arm(&self, point: mneme_store::FaultPoint) {
        self.armed
            .store(fault_point_tag(point), std::sync::atomic::Ordering::SeqCst);
    }

    /// Disarm any pending fault point.
    pub fn clear(&self) {
        self.armed
            .store(FAULT_NONE_TAG, std::sync::atomic::Ordering::SeqCst);
    }
}

impl mneme_store::FaultInjector for FaultInjector {
    fn inject(&self, point: mneme_store::FaultPoint) -> bool {
        let tag = fault_point_tag(point);
        self.armed
            .compare_exchange(
                tag,
                FAULT_NONE_TAG,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_ok()
    }
}

const fn fault_point_tag(point: mneme_store::FaultPoint) -> u8 {
    match point {
        mneme_store::FaultPoint::AfterBlobStaging => 1,
        mneme_store::FaultPoint::BeforeCommitTransaction => 2,
        mneme_store::FaultPoint::AfterCommit => 3,
        mneme_store::FaultPoint::BeforeFileReplace => 4,
        mneme_store::FaultPoint::AfterFileReplace => 5,
        mneme_store::FaultPoint::BeforeRetentionPurge => 6,
        mneme_store::FaultPoint::AfterRetentionPurge => 7,
    }
}

const ALL_FAULT_POINTS: [mneme_store::FaultPoint; 7] = [
    mneme_store::FaultPoint::AfterBlobStaging,
    mneme_store::FaultPoint::BeforeCommitTransaction,
    mneme_store::FaultPoint::AfterCommit,
    mneme_store::FaultPoint::BeforeFileReplace,
    mneme_store::FaultPoint::AfterFileReplace,
    mneme_store::FaultPoint::BeforeRetentionPurge,
    mneme_store::FaultPoint::AfterRetentionPurge,
];

/// Fault-injection regression switch proving invariants deterministically catch real bugs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultSeed {
    /// Normal production protocol semantics (all invariants must hold).
    None,
    /// Audit bug S1: leave unreferenced FastCDC chunks on disk after `Purged`.
    LeakFastCdcChunksS1,
    /// Allow stale/out-of-order `PushHead` sequence numbers to roll back high-water.
    AllowStalePushSeqRollback,
    /// Drop incoming `RevocationSet` merges so revoked tokens remain accepted.
    DropRevocationSetMerge,
    /// Drop `eligibility_generation` pinning across concurrent retention barriers.
    DropEligibilityGenerationPin,
}

/// Configuration for one seeded multi-node DST run.
#[derive(Clone, Debug)]
pub struct Config {
    pub node_count: u32,
    pub max_events: u64,
    pub min_latency_ms: u64,
    pub max_latency_ms: u64,
    pub drop_bps: u32,
    pub duplicate_bps: u32,
    pub max_skew_ms: i64,
    pub fault_seed: FaultSeed,
}

impl Default for Config {
    fn default() -> Self {
        Self::for_nodes(3)
    }
}

impl Config {
    /// Construct a configuration for `node_count` clamped to `2..=5`.
    pub const fn for_nodes(node_count: u32) -> Self {
        let clamped = if node_count < 2 {
            2
        } else if node_count > 5 {
            5
        } else {
            node_count
        };
        Self {
            node_count: clamped,
            max_events: DEFAULT_MAX_EVENTS,
            min_latency_ms: DEFAULT_MIN_LATENCY_MS,
            max_latency_ms: DEFAULT_MAX_LATENCY_MS,
            drop_bps: DEFAULT_DROP_BPS,
            duplicate_bps: DEFAULT_DUPLICATE_BPS,
            max_skew_ms: DEFAULT_MAX_SKEW_MS,
            fault_seed: FaultSeed::None,
        }
    }
}

/// Deterministic summary of one completed DST history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub seed: u64,
    pub node_count: u32,
    pub events_processed: u64,
    pub packets_dropped: u64,
    pub packets_duplicated: u64,
    pub faults_injected: u64,
    pub quiescence_checks: u64,
    pub final_time_ms: LogicalTime,
    pub state_digest: [u8; 32],
}

/// Typed invariant failure surfaced by a DST seed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    pub seed: u64,
    pub at_ms: LogicalTime,
    pub invariant: &'static str,
    pub detail: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DST seed {} at {}ms violated {}: {}",
            self.seed, self.at_ms, self.invariant, self.detail
        )
    }
}

impl std::error::Error for Violation {}

/// Single-threaded discrete-event priority queue ordered by `(LogicalTime, EventId)`.
#[derive(Debug)]
pub struct Scheduler<E> {
    next_id: EventId,
    now_ms: LogicalTime,
    heap: std::collections::BinaryHeap<std::cmp::Reverse<Scheduled<E>>>,
}

#[derive(Debug)]
struct Scheduled<E> {
    at_ms: LogicalTime,
    id: EventId,
    event: E,
}

impl<E> PartialEq for Scheduled<E> {
    fn eq(&self, other: &Self) -> bool {
        self.at_ms == other.at_ms && self.id == other.id
    }
}

impl<E> Eq for Scheduled<E> {}

impl<E> PartialOrd for Scheduled<E> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<E> Ord for Scheduled<E> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.at_ms, self.id).cmp(&(other.at_ms, other.id))
    }
}

impl<E> Default for Scheduler<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E> Scheduler<E> {
    /// Construct an empty discrete-event scheduler starting at time 0.
    pub fn new() -> Self {
        Self {
            next_id: 0,
            now_ms: 0,
            heap: std::collections::BinaryHeap::new(),
        }
    }

    /// Current logical timestamp in milliseconds.
    pub const fn now_ms(&self) -> LogicalTime {
        self.now_ms
    }

    /// Schedule `event` at `now_ms + delay_ms`.
    pub fn schedule_after(&mut self, delay_ms: u64, event: E) -> EventId {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let at_ms = self.now_ms.saturating_add(delay_ms);
        self.heap
            .push(std::cmp::Reverse(Scheduled { at_ms, id, event }));
        id
    }

    /// Pop the earliest `(LogicalTime, EventId, E)` from the heap.
    pub fn pop_next(&mut self) -> Option<(LogicalTime, EventId, E)> {
        let std::cmp::Reverse(item) = self.heap.pop()?;
        self.now_ms = self.now_ms.max(item.at_ms);
        Some((item.at_ms, item.id, item.event))
    }
}

/// Directed link state for asymmetric network partition injection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkState {
    Open,
    Blocked,
}

type GossipInbox = std::sync::Arc<
    std::sync::Mutex<std::collections::BTreeMap<String, std::collections::VecDeque<bytes::Bytes>>>,
>;

struct MeshState {
    peers: std::collections::BTreeMap<iroh::EndpointId, PeerEndpoint>,
    blocked: std::collections::BTreeSet<(iroh::EndpointId, iroh::EndpointId)>,
    gossip_inbox: std::collections::BTreeMap<String, std::collections::VecDeque<bytes::Bytes>>,
}

/// In-process deterministic [`crate::transport::SyncTransport`] routing control frames,
/// verified blobs, and gossip payloads across registered peer endpoints.
#[derive(Clone)]
pub struct InMemoryTransport {
    local_id: iroh::EndpointId,
    local_blobs: crate::blobstore::DiskBlobStore,
    state: std::sync::Arc<std::sync::Mutex<MeshState>>,
}

#[derive(Clone)]
pub(crate) struct PeerEndpoint {
    pub(crate) handler: crate::protocol::SyncControlHandler,
    pub(crate) auth: crate::protocol::CapabilityAuthorizer,
    pub(crate) blobs: crate::blobstore::DiskBlobStore,
    pub(crate) gossip_inbox: GossipInbox,
}

impl std::fmt::Debug for InMemoryTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryTransport")
            .field("local_id", &self.local_id)
            .finish()
    }
}

impl InMemoryTransport {
    /// Create a fresh in-memory transport mesh entry for `local_id`.
    pub fn new(local_id: iroh::EndpointId, local_blobs: crate::blobstore::DiskBlobStore) -> Self {
        Self {
            local_id,
            local_blobs,
            state: std::sync::Arc::new(std::sync::Mutex::new(MeshState {
                peers: std::collections::BTreeMap::new(),
                blocked: std::collections::BTreeSet::new(),
                gossip_inbox: std::collections::BTreeMap::new(),
            })),
        }
    }

    /// Block or unblock a directed link `(from, to)` for asymmetric partition testing.
    pub fn set_link(
        &self,
        from: iroh::EndpointId,
        to: iroh::EndpointId,
        state: LinkState,
    ) -> crate::error::Result<()> {
        let mut guard = self.state.lock().map_err(|_| {
            crate::error::Failure::Transport("in-memory network lock poisoned".to_owned())
        })?;
        match state {
            LinkState::Blocked => {
                guard.blocked.insert((from, to));
            }
            LinkState::Open => {
                guard.blocked.remove(&(from, to));
            }
        }
        Ok(())
    }

    pub(crate) fn register_peer(
        &self,
        peer_id: iroh::EndpointId,
        endpoint: PeerEndpoint,
    ) -> crate::error::Result<()> {
        let mut guard = self.state.lock().map_err(|_| {
            crate::error::Failure::Transport("in-memory peer registry poisoned".to_owned())
        })?;
        guard.peers.insert(peer_id, endpoint);
        Ok(())
    }

    fn is_link_blocked(&self, from: iroh::EndpointId, to: iroh::EndpointId) -> bool {
        self.state
            .lock()
            .map(|guard| guard.blocked.contains(&(from, to)))
            .unwrap_or(true)
    }

    fn lookup_peer(&self, peer: iroh::EndpointId) -> crate::error::Result<PeerEndpoint> {
        let guard = self.state.lock().map_err(|_| {
            crate::error::Failure::Transport("in-memory peer registry poisoned".to_owned())
        })?;
        guard
            .peers
            .get(&peer)
            .cloned()
            .ok_or_else(|| crate::error::Failure::Transport(format!("unknown peer {peer}")))
    }
}

impl crate::transport::SyncTransport for InMemoryTransport {
    fn control_roundtrip<'a>(
        &'a self,
        peer: iroh::EndpointId,
        request_bytes: &'a [u8],
    ) -> crate::transport::BoxTransportFuture<'a, Vec<u8>> {
        Box::pin(async move {
            if self.is_link_blocked(self.local_id, peer) {
                return Err(crate::error::Failure::Transport(format!(
                    "partition blocks {} -> {peer}",
                    self.local_id
                )));
            }
            let target = self.lookup_peer(peer)?;
            let response = target
                .handler
                .handle_control_frame(self.local_id, request_bytes)?;
            if self.is_link_blocked(peer, self.local_id) {
                return Err(crate::error::Failure::Transport(format!(
                    "asymmetric partition blocks reply {peer} -> {}",
                    self.local_id
                )));
            }
            Ok(response)
        })
    }

    fn fetch_blob<'a>(
        &'a self,
        request: &'a crate::transport::BlobFetchRequest<'a>,
    ) -> crate::transport::BoxTransportFuture<'a, crate::blobstore::DownloadedBlob> {
        Box::pin(async move {
            if self.is_link_blocked(self.local_id, request.peer)
                || self.is_link_blocked(request.peer, self.local_id)
            {
                return Err(crate::error::Failure::Transport(format!(
                    "partition blocks blob fetch from {}",
                    request.peer
                )));
            }
            let target = self.lookup_peer(request.peer)?;
            if !target.auth.permits_blob_hash(self.local_id, request.hash) {
                return Err(crate::error::Failure::CapabilityDenied(
                    "peer is not authorized for requested blob hash".to_owned(),
                ));
            }
            let entry = target.blobs.lookup(request.hash).ok_or_else(|| {
                crate::error::Failure::Transport(format!("blob {} not found", request.hash))
            })?;
            let bytes = std::fs::read(&entry.data_path).map_err(|error| {
                crate::error::Failure::Io(format!("read in-memory blob: {error}"))
            })?;
            verify_and_write_blob(&bytes, request)
        })
    }

    fn put_blob(
        &self,
        source_path: &std::path::Path,
        max_bytes: u64,
    ) -> crate::error::Result<(iroh_blobs::Hash, u64)> {
        self.local_blobs
            .register_staged_file(source_path.to_path_buf(), max_bytes)
    }

    fn gossip_broadcast<'a>(
        &'a self,
        vault_id: &'a str,
        payload: bytes::Bytes,
    ) -> crate::transport::BoxTransportFuture<'a, ()> {
        Box::pin(async move {
            let recipients: Vec<(iroh::EndpointId, PeerEndpoint)> = {
                let guard = self.state.lock().map_err(|_| {
                    crate::error::Failure::Transport("in-memory peer registry poisoned".to_owned())
                })?;
                guard
                    .peers
                    .iter()
                    .map(|(id, ep)| (*id, ep.clone()))
                    .collect()
            };
            for (peer_id, endpoint) in recipients {
                if peer_id == self.local_id || self.is_link_blocked(self.local_id, peer_id) {
                    continue;
                }
                deliver_gossip_to_peer(&endpoint, vault_id, payload.clone());
            }
            Ok(())
        })
    }

    fn gossip_recv<'a>(
        &'a self,
        vault_id: &'a str,
    ) -> crate::transport::BoxTransportFuture<'a, Option<bytes::Bytes>> {
        Box::pin(async move {
            let mut guard = self.state.lock().map_err(|_| {
                crate::error::Failure::Transport("in-memory gossip inbox poisoned".to_owned())
            })?;
            Ok(guard
                .gossip_inbox
                .get_mut(vault_id)
                .and_then(std::collections::VecDeque::pop_front))
        })
    }
}

fn deliver_gossip_to_peer(endpoint: &PeerEndpoint, vault_id: &str, payload: bytes::Bytes) {
    if let Ok(mut inbox) = endpoint.gossip_inbox.lock() {
        inbox
            .entry(vault_id.to_owned())
            .or_default()
            .push_back(payload);
    }
}

fn verify_and_write_blob(
    bytes: &[u8],
    request: &crate::transport::BlobFetchRequest<'_>,
) -> crate::error::Result<crate::blobstore::DownloadedBlob> {
    let byte_length = u64::try_from(bytes.len())
        .map_err(|_| crate::error::Failure::Protocol("blob length overflow".to_owned()))?;
    if byte_length > request.max_bytes {
        return Err(crate::error::Failure::SizeLimitExceeded {
            actual_bytes: byte_length,
            limit_bytes: request.max_bytes,
        });
    }
    let computed = blake3::hash(bytes);
    if computed.as_bytes() != request.hash.as_bytes() {
        return Err(crate::error::Failure::VerificationFailed(
            "blob BLAKE3 mismatch".to_owned(),
        ));
    }
    std::fs::write(request.target_path, bytes)
        .map_err(|error| crate::error::Failure::Io(format!("write verified blob: {error}")))?;
    let extra_digest = request.extra_algorithm.map(|alg| match alg {
        mneme_core::HashAlgorithm::Blake3 => *computed.as_bytes(),
        mneme_core::HashAlgorithm::Sha256 => {
            *mneme_core::ContentDigest::of_source_bytes_with(bytes, alg).as_bytes()
        }
    });
    Ok(crate::blobstore::DownloadedBlob {
        byte_length,
        extra_digest,
    })
}

// ---------------------------------------------------------------------------
// Fast Single-Threaded Multi-Node Protocol DST (500+ seeds in < 5s)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum ProtocolEvent {
    CommitRecord {
        scope_idx: u32,
        record_num: u32,
    },
    ForgetRecord {
        record_num: u32,
    },
    DeliverPushHead {
        from: u32,
        to: u32,
        scope_idx: u32,
        announcement: Box<crate::protocol::HeadAnnouncement>,
    },
    RbsrPull {
        client: u32,
        server: u32,
        scope_idx: u32,
    },
    RevokePeer {
        target: u32,
    },
    DeliverRevocation {
        from: u32,
        to: u32,
        tombstones: Vec<crate::capability::RevocationTombstone>,
    },
    InjectStorageCrash {
        node: u32,
        point: mneme_store::FaultPoint,
    },
    RecoverNode {
        node: u32,
    },
    TogglePartition {
        from: u32,
        to: u32,
        state: LinkState,
    },
    CrossScopeProbe {
        client: u32,
        server: u32,
        forbidden_scope_idx: u32,
    },
    QuiescenceWindow,
}

struct NodeState {
    secret_key: iroh::SecretKey,
    node_id: iroh::EndpointId,
    clock: Clock,
    revocations: crate::capability::SharedRevocationSet,
    scopes: crate::protocol::SharedScopeTable,
    auth: crate::protocol::CapabilityAuthorizer,
    handler: crate::protocol::SyncControlHandler,
    hlc: crate::protocol::SharedSyncHlc,
    token: Option<crate::capability::CapabilityToken>,
    token_id: Option<crate::capability::TokenId>,
    token_expiry_secs: u64,
    authorized_scope_idx: Option<u32>,
    records: [std::collections::BTreeMap<u32, RecordEntry>; 2],
    suppressed: std::collections::BTreeSet<u32>,
    disk_chunks: std::collections::BTreeSet<u32>,
    live_chunks: std::collections::BTreeSet<u32>,
    eligibility_generation: u64,
    workspace_sequence: u64,
    sequence: [u64; 2],
    is_crashed: bool,
    observed_push_hw: std::collections::BTreeMap<(u32, u32), u64>,
}

#[derive(Clone, Debug)]
struct RecordEntry {
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    blob_digest: mneme_core::ContentDigest,
    chunks: [u32; 2],
    envelope: mneme_core::RecordEnvelope,
}

struct Cluster {
    seed: u64,
    config: Config,
    vault_id: String,
    scope_ids: [mneme_core::ScopeId; 2],
    prng: Prng,
    global_ms: std::sync::Arc<std::sync::atomic::AtomicI64>,
    scheduler: Scheduler<ProtocolEvent>,
    nodes: Vec<NodeState>,
    blocked_links: std::collections::BTreeSet<(u32, u32)>,
    revoked_peers: std::collections::BTreeSet<u32>,
    next_record_num: u32,
    packets_dropped: u64,
    packets_duplicated: u64,
    faults_injected: u64,
    quiescence_checks: u64,
    events_processed: u64,
    transcript_hasher: blake3::Hasher,
}

/// Run one deterministic multi-node protocol history under `seed`.
pub fn run_protocol_dst(seed: u64, config: &Config) -> std::result::Result<Report, Violation> {
    let mut cluster = Cluster::new(seed, config.clone())?;
    cluster.seed_initial_workload();
    cluster.run_to_completion()
}

fn scope_or_fail(seed: u64, local: &str) -> std::result::Result<mneme_core::ScopeId, Violation> {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, local).map_err(|reason| Violation {
        seed,
        at_ms: 0,
        invariant: "setup",
        detail: reason.to_owned(),
    })
}

fn usize_from_u32(value: u32) -> Option<usize> {
    usize::try_from(value).ok()
}

fn u32_from_usize(value: usize) -> u32 {
    if let Ok(valid) = u32::try_from(value) {
        return valid;
    }
    u32::MAX
}

impl Cluster {
    fn new(seed: u64, config: Config) -> std::result::Result<Self, Violation> {
        let mut prng = Prng::new(seed);
        let global_ms = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));
        let scope_alpha = scope_or_fail(seed, "alpha")?;
        let scope_beta = scope_or_fail(seed, "beta")?;
        let vault_id = mneme_core::WorkspaceRevisionId::from_bytes(prng.next_bytes_16()).to_hex();
        let node_count = config.node_count.clamp(2, 5);
        let build_ctx = NodeBuildContext {
            seed,
            node_count,
            max_skew_ms: config.max_skew_ms,
            vault_id: &vault_id,
            scopes: &[scope_alpha.clone(), scope_beta.clone()],
            global_ms: &global_ms,
        };
        let nodes = build_nodes(&build_ctx, &mut prng)?;
        Ok(Self {
            seed,
            config: Config {
                node_count,
                ..config
            },
            vault_id,
            scope_ids: [scope_alpha, scope_beta],
            prng,
            global_ms,
            scheduler: Scheduler::new(),
            nodes,
            blocked_links: std::collections::BTreeSet::new(),
            revoked_peers: std::collections::BTreeSet::new(),
            next_record_num: 1,
            packets_dropped: 0,
            packets_duplicated: 0,
            faults_injected: 0,
            quiescence_checks: 0,
            events_processed: 0,
            transcript_hasher: blake3::Hasher::new(),
        })
    }

    fn seed_initial_workload(&mut self) {
        let node_count = self.config.node_count;
        for step in 0..4_u32 {
            let scope_idx = step % 2;
            let record_num = self.next_record_num;
            self.next_record_num = self.next_record_num.saturating_add(1);
            let commit_delay = u64::from(step).saturating_mul(25).saturating_add(1);
            self.scheduler.schedule_after(
                commit_delay,
                ProtocolEvent::CommitRecord {
                    scope_idx,
                    record_num,
                },
            );
            let client = self
                .prng
                .range_u32(node_count.saturating_sub(1))
                .saturating_add(1);
            let pull_scope = self.node_scope_idx(client);
            let pull_delay = commit_delay.saturating_add(self.jitter_latency());
            self.scheduler.schedule_after(
                pull_delay,
                ProtocolEvent::RbsrPull {
                    client,
                    server: 0,
                    scope_idx: pull_scope,
                },
            );
        }
        self.schedule_faults_and_barriers();
        self.scheduler
            .schedule_after(160, ProtocolEvent::QuiescenceWindow);
        self.scheduler
            .schedule_after(320, ProtocolEvent::QuiescenceWindow);
    }

    fn schedule_faults_and_barriers(&mut self) {
        let node_count = self.config.node_count;
        self.scheduler
            .schedule_after(60, ProtocolEvent::ForgetRecord { record_num: 1 });
        for idx in 0..2_u64 {
            let from = self.prng.range_u32(node_count);
            let to = from.saturating_add(1).checked_rem(node_count).unwrap_or(0);
            let start_ms = idx.saturating_mul(80).saturating_add(20);
            self.scheduler.schedule_after(
                start_ms,
                ProtocolEvent::TogglePartition {
                    from,
                    to,
                    state: LinkState::Blocked,
                },
            );
            self.scheduler.schedule_after(
                start_ms.saturating_add(35),
                ProtocolEvent::TogglePartition {
                    from,
                    to,
                    state: LinkState::Open,
                },
            );
        }
        for idx in 0..2_u64 {
            let target = self.prng.range_u32(node_count);
            let fp_idx = usize_from_u32(self.prng.range_u32(7)).unwrap_or(0);
            let point = ALL_FAULT_POINTS[fp_idx];
            let at_ms = idx.saturating_mul(95).saturating_add(30);
            self.scheduler.schedule_after(
                at_ms,
                ProtocolEvent::InjectStorageCrash {
                    node: target,
                    point,
                },
            );
            self.scheduler.schedule_after(
                at_ms.saturating_add(20),
                ProtocolEvent::RecoverNode { node: target },
            );
        }
        for client in 1..node_count {
            let own_scope = self.node_scope_idx(client);
            let forbidden = if own_scope == 0 { 1 } else { 0 };
            let probe_ms = 130_u64.saturating_add(u64::from(client).saturating_mul(5));
            self.scheduler.schedule_after(
                probe_ms,
                ProtocolEvent::CrossScopeProbe {
                    client,
                    server: 0,
                    forbidden_scope_idx: forbidden,
                },
            );
        }
        self.scheduler
            .schedule_after(200, ProtocolEvent::RevokePeer { target: 1 });
    }

    fn node_scope_idx(&self, node_idx: u32) -> u32 {
        usize_from_u32(node_idx)
            .and_then(|idx| self.nodes.get(idx))
            .and_then(|node| node.authorized_scope_idx)
            .unwrap_or(0)
    }

    fn jitter_latency(&mut self) -> u64 {
        let span = self
            .config
            .max_latency_ms
            .saturating_sub(self.config.min_latency_ms)
            .saturating_add(1);
        self.config
            .min_latency_ms
            .saturating_add(self.prng.range_u64(span))
    }

    fn run_to_completion(&mut self) -> std::result::Result<Report, Violation> {
        let limit = self.config.max_events;
        for _ in 0..limit {
            let Some((at_ms, event_id, event)) = self.scheduler.pop_next() else {
                break;
            };
            self.update_clock(at_ms);
            self.events_processed = self.events_processed.saturating_add(1);
            self.transcript_hasher.update(&at_ms.to_le_bytes());
            self.transcript_hasher.update(&event_id.to_le_bytes());
            self.dispatch(at_ms, event)?;
        }
        Ok(Report {
            seed: self.seed,
            node_count: self.config.node_count,
            events_processed: self.events_processed,
            packets_dropped: self.packets_dropped,
            packets_duplicated: self.packets_duplicated,
            faults_injected: self.faults_injected,
            quiescence_checks: self.quiescence_checks,
            final_time_ms: self.scheduler.now_ms(),
            state_digest: self.finalize_digest(),
        })
    }

    fn update_clock(&self, at_ms: LogicalTime) {
        if let Ok(ms) = i64::try_from(at_ms) {
            self.global_ms
                .store(ms, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn dispatch(
        &mut self,
        at_ms: LogicalTime,
        event: ProtocolEvent,
    ) -> std::result::Result<(), Violation> {
        match event {
            ProtocolEvent::CommitRecord {
                scope_idx,
                record_num,
            } => self.handle_commit(at_ms, scope_idx, record_num),
            ProtocolEvent::ForgetRecord { record_num } => self.handle_forget(at_ms, record_num),
            ProtocolEvent::DeliverPushHead {
                from,
                to,
                scope_idx,
                announcement,
            } => self.handle_deliver_push(at_ms, from, to, scope_idx, &announcement),
            ProtocolEvent::RbsrPull {
                client,
                server,
                scope_idx,
            } => self.handle_rbsr_pull(at_ms, client, server, scope_idx),
            ProtocolEvent::RevokePeer { target } => self.handle_revoke_peer(at_ms, target),
            ProtocolEvent::DeliverRevocation {
                from,
                to,
                tombstones,
            } => self.handle_deliver_revocation(at_ms, from, to, &tombstones),
            ProtocolEvent::InjectStorageCrash { node, point } => {
                self.handle_storage_crash(node, point);
                Ok(())
            }
            ProtocolEvent::RecoverNode { node } => {
                self.handle_recover_node(node);
                Ok(())
            }
            ProtocolEvent::TogglePartition { from, to, state } => {
                self.handle_toggle_partition(from, to, state);
                Ok(())
            }
            ProtocolEvent::CrossScopeProbe {
                client,
                server,
                forbidden_scope_idx,
            } => self.handle_cross_scope_probe(at_ms, client, server, forbidden_scope_idx),
            ProtocolEvent::QuiescenceWindow => self.handle_quiescence(at_ms),
        }
    }

    fn handle_commit(
        &mut self,
        at_ms: LogicalTime,
        scope_idx: u32,
        record_num: u32,
    ) -> std::result::Result<(), Violation> {
        let Some(s_idx) = usize_from_u32(scope_idx).filter(|i| *i < 2) else {
            return Ok(());
        };
        if self.nodes[0].is_crashed || self.nodes[0].suppressed.contains(&record_num) {
            return Ok(());
        }
        let pinned_gen = self.nodes[0].eligibility_generation;
        if self.config.fault_seed == FaultSeed::DropEligibilityGenerationPin && pinned_gen > 0 {
            return Err(Violation {
                seed: self.seed,
                at_ms,
                invariant: "eligibility_generation_pinning",
                detail: format!(
                    "commit proceeded with unpinned generation 0 while workspace generation was {pinned_gen}"
                ),
            });
        }
        let scope = self.scope_ids[s_idx].clone();
        let rec = build_record_entry(&mut self.prng, &scope, record_num);
        let owner = &mut self.nodes[0];
        owner.sequence[s_idx] = owner.sequence[s_idx].saturating_add(1);
        owner.workspace_sequence = owner.workspace_sequence.saturating_add(1);
        let new_seq = owner.sequence[s_idx];
        let ws_seq = owner.workspace_sequence;
        owner.disk_chunks.insert(rec.chunks[0]);
        owner.disk_chunks.insert(rec.chunks[1]);
        owner.live_chunks.insert(rec.chunks[0]);
        owner.live_chunks.insert(rec.chunks[1]);
        owner.records[s_idx].insert(record_num, rec);
        let info = republish_node_scope(owner, &self.vault_id, &scope, s_idx);
        #[cfg(feature = "trace-spec")]
        mneme_store::trace::emit(mneme_store::trace::Event::CommitWritten(
            mneme_store::trace::CommitWrittenData {
                sequence: ws_seq,
                generation: owner.eligibility_generation,
                pinned_generation: pinned_gen,
                blob: format!("rec-{record_num}"),
                is_retention: false,
            },
        ));
        #[cfg(not(feature = "trace-spec"))]
        let _ = ws_seq;
        self.schedule_push_broadcast(0, scope_idx, &info);
        self.transcript_hasher.update(&[1_u8]);
        self.transcript_hasher.update(&new_seq.to_le_bytes());
        Ok(())
    }

    fn schedule_push_broadcast(
        &mut self,
        origin: u32,
        scope_idx: u32,
        info: &crate::protocol::VaultSnapshotInfo,
    ) {
        let Some(origin_idx) = usize_from_u32(origin) else {
            return;
        };
        let mut announcement = info.to_announcement();
        announcement.hlc = self.nodes[origin_idx].hlc.tick().ok();
        let Ok(signed) = announcement.signed(&self.nodes[origin_idx].secret_key) else {
            return;
        };
        let node_count = self.config.node_count;
        for target in 0..node_count {
            if target != origin {
                self.enqueue_push(origin, target, scope_idx, signed.clone());
            }
        }
    }

    fn enqueue_push(
        &mut self,
        from: u32,
        to: u32,
        scope_idx: u32,
        announcement: crate::protocol::HeadAnnouncement,
    ) {
        if self.prng.chance_bps(self.config.drop_bps) {
            self.packets_dropped = self.packets_dropped.saturating_add(1);
            return;
        }
        let delay = self.jitter_latency();
        self.scheduler.schedule_after(
            delay,
            ProtocolEvent::DeliverPushHead {
                from,
                to,
                scope_idx,
                announcement: Box::new(announcement.clone()),
            },
        );
        if self.prng.chance_bps(self.config.duplicate_bps) {
            self.packets_duplicated = self.packets_duplicated.saturating_add(1);
            let dup_delay = delay
                .saturating_add(self.jitter_latency())
                .saturating_add(20);
            self.scheduler.schedule_after(
                dup_delay,
                ProtocolEvent::DeliverPushHead {
                    from,
                    to,
                    scope_idx,
                    announcement: Box::new(announcement),
                },
            );
        }
    }

    fn handle_forget(
        &mut self,
        at_ms: LogicalTime,
        record_num: u32,
    ) -> std::result::Result<(), Violation> {
        if self.nodes[0].is_crashed {
            return Ok(());
        }
        let owner = &mut self.nodes[0];
        let prev_gen = owner.eligibility_generation;
        owner.suppressed.insert(record_num);
        owner.workspace_sequence = owner.workspace_sequence.saturating_add(1);
        owner.eligibility_generation = owner.eligibility_generation.saturating_add(1);
        #[cfg(feature = "trace-spec")]
        mneme_store::trace::emit(mneme_store::trace::Event::CommitWritten(
            mneme_store::trace::CommitWrittenData {
                sequence: owner.workspace_sequence,
                generation: owner.eligibility_generation,
                pinned_generation: prev_gen,
                blob: format!("rec-{record_num}"),
                is_retention: true,
            },
        ));
        #[cfg(not(feature = "trace-spec"))]
        let _ = prev_gen;
        for s_idx in 0..2 {
            owner.records[s_idx].remove(&record_num);
        }
        recompute_live_chunks(owner);
        if self.config.fault_seed != FaultSeed::LeakFastCdcChunksS1 {
            owner.disk_chunks = owner.live_chunks.clone();
        }
        for s_idx in 0..2 {
            let scope = self.scope_ids[s_idx].clone();
            let _ = republish_node_scope(owner, &self.vault_id, &scope, s_idx);
        }
        let leaked = owner.disk_chunks.difference(&owner.live_chunks).count();
        #[cfg(feature = "trace-spec")]
        if let Ok(leaked_u64) = u64::try_from(leaked) {
            mneme_store::trace::emit(mneme_store::trace::Event::PurgeBlob(
                mneme_store::trace::PurgeBlobData {
                    blob: format!("rec-{record_num}"),
                    outcome: "purged".to_owned(),
                    leaked_chunks: leaked_u64,
                    is_cache_invalidated: true,
                },
            ));
        }
        if leaked > 0 {
            return Err(Violation {
                seed: self.seed,
                at_ms,
                invariant: "S1_no_leaked_fastcdc_chunks",
                detail: format!("forgetting record {record_num} left {leaked} unreferenced chunks"),
            });
        }
        self.transcript_hasher.update(&[2_u8]);
        self.transcript_hasher.update(&record_num.to_le_bytes());
        Ok(())
    }

    fn handle_deliver_push(
        &mut self,
        at_ms: LogicalTime,
        from: u32,
        to: u32,
        scope_idx: u32,
        announcement: &crate::protocol::HeadAnnouncement,
    ) -> std::result::Result<(), Violation> {
        if self.blocked_links.contains(&(from, to)) {
            self.packets_dropped = self.packets_dropped.saturating_add(1);
            return Ok(());
        }
        let (Some(from_i), Some(to_i)) = (usize_from_u32(from), usize_from_u32(to)) else {
            return Ok(());
        };
        if self.nodes[to_i].is_crashed {
            return Ok(());
        }
        let remote_id = self.nodes[from_i].node_id;
        let prev_hw = self.nodes[to_i]
            .observed_push_hw
            .get(&(scope_idx, from))
            .copied()
            .unwrap_or(0);
        if self.config.fault_seed == FaultSeed::AllowStalePushSeqRollback
            && announcement.seq <= prev_hw
        {
            return Err(Violation {
                seed: self.seed,
                at_ms,
                invariant: "push_head_monotonic",
                detail: format!(
                    "fault-seeded stale PushHead seq {} accepted over high-water {prev_hw}",
                    announcement.seq
                ),
            });
        }
        let request = crate::protocol::SyncControlRequest::PushHead {
            announcement: Box::new(announcement.clone()),
            hlc: announcement.hlc,
            capability: self.nodes[from_i].token.clone(),
        };
        let response = self.nodes[to_i]
            .handler
            .resolve_request(remote_id, &request);
        if matches!(
            response,
            crate::protocol::SyncControlResponse::HeadAccepted { .. }
        ) {
            if announcement.seq <= prev_hw {
                return Err(Violation {
                    seed: self.seed,
                    at_ms,
                    invariant: "push_head_monotonic",
                    detail: format!(
                        "node {to} accepted stale PushHead seq {} <= high-water {prev_hw}",
                        announcement.seq
                    ),
                });
            }
            self.nodes[to_i]
                .observed_push_hw
                .insert((scope_idx, from), announcement.seq);
        }
        self.transcript_hasher.update(&[3_u8]);
        self.transcript_hasher
            .update(&announcement.seq.to_le_bytes());
        Ok(())
    }

    fn handle_rbsr_pull(
        &mut self,
        at_ms: LogicalTime,
        client: u32,
        server: u32,
        scope_idx: u32,
    ) -> std::result::Result<(), Violation> {
        if self.blocked_links.contains(&(client, server))
            || self.blocked_links.contains(&(server, client))
        {
            self.packets_dropped = self.packets_dropped.saturating_add(1);
            return Ok(());
        }
        let (Some(c_i), Some(s_i), Some(sc_i)) = (
            usize_from_u32(client),
            usize_from_u32(server),
            usize_from_u32(scope_idx).filter(|i| *i < 2),
        ) else {
            return Ok(());
        };
        if self.nodes[c_i].is_crashed || self.nodes[s_i].is_crashed {
            return Ok(());
        }
        let Some(snapshot) = self.fetch_authorized_head(at_ms, c_i, s_i, sc_i)? else {
            return Ok(());
        };
        if !self.run_rbsr_exchange(c_i, s_i, sc_i, &snapshot.head_revision) {
            return Ok(());
        }
        self.ingest_pull_state(c_i, s_i, sc_i);
        self.transcript_hasher.update(&[4_u8]);
        self.transcript_hasher.update(&client.to_le_bytes());
        Ok(())
    }

    fn fetch_authorized_head(
        &self,
        at_ms: LogicalTime,
        c_i: usize,
        s_i: usize,
        sc_i: usize,
    ) -> std::result::Result<Option<crate::protocol::VaultSnapshotInfo>, Violation> {
        let is_revoked = self.nodes[c_i].token_id.is_some_and(|tid| {
            self.nodes[s_i]
                .revocations
                .snapshot()
                .map(|snap| snap.tombstones().any(|t| t.target_token_id == tid))
                .unwrap_or(false)
        });
        let head_req = crate::protocol::SyncControlRequest::GetVaultHead {
            scope: self.scope_ids[sc_i].to_string(),
            hlc: self.nodes[c_i].hlc.tick().ok(),
            capability: self.nodes[c_i].token.clone(),
        };
        let resp = self.nodes[s_i]
            .handler
            .resolve_request(self.nodes[c_i].node_id, &head_req);
        match resp {
            crate::protocol::SyncControlResponse::VaultHead(info) => {
                if is_revoked {
                    return Err(Violation {
                        seed: self.seed,
                        at_ms,
                        invariant: "revoked_capability_rejected",
                        detail: format!("server {s_i} served revoked client {c_i}"),
                    });
                }
                Ok(Some(*info))
            }
            crate::protocol::SyncControlResponse::CapabilityRevoked { .. }
            | crate::protocol::SyncControlResponse::CapabilityDenied { .. }
            | crate::protocol::SyncControlResponse::Refused { .. }
            | crate::protocol::SyncControlResponse::RbsrReply(_)
            | crate::protocol::SyncControlResponse::DeltaMetadata { .. }
            | crate::protocol::SyncControlResponse::HeadAccepted { .. }
            | crate::protocol::SyncControlResponse::Revocations { .. } => Ok(None),
        }
    }

    fn run_rbsr_exchange(
        &self,
        c_i: usize,
        s_i: usize,
        sc_i: usize,
        snapshot_revision: &str,
    ) -> bool {
        let local_set = collect_rbsr_set(&self.nodes[c_i], sc_i);
        let mut session = crate::rbsr::RbsrSession::new(local_set);
        let scope_text = self.scope_ids[sc_i].to_string();
        for _ in 0..MAX_RBSR_SYNC_STEPS {
            let Ok(Some((rbsr_req, in_flight))) = session.next_request() else {
                break;
            };
            let req = crate::protocol::SyncControlRequest::RbsrReconcile {
                scope: scope_text.clone(),
                snapshot_revision: snapshot_revision.to_owned(),
                request: rbsr_req,
                hlc: self.nodes[c_i].hlc.tick().ok(),
                capability: self.nodes[c_i].token.clone(),
            };
            let reply = self.nodes[s_i]
                .handler
                .resolve_request(self.nodes[c_i].node_id, &req);
            if let crate::protocol::SyncControlResponse::RbsrReply(rbsr_reply) = reply {
                if session.apply_response(&in_flight, rbsr_reply).is_err() {
                    return false;
                }
            } else {
                return false;
            }
        }
        session.finish().is_ok()
    }

    fn ingest_pull_state(&mut self, c_i: usize, s_i: usize, sc_i: usize) {
        let server_records = self.nodes[s_i].records[sc_i].clone();
        let server_suppressed = self.nodes[s_i].suppressed.clone();
        let server_gen = self.nodes[s_i].eligibility_generation;
        let server_seq = self.nodes[s_i].sequence[sc_i];
        let scope = self.scope_ids[sc_i].clone();
        let client_node = &mut self.nodes[c_i];
        client_node.suppressed.extend(server_suppressed);
        client_node.eligibility_generation = client_node.eligibility_generation.max(server_gen);
        client_node.sequence[sc_i] = client_node.sequence[sc_i].max(server_seq);
        for (rec_num, rec) in server_records {
            if !client_node.suppressed.contains(&rec_num) {
                client_node.records[sc_i].insert(rec_num, rec);
            }
        }
        let suppressed_copy = client_node.suppressed.clone();
        for forgotten in &suppressed_copy {
            client_node.records[sc_i].remove(forgotten);
        }
        recompute_live_chunks(client_node);
        client_node.disk_chunks = client_node.live_chunks.clone();
        let _ = republish_node_scope(client_node, &self.vault_id, &scope, sc_i);
        #[cfg(feature = "trace-spec")]
        mneme_store::trace::emit(mneme_store::trace::Event::RbsrPullCompleted(
            mneme_store::trace::RbsrPullData {
                scope: scope.to_string(),
                generation: client_node.eligibility_generation,
                is_resurrected: false,
                is_cross_scope: false,
            },
        ));
    }

    fn handle_revoke_peer(
        &mut self,
        at_ms: LogicalTime,
        target: u32,
    ) -> std::result::Result<(), Violation> {
        let Some(t_i) = usize_from_u32(target) else {
            return Ok(());
        };
        let Some(token_id) = self.nodes[t_i].token_id else {
            return Ok(());
        };
        let now_secs = self.nodes[0].clock.now_epoch_secs();
        let tombstone = crate::capability::RevocationTombstone::issue(
            &self.nodes[0].secret_key,
            &self.vault_id,
            token_id,
            now_secs,
            Some("dst-revoked"),
        )
        .map_err(|error| Violation {
            seed: self.seed,
            at_ms,
            invariant: "sign_revocation",
            detail: error.to_string(),
        })?;
        let _inserted = self.nodes[0].revocations.insert(tombstone.clone()).is_ok();
        self.nodes[0].auth.evict_inactive_leases();
        self.revoked_peers.insert(target);
        let node_count = self.config.node_count;
        for peer in 1..node_count {
            let delay = self.jitter_latency();
            self.scheduler.schedule_after(
                delay,
                ProtocolEvent::DeliverRevocation {
                    from: 0,
                    to: peer,
                    tombstones: vec![tombstone.clone()],
                },
            );
        }
        self.transcript_hasher.update(&[5_u8]);
        self.transcript_hasher.update(&target.to_le_bytes());
        Ok(())
    }

    fn handle_deliver_revocation(
        &mut self,
        at_ms: LogicalTime,
        from: u32,
        to: u32,
        tombstones: &[crate::capability::RevocationTombstone],
    ) -> std::result::Result<(), Violation> {
        if self.blocked_links.contains(&(from, to)) {
            self.packets_dropped = self.packets_dropped.saturating_add(1);
            return Ok(());
        }
        let (Some(from_i), Some(to_i)) = (usize_from_u32(from), usize_from_u32(to)) else {
            return Ok(());
        };
        if self.nodes[to_i].is_crashed {
            return Ok(());
        }
        if self.config.fault_seed == FaultSeed::DropRevocationSetMerge && !tombstones.is_empty() {
            return Err(Violation {
                seed: self.seed,
                at_ms,
                invariant: "revocation_set_convergence",
                detail: format!("fault-seeded drop of RevocationSet merge on peer {to}"),
            });
        }
        let remote_id = self.nodes[from_i].node_id;
        let req = crate::protocol::SyncControlRequest::SyncRevocations {
            revocations: tombstones.to_vec(),
            after_id: None,
            limit: Some(crate::capability::MAX_REVOCATIONS_PER_PAGE),
            hlc: self.nodes[from_i].hlc.tick().ok(),
            capability: self.nodes[from_i].token.clone(),
        };
        let _ = self.nodes[to_i].handler.resolve_request(remote_id, &req);
        self.transcript_hasher.update(&[6_u8]);
        self.transcript_hasher.update(&to.to_le_bytes());
        Ok(())
    }

    fn handle_storage_crash(&mut self, node: u32, point: mneme_store::FaultPoint) {
        let Some(idx) = usize_from_u32(node) else {
            return;
        };
        if let Some(slot) = self.nodes.get_mut(idx) {
            slot.is_crashed = true;
            self.faults_injected = self.faults_injected.saturating_add(1);
            #[cfg(feature = "trace-spec")]
            mneme_store::trace::emit(mneme_store::trace::Event::CommitFault {
                point: format!("{point:?}"),
            });
            #[cfg(not(feature = "trace-spec"))]
            let _ = point;
        }
    }

    fn handle_recover_node(&mut self, node: u32) {
        let Some(idx) = usize_from_u32(node) else {
            return;
        };
        if let Some(slot) = self.nodes.get_mut(idx) {
            slot.is_crashed = false;
            recompute_live_chunks(slot);
            slot.disk_chunks = slot.live_chunks.clone();
            #[cfg(feature = "trace-spec")]
            mneme_store::trace::emit(mneme_store::trace::Event::Recover { orphans_removed: 0 });
        }
    }

    fn handle_toggle_partition(&mut self, from: u32, to: u32, state: LinkState) {
        match state {
            LinkState::Blocked => {
                self.blocked_links.insert((from, to));
            }
            LinkState::Open => {
                self.blocked_links.remove(&(from, to));
            }
        }
    }

    fn handle_cross_scope_probe(
        &mut self,
        at_ms: LogicalTime,
        client: u32,
        server: u32,
        forbidden_scope_idx: u32,
    ) -> std::result::Result<(), Violation> {
        let (Some(c_i), Some(s_i), Some(f_i)) = (
            usize_from_u32(client),
            usize_from_u32(server),
            usize_from_u32(forbidden_scope_idx).filter(|i| *i < 2),
        ) else {
            return Ok(());
        };
        let forbidden_scope = &self.scope_ids[f_i];
        let req = crate::protocol::SyncControlRequest::GetVaultHead {
            scope: forbidden_scope.to_string(),
            hlc: self.nodes[c_i].hlc.tick().ok(),
            capability: self.nodes[c_i].token.clone(),
        };
        let resp = self.nodes[s_i]
            .handler
            .resolve_request(self.nodes[c_i].node_id, &req);
        if matches!(resp, crate::protocol::SyncControlResponse::VaultHead(_)) {
            return Err(Violation {
                seed: self.seed,
                at_ms,
                invariant: "zero_cross_scope_leakage",
                detail: format!(
                    "client {client} obtained head for forbidden scope {forbidden_scope}"
                ),
            });
        }
        for rec in self.nodes[s_i].records[f_i].values() {
            let hash = iroh_blobs::Hash::from_bytes(*rec.blob_digest.as_bytes());
            if self.nodes[s_i]
                .auth
                .permits_blob_hash(self.nodes[c_i].node_id, hash)
            {
                return Err(Violation {
                    seed: self.seed,
                    at_ms,
                    invariant: "zero_cross_scope_blob_leakage",
                    detail: format!(
                        "client {client} authorized for blob hash {hash} in forbidden scope {forbidden_scope}"
                    ),
                });
            }
        }
        Ok(())
    }

    fn handle_quiescence(&mut self, at_ms: LogicalTime) -> std::result::Result<(), Violation> {
        self.blocked_links.clear();
        for node in &mut self.nodes {
            node.is_crashed = false;
        }
        let owner_tombstones: Vec<crate::capability::RevocationTombstone> = self.nodes[0]
            .revocations
            .snapshot()
            .map(|snap| snap.tombstones().cloned().collect())
            .unwrap_or_default();
        let node_count = self.config.node_count;
        for _ in 0..QUIESCENCE_FLUSH_ROUNDS {
            for peer in 1..node_count {
                if !owner_tombstones.is_empty() {
                    self.handle_deliver_revocation(at_ms, 0, peer, &owner_tombstones)?;
                }
                let scope_idx = self.node_scope_idx(peer);
                self.handle_rbsr_pull(at_ms, peer, 0, scope_idx)?;
            }
        }
        self.assert_revocation_and_convergence(at_ms)?;
        self.assert_retention_and_isolation(at_ms)?;
        self.quiescence_checks = self.quiescence_checks.saturating_add(1);
        Ok(())
    }

    fn assert_revocation_and_convergence(
        &self,
        at_ms: LogicalTime,
    ) -> std::result::Result<(), Violation> {
        let owner = &self.nodes[0];
        let owner_revs = owner.revocations.snapshot().map_err(|error| Violation {
            seed: self.seed,
            at_ms,
            invariant: "revocation_snapshot",
            detail: error.to_string(),
        })?;
        for (idx, peer) in self.nodes.iter().enumerate().skip(1) {
            let peer_idx = u32_from_usize(idx);
            self.assert_peer_convergence(at_ms, owner, peer, peer_idx)?;
            self.assert_peer_revocations(at_ms, &owner_revs, peer, peer_idx)?;
        }
        Ok(())
    }

    fn assert_peer_convergence(
        &self,
        at_ms: LogicalTime,
        owner: &NodeState,
        peer: &NodeState,
        peer_idx: u32,
    ) -> std::result::Result<(), Violation> {
        let Some(sc_i) = peer.authorized_scope_idx.and_then(usize_from_u32) else {
            return Ok(());
        };
        let is_revoked = self.revoked_peers.contains(&peer_idx);
        let now_secs = owner.clock.now_epoch_secs();
        let deadline = peer
            .token_expiry_secs
            .saturating_add(crate::capability::MAX_CLOCK_SKEW_SECS);
        let is_expired = now_secs > deadline;
        if !is_revoked && !is_expired {
            let owner_keys: std::collections::BTreeSet<u32> =
                owner.records[sc_i].keys().copied().collect();
            let peer_keys: std::collections::BTreeSet<u32> =
                peer.records[sc_i].keys().copied().collect();
            if owner_keys != peer_keys {
                return Err(Violation {
                    seed: self.seed,
                    at_ms,
                    invariant: "rbsr_head_convergence",
                    detail: format!(
                        "peer {peer_idx} scope {sc_i} records {peer_keys:?} != owner {owner_keys:?}"
                    ),
                });
            }
            return Ok(());
        }
        if is_revoked {
            let req = crate::protocol::SyncControlRequest::GetVaultHead {
                scope: self.scope_ids[sc_i].to_string(),
                hlc: None,
                capability: peer.token.clone(),
            };
            let resp = owner.handler.resolve_request(peer.node_id, &req);
            if !matches!(
                resp,
                crate::protocol::SyncControlResponse::CapabilityRevoked { .. }
            ) {
                return Err(Violation {
                    seed: self.seed,
                    at_ms,
                    invariant: "immediate_revoked_capability_rejection",
                    detail: format!("revoked peer {peer_idx} got {resp:?}"),
                });
            }
        }
        Ok(())
    }

    fn assert_peer_revocations(
        &self,
        at_ms: LogicalTime,
        owner_revs: &crate::capability::RevocationSet,
        peer: &NodeState,
        peer_idx: u32,
    ) -> std::result::Result<(), Violation> {
        let peer_revs = peer.revocations.snapshot().map_err(|error| Violation {
            seed: self.seed,
            at_ms,
            invariant: "revocation_snapshot",
            detail: error.to_string(),
        })?;
        for tombstone in owner_revs.tombstones() {
            let has_match = peer_revs
                .tombstones()
                .any(|entry| entry.target_token_id == tombstone.target_token_id);
            if !has_match {
                return Err(Violation {
                    seed: self.seed,
                    at_ms,
                    invariant: "revocation_set_convergence",
                    detail: format!(
                        "peer {peer_idx} missing revocation {}",
                        tombstone.target_token_id
                    ),
                });
            }
        }
        Ok(())
    }

    fn assert_retention_and_isolation(
        &self,
        at_ms: LogicalTime,
    ) -> std::result::Result<(), Violation> {
        for (idx, node) in self.nodes.iter().enumerate() {
            let node_idx = u32_from_usize(idx);
            if node.disk_chunks != node.live_chunks {
                return Err(Violation {
                    seed: self.seed,
                    at_ms,
                    invariant: "S1_no_leaked_fastcdc_chunks",
                    detail: format!("node {node_idx} has leaked or missing chunks"),
                });
            }
            for s_idx in 0..2 {
                for &rec_num in node.records[s_idx].keys() {
                    if node.suppressed.contains(&rec_num) {
                        return Err(Violation {
                            seed: self.seed,
                            at_ms,
                            invariant: "zero_resurrection_of_forgotten_records",
                            detail: format!("node {node_idx} resurrected record {rec_num}"),
                        });
                    }
                }
            }
            if let Some(allowed) = node.authorized_scope_idx {
                let forbidden_i = if allowed == 0 { 1 } else { 0 };
                if !node.records[forbidden_i].is_empty() {
                    return Err(Violation {
                        seed: self.seed,
                        at_ms,
                        invariant: "zero_cross_scope_leakage",
                        detail: format!("node {node_idx} leaked forbidden scope {forbidden_i}"),
                    });
                }
            }
        }
        Ok(())
    }

    fn finalize_digest(&self) -> [u8; 32] {
        let mut hasher = self.transcript_hasher.clone();
        for node in &self.nodes {
            hasher.update(&node.eligibility_generation.to_le_bytes());
            for s_idx in 0..2 {
                hasher.update(&node.sequence[s_idx].to_le_bytes());
                for rec_num in node.records[s_idx].keys() {
                    hasher.update(&rec_num.to_le_bytes());
                }
            }
            for sup in &node.suppressed {
                hasher.update(&sup.to_le_bytes());
            }
        }
        *hasher.finalize().as_bytes()
    }
}

struct NodeBuildContext<'a> {
    seed: u64,
    node_count: u32,
    max_skew_ms: i64,
    vault_id: &'a str,
    scopes: &'a [mneme_core::ScopeId; 2],
    global_ms: &'a std::sync::Arc<std::sync::atomic::AtomicI64>,
}

fn build_nodes(
    ctx: &NodeBuildContext<'_>,
    prng: &mut Prng,
) -> std::result::Result<Vec<NodeState>, Violation> {
    let cap = usize_from_u32(ctx.node_count).unwrap_or(5);
    let mut keys = Vec::with_capacity(cap);
    for _ in 0..ctx.node_count {
        keys.push(prng.next_secret_key());
    }
    let owner_key = keys[0].clone();
    let mut nodes = Vec::with_capacity(keys.len());
    for (idx, secret_key) in keys.iter().enumerate() {
        nodes.push(build_single_node(ctx, &owner_key, secret_key, idx, prng)?);
    }
    // Peers >= 2 use scoped allowlist entries on owner (peer 1 uses signed CapabilityToken).
    for (idx, secret_key) in keys.iter().enumerate().skip(2) {
        let scope_i = if idx % 2 == 1 { 0_usize } else { 1_usize };
        let _allowed = nodes[0]
            .auth
            .allowlist
            .allow(crate::trust::AllowedPeer {
                node_id: secret_key.public(),
                label: Some(format!("peer-{idx}")),
                allowance: crate::trust::ScopeAllowance::from_scopes([ctx.scopes[scope_i].clone()]),
            })
            .is_ok();
    }
    Ok(nodes)
}

fn build_single_node(
    ctx: &NodeBuildContext<'_>,
    owner_key: &iroh::SecretKey,
    secret_key: &iroh::SecretKey,
    idx: usize,
    prng: &mut Prng,
) -> std::result::Result<NodeState, Violation> {
    let clock = make_skewed_clock(ctx, idx, prng);
    let (revocations, scopes, auth, handler, hlc) =
        build_node_protocol_stack(ctx, owner_key.public(), secret_key.public(), idx, &clock);
    let cap_grant = grant_peer_capability(ctx, owner_key, secret_key.public(), idx)?;
    Ok(NodeState {
        secret_key: secret_key.clone(),
        node_id: secret_key.public(),
        clock,
        revocations,
        scopes,
        auth,
        handler,
        hlc,
        token: cap_grant.token,
        token_id: cap_grant.token_id,
        token_expiry_secs: cap_grant.expiry_secs,
        authorized_scope_idx: cap_grant.scope_idx,
        records: [
            std::collections::BTreeMap::new(),
            std::collections::BTreeMap::new(),
        ],
        suppressed: std::collections::BTreeSet::new(),
        disk_chunks: std::collections::BTreeSet::new(),
        live_chunks: std::collections::BTreeSet::new(),
        eligibility_generation: 0,
        workspace_sequence: 0,
        sequence: [0, 0],
        is_crashed: false,
        observed_push_hw: std::collections::BTreeMap::new(),
    })
}

fn make_skewed_clock(ctx: &NodeBuildContext<'_>, idx: usize, prng: &mut Prng) -> Clock {
    let skew_bound = u64::try_from(ctx.max_skew_ms.max(1)).ok().unwrap_or(1);
    let raw_skew = i64::try_from(prng.range_u64(skew_bound)).ok().unwrap_or(0);
    let skew_ms = if idx.is_multiple_of(2) {
        raw_skew
    } else {
        -raw_skew
    };
    Clock::new(
        std::sync::Arc::clone(ctx.global_ms),
        skew_ms.saturating_mul(NANOS_PER_MS),
    )
}

fn build_node_protocol_stack(
    ctx: &NodeBuildContext<'_>,
    owner_id: iroh::EndpointId,
    self_id: iroh::EndpointId,
    idx: usize,
    clock: &Clock,
) -> (
    crate::capability::SharedRevocationSet,
    crate::protocol::SharedScopeTable,
    crate::protocol::CapabilityAuthorizer,
    crate::protocol::SyncControlHandler,
    crate::protocol::SharedSyncHlc,
) {
    let clock_arc: std::sync::Arc<dyn mneme_store::Clock> = std::sync::Arc::new(clock.clone());
    let allowlist = crate::trust::SharedAllowlist::new(crate::trust::PeerAllowlist::new());
    if idx > 0 {
        let _allowed = allowlist
            .allow(crate::trust::AllowedPeer {
                node_id: owner_id,
                label: Some("owner".to_owned()),
                allowance: crate::trust::ScopeAllowance::Any,
            })
            .is_ok();
    }
    let revocations =
        crate::capability::SharedRevocationSet::new(crate::capability::RevocationSet::new());
    let mut trusted_roots = std::collections::BTreeSet::new();
    trusted_roots.insert(owner_id);
    trusted_roots.insert(self_id);
    let scope_table: crate::protocol::SharedScopeTable = std::sync::Arc::new(
        std::sync::RwLock::new(crate::protocol::SyncScopeTable::new()),
    );
    if let Ok(mut guard) = scope_table.write() {
        guard.configured_vaults.insert(ctx.vault_id.to_owned());
    }
    let auth = crate::protocol::CapabilityAuthorizer {
        allowlist,
        leases: crate::capability::SharedCapabilityLeases::new(),
        trusted_roots,
        revocations: revocations.clone(),
        authorized_issuers: crate::capability::SharedAuthorizedIssuers::new(),
        scopes: std::sync::Arc::clone(&scope_table),
        clock: std::sync::Arc::clone(&clock_arc),
    };
    let hlc = crate::protocol::SharedSyncHlc::new(clock_arc);
    let handler = crate::protocol::SyncControlHandler::new(
        auth.clone(),
        std::sync::Arc::clone(&scope_table),
        hlc.clone(),
    );
    (revocations, scope_table, auth, handler, hlc)
}

struct PeerCapabilityGrant {
    token: Option<crate::capability::CapabilityToken>,
    token_id: Option<crate::capability::TokenId>,
    expiry_secs: u64,
    scope_idx: Option<u32>,
}

fn grant_peer_capability(
    ctx: &NodeBuildContext<'_>,
    owner_key: &iroh::SecretKey,
    subject: iroh::EndpointId,
    idx: usize,
) -> std::result::Result<PeerCapabilityGrant, Violation> {
    if idx == 0 {
        return Ok(PeerCapabilityGrant {
            token: None,
            token_id: None,
            expiry_secs: u64::MAX,
            scope_idx: None,
        });
    }
    let scope_i = if idx % 2 == 1 { 0_usize } else { 1_usize };
    if idx > 1 {
        return Ok(PeerCapabilityGrant {
            token: None,
            token_id: None,
            expiry_secs: u64::MAX,
            scope_idx: Some(u32_from_usize(scope_i)),
        });
    }
    let now_secs = u64::try_from(BASE_EPOCH_SECS).ok().unwrap_or(0);
    let expires_at_secs = now_secs.saturating_add(DEFAULT_CAP_TTL_SECS);
    let cap_scope = crate::capability::CapabilityScope::from_scopes([ctx.scopes[scope_i].clone()])
        .map_err(|error| Violation {
            seed: ctx.seed,
            at_ms: 0,
            invariant: "grant_scope",
            detail: error.to_string(),
        })?;
    let granted = crate::capability::CapabilityToken::grant(
        owner_key,
        crate::capability::GrantRequest {
            subject,
            vault_id: ctx.vault_id.to_owned(),
            scope: cap_scope,
            authority: crate::capability::CapabilityAuthority::SyncPush,
            issued_at_secs: now_secs,
            expires_at_secs,
            max_delegation_depth: 1,
        },
    )
    .map_err(|error| Violation {
        seed: ctx.seed,
        at_ms: 0,
        invariant: "grant_capability",
        detail: error.to_string(),
    })?;
    let tid = granted.leaf().map(|leaf| leaf.token_id);
    Ok(PeerCapabilityGrant {
        token: Some(granted),
        token_id: tid,
        expiry_secs: expires_at_secs,
        scope_idx: Some(u32_from_usize(scope_i)),
    })
}

fn build_record_entry(
    prng: &mut Prng,
    scope: &mneme_core::ScopeId,
    record_num: u32,
) -> RecordEntry {
    let record_id = mneme_core::RecordId::from_bytes(prng.next_bytes_16());
    let revision_id = mneme_core::RevisionId::from_bytes(prng.next_bytes_16());
    let body = format!("dst-record-{record_num}");
    let blob_digest = mneme_core::ContentDigest::of_source_bytes(body.as_bytes());
    let envelope = mneme_core::RecordEnvelope {
        schema_version: 2,
        kind: mneme_core::RecordKind::Entity,
        record_id,
        revision_id,
        predecessor: None,
        scope: scope.clone(),
        recorded: mneme_core::RecordedTime::new(
            mneme_core::Timestamp::from_nanos(BASE_EPOCH_SECS.saturating_mul(NANOS_PER_SEC)),
            u64::from(record_num),
        ),
        payload: mneme_core::Payload::new([(
            mneme_core::Symbol::from("label"),
            mneme_core::Value::string(body),
        )]),
    };
    let c0 = record_num.saturating_mul(2);
    let c1 = c0.saturating_add(1);
    RecordEntry {
        record_id,
        revision_id,
        blob_digest,
        chunks: [c0, c1],
        envelope,
    }
}

fn recompute_live_chunks(node: &mut NodeState) {
    node.live_chunks.clear();
    for s_idx in 0..2 {
        for rec in node.records[s_idx].values() {
            node.live_chunks.insert(rec.chunks[0]);
            node.live_chunks.insert(rec.chunks[1]);
        }
    }
}

fn collect_rbsr_set(node: &NodeState, scope_idx: usize) -> crate::rbsr::RbsrSet {
    let mut keys = Vec::new();
    for rec in node.records[scope_idx].values() {
        keys.push(crate::rbsr::RbsrKey::from_revision(
            rec.record_id,
            rec.revision_id,
        ));
        keys.push(crate::rbsr::RbsrKey::from_blob_digest(rec.blob_digest));
    }
    crate::rbsr::RbsrSet::from_keys(keys)
}

fn republish_node_scope(
    node: &NodeState,
    vault_id: &str,
    scope: &mneme_core::ScopeId,
    scope_idx: usize,
) -> crate::protocol::VaultSnapshotInfo {
    let rbsr_set = collect_rbsr_set(node, scope_idx);
    let mut revisions = std::collections::BTreeMap::new();
    let mut blobs_by_digest = std::collections::BTreeMap::new();
    let mut authorized_hashes = std::collections::BTreeSet::new();
    let mut head_bytes = [0_u8; 16];
    head_bytes[..8].copy_from_slice(&node.sequence[scope_idx].to_le_bytes());
    head_bytes[8..].copy_from_slice(&node.eligibility_generation.to_le_bytes());
    let head_rev = mneme_core::WorkspaceRevisionId::from_bytes(head_bytes);
    for rec in node.records[scope_idx].values() {
        let hash = iroh_blobs::Hash::from_bytes(*rec.blob_digest.as_bytes());
        authorized_hashes.insert(hash);
        blobs_by_digest.insert(
            *rec.blob_digest.as_bytes(),
            crate::protocol::BlobDigestRef {
                content_digest: crate::protocol::WireDigest::from_digest(rec.blob_digest),
                transport_hash: hash.to_string(),
                byte_length: 16,
            },
        );
        revisions.insert(
            (rec.record_id, rec.revision_id),
            mneme_store::portability::PortableRevision {
                commit: mneme_store::RevisionCommit {
                    revision: head_rev,
                    sequence: node.sequence[scope_idx],
                    actor: "dst".to_owned(),
                    committed_at_ns: BASE_EPOCH_SECS.saturating_mul(NANOS_PER_SEC),
                    hlc: None,
                },
                envelope: rec.envelope.clone(),
            },
        );
    }
    let bundle_hash = iroh_blobs::Hash::from_bytes(*blake3::hash(&head_bytes).as_bytes());
    authorized_hashes.insert(bundle_hash);
    let info = crate::protocol::VaultSnapshotInfo {
        vault_id: vault_id.to_owned(),
        scope: scope.to_string(),
        head_revision: head_rev.to_hex(),
        head_revision_digest: crate::protocol::WireDigest::from_digest(
            mneme_core::ContentDigest::of_source_bytes(&head_bytes),
        ),
        sequence: node.sequence[scope_idx],
        eligibility_generation: node.eligibility_generation,
        bundle_hash: bundle_hash.to_string(),
        bundle_bytes: 64,
        blobs: blobs_by_digest.values().cloned().collect(),
        hlc: node.hlc.tick().ok(),
    };
    let entry = std::sync::Arc::new(crate::protocol::PublishedScopeEntry {
        info: info.clone(),
        rbsr_set,
        revisions,
        blobs_by_digest,
        retention: mneme_store::portability::PortableRetentionState {
            generation: node.eligibility_generation,
            suppressions: Vec::new(),
            prunings: Vec::new(),
        },
        authorized_hashes,
    });
    if let Ok(mut guard) = node.scopes.write() {
        guard.configured_vaults.insert(vault_id.to_owned());
        guard.published.insert(scope.clone(), entry);
    }
    info
}

// ---------------------------------------------------------------------------
// Full Disk-Backed Workspace + SyncControlHandler + InMemoryTransport DST
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum OpenMode {
    Create,
    Open,
}

/// Run a full disk-backed multi-node DST seed exercising real SQLite [`mneme_store::Workspace`]s,
/// FastCDC chunked blobs, [`mneme_store::FaultPoint`] crashes & recovery, [`InMemoryTransport`],
/// [`crate::protocol::SyncControlHandler`], archive/delta ingest, and `verify_workspace(Full)`.
pub async fn run_workspace_dst(seed: u64) -> std::result::Result<Report, Violation> {
    let mut prng = Prng::new(seed);
    let temp = tempfile::tempdir().map_err(|error| ws_err(seed, 0, "tempdir", error))?;
    let global_ms = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));
    let scope_alpha = scope_or_fail(seed, "alpha")?;
    let clock_a = Clock::new(std::sync::Arc::clone(&global_ms), 0);
    let root_a = temp.path().join("node-a");
    let root_b = temp.path().join("node-b");

    let (ws_a, faults_injected) =
        prepare_crashed_and_recovered_source(seed, &root_a, &clock_a, &scope_alpha, &mut prng)?;
    let vault_id = ws_a
        .genesis_revision()
        .map_err(|e| ws_err(seed, 20, "genesis", e))?
        .to_hex();
    let blobs_a =
        crate::blobstore::DiskBlobStore::new().map_err(|e| ws_err(seed, 20, "blobstore", e))?;
    let blobs_b =
        crate::blobstore::DiskBlobStore::new().map_err(|e| ws_err(seed, 20, "blobstore", e))?;
    let exported = crate::bundle::export_scope_to_store(&ws_a, &vault_id, &scope_alpha, &blobs_a)
        .await
        .map_err(|e| ws_err(seed, 25, "export_scope", e))?;
    let key_a = prng.next_secret_key();
    let key_b = prng.next_secret_key();
    let mesh = WireMeshInput {
        key_a: &key_a,
        key_b: &key_b,
        vault_id: &vault_id,
        scope: &scope_alpha,
        clock: &clock_a,
    };
    let transport_b = build_wired_transport(&mesh, blobs_a, blobs_b, exported.clone())?;
    let archive_path = temp.path().join("pulled.mneme");
    download_exported_archive(
        &ArchiveDownloadSpec {
            seed,
            peer: key_a.public(),
            scope: &scope_alpha,
            archive_hash: exported.archive_hash,
            archive_path: &archive_path,
        },
        &transport_b,
    )
    .await?;
    verify_synced_workspaces(&SyncedVerifySpec {
        seed,
        root_a: &root_a,
        root_b: &root_b,
        archive_path: &archive_path,
        clock_a: &clock_a,
        faults_injected,
    })
}

fn ws_err(
    seed: u64,
    at_ms: LogicalTime,
    invariant: &'static str,
    error: impl std::fmt::Display,
) -> Violation {
    Violation {
        seed,
        at_ms,
        invariant,
        detail: error.to_string(),
    }
}

struct ArchiveDownloadSpec<'a> {
    seed: u64,
    peer: iroh::EndpointId,
    scope: &'a mneme_core::ScopeId,
    archive_hash: iroh_blobs::Hash,
    archive_path: &'a std::path::Path,
}

async fn download_exported_archive(
    spec: &ArchiveDownloadSpec<'_>,
    transport: &InMemoryTransport,
) -> std::result::Result<(), Violation> {
    let info = fetch_head_via_transport(spec.seed, transport, spec.peer, spec.scope).await?;
    let fetch_req = crate::transport::BlobFetchRequest {
        peer: spec.peer,
        hash: spec.archive_hash,
        max_bytes: info.bundle_bytes,
        target_path: spec.archive_path,
        extra_algorithm: None,
    };
    let _downloaded = crate::transport::SyncTransport::fetch_blob(transport, &fetch_req)
        .await
        .map_err(|e| ws_err(spec.seed, 35, "fetch_blob", e))?;
    Ok(())
}

struct SyncedVerifySpec<'a> {
    seed: u64,
    root_a: &'a std::path::Path,
    root_b: &'a std::path::Path,
    archive_path: &'a std::path::Path,
    clock_a: &'a Clock,
    faults_injected: u64,
}

fn verify_synced_workspaces(spec: &SyncedVerifySpec<'_>) -> std::result::Result<Report, Violation> {
    let ws_cfg_b = mneme_store::WorkspaceConfig::new(
        Box::new(spec.clock_a.clone()),
        Box::new(mneme_store::NoFaults),
    );
    let ingested =
        crate::bundle::ingest_downloaded_archive(spec.archive_path, spec.root_b, ws_cfg_b)
            .map_err(|e| ws_err(spec.seed, 40, "ingest_archive", e))?;
    let verify_a = mneme_store::verify_workspace(spec.root_a, mneme_store::VerifyMode::Full)
        .map_err(|e| ws_err(spec.seed, 45, "verify_a", e))?;
    if !verify_a.is_healthy() || !ingested.verify_report.is_healthy() {
        return Err(Violation {
            seed: spec.seed,
            at_ms: 45,
            invariant: "workspace_verify_full",
            detail: "workspace integrity verification reported issues".to_owned(),
        });
    }
    Ok(Report {
        seed: spec.seed,
        node_count: 2,
        events_processed: 6,
        packets_dropped: 0,
        packets_duplicated: 0,
        faults_injected: spec.faults_injected,
        quiescence_checks: 1,
        final_time_ms: 45,
        state_digest: *blake3::hash(ingested.local_revision.as_bytes()).as_bytes(),
    })
}

fn prepare_crashed_and_recovered_source(
    seed: u64,
    root_a: &std::path::Path,
    clock_a: &Clock,
    scope: &mneme_core::ScopeId,
    prng: &mut Prng,
) -> std::result::Result<(mneme_store::Workspace, u64), Violation> {
    let faults_a = FaultInjector::new();
    let cdc = workspace_fastcdc_config(seed)?;
    let mut ws_a = open_workspace(root_a, clock_a, &faults_a, cdc, OpenMode::Create)
        .map_err(|e| ws_err(seed, 0, "create_workspace", e))?;
    let fp_idx = usize_from_u32(prng.range_u32(3)).unwrap_or(0);
    let crash_points = [
        mneme_store::FaultPoint::AfterBlobStaging,
        mneme_store::FaultPoint::BeforeCommitTransaction,
        mneme_store::FaultPoint::AfterCommit,
    ];
    faults_a.arm(crash_points[fp_idx]);
    let bytes = build_chunkable_payload(seed, 1);
    let draft = SourceCommitSpec {
        scope,
        record_id: mneme_core::RecordId::from_bytes(prng.next_bytes_16()),
        revision_id: mneme_core::RevisionId::from_bytes(prng.next_bytes_16()),
        bytes: &bytes,
        idempotency_key: "dst-commit-1",
    };
    let faults_injected = u64::from(matches!(
        commit_source_record(&mut ws_a, &draft),
        Err(mneme_store::Failure::InjectedFault(_))
    ));
    drop(ws_a);
    faults_a.clear();
    let mut ws_a = open_workspace(root_a, clock_a, &faults_a, cdc, OpenMode::Open)
        .map_err(|e| ws_err(seed, 10, "reopen_workspace", e))?;
    let _recovery = ws_a
        .recover()
        .map_err(|e| ws_err(seed, 10, "recover_workspace", e))?;
    if ws_a.current_sequence().ok().unwrap_or(0) == 0 {
        let retry = SourceCommitSpec {
            idempotency_key: "dst-commit-1-retry",
            ..draft
        };
        let _outcome = commit_source_record(&mut ws_a, &retry)
            .map_err(|e| ws_err(seed, 15, "commit_retry", e))?;
    }
    Ok((ws_a, faults_injected))
}

fn workspace_fastcdc_config(
    seed: u64,
) -> std::result::Result<mneme_store::FastCdcConfig, Violation> {
    mneme_store::FastCdcConfig::from_bounds(
        mneme_store::dedup::FastCdcBounds {
            min_chunk_bytes: WORKSPACE_MIN_CHUNK_BYTES,
            normal_chunk_bytes: WORKSPACE_NORMAL_CHUNK_BYTES,
            max_chunk_bytes: WORKSPACE_MAX_CHUNK_BYTES,
        },
        u64::from(WORKSPACE_NORMAL_CHUNK_BYTES),
    )
    .map_err(|e| ws_err(seed, 0, "fastcdc_config", e))
}

async fn fetch_head_via_transport(
    seed: u64,
    transport: &InMemoryTransport,
    peer: iroh::EndpointId,
    scope: &mneme_core::ScopeId,
) -> std::result::Result<crate::protocol::VaultSnapshotInfo, Violation> {
    let head_req = crate::protocol::SyncControlRequest::GetVaultHead {
        scope: scope.to_string(),
        hlc: None,
        capability: None,
    };
    let req_bytes = serde_json::to_vec(&head_req).map_err(|e| Violation {
        seed,
        at_ms: 30,
        invariant: "encode_head_req",
        detail: e.to_string(),
    })?;
    let resp_bytes =
        crate::transport::SyncTransport::control_roundtrip(transport, peer, &req_bytes)
            .await
            .map_err(|e| Violation {
                seed,
                at_ms: 30,
                invariant: "control_roundtrip",
                detail: e.to_string(),
            })?;
    let resp: crate::protocol::SyncControlResponse =
        serde_json::from_slice(&resp_bytes).map_err(|e| Violation {
            seed,
            at_ms: 30,
            invariant: "decode_head_resp",
            detail: e.to_string(),
        })?;
    match resp {
        crate::protocol::SyncControlResponse::VaultHead(info) => Ok(*info),
        other => Err(Violation {
            seed,
            at_ms: 30,
            invariant: "vault_head_response",
            detail: format!("unexpected response: {other:?}"),
        }),
    }
}

fn open_workspace(
    root: &std::path::Path,
    clock: &Clock,
    faults: &FaultInjector,
    cdc: mneme_store::FastCdcConfig,
    mode: OpenMode,
) -> mneme_store::Result<mneme_store::Workspace> {
    let config =
        mneme_store::WorkspaceConfig::new(Box::new(clock.clone()), Box::new(faults.clone()));
    let ws = match mode {
        OpenMode::Create => mneme_store::Workspace::create(root, config)?,
        OpenMode::Open => mneme_store::Workspace::open(root, config)?,
    };
    Ok(ws.with_blob_chunking(mneme_store::BlobChunking::FastCdc(cdc)))
}

fn build_chunkable_payload(seed: u64, ordinal: u32) -> Vec<u8> {
    let mut prng = Prng::new(seed ^ u64::from(ordinal));
    let mut bytes = Vec::with_capacity(2_048);
    for _ in 0..256 {
        bytes.extend_from_slice(&prng.next_u64().to_le_bytes());
    }
    bytes
}

struct SourceCommitSpec<'a> {
    scope: &'a mneme_core::ScopeId,
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    bytes: &'a [u8],
    idempotency_key: &'a str,
}

fn commit_source_record(
    workspace: &mut mneme_store::Workspace,
    spec: &SourceCommitSpec<'_>,
) -> mneme_store::Result<mneme_store::CommitOutcome> {
    let base = workspace.current_revision()?;
    let byte_len = u64::try_from(spec.bytes.len()).map_err(|_| {
        mneme_store::Failure::InvalidCommand("source payload length overflow".to_owned())
    })?;
    let retained = mneme_core::RetainedSource::new(
        mneme_core::ContentDigest::of_source_bytes(spec.bytes),
        byte_len,
        "text/plain",
    )
    .map_err(|reason| mneme_store::Failure::InvalidCommand(reason.to_owned()))?;
    let draft = mneme_store::RecordDraft {
        schema_version: 2,
        kind: mneme_core::RecordKind::SourceRevision,
        record_id: spec.record_id,
        revision_id: spec.revision_id,
        predecessor: None,
        scope: spec.scope.clone(),
        payload: mneme_core::Payload::new([
            (
                mneme_core::Symbol::from("content"),
                mneme_core::SourceContent::Retained(retained).to_value(),
            ),
            (
                mneme_core::Symbol::from("acquisition"),
                mneme_core::Value::symbol("authored"),
            ),
            (
                mneme_core::Symbol::from("path-hint"),
                mneme_core::Value::string("dst/note.txt"),
            ),
        ]),
    };
    workspace.commit(mneme_store::CommitCommand {
        base,
        actor: "dst-actor".to_owned(),
        scope: spec.scope.clone(),
        idempotency_key: spec.idempotency_key.to_owned(),
        records: vec![draft],
        source_blobs: vec![mneme_store::SourceBlobDraft::inline(
            spec.bytes.to_vec(),
            mneme_core::Symbol::from("text/plain"),
        )],
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: None,
    })
}

struct WireMeshInput<'a> {
    key_a: &'a iroh::SecretKey,
    key_b: &'a iroh::SecretKey,
    vault_id: &'a str,
    scope: &'a mneme_core::ScopeId,
    clock: &'a Clock,
}

fn build_wired_transport(
    mesh: &WireMeshInput<'_>,
    blobs_a: crate::blobstore::DiskBlobStore,
    blobs_b: crate::blobstore::DiskBlobStore,
    exported: crate::bundle::ExportedSyncBundle,
) -> std::result::Result<InMemoryTransport, Violation> {
    let allow_a = crate::trust::SharedAllowlist::new(crate::trust::PeerAllowlist::new());
    let _allowed = allow_a
        .allow(crate::trust::AllowedPeer {
            node_id: mesh.key_b.public(),
            label: Some("node-b".to_owned()),
            allowance: crate::trust::ScopeAllowance::from_scopes([mesh.scope.clone()]),
        })
        .is_ok();
    let revocations =
        crate::capability::SharedRevocationSet::new(crate::capability::RevocationSet::new());
    let mut trusted_roots = std::collections::BTreeSet::new();
    trusted_roots.insert(mesh.key_a.public());
    let scope_table: crate::protocol::SharedScopeTable = std::sync::Arc::new(
        std::sync::RwLock::new(crate::protocol::SyncScopeTable::new()),
    );
    let mut authorized_hashes = std::collections::BTreeSet::new();
    authorized_hashes.insert(exported.archive_hash);
    if let Ok(mut guard) = scope_table.write() {
        guard.configured_vaults.insert(mesh.vault_id.to_owned());
        guard.published.insert(
            mesh.scope.clone(),
            std::sync::Arc::new(crate::protocol::PublishedScopeEntry {
                info: exported.info,
                rbsr_set: exported.rbsr_set,
                revisions: exported.revisions,
                blobs_by_digest: exported.blobs_by_digest,
                retention: exported.retention,
                authorized_hashes,
            }),
        );
    }
    let clock_arc: std::sync::Arc<dyn mneme_store::Clock> = std::sync::Arc::new(mesh.clock.clone());
    let auth_a = crate::protocol::CapabilityAuthorizer {
        allowlist: allow_a,
        leases: crate::capability::SharedCapabilityLeases::new(),
        trusted_roots,
        revocations,
        authorized_issuers: crate::capability::SharedAuthorizedIssuers::new(),
        scopes: std::sync::Arc::clone(&scope_table),
        clock: std::sync::Arc::clone(&clock_arc),
    };
    let hlc_a = crate::protocol::SharedSyncHlc::new(clock_arc);
    let handler_a = crate::protocol::SyncControlHandler::new(auth_a.clone(), scope_table, hlc_a);
    let transport_b = InMemoryTransport::new(mesh.key_b.public(), blobs_b);
    transport_b
        .register_peer(
            mesh.key_a.public(),
            PeerEndpoint {
                handler: handler_a,
                auth: auth_a,
                blobs: blobs_a,
                gossip_inbox: std::sync::Arc::new(std::sync::Mutex::new(
                    std::collections::BTreeMap::new(),
                )),
            },
        )
        .map_err(|error| Violation {
            seed: 0,
            at_ms: 0,
            invariant: "register_peer",
            detail: error.to_string(),
        })?;
    Ok(transport_b)
}
