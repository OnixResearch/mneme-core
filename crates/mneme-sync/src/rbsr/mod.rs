//! Deterministic Range-Based Set Reconciliation (RBSR, Aljoscha Meyer arXiv:2212.13567).
//!
//! Reconciles sorted sets of `(record_id, revision_id)` and `blob_digest` keys
//! using 256-bit modular-addition BLAKE3 range fingerprints, binary range
//! partitioning, bounded depth and frame sizes, and fail-closed validation.

#![allow(
    unknown_lints,
    assertion_density,
    path_segment_repetition,
    fragile_exhaustive_enum_match,
    allocation_in_loop,
    unbounded_collection_growth
)] // returns typed Result failures instead of panicking; Rbsr* matches module domain; exhaustive match on closed RBSR enums; per-round allocations bounded by MAX_RBSR_RANGES_PER_FRAME and MAX_RBSR_ROUNDS

/// Maximum serialized byte size of one RBSR request or response frame (256 KiB).
pub const MAX_RBSR_FRAME_BYTES: u64 = 256 * 1024;
/// Maximum range-partition tree depth before reconciliation fails closed.
pub const MAX_RBSR_DEPTH: u32 = 48;
/// Maximum protocol round trips permitted per reconciliation session.
pub const MAX_RBSR_ROUNDS: u32 = 1024;
/// Maximum subranges emitted by one split.
pub const MAX_RBSR_BRANCHING: u32 = 2;
/// Maximum queried ranges packed into one RBSR request frame.
pub const MAX_RBSR_RANGES_PER_FRAME: u32 = 64;
/// Maximum explicit items returned in one leaf resolution.
pub const MAX_RBSR_ITEMS_PER_LEAF: u32 = 32;
/// Local range cardinality threshold at or below which explicit items are sent.
pub const RBSR_LEAF_THRESHOLD: u32 = 8;

const MAX_BRANCHING_USIZE: usize = 2;
const MAX_RANGES_PER_FRAME_USIZE: usize = 64;
const MAX_ITEMS_PER_LEAF_USIZE: usize = 32;
const LEAF_THRESHOLD_USIZE: usize = 8;

const KEY_BYTE_LEN: usize = 33;
const DIGEST_BYTE_LEN: usize = 32;
const KIND_REVISION: u8 = 1;
const KIND_BLOB: u8 = 2;
const ELEMENT_HASH_CONTEXT: &str = "mneme.sync.rbsr.element.v1";
const RANGE_HASH_CONTEXT: &str = "mneme.sync.rbsr.range.v1";

/// Tag distinguishing record revisions from source blobs inside an [`RbsrKey`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum RbsrItemKind {
    /// A `(record_id, revision_id)` pair.
    Revision = KIND_REVISION,
    /// A 32-byte source blob `ContentDigest`.
    Blob = KIND_BLOB,
}

/// Fixed-width canonical element key in a sorted RBSR set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RbsrKey([u8; KEY_BYTE_LEN]);

impl RbsrKey {
    /// Construct a key representing `(record_id, revision_id)`.
    pub fn from_revision(
        record_id: mneme_core::RecordId,
        revision_id: mneme_core::RevisionId,
    ) -> Self {
        let rec = record_id.as_bytes();
        let rev = revision_id.as_bytes();
        Self([
            KIND_REVISION,
            rec[0],
            rec[1],
            rec[2],
            rec[3],
            rec[4],
            rec[5],
            rec[6],
            rec[7],
            rec[8],
            rec[9],
            rec[10],
            rec[11],
            rec[12],
            rec[13],
            rec[14],
            rec[15],
            rev[0],
            rev[1],
            rev[2],
            rev[3],
            rev[4],
            rev[5],
            rev[6],
            rev[7],
            rev[8],
            rev[9],
            rev[10],
            rev[11],
            rev[12],
            rev[13],
            rev[14],
            rev[15],
        ])
    }

    /// Construct a key representing a standalone `revision_id` (zeroed record prefix).
    pub fn from_revision_id(revision_id: mneme_core::RevisionId) -> Self {
        let rev = revision_id.as_bytes();
        Self([
            KIND_REVISION,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            rev[0],
            rev[1],
            rev[2],
            rev[3],
            rev[4],
            rev[5],
            rev[6],
            rev[7],
            rev[8],
            rev[9],
            rev[10],
            rev[11],
            rev[12],
            rev[13],
            rev[14],
            rev[15],
        ])
    }

    /// Construct a key representing a source blob [`mneme_core::ContentDigest`].
    pub const fn from_blob_digest(digest: mneme_core::ContentDigest) -> Self {
        Self::from_blob_bytes(*digest.as_bytes())
    }

    /// Construct a key directly from 32 raw digest bytes.
    pub const fn from_blob_bytes(bytes: [u8; DIGEST_BYTE_LEN]) -> Self {
        Self([
            KIND_BLOB, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
            bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
            bytes[15], bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22],
            bytes[23], bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30],
            bytes[31],
        ])
    }

    /// Decode and validate a 33-byte raw key slice.
    pub fn decode_bytes(bytes: &[u8]) -> crate::error::Result<Self> {
        let raw: [u8; KEY_BYTE_LEN] = bytes.try_into().map_err(|_| {
            crate::error::Failure::Protocol(format!(
                "RBSR key must be {KEY_BYTE_LEN} bytes, got {}",
                bytes.len()
            ))
        })?;
        match raw[0] {
            KIND_REVISION | KIND_BLOB => Ok(Self(raw)),
            tag => Err(crate::error::Failure::Protocol(format!(
                "invalid RBSR key tag {tag}"
            ))),
        }
    }

    /// Return the raw 33-byte representation.
    pub const fn as_bytes(&self) -> &[u8; KEY_BYTE_LEN] {
        &self.0
    }

    /// Return the item kind tag.
    pub const fn kind(self) -> RbsrItemKind {
        match self.0[0] {
            KIND_REVISION => RbsrItemKind::Revision,
            _ => RbsrItemKind::Blob,
        }
    }

    /// Extract `(record_id, revision_id)` if this key represents a revision.
    pub fn as_revision(self) -> Option<(mneme_core::RecordId, mneme_core::RevisionId)> {
        if self.0[0] != KIND_REVISION {
            return None;
        }
        let mut rec = [0_u8; 16];
        let mut rev = [0_u8; 16];
        rec.copy_from_slice(&self.0[1..17]);
        rev.copy_from_slice(&self.0[17..33]);
        Some((
            mneme_core::RecordId::from_bytes(rec),
            mneme_core::RevisionId::from_bytes(rev),
        ))
    }

    /// Extract the 32-byte digest if this key represents a blob.
    pub fn as_blob_bytes(self) -> Option<[u8; DIGEST_BYTE_LEN]> {
        if self.0[0] != KIND_BLOB {
            return None;
        }
        let mut out = [0_u8; DIGEST_BYTE_LEN];
        out.copy_from_slice(&self.0[1..33]);
        Some(out)
    }
}

impl serde::Serialize for RbsrKey {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&mneme_core::base64::encode(&self.0))
    }
}

impl<'de> serde::Deserialize<'de> for RbsrKey {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let decoded = mneme_core::base64::decode(&text).map_err(serde::de::Error::custom)?;
        Self::decode_bytes(&decoded).map_err(serde::de::Error::custom)
    }
}

/// Half-open interval boundary over the totally ordered [`RbsrKey`] space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RangeBound {
    /// Strict minimum boundary (`-∞`), less than every [`RbsrKey`].
    NegInfinity,
    /// Exact [`RbsrKey`] boundary.
    Key(RbsrKey),
    /// Strict maximum boundary (`+∞`), greater than every [`RbsrKey`].
    Infinity,
}

impl Ord for RangeBound {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (RangeBound::NegInfinity, RangeBound::NegInfinity)
            | (RangeBound::Infinity, RangeBound::Infinity) => std::cmp::Ordering::Equal,
            (RangeBound::NegInfinity, _) | (_, RangeBound::Infinity) => std::cmp::Ordering::Less,
            (RangeBound::Infinity, _) | (_, RangeBound::NegInfinity) => std::cmp::Ordering::Greater,
            (RangeBound::Key(left), RangeBound::Key(right)) => left.cmp(right),
        }
    }
}

impl PartialOrd for RangeBound {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl serde::Serialize for RangeBound {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            RangeBound::NegInfinity => serializer.serialize_str("-"),
            RangeBound::Infinity => serializer.serialize_str("+"),
            RangeBound::Key(key) => key.serialize(serializer),
        }
    }
}

impl<'de> serde::Deserialize<'de> for RangeBound {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        match text.as_str() {
            "-" => Ok(RangeBound::NegInfinity),
            "+" => Ok(RangeBound::Infinity),
            _ => {
                let decoded =
                    mneme_core::base64::decode(&text).map_err(serde::de::Error::custom)?;
                let key = RbsrKey::decode_bytes(&decoded).map_err(serde::de::Error::custom)?;
                Ok(RangeBound::Key(key))
            }
        }
    }
}

/// Order-independent cryptographic BLAKE3 range fingerprint over `[lower, upper)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RbsrFingerprint {
    pub count: u64,
    pub digest: [u8; DIGEST_BYTE_LEN],
}

impl RbsrFingerprint {
    /// Canonical fingerprint of an empty range.
    pub fn empty() -> Self {
        commit_fingerprint(0, [0_u64; 4])
    }
}

impl serde::Serialize for RbsrFingerprint {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let wire = WireFingerprint {
            count: self.count,
            digest: mneme_core::base64::encode(&self.digest),
        };
        wire.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for RbsrFingerprint {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let wire = WireFingerprint::deserialize(deserializer)?;
        let decoded = mneme_core::base64::decode(&wire.digest).map_err(serde::de::Error::custom)?;
        let digest: [u8; DIGEST_BYTE_LEN] = decoded
            .try_into()
            .map_err(|_| serde::de::Error::custom("fingerprint digest must be 32 bytes"))?;
        Ok(Self {
            count: wire.count,
            digest,
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WireFingerprint {
    #[serde(rename = "c")]
    count: u64,
    #[serde(rename = "d")]
    digest: String,
}

/// Probe sent by the initiator for one range `[lower, upper)`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "k", rename_all = "kebab-case")]
pub enum RbsrProbe {
    /// Compare range fingerprint `(count, digest)`.
    #[serde(rename = "f")]
    Fingerprint(RbsrFingerprint),
    /// Send explicit sorted local items in `[lower, upper)`.
    #[serde(rename = "i")]
    Items {
        #[serde(rename = "i")]
        items: Vec<RbsrKey>,
    },
}

/// One queried interval inside an [`RbsrRequest`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RbsrQueryRange {
    #[serde(rename = "l")]
    pub lower: RangeBound,
    #[serde(rename = "u")]
    pub upper: RangeBound,
    #[serde(rename = "d")]
    pub depth: u32,
    #[serde(rename = "p")]
    pub probe: RbsrProbe,
}

/// Bounded RBSR request frame sent from initiator to responder.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RbsrRequest {
    #[serde(rename = "r")]
    pub ranges: Vec<RbsrQueryRange>,
}

/// One child interval returned inside a split resolution.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RbsrSubrange {
    #[serde(rename = "l")]
    pub lower: RangeBound,
    #[serde(rename = "u")]
    pub upper: RangeBound,
    #[serde(rename = "d")]
    pub depth: u32,
    #[serde(rename = "f")]
    pub fingerprint: RbsrFingerprint,
}

/// Responder's resolution for one queried `[lower, upper)` interval.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "k", rename_all = "kebab-case")]
pub enum RbsrResolution {
    /// Both peers hold the identical subset in the queried range.
    #[serde(rename = "m")]
    Match,
    /// Responder holds zero items in the queried range.
    #[serde(rename = "e")]
    EmptyRemote,
    /// Responder's complete sorted items in `[lower, upper)`.
    #[serde(rename = "i")]
    Items {
        #[serde(rename = "l")]
        lower: RangeBound,
        #[serde(rename = "u")]
        upper: RangeBound,
        #[serde(rename = "i")]
        items: Vec<RbsrKey>,
    },
    /// Responder partitioned `[lower, upper)` at `pivots` with one fingerprint per subrange.
    #[serde(rename = "s")]
    Split {
        #[serde(rename = "l")]
        lower: RangeBound,
        #[serde(rename = "u")]
        upper: RangeBound,
        #[serde(rename = "p")]
        pivots: Vec<RangeBound>,
        #[serde(rename = "f")]
        fingerprints: Vec<RbsrFingerprint>,
    },
}

/// Bounded RBSR response frame sent from responder to initiator.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RbsrResponse {
    #[serde(rename = "r")]
    pub resolutions: Vec<RbsrResolution>,
}

/// Sorted, deduplicated set with $O(1)$ prefix-sum BLAKE3 range fingerprints.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RbsrSet {
    keys: Vec<RbsrKey>,
    prefix_sums: Vec<[u64; 4]>,
}

impl RbsrSet {
    /// Construct an empty RBSR set.
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            prefix_sums: vec![[0_u64; 4]],
        }
    }

    /// Build a sorted, deduplicated [`RbsrSet`] from an iterator of keys.
    pub fn from_keys(keys: impl IntoIterator<Item = RbsrKey>) -> Self {
        let mut sorted: Vec<RbsrKey> = keys.into_iter().collect();
        sorted.sort_unstable();
        sorted.dedup();

        let mut prefix_sums = Vec::with_capacity(sorted.len().saturating_add(1));
        let mut acc = [0_u64; 4];
        prefix_sums.push(acc);
        for key in &sorted {
            acc = add_u256(acc, hash_key(key));
            prefix_sums.push(acc);
        }

        Self {
            keys: sorted,
            prefix_sums,
        }
    }

    /// Number of items in this set.
    pub fn len_u64(&self) -> u64 {
        self.keys.len() as u64
    }

    /// Whether this set contains zero items.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Borrow all sorted keys in ascending order.
    pub fn keys(&self) -> &[RbsrKey] {
        &self.keys
    }

    /// Fingerprint of the full universe `(-∞, +∞)`.
    pub fn root_fingerprint(&self) -> RbsrFingerprint {
        let count = self.len_u64();
        let sum = self.prefix_sums.last().copied().unwrap_or([0_u64; 4]);
        commit_fingerprint(count, sum)
    }

    /// Compute the cryptographic range fingerprint for `[lower, upper)`.
    pub fn fingerprint_range(
        &self,
        lower: RangeBound,
        upper: RangeBound,
    ) -> crate::error::Result<RbsrFingerprint> {
        let (lo_idx, hi_idx) = self.range_indices(lower, upper)?;
        let count = hi_idx.saturating_sub(lo_idx) as u64;
        let hi_sum = self.prefix_sums.get(hi_idx).copied().unwrap_or([0_u64; 4]);
        let lo_sum = self.prefix_sums.get(lo_idx).copied().unwrap_or([0_u64; 4]);
        let sum = sub_u256(hi_sum, lo_sum);
        Ok(commit_fingerprint(count, sum))
    }

    /// Borrow the sorted items falling inside `[lower, upper)`.
    pub fn items_in_range(
        &self,
        lower: RangeBound,
        upper: RangeBound,
    ) -> crate::error::Result<&[RbsrKey]> {
        let (lo_idx, hi_idx) = self.range_indices(lower, upper)?;
        self.keys
            .get(lo_idx..hi_idx)
            .ok_or_else(|| crate::error::Failure::Protocol("RBSR slice bounds invalid".to_owned()))
    }

    /// Validate and evaluate an incoming [`RbsrRequest`] fail-closed.
    pub fn evaluate_request(&self, request: &RbsrRequest) -> crate::error::Result<RbsrResponse> {
        validate_request_bounds(request)?;
        let mut resolutions = Vec::with_capacity(request.ranges.len());
        for query in &request.ranges {
            let local_slice = self.items_in_range(query.lower, query.upper)?;
            let local_fp = self.fingerprint_range(query.lower, query.upper)?;
            let resolution = self.resolve_query(query, local_slice, local_fp)?;
            resolutions.push(resolution);
        }
        let response = RbsrResponse { resolutions };
        check_encoded_bound(&response)?;
        Ok(response)
    }

    fn resolve_query(
        &self,
        query: &RbsrQueryRange,
        local_slice: &[RbsrKey],
        local_fp: RbsrFingerprint,
    ) -> crate::error::Result<RbsrResolution> {
        if local_slice.is_empty() {
            let is_remote_empty = match &query.probe {
                RbsrProbe::Fingerprint(fp) => *fp == local_fp,
                RbsrProbe::Items { items } => items.is_empty(),
            };
            return Ok(if is_remote_empty {
                RbsrResolution::Match
            } else {
                RbsrResolution::EmptyRemote
            });
        }

        match &query.probe {
            RbsrProbe::Fingerprint(remote_fp) if *remote_fp == local_fp => {
                Ok(RbsrResolution::Match)
            }
            RbsrProbe::Items { items } if items.as_slice() == local_slice => {
                Ok(RbsrResolution::Match)
            }
            RbsrProbe::Items { .. } if local_slice.len() <= MAX_ITEMS_PER_LEAF_USIZE => {
                Ok(RbsrResolution::Items {
                    lower: query.lower,
                    upper: query.upper,
                    items: local_slice.to_vec(),
                })
            }
            RbsrProbe::Fingerprint(_) if local_slice.len() <= LEAF_THRESHOLD_USIZE => {
                Ok(RbsrResolution::Items {
                    lower: query.lower,
                    upper: query.upper,
                    items: local_slice.to_vec(),
                })
            }
            RbsrProbe::Fingerprint(_) | RbsrProbe::Items { .. } => {
                let _next_depth = next_child_depth(query.depth)?;
                let (pivots, fingerprints) =
                    self.split_pivots(query.lower, query.upper, local_slice)?;
                Ok(RbsrResolution::Split {
                    lower: query.lower,
                    upper: query.upper,
                    pivots,
                    fingerprints,
                })
            }
        }
    }

    fn split_pivots(
        &self,
        lower: RangeBound,
        upper: RangeBound,
        slice: &[RbsrKey],
    ) -> crate::error::Result<(Vec<RangeBound>, Vec<RbsrFingerprint>)> {
        if slice.len() < 2 {
            return Err(crate::error::Failure::Protocol(
                "cannot split RBSR range with fewer than two items".to_owned(),
            ));
        }
        let pivot = RangeBound::Key(slice[slice.len() / 2]);
        let left_fp = self.fingerprint_range(lower, pivot)?;
        let right_fp = self.fingerprint_range(pivot, upper)?;
        Ok((vec![pivot], vec![left_fp, right_fp]))
    }

    fn split_subranges(
        &self,
        lower: RangeBound,
        upper: RangeBound,
        child_depth: u32,
    ) -> crate::error::Result<Vec<RbsrSubrange>> {
        let slice = self.items_in_range(lower, upper)?;
        let (pivots, fingerprints) = self.split_pivots(lower, upper, slice)?;
        let mut children = Vec::with_capacity(fingerprints.len());
        let mut cursor = lower;
        for (pivot, fp) in pivots.into_iter().zip(&fingerprints) {
            children.push(RbsrSubrange {
                lower: cursor,
                upper: pivot,
                depth: child_depth,
                fingerprint: *fp,
            });
            cursor = pivot;
        }
        if let Some(&tail_fp) = fingerprints.last() {
            children.push(RbsrSubrange {
                lower: cursor,
                upper,
                depth: child_depth,
                fingerprint: tail_fp,
            });
        }
        Ok(children)
    }

    fn range_indices(
        &self,
        lower: RangeBound,
        upper: RangeBound,
    ) -> crate::error::Result<(usize, usize)> {
        if lower >= upper {
            return Err(crate::error::Failure::Protocol(
                "RBSR range must satisfy lower < upper".to_owned(),
            ));
        }
        let lo_idx = match lower {
            RangeBound::NegInfinity => 0,
            RangeBound::Key(key) => self.keys.partition_point(|item| *item < key),
            RangeBound::Infinity => {
                return Err(crate::error::Failure::Protocol(
                    "RBSR lower bound cannot be +infinity".to_owned(),
                ));
            }
        };
        let hi_idx = match upper {
            RangeBound::NegInfinity => {
                return Err(crate::error::Failure::Protocol(
                    "RBSR upper bound cannot be -infinity".to_owned(),
                ));
            }
            RangeBound::Key(key) => self.keys.partition_point(|item| *item < key),
            RangeBound::Infinity => self.keys.len(),
        };
        Ok((lo_idx, hi_idx))
    }
}

/// One pending range tracked by the initiator session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRange {
    pub lower: RangeBound,
    pub upper: RangeBound,
    pub depth: u32,
    pub remote_fp: Option<RbsrFingerprint>,
}

/// Final symmetric difference isolated by an [`RbsrSession`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RbsrOutcome {
    pub remote_only: Vec<RbsrKey>,
    pub local_only: Vec<RbsrKey>,
    pub rounds: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// Stateful iterative initiator for bounded RBSR reconciliation.
#[derive(Clone, Debug)]
pub struct RbsrSession {
    local: RbsrSet,
    pending: std::collections::BTreeMap<RangeBound, PendingRange>,
    remote_only: std::collections::BTreeSet<RbsrKey>,
    local_only: std::collections::BTreeSet<RbsrKey>,
    rounds: u32,
    bytes_sent: u64,
    bytes_received: u64,
}

impl RbsrSession {
    /// Start a new initiator session over `local`.
    pub fn new(local: RbsrSet) -> Self {
        let mut pending = std::collections::BTreeMap::new();
        pending.insert(
            RangeBound::NegInfinity,
            PendingRange {
                lower: RangeBound::NegInfinity,
                upper: RangeBound::Infinity,
                depth: 0,
                remote_fp: None,
            },
        );
        Self {
            local,
            pending,
            remote_only: std::collections::BTreeSet::new(),
            local_only: std::collections::BTreeSet::new(),
            rounds: 0,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    /// Produce the next bounded [`RbsrRequest`] and its aligned in-flight descriptors, or `None` when complete.
    pub fn next_request(
        &mut self,
    ) -> crate::error::Result<Option<(RbsrRequest, Vec<PendingRange>)>> {
        if self.pending.is_empty() {
            return Ok(None);
        }
        if self.rounds >= MAX_RBSR_ROUNDS {
            return Err(crate::error::Failure::Protocol(format!(
                "RBSR exceeded max rounds ({MAX_RBSR_ROUNDS})"
            )));
        }

        let mut queries: Vec<RbsrQueryRange> = Vec::new();
        let mut in_flight: Vec<PendingRange> = Vec::new();

        while let Some((first_key, entry)) = self.pending.pop_first() {
            let local_slice = self.local.items_in_range(entry.lower, entry.upper)?;
            let needs_split = entry.remote_fp.is_some() && local_slice.len() > LEAF_THRESHOLD_USIZE;

            if needs_split {
                let next_depth = next_child_depth(entry.depth)?;
                let children = self
                    .local
                    .split_subranges(entry.lower, entry.upper, next_depth)?;
                if queries.len().saturating_add(children.len()) > MAX_RANGES_PER_FRAME_USIZE {
                    self.pending.insert(first_key, entry);
                    break;
                }
                for child in children {
                    queries.push(RbsrQueryRange {
                        lower: child.lower,
                        upper: child.upper,
                        depth: child.depth,
                        probe: RbsrProbe::Fingerprint(child.fingerprint),
                    });
                    in_flight.push(PendingRange {
                        lower: child.lower,
                        upper: child.upper,
                        depth: child.depth,
                        remote_fp: None,
                    });
                }
            } else {
                if queries.len() >= MAX_RANGES_PER_FRAME_USIZE {
                    self.pending.insert(first_key, entry);
                    break;
                }
                let probe = if local_slice.len() <= LEAF_THRESHOLD_USIZE {
                    RbsrProbe::Items {
                        items: local_slice.to_vec(),
                    }
                } else {
                    let fp = self.local.fingerprint_range(entry.lower, entry.upper)?;
                    RbsrProbe::Fingerprint(fp)
                };
                queries.push(RbsrQueryRange {
                    lower: entry.lower,
                    upper: entry.upper,
                    depth: entry.depth,
                    probe,
                });
                in_flight.push(entry);
            }
        }

        let request = RbsrRequest { ranges: queries };
        let encoded_len = check_encoded_bound(&request)?;
        self.rounds = self.rounds.saturating_add(1);
        self.bytes_sent = self.bytes_sent.saturating_add(encoded_len);
        Ok(Some((request, in_flight)))
    }

    /// Validate and apply a [`RbsrResponse`] aligned 1-to-1 with `in_flight`.
    pub fn apply_response(
        &mut self,
        in_flight: &[PendingRange],
        response: RbsrResponse,
    ) -> crate::error::Result<()> {
        let encoded_len = check_encoded_bound(&response)?;
        self.bytes_received = self.bytes_received.saturating_add(encoded_len);

        if response.resolutions.len() != in_flight.len() {
            return Err(crate::error::Failure::Protocol(format!(
                "RBSR response length {} does not match request length {}",
                response.resolutions.len(),
                in_flight.len()
            )));
        }

        for (queried, resolution) in in_flight.iter().zip(response.resolutions) {
            self.apply_single_resolution(queried, resolution)?;
        }
        Ok(())
    }

    /// Consume the completed session and return sorted `remote_only` and `local_only` keys.
    pub fn finish(self) -> crate::error::Result<RbsrOutcome> {
        if !self.pending.is_empty() {
            return Err(crate::error::Failure::Protocol(
                "RBSR session finished with unresolved ranges".to_owned(),
            ));
        }
        Ok(RbsrOutcome {
            remote_only: self.remote_only.into_iter().collect(),
            local_only: self.local_only.into_iter().collect(),
            rounds: u64::from(self.rounds),
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
        })
    }

    fn apply_single_resolution(
        &mut self,
        queried: &PendingRange,
        resolution: RbsrResolution,
    ) -> crate::error::Result<()> {
        match resolution {
            RbsrResolution::Match => {}
            RbsrResolution::EmptyRemote => {
                for key in self.local.items_in_range(queried.lower, queried.upper)? {
                    self.local_only.insert(*key);
                }
            }
            RbsrResolution::Items {
                lower,
                upper,
                items,
            } => {
                require_exact_bounds(queried, lower, upper)?;
                validate_sorted_bounded_items(lower, upper, &items, MAX_ITEMS_PER_LEAF_USIZE)?;
                let local_slice = self.local.items_in_range(lower, upper)?;
                merge_sorted_diffs(
                    local_slice,
                    &items,
                    &mut self.local_only,
                    &mut self.remote_only,
                );
            }
            RbsrResolution::Split {
                lower,
                upper,
                pivots,
                fingerprints,
            } => {
                require_exact_bounds(queried, lower, upper)?;
                let children = build_and_validate_split_children(
                    lower,
                    upper,
                    queried.depth,
                    &pivots,
                    &fingerprints,
                )?;
                for child in children {
                    let local_fp = self.local.fingerprint_range(child.lower, child.upper)?;
                    if local_fp == child.fingerprint {
                        continue;
                    }
                    if child.fingerprint.count == 0 {
                        for key in self.local.items_in_range(child.lower, child.upper)? {
                            self.local_only.insert(*key);
                        }
                        continue;
                    }
                    self.pending.insert(
                        child.lower,
                        PendingRange {
                            lower: child.lower,
                            upper: child.upper,
                            depth: child.depth,
                            remote_fp: Some(child.fingerprint),
                        },
                    );
                }
            }
        }
        Ok(())
    }
}

/// Run a complete in-memory RBSR reconciliation between `local` and `remote`.
pub fn reconcile_in_memory(local: &RbsrSet, remote: &RbsrSet) -> crate::error::Result<RbsrOutcome> {
    let mut session = RbsrSession::new(local.clone());
    while let Some((request, in_flight)) = session.next_request()? {
        let response = remote.evaluate_request(&request)?;
        session.apply_response(&in_flight, response)?;
    }
    session.finish()
}

fn next_child_depth(depth: u32) -> crate::error::Result<u32> {
    let next = depth
        .checked_add(1)
        .ok_or_else(|| crate::error::Failure::Protocol("RBSR depth overflow".to_owned()))?;
    if next > MAX_RBSR_DEPTH {
        return Err(crate::error::Failure::Protocol(format!(
            "RBSR recursion depth {next} exceeds bound {MAX_RBSR_DEPTH}"
        )));
    }
    Ok(next)
}

fn require_exact_bounds(
    queried: &PendingRange,
    lower: RangeBound,
    upper: RangeBound,
) -> crate::error::Result<()> {
    if lower != queried.lower || upper != queried.upper {
        return Err(crate::error::Failure::Protocol(
            "RBSR response bounds do not match queried range".to_owned(),
        ));
    }
    Ok(())
}

fn validate_request_bounds(request: &RbsrRequest) -> crate::error::Result<()> {
    let _ = check_encoded_bound(request)?;
    if request.ranges.is_empty() {
        return Err(crate::error::Failure::Protocol(
            "RBSR request must contain at least one range".to_owned(),
        ));
    }
    if request.ranges.len() > MAX_RANGES_PER_FRAME_USIZE {
        return Err(crate::error::Failure::Protocol(format!(
            "RBSR request range count {} exceeds bound {MAX_RBSR_RANGES_PER_FRAME}",
            request.ranges.len()
        )));
    }
    let mut prev_upper: Option<RangeBound> = None;
    for query in &request.ranges {
        if query.lower >= query.upper {
            return Err(crate::error::Failure::Protocol(
                "RBSR query range must satisfy lower < upper".to_owned(),
            ));
        }
        if query.depth > MAX_RBSR_DEPTH {
            return Err(crate::error::Failure::Protocol(format!(
                "RBSR query depth {} exceeds bound {MAX_RBSR_DEPTH}",
                query.depth
            )));
        }
        if let Some(prev) = prev_upper
            && prev > query.lower
        {
            return Err(crate::error::Failure::Protocol(
                "RBSR query ranges are overlapping or out of order".to_owned(),
            ));
        }
        if let RbsrProbe::Items { items } = &query.probe {
            validate_sorted_bounded_items(
                query.lower,
                query.upper,
                items,
                MAX_ITEMS_PER_LEAF_USIZE,
            )?;
        }
        prev_upper = Some(query.upper);
    }
    Ok(())
}

fn build_and_validate_split_children(
    parent_lower: RangeBound,
    parent_upper: RangeBound,
    parent_depth: u32,
    pivots: &[RangeBound],
    fingerprints: &[RbsrFingerprint],
) -> crate::error::Result<Vec<RbsrSubrange>> {
    if pivots.is_empty() || fingerprints.len() != pivots.len().saturating_add(1) {
        return Err(crate::error::Failure::Protocol(
            "RBSR split pivots and fingerprints length mismatch".to_owned(),
        ));
    }
    if !(2..=MAX_BRANCHING_USIZE).contains(&fingerprints.len()) {
        return Err(crate::error::Failure::Protocol(format!(
            "RBSR split must have 2..={MAX_RBSR_BRANCHING} subranges, got {}",
            fingerprints.len()
        )));
    }
    let child_depth = next_child_depth(parent_depth)?;
    let mut children = Vec::with_capacity(fingerprints.len());
    let mut cursor = parent_lower;
    for (&pivot, &fp) in pivots.iter().zip(fingerprints) {
        if cursor >= pivot {
            return Err(crate::error::Failure::Protocol(
                "RBSR split pivots are non-monotonic or out of order".to_owned(),
            ));
        }
        children.push(RbsrSubrange {
            lower: cursor,
            upper: pivot,
            depth: child_depth,
            fingerprint: fp,
        });
        cursor = pivot;
    }
    let Some(&tail_fp) = fingerprints.last() else {
        return Err(crate::error::Failure::Protocol(
            "RBSR split tail fingerprint missing".to_owned(),
        ));
    };
    if cursor >= parent_upper {
        return Err(crate::error::Failure::Protocol(
            "RBSR split final pivot exceeds parent upper bound".to_owned(),
        ));
    }
    children.push(RbsrSubrange {
        lower: cursor,
        upper: parent_upper,
        depth: child_depth,
        fingerprint: tail_fp,
    });
    Ok(children)
}

fn validate_sorted_bounded_items(
    lower: RangeBound,
    upper: RangeBound,
    items: &[RbsrKey],
    max_items: usize,
) -> crate::error::Result<()> {
    if items.len() > max_items {
        return Err(crate::error::Failure::Protocol(format!(
            "RBSR leaf item count {} exceeds bound {max_items}",
            items.len()
        )));
    }
    let mut prev: Option<RbsrKey> = None;
    for &item in items {
        let bound = RangeBound::Key(item);
        if bound < lower || bound >= upper {
            return Err(crate::error::Failure::Protocol(
                "RBSR leaf item lies outside declared range bounds".to_owned(),
            ));
        }
        if let Some(previous) = prev
            && previous >= item
        {
            return Err(crate::error::Failure::Protocol(
                "RBSR leaf items are unsorted or duplicated".to_owned(),
            ));
        }
        prev = Some(item);
    }
    Ok(())
}

fn merge_sorted_diffs(
    local: &[RbsrKey],
    remote: &[RbsrKey],
    local_only: &mut std::collections::BTreeSet<RbsrKey>,
    remote_only: &mut std::collections::BTreeSet<RbsrKey>,
) {
    let mut i = 0_usize;
    let mut j = 0_usize;
    while i < local.len() && j < remote.len() {
        match local[i].cmp(&remote[j]) {
            std::cmp::Ordering::Less => {
                local_only.insert(local[i]);
                i = i.saturating_add(1);
            }
            std::cmp::Ordering::Greater => {
                remote_only.insert(remote[j]);
                j = j.saturating_add(1);
            }
            std::cmp::Ordering::Equal => {
                i = i.saturating_add(1);
                j = j.saturating_add(1);
            }
        }
    }
    for &item in local.get(i..).unwrap_or(&[]) {
        local_only.insert(item);
    }
    for &item in remote.get(j..).unwrap_or(&[]) {
        remote_only.insert(item);
    }
}

fn check_encoded_bound<T: serde::Serialize>(value: &T) -> crate::error::Result<u64> {
    let encoded = serde_json::to_vec(value)
        .map_err(|error| crate::error::Failure::Protocol(format!("encode RBSR frame: {error}")))?;
    let actual_bytes = encoded.len() as u64;
    if actual_bytes > MAX_RBSR_FRAME_BYTES {
        return Err(crate::error::Failure::SizeLimitExceeded {
            actual_bytes,
            limit_bytes: MAX_RBSR_FRAME_BYTES,
        });
    }
    Ok(actual_bytes)
}

fn hash_key(key: &RbsrKey) -> [u64; 4] {
    let mut hasher = blake3::Hasher::new_derive_key(ELEMENT_HASH_CONTEXT);
    hasher.update(&key.0);
    let digest = hasher.finalize();
    let b = digest.as_bytes();
    [
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
        u64::from_le_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]),
        u64::from_le_bytes([b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]]),
    ]
}

fn commit_fingerprint(count: u64, sum: [u64; 4]) -> RbsrFingerprint {
    let mut hasher = blake3::Hasher::new_derive_key(RANGE_HASH_CONTEXT);
    hasher.update(&count.to_le_bytes());
    for limb in sum {
        hasher.update(&limb.to_le_bytes());
    }
    let digest = hasher.finalize();
    RbsrFingerprint {
        count,
        digest: *digest.as_bytes(),
    }
}

const fn add_u256(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let (s0, c0) = a[0].overflowing_add(b[0]);
    let (s1a, c1a) = a[1].overflowing_add(b[1]);
    let (s1, c1b) = s1a.overflowing_add(if c0 { 1 } else { 0 });
    let (s2a, c2a) = a[2].overflowing_add(b[2]);
    let (s2, c2b) = s2a.overflowing_add(if c1a || c1b { 1 } else { 0 });
    let (s3a, _) = a[3].overflowing_add(b[3]);
    let (s3, _) = s3a.overflowing_add(if c2a || c2b { 1 } else { 0 });
    [s0, s1, s2, s3]
}

const fn sub_u256(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let (d0, b0) = a[0].overflowing_sub(b[0]);
    let (d1a, b1a) = a[1].overflowing_sub(b[1]);
    let (d1, b1b) = d1a.overflowing_sub(if b0 { 1 } else { 0 });
    let (d2a, b2a) = a[2].overflowing_sub(b[2]);
    let (d2, b2b) = d2a.overflowing_sub(if b1a || b1b { 1 } else { 0 });
    let (d3a, _) = a[3].overflowing_sub(b[3]);
    let (d3, _) = d3a.overflowing_sub(if b2a || b2b { 1 } else { 0 });
    [d0, d1, d2, d3]
}

#[cfg(test)]
#[allow(
    unknown_lints,
    unbounded_collection_growth,
    allocation_in_loop,
    raw_arithmetic_overflow
)] // test fixture construction builds 1000-item sets
mod tests {
    use super::*;

    fn make_blob_key(index: u64, salt: u8) -> RbsrKey {
        let mut input = [0_u8; 9];
        input[0..8].copy_from_slice(&index.to_le_bytes());
        input[8] = salt;
        let hash = blake3::hash(&input);
        RbsrKey::from_blob_bytes(*hash.as_bytes())
    }

    fn make_rev_key(index: u64, salt: u8) -> RbsrKey {
        let mut rec_input = [0_u8; 10];
        rec_input[0..8].copy_from_slice(&index.to_le_bytes());
        rec_input[8] = salt;
        rec_input[9] = 1;
        let rec_hash = blake3::hash(&rec_input);
        let mut rec = [0_u8; 16];
        rec.copy_from_slice(&rec_hash.as_bytes()[0..16]);

        let mut rev_input = [0_u8; 10];
        rev_input[0..8].copy_from_slice(&index.to_le_bytes());
        rev_input[8] = salt;
        rev_input[9] = 2;
        let rev_hash = blake3::hash(&rev_input);
        let mut rev = [0_u8; 16];
        rev.copy_from_slice(&rev_hash.as_bytes()[0..16]);

        RbsrKey::from_revision(
            mneme_core::RecordId::from_bytes(rec),
            mneme_core::RevisionId::from_bytes(rev),
        )
    }

    #[test]
    fn order_independent_fingerprint_and_empty_diff() {
        let mut keys_a = Vec::new();
        for idx in 0_u64..1050 {
            keys_a.push(make_rev_key(idx, 1));
            keys_a.push(make_blob_key(idx, 1));
        }
        let mut keys_b = keys_a.clone();
        keys_b.reverse();

        let set_a = RbsrSet::from_keys(keys_a);
        let set_b = RbsrSet::from_keys(keys_b);
        assert_eq!(set_a.root_fingerprint(), set_b.root_fingerprint());

        let outcome = reconcile_in_memory(&set_a, &set_b).expect("empty diff reconciles");
        assert!(outcome.remote_only.is_empty());
        assert!(outcome.local_only.is_empty());
        assert_eq!(outcome.rounds, 1);
        assert!(outcome.bytes_sent + outcome.bytes_received < 512);
    }

    #[test]
    fn thousand_item_sets_differing_by_five_reconcile_logarithmically() {
        let mut shared = Vec::new();
        for idx in 0_u64..1000 {
            shared.push(make_blob_key(idx, 7));
        }

        let mut keys_remote = shared.clone();
        let expected_remote_only = vec![
            make_blob_key(10_001, 9),
            make_blob_key(10_002, 9),
            make_blob_key(10_003, 9),
        ];
        keys_remote.extend(expected_remote_only.iter().copied());

        let mut keys_local = shared;
        let expected_local_only = vec![make_blob_key(20_001, 11), make_blob_key(20_002, 11)];
        keys_local.extend(expected_local_only.iter().copied());

        let remote = RbsrSet::from_keys(keys_remote);
        let local = RbsrSet::from_keys(keys_local);

        let outcome = reconcile_in_memory(&local, &remote).expect("5-diff reconciles");
        let mut expected_r = expected_remote_only;
        expected_r.sort_unstable();
        let mut expected_l = expected_local_only;
        expected_l.sort_unstable();

        assert_eq!(outcome.remote_only, expected_r);
        assert_eq!(outcome.local_only, expected_l);
        assert!(outcome.rounds <= 12);

        let full_list_bytes = serde_json::to_vec(remote.keys())
            .expect("full list json")
            .len() as u64;
        let rbsr_total_bytes = outcome.bytes_sent + outcome.bytes_received;
        assert!(
            rbsr_total_bytes < full_list_bytes / 4,
            "rounds={} sent={} recv={} total={} full_list_bytes={}",
            outcome.rounds,
            outcome.bytes_sent,
            outcome.bytes_received,
            rbsr_total_bytes,
            full_list_bytes
        );
    }

    #[test]
    fn disjoint_thousand_item_sets_reconcile_within_bounded_frames() {
        let mut keys_a = Vec::new();
        let mut keys_b = Vec::new();
        for idx in 0_u64..1000 {
            keys_a.push(make_blob_key(idx, 1));
            keys_b.push(make_blob_key(idx, 2));
        }
        let set_a = RbsrSet::from_keys(keys_a);
        let set_b = RbsrSet::from_keys(keys_b);

        let outcome = reconcile_in_memory(&set_a, &set_b).expect("disjoint reconciles");
        assert_eq!(outcome.remote_only.as_slice(), set_b.keys());
        assert_eq!(outcome.local_only.as_slice(), set_a.keys());
    }

    #[test]
    fn malformed_and_out_of_order_ranges_fail_closed() {
        let set = RbsrSet::from_keys((0_u64..64).map(|idx| make_blob_key(idx, 3)));
        let key_lo = set.keys()[10];
        let key_hi = set.keys()[5];

        // 1. lower >= upper rejected by evaluate_request
        let inverted = RbsrRequest {
            ranges: vec![RbsrQueryRange {
                lower: RangeBound::Key(key_lo),
                upper: RangeBound::Key(key_hi),
                depth: 0,
                probe: RbsrProbe::Fingerprint(RbsrFingerprint::empty()),
            }],
        };
        assert!(set.evaluate_request(&inverted).is_err());

        // 2. Overlapping / out-of-order request ranges rejected
        let overlapping = RbsrRequest {
            ranges: vec![
                RbsrQueryRange {
                    lower: RangeBound::NegInfinity,
                    upper: RangeBound::Key(key_lo),
                    depth: 0,
                    probe: RbsrProbe::Fingerprint(RbsrFingerprint::empty()),
                },
                RbsrQueryRange {
                    lower: RangeBound::Key(key_hi),
                    upper: RangeBound::Infinity,
                    depth: 0,
                    probe: RbsrProbe::Fingerprint(RbsrFingerprint::empty()),
                },
            ],
        };
        assert!(set.evaluate_request(&overlapping).is_err());

        // 3. Depth > MAX_RBSR_DEPTH rejected
        let too_deep = RbsrRequest {
            ranges: vec![RbsrQueryRange {
                lower: RangeBound::NegInfinity,
                upper: RangeBound::Infinity,
                depth: MAX_RBSR_DEPTH + 1,
                probe: RbsrProbe::Fingerprint(RbsrFingerprint::empty()),
            }],
        };
        assert!(set.evaluate_request(&too_deep).is_err());

        // 4. Unsorted / duplicate / out-of-bounds leaf items rejected
        let dup_items = RbsrRequest {
            ranges: vec![RbsrQueryRange {
                lower: RangeBound::NegInfinity,
                upper: RangeBound::Infinity,
                depth: 0,
                probe: RbsrProbe::Items {
                    items: vec![key_hi, key_hi],
                },
            }],
        };
        assert!(set.evaluate_request(&dup_items).is_err());

        let out_of_bounds_items = RbsrRequest {
            ranges: vec![RbsrQueryRange {
                lower: RangeBound::NegInfinity,
                upper: RangeBound::Key(key_hi),
                depth: 0,
                probe: RbsrProbe::Items {
                    items: vec![key_lo],
                },
            }],
        };
        assert!(set.evaluate_request(&out_of_bounds_items).is_err());

        // 5. Invalid key tag rejected on deserialize
        let bad_key = mneme_core::base64::encode(&[99_u8; 33]);
        assert!(serde_json::from_str::<RbsrKey>(&format!("\"{bad_key}\"")).is_err());

        // 6. Malformed Split response rejected by RbsrSession::apply_response
        let mut session = RbsrSession::new(set);
        let (_req, in_flight) = session.next_request().expect("req").expect("some");
        let bad_split = RbsrResponse {
            resolutions: vec![RbsrResolution::Split {
                lower: RangeBound::NegInfinity,
                upper: RangeBound::Infinity,
                pivots: vec![RangeBound::Key(key_lo), RangeBound::Key(key_hi)],
                fingerprints: vec![
                    RbsrFingerprint::empty(),
                    RbsrFingerprint::empty(),
                    RbsrFingerprint::empty(),
                ],
            }],
        };
        assert!(session.apply_response(&in_flight, bad_split).is_err());
    }
}
