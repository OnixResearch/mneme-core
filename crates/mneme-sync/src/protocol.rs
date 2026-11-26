//! Wire types, ALPN handlers, and deny-by-default peer allowlist enforcement.

#![allow(
    unknown_lints,
    assertion_density,
    path_segment_repetition,
    fragile_exhaustive_enum_match,
    numeric_units
)] // returns typed Result failures instead of panicking; AllowlistedProtocol/SyncControl* match module domain; exhaustive match on closed control enum; size_bytes carries explicit unit

use std::str::FromStr;

/// ALPN identifier for Mneme's sync control protocol.
pub const SYNC_CONTROL_ALPN: &[u8] = b"/mneme/sync/1";
/// Maximum control request/response message size (1 MiB).
pub const MAX_CONTROL_MESSAGE_BYTES: usize = 1024 * 1024;
/// Maximum delta metadata items requested in one control round-trip.
pub const MAX_DELTA_ITEMS_PER_REQUEST: u64 = 128;
/// Maximum size of a gossip head-revision announcement (4 KiB).
pub const MAX_GOSSIP_MESSAGE_BYTES: usize = 4096;
/// Maximum portable revision bundle accepted over Iroh sync.
pub const MAX_SYNC_BUNDLE_BYTES: u64 = mneme_store::portability::MAX_PORTABLE_ARCHIVE_BYTES;
/// Maximum wall-clock timeout for one sync control stream read/write (seconds).
pub const CONTROL_STREAM_TIMEOUT_SECS: u64 = 15;
/// Maximum control request frame size accepted from a not-yet-authenticated peer (128 KiB).
pub const MAX_UNAUTHENTICATED_CONTROL_BYTES: u64 = 128 * 1024;
/// Maximum concurrent sync control connections accepted by one node.
pub const MAX_CONCURRENT_CONTROL_CONNECTIONS: u64 = 64;
/// Maximum concurrent blob/gossip connections accepted by one node.
pub const MAX_CONCURRENT_TRANSPORT_CONNECTIONS: u64 = 64;

const UNAUTHORIZED_CLOSE_CODE: u32 = 403;
const RATE_LIMITED_CLOSE_CODE: u32 = 429;
const HEAD_ANNOUNCEMENT_SIGNING_DOMAIN: &[u8] = b"mneme.sync.head.announcement.v1\0";
const MAX_CONTROL_STREAMS_PER_CONN: u64 = 1024;

/// Relay policy for an Iroh sync endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayPreference {
    /// Disable relays completely (LAN / loopback offline-first mode).
    Disabled,
    /// Use Iroh's default relay servers.
    Default,
    /// Use one explicit relay URL.
    Custom(iroh::RelayUrl),
}

impl RelayPreference {
    pub(crate) fn into_iroh(self) -> iroh::RelayMode {
        match self {
            RelayPreference::Disabled => iroh::RelayMode::Disabled,
            RelayPreference::Default => iroh::RelayMode::Default,
            RelayPreference::Custom(url) => iroh::RelayMode::Custom(url.into()),
        }
    }
}

/// Address lookup / discovery mode for an Iroh sync endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryMode {
    /// No LAN multicast or internet DHT; addresses are supplied via memory lookup.
    OfflineLoopback,
    /// Local-first mDNS discovery on LAN with zero internet or relay dependency.
    MdnsOnly,
    /// Local-first mDNS plus Mainline DHT address lookup.
    MdnsAndDht,
}

/// Serialized representation of a [`mneme_core::ContentDigest`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WireDigest {
    pub algorithm: String,
    pub profile: String,
    pub boundary: String,
    pub hex: String,
}

impl WireDigest {
    /// Convert a [`mneme_core::ContentDigest`] into its wire representation.
    pub fn from_digest(digest: mneme_core::ContentDigest) -> Self {
        Self {
            algorithm: digest.algorithm().symbol().to_owned(),
            profile: digest.profile().symbol().to_owned(),
            boundary: digest.boundary().symbol().to_owned(),
            hex: digest.to_hex(),
        }
    }

    /// Parse and validate back into a [`mneme_core::ContentDigest`].
    pub fn to_digest(&self) -> crate::error::Result<mneme_core::ContentDigest> {
        let algorithm = mneme_core::HashAlgorithm::parse(&self.algorithm).ok_or_else(|| {
            crate::error::Failure::Protocol(format!("unsupported algorithm {}", self.algorithm))
        })?;
        let profile = mneme_core::EncodingProfile::parse(&self.profile).ok_or_else(|| {
            crate::error::Failure::Protocol(format!("unsupported profile {}", self.profile))
        })?;
        let boundary = mneme_core::ValueBoundary::parse(&self.boundary).ok_or_else(|| {
            crate::error::Failure::Protocol(format!("unsupported boundary {}", self.boundary))
        })?;
        let bytes = parse_hex_32(&self.hex)?;
        mneme_core::ContentDigest::from_parts(algorithm, profile, boundary, bytes)
            .map_err(|reason| crate::error::Failure::Protocol(reason.to_owned()))
    }
}

/// Reference to an immutable source blob exported alongside a revision bundle.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BlobDigestRef {
    pub content_digest: WireDigest,
    pub transport_hash: String,
    pub byte_length: u64,
}

/// Wire representation of a [`mneme_kernel::hlc::HybridTimestamp`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WireHlc {
    pub physical_ns: i64,
    pub logical: u32,
}

impl WireHlc {
    /// Convert a kernel [`mneme_kernel::hlc::HybridTimestamp`] into its wire form.
    pub const fn from_kernel(ts: mneme_kernel::hlc::HybridTimestamp) -> Self {
        Self {
            physical_ns: ts.physical_ns,
            logical: ts.logical,
        }
    }

    /// Convert back into a kernel [`mneme_kernel::hlc::HybridTimestamp`].
    pub const fn to_kernel(self) -> mneme_kernel::hlc::HybridTimestamp {
        mneme_kernel::hlc::HybridTimestamp {
            physical_ns: self.physical_ns,
            logical: self.logical,
        }
    }
}

/// Thread-safe Hybrid Logical Clock state owned by one [`crate::SyncNode`].
#[derive(Clone)]
pub(crate) struct SharedSyncHlc {
    inner: std::sync::Arc<std::sync::Mutex<(mneme_kernel::hlc::HybridTimestamp, i64)>>,
    clock: std::sync::Arc<dyn mneme_store::Clock>,
}

impl SharedSyncHlc {
    pub(crate) fn new(clock: std::sync::Arc<dyn mneme_store::Clock>) -> Self {
        let now_ns = clock.now().nanos();
        Self {
            inner: std::sync::Arc::new(std::sync::Mutex::new((
                mneme_kernel::hlc::HybridTimestamp {
                    physical_ns: now_ns,
                    logical: 0,
                },
                mneme_kernel::hlc::DEFAULT_MAX_SKEW_NS,
            ))),
            clock,
        }
    }

    pub(crate) fn current(&self) -> mneme_kernel::hlc::HybridTimestamp {
        self.inner
            .lock()
            .map(|guard| guard.0)
            .unwrap_or(mneme_kernel::hlc::HybridTimestamp {
                physical_ns: 0,
                logical: 0,
            })
    }

    pub(crate) fn set_max_skew_ns(&self, max_skew_ns: i64) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.1 = max_skew_ns;
        }
    }

    pub(crate) fn tick(&self) -> crate::error::Result<WireHlc> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| crate::error::Failure::Protocol("sync HLC mutex poisoned".to_owned()))?;
        let pt_ns = self.clock.now().nanos();
        let next = mneme_kernel::hlc::tick_local(guard.0, pt_ns, guard.1).map_err(|error| {
            crate::error::Failure::Protocol(format!("sync HLC tick failed: {error:?}"))
        })?;
        guard.0 = next;
        Ok(WireHlc::from_kernel(next))
    }

    pub(crate) fn observe(&self, remote: WireHlc) -> crate::error::Result<WireHlc> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| crate::error::Failure::Protocol("sync HLC mutex poisoned".to_owned()))?;
        let pt_ns = self.clock.now().nanos();
        let next = mneme_kernel::hlc::receive(guard.0, pt_ns, remote.to_kernel(), guard.1)
            .map_err(|error| {
                crate::error::Failure::Protocol(format!("sync HLC receive failed: {error:?}"))
            })?;
        guard.0 = next;
        Ok(WireHlc::from_kernel(next))
    }
}

const fn no_hlc() -> Option<WireHlc> {
    None
}

const fn default_generation() -> u64 {
    1
}

/// Wire representation of one [`mneme_store::portability::PortableSuppression`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct WirePortableSuppression {
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    pub target_kind: String,
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<WireDigest>,
    pub generation: u64,
}

impl WirePortableSuppression {
    fn from_portable(entry: &mneme_store::portability::PortableSuppression) -> Self {
        Self {
            target: entry.target.to_hex(),
            revision: entry.revision.map(|rev| rev.to_hex()),
            target_kind: entry.target_kind.clone(),
            mode: entry.mode.as_str().to_owned(),
            content_digest: entry.content_digest.map(WireDigest::from_digest),
            generation: entry.generation,
        }
    }

    fn to_portable(&self) -> crate::error::Result<mneme_store::portability::PortableSuppression> {
        let target = mneme_core::RecordId::from_hex(&self.target).map_err(|reason| {
            crate::error::Failure::Protocol(format!("invalid suppression target: {reason}"))
        })?;
        let revision = self
            .revision
            .as_deref()
            .map(|hex| {
                mneme_core::RevisionId::from_hex(hex).map_err(|reason| {
                    crate::error::Failure::Protocol(format!(
                        "invalid suppression revision: {reason}"
                    ))
                })
            })
            .transpose()?;
        let mode = mneme_store::SuppressionMode::parse(&self.mode).ok_or_else(|| {
            crate::error::Failure::Protocol(format!("invalid suppression mode {}", self.mode))
        })?;
        let content_digest = self
            .content_digest
            .as_ref()
            .map(WireDigest::to_digest)
            .transpose()?;
        Ok(mneme_store::portability::PortableSuppression {
            target,
            revision,
            target_kind: self.target_kind.clone(),
            mode,
            content_digest,
            generation: self.generation,
        })
    }
}

/// Wire representation of one [`mneme_store::portability::PortablePruning`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct WirePortablePruning {
    pub source: String,
    pub revision: String,
    pub digest: WireDigest,
}

impl WirePortablePruning {
    fn from_portable(entry: &mneme_store::portability::PortablePruning) -> Self {
        Self {
            source: entry.source.to_hex(),
            revision: entry.revision.to_hex(),
            digest: WireDigest::from_digest(entry.digest),
        }
    }

    fn to_portable(&self) -> crate::error::Result<mneme_store::portability::PortablePruning> {
        let source = mneme_core::RecordId::from_hex(&self.source).map_err(|reason| {
            crate::error::Failure::Protocol(format!("invalid pruning source: {reason}"))
        })?;
        let revision = mneme_core::RevisionId::from_hex(&self.revision).map_err(|reason| {
            crate::error::Failure::Protocol(format!("invalid pruning revision: {reason}"))
        })?;
        let digest = self.digest.to_digest()?;
        Ok(mneme_store::portability::PortablePruning {
            source,
            revision,
            digest,
        })
    }
}

/// Wire representation of [`mneme_store::portability::PortableRetentionState`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct WirePortableRetentionState {
    pub generation: u64,
    pub suppressions: Vec<WirePortableSuppression>,
    pub prunings: Vec<WirePortablePruning>,
}

impl WirePortableRetentionState {
    pub(crate) fn from_portable(state: &mneme_store::portability::PortableRetentionState) -> Self {
        Self {
            generation: state.generation,
            suppressions: state
                .suppressions
                .iter()
                .map(WirePortableSuppression::from_portable)
                .collect(),
            prunings: state
                .prunings
                .iter()
                .map(WirePortablePruning::from_portable)
                .collect(),
        }
    }

    pub(crate) fn to_portable(
        &self,
    ) -> crate::error::Result<mneme_store::portability::PortableRetentionState> {
        let suppressions = self
            .suppressions
            .iter()
            .map(WirePortableSuppression::to_portable)
            .collect::<crate::error::Result<Vec<_>>>()?;
        let prunings = self
            .prunings
            .iter()
            .map(WirePortablePruning::to_portable)
            .collect::<crate::error::Result<Vec<_>>>()?;
        Ok(mneme_store::portability::PortableRetentionState {
            generation: self.generation,
            suppressions,
            prunings,
        })
    }
}

/// Metadata describing a served vault scope revision and its portable bundle.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct VaultSnapshotInfo {
    pub vault_id: String,
    pub scope: String,
    pub head_revision: String,
    pub head_revision_digest: WireDigest,
    pub sequence: u64,
    #[serde(default = "default_generation")]
    pub eligibility_generation: u64,
    pub bundle_hash: String,
    pub bundle_bytes: u64,
    pub blobs: Vec<BlobDigestRef>,
    #[serde(default = "no_hlc", skip_serializing_if = "Option::is_none")]
    pub hlc: Option<WireHlc>,
}

impl VaultSnapshotInfo {
    /// Parse the [`mneme_core::ScopeId`] named by this snapshot.
    pub fn parsed_scope(&self) -> crate::error::Result<mneme_core::ScopeId> {
        parse_scope_id(&self.scope)
    }

    /// Parse the [`iroh_blobs::Hash`] of the portable revision bundle.
    pub fn parsed_bundle_hash(&self) -> crate::error::Result<iroh_blobs::Hash> {
        iroh_blobs::Hash::from_str(&self.bundle_hash).map_err(|error| {
            crate::error::Failure::Protocol(format!("invalid bundle hash: {error}"))
        })
    }

    /// Build a lightweight gossip [`HeadAnnouncement`] from this snapshot.
    pub fn to_announcement(&self) -> HeadAnnouncement {
        HeadAnnouncement {
            vault_id: self.vault_id.clone(),
            scope: self.scope.clone(),
            head_revision: self.head_revision.clone(),
            head_revision_digest: self.head_revision_digest.clone(),
            seq: self.sequence,
            bundle_hash: self.bundle_hash.clone(),
            bundle_bytes: self.bundle_bytes,
            hlc: self.hlc,
            origin: None,
            signature: None,
        }
    }

    /// Build and Ed25519-sign a [`HeadAnnouncement`] from this snapshot.
    pub fn to_signed_announcement(
        &self,
        signing_key: &iroh::SecretKey,
    ) -> crate::error::Result<HeadAnnouncement> {
        self.to_announcement().signed(signing_key)
    }
}

const fn no_origin() -> Option<iroh::EndpointId> {
    None
}

const fn no_signature() -> Option<crate::capability::CapabilitySignature> {
    None
}

/// Lightweight private-topic head announcement carried over `iroh-gossip` and `PushHead`.
///
/// Announcements never mutate ledger state directly; receivers verify the
/// originating node's Ed25519 signature, peer authorization, and monotonic `seq`
/// before pulling the referenced bundle over `iroh-blobs`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HeadAnnouncement {
    pub vault_id: String,
    pub scope: String,
    pub head_revision: String,
    pub head_revision_digest: WireDigest,
    pub seq: u64,
    pub bundle_hash: String,
    pub bundle_bytes: u64,
    #[serde(default = "no_hlc", skip_serializing_if = "Option::is_none")]
    pub hlc: Option<WireHlc>,
    #[serde(default = "no_origin", skip_serializing_if = "Option::is_none")]
    pub origin: Option<iroh::EndpointId>,
    #[serde(default = "no_signature", skip_serializing_if = "Option::is_none")]
    pub signature: Option<crate::capability::CapabilitySignature>,
}

impl HeadAnnouncement {
    /// Sign this announcement in-place with `signing_key`.
    pub fn sign(&mut self, signing_key: &iroh::SecretKey) -> crate::error::Result<()> {
        let origin = signing_key.public();
        self.origin = Some(origin);
        let message = canonical_announcement_bytes(self, origin)?;
        self.signature = Some(crate::capability::CapabilitySignature::from_iroh(
            signing_key.sign(&message),
        ));
        Ok(())
    }

    /// Return a copy of this announcement signed by `signing_key`.
    pub fn signed(mut self, signing_key: &iroh::SecretKey) -> crate::error::Result<Self> {
        self.sign(signing_key)?;
        Ok(self)
    }

    /// Verify the Ed25519 signature and return the authenticated originating [`iroh::EndpointId`].
    pub fn verify_signature(&self) -> crate::error::Result<iroh::EndpointId> {
        let origin = self.origin.ok_or_else(|| {
            crate::error::Failure::Protocol("head announcement missing origin".to_owned())
        })?;
        let signature = self.signature.ok_or_else(|| {
            crate::error::Failure::Protocol("head announcement missing signature".to_owned())
        })?;
        let message = canonical_announcement_bytes(self, origin)?;
        origin.verify(&message, signature.as_iroh()).map_err(|_| {
            crate::error::Failure::CapabilityDenied(format!(
                "invalid Ed25519 signature on head announcement from {origin}"
            ))
        })?;
        Ok(origin)
    }

    /// Encode as bounded JSON bytes for gossip broadcast.
    pub fn encode(&self) -> crate::error::Result<bytes::Bytes> {
        let encoded = serde_json::to_vec(self).map_err(|error| {
            crate::error::Failure::Protocol(format!("encode head announcement: {error}"))
        })?;
        if encoded.len() > MAX_GOSSIP_MESSAGE_BYTES {
            return Err(crate::error::Failure::SizeLimitExceeded {
                actual_bytes: encoded.len() as u64,
                limit_bytes: MAX_GOSSIP_MESSAGE_BYTES as u64,
            });
        }
        Ok(bytes::Bytes::from(encoded))
    }

    /// Decode and bound-check a received gossip announcement.
    pub fn decode(bytes: &[u8]) -> crate::error::Result<Self> {
        if bytes.len() > MAX_GOSSIP_MESSAGE_BYTES {
            return Err(crate::error::Failure::SizeLimitExceeded {
                actual_bytes: bytes.len() as u64,
                limit_bytes: MAX_GOSSIP_MESSAGE_BYTES as u64,
            });
        }
        let announcement: Self = serde_json::from_slice(bytes).map_err(|error| {
            crate::error::Failure::Protocol(format!("decode head announcement: {error}"))
        })?;
        validate_head_fields(&announcement)?;
        if announcement.origin.is_some() || announcement.signature.is_some() {
            let _ = announcement.verify_signature()?;
        }
        Ok(announcement)
    }
}

fn canonical_announcement_bytes(
    announcement: &HeadAnnouncement,
    origin: iroh::EndpointId,
) -> crate::error::Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(HEAD_ANNOUNCEMENT_SIGNING_DOMAIN);
    push_len_prefixed(&mut out, announcement.vault_id.as_bytes())?;
    push_len_prefixed(&mut out, announcement.scope.as_bytes())?;
    push_len_prefixed(&mut out, announcement.head_revision.as_bytes())?;
    push_len_prefixed(
        &mut out,
        announcement.head_revision_digest.algorithm.as_bytes(),
    )?;
    push_len_prefixed(
        &mut out,
        announcement.head_revision_digest.profile.as_bytes(),
    )?;
    push_len_prefixed(
        &mut out,
        announcement.head_revision_digest.boundary.as_bytes(),
    )?;
    push_len_prefixed(&mut out, announcement.head_revision_digest.hex.as_bytes())?;
    out.extend_from_slice(&announcement.seq.to_le_bytes());
    push_len_prefixed(&mut out, announcement.bundle_hash.as_bytes())?;
    out.extend_from_slice(&announcement.bundle_bytes.to_le_bytes());
    if let Some(ts) = announcement.hlc {
        out.push(1);
        out.extend_from_slice(&ts.physical_ns.to_le_bytes());
        out.extend_from_slice(&ts.logical.to_le_bytes());
    }
    out.extend_from_slice(origin.as_bytes());
    Ok(out)
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> crate::error::Result<()> {
    let len = u32::try_from(bytes.len()).map_err(|_| {
        crate::error::Failure::Protocol("announcement field exceeds u32 length".to_owned())
    })?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Wire key identifying one `(record_id, revision_id)` in a delta metadata fetch.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct WireRevisionKey {
    pub record_id: String,
    pub revision_id: String,
}

impl WireRevisionKey {
    pub(crate) fn from_pair(
        record_id: mneme_core::RecordId,
        revision_id: mneme_core::RevisionId,
    ) -> Self {
        Self {
            record_id: record_id.to_hex(),
            revision_id: revision_id.to_hex(),
        }
    }

    pub(crate) fn to_pair(
        &self,
    ) -> crate::error::Result<(mneme_core::RecordId, mneme_core::RevisionId)> {
        let record_id = mneme_core::RecordId::from_hex(&self.record_id).map_err(|reason| {
            crate::error::Failure::Protocol(format!("invalid record id in delta request: {reason}"))
        })?;
        let revision_id =
            mneme_core::RevisionId::from_hex(&self.revision_id).map_err(|reason| {
                crate::error::Failure::Protocol(format!(
                    "invalid revision id in delta request: {reason}"
                ))
            })?;
        Ok((record_id, revision_id))
    }
}

/// Canonical serialized [`mneme_store::portability::PortableRevision`] for delta sync.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct WireDeltaRevision {
    pub envelope_b64: String,
    pub commit_revision: String,
    pub commit_sequence: u64,
    pub commit_actor: String,
    pub commit_at_ns: i64,
    #[serde(default = "no_hlc", skip_serializing_if = "Option::is_none")]
    pub commit_hlc: Option<WireHlc>,
}

impl WireDeltaRevision {
    pub(crate) fn from_portable(revision: &mneme_store::portability::PortableRevision) -> Self {
        let encoded = mneme_core::binary::encode(&revision.envelope.to_value());
        Self {
            envelope_b64: mneme_core::base64::encode(&encoded),
            commit_revision: revision.commit.revision.to_hex(),
            commit_sequence: revision.commit.sequence,
            commit_actor: revision.commit.actor.clone(),
            commit_at_ns: revision.commit.committed_at_ns,
            commit_hlc: revision.commit.hlc.map(WireHlc::from_kernel),
        }
    }

    pub(crate) fn to_portable(
        &self,
        expected_scope: &mneme_core::ScopeId,
    ) -> crate::error::Result<mneme_store::portability::PortableRevision> {
        let bytes = mneme_core::base64::decode(&self.envelope_b64).map_err(|reason| {
            crate::error::Failure::Protocol(format!("invalid delta envelope base64: {reason}"))
        })?;
        let value = mneme_core::binary::decode_canonical(&bytes).map_err(|diagnostic| {
            crate::error::Failure::Protocol(format!("invalid delta envelope binary: {diagnostic}"))
        })?;
        let registry = mneme_core::SchemaRegistry::production();
        let envelope = mneme_core::RecordEnvelope::from_value_with_registry(&value, &registry)
            .map_err(|diagnostics| {
                crate::error::Failure::Protocol(format!(
                    "invalid delta record envelope: {}",
                    mneme_core::render_diagnostics(&diagnostics)
                ))
            })?;
        mneme_core::validate_record_value(&envelope.to_value(), &registry, None).map_err(
            |diagnostics| {
                crate::error::Failure::Protocol(format!(
                    "delta record failed schema validation: {}",
                    mneme_core::render_diagnostics(&diagnostics)
                ))
            },
        )?;
        if envelope.scope != *expected_scope {
            return Err(crate::error::Failure::Protocol(format!(
                "delta revision scope {} does not match {expected_scope}",
                envelope.scope
            )));
        }
        let commit_revision = mneme_core::WorkspaceRevisionId::from_hex(&self.commit_revision)
            .map_err(|reason| {
                crate::error::Failure::Protocol(format!("invalid delta commit revision: {reason}"))
            })?;
        Ok(mneme_store::portability::PortableRevision {
            envelope,
            commit: mneme_store::RevisionCommit {
                revision: commit_revision,
                sequence: self.commit_sequence,
                actor: self.commit_actor.clone(),
                committed_at_ns: self.commit_at_ns,
                hlc: self.commit_hlc.map(WireHlc::to_kernel),
            },
        })
    }
}

const fn no_capability() -> Option<crate::capability::CapabilityToken> {
    None
}

const fn default_false() -> bool {
    false
}

const fn no_tombstone_cursor() -> Option<crate::capability::TombstoneId> {
    None
}

const fn no_limit() -> Option<u64> {
    None
}

const fn no_retention() -> Option<Box<WirePortableRetentionState>> {
    None
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub(crate) enum SyncControlRequest {
    GetVaultHead {
        scope: String,
        #[serde(default = "no_hlc", skip_serializing_if = "Option::is_none")]
        hlc: Option<WireHlc>,
        #[serde(default = "no_capability", skip_serializing_if = "Option::is_none")]
        capability: Option<crate::capability::CapabilityToken>,
    },
    RbsrReconcile {
        scope: String,
        snapshot_revision: String,
        request: crate::rbsr::RbsrRequest,
        #[serde(default = "no_hlc", skip_serializing_if = "Option::is_none")]
        hlc: Option<WireHlc>,
        #[serde(default = "no_capability", skip_serializing_if = "Option::is_none")]
        capability: Option<crate::capability::CapabilityToken>,
    },
    FetchDeltaMetadata {
        scope: String,
        snapshot_revision: String,
        revisions: Vec<WireRevisionKey>,
        blobs: Vec<String>,
        #[serde(default = "no_hlc", skip_serializing_if = "Option::is_none")]
        hlc: Option<WireHlc>,
        #[serde(default = "no_capability", skip_serializing_if = "Option::is_none")]
        capability: Option<crate::capability::CapabilityToken>,
    },
    PushHead {
        announcement: Box<HeadAnnouncement>,
        #[serde(default = "no_hlc", skip_serializing_if = "Option::is_none")]
        hlc: Option<WireHlc>,
        #[serde(default = "no_capability", skip_serializing_if = "Option::is_none")]
        capability: Option<crate::capability::CapabilityToken>,
    },
    SyncRevocations {
        revocations: Vec<crate::capability::RevocationTombstone>,
        #[serde(
            default = "no_tombstone_cursor",
            skip_serializing_if = "Option::is_none"
        )]
        after_id: Option<crate::capability::TombstoneId>,
        #[serde(default = "no_limit", skip_serializing_if = "Option::is_none")]
        limit: Option<u64>,
        #[serde(default = "no_hlc", skip_serializing_if = "Option::is_none")]
        hlc: Option<WireHlc>,
        #[serde(default = "no_capability", skip_serializing_if = "Option::is_none")]
        capability: Option<crate::capability::CapabilityToken>,
    },
}

impl SyncControlRequest {
    fn capability(&self) -> Option<&crate::capability::CapabilityToken> {
        match self {
            SyncControlRequest::GetVaultHead { capability, .. }
            | SyncControlRequest::RbsrReconcile { capability, .. }
            | SyncControlRequest::FetchDeltaMetadata { capability, .. }
            | SyncControlRequest::PushHead { capability, .. }
            | SyncControlRequest::SyncRevocations { capability, .. } => capability.as_ref(),
        }
    }

    fn sender_hlc(&self) -> Option<WireHlc> {
        match self {
            SyncControlRequest::GetVaultHead { hlc, .. }
            | SyncControlRequest::RbsrReconcile { hlc, .. }
            | SyncControlRequest::FetchDeltaMetadata { hlc, .. }
            | SyncControlRequest::SyncRevocations { hlc, .. } => *hlc,
            SyncControlRequest::PushHead {
                announcement, hlc, ..
            } => hlc.or(announcement.hlc),
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub(crate) enum SyncControlResponse {
    VaultHead(Box<VaultSnapshotInfo>),
    RbsrReply(crate::rbsr::RbsrResponse),
    DeltaMetadata {
        revisions: Vec<WireDeltaRevision>,
        blobs: Vec<BlobDigestRef>,
        #[serde(default = "no_retention", skip_serializing_if = "Option::is_none")]
        retention: Option<Box<WirePortableRetentionState>>,
        #[serde(default = "no_hlc", skip_serializing_if = "Option::is_none")]
        hlc: Option<WireHlc>,
    },
    HeadAccepted {
        vault_id: String,
        scope: String,
        seq: u64,
        #[serde(default = "no_hlc", skip_serializing_if = "Option::is_none")]
        hlc: Option<WireHlc>,
    },
    Revocations {
        revocations: Vec<crate::capability::RevocationTombstone>,
        #[serde(default = "default_false")]
        has_more: bool,
        #[serde(
            default = "no_tombstone_cursor",
            skip_serializing_if = "Option::is_none"
        )]
        next_cursor: Option<crate::capability::TombstoneId>,
        #[serde(default = "no_hlc", skip_serializing_if = "Option::is_none")]
        hlc: Option<WireHlc>,
    },
    Refused {
        reason: String,
    },
    CapabilityDenied {
        reason: String,
    },
    CapabilityRevoked {
        token_id: String,
        reason: String,
    },
}

impl SyncControlResponse {
    pub(crate) fn sender_hlc(&self) -> Option<WireHlc> {
        match self {
            SyncControlResponse::VaultHead(info) => info.hlc,
            SyncControlResponse::DeltaMetadata { hlc, .. }
            | SyncControlResponse::HeadAccepted { hlc, .. }
            | SyncControlResponse::Revocations { hlc, .. } => *hlc,
            SyncControlResponse::RbsrReply(_)
            | SyncControlResponse::Refused { .. }
            | SyncControlResponse::CapabilityDenied { .. }
            | SyncControlResponse::CapabilityRevoked { .. } => None,
        }
    }
}

/// Protocol handler wrapper enforcing the deny-by-default Ed25519 allowlist.
#[derive(Clone, Debug)]
pub struct AllowlistedProtocol<P> {
    allowlist: crate::trust::SharedAllowlist,
    inner: P,
}

impl<P> AllowlistedProtocol<P> {
    /// Wrap `inner` so only peers present in `allowlist` are accepted.
    pub const fn new(allowlist: crate::trust::SharedAllowlist, inner: P) -> Self {
        Self { allowlist, inner }
    }
}

impl<P: iroh::protocol::ProtocolHandler> iroh::protocol::ProtocolHandler
    for AllowlistedProtocol<P>
{
    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> std::result::Result<(), iroh::protocol::AcceptError> {
        let remote = connection.remote_id();
        if !self.allowlist.is_allowed(remote) {
            connection.close(
                iroh::endpoint::VarInt::from_u32(UNAUTHORIZED_CLOSE_CODE),
                b"peer not allowlisted",
            );
            return Err(iroh::protocol::AcceptError::from_err(
                crate::error::Failure::UnauthorizedPeer(remote.to_string()),
            ));
        }
        self.inner.accept(connection).await
    }

    async fn shutdown(&self) {
        self.inner.shutdown().await;
    }
}

/// Published scope state shared between `SyncNode` and `/mneme/sync/1`.
#[derive(Clone, Debug)]
pub(crate) struct PublishedScopeEntry {
    pub info: VaultSnapshotInfo,
    pub rbsr_set: crate::rbsr::RbsrSet,
    pub revisions: std::collections::BTreeMap<
        (mneme_core::RecordId, mneme_core::RevisionId),
        mneme_store::portability::PortableRevision,
    >,
    pub blobs_by_digest: std::collections::BTreeMap<[u8; 32], BlobDigestRef>,
    pub retention: mneme_store::portability::PortableRetentionState,
    pub authorized_hashes: std::collections::BTreeSet<iroh_blobs::Hash>,
}

/// Shared authorization bundle for capability-enforced ALPN handlers.
#[derive(Clone)]
pub(crate) struct CapabilityAuthorizer {
    pub(crate) allowlist: crate::trust::SharedAllowlist,
    pub(crate) leases: crate::capability::SharedCapabilityLeases,
    pub(crate) trusted_roots: std::collections::BTreeSet<iroh::EndpointId>,
    pub(crate) revocations: crate::capability::SharedRevocationSet,
    pub(crate) authorized_issuers: crate::capability::SharedAuthorizedIssuers,
    pub(crate) scopes: SharedScopeTable,
    pub(crate) clock: std::sync::Arc<dyn mneme_store::Clock>,
}

impl CapabilityAuthorizer {
    pub(crate) fn configured_vaults(&self) -> std::collections::BTreeSet<String> {
        let Ok(guard) = self.scopes.read() else {
            return std::collections::BTreeSet::new();
        };
        guard.configured_vaults.clone()
    }

    pub(crate) fn is_configured_vault(&self, vault_id: &str) -> bool {
        self.scopes
            .read()
            .map(|guard| guard.configured_vaults.contains(vault_id))
            .unwrap_or(false)
    }

    pub(crate) fn effective_revokers(&self) -> std::collections::BTreeSet<iroh::EndpointId> {
        self.authorized_issuers
            .effective_revokers(&self.trusted_roots, &self.allowlist)
    }

    pub(crate) fn evict_inactive_leases(&self) {
        if let Ok(now_secs) = crate::capability::timestamp_to_epoch_secs(self.clock.now()) {
            let _evicted = self
                .leases
                .evict_inactive(&crate::capability::LeaseEvictionContext {
                    now_secs,
                    trusted_roots: &self.trusted_roots,
                    revocations: &self.revocations,
                })
                .is_ok();
        }
    }

    pub(crate) fn permits_connection(
        &self,
        remote: iroh::EndpointId,
        required: crate::capability::CapabilityAuthority,
    ) -> bool {
        if self.allowlist.is_allowed(remote) {
            return true;
        }
        let Ok(now_secs) = crate::capability::timestamp_to_epoch_secs(self.clock.now()) else {
            return false;
        };
        let configured = self.configured_vaults();
        self.leases.permits_any_vault_authority(
            remote,
            &configured,
            required,
            &crate::capability::LeaseEvictionContext {
                now_secs,
                trusted_roots: &self.trusted_roots,
                revocations: &self.revocations,
            },
        )
    }

    pub(crate) fn has_any_active_lease(&self, remote: iroh::EndpointId) -> bool {
        self.permits_connection(remote, crate::capability::CapabilityAuthority::ReadOnly)
    }

    pub(crate) fn permits_vault_scope(
        &self,
        remote: iroh::EndpointId,
        vault_id: &str,
        scope: &mneme_core::ScopeId,
        required: crate::capability::CapabilityAuthority,
    ) -> bool {
        if self.allowlist.is_allowed(remote) {
            return self.allowlist.allows_scope(remote, scope);
        }
        let Ok(now_secs) = crate::capability::timestamp_to_epoch_secs(self.clock.now()) else {
            return false;
        };
        self.leases
            .permits_vault_scope(&crate::capability::LeaseVaultScopeQuery {
                peer: remote,
                vault_id,
                scope,
                required,
                now_secs,
                trusted_roots: &self.trusted_roots,
                revocations: &self.revocations,
            })
    }

    pub(crate) fn permits_blob_hash(
        &self,
        remote: iroh::EndpointId,
        hash: iroh_blobs::Hash,
    ) -> bool {
        let Ok(guard) = self.scopes.read() else {
            return false;
        };
        for (scope, entry) in &guard.published {
            if entry.authorized_hashes.contains(&hash)
                && self.permits_vault_scope(
                    remote,
                    &entry.info.vault_id,
                    scope,
                    crate::capability::CapabilityAuthority::SyncPull,
                )
            {
                return true;
            }
        }
        false
    }
}

/// Spawn a scope-isolating `iroh-blobs` event interceptor that enforces
/// `(peer, vault_id, scope, SyncPull)` per requested hash and refuses `HashSeq`/push/observe.
pub(crate) fn spawn_scoped_blobs_events(
    auth: CapabilityAuthorizer,
) -> iroh_blobs::provider::events::EventSender {
    let mask = iroh_blobs::provider::events::EventMask {
        connected: iroh_blobs::provider::events::ConnectMode::Intercept,
        get: iroh_blobs::provider::events::RequestMode::Intercept,
        get_many: iroh_blobs::provider::events::RequestMode::Disabled,
        push: iroh_blobs::provider::events::RequestMode::Disabled,
        observe: iroh_blobs::provider::events::ObserveMode::Disabled,
        throttle: iroh_blobs::provider::events::ThrottleMode::None,
    };
    let (sender, mut receiver) = iroh_blobs::provider::events::EventSender::channel(128, mask);
    let task = tokio::task::spawn(async move {
        let mut connections: std::collections::BTreeMap<u64, iroh::EndpointId> =
            std::collections::BTreeMap::new();
        while let Some(message) = receiver.recv().await {
            handle_blob_provider_event(&auth, &mut connections, message).await;
        }
    });
    drop(task);
    sender
}

async fn handle_blob_provider_event(
    auth: &CapabilityAuthorizer,
    connections: &mut std::collections::BTreeMap<u64, iroh::EndpointId>,
    message: iroh_blobs::provider::events::ProviderMessage,
) {
    match message {
        iroh_blobs::provider::events::ProviderMessage::ClientConnected(msg) => {
            let decision = match msg.inner.endpoint_id {
                Some(remote)
                    if auth.permits_connection(
                        remote,
                        crate::capability::CapabilityAuthority::SyncPull,
                    ) =>
                {
                    connections.insert(msg.inner.connection_id, remote);
                    Ok(())
                }
                Some(_) | None => Err(iroh_blobs::provider::events::AbortReason::Permission),
            };
            let _sent = msg.tx.send(decision).await.is_ok();
        }
        iroh_blobs::provider::events::ProviderMessage::ConnectionClosed(msg) => {
            connections.remove(&msg.inner.connection_id);
        }
        iroh_blobs::provider::events::ProviderMessage::GetRequestReceived(msg) => {
            let decision = if !msg.inner.request.ranges.is_blob() {
                Err(iroh_blobs::provider::events::AbortReason::Permission)
            } else if let Some(&remote) = connections.get(&msg.inner.connection_id)
                && auth.permits_blob_hash(remote, msg.inner.request.hash)
            {
                Ok(())
            } else {
                Err(iroh_blobs::provider::events::AbortReason::Permission)
            };
            let _sent = msg.tx.send(decision).await.is_ok();
        }
        iroh_blobs::provider::events::ProviderMessage::GetManyRequestReceived(msg) => {
            let _sent = msg
                .tx
                .send(Err(iroh_blobs::provider::events::AbortReason::Permission))
                .await
                .is_ok();
        }
        iroh_blobs::provider::events::ProviderMessage::PushRequestReceived(msg) => {
            let _sent = msg
                .tx
                .send(Err(iroh_blobs::provider::events::AbortReason::Permission))
                .await
                .is_ok();
        }
        iroh_blobs::provider::events::ProviderMessage::ObserveRequestReceived(msg) => {
            let _sent = msg
                .tx
                .send(Err(iroh_blobs::provider::events::AbortReason::Permission))
                .await
                .is_ok();
        }
        iroh_blobs::provider::events::ProviderMessage::Throttle(msg) => {
            let _sent = msg.tx.send(Ok(())).await.is_ok();
        }
        iroh_blobs::provider::events::ProviderMessage::ClientConnectedNotify(_)
        | iroh_blobs::provider::events::ProviderMessage::GetRequestReceivedNotify(_)
        | iroh_blobs::provider::events::ProviderMessage::GetManyRequestReceivedNotify(_)
        | iroh_blobs::provider::events::ProviderMessage::PushRequestReceivedNotify(_)
        | iroh_blobs::provider::events::ProviderMessage::ObserveRequestReceivedNotify(_) => {}
    }
}

/// Protocol handler wrapper enforcing allowlist OR active vault-bound capability lease + concurrency bound.
#[derive(Clone)]
pub(crate) struct CapabilityProtocol<P> {
    auth: CapabilityAuthorizer,
    required_authority: crate::capability::CapabilityAuthority,
    connection_limit: std::sync::Arc<tokio::sync::Semaphore>,
    inner: P,
}

impl<P> std::fmt::Debug for CapabilityProtocol<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapabilityProtocol")
            .field("required_authority", &self.required_authority)
            .finish()
    }
}

const MAX_CONCURRENT_TRANSPORT_SEMAPHORE: usize = 64;
const MAX_CONCURRENT_CONTROL_SEMAPHORE: usize = 64;
const MAX_UNAUTH_CONTROL_FRAME_BYTES: usize = 128 * 1024;

impl<P> CapabilityProtocol<P> {
    pub(crate) fn new(
        auth: CapabilityAuthorizer,
        required_authority: crate::capability::CapabilityAuthority,
        inner: P,
    ) -> Self {
        Self {
            auth,
            required_authority,
            connection_limit: std::sync::Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_TRANSPORT_SEMAPHORE,
            )),
            inner,
        }
    }
}

impl<P: iroh::protocol::ProtocolHandler> iroh::protocol::ProtocolHandler for CapabilityProtocol<P> {
    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> std::result::Result<(), iroh::protocol::AcceptError> {
        let remote = connection.remote_id();
        if !self
            .auth
            .permits_connection(remote, self.required_authority)
        {
            connection.close(
                iroh::endpoint::VarInt::from_u32(UNAUTHORIZED_CLOSE_CODE),
                b"peer not authorized",
            );
            return Err(iroh::protocol::AcceptError::from_err(
                crate::error::Failure::UnauthorizedPeer(remote.to_string()),
            ));
        }
        let Ok(_permit) = std::sync::Arc::clone(&self.connection_limit).try_acquire_owned() else {
            connection.close(
                iroh::endpoint::VarInt::from_u32(RATE_LIMITED_CLOSE_CODE),
                b"connection capacity exceeded",
            );
            return Err(iroh::protocol::AcceptError::from_err(
                crate::error::Failure::Transport("connection capacity exceeded".to_owned()),
            ));
        };
        self.inner.accept(connection).await
    }

    async fn shutdown(&self) {
        self.inner.shutdown().await;
    }
}

/// Served scopes, configured vaults, and monotonic push watermarks shared between `SyncNode` and `SyncControlHandler`.
#[derive(Debug)]
pub(crate) struct SyncScopeTable {
    pub(crate) configured_vaults: std::collections::BTreeSet<String>,
    pub(crate) published:
        std::collections::BTreeMap<mneme_core::ScopeId, std::sync::Arc<PublishedScopeEntry>>,
    pub(crate) received_pushes: std::collections::BTreeMap<mneme_core::ScopeId, HeadAnnouncement>,
    pub(crate) push_high_water:
        std::collections::BTreeMap<(String, mneme_core::ScopeId, iroh::EndpointId), u64>,
}

impl SyncScopeTable {
    pub(crate) const fn new() -> Self {
        Self {
            configured_vaults: std::collections::BTreeSet::new(),
            published: std::collections::BTreeMap::new(),
            received_pushes: std::collections::BTreeMap::new(),
            push_high_water: std::collections::BTreeMap::new(),
        }
    }
}

pub(crate) type SharedScopeTable = std::sync::Arc<std::sync::RwLock<SyncScopeTable>>;

/// Protocol handler for [`SYNC_CONTROL_ALPN`].
#[derive(Clone)]
pub(crate) struct SyncControlHandler {
    auth: CapabilityAuthorizer,
    scopes: SharedScopeTable,
    hlc: SharedSyncHlc,
    connection_limit: std::sync::Arc<tokio::sync::Semaphore>,
}

impl std::fmt::Debug for SyncControlHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncControlHandler").finish()
    }
}

impl SyncControlHandler {
    pub(crate) fn new(
        auth: CapabilityAuthorizer,
        scopes: SharedScopeTable,
        hlc: SharedSyncHlc,
    ) -> Self {
        Self {
            auth,
            scopes,
            hlc,
            connection_limit: std::sync::Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_CONTROL_SEMAPHORE,
            )),
        }
    }

    fn lookup_authorized_scope(
        &self,
        remote: iroh::EndpointId,
        scope: &str,
        capability: Option<&crate::capability::CapabilityToken>,
        required_authority: crate::capability::CapabilityAuthority,
    ) -> std::result::Result<std::sync::Arc<PublishedScopeEntry>, SyncControlResponse> {
        let Ok(parsed_scope) = parse_scope_id(scope) else {
            return Err(SyncControlResponse::Refused {
                reason: format!("invalid scope '{scope}'"),
            });
        };
        let entry = {
            let Ok(guard) = self.scopes.read() else {
                return Err(SyncControlResponse::Refused {
                    reason: "published scope table unavailable".to_owned(),
                });
            };
            match guard.published.get(&parsed_scope) {
                Some(entry) => std::sync::Arc::clone(entry),
                None => {
                    return Err(SyncControlResponse::Refused {
                        reason: format!("scope {scope} is not served by this node"),
                    });
                }
            }
        };
        if self.auth.allowlist.is_allowed(remote) {
            if !self.auth.allowlist.allows_scope(remote, &parsed_scope) {
                return Err(SyncControlResponse::Refused {
                    reason: format!("peer is not authorized for scope {scope}"),
                });
            }
            return Ok(entry);
        }
        let Some(token) = capability else {
            return Err(SyncControlResponse::Refused {
                reason: "peer not allowlisted and no capability provided".to_owned(),
            });
        };
        self.verify_and_record(
            token,
            remote,
            &entry.info.vault_id,
            &parsed_scope,
            required_authority,
        )?;
        Ok(entry)
    }

    fn resolve_request(
        &self,
        remote: iroh::EndpointId,
        request: &SyncControlRequest,
    ) -> SyncControlResponse {
        if let Some(remote_hlc) = request.sender_hlc()
            && let Err(error) = self.hlc.observe(remote_hlc)
        {
            return SyncControlResponse::Refused {
                reason: error.to_string(),
            };
        }
        match request {
            SyncControlRequest::GetVaultHead {
                scope, capability, ..
            } => self.handle_get_vault_head(remote, scope, capability.as_ref()),
            SyncControlRequest::RbsrReconcile {
                scope,
                snapshot_revision,
                request,
                capability,
                ..
            } => self.handle_rbsr_reconcile(RbsrReconcileInput {
                remote,
                scope,
                snapshot_revision,
                request,
                capability: capability.as_ref(),
            }),
            SyncControlRequest::FetchDeltaMetadata {
                scope,
                snapshot_revision,
                revisions,
                blobs,
                capability,
                ..
            } => self.handle_fetch_delta_metadata(FetchDeltaMetadataInput {
                remote,
                scope,
                snapshot_revision,
                revisions,
                blobs,
                capability: capability.as_ref(),
            }),
            SyncControlRequest::PushHead {
                announcement,
                capability,
                ..
            } => self.handle_push_head(remote, announcement, capability.as_ref()),
            SyncControlRequest::SyncRevocations {
                revocations,
                after_id,
                limit,
                capability,
                ..
            } => self.handle_sync_revocations(
                remote,
                revocations,
                *after_id,
                *limit,
                capability.as_ref(),
            ),
        }
    }

    fn handle_get_vault_head(
        &self,
        remote: iroh::EndpointId,
        scope: &str,
        capability: Option<&crate::capability::CapabilityToken>,
    ) -> SyncControlResponse {
        let entry = match self.lookup_authorized_scope(
            remote,
            scope,
            capability,
            crate::capability::CapabilityAuthority::ReadOnly,
        ) {
            Ok(entry) => entry,
            Err(refused) => return refused,
        };
        // Keep GetVaultHead O(1): omit full N-blob lists on the wire;
        // peers discover missing blobs via RBSR on /mneme/sync/1.
        let mut summary = entry.info.clone();
        summary.blobs.clear();
        if let Ok(ts) = self.hlc.tick() {
            summary.hlc = Some(ts);
        }
        SyncControlResponse::VaultHead(Box::new(summary))
    }

    fn handle_rbsr_reconcile(&self, input: RbsrReconcileInput<'_>) -> SyncControlResponse {
        let entry = match self.lookup_authorized_scope(
            input.remote,
            input.scope,
            input.capability,
            crate::capability::CapabilityAuthority::SyncPull,
        ) {
            Ok(entry) => entry,
            Err(refused) => return refused,
        };
        if entry.info.head_revision != input.snapshot_revision {
            return SyncControlResponse::Refused {
                reason: format!(
                    "snapshot revision {} is stale (current {})",
                    input.snapshot_revision, entry.info.head_revision
                ),
            };
        }
        match entry.rbsr_set.evaluate_request(input.request) {
            Ok(reply) => SyncControlResponse::RbsrReply(reply),
            Err(error) => SyncControlResponse::Refused {
                reason: format!("RBSR request refused: {error}"),
            },
        }
    }

    fn handle_fetch_delta_metadata(
        &self,
        input: FetchDeltaMetadataInput<'_>,
    ) -> SyncControlResponse {
        let entry = match self.lookup_authorized_scope(
            input.remote,
            input.scope,
            input.capability,
            crate::capability::CapabilityAuthority::SyncPull,
        ) {
            Ok(entry) => entry,
            Err(refused) => return refused,
        };
        if entry.info.head_revision != input.snapshot_revision {
            return SyncControlResponse::Refused {
                reason: format!(
                    "snapshot revision {} is stale (current {})",
                    input.snapshot_revision, entry.info.head_revision
                ),
            };
        }
        resolve_delta_metadata(&entry, input.revisions, input.blobs, self.hlc.tick().ok())
    }

    fn authorize_push_head(
        &self,
        remote: iroh::EndpointId,
        announcement: &HeadAnnouncement,
        parsed_scope: &mneme_core::ScopeId,
        capability: Option<&crate::capability::CapabilityToken>,
    ) -> std::result::Result<iroh::EndpointId, SyncControlResponse> {
        let origin = announcement.verify_signature().map_err(|error| {
            SyncControlResponse::CapabilityDenied {
                reason: error.to_string(),
            }
        })?;
        if origin != remote {
            return Err(SyncControlResponse::CapabilityDenied {
                reason: format!(
                    "head announcement origin {origin} does not match remote peer {remote}"
                ),
            });
        }
        if !self.auth.is_configured_vault(&announcement.vault_id) {
            return Err(SyncControlResponse::CapabilityDenied {
                reason: format!(
                    "vault '{}' is not configured on this sync node",
                    announcement.vault_id
                ),
            });
        }
        if self.auth.allowlist.is_allowed(remote) {
            if !self.auth.allowlist.allows_scope(remote, parsed_scope) {
                return Err(SyncControlResponse::Refused {
                    reason: format!("peer is not authorized for scope {}", announcement.scope),
                });
            }
            return Ok(origin);
        }
        let Some(token) = capability else {
            return Err(SyncControlResponse::Refused {
                reason: "peer not allowlisted and no capability provided".to_owned(),
            });
        };
        self.verify_and_record(
            token,
            remote,
            &announcement.vault_id,
            parsed_scope,
            crate::capability::CapabilityAuthority::SyncPush,
        )?;
        Ok(origin)
    }

    fn handle_push_head(
        &self,
        remote: iroh::EndpointId,
        announcement: &HeadAnnouncement,
        capability: Option<&crate::capability::CapabilityToken>,
    ) -> SyncControlResponse {
        let Ok(parsed_scope) = parse_scope_id(&announcement.scope) else {
            return SyncControlResponse::Refused {
                reason: format!("invalid scope '{}'", announcement.scope),
            };
        };
        if validate_head_fields(announcement).is_err() {
            return SyncControlResponse::Refused {
                reason: "invalid head announcement payload".to_owned(),
            };
        }
        let origin = match self.authorize_push_head(remote, announcement, &parsed_scope, capability)
        {
            Ok(origin) => origin,
            Err(response) => return response,
        };
        let Ok(mut guard) = self.scopes.write() else {
            return SyncControlResponse::Refused {
                reason: "published scope table unavailable".to_owned(),
            };
        };
        let key = (announcement.vault_id.clone(), parsed_scope.clone(), origin);
        if let Some(&high_water) = guard.push_high_water.get(&key)
            && announcement.seq <= high_water
        {
            return SyncControlResponse::Refused {
                reason: format!(
                    "stale or rollback head push seq {} (high-water {})",
                    announcement.seq, high_water
                ),
            };
        }
        guard.push_high_water.insert(key, announcement.seq);
        guard
            .received_pushes
            .insert(parsed_scope, announcement.clone());
        SyncControlResponse::HeadAccepted {
            vault_id: announcement.vault_id.clone(),
            scope: announcement.scope.clone(),
            seq: announcement.seq,
            hlc: self.hlc.tick().ok(),
        }
    }

    fn handle_sync_revocations(
        &self,
        remote: iroh::EndpointId,
        incoming: &[crate::capability::RevocationTombstone],
        after_id: Option<crate::capability::TombstoneId>,
        limit: Option<u64>,
        capability: Option<&crate::capability::CapabilityToken>,
    ) -> SyncControlResponse {
        if incoming.len() as u64 > crate::capability::MAX_REVOCATIONS_PER_PAGE {
            return SyncControlResponse::Refused {
                reason: format!(
                    "revocation push batch {} exceeds page bound {}",
                    incoming.len(),
                    crate::capability::MAX_REVOCATIONS_PER_PAGE
                ),
            };
        }
        if !self.auth.allowlist.is_allowed(remote) {
            let Some(token) = capability else {
                return SyncControlResponse::Refused {
                    reason: "peer not allowlisted and no capability provided".to_owned(),
                };
            };
            if let Err(response) = self.verify_any_scope_read(token, remote) {
                return response;
            }
        }
        let authorized_revokers = self.auth.effective_revokers();
        if let Err(error) = self
            .auth
            .revocations
            .merge_tombstones_authorized(incoming, &authorized_revokers)
        {
            return SyncControlResponse::CapabilityDenied {
                reason: error.to_string(),
            };
        }
        self.auth.evict_inactive_leases();
        let page_limit = limit
            .unwrap_or(crate::capability::MAX_REVOCATIONS_PER_PAGE)
            .clamp(1, crate::capability::MAX_REVOCATIONS_PER_PAGE);
        let Ok((page, has_more)) = self.auth.revocations.page_after(after_id, page_limit) else {
            return SyncControlResponse::Refused {
                reason: "revocation set unavailable".to_owned(),
            };
        };
        let next_cursor = if has_more {
            page.last().map(|tombstone| tombstone.tombstone_id)
        } else {
            None
        };
        SyncControlResponse::Revocations {
            revocations: page,
            has_more,
            next_cursor,
            hlc: self.hlc.tick().ok(),
        }
    }

    fn verify_and_record(
        &self,
        token: &crate::capability::CapabilityToken,
        remote: iroh::EndpointId,
        vault_id: &str,
        scope: &mneme_core::ScopeId,
        required_authority: crate::capability::CapabilityAuthority,
    ) -> std::result::Result<(), SyncControlResponse> {
        let now_secs =
            crate::capability::timestamp_to_epoch_secs(self.auth.clock.now()).map_err(|error| {
                SyncControlResponse::CapabilityDenied {
                    reason: error.to_string(),
                }
            })?;
        let rev_snapshot =
            self.auth
                .revocations
                .snapshot()
                .map_err(|error| SyncControlResponse::Refused {
                    reason: error.to_string(),
                })?;
        let verified =
            crate::capability::verify_capability(&crate::capability::VerificationRequest {
                token,
                presenter: remote,
                vault_id,
                scope,
                required_authority,
                now_secs,
                trusted_roots: &self.auth.trusted_roots,
                revocations: &rev_snapshot,
            })
            .map_err(map_capability_failure)?;
        self.auth.authorized_issuers.record_verified(&verified);
        self.auth
            .leases
            .record_lease_with_eviction(
                remote,
                vault_id,
                &verified,
                &crate::capability::LeaseEvictionContext {
                    now_secs,
                    trusted_roots: &self.auth.trusted_roots,
                    revocations: &self.auth.revocations,
                },
            )
            .map_err(|error| SyncControlResponse::Refused {
                reason: error.to_string(),
            })?;
        Ok(())
    }

    fn verify_any_scope_read(
        &self,
        token: &crate::capability::CapabilityToken,
        remote: iroh::EndpointId,
    ) -> std::result::Result<(), SyncControlResponse> {
        let Some(leaf) = token.leaf() else {
            return Err(SyncControlResponse::CapabilityDenied {
                reason: "capability token has no leaf link".to_owned(),
            });
        };
        if !self.auth.is_configured_vault(&leaf.vault_id) {
            return Err(SyncControlResponse::CapabilityDenied {
                reason: format!(
                    "capability vault '{}' is not configured on this sync node",
                    leaf.vault_id
                ),
            });
        }
        let scope = match &leaf.scope {
            crate::capability::CapabilityScope::Wildcard => {
                mneme_core::ScopeId::new(mneme_core::ScopeClass::Workspace, "default").map_err(
                    |reason| SyncControlResponse::CapabilityDenied {
                        reason: reason.to_owned(),
                    },
                )?
            }
            crate::capability::CapabilityScope::Scopes(scopes) => {
                let Some(first) = scopes.iter().next() else {
                    return Err(SyncControlResponse::CapabilityDenied {
                        reason: "capability scope set cannot be empty".to_owned(),
                    });
                };
                parse_scope_id(first).map_err(|error| SyncControlResponse::CapabilityDenied {
                    reason: error.to_string(),
                })?
            }
        };
        self.verify_and_record(
            token,
            remote,
            &leaf.vault_id,
            &scope,
            crate::capability::CapabilityAuthority::ReadOnly,
        )
    }
}

fn validate_head_fields(announcement: &HeadAnnouncement) -> crate::error::Result<()> {
    let _ = parse_scope_id(&announcement.scope)?;
    let _ = mneme_core::WorkspaceRevisionId::from_hex(&announcement.head_revision).map_err(
        |reason| crate::error::Failure::Protocol(format!("invalid head revision: {reason}")),
    )?;
    let _ = announcement.head_revision_digest.to_digest()?;
    let _ = iroh_blobs::Hash::from_str(&announcement.bundle_hash).map_err(|error| {
        crate::error::Failure::Protocol(format!("invalid announcement bundle hash: {error}"))
    })?;
    Ok(())
}

fn map_capability_failure(error: crate::error::Failure) -> SyncControlResponse {
    match error {
        crate::error::Failure::CapabilityRevoked { token_id, reason } => {
            SyncControlResponse::CapabilityRevoked { token_id, reason }
        }
        other => SyncControlResponse::CapabilityDenied {
            reason: other.to_string(),
        },
    }
}

struct RbsrReconcileInput<'a> {
    remote: iroh::EndpointId,
    scope: &'a str,
    snapshot_revision: &'a str,
    request: &'a crate::rbsr::RbsrRequest,
    capability: Option<&'a crate::capability::CapabilityToken>,
}

struct FetchDeltaMetadataInput<'a> {
    remote: iroh::EndpointId,
    scope: &'a str,
    snapshot_revision: &'a str,
    revisions: &'a [WireRevisionKey],
    blobs: &'a [String],
    capability: Option<&'a crate::capability::CapabilityToken>,
}

fn resolve_delta_metadata(
    entry: &PublishedScopeEntry,
    revision_keys: &[WireRevisionKey],
    blob_hexes: &[String],
    hlc: Option<WireHlc>,
) -> SyncControlResponse {
    if revision_keys.len() as u64 > MAX_DELTA_ITEMS_PER_REQUEST
        || blob_hexes.len() as u64 > MAX_DELTA_ITEMS_PER_REQUEST
    {
        return SyncControlResponse::Refused {
            reason: format!("delta metadata request exceeds {MAX_DELTA_ITEMS_PER_REQUEST} items"),
        };
    }

    let mut out_revisions = Vec::with_capacity(revision_keys.len());
    for wire_key in revision_keys {
        let Ok(pair) = wire_key.to_pair() else {
            return SyncControlResponse::Refused {
                reason: "invalid revision key in delta request".to_owned(),
            };
        };
        let Some(revision) = entry.revisions.get(&pair) else {
            return SyncControlResponse::Refused {
                reason: format!("requested revision {} is not present", wire_key.revision_id),
            };
        };
        out_revisions.push(WireDeltaRevision::from_portable(revision));
    }

    let mut out_blobs = Vec::with_capacity(blob_hexes.len());
    for hex in blob_hexes {
        let Ok(digest_bytes) = decode_hex_32(hex) else {
            return SyncControlResponse::Refused {
                reason: format!("invalid blob digest hex '{hex}'"),
            };
        };
        let Some(blob_ref) = entry.blobs_by_digest.get(&digest_bytes) else {
            return SyncControlResponse::Refused {
                reason: format!("requested blob {hex} is not present"),
            };
        };
        out_blobs.push(blob_ref.clone());
    }

    SyncControlResponse::DeltaMetadata {
        revisions: out_revisions,
        blobs: out_blobs,
        retention: Some(Box::new(WirePortableRetentionState::from_portable(
            &entry.retention,
        ))),
        hlc,
    }
}

impl SyncControlHandler {
    async fn read_control_frame(
        &self,
        connection: &iroh::endpoint::Connection,
        remote: iroh::EndpointId,
        recv: &mut iroh::endpoint::RecvStream,
        stream_timeout: std::time::Duration,
    ) -> std::result::Result<Vec<u8>, iroh::protocol::AcceptError> {
        let is_pre_authenticated =
            self.auth.allowlist.is_allowed(remote) || self.auth.has_any_active_lease(remote);
        let read_limit = if is_pre_authenticated {
            MAX_CONTROL_MESSAGE_BYTES
        } else {
            MAX_UNAUTH_CONTROL_FRAME_BYTES
        };
        match tokio::time::timeout(stream_timeout, recv.read_to_end(read_limit)).await {
            Ok(Ok(bytes)) => Ok(bytes),
            Ok(Err(error)) => {
                if !is_pre_authenticated {
                    connection.close(
                        iroh::endpoint::VarInt::from_u32(UNAUTHORIZED_CLOSE_CODE),
                        b"unauthenticated control frame rejected",
                    );
                }
                Err(iroh::protocol::AcceptError::from_err(error))
            }
            Err(_) => {
                connection.close(
                    iroh::endpoint::VarInt::from_u32(RATE_LIMITED_CLOSE_CODE),
                    b"control stream read timeout",
                );
                Err(iroh::protocol::AcceptError::from_err(
                    crate::error::Failure::Transport("control stream read timeout".to_owned()),
                ))
            }
        }
    }

    async fn handle_control_stream(
        &self,
        connection: &iroh::endpoint::Connection,
        remote: iroh::EndpointId,
        mut send: iroh::endpoint::SendStream,
        mut recv: iroh::endpoint::RecvStream,
    ) -> std::result::Result<bool, iroh::protocol::AcceptError> {
        let stream_timeout = std::time::Duration::from_secs(CONTROL_STREAM_TIMEOUT_SECS);
        let request_bytes = self
            .read_control_frame(connection, remote, &mut recv, stream_timeout)
            .await?;
        let request: SyncControlRequest = match serde_json::from_slice(&request_bytes) {
            Ok(req) => req,
            Err(error) => {
                if !self.auth.allowlist.is_allowed(remote) {
                    connection.close(
                        iroh::endpoint::VarInt::from_u32(UNAUTHORIZED_CLOSE_CODE),
                        b"peer not allowlisted",
                    );
                    return Err(iroh::protocol::AcceptError::from_err(
                        crate::error::Failure::UnauthorizedPeer(remote.to_string()),
                    ));
                }
                let response = SyncControlResponse::Refused {
                    reason: format!("invalid control request: {error}"),
                };
                write_control_response(&mut send, &response, stream_timeout).await?;
                return Ok(false);
            }
        };
        if !self.auth.allowlist.is_allowed(remote) && request.capability().is_none() {
            connection.close(
                iroh::endpoint::VarInt::from_u32(UNAUTHORIZED_CLOSE_CODE),
                b"peer not allowlisted",
            );
            return Err(iroh::protocol::AcceptError::from_err(
                crate::error::Failure::UnauthorizedPeer(remote.to_string()),
            ));
        }
        let response = self.resolve_request(remote, &request);
        let should_close_after = !self.auth.allowlist.is_allowed(remote)
            && matches!(
                response,
                SyncControlResponse::CapabilityDenied { .. }
                    | SyncControlResponse::CapabilityRevoked { .. }
            );
        write_control_response(&mut send, &response, stream_timeout).await?;
        if should_close_after {
            let _stopped =
                tokio::time::timeout(std::time::Duration::from_millis(500), send.stopped())
                    .await
                    .is_ok();
        }
        Ok(should_close_after)
    }
}

impl iroh::protocol::ProtocolHandler for SyncControlHandler {
    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> std::result::Result<(), iroh::protocol::AcceptError> {
        let remote = connection.remote_id();
        let is_allowlisted = self.auth.allowlist.is_allowed(remote);
        if !is_allowlisted && self.auth.trusted_roots.is_empty() {
            connection.close(
                iroh::endpoint::VarInt::from_u32(UNAUTHORIZED_CLOSE_CODE),
                b"peer not allowlisted",
            );
            return Err(iroh::protocol::AcceptError::from_err(
                crate::error::Failure::UnauthorizedPeer(remote.to_string()),
            ));
        }
        let Ok(_permit) = std::sync::Arc::clone(&self.connection_limit).try_acquire_owned() else {
            connection.close(
                iroh::endpoint::VarInt::from_u32(RATE_LIMITED_CLOSE_CODE),
                b"control connection capacity exceeded",
            );
            return Err(iroh::protocol::AcceptError::from_err(
                crate::error::Failure::Transport("control connection capacity exceeded".to_owned()),
            ));
        };
        let stream_timeout = std::time::Duration::from_secs(CONTROL_STREAM_TIMEOUT_SECS);
        let mut streams_handled: u64 = 0;
        while streams_handled < MAX_CONTROL_STREAMS_PER_CONN {
            let accepted = tokio::time::timeout(stream_timeout, connection.accept_bi()).await;
            let Ok(Ok((send, recv))) = accepted else {
                break;
            };
            streams_handled = streams_handled.saturating_add(1);
            let should_close_after = self
                .handle_control_stream(&connection, remote, send, recv)
                .await?;
            if should_close_after {
                break;
            }
        }
        Ok(())
    }
}

async fn write_control_response(
    send: &mut iroh::endpoint::SendStream,
    response: &SyncControlResponse,
    timeout: std::time::Duration,
) -> std::result::Result<(), iroh::protocol::AcceptError> {
    let encoded = serde_json::to_vec(response).map_err(iroh::protocol::AcceptError::from_err)?;
    tokio::time::timeout(timeout, send.write_all(&encoded))
        .await
        .map_err(|_| {
            iroh::protocol::AcceptError::from_err(crate::error::Failure::Transport(
                "control stream write timeout".to_owned(),
            ))
        })?
        .map_err(iroh::protocol::AcceptError::from_err)?;
    send.finish().map_err(iroh::protocol::AcceptError::from_err)
}

/// Parse a `class:local` scope identifier string.
pub fn parse_scope_id(text: &str) -> crate::error::Result<mneme_core::ScopeId> {
    let (class_text, local) = text.split_once(':').ok_or_else(|| {
        crate::error::Failure::InvalidConfig(format!("scope '{text}' must use class:local"))
    })?;
    let class = mneme_core::ScopeClass::parse(class_text).ok_or_else(|| {
        crate::error::Failure::InvalidConfig(format!("unknown scope class '{class_text}'"))
    })?;
    mneme_core::ScopeId::new(class, local)
        .map_err(|reason| crate::error::Failure::InvalidConfig(reason.to_owned()))
}

pub(crate) fn decode_hex_32(text: &str) -> std::result::Result<[u8; 32], &'static str> {
    let raw = text.trim().as_bytes();
    if raw.len() != 64 {
        return Err("expected 64 hex chars");
    }
    let mut bytes = [0_u8; 32];
    for (index, slot) in bytes.iter_mut().enumerate() {
        let Some(start) = index.checked_mul(2) else {
            return Err("hex index overflow");
        };
        let Some(second) = start.checked_add(1) else {
            return Err("hex index overflow");
        };
        let (Some(&high), Some(&low)) = (raw.get(start), raw.get(second)) else {
            return Err("invalid hex slice");
        };
        let (Some(hi), Some(lo)) = (hex_nibble(high), hex_nibble(low)) else {
            return Err("invalid hex byte");
        };
        *slot = (hi << 4) | lo;
    }
    Ok(bytes)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => byte.checked_sub(b'0'),
        b'a'..=b'f' => match byte.checked_sub(b'a') {
            Some(offset) => offset.checked_add(10),
            None => None,
        },
        b'A'..=b'F' => match byte.checked_sub(b'A') {
            Some(offset) => offset.checked_add(10),
            None => None,
        },
        _ => None,
    }
}

pub(crate) fn parse_hex_32(text: &str) -> crate::error::Result<[u8; 32]> {
    decode_hex_32(text).map_err(|reason| crate::error::Failure::Protocol(reason.to_owned()))
}
