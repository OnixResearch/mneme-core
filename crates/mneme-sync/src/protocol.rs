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
/// Maximum size of a gossip head-revision announcement (4 KiB).
pub const MAX_GOSSIP_MESSAGE_BYTES: usize = 4096;
/// Maximum portable revision bundle accepted over Iroh sync.
pub const MAX_SYNC_BUNDLE_BYTES: u64 = mneme_store::portability::MAX_PORTABLE_ARCHIVE_BYTES;

const UNAUTHORIZED_CLOSE_CODE: u32 = 403;

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

/// Metadata describing a served vault scope revision and its portable bundle.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct VaultSnapshotInfo {
    pub vault_id: String,
    pub scope: String,
    pub head_revision: String,
    pub head_revision_digest: WireDigest,
    pub sequence: u64,
    pub bundle_hash: String,
    pub bundle_bytes: u64,
    pub blobs: Vec<BlobDigestRef>,
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
        }
    }
}

/// Lightweight private-topic head announcement carried over `iroh-gossip`.
///
/// Announcements never mutate ledger state directly; receivers verify peer
/// authorization and pull the referenced bundle over `iroh-blobs`.
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
}

impl HeadAnnouncement {
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
        let _ = parse_scope_id(&announcement.scope)?;
        let _ = mneme_core::WorkspaceRevisionId::from_hex(&announcement.head_revision).map_err(
            |reason| crate::error::Failure::Protocol(format!("invalid head revision: {reason}")),
        )?;
        let _ = announcement.head_revision_digest.to_digest()?;
        let _ = iroh_blobs::Hash::from_str(&announcement.bundle_hash).map_err(|error| {
            crate::error::Failure::Protocol(format!("invalid announcement bundle hash: {error}"))
        })?;
        Ok(announcement)
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub(crate) enum SyncControlRequest {
    GetVaultHead { scope: String },
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub(crate) enum SyncControlResponse {
    VaultHead(Box<VaultSnapshotInfo>),
    Refused { reason: String },
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

/// Served scope table shared between the sync node and the control ALPN handler.
pub(crate) type PublishedScopes = std::sync::Arc<
    std::sync::RwLock<std::collections::BTreeMap<mneme_core::ScopeId, VaultSnapshotInfo>>,
>;

/// Protocol handler for [`SYNC_CONTROL_ALPN`].
#[derive(Clone, Debug)]
pub(crate) struct SyncControlHandler {
    allowlist: crate::trust::SharedAllowlist,
    published: PublishedScopes,
}

impl SyncControlHandler {
    pub(crate) const fn new(
        allowlist: crate::trust::SharedAllowlist,
        published: PublishedScopes,
    ) -> Self {
        Self {
            allowlist,
            published,
        }
    }

    fn resolve_request(
        &self,
        remote: iroh::EndpointId,
        request_bytes: &[u8],
    ) -> SyncControlResponse {
        let request: SyncControlRequest = match serde_json::from_slice(request_bytes) {
            Ok(req) => req,
            Err(error) => {
                return SyncControlResponse::Refused {
                    reason: format!("invalid control request: {error}"),
                };
            }
        };
        match request {
            SyncControlRequest::GetVaultHead { scope } => {
                let Ok(parsed_scope) = parse_scope_id(&scope) else {
                    return SyncControlResponse::Refused {
                        reason: format!("invalid scope '{scope}'"),
                    };
                };
                if !self.allowlist.allows_scope(remote, &parsed_scope) {
                    return SyncControlResponse::Refused {
                        reason: format!("peer is not authorized for scope {scope}"),
                    };
                }
                let Ok(guard) = self.published.read() else {
                    return SyncControlResponse::Refused {
                        reason: "published scope table unavailable".to_owned(),
                    };
                };
                match guard.get(&parsed_scope) {
                    Some(info) => SyncControlResponse::VaultHead(Box::new(info.clone())),
                    None => SyncControlResponse::Refused {
                        reason: format!("scope {scope} is not served by this node"),
                    },
                }
            }
        }
    }
}

impl iroh::protocol::ProtocolHandler for SyncControlHandler {
    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> std::result::Result<(), iroh::protocol::AcceptError> {
        let remote = connection.remote_id();
        let (mut send, mut recv) = connection.accept_bi().await?;
        let request_bytes = recv
            .read_to_end(MAX_CONTROL_MESSAGE_BYTES)
            .await
            .map_err(iroh::protocol::AcceptError::from_err)?;
        let response = self.resolve_request(remote, &request_bytes);
        let encoded =
            serde_json::to_vec(&response).map_err(iroh::protocol::AcceptError::from_err)?;
        send.write_all(&encoded)
            .await
            .map_err(iroh::protocol::AcceptError::from_err)?;
        send.finish()
            .map_err(iroh::protocol::AcceptError::from_err)?;
        connection.closed().await;
        Ok(())
    }
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
