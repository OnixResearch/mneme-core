//! Explicit Ed25519 NodeId allowlist and local node identity management.
//!
//! Authorization is deny-by-default: mDNS and DHT only resolve network
//! addresses and never add peers to [`PeerAllowlist`].

#![allow(
    unknown_lints,
    assertion_density,
    fragile_exhaustive_enum_match,
    explicit_defaults
)] // returns typed Result failures instead of panicking; exhaustive match on closed two-variant allowance; serde optional fields use standard defaults

use std::io::Write;
use std::str::FromStr;

const ALLOWLIST_SCHEMA: &str = "mneme.sync-peers.v1";
const MAX_ALLOWLIST_BYTES: u64 = 256 * 1024;
const SECRET_KEY_LEN: usize = 32;

/// Scopes accepted from or served to a trusted peer.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "mode", content = "scopes", rename_all = "kebab-case")]
pub enum ScopeAllowance {
    /// Allow all scopes with this peer.
    Any,
    /// Allow only the explicitly enumerated scopes.
    Scopes(std::collections::BTreeSet<String>),
}

impl ScopeAllowance {
    /// Construct an allowance restricted to specific [`mneme_core::ScopeId`]s.
    pub fn from_scopes(scopes: impl IntoIterator<Item = mneme_core::ScopeId>) -> Self {
        let set = scopes.into_iter().map(|scope| scope.to_string()).collect();
        ScopeAllowance::Scopes(set)
    }

    /// Whether `scope` is permitted by this allowance.
    pub fn permits(&self, scope: &mneme_core::ScopeId) -> bool {
        match self {
            ScopeAllowance::Any => true,
            ScopeAllowance::Scopes(scopes) => scopes.contains(&scope.to_string()),
        }
    }
}

/// One allowlisted peer identified by its Ed25519 `iroh::EndpointId`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowedPeer {
    pub node_id: iroh::EndpointId,
    pub label: Option<String>,
    pub allowance: ScopeAllowance,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AllowlistDocument {
    schema: String,
    peers: Vec<PeerEntryDocument>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PeerEntryDocument {
    node_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    allowance: ScopeAllowance,
}

/// Deny-by-default peer allowlist keyed by Ed25519 NodeId.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerAllowlist {
    peers: std::collections::BTreeMap<iroh::EndpointId, AllowedPeer>,
}

impl PeerAllowlist {
    /// Create an empty allowlist that refuses every peer.
    pub const fn new() -> Self {
        Self {
            peers: std::collections::BTreeMap::new(),
        }
    }

    /// Add or replace an explicitly trusted peer.
    pub fn allow(&mut self, peer: AllowedPeer) {
        self.peers.insert(peer.node_id, peer);
    }

    /// Remove a peer from the allowlist; returns `true` if it was present.
    pub fn revoke(&mut self, node_id: iroh::EndpointId) -> bool {
        self.peers.remove(&node_id).is_some()
    }

    /// Whether `node_id` is explicitly allowlisted.
    pub fn is_allowed(&self, node_id: iroh::EndpointId) -> bool {
        self.peers.contains_key(&node_id)
    }

    /// Whether `node_id` is allowlisted for `scope`.
    pub fn allows_scope(&self, node_id: iroh::EndpointId, scope: &mneme_core::ScopeId) -> bool {
        self.peers
            .get(&node_id)
            .is_some_and(|peer| peer.allowance.permits(scope))
    }

    /// Iterate over all allowlisted peers in deterministic NodeId order.
    pub fn peers(&self) -> impl Iterator<Item = &AllowedPeer> {
        self.peers.values()
    }

    /// Number of allowlisted peers.
    pub fn len_u64(&self) -> u64 {
        self.peers.len() as u64
    }

    /// Load a persisted allowlist; returns an empty deny-by-default list if absent.
    pub fn load(path: &std::path::Path) -> crate::error::Result<Self> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Self::new()),
            Err(error) => {
                return Err(crate::error::Failure::Io(format!(
                    "read allowlist {}: {error}",
                    path.display()
                )));
            }
        };
        if bytes.len() as u64 > MAX_ALLOWLIST_BYTES {
            return Err(crate::error::Failure::SizeLimitExceeded {
                actual_bytes: bytes.len() as u64,
                limit_bytes: MAX_ALLOWLIST_BYTES,
            });
        }
        let doc: AllowlistDocument = serde_json::from_slice(&bytes).map_err(|error| {
            crate::error::Failure::InvalidConfig(format!("parse allowlist: {error}"))
        })?;
        if doc.schema != ALLOWLIST_SCHEMA {
            return Err(crate::error::Failure::InvalidConfig(format!(
                "unsupported allowlist schema {}",
                doc.schema
            )));
        }
        let mut list = Self::new();
        for entry in doc.peers {
            let node_id = parse_endpoint_id(&entry.node_id)?;
            list.allow(AllowedPeer {
                node_id,
                label: entry.label,
                allowance: entry.allowance,
            });
        }
        Ok(list)
    }

    /// Atomically write this allowlist to `path`.
    pub fn save(&self, path: &std::path::Path) -> crate::error::Result<()> {
        let doc = AllowlistDocument {
            schema: ALLOWLIST_SCHEMA.to_owned(),
            peers: self
                .peers
                .values()
                .map(|peer| PeerEntryDocument {
                    node_id: peer.node_id.to_string(),
                    label: peer.label.clone(),
                    allowance: peer.allowance.clone(),
                })
                .collect(),
        };
        let encoded = serde_json::to_vec_pretty(&doc).map_err(|error| {
            crate::error::Failure::InvalidConfig(format!("encode allowlist: {error}"))
        })?;
        write_atomic(path, &encoded)
    }
}

/// Thread-safe shared allowlist used by live endpoints and gossip handlers.
#[derive(Clone, Debug, Default)]
pub struct SharedAllowlist {
    inner: std::sync::Arc<std::sync::RwLock<PeerAllowlist>>,
}

impl SharedAllowlist {
    /// Wrap an initial [`PeerAllowlist`].
    pub fn new(initial: PeerAllowlist) -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::RwLock::new(initial)),
        }
    }

    /// Add or update a peer in the live allowlist.
    pub fn allow(&self, peer: AllowedPeer) -> crate::error::Result<()> {
        let mut guard = self.inner.write().map_err(|_| {
            crate::error::Failure::InvalidConfig("allowlist lock poisoned".to_owned())
        })?;
        guard.allow(peer);
        Ok(())
    }

    /// Remove a peer from the live allowlist.
    pub fn revoke(&self, node_id: iroh::EndpointId) -> crate::error::Result<bool> {
        let mut guard = self.inner.write().map_err(|_| {
            crate::error::Failure::InvalidConfig("allowlist lock poisoned".to_owned())
        })?;
        Ok(guard.revoke(node_id))
    }

    /// Check whether `node_id` is allowlisted.
    pub fn is_allowed(&self, node_id: iroh::EndpointId) -> bool {
        self.inner
            .read()
            .map(|guard| guard.is_allowed(node_id))
            .unwrap_or(false)
    }

    /// Check whether `node_id` is allowlisted for `scope`.
    pub fn allows_scope(&self, node_id: iroh::EndpointId, scope: &mneme_core::ScopeId) -> bool {
        self.inner
            .read()
            .map(|guard| guard.allows_scope(node_id, scope))
            .unwrap_or(false)
    }

    /// Snapshot the current allowlist.
    pub fn snapshot(&self) -> crate::error::Result<PeerAllowlist> {
        self.inner
            .read()
            .map(|guard| guard.clone())
            .map_err(|_| crate::error::Failure::InvalidConfig("allowlist lock poisoned".to_owned()))
    }
}

/// Parse an Ed25519 Iroh `EndpointId` (base32 or 64-hex string).
pub fn parse_endpoint_id(text: &str) -> crate::error::Result<iroh::EndpointId> {
    iroh::EndpointId::from_str(text.trim()).map_err(|error| {
        crate::error::Failure::InvalidConfig(format!("invalid node id '{text}': {error}"))
    })
}

/// Generate a fresh Ed25519 secret key from OS entropy.
#[allow(unknown_lints, ambient_random)] // explicit node identity key generation at the CLI/node shell
pub fn generate_secret_key() -> crate::error::Result<iroh::SecretKey> {
    let mut bytes = [0_u8; SECRET_KEY_LEN];
    getrandom::fill(&mut bytes)
        .map_err(|error| crate::error::Failure::Io(format!("generate node secret key: {error}")))?;
    Ok(iroh::SecretKey::from_bytes(&bytes))
}

/// Load an existing secret key from `path`, or create and persist a new one.
pub fn load_or_create_secret_key(path: &std::path::Path) -> crate::error::Result<iroh::SecretKey> {
    match std::fs::read_to_string(path) {
        Ok(text) => parse_secret_key_hex(&text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let key = generate_secret_key()?;
            let encoded = encode_hex(&key.to_bytes());
            write_private_key(path, encoded.as_bytes())?;
            Ok(key)
        }
        Err(error) => Err(crate::error::Failure::Io(format!(
            "read secret key {}: {error}",
            path.display()
        ))),
    }
}

fn parse_secret_key_hex(text: &str) -> crate::error::Result<iroh::SecretKey> {
    let bytes = crate::protocol::decode_hex_32(text)
        .map_err(|reason| crate::error::Failure::InvalidConfig(reason.to_owned()))?;
    Ok(iroh::SecretKey::from_bytes(&bytes))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    let cap = bytes.len().saturating_mul(2);
    let mut out = String::with_capacity(cap);
    for byte in bytes {
        out.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

pub(crate) fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> crate::error::Result<()> {
    let parent = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(parent).map_err(|error| {
        crate::error::Failure::Io(format!("create directory {}: {error}", parent.display()))
    })?;
    let mut temp = tempfile::Builder::new()
        .prefix(".mneme-sync-tmp-")
        .tempfile_in(parent)
        .map_err(|error| crate::error::Failure::Io(format!("create tempfile: {error}")))?;
    temp.write_all(bytes)
        .and_then(|()| temp.as_file().sync_all())
        .map_err(|error| crate::error::Failure::Io(format!("write {}: {error}", path.display())))?;
    temp.persist(path).map_err(|error| {
        crate::error::Failure::Io(format!("persist {}: {}", path.display(), error.error))
    })?;
    Ok(())
}

#[cfg(unix)]
fn write_private_key(path: &std::path::Path, bytes: &[u8]) -> crate::error::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    write_atomic(path, bytes)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|error| {
        crate::error::Failure::Io(format!("chmod 0600 on {}: {error}", path.display()))
    })
}

#[cfg(not(unix))]
fn write_private_key(path: &std::path::Path, bytes: &[u8]) -> crate::error::Result<()> {
    write_atomic(path, bytes)
}
