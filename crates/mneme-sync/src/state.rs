//! Persisted sync state, vault topic derivation, and path layout.

#![allow(
    unknown_lints,
    assertion_density,
    path_segment_repetition,
    explicit_defaults
)] // returns typed Result failures instead of panicking; SyncState/SyncReceipt/SyncPaths match module domain; serde optional fields use standard defaults

const STATE_SCHEMA: &str = "mneme.sync-state.v1";
const MAX_STATE_BYTES: u64 = 1024 * 1024;
const TOPIC_CONTEXT: &str = "mneme.sync.gossip-topic.v1";

/// Standard filenames inside a sync state directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncPaths {
    pub state_dir: std::path::PathBuf,
}

impl SyncPaths {
    /// Construct sync paths rooted at `state_dir`.
    pub fn new(state_dir: impl Into<std::path::PathBuf>) -> Self {
        Self {
            state_dir: state_dir.into(),
        }
    }

    /// Default sync state directory inside a workspace root (`<root>/sync`).
    pub fn for_workspace(workspace_root: &std::path::Path) -> Self {
        Self::new(workspace_root.join("sync"))
    }

    /// Path to the local Ed25519 node secret key.
    pub fn identity_path(&self) -> std::path::PathBuf {
        self.state_dir.join("identity.key")
    }

    /// Path to the explicit peer allowlist JSON file.
    pub fn allowlist_path(&self) -> std::path::PathBuf {
        self.state_dir.join("peers.json")
    }

    /// Path to the persisted sync receipts JSON file.
    pub fn state_path(&self) -> std::path::PathBuf {
        self.state_dir.join("state.json")
    }
}

/// Persisted receipt of the most recent verified pull for a `(scope, peer)`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SyncReceipt {
    pub vault_id: String,
    pub scope: String,
    pub peer: String,
    pub remote_revision: String,
    pub remote_revision_digest: String,
    pub remote_sequence: u64,
    pub bundle_hash: String,
    pub local_sequence: u64,
}

/// Persisted vault identity and per-peer sync receipts.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SyncState {
    pub schema: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<String>,
    #[serde(default)]
    pub receipts: Vec<SyncReceipt>,
}

impl Default for SyncState {
    fn default() -> Self {
        Self {
            schema: STATE_SCHEMA.to_owned(),
            vault_id: None,
            receipts: Vec::new(),
        }
    }
}

impl SyncState {
    /// Load sync state from `path`, or return an empty default if absent.
    pub fn load(path: &std::path::Path) -> crate::error::Result<Self> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => {
                return Err(crate::error::Failure::Io(format!(
                    "read sync state {}: {error}",
                    path.display()
                )));
            }
        };
        if bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(crate::error::Failure::SizeLimitExceeded {
                actual_bytes: bytes.len() as u64,
                limit_bytes: MAX_STATE_BYTES,
            });
        }
        let state: Self = serde_json::from_slice(&bytes).map_err(|error| {
            crate::error::Failure::InvalidConfig(format!("parse sync state: {error}"))
        })?;
        if state.schema != STATE_SCHEMA {
            return Err(crate::error::Failure::InvalidConfig(format!(
                "unsupported sync state schema {}",
                state.schema
            )));
        }
        Ok(state)
    }

    /// Persist sync state atomically to `path`.
    pub fn save(&self, path: &std::path::Path) -> crate::error::Result<()> {
        let encoded = serde_json::to_vec_pretty(self).map_err(|error| {
            crate::error::Failure::InvalidConfig(format!("encode sync state: {error}"))
        })?;
        crate::trust::write_atomic(path, &encoded)
    }

    /// Find an existing receipt matching `(vault_id, scope, peer)`.
    pub fn receipt_for(
        &self,
        vault_id: &str,
        scope: &mneme_core::ScopeId,
        peer: iroh::EndpointId,
    ) -> Option<&SyncReceipt> {
        let scope_text = scope.to_string();
        let peer_text = peer.to_string();
        self.receipts.iter().find(|receipt| {
            receipt.vault_id == vault_id && receipt.scope == scope_text && receipt.peer == peer_text
        })
    }

    /// Insert or replace the sync receipt for `(scope, peer)`.
    pub fn record_receipt(&mut self, receipt: SyncReceipt) {
        self.vault_id = Some(receipt.vault_id.clone());
        if let Some(existing) = self
            .receipts
            .iter_mut()
            .find(|item| item.scope == receipt.scope && item.peer == receipt.peer)
        {
            *existing = receipt;
        } else {
            self.receipts.push(receipt);
        }
    }
}

/// Derive a deterministic gossip topic identifier from `vault_id`.
pub fn topic_id_for_vault(vault_id: &str) -> iroh_gossip::TopicId {
    let key = blake3::derive_key(TOPIC_CONTEXT, vault_id.as_bytes());
    iroh_gossip::TopicId::from_bytes(key)
}

/// Resolve the stable `vault_id` for `workspace`, honoring any saved `SyncState` override.
pub fn resolve_vault_id(
    workspace: &mneme_store::Workspace,
    state: &SyncState,
) -> crate::error::Result<String> {
    if let Some(vault_id) = state.vault_id.as_deref() {
        return Ok(vault_id.to_owned());
    }
    Ok(workspace.genesis_revision()?.to_hex())
}
