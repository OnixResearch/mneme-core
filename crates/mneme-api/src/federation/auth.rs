//! Live-reloadable per-scope peer allowlist and wire-compatible `concap`
//! capability authorization for remote `irpc` vault federation.

#![allow(
    unknown_lints,
    assertion_density,
    path_segment_repetition,
    fragile_exhaustive_enum_match,
    explicit_defaults
)] // returns typed RpcError/FederationError results; exhaustive match on closed authority/scope enums; serde optional fields

use std::str::FromStr;

/// Schema tag matching `mneme-sync` convergent capability tokens.
pub const CAPABILITY_SCHEMA: &str = "mneme.sync-capability.v1";
/// Maximum delegation chain length permitted in a [`CapabilityToken`].
pub const MAX_DELEGATION_DEPTH: u8 = 8;
/// Maximum serialized byte size of one capability token JSON document (64 KiB).
pub const MAX_CAPABILITY_BYTES: u64 = 64 * 1024;
/// Maximum forward clock skew tolerated on `issued_at_secs` (5 minutes).
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;
/// Hard cap on tombstones retained in a federation [`RevocationSet`].
pub const MAX_REVOCATION_TOMBSTONES: u64 = 4096;
/// Maximum UTF-8 byte length of an optional revocation reason string.
pub const MAX_REVOCATION_REASON_BYTES: u32 = 256;

const LINK_SIGNING_DOMAIN: &[u8] = b"mneme.sync.cap.link.v1\0";
const TOMBSTONE_SIGNING_DOMAIN: &[u8] = b"mneme.sync.cap.revocation.v1\0";
const ID_BYTES_LEN: usize = 16;
const SIGNATURE_BYTES_LEN: usize = 64;
const NANOS_PER_SEC: i64 = 1_000_000_000;
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Scope allowance for an allowlisted federation peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopeGrant {
    /// Peer may query any scope on this vault.
    Any,
    /// Peer may query only the explicitly enumerated scopes.
    Scopes(std::collections::BTreeSet<String>),
}

impl ScopeGrant {
    /// Construct a grant restricted to explicit [`mneme_core::ScopeId`]s.
    pub fn from_scopes(scopes: impl IntoIterator<Item = mneme_core::ScopeId>) -> Self {
        Self::Scopes(scopes.into_iter().map(|scope| scope.to_string()).collect())
    }

    /// Whether `scope` is permitted by this grant.
    pub fn permits(&self, scope: &mneme_core::ScopeId) -> bool {
        match self {
            ScopeGrant::Any => true,
            ScopeGrant::Scopes(scopes) => scopes.contains(&scope.to_string()),
        }
    }
}

/// Explicit Ed25519 peer allowlist with optional per-scope restrictions. Empty by default (deny-all).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerAllowlist {
    peers: std::collections::BTreeMap<iroh::EndpointId, ScopeGrant>,
}

impl PeerAllowlist {
    /// An empty allowlist that refuses every remote peer.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Construct an allowlist from explicit Ed25519 peer identities (all scopes).
    pub fn from_peers(peers: impl IntoIterator<Item = iroh::EndpointId>) -> Self {
        Self {
            peers: peers
                .into_iter()
                .map(|peer| (peer, ScopeGrant::Any))
                .collect(),
        }
    }

    /// Add one authorized Ed25519 peer identity with access to all scopes.
    pub fn allow(&mut self, peer: iroh::EndpointId) {
        self.peers.insert(peer, ScopeGrant::Any);
    }

    /// Add or replace one authorized Ed25519 peer restricted to `scopes`.
    pub fn allow_scopes(
        &mut self,
        peer: iroh::EndpointId,
        scopes: impl IntoIterator<Item = mneme_core::ScopeId>,
    ) {
        self.peers.insert(peer, ScopeGrant::from_scopes(scopes));
    }

    /// Remove `peer` from the allowlist; returns `true` if it was present.
    pub fn revoke(&mut self, peer: &iroh::EndpointId) -> bool {
        self.peers.remove(peer).is_some()
    }

    /// Whether `peer` is explicitly authorized to connect.
    pub fn allows(&self, peer: &iroh::EndpointId) -> bool {
        self.peers.contains_key(peer)
    }

    /// Whether `peer` is explicitly authorized for `scope`.
    pub fn allows_scope(&self, peer: &iroh::EndpointId, scope: &mneme_core::ScopeId) -> bool {
        self.peers
            .get(peer)
            .is_some_and(|grant| grant.permits(scope))
    }

    /// Iterate over all allowlisted peer identities.
    pub fn peer_ids(&self) -> impl Iterator<Item = iroh::EndpointId> + '_ {
        self.peers.keys().copied()
    }

    /// Number of allowlisted peers.
    #[must_use]
    #[allow(unknown_lints, usize_in_public_api)] // std-shaped collection length
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether no peers are allowlisted.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

/// 128-bit capability token identifier.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TokenId([u8; ID_BYTES_LEN]);

impl TokenId {
    /// Construct from raw 16 bytes.
    pub const fn from_bytes(bytes: [u8; ID_BYTES_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow underlying 16 bytes.
    pub const fn as_bytes(&self) -> &[u8; ID_BYTES_LEN] {
        &self.0
    }

    /// Encode as 32 lowercase hexadecimal characters.
    pub fn to_hex(&self) -> String {
        encode_hex(&self.0)
    }

    /// Decode from 32 hexadecimal characters.
    pub fn from_hex(text: &str) -> Result<Self, String> {
        let mut bytes = [0_u8; ID_BYTES_LEN];
        decode_hex_exact(text, &mut bytes)?;
        Ok(Self(bytes))
    }
}

impl std::fmt::Debug for TokenId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TokenId({})", self.to_hex())
    }
}

impl std::fmt::Display for TokenId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl serde::Serialize for TokenId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for TokenId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_hex(&text).map_err(serde::de::Error::custom)
    }
}

/// 128-bit revocation tombstone identifier.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TombstoneId([u8; ID_BYTES_LEN]);

impl TombstoneId {
    /// Construct from raw 16 bytes.
    pub const fn from_bytes(bytes: [u8; ID_BYTES_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow underlying 16 bytes.
    pub const fn as_bytes(&self) -> &[u8; ID_BYTES_LEN] {
        &self.0
    }

    /// Encode as 32 lowercase hexadecimal characters.
    pub fn to_hex(&self) -> String {
        encode_hex(&self.0)
    }

    /// Decode from 32 hexadecimal characters.
    pub fn from_hex(text: &str) -> Result<Self, String> {
        let mut bytes = [0_u8; ID_BYTES_LEN];
        decode_hex_exact(text, &mut bytes)?;
        Ok(Self(bytes))
    }
}

impl std::fmt::Debug for TombstoneId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TombstoneId({})", self.to_hex())
    }
}

impl std::fmt::Display for TombstoneId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl serde::Serialize for TombstoneId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for TombstoneId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_hex(&text).map_err(serde::de::Error::custom)
    }
}

/// Hex-encoded 64-byte Ed25519 signature wrapper matching `mneme-sync`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CapabilitySignature(iroh::Signature);

impl CapabilitySignature {
    /// Wrap an [`iroh::Signature`].
    pub const fn from_iroh(signature: iroh::Signature) -> Self {
        Self(signature)
    }

    /// Borrow the underlying [`iroh::Signature`].
    pub const fn as_iroh(&self) -> &iroh::Signature {
        &self.0
    }

    /// Encode as 128 lowercase hex characters.
    pub fn to_hex(&self) -> String {
        encode_hex(&self.0.to_bytes())
    }

    /// Decode from 128 hex characters.
    pub fn from_hex(text: &str) -> Result<Self, String> {
        let mut bytes = [0_u8; SIGNATURE_BYTES_LEN];
        decode_hex_exact(text, &mut bytes)?;
        Ok(Self(iroh::Signature::from_bytes(&bytes)))
    }
}

impl std::fmt::Debug for CapabilitySignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CapabilitySignature({})", self.to_hex())
    }
}

impl serde::Serialize for CapabilitySignature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for CapabilitySignature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_hex(&text).map_err(serde::de::Error::custom)
    }
}

/// Ordered authority lattice matching `mneme-sync` `concap`.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityAuthority {
    ReadOnly,
    SyncPull,
    SyncPush,
}

impl CapabilityAuthority {
    /// Whether `self` satisfies `required`.
    pub const fn permits(self, required: Self) -> bool {
        self.rank() >= required.rank()
    }

    /// Whether delegating from `self` to `child` is non-escalating.
    pub const fn allows_attenuation_to(self, child: Self) -> bool {
        child.rank() <= self.rank()
    }

    const fn rank(self) -> u8 {
        match self {
            CapabilityAuthority::ReadOnly => 1,
            CapabilityAuthority::SyncPull => 2,
            CapabilityAuthority::SyncPush => 3,
        }
    }
}

/// Scope constraint carried by a `concap` link.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(tag = "mode", content = "scopes", rename_all = "kebab-case")]
pub enum CapabilityScope {
    Wildcard,
    Scopes(std::collections::BTreeSet<String>),
}

impl CapabilityScope {
    /// Construct an explicit scope constraint from one or more [`mneme_core::ScopeId`]s.
    pub fn from_scopes(
        scopes: impl IntoIterator<Item = mneme_core::ScopeId>,
    ) -> Result<Self, String> {
        let set: std::collections::BTreeSet<String> =
            scopes.into_iter().map(|scope| scope.to_string()).collect();
        if set.is_empty() {
            return Err("capability scope set must not be empty".to_owned());
        }
        Ok(CapabilityScope::Scopes(set))
    }

    /// Validate that explicit scopes are non-empty and syntactically valid.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            CapabilityScope::Wildcard => Ok(()),
            CapabilityScope::Scopes(scopes) => {
                if scopes.is_empty() {
                    return Err("capability scope set cannot be empty".to_owned());
                }
                for scope in scopes {
                    let _ = parse_scope_text(scope)?;
                }
                Ok(())
            }
        }
    }

    /// Whether `scope` is permitted by this constraint.
    pub fn permits(&self, scope: &mneme_core::ScopeId) -> bool {
        match self {
            CapabilityScope::Wildcard => true,
            CapabilityScope::Scopes(scopes) => scopes.contains(&scope.to_string()),
        }
    }

    /// Whether `self` is a valid non-escalating attenuation of `parent`.
    pub fn is_attenuation_of(&self, parent: &Self) -> bool {
        if self.validate().is_err() {
            return false;
        }
        match (self, parent) {
            (_, CapabilityScope::Wildcard) => true,
            (CapabilityScope::Wildcard, CapabilityScope::Scopes(_)) => false,
            (CapabilityScope::Scopes(child), CapabilityScope::Scopes(allowed)) => {
                child.is_subset(allowed)
            }
        }
    }
}

/// One Ed25519-signed delegation link in a `concap` token.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CapabilityLink {
    pub token_id: TokenId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<TokenId>,
    pub vault_id: String,
    pub issuer: iroh::EndpointId,
    pub subject: iroh::EndpointId,
    pub scope: CapabilityScope,
    pub authority: CapabilityAuthority,
    pub issued_at_secs: u64,
    pub expires_at_secs: u64,
    pub remaining_depth: u8,
    pub signature: CapabilitySignature,
}

/// Offline-verifiable `concap` capability delegation chain (`mneme.sync-capability.v1`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CapabilityToken {
    pub schema: String,
    pub links: Vec<CapabilityLink>,
}

/// Parameters for issuing a federation capability token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantParams {
    pub token_id: TokenId,
    pub vault_id: String,
    pub subject: iroh::EndpointId,
    pub scope: CapabilityScope,
    pub authority: CapabilityAuthority,
    pub issued_at_secs: u64,
    pub expires_at_secs: u64,
    pub max_delegation_depth: u8,
}

impl CapabilityToken {
    /// Issue a signed root capability token wire-compatible with `mneme-sync`.
    pub fn grant(issuer_key: &iroh::SecretKey, params: GrantParams) -> Result<Self, String> {
        if params.vault_id.trim().is_empty() {
            return Err("vault_id must not be empty".to_owned());
        }
        params.scope.validate()?;
        if params.expires_at_secs <= params.issued_at_secs {
            return Err("expires_at_secs must exceed issued_at_secs".to_owned());
        }
        if params.max_delegation_depth > MAX_DELEGATION_DEPTH {
            return Err(format!(
                "delegation depth {} exceeds {MAX_DELEGATION_DEPTH}",
                params.max_delegation_depth
            ));
        }
        let issuer = issuer_key.public();
        let message = canonical_link_fields_bytes(&LinkFieldsRef {
            token_id: params.token_id,
            parent_id: None,
            vault_id: &params.vault_id,
            issuer,
            subject: params.subject,
            scope: &params.scope,
            authority: params.authority,
            issued_at_secs: params.issued_at_secs,
            expires_at_secs: params.expires_at_secs,
            remaining_depth: params.max_delegation_depth,
        })?;
        let signature = CapabilitySignature::from_iroh(issuer_key.sign(&message));
        Ok(Self {
            schema: CAPABILITY_SCHEMA.to_owned(),
            links: vec![CapabilityLink {
                token_id: params.token_id,
                parent_id: None,
                vault_id: params.vault_id,
                issuer,
                subject: params.subject,
                scope: params.scope,
                authority: params.authority,
                issued_at_secs: params.issued_at_secs,
                expires_at_secs: params.expires_at_secs,
                remaining_depth: params.max_delegation_depth,
                signature,
            }],
        })
    }

    /// Encode this token to canonical JSON for transport in federation RPCs.
    pub fn to_json(&self) -> Result<String, String> {
        let json = serde_json::to_string(self).map_err(|error| error.to_string())?;
        if json.len() as u64 > MAX_CAPABILITY_BYTES {
            return Err("encoded capability token exceeds MAX_CAPABILITY_BYTES".to_owned());
        }
        Ok(json)
    }

    /// Parse a capability token JSON document with size bounds.
    pub fn from_json(text: &str) -> Result<Self, String> {
        if text.len() as u64 > MAX_CAPABILITY_BYTES {
            return Err("capability token document exceeds MAX_CAPABILITY_BYTES".to_owned());
        }
        serde_json::from_str(text).map_err(|error| format!("invalid capability JSON: {error}"))
    }
}

/// Signed revocation tombstone wire-compatible with `mneme-sync`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RevocationTombstone {
    pub tombstone_id: TombstoneId,
    pub vault_id: String,
    pub target_token_id: TokenId,
    pub revoker: iroh::EndpointId,
    pub revoked_at_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub signature: CapabilitySignature,
}

/// Parameters for signing a federation revocation tombstone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationParams<'a> {
    pub tombstone_id: TombstoneId,
    pub vault_id: &'a str,
    pub target_token_id: TokenId,
    pub revoked_at_secs: u64,
    pub reason: Option<&'a str>,
}

impl RevocationTombstone {
    /// Sign a revocation tombstone for `params.target_token_id`.
    pub fn issue(
        revoker_key: &iroh::SecretKey,
        params: &RevocationParams<'_>,
    ) -> Result<Self, String> {
        if params.vault_id.trim().is_empty() {
            return Err("vault_id must not be empty".to_owned());
        }
        let normalized_reason = validate_reason(params.reason)?;
        let revoker = revoker_key.public();
        let message = canonical_tombstone_bytes(&TombstoneFieldsRef {
            tombstone_id: params.tombstone_id,
            vault_id: params.vault_id,
            target_token_id: params.target_token_id,
            revoker,
            revoked_at_secs: params.revoked_at_secs,
            reason: normalized_reason.as_deref(),
        })?;
        let signature = CapabilitySignature::from_iroh(revoker_key.sign(&message));
        Ok(Self {
            tombstone_id: params.tombstone_id,
            vault_id: params.vault_id.to_owned(),
            target_token_id: params.target_token_id,
            revoker,
            revoked_at_secs: params.revoked_at_secs,
            reason: normalized_reason,
            signature,
        })
    }

    /// Verify Ed25519 signature and field bounds on this tombstone.
    pub fn verify_signature(&self) -> Result<(), String> {
        if self.vault_id.trim().is_empty() {
            return Err("vault_id must not be empty".to_owned());
        }
        let _ = validate_reason(self.reason.as_deref())?;
        let message = canonical_tombstone_bytes(&TombstoneFieldsRef {
            tombstone_id: self.tombstone_id,
            vault_id: &self.vault_id,
            target_token_id: self.target_token_id,
            revoker: self.revoker,
            revoked_at_secs: self.revoked_at_secs,
            reason: self.reason.as_deref(),
        })?;
        self.revoker
            .verify(&message, self.signature.as_iroh())
            .map_err(|_| format!("invalid signature on revocation {}", self.tombstone_id))
    }
}

/// Bounded grow-only set of verified revocation tombstones.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RevocationSet {
    tombstones: std::collections::BTreeMap<TombstoneId, RevocationTombstone>,
}

impl RevocationSet {
    /// Construct an empty revocation set.
    pub const fn new() -> Self {
        Self {
            tombstones: std::collections::BTreeMap::new(),
        }
    }

    /// Insert a tombstone if signed by an authorized revoker and within [`MAX_REVOCATION_TOMBSTONES`].
    pub fn insert_authorized(
        &mut self,
        tombstone: RevocationTombstone,
        authorized_revokers: &std::collections::BTreeSet<iroh::EndpointId>,
    ) -> Result<(), String> {
        if !authorized_revokers.contains(&tombstone.revoker) {
            return Err(format!("untrusted revocation issuer {}", tombstone.revoker));
        }
        tombstone.verify_signature()?;
        if let Some(existing) = self.tombstones.get(&tombstone.tombstone_id) {
            if existing == &tombstone {
                return Ok(());
            }
            return Err(format!(
                "conflicting tombstone for id {}",
                tombstone.tombstone_id
            ));
        }
        if (self.tombstones.len() as u64) >= MAX_REVOCATION_TOMBSTONES {
            return Err(format!(
                "revocation set reached capacity ({MAX_REVOCATION_TOMBSTONES})"
            ));
        }
        self.tombstones.insert(tombstone.tombstone_id, tombstone);
        Ok(())
    }

    fn find_valid_revocation(
        &self,
        vault_id: &str,
        target_token_id: TokenId,
        authorized_revokers: &std::collections::BTreeSet<iroh::EndpointId>,
    ) -> Option<&RevocationTombstone> {
        self.tombstones.values().find(|tombstone| {
            tombstone.vault_id == vault_id
                && tombstone.target_token_id == target_token_id
                && authorized_revokers.contains(&tombstone.revoker)
        })
    }
}

#[derive(Clone, Debug)]
struct FederationAuthState {
    allowlist: PeerAllowlist,
    vault_id: String,
    trusted_roots: std::collections::BTreeSet<iroh::EndpointId>,
    authorized_issuers: std::collections::BTreeSet<iroh::EndpointId>,
    revocations: RevocationSet,
}

/// Live-reloadable (`RwLock`) federation authorizer supporting per-scope allowlists and `concap` tokens.
#[derive(Clone, Debug)]
pub struct SharedFederationAuthorizer {
    inner: std::sync::Arc<std::sync::RwLock<FederationAuthState>>,
}

impl SharedFederationAuthorizer {
    /// Wrap an initial [`PeerAllowlist`] with default vault id `"default"`.
    pub fn from_allowlist(allowlist: PeerAllowlist) -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::RwLock::new(FederationAuthState {
                allowlist,
                vault_id: "default".to_owned(),
                trusted_roots: std::collections::BTreeSet::new(),
                authorized_issuers: std::collections::BTreeSet::new(),
                revocations: RevocationSet::new(),
            })),
        }
    }

    /// Configure the vault identifier bound into `concap` capability checks.
    pub fn set_vault_id(&self, vault_id: impl Into<String>) -> Result<(), String> {
        let value = vault_id.into();
        if value.trim().is_empty() {
            return Err("vault_id must not be empty".to_owned());
        }
        let mut guard = self
            .inner
            .write()
            .map_err(|_| "federation authorizer lock poisoned".to_owned())?;
        guard.vault_id = value;
        Ok(())
    }

    /// Add a trusted root capability issuer live.
    pub fn add_trusted_root(&self, root: iroh::EndpointId) -> Result<(), String> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| "federation authorizer lock poisoned".to_owned())?;
        guard.trusted_roots.insert(root);
        Ok(())
    }

    /// Remove a trusted root capability issuer live.
    pub fn remove_trusted_root(&self, root: &iroh::EndpointId) -> Result<bool, String> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| "federation authorizer lock poisoned".to_owned())?;
        Ok(guard.trusted_roots.remove(root))
    }

    /// Replace the live peer allowlist atomically.
    pub fn replace_allowlist(&self, allowlist: PeerAllowlist) -> Result<(), String> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| "federation authorizer lock poisoned".to_owned())?;
        guard.allowlist = allowlist;
        Ok(())
    }

    /// Live-add a peer allowed for all scopes.
    pub fn allow_peer(&self, peer: iroh::EndpointId) -> Result<(), String> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| "federation authorizer lock poisoned".to_owned())?;
        guard.allowlist.allow(peer);
        Ok(())
    }

    /// Live-add a peer restricted to explicit scopes.
    pub fn allow_peer_scopes(
        &self,
        peer: iroh::EndpointId,
        scopes: impl IntoIterator<Item = mneme_core::ScopeId>,
    ) -> Result<(), String> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| "federation authorizer lock poisoned".to_owned())?;
        guard.allowlist.allow_scopes(peer, scopes);
        Ok(())
    }

    /// Live-revoke a peer from the allowlist.
    pub fn revoke_peer(&self, peer: &iroh::EndpointId) -> Result<bool, String> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| "federation authorizer lock poisoned".to_owned())?;
        Ok(guard.allowlist.revoke(peer))
    }

    /// Live-insert a signed revocation tombstone from a trusted root, allowlisted peer, or known issuer.
    pub fn insert_revocation(&self, tombstone: RevocationTombstone) -> Result<(), String> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| "federation authorizer lock poisoned".to_owned())?;
        let mut revokers = guard.trusted_roots.clone();
        for peer in guard.allowlist.peer_ids() {
            revokers.insert(peer);
        }
        for issuer in &guard.authorized_issuers {
            revokers.insert(*issuer);
        }
        guard.revocations.insert_authorized(tombstone, &revokers)
    }

    /// Snapshot the current peer allowlist.
    pub fn allowlist_snapshot(&self) -> PeerAllowlist {
        self.inner
            .read()
            .map(|guard| guard.allowlist.clone())
            .unwrap_or_default()
    }

    /// Whether `peer` is permitted to establish a transport connection (allowlisted OR capability auth enabled).
    pub fn can_connect(&self, peer: &iroh::EndpointId) -> bool {
        let Ok(guard) = self.inner.read() else {
            return false;
        };
        guard.allowlist.allows(peer) || !guard.trusted_roots.is_empty()
    }

    /// Enforce `(caller, vault_id, scope, ReadOnly)` live on every federation RPC.
    pub fn authorize_scope(
        &self,
        caller: iroh::EndpointId,
        scope: &mneme_core::ScopeId,
        capability_document: Option<&str>,
        now_secs: u64,
    ) -> Result<(), super::protocol::RpcError> {
        let verified_issuers = {
            let guard = self.inner.read().map_err(|_| {
                super::protocol::RpcError::new(
                    super::protocol::RpcErrorCode::Unavailable,
                    "federation authorizer lock poisoned",
                )
            })?;
            if guard.allowlist.allows_scope(&caller, scope) {
                return Ok(());
            }
            let Some(doc) = capability_document else {
                return Err(super::protocol::RpcError::new(
                    super::protocol::RpcErrorCode::Unauthorized,
                    format!("peer {caller} is not authorized for scope {scope}"),
                ));
            };
            let token = CapabilityToken::from_json(doc).map_err(|reason| {
                super::protocol::RpcError::new(super::protocol::RpcErrorCode::Unauthorized, reason)
            })?;
            verify_federation_capability(
                &token,
                &CapabilityCheck {
                    presenter: caller,
                    vault_id: &guard.vault_id,
                    scope,
                    now_secs,
                    trusted_roots: &guard.trusted_roots,
                    revocations: &guard.revocations,
                },
            )
            .map_err(|reason| {
                super::protocol::RpcError::new(super::protocol::RpcErrorCode::Unauthorized, reason)
            })?
        };
        if let Ok(mut guard) = self.inner.write() {
            for issuer in verified_issuers {
                if (guard.authorized_issuers.len() as u64) >= MAX_REVOCATION_TOMBSTONES {
                    break;
                }
                guard.authorized_issuers.insert(issuer);
            }
        }
        Ok(())
    }
}

/// Convert a [`mneme_core::Timestamp`] to Unix epoch seconds, failing closed before 1970.
pub fn timestamp_to_epoch_secs(timestamp: mneme_core::Timestamp) -> Result<u64, String> {
    let secs = timestamp.nanos().div_euclid(NANOS_PER_SEC);
    u64::try_from(secs).map_err(|_| "clock timestamp precedes Unix epoch".to_owned())
}

struct CapabilityCheck<'a> {
    presenter: iroh::EndpointId,
    vault_id: &'a str,
    scope: &'a mneme_core::ScopeId,
    now_secs: u64,
    trusted_roots: &'a std::collections::BTreeSet<iroh::EndpointId>,
    revocations: &'a RevocationSet,
}

fn verify_federation_capability(
    token: &CapabilityToken,
    check: &CapabilityCheck<'_>,
) -> Result<Vec<iroh::EndpointId>, String> {
    if token.schema != CAPABILITY_SCHEMA {
        return Err(format!("unsupported capability schema {}", token.schema));
    }
    if token.links.is_empty() || token.links.len() > usize::from(MAX_DELEGATION_DEPTH) {
        return Err("invalid capability link chain length".to_owned());
    }
    let root = &token.links[0];
    if root.parent_id.is_some() {
        return Err("root capability link must not declare a parent".to_owned());
    }
    if !check.trusted_roots.contains(&root.issuer) {
        return Err(format!("untrusted root capability issuer {}", root.issuer));
    }
    let mut previous: Option<&CapabilityLink> = None;
    for link in &token.links {
        verify_link(link, check.vault_id, check.now_secs)?;
        if let Some(parent) = previous {
            verify_attenuation(parent, link)?;
        }
        previous = Some(link);
    }
    let leaf = token
        .links
        .last()
        .ok_or_else(|| "capability token has no leaf link".to_owned())?;
    if leaf.subject != check.presenter {
        return Err(format!(
            "capability subject {} does not match presenter {}",
            leaf.subject, check.presenter
        ));
    }
    if !leaf.authority.permits(CapabilityAuthority::ReadOnly) {
        return Err("capability lacks read-only authority".to_owned());
    }
    if !leaf.scope.permits(check.scope) {
        return Err(format!("capability does not permit scope {}", check.scope));
    }
    let mut revokers = check.trusted_roots.clone();
    let mut issuers = Vec::with_capacity(token.links.len().saturating_add(1));
    for link in &token.links {
        revokers.insert(link.issuer);
        issuers.push(link.issuer);
        if let Some(tombstone) =
            check
                .revocations
                .find_valid_revocation(check.vault_id, link.token_id, &revokers)
        {
            let reason = tombstone.reason.as_deref().unwrap_or("revoked");
            return Err(format!("capability {} revoked: {reason}", link.token_id));
        }
    }
    issuers.push(leaf.subject);
    Ok(issuers)
}

fn verify_link(
    link: &CapabilityLink,
    expected_vault_id: &str,
    now_secs: u64,
) -> Result<(), String> {
    if link.vault_id != expected_vault_id {
        return Err(format!(
            "capability bound to vault '{}' instead of '{expected_vault_id}'",
            link.vault_id
        ));
    }
    link.scope.validate()?;
    if link.remaining_depth > MAX_DELEGATION_DEPTH {
        return Err("remaining_depth exceeds MAX_DELEGATION_DEPTH".to_owned());
    }
    if link.expires_at_secs <= link.issued_at_secs {
        return Err("capability link expires_at_secs <= issued_at_secs".to_owned());
    }
    if link.issued_at_secs > now_secs.saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err(format!(
            "capability link {} issued_at_secs {} exceeds clock skew bound",
            link.token_id, link.issued_at_secs
        ));
    }
    if now_secs >= link.expires_at_secs {
        return Err(format!("capability link {} expired", link.token_id));
    }
    let message = canonical_link_fields_bytes(&LinkFieldsRef {
        token_id: link.token_id,
        parent_id: link.parent_id,
        vault_id: &link.vault_id,
        issuer: link.issuer,
        subject: link.subject,
        scope: &link.scope,
        authority: link.authority,
        issued_at_secs: link.issued_at_secs,
        expires_at_secs: link.expires_at_secs,
        remaining_depth: link.remaining_depth,
    })?;
    link.issuer
        .verify(&message, link.signature.as_iroh())
        .map_err(|_| format!("invalid Ed25519 signature on link {}", link.token_id))
}

fn verify_attenuation(parent: &CapabilityLink, child: &CapabilityLink) -> Result<(), String> {
    if child.parent_id != Some(parent.token_id) {
        return Err("delegation parent_id mismatch".to_owned());
    }
    if child.issuer != parent.subject {
        return Err("delegation issuer does not match parent subject".to_owned());
    }
    if !parent.authority.allows_attenuation_to(child.authority) {
        return Err("delegation escalates authority".to_owned());
    }
    if !child.scope.is_attenuation_of(&parent.scope) {
        return Err("delegation escalates scope".to_owned());
    }
    if child.expires_at_secs > parent.expires_at_secs {
        return Err("delegation extends expiration".to_owned());
    }
    if child.remaining_depth >= parent.remaining_depth {
        return Err("delegation failed to decrement remaining_depth".to_owned());
    }
    Ok(())
}

struct LinkFieldsRef<'a> {
    token_id: TokenId,
    parent_id: Option<TokenId>,
    vault_id: &'a str,
    issuer: iroh::EndpointId,
    subject: iroh::EndpointId,
    scope: &'a CapabilityScope,
    authority: CapabilityAuthority,
    issued_at_secs: u64,
    expires_at_secs: u64,
    remaining_depth: u8,
}

fn canonical_link_fields_bytes(fields: &LinkFieldsRef<'_>) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    out.extend_from_slice(LINK_SIGNING_DOMAIN);
    out.extend_from_slice(fields.token_id.as_bytes());
    match fields.parent_id {
        None => out.push(0),
        Some(parent) => {
            out.push(1);
            out.extend_from_slice(parent.as_bytes());
        }
    }
    push_length_prefixed(&mut out, fields.vault_id.as_bytes())?;
    out.extend_from_slice(fields.issuer.as_bytes());
    out.extend_from_slice(fields.subject.as_bytes());
    match fields.scope {
        CapabilityScope::Wildcard => out.push(0),
        CapabilityScope::Scopes(scopes) => {
            out.push(1);
            let count =
                u32::try_from(scopes.len()).map_err(|_| "scope count exceeds u32".to_owned())?;
            out.extend_from_slice(&count.to_le_bytes());
            for item in scopes {
                push_length_prefixed(&mut out, item.as_bytes())?;
            }
        }
    }
    out.push(fields.authority.rank());
    out.extend_from_slice(&fields.issued_at_secs.to_le_bytes());
    out.extend_from_slice(&fields.expires_at_secs.to_le_bytes());
    out.push(fields.remaining_depth);
    Ok(out)
}

struct TombstoneFieldsRef<'a> {
    tombstone_id: TombstoneId,
    vault_id: &'a str,
    target_token_id: TokenId,
    revoker: iroh::EndpointId,
    revoked_at_secs: u64,
    reason: Option<&'a str>,
}

fn canonical_tombstone_bytes(fields: &TombstoneFieldsRef<'_>) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    out.extend_from_slice(TOMBSTONE_SIGNING_DOMAIN);
    out.extend_from_slice(fields.tombstone_id.as_bytes());
    push_length_prefixed(&mut out, fields.vault_id.as_bytes())?;
    out.extend_from_slice(fields.target_token_id.as_bytes());
    out.extend_from_slice(fields.revoker.as_bytes());
    out.extend_from_slice(&fields.revoked_at_secs.to_le_bytes());
    match fields.reason {
        None => out.push(0),
        Some(text) => {
            out.push(1);
            push_length_prefixed(&mut out, text.as_bytes())?;
        }
    }
    Ok(out)
}

fn push_length_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    let len = u32::try_from(bytes.len()).map_err(|_| "canonical field exceeds u32".to_owned())?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn validate_reason(reason: Option<&str>) -> Result<Option<String>, String> {
    let Some(raw) = reason else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let Ok(len) = u32::try_from(trimmed.len()) else {
        return Err(format!(
            "revocation reason exceeds {MAX_REVOCATION_REASON_BYTES} bytes"
        ));
    };
    if len > MAX_REVOCATION_REASON_BYTES {
        return Err(format!(
            "revocation reason exceeds {MAX_REVOCATION_REASON_BYTES} bytes"
        ));
    }
    Ok(Some(trimmed.to_owned()))
}

fn parse_scope_text(text: &str) -> Result<mneme_core::ScopeId, String> {
    let (class_text, local) = text
        .split_once(':')
        .ok_or_else(|| format!("scope '{text}' must be <class>:<local>"))?;
    let class = mneme_core::ScopeClass::parse(class_text)
        .ok_or_else(|| format!("unknown scope class '{class_text}'"))?;
    mneme_core::ScopeId::new(class, local).map_err(|reason| reason.to_owned())
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

fn decode_hex_exact(text: &str, out: &mut [u8]) -> Result<(), String> {
    let raw = text.trim().as_bytes();
    let expected_chars = out.len().saturating_mul(2);
    if raw.len() != expected_chars {
        return Err(format!(
            "expected {expected_chars} hex chars, got {}",
            raw.len()
        ));
    }
    for (index, slot) in out.iter_mut().enumerate() {
        let start = index.saturating_mul(2);
        let second = start.saturating_add(1);
        let (Some(&high), Some(&low)) = (raw.get(start), raw.get(second)) else {
            return Err("invalid hex slice".to_owned());
        };
        let (Some(hi), Some(lo)) = (hex_nibble(high), hex_nibble(low)) else {
            return Err("invalid hex digit".to_owned());
        };
        *slot = (hi << 4) | lo;
    }
    Ok(())
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

impl FromStr for TokenId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl FromStr for TombstoneId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}
