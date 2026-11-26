//! Offline-verifiable convergent capabilities (`concap`) and CRDT revocation.
//!
//! Capabilities are Ed25519-signed delegation chains bound to Iroh NodeIds
//! (`iroh::EndpointId`), enforcing monotonic attenuation of authority, scope,
//! expiration, and delegation depth, paired with a grow-only CRDT revocation
//! set of signed tombstones for deterministic offline convergence.

#![allow(
    unknown_lints,
    assertion_density,
    path_segment_repetition,
    fragile_exhaustive_enum_match,
    explicit_defaults
)] // returns typed Result failures instead of panicking; Capability* matches module domain; exhaustive match on closed authority/scope enums; serde optional fields

use std::str::FromStr;

/// Schema tag for persisted standalone capability tokens.
pub const CAPABILITY_SCHEMA: &str = "mneme.sync-capability.v1";
/// Schema tag for persisted local capability stores.
pub const CAPABILITY_STORE_SCHEMA: &str = "mneme.sync-capabilities.v1";
/// Schema tag for persisted convergent revocation sets.
pub const REVOCATION_SET_SCHEMA: &str = "mneme.sync-revocations.v1";
/// Maximum delegation chain length permitted in a [`CapabilityToken`].
pub const MAX_DELEGATION_DEPTH: u8 = 8;
/// Maximum serialized byte size of one capability token document (64 KiB).
pub const MAX_CAPABILITY_BYTES: u64 = 64 * 1024;
/// Maximum serialized byte size of a capability store or revocation set (2 MiB).
pub const MAX_REVOCATION_SET_BYTES: u64 = 2 * 1024 * 1024;
/// Maximum UTF-8 byte length of an optional revocation reason string.
pub const MAX_REVOCATION_REASON_BYTES: u32 = 256;
/// Maximum forward clock skew tolerated on capability `issued_at_secs` (5 minutes).
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;
/// Hard cap on total tombstones held in a [`RevocationSet`] (guarantees persistence under 2 MiB).
pub const MAX_REVOCATION_TOMBSTONES: u64 = 4096;
/// Maximum tombstones returned or pushed in one paginated `SyncRevocations` frame.
pub const MAX_REVOCATIONS_PER_PAGE: u64 = 256;
/// Maximum active capability leases cached per remote peer.
pub const MAX_LEASES_PER_PEER: u64 = 64;
/// Maximum distinct peers tracked simultaneously in [`SharedCapabilityLeases`].
pub const MAX_LEASED_PEERS: u64 = 4096;
/// Maximum verified delegation issuers remembered for causal revocation checks.
pub const MAX_AUTHORIZED_ISSUERS: u64 = 4096;

const LINK_SIGNING_DOMAIN: &[u8] = b"mneme.sync.cap.link.v1\0";
const TOMBSTONE_SIGNING_DOMAIN: &[u8] = b"mneme.sync.cap.revocation.v1\0";
const ID_BYTES_LEN: usize = 16;
const SIGNATURE_BYTES_LEN: usize = 64;
const NANOS_PER_SEC: i64 = 1_000_000_000;
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Unique 128-bit identifier for one capability grant or delegation link.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TokenId([u8; ID_BYTES_LEN]);

impl TokenId {
    /// Construct from raw 16 bytes.
    pub const fn from_bytes(bytes: [u8; ID_BYTES_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying 16 bytes.
    pub const fn as_bytes(&self) -> &[u8; ID_BYTES_LEN] {
        &self.0
    }

    /// Convert to the 128-bit big-endian identifier used by `mneme_kernel::capability`.
    pub const fn to_kernel(&self) -> u128 {
        u128::from_be_bytes(self.0)
    }

    /// Encode as 32 lowercase hexadecimal characters.
    pub fn to_hex(&self) -> String {
        encode_hex(&self.0)
    }

    /// Decode from 32 hexadecimal characters.
    pub fn from_hex(text: &str) -> crate::error::Result<Self> {
        let bytes = decode_hex_16(text)?;
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

impl FromStr for TokenId {
    type Err = crate::error::Failure;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl serde::Serialize for TokenId {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for TokenId {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_hex(&text).map_err(serde::de::Error::custom)
    }
}

/// Unique 128-bit identifier for one signed revocation tombstone.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TombstoneId([u8; ID_BYTES_LEN]);

impl TombstoneId {
    /// Construct from raw 16 bytes.
    pub const fn from_bytes(bytes: [u8; ID_BYTES_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying 16 bytes.
    pub const fn as_bytes(&self) -> &[u8; ID_BYTES_LEN] {
        &self.0
    }

    /// Convert to the 128-bit big-endian identifier used by `mneme_kernel::capability`.
    pub const fn to_kernel(&self) -> u128 {
        u128::from_be_bytes(self.0)
    }

    /// Encode as 32 lowercase hexadecimal characters.
    pub fn to_hex(&self) -> String {
        encode_hex(&self.0)
    }

    /// Decode from 32 hexadecimal characters.
    pub fn from_hex(text: &str) -> crate::error::Result<Self> {
        let bytes = decode_hex_16(text)?;
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

impl FromStr for TombstoneId {
    type Err = crate::error::Failure;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl serde::Serialize for TombstoneId {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for TombstoneId {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_hex(&text).map_err(serde::de::Error::custom)
    }
}

/// Hex-encoded 64-byte Ed25519 signature wrapper over [`iroh::Signature`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CapabilitySignature(iroh::Signature);

impl CapabilitySignature {
    /// Wrap an [`iroh::Signature`].
    pub const fn from_iroh(signature: iroh::Signature) -> Self {
        Self(signature)
    }

    /// Borrow as an [`iroh::Signature`].
    pub const fn as_iroh(&self) -> &iroh::Signature {
        &self.0
    }

    /// Encode as 128 lowercase hexadecimal characters.
    pub fn to_hex(&self) -> String {
        encode_hex(&self.0.to_bytes())
    }

    /// Decode from 128 hexadecimal characters.
    pub fn from_hex(text: &str) -> crate::error::Result<Self> {
        let bytes = decode_hex_64(text)?;
        Ok(Self(iroh::Signature::from_bytes(&bytes)))
    }
}

impl std::fmt::Debug for CapabilitySignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CapabilitySignature({})", self.to_hex())
    }
}

impl serde::Serialize for CapabilitySignature {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for CapabilitySignature {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_hex(&text).map_err(serde::de::Error::custom)
    }
}

/// Ordered authority lattice for sync and remote federation capabilities.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityAuthority {
    /// Read-only snapshot metadata and query inspection (`GetVaultHead`).
    ReadOnly,
    /// Read-only inspection plus pulling verified bundles/blobs (`iroh-blobs`, `iroh-gossip`).
    SyncPull,
    /// Full sync pull authority plus pushing/announcing head revisions.
    SyncPush,
}

impl CapabilityAuthority {
    /// Stable lowercase symbol for serialization and CLI output.
    pub const fn symbol(self) -> &'static str {
        match self {
            CapabilityAuthority::ReadOnly => "read-only",
            CapabilityAuthority::SyncPull => "sync-pull",
            CapabilityAuthority::SyncPush => "sync-push",
        }
    }

    /// Parse from canonical kebab-case or PascalCase authority name.
    pub fn parse(text: &str) -> crate::error::Result<Self> {
        match text.trim() {
            "read-only" | "ReadOnly" | "readonly" => Ok(CapabilityAuthority::ReadOnly),
            "sync-pull" | "SyncPull" | "pull" => Ok(CapabilityAuthority::SyncPull),
            "sync-push" | "SyncPush" | "push" => Ok(CapabilityAuthority::SyncPush),
            other => Err(crate::error::Failure::InvalidConfig(format!(
                "unsupported capability authority '{other}' (expected read-only, sync-pull, or sync-push)"
            ))),
        }
    }

    /// Convert to the formally verified kernel authority lattice element.
    pub const fn to_kernel(self) -> mneme_kernel::capability::Authority {
        match self {
            CapabilityAuthority::ReadOnly => mneme_kernel::capability::Authority::ReadOnly,
            CapabilityAuthority::SyncPull => mneme_kernel::capability::Authority::SyncPull,
            CapabilityAuthority::SyncPush => mneme_kernel::capability::Authority::SyncPush,
        }
    }

    /// Whether `self` satisfies `required` (`self >= required`).
    pub fn permits(self, required: Self) -> bool {
        mneme_kernel::capability::authority_permits(self.to_kernel(), required.to_kernel())
    }

    /// Whether delegating from `self` to `child` is a valid non-escalating attenuation.
    pub fn allows_attenuation_to(self, child: Self) -> bool {
        mneme_kernel::capability::authority_attenuates(self.to_kernel(), child.to_kernel())
    }

    fn rank(self) -> u8 {
        mneme_kernel::capability::authority_rank(self.to_kernel())
    }
}

impl std::fmt::Display for CapabilityAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.symbol())
    }
}

/// Scope constraint carried by a capability link (`scope:*` or explicit scopes).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(tag = "mode", content = "scopes", rename_all = "kebab-case")]
pub enum CapabilityScope {
    /// Wildcard scope (`scope:*`) matching any valid [`mneme_core::ScopeId`].
    Wildcard,
    /// Non-empty set of explicit `class:local` scope identifiers.
    Scopes(std::collections::BTreeSet<String>),
}

impl CapabilityScope {
    /// Construct a wildcard (`scope:*`) capability scope.
    pub const fn wildcard() -> Self {
        CapabilityScope::Wildcard
    }

    /// Construct an explicit scope restriction from one or more [`mneme_core::ScopeId`]s.
    pub fn from_scopes(
        scopes: impl IntoIterator<Item = mneme_core::ScopeId>,
    ) -> crate::error::Result<Self> {
        let set: std::collections::BTreeSet<String> =
            scopes.into_iter().map(|scope| scope.to_string()).collect();
        if set.is_empty() {
            return Err(crate::error::Failure::InvalidConfig(
                "capability scope set must not be empty".to_owned(),
            ));
        }
        Ok(CapabilityScope::Scopes(set))
    }

    /// Parse either `"scope:*"` or one explicit `class:local` scope string.
    pub fn parse(text: &str) -> crate::error::Result<Self> {
        let trimmed = text.trim();
        if trimmed == "scope:*" || trimmed == "*" {
            return Ok(CapabilityScope::Wildcard);
        }
        let parsed = crate::protocol::parse_scope_id(trimmed)?;
        let mut set = std::collections::BTreeSet::new();
        set.insert(parsed.to_string());
        Ok(CapabilityScope::Scopes(set))
    }

    /// Parse one or more CLI scope arguments (`scope:*` or `class:local`).
    pub fn parse_list(items: &[String]) -> crate::error::Result<Self> {
        if items.is_empty() {
            return Err(crate::error::Failure::InvalidConfig(
                "at least one --scope (`scope:*` or `class:local`) is required".to_owned(),
            ));
        }
        let mut explicit = std::collections::BTreeSet::new();
        let mut has_wildcard = false;
        for item in items {
            let trimmed = item.trim();
            if trimmed == "scope:*" || trimmed == "*" {
                has_wildcard = true;
            } else {
                explicit.insert(parse_single_scope_text(trimmed)?);
            }
        }
        if has_wildcard && !explicit.is_empty() {
            return Err(crate::error::Failure::InvalidConfig(
                "cannot combine wildcard `scope:*` with explicit scopes".to_owned(),
            ));
        }
        if has_wildcard {
            return Ok(CapabilityScope::Wildcard);
        }
        Ok(CapabilityScope::Scopes(explicit))
    }

    /// Validate that explicit scopes are non-empty and syntactically valid.
    pub fn validate(&self) -> crate::error::Result<()> {
        match self {
            CapabilityScope::Wildcard => Ok(()),
            CapabilityScope::Scopes(scopes) => {
                if scopes.is_empty() {
                    return Err(crate::error::Failure::CapabilityDenied(
                        "capability scope set cannot be empty".to_owned(),
                    ));
                }
                for scope in scopes {
                    let _parsed = crate::protocol::parse_scope_id(scope)?;
                }
                Ok(())
            }
        }
    }

    /// Whether `scope` is permitted by this capability scope.
    pub fn permits(&self, scope: &mneme_core::ScopeId) -> bool {
        match self {
            CapabilityScope::Wildcard => true,
            CapabilityScope::Scopes(scopes) => scopes.contains(&scope.to_string()),
        }
    }

    /// Project this scope constraint into `(ScopeMode, Vec<Digest>)` for `mneme_kernel::capability`.
    fn to_kernel(
        &self,
    ) -> (
        mneme_kernel::capability::ScopeMode,
        Vec<mneme_kernel::hashing::Digest>,
    ) {
        match self {
            CapabilityScope::Wildcard => {
                (mneme_kernel::capability::ScopeMode::Wildcard, Vec::new())
            }
            CapabilityScope::Scopes(scopes) => {
                let digests = scopes
                    .iter()
                    .map(|scope| kernel_text_digest(scope))
                    .collect();
                (mneme_kernel::capability::ScopeMode::Explicit, digests)
            }
        }
    }

    /// Whether `self` is a valid non-escalating attenuation of `parent`.
    pub fn is_attenuation_of(&self, parent: &Self) -> bool {
        if self.validate().is_err() {
            return false;
        }
        let (child_mode, child_scopes) = self.to_kernel();
        let (parent_mode, parent_scopes) = parent.to_kernel();
        mneme_kernel::capability::scope_subset(
            child_mode,
            &child_scopes,
            parent_mode,
            &parent_scopes,
        )
    }
}

/// One signed link in a capability delegation chain.
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

/// Parameters for issuing a new root capability token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantRequest {
    pub vault_id: String,
    pub subject: iroh::EndpointId,
    pub scope: CapabilityScope,
    pub authority: CapabilityAuthority,
    pub issued_at_secs: u64,
    pub expires_at_secs: u64,
    pub max_delegation_depth: u8,
}

/// Parameters for delegating an attenuated child capability link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegateRequest {
    pub subject: iroh::EndpointId,
    pub scope: CapabilityScope,
    pub authority: CapabilityAuthority,
    pub issued_at_secs: u64,
    pub expires_at_secs: u64,
    pub remaining_depth: Option<u8>,
}

/// Offline-verifiable, attenuated Ed25519 capability delegation chain.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CapabilityToken {
    pub schema: String,
    pub links: Vec<CapabilityLink>,
}

impl CapabilityToken {
    /// Issue a new signed root capability token bound to `request.subject`.
    pub fn grant(
        issuer_key: &iroh::SecretKey,
        request: GrantRequest,
    ) -> crate::error::Result<Self> {
        validate_vault_id(&request.vault_id)?;
        request.scope.validate()?;
        validate_validity_window(ValidityWindow {
            issued_at_secs: request.issued_at_secs,
            expires_at_secs: request.expires_at_secs,
        })?;
        if request.max_delegation_depth > MAX_DELEGATION_DEPTH {
            return Err(crate::error::Failure::InvalidConfig(format!(
                "delegation depth {} exceeds maximum {}",
                request.max_delegation_depth, MAX_DELEGATION_DEPTH
            )));
        }
        let token_id = generate_token_id()?;
        let issuer = issuer_key.public();
        let link = sign_link(
            issuer_key,
            UnsignedLink {
                token_id,
                parent_id: None,
                vault_id: request.vault_id,
                issuer,
                subject: request.subject,
                scope: request.scope,
                authority: request.authority,
                issued_at_secs: request.issued_at_secs,
                expires_at_secs: request.expires_at_secs,
                remaining_depth: request.max_delegation_depth,
            },
        )?;
        Ok(Self {
            schema: CAPABILITY_SCHEMA.to_owned(),
            links: vec![link],
        })
    }

    /// Delegate an attenuated capability link from the leaf subject to `request.subject`.
    pub fn delegate(
        &self,
        delegator_key: &iroh::SecretKey,
        request: DelegateRequest,
    ) -> crate::error::Result<Self> {
        if self.schema != CAPABILITY_SCHEMA {
            return Err(crate::error::Failure::CapabilityDenied(format!(
                "unsupported capability schema {}",
                self.schema
            )));
        }
        let parent = self.links.last().ok_or_else(|| {
            crate::error::Failure::CapabilityDenied("capability token has no links".to_owned())
        })?;
        let chain_len = u8::try_from(self.links.len()).map_err(|_| {
            crate::error::Failure::CapabilityDenied("capability chain length overflow".to_owned())
        })?;
        if chain_len >= MAX_DELEGATION_DEPTH {
            return Err(crate::error::Failure::CapabilityDenied(format!(
                "delegation chain reached maximum depth {MAX_DELEGATION_DEPTH}"
            )));
        }
        validate_delegation_inputs(delegator_key.public(), parent, &request)?;
        let child_depth = resolve_child_depth(parent.remaining_depth, request.remaining_depth)?;
        let token_id = generate_token_id()?;
        let child = sign_link(
            delegator_key,
            UnsignedLink {
                token_id,
                parent_id: Some(parent.token_id),
                vault_id: parent.vault_id.clone(),
                issuer: delegator_key.public(),
                subject: request.subject,
                scope: request.scope,
                authority: request.authority,
                issued_at_secs: request.issued_at_secs,
                expires_at_secs: request.expires_at_secs,
                remaining_depth: child_depth,
            },
        )?;
        let mut links = self.links.clone();
        links.push(child);
        Ok(Self {
            schema: self.schema.clone(),
            links,
        })
    }

    /// Return the root link identifier, if non-empty.
    pub fn root_id(&self) -> Option<TokenId> {
        self.links.first().map(|link| link.token_id)
    }

    /// Return the leaf link granting effective authority to the presenter.
    pub fn leaf(&self) -> Option<&CapabilityLink> {
        self.links.last()
    }

    /// Return all link identifiers from root to leaf.
    pub fn link_ids(&self) -> Vec<TokenId> {
        self.links.iter().map(|link| link.token_id).collect()
    }

    /// Load a capability token JSON document from `path`.
    pub fn load(path: &std::path::Path) -> crate::error::Result<Self> {
        let bytes = read_bounded_file(path, MAX_CAPABILITY_BYTES, "capability token")?;
        let token: Self = serde_json::from_slice(&bytes).map_err(|error| {
            crate::error::Failure::InvalidConfig(format!("parse capability token: {error}"))
        })?;
        if token.schema != CAPABILITY_SCHEMA {
            return Err(crate::error::Failure::InvalidConfig(format!(
                "unsupported capability schema {}",
                token.schema
            )));
        }
        Ok(token)
    }

    /// Atomically persist this capability token JSON document to `path`.
    pub fn save(&self, path: &std::path::Path) -> crate::error::Result<()> {
        let encoded = serde_json::to_vec_pretty(self).map_err(|error| {
            crate::error::Failure::InvalidConfig(format!("encode capability token: {error}"))
        })?;
        if encoded.len() as u64 > MAX_CAPABILITY_BYTES {
            return Err(crate::error::Failure::SizeLimitExceeded {
                actual_bytes: encoded.len() as u64,
                limit_bytes: MAX_CAPABILITY_BYTES,
            });
        }
        crate::trust::write_atomic(path, &encoded)
    }
}

/// Signed revocation tombstone in the convergent G-Set CRDT.
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

impl RevocationTombstone {
    /// Issue a new signed revocation tombstone targeting `target_token_id`.
    pub fn issue(
        revoker_key: &iroh::SecretKey,
        vault_id: &str,
        target_token_id: TokenId,
        revoked_at_secs: u64,
        reason: Option<&str>,
    ) -> crate::error::Result<Self> {
        validate_vault_id(vault_id)?;
        let normalized_reason = validate_reason(reason)?;
        let tombstone_id = generate_tombstone_id()?;
        let revoker = revoker_key.public();
        let message = canonical_tombstone_bytes(&TombstoneFieldsRef {
            tombstone_id,
            vault_id,
            target_token_id,
            revoker,
            revoked_at_secs,
            reason: normalized_reason.as_deref(),
        })?;
        let signature = CapabilitySignature::from_iroh(revoker_key.sign(&message));
        Ok(Self {
            tombstone_id,
            vault_id: vault_id.to_owned(),
            target_token_id,
            revoker,
            revoked_at_secs,
            reason: normalized_reason,
            signature,
        })
    }

    /// Cryptographically verify the tombstone's Ed25519 signature and field bounds.
    pub fn verify_signature(&self) -> crate::error::Result<()> {
        validate_vault_id(&self.vault_id)?;
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
            .map_err(|_| {
                crate::error::Failure::CapabilityDenied(format!(
                    "invalid revocation signature on tombstone {}",
                    self.tombstone_id
                ))
            })
    }
}

/// Outcome of inserting a tombstone into [`RevocationSet`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationInsertOutcome {
    /// Tombstone was newly added to the CRDT set.
    Inserted,
    /// Identical tombstone was already present.
    AlreadyPresent,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RevocationSetDocument {
    schema: String,
    tombstones: Vec<RevocationTombstone>,
}

/// Deterministic grow-only CRDT set of verified [`RevocationTombstone`]s.
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

    /// Verify and insert one tombstone into the CRDT set, enforcing [`MAX_REVOCATION_TOMBSTONES`].
    pub fn insert(
        &mut self,
        tombstone: RevocationTombstone,
    ) -> crate::error::Result<RevocationInsertOutcome> {
        tombstone.verify_signature()?;
        if let Some(existing) = self.tombstones.get(&tombstone.tombstone_id) {
            if existing == &tombstone {
                return Ok(RevocationInsertOutcome::AlreadyPresent);
            }
            return Err(crate::error::Failure::CapabilityDenied(format!(
                "conflicting revocation tombstone for id {}",
                tombstone.tombstone_id
            )));
        }
        if self.len_u64() >= MAX_REVOCATION_TOMBSTONES {
            return Err(crate::error::Failure::CapabilityDenied(format!(
                "revocation set reached maximum capacity ({MAX_REVOCATION_TOMBSTONES})"
            )));
        }
        self.tombstones.insert(tombstone.tombstone_id, tombstone);
        Ok(RevocationInsertOutcome::Inserted)
    }

    /// Verify revoker authorization, signature, and capacity before inserting one tombstone.
    pub fn insert_authorized(
        &mut self,
        tombstone: RevocationTombstone,
        authorized_revokers: &std::collections::BTreeSet<iroh::EndpointId>,
    ) -> crate::error::Result<RevocationInsertOutcome> {
        if !authorized_revokers.contains(&tombstone.revoker) {
            return Err(crate::error::Failure::CapabilityDenied(format!(
                "untrusted revocation issuer {}",
                tombstone.revoker
            )));
        }
        self.insert(tombstone)
    }

    /// Atomically verify and merge all tombstones from `other` (commutative, associative, idempotent).
    pub fn merge(&mut self, other: &Self) -> crate::error::Result<u64> {
        let incoming: Vec<RevocationTombstone> = other.tombstones.values().cloned().collect();
        self.merge_tombstones(&incoming)
    }

    /// Atomically verify and merge a slice of tombstones into `self`, enforcing [`MAX_REVOCATION_TOMBSTONES`].
    pub fn merge_tombstones(
        &mut self,
        incoming: &[RevocationTombstone],
    ) -> crate::error::Result<u64> {
        self.merge_tombstones_filtered(incoming, None)
    }

    /// Atomically verify revoker authorization, signatures, and capacity before merging tombstones.
    pub fn merge_tombstones_authorized(
        &mut self,
        incoming: &[RevocationTombstone],
        authorized_revokers: &std::collections::BTreeSet<iroh::EndpointId>,
    ) -> crate::error::Result<u64> {
        self.merge_tombstones_filtered(incoming, Some(authorized_revokers))
    }

    fn merge_tombstones_filtered(
        &mut self,
        incoming: &[RevocationTombstone],
        authorized_revokers: Option<&std::collections::BTreeSet<iroh::EndpointId>>,
    ) -> crate::error::Result<u64> {
        if incoming.len() as u64 > MAX_REVOCATION_TOMBSTONES {
            return Err(crate::error::Failure::CapabilityDenied(format!(
                "incoming revocation batch ({}) exceeds maximum capacity ({MAX_REVOCATION_TOMBSTONES})",
                incoming.len()
            )));
        }
        let max_new_entries = usize::try_from(MAX_REVOCATION_TOMBSTONES).map_err(|_| {
            crate::error::Failure::InvalidConfig("revocation capacity overflow".to_owned())
        })?;
        let mut to_insert = std::collections::BTreeMap::new();
        for tombstone in incoming {
            if let Some(allowed) = authorized_revokers
                && !allowed.contains(&tombstone.revoker)
            {
                return Err(crate::error::Failure::CapabilityDenied(format!(
                    "untrusted revocation issuer {}",
                    tombstone.revoker
                )));
            }
            tombstone.verify_signature()?;
            if let Some(existing) = self.tombstones.get(&tombstone.tombstone_id) {
                if existing != tombstone {
                    return Err(crate::error::Failure::CapabilityDenied(format!(
                        "conflicting revocation tombstone for id {}",
                        tombstone.tombstone_id
                    )));
                }
                continue;
            }
            if let Some(pending) = to_insert.get(&tombstone.tombstone_id) {
                if pending != tombstone {
                    return Err(crate::error::Failure::CapabilityDenied(format!(
                        "conflicting revocation tombstone for id {}",
                        tombstone.tombstone_id
                    )));
                }
                continue;
            }
            if to_insert.len() >= max_new_entries {
                return Err(crate::error::Failure::CapabilityDenied(format!(
                    "revocation set would exceed maximum capacity ({MAX_REVOCATION_TOMBSTONES})"
                )));
            }
            to_insert.insert(tombstone.tombstone_id, tombstone.clone());
        }
        let projected = self.len_u64().saturating_add(to_insert.len() as u64);
        if projected > MAX_REVOCATION_TOMBSTONES {
            return Err(crate::error::Failure::CapabilityDenied(format!(
                "revocation set would exceed maximum capacity ({MAX_REVOCATION_TOMBSTONES})"
            )));
        }
        let mut inserted: u64 = 0;
        for (id, tombstone) in to_insert {
            if self.tombstones.insert(id, tombstone).is_none() {
                inserted = inserted.saturating_add(1);
            }
        }
        Ok(inserted)
    }

    /// Return a deterministic bounded page of tombstones strictly after `after_id`.
    ///
    /// Returns `(page, has_more)` where `page.len() <= max_items.min(MAX_REVOCATIONS_PER_PAGE)`.
    pub fn tombstones_after(
        &self,
        after_id: Option<TombstoneId>,
        max_items: u64,
    ) -> (Vec<RevocationTombstone>, bool) {
        let clamped_items = max_items.clamp(1, MAX_REVOCATIONS_PER_PAGE);
        let page_cap = match usize::try_from(clamped_items) {
            Ok(cap) => cap,
            Err(_) => return (Vec::new(), !self.tombstones.is_empty()),
        };
        let iter: Box<dyn Iterator<Item = &RevocationTombstone> + '_> = match after_id {
            Some(cursor) => Box::new(
                self.tombstones
                    .range((
                        std::ops::Bound::Excluded(cursor),
                        std::ops::Bound::Unbounded,
                    ))
                    .map(|(_, value)| value),
            ),
            None => Box::new(self.tombstones.values()),
        };
        let mut page = Vec::with_capacity(page_cap.min(self.tombstones.len()));
        let mut has_more = false;
        for tombstone in iter {
            if page.len() >= page_cap {
                has_more = true;
                break;
            }
            page.push(tombstone.clone());
        }
        (page, has_more)
    }

    /// Return all tombstones in deterministic [`TombstoneId`] order.
    pub fn tombstones(&self) -> impl Iterator<Item = &RevocationTombstone> {
        self.tombstones.values()
    }

    /// Number of tombstones in the set.
    pub fn len_u64(&self) -> u64 {
        self.tombstones.len() as u64
    }

    /// Collect target token IDs revoked for `vault_id` by any issuer in `authorized_revokers`.
    fn authorized_revoked_ids(
        &self,
        vault_id: &str,
        authorized_revokers: &std::collections::BTreeSet<iroh::EndpointId>,
    ) -> Vec<u128> {
        self.tombstones
            .values()
            .filter(|tombstone| {
                tombstone.vault_id == vault_id && authorized_revokers.contains(&tombstone.revoker)
            })
            .map(|tombstone| tombstone.target_token_id.to_kernel())
            .collect()
    }

    /// Find an authorized revocation matching `(vault_id, target_token_id)`.
    pub fn find_valid_revocation(
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

    /// Load and cryptographically verify a persisted revocation set; empty if absent.
    pub fn load(path: &std::path::Path) -> crate::error::Result<Self> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Self::new()),
            Err(error) => {
                return Err(crate::error::Failure::Io(format!(
                    "read revocation set {}: {error}",
                    path.display()
                )));
            }
        };
        if bytes.len() as u64 > MAX_REVOCATION_SET_BYTES {
            return Err(crate::error::Failure::SizeLimitExceeded {
                actual_bytes: bytes.len() as u64,
                limit_bytes: MAX_REVOCATION_SET_BYTES,
            });
        }
        let doc: RevocationSetDocument = serde_json::from_slice(&bytes).map_err(|error| {
            crate::error::Failure::InvalidConfig(format!("parse revocation set: {error}"))
        })?;
        if doc.schema != REVOCATION_SET_SCHEMA {
            return Err(crate::error::Failure::InvalidConfig(format!(
                "unsupported revocation set schema {}",
                doc.schema
            )));
        }
        let mut set = Self::new();
        let _ = set.merge_tombstones(&doc.tombstones)?;
        Ok(set)
    }

    /// Atomically persist this revocation set to `path`.
    pub fn save(&self, path: &std::path::Path) -> crate::error::Result<()> {
        let doc = RevocationSetDocument {
            schema: REVOCATION_SET_SCHEMA.to_owned(),
            tombstones: self.tombstones.values().cloned().collect(),
        };
        let encoded = serde_json::to_vec_pretty(&doc).map_err(|error| {
            crate::error::Failure::InvalidConfig(format!("encode revocation set: {error}"))
        })?;
        if encoded.len() as u64 > MAX_REVOCATION_SET_BYTES {
            return Err(crate::error::Failure::SizeLimitExceeded {
                actual_bytes: encoded.len() as u64,
                limit_bytes: MAX_REVOCATION_SET_BYTES,
            });
        }
        crate::trust::write_atomic(path, &encoded)
    }
}

/// Thread-safe shared CRDT revocation set used by live sync endpoints.
#[derive(Clone, Debug, Default)]
pub struct SharedRevocationSet {
    inner: std::sync::Arc<std::sync::RwLock<RevocationSet>>,
}

impl SharedRevocationSet {
    /// Wrap an initial [`RevocationSet`].
    pub fn new(initial: RevocationSet) -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::RwLock::new(initial)),
        }
    }

    /// Verify and insert one tombstone into the shared set.
    pub fn insert(
        &self,
        tombstone: RevocationTombstone,
    ) -> crate::error::Result<RevocationInsertOutcome> {
        let mut guard = self.inner.write().map_err(|_| {
            crate::error::Failure::InvalidConfig("revocation set lock poisoned".to_owned())
        })?;
        guard.insert(tombstone)
    }

    /// Verify revoker authorization, signature, and capacity before inserting one tombstone.
    pub fn insert_authorized(
        &self,
        tombstone: RevocationTombstone,
        authorized_revokers: &std::collections::BTreeSet<iroh::EndpointId>,
    ) -> crate::error::Result<RevocationInsertOutcome> {
        let mut guard = self.inner.write().map_err(|_| {
            crate::error::Failure::InvalidConfig("revocation set lock poisoned".to_owned())
        })?;
        guard.insert_authorized(tombstone, authorized_revokers)
    }

    /// Atomically verify and merge tombstones into the shared set.
    pub fn merge_tombstones(&self, incoming: &[RevocationTombstone]) -> crate::error::Result<u64> {
        let mut guard = self.inner.write().map_err(|_| {
            crate::error::Failure::InvalidConfig("revocation set lock poisoned".to_owned())
        })?;
        guard.merge_tombstones(incoming)
    }

    /// Atomically verify revoker authorization, signatures, and capacity before merging tombstones.
    pub fn merge_tombstones_authorized(
        &self,
        incoming: &[RevocationTombstone],
        authorized_revokers: &std::collections::BTreeSet<iroh::EndpointId>,
    ) -> crate::error::Result<u64> {
        let mut guard = self.inner.write().map_err(|_| {
            crate::error::Failure::InvalidConfig("revocation set lock poisoned".to_owned())
        })?;
        guard.merge_tombstones_authorized(incoming, authorized_revokers)
    }

    /// Return a deterministic bounded page of tombstones strictly after `after_id`.
    pub fn page_after(
        &self,
        after_id: Option<TombstoneId>,
        max_items: u64,
    ) -> crate::error::Result<(Vec<RevocationTombstone>, bool)> {
        let guard = self.inner.read().map_err(|_| {
            crate::error::Failure::InvalidConfig("revocation set lock poisoned".to_owned())
        })?;
        Ok(guard.tombstones_after(after_id, max_items))
    }

    /// Snapshot the current revocation set.
    pub fn snapshot(&self) -> crate::error::Result<RevocationSet> {
        self.inner.read().map(|guard| guard.clone()).map_err(|_| {
            crate::error::Failure::InvalidConfig("revocation set lock poisoned".to_owned())
        })
    }

    /// Number of tombstones in the shared set.
    pub fn len_u64(&self) -> u64 {
        self.inner.read().map(|guard| guard.len_u64()).unwrap_or(0)
    }
}

/// Inputs for offline capability verification.
pub struct VerificationRequest<'a> {
    pub token: &'a CapabilityToken,
    pub presenter: iroh::EndpointId,
    pub vault_id: &'a str,
    pub scope: &'a mneme_core::ScopeId,
    pub required_authority: CapabilityAuthority,
    pub now_secs: u64,
    pub trusted_roots: &'a std::collections::BTreeSet<iroh::EndpointId>,
    pub revocations: &'a RevocationSet,
}

/// Policy for checking the root link issuer during offline verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootTrustPolicy {
    /// Root issuer must be present in `trusted_roots`.
    RequireTrustedRoot,
    /// Skip root-set membership check (used for client-side pre-flight checks).
    AllowAnySignedRoot,
}

/// Verified capability summary returned after full chain and revocation checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCapability {
    pub root_id: TokenId,
    pub leaf_id: TokenId,
    pub link_ids: Vec<TokenId>,
    pub issuer_chain: Vec<iroh::EndpointId>,
    pub subject: iroh::EndpointId,
    pub scope: CapabilityScope,
    pub authority: CapabilityAuthority,
    pub expires_at_secs: u64,
    pub chain_depth: u8,
}

/// Verify a capability token offline against root trust, attenuation, expiry, and CRDT revocations.
pub fn verify_capability(
    request: &VerificationRequest<'_>,
) -> crate::error::Result<VerifiedCapability> {
    verify_capability_with_policy(request, RootTrustPolicy::RequireTrustedRoot)
}

/// Verify a capability token with an explicit [`RootTrustPolicy`].
pub fn verify_capability_with_policy(
    request: &VerificationRequest<'_>,
    root_policy: RootTrustPolicy,
) -> crate::error::Result<VerifiedCapability> {
    validate_vault_id(request.vault_id)?;
    validate_token_envelope(request.token)?;
    let root = &request.token.links[0];
    if root.parent_id.is_some() {
        return Err(crate::error::Failure::CapabilityDenied(
            "root capability link must not declare a parent".to_owned(),
        ));
    }
    if root_policy == RootTrustPolicy::RequireTrustedRoot
        && !request.trusted_roots.contains(&root.issuer)
    {
        return Err(crate::error::Failure::CapabilityDenied(format!(
            "untrusted root capability issuer {}",
            root.issuer
        )));
    }
    verify_chain_links(request)?;
    let leaf = request.token.leaf().ok_or_else(|| {
        crate::error::Failure::CapabilityDenied("capability token has no leaf link".to_owned())
    })?;
    if leaf.subject != request.presenter {
        return Err(crate::error::Failure::CapabilityDenied(format!(
            "capability subject {} does not match presenter {}",
            leaf.subject, request.presenter
        )));
    }
    if !leaf.authority.permits(request.required_authority) {
        return Err(crate::error::Failure::CapabilityDenied(format!(
            "capability authority {} is below required {}",
            leaf.authority, request.required_authority
        )));
    }
    if !leaf.scope.permits(request.scope) {
        return Err(crate::error::Failure::ScopeDenied {
            peer: request.presenter.to_string(),
            scope: request.scope.to_string(),
        });
    }
    check_causal_revocations(request)?;
    build_verified_summary(request.token, leaf)
}

/// Persisted capability entry in a local node's capability store.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StoredCapability {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub token: CapabilityToken,
}

/// Local capability store (`capabilities.json`) tracking issued and received tokens.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CapabilityStore {
    pub schema: String,
    pub entries: Vec<StoredCapability>,
}

impl Default for CapabilityStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityStore {
    /// Construct an empty capability store.
    pub fn new() -> Self {
        Self {
            schema: CAPABILITY_STORE_SCHEMA.to_owned(),
            entries: Vec::new(),
        }
    }

    /// Insert or replace a stored capability keyed by its leaf `TokenId`.
    pub fn upsert(
        &mut self,
        label: Option<String>,
        token: CapabilityToken,
    ) -> crate::error::Result<()> {
        let leaf_id = token
            .leaf()
            .ok_or_else(|| {
                crate::error::Failure::InvalidConfig(
                    "cannot store empty capability token".to_owned(),
                )
            })?
            .token_id;
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|entry| entry.token.leaf().map(|leaf| leaf.token_id) == Some(leaf_id))
        {
            existing.label = label;
            existing.token = token;
        } else {
            self.entries.push(StoredCapability { label, token });
        }
        Ok(())
    }

    /// Look up a stored capability by leaf or intermediate `TokenId`.
    pub fn find_by_token_id(&self, token_id: TokenId) -> Option<&StoredCapability> {
        self.entries.iter().find(|entry| {
            entry
                .token
                .links
                .iter()
                .any(|link| link.token_id == token_id)
        })
    }

    /// Look up a stored capability specifically matching leaf `token_id`.
    pub fn get_leaf(&self, token_id: TokenId) -> Option<&StoredCapability> {
        self.entries
            .iter()
            .find(|entry| entry.token.leaf().map(|leaf| leaf.token_id) == Some(token_id))
    }

    /// Load a capability store from `path`, or return an empty store if absent.
    pub fn load(path: &std::path::Path) -> crate::error::Result<Self> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Self::new()),
            Err(error) => {
                return Err(crate::error::Failure::Io(format!(
                    "read capability store {}: {error}",
                    path.display()
                )));
            }
        };
        if bytes.len() as u64 > MAX_REVOCATION_SET_BYTES {
            return Err(crate::error::Failure::SizeLimitExceeded {
                actual_bytes: bytes.len() as u64,
                limit_bytes: MAX_REVOCATION_SET_BYTES,
            });
        }
        let store: Self = serde_json::from_slice(&bytes).map_err(|error| {
            crate::error::Failure::InvalidConfig(format!("parse capability store: {error}"))
        })?;
        if store.schema != CAPABILITY_STORE_SCHEMA {
            return Err(crate::error::Failure::InvalidConfig(format!(
                "unsupported capability store schema {}",
                store.schema
            )));
        }
        Ok(store)
    }

    /// Atomically persist this capability store to `path`.
    pub fn save(&self, path: &std::path::Path) -> crate::error::Result<()> {
        let encoded = serde_json::to_vec_pretty(self).map_err(|error| {
            crate::error::Failure::InvalidConfig(format!("encode capability store: {error}"))
        })?;
        if encoded.len() as u64 > MAX_REVOCATION_SET_BYTES {
            return Err(crate::error::Failure::SizeLimitExceeded {
                actual_bytes: encoded.len() as u64,
                limit_bytes: MAX_REVOCATION_SET_BYTES,
            });
        }
        crate::trust::write_atomic(path, &encoded)
    }
}

/// Active verified capability lease recorded for a remote peer after control handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedLease {
    pub peer: iroh::EndpointId,
    pub vault_id: String,
    pub scope: CapabilityScope,
    pub authority: CapabilityAuthority,
    pub expires_at_secs: u64,
    pub link_ids: Vec<TokenId>,
    pub issuer_chain: Vec<iroh::EndpointId>,
}

impl VerifiedLease {
    fn is_active(
        &self,
        now_secs: u64,
        trusted_roots: &std::collections::BTreeSet<iroh::EndpointId>,
        revocations: &RevocationSet,
    ) -> bool {
        if now_secs >= self.expires_at_secs {
            return false;
        }
        let mut authorized_revokers = trusted_roots.clone();
        for (link_id, issuer) in self.link_ids.iter().zip(self.issuer_chain.iter()) {
            authorized_revokers.insert(*issuer);
            let active_revoked_ids =
                revocations.authorized_revoked_ids(&self.vault_id, &authorized_revokers);
            if mneme_kernel::capability::is_revoked(&[link_id.to_kernel()], &active_revoked_ids) {
                return false;
            }
        }
        true
    }
}

/// Thread-safe cache of verified peer capability leases, re-checked against revocations.
#[derive(Clone, Debug, Default)]
pub struct SharedCapabilityLeases {
    inner: std::sync::Arc<
        std::sync::RwLock<std::collections::BTreeMap<iroh::EndpointId, Vec<VerifiedLease>>>,
    >,
}

/// Query inputs for checking a peer's scope-bound capability lease.
pub struct LeaseScopeQuery<'a> {
    pub peer: iroh::EndpointId,
    pub scope: &'a mneme_core::ScopeId,
    pub required: CapabilityAuthority,
    pub now_secs: u64,
    pub trusted_roots: &'a std::collections::BTreeSet<iroh::EndpointId>,
    pub revocations: &'a SharedRevocationSet,
}

/// Query inputs for checking a peer's `(vault_id, scope, authority)` capability lease.
pub struct LeaseVaultScopeQuery<'a> {
    pub peer: iroh::EndpointId,
    pub vault_id: &'a str,
    pub scope: &'a mneme_core::ScopeId,
    pub required: CapabilityAuthority,
    pub now_secs: u64,
    pub trusted_roots: &'a std::collections::BTreeSet<iroh::EndpointId>,
    pub revocations: &'a SharedRevocationSet,
}

/// Eviction context used when recording or sweeping capability leases.
pub struct LeaseEvictionContext<'a> {
    pub now_secs: u64,
    pub trusted_roots: &'a std::collections::BTreeSet<iroh::EndpointId>,
    pub revocations: &'a SharedRevocationSet,
}

impl SharedCapabilityLeases {
    /// Construct an empty lease table.
    pub fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::RwLock::new(std::collections::BTreeMap::new())),
        }
    }

    /// Record a verified capability lease for `peer`, enforcing per-peer and global caps.
    pub fn record_lease(
        &self,
        peer: iroh::EndpointId,
        vault_id: &str,
        verified: &VerifiedCapability,
    ) -> crate::error::Result<()> {
        let mut guard = self.inner.write().map_err(|_| {
            crate::error::Failure::InvalidConfig("capability lease lock poisoned".to_owned())
        })?;
        if !guard.contains_key(&peer) && (guard.len() as u64) >= MAX_LEASED_PEERS {
            return Err(crate::error::Failure::CapabilityDenied(format!(
                "capability lease peer capacity ({MAX_LEASED_PEERS}) exceeded"
            )));
        }
        let leases = guard.entry(peer).or_default();
        insert_bounded_lease(leases, peer, vault_id, verified);
        Ok(())
    }

    /// Evict expired/revoked leases and record a verified capability lease for `peer`.
    pub fn record_lease_with_eviction(
        &self,
        peer: iroh::EndpointId,
        vault_id: &str,
        verified: &VerifiedCapability,
        eviction: &LeaseEvictionContext<'_>,
    ) -> crate::error::Result<()> {
        let rev_snapshot = eviction.revocations.snapshot()?;
        let mut guard = self.inner.write().map_err(|_| {
            crate::error::Failure::InvalidConfig("capability lease lock poisoned".to_owned())
        })?;
        if let Some(existing) = guard.get_mut(&peer) {
            existing.retain(|lease| {
                lease.is_active(eviction.now_secs, eviction.trusted_roots, &rev_snapshot)
            });
            if existing.is_empty() {
                guard.remove(&peer);
            }
        }
        if !guard.contains_key(&peer) && (guard.len() as u64) >= MAX_LEASED_PEERS {
            sweep_inactive_leases(
                &mut guard,
                eviction.now_secs,
                eviction.trusted_roots,
                &rev_snapshot,
            );
        }
        if !guard.contains_key(&peer) && (guard.len() as u64) >= MAX_LEASED_PEERS {
            return Err(crate::error::Failure::CapabilityDenied(format!(
                "capability lease peer capacity ({MAX_LEASED_PEERS}) exceeded"
            )));
        }
        let leases = guard.entry(peer).or_default();
        insert_bounded_lease(leases, peer, vault_id, verified);
        Ok(())
    }

    /// Purge all expired or revoked leases across all peers.
    pub fn evict_inactive(&self, eviction: &LeaseEvictionContext<'_>) -> crate::error::Result<u64> {
        let rev_snapshot = eviction.revocations.snapshot()?;
        let mut guard = self.inner.write().map_err(|_| {
            crate::error::Failure::InvalidConfig("capability lease lock poisoned".to_owned())
        })?;
        Ok(sweep_inactive_leases(
            &mut guard,
            eviction.now_secs,
            eviction.trusted_roots,
            &rev_snapshot,
        ))
    }

    /// Number of currently cached leases for `peer`.
    pub fn lease_count_for_peer(&self, peer: iroh::EndpointId) -> u64 {
        self.inner
            .read()
            .ok()
            .and_then(|guard| guard.get(&peer).map(|leases| leases.len() as u64))
            .unwrap_or(0)
    }

    /// Check whether `peer` currently holds a non-expired, non-revoked lease with `required`.
    pub fn permits_authority(
        &self,
        peer: iroh::EndpointId,
        required: CapabilityAuthority,
        now_secs: u64,
        trusted_roots: &std::collections::BTreeSet<iroh::EndpointId>,
        revocations: &SharedRevocationSet,
    ) -> bool {
        let Ok(rev_snapshot) = revocations.snapshot() else {
            return false;
        };
        let Ok(guard) = self.inner.read() else {
            return false;
        };
        let Some(leases) = guard.get(&peer) else {
            return false;
        };
        leases.iter().any(|lease| {
            lease.authority.permits(required)
                && lease.is_active(now_secs, trusted_roots, &rev_snapshot)
        })
    }

    /// Check whether `peer` holds an active lease bound to `vault_id` with `required` authority.
    pub fn permits_vault_authority(
        &self,
        peer: iroh::EndpointId,
        vault_id: &str,
        required: CapabilityAuthority,
        eviction: &LeaseEvictionContext<'_>,
    ) -> bool {
        let Ok(rev_snapshot) = eviction.revocations.snapshot() else {
            return false;
        };
        let Ok(guard) = self.inner.read() else {
            return false;
        };
        let Some(leases) = guard.get(&peer) else {
            return false;
        };
        leases.iter().any(|lease| {
            lease.vault_id == vault_id
                && lease.authority.permits(required)
                && lease.is_active(eviction.now_secs, eviction.trusted_roots, &rev_snapshot)
        })
    }

    /// Check whether `peer` holds an active lease bound to any vault in `configured_vaults`.
    pub fn permits_any_vault_authority(
        &self,
        peer: iroh::EndpointId,
        configured_vaults: &std::collections::BTreeSet<String>,
        required: CapabilityAuthority,
        eviction: &LeaseEvictionContext<'_>,
    ) -> bool {
        if configured_vaults.is_empty() {
            return false;
        }
        let Ok(rev_snapshot) = eviction.revocations.snapshot() else {
            return false;
        };
        let Ok(guard) = self.inner.read() else {
            return false;
        };
        let Some(leases) = guard.get(&peer) else {
            return false;
        };
        leases.iter().any(|lease| {
            configured_vaults.contains(&lease.vault_id)
                && lease.authority.permits(required)
                && lease.is_active(eviction.now_secs, eviction.trusted_roots, &rev_snapshot)
        })
    }

    /// Check whether `query.peer` currently holds a non-expired, non-revoked lease for `query.scope`.
    pub fn permits_scope(&self, query: &LeaseScopeQuery<'_>) -> bool {
        let Ok(rev_snapshot) = query.revocations.snapshot() else {
            return false;
        };
        let Ok(guard) = self.inner.read() else {
            return false;
        };
        let Some(leases) = guard.get(&query.peer) else {
            return false;
        };
        leases.iter().any(|lease| {
            lease.authority.permits(query.required)
                && lease.scope.permits(query.scope)
                && lease.is_active(query.now_secs, query.trusted_roots, &rev_snapshot)
        })
    }

    /// Check whether `query.peer` holds an active lease matching `(vault_id, scope, required)`.
    pub fn permits_vault_scope(&self, query: &LeaseVaultScopeQuery<'_>) -> bool {
        let Ok(rev_snapshot) = query.revocations.snapshot() else {
            return false;
        };
        let Ok(guard) = self.inner.read() else {
            return false;
        };
        let Some(leases) = guard.get(&query.peer) else {
            return false;
        };
        leases.iter().any(|lease| {
            lease.vault_id == query.vault_id
                && lease.authority.permits(query.required)
                && lease.scope.permits(query.scope)
                && lease.is_active(query.now_secs, query.trusted_roots, &rev_snapshot)
        })
    }
}

fn insert_bounded_lease(
    leases: &mut Vec<VerifiedLease>,
    peer: iroh::EndpointId,
    vault_id: &str,
    verified: &VerifiedCapability,
) {
    leases.retain(|lease| !lease.matches_vault_and_leaf(vault_id, verified.leaf_id));
    while (leases.len() as u64) >= MAX_LEASES_PER_PEER {
        if let Some((evict_index, _)) = leases
            .iter()
            .enumerate()
            .min_by_key(|(_, lease)| lease.expires_at_secs)
        {
            leases.swap_remove(evict_index);
        } else {
            break;
        }
    }
    leases.push(VerifiedLease {
        peer,
        vault_id: vault_id.to_owned(),
        scope: verified.scope.clone(),
        authority: verified.authority,
        expires_at_secs: verified.expires_at_secs,
        link_ids: verified.link_ids.clone(),
        issuer_chain: verified.issuer_chain.clone(),
    });
}

fn sweep_inactive_leases(
    table: &mut std::collections::BTreeMap<iroh::EndpointId, Vec<VerifiedLease>>,
    now_secs: u64,
    trusted_roots: &std::collections::BTreeSet<iroh::EndpointId>,
    revocations: &RevocationSet,
) -> u64 {
    let mut removed: u64 = 0;
    table.retain(|_, leases| {
        let before = leases.len();
        leases.retain(|lease| lease.is_active(now_secs, trusted_roots, revocations));
        removed = removed.saturating_add(before.saturating_sub(leases.len()) as u64);
        !leases.is_empty()
    });
    removed
}

impl VerifiedLease {
    fn matches_vault_and_leaf(&self, vault_id: &str, leaf_id: TokenId) -> bool {
        self.vault_id == vault_id && self.link_ids.last().copied() == Some(leaf_id)
    }
}

/// Bounded thread-safe registry of verified capability delegation issuers permitted to revoke.
#[derive(Clone, Debug, Default)]
pub struct SharedAuthorizedIssuers {
    inner: std::sync::Arc<std::sync::RwLock<std::collections::BTreeSet<iroh::EndpointId>>>,
}

impl SharedAuthorizedIssuers {
    /// Construct an empty verified-issuer registry.
    pub fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::RwLock::new(std::collections::BTreeSet::new())),
        }
    }

    /// Record issuers and subject from a verified capability chain, bounded by [`MAX_AUTHORIZED_ISSUERS`].
    pub fn record_verified(&self, verified: &VerifiedCapability) {
        let Ok(mut guard) = self.inner.write() else {
            return;
        };
        for issuer in &verified.issuer_chain {
            if (guard.len() as u64) >= MAX_AUTHORIZED_ISSUERS {
                break;
            }
            guard.insert(*issuer);
        }
        if (guard.len() as u64) < MAX_AUTHORIZED_ISSUERS {
            guard.insert(verified.subject);
        }
    }

    /// Compute the effective set of authorized revocation issuers (`trusted_roots` ∪ `allowlist` ∪ verified issuers).
    pub fn effective_revokers(
        &self,
        trusted_roots: &std::collections::BTreeSet<iroh::EndpointId>,
        allowlist: &crate::trust::SharedAllowlist,
    ) -> std::collections::BTreeSet<iroh::EndpointId> {
        let mut allowed = trusted_roots.clone();
        if let Ok(snapshot) = allowlist.snapshot() {
            for peer in snapshot.peers() {
                allowed.insert(peer.node_id);
            }
        }
        if let Ok(guard) = self.inner.read() {
            for issuer in guard.iter() {
                allowed.insert(*issuer);
            }
        }
        allowed
    }
}

/// Convert a [`mneme_core::Timestamp`] to Unix epoch seconds, failing closed before 1970.
pub fn timestamp_to_epoch_secs(timestamp: mneme_core::Timestamp) -> crate::error::Result<u64> {
    let secs = timestamp.nanos().div_euclid(NANOS_PER_SEC);
    u64::try_from(secs).map_err(|_| {
        crate::error::Failure::CapabilityDenied("clock timestamp precedes Unix epoch".to_owned())
    })
}

/// Generate a fresh 128-bit [`TokenId`] using the OS CSPRNG (fail-closed).
#[allow(unknown_lints, ambient_random)] // explicit fail-closed CSPRNG token ID generation
pub fn generate_token_id() -> crate::error::Result<TokenId> {
    let mut bytes = [0_u8; ID_BYTES_LEN];
    getrandom::fill(&mut bytes).map_err(|error| {
        crate::error::Failure::CsprngUnavailable(format!("generate token id: {error}"))
    })?;
    Ok(TokenId::from_bytes(bytes))
}

/// Generate a fresh 128-bit [`TombstoneId`] using the OS CSPRNG (fail-closed).
#[allow(unknown_lints, ambient_random)] // explicit fail-closed CSPRNG tombstone ID generation
pub fn generate_tombstone_id() -> crate::error::Result<TombstoneId> {
    let mut bytes = [0_u8; ID_BYTES_LEN];
    getrandom::fill(&mut bytes).map_err(|error| {
        crate::error::Failure::CsprngUnavailable(format!("generate tombstone id: {error}"))
    })?;
    Ok(TombstoneId::from_bytes(bytes))
}

struct UnsignedLink {
    token_id: TokenId,
    parent_id: Option<TokenId>,
    vault_id: String,
    issuer: iroh::EndpointId,
    subject: iroh::EndpointId,
    scope: CapabilityScope,
    authority: CapabilityAuthority,
    issued_at_secs: u64,
    expires_at_secs: u64,
    remaining_depth: u8,
}

struct UnsignedLinkRef<'a> {
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

fn sign_link(
    signer_key: &iroh::SecretKey,
    unsigned: UnsignedLink,
) -> crate::error::Result<CapabilityLink> {
    let message = canonical_link_fields_bytes(&UnsignedLinkRef {
        token_id: unsigned.token_id,
        parent_id: unsigned.parent_id,
        vault_id: &unsigned.vault_id,
        issuer: unsigned.issuer,
        subject: unsigned.subject,
        scope: &unsigned.scope,
        authority: unsigned.authority,
        issued_at_secs: unsigned.issued_at_secs,
        expires_at_secs: unsigned.expires_at_secs,
        remaining_depth: unsigned.remaining_depth,
    })?;
    let signature = CapabilitySignature::from_iroh(signer_key.sign(&message));
    Ok(CapabilityLink {
        token_id: unsigned.token_id,
        parent_id: unsigned.parent_id,
        vault_id: unsigned.vault_id,
        issuer: unsigned.issuer,
        subject: unsigned.subject,
        scope: unsigned.scope,
        authority: unsigned.authority,
        issued_at_secs: unsigned.issued_at_secs,
        expires_at_secs: unsigned.expires_at_secs,
        remaining_depth: unsigned.remaining_depth,
        signature,
    })
}

fn validate_vault_id(vault_id: &str) -> crate::error::Result<()> {
    if vault_id.trim().is_empty() {
        return Err(crate::error::Failure::InvalidConfig(
            "vault_id must not be empty".to_owned(),
        ));
    }
    Ok(())
}

fn parse_single_scope_text(text: &str) -> crate::error::Result<String> {
    let parsed = crate::protocol::parse_scope_id(text)?;
    Ok(parsed.to_string())
}

struct ValidityWindow {
    issued_at_secs: u64,
    expires_at_secs: u64,
}

fn validate_validity_window(window: ValidityWindow) -> crate::error::Result<()> {
    if window.expires_at_secs <= window.issued_at_secs {
        return Err(crate::error::Failure::InvalidConfig(format!(
            "expires_at_secs ({}) must exceed issued_at_secs ({})",
            window.expires_at_secs, window.issued_at_secs
        )));
    }
    Ok(())
}

fn validate_delegation_inputs(
    delegator: iroh::EndpointId,
    parent: &CapabilityLink,
    request: &DelegateRequest,
) -> crate::error::Result<()> {
    if delegator != parent.subject {
        return Err(crate::error::Failure::CapabilityDenied(format!(
            "delegator {delegator} does not match parent subject {}",
            parent.subject
        )));
    }
    if parent.remaining_depth == 0 {
        return Err(crate::error::Failure::CapabilityDenied(
            "parent capability allows zero remaining delegations".to_owned(),
        ));
    }
    if !parent.authority.allows_attenuation_to(request.authority) {
        return Err(crate::error::Failure::CapabilityDenied(format!(
            "cannot escalate authority from {} to {}",
            parent.authority, request.authority
        )));
    }
    if !request.scope.is_attenuation_of(&parent.scope) {
        return Err(crate::error::Failure::CapabilityDenied(
            "cannot escalate capability scope beyond parent grant".to_owned(),
        ));
    }
    validate_validity_window(ValidityWindow {
        issued_at_secs: request.issued_at_secs,
        expires_at_secs: request.expires_at_secs,
    })?;
    if request.issued_at_secs >= parent.expires_at_secs {
        return Err(crate::error::Failure::CapabilityDenied(
            "cannot delegate an already-expired capability".to_owned(),
        ));
    }
    if request.expires_at_secs > parent.expires_at_secs {
        return Err(crate::error::Failure::CapabilityDenied(format!(
            "cannot extend expiration ({}) beyond parent ({})",
            request.expires_at_secs, parent.expires_at_secs
        )));
    }
    Ok(())
}

fn resolve_child_depth(parent_depth: u8, requested_depth: Option<u8>) -> crate::error::Result<u8> {
    let max_allowed = parent_depth.checked_sub(1).ok_or_else(|| {
        crate::error::Failure::CapabilityDenied(
            "parent capability allows zero remaining delegations".to_owned(),
        )
    })?;
    match requested_depth {
        Some(depth) if depth > max_allowed => Err(crate::error::Failure::CapabilityDenied(
            format!("requested delegation depth {depth} exceeds allowed {max_allowed}"),
        )),
        Some(depth) => Ok(depth),
        None => Ok(max_allowed),
    }
}

fn validate_token_envelope(token: &CapabilityToken) -> crate::error::Result<()> {
    if token.schema != CAPABILITY_SCHEMA {
        return Err(crate::error::Failure::CapabilityDenied(format!(
            "unsupported capability schema {}",
            token.schema
        )));
    }
    if token.links.is_empty() {
        return Err(crate::error::Failure::CapabilityDenied(
            "capability token must contain at least one link".to_owned(),
        ));
    }
    if token.links.len() > usize::from(MAX_DELEGATION_DEPTH) {
        return Err(crate::error::Failure::CapabilityDenied(format!(
            "capability delegation depth {} exceeds bound {MAX_DELEGATION_DEPTH}",
            token.links.len()
        )));
    }
    Ok(())
}

fn verify_chain_links(request: &VerificationRequest<'_>) -> crate::error::Result<()> {
    let mut previous: Option<&CapabilityLink> = None;
    for (index, link) in request.token.links.iter().enumerate() {
        verify_single_link(link, request.vault_id, request.now_secs)?;
        if let Some(parent) = previous {
            let depth = u8::try_from(index.saturating_add(1)).map_err(|_| {
                crate::error::Failure::CapabilityDenied(
                    "capability chain depth overflow".to_owned(),
                )
            })?;
            verify_attenuation_step(parent, link, depth)?;
        }
        previous = Some(link);
    }
    Ok(())
}

fn verify_single_link(
    link: &CapabilityLink,
    expected_vault_id: &str,
    now_secs: u64,
) -> crate::error::Result<()> {
    if link.vault_id != expected_vault_id {
        return Err(crate::error::Failure::CapabilityDenied(format!(
            "capability bound to vault '{}' instead of '{}'",
            link.vault_id, expected_vault_id
        )));
    }
    link.scope.validate()?;
    if link.remaining_depth > MAX_DELEGATION_DEPTH {
        return Err(crate::error::Failure::CapabilityDenied(format!(
            "link {} remaining_depth {} exceeds maximum {MAX_DELEGATION_DEPTH}",
            link.token_id, link.remaining_depth
        )));
    }
    validate_validity_window(ValidityWindow {
        issued_at_secs: link.issued_at_secs,
        expires_at_secs: link.expires_at_secs,
    })?;
    if link.issued_at_secs > now_secs.saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err(crate::error::Failure::CapabilityDenied(format!(
            "capability link {} issued_at_secs {} exceeds clock skew bound (now {})",
            link.token_id, link.issued_at_secs, now_secs
        )));
    }
    if now_secs >= link.expires_at_secs {
        return Err(crate::error::Failure::CapabilityDenied(format!(
            "capability link {} expired at {} (now {})",
            link.token_id, link.expires_at_secs, now_secs
        )));
    }
    let message = canonical_link_bytes(link)?;
    link.issuer
        .verify(&message, link.signature.as_iroh())
        .map_err(|_| {
            crate::error::Failure::CapabilityDenied(format!(
                "invalid Ed25519 signature on capability link {}",
                link.token_id
            ))
        })
}

fn kernel_text_digest(text: &str) -> mneme_kernel::hashing::Digest {
    mneme_core::kernel_digest(&mneme_core::HashAlgorithm::Blake3.hash_bytes(text.as_bytes()))
}

fn link_to_kernel_policy(
    link: &CapabilityLink,
) -> (
    mneme_kernel::capability::LinkPolicy,
    Vec<mneme_kernel::hashing::Digest>,
) {
    let (scope_mode, scopes) = link.scope.to_kernel();
    (
        mneme_kernel::capability::LinkPolicy {
            vault_id: kernel_text_digest(&link.vault_id),
            authority: link.authority.to_kernel(),
            scope_mode,
            expires_at: link.expires_at_secs,
            remaining_depth: link.remaining_depth,
        },
        scopes,
    )
}

fn verify_attenuation_step(
    parent: &CapabilityLink,
    child: &CapabilityLink,
    depth: u8,
) -> crate::error::Result<()> {
    if child.parent_id != Some(parent.token_id) {
        return Err(crate::error::Failure::CapabilityDenied(format!(
            "link {} parent_id does not match {}",
            child.token_id, parent.token_id
        )));
    }
    if child.issuer != parent.subject {
        return Err(crate::error::Failure::CapabilityDenied(format!(
            "delegation link {} issuer {} does not match parent subject {}",
            child.token_id, child.issuer, parent.subject
        )));
    }
    if !parent.authority.allows_attenuation_to(child.authority) {
        return Err(crate::error::Failure::CapabilityDenied(format!(
            "link {} escalates authority from {} to {}",
            child.token_id, parent.authority, child.authority
        )));
    }
    if !child.scope.is_attenuation_of(&parent.scope) {
        return Err(crate::error::Failure::CapabilityDenied(format!(
            "link {} escalates scope beyond parent {}",
            child.token_id, parent.token_id
        )));
    }
    if child.expires_at_secs > parent.expires_at_secs {
        return Err(crate::error::Failure::CapabilityDenied(format!(
            "link {} extends expiration ({}) beyond parent ({})",
            child.token_id, child.expires_at_secs, parent.expires_at_secs
        )));
    }
    if child.remaining_depth >= parent.remaining_depth {
        return Err(crate::error::Failure::CapabilityDenied(format!(
            "link {} failed to decrement remaining delegation depth ({} vs {})",
            child.token_id, child.remaining_depth, parent.remaining_depth
        )));
    }
    let (parent_policy, parent_scopes) = link_to_kernel_policy(parent);
    let (child_policy, child_scopes) = link_to_kernel_policy(child);
    if !mneme_kernel::capability::attenuation_valid(
        &parent_policy,
        &parent_scopes,
        &child_policy,
        &child_scopes,
        depth,
        MAX_DELEGATION_DEPTH,
    ) {
        return Err(crate::error::Failure::CapabilityDenied(format!(
            "link {} failed kernel attenuation check beneath {}",
            child.token_id, parent.token_id
        )));
    }
    Ok(())
}

fn check_causal_revocations(request: &VerificationRequest<'_>) -> crate::error::Result<()> {
    let mut authorized_revokers = request.trusted_roots.clone();
    for link in &request.token.links {
        authorized_revokers.insert(link.issuer);
        let revoked_ids = request
            .revocations
            .authorized_revoked_ids(request.vault_id, &authorized_revokers);
        if mneme_kernel::capability::is_revoked(&[link.token_id.to_kernel()], &revoked_ids) {
            let reason = request
                .revocations
                .find_valid_revocation(request.vault_id, link.token_id, &authorized_revokers)
                .and_then(|tombstone| tombstone.reason.as_deref())
                .unwrap_or("revoked by authorized issuer");
            return Err(crate::error::Failure::CapabilityRevoked {
                token_id: link.token_id.to_string(),
                reason: reason.to_owned(),
            });
        }
    }
    Ok(())
}

fn build_verified_summary(
    token: &CapabilityToken,
    leaf: &CapabilityLink,
) -> crate::error::Result<VerifiedCapability> {
    let root_id = token
        .root_id()
        .ok_or_else(|| crate::error::Failure::CapabilityDenied("missing root link".to_owned()))?;
    let chain_depth = u8::try_from(token.links.len())
        .map_err(|_| crate::error::Failure::CapabilityDenied("chain depth overflow".to_owned()))?;
    Ok(VerifiedCapability {
        root_id,
        leaf_id: leaf.token_id,
        link_ids: token.link_ids(),
        issuer_chain: token.links.iter().map(|link| link.issuer).collect(),
        subject: leaf.subject,
        scope: leaf.scope.clone(),
        authority: leaf.authority,
        expires_at_secs: leaf.expires_at_secs,
        chain_depth,
    })
}

fn canonical_link_bytes(link: &CapabilityLink) -> crate::error::Result<Vec<u8>> {
    canonical_link_fields_bytes(&UnsignedLinkRef {
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
    })
}

fn canonical_link_fields_bytes(fields: &UnsignedLinkRef<'_>) -> crate::error::Result<Vec<u8>> {
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
    encode_canonical_scope(&mut out, fields.scope)?;
    out.push(fields.authority.rank());
    out.extend_from_slice(&fields.issued_at_secs.to_le_bytes());
    out.extend_from_slice(&fields.expires_at_secs.to_le_bytes());
    out.push(fields.remaining_depth);
    Ok(out)
}

fn encode_canonical_scope(out: &mut Vec<u8>, scope: &CapabilityScope) -> crate::error::Result<()> {
    match scope {
        CapabilityScope::Wildcard => {
            out.push(0);
            Ok(())
        }
        CapabilityScope::Scopes(scopes) => {
            out.push(1);
            let count = u32::try_from(scopes.len()).map_err(|_| {
                crate::error::Failure::InvalidConfig("scope count exceeds u32".to_owned())
            })?;
            out.extend_from_slice(&count.to_le_bytes());
            for item in scopes {
                push_length_prefixed(out, item.as_bytes())?;
            }
            Ok(())
        }
    }
}

struct TombstoneFieldsRef<'a> {
    tombstone_id: TombstoneId,
    vault_id: &'a str,
    target_token_id: TokenId,
    revoker: iroh::EndpointId,
    revoked_at_secs: u64,
    reason: Option<&'a str>,
}

fn canonical_tombstone_bytes(fields: &TombstoneFieldsRef<'_>) -> crate::error::Result<Vec<u8>> {
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

fn push_length_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> crate::error::Result<()> {
    let len = u32::try_from(bytes.len()).map_err(|_| {
        crate::error::Failure::InvalidConfig("canonical field exceeds u32 length".to_owned())
    })?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn validate_reason(reason: Option<&str>) -> crate::error::Result<Option<String>> {
    let Some(raw) = reason else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let Ok(len) = u32::try_from(trimmed.len()) else {
        return Err(crate::error::Failure::InvalidConfig(format!(
            "revocation reason exceeds {MAX_REVOCATION_REASON_BYTES} bytes"
        )));
    };
    if len > MAX_REVOCATION_REASON_BYTES {
        return Err(crate::error::Failure::InvalidConfig(format!(
            "revocation reason exceeds {MAX_REVOCATION_REASON_BYTES} bytes"
        )));
    }
    Ok(Some(trimmed.to_owned()))
}

fn read_bounded_file(
    path: &std::path::Path,
    max_bytes: u64,
    label: &str,
) -> crate::error::Result<Vec<u8>> {
    let bytes = std::fs::read(path).map_err(|error| {
        crate::error::Failure::Io(format!("read {label} {}: {error}", path.display()))
    })?;
    if bytes.len() as u64 > max_bytes {
        return Err(crate::error::Failure::SizeLimitExceeded {
            actual_bytes: bytes.len() as u64,
            limit_bytes: max_bytes,
        });
    }
    Ok(bytes)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

fn decode_hex_16(text: &str) -> crate::error::Result<[u8; ID_BYTES_LEN]> {
    let mut bytes = [0_u8; ID_BYTES_LEN];
    decode_hex_exact(text, &mut bytes)?;
    Ok(bytes)
}

fn decode_hex_64(text: &str) -> crate::error::Result<[u8; SIGNATURE_BYTES_LEN]> {
    let mut bytes = [0_u8; SIGNATURE_BYTES_LEN];
    decode_hex_exact(text, &mut bytes)?;
    Ok(bytes)
}

fn decode_hex_exact(text: &str, out: &mut [u8]) -> crate::error::Result<()> {
    let raw = text.trim().as_bytes();
    let expected_chars = out.len().saturating_mul(2);
    if raw.len() != expected_chars {
        return Err(crate::error::Failure::InvalidConfig(format!(
            "expected {expected_chars} hex chars, got {}",
            raw.len()
        )));
    }
    for (index, slot) in out.iter_mut().enumerate() {
        let start = index.saturating_mul(2);
        let second = start.saturating_add(1);
        let (Some(&high), Some(&low)) = (raw.get(start), raw.get(second)) else {
            return Err(crate::error::Failure::InvalidConfig(
                "invalid hex slice".to_owned(),
            ));
        };
        let (Some(hi), Some(lo)) = (hex_nibble(high), hex_nibble(low)) else {
            return Err(crate::error::Failure::InvalidConfig(
                "invalid hex digit".to_owned(),
            ));
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
