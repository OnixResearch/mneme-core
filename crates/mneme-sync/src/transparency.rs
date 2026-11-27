//! Signed tree heads, wire Merkle proofs, and self-verifying equivocation proofs.
//!
//! Peers pin the highest verified [`SignedTreeHead`] per `(origin, vault_id, scope)`.
//! Whenever a peer advances its tree head, the receiver requires an `O(log N)`
//! [`WireConsistencyProof`] verified through [`mneme_kernel::history_tree`].
//! Any same-size root split or failed consistency proof yields a compact,
//! self-verifying [`EquivocationProof`] that can be gossiped to peers.

const STH_SIGNING_DOMAIN: &[u8] = b"mneme.history.sth.v1\0";
const DIGEST_LEN: usize = 32;
const HEX_DIGEST_LEN: usize = 64;
const RAW_PROOF_HEADER_BYTES: u64 = 16;

/// Schema identifier for serialized [`EquivocationProof`] gossip frames.
pub const EQUIVOCATION_PROOF_SCHEMA: &str = "mneme.equivocation-proof.v1";

/// Ed25519-authenticated Crosby-Wallach Merkle tree head for one vault scope.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SignedTreeHead {
    pub vault_id: String,
    pub scope: String,
    pub tree_size: u64,
    pub root_hex: String,
    pub head_revision: String,
    pub eligibility_generation: u64,
    pub origin: iroh::EndpointId,
    pub signature: crate::capability::CapabilitySignature,
}

impl SignedTreeHead {
    /// Sign `head` for `(vault_id, scope)` using `signing_key`.
    pub fn sign(
        vault_id: &str,
        scope: &str,
        head: mneme_store::HistoryTreeHead,
        signing_key: &iroh::SecretKey,
    ) -> crate::error::Result<Self> {
        let origin = signing_key.public();
        let root_hex = encode_hex(&head.root);
        let head_revision = head.head_revision.to_hex();
        let payload = canonical_sth_bytes(SthFields {
            vault_id,
            scope,
            tree_size: head.tree_size,
            root_hex: &root_hex,
            head_revision: &head_revision,
            eligibility_generation: head.eligibility_generation,
            origin,
        })?;
        let signature =
            crate::capability::CapabilitySignature::from_iroh(signing_key.sign(&payload));
        Ok(Self {
            vault_id: vault_id.to_owned(),
            scope: scope.to_owned(),
            tree_size: head.tree_size,
            root_hex,
            head_revision,
            eligibility_generation: head.eligibility_generation,
            origin,
            signature,
        })
    }

    /// Verify the Ed25519 signature and return the authenticated origin peer.
    pub fn verify_signature(&self) -> crate::error::Result<iroh::EndpointId> {
        if self.tree_size == 0 {
            return Err(crate::error::Failure::Protocol(
                "signed tree head has zero tree_size".to_owned(),
            ));
        }
        let _ = self.root_bytes()?;
        let payload = canonical_sth_bytes(SthFields {
            vault_id: &self.vault_id,
            scope: &self.scope,
            tree_size: self.tree_size,
            root_hex: &self.root_hex,
            head_revision: &self.head_revision,
            eligibility_generation: self.eligibility_generation,
            origin: self.origin,
        })?;
        self.origin
            .verify(&payload, self.signature.as_iroh())
            .map_err(|_| {
                crate::error::Failure::CapabilityDenied(format!(
                    "invalid Ed25519 signature on SignedTreeHead from {}",
                    self.origin
                ))
            })?;
        Ok(self.origin)
    }

    /// Decode the 32-byte Merkle root digest.
    pub fn root_bytes(&self) -> crate::error::Result<[u8; DIGEST_LEN]> {
        decode_hex_32(&self.root_hex)
    }
}

/// Wire representation of an RFC 6962 append-only consistency proof.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WireConsistencyProof {
    pub old_size: u64,
    pub new_size: u64,
    pub nodes_hex: Vec<String>,
}

impl WireConsistencyProof {
    /// Convert a store [`mneme_store::ConsistencyProof`] to wire form.
    pub fn from_store(proof: &mneme_store::ConsistencyProof) -> Self {
        Self {
            old_size: proof.old_size,
            new_size: proof.new_size,
            nodes_hex: proof.nodes.iter().map(encode_hex).collect(),
        }
    }

    /// Decode back into a [`mneme_store::ConsistencyProof`].
    pub fn to_store(&self) -> crate::error::Result<mneme_store::ConsistencyProof> {
        let mut nodes = Vec::with_capacity(self.nodes_hex.len());
        for hex in &self.nodes_hex {
            nodes.push(decode_hex_32(hex)?);
        }
        Ok(mneme_store::ConsistencyProof {
            old_size: self.old_size,
            new_size: self.new_size,
            nodes,
        })
    }

    /// Verify against `(old_root, new_root)` via the Lean-proved kernel.
    pub fn verify(
        &self,
        old_root: [u8; DIGEST_LEN],
        new_root: [u8; DIGEST_LEN],
    ) -> crate::error::Result<bool> {
        let proof = self.to_store()?;
        Ok(proof.verify(old_root, new_root))
    }

    /// Compact binary footprint of this proof in bytes (`16 + 32 * nodes.len()`).
    pub fn raw_byte_len(&self) -> u64 {
        let node_bytes = (self.nodes_hex.len() as u64).saturating_mul(DIGEST_LEN as u64);
        RAW_PROOF_HEADER_BYTES.saturating_add(node_bytes)
    }
}

/// Wire representation of an RFC 6962 leaf inclusion proof.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WireInclusionProof {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub leaf_digest_hex: String,
    pub audit_path_hex: Vec<String>,
}

impl WireInclusionProof {
    /// Convert a store [`mneme_store::InclusionProof`] to wire form.
    pub fn from_store(proof: &mneme_store::InclusionProof) -> Self {
        Self {
            leaf_index: proof.leaf_index,
            tree_size: proof.tree_size,
            leaf_digest_hex: encode_hex(&proof.leaf_digest),
            audit_path_hex: proof.audit_path.iter().map(encode_hex).collect(),
        }
    }

    /// Decode back into a [`mneme_store::InclusionProof`].
    pub fn to_store(&self) -> crate::error::Result<mneme_store::InclusionProof> {
        let leaf_digest = decode_hex_32(&self.leaf_digest_hex)?;
        let mut audit_path = Vec::with_capacity(self.audit_path_hex.len());
        for hex in &self.audit_path_hex {
            audit_path.push(decode_hex_32(hex)?);
        }
        Ok(mneme_store::InclusionProof {
            leaf_index: self.leaf_index,
            tree_size: self.tree_size,
            leaf_digest,
            audit_path,
        })
    }

    /// Verify against `expected_root` via the Lean-proved kernel.
    pub fn verify(&self, expected_root: [u8; DIGEST_LEN]) -> crate::error::Result<bool> {
        let proof = self.to_store()?;
        Ok(proof.verify(expected_root))
    }
}

/// Compact, self-verifying gossipable proof that one peer signed conflicting
/// history tree heads (`sth_first`, `sth_second`) for the same vault and scope.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EquivocationProof {
    pub schema: String,
    pub sth_first: SignedTreeHead,
    pub sth_second: SignedTreeHead,
    #[serde(
        default = "no_consistency_proof",
        skip_serializing_if = "Option::is_none"
    )]
    pub consistency_proof: Option<WireConsistencyProof>,
}

const fn no_consistency_proof() -> Option<WireConsistencyProof> {
    None
}

impl EquivocationProof {
    /// Construct a new equivocation proof pair.
    pub fn new(
        sth_first: SignedTreeHead,
        sth_second: SignedTreeHead,
        consistency_proof: Option<WireConsistencyProof>,
    ) -> Self {
        Self {
            schema: EQUIVOCATION_PROOF_SCHEMA.to_owned(),
            sth_first,
            sth_second,
            consistency_proof,
        }
    }

    /// Self-verify both Ed25519 signatures and prove equivocation via the Lean-proved kernel.
    pub fn verify(&self) -> crate::error::Result<bool> {
        if self.schema != EQUIVOCATION_PROOF_SCHEMA {
            return Ok(false);
        }
        let origin_first = self.sth_first.verify_signature()?;
        let origin_second = self.sth_second.verify_signature()?;
        let is_same_identity = origin_first == origin_second
            && self.sth_first.vault_id == self.sth_second.vault_id
            && self.sth_first.scope == self.sth_second.scope;
        if !is_same_identity {
            return Ok(false);
        }
        let (smaller, larger) = if self.sth_first.tree_size <= self.sth_second.tree_size {
            (&self.sth_first, &self.sth_second)
        } else {
            (&self.sth_second, &self.sth_first)
        };
        let smaller_root = smaller.root_bytes()?;
        let larger_root = larger.root_bytes()?;
        let consistency = if smaller.tree_size == larger.tree_size {
            mneme_kernel::history_tree::ConsistencyVerdict::Consistent
        } else {
            match &self.consistency_proof {
                Some(proof)
                    if proof.old_size == smaller.tree_size
                        && proof.new_size == larger.tree_size
                        && proof.verify(smaller_root, larger_root)? =>
                {
                    mneme_kernel::history_tree::ConsistencyVerdict::Consistent
                }
                Some(_) | None => mneme_kernel::history_tree::ConsistencyVerdict::Inconsistent,
            }
        };
        let facts = mneme_kernel::history_tree::EquivocationFacts {
            is_both_signed_same_origin: true,
            first_size: smaller.tree_size,
            first_root: mneme_store::digest_to_kernel(smaller_root),
            second_size: larger.tree_size,
            second_root: mneme_store::digest_to_kernel(larger_root),
            consistency,
        };
        Ok(mneme_kernel::history_tree::equivocation_detected(facts))
    }

    /// Encode as bounded JSON bytes for gossip broadcast.
    pub fn encode(&self) -> crate::error::Result<bytes::Bytes> {
        let encoded = serde_json::to_vec(self).map_err(|error| {
            crate::error::Failure::Protocol(format!("encode equivocation proof: {error}"))
        })?;
        if encoded.len() > crate::protocol::MAX_GOSSIP_MESSAGE_BYTES {
            return Err(crate::error::Failure::SizeLimitExceeded {
                actual_bytes: encoded.len() as u64,
                limit_bytes: crate::protocol::MAX_GOSSIP_MESSAGE_BYTES as u64,
            });
        }
        Ok(bytes::Bytes::from(encoded))
    }

    /// Decode and self-verify an incoming gossiped equivocation proof.
    pub fn decode_verified(bytes: &[u8]) -> crate::error::Result<Self> {
        if bytes.len() > crate::protocol::MAX_GOSSIP_MESSAGE_BYTES {
            return Err(crate::error::Failure::SizeLimitExceeded {
                actual_bytes: bytes.len() as u64,
                limit_bytes: crate::protocol::MAX_GOSSIP_MESSAGE_BYTES as u64,
            });
        }
        let proof: Self = serde_json::from_slice(bytes).map_err(|error| {
            crate::error::Failure::Protocol(format!("decode equivocation proof: {error}"))
        })?;
        if !proof.verify()? {
            return Err(crate::error::Failure::Protocol(
                "equivocation proof failed verification".to_owned(),
            ));
        }
        Ok(proof)
    }
}

type TrackerKey = (iroh::EndpointId, String);

#[derive(Default, Debug)]
struct TrackerState {
    pinned: std::collections::BTreeMap<TrackerKey, SignedTreeHead>,
    equivocations: Vec<EquivocationProof>,
}

/// Thread-safe tracker of pinned peer [`SignedTreeHead`]s and verified [`EquivocationProof`]s.
#[derive(Clone, Default, Debug)]
pub struct SharedTreeHeadTracker {
    inner: std::sync::Arc<std::sync::RwLock<TrackerState>>,
}

impl SharedTreeHeadTracker {
    /// Create an empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Known pinned tree size for `(peer, scope)`, if any.
    pub fn known_tree_size(&self, peer: iroh::EndpointId, scope: &str) -> Option<u64> {
        let guard = self.inner.read().ok()?;
        guard
            .pinned
            .get(&(peer, scope.to_owned()))
            .map(|sth| sth.tree_size)
    }

    /// Return the currently pinned [`SignedTreeHead`] for `(peer, scope)`, if any.
    pub fn pinned_head(&self, peer: iroh::EndpointId, scope: &str) -> Option<SignedTreeHead> {
        let guard = self.inner.read().ok()?;
        guard.pinned.get(&(peer, scope.to_owned())).cloned()
    }

    /// Return all verified [`EquivocationProof`]s observed by this node.
    pub fn equivocations(&self) -> Vec<EquivocationProof> {
        self.inner
            .read()
            .map(|guard| guard.equivocations.clone())
            .unwrap_or_default()
    }

    /// Record an externally gossiped, already self-verified [`EquivocationProof`].
    pub fn record_verified_equivocation(
        &self,
        proof: EquivocationProof,
    ) -> crate::error::Result<()> {
        if !proof.verify()? {
            return Err(crate::error::Failure::Protocol(
                "refusing unverified equivocation proof".to_owned(),
            ));
        }
        let mut guard = self.inner.write().map_err(|_| {
            crate::error::Failure::Protocol("tree head tracker lock poisoned".to_owned())
        })?;
        if !guard.equivocations.contains(&proof) {
            guard.equivocations.push(proof);
        }
        Ok(())
    }

    /// Verify `incoming` against the pinned tree head for `(peer, incoming.scope)`.
    ///
    /// Returns `Ok(None)` when consistent (advancing the pin if larger), or
    /// `Ok(Some(proof))` when equivocation is cryptographically detected.
    pub fn observe(
        &self,
        peer: iroh::EndpointId,
        incoming: &SignedTreeHead,
        consistency_proof: Option<&WireConsistencyProof>,
    ) -> crate::error::Result<Option<EquivocationProof>> {
        let origin = incoming.verify_signature()?;
        if origin != peer {
            return Err(crate::error::Failure::CapabilityDenied(format!(
                "SignedTreeHead origin {origin} does not match peer {peer}"
            )));
        }
        let key = (peer, incoming.scope.clone());
        let prior = {
            let guard = self.inner.read().map_err(|_| {
                crate::error::Failure::Protocol("tree head tracker lock poisoned".to_owned())
            })?;
            guard.pinned.get(&key).cloned()
        };
        let Some(prior_sth) = prior else {
            let mut guard = self.inner.write().map_err(|_| {
                crate::error::Failure::Protocol("tree head tracker lock poisoned".to_owned())
            })?;
            guard.pinned.insert(key, incoming.clone());
            return Ok(None);
        };
        if prior_sth.vault_id != incoming.vault_id {
            return Err(crate::error::Failure::Protocol(format!(
                "peer {peer} switched vault_id from {} to {}",
                prior_sth.vault_id, incoming.vault_id
            )));
        }
        let is_consistent = verify_transition(&prior_sth, incoming, consistency_proof)?;
        if is_consistent {
            if incoming.tree_size > prior_sth.tree_size {
                let mut guard = self.inner.write().map_err(|_| {
                    crate::error::Failure::Protocol("tree head tracker lock poisoned".to_owned())
                })?;
                guard.pinned.insert(key, incoming.clone());
            }
            return Ok(None);
        }
        let eq_proof =
            EquivocationProof::new(prior_sth, incoming.clone(), consistency_proof.cloned());
        let mut guard = self.inner.write().map_err(|_| {
            crate::error::Failure::Protocol("tree head tracker lock poisoned".to_owned())
        })?;
        guard.equivocations.push(eq_proof.clone());
        Ok(Some(eq_proof))
    }
}

fn verify_transition(
    prior: &SignedTreeHead,
    incoming: &SignedTreeHead,
    consistency_proof: Option<&WireConsistencyProof>,
) -> crate::error::Result<bool> {
    let prior_root = prior.root_bytes()?;
    let incoming_root = incoming.root_bytes()?;
    if prior.tree_size == incoming.tree_size {
        return Ok(prior_root == incoming_root);
    }
    let (old_size, old_root, new_size, new_root) = if prior.tree_size < incoming.tree_size {
        (
            prior.tree_size,
            prior_root,
            incoming.tree_size,
            incoming_root,
        )
    } else {
        (
            incoming.tree_size,
            incoming_root,
            prior.tree_size,
            prior_root,
        )
    };
    let Some(proof) = consistency_proof else {
        return Ok(false);
    };
    if proof.old_size != old_size || proof.new_size != new_size {
        return Ok(false);
    }
    proof.verify(old_root, new_root)
}

struct SthFields<'a> {
    vault_id: &'a str,
    scope: &'a str,
    tree_size: u64,
    root_hex: &'a str,
    head_revision: &'a str,
    eligibility_generation: u64,
    origin: iroh::EndpointId,
}

fn canonical_sth_bytes(fields: SthFields<'_>) -> crate::error::Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(STH_SIGNING_DOMAIN);
    push_lp(&mut out, fields.vault_id.as_bytes())?;
    push_lp(&mut out, fields.scope.as_bytes())?;
    out.extend_from_slice(&fields.tree_size.to_le_bytes());
    push_lp(&mut out, fields.root_hex.as_bytes())?;
    push_lp(&mut out, fields.head_revision.as_bytes())?;
    out.extend_from_slice(&fields.eligibility_generation.to_le_bytes());
    out.extend_from_slice(fields.origin.as_bytes());
    Ok(out)
}

fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) -> crate::error::Result<()> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| crate::error::Failure::Protocol("STH field exceeds u32 length".to_owned()))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn encode_hex(bytes: &[u8; DIGEST_LEN]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(HEX_DIGEST_LEN);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn decode_hex_32(text: &str) -> crate::error::Result<[u8; DIGEST_LEN]> {
    if text.len() != HEX_DIGEST_LEN || !mneme_kernel::text::is_lower_hex(text.as_bytes()) {
        return Err(crate::error::Failure::Protocol(format!(
            "expected 64 lowercase hex chars, got length {}",
            text.len()
        )));
    }
    let bytes = text.as_bytes();
    let mut out = [0_u8; DIGEST_LEN];
    for (slot, pair) in out.iter_mut().zip(bytes.as_chunks::<2>().0) {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> crate::error::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte.saturating_sub(b'0')),
        b'a'..=b'f' => Ok(byte.saturating_sub(b'a').saturating_add(10)),
        _ => Err(crate::error::Failure::Protocol(
            "invalid lowercase hex nibble".to_owned(),
        )),
    }
}
