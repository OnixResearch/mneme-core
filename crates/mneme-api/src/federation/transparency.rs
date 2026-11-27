//! Wire transparency types (`WireSignedTreeHead`, `WireConsistencyProof`,
//! `WireInclusionProof`, `WireEquivocationProof`) for read-only vault federation.

const FED_STH_DOMAIN: &[u8] = b"mneme.federation.sth.v1\0";
const DIGEST_LEN: usize = 32;
const REVISION_LEN: usize = 16;
const ED25519_SIG_LEN: usize = 64;

/// Ed25519-signed Crosby-Wallach history tree head attached to federation responses.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WireSignedTreeHead {
    pub scope: String,
    pub tree_size: u64,
    pub root: [u8; DIGEST_LEN],
    pub head_revision: [u8; REVISION_LEN],
    pub eligibility_generation: u64,
    pub signer: [u8; DIGEST_LEN],
    pub signature: Vec<u8>,
}

impl WireSignedTreeHead {
    /// Sign `head` for `scope` with `signing_key`.
    pub fn sign(
        scope: &str,
        head: mneme_store::HistoryTreeHead,
        signing_key: &iroh::SecretKey,
    ) -> Self {
        let signer = *signing_key.public().as_bytes();
        let payload = canonical_fed_sth_bytes(FedSthFields {
            scope,
            tree_size: head.tree_size,
            root: head.root,
            head_revision: *head.head_revision.as_bytes(),
            eligibility_generation: head.eligibility_generation,
            signer,
        });
        let signature = signing_key.sign(&payload).to_bytes().to_vec();
        Self {
            scope: scope.to_owned(),
            tree_size: head.tree_size,
            root: head.root,
            head_revision: *head.head_revision.as_bytes(),
            eligibility_generation: head.eligibility_generation,
            signer,
            signature,
        }
    }

    /// Verify the Ed25519 signature and return the authenticated signer `EndpointId`.
    pub fn verify_signature(&self) -> Result<iroh::EndpointId, super::protocol::RpcError> {
        if self.tree_size == 0 {
            return Err(super::protocol::RpcError::new(
                super::protocol::RpcErrorCode::ProtocolError,
                "signed tree head has zero tree_size",
            ));
        }
        let signer = iroh::EndpointId::from_bytes(&self.signer).map_err(|_| {
            super::protocol::RpcError::new(
                super::protocol::RpcErrorCode::ProtocolError,
                "invalid Ed25519 signer public key on signed tree head",
            )
        })?;
        let sig_bytes =
            <[u8; ED25519_SIG_LEN]>::try_from(self.signature.as_slice()).map_err(|_| {
                super::protocol::RpcError::new(
                    super::protocol::RpcErrorCode::ProtocolError,
                    "invalid Ed25519 signature length on signed tree head",
                )
            })?;
        let signature = iroh::Signature::from_bytes(&sig_bytes);
        let payload = canonical_fed_sth_bytes(FedSthFields {
            scope: &self.scope,
            tree_size: self.tree_size,
            root: self.root,
            head_revision: self.head_revision,
            eligibility_generation: self.eligibility_generation,
            signer: self.signer,
        });
        signer.verify(&payload, &signature).map_err(|_| {
            super::protocol::RpcError::new(
                super::protocol::RpcErrorCode::ProtocolError,
                "invalid Ed25519 signature on federation signed tree head",
            )
        })?;
        Ok(signer)
    }
}

/// Compact wire consistency proof attached to `HeadState`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WireConsistencyProof {
    pub old_size: u64,
    pub new_size: u64,
    pub nodes: Vec<[u8; DIGEST_LEN]>,
}

impl WireConsistencyProof {
    /// Convert from a store [`mneme_store::ConsistencyProof`].
    pub fn from_store(proof: &mneme_store::ConsistencyProof) -> Self {
        Self {
            old_size: proof.old_size,
            new_size: proof.new_size,
            nodes: proof.nodes.clone(),
        }
    }

    /// Verify against `(old_root, new_root)` via the Lean-proved kernel.
    pub fn verify(&self, old_root: [u8; DIGEST_LEN], new_root: [u8; DIGEST_LEN]) -> bool {
        let proof = mneme_store::ConsistencyProof {
            old_size: self.old_size,
            new_size: self.new_size,
            nodes: self.nodes.clone(),
        };
        proof.verify(old_root, new_root)
    }
}

/// Compact wire inclusion proof attached to `PinnedSnapshotPayload`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WireInclusionProof {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub leaf_digest: [u8; DIGEST_LEN],
    pub audit_path: Vec<[u8; DIGEST_LEN]>,
}

impl WireInclusionProof {
    /// Convert from a store [`mneme_store::InclusionProof`].
    pub fn from_store(proof: &mneme_store::InclusionProof) -> Self {
        Self {
            leaf_index: proof.leaf_index,
            tree_size: proof.tree_size,
            leaf_digest: proof.leaf_digest,
            audit_path: proof.audit_path.clone(),
        }
    }

    /// Verify against `expected_root` via the Lean-proved kernel.
    pub fn verify(&self, expected_root: [u8; DIGEST_LEN]) -> bool {
        let proof = mneme_store::InclusionProof {
            leaf_index: self.leaf_index,
            tree_size: self.tree_size,
            leaf_digest: self.leaf_digest,
            audit_path: self.audit_path.clone(),
        };
        proof.verify(expected_root)
    }
}

/// Self-verifying federation equivocation proof (`sth_first`, `sth_second`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WireEquivocationProof {
    pub sth_first: WireSignedTreeHead,
    pub sth_second: WireSignedTreeHead,
    pub consistency_proof: Option<WireConsistencyProof>,
}

impl WireEquivocationProof {
    /// Self-verify both signatures and prove equivocation via the Lean-proved kernel.
    pub fn verify(&self) -> bool {
        let Ok(origin_first) = self.sth_first.verify_signature() else {
            return false;
        };
        let Ok(origin_second) = self.sth_second.verify_signature() else {
            return false;
        };
        if origin_first != origin_second || self.sth_first.scope != self.sth_second.scope {
            return false;
        }
        let (smaller, larger) = if self.sth_first.tree_size <= self.sth_second.tree_size {
            (&self.sth_first, &self.sth_second)
        } else {
            (&self.sth_second, &self.sth_first)
        };
        let consistency = if smaller.tree_size == larger.tree_size {
            mneme_kernel::history_tree::ConsistencyVerdict::Consistent
        } else {
            match &self.consistency_proof {
                Some(proof)
                    if proof.old_size == smaller.tree_size
                        && proof.new_size == larger.tree_size
                        && proof.verify(smaller.root, larger.root) =>
                {
                    mneme_kernel::history_tree::ConsistencyVerdict::Consistent
                }
                Some(_) | None => mneme_kernel::history_tree::ConsistencyVerdict::Inconsistent,
            }
        };
        let facts = mneme_kernel::history_tree::EquivocationFacts {
            is_both_signed_same_origin: true,
            first_size: smaller.tree_size,
            first_root: mneme_store::digest_to_kernel(smaller.root),
            second_size: larger.tree_size,
            second_root: mneme_store::digest_to_kernel(larger.root),
            consistency,
        };
        mneme_kernel::history_tree::equivocation_detected(facts)
    }
}

/// Client-side per-scope pinned [`WireSignedTreeHead`] tracker.
#[derive(Clone, Default, Debug)]
pub struct ClientTreeHeadPins {
    inner: std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<String, WireSignedTreeHead>>>,
}

impl ClientTreeHeadPins {
    /// Construct an empty client tree-head pin table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Known pinned tree size for `scope`, if any.
    pub fn known_size(&self, scope: &str) -> Option<u64> {
        let guard = self.inner.lock().ok()?;
        guard.get(scope).map(|sth| sth.tree_size)
    }

    /// Verify and pin an incoming [`WireSignedTreeHead`] for `scope`, rejecting equivocation.
    pub fn observe(
        &self,
        scope: &str,
        incoming: &WireSignedTreeHead,
        consistency: Option<&WireConsistencyProof>,
    ) -> Result<(), super::client::FederationError> {
        let incoming_origin = incoming
            .verify_signature()
            .map_err(super::client::FederationError::from)?;
        if incoming.scope != scope {
            return Err(super::client::FederationError::ProtocolError(format!(
                "signed tree head scope '{}' does not match requested '{scope}'",
                incoming.scope
            )));
        }
        let mut guard = self.inner.lock().map_err(|_| {
            super::client::FederationError::ProtocolError(
                "client tree-head tracker mutex poisoned".to_owned(),
            )
        })?;
        let Some(prior) = guard.get(scope).cloned() else {
            guard.insert(scope.to_owned(), incoming.clone());
            return Ok(());
        };
        let prior_origin = prior
            .verify_signature()
            .map_err(super::client::FederationError::from)?;
        if prior_origin != incoming_origin {
            return Err(super::client::FederationError::EquivocationDetected(
                format!("federation signer changed for scope {scope}"),
            ));
        }
        let is_consistent = if prior.tree_size == incoming.tree_size {
            prior.root == incoming.root
        } else {
            let (old_size, old_root, new_size, new_root) = if prior.tree_size < incoming.tree_size {
                (
                    prior.tree_size,
                    prior.root,
                    incoming.tree_size,
                    incoming.root,
                )
            } else {
                (
                    incoming.tree_size,
                    incoming.root,
                    prior.tree_size,
                    prior.root,
                )
            };
            consistency.is_some_and(|proof| {
                proof.old_size == old_size
                    && proof.new_size == new_size
                    && proof.verify(old_root, new_root)
            })
        };
        if !is_consistent {
            return Err(super::client::FederationError::EquivocationDetected(
                format!(
                    "consistency check failed for scope {scope} (prior size={}, incoming size={})",
                    prior.tree_size, incoming.tree_size
                ),
            ));
        }
        if incoming.tree_size > prior.tree_size {
            guard.insert(scope.to_owned(), incoming.clone());
        }
        Ok(())
    }
}

struct FedSthFields<'a> {
    scope: &'a str,
    tree_size: u64,
    root: [u8; DIGEST_LEN],
    head_revision: [u8; REVISION_LEN],
    eligibility_generation: u64,
    signer: [u8; DIGEST_LEN],
}

fn canonical_fed_sth_bytes(fields: FedSthFields<'_>) -> Vec<u8> {
    let scope_bytes = fields.scope.as_bytes();
    let mut out = Vec::new();
    out.extend_from_slice(FED_STH_DOMAIN);
    out.extend_from_slice(&(scope_bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(scope_bytes);
    out.extend_from_slice(&fields.tree_size.to_le_bytes());
    out.extend_from_slice(&fields.root);
    out.extend_from_slice(&fields.head_revision);
    out.extend_from_slice(&fields.eligibility_generation.to_le_bytes());
    out.extend_from_slice(&fields.signer);
    out
}
