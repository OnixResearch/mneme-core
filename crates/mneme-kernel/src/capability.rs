//! Convergent capability attenuation and G-Set revocation dominance rules.
//!
//! Capabilities form Ed25519-signed delegation chains whose cryptographic
//! verification lives in the imperative shells (`mneme-sync` and `mneme-api`).
//! This module proves the pure policy invariants:
//! - authority, scope, expiration, vault binding, and delegation depth attenuate
//!   monotonically across every link (so no leaf can ever exceed the root);
//! - G-Set revocation checks and merges are commutative, associative,
//!   idempotent, and monotone (once revoked, never un-revoked).

/// Ordered authority lattice for sync and remote federation capabilities
/// (`ReadOnly < SyncPull < SyncPush`).
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum Authority {
    /// Read-only snapshot metadata and query inspection.
    ReadOnly,
    /// Read-only inspection plus pulling verified bundles/blobs.
    SyncPull,
    /// Full sync pull authority plus pushing/announcing head revisions.
    SyncPush,
}

/// Monotonic numeric rank of an authority level (`1..=3`).
pub fn authority_rank(level: Authority) -> u8 {
    match level {
        Authority::ReadOnly => 1,
        Authority::SyncPull => 2,
        Authority::SyncPush => 3,
    }
}

/// Whether `held` authority satisfies `required` authority (`held >= required`).
pub fn authority_permits(held: Authority, required: Authority) -> bool {
    authority_rank(held) >= authority_rank(required)
}

/// Whether delegating from `parent` to `child` is non-escalating (`child <= parent`).
pub fn authority_attenuates(parent: Authority, child: Authority) -> bool {
    authority_rank(child) <= authority_rank(parent)
}

/// Scope mode of a capability link (`Wildcard` or explicit scope digests).
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum ScopeMode {
    /// Matches any valid scope (`scope:*`).
    Wildcard,
    /// Restricted to an explicit non-empty set of scope digests.
    Explicit,
}

/// Whether `needle` occurs in `haystack`.
pub fn digest_in_slice(
    needle: &crate::hashing::Digest,
    haystack: &[crate::hashing::Digest],
) -> bool {
    let mut found = false;
    let mut index = 0_usize;
    while index < haystack.len() && !found {
        found = crate::hashing::digest_eq(needle, &haystack[index]);
        index += 1;
    }
    found
}

/// Whether every digest in `child` occurs in `parent`.
pub fn slice_is_subset(
    child: &[crate::hashing::Digest],
    parent: &[crate::hashing::Digest],
) -> bool {
    let mut all_present = true;
    let mut index = 0_usize;
    while index < child.len() && all_present {
        all_present = digest_in_slice(&child[index], parent);
        index += 1;
    }
    all_present
}

/// Whether `(child_mode, child_scopes)` is a valid non-escalating attenuation
/// of `(parent_mode, parent_scopes)`.
///
/// Explicit scope sets must be non-empty; a wildcard parent permits any valid
/// child scope, while an explicit parent never permits a wildcard child.
pub fn scope_subset(
    child_mode: ScopeMode,
    child_scopes: &[crate::hashing::Digest],
    parent_mode: ScopeMode,
    parent_scopes: &[crate::hashing::Digest],
) -> bool {
    match (child_mode, parent_mode) {
        (ScopeMode::Wildcard, ScopeMode::Wildcard) => true,
        (ScopeMode::Explicit, ScopeMode::Wildcard) => !child_scopes.is_empty(),
        (ScopeMode::Wildcard, ScopeMode::Explicit) => false,
        (ScopeMode::Explicit, ScopeMode::Explicit) => {
            !child_scopes.is_empty()
                && !parent_scopes.is_empty()
                && slice_is_subset(child_scopes, parent_scopes)
        }
    }
}

/// Pure policy summary of one capability delegation link.
#[derive(Clone, Copy)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct LinkPolicy {
    /// Content digest of the vault identifier this link is bound to.
    pub vault_id: crate::hashing::Digest,
    /// Authority level granted by this link.
    pub authority: Authority,
    /// Scope mode (`Wildcard` or `Explicit`).
    pub scope_mode: ScopeMode,
    /// Expiration timestamp in Unix epoch seconds.
    pub expires_at: u64,
    /// Remaining delegations allowed beneath this link.
    pub remaining_depth: u8,
}

/// Whether delegating from `parent` to `child` at chain depth `depth` (within
/// `max_depth`) satisfies every monotonic attenuation invariant.
pub fn attenuation_valid(
    parent: &LinkPolicy,
    parent_scopes: &[crate::hashing::Digest],
    child: &LinkPolicy,
    child_scopes: &[crate::hashing::Digest],
    depth: u8,
    max_depth: u8,
) -> bool {
    crate::hashing::digest_eq(&child.vault_id, &parent.vault_id)
        && authority_attenuates(parent.authority, child.authority)
        && scope_subset(
            child.scope_mode,
            child_scopes,
            parent.scope_mode,
            parent_scopes,
        )
        && child.expires_at <= parent.expires_at
        && child.remaining_depth < parent.remaining_depth
        && depth <= max_depth
}

/// Join-semilattice state of a capability chain under G-Set revocations.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum RevocationState {
    /// No link in the chain is revoked.
    Active,
    /// At least one link in the chain is revoked (absorbing top element).
    Revoked,
}

/// Whether a 128-bit token identifier is present in `revocations`.
pub fn token_in_revocations(token: u128, revocations: &[u128]) -> bool {
    let mut found = false;
    let mut index = 0_usize;
    while index < revocations.len() && !found {
        found = token == revocations[index];
        index += 1;
    }
    found
}

/// Whether any token identifier in `chain_ids` is present in `revocations`.
pub fn is_revoked(chain_ids: &[u128], revocations: &[u128]) -> bool {
    let mut revoked = false;
    let mut index = 0_usize;
    while index < chain_ids.len() && !revoked {
        revoked = token_in_revocations(chain_ids[index], revocations);
        index += 1;
    }
    revoked
}

/// Classify `chain_ids` against `revocations` in the revocation join-semilattice.
pub fn revocation_state(chain_ids: &[u128], revocations: &[u128]) -> RevocationState {
    if is_revoked(chain_ids, revocations) {
        RevocationState::Revoked
    } else {
        RevocationState::Active
    }
}

/// Join two revocation states in the G-Set CRDT semilattice (`Revoked` dominates).
pub fn merge_revocation_state(left: RevocationState, right: RevocationState) -> RevocationState {
    match (left, right) {
        (RevocationState::Revoked, _) => RevocationState::Revoked,
        (_, RevocationState::Revoked) => RevocationState::Revoked,
        (RevocationState::Active, RevocationState::Active) => RevocationState::Active,
    }
}

/// Whether `chain_ids` is revoked under the G-Set union of `left` and `right`.
pub fn is_revoked_in_merge(chain_ids: &[u128], left: &[u128], right: &[u128]) -> bool {
    matches!(
        merge_revocation_state(
            revocation_state(chain_ids, left),
            revocation_state(chain_ids, right),
        ),
        RevocationState::Revoked
    )
}
