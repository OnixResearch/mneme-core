//! Mneme Iroh peer-to-peer verified blob & revision-bundle sync.
//!
//! Iroh is used strictly for transport (`iroh`), verified BLAKE3 blob/bundle
//! replication (`iroh-blobs`), local-first LAN/DHT address discovery
//! (`iroh-mdns-address-lookup` / `iroh-mainline-address-lookup`), and
//! lightweight head-revision gossip (`iroh-gossip`). Mneme's SQLite ledger,
//! portable restore/commit pipeline, and `verify_workspace` remain the sole
//! source of truth.

#![allow(unknown_lints, type_accumulation)] // intentional crate-root convenience re-exports
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))] // tests fail via panic rather than Result

pub mod bundle;
pub mod capability;
pub mod error;
pub mod node;
pub mod protocol;
pub mod state;
pub mod trust;

pub use bundle::{
    ExportedSyncBundle, IngestedWorkspace, PullDisposition, export_scope_to_store,
    ingest_downloaded_archive,
};
pub use capability::{
    CAPABILITY_SCHEMA, CAPABILITY_STORE_SCHEMA, CapabilityAuthority, CapabilityLink,
    CapabilityScope, CapabilitySignature, CapabilityStore, CapabilityToken, DelegateRequest,
    GrantRequest, LeaseScopeQuery, MAX_CAPABILITY_BYTES, MAX_DELEGATION_DEPTH,
    MAX_REVOCATION_REASON_BYTES, MAX_REVOCATION_SET_BYTES, REVOCATION_SET_SCHEMA,
    RevocationInsertOutcome, RevocationSet, RevocationTombstone, RootTrustPolicy,
    SharedCapabilityLeases, SharedRevocationSet, StoredCapability, TokenId, TombstoneId,
    VerificationRequest, VerifiedCapability, VerifiedLease, generate_token_id,
    generate_tombstone_id, timestamp_to_epoch_secs, verify_capability,
    verify_capability_with_policy,
};
pub use error::{Failure, Result};
pub use node::{
    PullOutcome, PullRequest, SyncNode, SyncNodeConfig, VaultGossipTopic, WorkspaceConfigFactory,
};
pub use protocol::{
    AllowlistedProtocol, BlobDigestRef, DiscoveryMode, HeadAnnouncement, MAX_CONTROL_MESSAGE_BYTES,
    MAX_GOSSIP_MESSAGE_BYTES, MAX_SYNC_BUNDLE_BYTES, RelayPreference, SYNC_CONTROL_ALPN,
    VaultSnapshotInfo, WireDigest, parse_scope_id,
};
pub use state::{SyncPaths, SyncReceipt, SyncState, resolve_vault_id, topic_id_for_vault};
pub use trust::{
    AllowedPeer, PeerAllowlist, ScopeAllowance, SharedAllowlist, generate_secret_key,
    load_or_create_secret_key, parse_endpoint_id,
};
