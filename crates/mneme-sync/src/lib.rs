//! Mneme Iroh peer-to-peer verified blob & revision-bundle sync.
//!
//! Iroh is used strictly for transport (`iroh`), verified BLAKE3 blob/bundle
//! replication (`iroh-blobs`), local-first LAN/DHT address discovery
//! (`iroh-mdns-address-lookup` / `iroh-mainline-address-lookup`), Range-Based
//! Set Reconciliation over `/mneme/sync/1` (`rbsr`), and lightweight
//! head-revision gossip (`iroh-gossip`). Mneme's SQLite ledger, portable
//! restore/commit pipeline, and `verify_workspace` remain the sole source of
//! truth.

#![allow(unknown_lints, type_accumulation)] // intentional crate-root convenience re-exports
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))] // tests fail via panic rather than Result

pub mod blobstore;
pub mod bundle;
pub mod capability;
pub mod error;
pub mod node;
pub mod protocol;
pub mod rbsr;
pub mod state;
pub mod trust;

pub use blobstore::{DiskBlobEntry, DiskBlobStore, DiskBlobsProtocol, DownloadedBlob};
pub use bundle::{
    ExportedSyncBundle, IngestedWorkspace, PullDisposition, collect_local_rbsr_set,
    export_scope_to_store, ingest_delta_to_workspace, ingest_downloaded_archive,
};
pub use capability::{
    CAPABILITY_SCHEMA, CAPABILITY_STORE_SCHEMA, CapabilityAuthority, CapabilityLink,
    CapabilityScope, CapabilitySignature, CapabilityStore, CapabilityToken, DelegateRequest,
    GrantRequest, LeaseEvictionContext, LeaseScopeQuery, LeaseVaultScopeQuery,
    MAX_AUTHORIZED_ISSUERS, MAX_CAPABILITY_BYTES, MAX_CLOCK_SKEW_SECS, MAX_DELEGATION_DEPTH,
    MAX_LEASED_PEERS, MAX_LEASES_PER_PEER, MAX_REVOCATION_REASON_BYTES, MAX_REVOCATION_SET_BYTES,
    MAX_REVOCATION_TOMBSTONES, MAX_REVOCATIONS_PER_PAGE, REVOCATION_SET_SCHEMA,
    RevocationInsertOutcome, RevocationSet, RevocationTombstone, RootTrustPolicy,
    SharedAuthorizedIssuers, SharedCapabilityLeases, SharedRevocationSet, StoredCapability,
    TokenId, TombstoneId, VerificationRequest, VerifiedCapability, VerifiedLease,
    generate_token_id, generate_tombstone_id, timestamp_to_epoch_secs, verify_capability,
    verify_capability_with_policy,
};
pub use error::{Failure, Result};
pub use node::{
    PullOutcome, PullRequest, SyncNode, SyncNodeConfig, SyncTransferStats, VaultGossipTopic,
    WorkspaceConfigFactory,
};
pub use protocol::{
    AllowlistedProtocol, BlobDigestRef, CONTROL_STREAM_TIMEOUT_SECS, DiscoveryMode,
    HeadAnnouncement, MAX_CONCURRENT_CONTROL_CONNECTIONS, MAX_CONCURRENT_TRANSPORT_CONNECTIONS,
    MAX_CONTROL_MESSAGE_BYTES, MAX_DELTA_ITEMS_PER_REQUEST, MAX_GOSSIP_MESSAGE_BYTES,
    MAX_SYNC_BUNDLE_BYTES, MAX_UNAUTHENTICATED_CONTROL_BYTES, RelayPreference, SYNC_CONTROL_ALPN,
    VaultSnapshotInfo, WireDigest, WireHlc, parse_scope_id,
};
pub use rbsr::{
    MAX_RBSR_BRANCHING, MAX_RBSR_DEPTH, MAX_RBSR_FRAME_BYTES, MAX_RBSR_ITEMS_PER_LEAF,
    MAX_RBSR_RANGES_PER_FRAME, MAX_RBSR_ROUNDS, PendingRange, RBSR_LEAF_THRESHOLD, RangeBound,
    RbsrFingerprint, RbsrItemKind, RbsrKey, RbsrOutcome, RbsrProbe, RbsrQueryRange, RbsrRequest,
    RbsrResolution, RbsrResponse, RbsrSession, RbsrSet, RbsrSubrange, reconcile_in_memory,
};
pub use state::{SyncPaths, SyncReceipt, SyncState, resolve_vault_id, topic_id_for_vault};
pub use trust::{
    AllowedPeer, PeerAllowlist, ScopeAllowance, SharedAllowlist, generate_secret_key,
    load_or_create_secret_key, parse_endpoint_id,
};
