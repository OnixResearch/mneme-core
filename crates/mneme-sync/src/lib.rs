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
pub mod error;
pub mod node;
pub mod protocol;
pub mod state;
pub mod trust;

pub use bundle::{
    ExportedSyncBundle, IngestedWorkspace, PullDisposition, export_scope_to_store,
    ingest_downloaded_archive,
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
