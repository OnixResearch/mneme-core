//! Read-only, revision-pinned remote vault federation over `irpc`.
#![allow(unknown_lints, type_accumulation)] // federation module root convenience re-exports

pub mod auth;
pub mod client;
pub mod protocol;
pub mod quinn;
pub mod server;

pub use auth::{
    CAPABILITY_SCHEMA, CapabilityAuthority, CapabilityLink, CapabilityScope, CapabilitySignature,
    CapabilityToken, GrantParams, MAX_CAPABILITY_BYTES, MAX_CLOCK_SKEW_SECS, MAX_DELEGATION_DEPTH,
    MAX_REVOCATION_REASON_BYTES, MAX_REVOCATION_TOMBSTONES, PeerAllowlist, RevocationParams,
    RevocationSet, RevocationTombstone, ScopeGrant, SharedFederationAuthorizer, TokenId,
    TombstoneId,
};
pub use client::{
    AttachmentTarget, FederationError, ParsedAttachment, RemoteDatalogRequest,
    RemoteViewFetchOptions, VaultFederationClient, parse_attachment_spec,
};
pub use protocol::{
    CalmSeal, CalmSealSignature, FEDERATION_ALPN, FederationLimits, HeadState, PROTOCOL_VERSION,
    PinnedSnapshotPayload, RemoteCoverage, RemoteDatalogResult, RemoteDerivation, RemotePremise,
    RemoteQueryRow, RpcError, RpcErrorCode, StalePolicy, VaultFederationMessage,
    VaultFederationProtocol, VaultMetadata, WireHybridTimestamp, scoped_manifest_digest,
};
pub use quinn::{
    authenticated_peer_id, make_authenticated_client_endpoint, make_authenticated_server_endpoint,
    make_authenticated_server_endpoint_with_authorizer,
};
pub use server::{IrohFederationHandler, ServerConfig, VaultFederationServer};
