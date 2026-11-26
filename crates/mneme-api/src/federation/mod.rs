//! Read-only, revision-pinned remote vault federation over `irpc`.

pub mod client;
pub mod protocol;
pub mod quinn;
pub mod server;

pub use client::{
    AttachmentTarget, FederationError, ParsedAttachment, RemoteDatalogRequest,
    RemoteViewFetchOptions, VaultFederationClient, parse_attachment_spec,
};
pub use protocol::{
    FEDERATION_ALPN, FederationLimits, HeadState, PROTOCOL_VERSION, PinnedSnapshotPayload,
    RemoteCoverage, RemoteDatalogResult, RemoteDerivation, RemotePremise, RemoteQueryRow, RpcError,
    RpcErrorCode, StalePolicy, VaultFederationMessage, VaultFederationProtocol, VaultMetadata,
};
pub use quinn::{
    authenticated_peer_id, make_authenticated_client_endpoint, make_authenticated_server_endpoint,
};
pub use server::{IrohFederationHandler, PeerAllowlist, ServerConfig, VaultFederationServer};
