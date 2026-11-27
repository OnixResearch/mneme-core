//! Error types for Mneme Iroh peer sync.

/// Sync operation failures.
#[derive(Debug, thiserror::Error)]
pub enum Failure {
    /// Peer is not present in the local Ed25519 allowlist.
    #[error("peer {0} is not in the local allowlist")]
    UnauthorizedPeer(String),
    /// Peer is allowlisted, but not for the requested scope.
    #[error("peer {peer} is not authorized for scope {scope}")]
    ScopeDenied { peer: String, scope: String },
    /// Presented capability token failed verification or attenuation checks.
    #[error("capability denied: {0}")]
    CapabilityDenied(String),
    /// Capability token or an ancestor delegation link was revoked.
    #[error("capability {token_id} revoked: {reason}")]
    CapabilityRevoked { token_id: String, reason: String },
    /// OS CSPRNG failed when generating a cryptographic identifier.
    #[error("CSPRNG failure: {0}")]
    CsprngUnavailable(String),
    /// Transport or QUIC connection failure.
    #[error("iroh transport error: {0}")]
    Transport(String),
    /// Sync control or gossip protocol failure.
    #[error("sync protocol error: {0}")]
    Protocol(String),
    /// Underlying store validation, commit, or restore failure.
    #[error(transparent)]
    Store(#[from] mneme_store::Failure),
    /// Post-pull workspace verification failed closed.
    #[error("workspace verification failed after sync: {0}")]
    VerificationFailed(String),
    /// Peer signed conflicting history tree heads (split view or history rewrite).
    #[error("equivocation detected from peer {peer} on scope {scope}")]
    EquivocationDetected {
        peer: String,
        scope: String,
        proof: Box<crate::transparency::EquivocationProof>,
    },
    /// Payload or archive exceeds configured transfer bounds.
    #[error("transfer size {actual_bytes} bytes exceeds bound {limit_bytes} bytes")]
    SizeLimitExceeded { actual_bytes: u64, limit_bytes: u64 },
    /// Invalid sync configuration or persisted state.
    #[error("invalid sync configuration: {0}")]
    InvalidConfig(String),
    /// Local filesystem I/O failure.
    #[error("sync I/O error: {0}")]
    Io(String),
}

/// Convenience result alias for sync operations.
pub type Result<T> = std::result::Result<T, Failure>;
