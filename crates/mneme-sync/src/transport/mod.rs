//! Narrow transport abstraction separating Mneme sync protocol logic from Iroh QUIC I/O.
//!
//! [`IrohTransport`] is the thin production implementation backed by `iroh`,
//! `iroh-blobs`, and `iroh-gossip`. Deterministic simulation (`crate::sim`)
//! supplies an in-process single-threaded implementation over the exact same
//! [`SyncTransport`] boundary.

#![allow(unknown_lints, path_segment_repetition)] // SyncTransport and IrohTransport are the public domain names required by the protocol design

use n0_future::StreamExt;

/// Boxed future type returned by [`SyncTransport`] async operations.
pub type BoxTransportFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = crate::error::Result<T>> + Send + 'a>>;

/// Parameters for fetching one verified content-addressed blob from a peer.
#[derive(Clone, Copy, Debug)]
pub struct BlobFetchRequest<'a> {
    pub peer: iroh::EndpointId,
    pub hash: iroh_blobs::Hash,
    pub max_bytes: u64,
    pub target_path: &'a std::path::Path,
    pub extra_algorithm: Option<mneme_core::HashAlgorithm>,
}

/// Narrow transport boundary for control RPC, verified blob transfer, and vault gossip.
pub trait SyncTransport: Send + Sync {
    /// Send one framed `/mneme/sync/1` control request and read the framed response bytes.
    fn control_roundtrip<'a>(
        &'a self,
        peer: iroh::EndpointId,
        request_bytes: &'a [u8],
    ) -> BoxTransportFuture<'a, Vec<u8>>;

    /// Fetch one verified content-addressed blob from `peer` into `request.target_path`.
    fn fetch_blob<'a>(
        &'a self,
        request: &'a BlobFetchRequest<'a>,
    ) -> BoxTransportFuture<'a, crate::blobstore::DownloadedBlob>;

    /// Register a local staged blob file for serving to authorized peers.
    fn put_blob(
        &self,
        source_path: &std::path::Path,
        max_bytes: u64,
    ) -> crate::error::Result<(iroh_blobs::Hash, u64)>;

    /// Broadcast one encoded gossip payload on `vault_id`'s topic.
    fn gossip_broadcast<'a>(
        &'a self,
        vault_id: &'a str,
        payload: bytes::Bytes,
    ) -> BoxTransportFuture<'a, ()>;

    /// Receive the next raw gossip payload from `vault_id`'s topic, if subscribed.
    fn gossip_recv<'a>(&'a self, vault_id: &'a str)
    -> BoxTransportFuture<'a, Option<bytes::Bytes>>;
}

type TopicSlot = std::sync::Arc<tokio::sync::Mutex<iroh_gossip::GossipTopic>>;

/// Production [`SyncTransport`] backed by `iroh::Endpoint`, [`crate::blobstore::DiskBlobStore`],
/// and `iroh_gossip::Gossip`.
#[derive(Clone)]
pub struct IrohTransport {
    endpoint: iroh::Endpoint,
    blobs: crate::blobstore::DiskBlobStore,
    gossip: iroh_gossip::Gossip,
    topics: std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<String, TopicSlot>>>,
}

impl std::fmt::Debug for IrohTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrohTransport")
            .field("node_id", &self.endpoint.id())
            .finish()
    }
}

impl IrohTransport {
    /// Wrap an existing Iroh endpoint, disk blob store, and gossip actor.
    pub fn new(
        endpoint: iroh::Endpoint,
        blobs: crate::blobstore::DiskBlobStore,
        gossip: iroh_gossip::Gossip,
    ) -> Self {
        Self {
            endpoint,
            blobs,
            gossip,
            topics: std::sync::Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new())),
        }
    }

    /// Return the local peer's Ed25519 identity.
    pub fn node_id(&self) -> iroh::EndpointId {
        self.endpoint.id()
    }

    /// Return the local endpoint's address info.
    pub fn addr(&self) -> iroh::EndpointAddr {
        self.endpoint.addr()
    }

    /// Access the underlying `iroh::Endpoint`.
    pub const fn endpoint(&self) -> &iroh::Endpoint {
        &self.endpoint
    }

    /// Access the underlying [`crate::blobstore::DiskBlobStore`].
    pub const fn blob_store(&self) -> &crate::blobstore::DiskBlobStore {
        &self.blobs
    }

    /// Access the underlying `iroh_gossip::Gossip`.
    pub const fn gossip(&self) -> &iroh_gossip::Gossip {
        &self.gossip
    }

    /// Open a direct `/mneme/sync/1` QUIC control connection to `peer`.
    pub async fn connect_control(
        &self,
        peer: iroh::EndpointId,
    ) -> crate::error::Result<iroh::endpoint::Connection> {
        self.endpoint
            .connect(peer, crate::protocol::SYNC_CONTROL_ALPN)
            .await
            .map_err(|error| {
                crate::error::Failure::Transport(format!("connect control to {peer}: {error}"))
            })
    }

    /// Open a direct `iroh-blobs` QUIC connection to `peer`.
    pub async fn connect_blobs(
        &self,
        peer: iroh::EndpointId,
    ) -> crate::error::Result<iroh::endpoint::Connection> {
        self.endpoint
            .connect(peer, iroh_blobs::ALPN)
            .await
            .map_err(|error| {
                crate::error::Failure::Transport(format!("connect blobs to {peer}: {error}"))
            })
    }

    /// Register a joined gossip topic handle for transport-level broadcast/recv.
    pub fn attach_gossip_topic(
        &self,
        vault_id: &str,
        topic: iroh_gossip::GossipTopic,
    ) -> crate::error::Result<()> {
        let mut guard = self.topics.lock().map_err(|_| {
            crate::error::Failure::Transport("gossip topic registry poisoned".to_owned())
        })?;
        guard.insert(
            vault_id.to_owned(),
            std::sync::Arc::new(tokio::sync::Mutex::new(topic)),
        );
        Ok(())
    }

    fn lookup_topic(&self, vault_id: &str) -> crate::error::Result<Option<TopicSlot>> {
        let guard = self.topics.lock().map_err(|_| {
            crate::error::Failure::Transport("gossip topic registry poisoned".to_owned())
        })?;
        Ok(guard.get(vault_id).cloned())
    }
}

impl SyncTransport for IrohTransport {
    fn control_roundtrip<'a>(
        &'a self,
        peer: iroh::EndpointId,
        request_bytes: &'a [u8],
    ) -> BoxTransportFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let conn = self.connect_control(peer).await?;
            let (mut send, mut recv) = conn.open_bi().await.map_err(|error| {
                crate::error::Failure::Transport(format!("open control stream: {error}"))
            })?;
            send.write_all(request_bytes).await.map_err(|error| {
                crate::error::Failure::Transport(format!("write control: {error}"))
            })?;
            send.finish().map_err(|error| {
                crate::error::Failure::Transport(format!("finish control write: {error}"))
            })?;
            recv.read_to_end(crate::protocol::MAX_CONTROL_MESSAGE_BYTES)
                .await
                .map_err(|error| crate::error::Failure::Transport(format!("read control: {error}")))
        })
    }

    fn fetch_blob<'a>(
        &'a self,
        request: &'a BlobFetchRequest<'a>,
    ) -> BoxTransportFuture<'a, crate::blobstore::DownloadedBlob> {
        Box::pin(async move {
            let conn = self.connect_blobs(request.peer).await?;
            crate::blobstore::download_blob_to_file(
                &conn,
                request.hash,
                request.max_bytes,
                request.target_path,
                request.extra_algorithm,
            )
            .await
        })
    }

    fn put_blob(
        &self,
        source_path: &std::path::Path,
        max_bytes: u64,
    ) -> crate::error::Result<(iroh_blobs::Hash, u64)> {
        self.blobs
            .register_staged_file(source_path.to_path_buf(), max_bytes)
    }

    fn gossip_broadcast<'a>(
        &'a self,
        vault_id: &'a str,
        payload: bytes::Bytes,
    ) -> BoxTransportFuture<'a, ()> {
        Box::pin(async move {
            let Some(topic) = self.lookup_topic(vault_id)? else {
                return Err(crate::error::Failure::Protocol(format!(
                    "gossip topic '{vault_id}' is not subscribed"
                )));
            };
            let mut guard = topic.lock().await;
            guard.broadcast(payload).await.map_err(|error| {
                crate::error::Failure::Protocol(format!("gossip broadcast: {error}"))
            })
        })
    }

    fn gossip_recv<'a>(
        &'a self,
        vault_id: &'a str,
    ) -> BoxTransportFuture<'a, Option<bytes::Bytes>> {
        Box::pin(async move {
            let Some(topic) = self.lookup_topic(vault_id)? else {
                return Ok(None);
            };
            let mut guard = topic.lock().await;
            while let Some(item) = guard.next().await {
                let event = item.map_err(|error| {
                    crate::error::Failure::Protocol(format!("gossip stream: {error}"))
                })?;
                if let iroh_gossip::Event::Received(message) = event {
                    return Ok(Some(message.content));
                }
            }
            Ok(None)
        })
    }
}
