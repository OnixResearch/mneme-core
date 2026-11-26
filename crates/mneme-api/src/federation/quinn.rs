//! Ed25519-authenticated QUIC (`noq`) transport setup for `irpc` federation.
//!
//! Both server and client present a self-signed Ed25519 X.509 certificate bound
//! to their `iroh::SecretKey` / `iroh::EndpointId`. The TLS 1.3 handshake
//! proves possession of the Ed25519 key and checks the peer's `EndpointId`
//! against the explicit [`super::server::PeerAllowlist`].

const ED25519_PUBLIC_KEY_LEN_BYTES: usize = 32;
const ED25519_BIT_STRING_LEN_BYTES: usize = 33;
const MAX_DER_LEN_BYTES: usize = 4;

/// Build an authenticated `noq::Endpoint` server bound to `bind_addr` whose
/// TLS 1.3 client verifier enforces `allowlist` on Ed25519 peer identities.
pub fn make_authenticated_server_endpoint(
    bind_addr: std::net::SocketAddr,
    secret_key: &iroh::SecretKey,
    allowlist: super::server::PeerAllowlist,
) -> Result<noq::Endpoint, super::client::FederationError> {
    let (cert_der, key_der) = ed25519_cert_pair(secret_key)?;
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let verifier = std::sync::Arc::new(AllowlistClientVerifier {
        allowlist,
        supported: provider.signature_verification_algorithms,
    });
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| super::client::FederationError::Transport(error.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|error| super::client::FederationError::Transport(error.to_string()))?;
    crypto.alpn_protocols = vec![super::protocol::FEDERATION_ALPN.to_vec()];
    let quic_config = noq::crypto::rustls::QuicServerConfig::try_from(crypto)
        .map_err(|error| super::client::FederationError::Transport(error.to_string()))?;
    let mut server_config = noq::ServerConfig::with_crypto(std::sync::Arc::new(quic_config));
    if let Some(transport) = std::sync::Arc::get_mut(&mut server_config.transport) {
        transport.max_concurrent_uni_streams(0_u8.into());
    }
    assert_eq!(std::sync::Arc::strong_count(&server_config.transport), 1);
    let endpoint = noq::Endpoint::server(server_config, bind_addr)
        .map_err(|error| super::client::FederationError::Transport(error.to_string()))?;
    assert!(endpoint.local_addr().is_ok());
    Ok(endpoint)
}

/// Build an authenticated `noq::Endpoint` client presenting `secret_key` and
/// verifying that the server presents `expected_server`.
pub fn make_authenticated_client_endpoint(
    bind_addr: std::net::SocketAddr,
    secret_key: &iroh::SecretKey,
    expected_server: iroh::EndpointId,
) -> Result<noq::Endpoint, super::client::FederationError> {
    let (cert_der, key_der) = ed25519_cert_pair(secret_key)?;
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let verifier = std::sync::Arc::new(PinnedServerVerifier {
        expected: expected_server,
        supported: provider.signature_verification_algorithms,
    });
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| super::client::FederationError::Transport(error.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![cert_der], key_der)
        .map_err(|error| super::client::FederationError::Transport(error.to_string()))?;
    crypto.alpn_protocols = vec![super::protocol::FEDERATION_ALPN.to_vec()];
    let quic_config = noq::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|error| super::client::FederationError::Transport(error.to_string()))?;
    let client_config = noq::ClientConfig::new(std::sync::Arc::new(quic_config));
    let endpoint = noq::Endpoint::client(bind_addr)
        .map_err(|error| super::client::FederationError::Transport(error.to_string()))?;
    assert!(endpoint.local_addr().is_ok());
    endpoint.set_default_client_config(client_config);
    assert!(expected_server.as_bytes().len() == ED25519_PUBLIC_KEY_LEN_BYTES);
    Ok(endpoint)
}

/// Extract the authenticated Ed25519 `EndpointId` from an accepted `noq::Connection`.
pub fn authenticated_peer_id(
    connection: &noq::Connection,
) -> Result<iroh::EndpointId, super::client::FederationError> {
    let identity = connection.peer_identity().ok_or_else(|| {
        super::client::FederationError::Unauthorized("peer presented no TLS identity".to_owned())
    })?;
    let certs = identity
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .map_err(|_| {
            super::client::FederationError::Unauthorized(
                "peer TLS identity is not an X.509 chain".to_owned(),
            )
        })?;
    let leaf = certs.first().ok_or_else(|| {
        super::client::FederationError::Unauthorized("peer X.509 chain is empty".to_owned())
    })?;
    assert!(!certs.is_empty());
    let peer_id = extract_ed25519_peer_id(leaf.as_ref()).map_err(|_| {
        super::client::FederationError::Unauthorized(
            "peer certificate does not contain a valid Ed25519 key".to_owned(),
        )
    })?;
    assert_eq!(peer_id.as_bytes().len(), ED25519_PUBLIC_KEY_LEN_BYTES);
    Ok(peer_id)
}

fn ed25519_cert_pair(
    secret_key: &iroh::SecretKey,
) -> Result<
    (
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    super::client::FederationError,
> {
    const ED25519_PKCS8_PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let mut pkcs8 = Vec::with_capacity(48);
    pkcs8.extend_from_slice(&ED25519_PKCS8_PREFIX);
    pkcs8.extend_from_slice(&secret_key.to_bytes());
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(pkcs8);
    let key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&key_der, &rcgen::PKCS_ED25519)
        .map_err(|error| super::client::FederationError::Transport(error.to_string()))?;
    let params = rcgen::CertificateParams::new(vec![secret_key.public().to_string()])
        .map_err(|error| super::client::FederationError::Transport(error.to_string()))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|error| super::client::FederationError::Transport(error.to_string()))?;
    Ok((cert.der().clone(), key_der.into()))
}

#[derive(Debug)]
struct AllowlistClientVerifier {
    allowlist: super::server::PeerAllowlist,
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl rustls::server::danger::ClientCertVerifier for AllowlistClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let peer_id = extract_ed25519_peer_id(end_entity.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        if !self.allowlist.allows(&peer_id) {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported.supported_schemes()
    }
}

#[derive(Debug)]
struct PinnedServerVerifier {
    expected: iroh::EndpointId,
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl rustls::client::danger::ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let peer_id = extract_ed25519_peer_id(end_entity.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        if peer_id != self.expected {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName,
            ));
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported.supported_schemes()
    }
}

/// Extract an Ed25519 `EndpointId` strictly from an X.509 Certificate's
/// `tbsCertificate.subjectPublicKeyInfo` DER field.
fn extract_ed25519_peer_id(cert_der: &[u8]) -> Result<iroh::EndpointId, ()> {
    const TAG_SEQUENCE: u8 = 0x30;
    const TAG_INTEGER: u8 = 0x02;
    const TAG_BIT_STRING: u8 = 0x03;
    const TAG_VERSION_CTX0: u8 = 0xa0;
    const ED25519_ALG_DER: [u8; 7] = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

    let mut outer = DerCursor::new(cert_der);
    let cert_body = outer.read_tlv(TAG_SEQUENCE)?;
    if !outer.is_empty() {
        return Err(());
    }
    let mut cert_seq = DerCursor::new(cert_body);
    let tbs_body = cert_seq.read_tlv(TAG_SEQUENCE)?;
    let mut tbs = DerCursor::new(tbs_body);
    if tbs.peek_tag() == Some(TAG_VERSION_CTX0) {
        let _ = tbs.read_tlv(TAG_VERSION_CTX0)?;
    }
    let _serial = tbs.read_tlv(TAG_INTEGER)?;
    let _sig_alg = tbs.read_tlv(TAG_SEQUENCE)?;
    let _issuer = tbs.read_tlv(TAG_SEQUENCE)?;
    let _validity = tbs.read_tlv(TAG_SEQUENCE)?;
    let _subject = tbs.read_tlv(TAG_SEQUENCE)?;
    let spki_body = tbs.read_tlv(TAG_SEQUENCE)?;
    let mut spki = DerCursor::new(spki_body);
    let alg_tlv = spki.read_raw_tlv(TAG_SEQUENCE)?;
    if alg_tlv != ED25519_ALG_DER {
        return Err(());
    }
    let key_bits = spki.read_tlv(TAG_BIT_STRING)?;
    if !spki.is_empty() || key_bits.len() != ED25519_BIT_STRING_LEN_BYTES || key_bits[0] != 0 {
        return Err(());
    }
    let key_bytes: [u8; ED25519_PUBLIC_KEY_LEN_BYTES] =
        key_bits[1..33].try_into().map_err(|_| ())?;
    assert_eq!(key_bytes.len(), ED25519_PUBLIC_KEY_LEN_BYTES);
    let peer = iroh::EndpointId::from_bytes(&key_bytes).map_err(|_| ())?;
    assert_eq!(peer.as_bytes(), &key_bytes);
    Ok(peer)
}

struct DerCursor<'a> {
    bytes: &'a [u8],
}

impl<'a> DerCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn peek_tag(&self) -> Option<u8> {
        self.bytes.first().copied()
    }

    fn read_tlv(&mut self, expected_tag: u8) -> Result<&'a [u8], ()> {
        let (header_len, body_len) = self.peek_tlv_bounds(expected_tag)?;
        let total = header_len.checked_add(body_len).ok_or(())?;
        let slice = self.bytes.get(..total).ok_or(())?;
        self.bytes = self.bytes.get(total..).ok_or(())?;
        slice.get(header_len..).ok_or(())
    }

    fn read_raw_tlv(&mut self, expected_tag: u8) -> Result<&'a [u8], ()> {
        let (header_len, body_len) = self.peek_tlv_bounds(expected_tag)?;
        let total = header_len.checked_add(body_len).ok_or(())?;
        let slice = self.bytes.get(..total).ok_or(())?;
        self.bytes = self.bytes.get(total..).ok_or(())?;
        Ok(slice)
    }

    fn peek_tlv_bounds(&self, expected_tag: u8) -> Result<(usize, usize), ()> {
        let tag = *self.bytes.first().ok_or(())?;
        if tag != expected_tag {
            return Err(());
        }
        let len_byte = *self.bytes.get(1).ok_or(())?;
        if len_byte < 0x80 {
            return Ok((2, usize::from(len_byte)));
        }
        let count = usize::from(len_byte & 0x7f);
        if count == 0 || count > MAX_DER_LEN_BYTES {
            return Err(());
        }
        let len_end = 2_usize.checked_add(count).ok_or(())?;
        assert!(len_end <= 2 + MAX_DER_LEN_BYTES);
        let len_slice = self.bytes.get(2..len_end).ok_or(())?;
        let mut length: usize = 0;
        for byte in len_slice {
            length = length
                .checked_shl(8)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or(())?;
        }
        assert!(len_end >= 3);
        Ok((len_end, length))
    }
}
