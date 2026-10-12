//! tokio-rustls adapter: rustls with the aws-lc-rs provider.

use std::sync::Arc;

use ::tokio_rustls::{
    client::TlsStream,
    rustls::{
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        crypto::{aws_lc_rs, WebPkiSupportedAlgorithms},
        pki_types::{CertificateDer, ServerName, UnixTime},
        version, ClientConfig, DigitallySignedStruct, Error, SignatureScheme,
    },
    TlsConnector,
};
use tokio::io::{AsyncRead, AsyncWrite};

use super::ClientAdapter;
use crate::support::{case::Tls, BoxError};

/// Stateless adapter for the tokio-rustls client stream.
pub(super) struct Adapter;

/// Accepts any server certificate, like the tokio-btls client with `SslVerifyMode::NONE`.
///
/// The test certificate has no SAN and is a CA certificate, which webpki rejects.
#[derive(Debug)]
struct NoVerifier(WebPkiSupportedAlgorithms);

// ===== impl NoVerifier =====

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

// ===== impl Adapter =====

impl ClientAdapter for Adapter {
    type Connector = TlsConnector;
    type Stream<S>
        = TlsStream<S>
    where
        S: AsyncRead + AsyncWrite + Unpin;

    const NAME: &'static str = "tokio-rustls";
    const TLS: Tls = Tls::Enabled;

    fn connector() -> Result<Self::Connector, BoxError> {
        let mut provider = aws_lc_rs::default_provider();
        provider.cipher_suites = vec![aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
        let verifier = NoVerifier(provider.signature_verification_algorithms);
        let config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        Ok(TlsConnector::from(Arc::new(config)))
    }

    async fn connect<S>(
        connector: &Self::Connector,
        transport: S,
    ) -> Result<Self::Stream<S>, BoxError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let server_name = ServerName::try_from("localhost")?;
        Ok(connector.connect(server_name, transport).await?)
    }
}
