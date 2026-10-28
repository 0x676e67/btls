//! tokio-btls adapter: BoringSSL through the crate under test.

use std::pin::Pin;

use ::btls::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion, Tls13Cipher};
use ::tokio_btls::SslStream;
use tokio::io::{AsyncRead, AsyncWrite};

use super::ClientAdapter;
use crate::support::{case::Tls, BoxError};

/// Stateless adapter for the tokio-btls client stream.
pub(super) struct Adapter;

impl ClientAdapter for Adapter {
    type Connector = SslConnector;
    type Stream<S>
        = SslStream<S>
    where
        S: AsyncRead + AsyncWrite + Unpin;

    const NAME: &'static str = "tokio-btls";
    const TLS: Tls = Tls::Enabled;

    fn connector() -> Result<Self::Connector, BoxError> {
        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_verify(SslVerifyMode::NONE);
        builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_tls13_ciphers(&[Tls13Cipher::AES_128_GCM_SHA256])?;
        Ok(builder.build())
    }

    async fn connect<S>(
        connector: &Self::Connector,
        transport: S,
    ) -> Result<Self::Stream<S>, BoxError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let ssl = connector
            .configure()?
            .verify_hostname(false)
            .into_ssl("localhost")?;
        let mut stream = SslStream::new(ssl, transport)?;
        Pin::new(&mut stream).connect().await?;
        Ok(stream)
    }
}
