//! Plaintext adapter: the bare transport, a TCP baseline below both TLS stacks.

use tokio::io::{AsyncRead, AsyncWrite};

use super::ClientAdapter;
use crate::support::{case::Tls, BoxError};

/// Stateless adapter that hands the transport back unchanged.
pub(super) struct Adapter;

impl ClientAdapter for Adapter {
    type Connector = ();
    type Stream<S>
        = S
    where
        S: AsyncRead + AsyncWrite + Unpin;

    const NAME: &'static str = "plaintext";
    const TLS: Tls = Tls::Disabled;

    fn connector() -> Result<Self::Connector, BoxError> {
        Ok(())
    }

    async fn connect<S>(_: &Self::Connector, transport: S) -> Result<Self::Stream<S>, BoxError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        Ok(transport)
    }
}
