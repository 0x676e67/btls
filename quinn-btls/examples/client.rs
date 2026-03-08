//! This example demonstrates an HTTP client that requests from a server.

use anyhow::{anyhow, Result};
use btls::x509::X509;
use bytes::BytesMut;
use bytes::{Buf, Bytes};
use clap::Parser;
use http::Uri;
use http_body::Body;
use http_body_util::BodyExt;
use quinn_btls::QuicSslContext;
use std::{
    fs,
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};
use tracing::Level;
use url::Url;

/// HTTP/3 over QUIC client
#[derive(Parser, Debug)]
#[clap(name = "client")]
struct Opt {
    /// Log level e.g. trace, debug, info, warn, error
    #[clap(long, default_value = "info")]
    log: Level,

    #[clap(default_value = "https://cloudflare-quic.com/")]
    url: Url,

    /// Override hostname used for certificate verification
    #[clap(long)]
    host: Option<String>,

    /// Custom certificate authority to trust, in DER format
    #[clap(long)]
    ca: Option<PathBuf>,

    /// Simulate NAT rebinding after connecting
    #[clap(long)]
    rebind: bool,

    /// Address to bind on
    #[clap(long, default_value = "0.0.0.0:0")]
    bind: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let options = Opt::parse();

    let url = options.url;
    let url_host = strip_ipv6_brackets(url.host_str().unwrap());
    let remote = (url_host, url.port().unwrap_or(443))
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("couldn't resolve to an address"))?;

    let mut client_crypto = quinn_btls::ClientConfig::new()?;
    if let Some(ca_path) = options.ca {
        client_crypto
            .ctx_mut()
            .cert_store_mut()
            .add_cert(X509::from_der(&fs::read(ca_path)?)?)?;
    } else {
        client_crypto
            .ctx_mut()
            .cert_store_mut()
            .set_default_paths()?;
    }

    let mut endpoint = quinn_btls::helpers::client_endpoint(options.bind)?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_crypto)));

    let start = Instant::now();
    let rebind = options.rebind;
    let host = options.host.as_deref().unwrap_or(url_host);

    tracing::info!("connecting to {host} at {remote}");
    let conn = endpoint
        .connect(remote, host)?
        .await
        .map_err(|e| anyhow!("failed to connect: {}", e))?;
    tracing::info!("connected at {:?}", start.elapsed());

    if rebind {
        let socket = std::net::UdpSocket::bind("[::]:0").unwrap();
        let addr = socket.local_addr().unwrap();
        tracing::info!("rebinding to {addr}");
        endpoint.rebind(socket).expect("rebind failed");
    }

    let (mut h3_conn, mut tx) = h3::client::new(h3_quinn::Connection::new(conn)).await?;

    let req = http::Request::get(Uri::try_from(url.as_str())?).body(())?;
    let (mut send, mut recv) = tx.send_request(req).await?.split();
    if let Err(e) = send.finish().await {
        tracing::error!("failed to send request: {e}");
    }

    let resp = {
        let resp = recv.recv_response().await?;
        let resp_body = Incoming::new(recv, resp.headers())
            .map_err(Into::<BoxError>::into)
            .boxed();
        resp.map(|_| resp_body)
    };
    tracing::info!("response: {:#?}", resp);

    let body = BodyExt::collect(resp.into_body())
        .await
        .map(|buf| buf.to_bytes())
        .map_err(|e| anyhow!("failed to collect response body: {e}"))?;
    tracing::info!("response body: {}", String::from_utf8_lossy(&body));

    h3_conn.shutdown(0).await?;
    Ok(())
}

fn strip_ipv6_brackets(host: &str) -> &str {
    // An ipv6 url looks like eg https://[::1]:4433/Cargo.toml, wherein the host [::1] is the
    // ipv6 address ::1 wrapped in brackets, per RFC 2732. This strips those.
    if host.starts_with('[') && host.ends_with(']') {
        &host[1..host.len() - 1]
    } else {
        host
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

struct Incoming<S, B> {
    inner: h3::client::RequestStream<S, B>,
    content_length: Option<u64>,
}

impl<S, B> Incoming<S, B> {
    fn new(stream: h3::client::RequestStream<S, B>, headers: &http::header::HeaderMap) -> Self {
        Self {
            inner: stream,
            content_length: headers
                .get(http::header::CONTENT_LENGTH)
                .and_then(|h| h.to_str().ok())
                .and_then(|v| v.parse().ok()),
        }
    }
}

impl<S, B> http_body::Body for Incoming<S, B>
where
    S: h3::quic::RecvStream,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        match futures_core::ready!(self.inner.poll_recv_data(cx)) {
            Ok(Some(mut b)) => Poll::Ready(Some(Ok(http_body::Frame::data(
                b.copy_to_bytes(b.remaining()),
            )))),
            Ok(None) => Poll::Ready(None),
            Err(e) => Poll::Ready(Some(Err(e.into()))),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        if let Some(content_length) = self.content_length {
            http_body::SizeHint::with_exact(content_length)
        } else {
            http_body::SizeHint::default()
        }
    }
}

pub async fn body_to_string<B>(
    mut body: B,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>>
where
    B: Body<Data = bytes::Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let mut buf = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Some(data) = frame.data_ref() {
            buf.extend_from_slice(data);
        }
    }
    Ok(String::from_utf8(buf.to_vec())?)
}
