use std::{net::ToSocketAddrs, pin::Pin, time::Duration};

use btls::ssl::{
    BoxCustomVerifyFinish, ErrorCode, Ssl, SslAcceptor, SslConnector, SslConnectorBuilder,
    SslFiletype, SslMethod, SslVerifyError, SslVerifyMode,
};
use btls::x509::{X509VerifyError, X509VerifyResult};
use futures::future;
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use tokio_btls::SslStream;

#[tokio::test]
async fn google() {
    let addr = "google.com:443".to_socket_addrs().unwrap().next().unwrap();
    let stream = TcpStream::connect(&addr).await.unwrap();

    let ssl = SslConnector::builder(SslMethod::tls())
        .unwrap()
        .build()
        .configure()
        .unwrap()
        .into_ssl("google.com")
        .unwrap();
    let mut stream = SslStream::new(ssl, stream).unwrap();

    Pin::new(&mut stream).connect().await.unwrap();

    stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();

    let mut buf = vec![];
    stream.read_to_end(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf);
    let response = response.trim_end();

    // any response code is fine
    assert!(response.starts_with("HTTP/1.0 "));
    assert!(response.ends_with("</html>") || response.ends_with("</HTML>"));
}

#[tokio::test]
async fn server() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = async move {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor
            .set_private_key_file("tests/key.pem", SslFiletype::PEM)
            .unwrap();
        acceptor
            .set_certificate_chain_file("tests/cert.pem")
            .unwrap();
        let acceptor = acceptor.build();

        let ssl = Ssl::new(acceptor.context()).unwrap();
        let stream = listener.accept().await.unwrap().0;
        let mut stream = SslStream::new(ssl, stream).unwrap();

        Pin::new(&mut stream).accept().await.unwrap();

        let mut buf = [0; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"asdf");

        stream.write_all(b"jkl;").await.unwrap();

        future::poll_fn(|ctx| Pin::new(&mut stream).poll_shutdown(ctx))
            .await
            .unwrap()
    };

    let client = async {
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.set_ca_file("tests/cert.pem").unwrap();
        let ssl = connector
            .build()
            .configure()
            .unwrap()
            .into_ssl("localhost")
            .unwrap();

        let stream = TcpStream::connect(&addr).await.unwrap();
        let mut stream = SslStream::new(ssl, stream).unwrap();

        Pin::new(&mut stream).connect().await.unwrap();

        stream.write_all(b"asdf").await.unwrap();

        let mut buf = vec![];
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"jkl;");
    };

    future::join(server, client).await;
}

/// The error codes and the client's verify result of a handshake with `tests/cert.pem`.
async fn handshake(
    inline_verify: bool,
    client: impl FnOnce(&mut SslConnectorBuilder),
) -> (
    Result<(), ErrorCode>,
    X509VerifyResult,
    Result<(), ErrorCode>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = async move {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor
            .set_private_key_file("tests/key.pem", SslFiletype::PEM)
            .unwrap();
        acceptor
            .set_certificate_chain_file("tests/cert.pem")
            .unwrap();
        let ssl = Ssl::new(acceptor.build().context()).unwrap();
        let stream = listener.accept().await.unwrap().0;
        let mut stream = SslStream::new(ssl, stream).unwrap();
        Pin::new(&mut stream).accept().await.map_err(|e| e.code())
    };

    let client = async {
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        client(&mut connector);
        let ssl = connector
            .build()
            .configure()
            .unwrap()
            .into_ssl("localhost")
            .unwrap();
        let stream = TcpStream::connect(&addr).await.unwrap();
        let mut stream = if inline_verify {
            SslStream::with_inline_verify(ssl, stream).unwrap()
        } else {
            SslStream::new(ssl, stream).unwrap()
        };
        let result = Pin::new(&mut stream).connect().await;
        (result.map_err(|e| e.code()), stream.ssl().verify_result())
    };

    let (server, (client, verify_result)) = future::join(server, client).await;
    (client, verify_result, server)
}

async fn verification_matches_inline() {
    let trusted = |c: &mut SslConnectorBuilder| c.set_ca_file("tests/cert.pem").unwrap();
    let ok = handshake(false, trusted).await;
    assert_eq!(ok, (Ok(()), Ok(()), Ok(())));
    assert_eq!(handshake(true, trusted).await, ok);

    let failed = handshake(false, |_| {}).await;
    assert_eq!(failed.1, Err(X509VerifyError::DEPTH_ZERO_SELF_SIGNED_CERT));
    assert_eq!(failed.0, Err(ErrorCode::SSL));
    assert_eq!(handshake(true, |_| {}).await, failed);
}

#[tokio::test]
async fn verification_on_current_thread_runtime() {
    verification_matches_inline().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn verification_on_multi_thread_runtime() {
    verification_matches_inline().await;
}

#[tokio::test]
async fn handshake_waits_for_async_callbacks() {
    let result = handshake(false, |c| {
        c.set_async_custom_verify_callback(SslVerifyMode::PEER, |_| {
            Ok(Box::pin(async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok(Box::new(|_: &mut _| Ok(())) as BoxCustomVerifyFinish)
            }))
        });
    })
    .await;
    assert_eq!(result.0, Ok(()));

    // Nothing would wake the task for a synchronous callback asking to retry.
    let retry = handshake(false, |c| {
        c.set_custom_verify_callback(SslVerifyMode::PEER, |_| Err(SslVerifyError::Retry));
    });
    let retry = tokio::time::timeout(Duration::from_secs(10), retry).await;
    assert_eq!(retry.unwrap().0, Err(ErrorCode::WANT_CERTIFICATE_VERIFY));
}
