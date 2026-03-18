use btls::ssl::{Ssl, SslAcceptor, SslFiletype};
use btls::ssl::{SslConnector, SslMethod};
use compio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use compio::net::{TcpListener, TcpStream};
use compio_btls::SslStream;
use futures::future;
use std::net::ToSocketAddrs;
use std::pin::Pin;

#[compio::test]
async fn google() {
    let addr = "google.com:443".to_socket_addrs().unwrap().next().unwrap();
    let stream = TcpStream::connect(&addr).await.unwrap();

    let config = SslConnector::builder(SslMethod::tls())
        .unwrap()
        .build()
        .configure()
        .unwrap();

    let ssl = config.into_ssl("google.com").unwrap();
    let mut stream = SslStream::new(ssl, stream).unwrap();
    Pin::new(&mut stream).connect().await.unwrap();

    stream.write(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
    stream.flush().await.unwrap();
    let (_, buf) = stream.read_to_end(vec![]).await.unwrap();
    stream.shutdown().await.unwrap();
    let response = String::from_utf8_lossy(&buf);

    // any response code is fine
    assert!(response.starts_with("HTTP/1.0 "));
    assert!(response.ends_with("</html>") || response.ends_with("</HTML>"));
}

#[compio::test]
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

        let (_, buf) = stream.read_exact(vec![0u8; 4]).await.unwrap();
        assert_eq!(&buf, b"asdf");

        stream.write(b"jkl;").await.unwrap();
        stream.flush().await.unwrap();

        Pin::new(&mut stream).shutdown().await.unwrap()
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
        stream.flush().await.unwrap();

        let (_, buf) = stream.read_to_end(vec![]).await.unwrap();
        assert_eq!(buf, b"jkl;");
    };

    future::join(server, client).await;
}
