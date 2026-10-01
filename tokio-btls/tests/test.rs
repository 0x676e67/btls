use std::{
    io::{self, IoSlice},
    net::ToSocketAddrs,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
};

use btls::ssl::{Ssl, SslAcceptor, SslConnector, SslFiletype, SslMethod};
use futures::future;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
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
    stream.flush().await.unwrap();

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

#[tokio::test]
async fn buffered_reads_preserve_record_boundaries() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Exercise varied write sizes, including writes larger than one TLS record.
    let records: Vec<Vec<u8>> = [1, 5, 300, 16 * 1024, 40 * 1024, 7]
        .iter()
        .enumerate()
        .map(|(i, &len)| vec![i as u8; len])
        .collect();
    let expected = records.concat();

    let server = async {
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

        for record in &records {
            stream.write_all(record).await.unwrap();
        }
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

        let mut buf = vec![];
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, expected);
    };

    future::join(server, client).await;
}

/// Counts writes that reach the transport and keeps the bytes written.
struct CountWrites {
    stream: TcpStream,
    writes: Arc<AtomicUsize>,
    wire: Arc<Mutex<Vec<u8>>>,
}

/// Number of TLS records in `wire`.
fn records(wire: &[u8]) -> usize {
    let (mut count, mut pos) = (0, 0);
    while pos + 5 <= wire.len() {
        pos += 5 + u16::from_be_bytes([wire[pos + 3], wire[pos + 4]]) as usize;
        count += 1;
    }
    count
}

impl AsyncRead for CountWrites {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for CountWrites {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        let res = Pin::new(&mut self.stream).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = res {
            self.wire.lock().unwrap().extend_from_slice(&buf[..n]);
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn vectored_writes_share_one_record() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let header = b"frame header";
    let payload = vec![7; 1000];
    let chunk = vec![8; 8 * 1024];
    let chunked = [&b"2000\r\n"[..], &chunk, b"\r\n"].concat().repeat(4);
    let large = vec![9; 100 * 1024];
    let expected = [&header[..], &payload, &chunked, &large].concat();

    let server = async {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor
            .set_private_key_file("tests/key.pem", SslFiletype::PEM)
            .unwrap();
        acceptor
            .set_certificate_chain_file("tests/cert.pem")
            .unwrap();
        let acceptor = acceptor.build();

        let ssl = Ssl::new(acceptor.context()).unwrap();
        let writes = Arc::new(AtomicUsize::new(0));
        let wire = Arc::new(Mutex::new(Vec::new()));
        let stream = CountWrites {
            stream: listener.accept().await.unwrap().0,
            writes: writes.clone(),
            wire: wire.clone(),
        };
        let mut stream = SslStream::new(ssl, stream).unwrap();
        Pin::new(&mut stream).accept().await.unwrap();

        writes.store(0, Ordering::Relaxed);
        let bufs = [IoSlice::new(header), IoSlice::new(&payload)];
        let n = stream.write_vectored(&bufs).await.unwrap();
        assert_eq!(n, header.len() + payload.len());
        assert_eq!(writes.load(Ordering::Relaxed), 1);

        // HTTP/1 chunked framing: size lines and CRLFs share records with the chunk data.
        wire.lock().unwrap().clear();
        let mut bufs = Vec::new();
        for _ in 0..4 {
            bufs.extend([
                IoSlice::new(b"2000\r\n"),
                IoSlice::new(&chunk),
                IoSlice::new(b"\r\n"),
            ]);
        }
        let mut bufs = &mut bufs[..];
        while !bufs.is_empty() {
            let n = stream.write_vectored(bufs).await.unwrap();
            IoSlice::advance_slices(&mut bufs, n);
        }
        stream.flush().await.unwrap();
        assert_eq!(records(&wire.lock().unwrap()), 4);

        stream.write_all(&large).await.unwrap();
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

        let mut buf = vec![];
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, expected);
    };

    future::join(server, client).await;
}
