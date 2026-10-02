use std::{
    io::{self, IoSlice},
    net::ToSocketAddrs,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::Duration,
};

use btls::ssl::{Ssl, SslAcceptor, SslConnector, SslFiletype, SslMethod, SslVersion};
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
    vectored_writes: Arc<AtomicUsize>,
    wire: Arc<Mutex<Vec<u8>>>,
}

/// TLS record lengths, including their headers.
fn record_lengths(wire: &[u8]) -> Vec<usize> {
    let mut lengths = Vec::new();
    let mut pos = 0;
    while pos < wire.len() {
        assert!(pos + 5 <= wire.len(), "incomplete TLS record header");
        let len = 5 + u16::from_be_bytes([wire[pos + 3], wire[pos + 4]]) as usize;
        pos += len;
        assert!(pos <= wire.len(), "incomplete TLS record body");
        lengths.push(len);
    }
    lengths
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

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.vectored_writes.fetch_add(1, Ordering::Relaxed);
        let res = Pin::new(&mut self.stream).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(mut n)) = res {
            let mut wire = self.wire.lock().unwrap();
            for buf in bufs {
                let len = n.min(buf.len());
                wire.extend_from_slice(&buf[..len]);
                n -= len;
                if n == 0 {
                    break;
                }
            }
        }
        res
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
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
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        tokio::time::timeout(
            Duration::from_secs(30),
            vectored_writes_for_version(version),
        )
        .await
        .expect("loopback vectored write test timed out");
    }
}

async fn vectored_writes_for_version(version: SslVersion) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let header = b"frame header";
    let payload = vec![7; 1000];
    // HTTP/1 chunked framing, including either side of the prefix-copy threshold.
    let cases = [
        (8 * 1024, 4, (3, 3)),
        // Each 16 KiB chunk adds a framing record to the flattened baseline.
        (16 * 1024, 4, (5 + 4, 5)),
        (8191, 5, (3, 3)),
        (8192, 5, (3, 3)),
        (8193, 5, (5, 3)),
    ];
    let chunked: Vec<Vec<Vec<u8>>> = cases
        .iter()
        .map(|&(len, count, _)| {
            let mut bufs = vec![Vec::new()];
            for chunk in 0..count {
                bufs.push(format!("{len:x}\r\n").into_bytes());
                // Vary both the chunk and byte offset so incorrect prefix consumption is visible.
                bufs.push(
                    (0..len)
                        .map(|offset| ((offset * 31 + chunk * 17) % 251) as u8)
                        .collect(),
                );
                bufs.push(Vec::new());
                bufs.push(b"\r\n".to_vec());
            }
            bufs.push(Vec::new());
            bufs
        })
        .collect();
    // Keep isolated pairs in place, but fill records across repeated pairs.
    let pair_cases = [
        (vec![10000, 7000], 2),
        (vec![8193, 8192], 2),
        ([10000, 7000].repeat(8), 9),
    ];
    let pairs: Vec<Vec<Vec<u8>>> = pair_cases
        .iter()
        .map(|(sizes, _)| {
            let mut bufs = vec![Vec::new()];
            for (index, &len) in sizes.iter().enumerate() {
                bufs.push(
                    (0..len)
                        .map(|offset| ((offset * 31 + index * 17) % 251) as u8)
                        .collect(),
                );
                bufs.push(Vec::new());
            }
            bufs
        })
        .collect();
    let large = vec![9; 100 * 1024];
    let mut expected = [&header[..], &payload].concat();
    for bufs in chunked.iter().chain(&pairs) {
        let flat = bufs.concat();
        expected.extend_from_slice(&flat);
        expected.extend_from_slice(&flat);
    }
    expected.extend_from_slice(&large);

    let server = async {
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        acceptor.set_min_proto_version(Some(version)).unwrap();
        acceptor.set_max_proto_version(Some(version)).unwrap();
        acceptor
            .set_private_key_file("tests/key.pem", SslFiletype::PEM)
            .unwrap();
        acceptor
            .set_certificate_chain_file("tests/cert.pem")
            .unwrap();
        let acceptor = acceptor.build();

        let ssl = Ssl::new(acceptor.context()).unwrap();
        let writes = Arc::new(AtomicUsize::new(0));
        let vectored_writes = Arc::new(AtomicUsize::new(0));
        let wire = Arc::new(Mutex::new(Vec::new()));
        let stream = CountWrites {
            stream: listener.accept().await.unwrap().0,
            writes: writes.clone(),
            vectored_writes: vectored_writes.clone(),
            wire: wire.clone(),
        };
        let mut stream = SslStream::new(ssl, stream).unwrap();
        Pin::new(&mut stream).accept().await.unwrap();
        assert_eq!(stream.ssl().version2(), Some(version));
        // Without the sealing API (FIPS builds), writes take the `SSL_write` loop.
        let sealed = stream.ssl().seal_app_data_limits().is_some();

        writes.store(0, Ordering::Relaxed);
        vectored_writes.store(0, Ordering::Relaxed);
        let bufs = [IoSlice::new(header), IoSlice::new(&payload)];
        let n = stream.write_vectored(&bufs).await.unwrap();
        assert_eq!(n, header.len() + payload.len());
        assert_eq!(writes.load(Ordering::Relaxed), 1);

        // Record counts for the same bytes written as slices and as one flattened buffer.
        for (&(len, count, counts), chunks) in cases.iter().zip(&chunked) {
            let flat = chunks.concat();
            wire.lock().unwrap().clear();
            let mut bufs: Vec<_> = chunks.iter().map(|buf| IoSlice::new(buf)).collect();
            let mut bufs = &mut bufs[..];
            while !bufs.is_empty() {
                let n = stream.write_vectored(bufs).await.unwrap();
                assert!(n > 0, "vectored write made no progress");
                IoSlice::advance_slices(&mut bufs, n);
            }
            stream.flush().await.unwrap();
            let vectored = record_lengths(&wire.lock().unwrap());

            wire.lock().unwrap().clear();
            stream.write_all(&flat).await.unwrap();
            stream.flush().await.unwrap();
            let flattened = record_lengths(&wire.lock().unwrap());
            let case = format!("{version:?}: {len}-byte chunks x {count}");
            assert_eq!(flattened.len(), counts.1, "{case}");
            if sealed {
                // Sealed records ignore slice boundaries.
                assert_eq!(vectored, flattened, "{case}");
            } else {
                // Larger slices stay in place, accepting extra framing records to avoid copying them.
                assert_eq!(vectored.len(), counts.0, "{case}");
            }
        }
        for ((sizes, count), pair) in pair_cases.iter().zip(&pairs) {
            let flat = pair.concat();
            wire.lock().unwrap().clear();
            let mut bufs: Vec<_> = pair.iter().map(|buf| IoSlice::new(buf)).collect();
            let mut bufs = &mut bufs[..];
            while !bufs.is_empty() {
                let n = stream.write_vectored(bufs).await.unwrap();
                assert!(n > 0, "vectored write made no progress");
                IoSlice::advance_slices(&mut bufs, n);
            }
            stream.flush().await.unwrap();
            let lengths = record_lengths(&wire.lock().unwrap());
            if sizes.len() == 2 && !sealed {
                // In particular, 8193 + 8192 must not become a full record plus a one-byte tail.
                assert!(
                    lengths.iter().all(|&len| len >= 64),
                    "{version:?}: {lengths:?}"
                );
            }

            wire.lock().unwrap().clear();
            stream.write_all(&flat).await.unwrap();
            stream.flush().await.unwrap();
            let flattened = record_lengths(&wire.lock().unwrap());
            assert_eq!(
                (lengths.len(), flattened.len()),
                (*count, *count),
                "{version:?}: slice lengths {sizes:?}"
            );
            if sealed {
                // Sealed records ignore slice boundaries.
                assert_eq!(lengths, flattened, "{version:?}: slice lengths {sizes:?}");
            }
        }
        // Sealed records go out with plain writes; the `SSL_write` loop sends its last record
        // together with the buffered ones.
        assert_eq!(vectored_writes.load(Ordering::Relaxed) > 0, !sealed);

        stream.write_all(&large).await.unwrap();
        future::poll_fn(|ctx| Pin::new(&mut stream).poll_shutdown(ctx))
            .await
            .unwrap()
    };

    let client = async {
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.set_min_proto_version(Some(version)).unwrap();
        connector.set_max_proto_version(Some(version)).unwrap();
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
        assert_eq!(stream.ssl().version2(), Some(version));

        let mut buf = vec![];
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, expected);
    };

    future::join(server, client).await;
}
