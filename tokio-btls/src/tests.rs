//! Stream-level tests over a TLS connection.

use std::{
    io, mem,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll, Waker},
};

use btls::ssl::{
    self, ErrorCode, Ssl, SslAcceptor, SslConnector, SslConnectorBuilder, SslFiletype, SslMethod,
    SslRef, SslSessionCacheMode, SslVersion,
};
use foreign_types::ForeignTypeRef;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

use crate::{
    write::{self, MAX_RECORD, RECORD_OVERHEAD, SEAL_STACK_LEN, WRITE_BUF_CAPACITY},
    SslStream,
};

/// Duplex transport whose writes can stall, fail once, or keep returning `BrokenPipe`.
///
/// A spent `budget` stalls writes, or fails them with `TimedOut` if `fail_when_spent` is set.
/// It counts write polls and copies the bytes it accepts into `tap`.
struct Gate {
    io: DuplexStream,
    open: bool,
    budget: usize,
    fail_when_spent: bool,
    interrupt: bool,
    interrupt_flush: bool,
    broken: bool,
    polls: usize,
    tap: Vec<u8>,
    // Returned once instead of `Pending` when no data is left: EOF or an error.
    drained: Option<io::Result<()>>,
}

impl AsyncRead for Gate {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.io).poll_read(cx, buf) {
            Poll::Pending => self.drained.take().map_or(Poll::Pending, Poll::Ready),
            read => read,
        }
    }
}

impl AsyncWrite for Gate {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.polls += 1;
        if self.broken {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if mem::take(&mut self.interrupt) {
            return Poll::Ready(Err(io::ErrorKind::Interrupted.into()));
        }
        if self.open && self.budget == 0 && self.fail_when_spent {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }
        if !self.open || self.budget == 0 {
            return Poll::Pending;
        }
        let n = buf.len().min(self.budget);
        let result = Pin::new(&mut self.io).poll_write(cx, &buf[..n]);
        if let Poll::Ready(Ok(written)) = result {
            self.budget -= written;
            self.tap.extend_from_slice(&buf[..written]);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if mem::take(&mut self.interrupt_flush) {
            return Poll::Ready(Err(io::ErrorKind::Interrupted.into()));
        }
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

async fn tls_pair() -> (SslStream<Gate>, SslStream<DuplexStream>) {
    tls_pair_with(SslVersion::TLS1_2, None).await
}

async fn tls_pair_with(
    version: SslVersion,
    max_fragment: Option<usize>,
) -> (SslStream<Gate>, SslStream<DuplexStream>) {
    let connector = SslConnector::builder(SslMethod::tls()).unwrap();
    tls_pair_from(connector, version, max_fragment, None).await
}

/// Connects a client built from `connector` to a server, both limited to `ciphers` if set;
/// the client's transport counts and taps only what is written after the handshake.
async fn tls_pair_from(
    mut connector: SslConnectorBuilder,
    version: SslVersion,
    max_fragment: Option<usize>,
    ciphers: Option<&str>,
) -> (SslStream<Gate>, SslStream<DuplexStream>) {
    // Keep the complete test payload in the transport while writes are polled manually.
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);

    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor.set_min_proto_version(Some(version)).unwrap();
    acceptor.set_max_proto_version(Some(version)).unwrap();
    if let Some(ciphers) = ciphers {
        acceptor.set_cipher_list(ciphers).unwrap();
        connector.set_cipher_list(ciphers).unwrap();
    }
    acceptor
        .set_private_key_file("tests/key.pem", SslFiletype::PEM)
        .unwrap();
    acceptor
        .set_certificate_chain_file("tests/cert.pem")
        .unwrap();
    let acceptor = acceptor.build();
    let mut server = SslStream::new(Ssl::new(acceptor.context()).unwrap(), server_io).unwrap();

    connector.set_min_proto_version(Some(version)).unwrap();
    connector.set_max_proto_version(Some(version)).unwrap();
    connector.set_ca_file("tests/cert.pem").unwrap();
    let mut ssl = connector
        .build()
        .configure()
        .unwrap()
        .into_ssl("localhost")
        .unwrap();
    if let Some(fragment) = max_fragment {
        ssl.set_max_send_fragment(fragment).unwrap();
    }
    let gate = Gate {
        io: client_io,
        open: true,
        budget: usize::MAX,
        fail_when_spent: false,
        interrupt: false,
        interrupt_flush: false,
        broken: false,
        polls: 0,
        tap: Vec::new(),
        drained: None,
    };
    let mut client = SslStream::new(ssl, gate).unwrap();

    let (connected, accepted) = tokio::join!(
        Pin::new(&mut client).connect(),
        Pin::new(&mut server).accept()
    );
    connected.unwrap();
    accepted.unwrap();
    client.get_mut().polls = 0;
    client.get_mut().tap.clear();
    (client, server)
}

/// Content types and lengths, headers included, of the TLS records in `wire`.
fn records(wire: &[u8]) -> Vec<(u8, usize)> {
    let mut records = Vec::new();
    let mut rest = wire;
    while !rest.is_empty() {
        assert!(rest.len() >= 5, "incomplete record header");
        let len = 5 + usize::from(u16::from_be_bytes([rest[3], rest[4]]));
        assert!(rest.len() >= len, "incomplete record body");
        records.push((rest[0], len));
        rest = &rest[len..];
    }
    records
}

#[tokio::test]
async fn read_takes_every_ready_record() {
    let (mut client, mut server) = tls_pair().await;
    let payload = vec![7; 3 * MAX_RECORD];
    server.write_all(&payload).await.unwrap();
    server.flush().await.unwrap();

    client.get_mut().drained = Some(Ok(()));

    let mut buf = vec![0; 4 * MAX_RECORD];
    assert_eq!(client.read(&mut buf).await.unwrap(), payload.len());
    // The read stops once the buffered ciphertext is used, before the transport's end.
    assert!(client.get_ref().drained.is_some());
    assert_eq!(client.read(&mut buf).await.unwrap(), 0);
}

#[tokio::test]
async fn read_reports_an_end_after_the_data_before_it() {
    for corrupt in [false, true] {
        let (mut client, mut server) = tls_pair().await;
        server.write_all(b"payload").await.unwrap();
        server.flush().await.unwrap();
        if corrupt {
            // A record that fails to open follows the data.
            let mut record = vec![23, 3, 3, 0, 32];
            record.resize(5 + 32, 0);
            server.get_mut().write_all(&record).await.unwrap();
        } else {
            server.shutdown().await.unwrap();
        }
        let mut cx = Context::from_waker(Waker::noop());
        let mut buf = [0; 64];

        // Both records arrive in one transport read; the end waits for the next read.
        let mut read = ReadBuf::new(&mut buf);
        let first = Pin::new(&mut client).poll_read(&mut cx, &mut read);
        assert!(matches!(first, Poll::Ready(Ok(()))), "{first:?}");
        assert_eq!(read.filled(), b"payload");
        let mut read = ReadBuf::new(&mut buf);
        match Pin::new(&mut client).poll_read(&mut cx, &mut read) {
            Poll::Ready(Ok(())) if !corrupt => assert!(read.filled().is_empty()),
            Poll::Ready(Err(_)) if corrupt => {}
            other => panic!("the end was lost: {other:?}"),
        }
    }
}

#[tokio::test]
async fn shutdown_resumes_after_backpressure() {
    let (mut client, mut server) = tls_pair().await;
    let mut cx = Context::from_waker(Waker::noop());

    // close_notify is queued, but the transport takes nothing yet.
    client.get_mut().open = false;
    assert!(Pin::new(&mut client).poll_shutdown(&mut cx).is_pending());

    client.get_mut().open = true;
    let res = Pin::new(&mut client).poll_shutdown(&mut cx);
    assert!(matches!(res, Poll::Ready(Ok(()))));

    let mut buf = Vec::new();
    server.read_to_end(&mut buf).await.unwrap();
    assert!(buf.is_empty());
}

#[tokio::test]
async fn sealed_records_survive_a_failed_drain() {
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        let (mut client, mut server) = tls_pair_with(version, None).await;
        let mut cx = Context::from_waker(Waker::noop());
        let data: Vec<_> = (0..3 * MAX_RECORD)
            .map(|offset| (offset ^ (offset >> 8)) as u8)
            .collect();

        // A one-time error after sealing is dropped: the record is reported and goes out
        // before the next write.
        client.get_mut().interrupt = true;
        assert_eq!(client.write(b"headerpayload").await.unwrap(), 13);

        // The transport takes part of the records, then fails. The sealed plaintext must be
        // reported, or the caller would send it again.
        client.get_mut().budget = 20_000;
        client.get_mut().fail_when_spent = true;
        let n = match Pin::new(&mut client).poll_write(&mut cx, &data) {
            Poll::Ready(Ok(n)) => n,
            result => panic!("expected the sealed length: {result:?}"),
        };
        assert_eq!(n, data.len());
        assert_eq!(client.get_ref().tap.len(), 20_000);
        let buffered = client.0.get_ref().write_buf.len();
        assert!(buffered > n - 20_000);

        // The buffered rest stays put; the error persists, so the next call reports it.
        match Pin::new(&mut client).poll_flush(&mut cx) {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::TimedOut),
            result => panic!("expected the deferred error: {result:?}"),
        }
        assert_eq!(client.0.get_ref().write_buf.len(), buffered);

        client.get_mut().budget = usize::MAX;
        client.shutdown().await.unwrap();
        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, [&b"headerpayload"[..], &data].concat());
    }
}

#[tokio::test]
async fn short_fragments_preserve_vectored_prefix_after_retries() {
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        let (mut client, mut server) = tls_pair_with(version, Some(512)).await;
        let segments: Vec<Vec<u8>> = [0, 3, 16384, 0, 40965, 1, 0, 32771, 95000, 0]
            .into_iter()
            .enumerate()
            .map(|(i, len)| {
                (0..len)
                    .map(|offset| ((offset ^ (offset >> 8)) as u8).wrapping_add(i as u8))
                    .collect()
            })
            .collect();
        let expected: Vec<_> = segments.iter().flatten().copied().collect();
        let mut bufs: Vec<_> = segments.iter().map(|buf| io::IoSlice::new(buf)).collect();
        let mut bufs = &mut bufs[..];
        let mut cx = Context::from_waker(Waker::noop());

        // Smaller SSL fragments force repeated partial consumption inside a source slice.
        let sealed = client.ssl().seal_app_data_limits().is_some();
        client.get_mut().budget = 0;
        let mut accepted = match Pin::new(&mut client).poll_write_vectored(&mut cx, bufs) {
            Poll::Ready(Ok(n)) => n,
            result => panic!("initial buffering failed: {result:?}"),
        };
        assert!(accepted > 0 && accepted < expected.len());
        if sealed {
            // Sealed records ignore slice boundaries, so the write stops after whole
            // fragments. No segment ends on a multiple of 512, so it stops inside a slice by
            // construction, whatever the budget.
            assert_eq!(accepted % 512, 0);
        }
        let mut boundary = 0;
        assert!(!segments.iter().any(|buf| {
            boundary += buf.len();
            boundary == accepted
        }));
        io::IoSlice::advance_slices(&mut bufs, accepted);
        assert!(Pin::new(&mut client)
            .poll_write_vectored(&mut cx, bufs)
            .is_pending());

        // Split ciphertext writes both inside record headers and inside record bodies.
        for budget in [37, 4093].into_iter().cycle().take(256) {
            if accepted == expected.len() {
                break;
            }
            client.get_mut().budget = budget;
            match Pin::new(&mut client).poll_write_vectored(&mut cx, bufs) {
                Poll::Ready(Ok(n)) => {
                    assert!(n > 0 && n <= expected.len() - accepted);
                    accepted += n;
                    io::IoSlice::advance_slices(&mut bufs, n);
                }
                Poll::Pending => {}
                Poll::Ready(Err(e)) => panic!("write failed: {e}"),
            }
        }
        assert_eq!(accepted, expected.len());

        // A partial drain and a later flush error must not replay accepted plaintext.
        client.get_mut().budget = 1;
        assert!(Pin::new(&mut client).poll_flush(&mut cx).is_pending());
        client.get_mut().budget = usize::MAX;
        client.get_mut().interrupt_flush = true;
        match Pin::new(&mut client).poll_flush(&mut cx) {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::Interrupted),
            result => panic!("expected flush failure: {result:?}"),
        }
        client.flush().await.unwrap();
        client.shutdown().await.unwrap();

        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, expected);
    }
}

#[tokio::test]
async fn buffer_cap_and_persistent_errors_preserve_consumed_prefix() {
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        let (mut client, mut server) = tls_pair_with(version, None).await;
        let mut cx = Context::from_waker(Waker::noop());
        let data: Vec<_> = (0..6 * MAX_RECORD)
            .map(|offset| (offset ^ (offset >> 8)) as u8)
            .collect();
        let mut expected = Vec::new();

        // While the transport is blocked, a write past the cap still takes a last tail of at
        // most one record, and later writes accept nothing.
        client.get_mut().open = false;
        let tail = &data[..5 * MAX_RECORD];
        assert!(matches!(
            Pin::new(&mut client).poll_write(&mut cx, tail),
            Poll::Ready(Ok(n)) if n == tail.len()
        ));
        expected.extend_from_slice(tail);
        let buffered = client.0.get_ref().write_buf.len();
        assert!(buffered > WRITE_BUF_CAPACITY);
        assert!(buffered <= tail.len() + 5 * RECORD_OVERHEAD);
        assert!(Pin::new(&mut client)
            .poll_write(&mut cx, b"extra")
            .is_pending());
        assert_eq!(client.0.get_ref().write_buf.len(), buffered);

        // A persistent error prevents every later write from accepting more input.
        client.get_mut().broken = true;
        for _ in 0..2 {
            match Pin::new(&mut client).poll_flush(&mut cx) {
                Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::BrokenPipe),
                result => panic!("expected persistent flush failure: {result:?}"),
            }
            match Pin::new(&mut client).poll_write(&mut cx, b"extra") {
                Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::BrokenPipe),
                result => panic!("expected persistent write failure: {result:?}"),
            }
            assert_eq!(client.0.get_ref().write_buf.len(), buffered);
        }
        client.get_mut().broken = false;
        client.get_mut().open = true;
        client.flush().await.unwrap();
        assert!(client.0.get_ref().write_buf.is_empty());

        // A write longer than the cap plus one record stops at the cap.
        client.get_mut().open = false;
        let consumed = match Pin::new(&mut client).poll_write(&mut cx, &data) {
            Poll::Ready(Ok(n)) => n,
            result => panic!("initial buffering failed: {result:?}"),
        };
        assert!(consumed > 0 && consumed < data.len());
        assert!(client.0.get_ref().write_buf.len() >= WRITE_BUF_CAPACITY);
        client.get_mut().open = true;
        client.write_all(&data[consumed..]).await.unwrap();
        client.flush().await.unwrap();
        assert!(client.0.get_ref().write_buf.is_empty());
        expected.extend_from_slice(&data);

        // If the error first occurs after sealing, report the consumed plaintext once.
        let tail = b"tail-queued-before-reporting-error";
        client.get_mut().broken = true;
        assert!(matches!(
            Pin::new(&mut client).poll_write(&mut cx, tail),
            Poll::Ready(Ok(n)) if n == tail.len()
        ));
        let buffered = client.0.get_ref().write_buf.len();
        assert!(buffered > 0);
        for _ in 0..2 {
            match Pin::new(&mut client).poll_flush(&mut cx) {
                Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::BrokenPipe),
                result => panic!("expected deferred flush failure: {result:?}"),
            }
            match Pin::new(&mut client).poll_write(&mut cx, b"unaccepted") {
                Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::BrokenPipe),
                result => panic!("expected deferred write failure: {result:?}"),
            }
            assert_eq!(client.0.get_ref().write_buf.len(), buffered);
        }

        client.get_mut().broken = false;
        client.shutdown().await.unwrap();
        expected.extend_from_slice(tail);
        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, expected);
    }
}

#[tokio::test]
async fn vectored_write_seals_full_records() {
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        let (mut client, mut server) = tls_pair_with(version, None).await;
        let mut cx = Context::from_waker(Waker::noop());
        // HTTP/2 DATA frames: a 9-byte header before each record-sized payload.
        let frames: Vec<Vec<u8>> = (0..8u8)
            .map(|i| {
                let len = if i % 2 == 0 { 9 } else { MAX_RECORD };
                (0..len).map(|offset| offset as u8 ^ i).collect()
            })
            .collect();
        let bufs: Vec<_> = frames.iter().map(|frame| io::IoSlice::new(frame)).collect();
        let expected = frames.concat();

        let sealed = client.ssl().seal_app_data_limits().is_some();
        match Pin::new(&mut client).poll_write_vectored(&mut cx, &bufs) {
            Poll::Ready(Ok(n)) => assert_eq!(n, expected.len()),
            result => panic!("vectored write failed: {result:?}"),
        }
        if sealed {
            // Records ignore slice boundaries: four full ones and the tail, in one poll.
            assert_eq!(client.get_ref().polls, 1);
            let records = records(&client.get_ref().tap);
            assert_eq!(records.len(), 5, "{records:?}");
            // Application data.
            assert!(records.iter().all(|&(kind, _)| kind == 23), "{records:?}");
            let full = records[0].1;
            let tail = expected.len() - 4 * MAX_RECORD;
            assert!(records[..4].iter().all(|&(_, len)| len == full));
            assert_eq!(records[4].1, full - (MAX_RECORD - tail));
        }

        client.shutdown().await.unwrap();
        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, expected);
    }
}

#[tokio::test]
async fn small_write_is_one_transport_write() {
    let (mut client, mut server) = tls_pair().await;
    let mut cx = Context::from_waker(Waker::noop());

    let res = Pin::new(&mut client).poll_write(&mut cx, &[1; 100]);
    assert!(matches!(res, Poll::Ready(Ok(100))));
    assert_eq!(client.get_ref().polls, 1);
    assert_eq!(client.0.get_ref().write_buf.capacity(), 0);

    // The record stays buffered while the transport takes nothing.
    client.get_mut().open = false;
    let res = Pin::new(&mut client).poll_write(&mut cx, &[2; 100]);
    assert!(matches!(res, Poll::Ready(Ok(100))));
    assert_eq!(client.get_ref().polls, 2);
    assert!(!client.0.get_ref().write_buf.is_empty());

    // Once the retry returns `Pending`, the transport is not polled again.
    let res = Pin::new(&mut client).poll_write(&mut cx, &[3; 100]);
    assert!(matches!(res, Poll::Ready(Ok(100))));
    assert_eq!(client.get_ref().polls, 3);

    // Nor once the `SSL_write` fallback's last record gets `Pending`.
    client.get_mut().open = true;
    client.flush().await.unwrap();
    client.get_mut().open = false;
    let polls = client.get_ref().polls;
    let bufs = [io::IoSlice::new(&[4; 100])];
    let res = Pin::new(&mut client).with_context(&mut cx, |s| {
        // `retry` resets this as each write starts; this call bypasses it.
        s.get_mut().write_buf.blocked = false;
        write::ssl_write_records(s, &bufs, 100)
    });
    assert_eq!(res.unwrap(), 100);
    assert_eq!(client.get_ref().polls, polls + 1);
    assert!(!client.0.get_ref().write_buf.is_empty());

    client.get_mut().open = true;
    client.shutdown().await.unwrap();
    let mut received = Vec::new();
    server.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, [[1; 100], [2; 100], [3; 100], [4; 100]].concat());
}

#[tokio::test]
async fn stack_overflow_goes_out_in_the_same_write() {
    // 32 CBC records of 512 bytes need more than `SEAL_STACK_LEN`.
    let connector = SslConnector::builder(SslMethod::tls()).unwrap();
    let (mut client, mut server) = tls_pair_from(
        connector,
        SslVersion::TLS1_2,
        Some(512),
        Some("ECDHE-RSA-AES128-SHA"),
    )
    .await;
    let mut cx = Context::from_waker(Waker::noop());
    let data: Vec<u8> = (0..MAX_RECORD).map(|i| (i % 251) as u8).collect();

    let limits = client.ssl().seal_app_data_limits();
    let res = Pin::new(&mut client).poll_write(&mut cx, &data);
    assert!(matches!(res, Poll::Ready(Ok(MAX_RECORD))), "{res:?}");
    if let Some(limits) = limits {
        assert!(limits.sealed_len(MAX_RECORD).unwrap() > SEAL_STACK_LEN);
        assert_eq!(client.get_ref().polls, 1);
        assert_eq!(records(&client.get_ref().tap).len(), MAX_RECORD / 512);
        assert!(client.0.get_ref().write_buf.is_empty());
    }

    client.shutdown().await.unwrap();
    let mut received = Vec::new();
    server.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, data);
}

#[tokio::test]
async fn first_server_write_carries_tickets() {
    let tickets = Arc::new(AtomicUsize::new(0));
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_session_cache_mode(SslSessionCacheMode::CLIENT);
    let counter = tickets.clone();
    connector.set_new_session_callback(move |_, _| {
        counter.fetch_add(1, Ordering::Relaxed);
    });
    let (mut client, mut server) = tls_pair_from(connector, SslVersion::TLS1_3, None, None).await;

    // The server defers its tickets to the first write, which seals them ahead of the data.
    let before = server.ssl().seal_app_data_limits();
    server.write_all(b"response").await.unwrap();
    let after = server.ssl().seal_app_data_limits();
    if let Some(before) = before {
        assert!(before.pending_len() > 0);
        assert_eq!(after.map(|limits| limits.pending_len()), Some(0));
    }

    let mut buf = [0; 8];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"response");
    assert!(tickets.load(Ordering::Relaxed) > 0);
}

#[tokio::test]
async fn key_update_ack_from_a_read_goes_out_first() {
    /// Pending handshake bytes, or `None` where sealing is unavailable.
    fn pending(ssl: &SslRef) -> Option<usize> {
        ssl.seal_app_data_limits()
            .map(|limits| limits.pending_len())
    }

    let large = vec![7; 100_000];
    // Client writes before and after the read that queues the ack, and the client records
    // in all, close_notify included.
    let cases: [(&[u8], &[u8], usize); 4] = [
        // No write: shutdown sends the ack.
        (b"", b"", 2),
        // Sealed on the stack.
        (b"", b"pong", 3),
        // Sealed behind a record buffered while the transport takes nothing.
        (b"a", b"b", 4),
        // Sealed into the buffer.
        (b"", &large, 9),
    ];
    for (early, late, count) in cases {
        let (mut client, mut server) = tls_pair_with(SslVersion::TLS1_3, None).await;
        let mut cx = Context::from_waker(Waker::noop());
        if !early.is_empty() {
            client.get_mut().open = false;
            let res = Pin::new(&mut client).poll_write(&mut cx, early);
            assert!(matches!(res, Poll::Ready(Ok(n)) if n == early.len()));
        }

        // SAFETY: `server.ssl()` is a live `SSL`.
        let requested = unsafe {
            btls_sys::SSL_key_update(server.ssl().as_ptr(), btls_sys::SSL_KEY_UPDATE_REQUESTED)
        };
        assert_eq!(requested, 1);
        server.write_all(b"ping").await.unwrap();
        let mut buf = [0; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert!(pending(client.ssl()).is_none_or(|len| len > 0));

        if !late.is_empty() {
            if early.is_empty() {
                client.write_all(late).await.unwrap();
            } else {
                let res = Pin::new(&mut client).poll_write(&mut cx, late);
                assert!(matches!(res, Poll::Ready(Ok(n)) if n == late.len()));
                client.get_mut().open = true;
            }
            assert!(pending(client.ssl()).is_none_or(|len| len == 0));
        }
        client.shutdown().await.unwrap();
        assert_eq!(records(&client.get_ref().tap).len(), count);

        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, [early, late].concat());
    }
}

#[tokio::test]
async fn write_after_shutdown_fails() {
    let (mut client, mut server) = tls_pair().await;
    let mut cx = Context::from_waker(Waker::noop());

    // close_notify stays buffered while the transport takes nothing.
    client.get_mut().open = false;
    assert!(Pin::new(&mut client).poll_shutdown(&mut cx).is_pending());
    let buffered = client.0.get_ref().write_buf.buffered().to_vec();
    assert!(!buffered.is_empty());

    let polls = client.get_ref().polls;
    match Pin::new(&mut client).poll_write(&mut cx, b"late") {
        Poll::Ready(Err(e)) => {
            let e = e.into_inner().unwrap().downcast::<ssl::Error>().unwrap();
            assert_eq!(e.code(), ErrorCode::SSL);
            let reason = e.ssl_error().unwrap().errors()[0].reason();
            assert_eq!(reason, Some("PROTOCOL_IS_SHUTDOWN"));
        }
        result => panic!("expected an SSL error: {result:?}"),
    }
    // Only the retry polled the transport, and nothing was added to the buffer.
    assert_eq!(client.get_ref().polls, polls + 1);
    assert_eq!(client.0.get_ref().write_buf.buffered(), buffered);

    client.get_mut().open = true;
    client.shutdown().await.unwrap();
    let mut received = Vec::new();
    server.read_to_end(&mut received).await.unwrap();
    assert!(received.is_empty());
}

#[tokio::test]
async fn shutdown_after_fatal_alert_closes_the_transport() {
    let (mut client, mut server) = tls_pair().await;
    let mut cx = Context::from_waker(Waker::noop());

    // A record that fails to open makes the client send a fatal alert, which stays buffered
    // while the transport takes nothing.
    let mut record = vec![23, 3, 3, 0, 32];
    record.resize(5 + 32, 0);
    server.get_mut().write_all(&record).await.unwrap();
    client.get_mut().open = false;
    let mut buf = [0; 16];
    let mut read = ReadBuf::new(&mut buf);
    let res = Pin::new(&mut client).poll_read(&mut cx, &mut read);
    assert!(matches!(res, Poll::Ready(Err(_))), "{res:?}");
    let alert = client.0.get_ref().write_buf.buffered().to_vec();
    assert!(matches!(records(&alert)[..], [(21, _)]), "{alert:?}");

    // Shutdown sends the alert in place of close_notify and closes the transport.
    client.get_mut().open = true;
    client.shutdown().await.unwrap();
    let mut wire = Vec::new();
    server.get_mut().read_to_end(&mut wire).await.unwrap();
    assert_eq!(wire, alert);
}

/// Accepts every write and fails every read with `NotConnected`.
struct Unconnected;

impl AsyncRead for Unconnected {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::ErrorKind::NotConnected.into()))
    }
}

impl AsyncWrite for Unconnected {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn handshake_reports_not_connected() {
    // btls retries `NotConnected` like `WouldBlock`, but no waker is registered for it.
    let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();
    let ssl = connector
        .configure()
        .unwrap()
        .into_ssl("localhost")
        .unwrap();
    let mut client = SslStream::new(ssl, Unconnected).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    match Pin::new(&mut client).poll_connect(&mut cx) {
        Poll::Ready(Err(e)) => {
            assert_eq!(
                e.io_error().map(io::Error::kind),
                Some(io::ErrorKind::NotConnected)
            );
        }
        result => panic!("expected NotConnected: {result:?}"),
    }
}
