//! Async TLS streams backed by BoringSSL.
//!
//! This crate provides a wrapper around the [`btls`] crate's [`SslStream`](ssl::SslStream) type
//! that works with with [`tokio`]'s [`AsyncRead`] and [`AsyncWrite`] traits rather than std's
//! blocking [`Read`] and [`Write`] traits.
//!
//! This file reimplements tokio-btls with the [overhauled](https://github.com/sfackler/tokio-openssl/commit/56f6618ab619f3e431fa8feec2d20913bf1473aa)
//! tokio-openssl interface while the tokio APIs from official [boring](https://github.com/cloudflare/boring) crate is not yet caught up
//! to it.

use std::{
    fmt, future,
    io::{self, Read, Write},
    mem,
    pin::Pin,
    task::{ready, Context, Poll},
};

use btls::{
    error::ErrorStack,
    ssl::{self, ErrorCode, ShutdownResult, Ssl, SslRef, SslStream as SslStreamCore},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Capacity of the ciphertext read buffer, large enough for one TLS record
/// supported by BoringSSL.
///
/// BoringSSL may request record headers and bodies in separate BIO reads.
/// Buffering lets these reads share data from one underlying read.
/// Larger bursts may require multiple refills.
const READ_BUF_CAPACITY: usize = 17 * 1024;

struct StreamWrapper<S> {
    stream: S,
    context: usize,
    read_buf: Vec<u8>,
    read_pos: usize,
    // Sealed records not yet written to `stream`.
    out_buf: Vec<u8>,
    // Set once `SSL_shutdown` has queued close_notify; later polls only flush it.
    shutdown_sent: bool,
}

/// Pending ciphertext at which sealing stops and writes return `Pending` until the transport
/// drains it.
const OUT_BUF_CAPACITY: usize = 64 * 1024;

/// Largest plaintext BoringSSL seals into one TLS record.
const MAX_RECORD: usize = 16 * 1024;

/// Per-record room reserved for header, nonce and tag; covers the AEAD suites.
const RECORD_OVERHEAD: usize = 64;

impl<S> fmt::Debug for StreamWrapper<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.stream, fmt)
    }
}

impl<S> StreamWrapper<S> {
    /// # Safety
    ///
    /// Must be called with `context` set to a valid pointer to a live `Context` object, and the
    /// wrapper must be pinned in memory.
    unsafe fn parts(&mut self) -> (Pin<&mut S>, &mut Context<'_>) {
        debug_assert_ne!(self.context, 0);
        let stream = Pin::new_unchecked(&mut self.stream);
        let context = &mut *(self.context as *mut _);
        (stream, context)
    }

    fn new(stream: S) -> Self {
        StreamWrapper {
            stream,
            context: 0,
            read_buf: Vec::new(),
            read_pos: 0,
            out_buf: Vec::new(),
            shutdown_sent: false,
        }
    }
}

impl<S> StreamWrapper<S>
where
    S: AsyncRead,
{
    /// Fills the empty read buffer with a single read of the underlying stream.
    ///
    /// Maps the underlying stream's `Poll::Pending` to `WouldBlock`.
    /// The underlying `AsyncRead` implementation registers the waker.
    fn fill_read_buf(&mut self) -> io::Result<()> {
        let mut read_buf = mem::take(&mut self.read_buf);
        read_buf.reserve(READ_BUF_CAPACITY);
        self.read_pos = 0;

        let (stream, cx) = unsafe { self.parts() };
        let mut buf = ReadBuf::uninit(read_buf.spare_capacity_mut());
        match stream.poll_read(cx, &mut buf)? {
            Poll::Ready(()) => {
                let filled = buf.filled().len();
                // SAFETY: `ReadBuf` guarantees its first `filled` bytes are initialized.
                unsafe { read_buf.set_len(filled) };
                self.read_buf = read_buf;
                Ok(())
            }
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

impl<S> Read for StreamWrapper<S>
where
    S: AsyncRead,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.read_buf.is_empty() {
            self.fill_read_buf()?;
        }

        let buffered = &self.read_buf[self.read_pos..];
        let n = buffered.len().min(buf.len());
        buf[..n].copy_from_slice(&buffered[..n]);
        self.read_pos += n;

        // Release the buffer as soon as it is drained, so a connection that stops reading here,
        // such as one returned to a pool, does not keep it.
        if self.read_pos == self.read_buf.len() {
            self.read_buf = Vec::new();
            self.read_pos = 0;
        }
        Ok(n)
    }
}

impl<S> StreamWrapper<S>
where
    S: AsyncWrite,
{
    fn out_pending(&self) -> usize {
        self.out_buf.len()
    }

    /// Writes buffered records to `stream`, keeping only what it did not accept.
    fn drain_out(&mut self) -> io::Result<()> {
        let mut pos = 0;
        let res = loop {
            if pos == self.out_buf.len() {
                break Ok(());
            }
            debug_assert_ne!(self.context, 0);
            // SAFETY: same invariants as `parts`; borrowing fields separately leaves `out_buf`
            // readable while the stream is written.
            let cx = unsafe { &mut *(self.context as *mut Context<'_>) };
            let stream = unsafe { Pin::new_unchecked(&mut self.stream) };
            match stream.poll_write(cx, &self.out_buf[pos..]) {
                Poll::Ready(Ok(0)) => break Err(io::ErrorKind::WriteZero.into()),
                Poll::Ready(Ok(n)) => pos += n,
                Poll::Ready(Err(e)) => break Err(e),
                Poll::Pending => break Err(io::Error::from(io::ErrorKind::WouldBlock)),
            }
        };
        if pos == self.out_buf.len() {
            // Like the read buffer, an idle connection holds no write buffer.
            self.out_buf = Vec::new();
        } else {
            // Partial writes must not leave sent bytes behind, or the buffer grows with traffic.
            self.out_buf.drain(..pos);
        }
        res
    }
}

/// Seals `bufs` into records and writes them to the transport in as few writes as possible.
///
/// Several small slices, such as an HTTP/2 frame header and its payload, share one record.
/// Larger input is sealed record by record until `OUT_BUF_CAPACITY` is pending, and all
/// sealed records then go out together. Records the transport cannot take yet stay buffered
/// for the next write or flush.
///
/// Each `SSL_write` gets at most one record of plaintext and nothing is sealed while the buffer
/// is full, so the BIO never refuses a record here whether or not the context enables
/// `SSL_MODE_ENABLE_PARTIAL_WRITE`. A refused record would stay pending in BoringSSL and fail
/// any retry with less data.
fn write_records<S>(
    s: &mut SslStreamCore<StreamWrapper<S>>,
    bufs: &[io::IoSlice<'_>],
) -> io::Result<usize>
where
    S: AsyncRead + AsyncWrite,
{
    let wrapper = s.get_mut();
    if wrapper.out_pending() > 0 {
        // Reports an error deferred by an earlier write before more plaintext is accepted.
        match wrapper.drain_out() {
            Err(e)
                if e.kind() != io::ErrorKind::WouldBlock
                    || wrapper.out_pending() >= OUT_BUF_CAPACITY =>
            {
                return Err(e);
            }
            _ => {}
        }
    }
    // Slices may alias, so the sum can exceed `usize::MAX` on 32-bit targets.
    let total = bufs.iter().fold(0usize, |n, b| n.saturating_add(b.len()));
    let sealed = total.min(OUT_BUF_CAPACITY);
    wrapper
        .out_buf
        .reserve(sealed + sealed.div_ceil(MAX_RECORD) * RECORD_OVERHEAD);

    let mut written = 0;
    let mut err = None;
    if total <= MAX_RECORD && bufs.iter().filter(|b| !b.is_empty()).count() > 1 {
        let mut record = Vec::with_capacity(total);
        for buf in bufs {
            record.extend_from_slice(buf);
        }
        match s.write(&record) {
            Ok(n) => written = n,
            Err(e) => err = Some(e),
        }
    } else {
        'bufs: for buf in bufs {
            let mut offset = 0;
            while offset < buf.len() {
                let end = buf.len().min(offset + MAX_RECORD);
                match s.write(&buf[offset..end]) {
                    Ok(n) => {
                        offset += n;
                        written += n;
                    }
                    Err(e) => {
                        err = Some(e);
                        break 'bufs;
                    }
                }
                if s.get_ref().out_pending() >= OUT_BUF_CAPACITY {
                    break 'bufs;
                }
            }
        }
    }

    let drained = s.get_mut().drain_out();
    if written > 0 {
        // The plaintext is sealed and buffered, so a retry would send it twice. A transport error
        // comes back from the next write or flush, which drain the buffer again.
        return Ok(written);
    }
    match (err, drained) {
        (Some(e), _) => Err(e),
        (None, Err(e)) if e.kind() != io::ErrorKind::WouldBlock => Err(e),
        (None, _) => Ok(0),
    }
}

impl<S> Write for StreamWrapper<S>
where
    S: AsyncWrite,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Only handshake flights and alerts can get here with a full buffer: `write_records`
        // starts each `SSL_write` below the cap, and one record is one BIO write.
        if self.out_pending() >= OUT_BUF_CAPACITY {
            self.drain_out()?;
        }
        self.out_buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.drain_out()?;
        let (stream, cx) = unsafe { self.parts() };
        match stream.poll_flush(cx) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

fn cvt<T>(r: io::Result<T>) -> Poll<io::Result<T>> {
    match r {
        Ok(v) => Poll::Ready(Ok(v)),
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
        Err(e) => Poll::Ready(Err(e)),
    }
}

fn cvt_ossl<T>(r: Result<T, ssl::Error>) -> Poll<Result<T, ssl::Error>> {
    match r {
        Ok(v) => Poll::Ready(Ok(v)),
        Err(e) => match e.code() {
            ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => Poll::Pending,
            _ => Poll::Ready(Err(e)),
        },
    }
}

/// An asynchronous version of [`btls::ssl::SslStream`].
///
/// Writes are sealed into a buffer and handed to the transport as it accepts them; a write can
/// complete with records still buffered, so call `flush` (or `shutdown`) before waiting on a
/// reply or dropping the stream.
#[derive(Debug)]
pub struct SslStream<S>(SslStreamCore<StreamWrapper<S>>);

impl<S: AsyncRead + AsyncWrite> SslStream<S> {
    #[inline]
    /// Like [`SslStream::new`](ssl::SslStream::new).
    pub fn new(ssl: Ssl, stream: S) -> Result<Self, ErrorStack> {
        SslStreamCore::new(ssl, StreamWrapper::new(stream)).map(SslStream)
    }

    #[inline]
    /// Like [`SslStream::connect`](ssl::SslStream::connect).
    pub fn poll_connect(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ssl::Error>> {
        self.with_context(cx, |s| cvt_ossl(s.connect()))
    }

    #[inline]
    /// A convenience method wrapping [`poll_connect`](Self::poll_connect).
    pub async fn connect(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_connect(cx)).await
    }

    #[inline]
    /// Like [`SslStream::accept`](ssl::SslStream::accept).
    pub fn poll_accept(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), ssl::Error>> {
        self.with_context(cx, |s| cvt_ossl(s.accept()))
    }

    #[inline]
    /// A convenience method wrapping [`poll_accept`](Self::poll_accept).
    pub async fn accept(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_accept(cx)).await
    }

    #[inline]
    /// Like [`SslStream::do_handshake`](ssl::SslStream::do_handshake).
    pub fn poll_do_handshake(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ssl::Error>> {
        self.with_context(cx, |s| cvt_ossl(s.do_handshake()))
    }

    #[inline]
    /// A convenience method wrapping [`poll_do_handshake`](Self::poll_do_handshake).
    pub async fn do_handshake(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_do_handshake(cx)).await
    }
}

impl<S> SslStream<S> {
    #[inline]
    /// Returns a shared reference to the `Ssl` object associated with this stream.
    pub fn ssl(&self) -> &SslRef {
        self.0.ssl()
    }

    #[inline]
    /// Returns a shared reference to the underlying stream.
    ///
    /// Its readiness (for example `readable()`) does not reflect ciphertext that has already been
    /// buffered.
    pub fn get_ref(&self) -> &S {
        &self.0.get_ref().stream
    }

    #[inline]
    /// Returns a mutable reference to the underlying stream.
    ///
    /// Reading from it directly skips ciphertext that has already been buffered, and its readiness
    /// (for example `readable()`) does not reflect that ciphertext. Writing to it directly can
    /// overtake records that are still buffered; flush first.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.0.get_mut().stream
    }

    #[inline]
    /// Returns a pinned mutable reference to the underlying stream.
    ///
    /// The same buffering caveats as [`get_mut`](Self::get_mut) apply.
    pub fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut S> {
        unsafe { Pin::new_unchecked(&mut self.get_unchecked_mut().0.get_mut().stream) }
    }

    fn with_context<F, R>(self: Pin<&mut Self>, ctx: &mut Context<'_>, f: F) -> R
    where
        F: FnOnce(&mut SslStreamCore<StreamWrapper<S>>) -> R,
    {
        let this = unsafe { self.get_unchecked_mut() };
        this.0.get_mut().context = ctx as *mut _ as usize;
        let r = f(&mut this.0);
        this.0.get_mut().context = 0;
        r
    }
}

impl<S> AsyncRead for SslStream<S>
where
    S: AsyncRead + AsyncWrite,
{
    fn poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.with_context(ctx, |s| {
            // SAFETY: read_uninit does not de-initialize the buffer.
            match cvt(s.read_uninit(unsafe { buf.unfilled_mut() }))? {
                Poll::Ready(nread) => {
                    // SAFETY: read_uninit guarantees that nread bytes have been initialized.
                    unsafe { buf.assume_init(nread) };
                    buf.advance(nread);
                    Poll::Ready(Ok(()))
                }
                Poll::Pending => Poll::Pending,
            }
        })
    }
}

impl<S> AsyncWrite for SslStream<S>
where
    S: AsyncRead + AsyncWrite,
{
    #[inline]
    fn poll_write(self: Pin<&mut Self>, ctx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.with_context(ctx, |s| cvt(write_records(s, &[io::IoSlice::new(buf)])))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.with_context(ctx, |s| cvt(write_records(s, bufs)))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> {
        self.with_context(ctx, |s| cvt(s.flush()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> {
        if !self.0.get_ref().shutdown_sent {
            match self.as_mut().with_context(ctx, |s| s.shutdown()) {
                Ok(ShutdownResult::Sent) | Ok(ShutdownResult::Received) => {}
                Err(ref e) if e.code() == ErrorCode::ZERO_RETURN => {}
                Err(ref e)
                    if e.code() == ErrorCode::WANT_READ || e.code() == ErrorCode::WANT_WRITE =>
                {
                    return Poll::Pending;
                }
                Err(e) => {
                    return Poll::Ready(Err(e.into_io_error().unwrap_or_else(io::Error::other)));
                }
            }
            // Calling `SSL_shutdown` again would wait for the peer's close_notify instead.
            self.as_mut()
                .with_context(ctx, |s| s.get_mut().shutdown_sent = true);
        }

        // close_notify is buffered like any record and must reach the transport first.
        ready!(self.as_mut().poll_flush(ctx))?;
        self.get_pin_mut().poll_shutdown(ctx)
    }
}

#[cfg(test)]
mod tests {
    use btls::ssl::{SslAcceptor, SslConnector, SslFiletype, SslMethod};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::*;

    /// Yields the given bytes in one read, then stays pending.
    struct Once(Vec<u8>);

    impl AsyncRead for Once {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.0.is_empty() {
                return Poll::Pending;
            }
            buf.put_slice(&mem::take(&mut self.0));
            Poll::Ready(Ok(()))
        }
    }

    /// Takes up to `budget` bytes, then stays pending.
    struct Sink {
        budget: usize,
        data: Vec<u8>,
    }

    impl AsyncWrite for Sink {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.budget == 0 {
                return Poll::Pending;
            }
            let n = buf.len().min(self.budget);
            self.budget -= n;
            self.data.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn write_buf_bounded_and_released() {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut wrapper = StreamWrapper::new(Sink {
            budget: 0,
            data: Vec::new(),
        });
        wrapper.context = &mut cx as *mut _ as usize;

        // A blocked transport stops buffering once the cap is reached.
        assert_eq!(
            wrapper.write(&[1; OUT_BUF_CAPACITY]).unwrap(),
            OUT_BUF_CAPACITY
        );
        let err = wrapper.write(&[2; 10]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(wrapper.out_pending(), OUT_BUF_CAPACITY);

        wrapper.stream.budget = usize::MAX;
        wrapper.flush().unwrap();
        assert_eq!(wrapper.stream.data.len(), OUT_BUF_CAPACITY);
        assert_eq!(wrapper.out_buf.capacity(), 0);
    }

    #[test]
    fn write_buf_bounded_under_partial_writes() {
        const CHUNK: usize = 16 * 1024;
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut wrapper = StreamWrapper::new(Sink {
            budget: 0,
            data: Vec::new(),
        });
        wrapper.context = &mut cx as *mut _ as usize;

        wrapper.write_all(&[0; 3 * CHUNK]).unwrap();
        for _ in 0..64 {
            wrapper.write_all(&[1; CHUNK]).unwrap();
            // The transport takes one record's worth per drain and never catches up.
            wrapper.stream.budget = CHUNK;
            let err = wrapper.drain_out().unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        }
        assert_eq!(wrapper.out_pending(), 3 * CHUNK);
        assert!(wrapper.out_buf.capacity() <= 2 * OUT_BUF_CAPACITY);
    }

    /// Duplex transport whose writes can be held back, or fail once with `Interrupted`.
    struct Gate {
        io: DuplexStream,
        open: bool,
        interrupt: bool,
    }

    impl AsyncRead for Gate {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for Gate {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if mem::take(&mut self.interrupt) {
                return Poll::Ready(Err(io::ErrorKind::Interrupted.into()));
            }
            if !self.open {
                return Poll::Pending;
            }
            Pin::new(&mut self.io).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.io).poll_shutdown(cx)
        }
    }

    async fn tls_pair() -> (SslStream<Gate>, SslStream<DuplexStream>) {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor
            .set_private_key_file("tests/key.pem", SslFiletype::PEM)
            .unwrap();
        acceptor
            .set_certificate_chain_file("tests/cert.pem")
            .unwrap();
        let acceptor = acceptor.build();
        let mut server = SslStream::new(Ssl::new(acceptor.context()).unwrap(), server_io).unwrap();

        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.set_ca_file("tests/cert.pem").unwrap();
        let ssl = connector
            .build()
            .configure()
            .unwrap()
            .into_ssl("localhost")
            .unwrap();
        let gate = Gate {
            io: client_io,
            open: true,
            interrupt: false,
        };
        let mut client = SslStream::new(ssl, gate).unwrap();

        let (connected, accepted) = tokio::join!(
            Pin::new(&mut client).connect(),
            Pin::new(&mut server).accept()
        );
        connected.unwrap();
        accepted.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn shutdown_resumes_after_backpressure() {
        let (mut client, mut server) = tls_pair().await;
        let mut cx = Context::from_waker(std::task::Waker::noop());

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
    async fn sealed_write_survives_transport_error() {
        let (mut client, mut server) = tls_pair().await;

        // The record is sealed before the transport fails; reporting the error would make the
        // caller send the plaintext again.
        client.get_mut().interrupt = true;
        assert_eq!(client.write(b"headerpayload").await.unwrap(), 13);
        client.shutdown().await.unwrap();

        let mut buf = Vec::new();
        server.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"headerpayload");
    }

    #[test]
    fn read_buf_released_when_drained() {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut wrapper = StreamWrapper::new(Once(vec![1; 100]));
        wrapper.context = &mut cx as *mut _ as usize;

        let mut buf = [0; 60];
        assert_eq!(wrapper.read(&mut buf).unwrap(), 60);
        assert_eq!(wrapper.read_buf.capacity(), READ_BUF_CAPACITY);

        assert_eq!(wrapper.read(&mut buf).unwrap(), 40);
        assert_eq!(wrapper.read_buf.capacity(), 0);

        let err = wrapper.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(wrapper.read_buf.capacity(), 0);
    }
}
