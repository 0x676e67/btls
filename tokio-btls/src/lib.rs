//! Async TLS streams backed by BoringSSL.
//!
//! This crate provides a wrapper around the [`btls`] crate's [`SslStream`](ssl::SslStream) type
//! that works with with [`tokio`]'s [`AsyncRead`] and [`AsyncWrite`] traits rather than std's
//! blocking [`Read`] and [`Write`] traits.
//!
//! This file reimplements tokio-btls with the [overhauled](https://github.com/sfackler/tokio-openssl/commit/56f6618ab619f3e431fa8feec2d20913bf1473aa)
//! tokio-openssl interface while the tokio APIs from official [boring](https://github.com/cloudflare/boring) crate is not yet caught up
//! to it.
//!
//! A client's certificate verification runs on Tokio's blocking thread pool, so that it does not
//! hold up the runtime; see [`SslStream::new`]. The handshake also waits for the futures of
//! btls's async callbacks, such as
//! [`set_async_custom_verify_callback`](ssl::SslContextBuilder::set_async_custom_verify_callback).

use std::{
    fmt, future,
    io::{self, Read, Write},
    pin::Pin,
    task::{Context, Poll},
};

use btls::{
    error::ErrorStack,
    ssl::{self, ErrorCode, ShutdownResult, Ssl, SslRef, SslStream as SslStreamCore, VerifyJob},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct StreamWrapper<S> {
    stream: S,
    context: usize,
}

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
}

impl<S> Read for StreamWrapper<S>
where
    S: AsyncRead,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (stream, cx) = unsafe { self.parts() };
        let mut buf = ReadBuf::new(buf);
        match stream.poll_read(cx, &mut buf)? {
            Poll::Ready(()) => Ok(buf.filled().len()),
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

impl<S> Write for StreamWrapper<S>
where
    S: AsyncWrite,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (stream, cx) = unsafe { self.parts() };
        match stream.poll_write(cx, buf) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
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

/// Runs a certificate verification on the blocking thread pool, or right away outside a runtime.
fn spawn_verify(job: VerifyJob) {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => drop(handle.spawn_blocking(job)),
        Err(_) => job(),
    }
}

/// An asynchronous version of [`btls::ssl::SslStream`].
#[derive(Debug)]
pub struct SslStream<S>(SslStreamCore<StreamWrapper<S>>, Verify);

/// Where a client's certificate verification runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verify {
    BlockingPool,
    Inline,
}

impl<S: AsyncRead + AsyncWrite> SslStream<S> {
    #[inline]
    /// Like [`SslStream::new`](ssl::SslStream::new).
    ///
    /// When the handshake starts as a client, the server's certificate chain is verified on
    /// Tokio's blocking thread pool with [`SslRef::try_set_async_default_verify`], unless a
    /// verify callback is configured by then. The result is that of BoringSSL's built-in
    /// verification, which may block, e.g. to read certificates from disk.
    pub fn new(ssl: Ssl, stream: S) -> Result<Self, ErrorStack> {
        Self::with_verify(ssl, stream, Verify::BlockingPool)
    }

    #[inline]
    /// Like [`Self::new`], but keeps BoringSSL's built-in verification on the task's thread.
    pub fn with_inline_verify(ssl: Ssl, stream: S) -> Result<Self, ErrorStack> {
        Self::with_verify(ssl, stream, Verify::Inline)
    }

    fn with_verify(ssl: Ssl, stream: S, verify: Verify) -> Result<Self, ErrorStack> {
        let stream = StreamWrapper { stream, context: 0 };
        SslStreamCore::new(ssl, stream).map(|s| SslStream(s, verify))
    }

    #[inline]
    /// Like [`SslStream::connect`](ssl::SslStream::connect).
    pub fn poll_connect(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ssl::Error>> {
        self.with_handshake_context(cx, Verify::BlockingPool, |s| s.connect())
    }

    #[inline]
    /// A convenience method wrapping [`poll_connect`](Self::poll_connect).
    pub async fn connect(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_connect(cx)).await
    }

    #[inline]
    /// Like [`SslStream::accept`](ssl::SslStream::accept).
    pub fn poll_accept(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), ssl::Error>> {
        self.with_handshake_context(cx, Verify::Inline, |s| s.accept())
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
        self.with_handshake_context(cx, Verify::BlockingPool, |s| s.do_handshake())
    }

    #[inline]
    /// A convenience method wrapping [`poll_do_handshake`](Self::poll_do_handshake).
    pub async fn do_handshake(mut self: Pin<&mut Self>) -> Result<(), ssl::Error> {
        future::poll_fn(|cx| self.as_mut().poll_do_handshake(cx)).await
    }

    /// Drives the handshake with `f`, with the task's waker as the `Ssl`'s task waker, so that
    /// the future of an async callback wakes the task once the handshake can continue.
    ///
    /// `verify` is where `f` may verify a client's certificates: `accept` sets the role of the
    /// `Ssl` only once it runs, so it cannot tell yet.
    fn with_handshake_context<F>(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        verify: Verify,
        f: F,
    ) -> Poll<Result<(), ssl::Error>>
    where
        F: FnOnce(&mut SslStreamCore<StreamWrapper<S>>) -> Result<(), ssl::Error>,
    {
        let blocking_pool = self.1 == Verify::BlockingPool && verify == Verify::BlockingPool;
        let waker = cx.waker().clone();
        self.with_context(cx, |s| {
            if blocking_pool {
                // Does nothing once set, or for a server.
                s.ssl_mut().try_set_async_default_verify(spawn_verify);
            }
            s.ssl_mut().set_task_waker(Some(waker));
            let result = f(s);
            let pending = s.ssl_mut().has_pending_async_callback();
            s.ssl_mut().set_task_waker(None);
            match result {
                // Only a pending future wakes the task: an error from a synchronous callback
                // asking to retry is returned.
                Err(e) if pending && e.would_block() => Poll::Pending,
                result => cvt_ossl(result),
            }
        })
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
    pub fn get_ref(&self) -> &S {
        &self.0.get_ref().stream
    }

    #[inline]
    /// Returns a mutable reference to the underlying stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.0.get_mut().stream
    }

    #[inline]
    /// Returns a pinned mutable reference to the underlying stream.
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
        self.with_context(ctx, |s| cvt(s.write(buf)))
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> {
        self.with_context(ctx, |s| cvt(s.flush()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> {
        match self.as_mut().with_context(ctx, |s| s.shutdown()) {
            Ok(ShutdownResult::Sent) | Ok(ShutdownResult::Received) => {}
            Err(ref e) if e.code() == ErrorCode::ZERO_RETURN => {}
            Err(ref e) if e.code() == ErrorCode::WANT_READ || e.code() == ErrorCode::WANT_WRITE => {
                return Poll::Pending;
            }
            Err(e) => {
                return Poll::Ready(Err(e.into_io_error().unwrap_or_else(io::Error::other)));
            }
        }

        self.get_pin_mut().poll_shutdown(ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use btls::ssl::{SslConnector, SslMethod};

    /// Starts a client handshake and returns whether the async verification could still be set,
    /// i.e. whether the stream left it alone.
    async fn left_alone(inline_verify: bool) -> bool {
        let ssl = SslConnector::builder(SslMethod::tls())
            .unwrap()
            .build()
            .configure()
            .unwrap()
            .into_ssl("localhost")
            .unwrap();
        let (stream, _peer) = tokio::io::duplex(1 << 16);
        let mut stream = if inline_verify {
            SslStream::with_inline_verify(ssl, stream).unwrap()
        } else {
            SslStream::new(ssl, stream).unwrap()
        };
        future::poll_fn(|cx| {
            assert!(Pin::new(&mut stream).poll_connect(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        stream.0.ssl_mut().try_set_async_default_verify(drop)
    }

    #[tokio::test]
    async fn client_verifies_on_blocking_pool() {
        assert!(!left_alone(false).await);
        assert!(left_alone(true).await);
    }
}
