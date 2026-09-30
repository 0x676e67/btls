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
    task::{Context, Poll},
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

    fn new(stream: S) -> Self {
        StreamWrapper {
            stream,
            context: 0,
            read_buf: Vec::new(),
            read_pos: 0,
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

/// An asynchronous version of [`btls::ssl::SslStream`].
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
    /// (for example `readable()`) does not reflect that ciphertext.
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
