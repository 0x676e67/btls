//! Async TLS streams backed by BoringSSL.
//!
//! This crate wraps the [`btls`] crate's [`SslStream`](ssl::SslStream) type so that it works
//! with [`tokio`]'s [`AsyncRead`] and [`AsyncWrite`] traits rather than std's blocking
//! [`Read`](io::Read) and [`Write`] traits.
//!
//! It follows the [overhauled](https://github.com/sfackler/tokio-openssl/commit/56f6618ab619f3e431fa8feec2d20913bf1473aa)
//! tokio-openssl interface, which the tokio APIs of the official
//! [boring](https://github.com/cloudflare/boring) crate have not caught up to.

mod bio;
mod error;
mod read;
#[cfg(test)]
mod tests;
mod transport;
mod write;

use std::{
    future,
    io::{self, Write},
    pin::Pin,
    task::{ready, Context, Poll},
};

use btls::{
    error::ErrorStack,
    ssl::{self, ErrorCode, ShutdownResult, Ssl, SslMode, SslRef, SslStream as SslStreamCore},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    bio::StreamWrapper,
    error::{closed_by_alert, cvt, cvt_ossl, would_block},
};

/// An asynchronous version of [`btls::ssl::SslStream`].
///
/// Writes may stay buffered after they complete; call `flush` or `shutdown` before waiting on a
/// reply or dropping the stream.
#[derive(Debug)]
pub struct SslStream<S>(SslStreamCore<StreamWrapper<S>>);

impl<S: AsyncRead + AsyncWrite> SslStream<S> {
    #[inline]
    /// Like [`SslStream::new`](ssl::SslStream::new), but also enables
    /// [`SslMode::ENABLE_PARTIAL_WRITE`] on `ssl`.
    pub fn new(mut ssl: Ssl, stream: S) -> Result<Self, ErrorStack> {
        // Allow `SSL_write` to return after one plaintext fragment.
        ssl.set_mode(SslMode::ENABLE_PARTIAL_WRITE);
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
        &self.0.get_ref().transport.stream
    }

    #[inline]
    /// Returns a mutable reference to the underlying stream.
    ///
    /// Reading from it directly skips ciphertext that has already been buffered, and its readiness
    /// (for example `readable()`) does not reflect that ciphertext. Flush before writing to it.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.0.get_mut().transport.stream
    }

    #[inline]
    /// Returns a pinned mutable reference to the underlying stream.
    ///
    /// The same buffering caveats as [`get_mut`](Self::get_mut) apply.
    pub fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut S> {
        // SAFETY: the stream is structurally pinned; it is never moved out of a pinned `SslStream`.
        unsafe { Pin::new_unchecked(&mut self.get_unchecked_mut().0.get_mut().transport.stream) }
    }

    /// Runs `f` with `ctx` installed for the transport I/O performed in it, clearing it even if
    /// `f` unwinds.
    fn with_context<F, R>(self: Pin<&mut Self>, ctx: &mut Context<'_>, f: F) -> R
    where
        F: FnOnce(&mut SslStreamCore<StreamWrapper<S>>) -> R,
    {
        /// Clears the installed context when dropped.
        struct Clear<'a, S>(&'a mut SslStreamCore<StreamWrapper<S>>);

        impl<S> Drop for Clear<'_, S> {
            fn drop(&mut self) {
                self.0.get_mut().transport.clear_context();
            }
        }

        // SAFETY: nothing is moved out of `this`; `Transport::parts` re-pins the stream in place.
        let this = unsafe { self.get_unchecked_mut() };
        // SAFETY: `ctx` stays borrowed for this call and is not used again; `clear` clears it on
        // return or unwind. The stream is structurally pinned in this `SslStream`.
        unsafe { this.0.get_mut().transport.set_context(ctx) };
        let clear = Clear(&mut this.0);
        f(&mut *clear.0)
    }
}

impl<S> AsyncRead for SslStream<S>
where
    S: AsyncRead + AsyncWrite,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.with_context(ctx, |s| {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if let Some(end) = s.get_mut().read_end.take() {
                return Poll::Ready(end);
            }
            if let Some(poll) = read::read_in_place(s, buf) {
                return poll;
            }
            // SSL_read returns at most one record, so keep reading while buffered ciphertext can
            // fill the caller's buffer. An end or error met after taking plaintext is reported by
            // the next read.
            let start = buf.filled().len();
            let end = loop {
                // SAFETY: read_uninit does not de-initialize the buffer.
                match cvt(s.read_uninit(unsafe { buf.unfilled_mut() })) {
                    Poll::Ready(Ok(0)) => break Some(Ok(())),
                    Poll::Ready(Ok(nread)) => {
                        // SAFETY: read_uninit guarantees that nread bytes have been initialized.
                        unsafe { buf.assume_init(nread) };
                        buf.advance(nread);
                        // Without buffered ciphertext, another record needs a transport poll.
                        if buf.remaining() == 0 || s.get_ref().read_buf.is_empty() {
                            break None;
                        }
                    }
                    Poll::Ready(Err(err)) => break Some(Err(err)),
                    Poll::Pending => break None,
                }
            };
            if buf.filled().len() == start {
                return end.map_or(Poll::Pending, Poll::Ready);
            }
            s.get_mut().read_end = end;
            Poll::Ready(Ok(()))
        })
    }
}

impl<S> AsyncWrite for SslStream<S>
where
    S: AsyncRead + AsyncWrite,
{
    #[inline]
    fn poll_write(self: Pin<&mut Self>, ctx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.with_context(ctx, |s| {
            cvt(write::write_records(s, &[io::IoSlice::new(buf)]))
        })
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.with_context(ctx, |s| cvt(write::write_records(s, bufs)))
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        true
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> {
        self.with_context(ctx, |s| cvt(s.flush()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> {
        if !self.0.get_ref().shutdown_sent {
            ready!(self.as_mut().with_context(ctx, |s| {
                match s.shutdown() {
                    Ok(ShutdownResult::Sent) | Ok(ShutdownResult::Received) => {}
                    Err(ref e) if e.code() == ErrorCode::ZERO_RETURN => {}
                    // A fatal alert already closed the write side; flush it and close the transport.
                    Err(ref e) if closed_by_alert(e) => {}
                    Err(ref e) if would_block(e) => return Poll::Pending,
                    Err(e) => {
                        return Poll::Ready(Err(e
                            .into_io_error()
                            .unwrap_or_else(io::Error::other)));
                    }
                }

                // Calling `SSL_shutdown` again would wait for the peer's close_notify, which is
                // not required: https://www.rfc-editor.org/rfc/rfc8446#section-6.1
                s.get_mut().shutdown_sent = true;
                Poll::Ready(Ok(()))
            }))?;
        }

        // close_notify, or a fatal alert sent earlier, is buffered like any record.
        ready!(self.as_mut().poll_flush(ctx))?;
        self.get_pin_mut().poll_shutdown(ctx)
    }
}
