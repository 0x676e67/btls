//! Async TLS streams backed by BoringSSL.
//!
//! A handshake over a transport yields an [`SslStream`], which implements [`AsyncRead`] and
//! [`AsyncWrite`]. TLS parameters are configured through the [`btls`] crate, whose types start
//! the handshake through [`SslConnectorExt`], [`ConnectConfigurationExt`], [`SslAcceptorExt`]
//! and [`SslExt`].
//!
//! ```no_run
//! # async fn run() -> std::io::Result<()> {
//! use btls::ssl::{SslConnector, SslMethod};
//! use tokio::net::TcpStream;
//! use tokio_btls::SslConnectorExt;
//!
//! let connector = SslConnector::builder(SslMethod::tls())?.build();
//! let tcp = TcpStream::connect("example.com:443").await?;
//! let stream = connector.connect_async("example.com", tcp).await?;
//! # drop(stream);
//! # Ok(())
//! # }
//! ```
//!
//! An [`Ssl`] configured by hand starts one through [`SslExt`]. [`SslStream::new`] instead
//! wraps the transport first, for a handshake driven in place by
//! [`connect`](SslStream::connect), [`accept`](SslStream::accept) or
//! [`do_handshake`](SslStream::do_handshake).

mod bio;
mod error;
mod read;
#[cfg(test)]
mod tests;
mod transport;
mod write;

use std::{
    error::Error,
    fmt,
    future::{self, Future},
    io::{self, Write},
    pin::Pin,
    task::{ready, Context, Poll},
};

use btls::{
    error::ErrorStack,
    ssl::{
        self, ConnectConfiguration, ErrorCode, ShutdownResult, Ssl, SslAcceptor, SslConnector,
        SslMode, SslRef, SslStream as SslStreamCore,
    },
    x509::X509VerifyError,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    bio::StreamWrapper,
    error::{closed_by_alert, cvt, cvt_handshake, would_block},
};

/// One step of a handshake on a stream.
type PollHandshake<S> = fn(&mut SslStream<S>, &mut Context<'_>) -> Poll<Result<(), ssl::Error>>;

/// Async handshakes for [`SslConnector`].
pub trait SslConnectorExt: sealed::Sealed {
    /// Starts a client-side TLS handshake over `stream`.
    ///
    /// `domain` is used for SNI and hostname verification, as in
    /// [`ConnectConfiguration::into_ssl`].
    fn connect_async<S>(&self, domain: &str, stream: S) -> Handshake<S>
    where
        S: AsyncRead + AsyncWrite;
}

/// Async handshakes for [`ConnectConfiguration`].
pub trait ConnectConfigurationExt: sealed::Sealed {
    /// Starts a client-side TLS handshake over `stream`.
    ///
    /// `domain` is used for SNI and hostname verification, as in
    /// [`ConnectConfiguration::into_ssl`].
    fn connect_async<S>(self, domain: &str, stream: S) -> Handshake<S>
    where
        S: AsyncRead + AsyncWrite;
}

/// Async handshakes for [`SslAcceptor`].
pub trait SslAcceptorExt: sealed::Sealed {
    /// Starts a server-side TLS handshake over `stream`.
    fn accept_async<S>(&self, stream: S) -> Handshake<S>
    where
        S: AsyncRead + AsyncWrite;
}

/// Async handshakes for [`Ssl`].
pub trait SslExt: sealed::Sealed {
    /// Starts a client-side TLS handshake over `stream`.
    fn connect_async<S>(self, stream: S) -> Handshake<S>
    where
        S: AsyncRead + AsyncWrite;

    /// Starts a server-side TLS handshake over `stream`.
    fn accept_async<S>(self, stream: S) -> Handshake<S>
    where
        S: AsyncRead + AsyncWrite;
}

mod sealed {
    use btls::ssl::{ConnectConfiguration, Ssl, SslAcceptor, SslConnector};

    pub trait Sealed {}

    impl Sealed for SslConnector {}
    impl Sealed for ConnectConfiguration {}
    impl Sealed for SslAcceptor {}
    impl Sealed for Ssl {}
}

/// An asynchronous version of [`btls::ssl::SslStream`].
///
/// Writes may stay buffered after they complete; call `flush` or `shutdown` before waiting on a
/// reply or dropping the stream.
///
/// The stream is `Unpin` whatever its transport is: the transport stays in an allocation of its
/// own until the stream is dropped.
#[derive(Debug)]
pub struct SslStream<S>(SslStreamCore<StreamWrapper<S>>);

/// A TLS handshake in progress, which resolves to the [`SslStream`] it ran on.
///
/// Like every handshake poll, it stays pending while a callback on the `Ssl` asks to retry
/// later. Such a callback must wake the task; the async callbacks of [`btls`] do.
#[must_use = "futures do nothing unless polled"]
pub struct Handshake<S> {
    // `None` once the handshake has finished; an error if it could not be set up.
    stream: Option<Result<SslStream<S>, ErrorStack>>,
    poll: PollHandshake<S>,
}

/// The error of a failed [`Handshake`].
///
/// A handshake that failed after it started keeps its stream, for the verification result and
/// the transport.
pub struct HandshakeError<S>(Failure<S>);

enum Failure<S> {
    /// The `Ssl` or the stream could not be set up.
    Setup(ErrorStack),
    Handshake(ssl::Error, SslStream<S>),
}

// ===== impl SslConnectorExt =====

impl SslConnectorExt for SslConnector {
    fn connect_async<S>(&self, domain: &str, stream: S) -> Handshake<S>
    where
        S: AsyncRead + AsyncWrite,
    {
        let ssl = self.configure().and_then(|config| config.into_ssl(domain));
        Handshake::new(ssl, stream, SslStream::poll_connect)
    }
}

// ===== impl ConnectConfigurationExt =====

impl ConnectConfigurationExt for ConnectConfiguration {
    fn connect_async<S>(self, domain: &str, stream: S) -> Handshake<S>
    where
        S: AsyncRead + AsyncWrite,
    {
        Handshake::new(self.into_ssl(domain), stream, SslStream::poll_connect)
    }
}

// ===== impl SslAcceptorExt =====

impl SslAcceptorExt for SslAcceptor {
    fn accept_async<S>(&self, stream: S) -> Handshake<S>
    where
        S: AsyncRead + AsyncWrite,
    {
        Handshake::new(Ssl::new(self.context()), stream, SslStream::poll_accept)
    }
}

// ===== impl SslExt =====

impl SslExt for Ssl {
    fn connect_async<S>(self, stream: S) -> Handshake<S>
    where
        S: AsyncRead + AsyncWrite,
    {
        Handshake::new(Ok(self), stream, SslStream::poll_connect)
    }

    fn accept_async<S>(self, stream: S) -> Handshake<S>
    where
        S: AsyncRead + AsyncWrite,
    {
        Handshake::new(Ok(self), stream, SslStream::poll_accept)
    }
}

// ===== impl SslStream =====

// Moving the stream does not move the transport, which lives in the BIO's allocation, so the
// stream can hand out `Pin<&mut S>` without being pinned itself.
impl<S> Unpin for SslStream<S> {}

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
    ///
    /// It stays pending while a callback on the `Ssl` asks to retry later, as [`Handshake`]
    /// explains.
    pub fn poll_connect(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ssl::Error>> {
        self.poll_handshake(cx, SslStreamCore::connect)
    }

    #[inline]
    /// A convenience method wrapping [`poll_connect`](Self::poll_connect).
    pub async fn connect(&mut self) -> Result<(), ssl::Error> {
        future::poll_fn(|cx| self.poll_connect(cx)).await
    }

    #[inline]
    /// Like [`SslStream::accept`](ssl::SslStream::accept).
    pub fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ssl::Error>> {
        self.poll_handshake(cx, SslStreamCore::accept)
    }

    #[inline]
    /// A convenience method wrapping [`poll_accept`](Self::poll_accept).
    pub async fn accept(&mut self) -> Result<(), ssl::Error> {
        future::poll_fn(|cx| self.poll_accept(cx)).await
    }

    #[inline]
    /// Like [`SslStream::do_handshake`](ssl::SslStream::do_handshake).
    pub fn poll_do_handshake(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ssl::Error>> {
        self.poll_handshake(cx, SslStreamCore::do_handshake)
    }

    #[inline]
    /// A convenience method wrapping [`poll_do_handshake`](Self::poll_do_handshake).
    pub async fn do_handshake(&mut self) -> Result<(), ssl::Error> {
        future::poll_fn(|cx| self.poll_do_handshake(cx)).await
    }

    /// Runs one handshake step, lending `cx`'s waker to the async callbacks set on the `Ssl`.
    fn poll_handshake(
        &mut self,
        cx: &mut Context<'_>,
        step: fn(&mut SslStreamCore<StreamWrapper<S>>) -> Result<(), ssl::Error>,
    ) -> Poll<Result<(), ssl::Error>> {
        self.0.ssl_mut().set_task_waker(Some(cx.waker().clone()));
        let res = self.with_context(cx, step);
        self.0.ssl_mut().set_task_waker(None);
        cvt_handshake(res)
    }
}

impl<S> SslStream<S> {
    #[inline]
    /// Returns a shared reference to the `Ssl` object associated with this stream.
    ///
    /// Its `pending()` does not count plaintext this stream holds for the next read.
    pub fn ssl(&self) -> &SslRef {
        self.0.ssl()
    }

    #[inline]
    /// Returns a mutable reference to the `Ssl` object associated with this stream.
    ///
    /// Records must not be sealed or opened through it: the stream would lose track of them.
    pub fn ssl_mut(&mut self) -> &mut SslRef {
        self.0.ssl_mut()
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
    pub fn get_mut(&mut self) -> &mut S
    where
        S: Unpin,
    {
        &mut self.0.get_mut().transport.stream
    }

    #[inline]
    /// Returns a pinned mutable reference to the underlying stream.
    ///
    /// The same buffering caveats as [`get_mut`](Self::get_mut) apply.
    pub fn get_pin_mut(&mut self) -> Pin<&mut S> {
        // SAFETY: the transport stays in the BIO's allocation until it is dropped there; only
        // `S: Unpin` lets `get_mut` or `HandshakeError::into_source_stream` reach or move it.
        unsafe { Pin::new_unchecked(&mut self.0.get_mut().transport.stream) }
    }

    /// Runs `f` with `cx` installed for the transport I/O performed in it, clearing it even if
    /// `f` unwinds.
    fn with_context<F, R>(&mut self, cx: &mut Context<'_>, f: F) -> R
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

        // SAFETY: `cx` stays borrowed for this call and is not used again; `clear` clears it on
        // return or unwind. The transport is pinned as `get_pin_mut` explains.
        unsafe { self.0.get_mut().transport.set_context(cx) };
        let clear = Clear(&mut self.0);
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
        self.get_mut().with_context(ctx, |s| {
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
        self.get_mut().with_context(ctx, |s| {
            cvt(write::write_records(s, &[io::IoSlice::new(buf)]))
        })
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .with_context(ctx, |s| cvt(write::write_records(s, bufs)))
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        true
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> {
        self.get_mut().with_context(ctx, |s| cvt(s.flush()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.0.get_ref().shutdown_sent {
            ready!(this.with_context(ctx, |s| {
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
                let wrapper = s.get_mut();
                wrapper.shutdown_sent = true;
                // A quiet shutdown closes the read side too.
                wrapper.read_buf.ask_ssl();
                Poll::Ready(Ok(()))
            }))?;
        }

        // close_notify, or a fatal alert sent earlier, is buffered like any record.
        ready!(this.with_context(ctx, |s| cvt(s.flush())))?;
        this.get_pin_mut().poll_shutdown(ctx)
    }
}

// ===== impl Handshake =====

impl<S: AsyncRead + AsyncWrite> Handshake<S> {
    /// Wraps `stream` for a handshake driven by `poll`; a failure to do so is reported by the
    /// first poll.
    fn new(ssl: Result<Ssl, ErrorStack>, stream: S, poll: PollHandshake<S>) -> Self {
        Handshake {
            stream: Some(ssl.and_then(|ssl| SslStream::new(ssl, stream))),
            poll,
        }
    }
}

impl<S: AsyncRead + AsyncWrite> Future for Handshake<S> {
    type Output = Result<SslStream<S>, HandshakeError<S>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let failure = match this.stream.take() {
            Some(Ok(mut stream)) => match (this.poll)(&mut stream, cx) {
                Poll::Ready(Ok(())) => return Poll::Ready(Ok(stream)),
                Poll::Ready(Err(err)) => Failure::Handshake(err, stream),
                Poll::Pending => {
                    this.stream = Some(Ok(stream));
                    return Poll::Pending;
                }
            },
            Some(Err(err)) => Failure::Setup(err),
            // Polled again after it finished: an error rather than a panic, with no cause.
            None => Failure::Setup(ErrorStack::get()),
        };
        Poll::Ready(Err(HandshakeError(failure)))
    }
}

// ===== impl HandshakeError =====

impl<S> HandshakeError<S> {
    /// Returns the `Ssl` of the failed handshake, or `None` if it did not start.
    #[must_use]
    pub fn ssl(&self) -> Option<&SslRef> {
        match &self.0 {
            Failure::Setup(_) => None,
            Failure::Handshake(_, stream) => Some(stream.ssl()),
        }
    }

    /// Returns the error code of the failed handshake, if it started.
    #[must_use]
    pub fn code(&self) -> Option<ErrorCode> {
        match &self.0 {
            Failure::Setup(_) => None,
            Failure::Handshake(err, _) => Some(err.code()),
        }
    }

    /// Returns the transport error that failed the handshake, if any.
    #[must_use]
    pub fn as_io_error(&self) -> Option<&io::Error> {
        match &self.0 {
            Failure::Setup(_) => None,
            Failure::Handshake(err, _) => err.io_error(),
        }
    }

    /// Returns a shared reference to the transport of the failed handshake, if it started.
    #[must_use]
    pub fn as_source_stream(&self) -> Option<&S> {
        match &self.0 {
            Failure::Setup(_) => None,
            Failure::Handshake(_, stream) => Some(stream.get_ref()),
        }
    }

    /// Returns the transport of the failed handshake, if it started.
    ///
    /// Handshake records still buffered for it are dropped.
    #[must_use]
    pub fn into_source_stream(self) -> Option<S>
    where
        S: Unpin,
    {
        match self.0 {
            Failure::Setup(_) => None,
            Failure::Handshake(_, stream) => Some(stream.0.into_inner().transport.stream),
        }
    }
}

// The stream is left out, so the error is `Debug` whatever the transport is.
impl<S> fmt::Debug for HandshakeError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Failure::Setup(err) => f.debug_tuple("Setup").field(err).finish(),
            Failure::Handshake(err, _) => f.debug_tuple("Handshake").field(err).finish(),
        }
    }
}

impl<S> fmt::Display for HandshakeError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Failure::Setup(err) => write!(f, "TLS stream setup failed {err}"),
            Failure::Handshake(err, stream) => {
                f.write_str("TLS handshake failed")?;
                let ssl = stream.ssl();
                if ssl.ssl_context().has_x509_support() {
                    match ssl.verify_result() {
                        // No verification took place, such as before a certificate is sent.
                        Ok(()) | Err(X509VerifyError::INVALID_CALL) => {}
                        Err(verify) => write!(f, ": cert verification failed - {verify}")?,
                    }
                }
                write!(f, " {err}")
            }
        }
    }
}

impl<S> Error for HandshakeError<S> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.0 {
            Failure::Setup(err) => Some(err),
            Failure::Handshake(err, _) => Some(err),
        }
    }
}

impl<S> From<HandshakeError<S>> for io::Error {
    fn from(err: HandshakeError<S>) -> Self {
        match err.0 {
            Failure::Setup(err) => err.into(),
            Failure::Handshake(err, _) => err.into_io_error().unwrap_or_else(io::Error::other),
        }
    }
}
