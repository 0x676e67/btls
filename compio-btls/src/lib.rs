//! Async TLS streams backed by BoringSSL.
//!
//! This crate provides a wrapper around the [`btls`] crate's [`SslStream`](ssl::SslStream) type
//! that works with [`compio-io`]'s [`AsyncRead`] and [`AsyncWrite`] traits rather than std's
//! blocking [`Read`] and [`Write`] traits.
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

use btls::{
    error::ErrorStack,
    ssl::{self, ErrorCode, Ssl, SslRef, SslStream as SslStreamCore},
};
use compio::buf::{IoBuf, IoBufMut};
use compio::BufResult;
use compio_io::{compat::SyncStream, AsyncRead, AsyncWrite};
use std::io;
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

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
pub struct SslStream<S>(SslStreamCore<SyncStream<S>>);

impl<S: AsyncRead + AsyncWrite> SslStream<S> {
    #[inline]
    /// Like [`SslStream::new`](ssl::SslStream::new).
    pub fn new(ssl: Ssl, stream: S) -> Result<Self, ErrorStack> {
        SslStreamCore::new(ssl, SyncStream::new(stream)).map(SslStream)
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
    pub async fn connect(self: Pin<&mut Self>) -> Result<(), ssl::Error> {
        self.drive_handshake(|s| s.connect()).await
    }

    #[inline]
    /// Like [`SslStream::accept`](ssl::SslStream::accept).
    pub fn poll_accept(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), ssl::Error>> {
        self.with_context(cx, |s| cvt_ossl(s.accept()))
    }

    #[inline]
    /// A convenience method wrapping [`poll_accept`](Self::poll_accept).
    pub async fn accept(self: Pin<&mut Self>) -> Result<(), ssl::Error> {
        self.drive_handshake(|s| s.accept()).await
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
    pub async fn do_handshake(self: Pin<&mut Self>) -> Result<(), ssl::Error> {
        self.drive_handshake(|s| s.do_handshake()).await
    }

    async fn drive_handshake<F>(mut self: Pin<&mut Self>, mut f: F) -> Result<(), ssl::Error>
    where
        F: FnMut(&mut SslStreamCore<SyncStream<S>>) -> Result<(), ssl::Error>,
    {
        loop {
            let res = {
                let this = unsafe { self.as_mut().get_unchecked_mut() };
                f(&mut this.0)
            };

            match res {
                Ok(()) => {
                    // Ensure handshake records are pushed out before returning.
                    if self.as_mut().flush_write_buf().await.is_err() {
                        // Keep API compatibility: this method reports ssl::Error.
                    }
                    return Ok(());
                }
                Err(e) => match e.code() {
                    ErrorCode::WANT_WRITE => {
                        if self.as_mut().flush_write_buf().await.is_err() {
                            return Err(e);
                        }
                    }
                    ErrorCode::WANT_READ => {
                        if self.as_mut().flush_write_buf().await.is_err() {
                            return Err(e);
                        }
                        if self.as_mut().fill_read_buf().await.is_err() {
                            return Err(e);
                        }
                    }
                    _ => return Err(e),
                },
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite> SslStream<S> {
    async fn fill_read_buf(mut self: Pin<&mut Self>) -> io::Result<usize> {
        let this = unsafe { self.as_mut().get_unchecked_mut() };
        this.0.get_mut().fill_read_buf().await
    }

    async fn flush_write_buf(mut self: Pin<&mut Self>) -> io::Result<usize> {
        let this = unsafe { self.as_mut().get_unchecked_mut() };
        this.0.get_mut().flush_write_buf().await
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
        self.0.get_ref().get_ref()
    }

    #[inline]
    /// Returns a mutable reference to the underlying stream.
    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut().get_mut()
    }

    #[inline]
    /// Returns a pinned mutable reference to the underlying stream.
    pub fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut S> {
        unsafe {
            let this = self.get_unchecked_mut();
            Pin::new_unchecked(this.0.get_mut().get_mut())
        }
    }

    fn with_context<F, R>(self: Pin<&mut Self>, ctx: &mut Context<'_>, f: F) -> R
    where
        F: FnOnce(&mut SslStreamCore<SyncStream<S>>) -> R,
    {
        let this = unsafe { self.get_unchecked_mut() };
        this.0.ssl_mut().set_task_waker(Some(ctx.waker().clone()));
        let r = f(&mut this.0);
        this.0.ssl_mut().set_task_waker(None);
        r
    }
}

impl<S> AsyncRead for SslStream<S>
where
    S: AsyncRead + AsyncWrite,
{
    async fn read<B: IoBufMut>(&mut self, mut buf: B) -> BufResult<usize, B> {
        let slice = buf.as_uninit();

        let mut f = {
            slice.fill(MaybeUninit::new(0));
            // SAFETY: The memory has been initialized.
            let slice =
                unsafe { std::slice::from_raw_parts_mut(slice.as_mut_ptr().cast(), slice.len()) };
            |s: &mut _| std::io::Read::read(s, slice)
        };

        loop {
            match f(&mut self.0) {
                Ok(res) => {
                    unsafe { buf.set_len(res) };
                    return BufResult(Ok(res), buf);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    match self.0.get_mut().fill_read_buf().await {
                        Ok(_) => continue,
                        Err(e) => return BufResult(Err(e), buf),
                    }
                }
                res => return BufResult(res, buf),
            }
        }
    }
}

impl<S> AsyncWrite for SslStream<S>
where
    S: AsyncRead + AsyncWrite,
{
    async fn write<T: IoBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        let slice = buf.as_init();
        loop {
            let res = io::Write::write(&mut self.0, slice);
            match res {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => match self.flush().await {
                    Ok(_) => continue,
                    Err(e) => return BufResult(Err(e), buf),
                },
                _ => return BufResult(res, buf),
            }
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        loop {
            match io::Write::flush(&mut self.0) {
                Ok(()) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.0.get_mut().flush_write_buf().await?;
                }
                Err(e) => return Err(e),
            }
        }
        self.0.get_mut().flush_write_buf().await?;
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.flush().await?;
        self.0.get_mut().get_mut().shutdown().await
    }
}
