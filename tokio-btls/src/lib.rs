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
    mem::{self, MaybeUninit},
    pin::Pin,
    slice,
    task::{ready, Context, Poll},
};

use btls::{
    error::ErrorStack,
    ssl::{self, ErrorCode, ShutdownResult, Ssl, SslMode, SslRef, SslStream as SslStreamCore},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Capacity of the ciphertext read buffer, large enough for one TLS record
/// supported by BoringSSL.
///
/// BoringSSL may request record headers and bodies in separate BIO reads.
/// Buffering lets these reads share data from one underlying read.
/// Larger bursts may require multiple refills.
const READ_BUF_CAPACITY: usize = 17 * 1024;

/// Buffered ciphertext threshold at which writes stop sealing, except for a final
/// plaintext tail of at most `MAX_RECORD` bytes.
const OUT_BUF_CAPACITY: usize = 64 * 1024;

/// Largest plaintext in one TLS record.
const MAX_RECORD: usize = 16 * 1024;

/// Room reserved per record for header, nonce and tag.
const RECORD_OVERHEAD: usize = 64;

/// Output room for writes sealed on the stack: one full record plus a ticket flight.
const SEAL_STACK_LEN: usize = 17 * 1024;

/// An asynchronous version of [`btls::ssl::SslStream`].
///
/// Writes may stay buffered after they complete; call `flush` or `shutdown` before waiting on a
/// reply or dropping the stream.
#[derive(Debug)]
pub struct SslStream<S>(SslStreamCore<StreamWrapper<S>>);

/// The BIO stream handed to BoringSSL, buffering ciphertext in both directions.
struct StreamWrapper<S> {
    transport: Transport<S>,
    read_buf: ReadBuffer,
    out_buf: OutBuffer,
    // Set while sealing the last record of a write, which goes straight to the transport.
    write_through: bool,
    // Set once `SSL_shutdown` has queued close_notify; later polls only flush it.
    shutdown_sent: bool,
}

/// The underlying stream and the task context of the poll driving it.
///
/// `context` is valid only inside `SslStream::with_context`, so all I/O through
/// [`parts`](Self::parts) happens there.
struct Transport<S> {
    stream: S,
    // Address of the `Context` installed by `SslStream::with_context`; reset to 0 when it returns.
    context: usize,
}

/// Ciphertext read from the transport but not yet taken by BoringSSL.
#[derive(Default)]
struct ReadBuffer {
    bytes: Vec<u8>,
    // The next byte to hand out is `bytes[pos]`.
    pos: usize,
}

/// Sealed records not yet written to the transport.
#[derive(Default)]
struct OutBuffer {
    bytes: Vec<u8>,
}

/// Packs the slices of one write into the plaintext of successive records.
///
/// A record within the current slice is borrowed in place; one spanning slices is copied into
/// `scratch`.
struct Packer<'a> {
    bufs: &'a [io::IoSlice<'a>],
    // The next unsealed byte is `bufs[i][off]`.
    i: usize,
    off: usize,
    scratch: Vec<u8>,
}

/// Seals `bufs` into records and writes them with as few transport writes as possible.
///
/// BoringSSL seals records across slice boundaries straight into caller memory: on the stack for
/// a write of at most `MAX_RECORD` bytes with nothing buffered, otherwise after the buffered
/// records, within [`seal_budget`]. [`ssl_write_records`] handles the states it declines. Either
/// way, a transport that returned `Pending` in this call is not polled again.
fn write_records<S>(
    s: &mut SslStreamCore<StreamWrapper<S>>,
    bufs: &[io::IoSlice<'_>],
) -> io::Result<usize>
where
    S: AsyncRead + AsyncWrite,
{
    let wrapper = s.get_mut();
    wrapper.out_buf.retry(&mut wrapper.transport)?;
    // Records stay buffered after a retry only if the transport returned `Pending`, which
    // registered the waker.
    let blocked = !wrapper.out_buf.is_empty();
    // Slices may alias, so the sum can exceed `usize::MAX` on 32-bit targets.
    let total = bufs.iter().fold(0usize, |n, b| n.saturating_add(b.len()));
    if total > 0 {
        if total <= MAX_RECORD && !blocked {
            if let Some(n) = seal_on_stack(s, bufs, total)? {
                return Ok(n);
            }
        }
        if let Some(limits) = s.ssl().seal_app_data_limits() {
            let budget = seal_budget(
                limits.max_fragment(),
                limits.record_overhead(),
                limits.pending_len(),
                s.get_ref().out_buf.len(),
                total,
            );
            if let Some(max_out) = limits.sealed_len(budget) {
                if let Some(n) = seal_into_out_buf(s, bufs, budget, max_out, blocked)? {
                    return Ok(n);
                }
            }
        }
    }
    ssl_write_records(s, bufs, total, blocked)
}

/// Plaintext to seal in one call: stop once about `OUT_BUF_CAPACITY` of ciphertext is buffered,
/// but take a final tail of at most `MAX_RECORD` bytes too, like [`ssl_write_records`].
///
/// `pending` handshake bytes go out ahead of the records, after the `buffered` ones.
fn seal_budget(
    fragment: usize,
    overhead: usize,
    pending: usize,
    buffered: usize,
    total: usize,
) -> usize {
    let room = OUT_BUF_CAPACITY
        .saturating_sub(buffered)
        .saturating_sub(pending);
    // The `SSL_write` loop seals at least one record per call.
    let records = room
        .div_ceil(fragment.saturating_add(overhead).max(1))
        .max(1);
    let cap = records.saturating_mul(fragment);
    if total.saturating_sub(cap) <= MAX_RECORD {
        total
    } else {
        cap
    }
}

/// Seals a write of at most `MAX_RECORD` bytes on the stack and sends it with one transport
/// write.
///
/// Returns `Ok(None)` if BoringSSL declines, changing nothing, or seals no plaintext.
#[inline(never)] // keep the 17 KiB frame out of `write_records`
fn seal_on_stack<S>(
    s: &mut SslStreamCore<StreamWrapper<S>>,
    bufs: &[io::IoSlice<'_>],
    total: usize,
) -> io::Result<Option<usize>>
where
    S: AsyncRead + AsyncWrite,
{
    let mut out = [MaybeUninit::<u8>::uninit(); SEAL_STACK_LEN];
    let sealed = match s.ssl_mut().seal_app_data(bufs, total, &mut out) {
        Ok(Some(sealed)) => sealed,
        Ok(None) => return Ok(None),
        Err(e) => return Err(io::Error::other(ssl::Error::from(e))),
    };
    // SAFETY: `seal_app_data` initialized the first `written` bytes of `out`, and `written` is at
    // most `out.len()`.
    let records = unsafe { slice::from_raw_parts(out.as_ptr().cast::<u8>(), sealed.written) };
    let wrapper = s.get_mut();
    debug_assert!(wrapper.out_buf.is_empty(), "sealing wrote to the BIO");
    // What the transport does not take stays buffered; an error surfaces on the next call.
    wrapper.out_buf.write_last(&mut wrapper.transport, records);
    Ok((sealed.consumed > 0).then_some(sealed.consumed))
}

/// Seals up to `budget` plaintext bytes after the buffered records, then drains them unless the
/// transport is `blocked`.
///
/// `max_out` is the output room the budget needs. Returns `Ok(None)` if BoringSSL declines,
/// changing nothing, or seals no plaintext.
fn seal_into_out_buf<S>(
    s: &mut SslStreamCore<StreamWrapper<S>>,
    bufs: &[io::IoSlice<'_>],
    budget: usize,
    max_out: usize,
    blocked: bool,
) -> io::Result<Option<usize>>
where
    S: AsyncRead + AsyncWrite,
{
    // The buffer lives behind the BIO, so move it out while the `SslRef` is borrowed mutably.
    let mut out = s.get_mut().out_buf.take();
    out.reserve(max_out);
    let res = s
        .ssl_mut()
        .seal_app_data(bufs, budget, &mut out.spare_capacity_mut()[..max_out]);
    if let Ok(Some(sealed)) = res {
        // SAFETY: `seal_app_data` initialized the first `written` bytes of the spare capacity,
        // and `written` is at most `max_out`, which `reserve` made room for.
        unsafe { out.set_len(out.len() + sealed.written) };
    }
    let wrapper = s.get_mut();
    wrapper.out_buf.restore(out);
    let consumed = match res {
        Ok(Some(sealed)) if sealed.consumed > 0 => sealed.consumed,
        Ok(_) => return Ok(None),
        Err(e) => return Err(io::Error::other(ssl::Error::from(e))),
    };
    if !blocked {
        // A drain error leaves the records buffered for the next call to report.
        let _ = wrapper.out_buf.drain(&mut wrapper.transport);
    }
    Ok(Some(consumed))
}

/// Seals `bufs` with one `SSL_write` per record and writes them with as few transport writes as
/// possible.
///
/// Small adjacent slices share records as in a flattened buffer. Sealing stops once buffered
/// ciphertext reaches `OUT_BUF_CAPACITY`, except when at most `MAX_RECORD` plaintext bytes remain.
/// The last record goes out with the buffer when possible; backpressure can leave it buffered too.
/// The BIO accepts every record, so BoringSSL never holds a pending write that a retry with
/// less data would fail.
fn ssl_write_records<S>(
    s: &mut SslStreamCore<StreamWrapper<S>>,
    bufs: &[io::IoSlice<'_>],
    total: usize,
    blocked: bool,
) -> io::Result<usize>
where
    S: AsyncRead + AsyncWrite,
{
    s.get_mut().out_buf.reserve(total);

    let mut written = 0usize;
    let mut err = None;
    let mut packer = Packer::new(bufs);
    // A short seal means a smaller fragment size; batch the rest instead. A blocked transport
    // would refuse the last record too.
    let mut through = !blocked;
    while let Some(plaintext) = packer.next_record() {
        let len = plaintext.len();
        s.get_mut().write_through = through && written.saturating_add(len) >= total;
        let res = s.write(plaintext);
        s.get_mut().write_through = false;
        let n = match res {
            Ok(n) => n,
            Err(e) => {
                err = Some(e);
                break;
            }
        };
        through &= n == len;
        written += n;
        packer.advance(n);

        // Finish a tail of at most one default record, even if backpressure leaves it buffered.
        if s.get_ref().out_buf.is_full() && total.saturating_sub(written) > MAX_RECORD {
            break;
        }
    }

    let wrapper = s.get_mut();
    let drained = if blocked {
        Ok(())
    } else {
        wrapper.out_buf.drain(&mut wrapper.transport)
    };
    if written > 0 {
        // Sealed plaintext must be reported, or a retry would send it twice.
        return Ok(written);
    }
    match (err, drained) {
        (Some(e), _) => Err(e),
        (None, Err(e)) if e.kind() != io::ErrorKind::WouldBlock => Err(e),
        (None, _) => Ok(0),
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

// ===== impl SslStream =====

impl<S: AsyncRead + AsyncWrite> SslStream<S> {
    #[inline]
    /// Like [`SslStream::new`](ssl::SslStream::new).
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

    /// Runs `f` with `ctx` installed as the context of the transport I/O BoringSSL performs in it.
    fn with_context<F, R>(self: Pin<&mut Self>, ctx: &mut Context<'_>, f: F) -> R
    where
        F: FnOnce(&mut SslStreamCore<StreamWrapper<S>>) -> R,
    {
        // SAFETY: nothing is moved out of `this`; `Transport::parts` re-pins the stream in place.
        let this = unsafe { self.get_unchecked_mut() };
        this.0.get_mut().transport.context = ctx as *mut _ as usize;
        let r = f(&mut this.0);
        this.0.get_mut().transport.context = 0;
        r
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

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.with_context(ctx, |s| cvt(write_records(s, bufs)))
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
                    Err(ref e)
                        if e.code() == ErrorCode::WANT_READ
                            || e.code() == ErrorCode::WANT_WRITE =>
                    {
                        return Poll::Pending;
                    }
                    Err(e) => {
                        return Poll::Ready(Err(e
                            .into_io_error()
                            .unwrap_or_else(io::Error::other)));
                    }
                }

                // Calling `SSL_shutdown` again would wait for the peer's close_notify instead.
                s.get_mut().shutdown_sent = true;
                Poll::Ready(Ok(()))
            }))?;
        }

        // close_notify is buffered like any record.
        ready!(self.as_mut().poll_flush(ctx))?;
        self.get_pin_mut().poll_shutdown(ctx)
    }
}

// ===== impl StreamWrapper =====

impl<S> StreamWrapper<S> {
    fn new(stream: S) -> Self {
        StreamWrapper {
            transport: Transport { stream, context: 0 },
            read_buf: ReadBuffer::default(),
            out_buf: OutBuffer::default(),
            write_through: false,
            shutdown_sent: false,
        }
    }
}

impl<S> fmt::Debug for StreamWrapper<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.transport.stream, fmt)
    }
}

impl<S> Read for StreamWrapper<S>
where
    S: AsyncRead,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_buf.read(&mut self.transport, buf)
    }
}

impl<S> Write for StreamWrapper<S>
where
    S: AsyncWrite,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.write_through {
            self.out_buf.write_last(&mut self.transport, buf);
        } else {
            self.out_buf.push(buf);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out_buf.drain(&mut self.transport)?;
        let (stream, cx) = self.transport.parts();
        match stream.poll_flush(cx) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

// ===== impl Transport =====

impl<S> Transport<S> {
    /// Returns the pinned stream and the context of the poll in progress.
    ///
    /// Must only run inside `SslStream::with_context`, which installs `context`.
    #[inline]
    fn parts(&mut self) -> (Pin<&mut S>, &mut Context<'_>) {
        debug_assert_ne!(self.context, 0);
        // SAFETY: every caller runs inside the `f` of `SslStream::with_context`: the BIO
        // callbacks, `write_records`, and `SslStreamCore::flush` from `poll_flush`. That call
        // stores the address of its live `&mut Context` before `f` and keeps it borrowed
        // throughout, so the pointer is non-null and live; a value left stale by an unwinding `f`
        // is overwritten before the next call. It takes the `SslStream` pinned and never moves
        // the stream out, so the stream stays pinned. Unit tests install a live local `Context`
        // the same way, with `Unpin` streams.
        unsafe {
            (
                Pin::new_unchecked(&mut self.stream),
                &mut *(self.context as *mut Context<'_>),
            )
        }
    }
}

// ===== impl ReadBuffer =====

impl ReadBuffer {
    /// Copies buffered ciphertext into `buf`, first refilling an empty buffer from `transport`.
    #[inline]
    fn read<S>(&mut self, transport: &mut Transport<S>, buf: &mut [u8]) -> io::Result<usize>
    where
        S: AsyncRead,
    {
        if self.bytes.is_empty() {
            self.fill(transport)?;
        }

        let buffered = &self.bytes[self.pos..];
        let n = buffered.len().min(buf.len());
        buf[..n].copy_from_slice(&buffered[..n]);
        self.pos += n;

        // Release the buffer as soon as it is drained, so a connection that stops reading here,
        // such as one returned to a pool, does not keep it.
        if self.pos == self.bytes.len() {
            self.bytes = Vec::new();
            self.pos = 0;
        }
        Ok(n)
    }

    /// Fills the empty buffer with a single read of `transport`.
    ///
    /// Maps the stream's `Poll::Pending` to `WouldBlock`; the stream registers the waker.
    fn fill<S>(&mut self, transport: &mut Transport<S>) -> io::Result<()>
    where
        S: AsyncRead,
    {
        let mut bytes = mem::take(&mut self.bytes);
        bytes.reserve(READ_BUF_CAPACITY);
        self.pos = 0;

        let (stream, cx) = transport.parts();
        let mut buf = ReadBuf::uninit(bytes.spare_capacity_mut());
        match stream.poll_read(cx, &mut buf)? {
            Poll::Ready(()) => {
                let filled = buf.filled().len();
                // SAFETY: `ReadBuf` guarantees its first `filled` bytes are initialized.
                unsafe { bytes.set_len(filled) };
                self.bytes = bytes;
                Ok(())
            }
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

// ===== impl OutBuffer =====

impl OutBuffer {
    #[inline]
    fn push(&mut self, record: &[u8]) {
        self.bytes.extend_from_slice(record);
    }

    #[inline]
    fn len(&self) -> usize {
        self.bytes.len()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Moves the buffered records out, so records can be sealed after them while the `SslRef` is
    /// borrowed.
    #[inline]
    fn take(&mut self) -> Vec<u8> {
        mem::take(&mut self.bytes)
    }

    /// Puts back the records moved out by [`take`](Self::take).
    ///
    /// Sealing does no transport I/O, so nothing reached the BIO meanwhile; bytes that did stay
    /// buffered after the records.
    #[inline]
    fn restore(&mut self, bytes: Vec<u8>) {
        debug_assert!(self.bytes.is_empty(), "sealing wrote to the BIO");
        let stray = mem::replace(&mut self.bytes, bytes);
        self.bytes.extend_from_slice(&stray);
    }

    /// Whether buffered ciphertext has reached `OUT_BUF_CAPACITY`.
    #[inline]
    fn is_full(&self) -> bool {
        self.bytes.len() >= OUT_BUF_CAPACITY
    }

    /// Reserves room for the records sealed from `total` plaintext bytes, up to the cap, when
    /// they span more than one record.
    #[inline]
    fn reserve(&mut self, total: usize) {
        if total > MAX_RECORD {
            let sealed = total.min(OUT_BUF_CAPACITY);
            self.bytes
                .reserve(sealed + sealed.div_ceil(MAX_RECORD) * RECORD_OVERHEAD);
        }
    }

    /// Retries buffered records before a write accepts more plaintext.
    ///
    /// Fails on transport errors, and on backpressure once the buffer is full.
    #[inline]
    fn retry<S>(&mut self, transport: &mut Transport<S>) -> io::Result<()>
    where
        S: AsyncWrite,
    {
        if self.bytes.is_empty() {
            return Ok(());
        }
        match self.drain(transport) {
            Err(e) if e.kind() != io::ErrorKind::WouldBlock || self.is_full() => Err(e),
            _ => Ok(()),
        }
    }

    /// Writes buffered records to `transport`, keeping what it does not accept.
    fn drain<S>(&mut self, transport: &mut Transport<S>) -> io::Result<()>
    where
        S: AsyncWrite,
    {
        let mut pos = 0;
        let res = loop {
            if pos == self.bytes.len() {
                break Ok(());
            }
            let (stream, cx) = transport.parts();
            match stream.poll_write(cx, &self.bytes[pos..]) {
                Poll::Ready(Ok(0)) => break Err(io::ErrorKind::WriteZero.into()),
                Poll::Ready(Ok(n)) => pos += n,
                Poll::Ready(Err(e)) => break Err(e),
                Poll::Pending => break Err(io::Error::from(io::ErrorKind::WouldBlock)),
            }
        };
        if pos == self.bytes.len() {
            self.bytes = Vec::new();
        } else {
            self.bytes.drain(..pos);
        }
        res
    }

    /// Writes buffered records and `record` in one transport write and buffers the rest.
    ///
    /// Errors leave the unwritten bytes buffered for the next drain to retry.
    fn write_last<S>(&mut self, transport: &mut Transport<S>, record: &[u8])
    where
        S: AsyncWrite,
    {
        let (stream, cx) = transport.parts();
        let pending = self.bytes.len();
        let res = if pending == 0 {
            stream.poll_write(cx, record)
        } else if stream.is_write_vectored() {
            let bufs = [io::IoSlice::new(&self.bytes), io::IoSlice::new(record)];
            stream.poll_write_vectored(cx, &bufs)
        } else {
            // Let the next drain combine the buffer and record into one write.
            Poll::Ready(Ok(0))
        };
        let n = match res {
            Poll::Ready(Ok(n)) => n,
            Poll::Ready(Err(_)) | Poll::Pending => 0,
        };
        if n < pending {
            self.bytes.drain(..n);
            self.bytes.extend_from_slice(record);
        } else {
            self.bytes.clear();
            self.bytes.extend_from_slice(&record[n - pending..]);
        }
    }
}

// ===== impl Packer =====

impl<'a> Packer<'a> {
    #[inline]
    fn new(bufs: &'a [io::IoSlice<'a>]) -> Self {
        Packer {
            bufs,
            i: 0,
            off: 0,
            scratch: Vec::new(),
        }
    }

    /// Skips empty slices and returns the plaintext of the next record, or `None` once every
    /// slice is sealed.
    ///
    /// Always inlined: it is the body of the `write_records` loop.
    #[inline(always)]
    fn next_record(&mut self) -> Option<&[u8]> {
        let bufs = self.bufs;
        let head = loop {
            let head = &bufs.get(self.i)?[self.off..];
            if !head.is_empty() {
                break head;
            }
            self.i += 1;
            self.off = 0;
        };

        let head_len = head.len().min(MAX_RECORD);
        let (len, end, tail) = self.pack();
        if len == head_len {
            return Some(&head[..len]);
        }
        Some(self.gather(head, len, end, tail))
    }

    /// Copies `head`, the whole slices up to `end` and `tail` bytes of `bufs[end]` into `scratch`.
    ///
    /// Never inlined: in its own function the per-slice copy loop takes fewer instructions.
    #[inline(never)]
    fn gather(&mut self, head: &[u8], len: usize, end: usize, tail: usize) -> &[u8] {
        let bufs = self.bufs;
        self.scratch.clear();
        self.scratch.reserve(len);
        self.scratch.extend_from_slice(head);
        for buf in &bufs[self.i + 1..end] {
            self.scratch.extend_from_slice(buf);
        }
        if tail > 0 {
            self.scratch.extend_from_slice(&bufs[end][..tail]);
        }
        &self.scratch
    }

    /// Chooses a record length, the end of grouped slices, and a prefix of the next slice.
    #[inline]
    fn pack(&self) -> (usize, usize, usize) {
        let Packer { bufs, i, off, .. } = *self;
        let head_len = (bufs[i].len() - off).min(MAX_RECORD);
        let mut len = head_len;
        let (mut end, mut tail) = (i + 1, 0);
        while end < bufs.len() && len < MAX_RECORD {
            let next = bufs[end].len();
            if len + next <= MAX_RECORD {
                len += next;
                end += 1;
            } else {
                // Avoid copying a prefix from slices larger than half a record to fill it.
                // An isolated head and final slice already need two records; keep their boundary.
                if next <= MAX_RECORD / 2
                    && (len > head_len || bufs[end + 1..].iter().any(|buf| !buf.is_empty()))
                {
                    tail = MAX_RECORD - len;
                    len = MAX_RECORD;
                }
                break;
            }
        }
        (len, end, tail)
    }

    /// Moves past `n` sealed bytes.
    #[inline]
    fn advance(&mut self, mut n: usize) {
        while n > 0 {
            let left = self.bufs[self.i].len() - self.off;
            if n < left {
                self.off += n;
                break;
            }
            n -= left;
            self.i += 1;
            self.off = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use btls::ssl::{
        SslAcceptor, SslConnector, SslConnectorBuilder, SslFiletype, SslMethod,
        SslSessionCacheMode, SslVersion,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::*;

    #[test]
    fn packing_preserves_in_place_heads_and_fills_longer_inputs() {
        type PackingCase<'a> = (&'a [usize], usize, usize, (usize, usize, usize));
        let cases: &[PackingCase<'_>] = &[
            (&[10000, 7000], 0, 0, (10000, 1, 0)),
            (&[8193, 8192], 0, 0, (8193, 1, 0)),
            (&[16000, 500], 0, 0, (16000, 1, 0)),
            (&[10000, 0, 7000, 0], 0, 0, (10000, 2, 0)),
            (&[8193, 8192, 0], 0, 0, (8193, 1, 0)),
            (&[7000, 0, 0], 0, 0, (7000, 3, 0)),
            (&[0, 7000, 0], 1, 0, (7000, 3, 0)),
            (&[23000, 7000, 0], 0, 13000, (10000, 1, 0)),
            (&[10000, 7000, 10000], 0, 0, (MAX_RECORD, 1, 6384)),
            (&[10000, 7000, 0, 10000], 0, 0, (MAX_RECORD, 1, 6384)),
            (&[6000, 6000, 7000], 0, 0, (MAX_RECORD, 2, 4384)),
            (&[8191, 8192], 0, 0, (16383, 2, 0)),
            (&[8192, 8192], 0, 0, (MAX_RECORD, 2, 0)),
            (&[8192, 8193, 1], 0, 0, (8192, 1, 0)),
        ];
        for &(lengths, i, off, expected) in cases {
            let data: Vec<_> = lengths.iter().map(|&len| vec![0; len]).collect();
            let bufs: Vec<_> = data.iter().map(|buf| io::IoSlice::new(buf)).collect();
            assert_eq!(
                Packer {
                    bufs: &bufs,
                    i,
                    off,
                    scratch: Vec::new()
                }
                .pack(),
                expected,
                "{lengths:?}, {i}, {off}"
            );
        }
    }

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

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[io::IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            let mut written = 0;
            for buf in bufs {
                match self.as_mut().poll_write(cx, buf) {
                    Poll::Ready(Ok(n)) => written += n,
                    _ => break,
                }
            }
            if written == 0 {
                return Poll::Pending;
            }
            Poll::Ready(Ok(written))
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn write_buf_released_when_drained() {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut wrapper = StreamWrapper::new(Sink {
            budget: 0,
            data: Vec::new(),
        });
        wrapper.transport.context = &mut cx as *mut _ as usize;

        wrapper.write_all(&[1; 100]).unwrap();
        let err = wrapper.flush().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(wrapper.out_buf.bytes.len(), 100);

        wrapper.transport.stream.budget = usize::MAX;
        wrapper.flush().unwrap();
        assert_eq!(wrapper.transport.stream.data, [1; 100]);
        assert_eq!(wrapper.out_buf.bytes.capacity(), 0);
    }

    #[test]
    fn last_record_follows_buffered_records() {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut wrapper = StreamWrapper::new(Sink {
            budget: 0,
            data: Vec::new(),
        });
        wrapper.transport.context = &mut cx as *mut _ as usize;

        wrapper.write_all(b"0123456789").unwrap();
        wrapper.write_through = true;
        // The transport stops inside the buffered records.
        wrapper.transport.stream.budget = 4;
        wrapper.write_all(b"abcde").unwrap();
        assert_eq!(wrapper.transport.stream.data, b"0123");
        assert_eq!(wrapper.out_buf.bytes, b"456789abcde");

        // One vectored write takes the buffered records and the head of the last one.
        wrapper.transport.stream.budget = 15;
        wrapper.write_all(b"fghij").unwrap();
        assert_eq!(wrapper.transport.stream.data, b"0123456789abcdefghi");
        assert_eq!(wrapper.out_buf.bytes, b"j");

        // With nothing buffered, the record goes straight out.
        wrapper.transport.stream.budget = usize::MAX;
        wrapper.flush().unwrap();
        wrapper.write_all(b"klm").unwrap();
        assert_eq!(wrapper.transport.stream.data, b"0123456789abcdefghijklm");
        assert_eq!(wrapper.out_buf.bytes.capacity(), 0);
    }

    #[test]
    fn write_buf_bounded_under_partial_writes() {
        const CHUNK: usize = 16 * 1024;
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut wrapper = StreamWrapper::new(Sink {
            budget: 0,
            data: Vec::new(),
        });
        wrapper.transport.context = &mut cx as *mut _ as usize;

        wrapper.write_all(&[0; 3 * CHUNK]).unwrap();
        for _ in 0..64 {
            wrapper.write_all(&[1; CHUNK]).unwrap();
            // The transport takes one record's worth per drain and never catches up.
            wrapper.transport.stream.budget = CHUNK;
            let err = wrapper.out_buf.drain(&mut wrapper.transport).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        }
        assert_eq!(wrapper.out_buf.bytes.len(), 3 * CHUNK);
        assert!(wrapper.out_buf.bytes.capacity() <= 2 * OUT_BUF_CAPACITY);
    }

    /// Duplex transport whose writes can stall, fail once, or keep returning `BrokenPipe`.
    ///
    /// It counts write polls and copies the bytes it accepts into `tap`.
    struct Gate {
        io: DuplexStream,
        open: bool,
        budget: usize,
        interrupt: bool,
        interrupt_flush: bool,
        broken: bool,
        polls: usize,
        tap: Vec<u8>,
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
            self.polls += 1;
            if self.broken {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            if mem::take(&mut self.interrupt) {
                return Poll::Ready(Err(io::ErrorKind::Interrupted.into()));
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
        tls_pair_from(connector, version, max_fragment).await
    }

    /// Connects a client built from `connector` to a server; the client's transport counts and
    /// taps only what is written after the handshake.
    async fn tls_pair_from(
        mut connector: SslConnectorBuilder,
        version: SslVersion,
        max_fragment: Option<usize>,
    ) -> (SslStream<Gate>, SslStream<DuplexStream>) {
        // Keep the complete test payload in the transport while writes are polled manually.
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);

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
            interrupt: false,
            interrupt_flush: false,
            broken: false,
            polls: 0,
            tap: Vec::new(),
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
            let mut cx = Context::from_waker(std::task::Waker::noop());

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
    async fn last_tail_stays_bounded_under_backpressure() {
        for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
            let (mut client, mut server) = tls_pair_with(version, None).await;
            client.get_mut().open = false;
            let mut cx = Context::from_waker(std::task::Waker::noop());
            let data: Vec<_> = (0..5 * MAX_RECORD)
                .map(|offset| (offset ^ (offset >> 8)) as u8)
                .collect();
            let consumed = match Pin::new(&mut client).poll_write(&mut cx, &data) {
                Poll::Ready(Ok(n)) => n,
                result => panic!("initial buffering failed: {result:?}"),
            };
            let buffered = client.0.get_ref().out_buf.bytes.len();
            assert_eq!(consumed, data.len());
            assert!(buffered > OUT_BUF_CAPACITY);
            assert!(buffered <= data.len() + 5 * RECORD_OVERHEAD);
            for _ in 0..4 {
                assert!(Pin::new(&mut client)
                    .poll_write(&mut cx, b"extra")
                    .is_pending());
                assert_eq!(client.0.get_ref().out_buf.bytes.len(), buffered);
            }

            client.get_mut().open = true;
            client.shutdown().await.unwrap();
            let mut received = Vec::new();
            server.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, data);
        }
    }

    #[tokio::test]
    async fn buffer_cap_and_persistent_errors_preserve_consumed_prefix() {
        for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
            let (mut client, mut server) = tls_pair_with(version, None).await;
            let mut cx = Context::from_waker(std::task::Waker::noop());
            let mut expected: Vec<_> = (0..6 * MAX_RECORD)
                .map(|offset| (offset ^ (offset >> 8)) as u8)
                .collect();

            // The cap stops accepting plaintext while the transport is blocked.
            client.get_mut().open = false;
            let consumed = match Pin::new(&mut client).poll_write(&mut cx, &expected) {
                Poll::Ready(Ok(n)) => n,
                result => panic!("initial buffering failed: {result:?}"),
            };
            assert!(consumed > 0 && consumed < expected.len());
            let buffered = client.0.get_ref().out_buf.bytes.len();
            assert!(buffered >= OUT_BUF_CAPACITY);
            assert!(Pin::new(&mut client)
                .poll_write(&mut cx, &expected[consumed..])
                .is_pending());
            assert_eq!(client.0.get_ref().out_buf.bytes.len(), buffered);

            // A persistent error prevents every later write from accepting more input.
            client.get_mut().broken = true;
            for _ in 0..2 {
                match Pin::new(&mut client).poll_flush(&mut cx) {
                    Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::BrokenPipe),
                    result => panic!("expected persistent flush failure: {result:?}"),
                }
                match Pin::new(&mut client).poll_write(&mut cx, &expected[consumed..]) {
                    Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::BrokenPipe),
                    result => panic!("expected persistent write failure: {result:?}"),
                }
                assert_eq!(client.0.get_ref().out_buf.bytes.len(), buffered);
            }

            client.get_mut().broken = false;
            client.get_mut().open = true;
            client.write_all(&expected[consumed..]).await.unwrap();
            client.flush().await.unwrap();
            assert!(client.0.get_ref().out_buf.bytes.is_empty());

            // If the error first occurs after sealing, report the consumed plaintext once.
            let tail = b"tail-queued-before-reporting-error";
            client.get_mut().broken = true;
            assert!(matches!(
                Pin::new(&mut client).poll_write(&mut cx, tail),
                Poll::Ready(Ok(n)) if n == tail.len()
            ));
            let buffered = client.0.get_ref().out_buf.bytes.len();
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
                assert_eq!(client.0.get_ref().out_buf.bytes.len(), buffered);
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
            let mut cx = Context::from_waker(std::task::Waker::noop());
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
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let sealed = client.ssl().seal_app_data_limits().is_some();

        let res = Pin::new(&mut client).poll_write(&mut cx, &[1; 100]);
        assert!(matches!(res, Poll::Ready(Ok(100))));
        assert_eq!(client.get_ref().polls, 1);
        assert_eq!(client.0.get_ref().out_buf.bytes.capacity(), 0);

        // The record stays buffered while the transport takes nothing.
        client.get_mut().open = false;
        let res = Pin::new(&mut client).poll_write(&mut cx, &[2; 100]);
        assert!(matches!(res, Poll::Ready(Ok(100))));
        if sealed {
            assert_eq!(client.get_ref().polls, 2);
        }
        assert!(!client.0.get_ref().out_buf.bytes.is_empty());

        // Once the retry returns `Pending`, the transport is not polled again.
        let polls = client.get_ref().polls;
        let res = Pin::new(&mut client).poll_write(&mut cx, &[3; 100]);
        assert!(matches!(res, Poll::Ready(Ok(100))));
        assert_eq!(client.get_ref().polls, polls + 1);

        client.get_mut().open = true;
        client.shutdown().await.unwrap();
        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, [[1; 100], [2; 100], [3; 100]].concat());
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
        let (mut client, mut server) = tls_pair_from(connector, SslVersion::TLS1_3, None).await;

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
    async fn write_after_shutdown_fails() {
        let (mut client, mut server) = tls_pair().await;
        let mut cx = Context::from_waker(std::task::Waker::noop());

        // close_notify stays buffered while the transport takes nothing.
        client.get_mut().open = false;
        assert!(Pin::new(&mut client).poll_shutdown(&mut cx).is_pending());
        let buffered = client.0.get_ref().out_buf.bytes.clone();
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
        assert_eq!(client.0.get_ref().out_buf.bytes, buffered);

        client.get_mut().open = true;
        client.shutdown().await.unwrap();
        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        assert!(received.is_empty());
    }

    #[test]
    fn seal_budget_matches_legacy_rule() {
        /// Plaintext the `SSL_write` loop seals from one flat buffer.
        fn legacy(
            fragment: usize,
            overhead: usize,
            pending: usize,
            buffered: usize,
            total: usize,
        ) -> usize {
            let (mut out, mut written) = (buffered + pending, 0);
            while written < total {
                let len = fragment.min(total - written);
                out += len + overhead;
                written += len;
                if out >= OUT_BUF_CAPACITY && total - written > MAX_RECORD {
                    break;
                }
            }
            written
        }

        // (fragment, overhead, pending, buffered, total, budget)
        let examples = [
            (16384, 22, 0, 0, 100, 100),
            // HTTP/2 4x(9B+16KiB): one call, five records.
            (16384, 22, 0, 0, 65572, 65572),
            (16384, 22, 0, 0, 81920, 81920),
            (16384, 22, 0, 0, 98304, 65536),
            // A TLS 1.3 server's first write with its tickets.
            (16384, 22, 520, 0, 16384, 16384),
            (512, 22, 0, 0, 185124, 62976),
            (512, 29, 0, 0, 185124, 62464),
            (16384, 22, 16500, 0, 98304, 49152),
            (16384, 22, 0, 60000, 98304, 16384),
            (16384, 22, 6000, 60000, 98304, 16384),
        ];
        for (fragment, overhead, pending, buffered, total, budget) in examples {
            let args = (fragment, overhead, pending, buffered, total);
            assert_eq!(
                seal_budget(fragment, overhead, pending, buffered, total),
                budget,
                "{args:?}"
            );
        }

        for fragment in [512, 1000, 16384] {
            for overhead in [22, 29, 85] {
                for pending in [0, 520, 16500] {
                    for buffered in [0, 1, 30000, OUT_BUF_CAPACITY - 1] {
                        for total in [1, 100, 16384, 16385, 65572, 81920, 98304, 185124] {
                            let args = (fragment, overhead, pending, buffered, total);
                            assert_eq!(
                                seal_budget(fragment, overhead, pending, buffered, total),
                                legacy(fragment, overhead, pending, buffered, total),
                                "{args:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn read_buf_released_when_drained() {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut wrapper = StreamWrapper::new(Once(vec![1; 100]));
        wrapper.transport.context = &mut cx as *mut _ as usize;

        let mut buf = [0; 60];
        assert_eq!(wrapper.read(&mut buf).unwrap(), 60);
        assert_eq!(wrapper.read_buf.bytes.capacity(), READ_BUF_CAPACITY);

        assert_eq!(wrapper.read(&mut buf).unwrap(), 40);
        assert_eq!(wrapper.read_buf.bytes.capacity(), 0);

        let err = wrapper.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(wrapper.read_buf.bytes.capacity(), 0);
    }
}
