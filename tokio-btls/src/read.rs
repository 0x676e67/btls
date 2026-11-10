use std::{cell::Cell, io, mem, ops::Range, task::Poll};

use btls::{
    error::ErrorStack,
    ssl::{Opened, SslRef, SslStream as SslStreamCore},
};
use tokio::io::{AsyncRead, ReadBuf};

use crate::{bio::StreamWrapper, transport::Transport};

/// Capacity of the ciphertext read buffer, enough for a record header plus the largest
/// ciphertext BoringSSL accepts (`SSL3_RT_MAX_ENCRYPTED_LENGTH`).
///
/// BoringSSL may request record headers and bodies in separate BIO reads. Buffering lets these
/// reads share data from one underlying read. Larger bursts may require multiple refills.
const READ_BUF_CAPACITY: usize = 17 * 1024;

thread_local! {
    /// The last read buffer released on this thread, taken by the next refill.
    ///
    /// Connections hold a buffer only while it holds data, so most refills would allocate one
    /// and most reads free it again; passing one along costs each thread a single buffer.
    static SPARE: Cell<Vec<u8>> = const { Cell::new(Vec::new()) };
}

/// Ciphertext read from the transport, and plaintext opened in place but not yet delivered.
///
/// The allocation is held only while it holds either: a read that leaves a partial record
/// refills it in place, and one that drains it hands it to [`SPARE`], so a connection that stops
/// reading there, such as one returned to a pool, keeps none.
#[derive(Default)]
pub(crate) struct ReadBuffer {
    bytes: Vec<u8>,
    // The next ciphertext byte is `bytes[pos]`.
    pos: usize,
    plain: Range<usize>,
    // The transport ended in `fill_partial`; the next BIO read reports the end to BoringSSL.
    eof: bool,
    // BoringSSL holds no input of its own, so an empty buffer needs no call into it. Only BIO
    // reads give it input, and post-handshake messages or a decline may leave it work.
    ssl_idle: bool,
}

/// Outcome of opening the next buffered record in place.
pub(crate) enum Open {
    /// A record was opened; its plaintext, if any, waits in the buffer.
    Record,
    /// No complete record is buffered; the next one needs this many bytes.
    Partial(usize),
    /// BoringSSL declined; read through `SSL_read`.
    Declined,
}

impl ReadBuffer {
    /// Whether no ciphertext is waiting.
    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.pos == self.bytes.len()
    }

    /// Copies buffered ciphertext into `buf`, first refilling an empty buffer from `transport`.
    #[inline]
    pub(crate) fn read<S>(
        &mut self,
        transport: &mut Transport<S>,
        buf: &mut [u8],
    ) -> io::Result<usize>
    where
        S: AsyncRead,
    {
        self.ssl_idle = false;
        if self.is_empty() {
            self.fill(transport)?;
        }

        let buffered = &self.bytes[self.pos..];
        let n = buffered.len().min(buf.len());
        buf[..n].copy_from_slice(&buffered[..n]);
        self.pos += n;
        self.release_drained();
        Ok(n)
    }

    /// Releases the allocation once it holds neither ciphertext nor undelivered plaintext.
    #[inline]
    pub(crate) fn release_drained(&mut self) {
        if self.is_empty() && !self.has_plain() {
            self.release();
        }
    }

    /// Hands the allocation to [`SPARE`], dropping what it holds.
    fn release(&mut self) {
        self.pos = 0;
        self.plain = 0..0;
        let mut bytes = mem::take(&mut self.bytes);
        if bytes.capacity() != 0 {
            bytes.clear();
            // Unavailable while the thread shuts down; the buffer is freed then.
            let _ = SPARE.try_with(|spare| spare.set(bytes));
        }
    }

    /// Refills the empty buffer with a single read of `transport`, or reports the end
    /// `fill_partial` met.
    ///
    /// Maps the stream's `Poll::Pending` to `WouldBlock`; the stream registers the waker. Every
    /// read delivers opened plaintext before BoringSSL reads again, so none is waiting here.
    fn fill<S>(&mut self, transport: &mut Transport<S>) -> io::Result<()>
    where
        S: AsyncRead,
    {
        debug_assert!(!self.has_plain(), "refilling over undelivered plaintext");
        self.pos = 0;
        self.plain = 0..0;
        if mem::take(&mut self.eof) {
            self.release();
            return Ok(());
        }
        self.bytes.clear();
        self.read_transport(transport, READ_BUF_CAPACITY)?;
        Ok(())
    }

    /// Makes the next `open` ask BoringSSL even with an empty buffer, after a call that may have
    /// changed what its read side reports.
    #[inline]
    pub(crate) fn ask_ssl(&mut self) {
        self.ssl_idle = false;
    }

    /// Whether opened plaintext waits for delivery.
    #[inline]
    pub(crate) fn has_plain(&self) -> bool {
        !self.plain.is_empty()
    }

    /// Copies opened plaintext into `buf`; returns whether some is left.
    #[inline]
    pub(crate) fn take_plain(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        let n = self.plain.len().min(buf.remaining());
        buf.put_slice(&self.bytes[self.plain.start..self.plain.start + n]);
        self.plain.start += n;
        self.has_plain()
    }

    /// Opens the next buffered record in place once its plaintext is delivered.
    ///
    /// Without buffered ciphertext, BoringSSL is only asked while it may hold input of its own.
    #[inline]
    pub(crate) fn open(&mut self, ssl: &mut SslRef) -> Result<Open, ErrorStack> {
        debug_assert!(!self.has_plain(), "opening over undelivered plaintext");
        if self.ssl_idle && self.is_empty() {
            return Ok(Open::Partial(0));
        }
        let opened = ssl.open_app_data(&mut self.bytes[self.pos..]);
        // Application data, or a partial record, passed the checks for pending work; an empty
        // record may have carried a post-handshake message that left some.
        self.ssl_idle = match &opened {
            Ok(Opened::Partial { .. }) => true,
            Ok(Opened::Record { plaintext, .. }) => !plaintext.is_empty(),
            _ => false,
        };
        Ok(match opened? {
            Opened::Record {
                consumed,
                plaintext,
            } => {
                self.plain = self.pos + plaintext.start..self.pos + plaintext.end;
                self.pos += consumed;
                Open::Record
            }
            Opened::Partial { needed } => Open::Partial(needed),
            Opened::Declined { consumed } => {
                self.pos += consumed;
                Open::Declined
            }
            _ => Open::Declined,
        })
    }

    /// Moves a partial record to the front and appends one read of `transport`, with room for at
    /// least `needed` bytes. Returns the bytes read, 0 at the end, which the next BIO read reports.
    pub(crate) fn fill_partial<S>(
        &mut self,
        transport: &mut Transport<S>,
        needed: usize,
    ) -> io::Result<usize>
    where
        S: AsyncRead,
    {
        debug_assert!(!self.has_plain(), "refilling over undelivered plaintext");
        if self.eof {
            return Ok(0);
        }
        self.bytes.drain(..self.pos);
        self.pos = 0;
        let filled = self.read_transport(transport, needed.max(READ_BUF_CAPACITY))?;
        self.eof = filled == 0;
        Ok(filled)
    }

    /// Appends one read of `transport` after growing the buffer to `capacity` bytes, and
    /// releases a buffer the read leaves empty, as an idle poll does.
    fn read_transport<S>(
        &mut self,
        transport: &mut Transport<S>,
        capacity: usize,
    ) -> io::Result<usize>
    where
        S: AsyncRead,
    {
        let (stream, cx) = transport.parts()?;
        if self.bytes.capacity() == 0 {
            self.bytes = SPARE.try_with(Cell::take).unwrap_or_default();
        }
        let len = self.bytes.len();
        self.bytes.reserve_exact(capacity.saturating_sub(len));

        let mut buf = ReadBuf::uninit(self.bytes.spare_capacity_mut());
        let read = match stream.poll_read(cx, &mut buf) {
            Poll::Ready(Ok(())) => Ok(buf.filled().len()),
            Poll::Ready(Err(err)) => Err(err),
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        };
        if let Ok(filled) = read {
            // SAFETY: `ReadBuf` guarantees its first `filled` bytes are initialized.
            unsafe { self.bytes.set_len(len + filled) };
        }
        if self.bytes.is_empty() {
            self.release();
        }
        read
    }
}

/// Delivers application data opened in place in the read buffer, or returns `None`, having
/// delivered nothing, when the read must go through `SSL_read`.
///
/// Like the `SSL_read` path, it keeps taking the records the transport has ready, and leaves an
/// end or error met after taking plaintext for the next read.
pub(crate) fn read_in_place<S>(
    s: &mut SslStreamCore<StreamWrapper<S>>,
    buf: &mut ReadBuf<'_>,
) -> Option<Poll<io::Result<()>>>
where
    S: AsyncRead,
{
    let start = buf.filled().len();
    // The buffer lives behind the BIO; move it out while the `SslRef` is borrowed mutably.
    let mut read_buf = mem::take(&mut s.get_mut().read_buf);
    let (mut declined, mut pending, mut end) = (false, false, None);
    loop {
        if (read_buf.has_plain() && read_buf.take_plain(buf)) || buf.remaining() == 0 {
            break;
        }
        // Without buffered ciphertext, another record needs a transport poll.
        if buf.filled().len() > start && read_buf.is_empty() {
            break;
        }
        let needed = match read_buf.open(s.ssl_mut()) {
            Ok(Open::Record) => continue,
            Ok(Open::Partial(needed)) => needed,
            Ok(Open::Declined) => {
                declined = true;
                break;
            }
            Err(err) => {
                end = Some(Err(io::Error::other(err)));
                break;
            }
        };
        match read_buf.fill_partial(&mut s.get_mut().transport, needed) {
            Ok(0) => {
                // `SSL_read` reports the end, or the truncated record before it.
                declined = true;
                break;
            }
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                pending = true;
                break;
            }
            Err(err) => {
                end = Some(Err(err));
                break;
            }
        }
    }
    read_buf.release_drained();
    let wrapper = s.get_mut();
    wrapper.read_buf = read_buf;
    if buf.filled().len() > start {
        wrapper.read_end = end;
        return Some(Poll::Ready(Ok(())));
    }
    if declined {
        return None;
    }
    debug_assert!(pending || end.is_some(), "an empty read must wait or end");
    Some(end.map_or(Poll::Pending, Poll::Ready))
}

#[cfg(test)]
mod tests {
    use std::{io::Read, pin::Pin, task::Context};

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
        let mut wrapper = StreamWrapper::new(Once(vec![1; 100]));
        wrapper.transport.set_noop_context();

        let mut buf = [0; 60];
        assert_eq!(wrapper.read(&mut buf).unwrap(), 60);
        // The buffer is held while ciphertext waits in it, and released once drained or idle.
        assert_eq!(wrapper.read_buf.bytes.capacity(), READ_BUF_CAPACITY);
        let allocation = wrapper.read_buf.bytes.as_ptr();
        assert_eq!(wrapper.read(&mut buf).unwrap(), 40);
        assert_eq!(wrapper.read_buf.bytes.capacity(), 0);
        let err = wrapper.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(wrapper.read_buf.bytes.capacity(), 0);

        // The next refill on this thread, by any connection, takes the released allocation.
        let mut other = StreamWrapper::new(Once(vec![2; 100]));
        other.transport.set_noop_context();
        assert_eq!(other.read(&mut buf).unwrap(), 60);
        assert_eq!(other.read_buf.bytes.as_ptr(), allocation);
    }
}
