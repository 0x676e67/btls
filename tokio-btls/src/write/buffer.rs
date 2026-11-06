use std::{io, task::Poll};

use btls::ssl::{self, SealLimits, SslRef};
use tokio::io::AsyncWrite;

use super::{MAX_RECORD, RECORD_OVERHEAD, WRITE_BUF_CAPACITY};
use crate::transport::Transport;

/// Sealed records not yet written to the transport, in order.
///
/// Output of [`seal_app_data`](btls::ssl::SslRef::seal_app_data) must reach the peer before
/// anything written later, so buffered records are never dropped or overtaken. Partial writes
/// advance `pos` instead of shifting the rest; appends drop the written prefix through
/// [`make_room`](Self::make_room).
#[derive(Default)]
pub(crate) struct WriteBuffer {
    bytes: Vec<u8>,
    // `bytes[..pos]` is written. `pos < bytes.len()` unless both are 0.
    pos: usize,
    // Set when the transport refuses records in `retry` or `write_last`; while set, a write only
    // buffers its records. `retry` recomputes it as each write starts, so it is stale between
    // writes, and `StreamWrapper::flush` ignores it.
    pub(crate) blocked: bool,
}

impl WriteBuffer {
    #[inline]
    pub(crate) fn push(&mut self, record: &[u8]) {
        self.make_room(record.len());
        self.bytes.extend_from_slice(record);
    }

    /// The records still to write.
    #[inline]
    pub(crate) fn buffered(&self) -> &[u8] {
        &self.bytes[self.pos..]
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.bytes.len() - self.pos
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Capacity of the backing allocation.
    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.bytes.capacity()
    }

    /// Reserves room to append `extra` bytes, first dropping the written prefix once it is at
    /// least as long as the rest, or when the append would reallocate anyway.
    #[inline]
    fn make_room(&mut self, extra: usize) {
        if self.pos > 0
            && (self.pos >= self.len() || self.bytes.capacity() - self.bytes.len() < extra)
        {
            self.bytes.copy_within(self.pos.., 0);
            self.bytes.truncate(self.bytes.len() - self.pos);
            self.pos = 0;
        }
        self.bytes.reserve(extra);
    }

    /// Seals as much of `bufs` as [`seal_budget`] allows after the buffered records.
    ///
    /// Returns the plaintext sealed, or `Ok(None)` if BoringSSL declines.
    #[inline]
    pub(crate) fn seal(
        &mut self,
        ssl: &mut SslRef,
        limits: SealLimits,
        bufs: &[io::IoSlice<'_>],
        total: usize,
    ) -> io::Result<Option<usize>> {
        let budget = seal_budget(
            limits.max_fragment(),
            limits.record_overhead(),
            limits.pending_len(),
            self.len(),
            total,
        );
        let Some(max_out) = limits.sealed_len(budget) else {
            return Ok(None);
        };
        self.make_room(max_out);
        let out = &mut self.bytes.spare_capacity_mut()[..max_out];
        let sealed = match ssl.seal_app_data(bufs, budget, out) {
            Ok(Some(sealed)) => sealed,
            Ok(None) => return Ok(None),
            Err(e) => return Err(io::Error::other(ssl::Error::from(e))),
        };
        // SAFETY: `seal_app_data` initialized the first `written` bytes of the spare capacity,
        // and `written` is at most `max_out`, which `make_room` reserved.
        unsafe { self.bytes.set_len(self.bytes.len() + sealed.written) };
        Ok(Some(sealed.consumed))
    }

    /// Whether buffered ciphertext has reached `WRITE_BUF_CAPACITY`.
    #[inline]
    pub(crate) fn is_full(&self) -> bool {
        self.len() >= WRITE_BUF_CAPACITY
    }

    /// Reserves room for the records sealed from `total` plaintext bytes, up to the cap, when
    /// they span more than one record. Assumes full records up to the cap; smaller fragments or a
    /// tail past it grow the buffer.
    #[inline]
    pub(crate) fn reserve(&mut self, total: usize) {
        if total > MAX_RECORD {
            let sealed = total.min(WRITE_BUF_CAPACITY);
            self.make_room(sealed + sealed.div_ceil(MAX_RECORD) * RECORD_OVERHEAD);
        }
    }

    /// Retries buffered records as a write starts, setting `blocked` if the transport refuses them.
    ///
    /// Fails on transport errors, and on backpressure once the buffer is full.
    #[inline]
    pub(crate) fn retry<S>(&mut self, transport: &mut Transport<S>) -> io::Result<()>
    where
        S: AsyncWrite,
    {
        if !self.bytes.is_empty() {
            match self.drain(transport) {
                Err(e) if e.kind() != io::ErrorKind::WouldBlock || self.is_full() => return Err(e),
                _ => {}
            }
        }
        // Records stay buffered only if the transport returned `Pending`, which registered the
        // waker.
        self.blocked = !self.bytes.is_empty();
        Ok(())
    }

    /// Ends a write by draining the records unless `blocked`.
    ///
    /// An error is dropped and leaves them buffered; the next `retry` reports it only if it
    /// recurs.
    #[inline]
    pub(crate) fn drain_unless_blocked<S>(&mut self, transport: &mut Transport<S>)
    where
        S: AsyncWrite,
    {
        if !self.blocked {
            let _ = self.drain(transport);
        }
    }

    /// Writes buffered records to `transport`, keeping what it does not accept and freeing the
    /// allocation once empty. Fails with `InvalidData` on an overcounted write, keeping its bytes.
    pub(crate) fn drain<S>(&mut self, transport: &mut Transport<S>) -> io::Result<()>
    where
        S: AsyncWrite,
    {
        let res = loop {
            if self.pos == self.bytes.len() {
                break Ok(());
            }
            let (stream, cx) = match transport.parts() {
                Ok(parts) => parts,
                Err(e) => break Err(e),
            };
            match stream.poll_write(cx, self.buffered()) {
                Poll::Ready(Ok(0)) => break Err(io::ErrorKind::WriteZero.into()),
                Poll::Ready(Ok(n)) if n <= self.len() => self.pos += n,
                Poll::Ready(Ok(_)) => {
                    break Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "transport wrote more bytes than it was given",
                    ))
                }
                Poll::Ready(Err(e)) => break Err(e),
                Poll::Pending => break Err(io::Error::from(io::ErrorKind::WouldBlock)),
            }
        };
        if self.pos == self.bytes.len() {
            self.bytes = Vec::new();
            self.pos = 0;
        }
        res
    }

    /// Writes buffered records and `record` in one transport write and buffers the rest; without
    /// vectored writes, `record` instead waits behind buffered records for the next drain.
    ///
    /// Sets `blocked` on `Pending`, an error or an overcount, keeping the unwritten bytes (all of
    /// them on an overcount) buffered; the next drain reports the error if it recurs.
    pub(crate) fn write_last<S>(&mut self, transport: &mut Transport<S>, record: &[u8])
    where
        S: AsyncWrite,
    {
        let pending = self.len();
        let res = match transport.parts() {
            Ok((stream, cx)) if pending == 0 => stream.poll_write(cx, record),
            Ok((stream, cx)) if stream.is_write_vectored() => {
                let bufs = [io::IoSlice::new(self.buffered()), io::IoSlice::new(record)];
                stream.poll_write_vectored(cx, &bufs)
            }
            // Let the next drain combine the buffer and record into one write.
            Ok(_) => Poll::Ready(Ok(0)),
            Err(e) => Poll::Ready(Err(e)),
        };
        let n = match res {
            Poll::Ready(Ok(n)) if n <= pending.saturating_add(record.len()) => n,
            Poll::Ready(_) | Poll::Pending => {
                self.blocked = true;
                0
            }
        };
        if n < pending {
            self.pos += n;
            self.push(record);
        } else {
            self.bytes.clear();
            self.pos = 0;
            self.bytes.extend_from_slice(&record[n - pending..]);
        }
    }
}

/// Plaintext to seal in one call: stop once about `WRITE_BUF_CAPACITY` of ciphertext is buffered,
/// but take a final tail of at most `MAX_RECORD` bytes too, like
/// [`ssl_write_records`](super::ssl_write_records).
///
/// `pending` handshake bytes go out ahead of the records, after the `buffered` ones.
fn seal_budget(
    fragment: usize,
    overhead: usize,
    pending: usize,
    buffered: usize,
    total: usize,
) -> usize {
    let room = WRITE_BUF_CAPACITY
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

#[cfg(test)]
mod tests {
    use std::{io::Write, pin::Pin, task::Context};

    use super::*;
    use crate::bio::StreamWrapper;

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
    fn last_record_follows_buffered_records() {
        let mut wrapper = StreamWrapper::new(Sink {
            budget: 0,
            data: Vec::new(),
        });
        wrapper.transport.set_noop_context();

        wrapper.write_all(b"0123456789").unwrap();
        let err = wrapper.flush().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        wrapper.write_through = true;
        // The transport stops inside the buffered records.
        wrapper.transport.stream.budget = 4;
        wrapper.write_all(b"abcde").unwrap();
        assert_eq!(wrapper.transport.stream.data, b"0123");
        assert_eq!(wrapper.write_buf.buffered(), b"456789abcde");

        // One vectored write takes the buffered records and the head of the last one.
        wrapper.transport.stream.budget = 15;
        wrapper.write_all(b"fghij").unwrap();
        assert_eq!(wrapper.transport.stream.data, b"0123456789abcdefghi");
        assert_eq!(wrapper.write_buf.buffered(), b"j");

        // With nothing buffered, the record goes straight out.
        wrapper.transport.stream.budget = usize::MAX;
        wrapper.flush().unwrap();
        wrapper.write_all(b"klm").unwrap();
        assert_eq!(wrapper.transport.stream.data, b"0123456789abcdefghijklm");
        assert_eq!(wrapper.write_buf.bytes.capacity(), 0);
    }

    #[test]
    fn write_buf_bounded_under_partial_writes() {
        const CHUNK: usize = 16 * 1024;
        let mut wrapper = StreamWrapper::new(Sink {
            budget: 0,
            data: Vec::new(),
        });
        wrapper.transport.set_noop_context();

        wrapper.write_all(&[0; 3 * CHUNK]).unwrap();
        for _ in 0..64 {
            wrapper.write_all(&[1; CHUNK]).unwrap();
            // The transport takes one record's worth per drain and never catches up.
            wrapper.transport.stream.budget = CHUNK;
            let err = wrapper.write_buf.drain(&mut wrapper.transport).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        }
        assert_eq!(wrapper.write_buf.len(), 3 * CHUNK);
        assert!(wrapper.write_buf.bytes.capacity() <= 2 * WRITE_BUF_CAPACITY);
    }

    #[test]
    fn write_buf_keeps_order_under_short_writes() {
        let mut wrapper = StreamWrapper::new(Sink {
            budget: 0,
            data: Vec::new(),
        });
        wrapper.transport.set_noop_context();

        // A backlog that never empties, so the written prefix is only ever dropped by compaction.
        let mut expected = vec![0xff; 1024];
        wrapper.write_buf.push(&expected);
        let mut capacity = 0;
        for i in 0..1000usize {
            // Records average slightly more than the 37 bytes the transport takes per round.
            let record: Vec<u8> = (0..1 + i % 74).map(|j| (i ^ j) as u8).collect();
            expected.extend_from_slice(&record);
            wrapper.transport.stream.budget = 37;
            if i % 3 == 1 {
                wrapper
                    .write_buf
                    .write_last(&mut wrapper.transport, &record);
            } else {
                wrapper.write_buf.push(&record);
            }
            let _ = wrapper.write_buf.drain(&mut wrapper.transport);
            assert!(!wrapper.write_buf.is_empty());
            capacity = capacity.max(wrapper.write_buf.bytes.capacity());
        }
        assert!(capacity <= 4096, "{capacity}");

        wrapper.transport.stream.budget = usize::MAX;
        wrapper.flush().unwrap();
        assert_eq!(wrapper.transport.stream.data, expected);
        assert_eq!(wrapper.write_buf.bytes.capacity(), 0);
    }

    /// Claims one byte more than each write was given.
    struct Overreport;

    impl AsyncWrite for Overreport {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len() + 1))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn misused_transport_fails_without_panicking() {
        let mut transport = Transport::new(Overreport);
        let mut write_buf = WriteBuffer::default();
        write_buf.push(b"record");

        // Outside a poll there is no context to hand the transport.
        let err = write_buf.drain(&mut transport).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        write_buf.write_last(&mut transport, b"last");
        assert!(write_buf.blocked);
        assert_eq!(write_buf.buffered(), b"recordlast");

        // An overcount keeps the records, as an error would.
        transport.set_noop_context();
        let err = write_buf.drain(&mut transport).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(write_buf.buffered(), b"recordlast");
        let mut write_buf = WriteBuffer::default();
        write_buf.write_last(&mut transport, b"last");
        assert!(write_buf.blocked);
        assert_eq!(write_buf.buffered(), b"last");
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
                if out >= WRITE_BUF_CAPACITY && total - written > MAX_RECORD {
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
                    for buffered in [0, 1, 30000, WRITE_BUF_CAPACITY - 1] {
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
}
