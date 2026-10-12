//! In-memory transport and the tokio-btls server driven over it between timed batches.

use std::{
    cell::RefCell,
    io::{self, IoSlice},
    pin::Pin,
    rc::Rc,
    task::{Context, Poll, Waker},
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_btls::SslStream;

use super::{case::Tls, BoxError, Direction};

/// Bytes written to one direction of the transport and not yet read.
#[derive(Default)]
struct Pipe {
    bytes: Vec<u8>,
    // The next byte to read is `bytes[pos]`.
    pos: usize,
    // Woken by the next write while a handshake read waits on this pipe.
    reader: Option<Waker>,
}

/// State both ends of one transport share.
struct Shared {
    pipes: [Pipe; 2],
    // Cleared once both handshakes are done: an empty read then fails instead of waiting.
    handshake: bool,
}

/// One end of an in-memory duplex transport for a single-thread runtime.
///
/// Writes never block and are kept until read. During the handshake a read of an empty pipe
/// waits for the other end; afterwards it fails with `UnexpectedEof`, so a stray poll fails at
/// once instead of hanging the only task.
pub(super) struct MemoryStream {
    shared: Rc<RefCell<Shared>>,
    // This end reads `pipes[rx]` and writes the other pipe.
    rx: usize,
}

/// The tokio-btls server end of a memory transport, which seals or opens bodies between timed
/// batches.
pub(super) struct MemoryPeer {
    stream: SslStream<MemoryStream>,
    // One received body; empty when the peer only sends.
    buf: Vec<u8>,
}

/// Creates the two connected ends of a transport in its handshake phase.
pub(super) fn pair() -> (MemoryStream, MemoryStream) {
    let shared = Rc::new(RefCell::new(Shared {
        pipes: Default::default(),
        handshake: true,
    }));
    let client = MemoryStream {
        shared: shared.clone(),
        rx: 0,
    };
    (client, MemoryStream { shared, rx: 1 })
}

// ===== impl MemoryStream =====

impl MemoryStream {
    /// Bytes waiting for this end to read.
    fn unread(&self) -> usize {
        let shared = self.shared.borrow();
        let pipe = &shared.pipes[self.rx];
        pipe.bytes.len() - pipe.pos
    }

    /// Bytes this end wrote that the other end has not read.
    fn in_flight(&self) -> usize {
        let shared = self.shared.borrow();
        let pipe = &shared.pipes[1 - self.rx];
        pipe.bytes.len() - pipe.pos
    }

    /// Appends `bufs` to the pipe the other end reads.
    fn append(&self, bufs: &[IoSlice<'_>]) -> usize {
        let (written, reader) = {
            let mut shared = self.shared.borrow_mut();
            let pipe = &mut shared.pipes[1 - self.rx];
            let start = pipe.bytes.len();
            for buf in bufs {
                pipe.bytes.extend_from_slice(buf);
            }
            (pipe.bytes.len() - start, pipe.reader.take())
        };
        if let Some(reader) = reader {
            reader.wake();
        }
        written
    }
}

impl AsyncRead for MemoryStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut shared = self.shared.borrow_mut();
        let handshake = shared.handshake;
        let pipe = &mut shared.pipes[self.rx];
        let available = &pipe.bytes[pipe.pos..];
        if available.is_empty() {
            if handshake {
                pipe.reader = Some(cx.waker().clone());
                return Poll::Pending;
            }
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read past the ciphertext of the current batch",
            )));
        }

        let n = available.len().min(buf.remaining());
        buf.put_slice(&available[..n]);
        pipe.pos += n;
        if pipe.pos == pipe.bytes.len() {
            // Keep the capacity: the next batch refills the same buffer.
            pipe.bytes.clear();
            pipe.pos = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MemoryStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(self.append(&[IoSlice::new(buf)])))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(self.append(bufs)))
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

// ===== impl MemoryPeer =====

impl MemoryPeer {
    /// Takes a server stream whose handshake has completed and ends the transport's handshake
    /// phase.
    ///
    /// Returns an error if the server already sent data the client never asked for.
    pub(super) fn new(
        stream: SslStream<MemoryStream>,
        direction: Direction,
        len: usize,
    ) -> Result<Self, BoxError> {
        let transport = stream.get_ref();
        transport.shared.borrow_mut().handshake = false;
        if transport.in_flight() != 0 || transport.unread() != 0 {
            return Err("memory transport holds data after the handshake".into());
        }
        let buf = match direction {
            Direction::Read => Vec::new(),
            Direction::Write => vec![0; len],
        };
        Ok(Self { stream, buf })
    }

    /// Ciphertext the client wrote that the peer has not read.
    pub(super) fn unread(&self) -> usize {
        self.stream.get_ref().unread()
    }

    /// Ciphertext the peer wrote that the client has not read.
    pub(super) fn in_flight(&self) -> usize {
        self.stream.get_ref().in_flight()
    }

    /// Seals `copies` of `part` into the transport.
    pub(super) async fn send(&mut self, part: &[u8], copies: usize) -> io::Result<()> {
        for _ in 0..copies {
            self.stream.write_all(part).await?;
        }
        self.stream.flush().await
    }

    /// Opens `copies` of `part` and compares each with it.
    ///
    /// The client's ciphertext must cover them, and nothing may follow. Only a lower bound holds
    /// for its length, since rustls adds a KeyUpdate record every 2^24 records.
    pub(super) async fn receive(&mut self, part: &[u8], copies: usize) -> Result<(), BoxError> {
        let sealed = Tls::Enabled.wire_len(part.len()) * copies;
        if self.unread() < sealed {
            return Err(format!("client wrote {} bytes, expected {sealed}", self.unread()).into());
        }
        let buf = &mut self.buf[..part.len()];
        for _ in 0..copies {
            self.stream.read_exact(buf).await?;
            if *buf != *part {
                return Err("server received a different body".into());
            }
        }
        match self.unread() {
            0 => Ok(()),
            left => Err(format!("client wrote {left} bytes beyond its bodies").into()),
        }
    }
}
