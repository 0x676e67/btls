use std::{
    fmt,
    io::{self, Read, Write},
    task::Poll,
};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::{read::ReadBuffer, transport::Transport, write::WriteBuffer};

/// The BIO stream handed to BoringSSL, buffering ciphertext in both directions.
///
/// Owned by the BIO for the life of the stream and reached through `SslStreamCore::get_mut`.
pub(crate) struct StreamWrapper<S> {
    pub(crate) transport: Transport<S>,
    pub(crate) read_buf: ReadBuffer,
    pub(crate) write_buf: WriteBuffer,
    // Set while sealing the record packed last in a write, which `write_last` sends with the
    // buffered records unless `write_buf` is blocked.
    pub(crate) write_through: bool,
    // Set once `SSL_shutdown` has nothing left to send; later polls only flush.
    pub(crate) shutdown_sent: bool,
    // The end or error a read met after taking plaintext, reported by the next read.
    pub(crate) read_end: Option<io::Result<()>>,
}

impl<S> StreamWrapper<S> {
    pub(crate) fn new(stream: S) -> Self {
        StreamWrapper {
            transport: Transport::new(stream),
            read_buf: ReadBuffer::default(),
            write_buf: WriteBuffer::default(),
            write_through: false,
            shutdown_sent: false,
            read_end: None,
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
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_buf.read(&mut self.transport, buf)
    }
}

impl<S> Write for StreamWrapper<S>
where
    S: AsyncWrite,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Once `write_buf` is blocked, no record goes straight to the transport.
        if self.write_through && !self.write_buf.blocked {
            self.write_buf.write_last(&mut self.transport, buf);
        } else {
            self.write_buf.push(buf);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.write_buf.drain(&mut self.transport)?;
        let (stream, cx) = self.transport.parts()?;
        match stream.poll_flush(cx) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}
