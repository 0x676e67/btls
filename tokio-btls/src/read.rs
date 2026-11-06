use std::{io, mem, task::Poll};

use tokio::io::{AsyncRead, ReadBuf};

use crate::transport::Transport;

/// Capacity of the ciphertext read buffer, large enough for one TLS record
/// supported by BoringSSL.
///
/// BoringSSL may request record headers and bodies in separate BIO reads.
/// Buffering lets these reads share data from one underlying read.
/// Larger bursts may require multiple refills.
const READ_BUF_CAPACITY: usize = 17 * 1024;

/// Ciphertext read from the transport but not yet taken by BoringSSL.
#[derive(Default)]
pub(crate) struct ReadBuffer {
    bytes: Vec<u8>,
    // The next byte to hand out is `bytes[pos]`.
    pos: usize,
}

impl ReadBuffer {
    /// Whether no ciphertext is waiting; a drained buffer is released at once.
    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.bytes.is_empty()
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

#[cfg(test)]
mod tests {
    use std::{
        io::Read,
        pin::Pin,
        task::{Context, Waker},
    };

    use super::*;
    use crate::bio::StreamWrapper;

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
        let mut cx = Context::from_waker(Waker::noop());
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
