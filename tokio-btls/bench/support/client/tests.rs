use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::io::{duplex, AsyncReadExt, AsyncWrite};

use super::{write_batch, write_part, Batches, BodyCase, BodyKind, ClientCase};
use crate::support::{case::BODY_CASES, BenchTarget, BoxError, Clock, Direction, Transport};

const PATIENCE: Duration = Duration::from_millis(10);
const BODY: [u8; 1024] = [7; 1024];

fn case(body_kind: BodyKind) -> ClientCase {
    ClientCase {
        target: BenchTarget {
            direction: Direction::Write,
            transport: Transport::Tcp,
            // These tests check I/O completion, independent of the platform's CPU clock.
            clock: Clock::Wall,
        },
        body: BodyCase {
            len: BODY.len(),
            chunk_size: BODY.len() / 16,
        },
        exact_framing: true,
        body_kind,
    }
}

fn assert_error_kind(error: BoxError, expected: io::ErrorKind) {
    assert_eq!(
        error
            .downcast_ref::<io::Error>()
            .expect("the batch retains the I/O error")
            .kind(),
        expected,
    );
}

#[tokio::test(flavor = "current_thread")]
async fn write_batch_times_out_when_receiver_does_not_read() {
    for body_kind in BodyKind::ALL {
        let (mut stream, _peer) = duplex(16);
        let error = write_batch(&mut stream, &BODY, case(body_kind), 1, PATIENCE)
            .await
            .expect_err("a blocked write must time out");
        assert_error_kind(error, io::ErrorKind::TimedOut);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn write_batch_completes_when_receiver_drains() {
    for body_kind in BodyKind::ALL {
        let (mut stream, mut peer) = duplex(16);
        let mut received = [0; BODY.len() * 2];
        tokio::try_join!(
            write_batch(
                &mut stream,
                &BODY,
                case(body_kind),
                2,
                Duration::from_secs(1)
            ),
            async {
                peer.read_exact(&mut received).await?;
                Ok::<_, BoxError>(())
            },
        )
        .expect("a draining receiver lets the batch finish");
        assert_eq!(&received[..BODY.len()], &BODY);
        assert_eq!(&received[BODY.len()..], &BODY);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn write_batch_preserves_write_errors() {
    for body_kind in BodyKind::ALL {
        let (mut stream, peer) = duplex(16);
        drop(peer);
        let error = write_batch(&mut stream, &BODY, case(body_kind), 1, PATIENCE)
            .await
            .expect_err("writing to a closed peer fails");
        assert_error_kind(error, io::ErrorKind::BrokenPipe);
    }
}

#[derive(Default)]
struct PendingFlush {
    written: usize,
    flush_polls: usize,
}

impl AsyncWrite for PendingFlush {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.written += buf.len();
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flush_polls += 1;
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn write_batch_times_out_while_flushing() {
    for body_kind in BodyKind::ALL {
        let mut stream = PendingFlush::default();
        let error = write_batch(&mut stream, &BODY, case(body_kind), 1, PATIENCE)
            .await
            .expect_err("the timeout also covers flushing buffered ciphertext");
        assert_error_kind(error, io::ErrorKind::TimedOut);
        assert_eq!(stream.written, BODY.len());
        assert!(stream.flush_polls > 0);
    }
}

#[derive(Default)]
struct RecordingWriter {
    bytes: Vec<u8>,
    vectored_widths: Vec<usize>,
    flushes: usize,
}

impl AsyncWrite for RecordingWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.bytes.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let before = self.bytes.len();
        self.vectored_widths
            .push(bufs.iter().filter(|buf| !buf.is_empty()).count());
        for buf in bufs {
            self.bytes.extend_from_slice(buf);
        }
        Poll::Ready(Ok(self.bytes.len() - before))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flushes += 1;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn large_cpu_bodies_write_the_documented_batches() {
    for (len, width, flushes) in [
        (256 * 1024, 8, 2),
        (1024 * 1024, 2, 8),
        (4096 * 1024, 1, 32),
    ] {
        let mut case = case(BodyKind::Chunked);
        case.target.clock = Clock::Cpu;
        case.body = *BODY_CASES
            .iter()
            .find(|body| body.len == len)
            .expect("the body is in the benchmark matrix");
        let body = case.body.bytes();
        let mut writer = RecordingWriter::default();
        let batches = Batches {
            len,
            split: true,
            left: 1,
            offset: 0,
        };
        for batch in batches {
            let part = &body[batch.part];
            for _ in 0..batch.copies {
                write_part(&mut writer, part, case)
                    .await
                    .expect("the recorder accepts each part");
            }
        }

        assert_eq!(writer.bytes, body);
        assert_eq!(writer.vectored_widths, vec![width; flushes]);
        assert_eq!(writer.flushes, flushes);
        assert_eq!(case.label("tokio-btls"), "batch128KB/chunked/tokio-btls");
    }
}
