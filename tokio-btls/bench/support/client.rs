//! Statically dispatched client adapters, connection setup and the measured loops.

mod btls;
mod plain;
mod rustls;

#[cfg(test)]
// Criterion's harness-free targets also set cfg(test), but omit the test functions.
#[allow(dead_code, unused_imports)]
mod tests;

use std::{
    cell::Cell,
    future::Future,
    io::{self, IoSlice},
    ops::Range,
    time::Duration,
};

use criterion::{measurement::WallTime, BenchmarkGroup};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    runtime::Runtime,
};

use super::{
    case::{BodyCase, BodyKind, Tls, BATCH_LEN, MAX_SLICES},
    memory::{self, MemoryPeer, MemoryStream},
    runtime::tokio_runtime,
    server::{self, Pace, TcpPeer},
    BenchTarget, BoxError, Clock, Direction, Transport,
};

/// Carries one body row from the runner into client registration.
#[derive(Clone, Copy)]
pub(super) struct ClientBenchCase {
    target: BenchTarget,
    body: BodyCase,
    exact_framing: bool,
}

/// One registered benchmark: the row's inputs and how the client hands the body over.
#[derive(Clone, Copy)]
struct ClientCase {
    target: BenchTarget,
    body: BodyCase,
    exact_framing: bool,
    body_kind: BodyKind,
}

/// One connected client stream, its server end and the buffers its iterations reuse.
struct Connection<T> {
    stream: T,
    // Read destination: the body's length for `full`, `chunk_size` for `chunked`; empty for writes.
    buf: Vec<u8>,
    peer: Peer,
    // Bodies moved so far, the checked one included.
    bodies: u64,
}

/// The server end of a connection.
enum Peer {
    /// tokio-btls on the client's task, over the memory transport.
    Memory(MemoryPeer),
    /// A server thread, over loopback TCP.
    Tcp(TcpPeer),
}

/// Copies of one part of a body that move between two clock reads.
struct Batch {
    part: Range<usize>,
    copies: usize,
}

/// Splits bodies into batches of whole bodies up to [`BATCH_LEN`], at least one, or, when
/// `split`, a larger body into parts of [`BATCH_LEN`].
struct Batches {
    len: usize,
    split: bool,
    left: u64,
    // Start of the next part of the current body.
    offset: usize,
}

/// Adapts one client stream library to the shared measured loops.
///
/// Connectors and connections are created outside measurement. Every TLS client offers only
/// TLS 1.3 with TLS_AES_128_GCM_SHA256 and skips certificate checks; the server asserts the suite.
trait ClientAdapter {
    /// Client configuration built once per registered benchmark.
    type Connector;

    /// Stream returned by [`Self::connect`] over transport `S`.
    type Stream<S>: AsyncRead + AsyncWrite + Unpin
    where
        S: AsyncRead + AsyncWrite + Unpin;

    /// Stable name appended to the Criterion benchmark ID.
    const NAME: &'static str;

    /// Whether the stream is TLS, which picks the server and the bytes on the wire.
    const TLS: Tls;

    /// Builds the client configuration.
    fn connector() -> Result<Self::Connector, BoxError>;

    /// Completes the client handshake over `transport`.
    fn connect<S>(
        connector: &Self::Connector,
        transport: S,
    ) -> impl Future<Output = Result<Self::Stream<S>, BoxError>>
    where
        S: AsyncRead + AsyncWrite + Unpin;
}

// ===== impl ClientBenchCase =====

impl ClientBenchCase {
    /// Creates the client input shared by both body kinds.
    pub(super) const fn new(target: BenchTarget, body: BodyCase, exact_framing: bool) -> Self {
        Self {
            target,
            body,
            exact_framing,
        }
    }
}

// ===== impl ClientCase =====

impl ClientCase {
    /// Copies the row's inputs for one body kind.
    const fn new(bench_case: ClientBenchCase, body_kind: BodyKind) -> Self {
        Self {
            target: bench_case.target,
            body: bench_case.body,
            exact_framing: bench_case.exact_framing,
            body_kind,
        }
    }

    /// Builds the body-kind/client suffix used in the Criterion benchmark ID.
    fn label(self, client: &str) -> String {
        let batch = match (self.target.transport, self.target.clock) {
            (Transport::Tcp, Clock::Cpu) if self.body.len > BATCH_LEN => "batch128KB/",
            _ => "",
        };
        format!("{batch}{}/{client}", self.body_kind)
    }

    /// Checks the bytes on the wire against full records.
    ///
    /// Exact unless relaxed, so a stack that splits or pads records fails instead of skewing the
    /// comparison.
    fn check_framing(self, got: usize, expected: usize) -> Result<(), BoxError> {
        if got == expected || (!self.exact_framing && got > expected) {
            return Ok(());
        }
        Err(format!("{got} bytes on the wire, expected {expected}").into())
    }
}

// ===== impl Connection =====

impl<T> Connection<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn new(stream: T, case: ClientCase, peer: Peer) -> Self {
        let buf = match (case.target.direction, case.body_kind) {
            (Direction::Read, BodyKind::Full) => vec![0; case.body.len],
            (Direction::Read, BodyKind::Chunked) => vec![0; case.body.chunk_size],
            (Direction::Write, _) => Vec::new(),
        };
        Self {
            stream,
            buf,
            peer,
            bodies: 0,
        }
    }

    /// Moves one body outside measurement, compares every read with it, and on the memory
    /// transport checks its ciphertext length. A streaming server then starts streaming.
    async fn check(&mut self, case: ClientCase) -> Result<(), BoxError> {
        let body = case.body.bytes();
        let same = |offset: usize, bytes: &[u8]| body[offset..offset + bytes.len()] == *bytes;
        let Self {
            stream,
            buf,
            peer,
            bodies,
        } = self;
        match (peer, case.target.direction) {
            (Peer::Tcp(peer), direction) => {
                // The server moves the body while the client does, so it needs no room in the
                // socket buffers.
                peer.request(body.len())?;
                match direction {
                    Direction::Read => {
                        read_part(stream, buf, case, 0..body.len(), same).await?;
                    }
                    Direction::Write => write_part(stream, body, case).await?,
                }
                peer.wait()?;
                if peer.streams() {
                    peer.stream()?;
                }
            }
            (peer @ Peer::Memory(_), Direction::Read) => {
                read_batches(stream, buf, peer, case, 1, same).await?;
            }
            (Peer::Memory(peer), Direction::Write) => {
                // Exact here: no KeyUpdate comes this early.
                write_part(stream, body, case).await?;
                case.check_framing(peer.unread(), Tls::Enabled.wire_len(body.len()))?;
                peer.receive(body, 1).await?;
            }
        }
        *bodies = 1;
        Ok(())
    }

    /// Moves `iters` bodies and returns the measured time.
    async fn run(&mut self, case: ClientCase, iters: u64) -> Result<Duration, BoxError> {
        let Self {
            stream,
            buf,
            peer,
            bodies,
        } = self;
        let elapsed = match (peer, case.target.direction) {
            (Peer::Tcp(tcp), Direction::Read) if tcp.streams() => {
                read_stream(stream, buf, case, iters).await?
            }
            (Peer::Tcp(tcp), Direction::Write) if tcp.streams() => {
                write_stream(stream, case, iters).await?
            }
            (peer, Direction::Read) => {
                read_batches(stream, buf, peer, case, iters, |_, _| true).await?
            }
            (peer, Direction::Write) => write_batches(stream, peer, case, iters).await?,
        };
        *bodies += iters;
        Ok(elapsed)
    }

    /// Ends the connection after measurement.
    ///
    /// A writer half-closes, and the TCP server must have received every body byte written.
    async fn finish(self, case: ClientCase) -> Result<(), BoxError> {
        let Self {
            mut stream,
            peer,
            bodies,
            ..
        } = self;
        let Peer::Tcp(mut peer) = peer else {
            return Ok(());
        };
        if let Direction::Write = case.target.direction {
            // close_notify and FIN end a streaming server's reads.
            if let Err(error) = stream.shutdown().await {
                return Err(peer.explain(error.into()));
            }
        }
        // Closing the socket fails a streaming server's next write.
        drop(stream);
        let moved = peer.finish()?;
        let written = bodies
            .checked_mul(u64::try_from(case.body.len)?)
            .ok_or("body bytes overflow u64")?;
        match case.target.direction {
            Direction::Write if moved != written => {
                Err(format!("server received {moved} bytes, client wrote {written}").into())
            }
            _ => Ok(()),
        }
    }

    /// Appends the server's error, if it stopped with one.
    fn explain(&mut self, error: BoxError) -> BoxError {
        match &mut self.peer {
            Peer::Tcp(peer) => peer.explain(error),
            Peer::Memory(_) => error,
        }
    }
}

// ===== impl Peer =====

impl Peer {
    /// Splits `iters` bodies of `len` bytes into batches. Over TCP a body larger than
    /// [`BATCH_LEN`] moves in parts, so every batch fits the socket buffers.
    fn batches(&self, len: usize, iters: u64) -> Batches {
        Batches {
            len,
            split: matches!(self, Self::Tcp(_)),
            left: iters,
            offset: 0,
        }
    }

    /// Bytes on the wire for `copies` of a `len`-byte part.
    fn wire_len(&self, len: usize, copies: usize) -> usize {
        let tls = match self {
            Self::Memory(_) => Tls::Enabled,
            Self::Tcp(peer) => peer.tls(),
        };
        tls.wire_len(len) * copies
    }

    /// Has the server send `copies` of `part` and returns the bytes then queued for the client.
    async fn send(&mut self, part: &[u8], copies: usize) -> Result<usize, BoxError> {
        match self {
            Self::Memory(peer) => {
                peer.send(part, copies).await?;
                Ok(peer.in_flight())
            }
            Self::Tcp(peer) => {
                let queued = peer.send(part.len(), copies)?;
                // The runtime takes in the socket's readiness here instead of in the timed reads.
                tokio::task::yield_now().await;
                Ok(queued)
            }
        }
    }

    /// Bytes still queued for the client.
    fn queued(&mut self) -> Result<usize, BoxError> {
        match self {
            Self::Memory(peer) => Ok(peer.in_flight()),
            Self::Tcp(peer) => Ok(peer.queued()?),
        }
    }

    /// Has the server receive `copies` of `part` and compare them with it.
    async fn receive(&mut self, part: &[u8], copies: usize) -> Result<(), BoxError> {
        match self {
            Self::Memory(peer) => peer.receive(part, copies).await,
            Self::Tcp(peer) => {
                peer.receive(part.len() * copies)?;
                // As in `send`: socket events from the server's reads are handled off the clock.
                tokio::task::yield_now().await;
                Ok(())
            }
        }
    }
}

// ===== impl Batches =====

impl Iterator for Batches {
    type Item = Batch;

    fn next(&mut self) -> Option<Batch> {
        if self.left == 0 {
            return None;
        }
        if self.split && self.len > BATCH_LEN {
            let start = self.offset;
            let end = self.len.min(start + BATCH_LEN);
            self.offset = end % self.len;
            if self.offset == 0 {
                self.left -= 1;
            }
            return Some(Batch {
                part: start..end,
                copies: 1,
            });
        }
        let per_batch = (BATCH_LEN / self.len).max(1);
        let copies = usize::try_from(self.left).map_or(per_batch, |left| left.min(per_batch));
        self.left -= copies as u64;
        Some(Batch {
            part: 0..self.len,
            copies,
        })
    }
}

/// Registers both body kinds of every stack for one body row: the TLS stacks, and over TCP the
/// bare stream.
///
/// Returns an error if a client, its runtime, its connection or its data check fails.
pub(super) fn bench_clients(
    group: &mut BenchmarkGroup<'_, WallTime>,
    bench_case: ClientBenchCase,
    reverse_order: bool,
) -> Result<(), BoxError> {
    type Register = fn(&mut BenchmarkGroup<'_, WallTime>, ClientCase) -> Result<(), BoxError>;
    let mut clients: [Register; 3] = [
        register::<btls::Adapter>,
        register::<rustls::Adapter>,
        register::<plain::Adapter>,
    ];
    let count = match bench_case.target.transport {
        Transport::Memory => 2,
        Transport::Tcp => 3,
    };
    let clients = &mut clients[..count];
    if reverse_order {
        clients.reverse();
    }
    for body_kind in BodyKind::ALL {
        let client_case = ClientCase::new(bench_case, body_kind);
        for register in clients.iter() {
            register(group, client_case)?;
        }
    }
    Ok(())
}

/// Connects one client outside measurement, checks one body, runs its benchmark, and checks
/// the connection afterwards.
///
/// Returns an error if any of the setup or the final check fails.
fn register<A>(group: &mut BenchmarkGroup<'_, WallTime>, case: ClientCase) -> Result<(), BoxError>
where
    A: ClientAdapter,
{
    let runtime = tokio_runtime()?;
    let connector = A::connector()?;
    let label = case.label(A::NAME);
    match case.target.transport {
        Transport::Memory => {
            let connection = runtime.block_on(open_memory::<A>(&connector, case))?;
            measure(group, &runtime, label, connection, case)
        }
        Transport::Tcp => {
            let connection = runtime.block_on(open_tcp::<A>(&connector, case))?;
            measure(group, &runtime, label, connection, case)
        }
    }
}

/// Handshakes over a fresh memory transport, both sides on this task, and checks one body.
async fn open_memory<A>(
    connector: &A::Connector,
    case: ClientCase,
) -> Result<Connection<A::Stream<MemoryStream>>, BoxError>
where
    A: ClientAdapter,
{
    let (client, server) = memory::pair();
    let acceptor = server::acceptor()?;
    let (stream, peer) = tokio::try_join!(
        A::connect(connector, client),
        server::accept(&acceptor, server)
    )?;
    let peer = MemoryPeer::new(peer, case.target.direction, case.body.len)?;
    let mut connection = Connection::new(stream, case, Peer::Memory(peer));
    connection.check(case).await?;
    Ok(connection)
}

/// Connects to a fresh loopback server thread, handshakes, and checks one body.
async fn open_tcp<A>(
    connector: &A::Connector,
    case: ClientCase,
) -> Result<Connection<A::Stream<TcpStream>>, BoxError>
where
    A: ClientAdapter,
{
    // Wall-time rows stream end to end; CPU-time rows time only the client's side of a batch.
    let pace = match case.target.clock {
        Clock::Wall => Pace::Stream,
        Clock::Cpu => Pace::Batch,
    };
    let (tcp, mut peer) =
        TcpPeer::open(A::TLS, pace, case.target.direction, case.body.bytes()).await?;
    let stream = match A::connect(connector, tcp).await {
        Ok(stream) => stream,
        Err(error) => return Err(peer.explain(error)),
    };
    let mut connection = Connection::new(stream, case, Peer::Tcp(peer));
    match connection.check(case).await {
        Ok(()) => Ok(connection),
        Err(error) => Err(connection.explain(error)),
    }
}

/// Registers `connection`, moving it into each timed batch and back outside the clock, and
/// finishes it once the benchmark has run.
///
/// # Panics
///
/// Panics inside the benchmark on an I/O error or a failed data check.
fn measure<T>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    runtime: &Runtime,
    label: String,
    connection: Connection<T>,
    case: ClientCase,
) -> Result<(), BoxError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let slot = &Cell::new(Some(connection));
    group.bench_function(label, |bencher| {
        bencher.to_async(runtime).iter_custom(|iters| {
            let mut connection = slot
                .take()
                .expect("the connection returns after every batch");
            async move {
                let elapsed = match connection.run(case, iters).await {
                    Ok(elapsed) => elapsed,
                    Err(error) => panic!("{}", connection.explain(error)),
                };
                slot.set(Some(connection));
                elapsed
            }
        });
    });
    let connection = slot.take().ok_or("the connection did not return")?;
    runtime.block_on(connection.finish(case))
}

/// Reads `iters` bodies the server streams.
async fn read_stream<T>(
    stream: &mut T,
    buf: &mut [u8],
    case: ClientCase,
    iters: u64,
) -> Result<Duration, BoxError>
where
    T: AsyncRead + Unpin,
{
    let body = case.body.bytes();
    let stopwatch = case.target.clock.start();
    let mut last = 0..0;
    for _ in 0..iters {
        last = read_part(stream, buf, case, 0..body.len(), |_, _| true).await?;
    }
    let elapsed = stopwatch.elapsed();
    check_tail(buf, last, body)?;
    Ok(elapsed)
}

/// Writes `iters` bodies to a server that reads them as they come.
async fn write_stream<T>(stream: &mut T, case: ClientCase, iters: u64) -> Result<Duration, BoxError>
where
    T: AsyncWrite + Unpin,
{
    let body = case.body.bytes();
    let stopwatch = case.target.clock.start();
    for _ in 0..iters {
        write_part(stream, body, case).await?;
    }
    Ok(stopwatch.elapsed())
}

/// Reads `iters` bodies in batches the server queues before the clock starts, passing each read
/// to `check` with its body offset.
async fn read_batches<T, F>(
    stream: &mut T,
    buf: &mut [u8],
    peer: &mut Peer,
    case: ClientCase,
    iters: u64,
    mut check: F,
) -> Result<Duration, BoxError>
where
    T: AsyncRead + Unpin,
    F: FnMut(usize, &[u8]) -> bool,
{
    let body = case.body.bytes();
    let mut elapsed = Duration::ZERO;
    for batch in peer.batches(body.len(), iters) {
        let part = &body[batch.part.clone()];
        let queued = peer.send(part, batch.copies).await?;
        case.check_framing(queued, peer.wire_len(part.len(), batch.copies))?;

        let stopwatch = case.target.clock.start();
        let mut last = 0..0;
        for _ in 0..batch.copies {
            last = read_part(stream, buf, case, batch.part.clone(), &mut check).await?;
        }
        elapsed += stopwatch.elapsed();

        check_tail(buf, last, &body[..batch.part.end])?;
        match peer.queued()? {
            0 => {}
            left => return Err(format!("client left {left} bytes unread").into()),
        }
    }
    Ok(elapsed)
}

/// Writes `iters` bodies in batches the server receives and compares after the clock stops.
async fn write_batches<T>(
    stream: &mut T,
    peer: &mut Peer,
    case: ClientCase,
    iters: u64,
) -> Result<Duration, BoxError>
where
    T: AsyncWrite + Unpin,
{
    let body = case.body.bytes();
    let mut elapsed = Duration::ZERO;
    for batch in peer.batches(body.len(), iters) {
        let part = &body[batch.part];
        if let Peer::Tcp(_) = peer {
            elapsed += write_batch(stream, part, case, batch.copies, server::PATIENCE).await?;
        } else {
            let stopwatch = case.target.clock.start();
            for _ in 0..batch.copies {
                write_part(stream, part, case).await?;
            }
            elapsed += stopwatch.elapsed();
        }
        peer.receive(part, batch.copies).await?;
    }
    Ok(elapsed)
}

/// Times a TCP write batch while the server waits for the later receive request.
///
/// Bound the wait in wall time: if the socket buffers cannot hold the batch, neither side
/// can make progress. Timer setup and completion checks stay outside the returned duration.
async fn write_batch<T>(
    stream: &mut T,
    part: &[u8],
    case: ClientCase,
    copies: usize,
    patience: Duration,
) -> Result<Duration, BoxError>
where
    T: AsyncWrite + Unpin,
{
    let write = async {
        let stopwatch = case.target.clock.start();
        for _ in 0..copies {
            write_part(stream, part, case).await?;
        }
        Ok::<_, io::Error>(stopwatch.elapsed())
    };
    tokio::time::timeout(patience, write)
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "client did not write and flush a batch in {patience:?}; socket send and \
                     receive buffers must hold the batch (on Linux, check net.core.wmem_max \
                     and net.core.rmem_max)"
                ),
            )
        })?
        .map_err(Into::into)
}

/// Writes `part` of a body as the case's kind, then flushes.
async fn write_part<T>(stream: &mut T, part: &[u8], case: ClientCase) -> io::Result<()>
where
    T: AsyncWrite + Unpin,
{
    match case.body_kind {
        BodyKind::Full => stream.write_all(part).await?,
        BodyKind::Chunked => {
            let mut slices = [IoSlice::new(&[]); MAX_SLICES];
            for (slice, chunk) in slices.iter_mut().zip(part.chunks(case.body.chunk_size)) {
                *slice = IoSlice::new(chunk);
            }
            let mut bufs = &mut slices[..part.len().div_ceil(case.body.chunk_size)];
            while !bufs.is_empty() {
                let n = stream.write_vectored(bufs).await?;
                if n == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                IoSlice::advance_slices(&mut bufs, n);
            }
        }
    }
    stream.flush().await
}

/// Reads `part` of a body as the case's kind and passes each read to `check` with its body
/// offset.
///
/// Each read asks for the rest of the body, as a reader of the whole body would; only the
/// server's batch ends it at the part's end. Returns where in `buf` the part's last bytes landed:
/// all of the part for `full`, the last read for `chunked`.
async fn read_part<T, F>(
    stream: &mut T,
    buf: &mut [u8],
    case: ClientCase,
    part: Range<usize>,
    mut check: F,
) -> io::Result<Range<usize>>
where
    T: AsyncRead + Unpin,
    F: FnMut(usize, &[u8]) -> bool,
{
    let len = case.body.len;
    let mut done = part.start;
    let mut last = 0..0;
    while done < part.end {
        let dst = match case.body_kind {
            BodyKind::Full => &mut buf[done..len],
            BodyKind::Chunked => {
                let n = buf.len().min(len - done);
                &mut buf[..n]
            }
        };
        let n = stream.read(dst).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        if !check(done, &dst[..n]) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "client read a different body",
            ));
        }
        done += n;
        last = match case.body_kind {
            BodyKind::Full => part.start..done,
            BodyKind::Chunked => 0..n,
        };
    }
    Ok(last)
}

/// Checks that the bytes the last read left at `last` in `buf` end `body`.
fn check_tail(buf: &[u8], last: Range<usize>, body: &[u8]) -> Result<(), BoxError> {
    if !body.ends_with(&buf[last]) {
        return Err("client read a different body".into());
    }
    Ok(())
}
