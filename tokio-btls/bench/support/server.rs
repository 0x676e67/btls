//! The tokio-btls server configuration every peer shares, and the loopback server thread that
//! answers one TCP connection.

use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::mpsc::{self, Receiver, RecvTimeoutError, Sender},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use btls::{
    pkey::PKey,
    ssl::{Ssl, SslAcceptor, SslMethod, SslOptions, SslVersion},
    x509::X509,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
    runtime::Runtime,
};
use tokio_btls::SslStream;

use super::{case::Tls, runtime::tokio_runtime, BoxError, Direction};

/// Cipher suite every TLS connection must negotiate, with TLS 1.3.
const SUITE: &str = "TLS_AES_128_GCM_SHA256";

/// Largest read of a server that receives bodies.
const SINK_BUF_LEN: usize = 64 * 1024;

/// Socket buffer size both ends of a batched connection ask for.
///
/// The effective capacity depends on the OS and its limits. Batched reads check that all
/// ciphertext has arrived before timing, and batched writes time out if they cannot finish.
const SOCKET_BUF_LEN: u32 = 512 * 1024;

/// How long a batch may wait for socket space or for the server to finish.
pub(super) const PATIENCE: Duration = Duration::from_secs(10);

/// How a TCP server moves bodies after the checked one.
#[derive(Clone, Copy)]
pub(super) enum Pace {
    /// It streams bodies to a reader, or drains a writer, until the client goes away.
    Stream,
    /// It moves one batch per request and waits on a channel, off the socket, in between.
    Batch,
}

/// What the client asks of its server thread.
enum Request {
    /// Move this many body bytes: write them to a reader, or read and check them from a writer.
    /// The server replies once done.
    Batch(usize),
    /// Move bodies at the server's own pace until the client goes away.
    Stream,
}

/// The client's handle on the server thread of one loopback connection.
pub(super) struct TcpPeer {
    tls: Tls,
    pace: Pace,
    // Dropped once the client is done, which stops a batch server.
    requests: Option<Sender<Request>>,
    replies: Receiver<()>,
    thread: Option<JoinHandle<Result<u64, BoxError>>>,
    // A second handle on the client's socket, to peek at the bytes queued for it.
    probe: std::net::TcpStream,
    // Peek destination; grows to one byte more than a batch.
    scratch: Vec<u8>,
}

/// The server end of one connection, on its own thread and runtime.
struct Server<S> {
    stream: S,
    direction: Direction,
    body: &'static [u8],
    // Body bytes moved so far, and where the next one sits in `body`.
    moved: u64,
    offset: usize,
    // Receive buffer; empty when the server sends.
    buf: Vec<u8>,
}

// ===== impl TcpPeer =====

impl TcpPeer {
    /// Connects a client socket to a fresh server thread that moves `body` in `direction`, as
    /// seen from the client, over TLS when `tls` is enabled.
    ///
    /// Must run on the client's runtime. Returns an error if a socket cannot be set up.
    pub(super) async fn open(
        tls: Tls,
        pace: Pace,
        direction: Direction,
        body: &'static [u8],
    ) -> Result<(TcpStream, Self), BoxError> {
        let listener = TcpSocket::new_v4()?;
        let client = TcpSocket::new_v4()?;
        if let Pace::Batch = pace {
            // Set before connecting, so the window scale fits; accepted sockets inherit them.
            for socket in [&listener, &client] {
                socket.set_recv_buffer_size(SOCKET_BUF_LEN)?;
                socket.set_send_buffer_size(SOCKET_BUF_LEN)?;
            }
        }
        listener.bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let listener = listener.listen(1)?;
        let client = client.connect(listener.local_addr()?).await?;
        let (socket, _) = listener.accept().await?;
        // Nagle would hold small records until the peer's delayed ACK.
        client.set_nodelay(true)?;
        socket.set_nodelay(true)?;

        let socket = socket.into_std()?;
        let client = client.into_std()?;
        let probe = client.try_clone()?;
        let client = TcpStream::from_std(client)?;

        let (requests, request_rx) = mpsc::channel();
        let (reply_tx, replies) = mpsc::channel();
        let thread =
            thread::spawn(move || serve(socket, tls, direction, body, request_rx, reply_tx));
        let peer = Self {
            tls,
            pace,
            requests: Some(requests),
            replies,
            thread: Some(thread),
            probe,
            scratch: Vec::new(),
        };
        Ok((client, peer))
    }

    /// Whether the stream carries TLS records.
    pub(super) const fn tls(&self) -> Tls {
        self.tls
    }

    /// Whether the server streams instead of moving batches on request.
    pub(super) const fn streams(&self) -> bool {
        matches!(self.pace, Pace::Stream)
    }

    /// Asks the server to move `len` body bytes; [`Self::wait`] returns once it has.
    pub(super) fn request(&self, len: usize) -> Result<(), BoxError> {
        self.send_request(Request::Batch(len))
    }

    /// Lets a streaming server move bodies at its own pace.
    pub(super) fn stream(&self) -> Result<(), BoxError> {
        self.send_request(Request::Stream)
    }

    /// Waits for the server to finish the requested bytes.
    pub(super) fn wait(&self) -> Result<(), BoxError> {
        match self.replies.recv_timeout(PATIENCE) {
            Ok(()) => Ok(()),
            Err(RecvTimeoutError::Timeout) => {
                Err(format!("server did not finish a batch in {PATIENCE:?}").into())
            }
            Err(RecvTimeoutError::Disconnected) => Err("server thread stopped".into()),
        }
    }

    /// Has the server write `copies` of a `len`-byte part, then waits until the client's socket
    /// holds all of their bytes. Returns how many it holds.
    ///
    /// Returns an error if the receive buffer is too small for the batch.
    pub(super) fn send(&mut self, len: usize, copies: usize) -> Result<usize, BoxError> {
        self.request(len * copies)?;
        self.wait()?;
        let wire = self.tls.wire_len(len) * copies;
        // Loopback delivers within the server's send, unless the kernel defers the softirq.
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            // One byte more than a batch shows bytes beyond it.
            let queued = self.peek(wire + 1)?;
            if queued >= wire {
                return Ok(queued);
            }
            if Instant::now() > deadline {
                return Err(format!(
                    "{queued} of {wire} bytes reached the client; its receive buffer must hold a \
                     batch (see net.core.rmem_max)"
                )
                .into());
            }
            thread::sleep(Duration::from_micros(50));
        }
    }

    /// Has the server read `len` body bytes and compare them with the body.
    pub(super) fn receive(&self, len: usize) -> Result<(), BoxError> {
        self.request(len)?;
        self.wait()
    }

    /// Bytes queued for the client, counted up to the largest batch so far.
    pub(super) fn queued(&mut self) -> io::Result<usize> {
        self.peek(self.scratch.len().max(1))
    }

    /// Appends the server's error to `error` if its thread stopped with one.
    pub(super) fn explain(&mut self, error: BoxError) -> BoxError {
        // Without requests a waiting batch server stops; a failing one may need a moment.
        self.requests = None;
        let deadline = Instant::now() + Duration::from_secs(1);
        while self.thread.as_ref().is_some_and(|t| !t.is_finished()) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        match self.thread.take_if(|thread| thread.is_finished()).map(join) {
            Some(Err(server)) => format!("{error} (server: {server})").into(),
            _ => error,
        }
    }

    /// Stops the server and returns the body bytes it moved.
    ///
    /// The client stream must already be closed, so that a streaming server's next write fails.
    pub(super) fn finish(self) -> Result<u64, BoxError> {
        let Self {
            requests,
            probe,
            thread,
            ..
        } = self;
        drop((requests, probe));
        thread.map_or_else(|| Err("server thread already joined".into()), join)
    }

    fn send_request(&self, request: Request) -> Result<(), BoxError> {
        self.requests
            .as_ref()
            .and_then(|requests| requests.send(request).ok())
            .ok_or_else(|| "server thread stopped".into())
    }

    /// Peeks at up to `limit` bytes queued for the client without taking them.
    fn peek(&mut self, limit: usize) -> io::Result<usize> {
        if self.scratch.len() < limit {
            self.scratch.resize(limit, 0);
        }
        match self.probe.peek(&mut self.scratch[..limit]) {
            Ok(n) => Ok(n),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(0),
            Err(error) => Err(error),
        }
    }
}

// ===== impl Server =====

impl<S> Server<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn new(stream: S, direction: Direction, body: &'static [u8]) -> Self {
        let buf = match direction {
            Direction::Read => Vec::new(),
            Direction::Write => vec![0; SINK_BUF_LEN],
        };
        Self {
            stream,
            direction,
            body,
            moved: 0,
            offset: 0,
            buf,
        }
    }

    /// Answers requests until the client drops its sender, or streams once asked to. Returns
    /// the body bytes moved.
    ///
    /// The thread blocks on `requests` outside the runtime, so between batches it sits neither
    /// in a socket call nor in epoll, and the client's traffic never wakes it.
    fn run(
        mut self,
        runtime: &Runtime,
        requests: Receiver<Request>,
        replies: Sender<()>,
    ) -> Result<u64, BoxError> {
        for request in requests {
            match request {
                Request::Batch(len) => {
                    runtime.block_on(self.batch(len))?;
                    if replies.send(()).is_err() {
                        break;
                    }
                }
                Request::Stream => return runtime.block_on(self.stream()),
            }
        }
        Ok(self.moved)
    }

    /// Writes `len` body bytes to a reader, or reads and checks them from a writer.
    async fn batch(&mut self, mut len: usize) -> Result<(), BoxError> {
        match self.direction {
            Direction::Read => {
                while len > 0 {
                    let n = len.min(self.body.len() - self.offset);
                    let part = &self.body[self.offset..self.offset + n];
                    self.stream.write_all(part).await?;
                    self.advance(n);
                    len -= n;
                }
                self.stream.flush().await?;
            }
            Direction::Write => {
                while len > 0 {
                    match self.read_checked(len).await? {
                        0 => return Err("client closed the connection mid-batch".into()),
                        n => len -= n,
                    }
                }
            }
        }
        Ok(())
    }

    /// Streams bodies to a reader, or reads and checks a writer's bodies until it half-closes.
    async fn stream(mut self) -> Result<u64, BoxError> {
        match self.direction {
            Direction::Read => {
                // The client checks what it reads, then closes the socket, which fails the next
                // write.
                while self
                    .stream
                    .write_all(&self.body[self.offset..])
                    .await
                    .is_ok()
                {
                    self.advance(self.body.len() - self.offset);
                }
            }
            Direction::Write => while self.read_checked(usize::MAX).await? > 0 {},
        }
        Ok(self.moved)
    }

    /// Reads at most `limit` bytes and compares them with the body at their offset. Returns 0
    /// at the end of the stream.
    async fn read_checked(&mut self, limit: usize) -> Result<usize, BoxError> {
        let len = limit.min(self.buf.len()).min(self.body.len() - self.offset);
        let n = self.stream.read(&mut self.buf[..len]).await?;
        if self.buf[..n] != self.body[self.offset..self.offset + n] {
            let moved = self.moved;
            return Err(format!("server received a different body after {moved} bytes").into());
        }
        self.advance(n);
        Ok(n)
    }

    fn advance(&mut self, n: usize) {
        self.moved += n as u64;
        self.offset = (self.offset + n) % self.body.len();
    }
}

/// Builds the server configuration every peer shares: TLS 1.3 only, no session tickets.
///
/// Returns an error if the test certificate or key cannot be loaded.
pub(super) fn acceptor() -> Result<SslAcceptor, BoxError> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    let cert = X509::from_pem(include_bytes!("../../tests/cert.pem"))?;
    let key = PKey::private_key_from_pem(include_bytes!("../../tests/key.pem"))?;
    builder.set_certificate(&cert)?;
    builder.set_private_key(&key)?;
    builder.check_private_key()?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    // A NewSessionTicket would otherwise land in the client's first measured read.
    builder.set_options(SslOptions::NO_TICKET);
    Ok(builder.build())
}

/// Completes the server handshake over `transport` and checks the negotiated suite.
///
/// The clients offer only TLS 1.3 with [`SUITE`], so this one check covers every stack.
pub(super) async fn accept<S>(
    acceptor: &SslAcceptor,
    transport: S,
) -> Result<SslStream<S>, BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = SslStream::new(Ssl::new(acceptor.context())?, transport)?;
    Pin::new(&mut stream).accept().await?;

    let ssl = stream.ssl();
    let suite = ssl
        .current_cipher()
        .and_then(|cipher| cipher.standard_name());
    if ssl.version2() != Some(SslVersion::TLS1_3) || suite != Some(SUITE) {
        return Err(format!(
            "negotiated {} {}, expected TLSv1.3 {SUITE}",
            ssl.version_str(),
            suite.unwrap_or("no cipher"),
        )
        .into());
    }
    Ok(stream)
}

/// Body of a server thread: accepts TLS when enabled, then answers the client's requests.
fn serve(
    socket: std::net::TcpStream,
    tls: Tls,
    direction: Direction,
    body: &'static [u8],
    requests: Receiver<Request>,
    replies: Sender<()>,
) -> Result<u64, BoxError> {
    let runtime = tokio_runtime()?;
    let socket = {
        let _runtime = runtime.enter();
        TcpStream::from_std(socket)?
    };
    match tls {
        Tls::Enabled => {
            let stream = runtime.block_on(async { accept(&acceptor()?, socket).await })?;
            Server::new(stream, direction, body).run(&runtime, requests, replies)
        }
        Tls::Disabled => Server::new(socket, direction, body).run(&runtime, requests, replies),
    }
}

/// Joins a server thread and returns its result.
fn join(thread: JoinHandle<Result<u64, BoxError>>) -> Result<u64, BoxError> {
    thread
        .join()
        .map_err(|_| io::Error::other("server thread panicked"))?
}
