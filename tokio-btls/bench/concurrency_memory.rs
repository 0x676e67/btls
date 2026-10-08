//! Measures the resident memory of a client process holding many concurrent connections.
//!
//! Not a Criterion target: the result is bytes, not time. Every case runs in a fresh client
//! process against one tokio-btls server process, so the resident set covers only the client.
//! Linux only, since it reads `/proc/self/status`.

use std::{
    env,
    future::Future,
    io::{self, BufRead, BufReader, Write},
    pin::Pin,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Instant,
};

use btls::{
    pkey::PKey,
    ssl::{Ssl, SslAcceptor, SslConnector, SslMethod, SslOptions, SslVerifyMode, SslVersion},
    x509::X509,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    runtime::Runtime,
    sync::Semaphore,
    task::JoinSet,
};
use tokio_btls::SslStream;
use tokio_rustls::{
    client::TlsStream,
    rustls::{
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        crypto::{aws_lc_rs, WebPkiSupportedAlgorithms},
        pki_types::{CertificateDer, ServerName, UnixTime},
        version, ClientConfig, DigitallySignedStruct, Error, SignatureScheme,
    },
    TlsConnector,
};

#[path = "support/allocator.rs"]
mod allocator;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Concurrent connections per case.
const CONNECTIONS: &[usize] = &[100, 1_000, 10_000];

/// Bytes each connection writes and then reads back in its one request.
const BODY_SIZES: &[usize] = &[1024, 64 * 1024, 1024 * 1024];

/// Client implementations, by the name each case reports.
const CLIENTS: &[&str] = &["tokio-btls", "tokio-rustls", "plaintext"];

/// Handshakes in flight at once, so the listener backlog never overflows.
const MAX_CONNECTING: usize = 256;

/// Response read buffer of each client connection, as an application would hold one.
const READ_BUF: usize = 8 * 1024;

/// Read and write buffer of each server connection.
const SERVER_BUF: usize = 16 * 1024;

/// Worker threads of the client and server runtimes.
const WORKERS: usize = 4;

/// Environment variables that pass a child process its role and case.
const ROLE: &str = "TOKIO_BTLS_BENCH_ROLE";
const CLIENT: &str = "TOKIO_BTLS_BENCH_CLIENT";
const CONNS: &str = "TOKIO_BTLS_BENCH_CONNS";
const BODY: &str = "TOKIO_BTLS_BENCH_BODY";
const PORT: &str = "TOKIO_BTLS_BENCH_PORT";

fn main() -> Result<(), BoxError> {
    match env::var(ROLE).as_deref() {
        Ok("server") => server(),
        Ok("client") => client(),
        _ => orchestrate(),
    }
}

/// Runs every case in its own client process and prints one table row per case.
///
/// `--test` runs only the smallest case of each client; a positional argument keeps only the
/// cases whose ID contains it.
fn orchestrate() -> Result<(), BoxError> {
    if !cfg!(target_os = "linux") {
        println!("concurrency_memory reads /proc/self/status and runs on Linux only");
        return Ok(());
    }

    let args: Vec<String> = env::args().skip(1).collect();
    let quick = args.iter().any(|arg| arg == "--test");
    let filter = args.iter().find(|arg| !arg.starts_with('-'));
    raise_fd_limit()?;

    let exe = env::current_exe()?;
    let server = Server::spawn(&exe)?;
    println!(
        "| Body | Connections | Client | Base RSS MiB | Idle KiB/conn | Peak KiB/conn | After KiB/conn | Seconds |"
    );
    println!("|---:|---:|---|---:|---:|---:|---:|---:|");

    for &body in BODY_SIZES {
        for &conns in CONNECTIONS {
            for &client in CLIENTS {
                let id = format!("{client}/{conns}/{}KB", body / 1024);
                if (quick && (body != BODY_SIZES[0] || conns != CONNECTIONS[0]))
                    || filter.is_some_and(|filter| !id.contains(filter.as_str()))
                {
                    continue;
                }

                let port = if client == "plaintext" {
                    server.plain_port
                } else {
                    server.tls_port
                };
                let output = Command::new(&exe)
                    .env(ROLE, "client")
                    .env(CLIENT, client)
                    .env(CONNS, conns.to_string())
                    .env(BODY, body.to_string())
                    .env(PORT, port.to_string())
                    .output()?;
                if !output.status.success() {
                    return Err(format!(
                        "{id} failed: {}",
                        String::from_utf8_lossy(&output.stderr).trim()
                    )
                    .into());
                }

                let sample = Sample::parse(&String::from_utf8_lossy(&output.stdout))?;
                let per_conn = |kib: u64| kib.saturating_sub(sample.base) as f64 / conns as f64;
                println!(
                    "| {} KB | {conns} | {client} | {:.1} | {:.1} | {:.1} | {:.1} | {:.1} |",
                    body / 1024,
                    sample.base as f64 / 1024.0,
                    per_conn(sample.idle),
                    per_conn(sample.peak),
                    per_conn(sample.after),
                    sample.seconds,
                );
                io::stdout().flush()?;
            }
        }
    }

    Ok(())
}

/// Lets each process open one socket per connection.
#[cfg(target_os = "linux")]
fn raise_fd_limit() -> io::Result<()> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, writable `rlimit`.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    limit.rlim_cur = limit.rlim_max;
    // SAFETY: `limit` is a valid `rlimit` whose soft limit does not exceed its hard limit.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn raise_fd_limit() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "concurrency_memory runs on Linux only",
    ))
}

/// The server child process and the ports it listens on; dropping it kills the process.
struct Server {
    child: Child,
    tls_port: u16,
    plain_port: u16,
}

/// Resident set sizes in KiB at each phase of one client case.
struct Sample {
    base: u64,
    idle: u64,
    peak: u64,
    after: u64,
    seconds: f64,
}

/// Opens client streams to the server for one implementation.
trait Connect: Send + Sync + 'static {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    fn connect(
        &self,
        tcp: TcpStream,
    ) -> impl Future<Output = Result<Self::Stream, BoxError>> + Send;
}

/// tokio-btls client streams.
struct Btls(SslConnector);

/// tokio-rustls client streams with the aws-lc-rs provider.
struct Rustls(TlsConnector);

/// Bare `TcpStream`s, the baseline without TLS.
struct Plain;

/// Accepts any server certificate; the test certificate has no SAN and is a CA certificate.
#[derive(Debug)]
struct NoVerifier(WebPkiSupportedAlgorithms);

// ===== impl Server =====

impl Server {
    /// Starts the server process and reads the two ports it prints.
    fn spawn(exe: &std::path::Path) -> Result<Self, BoxError> {
        let mut child = Command::new(exe)
            .env(ROLE, "server")
            .stdout(Stdio::piped())
            .spawn()?;
        let mut line = String::new();
        let stdout = child.stdout.take().ok_or("server stdout is not piped")?;
        BufReader::new(stdout).read_line(&mut line)?;
        let mut ports = line.split_whitespace().map(str::parse::<u16>);
        match (ports.next(), ports.next()) {
            (Some(Ok(tls_port)), Some(Ok(plain_port))) => Ok(Server {
                child,
                tls_port,
                plain_port,
            }),
            _ => {
                let _ = child.kill();
                Err(format!("server printed {line:?} instead of its ports").into())
            }
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ===== impl Sample =====

impl Sample {
    fn parse(line: &str) -> Result<Self, BoxError> {
        let mut fields = line.split_whitespace();
        let mut next = || {
            fields
                .next()
                .ok_or_else(|| format!("short client output {line:?}"))
        };
        Ok(Sample {
            base: next()?.parse()?,
            idle: next()?.parse()?,
            peak: next()?.parse()?,
            after: next()?.parse()?,
            seconds: next()?.parse()?,
        })
    }
}

// ===== impl Btls =====

impl Connect for Btls {
    type Stream = SslStream<TcpStream>;

    async fn connect(&self, tcp: TcpStream) -> Result<Self::Stream, BoxError> {
        let ssl = self
            .0
            .configure()?
            .verify_hostname(false)
            .into_ssl("localhost")?;
        let mut stream = SslStream::new(ssl, tcp)?;
        Pin::new(&mut stream).connect().await?;
        Ok(stream)
    }
}

// ===== impl Rustls =====

impl Connect for Rustls {
    type Stream = TlsStream<TcpStream>;

    async fn connect(&self, tcp: TcpStream) -> Result<Self::Stream, BoxError> {
        Ok(self
            .0
            .connect(ServerName::try_from("localhost")?, tcp)
            .await?)
    }
}

// ===== impl Plain =====

impl Connect for Plain {
    type Stream = TcpStream;

    async fn connect(&self, tcp: TcpStream) -> Result<Self::Stream, BoxError> {
        Ok(tcp)
    }
}

// ===== impl NoVerifier =====

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

/// Body of a client process: one case, printed as `base idle peak after seconds`.
fn client() -> Result<(), BoxError> {
    let name = env::var(CLIENT)?;
    let conns: usize = env::var(CONNS)?.parse()?;
    let body: usize = env::var(BODY)?.parse()?;
    let port: u16 = env::var(PORT)?.parse()?;
    let body: &'static [u8] = (0..body)
        .map(|i| (i % 251) as u8)
        .collect::<Vec<_>>()
        .leak();

    let runtime = runtime()?;
    match name.as_str() {
        "tokio-btls" => runtime.block_on(run(Btls(btls_connector()?), port, conns, body)),
        "tokio-rustls" => runtime.block_on(run(Rustls(rustls_connector()?), port, conns, body)),
        "plaintext" => runtime.block_on(run(Plain, port, conns, body)),
        _ => Err(format!("unknown client {name}").into()),
    }
}

fn runtime() -> io::Result<Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(WORKERS)
        .enable_all()
        .build()
}

/// Connects `conns` streams, then sends one request on all of them at once.
///
/// The resident set is read before connecting, once every handshake is done, as a peak over the
/// requests, and after them with every connection still open.
async fn run<C: Connect>(
    connector: C,
    port: u16,
    conns: usize,
    body: &'static [u8],
) -> Result<(), BoxError> {
    let connector = Arc::new(connector);
    let permits = Arc::new(Semaphore::new(MAX_CONNECTING));
    let base = status_kib("VmRSS:")?;
    let start = Instant::now();

    let mut tasks = JoinSet::new();
    for _ in 0..conns {
        let connector = connector.clone();
        let permits = permits.clone();
        tasks.spawn(async move {
            let _permit = permits.acquire_owned().await?;
            let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
            tcp.set_nodelay(true)?;
            connector.connect(tcp).await
        });
    }
    let mut streams = Vec::with_capacity(conns);
    while let Some(stream) = tasks.join_next().await {
        streams.push(stream??);
    }
    let idle = status_kib("VmRSS:")?;

    // Writing 5 resets the peak resident set (VmHWM) to the current one.
    std::fs::write("/proc/self/clear_refs", "5")?;
    let mut tasks = JoinSet::new();
    for mut stream in streams {
        tasks.spawn(async move {
            request(&mut stream, body).await?;
            Ok::<_, BoxError>(stream)
        });
    }
    let mut streams = Vec::with_capacity(conns);
    while let Some(stream) = tasks.join_next().await {
        streams.push(stream??);
    }
    let peak = status_kib("VmHWM:")?;
    let after = status_kib("VmRSS:")?;

    println!(
        "{base} {idle} {peak} {after} {:.1}",
        start.elapsed().as_secs_f64()
    );
    drop(streams);
    Ok(())
}

/// Writes a length-prefixed body, then reads the response of the same length.
async fn request<S>(stream: &mut S, body: &[u8]) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(&(body.len() as u64).to_le_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;

    let mut buf = vec![0; READ_BUF];
    let mut left = body.len();
    while left > 0 {
        let n = stream.read(&mut buf[..left.min(READ_BUF)]).await?;
        if n == 0 {
            return Err("server closed the connection early".into());
        }
        left -= n;
    }
    Ok(())
}

/// Reads one `/proc/self/status` field in KiB.
fn status_kib(field: &str) -> Result<u64, BoxError> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .and_then(|rest| rest.split_whitespace().next())
        .ok_or_else(|| format!("no {field} in /proc/self/status"))?;
    Ok(value.parse()?)
}

fn btls_connector() -> Result<SslConnector, BoxError> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    builder.set_verify(SslVerifyMode::NONE);
    builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_preserve_tls13_cipher_list(true);
    builder.set_cipher_list("AES128")?;
    Ok(builder.build())
}

fn rustls_connector() -> Result<TlsConnector, BoxError> {
    let mut provider = aws_lc_rs::default_provider();
    provider.cipher_suites = vec![aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
    let verifier = NoVerifier(provider.signature_verification_algorithms);
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

/// Body of the server process: tokio-btls on one port, plain TCP on another.
///
/// Each request is a little-endian `u64` length and that many bytes; the reply is as long.
fn server() -> Result<(), BoxError> {
    raise_fd_limit()?;
    runtime()?.block_on(listen())
}

/// Accepts connections on both ports until the process is killed.
async fn listen() -> Result<(), BoxError> {
    let cert = X509::from_pem(include_bytes!("../tests/cert.pem"))?;
    let key = PKey::private_key_from_pem(include_bytes!("../tests/key.pem"))?;
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    builder.set_certificate(&cert)?;
    builder.set_private_key(&key)?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_options(SslOptions::NO_TICKET);
    let acceptor = Arc::new(builder.build());

    let tls = TcpListener::bind("127.0.0.1:0").await?;
    let plain = TcpListener::bind("127.0.0.1:0").await?;
    println!(
        "{} {}",
        tls.local_addr()?.port(),
        plain.local_addr()?.port()
    );
    io::stdout().flush()?;

    loop {
        tokio::select! {
            accepted = tls.accept() => {
                let (tcp, _) = accepted?;
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let ssl = Ssl::new(acceptor.context())?;
                    let mut stream = SslStream::new(ssl, tcp)?;
                    Pin::new(&mut stream).accept().await?;
                    serve(stream).await
                });
            }
            accepted = plain.accept() => {
                let (tcp, _) = accepted?;
                tokio::spawn(serve(tcp));
            }
        }
    }
}

/// Answers requests until the client closes the connection.
async fn serve<S>(mut stream: S) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = vec![0; SERVER_BUF];
    loop {
        let mut header = [0; 8];
        match stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        let len = usize::try_from(u64::from_le_bytes(header))?;

        let mut left = len;
        while left > 0 {
            let n = stream.read(&mut buf[..left.min(SERVER_BUF)]).await?;
            if n == 0 {
                return Err("client closed the connection early".into());
            }
            left -= n;
        }
        let mut left = len;
        while left > 0 {
            let n = left.min(SERVER_BUF);
            stream.write_all(&buf[..n]).await?;
            left -= n;
        }
        stream.flush().await?;
    }
}
