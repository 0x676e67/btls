//! Vectored-write benchmark: tokio-btls (BoringSSL) vs tokio-rustls 0.26 (aws-lc-rs).
//!
//! The writer under test is the TLS server; the reader is always the same tokio-btls client,
//! so only the write path differs. Both sides negotiate TLS 1.3 / AES-128-GCM.
//!
//! Modes:
//!   tcp  - real loopback TCP; reader drains on another thread.
//!   null - after the handshake the server transport accepts and discards every write, so the
//!          numbers isolate the CPU cost of the TLS write path (no kernel copies).
//!
//! Usage: vbench [tcp|null|both] [filter] [runs]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    io::{self, IoSlice},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use btls::ssl::{
    Ssl, SslAcceptor, SslConnector, SslFiletype, SslMethod, SslVerifyMode, SslVersion,
};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::io::{Read, Write};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

// ===== allocation counter (Rust heap only, per thread) =====

struct Counting;
thread_local! {
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
        System.realloc(p, l, n)
    }
}
#[global_allocator]
static GLOBAL: Counting = Counting;
fn allocs() -> u64 {
    ALLOCS.with(|c| c.get())
}

fn minflt() -> u64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_THREAD, &mut ru) };
    ru.ru_minflt as u64
}

fn thread_cpu() -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

// ===== counting transport =====

#[derive(Default)]
struct Stats {
    write: AtomicU64,
    writev: AtomicU64,
    pending: AtomicU64,
    sys: AtomicU64,
    eagain: AtomicU64,
    bytes: AtomicU64,
    iovs: AtomicU64,
    null: AtomicBool,
}

impl Stats {
    fn reset(&self) {
        for c in [
            &self.write,
            &self.writev,
            &self.pending,
            &self.sys,
            &self.eagain,
            &self.bytes,
            &self.iovs,
        ] {
            c.store(0, Relaxed);
        }
    }
}

struct Io {
    fd: AsyncFd<std::net::TcpStream>,
    stats: Arc<Stats>,
}

impl Io {
    fn new(tcp: std::net::TcpStream, stats: Arc<Stats>) -> Self {
        tcp.set_nonblocking(true).unwrap();
        Io {
            fd: AsyncFd::new(tcp).unwrap(),
            stats,
        }
    }

    /// Runs `f` (exactly one syscall) when the socket is write-ready, counting calls and EAGAINs.
    fn poll_sys(
        &self,
        cx: &mut Context<'_>,
        mut f: impl FnMut(&std::net::TcpStream) -> io::Result<usize>,
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = match self.fd.poll_write_ready(cx) {
                Poll::Ready(g) => g?,
                Poll::Pending => {
                    self.stats.pending.fetch_add(1, Relaxed);
                    return Poll::Pending;
                }
            };
            self.stats.sys.fetch_add(1, Relaxed);
            match guard.try_io(|s| f(s.get_ref())) {
                Ok(Ok(n)) => {
                    self.stats.bytes.fetch_add(n as u64, Relaxed);
                    return Poll::Ready(Ok(n));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_) => {
                    self.stats.eagain.fetch_add(1, Relaxed);
                }
            }
        }
    }
}

impl AsyncRead for Io {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = std::task::ready!(self.fd.poll_read_ready(cx))?;
            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|s| (&*s.get_ref()).read(unfilled)) {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_) => continue,
            }
        }
    }
}

impl AsyncWrite for Io {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.stats.write.fetch_add(1, Relaxed);
        self.stats.iovs.fetch_add(1, Relaxed);
        if self.stats.null.load(Relaxed) {
            self.stats.bytes.fetch_add(buf.len() as u64, Relaxed);
            return Poll::Ready(Ok(buf.len()));
        }
        self.poll_sys(cx, |mut s| s.write(buf))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.stats.writev.fetch_add(1, Relaxed);
        self.stats.iovs.fetch_add(bufs.len() as u64, Relaxed);
        if self.stats.null.load(Relaxed) {
            let n: usize = bufs.iter().map(|b| b.len()).sum();
            self.stats.bytes.fetch_add(n as u64, Relaxed);
            return Poll::Ready(Ok(n));
        }
        self.poll_sys(cx, |mut s| s.write_vectored(bufs))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.fd.get_ref().shutdown(std::net::Shutdown::Write))
    }
}

// ===== TLS setup =====

const CERT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tokio-btls/tests/cert.pem"
);
const KEY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tokio-btls/tests/key.pem"
);

#[derive(Clone, Copy, PartialEq, Debug)]
enum Impl {
    Btls,
    Rustls,
}

enum Server {
    Btls(tokio_btls::SslStream<Io>),
    Rustls(tokio_rustls::server::TlsStream<Io>),
}

impl Server {
    fn stats(&self) -> &Stats {
        match self {
            Server::Btls(s) => &s.get_ref().stats,
            Server::Rustls(s) => &s.get_ref().0.stats,
        }
    }
    fn cipher(&self) -> String {
        match self {
            Server::Btls(s) => s
                .ssl()
                .current_cipher()
                .map(|c| c.name().to_string())
                .unwrap_or_default(),
            Server::Rustls(s) => format!(
                "{:?}",
                s.get_ref().1.negotiated_cipher_suite().map(|c| c.suite())
            ),
        }
    }
}

macro_rules! dispatch {
    ($s:expr, $x:ident => $e:expr) => {
        match $s {
            Server::Btls($x) => $e,
            Server::Rustls($x) => $e,
        }
    };
}

fn btls_acceptor() -> SslAcceptor {
    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    b.set_private_key_file(KEY, SslFiletype::PEM).unwrap();
    b.set_certificate_chain_file(CERT).unwrap();
    b.set_min_proto_version(Some(SslVersion::TLS1_3)).unwrap();
    b.build()
}

fn rustls_acceptor() -> tokio_rustls::TlsAcceptor {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites =
        vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
    let certs = CertificateDer::pem_file_iter(CERT)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_file(KEY).unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
}

fn btls_connector() -> SslConnector {
    let mut b = SslConnector::builder(SslMethod::tls()).unwrap();
    b.set_verify(SslVerifyMode::NONE);
    b.build()
}

// ===== workload =====

struct Case {
    name: &'static str,
    /// Slice lengths of one vectored message.
    shape: Vec<usize>,
    /// Plaintext to push per run.
    total: usize,
}

fn cases() -> Vec<Case> {
    const M: usize = 1 << 20;
    let mut h2 = Vec::new();
    for _ in 0..4 {
        h2.push(9);
        h2.push(16384);
    }
    vec![
        Case {
            name: "1x100B",
            shape: vec![100],
            total: 16 * M,
        },
        Case {
            name: "64x64B",
            shape: vec![64; 64],
            total: 64 * M,
        },
        Case {
            name: "512x32B",
            shape: vec![32; 512],
            total: 64 * M,
        },
        Case {
            name: "16x1KiB",
            shape: vec![1024; 16],
            total: 256 * M,
        },
        Case {
            name: "h2 4x(9B+16KiB)",
            shape: h2,
            total: 512 * M,
        },
        Case {
            name: "4x16KiB",
            shape: vec![16384; 4],
            total: 512 * M,
        },
        Case {
            name: "2x64KiB",
            shape: vec![65536; 2],
            total: 512 * M,
        },
        Case {
            name: "1x256KiB",
            shape: vec![262144],
            total: 512 * M,
        },
    ]
}

#[derive(Default, Clone, Copy)]
struct Sample {
    secs: f64,
    cpu: f64,
    rcpu: f64,
    tls_calls: u64,
    write: u64,
    writev: u64,
    sys: u64,
    eagain: u64,
    iovs: u64,
    cipher_bytes: u64,
    allocs: u64,
    faults: u64,
    plain: u64,
}

async fn write_all_vectored<W: AsyncWrite + Unpin>(
    w: &mut W,
    msg: &[&[u8]],
    calls: &mut u64,
) -> io::Result<()> {
    let mut iov: Vec<IoSlice<'_>> = msg.iter().map(|b| IoSlice::new(b)).collect();
    let mut bufs = &mut iov[..];
    while !bufs.is_empty() {
        let n = w.write_vectored(bufs).await?;
        *calls += 1;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        IoSlice::advance_slices(&mut bufs, n);
    }
    Ok(())
}

fn run_one(imp: Impl, case: &Case, null: bool) -> (Sample, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let scale: usize = std::env::var("VB_SCALE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let iters = (case.total / scale).div_ceil(case.shape.iter().sum());
    let expected = (iters * case.shape.iter().sum::<usize>()) as u64;

    let (hs_tx, hs_rx) = std::sync::mpsc::channel::<()>();
    let reader = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let tcp = TcpStream::connect(addr).await.unwrap();
            tcp.set_nodelay(true).unwrap();
            let mut cfg = btls_connector().configure().unwrap();
            cfg.set_verify_hostname(false);
            let ssl = cfg.into_ssl("localhost").unwrap();
            let mut s = tokio_btls::SslStream::new(ssl, tcp).unwrap();
            Pin::new(&mut s).connect().await.unwrap();
            hs_tx.send(()).unwrap();
            if null {
                // Hold the connection open; the server discards writes.
                let mut b = [0u8; 1];
                let _ = s.read(&mut b).await;
                return None;
            }
            let mut buf = vec![0u8; 256 * 1024];
            let mut got = 0u64;
            let c0 = thread_cpu();
            while got < expected {
                let n = s.read(&mut buf).await.unwrap();
                assert!(n > 0, "eof after {got}");
                got += n as u64;
            }
            Some((Instant::now(), (thread_cpu() - c0).as_secs_f64()))
        })
    });

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (sample, cipher) = rt.block_on(async {
        let (tcp, _) = tokio::net::TcpListener::from_std({
            listener.set_nonblocking(true).unwrap();
            listener
        })
        .unwrap()
        .accept()
        .await
        .unwrap();
        tcp.set_nodelay(true).unwrap();
        let stats = Arc::new(Stats::default());
        let io = Io::new(tcp.into_std().unwrap(), stats.clone());
        let mut server = match imp {
            Impl::Btls => {
                let ssl = Ssl::new(btls_acceptor().context()).unwrap();
                let mut s = tokio_btls::SslStream::new(ssl, io).unwrap();
                Pin::new(&mut s).accept().await.unwrap();
                Server::Btls(s)
            }
            Impl::Rustls => Server::Rustls(rustls_acceptor().accept(io).await.unwrap()),
        };
        // Make sure the reader finished its handshake before we start the clock.
        tokio::task::spawn_blocking(move || hs_rx.recv().unwrap())
            .await
            .unwrap();
        // Let session tickets etc. go out first.
        dispatch!(&mut server, s => s.flush().await.unwrap());
        let cipher = server.cipher();

        let data: Vec<Vec<u8>> = case.shape.iter().map(|&n| vec![0xa5u8; n]).collect();
        let msg: Vec<&[u8]> = data.iter().map(|v| &v[..]).collect();
        if null {
            server.stats().null.store(true, Relaxed);
        }
        server.stats().reset();
        let mut calls = 0u64;
        let a0 = allocs();
        let f0 = minflt();
        let c0 = thread_cpu();
        let t0 = Instant::now();
        for _ in 0..iters {
            dispatch!(&mut server, s => write_all_vectored(s, &msg, &mut calls).await.unwrap());
        }
        dispatch!(&mut server, s => s.flush().await.unwrap());
        let cpu = (thread_cpu() - c0).as_secs_f64();
        let wall_w = t0.elapsed();
        let a1 = allocs();
        let faults = minflt() - f0;
        let st = server.stats();
        let mut sample = Sample {
            secs: wall_w.as_secs_f64(),
            cpu,
            rcpu: 0.0,
            tls_calls: calls,
            write: st.write.load(Relaxed),
            writev: st.writev.load(Relaxed),
            sys: st.sys.load(Relaxed),
            eagain: st.eagain.load(Relaxed),
            iovs: st.iovs.load(Relaxed),
            cipher_bytes: st.bytes.load(Relaxed),
            allocs: a1 - a0,
            faults,
            plain: expected,
        };
        st.null.store(false, Relaxed);
        if null {
            dispatch!(&mut server, s => { let _ = s.shutdown().await; });
            drop(server);
            reader.join().unwrap();
        } else {
            let (end, rcpu) = tokio::task::spawn_blocking(move || reader.join().unwrap())
                .await
                .unwrap()
                .unwrap();
            sample.secs = (end - t0).as_secs_f64();
            sample.rcpu = rcpu;
            drop(server);
        }
        (sample, cipher)
    });
    (sample, cipher)
}

fn median(mut v: Vec<Sample>) -> Sample {
    v.sort_by(|a, b| a.secs.partial_cmp(&b.secs).unwrap());
    v[v.len() / 2]
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("both");
    let filter = args.get(2).cloned().unwrap_or_default();
    let runs: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3);
    let modes: &[bool] = match mode {
        "tcp" => &[false],
        "null" => &[true],
        _ => &[false, true],
    };
    println!(
        "| mode | case | impl | MiB/s | writer CPU ns/KiB | reader CPU ns/KiB | TLS calls/msg | transport calls/MiB | write/writev | iovs/writev | syscalls/MiB | EAGAIN/MiB | records/MiB | Rust allocs/MiB | writer page faults/MiB |"
    );
    println!("|---|---|---|---:|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|---:|");
    let mut printed_cipher = false;
    for &null in modes {
        for case in cases().iter().filter(|c| c.name.contains(&filter)) {
            let only = std::env::var("VB_IMPL").unwrap_or_default();
            for imp in [Impl::Btls, Impl::Rustls]
                .into_iter()
                .filter(|i| only.is_empty() || format!("{i:?}").eq_ignore_ascii_case(&only))
            {
                let mut samples = Vec::new();
                for _ in 0..runs {
                    let (s, cipher) = run_one(imp, case, null);
                    if !printed_cipher {
                        eprintln!("{imp:?} cipher: {cipher}");
                    }
                    samples.push(s);
                }
                printed_cipher = printed_cipher || imp == Impl::Rustls;
                let s = median(samples);
                let mib = s.plain as f64 / (1 << 20) as f64;
                let msg_len: usize = case.shape.iter().sum();
                let msgs = s.plain as f64 / msg_len as f64;
                let tw = (s.write + s.writev) as f64;
                // TLS 1.3 AES-GCM: 5 header + 1 inner type + 16 tag.
                let records = (s.cipher_bytes.saturating_sub(s.plain)) as f64 / 22.0;
                println!(
                    "| {} | {} | {:?} | {:.0} | {:.0} | {:.0} | {:.2} | {:.1} | {}/{} | {:.2} | {:.1} | {:.1} | {:.1} | {:.1} | {:.2} |",
                    if null { "null" } else { "tcp" },
                    case.name,
                    imp,
                    mib / s.secs,
                    s.cpu * 1e9 / (s.plain as f64 / 1024.0),
                    s.rcpu * 1e9 / (s.plain as f64 / 1024.0),
                    s.tls_calls as f64 / msgs,
                    tw / mib,
                    s.write,
                    s.writev,
                    if s.writev > 0 { (s.iovs - s.write) as f64 / s.writev as f64 } else { 0.0 },
                    s.sys as f64 / mib,
                    s.eagain as f64 / mib,
                    records / mib,
                    s.allocs as f64 / mib,
                    s.faults as f64 / mib,
                );
            }
        }
    }
}
