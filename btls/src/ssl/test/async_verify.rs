use foreign_types::ForeignTypeRef;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Wake, Waker};
use std::thread::{self, JoinHandle, Thread};

use crate::hpke::HpkeKey;
use crate::ssl::ech::SslEchKeys;
use crate::ssl::{
    Error, ErrorCode, HandshakeError, Ssl, SslContext, SslContextBuilder, SslFiletype, SslMethod,
    SslRef, SslVerifyMode,
};
use crate::x509::store::{X509Store, X509StoreBuilder};
use crate::x509::{X509VerifyError, X509VerifyResult, X509};

static ECH_CONFIG_LIST: &[u8] = include_bytes!("../../../test/echconfiglist");
static ECH_CONFIG_2: &[u8] = include_bytes!("../../../test/echconfig-2");
static ECH_KEY_2: &[u8] = include_bytes!("../../../test/echkey-2");

/// 2100-01-01, after every test certificate expires.
const Y2100: i64 = 4_102_444_800;

#[derive(Clone, Copy, Debug)]
enum Mode {
    /// BoringSSL's built-in verification.
    BuiltIn,
    /// The async verification without a task waker, on the handshake thread.
    Inline,
    /// The async verification in a job on another thread.
    Spawned,
}

/// What a handshake shows of the verification.
#[derive(Debug, PartialEq)]
struct Observed {
    client: Result<(), String>,
    verify_result: X509VerifyResult,
    /// The server's view, which includes the alert the client sent.
    server: Result<(), String>,
}

struct Scenario {
    name: &'static str,
    ctx: fn(&mut SslContextBuilder),
    ssl: fn(&mut SslRef),
    ech: bool,
    ok: bool,
}

fn store(pem: &[u8]) -> X509Store {
    let mut store = X509StoreBuilder::new().unwrap();
    store.add_cert(X509::from_pem(pem).unwrap()).unwrap();
    store.build()
}

fn trusted() -> X509Store {
    store(include_bytes!("../../../test/root-ca.pem"))
}

fn other() -> X509Store {
    store(include_bytes!("../../../test/root-ca-2.pem"))
}

fn client_ctx(setup: fn(&mut SslContextBuilder)) -> SslContext {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_verify(SslVerifyMode::PEER);
    setup(&mut ctx);
    ctx.build()
}

fn trust_root(ctx: &mut SslContextBuilder) {
    ctx.set_ca_file("test/root-ca.pem").unwrap();
}

fn reason(error: &Error) -> String {
    error
        .ssl_error()
        .and_then(|stack| stack.errors().first())
        .and_then(|error| error.reason())
        .map_or_else(|| format!("{:?}", error.code()), str::to_owned)
}

fn serve(ech: bool) -> (SocketAddr, JoinHandle<Result<(), String>>) {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_certificate_chain_file("test/cert.pem").unwrap();
    ctx.set_private_key_file("test/key.pem", SslFiletype::PEM)
        .unwrap();
    if ech {
        let key = HpkeKey::dhkem_p256_sha256(ECH_KEY_2).unwrap();
        let mut keys = SslEchKeys::builder().unwrap();
        keys.add_key(true, ECH_CONFIG_2, key).unwrap();
        ctx.set_ech_keys(&keys.build()).unwrap();
    }
    let ctx = ctx.build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let socket = listener.accept().unwrap().0;
        match Ssl::new(&ctx).unwrap().accept(socket) {
            Ok(mut stream) => {
                // The client may already be gone after a non-fatal verification failure.
                let _ = stream.write_all(&[0]);
                Ok(())
            }
            Err(HandshakeError::Failure(mid)) => Err(reason(mid.error())),
            Err(e) => panic!("unexpected server error: {e}"),
        }
    });
    (addr, server)
}

struct Unpark(Thread);

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

fn handshake(scenario: &Scenario, mode: Mode) -> Observed {
    let (addr, server) = serve(scenario.ech);
    let ctx = client_ctx(scenario.ctx);
    let mut ssl = Ssl::new(&ctx).unwrap();

    let jobs = Arc::new(AtomicUsize::new(0));
    match mode {
        Mode::BuiltIn => {}
        Mode::Inline => ssl.set_async_default_verify(|_| unreachable!("no task waker is set")),
        Mode::Spawned => {
            ssl.set_task_waker(Some(Waker::from(Arc::new(Unpark(thread::current())))));
            let jobs = jobs.clone();
            ssl.set_async_default_verify(move |job| {
                jobs.fetch_add(1, Ordering::SeqCst);
                thread::spawn(job);
            });
        }
    }
    (scenario.ssl)(&mut ssl);
    if scenario.ech {
        ssl.set_hostname("foobar.com").unwrap();
        ssl.set_ech_config_list(ECH_CONFIG_LIST).unwrap();
    }

    let mut result = ssl.connect(TcpStream::connect(addr).unwrap());
    let (client, verify_result) = loop {
        match result {
            Ok(mut stream) => {
                stream.read_exact(&mut [0]).unwrap();
                break (Ok(()), stream.ssl().verify_result());
            }
            Err(HandshakeError::WouldBlock(mid)) => {
                assert_eq!(mid.error().code(), ErrorCode::WANT_CERTIFICATE_VERIFY);
                thread::park();
                result = mid.handshake();
            }
            Err(HandshakeError::Failure(mid)) => {
                break (Err(reason(mid.error())), mid.ssl().verify_result());
            }
            Err(e) => panic!("unexpected client error: {e}"),
        }
    };
    if let Mode::Spawned = mode {
        assert_eq!(jobs.load(Ordering::SeqCst), 1, "{}", scenario.name);
    }

    Observed {
        client,
        verify_result,
        server: server.join().unwrap(),
    }
}

/// The async verification must decide exactly as the built-in one does, for every piece of
/// configuration it reproduces: a wrong store or a lost parameter shows up as a difference.
#[test]
fn matches_built_in_verification() {
    let scenarios = [
        Scenario {
            name: "trusted",
            ctx: trust_root,
            ssl: |_| {},
            ech: false,
            ok: true,
        },
        Scenario {
            name: "untrusted",
            ctx: |_| {},
            ssl: |_| {},
            ech: false,
            ok: false,
        },
        Scenario {
            name: "context verify store overrides the certificate store",
            ctx: |ctx| {
                trust_root(ctx);
                ctx.set_verify_cert_store(other()).unwrap();
            },
            ssl: |_| {},
            ech: false,
            ok: false,
        },
        Scenario {
            name: "context verify store",
            ctx: |ctx| ctx.set_verify_cert_store(trusted()).unwrap(),
            ssl: |_| {},
            ech: false,
            ok: true,
        },
        Scenario {
            name: "connection verify store",
            ctx: trust_root,
            ssl: |ssl| ssl.set_verify_cert_store(other()).unwrap(),
            ech: false,
            ok: false,
        },
        Scenario {
            name: "context switch drops the connection verify store",
            ctx: |ctx| ctx.set_verify_cert_store(other()).unwrap(),
            ssl: |ssl| {
                ssl.set_verify_cert_store(other()).unwrap();
                ssl.set_ssl_context(&client_ctx(trust_root)).unwrap();
            },
            ech: false,
            ok: true,
        },
        Scenario {
            name: "context switch takes the new context's verify store",
            ctx: trust_root,
            ssl: |ssl| {
                let ctx = client_ctx(|ctx| {
                    trust_root(ctx);
                    ctx.set_verify_cert_store(other()).unwrap();
                });
                ssl.set_ssl_context(&ctx).unwrap();
            },
            ech: false,
            ok: false,
        },
        Scenario {
            name: "hostname",
            ctx: trust_root,
            ssl: |ssl| ssl.param_mut().set_host("foobar.com").unwrap(),
            ech: false,
            ok: true,
        },
        Scenario {
            name: "hostname mismatch",
            ctx: trust_root,
            ssl: |ssl| ssl.param_mut().set_host("example.com").unwrap(),
            ech: false,
            ok: false,
        },
        Scenario {
            name: "expired",
            ctx: trust_root,
            ssl: |ssl| ssl.param_mut().set_time(Y2100),
            ech: false,
            ok: false,
        },
        Scenario {
            name: "verify mode none keeps the verify result",
            ctx: |_| {},
            ssl: |ssl| ssl.set_verify(SslVerifyMode::NONE),
            ech: false,
            ok: true,
        },
        Scenario {
            name: "rejected ECH verifies the public name",
            ctx: trust_root,
            ssl: |_| {},
            ech: true,
            ok: false,
        },
    ];

    for scenario in &scenarios {
        let built_in = handshake(scenario, Mode::BuiltIn);
        assert_eq!(built_in.client.is_ok(), scenario.ok, "{}", scenario.name);
        assert_eq!(
            handshake(scenario, Mode::Inline),
            built_in,
            "{} (inline)",
            scenario.name
        );
        assert_eq!(
            handshake(scenario, Mode::Spawned),
            built_in,
            "{} (spawned)",
            scenario.name
        );
    }

    let scenario = &scenarios[scenarios.len() - 2];
    assert_ne!(
        handshake(scenario, Mode::Spawned).verify_result,
        Err(X509VerifyError::APPLICATION_VERIFICATION)
    );
}

/// `try_set_async_default_verify` leaves alone what cannot move to another thread, and the
/// verification fails closed when such a callback shows up anyway, or when a job never runs.
#[test]
fn falls_back_or_fails_closed() {
    fn eligible(ctx: fn(&mut SslContextBuilder), ssl: fn(&mut SslRef)) -> bool {
        let ctx = client_ctx(ctx);
        let mut ssl_ = Ssl::new(&ctx).unwrap();
        ssl(&mut ssl_);
        ssl_.try_set_async_default_verify(|job| job())
    }

    assert!(eligible(|_| {}, |_| {}));
    assert!(!eligible(
        |ctx| ctx.set_verify_callback(SslVerifyMode::PEER, |ok, _| ok),
        |_| {}
    ));
    assert!(!eligible(
        |_| {},
        |ssl| ssl.set_verify_callback(SslVerifyMode::PEER, |ok, _| ok)
    ));
    assert!(!eligible(
        |ctx| ctx.set_cert_verify_callback(|ctx| ctx.verify_cert().unwrap()),
        |_| {}
    ));
    assert!(!eligible(
        |ctx| ctx.set_custom_verify_callback(SslVerifyMode::PEER, |_| Ok(())),
        |_| {}
    ));
    assert!(!eligible(
        |_| {},
        |ssl| ssl.set_custom_verify_callback(SslVerifyMode::PEER, |_| Ok(()))
    ));
    // The connection keeps the custom verify callback of the context it leaves.
    assert!(!eligible(
        |ctx| ctx.set_custom_verify_callback(SslVerifyMode::PEER, |_| Ok(())),
        |ssl| ssl.set_ssl_context(&client_ctx(|_| {})).unwrap()
    ));
    assert!(!eligible(
        |_| {},
        |ssl| unsafe { crate::ffi::SSL_set_accept_state(ssl.as_ptr()) }
    ));
    assert!(!eligible(
        |_| {},
        |ssl| assert!(ssl.try_set_async_default_verify(|job| job()))
    ));

    let fails_closed = |setup: fn(&mut SslRef)| {
        let (addr, server) = serve(false);
        let ctx = client_ctx(trust_root);
        let mut ssl = Ssl::new(&ctx).unwrap();
        setup(&mut ssl);
        let Err(HandshakeError::Failure(mid)) = ssl.connect(TcpStream::connect(addr).unwrap())
        else {
            panic!("the handshake should fail");
        };
        assert_eq!(reason(mid.error()), "CERTIFICATE_VERIFY_FAILED");
        assert_eq!(
            server.join().unwrap(),
            Err("TLSV1_ALERT_INTERNAL_ERROR".to_owned())
        );
    };
    // A verify callback set afterwards needs the handshake thread.
    fails_closed(|ssl| {
        ssl.set_async_default_verify(|job| job());
        ssl.set_verify_callback(SslVerifyMode::PEER, |ok, _| ok);
    });
    // A job dropped without running must not leave the handshake waiting.
    fails_closed(|ssl| {
        ssl.set_task_waker(Some(Waker::noop().clone()));
        ssl.set_async_default_verify(drop);
    });
}
