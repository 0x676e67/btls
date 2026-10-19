use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::ssl::{
    Ssl, SslContext, SslContextBuilder, SslFiletype, SslMethod, SslSession, SslSessionCacheMode,
    SslVerifyMode,
};
use crate::x509::store::X509StoreBuilder;
use crate::x509::X509;

#[test]
fn verify_peer_cert_chain_reverifies_resumed_sessions() {
    let mut server = SslContext::builder(SslMethod::tls()).unwrap();
    server.set_certificate_chain_file("test/cert.pem").unwrap();
    server
        .set_private_key_file("test/key.pem", SslFiletype::PEM)
        .unwrap();
    let server = server.build();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    // One context keeps ticket keys stable; rejected handshakes are expected.
    let handle = thread::spawn(move || {
        for _ in 0..5 {
            let socket = listener.accept().unwrap().0;
            if let Ok(mut stream) = Ssl::new(&server).unwrap().accept(socket) {
                stream.write_all(&[0]).unwrap();
            }
        }
    });

    let sessions = Arc::new(Mutex::new(Vec::new()));
    let verified = Arc::new(AtomicU8::new(0));
    let client = |trust: fn(&mut SslContextBuilder)| {
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        trust(&mut ctx);
        let verified = verified.clone();
        ctx.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
            verified.fetch_add(1, Ordering::SeqCst);
            Ok(ssl.verify_peer_cert_chain()?)
        });
        ctx.set_reverify_on_resume(true);
        ctx.set_session_cache_mode(SslSessionCacheMode::CLIENT);
        let sessions = sessions.clone();
        ctx.set_new_session_callback(move |_, session| sessions.lock().unwrap().push(session));
        ctx.build()
    };
    let connect = |ctx: &SslContext, host: &str, session: Option<SslSession>| {
        let mut ssl = Ssl::new(ctx).unwrap();
        ssl.param_mut().set_host(host).unwrap();
        if let Some(session) = session {
            // SAFETY: The handshake has not started. The session may target another host on
            // purpose, to show that re-verification rejects it.
            unsafe { ssl.set_session(&session).unwrap() };
        }
        let mut stream = ssl.connect(TcpStream::connect(addr).unwrap()).ok()?;
        // Reading processes the tickets sent after the handshake.
        stream.read_exact(&mut [0]).unwrap();
        Some(stream.ssl().session_reused())
    };
    let session = || sessions.lock().unwrap().pop();

    // A full handshake and a resumption both run the built-in checks.
    let ca_file = client(|ctx| ctx.set_ca_file("test/root-ca.pem").unwrap());
    assert_eq!(connect(&ca_file, "foobar.com", None), Some(false));
    assert_eq!(connect(&ca_file, "foobar.com", session()), Some(true));
    assert_eq!(verified.load(Ordering::SeqCst), 2);

    // Resuming for another host fails re-verification.
    assert_eq!(connect(&ca_file, "bogus.com", session()), None);
    assert_eq!(verified.load(Ordering::SeqCst), 3);

    // The verify store is used in place of the empty context store.
    let verify_store = client(|ctx| {
        let mut store = X509StoreBuilder::new().unwrap();
        let root = X509::from_pem(&std::fs::read("test/root-ca.pem").unwrap()).unwrap();
        store.add_cert(root).unwrap();
        ctx.set_verify_cert_store(store.build()).unwrap();
    });
    assert_eq!(connect(&verify_store, "foobar.com", None), Some(false));
    assert_eq!(connect(&client(|_| {}), "foobar.com", None), None);

    handle.join().unwrap();
}
