use std::io::Read;
use std::panic::{self, AssertUnwindSafe};

use super::server::Server;
use crate::ssl::{Opened, Ssl, SslContext, SslMethod, SslSessionCacheMode, SslVerifyMode};

/// Runs `f`, which must panic with a string literal, and returns that message.
fn panic_message<R>(f: impl FnOnce() -> R) -> &'static str {
    let panic = panic::catch_unwind(AssertUnwindSafe(f))
        .err()
        .expect("no panic");
    panic.downcast_ref::<&str>().copied().expect("not a str")
}

/// A client context whose session callback panics on the tickets a TLS 1.3 server sends after
/// the handshake.
fn session_panics() -> SslContext {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_session_cache_mode(SslSessionCacheMode::CLIENT);
    ctx.set_new_session_callback(|_, _| panic!("session"));
    ctx.build()
}

#[test]
fn callback_panic_resumes_in_the_caller() {
    // A panic in a verify callback fails the handshake that ran it.
    let mut server = Server::builder();
    server.should_error();
    let server = server.build();
    let mut client = server.client();
    client
        .ctx()
        .set_custom_verify_callback(SslVerifyMode::PEER, |_| panic!("verify"));
    assert_eq!(panic_message(|| client.connect_err()), "verify");

    // BoringSSL has no failure to report for the session callback, so the read that processed
    // the tickets succeeds inside it; the panic still resumes there.
    let server = Server::builder().build();
    let mut stream = Ssl::new(&session_panics())
        .unwrap()
        .connect(server.connect_tcp())
        .unwrap();
    assert_eq!(panic_message(|| stream.ssl_read(&mut [0])), "session");

    // And in `open_app_data`, when it is the call that opens a ticket's record.
    let server = Server::builder().build();
    let mut stream = Ssl::new(&session_panics())
        .unwrap()
        .connect(server.connect_tcp())
        .unwrap();
    let mut buf = vec![0; 17 * 1024];
    let mut len = 0;
    let message = panic_message(|| loop {
        len += stream.get_mut().read(&mut buf[len..]).unwrap();
        match stream.ssl_mut().open_app_data(&mut buf[..len]).unwrap() {
            Opened::Partial { .. } => {}
            opened => panic!("the session callback did not run: {opened:?}"),
        }
    });
    assert_eq!(message, "session");
}
