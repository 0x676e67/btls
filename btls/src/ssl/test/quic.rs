use std::mem;
use std::sync::{Arc, LazyLock, Mutex};

use crate::error::ErrorStack;
use crate::ex_data::Index;
use crate::ffi;
use crate::ssl::{
    AlpnError, EarlyDataReason, ErrorCode, QuicEncryptionLevel, QuicMethod, QuicMethodError, Ssl,
    SslAlert, SslCipherRef, SslContext, SslContextBuilder, SslFiletype, SslMethod, SslRef,
    SslSession, SslSessionCacheMode, SslVerifyMode, SslVersion,
};
use std::ffi::c_int;

const LEVELS: [QuicEncryptionLevel; 4] = [
    QuicEncryptionLevel::INITIAL,
    QuicEncryptionLevel::EARLY_DATA,
    QuicEncryptionLevel::HANDSHAKE,
    QuicEncryptionLevel::APPLICATION,
];

/// What BoringSSL handed a connection through its QUIC method.
#[derive(Default)]
struct Recorded {
    read_secrets: [Option<Vec<u8>>; 4],
    write_secrets: [Option<Vec<u8>>; 4],
    /// Handshake data not delivered to the peer yet.
    pending: Vec<(QuicEncryptionLevel, Vec<u8>)>,
    /// Handshake data from the peer, waiting for its level to be read.
    inbox: Vec<(QuicEncryptionLevel, Vec<u8>)>,
    alert: Option<(QuicEncryptionLevel, SslAlert)>,
    /// Makes [`QuicMethod::set_write_secret`] fail.
    fail_write_secret: bool,
}

static RECORDED: LazyLock<Index<Ssl, Recorded>> = LazyLock::new(|| Ssl::new_ex_index().unwrap());

fn recorded(ssl: &mut SslRef) -> &mut Recorded {
    ssl.ex_data_mut(*RECORDED).unwrap()
}

fn index(level: QuicEncryptionLevel) -> usize {
    LEVELS.iter().position(|&l| l == level).unwrap()
}

struct Recorder;

impl QuicMethod for Recorder {
    fn set_read_secret(
        &self,
        ssl: &mut SslRef,
        level: QuicEncryptionLevel,
        _: &SslCipherRef,
        secret: &[u8],
    ) -> Result<(), QuicMethodError> {
        recorded(ssl).read_secrets[index(level)] = Some(secret.to_vec());
        Ok(())
    }

    fn set_write_secret(
        &self,
        ssl: &mut SslRef,
        level: QuicEncryptionLevel,
        _: &SslCipherRef,
        secret: &[u8],
    ) -> Result<(), QuicMethodError> {
        let recorded = recorded(ssl);
        if recorded.fail_write_secret {
            return Err(QuicMethodError);
        }
        recorded.write_secrets[index(level)] = Some(secret.to_vec());
        Ok(())
    }

    fn add_handshake_data(
        &self,
        ssl: &mut SslRef,
        level: QuicEncryptionLevel,
        data: &[u8],
    ) -> Result<(), QuicMethodError> {
        recorded(ssl).pending.push((level, data.to_vec()));
        Ok(())
    }

    fn flush_flight(&self, _: &mut SslRef) -> Result<(), QuicMethodError> {
        Ok(())
    }

    fn send_alert(
        &self,
        ssl: &mut SslRef,
        level: QuicEncryptionLevel,
        alert: SslAlert,
    ) -> Result<(), QuicMethodError> {
        recorded(ssl).alert = Some((level, alert));
        Ok(())
    }
}

fn context(builder: &mut SslContextBuilder) {
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    builder.set_quic_method(Recorder).unwrap();
    builder.set_early_data_enabled(true);
}

fn server_builder() -> SslContextBuilder {
    let mut builder = SslContextBuilder::new(SslMethod::tls()).unwrap();
    context(&mut builder);
    builder.set_certificate_chain_file("test/cert.pem").unwrap();
    builder
        .set_private_key_file("test/key.pem", SslFiletype::PEM)
        .unwrap();
    builder
}

fn server_context() -> SslContext {
    let mut builder = server_builder();
    builder.set_alpn_select_callback(|_, _| Ok(b"h3"));
    builder.build()
}

/// A client context that keeps the sessions it receives in `sessions`.
fn client_context(sessions: Arc<Mutex<Vec<SslSession>>>) -> SslContext {
    let mut builder = SslContextBuilder::new(SslMethod::tls()).unwrap();
    context(&mut builder);
    builder.set_ca_file("test/root-ca.pem").unwrap();
    builder.set_verify(SslVerifyMode::PEER);
    builder.set_alpn_protos(b"\x02h3").unwrap();
    builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);
    builder.set_new_session_callback(move |_, session| sessions.lock().unwrap().push(session));
    builder.build()
}

fn client(ctx: &SslContext, session: Option<&SslSession>) -> Ssl {
    let mut ssl = Ssl::new(ctx).unwrap();
    ssl.set_ex_data(*RECORDED, Recorded::default());
    ssl.set_connect_state();
    ssl.set_quic_transport_params(b"client params").unwrap();
    if let Some(session) = session {
        unsafe { ssl.set_session(session).unwrap() };
    }
    ssl
}

fn server(ctx: &SslContext, early_data_context: &[u8]) -> Ssl {
    let mut ssl = Ssl::new(ctx).unwrap();
    ssl.set_ex_data(*RECORDED, Recorded::default());
    ssl.set_accept_state();
    ssl.set_quic_transport_params(b"server params").unwrap();
    ssl.set_quic_early_data_context(early_data_context).unwrap();
    ssl
}

/// Advances `ssl` on the data of its inbox, which BoringSSL only takes at the level it reads,
/// and hands what it wrote to `peer`.
fn step(ssl: &mut Ssl, peer: &mut Ssl) -> Result<(), ErrorCode> {
    let result = loop {
        let level = ssl.quic_read_level();
        let (ready, waiting): (Vec<_>, _) = mem::take(&mut recorded(ssl).inbox)
            .into_iter()
            .partition(|&(l, _)| l == level);
        recorded(ssl).inbox = waiting;
        for (_, data) in &ready {
            ssl.provide_quic_data(level, data).unwrap();
        }

        let result = if ssl.is_init_finished() {
            ssl.process_quic_post_handshake()
        } else {
            ssl.do_handshake()
        };
        match result {
            Err(e) if e != ErrorCode::WANT_READ => break Err(e),
            _ if ready.is_empty() => break Ok(()),
            _ => {}
        }
    };
    let pending = mem::take(&mut recorded(ssl).pending);
    recorded(peer).inbox.extend(pending);
    result
}

/// Runs both sides until the handshake and its session tickets are through.
fn handshake(client: &mut Ssl, server: &mut Ssl) {
    for _ in 0..8 {
        step(client, server).unwrap();
        step(server, client).unwrap();
    }
    assert!(client.is_init_finished() && server.is_init_finished());
}

fn secret(ssl: &mut Ssl, read: bool, level: QuicEncryptionLevel) -> Option<Vec<u8>> {
    let recorded = recorded(ssl);
    let secrets = if read {
        &recorded.read_secrets
    } else {
        &recorded.write_secrets
    };
    secrets[index(level)].clone()
}

/// Returns whether `errors` holds the SSL reason `reason`.
fn has_reason(errors: &ErrorStack, reason: c_int) -> bool {
    errors
        .errors()
        .iter()
        .any(|e| e.library_reason(ffi::ERR_LIB_SSL) == Some(reason))
}

#[test]
fn quic_handshake_and_early_data() {
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let client_ctx = client_context(sessions.clone());
    let server_ctx = server_context();
    let latest_session = || sessions.lock().unwrap().last().unwrap().clone();

    // A full handshake: the secrets of each level pair up, and the transport parameters cross.
    let mut c = client(&client_ctx, None);
    let mut s = server(&server_ctx, b"context");
    assert!(c.quic_max_handshake_flight_len(QuicEncryptionLevel::HANDSHAKE) > 0);
    handshake(&mut c, &mut s);
    for level in [
        QuicEncryptionLevel::HANDSHAKE,
        QuicEncryptionLevel::APPLICATION,
    ] {
        let client_write = secret(&mut c, false, level);
        assert!(client_write.is_some());
        assert_eq!(client_write, secret(&mut s, true, level));
        assert_eq!(secret(&mut c, true, level), secret(&mut s, false, level));
    }
    for ssl in [&c, &s] {
        assert_eq!(ssl.quic_read_level(), QuicEncryptionLevel::APPLICATION);
        assert_eq!(ssl.quic_write_level(), QuicEncryptionLevel::APPLICATION);
    }
    assert_eq!(c.peer_quic_transport_params(), Some(&b"server params"[..]));
    assert_eq!(s.peer_quic_transport_params(), Some(&b"client params"[..]));
    assert_eq!(c.early_data_reason(), EarlyDataReason::NO_SESSION_OFFERED);
    assert!(recorded(&mut c).alert.is_none() && recorded(&mut s).alert.is_none());
    assert!(latest_session().early_data_capable());

    // A resumption under the same context accepts 0-RTT.
    let mut c = client(&client_ctx, Some(&latest_session()));
    let mut s = server(&server_ctx, b"context");
    step(&mut c, &mut s).unwrap();
    assert!(c.in_early_data());
    let early_secret = secret(&mut c, false, QuicEncryptionLevel::EARLY_DATA);
    assert!(early_secret.is_some());
    handshake(&mut c, &mut s);
    assert_eq!(
        secret(&mut s, true, QuicEncryptionLevel::EARLY_DATA),
        early_secret
    );
    assert!(c.early_data_accepted() && s.early_data_accepted());
    assert_eq!(c.early_data_reason(), EarlyDataReason::ACCEPTED);

    // A client can turn 0-RTT off for one connection and still resume.
    let mut c = client(&client_ctx, Some(&latest_session()));
    c.set_early_data_enabled(false);
    let mut s = server(&server_ctx, b"context");
    step(&mut c, &mut s).unwrap();
    assert!(!c.in_early_data());
    handshake(&mut c, &mut s);
    assert!(c.session_reused());
    assert_eq!(c.early_data_reason(), EarlyDataReason::DISABLED);

    // A server under another context rejects 0-RTT, and the handshake goes on without it.
    let mut c = client(&client_ctx, Some(&latest_session()));
    let mut s = server(&server_ctx, b"other context");
    step(&mut c, &mut s).unwrap();
    step(&mut s, &mut c).unwrap();
    assert!(step(&mut c, &mut s) == Err(ErrorCode::EARLY_DATA_REJECTED));
    assert_eq!(c.early_data_reason(), EarlyDataReason::PEER_DECLINED);
    // Only the server knows why.
    assert_eq!(
        s.early_data_reason(),
        EarlyDataReason::QUIC_PARAMETER_MISMATCH
    );
    assert_eq!(s.early_data_reason().to_string(), "quic_parameter_mismatch");
    c.reset_early_data_reject();
    handshake(&mut c, &mut s);
    assert!(!c.early_data_accepted() && !s.early_data_accepted());

    // A server without an early data context issues sessions that do not allow 0-RTT.
    let mut c = client(&client_ctx, None);
    let mut s = server(&server_ctx, b"");
    handshake(&mut c, &mut s);
    let session = latest_session();
    assert!(!session.early_data_capable());
    let mut c = client(&client_ctx, Some(&session));
    let mut s = server(&server_ctx, b"context");
    step(&mut c, &mut s).unwrap();
    assert!(!c.in_early_data());
    handshake(&mut c, &mut s);
    assert!(c.session_reused());
    for ssl in [&c, &s] {
        assert_eq!(
            ssl.early_data_reason(),
            EarlyDataReason::UNSUPPORTED_FOR_SESSION
        );
    }
}

#[test]
fn failing_handshake() {
    let client_ctx = client_context(Arc::default());

    // A server that selects no ALPN protocol alerts at the level it writes.
    let mut builder = server_builder();
    builder.set_alpn_select_callback(|_, _| Err(AlpnError::ALERT_FATAL));
    let server_ctx = builder.build();
    let mut c = client(&client_ctx, None);
    let mut s = server(&server_ctx, b"context");
    step(&mut c, &mut s).unwrap();
    assert!(step(&mut s, &mut c) == Err(ErrorCode::SSL));
    assert!(has_reason(
        &ErrorStack::get(),
        ffi::SSL_R_NO_APPLICATION_PROTOCOL
    ));
    assert_eq!(
        recorded(&mut s).alert,
        Some((
            QuicEncryptionLevel::INITIAL,
            SslAlert::NO_APPLICATION_PROTOCOL
        ))
    );

    // A failing secret callback leaves its reason on the error queue.
    let server_ctx = server_context();
    let mut c = client(&client_ctx, None);
    let mut s = server(&server_ctx, b"context");
    recorded(&mut s).fail_write_secret = true;
    step(&mut c, &mut s).unwrap();
    assert!(step(&mut s, &mut c) == Err(ErrorCode::SSL));
    assert!(has_reason(
        &ErrorStack::get(),
        ffi::SSL_R_QUIC_INTERNAL_ERROR
    ));
}

#[test]
fn provide_quic_data_errors() {
    let client_ctx = client_context(Arc::default());
    let mut c = client(&client_ctx, None);

    let err = c
        .provide_quic_data(QuicEncryptionLevel::HANDSHAKE, b"data")
        .unwrap_err();
    assert!(has_reason(&err, ffi::SSL_R_WRONG_ENCRYPTION_LEVEL_RECEIVED));

    // The buffered data may fill the flight, but not exceed it.
    let len = c.quic_max_handshake_flight_len(QuicEncryptionLevel::INITIAL);
    c.provide_quic_data(QuicEncryptionLevel::INITIAL, &vec![0; len])
        .unwrap();
    let err = c
        .provide_quic_data(QuicEncryptionLevel::INITIAL, &[0])
        .unwrap_err();
    assert!(has_reason(&err, ffi::SSL_R_EXCESSIVE_MESSAGE_SIZE));
}

#[test]
fn alert_description() {
    assert_eq!(
        SslAlert::NO_APPLICATION_PROTOCOL.description(),
        "no application protocol"
    );
    assert_eq!(
        SslAlert::HANDSHAKE_FAILURE.description(),
        "handshake failure"
    );
}
