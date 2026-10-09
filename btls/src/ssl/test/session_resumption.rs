use super::server::Server;
use crate::asn1::Asn1Time;
use crate::bn::BigNum;
use crate::pkey::PKey;
use crate::ssl::connector::earliest_not_after;
use crate::ssl::test::MessageDigest;
use crate::ssl::ClientSession;
use crate::ssl::ConnectConfiguration;
use crate::ssl::HmacCtxRef;
use crate::ssl::SslConnector;
use crate::ssl::SslMethod;
use crate::ssl::SslRef;
use crate::ssl::SslSession;
use crate::ssl::SslSessionCacheMode;
use crate::ssl::SslVerifyError;
use crate::ssl::SslVerifyMode;
use crate::ssl::SslVersion;
use crate::ssl::TicketKeyCallbackResult;
use crate::symm::Cipher;
use crate::symm::CipherCtxRef;
use crate::x509::extension::SubjectAlternativeName;
use crate::x509::{X509Name, X509};
use std::fs;
use std::io::Read;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

static SUCCESS_ENCRYPTION_CALLED_BACK: AtomicU8 = AtomicU8::new(0);
static SUCCESS_DECRYPTION_CALLED_BACK: AtomicU8 = AtomicU8::new(0);
static NOOP_ENCRYPTION_CALLED_BACK: AtomicU8 = AtomicU8::new(0);
static NOOP_DECRYPTION_CALLED_BACK: AtomicU8 = AtomicU8::new(0);

#[test]
fn resume_session() {
    static SESSION_TICKET: OnceLock<SslSession> = OnceLock::new();
    static NST_RECIEVED_COUNT: AtomicU8 = AtomicU8::new(0);

    let mut server = Server::builder();
    server.expected_connections_count(2);
    let server = server.build();

    let mut client = server.client();
    client
        .ctx()
        .set_session_cache_mode(SslSessionCacheMode::CLIENT);
    client.ctx().set_new_session_callback(|_, session| {
        NST_RECIEVED_COUNT.fetch_add(1, Ordering::SeqCst);
        // The server sends multiple session tickets but we only care to retrieve one.
        let _ = SESSION_TICKET.set(session);
    });
    let ssl_stream = client.connect();

    assert!(!ssl_stream.ssl().session_reused());
    assert!(SESSION_TICKET.get().is_some());
    assert_eq!(NST_RECIEVED_COUNT.load(Ordering::SeqCst), 2);

    // Retrieve the session ticket
    let session_ticket = SESSION_TICKET.get().unwrap();

    // Attempt to resume the connection using the session ticket
    let client_2 = server.client();
    let mut ssl_builder = client_2.build().builder();
    unsafe { ssl_builder.ssl().set_session(session_ticket).unwrap() };
    let ssl_stream_2 = ssl_builder.connect();

    assert!(ssl_stream_2.ssl().session_reused());
}

#[test]
fn client_session_cache_apis() {
    let mut server = Server::builder();
    server.expected_connections_count(2);
    server
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    let server = server.build();

    let sessions = Arc::new(Mutex::new(Vec::new()));
    let callback_sessions = Arc::clone(&sessions);
    let verify_count = Arc::new(AtomicU8::new(0));
    let callback_verify_count = Arc::clone(&verify_count);

    let mut client = server.client();
    client
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    client
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    client
        .ctx()
        .set_session_cache_mode(SslSessionCacheMode::CLIENT | SslSessionCacheMode::NO_INTERNAL);
    let _ = client.ctx().set_session_timeout(60);
    assert_eq!(client.ctx().set_session_timeout(120), 60);
    client.ctx().set_reverify_on_resume(true);
    client
        .ctx()
        .set_custom_verify_callback(SslVerifyMode::PEER, move |_| {
            callback_verify_count.fetch_add(1, Ordering::SeqCst);
            Ok::<_, SslVerifyError>(())
        });
    client.ctx().set_new_session_callback(move |_, session| {
        callback_sessions.lock().unwrap().push(session);
    });
    let client = client.build();

    let first = client.builder().connect();
    assert!(!first.ssl().session_reused());
    assert_eq!(verify_count.load(Ordering::SeqCst), 1);

    let mut sessions = sessions.lock().unwrap();
    assert_eq!(sessions.len(), 2);
    assert!(sessions
        .iter()
        .all(|session| session.should_be_single_use()));
    let session = sessions.pop().unwrap();
    drop(sessions);
    assert!(session.should_be_single_use());
    let session_without_early_data = session.copy_without_early_data().unwrap();
    assert_eq!(
        session.to_der().unwrap(),
        session_without_early_data.to_der().unwrap()
    );

    let mut resumed = client.builder();
    // SAFETY: The session was created by this client's SSL_CTX, and the new handshake has not
    // started.
    unsafe { resumed.ssl().set_session(&session).unwrap() };
    let resumed = resumed.connect();
    assert!(resumed.ssl().session_reused());
    assert_eq!(verify_count.load(Ordering::SeqCst), 2);
}

#[test]
fn client_session_resumes_within_scope_and_domain() {
    let mut server = Server::builder();
    server.expected_connections_count(3);
    let server = server.build();

    let sessions = Arc::new(Mutex::new(Vec::new()));
    let connector = |scope: &[u8]| {
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.set_ca_file("test/root-ca.pem").unwrap();
        connector.set_session_id_context(scope).unwrap();
        let sessions = sessions.clone();
        connector.set_client_session_callback(move |_, session| {
            sessions.lock().unwrap().push(session);
        });
        connector.build()
    };
    let issue = |connector: &SslConnector, configure: fn(&mut ConnectConfiguration)| {
        let mut config = connector.configure().unwrap();
        configure(&mut config);
        let mut stream = config.connect("foobar.com", server.connect_tcp()).unwrap();
        // Reading processes the tickets sent after the handshake.
        stream.read_exact(&mut [0]).unwrap();
        sessions.lock().unwrap().drain(..).next_back().unwrap()
    };
    let offers = |connector: &SslConnector,
                  session: &ClientSession,
                  domain,
                  configure: fn(&mut ConnectConfiguration)| {
        let mut config = connector
            .configure()
            .unwrap()
            .client_session(session.clone());
        configure(&mut config);
        config.into_ssl(domain).unwrap().session().is_some()
    };

    // A shared session ID context resumes across contexts for the same domain and SNI use.
    let session = issue(&connector(b"scope"), |_| {});
    let shared = connector(b"scope");
    assert!(offers(&shared, &session, "foobar.com", |_| {}));
    assert!(offers(&shared, &session, "FOOBAR.com", |_| {}));
    assert!(!offers(&shared, &session, "bogus.com", |config| {
        config.set_verify_hostname(false)
    }));
    assert!(!offers(&shared, &session, "foobar.com", |config| {
        config.set_use_server_name_indication(false)
    }));
    assert!(!offers(
        &connector(b"other"),
        &session,
        "foobar.com",
        |_| {}
    ));
    let resumed = shared
        .configure()
        .unwrap()
        .client_session(session)
        .connect("foobar.com", server.connect_tcp())
        .unwrap();
    assert!(resumed.ssl().session_reused());

    // Without one, only the issuing context resumes, and never under stricter verification.
    let unscoped = connector(b"");
    let session = issue(&unscoped, |config| {
        config.set_verify_hostname(false);
        config.set_verify(SslVerifyMode::NONE);
    });
    assert!(offers(&unscoped, &session, "foobar.com", |config| {
        config.set_verify_hostname(false);
        config.set_verify(SslVerifyMode::NONE);
    }));
    assert!(!offers(&unscoped, &session, "foobar.com", |config| {
        config.set_verify_hostname(false)
    }));
    assert!(!offers(&unscoped, &session, "foobar.com", |config| {
        config.set_verify(SslVerifyMode::NONE)
    }));
    assert!(!offers(&connector(b""), &session, "foobar.com", |config| {
        config.set_verify_hostname(false);
        config.set_verify(SslVerifyMode::NONE);
    }));
}

#[test]
fn client_session_is_not_offered_after_its_chain_expires() {
    // A foobar.com leaf from the test root that expired a day ago.
    let day: libc::time_t = 24 * 60 * 60;
    let now: libc::time_t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .try_into()
        .unwrap();
    let key = PKey::private_key_from_pem(&fs::read("test/key.pem").unwrap()).unwrap();
    let ca = X509::from_pem(&fs::read("test/root-ca.pem").unwrap()).unwrap();
    let ca_key = PKey::private_key_from_pem(&fs::read("test/root-ca.key").unwrap()).unwrap();
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_text("CN", "foobar.com").unwrap();
    let name = name.build();
    let mut leaf = X509::builder().unwrap();
    leaf.set_version(2).unwrap();
    let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
    leaf.set_serial_number(&serial).unwrap();
    leaf.set_subject_name(&name).unwrap();
    leaf.set_issuer_name(ca.subject_name()).unwrap();
    leaf.set_pubkey(&key).unwrap();
    leaf.set_not_before(&Asn1Time::from_unix(now - 2 * day).unwrap())
        .unwrap();
    leaf.set_not_after(&Asn1Time::from_unix(now - day).unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .dns("foobar.com")
        .build(&leaf.x509v3_context(Some(&ca), None))
        .unwrap();
    leaf.append_extension(&san).unwrap();
    leaf.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let leaf = leaf.build();

    let mut server = Server::builder();
    server.ctx().set_certificate(&leaf).unwrap();
    let server = server.build();

    let sessions = Arc::new(Mutex::new(Vec::new()));
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file("test/root-ca.pem").unwrap();
    let issued = sessions.clone();
    connector.set_client_session_callback(move |_, session| issued.lock().unwrap().push(session));
    let connector = connector.build();

    // Verified as of a time inside the validity period.
    let mut config = connector.configure().unwrap();
    config.param_mut().set_time(now - day - day / 2);
    let mut stream = config.connect("foobar.com", server.connect_tcp()).unwrap();
    stream.read_exact(&mut [0]).unwrap();
    let session = sessions.lock().unwrap().pop().unwrap();
    let not_after = session.session().peer_chain_not_after();
    assert!(not_after.is_some());
    assert_eq!(not_after, earliest_not_after([&*leaf]));

    let offers = |configure: fn(&mut ConnectConfiguration)| {
        let mut config = connector
            .configure()
            .unwrap()
            .client_session(session.clone());
        configure(&mut config);
        config.into_ssl("foobar.com").unwrap().session().is_some()
    };
    assert!(!offers(|_| {}));
    assert!(offers(|config| config.set_verify(SslVerifyMode::NONE)));
}

#[test]
fn custom_callback_success() {
    static SESSION_TICKET: OnceLock<SslSession> = OnceLock::new();
    static NST_RECIEVED_COUNT: AtomicU8 = AtomicU8::new(0);

    let mut server = Server::builder();
    server.expected_connections_count(2);
    unsafe {
        server
            .ctx()
            .set_ticket_key_callback(test_success_tickey_key_callback);
    };
    let server = server.build();

    let mut client = server.client();
    client
        .ctx()
        .set_session_cache_mode(SslSessionCacheMode::CLIENT);
    client.ctx().set_new_session_callback(|_, session| {
        NST_RECIEVED_COUNT.fetch_add(1, Ordering::SeqCst);
        // The server sends multiple session tickets but we only care to retrieve one.
        let _ = SESSION_TICKET.set(session);
    });
    let ssl_stream = client.connect();

    assert!(!ssl_stream.ssl().session_reused());
    assert!(SESSION_TICKET.get().is_some());
    assert_eq!(SUCCESS_ENCRYPTION_CALLED_BACK.load(Ordering::SeqCst), 2);
    assert_eq!(SUCCESS_DECRYPTION_CALLED_BACK.load(Ordering::SeqCst), 0);
    assert_eq!(NST_RECIEVED_COUNT.load(Ordering::SeqCst), 2);

    // Retrieve the session ticket
    let session_ticket = SESSION_TICKET.get().unwrap();

    // Attempt to resume the connection using the session ticket
    let client_2 = server.client();
    let mut ssl_builder = client_2.build().builder();
    unsafe { ssl_builder.ssl().set_session(session_ticket).unwrap() };
    let ssl_stream_2 = ssl_builder.connect();

    assert!(ssl_stream_2.ssl().session_reused());
    assert_eq!(SUCCESS_ENCRYPTION_CALLED_BACK.load(Ordering::SeqCst), 4);
    assert_eq!(SUCCESS_DECRYPTION_CALLED_BACK.load(Ordering::SeqCst), 1);
}

#[test]
fn custom_callback_unrecognized_decryption_ticket() {
    static SESSION_TICKET: OnceLock<SslSession> = OnceLock::new();
    static NST_RECIEVED_COUNT: AtomicU8 = AtomicU8::new(0);

    let mut server = Server::builder();
    server.expected_connections_count(2);
    unsafe {
        server
            .ctx()
            .set_ticket_key_callback(test_noop_tickey_key_callback);
    };
    let server = server.build();

    let mut client = server.client();
    client
        .ctx()
        .set_session_cache_mode(SslSessionCacheMode::CLIENT);
    client.ctx().set_new_session_callback(|_, session| {
        NST_RECIEVED_COUNT.fetch_add(1, Ordering::SeqCst);
        // The server sends multiple session tickets but we only care to retrieve one.
        let _ = SESSION_TICKET.set(session);
    });
    let ssl_stream = client.connect();

    assert!(!ssl_stream.ssl().session_reused());
    assert!(SESSION_TICKET.get().is_some());
    assert_eq!(NOOP_ENCRYPTION_CALLED_BACK.load(Ordering::SeqCst), 2);
    assert_eq!(NOOP_DECRYPTION_CALLED_BACK.load(Ordering::SeqCst), 0);
    assert_eq!(NST_RECIEVED_COUNT.load(Ordering::SeqCst), 2);

    // Retrieve the session ticket
    let session_ticket = SESSION_TICKET.get().unwrap();

    // Attempt to resume the connection using the session ticket
    let client_2 = server.client();
    let mut ssl_builder = client_2.build().builder();
    unsafe { ssl_builder.ssl().set_session(session_ticket).unwrap() };
    let ssl_stream_2 = ssl_builder.connect();

    // Second connection was NOT resumed due to TicketKeyCallbackResult::Noop on decryption
    assert!(!ssl_stream_2.ssl().session_reused());
    assert_eq!(NOOP_ENCRYPTION_CALLED_BACK.load(Ordering::SeqCst), 4);
    assert_eq!(NOOP_DECRYPTION_CALLED_BACK.load(Ordering::SeqCst), 1);
}

// Successfully return a session ticket in encryption mode but return a
// TicketKeyCallbackResult::Noop in decryption mode.
fn test_noop_tickey_key_callback(
    _ssl: &SslRef,
    key_name: &mut [u8; 16],
    iv: &mut [u8; ffi::EVP_MAX_IV_LENGTH as usize],
    evp_ctx: &mut CipherCtxRef,
    hmac_ctx: &mut HmacCtxRef,
    encrypt: bool,
) -> TicketKeyCallbackResult {
    // These should only be used for testing purposes.
    const TEST_KEY_NAME: [u8; 16] = [5; 16];
    const TEST_CBC_IV: [u8; ffi::EVP_MAX_IV_LENGTH as usize] = [1; ffi::EVP_MAX_IV_LENGTH as usize];
    const TEST_AES_128_CBC_KEY: [u8; 16] = [2; 16];
    const TEST_HMAC_KEY: [u8; 32] = [3; 32];

    let digest = MessageDigest::sha256();
    let cipher = Cipher::aes_128_cbc();

    if encrypt {
        NOOP_ENCRYPTION_CALLED_BACK.fetch_add(1, Ordering::SeqCst);

        // Ensure key_name and iv are initialized and set test values.
        assert_eq!(key_name, &[0; 16]);
        assert_eq!(iv, &[0; 16]);
        key_name.copy_from_slice(&TEST_KEY_NAME);
        iv.copy_from_slice(&TEST_CBC_IV);

        // Set the encryption context.
        evp_ctx
            .init_encrypt(&cipher, &TEST_AES_128_CBC_KEY, &TEST_CBC_IV)
            .unwrap();

        // Set the hmac context.
        hmac_ctx.init(&TEST_HMAC_KEY, &digest).unwrap();

        TicketKeyCallbackResult::Success
    } else {
        NOOP_DECRYPTION_CALLED_BACK.fetch_add(1, Ordering::SeqCst);

        // Check key_name matches.
        assert_eq!(key_name, &TEST_KEY_NAME);

        TicketKeyCallbackResult::Noop
    }
}

// Custom callback to encrypt and decrypt session tickets
fn test_success_tickey_key_callback(
    _ssl: &SslRef,
    key_name: &mut [u8; 16],
    iv: &mut [u8; ffi::EVP_MAX_IV_LENGTH as usize],
    evp_ctx: &mut CipherCtxRef,
    hmac_ctx: &mut HmacCtxRef,
    encrypt: bool,
) -> TicketKeyCallbackResult {
    // These should only be used for testing purposes.
    const TEST_KEY_NAME: [u8; 16] = [5; 16];
    const TEST_CBC_IV: [u8; ffi::EVP_MAX_IV_LENGTH as usize] = [1; ffi::EVP_MAX_IV_LENGTH as usize];
    const TEST_AES_128_CBC_KEY: [u8; 16] = [2; 16];
    const TEST_HMAC_KEY: [u8; 32] = [3; 32];

    let digest = MessageDigest::sha256();
    let cipher = Cipher::aes_128_cbc();

    if encrypt {
        SUCCESS_ENCRYPTION_CALLED_BACK.fetch_add(1, Ordering::SeqCst);

        // Ensure key_name and iv are initialized and set test values.
        assert_eq!(key_name, &[0; 16]);
        assert_eq!(iv, &[0; 16]);
        key_name.copy_from_slice(&TEST_KEY_NAME);
        iv.copy_from_slice(&TEST_CBC_IV);

        // Set the encryption context.
        evp_ctx
            .init_encrypt(&cipher, &TEST_AES_128_CBC_KEY, &TEST_CBC_IV)
            .unwrap();

        // Set the hmac context.
        hmac_ctx.init(&TEST_HMAC_KEY, &digest).unwrap();
    } else {
        SUCCESS_DECRYPTION_CALLED_BACK.fetch_add(1, Ordering::SeqCst);

        // Check key_name matches.
        assert_eq!(key_name, &TEST_KEY_NAME);

        // Set the decryption context.
        evp_ctx
            .init_decrypt(&cipher, &TEST_AES_128_CBC_KEY, iv)
            .unwrap();

        // Set the hmac context.
        hmac_ctx.init(&TEST_HMAC_KEY, &digest).unwrap();
    }

    TicketKeyCallbackResult::Success
}
