#![cfg(not(feature = "fips"))]

use std::ffi::{c_int, c_void, CStr};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::slice;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use foreign_types::ForeignTypeRef;

use super::server::Server;
use crate::ffi;
use crate::ssl::{
    ExtensionType, SslConnector, SslContextBuilder, SslMethod, SslOptions, SslSession,
    SslSessionCacheMode, SslSignatureAlgorithm, SslVersion,
};

type RecordHeaders = Arc<Mutex<Vec<[u8; 5]>>>;

unsafe extern "C" fn capture_record_header(
    is_write: c_int,
    _version: c_int,
    content_type: c_int,
    buf: *const c_void,
    len: usize,
    _ssl: *mut ffi::SSL,
    arg: *mut c_void,
) {
    if is_write != 1
        || content_type != ffi::SSL3_RT_HEADER
        || len != ffi::SSL3_RT_HEADER_LENGTH as usize
        || buf.is_null()
        || arg.is_null()
    {
        return;
    }

    let mut header = [0; 5];
    // SAFETY: BoringSSL documents a five-byte buffer for SSL3_RT_HEADER. The
    // callback argument points to Arc-owned storage, and each context and stream
    // using the callback is dropped before that storage leaves scope.
    header.copy_from_slice(unsafe { slice::from_raw_parts(buf.cast(), len) });
    let headers = unsafe { &*arg.cast::<Mutex<Vec<[u8; 5]>>>() };
    if let Ok(mut headers) = headers.lock() {
        headers.push(header);
    }
}

fn capture_record_headers(ctx: &mut SslContextBuilder, headers: &RecordHeaders) {
    unsafe {
        ffi::SSL_CTX_set_msg_callback(ctx.as_ptr(), Some(capture_record_header));
        ffi::SSL_CTX_set_msg_callback_arg(ctx.as_ptr(), Arc::as_ptr(headers) as *mut c_void);
    }
}

fn clear_record_headers(headers: &RecordHeaders) {
    headers.lock().unwrap().clear();
}

fn application_record_lengths(headers: &RecordHeaders) -> Vec<usize> {
    headers
        .lock()
        .unwrap()
        .iter()
        .filter(|header| header[0] == ffi::SSL3_RT_APPLICATION_DATA as u8)
        .map(|header| u16::from_be_bytes([header[3], header[4]]) as usize)
        .collect()
}

fn u16_list(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|value| u16::from_be_bytes([value[0], value[1]]))
        .collect()
}

fn length_prefixed_u16_list(extension: &[u8]) -> Vec<u16> {
    assert!(extension.len() >= 2);
    assert_eq!(
        u16::from_be_bytes([extension[0], extension[1]]) as usize,
        extension.len() - 2
    );
    u16_list(&extension[2..])
}

fn supported_group_ids(extension: &[u8]) -> Vec<u16> {
    length_prefixed_u16_list(extension)
}

fn signature_algorithm_ids(extension: &[u8]) -> Vec<u16> {
    length_prefixed_u16_list(extension)
}

fn badssl_addr(host: &str) -> Option<TcpStream> {
    let addrs = match (host, 443).to_socket_addrs() {
        Ok(addrs) => addrs,
        Err(_) => return None,
    };

    for addr in addrs {
        if let Ok(stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            return Some(stream);
        }
    }

    None
}

fn connect_badssl_with_ciphers(host: &str, cipher_list: &str, expected_ciphers: &[&str]) {
    let Some(stream) = badssl_addr(host) else {
        return;
    };

    // These public badssl endpoints intentionally require legacy ciphers that
    // 0002-boringssl-legacy-ciphers.patch restores. Keep the cipher lists fixed so
    // future patch migrations fail if any listed suite disappears.
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    connector
        .set_max_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    connector.set_cipher_list(cipher_list).unwrap();
    // Windows CI images can fail to load the system trust roots for these
    // public endpoints. This test is about the legacy ciphers restored by our
    // patch, so only Windows skips certificate verification.
    #[cfg(windows)]
    connector.set_verify(crate::ssl::SslVerifyMode::NONE);
    let connector = connector.build();

    let mut stream = connector
        .connect(host, stream)
        .unwrap_or_else(|err| panic!("{host} TLS handshake failed: {err:?}"));
    let cipher = stream.ssl().current_cipher().unwrap();
    let standard_name = cipher.standard_name().unwrap();
    assert!(
        expected_ciphers.contains(&standard_name),
        "{host} negotiated unexpected cipher {standard_name}",
    );

    let request = format!("GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    assert!(
        response.starts_with(b"HTTP/1."),
        "{host} did not return an HTTP response",
    );
}

#[test]
fn boring_pq_p256_kyber_group_can_negotiate() {
    // boring-pq.patch adds P256Kyber768Draft00. Require a real TLS 1.3
    // handshake so a future patch migration cannot keep only the constant.
    let mut server = Server::builder();
    server
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server.ctx().set_curves_list("P256Kyber768Draft00").unwrap();
    let server = server.build();

    let mut client = server.client_with_root_ca();
    client
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    client
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    client.ctx().set_curves_list("P256Kyber768Draft00").unwrap();

    let stream = client.connect();
    assert_eq!(stream.ssl().version2(), Some(SslVersion::TLS1_3));
    assert_eq!(
        stream.ssl().curve(),
        Some(ffi::SSL_GROUP_P256_KYBER768_DRAFT00 as u16),
    );
    assert_eq!(stream.ssl().curve_name(), Some("P256Kyber768Draft00"));
}

#[test]
fn boringssl_patch_ffdhe_named_groups_are_advertised() {
    let supported_groups = Arc::new(Mutex::new(None));

    // 0001-boringssl-ffdhe.patch adds ffdhe2048/ffdhe3072 as NamedGroup entries. TLS 1.2
    // DHE sessions do not expose a negotiated group id through SSL_get_curve_id,
    // so this verifies the patch-owned behavior directly: name parsing,
    // group-name lookup, and ClientHello supported_groups emission.
    let mut server = Server::builder();
    server
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    server.ctx().set_cipher_list("AES128-GCM-SHA256").unwrap();
    server.ctx().set_select_certificate_callback({
        let supported_groups = Arc::clone(&supported_groups);
        move |client_hello| {
            *supported_groups.lock().unwrap() = client_hello
                .get_extension(ExtensionType::SUPPORTED_GROUPS)
                .map(ToOwned::to_owned);
            Ok(())
        }
    });
    let server = server.build();

    let mut client = server.client_with_root_ca();
    client
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    client.ctx().set_cipher_list("AES128-GCM-SHA256").unwrap();

    for (configured_name, expected_name, expected_id) in [
        ("ffdhe2048", "dhe2048", ffi::SSL_GROUP_FFDHE2048 as u16),
        ("ffdhe3072", "dhe3072", ffi::SSL_GROUP_FFDHE3072 as u16),
    ] {
        let mut ctx = crate::ssl::SslContext::builder(crate::ssl::SslMethod::tls()).unwrap();
        ctx.set_curves_list(configured_name)
            .unwrap_or_else(|_| panic!("NamedGroup alias {configured_name} should parse"));

        let ptr = unsafe { ffi::SSL_get_curve_name(expected_id) };
        assert!(!ptr.is_null());
        assert_eq!(
            unsafe { CStr::from_ptr(ptr).to_str().unwrap() },
            expected_name,
            "{configured_name} should map to the 0001-boringssl-ffdhe.patch group name",
        );
    }

    client.ctx().set_curves_list("ffdhe2048:ffdhe3072").unwrap();
    client.connect();

    let groups = supported_group_ids(&supported_groups.lock().unwrap().clone().unwrap());
    for (configured_name, expected_id) in [
        ("ffdhe2048", ffi::SSL_GROUP_FFDHE2048 as u16),
        ("ffdhe3072", ffi::SSL_GROUP_FFDHE3072 as u16),
    ] {
        assert!(
            groups.contains(&expected_id),
            "ClientHello did not advertise 0001-boringssl-ffdhe.patch NamedGroup {configured_name}",
        );
    }
}

#[test]
fn boringssl_patch_ffdhe_named_groups_negotiate_tls13() {
    // Upstream BoringSSL does not implement these FFDHE key shares. Require
    // both sides to use each group so 0001-boringssl-ffdhe.patch must generate,
    // validate, and derive a shared secret from the RFC 7919 public values.
    for (configured_name, expected_name, expected_id) in [
        ("ffdhe2048", "dhe2048", ffi::SSL_GROUP_FFDHE2048 as u16),
        ("ffdhe3072", "dhe3072", ffi::SSL_GROUP_FFDHE3072 as u16),
    ] {
        let mut server = Server::builder();
        server
            .ctx()
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        server
            .ctx()
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        server.ctx().set_curves_list(configured_name).unwrap();
        let server = server.build();

        let mut client = server.client_with_root_ca();
        client
            .ctx()
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        client
            .ctx()
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        client.ctx().set_curves_list(configured_name).unwrap();

        let stream = client.connect();
        assert_eq!(stream.ssl().version2(), Some(SslVersion::TLS1_3));
        assert_eq!(stream.ssl().curve(), Some(expected_id));
        assert_eq!(stream.ssl().curve_name(), Some(expected_name));
    }
}

#[test]
fn boringssl_patch_no_psk_dhe_ke_omits_psk_on_resumption() {
    let session = Arc::new(Mutex::new(None));
    let extensions = Arc::new(Mutex::new(Vec::new()));

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
    unsafe { ffi::SSL_CTX_set_early_data_enabled(server.ctx().as_ptr(), 1) };
    server.ctx().set_select_certificate_callback({
        let extensions = Arc::clone(&extensions);
        move |client_hello| {
            extensions.lock().unwrap().push((
                client_hello
                    .get_extension(ExtensionType::PRE_SHARED_KEY)
                    .is_some(),
                client_hello
                    .get_extension(ExtensionType::PSK_KEY_EXCHANGE_MODES)
                    .is_some(),
                client_hello
                    .get_extension(ExtensionType::EARLY_DATA)
                    .is_some(),
            ));
            Ok(())
        }
    });
    let server = server.build();

    let mut first_client = server.client_with_root_ca();
    first_client
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    first_client
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    unsafe { ffi::SSL_CTX_set_early_data_enabled(first_client.ctx().as_ptr(), 1) };
    first_client
        .ctx()
        .set_session_cache_mode(SslSessionCacheMode::CLIENT);
    first_client.ctx().set_new_session_callback({
        let session = Arc::clone(&session);
        move |_, new_session| {
            let mut session = session.lock().unwrap();
            if session.is_none() {
                *session = Some(new_session.to_der().unwrap());
            }
        }
    });
    let first_stream = first_client.connect();
    assert!(!first_stream.ssl().session_reused());

    let session = SslSession::from_der(
        session
            .lock()
            .unwrap()
            .as_deref()
            .expect("TLS 1.3 server did not issue a session ticket"),
    )
    .unwrap();
    assert_eq!(
        unsafe { ffi::SSL_SESSION_early_data_capable(session.as_ref().as_ptr()) },
        1,
        "the resumed handshake must exercise an early-data-capable session",
    );

    let mut resumed_client = server.client_with_root_ca();
    resumed_client
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    resumed_client
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    unsafe { ffi::SSL_CTX_set_early_data_enabled(resumed_client.ctx().as_ptr(), 1) };
    resumed_client.ctx().set_options(SslOptions::NO_PSK_DHE_KE);
    let mut resumed_client = resumed_client.build().builder();
    unsafe { resumed_client.ssl().set_session(&session).unwrap() };

    let resumed_stream = resumed_client.connect();
    assert!(!resumed_stream.ssl().session_reused());
    assert_eq!(
        unsafe { ffi::SSL_in_early_data(resumed_stream.ssl().as_ptr()) },
        0
    );

    let extensions = extensions.lock().unwrap();
    assert_eq!(extensions.len(), 2);
    assert_eq!(extensions[0], (false, true, false));
    assert_eq!(extensions[1], (false, false, false));
}

#[test]
fn boringssl_patch_3des_badssl_ciphers_negotiate() {
    connect_badssl_with_ciphers(
        "3des.badssl.com",
        "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        &[
            "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        ],
    );
}

#[test]
fn boringssl_patch_dh2048_badssl_ciphers_negotiate() {
    connect_badssl_with_ciphers(
        "dh2048.badssl.com",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA:TLS_DHE_RSA_WITH_AES_256_CBC_SHA:TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        &[
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        ],
    );
}

#[test]
fn boringssl_patch_clienthello_extensions_are_sent() {
    let record_size_limit = Arc::new(Mutex::new(None));
    let delegated_credential = Arc::new(Mutex::new(None));

    // 0005-record-size-limit.patch and 0006-delegated-credentials.patch add these
    // ClientHello knobs. The expected bytes document patch-owned extension
    // encoding, not upstream BoringSSL's native extension surface.
    let mut server = Server::builder();
    server.ctx().set_select_certificate_callback({
        let record_size_limit = Arc::clone(&record_size_limit);
        let delegated_credential = Arc::clone(&delegated_credential);
        move |client_hello| {
            *record_size_limit.lock().unwrap() = client_hello
                .get_extension(ExtensionType::RECORD_SIZE_LIMIT)
                .map(ToOwned::to_owned);
            *delegated_credential.lock().unwrap() = client_hello
                .get_extension(ExtensionType::DELEGATED_CREDENTIAL)
                .map(ToOwned::to_owned);
            Ok(())
        }
    });
    let server = server.build();

    let mut client = server.client_with_root_ca();
    client
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    client
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    // The RFC minimum is 64. The existing void setter preserves compatibility
    // by clamping smaller nonzero values instead of emitting an invalid value.
    client.ctx().set_record_size_limit(1);
    client
        .ctx()
        .set_delegated_credentials("rsa_pss_rsae_sha256:ecdsa_secp256r1_sha256")
        .unwrap();

    client.connect();

    assert_eq!(
        record_size_limit.lock().unwrap().as_deref(),
        Some(&[0x00, 0x40][..]),
    );
    assert_eq!(
        delegated_credential.lock().unwrap().as_deref(),
        Some(&[0x00, 0x04, 0x08, 0x04, 0x04, 0x03][..]),
    );
}

const RECORD_SIZE_LIMIT_TEST_DATA_LEN: usize = 1600;

fn configure_record_size_limit_context(
    ctx: &mut SslContextBuilder,
    version: SslVersion,
    limit: Option<u16>,
    headers: &RecordHeaders,
) {
    ctx.set_min_proto_version(Some(version)).unwrap();
    ctx.set_max_proto_version(Some(version)).unwrap();
    if version == SslVersion::TLS1_2 {
        ctx.set_cipher_list("ECDHE-RSA-AES128-GCM-SHA256").unwrap();
    }
    if let Some(limit) = limit {
        ctx.set_record_size_limit(limit);
    }
    capture_record_headers(ctx, headers);
}

fn expected_record_lengths(
    mut remaining: usize,
    max_application_data: usize,
    record_overhead: usize,
) -> Vec<usize> {
    let mut lengths = Vec::new();
    while remaining != 0 {
        let fragment = remaining.min(max_application_data);
        lengths.push(fragment + record_overhead);
        remaining -= fragment;
    }
    lengths
}

fn assert_record_size_limit_records(
    version: SslVersion,
    client_receive_limit: Option<u16>,
    server_receive_limit: Option<u16>,
    expected_client_records: &[usize],
    expected_server_records: &[usize],
) {
    let client_headers = RecordHeaders::default();
    let server_headers = RecordHeaders::default();

    let mut server = Server::builder();
    configure_record_size_limit_context(
        server.ctx(),
        version,
        server_receive_limit,
        &server_headers,
    );
    let server_headers_for_io = server_headers.clone();
    server.io_cb(move |mut stream| {
        // Server::Builder writes a one-byte handshake sentinel first. Start the
        // measurement after it so only the test payload remains.
        clear_record_headers(&server_headers_for_io);
        let mut received = vec![0; RECORD_SIZE_LIMIT_TEST_DATA_LEN];
        stream.read_exact(&mut received).unwrap();
        assert!(received.iter().all(|&byte| byte == 0x43));
        stream
            .write_all(&vec![0x53; RECORD_SIZE_LIMIT_TEST_DATA_LEN])
            .unwrap();
    });
    let server = server.build();

    let mut client = server.client_with_root_ca();
    configure_record_size_limit_context(
        client.ctx(),
        version,
        client_receive_limit,
        &client_headers,
    );
    let mut stream = client.connect();
    clear_record_headers(&client_headers);

    stream
        .write_all(&vec![0x43; RECORD_SIZE_LIMIT_TEST_DATA_LEN])
        .unwrap();
    let mut response = vec![0; RECORD_SIZE_LIMIT_TEST_DATA_LEN];
    stream.read_exact(&mut response).unwrap();
    assert!(response.iter().all(|&byte| byte == 0x53));

    drop(stream);
    drop(server);

    assert_eq!(
        application_record_lengths(&client_headers),
        expected_client_records,
        "client records did not follow the server's receive limit",
    );
    assert_eq!(
        application_record_lengths(&server_headers),
        expected_server_records,
        "server records did not follow the client's receive limit",
    );
}

#[test]
fn record_size_limit_patch_tls12_is_asymmetric() {
    // 0005-record-size-limit.patch implements the RFC 8449 record behavior that
    // upstream BoringSSL does not provide. TLS 1.2 AES-GCM adds an 8-byte
    // explicit nonce and a 16-byte tag after applying the peer's plaintext
    // limit.
    assert_record_size_limit_records(
        SslVersion::TLS1_2,
        Some(512),
        Some(700),
        &expected_record_lengths(RECORD_SIZE_LIMIT_TEST_DATA_LEN, 700, 24),
        &expected_record_lengths(RECORD_SIZE_LIMIT_TEST_DATA_LEN, 512, 24),
    );
}

#[test]
fn record_size_limit_patch_tls13_is_asymmetric() {
    // TLS 1.3 counts the inner content type in the negotiated limit. Thus a
    // limit of N carries at most N - 1 application bytes plus that byte and the
    // 16-byte AEAD tag.
    assert_record_size_limit_records(
        SslVersion::TLS1_3,
        Some(512),
        Some(700),
        &expected_record_lengths(RECORD_SIZE_LIMIT_TEST_DATA_LEN, 699, 17),
        &expected_record_lengths(RECORD_SIZE_LIMIT_TEST_DATA_LEN, 511, 17),
    );
}

#[test]
fn record_size_limit_patch_requires_negotiation() {
    // Advertising a receive limit is not enough by itself. Both peers must
    // opt in before either direction is restricted.
    assert_record_size_limit_records(
        SslVersion::TLS1_3,
        Some(512),
        None,
        &expected_record_lengths(RECORD_SIZE_LIMIT_TEST_DATA_LEN, 16_384, 17),
        &expected_record_lengths(RECORD_SIZE_LIMIT_TEST_DATA_LEN, 16_384, 17),
    );
    assert_record_size_limit_records(
        SslVersion::TLS1_3,
        None,
        Some(512),
        &expected_record_lengths(RECORD_SIZE_LIMIT_TEST_DATA_LEN, 16_384, 17),
        &expected_record_lengths(RECORD_SIZE_LIMIT_TEST_DATA_LEN, 16_384, 17),
    );
}

#[test]
fn boringssl_patch_partial_extension_order_can_handshake() {
    // 0004-boringssl-extension-order.patch adds explicit ClientHello extension
    // ordering. Unknown and duplicate entries are ignored, and the unlisted
    // extensions are shuffled after the configured prefix.
    let server = Server::builder().build();
    let mut client = server.client_with_root_ca();
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
        .set_extension_permutation(&[
            ExtensionType::SUPPORTED_VERSIONS,
            ExtensionType::from(0xffff),
            ExtensionType::SUPPORTED_VERSIONS,
            ExtensionType::KEY_SHARE,
            ExtensionType::SUPPORTED_GROUPS,
            ExtensionType::PSK_KEY_EXCHANGE_MODES,
            ExtensionType::SIGNATURE_ALGORITHMS,
        ])
        .unwrap();

    client.connect();
}

#[test]
fn boringssl_patch_allows_duplicate_signature_algorithms() {
    let signature_algorithms = Arc::new(Mutex::new(None));

    // 0008-boringssl-sigalgs.patch removes BoringSSL's sigalgs_unique rejection.
    // Duplicate signature algorithms are a compatibility behavior from our
    // patch, not a guarantee from upstream BoringSSL's native policy.
    let mut ctx = crate::ssl::SslContext::builder(crate::ssl::SslMethod::tls()).unwrap();
    ctx.set_sigalgs_list("RSA+SHA256:RSA+SHA256")
        .expect("0008-boringssl-sigalgs.patch should allow duplicate signing algorithm prefs");

    let mut server = Server::builder();
    server.ctx().set_select_certificate_callback({
        let signature_algorithms = Arc::clone(&signature_algorithms);
        move |client_hello| {
            *signature_algorithms.lock().unwrap() = client_hello
                .get_extension(ExtensionType::SIGNATURE_ALGORITHMS)
                .map(ToOwned::to_owned);
            Ok(())
        }
    });
    let server = server.build();

    let mut client = server.client_with_root_ca();
    client
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    client
        .ctx()
        .set_verify_algorithm_prefs(&[
            SslSignatureAlgorithm::RSA_PKCS1_SHA256,
            SslSignatureAlgorithm::RSA_PKCS1_SHA256,
        ])
        .expect("0008-boringssl-sigalgs.patch should allow duplicate verify algorithm prefs");

    client.connect();

    let sigalgs = signature_algorithm_ids(&signature_algorithms.lock().unwrap().clone().unwrap());
    assert_eq!(
        sigalgs
            .iter()
            .filter(|&&sigalg| sigalg == ffi::SSL_SIGN_RSA_PKCS1_SHA256 as u16)
            .count(),
        2,
        "ClientHello did not preserve the duplicated 0008-boringssl-sigalgs.patch algorithm",
    );
}

#[test]
fn boringssl_patch_preserves_tls13_cipher_order_in_clienthello() {
    let client_ciphers = Arc::new(Mutex::new(None));

    // 0007-boringssl-cipher-preferences.patch adds preserve_tls13_cipher_list to
    // keep our configured TLS 1.3 cipher order in ClientHello instead of
    // upstream BoringSSL's native default ordering.
    let mut server = Server::builder();
    server.ctx().set_select_certificate_callback({
        let client_ciphers = Arc::clone(&client_ciphers);
        move |client_hello| {
            *client_ciphers.lock().unwrap() = Some(client_hello.ciphers().to_vec());
            Ok(())
        }
    });
    let server = server.build();

    let mut client = server.client_with_root_ca();
    client
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    client
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    client.ctx().set_preserve_tls13_cipher_list(true);
    client.ctx().set_cipher_list("CHACHA20:AES128").unwrap();

    client.connect();

    let cipher_ids = u16_list(&client_ciphers.lock().unwrap().clone().unwrap());
    let chacha = cipher_ids
        .iter()
        .position(|&cipher| cipher == 0x1303)
        .unwrap();
    let aes128 = cipher_ids
        .iter()
        .position(|&cipher| cipher == 0x1301)
        .unwrap();

    assert!(chacha < aes128);
}

#[test]
fn boring_pq_can_disable_second_keyshare() {
    let client_key_share = Arc::new(Mutex::new(None));

    // boring-pq.patch adds SSL_use_second_keyshare so our fork can suppress the
    // extra PQ keyshare; this is patch behavior, not upstream BoringSSL policy.
    let mut server = Server::builder();
    server.ctx().set_select_certificate_callback({
        let client_key_share = Arc::clone(&client_key_share);
        move |client_hello| {
            *client_key_share.lock().unwrap() = client_hello
                .get_extension(ExtensionType::KEY_SHARE)
                .map(ToOwned::to_owned);
            Ok(())
        }
    });
    let server = server.build();

    let mut client = server.client_with_root_ca().build().builder();
    unsafe {
        ffi::SSL_use_second_keyshare(client.ssl().as_ptr(), 0);
    }
    client.connect();

    let key_share = client_key_share.lock().unwrap().clone().unwrap();
    assert_eq!(
        u16::from_be_bytes([key_share[0], key_share[1]]) as usize,
        key_share.len() - 2
    );

    let mut entries = 0;
    let mut remaining = &key_share[2..];
    while !remaining.is_empty() {
        assert!(remaining.len() >= 4);
        let share_len = u16::from_be_bytes([remaining[2], remaining[3]]) as usize;
        assert!(remaining.len() >= 4 + share_len);
        entries += 1;
        remaining = &remaining[4 + share_len..];
    }

    assert_eq!(entries, 1);
}
