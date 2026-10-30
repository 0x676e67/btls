#![cfg(not(feature = "fips"))]

use std::ffi::{c_int, c_void, CStr};
use std::io::{IoSlice, Read, Write};
use std::mem::MaybeUninit;
use std::net::TcpStream;
use std::slice;
use std::sync::{Arc, Mutex};

use foreign_types::ForeignTypeRef;

use super::server::Server;
use crate::ffi;
use crate::ssl::{
    with_ivecs, ExtensionType, Sealed, SslContextBuilder, SslOptions, SslRef, SslSession,
    SslSessionCacheMode, SslSignatureAlgorithm, SslStream, SslVersion, Tls13Cipher,
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

// Extension types in wire order, parsed from the ClientHello body.
fn client_hello_extension_types(hello: &[u8]) -> Vec<ExtensionType> {
    let u16_at =
        |offset: usize| usize::from(u16::from_be_bytes([hello[offset], hello[offset + 1]]));
    let mut offset = 2 + 32;
    offset += 1 + usize::from(hello[offset]);
    offset += 2 + u16_at(offset);
    offset += 1 + usize::from(hello[offset]);
    let end = offset + 2 + u16_at(offset);
    offset += 2;
    assert_eq!(end, hello.len());
    let mut types = Vec::new();
    while offset < end {
        types.push(ExtensionType::from(u16::from_be_bytes([
            hello[offset],
            hello[offset + 1],
        ])));
        offset += 4 + u16_at(offset + 2);
    }
    types
}

#[test]
fn record_size_limit_patch_keeps_configured_extension_position() {
    // 0004-boringssl-extension-order.patch sends the listed extensions first.
    // 0005-record-size-limit.patch must keep its slot in that prefix when the
    // limit is set and drop out without disturbing its neighbours when it is
    // not.
    let order = [
        ExtensionType::SUPPORTED_VERSIONS,
        ExtensionType::RECORD_SIZE_LIMIT,
        ExtensionType::KEY_SHARE,
        ExtensionType::SUPPORTED_GROUPS,
        ExtensionType::SIGNATURE_ALGORITHMS,
    ];
    for limit in [16_385, 0] {
        let types = Arc::new(Mutex::new(Vec::new()));
        let mut server = Server::builder();
        server.ctx().set_select_certificate_callback({
            let types = Arc::clone(&types);
            move |client_hello| {
                *types.lock().unwrap() = client_hello_extension_types(client_hello.as_bytes());
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
        client.ctx().set_extension_permutation(&order).unwrap();
        client.ctx().set_record_size_limit(limit);
        client.connect();

        let expected: Vec<_> = order
            .iter()
            .copied()
            .filter(|ext| limit != 0 || *ext != ExtensionType::RECORD_SIZE_LIMIT)
            .collect();
        let types = types.lock().unwrap();
        assert_eq!(types[..expected.len()], expected[..], "limit {limit}");
        assert_eq!(
            types.contains(&ExtensionType::RECORD_SIZE_LIMIT),
            limit != 0,
            "limit {limit}"
        );
    }
}

#[test]
fn boringssl_patch_f5_padding_fills_clienthello() {
    // 0007-boringssl-f5-padding.patch keeps the RFC 7685 padding upstream
    // removed: without ML-KEM a ClientHello of 256 to 511 bytes, handshake
    // header included, is padded to 512.
    let hello = Arc::new(Mutex::new(Vec::new()));
    let mut server = Server::builder();
    server.ctx().set_select_certificate_callback({
        let hello = Arc::clone(&hello);
        move |client_hello| {
            *hello.lock().unwrap() = client_hello.as_bytes().to_vec();
            Ok(())
        }
    });
    let server = server.build();
    let mut client = server.client_with_root_ca();
    client.ctx().set_curves_list("X25519").unwrap();
    client.ctx().set_alpn_protos(b"\x02h2\x08http/1.1").unwrap();
    let client = client.build();
    let mut connection = client.builder();
    connection.ssl().set_hostname("padding.example").unwrap();
    connection.connect();

    let hello = hello.lock().unwrap();
    assert!(client_hello_extension_types(&hello).contains(&ExtensionType::PADDING));
    assert_eq!(4 + hello.len(), 512);
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

fn payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i % 251) as u8 ^ seed.wrapping_mul(97))
        .collect()
}

/// Splits `data` into slices of the lengths in `shape`.
fn slices<'a>(data: &'a [u8], shape: &[usize]) -> Vec<IoSlice<'a>> {
    let mut start = 0;
    shape
        .iter()
        .map(|&len| {
            start += len;
            IoSlice::new(&data[start - len..start])
        })
        .collect()
}

fn write_sequence(ssl: &SslRef) -> u64 {
    unsafe { ffi::SSL_get_write_sequence(ssl.as_ptr()) }
}

/// Seals into an `out_len`-byte buffer and returns the written bytes.
fn seal(
    ssl: &mut SslRef,
    bufs: &[IoSlice<'_>],
    max_in: usize,
    out_len: usize,
) -> Option<(Sealed, Vec<u8>)> {
    let mut out = vec![MaybeUninit::uninit(); out_len];
    let sealed = ssl.seal_app_data(bufs, max_in, &mut out).unwrap()?;
    assert!(sealed.written <= out_len);
    // SAFETY: `seal_app_data` initialized the first `written` bytes.
    let written = out[..sealed.written]
        .iter()
        .map(|byte| unsafe { byte.assume_init() })
        .collect();
    Some((sealed, written))
}

/// Returns the body length of each TLS 1.2 or 1.3 application data record in `out`.
fn app_data_records(mut out: &[u8]) -> Vec<usize> {
    let mut lens = Vec::new();
    while !out.is_empty() {
        assert!(out.len() >= 5, "truncated record header");
        assert_eq!(out[0], 23, "not an application data record");
        assert_eq!(out[1..3], [3, 3], "unexpected record version");
        let len = usize::from(u16::from_be_bytes([out[3], out[4]]));
        assert!(out.len() >= 5 + len, "truncated record body");
        lens.push(len);
        out = &out[5 + len..];
    }
    lens
}

/// Checks `out` holds `consumed` bytes in full records, then sends it raw.
fn check_and_send(stream: &mut SslStream<TcpStream>, consumed: usize, out: &[u8]) {
    let limits = stream.ssl().seal_app_data_limits().unwrap();
    let records = app_data_records(out);
    assert_eq!(records.len(), consumed.div_ceil(limits.max_fragment()));
    let (last, full) = records.split_last().unwrap();
    assert!(
        full.iter().all(|&len| len == records[0] && *last <= len),
        "{records:?}"
    );
    assert!(records
        .iter()
        .all(|&len| len + 5 <= limits.max_fragment() + limits.record_overhead()));
    stream.get_mut().write_all(out).unwrap();
}

#[test]
fn seal_app_data_round_trip() {
    // (version, cipher list, TLS 1.3 suites, negotiated suite). The CBC suite is restored by
    // 0002-boringssl-legacy-ciphers.patch.
    let suites: [(_, _, &[Tls13Cipher], _); 5] = [
        (
            SslVersion::TLS1_2,
            "ECDHE-RSA-AES128-GCM-SHA256",
            &[],
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        ),
        (
            SslVersion::TLS1_2,
            "ECDHE-RSA-CHACHA20-POLY1305",
            &[],
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        ),
        (
            SslVersion::TLS1_2,
            "ECDHE-RSA-AES256-SHA384",
            &[],
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        ),
        (
            SslVersion::TLS1_3,
            "",
            &[Tls13Cipher::AES_128_GCM_SHA256],
            "TLS_AES_128_GCM_SHA256",
        ),
        (
            SslVersion::TLS1_3,
            "",
            &[Tls13Cipher::CHACHA20_POLY1305_SHA256],
            "TLS_CHACHA20_POLY1305_SHA256",
        ),
    ];
    // 1×100, 512×32, 4×(9 + 16 KiB) and 100 uneven slices, the first one empty. More than 64
    // slices takes the `Vec` conversion on Windows.
    let shapes: [Vec<usize>; 4] = [
        vec![100],
        vec![32; 512],
        vec![9 + 16384; 4],
        (0..100).map(|i| i * 211 % 1000).collect(),
    ];
    let datas: Vec<Vec<u8>> = shapes
        .iter()
        .enumerate()
        .map(|(seed, shape)| payload(shape.iter().sum(), seed as u8))
        .collect();
    // Each shape is sealed in one call, then the last one again `max_in` bytes at a time.
    let mut expected: Vec<u8> = datas.concat();
    expected.extend_from_slice(datas.last().unwrap());

    for (version, cipher_list, tls13_ciphers, suite) in suites {
        let mut server = Server::builder();
        server.ctx().set_min_proto_version(Some(version)).unwrap();
        server.ctx().set_max_proto_version(Some(version)).unwrap();
        if !cipher_list.is_empty() {
            server.ctx().set_cipher_list(cipher_list).unwrap();
        }
        server.io_cb({
            let expected = expected.clone();
            move |mut stream| {
                let mut received = Vec::new();
                stream.read_to_end(&mut received).unwrap();
                assert!(received == expected, "{suite}: corrupted data");
            }
        });
        let server = server.build();

        let mut client = server.client_with_root_ca();
        client.ctx().set_min_proto_version(Some(version)).unwrap();
        client.ctx().set_max_proto_version(Some(version)).unwrap();
        client.ctx().set_tls13_ciphers(tls13_ciphers).unwrap();
        if !cipher_list.is_empty() {
            client.ctx().set_cipher_list(cipher_list).unwrap();
        }
        let mut stream = client.connect();
        let cipher = stream.ssl().current_cipher().unwrap();
        assert_eq!(cipher.standard_name(), Some(suite));

        for (shape, data) in shapes.iter().zip(&datas) {
            let bufs = slices(data, shape);
            let limits = stream.ssl().seal_app_data_limits().unwrap();
            assert_eq!(limits.pending_len(), 0, "{suite}");
            let before = write_sequence(stream.ssl());
            let out_len = limits.sealed_len(data.len()).unwrap();
            let (sealed, out) = seal(stream.ssl_mut(), &bufs, usize::MAX, out_len).unwrap();
            assert_eq!(sealed.consumed, data.len(), "{suite}");
            check_and_send(&mut stream, sealed.consumed, &out);
            let records = data.len().div_ceil(limits.max_fragment()) as u64;
            assert_eq!(write_sequence(stream.ssl()), before + records, "{suite}");
        }

        // `max_in` stops mid-slice; the rest of the slices follow in later calls.
        let data = datas.last().unwrap();
        let mut bufs = slices(data, shapes.last().unwrap());
        let mut bufs = &mut bufs[..];
        let mut left = data.len();
        while left > 0 {
            let limits = stream.ssl().seal_app_data_limits().unwrap();
            let max_in = 5000;
            let out_len = limits.sealed_len(max_in).unwrap();
            let (sealed, out) = seal(stream.ssl_mut(), bufs, max_in, out_len).unwrap();
            assert_eq!(sealed.consumed, left.min(max_in), "{suite}");
            check_and_send(&mut stream, sealed.consumed, &out);
            IoSlice::advance_slices(&mut bufs, sealed.consumed);
            left -= sealed.consumed;
        }
        stream.shutdown().unwrap();
    }
}

#[test]
fn seal_app_data_honors_peer_record_size_limit() {
    // 0011 seals records itself, so it must take the fragment that 0005 derives
    // from the peer's record_size_limit. The TLS 1.3 limit counts the content type.
    let data = payload(5000, 3);
    for (version, fragment) in [(SslVersion::TLS1_2, 1000), (SslVersion::TLS1_3, 999)] {
        let mut server = Server::builder();
        server.ctx().set_min_proto_version(Some(version)).unwrap();
        server.ctx().set_max_proto_version(Some(version)).unwrap();
        server.ctx().set_record_size_limit(1000);
        server.io_cb({
            let data = data.clone();
            move |mut stream| {
                let mut received = Vec::new();
                stream.read_to_end(&mut received).unwrap();
                assert!(received == data, "{version:?}: corrupted data");
            }
        });
        let server = server.build();

        let mut client = server.client_with_root_ca();
        client.ctx().set_min_proto_version(Some(version)).unwrap();
        client.ctx().set_max_proto_version(Some(version)).unwrap();
        client.ctx().set_record_size_limit(16385);
        let mut stream = client.connect();
        let limits = stream.ssl().seal_app_data_limits().unwrap();
        assert_eq!(limits.max_fragment(), fragment, "{version:?}");
        let out_len = limits.sealed_len(data.len()).unwrap();
        let bufs = [IoSlice::new(&data)];
        let (sealed, out) = seal(stream.ssl_mut(), &bufs, usize::MAX, out_len).unwrap();
        assert_eq!(sealed.consumed, data.len(), "{version:?}");
        check_and_send(&mut stream, sealed.consumed, &out);
        stream.shutdown().unwrap();
    }
}

#[test]
fn seal_app_data_sends_key_update_first() {
    let data = payload(20000, 1);
    let mut server = Server::builder();
    server
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server.io_cb({
        let data = data.clone();
        move |mut stream| {
            let mut received = vec![0; data.len()];
            stream.read_exact(&mut received).unwrap();
            assert!(received == data, "corrupted data");
            stream.write_all(b"reply").unwrap();
            stream.read_to_end(&mut received).unwrap();
        }
    });
    let server = server.build();
    let mut stream = server.client_with_root_ca().connect();

    assert_eq!(
        unsafe { ffi::SSL_key_update(stream.ssl().as_ptr(), ffi::SSL_KEY_UPDATE_REQUESTED) },
        1
    );
    let limits = stream.ssl().seal_app_data_limits().unwrap();
    assert!(limits.pending_len() > 0);
    let out_len = limits.sealed_len(data.len()).unwrap();
    let (sealed, out) = seal(
        stream.ssl_mut(),
        &[IoSlice::new(&data)],
        usize::MAX,
        out_len,
    )
    .unwrap();
    assert_eq!(sealed.consumed, data.len());

    // The KeyUpdate goes first, under the old key; the data starts the new key at sequence 0.
    let records = app_data_records(&out);
    assert!(records[0] + 5 <= limits.pending_len());
    assert_eq!(records.len(), 1 + 2);
    assert_eq!(write_sequence(stream.ssl()), 2);
    assert_eq!(
        stream.ssl().seal_app_data_limits().unwrap().pending_len(),
        0
    );
    stream.get_mut().write_all(&out).unwrap();

    // The reply follows the server's own KeyUpdate.
    let mut reply = [0; 5];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"reply");
    stream.shutdown().unwrap();
}

#[test]
fn seal_app_data_limits_follow_state() {
    const FRAGMENT: usize = 16384;
    let data = payload(3 * FRAGMENT + 2001, 2);
    let mut server = Server::builder();
    server.io_cb({
        let data = data.clone();
        move |mut stream| {
            let mut received = Vec::new();
            stream.read_to_end(&mut received).unwrap();
            assert!(received == data, "corrupted data");
        }
    });
    let server = server.build();
    let mut client = server.client_with_root_ca().build().builder();
    let mut scratch = [MaybeUninit::uninit(); 64];
    assert_eq!(client.ssl().seal_app_data_limits(), None);
    assert!(matches!(
        client
            .ssl()
            .seal_app_data(&[IoSlice::new(b"x")], 1, &mut scratch),
        Ok(None)
    ));

    let mut stream = client.connect();
    assert_eq!(stream.ssl().version2(), Some(SslVersion::TLS1_3));
    let limits = stream.ssl().seal_app_data_limits().unwrap();
    assert_eq!(limits.max_fragment(), FRAGMENT);
    assert_eq!(limits.pending_len(), 0);
    assert_eq!(limits.sealed_len(0), Some(0));
    assert_eq!(limits.sealed_len(usize::MAX), None);

    // One byte short of the first record declines and changes nothing.
    let before = write_sequence(stream.ssl());
    let short = limits.sealed_len(100).unwrap() - 1;
    assert!(seal(stream.ssl_mut(), &[IoSlice::new(&data[..100])], 100, short).is_none());
    assert_eq!(write_sequence(stream.ssl()), before);

    // An exact fit for three records seals three, though more input is offered.
    let out_len = limits.sealed_len(3 * FRAGMENT).unwrap();
    let (sealed, out) = seal(
        stream.ssl_mut(),
        &[IoSlice::new(&data)],
        usize::MAX,
        out_len,
    )
    .unwrap();
    assert_eq!(sealed.consumed, 3 * FRAGMENT);
    assert_eq!(sealed.written, out_len);
    check_and_send(&mut stream, sealed.consumed, &out);

    stream.ssl_mut().set_max_send_fragment(512).unwrap();
    let limits = stream.ssl().seal_app_data_limits().unwrap();
    assert_eq!(limits.max_fragment(), 512);
    let rest = &data[3 * FRAGMENT..];
    let out_len = limits.sealed_len(rest.len()).unwrap();
    let (sealed, out) = seal(stream.ssl_mut(), &[IoSlice::new(rest)], usize::MAX, out_len).unwrap();
    assert_eq!(sealed.consumed, rest.len());
    let records = app_data_records(&out);
    let overhead = records[0] - 512;
    assert_eq!(records, [512, 512, 512, 465].map(|len| len + overhead));
    check_and_send(&mut stream, sealed.consumed, &out);

    stream.shutdown().unwrap();
    assert_eq!(stream.ssl().seal_app_data_limits(), None);
    assert!(matches!(
        stream
            .ssl_mut()
            .seal_app_data(&[IoSlice::new(b"x")], 1, &mut scratch),
        Ok(None)
    ));
}

#[test]
fn io_slice_matches_crypto_ivec() {
    let data = payload(1000, 3);
    let bufs: Vec<_> = (0..100)
        .map(|i| IoSlice::new(&data[i..i + i % 7]))
        .chain([IoSlice::new(&[])])
        .collect();
    let total: usize = bufs.iter().map(|buf| buf.len()).sum();
    let half: usize = bufs[..50].iter().map(|buf| buf.len()).sum();
    // Unix passes every slice; other targets convert only the slices that cover `max_in`.
    for max_in in [usize::MAX, half, 0] {
        with_ivecs(&bufs, max_in, |ivecs| {
            assert!(ivecs.len() <= bufs.len());
            let mut covered = 0;
            for (ivec, buf) in ivecs.iter().zip(&bufs) {
                assert_eq!(ivec.in_, buf.as_ptr());
                assert_eq!(ivec.len, buf.len());
                covered += buf.len();
            }
            assert!(covered >= max_in.min(total));
        });
    }
}
