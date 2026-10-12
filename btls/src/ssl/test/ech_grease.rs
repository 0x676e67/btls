#![cfg(not(feature = "fips"))]

use std::ffi::c_void;
use std::num::NonZeroU16;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use foreign_types::ForeignTypeRef;

use super::server::Server;
use crate::error::ErrorStack;
use crate::ffi;
use crate::ssl::{
    EchGreaseAead, EchGreaseInfo, EchGreaseParameters, Ssl, SslContext, SslMethod, SslRef,
    SslVersion,
};

fn parameters(info: &EchGreaseInfo<'_>, payload_length: usize) -> EchGreaseParameters {
    EchGreaseParameters {
        aead: info.default_aead(),
        payload_length: NonZeroU16::new(u16::try_from(payload_length).unwrap()).unwrap(),
    }
}

#[derive(Default)]
struct Capture {
    messages: Vec<Vec<u8>>,
    enable_after_first: Option<bool>,
}

// Capture complete handshake messages, including CH2. This observes the wire
// independently of the patch's size metadata and avoids an external service.
unsafe extern "C" fn capture_message(
    write: libc::c_int,
    _: libc::c_int,
    content_type: libc::c_int,
    data: *const c_void,
    len: usize,
    ssl: *mut ffi::SSL,
    arg: *mut c_void,
) {
    if write == 1 && content_type == ffi::SSL3_RT_HANDSHAKE as libc::c_int && len >= 4 {
        let bytes = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), len) };
        if bytes[0] == ffi::SSL3_MT_CLIENT_HELLO as u8 {
            let capture = unsafe { &mut *arg.cast::<Capture>() };
            capture.messages.push(bytes.to_vec());
            if let Some(enabled) = capture.enable_after_first.take() {
                unsafe { ffi::SSL_set_enable_ech_grease(ssl, enabled.into()) };
            }
        }
    }
}

fn extensions(hello: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut offset = 4 + 2 + 32;
    offset += 1 + usize::from(hello[offset]);
    let cipher_len = usize::from(u16::from_be_bytes([hello[offset], hello[offset + 1]]));
    offset += 2 + cipher_len;
    offset += 1 + usize::from(hello[offset]);
    let ext_len = usize::from(u16::from_be_bytes([hello[offset], hello[offset + 1]]));
    offset += 2;
    assert_eq!(offset + ext_len, hello.len());
    let mut result = Vec::new();
    while offset < hello.len() {
        let kind = u16::from_be_bytes([hello[offset], hello[offset + 1]]);
        let len = usize::from(u16::from_be_bytes([hello[offset + 2], hello[offset + 3]]));
        offset += 4;
        result.push((kind, hello[offset..offset + len].to_vec()));
        offset += len;
    }
    result
}

fn handshake(configure: impl FnOnce(&mut SslRef), hrr: bool) -> Vec<Vec<u8>> {
    handshake_with_toggle(configure, hrr, None)
}

fn handshake_with_toggle(
    configure: impl FnOnce(&mut SslRef),
    hrr: bool,
    enable_after_first: Option<bool>,
) -> Vec<Vec<u8>> {
    let mut server = Server::builder();
    if hrr {
        server.ctx().set_curves_list("P-384").unwrap();
    }
    let server = server.build();
    let mut client = server.client_with_root_ca().build().builder();
    client
        .ssl()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    client.ssl().set_curves_list("X25519:P-384").unwrap();
    client.ssl().set_enable_ech_grease(true);
    configure(client.ssl());
    let mut capture = Capture {
        enable_after_first,
        ..Capture::default()
    };
    unsafe {
        ffi::SSL_set_msg_callback(client.ssl().as_ptr(), Some(capture_message));
        ffi::SSL_set_msg_callback_arg(
            client.ssl().as_ptr(),
            std::ptr::from_mut(&mut capture).cast(),
        );
    }
    let mut stream = client.connect();
    unsafe {
        ffi::SSL_set_msg_callback(stream.ssl().as_ptr(), None);
    }
    assert_eq!(stream.ssl().used_hello_retry_request(), hrr);
    assert!(stream
        .ssl_mut()
        .set_ech_grease_callback(|_, _| panic!("late callback called"))
        .is_err());
    capture.messages
}

#[test]
fn ech_callback_does_not_add_grease_after_hrr() {
    for initially_enabled in [false, true] {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&calls);
        let messages = handshake_with_toggle(
            |ssl| {
                ssl.set_enable_ech_grease(initially_enabled);
                ssl.set_ech_grease_callback(move |_, info| {
                    count.fetch_add(1, Ordering::SeqCst);
                    Ok(parameters(info, 239))
                })
                .unwrap();
            },
            true,
            Some(!initially_enabled),
        );
        assert_eq!(messages.len(), 2);
        assert_eq!(calls.load(Ordering::SeqCst), usize::from(initially_enabled));
        if initially_enabled {
            assert_eq!(ech(&messages[0]), ech(&messages[1]));
        } else {
            for message in messages {
                assert!(!extensions(&message)
                    .iter()
                    .any(|(id, _)| { *id == ffi::TLSEXT_TYPE_encrypted_client_hello as u16 }));
            }
        }
    }
}

fn ech(hello: &[u8]) -> Vec<u8> {
    extensions(hello)
        .into_iter()
        .find(|(id, _)| *id == ffi::TLSEXT_TYPE_encrypted_client_hello as u16)
        .unwrap()
        .1
}

#[test]
fn ech_callback_fixed_lengths_and_order() {
    let baseline = handshake(|_| {}, false);
    assert!([186, 218, 250, 282].contains(&ech(&baseline[0]).len()));
    for requested in [1, 239, 4096] {
        let messages = handshake(
            |ssl| {
                ssl.set_ech_grease_callback(move |_, info| Ok(parameters(info, requested)))
                    .unwrap();
            },
            false,
        );
        let extension = ech(&messages[0]);
        let payload_len = usize::from(u16::from_be_bytes([extension[40], extension[41]]));
        assert_eq!(extension.len(), payload_len + 42);
        assert_eq!(payload_len, requested);
        let ids = |hello: &[u8]| {
            extensions(hello)
                .into_iter()
                .map(|(id, _)| id)
                .filter(|id| *id != ffi::TLSEXT_TYPE_padding as u16)
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(&messages[0]), ids(&baseline[0]));
    }
}

#[test]
fn ech_policy_callback_metadata_and_hrr_reuse() {
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    let messages = handshake(
        move |ssl| {
            ssl.set_hostname("localhost").unwrap();
            ssl.set_alpn_protos(b"\x02h2").unwrap();
            ssl.set_ech_grease_callback(move |_, info| {
                count.fetch_add(1, Ordering::SeqCst);
                assert_eq!(info.server_name_length(), Some(9));
                assert!(!info.is_dtls());
                assert!(!info.is_quic());
                assert_eq!(info.psk_extension_length(), 0);
                assert_eq!(info.aead_overhead(), 16);
                assert!(info
                    .cipher_suites()
                    .chunks_exact(2)
                    .any(|id| id == [0x13, 0x01]));
                assert!(info.extensions().any(|(id, _)| {
                    id == ffi::TLSEXT_TYPE_application_layer_protocol_negotiation as u16
                }));
                assert!(!info.extensions().any(|(id, _)| [
                    ffi::TLSEXT_TYPE_padding as u16,
                    ffi::TLSEXT_TYPE_pre_shared_key as u16,
                    ffi::TLSEXT_TYPE_encrypted_client_hello as u16,
                ]
                .contains(&id)));
                let others: usize = info.extensions().map(|(_, len)| 4 + len).sum();
                // The frame budget may reserve a trailing padding extension.
                assert!(info.max_payload_length() <= usize::from(u16::MAX) - others - 46);
                // A deliberately simple size-dependent policy, not an NSS emulator.
                Ok(EchGreaseParameters {
                    aead: EchGreaseAead::CHACHA20_POLY1305,
                    ..parameters(info, info.aead_overhead() + 2 * info.extensions().len())
                })
            })
            .unwrap();
        },
        true,
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(messages.len(), 2);
    assert_eq!(ech(&messages[0]), ech(&messages[1]));
    assert_eq!(&ech(&messages[0])[3..5], &[0, 3]);
}

#[test]
fn ech_callback_selects_aead_without_changing_tls_ciphers() {
    let ciphers = |hello: &[u8]| {
        let mut offset = 4 + 2 + 32;
        offset += 1 + usize::from(hello[offset]);
        let len = usize::from(u16::from_be_bytes([hello[offset], hello[offset + 1]]));
        hello[offset + 2..offset + 2 + len].to_vec()
    };
    for aes_hw in [false, true] {
        let default_aead = if aes_hw {
            EchGreaseAead::AES_128_GCM
        } else {
            EchGreaseAead::CHACHA20_POLY1305
        };
        let baseline = handshake(|ssl| ssl.set_aes_hw_override(aes_hw), false);
        for (aead, id) in [
            (EchGreaseAead::AES_128_GCM, 1),
            (EchGreaseAead::CHACHA20_POLY1305, 3),
        ] {
            let messages = handshake(
                |ssl| {
                    ssl.set_aes_hw_override(aes_hw);
                    ssl.set_ech_grease_callback(move |_, info| {
                        assert_eq!(info.default_aead(), default_aead);
                        Ok(EchGreaseParameters {
                            aead,
                            payload_length: NonZeroU16::new(239).unwrap(),
                        })
                    })
                    .unwrap();
                },
                false,
            );
            let extension = ech(&messages[0]);
            assert_eq!(&extension[3..5], &[0, id]);
            assert_eq!(extension.len(), 239 + 42);
            assert_eq!(ciphers(&messages[0]), ciphers(&baseline[0]));
        }
    }
}

#[test]
fn ech_callback_replacement_uses_latest_length() {
    let messages = handshake(
        |ssl| {
            ssl.set_ech_grease_callback(|_, _| panic!("replaced callback called"))
                .unwrap();
            ssl.set_ech_grease_callback(|_, info| Ok(parameters(info, 239)))
                .unwrap();
        },
        false,
    );
    assert_eq!(ech(&messages[0]).len(), 281);
}

#[test]
fn ech_policy_disabled_and_tls12_do_not_call_callback() {
    for tls12 in [false, true] {
        let server = Server::builder().build();
        let mut client = server.client_with_root_ca().build().builder();
        client.ssl().set_enable_ech_grease(tls12);
        if tls12 {
            client
                .ssl()
                .set_max_proto_version(Some(SslVersion::TLS1_2))
                .unwrap();
        }
        client
            .ssl()
            .set_ech_grease_callback(|_, _| panic!("unused policy called"))
            .unwrap();
        client.connect();
    }
}

#[test]
fn ech_policy_callback_errors_fail_handshake() {
    // Zero and oversized size_t values remain covered by the native C tests.
    for failure in 0..3 {
        let mut server = Server::builder();
        server.should_error();
        let server = server.build();
        let mut client = server.client_with_root_ca().build().builder();
        client.ssl().set_enable_ech_grease(true);
        client
            .ssl()
            .set_ech_grease_callback(move |_, info| match failure {
                0 => Err(ErrorStack::internal_error_str("test sizing error")),
                1 => Ok(parameters(info, usize::from(u16::MAX))),
                _ => Ok(parameters(info, info.max_payload_length() + 1)),
            })
            .unwrap();
        let error = client.connect_err();
        let crate::ssl::HandshakeError::Failure(stream) = error else {
            panic!("expected a failed handshake");
        };
        let expected = if failure == 0 {
            ffi::SSL_R_BAD_DATA_RETURNED_BY_CALLBACK
        } else {
            ffi::SSL_R_BAD_LENGTH
        };
        assert!(stream
            .error()
            .ssl_error()
            .unwrap()
            .errors()
            .iter()
            .any(|error| error.reason_code() == expected));
    }
}

#[test]
fn ech_policy_callback_ownership() {
    let context = SslContext::builder(SslMethod::tls()).unwrap().build();
    let mut ssl = Ssl::new(&context).unwrap();
    let marker = Arc::new(());
    let install = |ssl: &mut SslRef| {
        let captured = Arc::clone(&marker);
        ssl.set_ech_grease_callback(move |_, info| {
            let _ = &captured;
            Ok(parameters(info, 239))
        })
        .unwrap();
    };
    install(&mut ssl);
    assert_eq!(Arc::strong_count(&marker), 2);
    install(&mut ssl);
    assert_eq!(Arc::strong_count(&marker), 2);
    drop(ssl);
    assert_eq!(Arc::strong_count(&marker), 1);
}

#[test]
fn ech_context_policy_and_connection_override() {
    let mut server = Server::builder();
    server.expected_connections_count(4);
    let server = server.build();
    let counts = Arc::new([
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ]);
    let index = Ssl::new_ex_index::<usize>().unwrap();
    let policy = |counter: usize| {
        let counts = Arc::clone(&counts);
        move |ssl: &SslRef, info: &EchGreaseInfo<'_>| {
            assert_eq!(ssl.ex_data(index), Some(&counter));
            assert_eq!(info.server_name_length(), Some(9));
            counts[counter].fetch_add(1, Ordering::SeqCst);
            Ok(parameters(info, 239))
        }
    };
    let mut base = server.client_with_root_ca();
    base.ctx().set_ech_grease_callback(policy(0));
    let base = base.build();
    let mut other = SslContext::builder(SslMethod::tls()).unwrap();
    other.set_ca_file("test/root-ca.pem").unwrap();
    other.set_ech_grease_callback(policy(1));
    let other = other.build();
    for selected in [0, 0, 1, 2] {
        let mut connection = base.builder();
        let ssl = connection.ssl();
        ssl.set_enable_ech_grease(true);
        ssl.set_hostname("localhost").unwrap();
        ssl.set_ex_data(index, selected);
        if selected != 0 {
            ssl.set_ssl_context(&other).unwrap();
        }
        if selected == 2 {
            ssl.set_ech_grease_callback(policy(2)).unwrap();
        }
        connection.connect();
    }
    assert_eq!(
        counts.each_ref().map(|count| count.load(Ordering::SeqCst)),
        [2, 1, 1]
    );
    drop(base);
    drop(other);
    assert_eq!(Arc::strong_count(&counts), 1);
}

#[test]
fn ech_policy_resumption_preserves_psk_binder() {
    let mut server = Server::builder();
    server.expected_connections_count(2);
    server
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    let server = server.build();
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let saved = Arc::clone(&sessions);
    let mut client = server.client_with_root_ca();
    client
        .ctx()
        .set_session_cache_mode(crate::ssl::SslSessionCacheMode::CLIENT);
    client
        .ctx()
        .set_new_session_callback(move |_, session| saved.lock().unwrap().push(session));
    let client = client.build();
    let mut first = client.builder();
    first.ssl().set_enable_ech_grease(true);
    first
        .ssl()
        .set_ech_grease_callback(|_, info| Ok(parameters(info, 239)))
        .unwrap();
    assert!(!first.connect().ssl().session_reused());
    let session = sessions.lock().unwrap().pop().unwrap();
    let called = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&called);
    let mut second = client.builder();
    // The session came from the same context, before this handshake starts.
    unsafe { second.ssl().set_session(&session).unwrap() };
    second.ssl().set_enable_ech_grease(true);
    second
        .ssl()
        .set_ech_grease_callback(move |_, info| {
            assert!(info.psk_extension_length() > 4);
            count.fetch_add(1, Ordering::SeqCst);
            Ok(parameters(info, 400))
        })
        .unwrap();
    assert!(second.connect().ssl().session_reused());
    assert_eq!(called.load(Ordering::SeqCst), 1);
}
