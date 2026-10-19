#![cfg(not(feature = "fips"))]

use std::ffi::c_void;
use std::num::NonZeroU16;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use foreign_types::ForeignTypeRef;

use super::server::{ClientSslBuilder, Server};
use crate::error::ErrorStack;
use crate::ffi;
use crate::ssl::{
    EchGreaseAead, EchGreaseInfo, EchGreaseParameters, Ssl, SslContext, SslMethod, SslRef,
    SslVerifyMode, SslVersion,
};

const TLS_EXTENSION_HEADER_LEN: usize = 4;
// Outer type and KDF ID.
const ECH_AEAD_OFFSET: usize = 1 + 2;
// Outer type, KDF, AEAD, config ID and enc length.
const ECH_ENC_OFFSET: usize = 1 + 2 + 2 + 1 + 2;
// Outer type, KDF, AEAD, config ID, enc length, and X25519 encapsulated key.
const ECH_PAYLOAD_LENGTH_OFFSET: usize = 1 + 2 + 2 + 1 + 2 + 32;
const ECH_BODY_FRAMING_LEN: usize = ECH_PAYLOAD_LENGTH_OFFSET + 2;
const DEFAULT_PAYLOAD_LENGTHS: [usize; 4] = [144, 176, 208, 240];

fn parameters(info: &EchGreaseInfo<'_>, payload_length: usize) -> EchGreaseParameters {
    EchGreaseParameters {
        aead: info.default_aead(),
        payload_length: NonZeroU16::new(u16::try_from(payload_length).unwrap()).unwrap(),
        random_enc: false,
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
    let messages = connect_and_capture(client, enable_after_first);
    assert_eq!(messages.len(), if hrr { 2 } else { 1 });
    messages
}

fn connect_and_capture(
    mut client: ClientSslBuilder,
    enable_after_first: Option<bool>,
) -> Vec<Vec<u8>> {
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
    assert_eq!(
        stream.ssl().used_hello_retry_request(),
        capture.messages.len() == 2
    );
    assert!(stream
        .ssl_mut()
        .set_ech_grease_callback(|_, _| panic!("late callback called"))
        .is_err());
    assert!(stream.ssl_mut().clear_ech_grease_callback().is_err());
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
    assert!(DEFAULT_PAYLOAD_LENGTHS.contains(&(ech(&baseline[0]).len() - ECH_BODY_FRAMING_LEN)));
    for requested in [1, 239, 4096] {
        let reported = Arc::new(AtomicUsize::new(0));
        let message_length = Arc::clone(&reported);
        let messages = handshake(
            |ssl| {
                ssl.set_ech_grease_callback(move |_, info| {
                    // No hostname was configured, so no SNI is reported.
                    assert_eq!(info.server_name_length(), None);
                    message_length.store(info.message_length(), Ordering::SeqCst);
                    Ok(parameters(info, requested))
                })
                .unwrap();
            },
            false,
        );
        // The message is message_length + payload + header, except that RFC 7685
        // pads 256 to 511 bytes to 512, or up to 516 when fewer than five bytes
        // remain for the padding extension.
        let expected = reported.load(Ordering::SeqCst) + requested + 4;
        if (0x100..0x200).contains(&expected) {
            assert!((0x200..=0x204).contains(&messages[0].len()));
        } else {
            assert_eq!(messages[0].len(), expected);
        }
        let extension = ech(&messages[0]);
        let payload_len = usize::from(u16::from_be_bytes([
            extension[ECH_PAYLOAD_LENGTH_OFFSET],
            extension[ECH_PAYLOAD_LENGTH_OFFSET + 1],
        ]));
        assert_eq!(extension.len(), payload_len + ECH_BODY_FRAMING_LEN);
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
                let others: usize = info
                    .extensions()
                    .map(|(_, len)| TLS_EXTENSION_HEADER_LEN + len)
                    .sum();
                // The frame budget may reserve a trailing padding extension.
                assert!(
                    info.max_payload_length()
                        <= usize::from(u16::MAX)
                            - others
                            - TLS_EXTENSION_HEADER_LEN
                            - ECH_BODY_FRAMING_LEN
                );
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
    assert_eq!(
        &ech(&messages[0])[ECH_AEAD_OFFSET..ECH_AEAD_OFFSET + 2],
        &[0, 3]
    );
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
                            random_enc: false,
                        })
                    })
                    .unwrap();
                },
                false,
            );
            let extension = ech(&messages[0]);
            assert_eq!(&extension[ECH_AEAD_OFFSET..ECH_AEAD_OFFSET + 2], &[0, id]);
            assert_eq!(extension.len(), 239 + ECH_BODY_FRAMING_LEN);
            assert_eq!(ciphers(&messages[0]), ciphers(&baseline[0]));
        }
    }
}

// A canonical X25519 public key always has bit 255 clear; NSS sends random
// bytes, so the opt-in must set that bit in about half of the hellos.
#[test]
fn ech_callback_random_enc_sets_high_bit() {
    const ROUNDS: usize = 64;
    for random_enc in [false, true] {
        let mut server = Server::builder();
        server.expected_connections_count(ROUNDS);
        let server = server.build();
        let mut high_bits = 0;
        for _ in 0..ROUNDS {
            let mut client = server.client_with_root_ca().build().builder();
            client.ssl().set_enable_ech_grease(true);
            client
                .ssl()
                .set_ech_grease_callback(move |_, info| {
                    Ok(EchGreaseParameters {
                        random_enc,
                        ..parameters(info, 239)
                    })
                })
                .unwrap();
            let messages = connect_and_capture(client, None);
            let extension = ech(&messages[0]);
            assert_eq!(extension.len(), 239 + ECH_BODY_FRAMING_LEN);
            high_bits += usize::from(extension[ECH_ENC_OFFSET + 31] & 0x80 != 0);
        }
        if random_enc {
            // Seeing only one bit value has probability 2^-63.
            assert!(
                high_bits > 0 && high_bits < ROUNDS,
                "high_bits = {high_bits}"
            );
        } else {
            assert_eq!(high_bits, 0);
        }
    }
}

#[test]
fn ech_callback_random_enc_is_reused_after_hrr() {
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    let messages = handshake(
        move |ssl| {
            ssl.set_ech_grease_callback(move |_, info| {
                count.fetch_add(1, Ordering::SeqCst);
                Ok(EchGreaseParameters {
                    random_enc: true,
                    ..parameters(info, 239)
                })
            })
            .unwrap();
        },
        true,
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(ech(&messages[0]).len(), 239 + ECH_BODY_FRAMING_LEN);
    // Reuse enc and the payload: https://www.rfc-editor.org/rfc/rfc9849#section-6.2.1
    assert_eq!(ech(&messages[0]), ech(&messages[1]));
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
    assert_eq!(ech(&messages[0]).len(), 239 + ECH_BODY_FRAMING_LEN);
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
    for failure in 0..2 {
        let mut server = Server::builder();
        server.should_error();
        let server = server.build();
        let mut client = server.client_with_root_ca().build().builder();
        client.ssl().set_enable_ech_grease(true);
        client
            .ssl()
            .set_ech_grease_callback(move |_, info| match failure {
                0 => Err(ErrorStack::internal_error_str("test sizing error")),
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
            .any(|error| error.library_reason(ffi::ERR_LIB_SSL) == Some(expected)));
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
    // A closure of another type takes over without freeing the earlier one.
    let other = Arc::new(());
    let captured = Arc::clone(&other);
    ssl.set_ech_grease_callback(move |_, info| {
        let _ = &captured;
        Ok(parameters(info, 240))
    })
    .unwrap();
    assert_eq!(Arc::strong_count(&marker), 2);
    assert_eq!(Arc::strong_count(&other), 2);
    ssl.clear_ech_grease_callback().unwrap();
    assert_eq!(Arc::strong_count(&marker), 2);
    assert_eq!(Arc::strong_count(&other), 2);
    drop(ssl);
    assert_eq!(Arc::strong_count(&marker), 1);
    assert_eq!(Arc::strong_count(&other), 1);
}

#[test]
fn ech_policy_clear_restores_context_or_default() {
    for clear_context in [false, true] {
        for clear_connection in [false, true] {
            let server = Server::builder().build();
            let calls = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
            let policy = |index: usize, length| {
                let calls = Arc::clone(&calls);
                move |_: &SslRef, info: &EchGreaseInfo<'_>| {
                    calls[index].fetch_add(1, Ordering::SeqCst);
                    Ok(parameters(info, length))
                }
            };
            let mut client = server.client_with_root_ca();
            client.ctx().set_ech_grease_callback(policy(0, 239));
            if clear_context {
                client.ctx().clear_ech_grease_callback();
            }
            let client = client.build();
            let mut connection = client.builder();
            connection.ssl().set_enable_ech_grease(true);
            connection
                .ssl()
                .set_ech_grease_callback(policy(1, 400))
                .unwrap();
            if clear_connection {
                connection.ssl().clear_ech_grease_callback().unwrap();
                connection.ssl().clear_ech_grease_callback().unwrap();
            }
            let messages = connect_and_capture(connection, None);
            let length = ech(&messages[0]).len() - ECH_BODY_FRAMING_LEN;
            if !clear_connection {
                assert_eq!(length, 400);
            } else if !clear_context {
                assert_eq!(length, 239);
            } else {
                assert!(DEFAULT_PAYLOAD_LENGTHS.contains(&length));
            }
            assert_eq!(
                calls[0].load(Ordering::SeqCst),
                usize::from(clear_connection && !clear_context)
            );
            assert_eq!(
                calls[1].load(Ordering::SeqCst),
                usize::from(!clear_connection)
            );
            drop(client);
            assert_eq!(Arc::strong_count(&calls), 1);
        }
    }
}

#[test]
fn ech_policy_cannot_change_during_certificate_verification() {
    let calls = Arc::new(AtomicUsize::new(0));
    let verified = Arc::new(AtomicUsize::new(0));
    let messages = handshake(
        |ssl| {
            let calls = Arc::clone(&calls);
            ssl.set_ech_grease_callback(move |_, info| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(parameters(info, 239))
            })
            .unwrap();
            let verified = Arc::clone(&verified);
            ssl.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
                // The handshake state still exists here; this hits the policy lock.
                assert!(!ssl.is_init_finished());
                let replacement = ssl
                    .set_ech_grease_callback(|_, _| panic!("locked callback replaced"))
                    .unwrap_err();
                let clear = ssl.clear_ech_grease_callback().unwrap_err();
                for error in [replacement, clear] {
                    assert!(error.errors().iter().any(|error| {
                        error.library_reason(ffi::ERR_LIB_SSL)
                            == Some(ffi::ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED)
                    }));
                }
                verified.fetch_add(1, Ordering::SeqCst);
                Ok(())
            });
        },
        false,
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(verified.load(Ordering::SeqCst), 1);
    assert_eq!(ech(&messages[0]).len(), 239 + ECH_BODY_FRAMING_LEN);
}

#[test]
fn ech_metadata_includes_grease_in_wire_order() {
    let server = Server::builder().build();
    let metadata = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&metadata);
    let mut client = server.client_with_root_ca();
    client.ctx().set_grease_enabled(true);
    client.ctx().set_permute_extensions(true);
    client.ctx().set_ech_grease_callback(move |_, info| {
        *observed.lock().unwrap() = info.extensions().collect();
        Ok(parameters(info, 239))
    });
    let mut client = client.build().builder();
    client.ssl().set_enable_ech_grease(true);
    let messages = connect_and_capture(client, None);
    let wire: Vec<_> = extensions(&messages[0])
        .into_iter()
        .filter(|(id, _)| {
            ![
                ffi::TLSEXT_TYPE_encrypted_client_hello as u16,
                ffi::TLSEXT_TYPE_padding as u16,
                ffi::TLSEXT_TYPE_pre_shared_key as u16,
            ]
            .contains(id)
        })
        .map(|(id, body)| (id, body.len()))
        .collect();
    assert_eq!(*metadata.lock().unwrap(), wire);
    // RFC 8701's reserved extension IDs have equal bytes with low nibble 0xa.
    assert_eq!(
        wire.iter()
            .filter(|(id, _)| id & 0x0f0f == 0x0a0a && id >> 8 == id & 0xff)
            .count(),
        2
    );
}

// A synthetic view for exercising the NSS rule without a handshake.
struct NssVector {
    cipher_suites: Vec<u8>,
    extensions: Vec<ffi::SSL_ECH_GREASE_EXTENSION>,
    server_name_length: Option<usize>,
    psk_extension_length: usize,
}

impl NssVector {
    fn info(&self) -> ffi::SSL_ECH_GREASE_SIZE_INFO {
        ffi::SSL_ECH_GREASE_SIZE_INFO {
            ssl: std::ptr::null(),
            cipher_suites: self.cipher_suites.as_ptr(),
            cipher_suites_length: self.cipher_suites.len(),
            extensions: self.extensions.as_ptr(),
            num_extensions: self.extensions.len(),
            preamble_length: 0,
            psk_extension_length: self.psk_extension_length,
            server_name_length: self.server_name_length.unwrap_or(0),
            has_server_name: self.server_name_length.is_some().into(),
            is_dtls: 0,
            is_quic: 0,
            default_aead_id: ffi::EVP_HPKE_AES_128_GCM as u16,
            aead_overhead: 16,
            max_payload_length: 4096,
            message_length: 0,
        }
    }
}

fn ext(type_: u16, length: usize) -> ffi::SSL_ECH_GREASE_EXTENSION {
    ffi::SSL_ECH_GREASE_EXTENSION { type_, length }
}

// Synthetic Firefox-shaped TCP metadata, not a captured ClientHello. Only the
// suite count, extension types and server_name length affect the rule; other
// body lengths are representative. 15 cipher suites, then server_name,
// extended_master_secret, renegotiation_info, supported_groups,
// ec_point_formats, session_ticket, ALPN, status_request,
// delegated_credentials, signed_certificate_timestamp, key_share,
// supported_versions, signature_algorithms, psk_key_exchange_modes,
// record_size_limit and compress_certificate.
fn firefox_tcp(host_len: usize) -> NssVector {
    NssVector {
        cipher_suites: vec![0; 30],
        extensions: vec![
            ext(0x0000, 5 + host_len),
            ext(0x0017, 0),
            ext(0xff01, 1),
            ext(0x000a, 16),
            ext(0x000b, 2),
            ext(0x0023, 0),
            ext(0x0010, 14),
            ext(0x0005, 5),
            ext(0x0022, 11),
            ext(0x0012, 0),
            ext(0x0033, 1263),
            ext(0x002b, 5),
            ext(0x000d, 24),
            ext(0x002d, 2),
            ext(0x001c, 2),
            ext(0x001b, 3),
        ],
        server_name_length: Some(host_len),
        psk_extension_length: 0,
    }
}

// Synthetic QUIC metadata: the TLS 1.3 suites, server_name, then
// supported_groups, ALPN, status_request, delegated_credentials,
// signed_certificate_timestamp, key_share, supported_versions,
// signature_algorithms, psk_key_exchange_modes, record_size_limit and
// quic_transport_parameters.
fn firefox_quic(host_len: usize) -> NssVector {
    NssVector {
        cipher_suites: vec![0; 6],
        extensions: vec![
            ext(0x0000, 5 + host_len),
            ext(0x000a, 16),
            ext(0x0010, 5),
            ext(0x0005, 5),
            ext(0x0022, 11),
            ext(0x0012, 0),
            ext(0x0033, 1263),
            ext(0x002b, 3),
            ext(0x000d, 24),
            ext(0x002d, 2),
            ext(0x001c, 2),
            ext(0x0039, 87),
        ],
        server_name_length: Some(host_len),
        psk_extension_length: 0,
    }
}

// Synthetic reference vectors derived from NSS's inner encoding and padding,
// not independent browser captures. The fixed source defines their arithmetic:
// https://github.com/nss-dev/nss/blob/42dc6cfddbcee57f391dd1b4550604e68437986d/lib/ssl/tls13ech.c#L1351-L1653
// https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1.3
#[test]
fn ech_nss_payload_length_reference_vectors() {
    let fresh = firefox_tcp(19);
    assert_eq!(
        EchGreaseInfo(&fresh.info()).nss_payload_length(100, 19),
        240
    );
    // Hosts beyond grease_size get no name padding.
    let long = firefox_tcp(120);
    assert_eq!(
        EchGreaseInfo(&long.info()).nss_payload_length(100, 120),
        272
    );
    // Resumption copies the 107-byte pre_shared_key (64-byte ticket, SHA-256
    // binder) into the inner hello and offers early_data.
    let mut resumed = firefox_tcp(19);
    resumed.extensions.push(ext(0x002a, 0));
    resumed.psk_extension_length = 107;
    assert_eq!(
        EchGreaseInfo(&resumed.info()).nss_payload_length(100, 19),
        368
    );
    // IP literals send no SNI but still pad by the URL host, so the result
    // steps at a grease_size boundary: 127.0.0.1 at 93/94 and ::1 at 87/88.
    let mut literal = firefox_tcp(0);
    literal.extensions.remove(0);
    literal.server_name_length = None;
    let literal = literal.info();
    for (host_len, below, above) in [(9, 93, 94), (3, 87, 88)] {
        assert_eq!(
            EchGreaseInfo(&literal).nss_payload_length(below, host_len),
            208
        );
        assert_eq!(
            EchGreaseInfo(&literal).nss_payload_length(above, host_len),
            240
        );
    }
    let quic = firefox_quic(19);
    assert_eq!(EchGreaseInfo(&quic.info()).nss_payload_length(100, 19), 240);
    let mut quic_resumed = firefox_quic(19);
    quic_resumed.extensions.push(ext(0x002a, 0));
    quic_resumed.psk_extension_length = 123;
    assert_eq!(
        EchGreaseInfo(&quic_resumed.info()).nss_payload_length(100, 19),
        368
    );
    let mut quic_literal = firefox_quic(0);
    quic_literal.extensions.remove(0);
    quic_literal.server_name_length = None;
    assert_eq!(
        EchGreaseInfo(&quic_literal.info()).nss_payload_length(100, 9),
        208
    );
}

#[test]
fn ech_nss_grease_crosses_padding_boundary() {
    let plain = firefox_tcp(19);
    let mut grease = firefox_tcp(19);
    grease.extensions.insert(0, ext(0x0a0a, 0));
    grease.extensions.push(ext(0x1a1a, 1));
    // At max_name_len=100, the inner length is 217 before rounding. GREASE
    // adds four compressed-extension bytes and two version bytes: 223/224/225
    // at 100/101/102. Omitting the version bytes misses the final 32-byte step.
    for (max_name_len, expected) in [(100, 240), (101, 240), (102, 272)] {
        assert_eq!(
            EchGreaseInfo(&plain.info()).nss_payload_length(max_name_len, 19),
            240,
            "without GREASE, max_name_len={max_name_len}",
        );
        assert_eq!(
            EchGreaseInfo(&grease.info()).nss_payload_length(max_name_len, 19),
            expected,
            "with GREASE, max_name_len={max_name_len}",
        );
    }
}

// NSS picks the AEAD from a random bit, so both must appear.
#[test]
fn ech_nss_parameters_draw_both_aeads() {
    let vector = firefox_tcp(19);
    let info = vector.info();
    let mut aes = 0;
    for _ in 0..64 {
        let parameters = EchGreaseInfo(&info).nss_parameters(100, 19).unwrap();
        assert_eq!(parameters.payload_length.get(), 240);
        assert!(parameters.random_enc);
        aes += usize::from(parameters.aead == EchGreaseAead::AES_128_GCM);
    }
    // Seeing only one AEAD has probability 2^-63.
    assert!(aes > 0 && aes < 64);
    let mut tight = vector.info();
    tight.max_payload_length = 239;
    assert!(EchGreaseInfo(&tight).nss_parameters(100, 19).is_err());
}

#[test]
fn ech_nss_sizing_example() {
    for grease in [false, true] {
        let server = Server::builder().build();
        let expected = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&expected);
        let mut client = server.client_with_root_ca();
        client.ctx().set_grease_enabled(grease);
        client.ctx().set_ech_grease_callback(move |_, info| {
            let host_len = "localhost".len();
            assert_eq!(info.server_name_length(), Some(host_len));
            let host_len = u8::try_from(host_len).unwrap();
            let length = info.nss_payload_length(100, host_len);
            assert_eq!((length - info.aead_overhead()) % 32, 0);
            assert_eq!(info.nss_payload_length(132, host_len), length + 32);
            assert_eq!(
                info.nss_payload_length(0, host_len),
                info.nss_payload_length(host_len, host_len)
            );
            observed.store(length, Ordering::SeqCst);
            let parameters = info.nss_parameters(100, host_len)?;
            assert_eq!(usize::from(parameters.payload_length.get()), length);
            Ok(parameters)
        });
        let mut connection = client.build().builder();
        connection.ssl().set_hostname("localhost").unwrap();
        connection.ssl().set_enable_ech_grease(true);
        let messages = connect_and_capture(connection, None);
        assert_eq!(
            ech(&messages[0]).len(),
            expected.load(Ordering::SeqCst) + ECH_BODY_FRAMING_LEN
        );
    }
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
    first.ssl().set_hostname("localhost").unwrap();
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
    second.ssl().set_hostname("localhost").unwrap();
    second
        .ssl()
        .set_ech_grease_callback(move |_, info| {
            assert!(info.psk_extension_length() > 4);
            count.fetch_add(1, Ordering::SeqCst);
            Ok(parameters(info, info.nss_payload_length(100, 9)))
        })
        .unwrap();
    assert!(second.connect().ssl().session_reused());
    assert_eq!(called.load(Ordering::SeqCst), 1);
}
