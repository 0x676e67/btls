use std::sync::{Arc, Mutex};

use foreign_types::ForeignTypeRef;

use super::server::Server;
use crate::ffi;
use crate::ssl::{ExtensionType, SslVersion};

#[test]
fn boring_pq_p256_kyber_group_can_negotiate() {
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
#[cfg(not(feature = "fips"))]
fn boringssl_patch_tls12_sha384_cipher_is_advertised() {
    let client_ciphers = Arc::new(Mutex::new(None));

    let mut server = Server::builder();
    server
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    server
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    server
        .ctx()
        .set_cipher_list("ECDHE-RSA-AES128-GCM-SHA256")
        .unwrap();
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
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    client
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    client
        .ctx()
        .set_cipher_list("ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256")
        .unwrap();

    let stream = client.connect();
    let cipher = stream.ssl().current_cipher().unwrap();
    assert_eq!(stream.ssl().version2(), Some(SslVersion::TLS1_2));
    assert_eq!(
        cipher.standard_name(),
        Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    );

    let ciphers = client_ciphers.lock().unwrap().clone().unwrap();
    let cipher_ids = ciphers
        .chunks_exact(2)
        .map(|cipher| u16::from_be_bytes([cipher[0], cipher[1]]))
        .collect::<Vec<_>>();
    assert!(cipher_ids.contains(&0xc028));
}

#[test]
#[cfg(not(feature = "fips"))]
fn boringssl_patch_clienthello_extensions_are_sent() {
    let record_size_limit = Arc::new(Mutex::new(None));
    let delegated_credential = Arc::new(Mutex::new(None));

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
    client.ctx().set_record_size_limit(1200);
    client
        .ctx()
        .set_delegated_credentials("rsa_pss_rsae_sha256:ecdsa_secp256r1_sha256")
        .unwrap();

    client.connect();

    assert_eq!(
        record_size_limit.lock().unwrap().as_deref(),
        Some(&[0x04, 0xb0][..]),
    );
    assert_eq!(
        delegated_credential.lock().unwrap().as_deref(),
        Some(&[0x00, 0x04, 0x08, 0x04, 0x04, 0x03][..]),
    );
}

#[test]
#[cfg(not(feature = "fips"))]
fn boringssl_patch_preserves_tls13_cipher_order_in_clienthello() {
    let client_ciphers = Arc::new(Mutex::new(None));

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

    let ciphers = client_ciphers.lock().unwrap().clone().unwrap();
    let cipher_ids = ciphers
        .chunks_exact(2)
        .map(|cipher| u16::from_be_bytes([cipher[0], cipher[1]]))
        .collect::<Vec<_>>();
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
