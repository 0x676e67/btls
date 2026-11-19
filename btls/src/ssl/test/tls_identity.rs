use std::sync::mpsc;

use super::server::Server;
use crate::ssl::{
    ExtensionType, KeyShare, SslContext, SslMethod, SslSignatureAlgorithm, SslVersion,
};

#[test]
fn nist_mlkem_handshakes() {
    for (name, id, share) in [
        ("SecP256r1MLKEM768", 4587, KeyShare::P256_MLKEM768),
        ("SecP384r1MLKEM1024", 4589, KeyShare::P384_MLKEM1024),
    ] {
        for retry in [false, true] {
            let mut server = Server::builder();
            server.ctx().set_curves_list(name).unwrap();
            server
                .ctx()
                .set_min_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            let server = server.build();
            let mut client = server.client();
            client
                .ctx()
                .set_curves_list(&format!("X25519:{name}"))
                .unwrap();
            let client = client.build();
            let mut connection = client.builder();
            connection
                .ssl()
                .set_client_key_shares(&[if retry { KeyShare::X25519 } else { share }])
                .unwrap();
            let stream = connection.connect();
            assert_eq!(stream.ssl().curve(), Some(id));
            assert_eq!(stream.ssl().used_hello_retry_request(), retry);
        }
    }
}

fn capture_cert_algorithms(
    version: SslVersion,
    configured: bool,
    override_list: Option<&[SslSignatureAlgorithm]>,
) -> (Option<Vec<u8>>, Vec<u8>) {
    let (tx, rx) = mpsc::channel();
    let mut server = Server::builder();
    server.ctx().set_select_certificate_callback(move |hello| {
        tx.send((
            hello
                .get_extension(ExtensionType::SIGNATURE_ALGORITHMS_CERT)
                .map(ToOwned::to_owned),
            hello
                .get_extension(ExtensionType::SIGNATURE_ALGORITHMS)
                .unwrap()
                .to_vec(),
        ))
        .unwrap();
        Ok(())
    });
    let server = server.build();
    let mut client = server.client();
    client.ctx().set_min_proto_version(Some(version)).unwrap();
    client.ctx().set_max_proto_version(Some(version)).unwrap();
    if configured {
        client
            .ctx()
            .set_cert_signature_algorithms(&[
                SslSignatureAlgorithm::RSA_PKCS1_SHA256,
                SslSignatureAlgorithm::RSA_PKCS1_SHA1,
            ])
            .unwrap();
    }
    let client = client.build();
    let mut connection = client.builder();
    if let Some(list) = override_list {
        connection
            .ssl()
            .set_cert_signature_algorithms(list)
            .unwrap();
    }
    let _stream = connection.connect();
    rx.recv().unwrap()
}

#[test]
fn certificate_algorithms_are_independent_and_opt_in() {
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        let (default, sigalgs) = capture_cert_algorithms(version, false, None);
        assert_eq!(default, None);
        let (configured, after) = capture_cert_algorithms(version, true, None);
        assert_eq!(configured, Some(vec![0, 4, 4, 1, 2, 1]));
        assert_eq!(sigalgs, after);
        let (cleared, _) = capture_cert_algorithms(version, true, Some(&[]));
        assert_eq!(cleared, None);
        let (overridden, _) = capture_cert_algorithms(
            version,
            true,
            Some(&[SslSignatureAlgorithm::RSA_PKCS1_SHA256]),
        );
        assert_eq!(overridden, Some(vec![0, 2, 4, 1]));
    }
}

#[test]
fn certificate_algorithms_reject_oversized_list() {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    assert!(ctx
        .set_cert_signature_algorithms(&vec![SslSignatureAlgorithm::RSA_PKCS1_SHA256; 32767])
        .is_err());
}

#[test]
fn tls13_ciphers_can_follow_older_suites() {
    for last in [false, true] {
        let (tx, rx) = mpsc::channel();
        let mut server = Server::builder();
        server.ctx().set_select_certificate_callback(move |hello| {
            tx.send(hello.ciphers().to_vec()).unwrap();
            Ok(())
        });
        let server = server.build();
        let mut client = server.client();
        client
            .ctx()
            .set_cipher_list("ECDHE-RSA-AES128-GCM-SHA256")
            .unwrap();
        client
            .ctx()
            .set_tls13_ciphers(&[crate::ssl::Tls13Cipher::AES_128_GCM_SHA256])
            .unwrap();
        client.ctx().set_tls13_ciphers_last(last);
        let _stream = client.connect();
        let ciphers = rx.recv().unwrap();
        assert_eq!(
            ciphers,
            if last {
                vec![0xc0, 0x2f, 0x13, 1]
            } else {
                vec![0x13, 1, 0xc0, 0x2f]
            }
        );
    }
}
