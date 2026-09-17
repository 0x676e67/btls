use std::sync::{Arc, Mutex};

use crate::ssl::test::server::Server;
use crate::ssl::{ExtensionType, SslVersion};

fn is_grease_value(value: u16) -> bool {
    (value & 0x0f0f) == 0x0a0a && (value & 0xff) == (value >> 8)
}

fn signature_algorithm_ids(extension: &[u8]) -> Vec<u16> {
    assert!(extension.len() >= 2);
    assert_eq!(
        u16::from_be_bytes([extension[0], extension[1]]) as usize,
        extension.len() - 2
    );
    assert_eq!((extension.len() - 2) % 2, 0);
    extension[2..]
        .chunks_exact(2)
        .map(|value| u16::from_be_bytes([value[0], value[1]]))
        .collect()
}

fn capture_signature_algorithms(enabled: bool) -> Vec<u16> {
    let signature_algorithms = Arc::new(Mutex::new(None));

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

    let mut client = server.client();
    client
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    client
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    client.ctx().set_grease_sigalgs_enabled(enabled);

    client.connect();

    let extension = signature_algorithms
        .lock()
        .unwrap()
        .take()
        .expect("client should send signature_algorithms extension");

    signature_algorithm_ids(&extension)
}

#[test]
fn client_hello_signature_algorithms_grease_setting() {
    let plain = capture_signature_algorithms(false);
    let greased = capture_signature_algorithms(true);

    assert!(
        !plain.iter().any(|value| is_grease_value(*value)),
        "signature_algorithms should not contain GREASE when sigalgs GREASE is disabled",
    );
    assert!(
        greased.iter().any(|value| is_grease_value(*value)),
        "signature_algorithms should contain GREASE when set_grease_sigalgs_enabled(true)",
    );
    assert_eq!(
        greased.len(),
        plain.len() + 1,
        "sigalgs GREASE should insert one extra value",
    );
}
