use std::sync::{Arc, Mutex};

use crate::ssl::{ExtensionType, Ssl, SslContext, SslMethod, SslVersion};

use super::Server;

fn capture_trust_anchors_extension(
    context_ids: Option<&[u8]>,
    ssl_ids: Option<&[u8]>,
) -> Option<Vec<u8>> {
    let captured = Arc::new(Mutex::new(None));
    let mut server = Server::builder();
    server
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server.ctx().set_select_certificate_callback({
        let captured = Arc::clone(&captured);
        move |client_hello| {
            let extension = client_hello
                .get_extension(ExtensionType::TRUST_ANCHORS)
                .map(ToOwned::to_owned);
            *captured.lock().unwrap() = Some(extension);
            Ok(())
        }
    });
    let server = server.build();

    let mut client = server.client();
    client
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    client
        .ctx()
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    if let Some(ids) = context_ids {
        let ids = ids.to_vec();
        client.ctx().set_requested_trust_anchors(&ids).unwrap();
    }

    let client = client.build();
    let mut connection = client.builder();
    if let Some(ids) = ssl_ids {
        let ids = ids.to_vec();
        connection.ssl().set_requested_trust_anchors(&ids).unwrap();
    }
    connection.connect();

    let extension = captured.lock().unwrap().clone();
    extension.expect("select-certificate callback was not called")
}

#[test]
fn requested_trust_anchors_are_omitted_by_default() {
    assert_eq!(capture_trust_anchors_extension(None, None), None);
}

#[test]
fn context_requested_trust_anchors_are_copied_and_sent() {
    assert_eq!(
        capture_trust_anchors_extension(Some(b"\x03ctx"), None),
        Some(b"\x00\x04\x03ctx".to_vec())
    );
}

#[test]
fn ssl_requested_trust_anchors_override_context_configuration() {
    assert_eq!(
        capture_trust_anchors_extension(Some(b"\x03ctx"), Some(b"\x03ssl")),
        Some(b"\x00\x04\x03ssl".to_vec())
    );
}

#[test]
fn empty_requested_trust_anchors_still_send_the_extension() {
    assert_eq!(
        capture_trust_anchors_extension(None, Some(b"")),
        Some(b"\x00\x00".to_vec())
    );
}

#[test]
fn malformed_requested_trust_anchors_are_rejected() {
    for ids in [&b"\x00"[..], &b"\x04abc"[..]] {
        let mut context = SslContext::builder(SslMethod::tls()).unwrap();
        assert!(context.set_requested_trust_anchors(ids).is_err());

        let context = SslContext::builder(SslMethod::tls()).unwrap().build();
        let mut ssl = Ssl::new(&context).unwrap();
        assert!(ssl.set_requested_trust_anchors(ids).is_err());
    }
}
