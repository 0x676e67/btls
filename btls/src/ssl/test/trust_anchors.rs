use std::sync::mpsc;

use crate::ssl::{ExtensionType, Ssl, SslContext, SslContextBuilder, SslMethod, SslVersion};

use super::Server;

const CONTEXT_IDS: &[u8] = b"\x01a\x02bc";
const CONNECTION_IDS: &[u8] = b"\x02de\x03fgh";

#[derive(Default)]
struct RequestConfig<'a> {
    context_ids: Option<&'a [u8]>,
    connection_ids: Option<&'a [u8]>,
}

fn require_tls13(context: &mut SslContextBuilder) {
    context
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    context
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
}

fn set_then_overwrite_input(ids: &[u8], set: impl FnOnce(&[u8])) {
    let mut input = ids.to_vec();
    set(&input);

    // A set1 API must own a copy rather than retain the caller's buffer.
    input.fill(0);
}

fn capture_trust_anchors_extension(config: RequestConfig<'_>) -> Option<Vec<u8>> {
    let (captured_tx, captured_rx) = mpsc::channel();
    let mut server = Server::builder();
    require_tls13(server.ctx());
    server
        .ctx()
        .set_select_certificate_callback(move |client_hello| {
            let extension = client_hello
                .get_extension(ExtensionType::TRUST_ANCHORS)
                .map(ToOwned::to_owned);
            captured_tx.send(extension).unwrap();
            Ok(())
        });
    let server = server.build();

    let mut client = server.client();
    require_tls13(client.ctx());
    if let Some(ids) = config.context_ids {
        set_then_overwrite_input(ids, |input| {
            client.ctx().set_requested_trust_anchors(input).unwrap();
        });
    }

    let client = client.build();
    let mut connection = client.builder();
    if let Some(ids) = config.connection_ids {
        set_then_overwrite_input(ids, |input| {
            connection.ssl().set_requested_trust_anchors(input).unwrap();
        });
    }
    connection.connect();

    captured_rx
        .recv()
        .expect("select-certificate callback was not called")
}

#[test]
fn requested_trust_anchors_are_omitted_by_default() {
    assert_eq!(
        capture_trust_anchors_extension(RequestConfig::default()),
        None
    );
}

#[test]
fn context_requested_trust_anchors_are_copied_and_sent() {
    assert_eq!(
        capture_trust_anchors_extension(RequestConfig {
            context_ids: Some(CONTEXT_IDS),
            ..RequestConfig::default()
        }),
        Some(b"\x00\x05\x01a\x02bc".to_vec())
    );
}

#[test]
fn ssl_requested_trust_anchors_are_copied_and_override_context() {
    assert_eq!(
        capture_trust_anchors_extension(RequestConfig {
            context_ids: Some(CONTEXT_IDS),
            connection_ids: Some(CONNECTION_IDS),
        }),
        Some(b"\x00\x07\x02de\x03fgh".to_vec())
    );
}

#[test]
fn empty_requested_trust_anchors_are_sent_by_both_setters() {
    assert_eq!(
        capture_trust_anchors_extension(RequestConfig {
            context_ids: Some(b""),
            ..RequestConfig::default()
        }),
        Some(b"\x00\x00".to_vec())
    );
    assert_eq!(
        capture_trust_anchors_extension(RequestConfig {
            connection_ids: Some(b""),
            ..RequestConfig::default()
        }),
        Some(b"\x00\x00".to_vec())
    );
}

#[test]
fn malformed_requested_trust_anchors_are_rejected() {
    let malformed_lists = [
        ("empty ID", &b"\x00"[..]),
        ("truncated first ID", &b"\x04abc"[..]),
        ("truncated second ID", &b"\x01a\x02b"[..]),
    ];

    for (name, ids) in malformed_lists {
        let mut context = SslContext::builder(SslMethod::tls()).unwrap();
        assert!(
            context.set_requested_trust_anchors(ids).is_err(),
            "context setter accepted {name}: {ids:?}"
        );

        let context = SslContext::builder(SslMethod::tls()).unwrap().build();
        let mut ssl = Ssl::new(&context).unwrap();
        assert!(
            ssl.set_requested_trust_anchors(ids).is_err(),
            "SSL setter accepted {name}: {ids:?}"
        );
    }
}
