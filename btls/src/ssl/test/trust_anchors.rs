use crate::ssl::test::server::Server;

// A wire-format trust anchor ID list containing a single 3-byte anchor ID ("abc"):
// one 8-bit length-prefixed string, per draft-ietf-tls-trust-anchor-ids-00 Section 3.
static TRUST_ANCHOR_IDS: &[u8] = b"\x03abc";

#[test]
fn set_requested_trust_anchors_nonempty() {
    let server = Server::builder().build();

    let mut client = server.client_with_root_ca().build().builder();
    client
        .ssl()
        .set_requested_trust_anchors(TRUST_ANCHOR_IDS)
        .unwrap();
    client.ssl().set_hostname("foobar.com").unwrap();

    let ssl_stream = client.connect();
    assert!(ssl_stream.ssl().peer_certificate().is_some());
}

#[test]
fn set_requested_trust_anchors_empty() {
    // An empty slice is meaningful: the trust_anchors extension is still sent in
    // ClientHello, signalling support for the retry flow without requesting specific
    // trust anchors. It must reach the C function and not be collapsed to a no-op.
    let server = Server::builder().build();

    let mut client = server.client_with_root_ca().build().builder();
    client.ssl().set_requested_trust_anchors(&[]).unwrap();
    client.ssl().set_hostname("foobar.com").unwrap();

    let ssl_stream = client.connect();
    assert!(ssl_stream.ssl().peer_certificate().is_some());
}

#[test]
fn set_ctx_requested_trust_anchors_nonempty() {
    let server = Server::builder().build();

    let mut client = server.client_with_root_ca();
    client
        .ctx()
        .set_requested_trust_anchors(TRUST_ANCHOR_IDS)
        .unwrap();
    let mut client = client.build().builder();
    client.ssl().set_hostname("foobar.com").unwrap();

    let ssl_stream = client.connect();
    assert!(ssl_stream.ssl().peer_certificate().is_some());
}

#[test]
fn set_ctx_requested_trust_anchors_empty() {
    let server = Server::builder().build();

    let mut client = server.client_with_root_ca();
    client.ctx().set_requested_trust_anchors(&[]).unwrap();
    let mut client = client.build().builder();
    client.ssl().set_hostname("foobar.com").unwrap();

    let ssl_stream = client.connect();
    assert!(ssl_stream.ssl().peer_certificate().is_some());
}
