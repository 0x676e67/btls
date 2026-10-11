use std::sync::mpsc;

use crate::ssl::test::server::Server;
use crate::ssl::{ExtensionType, SslVersion};

/// Returns the client's server_padding extension and whether it received the padding.
fn handshake(request: Option<u16>, server_enabled: bool) -> (Option<Vec<u8>>, bool) {
    let (captured_tx, captured_rx) = mpsc::channel();
    let mut server = Server::builder();
    server
        .ctx()
        .set_select_certificate_callback(move |client_hello| {
            let extension = client_hello
                .get_extension(ExtensionType::SERVER_PADDING)
                .map(ToOwned::to_owned);
            captured_tx.send(extension).unwrap();
            Ok(())
        });
    server.ssl_cb(move |ssl| ssl.set_server_padding_enabled(server_enabled));
    let server = server.build();

    let mut client = server.client();
    client
        .ctx()
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    let client = client.build();
    let mut connection = client.builder();
    if let Some(num_bytes) = request {
        connection.ssl().set_server_padding_request(num_bytes);
    }
    let stream = connection.connect();

    let extension = captured_rx
        .recv()
        .expect("select-certificate callback was not called");
    (extension, stream.ssl().server_sent_requested_padding())
}

#[test]
fn server_padding_request() {
    assert_eq!(handshake(None, true), (None, false));
    assert_eq!(
        handshake(Some(1024), false),
        (Some(1024u16.to_be_bytes().to_vec()), false)
    );
    assert_eq!(
        handshake(Some(1024), true),
        (Some(1024u16.to_be_bytes().to_vec()), true)
    );
    // Servers ignore requests above 16 KiB.
    assert_eq!(
        handshake(Some(16 * 1024 + 1), true),
        (Some((16u16 * 1024 + 1).to_be_bytes().to_vec()), false)
    );
}
