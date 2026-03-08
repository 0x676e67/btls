#![allow(unused)]
mod aead;
mod alert;
mod alpn;
mod bffi_ext;
mod client;
mod error;
mod handshake_token;
mod hkdf;
mod hmac;
mod key;
mod macros;
mod retry;
mod secret;
mod server;
mod session_cache;
mod session_state;
mod suite;
mod version;

// Export the public interface.
pub use bffi_ext::*;
pub use client::Config as ClientConfig;
pub use error::{Error, Result};
pub use handshake_token::HandshakeTokenKey;
pub use hmac::HmacKey;
pub use server::Config as ServerConfig;
pub use session_cache::*;
pub use version::QuicVersion;

/// Information available from [quinn_proto::crypto::Session::handshake_data] once the handshake has completed.
#[derive(Clone, Debug)]
pub struct HandshakeData {
    /// The negotiated application protocol, if ALPN is in use
    ///
    /// Guaranteed to be set if a nonempty list of protocols was specified for this connection.
    pub protocol: Option<Vec<u8>>,

    /// The server name specified by the client, if any
    ///
    /// Always `None` for outgoing connections
    pub server_name: Option<String>,
}

pub mod helpers {
    use super::*;
    use quinn_proto::crypto;
    use std::sync::Arc;

    /// Create a server config with the given [`crypto::ServerConfig`]
    ///
    /// Uses a randomized handshake token key.
    pub fn server_config(crypto: Arc<dyn crypto::ServerConfig>) -> Result<quinn::ServerConfig> {
        Ok(quinn::ServerConfig::new(
            crypto,
            Arc::new(HandshakeTokenKey::new()?),
        ))
    }

    /// Returns a default endpoint configuration for BoringSSL.
    pub fn default_endpoint_config() -> quinn::EndpointConfig {
        let mut cfg = quinn::EndpointConfig::new(Arc::new(HmacKey::sha256()));
        cfg.supported_versions(QuicVersion::default_supported_versions());
        cfg
    }

    /// Helper to construct an endpoint for use with outgoing connections only
    ///
    /// Note that `addr` is the *local* address to bind to, which should usually be a wildcard
    /// address like `0.0.0.0:0` or `[::]:0`, which allow communication with any reachable IPv4 or
    /// IPv6 address respectively from an OS-assigned port.
    ///
    /// Platform defaults for dual-stack sockets vary. For example, any socket bound to a wildcard
    /// IPv6 address on Windows will not by default be able to communicate with IPv4
    /// addresses. Portable applications should bind an address that matches the family they wish to
    /// communicate within.
    #[cfg(feature = "runtime-tokio")]
    pub fn client_endpoint(addr: std::net::SocketAddr) -> std::io::Result<quinn::Endpoint> {
        let socket = std::net::UdpSocket::bind(addr)?;
        quinn::Endpoint::new(
            default_endpoint_config(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
    }

    /// Helper to construct an endpoint for use with both incoming and outgoing connections
    ///
    /// Platform defaults for dual-stack sockets vary. For example, any socket bound to a wildcard
    /// IPv6 address on Windows will not by default be able to communicate with IPv4
    /// addresses. Portable applications should bind an address that matches the family they wish to
    /// communicate within.
    #[cfg(feature = "runtime-tokio")]
    pub fn server_endpoint(
        config: quinn::ServerConfig,
        addr: std::net::SocketAddr,
    ) -> std::io::Result<quinn::Endpoint> {
        let socket = std::net::UdpSocket::bind(addr)?;
        quinn::Endpoint::new(
            default_endpoint_config(),
            Some(config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::error::Result;
    use crate::secret::{Secret, Secrets};
    use crate::suite::CipherSuite;
    use bytes::BytesMut;
    use hex_literal::hex;
    use quinn_proto::crypto::PacketKey;
    use quinn_proto::{ConnectionId, Side};

    /// Copied from quiche.
    #[test]
    fn test_initial_keys_v1() -> Result<()> {
        let dcid: &[u8] = &hex!("8394c8f03e515708");
        let version = QuicVersion::V1;
        let suite = CipherSuite::aes128_gcm_sha256();

        let s = Secrets::initial(version, &ConnectionId::new(dcid), Side::Client)?;

        let expected_enc_key: &[u8] = &hex!("1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(
            s.local.packet_key(version, suite)?.key().slice(),
            expected_enc_key
        );
        let expected_enc_iv: &[u8] = &hex!("fa044b2f42a3fd3b46fb255c");
        assert_eq!(
            s.local.packet_key(version, suite)?.iv().slice(),
            expected_enc_iv
        );
        let expected_enc_hdr_key: &[u8] = &hex!("9f50449e04a0e810283a1e9933adedd2");
        assert_eq!(
            s.local.header_key(version, suite)?.key().slice(),
            expected_enc_hdr_key
        );
        let expected_dec_key: &[u8] = &hex!("cf3a5331653c364c88f0f379b6067e37");
        assert_eq!(
            s.remote.packet_key(version, suite)?.key().slice(),
            expected_dec_key
        );
        let expected_dec_iv: &[u8] = &hex!("0ac1493ca1905853b0bba03e");
        assert_eq!(
            s.remote.packet_key(version, suite)?.iv().slice(),
            expected_dec_iv
        );
        let expected_dec_hdr_key: &[u8] = &hex!("c206b8d9b9f0f37644430b490eeaa314");
        assert_eq!(
            s.remote.header_key(version, suite)?.key().slice(),
            expected_dec_hdr_key
        );

        Ok(())
    }

    /// Copied from rustls.
    #[test]
    fn short_packet_header_protection() {
        // https://www.rfc-editor.org/rfc/rfc9001.html#name-chacha20-poly1305-short-hea

        const PN: u64 = 654360564;
        const SECRET: &[u8] =
            &hex!("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");

        let version = QuicVersion::V1;
        let suite = CipherSuite::chacha20_poly1305_sha256();

        let secret = Secret::from(SECRET);
        let hpk = secret
            .header_key(version, suite)
            .unwrap()
            .as_crypto()
            .unwrap();
        let packet = secret.packet_key(version, suite).unwrap();

        const PLAIN: &[u8] = &[0x42, 0x00, 0xbf, 0xf4, b'h', b'e', b'l', b'l', b'o'];

        let mut buf = PLAIN.to_vec();
        // Make space for the output tag.
        buf.extend_from_slice(&[0u8; 16]);
        packet.encrypt(PN, &mut buf, 4);

        let pn_offset = 1;
        hpk.encrypt(pn_offset, &mut buf);

        const PROTECTED: &[u8] = &hex!("593b46220c4d504a9f1857793356400fc4a784ee309dff98b2");

        assert_eq!(&buf, PROTECTED);

        hpk.decrypt(pn_offset, &mut buf);

        let (header, payload_tag) = buf.split_at(4);
        let mut payload_tag = BytesMut::from(payload_tag);
        packet.decrypt(PN, header, &mut payload_tag).unwrap();
        let plain = payload_tag.as_ref();
        assert_eq!(plain, &PLAIN[4..]);
    }

    /// Copied from rustls.
    #[test]
    fn key_update_test_vector() {
        let version = QuicVersion::V1;
        let suite = CipherSuite::aes128_gcm_sha256();
        let mut secrets = Secrets {
            version,
            suite,
            local: Secret::from(&hex!(
                "b8767708f8772358a6ea9fc43e4add2c961b3f5287a6d1467ee0aeab33724dbf"
            )),
            remote: Secret::from(&hex!(
                "42dc972140e0f2e39845b767613439dc6758ca43259b878506824eb1e438d855"
            )),
        };
        secrets.update().unwrap();

        let expected = Secrets {
            version,
            suite,
            local: Secret::from(&hex!(
                "42cac8c91cd5eb40682e432edf2d2be9f41a52ca6b22d8e6cdb1e8aca9061fce"
            )),
            remote: Secret::from(&hex!(
                "eb7f5e2a123f407db499e361cae590d4d992e14b7ace03c244e0422115b6d38a"
            )),
        };

        assert_eq!(expected, secrets);
    }

    #[test]
    fn client_encrypt_header() {
        let dcid = ConnectionId::new(&hex!("06b858ec6f80452b"));

        let secrets = Secrets::initial(QuicVersion::V1, &dcid, Side::Client).unwrap();
        let client = secrets.keys().unwrap().as_crypto().unwrap();

        // Client (encrypt)
        let mut packet: [u8; 51] = hex!(
            "c0000000010806b858ec6f80452b0000402100c8fb7ffd97230e38b70d86e7ff148afdf88fc21c4426c7d1cec79914c8785757"
        );
        let packet_number = 0;
        let packet_number_pos = 18;
        let header_len = 19;

        // Encrypt the payload.
        client
            .packet
            .local
            .encrypt(packet_number, &mut packet, header_len);
        let expected_after_packet_encrypt: [u8; 51] = hex!(
            "c0000000010806b858ec6f80452b0000402100f60e77fa2f629f9921fae64125c5632cf769d801a4693af6b949af37c2c45399"
        );
        assert_eq!(packet, expected_after_packet_encrypt);

        // Encrypt the header.
        client.header.local.encrypt(packet_number_pos, &mut packet);
        let expected_after_header_encrypt: [u8; 51] = hex!(
            "cd000000010806b858ec6f80452b000040210bf60e77fa2f629f9921fae64125c5632cf769d801a4693af6b949af37c2c45399"
        );
        assert_eq!(packet, expected_after_header_encrypt);
    }

    #[test]
    fn server_decrypt_header() {
        let dcid = ConnectionId::new(&hex!("06b858ec6f80452b"));
        let secrets = Secrets::initial(QuicVersion::V1, &dcid, Side::Server).unwrap();
        let server = secrets.keys().unwrap().as_crypto().unwrap();

        let mut packet = BytesMut::from(
            &hex!(
                "c8000000010806b858ec6f80452b00004021be3ef50807b84191a196f760a6dad1e9d1c430c48952cba0148250c21c0a6a70e1"
            )[..],
        );
        let packet_number = 0;
        let packet_number_pos = 18;
        let header_len = 19;

        // Decrypt the header.
        server.header.remote.decrypt(packet_number_pos, &mut packet);
        let expected_header: [u8; 19] = hex!("c0000000010806b858ec6f80452b0000402100");
        assert_eq!(packet[..header_len], expected_header);

        // Decrypt the payload.
        let mut header = packet;
        let mut packet = header.split_off(header_len);
        server
            .packet
            .remote
            .decrypt(packet_number, &header, &mut packet)
            .unwrap();
        assert_eq!(packet[..], [0; 16]);
    }
}
