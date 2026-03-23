use std::io::{self, Read, Write as _};

use super::server::Server;
use crate::ssl::CertificateCompressor;
use crate::x509::store::X509StoreBuilder;
use crate::x509::X509;

#[derive(Debug)]
struct BrotliCompressor {
    q: u32,
    lgwin: u32,
}

impl Default for BrotliCompressor {
    fn default() -> Self {
        Self { q: 11, lgwin: 32 }
    }
}

impl CertificateCompressor for BrotliCompressor {
    fn compress(&self, input: &[u8], output: &mut dyn std::io::Write) -> std::io::Result<()> {
        let mut writer = brotli::CompressorWriter::new(output, 1024, self.q, self.lgwin);
        writer.write_all(input)?;
        Ok(())
    }

    fn decompress(&self, input: &[u8], output: &mut dyn std::io::Write) -> std::io::Result<()> {
        let mut reader = brotli::Decompressor::new(input, 4096);
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf[..]) {
                Err(e) => {
                    if let io::ErrorKind::Interrupted = e.kind() {
                        continue;
                    }
                    return Err(e);
                }
                Ok(size) => {
                    if size == 0 {
                        break;
                    }
                    output.write_all(&buf[..size])?;
                }
            }
        }
        Ok(())
    }

    fn algorithm(&self) -> crate::ssl::CertificateCompressionAlgorithm {
        crate::ssl::CertificateCompressionAlgorithm::BROTLI
    }
}

#[test]
fn server_only_cert_compression() {
    let mut server_builder = Server::builder();
    server_builder
        .ctx()
        .add_certificate_compression_algorithm(BrotliCompressor::default())
        .unwrap();

    let server = server_builder.build();

    let mut store = X509StoreBuilder::new().unwrap();
    let x509 = X509::from_pem(super::ROOT_CERT).unwrap();
    store.add_cert(&x509).unwrap();

    let client = server.client();

    client.connect();
}

#[test]
fn client_only_cert_compression() {
    let server_builder = Server::builder().build();

    let mut store = X509StoreBuilder::new().unwrap();
    let x509 = X509::from_pem(super::ROOT_CERT).unwrap();
    store.add_cert(&x509).unwrap();

    let mut client = server_builder.client();
    client
        .ctx()
        .add_certificate_compression_algorithm(BrotliCompressor::default())
        .unwrap();

    client.connect();
}

#[test]
fn client_and_server_cert_compression() {
    let mut server = Server::builder();
    server
        .ctx()
        .add_certificate_compression_algorithm(BrotliCompressor::default())
        .unwrap();

    let server = server.build();

    let mut store = X509StoreBuilder::new().unwrap();
    let x509 = X509::from_pem(super::ROOT_CERT).unwrap();
    store.add_cert(&x509).unwrap();

    let mut client = server.client();
    client
        .ctx()
        .add_certificate_compression_algorithm(BrotliCompressor::default())
        .unwrap();

    client.connect();
}
