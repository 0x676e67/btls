#![cfg(not(feature = "fips"))]

use std::pin::Pin;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::process::{Child, Command, Output, Stdio};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::thread;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::time::{Duration, Instant};

use btls::asn1::Asn1Time;
use btls::bn::{BigNum, MsbOption};
use btls::ec::{EcGroup, EcKey};
use btls::hash::MessageDigest;
use btls::nid::Nid;
use btls::pkey::{PKey, Private};
use btls::ssl::{
    Ssl, SslAcceptor, SslCipherRef, SslConnector, SslFiletype, SslMethod, SslVerifyMode, SslVersion,
};
use btls::x509::{X509Name, X509};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_btls::SslStream;

#[derive(Clone, Copy, Eq, PartialEq)]
enum CipherPeer {
    BoringSslRsa,
    BoringSslEcdsa,
    OpenSslDhe,
}

struct AddedCipher {
    id: u16,
    rule_name: &'static str,
    standard_name: &'static str,
    peer: CipherPeer,
}

// This is the cipher inventory restored by boringssl.patch, not upstream
// BoringSSL's native list. Keep every entry negotiating so patch migrations do
// not silently leave a name that cannot carry TLS 1.2 application data.
// https://www.rfc-editor.org/rfc/rfc5246
// https://www.rfc-editor.org/rfc/rfc5289
const BORINGSSL_PATCH_ADDED_CIPHERS: &[AddedCipher] = &[
    AddedCipher {
        id: 0x0033,
        rule_name: "DHE-RSA-AES128-SHA",
        standard_name: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        peer: CipherPeer::OpenSslDhe,
    },
    AddedCipher {
        id: 0x0039,
        rule_name: "DHE-RSA-AES256-SHA",
        standard_name: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        peer: CipherPeer::OpenSslDhe,
    },
    AddedCipher {
        id: 0x003c,
        rule_name: "AES128-SHA256",
        standard_name: "TLS_RSA_WITH_AES_128_CBC_SHA256",
        peer: CipherPeer::BoringSslRsa,
    },
    AddedCipher {
        id: 0x003d,
        rule_name: "AES256-SHA256",
        standard_name: "TLS_RSA_WITH_AES_256_CBC_SHA256",
        peer: CipherPeer::BoringSslRsa,
    },
    AddedCipher {
        id: 0x0067,
        rule_name: "DHE-RSA-AES128-SHA256",
        standard_name: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        peer: CipherPeer::OpenSslDhe,
    },
    AddedCipher {
        id: 0x006b,
        rule_name: "DHE-RSA-AES256-SHA256",
        standard_name: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        peer: CipherPeer::OpenSslDhe,
    },
    AddedCipher {
        id: 0x009e,
        rule_name: "DHE-RSA-AES128-GCM-SHA256",
        standard_name: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        peer: CipherPeer::OpenSslDhe,
    },
    AddedCipher {
        id: 0x009f,
        rule_name: "DHE-RSA-AES256-GCM-SHA384",
        standard_name: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        peer: CipherPeer::OpenSslDhe,
    },
    AddedCipher {
        id: 0xc008,
        rule_name: "ECDHE-ECDSA-DES-CBC3-SHA",
        standard_name: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
        peer: CipherPeer::BoringSslEcdsa,
    },
    AddedCipher {
        id: 0xc012,
        rule_name: "ECDHE-RSA-DES-CBC3-SHA",
        standard_name: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        peer: CipherPeer::BoringSslRsa,
    },
    AddedCipher {
        id: 0xc023,
        rule_name: "ECDHE-ECDSA-AES128-SHA256",
        standard_name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        peer: CipherPeer::BoringSslEcdsa,
    },
    AddedCipher {
        id: 0xc024,
        rule_name: "ECDHE-ECDSA-AES256-SHA384",
        standard_name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        peer: CipherPeer::BoringSslEcdsa,
    },
    AddedCipher {
        id: 0xc028,
        rule_name: "ECDHE-RSA-AES256-SHA384",
        standard_name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        peer: CipherPeer::BoringSslRsa,
    },
];

fn ecdsa_server_identity() -> (PKey<Private>, X509) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let private_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();

    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "localhost")
        .unwrap();
    let name = name.build();

    let mut certificate = X509::builder().unwrap();
    certificate.set_version(2).unwrap();
    certificate.set_subject_name(&name).unwrap();
    certificate.set_issuer_name(&name).unwrap();
    certificate
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    certificate
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    certificate.set_pubkey(&private_key).unwrap();

    let mut serial = BigNum::new().unwrap();
    serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
    certificate
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();
    certificate
        .sign(&private_key, MessageDigest::sha256())
        .unwrap();

    (private_key, certificate.build())
}

fn boringssl_server(cipher: &AddedCipher) -> SslAcceptor {
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    acceptor
        .set_max_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    acceptor.set_cipher_list(cipher.rule_name).unwrap();

    match cipher.peer {
        CipherPeer::BoringSslRsa => {
            acceptor
                .set_certificate_chain_file("tests/cert.pem")
                .unwrap();
            acceptor
                .set_private_key_file("tests/key.pem", SslFiletype::PEM)
                .unwrap();
        }
        CipherPeer::BoringSslEcdsa => {
            let (private_key, certificate) = ecdsa_server_identity();
            acceptor.set_certificate(&certificate).unwrap();
            acceptor.set_private_key(&private_key).unwrap();
        }
        CipherPeer::OpenSslDhe => unreachable!(),
    }

    acceptor.build()
}

fn boringssl_client(cipher: &AddedCipher) -> Ssl {
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    connector
        .set_max_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    connector.set_cipher_list(cipher.rule_name).unwrap();
    connector.set_verify(SslVerifyMode::NONE);
    connector
        .build()
        .configure()
        .unwrap()
        .into_ssl("localhost")
        .unwrap()
}

fn assert_negotiated_cipher(cipher: &AddedCipher, negotiated: &SslCipherRef) {
    assert_eq!(
        negotiated.protocol_id(),
        cipher.id,
        "{} did not negotiate its expected IANA id",
        cipher.rule_name,
    );
    assert_eq!(
        negotiated.standard_name(),
        Some(cipher.standard_name),
        "{} negotiated an unexpected cipher",
        cipher.rule_name,
    );
}

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}

async fn negotiate_with_boringssl(cipher: &AddedCipher) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = boringssl_server(cipher);

    let server = async move {
        let socket = listener.accept().await.unwrap().0;
        let ssl = Ssl::new(acceptor.context()).unwrap();
        let mut stream = SslStream::new(ssl, socket).unwrap();
        Pin::new(&mut stream).accept().await.unwrap();

        for len in [1, 98, 99, 127, 128, 255, 256] {
            let mut received = vec![0; len];
            stream.read_exact(&mut received).await.unwrap();
            stream.write_all(&received).await.unwrap();
        }
    };

    let client = async {
        let socket = TcpStream::connect(addr).await.unwrap();
        let ssl = boringssl_client(cipher);
        let mut stream = SslStream::new(ssl, socket).unwrap();
        Pin::new(&mut stream).connect().await.unwrap();
        assert_negotiated_cipher(cipher, stream.ssl().current_cipher().unwrap());

        for len in [1, 98, 99, 127, 128, 255, 256] {
            let sent = payload(len);
            stream.write_all(&sent).await.unwrap();
            let mut received = vec![0; len];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, sent, "{} corrupted TLS data", cipher.rule_name);
        }
    };

    tokio::join!(server, client);
}

#[tokio::test]
async fn boringssl_patch_nondhe_ciphers_negotiate_individually() {
    for cipher in BORINGSSL_PATCH_ADDED_CIPHERS
        .iter()
        .filter(|cipher| cipher.peer != CipherPeer::OpenSslDhe)
    {
        negotiate_with_boringssl(cipher).await;
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
struct OpenSslServer {
    child: Option<Child>,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl OpenSslServer {
    fn spawn(addr: std::net::SocketAddr, cipher: &AddedCipher) -> Result<Self, String> {
        let cert_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../btls/test");
        let cipher_list = format!("{}:@SECLEVEL=0", cipher.rule_name);
        let child = Command::new("openssl")
            .arg("s_server")
            .arg("-accept")
            .arg(addr.to_string())
            .arg("-cert")
            .arg(cert_dir.join("cert.pem"))
            .arg("-key")
            .arg(cert_dir.join("key.pem"))
            .arg("-dhparam")
            .arg(cert_dir.join("dhparams.pem"))
            .arg("-cipher")
            .arg(cipher_list)
            .arg("-tls1_2")
            .arg("-www")
            .arg("-quiet")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("failed to start OpenSSL s_server: {error}"))?;

        Ok(Self { child: Some(child) })
    }

    fn wait_until_listening(&mut self, addr: std::net::SocketAddr) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let child = self.child.as_mut().unwrap();
            if let Some(status) = child
                .try_wait()
                .map_err(|error| format!("failed to query OpenSSL s_server: {error}"))?
            {
                return Err(format!("OpenSSL s_server exited early with {status}"));
            }

            if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("timed out waiting for OpenSSL s_server".to_owned());
            }
            thread::sleep(Duration::from_millis(25));
        }
    }

    fn stop(mut self) -> Output {
        let mut child = self.child.take().unwrap();
        let _ = child.kill();
        child.wait_with_output().unwrap()
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl Drop for OpenSslServer {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
async fn negotiate_with_openssl(
    addr: std::net::SocketAddr,
    cipher: &AddedCipher,
) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let socket = TcpStream::connect(addr)
            .await
            .map_err(|error| format!("failed to connect to OpenSSL s_server: {error}"))?;
        let ssl = boringssl_client(cipher);
        let mut stream = SslStream::new(ssl, socket)
            .map_err(|error| format!("failed to create TLS stream: {error}"))?;
        Pin::new(&mut stream)
            .connect()
            .await
            .map_err(|error| format!("TLS handshake failed: {error}"))?;
        let negotiated = stream
            .ssl()
            .current_cipher()
            .ok_or_else(|| "handshake completed without a cipher".to_owned())?;
        if negotiated.protocol_id() != cipher.id
            || negotiated.standard_name() != Some(cipher.standard_name)
        {
            return Err(format!(
                "expected {} ({:#06x}), negotiated {} ({:#06x})",
                cipher.standard_name,
                cipher.id,
                negotiated.standard_name().unwrap_or(negotiated.name()),
                negotiated.protocol_id(),
            ));
        }

        stream
            .write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .map_err(|error| format!("failed to write HTTP request: {error}"))?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .map_err(|error| format!("failed to read HTTP response: {error}"))?;
        if !response.starts_with(b"HTTP/1.") {
            return Err("OpenSSL s_server did not return an HTTP response".to_owned());
        }

        Ok(())
    })
    .await
    .map_err(|_| "timed out negotiating with OpenSSL s_server".to_owned())?
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[tokio::test]
async fn boringssl_patch_dhe_ciphers_negotiate_individually() {
    for cipher in BORINGSSL_PATCH_ADDED_CIPHERS
        .iter()
        .filter(|cipher| cipher.peer == CipherPeer::OpenSslDhe)
    {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let mut server = OpenSslServer::spawn(addr, cipher)
            .unwrap_or_else(|error| panic!("{}: {error}", cipher.rule_name));
        let result = match server.wait_until_listening(addr) {
            Ok(()) => negotiate_with_openssl(addr, cipher).await,
            Err(error) => Err(error),
        };
        let output = server.stop();

        if let Err(error) = result {
            panic!(
                "{}: {error}\nOpenSSL stdout:\n{}\nOpenSSL stderr:\n{}",
                cipher.rule_name,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
    }
}
