#![cfg(not(feature = "fips"))]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::ptr::{self, NonNull};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use foreign_types::ForeignTypeRef;

use crate::asn1::Asn1Time;
use crate::bn::BigNum;
use crate::ec::{EcGroup, EcKey};
use crate::ffi;
use crate::hash::MessageDigest;
use crate::nid::Nid;
use crate::pkey::{PKey, Private};
use crate::rsa::{Padding, Rsa};
use crate::sign::{RsaPssSaltlen, Signer};
use crate::ssl::{
    Ssl, SslContext, SslContextBuilder, SslMethod, SslSessionCacheMode, SslSignatureAlgorithm,
    SslVerifyMode, SslVersion,
};
use crate::x509::extension::KeyUsage;
use crate::x509::{X509Extension, X509NameBuilder, X509};

const DC_CERT_VERIFY_ALGORITHM: u16 = ffi::SSL_SIGN_ECDSA_SECP256R1_SHA256 as u16;
const DC_SIGNATURE_ALGORITHM: u16 = ffi::SSL_SIGN_RSA_PSS_RSAE_SHA256 as u16;

struct CryptoBuffer(NonNull<ffi::CRYPTO_BUFFER>);

impl CryptoBuffer {
    fn new(bytes: &[u8]) -> Self {
        let buffer =
            unsafe { ffi::CRYPTO_BUFFER_new(bytes.as_ptr(), bytes.len(), ptr::null_mut()) };
        Self(NonNull::new(buffer).expect("CRYPTO_BUFFER_new returned null"))
    }

    fn as_ptr(&self) -> *mut ffi::CRYPTO_BUFFER {
        self.0.as_ptr()
    }
}

impl Drop for CryptoBuffer {
    fn drop(&mut self) {
        unsafe { ffi::CRYPTO_BUFFER_free(self.as_ptr()) };
    }
}

struct TestSslCredential(NonNull<ffi::SSL_CREDENTIAL>);

impl TestSslCredential {
    fn new_delegated() -> Self {
        let credential = unsafe { ffi::SSL_CREDENTIAL_new_delegated() };
        Self(NonNull::new(credential).expect("SSL_CREDENTIAL_new_delegated returned null"))
    }

    fn as_ptr(&self) -> *mut ffi::SSL_CREDENTIAL {
        self.0.as_ptr()
    }
}

impl Drop for TestSslCredential {
    fn drop(&mut self) {
        unsafe { ffi::SSL_CREDENTIAL_free(self.as_ptr()) };
    }
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_u24_length_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    let len = u32::try_from(value.len()).unwrap();
    assert!(len <= 0x00ff_ffff);
    output.extend_from_slice(&len.to_be_bytes()[1..]);
    output.extend_from_slice(value);
}

fn make_delegation_certificate(now: i64) -> (PKey<Private>, X509) {
    let certificate_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "delegated-credential.test")
        .unwrap();
    let name = name.build();

    let mut certificate = X509::builder().unwrap();
    certificate.set_version(2).unwrap();
    certificate
        .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    certificate.set_subject_name(&name).unwrap();
    certificate.set_issuer_name(&name).unwrap();
    certificate
        .set_not_before(&Asn1Time::from_unix((now - 60 * 60) as _).unwrap())
        .unwrap();
    certificate
        .set_not_after(&Asn1Time::from_unix((now + 30 * 24 * 60 * 60) as _).unwrap())
        .unwrap();
    certificate.set_pubkey(&certificate_key).unwrap();

    let delegation_usage =
        X509Extension::new(None, None, "1.3.6.1.4.1.44363.44", "DER:05:00").unwrap();
    certificate.append_extension(&delegation_usage).unwrap();
    let key_usage = KeyUsage::new()
        .critical()
        .digital_signature()
        .build()
        .unwrap();
    certificate.append_extension(&key_usage).unwrap();
    certificate
        .sign(&certificate_key, MessageDigest::sha256())
        .unwrap();

    (certificate_key, certificate.build())
}

fn make_delegated_credential(
    certificate_key: &PKey<Private>,
    certificate: &X509,
    delegated_key: &PKey<Private>,
) -> Vec<u8> {
    let mut credential = Vec::new();
    // The certificate starts one hour before the test and the credential ends
    // one hour after it, so valid_time is two hours from certificate notBefore.
    credential.extend_from_slice(&(2 * 60 * 60_u32).to_be_bytes());
    push_u16(&mut credential, DC_CERT_VERIFY_ALGORITHM);
    push_u24_length_prefixed(&mut credential, &delegated_key.public_key_to_der().unwrap());

    // RFC 9345 signs the final standardized order. BoringSSL's upstream runner
    // still generates the older draft order, so keep this construction local
    // to the patch test rather than depending on that helper.
    let certificate_der = certificate.to_der().unwrap();
    let mut signed = vec![0x20; 64];
    signed.extend_from_slice(b"TLS, server delegated credentials\0");
    signed.extend_from_slice(&certificate_der);
    signed.extend_from_slice(&credential);
    push_u16(&mut signed, DC_SIGNATURE_ALGORITHM);

    let mut signer = Signer::new(MessageDigest::sha256(), certificate_key).unwrap();
    signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
    signer
        .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
        .unwrap();
    let signature = signer.sign_oneshot_to_vec(&signed).unwrap();
    let signature_len = u16::try_from(signature.len()).unwrap();

    let mut delegated_credential = credential;
    push_u16(&mut delegated_credential, DC_SIGNATURE_ALGORITHM);
    push_u16(&mut delegated_credential, signature_len);
    delegated_credential.extend_from_slice(&signature);
    delegated_credential
}

fn make_server_credential(
    certificate: &X509,
    delegated_key: &PKey<Private>,
    delegated_credential: &[u8],
) -> TestSslCredential {
    let certificate_der = CryptoBuffer::new(&certificate.to_der().unwrap());
    let delegated_credential = CryptoBuffer::new(delegated_credential);
    let credential = TestSslCredential::new_delegated();
    let chain = [certificate_der.as_ptr()];
    unsafe {
        assert_eq!(
            ffi::SSL_CREDENTIAL_set1_private_key(credential.as_ptr(), delegated_key.as_ptr()),
            1,
        );
        assert_eq!(
            ffi::SSL_CREDENTIAL_set1_cert_chain(credential.as_ptr(), chain.as_ptr(), chain.len(),),
            1,
        );
        assert_eq!(
            ffi::SSL_CREDENTIAL_set1_delegated_credential(
                credential.as_ptr(),
                delegated_credential.as_ptr(),
            ),
            1,
        );
    }
    credential
}

fn delegated_credential_contexts() -> (SslContextBuilder, SslContextBuilder) {
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let (certificate_key, certificate) = make_delegation_certificate(now);
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let delegated_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let delegated_credential =
        make_delegated_credential(&certificate_key, &certificate, &delegated_key);
    let credential = make_server_credential(&certificate, &delegated_key, &delegated_credential);

    let mut server_context = SslContext::builder(SslMethod::tls()).unwrap();
    server_context
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server_context
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    assert_eq!(
        unsafe { ffi::SSL_CTX_add1_credential(server_context.as_ptr(), credential.as_ptr()) },
        1,
    );
    let mut client_context = SslContext::builder(SslMethod::tls()).unwrap();
    client_context
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    client_context
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    client_context.set_verify(SslVerifyMode::NONE);
    client_context
        .set_verify_algorithm_prefs(&[SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256])
        .unwrap();
    client_context
        .set_delegated_credentials("ecdsa_secp256r1_sha256")
        .unwrap();

    (client_context, server_context)
}

fn accept_with_timeout(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                set_stream_timeouts(&stream);
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "timed out accepting test client");
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("failed to accept test client: {error}"),
        }
    }
}

fn set_stream_timeouts(stream: &TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .unwrap();
}

fn assert_delegated_credential_handshake(
    client_context: SslContextBuilder,
    server_context: SslContextBuilder,
) {
    let server_context = server_context.build();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let stream = accept_with_timeout(&listener);
        let ssl = Ssl::new(&server_context).unwrap();
        let mut stream = ssl.accept(stream).unwrap();
        stream.write_all(&[0x2a]).unwrap();
    });

    let ssl = Ssl::new(&client_context.build()).unwrap();
    assert!(!ssl.used_delegated_credential());
    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(30)).unwrap();
    set_stream_timeouts(&stream);
    let mut stream = ssl.connect(stream).unwrap();

    let mut byte = [0];
    stream.read_exact(&mut byte).unwrap();
    assert_eq!(byte, [0x2a]);
    assert!(stream.ssl().used_delegated_credential());
    assert_eq!(
        stream.ssl().peer_signature_algorithm(),
        Some(SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256),
    );
    server.join().unwrap();
}

// This exercises negotiation added by 0006-delegated-credentials.patch, not
// an upstream BoringSSL client capability. It also keeps the normal signature
// list distinct from the delegated credential's CertificateVerify algorithm.
#[test]
fn patch_delegated_credential_is_verified_and_used() {
    let (client_context, server_context) = delegated_credential_contexts();
    assert_delegated_credential_handshake(client_context, server_context);
}

// Cover the Rust API's documented input errors, including NUL rejection before
// FFI. An unsupported PSS-PSS name is not a request to use RSAE instead.
#[test]
fn patch_delegated_credential_rejects_invalid_algorithm_lists() {
    for algorithms in [
        "",
        "unknown_signature_algorithm",
        "ecdsa_secp256r1_sha256:unknown_signature_algorithm",
        "ecdsa_secp256r1_sha256:",
        "ecdsa_secp256r1_sha256\0:ecdsa_secp384r1_sha384",
        "rsa_pss_pss_sha256",
        "rsa_pss_pss_sha384",
        "rsa_pss_pss_sha512",
    ] {
        let mut context = SslContext::builder(SslMethod::tls()).unwrap();
        let error = context.set_delegated_credentials(algorithms).unwrap_err();
        assert!(!error.errors().is_empty(), "input: {algorithms:?}");
    }
}

#[test]
fn patch_delegated_credential_empty_list_does_not_disable_support() {
    let (mut client_context, server_context) = delegated_credential_contexts();
    assert!(client_context.set_delegated_credentials("").is_err());
    assert_delegated_credential_handshake(client_context, server_context);
}

// The public query describes authentication in this handshake, not the
// original session's authentication. No expiry or clock manipulation is needed.
#[test]
fn patch_delegated_credential_usage_is_false_on_resumption() {
    let (mut client_context, mut server_context) = delegated_credential_contexts();
    server_context.set_session_cache_mode(SslSessionCacheMode::SERVER);
    let server_context = server_context.build();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        for resumed in [false, true] {
            let stream = accept_with_timeout(&listener);
            let ssl = Ssl::new(&server_context).unwrap();
            let mut stream = ssl.accept(stream).unwrap();
            assert_eq!(stream.ssl().session_reused(), resumed);
            stream.write_all(&[0x2a]).unwrap();
            let mut reply = [0];
            stream.read_exact(&mut reply).unwrap();
            assert_eq!(reply, [0x2a]);
        }
    });

    let session = Arc::new(Mutex::new(None));
    client_context
        .set_session_cache_mode(SslSessionCacheMode::CLIENT | SslSessionCacheMode::NO_INTERNAL);
    client_context.set_new_session_callback({
        let session = session.clone();
        move |_, ticket| {
            let mut session = session.lock().unwrap();
            if session.is_none() {
                *session = Some(ticket);
            }
        }
    });
    let client_context = client_context.build();

    for resumed in [false, true] {
        let mut ssl = Ssl::new(&client_context).unwrap();
        assert!(!ssl.used_delegated_credential());
        if resumed {
            let ticket = session.lock().unwrap().take().expect("no session ticket");
            // SAFETY: This session came from the same SSL_CTX, and the new
            // connection has not started its handshake.
            unsafe { ssl.set_session(&ticket).unwrap() };
        }
        let stream = TcpStream::connect_timeout(&address, Duration::from_secs(30)).unwrap();
        set_stream_timeouts(&stream);
        let mut stream = ssl.connect(stream).unwrap();
        assert_eq!(stream.ssl().session_reused(), resumed);
        assert_eq!(stream.ssl().used_delegated_credential(), !resumed);
        // Reading application data processes the preceding TLS 1.3 tickets.
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [0x2a]);
        stream.write_all(&byte).unwrap();
    }
    server.join().unwrap();
}

#[test]
fn patch_delegated_credential_is_disabled_by_default() {
    let server = super::server::Server::builder().build();
    let stream = server.client().connect();
    assert!(!stream.ssl().used_delegated_credential());
}

#[test]
fn patch_delegated_credential_can_fall_back_to_certificate() {
    let server = super::server::Server::builder().build();
    let mut client = server.client();
    client
        .ctx()
        .set_delegated_credentials("ecdsa_secp256r1_sha256")
        .unwrap();
    let stream = client.connect();
    assert!(!stream.ssl().used_delegated_credential());
}
