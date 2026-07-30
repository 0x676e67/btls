use std::ffi::{c_char, c_void, CStr, CString};
use std::path::{Path, PathBuf};
use std::ptr::{self, NonNull};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::net::{TcpListener, TcpStream};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::os::fd::AsRawFd;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::process::{Child, Command, Output, Stdio};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::thread;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::time::{Duration, Instant};

use crate as ffi;

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

// The 42/43-byte pair crosses SHA-256's 64-byte final-block boundary after
// TLS's 13-byte MAC header, 0x80 marker, and 8-byte length field. The 98/99-byte
// pair does the same for SHA-384's 128-byte block and 16-byte length field.
const RECORD_LENGTHS: &[usize] = &[
    1, 7, 8, 9, 15, 16, 17, 42, 43, 63, 64, 98, 99, 127, 128, 255, 256,
];

#[derive(Clone, Copy)]
enum Identity {
    Rsa,
    Ecdsa,
}

impl Identity {
    fn certificate(self) -> &'static str {
        match self {
            Self::Rsa => "rsa-cert.pem",
            Self::Ecdsa => "ecdsa-cert.pem",
        }
    }

    fn private_key(self) -> &'static str {
        match self {
            Self::Rsa => "rsa-key.pem",
            Self::Ecdsa => "ecdsa-key.pem",
        }
    }
}

struct SslContext(NonNull<ffi::SSL_CTX>);

impl SslContext {
    fn client(cipher: &AddedCipher) -> Self {
        Self::new(cipher, None)
    }

    fn server(cipher: &AddedCipher, identity: Identity) -> Self {
        Self::new(cipher, Some(identity))
    }

    fn new(cipher: &AddedCipher, identity: Option<Identity>) -> Self {
        let method = unsafe { ffi::TLS_method() };
        let context =
            NonNull::new(unsafe { ffi::SSL_CTX_new(method) }).expect("SSL_CTX_new returned null");
        let context = Self(context);
        let cipher_name = CString::new(cipher.rule_name).unwrap();
        let tls12 = u16::try_from(ffi::TLS1_2_VERSION).unwrap();

        unsafe {
            assert_eq!(
                ffi::SSL_CTX_set_min_proto_version(context.as_ptr(), tls12),
                1,
                "{} did not accept TLS 1.2 as its minimum version",
                cipher.rule_name,
            );
            assert_eq!(
                ffi::SSL_CTX_set_max_proto_version(context.as_ptr(), tls12),
                1,
                "{} did not accept TLS 1.2 as its maximum version",
                cipher.rule_name,
            );
            assert_eq!(
                ffi::SSL_CTX_set_strict_cipher_list(context.as_ptr(), cipher_name.as_ptr()),
                1,
                "{} is missing from the patched cipher list",
                cipher.rule_name,
            );
            ffi::SSL_CTX_set_verify(context.as_ptr(), ffi::SSL_VERIFY_NONE, None);
        }

        if let Some(identity) = identity {
            let certificate = fixture_c_string(identity.certificate());
            let private_key = fixture_c_string(identity.private_key());
            unsafe {
                assert_eq!(
                    ffi::SSL_CTX_use_certificate_chain_file(context.as_ptr(), certificate.as_ptr()),
                    1,
                    "{} could not load its test certificate",
                    cipher.rule_name,
                );
                assert_eq!(
                    ffi::SSL_CTX_use_PrivateKey_file(
                        context.as_ptr(),
                        private_key.as_ptr(),
                        ffi::SSL_FILETYPE_PEM,
                    ),
                    1,
                    "{} could not load its test private key",
                    cipher.rule_name,
                );
                assert_eq!(
                    ffi::SSL_CTX_check_private_key(context.as_ptr()),
                    1,
                    "{} received a mismatched test identity",
                    cipher.rule_name,
                );
            }
        }

        context
    }

    fn as_ptr(&self) -> *mut ffi::SSL_CTX {
        self.0.as_ptr()
    }
}

impl Drop for SslContext {
    fn drop(&mut self) {
        unsafe { ffi::SSL_CTX_free(self.as_ptr()) };
    }
}

struct SslHandle(NonNull<ffi::SSL>);

impl SslHandle {
    fn new(context: &SslContext) -> Self {
        Self(
            NonNull::new(unsafe { ffi::SSL_new(context.as_ptr()) }).expect("SSL_new returned null"),
        )
    }

    fn as_ptr(&self) -> *mut ffi::SSL {
        self.0.as_ptr()
    }

    fn handshake_step(&self) -> Result<bool, String> {
        let result = unsafe { ffi::SSL_do_handshake(self.as_ptr()) };
        if result == 1 {
            return Ok(true);
        }

        let error = unsafe { ffi::SSL_get_error(self.as_ptr(), result) };
        if error == ffi::SSL_ERROR_WANT_READ || error == ffi::SSL_ERROR_WANT_WRITE {
            Ok(false)
        } else {
            Err(ssl_failure(self.as_ptr(), result))
        }
    }

    fn write_all(&self, data: &[u8]) -> Result<(), String> {
        let len = i32::try_from(data.len()).map_err(|error| error.to_string())?;
        let written = unsafe { ffi::SSL_write(self.as_ptr(), data.as_ptr().cast::<c_void>(), len) };
        if written == len {
            Ok(())
        } else {
            Err(ssl_failure(self.as_ptr(), written))
        }
    }

    fn read_exact(&self, len: usize) -> Result<Vec<u8>, String> {
        let mut output = vec![0; len];
        let mut offset = 0;
        while offset < output.len() {
            let remaining =
                i32::try_from(output.len() - offset).map_err(|error| error.to_string())?;
            let read = unsafe {
                ffi::SSL_read(
                    self.as_ptr(),
                    output[offset..].as_mut_ptr().cast::<c_void>(),
                    remaining,
                )
            };
            if read <= 0 {
                return Err(ssl_failure(self.as_ptr(), read));
            }
            offset += usize::try_from(read).unwrap();
        }
        Ok(output)
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn read_to_end(&self) -> Result<Vec<u8>, String> {
        let mut output = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            let read = unsafe {
                ffi::SSL_read(
                    self.as_ptr(),
                    buffer.as_mut_ptr().cast::<c_void>(),
                    buffer.len() as i32,
                )
            };
            if read > 0 {
                output.extend_from_slice(&buffer[..usize::try_from(read).unwrap()]);
                continue;
            }

            let error = unsafe { ffi::SSL_get_error(self.as_ptr(), read) };
            if error == ffi::SSL_ERROR_ZERO_RETURN || (error == ffi::SSL_ERROR_SYSCALL && read == 0)
            {
                return Ok(output);
            }
            return Err(ssl_failure(self.as_ptr(), read));
        }
    }
}

impl Drop for SslHandle {
    fn drop(&mut self) {
        unsafe { ffi::SSL_free(self.as_ptr()) };
    }
}

struct SslPair {
    client: SslHandle,
    server: SslHandle,
}

impl SslPair {
    fn new(client_context: &SslContext, server_context: &SslContext) -> Self {
        let client = SslHandle::new(client_context);
        let server = SslHandle::new(server_context);
        unsafe {
            ffi::SSL_set_connect_state(client.as_ptr());
            ffi::SSL_set_accept_state(server.as_ptr());
        }

        let mut client_bio = ptr::null_mut();
        let mut server_bio = ptr::null_mut();
        assert_eq!(
            unsafe { ffi::BIO_new_bio_pair(&mut client_bio, 0, &mut server_bio, 0) },
            1,
            "BIO_new_bio_pair failed",
        );
        unsafe {
            // SSL_set_bio takes one reference when the read and write BIOs match.
            ffi::SSL_set_bio(client.as_ptr(), client_bio, client_bio);
            ffi::SSL_set_bio(server.as_ptr(), server_bio, server_bio);
        }

        Self { client, server }
    }

    fn handshake(&self) -> Result<(), String> {
        let mut client_done = false;
        let mut server_done = false;
        for _ in 0..100 {
            if !client_done {
                client_done = self.client.handshake_step()?;
            }
            if !server_done {
                server_done = self.server.handshake_step()?;
            }
            if client_done && server_done {
                return Ok(());
            }
        }
        Err("in-memory TLS handshake did not converge".to_owned())
    }
}

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("test")
        .join("data")
        .join(name)
}

fn fixture_c_string(name: &str) -> CString {
    CString::new(fixture_path(name).to_string_lossy().as_bytes()).unwrap()
}

fn ssl_failure(ssl: *mut ffi::SSL, result: i32) -> String {
    let category = unsafe { ffi::SSL_get_error(ssl, result) };
    let packed_error = unsafe { ffi::ERR_get_error() };
    if packed_error == 0 {
        return format!("SSL operation failed with category {category}");
    }

    let mut buffer = [0 as c_char; 256];
    unsafe {
        ffi::ERR_error_string_n(packed_error, buffer.as_mut_ptr(), buffer.len());
    }
    let detail = unsafe { CStr::from_ptr(buffer.as_ptr()) }.to_string_lossy();
    format!("SSL operation failed with category {category}: {detail}")
}

fn assert_negotiated_cipher(cipher: &AddedCipher, ssl: &SslHandle) -> Result<(), String> {
    let negotiated = unsafe { ffi::SSL_get_current_cipher(ssl.as_ptr()) };
    if negotiated.is_null() {
        return Err("handshake completed without a cipher".to_owned());
    }

    let id = unsafe { ffi::SSL_CIPHER_get_protocol_id(negotiated) };
    let standard_name = unsafe { ffi::SSL_CIPHER_standard_name(negotiated) };
    if standard_name.is_null() {
        return Err(format!(
            "{} negotiated cipher {id:#06x} without a standard name",
            cipher.rule_name
        ));
    }
    let standard_name = unsafe { CStr::from_ptr(standard_name) }.to_string_lossy();

    if id != cipher.id || standard_name != cipher.standard_name {
        return Err(format!(
            "expected {} ({:#06x}), negotiated {} ({id:#06x})",
            cipher.standard_name, cipher.id, standard_name,
        ));
    }
    Ok(())
}

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}

fn negotiate_with_boringssl(cipher: &AddedCipher, record_lengths: impl IntoIterator<Item = usize>) {
    let identity = match cipher.peer {
        CipherPeer::BoringSslRsa => Identity::Rsa,
        CipherPeer::BoringSslEcdsa => Identity::Ecdsa,
        CipherPeer::OpenSslDhe => unreachable!(),
    };
    let client_context = SslContext::client(cipher);
    let server_context = SslContext::server(cipher, identity);
    let pair = SslPair::new(&client_context, &server_context);

    pair.handshake()
        .unwrap_or_else(|error| panic!("{}: {error}", cipher.rule_name));
    assert_negotiated_cipher(cipher, &pair.client)
        .unwrap_or_else(|error| panic!("{}: {error}", cipher.rule_name));

    for len in record_lengths {
        let sent = payload(len);
        pair.client
            .write_all(&sent)
            .unwrap_or_else(|error| panic!("{}: {error}", cipher.rule_name));
        let received = pair
            .server
            .read_exact(len)
            .unwrap_or_else(|error| panic!("{}: {error}", cipher.rule_name));
        assert_eq!(received, sent, "{} corrupted client data", cipher.rule_name);

        pair.server
            .write_all(&received)
            .unwrap_or_else(|error| panic!("{}: {error}", cipher.rule_name));
        let echoed = pair
            .client
            .read_exact(len)
            .unwrap_or_else(|error| panic!("{}: {error}", cipher.rule_name));
        assert_eq!(echoed, sent, "{} corrupted server data", cipher.rule_name);
    }
}

#[test]
fn boringssl_patch_nondhe_ciphers_negotiate_individually() {
    ffi::init();
    for cipher in BORINGSSL_PATCH_ADDED_CIPHERS
        .iter()
        .filter(|cipher| cipher.peer != CipherPeer::OpenSslDhe)
    {
        negotiate_with_boringssl(cipher, RECORD_LENGTHS.iter().copied());
    }
}

#[test]
fn boringssl_patch_sha2_cbc_record_lengths_are_exhaustive() {
    ffi::init();
    for cipher in BORINGSSL_PATCH_ADDED_CIPHERS
        .iter()
        .filter(|cipher| cipher.peer != CipherPeer::OpenSslDhe)
    {
        let max_len = match cipher.id {
            // Three complete SHA-256 blocks exercise every 64-byte alignment.
            0x003c | 0x003d => 3 * 64,
            // BoringSSL previously fixed SHA-384's short-message block count.
            // https://github.com/google/boringssl/commit/144d924e0b3c3a5ceb7083a408ba69b7cca1a25c
            0xc024 | 0xc028 => 3 * 128,
            _ => continue,
        };
        negotiate_with_boringssl(cipher, 1..=max_len);
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
struct OpenSslServer {
    child: Option<Child>,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl OpenSslServer {
    fn spawn(addr: std::net::SocketAddr, cipher: &AddedCipher) -> Result<Self, String> {
        let cipher_list = format!("{}:@SECLEVEL=0", cipher.rule_name);
        let child = Command::new("openssl")
            .arg("s_server")
            .arg("-accept")
            .arg(addr.to_string())
            .arg("-cert")
            .arg(fixture_path("rsa-cert.pem"))
            .arg("-key")
            .arg(fixture_path("rsa-key.pem"))
            .arg("-dhparam")
            .arg(fixture_path("dhparams.pem"))
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

            if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
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
fn negotiate_with_openssl(addr: std::net::SocketAddr, cipher: &AddedCipher) -> Result<(), String> {
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .map_err(|error| format!("failed to connect to OpenSSL s_server: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| format!("failed to set the read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| format!("failed to set the write timeout: {error}"))?;

    let context = SslContext::client(cipher);
    let ssl = SslHandle::new(&context);
    unsafe {
        ffi::SSL_set_connect_state(ssl.as_ptr());
        if ffi::SSL_set_fd(ssl.as_ptr(), stream.as_raw_fd()) != 1 {
            return Err("SSL_set_fd failed".to_owned());
        }
    }

    let result = unsafe { ffi::SSL_connect(ssl.as_ptr()) };
    if result != 1 {
        return Err(ssl_failure(ssl.as_ptr(), result));
    }
    assert_negotiated_cipher(cipher, &ssl)?;

    ssl.write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let response = ssl.read_to_end()?;
    if !response.starts_with(b"HTTP/1.") {
        return Err("OpenSSL s_server did not return an HTTP response".to_owned());
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn boringssl_patch_dhe_ciphers_negotiate_individually() {
    ffi::init();
    for cipher in BORINGSSL_PATCH_ADDED_CIPHERS
        .iter()
        .filter(|cipher| cipher.peer == CipherPeer::OpenSslDhe)
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let mut server = OpenSslServer::spawn(addr, cipher)
            .unwrap_or_else(|error| panic!("{}: {error}", cipher.rule_name));
        let result = match server.wait_until_listening(addr) {
            Ok(()) => negotiate_with_openssl(addr, cipher),
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
