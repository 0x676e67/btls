use crate::error::{br, br_zero_is_success, BoringResult};
use btls::error::ErrorStack;
use btls::pkey::{HasPrivate, PKey};
use btls::ssl::{Ssl, SslContext, SslContextRef, SslSession};
use btls::x509::store::X509StoreBuilderRef;
use btls::x509::X509;
use btls_sys as bffi;
use bytes::{Buf, BufMut};
use foreign_types_shared::{ForeignType, ForeignTypeRef};
use std::ffi::{c_char, c_int, c_uint, c_void, CStr};
use std::fmt::{Display, Formatter};
use std::result::Result as StdResult;
use std::{ffi, fmt, mem, ptr, slice};

/// Provides additional methods to [SslContext] needed for QUIC.
pub trait QuicSslContext {
    fn set_options(&mut self, options: u32) -> u32;
    fn verify_peer(&mut self, verify: bool);
    fn set_quic_method(&mut self, method: &bffi::SSL_QUIC_METHOD) -> BoringResult;
    fn set_session_cache_mode(&mut self, mode: c_int) -> c_int;
    fn set_new_session_callback(
        &mut self,
        cb: Option<
            unsafe extern "C" fn(ssl: *mut bffi::SSL, session: *mut bffi::SSL_SESSION) -> c_int,
        >,
    );
    fn set_info_callback(
        &mut self,
        cb: Option<unsafe extern "C" fn(ssl: *const bffi::SSL, type_: c_int, value: c_int)>,
    );
    fn set_keylog_callback(
        &mut self,
        cb: Option<unsafe extern "C" fn(ssl: *const bffi::SSL, line: *const c_char)>,
    );
    fn set_certificate(&mut self, cert: X509) -> BoringResult;
    fn load_certificate_from_pem_file(&mut self, path: &str) -> BoringResult;
    fn add_to_cert_chain(&mut self, cert: X509) -> BoringResult;
    fn load_cert_chain_from_pem_file(&mut self, path: &str) -> BoringResult;
    fn set_private_key<T: HasPrivate>(&mut self, key: PKey<T>) -> BoringResult;
    fn load_private_key_from_pem_file(&mut self, path: &str) -> BoringResult;
    fn check_private_key(&self) -> BoringResult;
    fn cert_store_mut(&mut self) -> &mut X509StoreBuilderRef;

    fn enable_early_data(&mut self, enable: bool);
    fn set_alpn_protos(&mut self, protos: &[u8]) -> BoringResult;
    fn set_alpn_select_cb(
        &mut self,
        cb: Option<
            unsafe extern "C" fn(
                ssl: *mut bffi::SSL,
                out: *mut *const u8,
                out_len: *mut u8,
                in_: *const u8,
                in_len: c_uint,
                arg: *mut c_void,
            ) -> c_int,
        >,
    );
    fn set_server_name_cb(
        &mut self,
        cb: Option<
            unsafe extern "C" fn(
                ssl: *mut bffi::SSL,
                out_alert: *mut c_int,
                arg: *mut c_void,
            ) -> c_int,
        >,
    );
    fn set_select_certificate_cb(
        &mut self,
        cb: Option<
            unsafe extern "C" fn(
                arg1: *const bffi::SSL_CLIENT_HELLO,
            ) -> bffi::ssl_select_cert_result_t,
        >,
    );
}

impl QuicSslContext for SslContext {
    fn set_options(&mut self, options: u32) -> u32 {
        unsafe { bffi::SSL_CTX_set_options(self.as_ptr(), options) }
    }

    fn verify_peer(&mut self, verify: bool) {
        let mode = if verify {
            bffi::SSL_VERIFY_PEER | bffi::SSL_VERIFY_FAIL_IF_NO_PEER_CERT
        } else {
            bffi::SSL_VERIFY_NONE
        };

        unsafe { bffi::SSL_CTX_set_verify(self.as_ptr(), mode, None) }
    }

    fn set_quic_method(&mut self, method: &bffi::SSL_QUIC_METHOD) -> BoringResult {
        unsafe { br(bffi::SSL_CTX_set_quic_method(self.as_ptr(), method)) }
    }

    fn set_session_cache_mode(&mut self, mode: c_int) -> c_int {
        unsafe { bffi::SSL_CTX_set_session_cache_mode(self.as_ptr(), mode) }
    }

    fn set_new_session_callback(
        &mut self,
        cb: Option<
            unsafe extern "C" fn(ssl: *mut bffi::SSL, session: *mut bffi::SSL_SESSION) -> c_int,
        >,
    ) {
        unsafe {
            bffi::SSL_CTX_sess_set_new_cb(self.as_ptr(), cb);
        }
    }

    fn set_info_callback(
        &mut self,
        cb: Option<unsafe extern "C" fn(ssl: *const bffi::SSL, type_: c_int, value: c_int)>,
    ) {
        unsafe { bffi::SSL_CTX_set_info_callback(self.as_ptr(), cb) }
    }

    fn set_keylog_callback(
        &mut self,
        cb: Option<unsafe extern "C" fn(ssl: *const bffi::SSL, line: *const c_char)>,
    ) {
        unsafe { bffi::SSL_CTX_set_keylog_callback(self.as_ptr(), cb) }
    }

    fn set_certificate(&mut self, cert: X509) -> BoringResult {
        unsafe {
            br(bffi::SSL_CTX_use_certificate(self.as_ptr(), cert.as_ptr()))?;
            mem::forget(cert);
            Ok(())
        }
    }

    fn load_certificate_from_pem_file(&mut self, path: &str) -> BoringResult {
        let path = ffi::CString::new(path).unwrap();
        unsafe {
            br(bffi::SSL_CTX_use_certificate_file(
                self.as_ptr(),
                path.as_ptr(),
                bffi::SSL_FILETYPE_PEM,
            ))
        }
    }

    fn add_to_cert_chain(&mut self, cert: X509) -> BoringResult {
        unsafe {
            br(bffi::SSL_CTX_add_extra_chain_cert(self.as_ptr(), cert.as_ptr()) as c_int)?;
            mem::forget(cert);
            Ok(())
        }
    }

    fn load_cert_chain_from_pem_file(&mut self, path: &str) -> BoringResult {
        let path = ffi::CString::new(path).unwrap();
        unsafe {
            br(bffi::SSL_CTX_use_certificate_chain_file(
                self.as_ptr(),
                path.as_ptr(),
            ))
        }
    }

    fn set_private_key<T: HasPrivate>(&mut self, key: PKey<T>) -> BoringResult {
        unsafe {
            br(bffi::SSL_CTX_use_PrivateKey(self.as_ptr(), key.as_ptr()))?;
            mem::forget(key);
            Ok(())
        }
    }

    fn load_private_key_from_pem_file(&mut self, path: &str) -> BoringResult {
        let path = ffi::CString::new(path).unwrap();

        unsafe {
            br(bffi::SSL_CTX_use_PrivateKey_file(
                self.as_ptr(),
                path.as_ptr(),
                bffi::SSL_FILETYPE_PEM,
            ))
        }
    }

    fn check_private_key(&self) -> BoringResult {
        unsafe { br(bffi::SSL_CTX_check_private_key(self.as_ptr())) }
    }

    fn cert_store_mut(&mut self) -> &mut X509StoreBuilderRef {
        unsafe { X509StoreBuilderRef::from_ptr_mut(bffi::SSL_CTX_get_cert_store(self.as_ptr())) }
    }

    fn enable_early_data(&mut self, enable: bool) {
        unsafe { bffi::SSL_CTX_set_early_data_enabled(self.as_ptr(), enable.into()) }
    }

    fn set_alpn_protos(&mut self, protos: &[u8]) -> BoringResult {
        unsafe {
            br_zero_is_success(bffi::SSL_CTX_set_alpn_protos(
                self.as_ptr(),
                protos.as_ptr(),
                protos.len() as _,
            ))
        }
    }

    fn set_alpn_select_cb(
        &mut self,
        cb: Option<
            unsafe extern "C" fn(
                *mut bffi::SSL,
                *mut *const u8,
                *mut u8,
                *const u8,
                c_uint,
                *mut c_void,
            ) -> c_int,
        >,
    ) {
        unsafe { bffi::SSL_CTX_set_alpn_select_cb(self.as_ptr(), cb, ptr::null_mut()) }
    }

    fn set_server_name_cb(
        &mut self,
        cb: Option<
            unsafe extern "C" fn(
                ssl: *mut bffi::SSL,
                out_alert: *mut c_int,
                arg: *mut c_void,
            ) -> c_int,
        >,
    ) {
        // The function always returns 1.
        unsafe {
            let _ = bffi::SSL_CTX_set_tlsext_servername_callback(self.as_ptr(), cb);
        }
    }

    fn set_select_certificate_cb(
        &mut self,
        cb: Option<
            unsafe extern "C" fn(
                arg1: *const bffi::SSL_CLIENT_HELLO,
            ) -> bffi::ssl_select_cert_result_t,
        >,
    ) {
        unsafe { bffi::SSL_CTX_set_select_certificate_cb(self.as_ptr(), cb) }
    }
}

/// Provides additional methods to [Ssl] needed for QUIC.
pub trait QuicSsl {
    fn set_connect_state(&mut self);
    fn set_accept_state(&mut self);
    fn state_string(&self) -> &'static str;
    fn set_quic_transport_params(&mut self, params: &[u8]) -> BoringResult;
    fn get_peer_quic_transport_params(&self) -> Option<&[u8]>;
    fn get_error(&self, raw: c_int) -> SslError;
    fn is_handshaking(&self) -> bool;
    fn do_handshake(&mut self) -> SslError;
    fn provide_quic_data(&mut self, level: Level, data: &[u8]) -> SslError;
    fn quic_max_handshake_flight_len(&self, level: Level) -> usize;
    fn quic_read_level(&self) -> Level;
    fn quic_write_level(&self) -> Level;
    fn process_post_handshake(&mut self) -> SslError;
    fn set_verify_hostname(&mut self, domain: &str) -> BoringResult;
    fn export_keyring_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> BoringResult;

    fn in_early_data(&self) -> bool;
    fn early_data_accepted(&self) -> bool;
    fn set_quic_method(&mut self, method: &bffi::SSL_QUIC_METHOD) -> BoringResult;
    fn set_quic_early_data_context(&mut self, value: &[u8]) -> BoringResult;
    fn get_early_data_reason(&self) -> bffi::ssl_early_data_reason_t;
    fn early_data_reason_string(reason: bffi::ssl_early_data_reason_t) -> &'static str;
    fn reset_early_rejected_data(&mut self);
    fn set_quic_use_legacy_codepoint(&mut self, use_legacy: bool);
}

impl QuicSsl for Ssl {
    fn set_connect_state(&mut self) {
        unsafe { bffi::SSL_set_connect_state(self.as_ptr()) }
    }

    fn set_accept_state(&mut self) {
        unsafe { bffi::SSL_set_accept_state(self.as_ptr()) }
    }

    fn state_string(&self) -> &'static str {
        unsafe {
            CStr::from_ptr(bffi::SSL_state_string_long(self.as_ptr()))
                .to_str()
                .unwrap()
        }
    }

    fn set_quic_transport_params(&mut self, params: &[u8]) -> BoringResult {
        unsafe {
            br(bffi::SSL_set_quic_transport_params(
                self.as_ptr(),
                params.as_ptr(),
                params.len(),
            ))
        }
    }

    fn get_peer_quic_transport_params(&self) -> Option<&[u8]> {
        let mut ptr: *const u8 = ptr::null();
        let mut len: usize = 0;

        unsafe {
            bffi::SSL_get_peer_quic_transport_params(self.as_ptr(), &mut ptr, &mut len);

            if len == 0 {
                None
            } else {
                Some(slice::from_raw_parts(ptr, len))
            }
        }
    }

    #[inline]
    fn get_error(&self, raw: c_int) -> SslError {
        unsafe { SslError(bffi::SSL_get_error(self.as_ptr(), raw)) }
    }

    #[inline]
    fn is_handshaking(&self) -> bool {
        unsafe { bffi::SSL_in_init(self.as_ptr()) == 1 }
    }

    #[inline]
    fn do_handshake(&mut self) -> SslError {
        self.get_error(unsafe { bffi::SSL_do_handshake(self.as_ptr()) })
    }

    #[inline]
    fn provide_quic_data(&mut self, level: Level, plaintext: &[u8]) -> SslError {
        unsafe {
            self.get_error(bffi::SSL_provide_quic_data(
                self.as_ptr(),
                level.into(),
                plaintext.as_ptr(),
                plaintext.len(),
            ))
        }
    }

    #[inline]
    fn quic_max_handshake_flight_len(&self, level: Level) -> usize {
        unsafe { bffi::SSL_quic_max_handshake_flight_len(self.as_ptr(), level.into()) }
    }

    #[inline]
    fn quic_read_level(&self) -> Level {
        unsafe { bffi::SSL_quic_read_level(self.as_ptr()).into() }
    }

    #[inline]
    fn quic_write_level(&self) -> Level {
        unsafe { bffi::SSL_quic_write_level(self.as_ptr()).into() }
    }

    #[inline]
    fn process_post_handshake(&mut self) -> SslError {
        self.get_error(unsafe { bffi::SSL_process_quic_post_handshake(self.as_ptr()) })
    }

    fn set_verify_hostname(&mut self, domain: &str) -> BoringResult {
        let param = self.param_mut();
        param.set_hostflags(btls::x509::verify::X509CheckFlags::NO_PARTIAL_WILDCARDS);
        match domain.parse() {
            Ok(ip) => param.set_ip(ip)?,
            Err(_) => param.set_host(domain)?,
        }
        Ok(())
    }

    #[inline]
    fn export_keyring_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> BoringResult {
        unsafe {
            br(bffi::SSL_export_keying_material(
                self.as_ptr(),
                output.as_mut_ptr(),
                output.len(),
                label.as_ptr() as *const c_char,
                label.len(),
                context.as_ptr(),
                context.len(),
                context.is_empty() as _,
            ))
        }
    }

    #[inline]
    fn in_early_data(&self) -> bool {
        unsafe { bffi::SSL_in_early_data(self.as_ptr()) == 1 }
    }

    #[inline]
    fn early_data_accepted(&self) -> bool {
        unsafe { bffi::SSL_early_data_accepted(self.as_ptr()) == 1 }
    }

    fn set_quic_method(&mut self, method: &bffi::SSL_QUIC_METHOD) -> BoringResult {
        unsafe { br(bffi::SSL_set_quic_method(self.as_ptr(), method)) }
    }

    fn set_quic_early_data_context(&mut self, value: &[u8]) -> BoringResult {
        unsafe {
            br(bffi::SSL_set_quic_early_data_context(
                self.as_ptr(),
                value.as_ptr(),
                value.len(),
            ))
        }
    }

    fn get_early_data_reason(&self) -> bffi::ssl_early_data_reason_t {
        unsafe { bffi::SSL_get_early_data_reason(self.as_ptr()) }
    }

    fn early_data_reason_string(reason: bffi::ssl_early_data_reason_t) -> &'static str {
        unsafe {
            bffi::SSL_early_data_reason_string(reason)
                .as_ref()
                .map_or("unknown", |reason| CStr::from_ptr(reason).to_str().unwrap())
        }
    }

    #[inline]
    fn reset_early_rejected_data(&mut self) {
        unsafe { bffi::SSL_reset_early_data_reject(self.as_ptr()) }
    }

    fn set_quic_use_legacy_codepoint(&mut self, use_legacy: bool) {
        unsafe { bffi::SSL_set_quic_use_legacy_codepoint(self.as_ptr(), use_legacy as _) }
    }
}

pub trait QuicSslSession {
    fn early_data_capable(&self) -> bool;
    fn copy_without_early_data(&mut self) -> SslSession;
    fn encode<W: BufMut>(&self, out: &mut W) -> BoringResult;
    fn decode<R: Buf>(ctx: &SslContextRef, r: &mut R) -> StdResult<SslSession, ErrorStack>;
}

impl QuicSslSession for SslSession {
    fn early_data_capable(&self) -> bool {
        unsafe { bffi::SSL_SESSION_early_data_capable(self.as_ptr()) == 1 }
    }

    fn copy_without_early_data(&mut self) -> SslSession {
        unsafe { SslSession::from_ptr(bffi::SSL_SESSION_copy_without_early_data(self.as_ptr())) }
    }

    fn encode<W: BufMut>(&self, out: &mut W) -> BoringResult {
        unsafe {
            let mut buf: *mut u8 = ptr::null_mut();
            let mut len = 0usize;
            br(bffi::SSL_SESSION_to_bytes(
                self.as_ptr(),
                &mut buf,
                &mut len,
            ))?;
            out.put_slice(slice::from_raw_parts(buf, len));
            bffi::OPENSSL_free(buf as _);
            Ok(())
        }
    }

    fn decode<R: Buf>(ctx: &SslContextRef, r: &mut R) -> StdResult<SslSession, ErrorStack> {
        unsafe {
            let in_len = r.remaining();
            let in_ = r.chunk();
            bffi::SSL_SESSION_from_bytes(in_.as_ptr(), in_len, ctx.as_ptr())
                .as_mut()
                .map_or_else(
                    || Err(ErrorStack::get()),
                    |session| Ok(SslSession::from_ptr(session)),
                )
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Level {
    Initial = 0,
    EarlyData = 1,
    Handshake = 2,
    Application = 3,
}

impl Level {
    pub const NUM_LEVELS: usize = 4;

    pub fn next(&self) -> Self {
        match self {
            Level::Initial => Level::Handshake,
            Level::EarlyData => Level::Handshake,
            _ => Level::Application,
        }
    }
}

impl From<bffi::ssl_encryption_level_t> for Level {
    fn from(value: bffi::ssl_encryption_level_t) -> Self {
        match value {
            bffi::ssl_encryption_level_t::ssl_encryption_initial => Self::Initial,
            bffi::ssl_encryption_level_t::ssl_encryption_early_data => Self::EarlyData,
            bffi::ssl_encryption_level_t::ssl_encryption_handshake => Self::Handshake,
            bffi::ssl_encryption_level_t::ssl_encryption_application => Self::Application,
            _ => unreachable!(),
        }
    }
}

impl From<Level> for bffi::ssl_encryption_level_t {
    fn from(value: Level) -> Self {
        match value {
            Level::Initial => bffi::ssl_encryption_level_t::ssl_encryption_initial,
            Level::EarlyData => bffi::ssl_encryption_level_t::ssl_encryption_early_data,
            Level::Handshake => bffi::ssl_encryption_level_t::ssl_encryption_handshake,
            Level::Application => bffi::ssl_encryption_level_t::ssl_encryption_application,
        }
    }
}

#[derive(Copy, Clone)]
pub struct SslError(c_int);

impl SslError {
    #[inline]
    pub fn value(&self) -> c_int {
        self.0
    }

    #[inline]
    pub fn is_none(&self) -> bool {
        self.0 == bffi::SSL_ERROR_NONE
    }

    #[inline]
    pub fn get_description(&self) -> &'static str {
        unsafe {
            CStr::from_ptr(bffi::SSL_error_description(self.0))
                .to_str()
                .unwrap()
        }
    }
}

impl Display for SslError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "SSL_ERROR[{}]: {}", self.0, self.get_description())
    }
}
