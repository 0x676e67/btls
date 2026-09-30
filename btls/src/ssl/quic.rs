//! QUIC support for TLS 1.3 connections ([RFC 9001](https://www.rfc-editor.org/rfc/rfc9001)).
//!
//! A QUIC connection has no BIO. BoringSSL hands its secrets and handshake messages to the
//! [`QuicMethod`] of the context instead of writing records, and takes the peer's handshake
//! messages through [`SslRef::provide_quic_data`].

use super::{ErrorCode, SslAlert, SslCipherRef, SslContext, SslContextBuilder, SslRef};
use crate::error::ErrorStack;
use crate::{cvt, ffi};
use foreign_types::ForeignTypeRef;
use openssl_macros::corresponds;
use std::ffi::c_int;
use std::marker::PhantomData;
use std::{ptr, slice};

/// A QUIC encryption level ([RFC 9001 §4.1.4](https://www.rfc-editor.org/rfc/rfc9001#section-4.1.4)).
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct QuicEncryptionLevel(ffi::ssl_encryption_level_t);

impl QuicEncryptionLevel {
    pub const INITIAL: Self = Self(ffi::ssl_encryption_level_t::ssl_encryption_initial);
    pub const EARLY_DATA: Self = Self(ffi::ssl_encryption_level_t::ssl_encryption_early_data);
    pub const HANDSHAKE: Self = Self(ffi::ssl_encryption_level_t::ssl_encryption_handshake);
    pub const APPLICATION: Self = Self(ffi::ssl_encryption_level_t::ssl_encryption_application);
}

/// A failed [`QuicMethod`] callback, which terminates the handshake.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct QuicMethodError;

/// The QUIC hooks of a context (`SSL_QUIC_METHOD`), see [`SslContextBuilder::set_quic_method`].
///
/// BoringSSL calls them from inside calls on the connection, such as
/// [`SslRef::do_handshake`] and [`SslRef::provide_quic_data`]. Per-connection state belongs in
/// the connection's ex data. An error terminates the handshake.
pub trait QuicMethod: Send + Sync + 'static {
    /// Installs the read secret and cipher suite of `level`. BoringSSL calls it at most once per
    /// level, and only after the write secret that ACKs the packets it protects.
    fn set_read_secret(
        &self,
        ssl: &mut SslRef,
        level: QuicEncryptionLevel,
        cipher: &SslCipherRef,
        secret: &[u8],
    ) -> Result<(), QuicMethodError>;

    /// Installs the write secret and cipher suite of `level`, at most once per level.
    fn set_write_secret(
        &self,
        ssl: &mut SslRef,
        level: QuicEncryptionLevel,
        cipher: &SslCipherRef,
        secret: &[u8],
    ) -> Result<(), QuicMethodError>;

    /// Adds handshake data to the current flight at `level`.
    fn add_handshake_data(
        &self,
        ssl: &mut SslRef,
        level: QuicEncryptionLevel,
        data: &[u8],
    ) -> Result<(), QuicMethodError>;

    /// Signals that the current flight, which may span several levels, is complete.
    fn flush_flight(&self, ssl: &mut SslRef) -> Result<(), QuicMethodError>;

    /// Sends a fatal alert at `level`.
    fn send_alert(
        &self,
        ssl: &mut SslRef,
        level: QuicEncryptionLevel,
        alert: SslAlert,
    ) -> Result<(), QuicMethodError>;
}

/// The `SSL_QUIC_METHOD` of `M`, which BoringSSL keeps a pointer to.
struct QuicMethodTable<M>(PhantomData<M>);

impl<M: QuicMethod> QuicMethodTable<M> {
    const METHOD: ffi::SSL_QUIC_METHOD = ffi::SSL_QUIC_METHOD {
        set_read_secret: Some(raw_set_read_secret::<M>),
        set_write_secret: Some(raw_set_write_secret::<M>),
        add_handshake_data: Some(raw_add_handshake_data::<M>),
        flush_flight: Some(raw_flush_flight::<M>),
        send_alert: Some(raw_send_alert::<M>),
    };
}

impl SslContextBuilder {
    /// Configures the context for QUIC, with `method` receiving the secrets and handshake data
    /// of its connections.
    #[corresponds(SSL_CTX_set_quic_method)]
    pub fn set_quic_method<M: QuicMethod>(&mut self, method: M) -> Result<(), ErrorStack> {
        self.replace_ex_data(SslContext::cached_ex_index::<M>(), method);
        // A promoted constant, so the table lives for the whole program.
        let table: &'static ffi::SSL_QUIC_METHOD = &QuicMethodTable::<M>::METHOD;
        unsafe { cvt(ffi::SSL_CTX_set_quic_method(self.as_ptr(), table)) }
    }
}

impl SslRef {
    /// Makes the connection a client, for connections without a BIO such as QUIC ones.
    #[corresponds(SSL_set_connect_state)]
    pub fn set_connect_state(&mut self) {
        unsafe { ffi::SSL_set_connect_state(self.as_ptr()) }
    }

    /// Makes the connection a server, for connections without a BIO such as QUIC ones.
    #[corresponds(SSL_set_accept_state)]
    pub fn set_accept_state(&mut self) {
        unsafe { ffi::SSL_set_accept_state(self.as_ptr()) }
    }

    /// Advances the handshake of a connection without a BIO, such as a QUIC one. Streams use
    /// [`SslStream::do_handshake`](super::SslStream::do_handshake) instead.
    ///
    /// [`ErrorCode::WANT_READ`] means the handshake waits for peer data. On [`ErrorCode::SSL`],
    /// the reason is on the error queue.
    #[corresponds(SSL_do_handshake)]
    pub fn do_handshake(&mut self) -> Result<(), ErrorCode> {
        let ret = unsafe { ffi::SSL_do_handshake(self.as_ptr()) };
        if ret == 1 {
            Ok(())
        } else {
            Err(self.error_code(ret))
        }
    }

    /// Sets the transport parameters this endpoint sends
    /// ([RFC 9001 §8.2](https://www.rfc-editor.org/rfc/rfc9001#section-8.2)).
    #[corresponds(SSL_set_quic_transport_params)]
    pub fn set_quic_transport_params(&mut self, params: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::SSL_set_quic_transport_params(
                self.as_ptr(),
                params.as_ptr(),
                params.len(),
            ))
        }
    }

    /// Returns the transport parameters the peer sent, once they arrived.
    #[corresponds(SSL_get_peer_quic_transport_params)]
    #[must_use]
    pub fn peer_quic_transport_params(&self) -> Option<&[u8]> {
        let mut params = ptr::null();
        let mut len = 0;
        unsafe {
            ffi::SSL_get_peer_quic_transport_params(self.as_ptr(), &mut params, &mut len);
            if len == 0 {
                None
            } else {
                Some(slice::from_raw_parts(params, len))
            }
        }
    }

    /// Selects the legacy codepoint 0xffa5 of the transport parameters extension instead of the
    /// standard 57, for draft versions of QUIC.
    #[corresponds(SSL_set_quic_use_legacy_codepoint)]
    pub fn set_quic_use_legacy_codepoint(&mut self, use_legacy: bool) {
        unsafe { ffi::SSL_set_quic_use_legacy_codepoint(self.as_ptr(), use_legacy.into()) }
    }

    /// Sets the context a server accepts 0-RTT under. BoringSSL stores it in the tickets it
    /// issues, and rejects 0-RTT from a ticket with another one. It should cover the transport
    /// parameters and application state that 0-RTT depends on
    /// ([RFC 9000 §7.4.1](https://www.rfc-editor.org/rfc/rfc9000#section-7.4.1)). Without it,
    /// a QUIC server issues no tickets for 0-RTT.
    #[corresponds(SSL_set_quic_early_data_context)]
    pub fn set_quic_early_data_context(&mut self, context: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::SSL_set_quic_early_data_context(
                self.as_ptr(),
                context.as_ptr(),
                context.len(),
            ))
        }
    }

    /// Returns the level that peer handshake data is expected at.
    #[corresponds(SSL_quic_read_level)]
    #[must_use]
    pub fn quic_read_level(&self) -> QuicEncryptionLevel {
        QuicEncryptionLevel(unsafe { ffi::SSL_quic_read_level(self.as_ptr()) })
    }

    /// Returns the level that handshake data is written at.
    #[corresponds(SSL_quic_write_level)]
    #[must_use]
    pub fn quic_write_level(&self) -> QuicEncryptionLevel {
        QuicEncryptionLevel(unsafe { ffi::SSL_quic_write_level(self.as_ptr()) })
    }

    /// Returns the most handshake data the peer may send at `level`, to bound buffering
    /// ([RFC 9000 §7.5](https://www.rfc-editor.org/rfc/rfc9000#section-7.5)).
    #[corresponds(SSL_quic_max_handshake_flight_len)]
    #[must_use]
    pub fn quic_max_handshake_flight_len(&self, level: QuicEncryptionLevel) -> usize {
        unsafe { ffi::SSL_quic_max_handshake_flight_len(self.as_ptr(), level.0) }
    }

    /// Provides handshake data the peer sent at `level`. It fails if the handshake does not
    /// expect data at `level`, and the connection should then be closed.
    #[corresponds(SSL_provide_quic_data)]
    pub fn provide_quic_data(
        &mut self,
        level: QuicEncryptionLevel,
        data: &[u8],
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::SSL_provide_quic_data(
                self.as_ptr(),
                level.0,
                data.as_ptr(),
                data.len(),
            ))
        }
    }

    /// Processes the handshake data provided after the handshake, such as session tickets.
    #[corresponds(SSL_process_quic_post_handshake)]
    pub fn process_quic_post_handshake(&mut self) -> Result<(), ErrorCode> {
        let ret = unsafe { ffi::SSL_process_quic_post_handshake(self.as_ptr()) };
        if ret == 1 {
            Ok(())
        } else {
            Err(self.error_code(ret))
        }
    }
}

/// Finds the [`QuicMethod`] of the context `ssl` belongs to and runs `f` with it.
fn with_method<M: QuicMethod>(
    ssl: *mut ffi::SSL,
    f: impl FnOnce(&M, &mut SslRef) -> Result<(), QuicMethodError>,
) -> c_int {
    // SAFETY: BoringSSL passes the callbacks the `SSL` they run for.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
    let ssl_context = ssl.ssl_context().to_owned();
    let Some(method) = ssl_context.ex_data(SslContext::cached_ex_index::<M>()) else {
        return 0;
    };
    f(method, ssl).is_ok().into()
}

unsafe extern "C" fn raw_set_read_secret<M: QuicMethod>(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    cipher: *const ffi::SSL_CIPHER,
    secret: *const u8,
    secret_len: usize,
) -> c_int {
    // SAFETY: BoringSSL passes the cipher suite and a secret of `secret_len` bytes.
    let cipher = unsafe { SslCipherRef::from_ptr(cipher.cast_mut()) };
    let secret = unsafe { slice::from_raw_parts(secret, secret_len) };
    with_method::<M>(ssl, |method, ssl| {
        method.set_read_secret(ssl, QuicEncryptionLevel(level), cipher, secret)
    })
}

unsafe extern "C" fn raw_set_write_secret<M: QuicMethod>(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    cipher: *const ffi::SSL_CIPHER,
    secret: *const u8,
    secret_len: usize,
) -> c_int {
    // SAFETY: BoringSSL passes the cipher suite and a secret of `secret_len` bytes.
    let cipher = unsafe { SslCipherRef::from_ptr(cipher.cast_mut()) };
    let secret = unsafe { slice::from_raw_parts(secret, secret_len) };
    with_method::<M>(ssl, |method, ssl| {
        method.set_write_secret(ssl, QuicEncryptionLevel(level), cipher, secret)
    })
}

unsafe extern "C" fn raw_add_handshake_data<M: QuicMethod>(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    data: *const u8,
    len: usize,
) -> c_int {
    // SAFETY: BoringSSL passes `len` bytes of handshake data.
    let data = unsafe { slice::from_raw_parts(data, len) };
    with_method::<M>(ssl, |method, ssl| {
        method.add_handshake_data(ssl, QuicEncryptionLevel(level), data)
    })
}

unsafe extern "C" fn raw_flush_flight<M: QuicMethod>(ssl: *mut ffi::SSL) -> c_int {
    with_method::<M>(ssl, |method, ssl| method.flush_flight(ssl))
}

unsafe extern "C" fn raw_send_alert<M: QuicMethod>(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    alert: u8,
) -> c_int {
    with_method::<M>(ssl, |method, ssl| {
        method.send_alert(ssl, QuicEncryptionLevel(level), SslAlert(alert.into()))
    })
}
