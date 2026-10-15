use std::ffi::c_void;
use std::num::NonZeroU16;
use std::{ptr, slice};

use foreign_types::ForeignTypeRef;
use openssl_macros::corresponds;

use super::{Ssl, SslContext, SslContextBuilder, SslRef};
use crate::error::ErrorStack;
use crate::{cvt_0i, ffi};

/// An AEAD identifier advertised in an ECH GREASE extension.
/// This does not select the cipher used to protect the TLS connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EchGreaseAead(u16);

impl EchGreaseAead {
    /// AES-128-GCM.
    pub const AES_128_GCM: Self = Self(ffi::EVP_HPKE_AES_128_GCM as u16);
    /// ChaCha20-Poly1305.
    pub const CHACHA20_POLY1305: Self = Self(ffi::EVP_HPKE_CHACHA20_POLY1305 as u16);
}

/// Parameters for one ECH GREASE extension, reused unchanged after HRR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EchGreaseParameters {
    /// AEAD identifier to advertise; the payload remains random bytes.
    pub aead: EchGreaseAead,
    /// Final payload length, including the simulated tag but not ECH framing.
    /// Must not exceed [`EchGreaseInfo::max_payload_length`].
    pub payload_length: NonZeroU16,
}

/// A read-only view of the first ClientHello, valid only during the callback.
///
/// Extension sizes exclude their headers; PSK is reported separately.
pub struct EchGreaseInfo<'a>(&'a ffi::SSL_ECH_GREASE_SIZE_INFO);

impl EchGreaseInfo<'_> {
    /// Cipher suite IDs in wire order, each encoded as two big-endian bytes.
    pub fn cipher_suites(&self) -> &[u8] {
        if self.0.cipher_suites_length == 0 {
            return &[];
        }
        // BoringSSL owns the serialized preamble until the callback returns.
        unsafe { slice::from_raw_parts(self.0.cipher_suites, self.0.cipher_suites_length) }
    }

    /// Extension type and body length, excluding ECH, padding, PSK and headers.
    /// Includes [RFC 8701] GREASE extensions in wire order, after any permutation.
    /// Size policies must account for these GREASE entries too.
    ///
    /// [RFC 8701]: https://www.rfc-editor.org/rfc/rfc8701.html
    pub fn extensions(&self) -> impl ExactSizeIterator<Item = (u16, usize)> + '_ {
        let extensions = if self.0.num_extensions == 0 {
            &[]
        } else {
            // Metadata is owned by the synchronous native callback invocation.
            unsafe { slice::from_raw_parts(self.0.extensions, self.0.num_extensions) }
        };
        extensions.iter().map(|ext| (ext.type_, ext.length))
    }

    /// Wire preamble length, including the session ID and DTLS cookie, excluding
    /// handshake and extensions headers. This is not an encoded ECH Inner size.
    pub fn preamble_length(&self) -> usize {
        self.0.preamble_length
    }

    /// Pending PSK extension body length; zero if absent.
    pub fn psk_extension_length(&self) -> usize {
        self.0.psk_extension_length
    }

    /// Encoded SNI hostname length, or `None` when SNI is absent.
    pub fn server_name_length(&self) -> Option<usize> {
        (self.0.has_server_name != 0).then_some(self.0.server_name_length)
    }

    /// AEAD BoringSSL would advertise without this callback.
    pub fn default_aead(&self) -> EchGreaseAead {
        EchGreaseAead(self.0.default_aead_id)
    }

    /// Ciphertext expansion, shared by both supported GREASE AEADs.
    pub fn aead_overhead(&self) -> usize {
        self.0.aead_overhead
    }

    /// CH1's remaining extensions-vector frame budget, not a peer acceptance limit.
    /// BoringSSL servers normally limit a handshake message to 16 KiB.
    /// HRR may need more room for a cookie or a larger key share in CH2.
    pub fn max_payload_length(&self) -> usize {
        self.0.max_payload_length
    }

    /// Whether this is a DTLS ClientHello.
    pub fn is_dtls(&self) -> bool {
        self.0.is_dtls != 0
    }

    /// Whether this connection uses QUIC.
    pub fn is_quic(&self) -> bool {
        self.0.is_quic != 0
    }
}

struct Callback<F>(F);

unsafe extern "C" fn parameter_callback<F, const CONTEXT: bool>(
    info: *const ffi::SSL_ECH_GREASE_SIZE_INFO,
    out: *mut ffi::SSL_ECH_GREASE_PARAMETERS,
    _: *mut c_void,
) -> libc::c_int
where
    F: Fn(&SslRef, &EchGreaseInfo<'_>) -> Result<EchGreaseParameters, ErrorStack>
        + Send
        + Sync
        + 'static,
{
    // Both views borrow the synchronous invocation. Shared SSL access prevents
    // safe code from replacing the closure or reentering this handshake.
    let info = unsafe { &*info };
    let ssl = unsafe { SslRef::from_ptr(info.ssl.cast_mut()) };
    let callback = if CONTEXT {
        ssl.ssl_context()
            .ex_data(SslContext::cached_ex_index::<Option<Callback<F>>>())
    } else {
        ssl.ex_data(Ssl::cached_ex_index::<Option<Callback<F>>>())
    };
    let Some(Some(callback)) = callback else {
        return 0;
    };
    // Like the other SSL callbacks, a panic aborts at this extern "C" boundary.
    match (callback.0)(ssl, &EchGreaseInfo(info)) {
        Ok(parameters) => {
            unsafe {
                *out = ffi::SSL_ECH_GREASE_PARAMETERS {
                    aead_id: parameters.aead.0,
                    payload_length: usize::from(parameters.payload_length.get()),
                }
            };
            1
        }
        Err(error) => {
            error.put();
            0
        }
    }
}

impl SslContextBuilder {
    /// Sets the default ECH GREASE policy for connections using this context.
    ///
    /// Called once when CH1 needs GREASE; HRR reuses its bytes. Does not enable
    /// GREASE or change real ECH or TLS cipher preferences. Errors or oversized
    /// output fail the handshake; panics abort, as with other SSL callbacks.
    /// See [`EchGreaseInfo::max_payload_length`] for sizing limits. Arbitrary
    /// lengths need not follow [RFC 9849]'s recommended distribution.
    /// Unlike NSS, this also applies to DTLS when ECH GREASE is enabled.
    /// Callbacks of other closure types may remain stored until this context
    /// is freed, even after replacement.
    ///
    /// [RFC 9849]: https://www.rfc-editor.org/rfc/rfc9849.html#section-6.2.1
    #[corresponds(SSL_CTX_set_ech_grease_callback)]
    pub fn set_ech_grease_callback<F>(&mut self, callback: F)
    where
        F: Fn(&SslRef, &EchGreaseInfo<'_>) -> Result<EchGreaseParameters, ErrorStack>
            + Send
            + Sync
            + 'static,
    {
        let _old = self.replace_ex_data(
            SslContext::cached_ex_index::<Option<Callback<F>>>(),
            Some(Callback(callback)),
        );
        unsafe {
            ffi::SSL_CTX_set_ech_grease_callback(
                self.as_ptr(),
                Some(parameter_callback::<F, true>),
                ptr::null_mut(),
            );
        }
    }

    /// Removes the context policy, restoring BoringSSL's default parameters.
    /// Per-connection overrides and the GREASE enable flag are unchanged.
    /// Stored closures remain owned by the context until replaced or freed.
    #[corresponds(SSL_CTX_set_ech_grease_callback)]
    pub fn clear_ech_grease_callback(&mut self) {
        unsafe {
            ffi::SSL_CTX_set_ech_grease_callback(self.as_ptr(), None, ptr::null_mut());
        }
    }
}

impl SslRef {
    /// Overrides [`SslContextBuilder::set_ech_grease_callback`] for this connection.
    /// Requires retained handshake configuration and a handshake that has not
    /// started CH1. Rejection leaves the active callback unchanged.
    /// The same sizing, error and panic rules apply.
    /// Callbacks of other closure types may remain stored until this connection
    /// is freed, even after replacement.
    #[corresponds(SSL_set_ech_grease_callback)]
    pub fn set_ech_grease_callback<F>(&mut self, callback: F) -> Result<(), ErrorStack>
    where
        F: Fn(&SslRef, &EchGreaseInfo<'_>) -> Result<EchGreaseParameters, ErrorStack>
            + Send
            + Sync
            + 'static,
    {
        let ssl = self.as_ptr();
        let index = Ssl::cached_ex_index::<Option<Callback<F>>>();
        if self.ex_data(index).is_none() {
            self.set_ex_data(index, None);
        }
        let slot = self
            .ex_data_mut(index)
            .ok_or_else(|| ErrorStack::internal_error_str("missing ECH GREASE callback slot"))?;
        unsafe {
            cvt_0i(ffi::SSL_set_ech_grease_callback(
                ssl,
                Some(parameter_callback::<F, false>),
                ptr::null_mut(),
            ))?;
        }
        drop(slot.replace(Callback(callback)));
        Ok(())
    }

    /// Removes the connection override, falling back to the current context's
    /// policy or BoringSSL's default parameters. Does not disable GREASE.
    /// Fails without changing the policy if CH1 has started, the handshake has
    /// finished, or the handshake configuration has been discarded.
    /// Stored closures remain owned by the connection until replaced or freed.
    #[corresponds(SSL_set_ech_grease_callback)]
    pub fn clear_ech_grease_callback(&mut self) -> Result<(), ErrorStack> {
        unsafe {
            cvt_0i(ffi::SSL_set_ech_grease_callback(
                self.as_ptr(),
                None,
                ptr::null_mut(),
            ))?;
        }
        Ok(())
    }
}
