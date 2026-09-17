use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::{ptr, slice};

use foreign_types::ForeignTypeRef;
use openssl_macros::corresponds;

use super::{Ssl, SslRef};
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
    pub payload_length: usize,
}

/// A read-only view of the first ClientHello, valid only during the callback.
///
/// Extension sizes exclude ECH, padding and PSK. The PSK size is supplied
/// separately. No extension writers are rerun to produce this view.
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

    /// Extension type and body length, excluding the four-byte extension header.
    pub fn extensions(&self) -> impl ExactSizeIterator<Item = (u16, usize)> + '_ {
        let extensions = if self.0.num_extensions == 0 {
            &[]
        } else {
            // Metadata is owned by the synchronous native callback invocation.
            unsafe { slice::from_raw_parts(self.0.extensions, self.0.num_extensions) }
        };
        extensions.iter().map(|ext| (ext.type_, ext.length))
    }

    /// ClientHello preamble length, excluding handshake and extensions headers.
    pub fn preamble_length(&self) -> usize {
        self.0.preamble_length
    }

    /// Pending PSK extension length, including its header; zero if absent.
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

    /// Maximum payload that fits alongside this ClientHello's other extensions.
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

type ParameterCallback =
    dyn Fn(&EchGreaseInfo<'_>) -> Result<EchGreaseParameters, ErrorStack> + Send + Sync;
struct Callback(Box<ParameterCallback>);
type StoredCallback = Option<Box<Callback>>;

unsafe extern "C" fn parameter_callback(
    info: *const ffi::SSL_ECH_GREASE_SIZE_INFO,
    out: *mut ffi::SSL_ECH_GREASE_PARAMETERS,
    arg: *mut c_void,
) -> libc::c_int {
    // The SSL's ex_data owns this stable Box until replacement or SSL destruction.
    // Neither the view nor its slices can escape the borrowed call.
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        let callback = &*arg.cast::<Callback>();
        (callback.0)(&EchGreaseInfo(&*info))
    }));
    match result {
        Ok(Ok(parameters)) => {
            unsafe {
                *out = ffi::SSL_ECH_GREASE_PARAMETERS {
                    aead_id: parameters.aead.0,
                    payload_length: parameters.payload_length,
                }
            };
            1
        }
        Ok(Err(error)) => {
            error.put();
            0
        }
        Err(_) => 0,
    }
}

impl SslRef {
    /// Selects ECH GREASE's AEAD identifier and final payload length together.
    ///
    /// Set before building ClientHello. Called once only when GREASE is needed;
    /// HRR and retransmissions reuse its bytes. This does not enable GREASE or
    /// affect real ECH or TLS cipher preferences. Replacing the callback after
    /// ClientHello starts fails without changing the previous callback.
    /// The callback belongs to this `Ssl`; install it separately on each new connection.
    ///
    /// Return a nonzero payload length at most [`EchGreaseInfo::max_payload_length`],
    /// including the simulated AEAD tag but excluding ECH framing. The callback
    /// controls AEAD selection and sizing; BoringSSL still generates the random bytes.
    /// Arbitrary lengths need not match [RFC 9849]'s recommended distribution.
    /// Returning an error or an invalid length fails the handshake.
    /// Panics are caught when unwinding is enabled and fail the handshake too.
    ///
    /// [RFC 9849]: https://www.rfc-editor.org/rfc/rfc9849.html#section-6.2.1
    #[corresponds(SSL_set_ech_grease_callback)]
    pub fn set_ech_grease_callback<F>(&mut self, callback: F) -> Result<(), ErrorStack>
    where
        F: Fn(&EchGreaseInfo<'_>) -> Result<EchGreaseParameters, ErrorStack>
            + Send
            + Sync
            + 'static,
    {
        let mut callback = Box::new(Callback(Box::new(callback)));
        let arg = ptr::from_mut(callback.as_mut()).cast::<c_void>();
        let ssl = self.as_ptr();
        // Allocate the ex_data slot before installing a pointer into the Box.
        let index = Ssl::cached_ex_index::<StoredCallback>();
        if self.ex_data(index).is_none() {
            self.set_ex_data(index, None);
        }
        let slot = self
            .ex_data_mut(index)
            .ok_or_else(|| ErrorStack::internal_error_str("missing ECH GREASE callback slot"))?;
        unsafe {
            cvt_0i(ffi::SSL_set_ech_grease_callback(
                ssl,
                Some(parameter_callback),
                arg,
            ))?;
        }
        // Store the new owner before dropping the old closure, whose Drop may panic.
        drop(slot.replace(callback));
        Ok(())
    }
}
