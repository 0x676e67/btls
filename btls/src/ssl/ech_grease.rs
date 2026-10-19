use std::ffi::c_void;
use std::num::NonZeroU16;
use std::{ptr, slice};

use foreign_types::ForeignTypeRef;
use openssl_macros::corresponds;

use super::{Ssl, SslContext, SslContextBuilder, SslRef};
use crate::error::ErrorStack;
use crate::rand::rand_bytes;
use crate::{cvt_0i, ffi};

const TLS_EXTENSION_HEADER_LEN: usize = 4;
// NSS's deprecated ticket_early_data_info, dropped from the inner hello.
const NSS_TICKET_EARLY_DATA_INFO: u16 = 46;

/// An AEAD identifier advertised in an ECH GREASE extension.
/// This does not select the cipher used to protect the TLS connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EchGreaseAead(u16);

impl EchGreaseAead {
    /// AES-128-GCM.
    pub const AES_128_GCM: Self = Self(ffi::EVP_HPKE_AES_128_GCM as u16);
    /// ChaCha20-Poly1305.
    pub const CHACHA20_POLY1305: Self = Self(ffi::EVP_HPKE_CHACHA20_POLY1305 as u16);

    /// Returns the HPKE AEAD identifier encoded in the extension.
    pub const fn id(self) -> u16 {
        self.0
    }
}

/// Rounding used by NSS when padding an ECH GREASE inner ClientHello.
/// This does not change other TLS settings.
/// Custom callbacks can return [`EchGreaseParameters`] without using these rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EchGreaseRounding {
    /// NSS before 3.127, as used by Firefox 119-154: pad to `32k + 31`.
    /// This reproduces the historical behavior, not RFC 9849's padding rule.
    NssPre3127,
    /// Round up to a multiple of 32 ([RFC 9849] 6.1.3), as in NSS 3.127 /
    /// Firefox 155 onward. See the [official fix] for Bug 2060720.
    ///
    /// [RFC 9849]: https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1.3
    /// [official fix]: https://firefox-source-docs.mozilla.org/security/nss/releases/nss_3_127.html
    Rfc9849,
}

/// Parameters for one ECH GREASE extension, reused unchanged after HRR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EchGreaseParameters {
    /// AEAD identifier to advertise; the payload remains random bytes.
    pub aead: EchGreaseAead,
    /// Final payload length, including the simulated tag but not ECH framing.
    /// Must not exceed [`EchGreaseInfo::max_payload_length`].
    pub payload_length: NonZeroU16,
    /// Send uniformly random bytes as `enc`, as NSS does, instead of an X25519
    /// public key. A canonical key always has bit 255 clear, so the choice is
    /// observable across connections.
    pub random_enc: bool,
}

/// A read-only view of the first ClientHello, valid only during the callback.
///
/// Extension sizes exclude their headers; PSK is reported separately.
pub struct EchGreaseInfo<'a>(pub(crate) &'a ffi::SSL_ECH_GREASE_SIZE_INFO);

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

    /// Host name length read from the serialized SNI extension, or `None` when
    /// no hostname was set; the connector sets none for IP literals.
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
    /// See [`message_length`](Self::message_length) for the 16 KiB BoringSSL limit.
    /// HRR may need more room for a cookie or a larger key share in CH2;
    /// dropping CH1's padding can also make CH2 shorter.
    pub fn max_payload_length(&self) -> usize {
        self.0.max_payload_length
    }

    /// ClientHello body length before the payload, including ECH framing, PSK
    /// and reserved padding. CH1's body is this plus the payload length, except
    /// that TLS over TCP pads a message of 256 to 511 bytes, header included,
    /// to at least 512 ([RFC 7685]). A BoringSSL server rejects a ClientHello
    /// above 16 KiB unless it requests client certificates.
    ///
    /// [RFC 7685]: https://www.rfc-editor.org/rfc/rfc7685.html
    pub fn message_length(&self) -> usize {
        self.0.message_length
    }

    /// Whether this is a DTLS ClientHello.
    pub fn is_dtls(&self) -> bool {
        self.0.is_dtls != 0
    }

    /// Whether this connection uses QUIC.
    pub fn is_quic(&self) -> bool {
        self.0.is_quic != 0
    }

    /// NSS-shaped payload length, including the tag, with explicit rounding.
    ///
    /// Follows NSS's [`tls13_MaybeGreaseEch`]: the inner hello keeps
    /// `server_name`, `supported_versions` (TLS 1.3 only) and `pre_shared_key`
    /// in full, drops the TLS 1.2-only extensions, compresses the rest, pads
    /// the host name to `max_name_len`, then applies `rounding`. Use
    /// [`EchGreaseRounding::NssPre3127`] for Firefox 119-154 or
    /// [`EchGreaseRounding::Rfc9849`] for the [NSS 3.127] fix.
    /// `max_name_len` is Firefox's `security.tls.ech.grease_size`, 100 by
    /// default. `host_len` is the URL host length, which NSS narrows to `u8`
    /// and applies even without SNI, as for IP literals. A GREASE version is
    /// assumed exactly when [RFC 8701] GREASE extensions are present, since
    /// BoringSSL emits both under the same flag. NSS never GREASEs DTLS; the
    /// rule is still evaluated there. Wire order follows the configured
    /// extension order, so list ECH last to match NSS; with GREASE enabled the
    /// trailing [RFC 8701] extension still follows ECH, unlike NSS.
    ///
    /// [NSS 3.127]: https://firefox-source-docs.mozilla.org/security/nss/releases/nss_3_127.html
    /// [`tls13_MaybeGreaseEch`]: https://github.com/nss-dev/nss/blob/42dc6cfddbcee57f391dd1b4550604e68437986d/lib/ssl/tls13ech.c#L2143
    /// [RFC 8701]: https://www.rfc-editor.org/rfc/rfc8701.html
    pub fn nss_payload_length(
        &self,
        max_name_len: u8,
        host_len: u8,
        rounding: EchGreaseRounding,
    ) -> usize {
        // EncodedClientHelloInner uses an empty session ID and the outer ciphers.
        let mut len = 2 + 32 + 1 + 2 + self.cipher_suites().len() + 1 + 1 + 2;
        len += TLS_EXTENSION_HEADER_LEN + 1; // Inner encrypted_client_hello marker.
        if let Some(sni) = self.server_name_length() {
            len += TLS_EXTENSION_HEADER_LEN + 5 + sni;
        }
        let mut compressed = 0;
        let mut grease_version = false;
        for (kind, _) in self.extensions() {
            if is_grease_type(kind) {
                grease_version = true;
            }
            // Omit the TLS 1.2-only extensions and ticket_early_data_info.
            if ![
                ffi::TLSEXT_TYPE_server_name as u16,
                ffi::TLSEXT_TYPE_supported_versions as u16,
                ffi::TLSEXT_TYPE_ec_point_formats as u16,
                ffi::TLSEXT_TYPE_extended_master_secret as u16,
                ffi::TLSEXT_TYPE_session_ticket as u16,
                NSS_TICKET_EARLY_DATA_INFO,
                ffi::TLSEXT_TYPE_renegotiate as u16,
            ]
            .contains(&kind)
            {
                compressed += 1;
            }
        }
        len += TLS_EXTENSION_HEADER_LEN + 3 + if grease_version { 2 } else { 0 };
        if self.psk_extension_length() != 0 {
            len += TLS_EXTENSION_HEADER_LEN + self.psk_extension_length();
        }
        if compressed != 0 {
            len += TLS_EXTENSION_HEADER_LEN + 1 + 2 * compressed;
        }
        len += usize::from(max_name_len.saturating_sub(host_len));
        let remainder = match rounding {
            EchGreaseRounding::NssPre3127 => len % 32,
            EchGreaseRounding::Rfc9849 => (len - 1) % 32,
        };
        len += 31 - remainder;
        len + self.aead_overhead()
    }

    /// NSS-shaped parameters: [`nss_payload_length`](Self::nss_payload_length),
    /// an AEAD drawn uniformly from the two accepted ones and a random `enc`.
    /// Fails if the length exceeds [`max_payload_length`](Self::max_payload_length).
    ///
    /// Capture the normalized URL host length, including for IPs without SNI.
    /// A context policy can instead read it from [`SslRef::ex_data`], populated
    /// with [`SslRef::set_ex_data`] on each configured connection.
    /// Use `Rfc9849` instead of `NssPre3127` for Firefox 155 and later:
    ///
    /// ```no_run
    /// use std::net::TcpStream;
    /// use btls::ssl::{EchGreaseRounding, SslConnector, SslMethod};
    /// # fn connect() -> Result<(), Box<dyn std::error::Error>> {
    /// let host = "127.0.0.1";
    /// let host_length = u8::try_from(host.len())?;
    /// let connector = SslConnector::builder(SslMethod::tls())?.build();
    /// let mut connection = connector.configure()?;
    /// connection.set_enable_ech_grease(true);
    /// connection.set_ech_grease_callback(move |_, info| {
    ///     info.nss_parameters(100, host_length, EchGreaseRounding::NssPre3127)
    /// })?;
    /// let ssl = connection.into_ssl(host)?; // No SNI for an IP literal.
    /// let _stream = ssl.connect(TcpStream::connect((host, 443))?)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn nss_parameters(
        &self,
        max_name_len: u8,
        host_len: u8,
        rounding: EchGreaseRounding,
    ) -> Result<EchGreaseParameters, ErrorStack> {
        let payload_length = self.nss_payload_length(max_name_len, host_len, rounding);
        let payload_length = u16::try_from(payload_length)
            .ok()
            .filter(|len| usize::from(*len) <= self.max_payload_length())
            .and_then(NonZeroU16::new)
            .ok_or_else(|| ErrorStack::internal_error_str("ECH GREASE payload exceeds budget"))?;
        let mut coin = [0];
        rand_bytes(&mut coin)?;
        Ok(EchGreaseParameters {
            aead: if coin[0] & 1 == 1 {
                EchGreaseAead::AES_128_GCM
            } else {
                EchGreaseAead::CHACHA20_POLY1305
            },
            payload_length,
            random_enc: true,
        })
    }
}

/// Whether `kind` is an RFC 8701 GREASE extension type.
fn is_grease_type(kind: u16) -> bool {
    kind & 0x0f0f == 0x0a0a && kind >> 8 == kind & 0xff
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
    // Both views borrow the synchronous invocation. BoringSSL locks the policy
    // while it runs, so the closure cannot be replaced from inside, and the
    // shared SSL setters still callable do not affect the extension being built.
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
                    random_enc: libc::c_int::from(parameters.random_enc),
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
    /// Called once when CH1 needs GREASE; HRR and DTLS HelloVerifyRequest reuse
    /// its bytes. Servers accept the policy but never call it.
    /// Does not enable [`GREASE`](SslRef::set_enable_ech_grease) or change real
    /// ECH or TLS cipher preferences. An installed policy decides every GREASE ClientHello: it
    /// can neither skip one nor defer to BoringSSL's random draw. Errors or
    /// oversized output fail the handshake; panics abort, as with other SSL
    /// callbacks.
    /// See [`EchGreaseInfo::max_payload_length`] for sizing limits. Arbitrary
    /// lengths need not follow [RFC 9849]'s recommended distribution;
    /// [`EchGreaseInfo::nss_parameters`] provides NSS-shaped parameters.
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
