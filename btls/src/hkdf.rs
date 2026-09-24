//! HMAC-based Extract-and-Expand Key Derivation Function (HKDF) as specified by
//! [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html).

use crate::error::ErrorStack;
use crate::hash::{DigestBytes, MessageDigest};
use crate::{cvt, ffi};

/// HKDF for a given hash function.
///
/// The digest determines `HashLen`, the length of the pseudorandom key (PRK)
/// returned by [`HkdfSuite::extract`]. HKDF-Expand limits output to
/// `255 * HashLen` bytes, as specified by [RFC 5869, Section
/// 2.3](https://www.rfc-editor.org/rfc/rfc5869.html#section-2.3).
#[derive(Copy, Clone)]
pub struct HkdfSuite {
    digest: MessageDigest,
}

impl HkdfSuite {
    /// Creates an HKDF suite using `digest`.
    #[must_use]
    pub fn new(digest: MessageDigest) -> Self {
        Self { digest }
    }

    /// Returns `HashLen`, the digest output size in bytes.
    #[must_use]
    pub fn prk_size(&self) -> usize {
        self.digest.size()
    }

    /// Computes HKDF-Extract as specified in [RFC 5869, Section
    /// 2.2](https://www.rfc-editor.org/rfc/rfc5869.html#section-2.2).
    ///
    /// `salt` is an optional salt value. An empty `salt` is treated as an
    /// omitted salt and is equivalent to a string of `HashLen` zero octets.
    /// `ikm` is the input keying material. The returned pseudorandom key (PRK)
    /// has length [`HkdfSuite::prk_size`].
    pub fn extract(&self, salt: &[u8], ikm: &[u8]) -> Result<DigestBytes, ErrorStack> {
        let mut prk = DigestBytes {
            buf: [0u8; ffi::EVP_MAX_MD_SIZE as usize],
            len: 0,
        };
        ffi::init();

        // BoringSSL's native HKDF_extract API orders these arguments as
        // secret/IKM, then salt, unlike the RFC 5869 notation and this API.
        unsafe {
            cvt(ffi::HKDF_extract(
                prk.buf.as_mut_ptr(),
                &mut prk.len,
                self.digest.as_ptr(),
                ikm.as_ptr(),
                ikm.len(),
                salt.as_ptr(),
                salt.len(),
            ))?;
        }

        debug_assert_eq!(prk.len, self.prk_size());

        Ok(prk)
    }

    /// Computes HKDF-Expand as specified in [RFC 5869, Section
    /// 2.3](https://www.rfc-editor.org/rfc/rfc5869.html#section-2.3).
    ///
    /// `prk` must be a pseudorandom key of at least `HashLen` bytes, usually
    /// the output of [`HkdfSuite::extract`]. Shorter PRKs are rejected.
    /// `info` is optional context and application-specific information and may
    /// be empty. The function writes `L` bytes of output keying material into
    /// `okm`, where `L` is its length. `okm` may be empty. HKDF limits `L` to
    /// `255 * HashLen`; output-limit errors are returned as [`ErrorStack`].
    pub fn expand(&self, prk: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), ErrorStack> {
        if prk.len() < self.prk_size() {
            return Err(ErrorStack::internal_error_str(
                "HKDF PRK is shorter than the digest output",
            ));
        }

        ffi::init();

        unsafe {
            cvt(ffi::HKDF_expand(
                okm.as_mut_ptr(),
                okm.len(),
                self.digest.as_ptr(),
                prk.as_ptr(),
                prk.len(),
                info.as_ptr(),
                info.len(),
            ))
        }
    }
}
