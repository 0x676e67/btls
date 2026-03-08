use crate::aead::Aead;
use crate::error::{Error, Result};
use crate::hkdf::Hkdf;
use btls_sys as bffi;
use std::fmt::{Debug, Formatter};
use std::sync::LazyLock;

// For AEAD_AES_128_GCM and AEAD_AES_256_GCM ... endpoints that do not send
// packets larger than 2^11 bytes cannot protect more than 2^28 packets.
// https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#name-confidentiality-limit
const AES_CONFIDENTIALITY_LIMIT: u64 = 2u64.pow(28);

// For AEAD_CHACHA20_POLY1305, the confidentiality limit is greater than the
// number of possible packets (2^62) and so can be disregarded.
// https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#name-limits-on-aead-usage
const CHACHA20_POLY1305_CONFIDENTIALITY_LIMIT: u64 = u64::MAX;

// For AEAD_AES_128_GCM ... endpoints that do not attempt to remove
// protection from packets larger than 2^11 bytes can attempt to remove
// protection from at most 2^57 packets.
// For AEAD_AES_256_GCM [the limit] is substantially larger than the limit for
// AEAD_AES_128_GCM. However, this document recommends that the same limit be
// applied to both functions as either limit is acceptably large.
// https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#name-integrity-limit
const AES_INTEGRITY_LIMIT: u64 = 2u64.pow(57);

// For AEAD_CHACHA20_POLY1305, the integrity limit is 2^36 invalid packets.
// https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#name-limits-on-aead-usage
const CHACHA20_POLY1305_INTEGRITY_LIMIT: u64 = 2u64.pow(36);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum ID {
    Aes128GcmSha256,
    Aes256GcmSha384,
    Chacha20Poly1305Sha256,
}

#[derive(Eq, PartialEq)]
pub(crate) struct CipherSuite {
    pub(crate) id: ID,
    pub(crate) hkdf: Hkdf,
    pub(crate) aead: &'static Aead,
    pub(crate) confidentiality_limit: u64,
    pub(crate) integrity_limit: u64,
}

impl Debug for CipherSuite {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.id, f)
    }
}

static AES128_GCM_SHA256: LazyLock<CipherSuite> = LazyLock::new(|| CipherSuite {
    id: ID::Aes128GcmSha256,
    hkdf: Hkdf::sha256(),
    aead: Aead::aes128_gcm(),
    confidentiality_limit: AES_CONFIDENTIALITY_LIMIT,
    integrity_limit: AES_INTEGRITY_LIMIT,
});

static AES256_GCM_SHA384: LazyLock<CipherSuite> = LazyLock::new(|| CipherSuite {
    id: ID::Aes256GcmSha384,
    hkdf: Hkdf::sha384(),
    aead: Aead::aes256_gcm(),
    confidentiality_limit: AES_CONFIDENTIALITY_LIMIT,
    integrity_limit: AES_INTEGRITY_LIMIT,
});

static CHACHA20_POLY1305_SHA256: LazyLock<CipherSuite> = LazyLock::new(|| CipherSuite {
    id: ID::Chacha20Poly1305Sha256,
    hkdf: Hkdf::sha256(),
    aead: Aead::chacha20_poly1305(),
    confidentiality_limit: CHACHA20_POLY1305_CONFIDENTIALITY_LIMIT,
    integrity_limit: CHACHA20_POLY1305_INTEGRITY_LIMIT,
});

unsafe impl Send for CipherSuite {}
unsafe impl Sync for CipherSuite {}

impl CipherSuite {
    #[inline]
    pub(crate) fn aes128_gcm_sha256() -> &'static Self {
        &AES128_GCM_SHA256
    }

    #[inline]
    pub(crate) fn aes256_gcm_sha384() -> &'static Self {
        &AES256_GCM_SHA384
    }

    #[inline]
    pub(crate) fn chacha20_poly1305_sha256() -> &'static Self {
        &CHACHA20_POLY1305_SHA256
    }

    #[inline]
    pub(crate) fn from_cipher(cipher: *const bffi::SSL_CIPHER) -> Result<&'static Self> {
        match unsafe { bffi::SSL_CIPHER_get_id(cipher) } as i32 {
            bffi::TLS1_CK_AES_128_GCM_SHA256 => Ok(Self::aes128_gcm_sha256()),
            bffi::TLS1_CK_AES_256_GCM_SHA384 => Ok(Self::aes256_gcm_sha384()),
            bffi::TLS1_CK_CHACHA20_POLY1305_SHA256 => Ok(Self::chacha20_poly1305_sha256()),
            id => Err(Error::invalid_input(format!("invalid cipher id: {id}"))),
        }
    }
}
