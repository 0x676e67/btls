use crate::error::{map_result, Error, Result};
use crate::key::{Key, Nonce, Tag};
use btls_sys as bffi;
use std::mem::MaybeUninit;
use std::sync::LazyLock;

const AES_128_GCM_KEY_LEN: usize = 16;
const AES_256_GCM_KEY_LEN: usize = 32;
const CHACHA20_POLY1305_KEY_LEN: usize = 32;

const AES_GCM_NONCE_LEN: usize = 12;
const POLY1305_NONCE_LEN: usize = 12;

pub(crate) const AES_GCM_TAG_LEN: usize = 16;
const POLY1305_TAG_LEN: usize = 16;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum ID {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

/// Wrapper around a raw BoringSSL EVP_AEAD.
#[derive(Copy, Clone, PartialEq, Eq)]
struct AeadPtr(*const bffi::EVP_AEAD);

unsafe impl Send for AeadPtr {}
unsafe impl Sync for AeadPtr {}

impl AeadPtr {
    fn aes128_gcm() -> Self {
        unsafe { Self(bffi::EVP_aead_aes_128_gcm()) }
    }

    fn aes256_gcm() -> Self {
        unsafe { Self(bffi::EVP_aead_aes_256_gcm()) }
    }

    fn chacha20_poly1305() -> Self {
        unsafe { Self(bffi::EVP_aead_chacha20_poly1305()) }
    }
}

/// Wrapper around an BoringSSL EVP_AEAD.
pub(crate) struct Aead {
    ptr: AeadPtr,
    pub(crate) id: ID,
    pub(crate) key_len: usize,
    pub(crate) tag_len: usize,
    pub(crate) nonce_len: usize,
}

impl PartialEq for Aead {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Aead {}

static AES128_GCM: LazyLock<Aead> = LazyLock::new(|| Aead {
    ptr: AeadPtr::aes128_gcm(),
    id: ID::Aes128Gcm,
    key_len: AES_128_GCM_KEY_LEN,
    tag_len: AES_GCM_TAG_LEN,
    nonce_len: AES_GCM_NONCE_LEN,
});

static AES256_GCM: LazyLock<Aead> = LazyLock::new(|| Aead {
    ptr: AeadPtr::aes256_gcm(),
    id: ID::Aes256Gcm,
    key_len: AES_256_GCM_KEY_LEN,
    tag_len: AES_GCM_TAG_LEN,
    nonce_len: AES_GCM_NONCE_LEN,
});

static CHACHA20_POLY1305: LazyLock<Aead> = LazyLock::new(|| Aead {
    ptr: AeadPtr::chacha20_poly1305(),
    id: ID::Chacha20Poly1305,
    key_len: CHACHA20_POLY1305_KEY_LEN,
    tag_len: POLY1305_TAG_LEN,
    nonce_len: POLY1305_NONCE_LEN,
});

impl Aead {
    #[inline]
    pub(crate) fn aes128_gcm() -> &'static Self {
        &AES128_GCM
    }

    #[inline]
    pub(crate) fn aes256_gcm() -> &'static Self {
        &AES256_GCM
    }

    #[inline]
    pub(crate) fn chacha20_poly1305() -> &'static Self {
        &CHACHA20_POLY1305
    }

    /// Creates a new zeroed key of the appropriate length for the AEAD algorithm.
    #[inline]
    pub(crate) fn zero_key(&self) -> Key {
        Key::with_len(self.key_len)
    }

    /// Creates a new zeroed nonce of the appropriate length for the AEAD algorithm.
    #[inline]
    pub(crate) fn zero_nonce(&self) -> Nonce {
        Nonce::with_len(self.nonce_len)
    }

    /// Creates a new zeroed tag of the appropriate length for the AEAD algorithm.
    #[inline]
    pub(crate) fn zero_tag(&self) -> Tag {
        Tag::with_len(self.tag_len)
    }

    #[inline]
    pub(crate) fn as_ptr(&self) -> *const bffi::EVP_AEAD {
        self.ptr.0
    }

    #[inline]
    pub(crate) fn new_aead_ctx(&self, key: &Key) -> Result<bffi::EVP_AEAD_CTX> {
        if key.len() != self.key_len {
            return Err(Error::invalid_input(format!(
                "key length invalid for AEAD_CTX: {}",
                key.len()
            )));
        }

        let ctx = unsafe {
            let mut ctx = MaybeUninit::uninit();

            map_result(bffi::EVP_AEAD_CTX_init(
                ctx.as_mut_ptr(),
                self.as_ptr(),
                key.as_ptr(),
                key.len(),
                self.tag_len,
                std::ptr::null_mut(),
            ))?;

            ctx.assume_init()
        };

        Ok(ctx)
    }
}
