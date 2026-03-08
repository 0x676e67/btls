use crate::error::map_ptr_result;
use crate::hkdf::DIGEST_BLOCK_LEN;
use btls::hash::MessageDigest;
use btls_sys as bffi;
use quinn_proto::crypto;
use rand::Rng;
use std::ffi::{c_uint, c_void};
use std::result::Result as StdResult;

const SIGNATURE_LEN_SHA_256: usize = 32;

/// Implementation of [crypto::HmacKey] using BoringSSL.
pub struct HmacKey {
    alg: MessageDigest,
    key: Vec<u8>,
}

impl HmacKey {
    /// Creates a new randomized SHA-256 HMAC key.
    pub fn sha256() -> Self {
        // Create a random key.
        let mut key = [0u8; DIGEST_BLOCK_LEN];
        rand::rng().fill_bytes(&mut key);

        Self {
            alg: MessageDigest::sha256(),
            key: Vec::from(key),
        }
    }
}

impl crypto::HmacKey for HmacKey {
    fn sign(&self, data: &[u8], out: &mut [u8]) {
        let mut out_len = out.len() as c_uint;
        unsafe {
            map_ptr_result(bffi::HMAC(
                self.alg.as_ptr(),
                self.key.as_ptr() as *const c_void,
                self.key.len(),
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                &mut out_len,
            ))
            .unwrap();
        }

        // Verify the signature length.
        if out_len as usize != self.signature_len() {
            panic!("HMAC.sign: generated signature with unexpected length: {out_len}");
        }
    }

    #[inline]
    fn signature_len(&self) -> usize {
        SIGNATURE_LEN_SHA_256
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> StdResult<(), crypto::CryptoError> {
        if signature.len() != self.signature_len() {
            return Err(crypto::CryptoError {});
        }

        // Sign the data.
        let mut out = [0u8; SIGNATURE_LEN_SHA_256];
        self.sign(data, &mut out);

        // Compare the output.
        if out == signature {
            return Ok(());
        }
        Err(crypto::CryptoError {})
    }
}
