use crate::error::Result;
use crate::hkdf::Hkdf;
use crate::key::{AeadKey, Key};
use crate::secret::Secret;
use crate::suite::CipherSuite;
use quinn_proto::crypto;

pub struct HandshakeTokenKey(Key);

impl HandshakeTokenKey {
    /// Creates a new randomized HandshakeTokenKey.
    pub fn new() -> Result<Self> {
        Self::new_for(Secret::random())
    }

    fn new_for(secret: Secret) -> Result<Self> {
        // Extract the key.
        let mut key = [0u8; Key::MAX_LEN];
        let len = Hkdf::sha256().extract(&[], secret.slice(), &mut key)?;
        Ok(Self(Key::new(key, len)))
    }
}

impl crypto::HandshakeTokenKey for HandshakeTokenKey {
    fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Box<dyn crypto::AeadKey> {
        let suite = CipherSuite::aes256_gcm_sha384();
        let prk = self.0.slice();
        let mut key = suite.aead.zero_key();
        Hkdf::sha256()
            .expand(prk, random_bytes, key.slice_mut())
            .unwrap();

        Box::new(AeadKey::new(suite, key).unwrap())
    }
}

#[cfg(test)]
mod test {
    use hex_literal::hex;
    use quinn_proto::crypto::HandshakeTokenKey;

    #[test]
    fn round_trip() {
        // Create a random token key.
        let master_key = hex!("ab35ad55e9957c0e67aedbbd76f6a781528a5b43cc57bfd633"
            "ccca412327aa23e0d7140d5fc290d1637746706c7d703e3bf405687a69ee82284a5ede49f59e19");
        let htk = super::HandshakeTokenKey::new_for(super::Secret::from(&master_key)).unwrap();

        // Generate an AEAD from the given random.
        let random_bytes = hex!("b088e52e27da85f8838e163ddb90fd35d633fad44f0ab9c39f05459297178599");
        let aead_key = htk.aead_from_hkdf(&random_bytes);

        // Inputs for the seal/open operations.
        let data = hex!("146a6d36221e4f24eda3a16f71a816a8a72dd7efbb0000000064076bde");
        let additional_data = hex!("00000000000000000000000000000001d60c084b239b74c31de86f");

        // Seal the buffer and verify the expected output.
        let mut buf = data.to_vec();
        aead_key.seal(&mut buf, &additional_data).unwrap();
        let expected = hex!("504a8f0841f3fb7dbf8b3df90b5be913cb5a28000918510baeff64"
            "5d72b67ab34a47da820a97416d68d0b605af");
        assert_eq!(&expected, buf.as_slice());

        // Now open and verify we get back the original data.
        let out = aead_key.open(&mut buf, &additional_data).unwrap();
        assert_eq!(&data, out);
    }
}
