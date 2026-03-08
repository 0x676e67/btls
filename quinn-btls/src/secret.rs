use crate::error::Result;
use crate::hkdf;
use crate::key::{HeaderKey, KeyPair, Keys, PacketKey};
use crate::macros::bounded_array;
use crate::suite::CipherSuite;
use crate::version::QuicVersion;
use quinn_proto::{ConnectionId, Side};

const MAX_SECRET_LEN: usize = hkdf::DIGEST_BLOCK_LEN;

bounded_array! {
    /// A buffer that can fit the largest master secret.
    pub(crate) struct Secret(MAX_SECRET_LEN)
}

impl Secret {
    /// Performs an in-place key update.
    #[inline]
    pub(crate) fn update(&mut self, version: QuicVersion, suite: &CipherSuite) -> Result<()> {
        let out = &mut [0u8; Secret::MAX_LEN][..self.len()];
        suite
            .hkdf
            .expand_label(self.slice(), version.key_update_label(), out)?;
        self.slice_mut().copy_from_slice(out);
        Ok(())
    }

    #[inline]
    pub(crate) fn header_key(
        &self,
        version: QuicVersion,
        suite: &'static CipherSuite,
    ) -> Result<HeaderKey> {
        HeaderKey::new(version, suite, self)
    }

    #[inline]
    pub(crate) fn packet_key(
        &self,
        version: QuicVersion,
        suite: &'static CipherSuite,
    ) -> Result<PacketKey> {
        PacketKey::new(version, suite, self)
    }
}

/// A secret pair for reading (decryption) and writing (encryption).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct Secrets {
    pub(crate) version: QuicVersion,
    pub(crate) suite: &'static CipherSuite,
    pub(crate) local: Secret,
    pub(crate) remote: Secret,
}

impl Secrets {
    /// Creates the Quic initial secrets.
    /// See <https://datatracker.ietf.org/doc/html/rfc9001#name-initial-secrets>.
    #[inline]
    pub(crate) fn initial(
        version: QuicVersion,
        dst_cid: &ConnectionId,
        side: Side,
    ) -> Result<Secrets> {
        // Initial secrets always use AES-128-GCM and SHA256.
        let suite = CipherSuite::aes128_gcm_sha256();

        // Generate the initial secret.
        let salt = version.initial_salt();
        let mut initial_secret = [0u8; Secret::MAX_LEN];
        let initial_secret_len = suite.hkdf.extract(salt, dst_cid, &mut initial_secret)?;
        let initial_secret = &initial_secret[..initial_secret_len];

        // Use the appropriate secret labels for "this" side of the connection.
        const CLIENT_LABEL: &[u8] = b"client in";
        const SERVER_LABEL: &[u8] = b"server in";
        let (local_label, remote_label) = match side {
            Side::Client => (CLIENT_LABEL, SERVER_LABEL),
            Side::Server => (SERVER_LABEL, CLIENT_LABEL),
        };

        let len = suite.hkdf.digest_size();
        let mut local = Secret::with_len(len);
        suite
            .hkdf
            .expand_label(initial_secret, local_label, local.slice_mut())?;

        let mut remote = Secret::with_len(len);
        suite
            .hkdf
            .expand_label(initial_secret, remote_label, remote.slice_mut())?;

        Ok(Secrets {
            version,
            suite,
            local,
            remote,
        })
    }

    #[inline]
    pub(crate) fn keys(&self) -> Result<Keys> {
        Ok(Keys {
            header: self.header_keys()?,
            packet: self.packet_keys()?,
        })
    }

    #[inline]
    pub(crate) fn header_keys(&self) -> Result<KeyPair<HeaderKey>> {
        Ok(KeyPair {
            local: self.local.header_key(self.version, self.suite)?,
            remote: self.remote.header_key(self.version, self.suite)?,
        })
    }

    #[inline]
    pub(crate) fn packet_keys(&self) -> Result<KeyPair<PacketKey>> {
        Ok(KeyPair {
            local: self.local.packet_key(self.version, self.suite)?,
            remote: self.remote.packet_key(self.version, self.suite)?,
        })
    }

    #[inline]
    pub(crate) fn update(&mut self) -> Result<()> {
        // Update the secrets.
        self.local.update(self.version, self.suite)?;
        self.remote.update(self.version, self.suite)?;
        Ok(())
    }

    #[inline]
    pub(crate) fn next_packet_keys(&mut self) -> Result<KeyPair<PacketKey>> {
        // Get the current keys.
        let keys = self.packet_keys()?;

        // Update the secrets.
        self.update()?;

        Ok(keys)
    }
}

pub(crate) struct SecretsBuilder {
    pub(crate) version: QuicVersion,
    pub(crate) suite: Option<&'static CipherSuite>,
    pub(crate) local_secret: Option<Secret>,
    pub(crate) remote_secret: Option<Secret>,
}

impl SecretsBuilder {
    pub(crate) fn new(version: QuicVersion) -> Self {
        Self {
            version,
            suite: None,
            local_secret: None,
            remote_secret: None,
        }
    }

    pub(crate) fn set_suite(&mut self, suite: &'static CipherSuite) {
        if let Some(prev) = self.suite {
            // Make sure it doesn't change once set.
            assert_eq!(prev, suite);
            return;
        }

        self.suite = Some(suite)
    }

    pub(crate) fn set_remote_secret(&mut self, secret: Secret) {
        if let Some(prev) = &self.remote_secret {
            // Make sure it doesn't change once set.
            assert_eq!(*prev, secret);
            return;
        }

        self.remote_secret = Some(secret)
    }

    pub(crate) fn set_local_secret(&mut self, secret: Secret) {
        if let Some(prev) = &self.local_secret {
            // Make sure it doesn't change once set.
            assert_eq!(*prev, secret);
            return;
        }

        self.local_secret = Some(secret)
    }

    pub(crate) fn build(&self) -> Option<Secrets> {
        if let Some(suite) = self.suite {
            if let Some(local) = self.local_secret {
                if let Some(remote) = self.remote_secret {
                    return Some(Secrets {
                        version: self.version,
                        suite,
                        local,
                        remote,
                    });
                }
            }
        }
        None
    }
}
