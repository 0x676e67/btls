use quinn_proto::crypto;
use std::result::Result as StdResult;

/// QUIC protocol version
///
/// Governs version-specific behavior in the TLS layer
// TODO: add support for draft version 2.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum QuicVersion {
    V1Draft29,
    V1Draft30,
    V1Draft31,
    V1Draft32,
    V1Draft33,
    V1Draft34,

    /// First stable RFC version.
    #[default]
    V1,
}

impl QuicVersion {
    const DRAFT_INDICATOR: u32 = 0xff00_0000;
    const VERSION_1_DRAFT_29: u32 = Self::DRAFT_INDICATOR | 29;
    const VERSION_1_DRAFT_30: u32 = Self::DRAFT_INDICATOR | 30;
    const VERSION_1_DRAFT_31: u32 = Self::DRAFT_INDICATOR | 31;
    const VERSION_1_DRAFT_32: u32 = Self::DRAFT_INDICATOR | 32;
    const VERSION_1_DRAFT_33: u32 = Self::DRAFT_INDICATOR | 33;
    const VERSION_1_DRAFT_34: u32 = Self::DRAFT_INDICATOR | 34;
    const VERSION_1: u32 = 1;

    /// Returns the default list of supported quic versions.
    pub fn default_supported_versions() -> Vec<u32> {
        let mut out = Vec::new();
        for v in [
            Self::V1,
            Self::V1Draft34,
            Self::V1Draft33,
            Self::V1Draft32,
            Self::V1Draft31,
            Self::V1Draft30,
            Self::V1Draft29,
        ] {
            out.push(v.label());
        }
        out
    }

    pub(crate) fn parse(version: u32) -> StdResult<Self, crypto::UnsupportedVersion> {
        match version {
            Self::VERSION_1_DRAFT_29 => Ok(Self::V1Draft29),
            Self::VERSION_1_DRAFT_30 => Ok(Self::V1Draft30),
            Self::VERSION_1_DRAFT_31 => Ok(Self::V1Draft31),
            Self::VERSION_1_DRAFT_32 => Ok(Self::V1Draft32),
            Self::VERSION_1_DRAFT_33 => Ok(Self::V1Draft33),
            Self::VERSION_1_DRAFT_34 => Ok(Self::V1Draft34),
            Self::VERSION_1 => Ok(Self::V1),
            _ => Err(crypto::UnsupportedVersion),
        }
    }

    pub(crate) fn label(&self) -> u32 {
        match self {
            Self::V1Draft29 => Self::VERSION_1_DRAFT_29,
            Self::V1Draft30 => Self::VERSION_1_DRAFT_30,
            Self::V1Draft31 => Self::VERSION_1_DRAFT_31,
            Self::V1Draft32 => Self::VERSION_1_DRAFT_32,
            Self::V1Draft33 => Self::VERSION_1_DRAFT_33,
            Self::V1Draft34 => Self::VERSION_1_DRAFT_34,
            Self::V1 => Self::VERSION_1,
        }
    }

    pub(crate) fn initial_salt(&self) -> &'static [u8] {
        match self {
            Self::V1Draft29 | Self::V1Draft30 | Self::V1Draft31 | Self::V1Draft32 => &[
                // https://datatracker.ietf.org/doc/html/draft-ietf-quic-tls-32#section-5.2
                0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61,
                0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99,
            ],
            Self::V1Draft33 | Self::V1Draft34 | Self::V1 => &[
                // https://www.rfc-editor.org/rfc/rfc9001.html#name-initial-secrets
                0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
            ],
        }
    }

    pub(crate) fn retry_integrity_key(&self) -> &'static [u8] {
        match self {
            Self::V1Draft29 | Self::V1Draft30 | Self::V1Draft31 | Self::V1Draft32 => &[
                // https://datatracker.ietf.org/doc/html/draft-ietf-quic-tls-32#section-5.8
                0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0, 0x57, 0x28, 0x15, 0x5a, 0x6c, 0xb9,
                0x6b, 0xe1,
            ],
            Self::V1Draft33 | Self::V1Draft34 | Self::V1 => &[
                // https://datatracker.ietf.org/doc/html/rfc9001#name-retry-packet-integrity
                0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68,
                0xc8, 0x4e,
            ],
        }
    }

    pub(crate) fn retry_integrity_nonce(&self) -> &'static [u8] {
        match self {
            Self::V1Draft29 | Self::V1Draft30 | Self::V1Draft31 | Self::V1Draft32 => &[
                // https://datatracker.ietf.org/doc/html/draft-ietf-quic-tls-32#section-5.8
                0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c,
            ],
            Self::V1Draft33 | Self::V1Draft34 | Self::V1 => &[
                // https://datatracker.ietf.org/doc/html/rfc9001#name-retry-packet-integrity
                0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
            ],
        }
    }

    /// Indicates whether this version uses the legacy TLS extension codepoint.
    pub(crate) fn uses_legacy_extension(&self) -> bool {
        match self {
            Self::V1Draft29
            | Self::V1Draft30
            | Self::V1Draft31
            | Self::V1Draft32
            | Self::V1Draft33
            | Self::V1Draft34 => true,
            Self::V1 => false,
        }
    }

    pub(crate) fn key_label(&self) -> &'static [u8] {
        b"quic key"
    }

    pub(crate) fn iv_label(&self) -> &'static [u8] {
        b"quic iv"
    }

    pub(crate) fn header_key_label(&self) -> &'static [u8] {
        b"quic hp"
    }

    pub(crate) fn key_update_label(&self) -> &'static [u8] {
        b"quic ku"
    }
}
