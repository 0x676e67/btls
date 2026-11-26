use crate::error::ErrorStack;
use crate::ssl::{SslContextBuilder, SslRef};
use btls_sys as ffi;
use foreign_types::ForeignTypeRef;
use openssl_macros::corresponds;
use std::ffi::c_int;

/// Serialization policy for the real ECH `ClientHelloInner`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EchInnerEncoding {
    /// Keep the BoringSSL serialization rules.
    #[default]
    Default,
    /// Write the ECH marker first, include eligible legacy cipher IDs without
    /// fallback SCSV, and compress the matching record size limit extension.
    /// The supported TLS versions and extension negotiation are unchanged.
    Nss,
}

impl EchInnerEncoding {
    fn as_raw(self) -> c_int {
        match self {
            Self::Default => 0,
            Self::Nss => 1,
        }
    }
}

impl SslContextBuilder {
    /// Sets the real ECH inner encoding for connections created from this
    /// context. This does not enable ECH or change ECH GREASE.
    #[corresponds(SSL_CTX_set_ech_inner_encoding_nss)]
    pub fn set_ech_inner_encoding(&mut self, encoding: EchInnerEncoding) {
        unsafe { ffi::SSL_CTX_set_ech_inner_encoding_nss(self.as_ptr(), encoding.as_raw()) }
    }
}

impl SslRef {
    /// Sets this connection's serialized ECHConfigList and overrides the context's
    /// encoding policy for the real ECH `ClientHelloInner`.
    ///
    /// If the list is invalid, neither setting is changed. The policy does not alter
    /// ECH configuration selection, fallback behavior, or ECH GREASE.
    pub fn set_ech_config_list_with_policy(
        &mut self,
        ech_config_list: &[u8],
        encoding: EchInnerEncoding,
    ) -> Result<(), ErrorStack> {
        self.set_ech_config_list(ech_config_list)?;
        unsafe { ffi::SSL_set_ech_inner_encoding_nss(self.as_ptr(), encoding.as_raw()) };
        Ok(())
    }
}
