use crate::ssl::SslContextBuilder;
use btls_sys as ffi;
use openssl_macros::corresponds;

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

impl SslContextBuilder {
    /// Sets the real ECH inner encoding for connections created from this
    /// context. This does not enable ECH or change ECH GREASE.
    #[corresponds(SSL_CTX_set_ech_inner_encoding_nss)]
    pub fn set_ech_inner_encoding(&mut self, encoding: EchInnerEncoding) {
        let nss = match encoding {
            EchInnerEncoding::Default => 0,
            EchInnerEncoding::Nss => 1,
        };
        unsafe { ffi::SSL_CTX_set_ech_inner_encoding_nss(self.as_ptr(), nss) }
    }
}
