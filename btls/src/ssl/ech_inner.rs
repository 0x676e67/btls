use crate::cvt_0i;
use crate::error::ErrorStack;
use crate::ssl::SslRef;
use btls_sys as ffi;
use foreign_types::ForeignTypeRef;
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

impl SslRef {
    /// Sets the serialized ECHConfigList and the real ECH `ClientHelloInner`
    /// encoding for this client connection. [`SslRef::set_ech_config_list`]
    /// selects [`EchInnerEncoding::Default`].
    ///
    /// If the list is invalid, neither setting is changed. The policy does not alter
    /// ECH configuration selection, fallback behavior, or ECH GREASE.
    pub fn set_ech_config_list_with_policy(
        &mut self,
        ech_config_list: &[u8],
        encoding: EchInnerEncoding,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt_0i(ffi::SSL_set1_ech_config_list_with_policy(
                self.as_ptr(),
                ech_config_list.as_ptr(),
                ech_config_list.len(),
                encoding.as_raw(),
            ))
            .map(|_| ())
        }
    }
}
