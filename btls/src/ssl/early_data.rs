//! TLS 1.3 early data (0-RTT, [RFC 8446 §2.3](https://www.rfc-editor.org/rfc/rfc8446#section-2.3)).

use super::{SslContextBuilder, SslRef, SslSessionRef};
use crate::ffi;
use foreign_types::ForeignTypeRef;
use openssl_macros::corresponds;
use std::ffi::CStr;
use std::fmt;

/// Why a connection did or did not use early data.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct EarlyDataReason(ffi::ssl_early_data_reason_t);

impl EarlyDataReason {
    /// The handshake has not progressed far enough for the 0-RTT status to be known.
    pub const UNKNOWN: Self = Self(ffi::ssl_early_data_reason_t::ssl_early_data_unknown);
    /// Early data is disabled on this side.
    pub const DISABLED: Self = Self(ffi::ssl_early_data_reason_t::ssl_early_data_disabled);
    /// Early data was accepted.
    pub const ACCEPTED: Self = Self(ffi::ssl_early_data_reason_t::ssl_early_data_accepted);
    /// The negotiated protocol version does not support early data.
    pub const PROTOCOL_VERSION: Self =
        Self(ffi::ssl_early_data_reason_t::ssl_early_data_protocol_version);
    /// The peer declined to offer or accept early data.
    pub const PEER_DECLINED: Self =
        Self(ffi::ssl_early_data_reason_t::ssl_early_data_peer_declined);
    /// The client did not offer a session.
    pub const NO_SESSION_OFFERED: Self =
        Self(ffi::ssl_early_data_reason_t::ssl_early_data_no_session_offered);
    /// The server declined to resume the session.
    pub const SESSION_NOT_RESUMED: Self =
        Self(ffi::ssl_early_data_reason_t::ssl_early_data_session_not_resumed);
    /// The session does not allow early data.
    pub const UNSUPPORTED_FOR_SESSION: Self =
        Self(ffi::ssl_early_data_reason_t::ssl_early_data_unsupported_for_session);
    /// The server sent a HelloRetryRequest.
    pub const HELLO_RETRY_REQUEST: Self =
        Self(ffi::ssl_early_data_reason_t::ssl_early_data_hello_retry_request);
    /// The negotiated ALPN protocol differs from the session's.
    pub const ALPN_MISMATCH: Self =
        Self(ffi::ssl_early_data_reason_t::ssl_early_data_alpn_mismatch);
    /// Channel ID was negotiated.
    pub const CHANNEL_ID: Self = Self(ffi::ssl_early_data_reason_t::ssl_early_data_channel_id);
    /// The ticket age was too far off.
    pub const TICKET_AGE_SKEW: Self =
        Self(ffi::ssl_early_data_reason_t::ssl_early_data_ticket_age_skew);
    /// The QUIC early data context differs from the session's, see
    /// [`SslRef::set_quic_early_data_context`].
    pub const QUIC_PARAMETER_MISMATCH: Self =
        Self(ffi::ssl_early_data_reason_t::ssl_early_data_quic_parameter_mismatch);
    /// The application settings (ALPS) differ from the session's.
    pub const ALPS_MISMATCH: Self =
        Self(ffi::ssl_early_data_reason_t::ssl_early_data_alps_mismatch);

    /// Returns a short name of the reason.
    #[corresponds(SSL_early_data_reason_string)]
    #[must_use]
    pub fn description(&self) -> Option<&'static str> {
        unsafe {
            let description = ffi::SSL_early_data_reason_string(self.0);
            if description.is_null() {
                None
            } else {
                CStr::from_ptr(description).to_str().ok()
            }
        }
    }
}

impl fmt::Display for EarlyDataReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.description() {
            Some(description) => f.write_str(description),
            None => write!(f, "unknown early data reason {}", self.0 .0),
        }
    }
}

impl SslContextBuilder {
    /// Sets whether early data is allowed. When it is, clients may send it with a session that
    /// allows it, and servers may accept it and may issue sessions that allow it. A QUIC server
    /// also needs [`SslRef::set_quic_early_data_context`]. When it is not, clients send none and
    /// servers reject it and issue sessions that do not allow it.
    #[corresponds(SSL_CTX_set_early_data_enabled)]
    pub fn set_early_data_enabled(&mut self, enabled: bool) {
        unsafe { ffi::SSL_CTX_set_early_data_enabled(self.as_ptr(), enabled.into()) }
    }
}

impl SslRef {
    /// Overrides [`SslContextBuilder::set_early_data_enabled`] for this connection.
    #[corresponds(SSL_set_early_data_enabled)]
    pub fn set_early_data_enabled(&mut self, enabled: bool) {
        unsafe { ffi::SSL_set_early_data_enabled(self.as_ptr(), enabled.into()) }
    }

    /// Returns whether the handshake is in the early data state, where a client may send early
    /// data and a server may read it.
    #[corresponds(SSL_in_early_data)]
    #[must_use]
    pub fn in_early_data(&self) -> bool {
        unsafe { ffi::SSL_in_early_data(self.as_ptr()) == 1 }
    }

    /// Returns whether the peer accepted the early data this client sent, or whether this server
    /// accepted it.
    #[corresponds(SSL_early_data_accepted)]
    #[must_use]
    pub fn early_data_accepted(&self) -> bool {
        unsafe { ffi::SSL_early_data_accepted(self.as_ptr()) == 1 }
    }

    /// Resets a client after its handshake failed with
    /// [`ErrorCode::EARLY_DATA_REJECTED`](super::ErrorCode::EARLY_DATA_REJECTED), so that it
    /// continues without early data.
    ///
    /// The handshake then runs as a full one and may end with other peer certificates, ALPN
    /// protocol and other properties, so values queried before the reset must be discarded and
    /// queried again.
    ///
    /// # Aborts
    ///
    /// BoringSSL aborts the process unless this is the first call since the handshake returned
    /// [`ErrorCode::EARLY_DATA_REJECTED`](super::ErrorCode::EARLY_DATA_REJECTED). Calling it
    /// without a reject, after the handshake completed, or twice aborts.
    #[corresponds(SSL_reset_early_data_reject)]
    pub fn reset_early_data_reject(&mut self) {
        unsafe { ffi::SSL_reset_early_data_reject(self.as_ptr()) }
    }

    /// Returns why the connection did or did not use early data.
    #[corresponds(SSL_get_early_data_reason)]
    #[must_use]
    pub fn early_data_reason(&self) -> EarlyDataReason {
        EarlyDataReason(unsafe { ffi::SSL_get_early_data_reason(self.as_ptr()) })
    }
}

impl SslSessionRef {
    /// Returns whether a client may send early data with the session.
    #[corresponds(SSL_SESSION_early_data_capable)]
    #[must_use]
    pub fn early_data_capable(&self) -> bool {
        unsafe { ffi::SSL_SESSION_early_data_capable(self.as_ptr()) == 1 }
    }
}
