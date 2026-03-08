use btls_sys as bffi;
use quinn_proto::{TransportError, TransportErrorCode};
use std::ffi::{c_int, CStr};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

pub(crate) enum AlertType {
    Warning,
    Fatal,
    Unknown,
}

impl AlertType {
    const ALERT_TYPE_WARNING: &'static str = "warning";
    const ALERT_TYPE_FATAL: &'static str = "fatal";
    const ALERT_TYPE_UNKNOWN: &'static str = "unknown";
}

impl Display for AlertType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Warning => f.write_str(Self::ALERT_TYPE_WARNING),
            Self::Fatal => f.write_str(Self::ALERT_TYPE_FATAL),
            _ => f.write_str(Self::ALERT_TYPE_UNKNOWN),
        }
    }
}

impl FromStr for AlertType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::ALERT_TYPE_WARNING => Ok(Self::Warning),
            Self::ALERT_TYPE_FATAL => Ok(Self::Fatal),
            _ => Ok(Self::Unknown),
        }
    }
}

#[derive(Copy, Clone)]
pub(crate) struct Alert(u8);

impl Alert {
    pub(crate) fn from(value: u8) -> Self {
        Alert(value)
    }

    pub(crate) fn handshake_failure() -> Self {
        Alert(bffi::SSL_AD_HANDSHAKE_FAILURE as u8)
    }

    pub(crate) fn get_description(&self) -> &'static str {
        unsafe {
            CStr::from_ptr(bffi::SSL_alert_desc_string_long(self.0 as c_int))
                .to_str()
                .unwrap()
        }
    }
}

impl Display for Alert {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "SSL alert [{}]: {}", self.0, self.get_description())
    }
}

impl From<Alert> for TransportErrorCode {
    fn from(alert: Alert) -> Self {
        TransportErrorCode::crypto(alert.0)
    }
}

impl From<Alert> for TransportError {
    fn from(alert: Alert) -> Self {
        TransportError {
            code: alert.into(),
            frame: None,
            reason: alert.get_description().to_string(),
        }
    }
}
