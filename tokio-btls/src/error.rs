//! Maps transport and BoringSSL errors onto [`Poll`].

use std::{io, task::Poll};

use btls::ssl::{self, ErrorCode};
use btls_sys as ffi;

pub(crate) fn cvt<T>(r: io::Result<T>) -> Poll<io::Result<T>> {
    match r {
        Ok(v) => Poll::Ready(Ok(v)),
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
        Err(e) => Poll::Ready(Err(e)),
    }
}

pub(crate) fn cvt_ossl<T>(r: Result<T, ssl::Error>) -> Poll<Result<T, ssl::Error>> {
    match r {
        Ok(v) => Poll::Ready(Ok(v)),
        Err(e) => match e.code() {
            ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => Poll::Pending,
            _ => Poll::Ready(Err(e)),
        },
    }
}

/// Whether `SSL_shutdown` failed because a fatal alert already closed the write side.
///
/// `SSL_shutdown` raises `PROTOCOL_IS_SHUTDOWN` only when a fatal alert, rather than
/// close_notify, closed the write side; reads keep reporting the error that sent it.
pub(crate) fn closed_by_alert(e: &ssl::Error) -> bool {
    e.ssl_error().is_some_and(|stack| {
        stack.errors().iter().any(|err| {
            err.library_reason(ffi::ERR_LIB_SSL) == Some(ffi::SSL_R_PROTOCOL_IS_SHUTDOWN)
        })
    })
}
