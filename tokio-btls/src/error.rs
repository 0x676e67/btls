//! Classifies transport and BoringSSL errors for the poll methods.

use std::{io, task::Poll};

use btls::ssl::{self, ErrorCode};
use btls_sys as ffi;

/// Maps `WouldBlock` to `Pending`; it must come from a transport `Pending`, which registered the
/// waker.
pub(crate) fn cvt<T>(r: io::Result<T>) -> Poll<io::Result<T>> {
    match r {
        Ok(v) => Poll::Ready(Ok(v)),
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
        Err(e) => Poll::Ready(Err(e)),
    }
}

/// Maps a handshake that must wait to `Pending`: on the transport, as in [`would_block`], or on
/// a callback that asked to retry later and wakes the task itself.
pub(crate) fn cvt_handshake(r: Result<(), ssl::Error>) -> Poll<Result<(), ssl::Error>> {
    match r {
        Err(ref e) if would_block(e) || callback_retry(e) => Poll::Pending,
        r => Poll::Ready(r),
    }
}

/// Whether a callback asked BoringSSL to retry the handshake later.
fn callback_retry(e: &ssl::Error) -> bool {
    matches!(
        e.code(),
        ErrorCode::WANT_X509_LOOKUP
            | ErrorCode::PENDING_SESSION
            | ErrorCode::PENDING_CERTIFICATE
            | ErrorCode::WANT_PRIVATE_KEY_OPERATION
            | ErrorCode::WANT_CERTIFICATE_VERIFY
            | ErrorCode::PENDING_TICKET
    )
}

/// Whether `e` asks to retry after a transport `Pending`, which registered the waker.
///
/// btls also retries on `NotConnected`, which nothing will wake the task for.
pub(crate) fn would_block(e: &ssl::Error) -> bool {
    matches!(e.code(), ErrorCode::WANT_READ | ErrorCode::WANT_WRITE)
        && e.io_error()
            .is_none_or(|err| err.kind() == io::ErrorKind::WouldBlock)
}

/// Whether `SSL_shutdown` failed because a fatal alert already closed the write side.
///
/// `SSL_shutdown` raises `PROTOCOL_IS_SHUTDOWN` only when a fatal alert, rather than
/// close_notify ([RFC 8446 §6.1](https://www.rfc-editor.org/rfc/rfc8446#section-6.1)), closed
/// the write side; reads keep reporting the error that sent it.
pub(crate) fn closed_by_alert(e: &ssl::Error) -> bool {
    e.ssl_error().is_some_and(|stack| {
        stack.errors().iter().any(|err| {
            err.library_reason(ffi::ERR_LIB_SSL) == Some(ffi::SSL_R_PROTOCOL_IS_SHUTDOWN)
        })
    })
}
