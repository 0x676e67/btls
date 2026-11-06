use std::{pin::Pin, task::Context};

/// The underlying stream and the task context of the poll driving it.
///
/// `context` is valid only inside `SslStream::with_context`, so all I/O through
/// [`parts`](Self::parts) happens there.
pub(crate) struct Transport<S> {
    pub(crate) stream: S,
    // Address of the `Context` installed by `SslStream::with_context`; reset to 0 when it returns.
    pub(crate) context: usize,
}

impl<S> Transport<S> {
    /// Returns the pinned stream and the context of the poll in progress.
    ///
    /// Must only run inside `SslStream::with_context`, which installs `context`.
    #[inline]
    pub(crate) fn parts(&mut self) -> (Pin<&mut S>, &mut Context<'_>) {
        debug_assert_ne!(self.context, 0);
        // SAFETY: every caller runs inside the `f` of `SslStream::with_context`: the BIO
        // callbacks, `write::write_records`, and `SslStreamCore::flush` from `poll_flush`. That
        // call stores the address of its live `&mut Context` before `f` and keeps it borrowed
        // throughout, so the pointer is non-null and live; a value left stale by an unwinding `f`
        // is overwritten before the next call. It takes the `SslStream` pinned and never moves
        // the stream out, so the stream stays pinned. Unit tests install a live local `Context`
        // the same way, with `Unpin` streams.
        unsafe {
            (
                Pin::new_unchecked(&mut self.stream),
                &mut *(self.context as *mut Context<'_>),
            )
        }
    }
}
