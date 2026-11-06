use std::{io, pin::Pin, task::Context};

/// The underlying stream and the task context of the poll driving it.
///
/// Each poll installs its context for the transport I/O it drives and clears it afterwards.
pub(crate) struct Transport<S> {
    pub(crate) stream: S,
    // Address of the installed `Context`, or 0. An address, unlike a pointer, keeps `Send`/`Sync`.
    context: usize,
}

impl<S> Transport<S> {
    pub(crate) fn new(stream: S) -> Self {
        Transport { stream, context: 0 }
    }

    /// Installs `cx` as the context of later [`parts`](Self::parts) calls.
    ///
    /// # Safety
    ///
    /// `cx` and the waker it borrows must stay valid, and `cx` otherwise unused, until
    /// [`clear_context`](Self::clear_context) runs. Unless `S: Unpin`, `stream` must not move from
    /// the first `parts` call until it is dropped.
    #[inline]
    pub(crate) unsafe fn set_context(&mut self, cx: &mut Context<'_>) {
        self.context = cx as *mut _ as usize;
    }

    #[inline]
    pub(crate) fn clear_context(&mut self) {
        self.context = 0;
    }

    /// Returns the pinned stream and the installed context; fails outside a poll.
    #[inline]
    pub(crate) fn parts(&mut self) -> io::Result<(Pin<&mut S>, &mut Context<'_>)> {
        if self.context == 0 {
            return Err(io::Error::other("TLS transport used outside a poll"));
        }
        // SAFETY: a nonzero `context` comes from `set_context`, whose caller keeps the context
        // valid until `clear_context` and keeps the stream pinned.
        unsafe {
            Ok((
                Pin::new_unchecked(&mut self.stream),
                &mut *(self.context as *mut Context<'_>),
            ))
        }
    }
}

#[cfg(test)]
impl<S: Unpin> Transport<S> {
    /// Installs a context with a no-op waker for the rest of the test.
    pub(crate) fn set_noop_context(&mut self) {
        let cx = Box::leak(Box::new(Context::from_waker(std::task::Waker::noop())));
        // SAFETY: the leaked context is never freed, and an `Unpin` stream may move.
        unsafe { self.set_context(cx) };
    }
}
