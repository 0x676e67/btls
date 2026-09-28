//! BoringSSL's built-in certificate verification, run off the handshake thread.
//!
//! BoringSSL has no getters for some of the state its built-in verification reads, so the
//! setters of this crate record it here: the connection's verify store, and whether a custom
//! verify callback or a certificate verify callback is set. State configured through raw
//! [`ffi`] calls instead is not seen.

use super::async_callbacks::{
    with_ex_data_future, BoxCustomVerifyFinish, BoxCustomVerifyFuture,
    SELECT_CUSTOM_VERIFY_FUTURE_INDEX, TASK_WAKER_INDEX,
};
use super::{Ssl, SslAlert, SslContext, SslContextBuilder, SslContextRef, SslRef, SslVerifyError};
use super::{SslVerifyMode, X509VerifyResult};
use crate::ex_data::Index;
use crate::ffi;
use crate::stack::{Stack, StackRef};
use crate::x509::store::{X509Store, X509StoreRef};
use crate::x509::{X509StoreContext, X509VerifyError, X509};
use foreign_types::{ForeignType, ForeignTypeRef};
use std::convert::identity;
use std::ffi::{c_char, c_int, c_long};
use std::future::Future;
use std::pin::Pin;
use std::ptr;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

/// A certificate verification handed to the spawner of
/// [`SslContextBuilder::set_async_default_verify`].
///
/// It may block, e.g. to look up certificates on disk, and should run where that does not hold
/// up other work, such as `tokio::task::spawn_blocking`.
pub type VerifyJob = Box<dyn FnOnce() + Send>;

/// The verify store set with [`SslContextBuilder::set_verify_cert_store`].
static CTX_VERIFY_STORE_INDEX: LazyLock<Index<SslContext, X509Store>> =
    LazyLock::new(|| SslContext::new_ex_index().unwrap());

/// Set when a custom verify callback is configured on the context.
static CTX_CUSTOM_VERIFY_INDEX: LazyLock<Index<SslContext, ()>> =
    LazyLock::new(|| SslContext::new_ex_index().unwrap());

/// Set when [`SslContextBuilder::set_cert_verify_callback`] is configured.
static CTX_CERT_VERIFY_INDEX: LazyLock<Index<SslContext, ()>> =
    LazyLock::new(|| SslContext::new_ex_index().unwrap());

/// The verify store set with [`SslRef::set_verify_cert_store`], until the context changes.
static SSL_VERIFY_STORE_INDEX: LazyLock<Index<Ssl, Option<X509Store>>> =
    LazyLock::new(|| Ssl::new_ex_index().unwrap());

/// Set when a custom verify callback is configured on the connection.
static SSL_CUSTOM_VERIFY_INDEX: LazyLock<Index<Ssl, ()>> =
    LazyLock::new(|| Ssl::new_ex_index().unwrap());

/// The verify result of a failed verification, see [`verify_error`].
static VERIFY_ERROR_INDEX: LazyLock<Index<Ssl, c_int>> =
    LazyLock::new(|| Ssl::new_ex_index().unwrap());

pub(super) fn record_ctx_verify_store(ctx: &mut SslContextBuilder, store: X509Store) {
    ctx.replace_ex_data(*CTX_VERIFY_STORE_INDEX, store);
}

pub(super) fn record_ctx_custom_verify(ctx: &mut SslContextBuilder) {
    ctx.replace_ex_data(*CTX_CUSTOM_VERIFY_INDEX, ());
}

pub(super) fn record_ctx_cert_verify(ctx: &mut SslContextBuilder) {
    ctx.replace_ex_data(*CTX_CERT_VERIFY_INDEX, ());
}

pub(super) fn record_ssl_verify_store(ssl: &mut SslRef, store: X509Store) {
    ssl.replace_ex_data(*SSL_VERIFY_STORE_INDEX, Some(store));
}

pub(super) fn record_ssl_custom_verify(ssl: &mut SslRef) {
    ssl.replace_ex_data(*SSL_CUSTOM_VERIFY_INDEX, ());
}

/// What [`record_context_switch`] needs to know about `ssl` before switching it to `ctx`: `None`
/// if `ctx` is its context already, else whether the current one has a custom verify callback.
pub(super) fn context_switch(ssl: &SslRef, ctx: &SslContextRef) -> Option<bool> {
    let current = ssl.ssl_context();
    (!ptr::eq(current.as_ptr(), ctx.as_ptr()))
        .then(|| has_ctx_flag(current, *CTX_CUSTOM_VERIFY_INDEX))
}

/// Follows `SSL_set_SSL_CTX` switching `ssl` to another context: BoringSSL replaces the
/// connection's certificate configuration, verify store included, with a copy of the new
/// context's, and keeps the callbacks the connection already has.
pub(super) fn record_context_switch(ssl: &mut SslRef, had_custom_verify: bool) {
    if had_custom_verify {
        record_ssl_custom_verify(ssl);
    }
    ssl.replace_ex_data(*SSL_VERIFY_STORE_INDEX, None);
}

fn has_ctx_flag(ctx: &SslContextRef, index: Index<SslContext, ()>) -> bool {
    ctx.ex_data(index).is_some()
}

impl SslContextBuilder {
    /// Runs BoringSSL's built-in certificate verification on another thread.
    ///
    /// When the peer's certificates arrive, the chain, the verify store and the verification
    /// parameters are captured, and `spawn` gets a [`VerifyJob`] that verifies them. Until it has
    /// run, the handshake stops with
    /// [`ErrorCode::WANT_CERTIFICATE_VERIFY`](super::ErrorCode::WANT_CERTIFICATE_VERIFY), and
    /// the task waker ([`SslRef::set_task_waker`]) is woken once it has. Without a task waker the
    /// verification runs on the handshake thread. A job dropped without running fails the
    /// handshake with an internal error.
    ///
    /// The result, the alert and [`SslRef::verify_result`] are those of the built-in
    /// verification, which this replaces while keeping the verify mode. A verify callback
    /// ([`Self::set_verify_callback`]) or a certificate verify callback
    /// ([`Self::set_cert_verify_callback`]) needs the handshake thread, so with one of them set
    /// the verification fails with an internal error; see
    /// [`SslRef::try_set_async_default_verify`] for a variant that checks first.
    ///
    /// # Panics
    ///
    /// This method panics if this context is not configured for X.509 certificates.
    #[doc(alias = "SSL_CTX_set_custom_verify")]
    pub fn set_async_default_verify<S>(&mut self, spawn: S)
    where
        S: Fn(VerifyJob) + Send + Sync + 'static,
    {
        self.ctx.check_x509();
        let mode = unsafe { ffi::SSL_CTX_get_verify_mode(self.as_ptr()) };
        self.set_custom_verify_callback(SslVerifyMode::from_bits_retain(mode), move |ssl| {
            verify(ssl, &spawn)
        });
    }
}

impl SslRef {
    /// Like [`SslContextBuilder::set_async_default_verify`].
    ///
    /// # Panics
    ///
    /// This method panics if this `Ssl` is not configured for X.509 certificates.
    #[doc(alias = "SSL_set_custom_verify")]
    pub fn set_async_default_verify<S>(&mut self, spawn: S)
    where
        S: Fn(VerifyJob) + Send + Sync + 'static,
    {
        self.ssl_context().check_x509();
        let mode = unsafe { ffi::SSL_get_verify_mode(self.as_ptr()) };
        self.set_custom_verify_callback(SslVerifyMode::from_bits_retain(mode), move |ssl| {
            verify(ssl, &spawn)
        });
    }

    /// Like [`Self::set_async_default_verify`], but only for a client whose verification can
    /// move to another thread unchanged. Returns whether it was set.
    ///
    /// It is not set for a server, whose context may change during the handshake, for a
    /// connection without X.509 certificates, or when a custom verify callback, a verify
    /// callback or a certificate verify callback is configured.
    pub fn try_set_async_default_verify<S>(&mut self, spawn: S) -> bool
    where
        S: Fn(VerifyJob) + Send + Sync + 'static,
    {
        let ctx = self.ssl_context();
        if !ctx.has_x509_support()
            || self.is_server()
            || self.ex_data(*SSL_CUSTOM_VERIFY_INDEX).is_some()
            || has_ctx_flag(ctx, *CTX_CUSTOM_VERIFY_INDEX)
            || has_callbacks(self)
        {
            return false;
        }
        self.set_async_default_verify(spawn);
        true
    }
}

/// Whether a callback that takes part in the built-in verification is set.
fn has_callbacks(ssl: &SslRef) -> bool {
    let verify_callback = unsafe { ffi::SSL_get_verify_callback(ssl.as_ptr()) };
    verify_callback.is_some() || has_ctx_flag(ssl.ssl_context(), *CTX_CERT_VERIFY_INDEX)
}

/// The custom verify callback: verifies the peer's chain in a job and returns its result.
fn verify(ssl: &mut SslRef, spawn: &dyn Fn(VerifyJob)) -> Result<(), SslVerifyError> {
    if ssl.ex_data(*TASK_WAKER_INDEX).is_none_or(Option::is_none) {
        // Nothing would wake the handshake once a job is done.
        let (verification, chain) = Verification::new(ssl).map_err(SslVerifyError::Invalid)?;
        return finish(ssl, &chain, verification.run()).map_err(SslVerifyError::Invalid);
    }

    let result = with_ex_data_future(
        &mut *ssl,
        *SELECT_CUSTOM_VERIFY_FUTURE_INDEX,
        |ssl| ssl,
        |ssl| start(ssl, spawn),
        identity,
    );
    match result {
        Poll::Ready(Ok(finish)) => finish(ssl).map_err(SslVerifyError::Invalid),
        Poll::Ready(Err(alert)) => Err(SslVerifyError::Invalid(alert)),
        Poll::Pending => Err(SslVerifyError::Retry),
    }
}

/// Hands the verification of `ssl`'s peer chain to `spawn`.
fn start(ssl: &mut SslRef, spawn: &dyn Fn(VerifyJob)) -> Result<BoxCustomVerifyFuture, SslAlert> {
    let (verification, chain) = Verification::new(ssl)?;
    let shared = Arc::new(Mutex::new(Shared::default()));
    let job = Job {
        verification: Some(verification),
        shared: shared.clone(),
    };
    spawn(Box::new(move || job.run()));
    Ok(Box::pin(VerifyFuture {
        shared,
        chain: Some(chain),
    }))
}

/// Turns the outcome of a verification into the result of the custom verify callback.
fn finish(ssl: &mut SslRef, chain: &[X509], outcome: Outcome) -> Result<(), SslAlert> {
    // The handshake waits in the same state while the job runs, so the peer's chain is still the
    // one that was verified. The result is only good for those certificates, so make sure.
    if !is_peer_chain(ssl, chain) {
        return Err(SslAlert::INTERNAL_ERROR);
    }

    match outcome {
        Outcome::Verified { ok: true, .. } => Ok(()),
        // As in ssl_crypto_x509_session_verify_cert_chain.
        Outcome::Verified { ok: false, error } => {
            ssl.replace_ex_data(*VERIFY_ERROR_INDEX, error);
            Err(SslAlert(unsafe {
                ffi::SSL_alert_from_verify_result(c_long::from(error))
            }))
        }
        Outcome::Dropped => Err(SslAlert::INTERNAL_ERROR),
    }
}

/// The verify result of the failed verification of this connection.
///
/// BoringSSL records `X509_V_ERR_APPLICATION_VERIFICATION` when a custom verification fails, so
/// [`SslRef::verify_result`] reports this instead. A resumed session keeps the former.
pub(super) fn verify_error(ssl: &SslRef, result: X509VerifyResult) -> X509VerifyResult {
    match (result, ssl.ex_data(*VERIFY_ERROR_INDEX)) {
        (Err(X509VerifyError::APPLICATION_VERIFICATION), Some(&error)) => unsafe {
            X509VerifyError::from_raw(error)
        },
        _ => result,
    }
}

/// Whether the peer's certificate chain of `ssl` consists of the very certificates of `chain`.
fn is_peer_chain(ssl: &SslRef, chain: &[X509]) -> bool {
    let current = unsafe { ffi::SSL_get_peer_full_cert_chain(ssl.as_ptr()) };
    if current.is_null() {
        return false;
    }
    let current = unsafe { StackRef::<X509>::from_ptr(current) };
    current.len() == chain.len()
        && current
            .iter()
            .zip(chain)
            .all(|(a, b)| ptr::eq(a.as_ptr(), b.as_ptr()))
}

/// What a job shares with the handshake waiting for it.
#[derive(Default)]
struct Shared {
    outcome: Option<Outcome>,
    waker: Option<Waker>,
}

fn lock(shared: &Mutex<Shared>) -> MutexGuard<'_, Shared> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

enum Outcome {
    /// `X509_verify_cert` ran: whether it succeeded, and the verify result it left.
    Verified { ok: bool, error: c_int },
    /// The job was dropped without running.
    Dropped,
}

struct Job {
    verification: Option<Verification>,
    shared: Arc<Mutex<Shared>>,
}

impl Job {
    fn run(mut self) {
        if let Some(verification) = self.verification.take() {
            self.complete(verification.run());
        }
    }

    /// Stores the outcome, unless there is one already, and wakes the handshake.
    fn complete(&self, outcome: Outcome) {
        let waker = {
            let mut shared = lock(&self.shared);
            if shared.outcome.is_some() {
                return;
            }
            shared.outcome = Some(outcome);
            shared.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // Does nothing once the job has run.
        self.complete(Outcome::Dropped);
    }
}

struct VerifyFuture {
    shared: Arc<Mutex<Shared>>,
    chain: Option<Vec<X509>>,
}

impl Future for VerifyFuture {
    type Output = Result<BoxCustomVerifyFinish, SslAlert>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let outcome = {
            let mut shared = lock(&self.shared);
            match shared.outcome.take() {
                Some(outcome) => outcome,
                None => {
                    shared.waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
            }
        };
        let chain = self.chain.take().unwrap_or_default();
        Poll::Ready(Ok(Box::new(move |ssl| finish(ssl, &chain, outcome))))
    }
}

/// An `X509_STORE_CTX` set up like the one of BoringSSL's built-in verification
/// (`ssl_crypto_x509_session_verify_cert_chain`). It owns what the context points to, so it can
/// outlive the handshake and move to another thread.
struct Verification {
    // Dropped first: it points to the store and the chain.
    ctx: X509StoreContext,
    _chain: Stack<X509>,
    _store: X509Store,
}

impl Verification {
    /// Returns the verification of `ssl`'s peer chain and the certificates it verifies.
    fn new(ssl: &SslRef) -> Result<(Self, Vec<X509>), SslAlert> {
        const INTERNAL_ERROR: SslAlert = SslAlert::INTERNAL_ERROR;

        if has_callbacks(ssl) {
            return Err(INTERNAL_ERROR);
        }

        let chain: Vec<X509> = unsafe {
            let chain = ffi::SSL_get_peer_full_cert_chain(ssl.as_ptr());
            if chain.is_null() {
                return Err(INTERNAL_ERROR);
            }
            StackRef::<X509>::from_ptr(chain)
                .iter()
                .map(ToOwned::to_owned)
                .collect()
        };
        let Some(leaf) = chain.first() else {
            return Err(INTERNAL_ERROR);
        };

        let store = verify_store(ssl);
        let mut owned_chain = Stack::new().map_err(|_| INTERNAL_ERROR)?;
        for cert in &chain {
            owned_chain.push(cert.clone()).map_err(|_| INTERNAL_ERROR)?;
        }
        let ctx = X509StoreContext::new().map_err(|_| INTERNAL_ERROR)?;

        let purpose = if ssl.is_server() {
            c"ssl_client"
        } else {
            c"ssl_server"
        };
        let mut name: *const c_char = ptr::null();
        let mut name_len = 0;
        unsafe {
            ffi::SSL_get0_ech_name_override(ssl.as_ptr(), &mut name, &mut name_len);
            // The parameters only exist once the context is initialized.
            let ok = ffi::X509_STORE_CTX_init(
                ctx.as_ptr(),
                store.as_ptr(),
                leaf.as_ptr(),
                owned_chain.as_ptr(),
            ) != 0
                && ffi::X509_STORE_CTX_set_default(ctx.as_ptr(), purpose.as_ptr()) != 0
                && {
                    let param = ffi::X509_STORE_CTX_get0_param(ctx.as_ptr());
                    // Anything non-default in the connection's parameters overrides the store's.
                    ffi::X509_VERIFY_PARAM_set1(param, ffi::SSL_get0_param(ssl.as_ptr())) != 0
                        // A rejected ECH is verified against the public name.
                        && (name_len == 0
                            || ffi::X509_VERIFY_PARAM_set1_host(param, name, name_len) != 0)
                };
            if !ok {
                ffi::ERR_clear_error();
                return Err(INTERNAL_ERROR);
            }
        }

        let verification = Verification {
            ctx,
            _chain: owned_chain,
            _store: store,
        };
        Ok((verification, chain))
    }

    fn run(self) -> Outcome {
        unsafe {
            let ok = ffi::X509_verify_cert(self.ctx.as_ptr()) > 0;
            let error = ffi::X509_STORE_CTX_get_error(self.ctx.as_ptr());
            // Do not leave errors on this thread for unrelated work to find.
            ffi::ERR_clear_error();
            Outcome::Verified { ok, error }
        }
    }
}

/// The store the built-in verification of `ssl` uses: the connection's verify store, else the
/// context's certificate store.
fn verify_store(ssl: &SslRef) -> X509Store {
    if let Some(Some(store)) = ssl.ex_data(*SSL_VERIFY_STORE_INDEX) {
        return store.clone();
    }
    let ctx = ssl.ssl_context();
    if let Some(store) = ctx.ex_data(*CTX_VERIFY_STORE_INDEX) {
        return store.clone();
    }
    unsafe { X509StoreRef::from_ptr(ffi::SSL_CTX_get_cert_store(ctx.as_ptr())).to_owned() }
}
