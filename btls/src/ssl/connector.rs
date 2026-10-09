use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{SystemTime, UNIX_EPOCH};

use foreign_types::ForeignTypeRef;
use openssl_macros::corresponds;

use crate::dh::Dh;
use crate::error::ErrorStack;
use crate::ex_data::Index;
use crate::ffi;
use crate::ssl::{
    HandshakeError, Ssl, SslContext, SslContextBuilder, SslContextRef, SslMethod, SslMode,
    SslOptions, SslRef, SslSession, SslSessionRef, SslStream, SslVerifyMode,
};
use crate::stack::StackRef;
use crate::version;
use crate::x509::{X509Ref, X509};
use std::net::IpAddr;

use super::callbacks::raw_client_session;
use super::{MidHandshakeSslStream, SESSION_CTX_INDEX};

pub(super) static CLIENT_SESSION_INDEX: LazyLock<Index<SslContext, ClientSessionCallback>> =
    LazyLock::new(|| SslContext::new_ex_index().unwrap());
pub(super) static SESSION_PEER_INDEX: LazyLock<Index<Ssl, SessionPeer>> =
    LazyLock::new(|| Ssl::new_ex_index().unwrap());
static NEXT_ISSUER: AtomicU64 = AtomicU64::new(1);

const FFDHE_2048: &str = "
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----
";

#[allow(clippy::inconsistent_digit_grouping)]
fn ctx(method: SslMethod) -> Result<SslContextBuilder, ErrorStack> {
    let mut ctx = SslContextBuilder::new(method)?;

    let mut opts = SslOptions::ALL
        | SslOptions::NO_COMPRESSION
        | SslOptions::NO_SSLV2
        | SslOptions::NO_SSLV3
        | SslOptions::SINGLE_DH_USE
        | SslOptions::SINGLE_ECDH_USE;
    opts &= !SslOptions::DONT_INSERT_EMPTY_FRAGMENTS;

    ctx.set_options(opts);

    let mut mode =
        SslMode::AUTO_RETRY | SslMode::ACCEPT_MOVING_WRITE_BUFFER | SslMode::ENABLE_PARTIAL_WRITE;

    // This is quite a useful optimization for saving memory, but historically
    // caused CVEs in OpenSSL pre-1.0.1h, according to
    // https://bugs.python.org/issue25672
    if version::number() >= 0x1000_1080 {
        mode |= SslMode::RELEASE_BUFFERS;
    }

    ctx.set_mode(mode);

    Ok(ctx)
}

/// A type which wraps client-side streams in a TLS session.
///
/// OpenSSL's default configuration is highly insecure. This connector manages the OpenSSL
/// structures, configuring cipher suites, session options, hostname verification, and more.
///
/// OpenSSL's built in hostname verification is used when linking against OpenSSL 1.0.2 or 1.1.0,
/// and a custom implementation is used when linking against OpenSSL 1.0.1.
#[derive(Clone, Debug)]
pub struct SslConnector(SslContext);

impl SslConnector {
    /// Creates a new builder for TLS connections.
    ///
    /// The default configuration is subject to change, and is currently derived from Python.
    pub fn builder(method: SslMethod) -> Result<SslConnectorBuilder, ErrorStack> {
        let mut ctx = ctx(method)?;
        ctx.set_default_verify_paths()?;
        ctx.set_cipher_list(
            "DEFAULT:!aNULL:!eNULL:!MD5:!3DES:!DES:!RC4:!IDEA:!SEED:!aDSS:!SRP:!PSK",
        )?;
        ctx.set_verify(SslVerifyMode::PEER);

        Ok(SslConnectorBuilder(ctx))
    }

    /// Creates a bare builder for TLS connections without default CA certificates.
    ///
    /// The caller is responsible for providing a custom certificate store.
    pub fn bare_builder(method: SslMethod) -> Result<SslConnectorBuilder, ErrorStack> {
        let mut ctx = ctx(method)?;
        ctx.set_cipher_list(
            "DEFAULT:!aNULL:!eNULL:!MD5:!3DES:!DES:!RC4:!IDEA:!SEED:!aDSS:!SRP:!PSK",
        )?;

        Ok(SslConnectorBuilder(ctx))
    }

    /// Initiates a client-side TLS session on a stream.
    ///
    /// The domain is used for SNI and hostname verification.
    pub fn setup_connect<S>(
        &self,
        domain: &str,
        stream: S,
    ) -> Result<MidHandshakeSslStream<S>, ErrorStack>
    where
        S: Read + Write,
    {
        self.configure()?.setup_connect(domain, stream)
    }

    /// Attempts a client-side TLS session on a stream.
    ///
    /// The domain is used for SNI (if it is not an IP address) and hostname verification if enabled.
    ///
    /// This is a convenience method which combines [`Self::setup_connect`] and
    /// [`MidHandshakeSslStream::handshake`].
    pub fn connect<S>(&self, domain: &str, stream: S) -> Result<SslStream<S>, HandshakeError<S>>
    where
        S: Read + Write,
    {
        self.setup_connect(domain, stream)
            .map_err(HandshakeError::SetupFailure)?
            .handshake()
    }

    /// Returns a structure allowing for configuration of a single TLS session before connection.
    pub fn configure(&self) -> Result<ConnectConfiguration, ErrorStack> {
        Ssl::new(&self.0).map(|ssl| ConnectConfiguration {
            ssl,
            sni: true,
            verify_hostname: true,
            session: None,
        })
    }

    /// Consumes the `SslConnector`, returning the inner raw `SslContext`.
    #[must_use]
    pub fn into_context(self) -> SslContext {
        self.0
    }

    /// Returns a shared reference to the inner raw `SslContext`.
    #[must_use]
    pub fn context(&self) -> &SslContextRef {
        &self.0
    }
}

/// A builder for `SslConnector`s.
pub struct SslConnectorBuilder(SslContextBuilder);

impl SslConnectorBuilder {
    /// Consumes the builder, returning an `SslConnector`.
    #[must_use]
    pub fn build(self) -> SslConnector {
        SslConnector(self.0.build())
    }

    /// Sets the callback which receives sessions for [`ConnectConfiguration::set_client_session`].
    ///
    /// Client session caching is enabled. Only connections created by
    /// [`ConnectConfiguration::into_ssl`] report sessions. This shares BoringSSL's new session
    /// callback with [`SslContextBuilder::set_new_session_callback`]; the last one set wins.
    #[corresponds(SSL_CTX_sess_set_new_cb)]
    pub fn set_client_session_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut SslRef, ClientSession) + 'static + Sync + Send,
    {
        let callback = ClientSessionCallback {
            issuer: NEXT_ISSUER.fetch_add(1, Ordering::Relaxed),
            callback: Box::new(callback),
        };
        self.replace_ex_data(*CLIENT_SESSION_INDEX, callback);
        unsafe {
            let mode =
                ffi::SSL_CTX_get_session_cache_mode(self.as_ptr()) | ffi::SSL_SESS_CACHE_CLIENT;
            ffi::SSL_CTX_set_session_cache_mode(self.as_ptr(), mode);
            ffi::SSL_CTX_sess_set_new_cb(self.as_ptr(), Some(raw_client_session));
        }
    }
}

impl Deref for SslConnectorBuilder {
    type Target = SslContextBuilder;

    fn deref(&self) -> &SslContextBuilder {
        &self.0
    }
}

impl DerefMut for SslConnectorBuilder {
    fn deref_mut(&mut self) -> &mut SslContextBuilder {
        &mut self.0
    }
}

/// A type which allows for configuration of a client-side TLS session before connection.
pub struct ConnectConfiguration {
    ssl: Ssl,
    sni: bool,
    verify_hostname: bool,
    session: Option<ClientSession>,
}

/// A client session and the connection it was issued on.
///
/// Sessions come from [`SslConnectorBuilder::set_client_session_callback`].
/// [`ConnectConfiguration::set_client_session`] offers one only to a connection with the same
/// domain and SNI use, no stricter hostname or peer verification, and the same non-empty
/// [session ID context](SslContextBuilder::set_session_id_context) or, without one, the same
/// context. A connection that verifies the peer is not offered a session whose certificate chain
/// has expired. Other per-connection changes through [`SslRef`], such as verify callbacks, verify
/// stores, or client certificates, are not tracked.
#[derive(Clone)]
pub struct ClientSession {
    session: SslSession,
    peer: SessionPeer,
    verify_peer: bool,
    /// Earliest expiry in the peer certificate chain, as POSIX time.
    not_after: Option<i64>,
    /// Callback token of the issuing context, compared when the session has no session ID context.
    issuer: Option<u64>,
}

/// Domain, SNI, and hostname verification of a connection created by
/// [`ConnectConfiguration::into_ssl`].
#[derive(Clone)]
pub(super) struct SessionPeer {
    domain: Arc<str>,
    sni: bool,
    verify_hostname: bool,
}

type ClientSessionFn = dyn Fn(&mut SslRef, ClientSession) + Sync + Send;

/// Client session callback, boxed so connections can find it without knowing its type.
///
/// The issuer token identifies the context without keeping it alive.
pub(super) struct ClientSessionCallback {
    issuer: u64,
    pub(super) callback: Box<ClientSessionFn>,
}

impl ClientSession {
    pub(super) fn new(session: SslSession, peer: SessionPeer, ssl: &SslRef) -> Self {
        ClientSession {
            session,
            peer,
            verify_peer: verifies_peer(ssl),
            not_after: chain_not_after(ssl),
            issuer: issuer(ssl.ssl_context()),
        }
    }

    /// Returns the underlying session.
    #[must_use]
    pub fn session(&self) -> &SslSessionRef {
        &self.session
    }

    /// Checks the session against the connection `ssl` will make to `domain`.
    ///
    /// BoringSSL rejects another session ID context only after the server resumes, and skips
    /// certificate checks on resumption unless reverify-on-resume runs a custom verifier.
    fn resumes(&self, ssl: &SslRef, domain: &str, sni: bool, verify_hostname: bool) -> bool {
        let scope = self.session.id_context();
        let verify_peer = verifies_peer(ssl);
        ssl.session_id_context() == Some(scope)
            && (!scope.is_empty()
                || self.issuer.is_some() && self.issuer == issuer(ssl.ssl_context()))
            && self.peer.domain.eq_ignore_ascii_case(domain)
            && self.peer.sni == sni
            && (self.peer.verify_hostname || !verify_hostname)
            && (self.verify_peer || !verify_peer)
            // Re-verification would reject an expired chain and fail the handshake.
            && !(verify_peer && self.chain_expired())
    }

    /// Returns whether a certificate in the peer chain has expired by now.
    fn chain_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|now| i64::try_from(now.as_secs()).ok());
        matches!((self.not_after, now), (Some(not_after), Some(now)) if now >= not_after)
    }
}

/// Returns the earliest expiry in the peer certificate chain, as POSIX time.
fn chain_not_after(ssl: &SslRef) -> Option<i64> {
    if !ssl.ssl_context().has_x509_support() {
        return None;
    }

    // SAFETY: the context uses the X.509 method, and the chain lives as long as the session
    // borrowed through `ssl`.
    let chain = unsafe { ffi::SSL_get_peer_full_cert_chain(ssl.as_ptr()) };
    if chain.is_null() {
        return None;
    }
    let chain = unsafe { StackRef::<X509>::from_ptr(chain) };
    earliest_not_after(chain)
}

/// Returns the earliest expiry among `certs`, as POSIX time.
pub(super) fn earliest_not_after<I>(certs: I) -> Option<i64>
where
    I: IntoIterator,
    I::Item: Deref<Target = X509Ref>,
{
    certs
        .into_iter()
        .filter_map(|cert| {
            let mut not_after = 0;
            // SAFETY: `cert` is valid, and `not_after` is a valid output.
            let ok = unsafe { ffi::ASN1_TIME_to_posix(cert.not_after().as_ptr(), &mut not_after) };
            (ok == 1).then_some(not_after)
        })
        .min()
}

/// Returns the token of the client session callback installed on `context`.
fn issuer(context: &SslContextRef) -> Option<u64> {
    context
        .ex_data(*CLIENT_SESSION_INDEX)
        .map(|callback| callback.issuer)
}

/// Returns whether `ssl` verifies the peer certificate; an unavailable mode counts as not.
fn verifies_peer(ssl: &SslRef) -> bool {
    // SAFETY: `ssl` is a valid connection; BoringSSL returns -1 when its configuration is gone.
    let mode = unsafe { ffi::SSL_get_verify_mode(ssl.as_ptr()) };
    mode >= 0 && SslVerifyMode::from_bits_retain(mode).contains(SslVerifyMode::PEER)
}

impl ConnectConfiguration {
    /// A builder-style version of `set_use_server_name_indication`.
    #[must_use]
    pub fn use_server_name_indication(mut self, use_sni: bool) -> ConnectConfiguration {
        self.set_use_server_name_indication(use_sni);
        self
    }

    /// Configures the use of Server Name Indication (SNI) when connecting.
    ///
    /// Defaults to `true`.
    pub fn set_use_server_name_indication(&mut self, use_sni: bool) {
        self.sni = use_sni;
    }

    /// A builder-style version of `set_verify_hostname`.
    #[must_use]
    pub fn verify_hostname(mut self, verify_hostname: bool) -> ConnectConfiguration {
        self.set_verify_hostname(verify_hostname);
        self
    }

    /// Configures the use of hostname verification when connecting.
    ///
    /// Defaults to `true`.
    ///
    /// # Warning
    ///
    /// You should think very carefully before you use this method. If hostname verification is not
    /// used, *any* valid certificate for *any* site will be trusted for use from any other. This
    /// introduces a significant vulnerability to man-in-the-middle attacks.
    pub fn set_verify_hostname(&mut self, verify_hostname: bool) {
        self.verify_hostname = verify_hostname;
    }

    /// A builder-style version of `set_client_session`.
    #[must_use]
    pub fn client_session(mut self, session: ClientSession) -> ConnectConfiguration {
        self.set_client_session(session);
        self
    }

    /// Offers a session for resumption.
    ///
    /// [`Self::into_ssl`] drops it unless it matches the connection as described on
    /// [`ClientSession`], and the handshake then proceeds without resumption.
    pub fn set_client_session(&mut self, session: ClientSession) {
        self.session = Some(session);
    }

    /// Returns an [`Ssl`] configured to connect to the provided domain.
    ///
    /// The domain is used for SNI (if it is not an IP address) and hostname verification if enabled.
    pub fn into_ssl(mut self, domain: &str) -> Result<Ssl, ErrorStack> {
        let sni = self.sni && domain.parse::<IpAddr>().is_err();
        if sni {
            self.ssl.set_hostname(domain)?;
        }

        if self.verify_hostname {
            setup_verify_hostname(&mut self.ssl, domain)?;
        }

        let reports_sessions = self
            .ssl
            .ex_data(*SESSION_CTX_INDEX)
            .is_some_and(|context| context.ex_data(*CLIENT_SESSION_INDEX).is_some());
        if reports_sessions {
            let peer = SessionPeer {
                domain: domain.into(),
                sni,
                verify_hostname: self.verify_hostname,
            };
            self.ssl.set_ex_data(*SESSION_PEER_INDEX, peer);
        }

        if let Some(session) = self
            .session
            .take()
            .filter(|session| session.resumes(&self.ssl, domain, sni, self.verify_hostname))
        {
            // SAFETY: `self.ssl` has not been attached to a stream, so its handshake has not
            // started, and the session was issued for a connection this one matches.
            unsafe { self.ssl.set_session(&session.session)? };
        }

        Ok(self.ssl)
    }

    /// Initiates a client-side TLS session on a stream.
    ///
    /// The domain is used for SNI (if it is not an IP address) and hostname verification if enabled.
    ///
    /// This is a convenience method which combines [`Self::into_ssl`] and
    /// [`Ssl::setup_connect`].
    pub fn setup_connect<S>(
        self,
        domain: &str,
        stream: S,
    ) -> Result<MidHandshakeSslStream<S>, ErrorStack>
    where
        S: Read + Write,
    {
        Ok(self.into_ssl(domain)?.setup_connect(stream))
    }

    /// Attempts a client-side TLS session on a stream.
    ///
    /// The domain is used for SNI (if it is not an IP address) and hostname verification if enabled.
    ///
    /// This is a convenience method which combines [`Self::setup_connect`] and
    /// [`MidHandshakeSslStream::handshake`].
    pub fn connect<S>(self, domain: &str, stream: S) -> Result<SslStream<S>, HandshakeError<S>>
    where
        S: Read + Write,
    {
        self.setup_connect(domain, stream)
            .map_err(HandshakeError::SetupFailure)?
            .handshake()
    }
}

impl Deref for ConnectConfiguration {
    type Target = SslRef;

    fn deref(&self) -> &SslRef {
        &self.ssl
    }
}

impl DerefMut for ConnectConfiguration {
    fn deref_mut(&mut self) -> &mut SslRef {
        &mut self.ssl
    }
}

/// A type which wraps server-side streams in a TLS session.
///
/// OpenSSL's default configuration is highly insecure. This connector manages the OpenSSL
/// structures, configuring cipher suites, session options, and more.
#[derive(Clone)]
pub struct SslAcceptor(SslContext);

impl SslAcceptor {
    /// Creates a new builder configured to connect to non-legacy clients. This should generally be
    /// considered a reasonable default choice.
    ///
    /// This corresponds to the intermediate configuration of version 5 of Mozilla's server side TLS
    /// recommendations. See its [documentation][docs] for more details on specifics.
    ///
    /// [docs]: https://wiki.mozilla.org/Security/Server_Side_TLS
    pub fn mozilla_intermediate_v5(method: SslMethod) -> Result<SslAcceptorBuilder, ErrorStack> {
        let mut ctx = ctx(method)?;
        ctx.set_options(SslOptions::NO_TLSV1 | SslOptions::NO_TLSV1_1);
        let dh = Dh::params_from_pem(FFDHE_2048.as_bytes())?;
        ctx.set_tmp_dh(&dh)?;
        ctx.set_cipher_list(
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:\
             ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
             DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
        )?;
        Ok(SslAcceptorBuilder(ctx))
    }

    /// Creates a new builder configured to connect to non-legacy clients. This should generally be
    /// considered a reasonable default choice.
    ///
    /// This corresponds to the intermediate configuration of version 4 of Mozilla's server side TLS
    /// recommendations. See its [documentation][docs] for more details on specifics.
    ///
    /// [docs]: https://wiki.mozilla.org/Security/Server_Side_TLS
    // FIXME remove in next major version
    pub fn mozilla_intermediate(method: SslMethod) -> Result<SslAcceptorBuilder, ErrorStack> {
        let mut ctx = ctx(method)?;
        ctx.set_options(SslOptions::CIPHER_SERVER_PREFERENCE);
        ctx.set_options(SslOptions::NO_TLSV1_3);
        let dh = Dh::params_from_pem(FFDHE_2048.as_bytes())?;
        ctx.set_tmp_dh(&dh)?;
        ctx.set_cipher_list(
            "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:\
             ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
             DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:\
             ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:\
             ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:\
             DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:\
             EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:\
             AES256-SHA:DES-CBC3-SHA:!DSS",
        )?;
        Ok(SslAcceptorBuilder(ctx))
    }

    /// Creates a new builder configured to connect to modern clients.
    ///
    /// This corresponds to the modern configuration of version 4 of Mozilla's server side TLS recommendations.
    /// See its [documentation][docs] for more details on specifics.
    ///
    /// [docs]: https://wiki.mozilla.org/Security/Server_Side_TLS
    // FIXME remove in next major version
    pub fn mozilla_modern(method: SslMethod) -> Result<SslAcceptorBuilder, ErrorStack> {
        let mut ctx = ctx(method)?;
        ctx.set_options(
            SslOptions::CIPHER_SERVER_PREFERENCE | SslOptions::NO_TLSV1 | SslOptions::NO_TLSV1_1,
        );
        ctx.set_options(SslOptions::NO_TLSV1_3);
        ctx.set_cipher_list(
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:\
             ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
             ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256",
        )?;
        Ok(SslAcceptorBuilder(ctx))
    }

    /// Initiates a server-side TLS handshake on a stream.
    ///
    /// See [`Ssl::setup_accept`] for more details.
    pub fn setup_accept<S>(&self, stream: S) -> Result<MidHandshakeSslStream<S>, ErrorStack>
    where
        S: Read + Write,
    {
        let ssl = Ssl::new(&self.0)?;

        Ok(ssl.setup_accept(stream))
    }

    /// Attempts a server-side TLS handshake on a stream.
    ///
    /// This is a convenience method which combines [`Self::setup_accept`] and
    /// [`MidHandshakeSslStream::handshake`].
    pub fn accept<S>(&self, stream: S) -> Result<SslStream<S>, HandshakeError<S>>
    where
        S: Read + Write,
    {
        self.setup_accept(stream)
            .map_err(HandshakeError::SetupFailure)?
            .handshake()
    }

    /// Consumes the `SslAcceptor`, returning the inner raw `SslContext`.
    #[must_use]
    pub fn into_context(self) -> SslContext {
        self.0
    }

    /// Returns a shared reference to the inner raw `SslContext`.
    #[must_use]
    pub fn context(&self) -> &SslContextRef {
        &self.0
    }
}

/// A builder for `SslAcceptor`s.
pub struct SslAcceptorBuilder(SslContextBuilder);

impl SslAcceptorBuilder {
    /// Consumes the builder, returning a `SslAcceptor`.
    #[must_use]
    pub fn build(self) -> SslAcceptor {
        SslAcceptor(self.0.build())
    }
}

impl Deref for SslAcceptorBuilder {
    type Target = SslContextBuilder;

    fn deref(&self) -> &SslContextBuilder {
        &self.0
    }
}

impl DerefMut for SslAcceptorBuilder {
    fn deref_mut(&mut self) -> &mut SslContextBuilder {
        &mut self.0
    }
}

fn setup_verify_hostname(ssl: &mut SslRef, domain: &str) -> Result<(), ErrorStack> {
    use crate::x509::verify::X509CheckFlags;

    let param = ssl.param_mut();
    param.set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS);
    match domain.parse() {
        Ok(ip) => param.set_ip(ip),
        Err(_) => param.set_host(domain),
    }
}
