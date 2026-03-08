use crate::alpn::AlpnProtocols;
use crate::bffi_ext::QuicSsl;
use crate::error::{map_result, Result};
use crate::secret::Secrets;
use crate::session_state::{SessionState, QUIC_METHOD};
use crate::version::QuicVersion;
use crate::{retry, QuicSslContext};
use btls::ssl::{Ssl, SslContext, SslContextBuilder, SslMethod, SslVersion};
use btls_sys as bffi;
use bytes::{Bytes, BytesMut};
use foreign_types_shared::ForeignType;
use quinn_proto::{
    crypto, transport_parameters::TransportParameters, ConnectionId, Side, TransportError,
};
use std::any::Any;
use std::ffi::{c_int, c_uint, c_void};
use std::result::Result as StdResult;
use std::slice;
use std::sync::Arc;
use std::sync::LazyLock;

/// Configuration for a server-side QUIC. Wraps around a BoringSSL [SslContext].
pub struct Config {
    ctx: SslContext,
    alpn_protocols: AlpnProtocols,
}

impl Config {
    pub fn new() -> Result<Self> {
        let mut builder = SslContextBuilder::new(SslMethod::tls())?;

        // QUIC requires TLS 1.3.
        builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

        builder.set_default_verify_paths()?;

        // We build the context early, since we are not allowed to further mutate the context
        // in start_session.
        let mut ctx = builder.build();

        // Disable verification of the client by default.
        ctx.verify_peer(false);

        // By default, enable early data (used for 0-RTT).
        ctx.enable_early_data(true);

        // Configure default ALPN protocols accepted by the server.QUIC requires ALPN be
        // configured (see https://www.rfc-editor.org/rfc/rfc9001.html#section-8.1).
        ctx.set_alpn_select_cb(Some(Session::alpn_select_callback));

        // Set the callback for receipt of the Server Name Indication (SNI) extension.
        ctx.set_server_name_cb(Some(Session::server_name_callback));

        // Set callbacks for the SessionState.
        ctx.set_quic_method(&QUIC_METHOD)?;
        ctx.set_info_callback(Some(SessionState::info_callback));

        ctx.set_options(bffi::SSL_OP_CIPHER_SERVER_PREFERENCE as u32);

        Ok(Self {
            ctx,
            alpn_protocols: AlpnProtocols::default(),
        })
    }

    /// Returns the underlying [SslContext] backing all created sessions.
    pub fn ctx(&self) -> &SslContext {
        &self.ctx
    }

    /// Returns the underlying [SslContext] backing all created sessions. Wherever possible use
    /// the provided methods to modify settings rather than accessing this directly.
    ///
    /// Care should be taken to avoid overriding required behavior. In particular, this
    /// configuration will set callbacks for QUIC events, alpn selection, server name,
    /// as well as info and key logging.
    pub fn ctx_mut(&mut self) -> &mut SslContext {
        &mut self.ctx
    }

    /// Sets whether or not the peer certificate should be verified. If `true`, any error
    /// during verification will be fatal. If not called, verification of the client is
    /// disabled by default.
    pub fn verify_peer(&mut self, verify: bool) {
        self.ctx.verify_peer(verify)
    }

    /// Sets the ALPN protocols that will be accepted by the server. QUIC requires that
    /// ALPN be used (see <https://www.rfc-editor.org/rfc/rfc9001.html#section-8.1>).
    ///
    /// If this method is not called, the server will default to accepting "h3".
    pub fn set_alpn(&mut self, alpn_protocols: &[Vec<u8>]) -> Result<()> {
        self.alpn_protocols = alpn_protocols.into();
        Ok(())
    }
}

impl crypto::ServerConfig for Config {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
    ) -> StdResult<crypto::Keys, crypto::UnsupportedVersion> {
        let version = QuicVersion::parse(version)?;
        let secrets = Secrets::initial(version, dst_cid, Side::Server).unwrap();
        Ok(secrets.keys().unwrap().as_crypto().unwrap())
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        let version = QuicVersion::parse(version).unwrap();
        retry::retry_tag(&version, orig_dst_cid, packet)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        let version = QuicVersion::parse(version).unwrap();
        Session::new(self, version, params).unwrap()
    }
}

static SESSION_INDEX: LazyLock<c_int> = LazyLock::new(|| unsafe {
    bffi::SSL_get_ex_new_index(0, std::ptr::null_mut(), std::ptr::null_mut(), None, None)
});

/// The [crypto::Session] implementation for BoringSSL.
struct Session {
    state: Box<SessionState>,
    alpn: AlpnProtocols,
    handshake_data_available: bool,
    handshake_data_sent: bool,
}

impl Session {
    fn new(
        cfg: Arc<Config>,
        version: QuicVersion,
        params: &TransportParameters,
    ) -> Result<Box<Self>> {
        let mut ssl = Ssl::new(&cfg.ctx).unwrap();

        // Configure the TLS extension based on the QUIC version used.
        ssl.set_quic_use_legacy_codepoint(version.uses_legacy_extension());

        // Configure the SSL to be a server.
        ssl.set_accept_state();

        // Set the transport parameters.
        ssl.set_quic_transport_params(&encode_params(params))
            .unwrap();

        // Need to se
        ssl.set_quic_early_data_context(b"quinn-boring").unwrap();

        let mut session = Box::new(Self {
            state: SessionState::new(ssl, Side::Server, version)?,
            alpn: cfg.alpn_protocols.clone(),
            handshake_data_available: false,
            handshake_data_sent: false,
        });

        // Register the instance in SSL ex_data. This allows the static callbacks to
        // reference the instance.
        unsafe {
            map_result(bffi::SSL_set_ex_data(
                session.state.ssl.as_ptr(),
                *SESSION_INDEX,
                &mut *session as *mut Self as *mut _,
            ))?;
        }

        Ok(session)
    }

    /// Server-side only callback from BoringSSL to select the ALPN protocol.
    #[inline]
    fn on_alpn_select<'a>(&mut self, offered: &'a [u8]) -> Result<&'a [u8]> {
        // Indicate that we now have handshake data available.
        self.handshake_data_available = true;

        self.alpn.select(offered)
    }

    /// Server-side only callback from BoringSSL indicating that the Server Name Indication (SNI)
    /// extension in the client hello was successfully parsed.
    #[inline]
    fn on_server_name(&mut self, _: *mut c_int) -> c_int {
        // Indicate that we now have handshake data available.
        self.handshake_data_available = true;

        // SSL_TLSEXT_ERR_OK causes the server_name extension to be acked in
        // ServerHello.
        bffi::SSL_TLSEXT_ERR_OK
    }
}

// Raw callbacks from BoringSSL
impl Session {
    #[inline]
    fn get_instance(ssl: *const bffi::SSL) -> &'static mut Session {
        unsafe {
            let data = bffi::SSL_get_ex_data(ssl, *SESSION_INDEX);
            if data.is_null() {
                panic!("BUG: Session instance missing")
            }
            &mut *(data as *mut Session)
        }
    }

    extern "C" fn alpn_select_callback(
        ssl: *mut bffi::SSL,
        out: *mut *const u8,
        out_len: *mut u8,
        in_: *const u8,
        in_len: c_uint,
        _: *mut c_void,
    ) -> c_int {
        let inst = Self::get_instance(ssl);

        unsafe {
            let protos = slice::from_raw_parts(in_, in_len as _);
            match inst.on_alpn_select(protos) {
                Ok(proto) => {
                    *out = proto.as_ptr() as _;
                    *out_len = proto.len() as _;
                    bffi::SSL_TLSEXT_ERR_OK
                }
                Err(_) => bffi::SSL_TLSEXT_ERR_ALERT_FATAL,
            }
        }
    }

    extern "C" fn server_name_callback(
        ssl: *mut bffi::SSL,
        out_alert: *mut c_int,
        _: *mut c_void,
    ) -> c_int {
        let inst = Self::get_instance(ssl);
        inst.on_server_name(out_alert)
    }
}

impl crypto::Session for Session {
    fn initial_keys(&self, dcid: &ConnectionId, side: Side) -> crypto::Keys {
        self.state.initial_keys(dcid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.state.handshake_data()
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.state.peer_identity()
    }

    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        self.state.early_crypto()
    }

    fn early_data_accepted(&self) -> Option<bool> {
        None
    }

    fn is_handshaking(&self) -> bool {
        self.state.is_handshaking()
    }

    fn read_handshake(&mut self, plaintext: &[u8]) -> StdResult<bool, TransportError> {
        self.state.read_handshake(plaintext)?;

        // Only indicate that handshake data is available once.
        if !self.handshake_data_sent && self.handshake_data_available {
            self.handshake_data_sent = true;
            return Ok(true);
        }

        Ok(false)
    }

    fn transport_parameters(&self) -> StdResult<Option<TransportParameters>, TransportError> {
        self.state.transport_parameters()
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<crypto::Keys> {
        self.state.write_handshake(buf)
    }

    fn next_1rtt_keys(&mut self) -> Option<crypto::KeyPair<Box<dyn crypto::PacketKey>>> {
        self.state.next_1rtt_keys()
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        self.state.is_valid_retry(orig_dst_cid, header, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> StdResult<(), crypto::ExportKeyingMaterialError> {
        self.state.export_keying_material(output, label, context)
    }
}

fn encode_params(params: &TransportParameters) -> Bytes {
    let mut out = BytesMut::with_capacity(128);
    params.write(&mut out);
    out.freeze()
}
