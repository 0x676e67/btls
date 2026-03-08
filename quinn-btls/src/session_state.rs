use crate::alert::Alert;
use crate::error::{map_cb_result, map_result, Result};
use crate::secret::{Secret, Secrets, SecretsBuilder};
use crate::suite::CipherSuite;
use crate::{retry, Error, HandshakeData, Level, QuicSsl, QuicVersion, SslError};
use btls::error::ErrorStack;
use btls::ssl::{NameType, Ssl};
use btls_sys as bffi;
use bytes::{Buf, BytesMut};
use foreign_types_shared::ForeignType;
use quinn_proto::{
    crypto, transport_parameters::TransportParameters, ConnectionId, Side, TransportError,
};
use std::any::Any;
use std::ffi::c_int;
use std::io::Cursor;
use std::result::Result as StdResult;
use std::slice;
use std::sync::LazyLock;
use tracing::{error, trace, warn};

pub(crate) static QUIC_METHOD: bffi::SSL_QUIC_METHOD = bffi::SSL_QUIC_METHOD {
    set_read_secret: Some(SessionState::set_read_secret_callback),
    set_write_secret: Some(SessionState::set_write_secret_callback),
    add_handshake_data: Some(SessionState::add_handshake_data_callback),
    flush_flight: Some(SessionState::flush_flight_callback),
    send_alert: Some(SessionState::send_alert_callback),
};

static SESSION_INDEX: LazyLock<c_int> = LazyLock::new(|| unsafe {
    bffi::SSL_get_ex_new_index(0, std::ptr::null_mut(), std::ptr::null_mut(), None, None)
});

pub(crate) struct SessionState {
    pub(crate) ssl: Ssl,
    pub(crate) version: QuicVersion,

    /// Indicates that early data was rejected in the last call to [Self::read_handshake].
    pub(crate) early_data_rejected: bool,

    side: Side,
    alert: Option<TransportError>,
    next_secrets: Option<Secrets>,
    keys_updated: bool,
    read_level: Level,
    write_level: Level,
    levels: [LevelState; Level::NUM_LEVELS],
    handshaking: bool,
}

impl SessionState {
    pub(crate) fn new(ssl: Ssl, side: Side, version: QuicVersion) -> Result<Box<Self>> {
        let levels = [
            LevelState::new(version, Level::Initial, &ssl),
            LevelState::new(version, Level::EarlyData, &ssl),
            LevelState::new(version, Level::Handshake, &ssl),
            LevelState::new(version, Level::Application, &ssl),
        ];

        let mut state = Box::new(Self {
            ssl,
            version,
            side,
            alert: None,
            next_secrets: None,
            keys_updated: false,
            read_level: Level::Initial,
            write_level: Level::Initial,
            levels,
            early_data_rejected: false,
            handshaking: true,
        });

        // Registers this instance as ex data on the underlying Ssl in order to support
        // BoringSSL callbacks to this instance.
        unsafe {
            map_result(bffi::SSL_set_ex_data(
                state.ssl.as_ptr(),
                *SESSION_INDEX,
                &mut *state as *mut Self as *mut _,
            ))?;
        }

        Ok(state)
    }

    #[inline]
    fn level_state(&self, level: Level) -> &LevelState {
        &self.levels[level as usize]
    }

    #[inline]
    fn level_state_mut(&mut self, level: Level) -> &mut LevelState {
        &mut self.levels[level as usize]
    }

    #[inline]
    pub(crate) fn is_handshaking(&self) -> bool {
        self.handshaking
    }

    #[inline]
    pub(crate) fn handshake_data(&self) -> Option<Box<dyn Any>> {
        let sni_name = if self.side.is_server() {
            self.ssl
                .servername(NameType::HOST_NAME)
                .map(|server_name| server_name.to_string())
        } else {
            // Server name does not apply to the client.
            None
        };

        let alpn_protocol = self.ssl.selected_alpn_protocol().map(Vec::from);

        if sni_name.is_none() && alpn_protocol.is_none() {
            None
        } else {
            Some(Box::new(HandshakeData {
                protocol: alpn_protocol,
                server_name: sni_name,
            }))
        }
    }

    #[inline]
    pub(crate) fn next_1rtt_keys(&mut self) -> Option<crypto::KeyPair<Box<dyn crypto::PacketKey>>> {
        self.next_secrets
            .as_mut()
            .map(|secrets| secrets.next_packet_keys().unwrap().as_crypto().unwrap())
    }

    #[inline]
    pub(crate) fn transport_parameters(
        &self,
    ) -> StdResult<Option<TransportParameters>, TransportError> {
        match self.ssl.get_peer_quic_transport_params() {
            Some(params) => {
                let params = TransportParameters::read(self.side, &mut Cursor::new(params))
                    .map_err(|e| TransportError {
                        code: Alert::handshake_failure().into(),
                        frame: None,
                        reason: format!("failed parsing transport params: {e:?}"),
                    })?;
                Ok(Some(params))
            }
            None => Ok(None),
        }
    }

    #[inline]
    pub(crate) fn read_handshake(&mut self, plaintext: &[u8]) -> StdResult<(), TransportError> {
        let ssl_err = self.ssl.provide_quic_data(self.read_level, plaintext);
        self.check_alert()?;
        self.check_ssl_error(ssl_err)?;

        self.advance_handshake()
    }

    #[inline]
    pub(crate) fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<crypto::Keys> {
        // Write all available data at the current write level.
        let write_state = self.level_state_mut(self.write_level);
        if write_state.write_buffer.has_remaining() {
            buf.extend_from_slice(&write_state.write_buffer);
            write_state.write_buffer.clear();
        }

        // Advance to the next write level.
        let ssl_engine_write_level = self.ssl.quic_write_level();
        let next_write_level = self.write_level.next();
        if next_write_level != self.write_level && next_write_level <= ssl_engine_write_level {
            self.write_level = next_write_level;

            // Indicate that we're updating the keys.
            self.keys_updated = true;
        }

        let out = if self.keys_updated {
            self.keys_updated = false;

            if self.next_secrets.is_some() {
                // Once we've returned the application secrets, stop sending key updates.
                None
            } else {
                // Determine if we're transitioning to the application-level keys.
                let is_app = self.write_level == Level::Application;

                // Build the secrets.
                let secrets = self
                    .level_state(self.write_level)
                    .builder
                    .build()
                    .unwrap_or_else(|| {
                        panic!("failed building secrets for level {:?}", self.write_level)
                    });

                if is_app {
                    // We've transitioned to the application level, we need to set the
                    // next (i.e. application) secrets for use from next_1rtt_keys.

                    // Copy the secrets and advance them to the next application secrets.
                    let mut next_app_secrets = secrets;
                    next_app_secrets.update().unwrap();

                    self.next_secrets = Some(next_app_secrets);
                }

                Some(secrets.keys().unwrap())
            }
        } else {
            None
        };

        out.map(|keys| keys.as_crypto().unwrap())
    }

    #[inline]
    pub(crate) fn is_valid_retry(
        &self,
        orig_dst_cid: &ConnectionId,
        header: &[u8],
        payload: &[u8],
    ) -> bool {
        retry::is_valid_retry(&self.version, orig_dst_cid, header, payload)
    }

    #[inline]
    pub(crate) fn peer_identity(&self) -> Option<Box<dyn Any>> {
        todo!()
    }

    #[inline]
    pub(crate) fn early_crypto(
        &self,
    ) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        let builder = &self.level_state(Level::EarlyData).builder;
        let version = builder.version;
        let suite = builder.suite?;
        let early_secret = match self.side {
            Side::Client => builder.local_secret?,
            Side::Server => builder.remote_secret?,
        };
        let header_key = early_secret
            .header_key(version, suite)
            .unwrap()
            .as_crypto()
            .unwrap();
        let packet_key = Box::new(early_secret.packet_key(version, suite).unwrap());

        Some((header_key, packet_key))
    }

    #[inline]
    pub(crate) fn initial_keys(&self, dcid: &ConnectionId, side: Side) -> crypto::Keys {
        let secrets = Secrets::initial(self.version, dcid, side).unwrap();
        secrets.keys().unwrap().as_crypto().unwrap()
    }

    #[inline]
    pub(crate) fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> StdResult<(), crypto::ExportKeyingMaterialError> {
        self.ssl
            .export_keyring_material(output, label, context)
            .map_err(|_| crypto::ExportKeyingMaterialError {})
    }

    #[inline]
    pub(crate) fn advance_handshake(&mut self) -> StdResult<(), TransportError> {
        self.early_data_rejected = false;

        if self.handshaking {
            let rc = self.ssl.do_handshake();

            // Update the state of the handshake.
            self.handshaking = self.ssl.is_handshaking();

            self.check_alert()?;
            self.check_ssl_error(rc)?;
        }

        if !self.handshaking {
            let ssl_err = self.ssl.process_post_handshake();
            self.check_alert()?;
            return self.check_ssl_error(ssl_err);
        }
        Ok(())
    }

    #[inline]
    pub(crate) fn check_alert(&self) -> StdResult<(), TransportError> {
        if let Some(alert) = &self.alert {
            return Err(alert.clone());
        }
        Ok(())
    }

    #[inline]
    pub(crate) fn check_ssl_error(&mut self, ssl_err: SslError) -> StdResult<(), TransportError> {
        match ssl_err.value() {
            bffi::SSL_ERROR_NONE => Ok(()),
            bffi::SSL_ERROR_WANT_READ
            | bffi::SSL_ERROR_WANT_WRITE
            | bffi::SSL_ERROR_PENDING_SESSION
            | bffi::SSL_ERROR_PENDING_CERTIFICATE
            | bffi::SSL_ERROR_PENDING_TICKET
            | bffi::SSL_ERROR_WANT_X509_LOOKUP
            | bffi::SSL_ERROR_WANT_PRIVATE_KEY_OPERATION
            | bffi::SSL_ERROR_WANT_CERTIFICATE_VERIFY => {
                // Not an error - retry when we get more data from the peer.
                trace!("SSL:{}", ssl_err.get_description());
                Ok(())
            }
            bffi::SSL_ERROR_EARLY_DATA_REJECTED => {
                // Reset the state to allow retry with 1-RTT.
                self.ssl.reset_early_rejected_data();

                // Indicate that the early data has been rejected for the current handshake.
                self.early_data_rejected = true;
                Ok(())
            }
            _ => {
                // Everything else is fatal.
                let reason = if ssl_err.value() == bffi::SSL_ERROR_SSL {
                    // Error occurred within the SSL library. Get details from the ErrorStack.
                    format!("{}: {:?}", ssl_err, ErrorStack::get())
                } else {
                    format!("{ssl_err}")
                };

                let mut err: TransportError = Alert::handshake_failure().into();
                err.reason = reason;
                Err(err)
            }
        }
    }
}

// BoringSSL event handlers.
impl SessionState {
    /// Callback from BoringSSL that configures the read secret and cipher suite for the given
    /// encryption level. If an error is returned, the handshake is terminated with an error.
    /// This function will be called at most once per encryption level.
    #[inline]
    fn on_set_read_secret(
        &mut self,
        level: Level,
        suite: &'static CipherSuite,
        secret: Secret,
    ) -> Result<()> {
        // Store the secret.
        let builder = &mut self.level_state_mut(level).builder;
        builder.set_suite(suite);
        builder.set_remote_secret(secret);

        // Advance the currently active read level.
        self.read_level = level;

        // Indicate that the next call to write_handshake should generate new keys.
        self.keys_updated = true;
        Ok(())
    }

    /// Callback from BoringSSL that configures the write secret and cipher suite for the given
    /// encryption level. If an error is returned, the handshake is terminated with an error.
    /// This function will be called at most once per encryption level.
    #[inline]
    fn on_set_write_secret(
        &mut self,
        level: Level,
        suite: &'static CipherSuite,
        secret: Secret,
    ) -> Result<()> {
        // Store the secret.
        let builder = &mut self.level_state_mut(level).builder;
        builder.set_suite(suite);
        builder.set_local_secret(secret);
        Ok(())
    }

    /// Callback from BoringSSL that adds handshake data to the current flight at the given
    /// encryption level. If an error is returned, the handshake is terminated with an error.
    #[inline]
    fn on_add_handshake_data(&mut self, level: Level, data: &[u8]) -> Result<()> {
        if level < self.write_level {
            return Err(Error::other(format!(
                "add_handshake_data for previous write level {level:?}"
            )));
        }

        // Make sure we don't exceed the buffer capacity for the level.
        let state = self.level_state_mut(level);
        if state.write_buffer.len() + data.len() > state.write_buffer.capacity() {
            return Err(Error::other(format!(
                "add_handshake_data exceeded buffer capacity for level {level:?}"
            )));
        }

        // Add the message to the level.
        state.write_buffer.extend_from_slice(data);
        Ok(())
    }

    /// Callback from BoringSSL called when the current flight is complete and should be
    /// written to the transport. Note a flight may contain data at several
    /// encryption levels.
    #[inline]
    fn on_flush_flight(&mut self) -> Result<()> {
        Ok(())
    }

    /// Callback from BoringSSL that sends a fatal alert at the specified encryption level.
    #[inline]
    fn on_send_alert(&mut self, _: Level, alert: Alert) -> Result<()> {
        self.alert = Some(alert.into());
        Ok(())
    }

    /// Callback from BoringSSL to handle (i.e. log) info events.
    fn on_info(&self, type_: c_int, value: c_int) {
        if type_ & bffi::SSL_CB_LOOP > 0 {
            trace!("SSL:ACCEPT_LOOP:{}", self.ssl.state_string());
        } else if type_ & bffi::SSL_CB_ALERT > 0 {
            let prefix = if type_ & bffi::SSL_CB_READ > 0 {
                "SSL:ALERT:READ:"
            } else {
                "SSL:ALERT:WRITE:"
            };

            if ((type_ & 0xF0) >> 8) == bffi::SSL3_AL_WARNING {
                warn!("{}{}", prefix, self.ssl.state_string());
            } else {
                error!("{}{}", prefix, self.ssl.state_string());
            }
        } else if type_ & bffi::SSL_CB_EXIT > 0 {
            if value == 1 {
                trace!("SSL:ACCEPT_EXIT_OK:{}", self.ssl.state_string());
            } else {
                // Not necessarily an actual error. It could just require additional
                // data from the other side.
                trace!("SSL:ACCEPT_EXIT_FAIL:{}", self.ssl.state_string());
            }
        } else if type_ & bffi::SSL_CB_HANDSHAKE_START > 0 {
            trace!("SSL:HANDSHAKE_START:{}", self.ssl.state_string());
        } else if type_ & bffi::SSL_CB_HANDSHAKE_DONE > 0 {
            trace!("SSL:HANDSHAKE_DONE:{}", self.ssl.state_string());
        } else {
            warn!(
                "SSL:unknown event type {}:{}",
                type_,
                self.ssl.state_string()
            );
        }
    }
}

// Raw callbacks from BoringSSL
impl SessionState {
    /// Called by the static callbacks to retrieve the instance pointer.
    #[inline]
    fn get_instance(ssl: *const bffi::SSL) -> &'static mut SessionState {
        unsafe {
            let data = bffi::SSL_get_ex_data(ssl, *SESSION_INDEX);
            if data.is_null() {
                panic!("BUG: SessionState instance missing")
            }
            &mut *(data as *mut SessionState)
        }
    }

    extern "C" fn set_read_secret_callback(
        ssl: *mut bffi::SSL,
        level: bffi::ssl_encryption_level_t,
        cipher: *const bffi::SSL_CIPHER,
        secret: *const u8,
        secret_len: usize,
    ) -> c_int {
        let inst = Self::get_instance(ssl);
        let level: Level = level.into();
        let secret = unsafe { slice::from_raw_parts(secret, secret_len) };
        let suite = CipherSuite::from_cipher(cipher).unwrap();
        let secret = Secret::from(secret);
        map_cb_result(inst.on_set_read_secret(level, suite, secret))
    }

    extern "C" fn set_write_secret_callback(
        ssl: *mut bffi::SSL,
        level: bffi::ssl_encryption_level_t,
        cipher: *const bffi::SSL_CIPHER,
        secret: *const u8,
        secret_len: usize,
    ) -> c_int {
        let inst = Self::get_instance(ssl);
        let level: Level = level.into();
        let secret = unsafe { slice::from_raw_parts(secret, secret_len) };
        let suite = CipherSuite::from_cipher(cipher).unwrap();
        let secret = Secret::from(secret);
        map_cb_result(inst.on_set_write_secret(level, suite, secret))
    }

    extern "C" fn add_handshake_data_callback(
        ssl: *mut bffi::SSL,
        level: bffi::ssl_encryption_level_t,
        data: *const u8,
        len: usize,
    ) -> c_int {
        let inst = Self::get_instance(ssl);
        let level: Level = level.into();
        let data = unsafe { slice::from_raw_parts(data, len) };
        map_cb_result(inst.on_add_handshake_data(level, data))
    }

    extern "C" fn flush_flight_callback(ssl: *mut bffi::SSL) -> c_int {
        let inst = Self::get_instance(ssl);
        map_cb_result(inst.on_flush_flight())
    }

    extern "C" fn send_alert_callback(
        ssl: *mut bffi::SSL,
        level: bffi::ssl_encryption_level_t,
        alert: u8,
    ) -> c_int {
        let inst = Self::get_instance(ssl);
        let level: Level = level.into();
        map_cb_result(inst.on_send_alert(level, Alert::from(alert)))
    }

    pub(crate) extern "C" fn info_callback(ssl: *const bffi::SSL, type_: c_int, value: c_int) {
        let inst = Self::get_instance(ssl);
        inst.on_info(type_, value);
    }
}

pub(crate) struct LevelState {
    pub(crate) builder: SecretsBuilder,
    pub(crate) write_buffer: BytesMut,
}

impl LevelState {
    #[inline]
    fn new(version: QuicVersion, level: Level, ssl: &Ssl) -> Self {
        let capacity = ssl.quic_max_handshake_flight_len(level);

        Self {
            builder: SecretsBuilder::new(version),
            write_buffer: BytesMut::with_capacity(capacity),
        }
    }
}
