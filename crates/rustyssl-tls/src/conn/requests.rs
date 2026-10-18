//! What an application asks of an established connection (OpenSSL's `ssl_lib.c` and
//! `s3_lib.c`): a key update, a renegotiation, post-handshake authentication, and keying
//! material. Each check fails with OpenSSL's reason; the request then happens in the next step,
//! as OpenSSL's next `SSL_write`, `SSL_read`, or `SSL_do_handshake` makes it. Shared addition
//! (fork M).

use rustyssl_abi as abi;

use super::Connection;
use super::common::Pha;
use super::common::keys;
use super::statem::{MsgFlow, st};
use crate::crypto::Provider;
use crate::error::{Error, Result};

impl Connection {
    /// Whether the handshake finished and none is under way (`SSL_is_init_finished`).
    #[must_use]
    pub fn init_finished(&self) -> bool {
        !self.st.in_init && self.st.hand_state == st(abi::TLS_ST_OK)
    }

    /// Back into the state machine (`ossl_statem_set_in_init(s, 1)`): the next step writes what
    /// was requested.
    fn enter_init(&mut self) {
        self.st.in_init = true;
        if self.st.state == MsgFlow::Finished {
            self.st.loop_reported = false;
        }
    }

    /// `SSL_key_update`: a KeyUpdate of `update_type` (`SSL_KEY_UPDATE_NOT_REQUESTED` or
    /// `SSL_KEY_UPDATE_REQUESTED`) in TLS 1.3, once the handshake is done. The caller checks
    /// for pending writes (`SSL_R_BAD_WRITE_RETRY`) first.
    ///
    /// # Errors
    /// `SSL_R_WRONG_SSL_VERSION`, `SSL_R_INVALID_KEY_UPDATE_TYPE`, `SSL_R_STILL_IN_INIT`.
    pub fn request_key_update(&mut self, update_type: i32) -> Result<()> {
        if !self.is_tls13() {
            return Err(Error::quiet(abi::SSL_R_WRONG_SSL_VERSION));
        }
        if update_type != abi::SSL_KEY_UPDATE_NOT_REQUESTED
            && update_type != abi::SSL_KEY_UPDATE_REQUESTED
        {
            return Err(Error::quiet(abi::SSL_R_INVALID_KEY_UPDATE_TYPE));
        }
        if !self.init_finished() {
            return Err(Error::quiet(abi::SSL_R_STILL_IN_INIT));
        }
        self.enter_init();
        self.hs.sh.key_update = update_type;
        Ok(())
    }

    /// `ssl3_write_bytes`' check before a write with nothing pending: a KeyUpdate or a
    /// NewSessionTicket waiting to be sent puts the connection back in init, so the write
    /// sends it first. Whether it did.
    pub fn post_handshake_write(&mut self) -> bool {
        let tickets = match &self.hs.role {
            super::RoleState::Server(s) => s.extra_tickets_expected > 0,
            _ => false,
        };
        if self.hs.sh.key_update == abi::SSL_KEY_UPDATE_NONE && !tickets {
            return false;
        }
        self.enter_init();
        true
    }

    /// The SRTP profile negotiated (`SSL_get_selected_srtp_profile`), if any.
    #[must_use]
    pub fn srtp_profile(&self) -> Option<u16> {
        self.hs.sh.srtp_profile
    }

    /// `SSL_get_key_update_type`: the KeyUpdate waiting to be sent, or `SSL_KEY_UPDATE_NONE`.
    #[must_use]
    pub fn key_update_type(&self) -> i32 {
        self.hs.sh.key_update
    }

    /// `SSL_renegotiate` (`new_session`) and `SSL_renegotiate_abbreviated`: a renegotiation
    /// before TLS 1.3, unless `SSL_OP_NO_RENEGOTIATION` forbids it; it starts at the next
    /// [`Connection::renegotiate_check`].
    ///
    /// # Errors
    /// `SSL_R_WRONG_SSL_VERSION`, `SSL_R_NO_RENEGOTIATION`.
    pub fn request_renegotiate(&mut self, new_session: bool) -> Result<()> {
        if self.is_tls13() {
            return Err(Error::quiet(abi::SSL_R_WRONG_SSL_VERSION));
        }
        if self.cfg.options & abi::SSL_OP_NO_RENEGOTIATION != 0 {
            return Err(Error::quiet(abi::SSL_R_NO_RENEGOTIATION));
        }
        self.renegotiate = true;
        self.hs.sh.new_session = new_session;
        self.s3_renegotiate = true;
        Ok(())
    }

    /// `ssl3_renegotiate_check`: starts a requested renegotiation when nothing is pending
    /// (`pending_io`: buffered input or unsent output) and, unless `initok`, no handshake is
    /// under way; whether it started.
    pub fn renegotiate_check(&mut self, initok: bool, pending_io: bool) -> bool {
        if !self.s3_renegotiate || pending_io || !self.input.is_empty() {
            return false;
        }
        if !initok && self.in_init() {
            return false;
        }
        // `ossl_statem_set_renegotiate`.
        self.enter_init();
        self.st.request_state = st(abi::TLS_ST_SW_HELLO_REQ);
        self.s3_renegotiate = false;
        self.num_renegotiations = self.num_renegotiations.saturating_add(1);
        self.total_renegotiations = self.total_renegotiations.saturating_add(1);
        true
    }

    /// `SSL_renegotiate_pending`: whether a renegotiation was asked for and hasn't finished.
    #[must_use]
    pub fn renegotiate_pending(&self) -> bool {
        self.renegotiate
    }

    /// The renegotiations started since the count was cleared, and in all
    /// (`SSL_num_renegotiations`, `SSL_total_renegotiations`).
    #[must_use]
    pub fn renegotiations(&self) -> (u32, u32) {
        (self.num_renegotiations, self.total_renegotiations)
    }

    /// `SSL_clear_num_renegotiations`: the count, cleared.
    pub fn clear_num_renegotiations(&mut self) -> u32 {
        core::mem::take(&mut self.num_renegotiations)
    }

    /// `SSL_verify_client_post_handshake`: a TLS 1.3 server's CertificateRequest after the
    /// handshake, to a client that offered post-handshake authentication.
    ///
    /// # Errors
    /// `SSL_R_WRONG_SSL_VERSION`, `SSL_R_NOT_SERVER`, `SSL_R_STILL_IN_INIT`,
    /// `SSL_R_EXTENSION_NOT_RECEIVED`, `SSL_R_REQUEST_PENDING`, `SSL_R_REQUEST_SENT`,
    /// `SSL_R_INVALID_CONFIG` (the verify mode wouldn't send one), or an internal error.
    pub fn request_post_handshake_auth(&mut self) -> Result<()> {
        if !self.is_tls13() {
            return Err(Error::quiet(abi::SSL_R_WRONG_SSL_VERSION));
        }
        if !self.cfg.server {
            return Err(Error::quiet(abi::SSL_R_NOT_SERVER));
        }
        if !self.init_finished() {
            return Err(Error::quiet(abi::SSL_R_STILL_IN_INIT));
        }
        match self.hs.sh.pha {
            Pha::None => return Err(Error::quiet(abi::SSL_R_EXTENSION_NOT_RECEIVED)),
            Pha::ExtSent => {
                return Err(Error {
                    alert: None,
                    reason: abi::ERR_R_INTERNAL_ERROR,
                    library_reason: true,
                    data: None,
                });
            }
            Pha::ExtReceived => {}
            Pha::RequestPending => return Err(Error::quiet(abi::SSL_R_REQUEST_PENDING)),
            Pha::Requested => return Err(Error::quiet(abi::SSL_R_REQUEST_SENT)),
        }
        self.hs.sh.pha = Pha::RequestPending;
        if !super::server::send_certificate_request(self) {
            self.hs.sh.pha = Pha::ExtReceived;
            return Err(Error::quiet(abi::SSL_R_INVALID_CONFIG));
        }
        self.enter_init();
        Ok(())
    }

    /// `SSL_export_keying_material`: `len` octets for `label` and `context` (`None`: no
    /// context, which TLS 1.2 distinguishes from an empty one). TLS 1.3 needs the server's
    /// Finished (`ossl_statem_export_allowed`); TLS 1.2 refuses the PRF's own labels.
    ///
    /// # Errors
    /// Not allowed yet or a reserved label (TLS 1.2: `SSL_R_TLS_ILLEGAL_EXPORTER_LABEL`; a
    /// context over 65535 octets: `ERR_R_PASSED_INVALID_ARGUMENT`), or the provider failed.
    /// An error with reason 0 raises nothing (OpenSSL's silent failures).
    pub fn export_keying_material(
        &self,
        p: &dyn Provider,
        label: &[u8],
        context: Option<&[u8]>,
        len: usize,
    ) -> Result<Vec<u8>> {
        let silent = Error {
            alert: None,
            reason: 0,
            library_reason: false,
            data: None,
        };
        if self.is_tls13() {
            if self.neg.server_finished.is_empty()
                || self.st.hand_state == st(abi::TLS_ST_SW_FINISHED)
                || self.neg.exporter_master.is_empty()
            {
                return Err(silent);
            }
        } else {
            let ctx_len = context.map_or(0, <[u8]>::len);
            if ctx_len > 0xffff {
                return Err(Error {
                    alert: None,
                    reason: abi::ERR_R_PASSED_INVALID_ARGUMENT,
                    library_reason: true,
                    data: None,
                });
            }
            // The PRF's input as OpenSSL builds it, checked against the reserved labels.
            let mut val = label.to_vec();
            val.extend_from_slice(&self.hs.client_random);
            val.extend_from_slice(&self.hs.server_random);
            for reserved in [
                &b"client finished"[..],
                b"server finished",
                b"master secret",
                b"extended master secret",
                b"key expansion",
            ] {
                if val.starts_with(reserved) {
                    return Err(Error::quiet(abi::SSL_R_TLS_ILLEGAL_EXPORTER_LABEL));
                }
            }
            if self.neg.master_secret.is_empty() {
                return Err(silent);
            }
        }
        let out = keys::export(
            self,
            p,
            label,
            context.unwrap_or_default(),
            context.is_some(),
            len,
        )?;
        Ok(out.bytes().to_vec())
    }

    /// `SSL_export_keying_material_early`: TLS 1.3's early exporter, when early data was sent
    /// (client) or accepted (server).
    ///
    /// # Errors
    /// Not allowed (reason 0: nothing raised), or the provider failed.
    pub fn export_keying_material_early(
        &self,
        p: &dyn Provider,
        label: &[u8],
        context: &[u8],
        len: usize,
    ) -> Result<Vec<u8>> {
        if self.neg.early_exporter_master.is_empty() {
            return Err(Error {
                alert: None,
                reason: 0,
                library_reason: false,
                data: None,
            });
        }
        let out = keys::export_early(self, p, label, context, len)?;
        Ok(out.bytes().to_vec())
    }
}
