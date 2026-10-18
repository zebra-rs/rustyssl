//! What the client and server share (OpenSSL's `statem_lib.c`): handshake set-up, the
//! Finished MACs, and re-entering the state machine for post-handshake messages.

use rustyssl_abi as abi;

use super::Connection;
use super::statem::{MsgFlow, ReadState, st};
use crate::crypto::Provider;
use crate::error::Result;

/// Sets up a handshake (`tls_setup_handshake`).
///
/// # Errors
/// No usable version or cipher.
pub(crate) fn setup_handshake(c: &mut Connection, p: &dyn Provider) -> Result<()> {
    if c.cfg.server {
        super::server::setup(c, p)
    } else {
        super::client::setup(c, p)
    }
}

/// Takes the Finished MAC the peer must send (`ssl3_take_mac`).
///
/// # Errors
/// The MAC couldn't be computed.
pub(crate) fn take_mac(c: &mut Connection, p: &dyn Provider) -> Result<()> {
    if c.cfg.server {
        super::server::take_mac(c, p)
    } else {
        super::client::take_mac(c, p)
    }
}

/// Goes back into the state machine to read a handshake message after the handshake
/// (renegotiation, or TLS 1.3's NewSessionTicket, KeyUpdate, and CertificateRequest).
pub(crate) fn enter_post_handshake(c: &mut Connection) {
    c.st.in_init = true;
    c.st.state = MsgFlow::Reading;
    c.st.read_state = ReadState::Header;
    c.st.loop_reported = false;
    c.st.header_done = false;
    if c.st.hand_state == st(abi::TLS_ST_BEFORE) {
        c.st.hand_state = st(abi::TLS_ST_OK);
    }
}
