//! Connection IDs (RFC 9000, section 5.1), as OpenSSL's QUIC uses them: each endpoint has one
//! local connection ID (a client's is zero-length; a server's eight octets, plus the client's
//! original DCID while the handshake runs), so no NEW_CONNECTION_ID is ever sent; of the peer's
//! IDs, at most two are active, retiring at most ten at once (`ossl_quic_channel_on_new_conn_id`).
//! Every stateless reset token the peer gives is kept to recognise a stateless reset.

use std::collections::{BTreeMap, VecDeque};

use crate::error::{Error, Result};
use crate::wire::{ConnId, RESET_TOKEN_LEN, frame_type as ft};

/// The length of the connection IDs a server chooses (OpenSSL's `INIT_DCID_LEN`/LCID length).
pub const LOCAL_CID_LEN: usize = 8;
/// The active_connection_id_limit we advertise (OpenSSL's `QUIC_MIN_ACTIVE_CONN_ID_LIMIT`).
pub const ACTIVE_CONN_ID_LIMIT: u64 = 2;
/// The most IDs one NEW_CONNECTION_ID may retire (OpenSSL's 10).
pub const MAX_RETIRE_AT_ONCE: u64 = 10;

/// The peer's connection IDs as one channel sees them.
#[derive(Clone, Debug)]
pub struct RemoteCids {
    /// The ID we send to.
    pub cur: ConnId,
    cur_seq: u64,
    cur_retire_prior_to: u64,
    /// Stateless reset tokens by sequence number (bounded: one per new ID, at most ten
    /// retirements apart, and pruned as they retire).
    reset_tokens: BTreeMap<u64, [u8; RESET_TOKEN_LEN]>,
    /// RETIRE_CONNECTION_ID frames to send.
    retire: VecDeque<u64>,
}

impl RemoteCids {
    /// Starting with `dcid` (sequence 0).
    #[must_use]
    pub fn new(dcid: ConnId) -> Self {
        Self {
            cur: dcid,
            cur_seq: 0,
            cur_retire_prior_to: 0,
            reset_tokens: BTreeMap::new(),
            retire: VecDeque::new(),
        }
    }

    /// The server's Initial or Retry gave a new ID for sequence 0.
    pub fn set_initial(&mut self, dcid: ConnId) {
        self.cur = dcid;
    }

    /// The server's stateless_reset_token transport parameter (for sequence 0).
    pub fn set_initial_reset_token(&mut self, token: [u8; RESET_TOKEN_LEN]) {
        self.reset_tokens.insert(0, token);
    }

    /// Whether `token` is a stateless reset token the peer gave us.
    #[must_use]
    pub fn is_reset_token(&self, token: &[u8; RESET_TOKEN_LEN]) -> bool {
        use subtle::ConstantTimeEq;
        // Constant time per token, as tokens are secrets until used.
        self.reset_tokens
            .values()
            .fold(subtle::Choice::from(0), |acc, t| acc | t.ct_eq(token))
            .into()
    }

    /// A NEW_CONNECTION_ID frame.
    ///
    /// # Errors
    /// PROTOCOL_VIOLATION while a zero-length ID is in use; CONNECTION_ID_LIMIT_ERROR if more
    /// than two would be active or more than ten retired at once.
    pub fn on_new_conn_id(
        &mut self,
        seq: u64,
        retire_prior_to: u64,
        cid: &[u8],
        reset_token: [u8; RESET_TOKEN_LEN],
    ) -> Result<()> {
        let t = ft::NEW_CONNECTION_ID;
        if self.cur.is_empty() {
            return Err(Error::protocol(t, "zero length connection id in use"));
        }
        let new_seq = self.cur_seq.max(seq);
        let new_rpt = self.cur_retire_prior_to.max(retire_prior_to);
        if new_seq.saturating_sub(new_rpt) > 1 {
            return Err(Error::new(
                rustyssl_abi::OSSL_QUIC_ERR_CONNECTION_ID_LIMIT_ERROR,
                t,
                "active_connection_id limit violated",
            ));
        }
        if new_rpt.saturating_sub(self.cur_retire_prior_to) > MAX_RETIRE_AT_ONCE {
            return Err(Error::new(
                rustyssl_abi::OSSL_QUIC_ERR_CONNECTION_ID_LIMIT_ERROR,
                t,
                "retiring connection id limit violated",
            ));
        }
        if new_seq > self.cur_seq {
            self.reset_tokens.insert(new_seq, reset_token);
            self.cur_seq = new_seq;
            self.cur = ConnId::new(cid)?;
        }
        let mut r = self.cur_retire_prior_to;
        while new_rpt > r {
            self.retire.push_back(r);
            r = r.saturating_add(1);
        }
        self.cur_retire_prior_to = new_rpt;
        // Tokens of IDs retired long ago can't be in use any more; keep the recent ones so a
        // reset arriving on an old path still matches.
        let floor = new_rpt.saturating_sub(MAX_RETIRE_AT_ONCE);
        self.reset_tokens.retain(|&s, _| s >= floor);
        Ok(())
    }

    /// The next RETIRE_CONNECTION_ID to send.
    pub fn take_retire(&mut self) -> Option<u64> {
        self.retire.pop_front()
    }

    /// A RETIRE_CONNECTION_ID of ours was lost.
    pub fn retire_lost(&mut self, seq: u64) {
        self.retire.push_back(seq);
    }

    /// Whether RETIRE_CONNECTION_ID frames are queued.
    #[must_use]
    pub fn has_retire(&self) -> bool {
        !self.retire.is_empty()
    }
}

/// A RETIRE_CONNECTION_ID frame received: as OpenSSL, a client (whose ID is zero-length) treats
/// it as PROTOCOL_VIOLATION; a server, with its single ID, ignores it.
///
/// # Errors
/// We're a client.
pub fn on_retire_conn_id(is_server: bool) -> Result<()> {
    if is_server {
        Ok(())
    } else {
        Err(Error::protocol(
            ft::RETIRE_CONNECTION_ID,
            "conn has zero-length CID",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(b: u8) -> ConnId {
        ConnId::new(&[b; 8]).unwrap()
    }

    #[test]
    fn new_conn_id_follows_openssl() {
        let mut r = RemoteCids::new(cid(1));
        r.on_new_conn_id(1, 0, &[2; 8], [2; 16]).unwrap();
        assert_eq!(r.cur, cid(2));
        assert!(r.is_reset_token(&[2; 16]));
        assert!(!r.is_reset_token(&[3; 16]));
        // Two active (0 and 1) and a third without retiring: the limit.
        let e = r.on_new_conn_id(2, 0, &[3; 8], [3; 16]).unwrap_err();
        assert_eq!(
            e.code,
            crate::error::code(rustyssl_abi::OSSL_QUIC_ERR_CONNECTION_ID_LIMIT_ERROR)
        );
        // With retire_prior_to 1: retire 0.
        let mut r = RemoteCids::new(cid(1));
        r.on_new_conn_id(1, 0, &[2; 8], [2; 16]).unwrap();
        r.on_new_conn_id(2, 1, &[3; 8], [3; 16]).unwrap();
        assert_eq!(r.take_retire(), Some(0));
        assert_eq!(r.take_retire(), None);
        assert_eq!(r.cur, cid(3));
        // Retiring more than ten at once.
        let e = r.on_new_conn_id(13, 12, &[4; 8], [4; 16]).unwrap_err();
        assert_eq!(e.reason, "retiring connection id limit violated");
        // A duplicate is harmless.
        r.on_new_conn_id(2, 1, &[3; 8], [3; 16]).unwrap();
        // Zero-length IDs can't change.
        let mut z = RemoteCids::new(ConnId::default());
        assert!(z.on_new_conn_id(1, 0, &[2; 8], [2; 16]).is_err());
        assert!(on_retire_conn_id(false).is_err());
        assert!(on_retire_conn_id(true).is_ok());
    }
}
