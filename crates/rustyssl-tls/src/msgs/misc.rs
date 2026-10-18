//! The other handshake messages: NewSessionTicket, EncryptedExtensions, Finished, KeyUpdate,
//! NextProtocol, and the empty ones (HelloRequest, ServerHelloDone, EndOfEarlyData).

use crate::codec::Reader;
use crate::error::{Error, Result};
use crate::msgs::ext::{self, Extension};
use crate::msgs::{OrAlert, ad, encode_with, r};

/// An empty message's body (HelloRequest, ServerHelloDone, EndOfEarlyData): anything in it is
/// `SSL_R_LENGTH_MISMATCH` with decode-error.
///
/// # Errors
/// As above.
pub fn empty(b: &[u8]) -> Result<()> {
    if b.is_empty() {
        Ok(())
    } else {
        Err(Error::decode(r::LENGTH_MISMATCH))
    }
}

/// A TLS 1.2 NewSessionTicket (RFC 5077).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewSessionTicket12 {
    /// The lifetime hint in seconds.
    pub lifetime_hint: u32,
    /// The ticket (empty: the server sends none after all).
    pub ticket: Vec<u8>,
}

/// A TLS 1.3 NewSessionTicket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewSessionTicket13 {
    /// The lifetime in seconds (OpenSSL caps what it keeps at 7 days).
    pub lifetime: u32,
    /// ticket_age_add.
    pub age_add: u32,
    /// ticket_nonce.
    pub nonce: Vec<u8>,
    /// The ticket (non-empty).
    pub ticket: Vec<u8>,
    /// The extension block's contents.
    pub extensions: Vec<u8>,
}

/// A NewSessionTicket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NewSessionTicket {
    /// TLS 1.2.
    Tls12(NewSessionTicket12),
    /// TLS 1.3.
    Tls13(NewSessionTicket13),
}

impl NewSessionTicket {
    /// Decodes the body (`tls_process_new_session_ticket`): every fault is
    /// `SSL_R_LENGTH_MISMATCH` with decode-error. In TLS 1.2 the ticket must fill the body (an
    /// empty one is allowed); in TLS 1.3 it must be non-empty and be followed by an extension
    /// block filling the rest.
    ///
    /// # Errors
    /// As above.
    pub fn parse(b: &[u8], tls13: bool) -> Result<Self> {
        let mm = Error::decode(r::LENGTH_MISMATCH);
        let mut rd = Reader::new(b);
        let lifetime = rd.u32().or_alert(mm)?;
        if !tls13 {
            let n = rd.u16().or_alert(mm)?;
            if rd.len() != usize::from(n) {
                return Err(mm);
            }
            return Ok(Self::Tls12(NewSessionTicket12 {
                lifetime_hint: lifetime,
                ticket: rd.take_rest().to_vec(),
            }));
        }
        let age_add = rd.u32().or_alert(mm)?;
        let nonce = rd.vec8().or_alert(mm)?.rest().to_vec();
        let n = rd.u16().or_alert(mm)?;
        if n == 0 || rd.len() < usize::from(n) {
            return Err(mm);
        }
        let ticket = rd.take(usize::from(n)).or_alert(mm)?.to_vec();
        let block = rd.vec16().or_alert(mm)?;
        rd.end().or_alert(mm)?;
        Ok(Self::Tls13(NewSessionTicket13 {
            lifetime,
            age_add,
            nonce,
            ticket,
            extensions: block.rest().to_vec(),
        }))
    }

    /// The body.
    ///
    /// # Errors
    /// A vector is too long.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_with(|w| match self {
            Self::Tls12(m) => {
                w.u32(m.lifetime_hint);
                w.vec(2, &m.ticket)
            }
            Self::Tls13(m) => {
                w.u32(m.lifetime);
                w.u32(m.age_add);
                w.vec(1, &m.nonce)?;
                w.vec(2, &m.ticket)?;
                w.vec(2, &m.extensions)
            }
        })
    }
}

/// EncryptedExtensions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedExtensions {
    /// The extension block's contents.
    pub extensions: Vec<u8>,
}

impl EncryptedExtensions {
    /// Decodes the body: an extension block filling it (`SSL_R_LENGTH_MISMATCH`,
    /// decode-error).
    ///
    /// # Errors
    /// As above.
    pub fn parse(b: &[u8]) -> Result<Self> {
        let mm = Error::decode(r::LENGTH_MISMATCH);
        let mut rd = Reader::new(b);
        let block = rd.vec16().or_alert(mm)?;
        rd.end().or_alert(mm)?;
        Ok(Self {
            extensions: block.rest().to_vec(),
        })
    }

    /// The extensions, split.
    ///
    /// # Errors
    /// Framing faults: `SSL_R_BAD_EXTENSION` with decode-error.
    pub fn split(&self) -> Result<Vec<Extension>> {
        ext::split(&self.extensions)
    }

    /// The body.
    ///
    /// # Errors
    /// The block is too long.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_with(|w| w.vec(2, &self.extensions))
    }
}

/// Finished.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finished {
    /// verify_data. Its length is checked against the expected one by the caller
    /// (`SSL_R_BAD_DIGEST_LENGTH` with decode-error), before the value (in constant time).
    pub verify_data: Vec<u8>,
}

/// KeyUpdate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyUpdate {
    /// request_update: 0 (update_not_requested) or 1 (update_requested).
    pub request_update: u8,
}

impl KeyUpdate {
    /// Decodes the body (`tls_process_key_update`): not exactly one octet is
    /// `SSL_R_BAD_KEY_UPDATE` with decode-error, a value other than 0 or 1 the same reason
    /// with illegal-parameter.
    ///
    /// # Errors
    /// As above.
    pub fn parse(b: &[u8]) -> Result<Self> {
        let [v] = b else {
            return Err(Error::decode(r::BAD_KEY_UPDATE));
        };
        if *v > 1 {
            return Err(Error::alert(ad::ILLEGAL_PARAMETER, r::BAD_KEY_UPDATE));
        }
        Ok(Self { request_update: *v })
    }
}

/// NextProtocol (the NPN draft's client message).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NextProtocol {
    /// The selected protocol.
    pub protocol: Vec<u8>,
    /// The padding.
    pub padding: Vec<u8>,
}

impl NextProtocol {
    /// Decodes the body (`tls_process_next_proto`): two 1-octet-length vectors filling it
    /// (`SSL_R_LENGTH_MISMATCH`, decode-error).
    ///
    /// # Errors
    /// As above.
    pub fn parse(b: &[u8]) -> Result<Self> {
        let mm = Error::decode(r::LENGTH_MISMATCH);
        let mut rd = Reader::new(b);
        let protocol = rd.vec8().or_alert(mm)?.rest().to_vec();
        let padding = rd.vec8().or_alert(mm)?.rest().to_vec();
        rd.end().or_alert(mm)?;
        Ok(Self { protocol, padding })
    }

    /// The body for `protocol`, padded to a multiple of 32 octets as OpenSSL's client does
    /// (`tls_construct_next_proto`).
    ///
    /// # Errors
    /// The protocol is longer than 255 octets.
    pub fn build(protocol: &[u8]) -> Result<Self> {
        let len = protocol.len();
        let rem = len.saturating_add(2) % 32;
        let padding_len = 32usize.saturating_sub(rem);
        if len > 255 {
            return Err(Error::internal());
        }
        Ok(Self {
            protocol: protocol.to_vec(),
            padding: vec![0; padding_len],
        })
    }

    /// The body.
    ///
    /// # Errors
    /// A vector is too long.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_with(|w| {
            w.vec(1, &self.protocol)?;
            w.vec(1, &self.padding)
        })
    }
}
