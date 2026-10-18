//! The hello messages: ClientHello (and the SSLv2-format one), ServerHello (and
//! HelloRetryRequest), and DTLS's HelloVerifyRequest.

use crate::codec::Reader;
use crate::consts::{
    HRR_RANDOM, MAX_SESSION_ID_LEN, RANDOM_LEN, TLS11_DOWNGRADE, TLS12_DOWNGRADE, version,
};
use crate::error::{Error, Result};
use crate::msgs::ext::{self, Extension};
use crate::msgs::{OrAlert, ad, encode_with, r};

/// A 32-octet random from a reader.
fn random(rd: &mut Reader<'_>, e: Error) -> Result<[u8; RANDOM_LEN]> {
    let b = rd.take(RANDOM_LEN).or_alert(e)?;
    let mut a = [0u8; RANDOM_LEN];
    a.copy_from_slice(b);
    Ok(a)
}

/// A ClientHello.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientHello {
    /// legacy_version (the client's highest version before TLS 1.3).
    pub legacy_version: u16,
    /// The client's random (for an SSLv2-format hello, its challenge, right-aligned and
    /// zero-padded or cut to 32 octets).
    pub random: [u8; RANDOM_LEN],
    /// legacy_session_id (at most 32 octets).
    pub session_id: Vec<u8>,
    /// DTLS's cookie; `None` in TLS.
    pub cookie: Option<Vec<u8>>,
    /// The cipher suites' octets as received: two per suite, or three per SSLv2 cipher spec.
    /// `bytes_to_cipher_list` checks them later with its own errors.
    pub cipher_suites: Vec<u8>,
    /// The compression methods.
    pub compression_methods: Vec<u8>,
    /// The extension block's contents (without its length); `None` when the hello has no
    /// block at all.
    pub extensions: Option<Vec<u8>>,
    /// Where the extension block's contents start within the body (for the PSK binders); 0
    /// without a block.
    pub extensions_offset: usize,
    /// Whether this came in SSLv2 format.
    pub sslv2: bool,
}

impl ClientHello {
    /// Decodes a ClientHello's body (`tls_process_client_hello`): a short version is
    /// `SSL_R_LENGTH_TOO_SHORT`, every later fault `SSL_R_LENGTH_MISMATCH`, all with
    /// decode-error (a session ID over 32 octets too). In DTLS with cookie exchange, OpenSSL
    /// stops after an empty cookie; read it first with [`ClientHello::dtls_cookie`].
    ///
    /// # Errors
    /// As above.
    pub fn parse(b: &[u8], dtls: bool) -> Result<Self> {
        let mm = Error::decode(r::LENGTH_MISMATCH);
        let mut rd = Reader::new(b);
        let legacy_version = rd.u16().or_alert(Error::decode(r::LENGTH_TOO_SHORT))?;
        let random = random(&mut rd, mm)?;
        let sid = rd.vec8().or_alert(mm)?;
        if sid.len() > MAX_SESSION_ID_LEN {
            return Err(mm);
        }
        let cookie = if dtls {
            Some(rd.vec8().or_alert(mm)?.rest().to_vec())
        } else {
            None
        };
        let cipher_suites = rd.vec16().or_alert(mm)?.rest().to_vec();
        let compression_methods = rd.vec8().or_alert(mm)?.rest().to_vec();
        let (extensions, extensions_offset) = if rd.is_empty() {
            (None, 0)
        } else {
            let block = rd.vec16().or_alert(mm)?;
            rd.end().or_alert(mm)?;
            let offset = b.len().saturating_sub(block.len());
            (Some(block.rest().to_vec()), offset)
        };
        Ok(Self {
            legacy_version,
            random,
            session_id: sid.rest().to_vec(),
            cookie,
            cipher_suites,
            compression_methods,
            extensions,
            extensions_offset,
            sslv2: false,
        })
    }

    /// A DTLS ClientHello's cookie, read as far as OpenSSL does before deciding whether to
    /// answer with a HelloVerifyRequest (`SSL_R_LENGTH_MISMATCH` with decode-error on a
    /// truncated hello).
    ///
    /// # Errors
    /// As above.
    pub fn dtls_cookie(b: &[u8]) -> Result<Vec<u8>> {
        let mm = Error::decode(r::LENGTH_MISMATCH);
        let mut rd = Reader::new(b);
        rd.u16().or_alert(Error::decode(r::LENGTH_TOO_SHORT))?;
        random(&mut rd, mm)?;
        let sid = rd.vec8().or_alert(mm)?;
        if sid.len() > MAX_SESSION_ID_LEN {
            return Err(mm);
        }
        Ok(rd.vec8().or_alert(mm)?.rest().to_vec())
    }

    /// Decodes an SSLv2-format ClientHello, starting at its message type (`isv2` in
    /// `tls_process_client_hello`): a type other than CLIENT-HELLO is an internal error, a
    /// short version `SSL_R_LENGTH_TOO_SHORT`, short lengths or contents that don't fill the
    /// record `SSL_R_RECORD_LENGTH_MISMATCH` (decode-error), a session ID over 32 octets
    /// `SSL_R_LENGTH_MISMATCH` (illegal-parameter). The challenge becomes the random,
    /// right-aligned; the compression is null; there are no extensions.
    ///
    /// # Errors
    /// As above.
    pub fn parse_v2(b: &[u8]) -> Result<Self> {
        let mut rd = Reader::new(b);
        let mt = rd.u8().or_alert(Error::internal())?;
        if core::ffi::c_int::from(mt) != rustyssl_abi::SSL2_MT_CLIENT_HELLO {
            return Err(Error::internal());
        }
        let legacy_version = rd.u16().or_alert(Error::decode(r::LENGTH_TOO_SHORT))?;
        let rl = Error::decode(r::RECORD_LENGTH_MISMATCH);
        let cs_len = rd.u16().or_alert(rl)?;
        let sid_len = rd.u16().or_alert(rl)?;
        let ch_len = rd.u16().or_alert(rl)?;
        if usize::from(sid_len) > MAX_SESSION_ID_LEN {
            return Err(Error::alert(ad::ILLEGAL_PARAMETER, r::LENGTH_MISMATCH));
        }
        let cipher_suites = rd.take(usize::from(cs_len)).or_alert(rl)?.to_vec();
        let session_id = rd.take(usize::from(sid_len)).or_alert(rl)?.to_vec();
        let challenge = rd.take(usize::from(ch_len)).or_alert(rl)?;
        rd.end().or_alert(rl)?;
        let n = challenge.len().min(RANDOM_LEN);
        let mut rnd = [0u8; RANDOM_LEN];
        let at = RANDOM_LEN.saturating_sub(n);
        if let (Some(dst), Some(src)) = (rnd.get_mut(at..), challenge.get(..n)) {
            dst.copy_from_slice(src);
        }
        Ok(Self {
            legacy_version,
            random: rnd,
            session_id,
            cookie: None,
            cipher_suites,
            compression_methods: vec![0],
            extensions: None,
            extensions_offset: 0,
            sslv2: true,
        })
    }

    /// The extensions, split (framing faults are `SSL_R_BAD_EXTENSION` with decode-error);
    /// empty without a block.
    ///
    /// # Errors
    /// As above.
    pub fn extensions(&self) -> Result<Vec<Extension>> {
        self.extensions
            .as_deref()
            .map_or(Ok(Vec::new()), ext::split)
    }

    /// The body (TLS or DTLS form; an SSLv2-format hello is encoded as a normal one).
    ///
    /// # Errors
    /// A vector is too long.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_with(|w| {
            w.u16(self.legacy_version);
            w.put(&self.random);
            w.vec(1, &self.session_id)?;
            if let Some(c) = &self.cookie {
                w.vec(1, c)?;
            }
            w.vec(2, &self.cipher_suites)?;
            w.vec(1, &self.compression_methods)?;
            if let Some(e) = &self.extensions {
                w.vec(2, e)?;
            }
            Ok(())
        })
    }
}

/// A TLS 1.3 server's sign that it negotiated a lower version (RFC 8446, section 4.1.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Downgrade {
    /// It negotiated TLS 1.2.
    Tls12,
    /// It negotiated TLS 1.1 or below.
    Tls11,
}

/// A ServerHello or HelloRetryRequest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerHello {
    /// legacy_version (TLS 1.2 for TLS 1.3).
    pub legacy_version: u16,
    /// The server's random (for a HelloRetryRequest, the fixed value).
    pub random: [u8; RANDOM_LEN],
    /// legacy_session_id_echo.
    pub session_id: Vec<u8>,
    /// The cipher suite.
    pub cipher_suite: u16,
    /// The compression method.
    pub compression: u8,
    /// The extension block's contents; `None` when there is no block.
    pub extensions: Option<Vec<u8>>,
    /// Whether this is a HelloRetryRequest.
    pub hrr: bool,
}

impl ServerHello {
    /// Decodes a ServerHello's body (`tls_process_server_hello`). With `hrr_possible` (the
    /// client may negotiate TLS 1.3), a TLS 1.2 version followed by the HelloRetryRequest
    /// random makes it one, and then its extension block is required. Faults are
    /// `SSL_R_LENGTH_MISMATCH` (decode-error), a session ID over 32 octets
    /// `SSL_R_SSL3_SESSION_ID_TOO_LONG` (illegal-parameter), a broken extension block
    /// `SSL_R_BAD_LENGTH` (decode-error).
    ///
    /// # Errors
    /// As above.
    pub fn parse(b: &[u8], hrr_possible: bool) -> Result<Self> {
        let mm = Error::decode(r::LENGTH_MISMATCH);
        let mut rd = Reader::new(b);
        let legacy_version = rd.u16().or_alert(mm)?;
        let hrr = hrr_possible
            && legacy_version == version::TLS1_2
            && rd.rest().get(..RANDOM_LEN) == Some(&HRR_RANDOM[..]);
        let random = random(&mut rd, mm)?;
        let sid = rd.vec8().or_alert(mm)?;
        if sid.len() > MAX_SESSION_ID_LEN {
            return Err(Error::alert(
                ad::ILLEGAL_PARAMETER,
                r::SSL3_SESSION_ID_TOO_LONG,
            ));
        }
        let cipher_suite = rd.u16().or_alert(mm)?;
        let compression = rd.u8().or_alert(mm)?;
        let extensions = if rd.is_empty() && !hrr {
            None
        } else {
            let bl = Error::decode(r::BAD_LENGTH);
            let block = rd.vec16().or_alert(bl)?;
            rd.end().or_alert(bl)?;
            Some(block.rest().to_vec())
        };
        Ok(Self {
            legacy_version,
            random,
            session_id: sid.rest().to_vec(),
            cipher_suite,
            compression,
            extensions,
            hrr,
        })
    }

    /// The downgrade sentinel at the end of the random, if any.
    #[must_use]
    pub fn downgrade(&self) -> Option<Downgrade> {
        let tail = self.random.get(RANDOM_LEN.saturating_sub(8)..)?;
        if tail == TLS12_DOWNGRADE {
            Some(Downgrade::Tls12)
        } else if tail == TLS11_DOWNGRADE {
            Some(Downgrade::Tls11)
        } else {
            None
        }
    }

    /// The extensions, split; empty without a block.
    ///
    /// # Errors
    /// Framing faults: `SSL_R_BAD_EXTENSION` with decode-error.
    pub fn extensions(&self) -> Result<Vec<Extension>> {
        self.extensions
            .as_deref()
            .map_or(Ok(Vec::new()), ext::split)
    }

    /// The body.
    ///
    /// # Errors
    /// A vector is too long.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_with(|w| {
            w.u16(self.legacy_version);
            w.put(&self.random);
            w.vec(1, &self.session_id)?;
            w.u16(self.cipher_suite);
            w.u8(self.compression);
            if let Some(e) = &self.extensions {
                w.vec(2, e)?;
            }
            Ok(())
        })
    }
}

/// DTLS's HelloVerifyRequest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelloVerifyRequest {
    /// server_version (OpenSSL skips it).
    pub server_version: u16,
    /// The cookie.
    pub cookie: Vec<u8>,
}

impl HelloVerifyRequest {
    /// Decodes the body (`dtls_process_hello_verify`): faults are `SSL_R_LENGTH_MISMATCH` with
    /// decode-error. Octets after the cookie are ignored, as by OpenSSL.
    ///
    /// # Errors
    /// As above.
    pub fn parse(b: &[u8]) -> Result<Self> {
        let mm = Error::decode(r::LENGTH_MISMATCH);
        let mut rd = Reader::new(b);
        let server_version = rd.u16().or_alert(mm)?;
        let cookie = rd.vec8().or_alert(mm)?.rest().to_vec();
        Ok(Self {
            server_version,
            cookie,
        })
    }

    /// The body.
    ///
    /// # Errors
    /// The cookie is longer than 255 octets.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_with(|w| {
            w.u16(self.server_version);
            w.vec(1, &self.cookie)
        })
    }
}
