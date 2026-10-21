//! Sessions on the server (`ssl_sess.c`: `ssl_get_new_session`, `ssl_get_prev_session`,
//! `lookup_sess_in_cache`), session tickets (`t1_lib.c`'s `tls_get_ticket_from_client` and
//! `tls_decrypt_ticket`; `statem_srvr.c`'s `tls_construct_new_session_ticket`), and TLS 1.3's
//! pre_shared_key (`tls_parse_ctos_psk`).
//!
//! capi owns the session cache: a lookup by session ID is [`Request::GetSession`], a
//! single-use ticket's removal [`Request::RemoveSession`], and a session to cache
//! [`crate::conn::Event::UpdateCache`] (reading [`crate::conn::Negotiated::session`]).
//!
//! A ticket is OpenSSL's format: the key name (16 octets), the IV (16), the session encrypted
//! with AES-CBC, and an HMAC-SHA256 over all of that. The keys are the application's (the
//! ticket key callback, [`Request::TicketKey`]) or the configuration's default
//! ([`crate::conn::Config::ticket_keys`]). The encrypted session is this crate's own encoding
//! ([`encode_session`]), not `i2d_SSL_SESSION`: tickets are only ever read by the server that
//! made them.

use rustyssl_abi as abi;
use subtle::ConstantTimeEq;

use super::{state, state_ref};
use crate::codec::{Reader, Writer};
use crate::conn::common::ext::{self, Ctx, Step};
use crate::conn::common::{KEX_MODE_FLAG_KE, KEX_MODE_FLAG_KE_DHE, ask_once, keys, security};
use crate::conn::statem::Construct;
use crate::conn::{Answer, Connection, Event, Request, Session};
use crate::consts::context as cx;
use crate::consts::ext as t;
use crate::consts::version as v;
use crate::crypto::{CipherAlg, HashAlg, Provider, Secret};
use crate::error::{Error, InFunc, Result};
use crate::keysched;
use crate::msgs::ext as mx;

/// `TLSEXT_KEYNAME_LENGTH`.
const KEYNAME_LEN: usize = 16;
/// `EVP_MAX_IV_LENGTH`, and AES-CBC's IV.
const IV_LEN: usize = 16;
/// HMAC-SHA256's length.
const MAC_LEN: usize = 32;
/// `TICKET_NONCE_SIZE`.
const TICKET_NONCE_SIZE: usize = 8;
/// RFC 8446's one-week limit on a ticket's lifetime (`ONE_WEEK_SEC`).
const ONE_WEEK_SEC: i64 = 7 * 24 * 60 * 60;
/// `TICKET_AGE_ALLOWANCE`, in milliseconds.
const TICKET_AGE_ALLOWANCE_MS: i64 = 10_000;
/// The method's default session timeout (`tls1_default_timeout`), in seconds.
const DEFAULT_TIMEOUT: i64 = 7200;
/// `SSL_SESSION_new`'s timeout, in seconds.
const SESSION_NEW_TIMEOUT: i64 = 60 * 5 + 4;
/// The most certificates a ticket's session may carry.
const MAX_CHAIN: usize = 100;

/// What decrypting a ticket found (`SSL_TICKET_STATUS`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Ticket {
    /// `SSL_TICKET_NONE`: no ticket.
    None,
    /// `SSL_TICKET_EMPTY`: an empty ticket (the client accepts one).
    Empty,
    /// `SSL_TICKET_NO_DECRYPT`: it can't be used.
    NoDecrypt,
    /// `SSL_TICKET_SUCCESS`.
    Success(Box<Session>),
    /// `SSL_TICKET_SUCCESS_RENEW`: it can be used, and a new one sent.
    Renew(Box<Session>),
    /// `SSL_TICKET_FATAL_ERR_*`.
    Fatal,
}

/// A TLS 1.3 PSK the client offered that the server can use.
#[derive(Clone, Debug)]
pub(crate) struct Found {
    /// The session (a ticket's, or one made for an external PSK).
    pub(crate) session: Session,
}

/// The configuration's ticket keys: the name, the IV (encrypting), the cipher key, and the
/// HMAC key.
struct Keys {
    name: Vec<u8>,
    iv: Vec<u8>,
    aes: Secret,
    hmac: Secret,
}

/// AES-CBC for a key's length.
fn cbc_for(key: &[u8]) -> Result<CipherAlg> {
    match key.len() {
        32 => Ok(CipherAlg::Aes256Cbc),
        16 => Ok(CipherAlg::Aes128Cbc),
        _ => Err(Error::internal()),
    }
}

/// The time a session expires (`calc_timeout`).
fn expires(s: &Session) -> i64 {
    s.time.saturating_add(s.timeout)
}

/// `ssl_get_new_session(s, 1)`: a new session for this handshake: the version, the session ID
/// context, the time and timeout, Extended Master Secret if the client sent it, and (below TLS
/// 1.3, without a ticket to send) a random session ID (`def_generate_session_id`).
///
/// # Errors
/// The random generator failed.
pub(crate) fn new_session(c: &mut Connection, p: &dyn Provider) -> Result<()> {
    new_session_inner(c, p).in_func("ssl_get_new_session")
}

/// See [`new_session`].
fn new_session_inner(c: &mut Connection, p: &dyn Provider) -> Result<()> {
    let timeout = if c.cfg.session_timeout == 0 {
        DEFAULT_TIMEOUT
    } else {
        c.cfg.session_timeout
    };
    let mut s = Session {
        version: c.neg.version,
        sid_ctx: c.cfg.sid_ctx.clone(),
        time: c.cfg.now,
        timeout,
        verify_result: i64::from(abi::X509_V_OK),
        max_fragment_len_mode: super::octet(abi::TLSEXT_max_fragment_length_UNSPECIFIED),
        ems: c.hs.sh.flags & abi::TLS1_FLAGS_RECEIVED_EXTMS != 0,
        ..Session::default()
    };
    if !c.is_tls13() && !c.hs.sh.ticket_expected {
        s.session_id = random_id(p)?;
    }
    c.neg.session = s;
    c.neg.peer_chain.clear();
    c.neg.peer_rpk = None;
    Ok(())
}

/// A random 32-octet session ID (`def_generate_session_id`).
///
/// # Errors
/// The random generator failed.
pub(crate) fn random_id(p: &dyn Provider) -> Result<Vec<u8>> {
    let n = usize::try_from(abi::SSL3_SSL_SESSION_ID_LENGTH).map_err(|_| Error::internal())?;
    let mut id = vec![0u8; n];
    p.random(&mut id, false)
        .map_err(|_| Error::alert(abi::SSL_AD_INTERNAL_ERROR, abi::ERR_R_INTERNAL_ERROR))?;
    Ok(id)
}

/// `lookup_sess_in_cache`: capi's cache and `get_session_cb` ([`Request::GetSession`]). `None`
/// while waiting; `Some(None)` for a miss.
fn lookup(c: &mut Connection, id: &[u8], tag: usize) -> Option<Option<Session>> {
    match ask_once(c, Request::GetSession { id: id.to_vec() }, tag)? {
        Answer::Session(s) => Some(s),
        _ => Some(None),
    }
}

/// `ssl_get_prev_session`: the session the client resumes, if any. TLS 1.3 reads
/// psk_key_exchange_modes and pre_shared_key here; earlier versions a ticket, or the session
/// ID in the cache. A session found must suit the version, the session ID context, its
/// timeout, and Extended Master Secret (a session that had it, resumed without it, is
/// `SSL_R_INCONSISTENT_EXTMS`). `None` while waiting; `Some(true)` resumes.
///
/// # Errors
/// A fatal ticket error, verification without a session ID context
/// (`SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED`), or inconsistent Extended Master Secret.
pub(crate) fn get_prev_session(c: &mut Connection, p: &dyn Provider) -> Result<Option<bool>> {
    get_prev_session_inner(c, p).in_func("ssl_get_prev_session")
}

/// See [`get_prev_session`].
fn get_prev_session_inner(c: &mut Connection, p: &dyn Provider) -> Result<Option<bool>> {
    let mut try_cache = false;
    let found = if c.is_tls13() {
        c.neg.session = Session::default();
        c.hs.sh.ticket_expected = true;
        for typ in [t::PSK_KEY_EXCHANGE_MODES, t::PRE_SHARED_KEY] {
            let idx = ext::index_of(typ).ok_or_else(Error::internal)?;
            if ext::parse_extension(c, p, idx, cx::CLIENT_HELLO, 0)? == Step::Wait {
                return Ok(None);
            }
        }
        state(c)?.psk_found.take().map(|f| f.session)
    } else {
        let Some(r) = ticket_from_client(c, p)? else {
            return Ok(None);
        };
        match r {
            Ticket::Fatal => {
                return Err(Error::alert(
                    abi::SSL_AD_INTERNAL_ERROR,
                    abi::ERR_R_INTERNAL_ERROR,
                ));
            }
            Ticket::None | Ticket::Empty => {
                let sid = super::hello::client_session_id(c)?;
                if sid.is_empty() {
                    None
                } else {
                    try_cache = true;
                    match lookup(c, &sid, 0) {
                        None => return Ok(None),
                        Some(s) => s,
                    }
                }
            }
            Ticket::NoDecrypt => None,
            Ticket::Success(s) | Ticket::Renew(s) => Some(*s),
        }
    };
    let Some(sess) = found else {
        return Ok(Some(false));
    };
    let miss = |c: &mut Connection| {
        if c.is_tls13() {
            c.neg.session = Session::default();
        }
        if !try_cache {
            c.hs.sh.ticket_expected = true;
        }
        Ok(Some(false))
    };
    if sess.version != c.neg.version || sess.sid_ctx != c.cfg.sid_ctx {
        return miss(c);
    }
    if c.cfg.verify_mode & abi::SSL_VERIFY_PEER != 0 && c.cfg.sid_ctx.is_empty() {
        return Err(Error::alert(
            abi::SSL_AD_INTERNAL_ERROR,
            abi::SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED,
        ));
    }
    if c.cfg.now > expires(&sess) {
        if try_cache {
            // The session is from the cache: it leaves it (the answer doesn't matter, but it
            // must be waited for, or the request stays pending).
            let r = Request::RemoveSession {
                id: sess.session_id.clone(),
            };
            if ask_once(c, r, 0).is_none() {
                return Ok(None);
            }
        }
        return miss(c);
    }
    let received_ems = c.hs.sh.flags & abi::TLS1_FLAGS_RECEIVED_EXTMS != 0;
    if sess.ems && !received_ems {
        return Err(Error::alert(
            abi::SSL_AD_HANDSHAKE_FAILURE,
            abi::SSL_R_INCONSISTENT_EXTMS,
        ));
    }
    if !sess.ems && received_ems {
        return miss(c);
    }
    // 3.6: before TLS 1.3, a session whose ID isn't the one the ClientHello offered (a
    // corrupt cache entry, an external cache returning the wrong session, tampering) isn't
    // resumed; the handshake goes on as a full one, without err's bookkeeping.
    if !c.is_tls13() {
        let sid = super::hello::client_session_id(c)?;
        if !sid.is_empty() && sess.session_id != sid {
            return Ok(Some(false));
        }
    }
    c.neg.verify_result = sess.verify_result;
    c.neg.peer_chain.clone_from(&sess.peer_chain);
    c.neg.session = sess;
    Ok(Some(true))
}

/// `tls_get_ticket_from_client`: TLS 1.2's session_ticket extension, unless tickets are off.
/// `None` while waiting.
fn ticket_from_client(c: &mut Connection, p: &dyn Provider) -> Result<Option<Ticket>> {
    c.hs.sh.ticket_expected = false;
    if c.neg.version <= v::SSL3 || !security::use_ticket(c) {
        return Ok(Some(Ticket::None));
    }
    let Some(body) = super::hello::received_body(c, t::SESSION_TICKET) else {
        return Ok(Some(Ticket::None));
    };
    let sid = super::hello::client_session_id(c)?;
    decrypt_ticket(c, p, &body, &sid, 0)
}

/// `tls_decrypt_ticket`: the session in a ticket. The key name picks the keys (the ticket key
/// callback's, which may ask for renewal, or the configuration's, which in TLS 1.3 always
/// renew); the HMAC is checked in constant time before anything is decrypted; any fault is
/// `SSL_TICKET_NO_DECRYPT` (a new ticket is sent). The session ID the client sent, if any, is
/// the resumed session's. `tag` tells the callback's answers apart for several identities.
/// `None` while waiting.
///
/// # Errors
/// None beyond what the status reports; `Result` for the provider's failures.
pub(crate) fn decrypt_ticket(
    c: &mut Connection,
    p: &dyn Provider,
    etick: &[u8],
    sess_id: &[u8],
    tag: usize,
) -> Result<Option<Ticket>> {
    let r = decrypt_inner(c, p, etick, sess_id, tag)?;
    let Some(r) = r else {
        return Ok(None);
    };
    let r = if c.cfg.callbacks.ticket_dec {
        match decrypt_cb(c, etick, r, tag) {
            Some(r) => r,
            None => return Ok(None),
        }
    } else {
        r
    };
    if (!c.cfg.callbacks.session_secret || c.is_tls13())
        && matches!(r, Ticket::NoDecrypt | Ticket::Renew(_) | Ticket::Empty)
    {
        c.hs.sh.ticket_expected = true;
    }
    Ok(Some(r))
}

/// `decrypt_ticket_cb`, unless a fatal error happened: what the application makes of the
/// result (`SSL_TICKET_RETURN_*`). `None` while waiting.
fn decrypt_cb(c: &mut Connection, etick: &[u8], r: Ticket, tag: usize) -> Option<Ticket> {
    let (status, session) = match &r {
        Ticket::Empty => (abi::SSL_TICKET_EMPTY, None),
        Ticket::NoDecrypt => (abi::SSL_TICKET_NO_DECRYPT, None),
        Ticket::Success(s) => (abi::SSL_TICKET_SUCCESS, Some(s.clone())),
        Ticket::Renew(s) => (abi::SSL_TICKET_SUCCESS_RENEW, Some(s.clone())),
        Ticket::None | Ticket::Fatal => return Some(r),
    };
    let keyname = etick
        .get(..etick.len().min(KEYNAME_LEN))
        .unwrap_or_default()
        .to_vec();
    let req = Request::TicketDecrypt {
        keyname,
        status,
        session,
    };
    let ret = match ask_once(c, req, tag)? {
        Answer::TicketDecrypt(v) => v,
        _ => abi::SSL_TICKET_RETURN_ABORT,
    };
    Some(match ret {
        abi::SSL_TICKET_RETURN_IGNORE => Ticket::None,
        abi::SSL_TICKET_RETURN_IGNORE_RENEW => match r {
            Ticket::Empty => Ticket::Empty,
            _ => Ticket::NoDecrypt,
        },
        abi::SSL_TICKET_RETURN_USE | abi::SSL_TICKET_RETURN_USE_RENEW => match r {
            Ticket::Success(s) | Ticket::Renew(s) => {
                if ret == abi::SSL_TICKET_RETURN_USE {
                    Ticket::Success(s)
                } else {
                    Ticket::Renew(s)
                }
            }
            _ => Ticket::Fatal,
        },
        _ => Ticket::Fatal,
    })
}

/// [`decrypt_ticket`]'s work.
fn decrypt_inner(
    c: &mut Connection,
    p: &dyn Provider,
    etick: &[u8],
    sess_id: &[u8],
    tag: usize,
) -> Result<Option<Ticket>> {
    if etick.is_empty() {
        return Ok(Some(Ticket::Empty));
    }
    if !c.is_tls13() && c.cfg.callbacks.session_secret {
        // The master secret comes from the session secret callback later (EAP-FAST).
        return Ok(Some(Ticket::NoDecrypt));
    }
    let header = KEYNAME_LEN.saturating_add(IV_LEN);
    let (Some(name), Some(iv)) = (etick.get(..KEYNAME_LEN), etick.get(KEYNAME_LEN..header)) else {
        return Ok(Some(Ticket::NoDecrypt));
    };
    if c.cfg.callbacks.ticket_key {
        // The callback's contexts check and decrypt the ticket.
        let r = Request::TicketKey {
            ticket: etick.to_vec(),
            session: Secret::default(),
            encrypt: false,
        };
        return Ok(match ask_once(c, r, tag) {
            None => None,
            Some(Answer::TicketKey { ret, data }) => Some(match data {
                _ if ret < 0 => Ticket::Fatal,
                Some(plain) if ret > 0 => opened(plain.bytes(), sess_id, ret == 2),
                _ => Ticket::NoDecrypt,
            }),
            Some(_) => Some(Ticket::Fatal),
        });
    }
    let Some(k) = &c.cfg.ticket_keys else {
        return Ok(Some(Ticket::Fatal));
    };
    if k.name[..] != *name {
        return Ok(Some(Ticket::NoDecrypt));
    }
    let renew = c.is_tls13();
    let (aes, hmac) = (k.aes_key.clone(), k.hmac_key.clone());
    let Ok(alg) = cbc_for(aes.bytes()) else {
        return Ok(Some(Ticket::Fatal));
    };
    if etick.len() <= header.saturating_add(MAC_LEN) {
        return Ok(Some(Ticket::NoDecrypt));
    }
    let body_len = etick.len().saturating_sub(MAC_LEN);
    let (Some(signed), Some(mac)) = (etick.get(..body_len), etick.get(body_len..)) else {
        return Ok(Some(Ticket::NoDecrypt));
    };
    let Ok(want) = keysched::hmac(p, HashAlg::Sha256, hmac.bytes(), &[signed]) else {
        return Ok(Some(Ticket::Fatal));
    };
    if !bool::from(want.as_slice().ct_eq(mac)) {
        return Ok(Some(Ticket::NoDecrypt));
    }
    let mut data = signed.get(header..).unwrap_or_default().to_vec();
    if data.is_empty() || !data.len().is_multiple_of(IV_LEN) {
        return Ok(Some(Ticket::NoDecrypt));
    }
    let Ok(mut cbc) = p.cipher(alg, aes.bytes(), false) else {
        return Ok(Some(Ticket::Fatal));
    };
    if cbc.crypt(iv, &mut data).is_err() {
        return Ok(Some(Ticket::Fatal));
    }
    let data = Secret::new(data);
    let Some(plain) = unpad(data.bytes()) else {
        return Ok(Some(Ticket::NoDecrypt));
    };
    Ok(Some(opened(plain, sess_id, renew)))
}

/// A decrypted ticket's session, with the session ID the client sent (if any): what
/// `d2i_SSL_SESSION` makes of the plaintext, `SSL_TICKET_NO_DECRYPT` if nothing.
fn opened(plain: &[u8], sess_id: &[u8], renew: bool) -> Ticket {
    let Some(mut sess) = decode_session(plain) else {
        return Ticket::NoDecrypt;
    };
    if !sess_id.is_empty() {
        sess.session_id = sess_id.to_vec();
    }
    if renew {
        Ticket::Renew(Box::new(sess))
    } else {
        Ticket::Success(Box::new(sess))
    }
}

/// PKCS #7 padding's removal (`EVP_DecryptFinal`), after the HMAC is checked.
fn unpad(b: &[u8]) -> Option<&[u8]> {
    let n = usize::from(*b.last()?);
    if n == 0 || n > IV_LEN || n > b.len() {
        return None;
    }
    let (data, pad) = b.split_at(b.len().checked_sub(n)?);
    pad.iter().all(|&x| usize::from(x) == n).then_some(data)
}

/// The ticket for `session`: sealed by the ticket key callback's contexts, or with the
/// configuration's keys. `None` while waiting; `Some(None)` when the callback declines (`0`: an
/// empty TLS 1.2 ticket, or no TLS 1.3 ticket).
///
/// # Errors
/// The callback failed (`SSL_R_CALLBACK_FAILED`), or its contexts or the keys did (internal).
fn sealed(
    c: &mut Connection,
    p: &dyn Provider,
    session: &Session,
    tag: usize,
) -> Result<Option<Option<Vec<u8>>>> {
    if !c.cfg.callbacks.ticket_key {
        let k = c.cfg.ticket_keys.clone().ok_or_else(Error::internal)?;
        let mut iv = vec![0u8; IV_LEN];
        p.random(&mut iv, false).map_err(|_| Error::internal())?;
        let keys = Keys {
            name: k.name.to_vec(),
            iv,
            aes: k.aes_key,
            hmac: k.hmac_key,
        };
        return seal(p, &keys, session).map(|t| Some(Some(t)));
    }
    let senc = Secret::new(encode_session(session)?);
    if senc.is_empty() || senc.len() > 0xff00 {
        return Err(Error::internal());
    }
    let r = Request::TicketKey {
        ticket: Vec::new(),
        session: senc,
        encrypt: true,
    };
    match ask_once(c, r, tag) {
        None => Ok(None),
        Some(Answer::TicketKey { ret: 0, .. }) => Ok(Some(None)),
        Some(Answer::TicketKey { ret, data }) => {
            if ret < 0 {
                return Err(Error::alert(
                    abi::SSL_AD_INTERNAL_ERROR,
                    abi::SSL_R_CALLBACK_FAILED,
                ));
            }
            let t = data.ok_or_else(Error::internal)?;
            Ok(Some(Some(t.bytes().to_vec())))
        }
        Some(_) => Err(Error::alert(
            abi::SSL_AD_INTERNAL_ERROR,
            abi::SSL_R_CALLBACK_FAILED,
        )),
    }
}

/// A ticket for `session` under the configuration's keys, for tests that offer one.
#[cfg(test)]
pub(crate) fn seal_for_test(c: &mut Connection, p: &dyn Provider, session: &Session) -> Vec<u8> {
    match sealed(c, p, session, 0) {
        Ok(Some(Some(t))) => t,
        other => panic!("cannot seal a ticket: {other:?}"),
    }
}

/// `construct_stateless_ticket`'s ticket: the key name, the IV, the session encrypted, and the
/// HMAC.
fn seal(p: &dyn Provider, k: &Keys, session: &Session) -> Result<Vec<u8>> {
    let senc = Secret::new(encode_session(session)?);
    if senc.is_empty() || senc.len() > 0xff00 {
        return Err(Error::internal());
    }
    let alg = cbc_for(k.aes.bytes())?;
    let pad = IV_LEN.saturating_sub(senc.len() % IV_LEN);
    let mut data = senc.bytes().to_vec();
    data.resize(
        senc.len().saturating_add(pad),
        u8::try_from(pad).map_err(|_| Error::internal())?,
    );
    let mut cbc = p
        .cipher(alg, k.aes.bytes(), true)
        .map_err(|_| Error::internal())?;
    cbc.crypt(&k.iv, &mut data).map_err(|_| Error::internal())?;
    let mut out = Vec::new();
    out.extend_from_slice(&k.name);
    out.extend_from_slice(&k.iv);
    out.extend_from_slice(&data);
    let mac = keysched::hmac(p, HashAlg::Sha256, k.hmac.bytes(), &[&out])
        .map_err(|_| Error::internal())?;
    out.extend_from_slice(&mac);
    Ok(out)
}

/// The session a TLS 1.3 ticket is made for (the parts of `tls_construct_new_session_ticket`
/// before the ticket): a fresh session ID and age_add, the PSK from the resumption master
/// secret and the nonce, the time, the ALPN protocol, and the early data limit.
fn prepare13(
    c: &mut Connection,
    p: &dyn Provider,
) -> Result<(Session, u32, [u8; TICKET_NONCE_SIZE])> {
    let hash = keys::handshake_md(c)?;
    let mut s = c.neg.session.clone();
    s.session_id = random_id(p)?;
    let mut a = [0u8; 4];
    p.random(&mut a, false)
        .map_err(|_| Error::alert(abi::SSL_AD_INTERNAL_ERROR, abi::ERR_R_INTERNAL_ERROR))?;
    let age_add = u32::from_be_bytes(a);
    s.ticket_age_add = age_add;
    let nonce = state(c)?.next_ticket_nonce.to_be_bytes();
    let psk = keysched::resumption_psk(p, hash, c.hs.sh.keys.resumption_master.bytes(), &nonce)?;
    s.master_key = psk.bytes().to_vec();
    s.time = c.cfg.now;
    if let Some(a) = &c.neg.alpn {
        s.alpn = Some(a.clone());
    }
    s.max_early_data = c.cfg.max_early_data;
    s.cipher_id = c.hs.new_cipher.map_or(s.cipher_id, |x| x.id);
    s.version = c.neg.version;
    Ok((s, age_add, nonce))
}

/// `tls_update_ticket_counts`.
fn update_ticket_counts(c: &mut Connection) -> Result<()> {
    let s = state(c)?;
    s.sent_tickets = s.sent_tickets.saturating_add(1);
    s.next_ticket_nonce = s.next_ticket_nonce.wrapping_add(1);
    s.extra_tickets_expected = s.extra_tickets_expected.saturating_sub(1);
    Ok(())
}

/// `tls_construct_new_session_ticket`. TLS 1.3: a ticket for a new session (stateful, the
/// session ID, with `SSL_OP_NO_TICKET` or anti-replay; stateless otherwise), its lifetime (at
/// most a week), age_add, nonce, and extensions; the session is then cached
/// ([`Event::UpdateCache`]). TLS 1.2: the lifetime hint (0 when resuming) and the ticket of the
/// session (an empty one when the ticket key callback declines).
///
/// # Errors
/// The ticket couldn't be made (OpenSSL's alerts and reasons).
pub(crate) fn construct_new_session_ticket(
    c: &mut Connection,
    p: &dyn Provider,
) -> Result<Construct> {
    let tls13 = c.is_tls13();
    let (session, age_add, nonce) = if tls13 {
        match state(c)?.pending_ticket.clone() {
            Some(x) => x,
            None => {
                let x = prepare13(c, p)?;
                state(c)?.pending_ticket = Some(x.clone());
                x
            }
        }
    } else {
        let mut s = c.neg.session.clone();
        s.master_key.clone_from(&c.neg.master_secret);
        (s, 0, [0; TICKET_NONCE_SIZE])
    };
    let mut session = session;
    // `kex_group`: this handshake's, or (a resumption without a key exchange) the original's.
    if let Some(g) = c.neg.group {
        session.kex_group = g;
    }
    if c.cfg.callbacks.ticket_gen {
        // One answer per ticket.
        let tag = usize::try_from(state(c)?.next_ticket_nonce).unwrap_or(usize::MAX);
        let r = Request::TicketGenerate {
            session: Box::new(session.clone()),
        };
        match ask_once(c, r, tag) {
            None => return Ok(Construct::Ask),
            Some(Answer::TicketGenerated { appdata, time }) => {
                // The application changed the connection's session (`SSL_get_session`).
                c.neg.session.ticket_appdata.clone_from(&appdata);
                c.neg.session.time = time;
                session.ticket_appdata = appdata;
                session.time = time;
            }
            Some(_) => {
                return Err(Error::alert_lib(
                    abi::SSL_AD_INTERNAL_ERROR,
                    abi::ERR_R_INTERNAL_ERROR,
                ));
            }
        }
    }
    let o = c.cfg.options;
    let stateful = tls13
        && (o & abi::SSL_OP_NO_TICKET != 0
            || (c.cfg.max_early_data > 0 && o & abi::SSL_OP_NO_ANTI_REPLAY == 0));
    let lifetime = if tls13 {
        session.timeout.min(ONE_WEEK_SEC)
    } else if c.neg.reused {
        0
    } else {
        session.timeout
    };
    let lifetime = u32::try_from(lifetime.max(0)).unwrap_or(u32::MAX);
    let ticket = if stateful {
        session.session_id.clone()
    } else {
        // One answer per ticket.
        let tag = usize::try_from(state(c)?.next_ticket_nonce).unwrap_or(usize::MAX);
        match sealed(c, p, &session, tag)? {
            None => return Ok(Construct::Ask),
            Some(None) => {
                if tls13 {
                    update_ticket_counts(c)?;
                    state(c)?.pending_ticket = None;
                    return Ok(Construct::DontSend);
                }
                let mut w = Writer::new();
                w.u32(0);
                w.u16(0);
                return Ok(Construct::Send(w.into_bytes()));
            }
            Some(Some(t)) => t,
        }
    };
    let mut w = Writer::new();
    w.u32(lifetime);
    if tls13 {
        w.u32(age_add);
        w.vec(1, &nonce).map_err(|_| Error::internal())?;
    }
    w.vec(2, &ticket).map_err(|_| Error::internal())?;
    if tls13 {
        let Some(block) = ext::construct(c, p, cx::TLS1_3_NEW_SESSION_TICKET, 0)? else {
            return Ok(Construct::Ask);
        };
        w.put(&block);
        c.neg.session = session;
        update_ticket_counts(c)?;
        state(c)?.pending_ticket = None;
        c.notify(Event::UpdateCache { server: true });
    }
    Ok(Construct::Send(w.into_bytes()))
}

/// `tls_get_stateful_ticket`: a ticket that is a session ID in the cache.
fn stateful_ticket(c: &mut Connection, tick: &[u8], tag: usize) -> Option<Ticket> {
    c.hs.sh.ticket_expected = true;
    let n = usize::try_from(abi::SSL_MAX_SSL_SESSION_ID_LENGTH).unwrap_or(32);
    if tick.is_empty() {
        return Some(Ticket::Empty);
    }
    if tick.len() != n {
        return Some(Ticket::NoDecrypt);
    }
    match lookup(c, tick, tag)? {
        None => Some(Ticket::NoDecrypt),
        Some(s) => Some(Ticket::Success(Box::new(s))),
    }
}

/// `tls_parse_ctos_psk`: the first identity the server can use (an external PSK from the
/// PSK session callback or the TLS 1.2-style PSK callback, or a ticket: stateful with
/// `SSL_OP_NO_TICKET` or anti-replay, else stateless), with a suite of the same hash; then its
/// binder is checked (`SSL_R_BINDER_DOES_NOT_VERIFY`, decrypt-error) and the session becomes
/// the handshake's, with the early secret. Early data needs the first identity, a ticket within
/// its lifetime and age tolerance, and (anti-replay) a ticket not used before. Ignored without
/// a key exchange mode this end accepts.
///
/// # Errors
/// A malformed extension or identity (`SSL_R_BAD_EXTENSION`, decode-error), a callback failed,
/// or the binder doesn't verify.
pub(crate) fn parse_psk(
    c: &mut Connection,
    p: &dyn Provider,
    body: &[u8],
    _x: &Ctx,
) -> Result<Step> {
    if c.hs.sh.psk_kex_mode & (KEX_MODE_FLAG_KE | KEX_MODE_FLAG_KE_DHE) == 0 {
        return Ok(Step::Done);
    }
    let offer = mx::psk::Offer::parse(body)?;
    c.hs.sh.ticket_expected = false;
    let o = c.cfg.options;
    let anti_replay = c.cfg.max_early_data > 0 && o & abi::SSL_OP_NO_ANTI_REPLAY == 0;
    let mut chosen: Option<(usize, Session, bool)> = None;
    for (id, ident) in offer.identities().enumerate() {
        let ident = ident?;
        let identity = ident.identity;
        let mut sess: Option<Session> = None;
        if c.cfg.callbacks.psk_session {
            let r = Request::PskSession {
                identity: identity.clone(),
                md: None,
            };
            match ask_once(c, r, id) {
                None => return Ok(Step::Wait),
                Some(Answer::Session(s)) => sess = s,
                Some(Answer::Continue) => {}
                Some(_) => {
                    return Err(Error::alert(
                        abi::SSL_AD_INTERNAL_ERROR,
                        abi::SSL_R_BAD_EXTENSION,
                    ));
                }
            }
        }
        let max_id = usize::try_from(abi::PSK_MAX_IDENTITY_LEN).unwrap_or(256);
        if sess.is_none() && c.cfg.callbacks.psk && identity.len() <= max_id {
            let r = Request::Psk {
                hint_or_identity: identity.clone(),
            };
            match ask_once(c, r, id) {
                None => return Ok(Step::Wait),
                Some(Answer::Psk(Some(e))) => {
                    let max_psk = usize::try_from(abi::PSK_MAX_PSK_LEN).unwrap_or(512);
                    if e.key.len() > max_psk {
                        return Err(Error::internal());
                    }
                    if !e.key.is_empty() {
                        let cid = crate::suites::cid(abi::TLS1_3_CK_AES_128_GCM_SHA256);
                        // `SSL_SESSION_new`'s time and timeout (`60 * 5 + 4`).
                        sess = Some(Session {
                            master_key: e.key,
                            cipher_id: cid,
                            version: v::TLS1_3,
                            time: c.cfg.now,
                            timeout: SESSION_NEW_TIMEOUT,
                            ..Session::default()
                        });
                    }
                }
                Some(_) => {}
            }
        }
        let external;
        if let Some(s) = &mut sess {
            s.sid_ctx.clone_from(&c.cfg.sid_ctx);
            external = true;
            if id == 0 {
                c.hs.sh.early_data_ok = true;
            }
            c.hs.sh.ticket_expected = true;
        } else {
            external = false;
            let stateful = o & abi::SSL_OP_NO_TICKET != 0 || anti_replay;
            let r = if stateful {
                stateful_ticket(c, &identity, id)
            } else {
                decrypt_ticket(c, p, &identity, &[], id)?
            };
            let Some(r) = r else {
                return Ok(Step::Wait);
            };
            let s = match r {
                Ticket::Empty => return Err(Error::decode(abi::SSL_R_BAD_EXTENSION)),
                Ticket::Fatal => return Err(Error::internal()),
                Ticket::None | Ticket::NoDecrypt => continue,
                Ticket::Success(s) | Ticket::Renew(s) => *s,
            };
            if anti_replay {
                let r = Request::RemoveSession {
                    id: s.session_id.clone(),
                };
                match ask_once(c, r, id) {
                    None => return Ok(Step::Wait),
                    Some(Answer::Allowed(true)) => {}
                    Some(_) => continue,
                }
            }
            let age_ms = i64::from(ident.obfuscated_ticket_age.wrapping_sub(s.ticket_age_add));
            let t_ms = c.cfg.now.saturating_sub(s.time).max(0).saturating_mul(1000);
            let expire = t_ms.saturating_add(1000);
            if id == 0
                && s.timeout.saturating_mul(1000) >= t_ms
                && age_ms <= expire
                && age_ms.saturating_add(TICKET_AGE_ALLOWANCE_MS) >= expire
            {
                c.hs.sh.early_data_ok = true;
            }
            sess = Some(s);
        }
        let Some(s) = sess else { continue };
        let Some(scp) = crate::suites::by_id(s.cipher_id) else {
            return Err(Error::internal());
        };
        let ours = c.hs.new_cipher.ok_or_else(Error::internal)?;
        // `ssl_md` of each suite's own `algorithm2`: a session from a TLS 1.1 or older suite
        // (MD5-SHA1) never fits a TLS 1.3 suite.
        if scp.handshake_hash() != ours.handshake_hash() {
            c.hs.sh.early_data_ok = false;
            c.hs.sh.ticket_expected = true;
            continue;
        }
        chosen = Some((id, s, external));
        break;
    }
    let Some((id, sess, external)) = chosen else {
        return Ok(Step::Done);
    };
    let scp = crate::suites::by_id(sess.cipher_id).ok_or_else(Error::internal)?;
    let hash = keys::hashes(v::TLS1_3, scp).0;
    let binder = offer.binder(id)?;
    if binder.len() != hash.len() {
        return Err(Error::decode(abi::SSL_R_BAD_EXTENSION));
    }
    let prefix = binder_prefix(c, &offer)?;
    let (sched, _) = ext::psk_do_binder(
        c,
        p,
        hash,
        &prefix,
        &sess.master_key,
        external,
        Some(&binder),
    )?;
    c.hs.sh.keys.schedule = Some(sched);
    let s = state(c)?;
    s.tick_identity = u16::try_from(id).map_err(|_| Error::internal())?;
    s.psk_found = Some(Found { session: sess });
    Ok(Step::Done)
}

/// The ClientHello up to its binders (with its handshake header), which the binders cover.
fn binder_prefix(c: &Connection, offer: &mx::psk::Offer) -> Result<Vec<u8>> {
    let s = state_ref(c).ok_or_else(Error::internal)?;
    let h = s.hello.as_ref().ok_or_else(Error::internal)?;
    let raw = ext::received(c, cx::CLIENT_HELLO, 0)
        .and_then(|r| r.get(t::PRE_SHARED_KEY))
        .ok_or_else(Error::internal)?;
    let at = h
        .extensions_offset
        .checked_add(raw.offset)
        .and_then(|n| n.checked_add(offer.binders_offset()))
        .ok_or_else(Error::internal)?;
    let msg = crate::msgs::frame(crate::consts::handshake::CLIENT_HELLO, &s.hello_body)?;
    let end = at
        .checked_add(crate::msgs::HEADER_LEN)
        .ok_or_else(Error::internal)?;
    msg.get(..end)
        .map(<[u8]>::to_vec)
        .ok_or_else(Error::internal)
}

/// [`encode_session`]'s format octet: always set.
const FORMAT_BASE: u8 = 1;
/// The format octet's flag for the application data.
const FORMAT_APPDATA: u8 = 2;
/// The format octet's flag for the peer's raw public key.
const FORMAT_RPK: u8 = 4;
/// The format octet's flag for the SRP login.
const FORMAT_SRP: u8 = 8;

/// The session's encoding inside a ticket (this crate's, versioned): every field of
/// [`Session`] but the ticket itself.
///
/// # Errors
/// A field is too long.
pub(crate) fn encode_session(s: &Session) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    let e = |_| Error::internal();
    // The format octet's bits beyond the first say which optional fields follow (the
    // application data, the peer's raw public key): a ticket with neither keeps format 1, so
    // its length (which the trace shows) stays the reference's.
    let mut format = FORMAT_BASE;
    if s.ticket_appdata.is_some() {
        format |= FORMAT_APPDATA;
    }
    if s.peer_rpk.is_some() {
        format |= FORMAT_RPK;
    }
    if s.srp_username.is_some() {
        format |= FORMAT_SRP;
    }
    w.u8(format);
    w.u16(s.version);
    w.u32(s.cipher_id);
    w.vec(1, &s.session_id).map_err(e)?;
    w.vec(1, &s.sid_ctx).map_err(e)?;
    w.vec(1, &s.master_key).map_err(e)?;
    w.u8(u8::from(s.ems));
    w.u32(s.ticket_age_add);
    // Four octets (the NewSessionTicket's), and the group in two: the format-1 ticket's
    // length stays the reference's.
    w.u32(u32::try_from(s.ticket_lifetime_hint).unwrap_or(u32::MAX));
    w.u16(s.kex_group);
    w.u64(u64::from_ne_bytes(s.time.to_ne_bytes()));
    w.u64(u64::from_ne_bytes(s.timeout.to_ne_bytes()));
    w.u32(s.max_early_data);
    for o in [&s.hostname, &s.alpn] {
        match o {
            None => w.u8(0),
            Some(b) => {
                w.u8(1);
                w.vec(2, b).map_err(e)?;
            }
        }
    }
    let n = u8::try_from(s.peer_chain.len()).map_err(|_| Error::internal())?;
    w.u8(n);
    for c in &s.peer_chain {
        w.vec(3, c).map_err(e)?;
    }
    w.u64(u64::from_ne_bytes(s.verify_result.to_ne_bytes()));
    w.u8(s.max_fragment_len_mode);
    w.u32(s.ext_flags);
    if let Some(b) = &s.ticket_appdata {
        w.vec(2, b).map_err(e)?;
    }
    if let Some(k) = &s.peer_rpk {
        w.vec(3, k).map_err(e)?;
    }
    if let Some(u) = &s.srp_username {
        w.vec(1, u).map_err(e)?;
    }
    Ok(w.into_bytes())
}

/// Decodes [`encode_session`]'s encoding, strictly: anything else, or octets over, is `None`.
#[must_use]
pub(crate) fn decode_session(b: &[u8]) -> Option<Session> {
    let mut rd = Reader::new(b);
    let format = rd.u8().ok()?;
    if format & FORMAT_BASE == 0
        || format & !(FORMAT_BASE | FORMAT_APPDATA | FORMAT_RPK | FORMAT_SRP) != 0
    {
        return None;
    }
    let version = rd.u16().ok()?;
    let cipher_id = rd.u32().ok()?;
    let session_id = rd.vec8().ok()?.rest().to_vec();
    let sid_ctx = rd.vec8().ok()?.rest().to_vec();
    let master_key = rd.vec8().ok()?.rest().to_vec();
    let ems = match rd.u8().ok()? {
        0 => false,
        1 => true,
        _ => return None,
    };
    let ticket_age_add = rd.u32().ok()?;
    let ticket_lifetime_hint = u64::from(rd.u32().ok()?);
    let kex_group = rd.u16().ok()?;
    let time = i64::from_ne_bytes(rd.u64().ok()?.to_ne_bytes());
    let timeout = i64::from_ne_bytes(rd.u64().ok()?.to_ne_bytes());
    let max_early_data = rd.u32().ok()?;
    let mut opt = || -> Option<Option<Vec<u8>>> {
        match rd.u8().ok()? {
            0 => Some(None),
            1 => Some(Some(rd.vec16().ok()?.rest().to_vec())),
            _ => None,
        }
    };
    let hostname = opt()?;
    let alpn = opt()?;
    let n = usize::from(rd.u8().ok()?);
    if n > MAX_CHAIN {
        return None;
    }
    let mut peer_chain = Vec::with_capacity(n);
    for _ in 0..n {
        peer_chain.push(rd.vec24().ok()?.rest().to_vec());
    }
    let verify_result = i64::from_ne_bytes(rd.u64().ok()?.to_ne_bytes());
    let max_fragment_len_mode = rd.u8().ok()?;
    let ext_flags = rd.u32().ok()?;
    let ticket_appdata = if format & FORMAT_APPDATA != 0 {
        Some(rd.vec16().ok()?.rest().to_vec())
    } else {
        None
    };
    let peer_rpk = if format & FORMAT_RPK != 0 {
        Some(rd.vec24().ok()?.rest().to_vec())
    } else {
        None
    };
    let srp_username = if format & FORMAT_SRP != 0 {
        Some(rd.vec8().ok()?.rest().to_vec())
    } else {
        None
    };
    rd.end().ok()?;
    if session_id.len() > 32 || sid_ctx.len() > 32 {
        return None;
    }
    Some(Session {
        version,
        not_resumable: false,
        cipher_id,
        session_id,
        sid_ctx,
        master_key,
        ems,
        ticket: None,
        ticket_age_add,
        ticket_lifetime_hint,
        time,
        timeout,
        max_early_data,
        hostname,
        alpn,
        peer_chain,
        peer_rpk,
        verify_result,
        max_fragment_len_mode,
        ext_flags,
        kex_group,
        ticket_appdata,
        srp_username,
    })
}
