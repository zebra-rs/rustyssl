//! The ticket key callbacks (`SSL_CTX_set_tlsext_ticket_key_evp_cb`, and the deprecated
//! `SSL_CTX_set_tlsext_ticket_key_cb` with an `HMAC_CTX`): the application sets up a cipher
//! context and an HMAC context, which then check and decrypt a received ticket
//! (`tls_decrypt_ticket`) or seal a new one (`construct_stateless_ticket`), as libssl does.
//! The core sees only the callback's verdict and the result ([`Answer::TicketKey`]).

use core::ffi::{c_char, c_int, c_uchar, c_uint};

use subtle::ConstantTimeEq;

use rustyssl_abi::{
    EVP_CIPHER_CTX, EVP_MAC_CTX, EVP_MAX_BLOCK_LENGTH, EVP_MAX_IV_LENGTH, EVP_MAX_MD_SIZE,
    HMAC_CTX, OSSL_LIB_CTX, SSL,
};
use rustyssl_tls::conn::Answer;
use rustyssl_tls::crypto::Secret;

use super::super::conn::Ssl;
use super::super::types::{AnyCb, TICK_KEY_NAME_LEN, TicketKeyEvpCb};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_get_iv_length, EVP_CIPHER_CTX_new, EVP_DecryptFinal_ex,
    EVP_DecryptUpdate, EVP_EncryptFinal_ex, EVP_EncryptUpdate,
};
use crate::evp::mac::{
    EVP_MAC_CTX_free, EVP_MAC_CTX_get_mac_size, EVP_MAC_CTX_new, EVP_MAC_fetch, EVP_MAC_final,
    EVP_MAC_free, EVP_MAC_update,
};
use crate::hmac::{HMAC_CTX_free, HMAC_CTX_new, HMAC_Final, HMAC_Update, HMAC_size};

/// The deprecated callback's real type, as `SSL_CTX_callback_ctrl` stored it.
type LegacyCb = unsafe extern "C" fn(
    *mut SSL,
    *mut c_uchar,
    *mut c_uchar,
    *mut EVP_CIPHER_CTX,
    *mut HMAC_CTX,
    c_int,
) -> c_int;

/// `SSL_TICKET_FATAL_ERR_OTHER`, as [`Answer::TicketKey`]'s `ret` says it.
const FATAL: c_int = -1;

/// The session context's ticket key callbacks and where its HMAC is fetched from.
struct Callbacks {
    evp: TicketKeyEvpCb,
    legacy: AnyCb,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
}

/// The session context's callbacks (`s->session_ctx`, whose ticket keys libssl uses).
fn callbacks(x: &Ssl) -> Option<Callbacks> {
    let sctx = x.state().session_ctx;
    // SAFETY: the connection's session context, which it keeps alive.
    unsafe { super::super::ctx::ctx(sctx) }.map(|c| {
        let st = c.state();
        Callbacks {
            evp: st.ticket_key_evp_cb,
            legacy: st.ticket_key_cb,
            libctx: c.libctx,
            propq: c.propq_ptr(),
        }
    })
}

/// An `SSL_HMAC`: the EVP MAC context, or (for the deprecated callback alone) an `HMAC_CTX`.
#[derive(Clone, Copy)]
enum Hmac {
    Mac(*mut EVP_MAC_CTX),
    Legacy(*mut HMAC_CTX),
}

impl Hmac {
    /// `ssl_hmac_new`, or `None`.
    ///
    /// # Safety
    /// The callbacks' library context is NULL or live; the query NULL or a string.
    unsafe fn new(cbs: &Callbacks) -> Option<Self> {
        if cbs.evp.is_none() && cbs.legacy.is_some() {
            // SAFETY: no preconditions.
            let h = unsafe { HMAC_CTX_new() };
            return (!h.is_null()).then_some(Self::Legacy(h));
        }
        // SAFETY: the caller's guarantee; a NUL-terminated name.
        let mac = unsafe { EVP_MAC_fetch(cbs.libctx, c"HMAC".as_ptr(), cbs.propq) };
        if mac.is_null() {
            return None;
        }
        // SAFETY: the method fetched above.
        let ctx = unsafe { EVP_MAC_CTX_new(mac) };
        // SAFETY: our reference (the context holds its own).
        unsafe { EVP_MAC_free(mac) };
        (!ctx.is_null()).then_some(Self::Mac(ctx))
    }

    /// `ssl_hmac_size`.
    fn size(&self) -> usize {
        match *self {
            // SAFETY: our live context.
            Self::Mac(c) => unsafe { EVP_MAC_CTX_get_mac_size(c) },
            // SAFETY: as above.
            Self::Legacy(h) => unsafe { HMAC_size(h) },
        }
    }

    /// `ssl_hmac_update` and `ssl_hmac_final`: the MAC of `data`, or `None`.
    fn mac(&self, data: &[u8]) -> Option<Vec<u8>> {
        let mut out = vec![0u8; usize::try_from(EVP_MAX_MD_SIZE).ok()?];
        let len = match *self {
            Self::Mac(c) => {
                let mut len = 0usize;
                // SAFETY: our live context; the octets.
                if unsafe { EVP_MAC_update(c, data.as_ptr(), data.len()) } <= 0
                    // SAFETY: as above; the room for the MAC.
                    || unsafe { EVP_MAC_final(c, out.as_mut_ptr(), &raw mut len, out.len()) } <= 0
                {
                    return None;
                }
                len
            }
            Self::Legacy(h) => {
                let mut len: c_uint = 0;
                // SAFETY: as above.
                if unsafe { HMAC_Update(h, data.as_ptr(), data.len()) } <= 0
                    // SAFETY: as above; `EVP_MAX_MD_SIZE` octets of room.
                    || unsafe { HMAC_Final(h, out.as_mut_ptr(), &raw mut len) } <= 0
                {
                    return None;
                }
                usize::try_from(len).ok()?
            }
        };
        out.truncate(len);
        Some(out)
    }

    /// Calls the application's callback with the name, the IV and the contexts.
    ///
    /// # Safety
    /// `name` has `TLSEXT_KEYNAME_LENGTH` ([`TICK_KEY_NAME_LEN`]) octets and `iv` `EVP_MAX_IV_LENGTH`; no lock is held.
    unsafe fn call(
        &self,
        cbs: &Callbacks,
        s: *mut SSL,
        name: *mut c_uchar,
        iv: *mut c_uchar,
        ctx: *mut EVP_CIPHER_CTX,
        enc: c_int,
    ) -> c_int {
        match (*self, cbs.evp, cbs.legacy) {
            // SAFETY: the application's callback, with the caller's buffers and our contexts.
            (Self::Mac(h), Some(cb), _) => unsafe { cb(s, name, iv, ctx, h, enc) },
            (Self::Legacy(h), None, Some(cb)) => {
                // SAFETY: the deprecated callback's real type, as it was stored.
                let cb: LegacyCb = unsafe { core::mem::transmute(cb) };
                // SAFETY: as above.
                unsafe { cb(s, name, iv, ctx, h, enc) }
            }
            _ => FATAL,
        }
    }
}

/// The contexts of one ticket, freed when dropped.
struct Contexts {
    cipher: *mut EVP_CIPHER_CTX,
    hmac: Option<Hmac>,
}

impl Drop for Contexts {
    fn drop(&mut self) {
        // SAFETY: ours, or NULL.
        unsafe { EVP_CIPHER_CTX_free(self.cipher) };
        match self.hmac {
            // SAFETY: ours.
            Some(Hmac::Mac(c)) => unsafe { EVP_MAC_CTX_free(c) },
            // SAFETY: ours.
            Some(Hmac::Legacy(h)) => unsafe { HMAC_CTX_free(h) },
            None => {}
        }
    }
}

/// A buffer's length as OpenSSL's `int` lengths take it.
fn int_len(n: usize) -> Option<c_int> {
    c_int::try_from(n).ok()
}

/// Answers [`rustyssl_tls::conn::Request::TicketKey`]: runs the callback, then has its
/// contexts open `ticket` (decrypting) or seal `session` (encrypting).
///
/// # Safety
/// `s` is the live connection behind `x`; no lock is held.
pub(crate) unsafe fn answer(
    s: *mut SSL,
    x: &Ssl,
    ticket: &[u8],
    session: &Secret,
    encrypt: bool,
) -> Answer {
    let fatal = Answer::TicketKey {
        ret: FATAL,
        data: None,
    };
    let Some(cbs) = callbacks(x) else {
        return fatal;
    };
    let mut cx = Contexts {
        // SAFETY: no preconditions.
        cipher: unsafe { EVP_CIPHER_CTX_new() },
        hmac: None,
    };
    // SAFETY: the session context's library context and query.
    cx.hmac = unsafe { Hmac::new(&cbs) };
    let Some(hmac) = cx.hmac else {
        return fatal;
    };
    if cx.cipher.is_null() {
        return fatal;
    }
    if encrypt {
        // SAFETY: the caller's guarantee.
        unsafe { seal(&cbs, s, &cx, hmac, session) }
    } else {
        // SAFETY: as above.
        unsafe { open(&cbs, s, &cx, hmac, ticket) }
    }
}

/// `tls_decrypt_ticket` with the callback's contexts.
///
/// # Safety
/// As for [`answer`].
unsafe fn open(cbs: &Callbacks, s: *mut SSL, cx: &Contexts, hmac: Hmac, ticket: &[u8]) -> Answer {
    let fatal = Answer::TicketKey {
        ret: FATAL,
        data: None,
    };
    let name_len = TICK_KEY_NAME_LEN;
    let Ok(iv_room) = usize::try_from(EVP_MAX_IV_LENGTH) else {
        return fatal;
    };
    // The callback gets the ticket's own key name and IV (a copy it may write to).
    let mut nctick = ticket.to_vec();
    if nctick.len() < name_len.saturating_add(iv_room) {
        return Answer::TicketKey { ret: 0, data: None };
    }
    let name = nctick.as_mut_ptr();
    let iv = name.wrapping_add(name_len);
    // SAFETY: the key name and the `EVP_MAX_IV_LENGTH` octets after it are in the copy; no
    // lock is held.
    let rv = unsafe { hmac.call(cbs, s, name, iv, cx.cipher, 0) };
    if rv <= 0 {
        return Answer::TicketKey {
            ret: rv,
            data: None,
        };
    }
    let no_decrypt = Answer::TicketKey {
        ret: rv,
        data: None,
    };
    let mlen = hmac.size();
    // SAFETY: our context, set up by the callback.
    let Ok(ivlen) = usize::try_from(unsafe { EVP_CIPHER_CTX_get_iv_length(cx.cipher) }) else {
        return fatal;
    };
    if mlen == 0 {
        return fatal;
    }
    let header = name_len.saturating_add(ivlen);
    if ticket.len() <= header.saturating_add(mlen) {
        return no_decrypt;
    }
    let body_len = ticket.len().saturating_sub(mlen);
    let (Some(signed), Some(tag)) = (ticket.get(..body_len), ticket.get(body_len..)) else {
        return no_decrypt;
    };
    let Some(want) = hmac.mac(signed) else {
        return fatal;
    };
    // `CRYPTO_memcmp`: in constant time.
    if want.len() != mlen || !bool::from(crate::dit::with(|| want.as_slice().ct_eq(tag))) {
        return no_decrypt;
    }
    let Some(enc) = signed.get(header..) else {
        return no_decrypt;
    };
    let Some(inl) = int_len(enc.len()) else {
        return fatal;
    };
    let block = usize::try_from(EVP_MAX_BLOCK_LENGTH).unwrap_or(32);
    let mut buf = vec![0u8; enc.len().saturating_add(block)];
    let mut len: c_int = 0;
    // SAFETY: our context; room for the input and a block; the octets.
    if unsafe { EVP_DecryptUpdate(cx.cipher, buf.as_mut_ptr(), &raw mut len, enc.as_ptr(), inl) }
        <= 0
    {
        // Erased when dropped.
        drop(Secret::new(buf));
        return fatal;
    }
    let Some(done) = usize::try_from(len).ok().filter(|&d| d <= buf.len()) else {
        drop(Secret::new(buf));
        return fatal;
    };
    let mut fin: c_int = 0;
    // SAFETY: as above; the room after what was written.
    let ok = unsafe {
        EVP_DecryptFinal_ex(cx.cipher, buf.as_mut_ptr().wrapping_add(done), &raw mut fin)
    } > 0;
    let total = usize::try_from(fin).map_or(done, |f| done.saturating_add(f));
    buf.truncate(total.min(buf.len()));
    let plain = Secret::new(buf);
    if !ok {
        return no_decrypt;
    }
    Answer::TicketKey {
        ret: rv,
        data: Some(plain),
    }
}

/// `construct_stateless_ticket` with the callback's contexts: key name, IV, encrypted session,
/// HMAC.
///
/// # Safety
/// As for [`answer`].
unsafe fn seal(
    cbs: &Callbacks,
    s: *mut SSL,
    cx: &Contexts,
    hmac: Hmac,
    session: &Secret,
) -> Answer {
    let failed = |ret| Answer::TicketKey { ret, data: None };
    let name_len = TICK_KEY_NAME_LEN;
    let Ok(iv_room) = usize::try_from(EVP_MAX_IV_LENGTH) else {
        return failed(FATAL);
    };
    let mut name = vec![0u8; name_len];
    let mut iv = vec![0u8; iv_room];
    // SAFETY: buffers of the sizes the callback writes; no lock is held.
    let rv = unsafe { hmac.call(cbs, s, name.as_mut_ptr(), iv.as_mut_ptr(), cx.cipher, 1) };
    if rv <= 0 {
        return failed(rv);
    }
    // From here a failure is the contexts' (an internal error, not the callback's).
    // SAFETY: our context, set up by the callback.
    let Ok(ivlen) = usize::try_from(unsafe { EVP_CIPHER_CTX_get_iv_length(cx.cipher) }) else {
        return failed(rv);
    };
    let Some(iv) = iv.get(..ivlen) else {
        return failed(rv);
    };
    let senc = session.bytes();
    let Some(inl) = int_len(senc.len()) else {
        return failed(rv);
    };
    let block = usize::try_from(EVP_MAX_BLOCK_LENGTH).unwrap_or(32);
    let mut enc = vec![0u8; senc.len().saturating_add(block)];
    let mut len: c_int = 0;
    // SAFETY: our context; room for the input and a block; the session's octets.
    if unsafe {
        EVP_EncryptUpdate(
            cx.cipher,
            enc.as_mut_ptr(),
            &raw mut len,
            senc.as_ptr(),
            inl,
        )
    } <= 0
    {
        return failed(rv);
    }
    let Ok(done) = usize::try_from(len) else {
        return failed(rv);
    };
    let mut fin: c_int = 0;
    // SAFETY: as above; the room after what was written.
    if unsafe { EVP_EncryptFinal_ex(cx.cipher, enc.as_mut_ptr().wrapping_add(done), &raw mut fin) }
        <= 0
    {
        return failed(rv);
    }
    let Some(total) = usize::try_from(fin).ok().map(|f| done.saturating_add(f)) else {
        return failed(rv);
    };
    if total > enc.len() {
        return failed(rv);
    }
    enc.truncate(total);
    let mut out = name;
    out.extend_from_slice(iv);
    out.extend_from_slice(&enc);
    let Some(mac) = hmac.mac(&out) else {
        return failed(rv);
    };
    out.extend_from_slice(&mac);
    Answer::TicketKey {
        ret: rv,
        data: Some(Secret::new(out)),
    }
}
