//! SRP over TLS 1.2 (`tls_srp.c`): a connection's SRP state (`s->srp_ctx`), copied from its
//! context's settings when it's made, the exports that read and set it, and the answers to the
//! core's SRP requests, which run the SRP callbacks with no lock held and make the numbers with
//! libcrypto's SRP functions.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use std::ffi::{CStr, CString};

use rustyssl_abi::{
    BIGNUM, OSSL_LIB_CTX, SRP_MINIMAL_N, SSL, SSL_AD_INTERNAL_ERROR, SSL_AD_UNKNOWN_PSK_IDENTITY,
    SSL_CTX, SSL_ERROR_NONE, SSL_MAX_MASTER_KEY_LENGTH, SSL_R_CALLBACK_FAILED, SSL_X509_LOOKUP,
    SSL3_AL_FATAL,
};
use rustyssl_tls::conn::{Answer, SrpParams};

use super::conn::{self, Ssl};
use super::ctx::{self, Srp};
use super::io::config::CtxSnapshot;
use super::types::{SrpClientPwdCb, SrpUsernameCb, SrpVerifyParamCb};
use crate::bn::conv::{BN_bin2bn, BN_bn2bin};
use crate::bn::{BN_clear_free, BN_copy, BN_dup, BN_free, BN_num_bits};
use crate::ffi::ffi_export;
use crate::srp::{
    SRP_Calc_A, SRP_Calc_B_ex, SRP_Calc_client_key_ex, SRP_Calc_server_key, SRP_Calc_u_ex,
    SRP_Calc_x_ex, SRP_Verify_A_mod_N, SRP_Verify_B_mod_N, SRP_check_known_gN_param,
    SRP_create_verifier_BN_ex, SRP_get_default_gN,
};

/// A connection's SRP state (`SRP_CTX`): the numbers are owned (freed, cleared, with it).
#[derive(Debug)]
pub(crate) struct ConnSrp {
    /// The login: a client's own, a server's the client sent.
    pub(crate) login: Option<CString>,
    /// The password (client) or the user's information (server).
    pub(crate) info: Option<CString>,
    n: *mut BIGNUM,
    g: *mut BIGNUM,
    s: *mut BIGNUM,
    v: *mut BIGNUM,
    big_b: *mut BIGNUM,
    b: *mut BIGNUM,
    big_a: *mut BIGNUM,
    a: *mut BIGNUM,
    /// The minimum size of N in bits.
    pub(crate) strength: c_int,
    cb_arg: *mut c_void,
    username_cb: SrpUsernameCb,
    verify_param_cb: SrpVerifyParamCb,
    give_client_pwd_cb: SrpClientPwdCb,
    /// Whether the password callback is the built-in one giving `info`.
    pwd_from_info: bool,
    /// `srp_Mask & SSL_kSRP`: SRP suites are usable.
    pub(crate) enabled: bool,
}

impl Default for ConnSrp {
    /// `ssl_srp_ctx_free_intern`'s state: nothing set, the minimal strength.
    fn default() -> Self {
        Self {
            login: None,
            info: None,
            n: ptr::null_mut(),
            g: ptr::null_mut(),
            s: ptr::null_mut(),
            v: ptr::null_mut(),
            big_b: ptr::null_mut(),
            b: ptr::null_mut(),
            big_a: ptr::null_mut(),
            a: ptr::null_mut(),
            strength: SRP_MINIMAL_N,
            cb_arg: ptr::null_mut(),
            username_cb: None,
            verify_param_cb: None,
            give_client_pwd_cb: None,
            pwd_from_info: false,
            enabled: false,
        }
    }
}

impl Drop for ConnSrp {
    fn drop(&mut self) {
        for bn in [
            self.n, self.g, self.s, self.v, self.big_b, self.b, self.big_a, self.a,
        ] {
            // SAFETY: ours, or NULL.
            unsafe { BN_clear_free(bn) };
        }
    }
}

/// Replaces an owned number, freeing (and clearing) the old one.
///
/// # Safety
/// `*slot` is NULL or ours; `new` is NULL or a number given to the slot.
unsafe fn put(slot: &mut *mut BIGNUM, new: *mut BIGNUM) {
    // SAFETY: the caller's guarantee.
    unsafe { BN_clear_free(*slot) };
    *slot = new;
}

/// `BN_copy` into an owned number, or `BN_dup` when there's none: `SSL_set_srp_server_param`'s
/// way (a failed copy leaves none).
///
/// # Safety
/// `*slot` is NULL or ours; `from` is a live number.
unsafe fn set_copy(slot: &mut *mut BIGNUM, from: *const BIGNUM) {
    if slot.is_null() {
        // SAFETY: the caller's number.
        *slot = unsafe { BN_dup(from) };
    // SAFETY: ours; the caller's number.
    } else if unsafe { BN_copy(*slot, from) }.is_null() {
        // SAFETY: ours.
        unsafe { BN_free(*slot) };
        *slot = ptr::null_mut();
    }
}

/// A number's octets (`BN_bn2bin`), `None` for NULL.
///
/// # Safety
/// `bn` is NULL or a live number.
unsafe fn octets(bn: *const BIGNUM) -> Option<Vec<u8>> {
    if bn.is_null() {
        return None;
    }
    // SAFETY: the caller's number.
    let bits = unsafe { BN_num_bits(bn) };
    let mut out = vec![0u8; usize::try_from(bits).ok()?.div_ceil(8)];
    // SAFETY: as above; room for its octets.
    let n = unsafe { BN_bn2bin(bn, out.as_mut_ptr()) };
    (usize::try_from(n).ok() == Some(out.len())).then_some(out)
}

/// A number from octets (`BN_bin2bn`), NULL on failure.
fn number(b: &[u8]) -> *mut BIGNUM {
    let Ok(len) = c_int::try_from(b.len()) else {
        return ptr::null_mut();
    };
    // SAFETY: `len` octets at `b`; a new number.
    unsafe { BN_bin2bn(b.as_ptr(), len, ptr::null_mut()) }
}

impl ConnSrp {
    /// Whether a username callback is set (a server asks for it after choosing a suite).
    pub(crate) const fn username_cb_set(&self) -> bool {
        self.username_cb.is_some()
    }

    /// `ssl_srp_ctx_init_intern`: the context's callbacks, strength, login, password and
    /// mask (the context holds no numbers).
    pub(crate) fn from_ctx(c: &Srp) -> Self {
        Self {
            login: c.login.clone(),
            info: c.info.clone(),
            strength: c.strength,
            cb_arg: c.cb_arg,
            username_cb: c.username_cb,
            verify_param_cb: c.verify_param_cb,
            give_client_pwd_cb: c.give_client_pwd_cb,
            pwd_from_info: c.pwd_from_info,
            enabled: c.enabled,
            ..Self::default()
        }
    }
}

/// The library context and property query of the connection's context.
///
/// # Safety
/// `x` is a live connection.
unsafe fn lib_of(x: &Ssl) -> (*mut OSSL_LIB_CTX, Option<CString>) {
    let st = x.state();
    // SAFETY: the connection's state; its reference keeps the context alive.
    let Some(c) = (unsafe { conn::ctx_of(&st) }) else {
        return (ptr::null_mut(), None);
    };
    drop(st);
    (c.libctx, c.propq.clone())
}

/// A property query's pointer (NULL for none).
fn pq(p: Option<&CString>) -> *const c_char {
    p.map_or(ptr::null(), |q| q.as_ptr())
}

/// `ssl_srp_server_param_with_username_intern`: the username callback (its result when not
/// `SSL_ERROR_NONE`, `*ad` starting as unknown-psk-identity), then B from a random b and the
/// user's N, g and verifier (`SSL3_AL_FATAL` with internal-error when one is missing).
///
/// # Safety
/// `s` is the live connection behind `x`; no lock is held.
unsafe fn server_param_with_username(
    s: *mut SSL,
    x: &Ssl,
    ad: &mut c_int,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> c_int {
    *ad = SSL_AD_UNKNOWN_PSK_IDENTITY;
    let (cb, arg) = {
        let st = x.state();
        (st.srp.username_cb, st.srp.cb_arg)
    };
    if let Some(cb) = cb {
        // SAFETY: the application's callback with its connection; no lock is held.
        let al = unsafe { cb(s, ad, arg) };
        if al != SSL_ERROR_NONE {
            return al;
        }
    }
    *ad = SSL_AD_INTERNAL_ERROR;
    let mut st = x.state();
    let srp = &mut st.srp;
    if srp.n.is_null() || srp.g.is_null() || srp.s.is_null() || srp.v.is_null() {
        return SSL3_AL_FATAL;
    }
    let mut rnd =
        rustyssl_crypto::bn::Zeroizing::new(vec![
            0u8;
            usize::try_from(SSL_MAX_MASTER_KEY_LENGTH)
                .unwrap_or(48)
        ]);
    // SAFETY: room for the octets; the library context.
    if unsafe { crate::rand_lib::RAND_priv_bytes_ex(libctx, rnd.as_mut_ptr(), rnd.len(), 0) } <= 0 {
        return SSL3_AL_FATAL;
    }
    // SAFETY: ours, or NULL; a new number.
    unsafe { put(&mut srp.b, number(&rnd)) };
    // SAFETY: our numbers (b may be NULL, which fails); the library context and query.
    let big_b = unsafe { SRP_Calc_B_ex(srp.b, srp.n, srp.g, srp.v, libctx, propq) };
    // SAFETY: ours, or NULL; the new number.
    unsafe { put(&mut srp.big_b, big_b) };
    if big_b.is_null() {
        SSL3_AL_FATAL
    } else {
        SSL_ERROR_NONE
    }
}

/// [`rustyssl_tls::conn::Request::SrpUsername`]: the login becomes the connection's, then
/// [`server_param_with_username`]; a negative result waits (`SSL_ERROR_WANT_X509_LOOKUP`).
///
/// # Safety
/// `s` is the live connection behind `x`; no lock is held.
pub(crate) unsafe fn username(
    s: *mut SSL,
    x: &Ssl,
    snap: Option<&CtxSnapshot>,
    login: &[u8],
) -> Option<Answer> {
    x.state().srp.login = CString::new(login).ok();
    let (libctx, propq) = snap.map_or((ptr::null_mut(), ptr::null()), |c| (c.libctx, c.propq()));
    let mut alert = SSL_AD_INTERNAL_ERROR;
    // SAFETY: the caller's guarantee.
    let ret = unsafe { server_param_with_username(s, x, &mut alert, libctx, propq) };
    if ret < 0 {
        x.state().rwstate = SSL_X509_LOOKUP;
        return None;
    }
    Some(Answer::SrpUsername { ret, alert })
}

/// [`rustyssl_tls::conn::Request::SrpServerParams`]: N, g, the salt and B, or none when one
/// is missing.
pub(crate) fn server_params(x: &Ssl) -> Answer {
    let st = x.state();
    let srp = &st.srp;
    // SAFETY: our numbers, or NULL (each).
    let [n, g, salt, b] = [srp.n, srp.g, srp.s, srp.big_b].map(|bn| unsafe { octets(bn) });
    let p = (|| {
        Some(SrpParams {
            n: n?,
            g: g?,
            s: salt?,
            b: b?,
        })
    })();
    Answer::SrpParams(p)
}

/// A secret number's octets, the number cleared and freed.
///
/// # Safety
/// `k` is NULL or a number of ours.
unsafe fn take_secret(k: *mut BIGNUM) -> Option<Vec<u8>> {
    // SAFETY: the caller's guarantee.
    let out = unsafe { octets(k) };
    // SAFETY: as above.
    unsafe { BN_clear_free(k) };
    out
}

/// [`rustyssl_tls::conn::Request::SrpServerSecret`] (`srp_generate_server_master_secret`):
/// the client's A becomes the connection's; the premaster secret is
/// `(A * v^u) ^ b % N`.
pub(crate) fn server_secret(x: &Ssl, snap: Option<&CtxSnapshot>, a: &[u8]) -> Answer {
    let (libctx, propq) = snap.map_or((ptr::null_mut(), ptr::null()), |c| (c.libctx, c.propq()));
    let mut st = x.state();
    let srp = &mut st.srp;
    // SAFETY: ours, or NULL; a new number.
    unsafe { put(&mut srp.big_a, number(a)) };
    // SAFETY: our numbers (NULL ones fail).
    if unsafe { SRP_Verify_A_mod_N(srp.big_a, srp.n) } == 0 {
        return Answer::SrpValue(None);
    }
    // SAFETY: as above; the library context and query.
    let u = unsafe { SRP_Calc_u_ex(srp.big_a, srp.big_b, srp.n, libctx, propq) };
    if u.is_null() {
        return Answer::SrpValue(None);
    }
    // SAFETY: as above.
    let k = unsafe { SRP_Calc_server_key(srp.big_a, srp.v, u, srp.b, srp.n) };
    // SAFETY: made above.
    unsafe { BN_clear_free(u) };
    // SAFETY: made above, or NULL.
    Answer::SrpValue(unsafe { take_secret(k) })
}

/// [`rustyssl_tls::conn::Request::SrpVerifyParams`]: the server's numbers become the
/// connection's, then the verify-parameter callback (with no lock held) or the known groups
/// decide.
///
/// # Safety
/// `s` is the live connection behind `x`; no lock is held.
pub(crate) unsafe fn verify_params(s: *mut SSL, x: &Ssl, p: &SrpParams) -> Answer {
    let (cb, arg) = {
        let mut st = x.state();
        let srp = &mut st.srp;
        for (slot, value) in [
            (&mut srp.n, &p.n),
            (&mut srp.g, &p.g),
            (&mut srp.s, &p.s),
            (&mut srp.big_b, &p.b),
        ] {
            // SAFETY: ours, or NULL; a new number.
            unsafe { put(slot, number(value)) };
        }
        (srp.verify_param_cb, srp.cb_arg)
    };
    if let Some(cb) = cb {
        // SAFETY: the application's callback with its connection; no lock is held.
        let ok = unsafe { cb(s, arg) } > 0;
        return Answer::SrpVerified(c_int::from(ok));
    }
    let st = x.state();
    // SAFETY: our numbers, or NULL (an unknown group).
    let known = unsafe { SRP_check_known_gN_param(st.srp.g, st.srp.n) };
    Answer::SrpVerified(if known.is_null() { -1 } else { 1 })
}

/// `ssl_srp_calc_a_param_intern`: a random a, and A = g^a % N.
///
/// # Safety
/// `x` is a live connection; `libctx` is NULL or live.
unsafe fn calc_a(x: &Ssl, libctx: *mut OSSL_LIB_CTX) -> bool {
    let mut rnd =
        rustyssl_crypto::bn::Zeroizing::new(vec![
            0u8;
            usize::try_from(SSL_MAX_MASTER_KEY_LENGTH)
                .unwrap_or(48)
        ]);
    // SAFETY: room for the octets; the library context.
    if unsafe { crate::rand_lib::RAND_priv_bytes_ex(libctx, rnd.as_mut_ptr(), rnd.len(), 0) } <= 0 {
        return false;
    }
    let mut st = x.state();
    let srp = &mut st.srp;
    let Ok(len) = c_int::try_from(rnd.len()) else {
        return false;
    };
    // SAFETY: the octets; a, reused when there is one (as `BN_bin2bn(.., a)` does).
    let a = unsafe { BN_bin2bn(rnd.as_ptr(), len, srp.a) };
    if a.is_null() {
        return false;
    }
    srp.a = a;
    // SAFETY: our numbers (NULL ones fail).
    let big_a = unsafe { SRP_Calc_A(srp.a, srp.n, srp.g) };
    if big_a.is_null() {
        return false;
    }
    // SAFETY: ours, or NULL; the new number.
    unsafe { put(&mut srp.big_a, big_a) };
    true
}

/// [`rustyssl_tls::conn::Request::SrpClientA`]: A, made now.
///
/// # Safety
/// `x` is a live connection.
pub(crate) unsafe fn client_a(x: &Ssl, snap: Option<&CtxSnapshot>) -> Answer {
    let libctx = snap.map_or(ptr::null_mut(), |c| c.libctx);
    // SAFETY: the caller's guarantee.
    if !unsafe { calc_a(x, libctx) } {
        return Answer::SrpValue(None);
    }
    // SAFETY: our number.
    Answer::SrpValue(unsafe { octets(x.state().srp.big_a) })
}

/// [`rustyssl_tls::conn::Request::SrpClientSecret`] (`srp_generate_client_master_secret`): B
/// checked, u, the password (the callback's, with no lock held, cleared and freed after; or
/// the one set), x from the salt, login and password, and the premaster secret
/// `(B - k * g^x) ^ (a + u * x) % N`. No password is `SSL_R_CALLBACK_FAILED`.
///
/// # Safety
/// `s` is the live connection behind `x`; no lock is held.
pub(crate) unsafe fn client_secret(s: *mut SSL, x: &Ssl, snap: Option<&CtxSnapshot>) -> Answer {
    let (libctx, propq) = snap.map_or((ptr::null_mut(), ptr::null()), |c| (c.libctx, c.propq()));
    let (u, cb, from_info, arg) = {
        let st = x.state();
        let srp = &st.srp;
        // SAFETY: our numbers (NULL ones fail).
        if unsafe { SRP_Verify_B_mod_N(srp.big_b, srp.n) } == 0 {
            return Answer::SrpValue(None);
        }
        // SAFETY: as above; the library context and query.
        let u = unsafe { SRP_Calc_u_ex(srp.big_a, srp.big_b, srp.n, libctx, propq) };
        (u, srp.give_client_pwd_cb, srp.pwd_from_info, srp.cb_arg)
    };
    if u.is_null() || (cb.is_none() && !from_info) {
        // SAFETY: made above, or NULL.
        unsafe { BN_clear_free(u) };
        return Answer::SrpValue(None);
    }
    // The password: the callback's (C memory, ours to clear and free), or the one set.
    let pwd = if let Some(cb) = cb {
        // SAFETY: the application's callback with its connection; no lock is held.
        unsafe { cb(s, arg) }
    } else {
        // `srp_password_from_info_cb`: a copy of the password set.
        let st = x.state();
        let p = st.srp.info.as_ref().map_or(ptr::null(), |i| i.as_ptr());
        // SAFETY: NULL or our string.
        unsafe { dup(p) }
    };
    if pwd.is_null() {
        // SAFETY: made above.
        unsafe { BN_clear_free(u) };
        return Answer::Fail {
            alert: u8::try_from(SSL_AD_INTERNAL_ERROR).ok(),
            reason: SSL_R_CALLBACK_FAILED,
        };
    }
    let k = {
        let st = x.state();
        let srp = &st.srp;
        let login = srp.login.as_ref().map_or(ptr::null(), |l| l.as_ptr());
        // SAFETY: our numbers and login (NULL fails); the password; the library context.
        let xx = unsafe { SRP_Calc_x_ex(srp.s, login, pwd, libctx, propq) };
        let k = if xx.is_null() {
            ptr::null_mut()
        } else {
            // SAFETY: as above.
            unsafe { SRP_Calc_client_key_ex(srp.n, srp.big_b, srp.g, xx, srp.a, u, libctx, propq) }
        };
        // SAFETY: made above, or NULL.
        unsafe { BN_clear_free(xx) };
        k
    };
    // SAFETY: made above.
    unsafe { BN_clear_free(u) };
    // SAFETY: the password's NUL-terminated C memory, ours now.
    let len = unsafe { CStr::from_ptr(pwd) }.count_bytes();
    // SAFETY: as above, freed once.
    unsafe { crate::mem::CRYPTO_clear_free(pwd.cast(), len, c"ssl/tls_srp.c".as_ptr(), 0) };
    // SAFETY: made above, or NULL.
    Answer::SrpValue(unsafe { take_secret(k) })
}

/// `OPENSSL_strdup` (NULL for NULL).
///
/// # Safety
/// `p` is NULL or a NUL-terminated string.
unsafe fn dup(p: *const c_char) -> *mut c_char {
    if p.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the caller's string.
    unsafe { crate::string::CRYPTO_strdup(p, c"ssl/tls_srp.c".as_ptr(), 0) }
}

ffi_export! {
    /// `SSL_CTX_SRP_CTX_init`: the context's SRP settings cleared (the minimal strength).
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_SRP_CTX_init(c: *mut SSL_CTX) -> c_int
    where failure = 0, library = rustyssl_abi::ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ctx::ctx(c) }) else { return 0 };
        x.state().srp = Srp::default();
        1
    }
}

ffi_export! {
    /// `SSL_CTX_SRP_CTX_free`: as [`rustyssl_private_SSL_CTX_SRP_CTX_init`].
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_SRP_CTX_free(c: *mut SSL_CTX) -> c_int
    where failure = 0, library = rustyssl_abi::ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ctx::ctx(c) }) else { return 0 };
        x.state().srp = Srp::default();
        1
    }
}

ffi_export! {
    /// `SSL_SRP_CTX_init`: the connection's SRP state again from its context's settings.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_SRP_CTX_init(s: *mut SSL) -> c_int
    where failure = 0, library = rustyssl_abi::ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { conn::ssl(s) }) else { return 0 };
        let st = x.state();
        // SAFETY: the connection's state; its reference keeps the context alive.
        let Some(c) = (unsafe { conn::ctx_of(&st) }) else { return 0 };
        drop(st);
        let fresh = ConnSrp::from_ctx(&c.state().srp);
        // The old numbers are freed with no lock held.
        let old = core::mem::replace(&mut x.state().srp, fresh);
        drop(old);
        1
    }
}

ffi_export! {
    /// `SSL_SRP_CTX_free`: the connection's SRP state cleared (the minimal strength).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_SRP_CTX_free(s: *mut SSL) -> c_int
    where failure = 0, library = rustyssl_abi::ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { conn::ssl(s) }) else { return 0 };
        let old = core::mem::take(&mut x.state().srp);
        drop(old);
        1
    }
}

ffi_export! {
    /// `SSL_srp_server_param_with_username`: the username callback, then B
    /// (`SSL_ERROR_NONE`, `SSL3_AL_FATAL` with `*ad`, or the callback's result).
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `ad` a writable `int`.
    pub unsafe extern "C" fn rustyssl_private_SSL_srp_server_param_with_username(s: *mut SSL, ad: *mut c_int) -> c_int
    where failure = SSL3_AL_FATAL, library = rustyssl_abi::ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { conn::ssl(s) }) else { return SSL3_AL_FATAL };
        // SAFETY: as above.
        let (libctx, propq) = unsafe { lib_of(x) };
        let mut al = 0;
        // SAFETY: as above; no lock is held.
        let r = unsafe { server_param_with_username(s, x, &mut al, libctx, pq(propq.as_ref())) };
        if !ad.is_null() {
            // SAFETY: the caller's `int`.
            unsafe { ad.write(al) };
        }
        r
    }
}

ffi_export! {
    /// `SSL_set_srp_server_param_pw`: the server's N and g from the named group (the
    /// default, 1024 bits, for NULL), and a new salt and verifier for `user` and `pass`.
    /// 1, or -1.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; the strings NULL or NUL-terminated.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_srp_server_param_pw(s: *mut SSL, user: *const c_char, pass: *const c_char, grp: *const c_char) -> c_int
    where failure = -1, library = rustyssl_abi::ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { conn::ssl(s) }) else { return -1 };
        // SAFETY: the caller's string, or NULL.
        let gn = unsafe { SRP_get_default_gN(grp) };
        if gn.is_null() {
            return -1;
        }
        // SAFETY: the library's static group.
        let gn = unsafe { &*gn };
        // SAFETY: as above.
        let (libctx, propq) = unsafe { lib_of(x) };
        let mut st = x.state();
        let srp = &mut st.srp;
        // SAFETY: the group's number.
        let (n, g) = (unsafe { BN_dup(gn.N) }, unsafe { BN_dup(gn.g) });
        for (slot, value) in [
            (&mut srp.n, n),
            (&mut srp.g, g),
            (&mut srp.v, ptr::null_mut()),
            (&mut srp.s, ptr::null_mut()),
        ] {
            // SAFETY: ours, or NULL; a number given to the slot, or NULL.
            unsafe { put(slot, value) };
        }
        // SAFETY: the caller's strings; our slots and numbers; the library context.
        let ok = unsafe {
            SRP_create_verifier_BN_ex(user, pass, &raw mut srp.s, &raw mut srp.v, srp.n, srp.g, libctx, pq(propq.as_ref()))
        };
        if ok == 0 { -1 } else { 1 }
    }
}

ffi_export! {
    /// `SSL_set_srp_server_param`: copies of whichever of N, g, the salt and the verifier are
    /// given, and the user's information; 1 when all four are set, else -1.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; the numbers NULL or live; `info` NULL or a
    /// NUL-terminated string.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_srp_server_param(s: *mut SSL, n: *const BIGNUM, g: *const BIGNUM, sa: *mut BIGNUM, v: *mut BIGNUM, info: *mut c_char) -> c_int
    where failure = -1, library = rustyssl_abi::ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { conn::ssl(s) }) else { return -1 };
        let mut st = x.state();
        let srp = &mut st.srp;
        for (slot, from) in [(&mut srp.n, n), (&mut srp.g, g), (&mut srp.s, sa.cast_const()), (&mut srp.v, v.cast_const())] {
            if !from.is_null() {
                // SAFETY: ours, or NULL; the caller's number.
                unsafe { set_copy(slot, from) };
            }
        }
        if !info.is_null() {
            // SAFETY: the caller's string.
            srp.info = Some(unsafe { CStr::from_ptr(info) }.to_owned());
        }
        if srp.n.is_null() || srp.g.is_null() || srp.s.is_null() || srp.v.is_null() {
            return -1;
        }
        1
    }
}

ffi_export! {
    /// `SRP_Calc_A_param`: a random a and the client's A from the connection's N and g; 1, or
    /// 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SRP_Calc_A_param(s: *mut SSL) -> c_int
    where failure = 0, library = rustyssl_abi::ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { conn::ssl(s) }) else { return 0 };
        // SAFETY: as above.
        let (libctx, _) = unsafe { lib_of(x) };
        // SAFETY: as above.
        c_int::from(unsafe { calc_a(x, libctx) })
    }
}

/// A connection's SRP value, or its context's when it has none.
///
/// # Safety
/// `s` is NULL or a live connection.
unsafe fn get<T>(
    s: *mut SSL,
    own: impl FnOnce(&ConnSrp) -> *mut T,
    ctx: impl FnOnce(&Srp) -> *mut T,
) -> *mut T {
    // SAFETY: the caller's guarantee.
    let Some(x) = (unsafe { conn::ssl(s) }) else {
        return ptr::null_mut();
    };
    let st = x.state();
    let p = own(&st.srp);
    if !p.is_null() {
        return p;
    }
    // SAFETY: the connection's state; its reference keeps the context alive.
    let Some(c) = (unsafe { conn::ctx_of(&st) }) else {
        return ptr::null_mut();
    };
    drop(st);
    ctx(&c.state().srp)
}

/// A string's pointer (NULL for none); it stays where it is while the string is kept.
fn str_ptr(s: Option<&CString>) -> *mut c_char {
    s.map_or(ptr::null_mut(), |s| s.as_ptr().cast_mut())
}

ffi_export! {
    /// `SSL_get_srp_g`: the connection's g (its context never has one).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_srp_g(s: *mut SSL) -> *mut BIGNUM
    where failure = ptr::null_mut(), library = rustyssl_abi::ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { get(s, |p| p.g, |_| ptr::null_mut()) }
    }
}

ffi_export! {
    /// `SSL_get_srp_N`: the connection's N (its context never has one).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_srp_N(s: *mut SSL) -> *mut BIGNUM
    where failure = ptr::null_mut(), library = rustyssl_abi::ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { get(s, |p| p.n, |_| ptr::null_mut()) }
    }
}

ffi_export! {
    /// `SSL_get_srp_username`: the connection's login, else its context's.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_srp_username(s: *mut SSL) -> *mut c_char
    where failure = ptr::null_mut(), library = rustyssl_abi::ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { get(s, |p| str_ptr(p.login.as_ref()), |c| str_ptr(c.login.as_ref())) }
    }
}

ffi_export! {
    /// `SSL_get_srp_userinfo`: the connection's user information (password), else its
    /// context's.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_srp_userinfo(s: *mut SSL) -> *mut c_char
    where failure = ptr::null_mut(), library = rustyssl_abi::ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { get(s, |p| str_ptr(p.info.as_ref()), |c| str_ptr(c.info.as_ref())) }
    }
}
