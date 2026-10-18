//! A session's encoding (OpenSSL's `ssl_asn1.c`: `i2d_SSL_SESSION`, `d2i_SSL_SESSION_ex`), its
//! PEM form (`PEM_STRING_SSL_SESSION`), and its text (`ssl_txt.c`: `SSL_SESSION_print`,
//! `SSL_SESSION_print_keylog`).
//!
//! The encoding is OpenSSL's `SSL_SESSION_ASN1` sequence, field for field (the same names,
//! tags, and embedded integers), through the template engine, so sessions written by either
//! library read on the other, and a decoding error names the same field.

use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_void};
use core::mem::offset_of;
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    ASN1_ITEM, ASN1_OCTET_STRING, ASN1_STRING, ASN1_TFLG_EMBED, ASN1_TFLG_EXPLICIT,
    ASN1_TFLG_IMPLICIT, ASN1_TFLG_OPTIONAL, ASN1_VALUE, BIO, BIO_NOCLOSE, DTLS1_BAD_VER,
    DTLS1_VERSION_MAJOR, ERR_LIB_SSL, EVP_PKEY, OSSL_LIB_CTX, PEM_STRING_SSL_SESSION,
    SSL_R_BAD_LENGTH, SSL_R_CIPHER_CODE_WRONG_LENGTH, SSL_R_UNKNOWN_SSL_VERSION,
    SSL_R_UNSUPPORTED_SSL_VERSION, SSL_SESSION, SSL_SESSION_ASN1_VERSION, SSL3_VERSION_MAJOR,
    TLS1_3_VERSION, V_ASN1_OCTET_STRING, X509, pem_password_cb,
};

use super::session::{
    self, MAX_MASTER_KEY, SESS_FLAG_EXTMS, SessData, from_time_t, max_id, max_sid_ctx, sess,
    time_now, to_time_t,
};
use crate::asn1::tpl::decode::ASN1_item_d2i;
use crate::asn1::tpl::encode::ASN1_item_i2d;
use crate::asn1::tpl::free::ASN1_item_free;
use crate::asn1::tpl::ints::{INT32_it, UINT32_it, ZINT32_it, ZINT64_it, ZUINT32_it, ZUINT64_it};
use crate::asn1::tpl::items::ASN1_OCTET_STRING_it;
use crate::asn1::tpl::statics::{Templates, sequence};
use crate::asn1::tpl::{Item, template_at};
use crate::bio::BIO_write;
use crate::bio::dump::BIO_dump_indent;
use crate::bio::file::BIO_new_fp;
use crate::err;
use crate::evp::pkey::EVP_PKEY_free;
use crate::ffi::ffi_export;
use crate::mem;
use crate::pem_cipher::{PEM_ASN1_write, PEM_ASN1_write_bio};
use crate::pem_read::{PEM_ASN1_read, PEM_ASN1_read_bio};
use crate::x509::cert::{X509_free, X509_it};
use crate::x509::ctx::X509_verify_cert_error_string;
use crate::x509::pubkey::{d2i_PUBKEY_ex, i2d_PUBKEY};

/// `SSL_SESSION_ASN1` (`ssl_asn1.c`), with its field names.
#[repr(C)]
#[allow(non_snake_case, reason = "OpenSSL's field names")]
struct SessAsn1 {
    version: u32,
    ssl_version: i32,
    cipher: *mut ASN1_OCTET_STRING,
    comp_id: *mut ASN1_OCTET_STRING,
    master_key: *mut ASN1_OCTET_STRING,
    session_id: *mut ASN1_OCTET_STRING,
    key_arg: *mut ASN1_OCTET_STRING,
    time: i64,
    timeout: i64,
    peer: *mut X509,
    session_id_context: *mut ASN1_OCTET_STRING,
    verify_result: i32,
    tlsext_hostname: *mut ASN1_OCTET_STRING,
    tlsext_tick_lifetime_hint: u64,
    tlsext_tick_age_add: u32,
    tlsext_tick: *mut ASN1_OCTET_STRING,
    psk_identity_hint: *mut ASN1_OCTET_STRING,
    psk_identity: *mut ASN1_OCTET_STRING,
    srp_username: *mut ASN1_OCTET_STRING,
    flags: u64,
    max_early_data: u32,
    alpn_selected: *mut ASN1_OCTET_STRING,
    tlsext_max_fragment_len_mode: u32,
    ticket_appdata: *mut ASN1_OCTET_STRING,
    kex_group: u32,
    peer_rpk: *mut ASN1_OCTET_STRING,
}

const SIMPLE: c_int = 0;
const EMBED: c_int = ASN1_TFLG_EMBED;
const IMP_OPT: c_int = ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL;
const EXP_OPT: c_int = ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL;
const EXP_OPT_EMBED: c_int = ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL | ASN1_TFLG_EMBED;

macro_rules! tt {
    ($($flags:expr, $tag:expr, $field:ident, $name:literal, $it:expr;)*) => {
        Templates([$(template_at($flags, $tag, offset_of!(SessAsn1, $field), $name, $it),)*])
    };
}

static SESS_TT: Templates<26> = tt![
    EMBED, 0, version, c"version", UINT32_it;
    EMBED, 0, ssl_version, c"ssl_version", INT32_it;
    SIMPLE, 0, cipher, c"cipher", ASN1_OCTET_STRING_it;
    SIMPLE, 0, session_id, c"session_id", ASN1_OCTET_STRING_it;
    SIMPLE, 0, master_key, c"master_key", ASN1_OCTET_STRING_it;
    IMP_OPT, 0, key_arg, c"key_arg", ASN1_OCTET_STRING_it;
    EXP_OPT_EMBED, 1, time, c"time", ZINT64_it;
    EXP_OPT_EMBED, 2, timeout, c"timeout", ZINT64_it;
    EXP_OPT, 3, peer, c"peer", X509_it;
    EXP_OPT, 4, session_id_context, c"session_id_context", ASN1_OCTET_STRING_it;
    EXP_OPT_EMBED, 5, verify_result, c"verify_result", ZINT32_it;
    EXP_OPT, 6, tlsext_hostname, c"tlsext_hostname", ASN1_OCTET_STRING_it;
    EXP_OPT, 7, psk_identity_hint, c"psk_identity_hint", ASN1_OCTET_STRING_it;
    EXP_OPT, 8, psk_identity, c"psk_identity", ASN1_OCTET_STRING_it;
    EXP_OPT_EMBED, 9, tlsext_tick_lifetime_hint, c"tlsext_tick_lifetime_hint", ZUINT64_it;
    EXP_OPT, 10, tlsext_tick, c"tlsext_tick", ASN1_OCTET_STRING_it;
    EXP_OPT, 11, comp_id, c"comp_id", ASN1_OCTET_STRING_it;
    EXP_OPT, 12, srp_username, c"srp_username", ASN1_OCTET_STRING_it;
    EXP_OPT_EMBED, 13, flags, c"flags", ZUINT64_it;
    EXP_OPT_EMBED, 14, tlsext_tick_age_add, c"tlsext_tick_age_add", ZUINT32_it;
    EXP_OPT_EMBED, 15, max_early_data, c"max_early_data", ZUINT32_it;
    EXP_OPT, 16, alpn_selected, c"alpn_selected", ASN1_OCTET_STRING_it;
    EXP_OPT_EMBED, 17, tlsext_max_fragment_len_mode, c"tlsext_max_fragment_len_mode", ZUINT32_it;
    EXP_OPT, 18, ticket_appdata, c"ticket_appdata", ASN1_OCTET_STRING_it;
    EXP_OPT_EMBED, 19, kex_group, c"kex_group", UINT32_it;
    EXP_OPT, 20, peer_rpk, c"peer_rpk", ASN1_OCTET_STRING_it;
];

/// The `SSL_SESSION_ASN1` item.
fn item() -> *const ASN1_ITEM {
    static ITEM: Item = sequence::<SessAsn1, 26>(&SESS_TT, None, c"SSL_SESSION_ASN1");
    &raw const ITEM.0
}

/// An OCTET STRING over borrowed octets (`ssl_session_oinit`), for encoding only.
fn octets(data: &[u8]) -> ASN1_STRING {
    ASN1_STRING {
        length: c_int::try_from(data.len()).unwrap_or(c_int::MAX),
        type_: V_ASN1_OCTET_STRING,
        data: data.as_ptr().cast_mut(),
        flags: 0,
    }
}

ffi_export! {
    /// Encodes the session (OpenSSL's `SSL_SESSION_ASN1`); 0 for NULL or a session with no
    /// cipher. As `i2d` does: the length, with the encoding at `*pp` (allocated when `*pp` is
    /// NULL, else written there and `*pp` advanced).
    ///
    /// # Safety
    /// `in_` is NULL or a live session; `pp` NULL or as for `i2d` functions.
    pub unsafe extern "C" fn rustyssl_private_i2d_SSL_SESSION(in_: *const SSL_SESSION, pp: *mut *mut c_uchar) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { sess(in_) }) else { return 0 };
        let d = x.data();
        if d.cipher.is_none() && d.cipher_id == 0 {
            return 0;
        }
        let l = d.cipher_id();
        let cipher_data = [((l >> 8) & 0xff) as u8, (l & 0xff) as u8];
        let mut cipher = octets(&cipher_data);
        let comp_data = [u8::try_from(d.compress_meth & 0xff).unwrap_or(0)];
        let mut comp_id = octets(&comp_data);
        let mut master_key = octets(d.master_key());
        let mut session_id = octets(d.id());
        let mut sid_ctx = octets(d.sid_ctx());
        let hostname_bytes: Vec<u8> = d.hostname.as_ref().map(|h| h.as_bytes().to_vec()).unwrap_or_default();
        let mut hostname = octets(&hostname_bytes);
        let mut tick = octets(d.tick.as_deref().unwrap_or_default());
        let hint_bytes: Vec<u8> = d.psk_identity_hint.as_ref().map(|h| h.as_bytes().to_vec()).unwrap_or_default();
        let mut hint = octets(&hint_bytes);
        let ident_bytes: Vec<u8> = d.psk_identity.as_ref().map(|h| h.as_bytes().to_vec()).unwrap_or_default();
        let mut ident = octets(&ident_bytes);
        let srp_bytes: Vec<u8> = d.srp_username.as_ref().map(|h| h.as_bytes().to_vec()).unwrap_or_default();
        let mut srp = octets(&srp_bytes);
        let mut alpn = octets(d.alpn_selected.as_deref().unwrap_or_default());
        let mut appdata = octets(d.ticket_appdata.as_deref().unwrap_or_default());
        // The raw public key as a SubjectPublicKeyInfo.
        let mut rpk_der: *mut c_uchar = ptr::null_mut();
        let mut rpk = ASN1_STRING { length: 0, type_: V_ASN1_OCTET_STRING, data: ptr::null_mut(), flags: 0 };
        if !d.peer_rpk.is_null() {
            // SAFETY: the session's key; the slot for its encoding.
            rpk.length = unsafe { i2d_PUBKEY(d.peer_rpk, &raw mut rpk_der) };
            rpk.data = rpk_der;
        }
        let some = |p: &mut ASN1_STRING| ptr::from_mut(p);
        let mut asn = SessAsn1 {
            version: u32::try_from(SSL_SESSION_ASN1_VERSION).unwrap_or(1),
            ssl_version: d.ssl_version,
            cipher: some(&mut cipher),
            comp_id: if d.compress_meth != 0 { some(&mut comp_id) } else { ptr::null_mut() },
            master_key: some(&mut master_key),
            session_id: some(&mut session_id),
            key_arg: ptr::null_mut(),
            time: to_time_t(d.time),
            timeout: to_time_t(d.timeout),
            peer: d.peer,
            session_id_context: some(&mut sid_ctx),
            verify_result: i32::try_from(d.verify_result).unwrap_or(i32::MAX),
            tlsext_hostname: if d.hostname.is_some() { some(&mut hostname) } else { ptr::null_mut() },
            tlsext_tick_lifetime_hint: d.tick_lifetime_hint,
            tlsext_tick_age_add: d.tick_age_add,
            tlsext_tick: if d.tick.is_some() { some(&mut tick) } else { ptr::null_mut() },
            psk_identity_hint: if d.psk_identity_hint.is_some() { some(&mut hint) } else { ptr::null_mut() },
            psk_identity: if d.psk_identity.is_some() { some(&mut ident) } else { ptr::null_mut() },
            srp_username: if d.srp_username.is_some() { some(&mut srp) } else { ptr::null_mut() },
            flags: u64::from(d.flags),
            max_early_data: d.max_early_data,
            alpn_selected: if d.alpn_selected.is_some() { some(&mut alpn) } else { ptr::null_mut() },
            tlsext_max_fragment_len_mode: u32::from(d.max_fragment_len_mode),
            ticket_appdata: if d.ticket_appdata.is_some() { some(&mut appdata) } else { ptr::null_mut() },
            kex_group: d.kex_group,
            peer_rpk: if rpk.length > 0 && !rpk.data.is_null() { some(&mut rpk) } else { ptr::null_mut() },
        };
        // SAFETY: the structure built above, whose strings borrow the locked session's octets
        // (the session isn't changed while it's encoded); the caller's output.
        let ret = unsafe { ASN1_item_i2d(ptr::from_mut(&mut asn).cast(), pp, item()) };
        drop(d);
        // SAFETY: the key's encoding, allocated by `i2d_PUBKEY`, or NULL.
        unsafe { mem::release(rpk_der.cast()) };
        ret
    }
}

/// An OCTET STRING's octets (empty for NULL).
///
/// # Safety
/// `s` is NULL or a live string.
unsafe fn octets_of<'a>(s: *const ASN1_OCTET_STRING) -> Option<&'a [u8]> {
    // SAFETY: the caller's guarantee.
    let s = unsafe { s.as_ref() }?;
    let n = usize::try_from(s.length).ok()?;
    if n == 0 || s.data.is_null() {
        return Some(&[]);
    }
    // SAFETY: the string's `length` octets.
    Some(unsafe { core::slice::from_raw_parts(s.data, n) })
}

/// `ssl_session_strndup`: a copy of the string up to its first NUL, or `None`.
///
/// # Safety
/// `s` is NULL or a live string.
unsafe fn strndup(s: *const ASN1_OCTET_STRING) -> Option<CString> {
    // SAFETY: the caller's guarantee.
    let o = unsafe { octets_of(s) }?;
    let end = o.iter().position(|&b| b == 0).unwrap_or(o.len());
    CString::new(o.get(..end).unwrap_or_default()).ok()
}

/// `ssl_session_memcpy`'s check: the octets (none for NULL or empty), or `Err` if longer than
/// `max`.
///
/// # Safety
/// `s` is NULL or a live string.
unsafe fn bounded<'a>(s: *const ASN1_OCTET_STRING, max: usize) -> Result<&'a [u8], ()> {
    // SAFETY: the caller's guarantee.
    match unsafe { octets_of(s) } {
        None => Ok(&[]),
        Some(o) if o.len() <= max => Ok(o),
        Some(_) => Err(()),
    }
}

/// The decoded fields into `d` (`d2i_SSL_SESSION_ex`'s checks and copies). `Err` after
/// raising OpenSSL's error (or none, where OpenSSL raises none).
///
/// # Safety
/// `asn` is a live decoded structure (its peer and strings are taken where OpenSSL takes
/// them); `libctx` and `propq` as for `d2i_PUBKEY_ex`.
unsafe fn fill(
    d: &mut SessData,
    asn: &mut SessAsn1,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> Result<(), ()> {
    const F: &str = "d2i_SSL_SESSION_ex";
    if i64::from(asn.version) != i64::from(SSL_SESSION_ASN1_VERSION) {
        err::raise(ERR_LIB_SSL, SSL_R_UNKNOWN_SSL_VERSION, F);
        return Err(());
    }
    let v = asn.ssl_version;
    if (v >> 8) != SSL3_VERSION_MAJOR && (v >> 8) != DTLS1_VERSION_MAJOR && v != DTLS1_BAD_VER {
        err::raise(ERR_LIB_SSL, SSL_R_UNSUPPORTED_SSL_VERSION, F);
        return Err(());
    }
    d.ssl_version = v;
    d.kex_group = asn.kex_group;
    // SAFETY: the decoded string.
    let c = unsafe { octets_of(asn.cipher) }.unwrap_or_default();
    let (Some(&c0), Some(&c1), 2) = (c.first(), c.get(1), c.len()) else {
        err::raise(ERR_LIB_SSL, SSL_R_CIPHER_CODE_WRONG_LENGTH, F);
        return Err(());
    };
    let id = 0x0300_0000 | (u32::from(c0) << 8) | u32::from(c1);
    d.cipher_id = id;
    d.cipher = rustyssl_tls::suites::by_id(id);
    if d.cipher.is_none() {
        return Err(());
    }
    // SAFETY: the decoded strings.
    let sid = unsafe { bounded(asn.session_id, max_id()) }?;
    d.set_id(sid);
    // SAFETY: as above.
    let mk = unsafe { bounded(asn.master_key, MAX_MASTER_KEY) }?;
    d.set_master_key(mk);
    d.time = if asn.time != 0 {
        from_time_t(asn.time)
    } else {
        time_now()
    };
    d.timeout = if asn.timeout != 0 {
        from_time_t(asn.timeout)
    } else {
        from_time_t(3)
    };
    d.calculate_timeout();
    // SAFETY: the session's old certificate, or NULL.
    unsafe { X509_free(d.peer) };
    d.peer = core::mem::replace(&mut asn.peer, ptr::null_mut());
    // SAFETY: the session's old key, or NULL.
    unsafe { EVP_PKEY_free(d.peer_rpk) };
    d.peer_rpk = ptr::null_mut();
    // SAFETY: the decoded string.
    if let Some(r) = unsafe { octets_of(asn.peer_rpk) } {
        let mut q = r.as_ptr();
        let len = c_long::try_from(r.len()).map_err(|_| ())?;
        // SAFETY: the key's octets; the caller's library context and properties.
        let k: *mut EVP_PKEY =
            unsafe { d2i_PUBKEY_ex(ptr::null_mut(), &raw mut q, len, libctx, propq) };
        if k.is_null() {
            return Err(());
        }
        d.peer_rpk = k;
    }
    // SAFETY: the decoded string.
    let ctx = unsafe { bounded(asn.session_id_context, max_sid_ctx()) }?;
    d.set_sid_ctx(ctx);
    d.verify_result = c_long::from(asn.verify_result);
    // SAFETY: the decoded strings.
    d.hostname = unsafe { strndup(asn.tlsext_hostname) };
    // SAFETY: as above.
    d.psk_identity_hint = unsafe { strndup(asn.psk_identity_hint) };
    // SAFETY: as above.
    d.psk_identity = unsafe { strndup(asn.psk_identity) };
    d.tick_lifetime_hint = asn.tlsext_tick_lifetime_hint;
    d.tick_age_add = asn.tlsext_tick_age_add;
    // SAFETY: as above.
    d.tick = unsafe { octets_of(asn.tlsext_tick) }.map(|t| t.to_vec().into_boxed_slice());
    // SAFETY: as above.
    match unsafe { octets_of(asn.comp_id) } {
        None => d.compress_meth = 0,
        Some(&[m]) => d.compress_meth = u32::from(m),
        Some(_) => {
            err::raise(ERR_LIB_SSL, SSL_R_BAD_LENGTH, F);
            return Err(());
        }
    }
    // SAFETY: as above.
    d.srp_username = unsafe { strndup(asn.srp_username) };
    // OpenSSL stores the 64-bit flags through an `int32_t`.
    d.flags = u32::try_from(asn.flags & 0xffff_ffff).unwrap_or(0);
    d.max_early_data = asn.max_early_data;
    // SAFETY: as above.
    d.alpn_selected =
        unsafe { octets_of(asn.alpn_selected) }.map(|a| a.to_vec().into_boxed_slice());
    d.max_fragment_len_mode = u8::try_from(asn.tlsext_max_fragment_len_mode & 0xff).unwrap_or(0);
    // SAFETY: as above.
    d.ticket_appdata =
        unsafe { octets_of(asn.ticket_appdata) }.map(|a| a.to_vec().into_boxed_slice());
    Ok(())
}

ffi_export! {
    /// Decodes a session with a library context for its raw public key: into `*a` when `a`
    /// and `*a` aren't NULL (else a new session, stored in `*a` when `a` isn't NULL), advancing
    /// `*pp`. NULL on failure (a new session is freed).
    ///
    /// # Safety
    /// `a` is NULL or a slot holding NULL or a live session; `pp` points to `length` octets;
    /// `libctx` NULL or a live library context; `propq` NULL or a string.
    pub unsafe extern "C" fn rustyssl_private_d2i_SSL_SESSION_ex(a: *mut *mut SSL_SESSION, pp: *mut *const c_uchar, length: c_long, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut SSL_SESSION
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        if pp.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's pointer.
        let mut p = unsafe { pp.read() };
        // SAFETY: the caller's octets; the item.
        let asnv: *mut ASN1_VALUE = unsafe { ASN1_item_d2i(ptr::null_mut(), &raw mut p, length, item()) };
        if asnv.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's slot, or NULL.
        let given = if a.is_null() { ptr::null_mut() } else { unsafe { a.read() } };
        let ret = if given.is_null() { session::blank() } else { given };
        let ok = !ret.is_null() && {
            // SAFETY: the decoded structure, which no one else holds.
            let asn = unsafe { &mut *asnv.cast::<SessAsn1>() };
            // SAFETY: the session made or given.
            unsafe { sess(ret) }.is_some_and(|x| {
                // SAFETY: the decoded structure; the caller's context.
                unsafe { fill(&mut x.data(), asn, libctx, propq) }.is_ok()
            })
        };
        // SAFETY: the decoded structure (what was taken from it is NULL now).
        unsafe { ASN1_item_free(asnv, item()) };
        if !ok {
            if given.is_null() {
                // SAFETY: the new session's only reference.
                unsafe { session::free(ret) };
            }
            return ptr::null_mut();
        }
        if !a.is_null() && given.is_null() {
            // SAFETY: the caller's slot.
            unsafe { a.write(ret) };
        }
        // SAFETY: the caller's pointer.
        unsafe { pp.write(p) };
        ret
    }
}

ffi_export! {
    /// `d2i_SSL_SESSION_ex` with the default library context.
    ///
    /// # Safety
    /// As for `d2i_SSL_SESSION_ex`.
    pub unsafe extern "C" fn rustyssl_private_d2i_SSL_SESSION(a: *mut *mut SSL_SESSION, pp: *mut *const c_uchar, length: c_long) -> *mut SSL_SESSION
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { rustyssl_private_d2i_SSL_SESSION_ex(a, pp, length, ptr::null_mut(), ptr::null()) }
    }
}

/// `d2i_SSL_SESSION` as a `d2i_of_void`, for the PEM readers.
unsafe extern "C" fn d2i_void(
    a: *mut *mut c_void,
    pp: *mut *const c_uchar,
    length: c_long,
) -> *mut c_void {
    // SAFETY: the PEM reader's arguments.
    unsafe { rustyssl_private_d2i_SSL_SESSION(a.cast(), pp, length) }.cast()
}

/// `i2d_SSL_SESSION` as an `i2d_of_void`, for the PEM writers.
unsafe extern "C" fn i2d_void(x: *const c_void, pp: *mut *mut c_uchar) -> c_int {
    // SAFETY: the PEM writer's arguments.
    unsafe { rustyssl_private_i2d_SSL_SESSION(x.cast(), pp) }
}

ffi_export! {
    /// Reads a PEM session ("SSL SESSION PARAMETERS") from `bp`, as `PEM_read_bio_*` do.
    ///
    /// # Safety
    /// `bp` is a live BIO; `x` NULL or a slot; `cb` and `u` as for `PEM_read_bio`.
    pub unsafe extern "C" fn rustyssl_private_PEM_read_bio_SSL_SESSION(bp: *mut BIO, x: *mut *mut SSL_SESSION, cb: pem_password_cb, u: *mut c_void) -> *mut SSL_SESSION
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { PEM_ASN1_read_bio(Some(d2i_void), PEM_STRING_SSL_SESSION.as_ptr(), bp, x.cast(), cb, u) }.cast()
    }
}

ffi_export! {
    /// Reads a PEM session from `fp`.
    ///
    /// # Safety
    /// `fp` is a live FILE; `x` NULL or a slot; `cb` and `u` as for `PEM_read`.
    pub unsafe extern "C" fn rustyssl_private_PEM_read_SSL_SESSION(fp: *mut libc::FILE, x: *mut *mut SSL_SESSION, cb: pem_password_cb, u: *mut c_void) -> *mut SSL_SESSION
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { PEM_ASN1_read(Some(d2i_void), PEM_STRING_SSL_SESSION.as_ptr(), fp.cast(), x.cast(), cb, u) }.cast()
    }
}

ffi_export! {
    /// Writes the session to `bp` in PEM: 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `x` a live session.
    pub unsafe extern "C" fn rustyssl_private_PEM_write_bio_SSL_SESSION(bp: *mut BIO, x: *const SSL_SESSION) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee; no encryption.
        unsafe { PEM_ASN1_write_bio(Some(i2d_void), PEM_STRING_SSL_SESSION.as_ptr(), bp, x.cast(), ptr::null(), ptr::null(), 0, None, ptr::null_mut()) }
    }
}

ffi_export! {
    /// Writes the session to `fp` in PEM: 1, or 0.
    ///
    /// # Safety
    /// `fp` is a live FILE; `x` a live session.
    pub unsafe extern "C" fn rustyssl_private_PEM_write_SSL_SESSION(fp: *mut libc::FILE, x: *const SSL_SESSION) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee; no encryption.
        unsafe { PEM_ASN1_write(Some(i2d_void), PEM_STRING_SSL_SESSION.as_ptr(), fp.cast(), x.cast(), ptr::null(), ptr::null(), 0, None, ptr::null_mut()) }
    }
}

/// Writes `text` to `bp`: whether all of it went.
///
/// # Safety
/// `bp` is a live BIO.
unsafe fn puts(bp: *mut BIO, text: &str) -> bool {
    if text.is_empty() {
        return true;
    }
    let Ok(n) = c_int::try_from(text.len()) else {
        return false;
    };
    // SAFETY: the caller's BIO; the text's octets.
    (unsafe { BIO_write(bp, text.as_ptr().cast(), n) }) == n
}

/// Octets as upper-case hex (`%02X` each).
fn hex_upper(b: &[u8]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(b.len().saturating_mul(2));
    for x in b {
        let _ = write!(s, "{x:02X}");
    }
    s
}

/// A C string, or "None".
fn or_none(s: &Option<CString>) -> String {
    s.as_ref()
        .map_or_else(|| "None".to_owned(), |c| c.to_string_lossy().into_owned())
}

ffi_export! {
    /// Prints the session as `SSL_SESSION_print` does (byte for byte): 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `x` NULL or a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_print(bp: *mut BIO, x: *const SSL_SESSION) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { sess(x) }) else { return 0 };
        // The text up to the ticket, the ticket's dump, and the rest, copied out first so the
        // session isn't locked while the BIO (and its callbacks) runs.
        let (head, tick, tail) = {
            let d = s.data();
            let tls13 = d.ssl_version == TLS1_3_VERSION;
            let mut h = String::from("SSL-Session:\n");
            h.push_str(&format!("    Protocol  : {}\n", rustyssl_tls::suites::protocol_str(d.ssl_version)));
            match d.cipher {
                None if (d.cipher_id & 0xff00_0000) == 0x0200_0000 => {
                    h.push_str(&format!("    Cipher    : {:06X}\n", d.cipher_id & 0x00ff_ffff));
                }
                None => h.push_str(&format!("    Cipher    : {:04X}\n", d.cipher_id & 0xffff)),
                Some(c) => h.push_str(&format!("    Cipher    : {}\n", c.name_str())),
            }
            h.push_str("    Session-ID: ");
            h.push_str(&hex_upper(d.id()));
            h.push_str("\n    Session-ID-ctx: ");
            h.push_str(&hex_upper(d.sid_ctx()));
            h.push_str(if tls13 { "\n    Resumption PSK: " } else { "\n    Master-Key: " });
            h.push_str(&hex_upper(d.master_key()));
            h.push_str("\n    PSK identity: ");
            h.push_str(&or_none(&d.psk_identity));
            h.push_str("\n    PSK identity hint: ");
            h.push_str(&or_none(&d.psk_identity_hint));
            h.push_str("\n    SRP username: ");
            h.push_str(&or_none(&d.srp_username));
            if d.tick_lifetime_hint != 0 {
                h.push_str(&format!("\n    TLS session ticket lifetime hint: {} (seconds)", d.tick_lifetime_hint));
            }
            let tick = d.tick.as_ref().map(|t| t.to_vec());
            if tick.is_some() {
                h.push_str("\n    TLS session ticket:\n");
            }
            let mut t = String::new();
            if d.compress_meth != 0 {
                t.push_str(&format!("\n    Compression: {}", d.compress_meth));
            }
            if d.time != 0 {
                t.push_str(&format!("\n    Start Time: {}", to_time_t(d.time)));
            }
            if d.timeout != 0 {
                t.push_str(&format!("\n    Timeout   : {} (sec)", to_time_t(d.timeout)));
            }
            t.push('\n');
            // SAFETY: no preconditions; a static string.
            let vs = unsafe { X509_verify_cert_error_string(d.verify_result) };
            let vtext = if vs.is_null() {
                String::new()
            } else {
                // SAFETY: a static NUL-terminated string.
                unsafe { CStr::from_ptr(vs) }.to_string_lossy().into_owned()
            };
            t.push_str(&format!("    Verify return code: {} ({vtext})\n", d.verify_result));
            t.push_str(&format!(
                "    Extended master secret: {}\n",
                if d.flags & SESS_FLAG_EXTMS != 0 { "yes" } else { "no" }
            ));
            if tls13 {
                t.push_str(&format!("    Max Early Data: {}\n", d.max_early_data));
            }
            (h, tick, t)
        };
        // SAFETY: the caller's BIO, for each write.
        if !unsafe { puts(bp, &head) } {
            return 0;
        }
        if let Some(t) = tick {
            let n = c_int::try_from(t.len()).unwrap_or(c_int::MAX);
            // SAFETY: as above; the ticket's octets.
            if unsafe { BIO_dump_indent(bp, t.as_ptr().cast(), n, 4) } <= 0 {
                return 0;
            }
        }
        // SAFETY: as above.
        c_int::from(unsafe { puts(bp, &tail) })
    }
}

ffi_export! {
    /// `SSL_SESSION_print` to a FILE: 1, or 0.
    ///
    /// # Safety
    /// `fp` is a live FILE; `x` NULL or a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_print_fp(fp: *mut libc::FILE, x: *const SSL_SESSION) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's FILE, not closed by the BIO.
        let b = unsafe { BIO_new_fp(fp.cast(), BIO_NOCLOSE) };
        if b.is_null() {
            err::raise(ERR_LIB_SSL, rustyssl_abi::ERR_R_BUF_LIB, "SSL_SESSION_print_fp");
            return 0;
        }
        // SAFETY: the BIO made above; the caller's session.
        let r = unsafe { rustyssl_private_SSL_SESSION_print(b, x) };
        // SAFETY: the BIO made above.
        unsafe { crate::bio::BIO_free(b) };
        r
    }
}

ffi_export! {
    /// Prints the session in NSS key log form (`RSA Session-ID:... Master-Key:...`): 1, or 0
    /// (for NULL, or a session with no ID or no master key).
    ///
    /// # Safety
    /// `bp` is a live BIO; `x` NULL or a live session.
    pub unsafe extern "C" fn rustyssl_private_SSL_SESSION_print_keylog(bp: *mut BIO, x: *const SSL_SESSION) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { sess(x) }) else { return 0 };
        let line = {
            let d = s.data();
            if d.session_id_length == 0 || d.master_key_length == 0 {
                return 0;
            }
            format!("RSA Session-ID:{} Master-Key:{}\n", hex_upper(d.id()), hex_upper(d.master_key()))
        };
        // SAFETY: the caller's BIO.
        c_int::from(unsafe { puts(bp, &line) })
    }
}
