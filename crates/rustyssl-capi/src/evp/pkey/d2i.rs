//! Keys from DER (`d2i_PrivateKey(3)`, `d2i_PublicKey`, `d2i_KeyParams`, `EVP_PKCS82PKEY`;
//! `d2i_pr.c`, `d2i_pu.c`, `d2i_param.c`, `evp_pkey.c`): a private key through the decoders
//! (a PrivateKeyInfo, or a type-specific structure) and, failing that, through the type's
//! ASN.1 method (its traditional format, then PKCS#8); a public key or parameters of a type
//! through its legacy structures; and keys to and from `PKCS8_PRIV_KEY_INFO`.
//!
//! As in OpenSSL, a decoded private key must have its private part, and the automatic
//! decoding's fallback guesses the type from the element count of the SEQUENCE (6 for DSA, 4
//! for EC, 3 for PKCS#8, else RSA). Where OpenSSL's legacy decoding frees the application's
//! key and then fails, leaving `*a` dangling, rustyssl frees it only on success
//! (docs/DEVIATIONS.md).

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use libc::FILE;

use rustyssl_abi::{
    ASN1_R_ASN1_PARSE_ERROR, ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE, ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE,
    ASN1_R_UNSUPPORTED_TYPE, BIO, ERR_LIB_ASN1, ERR_LIB_EVP, ERR_LIB_X509, ERR_R_ASN1_LIB,
    ERR_R_BUF_LIB, ERR_R_EVP_LIB, EVP_PKEY, EVP_PKEY_DSA, EVP_PKEY_EC, EVP_PKEY_KEY_PARAMETERS,
    EVP_PKEY_KEYPAIR, EVP_PKEY_NONE, EVP_PKEY_RSA, EVP_R_METHOD_NOT_SUPPORTED,
    EVP_R_PRIVATE_KEY_DECODE_ERROR, EVP_R_PRIVATE_KEY_ENCODE_ERROR,
    EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM, OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_LIB_CTX,
    PKCS8_PRIV_KEY_INFO,
};

use super::{
    EVP_PKEY_assign, EVP_PKEY_free, EVP_PKEY_get_base_id, EVP_PKEY_get_id, EVP_PKEY_new,
    EVP_PKEY_set_type, EVP_PKEY_type, legacy_data, pkey,
};
use crate::decoder::ctx::{
    OSSL_DECODER_CTX_free, OSSL_DECODER_CTX_get_num_decoders, OSSL_DECODER_from_data,
};
use crate::decoder::pkey::OSSL_DECODER_CTX_new_for_pkey;
use crate::err::{self, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::ffi::ffi_export;
use crate::objects::{OBJ_obj2nid, OBJ_obj2txt, i2t_ASN1_OBJECT};
use crate::x509::p8::{
    PKCS8_PRIV_KEY_INFO_free, PKCS8_PRIV_KEY_INFO_new, PKCS8_pkey_get0, d2i_PKCS8_PRIV_KEY_INFO,
    i2d_PKCS8_PRIV_KEY_INFO,
};

/// `OSSL_MAX_NAME_SIZE` (`internal/sizes.h`).
const MAX_NAME: usize = 50;
/// `MAX_NAME` as `OBJ_obj2txt` takes it.
const NAME_LEN: c_int = 50;

type D2iKey =
    unsafe extern "C" fn(*mut *mut EVP_PKEY, *mut *const c_uchar, c_long) -> *mut EVP_PKEY;

/// The text of an object as `OBJ_obj2txt` gives it in a name-sized buffer, or `None`.
///
/// # Safety
/// `obj` is a live object.
unsafe fn obj_text(obj: *const rustyssl_abi::ASN1_OBJECT) -> Option<[c_char; MAX_NAME]> {
    let mut buf = [0 as c_char; MAX_NAME];
    // SAFETY: the caller's object; the buffer's size.
    let n = unsafe { OBJ_obj2txt(buf.as_mut_ptr(), NAME_LEN, obj, 0) };
    (n > 0).then_some(buf)
}

/// `d2i_PrivateKey_decoder`: a private key (of `keytype`, or the PrivateKeyInfo's) through the
/// decoders, into `*a` when that holds a key; NULL otherwise, `*pp` restored.
///
/// # Safety
/// As for `d2i_PrivateKey_ex`.
unsafe fn private_decoder(
    keytype: c_int,
    a: *mut *mut EVP_PKEY,
    pp: *mut *const c_uchar,
    length: c_long,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> *mut EVP_PKEY {
    let mut len = usize::try_from(length).unwrap_or(0);
    let mut namebuf = [0 as c_char; MAX_NAME];
    let mut key_name: *const c_char = ptr::null();
    if keytype != EVP_PKEY_NONE {
        let name = super::ameth::type2name(keytype);
        if name.is_empty() || name.len() >= MAX_NAME {
            return ptr::null_mut();
        }
        for (d, &s) in namebuf.iter_mut().zip(&name) {
            *d = c_char::from_ne_bytes([s]);
        }
        key_name = namebuf.as_ptr();
    }
    // SAFETY: the caller's guarantee.
    let p = unsafe { pp.read() };
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    // SAFETY: the caller's octets.
    let p8 = unsafe { d2i_PKCS8_PRIV_KEY_INFO(ptr::null_mut(), pp, length) };
    // SAFETY: the mark set above.
    unsafe { ERR_pop_to_mark() };
    let structure = if p8.is_null() {
        c"type-specific"
    } else {
        let mut v = 0i64;
        // SAFETY: the decoded structure.
        let version = unsafe { (*p8.cast::<crate::x509::p8::P8>()).version };
        // SAFETY: its version INTEGER; a local.
        if unsafe { crate::asn1::integer::ASN1_INTEGER_get_int64(&raw mut v, version) } == 0
            || (v != 0 && v != 1)
        {
            // SAFETY: the caller's guarantee.
            unsafe { pp.write(p) };
            err::raise(
                ERR_LIB_ASN1,
                ASN1_R_ASN1_PARSE_ERROR,
                "d2i_PrivateKey_decoder",
            );
            // SAFETY: decoded above.
            unsafe { PKCS8_PRIV_KEY_INFO_free(p8) };
            return ptr::null_mut();
        }
        if key_name.is_null() {
            let mut algoid = ptr::null();
            // SAFETY: the structure; a local.
            if unsafe { PKCS8_pkey_get0(&raw mut algoid, ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), p8) } != 0
                // SAFETY: its object.
                && let Some(t) = unsafe { obj_text(algoid) }
            {
                namebuf = t;
                key_name = namebuf.as_ptr();
            }
        }
        // SAFETY: as above.
        unsafe { PKCS8_PRIV_KEY_INFO_free(p8) };
        c"PrivateKeyInfo"
    };
    // SAFETY: the caller's guarantee.
    unsafe { pp.write(p) };
    let mut fresh: *mut EVP_PKEY = ptr::null_mut();
    // SAFETY: as above.
    let bak_a = if a.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { a.read() }
    };
    let ppkey = if bak_a.is_null() { &raw mut fresh } else { a };
    // SAFETY: the key pointer; static strings; the caller's library context and properties.
    let dctx = unsafe {
        OSSL_DECODER_CTX_new_for_pkey(
            ppkey,
            c"DER".as_ptr(),
            structure.as_ptr(),
            key_name,
            EVP_PKEY_KEYPAIR,
            libctx,
            propq,
        )
    };
    if !a.is_null() {
        // SAFETY: as above.
        unsafe { a.write(bak_a) };
    }
    let fail = || {
        if ppkey != a {
            // SAFETY: the local key pointer.
            let k = unsafe { ppkey.read() };
            // SAFETY: the key decoded here, or NULL.
            unsafe { EVP_PKEY_free(k) };
        }
        ptr::null_mut()
    };
    if dctx.is_null() {
        return fail();
    }
    // SAFETY: the new context; the caller's octets.
    let ret = unsafe { OSSL_DECODER_from_data(dctx, pp, &raw mut len) };
    // SAFETY: made above.
    unsafe { OSSL_DECODER_CTX_free(dctx) };
    // SAFETY: the key pointer.
    let k = unsafe { ppkey.read() };
    // SAFETY: the decoded key, or NULL.
    let has_private =
        unsafe { pkey(k) }.is_some_and(|key| super::util_has(key, OSSL_KEYMGMT_SELECT_PRIVATE_KEY));
    if ret != 0 && has_private {
        if !a.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { a.write(k) };
        }
        return k;
    }
    fail()
}

/// `evp_pkcs82pkey_legacy`: a key of the PrivateKeyInfo's algorithm through its ASN.1 method's
/// `priv_decode_ex` or `priv_decode`, or NULL.
///
/// # Safety
/// `p8` is a live PrivateKeyInfo; `libctx` is NULL or a live library context; `propq` is NULL
/// or a string.
pub(crate) unsafe fn pkcs82pkey_legacy(
    p8: *const PKCS8_PRIV_KEY_INFO,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> *mut EVP_PKEY {
    const F: &str = "evp_pkcs82pkey_legacy";
    let mut algoid = ptr::null();
    // SAFETY: the caller's structure; a local.
    if unsafe {
        PKCS8_pkey_get0(
            &raw mut algoid,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            p8,
        )
    } == 0
    {
        return ptr::null_mut();
    }
    // SAFETY: no preconditions.
    let pk = unsafe { EVP_PKEY_new() };
    if pk.is_null() {
        err::raise(ERR_LIB_EVP, ERR_R_EVP_LIB, F);
        return ptr::null_mut();
    }
    let fail = || {
        // SAFETY: made above.
        unsafe { EVP_PKEY_free(pk) };
        ptr::null_mut()
    };
    // SAFETY: the structure's object.
    let nid = unsafe { OBJ_obj2nid(algoid) };
    // SAFETY: the new key.
    if unsafe { EVP_PKEY_set_type(pk, nid) } == 0 {
        let mut obj_tmp = [0 as c_char; 80];
        // SAFETY: the object; the buffer's size.
        unsafe { i2t_ASN1_OBJECT(obj_tmp.as_mut_ptr(), 80, algoid) };
        // SAFETY: NUL-terminated by `i2t_ASN1_OBJECT`.
        let name = unsafe { core::ffi::CStr::from_ptr(obj_tmp.as_ptr()) }.to_string_lossy();
        err::raise_with_text(
            ERR_LIB_EVP,
            EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM,
            F,
            &format!("TYPE={name}"),
        );
        return fail();
    }
    // SAFETY: the new key.
    let funcs = unsafe { pkey(pk) }
        .and_then(|k| k.ameth_funcs())
        .unwrap_or_default();
    if let Some(decode) = funcs.priv_decode_ex {
        // SAFETY: the method's function with the key, the structure, and the caller's context.
        if unsafe { decode(pk, p8, libctx, propq) } == 0 {
            return fail();
        }
    } else if let Some(decode) = funcs.priv_decode {
        // SAFETY: the method's function with the key and the structure.
        if unsafe { decode(pk, p8) } == 0 {
            err::raise(ERR_LIB_EVP, EVP_R_PRIVATE_KEY_DECODE_ERROR, F);
            return fail();
        }
    } else {
        err::raise(ERR_LIB_EVP, EVP_R_METHOD_NOT_SUPPORTED, F);
        return fail();
    }
    pk
}

/// `ossl_d2i_PrivateKey_legacy`: a private key of `keytype` through its ASN.1 method — its
/// traditional format, else PKCS#8 (which must give the type) — into `*a` when that holds a
/// key; `*pp` moves past it.
///
/// # Safety
/// As for `d2i_PrivateKey_ex`.
pub(crate) unsafe fn private_legacy(
    keytype: c_int,
    a: *mut *mut EVP_PKEY,
    pp: *mut *const c_uchar,
    length: c_long,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> *mut EVP_PKEY {
    const F: &str = "ossl_d2i_PrivateKey_legacy";
    // SAFETY: the caller's guarantee.
    let mut p = unsafe { pp.read() };
    // SAFETY: as above.
    let old = if a.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { a.read() }
    };
    let mut ret = if old.is_null() {
        // SAFETY: no preconditions.
        let pk = unsafe { EVP_PKEY_new() };
        if pk.is_null() {
            err::raise(ERR_LIB_ASN1, ERR_R_EVP_LIB, F);
            return ptr::null_mut();
        }
        pk
    } else {
        old
    };
    let fail = |ret: *mut EVP_PKEY| {
        if ret != old {
            // SAFETY: a key made here.
            unsafe { EVP_PKEY_free(ret) };
        }
        ptr::null_mut()
    };
    // SAFETY: the key.
    if unsafe { EVP_PKEY_set_type(ret, keytype) } == 0 {
        err::raise(ERR_LIB_ASN1, ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE, F);
        return fail(ret);
    }
    // SAFETY: as above.
    let funcs = unsafe { pkey(ret) }
        .and_then(|k| k.ameth_funcs())
        .unwrap_or_default();
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    let len = c_int::try_from(length).unwrap_or(c_int::MAX);
    let decoded = funcs.old_priv_decode.is_some_and(|decode| {
        // SAFETY: the method's function with the key and the caller's octets.
        unsafe { decode(ret, &raw mut p, len) != 0 }
    });
    if decoded {
        // SAFETY: the mark set above.
        unsafe { ERR_clear_last_mark() };
    } else if funcs.priv_decode.is_some() || funcs.priv_decode_ex.is_some() {
        // SAFETY: the caller's octets.
        let p8 = unsafe { d2i_PKCS8_PRIV_KEY_INFO(ptr::null_mut(), &raw mut p, length) };
        if p8.is_null() {
            // SAFETY: as above.
            unsafe { ERR_clear_last_mark() };
            return fail(ret);
        }
        // SAFETY: the structure; the caller's context.
        let tmp = unsafe { pkcs82pkey_legacy(p8, libctx, propq) };
        // SAFETY: decoded above.
        unsafe { PKCS8_PRIV_KEY_INFO_free(p8) };
        if tmp.is_null() {
            // SAFETY: as above.
            unsafe { ERR_clear_last_mark() };
            return fail(ret);
        }
        // SAFETY: as above.
        unsafe { ERR_pop_to_mark() };
        // SAFETY: the new key.
        if unsafe { EVP_PKEY_type(keytype) } != unsafe { EVP_PKEY_get_base_id(tmp) } {
            // SAFETY: made above.
            unsafe { EVP_PKEY_free(tmp) };
            return fail(ret);
        }
        // The application's key goes only now (OpenSSL frees it before the type check).
        // SAFETY: the key typed above, the caller's or made here.
        unsafe { EVP_PKEY_free(ret) };
        ret = tmp;
    } else {
        // SAFETY: as above.
        unsafe { ERR_clear_last_mark() };
        err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, F);
        return fail(ret);
    }
    // SAFETY: the caller's guarantee.
    unsafe { pp.write(p) };
    if !a.is_null() {
        // SAFETY: as above.
        unsafe { a.write(ret) };
    }
    ret
}

ffi_export! {
    /// A private key of the type from DER (a PrivateKeyInfo or the type's own structure) in a
    /// library context, into `*a` when that holds a key; `*pp` moves past it. NULL on failure.
    ///
    /// # Safety
    /// `pp` holds a pointer to `length` octets; `a` is NULL or holds NULL or a live key;
    /// `libctx` is NULL or a live library context; `propq` is NULL or a string.
    pub unsafe extern "C" fn d2i_PrivateKey_ex(keytype: c_int, a: *mut *mut EVP_PKEY, pp: *mut *const c_uchar, length: c_long, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let ret = unsafe { private_decoder(keytype, a, pp, length, libctx, propq) };
        if !ret.is_null() {
            return ret;
        }
        // SAFETY: as above.
        unsafe { private_legacy(keytype, a, pp, length, libctx, propq) }
    }
}

ffi_export! {
    /// `d2i_PrivateKey_ex` in the default library context.
    ///
    /// # Safety
    /// As for `d2i_PrivateKey_ex`.
    pub unsafe extern "C" fn d2i_PrivateKey(type_: c_int, a: *mut *mut EVP_PKEY, pp: *mut *const c_uchar, length: c_long) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { d2i_PrivateKey_ex(type_, a, pp, length, ptr::null_mut(), ptr::null()) }
    }
}

/// `d2i_AutoPrivateKey_legacy`: a private key of the type the SEQUENCE's element count
/// suggests (6 DSA, 4 EC, 3 PKCS#8, else RSA).
///
/// # Safety
/// As for `d2i_AutoPrivateKey_ex`.
unsafe fn auto_legacy(
    a: *mut *mut EVP_PKEY,
    pp: *mut *const c_uchar,
    length: c_long,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> *mut EVP_PKEY {
    // SAFETY: the caller's guarantee.
    let mut p = unsafe { pp.read() };
    // SAFETY: the caller's octets.
    let inkey = unsafe {
        crate::asn1::tpl::items::d2i_ASN1_SEQUENCE_ANY(ptr::null_mut(), &raw mut p, length)
    };
    // SAFETY: the decoded stack, or NULL.
    let n = unsafe { crate::stack::OPENSSL_sk_num(inkey.cast()) };
    /// `ASN1_TYPE_free` over an untyped pointer.
    unsafe extern "C" fn free_type(t: *mut c_void) {
        // SAFETY: an element of the stack.
        unsafe { crate::asn1::tpl::items::ASN1_TYPE_free(t.cast()) };
    }
    // SAFETY: as above; its types, freed with it.
    unsafe { crate::stack::OPENSSL_sk_pop_free(inkey.cast(), Some(free_type)) };
    // SAFETY: the caller's guarantee.
    p = unsafe { pp.read() };
    let keytype = match n {
        6 => EVP_PKEY_DSA,
        4 => EVP_PKEY_EC,
        3 => {
            // SAFETY: the caller's octets.
            let p8 = unsafe { d2i_PKCS8_PRIV_KEY_INFO(ptr::null_mut(), &raw mut p, length) };
            if p8.is_null() {
                err::raise(
                    ERR_LIB_ASN1,
                    ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE,
                    "d2i_AutoPrivateKey_legacy",
                );
                return ptr::null_mut();
            }
            // SAFETY: the structure; the caller's context.
            let ret = unsafe { pkcs82pkey_legacy(p8, libctx, propq) };
            // SAFETY: decoded above.
            unsafe { PKCS8_PRIV_KEY_INFO_free(p8) };
            if ret.is_null() {
                return ptr::null_mut();
            }
            // SAFETY: the caller's guarantee.
            unsafe { pp.write(p) };
            if !a.is_null() {
                // SAFETY: as above (OpenSSL leaves the old key to the application here).
                unsafe { a.write(ret) };
            }
            return ret;
        }
        _ => EVP_PKEY_RSA,
    };
    // SAFETY: the caller's guarantee.
    unsafe { private_legacy(keytype, a, pp, length, libctx, propq) }
}

ffi_export! {
    /// A private key of whatever type the DER holds, in a library context, into `*a` when that
    /// holds a key; `*pp` moves past it. NULL on failure.
    ///
    /// # Safety
    /// As for `d2i_PrivateKey_ex`.
    pub unsafe extern "C" fn d2i_AutoPrivateKey_ex(a: *mut *mut EVP_PKEY, pp: *mut *const c_uchar, length: c_long, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let ret = unsafe { private_decoder(EVP_PKEY_NONE, a, pp, length, libctx, propq) };
        if !ret.is_null() {
            return ret;
        }
        // SAFETY: as above.
        unsafe { auto_legacy(a, pp, length, libctx, propq) }
    }
}

ffi_export! {
    /// `d2i_AutoPrivateKey_ex` in the default library context.
    ///
    /// # Safety
    /// As for `d2i_AutoPrivateKey_ex`.
    pub unsafe extern "C" fn d2i_AutoPrivateKey(a: *mut *mut EVP_PKEY, pp: *mut *const c_uchar, length: c_long) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { d2i_AutoPrivateKey_ex(a, pp, length, ptr::null_mut(), ptr::null()) }
    }
}

/// One element read from a BIO, then decoded by `f`; NULL if either fails.
///
/// # Safety
/// `bp` is a live BIO; `f` decodes the octets it's given.
unsafe fn from_bio(
    bp: *mut BIO,
    f: impl FnOnce(*mut *const c_uchar, c_long) -> *mut EVP_PKEY,
) -> *mut EVP_PKEY {
    // SAFETY: the caller's guarantee.
    let Some(der) = (unsafe { crate::asn1::tpl::io::read_element_octets(bp) }) else {
        return ptr::null_mut();
    };
    let Ok(len) = c_long::try_from(der.len()) else {
        return ptr::null_mut();
    };
    let mut p = der.as_ptr();
    f(&raw mut p, len)
}

/// A file BIO over `fp` (left open) for `f`, or NULL with `ERR_R_BUF_LIB`.
///
/// # Safety
/// `fp` is an open `FILE`.
pub(crate) unsafe fn with_file(
    fp: *mut FILE,
    f: impl FnOnce(*mut BIO) -> *mut EVP_PKEY,
) -> *mut EVP_PKEY {
    // SAFETY: the caller's guarantee.
    let b = unsafe { crate::asn1::tpl::io::file_bio(fp) };
    if b.is_null() {
        err::raise(ERR_LIB_X509, ERR_R_BUF_LIB, "d2i_PrivateKey_ex_fp");
        return ptr::null_mut();
    }
    let ret = f(b);
    // SAFETY: made above.
    unsafe { crate::bio::BIO_free(b) };
    ret
}

/// `ASN1_d2i_bio_of(EVP_PKEY, EVP_PKEY_new, d2i, ...)`.
///
/// # Safety
/// `bp` is a live BIO; `a` is NULL or holds NULL or a live key.
pub(crate) unsafe fn d2i_bio_of(bp: *mut BIO, a: *mut *mut EVP_PKEY, d2i: D2iKey) -> *mut EVP_PKEY {
    /// `EVP_PKEY_new` over an untyped pointer.
    unsafe extern "C" fn make() -> *mut c_void {
        // SAFETY: no preconditions.
        unsafe { EVP_PKEY_new() }.cast()
    }
    // SAFETY: the key decoder, as OpenSSL's `ASN1_d2i_bio_of` casts it.
    let d2i = unsafe { core::mem::transmute::<D2iKey, crate::x509::pubkey::D2iVoid>(d2i) };
    // SAFETY: the caller's guarantee.
    unsafe { crate::asn1::tpl::io::ASN1_d2i_bio(Some(make), Some(d2i), bp, a.cast()) }.cast()
}

ffi_export! {
    /// Reads a private key of any type from a BIO (`d2i_AutoPrivateKey`).
    ///
    /// # Safety
    /// `bp` is a live BIO; `a` is NULL or holds NULL or a live key.
    pub unsafe extern "C" fn d2i_PrivateKey_bio(bp: *mut BIO, a: *mut *mut EVP_PKEY) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { d2i_bio_of(bp, a, d2i_AutoPrivateKey) }
    }
}

ffi_export! {
    /// Reads a private key of any type from a BIO in a library context.
    ///
    /// # Safety
    /// As for `d2i_PrivateKey_bio`; `libctx` is NULL or a live library context; `propq` is NULL
    /// or a string.
    pub unsafe extern "C" fn d2i_PrivateKey_ex_bio(bp: *mut BIO, a: *mut *mut EVP_PKEY, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        let f = |p, l| {
            // SAFETY: what `from_bio` gives.
            unsafe { d2i_AutoPrivateKey_ex(a, p, l, libctx, propq) }
        };
        // SAFETY: the caller's guarantee.
        unsafe { from_bio(bp, f) }
    }
}

ffi_export! {
    /// Reads a private key of any type from a file.
    ///
    /// # Safety
    /// `fp` is an open `FILE`; `a` is NULL or holds NULL or a live key.
    pub unsafe extern "C" fn d2i_PrivateKey_fp(fp: *mut FILE, a: *mut *mut EVP_PKEY) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        let f = |b| {
            // SAFETY: what `with_file` gives.
            unsafe { d2i_bio_of(b, a, d2i_AutoPrivateKey) }
        };
        // SAFETY: the caller's guarantee.
        unsafe { with_file(fp, f) }
    }
}

ffi_export! {
    /// Reads a private key of any type from a file in a library context.
    ///
    /// # Safety
    /// As for `d2i_PrivateKey_fp`; `libctx` is NULL or a live library context; `propq` is NULL
    /// or a string.
    pub unsafe extern "C" fn d2i_PrivateKey_ex_fp(fp: *mut FILE, a: *mut *mut EVP_PKEY, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        let f = |b| {
            // SAFETY: what `with_file` gives.
            unsafe { d2i_PrivateKey_ex_bio(b, a, libctx, propq) }
        };
        // SAFETY: the caller's guarantee.
        unsafe { with_file(fp, f) }
    }
}

ffi_export! {
    /// A public key of the type from its own structure (RSAPublicKey, DSA's public key, or an
    /// EC point into `*a`'s group), into `*a` when that holds a key. NULL on failure.
    ///
    /// # Safety
    /// `pp` holds a pointer to `length` octets; `a` is NULL or holds NULL or a live key.
    pub unsafe extern "C" fn d2i_PublicKey(type_: c_int, a: *mut *mut EVP_PKEY, pp: *mut *const c_uchar, length: c_long) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        const F: &str = "d2i_PublicKey";
        // SAFETY: the caller's guarantee.
        let old = if a.is_null() { ptr::null_mut() } else { unsafe { a.read() } };
        let ret = if old.is_null() {
            // SAFETY: no preconditions.
            let pk = unsafe { EVP_PKEY_new() };
            if pk.is_null() {
                err::raise(ERR_LIB_ASN1, ERR_R_EVP_LIB, F);
                return ptr::null_mut();
            }
            pk
        } else {
            old
        };
        let fail = || {
            if ret != old {
                // SAFETY: made here.
                unsafe { EVP_PKEY_free(ret) };
            }
            ptr::null_mut()
        };
        // A provided EC key's point goes into a legacy copy of its parameters.
        let mut copy: Option<*mut c_void> = None;
        // SAFETY: the key.
        if let Some(k) = unsafe { pkey(ret) }
            && k.is_provided()
            // SAFETY: as above.
            && unsafe { EVP_PKEY_get_base_id(ret) } == EVP_PKEY_EC
        {
            let Some(ec) = super::downgraded_legacy(k) else { return fail() };
            copy = Some(ec);
        }
        // SAFETY: as above.
        if (type_ != unsafe { EVP_PKEY_get_id(ret) } || copy.is_some()) && unsafe { EVP_PKEY_set_type(ret, type_) } == 0 {
            err::raise(ERR_LIB_ASN1, ERR_R_EVP_LIB, F);
            if let Some(ec) = copy {
                // SAFETY: the copy's key, taken above.
                unsafe { crate::ec::key::EC_KEY_free(ec.cast()) };
            }
            return fail();
        }
        // SAFETY: as above.
        let base = unsafe { EVP_PKEY_get_base_id(ret) };
        // SAFETY: as above.
        let current = unsafe { legacy_data(ret) };
        let key: *mut c_void = match base {
            // SAFETY: the caller's octets.
            EVP_PKEY_RSA => unsafe { crate::rsa_asn1::d2i_RSAPublicKey(ptr::null_mut(), pp, length) }.cast(),
            EVP_PKEY_DSA => {
                let mut d = current.cast();
                // SAFETY: the key's `DSA` to decode into (a new one for none); the octets.
                unsafe { crate::dsa_asn1::d2i_DSAPublicKey(&raw mut d, pp, length) }.cast()
            }
            EVP_PKEY_EC => {
                let mut e = copy.unwrap_or(current).cast();
                // SAFETY: the key's (or the copy's) EC key, whose group the point is on; the
                // octets.
                let r = unsafe { crate::ec::key_asn1::o2i_ECPublicKey(&raw mut e, pp, length) };
                if r.is_null() && copy.is_some() {
                    // SAFETY: the copy's key, taken above.
                    unsafe { crate::ec::key::EC_KEY_free(e) };
                }
                r.cast()
            }
            _ => {
                err::raise(ERR_LIB_ASN1, ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE, F);
                return fail();
            }
        };
        if key.is_null() {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, F);
            return fail();
        }
        if key != current {
            // SAFETY: the key takes the new structure.
            unsafe { EVP_PKEY_assign(ret, base, key) };
        }
        if !a.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { a.write(ret) };
        }
        ret
    }
}

ffi_export! {
    /// A key's parameters of the type through its ASN.1 method's `param_decode`, into `*a` when
    /// that holds a key. NULL on failure.
    ///
    /// # Safety
    /// `pp` holds a pointer to `length` octets; `a` is NULL or holds NULL or a live key.
    pub unsafe extern "C" fn d2i_KeyParams(type_: c_int, a: *mut *mut EVP_PKEY, pp: *mut *const c_uchar, length: c_long) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let old = if a.is_null() { ptr::null_mut() } else { unsafe { a.read() } };
        let ret = if old.is_null() {
            // SAFETY: no preconditions.
            let pk = unsafe { EVP_PKEY_new() };
            if pk.is_null() {
                return ptr::null_mut();
            }
            pk
        } else {
            old
        };
        let fail = || {
            if ret != old {
                // SAFETY: made here.
                unsafe { EVP_PKEY_free(ret) };
            }
            ptr::null_mut()
        };
        // SAFETY: the key.
        if type_ != unsafe { EVP_PKEY_get_id(ret) } && unsafe { EVP_PKEY_set_type(ret, type_) } == 0 {
            return fail();
        }
        // SAFETY: as above.
        let decode = unsafe { pkey(ret) }.and_then(|k| k.ameth_funcs()).and_then(|f| f.param_decode);
        let Some(decode) = decode else {
            err::raise(ERR_LIB_ASN1, ASN1_R_UNSUPPORTED_TYPE, "d2i_KeyParams");
            return fail();
        };
        let len = c_int::try_from(length).unwrap_or(c_int::MAX);
        // SAFETY: the method's function with the key and the caller's octets.
        if unsafe { decode(ret, pp, len) } == 0 {
            return fail();
        }
        if !a.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { a.write(ret) };
        }
        ret
    }
}

ffi_export! {
    /// Reads a key's parameters of the type from a BIO.
    ///
    /// # Safety
    /// `in_` is a live BIO; `a` is NULL or holds NULL or a live key.
    pub unsafe extern "C" fn d2i_KeyParams_bio(type_: c_int, a: *mut *mut EVP_PKEY, in_: *mut BIO) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        let f = |p, l| {
            // SAFETY: what `from_bio` gives.
            unsafe { d2i_KeyParams(type_, a, p, l) }
        };
        // SAFETY: the caller's guarantee.
        unsafe { from_bio(in_, f) }
    }
}

ffi_export! {
    /// A key from a PrivateKeyInfo in a library context: through the decoders (of its
    /// algorithm's key type, else any), else its type's ASN.1 method. NULL on failure.
    ///
    /// # Safety
    /// `p8` is NULL or a live PrivateKeyInfo; `libctx` is NULL or a live library context;
    /// `propq` is NULL or a string.
    pub unsafe extern "C" fn EVP_PKCS82PKEY_ex(p8: *const PKCS8_PRIV_KEY_INFO, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        if p8.is_null() {
            return ptr::null_mut();
        }
        let mut algoid = ptr::null();
        // SAFETY: the caller's structure; a local.
        if unsafe { PKCS8_pkey_get0(&raw mut algoid, ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), p8) } == 0 {
            return ptr::null_mut();
        }
        // SAFETY: its object.
        let Some(keytype) = (unsafe { obj_text(algoid) }) else { return ptr::null_mut() };
        let mut encoded: *mut c_uchar = ptr::null_mut();
        // SAFETY: the structure; a place for a new encoding.
        let encoded_len = unsafe { i2d_PKCS8_PRIV_KEY_INFO(p8.cast_mut(), &raw mut encoded) };
        if encoded_len <= 0 || encoded.is_null() {
            return ptr::null_mut();
        }
        let mut p8_data = encoded.cast_const();
        let mut len = usize::try_from(encoded_len).unwrap_or(0);
        let selection = EVP_PKEY_KEYPAIR | EVP_PKEY_KEY_PARAMETERS;
        let mut pk: *mut EVP_PKEY = ptr::null_mut();
        // SAFETY: a local key pointer; static strings and the name; the caller's context.
        let mut dctx = unsafe { OSSL_DECODER_CTX_new_for_pkey(&raw mut pk, c"DER".as_ptr(), c"PrivateKeyInfo".as_ptr(), keytype.as_ptr(), selection, libctx, propq) };
        // SAFETY: the new context.
        if !dctx.is_null() && unsafe { OSSL_DECODER_CTX_get_num_decoders(dctx) } == 0 {
            // SAFETY: made above.
            unsafe { OSSL_DECODER_CTX_free(dctx) };
            // SAFETY: as above, for any key type.
            dctx = unsafe { OSSL_DECODER_CTX_new_for_pkey(&raw mut pk, c"DER".as_ptr(), c"PrivateKeyInfo".as_ptr(), ptr::null(), selection, libctx, propq) };
        }
        // SAFETY: the context; the encoding.
        if dctx.is_null() || unsafe { OSSL_DECODER_from_data(dctx, &raw mut p8_data, &raw mut len) } == 0 {
            // SAFETY: the caller's structure and context.
            pk = unsafe { pkcs82pkey_legacy(p8, libctx, propq) };
        }
        // SAFETY: made above, `encoded_len` octets.
        unsafe { crate::mem::release_clean(encoded.cast(), usize::try_from(encoded_len).unwrap_or(0)) };
        // SAFETY: made above, or NULL.
        unsafe { OSSL_DECODER_CTX_free(dctx) };
        pk
    }
}

ffi_export! {
    /// `EVP_PKCS82PKEY_ex` in the default library context.
    ///
    /// # Safety
    /// As for `EVP_PKCS82PKEY_ex`.
    pub unsafe extern "C" fn EVP_PKCS82PKEY(p8: *const PKCS8_PRIV_KEY_INFO) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_PKCS82PKEY_ex(p8, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// A key's PrivateKeyInfo: a legacy key's through its ASN.1 method's `priv_encode` (a
    /// provided key's needs an encoder, step 4.7c). NULL on failure.
    ///
    /// # Safety
    /// `pkey` is a live key.
    pub unsafe extern "C" fn EVP_PKEY2PKCS8(pkey_: *const EVP_PKEY) -> *mut PKCS8_PRIV_KEY_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        const F: &str = "EVP_PKEY2PKCS8";
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { pkey(pkey_) }) else { return ptr::null_mut() };
        if k.is_provided() {
            crate::stub::unimplemented("EVP_PKEY2PKCS8 of a provided key (an encoder, step 4.7c)");
        }
        // SAFETY: no preconditions.
        let p8 = unsafe { PKCS8_PRIV_KEY_INFO_new() };
        if p8.is_null() {
            err::raise(ERR_LIB_EVP, ERR_R_ASN1_LIB, F);
            return ptr::null_mut();
        }
        let fail = |reason: c_int| {
            err::raise(ERR_LIB_EVP, reason, F);
            // SAFETY: made above.
            unsafe { PKCS8_PRIV_KEY_INFO_free(p8) };
            ptr::null_mut()
        };
        let Some(funcs) = k.ameth_funcs() else {
            return fail(EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM);
        };
        let Some(encode) = funcs.priv_encode else {
            return fail(EVP_R_METHOD_NOT_SUPPORTED);
        };
        // SAFETY: the method's function with the structure and the key.
        if unsafe { encode(p8, pkey_) } == 0 {
            return fail(EVP_R_PRIVATE_KEY_ENCODE_ERROR);
        }
        p8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ED25519 PrivateKeyInfo.
    const ED25519_P8: [u8; 48] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20, 0x0f, 0xc3, 0xdc, 0x12, 0x4a, 0x0f, 0x28, 0xcd, 0x34, 0x9e, 0x70, 0x4b, 0x86, 0x9e,
        0x78, 0xae, 0x7e, 0xbb, 0x7b, 0xce, 0xb1, 0x13, 0x8c, 0x21, 0x1b, 0x9d, 0xf4, 0x68, 0x10,
        0xaa, 0xb3, 0x0f,
    ];

    /// docs/DEVIATIONS.md: OpenSSL's legacy fallback frees the application's key before
    /// finding the PrivateKeyInfo of another type, and fails with `*a` dangling.
    #[test]
    #[cfg_attr(miri, ignore = "fetches, which loads the configuration")]
    fn a_key_given_survives_a_failed_decoding() {
        // SAFETY: no preconditions.
        let mut a = unsafe { EVP_PKEY_new() };
        let mut p = ED25519_P8.as_ptr();
        let len = c_long::try_from(ED25519_P8.len()).unwrap_or(0);
        // SAFETY: the key; the octets.
        let k =
            unsafe { d2i_PrivateKey(rustyssl_abi::EVP_PKEY_X25519, &raw mut a, &raw mut p, len) };
        assert!(k.is_null());
        // SAFETY: the application's key, still live.
        assert_eq!(unsafe { EVP_PKEY_get_id(a) }, rustyssl_abi::EVP_PKEY_X25519);
        // SAFETY: made above, freed once.
        unsafe { EVP_PKEY_free(a) };
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }
}
