//! ECX keys in `EVP_PKEY` (`ecx_meth.c`): the built-in X25519, X448, ED25519, and ED448 ASN.1
//! methods' functions for a key whose legacy data is an ECX key (`crate::ecx`, the key managers'
//! key data, shared by reference).
//!
//! A key moves between its legacy and provided forms (`export_to`, `import_from`) through the
//! raw public and private keys the ECX key managers take. Keys are compared by their public
//! keys, and their parameters are always equal.

use core::ffi::{CStr, c_int, c_long, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_PCTX, ASN1_PKEY_CTRL_DEFAULT_MD_NID, ASN1_PKEY_CTRL_GET1_TLS_ENCPT,
    ASN1_PKEY_CTRL_SET1_TLS_ENCPT, BIO, ERR_LIB_EC, ERR_R_EC_LIB, EVP_PKEY, NID_undef,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_LIB_CTX, OSSL_PARAM,
    OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_PUB_KEY,
};
use rustyssl_crypto::ecx::ED25519_SIGSIZE;
use rustyssl_crypto::ecx448::ED448_SIGSIZE;

use super::{EVP_PKEY_assign, EVP_PKEY_get_id, legacy_data};
use crate::asn1::hex::ASN1_buf_print;
use crate::bio::print::BIO_printf;
use crate::ecx::{self, EcxKey, EcxType, KeyOp};
use crate::err;
use crate::ffi::{bytes, ffi_callback};
use crate::mem::{self, CRYPTO_memcmp};
use crate::objects::OBJ_nid2ln;
use crate::params::build::{
    OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_push_octet_string,
    OSSL_PARAM_BLD_to_param,
};
use crate::params::dup::OSSL_PARAM_free;
use crate::provider::macs::wipe;

/// `X25519_BITS` (which `ecx_bits` gives ED25519 too).
const BITS_25519: c_int = 253;
/// `X448_BITS`.
const BITS_X448: c_int = 448;
/// `ED448_BITS`.
const BITS_ED448: c_int = 456;
/// `X25519_SECURITY_BITS`.
const SECURITY_BITS_25519: c_int = 128;
/// `X448_SECURITY_BITS`.
const SECURITY_BITS_448: c_int = 224;

/// The key's type, by its ASN.1 method (`pkey->ameth->pkey_id`).
///
/// # Safety
/// `p` is a live key.
unsafe fn type_of(p: *const EVP_PKEY) -> Option<EcxType> {
    // SAFETY: the caller's key.
    ecx::type_of(unsafe { EVP_PKEY_get_id(p) })
}

/// The keys' length for the key's type (`KEYLEN`).
///
/// # Safety
/// `p` is a live key.
unsafe fn keylen(p: *const EVP_PKEY) -> usize {
    // SAFETY: the caller's guarantee.
    unsafe { type_of(p) }.map_or(0, EcxType::keylen)
}

/// The key's ECX key (`pkey->pkey.ecx`), or none.
///
/// # Safety
/// `p` is a live key whose legacy data, if any, is an ECX key.
unsafe fn data<'a>(p: *const EVP_PKEY) -> Option<&'a EcxKey> {
    // SAFETY: the caller's key.
    let d = unsafe { legacy_data(p) };
    // SAFETY: an ECX key, or NULL.
    unsafe { ecx::key(d) }
}

/// Gives the key `ecx` (a reference it takes) as its legacy data, of the key's type. 1, or 0
/// (with the reference given up).
///
/// # Safety
/// `p` is a live key; `h` is NULL or ECX key data whose reference the caller gives.
unsafe fn assign(p: *mut EVP_PKEY, h: *mut c_void) -> c_int {
    if h.is_null() {
        return 0;
    }
    // SAFETY: the caller's key.
    let id = unsafe { EVP_PKEY_get_id(p) };
    // SAFETY: the caller's key; the ECX key, which it takes.
    if unsafe { EVP_PKEY_assign(p, id, h) } == 0 {
        // SAFETY: the reference not taken.
        unsafe { ecx::free(h) };
        return 0;
    }
    1
}

ffi_callback! {
    /// `ecx_pub_cmp`: 1 for the same public key, 0 for another, -2 when either is missing.
    ///
    /// # Safety
    /// `a` and `b` are live keys of the method's type.
    pub(crate) unsafe extern "C" fn ecx_pub_cmp(a: *const EVP_PKEY, b: *const EVP_PKEY) -> c_int
    where failure = -2, library = ERR_LIB_EC
    {
        // SAFETY: the caller's keys.
        let (Some(ka), Some(kb)) = (unsafe { data(a) }, unsafe { data(b) }) else { return -2 };
        // SAFETY: as above.
        let n = unsafe { keylen(a) };
        let (pa, pb) = (ka.public(), kb.public());
        let (Some(pa), Some(pb)) = (pa.get(..n), pb.get(..n)) else { return 0 };
        // SAFETY: octets of the length given.
        c_int::from(unsafe { CRYPTO_memcmp(pa.as_ptr().cast(), pb.as_ptr().cast(), n) } == 0)
    }
}

ffi_callback! {
    /// `ecx_size`: the key's length.
    ///
    /// # Safety
    /// `p` is a live key of the method's type.
    pub(crate) unsafe extern "C" fn ecx_size(p: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's key.
        c_int::try_from(unsafe { keylen(p) }).unwrap_or(0)
    }
}

ffi_callback! {
    /// `ecd_size25519`: a signature's size.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn ecd_size25519(_p: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        c_int::try_from(ED25519_SIGSIZE).unwrap_or(0)
    }
}

ffi_callback! {
    /// `ecd_size448`: a signature's size.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn ecd_size448(_p: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        c_int::try_from(ED448_SIGSIZE).unwrap_or(0)
    }
}

ffi_callback! {
    /// `ecx_bits`: by the key's type.
    ///
    /// # Safety
    /// `p` is a live key of the method's type.
    pub(crate) unsafe extern "C" fn ecx_bits(p: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's key.
        match unsafe { type_of(p) } {
            Some(EcxType::X448) => BITS_X448,
            Some(EcxType::Ed448) => BITS_ED448,
            _ => BITS_25519,
        }
    }
}

ffi_callback! {
    /// `ecx_security_bits`: by the key's type.
    ///
    /// # Safety
    /// `p` is a live key of the method's type.
    pub(crate) unsafe extern "C" fn ecx_security_bits(p: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's key.
        match unsafe { type_of(p) } {
            Some(EcxType::X448 | EcxType::Ed448) => SECURITY_BITS_448,
            _ => SECURITY_BITS_25519,
        }
    }
}

ffi_callback! {
    /// `ecx_free`: gives up the key's reference to its ECX key.
    ///
    /// # Safety
    /// `p` is a live key of the method's type.
    pub(crate) unsafe extern "C" fn ecx_free(p: *mut EVP_PKEY)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's key.
        let d = unsafe { legacy_data(p) };
        // SAFETY: its ECX key's reference, or NULL.
        unsafe { ecx::free(d) };
    }
}

ffi_callback! {
    /// `ecx_cmp_parameters`: the parameters are always equal.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn ecx_cmp_parameters(_a: *const EVP_PKEY, _b: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        1
    }
}

/// `ecx_key_print`: the key's type and keys, or a line saying it's invalid.
///
/// # Safety
/// `bp` is a live BIO; `p` is a live key of the method's type.
unsafe fn key_print(bp: *mut BIO, p: *const EVP_PKEY, indent: c_int, private: bool) -> c_int {
    // SAFETY: the caller's key.
    let k = unsafe { data(p) };
    // SAFETY: as above.
    let n = unsafe { keylen(p) };
    // SAFETY: as above.
    let id = unsafe { EVP_PKEY_get_id(p) };
    // SAFETY: no preconditions.
    let nm = unsafe { OBJ_nid2ln(id) };
    let nm = if nm.is_null() { c"".as_ptr() } else { nm };
    let line = |format: &CStr| {
        // SAFETY: the caller's BIO; a format with matching arguments.
        (unsafe { BIO_printf(bp, format.as_ptr(), indent, c"".as_ptr(), nm) }) > 0
    };
    let sub = indent.saturating_add(4);
    let (public, privkey) = match k {
        Some(k) => {
            let s = k.lock();
            (s.pubkey, s.privkey.clone())
        }
        None => ([0; ecx::MAX_KEYLEN], None),
    };
    let mut privkey = privkey;
    let ok = (|| {
        if private {
            let Some(d) = privkey.as_deref() else {
                return line(c"%*s<INVALID PRIVATE KEY>\n");
            };
            if !line(c"%*s%s Private-Key:\n") || !line(c"%*spriv:\n") {
                return false;
            }
            // SAFETY: the caller's BIO; the key's octets.
            if unsafe { ASN1_buf_print(bp, d.as_ptr(), d.len().min(n), sub) } == 0 {
                return false;
            }
        } else {
            if k.is_none() {
                return line(c"%*s<INVALID PUBLIC KEY>\n");
            }
            if !line(c"%*s%s Public-Key:\n") {
                return false;
            }
        }
        if !line(c"%*spub:\n") {
            return false;
        }
        let q = public.get(..n).unwrap_or_default();
        // SAFETY: the caller's BIO; the key's octets.
        (unsafe { ASN1_buf_print(bp, q.as_ptr(), q.len(), sub) }) != 0
    })();
    if let Some(d) = privkey.as_mut() {
        wipe(d);
    }
    c_int::from(ok)
}

ffi_callback! {
    /// `ecx_priv_print`.
    ///
    /// # Safety
    /// `bp` is a live BIO; `p` is a live key of the method's type.
    pub(crate) unsafe extern "C" fn ecx_priv_print(bp: *mut BIO, p: *const EVP_PKEY, indent: c_int, _ctx: *mut ASN1_PCTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { key_print(bp, p, indent, true) }
    }
}

ffi_callback! {
    /// `ecx_pub_print`.
    ///
    /// # Safety
    /// `bp` is a live BIO; `p` is a live key of the method's type.
    pub(crate) unsafe extern "C" fn ecx_pub_print(bp: *mut BIO, p: *const EVP_PKEY, indent: c_int, _ctx: *mut ASN1_PCTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { key_print(bp, p, indent, false) }
    }
}

ffi_callback! {
    /// `ecx_ctrl`: the TLS encoded point (the raw public key) set (a new ECX key) or got (a
    /// copy, with its length); -2 for other controls.
    ///
    /// # Safety
    /// `p` is a live key of the method's type; for a set, `arg2` holds `arg1` octets; for a get,
    /// `arg2` is a writable `unsigned char *`.
    pub(crate) unsafe extern "C" fn ecx_ctrl(p: *mut EVP_PKEY, op: c_int, arg1: c_long, arg2: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        match op {
            ASN1_PKEY_CTRL_SET1_TLS_ENCPT => {
                // SAFETY: the caller's key.
                let Some(kind) = (unsafe { type_of(p) }) else { return 0 };
                let Ok(n) = usize::try_from(arg1) else {
                    err::raise(ERR_LIB_EC, rustyssl_abi::EC_R_INVALID_ENCODING, "ossl_ecx_key_op");
                    return 0;
                };
                // SAFETY: the caller's guarantee.
                let Some(q) = (unsafe { bytes(arg2.cast::<u8>(), n) }) else {
                    err::raise(ERR_LIB_EC, rustyssl_abi::EC_R_INVALID_ENCODING, "ossl_ecx_key_op");
                    return 0;
                };
                let h = ecx::key_op(ptr::null_mut(), kind, &KeyOp::Public(q), None);
                // SAFETY: the caller's key; the new ECX key.
                unsafe { assign(p, h) }
            }
            ASN1_PKEY_CTRL_GET1_TLS_ENCPT => {
                // SAFETY: the caller's key.
                let Some(k) = (unsafe { data(p) }) else { return 0 };
                let public = k.public();
                let out = mem::alloc(public.len());
                if out.is_null() {
                    return 0;
                }
                // SAFETY: the allocation just made, of the key's length.
                unsafe { ptr::copy_nonoverlapping(public.as_ptr(), out.cast::<u8>(), public.len()) };
                // SAFETY: the caller's guarantee.
                unsafe { arg2.cast::<*mut c_uchar>().write(out.cast()) };
                c_int::try_from(public.len()).unwrap_or(0)
            }
            _ => -2,
        }
    }
}

ffi_callback! {
    /// `ecd_ctrl`: no default digest (pure EdDSA), as 2 (mandatory); -2 for other controls.
    ///
    /// # Safety
    /// For the default digest, `arg2` is a writable `int`.
    pub(crate) unsafe extern "C" fn ecd_ctrl(_p: *mut EVP_PKEY, op: c_int, _arg1: c_long, arg2: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        if op == ASN1_PKEY_CTRL_DEFAULT_MD_NID {
            // SAFETY: the caller's guarantee.
            unsafe { arg2.cast::<c_int>().write(NID_undef) };
            return 2;
        }
        -2
    }
}

/// `ecx_set_priv_key` and `ecx_set_pub_key`: a new ECX key from a raw key.
///
/// # Safety
/// `p` is a live key of the method's type; `raw` holds `len` octets.
unsafe fn set_raw(p: *mut EVP_PKEY, raw: *const c_uchar, len: usize, private: bool) -> c_int {
    // SAFETY: the caller's key.
    let Some(kind) = (unsafe { type_of(p) }) else {
        return 0;
    };
    // SAFETY: the caller's guarantee.
    let Some(d) = (unsafe { bytes(raw, len) }) else {
        err::raise(
            ERR_LIB_EC,
            rustyssl_abi::EC_R_INVALID_ENCODING,
            "ossl_ecx_key_op",
        );
        return 0;
    };
    let op = if private {
        KeyOp::Private(d)
    } else {
        KeyOp::Public(d)
    };
    // SAFETY: the caller's key.
    let libctx = unsafe { super::keymgmt_libctx(p) };
    let h = ecx::key_op(libctx, kind, &op, None);
    // SAFETY: the caller's key; the new ECX key.
    unsafe { assign(p, h) }
}

ffi_callback! {
    /// `ecx_set_priv_key`.
    ///
    /// # Safety
    /// `p` is a live key of the method's type; `priv_` holds `len` octets.
    pub(crate) unsafe extern "C" fn ecx_set_priv_key(p: *mut EVP_PKEY, priv_: *const c_uchar, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_raw(p, priv_, len, true) }
    }
}

ffi_callback! {
    /// `ecx_set_pub_key`.
    ///
    /// # Safety
    /// `p` is a live key of the method's type; `pub_` holds `len` octets.
    pub(crate) unsafe extern "C" fn ecx_set_pub_key(p: *mut EVP_PKEY, pub_: *const c_uchar, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_raw(p, pub_, len, false) }
    }
}

/// `ecx_get_priv_key` and `ecx_get_pub_key`: the key's length when `out` is NULL, else the key
/// into `out` (with room for `*len` octets).
///
/// # Safety
/// `p` is a live key of the method's type; `out` is NULL or has room for `*len` octets; `len`
/// is a live `size_t`.
unsafe fn get_raw(p: *const EVP_PKEY, out: *mut c_uchar, len: *mut usize, private: bool) -> c_int {
    // SAFETY: the caller's key.
    let n = unsafe { keylen(p) };
    if out.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { len.write(n) };
        return 1;
    }
    // SAFETY: the caller's key.
    let Some(k) = (unsafe { data(p) }) else {
        return 0;
    };
    // SAFETY: the caller's guarantee.
    if unsafe { len.read() } < n {
        return 0;
    }
    let mut v = {
        let s = k.lock();
        if private {
            match s.privkey.as_deref() {
                Some(d) => d.to_vec(),
                None => return 0,
            }
        } else {
            s.pubkey.get(..n).unwrap_or_default().to_vec()
        }
    };
    let ok = v.len() == n;
    if ok {
        // SAFETY: the caller's room for at least `n` octets.
        unsafe { ptr::copy_nonoverlapping(v.as_ptr(), out, n) };
        // SAFETY: the caller's guarantee.
        unsafe { len.write(n) };
    }
    wipe(&mut v);
    c_int::from(ok)
}

ffi_callback! {
    /// `ecx_get_priv_key`.
    ///
    /// # Safety
    /// As for `get_raw`.
    pub(crate) unsafe extern "C" fn ecx_get_priv_key(p: *const EVP_PKEY, priv_: *mut c_uchar, len: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { get_raw(p, priv_, len, true) }
    }
}

ffi_callback! {
    /// `ecx_get_pub_key`.
    ///
    /// # Safety
    /// As for `get_raw`.
    pub(crate) unsafe extern "C" fn ecx_get_pub_key(p: *const EVP_PKEY, pub_: *mut c_uchar, len: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { get_raw(p, pub_, len, false) }
    }
}

/// `ecx_pkey_dirty_cnt`: an ECX key never changes once set.
///
/// # Safety
/// No preconditions.
pub(crate) unsafe fn ecx_pkey_dirty_cnt(_p: *const EVP_PKEY) -> usize {
    1
}

/// `ecx_pkey_export_to`: the public key and, if there is one, the private key, to `importer`.
///
/// # Safety
/// `from` is a live key with ECX legacy data.
pub(crate) unsafe fn ecx_pkey_export_to(
    from: *const EVP_PKEY,
    importer: &mut dyn FnMut(c_int, *const OSSL_PARAM) -> c_int,
) -> c_int {
    // SAFETY: the method's key.
    let Some(k) = (unsafe { data(from) }) else {
        return 0;
    };
    let keylen = k.keylen();
    let (public, mut private) = {
        let s = k.lock();
        (s.pubkey, s.privkey.clone())
    };
    // SAFETY: no preconditions.
    let bld = unsafe { OSSL_PARAM_BLD_new() };
    if bld.is_null() {
        return 0;
    }
    let mut selection = OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    // SAFETY: the builder; a static name; octets that outlive the array's making.
    let mut ok = unsafe {
        OSSL_PARAM_BLD_push_octet_string(
            bld,
            OSSL_PKEY_PARAM_PUB_KEY.as_ptr(),
            public.as_ptr().cast(),
            keylen,
        )
    } != 0;
    if ok && let Some(d) = private.as_ref() {
        // SAFETY: as above.
        ok = unsafe {
            OSSL_PARAM_BLD_push_octet_string(
                bld,
                OSSL_PKEY_PARAM_PRIV_KEY.as_ptr(),
                d.as_ptr().cast(),
                keylen,
            )
        } != 0;
        selection |= OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    }
    let mut rv = 0;
    if ok {
        // SAFETY: the builder; what it reads is kept until here.
        let params = unsafe { OSSL_PARAM_BLD_to_param(bld) };
        rv = importer(selection, params);
        // SAFETY: the array made above, or NULL.
        unsafe { OSSL_PARAM_free(params) };
    }
    // SAFETY: the builder made above.
    unsafe { OSSL_PARAM_BLD_free(bld) };
    if let Some(d) = private.as_mut() {
        wipe(d);
    }
    rv
}

/// `ecx_generic_import_from`: a new ECX key of `to`'s type from `params` (the private key
/// included), assigned to `to`.
///
/// # Safety
/// `params` is a parameter array; `to` is a live key of the method's type.
pub(crate) unsafe fn ecx_pkey_import_from(
    params: *const OSSL_PARAM,
    to: *mut EVP_PKEY,
    libctx: *mut OSSL_LIB_CTX,
) -> c_int {
    // SAFETY: the caller's key.
    let Some(kind) = (unsafe { type_of(to) }) else {
        return 0;
    };
    let h = ecx::new(libctx, kind, None);
    // SAFETY: the key just made.
    let Some(k) = (unsafe { ecx::key(h) }) else {
        err::raise(ERR_LIB_EC, ERR_R_EC_LIB, "ecx_generic_import_from");
        return 0;
    };
    // SAFETY: the key; the caller's array.
    if !unsafe { ecx::key_fromdata(k, params, true) } {
        // SAFETY: the key made above.
        unsafe { ecx::free(h) };
        return 0;
    }
    // SAFETY: the caller's key; the ECX key, which it takes.
    unsafe { assign(to, h) }
}

ffi_callback! {
    /// `ecx_pkey_copy`: `to` gets a copy of `from`'s ECX key (or just its type without one). 1,
    /// or 0.
    ///
    /// # Safety
    /// `to` and `from` are live keys; `from`'s legacy data, if any, is an ECX key.
    pub(crate) unsafe extern "C" fn ecx_pkey_copy(to: *mut EVP_PKEY, from: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's key.
        let copy = unsafe { data(from) }.map_or(ptr::null_mut(), |k| ecx::dup(k, true, true));
        // SAFETY: as above.
        let id = unsafe { EVP_PKEY_get_id(from) };
        // SAFETY: the caller's key; the copy, which it takes, or NULL.
        let ret = unsafe { EVP_PKEY_assign(to, id, copy) };
        if ret == 0 {
            // SAFETY: the copy, not taken, or NULL.
            unsafe { ecx::free(copy) };
        }
        ret
    }
}

/// `ossl_ecx_key_op` with an AlgorithmIdentifier: its parameters must be absent, and its
/// object must be the key type `id`'s (or, for `EVP_PKEY_NONE`, gives the type); then the key
/// of `op` (a public or private key of the type's length). NULL with `EC_R_INVALID_ENCODING`.
///
/// # Safety
/// `palg` is NULL or a live AlgorithmIdentifier; `libctx` is NULL or a live library context.
pub(crate) unsafe fn key_op_algor(
    palg: *const rustyssl_abi::X509_ALGOR,
    p: Option<&[u8]>,
    mut id: c_int,
    private: bool,
    libctx: *mut rustyssl_abi::OSSL_LIB_CTX,
    propq: Option<&CStr>,
) -> *mut c_void {
    use rustyssl_abi::{EC_R_INVALID_ENCODING, ERR_LIB_EC, EVP_PKEY_NONE, V_ASN1_UNDEF};
    const F: &str = "ossl_ecx_key_op";
    if !palg.is_null() {
        let mut ptype = 0;
        // SAFETY: the caller's AlgorithmIdentifier; a local.
        unsafe {
            crate::x509::algor::X509_ALGOR_get0(
                ptr::null_mut(),
                &raw mut ptype,
                ptr::null_mut(),
                palg,
            )
        };
        if ptype != V_ASN1_UNDEF {
            err::raise(ERR_LIB_EC, EC_R_INVALID_ENCODING, F);
            return ptr::null_mut();
        }
        // SAFETY: the caller's AlgorithmIdentifier.
        let obj = unsafe { (*palg).algorithm };
        // SAFETY: its object.
        let nid = unsafe { crate::objects::OBJ_obj2nid(obj) };
        if id == EVP_PKEY_NONE {
            id = nid;
        } else if id != nid {
            err::raise(ERR_LIB_EC, EC_R_INVALID_ENCODING, F);
            return ptr::null_mut();
        }
    }
    let (Some(kind), Some(p)) = (ecx::type_of(id), p) else {
        err::raise(ERR_LIB_EC, EC_R_INVALID_ENCODING, F);
        return ptr::null_mut();
    };
    let op = if private {
        KeyOp::Private(p)
    } else {
        KeyOp::Public(p)
    };
    ecx::key_op(libctx, kind, &op, propq)
}

ffi_callback! {
    /// `ecx_pub_encode`: the raw public key, with the type's object and no parameters.
    ///
    /// # Safety
    /// `pk` is a live SubjectPublicKeyInfo; `pkey` is a live ECX key.
    pub(crate) unsafe extern "C" fn ecx_pub_encode(pk: *mut rustyssl_abi::X509_PUBKEY, pkey: *const EVP_PKEY) -> c_int
    where failure = 0, library = rustyssl_abi::ERR_LIB_EC
    {
        use rustyssl_abi::{EC_R_INVALID_KEY, ERR_LIB_EC, ERR_R_X509_LIB, V_ASN1_UNDEF};
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { data(pkey) }) else {
            err::raise(ERR_LIB_EC, EC_R_INVALID_KEY, "ecx_pub_encode");
            return 0;
        };
        // SAFETY: as above.
        let len = unsafe { keylen(pkey) };
        let penc: *mut c_uchar = crate::mem::alloc(len.max(1)).cast();
        if penc.is_null() {
            return 0;
        }
        {
            let s = k.lock();
            let src = s.pubkey.get(..len).unwrap_or_default();
            // SAFETY: a block of `len` octets; the key's.
            unsafe { ptr::copy_nonoverlapping(src.as_ptr(), penc, src.len()) };
        }
        // SAFETY: the caller's key.
        let id = unsafe { EVP_PKEY_get_id(pkey) };
        // SAFETY: no preconditions.
        let obj = unsafe { crate::objects::OBJ_nid2obj(id) };
        let n = c_int::try_from(len).unwrap_or(0);
        // SAFETY: the caller's structure takes the object and octets.
        if unsafe { crate::x509::pubkey::X509_PUBKEY_set0_param(pk, obj, V_ASN1_UNDEF, ptr::null_mut(), penc, n) } == 0 {
            // SAFETY: made above.
            unsafe { crate::mem::release(penc.cast()) };
            err::raise(ERR_LIB_EC, ERR_R_X509_LIB, "ecx_pub_encode");
            return 0;
        }
        1
    }
}

ffi_callback! {
    /// `ecx_pub_decode`: the raw public key of the key's type (the AlgorithmIdentifier
    /// checked), assigned to the key.
    ///
    /// # Safety
    /// `pkey` is a live key typed X25519, X448, ED25519, or ED448; `pubkey` is a live
    /// SubjectPublicKeyInfo.
    pub(crate) unsafe extern "C" fn ecx_pub_decode(pkey: *mut EVP_PKEY, pubkey: *const rustyssl_abi::X509_PUBKEY) -> c_int
    where failure = 0, library = rustyssl_abi::ERR_LIB_EC
    {
        let (mut p, mut pklen, mut palg) = (ptr::null(), 0, ptr::null_mut());
        // SAFETY: the caller's structure; locals.
        if unsafe { crate::x509::pubkey::X509_PUBKEY_get0_param(ptr::null_mut(), &raw mut p, &raw mut pklen, &raw mut palg, pubkey) } == 0 {
            return 0;
        }
        let len = usize::try_from(pklen).unwrap_or(0);
        // SAFETY: the structure's `pklen` octets.
        let key = unsafe { bytes(p, len) };
        // SAFETY: the caller's key.
        let id = unsafe { EVP_PKEY_get_id(pkey) };
        // SAFETY: the structure's AlgorithmIdentifier.
        let h = unsafe { key_op_algor(palg, key, id, false, ptr::null_mut(), None) };
        // SAFETY: the caller's key; the new ECX key, or NULL.
        unsafe { assign(pkey, h) }
    }
}

/// `ossl_ecx_key_from_pkcs8`: a PrivateKeyInfo's private key (an OCTET STRING of the type's
/// length) as a key of the AlgorithmIdentifier's type, in `libctx` with `propq`, or NULL.
///
/// # Safety
/// `p8` is a live PrivateKeyInfo; `libctx` is NULL or a live library context.
pub(crate) unsafe fn key_from_pkcs8(
    p8: *const rustyssl_abi::PKCS8_PRIV_KEY_INFO,
    libctx: *mut rustyssl_abi::OSSL_LIB_CTX,
    propq: Option<&CStr>,
) -> *mut c_void {
    use rustyssl_abi::EVP_PKEY_NONE;
    let (mut p, mut plen, mut palg) = (ptr::null(), 0, ptr::null());
    // SAFETY: the caller's structure; locals.
    if unsafe {
        crate::x509::p8::PKCS8_pkey_get0(
            ptr::null_mut(),
            &raw mut p,
            &raw mut plen,
            &raw mut palg,
            p8,
        )
    } == 0
    {
        return ptr::null_mut();
    }
    // SAFETY: the structure's `plen` octets.
    let oct = unsafe {
        crate::asn1::tpl::items::d2i_ASN1_OCTET_STRING(
            ptr::null_mut(),
            &raw mut p,
            c_long::from(plen),
        )
    };
    // SAFETY: the decoded string, or NULL.
    let key = unsafe { oct.as_ref() }.map(|o| {
        // SAFETY: the string's octets.
        unsafe { bytes(o.data, usize::try_from(o.length).unwrap_or(0)) }.unwrap_or(&[])
    });
    // SAFETY: the structure's AlgorithmIdentifier; the caller's guarantee.
    let h = unsafe { key_op_algor(palg, key, EVP_PKEY_NONE, true, libctx, propq) };
    // SAFETY: decoded above, or NULL.
    unsafe { crate::asn1::string::ASN1_STRING_clear_free(oct) };
    h
}

ffi_callback! {
    /// `ecx_priv_decode_ex`: a PrivateKeyInfo's key, in a library context, assigned to the key.
    ///
    /// # Safety
    /// `pkey` is a live key typed X25519, X448, ED25519, or ED448; `p8` is a live
    /// PrivateKeyInfo; `libctx` is NULL or a live library context; `propq` is NULL or a string.
    pub(crate) unsafe extern "C" fn ecx_priv_decode_ex(pkey: *mut EVP_PKEY, p8: *const rustyssl_abi::PKCS8_PRIV_KEY_INFO, libctx: *mut rustyssl_abi::OSSL_LIB_CTX, propq: *const core::ffi::c_char) -> c_int
    where failure = 0, library = rustyssl_abi::ERR_LIB_EC
    {
        // SAFETY: NULL or the caller's string.
        let propq = (!propq.is_null()).then(|| unsafe { CStr::from_ptr(propq) });
        // SAFETY: the caller's guarantee.
        let h = unsafe { key_from_pkcs8(p8, libctx, propq) };
        // SAFETY: the caller's key; the new ECX key, or NULL.
        unsafe { assign(pkey, h) }
    }
}

ffi_callback! {
    /// `ecx_priv_encode`: the raw private key as an OCTET STRING, with the type's object and no
    /// parameters.
    ///
    /// # Safety
    /// `p8` is a live PrivateKeyInfo; `pkey` is a live ECX key.
    pub(crate) unsafe extern "C" fn ecx_priv_encode(p8: *mut rustyssl_abi::PKCS8_PRIV_KEY_INFO, pkey: *const EVP_PKEY) -> c_int
    where failure = 0, library = rustyssl_abi::ERR_LIB_EC
    {
        use rustyssl_abi::{EC_R_INVALID_PRIVATE_KEY, ERR_LIB_EC, ERR_R_ASN1_LIB, V_ASN1_UNDEF};
        const F: &str = "ecx_priv_encode";
        // SAFETY: the caller's guarantee.
        let k = unsafe { data(pkey) };
        let Some(mut privkey) = k.and_then(|k| k.lock().privkey.clone()) else {
            err::raise(ERR_LIB_EC, EC_R_INVALID_PRIVATE_KEY, F);
            return 0;
        };
        let penc = (|| {
            let n = c_int::try_from(privkey.len()).ok()?;
            // The DER OCTET STRING: its tag, a short-form length, and the key (at most 57 octets).
            let mut der = vec![0x04, u8::try_from(n).ok().filter(|&l| l < 0x80)?];
            der.extend_from_slice(&privkey);
            let out: *mut c_uchar = mem::alloc(der.len()).cast();
            if out.is_null() {
                wipe(&mut der);
                return None;
            }
            // SAFETY: room for the encoding.
            unsafe { ptr::copy_nonoverlapping(der.as_ptr(), out, der.len()) };
            let len = c_int::try_from(der.len()).ok();
            wipe(&mut der);
            Some((out, len?))
        })();
        wipe(&mut privkey);
        let Some((penc, penclen)) = penc else {
            err::raise(ERR_LIB_EC, ERR_R_ASN1_LIB, F);
            return 0;
        };
        // SAFETY: the caller's key.
        let id = unsafe { EVP_PKEY_get_id(pkey) };
        // SAFETY: no preconditions.
        let obj = unsafe { crate::objects::OBJ_nid2obj(id) };
        // SAFETY: the caller's structure takes the object and octets.
        if unsafe { crate::x509::p8::PKCS8_pkey_set0(p8, obj, 0, V_ASN1_UNDEF, ptr::null_mut(), penc, penclen) } != 0 {
            return 1;
        }
        // SAFETY: made above, `penclen` octets.
        unsafe { mem::release_clean(penc.cast(), usize::try_from(penclen).unwrap_or(0)) };
        err::raise(ERR_LIB_EC, ERR_R_ASN1_LIB, F);
        0
    }
}

/// `evp_pkey_get1_ECX_KEY`: the key's ECX key with a new reference when the key's type is
/// `type_` (`EVP_R_EXPECTING_A_ECX_KEY` otherwise), or NULL.
///
/// # Safety
/// `p` is a live key.
pub(crate) unsafe fn get1_ecx_key(p: *mut EVP_PKEY, type_: c_int) -> *mut c_void {
    use rustyssl_abi::{ERR_LIB_EVP, EVP_R_EXPECTING_A_ECX_KEY};
    // SAFETY: the caller's guarantee.
    if unsafe { super::EVP_PKEY_get_base_id(p) } != type_ {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_EXPECTING_A_ECX_KEY,
            "evp_pkey_get0_ECX_KEY",
        );
        return ptr::null_mut();
    }
    // SAFETY: as above.
    let d = unsafe { super::pkey(p) }.map_or(ptr::null_mut(), super::get_legacy);
    if !d.is_null() {
        // SAFETY: the key's ECX key.
        unsafe { ecx::up_ref(d) };
    }
    d
}
