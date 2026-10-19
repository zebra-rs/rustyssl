//! The default provider's DH key exchange (`dh_exch.c`): the shared secret of a key and a
//! peer's with the same domain parameters (through the key's method, so an application's
//! `DH_METHOD` computes it), unpadded or padded to the prime's length (`pad`), and optionally
//! through X9.42's KDF in its ASN.1 form (`kdf-type` `X942KDF-ASN1`, with its digest, output
//! length, user keying material, and key-wrap algorithm, from the padded secret).
//!
//! The context follows OpenSSL's: an init resets the KDF type but keeps the padding and the
//! KDF's other settings; a digest refused as an XOF stays set, and one that can't be fetched
//! leaves none; the peer's parameters must match the key's, q compared only when the peer has
//! one.

use core::ffi::{CStr, c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    DH, ERR_LIB_PROV, OSSL_EXCHANGE_PARAM_KDF_DIGEST, OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS,
    OSSL_EXCHANGE_PARAM_KDF_OUTLEN, OSSL_EXCHANGE_PARAM_KDF_TYPE, OSSL_EXCHANGE_PARAM_KDF_UKM,
    OSSL_EXCHANGE_PARAM_PAD, OSSL_FUNC_KEYEXCH_DERIVE, OSSL_FUNC_KEYEXCH_DUPCTX,
    OSSL_FUNC_KEYEXCH_FREECTX, OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,
    OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, OSSL_FUNC_KEYEXCH_INIT, OSSL_FUNC_KEYEXCH_NEWCTX,
    OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, OSSL_FUNC_KEYEXCH_SET_PEER,
    OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, OSSL_KDF_NAME_X942KDF_ASN1, OSSL_KDF_PARAM_CEK_ALG,
    OSSL_LIB_CTX, OSSL_PARAM, OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_PTR, OSSL_PARAM_OCTET_STRING,
    OSSL_PARAM_UNSIGNED_INTEGER, OSSL_PARAM_UTF8_STRING, PROV_R_MISMATCHING_DOMAIN_PARAMETERS,
    PROV_R_MISSING_KEY, PROV_R_OUTPUT_BUFFER_TOO_SMALL, PROV_R_XOF_DIGESTS_NOT_ALLOWED,
};

use super::builtin::libctx_of;
use super::macs::{INT, SIZE_T, boxed, context, is_empty, locate, unbox, wipe};
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::dh::{DH_get0_pub_key, DH_size, dh, free, up_ref};
use crate::dh_meth::{DH_compute_key, DH_compute_key_padded};
use crate::dh_ops::kdf_x9_42_asn1;
use crate::err;
use crate::evp::digest::EVP_MD_get0_name;
use crate::evp::md_ctx::EVP_MD_xof;
use crate::ffi::{bytes, ffi_callback};
use crate::mem;
use crate::params::{
    OSSL_PARAM_get_octet_string, OSSL_PARAM_get_size_t, OSSL_PARAM_get_uint,
    OSSL_PARAM_get_utf8_string, OSSL_PARAM_locate, OSSL_PARAM_set_octet_ptr, OSSL_PARAM_set_size_t,
    OSSL_PARAM_set_utf8_string,
};
use crate::rsa::Md;

/// The size of the name buffers `dh_set_ctx_params` reads into.
const NAME: usize = 80;

/// `PROV_DH_CTX`.
struct DhCtx {
    libctx: *mut OSSL_LIB_CTX,
    /// The key and the peer's, each with a reference this holds, or NULL.
    dh: *mut DH,
    dhpeer: *mut DH,
    pad: bool,
    /// Whether X9.42's KDF derives from the shared secret.
    kdf_x942: bool,
    kdf_md: Option<Md>,
    kdf_ukm: Option<Vec<u8>>,
    kdf_outlen: usize,
    kdf_cekalg: Option<CString>,
}

impl Drop for DhCtx {
    fn drop(&mut self) {
        // SAFETY: the references this holds, or NULL.
        unsafe { free(self.dh) };
        // SAFETY: as above.
        unsafe { free(self.dhpeer) };
        if let Some(u) = self.kdf_ukm.as_mut() {
            wipe(u);
        }
    }
}

/// The context behind `vctx`.
///
/// # Safety
/// `vctx` is NULL or a live context from `dh_newctx`.
unsafe fn ctx<'a>(vctx: *mut c_void) -> Option<&'a mut DhCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { context::<DhCtx>(vctx) }
}

ffi_callback! {
    /// `dh_newctx`.
    ///
    /// # Safety
    /// `provctx` is the default provider's context.
    pub(crate) unsafe extern "C" fn dh_newctx(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        boxed(DhCtx {
            // SAFETY: the caller's guarantee.
            libctx: unsafe { libctx_of(provctx) },
            dh: ptr::null_mut(),
            dhpeer: ptr::null_mut(),
            pad: false,
            kdf_x942: false,
            kdf_md: None,
            kdf_ukm: None,
            kdf_outlen: 0,
            kdf_cekalg: None,
        })
    }
}

ffi_callback! {
    /// `dh_init`: the key, the KDF type reset, then the parameters.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `vdh` is NULL or a live DH key; `params` is NULL or an
    /// array.
    pub(crate) unsafe extern "C" fn dh_init(vctx: *mut c_void, vdh: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        let k = vdh.cast::<DH>();
        // SAFETY: the caller's key, or NULL.
        if k.is_null() || !unsafe { up_ref(k) } {
            return 0;
        }
        // SAFETY: the reference the context held, or NULL.
        unsafe { free(c.dh) };
        c.dh = k;
        c.kdf_x942 = false;
        // SAFETY: the caller's guarantee.
        unsafe { dh_set_ctx_params(vctx, params) }
    }
}

/// `dh_match_params`: whether the keys share p and g, and q when `priv_` has one (raising
/// `PROV_R_MISMATCHING_DOMAIN_PARAMETERS` if not).
///
/// # Safety
/// `priv_` and `peer` are NULL or live keys.
unsafe fn match_params(priv_: *const DH, peer: *const DH) -> bool {
    // SAFETY: the caller's guarantee.
    let (a, b) = (unsafe { dh(priv_) }, unsafe { dh(peer) });
    let ok = match (a, b) {
        (Some(a), Some(b)) => {
            let (sa, sb) = (a.snapshot(), b.snapshot());
            sa.params.cmp(&sb.params, sa.params.q.is_none())
        }
        _ => false,
    };
    if !ok {
        err::raise(
            ERR_LIB_PROV,
            PROV_R_MISMATCHING_DOMAIN_PARAMETERS,
            "dh_match_params",
        );
    }
    ok
}

ffi_callback! {
    /// `dh_set_peer`: the peer's key, with the key's parameters (q compared if the peer has
    /// one).
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `vdh` is NULL or a live DH key.
    pub(crate) unsafe extern "C" fn dh_set_peer(vctx: *mut c_void, vdh: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        let peer = vdh.cast::<DH>();
        // SAFETY: the caller's key and the context's.
        if peer.is_null() || !unsafe { match_params(peer, c.dh) } {
            return 0;
        }
        // SAFETY: the caller's key.
        if !unsafe { up_ref(peer) } {
            return 0;
        }
        // SAFETY: the reference the context held, or NULL.
        unsafe { free(c.dhpeer) };
        c.dhpeer = peer;
        1
    }
}

ffi_callback! {
    /// `dh_freectx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context the caller gives up.
    pub(crate) unsafe extern "C" fn dh_freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<DhCtx>(vctx) };
    }
}

ffi_callback! {
    /// `dh_dupctx`: references to the keys and digest, copies of the keying material and the
    /// key-wrap algorithm.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context.
    pub(crate) unsafe extern "C" fn dh_dupctx(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return ptr::null_mut() };
        let mut copy = DhCtx {
            libctx: c.libctx,
            dh: ptr::null_mut(),
            dhpeer: ptr::null_mut(),
            pad: c.pad,
            kdf_x942: c.kdf_x942,
            kdf_md: c.kdf_md.clone(),
            kdf_ukm: c.kdf_ukm.clone().filter(|u| !u.is_empty()),
            kdf_outlen: c.kdf_outlen,
            kdf_cekalg: c.kdf_cekalg.clone(),
        };
        for (src, dst) in [(c.dh, &mut copy.dh), (c.dhpeer, &mut copy.dhpeer)] {
            if !src.is_null() {
                // SAFETY: the context's live key.
                if !unsafe { up_ref(src) } {
                    return ptr::null_mut();
                }
                *dst = src;
            }
        }
        boxed(copy)
    }
}

/// `OSSL_PARAM_get_utf8_string` into a buffer of `NAME` octets.
///
/// # Safety
/// `p` is a parameter.
unsafe fn read_name(p: &OSSL_PARAM) -> Option<CString> {
    let mut buf = [0 as c_char; NAME];
    let mut s = buf.as_mut_ptr();
    // SAFETY: the parameter; the buffer.
    if unsafe { OSSL_PARAM_get_utf8_string(p, &raw mut s, NAME) } != 1 {
        return None;
    }
    // SAFETY: NUL-terminated by the call.
    Some(unsafe { CStr::from_ptr(buf.as_ptr()) }.to_owned())
}

ffi_callback! {
    /// `dh_set_ctx_params`: the KDF type (none or X942KDF-ASN1), the KDF's digest (fetched
    /// with the properties given), output length, keying material (none for an empty one),
    /// padding, and key-wrap algorithm (none for an empty one).
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn dh_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { crate::provider::param_decoders::decode(params, &crate::provider::param_decoders::DH_SET_CTX_PARAMS) } {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        let find = |key: &CStr| {
            // SAFETY: the caller's array; a static name.
            unsafe { locate(params, key) }
        };
        if let Some(p) = find(OSSL_EXCHANGE_PARAM_KDF_TYPE) {
            // SAFETY: a parameter of the array.
            let Some(name) = (unsafe { read_name(p) }) else { return 0 };
            if name.is_empty() {
                c.kdf_x942 = false;
            } else if name.as_c_str() == OSSL_KDF_NAME_X942KDF_ASN1 {
                c.kdf_x942 = true;
            } else {
                return 0;
            }
        }
        if let Some(p) = find(OSSL_EXCHANGE_PARAM_KDF_DIGEST) {
            // SAFETY: a parameter of the array.
            let Some(name) = (unsafe { read_name(p) }) else { return 0 };
            let props = match find(OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS) {
                // SAFETY: as above.
                Some(q) => match unsafe { read_name(q) } {
                    Some(v) => v,
                    None => return 0,
                },
                None => CString::default(),
            };
            // SAFETY: the context's library context; a name and a query.
            c.kdf_md = unsafe { Md::fetch(c.libctx, &name, props.as_ptr()) };
            let Some(md) = c.kdf_md.as_ref() else { return 0 };
            // SAFETY: the digest.
            if unsafe { EVP_MD_xof(md.ptr()) } != 0 {
                err::raise(ERR_LIB_PROV, PROV_R_XOF_DIGESTS_NOT_ALLOWED, "dh_set_ctx_params");
                return 0;
            }
        }
        if let Some(p) = find(OSSL_EXCHANGE_PARAM_KDF_OUTLEN) {
            let mut outlen: usize = 0;
            // SAFETY: a parameter of the array; a local.
            if unsafe { OSSL_PARAM_get_size_t(p, &raw mut outlen) } != 1 {
                return 0;
            }
            c.kdf_outlen = outlen;
        }
        if let Some(p) = find(OSSL_EXCHANGE_PARAM_KDF_UKM) {
            if let Some(old) = c.kdf_ukm.as_mut() {
                wipe(old);
            }
            c.kdf_ukm = None;
            if !p.data.is_null() && p.data_size != 0 {
                let mut data: *mut c_void = ptr::null_mut();
                let mut n: usize = 0;
                // SAFETY: a parameter of the array; a place for a new allocation.
                if unsafe { OSSL_PARAM_get_octet_string(p, &raw mut data, 0, &raw mut n) } != 1 {
                    return 0;
                }
                // SAFETY: the allocation just made holds `n` octets.
                let ukm = unsafe { bytes(data.cast::<u8>(), n) }.unwrap_or_default().to_vec();
                // SAFETY: the allocation just made, freed once.
                unsafe { mem::release(data) };
                c.kdf_ukm = Some(ukm);
            }
        }
        if let Some(p) = find(OSSL_EXCHANGE_PARAM_PAD) {
            let mut pad: c_uint = 0;
            // SAFETY: a parameter of the array; a local.
            if unsafe { OSSL_PARAM_get_uint(p, &raw mut pad) } != 1 {
                return 0;
            }
            c.pad = pad != 0;
        }
        if let Some(p) = find(OSSL_KDF_PARAM_CEK_ALG) {
            c.kdf_cekalg = None;
            if !p.data.is_null() && p.data_size != 0 {
                // SAFETY: a parameter of the array.
                let Some(name) = (unsafe { read_name(p) }) else { return 0 };
                c.kdf_cekalg = Some(name);
            }
        }
        1
    }
}

/// `known_settable_ctx_params`.
static SETTABLE: Params<8> = Params([
    defn(OSSL_EXCHANGE_PARAM_PAD, OSSL_PARAM_INTEGER, INT),
    defn(OSSL_EXCHANGE_PARAM_KDF_TYPE, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_EXCHANGE_PARAM_KDF_DIGEST, OSSL_PARAM_UTF8_STRING, 0),
    defn(
        OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS,
        OSSL_PARAM_UTF8_STRING,
        0,
    ),
    defn(
        OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_EXCHANGE_PARAM_KDF_UKM, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_KDF_PARAM_CEK_ALG, OSSL_PARAM_UTF8_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `dh_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn dh_settable_ctx_params(_vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `dh_get_ctx_params`: the KDF type, digest, output length, keying material (as a pointer
    /// to the context's), and key-wrap algorithm.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn dh_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { crate::provider::param_decoders::decode(params, &crate::provider::param_decoders::DH_GET_CTX_PARAMS) } {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        let find = |key: &CStr| {
            // SAFETY: the caller's array; a static name.
            unsafe { OSSL_PARAM_locate(params, key.as_ptr()) }
        };
        let p = find(OSSL_EXCHANGE_PARAM_KDF_TYPE);
        if !p.is_null() {
            let name = if c.kdf_x942 { OSSL_KDF_NAME_X942KDF_ASN1 } else { c"" };
            // SAFETY: a parameter of the array; a static string.
            if unsafe { OSSL_PARAM_set_utf8_string(p, name.as_ptr()) } != 1 {
                return 0;
            }
        }
        let p = find(OSSL_EXCHANGE_PARAM_KDF_DIGEST);
        if !p.is_null() {
            let name = match &c.kdf_md {
                // SAFETY: the context's digest.
                Some(m) => unsafe { EVP_MD_get0_name(m.ptr()) },
                None => c"".as_ptr(),
            };
            // SAFETY: a parameter of the array; a string.
            if unsafe { OSSL_PARAM_set_utf8_string(p, name) } != 1 {
                return 0;
            }
        }
        let p = find(OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
        // SAFETY: a parameter of the array.
        if !p.is_null() && unsafe { OSSL_PARAM_set_size_t(p, c.kdf_outlen) } != 1 {
            return 0;
        }
        let p = find(OSSL_EXCHANGE_PARAM_KDF_UKM);
        if !p.is_null() {
            let (u, n) = c.kdf_ukm.as_deref().map_or((ptr::null(), 0), |u| (u.as_ptr(), u.len()));
            // SAFETY: a parameter of the array; the context's keying material, which stays in
            // place until it's set again or the context is freed.
            if unsafe { OSSL_PARAM_set_octet_ptr(p, u.cast(), n) } != 1 {
                return 0;
            }
        }
        let p = find(OSSL_KDF_PARAM_CEK_ALG);
        if !p.is_null() {
            let name = c.kdf_cekalg.as_deref().unwrap_or(c"");
            // SAFETY: a parameter of the array; a string.
            if unsafe { OSSL_PARAM_set_utf8_string(p, name.as_ptr()) } != 1 {
                return 0;
            }
        }
        1
    }
}

/// `known_gettable_ctx_params`.
static GETTABLE: Params<6> = Params([
    defn(OSSL_EXCHANGE_PARAM_KDF_TYPE, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_EXCHANGE_PARAM_KDF_DIGEST, OSSL_PARAM_UTF8_STRING, 0),
    defn(
        OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_EXCHANGE_PARAM_KDF_UKM, OSSL_PARAM_OCTET_PTR, 0),
    defn(OSSL_KDF_PARAM_CEK_ALG, OSSL_PARAM_UTF8_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `dh_gettable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn dh_gettable_ctx_params(_vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        GETTABLE.0.as_ptr()
    }
}

/// `dh_plain_derive`: the shared secret (padded to the prime's length if `pad`) into `secret`,
/// which must have room for that length, or the length for NULL `secret`.
///
/// # Safety
/// `secret` is NULL or has room for `outlen` octets; `psecretlen` is writable.
unsafe fn plain_derive(
    c: &DhCtx,
    secret: *mut c_uchar,
    psecretlen: *mut usize,
    outlen: usize,
    pad: bool,
) -> c_int {
    if c.dh.is_null() || c.dhpeer.is_null() {
        err::raise(ERR_LIB_PROV, PROV_R_MISSING_KEY, "dh_plain_derive");
        return 0;
    }
    // SAFETY: the context's key.
    let size = unsafe { DH_size(c.dh) };
    // `(size_t)DH_size(dh)`: a key without a prime (-1) gives the largest size.
    let dhsize = usize::try_from(size).unwrap_or(usize::MAX);
    if secret.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { psecretlen.write(dhsize) };
        return 1;
    }
    if outlen < dhsize {
        err::raise(
            ERR_LIB_PROV,
            PROV_R_OUTPUT_BUFFER_TOO_SMALL,
            "dh_plain_derive",
        );
        return 0;
    }
    // SAFETY: the peer's key.
    let pub_key = unsafe { DH_get0_pub_key(c.dhpeer) };
    let ret = if pad {
        // SAFETY: the caller's room for the prime's length; the peer's number, or NULL; the key.
        unsafe { DH_compute_key_padded(secret, pub_key, c.dh) }
    } else {
        // SAFETY: as above.
        unsafe { DH_compute_key(secret, pub_key, c.dh) }
    };
    let Some(n) = usize::try_from(ret).ok().filter(|&n| n > 0) else {
        return 0;
    };
    // SAFETY: the caller's guarantee.
    unsafe { psecretlen.write(n) };
    1
}

/// `dh_X9_42_kdf_derive`: X9.42's KDF (ASN.1) of the padded shared secret, `kdf_outlen`
/// octets.
///
/// # Safety
/// As for `plain_derive`.
unsafe fn x942_derive(
    c: &DhCtx,
    secret: *mut c_uchar,
    psecretlen: *mut usize,
    outlen: usize,
) -> c_int {
    if secret.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { psecretlen.write(c.kdf_outlen) };
        return 1;
    }
    if c.kdf_outlen > outlen {
        err::raise(
            ERR_LIB_PROV,
            PROV_R_OUTPUT_BUFFER_TOO_SMALL,
            "dh_X9_42_kdf_derive",
        );
        return 0;
    }
    let mut zlen = 0;
    // SAFETY: a local.
    if unsafe { plain_derive(c, ptr::null_mut(), &raw mut zlen, 0, true) } != 1 {
        return 0;
    }
    // A key without a prime gives the largest size, which can't be allocated.
    let mut z = Vec::new();
    if z.try_reserve_exact(zlen).is_err() {
        return 0;
    }
    z.resize(zlen, 0);
    // SAFETY: room for `zlen` octets; a local.
    let mut ok = unsafe { plain_derive(c, z.as_mut_ptr(), &raw mut zlen, zlen, true) } == 1;
    if ok {
        let md = c
            .kdf_md
            .as_ref()
            .map_or(ptr::null(), |m| m.ptr().cast_const());
        let cek = c.kdf_cekalg.as_deref().map_or(ptr::null(), CStr::as_ptr);
        let z_used = z.get(..zlen).unwrap_or(&z);
        // SAFETY: the caller's room (at least `kdf_outlen`); the digest, or NULL; the
        // algorithm's name, or NULL; the context's library context.
        ok = unsafe {
            kdf_x9_42_asn1(
                secret,
                c.kdf_outlen,
                z_used,
                cek,
                c.kdf_ukm.as_deref(),
                md,
                c.libctx,
            )
        };
        if ok {
            // SAFETY: the caller's guarantee.
            unsafe { psecretlen.write(c.kdf_outlen) };
        }
    }
    wipe(&mut z);
    c_int::from(ok)
}

ffi_callback! {
    /// `dh_derive`: the shared secret, or X9.42's KDF of it.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `secret` is NULL or has room for `outlen` octets;
    /// `psecretlen` is writable.
    pub(crate) unsafe extern "C" fn dh_derive(vctx: *mut c_void, secret: *mut c_uchar, psecretlen: *mut usize, outlen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.kdf_x942 {
            // SAFETY: the caller's guarantee.
            unsafe { x942_derive(c, secret, psecretlen, outlen) }
        } else {
            // SAFETY: as above.
            unsafe { plain_derive(c, secret, psecretlen, outlen, c.pad) }
        }
    }
}

type NewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type InitFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *const OSSL_PARAM) -> c_int;
type SetPeerFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
type DeriveFn = unsafe extern "C" fn(*mut c_void, *mut c_uchar, *mut usize, usize) -> c_int;
type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
type DupCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type SetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type GetParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type ListFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;

/// `ossl_dh_keyexch_functions`.
pub(crate) static DH_KEYEXCH: Dispatch<11> = Dispatch([
    entry!(OSSL_FUNC_KEYEXCH_NEWCTX, dh_newctx, NewCtxFn),
    entry!(OSSL_FUNC_KEYEXCH_INIT, dh_init, InitFn),
    entry!(OSSL_FUNC_KEYEXCH_DERIVE, dh_derive, DeriveFn),
    entry!(OSSL_FUNC_KEYEXCH_SET_PEER, dh_set_peer, SetPeerFn),
    entry!(OSSL_FUNC_KEYEXCH_FREECTX, dh_freectx, FreeCtxFn),
    entry!(OSSL_FUNC_KEYEXCH_DUPCTX, dh_dupctx, DupCtxFn),
    entry!(
        OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,
        dh_set_ctx_params,
        SetParamsFn
    ),
    entry!(
        OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
        dh_settable_ctx_params,
        ListFn
    ),
    entry!(
        OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,
        dh_get_ctx_params,
        GetParamsFn
    ),
    entry!(
        OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS,
        dh_gettable_ctx_params,
        ListFn
    ),
    END,
]);
