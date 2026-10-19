//! The rest of the default provider's KDFs: PKCS12KDF (`pkcs12kdf.c`), KRB5KDF (`krb5kdf.c`),
//! HMAC-DRBG-KDF (`hmacdrbg_kdf.c` over `drbg_hmac.c`), and Argon2i/d/id (`argon2.c`).
//!
//! As in `kdfs.rs`, PKCS12KDF runs over `EVP_MD_CTX`, KRB5KDF over `EVP_CIPHER_CTX`, and
//! HMAC-DRBG-KDF over `EVP_MAC_CTX`, with the methods fetched from the provider's library
//! context. Argon2 fetches BLAKE2b and its MAC as the reference does (so a property query that
//! finds neither fails the same way), and computes over the KDF backend
//! (`rustyssl_crypto::kdf::argon2`) after the reference's checks. KRB5KDF's n-fold and triple
//! DES key fixup are the backend's too.

use core::ffi::{CStr, c_int, c_uchar, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    ERR_LIB_PROV, ERR_R_EVP_LIB, EVP_CIPHER, EVP_CIPHER_CTX, EVP_MAC, EVP_MAX_BLOCK_LENGTH,
    EVP_MAX_KEY_LENGTH, EVP_MD, NID_des_ede3_cbc, OSSL_ALG_PARAM_DIGEST, OSSL_FUNC_KDF_DERIVE,
    OSSL_FUNC_KDF_DUPCTX, OSSL_FUNC_KDF_FREECTX, OSSL_FUNC_KDF_GET_CTX_PARAMS,
    OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, OSSL_FUNC_KDF_NEWCTX, OSSL_FUNC_KDF_RESET,
    OSSL_FUNC_KDF_SET_CTX_PARAMS, OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, OSSL_KDF_PARAM_ARGON2_AD,
    OSSL_KDF_PARAM_ARGON2_LANES, OSSL_KDF_PARAM_ARGON2_MEMCOST, OSSL_KDF_PARAM_ARGON2_VERSION,
    OSSL_KDF_PARAM_CIPHER, OSSL_KDF_PARAM_CONSTANT, OSSL_KDF_PARAM_DIGEST,
    OSSL_KDF_PARAM_EARLY_CLEAN, OSSL_KDF_PARAM_HMACDRBG_ENTROPY, OSSL_KDF_PARAM_HMACDRBG_NONCE,
    OSSL_KDF_PARAM_ITER, OSSL_KDF_PARAM_KEY, OSSL_KDF_PARAM_MAC, OSSL_KDF_PARAM_PASSWORD,
    OSSL_KDF_PARAM_PKCS12_ID, OSSL_KDF_PARAM_PROPERTIES, OSSL_KDF_PARAM_SALT,
    OSSL_KDF_PARAM_SECRET, OSSL_KDF_PARAM_SIZE, OSSL_KDF_PARAM_THREADS, OSSL_LIB_CTX, OSSL_PARAM,
    OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UNSIGNED_INTEGER,
    OSSL_PARAM_UTF8_STRING, PROV_R_FAILED_TO_GENERATE_KEY, PROV_R_FAILED_TO_SET_PARAMETER,
    PROV_R_INVALID_CONSTANT_LENGTH, PROV_R_INVALID_DIGEST_SIZE, PROV_R_INVALID_ITERATION_COUNT,
    PROV_R_INVALID_MEMORY_SIZE, PROV_R_INVALID_MODE, PROV_R_INVALID_OUTPUT_LENGTH,
    PROV_R_INVALID_SALT_LENGTH, PROV_R_INVALID_THREAD_POOL_SIZE, PROV_R_MISSING_CIPHER,
    PROV_R_MISSING_CONSTANT, PROV_R_MISSING_KEY, PROV_R_MISSING_MAC, PROV_R_MISSING_MESSAGE_DIGEST,
    PROV_R_MISSING_PASS, PROV_R_MISSING_SALT, PROV_R_OUTPUT_BUFFER_TOO_SMALL,
    PROV_R_WRONG_FINAL_BLOCK_LENGTH, PROV_R_WRONG_OUTPUT_BUFFER_SIZE,
    PROV_R_XOF_DIGESTS_NOT_ALLOWED,
};
use rustyssl_crypto::kdf;

use super::builtin::libctx_of;
use super::kdfs::{
    CtxParamsFn, DeriveFn, DupCtxFn, FreeCtxFn, GetCtxParamsFn, MAX_MD, NewCtxFn, Ptr, ResetFn,
    Secret, SetCtxParamsFn, argon2_get_ctx_params, get_octets, macctx_load, md_size, memdup,
    pkcs12_get_ctx_params, raise, set_membuf, size_only_gettable, utf8,
};
use super::macs::{Prov, boxed, context, is_empty, locate, unbox};
use super::rands::HmacState;
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::err;
use crate::evp::cipher::{EVP_CIPHER_get_key_length, EVP_CIPHER_get_nid};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_get_block_size, EVP_CIPHER_CTX_get_key_length,
    EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_reset, EVP_CIPHER_CTX_set_key_length,
    EVP_CIPHER_CTX_set_padding, EVP_EncryptFinal_ex, EVP_EncryptInit_ex, EVP_EncryptUpdate,
};
use crate::evp::digest::{
    EVP_MD_fetch, EVP_MD_free, EVP_MD_get_block_size, EVP_MD_get_size, EVP_MD_get0_name,
};
use crate::evp::mac::{
    EVP_MAC_CTX_dup, EVP_MAC_CTX_get0_mac, EVP_MAC_fetch, EVP_MAC_free, EVP_MAC_get0_name,
};
use crate::evp::md_ctx::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new,
    EVP_MD_xof,
};
use crate::ffi::ffi_callback;
use crate::libctx::OSSL_get_max_threads;
use crate::params::{
    OSSL_PARAM_get_int, OSSL_PARAM_get_uint32, OSSL_PARAM_get_uint64, OSSL_PARAM_locate,
    OSSL_PARAM_set_size_t, OSSL_PARAM_set_utf8_string,
};

/// The caller's output buffer as a slice: empty for no octets, `None` for NULL with some.
///
/// # Safety
/// `out` is NULL or has room for `len` octets, not otherwise used while the slice lives.
unsafe fn out_slice<'a>(out: *mut c_uchar, len: usize) -> Option<&'a mut [u8]> {
    if len == 0 {
        return Some(&mut []);
    }
    if out.is_null() {
        return None;
    }
    // SAFETY: the caller's guarantee.
    Some(unsafe { core::slice::from_raw_parts_mut(out, len) })
}

/// A buffer's octets, empty for none.
fn bytes(s: Option<&Secret>) -> &[u8] {
    s.map_or(&[], |x| &x.0)
}

// -------------------------------------------------------------------------------------------
// PKCS12KDF

/// `KDF_PKCS12`.
struct Pkcs12 {
    provctx: Ptr,
    digest: Prov<EVP_MD>,
    pass: Option<Secret>,
    salt: Option<Secret>,
    iter: u64,
    id: c_int,
}

impl Pkcs12 {
    fn new(provctx: Ptr) -> Self {
        Self {
            provctx,
            digest: Prov::NONE,
            pass: None,
            salt: None,
            iter: 0,
            id: 0,
        }
    }
}

ffi_callback! {
    /// `kdf_pkcs12_new`.
    ///
    /// # Safety
    /// `provctx` is the provider's context.
    pub(crate) unsafe extern "C" fn pkcs12_new(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        boxed(Pkcs12::new(Ptr(provctx)))
    }
}

ffi_callback! {
    /// `kdf_pkcs12_free`.
    ///
    /// # Safety
    /// `vctx` is NULL or a PKCS12KDF context, not used afterwards.
    pub(crate) unsafe extern "C" fn pkcs12_free(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<Pkcs12>(vctx) };
    }
}

ffi_callback! {
    /// `kdf_pkcs12_reset`: everything cleared (no iterations, id 0).
    ///
    /// # Safety
    /// `vctx` is a live PKCS12KDF context.
    pub(crate) unsafe extern "C" fn pkcs12_reset(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { context::<Pkcs12>(vctx) } {
            *c = Pkcs12::new(c.provctx);
        }
    }
}

ffi_callback! {
    /// `kdf_pkcs12_dup`.
    ///
    /// # Safety
    /// `vctx` is a live PKCS12KDF context.
    pub(crate) unsafe extern "C" fn pkcs12_dup(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(src) = (unsafe { context::<Pkcs12>(vctx) }) else { return ptr::null_mut() };
        let (Some(salt), Some(pass)) = (memdup(&src.salt), memdup(&src.pass)) else {
            return ptr::null_mut();
        };
        let Some(digest) = src.digest.copy() else { return ptr::null_mut() };
        boxed(Pkcs12 { provctx: src.provctx, digest, pass, salt, iter: src.iter, id: src.id })
    }
}

ffi_callback! {
    /// `kdf_pkcs12_set_ctx_params`: the digest (any, XOFs too), password, salt, id, and
    /// iterations.
    ///
    /// # Safety
    /// `vctx` is a live PKCS12KDF context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn pkcs12_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { crate::provider::param_decoders::decode(params, &crate::provider::param_decoders::PKCS12_SET_CTX_PARAMS) } {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: as above.
        let Some(c) = (unsafe { context::<Pkcs12>(vctx) }) else { return 0 };
        // SAFETY: the context's provider.
        let libctx = unsafe { libctx_of(c.provctx.0) };
        // SAFETY: the caller's array.
        if !unsafe { c.digest.load(params, OSSL_ALG_PARAM_DIGEST, libctx) } {
            return 0;
        }
        for (name, slot) in [(OSSL_KDF_PARAM_PASSWORD, &mut c.pass), (OSSL_KDF_PARAM_SALT, &mut c.salt)] {
            // SAFETY: as above.
            if let Some(p) = unsafe { locate(params, name) } {
                // SAFETY: a parameter of the caller's array.
                if !unsafe { set_membuf(slot, p) } {
                    return 0;
                }
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_KDF_PARAM_PKCS12_ID) } {
            // SAFETY: a parameter of the caller's array; the context's field.
            if unsafe { OSSL_PARAM_get_int(p, &raw mut c.id) } == 0 {
                return 0;
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_KDF_PARAM_ITER) } {
            // SAFETY: as above.
            if unsafe { OSSL_PARAM_get_uint64(p, &raw mut c.iter) } == 0 {
                return 0;
            }
        }
        1
    }
}

/// `pkcs12kdf_derive`: RFC 7292 appendix B over `EVP_MD_CTX` (zero iterations count as one;
/// no salt and no password make no input, which fails as the reference's `malloc(0)` does).
///
/// # Safety
/// `md` is NULL or a live digest.
unsafe fn pkcs12_compute(
    pass: &[u8],
    salt: &[u8],
    id: c_int,
    iter: u64,
    md: *const EVP_MD,
    out: &mut [u8],
) -> bool {
    // SAFETY: no preconditions.
    let mctx = unsafe { EVP_MD_CTX_new() };
    if mctx.is_null() {
        raise(ERR_R_EVP_LIB, "pkcs12kdf_derive");
        return false;
    }
    // SAFETY: the caller's digest, or NULL (which raises).
    let vi = unsafe { EVP_MD_get_block_size(md) };
    // SAFETY: as above.
    let ui = unsafe { EVP_MD_get_size(md) };
    let ok = 'compute: {
        let (Some(u), Some(v)) = (
            usize::try_from(ui).ok().filter(|&n| n > 0),
            usize::try_from(vi).ok().filter(|&n| n > 0),
        ) else {
            raise(PROV_R_INVALID_DIGEST_SIZE, "pkcs12kdf_derive");
            break 'compute false;
        };
        let fill = |n: usize| n.div_ceil(v).checked_mul(v);
        let (Some(slen), Some(plen)) = (
            fill(salt.len()),
            if pass.is_empty() {
                Some(0)
            } else {
                fill(pass.len())
            },
        ) else {
            break 'compute false;
        };
        if slen.checked_add(plen).is_none_or(|n| n == 0) {
            break 'compute false;
        }
        let d = vec![id.to_le_bytes()[0]; v];
        let mut i = Secret(
            salt.iter()
                .copied()
                .cycle()
                .take(slen)
                .chain(pass.iter().copied().cycle().take(plen))
                .collect(),
        );
        let mut a = Secret(vec![0u8; u.max(MAX_MD)]);
        let mut b = Secret(vec![0u8; v]);
        let mut pos = 0usize;
        loop {
            // SAFETY: the context made here; the caller's digest; local buffers of their
            // lengths, `a` with room for the digest.
            let mut r = unsafe { EVP_DigestInit_ex(mctx, md, ptr::null_mut()) } != 0
                // SAFETY: as above.
                && unsafe { EVP_DigestUpdate(mctx, d.as_ptr().cast(), v) } != 0
                // SAFETY: as above.
                && unsafe { EVP_DigestUpdate(mctx, i.ptr().cast(), i.len()) } != 0
                // SAFETY: as above.
                && unsafe { EVP_DigestFinal_ex(mctx, a.0.as_mut_ptr(), ptr::null_mut()) } != 0;
            let mut n = 1u64;
            while r && n < iter {
                // SAFETY: as above.
                r = unsafe { EVP_DigestInit_ex(mctx, md, ptr::null_mut()) } != 0
                    // SAFETY: as above; `a`'s first `u` octets.
                    && unsafe { EVP_DigestUpdate(mctx, a.ptr().cast(), u) } != 0
                    // SAFETY: as above.
                    && unsafe { EVP_DigestFinal_ex(mctx, a.0.as_mut_ptr(), ptr::null_mut()) } != 0;
                n += 1;
            }
            if !r {
                break 'compute false;
            }
            let rest = out.len() - pos;
            let take = rest.min(u);
            if let (Some(dst), Some(src)) = (out.get_mut(pos..pos + take), a.0.get(..take)) {
                dst.copy_from_slice(src);
            }
            if u >= rest {
                break 'compute true;
            }
            pos += u;
            for (j, slot) in b.0.iter_mut().enumerate() {
                *slot = a.0.get(j % u).copied().unwrap_or(0);
            }
            // I_j = I_j + B + 1, for each v-octet block of I.
            for block in i.0.chunks_mut(v) {
                let mut carry = 1u16;
                for (x, &y) in block.iter_mut().rev().zip(b.0.iter().rev()) {
                    carry += u16::from(*x) + u16::from(y);
                    *x = carry.to_le_bytes()[0];
                    carry >>= 8;
                }
            }
        }
    };
    // SAFETY: the context made here.
    unsafe { EVP_MD_CTX_free(mctx) };
    ok
}

ffi_callback! {
    /// `kdf_pkcs12_derive`.
    ///
    /// # Safety
    /// `vctx` is a live PKCS12KDF context; `key` has room for `keylen` octets; `params` is
    /// NULL or a parameter array.
    pub(crate) unsafe extern "C" fn pkcs12_derive(vctx: *mut c_void, key: *mut c_uchar, keylen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { pkcs12_set_ctx_params(vctx, params) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let Some(c) = (unsafe { context::<Pkcs12>(vctx) }) else { return 0 };
        if c.pass.is_none() {
            raise(PROV_R_MISSING_PASS, "kdf_pkcs12_derive");
            return 0;
        }
        if c.salt.is_none() {
            raise(PROV_R_MISSING_SALT, "kdf_pkcs12_derive");
            return 0;
        }
        // SAFETY: the caller's room.
        let Some(out) = (unsafe { out_slice(key, keylen) }) else { return 0 };
        // SAFETY: the context's digest, or NULL.
        c_int::from(unsafe { pkcs12_compute(bytes(c.pass.as_ref()), bytes(c.salt.as_ref()), c.id, c.iter, c.digest.method, out) })
    }
}

static PKCS12_SETTABLE: Params<7> = Params([
    defn(
        OSSL_KDF_PARAM_PROPERTIES,
        OSSL_PARAM_UTF8_STRING as c_int,
        0,
    ),
    defn(OSSL_KDF_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_PASSWORD, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_SALT, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(
        OSSL_KDF_PARAM_ITER,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        size_of::<u64>(),
    ),
    defn(
        OSSL_KDF_PARAM_PKCS12_ID,
        OSSL_PARAM_INTEGER as c_int,
        size_of::<c_int>(),
    ),
    PARAM_END,
]);

ffi_callback! {
    /// `kdf_pkcs12_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn pkcs12_settable(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        PKCS12_SETTABLE.0.as_ptr()
    }
}

pub(super) static PKCS12_FUNCTIONS: Dispatch<10> = Dispatch([
    entry!(OSSL_FUNC_KDF_NEWCTX, pkcs12_new, NewCtxFn),
    entry!(OSSL_FUNC_KDF_DUPCTX, pkcs12_dup, DupCtxFn),
    entry!(OSSL_FUNC_KDF_FREECTX, pkcs12_free, FreeCtxFn),
    entry!(OSSL_FUNC_KDF_RESET, pkcs12_reset, ResetFn),
    entry!(OSSL_FUNC_KDF_DERIVE, pkcs12_derive, DeriveFn),
    entry!(
        OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        pkcs12_settable,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_SET_CTX_PARAMS,
        pkcs12_set_ctx_params,
        SetCtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        size_only_gettable,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_GET_CTX_PARAMS,
        pkcs12_get_ctx_params,
        GetCtxParamsFn
    ),
    END,
]);

// -------------------------------------------------------------------------------------------
// KRB5KDF

/// `KRB5KDF_CTX`.
struct Krb5 {
    provctx: Ptr,
    cipher: Prov<EVP_CIPHER>,
    key: Option<Secret>,
    constant: Option<Secret>,
}

impl Krb5 {
    fn new(provctx: Ptr) -> Self {
        Self {
            provctx,
            cipher: Prov::NONE,
            key: None,
            constant: None,
        }
    }
}

ffi_callback! {
    /// `krb5kdf_new`.
    ///
    /// # Safety
    /// `provctx` is the provider's context.
    pub(crate) unsafe extern "C" fn krb5_new(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        boxed(Krb5::new(Ptr(provctx)))
    }
}

ffi_callback! {
    /// `krb5kdf_free`.
    ///
    /// # Safety
    /// `vctx` is NULL or a KRB5KDF context, not used afterwards.
    pub(crate) unsafe extern "C" fn krb5_free(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<Krb5>(vctx) };
    }
}

ffi_callback! {
    /// `krb5kdf_reset`.
    ///
    /// # Safety
    /// `vctx` is a live KRB5KDF context.
    pub(crate) unsafe extern "C" fn krb5_reset(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { context::<Krb5>(vctx) } {
            *c = Krb5::new(c.provctx);
        }
    }
}

ffi_callback! {
    /// `krb5kdf_dup`.
    ///
    /// # Safety
    /// `vctx` is a live KRB5KDF context.
    pub(crate) unsafe extern "C" fn krb5_dup(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(src) = (unsafe { context::<Krb5>(vctx) }) else { return ptr::null_mut() };
        let (Some(key), Some(constant)) = (memdup(&src.key), memdup(&src.constant)) else {
            return ptr::null_mut();
        };
        let Some(cipher) = src.cipher.copy() else { return ptr::null_mut() };
        boxed(Krb5 { provctx: src.provctx, cipher, key, constant })
    }
}

ffi_callback! {
    /// `krb5kdf_set_ctx_params`: the cipher, the key, and the constant (each buffer cleared
    /// before it's read, so a refused one leaves none).
    ///
    /// # Safety
    /// `vctx` is a live KRB5KDF context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn krb5_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { crate::provider::param_decoders::decode(params, &crate::provider::param_decoders::KRB5KDF_SET_CTX_PARAMS) } {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: as above.
        let Some(c) = (unsafe { context::<Krb5>(vctx) }) else { return 0 };
        // SAFETY: the context's provider.
        let libctx = unsafe { libctx_of(c.provctx.0) };
        // SAFETY: the caller's array.
        if !unsafe { c.cipher.load(params, OSSL_KDF_PARAM_CIPHER, libctx) } {
            return 0;
        }
        for (name, slot) in [(OSSL_KDF_PARAM_KEY, &mut c.key), (OSSL_KDF_PARAM_CONSTANT, &mut c.constant)] {
            // SAFETY: as above.
            if let Some(p) = unsafe { locate(params, name) } {
                *slot = None;
                // SAFETY: a parameter of the caller's array.
                let Some(v) = (unsafe { get_octets(p) }) else { return 0 };
                *slot = Some(v);
            }
        }
        1
    }
}

/// `cipher_init`: the cipher, its key length if the key's differs, the key, and no padding.
///
/// # Safety
/// `ctx` is a live cipher context; `cipher` a live cipher.
unsafe fn krb5_cipher_init(
    ctx: *mut EVP_CIPHER_CTX,
    cipher: *const EVP_CIPHER,
    key: &[u8],
) -> bool {
    // SAFETY: the caller's context and cipher.
    if unsafe { EVP_EncryptInit_ex(ctx, cipher, ptr::null_mut(), ptr::null(), ptr::null()) } == 0 {
        return false;
    }
    // SAFETY: as above.
    let klen = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) };
    if usize::try_from(klen).ok() != Some(key.len()) {
        // The reference passes its `size_t` length as an `int`; one past `INT_MAX` fails here.
        let Ok(len) = c_int::try_from(key.len()) else {
            return false;
        };
        // SAFETY: as above.
        if unsafe { EVP_CIPHER_CTX_set_key_length(ctx, len) } <= 0 {
            return false;
        }
    }
    // SAFETY: as above; the key of the cipher's (now) length.
    if unsafe { EVP_EncryptInit_ex(ctx, ptr::null(), ptr::null_mut(), key.as_ptr(), ptr::null()) }
        == 0
    {
        return false;
    }
    // SAFETY: as above.
    let r = unsafe { EVP_CIPHER_CTX_set_padding(ctx, 0) };
    r != 0
}

/// `KRB5KDF`: the n-folded constant encrypted, then each block again with a fresh context,
/// into `okey` (the key's length, or 21 octets of triple DES's 24 for its unfixed key).
///
/// # Safety
/// `cipher` is a live cipher.
unsafe fn krb5_compute(
    cipher: *const EVP_CIPHER,
    key: &[u8],
    constant: &[u8],
    okey: &mut [u8],
) -> bool {
    /// Room for an update of a block (and a final one) after another block.
    const ROOM: usize = 2 * EVP_MAX_BLOCK_LENGTH as usize;
    // SAFETY: the caller's cipher.
    let des3 = unsafe { EVP_CIPHER_get_nid(cipher) } == NID_des_ede3_cbc;
    let mut no_fixup = false;
    if key.len() != okey.len() {
        if des3 && key.len() == 24 && okey.len() == 21 {
            no_fixup = true;
        } else {
            raise(PROV_R_WRONG_OUTPUT_BUFFER_SIZE, "KRB5KDF");
            return false;
        }
    }
    // SAFETY: no preconditions.
    let ctx = unsafe { EVP_CIPHER_CTX_new() };
    if ctx.is_null() {
        return false;
    }
    let mut blocks = [Secret(vec![0u8; ROOM]), Secret(vec![0u8; ROOM])];
    let ok = 'compute: {
        // SAFETY: the context made here; the caller's cipher.
        if !unsafe { krb5_cipher_init(ctx, cipher, key) } {
            break 'compute false;
        }
        // SAFETY: as above.
        let blocksize = usize::try_from(unsafe { EVP_CIPHER_CTX_get_block_size(ctx) }).unwrap_or(0);
        if blocksize == 0 {
            raise(PROV_R_MISSING_CIPHER, "KRB5KDF");
            break 'compute false;
        }
        if constant.is_empty() || constant.len() > blocksize {
            raise(PROV_R_INVALID_CONSTANT_LENGTH, "KRB5KDF");
            break 'compute false;
        }
        let (Ok(folded), Ok(inl)) = (kdf::n_fold(constant, blocksize), c_int::try_from(blocksize))
        else {
            break 'compute false;
        };
        let folded = Secret(folded);
        let Some(first) = blocks[0].0.get_mut(..blocksize) else {
            break 'compute false;
        };
        first.copy_from_slice(&folded.0);
        let (mut plain, mut osize) = (0usize, 0usize);
        while osize < okey.len() {
            let [a, b] = &mut blocks;
            let (pb, cb) = if plain == 0 { (&*a, b) } else { (&*b, a) };
            let mut olen: c_int = 0;
            // SAFETY: the context; a block of plaintext; room for its ciphertext.
            if unsafe { EVP_EncryptUpdate(ctx, cb.0.as_mut_ptr(), &raw mut olen, pb.ptr(), inl) }
                == 0
            {
                break 'compute false;
            }
            let cipherlen = usize::try_from(olen).unwrap_or(0);
            // SAFETY: as above.
            if unsafe { EVP_EncryptFinal_ex(ctx, cb.0.as_mut_ptr(), &raw mut olen) } == 0 {
                break 'compute false;
            }
            if olen != 0 {
                raise(PROV_R_WRONG_FINAL_BLOCK_LENGTH, "KRB5KDF");
                break 'compute false;
            }
            // A cipher that makes no output would never finish (the reference loops).
            if cipherlen == 0 {
                break 'compute false;
            }
            let n = cipherlen.min(okey.len() - osize);
            let (Some(dst), Some(src)) = (okey.get_mut(osize..osize + n), cb.0.get(..n)) else {
                break 'compute false;
            };
            dst.copy_from_slice(src);
            osize += n;
            if okey.len() > osize {
                // SAFETY: as above.
                if unsafe { EVP_CIPHER_CTX_reset(ctx) } == 0
                    // SAFETY: as above.
                    || !unsafe { krb5_cipher_init(ctx, cipher, key) }
                {
                    break 'compute false;
                }
                plain ^= 1;
            }
        }
        if des3 && !no_fixup && kdf::des3_random_to_key(okey).is_err() {
            raise(PROV_R_FAILED_TO_GENERATE_KEY, "KRB5KDF");
            break 'compute false;
        }
        true
    };
    // SAFETY: the context made here.
    unsafe { EVP_CIPHER_CTX_free(ctx) };
    ok
}

ffi_callback! {
    /// `krb5kdf_derive`.
    ///
    /// # Safety
    /// `vctx` is a live KRB5KDF context; `key` has room for `keylen` octets; `params` is NULL
    /// or a parameter array.
    pub(crate) unsafe extern "C" fn krb5_derive(vctx: *mut c_void, key: *mut c_uchar, keylen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { krb5_set_ctx_params(vctx, params) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let Some(c) = (unsafe { context::<Krb5>(vctx) }) else { return 0 };
        let missing = if c.cipher.method.is_null() {
            Some(PROV_R_MISSING_CIPHER)
        } else if c.key.is_none() {
            Some(PROV_R_MISSING_KEY)
        } else if c.constant.is_none() {
            Some(PROV_R_MISSING_CONSTANT)
        } else {
            None
        };
        if let Some(r) = missing {
            raise(r, "krb5kdf_derive");
            return 0;
        }
        // SAFETY: the caller's room.
        let Some(out) = (unsafe { out_slice(key, keylen) }) else { return 0 };
        // SAFETY: the context's cipher.
        c_int::from(unsafe { krb5_compute(c.cipher.method, bytes(c.key.as_ref()), bytes(c.constant.as_ref()), out) })
    }
}

ffi_callback! {
    /// `krb5kdf_get_ctx_params`: the size, the cipher's key length (`EVP_MAX_KEY_LENGTH`
    /// without one); 1 when it isn't asked for (3.6; 3.5 returned -2).
    ///
    /// # Safety
    /// `vctx` is a live KRB5KDF context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn krb5_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { crate::provider::param_decoders::decode(params, &crate::provider::param_decoders::KRB5KDF_GET_CTX_PARAMS) } {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context::<Krb5>(vctx) }) else { return 0 };
        let len = if c.cipher.method.is_null() {
            EVP_MAX_KEY_LENGTH as usize
        } else {
            // SAFETY: the context's cipher. The reference converts the `int` as it is.
            let n = unsafe { EVP_CIPHER_get_key_length(c.cipher.method) };
            usize::try_from(n).unwrap_or(usize::MAX)
        };
        // SAFETY: the caller's guarantee.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE.as_ptr()) };
        // 3.6: nothing asked is success.
        if p.is_null() {
            return 1;
        }
        // SAFETY: a parameter of the caller's array.
        unsafe { OSSL_PARAM_set_size_t(p, len) }
    }
}

static KRB5_SETTABLE: Params<5> = Params([
    defn(
        OSSL_KDF_PARAM_PROPERTIES,
        OSSL_PARAM_UTF8_STRING as c_int,
        0,
    ),
    defn(OSSL_KDF_PARAM_CIPHER, OSSL_PARAM_UTF8_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_KEY, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_CONSTANT, OSSL_PARAM_OCTET_STRING as c_int, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `krb5kdf_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn krb5_settable(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        KRB5_SETTABLE.0.as_ptr()
    }
}

pub(super) static KRB5_FUNCTIONS: Dispatch<10> = Dispatch([
    entry!(OSSL_FUNC_KDF_NEWCTX, krb5_new, NewCtxFn),
    entry!(OSSL_FUNC_KDF_DUPCTX, krb5_dup, DupCtxFn),
    entry!(OSSL_FUNC_KDF_FREECTX, krb5_free, FreeCtxFn),
    entry!(OSSL_FUNC_KDF_RESET, krb5_reset, ResetFn),
    entry!(OSSL_FUNC_KDF_DERIVE, krb5_derive, DeriveFn),
    entry!(
        OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        krb5_settable,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_SET_CTX_PARAMS,
        krb5_set_ctx_params,
        SetCtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        size_only_gettable,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_GET_CTX_PARAMS,
        krb5_get_ctx_params,
        GetCtxParamsFn
    ),
    END,
]);

// -------------------------------------------------------------------------------------------
// HMAC-DRBG-KDF

/// `KDF_HMAC_DRBG`: the DRBG's `PROV_DRBG_HMAC` (the HMAC context, digest, K and V), the
/// entropy and nonce, and whether it's instantiated.
struct HmacDrbg {
    provctx: Ptr,
    s: HmacState,
    entropy: Option<Secret>,
    nonce: Option<Secret>,
    init: bool,
}

impl HmacDrbg {
    fn new(provctx: Ptr) -> Self {
        Self {
            provctx,
            s: HmacState::new(),
            entropy: None,
            nonce: None,
            init: false,
        }
    }
}

ffi_callback! {
    /// `hmac_drbg_kdf_new`.
    ///
    /// # Safety
    /// `provctx` is the provider's context.
    pub(crate) unsafe extern "C" fn hmac_drbg_new(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        boxed(HmacDrbg::new(Ptr(provctx)))
    }
}

ffi_callback! {
    /// `hmac_drbg_kdf_free`.
    ///
    /// # Safety
    /// `vctx` is NULL or an HMAC-DRBG-KDF context, not used afterwards.
    pub(crate) unsafe extern "C" fn hmac_drbg_free(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<HmacDrbg>(vctx) };
    }
}

ffi_callback! {
    /// `hmac_drbg_kdf_reset`.
    ///
    /// # Safety
    /// `vctx` is a live HMAC-DRBG-KDF context.
    pub(crate) unsafe extern "C" fn hmac_drbg_reset(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { context::<HmacDrbg>(vctx) } {
            *c = HmacDrbg::new(c.provctx);
        }
    }
}

ffi_callback! {
    /// `hmac_drbg_kdf_dup`.
    ///
    /// # Safety
    /// `vctx` is a live HMAC-DRBG-KDF context.
    pub(crate) unsafe extern "C" fn hmac_drbg_dup(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(src) = (unsafe { context::<HmacDrbg>(vctx) }) else { return ptr::null_mut() };
        let mut dst = HmacDrbg::new(src.provctx);
        if !src.s.ctx.is_null() {
            // SAFETY: the source's live context.
            dst.s.ctx = unsafe { EVP_MAC_CTX_dup(src.s.ctx) };
            if dst.s.ctx.is_null() {
                return ptr::null_mut();
            }
        }
        let Some(digest) = src.s.digest.copy() else { return ptr::null_mut() };
        dst.s.digest = digest;
        (dst.s.k, dst.s.v, dst.s.blocklen) = (src.s.k, src.s.v, src.s.blocklen);
        let (Some(entropy), Some(nonce)) = (memdup(&src.entropy), memdup(&src.nonce)) else {
            return ptr::null_mut();
        };
        (dst.entropy, dst.nonce, dst.init) = (entropy, nonce, src.init);
        boxed(dst)
    }
}

ffi_callback! {
    /// `hmac_drbg_kdf_set_ctx_params`: the entropy and nonce (each one set starts over), and
    /// the digest (not an XOF), which makes a new HMAC context; K and V stay as they are.
    ///
    /// # Safety
    /// `vctx` is a live HMAC-DRBG-KDF context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn hmac_drbg_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { crate::provider::param_decoders::decode(params, &crate::provider::param_decoders::HMAC_DRBG_KDF_SET_CTX_PARAMS) } {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: as above.
        let Some(c) = (unsafe { context::<HmacDrbg>(vctx) }) else { return 0 };
        for (name, slot) in [(OSSL_KDF_PARAM_HMACDRBG_ENTROPY, &mut c.entropy), (OSSL_KDF_PARAM_HMACDRBG_NONCE, &mut c.nonce)] {
            // SAFETY: as above.
            if let Some(p) = unsafe { locate(params, name) } {
                // SAFETY: a parameter of the caller's array.
                let Some(v) = (unsafe { get_octets(p) }) else { return 0 };
                *slot = Some(v);
                c.init = false;
            }
        }
        // SAFETY: as above.
        if unsafe { locate(params, OSSL_ALG_PARAM_DIGEST) }.is_none() {
            return 1;
        }
        // SAFETY: the context's provider.
        let libctx = unsafe { libctx_of(c.provctx.0) };
        // SAFETY: the caller's array.
        if !unsafe { c.s.digest.load(params, OSSL_ALG_PARAM_DIGEST, libctx) } {
            return 0;
        }
        let md = c.s.digest.method;
        if !md.is_null() {
            // SAFETY: the digest just fetched.
            if unsafe { EVP_MD_xof(md) } != 0 {
                raise(PROV_R_XOF_DIGESTS_NOT_ALLOWED, "hmac_drbg_kdf_set_ctx_params");
                return 0;
            }
            // SAFETY: as above.
            let Some(size) = (unsafe { md_size(md) }) else { return 0 };
            c.s.blocklen = size;
        }
        // SAFETY: the context's MAC context; the caller's array; a static name.
        c_int::from(unsafe { macctx_load(&mut c.s.ctx, params, c"HMAC".as_ptr(), ptr::null(), ptr::null(), libctx) })
    }
}

ffi_callback! {
    /// `hmac_drbg_kdf_derive`: instantiated from the entropy and nonce (both needed, silently)
    /// on the first derivation after either is set, then generated.
    ///
    /// # Safety
    /// `vctx` is a live HMAC-DRBG-KDF context; `key` has room for `keylen` octets; `params`
    /// is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn hmac_drbg_derive(vctx: *mut c_void, key: *mut c_uchar, keylen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { hmac_drbg_set_ctx_params(vctx, params) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let Some(c) = (unsafe { context::<HmacDrbg>(vctx) }) else { return 0 };
        if !c.init {
            let (entropy, nonce) = (Secret(bytes(c.entropy.as_ref()).to_vec()), Secret(bytes(c.nonce.as_ref()).to_vec()));
            if entropy.len() == 0 || nonce.len() == 0 || !c.s.init(&entropy.0, &nonce.0, &[]) {
                return 0;
            }
            c.init = true;
        }
        // SAFETY: the caller's room.
        let Some(out) = (unsafe { out_slice(key, keylen) }) else { return 0 };
        c_int::from(c.s.generate(out, &[]))
    }
}

ffi_callback! {
    /// `hmac_drbg_kdf_get_ctx_params`: the MAC's name and the digest's (each failing without
    /// one); 1 otherwise.
    ///
    /// # Safety
    /// `vctx` is a live HMAC-DRBG-KDF context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn hmac_drbg_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { crate::provider::param_decoders::decode(params, &crate::provider::param_decoders::HMAC_DRBG_KDF_GET_CTX_PARAMS) } {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context::<HmacDrbg>(vctx) }) else { return 0 };
        // SAFETY: as above.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_KDF_PARAM_MAC.as_ptr()) };
        if !p.is_null() {
            if c.s.ctx.is_null() {
                return 0;
            }
            // SAFETY: the live context.
            let mac = unsafe { EVP_MAC_CTX_get0_mac(c.s.ctx) };
            // SAFETY: its method.
            let name = unsafe { EVP_MAC_get0_name(mac) };
            // SAFETY: a parameter of the caller's array; the method's name.
            if unsafe { OSSL_PARAM_set_utf8_string(p, name) } == 0 {
                return 0;
            }
        }
        // SAFETY: as above.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_KDF_PARAM_DIGEST.as_ptr()) };
        if !p.is_null() {
            let md = c.s.digest.method;
            if md.is_null() {
                return 0;
            }
            // SAFETY: the context's digest.
            let name = unsafe { EVP_MD_get0_name(md) };
            // SAFETY: a parameter of the caller's array; the digest's name.
            if unsafe { OSSL_PARAM_set_utf8_string(p, name) } == 0 {
                return 0;
            }
        }
        1
    }
}

static HMAC_DRBG_SETTABLE: Params<5> = Params([
    defn(
        OSSL_KDF_PARAM_PROPERTIES,
        OSSL_PARAM_UTF8_STRING as c_int,
        0,
    ),
    defn(OSSL_KDF_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING as c_int, 0),
    defn(
        OSSL_KDF_PARAM_HMACDRBG_ENTROPY,
        OSSL_PARAM_OCTET_STRING as c_int,
        0,
    ),
    defn(
        OSSL_KDF_PARAM_HMACDRBG_NONCE,
        OSSL_PARAM_OCTET_STRING as c_int,
        0,
    ),
    PARAM_END,
]);

static HMAC_DRBG_GETTABLE: Params<3> = Params([
    defn(OSSL_KDF_PARAM_MAC, OSSL_PARAM_UTF8_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING as c_int, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `hmac_drbg_kdf_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn hmac_drbg_settable(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        HMAC_DRBG_SETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `hmac_drbg_kdf_gettable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn hmac_drbg_gettable(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        HMAC_DRBG_GETTABLE.0.as_ptr()
    }
}

pub(super) static HMAC_DRBG_FUNCTIONS: Dispatch<10> = Dispatch([
    entry!(OSSL_FUNC_KDF_NEWCTX, hmac_drbg_new, NewCtxFn),
    entry!(OSSL_FUNC_KDF_FREECTX, hmac_drbg_free, FreeCtxFn),
    entry!(OSSL_FUNC_KDF_DUPCTX, hmac_drbg_dup, DupCtxFn),
    entry!(OSSL_FUNC_KDF_RESET, hmac_drbg_reset, ResetFn),
    entry!(OSSL_FUNC_KDF_DERIVE, hmac_drbg_derive, DeriveFn),
    entry!(
        OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        hmac_drbg_settable,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_SET_CTX_PARAMS,
        hmac_drbg_set_ctx_params,
        SetCtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        hmac_drbg_gettable,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_GET_CTX_PARAMS,
        hmac_drbg_get_ctx_params,
        GetCtxParamsFn
    ),
    END,
]);

// -------------------------------------------------------------------------------------------
// ARGON2I, ARGON2D, ARGON2ID

/// `ARGON2_MIN_MEMORY`: 2 blocks per synchronization point.
const ARGON2_MIN_MEMORY: u32 = 8;
/// `ARGON2_MAX_LANES` and `ARGON2_MAX_THREADS`.
const ARGON2_MAX_LANES: u32 = 0xff_ffff;
/// `ARGON2_MIN_SALT_LENGTH`.
const ARGON2_MIN_SALT_LENGTH: usize = 8;
/// `ARGON2_MIN_OUT_LENGTH`.
const ARGON2_MIN_OUT_LENGTH: u32 = 4;

/// `KDF_ARGON2`.
struct Argon2Ctx {
    libctx: *mut OSSL_LIB_CTX,
    variant: kdf::Argon2Variant,
    outlen: u32,
    pwd: Option<Secret>,
    salt: Option<Secret>,
    secret: Option<Secret>,
    ad: Option<Secret>,
    t_cost: u32,
    m_cost: u32,
    lanes: u32,
    threads: u32,
    version: u32,
    early_clean: bool,
    md: *mut EVP_MD,
    mac: *mut EVP_MAC,
    propq: Option<CString>,
}

impl Argon2Ctx {
    /// `kdf_argon2_init`: 64 octets, 3 passes, 8 blocks, a lane, a thread, version 0x13.
    fn new(libctx: *mut OSSL_LIB_CTX, variant: kdf::Argon2Variant) -> Self {
        Self {
            libctx,
            variant,
            outlen: 64,
            pwd: None,
            salt: None,
            secret: None,
            ad: None,
            t_cost: 3,
            m_cost: ARGON2_MIN_MEMORY,
            lanes: 1,
            threads: 1,
            version: 0x13,
            early_clean: false,
            md: ptr::null_mut(),
            mac: ptr::null_mut(),
            propq: None,
        }
    }

    /// `set_property_query`: the query, and the digest and MAC to fetch again.
    fn set_propq(&mut self, propq: Option<CString>) {
        self.propq = propq;
        self.free_methods();
    }

    fn free_methods(&mut self) {
        // SAFETY: the references this holds, or NULL.
        unsafe { EVP_MD_free(self.md) };
        // SAFETY: as above.
        unsafe { EVP_MAC_free(self.mac) };
        self.md = ptr::null_mut();
        self.mac = ptr::null_mut();
    }

    /// `kdf_argon2_ctx_set_out_length`.
    fn set_out_length(&mut self, outlen: u32) -> bool {
        if outlen < ARGON2_MIN_OUT_LENGTH {
            err::raise_with_text(
                ERR_LIB_PROV,
                PROV_R_INVALID_OUTPUT_LENGTH,
                "kdf_argon2_ctx_set_out_length",
                &format!("min: {ARGON2_MIN_OUT_LENGTH}"),
            );
            return false;
        }
        self.outlen = outlen;
        true
    }
}

impl Drop for Argon2Ctx {
    fn drop(&mut self) {
        self.free_methods();
    }
}

/// A new Argon2 context of the variant.
///
/// # Safety
/// `provctx` is the provider's context.
unsafe fn argon2_new(provctx: *mut c_void, variant: kdf::Argon2Variant) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    boxed(Argon2Ctx::new(unsafe { libctx_of(provctx) }, variant))
}

ffi_callback! {
    /// `kdf_argon2i_new`.
    ///
    /// # Safety
    /// `provctx` is the provider's context.
    pub(crate) unsafe extern "C" fn argon2i_new(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { argon2_new(provctx, kdf::Argon2Variant::I) }
    }
}

ffi_callback! {
    /// `kdf_argon2d_new`.
    ///
    /// # Safety
    /// `provctx` is the provider's context.
    pub(crate) unsafe extern "C" fn argon2d_new(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { argon2_new(provctx, kdf::Argon2Variant::D) }
    }
}

ffi_callback! {
    /// `kdf_argon2id_new`.
    ///
    /// # Safety
    /// `provctx` is the provider's context.
    pub(crate) unsafe extern "C" fn argon2id_new(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { argon2_new(provctx, kdf::Argon2Variant::Id) }
    }
}

ffi_callback! {
    /// `kdf_argon2_free`.
    ///
    /// # Safety
    /// `vctx` is NULL or an Argon2 context, not used afterwards.
    pub(crate) unsafe extern "C" fn argon2_free(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<Argon2Ctx>(vctx) };
    }
}

ffi_callback! {
    /// `kdf_argon2_reset`: everything back to the defaults (the query and methods too), the
    /// variant kept.
    ///
    /// # Safety
    /// `vctx` is a live Argon2 context.
    pub(crate) unsafe extern "C" fn argon2_reset(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { context::<Argon2Ctx>(vctx) } {
            *c = Argon2Ctx::new(c.libctx, c.variant);
        }
    }
}

/// `kdf_argon2_ctx_set_pwd` and its kin: refused (unchanged) for NULL data, else the old
/// value gone and the new one read; `check` may refuse it (raising), which leaves none.
///
/// # Safety
/// `p`'s data is NULL or holds `data_size` octets.
unsafe fn argon2_set_buffer(
    slot: &mut Option<Secret>,
    p: &OSSL_PARAM,
    check: impl Fn(usize) -> bool,
) -> bool {
    if p.data.is_null() {
        return false;
    }
    *slot = None;
    // SAFETY: the caller's guarantee.
    let Some(v) = (unsafe { get_octets(p) }) else {
        return false;
    };
    if u32::try_from(v.len()).is_err() || !check(v.len()) {
        return false;
    }
    *slot = Some(v);
    true
}

ffi_callback! {
    /// `kdf_argon2_set_ctx_params`: the password, salt (8 octets or more), secret, associated
    /// data, output size, passes, threads, lanes, memory, early clean, version, and property
    /// query, each `uint32` checked as the reference does.
    ///
    /// # Safety
    /// `vctx` is a live Argon2 context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn argon2_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { crate::provider::param_decoders::decode(params, &crate::provider::param_decoders::ARGON2_SET_CTX_PARAMS) } {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: as above.
        let Some(c) = (unsafe { context::<Argon2Ctx>(vctx) }) else { return 0 };
        type Check = fn(usize) -> bool;
        let any: Check = |_| true;
        let salt: Check = |n| {
            if n < ARGON2_MIN_SALT_LENGTH {
                err::raise_with_text(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH, "kdf_argon2_ctx_set_salt", &format!("min: {ARGON2_MIN_SALT_LENGTH}"));
                return false;
            }
            true
        };
        for (name, slot, check) in [
            (OSSL_KDF_PARAM_PASSWORD, &mut c.pwd, any),
            (OSSL_KDF_PARAM_SALT, &mut c.salt, salt),
            (OSSL_KDF_PARAM_SECRET, &mut c.secret, any),
            (OSSL_KDF_PARAM_ARGON2_AD, &mut c.ad, any),
        ] {
            // SAFETY: as above.
            if let Some(p) = unsafe { locate(params, name) } {
                // SAFETY: a parameter of the caller's array.
                if !unsafe { argon2_set_buffer(slot, p, check) } {
                    return 0;
                }
            }
        }
        let get = |name: &CStr| -> Option<Option<u32>> {
            // SAFETY: as above.
            let p = unsafe { locate(params, name) }?;
            let mut v = 0u32;
            // SAFETY: a parameter of the caller's array; a local.
            Some((unsafe { OSSL_PARAM_get_uint32(p, &raw mut v) } != 0).then_some(v))
        };
        let fail = |reason: c_int, function: &str, text: String| {
            err::raise_with_text(ERR_LIB_PROV, reason, function, &text);
            0
        };
        if let Some(v) = get(OSSL_KDF_PARAM_SIZE) {
            let Some(v) = v else { return 0 };
            if !c.set_out_length(v) {
                return 0;
            }
        }
        if let Some(v) = get(OSSL_KDF_PARAM_ITER) {
            let Some(v) = v else { return 0 };
            if v < 1 {
                return fail(PROV_R_INVALID_ITERATION_COUNT, "kdf_argon2_ctx_set_t_cost", "min: 1".into());
            }
            c.t_cost = v;
        }
        if let Some(v) = get(OSSL_KDF_PARAM_THREADS) {
            let Some(v) = v else { return 0 };
            if v < 1 {
                return fail(PROV_R_INVALID_THREAD_POOL_SIZE, "kdf_argon2_ctx_set_threads", "min threads: 1".into());
            }
            if v > ARGON2_MAX_LANES {
                return fail(PROV_R_INVALID_THREAD_POOL_SIZE, "kdf_argon2_ctx_set_threads", format!("max threads: {ARGON2_MAX_LANES}"));
            }
            c.threads = v;
        }
        if let Some(v) = get(OSSL_KDF_PARAM_ARGON2_LANES) {
            let Some(v) = v else { return 0 };
            if v > ARGON2_MAX_LANES {
                return fail(PROV_R_FAILED_TO_SET_PARAMETER, "kdf_argon2_ctx_set_lanes", format!("max lanes: {ARGON2_MAX_LANES}"));
            }
            if v < 1 {
                return fail(PROV_R_FAILED_TO_SET_PARAMETER, "kdf_argon2_ctx_set_lanes", "min lanes: 1".into());
            }
            c.lanes = v;
        }
        if let Some(v) = get(OSSL_KDF_PARAM_ARGON2_MEMCOST) {
            let Some(v) = v else { return 0 };
            if v < ARGON2_MIN_MEMORY {
                return fail(PROV_R_INVALID_MEMORY_SIZE, "kdf_argon2_ctx_set_m_cost", format!("min: {ARGON2_MIN_MEMORY}"));
            }
            c.m_cost = v;
        }
        if let Some(v) = get(OSSL_KDF_PARAM_EARLY_CLEAN) {
            let Some(v) = v else { return 0 };
            c.early_clean = v != 0;
        }
        if let Some(v) = get(OSSL_KDF_PARAM_ARGON2_VERSION) {
            let Some(v) = v else { return 0 };
            if !matches!(v, 0x10 | 0x13) {
                return fail(PROV_R_INVALID_MODE, "kdf_argon2_ctx_set_version", "invalid Argon2 version".into());
            }
            c.version = v;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_KDF_PARAM_PROPERTIES) } {
            let Some(text) = utf8(p) else { return 0 };
            let propq = if text.is_null() {
                None
            } else {
                // SAFETY: a UTF-8 string parameter's data: a C string.
                Some(unsafe { CStr::from_ptr(text) }.to_owned())
            };
            c.set_propq(propq);
        }
        1
    }
}

/// The low 32 bits, as the reference's `%u` prints a `uint64_t`.
fn low32(n: u64) -> u32 {
    u32::try_from(n & u64::from(u32::MAX)).unwrap_or(0)
}

/// Argon2 into `out` over the backend, with the context's parameters; the password and
/// secret wiped afterwards in early-clean mode, as the reference's first hash does.
fn argon2_compute(c: &mut Argon2Ctx, out: &mut [u8]) -> bool {
    let params = kdf::Argon2 {
        variant: c.variant,
        version: c.version,
        passes: c.t_cost,
        memory: c.m_cost,
        lanes: c.lanes,
        password: bytes(c.pwd.as_ref()),
        salt: bytes(c.salt.as_ref()),
        secret: bytes(c.secret.as_ref()),
        ad: bytes(c.ad.as_ref()),
    };
    let r = kdf::argon2(&params, out);
    if let Err(kdf::Error::Allocation) = r {
        err::raise_with_text(
            ERR_LIB_PROV,
            PROV_R_INVALID_MEMORY_SIZE,
            "initialize",
            "cannot allocate required memory",
        );
        return false;
    }
    if c.early_clean {
        for slot in [&mut c.pwd, &mut c.secret] {
            if slot.is_some() {
                *slot = Some(Secret::default());
            }
        }
    }
    r.is_ok()
}

ffi_callback! {
    /// `kdf_argon2_derive`: the MAC and digest fetched if they aren't yet, a salt, the output
    /// length (which becomes the context's unless `size` is among the parameters), the
    /// threads (no more than `OSSL_set_max_threads` allows, nor than the lanes), and the
    /// memory (8 blocks a lane).
    ///
    /// # Safety
    /// `vctx` is a live Argon2 context; `key` has room for `keylen` octets; `params` is NULL
    /// or a parameter array.
    pub(crate) unsafe extern "C" fn argon2_derive(vctx: *mut c_void, key: *mut c_uchar, keylen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { argon2_set_ctx_params(vctx, params) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let Some(c) = (unsafe { context::<Argon2Ctx>(vctx) }) else { return 0 };
        let propq = c.propq.as_ref().map_or(ptr::null(), |q| q.as_ptr());
        if c.mac.is_null() {
            // SAFETY: the context's library context; a static name; the query.
            c.mac = unsafe { EVP_MAC_fetch(c.libctx, c"blake2bmac".as_ptr(), propq) };
        }
        if c.mac.is_null() {
            err::raise_with_text(ERR_LIB_PROV, PROV_R_MISSING_MAC, "kdf_argon2_derive", "cannot fetch blake2bmac");
            return 0;
        }
        if c.md.is_null() {
            // SAFETY: as above.
            c.md = unsafe { EVP_MD_fetch(c.libctx, c"blake2b512".as_ptr(), propq) };
        }
        if c.md.is_null() {
            err::raise_with_text(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST, "kdf_argon2_derive", "cannot fetch blake2b512");
            return 0;
        }
        if c.salt.as_ref().is_none_or(|s| s.len() == 0) {
            raise(PROV_R_MISSING_SALT, "kdf_argon2_derive");
            return 0;
        }
        if keylen != c.outlen as usize {
            // SAFETY: the caller's guarantee.
            if unsafe { OSSL_PARAM_locate(params.cast_mut(), OSSL_KDF_PARAM_SIZE.as_ptr()) }.is_null() {
                // The reference truncates a length past 32 bits to its low ones, and derives
                // fewer octets than asked for; it's refused here (docs/DEVIATIONS.md).
                let Ok(len) = u32::try_from(keylen) else {
                    raise(PROV_R_INVALID_OUTPUT_LENGTH, "kdf_argon2_derive");
                    return 0;
                };
                if !c.set_out_length(len) {
                    return 0;
                }
            } else {
                raise(PROV_R_OUTPUT_BUFFER_TOO_SMALL, "kdf_argon2_derive");
                return 0;
            }
        }
        if c.threads > 1 {
            // SAFETY: the context's library context.
            let avail = unsafe { OSSL_get_max_threads(c.libctx) };
            if u64::from(c.threads) > avail {
                err::raise_with_text(ERR_LIB_PROV, PROV_R_INVALID_THREAD_POOL_SIZE, "kdf_argon2_derive", &format!("requested {} threads, available: {}", c.threads, low32(avail)));
                return 0;
            }
            if c.threads > c.lanes {
                err::raise_with_text(ERR_LIB_PROV, PROV_R_INVALID_THREAD_POOL_SIZE, "kdf_argon2_derive", &format!("requested more threads ({}) than lanes ({})", c.threads, c.lanes));
                return 0;
            }
        }
        if c.m_cost < c.lanes.saturating_mul(8) {
            err::raise_with_text(ERR_LIB_PROV, PROV_R_INVALID_MEMORY_SIZE, "kdf_argon2_derive", "m_cost must be greater or equal than 8 times the number of lanes");
            return 0;
        }
        // The reference computes into NULL as into a buffer, writing nothing.
        if key.is_null() {
            let mut scratch = Secret(vec![0u8; keylen]);
            return c_int::from(argon2_compute(c, &mut scratch.0));
        }
        // SAFETY: the caller's room.
        let Some(out) = (unsafe { out_slice(key, keylen) }) else { return 0 };
        c_int::from(argon2_compute(c, out))
    }
}

static ARGON2_SETTABLE: Params<13> = Params([
    defn(OSSL_KDF_PARAM_PASSWORD, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_SALT, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_SECRET, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(
        OSSL_KDF_PARAM_ARGON2_AD,
        OSSL_PARAM_OCTET_STRING as c_int,
        0,
    ),
    defn(
        OSSL_KDF_PARAM_SIZE,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        size_of::<u32>(),
    ),
    defn(
        OSSL_KDF_PARAM_ITER,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        size_of::<u32>(),
    ),
    defn(
        OSSL_KDF_PARAM_THREADS,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        size_of::<u32>(),
    ),
    defn(
        OSSL_KDF_PARAM_ARGON2_LANES,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        size_of::<u32>(),
    ),
    defn(
        OSSL_KDF_PARAM_ARGON2_MEMCOST,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        size_of::<u32>(),
    ),
    defn(
        OSSL_KDF_PARAM_EARLY_CLEAN,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        size_of::<u32>(),
    ),
    defn(
        OSSL_KDF_PARAM_ARGON2_VERSION,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        size_of::<u32>(),
    ),
    defn(
        OSSL_KDF_PARAM_PROPERTIES,
        OSSL_PARAM_UTF8_STRING as c_int,
        0,
    ),
    PARAM_END,
]);

ffi_callback! {
    /// `kdf_argon2_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn argon2_settable(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        ARGON2_SETTABLE.0.as_ptr()
    }
}

/// An Argon2 dispatch table with its `newctx` (Argon2 has no `dupctx`).
macro_rules! argon2_table {
    ($new:ident) => {
        Dispatch([
            entry!(OSSL_FUNC_KDF_NEWCTX, $new, NewCtxFn),
            entry!(OSSL_FUNC_KDF_FREECTX, argon2_free, FreeCtxFn),
            entry!(OSSL_FUNC_KDF_RESET, argon2_reset, ResetFn),
            entry!(OSSL_FUNC_KDF_DERIVE, argon2_derive, DeriveFn),
            entry!(
                OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
                argon2_settable,
                CtxParamsFn
            ),
            entry!(
                OSSL_FUNC_KDF_SET_CTX_PARAMS,
                argon2_set_ctx_params,
                SetCtxParamsFn
            ),
            entry!(
                OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
                size_only_gettable,
                CtxParamsFn
            ),
            entry!(
                OSSL_FUNC_KDF_GET_CTX_PARAMS,
                argon2_get_ctx_params,
                GetCtxParamsFn
            ),
            END,
        ])
    };
}

pub(super) static ARGON2I_FUNCTIONS: Dispatch<9> = argon2_table!(argon2i_new);
pub(super) static ARGON2D_FUNCTIONS: Dispatch<9> = argon2_table!(argon2d_new);
pub(super) static ARGON2ID_FUNCTIONS: Dispatch<9> = argon2_table!(argon2id_new);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::kdf::{
        EVP_KDF_CTX_free, EVP_KDF_CTX_new, EVP_KDF_derive, EVP_KDF_fetch, EVP_KDF_free,
    };
    use crate::params::{OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_utf8_string, end};

    /// Derives `keylen` octets into NULL with the KDF `name` and `params`.
    fn derive_into_null(name: &CStr, params: &[OSSL_PARAM], keylen: usize) -> c_int {
        // SAFETY: a static name.
        let kdf = unsafe { EVP_KDF_fetch(ptr::null_mut(), name.as_ptr(), ptr::null()) };
        // SAFETY: the method just fetched.
        let ctx = unsafe { EVP_KDF_CTX_new(kdf) };
        // SAFETY: as above.
        unsafe { EVP_KDF_free(kdf) };
        // SAFETY: the context; NULL output is the case under test; the caller's parameters.
        let r = unsafe { EVP_KDF_derive(ctx, ptr::null_mut(), keylen, params.as_ptr()) };
        // SAFETY: the test's context.
        unsafe { EVP_KDF_CTX_free(ctx) };
        r
    }

    fn octets(key: &CStr, data: &'static [u8]) -> OSSL_PARAM {
        // SAFETY: a static key and data.
        unsafe {
            OSSL_PARAM_construct_octet_string(
                key.as_ptr(),
                data.as_ptr().cast_mut().cast(),
                data.len(),
            )
        }
    }

    fn text(key: &CStr, value: &'static CStr) -> OSSL_PARAM {
        // SAFETY: a static key and string.
        unsafe { OSSL_PARAM_construct_utf8_string(key.as_ptr(), value.as_ptr().cast_mut(), 0) }
    }

    /// docs/DEVIATIONS.md: PKCS12KDF, KRB5KDF, and HMAC-DRBG-KDF refuse a NULL output with a
    /// length (the reference writes through NULL).
    #[test]
    #[cfg_attr(miri, ignore = "fetches, which loads the configuration")]
    fn null_outputs_are_refused() {
        let pkcs12 = [
            text(OSSL_KDF_PARAM_DIGEST, c"SHA256"),
            octets(OSSL_KDF_PARAM_PASSWORD, b"pw"),
            octets(OSSL_KDF_PARAM_SALT, b"salt"),
            end(),
        ];
        assert_eq!(derive_into_null(c"PKCS12KDF", &pkcs12, 16), 0);
        assert_eq!(derive_into_null(c"PKCS12KDF", &pkcs12, 0), 1);
        let krb5 = [
            text(OSSL_KDF_PARAM_CIPHER, c"AES-128-CBC"),
            octets(OSSL_KDF_PARAM_KEY, &[7; 16]),
            octets(OSSL_KDF_PARAM_CONSTANT, b"\x00\x00\x00\x02\x99"),
            end(),
        ];
        assert_eq!(derive_into_null(c"KRB5KDF", &krb5, 16), 0);
        let drbg = [
            text(OSSL_KDF_PARAM_DIGEST, c"SHA256"),
            octets(OSSL_KDF_PARAM_HMACDRBG_ENTROPY, b"entropy"),
            octets(OSSL_KDF_PARAM_HMACDRBG_NONCE, b"nonce"),
            end(),
        ];
        assert_eq!(derive_into_null(c"HMAC-DRBG-KDF", &drbg, 16), 0);
        assert_eq!(derive_into_null(c"HMAC-DRBG-KDF", &drbg, 0), 1);
    }

    /// docs/DEVIATIONS.md: Argon2 refuses an output length past 32 bits (the reference derives
    /// its low 32 bits' worth); into NULL, it computes and writes nothing, as the reference
    /// does.
    #[test]
    #[cfg_attr(miri, ignore = "fetches, which loads the configuration")]
    fn argon2_lengths_past_32_bits_are_refused() {
        let params = [octets(OSSL_KDF_PARAM_SALT, b"saltsalt"), end()];
        assert_eq!(derive_into_null(c"ARGON2ID", &params, 64), 1);
        let long = usize::try_from(u64::from(u32::MAX) + 65).unwrap_or(usize::MAX);
        assert_eq!(derive_into_null(c"ARGON2ID", &params, long), 0);
    }
}
