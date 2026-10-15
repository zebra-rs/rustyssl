//! The default provider's signature algorithms (`deflt_signature` in `providers/defltprov.c`):
//! so far the MAC "signatures" of HMAC, SIPHASH, POLY1305, and CMAC (`mac_legacy_sig.c`), which
//! sign through a digest context (`EVP_DigestSign*`) by running the MAC over the data with the
//! MAC key. The other signature algorithms come with their key types (4.3 onwards).
//!
//! As in OpenSSL, a MAC signature's context holds an `EVP_MAC_CTX` of the MAC (fetched with the
//! context's properties) and a reference to the key; the init gives the MAC the key's cipher,
//! the digest named, and the key's properties, then the key.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    ERR_LIB_PROV, EVP_MAC, EVP_MAC_CTX, OSSL_ALGORITHM, OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
    OSSL_FUNC_SIGNATURE_DUPCTX, OSSL_FUNC_SIGNATURE_FREECTX, OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, OSSL_FUNC_SIGNATURE_NEWCTX,
    OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, OSSL_LIB_CTX,
    OSSL_MAC_PARAM_CIPHER, OSSL_MAC_PARAM_DIGEST, OSSL_MAC_PARAM_PROPERTIES, OSSL_PARAM,
    PROV_R_NO_KEY_SET,
};

use super::builtin::libctx_of;
use super::ecdsa_sig;
use super::keymgmt::{mac_free, mac_key, mac_key_up_ref};
use super::rsa_sig;
use super::tables::{ALG_END, Algorithms, Dispatch, END, PARAM_END, Params, alg, entry, pending};
use crate::err;
use crate::evp::mac::{
    EVP_MAC_CTX_dup, EVP_MAC_CTX_free, EVP_MAC_CTX_new, EVP_MAC_CTX_set_params, EVP_MAC_fetch,
    EVP_MAC_final, EVP_MAC_free, EVP_MAC_init, EVP_MAC_settable_ctx_params, EVP_MAC_update,
};
use crate::ffi::ffi_callback;
use crate::params::{OSSL_PARAM_construct_utf8_string, end};
use crate::provider::Ptr;

/// A MAC signature's context (`PROV_MAC_CTX`).
struct MacSigCtx {
    libctx: Ptr<OSSL_LIB_CTX>,
    propq: Option<CString>,
    /// The key, with a reference (`MAC_KEY *`), or NULL.
    key: Ptr<c_void>,
    macctx: Ptr<EVP_MAC_CTX>,
}

impl Drop for MacSigCtx {
    fn drop(&mut self) {
        // SAFETY: the context's own MAC context, or NULL.
        unsafe { EVP_MAC_CTX_free(self.macctx.0) };
        // SAFETY: the context's reference to the key, or NULL.
        unsafe { mac_free(self.key.0) };
    }
}

/// The context behind `vctx`, or `None` for NULL.
///
/// # Safety
/// `vctx` is NULL or a context from `mac_newctx`, used by one caller at a time.
unsafe fn context<'a>(vctx: *mut c_void) -> Option<&'a mut MacSigCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { vctx.cast::<MacSigCtx>().as_mut() }
}

/// `mac_newctx`: a context for the MAC `macname`, fetched with `propq`; NULL if it can't be.
///
/// # Safety
/// `provctx` is the default provider's context; `propq` is NULL or a string.
unsafe fn mac_newctx(provctx: *mut c_void, propq: *const c_char, macname: &CStr) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    let libctx = unsafe { libctx_of(provctx) };
    let propq_owned = if propq.is_null() {
        None
    } else {
        // SAFETY: the caller's guarantee.
        Some(unsafe { CStr::from_ptr(propq) }.to_owned())
    };
    // SAFETY: the provider's context; a static name; the query.
    let mac: *mut EVP_MAC = unsafe { EVP_MAC_fetch(libctx, macname.as_ptr(), propq) };
    if mac.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the method fetched above.
    let macctx = unsafe { EVP_MAC_CTX_new(mac) };
    // SAFETY: the reference fetched above (the context holds its own).
    unsafe { EVP_MAC_free(mac) };
    if macctx.is_null() {
        return ptr::null_mut();
    }
    Box::into_raw(Box::new(MacSigCtx {
        libctx: Ptr(libctx),
        propq: propq_owned,
        key: Ptr(ptr::null_mut()),
        macctx: Ptr(macctx),
    }))
    .cast()
}

macro_rules! mac_newctx_fn {
    ($name:ident, $mac:expr) => {
        ffi_callback! {
            /// `mac_*_newctx`.
            ///
            /// # Safety
            /// `provctx` is the default provider's context; `propq` is NULL or a string.
            pub(crate) unsafe extern "C" fn $name(provctx: *mut c_void, propq: *const c_char) -> *mut c_void
            where failure = ptr::null_mut(), library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                unsafe { mac_newctx(provctx, propq, $mac) }
            }
        }
    };
}

mac_newctx_fn!(mac_hmac_newctx, c"HMAC");
mac_newctx_fn!(mac_siphash_newctx, c"SIPHASH");
mac_newctx_fn!(mac_poly1305_newctx, c"POLY1305");
mac_newctx_fn!(mac_cmac_newctx, c"CMAC");

ffi_callback! {
    /// `mac_digest_sign_init`: takes the key (or keeps the one it has), gives the MAC the key's
    /// cipher, the digest, and the key's properties, then starts it with the key.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `mdname` is NULL or a string; `vkey` is NULL or a live
    /// MAC key; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn mac_digest_sign_init(vctx: *mut c_void, mdname: *const c_char, vkey: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(vctx) }) else { return 0 };
        if c.key.0.is_null() && vkey.is_null() {
            err::raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET, "mac_digest_sign_init");
            return 0;
        }
        if !vkey.is_null() {
            // SAFETY: the caller's live key; the context takes a reference.
            unsafe { mac_key_up_ref(vkey) };
            // SAFETY: the context's old reference, or NULL.
            unsafe { mac_free(c.key.0) };
            c.key = Ptr(vkey);
        }
        // SAFETY: the context's key, live (it holds a reference).
        let Some(key) = (unsafe { mac_key(c.key.0) }) else { return 0 };
        let macctx = c.macctx.0;
        key.with(|priv_key, cipher, properties| {
            // `ossl_prov_set_macctx`: the digest, cipher, and properties (no engine: there are
            // none), then the key.
            let mut mp = Vec::with_capacity(4);
            if !mdname.is_null() {
                // SAFETY: a static key; the caller's name.
                mp.push(unsafe { OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST.as_ptr(), mdname.cast_mut(), 0) });
            }
            if !cipher.is_null() {
                // SAFETY: a static key; the cipher's name.
                mp.push(unsafe { OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER.as_ptr(), cipher.cast_mut(), 0) });
            }
            if let Some(p) = properties {
                // SAFETY: a static key; the key's properties, which outlive the call.
                mp.push(unsafe { OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_PROPERTIES.as_ptr(), p.as_ptr().cast_mut(), 0) });
            }
            mp.push(end());
            // SAFETY: the context's MAC context; the array above.
            if unsafe { EVP_MAC_CTX_set_params(macctx, mp.as_ptr()) } == 0 {
                return 0;
            }
            let (k, len) = priv_key.map_or((ptr::null(), 0), |k| (k.as_ptr(), k.len()));
            // SAFETY: the MAC context; the key's octets (in place while the lock is held); the
            // caller's array.
            c_int::from(unsafe { EVP_MAC_init(macctx, k, len, params) } != 0)
        })
    }
}

ffi_callback! {
    /// `mac_digest_sign_update`.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `data` holds `datalen` octets.
    pub(crate) unsafe extern "C" fn mac_digest_sign_update(vctx: *mut c_void, data: *const u8, datalen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(vctx) }) else { return 0 };
        if c.macctx.0.is_null() {
            return 0;
        }
        // SAFETY: the MAC context; the caller's data.
        unsafe { EVP_MAC_update(c.macctx.0, data, datalen) }
    }
}

ffi_callback! {
    /// `mac_digest_sign_final`.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `mac` is NULL or has room for `macsize` octets;
    /// `maclen` is room for a size.
    pub(crate) unsafe extern "C" fn mac_digest_sign_final(vctx: *mut c_void, mac: *mut u8, maclen: *mut usize, macsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(vctx) }) else { return 0 };
        if c.macctx.0.is_null() {
            return 0;
        }
        // SAFETY: the MAC context; the caller's buffers.
        unsafe { EVP_MAC_final(c.macctx.0, mac, maclen, macsize) }
    }
}

ffi_callback! {
    /// `mac_freectx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context, not used afterwards.
    pub(crate) unsafe extern "C" fn mac_freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        if !vctx.is_null() {
            // SAFETY: the box `mac_newctx` made, freed once.
            drop(unsafe { Box::from_raw(vctx.cast::<MacSigCtx>()) });
        }
    }
}

ffi_callback! {
    /// `mac_dupctx`: a copy with its own reference to the key and a copy of the MAC context.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context.
    pub(crate) unsafe extern "C" fn mac_dupctx(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(src) = (unsafe { context(vctx) }) else { return ptr::null_mut() };
        let mut dst = MacSigCtx {
            libctx: src.libctx,
            propq: src.propq.clone(),
            key: Ptr(ptr::null_mut()),
            macctx: Ptr(ptr::null_mut()),
        };
        if !src.key.0.is_null() {
            // SAFETY: the source's live key; the copy takes a reference.
            unsafe { mac_key_up_ref(src.key.0) };
            dst.key = src.key;
        }
        if !src.macctx.0.is_null() {
            // SAFETY: the source's MAC context.
            let m = unsafe { EVP_MAC_CTX_dup(src.macctx.0) };
            if m.is_null() {
                return ptr::null_mut();
            }
            dst.macctx = Ptr(m);
        }
        Box::into_raw(Box::new(dst)).cast()
    }
}

ffi_callback! {
    /// `mac_set_ctx_params`: the MAC context's.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn mac_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(vctx) }) else { return 0 };
        // SAFETY: the MAC context; the caller's array.
        unsafe { EVP_MAC_CTX_set_params(c.macctx.0, params) }
    }
}

/// `mac_settable_ctx_params`: the MAC's settable context parameters.
///
/// # Safety
/// `provctx` is the default provider's context.
unsafe fn settable(provctx: *mut c_void, macname: &CStr) -> *const OSSL_PARAM {
    // SAFETY: the caller's guarantee.
    let libctx = unsafe { libctx_of(provctx) };
    // SAFETY: the provider's context; a static name.
    let mac = unsafe { EVP_MAC_fetch(libctx, macname.as_ptr(), ptr::null()) };
    if mac.is_null() {
        return ptr::null();
    }
    // SAFETY: the method fetched above; its list is static.
    let params = unsafe { EVP_MAC_settable_ctx_params(mac) };
    // SAFETY: the reference fetched above.
    unsafe { EVP_MAC_free(mac) };
    params
}

macro_rules! mac_settable_fn {
    ($name:ident, $mac:expr) => {
        ffi_callback! {
            /// `mac_*_settable_ctx_params`.
            ///
            /// # Safety
            /// `provctx` is the default provider's context.
            pub(crate) unsafe extern "C" fn $name(_ctx: *mut c_void, provctx: *mut c_void) -> *const OSSL_PARAM
            where failure = ptr::null(), library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                unsafe { settable(provctx, $mac) }
            }
        }
    };
}

mac_settable_fn!(mac_hmac_settable_ctx_params, c"HMAC");
mac_settable_fn!(mac_siphash_settable_ctx_params, c"SIPHASH");
mac_settable_fn!(mac_poly1305_settable_ctx_params, c"POLY1305");
mac_settable_fn!(mac_cmac_settable_ctx_params, c"CMAC");

/// `mac_known_gettable_ctx_params`: none outside FIPS.
static MAC_GETTABLE: Params<1> = Params([PARAM_END]);

ffi_callback! {
    /// `mac_gettable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn mac_gettable_ctx_params(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        MAC_GETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `mac_get_ctx_params`: nothing to report outside FIPS.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context.
    pub(crate) unsafe extern "C" fn mac_get_ctx_params(vctx: *mut c_void, _params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        c_int::from(!vctx.is_null())
    }
}

type NewCtxFn = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
type DigestInitFn =
    unsafe extern "C" fn(*mut c_void, *const c_char, *mut c_void, *const OSSL_PARAM) -> c_int;
type UpdateFn = unsafe extern "C" fn(*mut c_void, *const u8, usize) -> c_int;
type FinalFn = unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize) -> c_int;
type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
type DupCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type SetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type GetParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type ListFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;

macro_rules! mac_signature_table {
    ($table:ident, $newctx:ident, $settable:ident) => {
        /// `ossl_mac_legacy_*_signature_functions`.
        static $table: Dispatch<11> = Dispatch([
            entry!(OSSL_FUNC_SIGNATURE_NEWCTX, $newctx, NewCtxFn),
            entry!(
                OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
                mac_digest_sign_init,
                DigestInitFn
            ),
            entry!(
                OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
                mac_digest_sign_update,
                UpdateFn
            ),
            entry!(
                OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
                mac_digest_sign_final,
                FinalFn
            ),
            entry!(OSSL_FUNC_SIGNATURE_FREECTX, mac_freectx, FreeCtxFn),
            entry!(OSSL_FUNC_SIGNATURE_DUPCTX, mac_dupctx, DupCtxFn),
            entry!(
                OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
                mac_set_ctx_params,
                SetParamsFn
            ),
            entry!(OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, $settable, ListFn),
            entry!(
                OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
                mac_get_ctx_params,
                GetParamsFn
            ),
            entry!(
                OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
                mac_gettable_ctx_params,
                ListFn
            ),
            END,
        ]);
    };
}

mac_signature_table!(
    HMAC_SIGNATURE,
    mac_hmac_newctx,
    mac_hmac_settable_ctx_params
);
mac_signature_table!(
    SIPHASH_SIGNATURE,
    mac_siphash_newctx,
    mac_siphash_settable_ctx_params
);
mac_signature_table!(
    POLY1305_SIGNATURE,
    mac_poly1305_newctx,
    mac_poly1305_settable_ctx_params
);
mac_signature_table!(
    CMAC_SIGNATURE,
    mac_cmac_newctx,
    mac_cmac_settable_ctx_params
);

/// The default provider's signature algorithms, in `deflt_signature`'s order; those of the key
/// types of later steps are pending (their names registered, nothing offered).
static DEFAULT_SIGNATURES: Algorithms<60> = Algorithms([
    pending(c"DSA:dsaEncryption:1.2.840.10040.4.1"),
    pending(c"DSA-SHA1:DSA-SHA-1:dsaWithSHA1:1.2.840.10040.4.3"),
    pending(c"DSA-SHA2-224:DSA-SHA224:dsa_with_SHA224:2.16.840.1.101.3.4.3.1"),
    pending(c"DSA-SHA2-256:DSA-SHA256:dsa_with_SHA256:2.16.840.1.101.3.4.3.2"),
    pending(c"DSA-SHA2-384:DSA-SHA384:dsa_with_SHA384:id-dsa-with-sha384:1.2.840.1.101.3.4.3.3"),
    pending(c"DSA-SHA2-512:DSA-SHA512:dsa_with_SHA512:id-dsa-with-sha512:1.2.840.1.101.3.4.3.4"),
    pending(c"DSA-SHA3-224:dsa_with_SHA3-224:id-dsa-with-sha3-224:2.16.840.1.101.3.4.3.5"),
    pending(c"DSA-SHA3-256:dsa_with_SHA3-256:id-dsa-with-sha3-256:2.16.840.1.101.3.4.3.6"),
    pending(c"DSA-SHA3-384:dsa_with_SHA3-384:id-dsa-with-sha3-384:2.16.840.1.101.3.4.3.7"),
    pending(c"DSA-SHA3-512:dsa_with_SHA3-512:id-dsa-with-sha3-512:2.16.840.1.101.3.4.3.8"),
    alg(
        c"RSA:rsaEncryption:1.2.840.113549.1.1.1",
        &rsa_sig::RSA_SIGNATURE,
    ),
    alg(
        c"RSA-RIPEMD160:ripemd160WithRSA:1.3.36.3.3.1.2",
        &rsa_sig::RSA_RIPEMD160_SIGNATURE,
    ),
    alg(
        c"RSA-SHA1:RSA-SHA-1:sha1WithRSAEncryption:1.2.840.113549.1.1.5",
        &rsa_sig::RSA_SHA1_SIGNATURE,
    ),
    alg(
        c"RSA-SHA2-224:RSA-SHA224:sha224WithRSAEncryption:1.2.840.113549.1.1.14",
        &rsa_sig::RSA_SHA224_SIGNATURE,
    ),
    alg(
        c"RSA-SHA2-256:RSA-SHA256:sha256WithRSAEncryption:1.2.840.113549.1.1.11",
        &rsa_sig::RSA_SHA256_SIGNATURE,
    ),
    alg(
        c"RSA-SHA2-384:RSA-SHA384:sha384WithRSAEncryption:1.2.840.113549.1.1.12",
        &rsa_sig::RSA_SHA384_SIGNATURE,
    ),
    alg(
        c"RSA-SHA2-512:RSA-SHA512:sha512WithRSAEncryption:1.2.840.113549.1.1.13",
        &rsa_sig::RSA_SHA512_SIGNATURE,
    ),
    alg(
        c"RSA-SHA2-512/224:RSA-SHA512-224:sha512-224WithRSAEncryption:1.2.840.113549.1.1.15",
        &rsa_sig::RSA_SHA512_224_SIGNATURE,
    ),
    alg(
        c"RSA-SHA2-512/256:RSA-SHA512-256:sha512-256WithRSAEncryption:1.2.840.113549.1.1.16",
        &rsa_sig::RSA_SHA512_256_SIGNATURE,
    ),
    alg(
        c"RSA-SHA3-224:id-rsassa-pkcs1-v1_5-with-sha3-224:2.16.840.1.101.3.4.3.13",
        &rsa_sig::RSA_SHA3_224_SIGNATURE,
    ),
    alg(
        c"RSA-SHA3-256:id-rsassa-pkcs1-v1_5-with-sha3-256:2.16.840.1.101.3.4.3.14",
        &rsa_sig::RSA_SHA3_256_SIGNATURE,
    ),
    alg(
        c"RSA-SHA3-384:id-rsassa-pkcs1-v1_5-with-sha3-384:2.16.840.1.101.3.4.3.15",
        &rsa_sig::RSA_SHA3_384_SIGNATURE,
    ),
    alg(
        c"RSA-SHA3-512:id-rsassa-pkcs1-v1_5-with-sha3-512:2.16.840.1.101.3.4.3.16",
        &rsa_sig::RSA_SHA3_512_SIGNATURE,
    ),
    alg(
        c"RSA-SM3:sm3WithRSAEncryption:1.2.156.10197.1.504",
        &rsa_sig::RSA_SM3_SIGNATURE,
    ),
    pending(c"ED25519:1.3.101.112"),
    pending(c"ED25519ph"),
    pending(c"ED25519ctx"),
    pending(c"ED448:1.3.101.113"),
    pending(c"ED448ph"),
    alg(c"ECDSA", &ecdsa_sig::ECDSA_SIGNATURE),
    alg(
        c"ECDSA-SHA1:ECDSA-SHA-1:ecdsa-with-SHA1:1.2.840.10045.4.1",
        &ecdsa_sig::ECDSA_SHA1_SIGNATURE,
    ),
    alg(
        c"ECDSA-SHA2-224:ECDSA-SHA224:ecdsa-with-SHA224:1.2.840.10045.4.3.1",
        &ecdsa_sig::ECDSA_SHA224_SIGNATURE,
    ),
    alg(
        c"ECDSA-SHA2-256:ECDSA-SHA256:ecdsa-with-SHA256:1.2.840.10045.4.3.2",
        &ecdsa_sig::ECDSA_SHA256_SIGNATURE,
    ),
    alg(
        c"ECDSA-SHA2-384:ECDSA-SHA384:ecdsa-with-SHA384:1.2.840.10045.4.3.3",
        &ecdsa_sig::ECDSA_SHA384_SIGNATURE,
    ),
    alg(
        c"ECDSA-SHA2-512:ECDSA-SHA512:ecdsa-with-SHA512:1.2.840.10045.4.3.4",
        &ecdsa_sig::ECDSA_SHA512_SIGNATURE,
    ),
    alg(
        c"ECDSA-SHA3-224:ecdsa_with_SHA3-224:id-ecdsa-with-sha3-224:2.16.840.1.101.3.4.3.9",
        &ecdsa_sig::ECDSA_SHA3_224_SIGNATURE,
    ),
    alg(
        c"ECDSA-SHA3-256:ecdsa_with_SHA3-256:id-ecdsa-with-sha3-256:2.16.840.1.101.3.4.3.10",
        &ecdsa_sig::ECDSA_SHA3_256_SIGNATURE,
    ),
    alg(
        c"ECDSA-SHA3-384:ecdsa_with_SHA3-384:id-ecdsa-with-sha3-384:2.16.840.1.101.3.4.3.11",
        &ecdsa_sig::ECDSA_SHA3_384_SIGNATURE,
    ),
    alg(
        c"ECDSA-SHA3-512:ecdsa_with_SHA3-512:id-ecdsa-with-sha3-512:2.16.840.1.101.3.4.3.12",
        &ecdsa_sig::ECDSA_SHA3_512_SIGNATURE,
    ),
    pending(c"SM2:1.2.156.10197.1.301"),
    pending(c"ML-DSA-44:MLDSA44:2.16.840.1.101.3.4.3.17:id-ml-dsa-44"),
    pending(c"ML-DSA-65:MLDSA65:2.16.840.1.101.3.4.3.18:id-ml-dsa-65"),
    pending(c"ML-DSA-87:MLDSA87:2.16.840.1.101.3.4.3.19:id-ml-dsa-87"),
    alg(c"HMAC", &HMAC_SIGNATURE),
    alg(c"SIPHASH", &SIPHASH_SIGNATURE),
    alg(c"POLY1305", &POLY1305_SIGNATURE),
    alg(c"CMAC", &CMAC_SIGNATURE),
    pending(c"SLH-DSA-SHA2-128s:id-slh-dsa-sha2-128s:2.16.840.1.101.3.4.3.20"),
    pending(c"SLH-DSA-SHA2-128f:id-slh-dsa-sha2-128f:2.16.840.1.101.3.4.3.21"),
    pending(c"SLH-DSA-SHA2-192s:id-slh-dsa-sha2-192s:2.16.840.1.101.3.4.3.22"),
    pending(c"SLH-DSA-SHA2-192f:id-slh-dsa-sha2-192f:2.16.840.1.101.3.4.3.23"),
    pending(c"SLH-DSA-SHA2-256s:id-slh-dsa-sha2-256s:2.16.840.1.101.3.4.3.24"),
    pending(c"SLH-DSA-SHA2-256f:id-slh-dsa-sha2-256f:2.16.840.1.101.3.4.3.25"),
    pending(c"SLH-DSA-SHAKE-128s:id-slh-dsa-shake-128s:2.16.840.1.101.3.4.3.26"),
    pending(c"SLH-DSA-SHAKE-128f:id-slh-dsa-shake-128f:2.16.840.1.101.3.4.3.27"),
    pending(c"SLH-DSA-SHAKE-192s:id-slh-dsa-shake-192s:2.16.840.1.101.3.4.3.28"),
    pending(c"SLH-DSA-SHAKE-192f:id-slh-dsa-shake-192f:2.16.840.1.101.3.4.3.29"),
    pending(c"SLH-DSA-SHAKE-256s:id-slh-dsa-shake-256s:2.16.840.1.101.3.4.3.30"),
    pending(c"SLH-DSA-SHAKE-256f:id-slh-dsa-shake-256f:2.16.840.1.101.3.4.3.31"),
    ALG_END,
]);

/// The default provider's signature algorithms, for `OSSL_OP_SIGNATURE`.
pub(crate) fn default_signatures() -> *const OSSL_ALGORITHM {
    DEFAULT_SIGNATURES.0.as_ptr()
}
