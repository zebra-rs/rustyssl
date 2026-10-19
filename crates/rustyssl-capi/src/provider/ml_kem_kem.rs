//! The default provider's ML-KEM KEM (`ml_kem_kem.c`), for the three ML-KEM key managers' keys
//! (`ml_kem_kmgmt::MlKemKey`): encapsulation to a public key, with random entropy or a caller's
//! `ikmE` of exactly 32 octets (used for one encapsulation), and decapsulation with a private
//! key.
//!
//! As in OpenSSL, the context holds the key data without a reference (the `EVP_PKEY` keeps it
//! alive), a size query needs only one of the lengths, the ciphertext's length is written before
//! the secret's is checked, a decapsulation tolerates a NULL length, and a ciphertext of the
//! wrong length fails with a random secret written.

use core::ffi::{c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_PROV, EVP_PKEY_OP_DECAPSULATE, EVP_PKEY_OP_ENCAPSULATE, OSSL_FUNC_KEM_DECAPSULATE,
    OSSL_FUNC_KEM_DECAPSULATE_INIT, OSSL_FUNC_KEM_ENCAPSULATE, OSSL_FUNC_KEM_ENCAPSULATE_INIT,
    OSSL_FUNC_KEM_FREECTX, OSSL_FUNC_KEM_NEWCTX, OSSL_FUNC_KEM_SET_CTX_PARAMS,
    OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, OSSL_KEM_PARAM_IKME, OSSL_PARAM, OSSL_PARAM_OCTET_STRING,
    PROV_R_INVALID_SEED_LENGTH, PROV_R_MISSING_KEY, PROV_R_NULL_LENGTH_POINTER,
    PROV_R_NULL_OUTPUT_BUFFER, PROV_R_OUTPUT_BUFFER_TOO_SMALL,
};
use rustyssl_crypto::mlkem::{RANDOM_BYTES, SHARED_SECRET_BYTES};

use super::macs::{boxed, context, is_empty, locate, unbox, wipe};
use super::ml_kem_kmgmt::{MlKemKey, key};
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::err;
use crate::ffi::{bytes, ffi_callback};
use crate::params::OSSL_PARAM_get_octet_string;
use crate::rand_lib::RAND_bytes_ex;

/// `PROV_ML_KEM_CTX`.
struct KemCtx {
    /// The key data, without a reference.
    key: *const c_void,
    /// The `ikmE` for the next encapsulation.
    entropy: Option<[u8; RANDOM_BYTES]>,
    op: c_int,
}

impl KemCtx {
    /// Forgets the entropy, wiping it.
    fn clear_entropy(&mut self) {
        if let Some(e) = self.entropy.as_mut() {
            wipe(e);
        }
        self.entropy = None;
    }

    /// The key.
    fn key<'a>(&self) -> Option<&'a MlKemKey> {
        // SAFETY: the key data the operation was initialized with, kept alive by its key.
        unsafe { key(self.key) }
    }
}

impl Drop for KemCtx {
    fn drop(&mut self) {
        self.clear_entropy();
    }
}

/// The context behind `vctx`.
///
/// # Safety
/// `vctx` is NULL or a live context from `ml_kem_newctx`.
unsafe fn ctx<'a>(vctx: *mut c_void) -> Option<&'a mut KemCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { context::<KemCtx>(vctx) }
}

/// Whether the key has a public key (`ossl_ml_kem_have_pubkey`).
fn has_public(k: Option<&MlKemKey>) -> bool {
    k.is_some_and(|k| k.lock().public().is_some())
}

/// Whether the key has a private key (`ossl_ml_kem_have_prvkey`).
fn has_private(k: Option<&MlKemKey>) -> bool {
    k.is_some_and(|k| k.lock().private().is_some())
}

ffi_callback! {
    /// `ml_kem_newctx`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn ml_kem_newctx(_provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        boxed(KemCtx { key: ptr::null(), entropy: None, op: 0 })
    }
}

ffi_callback! {
    /// `ml_kem_freectx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context the caller gives up.
    pub(crate) unsafe extern "C" fn ml_kem_freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<KemCtx>(vctx) };
    }
}

ffi_callback! {
    /// `ml_kem_set_ctx_params`: a decapsulation forgets any entropy; an encapsulation takes an
    /// `ikmE` of exactly 32 octets.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ml_kem_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { crate::provider::param_decoders::decode(params, &crate::provider::param_decoders::ML_KEM_SET_CTX_PARAMS) } {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.op == EVP_PKEY_OP_DECAPSULATE {
            c.clear_entropy();
        }
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        if c.op == EVP_PKEY_OP_ENCAPSULATE
            // SAFETY: the caller's array; a static name.
            && let Some(p) = unsafe { locate(params, OSSL_KEM_PARAM_IKME) }
        {
            let mut buf = [0u8; RANDOM_BYTES];
            let mut out = buf.as_mut_ptr().cast::<c_void>();
            let mut len = RANDOM_BYTES;
            // SAFETY: the parameter; room for the entropy.
            let got = unsafe { OSSL_PARAM_get_octet_string(p, &raw mut out, RANDOM_BYTES, &raw mut len) };
            c.clear_entropy();
            if got != 0 && len == RANDOM_BYTES {
                c.entropy = Some(buf);
                wipe(&mut buf);
                return 1;
            }
            wipe(&mut buf);
            err::raise(ERR_LIB_PROV, PROV_R_INVALID_SEED_LENGTH, "ml_kem_set_ctx_params");
            return 0;
        }
        1
    }
}

/// `ml_kem_settable_ctx_params`' list.
static SETTABLE: Params<2> = Params([
    defn(OSSL_KEM_PARAM_IKME, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `ml_kem_settable_ctx_params`.
    pub(crate) unsafe extern "C" fn ml_kem_settable_ctx_params(_vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SETTABLE.0.as_ptr()
    }
}

/// `ml_kem_init`: the key and operation, then the parameters.
///
/// # Safety
/// `vctx` is NULL or a live context; `vkey` is live key data; `params` is NULL or an array.
unsafe fn init(
    vctx: *mut c_void,
    op: c_int,
    vkey: *mut c_void,
    params: *const OSSL_PARAM,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx(vctx) }) else {
        return 0;
    };
    c.key = vkey;
    c.op = op;
    // SAFETY: the caller's guarantee.
    unsafe { ml_kem_set_ctx_params(vctx, params) }
}

ffi_callback! {
    /// `ml_kem_encapsulate_init`: a key with a public key.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `vkey` is NULL or live key data; `params` is NULL or
    /// an array.
    pub(crate) unsafe extern "C" fn ml_kem_encapsulate_init(vctx: *mut c_void, vkey: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !has_public(unsafe { key(vkey) }) {
            err::raise(ERR_LIB_PROV, PROV_R_MISSING_KEY, "ml_kem_encapsulate_init");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { init(vctx, EVP_PKEY_OP_ENCAPSULATE, vkey, params) }
    }
}

ffi_callback! {
    /// `ml_kem_decapsulate_init`: a key with a private key.
    ///
    /// # Safety
    /// As for `ml_kem_encapsulate_init`.
    pub(crate) unsafe extern "C" fn ml_kem_decapsulate_init(vctx: *mut c_void, vkey: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !has_private(unsafe { key(vkey) }) {
            err::raise(ERR_LIB_PROV, PROV_R_MISSING_KEY, "ml_kem_decapsulate_init");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { init(vctx, EVP_PKEY_OP_DECAPSULATE, vkey, params) }
    }
}

/// The body of `ml_kem_encapsulate`, before the entropy is forgotten.
///
/// # Safety
/// As for `ml_kem_encapsulate`.
unsafe fn encapsulate(
    c: &mut KemCtx,
    ctext: *mut c_uchar,
    clen: *mut usize,
    shsec: *mut c_uchar,
    slen: *mut usize,
) -> c_int {
    const F: &str = "ml_kem_encapsulate";
    let k = c.key();
    let Some(k) = k.filter(|k| has_public(Some(k))) else {
        err::raise(ERR_LIB_PROV, PROV_R_MISSING_KEY, F);
        return 0;
    };
    let ctext_bytes = k.variant.ciphertext_bytes();
    if shsec.is_null() {
        err::raise_with_text(
            ERR_LIB_PROV,
            PROV_R_NULL_OUTPUT_BUFFER,
            F,
            "NULL shared-secret buffer",
        );
        return 0;
    }
    // SAFETY: the caller's guarantee: NULL or a live `size_t`.
    let Some(cl) = (unsafe { clen.as_mut() }) else {
        err::raise_with_text(
            ERR_LIB_PROV,
            PROV_R_NULL_LENGTH_POINTER,
            F,
            "null ciphertext input/output length pointer",
        );
        return 0;
    };
    if *cl < ctext_bytes {
        err::raise_with_text(
            ERR_LIB_PROV,
            PROV_R_OUTPUT_BUFFER_TOO_SMALL,
            F,
            "ciphertext buffer too small",
        );
        return 0;
    }
    *cl = ctext_bytes;
    // SAFETY: as above.
    let Some(sl) = (unsafe { slen.as_mut() }) else {
        err::raise_with_text(
            ERR_LIB_PROV,
            PROV_R_NULL_LENGTH_POINTER,
            F,
            "null shared secret input/output length pointer",
        );
        return 0;
    };
    if *sl < SHARED_SECRET_BYTES {
        err::raise_with_text(
            ERR_LIB_PROV,
            PROV_R_OUTPUT_BUFFER_TOO_SMALL,
            F,
            "shared-secret buffer too small",
        );
        return 0;
    }
    *sl = SHARED_SECRET_BYTES;
    let mut entropy = match c.entropy {
        Some(e) => e,
        None => {
            let mut r = [0u8; RANDOM_BYTES];
            // SAFETY: the key's library context; room for the entropy.
            if unsafe { RAND_bytes_ex(k.libctx.0, r.as_mut_ptr(), RANDOM_BYTES, k.strength()) } < 1
            {
                return 0;
            }
            r
        }
    };
    let result = k.lock().public().and_then(|p| p.encapsulate(&entropy));
    wipe(&mut entropy);
    let Some((ct, secret)) = result else {
        return 0;
    };
    // SAFETY: the caller's room for at least the ciphertext's length (`*clen`).
    unsafe { ptr::copy_nonoverlapping(ct.as_ptr(), ctext, ct.len()) };
    // SAFETY: the caller's room for at least the secret's length (`*slen`).
    unsafe { ptr::copy_nonoverlapping(secret.as_ptr(), shsec, secret.len()) };
    1
}

ffi_callback! {
    /// `ml_kem_encapsulate`: the lengths when `ctext` is NULL (failing if both are NULL), else
    /// the ciphertext and shared secret into rooms of at least their lengths. Any `ikmE` set is
    /// used once.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `ctext` and `shsec` are NULL or have room for `*clen`
    /// and `*slen` octets; `clen` and `slen` are NULL or live `size_t`s.
    pub(crate) unsafe extern "C" fn ml_kem_encapsulate(vctx: *mut c_void, ctext: *mut c_uchar, clen: *mut usize, shsec: *mut c_uchar, slen: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if ctext.is_null()
            && let Some(k) = c.key().filter(|k| has_public(Some(k)))
        {
            if clen.is_null() && slen.is_null() {
                return 0;
            }
            // SAFETY: the caller's guarantee: NULL or a live `size_t`.
            if let Some(cl) = unsafe { clen.as_mut() } {
                *cl = k.variant.ciphertext_bytes();
            }
            // SAFETY: as above.
            if let Some(sl) = unsafe { slen.as_mut() } {
                *sl = SHARED_SECRET_BYTES;
            }
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let ret = unsafe { encapsulate(c, ctext, clen, shsec, slen) };
        c.clear_entropy();
        ret
    }
}

ffi_callback! {
    /// `ml_kem_decapsulate`: the secret's length when `shsec` is NULL, else the secret into room
    /// of at least its length (a NULL length taken as enough); a ciphertext of the wrong length
    /// fails with random octets written.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `shsec` is NULL or has room for `*slen` octets (32 if
    /// `slen` is NULL); `slen` is NULL or a live `size_t`; `ctext` holds `clen` octets.
    pub(crate) unsafe extern "C" fn ml_kem_decapsulate(vctx: *mut c_void, shsec: *mut c_uchar, slen: *mut usize, ctext: *const c_uchar, clen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "ml_kem_decapsulate";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        let Some(k) = c.key().filter(|k| has_private(Some(k))) else {
            err::raise(ERR_LIB_PROV, PROV_R_MISSING_KEY, F);
            return 0;
        };
        // SAFETY: the caller's guarantee: NULL or a live `size_t`.
        let sl = unsafe { slen.as_mut() };
        if shsec.is_null() {
            let Some(sl) = sl else { return 0 };
            *sl = SHARED_SECRET_BYTES;
            return 1;
        }
        if let Some(sl) = sl {
            if *sl < SHARED_SECRET_BYTES {
                err::raise_with_text(
                    ERR_LIB_PROV,
                    PROV_R_OUTPUT_BUFFER_TOO_SMALL,
                    F,
                    "shared-secret buffer too small",
                );
                return 0;
            }
            *sl = SHARED_SECRET_BYTES;
        }
        // `ossl_ml_kem_decap`.
        // SAFETY: the caller's guarantee.
        let ct = unsafe { bytes(ctext, clen) }.filter(|ct| ct.len() == k.variant.ciphertext_bytes());
        let secret = ct.and_then(|ct| k.lock().private().and_then(|p| p.decapsulate(ct)));
        let Some(secret) = secret else {
            if ct.is_none() {
                // SAFETY: the key's library context; the caller's room for the secret.
                unsafe { RAND_bytes_ex(k.libctx.0, shsec, SHARED_SECRET_BYTES, k.strength()) };
            }
            return 0;
        };
        // SAFETY: the caller's room for at least the secret's length.
        unsafe { ptr::copy_nonoverlapping(secret.as_ptr(), shsec, secret.len()) };
        1
    }
}

type NewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type InitFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *const OSSL_PARAM) -> c_int;
type EncapsulateFn =
    unsafe extern "C" fn(*mut c_void, *mut c_uchar, *mut usize, *mut c_uchar, *mut usize) -> c_int;
type DecapsulateFn =
    unsafe extern "C" fn(*mut c_void, *mut c_uchar, *mut usize, *const c_uchar, usize) -> c_int;
type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
type SetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type ListFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;

/// `ossl_ml_kem_asym_kem_functions`.
pub(crate) static ML_KEM_KEM: Dispatch<9> = Dispatch([
    entry!(OSSL_FUNC_KEM_NEWCTX, ml_kem_newctx, NewCtxFn),
    entry!(
        OSSL_FUNC_KEM_ENCAPSULATE_INIT,
        ml_kem_encapsulate_init,
        InitFn
    ),
    entry!(OSSL_FUNC_KEM_ENCAPSULATE, ml_kem_encapsulate, EncapsulateFn),
    entry!(
        OSSL_FUNC_KEM_DECAPSULATE_INIT,
        ml_kem_decapsulate_init,
        InitFn
    ),
    entry!(OSSL_FUNC_KEM_DECAPSULATE, ml_kem_decapsulate, DecapsulateFn),
    entry!(OSSL_FUNC_KEM_FREECTX, ml_kem_freectx, FreeCtxFn),
    entry!(
        OSSL_FUNC_KEM_SET_CTX_PARAMS,
        ml_kem_set_ctx_params,
        SetParamsFn
    ),
    entry!(
        OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,
        ml_kem_settable_ctx_params,
        ListFn
    ),
    END,
]);
