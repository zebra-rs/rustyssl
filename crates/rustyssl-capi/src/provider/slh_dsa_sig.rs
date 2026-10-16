//! The default provider's twelve SLH-DSA signatures (`slh_dsa_sig.c`, with `slh_dsa.c`'s
//! message handling over `rustyssl_crypto::slhdsa`), for the SLH-DSA key managers' keys
//! (`slh_dsa_kmgmt::SlhDsaKey`): a whole message signed or verified at once, through
//! `EVP_PKEY_sign_message_init` or `EVP_DigestSign`.
//!
//! The message is FIPS 205's pure encoding with the context string (`message-encoding` 1, the
//! default, or any value but 0) or the message as is (0). Signing is hedged with `n` fresh
//! octets, deterministic (`deterministic` nonzero: `PK.seed` instead), or uses a caller's
//! `test-entropy` of exactly `n` octets.
//!
//! As in OpenSSL, the context holds the key data without a reference (the `EVP_PKEY` keeps it
//! alive) and keeps its parameters across its own inits; a key of another parameter set fails
//! the init without an error; a size query needs no private key; a room too small and a
//! missing key are errors; and the algorithm identifier is `SEQUENCE { id-slh-dsa-* }`.

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_PROV, NID_SLH_DSA_SHA2_128f, NID_SLH_DSA_SHA2_128s, NID_SLH_DSA_SHA2_192f,
    NID_SLH_DSA_SHA2_192s, NID_SLH_DSA_SHA2_256f, NID_SLH_DSA_SHA2_256s, NID_SLH_DSA_SHAKE_128f,
    NID_SLH_DSA_SHAKE_128s, NID_SLH_DSA_SHAKE_192f, NID_SLH_DSA_SHAKE_192s, NID_SLH_DSA_SHAKE_256f,
    NID_SLH_DSA_SHAKE_256s, OSSL_FUNC_SIGNATURE_DIGEST_SIGN, OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
    OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
    OSSL_FUNC_SIGNATURE_DUPCTX, OSSL_FUNC_SIGNATURE_FREECTX, OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, OSSL_FUNC_SIGNATURE_NEWCTX,
    OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_SIGN, OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT, OSSL_FUNC_SIGNATURE_VERIFY,
    OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT, OSSL_LIB_CTX, OSSL_PARAM, OSSL_PARAM_INTEGER,
    OSSL_PARAM_OCTET_STRING, OSSL_SIGNATURE_PARAM_ALGORITHM_ID,
    OSSL_SIGNATURE_PARAM_CONTEXT_STRING, OSSL_SIGNATURE_PARAM_DETERMINISTIC,
    OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, OSSL_SIGNATURE_PARAM_TEST_ENTROPY,
    PROV_R_INVALID_DIGEST, PROV_R_INVALID_SIGNATURE_SIZE, PROV_R_MISSING_KEY, PROV_R_NO_KEY_SET,
};
use rustyssl_crypto::slhdsa::{self, MAX_CONTEXT, MAX_N, Variant};

use super::builtin::libctx_of;
use super::eddsa_sig::eddsa_aid;
use super::macs::{boxed, context, is_empty, locate, unbox, wipe};
use super::slh_dsa_kmgmt::{SlhDsaKey, key};
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::err;
use crate::ffi::{bytes, ffi_callback};
use crate::params::{
    OSSL_PARAM_get_int, OSSL_PARAM_get_octet_string, OSSL_PARAM_locate, OSSL_PARAM_set_octet_string,
};
use crate::rand_lib::RAND_priv_bytes_ex;

const INT_SIZE: usize = size_of::<c_int>();

/// `PROV_SLH_DSA_CTX`.
#[derive(Clone)]
struct SigCtx {
    libctx: *mut OSSL_LIB_CTX,
    /// The parameter set the algorithm signs with.
    variant: Variant,
    /// The key data, without a reference.
    key: *const c_void,
    context: Vec<u8>,
    /// The caller's `test-entropy` (`n` octets), or empty.
    entropy: Vec<u8>,
    /// `message-encoding`: 0 is the message as is, anything else the pure encoding.
    msg_encode: c_int,
    /// `deterministic`: nonzero signs with `PK.seed` for the randomness.
    deterministic: c_int,
    aid: Vec<u8>,
}

impl SigCtx {
    /// The key.
    fn key<'a>(&self) -> Option<&'a SlhDsaKey> {
        // SAFETY: the key data the operation was initialized with, kept alive by its key.
        unsafe { key(self.key) }
    }

    /// The message as the signature covers it (`msg_encode`).
    fn message(&self, msg: &[u8]) -> Option<Vec<u8>> {
        if self.msg_encode == 0 {
            return Some(msg.to_vec());
        }
        slhdsa::encode_message(&self.context, msg).map(|m| m.to_vec())
    }
}

impl Drop for SigCtx {
    fn drop(&mut self) {
        wipe(&mut self.entropy);
    }
}

/// The context behind `vctx`.
///
/// # Safety
/// `vctx` is NULL or a live context from `slh_dsa_newctx`.
unsafe fn ctx<'a>(vctx: *mut c_void) -> Option<&'a mut SigCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { context::<SigCtx>(vctx) }
}

/// The parameter set's NID.
const fn nid(variant: Variant) -> c_int {
    match variant {
        Variant::Sha2_128s => NID_SLH_DSA_SHA2_128s,
        Variant::Sha2_128f => NID_SLH_DSA_SHA2_128f,
        Variant::Sha2_192s => NID_SLH_DSA_SHA2_192s,
        Variant::Sha2_192f => NID_SLH_DSA_SHA2_192f,
        Variant::Sha2_256s => NID_SLH_DSA_SHA2_256s,
        Variant::Sha2_256f => NID_SLH_DSA_SHA2_256f,
        Variant::Shake128s => NID_SLH_DSA_SHAKE_128s,
        Variant::Shake128f => NID_SLH_DSA_SHAKE_128f,
        Variant::Shake192s => NID_SLH_DSA_SHAKE_192s,
        Variant::Shake192f => NID_SLH_DSA_SHAKE_192f,
        Variant::Shake256s => NID_SLH_DSA_SHAKE_256s,
        Variant::Shake256f => NID_SLH_DSA_SHAKE_256f,
    }
}

/// `slh_dsa_newctx`: pure encoding, hedged.
///
/// # Safety
/// `provctx` is the default provider's context.
unsafe fn newctx(provctx: *mut c_void, variant: Variant) -> *mut c_void {
    boxed(SigCtx {
        // SAFETY: the caller's guarantee.
        libctx: unsafe { libctx_of(provctx) },
        variant,
        key: ptr::null(),
        context: Vec::new(),
        entropy: Vec::new(),
        msg_encode: 1,
        deterministic: 0,
        aid: Vec::new(),
    })
}

ffi_callback! {
    /// `slh_dsa_freectx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context the caller gives up.
    pub(crate) unsafe extern "C" fn slh_dsa_freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<SigCtx>(vctx) };
    }
}

ffi_callback! {
    /// `slh_dsa_dupctx`: a copy, sharing the key data.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context.
    pub(crate) unsafe extern "C" fn slh_dsa_dupctx(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return ptr::null_mut() };
        boxed(c.clone())
    }
}

/// `slh_dsa_signverify_msg_init`: the key (or the one the context has), which must be of the
/// algorithm's parameter set, the algorithm identifier, then the parameters.
///
/// # Safety
/// `vctx` is NULL or a live context; `vkey` is NULL or live SLH-DSA key data; `params` is NULL
/// or an array.
unsafe fn msg_init(vctx: *mut c_void, vkey: *mut c_void, params: *const OSSL_PARAM) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx(vctx) }) else {
        return 0;
    };
    if vkey.is_null() && c.key.is_null() {
        err::raise(
            ERR_LIB_PROV,
            PROV_R_NO_KEY_SET,
            "slh_dsa_signverify_msg_init",
        );
        return 0;
    }
    if !vkey.is_null() {
        // SAFETY: the caller's guarantee.
        if unsafe { key(vkey) }.map(|k| k.variant) != Some(c.variant) {
            return 0;
        }
        c.key = vkey;
    }
    c.aid = eddsa_aid(nid(c.variant));
    // SAFETY: the caller's guarantee.
    unsafe { slh_dsa_set_ctx_params(vctx, params) }
}

ffi_callback! {
    /// `slh_dsa_sign_msg_init` and `slh_dsa_verify_msg_init`.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `vkey` is NULL or live SLH-DSA key data; `params` is
    /// NULL or an array.
    pub(crate) unsafe extern "C" fn slh_dsa_signverify_msg_init(vctx: *mut c_void, vkey: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { msg_init(vctx, vkey, params) }
    }
}

ffi_callback! {
    /// `slh_dsa_digest_signverify_init`: no digest may be named; without a key, only the
    /// parameters (on a context with one).
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `mdname` is NULL or a string; `vkey` is NULL or live
    /// SLH-DSA key data; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn slh_dsa_digest_signverify_init(vctx: *mut c_void, mdname: *const c_char, vkey: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !mdname.is_null() && unsafe { *mdname } != 0 {
            err::raise_with_text(
                ERR_LIB_PROV,
                PROV_R_INVALID_DIGEST,
                "slh_dsa_digest_signverify_init",
                "Explicit digest not supported for SLH-DSA operations",
            );
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if vkey.is_null() && !c.key.is_null() {
            // SAFETY: the caller's guarantee.
            return unsafe { slh_dsa_set_ctx_params(vctx, params) };
        }
        // SAFETY: the caller's guarantee.
        unsafe { msg_init(vctx, vkey, params) }
    }
}

ffi_callback! {
    /// `slh_dsa_sign` (also `slh_dsa_digest_sign`): the signature's length when `sig` is NULL,
    /// else the signature into room of at least its length.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `sig` is NULL or has room for `sigsize` octets;
    /// `siglen` is writable; `msg` holds `msg_len` octets.
    pub(crate) unsafe extern "C" fn slh_dsa_sign(vctx: *mut c_void, sig: *mut c_uchar, siglen: *mut usize, sigsize: usize, msg: *const c_uchar, msg_len: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "slh_sign_internal";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        let Some(k) = c.key() else { return 0 };
        let v = k.variant;
        let sig_len = v.signature_bytes();
        if sig.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { siglen.write(sig_len) };
            return 1;
        }
        let mut drawn = [0u8; MAX_N];
        let rand = if !c.entropy.is_empty() {
            Some(c.entropy.as_slice())
        } else if c.deterministic == 0 {
            let room = drawn.get_mut(..v.n()).unwrap_or_default();
            // SAFETY: the context's library context; room for `n` octets.
            if unsafe { RAND_priv_bytes_ex(c.libctx, room.as_mut_ptr(), room.len(), 0) } <= 0 {
                return 0;
            }
            drawn.get(..v.n())
        } else {
            None
        };
        // SAFETY: the caller's guarantee.
        let m = unsafe { bytes(msg, msg_len) }.and_then(|m| c.message(m));
        let ret = (|| {
            let mut m = m?;
            if sigsize < sig_len {
                err::raise_with_text(
                    ERR_LIB_PROV,
                    PROV_R_INVALID_SIGNATURE_SIZE,
                    F,
                    &format!("is {sigsize}, should be at least {sig_len}"),
                );
                wipe(&mut m);
                return None;
            }
            let private = k.lock().private().cloned();
            let Some(private) = private else {
                err::raise(ERR_LIB_PROV, PROV_R_MISSING_KEY, F);
                wipe(&mut m);
                return None;
            };
            let s = private.sign(&m, rand);
            wipe(&mut m);
            let s = s?;
            // SAFETY: the caller's room for `sigsize` (at least `sig_len`) octets.
            unsafe { ptr::copy_nonoverlapping(s.as_ptr(), sig, s.len()) };
            // SAFETY: the caller's guarantee.
            unsafe { siglen.write(sig_len) };
            Some(1)
        })();
        wipe(&mut drawn);
        ret.unwrap_or(0)
    }
}

ffi_callback! {
    /// `slh_dsa_verify` (also `slh_dsa_digest_verify`): whether `sig` signs `msg` (a key
    /// without a public key is an error; a signature of the wrong length fails).
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `sig` holds `siglen` octets; `msg` holds `msg_len`
    /// octets.
    pub(crate) unsafe extern "C" fn slh_dsa_verify(vctx: *mut c_void, sig: *const c_uchar, siglen: usize, msg: *const c_uchar, msg_len: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        let Some(k) = c.key() else { return 0 };
        // SAFETY: the caller's guarantee.
        let Some(mut m) = (unsafe { bytes(msg, msg_len) }).and_then(|m| c.message(m)) else {
            return 0;
        };
        let public = k.lock().public();
        let ret = match public {
            None => {
                err::raise(ERR_LIB_PROV, PROV_R_MISSING_KEY, "slh_verify_internal");
                false
            }
            // SAFETY: the caller's guarantee.
            Some(p) => unsafe { bytes(sig, siglen) }.is_some_and(|s| p.verify(&m, s)),
        };
        wipe(&mut m);
        c_int::from(ret)
    }
}

ffi_callback! {
    /// `slh_dsa_set_ctx_params`: the context string (at most 255 octets; a failure empties it),
    /// `test-entropy` (exactly `n` octets for the key; a failure forgets it), `deterministic`,
    /// and `message-encoding`, stopping at the first failure.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn slh_dsa_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: the caller's array; a static name.
        if let Some(p) = unsafe { locate(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING) } {
            let mut buf = [0u8; MAX_CONTEXT];
            let mut data = buf.as_mut_ptr().cast::<c_void>();
            let mut n = 0;
            // SAFETY: a parameter of the array; the buffer.
            if unsafe { OSSL_PARAM_get_octet_string(p, &raw mut data, MAX_CONTEXT, &raw mut n) } != 1 {
                c.context.clear();
                return 0;
            }
            c.context = buf.get(..n).unwrap_or_default().to_vec();
        }
        // SAFETY: the caller's array; a static name.
        if let Some(p) = unsafe { locate(params, OSSL_SIGNATURE_PARAM_TEST_ENTROPY) } {
            let Some(n) = c.key().map(|k| k.variant.n()) else { return 0 };
            wipe(&mut c.entropy);
            c.entropy.clear();
            let mut buf = [0u8; MAX_N];
            let mut data = buf.as_mut_ptr().cast::<c_void>();
            let mut len = 0;
            // SAFETY: a parameter of the array; the buffer's first `n` octets.
            let got = unsafe { OSSL_PARAM_get_octet_string(p, &raw mut data, n, &raw mut len) };
            if got == 1 && len == n {
                c.entropy = buf.get(..n).unwrap_or_default().to_vec();
            }
            wipe(&mut buf);
            if c.entropy.is_empty() {
                return 0;
            }
        }
        for (name, field) in [
            (OSSL_SIGNATURE_PARAM_DETERMINISTIC, &mut c.deterministic),
            (OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &mut c.msg_encode),
        ] {
            // SAFETY: the caller's array; a static name.
            if let Some(p) = unsafe { locate(params, name) }
                // SAFETY: a parameter of the array; the context's field.
                && unsafe { OSSL_PARAM_get_int(p, field) } == 0
            {
                return 0;
            }
        }
        1
    }
}

/// `settable_ctx_params`.
static SETTABLE: Params<5> = Params([
    defn(
        OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
        OSSL_PARAM_OCTET_STRING,
        0,
    ),
    defn(
        OSSL_SIGNATURE_PARAM_TEST_ENTROPY,
        OSSL_PARAM_OCTET_STRING,
        0,
    ),
    defn(
        OSSL_SIGNATURE_PARAM_DETERMINISTIC,
        OSSL_PARAM_INTEGER,
        INT_SIZE,
    ),
    defn(
        OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING,
        OSSL_PARAM_INTEGER,
        INT_SIZE,
    ),
    PARAM_END,
]);

ffi_callback! {
    /// `slh_dsa_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn slh_dsa_settable_ctx_params(_vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SETTABLE.0.as_ptr()
    }
}

/// `known_gettable_ctx_params`.
static GETTABLE: Params<2> = Params([
    defn(
        OSSL_SIGNATURE_PARAM_ALGORITHM_ID,
        OSSL_PARAM_OCTET_STRING,
        0,
    ),
    PARAM_END,
]);

ffi_callback! {
    /// `slh_dsa_gettable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn slh_dsa_gettable_ctx_params(_vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        GETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `slh_dsa_get_ctx_params`: the algorithm identifier (failing before an init).
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn slh_dsa_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        // SAFETY: the caller's array; a static name.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID.as_ptr()) };
        if !p.is_null() {
            let aid = if c.aid.is_empty() { ptr::null() } else { c.aid.as_ptr() };
            // SAFETY: a parameter of the array; the identifier, or NULL (which fails).
            if unsafe { OSSL_PARAM_set_octet_string(p, aid.cast(), c.aid.len()) } != 1 {
                return 0;
            }
        }
        1
    }
}

type NewCtxFn = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
type InitFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *const OSSL_PARAM) -> c_int;
type SignFn = unsafe extern "C" fn(
    *mut c_void,
    *mut c_uchar,
    *mut usize,
    usize,
    *const c_uchar,
    usize,
) -> c_int;
type VerifyFn =
    unsafe extern "C" fn(*mut c_void, *const c_uchar, usize, *const c_uchar, usize) -> c_int;
type DigestInitFn =
    unsafe extern "C" fn(*mut c_void, *const c_char, *mut c_void, *const OSSL_PARAM) -> c_int;
type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
type DupCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type GetParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type SetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type ListFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;

/// `MAKE_SIGNATURE_FUNCTIONS(alg, fn)`: a parameter set's new-context callback and table.
macro_rules! slh_dsa_signature {
    ($new:ident, $table:ident, $variant:expr) => {
        ffi_callback! {
            /// The parameter set's `slh_dsa_newctx`.
            ///
            /// # Safety
            /// `provctx` is the default provider's context.
            pub(crate) unsafe extern "C" fn $new(provctx: *mut c_void, _propq: *const c_char) -> *mut c_void
            where failure = ptr::null_mut(), library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                unsafe { newctx(provctx, $variant) }
            }
        }

        /// `ossl_slh_dsa_*_signature_functions`.
        pub(crate) static $table: Dispatch<16> = Dispatch([
            entry!(OSSL_FUNC_SIGNATURE_NEWCTX, $new, NewCtxFn),
            entry!(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT, slh_dsa_signverify_msg_init, InitFn),
            entry!(OSSL_FUNC_SIGNATURE_SIGN, slh_dsa_sign, SignFn),
            entry!(OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT, slh_dsa_signverify_msg_init, InitFn),
            entry!(OSSL_FUNC_SIGNATURE_VERIFY, slh_dsa_verify, VerifyFn),
            entry!(OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, slh_dsa_digest_signverify_init, DigestInitFn),
            entry!(OSSL_FUNC_SIGNATURE_DIGEST_SIGN, slh_dsa_sign, SignFn),
            entry!(OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, slh_dsa_digest_signverify_init, DigestInitFn),
            entry!(OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, slh_dsa_verify, VerifyFn),
            entry!(OSSL_FUNC_SIGNATURE_FREECTX, slh_dsa_freectx, FreeCtxFn),
            entry!(OSSL_FUNC_SIGNATURE_DUPCTX, slh_dsa_dupctx, DupCtxFn),
            entry!(OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, slh_dsa_set_ctx_params, SetParamsFn),
            entry!(OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, slh_dsa_settable_ctx_params, ListFn),
            entry!(OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, slh_dsa_get_ctx_params, GetParamsFn),
            entry!(OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, slh_dsa_gettable_ctx_params, ListFn),
            END,
        ]);
    };
}

slh_dsa_signature!(
    slh_dsa_sha2_128s_newctx,
    SHA2_128S_SIGNATURE,
    Variant::Sha2_128s
);
slh_dsa_signature!(
    slh_dsa_sha2_128f_newctx,
    SHA2_128F_SIGNATURE,
    Variant::Sha2_128f
);
slh_dsa_signature!(
    slh_dsa_sha2_192s_newctx,
    SHA2_192S_SIGNATURE,
    Variant::Sha2_192s
);
slh_dsa_signature!(
    slh_dsa_sha2_192f_newctx,
    SHA2_192F_SIGNATURE,
    Variant::Sha2_192f
);
slh_dsa_signature!(
    slh_dsa_sha2_256s_newctx,
    SHA2_256S_SIGNATURE,
    Variant::Sha2_256s
);
slh_dsa_signature!(
    slh_dsa_sha2_256f_newctx,
    SHA2_256F_SIGNATURE,
    Variant::Sha2_256f
);
slh_dsa_signature!(
    slh_dsa_shake_128s_newctx,
    SHAKE_128S_SIGNATURE,
    Variant::Shake128s
);
slh_dsa_signature!(
    slh_dsa_shake_128f_newctx,
    SHAKE_128F_SIGNATURE,
    Variant::Shake128f
);
slh_dsa_signature!(
    slh_dsa_shake_192s_newctx,
    SHAKE_192S_SIGNATURE,
    Variant::Shake192s
);
slh_dsa_signature!(
    slh_dsa_shake_192f_newctx,
    SHAKE_192F_SIGNATURE,
    Variant::Shake192f
);
slh_dsa_signature!(
    slh_dsa_shake_256s_newctx,
    SHAKE_256S_SIGNATURE,
    Variant::Shake256s
);
slh_dsa_signature!(
    slh_dsa_shake_256f_newctx,
    SHAKE_256F_SIGNATURE,
    Variant::Shake256f
);
