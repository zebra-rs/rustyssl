//! The default provider's ML-DSA-44, ML-DSA-65, and ML-DSA-87 signatures (`ml_dsa_sig.c`, with
//! `ml_dsa_sign.c`'s message handling over `rustyssl_crypto::mldsa`), for the ML-DSA key
//! managers' keys (`ml_dsa_kmgmt::MlDsaKey`): a whole message signed or verified at once,
//! through `EVP_PKEY_sign_message_init` or `EVP_DigestSign`.
//!
//! The message is FIPS 204's pure encoding with the context string (`message-encoding` 1, the
//! default), the message as is (0), or, with `mu` set, the 64-octet representative `mu`
//! itself. Signing is hedged with fresh randomness, deterministic (`deterministic` 1), or uses
//! a caller's `test-entropy` of exactly 32 octets.
//!
//! As in OpenSSL, the context holds the key data without a reference (the `EVP_PKEY` keeps it
//! alive) and keeps its context string, entropy, and flags across inits (only `mu` is reset);
//! a key of another parameter set, a key without the needed half, a room too small, and a
//! representative of the wrong length all fail without an error; and a sign that fails after
//! the room check still reports the signature's length. The algorithm identifier is
//! `SEQUENCE { id-ml-dsa-NN }`.

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_PROV, EVP_PKEY_OP_SIGN, EVP_PKEY_OP_SIGNMSG, EVP_PKEY_OP_VERIFYMSG, NID_ML_DSA_44,
    NID_ML_DSA_65, NID_ML_DSA_87, OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
    OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,
    OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, OSSL_FUNC_SIGNATURE_DUPCTX,
    OSSL_FUNC_SIGNATURE_FREECTX, OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, OSSL_FUNC_SIGNATURE_NEWCTX,
    OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_SIGNATURE_SIGN, OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL,
    OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT, OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE,
    OSSL_FUNC_SIGNATURE_VERIFY, OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL,
    OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT, OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE,
    OSSL_LIB_CTX, OSSL_PARAM, OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_STRING,
    OSSL_SIGNATURE_PARAM_ALGORITHM_ID, OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
    OSSL_SIGNATURE_PARAM_DETERMINISTIC, OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING,
    OSSL_SIGNATURE_PARAM_MU, OSSL_SIGNATURE_PARAM_SIGNATURE, OSSL_SIGNATURE_PARAM_TEST_ENTROPY,
    PROV_R_BAD_LENGTH, PROV_R_INVALID_DIGEST, PROV_R_INVALID_SEED_LENGTH, PROV_R_NO_KEY_SET,
};
use rustyssl_crypto::mldsa::{
    self, MAX_CONTEXT, MU_BYTES, MuHasher, PublicKey, RANDOM_BYTES, Variant,
};

use super::builtin::libctx_of;
use super::eddsa_sig::eddsa_aid;
use super::macs::{boxed, context, is_empty, locate, unbox, wipe};
use super::ml_dsa_kmgmt::{MlDsaKey, key};
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::err;
use crate::ffi::{bytes, ffi_callback};
use crate::params::{
    OSSL_PARAM_get_int, OSSL_PARAM_get_octet_string, OSSL_PARAM_locate, OSSL_PARAM_set_octet_string,
};
use crate::rand_lib::RAND_priv_bytes_ex;

const INT_SIZE: usize = size_of::<c_int>();

/// `PROV_ML_DSA_CTX`.
#[derive(Clone)]
struct SigCtx {
    libctx: *mut OSSL_LIB_CTX,
    /// The parameter set the algorithm signs with.
    variant: Variant,
    /// The key data, without a reference.
    key: *const c_void,
    context: Vec<u8>,
    /// The caller's `test-entropy`.
    entropy: Option<[u8; RANDOM_BYTES]>,
    /// `message-encoding`: 0 is the message as is, anything else the pure encoding.
    msg_encode: c_int,
    /// `deterministic`: 1 signs with zeros for the randomness.
    deterministic: c_int,
    aid: Vec<u8>,
    /// `mu`: the message is the representative `mu`.
    mu: c_int,
    /// The operation the context was last initialized for (`EVP_PKEY_OP_*`).
    operation: c_int,
    /// 3.6's message in pieces (`md_ctx`), from the first update; it survives a new init, as
    /// the reference's does.
    hasher: Option<MuHasher>,
    /// The signature a message-at-a-time verification checks (`signature`).
    sig: Option<Vec<u8>>,
}

impl SigCtx {
    /// The key.
    fn key<'a>(&self) -> Option<&'a MlDsaKey> {
        // SAFETY: the key data the operation was initialized with, kept alive by its key.
        unsafe { key(self.key) }
    }

    /// The representative `mu` of `msg` for `public` (`ml_dsa_sign_internal`'s and
    /// `ml_dsa_verify_internal`'s start), or `None` for a given `mu` of the wrong length.
    fn mu(&self, public: &PublicKey, msg: &[u8]) -> Option<[u8; MU_BYTES]> {
        if self.mu != 0 {
            let mu = <[u8; MU_BYTES]>::try_from(msg).ok();
            if mu.is_none() {
                // 3.6 says why (3.5 failed silently).
                err::raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH, "ml_dsa_sign_internal");
            }
            return mu;
        }
        if self.msg_encode == 0 {
            return public.mu(msg);
        }
        let mut m = mldsa::encode_message(&self.context, msg)?;
        let mu = public.mu(&m);
        // The encoded message may hold confidential content.
        wipe(&mut m);
        mu
    }
}

impl Drop for SigCtx {
    fn drop(&mut self) {
        if let Some(e) = self.entropy.as_mut() {
            wipe(e);
        }
    }
}

/// The context behind `vctx`.
///
/// # Safety
/// `vctx` is NULL or a live context from `ml_dsa_newctx`.
unsafe fn ctx<'a>(vctx: *mut c_void) -> Option<&'a mut SigCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { context::<SigCtx>(vctx) }
}

/// The parameter set's NID.
const fn nid(variant: Variant) -> c_int {
    match variant {
        Variant::MlDsa44 => NID_ML_DSA_44,
        Variant::MlDsa65 => NID_ML_DSA_65,
        Variant::MlDsa87 => NID_ML_DSA_87,
    }
}

/// `ml_dsa_newctx`: pure encoding, hedged.
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
        entropy: None,
        msg_encode: 1,
        deterministic: 0,
        aid: Vec::new(),
        mu: 0,
        operation: 0,
        hasher: None,
        sig: None,
    })
}

ffi_callback! {
    /// `ml_dsa_freectx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context the caller gives up.
    pub(crate) unsafe extern "C" fn ml_dsa_freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<SigCtx>(vctx) };
    }
}

ffi_callback! {
    /// `ml_dsa_dupctx`: a copy, sharing the key data.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context.
    pub(crate) unsafe extern "C" fn ml_dsa_dupctx(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return ptr::null_mut() };
        boxed(c.clone())
    }
}

/// `ml_dsa_signverify_msg_init`: the key (or the one the context has), which must be of the
/// algorithm's parameter set, the algorithm identifier, `mu` reset, then the parameters.
///
/// # Safety
/// `vctx` is NULL or a live context; `vkey` is NULL or live ML-DSA key data; `params` is NULL
/// or an array.
unsafe fn msg_init(
    vctx: *mut c_void,
    vkey: *mut c_void,
    params: *const OSSL_PARAM,
    operation: c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx(vctx) }) else {
        return 0;
    };
    if vkey.is_null() && c.key.is_null() {
        err::raise(
            ERR_LIB_PROV,
            PROV_R_NO_KEY_SET,
            "ml_dsa_signverify_msg_init",
        );
        return 0;
    }
    if !vkey.is_null() {
        c.key = vkey;
    }
    if c.key().map(|k| k.variant) != Some(c.variant) {
        return 0;
    }
    c.aid = eddsa_aid(nid(c.variant));
    c.mu = 0;
    c.operation = operation;
    // SAFETY: the caller's guarantee.
    unsafe { ml_dsa_set_ctx_params(vctx, params) }
}

ffi_callback! {
    /// `ml_dsa_sign_msg_init`.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `vkey` is NULL or live ML-DSA key data; `params` is
    /// NULL or an array.
    pub(crate) unsafe extern "C" fn ml_dsa_sign_msg_init(vctx: *mut c_void, vkey: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { msg_init(vctx, vkey, params, EVP_PKEY_OP_SIGNMSG) }
    }
}

ffi_callback! {
    /// `ml_dsa_verify_msg_init`.
    ///
    /// # Safety
    /// As for [`ml_dsa_sign_msg_init`].
    pub(crate) unsafe extern "C" fn ml_dsa_verify_msg_init(vctx: *mut c_void, vkey: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { msg_init(vctx, vkey, params, EVP_PKEY_OP_VERIFYMSG) }
    }
}

ffi_callback! {
    /// `ml_dsa_signverify_msg_update` (3.6): the next piece of the message, hashed into `mu`
    /// (refused when the message is `mu` itself).
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `data` holds `datalen` octets.
    pub(crate) unsafe extern "C" fn ml_dsa_signverify_msg_update(vctx: *mut c_void, data: *const c_uchar, datalen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.mu != 0 {
            return 0;
        }
        if c.hasher.is_none() {
            let Some(k) = c.key() else { return 0 };
            let material = k.lock();
            let Some(public) = material.public() else { return 0 };
            let context = (c.msg_encode != 0).then_some(&c.context[..]);
            c.hasher = public.mu_hasher(context);
        }
        // SAFETY: the caller's guarantee.
        let Some(data) = (unsafe { bytes(data, datalen) }) else { return 0 };
        c_int::from(c.hasher.as_mut().is_some_and(|h| h.update(data)))
    }
}

ffi_callback! {
    /// `ml_dsa_sign_msg_final` (3.6): the signature of the message so far (squeezing its `mu`
    /// on), or its length when `sig` is NULL.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `sig` is NULL or has room for `sigsize` octets;
    /// `siglen` is NULL or writable.
    pub(crate) unsafe extern "C" fn ml_dsa_sign_msg_final(vctx: *mut c_void, sig: *mut c_uchar, siglen: *mut usize, sigsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.hasher.is_none() {
            return 0;
        }
        let mut rnd = None;
        let mut mu = None;
        if !sig.is_null() {
            let Some(r) = randomness(c) else { return 0 };
            rnd = Some(r);
            mu = c.hasher.as_mut().and_then(MuHasher::squeeze);
            if mu.is_none() {
                return 0;
            }
        }
        // SAFETY: the caller's guarantee.
        let r = unsafe { sign_mu(c, mu.as_ref(), rnd.as_ref(), sig, siglen, sigsize) };
        if let Some(r) = rnd.as_mut() {
            wipe(r);
        }
        if let Some(m) = mu.as_mut() {
            wipe(m);
        }
        r
    }
}

ffi_callback! {
    /// `ml_dsa_verify_msg_final` (3.6): whether the `signature` set signs the message so far.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context.
    pub(crate) unsafe extern "C" fn ml_dsa_verify_msg_final(vctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        let Some(mu) = c.hasher.as_mut().and_then(MuHasher::squeeze) else { return 0 };
        let Some(k) = c.key() else { return 0 };
        let material = k.lock();
        let Some(public) = material.public() else { return 0 };
        c_int::from(public.verify(&mu, c.sig.as_deref().unwrap_or_default()))
    }
}

/// `ossl_ml_dsa_sign` of a given `mu` (3.6's order): the length reported first, then, with
/// `mu` and randomness, the signature into room of at least that length.
///
/// # Safety
/// `sig` is NULL or has room for `sigsize` octets; `siglen` is NULL or writable.
unsafe fn sign_mu(
    c: &SigCtx,
    mu: Option<&[u8; MU_BYTES]>,
    rnd: Option<&[u8; RANDOM_BYTES]>,
    sig: *mut c_uchar,
    siglen: *mut usize,
    sigsize: usize,
) -> c_int {
    let Some(k) = c.key() else { return 0 };
    let material = k.lock();
    let Some(private) = material.private() else {
        return 0;
    };
    let sig_len = k.variant.signature_bytes();
    // SAFETY: the caller's guarantee: NULL or writable.
    match unsafe { siglen.as_mut() } {
        Some(l) => *l = sig_len,
        None if sig.is_null() => return 0,
        None => {}
    }
    if sig.is_null() {
        return 1;
    }
    if sigsize < sig_len {
        return 0;
    }
    let (Some(mu), Some(rnd)) = (mu, rnd) else {
        return 0;
    };
    match private.sign(mu, rnd) {
        Some(s) => {
            // SAFETY: the caller's room for `sigsize` (at least `sig_len`) octets.
            unsafe { ptr::copy_nonoverlapping(s.as_ptr(), sig, s.len()) };
            1
        }
        None => 0,
    }
}

ffi_callback! {
    /// `ml_dsa_digest_signverify_init`: no digest may be named; `mu` reset; without a key, only
    /// the parameters (on a context with one).
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `mdname` is NULL or a string; `vkey` is NULL or live
    /// ML-DSA key data; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ml_dsa_digest_signverify_init(vctx: *mut c_void, mdname: *const c_char, vkey: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !mdname.is_null() && unsafe { *mdname } != 0 {
            err::raise_with_text(
                ERR_LIB_PROV,
                PROV_R_INVALID_DIGEST,
                "ml_dsa_digest_signverify_init",
                "Explicit digest not supported for ML-DSA operations",
            );
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        c.mu = 0;
        if vkey.is_null() && !c.key.is_null() {
            // SAFETY: the caller's guarantee.
            return unsafe { ml_dsa_set_ctx_params(vctx, params) };
        }
        // 3.6 initializes both digest directions as a signature.
        // SAFETY: the caller's guarantee.
        unsafe { msg_init(vctx, vkey, params, EVP_PKEY_OP_SIGN) }
    }
}

/// The randomness for a signature: the caller's `test-entropy`, zeros when deterministic, else
/// fresh private randomness (`None` if drawing it fails).
fn randomness(c: &SigCtx) -> Option<[u8; RANDOM_BYTES]> {
    if let Some(e) = c.entropy {
        return Some(e);
    }
    let mut rnd = [0u8; RANDOM_BYTES];
    if c.deterministic != 1 {
        // SAFETY: the context's library context; room for the randomness.
        if unsafe { RAND_priv_bytes_ex(c.libctx, rnd.as_mut_ptr(), RANDOM_BYTES, 0) } <= 0 {
            return None;
        }
    }
    Some(rnd)
}

ffi_callback! {
    /// `ml_dsa_sign` (also `ml_dsa_digest_sign`): the signature's length when `sig` is NULL,
    /// else the signature into room of at least its length. A key without a private key fails
    /// either way.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `sig` is NULL or has room for `sigsize` octets;
    /// `siglen` is NULL or writable; `msg` holds `msg_len` octets.
    pub(crate) unsafe extern "C" fn ml_dsa_sign(vctx: *mut c_void, sig: *mut c_uchar, siglen: *mut usize, sigsize: usize, msg: *const c_uchar, msg_len: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        let mut rnd = None;
        if !sig.is_null() {
            let Some(r) = randomness(c) else { return 0 };
            rnd = Some(r);
        }
        let ret = (|| {
            let k = c.key()?;
            let material = k.lock();
            let private = material.private()?;
            let sig_len = k.variant.signature_bytes();
            // 3.6 reports the length first, even when the room is too small (and fails a
            // length query without anywhere to report it).
            // SAFETY: the caller's guarantee: NULL or writable.
            match unsafe { siglen.as_mut() } {
                Some(l) => *l = sig_len,
                None if rnd.is_none() => return None,
                None => {}
            }
            let mut ret = 1;
            if let Some(rnd) = rnd.as_ref() {
                if sigsize < sig_len {
                    return None;
                }
                // SAFETY: the caller's guarantee.
                let signature = unsafe { bytes(msg, msg_len) }
                    .and_then(|m| c.mu(private.public(), m))
                    .and_then(|mu| private.sign(&mu, rnd));
                match signature {
                    // SAFETY: the caller's room for `sigsize` (at least `sig_len`) octets.
                    Some(s) => unsafe { ptr::copy_nonoverlapping(s.as_ptr(), sig, s.len()) },
                    None => ret = 0,
                }
            }
            Some(ret)
        })();
        if let Some(r) = rnd.as_mut() {
            wipe(r);
        }
        ret.unwrap_or(0)
    }
}

ffi_callback! {
    /// `ml_dsa_verify` (also `ml_dsa_digest_verify`): whether `sig` signs `msg` (a key without
    /// a public key, or a signature of the wrong length or encoding, fails).
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `sig` holds `siglen` octets; `msg` holds `msg_len`
    /// octets.
    pub(crate) unsafe extern "C" fn ml_dsa_verify(vctx: *mut c_void, sig: *const c_uchar, siglen: usize, msg: *const c_uchar, msg_len: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        let Some(k) = c.key() else { return 0 };
        let material = k.lock();
        let Some(public) = material.public() else { return 0 };
        // SAFETY: the caller's guarantee.
        let (Some(sig), Some(msg)) = (unsafe { bytes(sig, siglen) }, unsafe { bytes(msg, msg_len) }) else {
            return 0;
        };
        let Some(mu) = c.mu(public, msg) else { return 0 };
        c_int::from(public.verify(&mu, sig))
    }
}

ffi_callback! {
    /// `ml_dsa_set_ctx_params`: the context string (at most 255 octets; a failure empties it),
    /// `test-entropy` (exactly 32 octets; a failure forgets it), `deterministic`,
    /// `message-encoding`, and `mu`, stopping at the first failure.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ml_dsa_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
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
            if let Some(e) = c.entropy.as_mut() {
                wipe(e);
            }
            c.entropy = None;
            let mut buf = [0u8; RANDOM_BYTES];
            let mut data = buf.as_mut_ptr().cast::<c_void>();
            let mut n = 0;
            // SAFETY: a parameter of the array; the buffer.
            let got = unsafe { OSSL_PARAM_get_octet_string(p, &raw mut data, RANDOM_BYTES, &raw mut n) };
            if got != 1 {
                wipe(&mut buf);
                return 0;
            }
            if n != RANDOM_BYTES {
                wipe(&mut buf);
                err::raise(ERR_LIB_PROV, PROV_R_INVALID_SEED_LENGTH, "ml_dsa_set_ctx_params");
                return 0;
            }
            c.entropy = Some(buf);
            wipe(&mut buf);
        }
        for (name, field) in [
            (OSSL_SIGNATURE_PARAM_DETERMINISTIC, &mut c.deterministic),
            (OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &mut c.msg_encode),
            (OSSL_SIGNATURE_PARAM_MU, &mut c.mu),
        ] {
            // SAFETY: the caller's array; a static name.
            if let Some(p) = unsafe { locate(params, name) }
                // SAFETY: a parameter of the array; the context's field.
                && unsafe { OSSL_PARAM_get_int(p, field) } == 0
            {
                return 0;
            }
        }
        // 3.6: the signature a message-at-a-time verification checks.
        if c.operation == EVP_PKEY_OP_VERIFYMSG
            // SAFETY: the caller's array; a static name.
            && let Some(p) = unsafe { locate(params, OSSL_SIGNATURE_PARAM_SIGNATURE) }
        {
            c.sig = None;
            let mut data: *mut c_void = ptr::null_mut();
            let mut n = 0;
            // SAFETY: a parameter of the array; a place for a new allocation.
            if unsafe { OSSL_PARAM_get_octet_string(p, &raw mut data, 0, &raw mut n) } != 1 {
                return 0;
            }
            // SAFETY: the allocation just made holds `n` octets.
            c.sig = Some(unsafe { bytes(data.cast::<u8>(), n) }.unwrap_or_default().to_vec());
            // SAFETY: allocated by the call above.
            unsafe { crate::mem::release(data) };
        }
        1
    }
}

/// `ml_dsa_verifymsg_set_ctx_params_list` (3.6): with the signature.
static VERIFYMSG_SETTABLE: Params<7> = Params([
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
    defn(OSSL_SIGNATURE_PARAM_MU, OSSL_PARAM_INTEGER, INT_SIZE),
    defn(OSSL_SIGNATURE_PARAM_SIGNATURE, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);

/// `settable_ctx_params`.
static SETTABLE: Params<6> = Params([
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
    defn(OSSL_SIGNATURE_PARAM_MU, OSSL_PARAM_INTEGER, INT_SIZE),
    PARAM_END,
]);

ffi_callback! {
    /// `ml_dsa_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn ml_dsa_settable_ctx_params(vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's context, or NULL.
        if unsafe { ctx(vctx) }.is_some_and(|c| c.operation == EVP_PKEY_OP_VERIFYMSG) {
            return VERIFYMSG_SETTABLE.0.as_ptr();
        }
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
    /// `ml_dsa_gettable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn ml_dsa_gettable_ctx_params(_vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        GETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `ml_dsa_get_ctx_params`: the algorithm identifier (failing before an init).
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ml_dsa_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
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
type UpdateFn = unsafe extern "C" fn(*mut c_void, *const c_uchar, usize) -> c_int;
type SignFinalFn = unsafe extern "C" fn(*mut c_void, *mut c_uchar, *mut usize, usize) -> c_int;
type VerifyFinalFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type DupCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type GetParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type SetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type ListFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;

/// `MAKE_SIGNATURE_FUNCTIONS(alg)`: a parameter set's new-context callback and table.
macro_rules! ml_dsa_signature {
    ($new:ident, $table:ident, $variant:expr, $doc:literal) => {
        ffi_callback! {
            /// The parameter set's `ml_dsa_newctx`.
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

        #[doc = $doc]
        pub(crate) static $table: Dispatch<20> = Dispatch([
            entry!(OSSL_FUNC_SIGNATURE_NEWCTX, $new, NewCtxFn),
            entry!(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT, ml_dsa_sign_msg_init, InitFn),
            entry!(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE, ml_dsa_signverify_msg_update, UpdateFn),
            entry!(OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL, ml_dsa_sign_msg_final, SignFinalFn),
            entry!(OSSL_FUNC_SIGNATURE_SIGN, ml_dsa_sign, SignFn),
            entry!(OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT, ml_dsa_verify_msg_init, InitFn),
            entry!(OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE, ml_dsa_signverify_msg_update, UpdateFn),
            entry!(OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL, ml_dsa_verify_msg_final, VerifyFinalFn),
            entry!(OSSL_FUNC_SIGNATURE_VERIFY, ml_dsa_verify, VerifyFn),
            entry!(OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, ml_dsa_digest_signverify_init, DigestInitFn),
            entry!(OSSL_FUNC_SIGNATURE_DIGEST_SIGN, ml_dsa_sign, SignFn),
            entry!(OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, ml_dsa_digest_signverify_init, DigestInitFn),
            entry!(OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, ml_dsa_verify, VerifyFn),
            entry!(OSSL_FUNC_SIGNATURE_FREECTX, ml_dsa_freectx, FreeCtxFn),
            entry!(OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, ml_dsa_set_ctx_params, SetParamsFn),
            entry!(OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, ml_dsa_settable_ctx_params, ListFn),
            entry!(OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, ml_dsa_get_ctx_params, GetParamsFn),
            entry!(OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, ml_dsa_gettable_ctx_params, ListFn),
            entry!(OSSL_FUNC_SIGNATURE_DUPCTX, ml_dsa_dupctx, DupCtxFn),
            END,
        ]);
    };
}

ml_dsa_signature!(
    ml_dsa_44_newctx,
    ML_DSA_44_SIGNATURE,
    Variant::MlDsa44,
    "`ossl_ml_dsa_44_signature_functions`."
);
ml_dsa_signature!(
    ml_dsa_65_newctx,
    ML_DSA_65_SIGNATURE,
    Variant::MlDsa65,
    "`ossl_ml_dsa_65_signature_functions`."
);
ml_dsa_signature!(
    ml_dsa_87_newctx,
    ML_DSA_87_SIGNATURE,
    Variant::MlDsa87,
    "`ossl_ml_dsa_87_signature_functions`."
);
