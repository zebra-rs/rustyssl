//! The default provider's AEAD ciphers: GCM and CCM of AES, ARIA, and SM4, AES-OCB, and
//! ChaCha20-Poly1305, each with the reference's dispatch table and parameter lists
//! (`IMPLEMENT_aead_cipher`, `cipher_aes_ocb.c`, `cipher_chacha20_poly1305.c`), over
//! `rustyssl_crypto::provided::aead`.
//!
//! GCM's parameter functions walk the array in its order, as the reference's do; the others
//! look each parameter up. An update without output is AAD; CCM takes the message length as an
//! update with neither input nor output. A decryption that doesn't authenticate writes zeros
//! over the output it would have written and fails.
//!
//! What the reference would crash on (OCB writing to a NULL output) fails here instead, without
//! an error (docs/DEVIATIONS.md).

use core::ffi::{CStr, c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_EVP, ERR_LIB_PROV, EVP_CIPH_CCM_MODE, EVP_CIPH_GCM_MODE, EVP_CIPH_GCM_SIV_MODE,
    EVP_CIPH_OCB_MODE, EVP_CIPH_SIV_MODE, EVP_R_INPUT_NOT_INITIALIZED,
    OSSL_CIPHER_PARAM_AEAD_IV_GENERATED, OSSL_CIPHER_PARAM_AEAD_IVLEN, OSSL_CIPHER_PARAM_AEAD_TAG,
    OSSL_CIPHER_PARAM_AEAD_TAGLEN, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD,
    OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN,
    OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV,
    OSSL_CIPHER_PARAM_IV, OSSL_CIPHER_PARAM_IVLEN, OSSL_CIPHER_PARAM_KEYLEN,
    OSSL_CIPHER_PARAM_SPEED, OSSL_CIPHER_PARAM_UPDATED_IV, OSSL_FUNC_CIPHER_CIPHER,
    OSSL_FUNC_CIPHER_DECRYPT_INIT, OSSL_FUNC_CIPHER_DUPCTX, OSSL_FUNC_CIPHER_ENCRYPT_INIT,
    OSSL_FUNC_CIPHER_FINAL, OSSL_FUNC_CIPHER_FREECTX, OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
    OSSL_FUNC_CIPHER_GET_PARAMS, OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
    OSSL_FUNC_CIPHER_GETTABLE_PARAMS, OSSL_FUNC_CIPHER_NEWCTX, OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
    OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, OSSL_FUNC_CIPHER_UPDATE, OSSL_PARAM,
    OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UNSIGNED_INTEGER, PROV_R_FAILED_TO_GET_PARAMETER,
    PROV_R_FAILED_TO_SET_PARAMETER, PROV_R_INVALID_AAD, PROV_R_INVALID_DATA,
    PROV_R_INVALID_IV_LENGTH, PROV_R_INVALID_KEY_LENGTH, PROV_R_INVALID_TAG, PROV_R_TAG_NOT_SET,
};
use rustyssl_crypto::provided::aead::{Ccm, ChaChaPoly, Gcm, Io, Ocb, Raised};
use rustyssl_crypto::provided::cipher::{Error, Output};
use rustyssl_crypto::provided::siv::{GCM_SIV_NONCE, GcmSiv, Siv};
use rustyssl_crypto::sym::BlockAlgorithm;

use super::ciphers::{
    CtxParamsFn, DupFn, FinalFn, FreeFn, GENERIC_GETTABLE, GetCtxFn, GetParamsFn, GettableFn, Info,
    InitFn, NewCtxFn, SIZE_T, SetCtxFn, UINT, UpdateFn, Value, get_param, get_params_of, get_size,
    get_uint, is_empty, raise, set_param, write,
};
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::err;
use crate::ffi::ffi_callback;
use crate::params::{OSSL_PARAM_get_octet_string, OSSL_PARAM_locate, OSSL_PARAM_set_octet_string};

/// An AEAD algorithm context.
#[derive(Clone)]
pub(crate) enum Aead {
    Gcm(Box<Gcm>),
    Ccm(Box<Ccm>),
    Ocb(Box<Ocb>),
    ChaChaPoly(Box<ChaChaPoly>),
    Siv(Box<Siv>),
    GcmSiv(Box<GcmSiv>),
}

/// The context behind `vctx`, or `None` for NULL.
///
/// # Safety
/// `vctx` is NULL or a context `newctx` made and `freectx` hasn't freed.
unsafe fn context<'a>(vctx: *mut c_void) -> Option<&'a mut Aead> {
    // SAFETY: the caller's guarantee: a box from `newctx`, used by one caller at a time.
    unsafe { vctx.cast::<Aead>().as_mut() }
}

fn new_context(a: Aead) -> *mut c_void {
    Box::into_raw(Box::new(a)).cast()
}

/// `newctx`: GCM drawing its random IVs from the provider's context's generators.
///
/// # Safety
/// `provctx` is the provider's context.
unsafe fn new_provided(mut a: Aead, provctx: *mut c_void) -> *mut c_void {
    if let Aead::Gcm(g) = &mut a {
        // SAFETY: the caller's guarantee.
        let libctx = unsafe { super::builtin::libctx_of(provctx) };
        g.set_random(crate::rand_lib::random_source(libctx, false));
    }
    new_context(a)
}

/// Raises what a provider function raised.
#[track_caller]
fn raise_all(r: Raised, function: &str) {
    raise(r.first, function);
    if let Some(e) = r.then {
        raise(e, function);
    }
}

/// `len` octets at `p`, `None` for NULL; refuses (with `None` and `false`) lengths past
/// `max`, where the reference would read past what it was given.
///
/// # Safety
/// `p` is NULL or holds `len` octets.
unsafe fn arg<'a>(p: *const u8, len: usize) -> Option<&'a [u8]> {
    if p.is_null() {
        return None;
    }
    if len == 0 {
        return Some(&[]);
    }
    // SAFETY: the caller's guarantee.
    Some(unsafe { core::slice::from_raw_parts(p, len) })
}

ffi_callback! {
    /// `freectx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context from `newctx`, not used afterwards.
    pub(crate) unsafe extern "C" fn freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        if !vctx.is_null() {
            // SAFETY: the caller's guarantee: a box from `newctx`.
            drop(unsafe { Box::from_raw(vctx.cast::<Aead>()) });
        }
    }
}

ffi_callback! {
    /// `dupctx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a live algorithm context.
    pub(crate) unsafe extern "C" fn dupctx(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(vctx) }) else { return ptr::null_mut() };
        if let Aead::Siv(g) = c
            && !g.keyed()
        {
            // `ossl_siv128_copy_ctx` copies the CTR context, which has none to copy.
            err::raise(ERR_LIB_EVP, EVP_R_INPUT_NOT_INITIALIZED, "EVP_CIPHER_CTX_copy");
            return ptr::null_mut();
        }
        new_context(c.clone())
    }
}

/// The largest key and IV the inits read (`EVP_MAX_KEY_LENGTH`; GCM's longest IV).
const MAX_KEY: usize = 64;
const MAX_IV: usize = 128;

/// `einit`/`dinit` for all four: the key and IV, then the family's parameters.
///
/// # Safety
/// `vctx` is a live algorithm context; `key` and `iv` are NULL or hold `keylen` and `ivlen`
/// octets; `params` is NULL or a parameter array.
unsafe fn init(
    vctx: *mut c_void,
    (key, keylen): (*const u8, usize),
    (iv, ivlen): (*const u8, usize),
    params: *const OSSL_PARAM,
    enc: bool,
) -> c_int {
    const F: &str = "aead_init";
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { context(vctx) }) else {
        return 0;
    };
    // A length past any the ciphers take would only be read to be refused.
    let key = if !key.is_null() && keylen > MAX_KEY {
        Some(&[][..])
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { arg(key, keylen) }
    };
    if !iv.is_null() && ivlen > MAX_IV {
        raise(Error::InvalidIvLength, F);
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let iv = unsafe { arg(iv, ivlen) };
    let r = match c {
        Aead::Gcm(g) => g.init(enc, key, iv),
        Aead::Ccm(g) => g.init(enc, key, iv),
        Aead::Ocb(g) => g.init(enc, key, iv),
        Aead::ChaChaPoly(g) => g.init(enc, key, iv),
        // SIV takes no IV.
        Aead::Siv(g) => g.init(enc, key),
        Aead::GcmSiv(g) => g.init(enc, key, iv),
    };
    if let Err(e) = r {
        raise(e, F);
        return 0;
    }
    // SAFETY: the caller's guarantee.
    unsafe { set_ctx_params(vctx, params) }
}

ffi_callback! {
    /// `einit`.
    ///
    /// # Safety
    /// As for `init`.
    pub(crate) unsafe extern "C" fn einit(vctx: *mut c_void, key: *const u8, keylen: usize, iv: *const u8, ivlen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { init(vctx, (key, keylen), (iv, ivlen), params, true) }
    }
}

ffi_callback! {
    /// `dinit`.
    ///
    /// # Safety
    /// As for `init`.
    pub(crate) unsafe extern "C" fn dinit(vctx: *mut c_void, key: *const u8, keylen: usize, iv: *const u8, ivlen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { init(vctx, (key, keylen), (iv, ivlen), params, false) }
    }
}

/// Which provider function runs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Update,
    Cipher,
}

/// Writes a function's output and length, raising what it raised.
///
/// # Safety
/// `out` is NULL or has room for the output; `outl` is NULL or valid for a write.
unsafe fn finish(result: Result<Output, Raised>, out: *mut u8, outl: *mut usize, f: &str) -> c_int {
    let o = match result {
        Ok(o) => o,
        Err(r) => {
            raise_all(r, f);
            return 0;
        }
    };
    // SAFETY: the caller's guarantee.
    if !unsafe { write(out, &o) } {
        return 0;
    }
    if let Some(e) = o.failed {
        raise(e, f);
        return 0;
    }
    if outl.is_null() {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    unsafe { outl.write(o.len) };
    1
}

/// `update` and `cipher`.
///
/// # Safety
/// `vctx` is a live algorithm context; `in_` is NULL or holds `inl` octets; `out` is NULL or
/// has room for `outsize`; `outl` is valid for a write.
unsafe fn process(
    vctx: *mut c_void,
    out: *mut u8,
    outl: *mut usize,
    outsize: usize,
    (in_, inl): (*const u8, usize),
    op: Op,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { context(vctx) }) else {
        return 0;
    };
    let io = Io {
        // SAFETY: the caller's guarantee.
        input: unsafe { arg(in_, inl) },
        inl,
        out: !out.is_null(),
        in_place: out.cast_const() == in_,
        outsize,
    };
    let (r, f) = match (c, op) {
        (Aead::Gcm(g), Op::Update) => (g.update(io), "ossl_gcm_stream_update"),
        (Aead::Gcm(g), Op::Cipher) => (g.cipher(io).map_err(Raised::from), "ossl_gcm_cipher"),
        (Aead::Ccm(g), Op::Update) => (g.update(io), "ossl_ccm_stream_update"),
        (Aead::Ccm(g), Op::Cipher) => (g.cipher(io).map_err(Raised::from), "ossl_ccm_cipher"),
        (Aead::Ocb(g), Op::Update) => (g.update(io), "aes_ocb_block_update"),
        (Aead::Ocb(g), Op::Cipher) => (g.cipher(io), "aes_ocb_cipher"),
        (Aead::ChaChaPoly(g), Op::Update) => (
            g.update(io).map_err(Raised::from),
            "chacha20_poly1305_update",
        ),
        (Aead::ChaChaPoly(g), Op::Cipher) => (
            g.cipher(io).map_err(Raised::from),
            "chacha20_poly1305_cipher",
        ),
        // `update` is `cipher` for both.
        (Aead::Siv(g), _) => (
            g.cipher(io.input, io.inl, io.out, io.outsize)
                .map_err(Raised::from),
            "siv_cipher",
        ),
        (Aead::GcmSiv(g), _) => (
            g.cipher(io.input, io.inl, io.out, io.outsize)
                .map_err(Raised::from),
            "ossl_aes_gcm_siv_cipher",
        ),
    };
    // SAFETY: the caller's guarantee.
    unsafe { finish(r, out, outl, f) }
}

ffi_callback! {
    /// `update`: data (with output) or AAD (without).
    ///
    /// # Safety
    /// As for `process`.
    pub(crate) unsafe extern "C" fn update(vctx: *mut c_void, out: *mut u8, outl: *mut usize, outsize: usize, in_: *const u8, inl: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { process(vctx, out, outl, outsize, (in_, inl), Op::Update) }
    }
}

ffi_callback! {
    /// `cipher` (`EVP_Cipher`).
    ///
    /// # Safety
    /// As for `process`.
    pub(crate) unsafe extern "C" fn cipher(vctx: *mut c_void, out: *mut u8, outl: *mut usize, outsize: usize, in_: *const u8, inl: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { process(vctx, out, outl, outsize, (in_, inl), Op::Cipher) }
    }
}

ffi_callback! {
    /// `final`: the tag, made or checked (OCB's partial blocks too).
    ///
    /// # Safety
    /// `vctx` is a live algorithm context; `out` has room for a block; `outl` is valid for a
    /// write.
    pub(crate) unsafe extern "C" fn final_(vctx: *mut c_void, out: *mut u8, outl: *mut usize, _outsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(vctx) }) else { return 0 };
        let r = match c {
            Aead::Gcm(g) => g.finalize(),
            Aead::Ccm(g) => g.finalize(),
            Aead::Ocb(g) => g.finalize(),
            Aead::ChaChaPoly(g) => g.finalize(),
            Aead::Siv(g) => g.finalize(),
            Aead::GcmSiv(g) => g.finalize(),
        };
        // SAFETY: the caller's guarantee.
        unsafe { finish(r.map_err(Raised::from), out, outl, "aead_final") }
    }
}

/// The parameter's key.
fn key_of(p: &OSSL_PARAM) -> &CStr {
    // SAFETY: a parameter's key is a string.
    unsafe { CStr::from_ptr(p.key) }
}

/// The parameter's data as octets (`data_size` of them), `None` for NULL data.
///
/// # Safety
/// The parameter's data holds `data_size` octets.
unsafe fn data_of<'a>(p: &OSSL_PARAM) -> Option<&'a [u8]> {
    // SAFETY: the caller's guarantee.
    unsafe { arg(p.data.cast(), p.data_size) }
}

/// The parameter's data as room for `n` octets to write, `None` for NULL data.
///
/// # Safety
/// The parameter's data has room for `n` octets.
unsafe fn room_of<'a>(p: &OSSL_PARAM, n: usize) -> Option<&'a mut [u8]> {
    if p.data.is_null() {
        return None;
    }
    // SAFETY: the caller's guarantee.
    Some(unsafe { core::slice::from_raw_parts_mut(p.data.cast::<u8>(), n) })
}

fn is_octets(p: &OSSL_PARAM) -> bool {
    p.data_type == OSSL_PARAM_OCTET_STRING.cast_unsigned()
}

/// Sets an IV parameter: as an octet string, or else a pointer to the context's.
///
/// # Safety
/// `p` is a parameter; `iv` is the context's IV buffer (stable while the context lives).
unsafe fn set_iv_param(p: *mut OSSL_PARAM, iv: &mut [u8], f: &str) -> bool {
    // SAFETY: the caller's guarantee: a parameter.
    let key = key_of(unsafe { &*p });
    let v = Value::IvCopyFirst(iv.as_mut_ptr().cast_const(), iv.len());
    // SAFETY: the caller's guarantee; the parameter is found by its own key.
    unsafe { set_param(p, key, f, v) }
}

ffi_callback! {
    /// `get_ctx_params` for the four families.
    ///
    /// # Safety
    /// `vctx` is NULL or a live algorithm context; `params` is NULL or a parameter array whose
    /// octet data has the room its size says.
    pub(crate) unsafe extern "C" fn get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(vctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        match c {
            // SAFETY: the caller's guarantee.
            Aead::Gcm(g) => unsafe { gcm_get(g, params) },
            // SAFETY: the caller's guarantee.
            Aead::Ccm(g) => unsafe { ccm_get(g, params) },
            // SAFETY: the caller's guarantee.
            Aead::Ocb(g) => unsafe { ocb_get(g, params) },
            // SAFETY: the caller's guarantee.
            Aead::ChaChaPoly(g) => unsafe { chacha_poly_get(g, params) },
            // SAFETY: the caller's guarantee.
            Aead::Siv(g) => unsafe { siv_get(SivCtx::Siv(g), params) },
            // SAFETY: the caller's guarantee.
            Aead::GcmSiv(g) => unsafe { siv_get(SivCtx::GcmSiv(g), params) },
        }
    }
}

ffi_callback! {
    /// `set_ctx_params` for the four families.
    ///
    /// # Safety
    /// `vctx` is NULL or a live algorithm context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(vctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        match c {
            // SAFETY: the caller's guarantee.
            Aead::Gcm(g) => unsafe { gcm_set(g, params) },
            // SAFETY: the caller's guarantee.
            Aead::Ccm(g) => unsafe { ccm_set(g, params) },
            // SAFETY: the caller's guarantee.
            Aead::Ocb(g) => unsafe { ocb_set(g, params) },
            // SAFETY: the caller's guarantee.
            Aead::ChaChaPoly(g) => unsafe { chacha_poly_set(g, params) },
            // SAFETY: the caller's guarantee.
            Aead::Siv(g) => unsafe { siv_set(g, params) },
            // SAFETY: the caller's guarantee.
            Aead::GcmSiv(g) => unsafe { gcm_siv_set(g, params) },
        }
    }
}

/// The parameters of an array, in order.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn each<'a>(params: *mut OSSL_PARAM) -> impl Iterator<Item = *mut OSSL_PARAM> + 'a {
    let mut at = params;
    core::iter::from_fn(move || {
        // SAFETY: the caller's guarantee: the array is ended by a NULL key.
        let p = unsafe { at.as_ref() }?;
        if p.key.is_null() {
            return None;
        }
        let here = at;
        at = at.wrapping_add(1);
        Some(here)
    })
}

/// `ossl_gcm_get_ctx_params`, in the array's order.
///
/// # Safety
/// As for `get_ctx_params`.
unsafe fn gcm_get(g: &mut Gcm, params: *mut OSSL_PARAM) -> c_int {
    const F: &str = "ossl_gcm_get_ctx_params";
    // SAFETY: the caller's guarantee.
    for p in unsafe { each(params) } {
        // SAFETY: a parameter of the array.
        let q = unsafe { &*p };
        let key = key_of(q);
        let ok = if key == OSSL_CIPHER_PARAM_IVLEN {
            // SAFETY: as above.
            unsafe { set_param(p, key, F, Value::Size(g.iv_len())) }
        } else if key == OSSL_CIPHER_PARAM_KEYLEN {
            // SAFETY: as above.
            unsafe { set_param(p, key, F, Value::Size(g.key_len())) }
        } else if key == OSSL_CIPHER_PARAM_AEAD_TAGLEN {
            // SAFETY: as above.
            unsafe { set_param(p, key, F, Value::Size(g.tag_len())) }
        } else if key == OSSL_CIPHER_PARAM_IV || key == OSSL_CIPHER_PARAM_UPDATED_IV {
            let size = q.data_size;
            let Some(iv) = g.iv_buffer() else { return 0 };
            if iv.len() > size {
                err::raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH, F);
                return 0;
            }
            // SAFETY: as above; the context's IV.
            unsafe { set_iv_param(p, iv, F) }
        } else if key == OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD {
            // SAFETY: as above.
            unsafe { set_param(p, key, F, Value::Size(g.tls_aad_pad())) }
        } else if key == OSSL_CIPHER_PARAM_AEAD_TAG {
            let tag = match g.tag(q.data_size) {
                Ok(t) => t.to_vec(),
                Err(_) => {
                    err::raise(ERR_LIB_PROV, PROV_R_INVALID_TAG, F);
                    return 0;
                }
            };
            // SAFETY: a parameter of the array, and the tag.
            if unsafe { OSSL_PARAM_set_octet_string(p, tag.as_ptr().cast(), tag.len()) } == 0 {
                err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER, F);
                return 0;
            }
            true
        } else if key == OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN {
            if q.data.is_null() || !is_octets(q) {
                return 0;
            }
            let Ok(iv) = g.iv_gen(q.data_size) else {
                return 0;
            };
            // SAFETY: the caller's guarantee: room for the IV's octets asked for (or, for
            // none, all of it, as the reference writes).
            let Some(d) = (unsafe { room_of(q, iv.len()) }) else {
                return 0;
            };
            d.copy_from_slice(&iv);
            true
        } else if key == OSSL_CIPHER_PARAM_AEAD_IV_GENERATED {
            // A failure here raises only the parameter library's error.
            let v = core::ffi::c_uint::from(g.iv_generated());
            // SAFETY: a parameter of the array.
            unsafe { crate::params::OSSL_PARAM_set_uint(p, v) != 0 }
        } else {
            true
        };
        if !ok {
            return 0;
        }
    }
    1
}

/// `ossl_gcm_set_ctx_params`, in the array's order.
///
/// # Safety
/// As for `set_ctx_params`.
unsafe fn gcm_set(g: &mut Gcm, params: *const OSSL_PARAM) -> c_int {
    const F: &str = "ossl_gcm_set_ctx_params";
    // SAFETY: the caller's guarantee.
    for p in unsafe { each(params.cast_mut()) } {
        // SAFETY: a parameter of the array.
        let q = unsafe { &*p };
        let key = key_of(q);
        if key == OSSL_CIPHER_PARAM_AEAD_TAG {
            let mut buf = [0u8; 16];
            let mut vp: *mut c_void = buf.as_mut_ptr().cast();
            let mut sz = 0usize;
            // SAFETY: a parameter, a local buffer of 16 octets, and a local length.
            if unsafe { OSSL_PARAM_get_octet_string(p, &raw mut vp, 16, &raw mut sz) } == 0 {
                err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, F);
                return 0;
            }
            if g.set_tag(buf.get(..sz).unwrap_or_default()).is_err() {
                err::raise(ERR_LIB_PROV, PROV_R_INVALID_TAG, F);
                return 0;
            }
        } else if key == OSSL_CIPHER_PARAM_AEAD_IVLEN {
            let mut sz = 0usize;
            if get_size(p, &raw mut sz) == 0 {
                err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, F);
                return 0;
            }
            if g.set_iv_len(sz).is_err() {
                err::raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH, F);
                return 0;
            }
        } else if key == OSSL_CIPHER_PARAM_AEAD_TLS1_AAD {
            if !is_octets(q) {
                err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, F);
                return 0;
            }
            // SAFETY: an octet string parameter's data holds its size.
            let aad = unsafe { data_of(q) }.unwrap_or_default();
            if g.tls_init(aad).is_none() {
                err::raise(ERR_LIB_PROV, PROV_R_INVALID_AAD, F);
                return 0;
            }
        } else if key == OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED {
            if !is_octets(q) {
                err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, F);
                return 0;
            }
            // A length of (size_t)-1 restores the whole IV from the data.
            let whole = q.data_size == usize::MAX;
            let n = if whole { g.iv_len() } else { q.data_size };
            // SAFETY: an octet string parameter's data holds its size (the IV, for the whole).
            let fixed = unsafe { arg(q.data.cast(), n) }.unwrap_or_default();
            if g.tls_iv_fixed(fixed, whole).is_err() {
                err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, F);
                return 0;
            }
        } else if key == OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV {
            if q.data.is_null() || !is_octets(q) {
                return 0;
            }
            // SAFETY: as above.
            let inv = unsafe { data_of(q) }.unwrap_or_default();
            if g.set_iv_inv(inv).is_err() {
                return 0;
            }
        }
    }
    1
}

/// Looks a parameter up.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn find<'a>(
    params: *mut OSSL_PARAM,
    key: &CStr,
) -> Option<(*mut OSSL_PARAM, &'a OSSL_PARAM)> {
    // SAFETY: the caller's guarantee.
    let p = unsafe { OSSL_PARAM_locate(params, key.as_ptr()) };
    // SAFETY: a parameter of the array, or NULL.
    unsafe { p.as_ref() }.map(|q| (p, q))
}

/// `ossl_ccm_get_ctx_params`.
///
/// # Safety
/// As for `get_ctx_params`.
unsafe fn ccm_get(g: &mut Ccm, params: *mut OSSL_PARAM) -> c_int {
    const F: &str = "ossl_ccm_get_ctx_params";
    for (key, v) in [
        (OSSL_CIPHER_PARAM_IVLEN, g.iv_len()),
        (OSSL_CIPHER_PARAM_AEAD_TAGLEN, g.tag_len()),
    ] {
        // SAFETY: the caller's array.
        if !unsafe { set_param(params, key, F, Value::Size(v)) } {
            return 0;
        }
    }
    for key in [OSSL_CIPHER_PARAM_IV, OSSL_CIPHER_PARAM_UPDATED_IV] {
        // SAFETY: the caller's array.
        let Some((p, q)) = (unsafe { find(params, key) }) else {
            continue;
        };
        let size = q.data_size;
        if g.iv_len() > size {
            err::raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH, F);
            return 0;
        }
        // The reference copies `data_size` octets from its 16-octet buffer, past it for more,
        // and reports a pointer to it with that size; here the rest are zeros and the pointer's
        // size is the buffer's (docs/DEVIATIONS.md).
        let iv = g.iv_buffer();
        let ok = if is_octets(q) {
            let mut copy = vec![0u8; size];
            for (d, s) in copy.iter_mut().zip(iv.iter()) {
                *d = *s;
            }
            // SAFETY: a parameter of the array and a local copy.
            unsafe { OSSL_PARAM_set_octet_string(p, copy.as_ptr().cast(), size) != 0 }
        } else {
            let ptr = iv.as_mut_ptr().cast_const();
            // SAFETY: a parameter of the array; the context's buffer, which lives as long as
            // it, and no more of it than it holds.
            unsafe {
                crate::params::OSSL_PARAM_set_octet_ptr(p, ptr.cast(), size.min(iv.len())) != 0
            }
        };
        if !ok {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER, F);
            return 0;
        }
    }
    for (key, v) in [
        (OSSL_CIPHER_PARAM_KEYLEN, g.key_len()),
        (OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, g.tls_aad_pad()),
    ] {
        // SAFETY: the caller's array.
        if !unsafe { set_param(params, key, F, Value::Size(v)) } {
            return 0;
        }
    }
    // SAFETY: the caller's array.
    if let Some((_, q)) = unsafe { find(params, OSSL_CIPHER_PARAM_AEAD_TAG) } {
        if !g.tag_ready() {
            err::raise(ERR_LIB_PROV, PROV_R_TAG_NOT_SET, F);
            return 0;
        }
        if !is_octets(q) {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER, F);
            return 0;
        }
        let Ok(t) = g.tag(q.data_size) else { return 0 };
        // SAFETY: the caller's guarantee: room for its size, the tag's length.
        let Some(d) = (unsafe { room_of(q, t.len()) }) else {
            return 0;
        };
        d.copy_from_slice(&t);
    }
    1
}

/// `ossl_ccm_set_ctx_params`.
///
/// # Safety
/// As for `set_ctx_params`.
unsafe fn ccm_set(g: &mut Ccm, params: *const OSSL_PARAM) -> c_int {
    const F: &str = "ossl_ccm_set_ctx_params";
    let params = params.cast_mut();
    // SAFETY: the caller's array.
    if let Some((_, q)) = unsafe { find(params, OSSL_CIPHER_PARAM_AEAD_TAG) } {
        if !is_octets(q) {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, F);
            return 0;
        }
        // SAFETY: an octet string parameter's data holds its size (checked to 16 first).
        let tag = if q.data_size <= 16 {
            // SAFETY: as above.
            unsafe { data_of(q) }
        } else {
            None
        };
        if let Err(e) = g.set_tag(tag, q.data_size) {
            raise(e, F);
            return 0;
        }
    }
    // SAFETY: the caller's array.
    if let Some((p, _)) = unsafe { find(params, OSSL_CIPHER_PARAM_AEAD_IVLEN) } {
        let mut sz = 0usize;
        if get_size(p, &raw mut sz) == 0 {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, F);
            return 0;
        }
        if g.set_iv_len(sz).is_err() {
            err::raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH, F);
            return 0;
        }
    }
    // SAFETY: the caller's array.
    if let Some((_, q)) = unsafe { find(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD) } {
        if !is_octets(q) {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, F);
            return 0;
        }
        // SAFETY: as above.
        let aad = unsafe { data_of(q) }.unwrap_or_default();
        if g.tls_init(aad).is_none() {
            err::raise(ERR_LIB_PROV, PROV_R_INVALID_DATA, F);
            return 0;
        }
    }
    // SAFETY: the caller's array.
    if let Some((_, q)) = unsafe { find(params, OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED) } {
        if !is_octets(q) {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, F);
            return 0;
        }
        // SAFETY: as above.
        let fixed = unsafe { data_of(q) }.unwrap_or_default();
        if g.tls_iv_fixed(fixed).is_err() {
            err::raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH, F);
            return 0;
        }
    }
    1
}

/// `aes_ocb_get_ctx_params`.
///
/// # Safety
/// As for `get_ctx_params`.
unsafe fn ocb_get(g: &mut Ocb, params: *mut OSSL_PARAM) -> c_int {
    const F: &str = "aes_ocb_get_ctx_params";
    for (key, v) in [
        (OSSL_CIPHER_PARAM_IVLEN, g.iv_len()),
        (OSSL_CIPHER_PARAM_KEYLEN, g.key_len()),
        (OSSL_CIPHER_PARAM_AEAD_TAGLEN, g.tag_len()),
    ] {
        // SAFETY: the caller's array.
        if !unsafe { set_param(params, key, F, Value::Size(v)) } {
            return 0;
        }
    }
    let ivlen = g.iv_len();
    for (key, original) in [
        (OSSL_CIPHER_PARAM_IV, true),
        (OSSL_CIPHER_PARAM_UPDATED_IV, false),
    ] {
        // SAFETY: the caller's array.
        let Some((p, q)) = (unsafe { find(params, key) }) else {
            continue;
        };
        if ivlen > q.data_size {
            err::raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH, F);
            return 0;
        }
        let (oiv, iv) = g.ivs();
        let buf = if original { oiv } else { iv };
        let Some(b) = buf.get_mut(..ivlen) else {
            return 0;
        };
        // SAFETY: the parameter; the context's IV.
        if !unsafe { set_iv_param(p, b, F) } {
            return 0;
        }
    }
    // SAFETY: the caller's array.
    if let Some((_, q)) = unsafe { find(params, OSSL_CIPHER_PARAM_AEAD_TAG) } {
        if !is_octets(q) {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, F);
            return 0;
        }
        let t = match g.tag(q.data_size) {
            Ok(t) => t.to_vec(),
            Err(e) => {
                raise(e, F);
                return 0;
            }
        };
        // SAFETY: the caller's guarantee: room for its size, the tag's length.
        let Some(d) = (unsafe { room_of(q, t.len()) }) else {
            return 0;
        };
        d.copy_from_slice(&t);
    }
    1
}

/// `aes_ocb_set_ctx_params`.
///
/// # Safety
/// As for `set_ctx_params`.
unsafe fn ocb_set(g: &mut Ocb, params: *const OSSL_PARAM) -> c_int {
    const F: &str = "aes_ocb_set_ctx_params";
    let params = params.cast_mut();
    // SAFETY: the caller's array.
    if let Some((_, q)) = unsafe { find(params, OSSL_CIPHER_PARAM_AEAD_TAG) } {
        if !is_octets(q) {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, F);
            return 0;
        }
        // SAFETY: an octet string parameter's data holds its size (read only at the length the
        // context's tag has, at most 16).
        let tag = if q.data_size <= 16 {
            // SAFETY: as above.
            unsafe { data_of(q) }
        } else if q.data.is_null() {
            None
        } else {
            Some(&[0u8; 17][..])
        };
        if let Err(e) = g.set_tag(tag, q.data_size) {
            raise(e, F);
            return 0;
        }
    }
    // SAFETY: the caller's array.
    if let Some((p, _)) = unsafe { find(params, OSSL_CIPHER_PARAM_AEAD_IVLEN) } {
        let mut sz = 0usize;
        if get_size(p, &raw mut sz) == 0 {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, F);
            return 0;
        }
        if g.set_iv_len(sz).is_err() {
            return 0;
        }
    }
    // SAFETY: the caller's array.
    match unsafe { get_param(params, OSSL_CIPHER_PARAM_KEYLEN, F, get_size) } {
        Err(()) => return 0,
        Ok(Some(n)) if n != g.key_len() => {
            err::raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH, F);
            return 0;
        }
        Ok(_) => {}
    }
    1
}

/// `chacha20_poly1305_get_ctx_params`.
///
/// # Safety
/// As for `get_ctx_params`.
unsafe fn chacha_poly_get(g: &mut ChaChaPoly, params: *mut OSSL_PARAM) -> c_int {
    const F: &str = "chacha20_poly1305_get_ctx_params";
    for (key, v) in [
        (OSSL_CIPHER_PARAM_IVLEN, 12),
        (OSSL_CIPHER_PARAM_KEYLEN, 32),
        (OSSL_CIPHER_PARAM_AEAD_TAGLEN, g.tag_len()),
        (OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, g.tls_aad_pad()),
    ] {
        // SAFETY: the caller's array.
        if !unsafe { set_param(params, key, F, Value::Size(v)) } {
            return 0;
        }
    }
    // SAFETY: the caller's array.
    if let Some((_, q)) = unsafe { find(params, OSSL_CIPHER_PARAM_AEAD_TAG) } {
        if !is_octets(q) {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER, F);
            return 0;
        }
        let t = match g.tag(q.data_size) {
            Ok(t) => t.to_vec(),
            Err(e) => {
                raise(e, F);
                return 0;
            }
        };
        // SAFETY: the caller's guarantee: room for its size.
        let Some(d) = (unsafe { room_of(q, t.len()) }) else {
            return 0;
        };
        d.copy_from_slice(&t);
    }
    1
}

/// `chacha20_poly1305_set_ctx_params`.
///
/// # Safety
/// As for `set_ctx_params`.
unsafe fn chacha_poly_set(g: &mut ChaChaPoly, params: *const OSSL_PARAM) -> c_int {
    const F: &str = "chacha20_poly1305_set_ctx_params";
    for (key, want, reason) in [
        (OSSL_CIPHER_PARAM_KEYLEN, 32, PROV_R_INVALID_KEY_LENGTH),
        (OSSL_CIPHER_PARAM_IVLEN, 12, PROV_R_INVALID_IV_LENGTH),
    ] {
        // SAFETY: the caller's array.
        match unsafe { get_param(params, key, F, get_size) } {
            Err(()) => return 0,
            Ok(Some(n)) if n != want => {
                err::raise(ERR_LIB_PROV, reason, F);
                return 0;
            }
            Ok(_) => {}
        }
    }
    let params = params.cast_mut();
    // SAFETY: the caller's array.
    if let Some((_, q)) = unsafe { find(params, OSSL_CIPHER_PARAM_AEAD_TAG) } {
        if !is_octets(q) {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, F);
            return 0;
        }
        // SAFETY: an octet string parameter's data holds its size (checked to 16 first).
        let tag = if q.data_size <= 16 {
            // SAFETY: as above.
            unsafe { data_of(q) }
        } else {
            None
        };
        if let Err(e) = g.set_tag(tag, q.data_size) {
            raise(e, F);
            return 0;
        }
    }
    // SAFETY: the caller's array.
    if let Some((_, q)) = unsafe { find(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD) } {
        if !is_octets(q) {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, F);
            return 0;
        }
        // SAFETY: as above.
        let aad = unsafe { data_of(q) }.unwrap_or_default();
        if g.tls_init(aad).is_none() {
            err::raise(ERR_LIB_PROV, PROV_R_INVALID_DATA, F);
            return 0;
        }
    }
    // SAFETY: the caller's array.
    if let Some((_, q)) = unsafe { find(params, OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED) } {
        if !is_octets(q) {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, F);
            return 0;
        }
        // SAFETY: as above.
        let fixed = unsafe { data_of(q) }.unwrap_or_default();
        if g.tls_iv_fixed(fixed).is_err() {
            err::raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH, F);
            return 0;
        }
    }
    1
}

/// SIV's or GCM-SIV's context, for their common `get_ctx_params`.
enum SivCtx<'a> {
    Siv(&'a mut Siv),
    GcmSiv(&'a mut GcmSiv),
}

/// `aes_siv_get_ctx_params` and `ossl_aes_gcm_siv_get_ctx_params`: the tag (an octet string
/// of exactly 16 octets, encrypting, after a message for GCM-SIV), its length, and the key's.
///
/// # Safety
/// As for `get_ctx_params`.
unsafe fn siv_get(c: SivCtx<'_>, params: *mut OSSL_PARAM) -> c_int {
    let (f, keylen) = match &c {
        SivCtx::Siv(g) => ("aes_siv_get_ctx_params", g.key_len()),
        SivCtx::GcmSiv(g) => ("ossl_aes_gcm_siv_get_ctx_params", g.key_len()),
    };
    // SAFETY: the caller's array.
    let tag_param = unsafe { find(params, OSSL_CIPHER_PARAM_AEAD_TAG) };
    if let Some((p, q)) = tag_param.filter(|(_, q)| is_octets(q)) {
        let tag = match &c {
            SivCtx::Siv(g) => g.tag(q.data_size),
            SivCtx::GcmSiv(g) => g.tag(q.data_size),
        };
        let ok = tag.is_ok_and(|t| {
            // SAFETY: a parameter of the array; the tag's 16 octets.
            (unsafe { OSSL_PARAM_set_octet_string(p, t.as_ptr().cast(), t.len()) }) != 0
        });
        if !ok {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER, f);
            return 0;
        }
    }
    for (key, v) in [
        (OSSL_CIPHER_PARAM_AEAD_TAGLEN, 16),
        (OSSL_CIPHER_PARAM_KEYLEN, keylen),
    ] {
        // SAFETY: the caller's array.
        if !unsafe { set_param(params, key, f, Value::Size(v)) } {
            return 0;
        }
    }
    1
}

/// The `speed` parameter, if any.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn speed_of(params: *const OSSL_PARAM, f: &str) -> Result<Option<u32>, ()> {
    // SAFETY: the caller's guarantee.
    unsafe { get_param(params, OSSL_CIPHER_PARAM_SPEED, f, get_uint) }
}

/// `aes_siv_set_ctx_params`: the tag (ignored encrypting), `speed`, and `keylen` (only as it
/// is); `final` then fails until the next message.
///
/// # Safety
/// As for `set_ctx_params`.
unsafe fn siv_set(g: &mut Siv, params: *const OSSL_PARAM) -> c_int {
    const F: &str = "aes_siv_set_ctx_params";
    // SAFETY: the caller's array.
    if let Some((_, q)) = unsafe { find(params.cast_mut(), OSSL_CIPHER_PARAM_AEAD_TAG) } {
        if g.encrypting() {
            return 1;
        }
        let tag = if is_octets(q) {
            // SAFETY: the caller's guarantee.
            unsafe { data_of(q) }
        } else {
            None
        };
        if !tag.is_some_and(|t| g.set_tag(t).is_ok()) {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, F);
            return 0;
        }
    }
    // SAFETY: the caller's array.
    match unsafe { speed_of(params, F) } {
        Err(()) => return 0,
        Ok(Some(v)) => g.set_speed(v),
        Ok(None) => {}
    }
    // SAFETY: the caller's array.
    match unsafe { get_param(params, OSSL_CIPHER_PARAM_KEYLEN, F, get_size) } {
        Err(()) => return 0,
        Ok(Some(n)) if n != g.key_len() => return 0,
        Ok(_) => {}
    }
    g.reset_final();
    1
}

/// `ossl_aes_gcm_siv_set_ctx_params`: the tag (exactly 16 octets; kept decrypting), `speed`,
/// and `keylen` (only as it is).
///
/// # Safety
/// As for `set_ctx_params`.
unsafe fn gcm_siv_set(g: &mut GcmSiv, params: *const OSSL_PARAM) -> c_int {
    const F: &str = "ossl_aes_gcm_siv_set_ctx_params";
    // SAFETY: the caller's array.
    if let Some((_, q)) = unsafe { find(params.cast_mut(), OSSL_CIPHER_PARAM_AEAD_TAG) } {
        let tag = if is_octets(q) {
            // SAFETY: the caller's guarantee.
            unsafe { data_of(q) }
        } else {
            None
        };
        if !tag.is_some_and(|t| g.set_tag(t).is_ok()) {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, F);
            return 0;
        }
    }
    // SAFETY: the caller's array.
    match unsafe { speed_of(params, F) } {
        Err(()) => return 0,
        Ok(Some(v)) => g.set_speed(v),
        Ok(None) => {}
    }
    // SAFETY: the caller's array.
    match unsafe { get_param(params, OSSL_CIPHER_PARAM_KEYLEN, F, get_size) } {
        Err(()) => return 0,
        Ok(Some(n)) if n != g.key_len() => {
            err::raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH, F);
            return 0;
        }
        Ok(_) => {}
    }
    1
}

static SIV_GETTABLE: Params<4> = Params([
    defn(
        OSSL_CIPHER_PARAM_KEYLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(
        OSSL_CIPHER_PARAM_AEAD_TAGLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_CIPHER_PARAM_AEAD_TAG, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);
static SIV_SETTABLE: Params<4> = Params([
    defn(
        OSSL_CIPHER_PARAM_KEYLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_CIPHER_PARAM_SPEED, OSSL_PARAM_UNSIGNED_INTEGER, UINT),
    defn(OSSL_CIPHER_PARAM_AEAD_TAG, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);

static AEAD_GETTABLE: Params<10> = Params([
    defn(
        OSSL_CIPHER_PARAM_KEYLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_CIPHER_PARAM_IVLEN, OSSL_PARAM_UNSIGNED_INTEGER, SIZE_T),
    defn(
        OSSL_CIPHER_PARAM_AEAD_TAGLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_CIPHER_PARAM_IV, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_CIPHER_PARAM_UPDATED_IV, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_CIPHER_PARAM_AEAD_TAG, OSSL_PARAM_OCTET_STRING, 0),
    defn(
        OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(
        OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN,
        OSSL_PARAM_OCTET_STRING,
        0,
    ),
    defn(
        OSSL_CIPHER_PARAM_AEAD_IV_GENERATED,
        OSSL_PARAM_UNSIGNED_INTEGER,
        UINT,
    ),
    PARAM_END,
]);
static AEAD_SETTABLE: Params<6> = Params([
    defn(
        OSSL_CIPHER_PARAM_AEAD_IVLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_CIPHER_PARAM_AEAD_TAG, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, OSSL_PARAM_OCTET_STRING, 0),
    defn(
        OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED,
        OSSL_PARAM_OCTET_STRING,
        0,
    ),
    defn(
        OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV,
        OSSL_PARAM_OCTET_STRING,
        0,
    ),
    PARAM_END,
]);
static OCB_GETTABLE: Params<7> = Params([
    defn(
        OSSL_CIPHER_PARAM_KEYLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_CIPHER_PARAM_IVLEN, OSSL_PARAM_UNSIGNED_INTEGER, SIZE_T),
    defn(
        OSSL_CIPHER_PARAM_AEAD_TAGLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_CIPHER_PARAM_IV, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_CIPHER_PARAM_UPDATED_IV, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_CIPHER_PARAM_AEAD_TAG, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);
static OCB_SETTABLE: Params<4> = Params([
    defn(
        OSSL_CIPHER_PARAM_KEYLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(
        OSSL_CIPHER_PARAM_AEAD_IVLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_CIPHER_PARAM_AEAD_TAG, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);
static CHACHA_POLY_GETTABLE: Params<6> = Params([
    defn(
        OSSL_CIPHER_PARAM_KEYLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_CIPHER_PARAM_IVLEN, OSSL_PARAM_UNSIGNED_INTEGER, SIZE_T),
    defn(
        OSSL_CIPHER_PARAM_AEAD_TAGLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_CIPHER_PARAM_AEAD_TAG, OSSL_PARAM_OCTET_STRING, 0),
    defn(
        OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    PARAM_END,
]);
static CHACHA_POLY_SETTABLE: Params<6> = Params([
    defn(
        OSSL_CIPHER_PARAM_KEYLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_CIPHER_PARAM_IVLEN, OSSL_PARAM_UNSIGNED_INTEGER, SIZE_T),
    defn(OSSL_CIPHER_PARAM_AEAD_TAG, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, OSSL_PARAM_OCTET_STRING, 0),
    defn(
        OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED,
        OSSL_PARAM_OCTET_STRING,
        0,
    ),
    PARAM_END,
]);

macro_rules! list {
    ($name:ident, $list:ident) => {
        ffi_callback! {
            /// A context parameter list.
            ///
            /// # Safety
            /// No preconditions.
            pub(crate) unsafe extern "C" fn $name(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
            where failure = ptr::null(), library = ERR_LIB_PROV
            {
                $list.0.as_ptr()
            }
        }
    };
}

list!(aead_gettable_ctx_params, AEAD_GETTABLE);
list!(aead_settable_ctx_params, AEAD_SETTABLE);
list!(ocb_gettable_ctx_params, OCB_GETTABLE);
list!(ocb_settable_ctx_params, OCB_SETTABLE);
list!(chacha_poly_gettable_ctx_params, CHACHA_POLY_GETTABLE);
list!(chacha_poly_settable_ctx_params, CHACHA_POLY_SETTABLE);
list!(siv_gettable_ctx_params, SIV_GETTABLE);
list!(siv_settable_ctx_params, SIV_SETTABLE);

ffi_callback! {
    /// `ossl_cipher_generic_gettable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn gettable_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        GENERIC_GETTABLE.0.as_ptr()
    }
}

/// An AEAD's `get_params` facts: AEAD and custom IV, a 12-octet IV.
const fn aead_info(mode: c_int, key_len: usize, block_size: usize) -> Info {
    Info {
        mode: mode.cast_unsigned(),
        aead: true,
        custom_iv: true,
        cts: false,
        multiblock: false,
        rand_key: false,
        key_len,
        block_size,
        iv_len: 12,
    }
}

/// SIV's and GCM-SIV's `get_params` facts: AEAD and custom IV, a block of 1.
const fn siv_info(mode: c_int, key_len: usize, iv_len: usize) -> Info {
    Info {
        mode: mode.cast_unsigned(),
        aead: true,
        custom_iv: true,
        cts: false,
        multiblock: false,
        rand_key: false,
        key_len,
        block_size: 1,
        iv_len,
    }
}

/// One AEAD: `newctx`, `get_params`, and its table.
macro_rules! aead {
    ($name:ident, $make:expr, $info:expr, $gettable:ident, $settable:ident) => {
        pub(crate) mod $name {
            use super::*;

            ffi_callback! {
                /// `newctx`.
                ///
                /// # Safety
                /// No preconditions.
                pub(crate) unsafe extern "C" fn newctx(provctx: *mut c_void) -> *mut c_void
                where failure = ptr::null_mut(), library = ERR_LIB_PROV
                {
                    // SAFETY: the provider's context.
                    unsafe { new_provided($make, provctx) }
                }
            }

            ffi_callback! {
                /// `get_params`.
                ///
                /// # Safety
                /// `params` is NULL or a parameter array.
                pub(crate) unsafe extern "C" fn get_params(params: *mut OSSL_PARAM) -> c_int
                where failure = 0, library = ERR_LIB_PROV
                {
                    // SAFETY: the caller's guarantee.
                    unsafe { get_params_of($info, params) }
                }
            }

            pub(crate) static TABLE: Dispatch<15> = Dispatch([
                entry!(OSSL_FUNC_CIPHER_NEWCTX, newctx, NewCtxFn),
                entry!(OSSL_FUNC_CIPHER_FREECTX, freectx, FreeFn),
                entry!(OSSL_FUNC_CIPHER_DUPCTX, dupctx, DupFn),
                entry!(OSSL_FUNC_CIPHER_ENCRYPT_INIT, einit, InitFn),
                entry!(OSSL_FUNC_CIPHER_DECRYPT_INIT, dinit, InitFn),
                entry!(OSSL_FUNC_CIPHER_UPDATE, update, UpdateFn),
                entry!(OSSL_FUNC_CIPHER_FINAL, final_, FinalFn),
                entry!(OSSL_FUNC_CIPHER_CIPHER, cipher, UpdateFn),
                entry!(OSSL_FUNC_CIPHER_GET_PARAMS, get_params, GetParamsFn),
                entry!(OSSL_FUNC_CIPHER_GET_CTX_PARAMS, get_ctx_params, GetCtxFn),
                entry!(OSSL_FUNC_CIPHER_SET_CTX_PARAMS, set_ctx_params, SetCtxFn),
                entry!(
                    OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
                    gettable_params,
                    GettableFn
                ),
                entry!(OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, $gettable, CtxParamsFn),
                entry!(OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, $settable, CtxParamsFn),
                END,
            ]);
        }
    };
}

use BlockAlgorithm::{Aes, Aria, Sm4};

macro_rules! gcm {
    ($name:ident, $alg:expr, $len:expr) => {
        aead!(
            $name,
            Aead::Gcm(Box::new(Gcm::new($alg, $len))),
            aead_info(EVP_CIPH_GCM_MODE, $len, 1),
            aead_gettable_ctx_params,
            aead_settable_ctx_params
        );
    };
}

macro_rules! ccm {
    ($name:ident, $alg:expr, $len:expr) => {
        aead!(
            $name,
            Aead::Ccm(Box::new(Ccm::new($alg, $len))),
            aead_info(EVP_CIPH_CCM_MODE, $len, 1),
            aead_gettable_ctx_params,
            aead_settable_ctx_params
        );
    };
}

macro_rules! ocb {
    ($name:ident, $len:expr) => {
        aead!(
            $name,
            Aead::Ocb(Box::new(Ocb::new($len))),
            aead_info(EVP_CIPH_OCB_MODE, $len, 16),
            ocb_gettable_ctx_params,
            ocb_settable_ctx_params
        );
    };
}

gcm!(aes256gcm, Aes, 32);
gcm!(aes192gcm, Aes, 24);
gcm!(aes128gcm, Aes, 16);
ccm!(aes256ccm, Aes, 32);
ccm!(aes192ccm, Aes, 24);
ccm!(aes128ccm, Aes, 16);
ocb!(aes256ocb, 32);
ocb!(aes192ocb, 24);
ocb!(aes128ocb, 16);
gcm!(aria256gcm, Aria, 32);
gcm!(aria192gcm, Aria, 24);
gcm!(aria128gcm, Aria, 16);
ccm!(aria256ccm, Aria, 32);
ccm!(aria192ccm, Aria, 24);
ccm!(aria128ccm, Aria, 16);
gcm!(sm4128gcm, Sm4, 16);
ccm!(sm4128ccm, Sm4, 16);
aead!(
    chacha20_poly1305,
    Aead::ChaChaPoly(Box::new(ChaChaPoly::new())),
    aead_info(0, 32, 1),
    chacha_poly_gettable_ctx_params,
    chacha_poly_settable_ctx_params
);

macro_rules! siv {
    ($name:ident, $len:expr) => {
        aead!(
            $name,
            Aead::Siv(Box::new(Siv::new($len))),
            siv_info(EVP_CIPH_SIV_MODE, $len, 0),
            siv_gettable_ctx_params,
            siv_settable_ctx_params
        );
    };
}

macro_rules! gcm_siv {
    ($name:ident, $len:expr) => {
        aead!(
            $name,
            Aead::GcmSiv(Box::new(GcmSiv::new($len))),
            siv_info(EVP_CIPH_GCM_SIV_MODE, $len, GCM_SIV_NONCE),
            siv_gettable_ctx_params,
            siv_settable_ctx_params
        );
    };
}

siv!(aes128siv, 32);
siv!(aes192siv, 48);
siv!(aes256siv, 64);
gcm_siv!(aes128gcm_siv, 16);
gcm_siv!(aes192gcm_siv, 24);
gcm_siv!(aes256gcm_siv, 32);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{construct, end};
    use rustyssl_abi::OSSL_PARAM_OCTET_PTR;

    /// docs/DEVIATIONS.md: OCB's `cipher` with data, and its `final` with a partial block
    /// buffered, fail with a NULL output instead of writing through it.
    #[test]
    fn ocb_null_output_is_refused() {
        // SAFETY: no preconditions.
        let ctx = unsafe { aes128ocb::newctx(ptr::null_mut()) };
        let key = [1u8; 16];
        let iv = [2u8; 12];
        // SAFETY: a live context, a key and IV of their lengths, and no parameters.
        let r = unsafe { einit(ctx, key.as_ptr(), 16, iv.as_ptr(), 12, ptr::null()) };
        assert_eq!(r, 1);
        let data = [0u8; 20];
        let mut outl = 0usize;
        // SAFETY: data and a NULL output, the case under test.
        let r = unsafe { cipher(ctx, ptr::null_mut(), &raw mut outl, 32, data.as_ptr(), 20) };
        assert_eq!(r, 0);
        let mut out = [0u8; 32];
        // SAFETY: an output of the size given and data: one block out, four octets buffered.
        let r = unsafe { update(ctx, out.as_mut_ptr(), &raw mut outl, 32, data.as_ptr(), 20) };
        assert_eq!((r, outl), (1, 16));
        // SAFETY: a NULL output for the buffered octets, the case under test.
        let r = unsafe { final_(ctx, ptr::null_mut(), &raw mut outl, 32) };
        assert_eq!(r, 0);
        // SAFETY: the context from `newctx`.
        unsafe { freectx(ctx) };
    }

    /// docs/DEVIATIONS.md: SIV's and GCM-SIV's tag with NULL data fails decrypting (the
    /// reference copies 16 octets from NULL).
    #[test]
    fn null_tags_are_refused() {
        for newctx in [aes128siv::newctx, aes128gcm_siv::newctx] {
            // SAFETY: no preconditions.
            let ctx = unsafe { newctx(ptr::null_mut()) };
            let key = [1u8; 32];
            let iv = [2u8; 12];
            // SAFETY: a live context; a key and IV long enough for either.
            let r = unsafe {
                dinit(
                    ctx,
                    key.as_ptr(),
                    key_len(ctx),
                    iv.as_ptr(),
                    12,
                    ptr::null(),
                )
            };
            assert_eq!(r, 1);
            let params = [
                crate::params::construct(
                    OSSL_CIPHER_PARAM_AEAD_TAG.as_ptr(),
                    OSSL_PARAM_OCTET_STRING.cast_unsigned(),
                    ptr::null_mut(),
                    16,
                ),
                crate::params::end(),
            ];
            // SAFETY: a live context and a parameter array, NULL data the case under test.
            assert_eq!(unsafe { set_ctx_params(ctx, params.as_ptr()) }, 0);
            // SAFETY: the context from `newctx`.
            unsafe { freectx(ctx) };
        }
    }

    /// The key length of a SIV or GCM-SIV context.
    fn key_len(ctx: *mut c_void) -> usize {
        // SAFETY: a live context from one of this module's `newctx`.
        match unsafe { context(ctx) } {
            Some(Aead::Siv(g)) => g.key_len(),
            Some(Aead::GcmSiv(g)) => g.key_len(),
            _ => 0,
        }
    }

    /// docs/DEVIATIONS.md: GCM-SIV's message and final before an init fail (the reference
    /// uses a cipher context it hasn't made).
    #[test]
    fn gcm_siv_before_an_init_is_refused() {
        // SAFETY: no preconditions.
        let ctx = unsafe { aes128gcm_siv::newctx(ptr::null_mut()) };
        let data = [1u8; 5];
        let mut out = [0u8; 16];
        let mut outl = 0usize;
        // SAFETY: room for the output; the input.
        let r = unsafe { update(ctx, out.as_mut_ptr(), &raw mut outl, 16, data.as_ptr(), 5) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let r = unsafe { final_(ctx, out.as_mut_ptr(), &raw mut outl, 16) };
        assert_eq!(r, 0);
        // SAFETY: the context from `newctx`.
        unsafe { freectx(ctx) };
    }

    /// docs/DEVIATIONS.md: SIV's AAD, and its messages with `speed`, without a key fail (the
    /// reference crashes).
    #[test]
    fn siv_aad_without_a_key_is_refused() {
        // SAFETY: no preconditions.
        let ctx = unsafe { aes128siv::newctx(ptr::null_mut()) };
        // SAFETY: a live context, no key, no parameters.
        let r = unsafe { einit(ctx, ptr::null(), 0, ptr::null(), 0, ptr::null()) };
        assert_eq!(r, 1);
        let aad = [1u8; 5];
        let mut outl = 0usize;
        // SAFETY: AAD (no output) without a key, the case under test.
        let r = unsafe { update(ctx, ptr::null_mut(), &raw mut outl, 5, aad.as_ptr(), 5) };
        assert_eq!(r, 0);
        // A message with `speed` set: the reference uses the key's contexts unmade.
        let mut speed: core::ffi::c_uint = 1;
        let params = [
            crate::params::construct(
                OSSL_CIPHER_PARAM_SPEED.as_ptr(),
                OSSL_PARAM_UNSIGNED_INTEGER.cast_unsigned(),
                (&raw mut speed).cast(),
                size_of::<core::ffi::c_uint>(),
            ),
            crate::params::end(),
        ];
        // SAFETY: a live context and a parameter array.
        assert_eq!(unsafe { set_ctx_params(ctx, params.as_ptr()) }, 1);
        let mut out = [0u8; 5];
        // SAFETY: room for the output; the input.
        let r = unsafe { update(ctx, out.as_mut_ptr(), &raw mut outl, 5, aad.as_ptr(), 5) };
        assert_eq!(r, 0);
        // Its copy fails, and what a failed EVP copy leaves (no algorithm context) is refused.
        // SAFETY: a live context.
        assert!(unsafe { dupctx(ctx) }.is_null());
        // SAFETY: a NULL context, the case under test.
        let r = unsafe { final_(ptr::null_mut(), out.as_mut_ptr(), &raw mut outl, 5) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let r = unsafe {
            update(
                ptr::null_mut(),
                out.as_mut_ptr(),
                &raw mut outl,
                5,
                aad.as_ptr(),
                5,
            )
        };
        assert_eq!(r, 0);
        // SAFETY: the context from `newctx`.
        unsafe { freectx(ctx) };
    }

    /// docs/DEVIATIONS.md: CCM's IV requested into more room than its 16-octet buffer is the
    /// IV and zeros, and a pointer to it covers the buffer only.
    #[test]
    fn ccm_iv_into_more_room() {
        // SAFETY: no preconditions.
        let ctx = unsafe { aes128ccm::newctx(ptr::null_mut()) };
        let key = [1u8; 16];
        let iv = [0xf0u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6];
        // SAFETY: a live context, a key and IV of their lengths, and no parameters.
        let r = unsafe { einit(ctx, key.as_ptr(), 16, iv.as_ptr(), 7, ptr::null()) };
        assert_eq!(r, 1);
        let mut room = [0xeeu8; 40];
        let mut p: *const c_void = ptr::null();
        let mut params = [
            construct(
                OSSL_CIPHER_PARAM_IV.as_ptr(),
                OSSL_PARAM_OCTET_STRING.cast_unsigned(),
                room.as_mut_ptr().cast(),
                room.len(),
            ),
            construct(
                OSSL_CIPHER_PARAM_UPDATED_IV.as_ptr(),
                OSSL_PARAM_OCTET_PTR.cast_unsigned(),
                (&raw mut p).cast(),
                64,
            ),
            end(),
        ];
        // SAFETY: a live context and a parameter array.
        assert_eq!(unsafe { get_ctx_params(ctx, params.as_mut_ptr()) }, 1);
        assert_eq!(params[0].return_size, 40);
        assert_eq!(room[..7], iv);
        assert!(room[7..].iter().all(|&b| b == 0));
        assert!(!p.is_null());
        assert_eq!(params[1].return_size, 16);
        // SAFETY: the context from `newctx`.
        unsafe { freectx(ctx) };
    }
}
