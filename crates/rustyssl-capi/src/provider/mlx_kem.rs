//! The default provider's hybrid ML-KEM KEM (`mlx_kem.c`), for the hybrid key managers' keys
//! (`mlx_kmgmt::MlxKey`): an encapsulation is ML-KEM's to the key's ML-KEM component and an
//! ephemeral ECDH exchange with its ECDH component (the ephemeral public key the ECDH part of
//! the ciphertext); a decapsulation is ML-KEM's and the ECDH exchange with the ciphertext's
//! public key. Both run through EVP with the key's library context and properties.
//!
//! As in OpenSSL, the context holds the key data without a reference, a size query needs only
//! one of the lengths, the ciphertext's length is written before the secret's room is checked,
//! a decapsulation tolerates a NULL length, and a failure after the rooms are checked wipes the
//! secret.

use core::ffi::{c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, EVP_PKEY, EVP_PKEY_OP_DECAPSULATE, EVP_PKEY_OP_ENCAPSULATE,
    OSSL_FUNC_KEM_DECAPSULATE, OSSL_FUNC_KEM_DECAPSULATE_INIT, OSSL_FUNC_KEM_ENCAPSULATE,
    OSSL_FUNC_KEM_ENCAPSULATE_INIT, OSSL_FUNC_KEM_FREECTX, OSSL_FUNC_KEM_NEWCTX,
    OSSL_FUNC_KEM_SET_CTX_PARAMS, OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, OSSL_PARAM,
    OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, PROV_R_MISSING_KEY, PROV_R_NULL_LENGTH_POINTER,
    PROV_R_NULL_OUTPUT_BUFFER, PROV_R_OUTPUT_BUFFER_TOO_SMALL, PROV_R_WRONG_CIPHERTEXT_SIZE,
};

use super::macs::{boxed, context, unbox, wipe};
use super::mlx_kmgmt::{Components, Hybrid, ML_KEM_SECRET, MlxKey, key};
use super::tables::{Dispatch, END, PARAM_END, Params, entry};
use crate::err;
use crate::evp::exchange::{EVP_PKEY_derive, EVP_PKEY_derive_init, EVP_PKEY_derive_set_peer};
use crate::evp::kem::{
    EVP_PKEY_decapsulate, EVP_PKEY_decapsulate_init, EVP_PKEY_encapsulate,
    EVP_PKEY_encapsulate_init,
};
use crate::evp::pkey::params::{EVP_PKEY_get_octet_string_param, EVP_PKEY_set1_encoded_public_key};
use crate::evp::pkey::{EVP_PKEY_copy_parameters, EVP_PKEY_free, EVP_PKEY_new};
use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_pkey, EVP_PKEY_keygen, EVP_PKEY_keygen_init,
};
use crate::ffi::{bytes, ffi_callback};

/// `PROV_MLX_KEM_CTX`.
struct KemCtx {
    /// The key data, without a reference.
    key: *const c_void,
    op: c_int,
}

impl KemCtx {
    /// The key.
    fn key<'a>(&self) -> Option<&'a MlxKey> {
        // SAFETY: the key data the operation was initialized with, kept alive by its key.
        unsafe { key(self.key) }
    }
}

/// The context behind `vctx`.
///
/// # Safety
/// `vctx` is NULL or a live context from `mlx_kem_newctx`.
unsafe fn ctx<'a>(vctx: *mut c_void) -> Option<&'a mut KemCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { context::<KemCtx>(vctx) }
}

ffi_callback! {
    /// `mlx_kem_newctx`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn mlx_kem_newctx(_provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        boxed(KemCtx { key: ptr::null(), op: 0 })
    }
}

ffi_callback! {
    /// `mlx_kem_freectx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context the caller gives up.
    pub(crate) unsafe extern "C" fn mlx_kem_freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<KemCtx>(vctx) };
    }
}

/// `mlx_kem_init`: the key and operation (the parameters are ignored).
///
/// # Safety
/// `vctx` is NULL or a live context.
unsafe fn init(vctx: *mut c_void, op: c_int, vkey: *mut c_void) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx(vctx) }) else {
        return 0;
    };
    c.key = vkey;
    c.op = op;
    1
}

ffi_callback! {
    /// `mlx_kem_encapsulate_init`: a key with a public key.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `vkey` is NULL or live hybrid key data.
    pub(crate) unsafe extern "C" fn mlx_kem_encapsulate_init(vctx: *mut c_void, vkey: *mut c_void, _params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { key(vkey) }.is_some_and(MlxKey::has_public) {
            err::raise(ERR_LIB_PROV, PROV_R_MISSING_KEY, "mlx_kem_encapsulate_init");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { init(vctx, EVP_PKEY_OP_ENCAPSULATE, vkey) }
    }
}

ffi_callback! {
    /// `mlx_kem_decapsulate_init`: a key with a private key.
    ///
    /// # Safety
    /// As for `mlx_kem_encapsulate_init`.
    pub(crate) unsafe extern "C" fn mlx_kem_decapsulate_init(vctx: *mut c_void, vkey: *mut c_void, _params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { key(vkey) }.is_some_and(MlxKey::has_private) {
            err::raise(ERR_LIB_PROV, PROV_R_MISSING_KEY, "mlx_kem_decapsulate_init");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { init(vctx, EVP_PKEY_OP_DECAPSULATE, vkey) }
    }
}

/// `mlx_kem_settable_ctx_params`' list: nothing.
static SETTABLE: Params<1> = Params([PARAM_END]);

ffi_callback! {
    /// `mlx_kem_settable_ctx_params`.
    pub(crate) unsafe extern "C" fn mlx_kem_settable_ctx_params(_vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `mlx_kem_set_ctx_params`: nothing to set.
    pub(crate) unsafe extern "C" fn mlx_kem_set_ctx_params(_vctx: *mut c_void, _params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        1
    }
}

/// An internal error for a component's output of an unexpected size.
fn unexpected(f: &str, what: String) {
    err::raise_with_text(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, f, &what);
}

/// A context for `pkey`, freed on drop.
struct PkeyCtx(*mut rustyssl_abi::EVP_PKEY_CTX);

impl PkeyCtx {
    fn new(c: &Components, pkey: *mut EVP_PKEY) -> Self {
        // SAFETY: the key's library context; a live key; the properties or NULL.
        Self(unsafe { EVP_PKEY_CTX_new_from_pkey(c.libctx, pkey, c.propq()) })
    }
}

impl Drop for PkeyCtx {
    fn drop(&mut self) {
        // SAFETY: made by `new`, or NULL.
        unsafe { EVP_PKEY_CTX_free(self.0) };
    }
}

/// A key, freed on drop.
struct Pkey(*mut EVP_PKEY);

impl Drop for Pkey {
    fn drop(&mut self) {
        // SAFETY: a reference this holds, or NULL.
        unsafe { EVP_PKEY_free(self.0) };
    }
}

/// The encapsulation into the ciphertext's and secret's rooms (already checked).
fn encapsulate(info: &Hybrid, c: &Components, ct: &mut [u8], ss: &mut [u8]) -> bool {
    const F: &str = "mlx_kem_encapsulate";
    let m = &info.ml_kem;
    let (cm, cx) = (
        info.ml_kem_offset(info.pubkey_bytes),
        info.ecdh_offset(m.ctext_bytes),
    );
    let (sm, sx) = (
        info.ml_kem_offset(info.shsec_bytes),
        info.ecdh_offset(ML_KEM_SECRET),
    );
    let (Some(cbuf), Some(sbuf)) = (
        ct.get_mut(cm..cm.saturating_add(m.ctext_bytes)),
        ss.get_mut(sm..sm.saturating_add(ML_KEM_SECRET)),
    ) else {
        return false;
    };
    let (mut clen, mut slen) = (m.ctext_bytes, ML_KEM_SECRET);
    let ctx = PkeyCtx::new(c, c.mkey);
    // SAFETY: the context (or NULL, checked); the rooms of the lengths given.
    let ok = !ctx.0.is_null()
        && unsafe { EVP_PKEY_encapsulate_init(ctx.0, ptr::null()) } > 0
        && unsafe {
            EVP_PKEY_encapsulate(
                ctx.0,
                cbuf.as_mut_ptr(),
                &raw mut clen,
                sbuf.as_mut_ptr(),
                &raw mut slen,
            )
        } > 0;
    if !ok {
        return false;
    }
    let name = m.name.to_string_lossy();
    if clen != m.ctext_bytes {
        unexpected(
            F,
            format!("unexpected {name} ciphertext output size: {clen}"),
        );
        return false;
    }
    if slen != ML_KEM_SECRET {
        unexpected(
            F,
            format!("unexpected {name} shared secret output size: {slen}"),
        );
        return false;
    }
    drop(ctx);

    // The ephemeral ECDH key, its public key the rest of the ciphertext.
    let Some(cbuf) = ct.get_mut(cx..cx.saturating_add(info.pubkey_bytes)) else {
        return false;
    };
    let mut clen = info.pubkey_bytes;
    let ctx = PkeyCtx::new(c, c.xkey);
    let mut eph = Pkey(ptr::null_mut());
    // SAFETY: the context (or NULL, checked); a place for the key; the room for its public key.
    let ok = !ctx.0.is_null()
        && unsafe { EVP_PKEY_keygen_init(ctx.0) } > 0
        && unsafe { EVP_PKEY_keygen(ctx.0, &raw mut eph.0) } > 0
        && unsafe {
            EVP_PKEY_get_octet_string_param(
                eph.0,
                OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY.as_ptr(),
                cbuf.as_mut_ptr(),
                clen,
                &raw mut clen,
            )
        } > 0;
    if !ok {
        return false;
    }
    let xname = info.algorithm_name.to_string_lossy();
    if clen != info.pubkey_bytes {
        unexpected(
            F,
            format!("unexpected {xname} public key output size: {clen}"),
        );
        return false;
    }
    drop(ctx);

    let Some(sbuf) = ss.get_mut(sx..sx.saturating_add(info.shsec_bytes)) else {
        return false;
    };
    let mut slen = info.shsec_bytes;
    let ctx = PkeyCtx::new(c, eph.0);
    // SAFETY: the context (or NULL, checked); the peer's live key; the room for the secret.
    let ok = !ctx.0.is_null()
        && unsafe { EVP_PKEY_derive_init(ctx.0) } > 0
        && unsafe { EVP_PKEY_derive_set_peer(ctx.0, c.xkey) } > 0
        && unsafe { EVP_PKEY_derive(ctx.0, sbuf.as_mut_ptr(), &raw mut slen) } > 0;
    if !ok {
        return false;
    }
    if slen != info.shsec_bytes {
        unexpected(
            F,
            format!("unexpected {xname} shared secret output size: {slen}"),
        );
        return false;
    }
    true
}

ffi_callback! {
    /// `mlx_kem_encapsulate`: the lengths when `ctext` is NULL (failing if both are NULL), else
    /// the ciphertext and secret into rooms of at least their lengths.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `ctext` and `shsec` are NULL or have room for `*clen`
    /// and `*slen` octets; `clen` and `slen` are NULL or live `size_t`s.
    pub(crate) unsafe extern "C" fn mlx_kem_encapsulate(vctx: *mut c_void, ctext: *mut c_uchar, clen: *mut usize, shsec: *mut c_uchar, slen: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "mlx_kem_encapsulate";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        let Some(k) = c.key().filter(|k| k.has_public()) else {
            err::raise(ERR_LIB_PROV, PROV_R_MISSING_KEY, F);
            return 0;
        };
        let info = k.info;
        let (ct_len, ss_len) = (info.ciphertext_len(), info.secret_len());
        if ctext.is_null() {
            if clen.is_null() && slen.is_null() {
                return 0;
            }
            // SAFETY: the caller's guarantee: NULL or a live `size_t`.
            if let Some(cl) = unsafe { clen.as_mut() } {
                *cl = ct_len;
            }
            // SAFETY: as above.
            if let Some(sl) = unsafe { slen.as_mut() } {
                *sl = ss_len;
            }
            return 1;
        }
        if shsec.is_null() {
            err::raise_with_text(ERR_LIB_PROV, PROV_R_NULL_OUTPUT_BUFFER, F, "null shared-secret output buffer");
            return 0;
        }
        // SAFETY: the caller's guarantee: NULL or a live `size_t`.
        let Some(cl) = (unsafe { clen.as_mut() }) else {
            err::raise_with_text(ERR_LIB_PROV, PROV_R_NULL_LENGTH_POINTER, F, "null ciphertext input/output length pointer");
            return 0;
        };
        if *cl < ct_len {
            err::raise_with_text(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL, F, "ciphertext buffer too small");
            return 0;
        }
        *cl = ct_len;
        // SAFETY: as above.
        let Some(sl) = (unsafe { slen.as_mut() }) else {
            err::raise_with_text(ERR_LIB_PROV, PROV_R_NULL_LENGTH_POINTER, F, "null shared secret input/output length pointer");
            return 0;
        };
        if *sl < ss_len {
            err::raise_with_text(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL, F, "shared-secret buffer too small");
            return 0;
        }
        *sl = ss_len;
        // SAFETY: the caller's rooms of at least the lengths checked above.
        let ct = unsafe { core::slice::from_raw_parts_mut(ctext, ct_len) };
        // SAFETY: as above.
        let ss = unsafe { core::slice::from_raw_parts_mut(shsec, ss_len) };
        let comps = k.components();
        if encapsulate(info, &comps, ct, ss) {
            return 1;
        }
        wipe(ss);
        0
    }
}

/// The decapsulation of a ciphertext of the right length into the secret's room.
fn decapsulate(info: &Hybrid, c: &Components, ct: &[u8], ss: &mut [u8]) -> bool {
    const F: &str = "mlx_kem_decapsulate";
    let m = &info.ml_kem;
    let (cm, cx) = (
        info.ml_kem_offset(info.pubkey_bytes),
        info.ecdh_offset(m.ctext_bytes),
    );
    let (sm, sx) = (
        info.ml_kem_offset(info.shsec_bytes),
        info.ecdh_offset(ML_KEM_SECRET),
    );
    let (Some(cbuf), Some(sbuf)) = (
        ct.get(cm..cm.saturating_add(m.ctext_bytes)),
        ss.get_mut(sm..sm.saturating_add(ML_KEM_SECRET)),
    ) else {
        return false;
    };
    let mut slen = ML_KEM_SECRET;
    let ctx = PkeyCtx::new(c, c.mkey);
    // SAFETY: the context (or NULL, checked); the room for the secret; the ciphertext's part.
    let ok = !ctx.0.is_null()
        && unsafe { EVP_PKEY_decapsulate_init(ctx.0, ptr::null()) } > 0
        && unsafe {
            EVP_PKEY_decapsulate(
                ctx.0,
                sbuf.as_mut_ptr(),
                &raw mut slen,
                cbuf.as_ptr(),
                cbuf.len(),
            )
        } > 0;
    if !ok {
        return false;
    }
    if slen != ML_KEM_SECRET {
        let name = m.name.to_string_lossy();
        unexpected(
            F,
            format!("unexpected {name} shared secret output size: {slen}"),
        );
        return false;
    }
    drop(ctx);

    let (Some(cbuf), Some(sbuf)) = (
        ct.get(cx..cx.saturating_add(info.pubkey_bytes)),
        ss.get_mut(sx..sx.saturating_add(info.shsec_bytes)),
    ) else {
        return false;
    };
    let mut slen = info.shsec_bytes;
    let ctx = PkeyCtx::new(c, c.xkey);
    // SAFETY: no preconditions.
    let peer = Pkey(unsafe { EVP_PKEY_new() });
    // SAFETY: the context and peer (or NULL, checked); the key's live component; the
    // ciphertext's part; the room for the secret.
    let ok = !ctx.0.is_null()
        && !peer.0.is_null()
        && unsafe { EVP_PKEY_copy_parameters(peer.0, c.xkey) } > 0
        && unsafe { EVP_PKEY_set1_encoded_public_key(peer.0, cbuf.as_ptr(), cbuf.len()) } > 0
        && unsafe { EVP_PKEY_derive_init(ctx.0) } > 0
        && unsafe { EVP_PKEY_derive_set_peer(ctx.0, peer.0) } > 0
        && unsafe { EVP_PKEY_derive(ctx.0, sbuf.as_mut_ptr(), &raw mut slen) } > 0;
    if !ok {
        return false;
    }
    if slen != info.shsec_bytes {
        let xname = info.algorithm_name.to_string_lossy();
        unexpected(
            F,
            format!("unexpected {xname} shared secret output size: {slen}"),
        );
        return false;
    }
    true
}

ffi_callback! {
    /// `mlx_kem_decapsulate`: the secret's length when `shsec` is NULL, else the secret into
    /// room of at least its length (a NULL length taken as enough) from a ciphertext of exactly
    /// the hybrid's length.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `shsec` is NULL or has room for `*slen` octets (the
    /// secret's length if `slen` is NULL); `slen` is NULL or a live `size_t`; `ctext` holds
    /// `clen` octets.
    pub(crate) unsafe extern "C" fn mlx_kem_decapsulate(vctx: *mut c_void, shsec: *mut c_uchar, slen: *mut usize, ctext: *const c_uchar, clen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "mlx_kem_decapsulate";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        let Some(k) = c.key().filter(|k| k.has_private()) else {
            err::raise(ERR_LIB_PROV, PROV_R_MISSING_KEY, F);
            return 0;
        };
        let info = k.info;
        let ss_len = info.secret_len();
        // SAFETY: the caller's guarantee: NULL or a live `size_t`.
        let sl = unsafe { slen.as_mut() };
        if shsec.is_null() {
            let Some(sl) = sl else { return 0 };
            *sl = ss_len;
            return 1;
        }
        if let Some(sl) = sl {
            if *sl < ss_len {
                err::raise_with_text(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL, F, "shared-secret buffer too small");
                return 0;
            }
            *sl = ss_len;
        }
        if clen != info.ciphertext_len() {
            err::raise_with_text(
                ERR_LIB_PROV,
                PROV_R_WRONG_CIPHERTEXT_SIZE,
                F,
                &format!("wrong decapsulation input ciphertext size: {clen}"),
            );
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(ct) = (unsafe { bytes(ctext, clen) }) else { return 0 };
        // SAFETY: the caller's room of at least the secret's length.
        let ss = unsafe { core::slice::from_raw_parts_mut(shsec, ss_len) };
        let comps = k.components();
        if decapsulate(info, &comps, ct, ss) {
            return 1;
        }
        wipe(ss);
        0
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

/// `ossl_mlx_kem_asym_kem_functions`.
pub(crate) static MLX_KEM: Dispatch<9> = Dispatch([
    entry!(OSSL_FUNC_KEM_NEWCTX, mlx_kem_newctx, NewCtxFn),
    entry!(
        OSSL_FUNC_KEM_ENCAPSULATE_INIT,
        mlx_kem_encapsulate_init,
        InitFn
    ),
    entry!(
        OSSL_FUNC_KEM_ENCAPSULATE,
        mlx_kem_encapsulate,
        EncapsulateFn
    ),
    entry!(
        OSSL_FUNC_KEM_DECAPSULATE_INIT,
        mlx_kem_decapsulate_init,
        InitFn
    ),
    entry!(
        OSSL_FUNC_KEM_DECAPSULATE,
        mlx_kem_decapsulate,
        DecapsulateFn
    ),
    entry!(OSSL_FUNC_KEM_FREECTX, mlx_kem_freectx, FreeCtxFn),
    entry!(
        OSSL_FUNC_KEM_SET_CTX_PARAMS,
        mlx_kem_set_ctx_params,
        SetParamsFn
    ),
    entry!(
        OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,
        mlx_kem_settable_ctx_params,
        ListFn
    ),
    END,
]);
