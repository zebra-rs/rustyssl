//! Signing and verifying through a digest context (`EVP_DigestSignInit(3)`,
//! `EVP_DigestVerifyInit(3)`, `EVP_SignInit(3)`; `m_sigver.c`, `p_sign.c`, `p_verify.c`): the
//! digest context holds a key context with a signature operation (`EVP_PKEY_OP_SIGNCTX` or
//! `VERIFYCTX`), whose algorithm digests and signs the data itself.
//!
//! As in OpenSSL:
//! - The init finds the signature algorithm the key's type names (as `EVP_PKEY_sign_init`
//!   does), picks the digest (the given one, by name, or the key manager's default), and
//!   starts the algorithm; initializing again without a key restarts the same operation.
//! - A final without `EVP_MD_CTX_FLAG_FINALISE` signs a copy of the operation, so the context
//!   can go on; with it, or if the copy can't be made, the context is finalized.
//! - `EVP_SignFinal` and `EVP_VerifyFinal` digest, then sign or verify the digest with a key
//!   context of their own.
//!
//! Without a provider operation, OpenSSL's legacy path would use an `EVP_PKEY_METHOD`, of which
//! none can exist before 4.2d; those paths fail as OpenSSL's do without one.

use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    ENGINE, ERR_LIB_EVP, ERR_R_EVP_LIB, EVP_MAX_MD_SIZE, EVP_MD, EVP_MD_CTX,
    EVP_MD_CTX_FLAG_FINALISE, EVP_PKEY, EVP_PKEY_CTX, EVP_PKEY_OP_SIGNCTX, EVP_PKEY_OP_TYPE_SIG,
    EVP_PKEY_OP_UNDEFINED, EVP_PKEY_OP_VERIFYCTX, EVP_R_COMMAND_NOT_SUPPORTED, EVP_R_FINAL_ERROR,
    EVP_R_INITIALIZATION_ERROR, EVP_R_INVALID_OPERATION, EVP_R_NO_DEFAULT_DIGEST, EVP_R_NO_KEY_SET,
    EVP_R_NO_OPERATION_SET, EVP_R_PROVIDER_SIGNATURE_FAILURE,
    EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED, EVP_R_UPDATE_ERROR, OSSL_LIB_CTX, OSSL_OP_SIGNATURE,
    OSSL_PARAM,
};

use super::digest::{EVP_MD_fetch, EVP_MD_get0_name};
use super::legacy_md::EVP_get_digestbyname;
use super::md_ctx::{
    self, EVP_DigestFinal_ex, EVP_MD_CTX_copy_ex, EVP_MD_CTX_free, EVP_MD_CTX_new, FLAG_FINALISED,
    FLAG_KEEP_PKEY_CTX, MdCtx,
};
use super::pkey_ctx::{
    self, EVP_PKEY_CTX_dup, EVP_PKEY_CTX_free, EVP_PKEY_CTX_new, EVP_PKEY_CTX_new_from_pkey,
};
use super::signature::{
    self, EVP_PKEY_CTX_set_signature_md, EVP_PKEY_sign, EVP_PKEY_sign_init, EVP_PKEY_verify,
    EVP_PKEY_verify_init, NotChosen,
};
use crate::err::{self, ERR_clear_last_mark, ERR_count_to_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::ffi::ffi_export;
use crate::provider::Ptr;

/// `EVP_MD_CTX_FLAG_FINALISE`, as the flags' type.
const FINALISE: u64 = EVP_MD_CTX_FLAG_FINALISE as u64;

/// Whether `pctx` has a signature operation with a provider context: `Some(Some(false))` for
/// signing through a digest context, `Some(Some(true))` for verifying, `Some(None)` for another
/// signature operation; `None` without one.
///
/// # Safety
/// `pctx` is NULL or a live key context.
pub(crate) unsafe fn sig_operation(pctx: *mut EVP_PKEY_CTX) -> Option<Option<bool>> {
    // SAFETY: the caller's guarantee.
    let c = unsafe { pkey_ctx::context(pctx) }?;
    let s = c.lock();
    if !s.is_sig_op() || s.sigctx.0.is_null() {
        return None;
    }
    Some(match s.operation {
        EVP_PKEY_OP_SIGNCTX => Some(false),
        EVP_PKEY_OP_VERIFYCTX => Some(true),
        _ => None,
    })
}

/// The signature algorithm and its context of `pctx`'s signing or verifying through a digest
/// context, if that's its operation.
///
/// # Safety
/// `pctx` is NULL or a live key context.
pub(crate) unsafe fn sig_ctx(pctx: *mut EVP_PKEY_CTX) -> Option<(signature::Ref, *mut c_void)> {
    // SAFETY: the caller's guarantee.
    let c = unsafe { pkey_ctx::context(pctx) }?;
    let s = c.lock();
    if s.operation != EVP_PKEY_OP_SIGNCTX && s.operation != EVP_PKEY_OP_VERIFYCTX {
        return None;
    }
    let sig = s.signature.clone()?;
    (!s.sigctx.0.is_null()).then_some((sig, s.sigctx.0))
}

/// The `EVP_PKEY_CTRL_DIGESTINIT` a legacy digest init sends a key context that isn't signing
/// through a provider (`EVP_PKEY_CTX_ctrl`): without an `EVP_PKEY_METHOD` (none can exist
/// before 4.2d) it fails for a context without a signature operation and is unsupported (which
/// the init ignores) otherwise. False if the init fails.
///
/// # Safety
/// `pctx` is NULL or a live key context.
pub(crate) unsafe fn digest_init_ctrl(pctx: *mut EVP_PKEY_CTX) -> bool {
    const F: &str = "evp_pkey_ctx_ctrl_int";
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { pkey_ctx::context(pctx) }) else {
        return true;
    };
    let (operation, has_sig) = {
        let s = c.lock();
        (s.operation, s.is_sig_op() && s.signature.is_some())
    };
    if has_sig {
        return true;
    }
    if operation == EVP_PKEY_OP_UNDEFINED {
        err::raise(ERR_LIB_EVP, EVP_R_NO_OPERATION_SET, F);
        return false;
    }
    if operation & EVP_PKEY_OP_TYPE_SIG == 0 {
        err::raise(ERR_LIB_EVP, EVP_R_INVALID_OPERATION, F);
        return false;
    }
    err::raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED, F);
    true
}

/// `canon_mdname`: `UNDEF` is no digest.
fn canon_mdname(name: Option<CString>) -> Option<CString> {
    name.filter(|n| n.as_bytes() != b"UNDEF")
}

/// A C string as an owned `CString`, `None` for NULL.
///
/// # Safety
/// `s` is NULL or a string.
unsafe fn owned(s: *const c_char) -> Option<CString> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) }.to_owned())
}

/// The digest's name, `None` for NULL.
///
/// # Safety
/// `md` is NULL or a live digest.
unsafe fn md_name(md: *const EVP_MD) -> Option<CString> {
    if md.is_null() {
        return None;
    }
    // SAFETY: the caller's guarantee.
    let name = unsafe { EVP_MD_get0_name(md) };
    // SAFETY: NULL or the digest's string.
    unsafe { owned(name) }
}

/// `do_sigver_init`: sets `ctx` up to sign (or verify) with `pkey`'s type's signature algorithm
/// and the digest `type_` or `mdname`. 1, or 0 with an error.
///
/// # Safety
/// `ctx` is a live digest context; `pctx` is NULL or room for a pointer; `type_` is NULL or a
/// live digest; `mdname`, `props` are NULL or strings; `libctx` is NULL or a live library
/// context; `pkey` is NULL or a live key; `params` is NULL or an array.
#[expect(
    clippy::too_many_arguments,
    reason = "OpenSSL's internal function's arguments"
)]
unsafe fn do_sigver_init(
    ctx: *mut EVP_MD_CTX,
    pctx: *mut *mut EVP_PKEY_CTX,
    type_: *const EVP_MD,
    mdname: *const c_char,
    libctx: *mut OSSL_LIB_CTX,
    props: *const c_char,
    e: *mut ENGINE,
    pkey: *mut EVP_PKEY,
    ver: bool,
    params: *const OSSL_PARAM,
) -> c_int {
    const F: &str = "do_sigver_init";
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { md_ctx::context(ctx) }) else {
        return 0;
    };
    // SAFETY: the context's own fields.
    if !unsafe { md_ctx::free_algctx(c) } {
        return 0;
    }
    let mut reinit = true;
    if c.pctx.is_null() {
        reinit = false;
        c.pctx = if e.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, pkey, props) }
        } else {
            // SAFETY: as above.
            unsafe { EVP_PKEY_CTX_new(pkey, e) }
        };
    }
    if c.pctx.is_null() {
        return 0;
    }
    c.flags &= !FLAG_FINALISED;
    let locpctx = c.pctx;
    // SAFETY: the context's live key context.
    let Some(lc) = (unsafe { pkey_ctx::context(locpctx) }) else {
        return 0;
    };
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    let (ctx_km, operation, has_sig, propq, ctx_libctx, ctx_pkey) = {
        let s = lc.lock();
        (
            s.keymgmt.clone(),
            s.operation,
            s.signature.is_some() && !s.sigctx.0.is_null(),
            s.propquery.clone(),
            s.libctx.0,
            s.pkey.clone(),
        )
    };
    let Some(ctx_km) = ctx_km else {
        // A legacy key context: its EVP_PKEY_METHOD signs (4.2d).
        crate::stub::unimplemented("EVP_DigestSignInit with a legacy key context");
    };
    let wanted = if ver {
        EVP_PKEY_OP_VERIFYCTX
    } else {
        EVP_PKEY_OP_SIGNCTX
    };
    if reinit && (!pkey.is_null() || operation != wanted || !has_sig) {
        reinit = false;
    }
    // The query: the caller's, else the key context's.
    // SAFETY: the caller's guarantee.
    let props = unsafe { owned(props) }.or(propq.clone());
    let Some(ctx_pkey) = ctx_pkey else {
        // SAFETY: the mark set above.
        unsafe { ERR_clear_last_mark() };
        err::raise(ERR_LIB_EVP, EVP_R_NO_KEY_SET, F);
        return fail(lc);
    };
    // SAFETY: the caller's guarantee.
    let mut mdname = unsafe { owned(mdname) };
    let mut chosen_km: Option<super::keymgmt::Ref> = None;
    let mut provkey: Option<std::sync::Arc<super::pkey::KeyData>> = None;
    if reinit {
        if mdname.is_none() && type_.is_null() {
            // SAFETY: the context's requested digest, NULL or live.
            mdname = canon_mdname(unsafe { md_name(c.reqdigest) });
        }
        // SAFETY: the mark set above.
        unsafe { ERR_pop_to_mark() };
    } else {
        lc.lock().free_old_ops();
        let supported = ctx_km.get().query_operation_name(OSSL_OP_SIGNATURE);
        // SAFETY: the key context's library context.
        let chosen = unsafe {
            signature::choose(ctx_libctx, &ctx_km, &ctx_pkey, propq.as_deref(), &supported)
        };
        let chosen = match chosen {
            Ok(ch) => ch,
            Err(NotChosen::Legacy) => {
                // `legacy`: without an EVP_PKEY_METHOD, not supported.
                // SAFETY: the mark set above.
                unsafe { ERR_pop_to_mark() };
                err::raise(
                    ERR_LIB_EVP,
                    rustyssl_abi::EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
                    F,
                );
                return 0;
            }
            Err(NotChosen::Exhausted) => {
                // SAFETY: the mark set above.
                unsafe { ERR_clear_last_mark() };
                err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
                return fail(lc);
            }
        };
        // SAFETY: the mark set above.
        unsafe { ERR_pop_to_mark() };
        let algctx = chosen.signature.get().newctx(props.as_deref());
        {
            let mut s = lc.lock();
            s.signature = Some(chosen.signature.clone());
            s.operation = wanted;
            s.sigctx = Ptr(algctx);
        }
        if algctx.is_null() {
            err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
            return fail(lc);
        }
        chosen_km = chosen.keymgmt;
        provkey = Some(chosen.keydata);
    }
    // `reinitialize`:
    if !pctx.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { pctx.write(locpctx) };
    }
    // SAFETY: the context, still live.
    let Some(c) = (unsafe { md_ctx::context(ctx) }) else {
        return 0;
    };
    if !type_.is_null() {
        c.reqdigest = type_;
        if mdname.is_none() {
            // SAFETY: the caller's live digest.
            mdname = canon_mdname(unsafe { md_name(type_) });
        }
    } else {
        if mdname.is_none() && !reinit {
            let mut buf = [0 as c_char; 80];
            if let (Some(km), Some(kd)) = (&chosen_km, &provkey) {
                // SAFETY: the key manager's data; the local buffer.
                if unsafe {
                    super::pkey::default_digest_name(
                        km.get(),
                        kd.ptr(),
                        buf.as_mut_ptr(),
                        buf.len(),
                    )
                } > 0
                {
                    // SAFETY: a NUL-terminated name.
                    mdname = canon_mdname(Some(unsafe { CStr::from_ptr(buf.as_ptr()) }.to_owned()));
                }
            }
        }
        if let Some(name) = &mdname {
            // SAFETY: the context's own fields.
            unsafe { md_ctx::clear_digest(c, true, false) };
            // SAFETY: no preconditions.
            unsafe { ERR_set_mark() };
            // SAFETY: the key context's library context; the name and query.
            let fetched = unsafe {
                EVP_MD_fetch(
                    ctx_libctx,
                    name.as_ptr(),
                    props.as_deref().map_or(ptr::null(), CStr::as_ptr),
                )
            };
            c.fetched_digest = fetched;
            if fetched.is_null() {
                // SAFETY: the name.
                let md = unsafe { EVP_get_digestbyname(name.as_ptr()) };
                c.reqdigest = md;
                c.digest = md;
                if md.is_null() {
                    // SAFETY: the mark set above.
                    unsafe { ERR_clear_last_mark() };
                    err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
                    return fail(lc);
                }
            } else {
                c.digest = fetched;
                c.reqdigest = fetched;
            }
            // SAFETY: the mark set above.
            unsafe { ERR_pop_to_mark() };
        }
    }
    let (sig, algctx) = {
        let s = lc.lock();
        (s.signature.clone(), s.sigctx.0)
    };
    let Some(sig) = sig else { return fail(lc) };
    let m = sig.get();
    let key = provkey.as_ref().map_or(ptr::null_mut(), |k| k.ptr());
    let md = mdname.as_deref().map_or(ptr::null(), CStr::as_ptr);
    let (init, what) = if ver {
        (m.funcs.digest_verify_init, "digest_verify_init")
    } else {
        (m.funcs.digest_sign_init, "digest_sign_init")
    };
    let Some(init) = init else {
        m.raise(EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED, F, what);
        return fail(lc);
    };
    // SAFETY: the provider's function with its context, the digest's name, the key data, and
    // the caller's array.
    let ret = unsafe { init(algctx, md, key, params) };
    if ret > 0 || mdname.is_some() {
        // `end`: the distinguishing ID kept for the operation goes to it.
        let ret = if ret > 0 {
            // SAFETY: the context's live key context.
            unsafe { super::ctrl::use_cached_data(locpctx) }
        } else {
            ret
        };
        return c_int::from(ret > 0);
    }
    if type_.is_null() {
        err::raise(ERR_LIB_EVP, EVP_R_NO_DEFAULT_DIGEST, F);
    }
    m.raise(EVP_R_PROVIDER_SIGNATURE_FAILURE, F, what);
    fail(lc)
}

/// `do_sigver_init`'s `err`: ends the key context's operation.
fn fail(lc: &pkey_ctx::PkeyCtx) -> c_int {
    let mut s = lc.lock();
    s.free_old_ops();
    s.operation = EVP_PKEY_OP_UNDEFINED;
    0
}

ffi_export! {
    /// Sets `ctx` up to sign with `pkey` and the digest named `mdname` (the key's default for
    /// NULL), fetched from `libctx` with `props`; the key context into `*pctx` unless NULL.
    ///
    /// # Safety
    /// `ctx` is a live digest context; `pctx` is NULL or room for a pointer; `mdname` and
    /// `props` are NULL or strings; `libctx` is NULL or a live library context; `pkey` is NULL
    /// or a live key; `params` is NULL or an array.
    pub unsafe extern "C" fn EVP_DigestSignInit_ex(ctx: *mut EVP_MD_CTX, pctx: *mut *mut EVP_PKEY_CTX, mdname: *const c_char, libctx: *mut OSSL_LIB_CTX, props: *const c_char, pkey: *mut EVP_PKEY, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { do_sigver_init(ctx, pctx, ptr::null(), mdname, libctx, props, ptr::null_mut(), pkey, false, params) }
    }
}

ffi_export! {
    /// Sets `ctx` up to sign with `pkey` and the digest `type_` (the key's default for NULL).
    ///
    /// # Safety
    /// `ctx` is a live digest context; `pctx` is NULL or room for a pointer; `type_` is NULL or
    /// a live digest; `e` must be NULL (there are no engines); `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_DigestSignInit(ctx: *mut EVP_MD_CTX, pctx: *mut *mut EVP_PKEY_CTX, type_: *const EVP_MD, e: *mut ENGINE, pkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { do_sigver_init(ctx, pctx, type_, ptr::null(), ptr::null_mut(), ptr::null(), e, pkey, false, ptr::null()) }
    }
}

ffi_export! {
    /// As `EVP_DigestSignInit_ex`, to verify.
    ///
    /// # Safety
    /// As for `EVP_DigestSignInit_ex`.
    pub unsafe extern "C" fn EVP_DigestVerifyInit_ex(ctx: *mut EVP_MD_CTX, pctx: *mut *mut EVP_PKEY_CTX, mdname: *const c_char, libctx: *mut OSSL_LIB_CTX, props: *const c_char, pkey: *mut EVP_PKEY, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { do_sigver_init(ctx, pctx, ptr::null(), mdname, libctx, props, ptr::null_mut(), pkey, true, params) }
    }
}

ffi_export! {
    /// As `EVP_DigestSignInit`, to verify.
    ///
    /// # Safety
    /// As for `EVP_DigestSignInit`.
    pub unsafe extern "C" fn EVP_DigestVerifyInit(ctx: *mut EVP_MD_CTX, pctx: *mut *mut EVP_PKEY_CTX, type_: *const EVP_MD, e: *mut ENGINE, pkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { do_sigver_init(ctx, pctx, type_, ptr::null(), ptr::null_mut(), ptr::null(), e, pkey, true, ptr::null()) }
    }
}

/// The digest context's signing (or verifying) operation, if it has one with a provider side.
///
/// # Safety
/// `c`'s key context is NULL or live.
unsafe fn provided(c: &MdCtx, operation: c_int) -> Option<(signature::Ref, *mut c_void)> {
    // SAFETY: the caller's guarantee.
    let lc = unsafe { pkey_ctx::context(c.pctx) }?;
    let s = lc.lock();
    if s.operation != operation || s.sigctx.0.is_null() {
        return None;
    }
    Some((s.signature.clone()?, s.sigctx.0))
}

/// Runs an update or final of the algorithm, raising `EVP_R_PROVIDER_SIGNATURE_FAILURE` if it
/// fails without an error of its own.
fn guarded(
    sig: &signature::Signature,
    function: &str,
    what: &str,
    failed: impl Fn(c_int) -> bool,
    f: impl FnOnce() -> c_int,
) -> c_int {
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    let ret = f();
    // SAFETY: the mark set above.
    if failed(ret) && unsafe { ERR_count_to_mark() } == 0 {
        sig.raise(EVP_R_PROVIDER_SIGNATURE_FAILURE, function, what);
    }
    // SAFETY: as above.
    unsafe { ERR_clear_last_mark() };
    ret
}

/// `EVP_DigestSignUpdate` and `EVP_DigestVerifyUpdate`.
///
/// # Safety
/// `ctx` is a live digest context; `data` holds `dsize` octets.
unsafe fn sigver_update(
    ctx: *mut EVP_MD_CTX,
    data: *const c_void,
    dsize: usize,
    ver: bool,
) -> c_int {
    let function = if ver {
        "EVP_DigestVerifyUpdate"
    } else {
        "EVP_DigestSignUpdate"
    };
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { md_ctx::context(ctx) }) else {
        return 0;
    };
    if c.flags & FLAG_FINALISED != 0 {
        err::raise(ERR_LIB_EVP, EVP_R_UPDATE_ERROR, function);
        return 0;
    }
    let op = if ver {
        EVP_PKEY_OP_VERIFYCTX
    } else {
        EVP_PKEY_OP_SIGNCTX
    };
    // SAFETY: the context's key context, NULL or live.
    let Some((sig, algctx)) = (unsafe { provided(c, op) }) else {
        // `legacy`: an ordinary digest update.
        // SAFETY: the caller's guarantee.
        return unsafe { md_ctx::EVP_DigestUpdate(ctx, data, dsize) };
    };
    let m = sig.get();
    let (f, what) = if ver {
        (m.funcs.digest_verify_update, "digest_verify_update")
    } else {
        (m.funcs.digest_sign_update, "digest_sign_update")
    };
    let Some(f) = f else {
        m.raise(EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED, function, what);
        return 0;
    };
    // SAFETY: the provider's function with its context and the caller's data.
    guarded(
        m,
        function,
        what,
        |r| r <= 0,
        || unsafe { f(algctx, data.cast(), dsize) },
    )
}

ffi_export! {
    /// Adds `dsize` octets at `data` to what `ctx` signs.
    ///
    /// # Safety
    /// `ctx` is a live digest context; `data` holds `dsize` octets.
    pub unsafe extern "C" fn EVP_DigestSignUpdate(ctx: *mut EVP_MD_CTX, data: *const c_void, dsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { sigver_update(ctx, data, dsize, false) }
    }
}

ffi_export! {
    /// Adds `dsize` octets at `data` to what `ctx` verifies.
    ///
    /// # Safety
    /// `ctx` is a live digest context; `data` holds `dsize` octets.
    pub unsafe extern "C" fn EVP_DigestVerifyUpdate(ctx: *mut EVP_MD_CTX, data: *const c_void, dsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { sigver_update(ctx, data, dsize, true) }
    }
}

/// The algorithm context of a copy of the key context, for a final that leaves `ctx` able to
/// go on: the copy (to free) and its context, or `None` if it can't be copied.
///
/// # Safety
/// `pctx` is a live key context.
unsafe fn dup_for_final(pctx: *mut EVP_PKEY_CTX) -> Option<(*mut EVP_PKEY_CTX, *mut c_void)> {
    // SAFETY: the caller's guarantee.
    let d = unsafe { EVP_PKEY_CTX_dup(pctx) };
    // SAFETY: the copy, or NULL.
    let lc = unsafe { pkey_ctx::context(d) }?;
    let algctx = lc.lock().sigctx.0;
    Some((d, algctx))
}

ffi_export! {
    /// Signs what `ctx` was given into `sigret` (its room in `*siglen`, the length back); with
    /// a NULL `sigret`, the size a signature needs. 1, or 0 with an error.
    ///
    /// # Safety
    /// `ctx` is a live digest context; `sigret` is NULL or has room for `*siglen` octets;
    /// `siglen` is room for a size.
    pub unsafe extern "C" fn EVP_DigestSignFinal(ctx: *mut EVP_MD_CTX, sigret: *mut u8, siglen: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "EVP_DigestSignFinal";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { md_ctx::context(ctx) }) else { return 0 };
        if c.flags & FLAG_FINALISED != 0 {
            err::raise(ERR_LIB_EVP, EVP_R_FINAL_ERROR, F);
            return 0;
        }
        // SAFETY: the context's key context, NULL or live.
        let Some((sig, mut algctx)) = (unsafe { provided(c, EVP_PKEY_OP_SIGNCTX) }) else {
            // `legacy`: without an EVP_PKEY_METHOD (none can exist before 4.2d).
            err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
            return 0;
        };
        let m = sig.get();
        let Some(f) = m.funcs.digest_sign_final else {
            m.raise(EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED, F, "digest_sign_final");
            return 0;
        };
        let mut dctx = ptr::null_mut();
        if !sigret.is_null() && c.flags & FINALISE == 0 {
            // SAFETY: the context's live key context.
            if let Some((d, a)) = unsafe { dup_for_final(c.pctx) } {
                dctx = d;
                algctx = a;
            }
        }
        // SAFETY: the caller's guarantee.
        let size = if sigret.is_null() { 0 } else { unsafe { siglen.read() } };
        // SAFETY: the provider's function with its context and the caller's buffers.
        let r = guarded(m, F, "digest_sign_final", |r| r == 0, || unsafe { f(algctx, sigret, siglen, size) });
        if dctx.is_null() && !sigret.is_null() {
            // SAFETY: as above.
            if let Some(c) = unsafe { md_ctx::context(ctx) } {
                c.flags |= FLAG_FINALISED;
            }
        } else {
            // SAFETY: the copy made above, or NULL.
            unsafe { EVP_PKEY_CTX_free(dctx) };
        }
        r
    }
}

ffi_export! {
    /// Signs the `tbslen` octets at `tbs` into `sigret`, as `EVP_DigestSignUpdate` then
    /// `EVP_DigestSignFinal` (or the algorithm's one-shot signing).
    ///
    /// # Safety
    /// `ctx` is a live digest context; `sigret` is NULL or has room for `*siglen` octets;
    /// `siglen` is room for a size; `tbs` holds `tbslen` octets.
    pub unsafe extern "C" fn EVP_DigestSign(ctx: *mut EVP_MD_CTX, sigret: *mut u8, siglen: *mut usize, tbs: *const u8, tbslen: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "EVP_DigestSign";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { md_ctx::context(ctx) }) else { return 0 };
        if c.pctx.is_null() {
            err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
            return 0;
        }
        if c.flags & FLAG_FINALISED != 0 {
            err::raise(ERR_LIB_EVP, EVP_R_FINAL_ERROR, F);
            return 0;
        }
        // SAFETY: the context's live key context.
        if let Some((sig, algctx)) = unsafe { provided(c, EVP_PKEY_OP_SIGNCTX) }
            && let Some(f) = sig.get().funcs.digest_sign
        {
            if !sigret.is_null() {
                c.flags |= FLAG_FINALISED;
            }
            // SAFETY: the caller's guarantee.
            let size = if sigret.is_null() { 0 } else { unsafe { siglen.read() } };
            // SAFETY: the provider's function with its context and the caller's buffers.
            return guarded(sig.get(), F, "digest_sign", |r| r <= 0, || unsafe { f(algctx, sigret, siglen, size, tbs, tbslen) });
        }
        // SAFETY: the caller's guarantee.
        if !sigret.is_null() && unsafe { EVP_DigestSignUpdate(ctx, tbs.cast(), tbslen) } <= 0 {
            return 0;
        }
        // SAFETY: as above.
        unsafe { EVP_DigestSignFinal(ctx, sigret, siglen) }
    }
}

ffi_export! {
    /// Verifies the `siglen` octets at `sig` against what `ctx` was given: 1 if valid, 0 if not,
    /// < 0 on error.
    ///
    /// # Safety
    /// `ctx` is a live digest context; `sig` holds `siglen` octets.
    pub unsafe extern "C" fn EVP_DigestVerifyFinal(ctx: *mut EVP_MD_CTX, sig: *const u8, siglen: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "EVP_DigestVerifyFinal";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { md_ctx::context(ctx) }) else { return 0 };
        if c.flags & FLAG_FINALISED != 0 {
            err::raise(ERR_LIB_EVP, EVP_R_FINAL_ERROR, F);
            return 0;
        }
        // SAFETY: the context's key context, NULL or live.
        let Some((s, mut algctx)) = (unsafe { provided(c, EVP_PKEY_OP_VERIFYCTX) }) else {
            // `legacy`: without an EVP_PKEY_METHOD (none can exist before 4.2d).
            err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
            return 0;
        };
        let m = s.get();
        let Some(f) = m.funcs.digest_verify_final else {
            m.raise(EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED, F, "digest_verify_final");
            return 0;
        };
        let mut dctx = ptr::null_mut();
        if c.flags & FINALISE == 0 {
            // SAFETY: the context's live key context.
            if let Some((d, a)) = unsafe { dup_for_final(c.pctx) } {
                dctx = d;
                algctx = a;
            }
        }
        // SAFETY: the provider's function with its context and the caller's signature.
        let r = guarded(m, F, "digest_verify_final", |r| r == 0, || unsafe { f(algctx, sig, siglen) });
        if dctx.is_null() {
            // SAFETY: as above.
            if let Some(c) = unsafe { md_ctx::context(ctx) } {
                c.flags |= FLAG_FINALISED;
            }
        } else {
            // SAFETY: the copy made above.
            unsafe { EVP_PKEY_CTX_free(dctx) };
        }
        r
    }
}

ffi_export! {
    /// Verifies the `siglen` octets at `sigret` over the `tbslen` octets at `tbs`, as
    /// `EVP_DigestVerifyUpdate` then `EVP_DigestVerifyFinal` (or the algorithm's one-shot
    /// verification).
    ///
    /// # Safety
    /// `ctx` is a live digest context; `sigret` holds `siglen` octets; `tbs` holds `tbslen`.
    pub unsafe extern "C" fn EVP_DigestVerify(ctx: *mut EVP_MD_CTX, sigret: *const u8, siglen: usize, tbs: *const u8, tbslen: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "EVP_DigestVerify";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { md_ctx::context(ctx) }) else { return -1 };
        if c.pctx.is_null() {
            err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
            return -1;
        }
        if c.flags & FLAG_FINALISED != 0 {
            err::raise(ERR_LIB_EVP, EVP_R_FINAL_ERROR, F);
            return 0;
        }
        // SAFETY: the context's live key context.
        if let Some((sig, algctx)) = unsafe { provided(c, EVP_PKEY_OP_VERIFYCTX) }
            && let Some(f) = sig.get().funcs.digest_verify
        {
            c.flags |= FLAG_FINALISED;
            // SAFETY: the provider's function with its context and the caller's buffers.
            return guarded(sig.get(), F, "digest_verify", |r| r <= 0, || unsafe { f(algctx, sigret, siglen, tbs, tbslen) });
        }
        // SAFETY: the caller's guarantee.
        if unsafe { EVP_DigestVerifyUpdate(ctx, tbs.cast(), tbslen) } <= 0 {
            return -1;
        }
        // SAFETY: as above.
        unsafe { EVP_DigestVerifyFinal(ctx, sigret, siglen) }
    }
}

/// `EVP_SignFinal_ex`'s and `EVP_VerifyFinal_ex`'s digest: of a copy of `ctx` unless
/// `EVP_MD_CTX_FLAG_FINALISE` is set (or the copy fails). The digest's octets, or `None`.
///
/// # Safety
/// `ctx` is a live digest context.
unsafe fn final_digest(
    ctx: *mut EVP_MD_CTX,
    m: &mut [u8; EVP_MAX_MD_SIZE as usize],
) -> Option<c_uint> {
    let mut m_len: c_uint = 0;
    // SAFETY: the caller's guarantee.
    let flags = unsafe { md_ctx::context(ctx) }.map_or(0, |c| c.flags);
    if flags & FINALISE != 0 {
        // SAFETY: the caller's context; the buffer.
        return (unsafe { EVP_DigestFinal_ex(ctx, m.as_mut_ptr(), &raw mut m_len) } != 0)
            .then_some(m_len);
    }
    // SAFETY: no preconditions.
    let tmp = unsafe { EVP_MD_CTX_new() };
    if tmp.is_null() {
        err::raise(ERR_LIB_EVP, ERR_R_EVP_LIB, "EVP_SignFinal_ex");
        return None;
    }
    // SAFETY: a new context and the caller's.
    let rv = if unsafe { EVP_MD_CTX_copy_ex(tmp, ctx) } != 0 {
        // SAFETY: the copy; the buffer.
        unsafe { EVP_DigestFinal_ex(tmp, m.as_mut_ptr(), &raw mut m_len) }
    } else {
        // SAFETY: the caller's context; the buffer.
        unsafe { EVP_DigestFinal_ex(ctx, m.as_mut_ptr(), &raw mut m_len) }
    };
    // SAFETY: made above.
    unsafe { EVP_MD_CTX_free(tmp) };
    (rv != 0).then_some(m_len)
}

/// The digest `ctx` was set up with (`EVP_MD_CTX_get0_md`).
///
/// # Safety
/// `ctx` is a live digest context.
unsafe fn ctx_md(ctx: *mut EVP_MD_CTX) -> *const EVP_MD {
    // SAFETY: the caller's guarantee.
    unsafe { md_ctx::context(ctx) }.map_or(ptr::null(), |c| c.reqdigest)
}

ffi_export! {
    /// Digests what `ctx` was given and signs it with `pkey` (a key context from `libctx` with
    /// `propq`) into `sigret`, the length into `siglen`. 1, or 0.
    ///
    /// # Safety
    /// `ctx` is a live digest context; `sigret` is NULL or has room for the key's size;
    /// `siglen` is room for an `unsigned int`; `pkey` is NULL or a live key; `libctx` is NULL
    /// or a live library context; `propq` is NULL or a string.
    pub unsafe extern "C" fn EVP_SignFinal_ex(ctx: *mut EVP_MD_CTX, sigret: *mut u8, siglen: *mut c_uint, pkey: *mut EVP_PKEY, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if !siglen.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { siglen.write(0) };
        }
        let mut m = [0u8; EVP_MAX_MD_SIZE as usize];
        // SAFETY: the caller's guarantee.
        let Some(m_len) = (unsafe { final_digest(ctx, &mut m) }) else { return 0 };
        // SAFETY: the caller's key.
        let size = unsafe { super::pkey::EVP_PKEY_get_size(pkey) };
        let mut sltmp = usize::try_from(size).unwrap_or(usize::MAX);
        // SAFETY: the caller's guarantee.
        let pkctx = unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq) };
        let mut i = 0;
        // SAFETY: the caller's context.
        let md = unsafe { ctx_md(ctx) };
        // SAFETY: the context made above (NULL checked first).
        if !pkctx.is_null() && unsafe { EVP_PKEY_sign_init(pkctx) } > 0
            // SAFETY: as above; the digest.
            && unsafe { EVP_PKEY_CTX_set_signature_md(pkctx, md) } > 0
            // SAFETY: as above.
            && unsafe { EVP_PKEY_sign(pkctx, sigret, &raw mut sltmp, m.as_ptr(), m_len as usize) } > 0
        {
            if !siglen.is_null() {
                // SAFETY: the caller's guarantee.
                unsafe { siglen.write(c_uint::try_from(sltmp).unwrap_or(c_uint::MAX)) };
            }
            i = 1;
        }
        // SAFETY: made above, or NULL.
        unsafe { EVP_PKEY_CTX_free(pkctx) };
        i
    }
}

ffi_export! {
    /// `EVP_SignFinal_ex` in the default context.
    ///
    /// # Safety
    /// As for `EVP_SignFinal_ex`.
    pub unsafe extern "C" fn EVP_SignFinal(ctx: *mut EVP_MD_CTX, sigret: *mut u8, siglen: *mut c_uint, pkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_SignFinal_ex(ctx, sigret, siglen, pkey, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Digests what `ctx` was given and verifies the `siglen` octets at `sigbuf` over it with
    /// `pkey`: 1 if valid, 0 if not, -1 on error.
    ///
    /// # Safety
    /// `ctx` is a live digest context; `sigbuf` holds `siglen` octets; `pkey` is NULL or a live
    /// key; `libctx` is NULL or a live library context; `propq` is NULL or a string.
    pub unsafe extern "C" fn EVP_VerifyFinal_ex(ctx: *mut EVP_MD_CTX, sigbuf: *const u8, siglen: c_uint, pkey: *mut EVP_PKEY, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let mut m = [0u8; EVP_MAX_MD_SIZE as usize];
        // SAFETY: the caller's guarantee.
        let Some(m_len) = (unsafe { final_digest(ctx, &mut m) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        let pkctx = unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq) };
        let mut i = -1;
        // SAFETY: the caller's context.
        let md = unsafe { ctx_md(ctx) };
        // SAFETY: the context made above (NULL checked first).
        if !pkctx.is_null() && unsafe { EVP_PKEY_verify_init(pkctx) } > 0
            // SAFETY: as above; the digest.
            && unsafe { EVP_PKEY_CTX_set_signature_md(pkctx, md) } > 0
        {
            // SAFETY: as above; the caller's signature.
            i = unsafe { EVP_PKEY_verify(pkctx, sigbuf, siglen as usize, m.as_ptr(), m_len as usize) };
        }
        // SAFETY: made above, or NULL.
        unsafe { EVP_PKEY_CTX_free(pkctx) };
        i
    }
}

ffi_export! {
    /// `EVP_VerifyFinal_ex` in the default context.
    ///
    /// # Safety
    /// As for `EVP_VerifyFinal_ex`.
    pub unsafe extern "C" fn EVP_VerifyFinal(ctx: *mut EVP_MD_CTX, sigbuf: *const u8, siglen: c_uint, pkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_VerifyFinal_ex(ctx, sigbuf, siglen, pkey, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// The key context the digest context signs or verifies with, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live digest context.
    pub unsafe extern "C" fn EVP_MD_CTX_get_pkey_ctx(ctx: *const EVP_MD_CTX) -> *mut EVP_PKEY_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { md_ctx::context(ctx.cast_mut()) }.map_or(ptr::null_mut(), |c| c.pctx)
    }
}

ffi_export! {
    /// Gives the digest context the key context `pctx`, which the caller keeps (and frees),
    /// freeing the context's own; NULL takes it away.
    ///
    /// # Safety
    /// `ctx` is NULL or a live digest context; `pctx` is NULL or a live key context that
    /// outlives its use here.
    pub unsafe extern "C" fn EVP_MD_CTX_set_pkey_ctx(ctx: *mut EVP_MD_CTX, pctx: *mut EVP_PKEY_CTX)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { md_ctx::context(ctx) }) else { return };
        if c.flags & FLAG_KEEP_PKEY_CTX == 0 {
            // SAFETY: the context's own key context, or NULL.
            unsafe { EVP_PKEY_CTX_free(c.pctx) };
        }
        c.pctx = pctx;
        if pctx.is_null() {
            c.flags &= !FLAG_KEEP_PKEY_CTX;
        } else {
            c.flags |= FLAG_KEEP_PKEY_CTX;
        }
    }
}

ffi_export! {
    /// Whether `pkey` can sign through a digest context with the digest `name` (from `libctx`
    /// with `propq`): 1, or <= 0, raising nothing.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `libctx` is NULL or a live library context; `name` and
    /// `propq` are NULL or strings.
    pub unsafe extern "C" fn EVP_PKEY_digestsign_supports_digest(pkey: *mut EVP_PKEY, libctx: *mut OSSL_LIB_CTX, name: *const c_char, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: no preconditions.
        let ctx = unsafe { EVP_MD_CTX_new() };
        if ctx.is_null() {
            return -1;
        }
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        // SAFETY: the new context and the caller's arguments.
        let rv = unsafe { EVP_DigestSignInit_ex(ctx, ptr::null_mut(), name, libctx, propq, pkey, ptr::null()) };
        // SAFETY: the mark set above.
        unsafe { ERR_pop_to_mark() };
        // SAFETY: made above.
        unsafe { EVP_MD_CTX_free(ctx) };
        rv
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::pkey::EVP_PKEY_free;
    use crate::evp::pkey::raw::EVP_PKEY_new_raw_private_key_ex;
    use crate::libctx::{OSSL_LIB_CTX_free, OSSL_LIB_CTX_new};

    /// docs/DEVIATIONS.md: a NULL digest context or key is refused (the reference crashes).
    #[test]
    fn null_contexts_are_refused() {
        let md: *mut EVP_MD_CTX = ptr::null_mut();
        let mut len = 0usize;
        let sig = [0u8; 4];
        // SAFETY: NULL is the case under test, here and below.
        let got = unsafe { EVP_DigestSignUpdate(md, sig.as_ptr().cast(), 1) };
        assert_eq!(got, 0);
        // SAFETY: as above.
        let got = unsafe { EVP_DigestVerifyUpdate(md, sig.as_ptr().cast(), 1) };
        assert_eq!(got, 0);
        // SAFETY: as above.
        let got = unsafe { EVP_DigestSignFinal(md, ptr::null_mut(), &raw mut len) };
        assert_eq!(got, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_DigestVerifyFinal(md, sig.as_ptr(), 4) }, 0);
        // SAFETY: as above.
        let got = unsafe { EVP_DigestSign(md, ptr::null_mut(), &raw mut len, sig.as_ptr(), 4) };
        assert_eq!(got, 0);
        // SAFETY: as above.
        let got = unsafe { EVP_DigestVerify(md, sig.as_ptr(), 4, sig.as_ptr(), 4) };
        assert_eq!(got, -1);
        // SAFETY: as above.
        let got = unsafe {
            EVP_DigestSignInit(
                md,
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        assert_eq!(got, 0);
        // SAFETY: as above.
        assert!(unsafe { EVP_MD_CTX_get_pkey_ctx(md) }.is_null());
        // SAFETY: as above.
        unsafe { EVP_MD_CTX_set_pkey_ctx(md, ptr::null_mut()) };
        // SAFETY: as above.
        let got = unsafe { crate::evp::pkey::EVP_PKEY_can_sign(ptr::null()) };
        assert_eq!(got, 0);
        crate::err::take_all();
    }

    /// SipHash through a digest context (no digest, so no hash intrinsics under Miri): signed
    /// twice and from a copy, the same each time.
    #[test]
    fn signs_with_siphash() {
        // A context of its own: fetching from it loads no configuration, which Miri can't run.
        // SAFETY: no preconditions.
        let lib = unsafe { OSSL_LIB_CTX_new() };
        let key = [0x42u8; 16];
        // SAFETY: the context; a static name; the octets.
        let k = unsafe {
            EVP_PKEY_new_raw_private_key_ex(lib, c"SIPHASH".as_ptr(), ptr::null(), key.as_ptr(), 16)
        };
        // SAFETY: no preconditions.
        let md = unsafe { EVP_MD_CTX_new() };
        // SAFETY: the digest context, key, and library context.
        let init = unsafe {
            EVP_DigestSignInit_ex(
                md,
                ptr::null_mut(),
                ptr::null(),
                lib,
                ptr::null(),
                k,
                ptr::null(),
            )
        };
        assert_eq!(init, 1);
        // SAFETY: the context; the data.
        let got = unsafe { EVP_DigestSignUpdate(md, b"abc".as_ptr().cast(), 3) };
        assert_eq!(got, 1);
        let mut first = [0u8; 16];
        let mut out = [0u8; 64];
        for i in 0..2 {
            let mut len = out.len();
            // SAFETY: the context; the buffer and its room.
            let got = unsafe { EVP_DigestSignFinal(md, out.as_mut_ptr(), &raw mut len) };
            assert_eq!(got, 1);
            assert_eq!(len, 16);
            if i == 0 {
                first.copy_from_slice(out.get(..16).unwrap_or_default());
            }
            assert_eq!(out.get(..16), Some(&first[..]));
        }
        // SAFETY: no preconditions.
        let copy = unsafe { EVP_MD_CTX_new() };
        // SAFETY: both contexts.
        assert_eq!(unsafe { EVP_MD_CTX_copy_ex(copy, md) }, 1);
        let mut len = out.len();
        // SAFETY: the copy; the buffer and its room.
        let got = unsafe { EVP_DigestSignFinal(copy, out.as_mut_ptr(), &raw mut len) };
        assert_eq!(got, 1);
        assert_eq!(out.get(..len), Some(&first[..]));
        for c in [md, copy] {
            // SAFETY: made above.
            unsafe { EVP_MD_CTX_free(c) };
        }
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(k) };
        // SAFETY: as above, its objects freed.
        unsafe { OSSL_LIB_CTX_free(lib) };
    }

    /// HMAC-SHA256 through a digest context: RFC 4231's first test case, signed twice (the
    /// first final leaves the context usable), and from a copy.
    #[test]
    #[cfg_attr(
        all(miri, target_arch = "aarch64"),
        ignore = "sha2's ARMv8 path breaks Stacked Borrows (docs/DEPENDENCIES.md)"
    )]
    fn signs_with_hmac() {
        const WANT: [u8; 32] = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        // A context of its own: fetching from it loads no configuration, which Miri can't run.
        // SAFETY: no preconditions.
        let lib = unsafe { OSSL_LIB_CTX_new() };
        let key = [0x0bu8; 20];
        // SAFETY: the context; a static name; the octets.
        let k = unsafe {
            EVP_PKEY_new_raw_private_key_ex(lib, c"HMAC".as_ptr(), ptr::null(), key.as_ptr(), 20)
        };
        // SAFETY: no preconditions.
        let md = unsafe { EVP_MD_CTX_new() };
        // SAFETY: the digest context, key, and library context; a static name.
        let init = unsafe {
            EVP_DigestSignInit_ex(
                md,
                ptr::null_mut(),
                c"SHA2-256".as_ptr(),
                lib,
                ptr::null(),
                k,
                ptr::null(),
            )
        };
        assert_eq!(init, 1);
        // SAFETY: the context; the data.
        let got = unsafe { EVP_DigestSignUpdate(md, b"Hi There".as_ptr().cast(), 8) };
        assert_eq!(got, 1);
        let mut out = [0u8; 64];
        for _ in 0..2 {
            let mut len = out.len();
            // SAFETY: the context; the buffer and its room.
            let got = unsafe { EVP_DigestSignFinal(md, out.as_mut_ptr(), &raw mut len) };
            assert_eq!(got, 1);
            assert_eq!(out.get(..len), Some(&WANT[..]));
        }
        // SAFETY: no preconditions.
        let copy = unsafe { EVP_MD_CTX_new() };
        // SAFETY: both contexts.
        assert_eq!(unsafe { EVP_MD_CTX_copy_ex(copy, md) }, 1);
        let mut len = out.len();
        // SAFETY: the copy; the buffer and its room.
        let got = unsafe { EVP_DigestSignFinal(copy, out.as_mut_ptr(), &raw mut len) };
        assert_eq!(got, 1);
        assert_eq!(out.get(..len), Some(&WANT[..]));
        for c in [md, copy] {
            // SAFETY: made above.
            unsafe { EVP_MD_CTX_free(c) };
        }
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(k) };
        // SAFETY: as above, its objects freed.
        unsafe { OSSL_LIB_CTX_free(lib) };
    }
}
