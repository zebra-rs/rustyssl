//! Digest contexts (`EVP_DigestInit(3)`): `EVP_MD_CTX` and digesting through a fetched
//! digest's provider functions, ported from `crypto/evp/digest.c` and the accessors in
//! `evp_lib.c`.
//!
//! The context is OpenSSL's: a zeroed allocation holding the requested digest, the digest in
//! use and the reference the context owns, flags, the provider's algorithm context, and the
//! legacy update function. Its behavior follows the reference's paths, including:
//! - initializing with the same digest again reuses the algorithm context (so an XOF's length
//!   persists), and `EVP_MD_CTX_FLAG_NO_INIT` takes the legacy path, which with a provided
//!   digest frees the algorithm context and returns 1;
//! - `EVP_DigestUpdate` of nothing succeeds whatever the state; after a final, updating and
//!   finalizing again fail with `EVP_R_UPDATE_ERROR` and `EVP_R_FINAL_ERROR`; squeezing doesn't
//!   finalize, so updating after a squeeze reaches the algorithm;
//! - `EVP_DigestFinalXOF` passes its length as `xoflen` and then finalizes whatever the
//!   digest, so a fixed-size digest's own `final` decides;
//! - `EVP_MD_CTX_copy_ex` reuses the destination's algorithm context (`copyctx`) when both
//!   have the same digest.
//!
//! What OpenSSL dereferences without checking (a NULL context in most of these) is refused
//! here instead (docs/DEVIATIONS.md). A static digest (`EVP_sha256()`) is replaced by the
//! provider's, fetched by its short name, as OpenSSL does. A context set up to sign or verify
//! (`EVP_DigestSignInit`, `sigver.rs`) holds its key context, and its init, update, and
//! parameters go to the signature operation. The legacy `EVP_MD_meth_*` digests come with 3.11.

use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};
use core::ptr;

use rustyssl_abi::{
    ENGINE, ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, EVP_CTRL_SSL3_MASTER_SECRET, EVP_MD,
    EVP_MD_CTRL_MICALG, EVP_MD_CTRL_XOF_LEN, EVP_MD_CTX, EVP_MD_CTX_FLAG_CLEANED,
    EVP_MD_CTX_FLAG_NO_INIT, EVP_MD_CTX_FLAG_ONESHOT, EVP_MD_CTX_FLAG_REUSE, EVP_MD_FLAG_XOF,
    EVP_PKEY_CTX, EVP_R_CTRL_NOT_IMPLEMENTED, EVP_R_FINAL_ERROR, EVP_R_INITIALIZATION_ERROR,
    EVP_R_INVALID_NULL_ALGORITHM, EVP_R_METHOD_NOT_SUPPORTED, EVP_R_NO_DIGEST_SET,
    EVP_R_NOT_ABLE_TO_COPY_CTX, EVP_R_NOT_XOF_OR_INVALID_LENGTH, EVP_R_UPDATE_ERROR, NID_undef,
    OSSL_DIGEST_PARAM_MICALG, OSSL_DIGEST_PARAM_SIZE, OSSL_DIGEST_PARAM_SSL3_MS,
    OSSL_DIGEST_PARAM_XOFLEN, OSSL_LIB_CTX, OSSL_PARAM,
};

use super::digest::{
    EVP_MD_fetch, EVP_MD_free, EVP_MD_get_flags, EVP_MD_get_size, EVP_MD_up_ref, Md, Origin, method,
};
use super::pkey_ctx::{EVP_PKEY_CTX_dup, EVP_PKEY_CTX_free};
use crate::err;
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects::OBJ_nid2sn;
use crate::params::{OSSL_PARAM_locate_const, construct, end};

/// `EVP_MD_CTX_FLAG_KEEP_PKEY_CTX`, from the reference's internal `include/crypto/evp.h`.
pub(crate) const FLAG_KEEP_PKEY_CTX: c_ulong = 0x0400;
/// `EVP_MD_CTX_FLAG_FINALISED`, from the same header: set by a final, cleared by an init.
pub(crate) const FLAG_FINALISED: c_ulong = 0x0800;

/// A legacy update function (`EVP_MD_CTX_set_update_fn`).
type LegacyUpdateFn = unsafe extern "C" fn(*mut EVP_MD_CTX, *const c_void, usize) -> c_int;

/// What an `EVP_MD_CTX *` points to (`struct evp_md_ctx_st`): every field is valid zeroed.
#[repr(C)]
pub(crate) struct MdCtx {
    /// The digest the caller asked for (`EVP_MD_CTX_get0_md`).
    pub(crate) reqdigest: *const EVP_MD,
    /// The digest in use.
    pub(crate) digest: *const EVP_MD,
    /// The context's reference to the digest in use.
    pub(crate) fetched_digest: *mut EVP_MD,
    pub(crate) flags: c_ulong,
    /// The legacy digests' state; always NULL for provided digests.
    md_data: *mut c_void,
    /// The key context of a signing or verifying operation: the context's own unless
    /// `FLAG_KEEP_PKEY_CTX` says the application keeps it.
    pub(crate) pctx: *mut EVP_PKEY_CTX,
    pub(crate) update: Option<LegacyUpdateFn>,
    /// The provider's algorithm context.
    algctx: *mut c_void,
    /// The engine the digest in use came from, with a functional reference, or NULL.
    engine: *mut ENGINE,
}

/// The context behind `ctx`, or `None` for NULL.
///
/// # Safety
/// `ctx` is NULL or a live context from `EVP_MD_CTX_new`, not used elsewhere meanwhile.
pub(crate) unsafe fn context<'a>(ctx: *mut EVP_MD_CTX) -> Option<&'a mut MdCtx> {
    // SAFETY: the caller's guarantee: an allocation of an `MdCtx`, any bit pattern of which
    // is valid.
    unsafe { ctx.cast::<MdCtx>().as_mut() }
}

/// The digest method in use, if any.
///
/// # Safety
/// The context's digest is NULL or a live method (the context holds a reference).
unsafe fn digest_of<'a>(c: &MdCtx) -> Option<&'a Md> {
    // SAFETY: the caller's guarantee.
    unsafe { method(c.digest) }
}

/// `evp_md_ctx_free_algctx`: frees the algorithm context. False (with an error) if there's one
/// but no digest.
///
/// # Safety
/// The context's fields are its own.
pub(crate) unsafe fn free_algctx(c: &mut MdCtx) -> bool {
    if !c.algctx.is_null() {
        // SAFETY: the caller's guarantee.
        let Some(md) = (unsafe { digest_of(c) }) else {
            err::raise(
                ERR_LIB_EVP,
                EVP_R_INITIALIZATION_ERROR,
                "evp_md_ctx_free_algctx",
            );
            return false;
        };
        if let Some(free) = md.funcs.freectx {
            // SAFETY: the context's algorithm context, freed once.
            unsafe { free(c.algctx) };
        }
        c.algctx = ptr::null_mut();
    }
    true
}

/// `cleanup_old_md_data`: a legacy digest's `cleanup` (unless the context is already
/// cleaned), then its state freed (unless the context is to reuse it, or `force`).
///
/// The `cleanup` is the application's (or a static digest's), which may use the context: no
/// borrow of it is held across the call.
///
/// # Safety
/// `ctx` is NULL or a live digest context whose digest is NULL or live.
pub(crate) unsafe fn cleanup_old_md_data(ctx: *mut EVP_MD_CTX, force: bool) {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { context(ctx) }) else {
        return;
    };
    // SAFETY: as above.
    let Some(md) = (unsafe { digest_of(c) }) else {
        return;
    };
    let legacy = md.legacy_fns();
    if let Some(cleanup) = legacy.cleanup
        && c.flags & flag(EVP_MD_CTX_FLAG_CLEANED) == 0
    {
        // SAFETY: the digest's function with the caller's context.
        unsafe { cleanup(ctx) };
    }
    // SAFETY: as above (the call may have used the context).
    let Some(c) = (unsafe { context(ctx) }) else {
        return;
    };
    let size = usize::try_from(legacy.ctx_size).unwrap_or(0);
    if !c.md_data.is_null() && size > 0 && (c.flags & flag(EVP_MD_CTX_FLAG_REUSE) == 0 || force) {
        // SAFETY: the state this context allocated, of the digest's size.
        unsafe { mem::release_clean(c.md_data, size) };
        c.md_data = ptr::null_mut();
    }
}

/// `evp_md_ctx_clear_digest`.
///
/// # Safety
/// `ctx` is NULL or a live digest context whose fields are its own.
pub(crate) unsafe fn clear_digest(ctx: *mut EVP_MD_CTX, force: bool, keep_fetched: bool) {
    // SAFETY: the caller's guarantee.
    if let Some(c) = unsafe { context(ctx) }
        && !c.algctx.is_null()
    {
        // SAFETY: the caller's guarantee.
        if let Some(free) = unsafe { digest_of(c) }.and_then(|m| m.funcs.freectx) {
            // SAFETY: the context's algorithm context, freed once.
            unsafe { free(c.algctx) };
        }
        c.algctx = ptr::null_mut();
        c.flags |= flag(EVP_MD_CTX_FLAG_CLEANED);
    }
    // SAFETY: the caller's guarantee.
    unsafe { cleanup_old_md_data(ctx, force) };
    // SAFETY: as above.
    let Some(c) = (unsafe { context(ctx) }) else {
        return;
    };
    if force {
        c.digest = ptr::null();
    }
    let engine = core::mem::replace(&mut c.engine, ptr::null_mut());
    // SAFETY: the context's functional reference, or NULL; the engine's `finish` may run.
    unsafe { crate::engine::ENGINE_finish(engine) };
    // SAFETY: as above.
    let Some(c) = (unsafe { context(ctx) }) else {
        return;
    };
    if !keep_fetched {
        // SAFETY: the context's own reference.
        unsafe { EVP_MD_free(c.fetched_digest) };
        c.fetched_digest = ptr::null_mut();
        c.reqdigest = ptr::null();
    }
}

/// `evp_md_ctx_reset_ex`: frees what the context holds and, unless the digest is kept, clears
/// it whole.
///
/// # Safety
/// `ctx` is NULL or a live digest context whose fields are its own.
unsafe fn reset_ex(ctx: *mut EVP_MD_CTX, keep_fetched: bool) {
    // SAFETY: the caller's guarantee.
    if let Some(c) = unsafe { context(ctx) }
        && c.flags & FLAG_KEEP_PKEY_CTX == 0
    {
        // SAFETY: the context's own key context, or NULL.
        unsafe { EVP_PKEY_CTX_free(c.pctx) };
        c.pctx = ptr::null_mut();
    }
    // SAFETY: the caller's guarantee.
    unsafe { clear_digest(ctx, false, keep_fetched) };
    if !keep_fetched {
        // SAFETY: as above.
        if let Some(c) = unsafe { context(ctx) } {
            *c = MdCtx::zeroed();
        }
    }
}

impl MdCtx {
    /// An empty context (all fields zero, as `OPENSSL_cleanse` leaves it).
    fn zeroed() -> Self {
        Self {
            reqdigest: ptr::null(),
            digest: ptr::null(),
            fetched_digest: ptr::null_mut(),
            flags: 0,
            md_data: ptr::null_mut(),
            pctx: ptr::null_mut(),
            update: None,
            algctx: ptr::null_mut(),
            engine: ptr::null_mut(),
        }
    }
}

/// An `EVP_MD_CTX_FLAG_*` as the flags' type.
fn flag(f: c_int) -> c_ulong {
    c_ulong::try_from(f).unwrap_or(0)
}

ffi_export! {
    /// A new, empty digest context.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        mem::alloc_zeroed(size_of::<MdCtx>()).cast()
    }
}

ffi_export! {
    /// Frees what the context holds and empties it. Returns 1 (NULL too).
    ///
    /// # Safety
    /// `ctx` is NULL or a live digest context.
    pub unsafe extern "C" fn EVP_MD_CTX_reset(ctx: *mut EVP_MD_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { reset_ex(ctx, false) };
        1
    }
}

ffi_export! {
    /// Resets and frees the context; NULL does nothing.
    ///
    /// # Safety
    /// `ctx` is NULL or a live digest context, not used afterwards.
    pub unsafe extern "C" fn EVP_MD_CTX_free(ctx: *mut EVP_MD_CTX)
    where failure = (), library = ERR_LIB_EVP
    {
        if ctx.is_null() {
            return;
        }
        // SAFETY: the caller's guarantee.
        unsafe { EVP_MD_CTX_reset(ctx) };
        // SAFETY: an allocation from `EVP_MD_CTX_new`.
        unsafe { mem::release(ctx.cast()) };
    }
}

/// `evp_md_init_internal`.
///
/// # Safety
/// `ctx` is a live digest context; `type_` is NULL or a live digest method; `params` is NULL
/// or a parameter array.
unsafe fn init_internal(
    ctx: *mut EVP_MD_CTX,
    type_: *const EVP_MD,
    params: *const OSSL_PARAM,
    engine: *mut ENGINE,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { context(ctx) }) else {
        err::raise(
            ERR_LIB_EVP,
            ERR_R_PASSED_NULL_PARAMETER,
            "evp_md_init_internal",
        );
        return 0;
    };
    // A context set up to sign or verify starts that again (as before OpenSSL 3).
    // SAFETY: the context's key context, or NULL.
    if let Some(op) = unsafe { super::sigver::sig_operation(c.pctx) } {
        return match op {
            // SAFETY: the caller's context and digest; no key (the context's is kept).
            Some(false) => unsafe {
                super::sigver::EVP_DigestSignInit(
                    ctx,
                    ptr::null_mut(),
                    type_,
                    engine,
                    ptr::null_mut(),
                )
            },
            // SAFETY: as above.
            Some(true) => unsafe {
                super::sigver::EVP_DigestVerifyInit(
                    ctx,
                    ptr::null_mut(),
                    type_,
                    engine,
                    ptr::null_mut(),
                )
            },
            None => {
                err::raise(ERR_LIB_EVP, EVP_R_UPDATE_ERROR, "evp_md_init_internal");
                0
            }
        };
    }
    c.flags &= !(flag(EVP_MD_CTX_FLAG_CLEANED) | FLAG_FINALISED);
    let type_ = if type_.is_null() {
        if c.digest.is_null() {
            err::raise(ERR_LIB_EVP, EVP_R_NO_DIGEST_SET, "evp_md_init_internal");
            return 0;
        }
        c.digest
    } else {
        c.reqdigest = type_;
        type_
    };
    // SAFETY: the caller's live method.
    let nid = unsafe { method(type_) }.map_or(NID_undef, |m| m.nid);
    // An init after a final keeps the engine's digest when it's for the same algorithm.
    // SAFETY: the context's digest, or NULL.
    if !c.engine.is_null() && unsafe { digest_of(c) }.is_some_and(|m| m.nid == nid) {
        let current = c.digest;
        // SAFETY: the caller's guarantee; the context's own digest.
        return unsafe { init_legacy(ctx, current) };
    }
    // An engine left from before is let go.
    let old = core::mem::replace(&mut c.engine, ptr::null_mut());
    // SAFETY: the context's functional reference, or NULL; the engine's `finish` may run.
    unsafe { crate::engine::ENGINE_finish(old) };
    let reserved = if engine.is_null() {
        // SAFETY: no preconditions; a functional reference, or NULL.
        unsafe { crate::engine::table::ENGINE_get_digest_engine(nid) }
    } else {
        ptr::null_mut()
    };
    // SAFETY: as above (the engine's `finish` may have used the context).
    let Some(c) = (unsafe { context(ctx) }) else {
        return 0;
    };
    // SAFETY: the caller's live method.
    let application = unsafe { method(type_) }.is_some_and(|m| m.origin == Origin::Meth);
    if !engine.is_null()
        || !reserved.is_null()
        || c.flags & flag(EVP_MD_CTX_FLAG_NO_INIT) != 0
        || application
    {
        // The legacy path: a provided digest drops its algorithm context; the digest's C
        // functions do the work, on state of its size.
        // SAFETY: the context's own fields.
        if !unsafe { free_algctx(c) } {
            // SAFETY: the reference taken above, or NULL.
            unsafe { crate::engine::ENGINE_finish(reserved) };
            return 0;
        }
        if c.digest == c.fetched_digest.cast_const() {
            c.digest = ptr::null();
        }
        // SAFETY: the context's own reference.
        unsafe { EVP_MD_free(c.fetched_digest) };
        c.fetched_digest = ptr::null_mut();
        // SAFETY: the caller's guarantee; `reserved` is NULL or a functional reference.
        let Some(type_) = (unsafe { engine_digest(ctx, type_, nid, engine, reserved) }) else {
            return 0;
        };
        // SAFETY: the caller's guarantee.
        unsafe { init_legacy(ctx, type_) }
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { init_provided(ctx, type_, params) }
    }
}

/// The engine part of `evp_md_init_internal`'s legacy path: with `engine` (initialized here)
/// or the one reserved for the digest's NID, the engine's own digest, the engine's functional
/// reference kept by the context; else `type_`. `None` (with `EVP_R_INITIALIZATION_ERROR`)
/// when the engine doesn't initialize or has no digest for the NID.
///
/// # Safety
/// `ctx` is a live digest context; `type_` is a live digest method; `engine` is NULL or a live
/// engine; `reserved` is NULL or a functional reference the context takes over (NULL when
/// `engine` isn't).
unsafe fn engine_digest(
    ctx: *mut EVP_MD_CTX,
    type_: *const EVP_MD,
    nid: c_int,
    engine: *mut ENGINE,
    reserved: *mut ENGINE,
) -> Option<*const EVP_MD> {
    const F: &str = "evp_md_init_internal";
    let chosen = if engine.is_null() {
        reserved
    } else {
        // SAFETY: the caller's live engine; its `init` may run (no lock is held).
        if unsafe { crate::engine::ENGINE_init(engine) } == 0 {
            err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
            return None;
        }
        engine
    };
    if chosen.is_null() {
        return Some(type_);
    }
    // SAFETY: an initialized engine; its digest callback may run.
    let d = unsafe { crate::engine::table::ENGINE_get_digest(chosen, nid) };
    if d.is_null() {
        err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
        // SAFETY: the functional reference taken above.
        unsafe { crate::engine::ENGINE_finish(chosen) };
        return None;
    }
    // SAFETY: the caller's guarantee (the callbacks may have used the context).
    let c = unsafe { context(ctx) }?;
    c.engine = chosen;
    Some(d)
}

/// The legacy part of `evp_md_init_internal`: the digest's state (when it changes), the key
/// context told, and the digest's `init`.
///
/// # Safety
/// `ctx` is a live digest context; `type_` is a live digest method.
unsafe fn init_legacy(ctx: *mut EVP_MD_CTX, type_: *const EVP_MD) -> c_int {
    const F: &str = "evp_md_init_internal";
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { context(ctx) }) else {
        return 0;
    };
    if c.digest != type_ {
        // SAFETY: the context's own fields.
        unsafe { cleanup_old_md_data(ctx, true) };
        // SAFETY: as above.
        let Some(c) = (unsafe { context(ctx) }) else {
            return 0;
        };
        c.digest = type_;
        // The reference keeps no reference to the digest here; the context keeps one (none
        // is counted for a static or application's digest), so a fetched digest it points to
        // can't be freed under it.
        // SAFETY: the caller's live method.
        if unsafe { EVP_MD_up_ref(type_.cast_mut()) } != 0 {
            c.fetched_digest = type_.cast_mut();
        }
        // SAFETY: the caller's live method.
        let legacy = unsafe { method(type_) }
            .map(Md::legacy_fns)
            .unwrap_or_default();
        let size = usize::try_from(legacy.ctx_size).unwrap_or(0);
        if c.flags & flag(EVP_MD_CTX_FLAG_NO_INIT) == 0 && size > 0 {
            c.update = legacy.update;
            c.md_data = mem::alloc_zeroed(size);
            if c.md_data.is_null() {
                return 0;
            }
        }
    }
    // SAFETY: as above.
    let Some(c) = (unsafe { context(ctx) }) else {
        return 0;
    };
    // The key context of a legacy context is told of the init (`EVP_PKEY_CTRL_DIGESTINIT`).
    // SAFETY: the context's key context, or NULL.
    if !unsafe { super::sigver::digest_init_ctrl(c.pctx, ctx) } {
        return 0;
    }
    if c.flags & flag(EVP_MD_CTX_FLAG_NO_INIT) != 0 {
        return 1;
    }
    // SAFETY: the context's digest.
    let Some(init) = unsafe { digest_of(c) }.and_then(|m| m.legacy_fns().init) else {
        // OpenSSL calls the missing function and crashes.
        err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
        return 0;
    };
    // SAFETY: the digest's function with the caller's context.
    unsafe { init(ctx) }
}

/// The provided part of `evp_md_init_internal`: the digest's old state cleaned up, the
/// provider's digest (fetched for a static one), its algorithm context, and its `init`.
///
/// # Safety
/// `ctx` is a live digest context; `type_` is a live digest method; `params` is NULL or a
/// parameter array.
unsafe fn init_provided(
    ctx: *mut EVP_MD_CTX,
    type_: *const EVP_MD,
    params: *const OSSL_PARAM,
) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { cleanup_old_md_data(ctx, true) };
    // SAFETY: as above.
    let Some(c) = (unsafe { context(ctx) }) else {
        return 0;
    };
    if c.digest != type_ {
        // SAFETY: the context's own fields.
        if !unsafe { free_algctx(c) } {
            return 0;
        }
    }
    // SAFETY: the caller's guarantee.
    let Some(requested) = (unsafe { method(type_) }) else {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_INITIALIZATION_ERROR,
            "evp_md_init_internal",
        );
        return 0;
    };
    let mut type_ = type_;
    if requested.prov.0.is_null() {
        // A static digest: fetch the provider's by its short name ("NULL" for the NULL
        // digest), from the default context with no query.
        let nid = requested.nid;
        // SAFETY: no preconditions.
        let short = unsafe { OBJ_nid2sn(nid) };
        let name = if nid == NID_undef {
            c"NULL".as_ptr()
        } else {
            short
        };
        // SAFETY: the default context, a static name, and an empty query.
        let provmd = unsafe { EVP_MD_fetch(ptr::null_mut(), name, c"".as_ptr()) };
        if provmd.is_null() {
            err::raise(
                ERR_LIB_EVP,
                EVP_R_INITIALIZATION_ERROR,
                "evp_md_init_internal",
            );
            return 0;
        }
        // SAFETY: the context's own reference, replaced by the fetched one.
        unsafe { EVP_MD_free(c.fetched_digest) };
        c.fetched_digest = provmd;
        type_ = provmd;
    }
    // SAFETY: a live method.
    let Some(md) = (unsafe { method(type_) }) else {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_INITIALIZATION_ERROR,
            "evp_md_init_internal",
        );
        return 0;
    };
    if c.fetched_digest.cast_const() != type_ {
        // SAFETY: a live method.
        if unsafe { EVP_MD_up_ref(type_.cast_mut()) } == 0 {
            err::raise(
                ERR_LIB_EVP,
                EVP_R_INITIALIZATION_ERROR,
                "evp_md_init_internal",
            );
            return 0;
        }
        // SAFETY: the context's own reference, replaced.
        unsafe { EVP_MD_free(c.fetched_digest) };
        c.fetched_digest = type_.cast_mut();
    }
    c.digest = type_;
    if c.algctx.is_null() {
        let created = md.funcs.newctx.map_or(ptr::null_mut(), |new| {
            // SAFETY: the provider's function with its context.
            unsafe { new(md.provider_ctx()) }
        });
        if created.is_null() {
            err::raise(
                ERR_LIB_EVP,
                EVP_R_INITIALIZATION_ERROR,
                "evp_md_init_internal",
            );
            return 0;
        }
        c.algctx = created;
    }
    let Some(init) = md.funcs.init else {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_INITIALIZATION_ERROR,
            "evp_md_init_internal",
        );
        return 0;
    };
    let algctx = c.algctx;
    // SAFETY: the provider's function with its context and the caller's parameters.
    unsafe { init(algctx, params) }
}

ffi_export! {
    /// Sets up `ctx` to digest with `type_` (NULL: again with its digest), passing `params` to
    /// the algorithm. Returns 1, or 0 with an error.
    ///
    /// # Safety
    /// `ctx` is a live digest context; `type_` is NULL or a live digest method; `params` is
    /// NULL or a parameter array.
    pub unsafe extern "C" fn EVP_DigestInit_ex2(ctx: *mut EVP_MD_CTX, type_: *const EVP_MD, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { init_internal(ctx, type_, params, ptr::null_mut()) }
    }
}

ffi_export! {
    /// As [`EVP_DigestInit_ex2`] without parameters; `impl_` (an `ENGINE`) must be NULL.
    ///
    /// # Safety
    /// As for [`EVP_DigestInit_ex2`].
    pub unsafe extern "C" fn EVP_DigestInit_ex(ctx: *mut EVP_MD_CTX, type_: *const EVP_MD, impl_: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { init_internal(ctx, type_, ptr::null(), impl_) }
    }
}

ffi_export! {
    /// Resets `ctx`, then sets it up as [`EVP_DigestInit_ex`] does.
    ///
    /// # Safety
    /// As for [`EVP_DigestInit_ex2`].
    pub unsafe extern "C" fn EVP_DigestInit(ctx: *mut EVP_MD_CTX, type_: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_MD_CTX_reset(ctx) };
        // SAFETY: as above.
        unsafe { init_internal(ctx, type_, ptr::null(), ptr::null_mut()) }
    }
}

ffi_export! {
    /// Digests `count` octets at `data`. Returns 1, or 0 (with an error after a final).
    ///
    /// # Safety
    /// `ctx` is a live digest context; `data` holds `count` octets.
    pub unsafe extern "C" fn EVP_DigestUpdate(ctx: *mut EVP_MD_CTX, data: *const c_void, count: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if count == 0 {
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        if c.flags & FLAG_FINALISED != 0 {
            err::raise(ERR_LIB_EVP, EVP_R_UPDATE_ERROR, "EVP_DigestUpdate");
            return 0;
        }
        // A context set up to sign or verify takes the data that way (as before OpenSSL 3).
        // SAFETY: the context's key context, or NULL.
        if let Some(op) = unsafe { super::sigver::sig_operation(c.pctx) } {
            return match op {
                // SAFETY: the caller's context and data.
                Some(false) => unsafe { super::sigver::EVP_DigestSignUpdate(ctx, data, count) },
                // SAFETY: as above.
                Some(true) => unsafe { super::sigver::EVP_DigestVerifyUpdate(ctx, data, count) },
                None => {
                    err::raise(ERR_LIB_EVP, EVP_R_UPDATE_ERROR, "EVP_DigestUpdate");
                    0
                }
            };
        }
        // SAFETY: the context's digest.
        let md = unsafe { digest_of(c) };
        let provided = |m: &&Md| !m.prov.0.is_null() && c.flags & flag(EVP_MD_CTX_FLAG_NO_INIT) == 0;
        let Some(md) = md.filter(provided) else {
            // The legacy path: the context's update function, if it has one.
            let Some(update) = c.update else { return 0 };
            // SAFETY: the caller's function with the caller's context and data.
            return unsafe { update(ctx, data, count) };
        };
        let Some(update) = md.funcs.update else {
            err::raise(ERR_LIB_EVP, EVP_R_UPDATE_ERROR, "EVP_DigestUpdate");
            return 0;
        };
        let algctx = c.algctx;
        // SAFETY: the provider's function with its context and the caller's data.
        unsafe { update(algctx, data.cast(), count) }
    }
}

ffi_export! {
    /// Finishes into `md` (room for the digest's size), storing the length through `size`
    /// unless it's NULL. Returns 1, or 0 (with an error if already finalized).
    ///
    /// # Safety
    /// `ctx` is a live digest context; `md` has room for the digest; `size` is NULL or valid
    /// for a write.
    pub unsafe extern "C" fn EVP_DigestFinal_ex(ctx: *mut EVP_MD_CTX, md: *mut u8, size: *mut c_uint) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        if c.digest.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Ok(mdsize) = usize::try_from(unsafe { EVP_MD_CTX_get_size_ex(ctx) }) else {
            return 0;
        };
        // SAFETY: as above.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        // SAFETY: the context's digest.
        if let Some(m) = unsafe { digest_of(c) }
            && m.prov.0.is_null()
        {
            // SAFETY: the caller's guarantee.
            return unsafe { final_legacy(ctx, m, md, size, mdsize) };
        }
        // SAFETY: the context's digest.
        let Some(final_) = unsafe { digest_of(c) }.and_then(|m| m.funcs.final_) else {
            err::raise(ERR_LIB_EVP, EVP_R_FINAL_ERROR, "EVP_DigestFinal_ex");
            return 0;
        };
        if c.flags & FLAG_FINALISED != 0 {
            err::raise(ERR_LIB_EVP, EVP_R_FINAL_ERROR, "EVP_DigestFinal_ex");
            return 0;
        }
        let mut out = 0usize;
        let algctx = c.algctx;
        // SAFETY: the provider's function with its context and the caller's buffer.
        let mut ret = unsafe { final_(algctx, md, &raw mut out, mdsize) };
        c.flags |= FLAG_FINALISED;
        if !size.is_null() {
            match c_uint::try_from(out) {
                // SAFETY: the caller's guarantee.
                Ok(n) => unsafe { size.write(n) },
                Err(_) => {
                    err::raise(ERR_LIB_EVP, EVP_R_FINAL_ERROR, "EVP_DigestFinal_ex");
                    ret = 0;
                }
            }
        }
        ret
    }
}

/// After a legacy final: the digest's `cleanup` (and the context marked cleaned), then the
/// state cleared.
///
/// # Safety
/// `ctx` is a live digest context whose digest is `m`.
unsafe fn after_legacy_final(ctx: *mut EVP_MD_CTX, m: &Md) {
    let legacy = m.legacy_fns();
    if let Some(cleanup) = legacy.cleanup {
        // SAFETY: the digest's function with the caller's context.
        unsafe { cleanup(ctx) };
        // SAFETY: the caller's guarantee (the call may have used the context).
        if let Some(c) = unsafe { context(ctx) } {
            c.flags |= flag(EVP_MD_CTX_FLAG_CLEANED);
        }
    }
    // SAFETY: as above.
    if let Some(c) = unsafe { context(ctx) }
        && !c.md_data.is_null()
    {
        // SAFETY: the context's state, of the digest's size.
        unsafe { mem::cleanse(c.md_data, usize::try_from(legacy.ctx_size).unwrap_or(0)) };
    }
}

/// The legacy part of `EVP_DigestFinal_ex`: the digest's `final` into `md`, the length (the
/// digest's size, whatever `final` returned) through `size`, then the clean-up.
///
/// # Safety
/// As for `EVP_DigestFinal_ex`; the context's digest is `m`.
unsafe fn final_legacy(
    ctx: *mut EVP_MD_CTX,
    m: &Md,
    md: *mut u8,
    size: *mut c_uint,
    mdsize: usize,
) -> c_int {
    if mdsize > 64 {
        // `OPENSSL_assert(mdsize <= EVP_MAX_MD_SIZE)`.
        crate::ffi::die("mdsize <= EVP_MAX_MD_SIZE");
    }
    let Some(final_) = m.legacy_fns().final_ else {
        // OpenSSL calls the missing function and crashes.
        err::raise(ERR_LIB_EVP, EVP_R_FINAL_ERROR, "EVP_DigestFinal_ex");
        return 0;
    };
    // SAFETY: the digest's function with the caller's context and room for the digest.
    let ret = unsafe { final_(ctx, md) };
    if !size.is_null() {
        // SAFETY: the caller's guarantee; the size is at most 64.
        unsafe { size.write(c_uint::try_from(mdsize).unwrap_or(0)) };
    }
    // SAFETY: the caller's guarantee.
    unsafe { after_legacy_final(ctx, m) };
    ret
}

/// The legacy part of `EVP_DigestFinalXOF`: an XOF digest's `ctrl` sets the length, then its
/// `final`; anything else fails with `EVP_R_NOT_XOF_OR_INVALID_LENGTH`.
///
/// # Safety
/// As for `EVP_DigestFinalXOF`; the context's digest is `m`.
unsafe fn final_xof_legacy(ctx: *mut EVP_MD_CTX, m: &Md, md: *mut u8, size: usize) -> c_int {
    let legacy = m.legacy_fns();
    let xof = m.flags() & c_ulong::try_from(EVP_MD_FLAG_XOF).unwrap_or(0) != 0;
    let length = c_int::try_from(size).ok();
    let set = match (xof, length, legacy.ctrl) {
        (true, Some(n), Some(ctrl)) => {
            // SAFETY: the digest's function with the caller's context.
            let r = unsafe { ctrl(ctx, EVP_MD_CTRL_XOF_LEN, n, ptr::null_mut()) };
            r != 0
        }
        _ => false,
    };
    if !set {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_NOT_XOF_OR_INVALID_LENGTH,
            "EVP_DigestFinalXOF",
        );
        return 0;
    }
    let Some(final_) = legacy.final_ else {
        err::raise(ERR_LIB_EVP, EVP_R_FINAL_ERROR, "EVP_DigestFinalXOF");
        return 0;
    };
    // SAFETY: the digest's function with the caller's context and room for `size` octets.
    let ret = unsafe { final_(ctx, md) };
    // SAFETY: the caller's guarantee.
    unsafe { after_legacy_final(ctx, m) };
    ret
}

ffi_export! {
    /// [`EVP_DigestFinal_ex`], then resets the context.
    ///
    /// # Safety
    /// As for [`EVP_DigestFinal_ex`].
    pub unsafe extern "C" fn EVP_DigestFinal(ctx: *mut EVP_MD_CTX, md: *mut u8, size: *mut c_uint) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let ret = unsafe { EVP_DigestFinal_ex(ctx, md, size) };
        // SAFETY: as above.
        unsafe { EVP_MD_CTX_reset(ctx) };
        ret
    }
}

ffi_export! {
    /// Finishes an XOF into `size` octets at `md`: sets `xoflen`, then finalizes (whatever the
    /// digest, as OpenSSL does). Returns 1, or 0 with an error.
    ///
    /// # Safety
    /// `ctx` is a live digest context; `md` has room for `size` octets.
    pub unsafe extern "C" fn EVP_DigestFinalXOF(ctx: *mut EVP_MD_CTX, md: *mut u8, size: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        // SAFETY: the context's digest.
        let Some(m) = (unsafe { digest_of(c) }) else {
            err::raise(ERR_LIB_EVP, EVP_R_INVALID_NULL_ALGORITHM, "EVP_DigestFinalXOF");
            return 0;
        };
        if m.prov.0.is_null() {
            // SAFETY: the caller's guarantee.
            return unsafe { final_xof_legacy(ctx, m, md, size) };
        }
        let Some(final_) = m.funcs.final_ else {
            err::raise(ERR_LIB_EVP, EVP_R_FINAL_ERROR, "EVP_DigestFinalXOF");
            return 0;
        };
        if c.flags & FLAG_FINALISED != 0 {
            err::raise(ERR_LIB_EVP, EVP_R_FINAL_ERROR, "EVP_DigestFinalXOF");
            return 0;
        }
        let mut length = size;
        let params = [
            construct(
                OSSL_DIGEST_PARAM_XOFLEN.as_ptr(),
                rustyssl_crypto::params::UNSIGNED_INTEGER,
                (&raw mut length).cast(),
                size_of::<usize>(),
            ),
            end(),
        ];
        let mut ret = 0;
        // SAFETY: the caller's context and a parameter array.
        if unsafe { EVP_MD_CTX_set_params(ctx, params.as_ptr()) } >= 0 {
            // SAFETY: as above.
            let Some(c) = (unsafe { context(ctx) }) else { return 0 };
            let algctx = c.algctx;
            let mut out = size;
            // SAFETY: the provider's function with its context and the caller's buffer.
            ret = unsafe { final_(algctx, md, &raw mut out, size) };
        }
        // SAFETY: as above.
        if let Some(c) = unsafe { context(ctx) } {
            c.flags |= FLAG_FINALISED;
        }
        ret
    }
}

ffi_export! {
    /// Squeezes `size` more octets of an XOF into `md`; repeatable. Returns 1, or 0 with an
    /// error.
    ///
    /// # Safety
    /// `ctx` is a live digest context; `md` has room for `size` octets.
    pub unsafe extern "C" fn EVP_DigestSqueeze(ctx: *mut EVP_MD_CTX, md: *mut u8, size: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        // SAFETY: the context's digest.
        let Some(m) = (unsafe { digest_of(c) }) else {
            err::raise(ERR_LIB_EVP, EVP_R_INVALID_NULL_ALGORITHM, "EVP_DigestSqueeze");
            return 0;
        };
        let Some(squeeze) = m.funcs.squeeze else {
            err::raise(ERR_LIB_EVP, EVP_R_METHOD_NOT_SUPPORTED, "EVP_DigestSqueeze");
            return 0;
        };
        let algctx = c.algctx;
        let mut out = size;
        // SAFETY: the provider's function with its context and the caller's buffer.
        unsafe { squeeze(algctx, md, &raw mut out, size) }
    }
}

/// The legacy part of `EVP_MD_CTX_copy_ex`: `out` becomes a field-by-field copy of `src` (the
/// source's fields) with its own copy of the state (in `out`'s old state when the digests are
/// the same) and key context, then the digest's `copy` runs.
///
/// # Safety
/// `out` and `in_` are live digest contexts; `src` is `in_`'s fields; `md` is its digest.
unsafe fn copy_legacy(out: *mut EVP_MD_CTX, in_: *const EVP_MD_CTX, src: &MdCtx, md: &Md) -> c_int {
    // The copy keeps its own functional reference to the source's engine.
    // SAFETY: the source's engine, or NULL.
    if !src.engine.is_null() && unsafe { crate::engine::ENGINE_init(src.engine) } == 0 {
        err::raise(
            ERR_LIB_EVP,
            rustyssl_abi::ERR_R_ENGINE_LIB,
            "EVP_MD_CTX_copy_ex",
        );
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let Some(dst) = (unsafe { context(out) }) else {
        return 0;
    };
    let tmp_buf = if dst.digest == src.digest {
        dst.flags |= flag(EVP_MD_CTX_FLAG_REUSE);
        dst.md_data
    } else {
        ptr::null_mut()
    };
    // SAFETY: the destination's own fields.
    unsafe { reset_ex(out, false) };
    // SAFETY: as above (the clean-up may have used it).
    let Some(dst) = (unsafe { context(out) }) else {
        return 0;
    };
    *dst = MdCtx { ..*src };
    dst.flags &= !FLAG_KEEP_PKEY_CTX;
    dst.md_data = ptr::null_mut();
    dst.pctx = ptr::null_mut();
    // A legacy context has no algorithm context to share.
    dst.algctx = ptr::null_mut();
    if !dst.fetched_digest.is_null() {
        // SAFETY: the source's live method; the copy holds its own reference.
        unsafe { EVP_MD_up_ref(dst.fetched_digest) };
    }
    let legacy = md.legacy_fns();
    let size = usize::try_from(legacy.ctx_size).unwrap_or(0);
    if !src.md_data.is_null() && size > 0 {
        let data = if tmp_buf.is_null() {
            mem::alloc(size)
        } else {
            tmp_buf
        };
        if data.is_null() {
            return 0;
        }
        // SAFETY: both states hold the digest's state size; they are different allocations.
        unsafe { ptr::copy_nonoverlapping(src.md_data.cast::<u8>(), data.cast::<u8>(), size) };
        dst.md_data = data;
    } else if !tmp_buf.is_null() {
        // OpenSSL loses the old state here; it is freed.
        // SAFETY: the destination's old state, of the digest's size.
        unsafe { mem::release_clean(tmp_buf, size) };
    }
    dst.update = src.update;
    if !src.pctx.is_null() {
        // SAFETY: the source's live key context.
        let p = unsafe { EVP_PKEY_CTX_dup(src.pctx) };
        if p.is_null() {
            // SAFETY: the destination.
            unsafe { EVP_MD_CTX_reset(out) };
            return 0;
        }
        dst.pctx = p;
    }
    if let Some(copy) = legacy.copy {
        // SAFETY: the digest's function with both contexts.
        return unsafe { copy(out, in_) };
    }
    1
}

ffi_export! {
    /// Makes `out` a copy of `in_`. Returns 1, or 0 with an error.
    ///
    /// # Safety
    /// `out` is a live digest context; `in_` is NULL or one.
    pub unsafe extern "C" fn EVP_MD_CTX_copy_ex(out: *mut EVP_MD_CTX, in_: *const EVP_MD_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(src) = (unsafe { context(in_.cast_mut()) }) else {
            err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, "EVP_MD_CTX_copy_ex");
            return 0;
        };
        // A plain copy of the source's fields (the algorithm context and reference are fixed
        // up below).
        let src = MdCtx { ..*src };
        if out.cast_const() == in_ {
            // Copying a context onto itself leaves it as it is.
            return 1;
        }
        // SAFETY: the caller's guarantee.
        if unsafe { context(out) }.is_none() {
            err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, "EVP_MD_CTX_copy_ex");
            return 0;
        }
        // SAFETY: the source's digest.
        let md = unsafe { method(src.digest) };
        match md {
            None => {
                // Copying an uninitialized context.
                // SAFETY: the destination's own fields.
                unsafe { reset_ex(out, false) };
                // SAFETY: as above.
                let Some(dst) = (unsafe { context(out) }) else { return 0 };
                *dst = MdCtx { ..src };
                if !dst.fetched_digest.is_null() {
                    // SAFETY: the source's live method; the copy holds its own reference.
                    unsafe { EVP_MD_up_ref(dst.fetched_digest) };
                }
            }
            Some(md) if md.prov.0.is_null() || src.flags & flag(EVP_MD_CTX_FLAG_NO_INIT) != 0 => {
                // SAFETY: the caller's guarantee.
                return unsafe { copy_legacy(out, in_, &src, md) };
            }
            Some(md) => {
                let Some(dupctx) = md.funcs.dupctx else {
                    err::raise(ERR_LIB_EVP, EVP_R_NOT_ABLE_TO_COPY_CTX, "EVP_MD_CTX_copy_ex");
                    return 0;
                };
                // SAFETY: as above.
                let Some(dst) = (unsafe { context(out) }) else { return 0 };
                match md.funcs.copyctx {
                    Some(copyctx) if dst.digest == src.digest && !dst.algctx.is_null() => {
                        let (to, from) = (dst.algctx, src.algctx);
                        // SAFETY: the provider's function with two of its contexts.
                        unsafe { copyctx(to, from) };
                        // SAFETY: the destination's own key context, or NULL.
                        unsafe { EVP_PKEY_CTX_free(dst.pctx) };
                        dst.pctx = ptr::null_mut();
                        // SAFETY: the destination's own fields (a provided digest's state
                        // is in its algorithm context; there is no legacy clean-up to run).
                        unsafe { cleanup_old_md_data(out, false) };
                        // SAFETY: as above.
                        let Some(dst) = (unsafe { context(out) }) else { return 0 };
                        dst.flags = src.flags;
                        dst.update = src.update;
                    }
                    _ => {
                        let fetched = dst.fetched_digest;
                        // SAFETY: the destination's own fields.
                        unsafe { reset_ex(out, true) };
                        if fetched != src.fetched_digest {
                            if !src.fetched_digest.is_null() {
                                // SAFETY: the source's live method.
                                unsafe { EVP_MD_up_ref(src.fetched_digest) };
                            }
                            // SAFETY: the destination's own reference.
                            unsafe { EVP_MD_free(fetched) };
                        }
                        // SAFETY: as above.
                        let Some(dst) = (unsafe { context(out) }) else { return 0 };
                        *dst = MdCtx { ..src };
                        dst.pctx = ptr::null_mut();
                        dst.algctx = ptr::null_mut();
                        if !src.algctx.is_null() {
                            // SAFETY: the provider's function with its context.
                            let copy = unsafe { dupctx(src.algctx) };
                            if copy.is_null() {
                                err::raise(ERR_LIB_EVP, EVP_R_NOT_ABLE_TO_COPY_CTX, "EVP_MD_CTX_copy_ex");
                                return 0;
                            }
                            dst.algctx = copy;
                        }
                    }
                }
            }
        }
        // SAFETY: as above.
        let Some(dst) = (unsafe { context(out) }) else { return 0 };
        dst.flags &= !FLAG_KEEP_PKEY_CTX;
        // The copy gets a copy of the key context (`clone_pkey`).
        dst.pctx = ptr::null_mut();
        if !src.pctx.is_null() {
            // SAFETY: the source's live key context.
            let p = unsafe { EVP_PKEY_CTX_dup(src.pctx) };
            if p.is_null() {
                err::raise(ERR_LIB_EVP, EVP_R_NOT_ABLE_TO_COPY_CTX, "EVP_MD_CTX_copy_ex");
                // SAFETY: the destination.
                unsafe { EVP_MD_CTX_reset(out) };
                return 0;
            }
            dst.pctx = p;
        }
        1
    }
}

ffi_export! {
    /// Resets `out`, then copies `in_` into it.
    ///
    /// # Safety
    /// As for [`EVP_MD_CTX_copy_ex`].
    pub unsafe extern "C" fn EVP_MD_CTX_copy(out: *mut EVP_MD_CTX, in_: *const EVP_MD_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_MD_CTX_reset(out) };
        // SAFETY: as above.
        unsafe { EVP_MD_CTX_copy_ex(out, in_) }
    }
}

ffi_export! {
    /// A new copy of `in_`, or NULL.
    ///
    /// # Safety
    /// `in_` is NULL or a live digest context.
    pub unsafe extern "C" fn EVP_MD_CTX_dup(in_: *const EVP_MD_CTX) -> *mut EVP_MD_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: no preconditions.
        let out = unsafe { EVP_MD_CTX_new() };
        // SAFETY: a new context and the caller's.
        if !out.is_null() && unsafe { EVP_MD_CTX_copy_ex(out, in_) } == 0 {
            // SAFETY: the new context.
            unsafe { EVP_MD_CTX_free(out) };
            return ptr::null_mut();
        }
        out
    }
}

ffi_export! {
    /// Digests `count` octets at `data` with `type_` into `md`, the length through `size`.
    /// Returns 1, or 0.
    ///
    /// # Safety
    /// `data` holds `count` octets; `md` has room for the digest; `size` is NULL or valid for a
    /// write; `type_` is NULL or a live digest method; `impl_` is NULL.
    pub unsafe extern "C" fn EVP_Digest(data: *const c_void, count: usize, md: *mut u8, size: *mut c_uint, type_: *const EVP_MD, impl_: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: no preconditions.
        let ctx = unsafe { EVP_MD_CTX_new() };
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: a new context.
        unsafe { EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_ONESHOT) };
        // SAFETY: the new context and the caller's arguments.
        let ret = unsafe { EVP_DigestInit_ex(ctx, type_, impl_) } != 0
            // SAFETY: as above.
            && unsafe { EVP_DigestUpdate(ctx, data, count) } != 0
            // SAFETY: as above.
            && unsafe { EVP_DigestFinal_ex(ctx, md, size) } != 0;
        // SAFETY: the new context.
        unsafe { EVP_MD_CTX_free(ctx) };
        c_int::from(ret)
    }
}

ffi_export! {
    /// Fetches `name` from `libctx` with `propq` and digests `datalen` octets at `data` into
    /// `md`, the length through `mdlen` (0 if it failed). Returns 1, or 0.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `name` and `propq` are NULL or strings;
    /// `data` holds `datalen` octets; `md` has room for the digest; `mdlen` is NULL or valid
    /// for a write.
    pub unsafe extern "C" fn EVP_Q_digest(libctx: *mut OSSL_LIB_CTX, name: *const c_char, propq: *const c_char, data: *const c_void, datalen: usize, md: *mut u8, mdlen: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let digest = unsafe { EVP_MD_fetch(libctx, name, propq) };
        let mut temp: c_uint = 0;
        let mut ret = 0;
        if !digest.is_null() {
            // SAFETY: the caller's guarantee and a live method.
            ret = unsafe { EVP_Digest(data, datalen, md, &raw mut temp, digest, ptr::null_mut()) };
            // SAFETY: the fetched reference.
            unsafe { EVP_MD_free(digest) };
        }
        if !mdlen.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { mdlen.write(usize::try_from(temp).unwrap_or(0)) };
        }
        ret
    }
}

ffi_export! {
    /// Sets the algorithm's context parameters: its result, or 0 if it takes none (or for
    /// NULL).
    ///
    /// # Safety
    /// `ctx` is NULL or a live digest context; `params` is NULL or a parameter array.
    pub unsafe extern "C" fn EVP_MD_CTX_set_params(ctx: *mut EVP_MD_CTX, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        // A signing or verifying operation's algorithm takes them first.
        // SAFETY: the context's key context, or NULL.
        if let Some((sig, algctx)) = unsafe { super::sigver::sig_ctx(c.pctx) }
            && let Some(f) = sig.get().funcs.set_ctx_md_params
        {
            // SAFETY: the algorithm's function with its context and the caller's array.
            return unsafe { f(algctx, params) };
        }
        // SAFETY: the context's digest.
        let Some(set) = unsafe { digest_of(c) }.and_then(|m| m.funcs.set_ctx_params) else {
            return 0;
        };
        let algctx = c.algctx;
        // SAFETY: the provider's function with its context and the caller's parameters.
        unsafe { set(algctx, params) }
    }
}

ffi_export! {
    /// Gets the algorithm's context parameters: its result, or 0 if it has none (or for NULL).
    ///
    /// # Safety
    /// `ctx` is NULL or a live digest context; `params` is NULL or a parameter array.
    pub unsafe extern "C" fn EVP_MD_CTX_get_params(ctx: *mut EVP_MD_CTX, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        // A signing or verifying operation's algorithm takes them first.
        // SAFETY: the context's key context, or NULL.
        if let Some((sig, algctx)) = unsafe { super::sigver::sig_ctx(c.pctx) }
            && let Some(f) = sig.get().funcs.get_ctx_md_params
        {
            // SAFETY: the algorithm's function with its context and the caller's array.
            return unsafe { f(algctx, params) };
        }
        // SAFETY: the context's digest.
        let Some(get) = unsafe { digest_of(c) }.and_then(|m| m.funcs.get_ctx_params) else {
            return 0;
        };
        let algctx = c.algctx;
        // SAFETY: the provider's function with its context and the caller's parameters.
        unsafe { get(algctx, params) }
    }
}

ffi_export! {
    /// The context parameters `ctx`'s algorithm can set, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live digest context.
    pub unsafe extern "C" fn EVP_MD_CTX_settable_params(ctx: *mut EVP_MD_CTX) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return ptr::null() };
        // A signing or verifying operation's algorithm reports them first.
        // SAFETY: the context's key context, or NULL.
        if let Some((sig, algctx)) = unsafe { super::sigver::sig_ctx(c.pctx) }
            && let Some(f) = sig.get().funcs.settable_ctx_md_params
        {
            // SAFETY: the algorithm's function with its context.
            return unsafe { f(algctx) };
        }
        // SAFETY: the context's digest.
        let Some(m) = (unsafe { digest_of(c) }) else { return ptr::null() };
        let Some(list) = m.funcs.settable_ctx_params else { return ptr::null() };
        // SAFETY: the provider's function with its contexts.
        unsafe { list(c.algctx, m.provider_ctx()) }
    }
}

ffi_export! {
    /// The context parameters `ctx`'s algorithm can report, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live digest context.
    pub unsafe extern "C" fn EVP_MD_CTX_gettable_params(ctx: *mut EVP_MD_CTX) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return ptr::null() };
        // A signing or verifying operation's algorithm reports them first.
        // SAFETY: the context's key context, or NULL.
        if let Some((sig, algctx)) = unsafe { super::sigver::sig_ctx(c.pctx) }
            && let Some(f) = sig.get().funcs.gettable_ctx_md_params
        {
            // SAFETY: the algorithm's function with its context.
            return unsafe { f(algctx) };
        }
        // SAFETY: the context's digest.
        let Some(m) = (unsafe { digest_of(c) }) else { return ptr::null() };
        let Some(list) = m.funcs.gettable_ctx_params else { return ptr::null() };
        // SAFETY: the provider's function with its contexts.
        unsafe { list(c.algctx, m.provider_ctx()) }
    }
}

ffi_export! {
    /// The context parameters `md`'s contexts can set, or NULL.
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_settable_ctx_params(md: *const EVP_MD) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(md) }) else { return ptr::null() };
        let Some(list) = m.funcs.settable_ctx_params else { return ptr::null() };
        // SAFETY: the provider's function, without an algorithm context.
        unsafe { list(ptr::null_mut(), m.provider_ctx()) }
    }
}

ffi_export! {
    /// The context parameters `md`'s contexts can report, or NULL.
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_gettable_ctx_params(md: *const EVP_MD) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(md) }) else { return ptr::null() };
        let Some(list) = m.funcs.gettable_ctx_params else { return ptr::null() };
        // SAFETY: the provider's function, without an algorithm context.
        unsafe { list(ptr::null_mut(), m.provider_ctx()) }
    }
}

ffi_export! {
    /// The context's digest size: the algorithm's `size` context parameter if it has one (-1
    /// if that's unset), else the digest's size (-1 with an error with no digest).
    ///
    /// # Safety
    /// `ctx` is NULL or a live digest context.
    pub unsafe extern "C" fn EVP_MD_CTX_get_size_ex(ctx: *const EVP_MD_CTX) -> c_int
    where failure = -1, library = ERR_LIB_EVP
    {
        let c = ctx.cast_mut();
        // SAFETY: the caller's guarantee.
        let gettables = unsafe { EVP_MD_CTX_gettable_params(c) };
        let has_size = !gettables.is_null() && {
            // SAFETY: the algorithm's parameter list.
            let p = unsafe { OSSL_PARAM_locate_const(gettables, OSSL_DIGEST_PARAM_SIZE.as_ptr()) };
            !p.is_null()
        };
        if has_size {
            let mut size = 0usize;
            let mut params = [
                construct(
                    OSSL_DIGEST_PARAM_SIZE.as_ptr(),
                    rustyssl_crypto::params::UNSIGNED_INTEGER,
                    (&raw mut size).cast(),
                    size_of::<usize>(),
                ),
                end(),
            ];
            // SAFETY: the caller's context and a parameter array.
            if unsafe { EVP_MD_CTX_get_params(c, params.as_mut_ptr()) } != 1 || size == usize::MAX || size == 0 {
                return -1;
            }
            return c_int::try_from(size).unwrap_or(-1);
        }
        // SAFETY: the caller's guarantee.
        let md = unsafe { EVP_MD_CTX_get0_md(ctx) };
        // SAFETY: the context's method or NULL.
        unsafe { EVP_MD_get_size(md) }
    }
}

ffi_export! {
    /// The digest the context was set up with, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live digest context.
    pub unsafe extern "C" fn EVP_MD_CTX_get0_md(ctx: *const EVP_MD_CTX) -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { context(ctx.cast_mut()) }.map_or(ptr::null(), |c| c.reqdigest)
    }
}

ffi_export! {
    /// The deprecated name of [`EVP_MD_CTX_get0_md`].
    ///
    /// # Safety
    /// As for [`EVP_MD_CTX_get0_md`].
    pub unsafe extern "C" fn EVP_MD_CTX_md(ctx: *const EVP_MD_CTX) -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_MD_CTX_get0_md(ctx) }
    }
}

ffi_export! {
    /// The digest the context was set up with, with a new reference; NULL if none.
    ///
    /// # Safety
    /// `ctx` is NULL or a live digest context.
    pub unsafe extern "C" fn EVP_MD_CTX_get1_md(ctx: *mut EVP_MD_CTX) -> *mut EVP_MD
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let md = unsafe { EVP_MD_CTX_get0_md(ctx) }.cast_mut();
        // SAFETY: the context's live method.
        if md.is_null() || unsafe { EVP_MD_up_ref(md) } == 0 {
            return ptr::null_mut();
        }
        md
    }
}

ffi_export! {
    /// Sets `flags` (NULL does nothing, docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `ctx` is NULL or a live digest context.
    pub unsafe extern "C" fn EVP_MD_CTX_set_flags(ctx: *mut EVP_MD_CTX, flags: c_int)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { context(ctx) } {
            // The flags are an `int` widened to `unsigned long`, sign and all, as in C.
            c.flags |= c_ulong::from_ne_bytes(i64::from(flags).to_ne_bytes());
        }
    }
}

ffi_export! {
    /// Clears `flags` (NULL does nothing, docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `ctx` is NULL or a live digest context.
    pub unsafe extern "C" fn EVP_MD_CTX_clear_flags(ctx: *mut EVP_MD_CTX, flags: c_int)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { context(ctx) } {
            c.flags &= !c_ulong::from_ne_bytes(i64::from(flags).to_ne_bytes());
        }
    }
}

ffi_export! {
    /// Which of `flags` are set (0 for NULL, docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `ctx` is NULL or a live digest context.
    pub unsafe extern "C" fn EVP_MD_CTX_test_flags(ctx: *const EVP_MD_CTX, flags: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx.cast_mut()) }) else { return 0 };
        let set = c.flags & c_ulong::from_ne_bytes(i64::from(flags).to_ne_bytes());
        // The result is the `unsigned long` truncated to `int`, as C's conversion does.
        c_int::from_ne_bytes(u32::try_from(set & 0xffff_ffff).unwrap_or(0).to_ne_bytes())
    }
}

ffi_export! {
    /// The legacy digest's state: NULL for provided digests.
    ///
    /// # Safety
    /// `ctx` is NULL or a live digest context.
    pub unsafe extern "C" fn EVP_MD_CTX_get0_md_data(ctx: *const EVP_MD_CTX) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { context(ctx.cast_mut()) }.map_or(ptr::null_mut(), |c| c.md_data)
    }
}

ffi_export! {
    /// The context's legacy update function, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live digest context.
    pub unsafe extern "C" fn EVP_MD_CTX_update_fn(ctx: *mut EVP_MD_CTX) -> Option<LegacyUpdateFn>
    where failure = None, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { context(ctx) }.and_then(|c| c.update)
    }
}

ffi_export! {
    /// Sets the context's legacy update function, which [`EVP_DigestUpdate`] calls on the
    /// legacy path (`EVP_MD_CTX_FLAG_NO_INIT`).
    ///
    /// # Safety
    /// `ctx` is NULL or a live digest context; `update` is NULL or a function of the
    /// documented type.
    pub unsafe extern "C" fn EVP_MD_CTX_set_update_fn(ctx: *mut EVP_MD_CTX, update: Option<LegacyUpdateFn>)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { context(ctx) } {
            c.update = update;
        }
    }
}

ffi_export! {
    /// The old control interface, mapped to parameters: `EVP_MD_CTRL_XOF_LEN` sets `xoflen`,
    /// `EVP_MD_CTRL_MICALG` gets `micalg`, `EVP_CTRL_SSL3_MASTER_SECRET` sets `ssl3-ms`.
    /// Returns the result if positive, else 0 (with an error for NULL).
    ///
    /// # Safety
    /// `ctx` is NULL or a live digest context; `p2` is what `cmd` documents.
    pub unsafe extern "C" fn EVP_MD_CTX_ctrl(ctx: *mut EVP_MD_CTX, cmd: c_int, p1: c_int, p2: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else {
            err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, "EVP_MD_CTX_ctrl");
            return 0;
        };
        // SAFETY: the context's digest.
        let digest = unsafe { digest_of(c) };
        if !c.digest.is_null() && digest.is_none_or(|m| m.prov.0.is_null()) {
            // The legacy path: the digest's own `ctrl`.
            let Some(f) = digest.and_then(|m| m.legacy_fns().ctrl) else {
                err::raise(ERR_LIB_EVP, EVP_R_CTRL_NOT_IMPLEMENTED, "EVP_MD_CTX_ctrl");
                return 0;
            };
            // SAFETY: the digest's function with the caller's context and arguments.
            let ret = unsafe { f(ctx, cmd, p1, p2) };
            return if ret <= 0 { 0 } else { ret };
        }
        // `size_t` of an `int`, sign-extended, as C converts it.
        let mut size = usize::from_ne_bytes(isize::try_from(p1).unwrap_or(0).to_ne_bytes());
        let p1_size = usize::try_from(p1).unwrap_or(0);
        let ret = match cmd {
            EVP_MD_CTRL_XOF_LEN => {
                let params = [
                    construct(OSSL_DIGEST_PARAM_XOFLEN.as_ptr(), rustyssl_crypto::params::UNSIGNED_INTEGER, (&raw mut size).cast(), size_of::<usize>()),
                    end(),
                ];
                // SAFETY: the caller's context and a parameter array.
                unsafe { EVP_MD_CTX_set_params(ctx, params.as_ptr()) }
            }
            EVP_MD_CTRL_MICALG => {
                let mut params = [
                    construct(OSSL_DIGEST_PARAM_MICALG.as_ptr(), rustyssl_crypto::params::UTF8_STRING, p2, if p1 != 0 { p1_size } else { 9999 }),
                    end(),
                ];
                // SAFETY: the caller's context and a parameter array over its buffer.
                unsafe { EVP_MD_CTX_get_params(ctx, params.as_mut_ptr()) }
            }
            EVP_CTRL_SSL3_MASTER_SECRET => {
                let params = [
                    construct(OSSL_DIGEST_PARAM_SSL3_MS.as_ptr(), rustyssl_crypto::params::OCTET_STRING, p2, p1_size),
                    end(),
                ];
                // SAFETY: the caller's context and a parameter array over its secret.
                unsafe { EVP_MD_CTX_set_params(ctx, params.as_ptr()) }
            }
            // `EVP_CTRL_RET_UNSUPPORTED`.
            _ => -1,
        };
        ret.max(0)
    }
}

ffi_export! {
    /// Whether `md` is an XOF.
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_xof(md: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if md.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let flags = unsafe { EVP_MD_get_flags(md) };
        c_int::from(flags & c_ulong::try_from(EVP_MD_FLAG_XOF).unwrap_or(0) != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_contexts_are_refused() {
        let data = [0u8; 4];
        let mut out = [0u8; 64];
        let (null, outp) = (ptr::null_mut(), out.as_mut_ptr());
        // SAFETY: NULL is the case under test, here and below; the other arguments are valid.
        let r = unsafe { EVP_DigestUpdate(null, data.as_ptr().cast(), 4) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let r = unsafe { EVP_DigestFinal_ex(null, outp, ptr::null_mut()) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let r = unsafe { EVP_DigestInit_ex(null, ptr::null(), ptr::null_mut()) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let r = unsafe { EVP_DigestInit(null, ptr::null()) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let r = unsafe { EVP_DigestFinalXOF(null, outp, 8) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let r = unsafe { EVP_DigestSqueeze(null, outp, 8) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let r = unsafe { EVP_MD_CTX_set_params(null, ptr::null()) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let r = unsafe { EVP_MD_CTX_get_params(null, ptr::null_mut()) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        unsafe { EVP_MD_CTX_set_flags(null, 1) };
        // SAFETY: as above.
        unsafe { EVP_MD_CTX_clear_flags(null, 1) };
        // SAFETY: as above.
        let r = unsafe { EVP_MD_CTX_test_flags(ptr::null(), 1) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        unsafe { EVP_MD_CTX_set_update_fn(null, None) };
        crate::err::take_all();
    }

    #[test]
    #[cfg_attr(
        all(miri, target_arch = "aarch64"),
        ignore = "the keccak crate uses ARMv8 SHA-3 intrinsics there, which Miri can't run"
    )]
    fn final_xof_of_a_fixed_keccak_digest_writes_only_its_length() {
        // A context of its own, whose default provider is activated without loading the
        // configuration (which Miri can't).
        // SAFETY: no preconditions.
        let libctx = unsafe { crate::libctx::OSSL_LIB_CTX_new() };
        // SAFETY: a name and a live context.
        let md = unsafe { EVP_MD_fetch(libctx, c"SHA3-256".as_ptr(), ptr::null()) };
        assert!(!md.is_null());
        // SAFETY: no preconditions.
        let ctx = unsafe { EVP_MD_CTX_new() };
        let mut out = [0xeeu8; 48];
        // SAFETY: a new context and a live method.
        assert_eq!(unsafe { EVP_DigestInit_ex(ctx, md, ptr::null_mut()) }, 1);
        // A NULL output buffer is refused, and the context isn't finalized by it.
        // SAFETY: the context; NULL is the case under test.
        let r = unsafe { EVP_DigestFinal_ex(ctx, ptr::null_mut(), ptr::null_mut()) };
        assert_eq!(r, 0);
        // SAFETY: the context.
        let r = unsafe { EVP_MD_CTX_test_flags(ctx, 0x0800) };
        assert_eq!(
            r, 0x0800,
            "the EVP layer marks the context finalized all the same"
        );
        // SAFETY: the context and the method.
        assert_eq!(unsafe { EVP_DigestInit_ex(ctx, md, ptr::null_mut()) }, 1);
        // SAFETY: the context and room for 16 octets.
        assert_eq!(unsafe { EVP_DigestFinalXOF(ctx, out.as_mut_ptr(), 16) }, 1);
        assert!(
            out[16..].iter().all(|&b| b == 0xee),
            "nothing past the 16 octets asked for"
        );
        // The first 16 octets of SHA3-256 of nothing.
        let want = [
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61,
            0xd6, 0x62,
        ];
        assert_eq!(out[..16], want);
        // SAFETY: the context and the method, freed once.
        unsafe { EVP_MD_CTX_free(ctx) };
        // SAFETY: as above.
        unsafe { EVP_MD_free(md) };
        // SAFETY: the context, freed once.
        unsafe { crate::libctx::OSSL_LIB_CTX_free(libctx) };
    }
}
