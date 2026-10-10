//! The default provider's digests (`deflt_digests` in `providers/defltprov.c`): the algorithm
//! table `query_operation` offers for `OSSL_OP_DIGEST`, and each algorithm's dispatch table
//! over `rustyssl_crypto::provided::digest`, which has the provider functions' semantics.
//!
//! Each family's table has exactly the functions the reference's has, since the EVP layer's
//! behavior follows from which exist: SHA-1 and MD5-SHA1 can set `ssl3-ms`; SHAKE and
//! KECCAK-KMAC squeeze and get and set `xoflen`/`size`; BLAKE2 gets and sets `size`; the rest
//! have no context parameters at all. An algorithm context is a boxed
//! [`Ctx`], freed by `freectx`.

use core::ffi::{c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_PROV, OSSL_ALGORITHM, OSSL_DIGEST_PARAM_ALGID_ABSENT, OSSL_DIGEST_PARAM_BLOCK_SIZE,
    OSSL_DIGEST_PARAM_SIZE, OSSL_DIGEST_PARAM_SSL3_MS, OSSL_DIGEST_PARAM_XOF,
    OSSL_DIGEST_PARAM_XOFLEN, OSSL_FUNC_DIGEST_COPYCTX, OSSL_FUNC_DIGEST_DUPCTX,
    OSSL_FUNC_DIGEST_FINAL, OSSL_FUNC_DIGEST_FREECTX, OSSL_FUNC_DIGEST_GET_CTX_PARAMS,
    OSSL_FUNC_DIGEST_GET_PARAMS, OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS,
    OSSL_FUNC_DIGEST_GETTABLE_PARAMS, OSSL_FUNC_DIGEST_INIT, OSSL_FUNC_DIGEST_NEWCTX,
    OSSL_FUNC_DIGEST_SET_CTX_PARAMS, OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_DIGEST_SQUEEZE, OSSL_FUNC_DIGEST_UPDATE, OSSL_PARAM, OSSL_PARAM_INTEGER,
    OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UNSIGNED_INTEGER, PROV_R_FAILED_TO_GET_PARAMETER,
    PROV_R_FAILED_TO_SET_PARAMETER, PROV_R_INVALID_DIGEST_LENGTH, PROV_R_INVALID_DIGEST_SIZE,
};
use rustyssl_crypto::provided::digest::{Ctx, Error, Kind};

use super::tables::{
    ALG_END, Algorithms, Dispatch, END, PARAM_END, Params, alg, bare, defn, entry,
};
use crate::err;
use crate::ffi::ffi_callback;
use crate::params::{
    OSSL_PARAM_get_size_t, OSSL_PARAM_locate, OSSL_PARAM_locate_const, OSSL_PARAM_set_int,
    OSSL_PARAM_set_size_t, OSSL_PARAM_set_uint,
};

/// The algorithm context behind `vctx`, or `None` for NULL.
///
/// # Safety
/// `vctx` is NULL or a context `newctx` made and `freectx` hasn't freed.
unsafe fn context<'a>(vctx: *mut c_void) -> Option<&'a mut Ctx> {
    // SAFETY: the caller's guarantee: a box from `newctx`, used by one caller at a time as an
    // algorithm context is.
    unsafe { vctx.cast::<Ctx>().as_mut() }
}

/// `ossl_param_is_empty`.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn is_empty(params: *const OSSL_PARAM) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { params.as_ref() }.is_none_or(|p| p.key.is_null())
}

/// `newctx` for `kind`.
fn new_context(kind: Kind) -> *mut c_void {
    Box::into_raw(Box::new(Ctx::new(kind))).cast()
}

/// `ossl_digest_default_get_params`: the block size, size, and XOF and AlgorithmIdentifier
/// flags.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn default_get_params(kind: Kind, params: *mut OSSL_PARAM, function: &str) -> c_int {
    let flags = [
        (OSSL_DIGEST_PARAM_XOF, kind.is_xof()),
        (OSSL_DIGEST_PARAM_ALGID_ABSENT, kind.algid_absent()),
    ];
    for (key, value) in [
        (OSSL_DIGEST_PARAM_BLOCK_SIZE, kind.block_size()),
        (OSSL_DIGEST_PARAM_SIZE, kind.size()),
    ] {
        // SAFETY: the caller's array.
        let p = unsafe { OSSL_PARAM_locate(params, key.as_ptr()) };
        // SAFETY: a parameter of the array.
        if !p.is_null() && unsafe { OSSL_PARAM_set_size_t(p, value) } == 0 {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER, function);
            return 0;
        }
    }
    for (key, value) in flags {
        // SAFETY: the caller's array.
        let p = unsafe { OSSL_PARAM_locate(params, key.as_ptr()) };
        // SAFETY: a parameter of the array.
        if !p.is_null() && unsafe { OSSL_PARAM_set_int(p, c_int::from(value)) } == 0 {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER, function);
            return 0;
        }
    }
    1
}

ffi_callback! {
    /// `update`: absorbs `len` octets.
    ///
    /// # Safety
    /// `vctx` is a live algorithm context; `data` holds `len` octets.
    pub(crate) unsafe extern "C" fn update(vctx: *mut c_void, data: *const u8, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        let input: &[u8] = if len == 0 || data.is_null() {
            &[]
        } else {
            // SAFETY: the caller's guarantee.
            unsafe { core::slice::from_raw_parts(data, len) }
        };
        c_int::from(ctx.update(input))
    }
}

/// `final`'s and `squeeze`'s output: `outsz` octets at `out` (none for NULL).
///
/// # Safety
/// `out` is NULL or has room for `outsz` octets.
unsafe fn output<'a>(out: *mut u8, outsz: usize) -> &'a mut [u8] {
    if out.is_null() || outsz == 0 {
        &mut []
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { core::slice::from_raw_parts_mut(out, outsz) }
    }
}

ffi_callback! {
    /// `final`: the digest into `out` (room for `outsz`), its length through `outl`.
    ///
    /// # Safety
    /// `vctx` is a live algorithm context; `out` has room for `outsz` octets; `outl` is valid
    /// for a write.
    pub(crate) unsafe extern "C" fn final_(vctx: *mut c_void, out: *mut u8, outl: *mut usize, outsz: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        // No output buffer for output that has a length: the reference writes through NULL;
        // this fails without finalizing (docs/DEVIATIONS.md).
        if out.is_null() && outsz != 0 {
            return 0;
        }
        let mut length = 0;
        // SAFETY: the caller's guarantee.
        let result = ctx.finalize(unsafe { output(out, outsz) }, &mut length);
        let function = match ctx {
            Ctx::Keccak(_) => "keccak_final",
            Ctx::Blake2(_) => "blake2_internal_final",
            _ => "digest_internal_final",
        };
        // The reference stores the length on the Keccak and BLAKE2 paths even when they fail.
        let stores = result.is_ok() || matches!(ctx, Ctx::Keccak(_) | Ctx::Blake2(_));
        if stores && !outl.is_null() && result != Err(Error::InvalidDigestLength) {
            // SAFETY: the caller's guarantee.
            unsafe { outl.write(length) };
        }
        match result {
            Ok(()) => 1,
            Err(Error::Silent) => 0,
            Err(Error::InvalidDigestLength) => {
                err::raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH, function);
                0
            }
            Err(Error::InvalidDigestSize) => {
                err::raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_SIZE, function);
                0
            }
        }
    }
}

ffi_callback! {
    /// `squeeze` (SHAKE; KECCAK-KMAC's always fails, as the reference's does): `outsz` more
    /// octets, the count through `outl`.
    ///
    /// # Safety
    /// As for [`final_`].
    pub(crate) unsafe extern "C" fn squeeze(vctx: *mut c_void, out: *mut u8, outl: *mut usize, outsz: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        if !ctx.can_squeeze() || (out.is_null() && outsz != 0) {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let ok = ctx.squeeze(unsafe { output(out, outsz) });
        if !outl.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { outl.write(outsz) };
        }
        c_int::from(ok)
    }
}

ffi_callback! {
    /// `freectx`: wipes and frees the context; NULL does nothing.
    ///
    /// # Safety
    /// `vctx` is NULL or a context from `newctx`, not used afterwards.
    pub(crate) unsafe extern "C" fn freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        if !vctx.is_null() {
            // SAFETY: the caller's guarantee: a box from `newctx`.
            drop(unsafe { Box::from_raw(vctx.cast::<Ctx>()) });
        }
    }
}

ffi_callback! {
    /// `dupctx`: a copy of the context.
    ///
    /// # Safety
    /// `vctx` is a live algorithm context.
    pub(crate) unsafe extern "C" fn dupctx(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return ptr::null_mut() };
        Box::into_raw(Box::new(ctx.clone())).cast()
    }
}

ffi_callback! {
    /// `copyctx`: makes `out` a copy of `in_`.
    ///
    /// # Safety
    /// Both are live algorithm contexts of one algorithm.
    pub(crate) unsafe extern "C" fn copyctx(out: *mut c_void, in_: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let copy = unsafe { context(in_) }.map(|c| c.clone());
        // SAFETY: the caller's guarantee.
        if let (Some(o), Some(c)) = (unsafe { context(out) }, copy) {
            *o = c;
        }
    }
}

ffi_callback! {
    /// `init` for the digests without parameters: starts again.
    ///
    /// # Safety
    /// `vctx` is a live algorithm context.
    pub(crate) unsafe extern "C" fn init(vctx: *mut c_void, _params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { context(vctx) }.map_or(0, |c| c_int::from(c.init()))
    }
}

ffi_callback! {
    /// `init` for SHA-1 and MD5-SHA1: starts again, then sets the parameters.
    ///
    /// # Safety
    /// `vctx` is a live algorithm context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn ssl3_init(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        if !ctx.init() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { ssl3_set_ctx_params(vctx, params) }
    }
}

ffi_callback! {
    /// `set_ctx_params` for SHA-1 and MD5-SHA1: `ssl3-ms`, as an octet string.
    ///
    /// # Safety
    /// `vctx` is NULL or a live algorithm context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn ssl3_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: the caller's array.
        let p = unsafe { OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_SSL3_MS.as_ptr()) };
        // SAFETY: a parameter of the array, or NULL.
        let Some(p) = (unsafe { p.as_ref() }) else { return 1 };
        if p.data_type != OSSL_PARAM_OCTET_STRING.cast_unsigned() {
            return 1;
        }
        let ms: &[u8] = if p.data.is_null() || p.data_size == 0 {
            &[]
        } else {
            // SAFETY: an octet string parameter's data holds its size.
            unsafe { core::slice::from_raw_parts(p.data.cast(), p.data_size) }
        };
        c_int::from(ctx.ssl3_master_secret(ms))
    }
}

ffi_callback! {
    /// `init` for SHAKE and KECCAK-KMAC: starts again (the length stays), then sets the
    /// parameters.
    ///
    /// # Safety
    /// As for [`ssl3_init`].
    pub(crate) unsafe extern "C" fn xof_init(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        ctx.init();
        // SAFETY: the caller's guarantee.
        unsafe { xof_set_ctx_params(vctx, params) }
    }
}

ffi_callback! {
    /// `shake_set_ctx_params`: `xoflen`, or else `size`.
    ///
    /// # Safety
    /// As for [`ssl3_set_ctx_params`].
    pub(crate) unsafe extern "C" fn xof_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: the caller's array.
        let mut p = unsafe { OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_XOFLEN.as_ptr()) };
        if p.is_null() {
            // SAFETY: as above.
            p = unsafe { OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_SIZE.as_ptr()) };
        }
        if p.is_null() {
            return 1;
        }
        let mut n = 0usize;
        // SAFETY: a parameter of the array.
        if unsafe { OSSL_PARAM_get_size_t(p, &raw mut n) } == 0 {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, "shake_set_ctx_params");
            return 0;
        }
        ctx.set_xof_length(n);
        1
    }
}

ffi_callback! {
    /// `shake_get_ctx_params`: `xoflen` and its alias `size`.
    ///
    /// # Safety
    /// `vctx` is NULL or a live algorithm context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn xof_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        let n = ctx.xof_length().unwrap_or(0);
        for key in [OSSL_DIGEST_PARAM_XOFLEN, OSSL_DIGEST_PARAM_SIZE] {
            // SAFETY: the caller's array.
            let p = unsafe { OSSL_PARAM_locate(params, key.as_ptr()) };
            // SAFETY: a parameter of the array.
            if !p.is_null() && unsafe { OSSL_PARAM_set_size_t(p, n) } == 0 {
                err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, "shake_get_ctx_params");
                return 0;
            }
        }
        1
    }
}

ffi_callback! {
    /// `init` for BLAKE2: sets the parameters, then starts again with the size they set.
    ///
    /// # Safety
    /// As for [`ssl3_init`].
    pub(crate) unsafe extern "C" fn blake2_init(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { blake2_set_ctx_params(vctx, params) } == 0 {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { context(vctx) }.map_or(0, |c| c_int::from(c.init()))
    }
}

ffi_callback! {
    /// `ossl_blake2*_set_ctx_params`: `size`, 1 to the digest's size, for the next `init`.
    ///
    /// # Safety
    /// As for [`ssl3_set_ctx_params`].
    pub(crate) unsafe extern "C" fn blake2_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: the caller's array.
        let p = unsafe { OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_SIZE.as_ptr()) };
        if p.is_null() {
            return 1;
        }
        let mut n = 0usize;
        // SAFETY: a parameter of the array.
        if unsafe { OSSL_PARAM_get_size_t(p, &raw mut n) } == 0 {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, "blake2_set_ctx_params");
            return 0;
        }
        if ctx.set_blake2_size(n).is_err() {
            err::raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_SIZE, "blake2_set_ctx_params");
            return 0;
        }
        1
    }
}

ffi_callback! {
    /// `ossl_blake2*_get_ctx_params`: `size`.
    ///
    /// # Safety
    /// As for [`xof_get_ctx_params`].
    pub(crate) unsafe extern "C" fn blake2_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: the caller's array.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE.as_ptr()) };
        let size = ctx.blake2_size().unwrap_or(0);
        // SAFETY: a parameter of the array.
        if !p.is_null() && unsafe { OSSL_PARAM_set_uint(p, size.into()) } == 0 {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER, "blake2_get_ctx_params");
            return 0;
        }
        1
    }
}

const SIZE_T: usize = size_of::<usize>();
const INT: usize = size_of::<c_int>();

static DEFAULT_GETTABLE: Params<5> = Params([
    defn(
        OSSL_DIGEST_PARAM_BLOCK_SIZE,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_DIGEST_PARAM_SIZE, OSSL_PARAM_UNSIGNED_INTEGER, SIZE_T),
    defn(OSSL_DIGEST_PARAM_XOF, OSSL_PARAM_INTEGER, INT),
    defn(OSSL_DIGEST_PARAM_ALGID_ABSENT, OSSL_PARAM_INTEGER, INT),
    PARAM_END,
]);
static SSL3_SETTABLE: Params<2> = Params([
    bare(OSSL_DIGEST_PARAM_SSL3_MS, OSSL_PARAM_OCTET_STRING),
    PARAM_END,
]);
static XOF_CTX_PARAMS: Params<3> = Params([
    bare(OSSL_DIGEST_PARAM_XOFLEN, OSSL_PARAM_UNSIGNED_INTEGER),
    bare(OSSL_DIGEST_PARAM_SIZE, OSSL_PARAM_UNSIGNED_INTEGER),
    PARAM_END,
]);
static BLAKE2_CTX_PARAMS: Params<2> = Params([
    bare(OSSL_DIGEST_PARAM_SIZE, OSSL_PARAM_UNSIGNED_INTEGER),
    PARAM_END,
]);

ffi_callback! {
    /// `ossl_digest_default_gettable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn default_gettable_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        DEFAULT_GETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// SHA-1's and MD5-SHA1's settable context parameters.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn ssl3_settable_ctx_params(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SSL3_SETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// SHAKE's and KECCAK-KMAC's gettable and settable context parameters.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn xof_ctx_params(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        XOF_CTX_PARAMS.0.as_ptr()
    }
}

ffi_callback! {
    /// BLAKE2's gettable and settable context parameters.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn blake2_ctx_params(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        BLAKE2_CTX_PARAMS.0.as_ptr()
    }
}

type NewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type InitFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type UpdateFn = unsafe extern "C" fn(*mut c_void, *const u8, usize) -> c_int;
type FinalFn = unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize) -> c_int;
type FreeFn = unsafe extern "C" fn(*mut c_void);
type DupFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type CopyFn = unsafe extern "C" fn(*mut c_void, *mut c_void);
type GetParamsFn = unsafe extern "C" fn(*mut OSSL_PARAM) -> c_int;
type GettableFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;
type CtxParamsFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;
type SetCtxFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type GetCtxFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;

/// The table and per-algorithm functions of one digest of a family.
macro_rules! digest {
    ($name:ident, $kind:expr, $family:ident) => {
        pub(crate) mod $name {
            use super::*;

            ffi_callback! {
                /// `newctx`.
                ///
                /// # Safety
                /// No preconditions.
                pub(crate) unsafe extern "C" fn newctx(_provctx: *mut c_void) -> *mut c_void
                where failure = ptr::null_mut(), library = ERR_LIB_PROV
                {
                    new_context($kind)
                }
            }

            ffi_callback! {
                /// `get_params`: the block size, size, and flags.
                ///
                /// # Safety
                /// `params` is NULL or a parameter array.
                pub(crate) unsafe extern "C" fn get_params(params: *mut OSSL_PARAM) -> c_int
                where failure = 0, library = ERR_LIB_PROV
                {
                    // SAFETY: the caller's guarantee.
                    unsafe { default_get_params($kind, params, concat!(stringify!($name), "_get_params")) }
                }
            }

            $family!();
        }
    };
}

/// A dispatch table: the functions every digest has, the family's, and the end.
macro_rules! table {
    ($($extra:expr),* $(,)?) => {
        [
            entry!(OSSL_FUNC_DIGEST_NEWCTX, newctx, NewCtxFn),
            entry!(OSSL_FUNC_DIGEST_UPDATE, update, UpdateFn),
            entry!(OSSL_FUNC_DIGEST_FINAL, final_, FinalFn),
            entry!(OSSL_FUNC_DIGEST_FREECTX, freectx, FreeFn),
            entry!(OSSL_FUNC_DIGEST_DUPCTX, dupctx, DupFn),
            entry!(OSSL_FUNC_DIGEST_COPYCTX, copyctx, CopyFn),
            entry!(OSSL_FUNC_DIGEST_GET_PARAMS, get_params, GetParamsFn),
            entry!(OSSL_FUNC_DIGEST_GETTABLE_PARAMS, default_gettable_params, GettableFn),
            $($extra,)*
            END,
        ]
    };
}

macro_rules! plain {
    () => {
        pub(crate) static TABLE: Dispatch<10> =
            Dispatch(table![entry!(OSSL_FUNC_DIGEST_INIT, init, InitFn)]);
    };
}

macro_rules! ssl3 {
    () => {
        pub(crate) static TABLE: Dispatch<12> = Dispatch(table![
            entry!(OSSL_FUNC_DIGEST_INIT, ssl3_init, InitFn),
            entry!(
                OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,
                ssl3_settable_ctx_params,
                CtxParamsFn
            ),
            entry!(
                OSSL_FUNC_DIGEST_SET_CTX_PARAMS,
                ssl3_set_ctx_params,
                SetCtxFn
            ),
        ]);
    };
}

macro_rules! xof {
    () => {
        pub(crate) static TABLE: Dispatch<15> = Dispatch(table![
            entry!(OSSL_FUNC_DIGEST_SQUEEZE, squeeze, FinalFn),
            entry!(OSSL_FUNC_DIGEST_INIT, xof_init, InitFn),
            entry!(
                OSSL_FUNC_DIGEST_SET_CTX_PARAMS,
                xof_set_ctx_params,
                SetCtxFn
            ),
            entry!(
                OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,
                xof_ctx_params,
                CtxParamsFn
            ),
            entry!(
                OSSL_FUNC_DIGEST_GET_CTX_PARAMS,
                xof_get_ctx_params,
                GetCtxFn
            ),
            entry!(
                OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS,
                xof_ctx_params,
                CtxParamsFn
            ),
        ]);
    };
}

macro_rules! blake2 {
    () => {
        pub(crate) static TABLE: Dispatch<14> = Dispatch(table![
            entry!(OSSL_FUNC_DIGEST_INIT, blake2_init, InitFn),
            entry!(
                OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS,
                blake2_ctx_params,
                CtxParamsFn
            ),
            entry!(
                OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,
                blake2_ctx_params,
                CtxParamsFn
            ),
            entry!(
                OSSL_FUNC_DIGEST_GET_CTX_PARAMS,
                blake2_get_ctx_params,
                GetCtxFn
            ),
            entry!(
                OSSL_FUNC_DIGEST_SET_CTX_PARAMS,
                blake2_set_ctx_params,
                SetCtxFn
            ),
        ]);
    };
}

digest!(sha1, Kind::Sha1, ssl3);
digest!(sha224, Kind::Sha224, plain);
digest!(sha256, Kind::Sha256, plain);
digest!(sha256_192, Kind::Sha256_192, plain);
digest!(sha384, Kind::Sha384, plain);
digest!(sha512, Kind::Sha512, plain);
digest!(sha512_224, Kind::Sha512_224, plain);
digest!(sha512_256, Kind::Sha512_256, plain);
digest!(sha3_224, Kind::Sha3_224, plain);
digest!(sha3_256, Kind::Sha3_256, plain);
digest!(sha3_384, Kind::Sha3_384, plain);
digest!(sha3_512, Kind::Sha3_512, plain);
digest!(keccak_224, Kind::Keccak224, plain);
digest!(keccak_256, Kind::Keccak256, plain);
digest!(keccak_384, Kind::Keccak384, plain);
digest!(keccak_512, Kind::Keccak512, plain);
digest!(keccak_kmac_128, Kind::KeccakKmac128, xof);
digest!(keccak_kmac_256, Kind::KeccakKmac256, xof);
digest!(shake_128, Kind::Shake128, xof);
digest!(shake_256, Kind::Shake256, xof);
digest!(blake2s256, Kind::Blake2s256, blake2);
digest!(blake2b512, Kind::Blake2b512, blake2);
digest!(sm3, Kind::Sm3, plain);
digest!(md5, Kind::Md5, plain);
digest!(md5_sha1, Kind::Md5Sha1, ssl3);
digest!(ripemd160, Kind::Ripemd160, plain);
digest!(nullmd, Kind::Null, plain);

/// `deflt_digests`, with the reference's names (`PROV_NAMES_*`) in its order.
pub(crate) static DEFAULT_DIGESTS: Algorithms<28> = Algorithms([
    alg(c"SHA1:SHA-1:SSL3-SHA1:1.3.14.3.2.26", &sha1::TABLE),
    alg(
        c"SHA2-224:SHA-224:SHA224:2.16.840.1.101.3.4.2.4",
        &sha224::TABLE,
    ),
    alg(
        c"SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1",
        &sha256::TABLE,
    ),
    alg(c"SHA2-256/192:SHA-256/192:SHA256-192", &sha256_192::TABLE),
    alg(
        c"SHA2-384:SHA-384:SHA384:2.16.840.1.101.3.4.2.2",
        &sha384::TABLE,
    ),
    alg(
        c"SHA2-512:SHA-512:SHA512:2.16.840.1.101.3.4.2.3",
        &sha512::TABLE,
    ),
    alg(
        c"SHA2-512/224:SHA-512/224:SHA512-224:2.16.840.1.101.3.4.2.5",
        &sha512_224::TABLE,
    ),
    alg(
        c"SHA2-512/256:SHA-512/256:SHA512-256:2.16.840.1.101.3.4.2.6",
        &sha512_256::TABLE,
    ),
    alg(c"SHA3-224:2.16.840.1.101.3.4.2.7", &sha3_224::TABLE),
    alg(c"SHA3-256:2.16.840.1.101.3.4.2.8", &sha3_256::TABLE),
    alg(c"SHA3-384:2.16.840.1.101.3.4.2.9", &sha3_384::TABLE),
    alg(c"SHA3-512:2.16.840.1.101.3.4.2.10", &sha3_512::TABLE),
    alg(c"KECCAK-224", &keccak_224::TABLE),
    alg(c"KECCAK-256", &keccak_256::TABLE),
    alg(c"KECCAK-384", &keccak_384::TABLE),
    alg(c"KECCAK-512", &keccak_512::TABLE),
    alg(c"KECCAK-KMAC-128:KECCAK-KMAC128", &keccak_kmac_128::TABLE),
    alg(c"KECCAK-KMAC-256:KECCAK-KMAC256", &keccak_kmac_256::TABLE),
    alg(
        c"SHAKE-128:SHAKE128:2.16.840.1.101.3.4.2.11",
        &shake_128::TABLE,
    ),
    alg(
        c"SHAKE-256:SHAKE256:2.16.840.1.101.3.4.2.12",
        &shake_256::TABLE,
    ),
    alg(
        c"BLAKE2S-256:BLAKE2s256:1.3.6.1.4.1.1722.12.2.2.8",
        &blake2s256::TABLE,
    ),
    alg(
        c"BLAKE2B-512:BLAKE2b512:1.3.6.1.4.1.1722.12.2.1.16",
        &blake2b512::TABLE,
    ),
    alg(c"SM3:1.2.156.10197.1.401", &sm3::TABLE),
    alg(c"MD5:SSL3-MD5:1.2.840.113549.2.5", &md5::TABLE),
    alg(c"MD5-SHA1", &md5_sha1::TABLE),
    alg(
        c"RIPEMD-160:RIPEMD160:RIPEMD:RMD160:1.3.36.3.2.1",
        &ripemd160::TABLE,
    ),
    alg(c"NULL", &nullmd::TABLE),
    ALG_END,
]);

/// The default provider's digest table.
pub(crate) fn default_digests() -> *const OSSL_ALGORITHM {
    DEFAULT_DIGESTS.0.as_ptr()
}
