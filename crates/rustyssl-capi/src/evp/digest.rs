//! Message digest methods (`EVP_MD_fetch(3)`, `EVP_DigestInit(3)`'s method functions): an
//! `EVP_MD` made from a provider's digest algorithm (`evp_md_from_algorithm` in
//! `crypto/evp/digest.c`), fetched by name and properties, and its names, provider, sizes,
//! flags, and parameters.
//!
//! As in OpenSSL, a digest algorithm must offer either `digest` alone or the context functions
//! (`newctx`, `init`, `update`, `final`, `freectx`, and optionally `squeeze`), and its block
//! size, size, and XOF and absent-AlgorithmIdentifier flags are read from its parameters when
//! it's made, and its NID from the legacy digest its names map to (`set_legacy_nid`). The
//! static legacy digests (`EVP_sha256()`, `legacy_md.rs`) are methods too, without a provider
//! and with references that aren't counted, as OpenSSL's `EVP_ORIG_GLOBAL` ones, and so are
//! the digests applications make (`EVP_MD_meth_new(3)`, `md_meth.rs`; `EVP_ORIG_METH`), whose
//! sizes, flags, and C functions are set after they're made. A digest's C functions (the
//! legacy ones, which a context runs on its `md_data`) are kept with it: the static digests'
//! own, an application's, or none for a fetched one.

use core::ffi::{CStr, c_char, c_int, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::ffi::CString;
use std::sync::{Mutex, PoisonError};

use rustyssl_abi::{
    ERR_LIB_EVP, ERR_R_EVP_LIB, ERR_R_INTERNAL_ERROR, EVP_MD, EVP_MD_FLAG_DIGALGID_ABSENT,
    EVP_MD_FLAG_XOF, EVP_R_CACHE_CONSTANTS_FAILED, EVP_R_CANNOT_GET_PARAMETERS,
    EVP_R_INVALID_PROVIDER_FUNCTIONS, EVP_R_MESSAGE_DIGEST_IS_NULL, OBJ_NAME_TYPE_MD_METH,
    OSSL_ALGORITHM, OSSL_DIGEST_PARAM_ALGID_ABSENT, OSSL_DIGEST_PARAM_BLOCK_SIZE,
    OSSL_DIGEST_PARAM_SIZE, OSSL_DIGEST_PARAM_XOF, OSSL_FUNC_DIGEST_COPYCTX,
    OSSL_FUNC_DIGEST_DIGEST, OSSL_FUNC_DIGEST_DUPCTX, OSSL_FUNC_DIGEST_FINAL,
    OSSL_FUNC_DIGEST_FREECTX, OSSL_FUNC_DIGEST_GET_CTX_PARAMS, OSSL_FUNC_DIGEST_GET_PARAMS,
    OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, OSSL_FUNC_DIGEST_GETTABLE_PARAMS, OSSL_FUNC_DIGEST_INIT,
    OSSL_FUNC_DIGEST_NEWCTX, OSSL_FUNC_DIGEST_SET_CTX_PARAMS, OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_DIGEST_SQUEEZE, OSSL_FUNC_DIGEST_UPDATE, OSSL_LIB_CTX, OSSL_OP_DIGEST, OSSL_PARAM,
    OSSL_PROVIDER,
};

use super::fetch::{self, Kind};
use crate::err;
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::params::{construct, end};
use crate::provider::Ptr;

type GetParamsFn = unsafe extern "C" fn(*mut OSSL_PARAM) -> c_int;
type GettableParamsFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;
type AnyFn = unsafe extern "C" fn();
pub(crate) type NewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
pub(crate) type InitFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
pub(crate) type UpdateFn = unsafe extern "C" fn(*mut c_void, *const u8, usize) -> c_int;
pub(crate) type FinalFn = unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize) -> c_int;
pub(crate) type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
pub(crate) type DupCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
pub(crate) type CopyCtxFn = unsafe extern "C" fn(*mut c_void, *mut c_void);
pub(crate) type SetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
pub(crate) type GetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
pub(crate) type CtxParamsListFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;

/// A digest algorithm's context functions, as its dispatch table gave them.
#[derive(Default, Clone, Copy)]
pub(crate) struct Funcs {
    pub(crate) newctx: Option<NewCtxFn>,
    pub(crate) init: Option<InitFn>,
    pub(crate) update: Option<UpdateFn>,
    pub(crate) final_: Option<FinalFn>,
    pub(crate) squeeze: Option<FinalFn>,
    pub(crate) freectx: Option<FreeCtxFn>,
    pub(crate) dupctx: Option<DupCtxFn>,
    pub(crate) copyctx: Option<CopyCtxFn>,
    pub(crate) set_ctx_params: Option<SetCtxParamsFn>,
    pub(crate) get_ctx_params: Option<GetCtxParamsFn>,
    pub(crate) settable_ctx_params: Option<CtxParamsListFn>,
    pub(crate) gettable_ctx_params: Option<CtxParamsListFn>,
}

/// Where a digest method came from (`EVP_ORIG_*`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    /// Fetched from a provider, reference counted.
    Dynamic,
    /// One of the static legacy digests (`EVP_sha256()`): references aren't counted.
    Global,
    /// Made by an application (`EVP_MD_meth_new`): references aren't counted, and
    /// `EVP_MD_meth_free` frees it.
    Meth,
}

/// A legacy digest's `init` (and `cleanup`): the context.
pub(crate) type LegacyInitFn = unsafe extern "C" fn(*mut rustyssl_abi::EVP_MD_CTX) -> c_int;
/// A legacy digest's `update`.
pub(crate) type LegacyUpdateFn =
    unsafe extern "C" fn(*mut rustyssl_abi::EVP_MD_CTX, *const c_void, usize) -> c_int;
/// A legacy digest's `final`.
pub(crate) type LegacyFinalFn =
    unsafe extern "C" fn(*mut rustyssl_abi::EVP_MD_CTX, *mut u8) -> c_int;
/// A legacy digest's `copy`.
pub(crate) type LegacyCopyFn =
    unsafe extern "C" fn(*mut rustyssl_abi::EVP_MD_CTX, *const rustyssl_abi::EVP_MD_CTX) -> c_int;
/// A legacy digest's `md_ctrl`.
pub(crate) type LegacyCtrlFn =
    unsafe extern "C" fn(*mut rustyssl_abi::EVP_MD_CTX, c_int, c_int, *mut c_void) -> c_int;

/// A digest's C functions and the size of their state (`md_data`), as OpenSSL's `EVP_MD`
/// holds them.
#[derive(Default, Clone, Copy)]
pub(crate) struct Legacy {
    pub(crate) ctx_size: c_int,
    pub(crate) init: Option<LegacyInitFn>,
    pub(crate) update: Option<LegacyUpdateFn>,
    pub(crate) final_: Option<LegacyFinalFn>,
    pub(crate) copy: Option<LegacyCopyFn>,
    pub(crate) cleanup: Option<LegacyInitFn>,
    pub(crate) ctrl: Option<LegacyCtrlFn>,
}

/// The sizes and flags `EVP_MD_meth_set_*` set once.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Field {
    BlockSize,
    MdSize,
    Flags,
}

/// A digest method (`EVP_MD`): made from a provider's algorithm, or a static legacy one.
pub(crate) struct Md {
    pub(crate) origin: Origin,
    name_id: u32,
    /// The first name, for fetched methods; a static one's is its NID's short name.
    type_name: Option<CString>,
    pub(crate) pkey_type: c_int,
    /// The provider's description, a static string of its, or NULL.
    description: Ptr<c_char>,
    /// The provider, with a reference.
    pub(crate) prov: Ptr<OSSL_PROVIDER>,
    pub(crate) nid: c_int,
    block_size: AtomicI32,
    md_size: AtomicI32,
    flags: AtomicU64,
    /// The C functions (`EVP_MD_meth_set_*` sets an application's).
    legacy: Mutex<Legacy>,
    get_params: Option<GetParamsFn>,
    gettable_params: Option<GettableParamsFn>,
    /// The context functions.
    pub(crate) funcs: Funcs,
}

impl Md {
    /// A static legacy digest: no provider, the NIDs, sizes, and flags of OpenSSL's
    /// `EVP_sha256()`-style definitions.
    pub(crate) fn legacy(
        nid: c_int,
        pkey_type: c_int,
        md_size: c_int,
        flags: c_ulong,
        block_size: c_int,
        legacy: Legacy,
    ) -> Self {
        Self {
            origin: Origin::Global,
            name_id: 0,
            type_name: None,
            pkey_type,
            description: Ptr(ptr::null_mut()),
            prov: Ptr(ptr::null_mut()),
            nid,
            block_size: AtomicI32::new(block_size),
            md_size: AtomicI32::new(md_size),
            flags: AtomicU64::new(flags),
            legacy: Mutex::new(legacy),
            get_params: None,
            gettable_params: None,
            funcs: Funcs::default(),
        }
    }

    /// The digest's size (`md_size`).
    pub(crate) fn md_size(&self) -> c_int {
        self.md_size.load(Ordering::Relaxed)
    }

    /// The digest's block size.
    pub(crate) fn block_size(&self) -> c_int {
        self.block_size.load(Ordering::Relaxed)
    }

    /// The digest's flags.
    pub(crate) fn flags(&self) -> c_ulong {
        self.flags.load(Ordering::Relaxed)
    }

    /// The digest's C functions, as they are now.
    pub(crate) fn legacy_fns(&self) -> Legacy {
        *self.legacy.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Changes the C functions (an application's digest only).
    pub(crate) fn set_legacy(&self, change: impl FnOnce(&mut Legacy) -> bool) -> bool {
        change(&mut self.legacy.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// `EVP_MD_meth_set_*` of a size or the flags: sets `field` if it is still 0.
    pub(crate) fn set_once(&self, field: Field, value: i64) -> bool {
        match field {
            Field::BlockSize | Field::MdSize => {
                let target = if field == Field::BlockSize {
                    &self.block_size
                } else {
                    &self.md_size
                };
                let Ok(v) = c_int::try_from(value) else {
                    return false;
                };
                target
                    .compare_exchange(0, v, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            }
            Field::Flags => {
                let v = u64::from_ne_bytes(value.to_ne_bytes());
                self.flags
                    .compare_exchange(0, v, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            }
        }
    }

    /// An application's digest (`EVP_MD_meth_new`), or a copy of `from` (`EVP_MD_meth_dup`).
    pub(crate) fn meth(nid: c_int, pkey_type: c_int, from: Option<&Self>) -> Self {
        let mut md = Self::legacy(nid, pkey_type, 0, 0, 0, Legacy::default());
        md.origin = Origin::Meth;
        if let Some(f) = from {
            md.block_size = AtomicI32::new(f.block_size());
            md.md_size = AtomicI32::new(f.md_size());
            md.flags = AtomicU64::new(f.flags());
            md.legacy = Mutex::new(f.legacy_fns());
            md.description = Ptr(f.description.0);
        }
        md
    }

    /// The provider's context, which the parameter-list functions take.
    pub(crate) fn provider_ctx(&self) -> *mut c_void {
        // SAFETY: the method holds a reference to its live provider.
        unsafe { crate::provider::OSSL_PROVIDER_get0_provider_ctx(self.prov.0) }
    }
}

handle_type!(EVP_MD => Md);

impl Drop for Md {
    fn drop(&mut self) {
        // SAFETY: the provider reference the method holds.
        unsafe { OSSL_PROVIDER::free(self.prov.0) };
    }
}

/// A dispatch table's function as the type its id stands for.
///
/// # Safety
/// `F` is the function pointer type `f` really has.
unsafe fn cast<F: Copy>(f: AnyFn) -> F {
    // SAFETY: the caller's guarantee; function pointers all have one size.
    unsafe { core::mem::transmute_copy(&f) }
}

/// `evp_do_md_getparams` with the method's own `get_params`: OpenSSL's result (0 with an error
/// if there's none).
#[track_caller]
fn get_params(md: &Md, params: *mut OSSL_PARAM) -> c_int {
    let Some(get) = md.get_params else {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_CANNOT_GET_PARAMETERS,
            "evp_do_md_getparams",
        );
        return 0;
    };
    // SAFETY: the provider's function with the caller's array.
    unsafe { get(params) }
}

/// `evp_md_cache_constants`: reads the sizes and flags. False if that fails.
fn cache_constants(md: &mut Md) -> bool {
    let (mut block, mut size, mut xof, mut absent): (usize, usize, c_int, c_int) = (0, 0, 0, 0);
    let mut params = [
        construct(
            OSSL_DIGEST_PARAM_BLOCK_SIZE.as_ptr(),
            rustyssl_crypto::params::UNSIGNED_INTEGER,
            (&raw mut block).cast(),
            size_of::<usize>(),
        ),
        construct(
            OSSL_DIGEST_PARAM_SIZE.as_ptr(),
            rustyssl_crypto::params::UNSIGNED_INTEGER,
            (&raw mut size).cast(),
            size_of::<usize>(),
        ),
        construct(
            OSSL_DIGEST_PARAM_XOF.as_ptr(),
            rustyssl_crypto::params::INTEGER,
            (&raw mut xof).cast(),
            size_of::<c_int>(),
        ),
        construct(
            OSSL_DIGEST_PARAM_ALGID_ABSENT.as_ptr(),
            rustyssl_crypto::params::INTEGER,
            (&raw mut absent).cast(),
            size_of::<c_int>(),
        ),
        end(),
    ];
    let ok = get_params(md, params.as_mut_ptr()) > 0;
    let (Ok(block), Ok(size)) = (c_int::try_from(block), c_int::try_from(size)) else {
        return false;
    };
    if !ok {
        return false;
    }
    md.block_size = AtomicI32::new(block);
    md.md_size = AtomicI32::new(size);
    let mut flags = 0u64;
    if xof != 0 {
        flags |= u64::try_from(EVP_MD_FLAG_XOF).unwrap_or(0);
    }
    if absent != 0 {
        flags |= u64::try_from(EVP_MD_FLAG_DIGALGID_ABSENT).unwrap_or(0);
    }
    md.flags = AtomicU64::new(flags);
    true
}

/// `evp_md_from_algorithm`: a digest method from the provider's algorithm, with one reference,
/// or NULL with an error.
///
/// # Safety
/// `algo`'s names, description, and table are the provider's, valid while it lives; `prov` is
/// a live provider.
unsafe fn from_algorithm(
    name_id: u32,
    algo: &OSSL_ALGORITHM,
    prov: *mut OSSL_PROVIDER,
) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    let names = unsafe { CStr::from_ptr(algo.algorithm_names) }.to_bytes();
    let first = names.split(|&c| c == b':').next().unwrap_or(names);
    let Ok(type_name) = CString::new(first) else {
        err::raise(ERR_LIB_EVP, ERR_R_EVP_LIB, "evp_md_from_algorithm");
        return ptr::null_mut();
    };
    let mut functions: Vec<(c_int, AnyFn)> = Vec::new();
    let mut funcs = Funcs::default();
    let mut get_params_fn = None;
    let mut gettable_params = None;
    let mut counted = 0;
    let mut has_digest = false;
    let mut at = algo.implementation;
    // SAFETY: the caller's guarantee: the table is ended by a zero id.
    while let Some(d) = unsafe { at.as_ref() } {
        if d.function_id == 0 {
            break;
        }
        at = at.wrapping_add(1);
        let Some(f) = d.function else { continue };
        let id = d.function_id;
        // The first of each id counts, as OpenSSL keeps only the first.
        if functions.iter().any(|(i, _)| *i == id) {
            continue;
        }
        functions.push((id, f));
        /// Stores `f` as the function its id stands for.
        macro_rules! set {
            ($field:ident) => {
                // SAFETY: the provider's guarantee of the function type for this id.
                funcs.$field = Some(unsafe { cast(f) })
            };
        }
        match id {
            OSSL_FUNC_DIGEST_NEWCTX => set!(newctx),
            OSSL_FUNC_DIGEST_INIT => set!(init),
            OSSL_FUNC_DIGEST_UPDATE => set!(update),
            OSSL_FUNC_DIGEST_FINAL => set!(final_),
            OSSL_FUNC_DIGEST_SQUEEZE => set!(squeeze),
            OSSL_FUNC_DIGEST_FREECTX => set!(freectx),
            OSSL_FUNC_DIGEST_DUPCTX => set!(dupctx),
            OSSL_FUNC_DIGEST_COPYCTX => set!(copyctx),
            OSSL_FUNC_DIGEST_SET_CTX_PARAMS => set!(set_ctx_params),
            OSSL_FUNC_DIGEST_GET_CTX_PARAMS => set!(get_ctx_params),
            OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS => set!(settable_ctx_params),
            OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS => set!(gettable_ctx_params),
            _ => {}
        }
        match id {
            OSSL_FUNC_DIGEST_NEWCTX
            | OSSL_FUNC_DIGEST_INIT
            | OSSL_FUNC_DIGEST_UPDATE
            | OSSL_FUNC_DIGEST_FINAL
            | OSSL_FUNC_DIGEST_SQUEEZE
            | OSSL_FUNC_DIGEST_FREECTX => counted += 1,
            OSSL_FUNC_DIGEST_DIGEST => has_digest = true,
            // SAFETY: the provider's guarantee of the type for this id.
            OSSL_FUNC_DIGEST_GET_PARAMS => get_params_fn = Some(unsafe { cast::<GetParamsFn>(f) }),
            OSSL_FUNC_DIGEST_GETTABLE_PARAMS => {
                // SAFETY: as above.
                gettable_params = Some(unsafe { cast::<GettableParamsFn>(f) });
            }
            OSSL_FUNC_DIGEST_DUPCTX
            | OSSL_FUNC_DIGEST_SET_CTX_PARAMS
            | OSSL_FUNC_DIGEST_GET_CTX_PARAMS
            | OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS
            | OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS
            | OSSL_FUNC_DIGEST_COPYCTX => {}
            _ => {
                functions.pop();
            }
        }
    }
    if (counted != 0 && counted != 5 && counted != 6) || (counted == 0 && !has_digest) {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_INVALID_PROVIDER_FUNCTIONS,
            "evp_md_from_algorithm",
        );
        return ptr::null_mut();
    }
    // SAFETY: the caller's live provider; the method holds the reference.
    if !unsafe { OSSL_PROVIDER::up_ref(prov) } {
        return ptr::null_mut();
    }
    // `set_legacy_nid`: the NID of the legacy digest any of its names has (0 for none; a clash
    // between two fails).
    let mut nid = 0;
    for n in fetch::names_of(prov, name_id) {
        let Ok(c) = CString::new(n) else { continue };
        // SAFETY: a string and a type.
        let legacy =
            unsafe { crate::objects::name::OBJ_NAME_get(c.as_ptr(), OBJ_NAME_TYPE_MD_METH) };
        // SAFETY: the table holds digest methods for this type.
        let Some(m) = (unsafe { method(legacy.cast()) }) else {
            continue;
        };
        if nid != 0 && nid != m.nid {
            err::raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR, "evp_md_from_algorithm");
            return ptr::null_mut();
        }
        nid = m.nid;
    }
    let mut md = Md {
        origin: Origin::Dynamic,
        name_id,
        type_name: Some(type_name),
        pkey_type: 0,
        description: Ptr(algo.algorithm_description.cast_mut()),
        prov: Ptr(prov),
        nid,
        block_size: AtomicI32::new(0),
        md_size: AtomicI32::new(0),
        flags: AtomicU64::new(0),
        legacy: Mutex::new(Legacy::default()),
        get_params: get_params_fn,
        gettable_params,
        funcs,
    };
    if !cache_constants(&mut md) {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_CACHE_CONSTANTS_FAILED,
            "evp_md_from_algorithm",
        );
        return ptr::null_mut();
    }
    EVP_MD::new_handle(md).cast()
}

/// Adds a reference to a digest method in a store.
unsafe fn up_ref(md: *mut c_void) {
    // SAFETY: a live method.
    unsafe { EVP_MD::up_ref(md.cast()) };
}

/// Drops a reference to a digest method in a store.
unsafe fn free(md: *mut c_void) {
    // SAFETY: a reference the store held.
    unsafe { EVP_MD::free(md.cast()) };
}

/// Digest methods to fetching.
static DIGESTS: Kind = Kind {
    operation: OSSL_OP_DIGEST,
    from_algorithm,
    up_ref,
    free,
};

/// The method behind `md`, or `None` for NULL.
///
/// # Safety
/// `md` is NULL or a live digest method.
pub(crate) unsafe fn method<'a>(md: *const EVP_MD) -> Option<&'a Md> {
    // SAFETY: the caller's guarantee.
    unsafe { EVP_MD::get(md) }
}

/// A C string argument, `None` for NULL.
///
/// # Safety
/// `s` is NULL or a string.
unsafe fn text<'a>(s: *const c_char) -> Option<&'a CStr> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) })
}

ffi_export! {
    /// The digest `algorithm` from the providers of `ctx` (the thread's default context for
    /// NULL) that best matches `properties`, with a reference; NULL with an error if none does.
    ///
    /// # Safety
    /// `ctx` is NULL or a live library context; `algorithm` and `properties` are NULL or
    /// strings.
    pub unsafe extern "C" fn EVP_MD_fetch(ctx: *mut OSSL_LIB_CTX, algorithm: *const c_char, properties: *const c_char) -> *mut EVP_MD
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let name = unsafe { text(algorithm) };
        // SAFETY: as above.
        let props = unsafe { text(properties) };
        // SAFETY: the caller's guarantee.
        unsafe { fetch::fetch(ctx, &DIGESTS, name, props) }.cast()
    }
}

ffi_export! {
    /// Adds a reference. Returns 1.
    ///
    /// # Safety
    /// `md` is a live digest method.
    pub unsafe extern "C" fn EVP_MD_up_ref(md: *mut EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if unsafe { method(md) }.is_some_and(|m| m.origin == Origin::Dynamic) {
            // SAFETY: as above.
            unsafe { EVP_MD::up_ref(md) };
        }
        1
    }
}

ffi_export! {
    /// Drops a reference; NULL does nothing.
    ///
    /// # Safety
    /// `md` is NULL or a digest method the caller holds, not used afterwards.
    pub unsafe extern "C" fn EVP_MD_free(md: *mut EVP_MD)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if unsafe { method(md) }.is_some_and(|m| m.origin == Origin::Dynamic) {
            // SAFETY: as above.
            unsafe { EVP_MD::free(md) };
        }
    }
}

ffi_export! {
    /// The algorithm's first name, as its provider gave it; NULL for NULL.
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_get0_name(md: *const EVP_MD) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(md) }) else { return ptr::null() };
        match &m.type_name {
            Some(name) => name.as_ptr(),
            // SAFETY: no preconditions.
            None => unsafe { crate::objects::OBJ_nid2sn(m.nid) },
        }
    }
}

ffi_export! {
    /// The provider's description of the algorithm, or else its NID's long name. NULL for NULL
    /// (OpenSSL would crash, docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_get0_description(md: *const EVP_MD) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(md) }) else { return ptr::null() };
        if !m.description.0.is_null() {
            return m.description.0;
        }
        // SAFETY: no preconditions.
        unsafe { crate::objects::OBJ_nid2ln(m.nid) }
    }
}

ffi_export! {
    /// Whether `name` is one of the algorithm's names (compared as the context's names are).
    ///
    /// # Safety
    /// `md` is NULL or a live digest method; `name` is NULL or a string.
    pub unsafe extern "C" fn EVP_MD_is_a(md: *const EVP_MD, name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(md) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        let n = unsafe { text(name) }.map_or(&b""[..], CStr::to_bytes);
        if m.prov.0.is_null() {
            // A static or application's digest compares its name's number with `name`'s in the default
            // context (so two unknown names are "equal", as in OpenSSL).
            // SAFETY: the caller's live method.
            let own_name = unsafe { EVP_MD_get0_name(md) };
            // SAFETY: a static string or NULL.
            let own = unsafe { text(own_name) }.map_or(&b""[..], CStr::to_bytes);
            return c_int::from(fetch::number_in(ptr::null(), own) == fetch::number_in(ptr::null(), n));
        }
        c_int::from(fetch::number_in(m.prov.0, n) == m.name_id)
    }
}

/// `EVP_MD_names_do_all`'s callback.
type NameFn = unsafe extern "C" fn(*const c_char, *mut c_void);

ffi_export! {
    /// Calls `fn_` with each of the algorithm's names, in the order the context learned them.
    /// Returns 1 if it has any (0 for NULL, where OpenSSL would crash; docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `md` is NULL or a live digest method; `fn_` is a function of the documented type.
    pub unsafe extern "C" fn EVP_MD_names_do_all(md: *const EVP_MD, fn_: Option<NameFn>, data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(md) }) else { return 0 };
        if m.prov.0.is_null() {
            // A static or application's digest has no names of its own to list.
            return 1;
        }
        let names = fetch::names_of(m.prov.0, m.name_id);
        for n in &names {
            let Ok(c) = CString::new(n.clone()) else { continue };
            if let Some(f) = fn_ {
                // SAFETY: the caller's callback with a string and its data.
                unsafe { f(c.as_ptr(), data) };
            }
        }
        c_int::from(!names.is_empty())
    }
}

ffi_export! {
    /// The provider the method came from (NULL for NULL, docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_get0_provider(md: *const EVP_MD) -> *const OSSL_PROVIDER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(md) }.map_or(ptr::null(), |m| m.prov.0.cast_const())
    }
}

/// `EVP_MD_do_all_provided`'s callback.
type DoAllFn = unsafe extern "C" fn(*mut EVP_MD, *mut c_void);

ffi_export! {
    /// Calls `fn_` with each digest method the active providers of `libctx` offer, in the
    /// store's order.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `fn_` is a function of the documented type.
    pub unsafe extern "C" fn EVP_MD_do_all_provided(libctx: *mut OSSL_LIB_CTX, fn_: Option<DoAllFn>, arg: *mut c_void)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let all = unsafe { fetch::all(libctx, &DIGESTS) };
        for m in &all {
            if let Some(f) = fn_ {
                // SAFETY: the caller's callback with a method held for the call.
                unsafe { f(m.as_ptr().cast(), arg) };
            }
        }
    }
}

ffi_export! {
    /// Asks the algorithm for `params`: its result, or 0 (for NULL, or no `get_params`, with an
    /// error).
    ///
    /// # Safety
    /// `digest` is NULL or a live digest method; `params` is an array the algorithm may fill.
    pub unsafe extern "C" fn EVP_MD_get_params(digest: *const EVP_MD, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(digest) }) else { return 0 };
        match m.get_params {
            // SAFETY: the provider's function with the caller's array.
            Some(get) => unsafe { get(params) },
            None => 0,
        }
    }
}

ffi_export! {
    /// The parameters the algorithm can report, or NULL.
    ///
    /// # Safety
    /// `digest` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_gettable_params(digest: *const EVP_MD) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(digest) }) else { return ptr::null() };
        let Some(gettable) = m.gettable_params else { return ptr::null() };
        // SAFETY: a live provider.
        let provctx = unsafe { crate::provider::OSSL_PROVIDER_get0_provider_ctx(m.prov.0) };
        // SAFETY: the provider's function with its context.
        unsafe { gettable(provctx) }
    }
}

ffi_export! {
    /// The digest's NID: a static digest's own, a fetched one's from the legacy digest any of
    /// its names has (`NID_undef` if none); 0 for NULL (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_get_type(md: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(md) }.map_or(0, |m| m.nid)
    }
}

ffi_export! {
    /// The NID of the signature algorithm the digest pairs with by default
    /// (`NID_sha256WithRSAEncryption` for `EVP_sha256()`); 0 for fetched digests and for NULL
    /// (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_get_pkey_type(md: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(md) }.map_or(0, |m| m.pkey_type)
    }
}

ffi_export! {
    /// The digest's size in octets, or -1 with an error for NULL.
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_get_size(md: *const EVP_MD) -> c_int
    where failure = -1, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(md) }) else {
            err::raise(ERR_LIB_EVP, EVP_R_MESSAGE_DIGEST_IS_NULL, "EVP_MD_get_size");
            return -1;
        };
        m.md_size()
    }
}

ffi_export! {
    /// The digest's block size in octets, or -1 with an error for NULL.
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_get_block_size(md: *const EVP_MD) -> c_int
    where failure = -1, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(md) }) else {
            err::raise(ERR_LIB_EVP, EVP_R_MESSAGE_DIGEST_IS_NULL, "EVP_MD_get_block_size");
            return -1;
        };
        m.block_size()
    }
}

ffi_export! {
    /// The digest's flags (`EVP_MD_FLAG_XOF`, ...); 0 for NULL (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_get_flags(md: *const EVP_MD) -> c_ulong
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(md) }.map_or(0, Md::flags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustyssl_abi::{
        OSSL_CORE_HANDLE, OSSL_DISPATCH, OSSL_FUNC_PROVIDER_QUERY_OPERATION,
        OSSL_PARAM_UNSIGNED_INTEGER,
    };

    unsafe extern "C" fn newctx(p: *mut c_void) -> *mut c_void {
        p
    }
    unsafe extern "C" fn freectx(_: *mut c_void) {}
    unsafe extern "C" fn init(_: *mut c_void, _: *const OSSL_PARAM) -> c_int {
        1
    }
    unsafe extern "C" fn update(_: *mut c_void, _: *const u8, _: usize) -> c_int {
        1
    }
    unsafe extern "C" fn final_(_: *mut c_void, _: *mut u8, _: *mut usize, _: usize) -> c_int {
        1
    }
    unsafe extern "C" fn get_params(params: *mut OSSL_PARAM) -> c_int {
        // SAFETY: the core's parameter array.
        let p =
            unsafe { crate::params::OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE.as_ptr()) };
        if p.is_null() {
            return 1;
        }
        // SAFETY: a parameter of the array.
        unsafe { crate::params::OSSL_PARAM_set_size_t(p, 24) }
    }

    struct Table<const N: usize>([OSSL_DISPATCH; N]);
    // SAFETY: function pointers only.
    unsafe impl<const N: usize> Sync for Table<N> {}
    struct Algs([OSSL_ALGORITHM; 3]);
    // SAFETY: static strings and tables only.
    unsafe impl Sync for Algs {}

    macro_rules! entry {
        ($id:expr, $f:expr, $ty:ty) => {
            OSSL_DISPATCH {
                function_id: $id,
                // SAFETY: the core casts it back to the type its id stands for.
                function: Some(unsafe { core::mem::transmute::<$ty, unsafe extern "C" fn()>($f) }),
            }
        };
    }
    const END: OSSL_DISPATCH = OSSL_DISPATCH {
        function_id: 0,
        function: None,
    };

    static FUNCTIONS: Table<7> = Table([
        entry!(
            OSSL_FUNC_DIGEST_NEWCTX,
            newctx,
            unsafe extern "C" fn(*mut c_void) -> *mut c_void
        ),
        entry!(
            OSSL_FUNC_DIGEST_FREECTX,
            freectx,
            unsafe extern "C" fn(*mut c_void)
        ),
        entry!(
            OSSL_FUNC_DIGEST_INIT,
            init,
            unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int
        ),
        entry!(
            OSSL_FUNC_DIGEST_UPDATE,
            update,
            unsafe extern "C" fn(*mut c_void, *const u8, usize) -> c_int
        ),
        entry!(
            OSSL_FUNC_DIGEST_FINAL,
            final_,
            unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize) -> c_int
        ),
        entry!(
            OSSL_FUNC_DIGEST_GET_PARAMS,
            get_params,
            unsafe extern "C" fn(*mut OSSL_PARAM) -> c_int
        ),
        END,
    ]);

    static ALGS: Algs = Algs([
        OSSL_ALGORITHM {
            algorithm_names: c"RUST-MD:RMD".as_ptr(),
            property_definition: c"provider=rusttest,x.v=1".as_ptr(),
            implementation: FUNCTIONS.0.as_ptr(),
            algorithm_description: c"a test digest".as_ptr(),
        },
        OSSL_ALGORITHM {
            algorithm_names: c"RUST-MD".as_ptr(),
            property_definition: c"provider=rusttest,x.v=2".as_ptr(),
            implementation: FUNCTIONS.0.as_ptr(),
            algorithm_description: ptr::null(),
        },
        OSSL_ALGORITHM {
            algorithm_names: ptr::null(),
            property_definition: ptr::null(),
            implementation: ptr::null(),
            algorithm_description: ptr::null(),
        },
    ]);

    unsafe extern "C" fn query(
        _: *mut c_void,
        op: c_int,
        no_cache: *mut c_int,
    ) -> *const OSSL_ALGORITHM {
        // SAFETY: the core's flag.
        unsafe { no_cache.write(0) };
        if op == OSSL_OP_DIGEST {
            ALGS.0.as_ptr()
        } else {
            ptr::null()
        }
    }

    static PROVIDER: Table<2> = Table([
        entry!(
            OSSL_FUNC_PROVIDER_QUERY_OPERATION,
            query,
            unsafe extern "C" fn(*mut c_void, c_int, *mut c_int) -> *const OSSL_ALGORITHM
        ),
        END,
    ]);

    unsafe extern "C" fn provider_init(
        handle: *const OSSL_CORE_HANDLE,
        _: *const OSSL_DISPATCH,
        out: *mut *const OSSL_DISPATCH,
        provctx: *mut *mut c_void,
    ) -> c_int {
        // SAFETY: the core's out-parameters.
        unsafe { out.write(PROVIDER.0.as_ptr()) };
        // SAFETY: as above.
        unsafe { provctx.write(handle.cast_mut().cast()) };
        1
    }

    #[test]
    fn fetch_from_a_rust_provider() {
        let _ = OSSL_PARAM_UNSIGNED_INTEGER;
        // SAFETY: no preconditions.
        let ctx = unsafe { crate::libctx::OSSL_LIB_CTX_new() };
        // SAFETY: a live context, a string, and an init function.
        let r = unsafe {
            crate::provider::OSSL_PROVIDER_add_builtin(
                ctx,
                c"rusttest".as_ptr(),
                Some(provider_init),
            )
        };
        assert_eq!(r, 1);
        // SAFETY: as above.
        let prov = unsafe { crate::provider::OSSL_PROVIDER_load(ctx, c"rusttest".as_ptr()) };
        assert!(!prov.is_null());
        // SAFETY: a live context and strings.
        let a = unsafe { EVP_MD_fetch(ctx, c"rmd".as_ptr(), ptr::null()) };
        // SAFETY: as above.
        let b = unsafe { EVP_MD_fetch(ctx, c"RUST-MD".as_ptr(), c"x.v=2".as_ptr()) };
        // SAFETY: as above.
        let a2 = unsafe { EVP_MD_fetch(ctx, c"RUST-MD".as_ptr(), c"".as_ptr()) };
        assert!(!a.is_null() && !b.is_null() && a != b && a == a2);
        // SAFETY: live methods.
        assert_eq!(unsafe { EVP_MD_get_size(a) }, 24);
        // SAFETY: as above.
        let name = unsafe { EVP_MD_get0_name(b) };
        // SAFETY: the method's name, a string.
        let name = unsafe { CStr::from_ptr(name) };
        assert_eq!(name, c"RUST-MD");
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_MD_is_a(a, c"rust-md".as_ptr()) }, 1);
        let mut n = 0i32;
        unsafe extern "C" fn count(_: *mut EVP_MD, data: *mut c_void) {
            // SAFETY: the test's counter.
            unsafe { *data.cast::<i32>() += 1 };
        }
        // SAFETY: a live context and a counting callback.
        unsafe { EVP_MD_do_all_provided(ctx, Some(count), (&raw mut n).cast()) };
        assert_eq!(n, 2);
        for md in [a, b, a2] {
            // SAFETY: each reference the test holds, once.
            unsafe { EVP_MD_free(md) };
        }
        // SAFETY: the test's reference.
        assert_eq!(unsafe { crate::provider::OSSL_PROVIDER_unload(prov) }, 1);
        // SAFETY: unloaded, so nothing to fetch.
        assert!(unsafe { EVP_MD_fetch(ctx, c"RMD".as_ptr(), ptr::null()) }.is_null());
        // SAFETY: the context and everything it holds go.
        unsafe { crate::libctx::OSSL_LIB_CTX_free(ctx) };
        crate::err::take_all();
    }

    /// docs/DEVIATIONS.md: NULL digests.
    #[test]
    fn null_digests() {
        // SAFETY: NULL is the case under test, here and below.
        assert!(unsafe { EVP_MD_get0_description(ptr::null()) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { EVP_MD_get0_provider(ptr::null()) }.is_null());
        // SAFETY: as above.
        let r = unsafe { EVP_MD_names_do_all(ptr::null(), None, ptr::null_mut()) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_MD_get_type(ptr::null()) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_MD_get_flags(ptr::null()) }, 0);
    }
}
