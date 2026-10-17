//! Encoders (`OSSL_ENCODER(3)`; `encoder_meth.c`): an `OSSL_ENCODER` made from a provider's
//! encoder algorithm, fetched by name and properties, listed, and asked for its names,
//! properties, and parameters. Encoding with them is [`ctx`]'s.
//!
//! As in OpenSSL, an encoder must have `encode`, and either `newctx` and `freectx` or
//! `import_object` and `free_object` together or neither;
//! its property definition is parsed when it's made (failing the making if it can't be); and
//! fetching keeps an encoder made under a name the context doesn't know afterwards. Fetch errors
//! are `OSSL_ENCODER`'s, naming the "Name".

pub(crate) mod ctx;
pub(crate) mod pkey;

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    ERR_LIB_OSSL_ENCODER, ERR_R_INVALID_PROVIDER_FUNCTIONS, ERR_R_PASSED_NULL_PARAMETER,
    OSSL_ALGORITHM, OSSL_CORE_BIO, OSSL_ENCODER, OSSL_FUNC_ENCODER_DOES_SELECTION,
    OSSL_FUNC_ENCODER_ENCODE, OSSL_FUNC_ENCODER_FREE_OBJECT, OSSL_FUNC_ENCODER_FREECTX,
    OSSL_FUNC_ENCODER_GET_PARAMS, OSSL_FUNC_ENCODER_GETTABLE_PARAMS,
    OSSL_FUNC_ENCODER_IMPORT_OBJECT, OSSL_FUNC_ENCODER_NEWCTX, OSSL_FUNC_ENCODER_SET_CTX_PARAMS,
    OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, OSSL_LIB_CTX, OSSL_OP_ENCODER, OSSL_PARAM,
    OSSL_PROVIDER,
};
use rustyssl_crypto::property::List;

use crate::err;
use crate::evp::fetch::{self, Kind, Style};
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::provider::Ptr;

type AnyFn = unsafe extern "C" fn();
pub(crate) type NewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
pub(crate) type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
type GetParamsFn = unsafe extern "C" fn(*mut OSSL_PARAM) -> c_int;
type ListFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;
pub(crate) type SetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type DoesSelectionFn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
pub(crate) type EncodeFn = unsafe extern "C" fn(
    *mut c_void,
    *mut OSSL_CORE_BIO,
    *const c_void,
    *const OSSL_PARAM,
    c_int,
    rustyssl_abi::OSSL_PASSPHRASE_CALLBACK,
    *mut c_void,
) -> c_int;
pub(crate) type ImportObjectFn =
    unsafe extern "C" fn(*mut c_void, c_int, *const OSSL_PARAM) -> *mut c_void;
pub(crate) type FreeObjectFn = unsafe extern "C" fn(*mut c_void);

/// A encoder's functions, as its dispatch table gave them.
#[derive(Default, Clone, Copy)]
pub(crate) struct Funcs {
    pub(crate) newctx: Option<NewCtxFn>,
    pub(crate) freectx: Option<FreeCtxFn>,
    get_params: Option<GetParamsFn>,
    gettable_params: Option<ListFn>,
    pub(crate) set_ctx_params: Option<SetCtxParamsFn>,
    settable_ctx_params: Option<ListFn>,
    pub(crate) does_selection: Option<DoesSelectionFn>,
    pub(crate) encode: Option<EncodeFn>,
    pub(crate) import_object: Option<ImportObjectFn>,
    pub(crate) free_object: Option<FreeObjectFn>,
}

/// A encoder (`OSSL_ENCODER`).
pub(crate) struct Encoder {
    pub(crate) name_id: u32,
    name: CString,
    /// The provider's algorithm (its names, properties, description, and table), valid while
    /// the provider lives.
    pub(crate) algodef: Ptr<OSSL_ALGORITHM>,
    /// The parsed property definition.
    pub(crate) props: List,
    /// The provider, with a reference.
    pub(crate) prov: Ptr<OSSL_PROVIDER>,
    pub(crate) funcs: Funcs,
}

handle_type!(OSSL_ENCODER => Encoder);

impl Drop for Encoder {
    fn drop(&mut self) {
        // SAFETY: the provider reference the encoder holds.
        unsafe { OSSL_PROVIDER::free(self.prov.0) };
    }
}

impl Encoder {
    /// The provider's library context.
    pub(crate) fn libctx(&self) -> *mut OSSL_LIB_CTX {
        // SAFETY: the encoder's live provider.
        unsafe { crate::provider::libctx_of(self.prov.0) }
    }

    /// The provider's context, which the encoder's functions take.
    pub(crate) fn provider_ctx(&self) -> *mut c_void {
        // SAFETY: the encoder's live provider.
        unsafe { crate::provider::OSSL_PROVIDER_get0_provider_ctx(self.prov.0) }
    }

    /// `OSSL_ENCODER_get0_name`.
    pub(crate) fn name(&self) -> &CStr {
        &self.name
    }

    /// `OSSL_ENCODER_get0_properties`.
    pub(crate) fn properties(&self) -> *const c_char {
        // SAFETY: the provider's algorithm, valid while it lives.
        unsafe { (*self.algodef.0).property_definition }
    }

    /// The name's number in the provider's library context (0 for none).
    pub(crate) fn number_of(&self, name: &[u8]) -> u32 {
        fetch::number_in(self.prov.0, name)
    }

    /// `OSSL_ENCODER_is_a`.
    pub(crate) fn is_a(&self, name: &[u8]) -> bool {
        self.number_of(name) == self.name_id
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

/// `ossl_encoder_from_algorithm`: an encoder from the provider's algorithm, with one reference,
/// or NULL with an error.
///
/// # Safety
/// `algo`'s names, properties, description, and table are the provider's, valid while it
/// lives; `prov` is a live provider.
unsafe fn from_algorithm(
    name_id: u32,
    algo: &OSSL_ALGORITHM,
    prov: *mut OSSL_PROVIDER,
) -> *mut c_void {
    const F: &str = "ossl_encoder_from_algorithm";
    // SAFETY: the caller's guarantee.
    let names = unsafe { CStr::from_ptr(algo.algorithm_names) }.to_bytes();
    let first = names.split(|&c| c == b':').next().unwrap_or(names);
    let Ok(name) = CString::new(first) else {
        return ptr::null_mut();
    };
    // SAFETY: the caller's live provider.
    let libctx = unsafe { crate::provider::libctx_of(prov) };
    let defn = if algo.property_definition.is_null() {
        &b""[..]
    } else {
        // SAFETY: the provider's string.
        unsafe { CStr::from_ptr(algo.property_definition) }.to_bytes()
    };
    // SAFETY: the provider's context.
    let Some(props) = (unsafe { fetch::parse_definition_in(libctx, defn) }) else {
        return ptr::null_mut();
    };
    let mut f = Funcs::default();
    let mut at = algo.implementation;
    // SAFETY: the caller's guarantee: the table is ended by a zero id.
    while let Some(d) = unsafe { at.as_ref() } {
        if d.function_id == 0 {
            break;
        }
        at = at.wrapping_add(1);
        let Some(func) = d.function else { continue };
        /// Stores `func` as the function its id stands for, the first of each id only.
        macro_rules! set {
            ($field:ident) => {
                if f.$field.is_none() {
                    // SAFETY: the provider's guarantee of the function type for this id.
                    f.$field = Some(unsafe { cast(func) });
                }
            };
        }
        match d.function_id {
            OSSL_FUNC_ENCODER_NEWCTX => set!(newctx),
            OSSL_FUNC_ENCODER_FREECTX => set!(freectx),
            OSSL_FUNC_ENCODER_GET_PARAMS => set!(get_params),
            OSSL_FUNC_ENCODER_GETTABLE_PARAMS => set!(gettable_params),
            OSSL_FUNC_ENCODER_SET_CTX_PARAMS => set!(set_ctx_params),
            OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS => set!(settable_ctx_params),
            OSSL_FUNC_ENCODER_DOES_SELECTION => set!(does_selection),
            OSSL_FUNC_ENCODER_ENCODE => set!(encode),
            OSSL_FUNC_ENCODER_IMPORT_OBJECT => set!(import_object),
            OSSL_FUNC_ENCODER_FREE_OBJECT => set!(free_object),
            _ => {}
        }
    }
    // OpenSSL's check: one of the two pairs (`newctx`/`freectx`, `import_object`/
    // `free_object`) must come together or not at all.
    let ctx_paired = f.newctx.is_some() == f.freectx.is_some();
    let object_paired = f.import_object.is_some() == f.free_object.is_some();
    if !(ctx_paired || object_paired) || f.encode.is_none() {
        err::raise(ERR_LIB_OSSL_ENCODER, ERR_R_INVALID_PROVIDER_FUNCTIONS, F);
        return ptr::null_mut();
    }
    // SAFETY: the caller's live provider; the encoder holds the reference.
    if !unsafe { OSSL_PROVIDER::up_ref(prov) } {
        return ptr::null_mut();
    }
    OSSL_ENCODER::new_handle(Encoder {
        name_id,
        name,
        algodef: Ptr(ptr::from_ref(algo).cast_mut()),
        props,
        prov: Ptr(prov),
        funcs: f,
    })
    .cast()
}

/// Adds a reference to an encoder in a store.
unsafe fn up_ref(m: *mut c_void) {
    // SAFETY: a live encoder.
    unsafe { OSSL_ENCODER::up_ref(m.cast()) };
}

/// Drops a reference to an encoder in a store.
unsafe fn free(m: *mut c_void) {
    // SAFETY: a reference the store held.
    unsafe { OSSL_ENCODER::free(m.cast()) };
}

/// Encoders to fetching.
static ENCODERS: Kind = Kind {
    operation: OSSL_OP_ENCODER,
    style: Style::Encoder,
    from_algorithm,
    up_ref,
    free,
};

/// Every encoder the library context's active providers offer, each with a reference while
/// the caller has it (`OSSL_ENCODER_do_all_provided`'s list).
///
/// # Safety
/// `libctx` is NULL or a live library context.
pub(crate) unsafe fn all(libctx: *mut OSSL_LIB_CTX) -> Vec<fetch::Method> {
    // SAFETY: the caller's guarantee.
    unsafe { fetch::all(libctx, &ENCODERS) }
}

/// The encoder behind a handle, or `None` for NULL.
///
/// # Safety
/// `encoder` is NULL or a live encoder.
pub(crate) unsafe fn encoder<'a>(encoder: *const OSSL_ENCODER) -> Option<&'a Encoder> {
    // SAFETY: the caller's guarantee.
    unsafe { OSSL_ENCODER::get(encoder) }
}

/// A C string argument, or `None` for NULL.
///
/// # Safety
/// `s` is NULL or a string.
unsafe fn text<'a>(s: *const c_char) -> Option<&'a CStr> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) })
}

ffi_export! {
    /// The encoder `name` for the properties, with a reference, or NULL with an error.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `name` and `properties` are NULL or strings.
    pub unsafe extern "C" fn OSSL_ENCODER_fetch(libctx: *mut OSSL_LIB_CTX, name: *const c_char, properties: *const c_char) -> *mut OSSL_ENCODER
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        let n = unsafe { text(name) };
        // SAFETY: as above.
        let p = unsafe { text(properties) };
        // SAFETY: as above.
        unsafe { fetch::fetch(libctx, &ENCODERS, n, p) }.cast()
    }
}

ffi_export! {
    /// Adds a reference. 1.
    ///
    /// # Safety
    /// `encoder` is a live encoder.
    pub unsafe extern "C" fn OSSL_ENCODER_up_ref(encoder: *mut OSSL_ENCODER) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { OSSL_ENCODER::up_ref(encoder) })
    }
}

ffi_export! {
    /// Drops a reference; the encoder goes with the last. NULL does nothing.
    ///
    /// # Safety
    /// `encoder` is NULL or a live encoder whose reference the caller gives up.
    pub unsafe extern "C" fn OSSL_ENCODER_free(encoder: *mut OSSL_ENCODER)
    where failure = (), library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { OSSL_ENCODER::free(encoder) };
    }
}

ffi_export! {
    /// The encoder's provider, or NULL (with an error) for NULL.
    ///
    /// # Safety
    /// `encoder` is NULL or a live encoder.
    pub unsafe extern "C" fn OSSL_ENCODER_get0_provider(encoder: *const OSSL_ENCODER) -> *const OSSL_PROVIDER
    where failure = ptr::null(), library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { self::encoder(encoder) }) else {
            err::raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER, "OSSL_ENCODER_get0_provider");
            return ptr::null();
        };
        d.prov.0.cast_const()
    }
}

ffi_export! {
    /// The encoder's property definition, or NULL (with an error) for NULL.
    ///
    /// # Safety
    /// `encoder` is NULL or a live encoder.
    pub unsafe extern "C" fn OSSL_ENCODER_get0_properties(encoder: *const OSSL_ENCODER) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { self::encoder(encoder) }) else {
            err::raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER, "OSSL_ENCODER_get0_properties");
            return ptr::null();
        };
        d.properties()
    }
}

ffi_export! {
    /// The encoder's first name.
    ///
    /// # Safety
    /// `encoder` is NULL or a live encoder.
    pub unsafe extern "C" fn OSSL_ENCODER_get0_name(encoder: *const OSSL_ENCODER) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::encoder(encoder) }.map_or(ptr::null(), |d| d.name.as_ptr())
    }
}

ffi_export! {
    /// The encoder's description (the provider's), or NULL.
    ///
    /// # Safety
    /// `encoder` is NULL or a live encoder.
    pub unsafe extern "C" fn OSSL_ENCODER_get0_description(encoder: *const OSSL_ENCODER) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { self::encoder(encoder) }) else { return ptr::null() };
        // SAFETY: the provider's algorithm.
        unsafe { (*d.algodef.0).algorithm_description }
    }
}

ffi_export! {
    /// Whether `name` is one of the encoder's names.
    ///
    /// # Safety
    /// `encoder` is NULL or a live encoder; `name` is NULL or a string.
    pub unsafe extern "C" fn OSSL_ENCODER_is_a(encoder: *const OSSL_ENCODER, name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { self::encoder(encoder) }) else { return 0 };
        // SAFETY: as above.
        let n = unsafe { text(name) }.map_or(&b""[..], CStr::to_bytes);
        c_int::from(d.is_a(n))
    }
}

type NameFn = unsafe extern "C" fn(*const c_char, *mut c_void);

ffi_export! {
    /// Calls `fn_` with each of the encoder's names. 1, or 0 for NULL.
    ///
    /// # Safety
    /// `encoder` is NULL or a live encoder; `fn_` takes `data`.
    pub unsafe extern "C" fn OSSL_ENCODER_names_do_all(encoder: *const OSSL_ENCODER, fn_: Option<NameFn>, data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { self::encoder(encoder) }) else { return 0 };
        for &n in &fetch::c_names_of(d.prov.0, d.name_id) {
            if let Some(f) = fn_ {
                // SAFETY: the caller's callback with a string the context keeps, and its data.
                unsafe { f(n, data) };
            }
        }
        1
    }
}

type DoAllFn = unsafe extern "C" fn(*mut OSSL_ENCODER, *mut c_void);

ffi_export! {
    /// Calls `user_fn` with every encoder the library context's providers offer.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `user_fn` takes `user_arg`.
    pub unsafe extern "C" fn OSSL_ENCODER_do_all_provided(libctx: *mut OSSL_LIB_CTX, user_fn: Option<DoAllFn>, user_arg: *mut c_void)
    where failure = (), library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        for m in &unsafe { all(libctx) } {
            if let Some(f) = user_fn {
                // SAFETY: the caller's callback with an encoder held for the call.
                unsafe { f(m.as_ptr().cast(), user_arg) };
            }
        }
    }
}

ffi_export! {
    /// The encoder's gettable parameters (its provider's list), or NULL.
    ///
    /// # Safety
    /// `encoder` is NULL or a live encoder.
    pub unsafe extern "C" fn OSSL_ENCODER_gettable_params(encoder: *mut OSSL_ENCODER) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { self::encoder(encoder) }) else { return ptr::null() };
        let Some(f) = d.funcs.gettable_params else { return ptr::null() };
        // SAFETY: the provider's function with its context.
        unsafe { f(d.provider_ctx()) }
    }
}

ffi_export! {
    /// The encoder's parameters, or 0 for NULL or an encoder without them.
    ///
    /// # Safety
    /// `encoder` is NULL or a live encoder; `params` is NULL or an array.
    pub unsafe extern "C" fn OSSL_ENCODER_get_params(encoder: *mut OSSL_ENCODER, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { self::encoder(encoder) }) else { return 0 };
        let Some(f) = d.funcs.get_params else { return 0 };
        // SAFETY: the provider's function with the caller's array.
        unsafe { f(params) }
    }
}

ffi_export! {
    /// The parameters the encoder's contexts take (its provider's list), or NULL.
    ///
    /// # Safety
    /// `encoder` is NULL or a live encoder.
    pub unsafe extern "C" fn OSSL_ENCODER_settable_ctx_params(encoder: *mut OSSL_ENCODER) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_OSSL_ENCODER
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { self::encoder(encoder) }) else { return ptr::null() };
        let Some(f) = d.funcs.settable_ctx_params else { return ptr::null() };
        // SAFETY: the provider's function with its context.
        unsafe { f(d.provider_ctx()) }
    }
}
