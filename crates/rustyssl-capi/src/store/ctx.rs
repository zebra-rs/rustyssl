//! Opening and reading stores (`OSSL_STORE_open(3)`, `OSSL_STORE_attach(3)`,
//! `OSSL_STORE_expect(3)`; `store_lib.c`): the loader for a URI's scheme (a registered one first,
//! then the providers'; `file` too when the URI has no authority), and the objects it gives.
//!
//! The provider's loader calls back into the result handler and the passphrase callback while
//! it loads, so the context is reached through its raw pointer and no reference to it is held
//! across a loader's call.

use core::ffi::{CStr, VaList, c_char, c_int, c_void};
use core::ptr;
use std::collections::VecDeque;

use rustyssl_abi::{
    BIO, ERR_LIB_OSSL_STORE, ERR_R_CRYPTO_LIB, ERR_R_PASSED_INVALID_ARGUMENT,
    ERR_R_PASSED_NULL_PARAMETER, OSSL_LIB_CTX, OSSL_PARAM, OSSL_STORE_C_USE_SECMEM, OSSL_STORE_CTX,
    OSSL_STORE_INFO, OSSL_STORE_INFO_CRL, OSSL_STORE_INFO_NAME, OSSL_STORE_LOADER,
    OSSL_STORE_PARAM_ALIAS, OSSL_STORE_PARAM_DIGEST, OSSL_STORE_PARAM_EXPECT,
    OSSL_STORE_PARAM_FINGERPRINT, OSSL_STORE_PARAM_ISSUER, OSSL_STORE_PARAM_PROPERTIES,
    OSSL_STORE_PARAM_SERIAL, OSSL_STORE_PARAM_SUBJECT, OSSL_STORE_R_LOADING_STARTED,
    OSSL_STORE_R_UNSUPPORTED_OPERATION, OSSL_STORE_SEARCH, OSSL_STORE_SEARCH_BY_ALIAS,
    OSSL_STORE_SEARCH_BY_ISSUER_SERIAL, OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT,
    OSSL_STORE_SEARCH_BY_NAME, OSSL_STORE_post_process_info_fn, UI_METHOD,
};

use super::info::{OSSL_STORE_INFO_free, OSSL_STORE_INFO_get_type, search_of, strdup};
use super::meth::{OSSL_STORE_LOADER_fetch, provided};
use super::result::{LoadData, handle_load_result};
use super::{Funcs, OSSL_STORE_LOADER_free, loader, registered};
use crate::bn::BN_free;
use crate::bn::conv::ASN1_INTEGER_to_BN;
use crate::decoder::ctx::core_bio_new_from_bio;
use crate::err::{self, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::digest::EVP_MD_get0_name;
use crate::ffi::ffi_export;
use crate::mem;
use crate::params::build::{
    OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_push_BN,
    OSSL_PARAM_BLD_push_octet_string, OSSL_PARAM_BLD_push_utf8_string, OSSL_PARAM_BLD_to_param,
};
use crate::params::dup::OSSL_PARAM_free;
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_utf8_string,
    OSSL_PARAM_locate_const,
};
use crate::passphrase::{PwData, passphrase_callback_dec};
use crate::provider::OSSL_PROVIDER_get0_provider_ctx;
use crate::x509::name::i2d_X509_NAME;

fn raise(reason: c_int, f: &str) {
    err::raise(ERR_LIB_OSSL_STORE, reason, f);
}

/// `ossl_store_ctx_st`.
pub(crate) struct Ctx {
    /// The loader: a registered one, or the fetched one (with a reference).
    pub(crate) loader: *mut OSSL_STORE_LOADER,
    /// Whether `loader` was fetched (a provider's).
    pub(crate) fetched: bool,
    pub(crate) loader_ctx: *mut c_void,
    pub(crate) expected_type: c_int,
    /// From `CRYPTO_malloc`, or NULL.
    pub(crate) properties: *mut c_char,
    post_process: OSSL_STORE_post_process_info_fn,
    post_process_data: *mut c_void,
    /// A PKCS #12 file's objects still to give.
    pub(crate) cached_info: Option<VecDeque<*mut OSSL_STORE_INFO>>,
    pub(crate) pwdata: PwData,
    loading: bool,
    error_flag: bool,
}

/// The context behind a pointer, for as long as no loader's function runs.
///
/// # Safety
/// `p` is NULL or a live context, not otherwise borrowed.
pub(crate) unsafe fn ctx_of<'a>(p: *mut OSSL_STORE_CTX) -> Option<&'a mut Ctx> {
    // SAFETY: the caller's guarantee.
    unsafe { p.cast::<Ctx>().as_mut() }
}

/// A registered loader's functions.
///
/// # Safety
/// `l` is a live loader.
unsafe fn legacy(l: *const OSSL_STORE_LOADER) -> Funcs {
    // SAFETY: the caller's guarantee.
    unsafe { loader(l) }.map(|l| *l.funcs()).unwrap_or_default()
}

/// `loader_set_params`: the parameters, then the properties unless they set some.
///
/// # Safety
/// `l` is a provider's loader; `lctx` its context; `params` NULL or a parameter array;
/// `propq` NULL or a C string.
unsafe fn loader_set_params(
    l: *const OSSL_STORE_LOADER,
    lctx: *mut c_void,
    params: *const OSSL_PARAM,
    propq: *const c_char,
) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(set) = (unsafe { provided(l) }).and_then(|p| p.set_ctx_params) else {
        return params.is_null() && propq.is_null();
    };
    // SAFETY: the loader's function on its context; the caller's parameters.
    if !params.is_null() && unsafe { set(lctx, params) } == 0 {
        return false;
    }
    if !propq.is_null() {
        // SAFETY: the caller's parameters, or NULL.
        if !unsafe { OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_PROPERTIES.as_ptr()) }
            .is_null()
        {
            return true;
        }
        // SAFETY: the key and the caller's string, which the array only points to.
        let propp = [
            unsafe {
                OSSL_PARAM_construct_utf8_string(
                    OSSL_STORE_PARAM_PROPERTIES.as_ptr(),
                    propq.cast_mut(),
                    0,
                )
            },
            unsafe { OSSL_PARAM_construct_end() },
        ];
        // SAFETY: as above.
        if unsafe { set(lctx, propp.as_ptr()) } == 0 {
            return false;
        }
    }
    true
}

/// The schemes `OSSL_STORE_open_ex` tries for the URI: `file`, unless the URI has another
/// scheme with an authority (`scheme://`), then that scheme.
fn schemes_of(uri: &[u8]) -> Vec<Vec<u8>> {
    let mut schemes = vec![b"file".to_vec()];
    // `OPENSSL_strlcpy` into 256 octets.
    let copy = uri.get(..uri.len().min(255)).unwrap_or_default();
    if let Some(colon) = copy.iter().position(|&c| c == b':') {
        let (scheme, rest) = (
            copy.get(..colon).unwrap_or_default(),
            copy.get(colon + 1..).unwrap_or_default(),
        );
        if !scheme.eq_ignore_ascii_case(b"file") {
            if rest.starts_with(b"//") {
                schemes.pop();
            }
            schemes.push(scheme.to_vec());
        }
    }
    schemes
}

/// Closes the loader's context (`ossl_store_close_it`'s first part).
///
/// # Safety
/// `l` and `lctx` are a live loader and its context, not used again.
unsafe fn close_loader(l: *const OSSL_STORE_LOADER, fetched: bool, lctx: *mut c_void) -> c_int {
    if fetched {
        // SAFETY: the caller's guarantee.
        match unsafe { provided(l) }.and_then(|p| p.close) {
            // SAFETY: as above.
            Some(close) => unsafe { close(lctx) },
            None => 0,
        }
    } else {
        // SAFETY: as above.
        match unsafe { legacy(l) }.close {
            // SAFETY: as above.
            Some(close) => unsafe { close(lctx.cast()) },
            None => 0,
        }
    }
}

/// What opening found: the loader, whether fetched, and its context.
type Opened = (*mut OSSL_STORE_LOADER, bool, *mut c_void);

/// The loop of `OSSL_STORE_open_ex` over the schemes: the first loader that opens the URI.
/// `Err` when no scheme has a loader at all.
///
/// # Safety
/// As for [`OSSL_STORE_open_ex`]; `pwdata` outlives the opened context's use of it until it is
/// moved into the store's context (the loaders may keep its address only while opening).
#[expect(clippy::too_many_arguments, reason = "OpenSSL's")]
unsafe fn find_loader(
    uri: *const c_char,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
    ui_method: *const UI_METHOD,
    ui_data: *mut c_void,
    params: *const OSSL_PARAM,
    schemes: &[Vec<u8>],
    pwdata: &mut PwData,
) -> Result<Opened, ()> {
    let mut no_loader_found = true;
    let mut found: Opened = (ptr::null_mut(), false, ptr::null_mut());
    for scheme in schemes {
        let Ok(scheme) = std::ffi::CString::new(scheme.clone()) else {
            continue;
        };
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        let reg = registered(scheme.as_bytes());
        if reg.is_null() {
            // SAFETY: the mark set above.
            unsafe { ERR_pop_to_mark() };
        } else {
            // SAFETY: as above.
            unsafe { ERR_clear_last_mark() };
            no_loader_found = false;
            // SAFETY: a registered loader, live while registered.
            let f = unsafe { legacy(reg) };
            let lctx = match (f.open_ex, f.open) {
                // SAFETY: the application's loader, with the caller's arguments.
                (Some(open_ex), _) => unsafe {
                    open_ex(reg, uri, libctx, propq, ui_method, ui_data)
                },
                // SAFETY: as above.
                (None, Some(open)) => unsafe { open(reg, uri, ui_method, ui_data) },
                (None, None) => ptr::null_mut(),
            };
            found = (reg, false, lctx.cast());
            if !lctx.is_null() {
                break;
            }
            continue;
        }
        // SAFETY: the caller's context and properties; a C string.
        let fl = unsafe { OSSL_STORE_LOADER_fetch(libctx, scheme.as_ptr(), propq) };
        // SAFETY: the loader fetched here, or NULL.
        let Some(p) = (unsafe { provided(fl) }) else {
            continue;
        };
        no_loader_found = false;
        // SAFETY: its live provider.
        let provctx = unsafe { OSSL_PROVIDER_get0_provider_ctx(p.prov.0) };
        let mut lctx = ptr::null_mut();
        if let Some(open_ex) = p.open_ex {
            // SAFETY: the provider's function; the caller's URI and parameters; the
            // passphrase data the callback is given.
            lctx = unsafe {
                open_ex(
                    provctx,
                    uri,
                    params,
                    Some(passphrase_callback_dec),
                    ptr::from_mut(pwdata).cast(),
                )
            };
        } else if let Some(open) = p.open {
            // SAFETY: the provider's function; the caller's URI.
            lctx = unsafe { open(provctx, uri) };
            // SAFETY: the loader and its new context.
            if !lctx.is_null() && !unsafe { loader_set_params(fl, lctx, params, propq) } {
                // SAFETY: as above.
                unsafe { close_loader(fl, true, lctx) };
                lctx = ptr::null_mut();
            }
        }
        pwdata.clear_cache();
        if lctx.is_null() {
            // SAFETY: the reference fetched here.
            unsafe { OSSL_STORE_LOADER_free(fl) };
            found = (ptr::null_mut(), true, ptr::null_mut());
            continue;
        }
        found = (fl, true, lctx);
        break;
    }
    if no_loader_found { Err(()) } else { Ok(found) }
}

ffi_export! {
    /// Opens the URI with the loader for its scheme (a registered one, else the library
    /// context's providers', `propq` choosing): the store's context, or NULL.
    ///
    /// # Safety
    /// `uri` is NULL or a C string; `libctx` NULL or a live library context; `propq` NULL or a C
    /// string; `ui_method` NULL or a live method for `ui_data`; `params` NULL or a parameter
    /// array; `post_process` NULL or a callback for `post_process_data`.
    pub unsafe extern "C" fn OSSL_STORE_open_ex(uri: *const c_char, libctx: *mut OSSL_LIB_CTX, propq: *const c_char, ui_method: *const UI_METHOD, ui_data: *mut c_void, params: *const OSSL_PARAM, post_process: OSSL_STORE_post_process_info_fn, post_process_data: *mut c_void) -> *mut OSSL_STORE_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        const F: &str = "OSSL_STORE_open_ex";
        if uri.is_null() {
            raise(ERR_R_PASSED_NULL_PARAMETER, F);
            return ptr::null_mut();
        }
        // SAFETY: the caller's string.
        let schemes = schemes_of(unsafe { CStr::from_ptr(uri) }.to_bytes());
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        let mut pwdata = PwData::default();
        if !ui_method.is_null() {
            if !pwdata.set_ui_method(ui_method, ui_data) {
                raise(ERR_R_CRYPTO_LIB, F);
                // SAFETY: the mark set above.
                unsafe { ERR_clear_last_mark() };
                return ptr::null_mut();
            }
            pwdata.enable_caching();
        }
        // SAFETY: the caller's arguments.
        let found = unsafe { find_loader(uri, libctx, propq, ui_method, ui_data, params, &schemes, &mut pwdata) };
        let Ok((l, fetched, lctx)) = found.and_then(|o| if o.2.is_null() { Err(()) } else { Ok(o) }) else {
            // SAFETY: as above.
            unsafe { ERR_clear_last_mark() };
            return ptr::null_mut();
        };
        let props = if propq.is_null() {
            ptr::null_mut()
        } else {
            // SAFETY: the caller's string.
            let p = unsafe { strdup(propq) };
            if p.is_null() {
                // SAFETY: the loader and its context, opened here.
                unsafe { close_loader(l, fetched, lctx) };
                if fetched {
                    // SAFETY: the reference fetched.
                    unsafe { OSSL_STORE_LOADER_free(l) };
                }
                // SAFETY: as above.
                unsafe { ERR_clear_last_mark() };
                return ptr::null_mut();
            }
            p
        };
        let ctx = Box::into_raw(Box::new(Ctx {
            loader: l,
            fetched,
            loader_ctx: lctx,
            expected_type: 0,
            properties: props,
            post_process,
            post_process_data,
            cached_info: None,
            pwdata,
            loading: false,
            error_flag: false,
        }));
        // SAFETY: as above.
        unsafe { ERR_pop_to_mark() };
        ctx.cast()
    }
}

ffi_export! {
    /// [`OSSL_STORE_open_ex`] in the default library context, with no properties or
    /// parameters.
    ///
    /// # Safety
    /// As for [`OSSL_STORE_open_ex`].
    pub unsafe extern "C" fn OSSL_STORE_open(uri: *const c_char, ui_method: *const UI_METHOD, ui_data: *mut c_void, post_process: OSSL_STORE_post_process_info_fn, post_process_data: *mut c_void) -> *mut OSSL_STORE_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's arguments.
        unsafe { OSSL_STORE_open_ex(uri, ptr::null_mut(), ptr::null(), ui_method, ui_data, ptr::null(), post_process, post_process_data) }
    }
}

/// `OSSL_STORE_vctrl` over the context.
///
/// # Safety
/// `ctx` is a live context; `args` the command's arguments.
unsafe fn vctrl(ctx: *mut OSSL_STORE_CTX, cmd: c_int, mut args: VaList<'_>) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ctx_of(ctx) }) else {
        return 0;
    };
    let (l, lctx, fetched) = (c.loader, c.loader_ctx, c.fetched);
    if fetched {
        // SAFETY: its loader.
        let Some(set) = (unsafe { provided(l) }).and_then(|p| p.set_ctx_params) else {
            return 1;
        };
        let mut on: c_int;
        // SAFETY: no preconditions.
        let mut params = [unsafe { OSSL_PARAM_construct_end() }, unsafe {
            OSSL_PARAM_construct_end()
        }];
        if cmd == OSSL_STORE_C_USE_SECMEM {
            // SAFETY: the command's argument, a pointer to an `int`.
            let p = unsafe { args.next_arg::<*const c_int>() };
            // SAFETY: as above.
            on = unsafe { *p };
            // SAFETY: the key; `on`, which outlives the call.
            params[0] = unsafe { OSSL_PARAM_construct_int(c"use_secmem".as_ptr(), &raw mut on) };
        }
        // SAFETY: the loader's function on its context.
        return unsafe { set(lctx, params.as_ptr()) };
    }
    // SAFETY: as above.
    match unsafe { legacy(l) }.ctrl {
        Some(ctrl) => {
            // `va_list` as the loader's function takes it.
            type CtrlFn = unsafe extern "C" fn(*mut c_void, c_int, VaList<'_>) -> c_int;
            // SAFETY: the same function, its `va_list` parameter given as a `VaList`.
            let f: CtrlFn = unsafe { core::mem::transmute(ctrl) };
            // SAFETY: the application's loader on its context, with the caller's arguments.
            unsafe { f(lctx, cmd, args) }
        }
        None => 1,
    }
}

/// `OSSL_STORE_ctrl`: a command for the loader (`OSSL_STORE_C_USE_SECMEM`, or the loader's own).
///
/// # Safety
/// `ctx` is a live context; the arguments are the command's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OSSL_STORE_ctrl(ctx: *mut OSSL_STORE_CTX, cmd: c_int, args: ...) -> c_int {
    crate::ffi::guard(
        ERR_LIB_OSSL_STORE,
        "OSSL_STORE_ctrl",
        || 0,
        move || {
            // SAFETY: the caller's guarantee.
            unsafe { vctrl(ctx, cmd, args) }
        },
    )
}

ffi_export! {
    /// `OSSL_STORE_ctrl` with its arguments in a `va_list`.
    ///
    /// # Safety
    /// As for `OSSL_STORE_ctrl`.
    pub unsafe extern "C" fn OSSL_STORE_vctrl(ctx: *mut OSSL_STORE_CTX, cmd: c_int, args: VaList<'_>) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        unsafe { vctrl(ctx, cmd, args) }
    }
}

ffi_export! {
    /// Restricts what loading gives to one type (0 for any): 1, or 0 once loading started.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn OSSL_STORE_expect(ctx: *mut OSSL_STORE_CTX, expected_type: c_int) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_STORE
    {
        const F: &str = "OSSL_STORE_expect";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }).filter(|_| (0..=OSSL_STORE_INFO_CRL).contains(&expected_type)) else {
            raise(ERR_R_PASSED_INVALID_ARGUMENT, F);
            return 0;
        };
        if c.loading {
            raise(OSSL_STORE_R_LOADING_STARTED, F);
            return 0;
        }
        c.expected_type = expected_type;
        let (l, lctx, fetched) = (c.loader, c.loader_ctx, c.fetched);
        if fetched {
            // SAFETY: its loader.
            if let Some(set) = unsafe { provided(l) }.and_then(|p| p.set_ctx_params) {
                let mut t = expected_type;
                // SAFETY: the key; `t`, which outlives the call.
                let params = [unsafe { OSSL_PARAM_construct_int(OSSL_STORE_PARAM_EXPECT.as_ptr(), &raw mut t) }, unsafe { OSSL_PARAM_construct_end() }];
                // SAFETY: the loader's function on its context.
                return unsafe { set(lctx, params.as_ptr()) };
            }
            return 1;
        }
        // SAFETY: as above.
        match unsafe { legacy(l) }.expect {
            // SAFETY: the application's loader on its context.
            Some(expect) => unsafe { expect(lctx.cast(), expected_type) },
            None => 1,
        }
    }
}

/// The parameters of a search, as `OSSL_STORE_find` gives them to a provider's loader.
///
/// # Safety
/// `s`'s members are NULL or live.
unsafe fn search_params(s: &super::info::Search) -> *mut OSSL_PARAM {
    // SAFETY: no preconditions.
    let bld = unsafe { OSSL_PARAM_BLD_new() };
    if bld.is_null() {
        raise(ERR_R_CRYPTO_LIB, "OSSL_STORE_find");
        return ptr::null_mut();
    }
    let mut name_der: *mut u8 = ptr::null_mut();
    let mut number = ptr::null_mut();
    let ok = 'b: {
        match s.search_type {
            OSSL_STORE_SEARCH_BY_NAME | OSSL_STORE_SEARCH_BY_ISSUER_SERIAL => {
                // SAFETY: the search's name; room for the encoding.
                let n = unsafe { i2d_X509_NAME(s.name, &raw mut name_der) };
                let Ok(n) = usize::try_from(n) else {
                    break 'b false;
                };
                if n == 0 {
                    break 'b false;
                }
                if s.search_type == OSSL_STORE_SEARCH_BY_NAME {
                    // SAFETY: the builder; the encoding.
                    break 'b unsafe {
                        OSSL_PARAM_BLD_push_octet_string(
                            bld,
                            OSSL_STORE_PARAM_SUBJECT.as_ptr(),
                            name_der.cast(),
                            n,
                        )
                    } != 0;
                }
                // SAFETY: the search's serial.
                number = unsafe { ASN1_INTEGER_to_BN(s.serial, ptr::null_mut()) };
                !number.is_null()
                    // SAFETY: as above.
                    && unsafe { OSSL_PARAM_BLD_push_octet_string(bld, OSSL_STORE_PARAM_ISSUER.as_ptr(), name_der.cast(), n) } != 0
                    // SAFETY: as above; the number.
                    && unsafe { OSSL_PARAM_BLD_push_BN(bld, OSSL_STORE_PARAM_SERIAL.as_ptr(), number) } != 0
            }
            OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT => {
                // SAFETY: the search's digest.
                let name = unsafe { EVP_MD_get0_name(s.digest) };
                // SAFETY: the builder; the digest's name.
                (unsafe { OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_STORE_PARAM_DIGEST.as_ptr(), name, 0) }) != 0
                    // SAFETY: as above; the fingerprint.
                    && unsafe { OSSL_PARAM_BLD_push_octet_string(bld, OSSL_STORE_PARAM_FINGERPRINT.as_ptr(), s.string.cast(), s.stringlength) } != 0
            }
            OSSL_STORE_SEARCH_BY_ALIAS => {
                // SAFETY: the builder; the alias.
                (unsafe {
                    OSSL_PARAM_BLD_push_utf8_string(
                        bld,
                        OSSL_STORE_PARAM_ALIAS.as_ptr(),
                        s.string.cast(),
                        s.stringlength,
                    )
                }) != 0
            }
            _ => false,
        }
    };
    let params = if ok {
        // SAFETY: the builder.
        unsafe { OSSL_PARAM_BLD_to_param(bld) }
    } else {
        ptr::null_mut()
    };
    // SAFETY: made here.
    unsafe { OSSL_PARAM_BLD_free(bld) };
    // SAFETY: from `CRYPTO_malloc`, or NULL.
    unsafe { mem::release(name_der.cast()) };
    // SAFETY: made here, or NULL.
    unsafe { BN_free(number) };
    params
}

ffi_export! {
    /// Restricts what loading gives to what the search matches: 1, or 0 (once loading started,
    /// or when the loader can't search).
    ///
    /// # Safety
    /// `ctx` is a live context; `search` NULL or a live search.
    pub unsafe extern "C" fn OSSL_STORE_find(ctx: *mut OSSL_STORE_CTX, search: *const OSSL_STORE_SEARCH) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_STORE
    {
        const F: &str = "OSSL_STORE_find";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 0 };
        if c.loading {
            raise(OSSL_STORE_R_LOADING_STARTED, F);
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { search_of(search) }) else {
            raise(ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        };
        let (l, lctx, fetched) = (c.loader, c.loader_ctx, c.fetched);
        if fetched {
            // SAFETY: its loader.
            let Some(set) = (unsafe { provided(l) }).and_then(|p| p.set_ctx_params) else {
                raise(OSSL_STORE_R_UNSUPPORTED_OPERATION, F);
                return 0;
            };
            // SAFETY: the search's members.
            let params = unsafe { search_params(s) };
            if params.is_null() {
                return 0;
            }
            // SAFETY: the loader's function on its context.
            let ret = unsafe { set(lctx, params) };
            // SAFETY: made here.
            unsafe { OSSL_PARAM_free(params) };
            return ret;
        }
        // SAFETY: as above.
        match unsafe { legacy(l) }.find {
            // SAFETY: the application's loader on its context.
            Some(find) => unsafe { find(lctx.cast(), search) },
            None => {
                raise(OSSL_STORE_R_UNSUPPORTED_OPERATION, F);
                0
            }
        }
    }
}

/// One object from the loader (or the cache), before the post-processing: it, or NULL.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn load_one(ctx: *mut OSSL_STORE_CTX) -> Option<*mut OSSL_STORE_INFO> {
    // SAFETY: the caller's guarantee.
    let c = unsafe { ctx_of(ctx) }?;
    if let Some(q) = c.cached_info.as_mut() {
        return Some(q.pop_front().unwrap_or(ptr::null_mut()));
    }
    let (l, lctx, fetched) = (c.loader, c.loader_ctx, c.fetched);
    if fetched {
        // SAFETY: its loader.
        let load = (unsafe { provided(l) })?.load?;
        c.error_flag = false;
        let pw = ptr::from_mut(&mut c.pwdata).cast::<c_void>();
        let mut data = LoadData {
            v: ptr::null_mut(),
            ctx,
        };
        // SAFETY: the loader's function on its context; the handler and its data; the
        // passphrase callback and the context's data. No reference to the context is held.
        let ok = unsafe {
            load(
                lctx,
                Some(handle_load_result),
                (&raw mut data).cast(),
                Some(passphrase_callback_dec),
                pw,
            )
        };
        if ok == 0 {
            // SAFETY: as above, after the call.
            if let Some(c) = unsafe { ctx_of(ctx) } {
                c.error_flag = true;
            }
            return None;
        }
        return Some(data.v);
    }
    // SAFETY: as above.
    let load = unsafe { legacy(l) }.load?;
    let (ui_method, ui_data) = c.pwdata.ui_method();
    // SAFETY: the application's loader on its context.
    Some(unsafe { load(lctx.cast(), ui_method, ui_data) })
}

ffi_export! {
    /// The next object (of the type expected, if any), or NULL at the end or on an error.
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub unsafe extern "C" fn OSSL_STORE_load(ctx: *mut OSSL_STORE_CTX) -> *mut OSSL_STORE_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return ptr::null_mut() };
        c.loading = true;
        loop {
            // SAFETY: a live context.
            if unsafe { OSSL_STORE_eof(ctx) } != 0 {
                return ptr::null_mut();
            }
            // SAFETY: as above.
            let Some(mut v) = (unsafe { load_one(ctx) }) else { return ptr::null_mut() };
            // SAFETY: as above, after the loader.
            let Some(c) = (unsafe { ctx_of(ctx) }) else { return ptr::null_mut() };
            if let (Some(pp), false) = (c.post_process, v.is_null()) {
                let data = c.post_process_data;
                // SAFETY: the application's callback with the information, which it takes.
                v = unsafe { pp(v, data) };
                if v.is_null() {
                    continue;
                }
            }
            // SAFETY: as above, after the callback.
            let Some(c) = (unsafe { ctx_of(ctx) }) else { return ptr::null_mut() };
            c.pwdata.clear_cache();
            if !v.is_null() && c.expected_type != 0 {
                // SAFETY: the information.
                let t = unsafe { OSSL_STORE_INFO_get_type(v) };
                if t != OSSL_STORE_INFO_NAME && t != 0 && t != c.expected_type {
                    // SAFETY: as above, given up.
                    unsafe { OSSL_STORE_INFO_free(v) };
                    continue;
                }
            }
            return v;
        }
    }
}

ffi_export! {
    /// Deletes what the URI names, if its scheme's provider loader can: 1, or 0.
    ///
    /// # Safety
    /// As for [`OSSL_STORE_open_ex`].
    pub unsafe extern "C" fn OSSL_STORE_delete(uri: *const c_char, libctx: *mut OSSL_LIB_CTX, propq: *const c_char, ui_method: *const UI_METHOD, ui_data: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_STORE
    {
        if uri.is_null() {
            raise(ERR_R_PASSED_NULL_PARAMETER, "OSSL_STORE_delete");
            return 0;
        }
        // SAFETY: the caller's string.
        let u = unsafe { CStr::from_ptr(uri) }.to_bytes();
        let copy = u.get(..u.len().min(255)).unwrap_or_default();
        let Some(colon) = copy.iter().position(|&c| c == b':') else { return 0 };
        let Ok(scheme) = std::ffi::CString::new(copy.get(..colon).unwrap_or_default()) else { return 0 };
        let mut pwdata = PwData::default();
        if !ui_method.is_null() {
            if !pwdata.set_ui_method(ui_method, ui_data) {
                raise(ERR_R_CRYPTO_LIB, "OSSL_STORE_delete");
                return 0;
            }
            pwdata.enable_caching();
        }
        // SAFETY: the caller's context and properties; a C string.
        let fl = unsafe { OSSL_STORE_LOADER_fetch(libctx, scheme.as_ptr(), propq) };
        let mut res = 0;
        // SAFETY: the loader fetched here, or NULL.
        if let Some(p) = unsafe { provided(fl) }
            && let Some(delete) = p.delete
        {
            // SAFETY: its live provider.
            let provctx = unsafe { OSSL_PROVIDER_get0_provider_ctx(p.prov.0) };
            // SAFETY: the provider's function; the caller's URI and parameters.
            res = unsafe { delete(provctx, uri, params, Some(passphrase_callback_dec), (&raw mut pwdata).cast()) };
        }
        pwdata.clear_cache();
        // SAFETY: the reference fetched, or NULL.
        unsafe { OSSL_STORE_LOADER_free(fl) };
        res
    }
}

ffi_export! {
    /// Whether the last load failed (a registered loader says for itself).
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub unsafe extern "C" fn OSSL_STORE_error(ctx: *mut OSSL_STORE_CTX) -> c_int
    where failure = 1, library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 1 };
        if c.fetched {
            return c_int::from(c.error_flag);
        }
        let (l, lctx) = (c.loader, c.loader_ctx);
        // SAFETY: its loader.
        match unsafe { legacy(l) }.error {
            // SAFETY: the application's loader on its context.
            Some(error) => unsafe { error(lctx.cast()) },
            None => 1,
        }
    }
}

ffi_export! {
    /// Whether there is nothing more to load.
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub unsafe extern "C" fn OSSL_STORE_eof(ctx: *mut OSSL_STORE_CTX) -> c_int
    where failure = 1, library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 1 };
        if c.cached_info.as_ref().is_some_and(VecDeque::is_empty) {
            c.cached_info = None;
        }
        if c.cached_info.is_some() {
            return 0;
        }
        let (l, lctx, fetched) = (c.loader, c.loader_ctx, c.fetched);
        let ret = if fetched {
            // SAFETY: its loader.
            match unsafe { provided(l) }.and_then(|p| p.eof) {
                // SAFETY: the loader's function on its context.
                Some(eof) => unsafe { eof(lctx) },
                None => 1,
            }
        } else {
            // SAFETY: as above.
            match unsafe { legacy(l) }.eof {
                // SAFETY: the application's loader on its context.
                Some(eof) => unsafe { eof(lctx.cast()) },
                None => 1,
            }
        };
        c_int::from(ret != 0)
    }
}

ffi_export! {
    /// Closes the store and frees its context: the loader's answer (1 for NULL).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context, not used again.
    pub unsafe extern "C" fn OSSL_STORE_close(ctx: *mut OSSL_STORE_CTX) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_STORE
    {
        if ctx.is_null() {
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let (l, lctx, fetched) = match unsafe { ctx_of(ctx) } {
            Some(c) => (c.loader, c.loader_ctx, c.fetched),
            None => return 1,
        };
        // SAFETY: its loader and context, not used again.
        let ret = unsafe { close_loader(l, fetched, lctx) };
        // SAFETY: made by `OSSL_STORE_open_ex` or `OSSL_STORE_attach`, freed once.
        let c = unsafe { Box::from_raw(ctx.cast::<Ctx>()) };
        for i in c.cached_info.iter().flatten() {
            // SAFETY: the context's own informations.
            unsafe { OSSL_STORE_INFO_free(*i) };
        }
        if c.fetched {
            // SAFETY: the reference it fetched.
            unsafe { OSSL_STORE_LOADER_free(c.loader) };
        }
        // SAFETY: from `CRYPTO_malloc`, or NULL.
        unsafe { mem::release(c.properties.cast()) };
        ret
    }
}

ffi_export! {
    /// Whether the store's loader can search by the type.
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub unsafe extern "C" fn OSSL_STORE_supports_search(ctx: *mut OSSL_STORE_CTX, search_type: c_int) -> c_int
    where failure = 0, library = ERR_LIB_OSSL_STORE
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx_of(ctx) }) else { return 0 };
        let l = c.loader;
        if c.fetched {
            // SAFETY: its loader.
            let Some(p) = (unsafe { provided(l) }) else { return 0 };
            let Some(settable) = p.settable_ctx_params else { return 0 };
            // SAFETY: its live provider.
            let provctx = unsafe { OSSL_PROVIDER_get0_provider_ctx(p.prov.0) };
            // SAFETY: the provider's function.
            let params = unsafe { settable(provctx) };
            // SAFETY: the provider's array, or NULL.
            let has = |k: &CStr| !unsafe { OSSL_PARAM_locate_const(params, k.as_ptr()) }.is_null();
            return c_int::from(match search_type {
                OSSL_STORE_SEARCH_BY_NAME => has(OSSL_STORE_PARAM_SUBJECT),
                OSSL_STORE_SEARCH_BY_ISSUER_SERIAL => has(OSSL_STORE_PARAM_ISSUER) && has(OSSL_STORE_PARAM_SERIAL),
                OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT => has(OSSL_STORE_PARAM_FINGERPRINT),
                OSSL_STORE_SEARCH_BY_ALIAS => has(OSSL_STORE_PARAM_ALIAS),
                _ => false,
            });
        }
        // SAFETY: as above.
        let Some(find) = (unsafe { legacy(l) }).find else { return 0 };
        let tmp = super::info::Search {
            search_type,
            name: ptr::null_mut(),
            serial: ptr::null(),
            digest: ptr::null(),
            string: ptr::null(),
            stringlength: 0,
        };
        // SAFETY: the application's loader, asked with no context as OpenSSL asks.
        unsafe { find(ptr::null_mut(), ptr::from_ref(&tmp).cast()) }
    }
}

ffi_export! {
    /// Reads from `bp` with the loader for the scheme (`file` by default): the store's
    /// context, or NULL.
    ///
    /// # Safety
    /// `bp` is a live BIO that outlives the context; the other arguments as for
    /// [`OSSL_STORE_open_ex`].
    pub unsafe extern "C" fn OSSL_STORE_attach(bp: *mut BIO, scheme: *const c_char, libctx: *mut OSSL_LIB_CTX, propq: *const c_char, ui_method: *const UI_METHOD, ui_data: *mut c_void, params: *const OSSL_PARAM, post_process: OSSL_STORE_post_process_info_fn, post_process_data: *mut c_void) -> *mut OSSL_STORE_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_OSSL_STORE
    {
        let scheme = if scheme.is_null() { c"file".as_ptr() } else { scheme };
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        // SAFETY: the caller's string.
        let reg = registered(unsafe { CStr::from_ptr(scheme) }.to_bytes());
        let (l, fetched, lctx) = if reg.is_null() {
            // SAFETY: the caller's arguments.
            unsafe { attach_provided(bp, scheme, libctx, propq, params) }
        } else {
            // SAFETY: a registered loader, live while registered.
            let lctx = match unsafe { legacy(reg) }.attach {
                // SAFETY: the application's loader, with the caller's arguments.
                Some(attach) => unsafe { attach(reg, bp, libctx, propq, ui_method, ui_data) },
                None => ptr::null_mut(),
            };
            (reg, false, lctx.cast())
        };
        if lctx.is_null() {
            // SAFETY: the mark set above.
            unsafe { ERR_clear_last_mark() };
            return ptr::null_mut();
        }
        let mut pwdata = PwData::default();
        if !ui_method.is_null() && !pwdata.set_ui_method(ui_method, ui_data) {
            // SAFETY: the loader and its context, attached here.
            unsafe { close_loader(l, fetched, lctx) };
            if fetched {
                // SAFETY: the reference fetched.
                unsafe { OSSL_STORE_LOADER_free(l) };
            }
            // SAFETY: as above.
            unsafe { ERR_clear_last_mark() };
            return ptr::null_mut();
        }
        let ctx = Box::into_raw(Box::new(Ctx {
            loader: l,
            fetched,
            loader_ctx: lctx,
            expected_type: 0,
            properties: ptr::null_mut(),
            post_process,
            post_process_data,
            cached_info: None,
            pwdata,
            loading: false,
            error_flag: false,
        }));
        // SAFETY: as above.
        unsafe { ERR_pop_to_mark() };
        ctx.cast()
    }
}

/// `OSSL_STORE_attach` with a provider's loader.
///
/// # Safety
/// As for [`OSSL_STORE_attach`], `scheme` a C string.
unsafe fn attach_provided(
    bp: *mut BIO,
    scheme: *const c_char,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
    params: *const OSSL_PARAM,
) -> Opened {
    // SAFETY: the caller's arguments.
    let fl = unsafe { OSSL_STORE_LOADER_fetch(libctx, scheme, propq) };
    // SAFETY: the loader fetched here, or NULL.
    let Some(p) = (unsafe { provided(fl) }) else {
        return (ptr::null_mut(), true, ptr::null_mut());
    };
    // SAFETY: its live provider.
    let provctx = unsafe { OSSL_PROVIDER_get0_provider_ctx(p.prov.0) };
    // SAFETY: the caller's BIO.
    let cbio = unsafe { core_bio_new_from_bio(bp) };
    let mut lctx = ptr::null_mut();
    if let (false, Some(attach)) = (cbio.is_null(), p.attach) {
        // SAFETY: the provider's function on a core BIO of the caller's.
        lctx = unsafe { attach(provctx, cbio) };
        // SAFETY: the loader and its new context.
        if !lctx.is_null() && !unsafe { loader_set_params(fl, lctx, params, propq) } {
            // SAFETY: as above.
            unsafe { close_loader(fl, true, lctx) };
            lctx = ptr::null_mut();
        }
    }
    // SAFETY: made here (a reference to the BIO), or NULL; the loader keeps its own.
    unsafe { crate::bio::BIO_free(cbio.cast()) };
    if lctx.is_null() {
        // SAFETY: the reference fetched here.
        unsafe { OSSL_STORE_LOADER_free(fl) };
        return (ptr::null_mut(), true, ptr::null_mut());
    }
    (fl, true, lctx)
}
