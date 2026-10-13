//! Key encapsulation (`EVP_KEM(3)`, `EVP_PKEY_encapsulate(3)`, `EVP_PKEY_decapsulate(3)`;
//! `kem.c`): an `EVP_KEM` made from a provider's algorithm, fetched and introspected, and the
//! key context's encapsulation and decapsulation through it.
//!
//! As in OpenSSL:
//! - A KEM must have `newctx` and `freectx`, as many encapsulation functions as decapsulation
//!   ones (none, the function and one init, or both inits), and its parameter getters and
//!   setters in pairs.
//! - The init finds the KEM the key manager names and exports the key (and the authentication
//!   key, which must be of the key's type) to its provider's key manager. There's no legacy
//!   path: a key manager's provider without the KEM fails with
//!   `EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE`, and the fetches' errors stay queued.
//!
//! A KEM whose encapsulation functions are the two inits without the function would crash the
//! reference when it encapsulates; it fails here (docs/DEVIATIONS.md).

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_EVP, ERR_R_INTERNAL_ERROR, EVP_KEM, EVP_PKEY, EVP_PKEY_CTX, EVP_PKEY_OP_DECAPSULATE,
    EVP_PKEY_OP_ENCAPSULATE, EVP_PKEY_OP_UNDEFINED, EVP_R_DIFFERENT_KEY_TYPES,
    EVP_R_INITIALIZATION_ERROR, EVP_R_NO_KEY_SET, EVP_R_OPERATION_NOT_INITIALIZED,
    EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE, OSSL_FUNC_KEM_AUTH_DECAPSULATE_INIT,
    OSSL_FUNC_KEM_AUTH_ENCAPSULATE_INIT, OSSL_FUNC_KEM_DECAPSULATE, OSSL_FUNC_KEM_DECAPSULATE_INIT,
    OSSL_FUNC_KEM_DUPCTX, OSSL_FUNC_KEM_ENCAPSULATE, OSSL_FUNC_KEM_ENCAPSULATE_INIT,
    OSSL_FUNC_KEM_FREECTX, OSSL_FUNC_KEM_GET_CTX_PARAMS, OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS,
    OSSL_FUNC_KEM_NEWCTX, OSSL_FUNC_KEM_SET_CTX_PARAMS, OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,
    OSSL_LIB_CTX, OSSL_OP_KEM, OSSL_PARAM, OSSL_PROVIDER,
};

use super::fetch::Kind;
use super::keymgmt;
use super::opmeth::{self, AnyFn, Common, OpMethod, Table, keep, method_exports};
use super::pkey::{self, PkeyRef};
use super::pkey_ctx;
use crate::err;
use crate::ffi::ffi_export;
use crate::handle::handle_type;
use crate::provider::Ptr;

type InitFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *const OSSL_PARAM) -> c_int;
type AuthInitFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *const OSSL_PARAM) -> c_int;
type EncapsulateFn =
    unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, *mut u8, *mut usize) -> c_int;
type DecapsulateFn =
    unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, *const u8, usize) -> c_int;

/// A KEM's functions.
#[derive(Default, Clone, Copy)]
pub(crate) struct Funcs {
    common: Common,
    encapsulate_init: Option<InitFn>,
    auth_encapsulate_init: Option<AuthInitFn>,
    encapsulate: Option<EncapsulateFn>,
    decapsulate_init: Option<InitFn>,
    auth_decapsulate_init: Option<AuthInitFn>,
    decapsulate: Option<DecapsulateFn>,
}

impl Table for Funcs {
    const FROM_ALGORITHM: &'static str = "evp_kem_from_algorithm";

    fn set(&mut self, id: c_int, f: AnyFn) {
        let c = &mut self.common;
        match id {
            OSSL_FUNC_KEM_NEWCTX => keep!(c.newctx, f),
            OSSL_FUNC_KEM_ENCAPSULATE_INIT => keep!(self.encapsulate_init, f),
            OSSL_FUNC_KEM_AUTH_ENCAPSULATE_INIT => keep!(self.auth_encapsulate_init, f),
            OSSL_FUNC_KEM_ENCAPSULATE => keep!(self.encapsulate, f),
            OSSL_FUNC_KEM_DECAPSULATE_INIT => keep!(self.decapsulate_init, f),
            OSSL_FUNC_KEM_AUTH_DECAPSULATE_INIT => keep!(self.auth_decapsulate_init, f),
            OSSL_FUNC_KEM_DECAPSULATE => keep!(self.decapsulate, f),
            OSSL_FUNC_KEM_FREECTX => keep!(c.freectx, f),
            OSSL_FUNC_KEM_DUPCTX => keep!(c.dupctx, f),
            OSSL_FUNC_KEM_GET_CTX_PARAMS => keep!(c.get_ctx_params, f),
            OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS => keep!(c.gettable_ctx_params, f),
            OSSL_FUNC_KEM_SET_CTX_PARAMS => keep!(c.set_ctx_params, f),
            OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS => keep!(c.settable_ctx_params, f),
            _ => {}
        }
    }

    fn whole(&self) -> bool {
        let c = &self.common;
        let enc = usize::from(self.encapsulate_init.is_some())
            + usize::from(self.auth_encapsulate_init.is_some())
            + usize::from(self.encapsulate.is_some());
        let dec = usize::from(self.decapsulate_init.is_some())
            + usize::from(self.auth_decapsulate_init.is_some())
            + usize::from(self.decapsulate.is_some());
        c.newctx.is_some()
            && c.freectx.is_some()
            && matches!(enc, 0 | 2 | 3)
            && matches!(dec, 0 | 2 | 3)
            && enc == dec
            && c.params_paired()
    }

    fn common(&self) -> &Common {
        &self.common
    }
}

/// A KEM (`EVP_KEM`).
pub(crate) type Kem = OpMethod<Funcs>;

handle_type!(EVP_KEM => Kem);

/// A reference to a KEM.
pub(crate) type Ref = opmeth::Ref<EVP_KEM>;

/// KEMs to fetching.
static KEMS: Kind = Kind {
    operation: OSSL_OP_KEM,
    from_algorithm: opmeth::from_algorithm::<EVP_KEM, Funcs>,
    up_ref: opmeth::up_ref::<EVP_KEM>,
    free: opmeth::free::<EVP_KEM>,
};

method_exports! {
    EVP_KEM, KEMS;
    pub unsafe extern "C" fn EVP_KEM_fetch;
    pub unsafe extern "C" fn EVP_KEM_up_ref;
    pub unsafe extern "C" fn EVP_KEM_free;
    pub unsafe extern "C" fn EVP_KEM_get0_provider;
    pub unsafe extern "C" fn EVP_KEM_get0_name;
    pub unsafe extern "C" fn EVP_KEM_get0_description;
    pub unsafe extern "C" fn EVP_KEM_is_a;
    pub unsafe extern "C" fn EVP_KEM_names_do_all;
    pub unsafe extern "C" fn EVP_KEM_do_all_provided;
    pub unsafe extern "C" fn EVP_KEM_gettable_ctx_params;
    pub unsafe extern "C" fn EVP_KEM_settable_ctx_params;
}

/// `evp_kem_init`: starts encapsulating or decapsulating, authenticated with `authkey` if
/// given. 1, or <= 0 with an error.
///
/// # Safety
/// `ctx` is NULL or a live context; `params` is NULL or an array; `authkey` is NULL or a live
/// key.
unsafe fn kem_init(
    ctx: *mut EVP_PKEY_CTX,
    operation: c_int,
    params: *const OSSL_PARAM,
    authkey: *mut EVP_PKEY,
) -> c_int {
    const F: &str = "evp_kem_init";
    // SAFETY: the caller's guarantee.
    let c = unsafe { pkey_ctx::context(ctx) };
    let Some(c) = c.filter(|c| c.lock().keytype().is_some()) else {
        err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
        return 0;
    };
    let (libctx, keymgmt, pkey, propq) = {
        let mut s = c.lock();
        s.free_old_ops();
        s.operation = operation;
        (
            s.libctx.0,
            s.keymgmt.clone(),
            s.pkey.clone(),
            s.propquery.clone(),
        )
    };
    let fail = |ret: c_int| {
        let mut s = c.lock();
        s.free_old_ops();
        s.operation = EVP_PKEY_OP_UNDEFINED;
        ret
    };
    let Some(pkey) = pkey else {
        err::raise(ERR_LIB_EVP, EVP_R_NO_KEY_SET, F);
        return fail(0);
    };
    // SAFETY: the caller's guarantee.
    let auth = unsafe { PkeyRef::new(authkey) };
    if let Some(a) = &auth
        && a.get().type_() != pkey.get().type_()
    {
        err::raise(ERR_LIB_EVP, EVP_R_DIFFERENT_KEY_TYPES, F);
        return 0;
    }
    let Some(km) = keymgmt else {
        // A legacy context: its method has no KEM. OpenSSL asserts the key's key manager is the
        // context's (none), then finds no KEM's name without one.
        let reason = if pkey.get().is_provided() {
            ERR_R_INTERNAL_ERROR
        } else {
            EVP_R_INITIALIZATION_ERROR
        };
        err::raise(ERR_LIB_EVP, reason, F);
        return fail(0);
    };
    let supported = km.get().query_operation_name(OSSL_OP_KEM);
    let mut found = None;
    for iter in 1..3 {
        let kem: Option<Ref> = if iter == 1 {
            // SAFETY: the context's library context; the KEMs' kind.
            unsafe { opmeth::fetch_by_name(libctx, &KEMS, &supported, propq.as_deref()) }
        } else {
            // SAFETY: the key manager's live provider; the KEMs' kind.
            let k = unsafe {
                opmeth::fetch_from_prov(km.get().prov.0, &KEMS, &supported, propq.as_deref())
            };
            if k.is_none() {
                err::raise(
                    ERR_LIB_EVP,
                    EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
                    F,
                );
                return fail(-2);
            }
            k
        };
        let Some(kem) = kem else { continue };
        // SAFETY: the KEM's live provider.
        let tmp = unsafe {
            keymgmt::fetch_from_prov(kem.get().prov.0, km.get().name(), propq.as_deref())
        };
        let Some(tmp) = tmp else { continue };
        // SAFETY: the context's library context.
        let Some((tmp, kd)) =
            (unsafe { pkey::export_to_any(&pkey, libctx, Some(tmp), propq.as_deref()) })
        else {
            continue;
        };
        let akd = match &auth {
            None => None,
            // SAFETY: as above.
            Some(a) => match unsafe { pkey::export_to_any(a, libctx, Some(tmp), propq.as_deref()) }
            {
                Some((_, akd)) => Some(akd),
                None => {
                    err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
                    return fail(0);
                }
            },
        };
        found = Some((kem, kd, akd));
        break;
    }
    let Some((m, kd, akd)) = found else {
        err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
        return fail(0);
    };
    let algctx = m.get().newctx();
    {
        let mut s = c.lock();
        s.kem = Some(m.clone());
        s.kemctx = Ptr(algctx);
    }
    if algctx.is_null() {
        err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
        return fail(0);
    }
    let f = &m.get().funcs;
    let (init, auth_init) = if operation == EVP_PKEY_OP_ENCAPSULATE {
        (f.encapsulate_init, f.auth_encapsulate_init)
    } else {
        (f.decapsulate_init, f.auth_decapsulate_init)
    };
    let ret = match (&akd, init, auth_init) {
        // SAFETY: the provider's function with its context, the keys' data, and the array.
        (Some(a), _, Some(ai)) => unsafe { ai(algctx, kd.ptr(), a.ptr(), params) },
        // SAFETY: as above.
        (None, Some(i), _) => unsafe { i(algctx, kd.ptr(), params) },
        _ => {
            err::raise(
                ERR_LIB_EVP,
                EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
                F,
            );
            return fail(-2);
        }
    };
    if ret > 0 {
        return 1;
    }
    fail(ret)
}

ffi_export! {
    /// Starts encapsulating with the KEM the key's type names.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `params` is NULL or an array.
    pub unsafe extern "C" fn EVP_PKEY_encapsulate_init(ctx: *mut EVP_PKEY_CTX, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { kem_init(ctx, EVP_PKEY_OP_ENCAPSULATE, params, ptr::null_mut()) }
    }
}

ffi_export! {
    /// Starts encapsulating, authenticated with the private key `authpriv`. 0 for a NULL key.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `authpriv` is NULL or a live key; `params` is NULL or an
    /// array.
    pub unsafe extern "C" fn EVP_PKEY_auth_encapsulate_init(ctx: *mut EVP_PKEY_CTX, authpriv: *mut EVP_PKEY, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if authpriv.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { kem_init(ctx, EVP_PKEY_OP_ENCAPSULATE, params, authpriv) }
    }
}

ffi_export! {
    /// Starts decapsulating with the KEM the key's type names.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `params` is NULL or an array.
    pub unsafe extern "C" fn EVP_PKEY_decapsulate_init(ctx: *mut EVP_PKEY_CTX, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { kem_init(ctx, EVP_PKEY_OP_DECAPSULATE, params, ptr::null_mut()) }
    }
}

ffi_export! {
    /// Starts decapsulating, authenticated with the public key `authpub`. 0 for a NULL key.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `authpub` is NULL or a live key; `params` is NULL or an
    /// array.
    pub unsafe extern "C" fn EVP_PKEY_auth_decapsulate_init(ctx: *mut EVP_PKEY_CTX, authpub: *mut EVP_PKEY, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if authpub.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { kem_init(ctx, EVP_PKEY_OP_DECAPSULATE, params, authpub) }
    }
}

/// The context's KEM and its context during `operation`, or the C function's error and value.
fn kem_op(
    c: &pkey_ctx::PkeyCtx,
    operation: c_int,
    function: &str,
) -> Result<(Ref, *mut c_void), c_int> {
    let s = c.lock();
    if s.operation != operation {
        drop(s);
        err::raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_INITIALIZED, function);
        return Err(-1);
    }
    match (s.kem.clone(), s.kemctx.0) {
        (Some(m), algctx) if !algctx.is_null() => Ok((m, algctx)),
        _ => {
            drop(s);
            err::raise(
                ERR_LIB_EVP,
                EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
                function,
            );
            Err(-2)
        }
    }
}

ffi_export! {
    /// Makes a shared secret into `secret` and its encapsulation into `out` (lengths in and
    /// out through `*secretlen` and `*outlen`); with a NULL `out`, the sizes they need.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `out` and `secret` are NULL or have room for their
    /// lengths; `outlen` and `secretlen` are room for sizes (or NULL where the KEM allows).
    pub unsafe extern "C" fn EVP_PKEY_encapsulate(ctx: *mut EVP_PKEY_CTX, out: *mut u8, outlen: *mut usize, secret: *mut u8, secretlen: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "EVP_PKEY_encapsulate";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { pkey_ctx::context(ctx) }) else { return 0 };
        let (m, algctx) = match kem_op(c, EVP_PKEY_OP_ENCAPSULATE, F) {
            Ok(v) => v,
            Err(r) => return r,
        };
        if !out.is_null() && secret.is_null() {
            return 0;
        }
        let Some(f) = m.get().funcs.encapsulate else {
            // The reference calls the missing function (docs/DEVIATIONS.md).
            err::raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE, F);
            return -2;
        };
        // SAFETY: the provider's function with its context and the caller's buffers.
        unsafe { f(algctx, out, outlen, secret, secretlen) }
    }
}

ffi_export! {
    /// Recovers the shared secret from the `inlen` octets at `in_` into `secret` (its room in
    /// `*secretlen`, the length back); with a NULL `secret`, the size it needs.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `secret` is NULL or has room for `*secretlen` octets;
    /// `secretlen` is NULL or room for a size; `in_` holds `inlen` octets.
    pub unsafe extern "C" fn EVP_PKEY_decapsulate(ctx: *mut EVP_PKEY_CTX, secret: *mut u8, secretlen: *mut usize, in_: *const u8, inlen: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "EVP_PKEY_decapsulate";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { pkey_ctx::context(ctx) }) else { return 0 };
        if in_.is_null() || inlen == 0 || (secret.is_null() && secretlen.is_null()) {
            return 0;
        }
        let (m, algctx) = match kem_op(c, EVP_PKEY_OP_DECAPSULATE, F) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let Some(f) = m.get().funcs.decapsulate else {
            // The reference calls the missing function (docs/DEVIATIONS.md).
            err::raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE, F);
            return -2;
        };
        // SAFETY: the provider's function with its context and the caller's buffers.
        unsafe { f(algctx, secret, secretlen, in_, inlen) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: a NULL KEM is refused (the reference crashes).
    #[test]
    fn null_methods_are_refused() {
        let m: *mut EVP_KEM = ptr::null_mut();
        // SAFETY: NULL is the case under test, here and below.
        assert_eq!(unsafe { EVP_KEM_up_ref(m) }, 0);
        // SAFETY: as above.
        assert!(unsafe { EVP_KEM_get0_description(m) }.is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_KEM_is_a(m, c"ML-KEM-768".as_ptr()) }, 0);
        // SAFETY: as above.
        assert!(unsafe { EVP_KEM_settable_ctx_params(m) }.is_null());
        crate::err::take_all();
    }

    mod halfkem {
        //! A provider whose KEM has both encapsulation inits but no encapsulation (and the same
        //! for decapsulation), which makes a whole by OpenSSL's count.

        use core::ffi::{c_char, c_int, c_void};
        use core::ptr;

        use rustyssl_abi::{
            OSSL_ALGORITHM, OSSL_CORE_HANDLE, OSSL_DISPATCH, OSSL_FUNC_KEM_AUTH_DECAPSULATE_INIT,
            OSSL_FUNC_KEM_AUTH_ENCAPSULATE_INIT, OSSL_FUNC_KEM_DECAPSULATE_INIT,
            OSSL_FUNC_KEM_ENCAPSULATE_INIT, OSSL_FUNC_KEM_FREECTX, OSSL_FUNC_KEM_NEWCTX,
            OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_HAS, OSSL_FUNC_KEYMGMT_IMPORT,
            OSSL_FUNC_KEYMGMT_IMPORT_TYPES, OSSL_FUNC_KEYMGMT_NEW,
            OSSL_FUNC_PROVIDER_QUERY_OPERATION, OSSL_OP_KEM, OSSL_OP_KEYMGMT, OSSL_PARAM,
        };

        use crate::provider::tables::{ALG_END, Algorithms, Dispatch, END, entry};

        /// A key or a context: one octet, boxed.
        unsafe extern "C" fn new(_provctx: *mut c_void) -> *mut c_void {
            Box::into_raw(Box::new(0u8)).cast()
        }

        unsafe extern "C" fn free(p: *mut c_void) {
            if !p.is_null() {
                // SAFETY: a box `new` made.
                drop(unsafe { Box::from_raw(p.cast::<u8>()) });
            }
        }

        unsafe extern "C" fn has(_k: *const c_void, _selection: c_int) -> c_int {
            1
        }

        unsafe extern "C" fn import(_k: *mut c_void, _s: c_int, _p: *const OSSL_PARAM) -> c_int {
            1
        }

        static NO_PARAMS: crate::provider::tables::Params<1> =
            crate::provider::tables::Params([crate::provider::tables::PARAM_END]);

        unsafe extern "C" fn types(_s: c_int) -> *const OSSL_PARAM {
            NO_PARAMS.0.as_ptr()
        }

        unsafe extern "C" fn init(
            _c: *mut c_void,
            _k: *mut c_void,
            _p: *const OSSL_PARAM,
        ) -> c_int {
            1
        }

        unsafe extern "C" fn auth_init(
            _c: *mut c_void,
            _k: *mut c_void,
            _a: *mut c_void,
            _p: *const OSSL_PARAM,
        ) -> c_int {
            1
        }

        type NewFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
        type FreeFn = unsafe extern "C" fn(*mut c_void);
        type HasFn = unsafe extern "C" fn(*const c_void, c_int) -> c_int;
        type ImportFn = unsafe extern "C" fn(*mut c_void, c_int, *const OSSL_PARAM) -> c_int;
        type TypesFn = unsafe extern "C" fn(c_int) -> *const OSSL_PARAM;
        type InitFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *const OSSL_PARAM) -> c_int;
        type AuthFn =
            unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *const OSSL_PARAM) -> c_int;
        type QueryFn =
            unsafe extern "C" fn(*mut c_void, c_int, *mut c_int) -> *const OSSL_ALGORITHM;

        static KEYMGMT: Dispatch<6> = Dispatch([
            entry!(OSSL_FUNC_KEYMGMT_NEW, new, NewFn),
            entry!(OSSL_FUNC_KEYMGMT_FREE, free, FreeFn),
            entry!(OSSL_FUNC_KEYMGMT_HAS, has, HasFn),
            entry!(OSSL_FUNC_KEYMGMT_IMPORT, import, ImportFn),
            entry!(OSSL_FUNC_KEYMGMT_IMPORT_TYPES, types, TypesFn),
            END,
        ]);

        static KEM: Dispatch<7> = Dispatch([
            entry!(OSSL_FUNC_KEM_NEWCTX, new, NewFn),
            entry!(OSSL_FUNC_KEM_FREECTX, free, FreeFn),
            entry!(OSSL_FUNC_KEM_ENCAPSULATE_INIT, init, InitFn),
            entry!(OSSL_FUNC_KEM_AUTH_ENCAPSULATE_INIT, auth_init, AuthFn),
            entry!(OSSL_FUNC_KEM_DECAPSULATE_INIT, init, InitFn),
            entry!(OSSL_FUNC_KEM_AUTH_DECAPSULATE_INIT, auth_init, AuthFn),
            END,
        ]);

        const fn algs(table: &'static [OSSL_DISPATCH]) -> [OSSL_ALGORITHM; 2] {
            [
                OSSL_ALGORITHM {
                    algorithm_names: c"HALFKEM".as_ptr(),
                    property_definition: c"provider=halfkem".as_ptr(),
                    implementation: table.as_ptr(),
                    algorithm_description: ptr::null(),
                },
                ALG_END,
            ]
        }

        static KEYMGMTS: Algorithms<2> = Algorithms(algs(&KEYMGMT.0));
        static KEMS: Algorithms<2> = Algorithms(algs(&KEM.0));

        unsafe extern "C" fn query(
            _p: *mut c_void,
            op: c_int,
            no_cache: *mut c_int,
        ) -> *const OSSL_ALGORITHM {
            // SAFETY: the core's pointer.
            unsafe { no_cache.write(0) };
            match op {
                OSSL_OP_KEYMGMT => KEYMGMTS.0.as_ptr(),
                OSSL_OP_KEM => KEMS.0.as_ptr(),
                _ => ptr::null(),
            }
        }

        static PROVIDER: Dispatch<2> = Dispatch([
            entry!(OSSL_FUNC_PROVIDER_QUERY_OPERATION, query, QueryFn),
            END,
        ]);

        /// The provider's init function.
        pub(super) unsafe extern "C" fn provider_init(
            _handle: *const OSSL_CORE_HANDLE,
            _in: *const OSSL_DISPATCH,
            out: *mut *const OSSL_DISPATCH,
            provctx: *mut *mut c_void,
        ) -> c_int {
            // SAFETY: the core's pointers.
            unsafe { out.write(PROVIDER.0.as_ptr()) };
            // SAFETY: as above.
            unsafe { provctx.write(ptr::null_mut()) };
            1
        }

        /// The provider's name.
        pub(super) const NAME: *const c_char = c"halfkem".as_ptr();
    }

    /// docs/DEVIATIONS.md: a KEM with the inits but not the function fails to encapsulate (the
    /// reference calls the missing function).
    #[test]
    fn missing_functions_are_refused() {
        use crate::evp::pkey::EVP_PKEY_free;
        use crate::evp::pkey_ctx::{
            EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_name, EVP_PKEY_CTX_new_from_pkey,
            EVP_PKEY_fromdata, EVP_PKEY_fromdata_init,
        };
        use crate::libctx::{OSSL_LIB_CTX_free, OSSL_LIB_CTX_new};
        use crate::provider::{
            OSSL_PROVIDER_add_builtin, OSSL_PROVIDER_load, OSSL_PROVIDER_unload,
        };

        // SAFETY: no preconditions.
        let lib = unsafe { OSSL_LIB_CTX_new() };
        // SAFETY: the context; a static name; the init function.
        let added =
            unsafe { OSSL_PROVIDER_add_builtin(lib, halfkem::NAME, Some(halfkem::provider_init)) };
        assert_eq!(added, 1);
        // SAFETY: the context; a static name.
        let prov = unsafe { OSSL_PROVIDER_load(lib, halfkem::NAME) };
        assert!(!prov.is_null());
        // SAFETY: the context; a static name.
        let g = unsafe { EVP_PKEY_CTX_new_from_name(lib, c"HALFKEM".as_ptr(), ptr::null()) };
        let mut k: *mut EVP_PKEY = ptr::null_mut();
        // SAFETY: the context.
        assert_eq!(unsafe { EVP_PKEY_fromdata_init(g) }, 1);
        // SAFETY: the context; the key pointer; no parameters.
        let got = unsafe {
            EVP_PKEY_fromdata(
                g,
                &raw mut k,
                crate::evp::pkey_ctx::KEYPAIR,
                ptr::null_mut(),
            )
        };
        assert_eq!(got, 1);
        // SAFETY: the context and key.
        let c = unsafe { EVP_PKEY_CTX_new_from_pkey(lib, k, ptr::null()) };
        // SAFETY: the context.
        assert_eq!(unsafe { EVP_PKEY_encapsulate_init(c, ptr::null()) }, 1);
        let (mut out, mut sec) = ([0u8; 8], [0u8; 8]);
        let (mut outlen, mut seclen) = (8usize, 8usize);
        // SAFETY: the context; the buffers.
        let got = unsafe {
            EVP_PKEY_encapsulate(
                c,
                out.as_mut_ptr(),
                &raw mut outlen,
                sec.as_mut_ptr(),
                &raw mut seclen,
            )
        };
        assert_eq!(got, -2);
        // SAFETY: the context.
        assert_eq!(unsafe { EVP_PKEY_decapsulate_init(c, ptr::null()) }, 1);
        // SAFETY: the context; the buffers.
        let got =
            unsafe { EVP_PKEY_decapsulate(c, sec.as_mut_ptr(), &raw mut seclen, out.as_ptr(), 8) };
        assert_eq!(got, -2);
        // SAFETY: made above, here and below.
        unsafe { EVP_PKEY_CTX_free(c) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_CTX_free(g) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(k) };
        // SAFETY: as above.
        unsafe { OSSL_PROVIDER_unload(prov) };
        // SAFETY: as above, its objects freed.
        unsafe { OSSL_LIB_CTX_free(lib) };
        crate::err::take_all();
    }
}
