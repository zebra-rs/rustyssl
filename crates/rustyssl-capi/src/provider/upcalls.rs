//! The core's dispatch table (`provider-base(7)`, `core_dispatch_` in `crypto/provider_core.c`):
//! the functions a provider's init function gets to call back into the library, with the
//! provider's handle (its `OSSL_PROVIDER`). It is OpenSSL's table entry for entry, in its order
//! (docs/adr/0003-external-providers.md):
//!
//! - the core's parameters (`openssl-version`, `provider-name`, `module-filename`, then the
//!   provider's configuration), its library context, and thread-stop handlers;
//! - errors: a reason without a library is the provider's own, raised in the library number it
//!   was given; the marks;
//! - the core BIOs (`OSSL_CORE_BIO` is a `BIO` here, with its references) and `BIO_vsnprintf`;
//! - the self-test and indicator callbacks, the entropy and nonces (the system's, and the user's:
//!   the context's seed source once it has one);
//! - memory (the exported `CRYPTO_*` functions, so a provider's allocations honor
//!   `CRYPTO_set_mem_functions`), `OPENSSL_cleanse`;
//! - the child-provider callbacks and the provider functions (name, context, dispatch, references
//!   and activations);
//! - `obj_add_sigid` and `obj_create`.
//!
//! Each upcall of its own is an `ffi_callback!`, so a panic can't unwind into the provider. Where
//! OpenSSL's points straight at a library function, so does this table.

use core::ffi::{CStr, VaList, c_char, c_int, c_long, c_void};
use core::ptr;

use rustyssl_abi::{
    BIO, ERR_LIB_CRYPTO, NID_undef, OPENSSL_CORE_CTX, OPENSSL_VERSION_STR, OSSL_CORE_HANDLE,
    OSSL_DISPATCH, OSSL_LIB_CTX, OSSL_PARAM, OSSL_PARAM_UTF8_PTR,
    OSSL_PROV_PARAM_CORE_MODULE_FILENAME, OSSL_PROV_PARAM_CORE_PROV_NAME,
    OSSL_PROV_PARAM_CORE_VERSION, OSSL_PROVIDER,
};

use super::Provider;
use crate::ffi::ffi_callback;
use crate::handle::Handle;
use crate::params::{OSSL_PARAM_locate, OSSL_PARAM_set_utf8_ptr};

/// The provider behind a core handle, or `None` for NULL.
///
/// # Safety
/// `handle` is NULL or a provider's handle.
unsafe fn provider<'a>(handle: *const OSSL_CORE_HANDLE) -> Option<&'a Provider> {
    // SAFETY: the caller's guarantee: a core handle is a provider.
    unsafe { OSSL_PROVIDER::get(handle.cast()) }
}

// ---- the core's parameters ----

/// `param_types`: what `core_get_params` reports, ended by an empty one.
struct Gettable([OSSL_PARAM; 4]);

// SAFETY: the keys are static strings; the array is never written.
unsafe impl Sync for Gettable {}

const fn defn(key: &'static CStr) -> OSSL_PARAM {
    OSSL_PARAM {
        key: key.as_ptr(),
        data_type: OSSL_PARAM_UTF8_PTR.cast_unsigned(),
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    }
}

static GETTABLE: Gettable = Gettable([
    defn(OSSL_PROV_PARAM_CORE_VERSION),
    defn(OSSL_PROV_PARAM_CORE_PROV_NAME),
    defn(OSSL_PROV_PARAM_CORE_MODULE_FILENAME),
    OSSL_PARAM {
        key: ptr::null(),
        data_type: 0,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    },
]);

ffi_callback! {
    /// `core_gettable_params`: the parameters the core reports.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn core_gettable_params(_handle: *const OSSL_CORE_HANDLE) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_CRYPTO
    {
        GETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `core_get_params`: the core's version, the provider's name and module file (a provider
    /// without a module raises the DSO's `ERR_R_PASSED_NULL_PARAMETER` and gets NULL), then its
    /// configuration parameters (`OSSL_PROVIDER_get_conf_parameters`'s result).
    ///
    /// # Safety
    /// `handle` is a provider's handle; `params` an array ended by a NULL key whose entries may
    /// be written.
    pub(crate) unsafe extern "C" fn core_get_params(handle: *const OSSL_CORE_HANDLE, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(prov) = (unsafe { provider(handle) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_PROV_PARAM_CORE_VERSION.as_ptr()) };
        if !p.is_null() {
            // SAFETY: a parameter of the array; a static string.
            unsafe { OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR.as_ptr()) };
        }
        // SAFETY: as above.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_PROV_PARAM_CORE_PROV_NAME.as_ptr()) };
        if !p.is_null() {
            // SAFETY: as above; the name lives with the provider.
            unsafe { OSSL_PARAM_set_utf8_ptr(p, prov.name().as_ptr()) };
        }
        // SAFETY: as above.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_PROV_PARAM_CORE_MODULE_FILENAME.as_ptr()) };
        if !p.is_null() {
            // SAFETY: as above; the file name lives with the provider's module, or NULL.
            unsafe { OSSL_PARAM_set_utf8_ptr(p, prov.module_filename()) };
        }
        // SAFETY: the caller's guarantee.
        unsafe { super::OSSL_PROVIDER_get_conf_parameters(handle.cast(), params) }
    }
}

ffi_callback! {
    /// `core_get_libctx`: the library context the provider was loaded into, as given (NULL
    /// for the default).
    ///
    /// # Safety
    /// `handle` is a provider's handle.
    pub(crate) unsafe extern "C" fn core_get_libctx(handle: *const OSSL_CORE_HANDLE) -> *mut OPENSSL_CORE_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee: the handle is a provider.
        unsafe { provider(handle) }.map_or(ptr::null_mut(), |p| p.libctx().cast())
    }
}

ffi_callback! {
    /// `core_thread_start`: `handfn(arg)` runs when the calling thread stops
    /// (`OPENSSL_thread_stop` or its exit), unless the provider goes first. Returns 1.
    ///
    /// # Safety
    /// `handle` is a provider's handle; `handfn` takes `arg`.
    pub(crate) unsafe extern "C" fn core_thread_start(handle: *const OSSL_CORE_HANDLE, handfn: rustyssl_abi::OSSL_thread_stop_handler_fn, arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(prov) = (unsafe { provider(handle) }) else { return 0 };
        let Some(handfn) = handfn else { return 0 };
        c_int::from(crate::threads::add_stop_handler(ptr::from_ref(prov).addr(), handfn, arg))
    }
}

// ---- errors ----

ffi_callback! {
    /// `core_new_error`: `ERR_new`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn core_new_error(_handle: *const OSSL_CORE_HANDLE)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_new() };
    }
}

ffi_callback! {
    /// `core_set_error_debug`: `ERR_set_debug`.
    ///
    /// # Safety
    /// `file` and `func` are NULL or strings.
    pub(crate) unsafe extern "C" fn core_set_error_debug(_handle: *const OSSL_CORE_HANDLE, file: *const c_char, line: c_int, func: *const c_char)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { crate::err::ERR_set_debug(file, line, func) };
    }
}

ffi_callback! {
    /// `core_vset_error`: a reason with a library number is that library's, as raised by the
    /// library itself; one without is the provider's own, in the library it was given.
    ///
    /// # Safety
    /// `handle` is a provider's handle; `fmt` NULL or a format the arguments match.
    pub(crate) unsafe extern "C" fn core_vset_error(handle: *const OSSL_CORE_HANDLE, reason: u32, fmt: *const c_char, args: VaList<'_>)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let code = core::ffi::c_ulong::from(reason);
        let lib = crate::err::library_of(code);
        let (lib, reason) = if lib != 0 {
            (lib, crate::err::reason_of(code))
        } else {
            // SAFETY: the caller's guarantee.
            let own = unsafe { provider(handle) }.map_or(0, Provider::error_lib);
            (own, c_int::try_from(reason).unwrap_or(c_int::MAX))
        };
        // SAFETY: the caller's guarantee.
        unsafe { crate::err::ERR_vset_error(lib, reason, fmt, args) };
    }
}

ffi_callback! {
    /// `core_set_error_mark`: `ERR_set_mark`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn core_set_error_mark(_handle: *const OSSL_CORE_HANDLE) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_set_mark() }
    }
}

ffi_callback! {
    /// `core_clear_last_error_mark`: `ERR_clear_last_mark`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn core_clear_last_error_mark(_handle: *const OSSL_CORE_HANDLE) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_last_mark() }
    }
}

ffi_callback! {
    /// `core_pop_error_to_mark`: `ERR_pop_to_mark`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn core_pop_error_to_mark(_handle: *const OSSL_CORE_HANDLE) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_pop_to_mark() }
    }
}

ffi_callback! {
    /// `core_count_to_mark`: `ERR_count_to_mark`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn core_count_to_mark(_handle: *const OSSL_CORE_HANDLE) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_count_to_mark() }
    }
}

// ---- objects ----

/// `OBJ_txt2nid` of a string that may be NULL (`NID_undef`).
///
/// # Safety
/// `s` is NULL or a string.
unsafe fn txt2nid(s: *const c_char) -> c_int {
    if s.is_null() {
        return NID_undef;
    }
    // SAFETY: the caller's guarantee.
    unsafe { crate::objects::OBJ_txt2nid(s) }
}

ffi_callback! {
    /// `core_obj_add_sigid`: adds the signature algorithm `sign_name` over the digest
    /// `digest_name` (none if NULL or empty) and the key type `pkey_name`. 1 if it exists already;
    /// 0 if the signature or a given digest is unknown, or the key type is.
    ///
    /// # Safety
    /// Each name is NULL or a string.
    pub(crate) unsafe extern "C" fn core_obj_add_sigid(_handle: *const OSSL_CORE_HANDLE, sign_name: *const c_char, digest_name: *const c_char, pkey_name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let sign = unsafe { txt2nid(sign_name) };
        let mut digest = NID_undef;
        // SAFETY: the caller's guarantee.
        let pkey = unsafe { txt2nid(pkey_name) };
        // SAFETY: as above.
        let named = !digest_name.is_null() && unsafe { *digest_name } != 0;
        if named {
            // SAFETY: as above.
            digest = unsafe { txt2nid(digest_name) };
            if digest == NID_undef {
                return 0;
            }
        }
        if sign == NID_undef {
            return 0;
        }
        // SAFETY: NULL outputs are allowed.
        if unsafe { crate::objects::sigid::OBJ_find_sigid_algs(sign, ptr::null_mut(), ptr::null_mut()) } != 0 {
            return 1;
        }
        if pkey == NID_undef {
            return 0;
        }
        // SAFETY: no pointers.
        unsafe { crate::objects::sigid::OBJ_add_sigid(sign, digest, pkey) }
    }
}

ffi_callback! {
    /// `core_obj_create`: the object `oid` (`sn`, `ln`), made unless it exists. 1 if it does
    /// afterwards.
    ///
    /// # Safety
    /// Each argument is NULL or a string.
    pub(crate) unsafe extern "C" fn core_obj_create(_handle: *const OSSL_CORE_HANDLE, oid: *const c_char, sn: *const c_char, ln: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        if unsafe { txt2nid(oid) } != NID_undef {
            return 1;
        }
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { crate::objects::OBJ_create(oid, sn, ln) } != NID_undef)
    }
}

// ---- entropy and nonces ----

/// A secret's octets in memory of the kind `secure` (`OPENSSL_secure_malloc` or `OPENSSL_malloc`),
/// at `*pout`: the length, or 0 (with `*pout` untouched) if there are none or no memory.
///
/// # Safety
/// `pout` is valid for a write.
unsafe fn hand_out(octets: &[u8], secure: bool, pout: *mut *mut u8) -> usize {
    if octets.is_empty() || pout.is_null() {
        return 0;
    }
    let file = c"provider/upcalls.rs".as_ptr();
    let buf: *mut u8 = if secure {
        // SAFETY: no preconditions.
        unsafe { crate::secure::CRYPTO_secure_malloc(octets.len(), file, 0) }.cast()
    } else {
        // SAFETY: no preconditions.
        unsafe { crate::mem::CRYPTO_malloc(octets.len(), file, 0) }.cast()
    };
    if buf.is_null() {
        return 0;
    }
    // SAFETY: a new buffer of the octets' length.
    unsafe { ptr::copy_nonoverlapping(octets.as_ptr(), buf, octets.len()) };
    // SAFETY: the caller's guarantee.
    unsafe { pout.write(buf) };
    octets.len()
}

/// The library context a core handle's provider was loaded into.
///
/// # Safety
/// `handle` is NULL or a provider's handle.
unsafe fn libctx_of(handle: *const OSSL_CORE_HANDLE) -> *mut OSSL_LIB_CTX {
    // SAFETY: the caller's guarantee.
    unsafe { provider(handle) }.map_or(ptr::null_mut(), Provider::libctx)
}

ffi_callback! {
    /// `rand_get_entropy` (`ossl_rand_get_entropy`): `entropy` bits of the system's entropy in
    /// `min_len` to `max_len` octets of secure memory at `*pout`. The length, or 0.
    ///
    /// # Safety
    /// `pout` is valid for a write.
    pub(crate) unsafe extern "C" fn rand_get_entropy(_handle: *const OSSL_CORE_HANDLE, pout: *mut *mut u8, entropy: c_int, min_len: usize, max_len: usize) -> usize
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let Some(seed) = crate::rand::get_entropy(entropy, min_len, max_len) else { return 0 };
        // SAFETY: the caller's guarantee.
        unsafe { hand_out(&seed.0, true, pout) }
    }
}

ffi_callback! {
    /// `rand_cleanup_entropy`: clears and frees what `rand_get_entropy` gave.
    ///
    /// # Safety
    /// `buf` is NULL or what `rand_get_entropy` gave, of `len` octets.
    pub(crate) unsafe extern "C" fn rand_cleanup_entropy(_handle: *const OSSL_CORE_HANDLE, buf: *mut u8, len: usize)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { crate::secure::CRYPTO_secure_clear_free(buf.cast(), len, c"provider/upcalls.rs".as_ptr(), 0) };
    }
}

ffi_callback! {
    /// `rand_get_user_entropy` (`ossl_rand_get_user_entropy`): from the context's seed source
    /// once it has one that gives seeds, else the system's.
    ///
    /// # Safety
    /// `handle` is a provider's handle; `pout` is valid for a write.
    pub(crate) unsafe extern "C" fn rand_get_user_entropy(handle: *const OSSL_CORE_HANDLE, pout: *mut *mut u8, entropy: c_int, min_len: usize, max_len: usize) -> usize
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let seed = crate::rand_lib::seed_of(unsafe { libctx_of(handle) });
        if !seed.is_null() {
            // SAFETY: the seed source, held.
            let len = if unsafe { crate::evp::rand::can_seed(seed) } {
                // SAFETY: as above; the caller's output.
                Some(unsafe { crate::evp::rand::get_seed(seed, pout, entropy, min_len, max_len, ptr::null(), 0) })
            } else {
                None
            };
            // SAFETY: the reference taken for it.
            unsafe { crate::evp::rand::EVP_RAND_CTX_free(seed) };
            if let Some(len) = len {
                return len;
            }
        }
        let Some(seed) = crate::rand::get_entropy(entropy, min_len, max_len) else { return 0 };
        // SAFETY: the caller's guarantee.
        unsafe { hand_out(&seed.0, true, pout) }
    }
}

ffi_callback! {
    /// `rand_cleanup_user_entropy`: gives the seed source back its seed, or clears and frees the
    /// system's entropy.
    ///
    /// # Safety
    /// `handle` is a provider's handle; `buf` is NULL or what `rand_get_user_entropy` gave.
    pub(crate) unsafe extern "C" fn rand_cleanup_user_entropy(handle: *const OSSL_CORE_HANDLE, buf: *mut u8, len: usize)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let seed = crate::rand_lib::seed_of(unsafe { libctx_of(handle) });
        // SAFETY: the seed source, held, or NULL.
        if !seed.is_null() && unsafe { crate::evp::rand::can_seed(seed) } {
            // SAFETY: the seed source's own seed.
            unsafe { crate::evp::rand::clear_seed(seed, buf, len) };
        } else {
            // SAFETY: the caller's guarantee: the system's entropy, in secure memory.
            unsafe { crate::secure::CRYPTO_secure_clear_free(buf.cast(), len, c"provider/upcalls.rs".as_ptr(), 0) };
        }
        // SAFETY: the reference taken for it, or NULL.
        unsafe { crate::evp::rand::EVP_RAND_CTX_free(seed) };
    }
}

ffi_callback! {
    /// `rand_get_nonce` (`ossl_rand_get_nonce`): the nonce data and the salt in `min_len` to
    /// `max_len` octets at `*pout`. The length, or 0.
    ///
    /// # Safety
    /// `pout` is valid for a write; `salt` is NULL or `salt_len` octets.
    pub(crate) unsafe extern "C" fn rand_get_nonce(_handle: *const OSSL_CORE_HANDLE, pout: *mut *mut u8, min_len: usize, max_len: usize, salt: *const c_void, salt_len: usize) -> usize
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(salt) = (unsafe { crate::ffi::bytes(salt.cast(), salt_len) }) else { return 0 };
        let Some(nonce) = crate::rand::get_nonce(min_len, max_len, salt) else { return 0 };
        // SAFETY: the caller's guarantee.
        unsafe { hand_out(&nonce.0, false, pout) }
    }
}

ffi_callback! {
    /// `rand_get_user_nonce` (`ossl_rand_get_user_nonce`): from the context's seed source once
    /// it has one, else as `rand_get_nonce`.
    ///
    /// # Safety
    /// As for `rand_get_nonce`; `handle` is a provider's handle.
    pub(crate) unsafe extern "C" fn rand_get_user_nonce(handle: *const OSSL_CORE_HANDLE, pout: *mut *mut u8, min_len: usize, max_len: usize, salt: *const c_void, salt_len: usize) -> usize
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(salt) = (unsafe { crate::ffi::bytes(salt.cast(), salt_len) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        let libctx = unsafe { libctx_of(handle) };
        let Some(nonce) = crate::rand::user_nonce(libctx, min_len, max_len, salt) else { return 0 };
        // SAFETY: the caller's guarantee.
        unsafe { hand_out(&nonce.0, false, pout) }
    }
}

ffi_callback! {
    /// `rand_cleanup_nonce` and `rand_cleanup_user_nonce`: clears and frees a nonce.
    ///
    /// # Safety
    /// `buf` is NULL or what one of the nonce functions gave, of `len` octets.
    pub(crate) unsafe extern "C" fn rand_cleanup_nonce(_handle: *const OSSL_CORE_HANDLE, buf: *mut u8, len: usize)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { crate::mem::CRYPTO_clear_free(buf.cast(), len, c"provider/upcalls.rs".as_ptr(), 0) };
    }
}

// ---- the provider functions ----

ffi_callback! {
    /// `core_provider_get0_name`.
    ///
    /// # Safety
    /// `prov` is NULL or a provider's handle.
    pub(crate) unsafe extern "C" fn core_provider_get0_name(prov: *const OSSL_CORE_HANDLE) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { super::OSSL_PROVIDER_get0_name(prov.cast()) }
    }
}

ffi_callback! {
    /// `core_provider_get0_provider_ctx`.
    ///
    /// # Safety
    /// `prov` is NULL or a provider's handle.
    pub(crate) unsafe extern "C" fn core_provider_get0_provider_ctx(prov: *const OSSL_CORE_HANDLE) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { super::OSSL_PROVIDER_get0_provider_ctx(prov.cast()) }
    }
}

ffi_callback! {
    /// `core_provider_get0_dispatch`.
    ///
    /// # Safety
    /// `prov` is NULL or a provider's handle.
    pub(crate) unsafe extern "C" fn core_provider_get0_dispatch(prov: *const OSSL_CORE_HANDLE) -> *const OSSL_DISPATCH
    where failure = ptr::null(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { super::OSSL_PROVIDER_get0_dispatch(prov.cast()) }
    }
}

ffi_callback! {
    /// `core_provider_up_ref_intern`: activates the provider (1, or 0 if that failed), or adds
    /// a reference (the count afterwards, which counts the library's own references too).
    ///
    /// # Safety
    /// `prov` is NULL or a provider's handle.
    pub(crate) unsafe extern "C" fn core_provider_up_ref(prov: *const OSSL_CORE_HANDLE, activate: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { super::up_ref_intern(prov.cast::<OSSL_PROVIDER>().cast_mut(), activate != 0) }
    }
}

ffi_callback! {
    /// `core_provider_free_intern`: deactivates the provider (1, or 0 after more deactivations
    /// than activations), or drops a reference (1).
    ///
    /// # Safety
    /// `prov` is NULL or a provider's handle with the reference given up.
    pub(crate) unsafe extern "C" fn core_provider_free(prov: *const OSSL_CORE_HANDLE, deactivate: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { super::free_intern(prov.cast::<OSSL_PROVIDER>().cast_mut(), deactivate != 0) }
    }
}

/// The type of `provider_register_child_cb`'s create and remove callbacks.
pub(crate) type ChildFn = unsafe extern "C" fn(*const OSSL_CORE_HANDLE, *mut c_void) -> c_int;
/// The type of its global-properties callback.
pub(crate) type PropsFn = unsafe extern "C" fn(*const c_char, *mut c_void) -> c_int;

ffi_callback! {
    /// `ossl_provider_register_child_cb`: the callbacks hear of each provider of the handle's
    /// context activated (now and later) and deactivated, and of the context's global
    /// properties. 1, or 0 (each provider seen given to `remove_cb`) if a creation failed.
    ///
    /// # Safety
    /// `handle` is a provider's handle; the callbacks take `cbdata`.
    pub(crate) unsafe extern "C" fn provider_register_child_cb(handle: *const OSSL_CORE_HANDLE, create_cb: Option<ChildFn>, remove_cb: Option<ChildFn>, global_props_cb: Option<PropsFn>, cbdata: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let (Some(create), Some(remove), Some(props)) = (create_cb, remove_cb, global_props_cb) else {
            return 0;
        };
        // SAFETY: the caller's guarantee.
        unsafe { super::register_child_cb(handle.cast(), create, remove, props, cbdata) }
    }
}

ffi_callback! {
    /// `ossl_provider_deregister_child_cb`: the handle's callbacks are no longer called.
    ///
    /// # Safety
    /// `handle` is a provider's handle.
    pub(crate) unsafe extern "C" fn provider_deregister_child_cb(handle: *const OSSL_CORE_HANDLE)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { super::deregister_child_cb(handle.cast()) };
    }
}

// ---- the table ----

/// A dispatch table's entry for `$f`, whose type is `$t`.
macro_rules! entry {
    ($id:expr, $f:path as $t:ty) => {
        OSSL_DISPATCH {
            function_id: $id,
            // SAFETY: function pointers all have one representation; the provider casts the
            // entry back to the type its id stands for (`OSSL_FUNC_*_fn`), which `$t` is.
            function: Some(unsafe { core::mem::transmute::<$t, unsafe extern "C" fn()>($f) }),
        }
    };
}

type H = *const OSSL_CORE_HANDLE;
type Cb = *mut BIO;

/// The core's dispatch table, in OpenSSL's order, ended by a zero function id.
pub(crate) static DISPATCH: [OSSL_DISPATCH; 54] = {
    use rustyssl_abi::*;
    [
        entry!(
            OSSL_FUNC_CORE_GETTABLE_PARAMS,
            core_gettable_params as unsafe extern "C" fn(H) -> *const OSSL_PARAM
        ),
        entry!(
            OSSL_FUNC_CORE_GET_PARAMS,
            core_get_params as unsafe extern "C" fn(H, *mut OSSL_PARAM) -> c_int
        ),
        entry!(
            OSSL_FUNC_CORE_GET_LIBCTX,
            core_get_libctx as unsafe extern "C" fn(H) -> *mut OPENSSL_CORE_CTX
        ),
        entry!(
            OSSL_FUNC_CORE_THREAD_START,
            core_thread_start
                as unsafe extern "C" fn(H, OSSL_thread_stop_handler_fn, *mut c_void) -> c_int
        ),
        entry!(
            OSSL_FUNC_CORE_NEW_ERROR,
            core_new_error as unsafe extern "C" fn(H)
        ),
        entry!(
            OSSL_FUNC_CORE_SET_ERROR_DEBUG,
            core_set_error_debug as unsafe extern "C" fn(H, *const c_char, c_int, *const c_char)
        ),
        entry!(
            OSSL_FUNC_CORE_VSET_ERROR,
            core_vset_error as unsafe extern "C" fn(H, u32, *const c_char, VaList<'_>)
        ),
        entry!(
            OSSL_FUNC_CORE_SET_ERROR_MARK,
            core_set_error_mark as unsafe extern "C" fn(H) -> c_int
        ),
        entry!(
            OSSL_FUNC_CORE_CLEAR_LAST_ERROR_MARK,
            core_clear_last_error_mark as unsafe extern "C" fn(H) -> c_int
        ),
        entry!(
            OSSL_FUNC_CORE_POP_ERROR_TO_MARK,
            core_pop_error_to_mark as unsafe extern "C" fn(H) -> c_int
        ),
        entry!(
            OSSL_FUNC_CORE_COUNT_TO_MARK,
            core_count_to_mark as unsafe extern "C" fn(H) -> c_int
        ),
        entry!(
            OSSL_FUNC_BIO_NEW_FILE,
            crate::bio::file::BIO_new_file
                as unsafe extern "C" fn(*const c_char, *const c_char) -> Cb
        ),
        entry!(
            OSSL_FUNC_BIO_NEW_MEMBUF,
            crate::bio::mem::BIO_new_mem_buf as unsafe extern "C" fn(*const c_void, c_int) -> Cb
        ),
        entry!(
            OSSL_FUNC_BIO_READ_EX,
            crate::bio::BIO_read_ex
                as unsafe extern "C" fn(Cb, *mut c_void, usize, *mut usize) -> c_int
        ),
        entry!(
            OSSL_FUNC_BIO_WRITE_EX,
            crate::bio::BIO_write_ex
                as unsafe extern "C" fn(Cb, *const c_void, usize, *mut usize) -> c_int
        ),
        entry!(
            OSSL_FUNC_BIO_GETS,
            crate::bio::BIO_gets as unsafe extern "C" fn(Cb, *mut c_char, c_int) -> c_int
        ),
        entry!(
            OSSL_FUNC_BIO_PUTS,
            crate::bio::BIO_puts as unsafe extern "C" fn(Cb, *const c_char) -> c_int
        ),
        // As OpenSSL's: the provider's type has an `int` result.
        entry!(
            OSSL_FUNC_BIO_CTRL,
            crate::bio::BIO_ctrl as unsafe extern "C" fn(Cb, c_int, c_long, *mut c_void) -> c_long
        ),
        entry!(
            OSSL_FUNC_BIO_UP_REF,
            crate::bio::BIO_up_ref as unsafe extern "C" fn(Cb) -> c_int
        ),
        entry!(
            OSSL_FUNC_BIO_FREE,
            crate::bio::BIO_free as unsafe extern "C" fn(Cb) -> c_int
        ),
        entry!(
            OSSL_FUNC_BIO_VPRINTF,
            crate::bio::print::BIO_vprintf
                as unsafe extern "C" fn(Cb, *const c_char, VaList<'_>) -> c_int
        ),
        entry!(
            OSSL_FUNC_BIO_VSNPRINTF,
            crate::bio::print::BIO_vsnprintf
                as unsafe extern "C" fn(*mut c_char, usize, *const c_char, VaList<'_>) -> c_int
        ),
        entry!(
            OSSL_FUNC_SELF_TEST_CB,
            crate::libctx::OSSL_SELF_TEST_get_callback
                as unsafe extern "C" fn(*mut OSSL_LIB_CTX, *mut OSSL_CALLBACK, *mut *mut c_void)
        ),
        entry!(
            OSSL_FUNC_INDICATOR_CB,
            crate::libctx::OSSL_INDICATOR_get_callback
                as unsafe extern "C" fn(*mut OSSL_LIB_CTX, *mut OSSL_INDICATOR_CALLBACK)
        ),
        entry!(
            OSSL_FUNC_GET_ENTROPY,
            rand_get_entropy as unsafe extern "C" fn(H, *mut *mut u8, c_int, usize, usize) -> usize
        ),
        entry!(
            OSSL_FUNC_GET_USER_ENTROPY,
            rand_get_user_entropy
                as unsafe extern "C" fn(H, *mut *mut u8, c_int, usize, usize) -> usize
        ),
        entry!(
            OSSL_FUNC_CLEANUP_ENTROPY,
            rand_cleanup_entropy as unsafe extern "C" fn(H, *mut u8, usize)
        ),
        entry!(
            OSSL_FUNC_CLEANUP_USER_ENTROPY,
            rand_cleanup_user_entropy as unsafe extern "C" fn(H, *mut u8, usize)
        ),
        entry!(
            OSSL_FUNC_GET_NONCE,
            rand_get_nonce
                as unsafe extern "C" fn(
                    H,
                    *mut *mut u8,
                    usize,
                    usize,
                    *const c_void,
                    usize,
                ) -> usize
        ),
        entry!(
            OSSL_FUNC_GET_USER_NONCE,
            rand_get_user_nonce
                as unsafe extern "C" fn(
                    H,
                    *mut *mut u8,
                    usize,
                    usize,
                    *const c_void,
                    usize,
                ) -> usize
        ),
        entry!(
            OSSL_FUNC_CLEANUP_NONCE,
            rand_cleanup_nonce as unsafe extern "C" fn(H, *mut u8, usize)
        ),
        entry!(
            OSSL_FUNC_CLEANUP_USER_NONCE,
            rand_cleanup_nonce as unsafe extern "C" fn(H, *mut u8, usize)
        ),
        entry!(
            OSSL_FUNC_CRYPTO_MALLOC,
            crate::mem::CRYPTO_malloc
                as unsafe extern "C" fn(usize, *const c_char, c_int) -> *mut c_void
        ),
        entry!(
            OSSL_FUNC_CRYPTO_ZALLOC,
            crate::mem::CRYPTO_zalloc
                as unsafe extern "C" fn(usize, *const c_char, c_int) -> *mut c_void
        ),
        entry!(
            OSSL_FUNC_CRYPTO_FREE,
            crate::mem::CRYPTO_free as unsafe extern "C" fn(*mut c_void, *const c_char, c_int)
        ),
        entry!(
            OSSL_FUNC_CRYPTO_CLEAR_FREE,
            crate::mem::CRYPTO_clear_free
                as unsafe extern "C" fn(*mut c_void, usize, *const c_char, c_int)
        ),
        entry!(
            OSSL_FUNC_CRYPTO_REALLOC,
            crate::mem::CRYPTO_realloc
                as unsafe extern "C" fn(*mut c_void, usize, *const c_char, c_int) -> *mut c_void
        ),
        entry!(
            OSSL_FUNC_CRYPTO_CLEAR_REALLOC,
            crate::mem::CRYPTO_clear_realloc
                as unsafe extern "C" fn(
                    *mut c_void,
                    usize,
                    usize,
                    *const c_char,
                    c_int,
                ) -> *mut c_void
        ),
        entry!(
            OSSL_FUNC_CRYPTO_SECURE_MALLOC,
            crate::secure::CRYPTO_secure_malloc
                as unsafe extern "C" fn(usize, *const c_char, c_int) -> *mut c_void
        ),
        entry!(
            OSSL_FUNC_CRYPTO_SECURE_ZALLOC,
            crate::secure::CRYPTO_secure_zalloc
                as unsafe extern "C" fn(usize, *const c_char, c_int) -> *mut c_void
        ),
        entry!(
            OSSL_FUNC_CRYPTO_SECURE_FREE,
            crate::secure::CRYPTO_secure_free
                as unsafe extern "C" fn(*mut c_void, *const c_char, c_int)
        ),
        entry!(
            OSSL_FUNC_CRYPTO_SECURE_CLEAR_FREE,
            crate::secure::CRYPTO_secure_clear_free
                as unsafe extern "C" fn(*mut c_void, usize, *const c_char, c_int)
        ),
        entry!(
            OSSL_FUNC_CRYPTO_SECURE_ALLOCATED,
            crate::secure::CRYPTO_secure_allocated as unsafe extern "C" fn(*const c_void) -> c_int
        ),
        entry!(
            OSSL_FUNC_OPENSSL_CLEANSE,
            crate::mem::OPENSSL_cleanse as unsafe extern "C" fn(*mut c_void, usize)
        ),
        entry!(
            OSSL_FUNC_PROVIDER_REGISTER_CHILD_CB,
            provider_register_child_cb
                as unsafe extern "C" fn(
                    H,
                    Option<ChildFn>,
                    Option<ChildFn>,
                    Option<PropsFn>,
                    *mut c_void,
                ) -> c_int
        ),
        entry!(
            OSSL_FUNC_PROVIDER_DEREGISTER_CHILD_CB,
            provider_deregister_child_cb as unsafe extern "C" fn(H)
        ),
        entry!(
            OSSL_FUNC_PROVIDER_NAME,
            core_provider_get0_name as unsafe extern "C" fn(H) -> *const c_char
        ),
        entry!(
            OSSL_FUNC_PROVIDER_GET0_PROVIDER_CTX,
            core_provider_get0_provider_ctx as unsafe extern "C" fn(H) -> *mut c_void
        ),
        entry!(
            OSSL_FUNC_PROVIDER_GET0_DISPATCH,
            core_provider_get0_dispatch as unsafe extern "C" fn(H) -> *const OSSL_DISPATCH
        ),
        entry!(
            OSSL_FUNC_PROVIDER_UP_REF,
            core_provider_up_ref as unsafe extern "C" fn(H, c_int) -> c_int
        ),
        entry!(
            OSSL_FUNC_PROVIDER_FREE,
            core_provider_free as unsafe extern "C" fn(H, c_int) -> c_int
        ),
        entry!(
            OSSL_FUNC_CORE_OBJ_ADD_SIGID,
            core_obj_add_sigid
                as unsafe extern "C" fn(H, *const c_char, *const c_char, *const c_char) -> c_int
        ),
        entry!(
            OSSL_FUNC_CORE_OBJ_CREATE,
            core_obj_create
                as unsafe extern "C" fn(H, *const c_char, *const c_char, *const c_char) -> c_int
        ),
        OSSL_DISPATCH {
            function_id: 0,
            function: None,
        },
    ]
};

/// The functions a context made with `OSSL_LIB_CTX_new_from_dispatch` reaches the parent's BIOs
/// with (`ossl_bio_init_core`), from the table it was given.
#[derive(Clone, Copy, Default)]
pub(crate) struct CoreBio {
    pub(crate) read_ex:
        Option<unsafe extern "C" fn(*mut c_void, *mut c_void, usize, *mut usize) -> c_int>,
    pub(crate) write_ex:
        Option<unsafe extern "C" fn(*mut c_void, *const c_void, usize, *mut usize) -> c_int>,
    pub(crate) gets: Option<unsafe extern "C" fn(*mut c_void, *mut c_char, c_int) -> c_int>,
    pub(crate) puts: Option<unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int>,
    pub(crate) ctrl: Option<unsafe extern "C" fn(*mut c_void, c_int, c_long, *mut c_void) -> c_int>,
    pub(crate) up_ref: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    pub(crate) free: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
}

impl CoreBio {
    /// The BIO functions of a core dispatch table (read up to a limit), as `ossl_bio_init_core`
    /// keeps them: whatever is there (a BIO over them fails where one is missing).
    ///
    /// # Safety
    /// `table` is NULL or a dispatch table ended by a zero function id whose functions have the
    /// types their ids stand for.
    pub(crate) unsafe fn from_dispatch(table: *const OSSL_DISPATCH) -> Self {
        use rustyssl_abi::{
            OSSL_FUNC_BIO_CTRL, OSSL_FUNC_BIO_FREE, OSSL_FUNC_BIO_GETS, OSSL_FUNC_BIO_PUTS,
            OSSL_FUNC_BIO_READ_EX, OSSL_FUNC_BIO_UP_REF, OSSL_FUNC_BIO_WRITE_EX,
        };
        let mut b = Self::default();
        let mut at = table;
        for _ in 0..super::TABLE_LIMIT {
            // SAFETY: the caller's guarantee.
            let Some(d) = (unsafe { at.as_ref() }) else {
                break;
            };
            if d.function_id == 0 {
                break;
            }
            if let Some(f) = d.function {
                match d.function_id {
                    // SAFETY: the caller's guarantee of the function's type, here and below.
                    OSSL_FUNC_BIO_READ_EX => b.read_ex = Some(unsafe { super::cast(f) }),
                    // SAFETY: as above.
                    OSSL_FUNC_BIO_WRITE_EX => b.write_ex = Some(unsafe { super::cast(f) }),
                    // SAFETY: as above.
                    OSSL_FUNC_BIO_GETS => b.gets = Some(unsafe { super::cast(f) }),
                    // SAFETY: as above.
                    OSSL_FUNC_BIO_PUTS => b.puts = Some(unsafe { super::cast(f) }),
                    // SAFETY: as above.
                    OSSL_FUNC_BIO_CTRL => b.ctrl = Some(unsafe { super::cast(f) }),
                    // SAFETY: as above.
                    OSSL_FUNC_BIO_UP_REF => b.up_ref = Some(unsafe { super::cast(f) }),
                    // SAFETY: as above.
                    OSSL_FUNC_BIO_FREE => b.free = Some(unsafe { super::cast(f) }),
                    _ => {}
                }
            }
            at = at.wrapping_add(1);
        }
        b
    }
}
