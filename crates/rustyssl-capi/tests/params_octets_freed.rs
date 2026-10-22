//! `EVP_PKEY_CTX_set_params` on a context with an application's key method copies an
//! octet-string parameter for the method's ctrl. The reference never frees that copy (a leak
//! the `meth` fuzz target's LeakSanitizer found); rustyssl frees it unless a "set0" command (a
//! KDF UKM, the OAEP label) succeeded and so handed it to the method. This counts the blocks
//! the library's allocator holds around each call: a round of setting and freeing must leave
//! none behind, and the method must never be handed a block the library then frees.
//! Its own process, because the allocator is process-wide and replaceable only before the
//! first allocation.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;
use std::collections::HashSet;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    EVP_PKEY_CTRL_DH_KDF_UKM, EVP_PKEY_CTRL_EC_KDF_UKM, EVP_PKEY_CTRL_RSA_OAEP_LABEL, EVP_PKEY_EC,
    EVP_PKEY_RSA, OSSL_PARAM,
};
use rustyssl_capi as _;

type Ctx = c_void;
type CtrlFn = unsafe extern "C" fn(*mut Ctx, c_int, c_int, *mut c_void) -> c_int;
type InitFn = unsafe extern "C" fn(*mut Ctx) -> c_int;
type CleanupFn = unsafe extern "C" fn(*mut Ctx);
type DeriveFn = unsafe extern "C" fn(*mut Ctx, *mut u8, *mut usize) -> c_int;
type CryptFn = unsafe extern "C" fn(*mut Ctx, *mut u8, *mut usize, *const u8, usize) -> c_int;

unsafe extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn realloc(p: *mut c_void, size: usize) -> *mut c_void;
    fn free(p: *mut c_void);
    fn CRYPTO_set_mem_functions(
        malloc: Option<unsafe extern "C" fn(usize, *const c_char, c_int) -> *mut c_void>,
        realloc: Option<
            unsafe extern "C" fn(*mut c_void, usize, *const c_char, c_int) -> *mut c_void,
        >,
        free: Option<unsafe extern "C" fn(*mut c_void, *const c_char, c_int)>,
    ) -> c_int;
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
    fn EVP_PKEY_meth_new(id: c_int, flags: c_int) -> *mut c_void;
    fn EVP_PKEY_meth_set_ctrl(m: *mut c_void, c: Option<CtrlFn>, s: Option<unsafe extern "C" fn()>);
    fn EVP_PKEY_meth_set_cleanup(m: *mut c_void, c: Option<CleanupFn>);
    fn EVP_PKEY_meth_set_derive(m: *mut c_void, i: Option<InitFn>, d: Option<DeriveFn>);
    fn EVP_PKEY_meth_set_encrypt(m: *mut c_void, i: Option<InitFn>, e: Option<CryptFn>);
    fn EVP_PKEY_meth_add0(m: *const c_void) -> c_int;
    fn EVP_PKEY_CTX_new_id(id: c_int, e: *mut c_void) -> *mut Ctx;
    fn EVP_PKEY_CTX_free(c: *mut Ctx);
    fn EVP_PKEY_derive_init(c: *mut Ctx) -> c_int;
    fn EVP_PKEY_encrypt_init(c: *mut Ctx) -> c_int;
    fn EVP_PKEY_CTX_set_params(c: *mut Ctx, params: *const OSSL_PARAM) -> c_int;
    fn OSSL_PARAM_construct_octet_string(
        key: *const c_char,
        buf: *mut c_void,
        len: usize,
    ) -> OSSL_PARAM;
    fn OSSL_PARAM_construct_end() -> OSSL_PARAM;
}

/// The value behind a lock (a panic elsewhere fails the test anyway).
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The blocks the library's allocator holds.
static LIVE: Mutex<Option<HashSet<usize>>> = Mutex::new(None);

fn live() -> HashSet<usize> {
    lock(&LIVE).clone().unwrap_or_default()
}

fn track(add: *mut c_void, remove: *mut c_void) {
    let mut live = lock(&LIVE);
    let set = live.get_or_insert_with(HashSet::new);
    if !remove.is_null() {
        set.remove(&(remove as usize));
    }
    if !add.is_null() {
        set.insert(add as usize);
    }
}

unsafe extern "C" fn counting_malloc(n: usize, _: *const c_char, _: c_int) -> *mut c_void {
    // SAFETY: the system allocator.
    let p = unsafe { malloc(n) };
    track(p, ptr::null_mut());
    p
}

unsafe extern "C" fn counting_realloc(
    p: *mut c_void,
    n: usize,
    _: *const c_char,
    _: c_int,
) -> *mut c_void {
    // SAFETY: a block from the system allocator, or NULL.
    let q = unsafe { realloc(p, n) };
    if !q.is_null() || n == 0 {
        track(q, p);
    }
    q
}

unsafe extern "C" fn counting_free(p: *mut c_void, _: *const c_char, _: c_int) {
    // A block the library frees must not be one its method still holds.
    assert!(p.is_null() || lock(&KEPT).is_none_or(|k| k != p as usize));
    track(ptr::null_mut(), p);
    // SAFETY: a block from the system allocator, or NULL.
    unsafe { free(p) };
}

/// What the method's ctrl answers, and the octets a set0 command handed it.
static ANSWER: Mutex<c_int> = Mutex::new(1);
static KEPT: Mutex<Option<usize>> = Mutex::new(None);

fn release_kept() {
    let kept = lock(&KEPT).take();
    if let Some(p) = kept {
        // SAFETY: the octets a set0 command handed over, from the library's allocator.
        unsafe { CRYPTO_free(p as *mut c_void, c"params_octets_freed.rs".as_ptr(), 0) };
    }
}

unsafe extern "C" fn ctrl(_: *mut Ctx, cmd: c_int, _: c_int, p2: *mut c_void) -> c_int {
    let answer = *lock(&ANSWER);
    let set0 = matches!(
        cmd,
        EVP_PKEY_CTRL_DH_KDF_UKM | EVP_PKEY_CTRL_EC_KDF_UKM | EVP_PKEY_CTRL_RSA_OAEP_LABEL
    );
    if answer > 0 && set0 {
        release_kept();
        if !p2.is_null() {
            *lock(&KEPT) = Some(p2 as usize);
        }
    }
    answer
}

unsafe extern "C" fn cleanup(_: *mut Ctx) {
    release_kept();
}

unsafe extern "C" fn init(_: *mut Ctx) -> c_int {
    1
}

unsafe extern "C" fn derive(_: *mut Ctx, _: *mut u8, _: *mut usize) -> c_int {
    0
}

unsafe extern "C" fn encrypt(
    _: *mut Ctx,
    _: *mut u8,
    _: *mut usize,
    _: *const u8,
    _: usize,
) -> c_int {
    0
}

/// Sets each parameter with the method answering 1 and 0, on a fresh context for `id` started
/// by `start`; returns `set_params`'s answers.
fn round(
    id: c_int,
    start: unsafe extern "C" fn(*mut Ctx) -> c_int,
    keys: &[(&CStr, usize)],
) -> Vec<c_int> {
    let mut octets = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let mut answers = Vec::new();
    // SAFETY: a key type with a method added.
    let c = unsafe { EVP_PKEY_CTX_new_id(id, ptr::null_mut()) };
    assert!(!c.is_null());
    // SAFETY: the context.
    assert_eq!(unsafe { start(c) }, 1);
    for &(key, len) in keys {
        for answer in [1, 0] {
            *lock(&ANSWER) = answer;
            let before = live();
            let data = octets.as_mut_ptr().cast();
            // SAFETY: a static key; the octets outlive the call.
            let param = unsafe { OSSL_PARAM_construct_octet_string(key.as_ptr(), data, len) };
            // SAFETY: no preconditions.
            let params = [param, unsafe { OSSL_PARAM_construct_end() }];
            // SAFETY: the context; the array.
            answers.push(unsafe { EVP_PKEY_CTX_set_params(c, params.as_ptr()) });
            // Nothing new is left but what the method keeps.
            let kept = *lock(&KEPT);
            let grown: Vec<_> = live().difference(&before).copied().collect();
            assert!(
                grown.iter().all(|p| Some(*p) == kept),
                "{key:?} of {len} octets, the method answering {answer}: {} block(s) left",
                grown.len()
            );
        }
    }
    // SAFETY: the context, freed once.
    unsafe { EVP_PKEY_CTX_free(c) };
    assert!(lock(&KEPT).is_none());
    answers
}

#[test]
fn octets_set_through_a_method_are_freed_unless_handed_over() {
    // SAFETY: allocation functions that behave like malloc, realloc and free, installed before
    // anything allocates.
    let installed = unsafe {
        CRYPTO_set_mem_functions(
            Some(counting_malloc),
            Some(counting_realloc),
            Some(counting_free),
        )
    };
    assert_eq!(installed, 1);
    for id in [EVP_PKEY_EC, EVP_PKEY_RSA] {
        // SAFETY: no preconditions.
        let m = unsafe { EVP_PKEY_meth_new(id, 0) };
        assert!(!m.is_null());
        // SAFETY: the method above and its functions, here and below; added once and kept to
        // the end.
        unsafe { EVP_PKEY_meth_set_ctrl(m, Some(ctrl), None) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_meth_set_cleanup(m, Some(cleanup)) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_meth_set_derive(m, Some(init), Some(derive)) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_meth_set_encrypt(m, Some(init), Some(encrypt)) };
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_meth_add0(m) }, 1);
    }
    let derive_keys: &[(&CStr, usize)] = &[
        (c"kdf-ukm", 8),
        (c"kdf-ukm", 0),
        (c"salt", 3),
        (c"key", 3),
        (c"info", 3),
        (c"secret", 3),
        (c"seed", 3),
        (c"pass", 3),
    ];
    let label: &[(&CStr, usize)] = &[(c"oaep-label", 5), (c"oaep-label", 0)];
    // A first round warms the library's lazily made tables; a second must leave nothing.
    for warm in [true, false] {
        let before = live();
        let answers = round(EVP_PKEY_EC, EVP_PKEY_derive_init, derive_keys);
        assert_eq!(answers, [1, 0].repeat(derive_keys.len()));
        let answers = round(EVP_PKEY_RSA, EVP_PKEY_encrypt_init, label);
        assert_eq!(answers, [1, 0].repeat(label.len()));
        let after = live();
        if !warm {
            let left: Vec<_> = after.difference(&before).collect();
            assert!(
                left.is_empty(),
                "{} block(s) left after a round",
                left.len()
            );
        }
    }
}
