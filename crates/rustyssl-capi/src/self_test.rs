//! Self-test reporting (`OSSL_SELF_TEST_*`, `crypto/self_test_core.c`): the object a provider's
//! self tests report their phases through, to an application's `OSSL_CALLBACK` with the phase,
//! type, and description as parameters. Only a FIPS provider runs self tests (there is none),
//! but providers and applications may use the object; the per-library-context callback is in
//! [`crate::libctx`] (`OSSL_SELF_TEST_set_callback`).

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_CRYPTO, OSSL_CALLBACK, OSSL_PARAM, OSSL_PROV_PARAM_SELF_TEST_DESC,
    OSSL_PROV_PARAM_SELF_TEST_PHASE, OSSL_PROV_PARAM_SELF_TEST_TYPE, OSSL_SELF_TEST,
    OSSL_SELF_TEST_DESC_NONE, OSSL_SELF_TEST_PHASE_CORRUPT, OSSL_SELF_TEST_PHASE_FAIL,
    OSSL_SELF_TEST_PHASE_NONE, OSSL_SELF_TEST_PHASE_PASS, OSSL_SELF_TEST_PHASE_START,
    OSSL_SELF_TEST_TYPE_NONE,
};

use crate::ffi::ffi_export;
use crate::params::{self, OSSL_PARAM_construct_utf8_string};

/// `struct ossl_self_test_st`: the state and the parameters handed to the callback (at a
/// stable address: the object is boxed).
struct SelfTest {
    phase: *const c_char,
    type_: *const c_char,
    desc: *const c_char,
    cb: OSSL_CALLBACK,
    params: [OSSL_PARAM; 4],
    cb_arg: *mut c_void,
}

/// The object behind a handle.
///
/// # Safety
/// `st` is NULL or a live object, not otherwise borrowed.
unsafe fn object<'a>(st: *mut OSSL_SELF_TEST) -> Option<&'a mut SelfTest> {
    // SAFETY: the caller's guarantee.
    unsafe { st.cast::<SelfTest>().as_mut() }
}

/// `self_test_setparams`: the phase, type, and description as parameters (only the end without
/// a callback).
fn set_params(st: &mut SelfTest) {
    let end = params::end();
    st.params = [end, end, end, end];
    if st.cb.is_none() {
        return;
    }
    let entries = [
        (OSSL_PROV_PARAM_SELF_TEST_PHASE, st.phase),
        (OSSL_PROV_PARAM_SELF_TEST_TYPE, st.type_),
        (OSSL_PROV_PARAM_SELF_TEST_DESC, st.desc),
    ];
    for (slot, (key, value)) in st.params.iter_mut().zip(entries) {
        // SAFETY: a static key; a string, NULL, or the caller's (its length measured here, as
        // OpenSSL's does).
        *slot = unsafe { OSSL_PARAM_construct_utf8_string(key.as_ptr(), value.cast_mut(), 0) };
    }
}

/// Calls the object's callback with its parameters: its result (1 without a callback).
///
/// # Safety
/// `st` is a live object; the callback is the application's, called with no lock held.
unsafe fn report(st: *mut OSSL_SELF_TEST) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(s) = (unsafe { object(st) }) else {
        return 1;
    };
    let (cb, params, arg) = (s.cb, s.params.as_ptr(), s.cb_arg);
    match cb {
        // SAFETY: the application's callback with the object's parameters, which stay put.
        Some(f) => unsafe { f(params, arg) },
        None => 1,
    }
}

ffi_export! {
    /// A new reporting object for `cb` (NULL: report nothing) and `cbarg`, or NULL.
    ///
    /// # Safety
    /// `cb` is NULL or a callback; `cbarg` anything it accepts.
    pub unsafe extern "C" fn OSSL_SELF_TEST_new(cb: OSSL_CALLBACK, cbarg: *mut c_void) -> *mut OSSL_SELF_TEST
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        let end = params::end();
        let mut st = Box::new(SelfTest {
            phase: c"".as_ptr(),
            type_: c"".as_ptr(),
            desc: c"".as_ptr(),
            cb,
            params: [end, end, end, end],
            cb_arg: cbarg,
        });
        set_params(&mut st);
        Box::into_raw(st).cast()
    }
}

ffi_export! {
    /// Frees the object (nothing for NULL).
    ///
    /// # Safety
    /// `st` is NULL or a live object, not used after.
    pub unsafe extern "C" fn OSSL_SELF_TEST_free(st: *mut OSSL_SELF_TEST)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        if !st.is_null() {
            // SAFETY: the box made by OSSL_SELF_TEST_new.
            drop(unsafe { Box::from_raw(st.cast::<SelfTest>()) });
        }
    }
}

ffi_export! {
    /// Reports the start of a test of `type_` and `desc` (kept by reference, as in OpenSSL).
    ///
    /// # Safety
    /// `st` is NULL or a live object; `type_` and `desc` strings outliving the test.
    pub unsafe extern "C" fn OSSL_SELF_TEST_onbegin(st: *mut OSSL_SELF_TEST, type_: *const c_char, desc: *const c_char)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { object(st) }) else { return };
        if s.cb.is_none() {
            return;
        }
        s.phase = OSSL_SELF_TEST_PHASE_START.as_ptr();
        s.type_ = type_;
        s.desc = desc;
        set_params(s);
        // SAFETY: as above.
        unsafe { report(st) };
    }
}

ffi_export! {
    /// Reports the end of the test (passed if `ret` is 1, else failed), then resets the state
    /// to none (without reporting it).
    ///
    /// # Safety
    /// `st` is NULL or a live object.
    pub unsafe extern "C" fn OSSL_SELF_TEST_onend(st: *mut OSSL_SELF_TEST, ret: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { object(st) }) else { return };
        if s.cb.is_none() {
            return;
        }
        s.phase = if ret == 1 { OSSL_SELF_TEST_PHASE_PASS } else { OSSL_SELF_TEST_PHASE_FAIL }.as_ptr();
        set_params(s);
        // SAFETY: as above.
        unsafe { report(st) };
        // SAFETY: as above (the callback may have used the object).
        let Some(s) = (unsafe { object(st) }) else { return };
        s.phase = OSSL_SELF_TEST_PHASE_NONE.as_ptr();
        s.type_ = OSSL_SELF_TEST_TYPE_NONE.as_ptr();
        s.desc = OSSL_SELF_TEST_DESC_NONE.as_ptr();
    }
}

ffi_export! {
    /// Reports the corruption phase; if the callback returns 0, flips the low bit of
    /// `bytes[0]` (to fail the test on purpose) and returns 1. 0 otherwise.
    ///
    /// # Safety
    /// `st` is NULL or a live object; `bytes` holds at least one octet when there's a
    /// callback (as in OpenSSL; NULL is skipped here).
    pub unsafe extern "C" fn OSSL_SELF_TEST_oncorrupt_byte(st: *mut OSSL_SELF_TEST, bytes: *mut c_uchar) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { object(st) }) else { return 0 };
        if s.cb.is_none() {
            return 0;
        }
        s.phase = OSSL_SELF_TEST_PHASE_CORRUPT.as_ptr();
        set_params(s);
        // SAFETY: as above.
        if unsafe { report(st) } != 0 {
            return 0;
        }
        if !bytes.is_null() {
            // SAFETY: the caller's first octet.
            unsafe { *bytes ^= 1 };
        }
        1
    }
}
