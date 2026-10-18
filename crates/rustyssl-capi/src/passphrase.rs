//! Passphrases for decoding and encoding (`crypto/passphrase.c`): where an operation gets one
//! — a copy of an explicit passphrase, an `OSSL_PASSPHRASE_CALLBACK`, a `pem_password_cb`, or a
//! `UI_METHOD` — and the cache that keeps the first one an operation got for the rest of it.
//!
//! As in OpenSSL, an explicit passphrase (or a cached one) is copied cut to the room given; a
//! callback's answer is cached while caching is on; and the passphrase is wiped when replaced,
//! cleared, or dropped. A `pem_password_cb` or a `UI_METHOD` is asked through the UI layer,
//! which comes with step 4.7d: until then asking one aborts.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT, ERR_R_PASSED_NULL_PARAMETER, OSSL_PARAM,
    OSSL_PARAM_UTF8_STRING, OSSL_PASSPHRASE_CALLBACK, OSSL_PASSPHRASE_PARAM_INFO, UI_METHOD,
    pem_password_cb,
};
use rustyssl_crypto::bn::Zeroizing;

use crate::err;

/// Where the passphrase comes from (`ossl_passphrase_data_st`'s type and union).
#[derive(Default)]
enum Source {
    #[default]
    None,
    /// `is_expl_passphrase`: a copy.
    Explicit(Zeroizing<Vec<u8>>),
    /// `is_pem_password`.
    Pem(
        unsafe extern "C" fn(*mut c_char, c_int, c_int, *mut c_void) -> c_int,
        *mut c_void,
    ),
    /// `is_ossl_passphrase`.
    Ossl(
        unsafe extern "C" fn(
            *mut c_char,
            usize,
            *mut usize,
            *const OSSL_PARAM,
            *mut c_void,
        ) -> c_int,
        *mut c_void,
    ),
    /// `is_ui_method`.
    Ui(*const UI_METHOD, *mut c_void),
}

/// `struct ossl_passphrase_data_st`.
#[derive(Default)]
pub(crate) struct PwData {
    source: Source,
    cache_on: bool,
    cached: Option<Zeroizing<Vec<u8>>>,
}

// SAFETY: the callbacks and their arguments are the application's, which OpenSSL leaves to it
// to make safe across threads; the rest is owned.
unsafe impl Send for PwData {}

impl PwData {
    /// `ossl_pw_clear_passphrase_data`: no source, no cache, caching off.
    pub(crate) fn clear(&mut self) {
        *self = Self::default();
    }

    /// `ossl_pw_clear_passphrase_cache`.
    pub(crate) fn clear_cache(&mut self) {
        self.cached = None;
    }

    /// `ossl_pw_set_passphrase`: a copy of the passphrase.
    pub(crate) fn set_passphrase(&mut self, pass: &[u8]) {
        self.clear();
        self.source = Source::Explicit(Zeroizing::new(pass.to_vec()));
    }

    /// `ossl_pw_set_pem_password_cb`; false (with an error) for no callback.
    pub(crate) fn set_pem_password_cb(&mut self, cb: pem_password_cb, arg: *mut c_void) -> bool {
        let Some(cb) = cb else {
            err::raise(
                ERR_LIB_CRYPTO,
                ERR_R_PASSED_NULL_PARAMETER,
                "ossl_pw_set_pem_password_cb",
            );
            return false;
        };
        self.clear();
        self.source = Source::Pem(cb, arg);
        true
    }

    /// `ossl_pw_set_ossl_passphrase_cb`; false (with an error) for no callback.
    pub(crate) fn set_ossl_passphrase_cb(
        &mut self,
        cb: OSSL_PASSPHRASE_CALLBACK,
        arg: *mut c_void,
    ) -> bool {
        let Some(cb) = cb else {
            err::raise(
                ERR_LIB_CRYPTO,
                ERR_R_PASSED_NULL_PARAMETER,
                "ossl_pw_set_ossl_passphrase_cb",
            );
            return false;
        };
        self.clear();
        self.source = Source::Ossl(cb, arg);
        true
    }

    /// `ossl_pw_set_ui_method`; false (with an error) for no method.
    pub(crate) fn set_ui_method(
        &mut self,
        ui_method: *const UI_METHOD,
        ui_data: *mut c_void,
    ) -> bool {
        if ui_method.is_null() {
            err::raise(
                ERR_LIB_CRYPTO,
                ERR_R_PASSED_NULL_PARAMETER,
                "ossl_pw_set_ui_method",
            );
            return false;
        }
        self.clear();
        self.source = Source::Ui(ui_method, ui_data);
        true
    }

    /// The `UI_METHOD` and its data, if that is the source (NULLs otherwise), as a registered
    /// store loader gets them.
    pub(crate) fn ui_method(&self) -> (*const UI_METHOD, *mut c_void) {
        match self.source {
            Source::Ui(m, d) => (m, d),
            _ => (ptr::null(), ptr::null_mut()),
        }
    }

    /// `ossl_pw_enable_passphrase_caching`.
    pub(crate) fn enable_caching(&mut self) {
        self.cache_on = true;
    }

    /// `ossl_pw_get_passphrase`: the passphrase into `pass` (`pass_size` octets of room), its
    /// length into `*pass_len`. True, or false (with an error, unless the source said no).
    ///
    /// # Safety
    /// `pass` has room for `pass_size` octets; `pass_len` is writable; `params` is NULL or an
    /// array. A callback may be the application's, called with no lock held by this.
    pub(crate) unsafe fn get(
        this: *mut Self,
        pass: *mut c_char,
        pass_size: usize,
        pass_len: *mut usize,
        params: *const OSSL_PARAM,
        verify: bool,
    ) -> bool {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { this.as_mut() }) else {
            return false;
        };
        let source = match &d.source {
            Source::Explicit(p) => Some(p.as_slice()),
            _ if d.cache_on => d.cached.as_deref().map(Vec::as_slice),
            _ => None,
        };
        if let Some(src) = source {
            let n = src.len().min(pass_size);
            if let Some(from) = src.get(..n) {
                // SAFETY: the caller's room for `pass_size` octets.
                unsafe { ptr::copy_nonoverlapping(from.as_ptr(), pass.cast::<u8>(), n) };
            }
            // SAFETY: the caller's guarantee.
            unsafe { pass_len.write(n) };
            return true;
        }
        let ok = match d.source {
            Source::Ossl(cb, arg) => {
                // The application's callback, which may use this data's owner; nothing is borrowed.
                // SAFETY: the caller's guarantee for the room and length; the callback's own
                // contract.
                (unsafe { cb(pass, pass_size, pass_len, params, arg) }) != 0
            }
            _ => {
                // SAFETY: the caller's array, or NULL.
                let p = unsafe {
                    crate::params::OSSL_PARAM_locate_const(
                        params,
                        OSSL_PASSPHRASE_PARAM_INFO.as_ptr(),
                    )
                };
                // SAFETY: a parameter of the array, or NULL.
                let p = unsafe { p.as_ref() };
                if let Some(p) = p
                    && p.data_type != OSSL_PARAM_UTF8_STRING.cast_unsigned()
                {
                    err::raise_with_text(
                        ERR_LIB_CRYPTO,
                        ERR_R_PASSED_INVALID_ARGUMENT,
                        "ossl_pw_get_passphrase",
                        "Prompt info data type incorrect",
                    );
                    return false;
                }
                let prompt_info: *const c_char =
                    p.map_or(ptr::null(), |p| p.data.cast_const().cast());
                // SAFETY: the caller's guarantee (re-borrowed after the parameter check).
                let Some(d) = (unsafe { this.as_mut() }) else {
                    return false;
                };
                match d.source {
                    Source::Pem(cb, arg) => {
                        // The callback asked through a UI wrapper of it.
                        // SAFETY: the application's callback.
                        let m = unsafe {
                            crate::ui::UI_UTIL_wrap_read_pem_callback(Some(cb), c_int::from(verify))
                        };
                        if m.is_null() {
                            err::raise(
                                ERR_LIB_CRYPTO,
                                rustyssl_abi::ERR_R_UI_LIB,
                                "ossl_pw_get_passphrase",
                            );
                            return false;
                        }
                        // SAFETY: the caller's room and length; the wrapper and the callback's
                        // argument.
                        let ok = unsafe {
                            do_ui_passphrase(pass, pass_size, pass_len, prompt_info, verify, m, arg)
                        };
                        // SAFETY: made above.
                        unsafe { crate::ui::UI_destroy_method(m) };
                        ok
                    }
                    Source::Ui(m, data) => {
                        // SAFETY: as above, with the application's method and data.
                        unsafe {
                            do_ui_passphrase(
                                pass,
                                pass_size,
                                pass_len,
                                prompt_info,
                                verify,
                                m,
                                data,
                            )
                        }
                    }
                    _ => {
                        err::raise_with_text(
                            ERR_LIB_CRYPTO,
                            ERR_R_PASSED_INVALID_ARGUMENT,
                            "ossl_pw_get_passphrase",
                            "No password method specified",
                        );
                        return false;
                    }
                }
            }
        };
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { this.as_mut() }) else {
            return ok;
        };
        if ok && d.cache_on {
            // SAFETY: the callback's answer: its length, within the room.
            let n = unsafe { pass_len.read() }.min(pass_size);
            // SAFETY: the caller's room holds the answer.
            let answer = unsafe { core::slice::from_raw_parts(pass.cast::<u8>(), n) };
            d.cached = Some(Zeroizing::new(answer.to_vec()));
        }
        ok
    }
}

/// `do_ui_passphrase`: the passphrase asked through a UI with `ui_method` (and its data) and the
/// method's prompt for "pass phrase" (with `prompt_info`), twice when verifying. True, or
/// false with an error.
///
/// # Safety
/// `pass` has room for `pass_size` octets; `pass_len` is writable; `prompt_info` is NULL or a C
/// string; `ui_method` is NULL or a live method taking `ui_data`.
unsafe fn do_ui_passphrase(
    pass: *mut c_char,
    pass_size: usize,
    pass_len: *mut usize,
    prompt_info: *const c_char,
    verify: bool,
    ui_method: *const UI_METHOD,
    ui_data: *mut c_void,
) -> bool {
    use crate::ui::{
        UI_add_input_string, UI_add_user_data, UI_add_verify_string, UI_construct_prompt, UI_free,
        UI_get_result_length, UI_new, UI_process, UI_set_method,
    };
    use rustyssl_abi::{ERR_R_INTERRUPTED_OR_CANCELLED, ERR_R_UI_LIB, UI_INPUT_FLAG_DEFAULT_PWD};
    const F: &str = "do_ui_passphrase";
    if pass.is_null() || pass_size == 0 || pass_len.is_null() {
        err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER, F);
        return false;
    }
    // SAFETY: no preconditions.
    let ui = unsafe { UI_new() };
    if ui.is_null() {
        err::raise(ERR_LIB_CRYPTO, ERR_R_UI_LIB, F);
        return false;
    }
    if !ui_method.is_null() {
        // SAFETY: the new UI; the caller's method.
        unsafe { UI_set_method(ui, ui_method) };
        if !ui_data.is_null() {
            // SAFETY: as above, with the method's data.
            unsafe { UI_add_user_data(ui, ui_data) };
        }
    }
    let size = c_int::try_from(pass_size).unwrap_or(c_int::MAX);
    let (mut ipass, mut vpass) = (ptr::null_mut::<c_char>(), ptr::null_mut::<c_char>());
    // SAFETY: the new UI; a static description; the caller's info.
    let prompt = unsafe { UI_construct_prompt(ui, c"pass phrase".as_ptr(), prompt_info) };
    let mut ret = false;
    'ask: {
        if prompt.is_null() {
            err::raise(ERR_LIB_CRYPTO, ERR_R_UI_LIB, F);
            break 'ask;
        }
        ipass = crate::mem::zalloc(pass_size.saturating_add(1), ptr::null(), 0).cast();
        if ipass.is_null() {
            break 'ask;
        }
        // SAFETY: the UI; its prompt; a buffer of `pass_size + 1`.
        let prompt_idx =
            unsafe { UI_add_input_string(ui, prompt, UI_INPUT_FLAG_DEFAULT_PWD, ipass, 0, size) }
                .saturating_sub(1);
        if prompt_idx < 0 {
            err::raise(ERR_LIB_CRYPTO, ERR_R_UI_LIB, F);
            break 'ask;
        }
        if verify {
            vpass = crate::mem::zalloc(pass_size.saturating_add(1), ptr::null(), 0).cast();
            if vpass.is_null() {
                break 'ask;
            }
            // SAFETY: as above, verifying against the first answer.
            let verify_idx = unsafe {
                UI_add_verify_string(ui, prompt, UI_INPUT_FLAG_DEFAULT_PWD, vpass, 0, size, ipass)
            }
            .saturating_sub(1);
            if verify_idx < 0 {
                err::raise(ERR_LIB_CRYPTO, ERR_R_UI_LIB, F);
                break 'ask;
            }
        }
        // SAFETY: the UI, through its method (no lock held).
        match unsafe { UI_process(ui) } {
            -2 => err::raise(ERR_LIB_CRYPTO, ERR_R_INTERRUPTED_OR_CANCELLED, F),
            -1 => err::raise(ERR_LIB_CRYPTO, ERR_R_UI_LIB, F),
            _ => {
                // SAFETY: as above.
                let res = unsafe { UI_get_result_length(ui, prompt_idx) };
                let Ok(n) = usize::try_from(res) else {
                    err::raise(ERR_LIB_CRYPTO, ERR_R_UI_LIB, F);
                    break 'ask;
                };
                let n = n.min(pass_size);
                // SAFETY: the caller's guarantee.
                unsafe { pass_len.write(n) };
                // SAFETY: the answer's `n` octets; the caller's room for them.
                unsafe { ptr::copy_nonoverlapping(ipass, pass, n) };
                ret = true;
            }
        }
    }
    // SAFETY: made above (of `pass_size + 1` octets), or NULL.
    unsafe { crate::mem::release_clean(vpass.cast(), pass_size.saturating_add(1)) };
    // SAFETY: as above.
    unsafe { crate::mem::release_clean(ipass.cast(), pass_size.saturating_add(1)) };
    // SAFETY: made by the UI, or NULL.
    unsafe { crate::mem::release(prompt.cast()) };
    // SAFETY: made above.
    unsafe { UI_free(ui) };
    ret
}

/// `ossl_pw_passphrase_callback_dec`: an `OSSL_PASSPHRASE_CALLBACK` over a `PwData` (as `arg`),
/// for decoding.
///
/// # Safety
/// As for an `OSSL_PASSPHRASE_CALLBACK`, with `arg` a live `PwData`.
pub(crate) unsafe extern "C" fn passphrase_callback_dec(
    pass: *mut c_char,
    pass_size: usize,
    pass_len: *mut usize,
    params: *const OSSL_PARAM,
    arg: *mut c_void,
) -> c_int {
    // SAFETY: the caller's guarantee.
    c_int::from(unsafe { PwData::get(arg.cast(), pass, pass_size, pass_len, params, false) })
}

/// `ossl_pw_passphrase_callback_enc`: as `passphrase_callback_dec`, asking to verify.
///
/// # Safety
/// As for `passphrase_callback_dec`.
#[allow(dead_code, reason = "the encoders (4.7c) ask with it")]
pub(crate) unsafe extern "C" fn passphrase_callback_enc(
    pass: *mut c_char,
    pass_size: usize,
    pass_len: *mut usize,
    params: *const OSSL_PARAM,
    arg: *mut c_void,
) -> c_int {
    // SAFETY: the caller's guarantee.
    c_int::from(unsafe { PwData::get(arg.cast(), pass, pass_size, pass_len, params, true) })
}

/// `ossl_pw_pem_password`: a `pem_password_cb` over a `PwData` (as `userdata`), asking with
/// the prompt info "PEM" (`ossl_pw_get_password`): the passphrase's length, or -1.
///
/// # Safety
/// As for a `pem_password_cb`, with `userdata` a live `PwData`.
pub(crate) unsafe extern "C" fn pw_pem_password(
    buf: *mut c_char,
    size: c_int,
    rwflag: c_int,
    userdata: *mut c_void,
) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { pw_get_password(buf, size, rwflag, userdata, c"PEM") }
}

/// `ossl_pw_pvk_password`: as `pw_pem_password`, with the prompt info "PVK".
///
/// # Safety
/// As for `pw_pem_password`.
pub(crate) unsafe extern "C" fn pw_pvk_password(
    buf: *mut c_char,
    size: c_int,
    rwflag: c_int,
    userdata: *mut c_void,
) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { pw_get_password(buf, size, rwflag, userdata, c"PVK") }
}

/// `ossl_pw_get_password`: the passphrase the `PwData` gives, asking with the prompt `info`:
/// its length, or -1.
///
/// # Safety
/// As for `pw_pem_password`.
unsafe fn pw_get_password(
    buf: *mut c_char,
    size: c_int,
    rwflag: c_int,
    userdata: *mut c_void,
    info: &CStr,
) -> c_int {
    let params = [
        // SAFETY: a static name and string, read during the call.
        unsafe {
            crate::params::OSSL_PARAM_construct_utf8_string(
                OSSL_PASSPHRASE_PARAM_INFO.as_ptr(),
                info.as_ptr().cast_mut(),
                0,
            )
        },
        // SAFETY: no preconditions.
        unsafe { crate::params::OSSL_PARAM_construct_end() },
    ];
    let mut len = 0usize;
    let size = usize::try_from(size).unwrap_or(0);
    // SAFETY: the caller's guarantee; a local for the length.
    let ok = unsafe {
        PwData::get(
            userdata.cast(),
            buf,
            size,
            &raw mut len,
            params.as_ptr(),
            rwflag != 0,
        )
    };
    if ok {
        c_int::try_from(len).unwrap_or(-1)
    } else {
        -1
    }
}
