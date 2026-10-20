//! Ciphers applications make (`EVP_CIPHER_meth_new(3)`; `cmeth_lib.c`): a method with no
//! provider whose IV length, flags, state size, and C functions the application sets, each
//! once (a second set fails), and the getters, which report them for any cipher (none for a
//! static or fetched one: see below).
//!
//! OpenSSL's setters write into whatever cipher they're given, a static one (whose definition
//! is read-only, so the write crashes) or a fetched one (shared with every other user); here
//! they change only ciphers from `EVP_CIPHER_meth_new` or `EVP_CIPHER_meth_dup`, and fail on
//! others. OpenSSL's static ciphers carry C functions over state structures it doesn't publish
//! (`EVP_AES_KEY`, ...); here they have none, and a copy of one is a cipher without functions
//! (docs/DEVIATIONS.md). The functions given a NULL cipher fail where OpenSSL would crash.

use core::ffi::{c_int, c_ulong};
use core::ptr;

use rustyssl_abi::{ERR_LIB_EVP, EVP_CIPHER};

use super::cipher::{
    Cipher, Field, Legacy, LegacyAsn1Fn, LegacyCleanupFn, LegacyCtrlFn, LegacyDoCipherFn,
    LegacyInitFn, Origin, method,
};
use crate::ffi::ffi_export;
use crate::handle::Handle;

/// The application's cipher behind `cipher`, if it is one.
///
/// # Safety
/// `cipher` is NULL or a live cipher method.
unsafe fn own<'a>(cipher: *mut EVP_CIPHER) -> Option<&'a Cipher> {
    // SAFETY: the caller's guarantee.
    unsafe { method(cipher) }.filter(|m| m.origin == Origin::Meth)
}

/// The C functions of `cipher` (none for NULL).
///
/// # Safety
/// `cipher` is NULL or a live cipher method.
unsafe fn fns(cipher: *const EVP_CIPHER) -> Legacy {
    // SAFETY: the caller's guarantee.
    unsafe { method(cipher) }
        .map(Cipher::legacy_fns)
        .unwrap_or_default()
}

ffi_export! {
    /// A new cipher with the NID `cipher_type`, block size, and key length, and nothing else
    /// set, which the application sets up with the setters and frees with
    /// `EVP_CIPHER_meth_free`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_CIPHER_meth_new(cipher_type: c_int, block_size: c_int, key_len: c_int) -> *mut EVP_CIPHER
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        EVP_CIPHER::new_handle(Cipher::meth(cipher_type, block_size, key_len, None))
    }
}

ffi_export! {
    /// A copy of a static or application's cipher, as a new application's cipher; NULL for a
    /// fetched one (which `EVP_CIPHER_up_ref` shares instead).
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_meth_dup(cipher: *const EVP_CIPHER) -> *mut EVP_CIPHER
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(cipher) }) else { return ptr::null_mut() };
        if !m.prov.0.is_null() {
            return ptr::null_mut();
        }
        EVP_CIPHER::new_handle(Cipher::meth(m.nid, m.block_size(), m.key_len(), Some(m)))
    }
}

ffi_export! {
    /// Frees an application's cipher; anything else (and NULL) is left alone.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method, not used afterwards if it's an application's.
    pub unsafe extern "C" fn EVP_CIPHER_meth_free(cipher: *mut EVP_CIPHER)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if unsafe { own(cipher) }.is_some() {
            // SAFETY: the application's cipher, given up.
            unsafe { EVP_CIPHER::free(cipher) };
        }
    }
}

ffi_export! {
    /// Sets the cipher's IV length, if not yet set. Returns 1, or 0.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_meth_set_iv_length(cipher: *mut EVP_CIPHER, iv_len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let v = u64::from_ne_bytes(i64::from(iv_len).to_ne_bytes());
        // SAFETY: the caller's guarantee.
        unsafe { own(cipher) }.map_or(0, |m| c_int::from(m.set_once(Field::IvLen, v)))
    }
}

ffi_export! {
    /// Sets the cipher's flags (its mode and `EVP_CIPH_*` flags), if none are set yet. Returns
    /// 1, or 0.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_meth_set_flags(cipher: *mut EVP_CIPHER, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { own(cipher) }.map_or(0, |m| c_int::from(m.set_once(Field::Flags, flags)))
    }
}

ffi_export! {
    /// Sets the size of the state the cipher's functions keep (`cipher_data`), if not yet set.
    /// Returns 1, or 0.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_meth_set_impl_ctx_size(cipher: *mut EVP_CIPHER, ctx_size: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { own(cipher) }) else { return 0 };
        c_int::from(m.set_legacy(|l| {
            let fresh = l.ctx_size == 0;
            if fresh {
                l.ctx_size = ctx_size;
            }
            fresh
        }))
    }
}

ffi_export! {
    /// The size of the cipher's state (0 for NULL, and for a static or fetched cipher here).
    ///
    /// # Safety
    /// `e` is NULL or a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_impl_ctx_size(e: *const EVP_CIPHER) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { fns(e) }.ctx_size
    }
}

ffi_export! {
    /// Sets the cipher's `init` function, if not yet set. Returns 1, or 0.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method; `f` is NULL or a function of the documented
    /// type.
    pub unsafe extern "C" fn EVP_CIPHER_meth_set_init(cipher: *mut EVP_CIPHER, f: Option<LegacyInitFn>) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { own(cipher) }) else { return 0 };
        c_int::from(m.set_legacy(|l| {
            let fresh = l.init.is_none();
            if fresh {
                l.init = f;
            }
            fresh
        }))
    }
}

ffi_export! {
    /// Sets the cipher's `do_cipher` function, if not yet set. Returns 1, or 0.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method; `f` is NULL or a function of the documented
    /// type.
    pub unsafe extern "C" fn EVP_CIPHER_meth_set_do_cipher(cipher: *mut EVP_CIPHER, f: Option<LegacyDoCipherFn>) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { own(cipher) }) else { return 0 };
        c_int::from(m.set_legacy(|l| {
            let fresh = l.do_cipher.is_none();
            if fresh {
                l.do_cipher = f;
            }
            fresh
        }))
    }
}

ffi_export! {
    /// Sets the cipher's `cleanup` function, if not yet set. Returns 1, or 0.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method; `f` is NULL or a function of the documented
    /// type.
    pub unsafe extern "C" fn EVP_CIPHER_meth_set_cleanup(cipher: *mut EVP_CIPHER, f: Option<LegacyCleanupFn>) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { own(cipher) }) else { return 0 };
        c_int::from(m.set_legacy(|l| {
            let fresh = l.cleanup.is_none();
            if fresh {
                l.cleanup = f;
            }
            fresh
        }))
    }
}

ffi_export! {
    /// Sets the cipher's `set_asn1_params` function, if not yet set. Returns 1, or 0.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method; `f` is NULL or a function of the documented
    /// type.
    pub unsafe extern "C" fn EVP_CIPHER_meth_set_set_asn1_params(cipher: *mut EVP_CIPHER, f: Option<LegacyAsn1Fn>) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { own(cipher) }) else { return 0 };
        c_int::from(m.set_legacy(|l| {
            let fresh = l.set_asn1.is_none();
            if fresh {
                l.set_asn1 = f;
            }
            fresh
        }))
    }
}

ffi_export! {
    /// Sets the cipher's `get_asn1_params` function, if not yet set. Returns 1, or 0.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method; `f` is NULL or a function of the documented
    /// type.
    pub unsafe extern "C" fn EVP_CIPHER_meth_set_get_asn1_params(cipher: *mut EVP_CIPHER, f: Option<LegacyAsn1Fn>) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { own(cipher) }) else { return 0 };
        c_int::from(m.set_legacy(|l| {
            let fresh = l.get_asn1.is_none();
            if fresh {
                l.get_asn1 = f;
            }
            fresh
        }))
    }
}

ffi_export! {
    /// Sets the cipher's `ctrl` function, if not yet set. Returns 1, or 0.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method; `f` is NULL or a function of the documented
    /// type.
    pub unsafe extern "C" fn EVP_CIPHER_meth_set_ctrl(cipher: *mut EVP_CIPHER, f: Option<LegacyCtrlFn>) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { own(cipher) }) else { return 0 };
        c_int::from(m.set_legacy(|l| {
            let fresh = l.ctrl.is_none();
            if fresh {
                l.ctrl = f;
            }
            fresh
        }))
    }
}

ffi_export! {
    /// The cipher's `init` function: an application's, or NULL.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_meth_get_init(cipher: *const EVP_CIPHER) -> Option<LegacyInitFn>
    where failure = None, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { fns(cipher) }.init
    }
}

ffi_export! {
    /// The cipher's `do_cipher` function: an application's, or NULL.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_meth_get_do_cipher(cipher: *const EVP_CIPHER) -> Option<LegacyDoCipherFn>
    where failure = None, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { fns(cipher) }.do_cipher
    }
}

ffi_export! {
    /// The cipher's `cleanup` function: an application's, or NULL.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_meth_get_cleanup(cipher: *const EVP_CIPHER) -> Option<LegacyCleanupFn>
    where failure = None, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { fns(cipher) }.cleanup
    }
}

ffi_export! {
    /// The cipher's `set_asn1_params` function: an application's, or NULL.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_meth_get_set_asn1_params(cipher: *const EVP_CIPHER) -> Option<LegacyAsn1Fn>
    where failure = None, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { fns(cipher) }.set_asn1
    }
}

ffi_export! {
    /// The cipher's `get_asn1_params` function: an application's, or NULL.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_meth_get_get_asn1_params(cipher: *const EVP_CIPHER) -> Option<LegacyAsn1Fn>
    where failure = None, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { fns(cipher) }.get_asn1
    }
}

ffi_export! {
    /// The cipher's `ctrl` function: an application's, or NULL.
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method.
    pub unsafe extern "C" fn EVP_CIPHER_meth_get_ctrl(cipher: *const EVP_CIPHER) -> Option<LegacyCtrlFn>
    where failure = None, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { fns(cipher) }.ctrl
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get_iv_length};
    use crate::evp::legacy_cipher::EVP_aes_128_cbc;

    /// docs/DEVIATIONS.md: the setters change only an application's cipher; a static or
    /// fetched one is refused and stays as it was (OpenSSL writes into the read-only static
    /// definition and crashes, or changes the fetched cipher for every user of it).
    #[test]
    #[cfg_attr(miri, ignore = "fetches, which loads the configuration")]
    fn setters_refuse_static_and_fetched_ciphers() {
        // SAFETY: no preconditions.
        let fixed = unsafe { EVP_aes_128_cbc() }.cast_mut();
        // SAFETY: the default context and a static name.
        let fetched =
            unsafe { EVP_CIPHER_fetch(ptr::null_mut(), c"AES-128-CBC".as_ptr(), ptr::null()) };
        for c in [fixed, fetched] {
            // SAFETY: a live cipher, for each call below.
            assert_eq!(unsafe { EVP_CIPHER_meth_set_iv_length(c, 5) }, 0);
            // SAFETY: as above.
            assert_eq!(unsafe { EVP_CIPHER_meth_set_flags(c, 1) }, 0);
            // SAFETY: as above.
            assert_eq!(unsafe { EVP_CIPHER_meth_set_impl_ctx_size(c, 64) }, 0);
            // SAFETY: as above.
            assert_eq!(unsafe { EVP_CIPHER_meth_set_cleanup(c, None) }, 0);
            // SAFETY: as above.
            assert_eq!(unsafe { EVP_CIPHER_get_iv_length(c) }, 16);
        }
        // SAFETY: the fetched cipher's reference.
        unsafe { EVP_CIPHER_free(fetched) };
        // An application's cipher takes them.
        // SAFETY: no preconditions.
        let own = unsafe { EVP_CIPHER_meth_new(0, 8, 8) };
        // SAFETY: the new cipher.
        assert_eq!(unsafe { EVP_CIPHER_meth_set_iv_length(own, 5) }, 1);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_CIPHER_get_iv_length(own) }, 5);
        // SAFETY: as above.
        unsafe { EVP_CIPHER_meth_free(own) };
    }

    /// The static ciphers report their C functions and state size in the slots OpenSSL's fill
    /// (`legacy_cipher_fns`), and a copy of one keeps them.
    #[test]
    fn static_ciphers_have_their_functions() {
        // SAFETY: no preconditions.
        let aes = unsafe { EVP_aes_128_cbc() };
        // SAFETY: a static cipher, for each call below.
        assert!(unsafe { EVP_CIPHER_meth_get_init(aes) }.is_some());
        // SAFETY: as above.
        assert!(unsafe { EVP_CIPHER_meth_get_do_cipher(aes) }.is_some());
        // As in OpenSSL, AES-CBC has no `ctrl`.
        // SAFETY: as above.
        assert!(unsafe { EVP_CIPHER_meth_get_ctrl(aes) }.is_none());
        // SAFETY: as above.
        assert!(unsafe { EVP_CIPHER_impl_ctx_size(aes) } > 0);
        // SAFETY: as above.
        let copy = unsafe { EVP_CIPHER_meth_dup(aes) };
        assert!(!copy.is_null());
        // SAFETY: the copy.
        assert!(unsafe { EVP_CIPHER_meth_get_do_cipher(copy) }.is_some());
        // SAFETY: as above.
        unsafe { EVP_CIPHER_meth_free(copy) };
    }

    /// docs/DEVIATIONS.md: a static cipher whose state OpenSSL doesn't publish (AES-OCB) has
    /// functions that fail, in the slots OpenSSL's fill (no NULL to call), and no state size.
    #[test]
    fn private_state_ciphers_have_failing_functions() {
        // SAFETY: no preconditions.
        let gcm = unsafe { crate::evp::legacy_cipher::EVP_aes_128_ocb() };
        // SAFETY: a static cipher, for each call below.
        let init = unsafe { EVP_CIPHER_meth_get_init(gcm) };
        // SAFETY: as above.
        assert!(unsafe { EVP_CIPHER_meth_get_do_cipher(gcm) }.is_some());
        // SAFETY: as above.
        assert!(unsafe { EVP_CIPHER_meth_get_cleanup(gcm) }.is_some());
        // SAFETY: as above.
        assert!(unsafe { EVP_CIPHER_meth_get_ctrl(gcm) }.is_some());
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_CIPHER_impl_ctx_size(gcm) }, 0);
        // SAFETY: no preconditions.
        let ctx = unsafe { crate::evp::cipher_ctx::EVP_CIPHER_CTX_new() };
        // SAFETY: the cipher's function with a context (it touches none of it).
        let r = init.map(|f| unsafe { f(ctx, ptr::null(), ptr::null(), 1) });
        assert_eq!(r, Some(0));
        // SAFETY: made above.
        unsafe { crate::evp::cipher_ctx::EVP_CIPHER_CTX_free(ctx) };
        crate::err::take_all();
    }
}
