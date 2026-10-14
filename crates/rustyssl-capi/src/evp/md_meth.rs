//! Digests applications make (`EVP_MD_meth_new(3)`; `evp_lib.c`): a method with no provider
//! whose sizes, flags, state size, and C functions the application sets, each once (a second
//! set fails), and the getters, which report them for any digest (a static digest's own C
//! functions, none for a fetched one's).
//!
//! OpenSSL's setters write into whatever digest they're given, a static one (whose definition
//! is read-only, so the write crashes) or a fetched one (shared with every other user); here
//! they change only digests from `EVP_MD_meth_new` or `EVP_MD_meth_dup`, and fail on others
//! (docs/DEVIATIONS.md). The functions given a NULL digest fail where OpenSSL would crash.

use core::ffi::{c_int, c_ulong};
use core::ptr;

use rustyssl_abi::{ERR_LIB_EVP, EVP_MD};

use super::digest::{
    Field, Legacy, LegacyCopyFn, LegacyCtrlFn, LegacyFinalFn, LegacyInitFn, LegacyUpdateFn, Md,
    Origin, method,
};
use crate::ffi::ffi_export;
use crate::handle::Handle;

/// The application's digest behind `md`, if it is one.
///
/// # Safety
/// `md` is NULL or a live digest method.
unsafe fn own<'a>(md: *mut EVP_MD) -> Option<&'a Md> {
    // SAFETY: the caller's guarantee.
    unsafe { method(md) }.filter(|m| m.origin == Origin::Meth)
}

/// The C functions of `md` (none for NULL).
///
/// # Safety
/// `md` is NULL or a live digest method.
unsafe fn fns(md: *const EVP_MD) -> Legacy {
    // SAFETY: the caller's guarantee.
    unsafe { method(md) }
        .map(Md::legacy_fns)
        .unwrap_or_default()
}

ffi_export! {
    /// A new digest with the NIDs `md_type` and `pkey_type` and nothing else set, which the
    /// application sets up with the setters and frees with `EVP_MD_meth_free`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_MD_meth_new(md_type: c_int, pkey_type: c_int) -> *mut EVP_MD
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        EVP_MD::new_handle(Md::meth(md_type, pkey_type, None))
    }
}

ffi_export! {
    /// A copy of a static or application's digest, as a new application's digest; NULL for a
    /// fetched one (which `EVP_MD_up_ref` shares instead).
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_meth_dup(md: *const EVP_MD) -> *mut EVP_MD
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(md) }) else { return ptr::null_mut() };
        if !m.prov.0.is_null() {
            return ptr::null_mut();
        }
        EVP_MD::new_handle(Md::meth(m.nid, m.pkey_type, Some(m)))
    }
}

ffi_export! {
    /// Frees an application's digest; anything else (and NULL) is left alone.
    ///
    /// # Safety
    /// `md` is NULL or a live digest method, not used afterwards if it's an application's.
    pub unsafe extern "C" fn EVP_MD_meth_free(md: *mut EVP_MD)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if unsafe { own(md) }.is_some() {
            // SAFETY: the application's digest, given up.
            unsafe { EVP_MD::free(md) };
        }
    }
}

ffi_export! {
    /// Sets the digest's block size, if not yet set. Returns 1, or 0.
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_meth_set_input_blocksize(md: *mut EVP_MD, value: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { own(md) }.map_or(0, |m| c_int::from(m.set_once(Field::BlockSize, i64::from(value))))
    }
}

ffi_export! {
    /// Sets the digest's size (of its result), if not yet set. Returns 1, or 0.
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_meth_set_result_size(md: *mut EVP_MD, value: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { own(md) }.map_or(0, |m| c_int::from(m.set_once(Field::MdSize, i64::from(value))))
    }
}

ffi_export! {
    /// Sets the size of the state the digest's functions keep (`md_data`), if not yet set.
    /// Returns 1, or 0.
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_meth_set_app_datasize(md: *mut EVP_MD, datasize: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { own(md) }) else { return 0 };
        c_int::from(m.set_legacy(|l| {
            let fresh = l.ctx_size == 0;
            if fresh {
                l.ctx_size = datasize;
            }
            fresh
        }))
    }
}

ffi_export! {
    /// Sets the digest's flags (`EVP_MD_FLAG_XOF`, ...), if none are set yet. Returns 1, or 0.
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_meth_set_flags(md: *mut EVP_MD, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { own(md) }.map_or(0, |m| c_int::from(m.set_once(Field::Flags, i64::from_ne_bytes(flags.to_ne_bytes()))))
    }
}

ffi_export! {
    /// Sets the digest's `init` function, if not yet set. Returns 1, or 0.
    ///
    /// # Safety
    /// `md` is NULL or a live digest method; `f` is NULL or a function of the documented type.
    pub unsafe extern "C" fn EVP_MD_meth_set_init(md: *mut EVP_MD, f: Option<LegacyInitFn>) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { own(md) }) else { return 0 };
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
    /// Sets the digest's `update` function, if not yet set. Returns 1, or 0.
    ///
    /// # Safety
    /// `md` is NULL or a live digest method; `f` is NULL or a function of the documented type.
    pub unsafe extern "C" fn EVP_MD_meth_set_update(md: *mut EVP_MD, f: Option<LegacyUpdateFn>) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { own(md) }) else { return 0 };
        c_int::from(m.set_legacy(|l| {
            let fresh = l.update.is_none();
            if fresh {
                l.update = f;
            }
            fresh
        }))
    }
}

ffi_export! {
    /// Sets the digest's `final` function, if not yet set. Returns 1, or 0.
    ///
    /// # Safety
    /// `md` is NULL or a live digest method; `f` is NULL or a function of the documented type.
    pub unsafe extern "C" fn EVP_MD_meth_set_final(md: *mut EVP_MD, f: Option<LegacyFinalFn>) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { own(md) }) else { return 0 };
        c_int::from(m.set_legacy(|l| {
            let fresh = l.final_.is_none();
            if fresh {
                l.final_ = f;
            }
            fresh
        }))
    }
}

ffi_export! {
    /// Sets the digest's `copy` function, if not yet set. Returns 1, or 0.
    ///
    /// # Safety
    /// `md` is NULL or a live digest method; `f` is NULL or a function of the documented type.
    pub unsafe extern "C" fn EVP_MD_meth_set_copy(md: *mut EVP_MD, f: Option<LegacyCopyFn>) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { own(md) }) else { return 0 };
        c_int::from(m.set_legacy(|l| {
            let fresh = l.copy.is_none();
            if fresh {
                l.copy = f;
            }
            fresh
        }))
    }
}

ffi_export! {
    /// Sets the digest's `cleanup` function, if not yet set. Returns 1, or 0.
    ///
    /// # Safety
    /// `md` is NULL or a live digest method; `f` is NULL or a function of the documented type.
    pub unsafe extern "C" fn EVP_MD_meth_set_cleanup(md: *mut EVP_MD, f: Option<LegacyInitFn>) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { own(md) }) else { return 0 };
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
    /// Sets the digest's `ctrl` function, if not yet set. Returns 1, or 0.
    ///
    /// # Safety
    /// `md` is NULL or a live digest method; `f` is NULL or a function of the documented type.
    pub unsafe extern "C" fn EVP_MD_meth_set_ctrl(md: *mut EVP_MD, f: Option<LegacyCtrlFn>) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { own(md) }) else { return 0 };
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
    /// The digest's block size (0 for NULL).
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_meth_get_input_blocksize(md: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(md) }.map_or(0, |m| m.block_size())
    }
}

ffi_export! {
    /// The digest's size (0 for NULL).
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_meth_get_result_size(md: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(md) }.map_or(0, |m| m.md_size())
    }
}

ffi_export! {
    /// The digest's state size (0 for NULL).
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_meth_get_app_datasize(md: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(md) }.map_or(0, |m| m.legacy_fns().ctx_size)
    }
}

ffi_export! {
    /// The digest's flags (0 for NULL).
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_meth_get_flags(md: *const EVP_MD) -> c_ulong
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(md) }.map_or(0, Md::flags)
    }
}

ffi_export! {
    /// The digest's `init` function: an application's, a static digest's own, or NULL.
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_meth_get_init(md: *const EVP_MD) -> Option<LegacyInitFn>
    where failure = None, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { fns(md) }.init
    }
}

ffi_export! {
    /// The digest's `update` function: an application's, a static digest's own, or NULL.
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_meth_get_update(md: *const EVP_MD) -> Option<LegacyUpdateFn>
    where failure = None, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { fns(md) }.update
    }
}

ffi_export! {
    /// The digest's `final` function: an application's, a static digest's own, or NULL.
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_meth_get_final(md: *const EVP_MD) -> Option<LegacyFinalFn>
    where failure = None, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { fns(md) }.final_
    }
}

ffi_export! {
    /// The digest's `copy` function: an application's, a static digest's own, or NULL.
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_meth_get_copy(md: *const EVP_MD) -> Option<LegacyCopyFn>
    where failure = None, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { fns(md) }.copy
    }
}

ffi_export! {
    /// The digest's `cleanup` function: an application's, a static digest's own, or NULL.
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_meth_get_cleanup(md: *const EVP_MD) -> Option<LegacyInitFn>
    where failure = None, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { fns(md) }.cleanup
    }
}

ffi_export! {
    /// The digest's `ctrl` function: an application's, a static digest's own, or NULL.
    ///
    /// # Safety
    /// `md` is NULL or a live digest method.
    pub unsafe extern "C" fn EVP_MD_meth_get_ctrl(md: *const EVP_MD) -> Option<LegacyCtrlFn>
    where failure = None, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { fns(md) }.ctrl
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EVP_MD_get_size};
    use crate::evp::legacy_md::{EVP_sha3_256, EVP_sha256, EVP_shake128};

    /// docs/DEVIATIONS.md: the setters change only an application's digest; a static or
    /// fetched one is refused and stays as it was (OpenSSL writes into the read-only static
    /// definition and crashes, or changes the fetched digest for every user of it).
    #[test]
    #[cfg_attr(miri, ignore = "fetches, which loads the configuration")]
    fn setters_refuse_static_and_fetched_digests() {
        // SAFETY: no preconditions.
        let fixed = unsafe { EVP_sha256() }.cast_mut();
        // SAFETY: the default context and a static name.
        let fetched = unsafe { EVP_MD_fetch(ptr::null_mut(), c"SHA256".as_ptr(), ptr::null()) };
        for md in [fixed, fetched] {
            // SAFETY: a live digest, for each call below.
            assert_eq!(unsafe { EVP_MD_meth_set_result_size(md, 5) }, 0);
            // SAFETY: as above.
            assert_eq!(unsafe { EVP_MD_meth_set_flags(md, 1) }, 0);
            // SAFETY: as above.
            assert_eq!(unsafe { EVP_MD_meth_set_cleanup(md, None) }, 0);
            // SAFETY: as above.
            assert_eq!(unsafe { EVP_MD_get_size(md) }, 32);
        }
        // SAFETY: the fetched digest's reference.
        unsafe { EVP_MD_free(fetched) };
        // An application's digest takes them.
        // SAFETY: no preconditions.
        let own = unsafe { EVP_MD_meth_new(0, 0) };
        // SAFETY: the new digest.
        assert_eq!(unsafe { EVP_MD_meth_set_result_size(own, 5) }, 1);
        // SAFETY: as above.
        unsafe { EVP_MD_meth_free(own) };
    }

    /// docs/DEVIATIONS.md: SHA-3, SHAKE, BLAKE2, and SM3 report no C functions (their state is
    /// a structure OpenSSL doesn't publish, so an application can't size it).
    #[test]
    fn private_state_digests_have_no_functions() {
        // SAFETY: no preconditions.
        let sha3 = unsafe { EVP_sha3_256() };
        // SAFETY: as above.
        let shake = unsafe { EVP_shake128() };
        for md in [sha3, shake] {
            // SAFETY: a static digest, for each call below.
            assert!(unsafe { EVP_MD_meth_get_init(md) }.is_none());
            // SAFETY: as above.
            assert!(unsafe { EVP_MD_meth_get_update(md) }.is_none());
            // SAFETY: as above.
            assert!(unsafe { EVP_MD_meth_get_final(md) }.is_none());
        }
        // SAFETY: no preconditions.
        let sha256 = unsafe { EVP_sha256() };
        // SAFETY: a static digest.
        assert!(unsafe { EVP_MD_meth_get_init(sha256) }.is_some());
    }
}
