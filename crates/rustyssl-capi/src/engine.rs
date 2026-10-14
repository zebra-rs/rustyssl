//! The ENGINE functions applications call on the engines they hold. rustyssl has no engines
//! (docs/DEVIATIONS.md), so the only engine pointer they can be given is NULL, which OpenSSL's
//! accept and ignore; any other pointer isn't an engine, and aborts, as an unimplemented
//! export does (security rule 10). The rest of ENGINE comes with step 9.3.

use core::ffi::c_int;
use core::ptr;

use rustyssl_abi::{ENGINE, ERR_LIB_ENGINE};

use crate::ffi::ffi_export;

ffi_export! {
    /// Drops a structural reference to an engine: 1 for NULL, which OpenSSL ignores.
    ///
    /// # Safety
    /// `e` is NULL (there are no engines).
    pub unsafe extern "C" fn ENGINE_free(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        if !e.is_null() {
            crate::stub::unimplemented("ENGINE_free of an engine (rustyssl has none)");
        }
        1
    }
}

ffi_export! {
    /// Drops a functional reference to an engine: 1 for NULL, which OpenSSL ignores.
    ///
    /// # Safety
    /// `e` is NULL (there are no engines).
    pub unsafe extern "C" fn ENGINE_finish(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        if !e.is_null() {
            crate::stub::unimplemented("ENGINE_finish of an engine (rustyssl has none)");
        }
        1
    }
}

ffi_export! {
    /// The engine that implements the digest `nid` by default: none (there are no engines).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_get_digest_engine(nid: c_int) -> *mut ENGINE
    where failure = ptr::null_mut(), library = ERR_LIB_ENGINE
    {
        let _ = nid;
        ptr::null_mut()
    }
}

ffi_export! {
    /// The engine that implements the cipher `nid` by default: none (there are no engines).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_get_cipher_engine(nid: c_int) -> *mut ENGINE
    where failure = ptr::null_mut(), library = ERR_LIB_ENGINE
    {
        let _ = nid;
        ptr::null_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: there are no engines, so loading OpenSSL's built-in ones loads none,
    /// and none implements a digest or a cipher.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "initialization loads the configuration, reading the environment"
    )]
    fn there_are_no_engines() {
        let all = rustyssl_abi::OPENSSL_INIT_ENGINE_ALL_BUILTIN.cast_unsigned();
        // SAFETY: no settings.
        let r = unsafe { crate::init::OPENSSL_init_crypto(all, ptr::null()) };
        assert_eq!(r, 1);
        // SAFETY: no preconditions.
        assert!(unsafe { ENGINE_get_digest_engine(rustyssl_abi::NID_sha256) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { ENGINE_get_cipher_engine(rustyssl_abi::NID_aes_128_cbc) }.is_null());
        // SAFETY: NULL.
        assert_eq!(unsafe { ENGINE_free(ptr::null_mut()) }, 1);
    }
}
