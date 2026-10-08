//! `OSSL_sleep(3)`: sleeping for a number of milliseconds.

use core::time::Duration;

use rustyssl_abi::ERR_LIB_CRYPTO;

use crate::ffi::ffi_export;

/// Sleeps at least `millis` milliseconds, as OpenSSL's `nanosleep` loop does on Unix.
pub(crate) fn sleep_millis(millis: u64) {
    std::thread::sleep(Duration::from_millis(millis));
}

ffi_export! {
    /// Sleeps at least `millis` milliseconds.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_sleep(millis: u64)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        sleep_millis(millis);
    }
}
