//! `BIGNUM`s: making one from a word, and printing one.

use crate::bio::Bio;
use crate::ffi;
use crate::util::take_string;

crate::handle!(
    /// An owned `BIGNUM`.
    Bn, BIGNUM, BN_free
);

impl Bn {
    /// `BN_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::BN_new() })
    }

    /// `BN_set_word`.
    pub fn set_word(&self, w: u64) -> bool {
        // SAFETY: the number is live.
        unsafe { ffi::BN_set_word(self.as_ptr(), w) == 1 }
    }

    /// `BN_bn2hex`.
    pub fn to_hex(&self) -> Option<String> {
        // SAFETY: the number is live; the result is the caller's to free (take_string).
        take_string(unsafe { ffi::BN_bn2hex(self.as_ptr()) })
    }

    /// `BN_bn2dec`.
    pub fn to_dec(&self) -> Option<String> {
        // SAFETY: as above.
        take_string(unsafe { ffi::BN_bn2dec(self.as_ptr()) })
    }
}

/// `BN_print(bio, bn)`.
pub fn print(bio: &Bio, bn: &Bn) -> i32 {
    // SAFETY: the BIO and the number are live.
    unsafe { ffi::BN_print(bio.as_ptr(), bn.as_ptr()) }
}
