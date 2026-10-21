//! `BIGNUM`s: making, parsing, printing, and primes.

use core::ffi::c_int;

use crate::bio::Bio;
use crate::ffi;
use crate::util::{cstring, take_string};

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

    /// `BN_hex2bn(&bn, s)` into a new `BIGNUM`: `None` when it returns 0.
    pub fn from_hex(s: &str) -> Option<Self> {
        let c = cstring(s)?;
        let mut p = core::ptr::null_mut();
        // SAFETY: p is a valid out-pointer (NULL: allocate); c is a valid C string.
        let r = unsafe { ffi::BN_hex2bn(&mut p, c.as_ptr()) };
        let bn = Self::from_ptr(p);
        (r != 0).then_some(bn).flatten()
    }

    /// `BN_dec2bn(&bn, s)` into a new `BIGNUM`: `None` when it returns 0.
    pub fn from_dec(s: &str) -> Option<Self> {
        let c = cstring(s)?;
        let mut p = core::ptr::null_mut();
        // SAFETY: as in from_hex.
        let r = unsafe { ffi::BN_dec2bn(&mut p, c.as_ptr()) };
        let bn = Self::from_ptr(p);
        (r != 0).then_some(bn).flatten()
    }

    /// `BN_set_word`.
    pub fn set_word(&self, w: u64) -> bool {
        // SAFETY: the number is live.
        unsafe { ffi::BN_set_word(self.as_ptr(), w) == 1 }
    }

    /// `BN_print(bio, bn)`.
    pub fn print(&self, bio: &Bio) -> bool {
        // SAFETY: both are live.
        unsafe { ffi::BN_print(bio.as_ptr(), self.as_ptr()) == 1 }
    }

    /// `BN_check_prime(bn, NULL, NULL)`: 1 prime, 0 not, -1 an error.
    pub fn check_prime(&self) -> c_int {
        // SAFETY: the number is live; NULL context and callback are allowed.
        unsafe { ffi::BN_check_prime(self.as_ptr(), core::ptr::null_mut(), core::ptr::null_mut()) }
    }

    /// `BN_generate_prime_ex(bn, bits, safe, NULL, NULL, NULL)`.
    pub fn generate_prime(&self, bits: c_int, safe: bool) -> bool {
        // SAFETY: the number is live; NULL add, rem, and callback are allowed.
        unsafe {
            ffi::BN_generate_prime_ex(
                self.as_ptr(),
                bits,
                c_int::from(safe),
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null_mut(),
            ) == 1
        }
    }

    /// `BN_bn2hex`.
    pub fn to_hex(&self) -> Option<String> {
        // SAFETY: the number is live; the string is ours to free, which take_string does.
        take_string(unsafe { ffi::BN_bn2hex(self.as_ptr()) })
    }

    /// `BN_bn2dec`.
    pub fn to_dec(&self) -> Option<String> {
        // SAFETY: as in to_hex.
        take_string(unsafe { ffi::BN_bn2dec(self.as_ptr()) })
    }

    /// `BN_hex2bn`: the number, and how many characters it used (0 on failure).
    pub fn hex2bn(s: &str) -> (Option<Self>, c_int) {
        let Some(c) = cstring(s) else {
            return (None, 0);
        };
        let mut p: *mut crate::abi::BIGNUM = core::ptr::null_mut();
        // SAFETY: p is a valid out-pointer; c a valid C string.
        let n = unsafe { ffi::BN_hex2bn(&mut p, c.as_ptr()) };
        (Self::from_ptr(p), n)
    }

    /// `BN_add_word`.
    pub fn add_word(&self, w: core::ffi::c_ulong) -> bool {
        // SAFETY: the number is live.
        unsafe { ffi::BN_add_word(self.as_ptr(), w) == 1 }
    }

    /// `BN_is_zero`.
    pub fn is_zero(&self) -> bool {
        // SAFETY: the number is live.
        unsafe { ffi::BN_is_zero(self.as_ptr()) == 1 }
    }

    /// `BN_rand(bn, bits, top, bottom)`.
    pub fn rand(&self, bits: c_int, top: c_int, bottom: c_int) -> bool {
        // SAFETY: the number is live.
        unsafe { ffi::BN_rand(self.as_ptr(), bits, top, bottom) == 1 }
    }
}
