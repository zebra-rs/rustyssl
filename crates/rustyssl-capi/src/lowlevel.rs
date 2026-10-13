//! OpenSSL's deprecated low-level APIs (`SHA256_Init(3)`, `MD5(3)`, ...), which OpenSSL 3 still
//! exports. Their contexts are public structs the application owns, so every call copies the
//! struct into its mirror in [`rustyssl_crypto::lowlevel`], runs there, and copies it back.

pub(crate) mod hash;

use core::cell::UnsafeCell;

/// A one-shot's output buffer for when it's given none: static, as OpenSSL's, so callers that
/// pass no buffer share it, and using it from several threads at once is a race, as there.
pub(crate) struct StaticMd<const N: usize>(UnsafeCell<[u8; N]>);

// SAFETY: as OpenSSL's: callers that pass no buffer share it, at their own risk.
unsafe impl<const N: usize> Sync for StaticMd<N> {}

impl<const N: usize> StaticMd<N> {
    /// A zeroed buffer.
    pub(crate) const fn new() -> Self {
        Self(UnsafeCell::new([0; N]))
    }

    /// `md`, or this buffer if `md` is null.
    pub(crate) fn or(&self, md: *mut u8) -> *mut u8 {
        if md.is_null() {
            self.0.get().cast()
        } else {
            md
        }
    }
}
