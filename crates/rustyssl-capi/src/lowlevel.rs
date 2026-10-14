//! OpenSSL's deprecated low-level APIs (`SHA256_Init(3)`, `MD5(3)`, `AES_encrypt(3)`, ...) and
//! the block-mode helpers of `modes.h`, which OpenSSL 3 still exports. Their contexts are
//! public structs the application owns, so every call copies the struct into its mirror in
//! [`rustyssl_crypto::lowlevel`], runs there, and copies it back.
//!
//! The helpers here turn the caller's buffers into slices once, at the boundary: an input that
//! overlaps the output is copied first (which is what OpenSSL computes for one buffer), and
//! the block, CBC, and CTR functions the caller passes run through traits the core modes call.

pub(crate) mod aead;
pub(crate) mod aes;
pub(crate) mod des;
pub(crate) mod hash;
pub(crate) mod modes;

use core::cell::UnsafeCell;
use core::ffi::{c_int, c_void};
use core::ops::Deref;

use rustyssl_crypto::lowlevel::modes::{BLOCK, Block128, Cbc128, Ctr128};

use crate::mem::cleanse;

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

/// The caller's input: borrowed, or a copy (wiped when dropped) where it overlaps the output.
pub(crate) enum Input<'a> {
    /// The caller's octets.
    Borrowed(&'a [u8]),
    /// A copy of them.
    Copied(Vec<u8>),
}

impl Deref for Input<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Input::Borrowed(s) => s,
            Input::Copied(v) => v,
        }
    }
}

impl Drop for Input<'_> {
    fn drop(&mut self) {
        if let Input::Copied(v) = self {
            // SAFETY: the copy's own octets.
            unsafe { cleanse(v.as_mut_ptr().cast(), v.len()) };
        }
    }
}

/// The `in_len` octets at `input` and the `out_len` at `out`, or `None` if either is null with
/// a length. The input is copied first if the two overlap.
///
/// # Safety
/// `input` is null or valid for `in_len` octets of reads, and `out` null or valid for
/// `out_len` octets of reads and writes, for `'a`, with nothing else using them.
pub(crate) unsafe fn buffers<'a>(
    input: *const u8,
    in_len: usize,
    out: *mut u8,
    out_len: usize,
) -> Option<(Input<'a>, &'a mut [u8])> {
    if (in_len != 0 && input.is_null()) || (out_len != 0 && out.is_null()) {
        return None;
    }
    let (a, b) = (input.addr(), out.addr());
    let overlap = in_len != 0
        && out_len != 0
        && a < b.saturating_add(out_len)
        && b < a.saturating_add(in_len);
    let input = if in_len == 0 {
        Input::Borrowed(&[])
    } else {
        // SAFETY: the caller's `in_len` octets, read before any reference to the output exists.
        let s = unsafe { core::slice::from_raw_parts(input, in_len) };
        if overlap {
            Input::Copied(s.to_vec())
        } else {
            Input::Borrowed(s)
        }
    };
    let out: &mut [u8] = if out_len == 0 {
        &mut []
    } else {
        // SAFETY: the caller's `out_len` octets, which the input (copied if it overlapped)
        // doesn't share.
        unsafe { core::slice::from_raw_parts_mut(out, out_len) }
    };
    Some((input, out))
}

/// The `N` octets at `p`, or `None` for null.
///
/// # Safety
/// `p` is null or valid for `N` octets of reads.
pub(crate) unsafe fn read_array<const N: usize>(p: *const u8) -> Option<[u8; N]> {
    if p.is_null() {
        return None;
    }
    // SAFETY: the caller's `N` octets, read as octets whatever their alignment.
    Some(unsafe { p.cast::<[u8; N]>().read_unaligned() })
}

/// Writes `value` to the `N` octets at `p`.
///
/// # Safety
/// `p` is valid for `N` octets of writes.
pub(crate) unsafe fn write_array<const N: usize>(p: *mut u8, value: &[u8; N]) {
    // SAFETY: the caller's `N` octets, written as octets whatever their alignment.
    unsafe { p.cast::<[u8; N]>().write_unaligned(*value) };
}

/// A C block function and its key (`block128_f`).
pub(crate) struct CBlock {
    /// The function.
    pub(crate) f: unsafe extern "C" fn(*const u8, *mut u8, *const c_void),
    /// The key it's given.
    pub(crate) key: *const c_void,
}

impl Block128 for CBlock {
    fn block(&self, input: &[u8; BLOCK]) -> [u8; BLOCK] {
        let mut out = [0u8; BLOCK];
        // SAFETY: the caller's function with its key, a block in, and a block out.
        unsafe { (self.f)(input.as_ptr(), out.as_mut_ptr(), self.key) };
        out
    }
}

/// A C whole-buffer CBC function and its key (`cbc128_f`).
pub(crate) struct CCbc {
    /// The function.
    pub(crate) f: unsafe extern "C" fn(*const u8, *mut u8, usize, *const c_void, *mut u8, c_int),
    /// The key it's given.
    pub(crate) key: *const c_void,
}

impl Cbc128 for CCbc {
    fn cbc(&self, input: &[u8], out: &mut [u8], iv: &mut [u8; BLOCK], enc: bool) {
        if out.len() < input.len() {
            return;
        }
        // SAFETY: the caller's function with its key, the input, room for as much output, and
        // the IV.
        unsafe {
            (self.f)(
                input.as_ptr(),
                out.as_mut_ptr(),
                input.len(),
                self.key,
                iv.as_mut_ptr(),
                c_int::from(enc),
            )
        };
    }
}

/// A C whole-buffer CTR function and its key (`ctr128_f`).
pub(crate) struct CCtr {
    /// The function.
    pub(crate) f: unsafe extern "C" fn(*const u8, *mut u8, usize, *const c_void, *const u8),
    /// The key it's given.
    pub(crate) key: *const c_void,
}

impl Ctr128 for CCtr {
    fn ctr(&self, input: &[u8], out: &mut [u8], blocks: usize, iv: &[u8; BLOCK]) {
        let len = blocks.saturating_mul(BLOCK);
        if input.len() < len || out.len() < len {
            return;
        }
        // SAFETY: the caller's function with its key, `blocks` blocks in and out, and the
        // counter block.
        unsafe {
            (self.f)(
                input.as_ptr(),
                out.as_mut_ptr(),
                blocks,
                self.key,
                iv.as_ptr(),
            )
        };
    }
}
