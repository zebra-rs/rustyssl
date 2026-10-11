//! The legacy CMAC API (`CMAC_Init(3)`, `cmac.c`): a `CMAC_CTX` keeps a CBC cipher context
//! and the subkeys K1 and K2 derived from the key, over the `EVP_CIPHER_CTX` functions, so any
//! CBC cipher works. The default provider's CMAC runs on it, as OpenSSL's does.
//!
//! As in OpenSSL, a context can't be used until it has a cipher and a key; `CMAC_Final` leaves
//! the state so `CMAC_resume` can continue the same MAC. A cipher whose block is larger than
//! `EVP_MAX_BLOCK_LENGTH`, which the reference would overrun its buffers with, and a NULL
//! context are refused here (docs/DEVIATIONS.md).

use core::ffi::{c_int, c_uchar, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    CMAC_CTX, ENGINE, ERR_LIB_EVP, EVP_CIPHER, EVP_CIPHER_CTX, EVP_MAX_BLOCK_LENGTH, OSSL_PARAM,
};

use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_copy, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_get_block_size,
    EVP_CIPHER_CTX_get0_cipher, EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_reset,
    EVP_CIPHER_CTX_set_key_length, EVP_Cipher, EVP_EncryptInit_ex, EVP_EncryptInit_ex2,
};
use crate::ffi::ffi_export;
use crate::mem::{self, OPENSSL_cleanse};

const BLOCK: usize = EVP_MAX_BLOCK_LENGTH as usize;
/// `LOCAL_BUF_SIZE`: how much `CMAC_Update` enciphers at once.
const LOCAL_BUF_SIZE: usize = 2048;
/// An all-zero IV.
static ZERO_IV: [u8; BLOCK] = [0; BLOCK];

/// What a `CMAC_CTX *` points to (`struct CMAC_CTX_st`).
#[repr(C)]
struct Cmac {
    cctx: *mut EVP_CIPHER_CTX,
    k1: [u8; BLOCK],
    k2: [u8; BLOCK],
    /// The last block enciphered (the CBC chain's value).
    tbl: [u8; BLOCK],
    /// The last, possibly partial, block of input.
    last_block: [u8; BLOCK],
    /// The octets in `last_block`; -1 until the context has a key.
    nlast_block: c_int,
}

/// Zeroes `b` (`OPENSSL_cleanse`).
fn wipe(b: &mut [u8]) {
    // SAFETY: the slice's own octets.
    unsafe { OPENSSL_cleanse(b.as_mut_ptr().cast(), b.len()) };
}

impl Cmac {
    /// The cipher's block size, if it's one the buffers hold (0 included).
    fn block_size(&self) -> Option<usize> {
        // SAFETY: the context's own cipher context.
        let bl = unsafe { EVP_CIPHER_CTX_get_block_size(self.cctx) };
        usize::try_from(bl).ok().filter(|&b| b <= BLOCK)
    }

    /// `EVP_Cipher` of `len` octets from `in_` to `out`: true for success.
    ///
    /// # Safety
    /// `in_` holds and `out` has room for `len` octets.
    unsafe fn encipher(&self, out: *mut u8, in_: *const u8, len: usize) -> bool {
        let Ok(len) = c_uint::try_from(len) else {
            return false;
        };
        // SAFETY: the context's own cipher context; the caller's buffers.
        unsafe { EVP_Cipher(self.cctx, out, in_, len) > 0 }
    }
}

/// `make_kn`: the subkey from `l` (`bl` octets), a doubling in GF(2^bl*8).
fn make_kn(k: &mut [u8; BLOCK], l: &[u8; BLOCK], bl: usize) {
    let r = if bl == 16 { 0x87 } else { 0x1b };
    let carry = l.first().map_or(0, |b| b >> 7);
    let last = bl.saturating_sub(1);
    for (kb, w) in k.iter_mut().zip(l.windows(2)).take(last) {
        if let &[a, b] = w {
            *kb = (a << 1) | (b >> 7);
        }
    }
    // Constant-time: the reduction is masked in, not branched on.
    if let (Some(kb), Some(&lb)) = (k.get_mut(last), l.get(last)) {
        *kb = (lb << 1) ^ (0u8.wrapping_sub(carry) & r);
    }
}

/// The first `n` octets of `b` (all of it, should `n` exceed it).
fn head(b: &mut [u8], n: usize) -> &mut [u8] {
    let n = n.min(b.len());
    b.split_at_mut(n).0
}

/// The context behind `ctx`, or `None` for NULL.
///
/// # Safety
/// `ctx` is NULL or a live context from `CMAC_CTX_new`, not used elsewhere meanwhile.
unsafe fn context<'a>(ctx: *mut CMAC_CTX) -> Option<&'a mut Cmac> {
    // SAFETY: the caller's guarantee: an allocation of a `Cmac`, any bit pattern of which is
    // valid.
    unsafe { ctx.cast::<Cmac>().as_mut() }
}

ffi_export! {
    /// A new context, with a cipher context and neither cipher nor key, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn CMAC_CTX_new() -> *mut CMAC_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        let ctx = mem::alloc_zeroed(size_of::<Cmac>()).cast::<CMAC_CTX>();
        // SAFETY: the allocation just made, or NULL.
        let Some(c) = (unsafe { context(ctx) }) else { return ptr::null_mut() };
        // SAFETY: no preconditions.
        c.cctx = unsafe { EVP_CIPHER_CTX_new() };
        if c.cctx.is_null() {
            // SAFETY: the allocation just made.
            unsafe { mem::release(ctx.cast()) };
            return ptr::null_mut();
        }
        c.nlast_block = -1;
        ctx
    }
}

/// `CMAC_CTX_cleanup` on the context itself.
fn cleanup(c: &mut Cmac) {
    // SAFETY: the context's own cipher context.
    unsafe { EVP_CIPHER_CTX_reset(c.cctx) };
    wipe(&mut c.tbl);
    wipe(&mut c.k1);
    wipe(&mut c.k2);
    wipe(&mut c.last_block);
    c.nlast_block = -1;
}

ffi_export! {
    /// Clears the context: cipher, key, and state gone.
    ///
    /// # Safety
    /// `ctx` is NULL or a live CMAC context.
    pub unsafe extern "C" fn CMAC_CTX_cleanup(ctx: *mut CMAC_CTX)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { context(ctx) } {
            cleanup(c);
        }
    }
}

ffi_export! {
    /// The context's cipher context (NULL for NULL).
    ///
    /// # Safety
    /// `ctx` is NULL or a live CMAC context.
    pub unsafe extern "C" fn CMAC_CTX_get0_cipher_ctx(ctx: *mut CMAC_CTX) -> *mut EVP_CIPHER_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { context(ctx) }.map_or(ptr::null_mut(), |c| c.cctx)
    }
}

ffi_export! {
    /// Clears and frees the context; NULL does nothing.
    ///
    /// # Safety
    /// `ctx` is NULL or a live CMAC context, not used afterwards.
    pub unsafe extern "C" fn CMAC_CTX_free(ctx: *mut CMAC_CTX)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return };
        cleanup(c);
        // SAFETY: the context's own cipher context, not used again.
        unsafe { EVP_CIPHER_CTX_free(c.cctx) };
        // SAFETY: the context's allocation, from `CMAC_CTX_new`.
        unsafe { mem::release(ctx.cast()) };
    }
}

ffi_export! {
    /// Copies `in_`, which must have a key, into `out`. Returns 1, or 0.
    ///
    /// # Safety
    /// `out` and `in_` are NULL or live CMAC contexts.
    pub unsafe extern "C" fn CMAC_CTX_copy(out: *mut CMAC_CTX, in_: *const CMAC_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { in_.cast::<Cmac>().as_ref() }) else { return 0 };
        if s.nlast_block == -1 {
            return 0;
        }
        let Some(bl) = s.block_size().filter(|&b| b > 0) else { return 0 };
        let (scctx, k1, k2, tbl, last, n) = (s.cctx, s.k1, s.k2, s.tbl, s.last_block, s.nlast_block);
        if out.cast_const() == in_ {
            // The reference copies the cipher context onto itself.
            // SAFETY: the context's own cipher context.
            return unsafe { EVP_CIPHER_CTX_copy(scctx, scctx) };
        }
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { context(out) }) else { return 0 };
        // SAFETY: the two contexts' cipher contexts.
        if unsafe { EVP_CIPHER_CTX_copy(d.cctx, scctx) } == 0 {
            return 0;
        }
        for (dst, src) in [(&mut d.k1, &k1), (&mut d.k2, &k2), (&mut d.tbl, &tbl), (&mut d.last_block, &last)] {
            head(dst, bl).copy_from_slice(src.get(..bl).unwrap_or_default());
        }
        d.nlast_block = n;
        1
    }
}

/// `ossl_cmac_init`: (re)starts the MAC, with `cipher` (and `impl_`) and `keylen` octets of
/// `key` where given, or, all absent, again under the key it has. Returns 1, or 0.
///
/// # Safety
/// `ctx` is NULL or a live CMAC context; `key` is NULL or holds `keylen` octets; `cipher` is
/// NULL or a live cipher; `params` is NULL or a parameter array.
pub(crate) unsafe fn cmac_init(
    ctx: *mut CMAC_CTX,
    key: *const c_void,
    keylen: usize,
    cipher: *const EVP_CIPHER,
    impl_: *mut ENGINE,
    params: *const OSSL_PARAM,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { context(ctx) }) else {
        return 0;
    };
    // All absent means restart.
    if key.is_null() && cipher.is_null() && impl_.is_null() && keylen == 0 {
        if c.nlast_block == -1 {
            return 0;
        }
        // SAFETY: the context's own cipher context; a static IV.
        if unsafe {
            EVP_EncryptInit_ex2(c.cctx, ptr::null(), ptr::null(), ZERO_IV.as_ptr(), params)
        } == 0
        {
            return 0;
        }
        let Some(bl) = c.block_size().filter(|&b| b > 0) else {
            return 0;
        };
        head(&mut c.tbl, bl).fill(0);
        c.nlast_block = 0;
        return 1;
    }
    if !cipher.is_null() {
        // Not usable until it has a key too.
        c.nlast_block = -1;
        let ok = if impl_.is_null() {
            // SAFETY: the context's own cipher context; the caller's cipher and parameters.
            unsafe { EVP_EncryptInit_ex2(c.cctx, cipher, ptr::null(), ptr::null(), params) }
        } else {
            // SAFETY: as above, with the caller's engine.
            unsafe { EVP_EncryptInit_ex(c.cctx, cipher, impl_, ptr::null(), ptr::null()) }
        };
        if ok == 0 {
            return 0;
        }
    }
    if !key.is_null() {
        // Unusable if anything fails.
        c.nlast_block = -1;
        // SAFETY: the context's own cipher context.
        if unsafe { EVP_CIPHER_CTX_get0_cipher(c.cctx) }.is_null() {
            return 0;
        }
        // C's conversion of the length to `int`: the low 32 bits.
        let len = u32::try_from(keylen & 0xffff_ffff)
            .unwrap_or(0)
            .cast_signed();
        // SAFETY: the context's own cipher context.
        if unsafe { EVP_CIPHER_CTX_set_key_length(c.cctx, len) } <= 0 {
            return 0;
        }
        // SAFETY: the context's own cipher context; the caller's key; a static IV.
        if unsafe { EVP_EncryptInit_ex2(c.cctx, ptr::null(), key.cast(), ZERO_IV.as_ptr(), params) }
            == 0
        {
            return 0;
        }
        // A block larger than the buffers: the reference would overrun them.
        let Some(bl) = c.block_size() else { return 0 };
        let tbl = c.tbl.as_mut_ptr();
        // SAFETY: a block of zeroes into the context's own block buffer.
        if !unsafe { c.encipher(tbl, ZERO_IV.as_ptr(), bl) } {
            return 0;
        }
        make_kn(&mut c.k1, &c.tbl, bl);
        let k1 = c.k1;
        make_kn(&mut c.k2, &k1, bl);
        wipe(head(&mut c.tbl, bl));
        // Ready for the first block.
        // SAFETY: as above.
        if unsafe {
            EVP_EncryptInit_ex2(c.cctx, ptr::null(), ptr::null(), ZERO_IV.as_ptr(), params)
        } == 0
        {
            return 0;
        }
        head(&mut c.tbl, bl).fill(0);
        c.nlast_block = 0;
    }
    1
}

ffi_export! {
    /// `cmac_init` without parameters.
    ///
    /// # Safety
    /// As for `cmac_init`.
    pub unsafe extern "C" fn CMAC_Init(ctx: *mut CMAC_CTX, key: *const c_void, keylen: usize, cipher: *const EVP_CIPHER, impl_: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { cmac_init(ctx, key, keylen, cipher, impl_, ptr::null()) }
    }
}

ffi_export! {
    /// Adds `dlen` octets of `in_`. Returns 1, or 0 (with no key).
    ///
    /// # Safety
    /// `ctx` is NULL or a live CMAC context; `in_` holds `dlen` octets.
    pub unsafe extern "C" fn CMAC_Update(ctx: *mut CMAC_CTX, in_: *const c_void, dlen: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        if c.nlast_block == -1 {
            return 0;
        }
        if dlen == 0 {
            return 1;
        }
        let Some(bl) = c.block_size().filter(|&b| b > 0) else { return 0 };
        // SAFETY: the caller's guarantee.
        let mut data = unsafe { core::slice::from_raw_parts(in_.cast::<u8>(), dlen) };
        let Ok(mut n) = usize::try_from(c.nlast_block) else { return 0 };
        // Fill a partial block first.
        if n > 0 {
            let nleft = bl.saturating_sub(n).min(data.len());
            let Some(dst) = c.last_block.get_mut(n..n + nleft) else { return 0 };
            let (head, rest) = data.split_at(nleft);
            dst.copy_from_slice(head);
            n += nleft;
            c.nlast_block = c_int::try_from(n).unwrap_or(-1);
            if rest.is_empty() {
                return 1;
            }
            data = rest;
            let (tbl, last) = (c.tbl.as_mut_ptr(), c.last_block.as_ptr());
            // SAFETY: a block from and into the context's own buffers.
            if !unsafe { c.encipher(tbl, last, bl) } {
                return 0;
            }
        }
        // Every complete block but the last, a buffer's worth at a time.
        let mut buf = [0u8; LOCAL_BUF_SIZE];
        let max_burst = LOCAL_BUF_SIZE / bl;
        let mut blocks = (data.len() - 1) / bl;
        while blocks > 0 {
            let now = blocks.min(max_burst);
            let len = now * bl;
            // SAFETY: `len` octets of the input, into the buffer, which holds them.
            if !unsafe { c.encipher(buf.as_mut_ptr(), data.as_ptr(), len) } {
                return 0;
            }
            data = data.get(len..).unwrap_or_default();
            blocks -= now;
            if blocks == 0 {
                let last = buf.get(len - bl..len).unwrap_or_default();
                head(&mut c.tbl, bl).copy_from_slice(last);
            }
        }
        wipe(&mut buf);
        // The rest (one block at most) waits for more, or the final.
        head(&mut c.last_block, data.len()).copy_from_slice(data);
        c.nlast_block = c_int::try_from(data.len()).unwrap_or(-1);
        1
    }
}

ffi_export! {
    /// Writes the MAC (a block) to `out`, its length to `*poutlen`; with NULL `out`, just the
    /// length. Returns 1, or 0. The context can be resumed afterwards.
    ///
    /// # Safety
    /// `ctx` is NULL or a live CMAC context; `out` is NULL or has room for a block; `poutlen`
    /// is NULL or valid for a write.
    pub unsafe extern "C" fn CMAC_Final(ctx: *mut CMAC_CTX, out: *mut c_uchar, poutlen: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        if c.nlast_block == -1 {
            return 0;
        }
        let Some(bl) = c.block_size().filter(|&b| b > 0) else { return 0 };
        if !poutlen.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { poutlen.write(bl) };
        }
        if out.is_null() {
            return 1;
        }
        let Ok(lb) = usize::try_from(c.nlast_block) else { return 0 };
        let mut block = [0u8; BLOCK];
        let k = if lb == bl {
            &c.k1
        } else {
            let Some(rest) = c.last_block.get_mut(lb..bl) else { return 0 };
            if let Some((first, zeros)) = rest.split_first_mut() {
                *first = 0x80;
                zeros.fill(0);
            }
            &c.k2
        };
        for ((o, a), b) in block.iter_mut().zip(c.last_block.iter()).zip(k.iter()).take(bl) {
            *o = a ^ b;
        }
        // SAFETY: the caller's guarantee: room for a block at `out`.
        let out = unsafe { core::slice::from_raw_parts_mut(out, bl) };
        out.copy_from_slice(head(&mut block, bl));
        wipe(&mut block);
        // SAFETY: a block in place, in the caller's buffer.
        if !unsafe { c.encipher(out.as_mut_ptr(), out.as_ptr(), bl) } {
            wipe(out);
            return 0;
        }
        1
    }
}

ffi_export! {
    /// Continues the MAC after `CMAC_Final`, as if it hadn't been called. Returns 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live CMAC context.
    pub unsafe extern "C" fn CMAC_resume(ctx: *mut CMAC_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        if c.nlast_block == -1 {
            return 0;
        }
        // The last block enciphered is the IV to go on from.
        // SAFETY: the context's own cipher context and block buffer.
        unsafe { EVP_EncryptInit_ex(c.cctx, ptr::null(), ptr::null_mut(), ptr::null(), c.tbl.as_ptr()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: a NULL context is refused (the reference crashes).
    #[test]
    fn null_contexts_are_refused() {
        let mut out = [0u8; 32];
        let mut len = 0usize;
        let null = ptr::null_mut();
        // SAFETY: NULL is the case under test, here and below.
        let r = unsafe { CMAC_Init(null, ptr::null(), 0, ptr::null(), ptr::null_mut()) };
        assert_eq!(r, 0);
        // SAFETY: as above; one octet of the buffer.
        assert_eq!(unsafe { CMAC_Update(null, out.as_ptr().cast(), 1) }, 0);
        // SAFETY: as above; the buffers above.
        let r = unsafe { CMAC_Final(null, out.as_mut_ptr(), &raw mut len) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { CMAC_resume(null) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { CMAC_CTX_copy(null, ptr::null()) }, 0);
        // SAFETY: as above.
        assert!(unsafe { CMAC_CTX_get0_cipher_ctx(null) }.is_null());
        // SAFETY: as above.
        unsafe { CMAC_CTX_cleanup(null) };
        // SAFETY: as above.
        unsafe { CMAC_CTX_free(null) };
    }

    /// The subkeys of RFC 4493 (section 4), from L = AES-128(K, 0).
    #[test]
    fn subkeys() {
        let mut l = [0u8; BLOCK];
        let mut k1 = [0u8; BLOCK];
        let mut k2 = [0u8; BLOCK];
        l[..16].copy_from_slice(&[
            0x7d, 0xf7, 0x6b, 0x0c, 0x1a, 0xb8, 0x99, 0xb3, 0x3e, 0x42, 0xf0, 0x47, 0xb9, 0x1b,
            0x54, 0x6f,
        ]);
        make_kn(&mut k1, &l, 16);
        make_kn(&mut k2, &k1, 16);
        assert_eq!(
            k1[..16],
            [
                0xfb, 0xee, 0xd6, 0x18, 0x35, 0x71, 0x33, 0x66, 0x7c, 0x85, 0xe0, 0x8f, 0x72, 0x36,
                0xa8, 0xde
            ]
        );
        assert_eq!(
            k2[..16],
            [
                0xf7, 0xdd, 0xac, 0x30, 0x6a, 0xe2, 0x66, 0xcc, 0xf9, 0x0b, 0xc1, 0x1e, 0xe4, 0x6d,
                0x51, 0x3b
            ]
        );
    }
}
