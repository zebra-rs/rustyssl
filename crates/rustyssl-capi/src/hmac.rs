//! The legacy HMAC API (`HMAC(3)`, `hmac.c`): an `HMAC_CTX` keeps the digest and three digest
//! contexts (the running one, and the inner and outer pads' starts), over the `EVP_MD_CTX`
//! functions, so any digest works. The default provider's HMAC runs on it, as OpenSSL's does.
//! `HMAC()` is the one-shot, through `EVP_Q_mac`.
//!
//! The functions given a NULL context fail here where the reference would crash
//! (docs/DEVIATIONS.md).

use core::cell::UnsafeCell;
use core::ffi::{c_int, c_uchar, c_uint, c_ulong, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_EVP, EVP_MAX_MD_SIZE, EVP_MD, EVP_MD_CTX, HMAC_CTX, HMAC_MAX_MD_CBLOCK,
};

use crate::evp::digest::{EVP_MD_get_block_size, EVP_MD_get_size, EVP_MD_get0_name};
use crate::evp::mac::EVP_Q_mac;
use crate::evp::md_ctx::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_copy_ex, EVP_MD_CTX_free,
    EVP_MD_CTX_new, EVP_MD_CTX_reset, EVP_MD_CTX_set_flags, EVP_MD_xof,
};
use crate::ffi::ffi_export;
use crate::mem::{self, OPENSSL_cleanse};

/// `HMAC_MAX_MD_CBLOCK_SIZE`, the pads' room.
const CBLOCK: usize = HMAC_MAX_MD_CBLOCK as usize;

/// What an `HMAC_CTX *` points to (`struct hmac_ctx_st`): every field is valid zeroed.
#[repr(C)]
struct Hmac {
    md: *const EVP_MD,
    md_ctx: *mut EVP_MD_CTX,
    i_ctx: *mut EVP_MD_CTX,
    o_ctx: *mut EVP_MD_CTX,
}

impl Hmac {
    /// `hmac_ctx_cleanup`.
    fn cleanup(&mut self) {
        for c in [self.i_ctx, self.o_ctx, self.md_ctx] {
            // SAFETY: a context of ours, or NULL.
            unsafe { EVP_MD_CTX_reset(c) };
        }
        self.md = ptr::null();
    }

    /// `hmac_ctx_alloc_mds`: the three digest contexts, made where missing.
    fn alloc(&mut self) -> bool {
        for c in [&mut self.i_ctx, &mut self.o_ctx, &mut self.md_ctx] {
            if c.is_null() {
                // SAFETY: no preconditions.
                *c = unsafe { EVP_MD_CTX_new() };
            }
            if c.is_null() {
                return false;
            }
        }
        true
    }

    /// Frees the digest contexts.
    fn free_mds(&mut self) {
        for c in [&mut self.i_ctx, &mut self.o_ctx, &mut self.md_ctx] {
            // SAFETY: a context of ours, or NULL.
            unsafe { EVP_MD_CTX_free(*c) };
            *c = ptr::null_mut();
        }
    }
}

/// The context behind `ctx`, or `None` for NULL.
///
/// # Safety
/// `ctx` is NULL or a live context from `HMAC_CTX_new`, not used elsewhere meanwhile.
unsafe fn context<'a>(ctx: *mut HMAC_CTX) -> Option<&'a mut Hmac> {
    // SAFETY: the caller's guarantee: an allocation of an `Hmac`, any bit pattern of which is
    // valid.
    unsafe { ctx.cast::<Hmac>().as_mut() }
}

/// As [`context`], shared.
///
/// # Safety
/// As for [`context`].
unsafe fn context_ref<'a>(ctx: *const HMAC_CTX) -> Option<&'a Hmac> {
    // SAFETY: the caller's guarantee.
    unsafe { ctx.cast::<Hmac>().as_ref() }
}

/// Zeroes `b` (`OPENSSL_cleanse`).
fn wipe(b: &mut [u8]) {
    // SAFETY: the slice's own octets.
    unsafe { OPENSSL_cleanse(b.as_mut_ptr().cast(), b.len()) };
}

ffi_export! {
    /// A new context with its three digest contexts, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn HMAC_CTX_new() -> *mut HMAC_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        let ctx = mem::alloc_zeroed(size_of::<Hmac>()).cast::<HMAC_CTX>();
        // SAFETY: a context made here.
        if !ctx.is_null() && unsafe { HMAC_CTX_reset(ctx) } == 0 {
            // SAFETY: as above.
            unsafe { HMAC_CTX_free(ctx) };
            return ptr::null_mut();
        }
        ctx
    }
}

ffi_export! {
    /// Frees the context; NULL does nothing.
    ///
    /// # Safety
    /// `ctx` is NULL or a live HMAC context, not used afterwards.
    pub unsafe extern "C" fn HMAC_CTX_free(ctx: *mut HMAC_CTX)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(h) = (unsafe { context(ctx) }) else { return };
        h.cleanup();
        h.free_mds();
        // SAFETY: the context's allocation, from `HMAC_CTX_new`.
        unsafe { mem::release(ctx.cast()) };
    }
}

ffi_export! {
    /// Clears the context (digest and key gone), ready for `HMAC_Init_ex`. Returns 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live HMAC context.
    pub unsafe extern "C" fn HMAC_CTX_reset(ctx: *mut HMAC_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(h) = (unsafe { context(ctx) }) else { return 0 };
        h.cleanup();
        if !h.alloc() {
            h.cleanup();
            return 0;
        }
        1
    }
}

ffi_export! {
    /// Starts an HMAC: with `md` (which, if it changes, needs a key) and `len` octets of `key`
    /// (keeping the old key for NULL), or else again with the digest and key it has. Returns 1,
    /// or 0. An extendable-output digest is refused.
    ///
    /// # Safety
    /// `ctx` is NULL or a live HMAC context; `key` is NULL or holds `len` octets; `md` is NULL
    /// or a live digest; `impl_` is NULL.
    pub unsafe extern "C" fn HMAC_Init_ex(ctx: *mut HMAC_CTX, key: *const c_void, len: c_int, md: *const EVP_MD, impl_: *mut rustyssl_abi::ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(h) = (unsafe { context(ctx) }) else { return 0 };
        // Changing the digest needs a key.
        if !md.is_null() && md != h.md && (key.is_null() || len < 0) {
            return 0;
        }
        let md = if !md.is_null() {
            h.md = md;
            md
        } else if !h.md.is_null() {
            h.md
        } else {
            return 0;
        };
        // SAFETY: a live digest.
        if unsafe { EVP_MD_xof(md) } != 0 {
            return 0;
        }
        let mut keytmp = [0u8; CBLOCK];
        let mut pad = [0u8; CBLOCK];
        let mut rv = 0;
        'out: {
            if !key.is_null() {
                // SAFETY: a live digest.
                let j = unsafe { EVP_MD_get_block_size(md) };
                let Ok(block) = usize::try_from(j) else { break 'out };
                if block > CBLOCK {
                    break 'out;
                }
                let mut keytmp_length: c_uint = 0;
                if j < len {
                    let Ok(n) = usize::try_from(len) else { break 'out };
                    // SAFETY: the context's digest context; the caller's key of `len` octets;
                    // room for any digest.
                    let ok = unsafe { EVP_DigestInit_ex(h.md_ctx, md, impl_) } != 0
                        // SAFETY: as above.
                        && unsafe { EVP_DigestUpdate(h.md_ctx, key, n) } != 0
                        // SAFETY: as above.
                        && unsafe { EVP_DigestFinal_ex(h.md_ctx, keytmp.as_mut_ptr(), &raw mut keytmp_length) } != 0;
                    if !ok {
                        break 'out;
                    }
                } else {
                    let Ok(n) = usize::try_from(len) else { break 'out };
                    if n > CBLOCK {
                        break 'out;
                    }
                    // SAFETY: the caller's key of `len` octets, into room for `CBLOCK`.
                    unsafe { ptr::copy_nonoverlapping(key.cast::<u8>(), keytmp.as_mut_ptr(), n) };
                }
                // (The rest of `keytmp` is already zero.)
                for (p, k) in pad.iter_mut().zip(keytmp.iter()) {
                    *p = 0x36 ^ k;
                }
                // SAFETY: the inner context; the pad's first `block` octets.
                let ok = unsafe { EVP_DigestInit_ex(h.i_ctx, md, impl_) } != 0
                    // SAFETY: as above.
                    && unsafe { EVP_DigestUpdate(h.i_ctx, pad.as_ptr().cast(), block) } != 0;
                if !ok {
                    break 'out;
                }
                for (p, k) in pad.iter_mut().zip(keytmp.iter()) {
                    *p = 0x5c ^ k;
                }
                // SAFETY: the outer context, likewise.
                let ok = unsafe { EVP_DigestInit_ex(h.o_ctx, md, impl_) } != 0
                    // SAFETY: as above.
                    && unsafe { EVP_DigestUpdate(h.o_ctx, pad.as_ptr().cast(), block) } != 0;
                if !ok {
                    break 'out;
                }
            }
            // SAFETY: the context's own digest contexts.
            if unsafe { EVP_MD_CTX_copy_ex(h.md_ctx, h.i_ctx) } == 0 {
                break 'out;
            }
            rv = 1;
        }
        wipe(&mut keytmp);
        wipe(&mut pad);
        rv
    }
}

ffi_export! {
    /// `HMAC_Init_ex` without an engine, clearing the context first when given a key and a
    /// digest.
    ///
    /// # Safety
    /// As for `HMAC_Init_ex`.
    pub unsafe extern "C" fn HMAC_Init(ctx: *mut HMAC_CTX, key: *const c_void, len: c_int, md: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if !key.is_null() && !md.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { HMAC_CTX_reset(ctx) };
        }
        // SAFETY: the caller's guarantee.
        unsafe { HMAC_Init_ex(ctx, key, len, md, ptr::null_mut()) }
    }
}

ffi_export! {
    /// Adds `len` octets of `data`. Returns 1, or 0 (with no digest).
    ///
    /// # Safety
    /// `ctx` is NULL or a live HMAC context; `data` holds `len` octets.
    pub unsafe extern "C" fn HMAC_Update(ctx: *mut HMAC_CTX, data: *const c_uchar, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(h) = (unsafe { context(ctx) }) else { return 0 };
        if h.md.is_null() {
            return 0;
        }
        // SAFETY: the context's digest context; the caller's data.
        unsafe { EVP_DigestUpdate(h.md_ctx, data.cast(), len) }
    }
}

ffi_export! {
    /// Writes the HMAC to `md`, its length to `*len`. Returns 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live HMAC context; `md` has room for the digest's size; `len` is NULL
    /// or valid for a write.
    pub unsafe extern "C" fn HMAC_Final(ctx: *mut HMAC_CTX, md: *mut c_uchar, len: *mut c_uint) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(h) = (unsafe { context(ctx) }) else { return 0 };
        if h.md.is_null() {
            return 0;
        }
        let mut buf = [0u8; EVP_MAX_MD_SIZE as usize];
        let mut i: c_uint = 0;
        // SAFETY: the context's digest contexts; room for any digest; the caller's `md`, `len`.
        let ok = unsafe { EVP_DigestFinal_ex(h.md_ctx, buf.as_mut_ptr(), &raw mut i) } != 0
            // SAFETY: as above.
            && unsafe { EVP_MD_CTX_copy_ex(h.md_ctx, h.o_ctx) } != 0
            // SAFETY: as above.
            && unsafe { EVP_DigestUpdate(h.md_ctx, buf.as_ptr().cast(), i as usize) } != 0
            // SAFETY: as above.
            && unsafe { EVP_DigestFinal_ex(h.md_ctx, md, len) } != 0;
        wipe(&mut buf);
        c_int::from(ok)
    }
}

ffi_export! {
    /// The digest's size (0 for none).
    ///
    /// # Safety
    /// `ctx` is NULL or a live HMAC context.
    pub unsafe extern "C" fn HMAC_size(ctx: *const HMAC_CTX) -> usize
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(h) = (unsafe { context_ref(ctx) }) else { return 0 };
        // SAFETY: the context's digest, or NULL.
        let size = unsafe { EVP_MD_get_size(h.md) };
        usize::try_from(size).unwrap_or(0)
    }
}

ffi_export! {
    /// Copies `sctx` into `dctx`. Returns 1, or 0 (leaving `dctx` cleared).
    ///
    /// # Safety
    /// `dctx` and `sctx` are NULL or live HMAC contexts.
    pub unsafe extern "C" fn HMAC_CTX_copy(dctx: *mut HMAC_CTX, sctx: *mut HMAC_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if dctx == sctx && !dctx.is_null() {
            // Copying onto itself: each digest context copies onto itself.
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { context_ref(sctx) }) else { return 0 };
        let (si, so, sm, smd) = (s.i_ctx, s.o_ctx, s.md_ctx, s.md);
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { context(dctx) }) else { return 0 };
        let ok = d.alloc()
            // SAFETY: the two contexts' digest contexts.
            && unsafe { EVP_MD_CTX_copy_ex(d.i_ctx, si) } != 0
            // SAFETY: as above.
            && unsafe { EVP_MD_CTX_copy_ex(d.o_ctx, so) } != 0
            // SAFETY: as above.
            && unsafe { EVP_MD_CTX_copy_ex(d.md_ctx, sm) } != 0;
        if !ok {
            d.cleanup();
            return 0;
        }
        d.md = smd;
        1
    }
}

ffi_export! {
    /// Sets `flags` on the three digest contexts (as an `int`, as OpenSSL passes them).
    ///
    /// # Safety
    /// `ctx` is NULL or a live HMAC context.
    pub unsafe extern "C" fn HMAC_CTX_set_flags(ctx: *mut HMAC_CTX, flags: c_ulong)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(h) = (unsafe { context(ctx) }) else { return };
        // C's conversion to `int`: the low 32 bits.
        let f = u32::try_from(flags & 0xffff_ffff).unwrap_or(0).cast_signed();
        for c in [h.i_ctx, h.o_ctx, h.md_ctx] {
            // SAFETY: a context of ours.
            unsafe { EVP_MD_CTX_set_flags(c, f) };
        }
    }
}

ffi_export! {
    /// The context's digest, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live HMAC context.
    pub unsafe extern "C" fn HMAC_CTX_get_md(ctx: *const HMAC_CTX) -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { context_ref(ctx) }.map_or(ptr::null(), |h| h.md)
    }
}

/// `HMAC()`'s buffer when given none: static, as OpenSSL's, so not thread-safe to use.
struct StaticMd(UnsafeCell<[u8; EVP_MAX_MD_SIZE as usize]>);

// SAFETY: as OpenSSL's: callers that pass no buffer share it, at their own risk.
unsafe impl Sync for StaticMd {}

static STATIC_MD: StaticMd = StaticMd(UnsafeCell::new([0; EVP_MAX_MD_SIZE as usize]));

ffi_export! {
    /// The HMAC with `evp_md` of `data_len` octets of `data` under `key_len` octets of `key`,
    /// into `md` (a static buffer, shared by every such call, for NULL); its length through
    /// `*md_len`. Returns the HMAC's address, or NULL.
    ///
    /// # Safety
    /// `evp_md` is NULL or a live digest; `key` and `data` hold their lengths; `md` is NULL or
    /// has room for the digest's size; `md_len` is NULL or valid for a write.
    pub unsafe extern "C" fn HMAC(evp_md: *const EVP_MD, key: *const c_void, key_len: c_int, data: *const c_uchar, data_len: usize, md: *mut c_uchar, md_len: *mut c_uint) -> *mut c_uchar
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let size = unsafe { EVP_MD_get_size(evp_md) };
        let Ok(size) = usize::try_from(size) else { return ptr::null_mut() };
        if size == 0 {
            return ptr::null_mut();
        }
        let out = if md.is_null() { STATIC_MD.0.get().cast::<c_uchar>() } else { md };
        let mut len = 0usize;
        // A negative key length is the huge `size_t` it converts to, as in C.
        let keylen = isize::try_from(key_len).unwrap_or(0).cast_unsigned();
        // SAFETY: the caller's digest.
        let name = unsafe { EVP_MD_get0_name(evp_md) };
        // SAFETY: the default context; a static name; the digest's name; the caller's key,
        // data, and room (or the static buffer, of the largest digest's size).
        let ret = unsafe {
            EVP_Q_mac(ptr::null_mut(), c"HMAC".as_ptr(), ptr::null(), name, ptr::null(), key, keylen, data, data_len, out, size, &raw mut len)
        };
        if !md_len.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { md_len.write(u32::try_from(len).unwrap_or(0)) };
        }
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: a NULL context is refused (the reference crashes).
    #[test]
    fn null_contexts_are_refused() {
        let mut out = [0u8; 64];
        let mut len: c_uint = 0;
        let null = ptr::null_mut();
        // SAFETY: NULL is the case under test, here and below.
        let r =
            unsafe { HMAC_Init_ex(null, b"k".as_ptr().cast(), 1, ptr::null(), ptr::null_mut()) };
        assert_eq!(r, 0);
        // SAFETY: as above; one octet of the buffer.
        assert_eq!(unsafe { HMAC_Update(null, out.as_ptr(), 1) }, 0);
        // SAFETY: as above; the buffers above.
        let r = unsafe { HMAC_Final(null, out.as_mut_ptr(), &raw mut len) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { HMAC_size(null) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { HMAC_CTX_reset(null) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { HMAC_CTX_copy(null, null) }, 0);
        // SAFETY: no preconditions.
        let ctx = unsafe { HMAC_CTX_new() };
        // SAFETY: the context, and NULL.
        assert_eq!(unsafe { HMAC_CTX_copy(ctx, null) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { HMAC_CTX_copy(null, ctx) }, 0);
        // SAFETY: the test's context.
        unsafe { HMAC_CTX_free(ctx) };
        // SAFETY: as above.
        assert!(unsafe { HMAC_CTX_get_md(null) }.is_null());
        // SAFETY: as above.
        unsafe { HMAC_CTX_set_flags(null, 0) };
        // SAFETY: as above.
        unsafe { HMAC_CTX_free(null) };
    }
}
