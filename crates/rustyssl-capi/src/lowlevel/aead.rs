//! The AEAD helpers of `modes.h`: `CRYPTO_gcm128_*`, `CRYPTO_ccm128_*`, `CRYPTO_ocb128_*`,
//! and `CRYPTO_xts128_encrypt`, over [`rustyssl_crypto::lowlevel::aead`] with the block (and
//! bulk) functions the caller passes.
//!
//! A GCM or OCB context comes only from `CRYPTO_gcm128_new` or `CRYPTO_ocb128_new`, so its
//! layout is ours: the functions and keys, then the state, all in one block from the OpenSSL
//! allocator (an application frees an OCB context with `OPENSSL_free` after
//! `CRYPTO_ocb128_cleanup`), with nothing allocated beside it. CCM and XTS contexts have no
//! constructor: an application can only lay them out as OpenSSL's `modes_local.h` does, so
//! these mirror that layout (it isn't in the public headers, so it can't be generated).
//!
//! Where OpenSSL dereferences a null context, buffer, or function and crashes, these return 0
//! or -1 (null from a constructor) or do nothing (docs/DEVIATIONS.md).

use core::ffi::{c_int, c_uchar, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    CCM128_CONTEXT, ERR_LIB_CRYPTO, GCM128_CONTEXT, OCB128_CONTEXT, XTS128_CONTEXT, block128_f,
    ccm128_f, ctr128_f, ocb128_f,
};
use rustyssl_crypto::lowlevel::aead::{self, Ccm, Ccm128, Gcm, OCB_MAX_L, Ocb, Ocb128};
use rustyssl_crypto::lowlevel::modes::BLOCK;

use super::{CBlock, CCtr, buffers, read_array};
use crate::ffi::{bytes, ffi_export};
use crate::mem;

/// What a `GCM128_CONTEXT *` points to: the block function and its key, then the state.
#[repr(C)]
struct GcmCtx {
    block: unsafe extern "C" fn(*const u8, *mut u8, *const c_void),
    key: *const c_void,
    state: Gcm,
}

impl GcmCtx {
    fn block(&self) -> CBlock {
        CBlock {
            f: self.block,
            key: self.key,
        }
    }
}

/// The context behind a `GCM128_CONTEXT *`.
///
/// # Safety
/// `ctx` is null or from `CRYPTO_gcm128_new`, not released.
unsafe fn gcm<'a>(ctx: *mut GCM128_CONTEXT) -> Option<&'a mut GcmCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { ctx.cast::<GcmCtx>().as_mut() }
}

ffi_export! {
    /// A new GCM context over `block` under `key` (the hash key is `block`'s encryption of
    /// zeros), or null (for no function, or no memory). Freed with `CRYPTO_gcm128_release`.
    ///
    /// # Safety
    /// `block` is null or a block function for `key`, which outlives the context.
    pub unsafe extern "C" fn CRYPTO_gcm128_new(key: *mut c_void, block: block128_f) -> *mut GCM128_CONTEXT
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        let Some(f) = block else { return ptr::null_mut() };
        let ctx = mem::alloc(size_of::<GcmCtx>()).cast::<GcmCtx>();
        if ctx.is_null() {
            return ptr::null_mut();
        }
        let key = key.cast_const();
        let state = Gcm::new(&CBlock { f, key });
        // SAFETY: a fresh allocation of the context's size, from the allocator's
        // (sufficiently aligned) memory.
        unsafe { ctx.write(GcmCtx { block: f, key, state }) };
        ctx.cast()
    }
}

ffi_export! {
    /// Sets the context up afresh over `block` under `key`. Nothing for null.
    ///
    /// # Safety
    /// `ctx` is null or from `CRYPTO_gcm128_new`; `block` is null or a block function for
    /// `key`.
    pub unsafe extern "C" fn CRYPTO_gcm128_init(ctx: *mut GCM128_CONTEXT, key: *mut c_void, block: block128_f)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let Some(f) = block else { return };
        if ctx.is_null() {
            return;
        }
        let key = key.cast_const();
        let state = Gcm::new(&CBlock { f, key });
        // SAFETY: the caller's context, overwritten whole (its old state holds nothing to free).
        unsafe { ctx.cast::<GcmCtx>().write(GcmCtx { block: f, key, state }) };
    }
}

ffi_export! {
    /// Starts a message with the `len`-octet IV.
    ///
    /// # Safety
    /// `ctx` is null or a live GCM context; `iv` is null or holds `len` octets.
    pub unsafe extern "C" fn CRYPTO_gcm128_setiv(ctx: *mut GCM128_CONTEXT, iv: *const c_uchar, len: usize)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { gcm(ctx) }) else { return };
        // SAFETY: the caller's guarantee.
        let Some(iv) = (unsafe { bytes(iv, len) }) else { return };
        let b = c.block();
        c.state.setiv(iv, &b);
    }
}

ffi_export! {
    /// Absorbs `len` octets of AAD. Returns 0, -1 past 2^61 octets, or -2 after the message
    /// has started.
    ///
    /// # Safety
    /// `ctx` is null or a live GCM context; `aad` is null or holds `len` octets.
    pub unsafe extern "C" fn CRYPTO_gcm128_aad(ctx: *mut GCM128_CONTEXT, aad: *const c_uchar, len: usize) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { gcm(ctx) }) else { return -1 };
        // SAFETY: the caller's guarantee.
        let Some(aad) = (unsafe { bytes(aad, len) }) else { return -1 };
        c.state.aad(aad)
    }
}

/// A GCM encryption or decryption of `len` octets through `run`; -1 for null.
///
/// # Safety
/// `ctx` is null or a live GCM context; `input` and `out` are null or hold `len` octets.
unsafe fn gcm_crypt(
    ctx: *mut GCM128_CONTEXT,
    input: *const c_uchar,
    out: *mut c_uchar,
    len: usize,
    run: impl FnOnce(&mut Gcm, &[u8], &mut [u8], &CBlock) -> c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { gcm(ctx) }) else {
        return -1;
    };
    // SAFETY: the caller's guarantee.
    let Some((input, out)) = (unsafe { buffers(input, len, out, len) }) else {
        return -1;
    };
    let b = c.block();
    run(&mut c.state, &input, out, &b)
}

ffi_export! {
    /// Encrypts `len` octets. Returns 0, or -1 past 2^36 - 32 octets of message.
    ///
    /// # Safety
    /// `ctx` is null or a live GCM context; `in_` holds and `out` has room for `len` octets.
    pub unsafe extern "C" fn CRYPTO_gcm128_encrypt(ctx: *mut GCM128_CONTEXT, in_: *const c_uchar, out: *mut c_uchar, len: usize) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { gcm_crypt(ctx, in_, out, len, |g, i, o, b| g.encrypt(i, o, b)) }
    }
}

ffi_export! {
    /// Decrypts `len` octets. Returns as `CRYPTO_gcm128_encrypt`.
    ///
    /// # Safety
    /// As for `CRYPTO_gcm128_encrypt`.
    pub unsafe extern "C" fn CRYPTO_gcm128_decrypt(ctx: *mut GCM128_CONTEXT, in_: *const c_uchar, out: *mut c_uchar, len: usize) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { gcm_crypt(ctx, in_, out, len, |g, i, o, b| g.decrypt(i, o, b)) }
    }
}

ffi_export! {
    /// Encrypts `len` octets, the whole blocks through `stream` (counting in the counter
    /// block's last 32 bits), in 3 KiB strides. Returns as `CRYPTO_gcm128_encrypt`.
    ///
    /// # Safety
    /// As for `CRYPTO_gcm128_encrypt`, with `stream` null or a CTR function for the
    /// context's key.
    pub unsafe extern "C" fn CRYPTO_gcm128_encrypt_ctr32(ctx: *mut GCM128_CONTEXT, in_: *const c_uchar, out: *mut c_uchar, len: usize, stream: ctr128_f) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        let Some(f) = stream else { return -1 };
        // SAFETY: the caller's guarantee.
        unsafe { gcm_crypt(ctx, in_, out, len, |g, i, o, b| g.encrypt_ctr32(i, o, b, &CCtr { f, key: b.key })) }
    }
}

ffi_export! {
    /// Decrypts `len` octets, the whole blocks through `stream`. Returns as
    /// `CRYPTO_gcm128_encrypt`.
    ///
    /// # Safety
    /// As for `CRYPTO_gcm128_encrypt_ctr32`.
    pub unsafe extern "C" fn CRYPTO_gcm128_decrypt_ctr32(ctx: *mut GCM128_CONTEXT, in_: *const c_uchar, out: *mut c_uchar, len: usize, stream: ctr128_f) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        let Some(f) = stream else { return -1 };
        // SAFETY: the caller's guarantee.
        unsafe { gcm_crypt(ctx, in_, out, len, |g, i, o, b| g.decrypt_ctr32(i, o, b, &CCtr { f, key: b.key })) }
    }
}

ffi_export! {
    /// Finishes the tag and compares its first `len` octets with `tag`: 0 if equal, 1 if
    /// not, -1 for no tag or more than 16 octets. Nothing is reset: another finish hashes
    /// what's buffered again, as in OpenSSL.
    ///
    /// # Safety
    /// `ctx` is null or a live GCM context; `tag` is null or holds `len` octets.
    pub unsafe extern "C" fn CRYPTO_gcm128_finish(ctx: *mut GCM128_CONTEXT, tag: *const c_uchar, len: usize) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { gcm(ctx) }) else { return -1 };
        let tag = if tag.is_null() || len > BLOCK {
            None
        } else {
            // SAFETY: the caller's `len` (at most 16) octets.
            unsafe { bytes(tag, len) }
        };
        c.state.finish(tag)
    }
}

ffi_export! {
    /// Finishes the tag (as `CRYPTO_gcm128_finish` without one) and writes its first `len`
    /// octets (at most 16) to `tag`.
    ///
    /// # Safety
    /// `ctx` is null or a live GCM context; `tag` is null or has room for `len` octets (at
    /// most 16).
    pub unsafe extern "C" fn CRYPTO_gcm128_tag(ctx: *mut GCM128_CONTEXT, tag: *mut c_uchar, len: usize)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { gcm(ctx) }) else { return };
        if tag.is_null() {
            return;
        }
        // SAFETY: the caller's room, at most 16 octets of it.
        let out = unsafe { core::slice::from_raw_parts_mut(tag, len.min(BLOCK)) };
        c.state.tag(out);
    }
}

ffi_export! {
    /// Zeroes and frees the context. Null does nothing.
    ///
    /// # Safety
    /// `ctx` is null or from `CRYPTO_gcm128_new`; it isn't used afterwards.
    pub unsafe extern "C" fn CRYPTO_gcm128_release(ctx: *mut GCM128_CONTEXT)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        if ctx.is_null() {
            return;
        }
        // SAFETY: the caller's context, whose state is dropped (wiping it) before its memory is
        // zeroed and freed.
        let state = unsafe { &raw mut (*ctx.cast::<GcmCtx>()).state };
        // SAFETY: as above.
        unsafe { ptr::drop_in_place(state) };
        // SAFETY: the context's block from the allocator.
        unsafe { mem::release_clean(ctx.cast(), size_of::<GcmCtx>()) };
    }
}

/// `CCM128_CONTEXT`, as `modes_local.h` lays it out: the nonce block and the CBC-MAC (unions
/// of two `u64` and 16 octets), the block count, the block function, and its key.
#[repr(C, align(8))]
struct CcmCtx {
    nonce: [u8; BLOCK],
    cmac: [u8; BLOCK],
    blocks: u64,
    block: block128_f,
    key: *mut c_void,
}

const _: () = assert!(size_of::<CcmCtx>() == 56);

impl CcmCtx {
    fn load(&self) -> Ccm {
        Ccm {
            nonce: self.nonce,
            cmac: self.cmac,
            blocks: self.blocks,
        }
    }

    fn store(&mut self, c: &Ccm) {
        self.nonce = c.nonce;
        self.cmac = c.cmac;
        self.blocks = c.blocks;
    }
}

/// The caller's CCM context.
///
/// # Safety
/// `ctx` is null or a valid `CCM128_CONTEXT` as `modes_local.h` lays it out.
unsafe fn ccm<'a>(ctx: *mut CCM128_CONTEXT) -> Option<&'a mut CcmCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { ctx.cast::<CcmCtx>().as_mut() }
}

ffi_export! {
    /// Sets the context up for `m`-octet tags and an `l`-octet length field, over `block`
    /// under `key`.
    ///
    /// # Safety
    /// `ctx` is null or a `CCM128_CONTEXT` as `modes_local.h` lays it out.
    pub unsafe extern "C" fn CRYPTO_ccm128_init(ctx: *mut CCM128_CONTEXT, m: c_uint, l: c_uint, key: *mut c_void, block: block128_f)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        if ctx.is_null() {
            return;
        }
        // SAFETY: the caller's struct, written field by field (any octets in it are valid).
        let Some(c) = (unsafe { ccm(ctx) }) else { return };
        let mut state = c.load();
        state.init(m, l);
        c.store(&state);
        c.block = block;
        c.key = key;
    }
}

ffi_export! {
    /// Sets the nonce (its first `14 - L` octets of `nlen`) and the message length. Returns 0,
    /// or -1 for a nonce too short.
    ///
    /// # Safety
    /// `ctx` is null or a valid CCM context; `nonce` is null or holds `nlen` octets.
    pub unsafe extern "C" fn CRYPTO_ccm128_setiv(ctx: *mut CCM128_CONTEXT, nonce: *const c_uchar, nlen: usize, mlen: usize) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ccm(ctx) }) else { return -1 };
        // SAFETY: the caller's guarantee.
        let Some(nonce) = (unsafe { bytes(nonce, nlen) }) else { return -1 };
        let mut m = c.load();
        let r = m.setiv(nonce, mlen);
        c.store(&m);
        r
    }
}

ffi_export! {
    /// Absorbs the `alen` octets of AAD (once per message). Nothing for none.
    ///
    /// # Safety
    /// `ctx` is null or a valid CCM context; `aad` is null or holds `alen` octets.
    pub unsafe extern "C" fn CRYPTO_ccm128_aad(ctx: *mut CCM128_CONTEXT, aad: *const c_uchar, alen: usize)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ccm(ctx) }) else { return };
        let Some(f) = c.block else { return };
        // SAFETY: the caller's guarantee.
        let Some(aad) = (unsafe { bytes(aad, alen) }) else { return };
        let b = CBlock { f, key: c.key.cast_const() };
        let mut m = c.load();
        m.aad(aad, &b);
        c.store(&m);
    }
}

/// A CCM encryption or decryption of `len` octets through `run`; -1 for null.
///
/// # Safety
/// `ctx` is null or a valid CCM context; `input` and `out` are null or hold `len` octets.
unsafe fn ccm_crypt(
    ctx: *mut CCM128_CONTEXT,
    input: *const c_uchar,
    out: *mut c_uchar,
    len: usize,
    run: impl FnOnce(&mut Ccm, &[u8], &mut [u8], &CBlock) -> c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ccm(ctx) }) else {
        return -1;
    };
    let Some(f) = c.block else { return -1 };
    // SAFETY: the caller's guarantee.
    let Some((input, out)) = (unsafe { buffers(input, len, out, len) }) else {
        return -1;
    };
    let b = CBlock {
        f,
        key: c.key.cast_const(),
    };
    let mut m = c.load();
    let r = run(&mut m, &input, out, &b);
    c.store(&m);
    r
}

/// The caller's whole-block CCM function and its key.
struct CCcm {
    f: unsafe extern "C" fn(*const u8, *mut u8, usize, *const c_void, *const u8, *mut u8),
    key: *const c_void,
}

impl Ccm128 for CCcm {
    fn ccm(
        &self,
        input: &[u8],
        out: &mut [u8],
        blocks: usize,
        ivec: &[u8; BLOCK],
        cmac: &mut [u8; BLOCK],
    ) {
        let len = blocks.saturating_mul(BLOCK);
        if input.len() < len || out.len() < len {
            return;
        }
        // SAFETY: the caller's function with its key, `blocks` blocks in and out, the counter
        // block, and the CBC-MAC.
        unsafe {
            (self.f)(
                input.as_ptr(),
                out.as_mut_ptr(),
                blocks,
                self.key,
                ivec.as_ptr(),
                cmac.as_mut_ptr(),
            )
        };
    }
}

ffi_export! {
    /// Encrypts the message (`len` octets, the length set). Returns 0, -1 for another
    /// length, or -2 past 2^61 blocks under the key.
    ///
    /// # Safety
    /// `ctx` is null or a valid CCM context; `inp` holds and `out` has room for `len` octets.
    pub unsafe extern "C" fn CRYPTO_ccm128_encrypt(ctx: *mut CCM128_CONTEXT, inp: *const c_uchar, out: *mut c_uchar, len: usize) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { ccm_crypt(ctx, inp, out, len, |m, i, o, b| m.encrypt(i, o, b)) }
    }
}

ffi_export! {
    /// Decrypts the message. Returns 0, or -1 for another length than the one set.
    ///
    /// # Safety
    /// As for `CRYPTO_ccm128_encrypt`.
    pub unsafe extern "C" fn CRYPTO_ccm128_decrypt(ctx: *mut CCM128_CONTEXT, inp: *const c_uchar, out: *mut c_uchar, len: usize) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { ccm_crypt(ctx, inp, out, len, |m, i, o, b| m.decrypt(i, o, b)) }
    }
}

ffi_export! {
    /// Encrypts the message, the whole blocks through `stream`. Returns as
    /// `CRYPTO_ccm128_encrypt`.
    ///
    /// # Safety
    /// As for `CRYPTO_ccm128_encrypt`, with `stream` null or a CCM function for the key.
    pub unsafe extern "C" fn CRYPTO_ccm128_encrypt_ccm64(ctx: *mut CCM128_CONTEXT, inp: *const c_uchar, out: *mut c_uchar, len: usize, stream: ccm128_f) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        let Some(f) = stream else { return -1 };
        // SAFETY: the caller's guarantee.
        unsafe { ccm_crypt(ctx, inp, out, len, |m, i, o, b| m.encrypt_ccm64(i, o, b, &CCcm { f, key: b.key })) }
    }
}

ffi_export! {
    /// Decrypts the message, the whole blocks through `stream`. Returns as
    /// `CRYPTO_ccm128_decrypt`.
    ///
    /// # Safety
    /// As for `CRYPTO_ccm128_encrypt_ccm64`.
    pub unsafe extern "C" fn CRYPTO_ccm128_decrypt_ccm64(ctx: *mut CCM128_CONTEXT, inp: *const c_uchar, out: *mut c_uchar, len: usize, stream: ccm128_f) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        let Some(f) = stream else { return -1 };
        // SAFETY: the caller's guarantee.
        unsafe { ccm_crypt(ctx, inp, out, len, |m, i, o, b| m.decrypt_ccm64(i, o, b, &CCcm { f, key: b.key })) }
    }
}

ffi_export! {
    /// Writes the tag to `tag` if `len` is the configured size. Returns that size, or 0.
    ///
    /// # Safety
    /// `ctx` is null or a valid CCM context; `tag` is null or has room for `len` octets.
    pub unsafe extern "C" fn CRYPTO_ccm128_tag(ctx: *mut CCM128_CONTEXT, tag: *mut c_uchar, len: usize) -> usize
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ccm(ctx) }) else { return 0 };
        let m = usize::from((c.nonce[0] >> 3) & 7).saturating_mul(2).saturating_add(2);
        if len != m || tag.is_null() {
            return 0;
        }
        // SAFETY: the caller's room for `len` (at most 16) octets.
        let out = unsafe { core::slice::from_raw_parts_mut(tag, m) };
        c.load().tag(out, len)
    }
}

/// `XTS128_CONTEXT`, as `modes_local.h` lays it out: the data and tweak keys, then their
/// block functions.
#[repr(C)]
struct XtsCtx {
    key1: *mut c_void,
    key2: *mut c_void,
    block1: block128_f,
    block2: block128_f,
}

ffi_export! {
    /// XTS-encrypts (`enc` nonzero) or decrypts `len` octets (16 or more) under the tweak
    /// `iv`, a partial last block by ciphertext stealing. Returns 0, or -1.
    ///
    /// # Safety
    /// `ctx` is null or an `XTS128_CONTEXT` as `modes_local.h` lays it out; `iv` holds 16
    /// octets; `inp` holds and `out` has room for `len`.
    pub unsafe extern "C" fn CRYPTO_xts128_encrypt(ctx: *const XTS128_CONTEXT, iv: *const c_uchar, inp: *const c_uchar, out: *mut c_uchar, len: usize, enc: c_int) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        if len < BLOCK {
            return -1;
        }
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx.cast::<XtsCtx>().as_ref() }) else { return -1 };
        let (Some(f1), Some(f2)) = (c.block1, c.block2) else { return -1 };
        // SAFETY: the caller's guarantee.
        let Some(tweak) = (unsafe { read_array::<BLOCK>(iv) }) else { return -1 };
        // SAFETY: the caller's guarantee.
        let Some((input, out)) = (unsafe { buffers(inp, len, out, len) }) else { return -1 };
        let b1 = CBlock { f: f1, key: c.key1.cast_const() };
        let b2 = CBlock { f: f2, key: c.key2.cast_const() };
        aead::xts(&tweak, &input, out, enc != 0, &b1, &b2)
    }
}

/// What an `OCB128_CONTEXT *` points to: the block functions, their keys, the bulk function,
/// then the state.
#[repr(C)]
#[derive(Clone)]
struct OcbCtx {
    encrypt: unsafe extern "C" fn(*const u8, *mut u8, *const c_void),
    decrypt: unsafe extern "C" fn(*const u8, *mut u8, *const c_void),
    keyenc: *mut c_void,
    keydec: *mut c_void,
    stream: ocb128_f,
    state: Ocb,
}

impl OcbCtx {
    fn enc(&self) -> CBlock {
        CBlock {
            f: self.encrypt,
            key: self.keyenc.cast_const(),
        }
    }

    fn dec(&self) -> CBlock {
        CBlock {
            f: self.decrypt,
            key: self.keydec.cast_const(),
        }
    }
}

/// The caller's whole-block OCB function and its key.
struct COcb {
    f: unsafe extern "C" fn(
        *const u8,
        *mut u8,
        usize,
        *const c_void,
        usize,
        *mut u8,
        *const [u8; 16],
        *mut u8,
    ),
    key: *const c_void,
}

impl Ocb128 for COcb {
    fn ocb(
        &self,
        input: &[u8],
        out: &mut [u8],
        blocks: usize,
        start: usize,
        offset: &mut [u8; BLOCK],
        l: &[[u8; BLOCK]],
        checksum: &mut [u8; BLOCK],
    ) {
        let len = blocks.saturating_mul(BLOCK);
        if input.len() < len || out.len() < len || l.len() < OCB_MAX_L {
            return;
        }
        // SAFETY: the caller's function with its key, `blocks` blocks in and out, the offset,
        // the table of `L_i` (every one the blocks need computed), and the checksum.
        unsafe {
            (self.f)(
                input.as_ptr(),
                out.as_mut_ptr(),
                blocks,
                self.key,
                start,
                offset.as_mut_ptr(),
                l.as_ptr(),
                checksum.as_mut_ptr(),
            )
        };
    }
}

/// The context behind an `OCB128_CONTEXT *`.
///
/// # Safety
/// `ctx` is null or from `CRYPTO_ocb128_new`, not cleaned up.
unsafe fn ocb<'a>(ctx: *mut OCB128_CONTEXT) -> Option<&'a mut OcbCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { ctx.cast::<OcbCtx>().as_mut() }
}

/// Writes a fresh context at `ctx`. False for a missing block function.
///
/// # Safety
/// `ctx` is valid for writes of an `OcbCtx`.
unsafe fn ocb_init(
    ctx: *mut OcbCtx,
    keyenc: *mut c_void,
    keydec: *mut c_void,
    encrypt: block128_f,
    decrypt: block128_f,
    stream: ocb128_f,
) -> bool {
    let (Some(e), Some(d)) = (encrypt, decrypt) else {
        return false;
    };
    let state = Ocb::new(&CBlock {
        f: e,
        key: keyenc.cast_const(),
    });
    // SAFETY: the caller's guarantee; the old contents hold nothing to free.
    unsafe {
        ctx.write(OcbCtx {
            encrypt: e,
            decrypt: d,
            keyenc,
            keydec,
            stream,
            state,
        })
    };
    true
}

ffi_export! {
    /// A new OCB context over `encrypt` under `keyenc` and `decrypt` under `keydec`, with the
    /// bulk function `stream` (or none), or null. Freed with `CRYPTO_ocb128_cleanup`, then
    /// `OPENSSL_free`.
    ///
    /// # Safety
    /// The functions are null or block functions for their keys, which outlive the context;
    /// `stream` is null or an OCB function for them.
    pub unsafe extern "C" fn CRYPTO_ocb128_new(keyenc: *mut c_void, keydec: *mut c_void, encrypt: block128_f, decrypt: block128_f, stream: ocb128_f) -> *mut OCB128_CONTEXT
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        if encrypt.is_none() || decrypt.is_none() {
            return ptr::null_mut();
        }
        let ctx = mem::alloc(size_of::<OcbCtx>()).cast::<OcbCtx>();
        if ctx.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: a fresh allocation of the context's size, from the allocator's
        // (sufficiently aligned) memory.
        unsafe { ocb_init(ctx, keyenc, keydec, encrypt, decrypt, stream) };
        ctx.cast()
    }
}

ffi_export! {
    /// Sets the context up afresh. Returns 1, or 0 for null.
    ///
    /// # Safety
    /// `ctx` is null or from `CRYPTO_ocb128_new`; the functions as for `CRYPTO_ocb128_new`.
    pub unsafe extern "C" fn CRYPTO_ocb128_init(ctx: *mut OCB128_CONTEXT, keyenc: *mut c_void, keydec: *mut c_void, encrypt: block128_f, decrypt: block128_f, stream: ocb128_f) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: the caller's context.
        c_int::from(unsafe { ocb_init(ctx.cast(), keyenc, keydec, encrypt, decrypt, stream) })
    }
}

ffi_export! {
    /// Copies `src` into `dest`, with `keyenc` and `keydec` instead of `src`'s keys where they
    /// aren't null. Returns 1, or 0 for null.
    ///
    /// # Safety
    /// `dest` and `src` are null or from `CRYPTO_ocb128_new`.
    pub unsafe extern "C" fn CRYPTO_ocb128_copy_ctx(dest: *mut OCB128_CONTEXT, src: *mut OCB128_CONTEXT, keyenc: *mut c_void, keydec: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { ocb(src) }) else { return 0 };
        let mut copy = s.clone();
        if !keyenc.is_null() {
            copy.keyenc = keyenc;
        }
        if !keydec.is_null() {
            copy.keydec = keydec;
        }
        if dest.is_null() {
            return 0;
        }
        // SAFETY: the caller's context, overwritten whole.
        unsafe { dest.cast::<OcbCtx>().write(copy) };
        1
    }
}

ffi_export! {
    /// Starts a message with a `len`-octet nonce (1 to 15) and `taglen`-octet tags (1 to 16).
    /// Returns 1, or -1.
    ///
    /// # Safety
    /// `ctx` is null or a live OCB context; `iv` is null or holds `len` octets.
    pub unsafe extern "C" fn CRYPTO_ocb128_setiv(ctx: *mut OCB128_CONTEXT, iv: *const c_uchar, len: usize, taglen: usize) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ocb(ctx) }) else { return -1 };
        if !(1..=15).contains(&len) {
            return -1;
        }
        // SAFETY: the caller's guarantee.
        let Some(iv) = (unsafe { bytes(iv, len) }) else { return -1 };
        let e = c.enc();
        c.state.setiv(iv, taglen, &e)
    }
}

ffi_export! {
    /// Absorbs `len` octets of AAD (a partial block only in the last call). Returns 1, or 0
    /// for null.
    ///
    /// # Safety
    /// `ctx` is null or a live OCB context; `aad` is null or holds `len` octets.
    pub unsafe extern "C" fn CRYPTO_ocb128_aad(ctx: *mut OCB128_CONTEXT, aad: *const c_uchar, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ocb(ctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        let Some(aad) = (unsafe { bytes(aad, len) }) else { return 0 };
        let e = c.enc();
        c.state.aad(aad, &e)
    }
}

/// An OCB encryption or decryption of `len` octets; 0 for null.
///
/// # Safety
/// `ctx` is null or a live OCB context; `input` and `out` are null or hold `len` octets.
unsafe fn ocb_crypt(
    ctx: *mut OCB128_CONTEXT,
    input: *const c_uchar,
    out: *mut c_uchar,
    len: usize,
    enc: bool,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { ocb(ctx) }) else {
        return 0;
    };
    // SAFETY: the caller's guarantee.
    let Some((input, out)) = (unsafe { buffers(input, len, out, len) }) else {
        return 0;
    };
    let (e, d) = (c.enc(), c.dec());
    let key = if enc { c.keyenc } else { c.keydec };
    let stream = c.stream.map(|f| COcb {
        f,
        key: key.cast_const(),
    });
    let stream = stream.as_ref().map(|s| s as &dyn Ocb128);
    if enc {
        c.state.encrypt(&input, out, &e, &d, stream)
    } else {
        c.state.decrypt(&input, out, &e, &d, stream)
    }
}

ffi_export! {
    /// Encrypts `len` octets (a partial block only in the last call). Returns 1, or 0.
    ///
    /// # Safety
    /// `ctx` is null or a live OCB context; `in_` holds and `out` has room for `len` octets.
    pub unsafe extern "C" fn CRYPTO_ocb128_encrypt(ctx: *mut OCB128_CONTEXT, in_: *const c_uchar, out: *mut c_uchar, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { ocb_crypt(ctx, in_, out, len, true) }
    }
}

ffi_export! {
    /// Decrypts `len` octets (a partial block only in the last call). Returns 1, or 0.
    ///
    /// # Safety
    /// As for `CRYPTO_ocb128_encrypt`.
    pub unsafe extern "C" fn CRYPTO_ocb128_decrypt(ctx: *mut OCB128_CONTEXT, in_: *const c_uchar, out: *mut c_uchar, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { ocb_crypt(ctx, in_, out, len, false) }
    }
}

ffi_export! {
    /// Compares the first `len` octets (1 to 16) of the tag with `tag`: 0 if equal, 1 if not,
    /// -1 for another length.
    ///
    /// # Safety
    /// `ctx` is null or a live OCB context; `tag` is null or holds `len` octets.
    pub unsafe extern "C" fn CRYPTO_ocb128_finish(ctx: *mut OCB128_CONTEXT, tag: *const c_uchar, len: usize) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ocb(ctx) }) else { return -1 };
        if !(1..=BLOCK).contains(&len) {
            return -1;
        }
        // SAFETY: the caller's `len` (at most 16) octets.
        let Some(tag) = (unsafe { bytes(tag, len) }) else { return -1 };
        let e = c.enc();
        c.state.finish(tag, &e)
    }
}

ffi_export! {
    /// Writes the first `len` octets (1 to 16) of the tag to `tag`. Returns 1, or -1.
    ///
    /// # Safety
    /// `ctx` is null or a live OCB context; `tag` is null or has room for `len` octets.
    pub unsafe extern "C" fn CRYPTO_ocb128_tag(ctx: *mut OCB128_CONTEXT, tag: *mut c_uchar, len: usize) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ocb(ctx) }) else { return -1 };
        if !(1..=BLOCK).contains(&len) || tag.is_null() {
            return -1;
        }
        // SAFETY: the caller's room for `len` (at most 16) octets.
        let out = unsafe { core::slice::from_raw_parts_mut(tag, len) };
        let e = c.enc();
        c.state.tag(out, &e)
    }
}

ffi_export! {
    /// Zeroes the context (without freeing it: `OPENSSL_free` does). Null does nothing.
    ///
    /// # Safety
    /// `ctx` is null or from `CRYPTO_ocb128_new`.
    pub unsafe extern "C" fn CRYPTO_ocb128_cleanup(ctx: *mut OCB128_CONTEXT)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        if ctx.is_null() {
            return;
        }
        // SAFETY: the caller's context, whose memory is zeroed.
        unsafe { mem::cleanse(ctx.cast(), size_of::<OcbCtx>()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: null contexts, buffers, and functions return 0 or -1 (null from a
    /// constructor) or do nothing; the reference crashes.
    #[test]
    fn nulls_fail() {
        let mut out = [0u8; 32];
        let input = [1u8; 32];
        let mut tag = [0u8; 16];
        // SAFETY: nulls are the case under test, with buffers of the right sizes, for each
        // call below.
        assert!(unsafe { CRYPTO_gcm128_new(ptr::null_mut(), None) }.is_null());
        // SAFETY: as above.
        unsafe { CRYPTO_gcm128_setiv(ptr::null_mut(), input.as_ptr(), 12) };
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe { CRYPTO_gcm128_aad(ptr::null_mut(), input.as_ptr(), 1) },
            -1
        );
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe { CRYPTO_gcm128_encrypt(ptr::null_mut(), input.as_ptr(), out.as_mut_ptr(), 16) },
            -1
        );
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe { CRYPTO_gcm128_finish(ptr::null_mut(), tag.as_ptr(), 16) },
            -1
        );
        // SAFETY: as above.
        unsafe { CRYPTO_gcm128_tag(ptr::null_mut(), tag.as_mut_ptr(), 16) };
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe { CRYPTO_ccm128_setiv(ptr::null_mut(), input.as_ptr(), 13, 5) },
            -1
        );
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe { CRYPTO_ccm128_encrypt(ptr::null_mut(), input.as_ptr(), out.as_mut_ptr(), 5) },
            -1
        );
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe { CRYPTO_ccm128_tag(ptr::null_mut(), tag.as_mut_ptr(), 8) },
            0
        );
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe {
                CRYPTO_xts128_encrypt(
                    ptr::null(),
                    input.as_ptr(),
                    input.as_ptr(),
                    out.as_mut_ptr(),
                    32,
                    1,
                )
            },
            -1
        );
        // SAFETY: as above.
        assert!(
            // SAFETY: as above.
            unsafe { CRYPTO_ocb128_new(ptr::null_mut(), ptr::null_mut(), None, None, None) }
                .is_null()
        );
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe { CRYPTO_ocb128_setiv(ptr::null_mut(), input.as_ptr(), 12, 16) },
            -1
        );
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe { CRYPTO_ocb128_encrypt(ptr::null_mut(), input.as_ptr(), out.as_mut_ptr(), 16) },
            0
        );
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe {
                CRYPTO_ocb128_copy_ctx(
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            },
            0
        );
        // SAFETY: as above.
        unsafe { CRYPTO_ocb128_cleanup(ptr::null_mut()) };
        assert_eq!((out, tag), ([0; 32], [0; 16]));

        // A CCM context without a block function, and an XTS one without its functions.
        let mut ccm_ctx = CcmCtx {
            nonce: [0; 16],
            cmac: [0; 16],
            blocks: 0,
            block: None,
            key: ptr::null_mut(),
        };
        let c = (&raw mut ccm_ctx).cast::<CCM128_CONTEXT>();
        // SAFETY: as above.
        unsafe { CRYPTO_ccm128_aad(c, input.as_ptr(), 4) };
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe { CRYPTO_ccm128_decrypt(c, input.as_ptr(), out.as_mut_ptr(), 0) },
            -1
        );
        let xts_ctx = XtsCtx {
            key1: ptr::null_mut(),
            key2: ptr::null_mut(),
            block1: None,
            block2: None,
        };
        // SAFETY: as above.
        let r = unsafe {
            CRYPTO_xts128_encrypt(
                (&raw const xts_ctx).cast(),
                input.as_ptr(),
                input.as_ptr(),
                out.as_mut_ptr(),
                32,
                1,
            )
        };
        assert_eq!(r, -1);
        assert_eq!((ccm_ctx.cmac, out), ([0; 16], [0; 32]));
    }
}
