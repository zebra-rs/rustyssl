//! The legacy paths of the cipher context (`evp_enc.c`'s `legacy:` parts), for a cipher an
//! application made (`EVP_CIPHER_meth_new`): its `init` and `do_cipher` and the rest run on the
//! context, which keeps the IV by the cipher's mode, buffers partial blocks, pads and checks
//! padding, and holds the cipher's state (`cipher_data`, of the size it gives).
//!
//! The application's functions may use the context, so none of these holds a borrow of it
//! across their calls: each re-reads the context after one.
//!
//! The padding a decrypting final removes is checked in constant time, where OpenSSL compares
//! it octet by octet (a padding oracle, as its comment says, unless the ciphertext was
//! authenticated); the results are the same.

use core::ffi::{c_int, c_ulong, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_EVP, EVP_CIPH_ALWAYS_CALL_INIT, EVP_CIPH_CBC_MODE, EVP_CIPH_CFB_MODE,
    EVP_CIPH_CTR_MODE, EVP_CIPH_CTRL_INIT, EVP_CIPH_CUSTOM_COPY, EVP_CIPH_CUSTOM_IV,
    EVP_CIPH_CUSTOM_IV_LENGTH, EVP_CIPH_CUSTOM_KEY_LENGTH, EVP_CIPH_ECB_MODE,
    EVP_CIPH_FLAG_CUSTOM_CIPHER, EVP_CIPH_FLAG_LENGTH_BITS, EVP_CIPH_MODE, EVP_CIPH_NO_PADDING,
    EVP_CIPH_OFB_MODE, EVP_CIPH_STREAM_CIPHER, EVP_CIPH_VARIABLE_LENGTH, EVP_CIPH_WRAP_MODE,
    EVP_CIPHER, EVP_CIPHER_CTX, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW, EVP_CTRL_COPY, EVP_CTRL_GET_IVLEN,
    EVP_CTRL_INIT, EVP_CTRL_SET_KEY_LENGTH, EVP_R_BAD_DECRYPT, EVP_R_CTRL_NOT_IMPLEMENTED,
    EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED, EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH,
    EVP_R_INITIALIZATION_ERROR, EVP_R_INVALID_IV_LENGTH, EVP_R_INVALID_KEY_LENGTH,
    EVP_R_OUTPUT_WOULD_OVERFLOW, EVP_R_PARTIALLY_OVERLAPPING, EVP_R_WRAP_MODE_NOT_ALLOWED,
    EVP_R_WRONG_FINAL_BLOCK_LENGTH,
};

use super::super::cipher::{Cipher, EVP_CIPHER_free, Legacy, Origin, method};
use super::{CipherCtx, EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_reset, MAX_BLOCK, context, flag};
use crate::err;
use crate::mem;

/// The context's cipher, if it has one and it has no provider.
fn legacy_cipher<'a>(c: &CipherCtx) -> Option<&'a Cipher> {
    c.cipher().filter(|m| m.prov.0.is_null())
}

/// Whether `cipher` (or, for NULL, the context's) is an application's: the init that takes
/// the legacy path.
///
/// # Safety
/// `ctx` is a live cipher context; `cipher` is NULL or a live cipher method.
pub(super) unsafe fn is_application(ctx: *mut EVP_CIPHER_CTX, cipher: *const EVP_CIPHER) -> bool {
    let m = if cipher.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { context(ctx) }.and_then(|c| c.cipher())
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { method(cipher) }
    };
    m.is_some_and(|m| m.origin == Origin::Meth)
}

/// The context's legacy cipher's functions and flags, if it has one.
///
/// # Safety
/// `ctx` is NULL or a live cipher context.
unsafe fn legacy_of(ctx: *mut EVP_CIPHER_CTX) -> Option<(Legacy, c_ulong, c_int)> {
    // SAFETY: the caller's guarantee.
    let c = unsafe { context(ctx) }?;
    let m = legacy_cipher(c)?;
    Some((m.legacy_fns(), m.flags(), m.block_size()))
}

/// A pointer to the context's `buf`, made without a reference (the cipher's functions get it
/// while they may use the context).
fn buf_ptr(ctx: *mut EVP_CIPHER_CTX) -> *mut u8 {
    // SAFETY: a live context's field, addressed without a reference.
    unsafe { (&raw mut (*ctx.cast::<CipherCtx>()).buf).cast() }
}

/// `ossl_is_partially_overlapping`: whether two buffers of `len` overlap without being the
/// same (OpenSSL's unsigned pointer difference).
fn partially_overlapping(p1: *const u8, p2: *const u8, len: c_int) -> bool {
    let Ok(len) = usize::try_from(len) else {
        return false;
    };
    let diff = (p1 as usize).wrapping_sub(p2 as usize);
    len > 0 && diff != 0 && (diff < len || diff > 0usize.wrapping_sub(len))
}

/// The length the overlap checks use: `inl`, or its octets for a cipher that counts bits.
fn compared_len(flags: c_ulong, inl: c_int) -> c_int {
    if flags & flag(EVP_CIPH_FLAG_LENGTH_BITS) != 0 {
        inl.saturating_add(7) / 8
    } else {
        inl
    }
}

/// The cipher's `do_cipher` on the caller's buffers; 0 without one (OpenSSL calls NULL).
///
/// # Safety
/// `ctx` is a live cipher context; the buffers are what the cipher's function takes.
unsafe fn do_cipher(
    l: &Legacy,
    ctx: *mut EVP_CIPHER_CTX,
    out: *mut u8,
    input: *const u8,
    len: usize,
) -> c_int {
    let Some(f) = l.do_cipher else {
        err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, "do_cipher");
        return 0;
    };
    // SAFETY: the cipher's function with the caller's context and buffers.
    unsafe { f(ctx, out, input, len) }
}

/// The context's IV length (`EVP_CIPHER_CTX_get_iv_length`): the cipher's, or for one with
/// `EVP_CIPH_CUSTOM_IV_LENGTH` what its `ctrl` says, cached.
///
/// # Safety
/// `ctx` is a live cipher context with a legacy cipher.
pub(super) unsafe fn iv_length(ctx: *mut EVP_CIPHER_CTX) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { context(ctx) }) else {
        return 0;
    };
    let Some(m) = c.cipher() else { return 0 };
    if c.iv_len < 0 {
        let mut len = m.iv_len();
        if m.funcs.get_ctx_params.is_none() && m.flags() & flag(EVP_CIPH_CUSTOM_IV_LENGTH) != 0 {
            // SAFETY: the caller's context; a place for the length.
            let rv =
                unsafe { EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GET_IVLEN, 0, (&raw mut len).cast()) };
            if rv <= 0 {
                return -1;
            }
        }
        // SAFETY: as above (the call may have used the context).
        let Some(c) = (unsafe { context(ctx) }) else {
            return 0;
        };
        c.iv_len = len;
    }
    // SAFETY: as above.
    unsafe { context(ctx) }.map_or(0, |c| c.iv_len)
}

/// Runs a legacy cipher's `cleanup` and frees its state, before the context changes cipher or
/// is reset. False if `cleanup` failed (the state is kept, as in OpenSSL).
///
/// # Safety
/// `ctx` is NULL or a live cipher context.
pub(super) unsafe fn release(ctx: *mut EVP_CIPHER_CTX) -> bool {
    // SAFETY: the caller's guarantee.
    let Some((l, _, _)) = (unsafe { legacy_of(ctx) }) else {
        return true;
    };
    if let Some(cleanup) = l.cleanup {
        // SAFETY: the cipher's function with the caller's context.
        if unsafe { cleanup(ctx) } == 0 {
            return false;
        }
    }
    // SAFETY: as above (the call may have used the context).
    if let Some(c) = unsafe { context(ctx) }
        && !c.cipher_data.is_null()
    {
        let size = usize::try_from(l.ctx_size).unwrap_or(0);
        // SAFETY: the state this context allocated (or an application gave it to free), of the
        // cipher's size.
        unsafe { mem::release_clean(c.cipher_data, size) };
        c.cipher_data = ptr::null_mut();
    }
    true
}

/// The legacy part of `evp_cipher_init_internal`: the cipher set (its state allocated, its key
/// length taken, `EVP_CTRL_INIT` for one that asks), the IV kept by the mode, the cipher's
/// `init` when there's a key (or it always wants it), and the buffers emptied.
///
/// # Safety
/// `ctx` is a live cipher context; `cipher` is NULL or a live cipher method; `key` and `iv`
/// are NULL or hold the cipher's key and IV lengths.
pub(super) unsafe fn init(
    ctx: *mut EVP_CIPHER_CTX,
    cipher: *const EVP_CIPHER,
    key: *const u8,
    iv: *const u8,
    enc: c_int,
) -> c_int {
    const F: &str = "evp_cipher_init_internal";
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { context(ctx) }) else {
        return 0;
    };
    let enc = if enc == -1 {
        c.encrypt
    } else {
        let e = c_int::from(enc != 0);
        c.encrypt = e;
        e
    };
    if !cipher.is_null() {
        if !c.cipher.is_null() {
            let flags = c.flags;
            // SAFETY: the caller's context (its old cipher's `cleanup` may run).
            unsafe { EVP_CIPHER_CTX_reset(ctx) };
            // SAFETY: as above.
            let Some(c) = (unsafe { context(ctx) }) else {
                return 0;
            };
            c.encrypt = enc;
            c.flags = flags;
        }
        // SAFETY: as above.
        let Some(c) = (unsafe { context(ctx) }) else {
            return 0;
        };
        // SAFETY: the caller's live method.
        let Some(m) = (unsafe { method(cipher) }) else {
            return 0;
        };
        // The context holds no reference to an application's cipher, as in OpenSSL.
        // SAFETY: the context's own reference, if any.
        unsafe { EVP_CIPHER_free(c.fetched_cipher) };
        c.fetched_cipher = ptr::null_mut();
        c.cipher = cipher;
        let size = usize::try_from(m.legacy_fns().ctx_size).unwrap_or(0);
        if size > 0 {
            c.cipher_data = mem::alloc_zeroed(size);
            if c.cipher_data.is_null() {
                c.cipher = ptr::null();
                return 0;
            }
        } else {
            c.cipher_data = ptr::null_mut();
        }
        c.key_len = m.key_len();
        c.flags &= flag(EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
        if m.flags() & flag(EVP_CIPH_CTRL_INIT) != 0 {
            // SAFETY: the caller's context.
            if unsafe { EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_INIT, 0, ptr::null_mut()) } <= 0 {
                // SAFETY: as above.
                if let Some(c) = unsafe { context(ctx) } {
                    c.cipher = ptr::null();
                }
                err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
                return 0;
            }
        }
    }
    // SAFETY: as above.
    let Some(c) = (unsafe { context(ctx) }) else {
        return 0;
    };
    let Some(m) = c.cipher() else { return 0 };
    let block = m.block_size();
    if !matches!(block, 1 | 8 | 16) {
        // `OPENSSL_assert` of the block size.
        crate::ffi::die(
            "ctx->cipher->block_size == 1 || ctx->cipher->block_size == 8 || ctx->cipher->block_size == 16",
        );
    }
    let flags = m.flags();
    let mode = flags & flag(EVP_CIPH_MODE);
    if c.flags & flag(EVP_CIPHER_CTX_FLAG_WRAP_ALLOW) == 0 && mode == flag(EVP_CIPH_WRAP_MODE) {
        err::raise(ERR_LIB_EVP, EVP_R_WRAP_MODE_NOT_ALLOWED, F);
        return 0;
    }
    if flags & flag(EVP_CIPH_CUSTOM_IV) == 0 {
        let max = c.iv.len();
        match mode {
            m if m == flag(EVP_CIPH_STREAM_CIPHER) || m == flag(EVP_CIPH_ECB_MODE) => {}
            m if m == flag(EVP_CIPH_CFB_MODE)
                || m == flag(EVP_CIPH_OFB_MODE)
                || m == flag(EVP_CIPH_CBC_MODE) =>
            {
                if m != flag(EVP_CIPH_CBC_MODE) {
                    c.num = 0;
                }
                // SAFETY: the caller's context.
                let n = unsafe { iv_length(ctx) };
                let Some(n) = usize::try_from(n).ok().filter(|n| *n <= max) else {
                    err::raise(ERR_LIB_EVP, EVP_R_INVALID_IV_LENGTH, F);
                    return 0;
                };
                // SAFETY: as above (the length may have come from the cipher's `ctrl`).
                let Some(c) = (unsafe { context(ctx) }) else {
                    return 0;
                };
                if !iv.is_null() {
                    // SAFETY: the caller's IV of the cipher's IV length.
                    let src = unsafe { core::slice::from_raw_parts(iv, n) };
                    if let Some(d) = c.oiv.get_mut(..n) {
                        d.copy_from_slice(src);
                    }
                }
                let oiv = c.oiv;
                if let (Some(d), Some(s)) = (c.iv.get_mut(..n), oiv.get(..n)) {
                    d.copy_from_slice(s);
                }
            }
            m if m == flag(EVP_CIPH_CTR_MODE) => {
                c.num = 0;
                if !iv.is_null() {
                    // SAFETY: the caller's context.
                    let n = unsafe { iv_length(ctx) };
                    let Some(n) = usize::try_from(n).ok().filter(|n| *n > 0 && *n <= max) else {
                        err::raise(ERR_LIB_EVP, EVP_R_INVALID_IV_LENGTH, F);
                        return 0;
                    };
                    // SAFETY: as above.
                    let Some(c) = (unsafe { context(ctx) }) else {
                        return 0;
                    };
                    // SAFETY: the caller's IV of the cipher's IV length.
                    let src = unsafe { core::slice::from_raw_parts(iv, n) };
                    if let Some(d) = c.iv.get_mut(..n) {
                        d.copy_from_slice(src);
                    }
                }
            }
            _ => return 0,
        }
    }
    // SAFETY: as above.
    let Some((l, flags, _)) = (unsafe { legacy_of(ctx) }) else {
        return 0;
    };
    if !key.is_null() || flags & flag(EVP_CIPH_ALWAYS_CALL_INIT) != 0 {
        let Some(init) = l.init else {
            // OpenSSL calls the missing function and crashes.
            err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
            return 0;
        };
        // SAFETY: the cipher's function with the caller's context, key, and IV.
        if unsafe { init(ctx, key, iv, enc) } == 0 {
            return 0;
        }
    }
    // SAFETY: as above.
    let Some(c) = (unsafe { context(ctx) }) else {
        return 0;
    };
    c.buf_len = 0;
    c.final_used = 0;
    c.block_mask = block.saturating_sub(1);
    1
}

/// `evp_EncryptDecryptUpdate`: whole blocks through `do_cipher`, a partial one kept in `buf`
/// (or everything to a cipher that does its own buffering).
///
/// # Safety
/// `ctx` is a live cipher context with a legacy cipher; `out` has room for `inl` octets plus
/// a block; `input` holds `inl` octets; `outl` is valid for writes.
unsafe fn encrypt_decrypt_update(
    ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut u8,
    outl: *mut c_int,
    mut input: *const u8,
    mut inl: c_int,
) -> c_int {
    const F: &str = "evp_EncryptDecryptUpdate";
    // SAFETY: the caller's guarantee.
    let Some((l, flags, bl)) = (unsafe { legacy_of(ctx) }) else {
        return 0;
    };
    // SAFETY: as above.
    let Some(c) = (unsafe { context(ctx) }) else {
        return 0;
    };
    let cmpl = compared_len(c.flags, inl);
    if flags & flag(EVP_CIPH_FLAG_CUSTOM_CIPHER) != 0 {
        if bl == 1 && partially_overlapping(out, input, cmpl) {
            err::raise(ERR_LIB_EVP, EVP_R_PARTIALLY_OVERLAPPING, F);
            return 0;
        }
        let len = usize::try_from(inl).unwrap_or(0);
        // SAFETY: the caller's context and buffers.
        let i = unsafe { do_cipher(&l, ctx, out, input, len) };
        if i < 0 {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { outl.write(i) };
        return 1;
    }
    if inl <= 0 {
        // SAFETY: the caller's guarantee.
        unsafe { outl.write(0) };
        return c_int::from(inl == 0);
    }
    let buf_len = usize::try_from(c.buf_len).unwrap_or(0);
    if partially_overlapping(out.wrapping_add(buf_len), input, cmpl) {
        err::raise(ERR_LIB_EVP, EVP_R_PARTIALLY_OVERLAPPING, F);
        return 0;
    }
    let len = usize::try_from(inl).unwrap_or(0);
    if c.buf_len == 0 && inl & c.block_mask == 0 {
        // SAFETY: the caller's context and buffers.
        let ok = unsafe { do_cipher(&l, ctx, out, input, len) } != 0;
        // SAFETY: the caller's guarantee.
        unsafe { outl.write(if ok { inl } else { 0 }) };
        return c_int::from(ok);
    }
    let i = c.buf_len;
    let b = usize::try_from(bl).unwrap_or(0);
    if b > MAX_BLOCK {
        crate::ffi::die("bl <= (int)sizeof(ctx->buf)");
    }
    if i != 0 {
        let at = usize::try_from(i).unwrap_or(0);
        if bl - i > inl {
            // SAFETY: the caller's `inl` octets.
            let src = unsafe { core::slice::from_raw_parts(input, len) };
            if let Some(d) = c.buf.get_mut(at..at.saturating_add(len)) {
                d.copy_from_slice(src);
            }
            c.buf_len = c.buf_len.saturating_add(inl);
            // SAFETY: the caller's guarantee.
            unsafe { outl.write(0) };
            return 1;
        }
        let j = bl - i;
        if (inl - j) & !(bl - 1) > c_int::MAX - bl {
            err::raise(ERR_LIB_EVP, EVP_R_OUTPUT_WOULD_OVERFLOW, F);
            return 0;
        }
        let ju = usize::try_from(j).unwrap_or(0);
        // SAFETY: the first `j` of the caller's octets.
        let src = unsafe { core::slice::from_raw_parts(input, ju) };
        if let Some(d) = c.buf.get_mut(at..at.saturating_add(ju)) {
            d.copy_from_slice(src);
        }
        inl -= j;
        input = input.wrapping_add(ju);
        // SAFETY: the caller's context, room for a block, and the context's own buffer.
        if unsafe { do_cipher(&l, ctx, out, buf_ptr(ctx), b) } == 0 {
            return 0;
        }
        out = out.wrapping_add(b);
        // SAFETY: the caller's guarantee.
        unsafe { outl.write(bl) };
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { outl.write(0) };
    }
    let rest = inl & (bl - 1);
    inl -= rest;
    let whole = usize::try_from(inl).unwrap_or(0);
    if inl > 0 {
        // SAFETY: the caller's context and buffers.
        if unsafe { do_cipher(&l, ctx, out, input, whole) } == 0 {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let so_far = unsafe { outl.read() };
        // SAFETY: as above.
        unsafe { outl.write(so_far.saturating_add(inl)) };
    }
    // SAFETY: as above (the calls may have used the context).
    let Some(c) = (unsafe { context(ctx) }) else {
        return 0;
    };
    if rest != 0 {
        let r = usize::try_from(rest).unwrap_or(0);
        // SAFETY: the last `rest` of the caller's octets.
        let src = unsafe { core::slice::from_raw_parts(input.wrapping_add(whole), r) };
        if let Some(d) = c.buf.get_mut(..r) {
            d.copy_from_slice(src);
        }
    }
    c.buf_len = rest;
    1
}

/// The legacy `EVP_EncryptUpdate`/`EVP_DecryptUpdate` (the checks before it done): decrypting
/// with padding holds back the last whole block for the final.
///
/// # Safety
/// As for [`encrypt_decrypt_update`].
pub(super) unsafe fn update(
    ctx: *mut EVP_CIPHER_CTX,
    mut out: *mut u8,
    outl: *mut c_int,
    input: *const u8,
    inl: c_int,
    encrypting: bool,
) -> c_int {
    const F: &str = "EVP_DecryptUpdate";
    if encrypting {
        // SAFETY: the caller's guarantee.
        return unsafe { encrypt_decrypt_update(ctx, out, outl, input, inl) };
    }
    // SAFETY: the caller's guarantee.
    let Some((l, flags, b)) = (unsafe { legacy_of(ctx) }) else {
        return 0;
    };
    // SAFETY: as above.
    let Some(c) = (unsafe { context(ctx) }) else {
        return 0;
    };
    let cmpl = compared_len(c.flags, inl);
    if flags & flag(EVP_CIPH_FLAG_CUSTOM_CIPHER) != 0 {
        if b == 1 && partially_overlapping(out, input, cmpl) {
            err::raise(ERR_LIB_EVP, EVP_R_PARTIALLY_OVERLAPPING, F);
            return 0;
        }
        let len = usize::try_from(inl).unwrap_or(0);
        // SAFETY: the caller's context and buffers.
        let fix_len = unsafe { do_cipher(&l, ctx, out, input, len) };
        // SAFETY: the caller's guarantee.
        unsafe { outl.write(fix_len.max(0)) };
        return c_int::from(fix_len >= 0);
    }
    if inl <= 0 {
        // SAFETY: the caller's guarantee.
        unsafe { outl.write(0) };
        return c_int::from(inl == 0);
    }
    if c.flags & flag(EVP_CIPH_NO_PADDING) != 0 {
        // SAFETY: the caller's guarantee.
        return unsafe { encrypt_decrypt_update(ctx, out, outl, input, inl) };
    }
    let bu = usize::try_from(b).unwrap_or(0);
    if bu > MAX_BLOCK {
        crate::ffi::die("b <= sizeof(ctx->final)");
    }
    let fix_len = c.final_used != 0;
    if fix_len {
        if out.cast_const() == input || partially_overlapping(out, input, b) {
            err::raise(ERR_LIB_EVP, EVP_R_PARTIALLY_OVERLAPPING, F);
            return 0;
        }
        if inl & !(b - 1) > c_int::MAX - b {
            err::raise(ERR_LIB_EVP, EVP_R_OUTPUT_WOULD_OVERFLOW, F);
            return 0;
        }
        if let Some(f) = c.final_.get(..bu) {
            // SAFETY: the caller's room for a block before the rest.
            unsafe { ptr::copy_nonoverlapping(f.as_ptr(), out, bu) };
        }
        out = out.wrapping_add(bu);
    }
    // SAFETY: the caller's guarantee.
    if unsafe { encrypt_decrypt_update(ctx, out, outl, input, inl) } == 0 {
        return 0;
    }
    // SAFETY: as above (the calls may have used the context).
    let Some(c) = (unsafe { context(ctx) }) else {
        return 0;
    };
    if b > 1 && c.buf_len == 0 {
        // SAFETY: the caller's guarantee.
        let n = unsafe { outl.read() }.saturating_sub(b);
        // SAFETY: as above.
        unsafe { outl.write(n) };
        c.final_used = 1;
        let at = usize::try_from(n).unwrap_or(0);
        if let Some(d) = c.final_.get_mut(..bu) {
            // SAFETY: the block just written to the caller's buffer.
            unsafe { ptr::copy_nonoverlapping(out.wrapping_add(at), d.as_mut_ptr(), bu) };
        }
    } else {
        c.final_used = 0;
    }
    if fix_len {
        // SAFETY: the caller's guarantee.
        let so_far = unsafe { outl.read() };
        // SAFETY: as above.
        unsafe { outl.write(so_far.saturating_add(b)) };
    }
    1
}

/// The legacy `EVP_EncryptFinal_ex`/`EVP_DecryptFinal_ex` (the checks before it done):
/// encrypting pads the buffered octets to a block; decrypting checks the held-back block's
/// padding (in constant time) and gives what's before it.
///
/// # Safety
/// `ctx` is a live cipher context with a legacy cipher; `out` has room for a block; `outl` is
/// valid for writes.
pub(super) unsafe fn finalize(
    ctx: *mut EVP_CIPHER_CTX,
    out: *mut u8,
    outl: *mut c_int,
    encrypting: bool,
) -> c_int {
    let f = if encrypting {
        "EVP_EncryptFinal_ex"
    } else {
        "EVP_DecryptFinal_ex"
    };
    // SAFETY: the caller's guarantee.
    let Some((l, flags, b)) = (unsafe { legacy_of(ctx) }) else {
        return 0;
    };
    if flags & flag(EVP_CIPH_FLAG_CUSTOM_CIPHER) != 0 {
        // SAFETY: the caller's context and buffer.
        let i = unsafe { do_cipher(&l, ctx, out, ptr::null(), 0) };
        if i < 0 {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { outl.write(i) };
        return 1;
    }
    let bu = usize::try_from(b).unwrap_or(0);
    if bu > MAX_BLOCK {
        crate::ffi::die("b <= sizeof(ctx->buf)");
    }
    // SAFETY: as above.
    let Some(c) = (unsafe { context(ctx) }) else {
        return 0;
    };
    if encrypting {
        if b == 1 {
            return 1;
        }
        if c.flags & flag(EVP_CIPH_NO_PADDING) != 0 {
            if c.buf_len != 0 {
                err::raise(ERR_LIB_EVP, EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH, f);
                return 0;
            }
            return 1;
        }
        let bl = usize::try_from(c.buf_len).unwrap_or(0);
        let n = u8::try_from(bu.saturating_sub(bl)).unwrap_or(0);
        for v in c.buf.iter_mut().take(bu).skip(bl) {
            *v = n;
        }
        // SAFETY: the caller's context and room for a block, and the context's own buffer.
        let ret = unsafe { do_cipher(&l, ctx, out, buf_ptr(ctx), bu) };
        if ret != 0 {
            // SAFETY: the caller's guarantee.
            unsafe { outl.write(b) };
        }
        return ret;
    }
    if c.flags & flag(EVP_CIPH_NO_PADDING) != 0 {
        if c.buf_len != 0 {
            err::raise(ERR_LIB_EVP, EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH, f);
            return 0;
        }
        return 1;
    }
    if b > 1 {
        if c.buf_len != 0 || c.final_used == 0 {
            err::raise(ERR_LIB_EVP, EVP_R_WRONG_FINAL_BLOCK_LENGTH, f);
            return 0;
        }
        let Some(block) = c.final_.get(..bu) else {
            return 0;
        };
        let Some(n) = check_padding(block) else {
            err::raise(ERR_LIB_EVP, EVP_R_BAD_DECRYPT, f);
            return 0;
        };
        let keep = bu - n;
        if let Some(src) = block.get(..keep) {
            // SAFETY: the caller's room for a block.
            unsafe { ptr::copy_nonoverlapping(src.as_ptr(), out, keep) };
        }
        // SAFETY: the caller's guarantee.
        unsafe { outl.write(c_int::try_from(keep).unwrap_or(0)) };
    }
    1
}

/// The padding length of a decrypted block (1 to its length, each padding octet equal to it),
/// checked without branching on the octets; `None` if it's bad.
fn check_padding(block: &[u8]) -> Option<usize> {
    let len = block.len();
    let last = block.last().copied().unwrap_or(0);
    let n = usize::from(last);
    // All ones when n is within 1..=len.
    let in_range = ct_le(1, n) & ct_le(n, len);
    let mut good = in_range;
    for (i, &v) in block.iter().enumerate() {
        // Positions from the end below n must equal `last`.
        let from_end = len - 1 - i;
        let in_pad = ct_lt(from_end, n);
        let differs = ct_nonzero(usize::from(v ^ last));
        good &= !(in_pad & differs);
    }
    (good == usize::MAX).then_some(n)
}

/// All ones if `a < b`, else zero, without a branch (for values below `usize::MAX / 2`).
fn ct_lt(a: usize, b: usize) -> usize {
    0usize.wrapping_sub(a.wrapping_sub(b) >> (usize::BITS - 1))
}

/// All ones if `a <= b`, else zero.
fn ct_le(a: usize, b: usize) -> usize {
    !ct_lt(b, a)
}

/// All ones if `x != 0`, else zero.
fn ct_nonzero(x: usize) -> usize {
    0usize.wrapping_sub((x | x.wrapping_neg()) >> (usize::BITS - 1))
}

/// The legacy `EVP_CIPHER_CTX_ctrl`: the cipher's `ctrl`, whose -1 means unsupported.
///
/// # Safety
/// `ctx` is a live cipher context with a legacy cipher; `ptr` is what the command takes.
pub(super) unsafe fn ctrl(
    ctx: *mut EVP_CIPHER_CTX,
    type_: c_int,
    arg: c_int,
    ptr: *mut c_void,
) -> c_int {
    const F: &str = "EVP_CIPHER_CTX_ctrl";
    // SAFETY: the caller's guarantee.
    let Some(f) = (unsafe { legacy_of(ctx) }).and_then(|(l, _, _)| l.ctrl) else {
        err::raise(ERR_LIB_EVP, EVP_R_CTRL_NOT_IMPLEMENTED, F);
        return 0;
    };
    // SAFETY: the cipher's function with the caller's context and arguments.
    let ret = unsafe { f(ctx, type_, arg, ptr) };
    if ret == -1 {
        err::raise(ERR_LIB_EVP, EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED, F);
        return 0;
    }
    ret
}

/// The legacy `EVP_CIPHER_CTX_set_key_length`: the cipher's `ctrl` for one with
/// `EVP_CIPH_CUSTOM_KEY_LENGTH`, else any positive length for a variable-length cipher.
///
/// # Safety
/// `ctx` is a live cipher context with a legacy cipher.
pub(super) unsafe fn set_key_length(ctx: *mut EVP_CIPHER_CTX, keylen: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some((_, flags, _)) = (unsafe { legacy_of(ctx) }) else {
        return 0;
    };
    if flags & flag(EVP_CIPH_CUSTOM_KEY_LENGTH) != 0 {
        // SAFETY: the caller's context.
        return unsafe {
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_SET_KEY_LENGTH, keylen, ptr::null_mut())
        };
    }
    // SAFETY: as above.
    let Some(c) = (unsafe { context(ctx) }) else {
        return 0;
    };
    if c.key_len == keylen {
        return 1;
    }
    if keylen > 0 && flags & flag(EVP_CIPH_VARIABLE_LENGTH) != 0 {
        c.key_len = keylen;
        return 1;
    }
    err::raise(
        ERR_LIB_EVP,
        EVP_R_INVALID_KEY_LENGTH,
        "EVP_CIPHER_CTX_set_key_length",
    );
    0
}

/// The legacy `EVP_CIPHER_CTX_copy`: `out` a field-by-field copy of `in_` with its own copy of
/// the state, then `EVP_CTRL_COPY` for a cipher with `EVP_CIPH_CUSTOM_COPY`.
///
/// # Safety
/// `out` and `in_` are live cipher contexts; `in_`'s cipher is a legacy one.
pub(super) unsafe fn copy(out: *mut EVP_CIPHER_CTX, in_: *const EVP_CIPHER_CTX) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some((l, flags, _)) = (unsafe { legacy_of(in_.cast_mut()) }) else {
        return 0;
    };
    // SAFETY: the caller's guarantee.
    unsafe { EVP_CIPHER_CTX_reset(out) };
    // SAFETY: as above.
    let Some(src) = (unsafe { context(in_) }) else {
        return 0;
    };
    let src_data = src.cipher_data;
    let copy = CipherCtx { ..*src };
    // SAFETY: as above.
    let Some(dst) = (unsafe { context(out) }) else {
        return 0;
    };
    *dst = copy;
    dst.algctx = ptr::null_mut();
    dst.fetched_cipher = ptr::null_mut();
    dst.cipher_data = ptr::null_mut();
    let size = usize::try_from(l.ctx_size).unwrap_or(0);
    if !src_data.is_null() && size > 0 {
        let data = mem::alloc(size);
        if data.is_null() {
            dst.cipher = ptr::null();
            return 0;
        }
        // SAFETY: both hold the cipher's state size; different allocations.
        unsafe { ptr::copy_nonoverlapping(src_data.cast::<u8>(), data.cast::<u8>(), size) };
        dst.cipher_data = data;
    }
    if flags & flag(EVP_CIPH_CUSTOM_COPY) != 0 {
        let ok = match l.ctrl {
            // SAFETY: the cipher's function with the source context and the copy.
            Some(f) => (unsafe { f(in_.cast_mut(), EVP_CTRL_COPY, 0, out.cast()) }) != 0,
            None => false,
        };
        if !ok {
            // SAFETY: as above.
            if let Some(dst) = unsafe { context(out) } {
                dst.cipher = ptr::null();
            }
            err::raise(
                ERR_LIB_EVP,
                EVP_R_INITIALIZATION_ERROR,
                "EVP_CIPHER_CTX_copy",
            );
            return 0;
        }
    }
    1
}

/// The legacy `EVP_Cipher`: the cipher's `do_cipher` itself.
///
/// # Safety
/// `ctx` is a live cipher context with a legacy cipher; the buffers are what it takes.
pub(super) unsafe fn cipher(
    ctx: *mut EVP_CIPHER_CTX,
    out: *mut u8,
    input: *const u8,
    inl: usize,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some((l, _, _)) = (unsafe { legacy_of(ctx) }) else {
        return 0;
    };
    // SAFETY: as above.
    unsafe { do_cipher(&l, ctx, out, input, inl) }
}

/// The cipher's own `set_asn1_parameters` or `get_asn1_parameters`, if it has one.
///
/// # Safety
/// `ctx` is NULL or a live cipher context.
pub(crate) unsafe fn asn1_fn(
    ctx: *mut EVP_CIPHER_CTX,
    set: bool,
) -> Option<super::super::cipher::LegacyAsn1Fn> {
    // SAFETY: the caller's guarantee.
    let (l, _, _) = unsafe { legacy_of(ctx) }?;
    if set { l.set_asn1 } else { l.get_asn1 }
}

#[cfg(test)]
mod tests {
    use super::super::{
        EVP_CIPHER_CTX_copy, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_get_cipher_data,
        EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_set_cipher_data, EVP_CipherInit_ex,
    };
    use super::*;
    use crate::evp::cipher_meth::{EVP_CIPHER_meth_free, EVP_CIPHER_meth_new};

    /// OpenSSL's octet-by-octet check, which `check_padding` must agree with.
    fn naive(block: &[u8]) -> Option<usize> {
        let n = usize::from(*block.last()?);
        if n == 0 || n > block.len() {
            return None;
        }
        block[block.len() - n..]
            .iter()
            .all(|&v| usize::from(v) == n)
            .then_some(n)
    }

    /// docs/DEVIATIONS.md: the padding of an application's cipher's last block is checked in
    /// constant time, with OpenSSL's results: every last octet, with the padding intact and
    /// with each of its octets (and the one before it) changed.
    #[test]
    #[allow(clippy::indexing_slicing)]
    fn padding_check_matches_openssl() {
        for len in [8usize, 16] {
            for last in 0..=255u8 {
                let mut block = vec![0x5a; len];
                let n = usize::from(last).min(len);
                for v in &mut block[len - n..] {
                    *v = last;
                }
                assert_eq!(check_padding(&block), naive(&block), "{len} {last}");
                for i in 0..len {
                    let mut bad = block.clone();
                    bad[i] ^= 0x01;
                    assert_eq!(check_padding(&bad), naive(&bad), "{len} {last} {i}");
                }
            }
        }
    }

    /// docs/DEVIATIONS.md: copying a context whose application cipher has no state size but
    /// was given state (`EVP_CIPHER_CTX_set_cipher_data`) leaves the copy without it, where
    /// OpenSSL shares the pointer and both contexts free it.
    #[test]
    fn copy_does_not_share_unsized_state() {
        // SAFETY: no preconditions.
        let cipher = unsafe { EVP_CIPHER_meth_new(0, 1, 0) };
        // SAFETY: no preconditions.
        let ctx = unsafe { EVP_CIPHER_CTX_new() };
        // SAFETY: as above.
        let out = unsafe { EVP_CIPHER_CTX_new() };
        // SAFETY: a new context and cipher, no key (so no `init` to call).
        let init =
            unsafe { EVP_CipherInit_ex(ctx, cipher, ptr::null_mut(), ptr::null(), ptr::null(), 1) };
        assert_eq!(init, 1);
        // SAFETY: the context takes the allocation.
        unsafe { EVP_CIPHER_CTX_set_cipher_data(ctx, mem::alloc(8)) };
        // SAFETY: two live contexts.
        assert_eq!(unsafe { EVP_CIPHER_CTX_copy(out, ctx) }, 1);
        // SAFETY: as above.
        assert!(unsafe { EVP_CIPHER_CTX_get_cipher_data(out) }.is_null());
        // SAFETY: as above.
        assert!(!unsafe { EVP_CIPHER_CTX_get_cipher_data(ctx) }.is_null());
        // SAFETY: each freed once.
        unsafe { EVP_CIPHER_CTX_free(out) };
        // SAFETY: as above.
        unsafe { EVP_CIPHER_CTX_free(ctx) };
        // SAFETY: as above.
        unsafe { EVP_CIPHER_meth_free(cipher) };
    }
}
