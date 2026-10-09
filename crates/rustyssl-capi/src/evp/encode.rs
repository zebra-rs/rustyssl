//! Base64 (`EVP_EncodeInit(3)`, `EVP_EncodeUpdate`, `EVP_EncodeFinal`, `EVP_EncodeBlock`, the
//! `EVP_Decode*` counterparts, and `EVP_ENCODE_CTX_new`/`free`/`copy`/`num`) over
//! `rustyssl_asn1::base64`, which keeps OpenSSL's state and quirks.
//!
//! The output buffers are the caller's, unsized as in C: the man page gives the room each call
//! needs, and the octets (and the NUL OpenSSL writes after them) are copied there.

use core::ffi::{c_int, c_uchar};
use core::ptr;

use rustyssl_abi::{ERR_LIB_EVP, EVP_ENCODE_CTX};
use rustyssl_asn1::base64::{self, Ctx};

use crate::ffi::ffi_export;
use crate::mem;

/// The context behind an `EVP_ENCODE_CTX *`, or `None` for NULL.
///
/// # Safety
/// `ctx` is NULL or a live context from `EVP_ENCODE_CTX_new`.
unsafe fn context<'a>(ctx: *mut EVP_ENCODE_CTX) -> Option<&'a mut Ctx> {
    // SAFETY: the caller's guarantee; any bit pattern is a valid `Ctx`.
    unsafe { ctx.cast::<Ctx>().as_mut() }
}

/// The input `in_` and `inl` describe: empty for a non-positive length or NULL.
///
/// # Safety
/// `in_` is NULL or holds `inl` octets.
unsafe fn input<'a>(in_: *const c_uchar, inl: c_int) -> &'a [u8] {
    match usize::try_from(inl) {
        // SAFETY: the caller's guarantee.
        Ok(n) if n > 0 && !in_.is_null() => unsafe { core::slice::from_raw_parts(in_, n) },
        _ => &[],
    }
}

/// Copies `data` to `out`, then a NUL if `nul`; returns the length as an `int`.
///
/// # Safety
/// `out` has room for `data` and the NUL.
unsafe fn emit(out: *mut c_uchar, data: &[u8], nul: bool) -> c_int {
    if !data.is_empty() {
        // SAFETY: the caller's guarantee.
        unsafe { ptr::copy_nonoverlapping(data.as_ptr(), out, data.len()) };
    }
    if nul {
        // SAFETY: as above; the octet after the data.
        unsafe { out.wrapping_add(data.len()).write(0) };
    }
    c_int::try_from(data.len()).unwrap_or(c_int::MAX)
}

/// Stores `value` through `outl` unless it's NULL.
///
/// # Safety
/// `outl` is NULL or valid for a write.
unsafe fn store(outl: *mut c_int, value: c_int) {
    if !outl.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { outl.write(value) };
    }
}

ffi_export! {
    /// A new, zeroed context, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_ENCODE_CTX_new() -> *mut EVP_ENCODE_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        mem::alloc_zeroed(size_of::<Ctx>()).cast()
    }
}

ffi_export! {
    /// Frees a context; NULL does nothing.
    ///
    /// # Safety
    /// `ctx` is NULL or a context from `EVP_ENCODE_CTX_new`.
    pub unsafe extern "C" fn EVP_ENCODE_CTX_free(ctx: *mut EVP_ENCODE_CTX)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { mem::release(ctx.cast()) };
    }
}

ffi_export! {
    /// Copies `sctx`'s state into `dctx`. Returns 1.
    ///
    /// Unlike OpenSSL, NULL returns 0 rather than crashing (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// Each is NULL or a live context.
    pub unsafe extern "C" fn EVP_ENCODE_CTX_copy(dctx: *mut EVP_ENCODE_CTX, sctx: *const EVP_ENCODE_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let (Some(d), Some(s)) = (unsafe { context(dctx) }, unsafe { context(sctx.cast_mut()) }) else {
            return 0;
        };
        *d = *s;
        1
    }
}

ffi_export! {
    /// The octets (encoding) or characters (decoding) the context holds.
    ///
    /// # Safety
    /// `ctx` is NULL (0) or a live context.
    pub unsafe extern "C" fn EVP_ENCODE_CTX_num(ctx: *mut EVP_ENCODE_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { context(ctx) }.map_or(0, |c| c.num)
    }
}

ffi_export! {
    /// Starts encoding: lines of 48 octets.
    ///
    /// # Safety
    /// `ctx` is NULL (nothing) or a live context.
    pub unsafe extern "C" fn EVP_EncodeInit(ctx: *mut EVP_ENCODE_CTX)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { context(ctx) } {
            c.encode_init();
        }
    }
}

ffi_export! {
    /// Encodes `inl` octets of `in_`, writing the complete lines (each with a newline, then a
    /// NUL) to `out` and their length to `*outl`. Returns 1, or 0 for no input or too much
    /// output.
    ///
    /// # Safety
    /// `ctx` is a live context; `out` has room for the lines (65 a line, and a NUL); `outl`
    /// is valid for a write; `in_` holds `inl` octets.
    pub unsafe extern "C" fn EVP_EncodeUpdate(ctx: *mut EVP_ENCODE_CTX, out: *mut c_uchar, outl: *mut c_int, in_: *const c_uchar, inl: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { store(outl, 0) };
        // SAFETY: as above.
        let Some(c) = (unsafe { context(ctx) }) else {
            return 0;
        };
        // SAFETY: as above.
        let Some(encoded) = c.encode_update(unsafe { input(in_, inl) }) else {
            return 0;
        };
        // SAFETY: the caller's room.
        let n = unsafe { emit(out, &encoded.out, encoded.nul) };
        // SAFETY: as above.
        unsafe { store(outl, n) };
        1
    }
}

ffi_export! {
    /// Writes the last, short line (with a newline and a NUL) to `out` and its length to
    /// `*outl` (0 if nothing was held).
    ///
    /// # Safety
    /// `ctx` is a live context; `out` has room for 66 octets; `outl` is valid for a write.
    pub unsafe extern "C" fn EVP_EncodeFinal(ctx: *mut EVP_ENCODE_CTX, out: *mut c_uchar, outl: *mut c_int)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let line = unsafe { context(ctx) }.and_then(Ctx::encode_final);
        let n = match line {
            // SAFETY: the caller's room.
            Some(line) => unsafe { emit(out, &line, true) },
            None => 0,
        };
        // SAFETY: as above.
        unsafe { store(outl, n) };
    }
}

ffi_export! {
    /// Encodes `dlen` octets of `f` into `t` as one block of base64 (no newlines), then a NUL.
    /// Returns its length.
    ///
    /// # Safety
    /// `f` holds `dlen` octets; `t` has room for the encoding and the NUL.
    pub unsafe extern "C" fn EVP_EncodeBlock(t: *mut c_uchar, f: *const c_uchar, dlen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let encoded = base64::encode_block(unsafe { input(f, dlen) });
        // SAFETY: as above.
        unsafe { emit(t, &encoded, true) }
    }
}

ffi_export! {
    /// Starts decoding.
    ///
    /// # Safety
    /// `ctx` is NULL (nothing) or a live context.
    pub unsafe extern "C" fn EVP_DecodeInit(ctx: *mut EVP_ENCODE_CTX)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { context(ctx) } {
            c.decode_init();
        }
    }
}

ffi_export! {
    /// Decodes `inl` characters of `in_` (whitespace skipped, `-` ending it), writing the
    /// octets of complete groups to `out` and their count to `*outl`, even on error. Returns -1
    /// on error, 0 once the end (padding, `-`, or an empty input) is seen, else 1.
    ///
    /// # Safety
    /// `ctx` is a live context; `out` has room for the octets (3 for each 4 characters, and
    /// those held); `outl` is valid for a write; `in_` holds `inl` characters.
    pub unsafe extern "C" fn EVP_DecodeUpdate(ctx: *mut EVP_ENCODE_CTX, out: *mut c_uchar, outl: *mut c_int, in_: *const c_uchar, inl: c_int) -> c_int
    where failure = -1, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else {
            // SAFETY: as above.
            unsafe { store(outl, 0) };
            return -1;
        };
        let data = if inl < 0 {
            None
        } else {
            // SAFETY: as above.
            Some(unsafe { input(in_, inl) })
        };
        let decoded = c.decode_update(data);
        // SAFETY: the caller's room.
        let n = unsafe { emit(out, &decoded.out, false) };
        // SAFETY: as above.
        unsafe { store(outl, n) };
        decoded.ret
    }
}

ffi_export! {
    /// Decodes what is held, writing the octets to `out` and their count to `*outl`. Returns 1,
    /// or -1 if it doesn't decode.
    ///
    /// # Safety
    /// `ctx` is a live context; `out` has room for 48 octets; `outl` is valid for a write.
    pub unsafe extern "C" fn EVP_DecodeFinal(ctx: *mut EVP_ENCODE_CTX, out: *mut c_uchar, outl: *mut c_int) -> c_int
    where failure = -1, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { store(outl, 0) };
        // SAFETY: as above.
        let Some(c) = (unsafe { context(ctx) }) else {
            return -1;
        };
        let Some(octets) = c.decode_final() else {
            return -1;
        };
        // SAFETY: the caller's room.
        let n = unsafe { emit(out, &octets, false) };
        // SAFETY: as above.
        unsafe { store(outl, n) };
        1
    }
}

ffi_export! {
    /// Decodes `n` characters of `f` (leading whitespace and trailing line ends skipped) into
    /// `t`, 3 octets for each 4 characters, padding included. Returns the count, or -1.
    ///
    /// Unlike OpenSSL, a negative `n` is -1 rather than a read of 4 characters
    /// (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `f` holds `n` characters; `t` has room for the octets.
    pub unsafe extern "C" fn EVP_DecodeBlock(t: *mut c_uchar, f: *const c_uchar, n: c_int) -> c_int
    where failure = -1, library = ERR_LIB_EVP
    {
        if n < 0 {
            return -1;
        }
        // SAFETY: the caller's guarantee.
        match base64::decode_block(unsafe { input(f, n) }) {
            // SAFETY: as above.
            Some(octets) => unsafe { emit(t, &octets, false) },
            None => -1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_and_negative_arguments_are_safe() {
        let mut out = [0u8; 8];
        let mut outl: c_int = 7;
        // SAFETY: NULL contexts are refused.
        let r = unsafe { EVP_ENCODE_CTX_copy(ptr::null_mut(), ptr::null()) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let n = unsafe { EVP_ENCODE_CTX_num(ptr::null_mut()) };
        assert_eq!(n, 0);
        // SAFETY: as above, with room for the output.
        let r = unsafe {
            EVP_DecodeUpdate(
                ptr::null_mut(),
                out.as_mut_ptr(),
                &raw mut outl,
                c"QUJD".as_ptr().cast(),
                4,
            )
        };
        assert_eq!((r, outl), (-1, 0));
        // SAFETY: a negative length reads nothing.
        let r = unsafe { EVP_DecodeBlock(out.as_mut_ptr(), c"QUJD".as_ptr().cast(), -4) };
        assert_eq!(r, -1);
    }
}
