//! The block-mode helpers of `modes.h` (`CRYPTO_cbc128_encrypt` ... `CRYPTO_128_unwrap_pad`),
//! over [`rustyssl_crypto::lowlevel::modes`] with the block, CBC, or CTR function the caller
//! passes.
//!
//! Where OpenSSL calls a null function or dereferences a null buffer, IV, or position and
//! crashes, these do nothing (returning 0), and a position past the block is refused where
//! OpenSSL reads out of bounds (docs/DEVIATIONS.md).

use core::ffi::{c_int, c_uchar, c_uint, c_void};

use rustyssl_abi::{ERR_LIB_CRYPTO, block128_f, cbc128_f, ctr128_f};
use rustyssl_crypto::lowlevel::modes::{self, BLOCK, Block128};

use super::{CBlock, CCbc, CCtr, buffers, read_array, write_array};
use crate::ffi::ffi_export;

/// `len` rounded up to whole blocks.
fn whole_blocks(len: usize) -> Option<usize> {
    len.checked_next_multiple_of(BLOCK)
}

/// Runs `run` over the caller's buffers and IV, writing the IV back after. Does nothing for a
/// null buffer (with a length) or IV.
///
/// # Safety
/// As for [`buffers`]; `ivec` is null or valid for 16 octets of reads and writes.
pub(crate) unsafe fn with_iv<R>(
    input: *const c_uchar,
    in_len: usize,
    out: *mut c_uchar,
    out_len: usize,
    ivec: *mut c_uchar,
    run: impl FnOnce(&[u8], &mut [u8], &mut [u8; BLOCK]) -> R,
) -> Option<R> {
    // SAFETY: the caller's guarantee.
    let mut iv = unsafe { read_array::<BLOCK>(ivec) }?;
    // SAFETY: the caller's guarantee.
    let (input, out) = unsafe { buffers(input, in_len, out, out_len) }?;
    let result = run(&input, out, &mut iv);
    // SAFETY: the caller's IV, read above.
    unsafe { write_array(ivec, &iv) };
    Some(result)
}

/// The caller's block function.
fn block(f: block128_f, key: *const c_void) -> Option<CBlock> {
    f.map(|f| CBlock { f, key })
}

/// The caller's CBC function.
fn cbc(f: cbc128_f, key: *const c_void) -> Option<CCbc> {
    f.map(|f| CCbc { f, key })
}

/// CBC encryption of `len` octets, a partial last block padded and written whole.
///
/// # Safety
/// `input` holds `len` octets; `out` has room for `len` rounded up to whole blocks; `ivec`
/// holds 16; `block` is null or a block function for `key`.
pub(crate) unsafe fn cbc_encrypt(
    input: *const c_uchar,
    out: *mut c_uchar,
    len: usize,
    ivec: *mut c_uchar,
    b: &impl Block128,
) {
    if len == 0 {
        return;
    }
    let Some(out_len) = whole_blocks(len) else {
        return;
    };
    // SAFETY: the caller's guarantee.
    unsafe {
        with_iv(input, len, out, out_len, ivec, |i, o, iv| {
            modes::cbc_encrypt(i, o, iv, b)
        })
    };
}

/// CBC decryption of `len` octets, a partial last block read whole.
///
/// # Safety
/// `input` holds `len` rounded up to whole blocks; `out` has room for `len`; `ivec` holds 16.
pub(crate) unsafe fn cbc_decrypt(
    input: *const c_uchar,
    out: *mut c_uchar,
    len: usize,
    ivec: *mut c_uchar,
    b: &impl Block128,
) {
    if len == 0 {
        return;
    }
    let Some(in_len) = whole_blocks(len) else {
        return;
    };
    // SAFETY: the caller's guarantee.
    unsafe {
        with_iv(input, in_len, out, len, ivec, |i, o, iv| {
            modes::cbc_decrypt(i, o, len, iv, b)
        })
    };
}

ffi_export! {
    /// CBC-encrypts `len` octets from `in_` into `out` with `block` under `key`, chaining from
    /// and updating `ivec`; a partial last block is padded and written whole.
    ///
    /// # Safety
    /// `in_` holds `len` octets; `out` has room for `len` rounded up to whole blocks; `ivec`
    /// holds 16; `block` is null or a block function for `key`.
    pub unsafe extern "C" fn CRYPTO_cbc128_encrypt(in_: *const c_uchar, out: *mut c_uchar, len: usize, key: *const c_void, ivec: *mut c_uchar, block: block128_f)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let Some(b) = self::block(block, key) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { cbc_encrypt(in_, out, len, ivec, &b) }
    }
}

ffi_export! {
    /// CBC-decrypts `len` octets from `in_` into `out` with `block` under `key`, chaining from
    /// and updating `ivec`; a partial last block is read whole.
    ///
    /// # Safety
    /// `in_` holds `len` rounded up to whole blocks; `out` has room for `len`; `ivec` holds
    /// 16; `block` is null or a block function for `key`.
    pub unsafe extern "C" fn CRYPTO_cbc128_decrypt(in_: *const c_uchar, out: *mut c_uchar, len: usize, key: *const c_void, ivec: *mut c_uchar, block: block128_f)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let Some(b) = self::block(block, key) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { cbc_decrypt(in_, out, len, ivec, &b) }
    }
}

/// CTR mode through `run` with the caller's counter block, keystream buffer, and position;
/// nothing for a null one or a position past the block.
///
/// # Safety
/// `input` holds and `out` has room for `len` octets; `ivec` and `ecount_buf` hold 16; `num`
/// is null or valid for reads and writes.
unsafe fn ctr(
    input: *const c_uchar,
    out: *mut c_uchar,
    len: usize,
    ivec: *mut c_uchar,
    ecount_buf: *mut c_uchar,
    num: *mut c_uint,
    run: impl FnOnce(
        &[u8],
        &mut [u8],
        &mut [u8; BLOCK],
        &mut [u8; BLOCK],
        &mut u32,
    ) -> Result<(), modes::Corrupt>,
) {
    // SAFETY: the caller's guarantee.
    let Some(mut n) = (unsafe { num.as_ref() }).copied() else {
        return;
    };
    // SAFETY: the caller's guarantee.
    let Some(mut ecount) = (unsafe { read_array::<BLOCK>(ecount_buf) }) else {
        return;
    };
    // SAFETY: the caller's guarantee.
    let done = unsafe {
        with_iv(input, len, out, len, ivec, |i, o, iv| {
            run(i, o, iv, &mut ecount, &mut n)
        })
    };
    if done == Some(Ok(())) {
        // SAFETY: the caller's keystream buffer and position, read above.
        unsafe { write_array(ecount_buf, &ecount) };
        // SAFETY: as above.
        unsafe { num.write(n) };
    }
}

ffi_export! {
    /// CTR-encrypts (or decrypts) `len` octets with `block` under `key`: `ecount_buf` holds the
    /// keystream block and `*num` the position in it, between calls; `ivec` counts up whole.
    ///
    /// # Safety
    /// `in_` holds and `out` has room for `len` octets; `ivec` and `ecount_buf` hold 16;
    /// `num` is valid for reads and writes; `block` is null or a block function for `key`.
    pub unsafe extern "C" fn CRYPTO_ctr128_encrypt(in_: *const c_uchar, out: *mut c_uchar, len: usize, key: *const c_void, ivec: *mut c_uchar, ecount_buf: *mut c_uchar, num: *mut c_uint, block: block128_f)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let Some(b) = self::block(block, key) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { ctr(in_, out, len, ivec, ecount_buf, num, |i, o, iv, e, n| modes::ctr_encrypt(i, o, iv, e, n, &b)) }
    }
}

ffi_export! {
    /// As `CRYPTO_ctr128_encrypt`, with a function that encrypts whole blocks counting in the
    /// IV's last 32 bits; the carry out of them goes into the first 96 between its calls.
    ///
    /// # Safety
    /// As for `CRYPTO_ctr128_encrypt`, with `func` null or a CTR function for `key`.
    pub unsafe extern "C" fn CRYPTO_ctr128_encrypt_ctr32(in_: *const c_uchar, out: *mut c_uchar, len: usize, key: *const c_void, ivec: *mut c_uchar, ecount_buf: *mut c_uchar, num: *mut c_uint, func: ctr128_f)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let Some(f) = func.map(|f| CCtr { f, key }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { ctr(in_, out, len, ivec, ecount_buf, num, |i, o, iv, e, n| modes::ctr32_encrypt(i, o, iv, e, n, &f)) }
    }
}

/// OFB or CFB through `run` with the caller's IV and position: a negative position becomes -1
/// and nothing else happens, as in OpenSSL; nothing for a null one or a position past the
/// block.
///
/// # Safety
/// `input` holds and `out` has room for `len` octets; `ivec` holds 16; `num` is null or valid
/// for reads and writes.
pub(crate) unsafe fn stream(
    input: *const c_uchar,
    out: *mut c_uchar,
    len: usize,
    ivec: *mut c_uchar,
    num: *mut c_int,
    run: impl FnOnce(&[u8], &mut [u8], &mut [u8; BLOCK], &mut i32) -> Result<(), modes::Corrupt>,
) {
    // SAFETY: the caller's guarantee.
    let Some(mut n) = (unsafe { num.as_ref() }).copied() else {
        return;
    };
    if n < 0 {
        // SAFETY: the caller's position.
        unsafe { num.write(-1) };
        return;
    }
    // SAFETY: the caller's guarantee.
    let done = unsafe { with_iv(input, len, out, len, ivec, |i, o, iv| run(i, o, iv, &mut n)) };
    if done == Some(Ok(())) {
        // SAFETY: the caller's position, read above.
        unsafe { num.write(n) };
    }
}

ffi_export! {
    /// OFB-encrypts (or decrypts) `len` octets with `block` under `key`: `ivec` is the
    /// keystream block and `*num` the position in it.
    ///
    /// # Safety
    /// `in_` holds and `out` has room for `len` octets; `ivec` holds 16; `num` is valid for
    /// reads and writes; `block` is null or a block function for `key`.
    pub unsafe extern "C" fn CRYPTO_ofb128_encrypt(in_: *const c_uchar, out: *mut c_uchar, len: usize, key: *const c_void, ivec: *mut c_uchar, num: *mut c_int, block: block128_f)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let Some(b) = self::block(block, key) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { stream(in_, out, len, ivec, num, |i, o, iv, n| modes::ofb_encrypt(i, o, iv, n, &b)) }
    }
}

ffi_export! {
    /// CFB-encrypts (`enc` nonzero) or decrypts `len` octets with `block` under `key`: `ivec`
    /// becomes the ciphertext as it goes, `*num` the position in it.
    ///
    /// # Safety
    /// As for `CRYPTO_ofb128_encrypt`.
    pub unsafe extern "C" fn CRYPTO_cfb128_encrypt(in_: *const c_uchar, out: *mut c_uchar, len: usize, key: *const c_void, ivec: *mut c_uchar, num: *mut c_int, enc: c_int, block: block128_f)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let Some(b) = self::block(block, key) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { stream(in_, out, len, ivec, num, |i, o, iv, n| modes::cfb_encrypt(i, o, iv, n, enc != 0, &b)) }
    }
}

ffi_export! {
    /// CFB-8: `length` octets, a block function call each. `num` isn't used.
    ///
    /// # Safety
    /// `in_` holds and `out` has room for `length` octets; `ivec` holds 16; `block` is null or
    /// a block function for `key`.
    pub unsafe extern "C" fn CRYPTO_cfb128_8_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: usize, key: *const c_void, ivec: *mut c_uchar, num: *mut c_int, enc: c_int, block: block128_f)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let _ = num;
        let Some(b) = self::block(block, key) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { with_iv(in_, length, out, length, ivec, |i, o, iv| modes::cfb8_encrypt(i, o, iv, enc != 0, &b)) };
    }
}

ffi_export! {
    /// CFB-1: `bits` bits, most significant first, a block function call each; the other bits
    /// of the last output octet keep their values. `num` isn't used.
    ///
    /// # Safety
    /// `in_` holds and `out` has room for `bits` bits rounded up to octets; `ivec` holds 16;
    /// `block` is null or a block function for `key`.
    pub unsafe extern "C" fn CRYPTO_cfb128_1_encrypt(in_: *const c_uchar, out: *mut c_uchar, bits: usize, key: *const c_void, ivec: *mut c_uchar, num: *mut c_int, enc: c_int, block: block128_f)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let _ = num;
        let Some(b) = self::block(block, key) else { return };
        let octets = bits.div_ceil(8);
        // SAFETY: the caller's guarantee.
        unsafe { with_iv(in_, octets, out, octets, ivec, |i, o, iv| modes::cfb1_encrypt(i, o, bits, iv, enc != 0, &b)) };
    }
}

/// Ciphertext stealing through `run` over `len` octets each way; 0 for a null buffer or IV.
///
/// # Safety
/// `input` holds and `out` has room for `len` octets; `ivec` holds 16.
unsafe fn cts(
    input: *const c_uchar,
    out: *mut c_uchar,
    len: usize,
    ivec: *mut c_uchar,
    run: impl FnOnce(&[u8], &mut [u8], &mut [u8; BLOCK]) -> usize,
) -> usize {
    // SAFETY: the caller's guarantee.
    unsafe { with_iv(input, len, out, len, ivec, run) }.unwrap_or(0)
}

ffi_export! {
    /// CTS-encrypts `len` octets (more than 16) with `block` under `key`. Returns `len`, or 0.
    ///
    /// # Safety
    /// `in_` holds and `out` has room for `len` octets; `ivec` holds 16; `block` is null or a
    /// block function for `key`.
    pub unsafe extern "C" fn CRYPTO_cts128_encrypt_block(in_: *const c_uchar, out: *mut c_uchar, len: usize, key: *const c_void, ivec: *mut c_uchar, block: block128_f) -> usize
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let Some(b) = self::block(block, key) else { return 0 };
        if len <= BLOCK {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { cts(in_, out, len, ivec, |i, o, iv| modes::cts_encrypt_block(i, o, iv, &b)) }
    }
}

ffi_export! {
    /// CTS-encrypts `len` octets (more than 16) with the CBC function `cbc` under `key`.
    /// Returns `len`, or 0.
    ///
    /// # Safety
    /// As for `CRYPTO_cts128_encrypt_block`, with `cbc` null or a CBC function for `key`.
    pub unsafe extern "C" fn CRYPTO_cts128_encrypt(in_: *const c_uchar, out: *mut c_uchar, len: usize, key: *const c_void, ivec: *mut c_uchar, cbc: cbc128_f) -> usize
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let Some(f) = self::cbc(cbc, key) else { return 0 };
        if len <= BLOCK {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { cts(in_, out, len, ivec, |i, o, iv| modes::cts_encrypt(i, o, iv, &f)) }
    }
}

ffi_export! {
    /// CTS-decrypts `len` octets (more than 16) with `block` under `key`. Returns `len`, or 0.
    ///
    /// # Safety
    /// As for `CRYPTO_cts128_encrypt_block`.
    pub unsafe extern "C" fn CRYPTO_cts128_decrypt_block(in_: *const c_uchar, out: *mut c_uchar, len: usize, key: *const c_void, ivec: *mut c_uchar, block: block128_f) -> usize
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let Some(b) = self::block(block, key) else { return 0 };
        if len <= BLOCK {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { cts(in_, out, len, ivec, |i, o, iv| modes::cts_decrypt_block(i, o, iv, &b)) }
    }
}

ffi_export! {
    /// CTS-decrypts `len` octets (more than 16) with the CBC function `cbc` under `key`.
    /// Returns `len`, or 0.
    ///
    /// # Safety
    /// As for `CRYPTO_cts128_encrypt`.
    pub unsafe extern "C" fn CRYPTO_cts128_decrypt(in_: *const c_uchar, out: *mut c_uchar, len: usize, key: *const c_void, ivec: *mut c_uchar, cbc: cbc128_f) -> usize
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let Some(f) = self::cbc(cbc, key) else { return 0 };
        if len <= BLOCK {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { cts(in_, out, len, ivec, |i, o, iv| modes::cts_decrypt(i, o, iv, &f)) }
    }
}

ffi_export! {
    /// NIST CBC-CS3-encrypts `len` octets (16 or more) with `block` under `key`. Returns
    /// `len`, or 0.
    ///
    /// # Safety
    /// As for `CRYPTO_cts128_encrypt_block`.
    pub unsafe extern "C" fn CRYPTO_nistcts128_encrypt_block(in_: *const c_uchar, out: *mut c_uchar, len: usize, key: *const c_void, ivec: *mut c_uchar, block: block128_f) -> usize
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let Some(b) = self::block(block, key) else { return 0 };
        if len < BLOCK {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { cts(in_, out, len, ivec, |i, o, iv| modes::nistcts_encrypt_block(i, o, iv, &b)) }
    }
}

ffi_export! {
    /// NIST CBC-CS3-encrypts `len` octets (16 or more) with the CBC function `cbc` under
    /// `key`. Returns `len`, or 0.
    ///
    /// # Safety
    /// As for `CRYPTO_cts128_encrypt`.
    pub unsafe extern "C" fn CRYPTO_nistcts128_encrypt(in_: *const c_uchar, out: *mut c_uchar, len: usize, key: *const c_void, ivec: *mut c_uchar, cbc: cbc128_f) -> usize
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let Some(f) = self::cbc(cbc, key) else { return 0 };
        if len < BLOCK {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { cts(in_, out, len, ivec, |i, o, iv| modes::nistcts_encrypt(i, o, iv, &f)) }
    }
}

ffi_export! {
    /// NIST CBC-CS3-decrypts `len` octets (16 or more) with `block` under `key`. Returns
    /// `len`, or 0.
    ///
    /// # Safety
    /// As for `CRYPTO_cts128_encrypt_block`.
    pub unsafe extern "C" fn CRYPTO_nistcts128_decrypt_block(in_: *const c_uchar, out: *mut c_uchar, len: usize, key: *const c_void, ivec: *mut c_uchar, block: block128_f) -> usize
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let Some(b) = self::block(block, key) else { return 0 };
        if len < BLOCK {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { cts(in_, out, len, ivec, |i, o, iv| modes::nistcts_decrypt_block(i, o, iv, &b)) }
    }
}

ffi_export! {
    /// NIST CBC-CS3-decrypts `len` octets (16 or more) with the CBC function `cbc` under
    /// `key`. Returns `len`, or 0.
    ///
    /// # Safety
    /// As for `CRYPTO_cts128_encrypt`.
    pub unsafe extern "C" fn CRYPTO_nistcts128_decrypt(in_: *const c_uchar, out: *mut c_uchar, len: usize, key: *const c_void, ivec: *mut c_uchar, cbc: cbc128_f) -> usize
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let Some(f) = self::cbc(cbc, key) else { return 0 };
        if len < BLOCK {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { cts(in_, out, len, ivec, |i, o, iv| modes::nistcts_decrypt(i, o, iv, &f)) }
    }
}

/// The longest input the wraps take.
const WRAP_MAX: usize = 1 << 31;

/// An optional IV of `N` octets.
///
/// # Safety
/// `iv` is null or holds `N` octets.
unsafe fn optional_iv<const N: usize>(iv: *const c_uchar) -> Option<[u8; N]> {
    // SAFETY: the caller's guarantee.
    unsafe { read_array::<N>(iv) }
}

/// RFC 3394 wrapping of `inlen` octets (16 or more, in steps of 8) into `inlen + 8`.
///
/// # Safety
/// `iv` is null or holds 8 octets; `input` holds `inlen`; `out` has room for `inlen + 8`.
pub(crate) unsafe fn wrap(
    iv: *const c_uchar,
    out: *mut c_uchar,
    input: *const c_uchar,
    inlen: usize,
    b: &impl Block128,
) -> usize {
    if !inlen.is_multiple_of(8) || !(16..=WRAP_MAX).contains(&inlen) {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let iv = unsafe { optional_iv::<8>(iv) };
    // SAFETY: the caller's guarantee.
    let Some((input, out)) = (unsafe { buffers(input, inlen, out, inlen.saturating_add(8)) })
    else {
        return 0;
    };
    modes::wrap(iv.as_ref(), &input, out, b)
}

/// RFC 3394 unwrapping of `inlen` octets (24 or more, in steps of 8) into `inlen - 8`.
///
/// # Safety
/// `iv` is null or holds 8 octets; `input` holds `inlen`; `out` has room for `inlen - 8`.
pub(crate) unsafe fn unwrap(
    iv: *const c_uchar,
    out: *mut c_uchar,
    input: *const c_uchar,
    inlen: usize,
    b: &impl Block128,
) -> usize {
    let plain = inlen.wrapping_sub(8);
    if !plain.is_multiple_of(8) || !(16..=WRAP_MAX).contains(&plain) {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let iv = unsafe { optional_iv::<8>(iv) };
    // SAFETY: the caller's guarantee.
    let Some((input, out)) = (unsafe { buffers(input, inlen, out, plain) }) else {
        return 0;
    };
    modes::unwrap(iv.as_ref(), &input, out, b)
}

ffi_export! {
    /// RFC 3394-wraps `inlen` octets (16 to 2^31, in steps of 8) with `block` under `key` and
    /// `iv` (8 octets, or the default for null). Returns `inlen + 8`, or 0.
    ///
    /// # Safety
    /// `iv` is null or holds 8 octets; `in_` holds `inlen`; `out` has room for `inlen + 8`;
    /// `block` is null or a block function for `key`.
    pub unsafe extern "C" fn CRYPTO_128_wrap(key: *mut c_void, iv: *const c_uchar, out: *mut c_uchar, in_: *const c_uchar, inlen: usize, block: block128_f) -> usize
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let Some(b) = self::block(block, key.cast_const()) else { return 0 };
        // SAFETY: the caller's guarantee.
        unsafe { wrap(iv, out, in_, inlen, &b) }
    }
}

ffi_export! {
    /// RFC 3394-unwraps `inlen` octets with `block` (decrypting) under `key`, checking the IV
    /// against `iv` (or the default for null). Returns `inlen - 8`, or 0 (having zeroed the
    /// output for a wrong IV).
    ///
    /// # Safety
    /// `iv` is null or holds 8 octets; `in_` holds `inlen`; `out` has room for `inlen - 8`;
    /// `block` is null or a block function for `key`.
    pub unsafe extern "C" fn CRYPTO_128_unwrap(key: *mut c_void, iv: *const c_uchar, out: *mut c_uchar, in_: *const c_uchar, inlen: usize, block: block128_f) -> usize
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let Some(b) = self::block(block, key.cast_const()) else { return 0 };
        // SAFETY: the caller's guarantee.
        unsafe { unwrap(iv, out, in_, inlen, &b) }
    }
}

ffi_export! {
    /// RFC 5649-wraps `inlen` octets (1 to 2^31 - 1) with `block` under `key` and `icv` (4
    /// octets, or the default for null). Returns 16 for up to 8 octets, else `inlen` rounded
    /// up to steps of 8 plus 8; or 0.
    ///
    /// # Safety
    /// `icv` is null or holds 4 octets; `in_` holds `inlen`; `out` has room for the result;
    /// `block` is null or a block function for `key`.
    pub unsafe extern "C" fn CRYPTO_128_wrap_pad(key: *mut c_void, icv: *const c_uchar, out: *mut c_uchar, in_: *const c_uchar, inlen: usize, block: block128_f) -> usize
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let Some(b) = self::block(block, key.cast_const()) else { return 0 };
        if inlen == 0 || inlen >= WRAP_MAX {
            return 0;
        }
        let out_len = inlen.div_ceil(8).saturating_mul(8).saturating_add(8);
        // SAFETY: the caller's guarantee.
        let icv = unsafe { optional_iv::<4>(icv) };
        // SAFETY: the caller's guarantee.
        let Some((input, out)) = (unsafe { buffers(in_, inlen, out, out_len) }) else { return 0 };
        modes::wrap_pad(icv.as_ref(), &input, out, &b)
    }
}

ffi_export! {
    /// RFC 5649-unwraps `inlen` octets (16 to 2^31 - 1, in steps of 8) with `block`
    /// (decrypting) under `key`, checking the IV against `icv` (or the default for null), the
    /// length, and the padding. Returns the unwrapped length, or 0 (having zeroed the
    /// `inlen - 8` octets of output for a failed check).
    ///
    /// # Safety
    /// `icv` is null or holds 4 octets; `in_` holds `inlen`; `out` has room for `inlen - 8`;
    /// `block` is null or a block function for `key`.
    pub unsafe extern "C" fn CRYPTO_128_unwrap_pad(key: *mut c_void, icv: *const c_uchar, out: *mut c_uchar, in_: *const c_uchar, inlen: usize, block: block128_f) -> usize
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let Some(b) = self::block(block, key.cast_const()) else { return 0 };
        if !inlen.is_multiple_of(8) || !(16..WRAP_MAX).contains(&inlen) {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let icv = unsafe { optional_iv::<4>(icv) };
        // SAFETY: the caller's guarantee.
        let Some((input, out)) = (unsafe { buffers(in_, inlen, out, inlen.saturating_sub(8)) }) else { return 0 };
        modes::unwrap_pad(icv.as_ref(), &input, out, &b)
    }
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::*;

    /// A block function that XORs the key's first octet in.
    unsafe extern "C" fn xor_block(input: *const c_uchar, out: *mut c_uchar, key: *const c_void) {
        // SAFETY: the test's key, a block in, and a block out.
        let k = unsafe { *key.cast::<u8>() };
        // SAFETY: as above.
        let block = unsafe { input.cast::<[u8; BLOCK]>().read_unaligned() };
        // SAFETY: as above.
        unsafe {
            out.cast::<[u8; BLOCK]>()
                .write_unaligned(block.map(|x| x ^ k))
        };
    }

    /// docs/DEVIATIONS.md: a null function, buffer, IV, or position does nothing (returning
    /// 0); the reference crashes.
    #[test]
    fn nulls_do_nothing() {
        let key = [0x5au8];
        let k = key.as_ptr().cast::<c_void>();
        let input = [1u8; 32];
        let mut out = [0u8; 32];
        let mut iv = [0u8; 16];
        let mut ecount = [0u8; 16];
        let mut unum: c_uint = 0;
        // SAFETY: nulls are the case under test, with buffers of the right sizes, for each
        // call below.
        unsafe {
            CRYPTO_cbc128_encrypt(
                input.as_ptr(),
                out.as_mut_ptr(),
                32,
                k,
                iv.as_mut_ptr(),
                None,
            )
        };
        // SAFETY: as above.
        unsafe {
            CRYPTO_cbc128_encrypt(
                input.as_ptr(),
                out.as_mut_ptr(),
                32,
                k,
                ptr::null_mut(),
                Some(xor_block),
            )
        };
        // SAFETY: as above.
        unsafe {
            CRYPTO_cbc128_decrypt(
                ptr::null(),
                out.as_mut_ptr(),
                32,
                k,
                iv.as_mut_ptr(),
                Some(xor_block),
            )
        };
        // SAFETY: as above.
        unsafe {
            CRYPTO_ctr128_encrypt(
                input.as_ptr(),
                out.as_mut_ptr(),
                32,
                k,
                iv.as_mut_ptr(),
                ecount.as_mut_ptr(),
                ptr::null_mut(),
                Some(xor_block),
            )
        };
        // SAFETY: as above.
        unsafe {
            CRYPTO_ctr128_encrypt(
                input.as_ptr(),
                ptr::null_mut(),
                32,
                k,
                iv.as_mut_ptr(),
                ecount.as_mut_ptr(),
                &raw mut unum,
                Some(xor_block),
            )
        };
        // SAFETY: as above.
        unsafe {
            CRYPTO_ofb128_encrypt(
                input.as_ptr(),
                out.as_mut_ptr(),
                32,
                k,
                iv.as_mut_ptr(),
                ptr::null_mut(),
                Some(xor_block),
            )
        };
        assert_eq!((out, iv, ecount, unum), ([0; 32], [0; 16], [0; 16], 0));
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe {
                CRYPTO_cts128_encrypt_block(
                    input.as_ptr(),
                    out.as_mut_ptr(),
                    20,
                    k,
                    iv.as_mut_ptr(),
                    None,
                )
            },
            0
        );
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe {
                CRYPTO_cts128_encrypt(
                    input.as_ptr(),
                    out.as_mut_ptr(),
                    20,
                    k,
                    ptr::null_mut(),
                    None,
                )
            },
            0
        );
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe {
                CRYPTO_128_wrap(
                    k.cast_mut(),
                    ptr::null(),
                    out.as_mut_ptr(),
                    ptr::null(),
                    16,
                    Some(xor_block),
                )
            },
            0
        );
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe {
                CRYPTO_128_unwrap_pad(
                    k.cast_mut(),
                    ptr::null(),
                    out.as_mut_ptr(),
                    input.as_ptr(),
                    24,
                    None,
                )
            },
            0
        );
        assert_eq!(out, [0; 32]);
    }

    /// docs/DEVIATIONS.md: a position past the block is refused, changing nothing; the
    /// reference reads past the keystream block or IV.
    #[test]
    fn positions_past_the_block_are_refused() {
        let key = [0x5au8];
        let k = key.as_ptr().cast::<c_void>();
        let input = [1u8; 8];
        let mut out = [0u8; 8];
        let mut iv = [0u8; 16];
        let mut ecount = [0u8; 16];
        let mut unum: c_uint = 16;
        let mut num: c_int = 16;
        // SAFETY: the test's buffers, for each call below.
        unsafe {
            CRYPTO_ctr128_encrypt(
                input.as_ptr(),
                out.as_mut_ptr(),
                8,
                k,
                iv.as_mut_ptr(),
                ecount.as_mut_ptr(),
                &raw mut unum,
                Some(xor_block),
            )
        };
        // SAFETY: as above.
        unsafe {
            CRYPTO_ofb128_encrypt(
                input.as_ptr(),
                out.as_mut_ptr(),
                8,
                k,
                iv.as_mut_ptr(),
                &raw mut num,
                Some(xor_block),
            )
        };
        // SAFETY: as above.
        unsafe {
            CRYPTO_cfb128_encrypt(
                input.as_ptr(),
                out.as_mut_ptr(),
                8,
                k,
                iv.as_mut_ptr(),
                &raw mut num,
                1,
                Some(xor_block),
            )
        };
        assert_eq!((out, iv, unum, num), ([0; 8], [0; 16], 16, 16));
    }

    /// docs/DEVIATIONS.md: a failed RFC 5649 unwrap zeroes the `inlen - 8` octets it wrote;
    /// the reference zeroes `inlen`, 8 past them.
    #[test]
    fn failed_padded_unwraps_zero_only_their_output() {
        let key = [0x5au8];
        let k = key.as_ptr().cast_mut().cast::<c_void>();
        let plain = [7u8; 20];
        let mut wrapped = [0u8; 32];
        // SAFETY: the test's buffers, for each call below.
        let w = unsafe {
            CRYPTO_128_wrap_pad(
                k,
                ptr::null(),
                wrapped.as_mut_ptr(),
                plain.as_ptr(),
                20,
                Some(xor_block),
            )
        };
        assert_eq!(w, 32);
        wrapped[31] ^= 1;
        let mut out = [0xeeu8; 32];
        // SAFETY: as above.
        let u = unsafe {
            CRYPTO_128_unwrap_pad(
                k,
                ptr::null(),
                out.as_mut_ptr(),
                wrapped.as_ptr(),
                32,
                Some(xor_block),
            )
        };
        assert_eq!(u, 0);
        assert_eq!(out[..24], [0; 24]);
        assert_eq!(out[24..], [0xee; 8]);
    }
}
