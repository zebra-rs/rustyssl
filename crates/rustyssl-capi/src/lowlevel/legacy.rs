//! The deprecated Blowfish, CAST, RC2, and RC4 functions (`BF_set_key(3)`, `CAST_set_key`,
//! `RC2_set_key`, `RC4_set_key(3)`, their block functions and modes), over
//! [`rustyssl_crypto::lowlevel::legacy`].
//!
//! The key structs are read and written field by field. `RC4_KEY`'s words are `unsigned int`
//! or `unsigned char` by platform (as the generated layouts say), and `RC4_options` names the
//! platform's: OpenSSL's x86_64 assembly says "rc4(16x,int)" on Intel processors and
//! "rc4(8x,int)" on others (the Pentium 4 alone gets its byte layout, not reproduced here).
//! Where OpenSSL dereferences a null key or buffer and
//! crashes, these do nothing; a negative length does nothing where OpenSSL writes a block or
//! loops without end; an RC2 key of no octets expands from a zero where OpenSSL reads before
//! the key, and an RC4 key of none does nothing where OpenSSL reads past it
//! (docs/DEVIATIONS.md).

#![allow(
    clippy::useless_conversion,
    reason = "`RC4_INT` is `unsigned char` on some targets and `unsigned int` on others"
)]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong};

use rustyssl_abi::{BF_KEY, CAST_KEY, ERR_LIB_CRYPTO, RC2_KEY, RC4_KEY};
use rustyssl_crypto::lowlevel::legacy::{
    self, BfKey, Block64, CastKey, Rc2Key, Rc4, bf_set_key, cast_set_key, rc2_set_key, rc4_set_key,
};

use super::{buffers, read_array, write_array};
use crate::ffi::{bytes, ffi_export};

/// A length that isn't negative.
fn nonneg(len: c_long) -> Option<usize> {
    usize::try_from(len).ok()
}

/// CBC over the caller's buffers: encryption reads `length` and writes it rounded up to whole
/// blocks, decryption the other way round; the IV is updated.
///
/// # Safety
/// The buffers hold their lengths; `ivec` is null or holds 8 octets.
unsafe fn cbc(
    input: *const c_uchar,
    out: *mut c_uchar,
    length: c_long,
    c: &impl Block64,
    ivec: *mut c_uchar,
    enc: bool,
) {
    let Some(len) = nonneg(length) else { return };
    let whole = len.div_ceil(8).saturating_mul(8);
    let (in_len, out_len) = if enc { (len, whole) } else { (whole, len) };
    // SAFETY: the caller's guarantee.
    let Some(mut iv) = (unsafe { read_array::<8>(ivec) }) else {
        return;
    };
    // SAFETY: the caller's guarantee.
    let Some((input, out)) = (unsafe { buffers(input, in_len, out, out_len) }) else {
        return;
    };
    legacy::cbc(&input, out, len, c, &mut iv, enc);
    // SAFETY: the caller's IV, read above.
    unsafe { write_array(ivec, &iv) };
}

/// CFB-64 or OFB-64 over the caller's buffers through `run`, with the IV and position.
///
/// # Safety
/// The buffers hold `length` octets; `ivec` is null or holds 8; `num` is null or valid.
unsafe fn by_octets(
    input: *const c_uchar,
    out: *mut c_uchar,
    length: c_long,
    ivec: *mut c_uchar,
    num: *mut c_int,
    run: impl FnOnce(&[u8], &mut [u8], &mut [u8; 8], &mut i32),
) {
    let Some(len) = nonneg(length) else { return };
    // SAFETY: the caller's guarantee.
    let Some(mut n) = (unsafe { num.as_ref() }).copied() else {
        return;
    };
    // SAFETY: the caller's guarantee.
    let Some(mut iv) = (unsafe { read_array::<8>(ivec) }) else {
        return;
    };
    // SAFETY: the caller's guarantee.
    let Some((input, out)) = (unsafe { buffers(input, len, out, len) }) else {
        return;
    };
    run(&input, out, &mut iv, &mut n);
    // SAFETY: the caller's IV, read above.
    unsafe { write_array(ivec, &iv) };
    // SAFETY: the caller's position, read above.
    unsafe { num.write(n) };
}

/// One block through `c` from `input` to `out`.
///
/// # Safety
/// `input` and `out` are null or hold 8 octets.
unsafe fn one_block(input: *const c_uchar, out: *mut c_uchar, c: &impl Block64, enc: bool) {
    // SAFETY: the caller's guarantee.
    let Some(x) = (unsafe { read_array::<8>(input) }) else {
        return;
    };
    if out.is_null() {
        return;
    }
    let y = legacy::ecb(&x, c, enc);
    // SAFETY: the caller's 8 octets.
    unsafe { write_array(out, &y) };
}

/// Runs `f` on the caller's two words.
///
/// # Safety
/// `data` is null or holds two `u32`s.
unsafe fn words(data: *mut u32, f: impl FnOnce(&mut [u32; 2])) {
    if data.is_null() {
        return;
    }
    // SAFETY: the caller's two words, read whatever their alignment.
    let mut d = unsafe { data.cast::<[u32; 2]>().read_unaligned() };
    f(&mut d);
    // SAFETY: as above.
    unsafe { data.cast::<[u32; 2]>().write_unaligned(d) };
}

/// The caller's Blowfish key.
///
/// # Safety
/// `key` is null or a valid `BF_KEY`.
unsafe fn bf_key(key: *const BF_KEY) -> Option<BfKey> {
    // SAFETY: the caller's guarantee.
    let k = unsafe { key.as_ref() }?;
    Some(BfKey { p: k.P, s: k.S })
}

ffi_export! {
    /// "blowfish(ptr)", as OpenSSL's.
    ///
    /// # Safety
    /// Always safe to call.
    pub unsafe extern "C" fn BF_options() -> *const c_char
    where failure = c"blowfish(ptr)".as_ptr(), library = ERR_LIB_CRYPTO
    {
        c"blowfish(ptr)".as_ptr()
    }
}

ffi_export! {
    /// Sets `key` from the first `len` octets of `data` (at most 72; a length of 0 or less
    /// takes the first octet alone, as OpenSSL reads it).
    ///
    /// # Safety
    /// `key` is null or valid for writes; `data` is null or holds `len` octets (at least one).
    pub unsafe extern "C" fn BF_set_key(key: *mut BF_KEY, len: c_int, data: *const c_uchar)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let n = usize::try_from(len).ok().filter(|&n| n > 0).map_or(1, |n| n.min(72));
        // SAFETY: the caller's guarantee.
        let Some(octets) = (unsafe { bytes(data, n) }) else { return };
        if octets.is_empty() {
            return;
        }
        // SAFETY: the caller's key (integers: any octets are valid).
        let Some(k) = (unsafe { key.as_mut() }) else { return };
        let s = bf_set_key(octets);
        k.P = s.p;
        k.S = s.s;
    }
}

ffi_export! {
    /// Encrypts two words.
    ///
    /// # Safety
    /// `data` holds two words; `key` is a valid `BF_KEY`.
    pub unsafe extern "C" fn BF_encrypt(data: *mut c_uint, key: *const BF_KEY)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { bf_key(key) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { words(data, |d| k.encrypt_words(d)) };
    }
}

ffi_export! {
    /// Decrypts two words.
    ///
    /// # Safety
    /// As for `BF_encrypt`.
    pub unsafe extern "C" fn BF_decrypt(data: *mut c_uint, key: *const BF_KEY)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { bf_key(key) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { words(data, |d| k.decrypt_words(d)) };
    }
}

ffi_export! {
    /// One block, encrypting for nonzero `enc`.
    ///
    /// # Safety
    /// `in_` and `out` hold 8 octets; `key` is a valid `BF_KEY`.
    pub unsafe extern "C" fn BF_ecb_encrypt(in_: *const c_uchar, out: *mut c_uchar, key: *const BF_KEY, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { bf_key(key) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { one_block(in_, out, &k, enc != 0) };
    }
}

ffi_export! {
    /// CBC over `length` octets, updating `ivec`.
    ///
    /// # Safety
    /// `in_` and `out` hold `length` octets (rounded up to whole blocks on the whole side);
    /// `ivec` holds 8; `schedule` is a valid `BF_KEY`.
    pub unsafe extern "C" fn BF_cbc_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: c_long, schedule: *const BF_KEY, ivec: *mut c_uchar, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { bf_key(schedule) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { cbc(in_, out, length, &k, ivec, enc != 0) };
    }
}

ffi_export! {
    /// CFB-64 by octets; `*num` (its low three bits) is the position in `ivec`.
    ///
    /// # Safety
    /// `in_` and `out` hold `length` octets; `ivec` holds 8; `num` is valid; `schedule` is a
    /// valid `BF_KEY`.
    pub unsafe extern "C" fn BF_cfb64_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: c_long, schedule: *const BF_KEY, ivec: *mut c_uchar, num: *mut c_int, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { bf_key(schedule) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { by_octets(in_, out, length, ivec, num, |i, o, iv, n| legacy::cfb64(i, o, &k, iv, n, enc != 0)) };
    }
}

ffi_export! {
    /// OFB-64 by octets; `*num` (its low three bits) is the position in the keystream block.
    ///
    /// # Safety
    /// As for `BF_cfb64_encrypt`.
    pub unsafe extern "C" fn BF_ofb64_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: c_long, schedule: *const BF_KEY, ivec: *mut c_uchar, num: *mut c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { bf_key(schedule) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { by_octets(in_, out, length, ivec, num, |i, o, iv, n| legacy::ofb64(i, o, &k, iv, n)) };
    }
}

/// The caller's CAST key.
///
/// # Safety
/// `key` is null or a valid `CAST_KEY`.
unsafe fn cast_key(key: *const CAST_KEY) -> Option<CastKey> {
    // SAFETY: the caller's guarantee.
    let k = unsafe { key.as_ref() }?;
    Some(CastKey {
        data: k.data,
        short_key: k.short_key != 0,
    })
}

ffi_export! {
    /// Sets `key` from the first `len` octets of `data` (at most 16, zero-padded; 10 or fewer
    /// make a 12-round key).
    ///
    /// # Safety
    /// `key` is null or valid for writes; `data` is null or holds `len` octets.
    pub unsafe extern "C" fn CAST_set_key(key: *mut CAST_KEY, len: c_int, data: *const c_uchar)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let n = usize::try_from(len).unwrap_or(0).min(16);
        // SAFETY: the caller's guarantee.
        let Some(octets) = (unsafe { bytes(data, n) }) else { return };
        // SAFETY: the caller's key (integers: any octets are valid).
        let Some(k) = (unsafe { key.as_mut() }) else { return };
        let s = cast_set_key(octets);
        k.data = s.data;
        k.short_key = c_int::from(s.short_key);
    }
}

ffi_export! {
    /// Encrypts two words.
    ///
    /// # Safety
    /// `data` holds two words; `key` is a valid `CAST_KEY`.
    pub unsafe extern "C" fn CAST_encrypt(data: *mut c_uint, key: *const CAST_KEY)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { cast_key(key) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { words(data, |d| k.encrypt_words(d)) };
    }
}

ffi_export! {
    /// Decrypts two words.
    ///
    /// # Safety
    /// As for `CAST_encrypt`.
    pub unsafe extern "C" fn CAST_decrypt(data: *mut c_uint, key: *const CAST_KEY)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { cast_key(key) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { words(data, |d| k.decrypt_words(d)) };
    }
}

ffi_export! {
    /// One block, encrypting for nonzero `enc`.
    ///
    /// # Safety
    /// `in_` and `out` hold 8 octets; `key` is a valid `CAST_KEY`.
    pub unsafe extern "C" fn CAST_ecb_encrypt(in_: *const c_uchar, out: *mut c_uchar, key: *const CAST_KEY, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { cast_key(key) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { one_block(in_, out, &k, enc != 0) };
    }
}

ffi_export! {
    /// CBC over `length` octets, updating `iv`.
    ///
    /// # Safety
    /// As for `BF_cbc_encrypt`, with a `CAST_KEY`.
    pub unsafe extern "C" fn CAST_cbc_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: c_long, ks: *const CAST_KEY, iv: *mut c_uchar, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { cast_key(ks) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { cbc(in_, out, length, &k, iv, enc != 0) };
    }
}

ffi_export! {
    /// CFB-64 by octets.
    ///
    /// # Safety
    /// As for `BF_cfb64_encrypt`, with a `CAST_KEY`.
    pub unsafe extern "C" fn CAST_cfb64_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: c_long, schedule: *const CAST_KEY, ivec: *mut c_uchar, num: *mut c_int, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { cast_key(schedule) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { by_octets(in_, out, length, ivec, num, |i, o, iv, n| legacy::cfb64(i, o, &k, iv, n, enc != 0)) };
    }
}

ffi_export! {
    /// OFB-64 by octets.
    ///
    /// # Safety
    /// As for `BF_ofb64_encrypt`, with a `CAST_KEY`.
    pub unsafe extern "C" fn CAST_ofb64_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: c_long, schedule: *const CAST_KEY, ivec: *mut c_uchar, num: *mut c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { cast_key(schedule) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { by_octets(in_, out, length, ivec, num, |i, o, iv, n| legacy::ofb64(i, o, &k, iv, n)) };
    }
}

/// The caller's RC2 key.
///
/// # Safety
/// `key` is null or a valid `RC2_KEY`.
unsafe fn rc2_key(key: *const RC2_KEY) -> Option<Rc2Key> {
    // SAFETY: the caller's guarantee.
    let k = unsafe { key.as_ref() }?;
    Some(Rc2Key(k.data.map(u32::from)))
}

ffi_export! {
    /// Sets `key` from the first `len` octets of `data` (at most 128) with `bits` effective
    /// bits (1 to 1024; 0 or less, or more, is 1024).
    ///
    /// # Safety
    /// `key` is null or valid for writes; `data` is null or holds `len` octets.
    pub unsafe extern "C" fn RC2_set_key(key: *mut RC2_KEY, len: c_int, data: *const c_uchar, bits: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let n = usize::try_from(len).unwrap_or(0).min(128);
        // SAFETY: the caller's guarantee.
        let Some(octets) = (unsafe { bytes(data, n) }) else { return };
        // SAFETY: the caller's key (integers: any octets are valid).
        let Some(k) = (unsafe { key.as_mut() }) else { return };
        let s = rc2_set_key(octets, bits);
        for (d, w) in k.data.iter_mut().zip(s.0) {
            *d = w.try_into().unwrap_or_default();
        }
    }
}

/// Runs `f` on the caller's two `unsigned long`s, as 32-bit words (RC2 uses only their low
/// 32 bits, and writes back words without high bits).
///
/// # Safety
/// `data` is null or holds two `unsigned long`s.
unsafe fn long_words(data: *mut c_ulong, f: impl FnOnce(&mut [u32; 2])) {
    if data.is_null() {
        return;
    }
    // SAFETY: the caller's two `unsigned long`s, read whatever their alignment.
    let d = unsafe { data.cast::<[c_ulong; 2]>().read_unaligned() };
    let mut w = d.map(|x| u32::try_from(x & 0xffff_ffff).unwrap_or(0));
    f(&mut w);
    // SAFETY: as above.
    unsafe {
        data.cast::<[c_ulong; 2]>()
            .write_unaligned(w.map(c_ulong::from))
    };
}

ffi_export! {
    /// Encrypts two words (the low 32 bits of each `unsigned long`).
    ///
    /// # Safety
    /// `data` holds two `unsigned long`s; `key` is a valid `RC2_KEY`.
    pub unsafe extern "C" fn RC2_encrypt(data: *mut c_ulong, key: *mut RC2_KEY)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { rc2_key(key) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { long_words(data, |d| k.encrypt_words(d)) };
    }
}

ffi_export! {
    /// Decrypts two words.
    ///
    /// # Safety
    /// As for `RC2_encrypt`.
    pub unsafe extern "C" fn RC2_decrypt(data: *mut c_ulong, key: *mut RC2_KEY)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { rc2_key(key) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { long_words(data, |d| k.decrypt_words(d)) };
    }
}

ffi_export! {
    /// One block, encrypting for nonzero `enc`.
    ///
    /// # Safety
    /// `in_` and `out` hold 8 octets; `key` is a valid `RC2_KEY`.
    pub unsafe extern "C" fn RC2_ecb_encrypt(in_: *const c_uchar, out: *mut c_uchar, key: *mut RC2_KEY, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { rc2_key(key) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { one_block(in_, out, &k, enc != 0) };
    }
}

ffi_export! {
    /// CBC over `length` octets, updating `iv`.
    ///
    /// # Safety
    /// As for `BF_cbc_encrypt`, with an `RC2_KEY`.
    pub unsafe extern "C" fn RC2_cbc_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: c_long, ks: *mut RC2_KEY, iv: *mut c_uchar, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { rc2_key(ks) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { cbc(in_, out, length, &k, iv, enc != 0) };
    }
}

ffi_export! {
    /// CFB-64 by octets.
    ///
    /// # Safety
    /// As for `BF_cfb64_encrypt`, with an `RC2_KEY`.
    pub unsafe extern "C" fn RC2_cfb64_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: c_long, schedule: *mut RC2_KEY, ivec: *mut c_uchar, num: *mut c_int, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { rc2_key(schedule) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { by_octets(in_, out, length, ivec, num, |i, o, iv, n| legacy::cfb64(i, o, &k, iv, n, enc != 0)) };
    }
}

ffi_export! {
    /// OFB-64 by octets.
    ///
    /// # Safety
    /// As for `BF_ofb64_encrypt`, with an `RC2_KEY`.
    pub unsafe extern "C" fn RC2_ofb64_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: c_long, schedule: *mut RC2_KEY, ivec: *mut c_uchar, num: *mut c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { rc2_key(schedule) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { by_octets(in_, out, length, ivec, num, |i, o, iv, n| legacy::ofb64(i, o, &k, iv, n)) };
    }
}

/// `RC4_options` on x86_64: OpenSSL's assembly names its loop by the processor, "rc4(16x,int)"
/// on Intel's and "rc4(8x,int)" on others (the vendor that `cpuid` reports).
#[cfg(target_arch = "x86_64")]
fn rc4_options() -> &'static core::ffi::CStr {
    let v = core::arch::x86_64::__cpuid(0);
    let intel = [v.ebx, v.edx, v.ecx] == [*b"Genu", *b"ineI", *b"ntel"].map(u32::from_le_bytes);
    if intel {
        c"rc4(16x,int)"
    } else {
        c"rc4(8x,int)"
    }
}

/// `RC4_options` elsewhere: OpenSSL's C code's, for the width of `RC4_INT`.
#[cfg(not(target_arch = "x86_64"))]
fn rc4_options() -> &'static core::ffi::CStr {
    if size_of::<RC4_KEY>() < 256 * 4 {
        c"rc4(char)"
    } else {
        c"rc4(int)"
    }
}

ffi_export! {
    /// The RC4 implementation's options: the platform's, as OpenSSL's.
    ///
    /// # Safety
    /// Always safe to call.
    pub unsafe extern "C" fn RC4_options() -> *const c_char
    where failure = rc4_options().as_ptr(), library = ERR_LIB_CRYPTO
    {
        rc4_options().as_ptr()
    }
}

/// The caller's RC4 state.
fn rc4_load(k: &RC4_KEY) -> Rc4 {
    let mut s = Rc4 {
        x: u32::from(k.x),
        y: u32::from(k.y),
        data: [0; 256],
    };
    for (d, v) in s.data.iter_mut().zip(k.data) {
        *d = u32::from(v);
    }
    s
}

/// Copies the state back.
fn rc4_store(k: &mut RC4_KEY, s: &Rc4) {
    k.x = s.x.try_into().unwrap_or_default();
    k.y = s.y.try_into().unwrap_or_default();
    for (d, v) in k.data.iter_mut().zip(s.data) {
        *d = v.try_into().unwrap_or_default();
    }
}

ffi_export! {
    /// Sets `key` from the `len` octets at `data` (1 or more).
    ///
    /// # Safety
    /// `key` is null or valid for writes; `data` is null or holds `len` octets.
    pub unsafe extern "C" fn RC4_set_key(key: *mut RC4_KEY, len: c_int, data: *const c_uchar)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let Some(n) = usize::try_from(len).ok().filter(|&n| n > 0) else { return };
        // SAFETY: the caller's guarantee.
        let Some(octets) = (unsafe { bytes(data, n) }) else { return };
        // SAFETY: the caller's key (integers: any octets are valid).
        let Some(k) = (unsafe { key.as_mut() }) else { return };
        rc4_store(k, &rc4_set_key(octets));
    }
}

ffi_export! {
    /// XORs `len` octets of the keystream into `indata`, into `outdata`.
    ///
    /// # Safety
    /// `key` is a valid `RC4_KEY`; `indata` holds and `outdata` has room for `len` octets.
    pub unsafe extern "C" fn RC4(key: *mut RC4_KEY, len: usize, indata: *const c_uchar, outdata: *mut c_uchar)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key.as_mut() }) else { return };
        // SAFETY: the caller's guarantee.
        let Some((input, out)) = (unsafe { buffers(indata, len, outdata, len) }) else { return };
        let mut s = rc4_load(k);
        s.apply(&input, out);
        rc4_store(k, &s);
    }
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::*;

    /// A zeroed key struct.
    fn zeroed<T>() -> T {
        // SAFETY: the key structs are integers, for which zero is valid.
        unsafe { core::mem::zeroed() }
    }

    /// docs/DEVIATIONS.md: null keys and buffers, and negative lengths, do nothing; the
    /// reference crashes, writes a block, or loops without end.
    #[test]
    fn nulls_and_negative_lengths_do_nothing() {
        let bf: BF_KEY = zeroed();
        let input = [1u8; 16];
        let mut out = [0u8; 16];
        let mut iv = [0u8; 8];
        let mut num: c_int = 0;
        // (A zeroed key will do, and setting one is slow under Miri.)
        // SAFETY: nulls and negative lengths are the case under test, with buffers of the
        // right sizes, for each call below.
        unsafe { BF_ecb_encrypt(input.as_ptr(), out.as_mut_ptr(), ptr::null(), 1) };
        // SAFETY: as above.
        unsafe {
            BF_cbc_encrypt(
                input.as_ptr(),
                out.as_mut_ptr(),
                -1,
                &raw const bf,
                iv.as_mut_ptr(),
                1,
            )
        };
        // SAFETY: as above.
        unsafe {
            BF_cfb64_encrypt(
                input.as_ptr(),
                out.as_mut_ptr(),
                -1,
                &raw const bf,
                iv.as_mut_ptr(),
                &raw mut num,
                1,
            )
        };
        // SAFETY: as above.
        unsafe {
            BF_ofb64_encrypt(
                input.as_ptr(),
                out.as_mut_ptr(),
                16,
                &raw const bf,
                iv.as_mut_ptr(),
                ptr::null_mut(),
            )
        };
        // SAFETY: as above.
        unsafe { RC4(ptr::null_mut(), 16, input.as_ptr(), out.as_mut_ptr()) };
        assert_eq!((out, iv, num), ([0; 16], [0; 8], 0));
    }

    /// docs/DEVIATIONS.md: an RC2 key of no octets (or a negative length) expands from a zero
    /// (the reference reads before the key, or writes there); an RC4 key of no octets does
    /// nothing (the reference reads 256 octets past the key).
    #[test]
    fn empty_rc2_and_rc4_keys() {
        let mut a: RC2_KEY = zeroed();
        let mut b: RC2_KEY = zeroed();
        let none = [0u8; 1];
        // SAFETY: the test's keys and data, for each call below.
        unsafe { RC2_set_key(&raw mut a, 0, none.as_ptr(), 64) };
        // SAFETY: as above.
        unsafe { RC2_set_key(&raw mut b, -3, none.as_ptr(), 64) };
        assert_eq!(a.data, b.data);
        assert_eq!(
            a.data,
            rc2_set_key(&[], 64).0.map(|w| w.try_into().unwrap())
        );
        let mut k: RC4_KEY = zeroed();
        // SAFETY: as above.
        unsafe { RC4_set_key(&raw mut k, 0, none.as_ptr()) };
        assert!(k.data.iter().all(|&v| v == 0));
    }
}
