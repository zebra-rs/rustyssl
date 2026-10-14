//! The deprecated DES functions (`DES_set_key(3)`, `DES_ecb_encrypt(3)`, the modes, the
//! checksums, `DES_string_to_key`, and `DES_fcrypt`), over [`rustyssl_crypto::lowlevel::des`].
//!
//! A `DES_key_schedule` holds OpenSSL's form of the round keys, read and written as its words.
//! Lengths are `long`s: a negative one does nothing where OpenSSL writes a block or loops
//! without end, as does a CFB or OFB bit width it doesn't handle (OpenSSL loops without end or
//! shifts by more than a word); null keys, schedules, buffers, and IVs do nothing (returning 0,
//! or null) where OpenSSL crashes (docs/DEVIATIONS.md).

use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char, c_int, c_long, c_uchar};
use core::ptr;

use rustyssl_abi::{DES_LONG, DES_cblock, DES_key_schedule, ERR_LIB_CRYPTO, const_DES_cblock};
use rustyssl_crypto::lowlevel::des::{self, Cipher, Schedule};

use super::{buffers, read_array, write_array};
use crate::ffi::ffi_export;
use crate::rand_lib::RAND_priv_bytes;

/// The schedule's words.
fn load(ks: &DES_key_schedule) -> Schedule {
    let mut s = [0u32; 32];
    for (pair, k) in s.as_chunks_mut::<2>().0.iter_mut().zip(&ks.ks) {
        // SAFETY: every bit pattern is a valid value of the union's word view.
        *pair = unsafe { k.deslong };
    }
    s
}

/// Writes the schedule's words.
fn store(ks: &mut DES_key_schedule, s: &Schedule) {
    for (k, pair) in ks.ks.iter_mut().zip(s.as_chunks::<2>().0) {
        k.deslong = *pair;
    }
}

/// The caller's schedule.
///
/// # Safety
/// `ks` is null or a valid `DES_key_schedule`.
unsafe fn schedule(ks: *const DES_key_schedule) -> Option<Schedule> {
    // SAFETY: the caller's guarantee.
    unsafe { ks.as_ref() }.map(load)
}

/// The caller's 8-octet block.
///
/// # Safety
/// `p` is null or holds 8 octets.
unsafe fn block(p: *const [u8; 8]) -> Option<[u8; 8]> {
    // SAFETY: the caller's guarantee.
    unsafe { read_array::<8>(p.cast()) }
}

/// A length that isn't negative.
fn nonneg(len: c_long) -> Option<usize> {
    usize::try_from(len).ok()
}

/// `len` rounded up to whole blocks.
fn whole(len: usize) -> usize {
    len.div_ceil(8).saturating_mul(8)
}

ffi_export! {
    /// "des(int)": `DES_LONG` is an `int` here, as in OpenSSL.
    ///
    /// # Safety
    /// Always safe to call.
    pub unsafe extern "C" fn DES_options() -> *const c_char
    where failure = c"des(int)".as_ptr(), library = ERR_LIB_CRYPTO
    {
        c"des(int)".as_ptr()
    }
}

ffi_export! {
    /// Sets each octet's low bit for odd parity.
    ///
    /// # Safety
    /// `key` is null or holds 8 octets.
    pub unsafe extern "C" fn DES_set_odd_parity(key: *mut DES_cblock)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(mut k) = (unsafe { block(key) }) else { return };
        des::set_odd_parity(&mut k);
        // SAFETY: the caller's key, read above.
        unsafe { write_array(key.cast(), &k) };
    }
}

ffi_export! {
    /// 1 if every octet has odd parity, else 0.
    ///
    /// # Safety
    /// `key` is null or holds 8 octets.
    pub unsafe extern "C" fn DES_check_key_parity(key: *mut const_DES_cblock) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { block(key) }) else { return 0 };
        c_int::from(des::check_key_parity(&k))
    }
}

ffi_export! {
    /// 1 if the key is weak or semi-weak, else 0.
    ///
    /// # Safety
    /// `key` is null or holds 8 octets.
    pub unsafe extern "C" fn DES_is_weak_key(key: *mut const_DES_cblock) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { block(key) }) else { return 0 };
        c_int::from(des::is_weak_key(&k))
    }
}

/// Sets the schedule from the key. False for null.
///
/// # Safety
/// `key` is null or holds 8 octets; `schedule` is null or valid for writes.
unsafe fn set(key: *const [u8; 8], schedule: *mut DES_key_schedule) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { block(key) }) else {
        return false;
    };
    // SAFETY: the caller's guarantee (any octets are a valid schedule).
    let Some(s) = (unsafe { schedule.as_mut() }) else {
        return false;
    };
    store(s, &des::set_key_unchecked(&k));
    true
}

ffi_export! {
    /// Sets the schedule without checking the key.
    ///
    /// # Safety
    /// `key` is null or holds 8 octets; `schedule` is null or valid for writes.
    pub unsafe extern "C" fn DES_set_key_unchecked(key: *mut const_DES_cblock, schedule: *mut DES_key_schedule)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { set(key, schedule) };
    }
}

ffi_export! {
    /// Sets the schedule only for a key with odd parity that isn't weak. Returns 0, -1 for a
    /// parity error, or -2 for a weak key (or null).
    ///
    /// # Safety
    /// As for `DES_set_key_unchecked`.
    pub unsafe extern "C" fn DES_set_key_checked(key: *mut const_DES_cblock, schedule: *mut DES_key_schedule) -> c_int
    where failure = -2, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { block(key) }) else { return -2 };
        if !des::check_key_parity(&k) {
            return -1;
        }
        if des::is_weak_key(&k) {
            return -2;
        }
        // SAFETY: the caller's guarantee.
        if unsafe { set(key, schedule) } { 0 } else { -2 }
    }
}

ffi_export! {
    /// Sets the schedule whatever the key, returning 0, -1 for a parity error, or -2 for a
    /// weak key (or null).
    ///
    /// # Safety
    /// As for `DES_set_key_unchecked`.
    pub unsafe extern "C" fn DES_set_key(key: *mut const_DES_cblock, schedule: *mut DES_key_schedule) -> c_int
    where failure = -2, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { block(key) }) else { return -2 };
        let mut ret = 0;
        if !des::check_key_parity(&k) {
            ret = -1;
        }
        if des::is_weak_key(&k) {
            ret = -2;
        }
        // SAFETY: the caller's guarantee.
        if unsafe { set(key, schedule) } { ret } else { -2 }
    }
}

ffi_export! {
    /// `DES_set_key`.
    ///
    /// # Safety
    /// As for `DES_set_key_unchecked`.
    pub unsafe extern "C" fn DES_key_sched(key: *mut const_DES_cblock, schedule: *mut DES_key_schedule) -> c_int
    where failure = -2, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { DES_set_key(key, schedule) }
    }
}

ffi_export! {
    /// A random key with odd parity that isn't weak. Returns 1, or 0 if the generator fails.
    ///
    /// # Safety
    /// `ret` is null or has room for 8 octets.
    pub unsafe extern "C" fn DES_random_key(ret: *mut DES_cblock) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        if ret.is_null() {
            return 0;
        }
        loop {
            // SAFETY: the caller's 8 octets.
            if unsafe { RAND_priv_bytes(ret.cast(), 8) } != 1 {
                return 0;
            }
            // SAFETY: as above.
            let Some(k) = (unsafe { block(ret) }) else { return 0 };
            if !des::is_weak_key(&k) {
                break;
            }
        }
        // SAFETY: as above.
        unsafe { DES_set_odd_parity(ret) };
        1
    }
}

/// Runs `f` on the caller's two words.
///
/// # Safety
/// `data` is null or holds two `DES_LONG`s.
unsafe fn words(data: *mut DES_LONG, f: impl FnOnce(&mut [u32; 2])) {
    if data.is_null() {
        return;
    }
    // SAFETY: the caller's two words, read whatever their alignment.
    let mut d = unsafe { data.cast::<[u32; 2]>().read_unaligned() };
    f(&mut d);
    // SAFETY: as above.
    unsafe { data.cast::<[u32; 2]>().write_unaligned(d) };
}

ffi_export! {
    /// One block (two words in `c2l` order) with the permutations, encrypting for nonzero
    /// `enc`.
    ///
    /// # Safety
    /// `data` holds two words; `ks` is a valid schedule.
    pub unsafe extern "C" fn DES_encrypt1(data: *mut DES_LONG, ks: *mut DES_key_schedule, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { schedule(ks) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { words(data, |d| des::encrypt1(d, &s, enc != 0)) };
    }
}

ffi_export! {
    /// One block without the permutations, encrypting for nonzero `enc`.
    ///
    /// # Safety
    /// As for `DES_encrypt1`.
    pub unsafe extern "C" fn DES_encrypt2(data: *mut DES_LONG, ks: *mut DES_key_schedule, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { schedule(ks) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { words(data, |d| des::encrypt2(d, &s, enc != 0)) };
    }
}

/// The three schedules.
///
/// # Safety
/// Each is null or a valid schedule.
unsafe fn three(
    ks1: *const DES_key_schedule,
    ks2: *const DES_key_schedule,
    ks3: *const DES_key_schedule,
) -> Option<(Schedule, Schedule, Schedule)> {
    // SAFETY: the caller's guarantee.
    let a = unsafe { schedule(ks1) }?;
    // SAFETY: the caller's guarantee.
    let b = unsafe { schedule(ks2) }?;
    // SAFETY: the caller's guarantee.
    let c = unsafe { schedule(ks3) }?;
    Some((a, b, c))
}

ffi_export! {
    /// Triple-DES encryption (EDE) of one block.
    ///
    /// # Safety
    /// `data` holds two words; the schedules are valid.
    pub unsafe extern "C" fn DES_encrypt3(data: *mut DES_LONG, ks1: *mut DES_key_schedule, ks2: *mut DES_key_schedule, ks3: *mut DES_key_schedule)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some((a, b, c)) = (unsafe { three(ks1, ks2, ks3) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { words(data, |d| des::encrypt3(d, &a, &b, &c)) };
    }
}

ffi_export! {
    /// Triple-DES decryption of one block.
    ///
    /// # Safety
    /// As for `DES_encrypt3`.
    pub unsafe extern "C" fn DES_decrypt3(data: *mut DES_LONG, ks1: *mut DES_key_schedule, ks2: *mut DES_key_schedule, ks3: *mut DES_key_schedule)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some((a, b, c)) = (unsafe { three(ks1, ks2, ks3) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { words(data, |d| des::decrypt3(d, &a, &b, &c)) };
    }
}

/// One block through `c` into `output`.
///
/// # Safety
/// `input` and `output` are null or hold 8 octets.
unsafe fn one_block(input: *const [u8; 8], output: *mut [u8; 8], c: Cipher<'_>, enc: bool) {
    // SAFETY: the caller's guarantee.
    let Some(x) = (unsafe { block(input) }) else {
        return;
    };
    if output.is_null() {
        return;
    }
    let y = des::ecb(&x, c, enc);
    // SAFETY: the caller's 8 octets.
    unsafe { write_array(output.cast(), &y) };
}

ffi_export! {
    /// One block, encrypting for nonzero `enc`.
    ///
    /// # Safety
    /// `input` and `output` hold 8 octets; `ks` is a valid schedule.
    pub unsafe extern "C" fn DES_ecb_encrypt(input: *mut const_DES_cblock, output: *mut DES_cblock, ks: *mut DES_key_schedule, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { schedule(ks) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { one_block(input, output, Cipher::Single(&s), enc != 0) };
    }
}

ffi_export! {
    /// One block of triple DES, encrypting for nonzero `enc`.
    ///
    /// # Safety
    /// `input` and `output` hold 8 octets; the schedules are valid.
    pub unsafe extern "C" fn DES_ecb3_encrypt(input: *mut const_DES_cblock, output: *mut DES_cblock, ks1: *mut DES_key_schedule, ks2: *mut DES_key_schedule, ks3: *mut DES_key_schedule, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some((a, b, c)) = (unsafe { three(ks1, ks2, ks3) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { one_block(input, output, Cipher::Triple(&a, &b, &c), enc != 0) };
    }
}

/// A CBC-like mode over `length` octets: encryption reads `length` and writes it rounded up,
/// decryption the other way round; `run` gets the buffers and the IV, which is written back.
///
/// # Safety
/// The buffers hold their lengths; `ivec` is null or holds 8 octets.
unsafe fn blockwise(
    input: *const c_uchar,
    output: *mut c_uchar,
    length: c_long,
    ivec: *mut DES_cblock,
    enc: bool,
    run: impl FnOnce(&[u8], &mut [u8], usize, &mut [u8; 8]),
) {
    let Some(len) = nonneg(length) else { return };
    let (in_len, out_len) = if enc {
        (len, whole(len))
    } else {
        (whole(len), len)
    };
    // SAFETY: the caller's guarantee.
    let Some(mut iv) = (unsafe { block(ivec) }) else {
        return;
    };
    // SAFETY: the caller's guarantee.
    let Some((input, out)) = (unsafe { buffers(input, in_len, output, out_len) }) else {
        return;
    };
    run(&input, out, len, &mut iv);
    // SAFETY: the caller's IV, read above.
    unsafe { write_array(ivec.cast(), &iv) };
}

ffi_export! {
    /// CBC over `length` octets, leaving `ivec` as it was; a partial last block is padded
    /// with zeros and written whole on encryption.
    ///
    /// # Safety
    /// `input` holds and `output` has room for `length` octets, rounded up to whole blocks on
    /// the side that's whole; `ivec` holds 8; `schedule` is valid.
    pub unsafe extern "C" fn DES_cbc_encrypt(input: *const c_uchar, output: *mut c_uchar, length: c_long, schedule: *mut DES_key_schedule, ivec: *mut DES_cblock, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { self::schedule(schedule) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { blockwise(input, output, length, ivec, enc != 0, |i, o, l, iv| des::cbc(i, o, l, Cipher::Single(&s), iv, enc != 0, false)) };
    }
}

ffi_export! {
    /// CBC over `length` octets, updating `ivec`.
    ///
    /// # Safety
    /// As for `DES_cbc_encrypt`.
    pub unsafe extern "C" fn DES_ncbc_encrypt(input: *const c_uchar, output: *mut c_uchar, length: c_long, schedule: *mut DES_key_schedule, ivec: *mut DES_cblock, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { self::schedule(schedule) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { blockwise(input, output, length, ivec, enc != 0, |i, o, l, iv| des::cbc(i, o, l, Cipher::Single(&s), iv, enc != 0, true)) };
    }
}

ffi_export! {
    /// Triple-DES CBC over `length` octets, updating `ivec`.
    ///
    /// # Safety
    /// As for `DES_cbc_encrypt`, with three schedules.
    pub unsafe extern "C" fn DES_ede3_cbc_encrypt(input: *const c_uchar, output: *mut c_uchar, length: c_long, ks1: *mut DES_key_schedule, ks2: *mut DES_key_schedule, ks3: *mut DES_key_schedule, ivec: *mut DES_cblock, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some((a, b, c)) = (unsafe { three(ks1, ks2, ks3) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { blockwise(input, output, length, ivec, enc != 0, |i, o, l, iv| des::cbc(i, o, l, Cipher::Triple(&a, &b, &c), iv, enc != 0, true)) };
    }
}

ffi_export! {
    /// DESX-style CBC with the whitening blocks `inw` and `outw`, updating `ivec`.
    ///
    /// # Safety
    /// As for `DES_cbc_encrypt`; `inw` and `outw` hold 8 octets.
    pub unsafe extern "C" fn DES_xcbc_encrypt(input: *const c_uchar, output: *mut c_uchar, length: c_long, schedule: *mut DES_key_schedule, ivec: *mut DES_cblock, inw: *mut const_DES_cblock, outw: *mut const_DES_cblock, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { self::schedule(schedule) }) else { return };
        // SAFETY: the caller's guarantee.
        let (Some(inw), Some(outw)) = (unsafe { block(inw) }, unsafe { block(outw) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { blockwise(input, output, length, ivec, enc != 0, |i, o, l, iv| des::xcbc(i, o, l, &s, iv, &inw, &outw, enc != 0)) };
    }
}

ffi_export! {
    /// Propagating CBC over `length` octets; `ivec` stays as it was.
    ///
    /// # Safety
    /// As for `DES_cbc_encrypt`.
    pub unsafe extern "C" fn DES_pcbc_encrypt(input: *const c_uchar, output: *mut c_uchar, length: c_long, schedule: *mut DES_key_schedule, ivec: *mut DES_cblock, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { self::schedule(schedule) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { blockwise(input, output, length, ivec, enc != 0, |i, o, l, iv| des::pcbc(i, o, l, &s, iv, enc != 0)) };
    }
}

/// CFB with `numbits` (1 to 64) bits a step over `length` octets (whole steps only).
///
/// # Safety
/// The buffers hold `length` octets; `ivec` is null or holds 8.
unsafe fn cfb(
    input: *const c_uchar,
    out: *mut c_uchar,
    numbits: c_int,
    length: c_long,
    c: Cipher<'_>,
    ivec: *mut DES_cblock,
    enc: bool,
) {
    let Some(bits) = u32::try_from(numbits).ok().filter(|b| (1..=64).contains(b)) else {
        return;
    };
    let Some(len) = nonneg(length) else { return };
    let step = usize::try_from(bits.div_ceil(8)).unwrap_or(8);
    let used = len / step * step;
    // SAFETY: the caller's guarantee.
    let Some(mut iv) = (unsafe { block(ivec) }) else {
        return;
    };
    // SAFETY: the caller's guarantee.
    let Some((input, out)) = (unsafe { buffers(input, used, out, used) }) else {
        return;
    };
    des::cfb(&input, out, bits, len, c, &mut iv, enc);
    // SAFETY: the caller's IV, read above.
    unsafe { write_array(ivec.cast(), &iv) };
}

ffi_export! {
    /// CFB with `numbits` (1 to 64) bits a step over `length` octets; `ivec` updated.
    ///
    /// # Safety
    /// `in_` holds and `out` has room for `length` octets; `ivec` holds 8; `schedule` is valid.
    pub unsafe extern "C" fn DES_cfb_encrypt(in_: *const c_uchar, out: *mut c_uchar, numbits: c_int, length: c_long, schedule: *mut DES_key_schedule, ivec: *mut DES_cblock, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { self::schedule(schedule) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { cfb(in_, out, numbits, length, Cipher::Single(&s), ivec, enc != 0) };
    }
}

ffi_export! {
    /// Triple-DES CFB with `numbits` (1 to 64) bits a step over `length` octets.
    ///
    /// # Safety
    /// As for `DES_cfb_encrypt`, with three schedules.
    pub unsafe extern "C" fn DES_ede3_cfb_encrypt(in_: *const c_uchar, out: *mut c_uchar, numbits: c_int, length: c_long, ks1: *mut DES_key_schedule, ks2: *mut DES_key_schedule, ks3: *mut DES_key_schedule, ivec: *mut DES_cblock, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some((a, b, c)) = (unsafe { three(ks1, ks2, ks3) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { cfb(in_, out, numbits, length, Cipher::Triple(&a, &b, &c), ivec, enc != 0) };
    }
}

/// CFB-64 or OFB-64 by octets through `run`, with the caller's IV and position.
///
/// # Safety
/// The buffers hold `length` octets; `ivec` is null or holds 8; `num` is null or valid.
unsafe fn by_octets(
    input: *const c_uchar,
    out: *mut c_uchar,
    length: c_long,
    ivec: *mut DES_cblock,
    num: *mut c_int,
    run: impl FnOnce(&[u8], &mut [u8], &mut [u8; 8], &mut i32),
) {
    let Some(len) = nonneg(length) else { return };
    // SAFETY: the caller's guarantee.
    let Some(mut n) = (unsafe { num.as_ref() }).copied() else {
        return;
    };
    // SAFETY: the caller's guarantee.
    let Some(mut iv) = (unsafe { block(ivec) }) else {
        return;
    };
    // SAFETY: the caller's guarantee.
    let Some((input, out)) = (unsafe { buffers(input, len, out, len) }) else {
        return;
    };
    run(&input, out, &mut iv, &mut n);
    // SAFETY: the caller's IV, read above.
    unsafe { write_array(ivec.cast(), &iv) };
    // SAFETY: the caller's position, read above.
    unsafe { num.write(n) };
}

ffi_export! {
    /// CFB-64 by octets; `*num` (its low three bits) is the position in `ivec`.
    ///
    /// # Safety
    /// `in_` holds and `out` has room for `length` octets; `ivec` holds 8; `num` is valid;
    /// `schedule` is valid.
    pub unsafe extern "C" fn DES_cfb64_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: c_long, schedule: *mut DES_key_schedule, ivec: *mut DES_cblock, num: *mut c_int, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { self::schedule(schedule) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { by_octets(in_, out, length, ivec, num, |i, o, iv, n| des::cfb64(i, o, Cipher::Single(&s), iv, n, enc != 0)) };
    }
}

ffi_export! {
    /// Triple-DES CFB-64 by octets.
    ///
    /// # Safety
    /// As for `DES_cfb64_encrypt`, with three schedules.
    pub unsafe extern "C" fn DES_ede3_cfb64_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: c_long, ks1: *mut DES_key_schedule, ks2: *mut DES_key_schedule, ks3: *mut DES_key_schedule, ivec: *mut DES_cblock, num: *mut c_int, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some((a, b, c)) = (unsafe { three(ks1, ks2, ks3) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { by_octets(in_, out, length, ivec, num, |i, o, iv, n| des::cfb64(i, o, Cipher::Triple(&a, &b, &c), iv, n, enc != 0)) };
    }
}

ffi_export! {
    /// OFB-64 by octets; `*num` (its low three bits) is the position in the keystream block.
    ///
    /// # Safety
    /// As for `DES_cfb64_encrypt`.
    pub unsafe extern "C" fn DES_ofb64_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: c_long, schedule: *mut DES_key_schedule, ivec: *mut DES_cblock, num: *mut c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { self::schedule(schedule) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { by_octets(in_, out, length, ivec, num, |i, o, iv, n| des::ofb64(i, o, Cipher::Single(&s), iv, n)) };
    }
}

ffi_export! {
    /// Triple-DES OFB-64 by octets.
    ///
    /// # Safety
    /// As for `DES_ede3_cfb64_encrypt`.
    pub unsafe extern "C" fn DES_ede3_ofb64_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: c_long, k1: *mut DES_key_schedule, k2: *mut DES_key_schedule, k3: *mut DES_key_schedule, ivec: *mut DES_cblock, num: *mut c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some((a, b, c)) = (unsafe { three(k1, k2, k3) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { by_octets(in_, out, length, ivec, num, |i, o, iv, n| des::ofb64(i, o, Cipher::Triple(&a, &b, &c), iv, n)) };
    }
}

ffi_export! {
    /// OFB with `numbits` (1 to 64) bits a step, `length` steps (not octets) of
    /// `(numbits + 7) / 8` octets each; `ivec` updated.
    ///
    /// # Safety
    /// `in_` holds and `out` has room for `length` steps; `ivec` holds 8; `schedule` is
    /// valid.
    pub unsafe extern "C" fn DES_ofb_encrypt(in_: *const c_uchar, out: *mut c_uchar, numbits: c_int, length: c_long, schedule: *mut DES_key_schedule, ivec: *mut DES_cblock)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { self::schedule(schedule) }) else { return };
        let Some(bits) = u32::try_from(numbits).ok().filter(|b| (1..=64).contains(b)) else { return };
        let steps = nonneg(length).unwrap_or(0);
        let octets = steps.saturating_mul(usize::try_from(bits.div_ceil(8)).unwrap_or(8));
        // SAFETY: the caller's guarantee.
        let Some(mut iv) = (unsafe { block(ivec) }) else { return };
        // SAFETY: the caller's guarantee.
        let Some((input, out)) = (unsafe { buffers(in_, octets, out, octets) }) else { return };
        des::ofb(&input, out, bits, steps, &s, &mut iv);
        // SAFETY: the caller's IV, read above.
        unsafe { write_array(ivec.cast(), &iv) };
    }
}

ffi_export! {
    /// The CBC-MAC of `length` octets under `schedule` from `ivec`, into `output` if it isn't
    /// null; returns its second word byte-swapped (MIT Kerberos's checksum), or 0 for null.
    ///
    /// # Safety
    /// `input` holds `length` octets; `output` is null or has room for 8; `ivec` holds 8;
    /// `schedule` is valid.
    pub unsafe extern "C" fn DES_cbc_cksum(input: *const c_uchar, output: *mut DES_cblock, length: c_long, schedule: *mut DES_key_schedule, ivec: *mut const_DES_cblock) -> DES_LONG
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { self::schedule(schedule) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        let Some(iv) = (unsafe { block(ivec) }) else { return 0 };
        let len = nonneg(length).unwrap_or(0);
        // SAFETY: the caller's guarantee.
        let Some((input, _)) = (unsafe { buffers(input, len, ptr::null_mut(), 0) }) else { return 0 };
        let (mac, r) = des::cbc_cksum(&input, len, &s, &iv);
        if !output.is_null() {
            // SAFETY: the caller's 8 octets.
            unsafe { write_array(output.cast(), &mac) };
        }
        r
    }
}

ffi_export! {
    /// Kerberos's quadratic checksum of `length` octets from `seed`, `out_count` rounds (1 to
    /// 4), each round's two words into `output` (if it isn't null); returns the last first
    /// word.
    ///
    /// # Safety
    /// `input` holds `length` octets; `output` is null or has room for `out_count` blocks (at
    /// most 4); `seed` holds 8.
    pub unsafe extern "C" fn DES_quad_cksum(input: *const c_uchar, output: *mut DES_cblock, length: c_long, out_count: c_int, seed: *mut DES_cblock) -> DES_LONG
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(seed) = (unsafe { block(seed) }) else { return 0 };
        let len = nonneg(length).unwrap_or(0);
        // SAFETY: the caller's guarantee.
        let Some((input, _)) = (unsafe { buffers(input, len, ptr::null_mut(), 0) }) else { return 0 };
        let (outs, r) = des::quad_cksum(&input, len, out_count, &seed);
        if !output.is_null() {
            for (i, pair) in outs.iter().enumerate() {
                let mut b = [0u8; 8];
                b[..4].copy_from_slice(&pair[0].to_ne_bytes());
                b[4..].copy_from_slice(&pair[1].to_ne_bytes());
                // SAFETY: the caller's room for this block (`i` is below `out_count`, at
                // most 4).
                unsafe { write_array(output.wrapping_add(i).cast(), &b) };
            }
        }
        r
    }
}

/// The C string at `s`, or `None` for null.
///
/// # Safety
/// `s` is null or a NUL-terminated string.
unsafe fn c_str<'a>(s: *const c_char) -> Option<&'a [u8]> {
    if s.is_null() {
        return None;
    }
    // SAFETY: the caller's string.
    Some(unsafe { CStr::from_ptr(s) }.to_bytes())
}

ffi_export! {
    /// A key from `str_`: folded, odd parity, then its CBC checksum under itself.
    ///
    /// # Safety
    /// `str_` is a NUL-terminated string; `key` has room for 8 octets.
    pub unsafe extern "C" fn DES_string_to_key(str_: *const c_char, key: *mut DES_cblock)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { c_str(str_) }) else { return };
        if key.is_null() {
            return;
        }
        let k = des::string_to_key(s);
        // SAFETY: the caller's 8 octets.
        unsafe { write_array(key.cast(), &k) };
    }
}

ffi_export! {
    /// Two keys from `str_`.
    ///
    /// # Safety
    /// `str_` is a NUL-terminated string; `key1` and `key2` have room for 8 octets each.
    pub unsafe extern "C" fn DES_string_to_2keys(str_: *const c_char, key1: *mut DES_cblock, key2: *mut DES_cblock)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { c_str(str_) }) else { return };
        if key1.is_null() || key2.is_null() {
            return;
        }
        let (a, b) = des::string_to_2keys(s);
        // SAFETY: the caller's 8 octets.
        unsafe { write_array(key1.cast(), &a) };
        // SAFETY: the caller's 8 octets.
        unsafe { write_array(key2.cast(), &b) };
    }
}

ffi_export! {
    /// Traditional `crypt(3)` of `buf` (its first 8 octets) with the two salt characters,
    /// into `ret` (14 octets, NUL-terminated). Returns `ret`, or null for a salt character
    /// that's NUL or past 127 (having written the salt's characters up to it, as OpenSSL).
    ///
    /// # Safety
    /// `buf` and `salt` are NUL-terminated strings; `ret` has room for 14 octets.
    pub unsafe extern "C" fn DES_fcrypt(buf: *const c_char, salt: *const c_char, ret: *mut c_char) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        if salt.is_null() || ret.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's salt string, its first octet.
        let s0 = unsafe { salt.cast::<u8>().read() };
        let s1 = if s0 != 0 && s0 < 128 {
            // SAFETY: the salt's second octet (the first wasn't its NUL).
            unsafe { salt.cast::<u8>().wrapping_add(1).read() }
        } else {
            0
        };
        // SAFETY: the caller's guarantee.
        let Some(pw) = (unsafe { c_str(buf) }) else { return ptr::null_mut() };
        let r = des::fcrypt(pw, [s0, s1]);
        let written = [s0, s1];
        for (i, b) in written.iter().take(r.salt_written).enumerate() {
            // SAFETY: the caller's room for 14 octets.
            unsafe { ret.cast::<u8>().wrapping_add(i).write(*b) };
        }
        let Some(out) = r.out else { return ptr::null_mut() };
        // SAFETY: as above.
        unsafe { write_array(ret.cast(), &out) };
        ret
    }
}

/// `DES_crypt`'s buffer: static, as OpenSSL's, so not thread-safe to use.
struct CryptBuf(UnsafeCell<[c_char; 14]>);

// SAFETY: as OpenSSL's: callers share it, at their own risk.
unsafe impl Sync for CryptBuf {}

static CRYPT_BUF: CryptBuf = CryptBuf(UnsafeCell::new([0; 14]));

ffi_export! {
    /// `DES_fcrypt` into a static buffer.
    ///
    /// # Safety
    /// `buf` and `salt` are NUL-terminated strings.
    pub unsafe extern "C" fn DES_crypt(buf: *const c_char, salt: *const c_char) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's strings and the static buffer of 14 octets.
        unsafe { DES_fcrypt(buf, salt, CRYPT_BUF.0.get().cast()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A schedule for a test key.
    fn ks() -> DES_key_schedule {
        // SAFETY: an all-zero schedule is valid (integers).
        let mut s: DES_key_schedule = unsafe { core::mem::zeroed() };
        store(&mut s, &des::set_key_unchecked(&[1, 2, 3, 4, 5, 6, 7, 8]));
        s
    }

    /// docs/DEVIATIONS.md: null keys, schedules, buffers, IVs, and positions do nothing (or
    /// return 0, -2, or null); the reference crashes.
    #[test]
    fn nulls_do_nothing() {
        let mut s = ks();
        let input = [1u8; 16];
        let mut out = [0u8; 16];
        let mut iv = [0u8; 8];
        // SAFETY: nulls are the case under test, with buffers of the right sizes, for each
        // call below.
        assert_eq!(unsafe { DES_set_key(ptr::null_mut(), &raw mut s) }, -2);
        // SAFETY: as above.
        assert_eq!(unsafe { DES_is_weak_key(ptr::null_mut()) }, 0);
        // SAFETY: as above.
        unsafe {
            DES_ecb_encrypt(
                input.as_ptr().cast_mut().cast(),
                out.as_mut_ptr().cast(),
                ptr::null_mut(),
                1,
            )
        };
        // SAFETY: as above.
        unsafe {
            DES_ncbc_encrypt(
                input.as_ptr(),
                out.as_mut_ptr(),
                16,
                &raw mut s,
                ptr::null_mut(),
                1,
            )
        };
        // SAFETY: as above.
        unsafe {
            DES_cfb64_encrypt(
                input.as_ptr(),
                out.as_mut_ptr(),
                16,
                &raw mut s,
                iv.as_mut_ptr().cast(),
                ptr::null_mut(),
                1,
            )
        };
        // SAFETY: as above.
        unsafe { DES_encrypt1(ptr::null_mut(), &raw mut s, 1) };
        // SAFETY: as above.
        assert!(unsafe { DES_fcrypt(ptr::null(), c"ab".as_ptr(), ptr::null_mut()) }.is_null());
        assert_eq!((out, iv), ([0; 16], [0; 8]));
    }

    /// docs/DEVIATIONS.md: a negative length does nothing; the reference writes a block (the
    /// CBC family) or loops without end (CFB and OFB by octets, CFB by bits).
    #[test]
    fn negative_lengths_do_nothing() {
        let mut s = ks();
        let input = [1u8; 16];
        let mut out = [0u8; 16];
        let mut iv = [0u8; 8];
        let mut num: c_int = 0;
        let ivp = iv.as_mut_ptr().cast::<DES_cblock>();
        // SAFETY: the test's buffers and schedule, for each call below.
        unsafe { DES_ncbc_encrypt(input.as_ptr(), out.as_mut_ptr(), -1, &raw mut s, ivp, 1) };
        // SAFETY: as above.
        unsafe {
            DES_xcbc_encrypt(
                input.as_ptr(),
                out.as_mut_ptr(),
                -9,
                &raw mut s,
                ivp,
                ivp,
                ivp,
                1,
            )
        };
        // SAFETY: as above.
        unsafe { DES_cfb_encrypt(input.as_ptr(), out.as_mut_ptr(), 8, -1, &raw mut s, ivp, 1) };
        // SAFETY: as above.
        unsafe {
            DES_ofb64_encrypt(
                input.as_ptr(),
                out.as_mut_ptr(),
                -1,
                &raw mut s,
                ivp,
                &raw mut num,
            )
        };
        assert_eq!((out, iv, num), ([0; 16], [0; 8], 0));
    }

    /// docs/DEVIATIONS.md: triple-DES CFB with a bit width of 0 or less, and OFB with one,
    /// do nothing; the reference loops without end or shifts by more than a word.
    #[test]
    fn bad_bit_widths_do_nothing() {
        let mut s = ks();
        let input = [1u8; 16];
        let mut out = [0u8; 16];
        let mut iv = [0u8; 8];
        let ivp = iv.as_mut_ptr().cast::<DES_cblock>();
        // SAFETY: the test's buffers and schedule, for each call below.
        unsafe {
            DES_ede3_cfb_encrypt(
                input.as_ptr(),
                out.as_mut_ptr(),
                0,
                16,
                &raw mut s,
                &raw mut s,
                &raw mut s,
                ivp,
                1,
            )
        };
        // SAFETY: as above.
        unsafe {
            DES_ede3_cfb_encrypt(
                input.as_ptr(),
                out.as_mut_ptr(),
                -1,
                16,
                &raw mut s,
                &raw mut s,
                &raw mut s,
                ivp,
                1,
            )
        };
        // SAFETY: as above.
        unsafe { DES_ofb_encrypt(input.as_ptr(), out.as_mut_ptr(), 0, 2, &raw mut s, ivp) };
        assert_eq!((out, iv), ([0; 16], [0; 8]));
    }
}
