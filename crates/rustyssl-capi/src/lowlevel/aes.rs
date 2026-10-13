//! The deprecated AES functions (`AES_set_encrypt_key(3)`, `AES_encrypt(3)`, `AES_cbc_encrypt`,
//! the CFB, OFB, and IGE modes, and the RFC 3394 key wraps), over
//! [`rustyssl_crypto::lowlevel::aes`] and the block modes.
//!
//! An `AES_KEY` holds the expanded key schedule in its words, laid out as the reference's code
//! for the platform leaves it: OpenSSL's x86_64 assembly keeps each round key's octets as they
//! are, its C code (every other target) each four as a big-endian word. Only the schedule's
//! words and `rounds` are written. Where OpenSSL dereferences a null key or buffer and crashes,
//! these do nothing (returning -1 or 0 where they return anything), and a key with a number of
//! rounds AES doesn't have is refused (docs/DEVIATIONS.md). The IGE functions abort on a bad
//! argument, as OpenSSL's assertions do.

use core::ffi::{CStr, c_char, c_int, c_uchar, c_uint};

use rustyssl_abi::{AES_BLOCK_SIZE, AES_DECRYPT, AES_ENCRYPT, AES_KEY, ERR_LIB_CRYPTO};
use rustyssl_crypto::lowlevel::aes::{MAX_ROUNDS, Schedule, decrypt_schedule, encrypt_schedule};
use rustyssl_crypto::lowlevel::modes::{self, BLOCK, Block128};

use super::modes::{cbc_decrypt, cbc_encrypt, stream, unwrap, with_iv, wrap};
use super::{buffers, read_array, write_array};
use crate::ffi::ffi_export;
use crate::init::OPENSSL_die;

/// An `AES_KEY` word from four round-key octets: as they are on x86_64 (OpenSSL's assembly),
/// a big-endian word elsewhere (its C code).
#[cfg(target_arch = "x86_64")]
fn to_word(b: [u8; 4]) -> u32 {
    u32::from_ne_bytes(b)
}

/// An `AES_KEY` word from four round-key octets: as they are on x86_64 (OpenSSL's assembly),
/// a big-endian word elsewhere (its C code).
#[cfg(not(target_arch = "x86_64"))]
fn to_word(b: [u8; 4]) -> u32 {
    u32::from_be_bytes(b)
}

/// The four round-key octets of an `AES_KEY` word.
#[cfg(target_arch = "x86_64")]
fn from_word(w: u32) -> [u8; 4] {
    w.to_ne_bytes()
}

/// The four round-key octets of an `AES_KEY` word.
#[cfg(not(target_arch = "x86_64"))]
fn from_word(w: u32) -> [u8; 4] {
    w.to_be_bytes()
}

/// The key's schedule, or `None` for a number of rounds AES doesn't have.
fn load(key: &AES_KEY) -> Option<Schedule> {
    let rounds = usize::try_from(key.rounds)
        .ok()
        .filter(|r| matches!(r, 10 | 12 | 14))?;
    let mut s = Schedule {
        keys: [[0; 16]; MAX_ROUNDS + 1],
        rounds,
    };
    for (round, words) in s.keys.iter_mut().zip(key.rd_key.as_chunks::<4>().0) {
        for (dst, w) in round.as_chunks_mut::<4>().0.iter_mut().zip(words) {
            *dst = from_word(*w);
        }
    }
    Some(s)
}

/// Writes the schedule's words and rounds into the key, leaving the words past it.
fn store(key: &mut AES_KEY, s: &Schedule) {
    let words = s.rounds.saturating_add(1).saturating_mul(4);
    let octets = s.keys.as_flattened();
    for (w, b) in key
        .rd_key
        .iter_mut()
        .zip(octets.as_chunks::<4>().0)
        .take(words)
    {
        *w = to_word(*b);
    }
    key.rounds = c_int::try_from(s.rounds).unwrap_or(0);
}

/// Encryption with a schedule.
struct Encrypt(Schedule);

impl Block128 for Encrypt {
    fn block(&self, input: &[u8; BLOCK]) -> [u8; BLOCK] {
        self.0.encrypt(input)
    }
}

/// Decryption with a schedule.
struct Decrypt(Schedule);

impl Block128 for Decrypt {
    fn block(&self, input: &[u8; BLOCK]) -> [u8; BLOCK] {
        self.0.decrypt(input)
    }
}

/// The key's schedule, for null or a bad number of rounds `None`.
///
/// # Safety
/// `key` is null or a valid `AES_KEY`.
unsafe fn schedule(key: *const AES_KEY) -> Option<Schedule> {
    // SAFETY: the caller's guarantee.
    load(unsafe { key.as_ref() }?)
}

/// Sets `key` to the schedule `make` expands from the `bits / 8` octets at `user_key`.
///
/// # Safety
/// `user_key` is null or holds `bits / 8` octets; `key` is null or valid for writes.
unsafe fn set_key(
    user_key: *const c_uchar,
    bits: c_int,
    key: *mut AES_KEY,
    make: fn(&[u8]) -> Result<Schedule, rustyssl_crypto::lowlevel::aes::Error>,
) -> c_int {
    if user_key.is_null() || key.is_null() {
        return -1;
    }
    let len = match bits {
        128 => 16,
        192 => 24,
        256 => 32,
        _ => return -2,
    };
    // SAFETY: the caller's key octets.
    let octets = unsafe { core::slice::from_raw_parts(user_key, len) };
    let Ok(s) = make(octets) else { return -2 };
    // SAFETY: the caller's key, non-null, which may be uninitialized: only its integer words
    // are written.
    let Some(key) = (unsafe { key.as_mut() }) else {
        return -1;
    };
    store(key, &s);
    0
}

ffi_export! {
    /// The AES implementation's options: "aes(partial)", as OpenSSL's.
    ///
    /// # Safety
    /// Always safe to call.
    pub unsafe extern "C" fn AES_options() -> *const c_char
    where failure = c"aes(partial)".as_ptr(), library = ERR_LIB_CRYPTO
    {
        c"aes(partial)".as_ptr()
    }
}

ffi_export! {
    /// Sets `key` to the encryption schedule of the `bits` (128, 192, or 256) bits at
    /// `user_key`. Returns 0, -1 for a null pointer, or -2 for another size.
    ///
    /// # Safety
    /// `user_key` is null or holds `bits / 8` octets; `key` is null or valid for writes.
    pub unsafe extern "C" fn AES_set_encrypt_key(user_key: *const c_uchar, bits: c_int, key: *mut AES_KEY) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_key(user_key, bits, key, encrypt_schedule) }
    }
}

ffi_export! {
    /// Sets `key` to the decryption schedule of the `bits` bits at `user_key`. Returns as
    /// `AES_set_encrypt_key`.
    ///
    /// # Safety
    /// As for `AES_set_encrypt_key`.
    pub unsafe extern "C" fn AES_set_decrypt_key(user_key: *const c_uchar, bits: c_int, key: *mut AES_KEY) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_key(user_key, bits, key, decrypt_schedule) }
    }
}

/// One block through `f` with the key's schedule; nothing for a null pointer or a bad key.
///
/// # Safety
/// `input` and `out` are null or hold 16 octets; `key` is null or a valid `AES_KEY`.
unsafe fn one_block(
    input: *const c_uchar,
    out: *mut c_uchar,
    key: *const AES_KEY,
    f: fn(&Schedule, &[u8; BLOCK]) -> [u8; BLOCK],
) {
    // SAFETY: the caller's guarantee.
    let Some(s) = (unsafe { schedule(key) }) else {
        return;
    };
    // SAFETY: the caller's guarantee.
    let Some(block) = (unsafe { read_array::<BLOCK>(input) }) else {
        return;
    };
    if out.is_null() {
        return;
    }
    let result = f(&s, &block);
    // SAFETY: the caller's 16 octets of output.
    unsafe { write_array(out, &result) };
}

ffi_export! {
    /// Encrypts the block at `in_` into `out` with an encryption schedule.
    ///
    /// # Safety
    /// `in_` and `out` hold 16 octets (they may be the same); `key` is a valid `AES_KEY`.
    pub unsafe extern "C" fn AES_encrypt(in_: *const c_uchar, out: *mut c_uchar, key: *const AES_KEY)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { one_block(in_, out, key, Schedule::encrypt) }
    }
}

ffi_export! {
    /// Decrypts the block at `in_` into `out` with a decryption schedule.
    ///
    /// # Safety
    /// As for `AES_encrypt`.
    pub unsafe extern "C" fn AES_decrypt(in_: *const c_uchar, out: *mut c_uchar, key: *const AES_KEY)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { one_block(in_, out, key, Schedule::decrypt) }
    }
}

ffi_export! {
    /// `AES_encrypt` for `AES_ENCRYPT`, `AES_decrypt` for any other `enc`.
    ///
    /// # Safety
    /// As for `AES_encrypt`.
    pub unsafe extern "C" fn AES_ecb_encrypt(in_: *const c_uchar, out: *mut c_uchar, key: *const AES_KEY, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let f = if enc == AES_ENCRYPT { Schedule::encrypt } else { Schedule::decrypt };
        // SAFETY: the caller's guarantee.
        unsafe { one_block(in_, out, key, f) }
    }
}

ffi_export! {
    /// CBC-encrypts (`enc` nonzero, with an encryption schedule) or decrypts `length` octets,
    /// chaining from and updating `ivec`: a partial last block is padded and written whole on
    /// encryption, read whole on decryption.
    ///
    /// # Safety
    /// `in_` and `out` hold `length` octets, rounded up to whole blocks for the input on
    /// decryption and the output on encryption; `ivec` holds 16; `key` is a valid `AES_KEY`.
    pub unsafe extern "C" fn AES_cbc_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: usize, key: *const AES_KEY, ivec: *mut c_uchar, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        if length == 0 {
            return;
        }
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { schedule(key) }) else { return };
        if enc != 0 {
            // SAFETY: the caller's guarantee.
            unsafe { cbc_encrypt(in_, out, length, ivec, &Encrypt(s)) }
        } else {
            // SAFETY: the caller's guarantee.
            unsafe { cbc_decrypt(in_, out, length, ivec, &Decrypt(s)) }
        }
    }
}

ffi_export! {
    /// CFB-128 over `length` octets with an encryption schedule (both ways), `*num` the
    /// position in `ivec`.
    ///
    /// # Safety
    /// `in_` holds and `out` has room for `length` octets; `ivec` holds 16; `num` is valid
    /// for reads and writes; `key` is a valid `AES_KEY`.
    pub unsafe extern "C" fn AES_cfb128_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: usize, key: *const AES_KEY, ivec: *mut c_uchar, num: *mut c_int, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { schedule(key) }) else { return };
        let b = Encrypt(s);
        // SAFETY: the caller's guarantee.
        unsafe { stream(in_, out, length, ivec, num, |i, o, iv, n| modes::cfb_encrypt(i, o, iv, n, enc != 0, &b)) }
    }
}

ffi_export! {
    /// CFB-1 over `length` bits, most significant first; the other bits of the last output
    /// octet keep their values. `num` isn't used.
    ///
    /// # Safety
    /// `in_` holds and `out` has room for `length` bits rounded up to octets; `ivec` holds 16;
    /// `key` is a valid `AES_KEY`.
    pub unsafe extern "C" fn AES_cfb1_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: usize, key: *const AES_KEY, ivec: *mut c_uchar, num: *mut c_int, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let _ = num;
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { schedule(key) }) else { return };
        let b = Encrypt(s);
        let octets = length.div_ceil(8);
        // SAFETY: the caller's guarantee.
        unsafe { with_iv(in_, octets, out, octets, ivec, |i, o, iv| modes::cfb1_encrypt(i, o, length, iv, enc != 0, &b)) };
    }
}

ffi_export! {
    /// CFB-8 over `length` octets. `num` isn't used.
    ///
    /// # Safety
    /// `in_` holds and `out` has room for `length` octets; `ivec` holds 16; `key` is a valid
    /// `AES_KEY`.
    pub unsafe extern "C" fn AES_cfb8_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: usize, key: *const AES_KEY, ivec: *mut c_uchar, num: *mut c_int, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let _ = num;
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { schedule(key) }) else { return };
        let b = Encrypt(s);
        // SAFETY: the caller's guarantee.
        unsafe { with_iv(in_, length, out, length, ivec, |i, o, iv| modes::cfb8_encrypt(i, o, iv, enc != 0, &b)) };
    }
}

ffi_export! {
    /// OFB over `length` octets with an encryption schedule, `*num` the position in `ivec`.
    ///
    /// # Safety
    /// As for `AES_cfb128_encrypt`.
    pub unsafe extern "C" fn AES_ofb128_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: usize, key: *const AES_KEY, ivec: *mut c_uchar, num: *mut c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { schedule(key) }) else { return };
        let b = Encrypt(s);
        // SAFETY: the caller's guarantee.
        unsafe { stream(in_, out, length, ivec, num, |i, o, iv, n| modes::ofb_encrypt(i, o, iv, n, &b)) }
    }
}

/// `OPENSSL_assert` in `aes_ige.c`: aborts with OpenSSL's message if `ok` is false.
fn ige_assert(ok: bool, text: &CStr, line: c_int) {
    if !ok {
        // SAFETY: static strings.
        unsafe { OPENSSL_die(text.as_ptr(), c"crypto/aes/aes_ige.c".as_ptr(), line) };
    }
}

/// IGE's and bi-IGE's assertions: no null pointer, `enc` one of the two, whole blocks.
fn ige_checks(pointers: bool, enc: c_int, length: usize, line: c_int) {
    ige_assert(
        pointers,
        c"assertion failed: in && out && key && ivec",
        line,
    );
    ige_assert(
        enc == AES_ENCRYPT || enc == AES_DECRYPT,
        c"assertion failed: (AES_ENCRYPT == enc) || (AES_DECRYPT == enc)",
        line.saturating_add(1),
    );
    let block = usize::try_from(AES_BLOCK_SIZE).unwrap_or(BLOCK);
    ige_assert(
        length.is_multiple_of(block),
        c"assertion failed: (length % AES_BLOCK_SIZE) == 0",
        line.saturating_add(2),
    );
}

ffi_export! {
    /// IGE over `length` octets (whole blocks): `ivec` holds two blocks, the previous
    /// ciphertext and plaintext, and ends as the last ones. Aborts for a null pointer, another
    /// `enc`, or a partial block, as OpenSSL's assertions do.
    ///
    /// # Safety
    /// `in_` holds and `out` has room for `length` octets; `ivec` holds 32; `key` is a valid
    /// `AES_KEY` for the direction.
    pub unsafe extern "C" fn AES_ige_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: usize, key: *const AES_KEY, ivec: *mut c_uchar, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        if length == 0 {
            return;
        }
        ige_checks(!in_.is_null() && !out.is_null() && !key.is_null() && !ivec.is_null(), enc, length, 58);
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { schedule(key) }) else { return };
        // SAFETY: the caller's guarantee.
        let Some(mut iv) = (unsafe { read_array::<32>(ivec) }) else { return };
        // SAFETY: the caller's guarantee.
        let Some((input, out)) = (unsafe { buffers(in_, length, out, length) }) else { return };
        if enc == AES_ENCRYPT {
            modes::ige(&input, out, &mut iv, true, &Encrypt(s));
        } else {
            modes::ige(&input, out, &mut iv, false, &Decrypt(s));
        }
        // SAFETY: the caller's IV, read above.
        unsafe { write_array(ivec, &iv) };
    }
}

ffi_export! {
    /// Bi-directional IGE over `length` octets (whole blocks) with `key` alone (`key2` is
    /// never used, as in OpenSSL), under the four blocks at `ivec`. Aborts as
    /// `AES_ige_encrypt` does, a zero length included.
    ///
    /// # Safety
    /// `in_` holds and `out` has room for `length` octets; `ivec` holds 64; `key` is a valid
    /// `AES_KEY` for the direction.
    pub unsafe extern "C" fn AES_bi_ige_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: usize, key: *const AES_KEY, key2: *const AES_KEY, ivec: *const c_uchar, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let _ = key2;
        ige_checks(!in_.is_null() && !out.is_null() && !key.is_null() && !ivec.is_null(), enc, length, 194);
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { schedule(key) }) else { return };
        // SAFETY: the caller's guarantee.
        let Some(iv) = (unsafe { read_array::<64>(ivec) }) else { return };
        // SAFETY: the caller's guarantee.
        let Some((input, out)) = (unsafe { buffers(in_, length, out, length) }) else { return };
        if enc == AES_ENCRYPT {
            modes::bi_ige(&input, out, &iv, true, &Encrypt(s));
        } else {
            modes::bi_ige(&input, out, &iv, false, &Decrypt(s));
        }
    }
}

/// A wrap's length as OpenSSL's `int` return value.
fn as_int(r: usize) -> c_int {
    u32::try_from(r).map_or(0, u32::cast_signed)
}

ffi_export! {
    /// RFC 3394-wraps `inlen` octets with an encryption schedule and `iv` (8 octets, or the
    /// default for null). Returns `inlen + 8`, or 0.
    ///
    /// # Safety
    /// `key` is a valid `AES_KEY`; `iv` is null or holds 8 octets; `in_` holds `inlen`; `out`
    /// has room for `inlen + 8`.
    pub unsafe extern "C" fn AES_wrap_key(key: *mut AES_KEY, iv: *const c_uchar, out: *mut c_uchar, in_: *const c_uchar, inlen: c_uint) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { schedule(key) }) else { return 0 };
        let Ok(inlen) = usize::try_from(inlen) else { return 0 };
        // SAFETY: the caller's guarantee.
        as_int(unsafe { wrap(iv, out, in_, inlen, &Encrypt(s)) })
    }
}

ffi_export! {
    /// RFC 3394-unwraps `inlen` octets with a decryption schedule, checking the IV against
    /// `iv` (or the default for null). Returns `inlen - 8`, or 0 (having zeroed the output
    /// for a wrong IV).
    ///
    /// # Safety
    /// `key` is a valid `AES_KEY`; `iv` is null or holds 8 octets; `in_` holds `inlen`; `out`
    /// has room for `inlen - 8`.
    pub unsafe extern "C" fn AES_unwrap_key(key: *mut AES_KEY, iv: *const c_uchar, out: *mut c_uchar, in_: *const c_uchar, inlen: c_uint) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { schedule(key) }) else { return 0 };
        let Ok(inlen) = usize::try_from(inlen) else { return 0 };
        // SAFETY: the caller's guarantee.
        as_int(unsafe { unwrap(iv, out, in_, inlen, &Decrypt(s)) })
    }
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::*;

    /// docs/DEVIATIONS.md: null keys and buffers do nothing (or return 0); the reference
    /// crashes. A key whose rounds AES doesn't have is refused; the reference reads past the
    /// schedule.
    #[test]
    fn nulls_and_bad_keys_do_nothing() {
        let user = [3u8; 16];
        // SAFETY: an all-zero `AES_KEY` is valid (integers).
        let mut key: AES_KEY = unsafe { core::mem::zeroed() };
        // SAFETY: the test's key and buffers, and nulls, for each call below.
        assert_eq!(
            // SAFETY: as above.
            unsafe { AES_set_encrypt_key(user.as_ptr(), 128, &raw mut key) },
            0
        );
        let input = [1u8; 32];
        let mut out = [0u8; 32];
        let mut iv = [0u8; 16];
        // SAFETY: as above.
        unsafe { AES_encrypt(input.as_ptr(), out.as_mut_ptr(), ptr::null()) };
        // SAFETY: as above.
        unsafe { AES_encrypt(ptr::null(), out.as_mut_ptr(), &raw const key) };
        // SAFETY: as above.
        unsafe {
            AES_cbc_encrypt(
                input.as_ptr(),
                out.as_mut_ptr(),
                32,
                &raw const key,
                ptr::null_mut(),
                1,
            )
        };
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe {
                AES_wrap_key(
                    ptr::null_mut(),
                    ptr::null(),
                    out.as_mut_ptr(),
                    input.as_ptr(),
                    16,
                )
            },
            0
        );
        assert_eq!(out, [0; 32]);
        key.rounds = 9;
        // SAFETY: as above.
        unsafe { AES_encrypt(input.as_ptr(), out.as_mut_ptr(), &raw const key) };
        // SAFETY: as above.
        unsafe {
            AES_cbc_encrypt(
                input.as_ptr(),
                out.as_mut_ptr(),
                32,
                &raw const key,
                iv.as_mut_ptr(),
                1,
            )
        };
        key.rounds = 1000;
        // SAFETY: as above.
        unsafe { AES_decrypt(input.as_ptr(), out.as_mut_ptr(), &raw const key) };
        assert_eq!((out, iv), ([0; 32], [0; 16]));
    }
}
