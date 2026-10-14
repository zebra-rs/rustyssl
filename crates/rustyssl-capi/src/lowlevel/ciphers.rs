//! The deprecated IDEA, SEED, and Camellia functions (`IDEA_set_encrypt_key(3)`,
//! `SEED_set_key(3)`, `Camellia_set_key(3)`, their block functions and modes), over
//! [`rustyssl_crypto::lowlevel::legacy::idea`], [`rustyssl_crypto::lowlevel::seed`], and
//! [`rustyssl_crypto::lowlevel::camellia`] and the block modes.
//!
//! The key structs are read and written word by word. A `CAMELLIA_KEY`'s words are laid out
//! as the reference's code for the platform leaves them: OpenSSL's x86_64 assembly swaps each
//! pair of words its C code (every other target) writes. Only the words a key setter fills
//! are written. Where OpenSSL dereferences a null key or buffer and crashes, these do nothing;
//! a negative length does nothing where OpenSSL's IDEA CBC writes a block and its CFB and OFB
//! loop without end; and a Camellia key with grand rounds past 1 to 4 is refused where OpenSSL
//! reads past the key or loops (docs/DEVIATIONS.md).

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong};

use rustyssl_abi::{
    CAMELLIA_ENCRYPT, CAMELLIA_KEY, ERR_LIB_CRYPTO, IDEA_KEY_SCHEDULE, SEED_KEY_SCHEDULE,
};
use rustyssl_crypto::lowlevel::camellia::{self, CamelliaKey, filled_words};
use rustyssl_crypto::lowlevel::legacy::idea::{self, DECRYPT_WORDS, IdeaKey};
use rustyssl_crypto::lowlevel::modes::{self, BLOCK};
use rustyssl_crypto::lowlevel::seed::{self, SeedKey};

use super::legacy::{by_octets, cbc as cbc64, long_words, one_block as one_block64};
use super::modes::{cbc_decrypt, cbc_encrypt, ctr, stream, with_iv};
use super::{read_array, write_array};
use crate::ffi::ffi_export;

// IDEA

/// The caller's IDEA schedule.
///
/// # Safety
/// `ks` is null or a valid `IDEA_KEY_SCHEDULE`.
unsafe fn idea_key(ks: *const IDEA_KEY_SCHEDULE) -> Option<IdeaKey> {
    // SAFETY: the caller's guarantee.
    let k = unsafe { ks.as_ref() }?;
    let mut words = [0u32; idea::WORDS];
    for (d, s) in words.iter_mut().zip(k.data.as_flattened()) {
        *d = *s;
    }
    Some(IdeaKey(words))
}

/// Writes the first `n` words of `k` into the caller's schedule.
fn idea_store(ks: &mut IDEA_KEY_SCHEDULE, k: &IdeaKey, n: usize) {
    for (d, s) in ks.data.as_flattened_mut().iter_mut().zip(&k.0).take(n) {
        *d = *s;
    }
}

ffi_export! {
    /// The IDEA implementation's options: "idea(int)", as OpenSSL's.
    ///
    /// # Safety
    /// Always safe to call.
    pub unsafe extern "C" fn IDEA_options() -> *const c_char
    where failure = c"idea(int)".as_ptr(), library = ERR_LIB_CRYPTO
    {
        c"idea(int)".as_ptr()
    }
}

ffi_export! {
    /// Sets `ks` to the encryption schedule of the 16 octets at `key`.
    ///
    /// # Safety
    /// `key` holds 16 octets; `ks` is valid for writes.
    pub unsafe extern "C" fn IDEA_set_encrypt_key(key: *const c_uchar, ks: *mut IDEA_KEY_SCHEDULE)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(octets) = (unsafe { read_array::<16>(key) }) else { return };
        let k = idea::set_encrypt_key(&octets);
        // SAFETY: the caller's schedule, which may be uninitialized: only its integer words
        // are written.
        let Some(ks) = (unsafe { ks.as_mut() }) else { return };
        idea_store(ks, &k, idea::WORDS);
    }
}

ffi_export! {
    /// Sets `dk` to the decryption schedule of the encryption schedule `ek` (its first 52
    /// words; they may be the same schedule, computed in place as OpenSSL does).
    ///
    /// # Safety
    /// `ek` is a valid `IDEA_KEY_SCHEDULE`; `dk` is valid for writes.
    pub unsafe extern "C" fn IDEA_set_decrypt_key(ek: *mut IDEA_KEY_SCHEDULE, dk: *mut IDEA_KEY_SCHEDULE)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(mut k) = (unsafe { idea_key(ek) }) else { return };
        let d = if core::ptr::eq(ek, dk) {
            idea::set_decrypt_key_in_place(&mut k.0);
            k
        } else {
            idea::set_decrypt_key(&k.0)
        };
        // SAFETY: the caller's schedule, which may be uninitialized: only its integer words
        // are written.
        let Some(dk) = (unsafe { dk.as_mut() }) else { return };
        idea_store(dk, &d, DECRYPT_WORDS);
    }
}

ffi_export! {
    /// Encrypts (or, with a decryption schedule, decrypts) two words: the low 32 bits of each
    /// `unsigned long`, written back without high bits.
    ///
    /// # Safety
    /// `in_` holds two `unsigned long`s; `ks` is a valid `IDEA_KEY_SCHEDULE`.
    pub unsafe extern "C" fn IDEA_encrypt(in_: *mut c_ulong, ks: *mut IDEA_KEY_SCHEDULE)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { idea_key(ks) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { long_words(in_, |d| *d = k.encrypt_words(*d)) };
    }
}

ffi_export! {
    /// One block through the schedule.
    ///
    /// # Safety
    /// `in_` and `out` hold 8 octets; `ks` is a valid `IDEA_KEY_SCHEDULE`.
    pub unsafe extern "C" fn IDEA_ecb_encrypt(in_: *const c_uchar, out: *mut c_uchar, ks: *mut IDEA_KEY_SCHEDULE)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { idea_key(ks) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { one_block64(in_, out, &k, true) };
    }
}

ffi_export! {
    /// CBC over `length` octets with the schedule (an encryption one for nonzero `enc`, a
    /// decryption one otherwise), updating `iv`: a partial last block is padded and written
    /// whole on encryption, read whole on decryption.
    ///
    /// # Safety
    /// `in_` and `out` hold `length` octets, rounded up to whole blocks for the input on
    /// decryption and the output on encryption; `iv` holds 8; `ks` is a valid
    /// `IDEA_KEY_SCHEDULE`.
    pub unsafe extern "C" fn IDEA_cbc_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: c_long, ks: *mut IDEA_KEY_SCHEDULE, iv: *mut c_uchar, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { idea_key(ks) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { cbc64(in_, out, length, &k, iv, enc != 0) };
    }
}

/// Reads the caller's position: `None` for null, and for a negative one also sets it to -1
/// (OpenSSL's IDEA refuses it so).
///
/// # Safety
/// `num` is null or valid for reads and writes.
unsafe fn idea_num(num: *mut c_int) -> Option<()> {
    // SAFETY: the caller's guarantee.
    let n = unsafe { num.as_ref() }.copied()?;
    if n < 0 {
        // SAFETY: the caller's position.
        unsafe { num.write(-1) };
        return None;
    }
    Some(())
}

ffi_export! {
    /// CFB-64 over `length` octets with an encryption schedule (both ways), `*num` the
    /// position in `iv`; a negative position becomes -1 and nothing else happens.
    ///
    /// # Safety
    /// `in_` holds and `out` has room for `length` octets; `iv` holds 8; `num` is valid for
    /// reads and writes; `ks` is a valid `IDEA_KEY_SCHEDULE`.
    pub unsafe extern "C" fn IDEA_cfb64_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: c_long, ks: *mut IDEA_KEY_SCHEDULE, iv: *mut c_uchar, num: *mut c_int, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        if unsafe { idea_num(num) }.is_none() { return }
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { idea_key(ks) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { by_octets(in_, out, length, iv, num, |i, o, v, n| rustyssl_crypto::lowlevel::legacy::cfb64(i, o, &k, v, n, enc != 0)) };
    }
}

ffi_export! {
    /// OFB-64 over `length` octets with an encryption schedule, `*num` the position in the
    /// keystream block; a negative position becomes -1 and nothing else happens.
    ///
    /// # Safety
    /// As for `IDEA_cfb64_encrypt`.
    pub unsafe extern "C" fn IDEA_ofb64_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: c_long, ks: *mut IDEA_KEY_SCHEDULE, iv: *mut c_uchar, num: *mut c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        if unsafe { idea_num(num) }.is_none() { return }
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { idea_key(ks) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { by_octets(in_, out, length, iv, num, |i, o, v, n| rustyssl_crypto::lowlevel::legacy::ofb64(i, o, &k, v, n)) };
    }
}

// SEED

/// The caller's SEED schedule.
///
/// # Safety
/// `ks` is null or a valid `SEED_KEY_SCHEDULE`.
unsafe fn seed_key(ks: *const SEED_KEY_SCHEDULE) -> Option<SeedKey> {
    // SAFETY: the caller's guarantee.
    let k = unsafe { ks.as_ref() }?;
    Some(SeedKey(k.data))
}

/// One block from `input` to `out` through `f`; nothing for a null pointer.
///
/// # Safety
/// `input` and `out` are null or hold 16 octets.
unsafe fn one_block(
    input: *const c_uchar,
    out: *mut c_uchar,
    f: impl FnOnce(&[u8; BLOCK]) -> [u8; BLOCK],
) {
    // SAFETY: the caller's guarantee.
    let Some(x) = (unsafe { read_array::<BLOCK>(input) }) else {
        return;
    };
    if out.is_null() {
        return;
    }
    let y = f(&x);
    // SAFETY: the caller's 16 octets.
    unsafe { write_array(out, &y) };
}

ffi_export! {
    /// Sets `ks` to the round keys of the 16 octets at `rawkey`.
    ///
    /// # Safety
    /// `rawkey` holds 16 octets; `ks` is valid for writes.
    pub unsafe extern "C" fn SEED_set_key(rawkey: *const c_uchar, ks: *mut SEED_KEY_SCHEDULE)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(octets) = (unsafe { read_array::<16>(rawkey) }) else { return };
        let k = seed::set_key(&octets);
        // SAFETY: the caller's schedule, which may be uninitialized: only its integer words
        // are written.
        let Some(ks) = (unsafe { ks.as_mut() }) else { return };
        ks.data = k.0;
    }
}

ffi_export! {
    /// Encrypts the block at `s` into `d`.
    ///
    /// # Safety
    /// `s` and `d` hold 16 octets (they may be the same); `ks` is a valid `SEED_KEY_SCHEDULE`.
    pub unsafe extern "C" fn SEED_encrypt(s: *const c_uchar, d: *mut c_uchar, ks: *const SEED_KEY_SCHEDULE)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { seed_key(ks) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { one_block(s, d, |b| k.encrypt(b)) };
    }
}

ffi_export! {
    /// Decrypts the block at `s` into `d`.
    ///
    /// # Safety
    /// As for `SEED_encrypt`.
    pub unsafe extern "C" fn SEED_decrypt(s: *const c_uchar, d: *mut c_uchar, ks: *const SEED_KEY_SCHEDULE)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { seed_key(ks) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { one_block(s, d, |b| k.decrypt(b)) };
    }
}

ffi_export! {
    /// `SEED_encrypt` for nonzero `enc`, `SEED_decrypt` otherwise.
    ///
    /// # Safety
    /// As for `SEED_encrypt`.
    pub unsafe extern "C" fn SEED_ecb_encrypt(in_: *const c_uchar, out: *mut c_uchar, ks: *const SEED_KEY_SCHEDULE, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { seed_key(ks) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { one_block(in_, out, |b| if enc != 0 { k.encrypt(b) } else { k.decrypt(b) }) };
    }
}

ffi_export! {
    /// CBC over `len` octets, chaining from and updating `ivec`: a partial last block is padded
    /// and written whole on encryption, read whole on decryption.
    ///
    /// # Safety
    /// `in_` and `out` hold `len` octets, rounded up to whole blocks for the input on
    /// decryption and the output on encryption; `ivec` holds 16; `ks` is a valid
    /// `SEED_KEY_SCHEDULE`.
    pub unsafe extern "C" fn SEED_cbc_encrypt(in_: *const c_uchar, out: *mut c_uchar, len: usize, ks: *const SEED_KEY_SCHEDULE, ivec: *mut c_uchar, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        if len == 0 {
            return;
        }
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { seed_key(ks) }) else { return };
        if enc != 0 {
            // SAFETY: the caller's guarantee.
            unsafe { cbc_encrypt(in_, out, len, ivec, &seed::Encrypt(&k)) }
        } else {
            // SAFETY: the caller's guarantee.
            unsafe { cbc_decrypt(in_, out, len, ivec, &seed::Decrypt(&k)) }
        }
    }
}

ffi_export! {
    /// CFB-128 over `len` octets (both ways), `*num` the position in `ivec`.
    ///
    /// # Safety
    /// `in_` holds and `out` has room for `len` octets; `ivec` holds 16; `num` is valid for
    /// reads and writes; `ks` is a valid `SEED_KEY_SCHEDULE`.
    pub unsafe extern "C" fn SEED_cfb128_encrypt(in_: *const c_uchar, out: *mut c_uchar, len: usize, ks: *const SEED_KEY_SCHEDULE, ivec: *mut c_uchar, num: *mut c_int, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { seed_key(ks) }) else { return };
        let b = seed::Encrypt(&k);
        // SAFETY: the caller's guarantee.
        unsafe { stream(in_, out, len, ivec, num, |i, o, iv, n| modes::cfb_encrypt(i, o, iv, n, enc != 0, &b)) }
    }
}

ffi_export! {
    /// OFB over `len` octets, `*num` the position in `ivec`.
    ///
    /// # Safety
    /// As for `SEED_cfb128_encrypt`.
    pub unsafe extern "C" fn SEED_ofb128_encrypt(in_: *const c_uchar, out: *mut c_uchar, len: usize, ks: *const SEED_KEY_SCHEDULE, ivec: *mut c_uchar, num: *mut c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { seed_key(ks) }) else { return };
        let b = seed::Encrypt(&k);
        // SAFETY: the caller's guarantee.
        unsafe { stream(in_, out, len, ivec, num, |i, o, iv, n| modes::ofb_encrypt(i, o, iv, n, &b)) }
    }
}

// Camellia

/// The index in a `CAMELLIA_KEY`'s words of OpenSSL's C word `i`: the same, but on x86_64
/// (OpenSSL's assembly) each pair swapped.
#[cfg(target_arch = "x86_64")]
fn slot(i: usize) -> usize {
    i ^ 1
}

/// The index in a `CAMELLIA_KEY`'s words of OpenSSL's C word `i`: the same, but on x86_64
/// (OpenSSL's assembly) each pair swapped.
#[cfg(not(target_arch = "x86_64"))]
fn slot(i: usize) -> usize {
    i
}

/// The caller's Camellia key, or `None` for null or grand rounds past 1 to 4 (with which
/// OpenSSL reads past the key; with 1 or 2, which no key setter leaves, it runs fewer rounds).
///
/// # Safety
/// `key` is null or a valid `CAMELLIA_KEY`.
unsafe fn cmll_key(key: *const CAMELLIA_KEY) -> Option<CamelliaKey> {
    // SAFETY: the caller's guarantee.
    let k = unsafe { key.as_ref() }?;
    let grand_rounds = usize::try_from(k.grand_rounds)
        .ok()
        .filter(|g| matches!(g, 1..=4))?;
    // SAFETY: the union's words, integers that any bits are valid for (its other member, a
    // `double`, is only there for alignment).
    let rd = unsafe { k.u.rd_key };
    let mut words = [0u32; camellia::WORDS];
    for (i, w) in words.iter_mut().enumerate() {
        *w = rd.get(slot(i)).copied().unwrap_or(0);
    }
    Some(CamelliaKey {
        words,
        grand_rounds,
    })
}

ffi_export! {
    /// Sets `key` to the key table of the `bits` (128, 192, or 256) bits at `user_key`.
    /// Returns 0, -1 for a null pointer, or -2 for another size.
    ///
    /// # Safety
    /// `user_key` is null or holds `bits / 8` octets; `key` is null or valid for writes.
    pub unsafe extern "C" fn Camellia_set_key(user_key: *const c_uchar, bits: c_int, key: *mut CAMELLIA_KEY) -> c_int
    where failure = -1, library = ERR_LIB_CRYPTO
    {
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
        let Some(k) = camellia::set_key(octets) else { return -2 };
        // SAFETY: the caller's key, non-null, which may be uninitialized: only its integer
        // words are written, through a raw pointer to them.
        let rd = unsafe { &raw mut (*key).u.rd_key };
        // SAFETY: as above.
        let Some(rd) = (unsafe { rd.as_mut() }) else { return -1 };
        for (i, w) in k.words.iter().enumerate().take(filled_words(k.grand_rounds)) {
            if let Some(d) = rd.get_mut(slot(i)) {
                *d = *w;
            }
        }
        // SAFETY: as above.
        unsafe { (*key).grand_rounds = c_int::try_from(k.grand_rounds).unwrap_or(0) };
        0
    }
}

ffi_export! {
    /// Encrypts the block at `in_` into `out`.
    ///
    /// # Safety
    /// `in_` and `out` hold 16 octets (they may be the same); `key` is a valid `CAMELLIA_KEY`.
    pub unsafe extern "C" fn Camellia_encrypt(in_: *const c_uchar, out: *mut c_uchar, key: *const CAMELLIA_KEY)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { cmll_key(key) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { one_block(in_, out, |b| k.encrypt(b)) };
    }
}

ffi_export! {
    /// Decrypts the block at `in_` into `out`.
    ///
    /// # Safety
    /// As for `Camellia_encrypt`.
    pub unsafe extern "C" fn Camellia_decrypt(in_: *const c_uchar, out: *mut c_uchar, key: *const CAMELLIA_KEY)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { cmll_key(key) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { one_block(in_, out, |b| k.decrypt(b)) };
    }
}

ffi_export! {
    /// `Camellia_encrypt` for `CAMELLIA_ENCRYPT`, `Camellia_decrypt` for any other `enc`.
    ///
    /// # Safety
    /// As for `Camellia_encrypt`.
    pub unsafe extern "C" fn Camellia_ecb_encrypt(in_: *const c_uchar, out: *mut c_uchar, key: *const CAMELLIA_KEY, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { cmll_key(key) }) else { return };
        // SAFETY: the caller's guarantee.
        unsafe { one_block(in_, out, |b| if enc == CAMELLIA_ENCRYPT { k.encrypt(b) } else { k.decrypt(b) }) };
    }
}

ffi_export! {
    /// CBC over `length` octets, chaining from and updating `ivec`: a partial last block is
    /// padded and written whole on encryption, read whole on decryption.
    ///
    /// # Safety
    /// `in_` and `out` hold `length` octets, rounded up to whole blocks for the input on
    /// decryption and the output on encryption; `ivec` holds 16; `key` is a valid
    /// `CAMELLIA_KEY`.
    pub unsafe extern "C" fn Camellia_cbc_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: usize, key: *const CAMELLIA_KEY, ivec: *mut c_uchar, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        if length == 0 {
            return;
        }
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { cmll_key(key) }) else { return };
        if enc != 0 {
            // SAFETY: the caller's guarantee.
            unsafe { cbc_encrypt(in_, out, length, ivec, &camellia::Encrypt(&k)) }
        } else {
            // SAFETY: the caller's guarantee.
            unsafe { cbc_decrypt(in_, out, length, ivec, &camellia::Decrypt(&k)) }
        }
    }
}

ffi_export! {
    /// CFB-128 over `length` octets (both ways), `*num` the position in `ivec`.
    ///
    /// # Safety
    /// `in_` holds and `out` has room for `length` octets; `ivec` holds 16; `num` is valid
    /// for reads and writes; `key` is a valid `CAMELLIA_KEY`.
    pub unsafe extern "C" fn Camellia_cfb128_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: usize, key: *const CAMELLIA_KEY, ivec: *mut c_uchar, num: *mut c_int, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { cmll_key(key) }) else { return };
        let b = camellia::Encrypt(&k);
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
    /// `key` is a valid `CAMELLIA_KEY`.
    pub unsafe extern "C" fn Camellia_cfb1_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: usize, key: *const CAMELLIA_KEY, ivec: *mut c_uchar, num: *mut c_int, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let _ = num;
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { cmll_key(key) }) else { return };
        let b = camellia::Encrypt(&k);
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
    /// `CAMELLIA_KEY`.
    pub unsafe extern "C" fn Camellia_cfb8_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: usize, key: *const CAMELLIA_KEY, ivec: *mut c_uchar, num: *mut c_int, enc: c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        let _ = num;
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { cmll_key(key) }) else { return };
        let b = camellia::Encrypt(&k);
        // SAFETY: the caller's guarantee.
        unsafe { with_iv(in_, length, out, length, ivec, |i, o, iv| modes::cfb8_encrypt(i, o, iv, enc != 0, &b)) };
    }
}

ffi_export! {
    /// OFB over `length` octets, `*num` the position in `ivec`.
    ///
    /// # Safety
    /// As for `Camellia_cfb128_encrypt`.
    pub unsafe extern "C" fn Camellia_ofb128_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: usize, key: *const CAMELLIA_KEY, ivec: *mut c_uchar, num: *mut c_int)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { cmll_key(key) }) else { return };
        let b = camellia::Encrypt(&k);
        // SAFETY: the caller's guarantee.
        unsafe { stream(in_, out, length, ivec, num, |i, o, iv, n| modes::ofb_encrypt(i, o, iv, n, &b)) }
    }
}

ffi_export! {
    /// CTR over `length` octets: `ecount_buf` holds the keystream block and `*num` the position
    /// in it, between calls; `ivec` counts up whole.
    ///
    /// # Safety
    /// `in_` holds and `out` has room for `length` octets; `ivec` and `ecount_buf` hold 16;
    /// `num` is valid for reads and writes; `key` is a valid `CAMELLIA_KEY`.
    pub unsafe extern "C" fn Camellia_ctr128_encrypt(in_: *const c_uchar, out: *mut c_uchar, length: usize, key: *const CAMELLIA_KEY, ivec: *mut c_uchar, ecount_buf: *mut c_uchar, num: *mut c_uint)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { cmll_key(key) }) else { return };
        let b = camellia::Encrypt(&k);
        // SAFETY: the caller's guarantee.
        unsafe { ctr(in_, out, length, ivec, ecount_buf, num, |i, o, iv, e, n| modes::ctr_encrypt(i, o, iv, e, n, &b)) }
    }
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::*;

    /// A zeroed key struct.
    fn zeroed<T>() -> T {
        // SAFETY: the key structs are integers (and Camellia's a union of them with a
        // `double`), for which zero is valid.
        unsafe { core::mem::zeroed() }
    }

    /// docs/DEVIATIONS.md: null keys and buffers, and negative lengths, do nothing; the
    /// reference crashes, writes a block, or loops without end. A negative IDEA position
    /// becomes -1, as there.
    #[test]
    fn nulls_and_negative_lengths_do_nothing() {
        let mut ks: IDEA_KEY_SCHEDULE = zeroed();
        let input = [7u8; 16];
        let mut out = [0xeeu8; 16];
        let mut iv = [3u8; 8];
        let mut num: c_int = 2;
        // SAFETY: nulls and negative lengths are the case under test, with buffers of the
        // right sizes, for each call below.
        unsafe { IDEA_set_encrypt_key(ptr::null(), &raw mut ks) };
        // SAFETY: as above.
        unsafe { IDEA_set_decrypt_key(ptr::null_mut(), &raw mut ks) };
        // SAFETY: as above.
        unsafe { IDEA_encrypt(ptr::null_mut(), &raw mut ks) };
        // SAFETY: as above.
        unsafe { SEED_encrypt(input.as_ptr(), out.as_mut_ptr(), ptr::null()) };
        // SAFETY: as above.
        unsafe { Camellia_encrypt(input.as_ptr(), out.as_mut_ptr(), ptr::null()) };
        // SAFETY: as above.
        let r = unsafe { Camellia_set_key(ptr::null(), 128, ptr::null_mut()) };
        assert_eq!(r, -1);
        // SAFETY: as above.
        unsafe {
            IDEA_cbc_encrypt(
                input.as_ptr(),
                out.as_mut_ptr(),
                -1,
                &raw mut ks,
                iv.as_mut_ptr(),
                1,
            )
        };
        // SAFETY: as above.
        unsafe {
            IDEA_cfb64_encrypt(
                input.as_ptr(),
                out.as_mut_ptr(),
                -3,
                &raw mut ks,
                iv.as_mut_ptr(),
                &raw mut num,
                1,
            )
        };
        // SAFETY: as above.
        unsafe {
            IDEA_ofb64_encrypt(
                input.as_ptr(),
                out.as_mut_ptr(),
                -3,
                &raw mut ks,
                iv.as_mut_ptr(),
                &raw mut num,
            )
        };
        assert_eq!((out, iv, num), ([0xee; 16], [3; 8], 2));
        num = -4;
        // SAFETY: as above.
        unsafe {
            IDEA_ofb64_encrypt(
                input.as_ptr(),
                out.as_mut_ptr(),
                16,
                &raw mut ks,
                iv.as_mut_ptr(),
                &raw mut num,
            )
        };
        assert_eq!((out, num), ([0xee; 16], -1));
    }

    /// docs/DEVIATIONS.md: a Camellia key with grand rounds past 1 to 4 is refused and nothing
    /// is written (the reference reads past the key, or loops).
    #[test]
    fn camellia_bad_grand_rounds_do_nothing() {
        let mut key: CAMELLIA_KEY = zeroed();
        let input = [1u8; 16];
        // SAFETY: the test's key and data.
        let r = unsafe { Camellia_set_key([9u8; 16].as_ptr(), 128, &raw mut key) };
        assert_eq!(r, 0);
        assert_eq!(key.grand_rounds, 3);
        for g in [0, 5, 6, -1, c_int::MIN, c_int::MAX] {
            key.grand_rounds = g;
            let mut out = [0xeeu8; 16];
            // SAFETY: as above.
            unsafe { Camellia_encrypt(input.as_ptr(), out.as_mut_ptr(), &raw const key) };
            // SAFETY: as above.
            unsafe { Camellia_decrypt(input.as_ptr(), out.as_mut_ptr(), &raw const key) };
            assert_eq!(out, [0xee; 16]);
        }
    }
}
