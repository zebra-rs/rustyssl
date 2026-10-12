//! The big-number parameters (`OSSL_PARAM_get_BN(3)`, `OSSL_PARAM_set_BN`), parameters from
//! text (`OSSL_PARAM_allocate_from_text(3)`; `params_from_text.c`), and printing them
//! (`OSSL_PARAM_print_to_bio`).
//!
//! An integer parameter's data is the number in the machine's octet order: unsigned for
//! `OSSL_PARAM_UNSIGNED_INTEGER`, two's complement for `OSSL_PARAM_INTEGER`.

use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    BIGNUM, BIO, CRYPTO_R_INTEGER_OVERFLOW, CRYPTO_R_INVALID_NEGATIVE_VALUE,
    CRYPTO_R_ODD_NUMBER_OF_DIGITS, CRYPTO_R_TOO_SMALL_BUFFER, ERR_LIB_CRYPTO, ERR_R_BN_LIB,
    ERR_R_PASSED_INVALID_ARGUMENT, OSSL_PARAM,
};
use rustyssl_crypto::bn::{BigNum, Endian};
use rustyssl_crypto::params::{
    Error, INTEGER, OCTET_PTR, OCTET_STRING, REAL, UNSIGNED_INTEGER, UTF8_PTR, UTF8_STRING,
};

use super::{
    OSSL_PARAM_get_double, OSSL_PARAM_get_int64, OSSL_PARAM_get_uint64, raise, unmodified,
};
use crate::bio::{dump::BIO_dump, print::BIO_printf};
use crate::bn::{BN_print, new_bignum, value};
use crate::err;
use crate::ffi::ffi_export;
use crate::mem;
use crate::string::OPENSSL_hexstr2buf_ex;

/// The machine's octet order.
const NATIVE: Endian = if cfg!(target_endian = "little") {
    Endian::Little
} else {
    Endian::Big
};

ffi_export! {
    /// The integer parameter `p` as a number, into `*val` (a new number if it's NULL).
    /// Returns 1, or 0.
    ///
    /// # Safety
    /// `p` is NULL or a parameter whose data holds `data_size` octets; `val` is NULL or points
    /// to NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn OSSL_PARAM_get_BN(p: *const OSSL_PARAM, val: *mut *mut BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        const F: &str = "OSSL_PARAM_get_BN";
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { p.as_ref() }).filter(|p| !p.data.is_null() && !val.is_null()) else {
            raise(Error::NullArgument, F);
            return 0;
        };
        let signed = match p.data_type {
            UNSIGNED_INTEGER => false,
            INTEGER => true,
            _ => {
                raise(Error::BadType, F);
                err::raise(ERR_LIB_CRYPTO, ERR_R_BN_LIB, F);
                return 0;
            }
        };
        let v = c_int::try_from(p.data_size).ok().and_then(|_| {
            // SAFETY: the caller's guarantee.
            let octets = unsafe { core::slice::from_raw_parts(p.data.cast::<u8>(), p.data_size) };
            BigNum::from_bin(octets, NATIVE, signed).ok()
        });
        let Some(v) = v else {
            err::raise(ERR_LIB_CRYPTO, ERR_R_BN_LIB, F);
            return 0;
        };
        // SAFETY: the caller's guarantee.
        let existing = unsafe { *val };
        if existing.is_null() {
            let b = new_bignum(v, false);
            if b.is_null() {
                err::raise(ERR_LIB_CRYPTO, ERR_R_BN_LIB, F);
                return 0;
            }
            // SAFETY: as above.
            unsafe { *val = b };
            return 1;
        }
        // SAFETY: as above.
        if !unsafe { crate::bn::store(existing, v) } {
            err::raise(ERR_LIB_CRYPTO, ERR_R_BN_LIB, F);
            return 0;
        }
        1
    }
}

ffi_export! {
    /// Stores a number in the integer parameter `p`, padded to its `data_size` (with a NULL
    /// data, only sets `return_size` to the octets it needs). An unsigned parameter can't take
    /// a negative number. Returns 1, or 0.
    ///
    /// # Safety
    /// `p` is NULL or a parameter whose data is NULL or has room for `data_size` octets; `val`
    /// is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn OSSL_PARAM_set_BN(p: *mut OSSL_PARAM, val: *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        const F: &str = "OSSL_PARAM_set_BN";
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { p.as_mut() }) else {
            raise(Error::NullArgument, F);
            return 0;
        };
        p.return_size = 0;
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { value(val) }) else {
            raise(Error::NullArgument, F);
            return 0;
        };
        if p.data_type == UNSIGNED_INTEGER && v.is_negative() {
            raise(Error::BadType, F);
            return 0;
        }
        // An octet more for a signed number's sign, and at least one, for zero.
        let bytes = v.num_bytes().saturating_add(usize::from(p.data_type == INTEGER)).max(1);
        if p.data.is_null() {
            p.return_size = bytes;
            return 1;
        }
        if p.data_size < bytes {
            p.return_size = bytes;
            raise(Error::TooSmall, F);
            return 0;
        }
        let signed = match p.data_type {
            UNSIGNED_INTEGER => false,
            INTEGER => true,
            _ => {
                raise(Error::BadType, F);
                return 0;
            }
        };
        let Some(octets) = v.to_bin(Some(p.data_size), NATIVE, signed) else {
            err::raise(ERR_LIB_CRYPTO, CRYPTO_R_INTEGER_OVERFLOW, F);
            return 0;
        };
        // SAFETY: the caller's room for `data_size` octets.
        unsafe { ptr::copy_nonoverlapping(octets.as_ptr(), p.data.cast::<u8>(), octets.len()) };
        p.return_size = p.data_size;
        1
    }
}

/// `prepare_from_text`'s outcome: the definition, whether the key had `hex`, the data's size,
/// and the number for an integer.
struct Prepared {
    def: OSSL_PARAM,
    hex: bool,
    size: usize,
    number: Option<BigNum>,
}

/// `prepare_from_text`: finds `key`'s definition (setting `*found`) and works out the data's
/// size; `None` if the key is unknown or the value doesn't suit it.
///
/// # Safety
/// `paramdefs` is an array of parameters; `key` and `value` are strings; `found` is NULL or
/// writable.
unsafe fn prepare(
    paramdefs: *const OSSL_PARAM,
    key: &CStr,
    value: *const c_char,
    value_n: usize,
    found: *mut c_int,
) -> Option<Prepared> {
    let (hex, key) = match key.to_bytes().strip_prefix(b"hex") {
        Some(_) => (true, key.as_ptr().wrapping_add(3)),
        None => (false, key.as_ptr()),
    };
    // SAFETY: the caller's guarantee.
    let def = unsafe { super::OSSL_PARAM_locate_const(paramdefs, key) };
    if !found.is_null() {
        // SAFETY: as above.
        unsafe { *found = c_int::from(!def.is_null()) };
    }
    // SAFETY: a parameter of the array.
    let def = *unsafe { def.as_ref() }?;
    let mut prepared = Prepared {
        def,
        hex,
        size: 0,
        number: None,
    };
    match def.data_type {
        INTEGER | UNSIGNED_INTEGER => {
            let mut bn: *mut BIGNUM = ptr::null_mut();
            let r = if hex {
                // SAFETY: as above.
                unsafe { crate::bn::BN_hex2bn(&raw mut bn, value) }
            } else {
                // SAFETY: as above.
                unsafe { crate::bn::BN_asc2bn(&raw mut bn, value) }
            };
            // SAFETY: NULL or the number just made.
            let number = unsafe { crate::bn::value(bn) };
            // SAFETY: ours to free.
            unsafe { crate::bn::BN_free(bn) };
            let mut n = number.filter(|_| r != 0)?;
            if def.data_type == UNSIGNED_INTEGER && n.is_negative() {
                err::raise(
                    ERR_LIB_CRYPTO,
                    CRYPTO_R_INVALID_NEGATIVE_VALUE,
                    "prepare_from_text",
                );
                return None;
            }
            // Two's complement, part one: a negative number's magnitude less one, whose octets
            // `construct` inverts.
            if def.data_type == INTEGER && n.is_negative() && n.add_word(1).is_err() {
                return None;
            }
            let mut bits = n.num_bits();
            if def.data_type == INTEGER && bits % 8 == 0 {
                bits = bits.saturating_add(8);
            }
            prepared.size = bits.div_ceil(8);
            if def.data_size > 0 {
                if bits > def.data_size.saturating_mul(8) {
                    err::raise(
                        ERR_LIB_CRYPTO,
                        CRYPTO_R_TOO_SMALL_BUFFER,
                        "prepare_from_text",
                    );
                    return None;
                }
                prepared.size = def.data_size;
            }
            prepared.number = Some(n);
        }
        UTF8_STRING => {
            if hex {
                err::raise(
                    ERR_LIB_CRYPTO,
                    ERR_R_PASSED_INVALID_ARGUMENT,
                    "prepare_from_text",
                );
                return None;
            }
            // SAFETY: as above.
            prepared.size = unsafe { CStr::from_ptr(value) }
                .count_bytes()
                .saturating_add(1);
        }
        OCTET_STRING => {
            if hex {
                // SAFETY: as above.
                let digits = unsafe { CStr::from_ptr(value) }.count_bytes();
                if digits % 2 != 0 {
                    err::raise(
                        ERR_LIB_CRYPTO,
                        CRYPTO_R_ODD_NUMBER_OF_DIGITS,
                        "prepare_from_text",
                    );
                    return None;
                }
                prepared.size = digits / 2;
            } else {
                prepared.size = value_n;
            }
        }
        _ => {}
    }
    Some(prepared)
}

/// `construct_from_text`: writes the value into `buf` (of `prepared.size` octets) and makes
/// `*to` the definition with that data; `false` if hex octets don't parse.
///
/// # Safety
/// `buf` has room for `prepared.size` octets; `value` is a string of at least `value_n`
/// octets; `to` is writable.
unsafe fn construct(
    to: *mut OSSL_PARAM,
    prepared: &Prepared,
    value: *const c_char,
    value_n: usize,
    buf: *mut u8,
) -> bool {
    let mut size = prepared.size;
    if size > 0 {
        match prepared.def.data_type {
            INTEGER | UNSIGNED_INTEGER => {
                if let Some(n) = &prepared.number {
                    let negative = prepared.def.data_type == INTEGER && n.is_negative();
                    if let Some(octets) = n.to_bin(Some(size), NATIVE, false) {
                        for (i, &o) in octets.iter().enumerate() {
                            // SAFETY: the room for `size` octets.
                            unsafe { buf.wrapping_add(i).write(if negative { !o } else { o }) };
                        }
                    }
                }
            }
            UTF8_STRING => {
                // SAFETY: the room for the string and its NUL, which `size` counted.
                unsafe { libc::strncpy(buf.cast(), value, size) };
                size -= 1;
            }
            OCTET_STRING => {
                if prepared.hex {
                    let mut len = 0usize;
                    // SAFETY: as above.
                    if unsafe {
                        OPENSSL_hexstr2buf_ex(
                            buf,
                            size,
                            &raw mut len,
                            value,
                            c_char::try_from(b':').unwrap_or_default(),
                        )
                    } == 0
                    {
                        return false;
                    }
                } else {
                    // SAFETY: the caller's `value_n` octets.
                    unsafe { ptr::copy_nonoverlapping(value.cast::<u8>(), buf, value_n.min(size)) };
                }
            }
            _ => {}
        }
    }
    let param = OSSL_PARAM {
        data: buf.cast(),
        data_size: size,
        return_size: unmodified(),
        ..prepared.def
    };
    // SAFETY: the caller's guarantee.
    unsafe { to.write(param) };
    true
}

ffi_export! {
    /// Makes `*to` the parameter of `paramdefs` named `key` (`hex` first for a hex value)
    /// holding `value`, in data it allocates (free `to->data` with `OPENSSL_free`): an integer
    /// read as `BN_asc2bn` (or `BN_hex2bn`) does, sized to the definition or the number, a
    /// UTF-8 string, or octets (`value_n` of them, or hex). `*found` says whether the key was
    /// found. Returns 1, or 0.
    ///
    /// # Safety
    /// `to` is NULL or writable; `paramdefs` is NULL or an array of parameters; `key` and
    /// `value` are NULL or strings (`value` with at least `value_n` octets); `found` is NULL or
    /// writable.
    pub unsafe extern "C" fn OSSL_PARAM_allocate_from_text(to: *mut OSSL_PARAM, paramdefs: *const OSSL_PARAM, key: *const c_char, value: *const c_char, value_n: usize, found: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        if to.is_null() || paramdefs.is_null() || key.is_null() || value.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let key = unsafe { CStr::from_ptr(key) };
        // SAFETY: as above.
        let Some(prepared) = (unsafe { prepare(paramdefs, key, value, value_n, found) }) else { return 0 };
        let buf = mem::alloc_zeroed(prepared.size.max(1)).cast::<u8>();
        if buf.is_null() {
            return 0;
        }
        // SAFETY: `buf` has room for the size; the caller's guarantee for the rest.
        if unsafe { construct(to, &prepared, value, value_n, buf) } {
            return 1;
        }
        // SAFETY: ours to free.
        unsafe { mem::release(buf.cast()) };
        0
    }
}

/// Prints one value of `p` to `bio`: -1 on a write failure, else what the reference's last
/// print returned.
///
/// # Safety
/// `bio` is NULL or a live BIO; `p`'s data holds `data_size` octets.
unsafe fn print_value(bio: *mut BIO, p: &OSSL_PARAM) -> c_int {
    let error = c"error getting value\n".as_ptr();
    let dump = |data: *const c_void| {
        // SAFETY: the parameter's data.
        unsafe {
            BIO_dump(
                bio,
                data,
                c_int::try_from(p.data_size).unwrap_or(c_int::MAX),
            )
        }
    };
    match p.data_type {
        UNSIGNED_INTEGER | INTEGER if p.data_size > size_of::<i64>() => {
            let mut bn: *mut BIGNUM = ptr::null_mut();
            // SAFETY: the caller's parameter.
            let r = if unsafe { OSSL_PARAM_get_BN(p, &raw mut bn) } != 0 {
                // SAFETY: the number just made.
                unsafe { BN_print(bio, bn) }
            } else {
                // SAFETY: the caller's BIO.
                unsafe { BIO_printf(bio, error) }
            };
            // SAFETY: ours to free.
            unsafe { crate::bn::BN_free(bn) };
            r
        }
        UNSIGNED_INTEGER => {
            let mut u = 0u64;
            // SAFETY: the caller's parameter.
            if unsafe { OSSL_PARAM_get_uint64(p, &raw mut u) } != 0 {
                // SAFETY: as above; the format takes an `unsigned long long`.
                unsafe { BIO_printf(bio, c"%llu\n".as_ptr(), u) }
            } else {
                // SAFETY: as above.
                unsafe { BIO_printf(bio, error) }
            }
        }
        INTEGER => {
            let mut i = 0i64;
            // SAFETY: the caller's parameter.
            if unsafe { OSSL_PARAM_get_int64(p, &raw mut i) } != 0 {
                // SAFETY: as above; the format takes a `long long`.
                unsafe { BIO_printf(bio, c"%lld\n".as_ptr(), i) }
            } else {
                // SAFETY: as above.
                unsafe { BIO_printf(bio, error) }
            }
        }
        UTF8_PTR | UTF8_STRING | OCTET_PTR | OCTET_STRING => dump(p.data),
        REAL => {
            let mut d = 0f64;
            // SAFETY: the caller's parameter.
            if unsafe { OSSL_PARAM_get_double(p, &raw mut d) } != 0 {
                // SAFETY: as above; the format takes a `double`.
                unsafe { BIO_printf(bio, c"%f\n".as_ptr(), d) }
            } else {
                // SAFETY: as above.
                unsafe { BIO_printf(bio, error) }
            }
        }
        // SAFETY: as above; the format takes an `unsigned int` and a `size_t`.
        t => unsafe {
            BIO_printf(
                bio,
                c"unknown type (%u) of %zu bytes\n".as_ptr(),
                c_uint::from(t),
                p.data_size,
            )
        },
    }
}

ffi_export! {
    /// Prints each parameter's key (`key: `) and, if `print_values`, its value: integers in
    /// decimal (in hex, without a newline, beyond 8 octets), strings and octets as a hex dump,
    /// reals with `%f`. Returns 1, or 0 if a write failed.
    ///
    /// # Safety
    /// `p` is NULL or an array of parameters whose data holds their sizes; `bio` is NULL or a
    /// live BIO.
    pub unsafe extern "C" fn OSSL_PARAM_print_to_bio(p: *const OSSL_PARAM, bio: *mut BIO, print_values: c_int) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let mut ok: c_int = -1;
        let mut at = p;
        // SAFETY: the caller's array, up to its terminator.
        while let Some(param) = unsafe { at.as_ref() } {
            if param.key.is_null() {
                break;
            }
            // SAFETY: the caller's BIO; the key is a string.
            ok = unsafe { BIO_printf(bio, c"%s: ".as_ptr(), param.key) };
            if ok == -1 {
                return 0;
            }
            if print_values == 0 {
                // SAFETY: as above.
                unsafe { BIO_printf(bio, c"\n".as_ptr()) };
            } else {
                // SAFETY: the caller's parameter.
                ok = unsafe { print_value(bio, param) };
                if ok == -1 {
                    return 0;
                }
            }
            at = at.wrapping_add(1);
        }
        c_int::from(ok != -1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: an integer wider than 8 octets prints in hex (OpenSSL passes an
    /// uninitialized pointer to `OSSL_PARAM_get_BN`).
    #[test]
    fn wide_integers_print() {
        let mut wide: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let params = [
            super::super::construct(
                c"w".as_ptr(),
                UNSIGNED_INTEGER,
                wide.as_mut_ptr().cast(),
                wide.len(),
            ),
            super::super::end(),
        ];
        // SAFETY: no preconditions.
        let method = unsafe { crate::bio::mem::BIO_s_mem() };
        // SAFETY: a built-in method.
        let mem = unsafe { crate::bio::BIO_new(method) };
        // SAFETY: the parameters and BIO made here.
        let r = unsafe { OSSL_PARAM_print_to_bio(params.as_ptr(), mem, 1) };
        assert_eq!(r, 1);
        let mut out = [0u8; 64];
        // SAFETY: the BIO; room for 64 octets.
        let n = unsafe { crate::bio::BIO_read(mem, out.as_mut_ptr().cast(), 64) };
        let printed = out.get(..usize::try_from(n).unwrap_or(0)).unwrap_or(&[]);
        assert_eq!(printed, b"w: C0B0A090807060504030201");
        // SAFETY: ours to free.
        unsafe { crate::bio::BIO_free(mem) };
    }

    /// docs/DEVIATIONS.md: an integer parameter longer than `INT_MAX` octets fails (OpenSSL
    /// truncates the length to an `int`).
    #[test]
    fn oversized_integers_fail() {
        let p = super::super::construct(
            c"n".as_ptr(),
            UNSIGNED_INTEGER,
            ptr::dangling_mut(),
            usize::MAX,
        );
        let mut b: *mut BIGNUM = ptr::null_mut();
        // SAFETY: the data isn't read: the size is refused first.
        assert_eq!(unsafe { OSSL_PARAM_get_BN(&raw const p, &raw mut b) }, 0);
        assert!(b.is_null());
        crate::err::take_all();
    }

    /// docs/DEVIATIONS.md: `OSSL_PARAM_allocate_from_text` with a NULL key or value fails.
    #[test]
    fn null_keys_and_values_fail() {
        let defs = [
            super::super::construct(c"n".as_ptr(), INTEGER, ptr::null_mut(), 0),
            super::super::end(),
        ];
        let mut to = super::super::end();
        // SAFETY: the definitions made here; NULL is the case under test.
        let r = unsafe {
            OSSL_PARAM_allocate_from_text(
                &raw mut to,
                defs.as_ptr(),
                ptr::null(),
                c"1".as_ptr(),
                1,
                ptr::null_mut(),
            )
        };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let r = unsafe {
            OSSL_PARAM_allocate_from_text(
                &raw mut to,
                defs.as_ptr(),
                c"n".as_ptr(),
                ptr::null(),
                0,
                ptr::null_mut(),
            )
        };
        assert_eq!(r, 0);
    }
}
