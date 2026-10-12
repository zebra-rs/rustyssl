//! Conversions (`BN_bn2bin(3)`, `BN_bn2hex`, `BN_hex2bn`, `BN_bn2mpi`, `BN_print`,
//! `BN_to_ASN1_INTEGER`, `ASN1_bn_print`): octet strings, text, MPIs, and ASN.1 integers.

use core::ffi::{CStr, c_char, c_int, c_uchar};
use core::ptr;

use libc::FILE;
use rustyssl_abi::{
    ASN1_ENUMERATED, ASN1_INTEGER, ASN1_R_BN_LIB, ASN1_R_WRONG_INTEGER_TYPE, BIGNUM, BIO,
    BIO_NOCLOSE, ERR_LIB_ASN1, ERR_LIB_BN, ERR_R_ASN1_LIB, ERR_R_NESTED_ASN1_ERROR,
    ERR_R_PASSED_INVALID_ARGUMENT, V_ASN1_ENUMERATED, V_ASN1_INTEGER, V_ASN1_NEG,
};
use rustyssl_crypto::bn::{BigNum, Endian};

use super::{BN_FLG_STATIC_DATA, bignum, new_bignum, raise, store, value};
use crate::asn1::string;
use crate::bio::{self, print::BIO_printf};
use crate::err;
use crate::ffi::ffi_export;
use crate::objects::c_string;

/// The octets at `s`, or `None` for a negative length or NULL with a positive one.
///
/// # Safety
/// `s` is NULL or holds `len` octets.
unsafe fn octets<'a>(s: *const c_uchar, len: c_int) -> Option<&'a [u8]> {
    let len = usize::try_from(len).ok()?;
    if len == 0 {
        return Some(&[]);
    }
    if s.is_null() {
        return None;
    }
    // SAFETY: the caller's guarantee.
    Some(unsafe { core::slice::from_raw_parts(s, len) })
}

/// `bin2bn`: the number in `len` octets at `s`, in `ret` (or a new number if NULL); `ret` or
/// the new number, or NULL.
///
/// # Safety
/// `s` holds `len` octets; `ret` is NULL or a live `BIGNUM`.
unsafe fn bin2bn(
    s: *const c_uchar,
    len: c_int,
    ret: *mut BIGNUM,
    endian: Endian,
    signed: bool,
) -> *mut BIGNUM {
    // SAFETY: the caller's guarantee.
    let Some(bytes) = (unsafe { octets(s, len) }) else {
        return ptr::null_mut();
    };
    let v = match BigNum::from_bin(bytes, endian, signed) {
        Ok(v) => v,
        Err(e) => {
            raise(e);
            return ptr::null_mut();
        }
    };
    if ret.is_null() {
        return new_bignum(v, false);
    }
    // SAFETY: the caller's guarantee.
    if unsafe { store(ret, v) } {
        ret
    } else {
        ptr::null_mut()
    }
}

/// `bn2binpad`: `a` in `tolen` octets at `to` (as few as it takes for -1); the length, or -1.
///
/// # Safety
/// `a` is NULL or a live `BIGNUM`; `to` has room for the octets written.
unsafe fn bn2binpad(
    a: *const BIGNUM,
    to: *mut c_uchar,
    tolen: c_int,
    endian: Endian,
    signed: bool,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(v) = (unsafe { value(a) }) else {
        return -1;
    };
    let tolen = if tolen == -1 {
        None
    } else {
        Some(usize::try_from(tolen).unwrap_or(0))
    };
    let Some(out) = v.to_bin(tolen, endian, signed) else {
        return -1;
    };
    if out.is_empty() {
        return 0;
    }
    if to.is_null() {
        return -1;
    }
    // SAFETY: the caller's room for the octets.
    unsafe { ptr::copy_nonoverlapping(out.as_ptr(), to, out.len()) };
    c_int::try_from(out.len()).unwrap_or(-1)
}

/// The machine's octet order.
const NATIVE: Endian = if cfg!(target_endian = "little") {
    Endian::Little
} else {
    Endian::Big
};

/// Defines the octet-string readers.
macro_rules! readers {
    ($( $(#[$attr:meta])* pub unsafe extern "C" fn $name:ident = ($endian:expr, $signed:expr); )*) => {$(
        ffi_export! {
            $(#[$attr])*
            /// Returns `ret` (or a new number if it's NULL), or NULL; a negative length fails.
            ///
            /// # Safety
            /// `s` holds `len` octets; `ret` is NULL or a live `BIGNUM`.
            pub unsafe extern "C" fn $name(s: *const c_uchar, len: c_int, ret: *mut BIGNUM) -> *mut BIGNUM
            where failure = ptr::null_mut(), library = ERR_LIB_BN
            {
                // SAFETY: the caller's guarantee.
                unsafe { bin2bn(s, len, ret, $endian, $signed) }
            }
        }
    )*};
}

readers! {
    /// The non-negative number in `len` big-endian octets.
    pub unsafe extern "C" fn BN_bin2bn = (Endian::Big, false);
    /// The number in `len` big-endian octets of two's complement.
    pub unsafe extern "C" fn BN_signed_bin2bn = (Endian::Big, true);
    /// The non-negative number in `len` little-endian octets.
    pub unsafe extern "C" fn BN_lebin2bn = (Endian::Little, false);
    /// The number in `len` little-endian octets of two's complement.
    pub unsafe extern "C" fn BN_signed_lebin2bn = (Endian::Little, true);
    /// The non-negative number in `len` octets in the machine's order.
    pub unsafe extern "C" fn BN_native2bn = (NATIVE, false);
    /// The number in `len` octets of two's complement in the machine's order.
    pub unsafe extern "C" fn BN_signed_native2bn = (NATIVE, true);
}

/// Defines the padded octet-string writers.
macro_rules! writers {
    ($( $(#[$attr:meta])* pub unsafe extern "C" fn $name:ident = ($endian:expr, $signed:expr); )*) => {$(
        ffi_export! {
            $(#[$attr])*
            /// Returns `tolen`, or -1 if it doesn't fit (or `tolen` is negative).
            ///
            /// # Safety
            /// `a` is NULL or a live `BIGNUM`; `to` has room for `tolen` octets.
            pub unsafe extern "C" fn $name(a: *const BIGNUM, to: *mut c_uchar, tolen: c_int) -> c_int
            where failure = -1, library = ERR_LIB_BN
            {
                if tolen < 0 {
                    return -1;
                }
                // SAFETY: the caller's guarantee.
                unsafe { bn2binpad(a, to, tolen, $endian, $signed) }
            }
        }
    )*};
}

writers! {
    /// Writes a number's magnitude as `tolen` big-endian octets, zero-padded.
    pub unsafe extern "C" fn BN_bn2binpad = (Endian::Big, false);
    /// Writes a number as `tolen` big-endian octets of two's complement.
    pub unsafe extern "C" fn BN_signed_bn2bin = (Endian::Big, true);
    /// Writes a number's magnitude as `tolen` little-endian octets, zero-padded.
    pub unsafe extern "C" fn BN_bn2lebinpad = (Endian::Little, false);
    /// Writes a number as `tolen` little-endian octets of two's complement.
    pub unsafe extern "C" fn BN_signed_bn2lebin = (Endian::Little, true);
    /// Writes a number's magnitude as `tolen` octets in the machine's order, zero-padded.
    pub unsafe extern "C" fn BN_bn2nativepad = (NATIVE, false);
    /// Writes a number as `tolen` octets of two's complement in the machine's order.
    pub unsafe extern "C" fn BN_signed_bn2native = (NATIVE, true);
}

ffi_export! {
    /// Writes a number's magnitude as big-endian octets (`BN_num_bytes` of them); returns
    /// their count.
    ///
    /// # Safety
    /// `a` is NULL or a live `BIGNUM`; `to` has room for `BN_num_bytes(a)` octets.
    pub unsafe extern "C" fn BN_bn2bin(a: *const BIGNUM, to: *mut c_uchar) -> c_int
    where failure = -1, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { bn2binpad(a, to, -1, Endian::Big, false) }
    }
}

/// `text` as a string in C memory, or NULL.
fn c_text(text: &str) -> *mut c_char {
    c_string(text.as_bytes())
}

ffi_export! {
    /// A number as hex text (`-` and uppercase digits, whole octets), to free with
    /// `OPENSSL_free`; NULL on failure.
    ///
    /// # Safety
    /// `a` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_bn2hex(a: *const BIGNUM) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { value(a) }.map_or(ptr::null_mut(), |v| c_text(&v.to_hex()))
    }
}

ffi_export! {
    /// A number as decimal text, to free with `OPENSSL_free`; NULL on failure.
    ///
    /// # Safety
    /// `a` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_bn2dec(a: *const BIGNUM) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { value(a) }.map_or(ptr::null_mut(), |v| c_text(&v.to_dec()))
    }
}

/// The digits at the start of `a` after an optional `-`, as `BN_hex2bn` and `BN_dec2bn` count
/// them (at most `INT_MAX / 4`): the sign, the digits, and the count with the sign.
fn digits(a: &[u8], is_digit: fn(&u8) -> bool) -> Option<(bool, &[u8], c_int)> {
    let (neg, rest) = match a.split_first() {
        Some((b'-', rest)) => (true, rest),
        _ => (false, a),
    };
    let limit = usize::try_from(c_int::MAX / 4).unwrap_or(0);
    let i = rest
        .iter()
        .take(limit.saturating_add(1))
        .take_while(|c| is_digit(c))
        .count();
    if i == 0 || i > limit {
        return None;
    }
    let num = c_int::try_from(i).ok()?.checked_add(c_int::from(neg))?;
    Some((neg, rest.get(..i)?, num))
}

/// `BN_hex2bn` and `BN_dec2bn`: the number at the start of `a` into `*bn` (a new number if it's
/// NULL); the characters taken, or 0.
///
/// # Safety
/// `bn` is NULL or points to NULL or a live `BIGNUM`; `a` is NULL or a string.
unsafe fn text2bn(bn: *mut *mut BIGNUM, a: *const c_char, hex: bool) -> c_int {
    if a.is_null() {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let text = unsafe { CStr::from_ptr(a) }.to_bytes();
    let is_digit: fn(&u8) -> bool = if hex {
        u8::is_ascii_hexdigit
    } else {
        u8::is_ascii_digit
    };
    let Some((neg, digits, num)) = digits(text, is_digit) else {
        return 0;
    };
    if bn.is_null() {
        return num;
    }
    // SAFETY: the caller's guarantee.
    let existing = unsafe { *bn };
    if !existing.is_null() {
        // SAFETY: as above.
        let Some(b) = (unsafe { bignum(existing) }) else {
            return 0;
        };
        if hex && b.flags() & BN_FLG_STATIC_DATA != 0 {
            err::raise(ERR_LIB_BN, ERR_R_PASSED_INVALID_ARGUMENT, "BN_hex2bn");
            return 0;
        }
        // OpenSSL zeroes the number first, so a failure leaves zero.
        if b.update(|v| *v = BigNum::zero()).is_none() {
            return 0;
        }
    }
    let parsed = if hex {
        BigNum::from_hex_digits(digits)
    } else {
        BigNum::from_dec_digits(digits)
    };
    let mut v = match parsed {
        Ok(v) => v,
        Err(e) => {
            raise(e);
            return 0;
        }
    };
    v.set_negative(neg);
    if existing.is_null() {
        // SAFETY: the caller's pointer.
        unsafe { *bn = new_bignum(v, false) };
        return num;
    }
    // SAFETY: as above.
    if unsafe { store(existing, v) } {
        num
    } else {
        0
    }
}

ffi_export! {
    /// Reads the hex number (with an optional `-`) at the start of `a` into `*bn`, making one
    /// if `*bn` is NULL. Returns the characters taken, or 0; with `bn` NULL, only counts them.
    ///
    /// # Safety
    /// `bn` is NULL or points to NULL or a live `BIGNUM`; `a` is NULL or a string.
    pub unsafe extern "C" fn BN_hex2bn(bn: *mut *mut BIGNUM, a: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { text2bn(bn, a, true) }
    }
}

ffi_export! {
    /// Reads the decimal number (with an optional `-`) at the start of `a` into `*bn`, as
    /// `BN_hex2bn` does.
    ///
    /// # Safety
    /// `bn` is NULL or points to NULL or a live `BIGNUM`; `a` is NULL or a string.
    pub unsafe extern "C" fn BN_dec2bn(bn: *mut *mut BIGNUM, a: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        unsafe { text2bn(bn, a, false) }
    }
}

ffi_export! {
    /// Reads a decimal number, or a hex one after `0x` or `0X`, each after an optional `-`,
    /// into `*bn` as `BN_hex2bn` does. Returns 1, or 0.
    ///
    /// # Safety
    /// `bn` is NULL or points to NULL or a live `BIGNUM`; `a` is NULL or a string.
    pub unsafe extern "C" fn BN_asc2bn(bn: *mut *mut BIGNUM, a: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        if a.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let text = unsafe { CStr::from_ptr(a) }.to_bytes();
        let neg = text.first() == Some(&b'-');
        let skip = usize::from(neg);
        let rest = text.get(skip..).unwrap_or(&[]);
        let hex = rest.first() == Some(&b'0') && matches!(rest.get(1), Some(b'x' | b'X'));
        let start = a.wrapping_add(skip).wrapping_add(if hex { 2 } else { 0 });
        // SAFETY: as above; `start` is within the string.
        if unsafe { text2bn(bn, start, hex) } == 0 {
            return 0;
        }
        if neg && !bn.is_null() {
            // SAFETY: as above.
            let made = unsafe { *bn };
            // SAFETY: `text2bn` left a number there.
            if let Some(b) = unsafe { bignum(made) } {
                let _ = b.update(|v| v.set_negative(true));
            }
        }
        1
    }
}

ffi_export! {
    /// Writes a number as an MPI (a four-octet length, then the magnitude with a sign bit) to
    /// `d`, unless it's NULL; returns the MPI's length.
    ///
    /// # Safety
    /// `a` is NULL or a live `BIGNUM`; `d` is NULL or has room for the MPI.
    pub unsafe extern "C" fn BN_bn2mpi(a: *const BIGNUM, d: *mut c_uchar) -> c_int
    where failure = -1, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { value(a) }) else { return -1 };
        let mpi = v.to_mpi();
        if !d.is_null() {
            // SAFETY: the caller's room for the MPI.
            unsafe { ptr::copy_nonoverlapping(mpi.as_ptr(), d, mpi.len()) };
        }
        c_int::try_from(mpi.len()).unwrap_or(-1)
    }
}

ffi_export! {
    /// The number in an MPI of exactly `n` octets, in `ain` (or a new number if NULL); NULL
    /// on failure.
    ///
    /// # Safety
    /// `d` holds `n` octets; `ain` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_mpi2bn(d: *const c_uchar, n: c_int, ain: *mut BIGNUM) -> *mut BIGNUM
    where failure = ptr::null_mut(), library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let bytes = unsafe { octets(d, n) }.unwrap_or(&[]);
        let v = match BigNum::from_mpi(bytes) {
            Ok(v) => v,
            Err(e) => {
                raise(e);
                return ptr::null_mut();
            }
        };
        if ain.is_null() {
            return new_bignum(v, false);
        }
        // SAFETY: the caller's guarantee.
        if unsafe { store(ain, v) } { ain } else { ptr::null_mut() }
    }
}

ffi_export! {
    /// Prints a number in uppercase hex without leading zeros (and `-`), one character at a
    /// time. Returns 1, or 0.
    ///
    /// # Safety
    /// `bp` is NULL or a live BIO; `a` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_print(bp: *mut BIO, a: *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { value(a) }) else { return 0 };
        for c in v.to_hex_digits().bytes() {
            // SAFETY: the caller's BIO; one octet.
            if unsafe { bio::BIO_write(bp, (&raw const c).cast(), 1) } != 1 {
                return 0;
            }
        }
        1
    }
}

ffi_export! {
    /// `BN_print` to a `FILE`.
    ///
    /// # Safety
    /// `fp` is NULL or an open `FILE`; `a` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn BN_print_fp(fp: *mut FILE, a: *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_BN
    {
        // SAFETY: the caller's guarantee.
        let b = unsafe { bio::file::BIO_new_fp(fp, BIO_NOCLOSE) };
        if b.is_null() {
            return 0;
        }
        // SAFETY: the BIO just made; the caller's number.
        let ret = unsafe { BN_print(b, a) };
        // SAFETY: ours to free.
        unsafe { bio::BIO_free(b) };
        ret
    }
}

/// `bn_to_asn1_string`: `bn` in `ai` (or a new string) of type `atype`.
///
/// # Safety
/// `bn` is NULL or a live `BIGNUM`; `ai` is NULL or a live string.
unsafe fn bn_to_asn1_string(
    bn: *const BIGNUM,
    ai: *mut ASN1_INTEGER,
    atype: c_int,
) -> *mut ASN1_INTEGER {
    const F: &str = "bn_to_asn1_string";
    // SAFETY: the caller's guarantee.
    let Some(v) = (unsafe { value(bn) }) else {
        return ptr::null_mut();
    };
    let ret = if ai.is_null() {
        string::type_new(atype)
    } else {
        ai
    };
    if ret.is_null() {
        err::raise(ERR_LIB_ASN1, ERR_R_NESTED_ASN1_ERROR, F);
        return ptr::null_mut();
    }
    let mut kind = atype;
    if v.is_negative() {
        kind |= V_ASN1_NEG;
    }
    // SAFETY: the string is live.
    unsafe { (*ret).type_ = kind };
    let octets = v.to_bin(None, Endian::Big, false).unwrap_or_default();
    let data: &[u8] = if octets.is_empty() { &[0] } else { &octets };
    let len = c_int::try_from(data.len()).unwrap_or(c_int::MAX);
    // SAFETY: as above; `data` holds `len` octets.
    if unsafe { string::set(ret, data.as_ptr().cast(), len) } == 0 {
        err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, F);
        if ret != ai {
            // SAFETY: ours to free.
            unsafe { string::ASN1_STRING_free(ret) };
        }
        return ptr::null_mut();
    }
    ret
}

/// `asn1_string_to_bn`: the integer `ai`, if its type is `itype`, in `bn` (or a new number).
///
/// # Safety
/// `ai` is NULL or a live string; `bn` is NULL or a live `BIGNUM`.
unsafe fn asn1_string_to_bn(ai: *const ASN1_INTEGER, bn: *mut BIGNUM, itype: c_int) -> *mut BIGNUM {
    const F: &str = "asn1_string_to_bn";
    if ai.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the caller's guarantee.
    let a = unsafe { &*ai };
    if a.type_ & !V_ASN1_NEG != itype {
        err::raise(ERR_LIB_ASN1, ASN1_R_WRONG_INTEGER_TYPE, F);
        return ptr::null_mut();
    }
    // SAFETY: the string's data holds its length.
    let ret = unsafe { bin2bn(a.data, a.length, bn, Endian::Big, false) };
    if ret.is_null() {
        err::raise(ERR_LIB_ASN1, ASN1_R_BN_LIB, F);
        return ptr::null_mut();
    }
    if a.type_ & V_ASN1_NEG != 0 {
        // SAFETY: the number just stored.
        if let Some(b) = unsafe { bignum(ret) } {
            let _ = b.update(|v| v.set_negative(true));
        }
    }
    ret
}

ffi_export! {
    /// A number as an INTEGER, in `ai` (its type reset) or a new one; NULL on failure.
    ///
    /// # Safety
    /// `bn` is NULL or a live `BIGNUM`; `ai` is NULL or a live `ASN1_INTEGER`.
    pub unsafe extern "C" fn BN_to_ASN1_INTEGER(bn: *const BIGNUM, ai: *mut ASN1_INTEGER) -> *mut ASN1_INTEGER
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { bn_to_asn1_string(bn, ai, V_ASN1_INTEGER) }
    }
}

ffi_export! {
    /// A number as an ENUMERATED, as `BN_to_ASN1_INTEGER` does.
    ///
    /// # Safety
    /// `bn` is NULL or a live `BIGNUM`; `ai` is NULL or a live `ASN1_ENUMERATED`.
    pub unsafe extern "C" fn BN_to_ASN1_ENUMERATED(bn: *const BIGNUM, ai: *mut ASN1_ENUMERATED) -> *mut ASN1_ENUMERATED
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { bn_to_asn1_string(bn, ai, V_ASN1_ENUMERATED) }
    }
}

ffi_export! {
    /// An INTEGER as a number, in `bn` or a new one; NULL for another type or on failure.
    ///
    /// # Safety
    /// `ai` is NULL or a live `ASN1_INTEGER`; `bn` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn ASN1_INTEGER_to_BN(ai: *const ASN1_INTEGER, bn: *mut BIGNUM) -> *mut BIGNUM
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { asn1_string_to_bn(ai, bn, V_ASN1_INTEGER) }
    }
}

ffi_export! {
    /// An ENUMERATED as a number, as `ASN1_INTEGER_to_BN` does.
    ///
    /// # Safety
    /// `ai` is NULL or a live `ASN1_ENUMERATED`; `bn` is NULL or a live `BIGNUM`.
    pub unsafe extern "C" fn ASN1_ENUMERATED_to_BN(ai: *const ASN1_ENUMERATED, bn: *mut BIGNUM) -> *mut BIGNUM
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { asn1_string_to_bn(ai, bn, V_ASN1_ENUMERATED) }
    }
}

/// `ASN1_PRINT_MAX_INDENT`.
const PRINT_MAX_INDENT: c_int = 128;

ffi_export! {
    /// Prints a number labelled `number`, indented by `indent`: `0`, a word's value in decimal
    /// and hex, or the label (and `(Negative)`) and the magnitude's octets, colon-separated and
    /// indented four more (with a zero octet first if the top bit is set). NULL prints nothing.
    /// Returns 1, or 0.
    ///
    /// # Safety
    /// `bp` is NULL or a live BIO; `number` is NULL or a string; `num` is NULL or a live
    /// `BIGNUM`.
    pub unsafe extern "C" fn ASN1_bn_print(bp: *mut BIO, number: *const c_char, num: *const BIGNUM, ign: *mut c_uchar, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        let _ = ign;
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { value(num) }) else { return 1 };
        let neg = if v.is_negative() { c"-" } else { c"" };
        // SAFETY: the caller's BIO.
        if unsafe { bio::BIO_indent(bp, indent, PRINT_MAX_INDENT) } == 0 {
            return 0;
        }
        if v.is_zero() {
            // SAFETY: as above; the format takes a string.
            return c_int::from(unsafe { BIO_printf(bp, c"%s 0\n".as_ptr(), number) } > 0);
        }
        if v.num_bytes() <= rustyssl_crypto::bn::LIMB_BYTES {
            let w = v.limbs().first().copied().unwrap_or(0);
            // SAFETY: as above; the format takes two strings around each `unsigned long`.
            let r = unsafe {
                BIO_printf(bp, c"%s %s%lu (%s0x%lx)\n".as_ptr(), number, neg.as_ptr(), w, neg.as_ptr(), w)
            };
            return c_int::from(r > 0);
        }
        let label = if v.is_negative() { c" (Negative)" } else { c"" };
        // SAFETY: as above; the format takes two strings.
        if unsafe { BIO_printf(bp, c"%s%s\n".as_ptr(), number, label.as_ptr()) } <= 0 {
            return 0;
        }
        let mag = v.to_bin(None, Endian::Big, false).unwrap_or_default();
        let mut buf = rustyssl_crypto::bn::Zeroizing::new(Vec::with_capacity(mag.len().saturating_add(1)));
        if mag.first().is_some_and(|b| b & 0x80 != 0) {
            buf.push(0);
        }
        buf.extend_from_slice(&mag);
        // SAFETY: as above; `buf` holds its length.
        let r = unsafe { crate::asn1::hex::ASN1_buf_print(bp, buf.as_ptr(), buf.len(), indent.saturating_add(4)) };
        c_int::from(r != 0)
    }
}
