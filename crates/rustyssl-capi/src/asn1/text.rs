//! Character strings (`ASN1_mbstring_copy(3)`, `ASN1_STRING_set_by_NID(3)`,
//! `ASN1_STRING_TABLE_add(3)`, `ASN1_STRING_to_UTF8`, `ASN1_STRING_print_ex(3)`,
//! `ASN1_STRING_print`, `ASN1_PRINTABLE_type`, `UTF8_getc`, `ASN1_tag2str`), over
//! `rustyssl_asn1::text`.
//!
//! The string table maps NIDs to the size limits and types their strings may have: OpenSSL's
//! built-in table, then entries applications add, which `ASN1_STRING_TABLE_get` finds first.
//! The default mask (`ASN1_STRING_set_default_mask`) is process-wide, as in OpenSSL.

use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use libc::FILE;
use rustyssl_abi::{
    ASN1_R_ILLEGAL_CHARACTERS, ASN1_R_INVALID_BMPSTRING_LENGTH,
    ASN1_R_INVALID_UNIVERSALSTRING_LENGTH, ASN1_R_INVALID_UTF8STRING, ASN1_R_STRING_TOO_LONG,
    ASN1_R_STRING_TOO_SHORT, ASN1_R_UNKNOWN_FORMAT, ASN1_STRING, ASN1_STRING_TABLE,
    ASN1_UNIVERSALSTRING, B_ASN1_BIT_STRING, B_ASN1_BMPSTRING, B_ASN1_GENERALIZEDTIME,
    B_ASN1_GENERALSTRING, B_ASN1_GRAPHICSTRING, B_ASN1_IA5STRING, B_ASN1_ISO64STRING,
    B_ASN1_NUMERICSTRING, B_ASN1_OCTET_STRING, B_ASN1_PRINTABLESTRING, B_ASN1_SEQUENCE,
    B_ASN1_T61STRING, B_ASN1_UNIVERSALSTRING, B_ASN1_UNKNOWN, B_ASN1_UTCTIME, B_ASN1_UTF8STRING,
    B_ASN1_VIDEOTEXSTRING, BIO, DIRSTRING_TYPE, ERR_LIB_ASN1, ERR_R_ASN1_LIB,
    ERR_R_PASSED_INVALID_ARGUMENT, ERR_R_PASSED_NULL_PARAMETER, MBSTRING_FLAG, NID_INN, NID_OGRN,
    NID_SNILS, NID_commonName, NID_countryCode3c, NID_countryCode3n, NID_countryName,
    NID_dnQualifier, NID_dnsName, NID_domainComponent, NID_friendlyName, NID_givenName,
    NID_id_on_SmtpUTF8Mailbox, NID_initials, NID_jurisdictionCountryName, NID_localityName,
    NID_ms_csp_name, NID_name, NID_organizationName, NID_organizationalUnitName,
    NID_pkcs9_challengePassword, NID_pkcs9_emailAddress, NID_pkcs9_unstructuredAddress,
    NID_pkcs9_unstructuredName, NID_rfc822Mailbox, NID_serialNumber, NID_stateOrProvinceName,
    NID_surname, OPENSSL_INIT_LOAD_CONFIG, OPENSSL_STACK, PKCS9STRING_TYPE, STABLE_FLAGS_MALLOC,
    STABLE_NO_MASK, V_ASN1_IA5STRING, V_ASN1_PRINTABLESTRING, V_ASN1_T61STRING,
    V_ASN1_UNIVERSALSTRING, ub_common_name, ub_email_address, ub_locality_name, ub_name,
    ub_organization_name, ub_organization_unit_name, ub_state_name,
};
use rustyssl_asn1::text::{self, Form, MbError, PrintError};

use super::string;
use crate::err;
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::stack::{
    OPENSSL_sk_find, OPENSSL_sk_new, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_sort,
    OPENSSL_sk_value,
};

/// A C `int` constant as the `unsigned long` masks are.
fn mask(bits: c_int) -> c_ulong {
    c_ulong::try_from(bits).unwrap_or(0)
}

/// The octets at `data`: `len` of them, or none for NULL data or a negative length.
///
/// # Safety
/// `data` is NULL or holds `len` octets.
unsafe fn octets<'a>(data: *const c_uchar, len: c_int) -> &'a [u8] {
    match usize::try_from(len) {
        // SAFETY: the caller's guarantee.
        Ok(n) if !data.is_null() => unsafe { core::slice::from_raw_parts(data, n) },
        _ => &[],
    }
}

ffi_export! {
    /// Decodes the UTF-8 character at `str` (at most `len` octets) into `*val`. Returns its
    /// length, 0 for no input, or -1 (cut short), -2 (bad first octet or a surrogate), -3 (bad
    /// continuation octet), -4 (overlong or past Unicode).
    ///
    /// Unlike OpenSSL, NULL `val` isn't written (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `str` holds `len` octets; `val` is NULL or valid for a write.
    pub unsafe extern "C" fn UTF8_getc(str: *const c_uchar, len: c_int, val: *mut c_ulong) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        if len <= 0 || str.is_null() {
            return 0;
        }
        // At most the 4 octets a character can take are read.
        // SAFETY: the caller's guarantee.
        let input = unsafe { octets(str, len.min(4)) };
        match text::utf8_get(input) {
            Ok(Some((value, length))) => {
                if !val.is_null() {
                    // SAFETY: the caller's guarantee.
                    unsafe { val.write(c_ulong::from(value)) };
                }
                c_int::try_from(length).unwrap_or(0)
            }
            Ok(None) => 0,
            Err(code) => code,
        }
    }
}

ffi_export! {
    /// Encodes `value` as UTF-8 into `str` (`len` octets), or only measures it with NULL `str`.
    /// Returns the octets needed, -1 if they don't fit, or -2 for a surrogate or a value past
    /// Unicode.
    ///
    /// # Safety
    /// `str` is NULL or valid for writes of `len` octets.
    pub unsafe extern "C" fn UTF8_putc(str: *mut c_uchar, len: c_int, value: c_ulong) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        let room = if str.is_null() { 4 } else if len <= 0 { return -1 } else { len };
        let encoded = match text::utf8_put(value) {
            Ok(encoded) => encoded,
            Err(code) => return code,
        };
        let needed = c_int::try_from(encoded.len()).unwrap_or(4);
        if room < needed {
            return -1;
        }
        if !str.is_null() {
            // SAFETY: `needed` octets fit in the caller's buffer.
            unsafe { ptr::copy_nonoverlapping(encoded.as_ptr(), str, encoded.len()) };
        }
        needed
    }
}

/// Raises the error `ASN1_mbstring_ncopy` raises for `error`.
fn raise_mb(error: MbError) {
    let function = "ASN1_mbstring_ncopy";
    match error {
        MbError::StringTooLong => err::raise(ERR_LIB_ASN1, ASN1_R_STRING_TOO_LONG, function),
        MbError::PassedInvalidArgument => {
            err::raise(ERR_LIB_ASN1, ERR_R_PASSED_INVALID_ARGUMENT, function);
        }
        MbError::InvalidBmpLength => {
            err::raise(ERR_LIB_ASN1, ASN1_R_INVALID_BMPSTRING_LENGTH, function);
        }
        MbError::InvalidUniversalLength => {
            err::raise(
                ERR_LIB_ASN1,
                ASN1_R_INVALID_UNIVERSALSTRING_LENGTH,
                function,
            );
        }
        MbError::InvalidUtf8 => err::raise(ERR_LIB_ASN1, ASN1_R_INVALID_UTF8STRING, function),
        MbError::UnknownFormat => err::raise(ERR_LIB_ASN1, ASN1_R_UNKNOWN_FORMAT, function),
        MbError::TooShort(min) => err::raise_with_text(
            ERR_LIB_ASN1,
            ASN1_R_STRING_TOO_SHORT,
            function,
            &format!("minsize={min}"),
        ),
        MbError::TooLong(max) => err::raise_with_text(
            ERR_LIB_ASN1,
            ASN1_R_STRING_TOO_LONG,
            function,
            &format!("maxsize={max}"),
        ),
        MbError::IllegalCharacters => err::raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_CHARACTERS, function),
    }
}

/// `ASN1_mbstring_ncopy`.
///
/// # Safety
/// `out` is NULL or points to NULL or a live string; `input` is NULL or holds `len` octets (a
/// NUL-terminated string for -1).
unsafe fn mbstring_ncopy(
    out: *mut *mut ASN1_STRING,
    input: *const c_uchar,
    len: c_int,
    inform: c_int,
    mask_in: c_ulong,
    minsize: c_long,
    maxsize: c_long,
) -> c_int {
    if input.is_null() && len != 0 {
        err::raise(
            ERR_LIB_ASN1,
            ERR_R_PASSED_NULL_PARAMETER,
            "ASN1_mbstring_ncopy",
        );
        return -1;
    }
    let len = if len == -1 {
        // SAFETY: the caller's guarantee.
        let measured = unsafe { libc::strlen(input.cast()) };
        match c_int::try_from(measured) {
            Ok(n) if n < c_int::MAX => n,
            _ => {
                raise_mb(MbError::StringTooLong);
                return -1;
            }
        }
    } else {
        len
    };
    let mask_in = if mask_in == 0 {
        mask(DIRSTRING_TYPE)
    } else {
        mask_in
    };
    if len < 0 {
        raise_mb(MbError::PassedInvalidArgument);
        return -1;
    }
    // SAFETY: the caller's guarantee.
    let data = unsafe { octets(input, len) };
    let form = Form::from_mbstring(inform);
    let chosen = match text::check_and_choose(data, form, mask_in, minsize, maxsize) {
        Ok(chosen) => chosen,
        Err(error) => {
            raise_mb(error);
            return -1;
        }
    };
    if out.is_null() {
        return chosen.string_type;
    }
    // SAFETY: the caller's guarantee.
    let existing = unsafe { *out };
    let dest = if existing.is_null() {
        let made = string::type_new(chosen.string_type);
        if made.is_null() {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, "ASN1_mbstring_ncopy");
            return -1;
        }
        // SAFETY: as above.
        unsafe { *out = made };
        made
    } else {
        // SAFETY: the caller's string.
        unsafe { string::ASN1_STRING_set0(existing, ptr::null_mut(), 0) };
        // SAFETY: as above.
        unsafe { (*existing).type_ = chosen.string_type };
        existing
    };
    let fail = || {
        if existing.is_null() {
            // SAFETY: the string made here.
            unsafe { string::ASN1_STRING_free(dest) };
            // SAFETY: as above.
            unsafe { *out = ptr::null_mut() };
        }
        -1
    };
    if chosen.same_form {
        // SAFETY: a live string; the caller's input holds `len` octets.
        if unsafe { string::set(dest, input.cast(), len) } == 0 {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, "ASN1_mbstring_ncopy");
            return fail();
        }
        return chosen.string_type;
    }
    let converted = match text::convert(data, form.unwrap_or(Form::Ascii), chosen.form) {
        Ok(converted) => converted,
        Err(error) => {
            raise_mb(error);
            return fail();
        }
    };
    let Ok(length) = c_int::try_from(converted.len()) else {
        return fail();
    };
    let buffer: *mut u8 = mem::alloc(converted.len() + 1).cast();
    if buffer.is_null() {
        return fail();
    }
    // SAFETY: `buffer` has room for the octets and a NUL.
    unsafe { ptr::copy_nonoverlapping(converted.as_ptr(), buffer, converted.len()) };
    // SAFETY: as above.
    unsafe { buffer.wrapping_add(converted.len()).write(0) };
    // SAFETY: the string, whose data was released above.
    let target = unsafe { &mut *dest };
    target.length = length;
    target.data = buffer;
    chosen.string_type
}

ffi_export! {
    /// `ASN1_mbstring_ncopy` without size limits.
    ///
    /// # Safety
    /// As for `ASN1_mbstring_ncopy`.
    pub unsafe extern "C" fn ASN1_mbstring_copy(out: *mut *mut ASN1_STRING, in_: *const c_uchar, len: c_int, inform: c_int, mask: c_ulong) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { mbstring_ncopy(out, in_, len, inform, mask, 0, 0) }
    }
}

ffi_export! {
    /// Converts `len` octets of `in` (or to its NUL for -1) in form `inform` (`MBSTRING_ASC`,
    /// `_BMP`, `_UNIV`, `_UTF8`) to the first string type of `mask` (0 for `DIRSTRING_TYPE`)
    /// that can hold every character, checking its character count against `minsize` and
    /// `maxsize` (when positive). The result goes into `*out` (made if NULL), or with NULL `out`
    /// only the type is returned. Returns the `V_ASN1_*` type, or -1 with an error.
    ///
    /// Unlike OpenSSL, NULL `in` with a nonzero length fails rather than crashing
    /// (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `out` is NULL or points to NULL or a live string; `in` is NULL or holds `len` octets (a
    /// NUL-terminated string for -1).
    pub unsafe extern "C" fn ASN1_mbstring_ncopy(out: *mut *mut ASN1_STRING, in_: *const c_uchar, len: c_int, inform: c_int, mask: c_ulong, minsize: c_long, maxsize: c_long) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { mbstring_ncopy(out, in_, len, inform, mask, minsize, maxsize) }
    }
}

/// The mask `ASN1_STRING_set_by_NID` and `ASN1_mbstring` callers start from.
static DEFAULT_MASK: AtomicU64 = AtomicU64::new(0x2000);

const _: () = assert!(B_ASN1_UTF8STRING == 0x2000);

fn default_mask() -> c_ulong {
    DEFAULT_MASK.load(Ordering::Relaxed)
}

ffi_export! {
    /// Sets the mask of string types `ASN1_STRING_set_by_NID` allows (with the table's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_STRING_set_default_mask(mask: c_ulong)
    where failure = (), library = ERR_LIB_ASN1
    {
        DEFAULT_MASK.store(mask, Ordering::Relaxed);
    }
}

ffi_export! {
    /// The default mask (`B_ASN1_UTF8STRING` unless set).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_STRING_get_default_mask() -> c_ulong
    where failure = 0, library = ERR_LIB_ASN1
    {
        default_mask()
    }
}

ffi_export! {
    /// Sets the default mask by name: `MASK:<number>`, `nombstr`, `pkix`, `utf8only`, or
    /// `default`. Returns 1, or 0 for anything else.
    ///
    /// # Safety
    /// `p` is NULL or a NUL-terminated string.
    pub unsafe extern "C" fn ASN1_STRING_set_default_mask_asc(p: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        if p.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let name = unsafe { CStr::from_ptr(p) }.to_bytes();
        let value = if let Some(number) = name.strip_prefix(b"MASK:") {
            if number.is_empty() {
                return 0;
            }
            let start = p.wrapping_add(5);
            let mut end: *mut c_char = ptr::null_mut();
            // SAFETY: a NUL-terminated string; `end` is local.
            let value = unsafe { libc::strtoul(start, &raw mut end, 0) };
            // SAFETY: `strtoul` leaves `end` within the string.
            if unsafe { end.read() } != 0 {
                return 0;
            }
            value
        } else {
            match name {
                b"nombstr" => !mask(B_ASN1_BMPSTRING | B_ASN1_UTF8STRING),
                b"pkix" => !mask(B_ASN1_T61STRING),
                b"utf8only" => mask(B_ASN1_UTF8STRING),
                b"default" => 0xFFFF_FFFF,
                _ => return 0,
            }
        };
        DEFAULT_MASK.store(value, Ordering::Relaxed);
        1
    }
}

/// Upper bounds `tbl_standard.h` defines itself (not in the public headers).
const UB_SERIAL_NUMBER: c_int = 64;
const UB_RFC822_MAILBOX: c_int = 256;

/// An entry of the built-in table.
const fn entry(
    nid: c_int,
    minsize: c_int,
    maxsize: c_int,
    mask: c_int,
    flags: c_int,
) -> ASN1_STRING_TABLE {
    #[expect(
        clippy::cast_sign_loss,
        reason = "the masks and flags are positive constants"
    )]
    ASN1_STRING_TABLE {
        nid,
        minsize: minsize as c_long,
        maxsize: maxsize as c_long,
        mask: mask as c_ulong,
        flags: flags as c_ulong,
    }
}

/// OpenSSL's built-in string table (`tbl_standard.h`), sorted by NID.
static STANDARD: [ASN1_STRING_TABLE; 28] = [
    entry(NID_commonName, 1, ub_common_name, DIRSTRING_TYPE, 0),
    entry(
        NID_countryName,
        2,
        2,
        B_ASN1_PRINTABLESTRING,
        STABLE_NO_MASK,
    ),
    entry(NID_localityName, 1, ub_locality_name, DIRSTRING_TYPE, 0),
    entry(NID_stateOrProvinceName, 1, ub_state_name, DIRSTRING_TYPE, 0),
    entry(
        NID_organizationName,
        1,
        ub_organization_name,
        DIRSTRING_TYPE,
        0,
    ),
    entry(
        NID_organizationalUnitName,
        1,
        ub_organization_unit_name,
        DIRSTRING_TYPE,
        0,
    ),
    entry(
        NID_pkcs9_emailAddress,
        1,
        ub_email_address,
        B_ASN1_IA5STRING,
        STABLE_NO_MASK,
    ),
    entry(NID_pkcs9_unstructuredName, 1, -1, PKCS9STRING_TYPE, 0),
    entry(NID_pkcs9_challengePassword, 1, -1, PKCS9STRING_TYPE, 0),
    entry(NID_pkcs9_unstructuredAddress, 1, -1, DIRSTRING_TYPE, 0),
    entry(NID_givenName, 1, ub_name, DIRSTRING_TYPE, 0),
    entry(NID_surname, 1, ub_name, DIRSTRING_TYPE, 0),
    entry(NID_initials, 1, ub_name, DIRSTRING_TYPE, 0),
    entry(
        NID_serialNumber,
        1,
        UB_SERIAL_NUMBER,
        B_ASN1_PRINTABLESTRING,
        STABLE_NO_MASK,
    ),
    entry(NID_friendlyName, -1, -1, B_ASN1_BMPSTRING, STABLE_NO_MASK),
    entry(NID_name, 1, ub_name, DIRSTRING_TYPE, 0),
    entry(
        NID_dnQualifier,
        -1,
        -1,
        B_ASN1_PRINTABLESTRING,
        STABLE_NO_MASK,
    ),
    entry(NID_domainComponent, 1, -1, B_ASN1_IA5STRING, STABLE_NO_MASK),
    entry(NID_ms_csp_name, -1, -1, B_ASN1_BMPSTRING, STABLE_NO_MASK),
    entry(
        NID_rfc822Mailbox,
        1,
        UB_RFC822_MAILBOX,
        B_ASN1_IA5STRING,
        STABLE_NO_MASK,
    ),
    entry(
        NID_jurisdictionCountryName,
        2,
        2,
        B_ASN1_PRINTABLESTRING,
        STABLE_NO_MASK,
    ),
    entry(NID_INN, 1, 12, B_ASN1_NUMERICSTRING, STABLE_NO_MASK),
    entry(NID_OGRN, 1, 13, B_ASN1_NUMERICSTRING, STABLE_NO_MASK),
    entry(NID_SNILS, 1, 11, B_ASN1_NUMERICSTRING, STABLE_NO_MASK),
    entry(
        NID_countryCode3c,
        3,
        3,
        B_ASN1_PRINTABLESTRING,
        STABLE_NO_MASK,
    ),
    entry(
        NID_countryCode3n,
        3,
        3,
        B_ASN1_NUMERICSTRING,
        STABLE_NO_MASK,
    ),
    entry(NID_dnsName, 0, -1, B_ASN1_UTF8STRING, STABLE_NO_MASK),
    entry(
        NID_id_on_SmtpUTF8Mailbox,
        1,
        ub_email_address,
        B_ASN1_UTF8STRING,
        STABLE_NO_MASK,
    ),
];

/// The table entries applications added (OpenSSL's `stable`), a stack sorted by NID.
struct Added(*mut OPENSSL_STACK);

// SAFETY: the stack is only used under the mutex.
unsafe impl Send for Added {}

static ADDED: Mutex<Added> = Mutex::new(Added(ptr::null_mut()));

ffi_callback! {
    /// `sk_table_cmp`: by NID.
    ///
    /// # Safety
    /// Both point to stack slots holding live entries.
    pub(crate) unsafe extern "C" fn by_nid(a: *const c_void, b: *const c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let a = unsafe { *a.cast::<*const ASN1_STRING_TABLE>() };
        // SAFETY: as above.
        let b = unsafe { *b.cast::<*const ASN1_STRING_TABLE>() };
        // SAFETY: as above.
        let (a, b) = (unsafe { (*a).nid }, unsafe { (*b).nid });
        a.wrapping_sub(b)
    }
}

ffi_callback! {
    /// `st_free`: frees an entry made by `ASN1_STRING_TABLE_add` (marked `STABLE_FLAGS_MALLOC`).
    ///
    /// # Safety
    /// `entry` is a live entry of the stack.
    pub(crate) unsafe extern "C" fn free_entry(entry: *mut c_void)
    where failure = (), library = ERR_LIB_ASN1
    {
        let table: *mut ASN1_STRING_TABLE = entry.cast();
        // SAFETY: the caller's guarantee.
        if unsafe { (*table).flags } & mask(STABLE_FLAGS_MALLOC) != 0 {
            // SAFETY: entries marked so came from this allocator.
            unsafe { mem::release(entry) };
        }
    }
}

/// `ASN1_STRING_TABLE_get` with the added entries' lock held.
fn table_get(added: &Added, nid: c_int) -> *mut ASN1_STRING_TABLE {
    if !added.0.is_null() {
        let key = entry(nid, 0, 0, 0, 0);
        // SAFETY: the stack, under the mutex.
        unsafe { OPENSSL_sk_sort(added.0) };
        // SAFETY: as above; the comparator reads the key's NID.
        let index = unsafe { OPENSSL_sk_find(added.0, (&raw const key).cast()) };
        if index >= 0 {
            // SAFETY: as above.
            return unsafe { OPENSSL_sk_value(added.0, index) }.cast();
        }
    }
    STANDARD
        .binary_search_by_key(&nid, |e| e.nid)
        .ok()
        .and_then(|i| STANDARD.get(i))
        .map_or(ptr::null_mut(), |e| ptr::from_ref(e).cast_mut())
}

/// As OpenSSL, loads the configuration (which can add entries) before a lookup.
fn load_config() {
    if cfg!(miri) {
        return;
    }
    let flag = u64::try_from(OPENSSL_INIT_LOAD_CONFIG).unwrap_or(0);
    // SAFETY: no settings.
    let _ = unsafe { crate::init::OPENSSL_init_crypto(flag, ptr::null()) };
}

ffi_export! {
    /// The table entry for `nid`: one added with `ASN1_STRING_TABLE_add`, else a built-in one,
    /// else NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_STRING_TABLE_get(nid: c_int) -> *mut ASN1_STRING_TABLE
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        load_config();
        let added = ADDED.lock().unwrap_or_else(PoisonError::into_inner);
        table_get(&added, nid)
    }
}

ffi_export! {
    /// Adds or changes the table entry for `nid`: sizes when not negative, the mask and flags
    /// when not 0 (flags with `STABLE_FLAGS_MALLOC`). A new entry starts from the built-in one,
    /// if any. Returns 1, or 0 on failure.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_STRING_TABLE_add(nid: c_int, minsize: c_long, maxsize: c_long, mask: c_ulong, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        load_config();
        let mut added = ADDED.lock().unwrap_or_else(PoisonError::into_inner);
        if added.0.is_null() {
            // SAFETY: a comparator for stacks of entries.
            added.0 = unsafe { OPENSSL_sk_new(Some(by_nid)) };
        }
        let fail = || {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, "ASN1_STRING_TABLE_add");
            0
        };
        if added.0.is_null() {
            return fail();
        }
        let found = table_get(&added, nid);
        // SAFETY: entries are live.
        let target = if !found.is_null() && unsafe { (*found).flags } & self::mask(STABLE_FLAGS_MALLOC) != 0 {
            found
        } else {
            let made: *mut ASN1_STRING_TABLE = mem::alloc_zeroed(size_of::<ASN1_STRING_TABLE>()).cast();
            if made.is_null() {
                return fail();
            }
            // SAFETY: the stack, under the mutex.
            if unsafe { OPENSSL_sk_push(added.0, made.cast()) } == 0 {
                // SAFETY: not added.
                unsafe { mem::release(made.cast()) };
                return fail();
            }
            let malloc = self::mask(STABLE_FLAGS_MALLOC);
            let initial = if found.is_null() {
                ASN1_STRING_TABLE { nid, minsize: -1, maxsize: -1, mask: 0, flags: malloc }
            } else {
                // SAFETY: a live entry.
                let base = unsafe { found.read() };
                ASN1_STRING_TABLE { flags: base.flags | malloc, ..base }
            };
            // SAFETY: the new entry.
            unsafe { made.write(initial) };
            made
        };
        // SAFETY: an added entry, under the mutex.
        let entry = unsafe { &mut *target };
        if minsize >= 0 {
            entry.minsize = minsize;
        }
        if maxsize >= 0 {
            entry.maxsize = maxsize;
        }
        if mask != 0 {
            entry.mask = mask;
        }
        if flags != 0 {
            entry.flags = self::mask(STABLE_FLAGS_MALLOC) | flags;
        }
        1
    }
}

ffi_export! {
    /// Forgets the entries added with `ASN1_STRING_TABLE_add`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_STRING_TABLE_cleanup()
    where failure = (), library = ERR_LIB_ASN1
    {
        let stack = {
            let mut added = ADDED.lock().unwrap_or_else(PoisonError::into_inner);
            core::mem::replace(&mut added.0, ptr::null_mut())
        };
        // SAFETY: the stack, no longer shared.
        unsafe { OPENSSL_sk_pop_free(stack, Some(free_entry)) };
    }
}

ffi_export! {
    /// Converts `in` as `ASN1_mbstring_ncopy` does with the table entry for `nid` (its sizes, and
    /// its mask ANDed with the default mask unless `STABLE_NO_MASK`), or `DIRSTRING_TYPE` and
    /// the default mask without one. Returns `*out` (or a new string for NULL `out`), or NULL.
    ///
    /// # Safety
    /// As for `ASN1_mbstring_ncopy`.
    pub unsafe extern "C" fn ASN1_STRING_set_by_NID(out: *mut *mut ASN1_STRING, in_: *const c_uchar, inlen: c_int, inform: c_int, nid: c_int) -> *mut ASN1_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        let mut local: *mut ASN1_STRING = ptr::null_mut();
        let out = if out.is_null() { &raw mut local } else { out };
        // SAFETY: no preconditions.
        let table = unsafe { ASN1_STRING_TABLE_get(nid) };
        let result = if table.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { mbstring_ncopy(out, in_, inlen, inform, mask(DIRSTRING_TYPE) & default_mask(), 0, 0) }
        } else {
            // SAFETY: a live entry.
            let entry = unsafe { table.read() };
            let mut allowed = entry.mask;
            if entry.flags & mask(STABLE_NO_MASK) == 0 {
                allowed &= default_mask();
            }
            // SAFETY: the caller's guarantee.
            unsafe { mbstring_ncopy(out, in_, inlen, inform, allowed, entry.minsize, entry.maxsize) }
        };
        if result <= 0 {
            return ptr::null_mut();
        }
        // SAFETY: `out` is the caller's or the local.
        unsafe { *out }
    }
}

ffi_export! {
    /// Converts `in` (a text type) to a new UTF-8 buffer (`OPENSSL_malloc`) in `*out`. Returns
    /// its length, or a negative value for an unknown type or a failed conversion.
    ///
    /// Unlike OpenSSL, NULL `out` fails (-1) rather than crashing (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `out` is NULL or valid for a write; `in` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_STRING_to_UTF8(out: *mut *mut c_uchar, in_: *const ASN1_STRING) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        if in_.is_null() {
            return -1;
        }
        // SAFETY: the caller's guarantee.
        let string = unsafe { &*in_ };
        let width = text::tag_width(string.type_);
        if !(0..=30).contains(&string.type_) || width == -1 {
            return -1;
        }
        if out.is_null() {
            err::raise(ERR_LIB_ASN1, ERR_R_PASSED_NULL_PARAMETER, "ASN1_STRING_to_UTF8");
            return -1;
        }
        let mut temporary = ASN1_STRING { length: 0, type_: 0, data: ptr::null_mut(), flags: 0 };
        let mut target = &raw mut temporary;
        // SAFETY: the string's data; the temporary is local.
        let result = unsafe {
            mbstring_ncopy(&raw mut target, string.data, string.length, width | MBSTRING_FLAG, mask(B_ASN1_UTF8STRING), 0, 0)
        };
        if result < 0 {
            return result;
        }
        // SAFETY: the caller's guarantee.
        unsafe { out.write(temporary.data) };
        temporary.length
    }
}

/// OpenSSL's `tag2bit`: each universal tag's `B_ASN1_*` bit.
fn tag_bit(tag: c_int) -> c_ulong {
    let bits = [
        0,
        0,
        0,
        B_ASN1_BIT_STRING,
        B_ASN1_OCTET_STRING,
        0,
        0,
        B_ASN1_UNKNOWN,
        B_ASN1_UNKNOWN,
        B_ASN1_UNKNOWN,
        0,
        B_ASN1_UNKNOWN,
        B_ASN1_UTF8STRING,
        B_ASN1_UNKNOWN,
        B_ASN1_UNKNOWN,
        B_ASN1_UNKNOWN,
        B_ASN1_SEQUENCE,
        0,
        B_ASN1_NUMERICSTRING,
        B_ASN1_PRINTABLESTRING,
        B_ASN1_T61STRING,
        B_ASN1_VIDEOTEXSTRING,
        B_ASN1_IA5STRING,
        B_ASN1_UTCTIME,
        B_ASN1_GENERALIZEDTIME,
        B_ASN1_GRAPHICSTRING,
        B_ASN1_ISO64STRING,
        B_ASN1_GENERALSTRING,
        B_ASN1_UNIVERSALSTRING,
        B_ASN1_UNKNOWN,
        B_ASN1_BMPSTRING,
    ];
    usize::try_from(tag)
        .ok()
        .and_then(|t| bits.get(t))
        .map_or(0, |&b| mask(b))
}

ffi_export! {
    /// The `B_ASN1_*` bit of universal tag `tag` (0 for none, or outside 0 to 30).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_tag2bit(tag: c_int) -> c_ulong
    where failure = 0, library = ERR_LIB_ASN1
    {
        tag_bit(tag)
    }
}

ffi_export! {
    /// The name of universal tag `tag` (`"(unknown)"` outside 0 to 30, the negative INTEGER and
    /// ENUMERATED types named as their positive ones).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_tag2str(tag: c_int) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_ASN1
    {
        text::tag_name(tag).as_ptr()
    }
}

ffi_export! {
    /// The narrowest of PrintableString, IA5String, and T61String that holds `len` octets of `s`
    /// (to its NUL for a negative `len`; PrintableString for NULL).
    ///
    /// # Safety
    /// `s` is NULL or holds `len` octets (a NUL-terminated string for a negative `len`).
    pub unsafe extern "C" fn ASN1_PRINTABLE_type(s: *const c_uchar, len: c_int) -> c_int
    where failure = V_ASN1_PRINTABLESTRING, library = ERR_LIB_ASN1
    {
        if s.is_null() {
            return V_ASN1_PRINTABLESTRING;
        }
        let data: &[u8] = if len < 0 {
            // SAFETY: the caller's guarantee.
            unsafe { CStr::from_ptr(s.cast()) }.to_bytes()
        } else {
            // SAFETY: as above.
            unsafe { octets(s, len) }
        };
        if data.iter().any(|&c| !c.is_ascii()) {
            V_ASN1_T61STRING
        } else if data.iter().any(|&c| !text::is_asn1_print(u32::from(c))) {
            V_ASN1_IA5STRING
        } else {
            V_ASN1_PRINTABLESTRING
        }
    }
}

ffi_export! {
    /// Narrows a UniversalString whose characters all fit in one octet to those octets, typed
    /// by `ASN1_PRINTABLE_type`. Returns 1, or 0 (unchanged) otherwise.
    ///
    /// Unlike OpenSSL, NULL `s`, or an empty string without data, returns 0 rather than
    /// crashing (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `s` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_UNIVERSALSTRING_to_string(s: *mut ASN1_UNIVERSALSTRING) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        if s.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let string = unsafe { &mut *s };
        if string.type_ != V_ASN1_UNIVERSALSTRING || string.length % 4 != 0 || string.data.is_null() {
            return 0;
        }
        // SAFETY: the string's data holds its length.
        let data = unsafe { octets(string.data, string.length) };
        if data.chunks(4).any(|c| c.get(..3) != Some(&[0, 0, 0][..])) {
            return 0;
        }
        let narrowed: Vec<u8> = data.chunks(4).filter_map(|c| c.get(3).copied()).collect();
        // SAFETY: the narrowed octets and a NUL fit in the string's buffer.
        unsafe { ptr::copy_nonoverlapping(narrowed.as_ptr(), string.data, narrowed.len()) };
        // SAFETY: as above.
        unsafe { string.data.wrapping_add(narrowed.len()).write(0) };
        string.length /= 4;
        // SAFETY: the string's narrowed data.
        string.type_ = unsafe { ASN1_PRINTABLE_type(string.data, string.length) };
        1
    }
}

ffi_export! {
    /// Writes `v`'s octets to `bp`, each outside printable ASCII (but newline and carriage
    /// return) as `.`, in writes of up to 80. Returns 1, or 0 for NULL `v` or a failed write.
    ///
    /// # Safety
    /// `bp` is NULL or a live BIO; `v` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_STRING_print(bp: *mut BIO, v: *const ASN1_STRING) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        if v.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let string = unsafe { &*v };
        // SAFETY: the string's data holds its length.
        let data = unsafe { octets(string.data, string.length) };
        let shown: Vec<u8> = data
            .iter()
            .map(|&c| if c > b'~' || (c < b' ' && c != b'\n' && c != b'\r') { b'.' } else { c })
            .collect();
        for chunk in shown.chunks(80) {
            let n = c_int::try_from(chunk.len()).unwrap_or(0);
            // SAFETY: the caller's guarantee about `bp`.
            if unsafe { crate::bio::BIO_write(bp, chunk.as_ptr().cast(), n) } <= 0 {
                return 0;
            }
        }
        1
    }
}

/// `do_print_ex` for `str` with a writer; raises the errors OpenSSL raises.
///
/// # Safety
/// `str` is a live string.
unsafe fn print_ex(str: *const ASN1_STRING, flags: c_ulong, sink: text::Sink<'_>) -> c_int {
    // SAFETY: the caller's guarantee.
    let string = unsafe { &*str };
    // SAFETY: the string's data holds its length.
    let data = unsafe { octets(string.data, string.length) };
    match text::print_ex(data, string.type_, string.flags, flags, sink) {
        Ok(n) => n,
        Err(error) => {
            match error {
                PrintError::InvalidUniversalLength => {
                    err::raise(
                        ERR_LIB_ASN1,
                        ASN1_R_INVALID_UNIVERSALSTRING_LENGTH,
                        "do_buf",
                    );
                }
                PrintError::InvalidBmpLength => {
                    err::raise(ERR_LIB_ASN1, ASN1_R_INVALID_BMPSTRING_LENGTH, "do_buf");
                }
                PrintError::Failed => {}
            }
            -1
        }
    }
}

ffi_export! {
    /// Prints `str` to `out` as the `ASN1_STRFLGS_*` in `flags` say (escapes, quoting, type
    /// names, hex dumps, UTF-8 conversion). Returns the characters printed (or, for NULL `out`,
    /// that would be), or -1.
    ///
    /// Unlike OpenSSL, NULL `str` returns -1 rather than crashing (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `out` is NULL or a live BIO; `str` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_STRING_print_ex(out: *mut BIO, str: *const ASN1_STRING, flags: c_ulong) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        if str.is_null() {
            return -1;
        }
        let mut write = |chunk: &[u8]| {
            let n = c_int::try_from(chunk.len()).unwrap_or(0);
            // SAFETY: the caller's guarantee about `out`.
            unsafe { crate::bio::BIO_write(out, chunk.as_ptr().cast(), n) == n }
        };
        let sink: text::Sink<'_> = if out.is_null() { None } else { Some(&mut write) };
        // SAFETY: the caller's guarantee.
        unsafe { print_ex(str, flags, sink) }
    }
}

ffi_export! {
    /// `ASN1_STRING_print_ex` to a `FILE`.
    ///
    /// # Safety
    /// `fp` is NULL or an open `FILE`; `str` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_STRING_print_ex_fp(fp: *mut FILE, str: *const ASN1_STRING, flags: c_ulong) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        if str.is_null() {
            return -1;
        }
        let mut write = |chunk: &[u8]| {
            // SAFETY: the caller's guarantee about `fp`; `chunk` holds its length.
            unsafe { libc::fwrite(chunk.as_ptr().cast(), 1, chunk.len(), fp) == chunk.len() }
        };
        let sink: text::Sink<'_> = if fp.is_null() { None } else { Some(&mut write) };
        // SAFETY: the caller's guarantee.
        unsafe { print_ex(str, flags, sink) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_arguments_are_safe() {
        // SAFETY: NULL input with a length is refused.
        let refused = unsafe { ASN1_mbstring_copy(ptr::null_mut(), ptr::null(), 3, 0x1001, 0) };
        assert_eq!(refused, -1);
        // SAFETY: NULL `out` is refused.
        let no_out = unsafe { ASN1_STRING_to_UTF8(ptr::null_mut(), ptr::null()) };
        assert_eq!(no_out, -1);
        // SAFETY: NULL strings are refused.
        let result = unsafe { ASN1_STRING_print_ex(ptr::null_mut(), ptr::null(), 0) };
        assert_eq!(result, -1);
        // SAFETY: as above.
        let result = unsafe { ASN1_UNIVERSALSTRING_to_string(ptr::null_mut()) };
        assert_eq!(result, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { ASN1_STRING_set_default_mask_asc(ptr::null()) }, 0);
        let mut value: c_ulong = 0;
        // SAFETY: a 1-octet input; NULL `val` isn't written.
        let result = unsafe { UTF8_getc(c"A".as_ptr().cast(), 1, ptr::null_mut()) };
        assert_eq!(result, 1);
        // SAFETY: as above, with a value.
        let result = unsafe { UTF8_getc(c"A".as_ptr().cast(), 1, &raw mut value) };
        assert_eq!(result, 1);
        assert_eq!(value, 0x41);
        let s = string::type_new(V_ASN1_UNIVERSALSTRING);
        // SAFETY: an empty string without data is left alone.
        assert_eq!(unsafe { ASN1_UNIVERSALSTRING_to_string(s) }, 0);
        // SAFETY: made above.
        unsafe { string::ASN1_STRING_free(s) };
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }
}
