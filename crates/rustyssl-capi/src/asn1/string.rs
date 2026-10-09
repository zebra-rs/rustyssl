//! `ASN1_STRING`, the public-layout string under every universal string type, INTEGER,
//! ENUMERATED, BIT STRING, and the times (`ASN1_STRING_new(3)`, `ASN1_STRING_set(3)`,
//! `ASN1_STRING_length(3)`), and the `new`/`free` functions of each of those types.
//!
//! The struct is the application's to read and write (`length`, `type`, `data`, `flags`), so
//! its fields are taken as they are: the data is `length` octets from `OPENSSL_malloc`, plus a
//! NUL that `ASN1_STRING_set` keeps after them. As in OpenSSL, `ASN1_STRING_set` reuses the
//! buffer when the new contents fit in the old length, an `ASN1_STRING_FLAG_NDEF` string doesn't
//! own its data, and an `ASN1_STRING_FLAG_EMBED` one is part of another structure (only its
//! data is freed).

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_BMPSTRING, ASN1_ENUMERATED, ASN1_GENERALIZEDTIME, ASN1_GENERALSTRING,
    ASN1_IA5STRING, ASN1_INTEGER, ASN1_OCTET_STRING, ASN1_PRINTABLESTRING, ASN1_R_TOO_LARGE,
    ASN1_STRING, ASN1_STRING_FLAG_EMBED, ASN1_STRING_FLAG_NDEF, ASN1_T61STRING,
    ASN1_UNIVERSALSTRING, ASN1_UTCTIME, ASN1_UTF8STRING, ASN1_VISIBLESTRING, ERR_LIB_ASN1,
    V_ASN1_BIT_STRING, V_ASN1_BMPSTRING, V_ASN1_ENUMERATED, V_ASN1_GENERALIZEDTIME,
    V_ASN1_GENERALSTRING, V_ASN1_IA5STRING, V_ASN1_INTEGER, V_ASN1_OCTET_STRING,
    V_ASN1_PRINTABLESTRING, V_ASN1_T61STRING, V_ASN1_UNIVERSALSTRING, V_ASN1_UTCTIME,
    V_ASN1_UTF8STRING, V_ASN1_VISIBLESTRING,
};

use crate::err;
use crate::ffi::ffi_export;
use crate::mem;

/// `ossl_asn1_string_embed_free`: the data unless the string doesn't own it (NDEF), then the
/// struct unless it is embedded.
///
/// # Safety
/// `a` is NULL or a live string, not used afterwards.
pub(crate) unsafe fn embed_free(a: *mut ASN1_STRING, embed: bool) {
    if a.is_null() {
        return;
    }
    // SAFETY: the caller's guarantee.
    let string = unsafe { &mut *a };
    if string.flags & c_long::from(ASN1_STRING_FLAG_NDEF) == 0 {
        // SAFETY: a string's own data came from this allocator.
        unsafe { mem::release(string.data.cast()) };
    }
    if !embed {
        // SAFETY: a string not embedded came from this allocator.
        unsafe { mem::release(a.cast()) };
    }
}

/// `ASN1_STRING_set`.
///
/// # Safety
/// `str` is a live string; `data` is NULL or holds `len_in` octets (a NUL-terminated string
/// for a negative `len_in`).
pub(crate) unsafe fn set(str: *mut ASN1_STRING, data: *const c_void, len_in: c_int) -> c_int {
    let len = match usize::try_from(len_in) {
        Ok(len) => len,
        Err(_) if data.is_null() => return 0,
        // SAFETY: the caller's guarantee.
        Err(_) => unsafe { libc::strlen(data.cast()) },
    };
    // At most INT_MAX - 1, leaving room for the NUL.
    let Some(length) = c_int::try_from(len).ok().filter(|&l| l < c_int::MAX) else {
        err::raise(ERR_LIB_ASN1, ASN1_R_TOO_LARGE, "ASN1_STRING_set");
        return 0;
    };
    // SAFETY: the caller's guarantee.
    let string = unsafe { &mut *str };
    // A negative length, as `size_t`, is larger than any new one.
    let old = isize::try_from(string.length).map_or(usize::MAX, isize::cast_unsigned);
    if old <= len || string.data.is_null() {
        // SAFETY: the string's data came from this allocator (or is NULL).
        let grown = unsafe { mem::resize(string.data.cast(), len + 1) };
        if grown.is_null() {
            return 0;
        }
        string.data = grown.cast();
    }
    string.length = length;
    if !data.is_null() {
        // SAFETY: the data holds `len` octets; the buffer has room for them and a NUL.
        unsafe { ptr::copy_nonoverlapping(data.cast::<u8>(), string.data, len) };
        // SAFETY: as above.
        unsafe { string.data.wrapping_add(len).write(0) };
    }
    1
}

/// `ASN1_STRING_type_new`.
pub(crate) fn type_new(kind: c_int) -> *mut ASN1_STRING {
    let string: *mut ASN1_STRING = mem::alloc_zeroed(size_of::<ASN1_STRING>()).cast();
    if !string.is_null() {
        // SAFETY: just allocated, zeroed, and big enough.
        unsafe { (*string).type_ = kind };
    }
    string
}

/// `ASN1_STRING_copy`.
///
/// # Safety
/// `dst` is a live string; `str` is NULL or a live string.
pub(crate) unsafe fn copy(dst: *mut ASN1_STRING, str: *const ASN1_STRING) -> c_int {
    if str.is_null() {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let source = unsafe { &*str };
    // SAFETY: as above.
    unsafe { (*dst).type_ = source.type_ };
    // SAFETY: the source's data holds its length.
    if unsafe { set(dst, source.data.cast(), source.length) } == 0 {
        return 0;
    }
    let embed = c_long::from(ASN1_STRING_FLAG_EMBED);
    // SAFETY: the caller's guarantee.
    let target = unsafe { &mut *dst };
    target.flags &= embed;
    target.flags |= source.flags & !embed;
    1
}

ffi_export! {
    /// A new, empty OCTET STRING.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_STRING_new() -> *mut ASN1_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        type_new(V_ASN1_OCTET_STRING)
    }
}

ffi_export! {
    /// A new, empty string of type `type`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_STRING_type_new(type_: c_int) -> *mut ASN1_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        type_new(type_)
    }
}

ffi_export! {
    /// Frees `a`: its data unless it has `ASN1_STRING_FLAG_NDEF`, the struct unless it has
    /// `ASN1_STRING_FLAG_EMBED`.
    ///
    /// # Safety
    /// `a` is NULL or a live string, not used afterwards.
    pub unsafe extern "C" fn ASN1_STRING_free(a: *mut ASN1_STRING)
    where failure = (), library = ERR_LIB_ASN1
    {
        if a.is_null() {
            return;
        }
        // SAFETY: the caller's guarantee.
        let embed = unsafe { (*a).flags } & c_long::from(ASN1_STRING_FLAG_EMBED) != 0;
        // SAFETY: as above.
        unsafe { embed_free(a, embed) };
    }
}

ffi_export! {
    /// `ASN1_STRING_free`, first overwriting the data it owns.
    ///
    /// Unlike OpenSSL, a negative length overwrites nothing rather than crashing
    /// (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// As for `ASN1_STRING_free`.
    pub unsafe extern "C" fn ASN1_STRING_clear_free(a: *mut ASN1_STRING)
    where failure = (), library = ERR_LIB_ASN1
    {
        if a.is_null() {
            return;
        }
        // SAFETY: the caller's guarantee.
        let string = unsafe { &*a };
        let owned = string.flags & c_long::from(ASN1_STRING_FLAG_NDEF) == 0;
        if owned && !string.data.is_null() {
            let length = usize::try_from(string.length).unwrap_or(0);
            // SAFETY: the data holds `length` octets.
            unsafe { mem::cleanse(string.data.cast(), length) };
        }
        // SAFETY: as above.
        unsafe { ASN1_STRING_free(a) };
    }
}

ffi_export! {
    /// Sets `str` to a copy of `len_in` octets of `data` (to its NUL for a negative `len_in`),
    /// keeping a NUL after them; with NULL `data`, only sizes it. Returns 1, or 0 on failure
    /// (`ASN1_R_TOO_LARGE` past `INT_MAX` - 1 octets).
    ///
    /// # Safety
    /// `str` is a live string; `data` is NULL or holds `len_in` octets (a NUL-terminated
    /// string for a negative `len_in`).
    pub unsafe extern "C" fn ASN1_STRING_set(str: *mut ASN1_STRING, data: *const c_void, len_in: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        if str.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { set(str, data, len_in) }
    }
}

ffi_export! {
    /// Gives `str` the data `data` (from `OPENSSL_malloc`) of `len` octets, freeing its own.
    ///
    /// # Safety
    /// `str` is a live string; `data` is NULL or from this allocator, holding `len` octets.
    pub unsafe extern "C" fn ASN1_STRING_set0(str: *mut ASN1_STRING, data: *mut c_void, len: c_int)
    where failure = (), library = ERR_LIB_ASN1
    {
        if str.is_null() {
            return;
        }
        // SAFETY: the caller's guarantee.
        let string = unsafe { &mut *str };
        // SAFETY: the string's data came from this allocator.
        unsafe { mem::release(string.data.cast()) };
        string.data = data.cast();
        string.length = len;
    }
}

ffi_export! {
    /// Copies `str`'s type, data, and flags (all but `ASN1_STRING_FLAG_EMBED`) into `dst`.
    /// Returns 1, or 0 for NULL `str` or on failure.
    ///
    /// # Safety
    /// `dst` is a live string; `str` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_STRING_copy(dst: *mut ASN1_STRING, str: *const ASN1_STRING) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        if dst.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { copy(dst, str) }
    }
}

ffi_export! {
    /// A new copy of `str`, or NULL.
    ///
    /// # Safety
    /// `str` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_STRING_dup(str: *const ASN1_STRING) -> *mut ASN1_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        if str.is_null() {
            return ptr::null_mut();
        }
        let copied = type_new(V_ASN1_OCTET_STRING);
        if copied.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: a new string; the caller's guarantee about `str`.
        if unsafe { copy(copied, str) } == 0 {
            // SAFETY: the new string.
            unsafe { ASN1_STRING_free(copied) };
            return ptr::null_mut();
        }
        copied
    }
}

/// `ASN1_STRING_cmp`.
///
/// # Safety
/// `a` and `b` are live strings, their data holding their lengths.
pub(crate) unsafe fn compare(a: *const ASN1_STRING, b: *const ASN1_STRING) -> c_int {
    // SAFETY: the caller's guarantee.
    let a = unsafe { &*a };
    // SAFETY: as above.
    let b = unsafe { &*b };
    let difference = a.length.wrapping_sub(b.length);
    if difference != 0 {
        return difference;
    }
    if let Ok(length) = usize::try_from(a.length)
        && length > 0
    {
        // SAFETY: both hold `length` octets.
        let x = unsafe { core::slice::from_raw_parts(a.data, length) };
        // SAFETY: as above.
        let y = unsafe { core::slice::from_raw_parts(b.data, length) };
        if let Some((p, q)) = x.iter().zip(y).find(|(p, q)| p != q) {
            return c_int::from(*p) - c_int::from(*q);
        }
    }
    a.type_.wrapping_sub(b.type_)
}

ffi_export! {
    /// Compares by length, then octets, then type; 0 if equal.
    ///
    /// Unlike OpenSSL, a NULL string sorts first rather than crashing (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `a` and `b` are NULL or live strings.
    pub unsafe extern "C" fn ASN1_STRING_cmp(a: *const ASN1_STRING, b: *const ASN1_STRING) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        match (a.is_null(), b.is_null()) {
            (true, true) => 0,
            (true, false) => -1,
            (false, true) => 1,
            // SAFETY: the caller's guarantee.
            (false, false) => unsafe { compare(a, b) },
        }
    }
}

ffi_export! {
    /// `x`'s length.
    ///
    /// # Safety
    /// `x` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_STRING_length(x: *const ASN1_STRING) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        if x.is_null() { 0 } else { unsafe { (*x).length } }
    }
}

ffi_export! {
    /// Sets `x`'s length (only the field).
    ///
    /// # Safety
    /// `x` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_STRING_length_set(x: *mut ASN1_STRING, len: c_int)
    where failure = (), library = ERR_LIB_ASN1
    {
        if !x.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { (*x).length = len };
        }
    }
}

ffi_export! {
    /// `x`'s type.
    ///
    /// # Safety
    /// `x` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_STRING_type(x: *const ASN1_STRING) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        if x.is_null() { 0 } else { unsafe { (*x).type_ } }
    }
}

ffi_export! {
    /// `x`'s data.
    ///
    /// # Safety
    /// `x` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_STRING_get0_data(x: *const ASN1_STRING) -> *const c_uchar
    where failure = ptr::null(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        if x.is_null() { ptr::null() } else { unsafe { (*x).data } }
    }
}

ffi_export! {
    /// `x`'s data, to modify.
    ///
    /// # Safety
    /// `x` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_STRING_data(x: *mut ASN1_STRING) -> *mut c_uchar
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        if x.is_null() { ptr::null_mut() } else { unsafe { (*x).data } }
    }
}

ffi_export! {
    /// `ASN1_STRING_dup` for an OCTET STRING.
    ///
    /// # Safety
    /// As for `ASN1_STRING_dup`.
    pub unsafe extern "C" fn ASN1_OCTET_STRING_dup(x: *const ASN1_OCTET_STRING) -> *mut ASN1_OCTET_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_STRING_dup(x) }
    }
}

ffi_export! {
    /// `ASN1_STRING_cmp` for OCTET STRINGs.
    ///
    /// # Safety
    /// As for `ASN1_STRING_cmp`.
    pub unsafe extern "C" fn ASN1_OCTET_STRING_cmp(a: *const ASN1_OCTET_STRING, b: *const ASN1_OCTET_STRING) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_STRING_cmp(a, b) }
    }
}

ffi_export! {
    /// `ASN1_STRING_set` for an OCTET STRING.
    ///
    /// # Safety
    /// As for `ASN1_STRING_set`.
    pub unsafe extern "C" fn ASN1_OCTET_STRING_set(x: *mut ASN1_OCTET_STRING, d: *const c_uchar, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_STRING_set(x, d.cast(), len) }
    }
}

ffi_export! {
    /// A new, empty `ASN1_OCTET_STRING`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_OCTET_STRING_new() -> *mut ASN1_OCTET_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        type_new(V_ASN1_OCTET_STRING)
    }
}

ffi_export! {
    /// Frees a `ASN1_OCTET_STRING` (`ASN1_STRING_free`).
    ///
    /// # Safety
    /// As for `ASN1_STRING_free`.
    pub unsafe extern "C" fn ASN1_OCTET_STRING_free(a: *mut ASN1_OCTET_STRING)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_STRING_free(a) }
    }
}

ffi_export! {
    /// A new, empty `ASN1_INTEGER`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_INTEGER_new() -> *mut ASN1_INTEGER
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        type_new(V_ASN1_INTEGER)
    }
}

ffi_export! {
    /// Frees a `ASN1_INTEGER` (`ASN1_STRING_free`).
    ///
    /// # Safety
    /// As for `ASN1_STRING_free`.
    pub unsafe extern "C" fn ASN1_INTEGER_free(a: *mut ASN1_INTEGER)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_STRING_free(a) }
    }
}

ffi_export! {
    /// A new, empty `ASN1_ENUMERATED`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_ENUMERATED_new() -> *mut ASN1_ENUMERATED
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        type_new(V_ASN1_ENUMERATED)
    }
}

ffi_export! {
    /// Frees a `ASN1_ENUMERATED` (`ASN1_STRING_free`).
    ///
    /// # Safety
    /// As for `ASN1_STRING_free`.
    pub unsafe extern "C" fn ASN1_ENUMERATED_free(a: *mut ASN1_ENUMERATED)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_STRING_free(a) }
    }
}

ffi_export! {
    /// A new, empty `ASN1_BIT_STRING`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_BIT_STRING_new() -> *mut ASN1_BIT_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        type_new(V_ASN1_BIT_STRING)
    }
}

ffi_export! {
    /// Frees a `ASN1_BIT_STRING` (`ASN1_STRING_free`).
    ///
    /// # Safety
    /// As for `ASN1_STRING_free`.
    pub unsafe extern "C" fn ASN1_BIT_STRING_free(a: *mut ASN1_BIT_STRING)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_STRING_free(a) }
    }
}

ffi_export! {
    /// A new, empty `ASN1_UTF8STRING`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_UTF8STRING_new() -> *mut ASN1_UTF8STRING
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        type_new(V_ASN1_UTF8STRING)
    }
}

ffi_export! {
    /// Frees a `ASN1_UTF8STRING` (`ASN1_STRING_free`).
    ///
    /// # Safety
    /// As for `ASN1_STRING_free`.
    pub unsafe extern "C" fn ASN1_UTF8STRING_free(a: *mut ASN1_UTF8STRING)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_STRING_free(a) }
    }
}

ffi_export! {
    /// A new, empty `ASN1_PRINTABLESTRING`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_PRINTABLESTRING_new() -> *mut ASN1_PRINTABLESTRING
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        type_new(V_ASN1_PRINTABLESTRING)
    }
}

ffi_export! {
    /// Frees a `ASN1_PRINTABLESTRING` (`ASN1_STRING_free`).
    ///
    /// # Safety
    /// As for `ASN1_STRING_free`.
    pub unsafe extern "C" fn ASN1_PRINTABLESTRING_free(a: *mut ASN1_PRINTABLESTRING)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_STRING_free(a) }
    }
}

ffi_export! {
    /// A new, empty `ASN1_T61STRING`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_T61STRING_new() -> *mut ASN1_T61STRING
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        type_new(V_ASN1_T61STRING)
    }
}

ffi_export! {
    /// Frees a `ASN1_T61STRING` (`ASN1_STRING_free`).
    ///
    /// # Safety
    /// As for `ASN1_STRING_free`.
    pub unsafe extern "C" fn ASN1_T61STRING_free(a: *mut ASN1_T61STRING)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_STRING_free(a) }
    }
}

ffi_export! {
    /// A new, empty `ASN1_IA5STRING`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_IA5STRING_new() -> *mut ASN1_IA5STRING
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        type_new(V_ASN1_IA5STRING)
    }
}

ffi_export! {
    /// Frees a `ASN1_IA5STRING` (`ASN1_STRING_free`).
    ///
    /// # Safety
    /// As for `ASN1_STRING_free`.
    pub unsafe extern "C" fn ASN1_IA5STRING_free(a: *mut ASN1_IA5STRING)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_STRING_free(a) }
    }
}

ffi_export! {
    /// A new, empty `ASN1_GENERALSTRING`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_GENERALSTRING_new() -> *mut ASN1_GENERALSTRING
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        type_new(V_ASN1_GENERALSTRING)
    }
}

ffi_export! {
    /// Frees a `ASN1_GENERALSTRING` (`ASN1_STRING_free`).
    ///
    /// # Safety
    /// As for `ASN1_STRING_free`.
    pub unsafe extern "C" fn ASN1_GENERALSTRING_free(a: *mut ASN1_GENERALSTRING)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_STRING_free(a) }
    }
}

ffi_export! {
    /// A new, empty `ASN1_UTCTIME`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_UTCTIME_new() -> *mut ASN1_UTCTIME
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        type_new(V_ASN1_UTCTIME)
    }
}

ffi_export! {
    /// Frees a `ASN1_UTCTIME` (`ASN1_STRING_free`).
    ///
    /// # Safety
    /// As for `ASN1_STRING_free`.
    pub unsafe extern "C" fn ASN1_UTCTIME_free(a: *mut ASN1_UTCTIME)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_STRING_free(a) }
    }
}

ffi_export! {
    /// A new, empty `ASN1_GENERALIZEDTIME`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_GENERALIZEDTIME_new() -> *mut ASN1_GENERALIZEDTIME
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        type_new(V_ASN1_GENERALIZEDTIME)
    }
}

ffi_export! {
    /// Frees a `ASN1_GENERALIZEDTIME` (`ASN1_STRING_free`).
    ///
    /// # Safety
    /// As for `ASN1_STRING_free`.
    pub unsafe extern "C" fn ASN1_GENERALIZEDTIME_free(a: *mut ASN1_GENERALIZEDTIME)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_STRING_free(a) }
    }
}

ffi_export! {
    /// A new, empty `ASN1_VISIBLESTRING`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_VISIBLESTRING_new() -> *mut ASN1_VISIBLESTRING
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        type_new(V_ASN1_VISIBLESTRING)
    }
}

ffi_export! {
    /// Frees a `ASN1_VISIBLESTRING` (`ASN1_STRING_free`).
    ///
    /// # Safety
    /// As for `ASN1_STRING_free`.
    pub unsafe extern "C" fn ASN1_VISIBLESTRING_free(a: *mut ASN1_VISIBLESTRING)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_STRING_free(a) }
    }
}

ffi_export! {
    /// A new, empty `ASN1_UNIVERSALSTRING`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_UNIVERSALSTRING_new() -> *mut ASN1_UNIVERSALSTRING
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        type_new(V_ASN1_UNIVERSALSTRING)
    }
}

ffi_export! {
    /// Frees a `ASN1_UNIVERSALSTRING` (`ASN1_STRING_free`).
    ///
    /// # Safety
    /// As for `ASN1_STRING_free`.
    pub unsafe extern "C" fn ASN1_UNIVERSALSTRING_free(a: *mut ASN1_UNIVERSALSTRING)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_STRING_free(a) }
    }
}

ffi_export! {
    /// A new, empty `ASN1_BMPSTRING`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ASN1_BMPSTRING_new() -> *mut ASN1_BMPSTRING
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        type_new(V_ASN1_BMPSTRING)
    }
}

ffi_export! {
    /// Frees a `ASN1_BMPSTRING` (`ASN1_STRING_free`).
    ///
    /// # Safety
    /// As for `ASN1_STRING_free`.
    pub unsafe extern "C" fn ASN1_BMPSTRING_free(a: *mut ASN1_BMPSTRING)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_STRING_free(a) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_strings_and_negative_lengths_are_safe() {
        // SAFETY: NULL strings are refused.
        assert_eq!(unsafe { ASN1_STRING_length(ptr::null()) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { ASN1_STRING_type(ptr::null()) }, 0);
        // SAFETY: as above.
        assert!(unsafe { ASN1_STRING_get0_data(ptr::null()) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { ASN1_STRING_data(ptr::null_mut()) }.is_null());
        // SAFETY: as above.
        let set = unsafe { ASN1_STRING_set(ptr::null_mut(), c"x".as_ptr().cast(), 1) };
        assert_eq!(set, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { ASN1_STRING_copy(ptr::null_mut(), ptr::null()) }, 0);
        // SAFETY: as above.
        unsafe { ASN1_STRING_set0(ptr::null_mut(), ptr::null_mut(), 3) };
        // SAFETY: as above.
        unsafe { ASN1_STRING_length_set(ptr::null_mut(), 3) };
        // SAFETY: no preconditions.
        let s = unsafe { ASN1_STRING_new() };
        // SAFETY: NULL sorts first.
        assert_eq!(unsafe { ASN1_STRING_cmp(ptr::null(), s) }, -1);
        // SAFETY: a live string.
        assert_eq!(unsafe { ASN1_STRING_set(s, c"abc".as_ptr().cast(), 3) }, 1);
        // SAFETY: as above; a negative length clears nothing.
        unsafe { ASN1_STRING_length_set(s, -5) };
        // SAFETY: the string, freed.
        unsafe { ASN1_STRING_clear_free(s) };
    }
}
