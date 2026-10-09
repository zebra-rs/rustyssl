//! Times (`ASN1_TIME_set(3)`, `ASN1_TIME_to_tm`, `ASN1_TIME_diff`, `ASN1_TIME_print_ex`,
//! `ASN1_TIME_set_string_X509`, `ASN1_UTCTIME_*`, `ASN1_GENERALIZEDTIME_*`, and the
//! `OPENSSL_gmtime*` family), over `rustyssl_asn1::time`, which documents what OpenSSL accepts.
//!
//! Times are `ASN1_STRING`s typed UTCTIME or GENERALIZEDTIME. Functions that take a NULL
//! `ASN1_TIME` where OpenSSL means "now" (`ASN1_TIME_to_tm`, so `ASN1_TIME_diff` and
//! `ASN1_TIME_compare` too) read the clock, as there.

use core::ffi::{CStr, c_char, c_int, c_long, c_ulong};
use core::ptr;

use libc::{time_t, tm};
use rustyssl_abi::{
    ASN1_DTFLGS_ISO8601, ASN1_DTFLGS_RFC822, ASN1_DTFLGS_TYPE_MASK, ASN1_GENERALIZEDTIME,
    ASN1_R_ERROR_GETTING_TIME, ASN1_STRING, ASN1_STRING_FLAG_X509_TIME, ASN1_TIME, ASN1_UTCTIME,
    BIO, ERR_LIB_ASN1, V_ASN1_GENERALIZEDTIME, V_ASN1_OCTET_STRING, V_ASN1_UNDEF, V_ASN1_UTCTIME,
};
use rustyssl_asn1::time::{self as core_time, Kind, Tm};

use super::string;
use crate::bio::print::{Arg, printf};
use crate::err;
use crate::ffi::ffi_export;

/// The fields OpenSSL uses of a C `struct tm`.
fn from_c(t: &tm) -> Tm {
    Tm {
        sec: t.tm_sec,
        min: t.tm_min,
        hour: t.tm_hour,
        mday: t.tm_mday,
        mon: t.tm_mon,
        year: t.tm_year,
        wday: t.tm_wday,
        yday: t.tm_yday,
    }
}

/// A C `struct tm` with these fields and the rest zero, as OpenSSL's parser fills one.
fn to_c(t: &Tm) -> tm {
    // SAFETY: `struct tm` is plain data; all zeros (a NULL zone pointer) is valid.
    let mut out: tm = unsafe { core::mem::zeroed() };
    out.tm_sec = t.sec;
    out.tm_min = t.min;
    out.tm_hour = t.hour;
    out.tm_mday = t.mday;
    out.tm_mon = t.mon;
    out.tm_year = t.year;
    out.tm_wday = t.wday;
    out.tm_yday = t.yday;
    out
}

/// `gmtime_r`.
fn gmtime(t: time_t) -> Option<tm> {
    // SAFETY: `struct tm` is plain data.
    let mut out: tm = unsafe { core::mem::zeroed() };
    // SAFETY: valid pointers to locals.
    let result = unsafe { libc::gmtime_r(&raw const t, &raw mut out) };
    (!result.is_null()).then_some(out)
}

/// The kind of a string typed UTCTIME or GENERALIZEDTIME.
fn kind_of(type_: c_int) -> Option<Kind> {
    match type_ {
        V_ASN1_UTCTIME => Some(Kind::Utc),
        V_ASN1_GENERALIZEDTIME => Some(Kind::Generalized),
        _ => None,
    }
}

/// `ossl_asn1_time_to_tm`: the time `d` holds (with the offset applied only when `fill`).
///
/// # Safety
/// `d` is a live string whose data holds its length.
unsafe fn time_to_tm(d: *const ASN1_STRING, fill: bool) -> Option<Tm> {
    // SAFETY: the caller's guarantee.
    let string = unsafe { &*d };
    let kind = kind_of(string.type_)?;
    let strict = string.flags & c_long::from(ASN1_STRING_FLAG_X509_TIME) != 0;
    let data: &[u8] = match usize::try_from(string.length) {
        // SAFETY: the caller's guarantee.
        Ok(n) if !string.data.is_null() => unsafe { core::slice::from_raw_parts(string.data, n) },
        _ => &[],
    };
    core_time::parse(data, kind, strict, fill)
}

/// `ASN1_TIME_to_tm`: the time `s` holds, or the current time for NULL.
///
/// # Safety
/// `s` is NULL or a live string.
unsafe fn to_tm_or_now(s: *const ASN1_STRING) -> Option<Tm> {
    if s.is_null() {
        // SAFETY: NULL asks only for the result.
        let now = unsafe { libc::time(ptr::null_mut()) };
        return gmtime(now).map(|t| from_c(&t));
    }
    // SAFETY: the caller's guarantee.
    unsafe { time_to_tm(s, true) }
}

/// `ossl_asn1_time_from_tm`: `ts` written into `s` (or a new string) as `type` (UTCTIME,
/// GENERALIZEDTIME, or for `V_ASN1_UNDEF` UTCTIME when the year allows), or NULL.
///
/// # Safety
/// `s` is NULL or a live string.
unsafe fn time_from_tm(s: *mut ASN1_STRING, ts: &Tm, type_: c_int) -> *mut ASN1_STRING {
    let kind = match type_ {
        V_ASN1_UNDEF if core_time::is_utc(ts.year) => Kind::Utc,
        V_ASN1_UNDEF | V_ASN1_GENERALIZEDTIME => Kind::Generalized,
        V_ASN1_UTCTIME if core_time::is_utc(ts.year) => Kind::Utc,
        _ => return ptr::null_mut(),
    };
    let target = if s.is_null() {
        string::type_new(V_ASN1_OCTET_STRING)
    } else {
        s
    };
    if target.is_null() {
        return ptr::null_mut();
    }
    let fail = move || {
        if target != s {
            // SAFETY: the string made here.
            unsafe { string::ASN1_STRING_free(target) };
        }
        ptr::null_mut()
    };
    // SAFETY: a live string; NULL data only sizes it (20 octets and a NUL).
    if unsafe { string::set(target, ptr::null(), 20) } == 0 {
        return fail();
    }
    // SAFETY: as above.
    let string = unsafe { &mut *target };
    string.type_ = if kind == Kind::Utc {
        V_ASN1_UTCTIME
    } else {
        V_ASN1_GENERALIZEDTIME
    };
    if ts.mon > c_int::MAX - 1 || (kind == Kind::Generalized && ts.year > c_int::MAX - 1900) {
        return fail();
    }
    let (text, length) = core_time::format(ts, kind);
    // SAFETY: the buffer holds 21 octets; the text is at most 19, then a NUL.
    unsafe { ptr::copy_nonoverlapping(text.as_ptr(), string.data, text.len()) };
    // SAFETY: as above.
    unsafe { string.data.wrapping_add(text.len()).write(0) };
    string.length = length;
    target
}

/// `ASN1_TIME_adj` and the typed `_adj` functions: `t` moved by the offsets, written as `type`.
///
/// # Safety
/// `s` is NULL or a live string.
unsafe fn adj(
    s: *mut ASN1_STRING,
    t: time_t,
    offset_day: c_int,
    offset_sec: c_long,
    type_: c_int,
    raise: bool,
) -> *mut ASN1_STRING {
    let Some(now) = gmtime(t) else {
        if raise {
            err::raise(ERR_LIB_ASN1, ASN1_R_ERROR_GETTING_TIME, "ASN1_TIME_adj");
        }
        return ptr::null_mut();
    };
    let mut ts = from_c(&now);
    if (offset_day != 0 || offset_sec != 0)
        && !core_time::gmtime_adj(&mut ts, offset_day, offset_sec)
    {
        return ptr::null_mut();
    }
    // SAFETY: the caller's guarantee.
    unsafe { time_from_tm(s, &ts, type_) }
}

ffi_export! {
    /// The UTC broken-down time of `*timer` into `*result`; returns `result`, or NULL.
    ///
    /// Unlike OpenSSL, NULL pointers return NULL rather than crashing (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `timer` is NULL or valid for a read; `result` is NULL or valid for a write.
    pub unsafe extern "C" fn OPENSSL_gmtime(timer: *const time_t, result: *mut tm) -> *mut tm
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        if timer.is_null() || result.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let Some(t) = gmtime(unsafe { timer.read() }) else {
            return ptr::null_mut();
        };
        // SAFETY: as above.
        unsafe { result.write(t) };
        result
    }
}

ffi_export! {
    /// Moves `*tm` by `off_day` days and `offset_sec` seconds (its date and time fields only).
    /// Returns 1, or 0 for a result outside the years 1900 to 9999.
    ///
    /// # Safety
    /// `tm` is NULL or a valid `struct tm`.
    pub unsafe extern "C" fn OPENSSL_gmtime_adj(tm: *mut tm, off_day: c_int, offset_sec: c_long) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        if tm.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let target = unsafe { &mut *tm };
        let mut t = from_c(target);
        if !core_time::gmtime_adj(&mut t, off_day, offset_sec) {
            return 0;
        }
        target.tm_year = t.year;
        target.tm_mon = t.mon;
        target.tm_mday = t.mday;
        target.tm_hour = t.hour;
        target.tm_min = t.min;
        target.tm_sec = t.sec;
        1
    }
}

ffi_export! {
    /// The days (into `*pday`) and seconds (into `*psec`, both of one sign) from `from` to
    /// `to`. Returns 1, or 0 for a date before Julian day 0.
    ///
    /// # Safety
    /// `pday` and `psec` are NULL or valid for writes; `from` and `to` are NULL or valid.
    pub unsafe extern "C" fn OPENSSL_gmtime_diff(pday: *mut c_int, psec: *mut c_int, from: *const tm, to: *const tm) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        if from.is_null() || to.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let (from, to) = (from_c(unsafe { &*from }), from_c(unsafe { &*to }));
        let Some((days, secs)) = core_time::gmtime_diff(&from, &to) else {
            return 0;
        };
        if !pday.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { pday.write(days) };
        }
        if !psec.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { psec.write(secs) };
        }
        1
    }
}

/// Checks `s` as `type` (1 if it parses, else 0).
///
/// # Safety
/// `s` is NULL or a live string.
unsafe fn check_as(s: *const ASN1_STRING, type_: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    if s.is_null() || unsafe { (*s).type_ } != type_ {
        return 0;
    }
    // SAFETY: as above.
    c_int::from(unsafe { time_to_tm(s, false) }.is_some())
}

ffi_export! {
    /// Whether `t` is a valid UTCTIME or GENERALIZEDTIME.
    ///
    /// Unlike OpenSSL, NULL is 0 rather than a crash (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `t` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_TIME_check(t: *const ASN1_TIME) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        if t.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let type_ = unsafe { (*t).type_ };
        // SAFETY: as above.
        unsafe { check_as(t, type_) }
    }
}

ffi_export! {
    /// Whether `d` is a valid UTCTIME.
    ///
    /// # Safety
    /// `d` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_UTCTIME_check(d: *const ASN1_UTCTIME) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { check_as(d, V_ASN1_UTCTIME) }
    }
}

ffi_export! {
    /// Whether `d` is a valid GENERALIZEDTIME.
    ///
    /// # Safety
    /// `d` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_GENERALIZEDTIME_check(d: *const ASN1_GENERALIZEDTIME) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { check_as(d, V_ASN1_GENERALIZEDTIME) }
    }
}

ffi_export! {
    /// `t` moved by `offset_day` days and `offset_sec` seconds, into `s` (or a new string) as a
    /// UTCTIME if the year allows, else a GENERALIZEDTIME. NULL on failure
    /// (`ASN1_R_ERROR_GETTING_TIME` if `t` has no UTC time).
    ///
    /// # Safety
    /// `s` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_TIME_adj(s: *mut ASN1_TIME, t: time_t, offset_day: c_int, offset_sec: c_long) -> *mut ASN1_TIME
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { adj(s, t, offset_day, offset_sec, V_ASN1_UNDEF, true) }
    }
}

ffi_export! {
    /// `ASN1_TIME_adj` without offsets.
    ///
    /// # Safety
    /// As for `ASN1_TIME_adj`.
    pub unsafe extern "C" fn ASN1_TIME_set(s: *mut ASN1_TIME, t: time_t) -> *mut ASN1_TIME
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { adj(s, t, 0, 0, V_ASN1_UNDEF, true) }
    }
}

ffi_export! {
    /// `ASN1_TIME_adj` as a UTCTIME (NULL if the year can't be one).
    ///
    /// # Safety
    /// As for `ASN1_TIME_adj`.
    pub unsafe extern "C" fn ASN1_UTCTIME_adj(s: *mut ASN1_UTCTIME, t: time_t, offset_day: c_int, offset_sec: c_long) -> *mut ASN1_UTCTIME
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { adj(s, t, offset_day, offset_sec, V_ASN1_UTCTIME, false) }
    }
}

ffi_export! {
    /// `ASN1_UTCTIME_adj` without offsets.
    ///
    /// # Safety
    /// As for `ASN1_TIME_adj`.
    pub unsafe extern "C" fn ASN1_UTCTIME_set(s: *mut ASN1_UTCTIME, t: time_t) -> *mut ASN1_UTCTIME
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { adj(s, t, 0, 0, V_ASN1_UTCTIME, false) }
    }
}

ffi_export! {
    /// `ASN1_TIME_adj` as a GENERALIZEDTIME.
    ///
    /// # Safety
    /// As for `ASN1_TIME_adj`.
    pub unsafe extern "C" fn ASN1_GENERALIZEDTIME_adj(s: *mut ASN1_GENERALIZEDTIME, t: time_t, offset_day: c_int, offset_sec: c_long) -> *mut ASN1_GENERALIZEDTIME
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { adj(s, t, offset_day, offset_sec, V_ASN1_GENERALIZEDTIME, false) }
    }
}

ffi_export! {
    /// `ASN1_GENERALIZEDTIME_adj` without offsets.
    ///
    /// # Safety
    /// As for `ASN1_TIME_adj`.
    pub unsafe extern "C" fn ASN1_GENERALIZEDTIME_set(s: *mut ASN1_GENERALIZEDTIME, t: time_t) -> *mut ASN1_GENERALIZEDTIME
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { adj(s, t, 0, 0, V_ASN1_GENERALIZEDTIME, false) }
    }
}

/// A string on the stack holding `str` as `type_` with `flags` (the data borrowed).
fn borrowed(text: &CStr, type_: c_int, flags: c_long) -> Option<ASN1_STRING> {
    Some(ASN1_STRING {
        length: c_int::try_from(text.to_bytes().len()).ok()?,
        type_,
        data: text.as_ptr().cast_mut().cast(),
        flags,
    })
}

/// The typed `_set_string`: `str` checked as `type_`, then copied into `s` if not NULL.
///
/// # Safety
/// `s` is NULL or a live string; `str` is NULL or a NUL-terminated string.
unsafe fn set_string_as(s: *mut ASN1_STRING, str: *const c_char, type_: c_int) -> c_int {
    if str.is_null() {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let Some(t) = borrowed(unsafe { CStr::from_ptr(str) }, type_, 0) else {
        return 0;
    };
    // SAFETY: a live string on the stack.
    if unsafe { check_as(&raw const t, type_) } == 0 {
        return 0;
    }
    // SAFETY: the caller's guarantee about `s`; `t` is live.
    if !s.is_null() && unsafe { string::copy(s, &raw const t) } == 0 {
        return 0;
    }
    1
}

ffi_export! {
    /// Sets `s` (if not NULL) to the UTCTIME `str` if it is a valid one. Returns 1 or 0.
    ///
    /// Unlike OpenSSL, NULL `str` returns 0 rather than crashing (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `s` is NULL or a live string; `str` is NULL or a NUL-terminated string.
    pub unsafe extern "C" fn ASN1_UTCTIME_set_string(s: *mut ASN1_UTCTIME, str: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_string_as(s, str, V_ASN1_UTCTIME) }
    }
}

ffi_export! {
    /// Sets `s` (if not NULL) to the GENERALIZEDTIME `str` if it is a valid one.
    ///
    /// # Safety
    /// As for `ASN1_UTCTIME_set_string`.
    pub unsafe extern "C" fn ASN1_GENERALIZEDTIME_set_string(s: *mut ASN1_GENERALIZEDTIME, str: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_string_as(s, str, V_ASN1_GENERALIZEDTIME) }
    }
}

ffi_export! {
    /// `ASN1_UTCTIME_set_string`, else `ASN1_GENERALIZEDTIME_set_string`.
    ///
    /// # Safety
    /// As for `ASN1_UTCTIME_set_string`.
    pub unsafe extern "C" fn ASN1_TIME_set_string(s: *mut ASN1_TIME, str: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        if unsafe { set_string_as(s, str, V_ASN1_UTCTIME) } == 1 {
            return 1;
        }
        // SAFETY: as above.
        unsafe { set_string_as(s, str, V_ASN1_GENERALIZEDTIME) }
    }
}

ffi_export! {
    /// Sets `s` (if not NULL) to `str` in RFC 5280's form: a UTCTIME or GENERALIZEDTIME with
    /// seconds, `Z`, and no fraction; a GENERALIZEDTIME for 1950 to 2049 becomes a UTCTIME. The
    /// result carries `ASN1_STRING_FLAG_X509_TIME`, as in OpenSSL. Returns 1 or 0.
    ///
    /// # Safety
    /// As for `ASN1_UTCTIME_set_string`.
    pub unsafe extern "C" fn ASN1_TIME_set_string_X509(s: *mut ASN1_TIME, str: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        if str.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let text = unsafe { CStr::from_ptr(str) };
        let flags = c_long::from(ASN1_STRING_FLAG_X509_TIME);
        let Some(mut t) = borrowed(text, V_ASN1_UTCTIME, flags) else {
            return 0;
        };
        // SAFETY: a live string on the stack.
        if unsafe { check_as(&raw const t, V_ASN1_UTCTIME) } == 0 {
            t.type_ = V_ASN1_GENERALIZEDTIME;
            // SAFETY: as above.
            if unsafe { check_as(&raw const t, V_ASN1_GENERALIZEDTIME) } == 0 {
                return 0;
            }
        }
        let mut narrowed: Vec<u8> = Vec::new();
        if !s.is_null() && t.type_ == V_ASN1_GENERALIZEDTIME {
            // SAFETY: as above.
            let Some(parsed) = (unsafe { time_to_tm(&raw const t, true) }) else {
                return 0;
            };
            if core_time::is_utc(parsed.year) {
                narrowed.extend_from_slice(text.to_bytes().get(2..).unwrap_or(&[]));
                narrowed.push(0);
                t.length = t.length.saturating_sub(2);
                t.data = narrowed.as_mut_ptr();
                t.type_ = V_ASN1_UTCTIME;
            }
        }
        // SAFETY: the caller's guarantee about `s`; `t` and its data are live.
        if s.is_null() || unsafe { string::copy(s, &raw const t) } != 0 {
            return 1;
        }
        0
    }
}

ffi_export! {
    /// The time `s` holds into `*tm` (the fields OpenSSL fills, the rest zero), or for NULL `s`
    /// the current time. Returns 1, or 0 if `s` isn't a valid time.
    ///
    /// Unlike OpenSSL, NULL `tm` returns 0 rather than crashing (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `s` is NULL or a live string; `tm` is NULL or valid for a write.
    pub unsafe extern "C" fn ASN1_TIME_to_tm(s: *const ASN1_TIME, tm: *mut tm) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        if tm.is_null() {
            return 0;
        }
        if s.is_null() {
            // SAFETY: NULL asks only for the result.
            let now = unsafe { libc::time(ptr::null_mut()) };
            let Some(t) = gmtime(now) else {
                return 0;
            };
            // SAFETY: the caller's guarantee.
            unsafe { tm.write(t) };
            return 1;
        }
        // SAFETY: the caller's guarantee.
        match unsafe { time_to_tm(s, true) } {
            Some(t) => {
                // SAFETY: as above.
                unsafe { tm.write(to_c(&t)) };
                1
            }
            None => 0,
        }
    }
}

ffi_export! {
    /// The time `t` holds (or now, for NULL) as a GENERALIZEDTIME, into `*out` (reused if not
    /// NULL) or a new string. NULL if `t` isn't a valid time.
    ///
    /// # Safety
    /// `t` is NULL or a live string; `out` is NULL or points to NULL or a live string.
    pub unsafe extern "C" fn ASN1_TIME_to_generalizedtime(t: *const ASN1_TIME, out: *mut *mut ASN1_GENERALIZEDTIME) -> *mut ASN1_GENERALIZEDTIME
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let Some(parsed) = (unsafe { to_tm_or_now(t) }) else {
            return ptr::null_mut();
        };
        // SAFETY: as above.
        let existing = if out.is_null() { ptr::null_mut() } else { unsafe { *out } };
        // SAFETY: as above.
        let result = unsafe { time_from_tm(existing, &parsed, V_ASN1_GENERALIZEDTIME) };
        if !out.is_null() && !result.is_null() {
            // SAFETY: as above.
            unsafe { *out = result };
        }
        result
    }
}

ffi_export! {
    /// The days and seconds (into `*pday` and `*psec`, either NULL) from `from` to `to` (NULL
    /// for now). Returns 1, or 0 if either isn't a valid time.
    ///
    /// # Safety
    /// `pday` and `psec` are NULL or valid for writes; `from` and `to` are NULL or live strings.
    pub unsafe extern "C" fn ASN1_TIME_diff(pday: *mut c_int, psec: *mut c_int, from: *const ASN1_TIME, to: *const ASN1_TIME) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let Some(from) = (unsafe { to_tm_or_now(from) }) else {
            return 0;
        };
        // SAFETY: as above.
        let Some(to) = (unsafe { to_tm_or_now(to) }) else {
            return 0;
        };
        let Some((days, secs)) = core_time::gmtime_diff(&from, &to) else {
            return 0;
        };
        if !pday.is_null() {
            // SAFETY: as above.
            unsafe { pday.write(days) };
        }
        if !psec.is_null() {
            // SAFETY: as above.
            unsafe { psec.write(secs) };
        }
        1
    }
}

/// The sign of a difference in days and seconds.
fn sign(days: c_int, secs: c_int) -> c_int {
    if days > 0 || secs > 0 {
        1
    } else if days < 0 || secs < 0 {
        -1
    } else {
        0
    }
}

ffi_export! {
    /// -1, 0, or 1 as `a` is before, at, or after `b` (NULL for now); -2 if either is invalid.
    ///
    /// # Safety
    /// `a` and `b` are NULL or live strings.
    pub unsafe extern "C" fn ASN1_TIME_compare(a: *const ASN1_TIME, b: *const ASN1_TIME) -> c_int
    where failure = -2, library = ERR_LIB_ASN1
    {
        let (mut days, mut secs) = (0, 0);
        // SAFETY: the caller's guarantee; the outputs are locals.
        if unsafe { ASN1_TIME_diff(&raw mut days, &raw mut secs, b, a) } == 0 {
            return -2;
        }
        sign(days, secs)
    }
}

/// `ASN1_TIME_cmp_time_t` and `ASN1_UTCTIME_cmp_time_t` once `s` is parsed.
fn compare_time_t(parsed: Option<Tm>, t: time_t) -> c_int {
    let Some(stm) = parsed else {
        return -2;
    };
    let Some(ttm) = gmtime(t) else {
        return -2;
    };
    match core_time::gmtime_diff(&from_c(&ttm), &stm) {
        Some((days, secs)) => sign(days, secs),
        None => -2,
    }
}

ffi_export! {
    /// -1, 0, or 1 as `s` (NULL for now) is before, at, or after `t`; -2 if it is invalid.
    ///
    /// # Safety
    /// `s` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_TIME_cmp_time_t(s: *const ASN1_TIME, t: time_t) -> c_int
    where failure = -2, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        compare_time_t(unsafe { to_tm_or_now(s) }, t)
    }
}

ffi_export! {
    /// `ASN1_TIME_cmp_time_t` for a UTCTIME (-2 for another type).
    ///
    /// Unlike OpenSSL, NULL `s` is -2 rather than a crash (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `s` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_UTCTIME_cmp_time_t(s: *const ASN1_UTCTIME, t: time_t) -> c_int
    where failure = -2, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        if s.is_null() || unsafe { (*s).type_ } != V_ASN1_UTCTIME {
            return -2;
        }
        // SAFETY: as above.
        compare_time_t(unsafe { time_to_tm(s, true) }, t)
    }
}

ffi_export! {
    /// Rewrites `t` in its normal form: a UTCTIME for 1950 to 2049, else a GENERALIZEDTIME,
    /// with seconds, `Z`, no fraction, and any offset folded in. Returns 1 or 0.
    ///
    /// # Safety
    /// `t` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_TIME_normalize(t: *mut ASN1_TIME) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        if t.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(parsed) = (unsafe { time_to_tm(t, true) }) else {
            return 0;
        };
        // SAFETY: as above.
        c_int::from(!unsafe { time_from_tm(t, &parsed, V_ASN1_UNDEF) }.is_null())
    }
}

const MONTHS: [&CStr; 12] = [
    c"Jan", c"Feb", c"Mar", c"Apr", c"May", c"Jun", c"Jul", c"Aug", c"Sep", c"Oct", c"Nov", c"Dec",
];

/// `ossl_asn1_time_print_ex`: positive if printed.
///
/// # Safety
/// `bp` is NULL or a live BIO; `tm` is a live string.
unsafe fn print_time(bp: *mut BIO, tm: *const ASN1_STRING, flags: c_ulong) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(stm) = (unsafe { time_to_tm(tm, true) }) else {
        // SAFETY: as above.
        let wrote = unsafe { crate::bio::BIO_write(bp, c"Bad time value".as_ptr().cast(), 14) };
        return if wrote != 0 { -1 } else { 0 };
    };
    // SAFETY: as above.
    let string = unsafe { &*tm };
    let data: &[u8] = match usize::try_from(string.length) {
        // SAFETY: the string's data holds its length.
        Ok(n) if !string.data.is_null() => unsafe { core::slice::from_raw_parts(string.data, n) },
        _ => &[],
    };
    let iso = flags & ASN1_DTFLGS_TYPE_MASK == ASN1_DTFLGS_ISO8601;
    let month = MONTHS
        .get(usize::try_from(stm.mon).unwrap_or(0))
        .copied()
        .unwrap_or(c"Jan");
    let year = stm.year.wrapping_add(1900);
    let mut fraction: &[u8] = &[];
    if string.type_ == V_ASN1_GENERALIZEDTIME && data.len() > 15 && data.get(14) == Some(&b'.') {
        let digits = data.get(15..).unwrap_or(&[]);
        let n = digits.iter().take_while(|c| c.is_ascii_digit()).count();
        fraction = digits.get(..n).unwrap_or(&[]);
    }
    let printed = if !fraction.is_empty() {
        let fraction_len = Arg::Int(c_int::try_from(fraction.len()).unwrap_or(0));
        let fraction_ptr = Arg::Pointer(fraction.as_ptr().cast());
        if iso {
            // SAFETY: the caller's guarantee about `bp`; the arguments match the format.
            unsafe {
                printf(
                    bp,
                    c"%4d-%02d-%02d %02d:%02d:%02d.%.*sZ",
                    &[
                        Arg::Int(year),
                        Arg::Int(stm.mon.wrapping_add(1)),
                        Arg::Int(stm.mday),
                        Arg::Int(stm.hour),
                        Arg::Int(stm.min),
                        Arg::Int(stm.sec),
                        fraction_len,
                        fraction_ptr,
                    ],
                )
            }
        } else {
            // SAFETY: as above.
            unsafe {
                printf(
                    bp,
                    c"%s %2d %02d:%02d:%02d.%.*s %d GMT",
                    &[
                        Arg::Pointer(month.as_ptr().cast()),
                        Arg::Int(stm.mday),
                        Arg::Int(stm.hour),
                        Arg::Int(stm.min),
                        Arg::Int(stm.sec),
                        fraction_len,
                        fraction_ptr,
                        Arg::Int(year),
                    ],
                )
            }
        }
    } else if iso {
        // SAFETY: as above.
        unsafe {
            printf(
                bp,
                c"%4d-%02d-%02d %02d:%02d:%02dZ",
                &[
                    Arg::Int(year),
                    Arg::Int(stm.mon.wrapping_add(1)),
                    Arg::Int(stm.mday),
                    Arg::Int(stm.hour),
                    Arg::Int(stm.min),
                    Arg::Int(stm.sec),
                ],
            )
        }
    } else {
        // SAFETY: as above.
        unsafe {
            printf(
                bp,
                c"%s %2d %02d:%02d:%02d %d GMT",
                &[
                    Arg::Pointer(month.as_ptr().cast()),
                    Arg::Int(stm.mday),
                    Arg::Int(stm.hour),
                    Arg::Int(stm.min),
                    Arg::Int(stm.sec),
                    Arg::Int(year),
                ],
            )
        }
    };
    c_int::from(printed > 0)
}

ffi_export! {
    /// Prints `tm` to `bp`: `Mon DD HH:MM:SS[.fff] YYYY GMT` (`ASN1_DTFLGS_RFC822`) or
    /// `YYYY-MM-DD HH:MM:SS[.fff]Z` (`ASN1_DTFLGS_ISO8601`); `Bad time value` for an invalid
    /// time. Returns 1 if a time was printed, else 0.
    ///
    /// Unlike OpenSSL, NULL `tm` returns 0 rather than crashing (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `bp` is NULL or a live BIO; `tm` is NULL or a live string.
    pub unsafe extern "C" fn ASN1_TIME_print_ex(bp: *mut BIO, tm: *const ASN1_TIME, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        if tm.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { print_time(bp, tm, flags) } > 0)
    }
}

ffi_export! {
    /// `ASN1_TIME_print_ex` with `ASN1_DTFLGS_RFC822`.
    ///
    /// # Safety
    /// As for `ASN1_TIME_print_ex`.
    pub unsafe extern "C" fn ASN1_TIME_print(bp: *mut BIO, tm: *const ASN1_TIME) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_TIME_print_ex(bp, tm, ASN1_DTFLGS_RFC822) }
    }
}

ffi_export! {
    /// `ASN1_TIME_print` for a UTCTIME (0 for another type).
    ///
    /// # Safety
    /// As for `ASN1_TIME_print_ex`.
    pub unsafe extern "C" fn ASN1_UTCTIME_print(bp: *mut BIO, tm: *const ASN1_UTCTIME) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        if tm.is_null() || unsafe { (*tm).type_ } != V_ASN1_UTCTIME {
            return 0;
        }
        // SAFETY: as above.
        unsafe { ASN1_TIME_print(bp, tm) }
    }
}

ffi_export! {
    /// `ASN1_TIME_print` for a GENERALIZEDTIME (0 for another type).
    ///
    /// # Safety
    /// As for `ASN1_TIME_print_ex`.
    pub unsafe extern "C" fn ASN1_GENERALIZEDTIME_print(bp: *mut BIO, tm: *const ASN1_GENERALIZEDTIME) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        if tm.is_null() || unsafe { (*tm).type_ } != V_ASN1_GENERALIZEDTIME {
            return 0;
        }
        // SAFETY: as above.
        unsafe { ASN1_TIME_print(bp, tm) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_arguments_are_safe() {
        // SAFETY: NULL pointers are refused.
        let gm = unsafe { OPENSSL_gmtime(ptr::null(), ptr::null_mut()) };
        assert!(gm.is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { OPENSSL_gmtime_adj(ptr::null_mut(), 1, 0) }, 0);
        // SAFETY: as above.
        let diff = unsafe {
            OPENSSL_gmtime_diff(ptr::null_mut(), ptr::null_mut(), ptr::null(), ptr::null())
        };
        assert_eq!(diff, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { ASN1_TIME_check(ptr::null()) }, 0);
        // SAFETY: as above.
        let result = unsafe { ASN1_TIME_set_string(ptr::null_mut(), ptr::null()) };
        assert_eq!(result, 0);
        // SAFETY: as above.
        let result = unsafe { ASN1_TIME_set_string_X509(ptr::null_mut(), ptr::null()) };
        assert_eq!(result, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { ASN1_TIME_to_tm(ptr::null(), ptr::null_mut()) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { ASN1_UTCTIME_cmp_time_t(ptr::null(), 0) }, -2);
        // SAFETY: as above.
        let result = unsafe { ASN1_TIME_print_ex(ptr::null_mut(), ptr::null(), 0) };
        assert_eq!(result, 0);
        // SAFETY: as above.
        let result = unsafe { ASN1_UTCTIME_print(ptr::null_mut(), ptr::null()) };
        assert_eq!(result, 0);
    }
}
