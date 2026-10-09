//! Fuzzes the property parser (`property(7)`): arbitrary text as a definition and as a query,
//! in the safe core and through `EVP_set_default_properties`/`EVP_get1_default_properties`. A
//! parse must never panic; a query matched against a definition counts at most its own
//! properties; a merge keeps names sorted and unique; and the C API accepts exactly the queries
//! that parse and have canonical text, and reads that text back.

#![no_main]

use core::ffi::{c_char, c_int, c_void};
use std::ffi::{CStr, CString};

use libfuzzer_sys::fuzz_target;
use rustyssl_crypto::property::{self, Strings};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn OSSL_LIB_CTX_new() -> *mut c_void;
    fn OSSL_LIB_CTX_free(ctx: *mut c_void);
    fn EVP_set_default_properties(ctx: *mut c_void, propq: *const c_char) -> c_int;
    fn EVP_get1_default_properties(ctx: *mut c_void) -> *mut c_char;
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
    fn ERR_clear_error();
}

fuzz_target!(|data: &[u8]| {
    // The text up to a NUL is the query; what follows (to the next NUL) the definition.
    let mut parts = data.split(|&b| b == 0);
    let query = parts.next().unwrap_or_default();
    let defn = parts.next().unwrap_or_default();

    let mut strings = Strings::new();
    let d = property::parse_definition(&mut strings, defn);
    let q = property::parse_query(&mut strings, query, data.len() % 2 == 0);
    let _ = q.list.as_ref().map(|l| property::to_text(&strings, Some(l)));
    if let (Some(d), Some(q)) = (&d.list, &q.list) {
        let n = property::match_count(q, d);
        assert!(n >= -1 && usize::try_from(n).map_or(true, |n| n <= q.properties.len()));
        let merged = property::merge(q, d);
        assert!(merged.properties.windows(2).all(|w| w[0].name < w[1].name || (w[0].name == 0 && w[1].name == 0)));
        let _ = property::to_text(&strings, Some(&merged));
        let _ = property::is_enabled(&mut strings, b"fips", Some(&merged));
    }

    let c = CString::new(query).unwrap();
    // SAFETY: no preconditions; freed below.
    let ctx = unsafe { OSSL_LIB_CTX_new() };
    // SAFETY: a live context and a string.
    let r = unsafe { EVP_set_default_properties(ctx, c.as_ptr()) };
    // SAFETY: a live context.
    let got = unsafe { EVP_get1_default_properties(ctx) };
    assert!(!got.is_null());
    // SAFETY: a string from the library.
    let got_text = unsafe { CStr::from_ptr(got) }.to_bytes().to_vec();
    // A fresh context numbers names as fresh core strings do: the C API accepts exactly the
    // queries that parse and have canonical text, and reads that text back.
    let mut fresh = Strings::new();
    let list = property::parse_query(&mut fresh, query, true).list;
    let expected = list.as_ref().and_then(|l| property::to_text(&fresh, Some(l)));
    assert_eq!(r == 1, expected.is_some());
    assert_eq!(got_text, expected.unwrap_or_default());
    // SAFETY: from the library's allocator.
    unsafe { CRYPTO_free(got.cast(), c"".as_ptr(), 0) };
    // SAFETY: made above.
    unsafe { OSSL_LIB_CTX_free(ctx) };
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
