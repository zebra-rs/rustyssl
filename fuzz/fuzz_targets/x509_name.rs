//! Fuzzes name decoding on untrusted input: d2i_X509_NAME, then everything that reads a name
//! decoded from it: the re-encoding, the one-line form (into a short buffer and a new one),
//! print_ex in each style, the hashes, and the comparison with a copy rebuilt entry by entry.
//! Nothing may crash or read out of bounds (ASan).

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{BIO, BIO_METHOD, X509_NAME, X509_NAME_ENTRY};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn d2i_X509_NAME(a: *mut *mut X509_NAME, pp: *mut *const c_uchar, len: c_long) -> *mut X509_NAME;
    fn i2d_X509_NAME(a: *const X509_NAME, out: *mut *mut c_uchar) -> c_int;
    fn X509_NAME_free(a: *mut X509_NAME);
    fn X509_NAME_new() -> *mut X509_NAME;
    fn X509_NAME_oneline(a: *const X509_NAME, buf: *mut c_char, len: c_int) -> *mut c_char;
    fn X509_NAME_print_ex(out: *mut BIO, nm: *const X509_NAME, indent: c_int, flags: c_ulong) -> c_int;
    fn X509_NAME_print(bp: *mut BIO, name: *const X509_NAME, obase: c_int) -> c_int;
    fn X509_NAME_hash_ex(x: *const X509_NAME, libctx: *mut c_void, propq: *const c_char, ok: *mut c_int) -> c_ulong;
    fn X509_NAME_hash_old(x: *const X509_NAME) -> c_ulong;
    fn X509_NAME_cmp(a: *const X509_NAME, b: *const X509_NAME) -> c_int;
    fn X509_NAME_entry_count(name: *const X509_NAME) -> c_int;
    fn X509_NAME_get_entry(name: *const X509_NAME, loc: c_int) -> *mut X509_NAME_ENTRY;
    fn X509_NAME_add_entry(name: *mut X509_NAME, ne: *const X509_NAME_ENTRY, loc: c_int, set: c_int) -> c_int;
    fn X509_NAME_delete_entry(name: *mut X509_NAME, loc: c_int) -> *mut X509_NAME_ENTRY;
    fn X509_NAME_ENTRY_free(e: *mut X509_NAME_ENTRY);
    fn BIO_new(m: *const BIO_METHOD) -> *mut BIO;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
    fn ERR_clear_error();
}

/// XN_FLAG_ONELINE, XN_FLAG_RFC2253, XN_FLAG_MULTILINE, and a few combinations.
const STYLES: [c_ulong; 6] = [0x82031f, 0x1172b17, 0x2a40006, 0x40000, 0x10000 | 0x200000 | 0x800000, 0x30000 | 0x1000000];

fuzz_target!(|data: &[u8]| {
    let Ok(len) = c_long::try_from(data.len()) else { return };
    // SAFETY: the input, read within its length; the names, BIOs, and strings made here, freed.
    unsafe {
        let mut p = data.as_ptr();
        let n = d2i_X509_NAME(ptr::null_mut(), &mut p, len);
        if n.is_null() {
            ERR_clear_error();
            return;
        }
        let mut der = ptr::null_mut();
        let l = i2d_X509_NAME(n, &mut der);
        if l > 0 {
            CRYPTO_free(der.cast(), c"".as_ptr(), 0);
        }
        let mut buf = [0 as c_char; 17];
        X509_NAME_oneline(n, buf.as_mut_ptr(), 17);
        let one = X509_NAME_oneline(n, ptr::null_mut(), 0);
        CRYPTO_free(one.cast(), c"".as_ptr(), 0);
        let bio = BIO_new(BIO_s_mem());
        for s in STYLES {
            X509_NAME_print_ex(bio, n, 3, s);
        }
        X509_NAME_print(bio, n, 0);
        BIO_free(bio);
        let mut ok = 0;
        X509_NAME_hash_ex(n, ptr::null_mut(), ptr::null(), &mut ok);
        X509_NAME_hash_old(n);
        let copy = X509_NAME_new();
        for i in 0..X509_NAME_entry_count(n) {
            X509_NAME_add_entry(copy, X509_NAME_get_entry(n, i), -1, if i % 2 == 0 { 0 } else { -1 });
        }
        X509_NAME_cmp(n, copy);
        let e = X509_NAME_delete_entry(copy, 0);
        X509_NAME_ENTRY_free(e);
        X509_NAME_cmp(copy, n);
        X509_NAME_free(copy);
        X509_NAME_free(n);
        ERR_clear_error();
    }
});
