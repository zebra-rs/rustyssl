//! Fuzzes `a2i_ASN1_INTEGER` and `a2i_ASN1_STRING`, which parse hex text from a BIO, through the
//! C ABI: arbitrary
//! text, with an arbitrary line buffer size, must never read or write outside the buffer (an
//! exact-size allocation, so ASan catches it), and a value it parses that fits on one line of
//! `i2a_ASN1_INTEGER` (35 octets) must parse back to the same octets from that line.

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

#[repr(C)]
struct AsnString {
    length: c_int,
    type_: c_int,
    data: *mut u8,
    flags: c_long,
}

#[repr(C)]
struct Bio {
    _opaque: [u8; 0],
}

unsafe extern "C" {
    fn BIO_s_mem() -> *const c_void;
    fn BIO_new(method: *const c_void) -> *mut Bio;
    fn BIO_write(b: *mut Bio, data: *const c_void, len: c_int) -> c_int;
    fn BIO_free(b: *mut Bio) -> c_int;
    fn BIO_ctrl(b: *mut Bio, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    fn ASN1_INTEGER_new() -> *mut AsnString;
    fn ASN1_INTEGER_free(a: *mut AsnString);
    fn a2i_ASN1_INTEGER(bp: *mut Bio, bs: *mut AsnString, buf: *mut c_char, size: c_int) -> c_int;
    fn a2i_ASN1_STRING(bp: *mut Bio, bs: *mut AsnString, buf: *mut c_char, size: c_int) -> c_int;
    fn i2a_ASN1_INTEGER(bp: *mut Bio, a: *const AsnString) -> c_int;
    fn ERR_clear_error();
}

/// `BIO_CTRL_INFO`: the memory BIO's data.
const BIO_CTRL_INFO: c_int = 3;

/// Parses `text` with a line buffer of `size` octets; the octets on success.
fn parse(text: &[u8], size: usize) -> Option<Vec<u8>> {
    parse_with(text, size, a2i_ASN1_INTEGER)
}

/// The function `parse` uses.
type A2i = unsafe extern "C" fn(*mut Bio, *mut AsnString, *mut c_char, c_int) -> c_int;

/// `parse` with `a2i`.
fn parse_with(text: &[u8], size: usize, a2i: A2i) -> Option<Vec<u8>> {
    // SAFETY: the memory method; the BIO is freed below.
    let bio = unsafe { BIO_new(BIO_s_mem()) };
    // SAFETY: `text` holds its length.
    unsafe { BIO_write(bio, text.as_ptr().cast(), c_int::try_from(text.len()).unwrap()) };
    // SAFETY: no preconditions.
    let a = unsafe { ASN1_INTEGER_new() };
    // At least one octet: BIO_gets writes a NUL even for size 0, in OpenSSL too.
    let mut buf = vec![0u8; size.max(1)].into_boxed_slice();
    // SAFETY: `buf` holds `size` octets.
    let ok = unsafe { a2i(bio, a, buf.as_mut_ptr().cast(), c_int::try_from(size).unwrap()) };
    // SAFETY: a live string.
    let result = (ok == 1).then(|| unsafe {
        let s = &*a;
        if s.data.is_null() { Vec::new() } else { std::slice::from_raw_parts(s.data, usize::try_from(s.length).unwrap()).to_vec() }
    });
    // SAFETY: made above.
    unsafe {
        ASN1_INTEGER_free(a);
        BIO_free(bio);
    }
    result
}

fuzz_target!(|input: &[u8]| {
    let Some((&size, text)) = input.split_first() else {
        return;
    };
    // a2i_ASN1_STRING reads the same lines, cut differently; it must stay within them too.
    let _ = parse_with(text, usize::from(size), a2i_ASN1_STRING);
    let Some(octets) = parse(text, usize::from(size)) else {
        // SAFETY: no preconditions.
        unsafe { ERR_clear_error() };
        return;
    };
    if octets.is_empty() || octets.len() > 35 {
        return;
    }
    // Print it with i2a_ASN1_INTEGER and read it back.
    // SAFETY: the memory method; freed below.
    let out = unsafe { BIO_new(BIO_s_mem()) };
    // SAFETY: no preconditions.
    let a = unsafe { ASN1_INTEGER_new() };
    // SAFETY: a live string, given the octets.
    unsafe {
        let data = libc_malloc(octets.len());
        ptr::copy_nonoverlapping(octets.as_ptr(), data, octets.len());
        (*a).data = data;
        (*a).length = c_int::try_from(octets.len()).unwrap();
        i2a_ASN1_INTEGER(out, a);
    }
    let mut printed: *mut c_char = ptr::null_mut();
    // SAFETY: a memory BIO's data.
    let n = unsafe { BIO_ctrl(out, BIO_CTRL_INFO, 0, (&raw mut printed).cast()) };
    // SAFETY: as above.
    let mut line = unsafe { std::slice::from_raw_parts(printed.cast::<u8>(), usize::try_from(n).unwrap()) }.to_vec();
    line.push(b'\n');
    let back = parse(&line, 256).expect("i2a output parses");
    // A leading 00 is dropped on reading, as OpenSSL does.
    let expected = if octets.first() == Some(&0) { &octets[1..] } else { &octets[..] };
    assert_eq!(back, expected);
    // SAFETY: made above.
    unsafe {
        ASN1_INTEGER_free(a);
        BIO_free(out);
        ERR_clear_error();
    }
});

/// Memory `ASN1_INTEGER_free` can free: `OPENSSL_malloc`'s.
unsafe fn libc_malloc(size: usize) -> *mut u8 {
    unsafe extern "C" {
        fn CRYPTO_malloc(num: usize, file: *const c_char, line: c_int) -> *mut c_void;
    }
    // SAFETY: no preconditions.
    unsafe { CRYPTO_malloc(size, c"fuzz".as_ptr(), 0) }.cast()
}
