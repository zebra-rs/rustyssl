//! Fuzzes `ASN1_parse` and `ASN1_parse_dump` (the `asn1parse` listing) on arbitrary input of
//! exactly its claimed size (so a read past it is an ASan error), with the indent and dump
//! settings taken from the first octet: any nesting, lengths, and tags must list or fail, and
//! never read beyond the input.

#![no_main]

use core::ffi::{c_int, c_long, c_uchar, c_void};

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{BIO, BIO_METHOD};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_new(method: *const BIO_METHOD) -> *mut BIO;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn BIO_ctrl(b: *mut BIO, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    fn ASN1_parse(bp: *mut BIO, pp: *const c_uchar, len: c_long, indent: c_int) -> c_int;
    fn ASN1_parse_dump(bp: *mut BIO, pp: *const c_uchar, len: c_long, indent: c_int, dump: c_int) -> c_int;
    fn ERR_clear_error();
}

fuzz_target!(|data: &[u8]| {
    let Some((&settings, input)) = data.split_first() else {
        return;
    };
    let copy = input.to_vec().into_boxed_slice();
    let len = c_long::try_from(copy.len()).unwrap();
    let indent = c_int::from(settings & 1);
    let dump = match settings >> 1 & 3 {
        0 => -2,
        1 => -1,
        2 => 0,
        _ => c_int::from(settings >> 3),
    };
    // SAFETY: no preconditions.
    let bio = unsafe { BIO_new(BIO_s_mem()) };
    // SAFETY: a memory BIO; `copy` holds `len` octets.
    let r = unsafe {
        if dump == -2 {
            ASN1_parse(bio, copy.as_ptr(), len, indent)
        } else {
            ASN1_parse_dump(bio, copy.as_ptr(), len, indent, dump)
        }
    };
    assert!((0..=2).contains(&r));
    // SAFETY: the BIO made above; BIO_CTRL_RESET, then free.
    unsafe {
        BIO_ctrl(bio, 1, 0, core::ptr::null_mut());
        BIO_free(bio);
        ERR_clear_error();
    }
});
