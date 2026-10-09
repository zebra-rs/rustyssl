//! Fuzzes reading elements from a BIO (`asn1_d2i_read_bio` behind `ASN1_item_d2i_bio`):
//! arbitrary input in a memory BIO, read as ANY until a read fails. Each element read must
//! decode the same as decoding the input directly at that point, and the reads must stay within
//! the input (ASan), however its headers, lengths, and end-of-contents octets are arranged.

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{ASN1_ITEM, ASN1_VALUE, BIO};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> *mut BIO;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn ASN1_item_d2i_bio(it: *const ASN1_ITEM, input: *mut BIO, x: *mut c_void) -> *mut c_void;
    fn ASN1_item_d2i(pval: *mut *mut ASN1_VALUE, input: *mut *const c_uchar, len: c_long, it: *const ASN1_ITEM) -> *mut ASN1_VALUE;
    fn ASN1_item_i2d(val: *const ASN1_VALUE, out: *mut *mut c_uchar, it: *const ASN1_ITEM) -> c_int;
    fn ASN1_item_free(val: *mut ASN1_VALUE, it: *const ASN1_ITEM);
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
    fn ERR_clear_error();
    fn ASN1_ANY_it() -> *const ASN1_ITEM;
}

/// The encoding of `value`, or `None`.
fn encode(value: *mut ASN1_VALUE, it: *const ASN1_ITEM) -> Option<Vec<u8>> {
    let mut der: *mut c_uchar = ptr::null_mut();
    // SAFETY: a live value of the item.
    let n = unsafe { ASN1_item_i2d(value, &mut der, it) };
    if n <= 0 {
        return None;
    }
    // SAFETY: the buffer holds `n` octets.
    let out = unsafe { core::slice::from_raw_parts(der, usize::try_from(n).unwrap()) }.to_vec();
    // SAFETY: a buffer from the allocator.
    unsafe { CRYPTO_free(der.cast(), ptr::null(), 0) };
    Some(out)
}

fuzz_target!(|input: &[u8]| {
    // SAFETY: no preconditions.
    let it = unsafe { ASN1_ANY_it() };
    let copy = input.to_vec().into_boxed_slice();
    let len = c_int::try_from(copy.len()).unwrap();
    // SAFETY: `copy` holds `len` octets and outlives the BIO.
    let bio = unsafe { BIO_new_mem_buf(copy.as_ptr().cast(), len) };
    assert!(!bio.is_null());
    let mut direct = copy.as_ptr();
    let end = copy.as_ptr() as usize + copy.len();
    for _ in 0..=copy.len() {
        // SAFETY: a live BIO.
        let value: *mut ASN1_VALUE = unsafe { ASN1_item_d2i_bio(it, bio, ptr::null_mut()) }.cast();
        if value.is_null() {
            break;
        }
        // The element came from where direct decoding stands, and decodes the same there.
        let rest = c_long::try_from(end - direct as usize).unwrap();
        // SAFETY: `direct` lies within `copy`, `rest` octets before its end.
        let same = unsafe { ASN1_item_d2i(ptr::null_mut(), &mut direct, rest, it) };
        assert!(!same.is_null(), "an element read from the BIO decodes in place");
        assert_eq!(encode(value, it), encode(same, it));
        // SAFETY: values of the item.
        unsafe {
            ASN1_item_free(value, it);
            ASN1_item_free(same, it);
        }
    }
    // SAFETY: the BIO made above; no preconditions.
    unsafe {
        BIO_free(bio);
        ERR_clear_error();
    }
});
