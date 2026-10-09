//! Fuzzes ASN.1 headers and OBJECT IDENTIFIER elements through the C ABI, and the element
//! reader in `rustyssl-asn1`. `ASN1_get_object` reads arbitrary input of exactly its claimed
//! size (so a read past it is an ASan error); a header it accepts must come back the same after
//! `ASN1_put_object` writes it again. `d2i_ASN1_OBJECT` on arbitrary input must give an object
//! whose `i2d_ASN1_OBJECT` encoding decodes to the same object. The element reader must never
//! panic and stay within its input.

#![no_main]

use core::ffi::{c_int, c_long, c_uchar};
use core::ptr;

use libfuzzer_sys::fuzz_target;
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

#[repr(C)]
struct AsnObject {
    _opaque: [u8; 0],
}

unsafe extern "C" {
    fn ASN1_get_object(pp: *mut *const c_uchar, plength: *mut c_long, ptag: *mut c_int, pclass: *mut c_int, omax: c_long) -> c_int;
    fn ASN1_put_object(pp: *mut *mut c_uchar, constructed: c_int, length: c_int, tag: c_int, xclass: c_int);
    fn ASN1_object_size(constructed: c_int, length: c_int, tag: c_int) -> c_int;
    fn d2i_ASN1_OBJECT(a: *mut *mut AsnObject, pp: *mut *const c_uchar, length: c_long) -> *mut AsnObject;
    fn i2d_ASN1_OBJECT(a: *const AsnObject, pp: *mut *mut c_uchar) -> c_int;
    fn OBJ_cmp(a: *const AsnObject, b: *const AsnObject) -> c_int;
    fn OBJ_obj2nid(a: *const AsnObject) -> c_int;
    fn OBJ_nid2obj(n: c_int) -> *mut AsnObject;
    fn ASN1_OBJECT_free(a: *mut AsnObject);
    fn ERR_clear_error();
}

struct Read {
    ret: c_int,
    length: c_long,
    tag: c_int,
    class: c_int,
    used: usize,
}

fn read(input: &[u8]) -> Read {
    // An exact-size copy, so a read past it is caught.
    let copy = input.to_vec().into_boxed_slice();
    let mut p = copy.as_ptr();
    let (mut length, mut tag, mut class) = (0, 0, 0);
    let omax = c_long::try_from(copy.len()).unwrap();
    // SAFETY: `copy` holds `omax` octets; the outputs are locals.
    let ret = unsafe { ASN1_get_object(&mut p, &mut length, &mut tag, &mut class, omax) };
    Read { ret, length, tag, class, used: p as usize - copy.as_ptr() as usize }
}

fn free_unshared(object: *mut AsnObject) {
    // SAFETY: a live object (or NULL); shared ones are left alone.
    unsafe {
        if !object.is_null() && object != OBJ_nid2obj(OBJ_obj2nid(object)) {
            ASN1_OBJECT_free(object);
        }
    }
}

fuzz_target!(|input: &[u8]| {
    let r = read(input);
    if r.ret & 0x81 == 0
        && let Ok(length) = c_int::try_from(r.length)
    {
        let constructed = c_int::from(r.ret & 0x20 != 0);
        // SAFETY: no preconditions.
        let size = unsafe { ASN1_object_size(constructed, length, r.tag) };
        if size > 0 {
            let mut buf = vec![0u8; 64];
            let mut p = buf.as_mut_ptr();
            // SAFETY: a header is at most 64 octets.
            unsafe { ASN1_put_object(&mut p, constructed, length, r.tag, r.class) };
            let written = p as usize - buf.as_ptr() as usize;
            assert!(written <= r.used, "the shortest form is no longer than what was read");
            buf.truncate(written);
            buf.extend(std::iter::repeat_n(0, usize::try_from(length).unwrap()));
            let again = read(&buf);
            assert_eq!((again.ret, again.length, again.tag, again.class, again.used), (r.ret, r.length, r.tag, r.class, written));
            assert!(rustyssl_asn1::der::is_der(&buf));
        }
    }

    let copy = input.to_vec().into_boxed_slice();
    let mut p = copy.as_ptr();
    let len = c_long::try_from(copy.len()).unwrap();
    // SAFETY: `copy` holds `len` octets.
    let object = unsafe { d2i_ASN1_OBJECT(ptr::null_mut(), &mut p, len) };
    if !object.is_null() {
        let mut der = vec![0u8; copy.len() + 16];
        let mut q = der.as_mut_ptr();
        // SAFETY: room for the encoding, which is no longer than its source plus a header.
        let n = unsafe { i2d_ASN1_OBJECT(object, &mut q) };
        assert!(n > 0);
        der.truncate(usize::try_from(n).unwrap());
        let mut r = der.as_ptr();
        // SAFETY: `der` holds `n` octets.
        let back = unsafe { d2i_ASN1_OBJECT(ptr::null_mut(), &mut r, c_long::from(n)) };
        assert!(!back.is_null());
        // SAFETY: live objects.
        assert_eq!(unsafe { OBJ_cmp(object, back) }, 0);
        free_unshared(back);
    }
    free_unshared(object);

    if let Ok(element) = rustyssl_asn1::der::element(input) {
        assert!(element.raw.len() <= input.len() && element.content.len() <= element.raw.len());
    }
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
