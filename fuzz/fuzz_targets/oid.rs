//! Fuzzes the OID text and content parsers through their C ABI. Arbitrary text through
//! `a2d_ASN1_OBJECT` (and `OBJ_txt2obj`, which also looks names up) must give content that
//! `OBJ_obj2txt` prints back as text encoding to the same octets; arbitrary content octets
//! through `OBJ_obj2txt` must fail exactly when OpenSSL's rules say (too long, or ending inside a
//! subidentifier), and otherwise round-trip unless a subidentifier has a leading 0x80 (which
//! has no canonical text).

#![no_main]

use core::ffi::{c_char, c_int, c_uchar};
use core::ptr;
use std::ffi::{CStr, CString};

use libfuzzer_sys::fuzz_target;
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

#[repr(C)]
struct AsnObject {
    _opaque: [u8; 0],
}

unsafe extern "C" {
    fn a2d_ASN1_OBJECT(out: *mut c_uchar, olen: c_int, buf: *const c_char, num: c_int) -> c_int;
    fn OBJ_txt2obj(s: *const c_char, no_name: c_int) -> *mut AsnObject;
    fn OBJ_obj2txt(buf: *mut c_char, buf_len: c_int, a: *const AsnObject, no_name: c_int) -> c_int;
    fn ASN1_OBJECT_create(
        nid: c_int,
        data: *mut c_uchar,
        len: c_int,
        sn: *const c_char,
        ln: *const c_char,
    ) -> *mut AsnObject;
    fn ASN1_OBJECT_free(a: *mut AsnObject);
    fn ERR_clear_error();
}

/// `a2d_ASN1_OBJECT` of `text` (to its NUL), measured and encoded, which must agree.
fn encode(text: &CStr) -> Option<Vec<u8>> {
    let mut out = vec![0u8; text.to_bytes().len() + 16];
    let size = c_int::try_from(out.len()).ok()?;
    // SAFETY: a NUL-terminated string; only measuring.
    let measured = unsafe { a2d_ASN1_OBJECT(ptr::null_mut(), 0, text.as_ptr(), -1) };
    // SAFETY: `out` has `size` bytes.
    let n = unsafe { a2d_ASN1_OBJECT(out.as_mut_ptr(), size, text.as_ptr(), -1) };
    assert_eq!(measured, n, "measuring and encoding disagree");
    out.truncate(usize::try_from(n).ok()?);
    (n > 0).then_some(out)
}

/// `OBJ_obj2txt` (numbers only) of an object with `content`: the result and the text.
fn text_of(content: &[u8]) -> (c_int, CString) {
    let mut data = content.to_vec();
    let len = c_int::try_from(data.len()).unwrap();
    // SAFETY: `data` holds `len` bytes; no names.
    let object = unsafe { ASN1_OBJECT_create(0, data.as_mut_ptr(), len, ptr::null(), ptr::null()) };
    assert!(!object.is_null() || content.is_empty());
    let mut buf = vec![0u8; 8192];
    // SAFETY: `buf` has room; the object is live (or NULL).
    let n = unsafe { OBJ_obj2txt(buf.as_mut_ptr().cast(), 8192, object, 1) };
    // SAFETY: made above.
    unsafe { ASN1_OBJECT_free(object) };
    let end = buf.iter().position(|&b| b == 0).unwrap();
    buf.truncate(end);
    (n, CString::new(buf).unwrap())
}

fuzz_target!(|input: &[u8]| {
    let (&selector, data) = input.split_first().unwrap_or((&0, &[]));
    if selector & 1 == 0 {
        let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        let text = CString::new(&data[..end]).unwrap();
        if let Some(octets) = encode(&text) {
            let (n, printed) = text_of(&octets);
            if octets.len() > 586 {
                assert_eq!(n, -1, "OBJ_obj2txt prints only RFC 2578's lengths");
            } else {
                assert!(n > 0, "content from text doesn't print: {octets:02x?}");
                assert_eq!(encode(&printed).as_deref(), Some(octets.as_slice()), "{printed:?}");
            }
        }
        // SAFETY: a NUL-terminated string.
        let object = unsafe { OBJ_txt2obj(text.as_ptr(), c_int::from(selector & 2 != 0)) };
        // SAFETY: freed only if it was made for this call.
        unsafe { ASN1_OBJECT_free(object) };
    } else {
        let (n, printed) = text_of(data);
        let fails = data.len() > 586 || data.last().is_some_and(|&b| b & 0x80 != 0);
        if data.is_empty() {
            assert_eq!(n, 0);
        } else if fails {
            assert_eq!(n, -1);
        } else {
            assert_eq!(usize::try_from(n).ok(), Some(printed.as_bytes().len()));
            let canonical = data
                .iter()
                .enumerate()
                .all(|(i, &b)| b != 0x80 || (i > 0 && data[i - 1] & 0x80 != 0));
            if canonical {
                assert_eq!(encode(&printed).as_deref(), Some(data), "{printed:?}");
            }
        }
    }
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
