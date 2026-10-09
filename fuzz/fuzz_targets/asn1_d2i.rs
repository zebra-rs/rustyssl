//! Fuzzes the template engine's decoder through the C ABI: arbitrary input (DER or BER, of
//! exactly its claimed size, so a read past it is an ASan error) decoded with a universal item
//! or with an application-style SEQUENCE defined here as C would define it (OPTIONAL, EXPLICIT
//! and IMPLICIT fields, SET OF ANY, a DirectoryString, and itself, nested). A value that decodes
//! must encode, and an encoding that decodes must encode the same again; it must also print.

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::mem::offset_of;
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{
    ASN1_ITEM, ASN1_ITYPE_SEQUENCE, ASN1_TEMPLATE, ASN1_TFLG_CONTEXT, ASN1_TFLG_EXPTAG,
    ASN1_TFLG_IMPTAG, ASN1_TFLG_OPTIONAL, ASN1_TFLG_SEQUENCE_OF, ASN1_TFLG_SET_OF, ASN1_VALUE,
    BIO, BIO_METHOD, V_ASN1_SEQUENCE,
};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn ASN1_item_d2i(pval: *mut *mut ASN1_VALUE, input: *mut *const c_uchar, len: c_long, it: *const ASN1_ITEM) -> *mut ASN1_VALUE;
    fn ASN1_item_i2d(val: *const ASN1_VALUE, out: *mut *mut c_uchar, it: *const ASN1_ITEM) -> c_int;
    fn ASN1_item_free(val: *mut ASN1_VALUE, it: *const ASN1_ITEM);
    fn ASN1_item_print(out: *mut BIO, val: *const ASN1_VALUE, indent: c_int, it: *const ASN1_ITEM, pctx: *const c_void) -> c_int;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_new(method: *const BIO_METHOD) -> *mut BIO;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
    fn ERR_clear_error();
    fn ASN1_ANY_it() -> *const ASN1_ITEM;
    fn ASN1_SEQUENCE_ANY_it() -> *const ASN1_ITEM;
    fn ASN1_SET_ANY_it() -> *const ASN1_ITEM;
    fn ASN1_OCTET_STRING_it() -> *const ASN1_ITEM;
    fn ASN1_INTEGER_it() -> *const ASN1_ITEM;
    fn ASN1_BIT_STRING_it() -> *const ASN1_ITEM;
    fn ASN1_IA5STRING_it() -> *const ASN1_ITEM;
    fn ASN1_BMPSTRING_it() -> *const ASN1_ITEM;
    fn ASN1_TIME_it() -> *const ASN1_ITEM;
    fn DIRECTORYSTRING_it() -> *const ASN1_ITEM;
    fn INT64_it() -> *const ASN1_ITEM;
    fn UINT32_it() -> *const ASN1_ITEM;
}

/// The application's structure.
#[repr(C)]
struct Record {
    version: *mut c_void,
    opt: *mut c_void,
    imp: *mut c_void,
    set: *mut c_void,
    seq: *mut c_void,
    dir: *mut c_void,
    inner: *mut c_void,
}

struct Templates([ASN1_TEMPLATE; 7]);
// SAFETY: immutable tables of pointers to static data.
unsafe impl Sync for Templates {}
struct Item(ASN1_ITEM);
// SAFETY: as above.
unsafe impl Sync for Item {}

const fn flags(f: c_int) -> c_ulong {
    f.cast_unsigned() as c_ulong
}

const fn field(f: c_int, tag: c_long, offset: usize, name: &'static core::ffi::CStr, item: unsafe extern "C" fn() -> *const ASN1_ITEM) -> ASN1_TEMPLATE {
    ASN1_TEMPLATE { flags: flags(f), tag, offset: offset as c_ulong, field_name: name.as_ptr(), item: Some(item) }
}

unsafe extern "C" fn record_it() -> *const ASN1_ITEM {
    &raw const RECORD.0
}

static RECORD_TT: Templates = Templates([
    field(0, 0, offset_of!(Record, version), c"version", ASN1_INTEGER_it),
    field(ASN1_TFLG_EXPTAG | ASN1_TFLG_CONTEXT | ASN1_TFLG_OPTIONAL, 0, offset_of!(Record, opt), c"opt", ASN1_OCTET_STRING_it),
    field(ASN1_TFLG_IMPTAG | ASN1_TFLG_CONTEXT | ASN1_TFLG_OPTIONAL, 1, offset_of!(Record, imp), c"imp", ASN1_IA5STRING_it),
    field(ASN1_TFLG_SET_OF, 0, offset_of!(Record, set), c"set", ASN1_ANY_it),
    field(ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL, 0, offset_of!(Record, seq), c"seq", ASN1_INTEGER_it),
    field(ASN1_TFLG_OPTIONAL, 0, offset_of!(Record, dir), c"dir", DIRECTORYSTRING_it),
    field(ASN1_TFLG_EXPTAG | ASN1_TFLG_CONTEXT | ASN1_TFLG_OPTIONAL, 2, offset_of!(Record, inner), c"inner", record_it),
]);

static RECORD: Item = Item(ASN1_ITEM {
    itype: ASN1_ITYPE_SEQUENCE as c_char,
    utype: V_ASN1_SEQUENCE as c_long,
    templates: &raw const RECORD_TT.0 as *const ASN1_TEMPLATE,
    tcount: 7,
    funcs: ptr::null(),
    size: size_of::<Record>() as c_long,
    sname: c"RECORD".as_ptr(),
});

/// Decodes `input` (copied to exactly its size) with `it`: the value and how much was read.
fn decode(input: &[u8], it: *const ASN1_ITEM) -> (*mut ASN1_VALUE, usize) {
    let copy = input.to_vec().into_boxed_slice();
    let mut p = copy.as_ptr();
    let len = c_long::try_from(copy.len()).unwrap();
    // SAFETY: `copy` holds `len` octets.
    let value = unsafe { ASN1_item_d2i(ptr::null_mut(), &mut p, len, it) };
    (value, p as usize - copy.as_ptr() as usize)
}

/// Encodes `value` into a new buffer.
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

fuzz_target!(|data: &[u8]| {
    let Some((&which, input)) = data.split_first() else {
        return;
    };
    // SAFETY: the item functions take no arguments.
    let it = unsafe {
        match which % 13 {
            0 => ASN1_ANY_it(),
            1 => ASN1_SEQUENCE_ANY_it(),
            2 => ASN1_SET_ANY_it(),
            3 => ASN1_OCTET_STRING_it(),
            4 => ASN1_INTEGER_it(),
            5 => ASN1_BIT_STRING_it(),
            6 => ASN1_BMPSTRING_it(),
            7 => ASN1_TIME_it(),
            8 => DIRECTORYSTRING_it(),
            9 => INT64_it(),
            10 => UINT32_it(),
            _ => record_it(),
        }
    };
    let (value, used) = decode(input, it);
    assert!(used <= input.len());
    if !value.is_null() {
        // Printing what was decoded must work or fail cleanly.
        // SAFETY: no preconditions; then a memory BIO and a value of the item.
        unsafe {
            let mem = BIO_new(BIO_s_mem());
            ASN1_item_print(mem, value, 0, it, ptr::null());
            BIO_free(mem);
        }
        // OpenSSL can write what it can't read back (an ANY of universal tag 0 is `00 00`, an
        // end-of-contents), so an encoding needn't decode; one that does must be read whole and
        // encode the same again.
        if let Some(der) = encode(value, it) {
            let (again, read) = decode(&der, it);
            if !again.is_null() {
                assert_eq!(read, der.len());
                assert_eq!(encode(again, it).as_deref(), Some(&der[..]), "an encoding is stable");
                // SAFETY: a value of the item.
                unsafe { ASN1_item_free(again, it) };
            }
        }
        // SAFETY: as above.
        unsafe { ASN1_item_free(value, it) };
    }
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
