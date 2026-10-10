//! Fuzzes PEM framing through the C ABI: arbitrary text read block by block with
//! `PEM_read_bio_ex` and each flag must parse or fail without going out of bounds (ASan), and
//! arbitrary octets written with `PEM_write_bio` must read back unchanged, name and all. Each
//! block's header is read as encryption (`PEM_get_EVP_CIPHER_INFO`) and, naming a cipher, its
//! body decrypted in place (`PEM_do_header`), which must stay within it.

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn BIO_s_mem() -> *const c_void;
    fn BIO_new(method: *const c_void) -> *mut c_void;
    fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> *mut c_void;
    fn BIO_free(b: *mut c_void) -> c_int;
    fn PEM_read_bio_ex(bp: *mut c_void, name: *mut *mut c_char, header: *mut *mut c_char, data: *mut *mut c_uchar, len: *mut c_long, flags: c_uint) -> c_int;
    fn PEM_write_bio(bp: *mut c_void, name: *const c_char, header: *const c_char, data: *const c_uchar, len: c_long) -> c_int;
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
    fn ERR_clear_error();
    fn PEM_get_EVP_CIPHER_INFO(header: *mut c_char, cipher: *mut CipherInfo) -> c_int;
    fn PEM_do_header(cipher: *mut CipherInfo, data: *mut c_uchar, plen: *mut c_long, cb: *const c_void, u: *const c_void) -> c_int;
}

/// `EVP_CIPHER_INFO`.
#[repr(C)]
struct CipherInfo {
    cipher: *const c_void,
    iv: [u8; 16],
}

/// Reads every block from `bio`: (name, header, data) of each.
fn read_blocks(bio: *mut c_void, flags: c_uint) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut blocks = Vec::new();
    loop {
        let (mut name, mut header, mut data, mut len) = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), 0);
        // SAFETY: a live BIO; the outputs are locals.
        let r = unsafe { PEM_read_bio_ex(bio, &mut name, &mut header, &mut data, &mut len, flags) };
        if r != 1 {
            break;
        }
        let mut info = CipherInfo { cipher: ptr::null(), iv: [0; 16] };
        // SAFETY: the header the call allocated (a string), and a local.
        if unsafe { PEM_get_EVP_CIPHER_INFO(header, &mut info) } == 1 && !info.cipher.is_null() {
            let before = len;
            // SAFETY: the body of `len` octets, decrypted in place under a password string.
            unsafe { PEM_do_header(&mut info, data, &mut len, ptr::null(), c"pw".as_ptr().cast()) };
            assert!(len <= before);
        }
        // SAFETY: the strings and data the call allocated, freed after copying.
        unsafe {
            let n = std::ffi::CStr::from_ptr(name).to_bytes().to_vec();
            let h = std::ffi::CStr::from_ptr(header).to_bytes().to_vec();
            let d = std::slice::from_raw_parts(data, usize::try_from(len).unwrap()).to_vec();
            CRYPTO_free(name.cast(), ptr::null(), 0);
            CRYPTO_free(header.cast(), ptr::null(), 0);
            CRYPTO_free(data.cast(), ptr::null(), 0);
            blocks.push((n, h, d));
        }
    }
    blocks
}

fuzz_target!(|input: &[u8]| {
    let Some((&first, text)) = input.split_first() else {
        return;
    };
    let flags: c_uint = match first % 3 {
        0 => 0,
        1 => 2,
        _ => 4,
    };
    let copy = text.to_vec().into_boxed_slice();
    // SAFETY: `copy` outlives the BIO.
    let bio = unsafe { BIO_new_mem_buf(copy.as_ptr().cast(), c_int::try_from(copy.len()).unwrap()) };
    let _ = read_blocks(bio, flags);
    // SAFETY: made above.
    unsafe { BIO_free(bio) };

    // A name of letters and spaces from the first octets, the rest as data.
    let name: Vec<u8> = text.iter().take(8).map(|b| if b % 5 == 0 { b' ' } else { b'A' + b % 26 }).collect();
    let mut cname = name.clone();
    cname.push(0);
    // SAFETY: the memory method.
    let mem = unsafe { BIO_new(BIO_s_mem()) };
    // SAFETY: a live BIO; a NUL-terminated name; `text` holds its length.
    let w = unsafe { PEM_write_bio(mem, cname.as_ptr().cast(), ptr::null(), text.as_ptr(), c_long::try_from(text.len()).unwrap()) };
    let blocks = read_blocks(mem, 2);
    if !text.is_empty() {
        assert!(w > 0);
        assert_eq!(blocks, vec![(name, Vec::new(), text.to_vec())], "what is written reads back");
    }
    // SAFETY: made above; no preconditions.
    unsafe {
        BIO_free(mem);
        ERR_clear_error();
    }
});
