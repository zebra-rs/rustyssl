//! Fuzzes the base64 filter (`BIO_f_base64`) through the C ABI: arbitrary octets written in
//! chunks (with or without newlines) and flushed must read back through the filter unchanged,
//! and arbitrary text read through it in chunks must decode or fail without going out of bounds
//! (ASan).

#![no_main]

use core::ffi::{c_int, c_long, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn BIO_s_mem() -> *const c_void;
    fn BIO_f_base64() -> *const c_void;
    fn BIO_new(method: *const c_void) -> *mut c_void;
    fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> *mut c_void;
    fn BIO_push(b: *mut c_void, next: *mut c_void) -> *mut c_void;
    fn BIO_free_all(b: *mut c_void);
    fn BIO_write(b: *mut c_void, data: *const c_void, len: c_int) -> c_int;
    fn BIO_read(b: *mut c_void, data: *mut c_void, len: c_int) -> c_int;
    fn BIO_ctrl(b: *mut c_void, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    fn BIO_set_flags(b: *mut c_void, flags: c_int);
    fn ERR_clear_error();
}

const BIO_CTRL_FLUSH: c_int = 11;
const BIO_CTRL_INFO: c_int = 3;
const BIO_FLAGS_BASE64_NO_NL: c_int = 0x100;

/// Reads everything through a base64 filter over `text`, in chunks of `chunk`.
fn read_all(text: &[u8], chunk: usize, flags: c_int) -> Vec<u8> {
    let copy = text.to_vec().into_boxed_slice();
    // SAFETY: `copy` outlives the BIOs; built-in methods.
    let b64 = unsafe {
        let mem = BIO_new_mem_buf(copy.as_ptr().cast(), c_int::try_from(copy.len()).unwrap());
        let b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, flags);
        BIO_push(b64, mem)
    };
    let mut out = Vec::new();
    loop {
        let mut buf = vec![0u8; chunk].into_boxed_slice();
        // SAFETY: `buf` has room for `chunk` octets.
        let r = unsafe { BIO_read(b64, buf.as_mut_ptr().cast(), c_int::try_from(chunk).unwrap()) };
        if r <= 0 || out.len() > 1 << 20 {
            break;
        }
        out.extend_from_slice(&buf[..usize::try_from(r).unwrap()]);
    }
    // SAFETY: the chain made above.
    unsafe { BIO_free_all(b64) };
    out
}

fuzz_target!(|input: &[u8]| {
    let Some((&first, data)) = input.split_first() else {
        return;
    };
    let chunk = usize::from(first & 0x3f) + 1;
    let flags = if first & 0x40 != 0 { BIO_FLAGS_BASE64_NO_NL } else { 0 };
    // SAFETY: built-in methods; the chain is freed below.
    let (b64, mem) = unsafe {
        let mem = BIO_new(BIO_s_mem());
        let b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, flags);
        (BIO_push(b64, mem), mem)
    };
    for piece in data.chunks(chunk) {
        // SAFETY: `piece` holds its length.
        let w = unsafe { BIO_write(b64, piece.as_ptr().cast(), c_int::try_from(piece.len()).unwrap()) };
        assert_eq!(usize::try_from(w).unwrap(), piece.len());
    }
    // SAFETY: a live chain; the memory BIO's data pointer is read into a local.
    let text = unsafe {
        assert_eq!(BIO_ctrl(b64, BIO_CTRL_FLUSH, 0, ptr::null_mut()), 1);
        let mut p: *mut u8 = ptr::null_mut();
        let n = BIO_ctrl(mem, BIO_CTRL_INFO, 0, (&raw mut p).cast());
        let text = if n > 0 { std::slice::from_raw_parts(p, usize::try_from(n).unwrap()).to_vec() } else { Vec::new() };
        BIO_free_all(b64);
        text
    };
    assert_eq!(read_all(&text, chunk, flags), data, "what is written reads back");
    let _ = read_all(data, chunk, flags);
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
