//! Fuzzes S/MIME's MIME handling on untrusted input: the input's headers parsed and its body
//! taken (`SMIME_text`), and the input copied with its line ends made canonical
//! (`SMIME_crlf_copy`, with flags from the first octet). The copy, read back, must hold no bare
//! LF in text mode. Nothing may crash or read out of bounds (ASan).

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{
    BIO, BIO_CTRL_INFO, BIO_METHOD, CMS_BINARY, SMIME_ASCIICRLF, SMIME_BINARY, SMIME_CRLFEOL,
    SMIME_TEXT,
};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn SMIME_text(in_: *mut BIO, out: *mut BIO) -> c_int;
    fn SMIME_crlf_copy(in_: *mut BIO, out: *mut BIO, flags: c_int) -> c_int;
    fn BIO_new(m: *const BIO_METHOD) -> *mut BIO;
    fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> *mut BIO;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_ctrl(b: *mut BIO, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn ERR_clear_error();
}

fn contents(b: *mut BIO) -> Vec<u8> {
    let mut p: *mut c_char = ptr::null_mut();
    // SAFETY: a live memory BIO; room for the pointer.
    let n = unsafe { BIO_ctrl(b, BIO_CTRL_INFO, 0, (&raw mut p).cast()) };
    match usize::try_from(n) {
        // SAFETY: the BIO's `n` octets.
        Ok(n) if n > 0 => unsafe { core::slice::from_raw_parts(p.cast::<u8>(), n) }.to_vec(),
        _ => Vec::new(),
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&first, body)) = data.split_first() else {
        return;
    };
    let Ok(len) = c_int::try_from(body.len()) else {
        return;
    };
    let choices = [SMIME_BINARY, SMIME_TEXT, SMIME_ASCIICRLF, CMS_BINARY, SMIME_CRLFEOL];
    let flags = choices
        .iter()
        .enumerate()
        .filter(|(i, _)| first & (1 << i) != 0)
        .fold(0, |f, (_, &c)| f | c);
    // SAFETY: the built-in method.
    let out = unsafe { BIO_new(BIO_s_mem()) };
    // SAFETY: the input's octets, outliving the BIO.
    let src = unsafe { BIO_new_mem_buf(body.as_ptr().cast(), len) };
    // SAFETY: live BIOs.
    unsafe { SMIME_text(src, out) };
    // SAFETY: as above.
    unsafe { BIO_free(src) };
    // SAFETY: as above.
    unsafe { BIO_free(out) };

    // SAFETY: the built-in method.
    let out = unsafe { BIO_new(BIO_s_mem()) };
    // SAFETY: as above.
    let src = unsafe { BIO_new_mem_buf(body.as_ptr().cast(), len) };
    // SAFETY: live BIOs.
    let ok = unsafe { SMIME_crlf_copy(src, out, flags) };
    if ok == 1 && flags & (SMIME_BINARY | CMS_BINARY) == 0 {
        let copy = contents(out);
        for (i, &c) in copy.iter().enumerate() {
            if c == b'\n' {
                assert!(i > 0 && copy[i - 1] == b'\r', "a bare LF in text mode");
            }
        }
    }
    // SAFETY: as above.
    unsafe { BIO_free(src) };
    // SAFETY: as above.
    unsafe { BIO_free(out) };
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
