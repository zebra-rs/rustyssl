//! PEM framing (`PEM_read_bio_ex(3)`, `PEM_read_bio`, `PEM_read`, `PEM_write_bio`,
//! `PEM_write`, `PEM_proc_type`, `PEM_dek_info`), as OpenSSL's `pem_lib.c` does it, over
//! `rustyssl_asn1::pem` and the base64 codec.
//!
//! The typed PEM functions come with their types; the encrypted forms (`Proc-Type` and
//! `DEK-Info` read back, `PEM_do_header`, `PEM_ASN1_write*`) are in `pem_cipher`.

use core::ffi::{CStr, c_char, c_int, c_long, c_uchar};
use core::ptr;

use libc::FILE;
use rustyssl_abi::{
    BIO, BIO_NOCLOSE, ERR_LIB_PEM, ERR_R_BIO_LIB, ERR_R_BUF_LIB, ERR_R_EVP_LIB,
    ERR_R_PASSED_INVALID_ARGUMENT, PEM_BUFSIZE, PEM_R_BAD_BASE64_DECODE, PEM_R_BAD_END_LINE,
    PEM_R_NO_START_LINE, PEM_TYPE_ENCRYPTED, PEM_TYPE_MIC_CLEAR, PEM_TYPE_MIC_ONLY,
};
use rustyssl_asn1::base64::Ctx;
use rustyssl_asn1::pem::{self, Body, Error, LINESIZE, Line};

use crate::bio;
use crate::bio::print::BIO_snprintf;
use crate::err;
use crate::ffi::ffi_export;
use crate::mem;
use crate::secure;

/// `PEM_MALLOC`: `num` octets, from the secure heap with `PEM_FLAG_SECURE`.
fn pem_malloc(num: usize, flags: u32) -> *mut u8 {
    if flags & pem::FLAG_SECURE != 0 {
        // SAFETY: no preconditions.
        unsafe { secure::CRYPTO_secure_malloc(num, ptr::null(), 0) }.cast()
    } else {
        mem::alloc(num).cast()
    }
}

/// `PEM_FREE`.
///
/// # Safety
/// `p` is NULL or a block from [`pem_malloc`] with the same `flags`.
unsafe fn pem_free(p: *mut u8, flags: u32, num: usize) {
    if flags & pem::FLAG_SECURE != 0 {
        // SAFETY: the caller's guarantee.
        unsafe { secure::CRYPTO_secure_clear_free(p.cast(), num, ptr::null(), 0) };
    } else {
        // SAFETY: as above.
        unsafe { mem::release(p.cast()) };
    }
}

/// A copy of `bytes` from [`pem_malloc`], with `extra` zero octets after; NULL if that fails
/// (as for 0 octets, which `CRYPTO_malloc` doesn't give).
fn pem_copy(bytes: &[u8], extra: usize, flags: u32) -> *mut u8 {
    let size = bytes.len().saturating_add(extra);
    let block = pem_malloc(size, flags);
    if !block.is_null() {
        // SAFETY: a new block of `size` octets.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), block, bytes.len()) };
        // SAFETY: as above.
        unsafe { ptr::write_bytes(block.wrapping_add(bytes.len()), 0, extra) };
    }
    block
}

/// Reads a line with `BIO_gets` into `line`: the count it returns.
///
/// # Safety
/// `bp` is NULL or a live BIO.
unsafe fn gets(bp: *mut BIO, line: &mut Line) -> c_int {
    let size = c_int::try_from(LINESIZE).unwrap_or(c_int::MAX);
    // SAFETY: the caller's BIO; `line` has room for `LINESIZE` octets.
    unsafe { bio::BIO_gets(bp, line.as_mut_ptr().cast(), size) }
}

/// Wipes a line buffer that held secret data.
fn wipe(line: &mut Line, flags: u32) {
    if flags & pem::FLAG_SECURE != 0 {
        line.fill(0);
    }
}

/// A PEM block's name (NUL included), header, and data.
type Parts = (Vec<u8>, Vec<u8>, Vec<u8>);

/// `get_name` and `get_header_and_data`, then the decoding: the name (as allocated, NUL
/// included), the header, and the data.
///
/// # Safety
/// `bp` is NULL or a live BIO.
unsafe fn read_pem(bp: *mut BIO, flags: u32) -> Result<Parts, Error> {
    let mut line: Line = [0; LINESIZE + 1];
    let mut first_call = true;
    let name = loop {
        // SAFETY: the caller's guarantee.
        let len = unsafe { gets(bp, &mut line) };
        let Ok(len) = usize::try_from(len) else {
            return Err(Error::NoStartLine);
        };
        if len == 0 {
            return Err(Error::NoStartLine);
        }
        let len = pem::sanitize_line(&mut line, len, flags & !pem::FLAG_ONLY_B64, first_call);
        first_call = false;
        if let Some(name) = pem::begin_name(&mut line, len) {
            break name;
        }
    };
    let mut body = Body::new(&name, flags);
    let result = loop {
        // SAFETY: as above.
        let len = unsafe { gets(bp, &mut line) };
        let len = match usize::try_from(len) {
            Ok(n) if n > 0 => n,
            _ => break Err(Error::BadEndLine),
        };
        match body.line(&mut line, len) {
            Ok(true) => break Ok(()),
            Ok(false) => {}
            Err(e) => break Err(e),
        }
    };
    wipe(&mut line, flags);
    result?;
    let (header, data) = body.finish()?;
    Ok((name, header, data))
}

ffi_export! {
    /// Reads the next PEM block from `bp` (skipping anything before a BEGIN line): its name,
    /// header, and decoded data, each allocated for the caller (from the secure heap with
    /// `PEM_FLAG_SECURE`), and the data's length. `flags` also takes
    /// `PEM_FLAG_EAY_COMPATIBLE` (trailing whitespace trimmed) or `PEM_FLAG_ONLY_B64` (data
    /// lines cut at their first non-base64 character), not both. Returns 1, or 0.
    ///
    /// Unlike OpenSSL, NULL output pointers return 0 rather than crashing
    /// (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `bp` is NULL or a live BIO; the output pointers are valid for writes.
    pub unsafe extern "C" fn PEM_read_bio_ex(bp: *mut BIO, name_out: *mut *mut c_char, header: *mut *mut c_char, data: *mut *mut c_uchar, len_out: *mut c_long, flags: core::ffi::c_uint) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        if name_out.is_null() || header.is_null() || data.is_null() || len_out.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee, for each output below.
        unsafe { len_out.write(0) };
        // SAFETY: as above.
        unsafe { name_out.write(ptr::null_mut()) };
        // SAFETY: as above.
        unsafe { header.write(ptr::null_mut()) };
        // SAFETY: as above.
        unsafe { data.write(ptr::null_mut()) };
        if flags & pem::FLAG_EAY_COMPATIBLE != 0 && flags & pem::FLAG_ONLY_B64 != 0 {
            err::raise(ERR_LIB_PEM, ERR_R_PASSED_INVALID_ARGUMENT, "PEM_read_bio_ex");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let (name, head, octets) = match unsafe { read_pem(bp, flags) } {
            Ok(parts) => parts,
            Err(e) => {
                let reason = match e {
                    Error::NoStartLine => Some(PEM_R_NO_START_LINE),
                    Error::BadEndLine => Some(PEM_R_BAD_END_LINE),
                    Error::BadBase64Decode => Some(PEM_R_BAD_BASE64_DECODE),
                    Error::Silent => None,
                };
                if let Some(reason) = reason {
                    err::raise(ERR_LIB_PEM, reason, "PEM_read_bio_ex");
                }
                return 0;
            }
        };
        let h = pem_copy(&head, 1, flags);
        let d = pem_copy(&octets, 0, flags);
        if h.is_null() || d.is_null() {
            // SAFETY: the blocks just made, or NULL.
            unsafe { pem_free(h, flags, 0) };
            // SAFETY: as above.
            unsafe { pem_free(d, flags, 0) };
            return 0;
        }
        let n = pem_copy(&name, 0, flags);
        if n.is_null() {
            // SAFETY: as above.
            unsafe { pem_free(h, flags, 0) };
            // SAFETY: as above.
            unsafe { pem_free(d, flags, 0) };
            return 0;
        }
        // SAFETY: the caller's guarantee, for each output below.
        unsafe { name_out.write(n.cast()) };
        // SAFETY: as above.
        unsafe { header.write(h.cast()) };
        // SAFETY: as above.
        unsafe { data.write(d) };
        // SAFETY: as above.
        unsafe { len_out.write(c_long::try_from(octets.len()).unwrap_or(c_long::MAX)) };
        1
    }
}

ffi_export! {
    /// `PEM_read_bio_ex` with `PEM_FLAG_EAY_COMPATIBLE`.
    ///
    /// # Safety
    /// As for `PEM_read_bio_ex`.
    pub unsafe extern "C" fn PEM_read_bio(bp: *mut BIO, name: *mut *mut c_char, header: *mut *mut c_char, data: *mut *mut c_uchar, len: *mut c_long) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        let flags = pem::FLAG_EAY_COMPATIBLE;
        // SAFETY: the caller's guarantee.
        unsafe { PEM_read_bio_ex(bp, name, header, data, len, flags) }
    }
}

/// A `FILE` BIO that leaves the stream open, or NULL after raising `ERR_R_BUF_LIB`.
///
/// # Safety
/// `fp` is an open `FILE`.
pub(crate) unsafe fn file_bio(fp: *mut FILE, function: &str) -> *mut BIO {
    // SAFETY: the caller's guarantee.
    let b = unsafe { bio::file::BIO_new_fp(fp, BIO_NOCLOSE) };
    if b.is_null() {
        err::raise(ERR_LIB_PEM, ERR_R_BUF_LIB, function);
    }
    b
}

ffi_export! {
    /// `PEM_read_bio` from a `FILE`, which is left open.
    ///
    /// # Safety
    /// As for `PEM_read_bio`, with `fp` an open `FILE`.
    pub unsafe extern "C" fn PEM_read(fp: *mut FILE, name: *mut *mut c_char, header: *mut *mut c_char, data: *mut *mut c_uchar, len: *mut c_long) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        let b = unsafe { file_bio(fp, "PEM_read") };
        if b.is_null() {
            return 0;
        }
        // SAFETY: as above.
        let ret = unsafe { PEM_read_bio(b, name, header, data, len) };
        // SAFETY: the BIO made above.
        unsafe { bio::BIO_free(b) };
        ret
    }
}

/// `BIO_write` of `data`: whether all of it was written.
///
/// # Safety
/// `bp` is NULL or a live BIO.
unsafe fn write_all(bp: *mut BIO, data: &[u8]) -> bool {
    let n = c_int::try_from(data.len()).unwrap_or(c_int::MAX);
    // SAFETY: the caller's BIO; `data` holds `n` octets.
    let written = unsafe { bio::BIO_write(bp, data.as_ptr().cast(), n) };
    written == n
}

ffi_export! {
    /// Writes a PEM block to `bp`: the BEGIN line for `name`, `header` (if not empty) and a
    /// newline, `len` octets of `data` in base64 lines of 64, and the END line. Returns the
    /// length of the base64, or 0.
    ///
    /// Unlike OpenSSL, NULL `name`, or NULL `data` with a positive `len`, returns 0 rather than
    /// crashing (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `bp` is NULL or a live BIO; `name` and `header` are NULL or strings; `data` holds `len`
    /// octets.
    pub unsafe extern "C" fn PEM_write_bio(bp: *mut BIO, name: *const c_char, header: *const c_char, data: *const c_uchar, len: c_long) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        if name.is_null() || (data.is_null() && len > 0) {
            return 0;
        }
        let fail = |reason: c_int| {
            err::raise(ERR_LIB_PEM, reason, "PEM_write_bio");
            0
        };
        // SAFETY: the caller's guarantee.
        let name = unsafe { CStr::from_ptr(name) }.to_bytes();
        // SAFETY: the caller's BIO.
        let w = |d: &[u8]| unsafe { write_all(bp, d) };
        let ok = w(b"-----BEGIN ") && w(name) && w(b"-----\n");
        if !ok {
            return fail(ERR_R_BIO_LIB);
        }
        let header = if header.is_null() {
            &[][..]
        } else {
            // SAFETY: as above.
            unsafe { CStr::from_ptr(header) }.to_bytes()
        };
        if !header.is_empty() && !(w(header) && w(b"\n")) {
            return fail(ERR_R_BIO_LIB);
        }
        let mut ctx = Ctx::default();
        ctx.encode_init();
        let octets = match usize::try_from(len) {
            // SAFETY: the caller's guarantee.
            Ok(n) if n > 0 => unsafe { core::slice::from_raw_parts(data, n) },
            _ => &[],
        };
        let chunk = usize::try_from(PEM_BUFSIZE).unwrap_or(1024) * 5;
        let mut total: usize = 0;
        for piece in octets.chunks(chunk) {
            let Some(encoded) = ctx.encode_update(piece) else {
                return fail(ERR_R_EVP_LIB);
            };
            if !encoded.out.is_empty() && !w(&encoded.out) {
                return fail(ERR_R_BIO_LIB);
            }
            total = total.saturating_add(encoded.out.len());
        }
        let last = ctx.encode_final().unwrap_or_default();
        if !last.is_empty() && !w(&last) {
            return fail(ERR_R_BIO_LIB);
        }
        let ok = w(b"-----END ") && w(name) && w(b"-----\n");
        if !ok {
            return fail(ERR_R_BIO_LIB);
        }
        c_int::try_from(total.saturating_add(last.len())).unwrap_or(c_int::MAX)
    }
}

ffi_export! {
    /// `PEM_write_bio` to a `FILE`, which is left open.
    ///
    /// # Safety
    /// As for `PEM_write_bio`, with `fp` an open `FILE`.
    pub unsafe extern "C" fn PEM_write(fp: *mut FILE, name: *const c_char, header: *const c_char, data: *const c_uchar, len: c_long) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        let b = unsafe { file_bio(fp, "PEM_write") };
        if b.is_null() {
            return 0;
        }
        // SAFETY: as above.
        let ret = unsafe { PEM_write_bio(b, name, header, data, len) };
        // SAFETY: the BIO made above.
        unsafe { bio::BIO_free(b) };
        ret
    }
}

/// The room left in a `PEM_BUFSIZE` buffer `buf` after its string, and where it ends; `None`
/// if the string already fills it (OpenSSL would write past it).
///
/// # Safety
/// `buf` is a string in a buffer of `PEM_BUFSIZE` octets.
unsafe fn append_point(buf: *mut c_char) -> Option<(*mut c_char, usize)> {
    // SAFETY: the caller's guarantee.
    let used = unsafe { CStr::from_ptr(buf) }.count_bytes();
    let room = usize::try_from(PEM_BUFSIZE)
        .unwrap_or(0)
        .checked_sub(used)
        .filter(|&r| r > 0)?;
    Some((buf.wrapping_add(used), room))
}

ffi_export! {
    /// Appends `Proc-Type: 4,` and the type's name (`ENCRYPTED`, `MIC-CLEAR`, `MIC-ONLY`, else
    /// `BAD-TYPE`) and a newline to the string in `buf`, within `PEM_BUFSIZE`.
    ///
    /// Unlike OpenSSL, a string that already fills `PEM_BUFSIZE` is left alone rather than
    /// written past (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `buf` holds a string and has room for `PEM_BUFSIZE` octets.
    pub unsafe extern "C" fn PEM_proc_type(buf: *mut c_char, type_: c_int)
    where failure = (), library = ERR_LIB_PEM
    {
        let s = match type_ {
            PEM_TYPE_ENCRYPTED => c"ENCRYPTED",
            PEM_TYPE_MIC_CLEAR => c"MIC-CLEAR",
            PEM_TYPE_MIC_ONLY => c"MIC-ONLY",
            _ => c"BAD-TYPE",
        };
        // SAFETY: the caller's guarantee.
        if let Some((p, room)) = unsafe { append_point(buf) } {
            // SAFETY: `room` octets at `p`; the format takes one string.
            unsafe { BIO_snprintf(p, room, c"Proc-Type: 4,%s\n".as_ptr(), s.as_ptr()) };
        }
    }
}

ffi_export! {
    /// Appends `DEK-Info: `, `type`, a comma, `len` octets of `str` in uppercase hex, and a
    /// newline to the string in `buf`, as far as `PEM_BUFSIZE` allows.
    ///
    /// # Safety
    /// `buf` holds a string and has room for `PEM_BUFSIZE` octets; `type_` is NULL or a
    /// string; `str` holds `len` octets.
    pub unsafe extern "C" fn PEM_dek_info(buf: *mut c_char, type_: *const c_char, len: c_int, str: *const c_char)
    where failure = (), library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        let Some((mut p, room)) = (unsafe { append_point(buf) }) else {
            return;
        };
        let mut j = c_int::try_from(room).unwrap_or(c_int::MAX);
        // SAFETY: `j` octets at `p`; the format takes one string.
        let n = unsafe { BIO_snprintf(p, usize::try_from(j).unwrap_or(0), c"DEK-Info: %s,".as_ptr(), type_) };
        if n <= 0 {
            return;
        }
        j -= n;
        p = p.wrapping_add(usize::try_from(n).unwrap_or(0));
        for i in 0..usize::try_from(len).unwrap_or(0) {
            // SAFETY: the caller's guarantee: `len` octets at `str`.
            let octet = unsafe { str.wrapping_add(i).read() };
            let value = c_int::from(u8::from_ne_bytes(octet.to_ne_bytes()));
            // SAFETY: `j` octets at `p`; the format takes an int.
            let n = unsafe { BIO_snprintf(p, usize::try_from(j).unwrap_or(0), c"%02X".as_ptr(), value) };
            if n <= 0 {
                return;
            }
            j -= n;
            p = p.wrapping_add(usize::try_from(n).unwrap_or(0));
        }
        if j > 1 {
            // SAFETY: two octets of room at `p`.
            unsafe { ptr::copy_nonoverlapping(c"\n".as_ptr(), p, 2) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_arguments_and_full_buffers_are_safe() {
        let mut len: c_long = 0;
        // SAFETY: NULL outputs are refused before any read.
        let r = unsafe {
            PEM_read_bio_ex(
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &raw mut len,
                0,
            )
        };
        assert_eq!(r, 0);
        // SAFETY: a NULL name is refused.
        let r = unsafe { PEM_write_bio(ptr::null_mut(), ptr::null(), ptr::null(), ptr::null(), 0) };
        assert_eq!(r, 0);
        let x = c_char::from_ne_bytes(*b"x");
        let mut buf = [x; 1024];
        buf[1023] = 0;
        // SAFETY: a full PEM_BUFSIZE buffer is left alone.
        unsafe { PEM_proc_type(buf.as_mut_ptr(), PEM_TYPE_ENCRYPTED) };
        assert_eq!(buf[1023], 0);
        buf[1023] = x;
        buf[0] = 0;
        // SAFETY: an empty string in a full-size buffer.
        unsafe { PEM_proc_type(buf.as_mut_ptr(), PEM_TYPE_ENCRYPTED) };
        // SAFETY: the string just written.
        let written = unsafe { CStr::from_ptr(buf.as_ptr()) };
        assert_eq!(
            written,
            c"Proc-Type: 4,ENCRYPTED
"
        );
    }
}
