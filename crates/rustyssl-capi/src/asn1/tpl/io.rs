//! Encoding to and decoding from BIOs and `FILE`s (`ASN1_item_d2i_bio(3)`,
//! `ASN1_item_i2d_bio`, their `_fp` and `_ex` forms, `ASN1_item_i2d_mem_bio`, and the old
//! `ASN1_d2i_bio`/`ASN1_i2d_bio` pair taking `d2i`/`i2d` functions), as OpenSSL's
//! `a_d2i_fp.c` and `a_i2d_fp.c` do.
//!
//! Decoding first reads one whole element from the BIO (`asn1_d2i_read_bio`): enough of each
//! header to know its length, then the content, in chunks that double from 16 KiB so that a
//! length the input doesn't back fails at its end rather than allocating it all; an
//! indefinite length is followed to its end-of-contents octets. The buffer is a `BUF_MEM`, as
//! in OpenSSL, and every look at it is bounded by its length.

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use libc::FILE;

use rustyssl_abi::{
    ASN1_ITEM, ASN1_R_HEADER_TOO_LONG, ASN1_R_NOT_ENOUGH_DATA, ASN1_R_TOO_LONG, ASN1_VALUE, BIO,
    BIO_NOCLOSE, BUF_MEM, ERR_LIB_ASN1, ERR_R_ASN1_LIB, ERR_R_BUF_LIB, ERR_R_PASSED_NULL_PARAMETER,
    ERR_REASON_MASK, OSSL_LIB_CTX, V_ASN1_EOC, d2i_of_void, i2d_of_void,
};

use super::decode::ASN1_item_d2i_ex;
use super::encode::ASN1_item_i2d;
use crate::bio;
use crate::buffer;
use crate::err;
use crate::ffi::ffi_export;
use crate::mem;

/// The octets read for a header before looking at it (`HEADER_SIZE`).
const HEADER_SIZE: usize = 2;

/// The first chunk of content read at once (`ASN1_CHUNK_INITIAL_SIZE`).
const CHUNK_INITIAL_SIZE: usize = 16 * 1024;

/// A `BUF_MEM` owned here.
struct Buf(*mut BUF_MEM);

impl Buf {
    /// The buffer's octets: its whole length.
    fn bytes(&self) -> &[u8] {
        // SAFETY: a live buffer.
        let b = unsafe { &*self.0 };
        if b.data.is_null() || b.length == 0 {
            return &[];
        }
        // SAFETY: a buffer's data holds its length.
        unsafe { core::slice::from_raw_parts(b.data.cast::<u8>(), b.length) }
    }

    /// `BUF_MEM_grow_clean` to `len`: false on failure (including, as in C, a result of 0).
    fn grow(&mut self, len: usize) -> bool {
        // SAFETY: a live buffer.
        let grown = unsafe { buffer::BUF_MEM_grow_clean(self.0, len) };
        grown != 0
    }

    /// `BIO_read` of up to `n` octets into the buffer at `at`, which has room for them.
    fn read(&mut self, bio: *mut BIO, at: usize, n: usize) -> c_int {
        let Ok(n) = c_int::try_from(n) else {
            return -1;
        };
        // SAFETY: a live buffer.
        let data = unsafe { (*self.0).data };
        // SAFETY: the caller's room within the buffer's length.
        unsafe { bio::BIO_read(bio, data.cast::<u8>().wrapping_add(at).cast(), n) }
    }
}

impl Drop for Buf {
    fn drop(&mut self) {
        // SAFETY: a buffer owned here.
        unsafe { buffer::BUF_MEM_free(self.0) };
    }
}

/// Raises an ASN1 error from `asn1_d2i_read_bio`.
#[track_caller]
fn raise(reason: c_int) {
    err::raise(ERR_LIB_ASN1, reason, "asn1_d2i_read_bio");
}

/// `asn1_d2i_read_bio`: reads one element (and, for an indefinite length, everything up to
/// its end-of-contents octets) from `bio`. Returns the buffer and the element's length, or
/// `None` after raising an error (none for a clean end of input before an element).
///
/// # Safety
/// `bio` is a live BIO.
unsafe fn read_bio(bio: *mut BIO) -> Option<(Buf, usize)> {
    // SAFETY: no preconditions.
    let b = unsafe { buffer::BUF_MEM_new() };
    if b.is_null() {
        raise(ERR_R_BUF_LIB);
        return None;
    }
    let mut buf = Buf(b);
    // SAFETY: no preconditions.
    unsafe { err::ERR_set_mark() };
    // SAFETY: as above.
    let result = unsafe { read_element(bio, &mut buf) };
    // SAFETY: the mark set above.
    unsafe { err::ERR_clear_last_mark() };
    result.map(|off| (buf, off))
}

/// The loop of `asn1_d2i_read_bio`.
///
/// # Safety
/// `bio` is a live BIO.
unsafe fn read_element(bio: *mut BIO, buf: &mut Buf) -> Option<usize> {
    let mut want = HEADER_SIZE;
    let mut eos: u32 = 0;
    let mut off: usize = 0;
    let mut len: usize = 0;
    loop {
        let diff = len.wrapping_sub(off);
        if want >= diff {
            want = want.wrapping_sub(diff);
            if !len.checked_add(want).is_some_and(|total| buf.grow(total)) {
                raise(ERR_R_BUF_LIB);
                return None;
            }
            let i = buf.read(bio, len, want);
            if i <= 0 {
                // Only a clean end at an element boundary is quiet: callers loop over
                // concatenated elements until it.
                if i < 0 || diff != 0 || eos != 0 {
                    raise(ASN1_R_NOT_ENOUGH_DATA);
                }
                return None;
            }
            let got = usize::try_from(i).unwrap_or(0);
            let Some(new_len) = len.checked_add(got) else {
                raise(ASN1_R_TOO_LONG);
                return None;
            };
            len = new_len;
            if got < want {
                continue;
            }
        }
        // The header so far: octets past `len` read as the zeros the buffer was grown with.
        let data = buf.bytes();
        let at = |i: usize| -> u8 {
            match off.checked_add(i) {
                Some(j) if j < len => data.get(j).copied().unwrap_or(0),
                _ => 0,
            }
        };
        let mut diff = len.wrapping_sub(off);
        if diff < 2 {
            raise(ASN1_R_NOT_ENOUGH_DATA);
            return None;
        }
        diff = diff.wrapping_sub(1);
        // `q`: the index of the next header octet to look at.
        let mut q: usize = 1;
        if at(0) & 0x1f == 0x1f {
            let mut n: u32 = 0;
            loop {
                if n > 4 {
                    raise(ASN1_R_HEADER_TOO_LONG);
                    return None;
                }
                n = n.wrapping_add(1);
                diff = diff.wrapping_sub(1);
                if diff == 0 {
                    break;
                }
                let octet = at(q);
                q = q.wrapping_add(1);
                if octet & 0x80 == 0 {
                    break;
                }
            }
            if diff == 0 {
                want = q.wrapping_add(2);
                if at(q) & 0x80 != 0 {
                    want = want.wrapping_add(1);
                }
                continue;
            }
        }
        diff = diff.wrapping_sub(1);
        let length_octet = at(q);
        if length_octet & 0x80 != 0 {
            let n = usize::from(length_octet & 0x7f);
            if n > size_of::<c_long>() {
                raise(ASN1_R_TOO_LONG);
                return None;
            }
            if n > diff {
                want = q.wrapping_add(n).wrapping_add(1);
                continue;
            }
        }
        // A whole header: read it as ASN1_get_object does.
        let header_input = data.get(off..len).unwrap_or(&[]);
        let limit = header_input
            .len()
            .min(usize::try_from(c_int::MAX).unwrap_or(usize::MAX));
        let result = crate::asn1::read_header_in(header_input.get(..limit).unwrap_or(&[]));
        let h = match result {
            Ok(h) => {
                if h.overrun {
                    // A length past what's read so far is expected here.
                    // SAFETY: no preconditions.
                    let code = unsafe { err::ERR_peek_last_error() };
                    let reason = code & core::ffi::c_ulong::from(ERR_REASON_MASK.cast_unsigned());
                    if reason != core::ffi::c_ulong::from(ASN1_R_TOO_LONG.cast_unsigned()) {
                        return None;
                    }
                    // SAFETY: the mark set by `read_bio`.
                    unsafe { err::ERR_pop_to_mark() };
                    // SAFETY: no preconditions.
                    unsafe { err::ERR_set_mark() };
                }
                h
            }
            Err(_) => return None,
        };
        off = off.wrapping_add(h.header_len);
        if h.indefinite {
            if eos == u32::MAX {
                raise(ASN1_R_HEADER_TOO_LONG);
                return None;
            }
            eos = eos.wrapping_add(1);
            want = HEADER_SIZE;
        } else if eos != 0 && h.length == 0 && h.tag == V_ASN1_EOC {
            eos = eos.wrapping_sub(1);
            if eos == 0 {
                break;
            }
            want = HEADER_SIZE;
        } else {
            let slen = usize::try_from(h.length).unwrap_or(usize::MAX);
            want = slen;
            let have = len.wrapping_sub(off);
            if want > have {
                let mut chunk_max = CHUNK_INITIAL_SIZE;
                want = want.wrapping_sub(have);
                if want > usize::try_from(c_int::MAX).unwrap_or(usize::MAX)
                    || len.checked_add(want).is_none()
                {
                    raise(ASN1_R_TOO_LONG);
                    return None;
                }
                while want > 0 {
                    let mut chunk = want.min(chunk_max);
                    if !buf.grow(len.wrapping_add(chunk)) {
                        raise(ERR_R_BUF_LIB);
                        return None;
                    }
                    want = want.wrapping_sub(chunk);
                    while chunk > 0 {
                        let i = buf.read(bio, len, chunk);
                        if i <= 0 {
                            raise(ASN1_R_NOT_ENOUGH_DATA);
                            return None;
                        }
                        let got = usize::try_from(i).unwrap_or(0).min(chunk);
                        len = len.wrapping_add(got);
                        chunk = chunk.wrapping_sub(got);
                    }
                    if chunk_max < usize::try_from(c_int::MAX / 2).unwrap_or(0) {
                        chunk_max = chunk_max.wrapping_mul(2);
                    }
                }
            }
            let Some(end) = off.checked_add(slen) else {
                raise(ASN1_R_TOO_LONG);
                return None;
            };
            off = end;
            if eos == 0 {
                break;
            }
            want = HEADER_SIZE;
        }
    }
    if off > usize::try_from(c_int::MAX).unwrap_or(usize::MAX) {
        raise(ASN1_R_TOO_LONG);
        return None;
    }
    Some(off)
}

/// Writes all of `data` to `out`, as `ASN1_i2d_bio`'s loop does: 1, or 0 if a write fails.
///
/// # Safety
/// `out` is a live BIO.
unsafe fn write_all(out: *mut BIO, data: &[u8]) -> c_int {
    let mut rest = data;
    loop {
        let n = c_int::try_from(rest.len()).unwrap_or(c_int::MAX);
        // SAFETY: the caller's BIO; `rest` holds `n` octets.
        let i = unsafe { bio::BIO_write(out, rest.as_ptr().cast(), n) };
        if i == n {
            return 1;
        }
        if i <= 0 {
            return 0;
        }
        rest = rest.get(usize::try_from(i).unwrap_or(0)..).unwrap_or(&[]);
    }
}

/// A `FILE` BIO that leaves the stream open (`BIO_new` and `BIO_set_fp` with `BIO_NOCLOSE`),
/// or NULL after raising `ERR_R_BUF_LIB`.
///
/// # Safety
/// `fp` is an open `FILE`.
pub(crate) unsafe fn file_bio(fp: *mut FILE) -> *mut BIO {
    // SAFETY: the caller's guarantee.
    let b = unsafe { bio::file::BIO_new_fp(fp, BIO_NOCLOSE) };
    if b.is_null() {
        err::raise(ERR_LIB_ASN1, ERR_R_BUF_LIB, "ASN1_item_d2i_fp");
    }
    b
}

ffi_export! {
    /// Reads one element from `in_` and decodes it as `it` into `x` (an `ASN1_VALUE **`, or
    /// NULL), passing `libctx` and `propq` on. Returns the value or NULL.
    ///
    /// # Safety
    /// `it` is a live item whose tables and functions can be trusted; `in_` is NULL or a live
    /// BIO; `x` is NULL or a slot for a value of `it`; `propq` is NULL or a string.
    pub unsafe extern "C" fn ASN1_item_d2i_bio_ex(it: *const ASN1_ITEM, in_: *mut BIO, x: *mut c_void, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        if in_.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let Some((buf, len)) = (unsafe { read_bio(in_) }) else {
            return ptr::null_mut();
        };
        let mut p = buf.bytes().as_ptr();
        let len = c_long::try_from(len).unwrap_or(c_long::MAX);
        // SAFETY: the buffer holds the element; the caller's guarantee for the rest.
        unsafe { ASN1_item_d2i_ex(x.cast(), &raw mut p, len, it, libctx, propq) }.cast()
    }
}

ffi_export! {
    /// `ASN1_item_d2i_bio_ex` without a library context.
    ///
    /// # Safety
    /// As for `ASN1_item_d2i_bio_ex`.
    pub unsafe extern "C" fn ASN1_item_d2i_bio(it: *const ASN1_ITEM, in_: *mut BIO, x: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_d2i_bio_ex(it, in_, x, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// `ASN1_item_d2i_bio_ex` reading from a `FILE`, which is left open.
    ///
    /// # Safety
    /// As for `ASN1_item_d2i_bio_ex`, with `in_` an open `FILE`.
    pub unsafe extern "C" fn ASN1_item_d2i_fp_ex(it: *const ASN1_ITEM, in_: *mut FILE, x: *mut c_void, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let b = unsafe { file_bio(in_) };
        if b.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        let ret = unsafe { ASN1_item_d2i_bio_ex(it, b, x, libctx, propq) };
        // SAFETY: the BIO made above.
        unsafe { bio::BIO_free(b) };
        ret
    }
}

ffi_export! {
    /// `ASN1_item_d2i_fp_ex` without a library context.
    ///
    /// # Safety
    /// As for `ASN1_item_d2i_fp_ex`.
    pub unsafe extern "C" fn ASN1_item_d2i_fp(it: *const ASN1_ITEM, in_: *mut FILE, x: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_d2i_fp_ex(it, in_, x, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Encodes `x` as `it` and writes it to `out`. Returns 1, or 0.
    ///
    /// # Safety
    /// `it` is a live item whose tables and functions can be trusted; `out` is a live BIO;
    /// `x` is a live value of `it`.
    pub unsafe extern "C" fn ASN1_item_i2d_bio(it: *const ASN1_ITEM, out: *mut BIO, x: *const c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        let mut b: *mut c_uchar = ptr::null_mut();
        // SAFETY: the caller's guarantee, with a local slot.
        let n = unsafe { ASN1_item_i2d(x.cast(), &raw mut b, it) };
        if n < 0 || b.is_null() {
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, "ASN1_item_i2d_bio");
            return 0;
        }
        // SAFETY: the encoding just made, of `n` octets.
        let data = unsafe { core::slice::from_raw_parts(b, usize::try_from(n).unwrap_or(0)) };
        // SAFETY: the caller's BIO.
        let ret = unsafe { write_all(out, data) };
        // SAFETY: the encoding, from this allocator.
        unsafe { mem::release(b.cast()) };
        ret
    }
}

ffi_export! {
    /// `ASN1_item_i2d_bio` writing to a `FILE`, which is left open.
    ///
    /// # Safety
    /// As for `ASN1_item_i2d_bio`, with `out` an open `FILE`.
    pub unsafe extern "C" fn ASN1_item_i2d_fp(it: *const ASN1_ITEM, out: *mut FILE, x: *const c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let b = unsafe { file_bio(out) };
        if b.is_null() {
            return 0;
        }
        // SAFETY: as above.
        let ret = unsafe { ASN1_item_i2d_bio(it, b, x) };
        // SAFETY: the BIO made above.
        unsafe { bio::BIO_free(b) };
        ret
    }
}

ffi_export! {
    /// A new memory BIO holding the encoding of `val` as `it`, or NULL.
    ///
    /// # Safety
    /// `it` is NULL or a live item whose tables and functions can be trusted; `val` is NULL or
    /// a live value of `it`.
    pub unsafe extern "C" fn ASN1_item_i2d_mem_bio(it: *const ASN1_ITEM, val: *const ASN1_VALUE) -> *mut BIO
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        if it.is_null() || val.is_null() {
            err::raise(ERR_LIB_ASN1, ERR_R_PASSED_NULL_PARAMETER, "ASN1_item_i2d_mem_bio");
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let method = unsafe { bio::mem::BIO_s_mem() };
        // SAFETY: the built-in method.
        let res = unsafe { bio::BIO_new(method) };
        if res.is_null() {
            return res;
        }
        // SAFETY: the caller's guarantee; a new BIO.
        if unsafe { ASN1_item_i2d_bio(it, res, val.cast()) } <= 0 {
            // SAFETY: the BIO made above.
            unsafe { bio::BIO_free(res) };
            return ptr::null_mut();
        }
        res
    }
}

ffi_export! {
    /// Reads one element from `in_` and decodes it with `d2i` into `x` (`xnew` is unused, as
    /// in OpenSSL). Returns the value or NULL.
    ///
    /// # Safety
    /// `d2i` is a decoding function trusted with the element; `in_` is a live BIO; `x` is
    /// whatever `d2i` takes.
    pub unsafe extern "C" fn ASN1_d2i_bio(xnew: Option<unsafe extern "C" fn() -> *mut c_void>, d2i: d2i_of_void, in_: *mut BIO, x: *mut *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        let _ = xnew;
        // SAFETY: the caller's guarantee.
        let Some((buf, len)) = (unsafe { read_bio(in_) }) else {
            return ptr::null_mut();
        };
        let Some(d2i) = d2i else {
            return ptr::null_mut();
        };
        let mut p = buf.bytes().as_ptr();
        let len = c_long::try_from(len).unwrap_or(c_long::MAX);
        // SAFETY: the caller's function, given the element.
        unsafe { d2i(x, &raw mut p, len) }
    }
}

ffi_export! {
    /// `ASN1_d2i_bio` reading from a `FILE`, which is left open.
    ///
    /// # Safety
    /// As for `ASN1_d2i_bio`, with `in_` an open `FILE`.
    pub unsafe extern "C" fn ASN1_d2i_fp(xnew: Option<unsafe extern "C" fn() -> *mut c_void>, d2i: d2i_of_void, in_: *mut FILE, x: *mut *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let b = unsafe { file_bio(in_) };
        if b.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        let ret = unsafe { ASN1_d2i_bio(xnew, d2i, b, x) };
        // SAFETY: the BIO made above.
        unsafe { bio::BIO_free(b) };
        ret
    }
}

ffi_export! {
    /// Encodes `x` with `i2d` and writes it to `out`. Returns 1, or 0.
    ///
    /// # Safety
    /// `i2d` is an encoding function trusted with `x` and a buffer of the length it reports;
    /// `out` is a live BIO.
    pub unsafe extern "C" fn ASN1_i2d_bio(i2d: i2d_of_void, out: *mut BIO, x: *const c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        let Some(i2d) = i2d else {
            return 0;
        };
        // SAFETY: the caller's function, measuring.
        let n = unsafe { i2d(x, ptr::null_mut()) };
        let Ok(size) = usize::try_from(n) else {
            return 0;
        };
        if size == 0 {
            return 0;
        }
        let b: *mut c_uchar = mem::alloc(size).cast();
        if b.is_null() {
            return 0;
        }
        let mut p = b;
        // SAFETY: the caller's function, writing the `n` octets it measured.
        unsafe { i2d(x, &raw mut p) };
        // SAFETY: the buffer of `n` octets.
        let data = unsafe { core::slice::from_raw_parts(b, size) };
        // SAFETY: the caller's BIO.
        let ret = unsafe { write_all(out, data) };
        // SAFETY: the buffer, from this allocator.
        unsafe { mem::release(b.cast()) };
        ret
    }
}

ffi_export! {
    /// `ASN1_i2d_bio` writing to a `FILE`, which is left open.
    ///
    /// # Safety
    /// As for `ASN1_i2d_bio`, with `out` an open `FILE`.
    pub unsafe extern "C" fn ASN1_i2d_fp(i2d: i2d_of_void, out: *mut FILE, x: *const c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let b = unsafe { file_bio(out) };
        if b.is_null() {
            return 0;
        }
        // SAFETY: as above.
        let ret = unsafe { ASN1_i2d_bio(i2d, b, x) };
        // SAFETY: the BIO made above.
        unsafe { bio::BIO_free(b) };
        ret
    }
}

/// `ossl_read_der` (and `epki2pki`'s read): one element read from the BIO
/// (`asn1_d2i_read_bio`), as the whole buffer read, or `None` (errors raised for a broken one).
///
/// # Safety
/// `bio` is a live BIO.
pub(crate) unsafe fn read_der(bio: *mut BIO) -> Option<Vec<u8>> {
    // SAFETY: the caller's guarantee.
    unsafe { read_bio(bio) }.map(|(b, _)| b.bytes().to_vec())
}

/// `asn1_d2i_read_bio` as the `_ex_bio` decoders use it: one element's octets (its length
/// only), or `None` after raising an error.
///
/// # Safety
/// `bio` is a live BIO.
pub(crate) unsafe fn read_element_octets(bio: *mut BIO) -> Option<Vec<u8>> {
    // SAFETY: the caller's guarantee.
    let (b, len) = unsafe { read_bio(bio) }?;
    b.bytes().get(..len).map(<[u8]>::to_vec)
}

ffi_export! {
    /// Reads one element (to its end-of-contents octets for an indefinite length) from `in_`
    /// into a new buffer for `*pb`. Its length, or -1 with an error.
    ///
    /// # Safety
    /// `in_` is a live BIO; `pb` is writable.
    pub unsafe extern "C" fn asn1_d2i_read_bio(in_: *mut BIO, pb: *mut *mut BUF_MEM) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        if pb.is_null() {
            raise(ERR_R_PASSED_NULL_PARAMETER);
            return -1;
        }
        // SAFETY: the caller's guarantee.
        let Some((b, len)) = (unsafe { read_bio(in_) }) else { return -1 };
        let Ok(n) = c_int::try_from(len) else {
            raise(ASN1_R_TOO_LONG);
            return -1;
        };
        let raw = b.0;
        core::mem::forget(b);
        // SAFETY: the caller's guarantee; the buffer passes to the caller.
        unsafe { pb.write(raw) };
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: OpenSSL's writes the buffer through NULL and crashes.
    #[test]
    fn read_bio_into_null_is_refused() {
        let der = [0x30u8, 0x00];
        // SAFETY: the octets, read-only for the BIO's life.
        let b = unsafe { crate::bio::mem::BIO_new_mem_buf(der.as_ptr().cast(), 2) };
        // SAFETY: the BIO; NULL.
        assert_eq!(unsafe { asn1_d2i_read_bio(b, ptr::null_mut()) }, -1);
        let mut m: *mut BUF_MEM = ptr::null_mut();
        // SAFETY: as above; a local.
        assert_eq!(unsafe { asn1_d2i_read_bio(b, &raw mut m) }, 2);
        // SAFETY: the buffer read, the caller's now.
        unsafe { buffer::BUF_MEM_free(m) };
        // SAFETY: made above, freed once.
        unsafe { bio::BIO_free(b) };
        // SAFETY: no preconditions.
        unsafe { err::ERR_clear_error() };
    }
}
