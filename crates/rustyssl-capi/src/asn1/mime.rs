//! S/MIME's MIME handling (`asn_mime.c`): copying a content with its line ends made canonical,
//! and taking the text of a `text/plain` part. The header parser is
//! [`rustyssl_asn1::mime`]'s.

use core::ffi::c_int;
use core::ptr;

use rustyssl_abi::{
    ASN1_R_INVALID_MIME_TYPE, ASN1_R_MIME_NO_CONTENT_TYPE, ASN1_R_MIME_PARSE_ERROR, BIO,
    BIO_CTRL_FLUSH, ERR_LIB_ASN1, ERR_R_BIO_LIB, ERR_R_PASSED_NULL_PARAMETER, SMIME_ASCIICRLF,
    SMIME_BINARY, SMIME_TEXT,
};
use rustyssl_asn1::mime::{HeaderParser, Headers, MAX_LINE, strip_eol};

use crate::bio::buffer::BIO_f_buffer;
use crate::bio::{BIO_ctrl, BIO_free, BIO_gets, BIO_new, BIO_pop, BIO_push, BIO_read, BIO_write};
use crate::err;
use crate::ffi::ffi_export;

/// `MAX_SMLEN`: a line's room, with its NUL.
const LINE_ROOM: usize = MAX_LINE + 1;

/// Writes all of `data`, ignoring failures as OpenSSL does (the final flush reports them).
fn write(out: *mut BIO, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let n = c_int::try_from(data.len()).unwrap_or(c_int::MAX);
    // SAFETY: a live BIO; the slice's octets.
    unsafe { BIO_write(out, data.as_ptr().cast(), n) };
}

/// The next line of `bio` as `BIO_gets` reads it into `buf`: `None` at its end or on error.
fn gets(bio: *mut BIO, buf: &mut [u8; LINE_ROOM]) -> Option<usize> {
    let room = c_int::try_from(LINE_ROOM).unwrap_or(0);
    // SAFETY: a live BIO; room for `room` octets.
    let len = unsafe { BIO_gets(bio, buf.as_mut_ptr().cast(), room) };
    usize::try_from(len)
        .ok()
        .filter(|&n| n > 0)
        .map(|n| n.min(MAX_LINE))
}

ffi_export! {
    /// Copies `in_` to `out` through a buffer: as is for `SMIME_BINARY`, otherwise line by
    /// line with CRLF line ends (after a `text/plain` header for `SMIME_TEXT`; trailing blank
    /// lines dropped for `SMIME_ASCIICRLF`). 1, or 0.
    ///
    /// # Safety
    /// `in_` and `out` are NULL or live BIOs.
    pub unsafe extern "C" fn SMIME_crlf_copy(in_: *mut BIO, out: *mut BIO, flags: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        const F: &str = "SMIME_crlf_copy";
        if in_.is_null() || out.is_null() {
            err::raise(ERR_LIB_ASN1, ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        }
        // SAFETY: no preconditions.
        let method = unsafe { BIO_f_buffer() };
        // SAFETY: the built-in method.
        let bf = unsafe { BIO_new(method) };
        if bf.is_null() {
            err::raise(ERR_LIB_ASN1, ERR_R_BIO_LIB, F);
            return 0;
        }
        // SAFETY: live BIOs; the buffer goes in front of the caller's.
        let out = unsafe { BIO_push(bf, out) };
        let mut line = [0u8; LINE_ROOM];
        if flags & SMIME_BINARY != 0 {
            let room = c_int::try_from(LINE_ROOM).unwrap_or(0);
            loop {
                // SAFETY: the caller's BIO; room for `room` octets.
                let len = unsafe { BIO_read(in_, line.as_mut_ptr().cast(), room) };
                let Some(data) = usize::try_from(len).ok().filter(|&n| n > 0).and_then(|n| line.get(..n)) else {
                    break;
                };
                write(out, data);
            }
        } else {
            let mut eolcnt = 0usize;
            if flags & SMIME_TEXT != 0 {
                write(out, b"Content-Type: text/plain\r\n\r\n");
            }
            while let Some(len) = gets(in_, &mut line) {
                let read = line.get(..len).unwrap_or_default();
                let (len, eol) = strip_eol(read, flags);
                let text = read.get(..len).unwrap_or_default();
                if !text.is_empty() {
                    if flags & SMIME_ASCIICRLF != 0 {
                        for _ in 0..eolcnt {
                            write(out, b"\r\n");
                        }
                        eolcnt = 0;
                    }
                    write(out, text);
                    if eol {
                        write(out, b"\r\n");
                    }
                } else if flags & SMIME_ASCIICRLF != 0 {
                    eolcnt = eolcnt.saturating_add(1);
                } else if eol {
                    write(out, b"\r\n");
                }
            }
        }
        // SAFETY: the chain.
        let ret = unsafe { BIO_ctrl(out, BIO_CTRL_FLUSH, 0, ptr::null_mut()) };
        // SAFETY: as above; the buffer leaves it.
        unsafe { BIO_pop(out) };
        // SAFETY: the buffer made here.
        unsafe { BIO_free(bf) };
        c_int::from(ret > 0)
    }
}

/// `mime_parse_hdr`: the headers at the start of `bio`, up to a blank line or its end.
pub(crate) fn parse_headers(bio: *mut BIO) -> Option<Headers> {
    let mut parser = HeaderParser::new();
    let mut line = [0u8; LINE_ROOM];
    while let Some(len) = gets(bio, &mut line) {
        if !parser.line(line.get(..len).unwrap_or_default()).ok()? {
            break;
        }
    }
    Some(parser.finish())
}

ffi_export! {
    /// Copies the body of a `text/plain` MIME part in `in_` to `out`: 1, or 0.
    ///
    /// # Safety
    /// `in_` and `out` are live BIOs.
    pub unsafe extern "C" fn SMIME_text(in_: *mut BIO, out: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        const F: &str = "SMIME_text";
        let Some(headers) = parse_headers(in_) else {
            err::raise(ERR_LIB_ASN1, ASN1_R_MIME_PARSE_ERROR, F);
            return 0;
        };
        let Some(value) = headers.find(b"content-type").and_then(|h| h.value.as_deref()) else {
            err::raise(ERR_LIB_ASN1, ASN1_R_MIME_NO_CONTENT_TYPE, F);
            return 0;
        };
        if value != b"text/plain" {
            let mut text = b"type: ".to_vec();
            text.extend_from_slice(value);
            err::raise_with_bytes(ERR_LIB_ASN1, ASN1_R_INVALID_MIME_TYPE, F, &text);
            return 0;
        }
        let mut buf = [0u8; 4096];
        let room = c_int::try_from(buf.len()).unwrap_or(0);
        loop {
            // SAFETY: the caller's BIO; room for `room` octets.
            let len = unsafe { BIO_read(in_, buf.as_mut_ptr().cast(), room) };
            if len < 0 {
                return 0;
            }
            let Some(data) = usize::try_from(len).ok().filter(|&n| n > 0).and_then(|n| buf.get(..n)) else {
                return 1;
            };
            write(out, data);
        }
    }
}
