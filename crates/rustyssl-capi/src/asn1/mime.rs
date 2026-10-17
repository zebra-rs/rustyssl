//! S/MIME's MIME handling (`asn_mime.c`): copying a content with its line ends made canonical,
//! taking the text of a `text/plain` part, streaming an ASN.1 value with indefinite lengths (as
//! DER or PEM), and writing and reading S/MIME messages, opaque or multipart/signed. The header
//! parser is [`rustyssl_asn1::mime`]'s.

use core::ffi::{CStr, c_char, c_int, c_long};
use core::ptr;

use rustyssl_abi::{
    ASN1_ITEM, ASN1_OP_DETACHED_POST, ASN1_OP_DETACHED_PRE, ASN1_R_ASN1_PARSE_ERROR,
    ASN1_R_ASN1_SIG_PARSE_ERROR, ASN1_R_DECODE_ERROR, ASN1_R_INVALID_MIME_TYPE,
    ASN1_R_MIME_NO_CONTENT_TYPE, ASN1_R_MIME_PARSE_ERROR, ASN1_R_MIME_SIG_PARSE_ERROR,
    ASN1_R_NO_CONTENT_TYPE, ASN1_R_NO_MULTIPART_BODY_FAILURE, ASN1_R_NO_MULTIPART_BOUNDARY,
    ASN1_R_NO_SIG_CONTENT_TYPE, ASN1_R_SIG_INVALID_MIME_TYPE, ASN1_R_STREAMING_NOT_SUPPORTED,
    ASN1_STREAM_ARG, ASN1_VALUE, BIO, BIO_CTRL_FLUSH, CMS_BINARY, ERR_LIB_ASN1, ERR_R_BIO_LIB,
    ERR_R_BUF_LIB, ERR_R_PASSED_NULL_PARAMETER, EVP_MD_CTRL_MICALG, NID_id_GostR3411_94,
    NID_id_GostR3411_2012_256, NID_id_GostR3411_2012_512, NID_id_smime_ct_authEnvelopedData,
    NID_id_smime_ct_compressedData, NID_id_smime_ct_receipt, NID_md5, NID_pkcs7_enveloped,
    NID_pkcs7_signed, NID_sha1, NID_sha256, NID_sha384, NID_sha512, NID_shake128, NID_shake256,
    NID_undef, OSSL_LIB_CTX, PKCS7_REUSE_DIGEST, SMIME_ASCIICRLF, SMIME_BINARY, SMIME_CRLFEOL,
    SMIME_DETACHED, SMIME_OLDMIME, SMIME_STREAM, SMIME_TEXT, X509_ALGOR, stack_st_X509_ALGOR,
};
use rustyssl_asn1::mime::{HeaderParser, Headers, MAX_LINE, strip_eol};

use crate::asn1::ndef::{BIO_new_NDEF, stream_callback};
use crate::asn1::tpl::io::{ASN1_item_d2i_bio_ex, ASN1_item_i2d_bio};
use crate::bio::base64::BIO_f_base64;
use crate::bio::buffer::BIO_f_buffer;
use crate::bio::{
    BIO_ctrl, BIO_free, BIO_get_line, BIO_gets, BIO_new, BIO_pop, BIO_push, BIO_read, BIO_write,
};
use crate::err;
use crate::evp::legacy_md::EVP_get_digestbyname;
use crate::evp::md_meth::EVP_MD_meth_get_ctrl;
use crate::ffi::ffi_export;
use crate::objects::{OBJ_nid2sn, OBJ_obj2nid};
use crate::rand_lib::RAND_bytes_ex;
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_value};

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

/// Writes `text`, ignoring failures as OpenSSL's `BIO_printf` calls do.
fn puts(out: *mut BIO, text: &str) {
    write(out, text.as_bytes());
}

/// `BIO_flush`.
fn flush(b: *mut BIO) -> c_long {
    // SAFETY: a live BIO.
    unsafe { BIO_ctrl(b, BIO_CTRL_FLUSH, 0, ptr::null_mut()) }
}

ffi_export! {
    /// Encodes `val` to `out`: streamed with indefinite lengths from `in_` for `SMIME_STREAM`,
    /// as stored otherwise. 1, or 0.
    ///
    /// # Safety
    /// `out` is a live BIO; `val` a live value of `it`; `in_` NULL or a live BIO.
    pub unsafe extern "C" fn i2d_ASN1_bio_stream(out: *mut BIO, val: *mut ASN1_VALUE, in_: *mut BIO, flags: c_int, it: *const ASN1_ITEM) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        if flags & SMIME_STREAM == 0 {
            // SAFETY: the caller's guarantee.
            return unsafe { ASN1_item_i2d_bio(it, out, val.cast_const().cast()) };
        }
        // SAFETY: as above.
        let mut bio = unsafe { BIO_new_NDEF(out, val, it) };
        if bio.is_null() {
            err::raise(ERR_LIB_ASN1, ERR_R_BUF_LIB, "i2d_ASN1_bio_stream");
            return 0;
        }
        // SAFETY: the caller's input; the stream.
        let rv = c_int::from(unsafe { SMIME_crlf_copy(in_, bio, flags) } != 0);
        flush(bio);
        // The BIOs in front of the caller's, which the stream made.
        while !bio.is_null() && bio != out {
            // SAFETY: a BIO of the stream.
            let next = unsafe { BIO_pop(bio) };
            // SAFETY: as above, out of the chain.
            unsafe { BIO_free(bio) };
            bio = next;
        }
        rv
    }
}

/// `B64_write_ASN1`: [`i2d_ASN1_bio_stream`] through a base64 filter.
///
/// # Safety
/// As for [`i2d_ASN1_bio_stream`].
unsafe fn b64_write(
    out: *mut BIO,
    val: *mut ASN1_VALUE,
    in_: *mut BIO,
    flags: c_int,
    it: *const ASN1_ITEM,
) -> c_int {
    // SAFETY: no preconditions.
    let method = unsafe { BIO_f_base64() };
    // SAFETY: the built-in method.
    let b64 = unsafe { BIO_new(method) };
    if b64.is_null() {
        err::raise(ERR_LIB_ASN1, ERR_R_BIO_LIB, "B64_write_ASN1");
        return 0;
    }
    // SAFETY: live BIOs; the filter goes in front.
    let chain = unsafe { BIO_push(b64, out) };
    // SAFETY: the caller's guarantee.
    let r = unsafe { i2d_ASN1_bio_stream(chain, val, in_, flags, it) };
    flush(chain);
    // SAFETY: the filter leaves the caller's BIO.
    unsafe { BIO_pop(chain) };
    // SAFETY: the filter made here.
    unsafe { BIO_free(b64) };
    r
}

ffi_export! {
    /// [`i2d_ASN1_bio_stream`] as PEM labelled `hdr`.
    ///
    /// # Safety
    /// As for [`i2d_ASN1_bio_stream`]; `hdr` a C string.
    pub unsafe extern "C" fn PEM_write_bio_ASN1_stream(out: *mut BIO, val: *mut ASN1_VALUE, in_: *mut BIO, flags: c_int, hdr: *const c_char, it: *const ASN1_ITEM) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's string, or NULL.
        let label = unsafe { hdr.as_ref() }.map(|_| unsafe { CStr::from_ptr(hdr) }.to_bytes()).unwrap_or(b"(null)");
        let mut begin = b"-----BEGIN ".to_vec();
        begin.extend_from_slice(label);
        begin.extend_from_slice(b"-----\n");
        write(out, &begin);
        // SAFETY: the caller's guarantee.
        let r = unsafe { b64_write(out, val, in_, flags, it) };
        let mut end = b"-----END ".to_vec();
        end.extend_from_slice(label);
        end.extend_from_slice(b"-----\n");
        write(out, &end);
        r
    }
}

/// `asn1_write_micalg`: the digests' MIME names, comma-separated.
fn write_micalg(out: *mut BIO, mdalgs: *mut stack_st_X509_ALGOR) -> bool {
    let mut have_unknown = false;
    let mut write_comma = false;
    // SAFETY: the digest algorithms, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(mdalgs.cast()) } {
        if write_comma {
            write(out, b",");
        }
        write_comma = true;
        // SAFETY: an index within them.
        let alg = unsafe { OPENSSL_sk_value(mdalgs.cast(), i) }.cast::<X509_ALGOR>();
        // SAFETY: an algorithm identifier, or NULL, and its object.
        let nid =
            unsafe { alg.as_ref() }.map_or(NID_undef, |a| unsafe { OBJ_obj2nid(a.algorithm) });
        if nid == NID_shake128 {
            puts(out, "shake-128");
            continue;
        }
        if nid == NID_shake256 {
            puts(out, "shake-256");
            continue;
        }
        // SAFETY: any NID.
        let sn = unsafe { OBJ_nid2sn(nid) };
        // SAFETY: NULL or a static name.
        let md = unsafe { EVP_get_digestbyname(sn) };
        let ctrl = if md.is_null() {
            None
        } else {
            // SAFETY: a live digest.
            unsafe { EVP_MD_meth_get_ctrl(md) }
        };
        if let Some(ctrl) = ctrl {
            let mut micstr: *mut c_char = ptr::null_mut();
            // SAFETY: the digest's own control, asked for its MIME name.
            let rv = unsafe {
                ctrl(
                    ptr::null_mut(),
                    EVP_MD_CTRL_MICALG,
                    0,
                    (&raw mut micstr).cast(),
                )
            };
            if rv > 0 {
                if !micstr.is_null() {
                    // SAFETY: the name the control made, a C string from CRYPTO_malloc.
                    write(out, unsafe { CStr::from_ptr(micstr) }.to_bytes());
                    // SAFETY: as above.
                    unsafe { crate::mem::release(micstr.cast()) };
                }
                continue;
            }
            if rv != -2 {
                return false;
            }
        }
        let name = match nid {
            n if n == NID_sha1 => Some("sha1"),
            n if n == NID_md5 => Some("md5"),
            n if n == NID_sha256 => Some("sha-256"),
            n if n == NID_sha384 => Some("sha-384"),
            n if n == NID_sha512 => Some("sha-512"),
            n if n == NID_id_GostR3411_94 => Some("gostr3411-94"),
            n if n == NID_id_GostR3411_2012_256 => Some("gostr3411-2012-256"),
            n if n == NID_id_GostR3411_2012_512 => Some("gostr3411-2012-512"),
            _ => None,
        };
        match name {
            Some(n) => puts(out, n),
            None if have_unknown => write_comma = false,
            None => {
                puts(out, "unknown");
                have_unknown = true;
            }
        }
    }
    true
}

/// `asn1_output_data`: the content, through the type's detached-signing chain if it has one.
///
/// # Safety
/// `out` and `data` are live BIOs; `val` a live value of `it`.
unsafe fn output_data(
    out: *mut BIO,
    data: *mut BIO,
    val: *mut ASN1_VALUE,
    flags: c_int,
    it: *const ASN1_ITEM,
) -> bool {
    if flags & SMIME_DETACHED == 0 || flags & PKCS7_REUSE_DIGEST != 0 {
        // SAFETY: the caller's BIOs.
        return unsafe { SMIME_crlf_copy(data, out, flags) } != 0;
    }
    let Some(cb) = stream_callback(it) else {
        err::raise(
            ERR_LIB_ASN1,
            ASN1_R_STREAMING_NOT_SUPPORTED,
            "asn1_output_data",
        );
        return false;
    };
    let mut sarg = ASN1_STREAM_ARG {
        out,
        ndef_bio: ptr::null_mut(),
        boundary: ptr::null_mut(),
    };
    let mut v = val;
    // SAFETY: the type's callback, with the caller's value and the stream.
    if unsafe { cb(ASN1_OP_DETACHED_PRE, &mut v, it, (&raw mut sarg).cast()) } <= 0 {
        return false;
    }
    // SAFETY: the caller's data; the chain.
    let mut rv = unsafe { SMIME_crlf_copy(data, sarg.ndef_bio, flags) } != 0;
    // SAFETY: as above.
    if unsafe { cb(ASN1_OP_DETACHED_POST, &mut v, it, (&raw mut sarg).cast()) } <= 0 {
        rv = false;
    }
    while !sarg.ndef_bio.is_null() && sarg.ndef_bio != out {
        // SAFETY: a BIO of the chain the callback made.
        let next = unsafe { BIO_pop(sarg.ndef_bio) };
        // SAFETY: as above, out of the chain.
        unsafe { BIO_free(sarg.ndef_bio) };
        sarg.ndef_bio = next;
    }
    rv
}

ffi_export! {
    /// Writes `val` as S/MIME to `bio`: multipart/signed with `data` as its first part for
    /// `SMIME_DETACHED`, otherwise an opaque `application/pkcs7-mime` part. 1, or 0.
    ///
    /// # Safety
    /// `bio` is a live BIO; `val` a live value of `it`; `data` and `mdalgs` NULL or live.
    pub unsafe extern "C" fn SMIME_write_ASN1_ex(bio: *mut BIO, val: *mut ASN1_VALUE, data: *mut BIO, flags: c_int, ctype_nid: c_int, econt_nid: c_int, mdalgs: *mut stack_st_X509_ALGOR, it: *const ASN1_ITEM, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        let _ = propq;
        let prefix = if flags & SMIME_OLDMIME != 0 { "application/x-pkcs7-" } else { "application/pkcs7-" };
        let eol = if flags & SMIME_CRLFEOL != 0 { "\r\n" } else { "\n" };
        if flags & SMIME_DETACHED != 0 && !data.is_null() {
            let mut raw = [0u8; 32];
            // SAFETY: room for 32 octets.
            if unsafe { RAND_bytes_ex(libctx, raw.as_mut_ptr(), raw.len(), 0) } <= 0 {
                return 0;
            }
            let bound: String = raw.iter().map(|b| char::from_digit(u32::from(b & 0xf), 16).unwrap_or('0').to_ascii_uppercase()).collect();
            puts(bio, &format!("MIME-Version: 1.0{eol}"));
            puts(bio, "Content-Type: multipart/signed;");
            puts(bio, &format!(" protocol=\"{prefix}signature\";"));
            puts(bio, " micalg=\"");
            if !write_micalg(bio, mdalgs) {
                return 0;
            }
            puts(bio, &format!("\"; boundary=\"----{bound}\"{eol}{eol}"));
            puts(bio, &format!("This is an S/MIME signed message{eol}{eol}"));
            puts(bio, &format!("------{bound}{eol}"));
            // SAFETY: the caller's guarantee.
            if !unsafe { output_data(bio, data, val, flags, it) } {
                return 0;
            }
            puts(bio, &format!("{eol}------{bound}{eol}"));
            puts(bio, &format!("Content-Type: {prefix}signature;"));
            puts(bio, &format!(" name=\"smime.p7s\"{eol}"));
            puts(bio, &format!("Content-Transfer-Encoding: base64{eol}"));
            puts(bio, "Content-Disposition: attachment;");
            puts(bio, &format!(" filename=\"smime.p7s\"{eol}{eol}"));
            // SAFETY: as above.
            unsafe { b64_write(bio, val, ptr::null_mut(), 0, it) };
            puts(bio, &format!("{eol}------{bound}--{eol}{eol}"));
            return 1;
        }
        let mut cname = "smime.p7m";
        let msg_type = match ctype_nid {
            n if n == NID_pkcs7_enveloped => Some("enveloped-data"),
            n if n == NID_id_smime_ct_authEnvelopedData => Some("authEnveloped-data"),
            n if n == NID_pkcs7_signed => {
                if econt_nid == NID_id_smime_ct_receipt {
                    Some("signed-receipt")
                // SAFETY: the digest algorithms, or NULL.
                } else if unsafe { OPENSSL_sk_num(mdalgs.cast()) } >= 0 {
                    Some("signed-data")
                } else {
                    Some("certs-only")
                }
            }
            n if n == NID_id_smime_ct_compressedData => {
                cname = "smime.p7z";
                Some("compressed-data")
            }
            _ => None,
        };
        puts(bio, &format!("MIME-Version: 1.0{eol}"));
        puts(bio, "Content-Disposition: attachment;");
        puts(bio, &format!(" filename=\"{cname}\"{eol}"));
        puts(bio, &format!("Content-Type: {prefix}mime;"));
        if let Some(t) = msg_type {
            puts(bio, &format!(" smime-type={t};"));
        }
        puts(bio, &format!(" name=\"{cname}\"{eol}"));
        puts(bio, &format!("Content-Transfer-Encoding: base64{eol}{eol}"));
        // SAFETY: as above.
        if unsafe { b64_write(bio, val, data, flags, it) } == 0 {
            return 0;
        }
        puts(bio, eol);
        1
    }
}

ffi_export! {
    /// [`SMIME_write_ASN1_ex`] in the default library context.
    ///
    /// # Safety
    /// As for [`SMIME_write_ASN1_ex`].
    pub unsafe extern "C" fn SMIME_write_ASN1(bio: *mut BIO, val: *mut ASN1_VALUE, data: *mut BIO, flags: c_int, ctype_nid: c_int, econt_nid: c_int, mdalgs: *mut stack_st_X509_ALGOR, it: *const ASN1_ITEM) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { SMIME_write_ASN1_ex(bio, val, data, flags, ctype_nid, econt_nid, mdalgs, it, ptr::null_mut(), ptr::null()) }
    }
}

/// `mime_bound_check`: 1 for a part boundary, 2 for the closing one, 0 otherwise.
fn bound_check(line: &[u8], bound: &[u8]) -> c_int {
    let Some(blen) = bound.len().checked_add(2) else {
        return 0;
    };
    if blen > line.len() {
        return 0;
    }
    let Some(rest) = line.strip_prefix(b"--") else {
        return 0;
    };
    let Some(after) = rest.strip_prefix(bound) else {
        return 0;
    };
    if after.starts_with(b"--") { 2 } else { 1 }
}

/// Frees parts made by [`multi_split`].
fn free_parts(parts: Vec<*mut BIO>) {
    for p in parts {
        // SAFETY: a part made here, or NULL.
        unsafe { BIO_free(p) };
    }
}

/// `multi_split`: the parts of a multipart body between `--bound` lines, each a memory BIO,
/// up to the closing boundary, or `None`.
fn multi_split(bio: *mut BIO, flags: c_int, bound: &[u8]) -> Option<Vec<*mut BIO>> {
    let mut parts = Vec::new();
    let mut bpart: *mut BIO = ptr::null_mut();
    let (mut part, mut first, mut eol) = (0u32, true, false);
    let mut line = [0u8; LINE_ROOM];
    let room = c_int::try_from(LINE_ROOM).unwrap_or(0);
    loop {
        // SAFETY: the caller's BIO; room for a line.
        let len = unsafe { BIO_get_line(bio, line.as_mut_ptr().cast(), room) };
        let Some(text) = usize::try_from(len)
            .ok()
            .filter(|&n| n > 0)
            .and_then(|n| line.get(..n.min(MAX_LINE)))
        else {
            break;
        };
        // `strncmp` stops at a NUL, which never matches the boundary.
        let cstr = text.split(|&c| c == 0).next().unwrap_or_default();
        match bound_check(cstr, bound) {
            1 => {
                first = true;
                part = part.saturating_add(1);
            }
            2 => {
                parts.push(bpart);
                return Some(parts);
            }
            _ if part != 0 => {
                let (n, next_eol) = strip_eol(text, flags);
                if first {
                    first = false;
                    if !bpart.is_null() {
                        parts.push(bpart);
                    }
                    bpart = crate::pkcs7::doit::mem_bio();
                    if bpart.is_null() {
                        free_parts(parts);
                        return None;
                    }
                } else if eol {
                    if flags & CMS_BINARY == 0 || flags & SMIME_CRLFEOL != 0 {
                        write(bpart, b"\r\n");
                    } else {
                        write(bpart, b"\n");
                    }
                }
                eol = next_eol;
                write(bpart, text.get(..n).unwrap_or_default());
            }
            _ => {}
        }
    }
    // SAFETY: the part being filled, or NULL.
    unsafe { BIO_free(bpart) };
    free_parts(parts);
    None
}

/// `b64_read_asn1`: a base64-encoded DER value.
///
/// # Safety
/// `bio` is a live BIO; the others as for `ASN1_item_d2i_bio_ex`.
unsafe fn b64_read(
    bio: *mut BIO,
    it: *const ASN1_ITEM,
    x: *mut *mut ASN1_VALUE,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> *mut ASN1_VALUE {
    // SAFETY: no preconditions.
    let method = unsafe { BIO_f_base64() };
    // SAFETY: the built-in method.
    let b64 = unsafe { BIO_new(method) };
    if b64.is_null() {
        err::raise(ERR_LIB_ASN1, ERR_R_BIO_LIB, "b64_read_asn1");
        return ptr::null_mut();
    }
    // SAFETY: live BIOs; the filter goes in front.
    let chain = unsafe { BIO_push(b64, bio) };
    // SAFETY: the caller's guarantee.
    let val =
        unsafe { ASN1_item_d2i_bio_ex(it, chain, x.cast(), libctx, propq) }.cast::<ASN1_VALUE>();
    if val.is_null() {
        err::raise(ERR_LIB_ASN1, ASN1_R_DECODE_ERROR, "b64_read_asn1");
    }
    flush(chain);
    // SAFETY: the filter leaves the caller's BIO.
    unsafe { BIO_pop(chain) };
    // SAFETY: the filter made here.
    unsafe { BIO_free(b64) };
    val
}

fn raise_type(reason: c_int, f: &str, value: &[u8]) {
    let mut text = b"type: ".to_vec();
    text.extend_from_slice(value);
    err::raise_with_bytes(ERR_LIB_ASN1, reason, f, &text);
}

ffi_export! {
    /// Reads an S/MIME message: multipart/signed (the signature decoded, the content's part
    /// to `*bcont`) or an opaque `application/pkcs7-mime` part. The value, or NULL.
    ///
    /// # Safety
    /// `bio` is a live BIO; `bcont` NULL or room for a BIO; `x` as for `d2i_*`.
    pub unsafe extern "C" fn SMIME_read_ASN1_ex(bio: *mut BIO, flags: c_int, bcont: *mut *mut BIO, it: *const ASN1_ITEM, x: *mut *mut ASN1_VALUE, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut ASN1_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        const F: &str = "SMIME_read_ASN1_ex";
        // SAFETY: the caller's room, or NULL.
        if let Some(b) = unsafe { bcont.as_mut() } {
            *b = ptr::null_mut();
        }
        let Some(headers) = parse_headers(bio) else {
            err::raise(ERR_LIB_ASN1, ASN1_R_MIME_PARSE_ERROR, F);
            return ptr::null_mut();
        };
        let Some(hdr) = headers.find(b"content-type").filter(|h| h.value.is_some()) else {
            err::raise(ERR_LIB_ASN1, ASN1_R_NO_CONTENT_TYPE, F);
            return ptr::null_mut();
        };
        let value = hdr.value.as_deref().unwrap_or_default();
        if value == b"multipart/signed" {
            let Some(bound) = hdr.param(b"boundary").and_then(|p| p.value.clone()) else {
                err::raise(ERR_LIB_ASN1, ASN1_R_NO_MULTIPART_BOUNDARY, F);
                return ptr::null_mut();
            };
            let parts = match multi_split(bio, flags, &bound) {
                Some(p) if p.len() == 2 => p,
                other => {
                    err::raise(ERR_LIB_ASN1, ASN1_R_NO_MULTIPART_BODY_FAILURE, F);
                    free_parts(other.unwrap_or_default());
                    return ptr::null_mut();
                }
            };
            let (Some(&content), Some(&asnin)) = (parts.first(), parts.get(1)) else {
                free_parts(parts);
                return ptr::null_mut();
            };
            let Some(sig_headers) = parse_headers(asnin) else {
                err::raise(ERR_LIB_ASN1, ASN1_R_MIME_SIG_PARSE_ERROR, F);
                free_parts(parts);
                return ptr::null_mut();
            };
            let Some(sig) = sig_headers.find(b"content-type").and_then(|h| h.value.as_deref()) else {
                err::raise(ERR_LIB_ASN1, ASN1_R_NO_SIG_CONTENT_TYPE, F);
                free_parts(parts);
                return ptr::null_mut();
            };
            if sig != b"application/x-pkcs7-signature" && sig != b"application/pkcs7-signature" {
                raise_type(ASN1_R_SIG_INVALID_MIME_TYPE, F, sig);
                free_parts(parts);
                return ptr::null_mut();
            }
            // SAFETY: the signature's part; the caller's guarantee.
            let val = unsafe { b64_read(asnin, it, x, libctx, propq) };
            if val.is_null() {
                err::raise(ERR_LIB_ASN1, ASN1_R_ASN1_SIG_PARSE_ERROR, F);
                free_parts(parts);
                return ptr::null_mut();
            }
            // SAFETY: as above.
            if let Some(b) = unsafe { bcont.as_mut() } {
                *b = content;
                // SAFETY: the signature's part, read.
                unsafe { BIO_free(asnin) };
            } else {
                free_parts(parts);
            }
            return val;
        }
        if value != b"application/x-pkcs7-mime" && value != b"application/pkcs7-mime" {
            raise_type(ASN1_R_INVALID_MIME_TYPE, F, value);
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let val = unsafe { b64_read(bio, it, x, libctx, propq) };
        if val.is_null() {
            err::raise(ERR_LIB_ASN1, ASN1_R_ASN1_PARSE_ERROR, F);
        }
        val
    }
}

ffi_export! {
    /// [`SMIME_read_ASN1_ex`] in the default library context.
    ///
    /// # Safety
    /// As for [`SMIME_read_ASN1_ex`].
    pub unsafe extern "C" fn SMIME_read_ASN1(bio: *mut BIO, bcont: *mut *mut BIO, it: *const ASN1_ITEM) -> *mut ASN1_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { SMIME_read_ASN1_ex(bio, 0, bcont, it, ptr::null_mut(), ptr::null_mut(), ptr::null()) }
    }
}
