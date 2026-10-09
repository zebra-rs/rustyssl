//! `ASN1_parse(3)` and `ASN1_parse_dump`: the `openssl asn1parse` listing of BER, one line per
//! element (offset, depth, header and content lengths, the tag, and for primitives a rendering
//! of the content), as OpenSSL's `asn1_parse.c` writes it, byte for byte.
//!
//! The input is one slice from the caller's pointer and length, every element is read within
//! what its parents allow, and nesting stops at OpenSSL's 128 levels. The line prefix goes
//! through a prefix BIO (`BIO_f_prefix`), pushed onto the caller's BIO unless it is one, as in
//! OpenSSL, so indentation and an existing prefix behave the same.

use core::ffi::{CStr, c_int, c_long, c_uchar, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    ASN1_OBJECT, ASN1_STRING, BIO, BIO_CTRL_GET_INDENT, BIO_CTRL_SET_INDENT, BIO_CTRL_SET_PREFIX,
    ERR_LIB_ASN1, V_ASN1_APPLICATION, V_ASN1_BMPSTRING, V_ASN1_BOOLEAN, V_ASN1_CONSTRUCTED,
    V_ASN1_CONTEXT_SPECIFIC, V_ASN1_ENUMERATED, V_ASN1_EOC, V_ASN1_GENERALIZEDTIME,
    V_ASN1_IA5STRING, V_ASN1_INTEGER, V_ASN1_NEG_ENUMERATED, V_ASN1_NEG_INTEGER,
    V_ASN1_NUMERICSTRING, V_ASN1_OBJECT, V_ASN1_OCTET_STRING, V_ASN1_PRINTABLESTRING,
    V_ASN1_PRIVATE, V_ASN1_T61STRING, V_ASN1_UTCTIME, V_ASN1_UTF8STRING, V_ASN1_VISIBLESTRING,
};

use super::text::ASN1_tag2str;
use super::tpl::items::{d2i_ASN1_ENUMERATED, d2i_ASN1_INTEGER, d2i_ASN1_OCTET_STRING};
use super::{read_header_in, string};
use crate::bio;
use crate::ffi::ffi_export;
use crate::objects;

/// The deepest nesting `asn1_parse2` follows (`ASN1_PARSE_MAXDEPTH`).
const MAX_DEPTH: c_int = 128;

/// The indent `BIO_dump_indent` gets for content dumps.
const DUMP_INDENT: c_int = 6;

/// `BIO_write` of `data`: its result.
///
/// # Safety
/// `bp` is NULL or a live BIO.
unsafe fn write(bp: *mut BIO, data: &[u8]) -> c_int {
    let n = c_int::try_from(data.len()).unwrap_or(c_int::MAX);
    // SAFETY: the caller's BIO; `data` holds `n` octets.
    unsafe { bio::BIO_write(bp, data.as_ptr().cast(), n) }
}

/// `BIO_puts` of `s`: its result.
///
/// # Safety
/// `bp` is NULL or a live BIO.
unsafe fn puts(bp: *mut BIO, s: &CStr) -> c_int {
    // SAFETY: the caller's BIO; a string.
    unsafe { bio::BIO_puts(bp, s.as_ptr()) }
}

/// `BIO_ctrl`.
///
/// # Safety
/// `bp` is NULL or a live BIO; `parg` is what `cmd` takes.
unsafe fn ctrl(bp: *mut BIO, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long {
    // SAFETY: the caller's guarantee.
    unsafe { bio::BIO_ctrl(bp, cmd, larg, parg) }
}

/// `asn1_print_info`: the element's line prefix (offset, depth, lengths, primitive or
/// constructed) through a prefix BIO with `indent`, then its tag, padded to 18 columns.
///
/// # Safety
/// `bp` is NULL or a live BIO.
#[expect(clippy::too_many_arguments, reason = "OpenSSL's signature")]
unsafe fn print_info(
    bp: *mut BIO,
    offset: c_long,
    depth: c_int,
    hl: c_int,
    len: c_long,
    tag: c_int,
    xclass: c_int,
    constructed: c_int,
    indent: c_int,
) -> c_int {
    let kind = if constructed & V_ASN1_CONSTRUCTED != 0 {
        "cons: "
    } else {
        "prim: "
    };
    let prefix = if constructed == (V_ASN1_CONSTRUCTED | 1) {
        format!("{offset:5}:d={depth:<2} hl={hl} l=inf  {kind}")
    } else {
        format!("{offset:5}:d={depth:<2} hl={hl} l={len:4} {kind}")
    };
    let Ok(prefix) = CString::new(prefix) else {
        return 0;
    };
    let mut bp = bp;
    let mut pushed: *mut BIO = ptr::null_mut();
    let mut saved_indent: c_long = -1;
    let mut i = 0;
    'done: {
        if !bp.is_null() {
            // SAFETY: the caller's BIO; the prefix is copied.
            if unsafe {
                ctrl(
                    bp,
                    BIO_CTRL_SET_PREFIX,
                    0,
                    prefix.as_ptr().cast_mut().cast(),
                )
            } <= 0
            {
                // SAFETY: no preconditions.
                let method = unsafe { bio::prefix::BIO_f_prefix() };
                // SAFETY: the built-in method.
                pushed = unsafe { bio::BIO_new(method) };
                if pushed.is_null() {
                    break 'done;
                }
                // SAFETY: a new BIO onto the caller's.
                bp = unsafe { bio::BIO_push(pushed, bp) };
                if bp.is_null() {
                    break 'done;
                }
            }
            // SAFETY: a live BIO.
            saved_indent = unsafe { ctrl(bp, BIO_CTRL_GET_INDENT, 0, ptr::null_mut()) };
            // SAFETY: as above.
            if unsafe { ctrl(bp, BIO_CTRL_SET_PREFIX, 0, prefix.as_ptr().cast_mut().cast()) } <= 0
                // SAFETY: as above.
                || unsafe { ctrl(bp, BIO_CTRL_SET_INDENT, c_long::from(indent), ptr::null_mut()) } <= 0
            {
                break 'done;
            }
        }
        let tag_text: Vec<u8> = if xclass & V_ASN1_PRIVATE == V_ASN1_PRIVATE {
            format!("priv [ {tag} ] ").into_bytes()
        } else if xclass & V_ASN1_CONTEXT_SPECIFIC == V_ASN1_CONTEXT_SPECIFIC {
            format!("cont [ {tag} ]").into_bytes()
        } else if xclass & V_ASN1_APPLICATION == V_ASN1_APPLICATION {
            format!("appl [ {tag} ]").into_bytes()
        } else if tag > 30 {
            format!("<ASN1 {tag}>").into_bytes()
        } else {
            // SAFETY: no preconditions.
            let name = unsafe { ASN1_tag2str(tag) };
            // SAFETY: a static string.
            unsafe { CStr::from_ptr(name) }.to_bytes().to_vec()
        };
        let mut padded = tag_text;
        while padded.len() < 18 {
            padded.push(b' ');
        }
        // SAFETY: as above.
        i = c_int::from(unsafe { write(bp, &padded) } > 0);
    }
    if saved_indent >= 0 {
        // SAFETY: as above.
        unsafe { ctrl(bp, BIO_CTRL_SET_INDENT, saved_indent, ptr::null_mut()) };
    }
    if !pushed.is_null() {
        // SAFETY: the BIO pushed above, the chain's head.
        unsafe { bio::BIO_pop(bp) };
    }
    // SAFETY: the BIO pushed above, or NULL.
    unsafe { bio::BIO_free(pushed) };
    i
}

/// Uppercase hex of `octets`, as `%02X` each.
fn upper_hex(octets: &[u8]) -> Vec<u8> {
    octets
        .iter()
        .flat_map(|b| format!("{b:02X}").into_bytes())
        .collect()
}

/// Whether OpenSSL prints an OCTET STRING's octets as text.
fn printable(octets: &[u8]) -> bool {
    octets
        .iter()
        .all(|&c| !((c < b' ' && c != b'\n' && c != b'\r' && c != b'\t') || c > b'~'))
}

/// A string's octets, none for NULL data or a non-positive length.
///
/// # Safety
/// `s` is a live string whose data holds its length.
unsafe fn octets<'a>(s: *const ASN1_STRING) -> &'a [u8] {
    // SAFETY: the caller's guarantee.
    let s = unsafe { &*s };
    match usize::try_from(s.length) {
        // SAFETY: as above.
        Ok(n) if n > 0 && !s.data.is_null() => unsafe { core::slice::from_raw_parts(s.data, n) },
        _ => &[],
    }
}

/// What a parse step leaves: 0 to stop (error), 1 for the input read, 2 at an end-of-contents.
type Ret = c_int;

/// The content of one primitive element (`asn1_parse2`'s primitive branch): returns false to
/// stop.
///
/// # Safety
/// `bp` is NULL or a live BIO; `o` is a slot for the object reused across elements.
#[expect(clippy::too_many_arguments, reason = "the state of asn1_parse2's loop")]
unsafe fn primitive(
    bp: *mut BIO,
    element: &[u8],
    hl: usize,
    content: &[u8],
    tag: c_int,
    dump: c_int,
    o: &mut *mut ASN1_OBJECT,
    len: c_long,
) -> bool {
    let mut nl = false;
    let mut dump_cont = false;
    let whole_len = c_long::try_from(element.len()).unwrap_or(c_long::MAX);
    let mut opp = element.as_ptr();
    let dump_len = |n: usize| -> c_int {
        let n = c_int::try_from(n).unwrap_or(c_int::MAX);
        if dump == -1 || dump > n { n } else { dump }
    };
    match tag {
        V_ASN1_PRINTABLESTRING
        | V_ASN1_T61STRING
        | V_ASN1_IA5STRING
        | V_ASN1_VISIBLESTRING
        | V_ASN1_NUMERICSTRING
        | V_ASN1_UTF8STRING
        | V_ASN1_UTCTIME
        | V_ASN1_GENERALIZEDTIME => {
            // SAFETY: the caller's BIO.
            if unsafe { write(bp, b":") } <= 0 {
                return false;
            }
            let want = c_int::try_from(content.len()).unwrap_or(-1);
            // SAFETY: as above.
            if !content.is_empty() && unsafe { write(bp, content) } != want {
                return false;
            }
        }
        V_ASN1_OBJECT => {
            // SAFETY: the reused slot; the element's octets.
            if unsafe { objects::d2i_ASN1_OBJECT(&raw mut *o, &raw mut opp, whole_len) }.is_null() {
                // SAFETY: the caller's BIO.
                if unsafe { puts(bp, c":BAD OBJECT") } <= 0 {
                    return false;
                }
                dump_cont = true;
            } else {
                // SAFETY: as above.
                if unsafe { write(bp, b":") } <= 0 {
                    return false;
                }
                // SAFETY: a live object.
                unsafe { objects::i2a_ASN1_OBJECT(bp, *o) };
            }
        }
        V_ASN1_BOOLEAN => {
            if content.len() != 1 {
                // SAFETY: the caller's BIO.
                if unsafe { puts(bp, c":BAD BOOLEAN") } <= 0 {
                    return false;
                }
                dump_cont = true;
            }
            if let Some(first) = content.first() {
                // SAFETY: as above.
                unsafe { write(bp, format!(":{first}").as_bytes()) };
            }
        }
        V_ASN1_BMPSTRING => {}
        V_ASN1_OCTET_STRING => {
            // SAFETY: the element's octets.
            let os = unsafe { d2i_ASN1_OCTET_STRING(ptr::null_mut(), &raw mut opp, whole_len) };
            if !os.is_null() {
                // SAFETY: a live string.
                let data = unsafe { octets(os) };
                let ok = if data.is_empty() {
                    true
                } else if printable(data) {
                    // SAFETY: the caller's BIO.
                    (unsafe { write(bp, b":") }) > 0 && (unsafe { write(bp, data) }) > 0
                } else if dump == 0 {
                    // SAFETY: as above.
                    (unsafe { write(bp, b"[HEX DUMP]:") }) > 0
                        && (unsafe { write(bp, &upper_hex(data)) }) > 0
                } else {
                    // SAFETY: as above.
                    let ok = (nl || unsafe { write(bp, b"\n") } > 0)
                        // SAFETY: as above; the string's octets.
                        && unsafe { bio::dump::BIO_dump_indent(bp, data.as_ptr().cast(), dump_len(data.len()), DUMP_INDENT) } > 0;
                    nl = true;
                    ok
                };
                // SAFETY: the string decoded above.
                unsafe { string::ASN1_STRING_free(os) };
                if !ok {
                    return false;
                }
            }
        }
        V_ASN1_INTEGER | V_ASN1_ENUMERATED => {
            let (decoded, negative, bad) = if tag == V_ASN1_INTEGER {
                // SAFETY: the element's octets.
                (
                    unsafe { d2i_ASN1_INTEGER(ptr::null_mut(), &raw mut opp, whole_len) },
                    V_ASN1_NEG_INTEGER,
                    c":BAD INTEGER",
                )
            } else {
                // SAFETY: as above.
                (
                    unsafe { d2i_ASN1_ENUMERATED(ptr::null_mut(), &raw mut opp, whole_len) },
                    V_ASN1_NEG_ENUMERATED,
                    c":BAD ENUMERATED",
                )
            };
            if decoded.is_null() {
                // SAFETY: the caller's BIO.
                if unsafe { puts(bp, bad) } <= 0 {
                    return false;
                }
                dump_cont = true;
            } else {
                // SAFETY: a live string.
                let kind = unsafe { (*decoded).type_ };
                // SAFETY: as above.
                let data = unsafe { octets(decoded) };
                let mut text = b":".to_vec();
                if kind == negative {
                    text.push(b'-');
                }
                text.extend(upper_hex(data));
                if data.is_empty() {
                    text.extend_from_slice(b"00");
                }
                // SAFETY: the string decoded above.
                unsafe { string::ASN1_STRING_free(decoded) };
                // SAFETY: the caller's BIO.
                if unsafe { write(bp, &text) } <= 0 {
                    return false;
                }
            }
        }
        _ => {
            if !content.is_empty() && dump != 0 {
                // SAFETY: the caller's BIO.
                let ok = (nl || unsafe { write(bp, b"\n") } > 0)
                    // SAFETY: as above; the content's octets.
                    && unsafe { bio::dump::BIO_dump_indent(bp, content.as_ptr().cast(), dump_len(content.len()), DUMP_INDENT) } > 0;
                if !ok {
                    return false;
                }
                nl = true;
            }
        }
    }
    if dump_cont {
        let shown = element.get(hl..).unwrap_or(&[]);
        let shown = shown
            .get(..usize::try_from(len).unwrap_or(0))
            .unwrap_or(shown);
        // SAFETY: the caller's BIO.
        if unsafe { puts(bp, c":[") } <= 0 {
            return false;
        }
        // SAFETY: as above.
        if !shown.is_empty() && unsafe { write(bp, &upper_hex(shown)) } <= 0 {
            return false;
        }
        // SAFETY: as above.
        if unsafe { puts(bp, c"]") } <= 0 {
            return false;
        }
    }
    // SAFETY: as above.
    if !nl && unsafe { write(bp, b"\n") } <= 0 {
        return false;
    }
    true
}

/// `asn1_parse2`: lists the elements of `input` (all of it OpenSSL's `length`), moving it
/// past what was read. `base` is where the offsets count from, less `offset`.
///
/// # Safety
/// `bp` is NULL or a live BIO.
unsafe fn parse2(
    bp: *mut BIO,
    input: &mut &[u8],
    offset: c_int,
    depth: c_int,
    indent: c_int,
    dump: c_int,
) -> Ret {
    if depth > MAX_DEPTH {
        // SAFETY: the caller's BIO.
        unsafe { puts(bp, c"BAD RECURSION DEPTH\n") };
        return 0;
    }
    let start = *input;
    let mut p = *input;
    let mut o: *mut ASN1_OBJECT = ptr::null_mut();
    let at = |p: &[u8]| -> c_int {
        let used = p.as_ptr().addr().wrapping_sub(start.as_ptr().addr());
        offset.wrapping_add(c_int::try_from(used).unwrap_or(c_int::MAX))
    };
    let ret = 'end: {
        while !p.is_empty() {
            let op = p;
            let header = read_header_in(p);
            let h = match header {
                Ok(h) if !h.overrun => h,
                result => {
                    if let Ok(h) = result {
                        p = p.get(h.header_len..).unwrap_or(&[]);
                    }
                    // SAFETY: the caller's BIO.
                    unsafe { puts(bp, c"Error in encoding\n") };
                    break 'end 0;
                }
            };
            let j =
                (if h.constructed { V_ASN1_CONSTRUCTED } else { 0 }) | c_int::from(h.indefinite);
            let hl = h.header_len;
            p = p.get(hl..).unwrap_or(&[]);
            let mut len = c_long::try_from(h.length).unwrap_or(c_long::MAX);
            let tag = h.tag;
            let xclass = c_int::from(h.class);
            let hl_int = c_int::try_from(hl).unwrap_or(c_int::MAX);
            // SAFETY: the caller's BIO.
            if unsafe {
                print_info(
                    bp,
                    c_long::from(at(op)),
                    depth,
                    hl_int,
                    len,
                    tag,
                    xclass,
                    j,
                    if indent != 0 { depth } else { 0 },
                )
            } == 0
            {
                break 'end 0;
            }
            let length = c_long::try_from(p.len()).unwrap_or(c_long::MAX);
            if j & V_ASN1_CONSTRUCTED != 0 {
                // SAFETY: as above.
                if unsafe { write(bp, b"\n") } <= 0 {
                    break 'end 0;
                }
                if len > length {
                    // SAFETY: as above.
                    unsafe { write(bp, format!("length is greater than {length}\n").as_bytes()) };
                    break 'end 0;
                }
                let sp = p;
                if j == 0x21 && len == 0 {
                    loop {
                        let mut rest = p;
                        // SAFETY: as above.
                        let r = unsafe {
                            parse2(bp, &mut rest, at(p), depth.wrapping_add(1), indent, dump)
                        };
                        p = rest;
                        if r == 0 {
                            break 'end 0;
                        }
                        if r == 2 || p.is_empty() {
                            len = c_long::try_from(sp.len().wrapping_sub(p.len()))
                                .unwrap_or(c_long::MAX);
                            break;
                        }
                    }
                } else {
                    let n = usize::try_from(len).unwrap_or(0);
                    let mut inner = p.get(..n).unwrap_or(p);
                    while !inner.is_empty() {
                        let here = at(inner);
                        // SAFETY: as above.
                        let r = unsafe {
                            parse2(bp, &mut inner, here, depth.wrapping_add(1), indent, dump)
                        };
                        if r == 0 {
                            p = p.get(n.wrapping_sub(inner.len())..).unwrap_or(&[]);
                            break 'end 0;
                        }
                    }
                    p = p.get(n..).unwrap_or(&[]);
                }
            } else if xclass != 0 {
                p = p.get(usize::try_from(len).unwrap_or(0)..).unwrap_or(&[]);
                // SAFETY: as above.
                if unsafe { write(bp, b"\n") } <= 0 {
                    break 'end 0;
                }
            } else {
                let n = usize::try_from(len).unwrap_or(0);
                let content = p.get(..n).unwrap_or(p);
                let element = op.get(..hl.wrapping_add(n)).unwrap_or(op);
                // SAFETY: as above.
                if !unsafe { primitive(bp, element, hl, content, tag, dump, &mut o, len) } {
                    break 'end 0;
                }
                p = p.get(n..).unwrap_or(&[]);
                if tag == V_ASN1_EOC && xclass == 0 {
                    break 'end 2;
                }
            }
        }
        1
    };
    // SAFETY: the object decoded along the way, or NULL.
    unsafe { objects::ASN1_OBJECT_free(o) };
    *input = p;
    ret
}

/// The input `pp` and `len` describe, as a slice; empty for NULL or a non-positive length.
///
/// # Safety
/// `pp` is NULL or valid for reads of `len` octets.
unsafe fn input<'a>(pp: *const c_uchar, len: c_long) -> &'a [u8] {
    match usize::try_from(len) {
        // SAFETY: the caller's guarantee.
        Ok(n) if n > 0 && !pp.is_null() && isize::try_from(n).is_ok() => unsafe {
            core::slice::from_raw_parts(pp, n)
        },
        _ => &[],
    }
}

ffi_export! {
    /// Writes the `asn1parse` listing of `len` octets at `pp` to `bp`, indenting nested
    /// elements if `indent`. Returns 1, 2 if it stopped at an end-of-contents at the top, or 0
    /// on bad input or a failed write.
    ///
    /// # Safety
    /// `bp` is NULL or a live BIO; `pp` holds `len` octets.
    pub unsafe extern "C" fn ASN1_parse(bp: *mut BIO, pp: *const c_uchar, len: c_long, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let mut p = unsafe { input(pp, len) };
        // SAFETY: as above.
        unsafe { parse2(bp, &mut p, 0, 0, indent, 0) }
    }
}

ffi_export! {
    /// `ASN1_parse`, dumping the content of unprintable primitives: up to `dump` octets, or all
    /// with -1 (0 for none, writing OCTET STRINGs in hex).
    ///
    /// # Safety
    /// As for `ASN1_parse`.
    pub unsafe extern "C" fn ASN1_parse_dump(bp: *mut BIO, pp: *const c_uchar, len: c_long, indent: c_int, dump: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let mut p = unsafe { input(pp, len) };
        // SAFETY: as above.
        unsafe { parse2(bp, &mut p, 0, 0, indent, dump) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lists `input` to a memory BIO: the return and the text.
    fn list(input: &[u8], indent: c_int, dump: c_int) -> (c_int, String) {
        // SAFETY: no preconditions.
        let method = unsafe { bio::mem::BIO_s_mem() };
        // SAFETY: the built-in method.
        let mem = unsafe { bio::BIO_new(method) };
        let len = c_long::try_from(input.len()).unwrap();
        // SAFETY: a memory BIO; `input` holds `len` octets.
        let r = unsafe { ASN1_parse_dump(mem, input.as_ptr(), len, indent, dump) };
        let mut out = vec![0u8; 4096];
        // SAFETY: as above, with room for 4096 octets.
        let n = unsafe { bio::BIO_read(mem, out.as_mut_ptr().cast(), 4096) };
        out.truncate(usize::try_from(n.max(0)).unwrap());
        // SAFETY: the BIO made above.
        unsafe { bio::BIO_free(mem) };
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
        (r, String::from_utf8_lossy(&out).into_owned())
    }

    #[test]
    fn listings() {
        let (r, text) = list(&[0x30, 0x06, 0x02, 0x01, 0x05, 0x04, 0x01, 0x41], 1, 0);
        assert_eq!(r, 1);
        assert_eq!(
            text,
            "    0:d=0  hl=2 l=   6 cons: SEQUENCE          \n    2:d=1  hl=2 l=   1 prim:  INTEGER           :05\n    5:d=1  hl=2 l=   1 prim:  OCTET STRING      :A\n"
        );
        let (r, text) = list(&[0x30, 0x80, 0x04, 0x02, 0x00, 0xff, 0x00, 0x00], 0, -1);
        assert_eq!(r, 1);
        assert!(text.contains("0000 - 00 ff"));
        assert_eq!(list(&[0x04, 0x05, 0x61], 0, 0).0, 0);
        assert_eq!(list(&[0x30, 0x80].repeat(130), 0, 0).0, 0);
    }
}
