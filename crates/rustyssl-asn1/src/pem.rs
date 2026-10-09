//! PEM framing as OpenSSL's `PEM_read_bio_ex` reads it (`crypto/pem/pem_lib.c`): lines of at
//! most 254 characters, a `-----BEGIN name-----` line after any others, an optional header
//! ended by a blank line, base64 lines, and a matching `-----END name-----`. The caller reads
//! the lines (`BIO_gets` into a 256-octet buffer) and hands each to [`sanitize_line`],
//! [`begin_name`], and [`Body::line`]; [`Body::finish`] decodes the base64.
//!
//! Lines are handled as OpenSSL handles them, C strings and all: a NUL in a line ends what
//! comparisons and copies see, and the default (`PEM_FLAG_EAY_COMPATIBLE`) trimming compares
//! each trailing character with `' '` as a C `char`, which is signed on some platforms and not
//! on others, so octets from 0x80 are trimmed on the former only, as in OpenSSL.

use core::ffi::c_char;

use crate::base64::Ctx;

/// `PEM_FLAG_SECURE`.
pub const FLAG_SECURE: u32 = rustyssl_abi::PEM_FLAG_SECURE.cast_unsigned();
/// `PEM_FLAG_EAY_COMPATIBLE`: trim trailing whitespace (and, with a signed `char`, octets
/// from 0x80).
pub const FLAG_EAY_COMPATIBLE: u32 = rustyssl_abi::PEM_FLAG_EAY_COMPATIBLE.cast_unsigned();
/// `PEM_FLAG_ONLY_B64`: keep only the base64 characters a data line starts with.
pub const FLAG_ONLY_B64: u32 = rustyssl_abi::PEM_FLAG_ONLY_B64.cast_unsigned();

/// The size `BIO_gets` is given (`LINESIZE`): lines of up to 254 characters.
pub const LINESIZE: usize = 255;

/// The line buffer: `LINESIZE + 1` octets, room for the newline sanitizing adds.
pub type Line = [u8; LINESIZE + 1];

const BEGINSTR: &[u8] = b"-----BEGIN ";
const ENDSTR: &[u8] = b"-----END ";
const TAILSTR: &[u8] = b"-----\n";

/// Why reading PEM failed: OpenSSL's reasons, or none (`Silent`) where it raises none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// `PEM_R_NO_START_LINE`.
    NoStartLine,
    /// `PEM_R_BAD_END_LINE`.
    BadEndLine,
    /// `PEM_R_BAD_BASE64_DECODE`.
    BadBase64Decode,
    /// A failure OpenSSL reports without an error: an encrypted line longer than 64, or no
    /// data.
    Silent,
}

/// `ossl_isbase64`.
fn is_base64(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=')
}

/// `ossl_iscntrl`.
fn is_cntrl(c: u8) -> bool {
    c < 0x20 || c == 0x7f
}

/// `c <= ' '` for a C `char` holding `c`.
fn char_le_space(c: u8) -> bool {
    c_char::from_ne_bytes([c]) <= c_char::from_ne_bytes(*b" ")
}

/// `sanitize_line`: trims or filters the `len` characters `BIO_gets` read into `line` (a BOM
/// dropped from the first line), ends them with `'\n'` and a NUL, and returns the new length.
pub fn sanitize_line(line: &mut Line, len: usize, flags: u32, first_call: bool) -> usize {
    let mut len = len.min(LINESIZE - 1);
    if first_call && len > 3 && line.starts_with(&[0xEF, 0xBB, 0xBF]) {
        line.copy_within(3..len, 0);
        len = len.wrapping_sub(3);
        if let Some(c) = line.get_mut(len) {
            *c = 0;
        }
    }
    if flags & FLAG_EAY_COMPATIBLE != 0 {
        // From the NUL BIO_gets wrote, back over whitespace.
        let mut end = Some(len);
        while let Some(i) = end {
            if !line.get(i).is_some_and(|&c| char_le_space(c)) {
                break;
            }
            end = i.checked_sub(1);
        }
        len = end.map_or(0, |i| i.wrapping_add(1));
    } else if flags & FLAG_ONLY_B64 != 0 {
        len = line
            .iter()
            .take(len)
            .take_while(|&&c| is_base64(c) && c != b'\n' && c != b'\r')
            .count();
    } else {
        let mut i = 0;
        while i < len {
            let Some(c) = line.get_mut(i) else { break };
            if *c == b'\n' || *c == b'\r' {
                break;
            }
            if is_cntrl(*c) {
                *c = b' ';
            }
            i = i.wrapping_add(1);
        }
        len = i;
    }
    if let Some(c) = line.get_mut(len) {
        *c = b'\n';
    }
    len = len.wrapping_add(1);
    if let Some(c) = line.get_mut(len) {
        *c = 0;
    }
    len
}

/// The line as C string functions see it: up to its first NUL.
fn c_str(line: &[u8]) -> &[u8] {
    let end = line.iter().position(|&c| c == 0).unwrap_or(line.len());
    line.get(..end).unwrap_or(line)
}

/// `get_name`'s test of a sanitized line of `len`: the name OpenSSL copies out (with the NUL
/// it puts after it, so as a C string up to the first NUL) if it's a BEGIN line.
pub fn begin_name(line: &mut Line, len: usize) -> Option<Vec<u8>> {
    let text = c_str(line);
    let tail_at = len.checked_sub(TAILSTR.len())?;
    let is_begin = text.starts_with(BEGINSTR)
        && line
            .get(tail_at..)
            .is_some_and(|t| c_str(t).starts_with(TAILSTR));
    if !is_begin {
        return None;
    }
    if let Some(c) = line.get_mut(tail_at) {
        *c = 0;
    }
    let name_len = len
        .checked_sub(BEGINSTR.len().wrapping_add(TAILSTR.len()))?
        .wrapping_add(1);
    line.get(BEGINSTR.len()..BEGINSTR.len().wrapping_add(name_len))
        .map(<[u8]>::to_vec)
}

/// Where lines go: the header until a blank line, the data after.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Header {
    Maybe,
    In,
    Post,
}

/// `get_header_and_data`'s state.
pub struct Body {
    name: Vec<u8>,
    flags: u32,
    header: Vec<u8>,
    data: Vec<u8>,
    got_header: Header,
    /// Lines go to the data (after a blank line).
    to_data: bool,
    end: bool,
    partial_line_read: bool,
}

impl Body {
    /// Reading the body of the PEM `name` (as the C string `get_name` gave).
    pub fn new(name: &[u8], flags: u32) -> Self {
        Self {
            name: c_str(name).to_vec(),
            flags,
            header: Vec::new(),
            data: Vec::new(),
            got_header: Header::Maybe,
            to_data: false,
            end: false,
            partial_line_read: false,
        }
    }

    /// Takes the next line, `len` characters as `BIO_gets` read them. `Ok(true)` at the END
    /// line.
    pub fn line(&mut self, line: &mut Line, len: usize) -> Result<bool, Error> {
        let raw = len.min(LINESIZE - 1);
        let prev_partial = self.partial_line_read;
        self.partial_line_read = raw == LINESIZE - 1 && line.get(LINESIZE - 2) != Some(&b'\n');
        if self.got_header == Header::Maybe && line.get(..raw).is_some_and(|l| l.contains(&b':')) {
            self.got_header = Header::In;
        }
        let mut flags = self.flags;
        if c_str(line).starts_with(ENDSTR) || self.got_header == Header::In {
            flags &= !FLAG_ONLY_B64;
        }
        let len = sanitize_line(line, raw, flags, false);
        if line.first() == Some(&b'\n') {
            if !prev_partial {
                if self.got_header == Header::Post {
                    return Err(Error::BadEndLine);
                }
                self.got_header = Header::Post;
                self.to_data = true;
            }
            return Ok(false);
        }
        let text = c_str(line);
        if let Some(rest) = text.strip_prefix(ENDSTR) {
            let matches = rest
                .strip_prefix(self.name.as_slice())
                .is_some_and(|t| t.starts_with(TAILSTR));
            if !matches {
                return Err(Error::BadEndLine);
            }
            if self.got_header == Header::Maybe {
                // No header after all: what was read is the data.
                self.data = core::mem::take(&mut self.header);
            }
            return Ok(true);
        }
        if self.end {
            return Err(Error::BadEndLine);
        }
        let target = if self.to_data {
            &mut self.data
        } else {
            &mut self.header
        };
        target.extend_from_slice(text);
        if self.got_header == Header::Post {
            // An encrypted file's lines are 64 characters and a newline, the last shorter.
            if len > 65 {
                return Err(Error::Silent);
            }
            if len < 65 {
                self.end = true;
            }
        }
        Ok(false)
    }

    /// Decodes the data: the header text and the octets.
    pub fn finish(self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        if self.data.is_empty() {
            return Err(Error::Silent);
        }
        let mut ctx = Ctx::default();
        ctx.decode_init();
        let decoded = ctx.decode_update(Some(&self.data));
        if decoded.ret < 0 {
            return Err(Error::BadBase64Decode);
        }
        let tail = ctx.decode_final().ok_or(Error::BadBase64Decode)?;
        let mut out = decoded.out;
        out.extend(tail);
        Ok((self.header, out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(text: &[u8]) -> (Line, usize) {
        let mut l = [0u8; LINESIZE + 1];
        let n = text.len().min(LINESIZE - 1);
        l[..n].copy_from_slice(&text[..n]);
        (l, n)
    }

    #[test]
    fn reads_a_body() {
        let (mut l, n) = line(b"-----BEGIN TEST-----  \n");
        let n = sanitize_line(&mut l, n, FLAG_EAY_COMPATIBLE, true);
        let name = begin_name(&mut l, n).unwrap();
        assert_eq!(c_str(&name), b"TEST");
        let mut body = Body::new(&name, FLAG_EAY_COMPATIBLE);
        for text in [&b"aGVsbG8=\n"[..], b"-----END TEST-----\n"] {
            let (mut l, n) = line(text);
            if body.line(&mut l, n).unwrap() {
                break;
            }
        }
        assert_eq!(body.finish().unwrap(), (Vec::new(), b"hello".to_vec()));
    }

    #[test]
    fn sanitizes() {
        let (mut l, n) = line(b"ab\x01c\r\n");
        assert_eq!(sanitize_line(&mut l, n, 0, false), 5);
        assert_eq!(&l[..6], b"ab c\n\0");
        let (mut l, n) = line(b"QUJD junk\n");
        assert_eq!(sanitize_line(&mut l, n, FLAG_ONLY_B64, false), 5);
        let (mut l, n) = line(b"\xEF\xBB\xBFline \n");
        assert_eq!(sanitize_line(&mut l, n, FLAG_EAY_COMPATIBLE, true), 5);
        assert_eq!(&l[..5], b"line\n");
    }
}
