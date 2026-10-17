//! MIME as S/MIME uses it (`crypto/asn1/asn_mime.c`): the header parser behind `SMIME_text` and
//! `SMIME_read_ASN1`, and the end-of-line handling of `SMIME_crlf_copy`.
//!
//! The parser is OpenSSL's, quirk for quirk, because what it accepts decides which messages
//! verify: a value keeps its comments, a quote opens a value only at its start, a value of one
//! quoted character is lost, and a line that ends inside a comment or a quote adds nothing. Lines
//! arrive as `BIO_gets` reads them, at most [`MAX_LINE`] octets, and a longer line is read as
//! several. Unlike OpenSSL, which lets them grow with the input, the headers and their parameters
//! are capped at [`MAX_ENTRIES`] (docs/DEVIATIONS.md).

use rustyssl_abi::{CMS_BINARY, SMIME_ASCIICRLF, SMIME_CRLFEOL};

/// The longest line OpenSSL reads at once (`MAX_SMLEN` less its NUL).
pub const MAX_LINE: usize = 1023;

/// The most headers and parameters, together, one parse keeps.
pub const MAX_ENTRIES: usize = 10_000;

/// The headers outgrew [`MAX_ENTRIES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooManyEntries;

/// A header's parameter: its name in lower case, and its value as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    pub name: Option<Vec<u8>>,
    pub value: Option<Vec<u8>>,
}

/// A header: its name and value in lower case, and its parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: Option<Vec<u8>>,
    pub value: Option<Vec<u8>>,
    pub params: Vec<Param>,
}

impl Header {
    /// `mime_param_find`: the first parameter named `name` in sorted order.
    pub fn param(&self, name: &[u8]) -> Option<&Param> {
        self.params.iter().find(|p| p.name.as_deref() == Some(name))
    }
}

/// Parsed headers, sorted by name, each one's parameters by theirs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers(pub Vec<Header>);

impl Headers {
    /// `mime_hdr_find`: the first header named `name` (in lower case) in sorted order. The sort
    /// is stable, so of duplicates this is the first one read; OpenSSL's `qsort` leaves which
    /// one to the C library.
    pub fn find(&self, name: &[u8]) -> Option<&Header> {
        self.0.iter().find(|h| h.name.as_deref() == Some(name))
    }
}

/// `ossl_isspace`.
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// `strip_start`: past leading white space, or past an opening quote.
fn strip_start(s: &[u8]) -> Option<&[u8]> {
    for (i, &c) in s.iter().enumerate() {
        if c == b'"' {
            return s.get(i.checked_add(1)?..).filter(|r| !r.is_empty());
        }
        if !is_space(c) {
            return s.get(i..);
        }
    }
    None
}

/// `strip_end`: without trailing white space, or cut at a closing quote; a quote second from
/// the start gives nothing, as OpenSSL's does.
fn strip_end(s: &[u8]) -> Option<&[u8]> {
    for (i, &c) in s.iter().enumerate().rev() {
        if c == b'"' {
            if i == 1 {
                return None;
            }
            return s.get(..i);
        }
        if !is_space(c) {
            return s.get(..i.checked_add(1)?);
        }
    }
    None
}

/// `strip_ends`.
fn strip_ends(s: &[u8]) -> Option<&[u8]> {
    strip_start(s).and_then(strip_end)
}

fn lower(s: Option<&[u8]>) -> Option<Vec<u8>> {
    s.map(<[u8]>::to_ascii_lowercase)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Start,
    Type,
    Name,
    Value,
    Quote,
    Comment,
}

/// `mime_parse_hdr`, fed one line at a time.
#[derive(Debug, Default)]
pub struct HeaderParser {
    headers: Vec<Header>,
    /// The header the last line added, which continuation lines extend.
    current: Option<usize>,
    entries: usize,
}

impl HeaderParser {
    pub fn new() -> Self {
        Self::default()
    }

    fn count(&mut self) -> Result<(), TooManyEntries> {
        if self.entries >= MAX_ENTRIES {
            return Err(TooManyEntries);
        }
        self.entries = self.entries.saturating_add(1);
        Ok(())
    }

    fn add_header(
        &mut self,
        name: Option<&[u8]>,
        value: Option<&[u8]>,
    ) -> Result<(), TooManyEntries> {
        self.count()?;
        self.current = Some(self.headers.len());
        self.headers.push(Header {
            name: lower(name),
            value: lower(value),
            params: Vec::new(),
        });
        Ok(())
    }

    fn add_param(
        &mut self,
        name: Option<&[u8]>,
        value: Option<&[u8]>,
    ) -> Result<(), TooManyEntries> {
        self.count()?;
        if let Some(h) = self.current.and_then(|i| self.headers.get_mut(i)) {
            h.params.push(Param {
                name: lower(name),
                value: value.map(<[u8]>::to_vec),
            });
        }
        Ok(())
    }

    /// Parses one line as `BIO_gets` returned it, read as a C string: `Ok(false)` if it is
    /// blank and ends the headers.
    pub fn line(&mut self, line: &[u8]) -> Result<bool, TooManyEntries> {
        let text = line.split(|&c| c == 0).next().unwrap_or_default();
        let continued = self.current.is_some() && text.first().copied().is_some_and(is_space);
        let mut state = if continued { State::Name } else { State::Start };
        let mut save = State::Start;
        let mut name: Option<&[u8]> = None;
        let mut q = 0usize;
        let end = text
            .iter()
            .position(|&c| c == b'\r' || c == b'\n')
            .unwrap_or(text.len());
        for (p, &c) in text.iter().enumerate().take(end) {
            let segment = text.get(q..p).unwrap_or_default();
            let next = p.saturating_add(1);
            match state {
                State::Start if c == b':' => {
                    state = State::Type;
                    name = strip_ends(segment);
                    q = next;
                }
                State::Type if c == b';' => {
                    self.add_header(name, strip_ends(segment))?;
                    name = None;
                    q = next;
                    state = State::Name;
                }
                State::Type | State::Value if c == b'(' => {
                    save = state;
                    state = State::Comment;
                }
                State::Comment if c == b')' => state = save,
                State::Name if c == b'=' => {
                    state = State::Value;
                    name = strip_ends(segment);
                    q = next;
                }
                State::Value if c == b';' => {
                    state = State::Name;
                    self.add_param(name, strip_ends(segment))?;
                    name = None;
                    q = next;
                }
                State::Value if c == b'"' => state = State::Quote,
                State::Quote if c == b'"' => state = State::Value,
                _ => {}
            }
        }
        // The last value runs to the C string's end, past a CR or LF that ended the scan.
        let rest = text.get(q..).unwrap_or_default();
        match state {
            State::Type => self.add_header(name, strip_ends(rest))?,
            State::Value => self.add_param(name, strip_ends(rest))?,
            _ => {}
        }
        Ok(end != 0)
    }

    /// The headers read, sorted.
    pub fn finish(mut self) -> Headers {
        self.headers.sort_by(|a, b| a.name.cmp(&b.name));
        for h in &mut self.headers {
            h.params.sort_by(|a, b| a.name.cmp(&b.name));
        }
        Headers(self.headers)
    }
}

/// `strip_eol`: the line's length without its end of line, and whether it had one. With
/// `CMS_BINARY` only a final LF (CRLF with `SMIME_CRLFEOL`) counts; otherwise trailing CRs and
/// LFs go, and with `SMIME_ASCIICRLF` the spaces before them.
pub fn strip_eol(line: &[u8], flags: i32) -> (usize, bool) {
    let mut len = line.len();
    if flags & CMS_BINARY != 0 {
        if line.last() != Some(&b'\n') {
            return (len, false);
        }
        if flags & SMIME_CRLFEOL != 0 {
            let before = len.checked_sub(2).and_then(|i| line.get(i));
            if before != Some(&b'\r') {
                return (len, false);
            }
            len = len.saturating_sub(1);
        }
        return (len.saturating_sub(1), true);
    }
    let mut eol = false;
    while let Some(&c) = len.checked_sub(1).and_then(|i| line.get(i)) {
        let space = eol && flags & SMIME_ASCIICRLF != 0 && c == b' ';
        if c == b'\n' {
            eol = true;
        } else if !space && c != b'\r' {
            break;
        }
        len = len.saturating_sub(1);
    }
    (len, eol)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(lines: &[&[u8]]) -> Headers {
        let mut p = HeaderParser::new();
        for l in lines {
            if !p.line(l).unwrap() {
                break;
            }
        }
        p.finish()
    }

    fn value<'a>(h: &'a Headers, name: &str) -> Option<&'a [u8]> {
        h.find(name.as_bytes()).and_then(|h| h.value.as_deref())
    }

    #[test]
    fn headers_and_parameters() {
        let h = parse(&[
            b"MIME-Version: 1.0\r\n",
            b"Content-Type: Multipart/Signed; Protocol=\"application/x-pkcs7-signature\";\r\n",
            b"\tmicalg=\"sha-256\"; boundary=\"----ABC\"\r\n",
            b"\r\n",
            b"Body: ignored\r\n",
        ]);
        assert_eq!(h.0.len(), 2);
        assert_eq!(value(&h, "mime-version"), Some(&b"1.0"[..]));
        let ct = h.find(b"content-type").unwrap();
        assert_eq!(ct.value.as_deref(), Some(&b"multipart/signed"[..]));
        let get = |n: &str| ct.param(n.as_bytes()).and_then(|p| p.value.as_deref());
        assert_eq!(get("protocol"), Some(&b"application/x-pkcs7-signature"[..]));
        assert_eq!(get("micalg"), Some(&b"sha-256"[..]));
        assert_eq!(get("boundary"), Some(&b"----ABC"[..]));
        assert!(h.find(b"body").is_none());
    }

    #[test]
    fn openssl_quirks() {
        let h = parse(&[
            b"A: text/plain (a comment)\n",
            b"B: x\"\n",
            b"C: (unclosed\n",
            b"D: \"q\"\n",
            b"E: v\rw\n",
            b"no colon\n",
        ]);
        assert_eq!(value(&h, "a"), Some(&b"text/plain (a comment)"[..]));
        // A quote second from the start loses the value.
        assert!(h.find(b"b").unwrap().value.is_none());
        // A line ending inside a comment adds nothing.
        assert!(h.find(b"c").is_none());
        assert!(h.find(b"d").unwrap().value.is_none());
        // The scan stops at the CR, the value runs on past it.
        assert_eq!(value(&h, "e"), Some(&b"v\rw"[..]));
    }

    #[test]
    fn duplicates_keep_the_first() {
        let h = parse(&[b"X: one\n", b"Y: y\n", b"X: two\n"]);
        assert_eq!(value(&h, "x"), Some(&b"one"[..]));
    }

    #[test]
    fn entries_are_capped() {
        let mut p = HeaderParser::new();
        for _ in 0..MAX_ENTRIES {
            assert_eq!(p.line(b"H: v\n"), Ok(true));
        }
        assert_eq!(p.line(b"H: v\n"), Err(TooManyEntries));
    }

    #[test]
    fn end_of_line() {
        assert_eq!(strip_eol(b"abc \r\n", 0), (4, true));
        assert_eq!(strip_eol(b"abc \r\n", SMIME_ASCIICRLF), (3, true));
        assert_eq!(strip_eol(b"abc\r", 0), (3, false));
        assert_eq!(strip_eol(b"abc\r\n", CMS_BINARY), (4, true));
        assert_eq!(strip_eol(b"abc\r\n", CMS_BINARY | SMIME_CRLFEOL), (3, true));
        assert_eq!(strip_eol(b"abc\n", CMS_BINARY | SMIME_CRLFEOL), (4, false));
        assert_eq!(strip_eol(b"\r\n\n", 0), (0, true));
    }
}
