//! What a logical line is (`def_load_bio`'s parsing half, with `str_copy`'s expansion).
//!
//! OpenSSL works on the line as a C string, writing terminators into it as it goes; this
//! works on a copy that ends in a NUL, reading past its end as NUL, so each scan stops there
//! whatever the method's classes say.

use crate::Classes;
use crate::classes::{ALNUM, ALNUM_PUNCT, COMMENT, DOLLAR, DQUOTE, EOF, ESC, FCOMMENT, QUOTE, WS};

/// How long a value may grow through its variable references (`MAX_CONF_VALUE_LENGTH`).
pub const MAX_VALUE_LENGTH: usize = 65536;

/// Why a line can't be read: OpenSSL's `CONF_R_*` reasons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A section header without its `]` (`CONF_R_MISSING_CLOSE_SQUARE_BRACKET`).
    MissingCloseSquareBracket,
    /// A name without `=`; OpenSSL's data says what follows the name (`HERE-->...`).
    MissingEqualSign(Vec<u8>),
    /// A malformed pragma (`CONF_R_INVALID_PRAGMA`).
    InvalidPragma,
    /// `${` or `$(` without its closing brace (`CONF_R_NO_CLOSE_BRACE`).
    NoCloseBrace,
    /// A reference to a variable that isn't set (`CONF_R_VARIABLE_HAS_NO_VALUE`).
    VariableHasNoValue,
    /// A value grown past [`MAX_VALUE_LENGTH`] (`CONF_R_VARIABLE_EXPANSION_TOO_LONG`).
    VariableExpansionTooLong,
    /// A relative include with the `abspath` pragma on (`CONF_R_RELATIVE_PATH`).
    RelativePath,
}

/// A pragma's setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pragma {
    /// `dollarid`: `$` is part of names, and references need braces.
    DollarId(bool),
    /// `abspath`: includes must be absolute.
    AbsPath(bool),
    /// `includedir`: the directory relative includes are under.
    IncludeDir(Vec<u8>),
    /// Any other pragma, which OpenSSL ignores.
    Unknown,
}

/// What a logical line is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// Nothing (blank, or a comment).
    Blank,
    /// A section header: the section to go on in, created if new.
    Section(Vec<u8>),
    /// `name = value`, for the current section (`None`) or the one before `::`.
    Value {
        /// The section named with `section::name`, if any.
        section: Option<Vec<u8>>,
        /// The name, as written (escapes kept).
        name: Vec<u8>,
        /// The value, its quotes, escapes, and references resolved.
        value: Vec<u8>,
    },
    /// A `.pragma` directive.
    Pragma(Pragma),
    /// An `.include`: the path to read (a file, or a directory of `.cnf` and `.conf` files).
    Include(Vec<u8>),
}

/// The values set so far, for references: OpenSSL's `_CONF_get_string`.
pub trait Lookup {
    /// The value of `name` in `section` (or, if not there or `section` is `None`, in
    /// `default`; and in the environment for the `ENV` section).
    fn get(&self, section: Option<&[u8]>, name: &[u8]) -> Option<Vec<u8>>;

    /// `OPENSSL_CONF_INCLUDE`, which takes precedence over the `includedir` pragma; asked for
    /// only when a line includes a file.
    fn include_env(&self) -> Option<Vec<u8>> {
        None
    }
}

/// The state a line is read in.
#[derive(Debug, Clone, Copy)]
pub struct Options<'a> {
    /// The method's character classes.
    pub classes: Classes<'a>,
    /// The section the line is in.
    pub section: &'a [u8],
    /// The `dollarid` pragma.
    pub dollarid: bool,
    /// The `abspath` pragma.
    pub abspath: bool,
    /// The `includedir` pragma's directory.
    pub includedir: Option<&'a [u8]>,
}

/// A line as a C string: the octets and a NUL, read past its end as NUL.
struct Text<'a> {
    buf: Vec<u8>,
    o: &'a Options<'a>,
}

impl Text<'_> {
    fn at(&self, i: usize) -> u8 {
        self.buf.get(i).copied().unwrap_or(0)
    }

    fn is(&self, i: usize, t: u16) -> bool {
        self.o.classes.is(self.at(i), t)
    }

    /// Whether `i` is at the end: a NUL by the classes' say, or past the octets.
    fn eof(&self, i: usize) -> bool {
        i >= self.buf.len() || self.is(i, EOF)
    }

    fn set(&mut self, i: usize, c: u8) {
        if let Some(b) = self.buf.get_mut(i) {
            *b = c;
        }
    }

    /// The C string at `i`: up to the next NUL.
    fn cstr(&self, i: usize) -> &[u8] {
        let rest = self.buf.get(i..).unwrap_or_default();
        rest.split(|&c| c == 0).next().unwrap_or_default()
    }

    fn slice(&self, from: usize, to: usize) -> Vec<u8> {
        self.buf.get(from..to).unwrap_or_default().to_vec()
    }

    fn eat_ws(&self, mut p: usize) -> usize {
        while p < self.buf.len() && self.is(p, WS) && !self.eof(p) {
            p = p.saturating_add(1);
        }
        p
    }

    /// Ends the string at `start` after its last non-space.
    fn trim_ws(&mut self, start: usize) {
        let mut p = start;
        while !self.eof(p) {
            p = p.saturating_add(1);
        }
        while p > start && self.is(p.saturating_sub(1), WS) {
            p = p.saturating_sub(1);
        }
        self.set(p, 0);
    }

    fn scan_esc(&self, p: usize) -> usize {
        if self.eof(p.saturating_add(1)) {
            p.saturating_add(1)
        } else {
            p.saturating_add(2)
        }
    }

    fn eat_alpha_numeric(&self, mut p: usize) -> usize {
        while p < self.buf.len() {
            if self.is(p, ESC) {
                p = self.scan_esc(p);
                continue;
            }
            if !(self.is(p, ALNUM_PUNCT) || (self.o.dollarid && self.is(p, DOLLAR))) {
                return p;
            }
            p = p.saturating_add(1);
        }
        p
    }

    fn scan_quote(&self, mut p: usize) -> usize {
        let q = self.at(p);
        p = p.saturating_add(1);
        while !self.eof(p) && self.at(p) != q {
            if self.is(p, ESC) {
                p = p.saturating_add(1);
                if self.eof(p) {
                    return p;
                }
            }
            p = p.saturating_add(1);
        }
        if self.at(p) == q {
            p = p.saturating_add(1);
        }
        p
    }

    fn scan_dquote(&self, mut p: usize) -> usize {
        let q = self.at(p);
        p = p.saturating_add(1);
        while !self.eof(p) {
            if self.at(p) == q {
                if self.at(p.saturating_add(1)) == q {
                    p = p.saturating_add(1);
                } else {
                    break;
                }
            }
            p = p.saturating_add(1);
        }
        if self.at(p) == q {
            p = p.saturating_add(1);
        }
        p
    }

    /// Ends the line at its comment, skipping quotes and escapes.
    fn clear_comments(&mut self) {
        let mut p = 0;
        loop {
            if self.is(p, FCOMMENT) {
                self.set(p, 0);
                return;
            }
            if !self.is(p, WS) || p >= self.buf.len() {
                break;
            }
            p = p.saturating_add(1);
        }
        while p < self.buf.len() {
            if self.is(p, COMMENT) {
                self.set(p, 0);
                return;
            }
            if self.is(p, DQUOTE) {
                p = self.scan_dquote(p);
            } else if self.is(p, QUOTE) {
                p = self.scan_quote(p);
            } else if self.is(p, ESC) {
                p = self.scan_esc(p);
            } else if self.eof(p) {
                return;
            } else {
                p = p.saturating_add(1);
            }
        }
    }

    /// The string at `from` with its quotes and escapes resolved and its references expanded
    /// (`str_copy`), references without a section looked up in `section`.
    fn expand(
        &self,
        section: Option<&[u8]>,
        mut from: usize,
        lookup: &dyn Lookup,
    ) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        // OpenSSL's buffer length, which bounds the expansion.
        let mut length = self.cstr(from).len().saturating_add(1);
        loop {
            let c = self.at(from);
            if self.is(from, QUOTE) {
                from = from.saturating_add(1);
                while !self.eof(from) && self.at(from) != c {
                    if self.is(from, ESC) {
                        from = from.saturating_add(1);
                        if self.eof(from) {
                            break;
                        }
                    }
                    out.push(self.at(from));
                    from = from.saturating_add(1);
                }
                if self.at(from) == c {
                    from = from.saturating_add(1);
                }
            } else if self.is(from, DQUOTE) {
                from = from.saturating_add(1);
                while !self.eof(from) {
                    if self.at(from) == c {
                        if self.at(from.saturating_add(1)) == c {
                            from = from.saturating_add(1);
                        } else {
                            break;
                        }
                    }
                    out.push(self.at(from));
                    from = from.saturating_add(1);
                }
                if self.at(from) == c {
                    from = from.saturating_add(1);
                }
            } else if self.is(from, ESC) {
                from = from.saturating_add(1);
                let v = self.at(from);
                let end = self.eof(from);
                from = from.saturating_add(1);
                if end {
                    break;
                }
                out.push(match v {
                    b'r' => b'\r',
                    b'n' => b'\n',
                    b'b' => 0x08,
                    b't' => b'\t',
                    v => v,
                });
            } else if self.eof(from) {
                break;
            } else if c == b'$' && {
                let n = self.at(from.saturating_add(1));
                !self.o.dollarid || n == b'{' || n == b'('
            } {
                let mut s = from.saturating_add(1);
                let close = match self.at(s) {
                    b'{' => Some(b'}'),
                    b'(' => Some(b')'),
                    _ => None,
                };
                if close.is_some() {
                    s = s.saturating_add(1);
                }
                let name_char =
                    |t: &Self, i: usize| t.is(i, ALNUM) || (t.o.dollarid && t.is(i, DOLLAR));
                let mut cp: Option<Vec<u8>> = section.map(<[u8]>::to_vec);
                let mut np = s;
                let mut e = s;
                while e < self.buf.len() && name_char(self, e) {
                    e = e.saturating_add(1);
                }
                if self.at(e) == b':' && self.at(e.saturating_add(1)) == b':' {
                    cp = Some(self.slice(np, e));
                    e = e.saturating_add(2);
                    np = e;
                    while e < self.buf.len() && name_char(self, e) {
                        e = e.saturating_add(1);
                    }
                }
                let name = self.slice(np, e);
                if let Some(q) = close {
                    if self.at(e) != q {
                        return Err(Error::NoCloseBrace);
                    }
                    e = e.saturating_add(1);
                }
                let value = lookup
                    .get(cp.as_deref(), &name)
                    .ok_or(Error::VariableHasNoValue)?;
                // OpenSSL's value is a C string.
                let value = value.split(|&c| c == 0).next().unwrap_or_default();
                let newsize = value
                    .len()
                    .checked_add(length)
                    .and_then(|n| n.checked_sub(e.saturating_sub(from)))
                    .ok_or(Error::VariableExpansionTooLong)?;
                if newsize > MAX_VALUE_LENGTH {
                    return Err(Error::VariableExpansionTooLong);
                }
                length = newsize;
                out.extend_from_slice(value);
                from = e;
            } else {
                out.push(c);
                from = from.saturating_add(1);
            }
        }
        Ok(out)
    }
}

/// `parsebool`: `on`/`true` or `off`/`false`, in any case.
fn parse_bool(v: &[u8]) -> Result<bool, Error> {
    if v.eq_ignore_ascii_case(b"on") || v.eq_ignore_ascii_case(b"true") {
        Ok(true)
    } else if v.eq_ignore_ascii_case(b"off") || v.eq_ignore_ascii_case(b"false") {
        Ok(false)
    } else {
        Err(Error::InvalidPragma)
    }
}

/// What the logical `line` is, read with `o`, its references looked up through `lookup`.
pub fn parse_line(o: &Options<'_>, line: &[u8], lookup: &dyn Lookup) -> Result<Line, Error> {
    let mut buf = Vec::with_capacity(line.len().saturating_add(1));
    buf.extend_from_slice(line);
    buf.push(0);
    let mut t = Text { buf, o };
    t.clear_comments();
    let s = t.eat_ws(0);
    if t.eof(s) {
        return Ok(Line::Blank);
    }
    if t.at(s) == b'[' {
        let start = t.eat_ws(s.saturating_add(1));
        let mut ss = start;
        let end = loop {
            let end = t.eat_alpha_numeric(ss);
            let p = t.eat_ws(end);
            if t.at(p) == b']' {
                break end;
            }
            if t.at(p) != 0 && ss != p {
                ss = p;
                continue;
            }
            return Err(Error::MissingCloseSquareBracket);
        };
        t.set(end, 0);
        return t.expand(None, start, lookup).map(Line::Section);
    }
    let mut pname = s;
    let mut end = t.eat_alpha_numeric(s);
    let mut psection = None;
    if t.at(end) == b':' && t.at(end.saturating_add(1)) == b':' {
        psection = Some(t.slice(pname, end));
        t.set(end, 0);
        end = end.saturating_add(2);
        pname = end;
        end = t.eat_alpha_numeric(end);
    }
    let mut p = t.eat_ws(end);
    if t.cstr(pname).starts_with(b".pragma") {
        pname = pname.saturating_add(7);
        if p != pname || t.at(p) == b'=' {
            if t.at(p) == b'=' {
                p = t.eat_ws(p.saturating_add(1));
            }
            t.trim_ws(p);
            let colon = t.cstr(p).iter().position(|&c| c == b':');
            let Some(colon) = colon.filter(|&c| c != 0).map(|c| p.saturating_add(c)) else {
                return Err(Error::InvalidPragma);
            };
            if t.at(colon.saturating_add(1)) == 0 {
                return Err(Error::InvalidPragma);
            }
            t.set(colon, 0);
            t.trim_ws(p);
            let pval = t.eat_ws(colon.saturating_add(1));
            let value = t.cstr(pval).to_vec();
            return Ok(Line::Pragma(match t.cstr(p) {
                b"dollarid" => Pragma::DollarId(parse_bool(&value)?),
                b"abspath" => Pragma::AbsPath(parse_bool(&value)?),
                b"includedir" => Pragma::IncludeDir(value),
                _ => Pragma::Unknown,
            }));
        }
    }
    if t.cstr(pname).starts_with(b".include") {
        pname = pname.saturating_add(8);
        if p != pname || t.at(p) == b'=' {
            if t.at(p) == b'=' {
                p = t.eat_ws(p.saturating_add(1));
            }
            t.trim_ws(p);
            let section = psection.as_deref().unwrap_or(o.section);
            let include = t.expand(Some(section), p, lookup)?;
            let env = lookup.include_env();
            let dir = env.as_deref().or(o.includedir);
            let path = match dir {
                Some(dir) if include.first() != Some(&b'/') => {
                    let mut path = dir.to_vec();
                    if dir.last() != Some(&b'/') {
                        path.push(b'/');
                    }
                    path.extend_from_slice(&include);
                    path
                }
                _ => include,
            };
            if o.abspath && path.first() != Some(&b'/') {
                return Err(Error::RelativePath);
            }
            return Ok(Line::Include(path));
        }
    }
    if t.at(p) != b'=' {
        return Err(Error::MissingEqualSign(t.cstr(p).to_vec()));
    }
    let name = t.slice(pname, end);
    t.set(end, 0);
    let start = t.eat_ws(p.saturating_add(1));
    t.trim_ws(start);
    let section = psection.as_deref().unwrap_or(o.section);
    let value = t.expand(Some(section), start, lookup)?;
    Ok(Line::Value {
        section: psection,
        name,
        value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Map(HashMap<(Vec<u8>, Vec<u8>), Vec<u8>>, Option<Vec<u8>>);

    impl Lookup for Map {
        fn get(&self, section: Option<&[u8]>, name: &[u8]) -> Option<Vec<u8>> {
            section
                .and_then(|s| self.0.get(&(s.to_vec(), name.to_vec())))
                .or_else(|| self.0.get(&(b"default".to_vec(), name.to_vec())))
                .cloned()
        }

        fn include_env(&self) -> Option<Vec<u8>> {
            self.1.clone()
        }
    }

    fn opts(section: &[u8]) -> Options<'_> {
        Options {
            classes: Classes::DEFAULT,
            section,
            dollarid: false,
            abspath: false,
            includedir: None,
        }
    }

    fn map() -> Map {
        let mut m = HashMap::new();
        m.insert((b"default".to_vec(), b"a".to_vec()), b"1".to_vec());
        m.insert((b"s".to_vec(), b"v".to_vec()), b"sv".to_vec());
        Map(m, None)
    }

    fn value(line: &[u8]) -> Result<Line, Error> {
        parse_line(&opts(b"default"), line, &map())
    }

    fn v(name: &[u8], value: &[u8]) -> Line {
        Line::Value {
            section: None,
            name: name.to_vec(),
            value: value.to_vec(),
        }
    }

    #[test]
    fn values() {
        assert_eq!(value(b"  x = y  # c"), Ok(v(b"x", b"y")));
        assert_eq!(value(b"x = 'a # b' \"c\"\"d\""), Ok(v(b"x", b"a # b cd")));
        assert_eq!(value(b"x = \\n\\t\\q"), Ok(v(b"x", b"\n\tq")));
        assert_eq!(
            value(b"x = $a-${a}-$(a)-$s::v-${s::v}"),
            Ok(v(b"x", b"1-1-1-sv-sv"))
        );
        assert_eq!(value(b"x = $none"), Err(Error::VariableHasNoValue));
        assert_eq!(value(b"x = ${a"), Err(Error::NoCloseBrace));
        assert_eq!(value(b"x 1"), Err(Error::MissingEqualSign(b"1".to_vec())));
        assert_eq!(value(b"# only"), Ok(Line::Blank));
        assert_eq!(value(b"= v"), Ok(v(b"", b"v")));
        assert_eq!(
            value(b"s::x = $v"),
            Ok(Line::Value {
                section: Some(b"s".to_vec()),
                name: b"x".to_vec(),
                value: b"sv".to_vec()
            })
        );
    }

    #[test]
    fn sections() {
        assert_eq!(value(b"[ a b ]"), Ok(Line::Section(b"a b".to_vec())));
        assert_eq!(value(b"[]"), Ok(Line::Section(Vec::new())));
        assert_eq!(value(b"[a"), Err(Error::MissingCloseSquareBracket));
        assert_eq!(value(b"[ a b c"), Err(Error::MissingCloseSquareBracket));
    }

    #[test]
    fn pragmas_and_includes() {
        assert_eq!(
            value(b".pragma dollarid:on"),
            Ok(Line::Pragma(Pragma::DollarId(true)))
        );
        assert_eq!(
            value(b".pragma = abspath : FALSE "),
            Ok(Line::Pragma(Pragma::AbsPath(false)))
        );
        assert_eq!(
            value(b".pragma includedir:/x y"),
            Ok(Line::Pragma(Pragma::IncludeDir(b"/x y".to_vec())))
        );
        assert_eq!(value(b".pragma other:1"), Ok(Line::Pragma(Pragma::Unknown)));
        assert_eq!(value(b".pragma dollarid"), Err(Error::InvalidPragma));
        assert_eq!(value(b".pragma :on"), Err(Error::InvalidPragma));
        assert_eq!(value(b".pragma dollarid:"), Err(Error::InvalidPragma));
        assert_eq!(value(b".pragmatic = 1"), Err(Error::InvalidPragma));
        assert_eq!(
            value(b".include a.cnf"),
            Ok(Line::Include(b"a.cnf".to_vec()))
        );
        let mut o = opts(b"default");
        o.includedir = Some(b"/etc/ssl");
        let mut env = map();
        env.1 = Some(b"/env/".to_vec());
        assert_eq!(
            parse_line(&o, b".include = $a.cnf", &env),
            Ok(Line::Include(b"/env/1.cnf".to_vec()))
        );
        assert_eq!(
            parse_line(&o, b".include rel", &map()),
            Ok(Line::Include(b"/etc/ssl/rel".to_vec()))
        );
        assert_eq!(
            parse_line(&o, b".include /abs", &map()),
            Ok(Line::Include(b"/abs".to_vec()))
        );
        o.includedir = None;
        o.abspath = true;
        assert_eq!(
            parse_line(&o, b".include rel", &map()),
            Err(Error::RelativePath)
        );
    }

    #[test]
    fn dollar_ids() {
        let mut o = opts(b"default");
        o.dollarid = true;
        assert_eq!(
            parse_line(&o, b"c$ = $a$b ${a}", &map()),
            Ok(v(b"c$", b"$a$b 1"))
        );
    }

    #[test]
    fn expansion_is_bounded() {
        let mut m = map();
        m.0.insert((b"default".to_vec(), b"big".to_vec()), vec![b'x'; 40000]);
        assert_eq!(
            parse_line(&opts(b"default"), b"x = $big$big", &m),
            Err(Error::VariableExpansionTooLong)
        );
        assert!(parse_line(&opts(b"default"), b"x = $big", &m).is_ok());
    }
}
