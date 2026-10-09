//! Properties (`property(7)`, `crypto/property/`): the strings a library context numbers, the
//! parsers of property definitions (what an algorithm offers, `provider=default,fips=yes`) and
//! queries (what a caller asks for, `?fips=yes,-provider`), matching a query against a
//! definition, merging two lists, and the canonical text of a list.
//!
//! As in OpenSSL, names and values are numbered per context in the order they're first seen
//! (the predefined names and the values `yes` and `no` first), lists are sorted by name number,
//! and the canonical text lists them from the highest number down, so it depends on the
//! context's history. Parsing raises OpenSSL's errors with its data text, some on the way to
//! success (a query whose value can't be parsed keeps the name with no value).

use std::collections::HashMap;

/// A name's or value's number in a context; 0 is none.
pub type Idx = u32;

/// The value `yes` (`OSSL_PROPERTY_TRUE`).
pub const TRUE: Idx = 1;
/// The value `no` (`OSSL_PROPERTY_FALSE`).
pub const FALSE: Idx = 2;

/// The names every context knows (`ossl_property_parse_init`).
const PREDEFINED_NAMES: [&[u8]; 6] = [
    b"provider",
    b"version",
    b"fips",
    b"output",
    b"input",
    b"structure",
];

/// The longest name, and the longest value, OpenSSL's buffers hold (with a NUL).
const NAME_MAX: usize = 99;
const VALUE_MAX: usize = 999;

/// One table of numbered strings.
#[derive(Default)]
struct Table {
    strings: Vec<Vec<u8>>,
    numbers: HashMap<Vec<u8>, Idx>,
}

impl Table {
    fn get(&mut self, s: &[u8], create: bool) -> Idx {
        if let Some(&n) = self.numbers.get(s) {
            return n;
        }
        if !create {
            return 0;
        }
        // OpenSSL's numbers are `int`s; one past the last fails.
        let Some(n) = self
            .strings
            .len()
            .checked_add(1)
            .and_then(|n| Idx::try_from(n).ok())
            .filter(|&n| i32::try_from(n).is_ok())
        else {
            return 0;
        };
        self.strings.push(s.to_vec());
        self.numbers.insert(s.to_vec(), n);
        n
    }

    fn text(&self, n: Idx) -> Option<&[u8]> {
        let i = usize::try_from(n).ok()?.checked_sub(1)?;
        self.strings.get(i).map(Vec::as_slice)
    }
}

/// A context's property names and values.
pub struct Strings {
    names: Table,
    values: Table,
}

impl Default for Strings {
    fn default() -> Self {
        Self::new()
    }
}

impl Strings {
    /// The strings of a new context: the predefined names, then `yes` and `no`.
    pub fn new() -> Self {
        let mut s = Self {
            names: Table::default(),
            values: Table::default(),
        };
        for name in PREDEFINED_NAMES {
            s.names.get(name, true);
        }
        s.values.get(b"yes", true);
        s.values.get(b"no", true);
        s
    }

    /// `ossl_property_name`: the name's number, made if `create` (0 if not found).
    pub fn name(&mut self, s: &[u8], create: bool) -> Idx {
        self.names.get(s, create)
    }

    /// `ossl_property_name_str`.
    pub fn name_text(&self, n: Idx) -> Option<&[u8]> {
        self.names.text(n)
    }

    /// `ossl_property_value`.
    pub fn value(&mut self, s: &[u8], create: bool) -> Idx {
        self.values.get(s, create)
    }

    /// `ossl_property_value_str`.
    pub fn value_text(&self, n: Idx) -> Option<&[u8]> {
        self.values.text(n)
    }
}

/// How a query compares a property.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Oper {
    /// `name=value`, or a name alone (`=yes`).
    Eq,
    /// `name!=value`.
    Ne,
    /// `-name`: ignore the property (and any default for it).
    Override,
}

/// A property's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    /// A string value's number.
    String(Idx),
    /// A number.
    Number(i64),
    /// A query's value that couldn't be parsed (or none, for an override).
    Undefined,
}

/// One property of a list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Definition {
    /// The name's number (0 for a name the context doesn't know, in a query).
    pub name: Idx,
    /// The comparison (always `Eq` in a definition).
    pub oper: Oper,
    /// `?name`: preferred, not required.
    pub optional: bool,
    /// The value.
    pub value: Value,
}

/// A parsed list, sorted by name number.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct List {
    /// The properties.
    pub properties: Vec<Definition>,
    /// Whether any is optional.
    pub has_optional: bool,
}

/// OpenSSL's reasons for parse errors (`PROP_R_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// `PROP_R_NAME_TOO_LONG`.
    NameTooLong,
    /// `PROP_R_NOT_AN_ASCII_CHARACTER`.
    NotAnAsciiCharacter,
    /// `PROP_R_NOT_AN_HEXADECIMAL_DIGIT`.
    NotAnHexadecimalDigit,
    /// `PROP_R_NOT_AN_IDENTIFIER`.
    NotAnIdentifier,
    /// `PROP_R_NOT_AN_OCTAL_DIGIT`.
    NotAnOctalDigit,
    /// `PROP_R_NOT_A_DECIMAL_DIGIT`.
    NotADecimalDigit,
    /// `PROP_R_NO_MATCHING_STRING_DELIMITER`.
    NoMatchingStringDelimiter,
    /// `PROP_R_NO_VALUE`.
    NoValue,
    /// `PROP_R_PARSE_FAILED`.
    ParseFailed,
    /// `PROP_R_STRING_TOO_LONG`.
    StringTooLong,
    /// `PROP_R_TRAILING_CHARACTERS`.
    TrailingCharacters,
}

/// An error parsing raised, with its data text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// The reason.
    pub reason: Reason,
    /// The text OpenSSL's `ERR_raise_data` formats.
    pub data: Vec<u8>,
}

/// What a parse made, and the errors it raised (in order), which a successful parse may have
/// too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// The list, or `None` if the text isn't valid.
    pub list: Option<List>,
    /// The errors.
    pub errors: Vec<Error>,
}

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn is_print(c: u8) -> bool {
    (0x20..0x7f).contains(&c)
}

/// The parser: the text, its errors, and the context's strings.
struct Parser<'a> {
    text: &'a [u8],
    strings: &'a mut Strings,
    errors: Vec<Error>,
}

impl Parser<'_> {
    /// The character at `i`, NUL past the end (as the C string's terminator).
    fn at(&self, i: usize) -> u8 {
        self.text.get(i).copied().unwrap_or(0)
    }

    /// The text from `i` on.
    fn rest(&self, i: usize) -> &[u8] {
        self.text.get(i..).unwrap_or_default()
    }

    fn skip_space(&self, mut i: usize) -> usize {
        while is_space(self.at(i)) {
            i = i.saturating_add(1);
        }
        i
    }

    fn raise(&mut self, reason: Reason, prefix: &[u8], at: usize, suffix: &[u8]) {
        let mut data = prefix.to_vec();
        data.extend_from_slice(self.rest(at));
        data.extend_from_slice(suffix);
        self.errors.push(Error { reason, data });
    }

    /// `match_ch`.
    fn match_ch(&self, t: &mut usize, m: u8) -> bool {
        if self.at(*t) == m {
            *t = self.skip_space(t.saturating_add(1));
            return true;
        }
        false
    }

    /// `parse_name`: the name's number (made if it's a user name, with a dot, and `create`).
    fn name(&mut self, t: &mut usize, create: bool) -> Option<Idx> {
        let start = *t;
        let mut s = start;
        let mut name = Vec::new();
        let mut too_long = false;
        let mut user_name = false;
        loop {
            if !self.at(s).is_ascii_alphabetic() {
                self.raise(Reason::NotAnIdentifier, b"HERE-->", start, b"");
                return None;
            }
            loop {
                if name.len() < NAME_MAX {
                    name.push(self.at(s).to_ascii_lowercase());
                } else {
                    too_long = true;
                }
                s = s.saturating_add(1);
                if !(self.at(s) == b'_' || self.at(s).is_ascii_alphanumeric()) {
                    break;
                }
            }
            if self.at(s) != b'.' {
                break;
            }
            user_name = true;
            if name.len() < NAME_MAX {
                name.push(b'.');
            } else {
                too_long = true;
            }
            s = s.saturating_add(1);
        }
        if too_long {
            self.raise(Reason::NameTooLong, b"HERE-->", start, b"");
            return None;
        }
        *t = self.skip_space(s);
        Some(self.strings.name(&name, user_name && create))
    }

    /// Whether `c` may end a number.
    fn ends_number(c: u8) -> bool {
        is_space(c) || c == 0 || c == b','
    }

    /// `parse_number`, `parse_hex`, and `parse_oct`: digits in `base` from `*t`.
    fn number(&mut self, t: &mut usize, base: u32) -> Option<i64> {
        let reason = match base {
            16 => Reason::NotAnHexadecimalDigit,
            8 => Reason::NotAnOctalDigit,
            _ => Reason::NotADecimalDigit,
        };
        let digit = |c: u8| -> Option<i64> {
            let d = char::from(c).to_digit(base)?;
            // OpenSSL takes only lowercase `x` but either case of hex digits.
            Some(i64::from(d))
        };
        let mut s = *t;
        let mut v: i64 = 0;
        loop {
            let Some(d) = digit(self.at(s)) else {
                // The hexadecimal parser's message has no arrow.
                let prefix: &[u8] = if base == 16 { b"" } else { b"HERE-->" };
                self.raise(reason, prefix, *t, b"");
                return None;
            };
            let base = i64::from(base);
            let limit = i64::MAX
                .checked_sub(d)
                .and_then(|m| m.checked_div(base))
                .unwrap_or(0);
            if v > limit {
                self.raise(Reason::ParseFailed, b"Property ", *t, b" overflows");
                return None;
            }
            v = v
                .checked_mul(base)
                .and_then(|v| v.checked_add(d))
                .unwrap_or(i64::MAX);
            s = s.saturating_add(1);
            if digit(self.at(s)).is_none() {
                break;
            }
        }
        if !Self::ends_number(self.at(s)) {
            self.raise(reason, b"HERE-->", *t, b"");
            return None;
        }
        *t = self.skip_space(s);
        Some(v)
    }

    /// `parse_string`: a quoted value from `*t` (after the opening `delim`).
    fn quoted(&mut self, t: &mut usize, delim: u8, create: bool) -> Option<Value> {
        let mut s = *t;
        let mut v = Vec::new();
        let mut too_long = false;
        while self.at(s) != 0 && self.at(s) != delim {
            if v.len() < VALUE_MAX {
                v.push(self.at(s));
            } else {
                too_long = true;
            }
            s = s.saturating_add(1);
        }
        if self.at(s) == 0 {
            self.raise(
                Reason::NoMatchingStringDelimiter,
                &[b'H', b'E', b'R', b'E', b'-', b'-', b'>', delim],
                *t,
                b"",
            );
            return None;
        }
        let value = if too_long {
            self.raise(Reason::StringTooLong, b"HERE-->", *t, b"");
            None
        } else {
            Some(Value::String(self.strings.value(&v, create)))
        };
        *t = self.skip_space(s.saturating_add(1));
        value
    }

    /// `parse_unquoted`: a bare value from `*t`, lowercased. It moves `*t` on even when the
    /// value is too long or (not `create`) unknown, which fail.
    fn unquoted(&mut self, t: &mut usize, create: bool) -> Option<Value> {
        let mut s = *t;
        let mut v = Vec::new();
        let mut too_long = false;
        if self.at(s) == 0 || self.at(s) == b',' {
            return None;
        }
        while is_print(self.at(s)) && !is_space(self.at(s)) && self.at(s) != b',' {
            if v.len() < VALUE_MAX {
                v.push(self.at(s).to_ascii_lowercase());
            } else {
                too_long = true;
            }
            s = s.saturating_add(1);
        }
        if !Self::ends_number(self.at(s)) {
            self.raise(Reason::NotAnAsciiCharacter, b"HERE-->", s, b"");
            return None;
        }
        let value = if too_long {
            self.raise(Reason::StringTooLong, b"HERE-->", *t, b"");
            None
        } else {
            match self.strings.value(&v, create) {
                0 => None,
                n => Some(Value::String(n)),
            }
        };
        *t = self.skip_space(s);
        value
    }

    /// `parse_value`.
    fn value(&mut self, t: &mut usize, create: bool) -> Option<Value> {
        let c = self.at(*t);
        let next = self.at(t.saturating_add(1));
        let mut s = t.saturating_add(1);
        let r = match c {
            b'"' | b'\'' => self.quoted(&mut s, c, create),
            b'+' => self.number(&mut s, 10).map(Value::Number),
            b'-' => self
                .number(&mut s, 10)
                .map(|v| Value::Number(v.wrapping_neg())),
            b'0' if next == b'x' => {
                s = t.saturating_add(2);
                self.number(&mut s, 16).map(Value::Number)
            }
            b'0' if next.is_ascii_digit() => self.number(&mut s, 8).map(Value::Number),
            _ if c.is_ascii_digit() => return self.number(t, 10).map(Value::Number),
            _ if c.is_ascii_alphabetic() => return self.unquoted(t, create),
            _ => None,
        };
        if r.is_some() {
            *t = s;
        }
        r
    }

    /// `stack_to_property_list`: sorts by name number and rejects a name given twice.
    fn list(&mut self, mut properties: Vec<Definition>) -> Option<List> {
        properties.sort_by_key(|p| p.name);
        if let Some(w) = properties
            .windows(2)
            .find(|w| w.first().map(|p| p.name) == w.get(1).map(|p| p.name))
        {
            let name = w.first().map_or(0, |p| p.name);
            let text = self
                .strings
                .name_text(name)
                .map_or_else(|| b"<NULL>".to_vec(), <[u8]>::to_vec);
            let mut data = b"Duplicated name `".to_vec();
            data.extend_from_slice(&text);
            data.push(b'\'');
            self.errors.push(Error {
                reason: Reason::ParseFailed,
                data,
            });
            return None;
        }
        let has_optional = properties.iter().any(|p| p.optional);
        Some(List {
            properties,
            has_optional,
        })
    }

    /// Fails on anything left after the list.
    fn end(&mut self, s: usize, properties: Vec<Definition>) -> Option<List> {
        if self.at(s) != 0 {
            self.raise(Reason::TrailingCharacters, b"HERE-->", s, b"");
            return None;
        }
        self.list(properties)
    }

    /// `ossl_parse_property`.
    fn definition(&mut self) -> Option<List> {
        let mut s = self.skip_space(0);
        let mut properties = Vec::new();
        let mut done = self.at(s) == 0;
        while !done {
            let start = s;
            let name = self.name(&mut s, true)?;
            if name == 0 {
                self.raise(Reason::ParseFailed, b"Unknown name HERE-->", start, b"");
                return None;
            }
            let value = if self.match_ch(&mut s, b'=') {
                let Some(v) = self.value(&mut s, true) else {
                    self.raise(Reason::NoValue, b"HERE-->", start, b"");
                    return None;
                };
                v
            } else {
                Value::String(TRUE)
            };
            properties.push(Definition {
                name,
                oper: Oper::Eq,
                optional: false,
                value,
            });
            done = !self.match_ch(&mut s, b',');
        }
        self.end(s, properties)
    }

    /// `ossl_parse_query`.
    fn query(&mut self, create_values: bool) -> Option<List> {
        let mut s = self.skip_space(0);
        let mut properties = Vec::new();
        let mut done = self.at(s) == 0;
        while !done {
            if self.match_ch(&mut s, b'-') {
                let name = self.name(&mut s, true)?;
                properties.push(Definition {
                    name,
                    oper: Oper::Override,
                    optional: false,
                    value: Value::Undefined,
                });
            } else {
                let optional = self.match_ch(&mut s, b'?');
                let name = self.name(&mut s, true)?;
                let oper = if self.match_ch(&mut s, b'=') {
                    Some(Oper::Eq)
                } else if self.at(s) == b'!' && self.at(s.saturating_add(1)) == b'=' {
                    s = self.skip_space(s.saturating_add(2));
                    Some(Oper::Ne)
                } else {
                    None
                };
                let (oper, value) = match oper {
                    // A name alone is true.
                    None => (Oper::Eq, Value::String(TRUE)),
                    Some(oper) => (
                        oper,
                        self.value(&mut s, create_values)
                            .unwrap_or(Value::Undefined),
                    ),
                };
                properties.push(Definition {
                    name,
                    oper,
                    optional,
                    value,
                });
            }
            done = !self.match_ch(&mut s, b',');
        }
        self.end(s, properties)
    }
}

/// `ossl_parse_property`: an algorithm's property definition. Names without a dot must be
/// known to the context; values are added to it.
pub fn parse_definition(strings: &mut Strings, text: &[u8]) -> Parsed {
    let mut p = Parser {
        text,
        strings,
        errors: Vec::new(),
    };
    let list = p.definition();
    Parsed {
        list,
        errors: p.errors,
    }
}

/// `ossl_parse_query`: a property query. Unknown names without a dot are kept as number 0;
/// values are added to the context if `create_values`, and otherwise an unknown bare value
/// leaves the property with no value.
pub fn parse_query(strings: &mut Strings, text: &[u8], create_values: bool) -> Parsed {
    let mut p = Parser {
        text,
        strings,
        errors: Vec::new(),
    };
    let list = p.query(create_values);
    Parsed {
        list,
        errors: p.errors,
    }
}

/// `ossl_property_match_count`: how many of the query's properties the definition matches,
/// or -1 if it fails one that isn't optional. A property the definition lacks compares as
/// `no`.
pub fn match_count(query: &List, defn: &List) -> i32 {
    let q = &query.properties;
    let d = &defn.properties;
    let (mut i, mut j) = (0, 0);
    let mut matches: i32 = 0;
    while let Some(qp) = q.get(i) {
        if qp.oper == Oper::Override {
            i = i.saturating_add(1);
            continue;
        }
        if let Some(dp) = d.get(j) {
            if qp.name > dp.name {
                j = j.saturating_add(1);
                continue;
            }
            if qp.name == dp.name {
                let eq = qp.value == dp.value && qp.value != Value::Undefined;
                if (eq && qp.oper == Oper::Eq) || (!eq && qp.oper == Oper::Ne) {
                    matches = matches.saturating_add(1);
                } else if !qp.optional {
                    return -1;
                }
                i = i.saturating_add(1);
                j = j.saturating_add(1);
                continue;
            }
        }
        match qp.value {
            Value::Undefined => {
                if qp.oper == Oper::Ne {
                    matches = matches.saturating_add(1);
                } else if !qp.optional {
                    return -1;
                }
            }
            Value::String(v)
                if (qp.oper == Oper::Eq && v == FALSE) || (qp.oper == Oper::Ne && v != FALSE) =>
            {
                matches = matches.saturating_add(1);
            }
            _ => {
                if !qp.optional {
                    return -1;
                }
            }
        }
        i = i.saturating_add(1);
    }
    matches
}

/// `ossl_property_merge`: both lists' properties, `a`'s where both have a name.
pub fn merge(a: &List, b: &List) -> List {
    let (ap, bp) = (&a.properties, &b.properties);
    let (mut i, mut j) = (0, 0);
    let mut properties = Vec::with_capacity(ap.len().saturating_add(bp.len()));
    loop {
        let copy = match (ap.get(i), bp.get(j)) {
            (None, None) => break,
            (None, Some(y)) => {
                j = j.saturating_add(1);
                y
            }
            (Some(x), None) => {
                i = i.saturating_add(1);
                x
            }
            (Some(x), Some(y)) if x.name <= y.name => {
                if x.name == y.name {
                    j = j.saturating_add(1);
                }
                i = i.saturating_add(1);
                x
            }
            (Some(_), Some(y)) => {
                j = j.saturating_add(1);
                y
            }
        };
        properties.push(*copy);
    }
    let has_optional = properties.iter().any(|p| p.optional);
    List {
        properties,
        has_optional,
    }
}

/// `put_str`: a name or value, quoted unless it's only letters, digits, `.`, and `_` (with
/// double quotes if it has a single one).
fn put_str(out: &mut Vec<u8>, s: &[u8]) {
    let mut quote = None;
    for &c in s {
        if !c.is_ascii_alphanumeric() && c != b'.' && c != b'_' {
            if quote.is_none() {
                quote = Some(b'\'');
            }
            if c == b'\'' {
                quote = Some(b'"');
            }
        }
    }
    out.extend(quote);
    out.extend_from_slice(s);
    out.extend(quote);
}

/// `ossl_property_list_to_string`: the canonical text of a list (empty for none), from the
/// highest name number down, skipping unknown names; `None` if a compared property has no
/// value (OpenSSL's 0).
pub fn to_text(strings: &Strings, list: Option<&List>) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let Some(list) = list else { return Some(out) };
    for p in list.properties.iter().rev() {
        if p.name == 0 {
            continue;
        }
        if !out.is_empty() {
            out.push(b',');
        }
        if p.optional {
            out.push(b'?');
        } else if p.oper == Oper::Override {
            out.push(b'-');
        }
        put_str(&mut out, strings.name_text(p.name)?);
        if p.oper == Oper::Override {
            continue;
        }
        if p.oper == Oper::Ne {
            out.push(b'!');
        }
        out.push(b'=');
        match p.value {
            Value::String(v) => put_str(&mut out, strings.value_text(v)?),
            Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
            Value::Undefined => return None,
        }
    }
    Some(out)
}

/// `ossl_property_find_property`: the property `name` in the list.
pub fn find<'a>(
    strings: &mut Strings,
    list: Option<&'a List>,
    name: &[u8],
) -> Option<&'a Definition> {
    let n = strings.name(name, false);
    if n == 0 {
        return None;
    }
    let list = list?;
    let i = list.properties.binary_search_by_key(&n, |p| p.name).ok()?;
    list.properties.get(i)
}

/// `ossl_property_is_enabled`: whether the list asks for `name` to be `yes` (or, with `!=`,
/// anything but `yes`), not optionally.
pub fn is_enabled(strings: &mut Strings, name: &[u8], list: Option<&List>) -> bool {
    let Some(p) = find(strings, list, name) else {
        return false;
    };
    if p.optional || p.oper == Oper::Override {
        return false;
    }
    match p.value {
        Value::String(v) => (p.oper == Oper::Eq && v == TRUE) || (p.oper == Oper::Ne && v != TRUE),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(s: &mut Strings, text: &str) -> Parsed {
        parse_query(s, text.as_bytes(), true)
    }

    fn text(s: &Strings, list: &List) -> String {
        String::from_utf8(to_text(s, Some(list)).unwrap()).unwrap()
    }

    #[test]
    fn canonical_text_follows_name_numbers() {
        let mut s = Strings::new();
        let q = query(
            &mut s,
            " provider = Default , ?fips=yes, x.y != 'a b', -output,version=0x1F",
        );
        assert_eq!(q.errors, vec![]);
        let list = q.list.unwrap();
        assert_eq!(
            text(&s, &list),
            "x.y!='a b',-output,?fips=yes,version=31,provider=default"
        );
        assert!(list.has_optional);
    }

    #[test]
    fn errors_carry_openssl_text() {
        let mut s = Strings::new();
        let q = query(&mut s, "foo,bar");
        assert_eq!(q.list, None);
        assert_eq!(q.errors[0].data, b"Duplicated name `<NULL>'");
        let q = query(&mut s, "fips=12a");
        assert_eq!(q.errors[0].reason, Reason::NotADecimalDigit);
        assert_eq!(q.errors[0].data, b"HERE-->12a");
        assert_eq!(q.errors[1].reason, Reason::TrailingCharacters);
        let q = query(&mut s, "fips=99999999999999999999");
        assert_eq!(q.errors[0].data, b"Property 99999999999999999999 overflows");
        let d = parse_definition(&mut s, b"nosuch=1");
        assert_eq!(d.errors[0].data, b"Unknown name HERE-->nosuch=1");
        let q = query(&mut s, "fips=");
        assert!(q.errors.is_empty());
        assert_eq!(to_text(&s, q.list.as_ref()), None);
    }

    #[test]
    fn matching() {
        let mut s = Strings::new();
        let defn = parse_definition(&mut s, b"provider=default,fips=yes")
            .list
            .unwrap();
        let m = |s: &mut Strings, q: &str| match_count(&query(s, q).list.unwrap(), &defn);
        assert_eq!(m(&mut s, "provider=default"), 1);
        assert_eq!(m(&mut s, "provider=legacy"), -1);
        assert_eq!(m(&mut s, "?provider=legacy,fips"), 1);
        assert_eq!(m(&mut s, "output=no"), 1);
        assert_eq!(m(&mut s, "output"), -1);
        assert_eq!(m(&mut s, "-provider,fips!=no"), 1);
        assert_eq!(m(&mut s, "fips=1"), -1);
        let merged = merge(&query(&mut s, "fips=no").list.unwrap(), &defn);
        assert_eq!(text(&s, &merged), "fips=no,provider=default");
        assert!(is_enabled(&mut s, b"fips", Some(&defn)));
        assert!(!is_enabled(&mut s, b"fips", Some(&merged)));
    }
}
