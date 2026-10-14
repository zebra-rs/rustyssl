//! A small JSON reader for the test-vector files xtask fetches (Wycheproof): objects, arrays,
//! strings with every escape, numbers kept as their text, `true`, `false`, and `null`. The
//! files are downloaded data, so nesting is capped and every error is reported, never panicked.

use crate::util::Result;

/// How deep arrays and objects may nest.
const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// A number's text, as written.
    Number(String),
    String(String),
    Array(Vec<Value>),
    /// The members in their order.
    Object(Vec<(String, Value)>),
}

impl Value {
    /// The member `key` of an object.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    /// A number without a fraction or exponent.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Number(n) => n.parse().ok(),
            _ => None,
        }
    }
}

/// Parses `text`, which must hold one value and nothing else but white space.
pub fn parse(text: &str) -> Result<Value> {
    let mut p = Parser {
        bytes: text.as_bytes(),
        at: 0,
    };
    let value = p.value(0)?;
    p.space();
    if p.at != p.bytes.len() {
        return Err(p.error("text after the value"));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn error(&self, what: &str) -> Box<dyn std::error::Error> {
        format!("JSON: {what} at octet {}", self.at).into()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.at += 1;
        Some(b)
    }

    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn expect(&mut self, b: u8) -> Result {
        if self.next() == Some(b) {
            Ok(())
        } else {
            Err(self.error(&format!("expected `{}`", char::from(b))))
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Result<Value> {
        if self.bytes.get(self.at..self.at + word.len()) == Some(word.as_bytes()) {
            self.at += word.len();
            Ok(value)
        } else {
            Err(self.error("unknown literal"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value> {
        if depth > MAX_DEPTH {
            return Err(self.error("nested too deep"));
        }
        self.space();
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(self.error("expected a value")),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value> {
        self.expect(b'{')?;
        let mut members = Vec::new();
        self.space();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::Object(members));
        }
        loop {
            self.space();
            let key = self.string()?;
            self.space();
            self.expect(b':')?;
            let value = self.value(depth + 1)?;
            members.push((key, value));
            self.space();
            match self.next() {
                Some(b',') => {}
                Some(b'}') => return Ok(Value::Object(members)),
                _ => return Err(self.error("expected `,` or `}`")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.space();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.space();
            match self.next() {
                Some(b',') => {}
                Some(b']') => return Ok(Value::Array(items)),
                _ => return Err(self.error("expected `,` or `]`")),
            }
        }
    }

    fn number(&mut self) -> Result<Value> {
        let start = self.at;
        while matches!(
            self.peek(),
            Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
        ) {
            self.at += 1;
        }
        let text = std::str::from_utf8(self.bytes.get(start..self.at).unwrap_or_default())?;
        if text.parse::<f64>().is_err() {
            return Err(self.error("bad number"));
        }
        Ok(Value::Number(text.to_owned()))
    }

    fn hex4(&mut self) -> Result<u32> {
        let digits = self
            .bytes
            .get(self.at..self.at + 4)
            .ok_or_else(|| self.error("short \\u escape"))?;
        let value = u32::from_str_radix(std::str::from_utf8(digits)?, 16)
            .map_err(|_| self.error("bad \\u escape"))?;
        self.at += 4;
        Ok(value)
    }

    fn string(&mut self) -> Result<String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let start = self.at;
            while !matches!(self.peek(), None | Some(b'"' | b'\\')) {
                if self.peek().is_some_and(|b| b < 0x20) {
                    return Err(self.error("control character in a string"));
                }
                self.at += 1;
            }
            out.push_str(std::str::from_utf8(
                self.bytes.get(start..self.at).unwrap_or_default(),
            )?);
            match self.next() {
                Some(b'"') => return Ok(out),
                Some(b'\\') => {}
                _ => return Err(self.error("unterminated string")),
            }
            let c = match self.next() {
                Some(b'"') => '"',
                Some(b'\\') => '\\',
                Some(b'/') => '/',
                Some(b'b') => '\u{8}',
                Some(b'f') => '\u{c}',
                Some(b'n') => '\n',
                Some(b'r') => '\r',
                Some(b't') => '\t',
                Some(b'u') => {
                    let first = self.hex4()?;
                    let code = if (0xd800..0xdc00).contains(&first) {
                        if self.next() != Some(b'\\') || self.next() != Some(b'u') {
                            return Err(self.error("a lone surrogate"));
                        }
                        let second = self.hex4()?;
                        if !(0xdc00..0xe000).contains(&second) {
                            return Err(self.error("a lone surrogate"));
                        }
                        0x1_0000 + ((first - 0xd800) << 10) + (second - 0xdc00)
                    } else {
                        first
                    };
                    char::from_u32(code).ok_or_else(|| self.error("a lone surrogate"))?
                }
                _ => return Err(self.error("bad escape")),
            };
            out.push(c);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_what_wycheproof_uses() {
        let v = parse(r#" {"a": [1, -2.5e3, "x\"\u00e9\ud83d\ude00", true, null, {}], "b": []} "#)
            .unwrap();
        let a = v.get("a").and_then(Value::as_array).unwrap();
        assert_eq!(a[0].as_u64(), Some(1));
        assert_eq!(a[1], Value::Number("-2.5e3".to_owned()));
        assert_eq!(a[2].as_str(), Some("x\"\u{e9}\u{1f600}"));
        assert_eq!(a[3], Value::Bool(true));
        assert_eq!(
            v.get("b").and_then(Value::as_array).map(<[Value]>::len),
            Some(0)
        );
    }

    #[test]
    fn rejects_bad_text() {
        for bad in [
            "",
            "[1,",
            "{\"a\" 1}",
            "\"\\ud800\"",
            "[1] 2",
            "tru",
            "\"a\nb\"",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        assert!(parse(&"[".repeat(100)).is_err());
    }
}
