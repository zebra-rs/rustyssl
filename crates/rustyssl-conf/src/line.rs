//! Logical lines from what a reader gives (`def_load_bio`'s reading half).

use crate::Classes;
use crate::classes::ESC;

/// The size of OpenSSL's reads: `BIO_gets` into 512 octets less one, so at most 510 octets
/// and a terminator come in at once.
pub const READ_SIZE: usize = 511;

/// What [`Lines::feed`] makes of a read.
#[derive(Debug, PartialEq, Eq)]
pub enum Next {
    /// The reader is at its end (nothing read and no line pending): the caller goes on with
    /// the next file, or stops.
    End,
    /// The read continues a line: feed the next one.
    More,
    /// A logical line, without its line ending and continuations.
    Line(Vec<u8>),
}

/// Puts logical lines together from reads of at most [`READ_SIZE`] less one octets, as
/// OpenSSL does: a read that fills the buffer without a line ending continues the line (as
/// does one cut short by a NUL, which the caller drops with what follows it, as `strlen`
/// does); trailing CRs and LFs end it; an unescaped `\` at its end continues it on the next
/// line; a UTF-8 byte order mark at the start of the first read is dropped.
#[derive(Debug)]
pub struct Lines {
    buf: Vec<u8>,
    again: bool,
    first: bool,
    line: i64,
}

impl Default for Lines {
    fn default() -> Self {
        Self::new()
    }
}

impl Lines {
    /// Nothing read yet.
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            again: false,
            first: true,
            line: 0,
        }
    }

    /// The number of lines ended so far (OpenSSL's `eline`), across every file read.
    pub fn line(&self) -> i64 {
        self.line
    }

    /// Takes one read: its octets up to the first NUL (at most [`READ_SIZE`] less one).
    pub fn feed(&mut self, classes: Classes<'_>, read: &[u8]) -> Next {
        let mut chunk = read;
        if self.first {
            self.first = false;
            if let Some(rest) = chunk.strip_prefix(&[0xef, 0xbb, 0xbf]) {
                chunk = rest;
            }
        }
        if chunk.is_empty() && !self.again {
            return Next::End;
        }
        self.again = false;
        let full = chunk.len();
        let mut kept = full;
        while let Some(&c) = kept.checked_sub(1).and_then(|i| chunk.get(i)) {
            if c != b'\r' && c != b'\n' {
                break;
            }
            kept = kept.saturating_sub(1);
        }
        if full != 0 && kept == full {
            // No line ending: a long line, continued by the next read.
            self.again = true;
        } else {
            self.line = self.line.saturating_add(1);
        }
        self.buf
            .extend_from_slice(chunk.get(..kept).unwrap_or_default());
        if !self.again {
            let n = self.buf.len();
            let last = n.checked_sub(1).and_then(|i| self.buf.get(i)).copied();
            let before = n.checked_sub(2).and_then(|i| self.buf.get(i)).copied();
            if let Some(last) = last
                && classes.is(last, ESC)
                && (n <= 1 || !before.is_some_and(|b| classes.is(b, ESC)))
            {
                self.buf.pop();
                self.again = true;
            }
        }
        if self.again {
            return Next::More;
        }
        Next::Line(core::mem::take(&mut self.buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(reads: &[&[u8]]) -> (Vec<Next>, i64) {
        let mut l = Lines::new();
        let out = reads.iter().map(|r| l.feed(Classes::DEFAULT, r)).collect();
        (out, l.line())
    }

    #[test]
    fn endings_continuations_and_marks() {
        let (out, n) = lines(&[b"\xef\xbb\xbfa = 1\r\n", b"b = 2 \\\n", b"  c\n", b""]);
        assert_eq!(
            out,
            [
                Next::Line(b"a = 1".to_vec()),
                Next::More,
                Next::Line(b"b = 2   c".to_vec()),
                Next::End
            ]
        );
        assert_eq!(n, 3);
        // An escaped backslash ends the line; a long read continues it.
        let (out, _) = lines(&[b"x = \\\\\n", b"long", b"er\n"]);
        assert_eq!(
            out,
            [
                Next::Line(b"x = \\\\".to_vec()),
                Next::More,
                Next::Line(b"longer".to_vec())
            ]
        );
        // A pending line ends at the end of the reader.
        let (out, n) = lines(&[b"tail", b"", b""]);
        assert_eq!(out, [Next::More, Next::Line(b"tail".to_vec()), Next::End]);
        assert_eq!(n, 1);
        // Only the first read loses a byte order mark.
        let (out, _) = lines(&[b"\n", b"\xef\xbb\xbfz\n"]);
        assert_eq!(
            out,
            [
                Next::Line(Vec::new()),
                Next::Line(b"\xef\xbb\xbfz".to_vec())
            ]
        );
    }
}
