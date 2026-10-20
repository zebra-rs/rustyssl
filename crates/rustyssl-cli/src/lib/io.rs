//! The program's standard streams (`bio_in`, `bio_out`, `bio_err` of `openssl.c`).
//!
//! Upstream wraps `stdin`, `stdout`, and `stderr` in file `BIO`s. Here they are `fd` `BIO`s on
//! 0, 1, and 2, which write the same bytes, unbuffered; the CLI's own text goes through the
//! same `BIO`s (standard error through the descriptor directly, which is the same unbuffered
//! stream), so the library's output and the CLI's stay in order.

use std::cell::RefCell;
use std::io::{self, Write};

use rustyssl_ossl::Bio;

struct Streams {
    input: Bio,
    out: Bio,
    err: Bio,
}

thread_local! {
    /// The streams, made once by the thread that uses them (the main thread) and kept to the
    /// end (the descriptors themselves are never closed).
    static STREAMS: Option<&'static Streams> = (|| {
        let s = Streams {
            input: Bio::new_fd(0, false)?,
            out: Bio::new_fd(1, false)?,
            err: Bio::new_fd(2, false)?,
        };
        Some(&*Box::leak(Box::new(s)))
    })();
}

/// Wraps the descriptors; the program calls this first.
pub fn init() -> bool {
    streams().is_some()
}

fn streams() -> Option<&'static Streams> {
    STREAMS.with(|s| *s)
}

thread_local! {
    /// Standard error, captured (for tests).
    static CAPTURED: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

/// Runs `f`, collecting what it writes to standard error through [`err`].
/// Captures nest: the outer capture resumes afterwards.
pub fn capture_err<T>(f: impl FnOnce() -> T) -> (T, Vec<u8>) {
    let outer = CAPTURED.with(|c| c.borrow_mut().replace(Vec::new()));
    let t = f();
    let bytes = CAPTURED.with(|c| std::mem::replace(&mut *c.borrow_mut(), outer));
    (t, bytes.unwrap_or_default())
}

/// Standard error for the CLI's own text (`opt_printf_stderr`, `BIO_printf(bio_err, ...)`).
pub struct ErrStream;

impl Write for ErrStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let captured = CAPTURED.with(|c| {
            c.borrow_mut().as_mut().map(|v| {
                v.extend_from_slice(buf);
            })
        });
        match captured {
            Some(()) => Ok(buf.len()),
            None => io::stderr().write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stderr().flush()
    }
}

/// See [`ErrStream`].
pub fn err() -> ErrStream {
    ErrStream
}

/// `bio_err`, for the library's own printing (`ERR_print_errors(bio_err)`, ...).
pub fn bio_err() -> Option<&'static Bio> {
    streams().map(|s| &s.err)
}

/// `bio_out`.
pub fn bio_out() -> Option<&'static Bio> {
    streams().map(|s| &s.out)
}

/// `bio_in`.
pub fn bio_in() -> Option<&'static Bio> {
    streams().map(|s| &s.input)
}

/// Standard output (`printf`, `BIO_printf(bio_out, ...)`): through `bio_out`.
pub struct OutStream;

impl Write for OutStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match bio_out() {
            Some(b) => {
                b.write_all(buf)?;
                Ok(buf.len())
            }
            None => Err(io::Error::other("no standard output")),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// See [`OutStream`].
pub fn out() -> OutStream {
    OutStream
}

/// `ERR_print_errors(bio_err)`.
pub fn print_errors() {
    if let Some(b) = bio_err() {
        rustyssl_ossl::err::print_errors(b);
    }
}
