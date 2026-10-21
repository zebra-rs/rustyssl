//! `apps/lib/app_params.c`: describing and printing `OSSL_PARAM`s (`list`, `mac`, `kdf`), and
//! `app_params_new_from_opts` of `apps.c` (`-macopt`, `-kdfopt`, `-skeyopt`).

use std::io::Write;

use rustyssl_ossl::abi::{
    OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_PTR, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UNSIGNED_INTEGER,
    OSSL_PARAM_UTF8_PTR, OSSL_PARAM_UTF8_STRING,
};
use rustyssl_ossl::params::{ParamRef, Params, ParamsRef, Value};

use super::io;
use super::opt::eprintf;

/// The most of an octet string's body that is printed.
const MAX_OCTET_STRING_OUTPUT_BYTES: usize = 24;

fn is(t: u32, c: i32) -> bool {
    u32::try_from(c).is_ok_and(|c| c == t)
}

/// `describe_param_type`.
fn describe_param_type(p: &ParamRef<'_>) -> String {
    let t = p.data_type();
    let (type_mod, kind, show_number) = if is(t, OSSL_PARAM_UNSIGNED_INTEGER) {
        ("unsigned ", "integer", false)
    } else if is(t, OSSL_PARAM_INTEGER) {
        ("", "integer", false)
    } else if is(t, OSSL_PARAM_UTF8_PTR) {
        ("pointer to a ", "UTF8 encoded string", false)
    } else if is(t, OSSL_PARAM_UTF8_STRING) {
        ("", "UTF8 encoded string", false)
    } else if is(t, OSSL_PARAM_OCTET_PTR) {
        ("pointer to an ", "octet string", false)
    } else if is(t, OSSL_PARAM_OCTET_STRING) {
        ("", "octet string", false)
    } else {
        ("", "unknown type", true)
    };
    let mut buf = format!("{}: {type_mod}{kind}", p.key());
    if show_number {
        buf.push_str(&format!(" [{t}]"));
    }
    if p.data_size() == 0 {
        buf.push_str(" (arbitrary size)");
    } else {
        buf.push_str(&format!(" (max {} bytes large)", p.data_size()));
    }
    // The description is formatted into a 200-byte buffer.
    truncate(&mut buf, 199);
    buf
}

fn truncate(s: &mut String, max: usize) {
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
}

/// `print_param_types(thing, pdefs, indent)`.
pub fn print_param_types(thing: &str, pdefs: ParamsRef<'_>, indent: usize) {
    if pdefs.is_null() {
        return;
    }
    let pad = " ".repeat(indent);
    let mut text = String::new();
    let mut entries = pdefs.iter().peekable();
    if entries.peek().is_none() {
        // A badly written provider's empty list.
        text.push_str(&format!("{pad}Empty list of {thing} (!!!)\n"));
    } else {
        text.push_str(&format!("{pad}{thing}:\n"));
        for p in entries {
            text.push_str(&format!("{pad}  {}\n", describe_param_type(&p)));
        }
    }
    let _ = io::out().write_all(text.as_bytes());
}

/// `print_param_value(p, indent)`.
pub fn print_param_value(p: &ParamRef<'_>, indent: usize) {
    let mut out: Vec<u8> = format!("{}{}: ", " ".repeat(indent), p.key()).into_bytes();
    match p.value() {
        Value::Unsigned(Some(u)) => out.extend_from_slice(format!("{u}\n").as_bytes()),
        Value::Signed(Some(i)) => out.extend_from_slice(format!("{i}\n").as_bytes()),
        Value::Unsigned(None) | Value::Signed(None) => {
            out.extend_from_slice(b"error getting value\n");
        }
        Value::Bytes { utf8: true, bytes } => match bytes {
            Err(()) => out.extend_from_slice(b" ptr null\n"),
            Ok(None) => out.extend_from_slice(b" null\n"),
            Ok(Some(s)) => {
                out.push(b'\'');
                out.extend_from_slice(&s);
                out.extend_from_slice(b"'\n");
            }
        },
        Value::Bytes { utf8: false, bytes } => {
            out.extend_from_slice(format!("<{} bytes>", p.return_size()).as_bytes());
            match bytes {
                Err(()) => out.extend_from_slice(b" ptr null\n"),
                Ok(None) => out.extend_from_slice(b" null\n"),
                Ok(Some(b)) if b.is_empty() => out.push(b'\n'),
                Ok(Some(b)) => {
                    let (shown, tail): (&[u8], &[u8]) = if b.len() > MAX_OCTET_STRING_OUTPUT_BYTES {
                        (
                            b.get(..MAX_OCTET_STRING_OUTPUT_BYTES).unwrap_or_default(),
                            b"...\n",
                        )
                    } else {
                        (&b, b"\n")
                    };
                    out.push(b' ');
                    for byte in shown {
                        out.extend_from_slice(format!("{byte:02x}").as_bytes());
                    }
                    out.extend_from_slice(tail);
                }
            }
        }
        Value::Unknown => out.extend_from_slice(
            format!(
                "unknown type ({}) of {} bytes\n",
                p.data_type(),
                p.return_size()
            )
            .as_bytes(),
        ),
    }
    let _ = io::out().write_all(&out);
}

/// `app_params_new_from_opts(opts, paramdefs)`: each `key:value` option as a parameter, with
/// upstream's message (and the error queue) when one can't be.
pub fn app_params_new_from_opts(opts: &[String], paramdefs: ParamsRef<'_>) -> Option<Params> {
    match Params::from_text(paramdefs, opts) {
        Ok(p) => Some(p),
        Err(e) => {
            let what = if e.found { "error" } else { "unknown" };
            let opt = opts.get(e.index).map_or("", String::as_str);
            eprintf!("Parameter {what} '{opt}'\n");
            io::print_errors();
            None
        }
    }
}
