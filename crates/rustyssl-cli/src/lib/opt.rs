//! Option parsing: a port of `apps/lib/opt.c` (ADR 0007, section 3), with its semantics and its
//! exact help, usage, and error texts.
//!
//! The tables come from codegen (`crate::generated::options`). As in upstream:
//! - names match exactly (no unique-prefix matching); `-h` also selects `help`, and `--name`
//!   is the same as `-name`;
//! - `-name=value` gives a value inline; a lone `--` ends the options;
//! - each value type is checked (`n` an int, `p` a positive int, `<` nothing, a format letter a
//!   format, ...), with `opt.c`'s messages, which go to standard error.
//!
//! Upstream keeps the parser's state in globals; here a [`Parser`] holds one command's, and the
//! program name every message starts with (`opt_getprog()`) is [`prog`].

use std::cell::RefCell;
use std::io::Write;

use super::io;

/// Kinds of marker entries (`OPT_HELP_STR`, `OPT_MORE_STR`, `OPT_SECTION_STR`,
/// `OPT_PARAM_STR`), which C tells apart by address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Marker {
    Help,
    More,
    Section,
    Param,
}

/// One `OPTIONS` entry.
#[derive(Debug)]
pub struct OptDef<O: 'static> {
    /// The name without its `-`; markers have `-H`, `-M`, `-S`, `-P`, as in `opt.c`.
    pub name: &'static str,
    pub marker: Option<Marker>,
    /// What [`Parser::next`] returns for it; `None` for `OPT_DUP` (a second listing in the
    /// help, after the real one).
    pub ret: Option<O>,
    /// The value type: `-` or 0 for none, `s`, `<`, `>`, `n`, `p`, a format letter, ...
    pub valtype: u8,
    pub help: Option<&'static str>,
}

/// A command's choice enum: `OPT_ERR` and `OPT_EOF`.
pub trait Choice: Copy + 'static {
    const ERR: Self;
    const EOF: Self;
}

/// `fmt.h`'s formats, as the apps number them (an apps-internal convention, not ABI).
pub mod format {
    pub const B_FORMAT_TEXT: i32 = 0x8000;
    pub const UNDEF: i32 = 0;
    pub const TEXT: i32 = 1 | B_FORMAT_TEXT;
    pub const BINARY: i32 = 2;
    pub const BASE64: i32 = 3 | B_FORMAT_TEXT;
    pub const ASN1: i32 = 4;
    pub const PEM: i32 = 5 | B_FORMAT_TEXT;
    pub const PKCS12: i32 = 6;
    pub const SMIME: i32 = 7 | B_FORMAT_TEXT;
    pub const ENGINE: i32 = 8;
    pub const PEMRSA: i32 = 9 | B_FORMAT_TEXT;
    pub const ASN1RSA: i32 = 10;
    pub const MSBLOB: i32 = 11;
    pub const PVK: i32 = 12;
    pub const HTTP: i32 = 13;
    pub const NSS: i32 = 14;

    /// `FMT_istext`.
    pub fn is_text(format: i32) -> bool {
        format & B_FORMAT_TEXT == B_FORMAT_TEXT
    }
}

/// `opt_format`'s flags (`OPT_FMT_*` of `opt.h`).
pub mod fmt_flags {
    pub const PEM: u64 = 1 << 1;
    pub const DER: u64 = 1 << 2;
    pub const B64: u64 = 1 << 3;
    pub const PKCS12: u64 = 1 << 4;
    pub const SMIME: u64 = 1 << 5;
    pub const ENGINE: u64 = 1 << 6;
    pub const MSBLOB: u64 = 1 << 7;
    pub const NSS: u64 = 1 << 8;
    pub const TEXT: u64 = 1 << 9;
    pub const HTTP: u64 = 1 << 10;
    pub const PVK: u64 = 1 << 11;
    pub const PEMDER: u64 = PEM | DER;
    pub const ASN1: u64 = PEM | DER | B64;
    pub const PDE: u64 = PEMDER | ENGINE;
    pub const PDS: u64 = PEMDER | SMIME;
    pub const ANY: u64 =
        PEM | DER | B64 | PKCS12 | SMIME | ENGINE | MSBLOB | NSS | TEXT | HTTP | PVK;
}

thread_local! {
    /// `opt.c`'s `prog[40]`: the program name messages start with. The commands run on the
    /// main thread; one per thread keeps the tests apart.
    static PROG: RefCell<String> = const { RefCell::new(String::new()) };
}

/// `MAX_OPT_HELP_WIDTH`.
const MAX_OPT_HELP_WIDTH: usize = 30;

/// `opt_getprog()`.
pub fn prog() -> String {
    PROG.with(|p| p.borrow().clone())
}

/// Keeps the first 39 bytes, as `strncpy` into `prog[40]` does (on a character boundary).
fn set_prog(name: &str) {
    let mut end = name.len().min(39);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    PROG.with(|p| {
        let mut p = p.borrow_mut();
        p.clear();
        p.push_str(name.get(..end).unwrap_or_default());
    });
}

/// `opt_path_end` (Unix): what follows the last `/`, unless the only `/` is the first byte.
pub fn path_end(filename: &str) -> &str {
    match filename.rfind('/') {
        Some(0) | None => filename,
        Some(i) => filename.get(i + 1..).unwrap_or_default(),
    }
}

/// `opt_progname`.
pub fn progname(argv0: &str) -> String {
    set_prog(path_end(argv0));
    prog()
}

/// `opt_appname`: the program name followed by ` <argv0>`, within the 40-byte buffer.
pub fn appname(argv0: &str) -> String {
    let p = prog();
    let room = 40usize.saturating_sub(p.len()).saturating_sub(2);
    let mut extra = format!(" {argv0}");
    let mut end = extra.len().min(room);
    while !extra.is_char_boundary(end) {
        end -= 1;
    }
    extra.truncate(end);
    set_prog(&format!("{p}{extra}"));
    prog()
}

/// `opt_printf_stderr` with C's `%s` (taking `args` in turn) and `%%`; returns the length.
pub fn printf_stderr(fmt: &str, args: &[&str]) -> usize {
    let text = c_format(fmt, args);
    let _ = io::err().write_all(text.as_bytes());
    text.len()
}

/// Writes `text` to standard error; returns its length.
pub fn write_err(text: &str) -> usize {
    let _ = io::err().write_all(text.as_bytes());
    text.len()
}

/// A C format string with `%s` and `%%` only.
fn c_format(fmt: &str, args: &[&str]) -> String {
    let mut out = String::new();
    let mut args = args.iter();
    let mut chars = fmt.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('s') => out.push_str(args.next().copied().unwrap_or("(null)")),
            Some('%') => out.push('%'),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

/// Writes to standard error (`opt_printf_stderr` for text without directives), returning the
/// length written, as `BIO_printf` does.
macro_rules! eprintf {
    ($($arg:tt)*) => {
        $crate::lib::opt::write_err(&format!($($arg)*))
    };
}
pub(crate) use eprintf;

/// The parser for one command's arguments (`opt_init` ... `opt_rest`).
pub struct Parser<O: Choice> {
    argv: Vec<String>,
    index: usize,
    arg: Option<String>,
    flag: Option<String>,
    dunno: Option<String>,
    unknown: Option<&'static OptDef<O>>,
    unknown_name: Option<&'static str>,
    opts: &'static [OptDef<O>],
}

impl<O: Choice> Parser<O> {
    /// `opt_init`: `argv[0]` names the program in every message.
    pub fn new(argv: &[String], opts: &'static [OptDef<O>]) -> Self {
        Self::with_unknown(argv, opts, None)
    }

    /// `opt_set_unknown_name(name)` then `opt_init`: the table's entry with an empty name
    /// stands for one argument that isn't an option (a digest or cipher name, for instance).
    pub fn with_unknown(
        argv: &[String],
        opts: &'static [OptDef<O>],
        unknown_name: Option<&'static str>,
    ) -> Self {
        progname(argv.first().map_or("", String::as_str));
        let mut unknown = None;
        for o in opts {
            if o.marker == Some(Marker::Param) {
                break;
            }
            if o.marker.is_none() && o.name.is_empty() && unknown_name.is_some() {
                unknown = Some(o);
            }
        }
        Self {
            argv: argv.to_vec(),
            index: 1,
            arg: None,
            flag: None,
            dunno: None,
            unknown,
            unknown_name,
            opts,
        }
    }

    /// The program name, as `opt_init` returns it.
    pub fn prog(&self) -> String {
        prog()
    }

    /// `opt_begin`: start again from the first argument.
    pub fn begin(&mut self) {
        self.index = 1;
        self.arg = None;
        self.flag = None;
    }

    /// `opt_next`: the next option's choice; `EOF` at the end of the options, `ERR` (the
    /// message printed) on an error.
    pub fn next(&mut self) -> O {
        self.arg = None;
        let Some(word) = self.argv.get(self.index).cloned() else {
            return O::EOF;
        };
        if !word.starts_with('-') {
            return O::EOF;
        }
        self.index += 1;
        if word == "--" {
            return O::EOF;
        }
        let mut p = word.get(1..).unwrap_or_default();
        if let Some(rest) = p.strip_prefix('-') {
            p = rest;
        }
        let (p, inline) = match p.split_once('=') {
            Some((name, value)) => (name, Some(value.to_owned())),
            None => (p, None),
        };
        self.flag = Some(format!("-{p}"));
        self.arg = inline;
        let prog = prog();
        for o in self.opts {
            if !(p == "h" && o.name == "help") && p != o.name {
                continue;
            }
            let Some(ret) = o.ret else {
                continue; // OPT_DUP: the real entry came first
            };
            if o.valtype == 0 || o.valtype == b'-' {
                if self.arg.is_some() {
                    eprintf!("{prog}: Option -{p} does not take a value\n");
                    return O::ERR;
                }
                return ret;
            }
            if self.arg.is_none() {
                let Some(value) = self.argv.get(self.index).cloned() else {
                    eprintf!("{prog}: Option -{} needs a value\n", o.name);
                    return O::ERR;
                };
                self.index += 1;
                self.arg = Some(value);
            }
            let arg = self.arg.clone().unwrap_or_default();
            match o.valtype {
                b'/' => {
                    if isdir(&arg) != Some(true) {
                        eprintf!("{prog}: Not a directory: {arg}\n");
                        return O::ERR;
                    }
                }
                b'p' | b'n' | b'N' => {
                    let Some(ival) = int(&arg) else {
                        return O::ERR;
                    };
                    if o.valtype == b'p' && ival <= 0 {
                        eprintf!(
                            "{prog}: Non-positive number \"{arg}\" for option -{}\n",
                            o.name
                        );
                        return O::ERR;
                    }
                    if o.valtype == b'N' && ival < 0 {
                        eprintf!("{prog}: Negative number \"{arg}\" for option -{}\n", o.name);
                        return O::ERR;
                    }
                }
                b'M' => {
                    if intmax(&arg).is_none() {
                        return O::ERR;
                    }
                }
                b'U' => {
                    if uintmax(&arg).is_none() {
                        return O::ERR;
                    }
                }
                b'l' => {
                    if long(&arg).is_none() {
                        return O::ERR;
                    }
                }
                b'u' => {
                    if ulong(&arg).is_none() {
                        return O::ERR;
                    }
                }
                b'c' | b'E' | b'F' | b'f' | b'A' | b'a' => {
                    let flags = match o.valtype {
                        b'c' => fmt_flags::PDS,
                        b'E' => fmt_flags::PDE,
                        b'F' => fmt_flags::PEMDER,
                        b'A' => fmt_flags::ASN1,
                        _ => fmt_flags::ANY,
                    };
                    if parse_format(&arg, flags).is_none() {
                        eprintf!("{prog}: Invalid format \"{arg}\" for option -{}\n", o.name);
                        return O::ERR;
                    }
                }
                _ => {} // strings, files, parameters
            }
            return ret;
        }
        if let Some(unknown) = self.unknown {
            if let Some(dunno) = &self.dunno {
                eprintf!(
                    "{prog}: Multiple {} or unknown options: -{dunno} and -{p}\n",
                    self.unknown_name.unwrap_or_default()
                );
                return O::ERR;
            }
            self.dunno = Some(p.to_owned());
            return unknown.ret.unwrap_or(O::ERR);
        }
        eprintf!("{prog}: Unknown option: -{p}\n");
        O::ERR
    }

    /// `opt_arg`: the most recent option's value.
    pub fn arg(&self) -> &str {
        self.arg.as_deref().unwrap_or_default()
    }

    /// `opt_arg` as C has it: `None` before any value.
    pub fn arg_opt(&self) -> Option<&str> {
        self.arg.as_deref()
    }

    /// `opt_flag`: the most recent option, with one `-`.
    pub fn flag(&self) -> &str {
        self.flag.as_deref().unwrap_or_default()
    }

    /// `opt_unknown`: the unknown option, without its `-`.
    pub fn unknown(&self) -> Option<&str> {
        self.dunno.as_deref()
    }

    /// `reset_unknown`.
    pub fn reset_unknown(&mut self) {
        self.dunno = None;
    }

    /// `opt_int_arg`: the value as an int (its range already checked), -1 if it isn't one.
    pub fn int_arg(&self) -> i32 {
        int(self.arg()).unwrap_or(-1)
    }

    /// `opt_rest`: the arguments after the options.
    pub fn rest(&self) -> &[String] {
        self.argv.get(self.index..).unwrap_or_default()
    }

    /// `opt_num_rest`.
    pub fn num_rest(&self) -> usize {
        self.rest().len()
    }

    /// `opt_check_rest_arg`: with `expected`, exactly one more argument (named `expected` in
    /// the message); without, none.
    pub fn check_rest_arg(&self, expected: Option<&str>) -> bool {
        let prog = prog();
        let first = self.rest().first().filter(|a| !a.is_empty());
        let Some(opt) = first else {
            if let Some(e) = expected {
                eprintf!("{prog}: Missing argument: {e}\n");
                return false;
            }
            return true;
        };
        if let Some(e) = expected {
            match self.argv.get(self.index + 1).filter(|a| !a.is_empty()) {
                None => return true,
                Some(extra) => {
                    eprintf!("{prog}: Extra argument after {e}: \"{extra}\"\n");
                    return false;
                }
            }
        }
        match &self.dunno {
            None => eprintf!("{prog}: Extra option: \"{opt}\"\n"),
            Some(d) => eprintf!("{prog}: Extra (unknown) options: \"{d}\" \"{opt}\"\n"),
        };
        false
    }
}

/// `opt_isdir`: `None` when the name can't be stat'ed.
pub fn isdir(name: &str) -> Option<bool> {
    std::fs::metadata(name).ok().map(|m| m.is_dir())
}

/// What `strtol`/`strtoul` with base 0 make of `s`: the magnitude, whether it was negated, and
/// whether every byte was used. `None` when no digits were read (`endp == value`).
fn strto(s: &str) -> Option<(u128, bool, bool, bool)> {
    let b = s.as_bytes();
    let mut i = 0;
    while b
        .get(i)
        .is_some_and(|c| matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r'))
    {
        i += 1;
    }
    let mut neg = false;
    if let Some(&c @ (b'+' | b'-')) = b.get(i) {
        neg = c == b'-';
        i += 1;
    }
    let mut base = 10;
    if b.get(i) == Some(&b'0')
        && matches!(b.get(i + 1), Some(b'x' | b'X'))
        && b.get(i + 2).is_some_and(u8::is_ascii_hexdigit)
    {
        base = 16;
        i += 2;
    } else if b.get(i) == Some(&b'0') {
        base = 8;
    }
    let start = i;
    let mut value: u128 = 0;
    let mut overflow = false;
    while let Some(d) = b.get(i).and_then(|c| char::from(*c).to_digit(base)) {
        value = match value
            .checked_mul(u128::from(base))
            .and_then(|v| v.checked_add(u128::from(d)))
        {
            Some(v) if v <= u128::from(u64::MAX) + 1 => v,
            _ => {
                overflow = true;
                u128::from(u64::MAX) + 1
            }
        };
        i += 1;
    }
    if i == start {
        return None;
    }
    Some((value, neg, overflow, i == b.len()))
}

/// `opt_number_error`.
fn number_error(v: &str) {
    let prog = prog();
    let kind = if v.starts_with("0x") || v.starts_with("0X") {
        "a hexadecimal"
    } else if v.starts_with('0') {
        "an octal"
    } else {
        "a"
    };
    eprintf!("{prog}: Can't parse \"{v}\" as {kind} number\n");
}

/// `strtol` into a signed 64-bit `long`: `None` on no digits, trailing bytes, or overflow.
fn signed(v: &str) -> Option<i64> {
    let (mag, neg, overflow, all) = strto(v)?;
    if !all || overflow {
        return None;
    }
    if neg {
        let m = i128::try_from(mag).ok()?;
        i64::try_from(-m).ok()
    } else {
        i64::try_from(mag).ok()
    }
}

/// `strtoul` into an unsigned 64-bit `long`: a leading `-` negates, wrapping, as C does.
fn unsigned(v: &str) -> Option<u64> {
    let (mag, neg, overflow, all) = strto(v)?;
    if !all || overflow {
        return None;
    }
    let m = u64::try_from(mag).ok()?;
    Some(if neg { m.wrapping_neg() } else { m })
}

/// `strtol(s, &end, 0)` where only a whole, in-range number counts, without a message.
pub fn strtol(s: &str) -> Option<i64> {
    signed(s)
}

/// `opt_long`.
pub fn long(v: &str) -> Option<i64> {
    let r = signed(v);
    if r.is_none() {
        number_error(v);
    }
    r
}

/// `opt_int`.
pub fn int(v: &str) -> Option<i32> {
    let l = long(v)?;
    match i32::try_from(l) {
        Ok(i) => Some(i),
        Err(_) => {
            let prog = prog();
            eprintf!("{prog}: Value \"{v}\" outside integer range\n");
            None
        }
    }
}

/// `opt_ulong`.
pub fn ulong(v: &str) -> Option<u64> {
    let r = unsigned(v);
    if r.is_none() {
        number_error(v);
    }
    r
}

/// `opt_intmax` (`intmax_t` is 64 bits on every target).
pub fn intmax(v: &str) -> Option<i64> {
    long(v)
}

/// `opt_uintmax`.
pub fn uintmax(v: &str) -> Option<u64> {
    ulong(v)
}

/// `formats[]` of `opt.c`.
const FORMATS: &[(&str, u64)] = &[
    ("pem", fmt_flags::PEM),
    ("der", fmt_flags::DER),
    ("b64", fmt_flags::B64),
    ("pkcs12", fmt_flags::PKCS12),
    ("smime", fmt_flags::SMIME),
    ("engine", fmt_flags::ENGINE),
    ("msblob", fmt_flags::MSBLOB),
    ("nss", fmt_flags::NSS),
    ("text", fmt_flags::TEXT),
    ("http", fmt_flags::HTTP),
    ("pvk", fmt_flags::PVK),
];

/// `opt_format_error`.
fn format_error(s: &str, flags: u64) -> Option<i32> {
    let prog = prog();
    let mut text = format!("{prog}: Bad format \"{s}\"; must be one of: ");
    for (name, bit) in FORMATS {
        if flags & bit != 0 {
            text.push(' ');
            text.push_str(name);
        }
    }
    text.push('\n');
    let _ = io::err().write_all(text.as_bytes());
    None
}

/// `opt_format`: the format `s` names, if `flags` allows it; messages as upstream's.
pub fn parse_format(s: &str, flags: u64) -> Option<i32> {
    use fmt_flags as f;
    let prog = prog();
    let first = s.bytes().next().unwrap_or(0);
    let short = s.len() == 1;
    let need = |bit: u64, value: i32| -> Option<i32> {
        if flags & bit == 0 {
            format_error(s, flags)
        } else {
            Some(value)
        }
    };
    match first {
        b'B' | b'b' => {
            if short || ["B64", "b64", "BASE64", "base64"].contains(&s) {
                need(f::B64, format::BASE64)
            } else {
                None
            }
        }
        b'D' | b'd' => need(f::DER, format::ASN1),
        b'T' | b't' => need(f::TEXT, format::TEXT),
        b'N' | b'n' => {
            if flags & f::NSS == 0 || (s != "NSS" && s != "nss") {
                return format_error(s, flags);
            }
            Some(format::NSS)
        }
        b'S' | b's' => need(f::SMIME, format::SMIME),
        b'M' | b'm' => need(f::MSBLOB, format::MSBLOB),
        b'E' | b'e' => need(f::ENGINE, format::ENGINE),
        b'H' | b'h' => need(f::HTTP, format::HTTP),
        b'1' => need(f::PKCS12, format::PKCS12),
        b'P' | b'p' => {
            if short || s == "PEM" || s == "pem" {
                need(f::PEM, format::PEM)
            } else if s == "PVK" || s == "pvk" {
                need(f::PVK, format::PVK)
            } else if ["P12", "p12", "PKCS12", "pkcs12"].contains(&s) {
                need(f::PKCS12, format::PKCS12)
            } else {
                eprintf!("{prog}: Bad format \"{s}\"\n");
                None
            }
        }
        _ => {
            eprintf!("{prog}: Bad format \"{s}\"\n");
            None
        }
    }
}

/// `format2str`.
fn format2str(format: i32) -> &'static str {
    match format {
        format::PEM => "PEM",
        format::ASN1 => "DER",
        format::TEXT => "TEXT",
        format::NSS => "NSS",
        format::SMIME => "SMIME",
        format::MSBLOB => "MSBLOB",
        format::ENGINE => "ENGINE",
        format::HTTP => "HTTP",
        format::PKCS12 => "P12",
        format::PVK => "PVK",
        _ => "(undefined)",
    }
}

/// `print_format_error`.
pub fn print_format_error(format: i32, flags: u64) {
    let _ = format_error(format2str(format), flags);
}

/// `opt_pair`: the value paired with `name`, or the list of names.
pub fn pair<T: Copy>(name: &str, pairs: &[(&str, T)]) -> Option<T> {
    if let Some((_, v)) = pairs.iter().find(|(n, _)| *n == name) {
        return Some(*v);
    }
    let prog = prog();
    eprintf!("{prog}: Value must be one of:\n");
    for (n, _) in pairs {
        eprintf!("\t{n}\n");
    }
    None
}

/// `opt_string`.
pub fn string(name: &str, options: &[&str]) -> bool {
    if options.contains(&name) {
        return true;
    }
    let prog = prog();
    eprintf!("{prog}: Value must be one of:\n");
    for n in options {
        eprintf!("\t{n}\n");
    }
    false
}

/// `valtype2param`.
fn valtype2param(valtype: u8) -> &'static str {
    match valtype {
        0 | b'-' => "",
        b':' => "uri",
        b's' => "val",
        b'/' => "dir",
        b'<' => "infile",
        b'>' => "outfile",
        b'p' => "+int",
        b'n' => "int",
        b'l' => "long",
        b'u' => "ulong",
        b'E' => "PEM|DER|ENGINE",
        b'F' => "PEM|DER",
        b'f' => "format",
        b'M' => "intmax",
        b'N' => "nonneg",
        b'U' => "uintmax",
        _ => "parm",
    }
}

/// `opt_print`.
fn print_one<O>(o: &OptDef<O>, doingparams: bool, width: usize) {
    let width = width.min(80);
    let help = o.help.unwrap_or("(No additional info)");
    let prog = prog();
    match o.marker {
        Some(Marker::Help) => {
            printf_stderr(help, &[&prog]);
            return;
        }
        Some(Marker::Section) => {
            printf_stderr("\n", &[]);
            printf_stderr(help, &[&prog]);
            return;
        }
        Some(Marker::Param) => {
            printf_stderr("\nParameters:\n", &[]);
            return;
        }
        Some(Marker::More) => {
            eprintf!("{}  {help}\n", " ".repeat(width));
            return;
        }
        None => {}
    }
    let mut linelen = 0;
    linelen += eprintf!(" {}", if doingparams { "" } else { "-" });
    linelen += eprintf!("{}", if o.name.is_empty() { "*" } else { o.name });
    if o.valtype != b'-' {
        linelen += eprintf!(" {}", valtype2param(o.valtype));
    }
    if linelen >= MAX_OPT_HELP_WIDTH || linelen > width {
        eprintf!("\n");
        linelen = 0;
    }
    eprintf!("{}  {help}\n", " ".repeat(width - linelen));
}

/// `opt_help`: the usage line and each entry, to standard error.
pub fn help<O>(list: &[OptDef<O>]) {
    let standard_prolog = list.first().is_none_or(|o| o.marker != Some(Marker::Help));
    let mut width = 5;
    for o in list {
        if o.marker == Some(Marker::More) {
            continue;
        }
        let mut i = 2 + o.name.len();
        if o.valtype != b'-' {
            i += 1 + valtype2param(o.valtype).len();
        }
        width = width.max(i);
    }
    width = width.min(MAX_OPT_HELP_WIDTH);
    if standard_prolog {
        let prog = prog();
        eprintf!("Usage: {prog} [options]\n");
        if list
            .first()
            .is_none_or(|o| o.marker != Some(Marker::Section))
        {
            eprintf!("Valid options are:\n");
        }
    }
    let mut sawparams = false;
    for o in list {
        if o.marker == Some(Marker::Param) {
            sawparams = true;
        }
        print_one(o, sawparams, width);
    }
}

/// For a command not ported yet (which fails closed): parses `argv` with its table, silently,
/// and prints the help if `-help` comes before the options end or go wrong. Returns whether it
/// did.
pub fn help_only<O: Choice + PartialEq>(argv: &[String], list: &'static [OptDef<O>]) -> bool {
    let Some(help_ret) = list.iter().find(|o| o.name == "help").and_then(|o| o.ret) else {
        return false;
    };
    let (asked, _) = io::capture_err(|| {
        let mut p = Parser::new(argv, list);
        loop {
            let o = p.next();
            if o == help_ret {
                return true;
            }
            if o == O::EOF || o == O::ERR {
                return false;
            }
        }
    });
    if asked {
        help(list);
    }
    asked
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generated::options::{self, R, V, version};

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| (*s).to_owned()).collect()
    }

    /// Runs `f`, returning what it wrote to standard error.
    fn stderr_of<T>(f: impl FnOnce() -> T) -> (T, String) {
        let (t, bytes) = io::capture_err(f);
        (t, String::from_utf8(bytes).unwrap())
    }

    #[test]
    fn program_names() {
        assert_eq!(path_end("/usr/bin/openssl"), "openssl");
        assert_eq!(path_end("/openssl"), "/openssl");
        assert_eq!(path_end("openssl"), "openssl");
        assert_eq!(progname("../x/openssl"), "openssl");
        assert_eq!(appname("x509"), "openssl x509");
        progname(&"a".repeat(50));
        assert_eq!(prog().len(), 39);
    }

    #[test]
    fn flags_values_and_the_end() {
        use version::Opt;
        let a = argv(&["version", "-a", "--v", "-h", "--", "-b"]);
        let mut p = Parser::new(&a, version::OPTIONS);
        assert_eq!(p.next(), Opt::A);
        assert_eq!(p.flag(), "-a");
        assert_eq!(p.next(), Opt::V);
        assert_eq!(p.flag(), "-v");
        assert_eq!(p.next(), Opt::HELP);
        assert_eq!(p.next(), Opt::EOF);
        assert_eq!(p.rest(), ["-b"]);
        assert_eq!(p.prog(), "version");

        let a = argv(&["version", "-x", "rest"]);
        let mut p = Parser::new(&a, version::OPTIONS);
        let (o, e) = stderr_of(|| p.next());
        assert_eq!(o, Opt::ERR);
        assert_eq!(e, "version: Unknown option: -x\n");

        let a = argv(&["version", "-a=1"]);
        let mut p = Parser::new(&a, version::OPTIONS);
        let (o, e) = stderr_of(|| p.next());
        assert_eq!(o, Opt::ERR);
        assert_eq!(e, "version: Option -a does not take a value\n");

        let a = argv(&["version", "arg", "-a"]);
        let mut p = Parser::new(&a, version::OPTIONS);
        assert_eq!(p.next(), Opt::EOF);
        assert_eq!(p.num_rest(), 2);
        let (ok, e) = stderr_of(|| p.check_rest_arg(None));
        assert!(!ok);
        assert_eq!(e, "version: Extra option: \"arg\"\n");
        let (ok, e) = stderr_of(|| p.check_rest_arg(Some("file")));
        assert!(!ok);
        assert_eq!(e, "version: Extra argument after file: \"-a\"\n");
    }

    #[test]
    fn markers_match_with_three_dashes_as_in_c() {
        use version::Opt;
        // `---S` leaves `-S`, the section marker's name, whose retval 1 is OPT_HELP.
        let a = argv(&["version", "---S"]);
        let mut p = Parser::new(&a, version::OPTIONS);
        assert_eq!(p.next(), Opt::HELP);
    }

    #[test]
    fn values_are_checked() {
        use options::rand::Opt;
        let a = argv(&["rand", "-out"]);
        let mut p = Parser::new(&a, options::rand::OPTIONS);
        let (o, e) = stderr_of(|| p.next());
        assert_eq!(o, Opt::ERR);
        assert_eq!(e, "rand: Option -out needs a value\n");

        let a = argv(&["rand", "-out=f", "-rand", "a:b", "-writerand", "w"]);
        let mut p = Parser::new(&a, options::rand::OPTIONS);
        assert_eq!(p.next(), Opt::OUT);
        assert_eq!(p.arg(), "f");
        assert_eq!(p.next(), Opt::OPT_R(R::RAND));
        assert_eq!(p.arg(), "a:b");
        assert_eq!(p.next(), Opt::OPT_R(R::WRITERAND));

        use options::verify::Opt as VOpt;
        let a = argv(&["verify", "-verify_depth", "0x1g"]);
        let mut p = Parser::new(&a, options::verify::OPTIONS);
        let (o, e) = stderr_of(|| p.next());
        assert_eq!(o, VOpt::ERR);
        assert_eq!(e, "verify: Can't parse \"0x1g\" as a hexadecimal number\n");
        let a = argv(&["verify", "-verify_depth", " 017", "-attime", "-0x10"]);
        let mut p = Parser::new(&a, options::verify::OPTIONS);
        assert_eq!(p.next(), VOpt::OPT_V(V::VERIFY_DEPTH));
        assert_eq!(p.int_arg(), 15);
        assert_eq!(p.next(), VOpt::OPT_V(V::ATTIME));
        assert_eq!(intmax(p.arg()), Some(-16));

        use options::genrsa::Opt as GOpt;
        let a = argv(&["genrsa", "-primes", "99999999999"]);
        let mut p = Parser::new(&a, options::genrsa::OPTIONS);
        let (o, e) = stderr_of(|| p.next());
        assert_eq!(o, GOpt::ERR);
        assert_eq!(e, "genrsa: Value \"99999999999\" outside integer range\n");
        let a = argv(&["genrsa", "-primes", "0"]);
        let mut p = Parser::new(&a, options::genrsa::OPTIONS);
        let (o, e) = stderr_of(|| p.next());
        assert_eq!(o, GOpt::ERR);
        assert_eq!(e, "genrsa: Non-positive number \"0\" for option -primes\n");
    }

    #[test]
    fn numbers_parse_as_strtol() {
        let ((), _) = stderr_of(|| {
            assert_eq!(long("10"), Some(10));
            assert_eq!(long("-010"), Some(-8));
            assert_eq!(long("0x7fffffffffffffff"), Some(i64::MAX));
            assert_eq!(long("-9223372036854775808"), Some(i64::MIN));
            assert_eq!(long("9223372036854775808"), None);
            assert_eq!(long(""), None);
            assert_eq!(long("0x"), None);
            assert_eq!(long("1 "), None);
            assert_eq!(long("08"), None);
            assert_eq!(ulong("-1"), Some(u64::MAX));
            assert_eq!(ulong("18446744073709551616"), None);
        });
        let (_, e) = stderr_of(|| long("08"));
        assert_eq!(
            e,
            "openssl: Can't parse \"08\" as an octal number\n".replace("openssl", &prog())
        );
    }

    #[test]
    fn formats() {
        use fmt_flags as f;
        let (r, e) = stderr_of(|| parse_format("DER", f::PEMDER));
        assert_eq!((r, e.as_str()), (Some(format::ASN1), ""));
        assert_eq!(
            stderr_of(|| parse_format("p", f::PEMDER)).0,
            Some(format::PEM)
        );
        assert_eq!(
            stderr_of(|| parse_format("pkcs12", f::ANY)).0,
            Some(format::PKCS12)
        );
        assert_eq!(
            stderr_of(|| parse_format("bad", f::ANY)),
            (None, String::new())
        );
        let p = prog();
        let (r, e) = stderr_of(|| parse_format("smime", f::PEMDER));
        assert_eq!(r, None);
        assert_eq!(
            e,
            format!("{p}: Bad format \"smime\"; must be one of:  pem der\n")
        );
        let (_, e) = stderr_of(|| parse_format("xyz", f::PEMDER));
        assert_eq!(e, format!("{p}: Bad format \"xyz\"\n"));
        let (_, e) = stderr_of(|| parse_format("pfx", f::PEMDER));
        assert_eq!(e, format!("{p}: Bad format \"pfx\"\n"));
    }

    #[test]
    fn invalid_format_option() {
        use options::crl::Opt;
        let a = argv(&["crl", "-inform", "SMIME"]);
        let mut p = Parser::new(&a, options::crl::OPTIONS);
        let (o, e) = stderr_of(|| p.next());
        assert_eq!(o, Opt::ERR);
        assert_eq!(
            e,
            "crl: Bad format \"SMIME\"; must be one of:  pem der\n\
             crl: Invalid format \"SMIME\" for option -inform\n"
        );
    }

    #[test]
    fn unknown_option_slot() {
        use options::dgst::Opt;
        let a = argv(&["dgst", "-sha256", "-md5"]);
        let mut p = Parser::with_unknown(&a, options::dgst::OPTIONS, Some("digest"));
        assert_eq!(p.next(), Opt::DIGEST);
        assert_eq!(p.unknown(), Some("sha256"));
        let (o, e) = stderr_of(|| p.next());
        assert_eq!(o, Opt::ERR);
        assert_eq!(
            e,
            "dgst: Multiple digest or unknown options: -sha256 and -md5\n"
        );
    }

    #[test]
    fn pairs_and_strings() {
        let p = prog();
        assert_eq!(stderr_of(|| pair("b", &[("a", 1), ("b", 2)])).0, Some(2));
        let (r, e) = stderr_of(|| pair("c", &[("a", 1), ("b", 2)]));
        assert_eq!(r, None);
        assert_eq!(e, format!("{p}: Value must be one of:\n\ta\n\tb\n"));
        assert!(!stderr_of(|| string("c", &["a"])).0);
    }

    #[test]
    fn help_layout() {
        progname("version");
        let ((), e) = stderr_of(|| help(version::OPTIONS));
        assert_eq!(
            e,
            "Usage: version [options]\n\nGeneral options:\n \
             -help  Display this summary\n\nOutput options:\n \
             -a     Show all data\n -b     Show build date\n -d     Show configuration directory\n \
             -e     Show engines directory\n -m     Show modules directory\n \
             -f     Show compiler flags used\n -o     Show some internal datatype options\n \
             -p     Show target build platform\n -r     Show random seeding options\n \
             -v     Show library version\n -c     Show CPU settings info\n"
        );
    }

    #[test]
    fn c_formats() {
        assert_eq!(
            c_format("Usage: %s [options] %%\n", &["x"]),
            "Usage: x [options] %\n"
        );
        assert_eq!(c_format("%d", &[]), "%d");
    }
}
