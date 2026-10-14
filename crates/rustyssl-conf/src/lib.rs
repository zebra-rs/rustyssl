//! The configuration-file language of `openssl.cnf` (config(5)), as OpenSSL's `conf_def.c`
//! reads it: [`Lines`] puts the physical lines a reader gives together into logical ones
//! (OpenSSL's 512-octet reads, continuations, a byte order mark, and the line count), and
//! [`parse_line`] says what each logical line is: a section header, a value (its variable
//! references expanded through a [`Lookup`]), a pragma, or an include, with OpenSSL's
//! character classes ([`classes`]) and its quirks.
//!
//! This is sans-IO: the caller reads files and directories, keeps the sections and values,
//! and answers the lookups. Configuration files can come from anyone who can set
//! `OPENSSL_CONF`, so everything here is bounded: every scan stops at the end of its line,
//! and a value can't grow past [`MAX_VALUE_LENGTH`] through its references.

#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

pub mod classes;
mod line;
mod list;
mod parse;

pub use line::{Lines, Next, READ_SIZE};
pub use list::{NameValue, NameValueError, list_items, name_value_list};
pub use parse::{Error, Line, Lookup, MAX_VALUE_LENGTH, Options, Pragma, parse_line};

/// A method's character classes: OpenSSL's `CONF_type_default` or `CONF_type_win32`, or what
/// an application's method gives.
#[derive(Clone, Copy, Debug)]
pub struct Classes<'a>(pub &'a [u16; 128]);

impl Classes<'_> {
    /// The default method's classes.
    pub const DEFAULT: Classes<'static> = Classes(&classes::DEFAULT);
    /// The WIN32 method's classes.
    pub const WIN32: Classes<'static> = Classes(&classes::WIN32);

    /// Whether `c` has any of the classes `t` (`is_keytype`): never for eight-bit octets.
    pub fn is(&self, c: u8, t: u16) -> bool {
        self.0.get(usize::from(c)).is_some_and(|k| k & t != 0)
    }
}
