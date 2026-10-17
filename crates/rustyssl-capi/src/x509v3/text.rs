//! Printing an extension's text: the writes of OpenSSL's `BIO_printf` and `BIO_puts` calls,
//! formatted in Rust, with their results.

use core::ffi::c_int;

use rustyssl_abi::{ASN1_STRING, BIO};

use crate::bio::BIO_write;

/// The BIO an extension prints to.
#[derive(Clone, Copy)]
pub(crate) struct Out(*mut BIO);

impl Out {
    /// # Safety
    /// `bio` is a live BIO while the value is used.
    pub(crate) const unsafe fn new(bio: *mut BIO) -> Self {
        Self(bio)
    }

    /// The BIO.
    pub(crate) const fn bio(self) -> *mut BIO {
        self.0
    }

    /// Writes the octets: their count (0 for none), or -1 if they aren't all written, as
    /// `BIO_printf` returns.
    pub(crate) fn write(self, octets: &[u8]) -> c_int {
        if octets.is_empty() {
            return 0;
        }
        let Ok(n) = c_int::try_from(octets.len()) else {
            return -1;
        };
        // SAFETY: a live BIO (`new`'s guarantee); the octets.
        let wrote = unsafe { BIO_write(self.0, octets.as_ptr().cast(), n) };
        if wrote == n { n } else { -1 }
    }

    /// Writes the text, as [`Out::write`].
    pub(crate) fn print(self, text: &str) -> c_int {
        self.write(text.as_bytes())
    }

    /// `BIO_printf(out, "%*s<text>", indent, "")`: the indent (its magnitude, as `%*s` pads a
    /// negative width too) and the text, as [`Out::write`].
    pub(crate) fn line(self, indent: c_int, text: &str) -> c_int {
        let pad = usize::try_from(indent.unsigned_abs()).unwrap_or(0);
        self.print(&format!("{:pad$}{text}", ""))
    }

    /// `"%*s%.*s"` of a string, as [`Out::write`].
    ///
    /// # Safety
    /// `s` is a live string.
    pub(crate) unsafe fn line_string(self, indent: c_int, s: *const ASN1_STRING) -> c_int {
        let pad = usize::try_from(indent.unsigned_abs()).unwrap_or(0);
        let mut text = vec![b' '; pad];
        // SAFETY: the caller's guarantee.
        text.extend_from_slice(unsafe { precision_text(s) });
        self.write(&text)
    }
}

/// What `%.*s` prints of a string's data and length: up to the length or the first NUL,
/// `<NULL>` (as far as the length) for no data. A negative length, for which `%.*s` would read
/// to a NUL past the string's data, prints nothing.
///
/// # Safety
/// `s` is a live string.
pub(crate) unsafe fn precision_text<'a>(s: *const ASN1_STRING) -> &'a [u8] {
    // SAFETY: the caller's guarantee.
    let Some(s) = (unsafe { s.as_ref() }) else {
        return &[];
    };
    let Ok(len) = usize::try_from(s.length) else {
        return &[];
    };
    let data: &[u8] = if s.data.is_null() {
        b"<NULL>"
    } else {
        // SAFETY: a string's data holds its length.
        unsafe { core::slice::from_raw_parts(s.data, len) }
    };
    let data = data.get(..len.min(data.len())).unwrap_or_default();
    let end = data.iter().position(|&c| c == 0).unwrap_or(data.len());
    data.get(..end).unwrap_or_default()
}
