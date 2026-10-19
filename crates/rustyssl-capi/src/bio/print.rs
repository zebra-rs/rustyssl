//! OpenSSL's own printf (`BIO_printf(3)`): `BIO_printf`, `BIO_vprintf`, `BIO_snprintf`, and
//! `BIO_vsnprintf`, which `ERR_set_error` and the dump and debug functions share.
//!
//! OpenSSL doesn't use the C library's printf. Its formatter (`_dopr` in `bio_print.c`)
//! differs from C's in many details, and applications diff its output, so this is a port of its
//! behavior, quirks included. This follows OpenSSL 3.6's formatter, which differs from 3.5's
//! (docs/IMPLEMENTATION_PLAN.md, step 9.5):
//! - A negative width from `*` sets the `-` flag; a negative precision from `*` counts as none.
//!   A `.` without digits is a precision of 0. Widths and precisions of `INT_MAX / 10` or more
//!   fail.
//! - Integers follow C: a precision drops the `0` flag, 0 with a precision of 0 prints nothing,
//!   `%#o` always gets its `0` (counted against the precision), `%#x` gets `0x` (`0X` for `%#X`)
//!   only when the value isn't 0, and `%p` prints like `%#x`. `hh` and `t` are length modifiers,
//!   and `%n` honors each length modifier.
//! - `%f`, `%e`, and `%g` print at most 9 decimals, round half up on the scaled fraction, print
//!   `?` as the sign of an infinity or NaN (whose digits are 0), fail for values of 2^64 or more,
//!   leave 10.0 as the mantissa of `%e` (`10.000000e+00`), drop the leading digit of a 20-digit
//!   integer part, and never pad on the right (the `-` flag drops the padding). `L` reads a
//!   `double`, as OpenSSL is built without `long double`.
//! - `%w` skips the character after it; unknown conversions print nothing.
//! - `BIO_snprintf` returns -1 when the output doesn't fit (the buffer holds what fit, and a NUL
//!   if it has room); it reads the whole format, and all the arguments, regardless.
//! - `BIO_printf` grows its buffer 1 KiB at a time and fails once that would pass `INT_MAX`.
//!
//! The arithmetic wraps where OpenSSL's C does, and `f64` is the C `double` OpenSSL computes in,
//! so the digits match bit for bit. The format is never read past its NUL (OpenSSL's `%w` at
//! the end of a format reads past it).

use core::ffi::{CStr, VaList, c_char, c_int, c_void};
use core::ptr;

use rustyssl_abi::{BIO, ERR_LIB_BIO};

use crate::ffi::{ffi_export, guard};

/// OpenSSL's `BUFFER_INC`: how much `BIO_printf`'s buffer grows by.
const BUFFER_INC: usize = 1024;

/// The size of `BIO_printf`'s first buffer, on its stack in OpenSSL.
const STACK_BUFFER: usize = 2048;

/// The largest output, with its NUL, that `BIO_printf` can hold: its buffer grows from
/// [`STACK_BUFFER`] by [`BUFFER_INC`] while that keeps it within `INT_MAX`.
const GROWING_LIMIT: usize = {
    let max = c_int::MAX.unsigned_abs() as usize;
    STACK_BUFFER + BUFFER_INC * ((max - BUFFER_INC - STACK_BUFFER) / BUFFER_INC + 1)
};

// The format flags (OpenSSL's `DP_F_*`).
const MINUS: u8 = 1 << 0;
const PLUS: u8 = 1 << 1;
const SPACE: u8 = 1 << 2;
const NUM: u8 = 1 << 3;
const ZERO: u8 = 1 << 4;
const UP: u8 = 1 << 5;
const UNSIGNED: u8 = 1 << 6;

/// A length modifier (OpenSSL's `DP_C_*`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Modifier {
    Int,
    Char,
    Short,
    Long,
    LongDouble,
    LongLong,
    Size,
    Ptrdiff,
}

/// Where the formatter is in a conversion (OpenSSL's `DP_S_*`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Default,
    Flags,
    Min,
    Dot,
    Max,
    Mod,
    Conv,
}

/// A floating-point conversion.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Style {
    F,
    E,
    G,
}

/// The formatter failed: the output is discarded and the caller returns -1.
struct Failed;

/// The arguments a format consumes: a C `va_list`, or those of a call from Rust.
pub(crate) trait Args {
    /// The next argument as an `int` (also for `unsigned int`, `char`, and `short`, which C
    /// promotes).
    ///
    /// # Safety
    /// An argument of that type is next.
    unsafe fn int(&mut self) -> c_int;
    /// The next argument as a 64-bit integer (`long`, `long long`, `int64_t`, `size_t`, and
    /// their signed and unsigned forms, all 64 bits on the supported targets).
    ///
    /// # Safety
    /// An argument of that type is next.
    unsafe fn long(&mut self) -> u64;
    /// The next argument as a `double`.
    ///
    /// # Safety
    /// An argument of that type is next.
    unsafe fn double(&mut self) -> f64;
    /// The next argument as a pointer.
    ///
    /// # Safety
    /// An argument of that type is next.
    unsafe fn pointer(&mut self) -> *mut c_void;
}

impl Args for VaList<'_> {
    unsafe fn int(&mut self) -> c_int {
        // SAFETY: the caller's guarantee.
        unsafe { self.next_arg::<c_int>() }
    }

    unsafe fn long(&mut self) -> u64 {
        // SAFETY: the caller's guarantee.
        unsafe { self.next_arg::<u64>() }
    }

    unsafe fn double(&mut self) -> f64 {
        // SAFETY: the caller's guarantee.
        unsafe { self.next_arg::<f64>() }
    }

    unsafe fn pointer(&mut self) -> *mut c_void {
        // SAFETY: the caller's guarantee.
        unsafe { self.next_arg::<*mut c_void>() }
    }
}

/// An argument from Rust code formatting with OpenSSL's rules.
#[derive(Clone, Copy)]
pub(crate) enum Arg {
    Int(c_int),
    Long(u64),
    Pointer(*const c_void),
}

/// The arguments of a call from Rust, in order. A conversion that doesn't match its argument
/// gets zero (or null), never undefined behavior.
pub(crate) struct Values<'a>(core::slice::Iter<'a, Arg>);

impl<'a> Values<'a> {
    pub(crate) fn new(args: &'a [Arg]) -> Self {
        Self(args.iter())
    }
}

impl Args for Values<'_> {
    unsafe fn int(&mut self) -> c_int {
        match self.0.next() {
            Some(Arg::Int(value)) => *value,
            _ => 0,
        }
    }

    unsafe fn long(&mut self) -> u64 {
        match self.0.next() {
            Some(Arg::Long(value)) => *value,
            Some(Arg::Int(value)) => u64::from(value.cast_unsigned()),
            _ => 0,
        }
    }

    unsafe fn double(&mut self) -> f64 {
        self.0.next();
        0.0
    }

    unsafe fn pointer(&mut self) -> *mut c_void {
        match self.0.next() {
            Some(Arg::Pointer(value)) => value.cast_mut(),
            _ => ptr::null_mut(),
        }
    }
}

/// Where the formatter writes (OpenSSL's `sbuffer` and `buffer`).
enum Sink {
    /// The caller's buffer of `size` bytes (`BIO_snprintf`); null fails.
    Fixed { buf: *mut u8, size: usize },
    /// A growing buffer (`BIO_printf`).
    Growing(Vec<u8>),
}

/// The output so far (`currlen` is `len`; `pos`, what `%n` reports, also counts what a full
/// fixed buffer dropped).
struct Output {
    sink: Sink,
    len: usize,
    pos: i64,
}

impl Output {
    fn new(sink: Sink) -> Self {
        Self {
            sink,
            len: 0,
            pos: 0,
        }
    }

    /// OpenSSL's `doapr_outch`: appends `c`. A full fixed buffer drops it.
    fn put(&mut self, c: u8) -> Result<(), Failed> {
        self.repeat(c, 1)
    }

    /// Appends `count` copies of `c`, as that many calls of [`put`](Self::put) would (OpenSSL's
    /// padding loops, which `eob_ok` cuts short at the end of a fixed buffer, counting the rest).
    fn repeat(&mut self, c: u8, count: usize) -> Result<(), Failed> {
        if count == 0 {
            return Ok(());
        }
        self.pos = i64::try_from(count)
            .ok()
            .and_then(|n| self.pos.checked_add(n))
            .unwrap_or(i64::MAX);
        match &mut self.sink {
            Sink::Fixed { buf, size } => {
                if buf.is_null() {
                    return Err(Failed);
                }
                let room = size.saturating_sub(self.len).min(count);
                // SAFETY: the caller of BIO_snprintf gave `size` writable bytes; `len` is
                // within them, and so are the `room` bytes after it.
                let at = unsafe { buf.add(self.len) };
                // SAFETY: as above.
                unsafe { at.write_bytes(c, room) };
                self.len += room;
            }
            Sink::Growing(out) => {
                // OpenSSL fails at the first character past the limit, discarding the output;
                // failing before writing any of them leaves the same result.
                let end = self.len.checked_add(count).ok_or(Failed)?;
                if end > GROWING_LIMIT {
                    return Err(Failed);
                }
                out.try_reserve(count).map_err(|_| Failed)?;
                out.resize(end, c);
                self.len = end;
            }
        }
        Ok(())
    }

    /// Appends `bytes`, as [`put`](Self::put) for each would.
    fn extend(&mut self, bytes: &[u8]) -> Result<(), Failed> {
        bytes.iter().try_for_each(|b| self.put(*b))
    }
}

/// The low 32 bits of `value` as a C `int`, as C converts a wider integer to `int`.
fn wrap(value: i128) -> c_int {
    u32::try_from(value & 0xFFFF_FFFF).map_or(0, u32::cast_signed)
}

/// A count from OpenSSL's `int` arithmetic, as a number of characters (none if negative).
fn count(value: c_int) -> usize {
    usize::try_from(value).unwrap_or(0)
}

/// Up to `N` digits, least significant first.
struct Digits<const N: usize> {
    digits: [u8; N],
    len: usize,
}

impl<const N: usize> Digits<N> {
    fn new() -> Self {
        Self {
            digits: [0; N],
            len: 0,
        }
    }

    fn push(&mut self, digit: u8) {
        if let Some(slot) = self.digits.get_mut(self.len) {
            *slot = digit;
            self.len += 1;
        }
    }

    /// The digits, most significant first.
    fn most_significant_first(&self) -> impl Iterator<Item = u8> + '_ {
        self.digits.iter().take(self.len).rev().copied()
    }

    /// The count as a C `int`.
    fn place(&self) -> c_int {
        c_int::try_from(self.len).unwrap_or(c_int::MAX)
    }
}

/// The digit for `value` (below 16).
fn digit(value: u64, upper: bool) -> u8 {
    let digits = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    usize::try_from(value)
        .ok()
        .and_then(|i| digits.get(i))
        .copied()
        .unwrap_or(b'0')
}

/// A C string being read, one character at a time, never past its NUL.
struct Format(*const u8);

impl Format {
    /// The character at the cursor.
    fn peek(&self) -> u8 {
        // SAFETY: the cursor is inside the format, at or before its NUL.
        unsafe { self.0.read() }
    }

    /// OpenSSL's `*format++`: the character at the cursor, which moves on unless it's the NUL.
    fn next(&mut self) -> u8 {
        let c = self.peek();
        self.skip();
        c
    }

    /// Moves past the character at the cursor, unless it's the NUL.
    fn skip(&mut self) {
        if self.peek() != 0 {
            // SAFETY: the character isn't the NUL, so the next one is in the format too.
            self.0 = unsafe { self.0.add(1) };
        }
    }
}

/// OpenSSL's `_dopr`: formats into `out`, then appends a NUL. Returns the length without the
/// NUL (`currlen - 1`, wrapping as in C) and whether a fixed buffer was too small. A failure
/// still cuts the output short and ends it with a NUL, as OpenSSL does.
///
/// # Safety
/// `format` is a NUL-terminated string; `args` are what it says, as for C's `printf`.
unsafe fn dopr(
    format: *const c_char,
    args: &mut impl Args,
    out: &mut Output,
) -> Result<(usize, bool), Failed> {
    // SAFETY: the caller's guarantee.
    let formatted = unsafe { conversions(format, args, out) };
    let mut truncated = false;
    if let Sink::Fixed { size, .. } = out.sink {
        truncated = out.len > size.wrapping_sub(1);
        if truncated {
            out.len = size - 1;
        }
    }
    let ended = out.put(0);
    formatted?;
    ended?;
    Ok((out.len.wrapping_sub(1), truncated))
}

/// `_dopr`'s loop over the format.
///
/// # Safety
/// As for [`dopr`].
unsafe fn conversions(
    format: *const c_char,
    args: &mut impl Args,
    out: &mut Output,
) -> Result<(), Failed> {
    /// Widths and precisions stop growing here; another digit fails.
    const CAP: c_int = c_int::MAX / 10;
    let mut format = Format(format.cast());
    let mut state = State::Default;
    let mut flags = 0u8;
    let mut size = Modifier::Int;
    let mut min: c_int = 0;
    let mut max: c_int = -1;
    let mut ch = format.next();
    while ch != 0 {
        match state {
            State::Default => {
                if ch == b'%' {
                    state = State::Flags;
                } else {
                    out.put(ch)?;
                }
                ch = format.next();
            }
            State::Flags => {
                let flag = match ch {
                    b'-' => MINUS,
                    b'+' => PLUS,
                    b' ' => SPACE,
                    b'#' => NUM,
                    b'0' => ZERO,
                    _ => 0,
                };
                if flag == 0 {
                    state = State::Min;
                } else {
                    flags |= flag;
                    ch = format.next();
                }
            }
            State::Min => {
                if ch.is_ascii_digit() {
                    if min >= CAP {
                        return Err(Failed);
                    }
                    min = 10 * min + c_int::from(ch - b'0');
                    ch = format.next();
                } else {
                    if ch == b'*' {
                        // SAFETY: the caller's guarantee.
                        min = unsafe { args.int() };
                        if min < 0 {
                            flags |= MINUS;
                            min = min.wrapping_neg();
                        }
                        ch = format.next();
                    }
                    state = State::Dot;
                }
            }
            State::Dot => {
                if ch == b'.' {
                    state = State::Max;
                    ch = format.next();
                } else {
                    state = State::Mod;
                }
            }
            State::Max => {
                if ch.is_ascii_digit() {
                    max = max.max(0);
                    if max >= CAP {
                        return Err(Failed);
                    }
                    max = 10 * max + c_int::from(ch - b'0');
                    ch = format.next();
                } else {
                    if ch == b'*' {
                        // SAFETY: the caller's guarantee.
                        max = unsafe { args.int() };
                        ch = format.next();
                    } else {
                        max = max.max(0);
                    }
                    state = State::Mod;
                }
            }
            State::Mod => {
                let modifier = match ch {
                    b'h' if format.peek() == b'h' => {
                        format.skip();
                        Some(Modifier::Char)
                    }
                    b'h' => Some(Modifier::Short),
                    b'l' if format.peek() == b'l' => {
                        format.skip();
                        Some(Modifier::LongLong)
                    }
                    b'l' => Some(Modifier::Long),
                    b'q' | b'j' => Some(Modifier::LongLong),
                    b'L' => Some(Modifier::LongDouble),
                    b'z' => Some(Modifier::Size),
                    b't' => Some(Modifier::Ptrdiff),
                    _ => None,
                };
                if let Some(modifier) = modifier {
                    size = modifier;
                    ch = format.next();
                }
                state = State::Conv;
            }
            State::Conv => {
                // SAFETY: the caller's guarantee.
                unsafe { convert(ch, &mut format, args, out, flags, size, min, max) }?;
                ch = format.next();
                state = State::Default;
                flags = 0;
                size = Modifier::Int;
                min = 0;
                max = -1;
            }
        }
    }
    Ok(())
}

/// One conversion, `ch`, with its flags, length modifier, width, and precision.
///
/// # Safety
/// As for [`dopr`].
#[expect(
    clippy::too_many_arguments,
    reason = "the state of OpenSSL's formatter"
)]
unsafe fn convert(
    ch: u8,
    format: &mut Format,
    args: &mut impl Args,
    out: &mut Output,
    mut flags: u8,
    size: Modifier,
    min: c_int,
    mut max: c_int,
) -> Result<(), Failed> {
    match ch {
        b'd' | b'i' => {
            // SAFETY: the caller's guarantee.
            let value = match unsafe { integer(args, size) } {
                Integer::Wide(value) => value,
                Integer::Int(value) => {
                    let value = match size {
                        Modifier::Char => i64::from(value.to_le_bytes()[0].cast_signed()),
                        Modifier::Short => i64::from(wrap_short(value)),
                        _ => i64::from(value),
                    };
                    value.cast_unsigned()
                }
            };
            fmtint(out, value, 10, min, max, flags)
        }
        b'X' | b'x' | b'o' | b'u' => {
            if ch == b'X' {
                flags |= UP;
            }
            flags |= UNSIGNED;
            // SAFETY: the caller's guarantee.
            let value = match unsafe { integer(args, size) } {
                Integer::Wide(value) => value,
                Integer::Int(value) => {
                    let value = value.cast_unsigned();
                    u64::from(match size {
                        Modifier::Char => value & 0xFF,
                        Modifier::Short => value & 0xFFFF,
                        _ => value,
                    })
                }
            };
            let base = match ch {
                b'o' => 8,
                b'u' => 10,
                _ => 16,
            };
            fmtint(out, value, base, min, max, flags)
        }
        b'f' | b'E' | b'e' | b'G' | b'g' => {
            if ch == b'E' || ch == b'G' {
                flags |= UP;
            }
            let style = match ch {
                b'f' => Style::F,
                b'E' | b'e' => Style::E,
                _ => Style::G,
            };
            // SAFETY: as above.
            let value = unsafe { args.double() };
            fmtfp(out, value, min, max, flags, style)
        }
        b'c' => {
            // SAFETY: as above.
            let c = unsafe { args.int() };
            out.put(c.to_le_bytes()[0])
        }
        b's' => {
            // SAFETY: as above.
            let value = unsafe { args.pointer() }.cast::<c_char>();
            if max < 0 {
                max = c_int::MAX;
            }
            // SAFETY: as above: a string, or null.
            unsafe { fmtstr(out, value, flags, min, max) }
        }
        b'p' => {
            // SAFETY: as above.
            let value = unsafe { args.pointer() };
            fmtint(out, value.addr() as u64, 16, min, max, flags | NUM)
        }
        b'n' => {
            // SAFETY: as above.
            let num = unsafe { args.pointer() };
            if !num.is_null() {
                let pos = out.pos;
                // SAFETY: as above: `%n` takes a pointer to the integer type its length
                // modifier names, which gets the count converted to that type, as C converts.
                unsafe {
                    match size {
                        Modifier::Char => {
                            num.cast::<i8>().write(pos.to_le_bytes()[0].cast_signed())
                        }
                        Modifier::Short => num.cast::<i16>().write(wrap_short(wrap(pos.into()))),
                        Modifier::Long
                        | Modifier::LongLong
                        | Modifier::Size
                        | Modifier::Ptrdiff => num.cast::<i64>().write(pos),
                        Modifier::Int | Modifier::LongDouble => {
                            num.cast::<c_int>().write(wrap(pos.into()));
                        }
                    }
                }
            }
            Ok(())
        }
        b'%' => out.put(b'%'),
        b'w' => {
            format.skip();
            Ok(())
        }
        _ => Ok(()),
    }
}

/// An integer argument as read: an `int` (also for the types C promotes to one), or 64 bits.
enum Integer {
    Int(c_int),
    Wide(u64),
}

/// Reads an integer argument with length modifier `size`.
///
/// # Safety
/// An argument of that type is next.
unsafe fn integer(args: &mut impl Args, size: Modifier) -> Integer {
    if matches!(
        size,
        Modifier::Long | Modifier::LongLong | Modifier::Size | Modifier::Ptrdiff
    ) {
        // SAFETY: the caller's guarantee.
        Integer::Wide(unsafe { args.long() })
    } else {
        // SAFETY: the caller's guarantee.
        Integer::Int(unsafe { args.int() })
    }
}

/// `(short)value`, as C converts an `int`.
fn wrap_short(value: c_int) -> i16 {
    i16::from_le_bytes([value.to_le_bytes()[0], value.to_le_bytes()[1]])
}

/// OpenSSL's `fmtstr`: `value` (`<NULL>` for null) in at most `max` characters, padded to `min`.
///
/// # Safety
/// `value` is null or a string that has a NUL or at least `max` readable bytes.
unsafe fn fmtstr(
    out: &mut Output,
    value: *const c_char,
    flags: u8,
    min: c_int,
    mut max: c_int,
) -> Result<(), Failed> {
    let value = if value.is_null() {
        c"<NULL>".as_ptr()
    } else {
        value
    };
    let limit = usize::try_from(max).unwrap_or(usize::MAX);
    // SAFETY: the caller's guarantee.
    let len = unsafe { libc::strnlen(value, limit) };
    let mut strln = c_int::try_from(len).ok();
    let mut padlen: c_int = 0;
    if min >= 0
        && let Some(strln) = strln.filter(|n| *n < c_int::MAX)
    {
        padlen = (min - strln).max(0);
    }
    if max >= 0 {
        max = if max < c_int::MAX - padlen {
            max + padlen
        } else {
            c_int::MAX
        };
    }
    let mut cnt: c_int = 0;
    if flags & MINUS == 0 && padlen > 0 {
        if max >= 0 {
            padlen = padlen.min(max);
            cnt = padlen;
        }
        out.repeat(b' ', count(padlen))?;
    }
    let mut take = len;
    if max >= 0 {
        if strln.is_none_or(|n| n > max - cnt) {
            strln = Some(max - cnt);
            take = count(max - cnt);
        }
        cnt += strln.unwrap_or(0);
    }
    // SAFETY: `take` is at most `len`, and `len` bytes before any NUL are readable (strnlen
    // read them).
    let bytes = unsafe { core::slice::from_raw_parts(value.cast::<u8>(), take) };
    out.extend(bytes)?;
    if flags & MINUS != 0 && padlen > 0 {
        if max >= 0 {
            padlen = padlen.min(max - cnt);
        }
        out.repeat(b' ', count(padlen))?;
    }
    Ok(())
}

/// OpenSSL's `fmtint`: `value` in `base`, signed unless the flags say `UNSIGNED`, with at least
/// `max` digits, padded to `min`.
fn fmtint(
    out: &mut Output,
    value: u64,
    base: u64,
    min: c_int,
    max: c_int,
    mut flags: u8,
) -> Result<(), Failed> {
    let max = if max < 0 {
        1
    } else {
        // A precision drops the `0` flag.
        flags &= !ZERO;
        max
    };
    let mut magnitude = value;
    let mut sign = None;
    if flags & UNSIGNED == 0 {
        if value.cast_signed() < 0 {
            sign = Some(b'-');
            magnitude = 0u64.wrapping_sub(value);
        } else if flags & PLUS != 0 {
            sign = Some(b'+');
        } else if flags & SPACE != 0 {
            sign = Some(b' ');
        }
    }
    let prefix: &[u8] = match (flags & NUM != 0, base) {
        (true, 8) => b"0",
        (true, 16) if value != 0 && flags & UP != 0 => b"0X",
        (true, 16) if value != 0 => b"0x",
        _ => b"",
    };
    let octal = c_int::from(base == 8 && !prefix.is_empty());
    // OpenSSL's buffer: `DECIMAL_SIZE(int64_t) + 3`, which every value fits. 0 has no digits.
    let mut digits = Digits::<26>::new();
    while magnitude != 0 && digits.len < 26 {
        digits.push(digit(magnitude % base, flags & UP != 0));
        magnitude /= base;
    }
    if digits.len == 26 {
        digits.len -= 1;
    }
    let place = digits.place();
    let mut zpadlen = max.wrapping_sub(place).wrapping_sub(octal).max(0);
    let shown = place
        .wrapping_add(zpadlen)
        .wrapping_add(c_int::from(sign.is_some()))
        .wrapping_add(c_int::try_from(prefix.len()).unwrap_or(0));
    let mut spadlen = min.wrapping_sub(max.max(shown)).max(0);
    if flags & MINUS != 0 {
        spadlen = -spadlen;
    } else if flags & ZERO != 0 {
        zpadlen = zpadlen.wrapping_add(spadlen);
        spadlen = 0;
    }
    out.repeat(b' ', count(spadlen))?;
    if let Some(sign) = sign {
        out.put(sign)?;
    }
    out.extend(prefix)?;
    out.repeat(b'0', count(zpadlen))?;
    digits
        .most_significant_first()
        .try_for_each(|d| out.put(d))?;
    out.repeat(b' ', count(spadlen.wrapping_neg()))
}

/// OpenSSL's `abs_val`: the magnitude, with infinities and NaNs as 0.
fn abs_val(value: f64) -> f64 {
    let result = if value < 0.0 { -value } else { value };
    if (result > 0.0 && result / 2.0 == result) || result.is_nan() {
        0.0
    } else {
        result
    }
}

/// OpenSSL's `pow_10`: 10 to the `exponent` (not negative), by repeated multiplication.
fn pow_10(exponent: c_int) -> f64 {
    let mut result: f64 = 1.0;
    for _ in 0..exponent {
        result *= 10.0;
        if result.is_infinite() {
            break;
        }
    }
    result
}

/// OpenSSL's `roundv`: `value` rounded half up, for values that fit a `long`.
#[expect(clippy::cast_possible_truncation, reason = "C's (long) conversion")]
fn roundv(value: f64) -> i64 {
    let mut intpart = value as i64;
    #[expect(clippy::cast_precision_loss, reason = "C's conversion back to double")]
    let fraction = value - intpart as f64;
    if fraction >= 0.5 {
        intpart = intpart.wrapping_add(1);
    }
    intpart
}

/// OpenSSL's `fmtfp`: `fvalue` in `style`, with `max` decimals (significant digits for `%g`),
/// padded to `min`.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    reason = "C's conversions between double and unsigned long, on values checked to fit"
)]
fn fmtfp(
    out: &mut Output,
    fvalue: f64,
    min: c_int,
    max: c_int,
    flags: u8,
    style: Style,
) -> Result<(), Failed> {
    let mut max = if max < 0 { 6 } else { max };
    let mut sign = if fvalue < 0.0 {
        Some(b'-')
    } else if flags & PLUS != 0 {
        Some(b'+')
    } else if flags & SPACE != 0 {
        Some(b' ')
    } else {
        None
    };
    let mut ufvalue = abs_val(fvalue);
    if ufvalue == 0.0 && fvalue != 0.0 {
        sign = Some(b'?');
    }
    let realstyle = if style != Style::G {
        style
    } else if ufvalue == 0.0 {
        Style::F
    } else if ufvalue < 0.0001
        || (max == 0 && ufvalue >= 10.0)
        || (max > 0 && ufvalue >= pow_10(max))
    {
        Style::E
    } else {
        Style::F
    };
    let mut exp: i64 = 0;
    if style != Style::F {
        let mut tmpvalue = ufvalue;
        if ufvalue != 0.0 {
            while tmpvalue < 1.0 {
                tmpvalue *= 10.0;
                exp -= 1;
            }
            while tmpvalue > 10.0 {
                tmpvalue /= 10.0;
                exp += 1;
            }
        }
        if style == Style::G {
            if max == 0 {
                max = 1;
            }
            if realstyle == Style::F {
                max = wrap(i128::from(max) - i128::from(exp + 1));
                if max < 0 {
                    // OpenSSL ends the output there; the result is discarded anyway.
                    let _ = out.put(0);
                    return Err(Failed);
                }
            } else {
                max -= 1;
            }
        }
        if realstyle == Style::E {
            ufvalue = tmpvalue;
        }
    }
    if ufvalue >= (u64::MAX - 65535) as f64 + 65536.0 {
        let _ = out.put(0);
        return Err(Failed);
    }
    let mut intpart = ufvalue as u64;
    max = max.min(9);
    let max10 = roundv(pow_10(max)) as u64;
    let mut fracpart = roundv(pow_10(max) * (ufvalue - intpart as f64)) as u64;
    if fracpart >= max10 {
        intpart = intpart.wrapping_add(1);
        fracpart -= max10;
    }
    let mut iconvert = Digits::<20>::new();
    loop {
        iconvert.push(digit(intpart % 10, false));
        intpart /= 10;
        if intpart == 0 || iconvert.len >= 20 {
            break;
        }
    }
    if iconvert.len == 20 {
        // OpenSSL's buffer holds 19 digits and the NUL that overwrites the 20th.
        iconvert.len -= 1;
    }
    let mut fconvert = Digits::<20>::new();
    let mut fplace: c_int = 0;
    while fplace < max {
        if style == Style::G && fplace == 0 && fracpart.is_multiple_of(10) {
            // `%g` drops trailing zeros.
            max -= 1;
            fracpart /= 10;
            if fplace < max {
                continue;
            }
            break;
        }
        fconvert.push(digit(fracpart % 10, false));
        fplace += 1;
        fracpart /= 10;
    }
    let mut econvert = Digits::<20>::new();
    if realstyle == Style::E {
        let mut tmpexp = wrap(i128::from(exp)).unsigned_abs();
        loop {
            econvert.push(digit(u64::from(tmpexp % 10), false));
            tmpexp /= 10;
            if tmpexp == 0 || econvert.len >= 20 {
                break;
            }
        }
        if tmpexp > 0 {
            let _ = out.put(0);
            return Err(Failed);
        }
        if econvert.len == 1 {
            econvert.push(b'0');
        }
    }
    let mut padlen = wrap(
        i128::from(min)
            - i128::from(iconvert.place())
            - i128::from(max)
            - i128::from(max > 0)
            - i128::from(sign.is_some()),
    );
    if realstyle == Style::E {
        padlen = padlen.wrapping_sub(2 + econvert.place());
    }
    let zpadlen = (max - fplace).max(0);
    padlen = padlen.max(0);
    if flags & MINUS != 0 {
        padlen = -padlen;
    }
    if flags & ZERO != 0 && padlen > 0 {
        if let Some(s) = sign.take() {
            out.put(s)?;
            padlen -= 1;
        }
        out.repeat(b'0', count(padlen))?;
        padlen = 0;
    }
    // OpenSSL drops the padding of the `-` flag: it clears `padlen` here, before the padding on
    // the right would print.
    out.repeat(b' ', count(padlen))?;
    if let Some(sign) = sign {
        out.put(sign)?;
    }
    iconvert
        .most_significant_first()
        .try_for_each(|d| out.put(d))?;
    if max > 0 || flags & NUM != 0 {
        out.put(b'.')?;
        fconvert
            .most_significant_first()
            .try_for_each(|d| out.put(d))?;
    }
    out.repeat(b'0', count(zpadlen))?;
    if realstyle == Style::E {
        out.put(if flags & UP == 0 { b'e' } else { b'E' })?;
        out.put(if exp < 0 { b'-' } else { b'+' })?;
        econvert
            .most_significant_first()
            .try_for_each(|d| out.put(d))?;
    }
    Ok(())
}

/// `BIO_vsnprintf`: formats into `buf`, which has `n` bytes. Returns the length without the
/// NUL, or -1 if the output didn't fit or formatting failed.
///
/// # Safety
/// `buf` is null or valid for `n` bytes of writes; `format` is null or a NUL-terminated
/// string whose conversions `args` match.
pub(crate) unsafe fn vsnprintf(
    buf: *mut c_char,
    n: usize,
    format: *const c_char,
    args: &mut impl Args,
) -> c_int {
    if format.is_null() {
        return -1;
    }
    let mut out = Output::new(Sink::Fixed {
        buf: buf.cast(),
        size: n,
    });
    // SAFETY: the caller's guarantee.
    match unsafe { dopr(format, args, &mut out) } {
        Ok((len, false)) => c_int::try_from(len).unwrap_or(-1),
        Ok((_, true)) | Err(Failed) => -1,
    }
}

/// [`vsnprintf`] for Rust callers, into a Rust buffer.
pub(crate) fn snprintf(buf: &mut [u8], format: &CStr, args: &[Arg]) -> c_int {
    // SAFETY: the buffer is writable for its length; `Values` hands out matching arguments
    // or zeros, and the pointers among `args` are the callers' strings.
    unsafe {
        vsnprintf(
            buf.as_mut_ptr().cast(),
            buf.len(),
            format.as_ptr(),
            &mut Values::new(args),
        )
    }
}

/// `BIO_vprintf`: formats, then writes the output to `bio` in one `BIO_write`. Returns what
/// that returns, or -1 if formatting failed.
///
/// # Safety
/// `bio` is null or a live BIO; `format` is null or a NUL-terminated string whose conversions
/// `args` match.
pub(crate) unsafe fn vprintf(bio: *mut BIO, format: *const c_char, args: &mut impl Args) -> c_int {
    if format.is_null() {
        return -1;
    }
    let mut out = Output::new(Sink::Growing(Vec::new()));
    // SAFETY: the caller's guarantee.
    let Ok((len, _)) = (unsafe { dopr(format, args, &mut out) }) else {
        return -1;
    };
    let Sink::Growing(bytes) = out.sink else {
        return -1;
    };
    let len = c_int::try_from(len).unwrap_or(c_int::MAX);
    // SAFETY: the caller's guarantee about `bio`; `bytes` holds `len` bytes and the NUL.
    unsafe { super::BIO_write(bio, bytes.as_ptr().cast(), len) }
}

/// [`vprintf`] for Rust callers.
///
/// # Safety
/// `bio` is null or a live BIO; the pointers among `args` are strings, as `format` expects.
pub(crate) unsafe fn printf(bio: *mut BIO, format: &CStr, args: &[Arg]) -> c_int {
    // SAFETY: the caller's guarantee; `Values` hands out matching arguments or zeros.
    unsafe { vprintf(bio, format.as_ptr(), &mut Values::new(args)) }
}

/// Formats `format` and writes it to `bio`, as C's `printf`. Returns the number of bytes
/// written, or -1 (also when the BIO wrote nothing; see `BIO_write`).
///
/// # Safety
/// `bio` is null or a live BIO; `format` is a NUL-terminated string whose conversions the
/// arguments match, as for C's `printf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_printf(bio: *mut BIO, format: *const c_char, args: ...) -> c_int {
    guard(
        ERR_LIB_BIO,
        "BIO_printf",
        || -1,
        move || {
            let mut args = args;
            // SAFETY: the caller's guarantee.
            unsafe { vprintf(bio, format, &mut args) }
        },
    )
}

ffi_export! {
    /// `BIO_printf` with its arguments in a `va_list`.
    ///
    /// # Safety
    /// As for `BIO_printf`.
    pub unsafe extern "C" fn BIO_vprintf(bio: *mut BIO, format: *const c_char, args: VaList<'_>) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        let mut args = args;
        // SAFETY: the caller's guarantee.
        unsafe { vprintf(bio, format, &mut args) }
    }
}

/// Formats into `buf`, which has `n` bytes, always ending it with a NUL if `n` isn't 0.
/// Returns the length without the NUL, or -1 if the output didn't fit (unlike C's
/// `snprintf`) or formatting failed.
///
/// # Safety
/// `buf` is valid for `n` bytes of writes; `format` is a NUL-terminated string whose
/// conversions the arguments match, as for C's `printf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn BIO_snprintf(
    buf: *mut c_char,
    n: usize,
    format: *const c_char,
    args: ...
) -> c_int {
    guard(
        ERR_LIB_BIO,
        "BIO_snprintf",
        || -1,
        move || {
            let mut args = args;
            // SAFETY: the caller's guarantee.
            unsafe { vsnprintf(buf, n, format, &mut args) }
        },
    )
}

ffi_export! {
    /// `BIO_snprintf` with its arguments in a `va_list`.
    ///
    /// # Safety
    /// As for `BIO_snprintf`.
    pub unsafe extern "C" fn BIO_vsnprintf(buf: *mut c_char, n: usize, format: *const c_char, args: VaList<'_>) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        let mut args = args;
        // SAFETY: the caller's guarantee.
        unsafe { vsnprintf(buf, n, format, &mut args) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn format(format: &CStr, args: &[Arg]) -> (c_int, Vec<u8>) {
        let mut buf = [b'#'; 64];
        let ret = snprintf(&mut buf, format, args);
        let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
        (ret, buf[..end].to_vec())
    }

    #[test]
    fn integers_follow_openssl() {
        assert_eq!(
            format(
                c"%5d|%-5d|%05d",
                &[Arg::Int(42), Arg::Int(-7), Arg::Int(-7)]
            )
            .1,
            b"   42|-7   |-0007"
        );
        assert_eq!(
            format(c"%#x %#o %X", &[Arg::Int(255), Arg::Int(8), Arg::Int(255)]).1,
            b"0xff 010 FF"
        );
        assert_eq!(
            format(c"%.3d|%+d|% d", &[Arg::Int(5), Arg::Int(5), Arg::Int(5)]).1,
            b"005|+5| 5"
        );
        // A negative width from `*` is the `-` flag, as in C's printf.
        assert_eq!(format(c"[%*d]", &[Arg::Int(-4), Arg::Int(1)]).1, b"[1   ]");
        assert_eq!(format(c"%hhd", &[Arg::Int(257)]).1, b"1");
        assert_eq!(
            format(c"%#x|%#o|%.0d", &[Arg::Int(0), Arg::Int(0), Arg::Int(0)]).1,
            b"0|0|"
        );
        assert_eq!(format(c"%ld", &[Arg::Long(u64::MAX)]).1, b"-1");
    }

    #[test]
    fn strings_follow_openssl() {
        let s = Arg::Pointer(c"hello".as_ptr().cast());
        assert_eq!(
            format(c"[%8s][%-8s][%.2s]", &[s, s, s]).1,
            b"[   hello][hello   ][he]"
        );
        assert_eq!(format(c"%s", &[Arg::Pointer(ptr::null())]).1, b"<NULL>");
        // The width counts against the precision's limit, as in OpenSSL.
        assert_eq!(format(c"[%6.2s]", &[s]).1, b"[    he]");
    }

    #[test]
    fn doubles_follow_openssl() {
        fn f(format: &CStr, value: f64) -> Vec<u8> {
            unsafe extern "C" fn call(
                buf: *mut c_char,
                n: usize,
                format: *const c_char,
                args: ...
            ) -> c_int {
                let mut args = args;
                // SAFETY: the test's arguments match its formats.
                unsafe { vsnprintf(buf, n, format, &mut args) }
            }
            let mut buf = [0u8; 64];
            // SAFETY: as above.
            let ret = unsafe { call(buf.as_mut_ptr().cast(), buf.len(), format.as_ptr(), value) };
            if ret < 0 {
                return b"(fail)".to_vec();
            }
            buf[..usize::try_from(ret).unwrap()].to_vec()
        }
        assert_eq!(f(c"%f", 1.5), b"1.500000");
        assert_eq!(f(c"%.2f", 2.675), b"2.67");
        assert_eq!(f(c"%e", 10.0), b"10.000000e+00");
        assert_eq!(f(c"%e", 12345.678), b"1.234568e+04");
        assert_eq!(f(c"%g", 0.0001), b"0.0001");
        assert_eq!(f(c"%g", 100000.0), b"100000");
        assert_eq!(f(c"%g", 1e-5), b"1e-05");
        assert_eq!(f(c"%f", f64::INFINITY), b"?0.000000");
        assert_eq!(f(c"%f", 1e20), b"(fail)");
        assert_eq!(f(c"%.12f", 0.5), b"0.500000000");
    }

    #[test]
    fn a_full_buffer_truncates_and_fails() {
        let mut buf = [b'#'; 4];
        assert_eq!(snprintf(&mut buf, c"abcdef", &[]), -1);
        assert_eq!(&buf, b"abc\0");
        let mut empty = [b'#'; 1];
        assert_eq!(snprintf(&mut empty[..0], c"x", &[]), -1);
        assert_eq!(empty, [b'#']);
        assert_eq!(snprintf(&mut buf, c"abc", &[]), 3);
    }

    /// docs/DEVIATIONS.md: OpenSSL dereferences a null format and a null `%n` target, and
    /// reads past the NUL after a final `%w`.
    #[test]
    fn null_formats_and_targets_fail_or_are_skipped() {
        let mut buf = [b'#'; 8];
        // SAFETY: the buffer is valid; a null format is never read.
        let ret = unsafe {
            vsnprintf(
                buf.as_mut_ptr().cast(),
                8,
                ptr::null(),
                &mut Values::new(&[]),
            )
        };
        assert_eq!(ret, -1);
        // SAFETY: a null BIO is ignored; a null format is never read.
        assert_eq!(unsafe { printf(ptr::null_mut(), c"", &[]) }, 0);
        assert_eq!(
            format(c"ab%n", &[Arg::Pointer(ptr::null())]),
            (2, b"ab".to_vec())
        );
        assert_eq!(format(c"a%w", &[]), (1, b"a".to_vec()));
    }

    #[test]
    fn the_growing_limit_is_where_openssl_stops_growing() {
        let max = usize::try_from(c_int::MAX).unwrap();
        let mut size = STACK_BUFFER;
        while size <= max - BUFFER_INC {
            size += BUFFER_INC;
        }
        assert_eq!(size, GROWING_LIMIT);
    }
}
