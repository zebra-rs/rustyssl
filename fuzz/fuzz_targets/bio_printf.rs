//! Fuzzes OpenSSL's printf through its C ABI: the input is a buffer size and a format. Every
//! argument is the same pointer, to a NUL-terminated string in a writable buffer, which every
//! conversion can take (`%s` and `%n` among them; integers read its bits). The
//! format is kept to as many conversions as there are arguments, and away from widths that
//! would make `BIO_printf` build gigabytes.
//!
//! Checks: nothing panics or crashes; `BIO_snprintf` never writes past its buffer, and a
//! non-negative return is the length before the NUL it wrote; and what fits in a large buffer
//! is exactly what `BIO_printf` writes to a memory BIO, unless the format has a floating-point
//! conversion: where the calling convention passes doubles in their own registers (x86_64's
//! SSE registers), those conversions read whatever is there, which differs between calls.

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_void};

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{BIO, BIO_CTRL_INFO, BIO_METHOD};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_new(method: *const BIO_METHOD) -> *mut BIO;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn BIO_ctrl(b: *mut BIO, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    fn BIO_snprintf(buf: *mut c_char, n: usize, format: *const c_char, ...) -> c_int;
    fn BIO_printf(bio: *mut BIO, format: *const c_char, ...) -> c_int;
}

/// Whether a conversion in `format` takes a double (`%e`, `%f`, `%g`, `%a` in either case),
/// whose value the pointer arguments don't determine on every target.
fn has_float_conversion(format: &[u8]) -> bool {
    let mut i = 0;
    while let Some(off) = format.get(i..).and_then(|rest| rest.iter().position(|b| *b == b'%')) {
        i += off + 1;
        // Flags, width, precision and length modifiers come before the conversion.
        while format.get(i).is_some_and(|b| b"-+ #0123456789.*hlLqjzt'".contains(b)) {
            i += 1;
        }
        match format.get(i) {
            Some(b'e' | b'E' | b'f' | b'F' | b'g' | b'G' | b'a' | b'A') => return true,
            // A `%` here starts the next conversion (BIO_printf prints an invalid one as it
            // stands, `%LLj%G` among them), so it isn't stepped over; `%%G` counts as a
            // conversion too, which only skips a comparison.
            Some(b'%') => {}
            Some(_) => i += 1,
            None => break,
        }
    }
    false
}

/// The arguments' target, reset before each call (`%n` writes to it).
fn target() -> [u8; 64] {
    let mut target = [0u8; 64];
    target[..5].copy_from_slice(b"fuzz\0");
    target
}

fuzz_target!(|data: &[u8]| {
    let Some((&size, format)) = data.split_first() else {
        return;
    };
    let format: Vec<u8> = format.iter().copied().take_while(|b| *b != 0).chain([0]).collect();
    // Each conversion and each `*` takes at most one argument; there are 12.
    if format.iter().filter(|b| **b == b'%' || **b == b'*').count() > 12 {
        return;
    }
    let size = usize::from(size % 64);

    let mut arg = target();
    let p = arg.as_mut_ptr();
    let mut small = [b'#'; 80];
    // SAFETY: the buffer has room for `size` bytes; every argument is the same valid pointer.
    let ret = unsafe {
        BIO_snprintf(small.as_mut_ptr().cast(), size, format.as_ptr().cast(), p, p, p, p, p, p, p, p, p, p, p, p)
    };
    assert!(small[size..].iter().all(|b| *b == b'#'), "wrote past the buffer");
    if ret >= 0 {
        let len = usize::try_from(ret).unwrap();
        assert!(len < size && small[len] == 0);
    }

    // `BIO_printf` would build a huge output from large widths, `*` among them.
    let digits = format.split(|b| !b.is_ascii_digit()).map(<[u8]>::len).max().unwrap_or(0);
    if digits > 4 || format.contains(&b'*') {
        return;
    }
    arg = target();
    let p = arg.as_mut_ptr();
    let mut large = vec![0u8; 1 << 16];
    // SAFETY: as above.
    let fitted = unsafe {
        BIO_snprintf(large.as_mut_ptr().cast(), large.len(), format.as_ptr().cast(), p, p, p, p, p, p, p, p, p, p, p, p)
    };
    arg = target();
    let p = arg.as_mut_ptr();
    // SAFETY: the built-in method.
    let bio = unsafe { BIO_new(BIO_s_mem()) };
    // SAFETY: as above.
    let printed = unsafe { BIO_printf(bio, format.as_ptr().cast(), p, p, p, p, p, p, p, p, p, p, p, p) };
    let mut out: *mut c_char = core::ptr::null_mut();
    // SAFETY: BIO_get_mem_data on a live memory BIO.
    let len = unsafe { BIO_ctrl(bio, BIO_CTRL_INFO, 0, (&raw mut out).cast()) };
    let written = if len > 0 {
        // SAFETY: the BIO's data holds `len` bytes.
        unsafe { core::slice::from_raw_parts(out.cast::<u8>(), usize::try_from(len).unwrap()) }.to_vec()
    } else {
        Vec::new()
    };
    if fitted >= 0 && !has_float_conversion(&format) {
        let fitted = usize::try_from(fitted).unwrap();
        assert_eq!(written, &large[..fitted]);
        assert_eq!(usize::try_from(printed.max(0)).unwrap(), fitted);
    }
    // SAFETY: a live BIO.
    unsafe { BIO_free(bio) };
    let _ = arg;
});
