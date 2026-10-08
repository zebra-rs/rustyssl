//! `BIO_debug_callback(3)`: a BIO callback that describes each operation, to the BIO in the
//! callback argument or, without one, to stderr.

use core::ffi::{CStr, c_char, c_int, c_long};
use std::io::Write as _;

use rustyssl_abi::{
    BIO, BIO_CB_CTRL, BIO_CB_FREE, BIO_CB_GETS, BIO_CB_PUTS, BIO_CB_READ, BIO_CB_RECVMMSG,
    BIO_CB_RETURN, BIO_CB_SENDMMSG, BIO_CB_WRITE, BIO_MMSG_CB_ARGS, BIO_TYPE_DESCRIPTOR,
    ERR_LIB_BIO,
};

use super::print::{Arg, snprintf};
use crate::ffi::ffi_export;

/// A `size_t` argument.
fn size(value: usize) -> Arg {
    Arg::Long(u64::try_from(value).unwrap_or(u64::MAX))
}

ffi_export! {
    /// Describes operation `oper` on `bio` in one line, as OpenSSL does: `BIO[address]: `,
    /// then what is done (`write(num,len) - method name`, `read return ret processed: n`,
    /// ...), cut to 255 bytes. Writes it to the BIO that is `bio`'s callback argument, or to
    /// stderr if there is none. Returns `ret`, or for the end of `BIO_sendmmsg` and
    /// `BIO_recvmmsg` the number of messages. A null `bio` writes nothing (OpenSSL's would
    /// crash).
    ///
    /// # Safety
    /// `bio` is null or a live BIO; `argp` is what `oper` passes (the message arguments for
    /// `BIO_CB_SENDMMSG` and `BIO_CB_RECVMMSG`); `processed` is null or valid for a read.
    pub unsafe extern "C" fn BIO_debug_callback_ex(bio: *mut BIO, oper: c_int, argp: *const c_char, len: usize, argi: c_int, argl: c_long, ret: c_int, processed: *mut usize) -> c_long
    where failure = c_long::from(ret), library = ERR_LIB_BIO
    {
        let _ = argl;
        let mut result = c_long::from(ret);
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { super::object(bio) }) else {
            return result;
        };
        let processed = if processed.is_null() {
            0
        } else {
            // SAFETY: the caller's guarantee.
            unsafe { processed.read() }
        };
        // SAFETY: a BIO's method outlives it.
        let method = unsafe { super::method::method(object.method.0) };
        let name = Arg::Pointer(method.map_or(core::ptr::null(), |m| m.name()).cast());
        let descriptor = method.is_some_and(|m| m.kind() & BIO_TYPE_DESCRIPTOR != 0);
        let num = Arg::Int(object.num.load(core::sync::atomic::Ordering::Relaxed));
        let messages = || {
            let args = argp.cast::<BIO_MMSG_CB_ARGS>();
            if args.is_null() {
                size(0)
            } else {
                // SAFETY: the caller's guarantee: these operations pass their arguments.
                size(unsafe { (*args).num_msg })
            }
        };

        let mut buf = [0u8; 256];
        let prefix = snprintf(&mut buf, c"BIO[%p]: ", &[Arg::Pointer(bio.cast_const().cast())]);
        let rest = buf.get_mut(usize::try_from(prefix).unwrap_or(0)..).unwrap_or_default();
        let (format, args): (&CStr, Vec<Arg>) = match oper {
            BIO_CB_FREE => (c"Free - %s\n", vec![name]),
            BIO_CB_READ if descriptor => (c"read(%d,%zu) - %s fd=%d\n", vec![num, size(len), name, num]),
            BIO_CB_READ => (c"read(%d,%zu) - %s\n", vec![num, size(len), name]),
            BIO_CB_WRITE if descriptor => (c"write(%d,%zu) - %s fd=%d\n", vec![num, size(len), name, num]),
            BIO_CB_WRITE => (c"write(%d,%zu) - %s\n", vec![num, size(len), name]),
            BIO_CB_PUTS => (c"puts() - %s\n", vec![name]),
            BIO_CB_GETS => (c"gets(%zu) - %s\n", vec![size(len), name]),
            BIO_CB_CTRL => (c"ctrl(%d) - %s\n", vec![Arg::Int(argi), name]),
            BIO_CB_RECVMMSG => (c"recvmmsg(%zu) - %s", vec![messages(), name]),
            BIO_CB_SENDMMSG => (c"sendmmsg(%zu) - %s", vec![messages(), name]),
            o if o == BIO_CB_RETURN | BIO_CB_READ => (c"read return %d processed: %zu\n", vec![Arg::Int(ret), size(processed)]),
            o if o == BIO_CB_RETURN | BIO_CB_WRITE => (c"write return %d processed: %zu\n", vec![Arg::Int(ret), size(processed)]),
            o if o == BIO_CB_RETURN | BIO_CB_GETS => (c"gets return %d processed: %zu\n", vec![Arg::Int(ret), size(processed)]),
            o if o == BIO_CB_RETURN | BIO_CB_PUTS => (c"puts return %d processed: %zu\n", vec![Arg::Int(ret), size(processed)]),
            o if o == BIO_CB_RETURN | BIO_CB_CTRL => (c"ctrl return %d\n", vec![Arg::Int(ret)]),
            o if o == BIO_CB_RETURN | BIO_CB_RECVMMSG || o == BIO_CB_RETURN | BIO_CB_SENDMMSG => {
                result = i64::from_ne_bytes(u64::try_from(len).unwrap_or(u64::MAX).to_ne_bytes());
                let format = if o == BIO_CB_RETURN | BIO_CB_RECVMMSG {
                    c"recvmmsg processed: %zu\n"
                } else {
                    c"sendmmsg processed: %zu\n"
                };
                (format, vec![size(len)])
            }
            _ => (c"bio callback - unknown type (%d)\n", vec![Arg::Int(oper)]),
        };
        // Output that doesn't fit is cut short; OpenSSL ignores the failure too.
        snprintf(rest, format, &args);

        let text = CStr::from_bytes_until_nul(&buf).map_or(b"".as_slice(), CStr::to_bytes);
        let out = object.callbacks().arg.0.cast::<BIO>();
        if out.is_null() {
            // Nothing useful can be done if stderr is closed.
            let _ = std::io::stderr().write_all(text);
        } else {
            let len = c_int::try_from(text.len()).unwrap_or(c_int::MAX);
            // SAFETY: the callback argument of a BIO with this callback is a BIO.
            unsafe { super::BIO_write(out, text.as_ptr().cast(), len) };
        }
        result
    }
}

ffi_export! {
    /// The old-style form of `BIO_debug_callback_ex`, which gets the length in `argi` and the
    /// count in `ret`. Returns `ret`.
    ///
    /// # Safety
    /// As for `BIO_debug_callback_ex`.
    pub unsafe extern "C" fn BIO_debug_callback(bio: *mut BIO, cmd: c_int, argp: *const c_char, argi: c_int, argl: c_long, ret: c_long) -> c_long
    where failure = ret, library = ERR_LIB_BIO
    {
        let mut processed = if ret > 0 { usize::try_from(ret).unwrap_or(0) } else { 0 };
        let len = usize::from_ne_bytes(i64::from(argi).to_ne_bytes());
        let ret_int = if ret > 0 { 1 } else { super::wrap_int(ret) };
        // SAFETY: the caller's guarantee; `processed` is a local.
        unsafe { BIO_debug_callback_ex(bio, cmd, argp, len, argi, argl, ret_int, &raw mut processed) };
        ret
    }
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::*;

    /// docs/DEVIATIONS.md: OpenSSL dereferences a null BIO.
    #[test]
    fn a_null_bio_writes_nothing() {
        let null = ptr::null_mut();
        // SAFETY: a null BIO is refused before use.
        let ret = unsafe {
            BIO_debug_callback_ex(null, BIO_CB_WRITE, ptr::null(), 0, 0, 0, 7, null.cast())
        };
        assert_eq!(ret, 7);
        // SAFETY: as above.
        let ret = unsafe { BIO_debug_callback(null, BIO_CB_READ, ptr::null(), 0, 0, -3) };
        assert_eq!(ret, -3);
    }
}
