//! The base64 filter (`BIO_f_base64(3)`): encodes what is written through it, in lines of 64
//! characters (or none with `BIO_FLAGS_BASE64_NO_NL`) finished by `BIO_flush`, and decodes what
//! is read, skipping lines before the first that decodes. A port of OpenSSL's `bio_b64.c`, over
//! `rustyssl_asn1::base64`.
//!
//! The filter's state is taken out of its lock while it reads from or writes to the next BIO,
//! which may be an application's, and put back after.

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr;
use core::sync::atomic::Ordering;

use rustyssl_abi::{
    BIO, BIO_C_DO_STATE_MACHINE, BIO_CTRL_DUP, BIO_CTRL_EOF, BIO_CTRL_FLUSH, BIO_CTRL_PENDING,
    BIO_CTRL_RESET, BIO_CTRL_WPENDING, BIO_FLAGS_BASE64_NO_NL, BIO_FLAGS_SHOULD_RETRY, BIO_METHOD,
    BIO_TYPE_BASE64, BIO_info_cb, ERR_LIB_BIO,
};
use rustyssl_asn1::base64::{self, Ctx};

use super::method::{Builtin, Funcs};
use super::object;
use super::state::{self, lock};
use crate::ffi::{ffi_callback, ffi_export};

/// The characters read from the next BIO at a time (`B64_BLOCK_SIZE`).
const BLOCK_SIZE: usize = 1024;

/// What the filter last did.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum Mode {
    #[default]
    None,
    Encode,
    Decode,
}

/// The state of a base64 filter (OpenSSL's `BIO_B64_CTX`).
struct B64 {
    /// Encoded text to write, or decoded octets to read, from `buf_off` to `buf.len()`.
    buf: Vec<u8>,
    buf_off: usize,
    /// Characters read and not yet decoded, or (without newlines) octets not yet encoded.
    tmp: Vec<u8>,
    /// Skipping to the end of an overlong line before looking for base64.
    tmp_nl: bool,
    encode: Mode,
    /// No line has decoded yet.
    start: bool,
    /// Above 0 while more may be read; the end (0) or an error (below) after.
    cont: c_int,
    base64: Ctx,
}

impl Default for B64 {
    fn default() -> Self {
        Self {
            buf: Vec::new(),
            buf_off: 0,
            tmp: Vec::new(),
            tmp_nl: false,
            encode: Mode::None,
            start: true,
            cont: 1,
            base64: Ctx::default(),
        }
    }
}

impl B64 {
    fn pending(&self) -> usize {
        self.buf.len().saturating_sub(self.buf_off)
    }

    fn reset_buf(&mut self) {
        self.buf.clear();
        self.buf_off = 0;
    }
}

/// Runs `body` on the filter's state, taken out of its lock while it runs.
fn with_state<R>(b: *mut BIO, failure: R, body: impl FnOnce(&super::Bio, &mut B64) -> R) -> R {
    // SAFETY: the caller's BIO, live while its method runs.
    let Some(object) = (unsafe { object(b) }) else {
        return failure;
    };
    let Some(state) = state::get::<B64>(object) else {
        return failure;
    };
    let mut st = core::mem::take(&mut *lock(&state));
    let ret = body(object, &mut st);
    *lock(&state) = st;
    ret
}

/// `BIO_should_retry` of the next BIO.
fn should_retry(next: *mut BIO) -> bool {
    // SAFETY: the next BIO, live while it is in the chain.
    unsafe { object(next) }.is_some_and(|n| n.flags() & BIO_FLAGS_SHOULD_RETRY != 0)
}

/// Writes `data` to `next` (`BIO_write`).
fn write_next(next: *mut BIO, data: &[u8]) -> c_int {
    let n = c_int::try_from(data.len()).unwrap_or(c_int::MAX);
    // SAFETY: the next BIO is live; `data` holds `n` octets.
    unsafe { super::BIO_write(next, data.as_ptr().cast(), n) }
}

/// Writes what is pending to `next`. `Err` with `BIO_write`'s result if it fails.
fn drain(object: &super::Bio, st: &mut B64, next: *mut BIO) -> Result<(), c_int> {
    while st.pending() > 0 {
        let i = write_next(next, st.buf.get(st.buf_off..).unwrap_or(&[]));
        if i <= 0 {
            super::copy_next_retry(object);
            return Err(i);
        }
        st.buf_off = st.buf_off.saturating_add(usize::try_from(i).unwrap_or(0));
    }
    Ok(())
}

/// `b64_write`: encodes `input` (none: only writes what is pending) to the next BIO.
fn write_body(object: &super::Bio, st: &mut B64, input: Option<&[u8]>) -> c_int {
    let next = object.next();
    if next.is_null() {
        return 0;
    }
    object.clear_retry_flags();
    if st.encode != Mode::Encode {
        st.encode = Mode::Encode;
        st.reset_buf();
        st.tmp.clear();
        st.base64.encode_init();
    }
    if let Err(i) = drain(object, st, next) {
        return i;
    }
    st.reset_buf();
    let Some(mut input) = input.filter(|i| !i.is_empty()) else {
        return 0;
    };
    let no_nl = object.flags() & BIO_FLAGS_BASE64_NO_NL != 0;
    let mut ret: usize = 0;
    let int = |n: usize| c_int::try_from(n).unwrap_or(c_int::MAX);
    while !input.is_empty() {
        let mut n = input.len().min(BLOCK_SIZE);
        if no_nl {
            if !st.tmp.is_empty() {
                n = (3 - st.tmp.len().min(3)).min(input.len());
                st.tmp.extend_from_slice(input.get(..n).unwrap_or(&[]));
                ret = ret.saturating_add(n);
                if st.tmp.len() < 3 {
                    break;
                }
                st.buf = base64::encode_block(&st.tmp);
                st.tmp.clear();
            } else {
                if n < 3 {
                    st.tmp.extend_from_slice(input.get(..n).unwrap_or(&[]));
                    ret = ret.saturating_add(n);
                    break;
                }
                n -= n % 3;
                st.buf = base64::encode_block(input.get(..n).unwrap_or(&[]));
                ret = ret.saturating_add(n);
            }
        } else {
            match st.base64.encode_update(input.get(..n).unwrap_or(&[])) {
                Some(encoded) => st.buf = encoded.out,
                None => return if ret == 0 { -1 } else { int(ret) },
            }
            ret = ret.saturating_add(n);
        }
        input = input.get(n..).unwrap_or(&[]);
        st.buf_off = 0;
        if let Err(i) = drain(object, st, next) {
            return if ret == 0 { i } else { int(ret) };
        }
        st.reset_buf();
    }
    int(ret)
}

/// `b64_read`: decodes into `out` from the next BIO.
fn read_body(object: &super::Bio, st: &mut B64, out: &mut [u8]) -> c_int {
    let next = object.next();
    if next.is_null() {
        return 0;
    }
    object.clear_retry_flags();
    if st.encode != Mode::Decode {
        st.encode = Mode::Decode;
        st.reset_buf();
        st.tmp.clear();
        st.base64.decode_init();
    }
    let mut ret: usize = 0;
    let mut out = out;
    if st.pending() > 0 {
        let i = st.pending().min(out.len());
        let (head, tail) = out.split_at_mut(i);
        head.copy_from_slice(
            st.buf
                .get(st.buf_off..st.buf_off.saturating_add(i))
                .unwrap_or(&[]),
        );
        out = tail;
        ret = i;
        st.buf_off = st.buf_off.saturating_add(i);
        if st.pending() == 0 {
            st.reset_buf();
        }
    }
    let mut ret_code = if st.cont < 0 { st.cont } else { 0 };
    let no_nl = object.flags() & BIO_FLAGS_BASE64_NO_NL != 0;
    while !out.is_empty() {
        let mut again = st.cont;
        if again <= 0 {
            break;
        }
        let have = st.tmp.len();
        let mut chunk = vec![0u8; BLOCK_SIZE.saturating_sub(have)];
        let want = c_int::try_from(chunk.len()).unwrap_or(c_int::MAX);
        // SAFETY: the next BIO is live; `chunk` has room for `want` octets.
        let i = unsafe { super::BIO_read(next, chunk.as_mut_ptr().cast(), want) };
        if i <= 0 {
            ret_code = i;
            if !should_retry(next) {
                if have == 0 {
                    if st.base64.decode_final().is_none() {
                        ret_code = -1;
                    }
                    st.base64.decode_init();
                }
                st.cont = ret_code;
            }
            if have == 0 {
                break;
            }
            again = 0;
        } else {
            chunk.truncate(usize::try_from(i).unwrap_or(0));
            st.tmp.extend_from_slice(&chunk);
        }
        let mut len = st.tmp.len();
        if st.start && no_nl {
            // Without newlines there are no lines to skip: decode from the start.
        } else if st.start {
            let mut p = 0;
            let mut q = 0;
            for j in 0..len {
                q = j + 1;
                if st.tmp.get(j) != Some(&b'\n') {
                    continue;
                }
                if st.tmp_nl {
                    p = q;
                    st.tmp_nl = false;
                    continue;
                }
                let decoded = st
                    .base64
                    .decode_update(Some(st.tmp.get(p..q).unwrap_or(&[])));
                st.base64.decode_init();
                if decoded.ret <= 0 && decoded.out.is_empty() {
                    p = q;
                    continue;
                }
                st.start = false;
                break;
            }
            if !st.start && p != 0 {
                // Decoding starts at the line that decoded.
                len -= p;
                st.tmp.drain(..p);
            }
            if st.start {
                if p == 0 {
                    if len == BLOCK_SIZE {
                        st.tmp_nl = true;
                        st.tmp.clear();
                    }
                } else if p != q {
                    st.tmp.drain(..p);
                    st.tmp.truncate(q - p);
                } else {
                    st.tmp.clear();
                }
                if again > 0 {
                    continue;
                }
                break;
            }
        } else if len < BLOCK_SIZE && again > 0 {
            continue;
        }
        let mut text = core::mem::take(&mut st.tmp);
        text.truncate(len);
        let decoded = st.base64.decode_update(Some(&text));
        st.cont = decoded.ret;
        st.buf = decoded.out;
        st.buf_off = 0;
        if decoded.ret < 0 {
            ret_code = if st.start { 0 } else { decoded.ret };
            st.buf.clear();
            break;
        }
        let i = st.buf.len().min(out.len());
        let (head, tail) = out.split_at_mut(i);
        head.copy_from_slice(st.buf.get(..i).unwrap_or(&[]));
        out = tail;
        ret = ret.saturating_add(i);
        st.buf_off = i;
        if st.pending() == 0 {
            st.reset_buf();
        }
    }
    super::copy_next_retry(object);
    if ret == 0 {
        ret_code
    } else {
        c_int::try_from(ret).unwrap_or(c_int::MAX)
    }
}

ffi_callback! {
    /// Sets up a base64 filter.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn b64_new(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        state::install(object, B64::default());
        object.init.store(1, Ordering::Relaxed);
        1
    }
}

ffi_callback! {
    /// Frees a base64 filter's state.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn b64_free(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else {
            return 0;
        };
        if state::remove::<B64>(object).is_none() {
            return 0;
        }
        object.init.store(0, Ordering::Relaxed);
        1
    }
}

ffi_callback! {
    /// Reads decoded octets.
    ///
    /// # Safety
    /// `b` is a live BIO; `out` is NULL or valid for `outl` octets of writes.
    pub(crate) unsafe extern "C" fn b64_read(b: *mut BIO, out: *mut c_char, outl: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        if out.is_null() {
            return 0;
        }
        let Ok(n) = usize::try_from(outl) else {
            return with_state(b, 0, |object, st| read_body(object, st, &mut []));
        };
        // SAFETY: the caller's guarantee.
        let out = unsafe { core::slice::from_raw_parts_mut(out.cast::<u8>(), n) };
        with_state(b, 0, |object, st| read_body(object, st, out))
    }
}

ffi_callback! {
    /// Encodes and writes.
    ///
    /// # Safety
    /// `b` is a live BIO; `data` is NULL or valid for `len` octets.
    pub(crate) unsafe extern "C" fn b64_write(b: *mut BIO, data: *const c_char, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        let input = match usize::try_from(len) {
            // SAFETY: the caller's guarantee.
            Ok(n) if n > 0 && !data.is_null() => Some(unsafe { core::slice::from_raw_parts(data.cast::<u8>(), n) }),
            _ => None,
        };
        with_state(b, 0, |object, st| write_body(object, st, input))
    }
}

ffi_callback! {
    /// Writes a string through the filter's own write (`b64_write`), without the BIO's
    /// callbacks or counts, as OpenSSL does.
    ///
    /// # Safety
    /// `b` is a live BIO; `text` is a NUL-terminated string.
    pub(crate) unsafe extern "C" fn b64_puts(b: *mut BIO, text: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        if text.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let bytes = unsafe { CStr::from_ptr(text) }.to_bytes();
        with_state(b, 0, |object, st| write_body(object, st, Some(bytes)))
    }
}

/// `BIO_CTRL_FLUSH`: writes what is pending, then the last line (or group), then flushes the
/// next BIO.
fn flush(object: &super::Bio, st: &mut B64, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long {
    let next = object.next();
    loop {
        while st.pending() > 0 {
            let before = st.pending();
            let i = write_body(object, st, None);
            if i < 0 {
                return c_long::from(i);
            }
            if i == 0 && st.pending() == before {
                // The next BIO took nothing; OpenSSL would loop here forever.
                return 0;
            }
        }
        if object.flags() & BIO_FLAGS_BASE64_NO_NL != 0 {
            if !st.tmp.is_empty() {
                st.buf = base64::encode_block(&st.tmp);
                st.buf_off = 0;
                st.tmp.clear();
                continue;
            }
        } else if st.encode != Mode::None && st.base64.num != 0 {
            st.buf_off = 0;
            st.buf = st.base64.encode_final().unwrap_or_default();
            continue;
        }
        break;
    }
    // SAFETY: the next BIO is live; `ptr` is the caller's.
    let ret = unsafe { super::BIO_ctrl(next, cmd, num, ptr) };
    super::copy_next_retry(object);
    ret
}

ffi_callback! {
    /// The base64 filter's controls.
    ///
    /// # Safety
    /// `b` is a live BIO; `ptr` is what the command expects.
    pub(crate) unsafe extern "C" fn b64_ctrl(b: *mut BIO, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        with_state(b, 0, |object, st| {
            let next = object.next();
            if next.is_null() {
                return 0;
            }
            // SAFETY: the next BIO is live; `ptr` is the caller's.
            let pass = || unsafe { super::BIO_ctrl(next, cmd, num, ptr) };
            let pending = c_long::try_from(st.pending()).unwrap_or(c_long::MAX);
            match cmd {
                BIO_CTRL_RESET => {
                    st.cont = 1;
                    st.start = true;
                    st.encode = Mode::None;
                    pass()
                }
                BIO_CTRL_EOF => {
                    if st.cont <= 0 { 1 } else { pass() }
                }
                BIO_CTRL_WPENDING => {
                    if pending == 0 && st.encode != Mode::None && st.base64.num != 0 {
                        1
                    } else if pending <= 0 {
                        pass()
                    } else {
                        pending
                    }
                }
                BIO_CTRL_PENDING => {
                    if pending <= 0 { pass() } else { pending }
                }
                BIO_CTRL_FLUSH => flush(object, st, cmd, num, ptr),
                BIO_C_DO_STATE_MACHINE => {
                    object.clear_retry_flags();
                    let ret = pass();
                    super::copy_next_retry(object);
                    ret
                }
                BIO_CTRL_DUP => 1,
                _ => pass(),
            }
        })
    }
}

ffi_callback! {
    /// Passes `BIO_callback_ctrl` to the next BIO.
    ///
    /// # Safety
    /// `b` is a live BIO.
    pub(crate) unsafe extern "C" fn b64_callback_ctrl(b: *mut BIO, cmd: c_int, fp: BIO_info_cb) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let next = unsafe { object(b) }.map_or(ptr::null_mut(), super::Bio::next);
        if next.is_null() {
            return 0;
        }
        // SAFETY: the next BIO is live.
        unsafe { super::BIO_callback_ctrl(next, cmd, fp) }
    }
}

static BASE64: Builtin = Builtin::new(BIO_TYPE_BASE64, c"base64 encoding", || Funcs {
    bputs: Some(b64_puts),
    ctrl: Some(b64_ctrl),
    create: Some(b64_new),
    destroy: Some(b64_free),
    callback_ctrl: Some(b64_callback_ctrl),
    ..Funcs::classic(b64_write, b64_read)
});

ffi_export! {
    /// Returns the base64 filter's method: base64 encodes what is written through it (finish
    /// with `BIO_flush`) and decodes what is read.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_f_base64() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        BASE64.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bio::method::{BIO_meth_free, BIO_meth_new, BIO_meth_set_write};

    /// A sink that takes nothing.
    unsafe extern "C" fn refuse(_b: *mut BIO, _data: *const c_char, _len: c_int) -> c_int {
        0
    }

    /// docs/DEVIATIONS.md: OpenSSL's flush loops forever when the next BIO takes nothing.
    #[test]
    fn a_flush_into_a_full_sink_ends() {
        // SAFETY: a new method with a name.
        let method = unsafe { BIO_meth_new(0x400 | 99, c"refuse".as_ptr()) };
        // SAFETY: the method made above.
        unsafe { BIO_meth_set_write(method, Some(refuse)) };
        // SAFETY: the method, live until freed below.
        let sink = unsafe { crate::bio::BIO_new(method) };
        // SAFETY: a live BIO.
        unsafe { crate::bio::BIO_set_init(sink, 1) };
        // SAFETY: the built-in method.
        let b64 = unsafe { crate::bio::BIO_new(BASE64.get()) };
        // SAFETY: live BIOs; the chain owns the sink.
        unsafe { crate::bio::BIO_push(b64, sink) };
        // SAFETY: a live chain; 3 octets.
        let w = unsafe { crate::bio::BIO_write(b64, c"abc".as_ptr().cast(), 3) };
        assert_eq!(w, 3);
        // SAFETY: as above.
        let r = unsafe { crate::bio::BIO_ctrl(b64, BIO_CTRL_FLUSH, 0, ptr::null_mut()) };
        assert_eq!(r, 0);
        // SAFETY: the chain, then the method.
        unsafe { crate::bio::BIO_free_all(b64) };
        // SAFETY: as above.
        unsafe { BIO_meth_free(method) };
    }
}
