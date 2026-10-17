//! The ASN.1 streaming filter (`BIO_f_asn1(3)`, OpenSSL's `bio_asn1.c`): what is written through
//! it goes out as primitive OCTET STRINGs, one per write, after a prefix and before a suffix that
//! functions set with `BIO_asn1_set_prefix` and `BIO_asn1_set_suffix` produce. `BIO_new_NDEF`
//! builds indefinite-length encodings on it.
//!
//! The prefix and suffix functions get the filter's buffer, length, and argument by address, as
//! in OpenSSL, but as copies: the filter's lock is never held while one runs (README.md, security
//! rule 7), and what it leaves is stored when it returns.

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;
use core::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use rustyssl_abi::{
    BIO, BIO_C_GET_EX_ARG, BIO_C_GET_PREFIX, BIO_C_GET_SUFFIX, BIO_C_SET_EX_ARG, BIO_C_SET_PREFIX,
    BIO_C_SET_SUFFIX, BIO_CTRL_FLUSH, BIO_FLAGS_RWS, BIO_FLAGS_SHOULD_RETRY, BIO_METHOD,
    BIO_TYPE_ASN1, BIO_info_cb, ERR_LIB_ASN1, ERR_LIB_BIO, V_ASN1_OCTET_STRING, V_ASN1_UNIVERSAL,
    asn1_ps_func,
};

use crate::asn1::{ASN1_object_size, ASN1_put_object};
use crate::bio::method::{Builtin, Funcs};
use crate::bio::state::{self, lock};
use crate::bio::{
    BIO_callback_ctrl, BIO_clear_flags, BIO_copy_next_retry, BIO_ctrl, BIO_gets, BIO_read,
    BIO_write, Bio, object,
};
use crate::ffi::{ffi_callback, ffi_export};

/// `DEFAULT_ASN1_BUF_SIZE`: room for an OCTET STRING's header.
const BUF_SIZE: usize = 20;

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Start,
    PreCopy,
    Header,
    HeaderCopy,
    DataCopy,
    PostCopy,
    Done,
}

/// A pointer a prefix or suffix function keeps in the filter.
#[derive(Clone, Copy)]
struct Raw<T>(*mut T);

// SAFETY: the pointers belong to the prefix and suffix functions, which OpenSSL lets run on any
// thread that uses the BIO (one at a time); the filter only hands them back.
unsafe impl<T> Send for Raw<T> {}

/// The filter's state (OpenSSL's `BIO_ASN1_BUF_CTX`).
struct Asn1Bio {
    state: State,
    buf: [u8; BUF_SIZE],
    bufpos: usize,
    buflen: usize,
    copylen: c_int,
    class: c_int,
    tag: c_int,
    prefix: asn1_ps_func,
    prefix_free: asn1_ps_func,
    suffix: asn1_ps_func,
    suffix_free: asn1_ps_func,
    ex_buf: Raw<c_uchar>,
    ex_len: c_int,
    ex_pos: c_int,
    ex_arg: Raw<c_void>,
}

/// `BIO_ASN1_EX_FUNCS`, which the prefix and suffix controls take.
#[repr(C)]
struct ExFuncs {
    ex_func: asn1_ps_func,
    ex_free_func: asn1_ps_func,
}

type Shared = Arc<Mutex<Asn1Bio>>;

fn shared(b: *mut BIO) -> Option<(&'static Bio, Shared)> {
    // SAFETY: a live BIO, as the callers' callers guarantee.
    let object = unsafe { object(b) }?;
    let s = state::get::<Asn1Bio>(object)?;
    Some((object, s))
}

/// `BIO_clear_retry_flags`.
fn clear_retry(b: *mut BIO) {
    // SAFETY: a live BIO.
    unsafe { BIO_clear_flags(b, BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY) };
}

/// Calls a prefix or suffix function on copies of the filter's buffer, length, and argument,
/// and stores what it leaves: its result.
fn call(
    s: &Shared,
    b: *mut BIO,
    f: unsafe extern "C" fn(*mut BIO, *mut *mut c_uchar, *mut c_int, *mut c_void) -> c_int,
) -> c_int {
    let (mut buf, mut len, mut arg) = {
        let st = lock(s);
        (st.ex_buf.0, st.ex_len, st.ex_arg.0)
    };
    // SAFETY: the function set for this filter, with the filter's values by address.
    let r = unsafe { f(b, &mut buf, &mut len, (&raw mut arg).cast()) };
    let mut st = lock(s);
    st.ex_buf = Raw(buf);
    st.ex_len = len;
    st.ex_arg = Raw(arg);
    r
}

/// `asn1_bio_setup_ex`: the prefix or suffix made, and the state after it.
fn setup_ex(s: &Shared, b: *mut BIO, setup: asn1_ps_func, ex_state: State, other: State) -> bool {
    if let Some(f) = setup
        && call(s, b, f) == 0
    {
        clear_retry(b);
        return false;
    }
    let mut st = lock(s);
    st.state = if st.ex_len > 0 { ex_state } else { other };
    true
}

/// `asn1_bio_flush_ex`: the prefix or suffix written to `next`, then freed.
fn flush_ex(s: &Shared, b: *mut BIO, next: *mut BIO, cleanup: asn1_ps_func, then: State) -> c_int {
    let mut ret;
    loop {
        let (buf, len, pos) = {
            let st = lock(s);
            (st.ex_buf.0, st.ex_len, st.ex_pos)
        };
        if len <= 0 {
            return 1;
        }
        let at = usize::try_from(pos).unwrap_or(0);
        // SAFETY: the prefix or suffix function's buffer, `pos + len` octets long; the next BIO.
        ret = unsafe { BIO_write(next, buf.wrapping_add(at).cast(), len) };
        if ret <= 0 {
            break;
        }
        let left = len.saturating_sub(ret);
        lock(s).ex_len = left;
        if left > 0 {
            lock(s).ex_pos = pos.saturating_add(ret);
        } else {
            if let Some(f) = cleanup {
                call(s, b, f);
            }
            let mut st = lock(s);
            st.state = then;
            st.ex_pos = 0;
            break;
        }
    }
    ret
}

/// `asn1_bio_write`: the caller's octets as OCTET STRINGs, after the prefix.
///
/// # Safety
/// `b` is a live BIO; `data` is NULL or valid for `len` octets.
unsafe fn write(b: *mut BIO, data: *const c_char, len: c_int) -> c_int {
    let Some((object, s)) = shared(b) else {
        return 0;
    };
    let next = object.next();
    let Ok(n) = usize::try_from(len) else {
        return 0;
    };
    if data.is_null() || next.is_null() {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let Some(mut input) = (unsafe { crate::ffi::bytes(data.cast(), n) }) else {
        return 0;
    };
    let mut wrlen: c_int = 0;
    let mut ret: c_int;
    'done: loop {
        let current = lock(&s).state;
        match current {
            State::Start => {
                let prefix = lock(&s).prefix;
                if !setup_ex(&s, b, prefix, State::PreCopy, State::Header) {
                    return -1;
                }
            }
            State::PreCopy => {
                let free = lock(&s).prefix_free;
                ret = flush_ex(&s, b, next, free, State::Header);
                if ret <= 0 {
                    break 'done;
                }
            }
            State::Header => {
                let inl = c_int::try_from(input.len()).unwrap_or(c_int::MAX);
                let mut st = lock(&s);
                // SAFETY: no preconditions.
                let size = unsafe { ASN1_object_size(0, inl, st.tag) };
                let Some(hlen) = usize::try_from(size.saturating_sub(inl))
                    .ok()
                    .filter(|&h| h <= BUF_SIZE)
                else {
                    return -1;
                };
                let mut p = st.buf.as_mut_ptr();
                let (tag, class) = (st.tag, st.class);
                // SAFETY: room for the header, which `ASN1_object_size` measured.
                unsafe { ASN1_put_object(&mut p, 0, inl, tag, class) };
                st.buflen = hlen;
                st.bufpos = 0;
                st.copylen = inl;
                st.state = State::HeaderCopy;
            }
            State::HeaderCopy => {
                let (header, pos, hlen) = {
                    let st = lock(&s);
                    (st.buf, st.bufpos, st.buflen)
                };
                let part = header
                    .get(pos..pos.saturating_add(hlen))
                    .unwrap_or_default();
                let n = c_int::try_from(part.len()).unwrap_or(0);
                // SAFETY: the header's octets; the next BIO.
                ret = unsafe { BIO_write(next, part.as_ptr().cast(), n) };
                if ret <= 0 {
                    break 'done;
                }
                let done = usize::try_from(ret).unwrap_or(0).min(hlen);
                let mut st = lock(&s);
                st.buflen = hlen - done;
                if st.buflen != 0 {
                    st.bufpos = pos.saturating_add(done);
                } else {
                    st.bufpos = 0;
                    st.state = State::DataCopy;
                }
            }
            State::DataCopy => {
                let copylen = usize::try_from(lock(&s).copylen).unwrap_or(0);
                let chunk = input.get(..copylen.min(input.len())).unwrap_or_default();
                let n = c_int::try_from(chunk.len()).unwrap_or(0);
                // SAFETY: the caller's octets; the next BIO.
                ret = unsafe { BIO_write(next, chunk.as_ptr().cast(), n) };
                if ret <= 0 {
                    break 'done;
                }
                let done = usize::try_from(ret).unwrap_or(0).min(chunk.len());
                wrlen = wrlen.saturating_add(ret);
                input = input.get(done..).unwrap_or_default();
                let mut st = lock(&s);
                st.copylen = st.copylen.saturating_sub(ret);
                if st.copylen == 0 {
                    st.state = State::Header;
                }
                if input.is_empty() {
                    break 'done;
                }
            }
            State::PostCopy | State::Done => {
                clear_retry(b);
                return 0;
            }
        }
    }
    clear_retry(b);
    // SAFETY: a live BIO.
    unsafe { BIO_copy_next_retry(b) };
    if wrlen > 0 { wrlen } else { ret }
}

ffi_callback! {
    /// The filter's `bwrite`.
    ///
    /// # Safety
    /// `b` is a live BIO; `data` is NULL or valid for `len` octets.
    pub(crate) unsafe extern "C" fn asn1_bio_write(b: *mut BIO, data: *const c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { write(b, data, len) }
    }
}

ffi_callback! {
    /// Reads from the next BIO.
    ///
    /// # Safety
    /// `b` is a live BIO; `data` is valid for `len` octets.
    pub(crate) unsafe extern "C" fn asn1_bio_read(b: *mut BIO, data: *mut c_char, len: c_int) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let next = unsafe { object(b) }.map_or(ptr::null_mut(), Bio::next);
        if next.is_null() {
            return 0;
        }
        // SAFETY: as above.
        unsafe { BIO_read(next, data.cast(), len) }
    }
}

ffi_callback! {
    /// Writes a string through the filter.
    ///
    /// # Safety
    /// `b` is a live BIO; `text` a C string.
    pub(crate) unsafe extern "C" fn asn1_bio_puts(b: *mut BIO, text: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        if text.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let n = unsafe { core::ffi::CStr::from_ptr(text) }.count_bytes();
        // SAFETY: as above.
        unsafe { write(b, text, c_int::try_from(n).unwrap_or(c_int::MAX)) }
    }
}

ffi_callback! {
    /// Reads a line from the next BIO.
    ///
    /// # Safety
    /// `b` is a live BIO; `buf` is valid for `size` octets.
    pub(crate) unsafe extern "C" fn asn1_bio_gets(b: *mut BIO, buf: *mut c_char, size: c_int) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let next = unsafe { object(b) }.map_or(ptr::null_mut(), Bio::next);
        if next.is_null() {
            return 0;
        }
        // SAFETY: as above.
        unsafe { BIO_gets(next, buf, size) }
    }
}

ffi_callback! {
    /// Passes `BIO_callback_ctrl` to the next BIO.
    ///
    /// # Safety
    /// `b` is a live BIO.
    pub(crate) unsafe extern "C" fn asn1_bio_callback_ctrl(b: *mut BIO, cmd: c_int, fp: BIO_info_cb) -> c_long
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let next = unsafe { object(b) }.map_or(ptr::null_mut(), Bio::next);
        if next.is_null() {
            return 0;
        }
        // SAFETY: as above.
        unsafe { BIO_callback_ctrl(next, cmd, fp) }
    }
}

ffi_callback! {
    /// The filter's controls: the prefix and suffix functions and their argument; a flush
    /// writes the suffix; the rest go to the next BIO.
    ///
    /// # Safety
    /// `b` is a live BIO; `arg2` is what the command expects.
    pub(crate) unsafe extern "C" fn asn1_bio_ctrl(b: *mut BIO, cmd: c_int, arg1: c_long, arg2: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_ASN1
    {
        let Some((object, s)) = shared(b) else { return 0 };
        let next = object.next();
        match cmd {
            BIO_C_SET_PREFIX | BIO_C_SET_SUFFIX | BIO_C_GET_PREFIX | BIO_C_GET_SUFFIX => {
                let ex = arg2.cast::<ExFuncs>();
                if ex.is_null() {
                    return 0;
                }
                let mut st = lock(&s);
                match cmd {
                    BIO_C_SET_PREFIX => {
                        // SAFETY: the caller's functions.
                        let e = unsafe { ex.read() };
                        st.prefix = e.ex_func;
                        st.prefix_free = e.ex_free_func;
                    }
                    BIO_C_SET_SUFFIX => {
                        // SAFETY: as above.
                        let e = unsafe { ex.read() };
                        st.suffix = e.ex_func;
                        st.suffix_free = e.ex_free_func;
                    }
                    BIO_C_GET_PREFIX => {
                        // SAFETY: the caller's room.
                        unsafe { ex.write(ExFuncs { ex_func: st.prefix, ex_free_func: st.prefix_free }) };
                    }
                    _ => {
                        // SAFETY: as above.
                        unsafe { ex.write(ExFuncs { ex_func: st.suffix, ex_free_func: st.suffix_free }) };
                    }
                }
                1
            }
            BIO_C_SET_EX_ARG => {
                lock(&s).ex_arg = Raw(arg2);
                1
            }
            BIO_C_GET_EX_ARG => {
                if arg2.is_null() {
                    return 0;
                }
                let arg = lock(&s).ex_arg.0;
                // SAFETY: the caller's room for a pointer.
                unsafe { arg2.cast::<*mut c_void>().write(arg) };
                1
            }
            BIO_CTRL_FLUSH => {
                if next.is_null() {
                    return 0;
                }
                if lock(&s).state == State::Header {
                    let suffix = lock(&s).suffix;
                    if !setup_ex(&s, b, suffix, State::PostCopy, State::Done) {
                        return 0;
                    }
                }
                if lock(&s).state == State::PostCopy {
                    let free = lock(&s).suffix_free;
                    let ret = flush_ex(&s, b, next, free, State::Done);
                    if ret <= 0 {
                        return c_long::from(ret);
                    }
                }
                if lock(&s).state == State::Done {
                    // SAFETY: the next BIO; the caller's arguments.
                    unsafe { BIO_ctrl(next, cmd, arg1, arg2) }
                } else {
                    clear_retry(b);
                    0
                }
            }
            _ => {
                if next.is_null() {
                    return 0;
                }
                // SAFETY: as above.
                unsafe { BIO_ctrl(next, cmd, arg1, arg2) }
            }
        }
    }
}

ffi_callback! {
    /// Sets up the filter: an OCTET STRING per write, no prefix or suffix yet.
    ///
    /// # Safety
    /// `b` is NULL or a live BIO.
    pub(crate) unsafe extern "C" fn asn1_bio_new(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else { return 0 };
        state::install(object, Asn1Bio {
            state: State::Start,
            buf: [0; BUF_SIZE],
            bufpos: 0,
            buflen: 0,
            copylen: 0,
            class: V_ASN1_UNIVERSAL,
            tag: V_ASN1_OCTET_STRING,
            prefix: None,
            prefix_free: None,
            suffix: None,
            suffix_free: None,
            ex_buf: Raw(ptr::null_mut()),
            ex_len: 0,
            ex_pos: 0,
            ex_arg: Raw(ptr::null_mut()),
        });
        object.init.store(1, Ordering::Relaxed);
        1
    }
}

ffi_callback! {
    /// Frees the filter, calling its prefix and suffix free functions.
    ///
    /// # Safety
    /// `b` is NULL or a live BIO, not used afterwards.
    pub(crate) unsafe extern "C" fn asn1_bio_free(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else { return 0 };
        let Some(s) = state::get::<Asn1Bio>(object) else { return 0 };
        let (prefix_free, suffix_free) = {
            let st = lock(&s);
            (st.prefix_free, st.suffix_free)
        };
        if let Some(f) = prefix_free {
            call(&s, b, f);
        }
        if let Some(f) = suffix_free {
            call(&s, b, f);
        }
        drop(state::remove::<Asn1Bio>(object));
        object.init.store(0, Ordering::Relaxed);
        1
    }
}

static ASN1: Builtin = Builtin::new(BIO_TYPE_ASN1, c"asn1", || Funcs {
    bputs: Some(asn1_bio_puts),
    bgets: Some(asn1_bio_gets),
    ctrl: Some(asn1_bio_ctrl),
    create: Some(asn1_bio_new),
    destroy: Some(asn1_bio_free),
    callback_ctrl: Some(asn1_bio_callback_ctrl),
    ..Funcs::classic(asn1_bio_write, asn1_bio_read)
});

ffi_export! {
    /// The ASN.1 streaming filter's method.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_f_asn1() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_ASN1
    {
        ASN1.get()
    }
}

/// `asn1_bio_set_ex`.
fn set_ex(b: *mut BIO, cmd: c_int, f: asn1_ps_func, free: asn1_ps_func) -> c_int {
    let mut ex = ExFuncs {
        ex_func: f,
        ex_free_func: free,
    };
    // SAFETY: a live BIO, or NULL; the functions by address.
    let r = unsafe { BIO_ctrl(b, cmd, 0, (&raw mut ex).cast()) };
    c_int::try_from(r).unwrap_or(0)
}

/// `asn1_bio_get_ex`.
///
/// # Safety
/// `pf` and `pfree` are NULL or room for a function.
unsafe fn get_ex(
    b: *mut BIO,
    cmd: c_int,
    pf: *mut asn1_ps_func,
    pfree: *mut asn1_ps_func,
) -> c_int {
    let mut ex = ExFuncs {
        ex_func: None,
        ex_free_func: None,
    };
    // SAFETY: a live BIO, or NULL; room for the functions.
    let r = unsafe { BIO_ctrl(b, cmd, 0, (&raw mut ex).cast()) };
    let r = c_int::try_from(r).unwrap_or(0);
    if r > 0 {
        // SAFETY: the caller's room.
        if let Some(p) = unsafe { pf.as_mut() } {
            *p = ex.ex_func;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { pfree.as_mut() } {
            *p = ex.ex_free_func;
        }
    }
    r
}

ffi_export! {
    /// Sets the filter's prefix function and the function that frees what it made.
    ///
    /// # Safety
    /// `b` is NULL or a live BIO.
    pub unsafe extern "C" fn BIO_asn1_set_prefix(b: *mut BIO, prefix: asn1_ps_func, prefix_free: asn1_ps_func) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        set_ex(b, BIO_C_SET_PREFIX, prefix, prefix_free)
    }
}

ffi_export! {
    /// The filter's prefix functions.
    ///
    /// # Safety
    /// `b` is NULL or a live BIO; the others room for a function.
    pub unsafe extern "C" fn BIO_asn1_get_prefix(b: *mut BIO, pprefix: *mut asn1_ps_func, pprefix_free: *mut asn1_ps_func) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { get_ex(b, BIO_C_GET_PREFIX, pprefix, pprefix_free) }
    }
}

ffi_export! {
    /// Sets the filter's suffix function and the function that frees what it made.
    ///
    /// # Safety
    /// `b` is NULL or a live BIO.
    pub unsafe extern "C" fn BIO_asn1_set_suffix(b: *mut BIO, suffix: asn1_ps_func, suffix_free: asn1_ps_func) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        set_ex(b, BIO_C_SET_SUFFIX, suffix, suffix_free)
    }
}

ffi_export! {
    /// The filter's suffix functions.
    ///
    /// # Safety
    /// `b` is NULL or a live BIO; the others room for a function.
    pub unsafe extern "C" fn BIO_asn1_get_suffix(b: *mut BIO, psuffix: *mut asn1_ps_func, psuffix_free: *mut asn1_ps_func) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { get_ex(b, BIO_C_GET_SUFFIX, psuffix, psuffix_free) }
    }
}
