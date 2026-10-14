//! The EVP filters (`BIO_f_md(3)`, `BIO_f_cipher(3)`, `BIO_f_reliable`): a digest of what
//! passes through, finished by `BIO_gets`; encryption of what is written (finished by
//! `BIO_flush`) and decryption of what is read; and OpenSSL's framing with a digest over each
//! block. Ports of OpenSSL's `bio_md.c`, `bio_enc.c`, and `bio_ok.c`, over the EVP functions.
//!
//! The filters keep an `EVP_MD_CTX` or `EVP_CIPHER_CTX` that applications get
//! (`BIO_get_md_ctx`, `BIO_get_cipher_ctx`) and may set up themselves, so they call the EVP
//! functions on it as OpenSSL's do. The digest filter's context is also the BIO's `ptr`, as
//! OpenSSL's data is (nothing here reads it from there). The filters' state is taken out of its
//! lock while they call out (to the next BIO, which may be an application's), and put back
//! after.
//!
//! The reliable filter writes a random seed into its digest's legacy state
//! (`EVP_MD_CTX_get0_md_data`), which provided digests don't have: OpenSSL 3 crashes there, on
//! its first write or once a read has brought the seed in. Here those fail, as does a flush
//! with less than a block's header buffered (OpenSSL's length underflows) and one that OpenSSL
//! would loop on without end (docs/DEVIATIONS.md).

use core::ffi::{c_char, c_int, c_long, c_uint, c_void};
use core::ptr;
use core::sync::atomic::Ordering;

use rustyssl_abi::{
    BIO, BIO_C_DO_STATE_MACHINE, BIO_C_GET_CIPHER_CTX, BIO_C_GET_CIPHER_STATUS, BIO_C_GET_MD,
    BIO_C_GET_MD_CTX, BIO_C_SET_MD, BIO_C_SET_MD_CTX, BIO_CB_CTRL, BIO_CB_RETURN, BIO_CTRL_DUP,
    BIO_CTRL_EOF, BIO_CTRL_FLUSH, BIO_CTRL_INFO, BIO_CTRL_PENDING, BIO_CTRL_RESET, BIO_CTRL_SET,
    BIO_CTRL_WPENDING, BIO_FLAGS_SHOULD_RETRY, BIO_METHOD, BIO_TYPE_CIPHER, BIO_TYPE_MD,
    BIO_info_cb, ERR_LIB_BIO, EVP_CIPHER, EVP_CIPHER_CTX, EVP_MAX_BLOCK_LENGTH, EVP_MAX_MD_SIZE,
    EVP_MD, EVP_MD_CTX,
};

use super::method::{Builtin, Funcs};
use super::object;
use super::state::{self, lock};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_copy, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_get_block_size,
    EVP_CIPHER_CTX_is_encrypting, EVP_CIPHER_CTX_new, EVP_CipherFinal_ex, EVP_CipherInit_ex,
    EVP_CipherUpdate,
};
use crate::evp::digest::EVP_MD_get_size;
use crate::evp::md_ctx::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_copy_ex, EVP_MD_CTX_free,
    EVP_MD_CTX_get_size_ex, EVP_MD_CTX_get0_md, EVP_MD_CTX_get0_md_data, EVP_MD_CTX_new,
};
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem::OPENSSL_cleanse;

/// Zeroes `b` (`OPENSSL_cleanse`), as OpenSSL clears its filters' buffers.
fn wipe(b: &mut [u8]) {
    // SAFETY: the slice's own octets.
    unsafe { OPENSSL_cleanse(b.as_mut_ptr().cast(), b.len()) };
}

/// A context pointer kept in a filter's state.
struct Raw<T>(*mut T);

impl<T> Clone for Raw<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Raw<T> {}

impl<T> Default for Raw<T> {
    fn default() -> Self {
        Self(ptr::null_mut())
    }
}

// SAFETY: the pointer is an EVP context handle, which OpenSSL lets any thread use (one at a
// time, as the BIO is); the filter only passes it to the EVP functions.
unsafe impl<T> Send for Raw<T> {}

/// Runs `body` on a filter's state of type `T`, taken out of its lock while it runs.
fn with_state<T: Default + Send + 'static, R>(
    b: *mut BIO,
    failure: R,
    body: impl FnOnce(&super::Bio, &mut T) -> R,
) -> R {
    // SAFETY: the caller's BIO, live while its method runs.
    let Some(object) = (unsafe { object(b) }) else {
        return failure;
    };
    let Some(state) = state::get::<T>(object) else {
        return failure;
    };
    let mut st = core::mem::take(&mut *lock(&state));
    let ret = body(object, &mut st);
    *lock(&state) = st;
    ret
}

/// `BIO_should_retry` of a BIO.
fn should_retry(bio: *mut BIO) -> bool {
    // SAFETY: a BIO in the chain, live while it is there.
    unsafe { object(bio) }.is_some_and(|n| n.flags() & BIO_FLAGS_SHOULD_RETRY != 0)
}

/// `BIO_ctrl` on the next BIO.
fn ctrl_next(next: *mut BIO, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long {
    // SAFETY: the next BIO is null or live; `ptr` is the caller's, for this command.
    unsafe { super::BIO_ctrl(next, cmd, num, ptr) }
}

/// `BIO_read` from the next BIO into `buf`, at most `len` octets.
fn read_next(next: *mut BIO, buf: *mut u8, len: usize) -> c_int {
    let n = c_int::try_from(len).unwrap_or(c_int::MAX);
    // SAFETY: the next BIO is live; `buf` has room for `len` octets.
    unsafe { super::BIO_read(next, buf.cast(), n) }
}

/// `BIO_write` of `data` to the next BIO.
fn write_next(next: *mut BIO, data: &[u8]) -> c_int {
    let n = c_int::try_from(data.len()).unwrap_or(c_int::MAX);
    // SAFETY: the next BIO is live; `data` holds `n` octets.
    unsafe { super::BIO_write(next, data.as_ptr().cast(), n) }
}

/// Passes `BIO_callback_ctrl` to the next BIO.
fn callback_ctrl(b: *mut BIO, cmd: c_int, fp: BIO_info_cb) -> c_long {
    // SAFETY: the caller's BIO, live while its method runs.
    let next = unsafe { object(b) }.map_or(ptr::null_mut(), super::Bio::next);
    if next.is_null() {
        return 0;
    }
    // SAFETY: the next BIO is live.
    unsafe { super::BIO_callback_ctrl(next, cmd, fp) }
}

/// A length as an `int` (the filters' lengths are small).
fn int(n: usize) -> c_int {
    c_int::try_from(n).unwrap_or(c_int::MAX)
}

// The digest filter.

/// The digest filter's state: its context (OpenSSL's data).
#[derive(Default, Clone, Copy)]
struct Md {
    ctx: Raw<EVP_MD_CTX>,
}

/// The digest filter's context, and the BIO.
fn md_ctx<'a>(b: *mut BIO) -> Option<(&'a super::Bio, *mut EVP_MD_CTX)> {
    // SAFETY: the caller's BIO, live while its method runs.
    let object = unsafe { object(b) }?;
    let state = state::get::<Md>(object)?;
    let ctx = lock(&state).ctx.0;
    Some((object, ctx))
}

ffi_callback! {
    /// Makes a digest filter's context.
    ///
    /// # Safety
    /// `b` is a live BIO.
    pub(crate) unsafe extern "C" fn md_new(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else { return 0 };
        // SAFETY: no preconditions.
        let ctx = unsafe { EVP_MD_CTX_new() };
        if ctx.is_null() {
            return 0;
        }
        state::install(object, Md { ctx: Raw(ctx) });
        object.ptr.store(ctx.cast(), Ordering::Relaxed);
        object.init.store(1, Ordering::Relaxed);
        1
    }
}

ffi_callback! {
    /// Frees a digest filter's context (the one it has now, which `BIO_set_md_ctx` may have
    /// given it).
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn md_free(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else { return 0 };
        let Some(state) = state::remove::<Md>(object) else { return 0 };
        let ctx = lock(&state).ctx.0;
        // SAFETY: the filter's context, which it owns.
        unsafe { EVP_MD_CTX_free(ctx) };
        object.init.store(0, Ordering::Relaxed);
        1
    }
}

ffi_callback! {
    /// Reads from the next BIO, digesting what comes.
    ///
    /// # Safety
    /// `b` is a live BIO; `out` is NULL or valid for `outl` octets of writes.
    pub(crate) unsafe extern "C" fn md_read(b: *mut BIO, out: *mut c_char, outl: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        if out.is_null() {
            return 0;
        }
        let Some((object, ctx)) = md_ctx(b) else { return 0 };
        let next = object.next();
        if ctx.is_null() || next.is_null() {
            return 0;
        }
        // SAFETY: the next BIO is live; `out` has room for `outl` octets.
        let ret = unsafe { super::BIO_read(next, out.cast(), outl) };
        if object.init.load(Ordering::Relaxed) != 0 && ret > 0 {
            let n = usize::try_from(ret).unwrap_or(0);
            // SAFETY: the filter's context; the `ret` octets just read.
            if unsafe { EVP_DigestUpdate(ctx, out.cast(), n) } <= 0 {
                return -1;
            }
        }
        object.clear_retry_flags();
        super::copy_next_retry(object);
        ret
    }
}

ffi_callback! {
    /// Writes to the next BIO, digesting what it took.
    ///
    /// # Safety
    /// `b` is a live BIO; `data` is NULL or holds `len` octets.
    pub(crate) unsafe extern "C" fn md_write(b: *mut BIO, data: *const c_char, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        if data.is_null() || len <= 0 {
            return 0;
        }
        let Some((object, ctx)) = md_ctx(b) else { return 0 };
        let next = object.next();
        let mut ret = 0;
        if !ctx.is_null() && !next.is_null() {
            // SAFETY: the next BIO is live; `data` holds `len` octets.
            ret = unsafe { super::BIO_write(next, data.cast(), len) };
        }
        if object.init.load(Ordering::Relaxed) != 0 && ret > 0 {
            let n = usize::try_from(ret).unwrap_or(0);
            // SAFETY: the filter's context; the first `ret` of the caller's octets.
            if unsafe { EVP_DigestUpdate(ctx, data.cast(), n) } == 0 {
                object.clear_retry_flags();
                return 0;
            }
        }
        if !next.is_null() {
            object.clear_retry_flags();
            super::copy_next_retry(object);
        }
        ret
    }
}

ffi_callback! {
    /// The digest filter's controls.
    ///
    /// # Safety
    /// `b` is a live BIO; `ptr` is what the command expects.
    pub(crate) unsafe extern "C" fn md_ctrl(b: *mut BIO, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else { return 0 };
        let Some(state) = state::get::<Md>(object) else { return 0 };
        let ctx = lock(&state).ctx.0;
        let next = object.next();
        let init = object.init.load(Ordering::Relaxed) != 0;
        match cmd {
            BIO_CTRL_RESET => {
                let ret = if init {
                    // SAFETY: the filter's context.
                    let md = unsafe { EVP_MD_CTX_get0_md(ctx) };
                    // SAFETY: the filter's context, and its digest.
                    c_long::from(unsafe { EVP_DigestInit_ex(ctx, md, ptr::null_mut()) })
                } else {
                    0
                };
                if ret > 0 { ctrl_next(next, cmd, num, ptr) } else { ret }
            }
            BIO_C_GET_MD => {
                if !init {
                    return 0;
                }
                let out = ptr.cast::<*const EVP_MD>();
                if !out.is_null() {
                    // SAFETY: the filter's context.
                    let md = unsafe { EVP_MD_CTX_get0_md(ctx) };
                    // SAFETY: `ptr` is the caller's `const EVP_MD **`.
                    unsafe { out.write(md) };
                }
                1
            }
            BIO_C_GET_MD_CTX => {
                let out = ptr.cast::<*mut EVP_MD_CTX>();
                if !out.is_null() {
                    // SAFETY: `ptr` is the caller's `EVP_MD_CTX **`.
                    unsafe { out.write(ctx) };
                }
                object.init.store(1, Ordering::Relaxed);
                1
            }
            BIO_C_SET_MD_CTX => {
                if !init {
                    return 0;
                }
                // The filter takes the context, as OpenSSL's does (and keeps the old one,
                // which the application may still hold).
                lock(&state).ctx = Raw(ptr.cast());
                object.ptr.store(ptr, Ordering::Relaxed);
                1
            }
            BIO_C_DO_STATE_MACHINE => {
                object.clear_retry_flags();
                let ret = ctrl_next(next, cmd, num, ptr);
                super::copy_next_retry(object);
                ret
            }
            BIO_C_SET_MD => {
                // SAFETY: the filter's context; `ptr` is the caller's digest.
                let ret = c_long::from(unsafe { EVP_DigestInit_ex(ctx, ptr.cast::<EVP_MD>(), ptr::null_mut()) });
                if ret > 0 {
                    object.init.store(1, Ordering::Relaxed);
                }
                ret
            }
            BIO_CTRL_DUP => {
                // SAFETY: `ptr` is the copy, a live BIO.
                let dctx = unsafe { peek(ptr.cast(), |d: &Md| d.ctx.0) }.unwrap_or(ptr::null_mut());
                // SAFETY: the copy's context and the filter's.
                if unsafe { EVP_MD_CTX_copy_ex(dctx, ctx) } == 0 {
                    return 0;
                }
                // OpenSSL marks this filter, not the copy, initialized.
                object.init.store(1, Ordering::Relaxed);
                1
            }
            _ => ctrl_next(next, cmd, num, ptr),
        }
    }
}

/// `f` of the state of type `T` of the BIO `b`, if it has one.
///
/// # Safety
/// `b` is null or a live BIO.
unsafe fn peek<T: Send + 'static, R>(b: *mut BIO, f: impl FnOnce(&T) -> R) -> Option<R> {
    // SAFETY: the caller's guarantee.
    let object = unsafe { object(b) }?;
    let state = state::get::<T>(object)?;
    let r = f(&lock(&state));
    Some(r)
}

ffi_callback! {
    /// Finishes the digest into `buf`, which must have room for it (`size` at least the
    /// digest's size; 0 if not). Returns the digest's length, or -1 if it can't be finished.
    ///
    /// # Safety
    /// `b` is a live BIO; `buf` is valid for `size` octets of writes.
    pub(crate) unsafe extern "C" fn md_gets(b: *mut BIO, buf: *mut c_char, size: c_int) -> c_int
    where failure = -1, library = ERR_LIB_BIO
    {
        let Some((_, ctx)) = md_ctx(b) else { return 0 };
        // SAFETY: the filter's context.
        if size < unsafe { EVP_MD_CTX_get_size_ex(ctx) } {
            return 0;
        }
        let mut ret: c_uint = 0;
        // SAFETY: the filter's context; `buf` has room for the digest, checked above.
        if unsafe { EVP_DigestFinal_ex(ctx, buf.cast(), &raw mut ret) } <= 0 {
            return -1;
        }
        c_int::try_from(ret).unwrap_or(-1)
    }
}

ffi_callback! {
    /// Passes `BIO_callback_ctrl` to the next BIO.
    ///
    /// # Safety
    /// `b` is a live BIO.
    pub(crate) unsafe extern "C" fn md_callback_ctrl(b: *mut BIO, cmd: c_int, fp: BIO_info_cb) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        callback_ctrl(b, cmd, fp)
    }
}

static MD: Builtin = Builtin::new(BIO_TYPE_MD, c"message digest", || Funcs {
    bgets: Some(md_gets),
    ctrl: Some(md_ctrl),
    create: Some(md_new),
    destroy: Some(md_free),
    callback_ctrl: Some(md_callback_ctrl),
    ..Funcs::classic(md_write, md_read)
});

ffi_export! {
    /// Returns the digest filter's method: digests what passes through it; `BIO_set_md` picks
    /// the digest and `BIO_gets` finishes it.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_f_md() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        MD.get()
    }
}

// The cipher filter.

/// The octets read from the next BIO at a time (`ENC_BLOCK_SIZE`).
const ENC_BLOCK_SIZE: usize = 4096;
/// The most octets decrypted into the filter's buffer at a time (`ENC_MIN_CHUNK`).
const ENC_MIN_CHUNK: usize = 256;
/// Where read octets start in the buffer: past room for a chunk's output (`BUF_OFFSET`).
const BUF_OFFSET: usize = ENC_MIN_CHUNK + EVP_MAX_BLOCK_LENGTH.unsigned_abs() as usize;
/// The buffer: room for a chunk's output, then a block of read octets (or a block's output).
const ENC_BUF: usize = BUF_OFFSET + ENC_BLOCK_SIZE;

/// The cipher filter's state (OpenSSL's `BIO_ENC_CTX`). Lengths and offsets are OpenSSL's
/// `int`s, which its steps can leave with the offset past the length.
struct Enc {
    buf_len: i64,
    buf_off: i64,
    /// Above 0 while more may be read; the next BIO's last result after.
    cont: c_int,
    finished: bool,
    /// 0 after a failed update or final (bad decrypt).
    ok: c_int,
    cipher: Raw<EVP_CIPHER_CTX>,
    read_start: usize,
    read_end: usize,
    buf: Vec<u8>,
}

impl Default for Enc {
    fn default() -> Self {
        Self {
            buf_len: 0,
            buf_off: 0,
            cont: 1,
            finished: false,
            ok: 1,
            cipher: Raw::default(),
            read_start: BUF_OFFSET,
            read_end: BUF_OFFSET,
            buf: Vec::new(),
        }
    }
}

impl Enc {
    /// The buffer's octets from `at` to `end`, empty if out of range.
    fn span(&self, at: i64, end: i64) -> &[u8] {
        let (Ok(a), Ok(e)) = (usize::try_from(at), usize::try_from(end)) else {
            return &[];
        };
        self.buf.get(a..e).unwrap_or(&[])
    }

    /// `EVP_CipherUpdate` of `input` (offsets into the buffer) into the buffer's start,
    /// setting the length.
    fn update_in_place(&mut self, from: usize, len: usize) -> bool {
        let mut outl: c_int = 0;
        let base = self.buf.as_mut_ptr();
        if from.saturating_add(len) > self.buf.len()
            || len.saturating_add(EVP_MAX_BLOCK_LENGTH.unsigned_abs() as usize) > from
        {
            return false;
        }
        // SAFETY: the filter's cipher context; the input lies in the buffer from `from`, and
        // the output (at most a block more than the input) fits before it, as checked.
        let ok = unsafe {
            EVP_CipherUpdate(
                self.cipher.0,
                base,
                &raw mut outl,
                base.wrapping_add(from),
                int(len),
            )
        };
        self.buf_len = i64::from(outl);
        ok != 0
    }

    /// `EVP_CipherUpdate` of `input` into the buffer's start, setting the length.
    fn update_from(&mut self, input: &[u8]) -> bool {
        let mut outl: c_int = 0;
        // SAFETY: the filter's cipher context; at most a block of input's output, which the
        // buffer has room for past the input's length (at most `ENC_BLOCK_SIZE`).
        let ok = unsafe {
            EVP_CipherUpdate(
                self.cipher.0,
                self.buf.as_mut_ptr(),
                &raw mut outl,
                input.as_ptr(),
                int(input.len()),
            )
        };
        self.buf_len = i64::from(outl);
        ok != 0
    }

    /// `EVP_CipherFinal_ex` into the buffer's start, setting the length; the result.
    fn finish(&mut self) -> c_int {
        let mut outl: c_int = 0;
        // SAFETY: the filter's cipher context; at most a block of output.
        let ret =
            unsafe { EVP_CipherFinal_ex(self.cipher.0, self.buf.as_mut_ptr(), &raw mut outl) };
        self.buf_len = i64::from(outl);
        ret
    }
}

ffi_callback! {
    /// Makes a cipher filter's state and context.
    ///
    /// # Safety
    /// `b` is a live BIO.
    pub(crate) unsafe extern "C" fn enc_new(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else { return 0 };
        let Some(buf) = state::zeroed(ENC_BUF) else { return 0 };
        // SAFETY: no preconditions.
        let cipher = unsafe { EVP_CIPHER_CTX_new() };
        if cipher.is_null() {
            return 0;
        }
        state::install(object, Enc { cipher: Raw(cipher), buf, ..Enc::default() });
        object.init.store(1, Ordering::Relaxed);
        1
    }
}

ffi_callback! {
    /// Frees a cipher filter's state and context.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn enc_free(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else { return 0 };
        let Some(state) = state::remove::<Enc>(object) else { return 0 };
        let mut st = core::mem::take(&mut *lock(&state));
        // SAFETY: the filter's context, which it owns.
        unsafe { EVP_CIPHER_CTX_free(st.cipher.0) };
        wipe(&mut st.buf);
        object.init.store(0, Ordering::Relaxed);
        1
    }
}

/// `enc_read`: decrypts (or encrypts) from the next BIO into `out`.
fn enc_read_body(object: &super::Bio, st: &mut Enc, out: &mut [u8]) -> c_int {
    let next = object.next();
    if next.is_null() || st.cipher.0.is_null() {
        return 0;
    }
    let mut ret: i64 = 0;
    let mut pos = 0usize;
    let mut outl = i64::try_from(out.len()).unwrap_or(0);
    let copy = |out: &mut [u8], pos: usize, src: &[u8]| {
        for (d, s) in out.iter_mut().skip(pos).zip(src) {
            *d = *s;
        }
    };
    if st.buf_len > 0 {
        let i = (st.buf_len - st.buf_off).min(outl).max(0);
        copy(out, pos, st.span(st.buf_off, st.buf_off + i));
        ret = i;
        pos = pos.saturating_add(usize::try_from(i).unwrap_or(0));
        outl -= i;
        st.buf_off += i;
        if st.buf_len == st.buf_off {
            st.buf_len = 0;
            st.buf_off = 0;
        }
    }
    // SAFETY: the filter's cipher context.
    let mut blocksize = i64::from(unsafe { EVP_CIPHER_CTX_get_block_size(st.cipher.0) });
    if blocksize == 0 {
        return 0;
    }
    if blocksize == 1 {
        blocksize = 0;
    }
    let min_chunk = i64::try_from(ENC_MIN_CHUNK).unwrap_or(0);
    while outl > 0 {
        if st.cont <= 0 {
            break;
        }
        let mut i: i64;
        if st.read_start == st.read_end {
            st.read_start = BUF_OFFSET;
            st.read_end = BUF_OFFSET;
            let at = st.buf.as_mut_ptr().wrapping_add(BUF_OFFSET);
            i = i64::from(read_next(next, at, ENC_BLOCK_SIZE));
            if i > 0 {
                st.read_end = st.read_end.saturating_add(usize::try_from(i).unwrap_or(0));
            }
        } else {
            i = i64::try_from(st.read_end.saturating_sub(st.read_start)).unwrap_or(0);
        }
        if i <= 0 {
            if should_retry(next) {
                if ret == 0 {
                    ret = i;
                }
                break;
            }
            st.cont = c_int::try_from(i).unwrap_or(-1);
            st.finished = true;
            st.ok = st.finish();
            st.buf_off = 0;
        } else {
            if outl > min_chunk {
                // Decrypt straight into the caller's buffer, leaving a block of room.
                let j = outl - blocksize;
                let take = usize::try_from(i.min(j)).unwrap_or(0);
                let Some(input) = st
                    .buf
                    .get(st.read_start..st.read_start.saturating_add(take))
                else {
                    return 0;
                };
                let mut scratch =
                    vec![
                        0u8;
                        take.saturating_add(2 * EVP_MAX_BLOCK_LENGTH.unsigned_abs() as usize)
                    ];
                let mut produced: c_int = 0;
                // SAFETY: the filter's cipher context; `scratch` has room for the input's
                // output and more.
                let ok = unsafe {
                    EVP_CipherUpdate(
                        st.cipher.0,
                        scratch.as_mut_ptr(),
                        &raw mut produced,
                        input.as_ptr(),
                        int(take),
                    )
                };
                if ok == 0 {
                    object.clear_retry_flags();
                    wipe(&mut scratch);
                    return 0;
                }
                let produced = i64::from(produced).clamp(0, outl);
                copy(
                    out,
                    pos,
                    scratch
                        .get(..usize::try_from(produced).unwrap_or(0))
                        .unwrap_or(&[]),
                );
                wipe(&mut scratch);
                ret += produced;
                pos = pos.saturating_add(usize::try_from(produced).unwrap_or(0));
                outl -= produced;
                i -= j;
                if i <= 0 {
                    st.read_start = st.read_end;
                    continue;
                }
                st.read_start = st
                    .read_start
                    .saturating_add(usize::try_from(j).unwrap_or(0));
            }
            if i > min_chunk {
                i = min_chunk;
            }
            let n = usize::try_from(i).unwrap_or(0);
            if !st.update_in_place(st.read_start, n) {
                object.clear_retry_flags();
                st.ok = 0;
                return 0;
            }
            st.read_start = st.read_start.saturating_add(n);
            st.cont = 1;
            if st.buf_len == 0 {
                continue;
            }
        }
        let i = st.buf_len.min(outl);
        if i <= 0 {
            break;
        }
        copy(out, pos, st.span(0, i));
        ret += i;
        st.buf_off = i;
        outl -= i;
        pos = pos.saturating_add(usize::try_from(i).unwrap_or(0));
    }
    object.clear_retry_flags();
    super::copy_next_retry(object);
    if ret == 0 {
        st.cont
    } else {
        c_int::try_from(ret).unwrap_or(c_int::MAX)
    }
}

ffi_callback! {
    /// Reads through the cipher.
    ///
    /// # Safety
    /// `b` is a live BIO; `out` is NULL or valid for `outl` octets of writes.
    pub(crate) unsafe extern "C" fn enc_read(b: *mut BIO, out: *mut c_char, outl: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        if out.is_null() {
            return 0;
        }
        let len = usize::try_from(outl).unwrap_or(0);
        // SAFETY: the caller's guarantee.
        let out = unsafe { core::slice::from_raw_parts_mut(out.cast::<u8>(), len) };
        with_state(b, 0, |object, st: &mut Enc| enc_read_body(object, st, out))
    }
}

/// `enc_write`: writes what is pending, then encrypts (or decrypts) `input` (none: only the
/// pending octets) to the next BIO.
fn enc_write_body(object: &super::Bio, st: &mut Enc, input: Option<&[u8]>) -> c_int {
    let next = object.next();
    if next.is_null() || st.cipher.0.is_null() {
        return 0;
    }
    let total = input.map_or(0, |i| i64::try_from(i.len()).unwrap_or(0));
    object.clear_retry_flags();
    while st.buf_len - st.buf_off > 0 {
        let i = write_next(next, st.span(st.buf_off, st.buf_len));
        if i <= 0 {
            super::copy_next_retry(object);
            return i;
        }
        st.buf_off += i64::from(i);
    }
    let Some(mut input) = input.filter(|i| !i.is_empty()) else {
        return 0;
    };
    st.buf_off = 0;
    let mut inl = total;
    while inl > 0 {
        let (chunk, rest) = input.split_at(input.len().min(ENC_BLOCK_SIZE));
        if !st.update_from(chunk) {
            object.clear_retry_flags();
            st.ok = 0;
            return 0;
        }
        inl -= i64::try_from(chunk.len()).unwrap_or(0);
        input = rest;
        st.buf_off = 0;
        while st.buf_len - st.buf_off > 0 {
            let i = write_next(next, st.span(st.buf_off, st.buf_len));
            if i <= 0 {
                super::copy_next_retry(object);
                return if total == inl {
                    i
                } else {
                    c_int::try_from(total - inl).unwrap_or(c_int::MAX)
                };
            }
            st.buf_off += i64::from(i);
        }
        st.buf_len = 0;
        st.buf_off = 0;
    }
    super::copy_next_retry(object);
    c_int::try_from(total).unwrap_or(c_int::MAX)
}

ffi_callback! {
    /// Writes through the cipher.
    ///
    /// # Safety
    /// `b` is a live BIO; `data` is NULL or holds `len` octets.
    pub(crate) unsafe extern "C" fn enc_write(b: *mut BIO, data: *const c_char, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        let input = match usize::try_from(len) {
            // SAFETY: the caller's guarantee.
            Ok(n) if n > 0 && !data.is_null() => Some(unsafe { core::slice::from_raw_parts(data.cast::<u8>(), n) }),
            _ => None,
        };
        with_state(b, 0, |object, st: &mut Enc| enc_write_body(object, st, input))
    }
}

/// `BIO_CTRL_FLUSH`: writes what is pending, finishes the cipher and writes that, then flushes
/// the next BIO.
fn enc_flush(
    object: &super::Bio,
    st: &mut Enc,
    cmd: c_int,
    num: c_long,
    ptr: *mut c_void,
) -> c_long {
    loop {
        while st.buf_len != st.buf_off {
            let pend = st.buf_len - st.buf_off;
            let i = enc_write_body(object, st, None);
            if i < 0 || st.buf_len - st.buf_off == pend {
                return c_long::from(i);
            }
        }
        if st.finished {
            break;
        }
        st.finished = true;
        st.buf_off = 0;
        let ret = st.finish();
        st.ok = ret;
        if ret <= 0 {
            return c_long::from(ret);
        }
    }
    let ret = ctrl_next(object.next(), cmd, num, ptr);
    super::copy_next_retry(object);
    ret
}

ffi_callback! {
    /// The cipher filter's controls.
    ///
    /// # Safety
    /// `b` is a live BIO; `ptr` is what the command expects.
    pub(crate) unsafe extern "C" fn enc_ctrl(b: *mut BIO, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        with_state(b, 0, |object, st: &mut Enc| {
            let next = object.next();
            let cipher = st.cipher.0;
            match cmd {
                BIO_CTRL_RESET => {
                    st.ok = 1;
                    st.finished = false;
                    // SAFETY: the filter's cipher context.
                    let enc = unsafe { EVP_CIPHER_CTX_is_encrypting(cipher) };
                    // SAFETY: as above; no new cipher, key, or IV.
                    if unsafe { EVP_CipherInit_ex(cipher, ptr::null(), ptr::null_mut(), ptr::null(), ptr::null(), enc) } == 0 {
                        return 0;
                    }
                    ctrl_next(next, cmd, num, ptr)
                }
                BIO_CTRL_EOF => {
                    if st.cont <= 0 { 1 } else { ctrl_next(next, cmd, num, ptr) }
                }
                BIO_CTRL_WPENDING | BIO_CTRL_PENDING => {
                    let ret = st.buf_len - st.buf_off;
                    if ret <= 0 { ctrl_next(next, cmd, num, ptr) } else { c_long::try_from(ret).unwrap_or(c_long::MAX) }
                }
                BIO_CTRL_FLUSH => enc_flush(object, st, cmd, num, ptr),
                BIO_C_GET_CIPHER_STATUS => c_long::from(st.ok),
                BIO_C_DO_STATE_MACHINE => {
                    object.clear_retry_flags();
                    let ret = ctrl_next(next, cmd, num, ptr);
                    super::copy_next_retry(object);
                    ret
                }
                BIO_C_GET_CIPHER_CTX => {
                    let out = ptr.cast::<*mut EVP_CIPHER_CTX>();
                    if !out.is_null() {
                        // SAFETY: `ptr` is the caller's `EVP_CIPHER_CTX **`.
                        unsafe { out.write(cipher) };
                    }
                    object.init.store(1, Ordering::Relaxed);
                    1
                }
                BIO_CTRL_DUP => {
                    let dbio = ptr.cast::<BIO>();
                    // SAFETY: `ptr` is the copy, a live BIO.
                    let dcipher = unsafe { peek(dbio, |d: &Enc| d.cipher.0) }.unwrap_or(ptr::null_mut());
                    // SAFETY: the copy's context and the filter's.
                    let ret = unsafe { EVP_CIPHER_CTX_copy(dcipher, cipher) };
                    if ret != 0 {
                        // SAFETY: as above.
                        if let Some(d) = unsafe { super::object(dbio) } {
                            d.init.store(1, Ordering::Relaxed);
                        }
                    }
                    c_long::from(ret)
                }
                _ => ctrl_next(next, cmd, num, ptr),
            }
        })
    }
}

ffi_callback! {
    /// Passes `BIO_callback_ctrl` to the next BIO.
    ///
    /// # Safety
    /// `b` is a live BIO.
    pub(crate) unsafe extern "C" fn enc_callback_ctrl(b: *mut BIO, cmd: c_int, fp: BIO_info_cb) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        callback_ctrl(b, cmd, fp)
    }
}

static CIPHER: Builtin = Builtin::new(BIO_TYPE_CIPHER, c"cipher", || Funcs {
    ctrl: Some(enc_ctrl),
    create: Some(enc_new),
    destroy: Some(enc_free),
    callback_ctrl: Some(enc_callback_ctrl),
    ..Funcs::classic(enc_write, enc_read)
});

ffi_export! {
    /// Returns the cipher filter's method: encrypts or decrypts what passes through it, as
    /// `BIO_set_cipher` sets it up; `BIO_flush` finishes a write.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_f_cipher() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        CIPHER.get()
    }
}

ffi_export! {
    /// Sets up a cipher filter: `EVP_CipherInit_ex` of its context with the cipher `c`, key
    /// `k`, IV `i`, and direction `e` (1 to encrypt), calling the BIO's callback before (as a
    /// `BIO_CTRL_SET` control; nothing is done if it returns 0 or less) and after (its result
    /// is the result). Returns 1, or 0 on failure.
    ///
    /// # Safety
    /// `b` is a live BIO; `c`, `k`, and `i` are what `EVP_CipherInit_ex` takes.
    pub unsafe extern "C" fn BIO_set_cipher(b: *mut BIO, c: *const EVP_CIPHER, k: *const u8, i: *const u8, e: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else { return 0 };
        let Some(state) = state::get::<Enc>(object) else { return 0 };
        let cipher = lock(&state).cipher.0;
        // SAFETY: the caller's BIO.
        let callback_ex = unsafe { super::BIO_get_callback_ex(b) };
        // SAFETY: as above.
        let callback = if callback_ex.is_none() { unsafe { super::BIO_get_callback(b) } } else { None };
        let argp = c.cast::<c_char>();
        if let Some(cb) = callback_ex {
            // SAFETY: the application's callback takes these arguments.
            if unsafe { cb(b, BIO_CB_CTRL, argp, 0, BIO_CTRL_SET, c_long::from(e), 1, ptr::null_mut()) } <= 0 {
                return 0;
            }
        } else if let Some(cb) = callback {
            // SAFETY: as above.
            if unsafe { cb(b, BIO_CB_CTRL, argp, BIO_CTRL_SET, c_long::from(e), 0) } <= 0 {
                return 0;
            }
        }
        object.init.store(1, Ordering::Relaxed);
        // SAFETY: the filter's cipher context; the caller's cipher, key, and IV.
        if unsafe { EVP_CipherInit_ex(cipher, c, ptr::null_mut(), k, i, e) } == 0 {
            return 0;
        }
        if let Some(cb) = callback_ex {
            // SAFETY: as above.
            let r = unsafe { cb(b, BIO_CB_CTRL | BIO_CB_RETURN, argp, 0, BIO_CTRL_SET, c_long::from(e), 1, ptr::null_mut()) };
            return super::wrap_int(r);
        }
        if let Some(cb) = callback {
            // SAFETY: as above.
            let r = unsafe { cb(b, BIO_CB_CTRL, argp, BIO_CTRL_SET, c_long::from(e), 1) };
            return super::wrap_int(r);
        }
        1
    }
}

// The reliable filter.

/// The size of a block's content (`OK_BLOCK_SIZE`).
const OK_BLOCK_SIZE: usize = 4096;
/// The size of a block's length header (`OK_BLOCK_BLOCK`).
const OK_BLOCK_BLOCK: usize = 4;
/// The buffer: a block, its header, and room for digests (`IOBS`).
const IOBS: usize = OK_BLOCK_SIZE + OK_BLOCK_BLOCK + 3 * EVP_MAX_MD_SIZE.unsigned_abs() as usize;

/// The reliable filter's state (OpenSSL's `BIO_OK_CTX`). The signature step never completes
/// (see the module's notes), so no block is ever read or written, and none is ever ready to
/// go out (OpenSSL's `blockout`).
struct Reliable {
    buf_len: usize,
    buf_off: usize,
    cont: c_int,
    md: Raw<EVP_MD_CTX>,
    /// The signature (the seed and its digest) must be sent or checked first.
    sigio: bool,
    buf: Vec<u8>,
}

impl Default for Reliable {
    fn default() -> Self {
        Self {
            buf_len: 0,
            buf_off: 0,
            cont: 1,
            md: Raw::default(),
            sigio: true,
            buf: Vec::new(),
        }
    }
}

impl Reliable {
    /// The digest's size (0 or less without one).
    fn md_size(&self) -> c_int {
        // SAFETY: the filter's context.
        let digest = unsafe { EVP_MD_CTX_get0_md(self.md.0) };
        // SAFETY: the context's digest, or NULL.
        unsafe { EVP_MD_get_size(digest) }
    }

    /// Starts the digest again for the seed, as OpenSSL does, then needs its legacy state,
    /// which provided digests don't have: `false` where OpenSSL writes or reads through NULL.
    fn seed_step(&mut self) -> bool {
        // SAFETY: the filter's context and its digest.
        let digest = unsafe { EVP_MD_CTX_get0_md(self.md.0) };
        // SAFETY: as above.
        if unsafe { EVP_DigestInit_ex(self.md.0, digest, ptr::null_mut()) } == 0 {
            return false;
        }
        // rustyssl's digests have no legacy state (`EVP_MD_CTX_get0_md_data` is NULL), where
        // OpenSSL writes or reads the seed; application-defined digests (step 3.11) could have
        // one, and the protocol would go on from here.
        // SAFETY: the filter's context.
        let md_data = unsafe { EVP_MD_CTX_get0_md_data(self.md.0) };
        debug_assert!(md_data.is_null());
        false
    }

    /// `sig_out`: makes the signature to send first. `false` on failure.
    fn sig_out(&mut self) -> bool {
        let Ok(md_size) = usize::try_from(self.md_size()) else {
            return false;
        };
        if md_size == 0 {
            return false;
        }
        if self.buf_len.saturating_add(2 * md_size) > OK_BLOCK_SIZE {
            return true;
        }
        self.seed_step()
    }

    /// `sig_in`: checks the signature once it has come in. `false` on failure.
    fn sig_in(&mut self) -> bool {
        if self.md.0.is_null() {
            return false;
        }
        let Ok(md_size) = usize::try_from(self.md_size()) else {
            return false;
        };
        if md_size == 0 {
            return false;
        }
        if self.buf_len.saturating_sub(self.buf_off) < 2 * md_size {
            return true;
        }
        self.seed_step()
    }
}

ffi_callback! {
    /// Makes a reliable filter's state and digest context; it isn't initialized until
    /// `BIO_set_md`.
    ///
    /// # Safety
    /// `b` is a live BIO.
    pub(crate) unsafe extern "C" fn ok_new(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else { return 0 };
        let Some(buf) = state::zeroed(IOBS) else { return 0 };
        // SAFETY: no preconditions.
        let md = unsafe { EVP_MD_CTX_new() };
        if md.is_null() {
            return 0;
        }
        state::install(object, Reliable { md: Raw(md), buf, ..Reliable::default() });
        object.init.store(0, Ordering::Relaxed);
        1
    }
}

ffi_callback! {
    /// Frees a reliable filter's state and context.
    ///
    /// # Safety
    /// `b` is null or a live BIO.
    pub(crate) unsafe extern "C" fn ok_free(b: *mut BIO) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        // SAFETY: the caller's guarantee.
        let Some(object) = (unsafe { object(b) }) else { return 0 };
        let Some(state) = state::remove::<Reliable>(object) else { return 0 };
        let mut st = core::mem::take(&mut *lock(&state));
        // SAFETY: the filter's context, which it owns.
        unsafe { EVP_MD_CTX_free(st.md.0) };
        wipe(&mut st.buf);
        object.init.store(0, Ordering::Relaxed);
        1
    }
}

/// `ok_read`: reads from the next BIO until the signature can be checked (which fails).
fn ok_read_body(object: &super::Bio, st: &mut Reliable, outl: usize) -> c_int {
    let next = object.next();
    if next.is_null() || object.init.load(Ordering::Relaxed) == 0 {
        return 0;
    }
    if outl > 0 {
        loop {
            let room = st.buf.len().saturating_sub(st.buf_len);
            let at = st.buf.as_mut_ptr().wrapping_add(st.buf_len);
            let i = read_next(next, at, room);
            if i <= 0 {
                break;
            }
            st.buf_len = st.buf_len.saturating_add(usize::try_from(i).unwrap_or(0));
            if st.sigio && !st.sig_in() {
                object.clear_retry_flags();
                return 0;
            }
            if st.cont <= 0 {
                break;
            }
        }
    }
    object.clear_retry_flags();
    super::copy_next_retry(object);
    0
}

ffi_callback! {
    /// Reads through the filter: never past the signature (see the module's notes).
    ///
    /// # Safety
    /// `b` is a live BIO; `out` is NULL or valid for `outl` octets of writes.
    pub(crate) unsafe extern "C" fn ok_read(b: *mut BIO, out: *mut c_char, outl: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        if out.is_null() {
            return 0;
        }
        let len = usize::try_from(outl).unwrap_or(0);
        with_state(b, 0, |object, st: &mut Reliable| ok_read_body(object, st, len))
    }
}

ffi_callback! {
    /// Writes through the filter: the signature must go first, which fails (see the module's
    /// notes).
    ///
    /// # Safety
    /// `b` is a live BIO; `data` is NULL or holds `len` octets.
    pub(crate) unsafe extern "C" fn ok_write(b: *mut BIO, data: *const c_char, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_BIO
    {
        if len <= 0 {
            return len;
        }
        let _ = data;
        with_state(b, 0, |object, st: &mut Reliable| {
            if object.next().is_null() || object.init.load(Ordering::Relaxed) == 0 {
                return 0;
            }
            if st.sigio && !st.sig_out() {
                object.clear_retry_flags();
                return 0;
            }
            // `sig_out` only succeeds by waiting for room, which an empty buffer has.
            object.clear_retry_flags();
            0
        })
    }
}

ffi_callback! {
    /// The reliable filter's controls.
    ///
    /// # Safety
    /// `b` is a live BIO; `ptr` is what the command expects.
    pub(crate) unsafe extern "C" fn ok_ctrl(b: *mut BIO, cmd: c_int, num: c_long, ptr: *mut c_void) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        with_state(b, 0, |object, st: &mut Reliable| {
            let next = object.next();
            match cmd {
                BIO_CTRL_RESET => {
                    st.buf_len = 0;
                    st.buf_off = 0;
                    st.cont = 1;
                    st.sigio = true;
                    ctrl_next(next, cmd, num, ptr)
                }
                BIO_CTRL_EOF => {
                    if st.cont <= 0 { 1 } else { ctrl_next(next, cmd, num, ptr) }
                }
                BIO_CTRL_PENDING | BIO_CTRL_WPENDING => {
                    // No block is ever ready, so OpenSSL's count of one is 0 and it asks the next.
                    ctrl_next(next, cmd, num, ptr)
                }
                BIO_CTRL_FLUSH => {
                    // OpenSSL frames what is buffered as a block, which fails without a digest
                    // and with less than a block's header buffered (its length underflows),
                    // and otherwise loops without end writing the block out; it never gets
                    // past that (writes never buffer anything, see the module's notes). It
                    // asks the digest's size first, which raises an error without one.
                    let _ = st.md_size();
                    object.clear_retry_flags();
                    0
                }
                BIO_C_DO_STATE_MACHINE => {
                    object.clear_retry_flags();
                    let ret = ctrl_next(next, cmd, num, ptr);
                    super::copy_next_retry(object);
                    ret
                }
                BIO_CTRL_INFO => c_long::from(st.cont),
                BIO_C_SET_MD => {
                    // SAFETY: the filter's context; `ptr` is the caller's digest.
                    if unsafe { EVP_DigestInit_ex(st.md.0, ptr.cast::<EVP_MD>(), ptr::null_mut()) } == 0 {
                        return 0;
                    }
                    object.init.store(1, Ordering::Relaxed);
                    1
                }
                BIO_C_GET_MD => {
                    if object.init.load(Ordering::Relaxed) == 0 {
                        return 0;
                    }
                    let out = ptr.cast::<*const EVP_MD>();
                    if !out.is_null() {
                        // SAFETY: the filter's context.
                        let md = unsafe { EVP_MD_CTX_get0_md(st.md.0) };
                        // SAFETY: `ptr` is the caller's `const EVP_MD **`.
                        unsafe { out.write(md) };
                    }
                    1
                }
                _ => ctrl_next(next, cmd, num, ptr),
            }
        })
    }
}

ffi_callback! {
    /// Passes `BIO_callback_ctrl` to the next BIO.
    ///
    /// # Safety
    /// `b` is a live BIO.
    pub(crate) unsafe extern "C" fn ok_callback_ctrl(b: *mut BIO, cmd: c_int, fp: BIO_info_cb) -> c_long
    where failure = 0, library = ERR_LIB_BIO
    {
        callback_ctrl(b, cmd, fp)
    }
}

static RELIABLE: Builtin = Builtin::new(BIO_TYPE_CIPHER, c"reliable", || Funcs {
    ctrl: Some(ok_ctrl),
    create: Some(ok_new),
    destroy: Some(ok_free),
    callback_ctrl: Some(ok_callback_ctrl),
    ..Funcs::classic(ok_write, ok_read)
});

ffi_export! {
    /// Returns the reliable filter's method: OpenSSL's framing of blocks with a digest each,
    /// after a signature. Its writes, reads, and flushes fail once a digest is set, where
    /// OpenSSL 3 crashes (see the module's notes).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn BIO_f_reliable() -> *const BIO_METHOD
    where failure = ptr::null(), library = ERR_LIB_BIO
    {
        RELIABLE.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bio::mem::BIO_s_mem;
    use crate::bio::{
        BIO_ctrl, BIO_ctrl_pending, BIO_free_all, BIO_new, BIO_push, BIO_read, BIO_write,
    };
    use crate::evp::legacy_md::EVP_sha256;

    /// A reliable filter with SHA-256, over a memory BIO holding `data`.
    fn reliable(data: &[u8]) -> (*mut BIO, *mut BIO) {
        // SAFETY: the built-in methods.
        let ok = unsafe { BIO_new(RELIABLE.get()) };
        // SAFETY: no preconditions.
        let method = unsafe { BIO_s_mem() };
        // SAFETY: the built-in method.
        let mem = unsafe { BIO_new(method) };
        // SAFETY: live BIOs; the chain owns the memory BIO.
        unsafe { BIO_push(ok, mem) };
        // SAFETY: no preconditions.
        let md = unsafe { EVP_sha256() };
        // SAFETY: a live BIO; the built-in digest.
        let set = unsafe { BIO_ctrl(ok, BIO_C_SET_MD, 0, md.cast_mut().cast()) };
        assert_eq!(set, 1);
        if !data.is_empty() {
            // SAFETY: a live BIO; `data`'s octets.
            let w = unsafe { BIO_write(mem, data.as_ptr().cast(), int(data.len())) };
            assert_eq!(w, int(data.len()));
        }
        (ok, mem)
    }

    /// docs/DEVIATIONS.md: with a digest set, the reliable filter's writes fail where OpenSSL
    /// writes its seed through NULL and crashes, and nothing reaches the next BIO.
    #[test]
    #[cfg_attr(miri, ignore = "sets a digest, which loads the configuration")]
    fn reliable_writes_fail() {
        let (ok, mem) = reliable(&[]);
        // SAFETY: a live chain; 5 octets.
        let w = unsafe { BIO_write(ok, c"hello".as_ptr().cast(), 5) };
        assert_eq!(w, 0);
        // SAFETY: a live BIO.
        assert_eq!(unsafe { BIO_ctrl_pending(mem) }, 0);
        // SAFETY: the chain.
        unsafe { BIO_free_all(ok) };
    }

    /// docs/DEVIATIONS.md: a read fails once the seed has come in (OpenSSL copies it through
    /// NULL), and so does a flush: with nothing buffered (OpenSSL's length underflows) or after
    /// such a read (OpenSSL loops without end).
    #[test]
    #[cfg_attr(miri, ignore = "sets a digest, which loads the configuration")]
    fn reliable_reads_and_flushes_fail() {
        let (ok, _) = reliable(&[7; 300]);
        let mut out = [0u8; 64];
        // SAFETY: a live chain; room for 64 octets.
        let r = unsafe { BIO_read(ok, out.as_mut_ptr().cast(), 64) };
        assert_eq!(r, 0);
        // SAFETY: a live chain.
        let f = unsafe { BIO_ctrl(ok, BIO_CTRL_FLUSH, 0, ptr::null_mut()) };
        assert_eq!(f, 0);
        // SAFETY: the chain.
        unsafe { BIO_free_all(ok) };
        let (ok, _) = reliable(&[]);
        // SAFETY: a live chain.
        let f = unsafe { BIO_ctrl(ok, BIO_CTRL_FLUSH, 0, ptr::null_mut()) };
        assert_eq!(f, 0);
        // SAFETY: the chain.
        unsafe { BIO_free_all(ok) };
    }
}
