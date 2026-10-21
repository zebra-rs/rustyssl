//! `BIO`s: owned chains, reads and writes over slices.

use core::ffi::c_int;
use std::io;

use crate::abi::{BIO, BIO_CLOSE, BIO_CTRL_FLUSH, BIO_CTRL_PENDING, BIO_CTRL_RESET, BIO_NOCLOSE};
use crate::ffi;
use crate::util::cstring;

/// An owned `BIO` chain, freed with `BIO_free_all`.
pub struct Bio(core::ptr::NonNull<BIO>);

impl Bio {
    /// Takes ownership of `p`; `None` for NULL.
    pub fn from_ptr(p: *mut BIO) -> Option<Self> {
        core::ptr::NonNull::new(p).map(Self)
    }

    /// The `BIO`, for the C API (it stays owned by `self`).
    pub fn as_ptr(&self) -> *mut BIO {
        self.0.as_ptr()
    }

    /// Gives up ownership.
    pub fn into_ptr(self) -> *mut BIO {
        let p = self.0.as_ptr();
        core::mem::forget(self);
        p
    }

    /// `BIO_new_fd(fd, close ? BIO_CLOSE : BIO_NOCLOSE)`.
    pub fn new_fd(fd: c_int, close: bool) -> Option<Self> {
        let flags = if close { BIO_CLOSE } else { BIO_NOCLOSE };
        // SAFETY: BIO_new_fd takes any fd and flag value; it doesn't touch the fd until used.
        Self::from_ptr(unsafe { ffi::BIO_new_fd(fd, flags) })
    }

    /// `BIO_new_file(name, mode)`.
    pub fn new_file(name: &str, mode: &str) -> Option<Self> {
        let (n, m) = (cstring(name)?, cstring(mode)?);
        // SAFETY: both arguments are valid C strings for the call's duration.
        Self::from_ptr(unsafe { ffi::BIO_new_file(n.as_ptr(), m.as_ptr()) })
    }

    /// `BIO_new(BIO_s_mem())`.
    pub fn new_mem() -> Option<Self> {
        // SAFETY: no arguments; the result is a static method table.
        let method = unsafe { ffi::BIO_s_mem() };
        // SAFETY: method is a valid method table.
        Self::from_ptr(unsafe { ffi::BIO_new(method) })
    }

    /// A read-only memory `BIO` holding a copy of `data`.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let b = Self::new_mem()?;
        b.write_all(data).ok()?;
        Some(b)
    }

    /// `BIO_write`: what it returns (bytes written, or <= 0).
    pub fn write(&self, data: &[u8]) -> c_int {
        let Ok(n) = c_int::try_from(data.len()) else {
            return -1;
        };
        // SAFETY: data is valid for n bytes; the BIO is live.
        unsafe { ffi::BIO_write(self.as_ptr(), data.as_ptr().cast(), n) }
    }

    /// Writes all of `data`, in chunks that fit an `int`.
    pub fn write_all(&self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            let chunk = data.get(..data.len().min(1 << 30)).unwrap_or(data);
            let n = self.write(chunk);
            let Ok(n) = usize::try_from(n) else {
                return Err(io::Error::other("BIO_write failed"));
            };
            if n == 0 {
                return Err(io::Error::other("BIO_write wrote nothing"));
            }
            data = data.get(n..).unwrap_or_default();
        }
        Ok(())
    }

    /// `BIO_new(BIO_f_buffer())`.
    pub fn new_buffer() -> Option<Self> {
        // SAFETY: no arguments; the result is a static method table.
        let method = unsafe { ffi::BIO_f_buffer() };
        // SAFETY: method is a valid method table.
        Self::from_ptr(unsafe { ffi::BIO_new(method) })
    }

    /// `BIO_gets(bio, buf, size)`: what it returns, and the line read (up to `size - 1`
    /// bytes, with its newline).
    pub fn gets(&self, size: usize) -> (c_int, Vec<u8>) {
        let mut buf = vec![0u8; size.max(1)];
        let n = c_int::try_from(buf.len()).unwrap_or(c_int::MAX);
        // SAFETY: buf is writable for n bytes; the BIO is live.
        let r = unsafe { ffi::BIO_gets(self.as_ptr(), buf.as_mut_ptr().cast(), n) };
        let len = buf.iter().position(|&b| b == 0).unwrap_or(0);
        buf.truncate(if r > 0 { len } else { 0 });
        (r, buf)
    }

    /// `BIO_read` into `buf`: what it returns.
    pub fn read(&self, buf: &mut [u8]) -> c_int {
        let n = c_int::try_from(buf.len()).unwrap_or(c_int::MAX);
        // SAFETY: buf is valid for writing n bytes; the BIO is live.
        unsafe { ffi::BIO_read(self.as_ptr(), buf.as_mut_ptr().cast(), n) }
    }

    /// Reads to the end (or the first error).
    pub fn read_to_end(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = self.read(&mut buf);
            match usize::try_from(n) {
                Ok(n) if n > 0 => out.extend_from_slice(buf.get(..n).unwrap_or_default()),
                _ => break,
            }
        }
        out
    }

    fn ctrl(&self, cmd: c_int) -> core::ffi::c_long {
        // SAFETY: these commands take no pointer argument; the BIO is live.
        unsafe { ffi::BIO_ctrl(self.as_ptr(), cmd, 0, core::ptr::null_mut()) }
    }

    /// `BIO_flush`.
    pub fn flush(&self) -> bool {
        self.ctrl(BIO_CTRL_FLUSH) > 0
    }

    /// `BIO_reset`.
    pub fn reset(&self) -> bool {
        self.ctrl(BIO_CTRL_RESET) >= 0
    }

    /// `BIO_pending`.
    pub fn pending(&self) -> usize {
        usize::try_from(self.ctrl(BIO_CTRL_PENDING)).unwrap_or(0)
    }

    /// `BIO_push(self, next)`: the chain, `self` first.
    pub fn push(self, next: Bio) -> Bio {
        // SAFETY: both BIOs are live; the chain (owned by self) now owns next.
        unsafe { ffi::BIO_push(self.as_ptr(), next.into_ptr()) };
        self
    }
}

impl Drop for Bio {
    fn drop(&mut self) {
        // SAFETY: the chain is owned by self and freed exactly once, here.
        unsafe { ffi::BIO_free_all(self.as_ptr()) };
    }
}

impl io::Write for &Bio {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Bio::flush(self);
        Ok(())
    }
}

impl Bio {
    /// `BIO_set_mem_eof_return(bio, v)`.
    pub fn set_mem_eof_return(&self, v: core::ffi::c_long) {
        // SAFETY: a memory BIO's command with no pointer argument; the BIO is live.
        unsafe {
            ffi::BIO_ctrl(
                self.as_ptr(),
                crate::abi::BIO_C_SET_BUF_MEM_EOF_RETURN,
                v,
                core::ptr::null_mut(),
            )
        };
    }

    /// `BIO_dump(bio, data, len)`.
    pub fn dump(&self, data: &[u8]) -> c_int {
        let Ok(n) = c_int::try_from(data.len()) else {
            return -1;
        };
        // SAFETY: data is valid for n bytes; the BIO is live.
        unsafe { ffi::BIO_dump(self.as_ptr(), data.as_ptr().cast(), n) }
    }

    /// `ASN1_parse_dump(bio, data, len, indent, dump)`.
    pub fn asn1_parse_dump(&self, data: &[u8], indent: c_int, dump: c_int) -> c_int {
        let Ok(n) = core::ffi::c_long::try_from(data.len()) else {
            return 0;
        };
        // SAFETY: data is valid for n bytes; the BIO is live.
        unsafe { ffi::ASN1_parse_dump(self.as_ptr(), data.as_ptr(), n, indent, dump) }
    }
}

impl Bio {
    /// `BIO_reset`: what it returns (0 on success for file BIOs).
    pub fn reset_ret(&self) -> core::ffi::c_long {
        self.ctrl(BIO_CTRL_RESET)
    }
}

impl Bio {
    /// `BIO_get_line(bio, buf, size)`: what it returns, and the bytes read (up to `size - 1`,
    /// with the newline).
    pub fn get_line(&self, size: usize) -> (c_int, Vec<u8>) {
        let mut buf = vec![0u8; size.max(1)];
        let n = c_int::try_from(buf.len()).unwrap_or(c_int::MAX);
        // SAFETY: buf is writable for n bytes; the BIO is live.
        let r = unsafe { ffi::BIO_get_line(self.as_ptr(), buf.as_mut_ptr().cast(), n) };
        buf.truncate(usize::try_from(r).unwrap_or(0));
        (r, buf)
    }
}

impl Bio {
    /// `BIO_new(BIO_f_base64())`.
    pub fn new_base64() -> Option<Self> {
        // SAFETY: no arguments; the result is a static method table.
        let method = unsafe { ffi::BIO_f_base64() };
        // SAFETY: method is a valid method table.
        Self::from_ptr(unsafe { ffi::BIO_new(method) })
    }
}

/// A `BIO` borrowed from the chain that owns it ([`Bio::next_bio`]).
pub struct BioRef<'a>(
    core::mem::ManuallyDrop<Bio>,
    core::marker::PhantomData<&'a Bio>,
);

impl core::ops::Deref for BioRef<'_> {
    type Target = Bio;

    fn deref(&self) -> &Bio {
        &self.0
    }
}

impl Bio {
    /// `BIO_new(BIO_s_file())`: a file `BIO` with no file yet.
    pub fn new_file_unset() -> Option<Self> {
        // SAFETY: no arguments; the result is a static method table.
        let method = unsafe { ffi::BIO_s_file() };
        // SAFETY: method is a valid method table.
        Self::from_ptr(unsafe { ffi::BIO_new(method) })
    }

    /// `BIO_new(BIO_f_md())`.
    pub fn new_md() -> Option<Self> {
        // SAFETY: no arguments; the result is a static method table.
        let method = unsafe { ffi::BIO_f_md() };
        // SAFETY: method is a valid method table.
        Self::from_ptr(unsafe { ffi::BIO_new(method) })
    }

    /// `BIO_next`: the next `BIO` of the chain, borrowed.
    pub fn next_bio(&self) -> Option<BioRef<'_>> {
        // SAFETY: the BIO is live; the next one is owned by the chain.
        let p = unsafe { ffi::BIO_next(self.as_ptr()) };
        Bio::from_ptr(p).map(|b| BioRef(core::mem::ManuallyDrop::new(b), core::marker::PhantomData))
    }

    /// `BIO_read_filename(bio, name)`: what it returns.
    pub fn read_filename(&self, name: &str) -> core::ffi::c_long {
        let Some(n) = cstring(name) else {
            return 0;
        };
        // SAFETY: the BIO is live; n is a valid C string the BIO copies or opens at once.
        unsafe {
            ffi::BIO_ctrl(
                self.as_ptr(),
                crate::abi::BIO_C_SET_FILENAME,
                core::ffi::c_long::from(BIO_CLOSE | crate::abi::BIO_FP_READ),
                n.as_ptr().cast_mut().cast(),
            )
        }
    }

    /// `BIO_set_fp(bio, stdin, BIO_NOCLOSE)`, with standard input as a new `FILE` on
    /// descriptor 0 (left open, as `stdin` is).
    pub fn set_fp_stdin(&self) -> bool {
        // SAFETY: fdopen takes any descriptor and a valid mode string.
        let fp = unsafe { libc::fdopen(0, c"r".as_ptr()) };
        if fp.is_null() {
            return false;
        }
        // SAFETY: the BIO is live; fp stays open for the rest of the program.
        unsafe {
            ffi::BIO_ctrl(
                self.as_ptr(),
                crate::abi::BIO_C_SET_FILE_PTR,
                core::ffi::c_long::from(BIO_NOCLOSE),
                fp.cast(),
            ) == 1
        }
    }

    /// `BIO_eof`.
    pub fn eof(&self) -> bool {
        self.ctrl(crate::abi::BIO_CTRL_EOF) != 0
    }

    /// `BIO_set_callback_ex(bio, BIO_debug_callback_ex)` and `BIO_set_callback_arg(bio,
    /// out)`: every operation on the `BIO` is logged to `out`, which must outlive it.
    pub fn set_debug_callback(&self, out: &'static Bio) {
        static CB: crate::load::Symbol =
            crate::load::Symbol::new(crate::load::Library::Crypto, "BIO_debug_callback_ex\0");
        let p = CB.get();
        // SAFETY: p is the address of the export BIO_debug_callback_ex, whose prototype is
        // exactly BIO_callback_fn_ex's function type.
        let cb: crate::abi::BIO_callback_fn_ex = unsafe { core::mem::transmute(p) };
        // SAFETY: the BIO is live; the callback is the library's own.
        unsafe { ffi::BIO_set_callback_ex(self.as_ptr(), cb) };
        // SAFETY: the BIO is live; the callback's argument is a BIO that lives for the rest
        // of the program.
        unsafe { ffi::BIO_set_callback_arg(self.as_ptr(), out.as_ptr().cast()) };
    }

    /// `BIO_get_md_ctx`: the digest context of a digest `BIO`, borrowed.
    pub fn md_ctx(&self) -> Option<crate::evp::MdCtxRef<'_>> {
        let mut ctx: *mut crate::abi::EVP_MD_CTX = core::ptr::null_mut();
        // SAFETY: the BIO is live; ctx is a valid out-pointer for this command.
        let r = unsafe {
            ffi::BIO_ctrl(
                self.as_ptr(),
                crate::abi::BIO_C_GET_MD_CTX,
                0,
                (&raw mut ctx).cast(),
            )
        };
        if r <= 0 || ctx.is_null() {
            return None;
        }
        Some(crate::evp::MdCtxRef::new(ctx))
    }
}

impl Bio {
    /// `BIO_gets(bio, buf, size)` for binary results (a digest `BIO`'s digest): what it
    /// returns, and that many bytes.
    pub fn gets_bytes(&self, size: usize) -> (c_int, Vec<u8>) {
        let mut buf = vec![0u8; size.max(1)];
        let n = c_int::try_from(buf.len()).unwrap_or(c_int::MAX);
        // SAFETY: buf is writable for n bytes; the BIO is live.
        let r = unsafe { ffi::BIO_gets(self.as_ptr(), buf.as_mut_ptr().cast(), n) };
        buf.truncate(usize::try_from(r).unwrap_or(0));
        (r, buf)
    }
}

impl Bio {
    /// `BIO_new(BIO_f_cipher())`.
    pub fn new_cipher() -> Option<Self> {
        // SAFETY: no arguments; the result is a static method table.
        let method = unsafe { ffi::BIO_f_cipher() };
        // SAFETY: method is a valid method table.
        Self::from_ptr(unsafe { ffi::BIO_new(method) })
    }

    /// `BIO_get_cipher_ctx`: the cipher context of a cipher `BIO`, borrowed.
    pub fn cipher_ctx(&self) -> Option<crate::evp::CipherCtxRef<'_>> {
        let mut ctx: *mut crate::abi::EVP_CIPHER_CTX = core::ptr::null_mut();
        // SAFETY: the BIO is live; ctx is a valid out-pointer for this command.
        let r = unsafe {
            ffi::BIO_ctrl(
                self.as_ptr(),
                crate::abi::BIO_C_GET_CIPHER_CTX,
                0,
                (&raw mut ctx).cast(),
            )
        };
        if r <= 0 || ctx.is_null() {
            return None;
        }
        Some(crate::evp::CipherCtxRef::new(ctx))
    }

    /// `BIO_set_flags`.
    pub fn set_flags(&self, flags: c_int) {
        // SAFETY: the BIO is live.
        unsafe { ffi::BIO_set_flags(self.as_ptr(), flags) };
    }

    /// `BIO_number_read`.
    pub fn number_read(&self) -> u64 {
        // SAFETY: the BIO is live.
        unsafe { ffi::BIO_number_read(self.as_ptr()) }
    }

    /// `BIO_number_written`.
    pub fn number_written(&self) -> u64 {
        // SAFETY: the BIO is live.
        unsafe { ffi::BIO_number_written(self.as_ptr()) }
    }
}

impl Bio {
    /// The last `BIO` of the chain (`self` when it is alone), borrowed.
    pub fn bottom(&self) -> BioRef<'_> {
        let mut p = self.as_ptr();
        loop {
            // SAFETY: p is a live BIO of the chain self owns.
            let next = unsafe { ffi::BIO_next(p) };
            if next.is_null() {
                break;
            }
            p = next;
        }
        // p is non-NULL: it starts as self's.
        let b = Bio(core::ptr::NonNull::new(p).unwrap_or(self.0));
        BioRef(core::mem::ManuallyDrop::new(b), core::marker::PhantomData)
    }
}
