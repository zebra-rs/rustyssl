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
