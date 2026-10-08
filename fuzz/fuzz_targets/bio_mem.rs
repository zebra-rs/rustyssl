//! Fuzzes the memory BIO through its C ABI against a model: the buffer since its last
//! compaction and a read position in it. Each three-byte operation writes, reads, gets a line,
//! seeks, tells, or resets; after each one, what is pending and what reads return must match
//! the model. A write first moves the unread data to the buffer's start, as OpenSSL does,
//! unless it writes nothing.

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_void};

use libfuzzer_sys::fuzz_target;
use rustssl_abi::{BIO, BIO_C_FILE_SEEK, BIO_C_FILE_TELL, BIO_CTRL_PENDING, BIO_CTRL_RESET, BIO_METHOD};
// Linked for its exports, which the declarations below resolve to.
use rustssl_capi as _;

unsafe extern "C" {
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_new(method: *const BIO_METHOD) -> *mut BIO;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn BIO_write(b: *mut BIO, data: *const c_void, len: c_int) -> c_int;
    fn BIO_read(b: *mut BIO, data: *mut c_void, len: c_int) -> c_int;
    fn BIO_gets(b: *mut BIO, buf: *mut c_char, size: c_int) -> c_int;
    fn BIO_ctrl(b: *mut BIO, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
}

struct Model {
    buffer: Vec<u8>,
    position: usize,
}

impl Model {
    fn unread(&self) -> &[u8] {
        &self.buffer[self.position..]
    }

    fn take(&mut self, n: usize) -> Vec<u8> {
        let taken = self.unread()[..n].to_vec();
        self.position += n;
        taken
    }
}

fuzz_target!(|data: &[u8]| {
    // SAFETY: the built-in method.
    let bio = unsafe { BIO_new(BIO_s_mem()) };
    assert!(!bio.is_null());
    let mut model = Model { buffer: Vec::new(), position: 0 };
    let mut out = [0u8; 256];
    for operation in data.chunks_exact(3) {
        let &[kind, a, b] = operation else { unreachable!() };
        let n = usize::from(a);
        match kind % 6 {
            0 => {
                let bytes: Vec<u8> = (0..n).map(|i| b.wrapping_add(i as u8)).collect();
                // SAFETY: a live BIO; `bytes` holds `n` bytes.
                let written = unsafe { BIO_write(bio, bytes.as_ptr().cast(), c_int::from(a)) };
                assert_eq!(written, c_int::from(a));
                // BIO_write returns before reaching the BIO for zero bytes, so nothing moves.
                if n > 0 {
                    model.buffer.drain(..model.position);
                    model.position = 0;
                    model.buffer.extend_from_slice(&bytes);
                }
            }
            1 => {
                // SAFETY: as above; `out` holds 256 bytes.
                let got = unsafe { BIO_read(bio, out.as_mut_ptr().cast(), c_int::from(a)) };
                let expected = n.min(model.unread().len());
                if expected == 0 {
                    assert!(got <= 0, "empty: {got}");
                } else {
                    assert_eq!(usize::try_from(got).unwrap(), expected);
                    assert_eq!(&out[..expected], &model.take(expected)[..]);
                }
            }
            2 => {
                let size = c_int::from(a);
                // SAFETY: as above.
                let got = unsafe { BIO_gets(bio, out.as_mut_ptr().cast(), size) };
                let limit = usize::from(a).saturating_sub(1).min(model.unread().len());
                let line = model.unread()[..limit]
                    .iter()
                    .position(|c| *c == b'\n')
                    .map_or(limit, |i| i + 1);
                if line == 0 {
                    assert!(got <= 0);
                } else {
                    assert_eq!(usize::try_from(got).unwrap(), line);
                    assert_eq!(&out[..line], &model.take(line)[..]);
                    assert_eq!(out[line], 0);
                }
            }
            3 => {
                let to = c_long::from(b);
                // SAFETY: as above.
                let ret = unsafe { BIO_ctrl(bio, BIO_C_FILE_SEEK, to, core::ptr::null_mut()) };
                if usize::from(b) > model.buffer.len() {
                    assert_eq!(ret, -1);
                } else {
                    assert_eq!(ret, to);
                    model.position = usize::from(b);
                }
            }
            4 => {
                // SAFETY: as above.
                let at = unsafe { BIO_ctrl(bio, BIO_C_FILE_TELL, 0, core::ptr::null_mut()) };
                assert_eq!(usize::try_from(at).unwrap(), model.position);
            }
            _ => {
                // SAFETY: as above.
                assert_eq!(unsafe { BIO_ctrl(bio, BIO_CTRL_RESET, 0, core::ptr::null_mut()) }, 1);
                model.buffer.clear();
                model.position = 0;
            }
        }
        // SAFETY: as above.
        let pending = unsafe { BIO_ctrl(bio, BIO_CTRL_PENDING, 0, core::ptr::null_mut()) };
        assert_eq!(usize::try_from(pending).unwrap(), model.unread().len());
    }
    // SAFETY: frees the BIO made above.
    unsafe { BIO_free(bio) };
});
