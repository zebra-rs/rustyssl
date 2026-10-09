//! Fuzzes datagram memory BIOs and pairs through their C ABI against a model: a queue of
//! datagrams. Writes queue a datagram (a memory BIO grows; a pair end's fixed buffer refuses
//! one that doesn't fit, which the model then drops); reads take the next datagram, truncated
//! to the read's size unless no-truncation is on, in which case a short read leaves it. What
//! comes out must be what went in, and `BIO_pending` the next datagram's length. A write of 0
//! bytes returns 0 without reaching the BIO; a read of 0 bytes reads a datagram, truncated.

#![no_main]

use core::ffi::{c_int, c_long, c_void};
use core::ptr;
use std::collections::VecDeque;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{BIO, BIO_CTRL_DGRAM_SET_NO_TRUNC, BIO_CTRL_PENDING, BIO_C_SET_WRITE_BUF_SIZE, BIO_METHOD};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn BIO_s_dgram_mem() -> *const BIO_METHOD;
    fn BIO_new(method: *const BIO_METHOD) -> *mut BIO;
    fn BIO_new_bio_dgram_pair(a: *mut *mut BIO, size_a: usize, b: *mut *mut BIO, size_b: usize) -> c_int;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn BIO_write(b: *mut BIO, data: *const c_void, len: c_int) -> c_int;
    fn BIO_read(b: *mut BIO, data: *mut c_void, len: c_int) -> c_int;
    fn BIO_ctrl(b: *mut BIO, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    fn ERR_clear_error();
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, ops)) = data.split_first() else {
        return;
    };
    let pair = mode & 1 != 0;
    let (writer, reader, other) = if pair {
        let (mut a, mut b) = (ptr::null_mut(), ptr::null_mut());
        // SAFETY: valid out-pointers; a small buffer so that it fills.
        assert_eq!(unsafe { BIO_new_bio_dgram_pair(&mut a, 2048, &mut b, 2048) }, 1);
        (a, b, b)
    } else {
        // SAFETY: the built-in method.
        let m = unsafe { BIO_new(BIO_s_dgram_mem()) };
        (m, m, ptr::null_mut())
    };
    let mut queue: VecDeque<Vec<u8>> = VecDeque::new();
    let mut no_trunc = false;
    let mut counter = 0u8;
    for op in ops.chunks_exact(2) {
        let n = usize::from(op[1]) * 7;
        match op[0] % 4 {
            0 | 1 => {
                let datagram: Vec<u8> = (0..n).map(|_| { counter = counter.wrapping_add(1); counter }).collect();
                // SAFETY: the datagram is valid for its length.
                let ret = unsafe { BIO_write(writer, datagram.as_ptr().cast(), n as c_int) };
                if n == 0 {
                    // BIO_write of nothing returns 0 without reaching the BIO.
                    assert_eq!(ret, 0);
                } else if ret == n as c_int {
                    queue.push_back(datagram);
                } else {
                    assert!(pair && ret == -1, "only a pair's fixed buffer refuses a write");
                }
            }
            2 => {
                let mut buf = vec![0u8; n];
                // SAFETY: the buffer is valid for its length.
                let ret = unsafe { BIO_read(reader, buf.as_mut_ptr().cast(), n as c_int) };
                match queue.front() {
                    None => assert_eq!(ret, -1),
                    Some(next) if no_trunc && n < next.len() => assert_eq!(ret, -1),
                    Some(_) => {
                        let next = queue.pop_front().unwrap();
                        let len = next.len().min(n);
                        assert_eq!(ret, len as c_int);
                        assert_eq!(&buf[..len], &next[..len]);
                    }
                }
            }
            _ => {
                no_trunc = op[1] & 1 != 0;
                // SAFETY: a live BIO.
                unsafe { BIO_ctrl(reader, BIO_CTRL_DGRAM_SET_NO_TRUNC, c_long::from(no_trunc), ptr::null_mut()) };
            }
        }
        // SAFETY: a live BIO.
        let pending = unsafe { BIO_ctrl(reader, BIO_CTRL_PENDING, 0, ptr::null_mut()) };
        assert_eq!(pending as usize, queue.front().map_or(0, Vec::len));
    }
    let _ = BIO_C_SET_WRITE_BUF_SIZE;
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
    // SAFETY: live BIOs, freed once.
    unsafe {
        BIO_free(writer);
        if !other.is_null() && other != writer {
            BIO_free(other);
        }
    }
});
