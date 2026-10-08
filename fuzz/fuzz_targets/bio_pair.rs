//! Fuzzes BIO pairs and the buffering filters through their C ABI against a model.
//!
//! The first half of the input drives a pair with small buffers: writes, reads, and the
//! non-copying `BIO_nread` and `BIO_nwrite`, each direction modelled as a queue of at most the
//! writer's buffer size. What comes out must be what went in, in order, and the pending counts
//! and the write guarantee must match the queues. The second half writes chunks through a
//! buffer, line buffer, or prefix filter into a memory BIO; after a flush, the memory BIO must
//! hold exactly what was written (with the prefix filter, before each line).

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;
use std::collections::VecDeque;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{BIO, BIO_C_GET_WRITE_GUARANTEE, BIO_CTRL_FLUSH, BIO_CTRL_INFO, BIO_CTRL_PENDING, BIO_CTRL_SET_PREFIX, BIO_METHOD};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn BIO_new_bio_pair(a: *mut *mut BIO, size_a: usize, b: *mut *mut BIO, size_b: usize) -> c_int;
    fn BIO_free(b: *mut BIO) -> c_int;
    fn BIO_free_all(b: *mut BIO);
    fn BIO_new(method: *const BIO_METHOD) -> *mut BIO;
    fn BIO_push(b: *mut BIO, next: *mut BIO) -> *mut BIO;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn BIO_f_buffer() -> *const BIO_METHOD;
    fn BIO_f_linebuffer() -> *const BIO_METHOD;
    fn BIO_f_prefix() -> *const BIO_METHOD;
    fn BIO_write(b: *mut BIO, data: *const c_void, len: c_int) -> c_int;
    fn BIO_read(b: *mut BIO, data: *mut c_void, len: c_int) -> c_int;
    fn BIO_nread(b: *mut BIO, buf: *mut *mut c_char, num: c_int) -> c_int;
    fn BIO_nwrite(b: *mut BIO, buf: *mut *mut c_char, num: c_int) -> c_int;
    fn BIO_ctrl(b: *mut BIO, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
}

fn pair(ops: &[u8]) {
    let sizes = [usize::from(ops.first().copied().unwrap_or(0) % 32) + 1, usize::from(ops.get(1).copied().unwrap_or(0) % 32) + 1];
    let (mut a, mut b) = (ptr::null_mut(), ptr::null_mut());
    // SAFETY: valid out-pointers.
    assert_eq!(unsafe { BIO_new_bio_pair(&mut a, sizes[0], &mut b, sizes[1]) }, 1);
    let ends = [a, b];
    // queues[i]: written by end i, read by the other end.
    let mut queues = [VecDeque::new(), VecDeque::new()];
    let mut counter = 0u8;
    for op in ops.get(2..).unwrap_or_default().chunks_exact(2) {
        let (kind, n) = (op[0], usize::from(op[1] % 40));
        let me = usize::from(kind & 1);
        let other = 1 - me;
        let end = ends[me];
        match (kind >> 1) % 4 {
            0 => {
                let data: Vec<u8> = (0..n).map(|_| { counter = counter.wrapping_add(1); counter }).collect();
                // SAFETY: the data is valid for its length.
                let ret = unsafe { BIO_write(end, data.as_ptr().cast(), n as c_int) };
                let room = sizes[me] - queues[me].len();
                let expected = if n == 0 { 0 } else if room == 0 { -1 } else { n.min(room) as c_int };
                assert_eq!(ret, expected);
                if ret > 0 {
                    queues[me].extend(&data[..ret as usize]);
                } else {
                    counter = counter.wrapping_sub(n as u8);
                }
            }
            1 => {
                let mut out = vec![0u8; n];
                // SAFETY: the buffer is valid for its length.
                let ret = unsafe { BIO_read(end, out.as_mut_ptr().cast(), n as c_int) };
                let queue = &mut queues[other];
                let expected = if n == 0 { 0 } else if queue.is_empty() { -1 } else { n.min(queue.len()) as c_int };
                assert_eq!(ret, expected);
                for byte in out.iter().take(ret.max(0) as usize) {
                    assert_eq!(Some(*byte), queue.pop_front());
                }
            }
            2 => {
                let mut p: *mut c_char = ptr::null_mut();
                // SAFETY: a valid out-pointer.
                let ret = unsafe { BIO_nread(end, &mut p, n as c_int) };
                let queue = &mut queues[other];
                if queue.is_empty() {
                    assert!(ret <= 0);
                } else {
                    assert!(ret >= 0 && ret as usize <= n.min(queue.len()));
                    for i in 0..ret.max(0) as usize {
                        // SAFETY: BIO_nread pointed at `ret` readable bytes.
                        assert_eq!(Some(unsafe { *p.add(i) } as u8), queue.pop_front());
                    }
                }
            }
            _ => {
                let mut p: *mut c_char = ptr::null_mut();
                let room = sizes[me] - queues[me].len();
                // SAFETY: a valid out-pointer.
                let ret = unsafe { BIO_nwrite(end, &mut p, n as c_int) };
                if room == 0 {
                    assert_eq!(ret, -1);
                } else {
                    assert!(ret >= 0 && ret as usize <= n.min(room));
                    for i in 0..ret.max(0) as usize {
                        counter = counter.wrapping_add(1);
                        // SAFETY: BIO_nwrite handed out `ret` writable bytes.
                        unsafe { *p.add(i) = counter as c_char };
                        queues[me].push_back(counter);
                    }
                }
            }
        }
        for i in 0..2 {
            // SAFETY: live BIOs.
            let pending = unsafe { BIO_ctrl(ends[i], BIO_CTRL_PENDING, 0, ptr::null_mut()) };
            assert_eq!(pending as usize, queues[1 - i].len());
            // SAFETY: as above.
            let guarantee = unsafe { BIO_ctrl(ends[i], BIO_C_GET_WRITE_GUARANTEE, 0, ptr::null_mut()) };
            assert_eq!(guarantee as usize, sizes[i] - queues[i].len());
        }
    }
    // SAFETY: live BIOs, freed once.
    unsafe {
        BIO_free(a);
        BIO_free(b);
    }
}

fn filter(data: &[u8]) {
    let Some((&kind, chunks)) = data.split_first() else {
        return;
    };
    // SAFETY: built-in methods.
    let method = unsafe {
        match kind % 3 {
            0 => BIO_f_buffer(),
            1 => BIO_f_linebuffer(),
            _ => BIO_f_prefix(),
        }
    };
    // SAFETY: as above.
    let mem = unsafe { BIO_new(BIO_s_mem()) };
    // SAFETY: as above.
    let f = unsafe { BIO_push(BIO_new(method), mem) };
    if kind % 3 == 2 {
        // SAFETY: a live prefix filter and a NUL-terminated prefix.
        unsafe { BIO_ctrl(f, BIO_CTRL_SET_PREFIX, 0, c"> ".as_ptr().cast_mut().cast()) };
    }
    let mut written = Vec::new();
    let mut rest = chunks;
    while let Some((&len, tail)) = rest.split_first() {
        let len = usize::from(len) * 64 % 9000;
        let chunk: Vec<u8> = tail.iter().copied().cycle().take(len).collect();
        rest = tail.get(len.min(tail.len()).min(8)..).unwrap_or_default();
        // SAFETY: the chunk is valid for its length.
        let ret = unsafe { BIO_write(f, chunk.as_ptr().cast(), chunk.len() as c_int) };
        assert_eq!(ret, chunk.len() as c_int);
        written.extend_from_slice(&chunk);
    }
    // SAFETY: a live chain.
    assert_eq!(unsafe { BIO_ctrl(f, BIO_CTRL_FLUSH, 0, ptr::null_mut()) }, 1);
    let mut out: *mut c_char = ptr::null_mut();
    // SAFETY: BIO_get_mem_data on the memory BIO.
    let len = unsafe { BIO_ctrl(mem, BIO_CTRL_INFO, 0, (&raw mut out).cast()) };
    let got = if len > 0 {
        // SAFETY: the memory BIO holds `len` bytes.
        unsafe { core::slice::from_raw_parts(out.cast::<u8>(), len as usize) }.to_vec()
    } else {
        Vec::new()
    };
    let expected = if kind % 3 == 2 {
        let mut expected = Vec::new();
        let mut start = true;
        for &c in &written {
            if start {
                expected.extend_from_slice(b"> ");
            }
            expected.push(c);
            start = c == b'\n';
        }
        expected
    } else {
        written
    };
    assert_eq!(got, expected);
    // SAFETY: a live chain, freed once.
    unsafe { BIO_free_all(f) };
}

fuzz_target!(|data: &[u8]| {
    let half = data.len() / 2;
    pair(&data[..half]);
    filter(&data[half..]);
});
