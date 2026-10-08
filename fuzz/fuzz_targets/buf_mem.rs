//! Fuzzes `BUF_MEM` through its C ABI against a model. The input is a flags byte followed by
//! three-byte operations: grow, grow_clean, or overwrite the contents. After each one, the
//! buffer's length and bytes must equal the model's, which is a `Vec` that grows with zeros:
//! OpenSSL zeroes every byte a grow exposes, whether or not an earlier shrink left it behind.

#![no_main]

use core::ffi::c_ulong;
use core::slice;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::BUF_MEM;
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn BUF_MEM_new_ex(flags: c_ulong) -> *mut BUF_MEM;
    fn BUF_MEM_free(buffer: *mut BUF_MEM);
    fn BUF_MEM_grow(buffer: *mut BUF_MEM, len: usize) -> usize;
    fn BUF_MEM_grow_clean(buffer: *mut BUF_MEM, len: usize) -> usize;
}

fuzz_target!(|data: &[u8]| {
    let (flags, operations) = match data.split_first() {
        Some((first, rest)) => (c_ulong::from(first & 1), rest),
        None => (0, data),
    };
    // SAFETY: always safe to call.
    let buffer = unsafe { BUF_MEM_new_ex(flags) };
    assert!(!buffer.is_null());
    let mut model: Vec<u8> = Vec::new();

    for operation in operations.chunks_exact(3) {
        let &[kind, low, high] = operation else { unreachable!() };
        let len = usize::from(u16::from_le_bytes([low, high])) % 8192;
        match kind % 3 {
            0 => {
                // SAFETY: `buffer` is live and used only here.
                assert_eq!(unsafe { BUF_MEM_grow(buffer, len) }, len);
                model.resize(len, 0);
            }
            1 => {
                // SAFETY: as above.
                assert_eq!(unsafe { BUF_MEM_grow_clean(buffer, len) }, len);
                model.resize(len, 0);
            }
            _ => {
                // SAFETY: `data` holds at least `length` bytes.
                let fields = unsafe { &*buffer };
                if fields.length > 0 {
                    // SAFETY: `data` holds `length` bytes, and nothing else refers to them.
                    let contents = unsafe {
                        slice::from_raw_parts_mut(fields.data.cast::<u8>(), fields.length)
                    };
                    contents.fill(low);
                }
                model.fill(low);
            }
        }
        // SAFETY: as above.
        let fields = unsafe { &*buffer };
        assert_eq!(fields.length, model.len());
        assert!(fields.max >= fields.length);
        if fields.length > 0 {
            // SAFETY: `data` holds at least `length` bytes.
            let contents = unsafe { slice::from_raw_parts(fields.data.cast::<u8>(), fields.length) };
            assert_eq!(contents, &model[..]);
        }
    }
    // SAFETY: frees the buffer made above.
    unsafe { BUF_MEM_free(buffer) };
});
