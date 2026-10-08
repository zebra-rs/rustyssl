//! Fuzzes the hash table through its C ABI against a model, a `HashMap`. Items are numbers;
//! each two-byte operation inserts, deletes, or looks one up, under a hash that sends many
//! numbers to the same bucket so chains, splits, and merges all get exercised. After each
//! operation the item count must match, and every so often a doall walk must visit each item
//! exactly once.

#![no_main]

use core::ffi::{c_int, c_ulong, c_void};
use core::ptr;
use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{OPENSSL_LH_COMPFUNC, OPENSSL_LH_DOALL_FUNCARG, OPENSSL_LH_HASHFUNC, OPENSSL_LHASH};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn OPENSSL_LH_new(h: OPENSSL_LH_HASHFUNC, c: OPENSSL_LH_COMPFUNC) -> *mut OPENSSL_LHASH;
    fn OPENSSL_LH_free(lh: *mut OPENSSL_LHASH);
    fn OPENSSL_LH_insert(lh: *mut OPENSSL_LHASH, data: *mut c_void) -> *mut c_void;
    fn OPENSSL_LH_delete(lh: *mut OPENSSL_LHASH, data: *const c_void) -> *mut c_void;
    fn OPENSSL_LH_retrieve(lh: *mut OPENSSL_LHASH, data: *const c_void) -> *mut c_void;
    fn OPENSSL_LH_num_items(lh: *const OPENSSL_LHASH) -> c_ulong;
    fn OPENSSL_LH_set_down_load(lh: *mut OPENSSL_LHASH, dl: c_ulong);
    fn OPENSSL_LH_doall_arg_thunk(
        lh: *mut OPENSSL_LHASH,
        daaw: rustyssl_abi::OPENSSL_LH_DOALL_FUNCARG_THUNK,
        f: OPENSSL_LH_DOALL_FUNCARG,
        arg: *mut c_void,
    );
}

/// Items: two copies of each number, so lookups find equal items at other addresses.
static ITEMS: [[u16; 256]; 2] = {
    let mut items = [[0; 256]; 2];
    let mut i = 0;
    while i < 256 {
        items[0][i] = i as u16;
        items[1][i] = i as u16;
        i += 1;
    }
    items
};

unsafe extern "C" fn hash(data: *const c_void) -> c_ulong {
    // SAFETY: items are u16s.
    c_ulong::from(unsafe { *data.cast::<u16>() } % 37)
}

unsafe extern "C" fn compare(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: as above.
    let a = unsafe { *a.cast::<u16>() };
    // SAFETY: as above.
    let b = unsafe { *b.cast::<u16>() };
    c_int::from(a != b)
}

unsafe extern "C" fn collect(item: *mut c_void, seen: *mut c_void) {
    // SAFETY: the walk passes the Vec below and an item.
    unsafe { (*seen.cast::<Vec<u16>>()).push(*item.cast::<u16>()) };
}

fn item(copy: usize, number: u8) -> *mut c_void {
    ptr::from_ref(&ITEMS[copy][usize::from(number)]).cast_mut().cast()
}

fuzz_target!(|data: &[u8]| {
    // SAFETY: valid callbacks.
    let lh = unsafe { OPENSSL_LH_new(Some(hash), Some(compare)) };
    let mut model: HashMap<u8, *mut c_void> = HashMap::new();
    for (step, operation) in data.chunks_exact(2).enumerate() {
        let &[kind, number] = operation else { unreachable!() };
        let mine = item(usize::from(kind & 1), number);
        let other = item(usize::from(!kind & 1), number);
        match (kind >> 1) % 5 {
            0 | 1 => {
                // SAFETY: a live table; the items outlive it.
                let old = unsafe { OPENSSL_LH_insert(lh, mine) };
                assert_eq!(old, model.insert(number, mine).unwrap_or(ptr::null_mut()));
            }
            2 => {
                // SAFETY: as above.
                let removed = unsafe { OPENSSL_LH_delete(lh, other) };
                assert_eq!(removed, model.remove(&number).unwrap_or(ptr::null_mut()));
            }
            3 => {
                // SAFETY: as above.
                let found = unsafe { OPENSSL_LH_retrieve(lh, other) };
                assert_eq!(found, model.get(&number).copied().unwrap_or(ptr::null_mut()));
            }
            _ => {
                // SAFETY: as above.
                unsafe { OPENSSL_LH_set_down_load(lh, c_ulong::from(number) * 4) };
            }
        }
        // SAFETY: as above.
        assert_eq!(unsafe { OPENSSL_LH_num_items(lh) }, model.len() as c_ulong);
        if step % 16 == 15 {
            let mut seen: Vec<u16> = Vec::new();
            let arg = ptr::from_mut(&mut seen).cast();
            // SAFETY: as above; `collect` takes the Vec.
            unsafe { OPENSSL_LH_doall_arg_thunk(lh, None, Some(collect), arg) };
            seen.sort_unstable();
            let mut expected: Vec<u16> = model.keys().map(|k| u16::from(*k)).collect();
            expected.sort_unstable();
            assert_eq!(seen, expected);
        }
    }
    // SAFETY: frees the table made above.
    unsafe { OPENSSL_LH_free(lh) };
});
