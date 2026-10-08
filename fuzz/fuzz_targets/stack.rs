//! Fuzzes the generic stack through its C ABI against a model. Elements are pointers into a
//! pool of small numbers, compared by value. Each two-byte operation pushes, inserts, removes,
//! replaces, sorts, or finds; after each one the stack must hold the model's elements. Sorting
//! is the C library's `qsort`, which needn't keep equal elements in order, so after a sort only
//! the values are compared, and the model takes the stack's order.

#![no_main]

use core::ffi::{c_int, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustssl_abi::{OPENSSL_STACK, OPENSSL_sk_compfunc};
// Linked for its exports, which the declarations below resolve to.
use rustssl_capi as _;

unsafe extern "C" {
    fn OPENSSL_sk_new(cmp: OPENSSL_sk_compfunc) -> *mut OPENSSL_STACK;
    fn OPENSSL_sk_free(st: *mut OPENSSL_STACK);
    fn OPENSSL_sk_num(st: *const OPENSSL_STACK) -> c_int;
    fn OPENSSL_sk_value(st: *const OPENSSL_STACK, i: c_int) -> *mut c_void;
    fn OPENSSL_sk_insert(st: *mut OPENSSL_STACK, data: *const c_void, loc: c_int) -> c_int;
    fn OPENSSL_sk_delete(st: *mut OPENSSL_STACK, loc: c_int) -> *mut c_void;
    fn OPENSSL_sk_delete_ptr(st: *mut OPENSSL_STACK, p: *const c_void) -> *mut c_void;
    fn OPENSSL_sk_set(st: *mut OPENSSL_STACK, i: c_int, data: *const c_void) -> *mut c_void;
    fn OPENSSL_sk_sort(st: *mut OPENSSL_STACK);
    fn OPENSSL_sk_find(st: *mut OPENSSL_STACK, data: *const c_void) -> c_int;
    fn OPENSSL_sk_find_all(st: *mut OPENSSL_STACK, data: *const c_void, pnum: *mut c_int) -> c_int;
    fn OPENSSL_sk_is_sorted(st: *const OPENSSL_STACK) -> c_int;
}

static POOL: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7,
];

unsafe extern "C" fn by_value(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the stack holds pointers into POOL, and the key is one too.
    let a = unsafe { **a.cast::<*const u8>() };
    // SAFETY: as above.
    let b = unsafe { **b.cast::<*const u8>() };
    c_int::from(a > b) - c_int::from(a < b)
}

fn value(element: *const c_void) -> u8 {
    // SAFETY: elements point into POOL.
    unsafe { *element.cast::<u8>() }
}

fn contents(st: *mut OPENSSL_STACK) -> Vec<*const c_void> {
    // SAFETY: a live stack.
    let n = unsafe { OPENSSL_sk_num(st) };
    // SAFETY: as above, for each index below the count.
    (0..n).map(|i| unsafe { OPENSSL_sk_value(st, i) }.cast_const()).collect()
}

fuzz_target!(|data: &[u8]| {
    // SAFETY: a valid comparator.
    let st = unsafe { OPENSSL_sk_new(Some(by_value)) };
    let mut model: Vec<*const c_void> = Vec::new();
    for operation in data.chunks_exact(2) {
        let &[kind, arg] = operation else { unreachable!() };
        let element: *const c_void = ptr::from_ref(&POOL[usize::from(arg % 32)]).cast();
        let loc = c_int::from(arg % 40) - 4;
        match kind % 8 {
            0 | 1 => {
                // SAFETY: a live stack.
                let n = unsafe { OPENSSL_sk_insert(st, element, loc) };
                match usize::try_from(loc) {
                    Ok(at) if at < model.len() => model.insert(at, element),
                    _ => model.push(element),
                }
                assert_eq!(usize::try_from(n).unwrap(), model.len());
            }
            2 => {
                // SAFETY: as above.
                let removed = unsafe { OPENSSL_sk_delete(st, loc) }.cast_const();
                let expected = match usize::try_from(loc) {
                    Ok(at) if at < model.len() => model.remove(at),
                    _ => ptr::null(),
                };
                assert_eq!(removed, expected);
            }
            3 => {
                // SAFETY: as above.
                let removed = unsafe { OPENSSL_sk_delete_ptr(st, element) }.cast_const();
                let expected = model.iter().position(|e| *e == element).map_or(ptr::null(), |at| model.remove(at));
                assert_eq!(removed, expected);
            }
            4 => {
                // SAFETY: as above.
                let set = unsafe { OPENSSL_sk_set(st, loc, element) }.cast_const();
                match usize::try_from(loc) {
                    Ok(at) if at < model.len() => {
                        model[at] = element;
                        assert_eq!(set, element);
                    }
                    _ => assert!(set.is_null()),
                }
            }
            5 => {
                // SAFETY: as above.
                unsafe { OPENSSL_sk_sort(st) };
                // SAFETY: as above.
                assert_eq!(unsafe { OPENSSL_sk_is_sorted(st) }, 1);
                let mut values: Vec<u8> = model.iter().map(|e| value(*e)).collect();
                values.sort_unstable();
                model = contents(st);
                assert_eq!(model.iter().map(|e| value(*e)).collect::<Vec<_>>(), values);
            }
            _ => {
                let mut count = 0;
                // SAFETY: as above.
                let found = unsafe { OPENSSL_sk_find(st, element) };
                // SAFETY: as above.
                let all = unsafe { OPENSSL_sk_find_all(st, element, &mut count) };
                let matches = model.iter().filter(|e| value(**e) == value(element)).count();
                let first = model.iter().position(|e| value(*e) == value(element));
                assert_eq!(found, first.map_or(-1, |i| c_int::try_from(i).unwrap()));
                assert_eq!(all, found);
                if matches > 0 {
                    assert_eq!(usize::try_from(count).unwrap(), matches);
                }
            }
        }
        assert_eq!(contents(st), model);
    }
    // SAFETY: frees the stack made above.
    unsafe { OPENSSL_sk_free(st) };
});
